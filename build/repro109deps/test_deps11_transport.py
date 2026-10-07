"""Real transport/download functions; only the curl process is disk-fed."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import private_curl
import public_archive
import source_download


class Deps11TransportTests(unittest.TestCase):
    def setUp(self):
        evidence = os.environ.get('REPRO109_REAL_SOURCE_EVIDENCE')
        # The inherited 46-route control owns its entire evidence destination
        # and creates it only after success. Keep our retained fixtures beside it.
        self.root = (Path(evidence).with_name(Path(evidence).name + '-deps11') / self._testMethodName if evidence else
                     Path(tempfile.mkdtemp(prefix='deps11-own-inert-')))
        self.root.mkdir(parents=True, exist_ok=True)
        self.body = b'own inert source archive fixture; never unpacked or executed\n'
        self.url = source_download.read_routes()['routes']['ninja']['url']

    def exercise(self, label, replies):
        root = self.root / label
        root.mkdir()
        descriptor = dict(name='ninja', url=self.url, size=len(self.body),
                          sha256=hashlib.sha256(self.body).hexdigest())
        replies = iter(replies)
        calls = []
        def fake_curl(argv, *, input, env, stdout, stderr, timeout):
            if argv[:2] != ['/usr/bin/curl', '--disable']:
                raise AssertionError('Only the curl process may be substituted')
            rc, status, body, metadata = next(replies)
            config = input.decode()
            selected = json.loads(next(line[6:] for line in config.splitlines() if line.startswith('url = ')))
            self.assertEqual(selected, self.url)
            self.assertFalse({'GH_TOKEN', 'GITHUB_TOKEN', 'RESULTS_TOKEN'} & set(env))
            self.assertNotIn('Authorization:', config)
            target = Path(argv[argv.index('--output') + 1])
            if body is not None:
                target.write_bytes(body)
            calls.append(dict(rc=rc, status=status, body_bytes=0 if body is None else len(body)))
            headers = 'HTTP/1.1 ' + str(status) + ' OWN FIXTURE\r\n'
            if metadata is not None:
                for key, value in metadata.items():
                    headers += key + ': ' + str(value) + '\r\n'
            result = headers + '\r\n' + private_curl.MARKER + str(status) + '\n' + self.url + '\n'
            return subprocess.CompletedProcess(argv, rc, result.encode(), b'owned transport diagnostic')
        def transfer(url, target, limit, timeout_seconds):
            return private_curl.source_transfer(url, target, limit, timeout_seconds,
                                               allowed_hosts=['github.com', 'codeload.github.com'])
        error = None
        with patch.object(private_curl.subprocess, 'run', autospec=True, side_effect=fake_curl), \
             patch.object(public_archive.time, 'sleep', autospec=True) as pause:
            try:
                result = public_archive.download(descriptor, root / 'accepted.archive', root, transfer=transfer)
            except ValueError as failure:
                result = None
                error = str(failure)
        receipt = json.loads((root / 'public-archives/ninja/receipt.json').read_text())
        (root / 'CONTROL.json').write_text(json.dumps(dict(classification='OWN_INERT_REAL_FUNCTIONS_OFFLINE',
            curl_process_calls=calls, pause_seconds=[call.args[0] for call in pause.call_args_list],
            error=error, accepted=result is not None), indent=2) + '\n')
        return result, receipt, calls, pause.call_args_list

    def complete(self):
        return 0, 200, self.body, {'Content-Length': len(self.body)}

    def test_first_tls35_http0_requires_second_attempt(self):
        result, receipt, calls, pauses = self.exercise('TLS35', [(35, 0, None, None), self.complete()])
        self.assertIsNotNone(result)
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(pauses), 1)
        self.assertGreater(pauses[0].args[0], 0)
        self.assertEqual(receipt['attempts'][0]['curl_rc'], 35)
        self.assertTrue(receipt['attempts'][0]['retryable'])
        self.assertEqual(receipt['attempts'][0]['received_bytes'], 0)
        self.assertEqual(receipt['attempts'][0]['raw_body']['state'], 'NOT_ENABLED')

    def test_all_requested_and_inherited_transient_codes_real_path(self):
        for rc in [5, 6, 7, 18, 28, 35, 52, 55, 56, 92]:
            with self.subTest(rc=rc):
                result, receipt, calls, pauses = self.exercise('RC' + str(rc), [(rc, 0, None, None), self.complete()])
                self.assertIsNotNone(result)
                self.assertEqual(len(calls), 2)
                self.assertEqual(len(pauses), 1)
                self.assertTrue(receipt['attempts'][0]['retryable'])

    def test_all_http5xx_classification(self):
        for status in range(500, 600):
            with self.subTest(status=status):
                self.assertTrue(private_curl.transport_failure(22, status)[1])

    def test_http429_and_5xx_real_path_even_error_body_encoded(self):
        for status in [429, 500, 501, 509, 599]:
            with self.subTest(status=status):
                result, receipt, calls, pauses = self.exercise('HTTP' + str(status),
                    [(22, status, b'error', {'Content-Encoding': 'gzip'}), self.complete()])
                self.assertIsNotNone(result)
                self.assertEqual(len(calls), 2)
                self.assertEqual(len(pauses), 1)

    def test_all_http4xx_except429_terminal(self):
        for status in range(400, 500):
            if status != 429:
                with self.subTest(status=status):
                    self.assertFalse(private_curl.transport_failure(22, status)[1])
        for status in [400, 401, 403, 404, 408, 410, 499]:
            result, receipt, calls, pauses = self.exercise('HTTP' + str(status), [(22, status, None, None)])
            self.assertIsNone(result)
            self.assertEqual(len(calls), 1)
            self.assertEqual(len(pauses), 0)
            self.assertFalse(receipt['attempts'][0]['retryable'])

    def test_six_failed_attempts_bound_five_retries(self):
        result, receipt, calls, pauses = self.exercise('EXHAUST', [(35, 0, None, None)] * 6)
        self.assertIsNone(result)
        self.assertEqual(len(calls), 6)
        self.assertEqual(len(pauses), 5)
        self.assertEqual(receipt['maximum_retries'], 5)
        self.assertEqual(len(receipt['attempts']), 6)
        self.assertEqual(receipt['state'], 'FAILED')
        self.assertEqual([attempt['number'] for attempt in receipt['attempts']], list(range(1, 7)))

    def test_completed_http200_size_sha_and_length_terminal(self):
        for label, body, headers in [('SIZE', self.body[:-1], {}),
                                      ('SHA', b'x' * len(self.body), {'Content-Length': len(self.body)}),
                                      ('LENGTH', self.body[:-1], {'Content-Length': len(self.body)})]:
            result, receipt, calls, pauses = self.exercise(label, [(0, 200, body, headers)])
            self.assertIsNone(result)
            self.assertEqual(len(calls), 1)
            self.assertFalse(receipt['attempts'][0]['retryable'])
            self.assertEqual(len(pauses), 0)

    def test_incomplete_curl18_http200_keeps_transport_retry(self):
        result, receipt, calls, pauses = self.exercise('PARTIAL',
            [(18, 200, self.body[:3], {'Content-Length': len(self.body)}), self.complete()])
        self.assertIsNotNone(result)
        self.assertEqual(len(calls), 2)
        first = receipt['attempts'][0]
        self.assertEqual((self.root / 'PARTIAL' / first['raw_body']['path']).read_bytes(), self.body[:3])

    def test_local_certificate_and_protocol_errors_terminal(self):
        for rc in [23, 60, 63, 77]:
            result, receipt, calls, pauses = self.exercise('RC' + str(rc), [(rc, 0, None, None)])
            self.assertIsNone(result)
            self.assertEqual(len(calls), 1)
            self.assertEqual(len(pauses), 0)

    def test_no_metadata_transient_still_retries(self):
        with patch.object(private_curl.subprocess, 'run', autospec=True,
                          return_value=subprocess.CompletedProcess([], 35, b'', b'own')):
            result = private_curl.source_transfer(self.url, self.root / 'empty', len(self.body),
                                                  allowed_hosts=['github.com', 'codeload.github.com'])
        self.assertTrue(result['retryable'])
        self.assertEqual(result['http_status'], 'NOT_ENABLED')

    def test_malformed_metadata_remains_terminal(self):
        with patch.object(private_curl.subprocess, 'run', autospec=True,
                          return_value=subprocess.CompletedProcess([], 35, b'malformed', b'own')):
            result = private_curl.source_transfer(self.url, self.root / 'malformed', len(self.body),
                                                  allowed_hosts=['github.com', 'codeload.github.com'])
        self.assertFalse(result['retryable'])
