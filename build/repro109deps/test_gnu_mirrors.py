"""Owned bytes and inert transport fixtures; never fetch or execute source code."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'repro109'))
import source_download as source
import private_curl
import public_archive


class GnuMirrorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.body = b'owned-gnu-archive'
        self.urls = ['https://ftp.gnu.org/gnu/owned/owned.tar.xz',
                     'https://ftpmirror.gnu.org/owned/owned.tar.xz',
                     'https://mirrors.kernel.org/gnu/owned/owned.tar.xz']
        self.row = dict(name='owned-gnu', url=self.urls[0], source_urls=self.urls,
                        source_route=dict(allowed_hosts=['ftp.gnu.org', 'ftpmirror.gnu.org',
                                                         'mirrors.kernel.org']),
                        size=len(self.body), sha256=hashlib.sha256(self.body).hexdigest())
        self.destination = self.root / 'accepted.archive'
        self.out = self.root / 'out'
        self.out.mkdir()

    def receipt(self):
        return json.loads((self.out / 'public-archives/owned-gnu/receipt.json').read_text())

    def exercise(self, responses):
        seen = []
        sequence = iter(responses)
        def transfer(url, target, limit, timeout_seconds):
            seen.append((url, limit, timeout_seconds))
            body, metadata = next(sequence)
            target.write_bytes(body)
            return dict(dict(curl_rc=0, http_status=200, content_length=str(len(body)),
                             final_host=private_curl.urllib.parse.urlparse(url).hostname), **metadata)
        with patch.object(public_archive.time, 'sleep'):
            try:
                result = public_archive.download(self.row, self.destination, self.out, transfer=transfer)
                error = None
            except ValueError as failure:
                result, error = None, str(failure)
        return result, error, self.receipt(), seen

    def tls_failure(self):
        return b'', dict(curl_rc=35, http_status=0, failure_reason='curl transfer failed; rc=35',
                         retryable=True, stderr_state='NOT_SAVED_SENSITIVE_TRANSFER_DIAGNOSTICS')

    def test_primary_success_does_not_contact_mirrors(self):
        result, error, receipt, seen = self.exercise([(self.body, {})])
        self.assertIsNone(error)
        self.assertEqual([row[0] for row in seen], self.urls[:1])
        self.assertEqual(result['selected_source_host'], 'ftp.gnu.org')
        self.assertFalse(receipt['attempts'][0]['fallback_next_source'])

    def test_primary_tls35_selects_first_mirror_with_same_sha(self):
        result, error, receipt, seen = self.exercise([self.tls_failure(), (self.body, {})])
        self.assertIsNone(error)
        self.assertEqual([row[0] for row in seen], self.urls[:2])
        self.assertEqual(result['selected_source_index'], 1)
        self.assertEqual(result['selected_source_host'], 'ftpmirror.gnu.org')
        self.assertEqual(result['sha256'], self.row['sha256'])
        self.assertEqual(self.destination.read_bytes(), self.body)
        self.assertEqual(receipt['attempts'][0]['raw_body']['state'], 'EMPTY')

    def test_two_tls35_failures_select_kernel_and_preserve_failed_bodies(self):
        result, error, receipt, seen = self.exercise([self.tls_failure(), self.tls_failure(),
                                                     (self.body, {})])
        self.assertIsNone(error)
        self.assertEqual([row[0] for row in seen], self.urls)
        self.assertEqual(result['selected_source_host'], 'mirrors.kernel.org')
        self.assertEqual(result['selected_final_host'], 'mirrors.kernel.org')
        for number in (1, 2):
            self.assertEqual((self.out / ('public-archives/owned-gnu/attempt-%d.body' % number)).read_bytes(), b'')

    def test_six_attempt_limit_last_mirror_only_retries(self):
        result, error, receipt, seen = self.exercise([self.tls_failure()] * 6)
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        self.assertEqual([row[0] for row in seen], self.urls[:2] + self.urls[2:] * 4)
        self.assertEqual(len(receipt['attempts']), 6)
        self.assertEqual(receipt['maximum_retries'], 5)
        self.assertEqual(receipt['time_cap_seconds'], 150)
        self.assertFalse(self.destination.exists())

    def test_wrong_sha_is_terminal_at_each_endpoint(self):
        for index in range(3):
            with self.subTest(source_index=index), tempfile.TemporaryDirectory() as directory:
                self.out = Path(directory) / 'out'; self.out.mkdir()
                self.destination = Path(directory) / 'accepted.archive'
                result, error, receipt, seen = self.exercise([self.tls_failure()] * index +
                                                            [(b'X' * len(self.body), {})])
                self.assertIsNone(result)
                self.assertEqual(len(seen), index + 1)
                self.assertEqual(receipt['attempts'][-1]['failure_reason'], 'archive checksum or size differs')
                self.assertFalse(receipt['attempts'][-1]['fallback_next_source'])
                self.assertFalse(self.destination.exists())

    def test_404_or_410_select_next_mirror_but_certificate_failure_is_terminal(self):
        for status in (404, 410):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                self.out = Path(directory) / 'out'; self.out.mkdir()
                self.destination = Path(directory) / 'accepted.archive'
                result, error, receipt, seen = self.exercise([
                    (b'', dict(curl_rc=22, http_status=status, failure_reason='expected HTTP 200', retryable=False)),
                    (self.body, {})])
                self.assertIsNone(error)
                self.assertEqual(len(seen), 2)
        with tempfile.TemporaryDirectory() as directory:
            self.out = Path(directory) / 'out'; self.out.mkdir()
            self.destination = Path(directory) / 'accepted.archive'
            result, error, receipt, seen = self.exercise([
                (b'', dict(curl_rc=60, http_status=0, failure_reason='expected HTTP 200', retryable=False))])
            self.assertIsNotNone(error)
            self.assertEqual(len(seen), 1)
            self.assertFalse(receipt['attempts'][0]['fallback_next_source'])

    def test_unapproved_ftpmirror_redirect_is_never_followed_kernel_remains_available(self):
        seen = []
        def run(argv, **kwargs):
            config = kwargs['input'].decode()
            url = json.loads(config.splitlines()[0].partition(' = ')[2])
            seen.append(url)
            self.assertNotIn('Authorization:', config)
            self.assertNotIn('owned-secret', config)
            self.assertFalse({'RESULTS_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN'} & set(kwargs['env']))
            target = Path(argv[argv.index('--output') + 1])
            if len(seen) == 1:
                status, code, headers, body = 0, 35, '', b''
            elif len(seen) == 2:
                status, code, body = 302, 0, b''
                headers = 'HTTP/1.1 302 Found\r\nLocation: https://foreign.invalid/owned.tar.xz\r\n\r\n'
            else:
                status, code, body = 200, 0, self.body
                headers = 'HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n' % len(body)
            target.write_bytes(body)
            return subprocess.CompletedProcess(argv, code,
                (headers + private_curl.MARKER + str(status) + '\n' + url + '\n').encode(), b'')
        with patch.object(private_curl.subprocess, 'run', side_effect=run), \
             patch.object(public_archive.time, 'sleep'), \
             patch.dict(os.environ, dict(RESULTS_TOKEN='owned-secret', GH_TOKEN='owned-secret', GITHUB_TOKEN='owned-secret')):
            result = public_archive.download(self.row, self.destination, self.out,
                transfer=lambda *args, **kwargs: private_curl.source_transfer(
                    *args, allowed_hosts=self.row['source_route']['allowed_hosts'], **kwargs))
        self.assertEqual(seen, self.urls)
        self.assertEqual(result['selected_source_host'], 'mirrors.kernel.org')
        self.assertEqual(result['attempts'][1]['failure_stage'], 'REDIRECT_DESTINATION_REFUSED')
        self.assertFalse(result['attempts'][1]['retryable'])
        self.assertTrue(result['attempts'][1]['fallback_next_source'])

    def test_malformed_metadata_and_oversize_stay_terminal_with_mirrors(self):
        for body, metadata in [(b'', dict(curl_rc=0, http_status=200,
              failure_reason='curl response metadata or redirect destination refused', retryable=False)),
              (self.body + b'X', {})]:
            with tempfile.TemporaryDirectory() as directory:
                self.out = Path(directory) / 'out'; self.out.mkdir()
                self.destination = Path(directory) / 'accepted.archive'
                result, error, receipt, seen = self.exercise([(body, metadata)])
                self.assertIsNotNone(error)
                self.assertEqual(len(seen), 1)
                self.assertFalse(receipt['attempts'][0]['fallback_next_source'])

    def test_budget_is_shared_and_reserves_time_for_untried_sources(self):
        with patch.object(public_archive.time, 'monotonic', return_value=0):
            result, error, receipt, seen = self.exercise([self.tls_failure(), self.tls_failure(), (self.body, {})])
        self.assertIsNone(error)
        self.assertEqual([row[2] for row in seen], [50, 75, 90])
        self.assertEqual([row['timeout_seconds'] for row in receipt['attempts']], [50, 75, 90])

    def test_source_sequence_shape_is_validated_before_transport(self):
        bad = [None, 'foreign', [], [self.urls[1]], [self.urls[0]] * 2,
               [self.urls[0], {}], self.urls + ['https://extra.invalid/file']]
        for sequence in bad:
            with self.subTest(sequence=sequence), patch.object(public_archive, 'public_transfer') as call:
                row = dict(self.row, source_urls=sequence)
                with self.assertRaisesRegex(ValueError, 'source sequence'):
                    public_archive.download(row, self.destination, self.out)
                call.assert_not_called()
        row = dict(self.row); del row['source_route']
        with self.assertRaisesRegex(ValueError, 'source sequence'):
            public_archive.download(row, self.destination, self.out)

    def test_all_seven_gnu_routes_match_locked_file_and_other_routes_stay_pinned(self):
        routes = source.read_routes()['routes']
        rows = json.loads((HERE / 'deps.lock.json').read_bytes())['components']
        gnu = []
        for row in rows:
            if row.get('source_kind') == 'git':
                continue
            with patch.object(public_archive, 'download', return_value={}) as call:
                source.download(row, Path('owned-unused'), Path('owned-out'))
            request = call.call_args[0][0]
            self.assertEqual(request['sha256'], row['sha256'])
            route = routes[row['name']]
            self.assertEqual(request['source_urls'], [row['url']] + route.get('mirror_urls', []))
            if row['url'].startswith('https://ftp.gnu.org/gnu/'):
                gnu.append(row['name'])
                self.assertEqual(len(request['source_urls']), 3)
            elif row['url'].startswith('https://downloads.sourceforge.net/project/'):
                self.assertEqual(len(request['source_urls']), 3)
            else:
                self.assertNotIn('mirror_urls', route)
                self.assertEqual(len(request['source_urls']), 1)
        self.assertEqual(set(gnu), {'libunistring', 'gettext', 'bison', 'gmp', 'nettle', 'libtasn1', 'libidn2'})

    def test_mirror_lock_rejects_order_path_protocol_query_host_and_non_gnu_grants(self):
        original = source.read_routes()
        changes = [None, list(reversed(original['routes']['gmp']['mirror_urls'])),
                   ['https://ftpmirror.gnu.org/gmp/foreign.tar.xz', original['routes']['gmp']['mirror_urls'][1]],
                   ['http://ftpmirror.gnu.org/gmp/gmp-6.3.0.tar.xz', original['routes']['gmp']['mirror_urls'][1]],
                   [original['routes']['gmp']['mirror_urls'][0] + '?token=owned', original['routes']['gmp']['mirror_urls'][1]],
                   ['https://ftpmirror.gnu.org.foreign.invalid/gmp/gmp-6.3.0.tar.xz', original['routes']['gmp']['mirror_urls'][1]]]
        for mirrors in changes:
            routes = copy.deepcopy(original); routes['routes']['gmp']['mirror_urls'] = mirrors
            self.refuse_routes(routes)
        routes = copy.deepcopy(original); routes['routes']['gmp']['allowed_hosts'].append('foreign.invalid')
        self.refuse_routes(routes)
        routes = copy.deepcopy(original); routes['routes']['ffmpeg']['mirror_urls'] = self.urls[1:]
        self.refuse_routes(routes)

    def refuse_routes(self, routes):
        fixture = self.root / 'locks'; fixture.mkdir(exist_ok=True)
        (fixture / 'deps.lock.json').write_bytes((HERE / 'deps.lock.json').read_bytes())
        (fixture / 'source-routes.lock.json').write_text(json.dumps(routes))
        with patch.object(source, 'HERE', fixture), self.assertRaises(ValueError):
            source.read_routes()


if __name__ == '__main__':
    unittest.main()
