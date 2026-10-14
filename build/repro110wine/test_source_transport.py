"""Offline controls of the c12 source transport: redirects, retries with pauses, HTTP/1.1, resume. No network."""
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import source_transport as st
import private_curl
import public_archive

ROUTE = ['downloads.sourceforge.net', 'cfhcable.dl.sourceforge.net']
START = 'https://downloads.sourceforge.net/project/freetype/freetype2/2.14.3/freetype-2.14.3.tar.xz'
MIRROR = 'https://phoenixnap.dl.sourceforge.net/project/freetype/freetype2/2.14.3/freetype-2.14.3.tar.xz'
SIGNED = MIRROR + '?viasf=1&fid=22b6&e=1792044830&st=SECRETTOKEN'
BODY = bytes(range(256)) * 40


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Net:
    """Scripted stand-in for /usr/bin/curl: every URL has a queue of responses, consumed in order."""
    def __init__(self, script):
        self.script = {url: list(steps) for url, steps in script.items()}
        self.calls = []

    def __call__(self, argv, config, seconds):
        url = json.loads(config.split('url = ', 1)[1].split('\n', 1)[0])
        self.calls.append((url, argv))
        step = self.script[url].pop(0)
        out = Path(argv[argv.index('--output') + 1])
        with open(out, 'ab' if step.get('append') else 'wb') as stream:
            stream.write(step.get('body', b''))
        lines = ''.join(k + ': ' + v + '\r\n' for k, v in step.get('headers', {}).items())
        head = 'HTTP/1.1 ' + str(step['status']) + ' X\r\n' + lines + '\r\n'
        stdout = (head + private_curl.MARKER + str(step['status']) + '\n' + url + '\n').encode('latin1')
        return SimpleNamespace(returncode=step.get('rc', 0), stdout=stdout, stderr=b'')


def redirect(location, status=302):
    return dict(status=status, headers={'Location': location}, body=b'302 Found\n')


def ok(body=BODY):
    return dict(status=200, headers={'Content-Length': str(len(body))}, body=body)


class Transport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='transport-', dir=os.environ['REPRO109_TEST_TMP'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sleeps = []
        st.reset()
        for patcher in (mock.patch.object(st, '_sleep', self.sleeps.append), mock.patch('time.sleep')):
            patcher.start(); self.addCleanup(patcher.stop)

    def use(self, script):
        self.net = Net(script)
        patcher = mock.patch.object(st, '_curl', self.net)
        patcher.start(); self.addCleanup(patcher.stop)
        return self.net

    def download(self, body=BODY, urls=None, digest=None):
        urls = urls or [START]
        row = dict(name='freetype', url=urls[0], sha256=digest or sha(body), size=len(body))
        if len(urls) > 1:
            row.update(source_urls=urls, source_route=dict(component='freetype', allowed_hosts=ROUTE))
        out = self.root / 'out'
        out.mkdir(exist_ok=True)
        transfer = partial(st.source_transfer, allowed_hosts=ROUTE)
        return public_archive.download(row, self.root / 'freetype.tar.xz', out, transfer=transfer), out

    def test_redirect_to_a_mirror_off_the_route_list_is_followed_when_the_bytes_match(self):
        self.use({START: [redirect(SIGNED)], SIGNED: [ok()]})
        receipt, out = self.download()
        self.assertEqual(receipt['state'], 'PRESENT')
        attempt = receipt['attempts'][0]
        self.assertEqual(attempt['redirect_chain'], [dict(status=302, from_host='downloads.sourceforge.net',
            to_host='phoenixnap.dl.sourceforge.net', to_path='/project/freetype/freetype2/2.14.3/freetype-2.14.3.tar.xz',
            query='OMITTED_SIGNED')])
        self.assertEqual((attempt['final_host'], attempt['redirects'], attempt['http_status']),
                         ('phoenixnap.dl.sourceforge.net', 1, 200))
        self.assertEqual((self.root / 'freetype.tar.xz').read_bytes(), BODY)
        # The signed query string reaches curl but never the receipt or any saved file.
        saved = json.dumps(receipt) + ''.join(p.read_text(errors='replace') for p in out.rglob('*') if p.is_file())
        self.assertNotIn('SECRETTOKEN', saved)
        self.assertNotIn('SECRETTOKEN', (out / 'public-archives/freetype/receipt.json').read_text())

    def test_a_redirect_with_a_zero_length_body_does_not_leak_its_headers_into_a_chunked_final_response(self):
        # codeload.github.com answers 200 without Content-Length after a 302 that said `Content-Length: 0`.
        chunked = dict(status=200, headers={'Transfer-Encoding': 'chunked'}, body=BODY)
        zero = dict(status=302, headers={'Location': 'https://codeload.example.org/a/tar.gz/refs/tags/v1', 'Content-Length': '0'})
        self.use({START: [zero], 'https://codeload.example.org/a/tar.gz/refs/tags/v1': [chunked]})
        receipt, _ = self.download()
        self.assertEqual(receipt['state'], 'PRESENT')
        self.assertEqual(receipt['attempts'][0]['content_length'], 'EMPTY')

    def test_other_bytes_behind_a_redirect_are_refused(self):
        self.use({START: [redirect(SIGNED)], SIGNED: [ok(b'x' * len(BODY))]})
        with self.assertRaisesRegex(ValueError, 'archive checksum or size differs'):
            self.download()
        self.assertFalse((self.root / 'freetype.tar.xz').exists())

    def test_a_redirect_destination_that_is_not_plain_https_with_a_dns_name_is_refused(self):
        for location in ('http://mirror.example.org/a', 'https://192.0.2.7/a', 'https://user:pw@mirror.example.org/a',
                         'https://localhost/a', 'https://mirror.example.org:8443/a', 'https://printer.local/a',
                         'https://mirror.example.org/a#frag', ''):
            with self.subTest(location=location):
                self.use({START: [redirect(location)]})
                result = st.source_transfer(START, self.root / ('t%d' % len(self.net.calls) + str(abs(hash(location)))),
                                            len(BODY), 30, allowed_hosts=ROUTE)
                self.assertEqual(result['failure_stage'], 'REDIRECT_DESTINATION_REFUSED')
                self.assertFalse(result['retryable'])

    def test_more_than_five_redirects_are_refused(self):
        urls = ['https://hop%d.example.org/a' % i for i in range(8)]
        script = {START: [redirect(urls[0])]}
        script.update({urls[i]: [redirect(urls[i + 1])] for i in range(7)})
        self.use(script)
        result = st.source_transfer(START, self.root / 'chain', len(BODY), 30, allowed_hosts=ROUTE)
        self.assertEqual(result['failure_stage'], 'REDIRECT_DESTINATION_REFUSED')
        self.assertEqual(len(result['redirect_chain']), st.MAX_REDIRECTS)

    def test_the_requested_address_must_still_be_an_exact_route_host(self):
        self.use({})
        with self.assertRaisesRegex(ValueError, 'Public source origin refused'):
            st.source_transfer('https://elsewhere.example.org/a.tar.xz', self.root / 'x', 10, 30, allowed_hosts=ROUTE)
        with self.assertRaisesRegex(ValueError, 'Public source origin refused'):
            st.source_transfer('http://downloads.sourceforge.net/a.tar.xz', self.root / 'x', 10, 30, allowed_hosts=ROUTE)

    def test_every_transfer_uses_http_1_1_and_no_curlrc(self):
        net = self.use({START: [ok()]})
        self.download()
        argv = net.calls[0][1]
        self.assertIn('--http1.1', argv)
        self.assertEqual(argv[1], '--disable')
        self.assertIn('=https', argv)

    def test_a_connection_cut_after_progress_is_continued_with_a_range_request(self):
        cut = 4096
        net = self.use({START: [dict(status=200, rc=92, headers={'Content-Length': str(len(BODY))}, body=BODY[:cut]),
                                dict(status=206, headers={'Content-Range': 'bytes %d-%d/%d' % (cut, len(BODY) - 1, len(BODY))},
                                     body=BODY[cut:], append=True)]})
        receipt, _ = self.download()
        self.assertEqual(receipt['state'], 'PRESENT')
        attempt = receipt['attempts'][0]
        self.assertEqual((attempt['resumed_segments'], attempt['http_status'], attempt['content_length']), (1, 200, str(len(BODY))))
        self.assertEqual([s['status'] for s in attempt['segments']], [200, 206])
        self.assertIn('--continue-at', net.calls[1][1])
        self.assertNotIn('--continue-at', net.calls[0][1])
        self.assertEqual((self.root / 'freetype.tar.xz').read_bytes(), BODY)
        self.assertEqual(self.sleeps, [])

    def test_a_resumed_file_that_does_not_match_the_digest_is_still_refused(self):
        cut = 4096
        tampered = BODY[:cut] + b'\0' * (len(BODY) - cut)
        self.use({START: [dict(status=200, rc=92, headers={'Content-Length': str(len(BODY))}, body=BODY[:cut]),
                          dict(status=206, headers={'Content-Range': 'bytes %d-%d/%d' % (cut, len(BODY) - 1, len(BODY))},
                               body=tampered[cut:], append=True)]})
        with self.assertRaisesRegex(ValueError, 'archive checksum or size differs'):
            self.download()

    def test_a_server_that_ignores_the_range_makes_the_next_attempt_start_over_after_a_pause(self):
        cut = 4096
        self.use({START: [dict(status=200, rc=92, headers={'Content-Length': str(len(BODY))}, body=BODY[:cut]),
                          dict(status=200, rc=33, body=b''), ok()]})
        receipt, _ = self.download()
        self.assertEqual(receipt['state'], 'PRESENT')
        self.assertEqual(len(receipt['attempts']), 2)
        self.assertEqual(receipt['attempts'][0]['failure_reason'], 'server did not honour the byte range')
        self.assertEqual(self.sleeps, [10])
        self.assertEqual(receipt['attempts'][1]['pause_before_seconds'], 10)

    def test_server_errors_are_retried_three_times_with_growing_pauses_and_then_given_up(self):
        busy = dict(status=503, rc=56, headers={'Content-Length': '515'}, body=b'busy')
        self.use({START: [busy] * 4})
        with self.assertRaisesRegex(ValueError, 'Public archive FAILED'):
            self.download()
        self.assertEqual(self.sleeps, [10, 30, 60])
        receipt = json.loads((self.root / 'out/public-archives/freetype/receipt.json').read_text())
        self.assertEqual(len(receipt['attempts']), 4)
        self.assertEqual([a['pause_before_seconds'] for a in receipt['attempts']], [0, 10, 30, 60])
        self.assertEqual(receipt['attempts'][-1]['retry_budget'], 'EXHAUSTED')
        self.assertEqual(receipt['attempts'][0]['retry_policy'], dict(retries=3, pauses_seconds=[10, 30, 60]))

    def test_a_server_that_recovers_after_one_pause_is_accepted(self):
        self.use({START: [dict(status=503, rc=56, body=b'busy'), ok()]})
        receipt, _ = self.download()
        self.assertEqual((receipt['state'], len(receipt['attempts']), self.sleeps), ('PRESENT', 2, [10]))

    def test_a_missing_archive_is_not_retried(self):
        self.use({START: [dict(status=404, rc=22, body=b'no')]})
        with self.assertRaisesRegex(ValueError, 'Public archive FAILED'):
            self.download()
        self.assertEqual(self.sleeps, [])

    def test_install_replaces_the_name_the_shared_downloader_looks_up(self):
        source_download = SimpleNamespace(source_transfer=None)
        policy = st.install(source_download)
        self.assertIs(source_download.source_transfer, st.source_transfer)
        self.assertEqual(policy['pauses_seconds'], [10, 30, 60])
        sys.path.insert(0, str(HERE.parent / 'repro109deps'))
        import source_download as shared
        self.assertTrue(callable(getattr(shared, 'source_transfer', None)))

    def test_summary_lists_redirects_pauses_and_resumes_for_the_report(self):
        self.use({START: [dict(status=503, rc=56, body=b'busy'), redirect(SIGNED)], SIGNED: [ok()]})
        _, out = self.download()
        summary = st.summarize(out)
        row = summary['components']['freetype']
        self.assertEqual((summary['redirected'], summary['retried'], summary['failed']), (['freetype'], ['freetype'], []))
        self.assertEqual((row['pauses_seconds'], row['attempts'], row['final_hosts']),
                         ([10], 2, ['downloads.sourceforge.net', 'phoenixnap.dl.sourceforge.net']))
        self.assertNotIn('SECRETTOKEN', json.dumps(summary))


class Prepare(unittest.TestCase):
    def run_main(self, argv, **loaded):
        import prepare_sources
        source_download = SimpleNamespace(source_transfer=None)
        dep = SimpleNamespace(source_download=source_download, read_lock=lambda: dict(toolchain={}, components=[]),
                              cloud_guard=mock.Mock())
        preflight = SimpleNamespace(dep=dep, collect=mock.Mock(**loaded.get('collect', {})), extract_inputs=mock.Mock())
        with mock.patch.object(prepare_sources.full, 'check_inputs'), \
             mock.patch.object(prepare_sources.full, 'load_driver', return_value=preflight), \
             mock.patch.object(prepare_sources.full, 'apply_profile',
                               side_effect=lambda lock, profile: dict(lock, profile=profile)):
            return prepare_sources.main(argv), preflight, source_download

    def test_collect_installs_the_transport_selects_the_profile_and_writes_the_summary(self):
        with tempfile.TemporaryDirectory(dir=os.environ['REPRO109_TEST_TMP']) as directory:
            work = Path(directory) / 'inputs'

            def collect(root, lock, workers, minutes):
                (Path(root) / 'reports').mkdir(parents=True)
                collect.seen = (lock['profile'], workers, minutes)
                return dict(status='ALL_SOURCE_INPUTS_PRESENT_NOT_BUILT')
            code, preflight, source_download = self.run_main(
                ['--work', str(work), '--profile', 'github-macos26-arm64', '--minutes', '9'], collect=dict(side_effect=collect))
            self.assertEqual(code, 0)
            self.assertIs(source_download.source_transfer, st.source_transfer)
            self.assertEqual(collect.seen, ('github-macos26-arm64', 8, 9))
            summary = json.loads((work / 'reports/source-transport-summary.json').read_text())
            self.assertEqual(summary['failed'], [])
            self.assertEqual(summary['policy']['pauses_seconds'], [10, 30, 60])

    def test_a_failed_source_set_gives_a_failing_exit_status(self):
        with tempfile.TemporaryDirectory(dir=os.environ['REPRO109_TEST_TMP']) as directory:
            work = Path(directory) / 'inputs'

            def collect(root, lock, workers, minutes):
                (Path(root) / 'reports').mkdir(parents=True)
                return dict(status='SOURCE_INPUTS_FAILED_NO_BUILD')
            code, _, _ = self.run_main(['--work', str(work)], collect=dict(side_effect=collect))
            self.assertEqual(code, 1)

    def test_extract_rehashes_without_any_download(self):
        code, preflight, source_download = self.run_main(['--work', '/nonexistent/x', '--extract', '/nonexistent/a.tar.gz'])
        self.assertEqual(code, 0)
        preflight.extract_inputs.assert_called_once()
        preflight.collect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
