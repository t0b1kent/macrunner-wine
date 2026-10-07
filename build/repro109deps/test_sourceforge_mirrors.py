"""SourceForge family controls with owned bytes and inert curl responses."""
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
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'repro109'))
import source_download as source
import private_curl
import public_archive

COMPONENTS = ('lame', 'libpng', 'freetype')


class SourceForgeMirrorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.body = b'owned-sourceforge-archive'
        self.routes = source.read_routes()['routes']

    def exercise(self, component, responses):
        root = self.root / str(len(list(self.root.iterdir())))
        root.mkdir()
        destination, out = root / 'accepted.archive', root / 'out'
        out.mkdir()
        route = self.routes[component]
        urls = [route['url']] + route['mirror_urls']
        request = dict(name=component, url=urls[0], source_urls=urls,
                       source_route=dict(allowed_hosts=route['allowed_hosts']),
                       size=len(self.body), sha256=hashlib.sha256(self.body).hexdigest())
        seen, sequence = [], iter(responses)

        def run(argv, **kwargs):
            config = kwargs['input'].decode()
            url = json.loads(config.splitlines()[0].partition(' = ')[2])
            seen.append(url)
            self.assertNotIn('Authorization:', config)
            self.assertNotIn('owned-secret', config)
            self.assertFalse({'RESULTS_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN'} & set(kwargs['env']))
            self.assertNotIn('--location', argv)
            self.assertNotIn('-L', argv)
            code, status, body, location = next(sequence)
            Path(argv[argv.index('--output') + 1]).write_bytes(body)
            headers = 'HTTP/1.1 %d Owned\r\nContent-Length: %d\r\n' % (status, len(body))
            if location:
                headers += 'Location: ' + location + '\r\n'
            return subprocess.CompletedProcess(argv, code,
                (headers + '\r\n' + private_curl.MARKER + str(status) + '\n' + url + '\n').encode(), b'')

        with patch.object(private_curl.subprocess, 'run', side_effect=run), \
             patch.object(public_archive.time, 'sleep'), \
             patch.dict(os.environ, dict(RESULTS_TOKEN='owned-secret', GH_TOKEN='owned-secret', GITHUB_TOKEN='owned-secret')):
            try:
                result = public_archive.download(request, destination, out,
                    transfer=lambda *args, **kwargs: private_curl.source_transfer(
                        *args, allowed_hosts=route['allowed_hosts'], **kwargs))
                error = None
            except ValueError as failure:
                result, error = None, str(failure)
        receipt = json.loads((out / 'public-archives' / component / 'receipt.json').read_text())
        return result, error, receipt, seen, destination

    def unknown(self, component):
        host = {'lame': 'pilotfiber.dl.sourceforge.net',
                'libpng': 'phoenixnap.dl.sourceforge.net',
                'freetype': 'unlisted.dl.sourceforge.net'}[component]
        path = urlparse(self.routes[component]['url']).path
        return (0, 302, b'owned redirect error', 'https://' + host + path + '?owned-query=redacted')

    def test_b40_refused_redirects_and_sibling_select_pinned_first_mirror(self):
        for component in COMPONENTS:
            with self.subTest(component=component):
                result, error, receipt, seen, destination = self.exercise(component,
                    [self.unknown(component), (0, 200, self.body, None)])
                route = self.routes[component]
                self.assertIsNone(error)
                self.assertEqual(seen, [route['url'], route['mirror_urls'][0]])
                self.assertEqual(result['selected_source_host'], 'cfhcable.dl.sourceforge.net')
                self.assertEqual(destination.read_bytes(), self.body)
                self.assertEqual(receipt['attempts'][0]['failure_stage'], 'REDIRECT_DESTINATION_REFUSED')
                self.assertTrue(receipt['attempts'][0]['fallback_next_source'])
                self.assertNotIn('owned-query', json.dumps(receipt))

    def test_primary_success_contacts_only_primary(self):
        for component in COMPONENTS:
            with self.subTest(component=component):
                result, error, receipt, seen, destination = self.exercise(component,
                    [(0, 200, self.body, None)])
                self.assertIsNone(error)
                self.assertEqual(seen, [self.routes[component]['url']])
                self.assertEqual(result['selected_source_index'], 0)

    def test_failed_first_mirror_selects_second_under_existing_budget(self):
        for component in COMPONENTS:
            with self.subTest(component=component), patch.object(public_archive.time, 'monotonic', return_value=0):
                result, error, receipt, seen, destination = self.exercise(component,
                    [self.unknown(component), (35, 0, b'', None), (0, 200, self.body, None)])
                self.assertIsNone(error)
                self.assertEqual(seen, [self.routes[component]['url']] + self.routes[component]['mirror_urls'])
                self.assertEqual(result['selected_source_host'], 'gigenet.dl.sourceforge.net')
                self.assertEqual([row['timeout_seconds'] for row in receipt['attempts']], [50, 75, 90])

    def test_six_attempt_cap_does_not_restart_route_or_contact_unlisted_hosts(self):
        for component in COMPONENTS:
            with self.subTest(component=component):
                result, error, receipt, seen, destination = self.exercise(component,
                    [self.unknown(component)] + [(35, 0, b'', None)] * 5)
                urls = [self.routes[component]['url']] + self.routes[component]['mirror_urls']
                self.assertIsNotNone(error)
                self.assertEqual(seen, urls[:2] + urls[2:] * 4)
                self.assertEqual(len(receipt['attempts']), 6)
                self.assertEqual(receipt['time_cap_seconds'], 150)
                self.assertFalse(destination.exists())

    def test_checksum_failure_tries_every_remaining_source(self):
        for component in COMPONENTS:
            for index in range(3):
                with self.subTest(component=component, source_index=index):
                    prefix = ([self.unknown(component)] + [(35, 0, b'', None)] * (index - 1)) if index else []
                    result, error, receipt, seen, destination = self.exercise(component,
                        prefix + [(0, 200, b'X' * len(self.body), None)] * (3 - index))
                    self.assertIsNotNone(error)
                    self.assertEqual(len(seen), 3)
                    self.assertEqual(receipt['attempts'][-1]['failure_reason'], 'archive checksum or size differs')
                    self.assertFalse(receipt['attempts'][-1]['fallback_next_source'])
                    self.assertFalse(destination.exists())

    def test_certificate_refusal_is_terminal_for_family(self):
        for component in COMPONENTS:
            with self.subTest(component=component):
                result, error, receipt, seen, destination = self.exercise(component,
                    [(60, 0, b'', None)])
                self.assertIsNotNone(error)
                self.assertEqual(len(seen), 1)
                self.assertFalse(receipt['attempts'][0]['fallback_next_source'])

    def test_real_download_requests_preserve_all_three_source_sha_and_sizes(self):
        rows = json.loads((HERE / 'deps.lock.json').read_bytes())['components']
        pins = source.read_pins()['component_sizes_lines']
        for row in rows:
            if row['name'] not in COMPONENTS:
                continue
            with self.subTest(component=row['name']), patch.object(public_archive, 'download', return_value={}) as call:
                source.download(row, Path('owned-unused'), Path('owned-out'))
                request = call.call_args[0][0]
                self.assertEqual(request['sha256'], row['sha256'])
                self.assertEqual(request['size'], pins[row['name']][0])
                self.assertEqual(request['source_urls'], [row['url']] + self.routes[row['name']]['mirror_urls'])
                self.assertEqual(len(request['source_urls']), 3)

    def test_route_lock_rejects_changed_project_order_host_protocol_query_and_missing_mirrors(self):
        original = source.read_routes()
        for component in COMPONENTS:
            mirrors = original['routes'][component]['mirror_urls']
            changes = [None, list(reversed(mirrors)), mirrors[:1],
                       [mirrors[0].replace('/project/' + component + '/', '/project/foreign/'), mirrors[1]],
                       [mirrors[0].replace('https://', 'http://'), mirrors[1]],
                       [mirrors[0] + '?query=owned', mirrors[1]],
                       [mirrors[0] + '#owned', mirrors[1]],
                       [mirrors[0].replace('cfhcable.dl.sourceforge.net', 'cfhcable.dl.sourceforge.net.foreign.invalid'), mirrors[1]]]
            for changed in changes:
                with self.subTest(component=component, changed=changed):
                    routes = copy.deepcopy(original)
                    routes['routes'][component]['mirror_urls'] = changed
                    fixture = self.root / 'locks'
                    fixture.mkdir(exist_ok=True)
                    (fixture / 'deps.lock.json').write_bytes((HERE / 'deps.lock.json').read_bytes())
                    (fixture / 'source-routes.lock.json').write_text(json.dumps(routes))
                    with patch.object(source, 'HERE', fixture), self.assertRaises(ValueError):
                        source.read_routes()


if __name__ == '__main__':
    unittest.main()
