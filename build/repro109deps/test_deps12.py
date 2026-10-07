"""Real transport/adapter functions with own disk-fed and loopback fixtures."""
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import port_probe
import private_curl
import public_archive
import source_download
from source_fixes import gnutls_port_observation

HERE = Path(__file__).resolve().parent


class Deps12Tests(unittest.TestCase):
    def route(self, name, location, bad_sha=False):
        route = source_download.read_routes()['routes'][name]
        body = b'own inert archive fixture'
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'archive'
            def child(argv, **kwargs):
                calls.append((argv, kwargs))
                config = kwargs['input'].decode()
                url = json.loads(next(s[6:] for s in config.splitlines() if s.startswith('url = ')))
                final = len(calls) == 2
                payload = body if final else b'own 302'
                Path(argv[argv.index('--output') + 1]).write_bytes(payload)
                code = 200 if final else 302
                headers = 'HTTP/1.1 ' + str(code) + ' OK\r\nContent-Length: ' + str(len(payload)) + '\r\n'
                if not final:
                    headers += 'Location: ' + location + '\r\n'
                return subprocess.CompletedProcess(argv, 0,
                    (headers + '\r\n' + private_curl.MARKER + str(code) + '\n' + url + '\n').encode(), b'')
            transfer = lambda url, path, cap, timeout_seconds: private_curl.source_transfer(
                url, path, cap, timeout_seconds, allowed_hosts=route['allowed_hosts'])
            request = dict(name=name, url=route['url'], size=len(body),
                           sha256='0' * 64 if bad_sha else hashlib.sha256(body).hexdigest())
            with patch.object(private_curl.subprocess, 'run', side_effect=child), \
                 patch.object(public_archive.time, 'sleep'):
                try:
                    receipt = public_archive.download(request, target, root / 'out', transfer=transfer)
                    error = None
                except ValueError as exc:
                    receipt, error = None, str(exc)
            accepted = target.exists()
            for argv, kwargs in calls:
                self.assertNotIn('--location', argv)
                self.assertNotIn(b'Authorization:', kwargs['input'])
                self.assertFalse({'GH_TOKEN', 'RESULTS_TOKEN', 'GITHUB_TOKEN'} & set(kwargs['env']))
            return receipt, error, accepted, calls

    def test_exact_b27_mirrors_and_integrity(self):
        for name, host in [('libpng', 'psychz.dl.sourceforge.net'),
                           ('lame', 'phoenixnap.dl.sourceforge.net')]:
            with self.subTest(name=name):
                result, error, accepted, calls = self.route(name, 'https://' + host + '/own-fixture')
                self.assertIsNone(error)
                self.assertTrue(accepted)
                self.assertEqual(len(calls), 2)
                self.assertEqual(result['attempts'][0]['final_host'], host)
                result, error, accepted, calls = self.route(name, 'https://' + host + '/own-fixture', True)
                self.assertIsNone(result)
                self.assertFalse(accepted)
                self.assertEqual(len(calls), 2)
                self.assertIn('checksum', error)

    def test_foreign_cross_component_and_suffix_redirects_refused_before_request(self):
        for name, host in [('libpng', 'psychz.dl.sourceforge.net'),
                           ('lame', 'phoenixnap.dl.sourceforge.net')]:
            other = 'phoenixnap.dl.sourceforge.net' if name == 'libpng' else 'psychz.dl.sourceforge.net'
            for location in ['https://foreign.invalid/a', 'https://' + other + '/a',
                             'https://' + host + '.foreign.invalid/a', 'http://' + host + '/a',
                             'https://u:p@' + host + '/a', 'https://' + host + ':444/a']:
                with self.subTest(name=name, location=location):
                    result, error, accepted, calls = self.route(name, location)
                    self.assertIsNone(result)
                    self.assertFalse(accepted)
                    self.assertEqual(len(calls), 1)
                    self.assertIn('refused', error)

    def test_route_cross_component_grant_refused(self):
        original = source_download.read_routes()
        for name, foreign in [('libpng', 'phoenixnap.dl.sourceforge.net'),
                              ('lame', 'psychz.dl.sourceforge.net')]:
            mutated = copy.deepcopy(original)
            mutated['routes'][name]['allowed_hosts'].append(foreign)
            with patch.object(Path, 'read_text', return_value=json.dumps(mutated)):
                with self.assertRaises(ValueError):
                    source_download.read_routes()

    def test_owned_listener_and_closed_port_real_functions_and_cli(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(('127.0.0.1', 0))
            port = server.getsockname()[1]
            result = port_probe.readiness(port)
            self.assertEqual(result['rc'], 1)
            self.assertIn(result['state'], ['EMPTY', 'FAILED'])
            server.listen(4)
            result = port_probe.readiness(port)
            self.assertEqual(result['rc'], 0)
            self.assertEqual(result['state'], 'PRESENT')
            run = subprocess.run([sys.executable, '-B', '-I', str(HERE / 'port_probe.py'),
                                  '--check-listening', '--port', str(port)],
                                 stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stdout, b'')

    def test_connect_timeout_and_input_guards(self):
        def timeout(*args, **kwargs):
            self.assertEqual(args, (('127.0.0.1', 12345),))
            self.assertEqual(kwargs, dict(timeout=0.5))
            raise socket.timeout()
        result = port_probe.readiness(12345, connector=timeout)
        self.assertEqual(result['rc'], 1)
        self.assertEqual(result['reason'], 'CONNECT_TIMEOUT')
        def refused(*args, **kwargs):
            raise OSError(errno.ECONNREFUSED, 'own fixture')
        self.assertEqual(port_probe.readiness(12345, connector=refused)['state'], 'EMPTY')
        for value in [0, 65536, True, '12345']:
            with self.assertRaises(ValueError):
                port_probe.readiness(value, connector=timeout)

    def test_authored_darwin_and_other_platform_adapter_real_shell(self):
        original = (HERE / 'fixtures/gnutls-common-3.8.13.sh').read_bytes()
        after, count = gnutls_port_observation(original)
        self.assertEqual(count, 2)
        start = after.index(b'\tif test "$(uname -s)"')
        body = after[start:after.index(b'\n}', start)].decode()
        for platform, probe_rc, listen, expected in [('Darwin', 0, False, 0),
                                                     ('Darwin', 1, True, 1),
                                                     ('Linux', 1, True, 0)]:
            with self.subTest(platform=platform, expected=expected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tools = root / 'tools'
                tools.mkdir()
                for name, text in [
                    ('uname', '#!/bin/sh\nprintf "%s\\n" "$OWN_PLATFORM"\n'),
                    ('netstat', '#!/bin/sh\n' + ('printf "tcp4 0 0 *.12345 *.* LISTEN\\n"\n' if listen else 'exit 1\n')),
                    ('python', '#!/bin/sh\ncase "$*" in *--check-listening*) exit "$OWN_PROBE_RC";; *) exit 0;; esac\n')]:
                    path = tools / name
                    path.write_text(text)
                    path.chmod(0o755)
                env = dict(PATH=str(tools) + ':/usr/bin:/bin', OWN_PLATFORM=platform,
                           OWN_PROBE_RC=str(probe_rc), REPRO109_PORT_PYTHON=str(tools / 'python'),
                           REPRO109_PORT_PROBE='own-inert-probe', abs_top_builddir=str(root),
                           PFCMD=str(tools / 'netstat'))
                script = 'owned() {\nlocal PORT="$1"\n' + body + '\n}\nowned 12345; rc=$?; printf "%s\\n" "$rc"\n'
                run = subprocess.run(['/bin/sh'], input=script.encode(), env=env,
                                     capture_output=True, timeout=5)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(run.stdout, str(expected).encode() + b'\n')
                self.assertEqual(run.stderr, b'')
