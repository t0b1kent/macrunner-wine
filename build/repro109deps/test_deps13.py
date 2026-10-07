"""Measured b28 boundaries: passive owned listener, timeout, link inputs."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import build_deps
import deps13_support
import port_probe
from source_fixes import gnutls_port_observation

HERE = Path(__file__).resolve().parent

class Deps13Tests(unittest.TestCase):
    def test_passive_parser_ipv4_ipv6_wildcard_and_owned_scope(self):
        for address in [b'127.0.0.1:3456', b'[::1]:3456', b'*:3456']:
            def fake(argv, **kwargs):
                self.assertEqual(argv, ['/usr/sbin/lsof','-nP','-a','-p','123','-iTCP:3456','-sTCP:LISTEN','-F','pfn'])
                return subprocess.CompletedProcess(argv, 0, b'p123\nf9\nn'+address+b'\n', b'')
            with patch.object(socket, 'create_connection', side_effect=AssertionError('Protocol connection forbidden')):
                self.assertEqual(port_probe.owned_listener(3456, 123, fake)['rc'], 0)

    def test_passive_query_does_not_consume_one_shot_listener(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));listener.listen(1)
            report=port_probe.owned_listener(listener.getsockname()[1],os.getpid())
            self.assertEqual((report['state'],report['rc']),('PRESENT',0))
            listener.settimeout(0.05)
            with self.assertRaises(socket.timeout):listener.accept()

    def test_passive_cli_does_not_consume_listener(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));listener.listen(1)
            child=subprocess.run([sys.executable,'-B','-I',str(HERE/'port_probe.py'),
                 '--check-listening','--port',str(listener.getsockname()[1]),'--owned-pid',str(os.getpid())],
                 stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
            self.assertEqual(child.returncode,0)
            listener.settimeout(0.05)
            with self.assertRaises(socket.timeout):listener.accept()

    def test_foreign_pid_or_port_cannot_be_ready(self):
        for data in [b'p124\nf9\nn*:3456\n',b'p123\nf9\nn*:34560\n',b'p123\np124\nn*:3456\n']:
            fake=lambda argv, **kwargs:subprocess.CompletedProcess(argv,0,data,b'')
            self.assertEqual(port_probe.owned_listener(3456,123,fake)['rc'],1)

    def test_listener_empty_failure_and_dropped_are_distinct(self):
        for rc,data,state in [(1,b'','EMPTY'),(2,b'','FAILED'),(0,b'x'*65537,'DROPPED')]:
            fake=lambda argv, **kwargs:subprocess.CompletedProcess(argv,rc,data,b'')
            report=port_probe.owned_listener(3456,123,fake)
            self.assertEqual((report['state'],report['rc']),(state,1))
        def expired(*args,**kwargs):raise subprocess.TimeoutExpired(args[0],2)
        self.assertEqual(port_probe.owned_listener(3456,123,expired)['reason'],'TIMEOUT')

    def test_listener_rejects_invalid_scope_before_native_query(self):
        for port,pid in [(0,123),(65536,123),(True,123),(3456,0),(3456,1),(3456,True)]:
            with self.assertRaises(ValueError):port_probe.owned_listener(port,pid)

    def timeout(self, *args):
        return subprocess.run([sys.executable,'-B','-I',str(HERE/'native_timeout.py'),*args],
                              stdin=subprocess.DEVNULL,capture_output=True,timeout=5)

    def test_timeout_preserves_success_argv_and_returncode(self):
        result=self.timeout('2',sys.executable,'-c','import sys; print(sys.argv[1]); sys.exit(17)','a b')
        self.assertEqual((result.returncode,result.stdout),(17,b'a b\n'))

    def test_timeout_bounds_owned_session_and_reaps_leader(self):
        code='import os,signal,sys,time; signal.signal(signal.SIGTERM,lambda *a:sys.exit(0)); print(os.getpid(),flush=True); time.sleep(5)'
        result=self.timeout('0.2',sys.executable,'-c',code)
        self.assertEqual(result.returncode,124)
        pid=int(result.stdout.strip())
        with self.assertRaises(ProcessLookupError):os.kill(pid,0)

    def test_timeout_version_and_invalid_inputs(self):
        self.assertEqual(self.timeout('--version').returncode,0)
        self.assertEqual(self.timeout('0',sys.executable).returncode,125)
        self.assertEqual(self.timeout('nan',sys.executable).returncode,125)
        self.assertEqual(self.timeout('1','/repro109-owned-command-that-does-not-exist').returncode,127)

    def test_timeout_installer_quotes_paths_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'prefix with space';events=[]
            env=deps13_support.component_environment({'name':'gnutls'},{'LDFLAGS':''},root,HERE,root,
                                                    lambda *a,**kw:events.append(kw))
            result=subprocess.run([env['TIMEOUT'],'1',sys.executable,'-c','print("owned")'],capture_output=True,timeout=5)
            self.assertEqual((result.returncode,result.stdout),(0,b'owned\n'))
            self.assertEqual(Path(env['TIMEOUT']).name, 'timeout')
            literal_env = dict(os.environ, PATH=str(root/'bin')+':/usr/bin:/bin')
            literal = subprocess.run(['/bin/sh', '-c', 'timeout 1 "$1" -c \'print("literal")\'',
                                      'owned-fixture', sys.executable], env=literal_env,
                                     stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
            self.assertEqual((literal.returncode,literal.stdout),(0,b'literal\n'))
            self.assertEqual(events[0]['purpose'],'BUILD_TEST_TOOL_NOT_RUNTIME_PAYLOAD')
            with self.assertRaises(ValueError):deps13_support.component_environment({'name':'gnutls'},{},root,HERE,root,lambda *a,**kw:None)

    def test_relative_rpath_covers_all_gstreamer_plugin_families(self):
        lock=json.loads((HERE/'deps.lock.json').read_text());rows=[r for r in lock['components'] if r.get('gst_plugins')]
        self.assertEqual(len(rows),6)
        for row in rows:
            env=deps13_support.component_environment(row,{'LDFLAGS':'-L/prefix/lib'},Path('/prefix'),HERE,Path('/out'),lambda *a,**kw:None)
            self.assertEqual(env['LDFLAGS'],'-L/prefix/lib -Wl,-rpath,@loader_path/..')
        env=deps13_support.component_environment({'name':'glib'},{'LDFLAGS':'-L/prefix/lib'},Path('/prefix'),HERE,Path('/out'),lambda *a,**kw:None)
        self.assertEqual(env['LDFLAGS'],'-L/prefix/lib')

    def test_ffmpeg_sdk_iconv_is_enabled_and_linked(self):
        row=next(r for r in json.loads((HERE/'deps.lock.json').read_text())['components'] if r['name']=='ffmpeg')
        configure=build_deps.build_steps(row,Path('/owned/source'),Path('/owned/prefix'),Path('/owned/sdk'),4)[0]
        self.assertIn('--enable-iconv',configure)
        self.assertEqual(configure.count('--extra-libs=-liconv'),1)
        self.assertEqual(row['sha256'],'b6863adde98898f42602017462871b5f6333e65aec803fdd7a6308639c52edf3')

    def test_real_gnutls_transform_never_connects_for_readiness(self):
        original=(HERE/'fixtures/gnutls-common-3.8.13.sh').read_bytes()
        transformed,count=gnutls_port_observation(original)
        self.assertEqual(count,2)
        self.assertNotIn(b'--tcp',transformed)
        self.assertEqual(transformed.count(b'--owned-pid'),3)
        self.assertIn(b'${PID:-${TLS_SERVER_PID:-${OCSP_PID:-0}}}',transformed)
        with self.assertRaises(ValueError):gnutls_port_observation(original+b'foreign')

if __name__=='__main__':
    unittest.main()
