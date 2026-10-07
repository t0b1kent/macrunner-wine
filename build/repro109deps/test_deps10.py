"""Actual host guards and owned port-observer controls; all processes disk-fed."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import create_autospec, patch

import build_deps as deps
import port_probe
import private_curl
import public_archive
import source_download as source
from source_fixes import gnutls_port_observation


class Deps10Tests(unittest.TestCase):
    def test_route_coverage_and_component_specific_official_hosts(self):
        rows = [r for r in deps.read_lock()['components'] if r.get('source_kind') != 'git']
        routes = source.read_routes()['routes']
        self.assertEqual(len(routes), 46)
        for r in rows:
            self.assertEqual(routes[r['name']]['url'], r['url'])
        for name in ['libogg', 'opus', 'libvorbis', 'flac', 'theora']:
            self.assertEqual(routes[name]['allowed_hosts'], ['downloads.xiph.org', 'ftp.osuosl.org'])
        self.assertEqual(routes['gnutls']['allowed_hosts'], ['www.gnupg.org'])

    def test_malformed_and_cross_component_routes_refused_before_curl(self):
        routes = source.read_routes()
        mutations = [lambda d: d.update(deps_lock_sha256='0'*64),
                     lambda d: d['routes'].pop('libogg'),
                     lambda d: d['routes']['libogg'].update(url='https://foreign.invalid/archive'),
                     lambda d: d['routes']['libogg'].update(allowed_hosts=['downloads.xiph.org','github.com']),
                     lambda d: d['routes']['libogg'].update(allowed_hosts=['downloads.xiph.org','*.xiph.org']),
                     lambda d: d['routes']['libogg'].update(allowed_hosts=['downloads.xiph.org',{}]),
                     lambda d: d['routes']['libogg'].update(allowed_hosts=['downloads.xiph.org']*2)]
        for mutate in mutations:
            d = copy.deepcopy(routes); mutate(d)
            with self.subTest(mutate=mutate), patch.object(Path,'read_text',return_value=json.dumps(d)), \
                 patch.object(private_curl.subprocess,'run',autospec=True) as process:
                with self.assertRaises(ValueError): source.read_routes()
                process.assert_not_called()

    def xiph(self, candidate, bad_body=False, second_hop=None):
        origin='https://downloads.xiph.org/releases/ogg/libogg-1.3.6.tar.gz'
        calls=[]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); body=b'owned-archive'; target=root/'archive'
            def run(argv, **kwargs):
                calls.append((argv,kwargs)); number=len(calls)
                config=kwargs['input'].decode()
                url=json.loads(next(s[6:] for s in config.splitlines() if s.startswith('url = ')))
                final=number > (2 if second_hop else 1)
                location=second_hop if number==2 and second_hop else candidate
                code=200 if final else 302
                payload=(b'wrong-archive' if bad_body else body) if final else b'owned-302'
                Path(argv[argv.index('--output')+1]).write_bytes(payload)
                headers='HTTP/1.1 '+str(code)+' OK\r\nContent-Length: '+str(len(payload))+'\r\n'
                if code==302:headers+='Location: '+location+'\r\n'
                return subprocess.CompletedProcess(argv,0,(headers+'\r\n'+private_curl.MARKER+str(code)+'\n'+url+'\n').encode(),b'')
            transfer=lambda url,target,limit,timeout_seconds: private_curl.source_transfer(
                url,target,limit,timeout_seconds,allowed_hosts=['downloads.xiph.org','ftp.osuosl.org'])
            row=dict(name='libogg',url=origin,size=len(body),sha256=hashlib.sha256(body).hexdigest())
            with patch.dict(os.environ,{'RESULTS_TOKEN':'owned-secret','GH_TOKEN':'owned-secret'}), \
                 patch.object(private_curl.subprocess,'run',autospec=True,side_effect=run), \
                 patch.object(public_archive.time,'sleep'):
                try: receipt=public_archive.download(row,target,root/'out',transfer=transfer); error=None
                except ValueError as e: receipt=None;error=str(e)
            exists=target.exists()
            for argv,kwargs in calls:
                self.assertNotIn('--location',argv)
                self.assertNotIn(b'Authorization:',kwargs['input'])
                self.assertNotIn(b'owned-secret',kwargs['input'])
                self.assertFalse({'RESULTS_TOKEN','GH_TOKEN','GITHUB_TOKEN'} & set(kwargs['env']))
            return receipt,error,exists,calls

    def test_official_xiph_redirect_and_sha_accepted(self):
        r,e,exists,calls=self.xiph('https://ftp.osuosl.org/pub/xiph/releases/ogg/libogg-1.3.6.tar.gz')
        self.assertIsNone(e);self.assertTrue(exists);self.assertEqual(len(calls),2)
        self.assertEqual(r['attempts'][0]['final_host'],'ftp.osuosl.org')

    def test_mirror_subdomain_suffix_credentials_http_port_fragment_and_foreign_refused(self):
        for location in ['https://ftp.osuosl.org.foreign.invalid/a','https://other.osuosl.org/a',
                         'https://github.com/a','http://ftp.osuosl.org/a','https://u:p@ftp.osuosl.org/a',
                         'https://ftp.osuosl.org:444/a','https://ftp.osuosl.org/a#fragment']:
            with self.subTest(location=location):
                r,e,exists,calls=self.xiph(location)
                self.assertIsNone(r);self.assertFalse(exists);self.assertEqual(len(calls),1)
                self.assertIn('refused',e)

    def test_each_hop_checked_before_request(self):
        r,e,exists,calls=self.xiph('https://ftp.osuosl.org/a',second_hop='https://github.com/foreign')
        self.assertIsNone(r);self.assertFalse(exists);self.assertEqual(len(calls),2)

    def test_official_mirror_wrong_sha_never_accepted(self):
        r,e,exists,calls=self.xiph('https://ftp.osuosl.org/a',bad_body=True)
        self.assertIsNone(r);self.assertFalse(exists);self.assertIn('checksum',e)

    def test_observer_exact_upstream_source_guard_and_preserved_return(self):
        original=(Path(__file__).parent/'fixtures/gnutls-common-3.8.13.sh').read_bytes()
        after,count=gnutls_port_observation(original);self.assertEqual(count,2)
        with self.assertRaises(ValueError):gnutls_port_observation(original+b'foreign')
        # Execute ONLY our authored suffix inside an entirely owned shell fixture.
        start=after.index(b'\trepro109_port_rc=$?')
        suffix=after[start:after.index(b'\n}',start)].decode()
        with tempfile.TemporaryDirectory() as directory:
            for expected,command in [(0,'true'),(1,'false')]:
                script='abs_top_builddir='+directory+'\nREPRO109_PORT_PYTHON=/usr/bin/false\nREPRO109_PORT_PROBE=unused\n'
                script+='owned() {\n'+command+'\n'+suffix+'\n}\nowned; r=$?; printf "%s\\n" "$r"\n'
                child=subprocess.run(['/bin/sh'],input=script.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
                self.assertEqual(child.returncode,0);self.assertEqual(child.stdout,str(expected).encode()+b'\n')
                self.assertEqual(child.stderr,b'')

    def observe(self,replies):
        call=create_autospec(subprocess.run,side_effect=replies)
        with patch.object(port_probe.shutil,'which',return_value='/usr/sbin/netstat'):
            report=port_probe.observe('netstat',12345,run=call)
        self.assertEqual(call.call_count,2)
        for args,kwargs in call.call_args_list:
            self.assertEqual(kwargs['timeout'],5);self.assertEqual(kwargs['env']['LC_ALL'],'C')
        return report

    def test_port_observer_retains_owned_lines_only_and_distinguishes_empty(self):
        raw=b'tcp4 0 0 *.12345 *.* LISTEN\nUNRELATED OWNED-FIXTURE *.9999 *.* LISTEN\n'
        r=self.observe([subprocess.CompletedProcess([],0,raw,b''),subprocess.CompletedProcess([],0,b'',b'')])
        self.assertEqual(r['observations'][0]['owned_lines'],['tcp4 0 0 *.12345 *.* LISTEN\n'])
        self.assertEqual(r['observations'][0]['upstream_LISTEN_matches'],1)
        self.assertEqual(r['observations'][1]['state'],'EMPTY')
        self.assertNotIn('UNRELATED',json.dumps(r))

    def test_port_observer_caps_errors_timeouts_and_native_path(self):
        r=self.observe([subprocess.CompletedProcess([],1,b'x'*(256*1024+1),b''),
                        subprocess.TimeoutExpired(['netstat'],5)])
        self.assertEqual(r['observations'][0]['state'],'DROPPED')
        self.assertEqual(r['observations'][1]['reason'],'TIMEOUT')
        with patch.object(port_probe.shutil,'which',return_value='/foreign/netstat'):
            self.assertEqual(port_probe.observe('netstat',12345)['state'],'FAILED')
        for port in [0,65536,True]:
            with self.assertRaises(ValueError):port_probe.observe('netstat',port)
