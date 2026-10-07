"""Own synthetic archives and mocked curl; no external download or tool execution."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import build_deps as deps
import source_download as source
import private_curl
import public_archive
# Shared transport changes must retain the complete established FEX controls.
from test_public_archive import PublicArchiveTests, PublicCurlTests


class SourceDownloadTests(unittest.TestCase):
    def test_44_measured_sizes_and_two_explicit_unknowns_bind_exact_lock(self):
        pins = source.read_pins()
        self.assertEqual(len(pins['component_sizes_lines']), 44)
        self.assertEqual(pins['unpinned_sizes'], ['ffmpeg', 'gst-libav'])
        rows = deps.read_lock()['components']
        for row in rows:
            if row.get('source_kind') == 'git':
                continue
            with self.subTest(component=row['name']), patch.object(public_archive, 'download', return_value={}) as call:
                source.download(row, Path('owned-unused'), Path('owned-out'))
                args, kwargs = call.call_args
                self.assertEqual(args[0]['sha256'], row['sha256'])
                self.assertIs(kwargs['transfer'].func, source.source_transfer)
                self.assertEqual(kwargs['transfer'].keywords['allowed_hosts'],
                                 source.read_routes()['routes'][row['name']]['allowed_hosts'])
                self.assertEqual('size' in args[0], row['name'] in pins['component_sizes_lines'])

    def test_modified_source_url_or_digest_never_reaches_transport(self):
        original = deps.read_lock()['components'][0]
        for key in ['url', 'sha256']:
            row = copy.deepcopy(original); row[key] = 'foreign'
            with patch.object(public_archive, 'download') as call:
                with self.assertRaisesRegex(ValueError, 'locked publisher'):
                    source.download(row, Path('unused'), Path('unused'))
                call.assert_not_called()

    def test_unknown_exact_size_still_requires_full_sha_and_preserves_partial(self):
        raw = b'owned-archive'
        row = dict(name='ffmpeg', url='https://ffmpeg.org/owned', maximum_size=64,
                   sha256=hashlib.sha256(raw).hexdigest())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); dest = root/'archive'; out = root/'out'
            replies = iter([raw[:3], raw])
            def transfer(url, target, limit, timeout_seconds):
                body = next(replies); target.write_bytes(body)
                return dict(curl_rc=18 if len(body) != len(raw) else 0, retryable=len(body) != len(raw),
                            http_status=200, content_length=str(len(raw)), content_encoding='identity')
            with patch.object(public_archive.time, 'sleep'):
                receipt = public_archive.download(row, dest, out, transfer=transfer)
            self.assertEqual(dest.read_bytes(), raw)
            self.assertEqual(receipt['expected_bytes'], 'NOT_ENABLED')
            self.assertEqual(len(receipt['attempts']), 2)
            self.assertEqual((out/receipt['attempts'][0]['raw_body']['path']).read_bytes(), raw[:3])
            self.assertEqual(receipt['attempts'][0]['missing_bytes'], 'NOT_ENABLED')

    def test_unknown_exact_size_rejects_wrong_sha_and_over_cap(self):
        for body, length in [(b'wrong', '5'), (b'x'*9, '9')]:
            with self.subTest(length=length), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); dest=root/'archive'
                row=dict(name='gst-libav', url='https://gstreamer.freedesktop.org/owned',
                         maximum_size=8, sha256=hashlib.sha256(b'right').hexdigest())
                def transfer(url, target, limit, timeout_seconds):
                    target.write_bytes(body)
                    return dict(curl_rc=0, http_status=200, content_length=length, content_encoding='identity')
                with patch.object(public_archive.time, 'sleep'), self.assertRaises(ValueError):
                    public_archive.download(row, dest, root/'out', transfer=transfer)
                self.assertFalse(dest.exists())

    def test_official_sourceforge_hops_strip_credentials_and_false_suffix_refused(self):
        first='https://downloads.sourceforge.net/owned-fixture'
        final='https://downloads.sf.net/foreign'  # not an allowed mirror
        for candidate, accepted in [('https://netix.dl.sourceforge.net/owned', True), (final, False),
                                    ('https://netix.dl.sourceforge.net.foreign.invalid/owned', False)]:
            calls=[]
            def run(argv, **kwargs):
                calls.append((argv, kwargs)); code=302 if len(calls)==1 else 200
                url=first if code==302 else candidate
                headers='HTTP/1.1 '+str(code)+' OK\r\n'
                headers+=('Location: '+candidate+'\r\n') if code==302 else 'Content-Length: 3\r\n'
                Path(argv[argv.index('--output')+1]).write_bytes(b'' if code==302 else b'own')
                return subprocess.CompletedProcess(argv,0,(headers+'\r\n'+private_curl.MARKER+str(code)+'\n'+url+'\n').encode(),b'')
            with tempfile.TemporaryDirectory() as directory, \
                 patch.dict(os.environ, dict(RESULTS_TOKEN='owned-secret', GH_TOKEN='owned-secret', GITHUB_TOKEN='owned-secret')), \
                 patch.object(private_curl.subprocess,'run',side_effect=run):
                receipt=private_curl.source_transfer(first,Path(directory)/'body',3)
            self.assertEqual(receipt['curl_rc']==0 and receipt['http_status']==200,accepted)
            self.assertEqual(len(calls),2 if accepted else 1)
            for argv,kwargs in calls:
                self.assertNotIn(b'Authorization:',kwargs['input'])
                self.assertNotIn(b'owned-secret',kwargs['input'])
                self.assertFalse({'RESULTS_TOKEN','GH_TOKEN','GITHUB_TOKEN'} & set(kwargs['env']))

    def test_all_locked_archive_publishers_pass_source_origin_guard_without_curl(self):
        for row in deps.read_lock()['components']:
            if row.get('source_kind')=='git': continue
            with self.subTest(component=row['name']), patch.object(private_curl,'_transfer',return_value={}) as call:
                private_curl.source_transfer(row['url'],Path('unused'),1)
                self.assertIsNone(call.call_args[0][4])

    def test_tar_graph_guard_and_real_extraction_on_both_python_branches(self):
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w') as archive:
            for name,kind,target in [('pkg',tarfile.DIRTYPE,''),('pkg/data',tarfile.REGTYPE,''),
                                     ('pkg/alias',tarfile.SYMTYPE,'data'),('pkg/chain',tarfile.SYMTYPE,'alias')]:
                member=tarfile.TarInfo(name);member.type=kind;member.linkname=target
                member.mode=0o755 if kind==tarfile.DIRTYPE else 0o644
                if kind==tarfile.REGTYPE: member.size=3;archive.addfile(member,io.BytesIO(b'own'))
                else: archive.addfile(member)
        for fallback in [False, True]:
            with self.subTest(fallback=fallback), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);archive=root/'own.tar';archive.write_bytes(raw.getvalue())
                if fallback:
                    # Emulate Apple's pre-filter tarfile default as well as its
                    # absent data_filter; Python 3.14 defaults to calling it.
                    with patch.object(tarfile,'data_filter',None,create=True), \
                         patch.object(tarfile.TarFile,'extraction_filter',
                                      staticmethod(lambda member, path: member),create=True):
                        selected=deps.unpack(archive,root/'extract')
                else: selected=deps.unpack(archive,root/'extract')
                self.assertEqual((selected/'chain').read_bytes(),b'own')
                self.assertTrue((root/'reports/extract-links.json').is_file())

    def test_tar_link_escape_cycle_or_member_through_link_refused_before_extraction(self):
        for names in [[('pkg/a','../../escape')],[('pkg/a','b'),('pkg/b','a')],
                      [('pkg/a','data'),('pkg/a/file','')]]:
            members=[]
            for name,target in names:
                member=tarfile.TarInfo(name);member.type=tarfile.SYMTYPE if target else tarfile.REGTYPE
                member.linkname=target;members.append(member)
            stream=unittest.mock.Mock()
            with self.subTest(names=names), self.assertRaises(ValueError):
                source.extract_tar(stream,members,Path('unused'))
            stream.extractall.assert_not_called()
