"""Owned fixtures only: curl is mocked; no external payload is downloaded or run."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import archive_safety
import source_download as source
import private_curl
import public_archive


class PublicArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root / 'out'; self.out.mkdir()
        self.path = self.root / 'cmake.archive'
        self.raw = b'abcdef'
        self.row = dict(name='cmake', url='https://files.pythonhosted.org/owned-fixture',
                        size=6, sha256=hashlib.sha256(self.raw).hexdigest())

    def exercise(self, replies):
        sequence = iter(replies)
        def transfer(url, target, limit, timeout_seconds):
            body, extra = next(sequence)
            target.write_bytes(body)
            return dict(dict(curl_rc=0, http_status=200, content_length='6',
                             content_encoding='identity'), **extra)
        with patch.object(public_archive, 'public_transfer', side_effect=transfer) as call, \
             patch.object(public_archive.time, 'sleep'):
            try:
                result = public_archive.download(self.row, self.path, self.out)
                error = None
            except ValueError as failure:
                result, error = None, str(failure)
        receipt = json.loads((self.out/'public-archives/cmake/receipt.json').read_text())
        return result, error, receipt, call.call_count

    def test_complete_exact_body_and_receipt(self):
        result, error, receipt, calls = self.exercise([(self.raw, {})])
        self.assertIsNone(error); self.assertEqual(calls, 1)
        self.assertEqual(self.path.read_bytes(), self.raw)
        self.assertEqual(result['sha256'], self.row['sha256'])
        self.assertTrue(receipt['attempts'][0]['body_complete'])

    def test_partial_retry_preserves_exact_failed_body(self):
        result, error, receipt, calls = self.exercise([(b'abc', {'curl_rc':18, 'retryable':True}), (self.raw,{})])
        self.assertIsNone(error); self.assertEqual(calls, 2)
        first = receipt['attempts'][0]
        self.assertEqual(first['missing_bytes'], 3)
        self.assertEqual((self.out/first['raw_body']['path']).read_bytes(), b'abc')
        self.assertEqual(first['received_sha256'], hashlib.sha256(b'abc').hexdigest())

    def test_short_http200_body_refuses_without_retry_and_never_extracts(self):
        result, error, receipt, calls = self.exercise([(b'abc', {})])
        self.assertIsNone(result); self.assertEqual(calls, 1)
        self.assertFalse(self.path.exists()); self.assertEqual(len(receipt['attempts']), 1)
        self.assertIn('expected=6/', error); self.assertIn('received=3/', error)
        for attempt in receipt['attempts']:
            self.assertEqual((self.out/attempt['raw_body']['path']).read_bytes(), b'abc')

    def test_wrong_digest_never_accepted(self):
        result, error, receipt, calls = self.exercise([(b'ghijkl', {})])
        self.assertIsNone(result); self.assertEqual(calls, 1)
        self.assertFalse(self.path.exists()); self.assertIn('checksum', error)

    def test_206_encoding_declared_oversize_and_certificate_refuse_without_retry(self):
        for extra in [dict(http_status=206), dict(content_encoding='gzip'), dict(content_length='7'),
                      dict(curl_rc=60, retryable=False, failure_reason='certificate refused')]:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as directory:
                self.out = Path(directory); self.path = self.out/'archive'
                result, error, receipt, calls = self.exercise([(b'abc', extra)])
                self.assertIsNone(result); self.assertEqual(calls, 1)
                self.assertFalse(self.path.exists())

    def test_unknown_content_length_still_requires_pinned_size_and_sha(self):
        result, error, receipt, calls = self.exercise([(self.raw, dict(content_length='EMPTY'))])
        self.assertIsNone(error); self.assertEqual(calls, 1)

    def test_existing_destination_is_preserved(self):
        self.path.write_bytes(b'owned previous evidence')
        with patch.object(public_archive, 'public_transfer') as call:
            with self.assertRaisesRegex(ValueError, 'already exists'):
                public_archive.download(self.row, self.path, self.out)
        call.assert_not_called(); self.assertEqual(self.path.read_bytes(), b'owned previous evidence')

    def test_deadline_refuses_without_network(self):
        with patch.object(public_archive.time, 'monotonic', side_effect=[0, 151]), \
             patch.object(public_archive, 'public_transfer') as call:
            with self.assertRaisesRegex(ValueError, 'deadline'):
                public_archive.download(self.row, self.path, self.out)
        call.assert_not_called()


class PublicCurlTests(unittest.TestCase):
    def test_every_public_hop_has_no_credentials_and_stripped_environment(self):
        first = 'https://github.com/owned-fixture'
        final = 'https://release-assets.githubusercontent.com/owned-fixture'
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            code = 302 if len(calls) == 1 else 200
            url = first if len(calls) == 1 else final
            headers = 'HTTP/1.1 ' + str(code) + ' OK\r\n'
            headers += ('Location: ' + final + '\r\n') if code == 302 else 'Content-Length: 6\r\n'
            Path(argv[argv.index('--output')+1]).write_bytes(b'' if code==302 else b'abcdef')
            return subprocess.CompletedProcess(argv, 0,
                (headers+'\r\n'+private_curl.MARKER+str(code)+'\n'+url+'\n').encode(), b'')
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, dict(RESULTS_TOKEN='owned-secret', GH_TOKEN='owned-secret', GITHUB_TOKEN='owned-secret')), \
             patch.object(private_curl.subprocess, 'run', side_effect=run):
            receipt = private_curl.public_transfer(first, Path(directory)/'body', 6)
        self.assertEqual(receipt['http_status'], 200); self.assertEqual(len(calls), 2)
        for argv, kwargs in calls:
            self.assertEqual(argv[:2], ['/usr/bin/curl','--disable'])
            self.assertNotIn('--location', argv); self.assertNotIn('-L', argv)
            self.assertNotIn(b'Authorization:', kwargs['input']); self.assertNotIn(b'owned-secret', kwargs['input'])
            self.assertFalse({'GH_TOKEN','GITHUB_TOKEN','RESULTS_TOKEN'} & set(kwargs['env']))

    def test_foreign_or_plaintext_origins_refused_before_curl(self):
        for url in ['http://github.com/owned', 'https://foreign.invalid/tool',
                    'https://user:pass@github.com/tool', 'https://github.com:444/tool']:
            with patch.object(private_curl.subprocess, 'run') as call:
                with self.assertRaises(ValueError):
                    private_curl.public_transfer(url, Path('unused-owned-body'), 6)
                call.assert_not_called()


def member(name, kind='file', target=''):
    entry = tarfile.TarInfo(name)
    entry.type = {'file':tarfile.REGTYPE, 'dir':tarfile.DIRTYPE,
                  'sym':tarfile.SYMTYPE, 'hard':tarfile.LNKTYPE, 'fifo':tarfile.FIFOTYPE}[kind]
    entry.linkname = target
    return entry


class TarGraphTests(unittest.TestCase):
    def test_real_llvm_addr2line_chain_shape_resolves_to_internal_regular_file(self):
        graph = archive_safety.validate_tar([
            member('release/bin/llvm-symbolizer'),
            member('release/bin/llvm-addr2line', 'sym', 'llvm-symbolizer'),
            member('release/bin/aarch64-w64-mingw32-addr2line', 'sym', 'llvm-addr2line')])
        self.assertEqual(graph['link_graph'][-1]['resolved'], 'release/bin/llvm-symbolizer')
        self.assertEqual(graph['link_graph'][-1]['hops'], 2)

    def test_target_through_internal_directory_alias_is_allowed(self):
        graph = archive_safety.validate_tar([member('release/lib/tool'),
            member('release/lib-alias', 'sym', 'lib'),
            member('release/bin/tool', 'sym', '../lib-alias/tool')])
        self.assertEqual(graph['link_graph'][-1]['resolved'], 'release/lib/tool')

    def test_hardlink_through_alias_requires_internal_regular_target(self):
        graph = archive_safety.validate_tar([member('release/tool'),
            member('release/alias', 'sym', 'tool'), member('release/hard', 'hard', 'release/alias')])
        self.assertEqual(graph['link_graph'][-1]['resolved'], 'release/tool')

    def test_escape_absolute_cycles_duplicates_special_files_and_write_through_links_refused(self):
        cases = [([member('release/tool','sym','../../outside')], 'escapes'),
                 ([member('release/a','sym','b'),member('release/b','sym','../../outside')], 'escapes'),
                 ([member('release/tool','sym','/absolute')], 'absolute'),
                 ([member('release/a','sym','b'),member('release/b','sym','a')], 'cycle'),
                 ([member('release/a'),member('release/./a')], 'duplicate'),
                 ([member('release/fifo','fifo')], 'special'),
                 ([member('release/alias','sym','dir'),member('release/alias/file')], 'traverses'),
                 ([member('../outside')], 'escapes'),
                 ([member('release/hard','hard','release/missing')], 'regular')]
        for entries, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                archive_safety.validate_tar(entries)

    def test_parent_resolution_after_alias_is_checked_against_actual_root(self):
        with self.assertRaisesRegex(ValueError, 'escapes'):
            archive_safety.validate_tar([member('release/alias','sym','.'),
                member('release/bin/tool','sym','../alias/../../outside')])

    def test_owned_tar_chain_extracts_with_data_filter_and_apple_fallback(self):
        for fallback in [False, True]:
            if not fallback and not callable(getattr(tarfile, 'data_filter', None)):
                continue
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); archive = root/'owned.tar.gz'; tree=root/'tree'
                with tarfile.open(archive, 'w:gz') as stream:
                    entry = member('release/bin/tool'); entry.size=5
                    stream.addfile(entry, io.BytesIO(b'owned'))
                    stream.addfile(member('release/bin/alias','sym','tool'))
                    stream.addfile(member('release/bin/wrapper','sym','alias'))
                with patch.object(tarfile, 'data_filter', None, create=True) if fallback else patch.dict({}, {}):
                    source.extract_tar(archive, tree)
                self.assertEqual((tree/'release/bin/wrapper').read_bytes(), b'owned')


if __name__ == '__main__':
    unittest.main(verbosity=2)
