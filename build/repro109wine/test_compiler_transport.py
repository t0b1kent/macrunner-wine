"""Production compiler transport/unpack with owned inert disk bodies; no network/tools."""
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
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_wine as wine
import private_curl


class CompilerTransport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ['REPRO109_TEST_TMP'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root / 'reports'; self.out.mkdir()
        self.body = self.root / 'owned.tar.xz'
        self.make_archive()
        self.row = dict(name='llvm-mingw', url=wine.COMPILER_URL,
                        size=self.body.stat().st_size, sha256=wine.public_archive.sha(self.body))
        self.calls = []
        self.redirect = None

    def make_archive(self, *, escape=False, missing=None):
        top = 'llvm-mingw-20260505-ucrt-macos-universal/bin/'
        data = b'OWNED INERT COMPILER FIXTURE; NOT EXECUTABLE'
        with tarfile.open(self.body, 'w:xz') as stream:
            for name in ['clang', 'ld.lld']:
                item = tarfile.TarInfo(top + name); item.size = len(data); item.mode = 0o644
                stream.addfile(item, io.BytesIO(data))
            for arch in ['aarch64', 'arm64ec', 'x86_64', 'i686']:
                for suffix in ['gcc', 'g++']:
                    name = f'{arch}-w64-mingw32-{suffix}'
                    if name == missing: continue
                    item = tarfile.TarInfo(top + name); item.type = tarfile.SYMTYPE
                    item.linkname = '../../../escape' if escape else 'clang'
                    stream.addfile(item)

    def disk_curl(self, argv, **kwargs):
        self.assertEqual(argv[:2], ['/usr/bin/curl', '--disable'])
        self.assertFalse({'RESULTS_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN'} & set(kwargs['env']))
        self.assertNotIn(b'Authorization:', kwargs['input'])
        url = json.loads(next(line.split('=', 1)[1].strip()
            for line in kwargs['input'].decode().splitlines() if line.startswith('url =')))
        self.calls.append(url)
        target = Path(argv[argv.index('--output') + 1])
        if self.redirect and url == wine.COMPILER_URL:
            target.write_bytes(b'')
            code = 302; extra = 'Location: ' + self.redirect + '\r\n'
        else:
            target.write_bytes(self.body.read_bytes())
            code = 200; extra = 'Content-Length: ' + str(self.body.stat().st_size) + '\r\n'
        raw = ('HTTP/1.1 ' + str(code) + ' OWNED\r\n' + extra + '\r\n' +
               private_curl.MARKER + str(code) + '\n' + url + '\n').encode()
        return subprocess.CompletedProcess(argv, 0, raw, b'')

    def download(self):
        target = self.root / 'downloaded.tar.xz'
        with mock.patch.object(private_curl.subprocess, 'run', autospec=True, side_effect=self.disk_curl), \
             mock.patch.object(wine.public_archive.time, 'sleep', autospec=True):
            receipt = wine.download_compiler(self.row, target, self.out)
        return target, receipt

    def unpack(self, target=None):
        target = self.body if target is None else target
        return wine.prepare_compiler(target, self.root / 'toolchain', self.row['sha256'], self.out)

    def test_real_download_redirect_and_unpack_with_inert_tools(self):
        self.redirect = 'https://release-assets.githubusercontent.com/owned-compiler'
        target, receipt = self.download(); llvm = self.unpack(target)
        self.assertEqual(self.calls, [wine.COMPILER_URL, self.redirect])
        self.assertEqual(receipt['state'], 'PRESENT')
        self.assertEqual(target.read_bytes(), self.body.read_bytes())
        self.assertEqual((llvm / 'bin/arm64ec-w64-mingw32-gcc').read_bytes(),
                         b'OWNED INERT COMPILER FIXTURE; NOT EXECUTABLE')
        report = json.loads((self.out / 'compiler-archive.json').read_bytes())
        self.assertEqual(len(report['selected']), 10)
        self.assertEqual(report['graph']['links'], 8)
        self.assertEqual(report['execution'], 'NOT_ENABLED')
        evidence = os.environ.get('REPRO109_COMPILER_EVIDENCE')
        if evidence:
            import shutil
            dest = Path(evidence) / (f'{sys.version_info.major}-{sys.version_info.minor}-opt{sys.flags.optimize}')
            dest.mkdir(parents=True, exist_ok=False)
            shutil.copytree(self.out, dest / 'reports')
            shutil.copyfile(self.body, dest / 'owned.tar.xz')

    def test_real_apple_python_extract_without_data_filter(self):
        with mock.patch.object(tarfile, 'data_filter', None, create=True):
            llvm = self.unpack()
        self.assertTrue((llvm / 'bin/i686-w64-mingw32-g++').is_file())

    def test_foreign_origin_refused_before_transport(self):
        self.row['url'] = 'https://github.com/foreign/project/releases/download/version/tool.tar.xz'
        with self.assertRaisesRegex(ValueError, 'Foreign llvm-mingw'): self.download()
        self.assertEqual(self.calls, [])

    def test_real_redirect_to_foreign_host_refused(self):
        self.redirect = 'https://foreign.invalid/owned'
        with self.assertRaisesRegex(ValueError, 'redirect destination refused'): self.download()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse((self.root / 'downloaded.tar.xz').exists())

    def test_real_sha_mismatch_never_promoted(self):
        self.row['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'archive checksum'): self.download()
        self.assertEqual(len(self.calls), 1)
        receipt = json.loads((self.out / 'public-archives/llvm-mingw/receipt.json').read_bytes())
        self.assertEqual(receipt['state'], 'FAILED')
        self.assertEqual(len(receipt['attempts']), 1)
        self.assertFalse(receipt['attempts'][0]['retryable'])
        self.assertFalse((self.root / 'downloaded.tar.xz').exists())

    def test_unpack_sha_drift_refused_before_destination(self):
        self.row['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'Compiler archive drift'): self.unpack()
        self.assertFalse((self.root / 'toolchain').exists())

    def test_unpack_link_graph_escape_refused_before_destination(self):
        self.make_archive(escape=True); self.row['sha256'] = wine.public_archive.sha(self.body)
        with self.assertRaisesRegex(ValueError, 'link escapes'): self.unpack()
        self.assertFalse((self.root / 'toolchain').exists())

    def test_missing_sibling_compiler_refused(self):
        self.make_archive(missing='i686-w64-mingw32-g++')
        self.row['sha256'] = wine.public_archive.sha(self.body)
        with self.assertRaisesRegex(ValueError, 'Compiler command missing'): self.unpack()

    def test_extraction_collision_refused(self):
        (self.root / 'toolchain').mkdir()
        with self.assertRaisesRegex(ValueError, 'fresh directory'): self.unpack()

    def test_archive_symlink_refused(self):
        target = self.root / 'linked.tar.xz'; target.symlink_to(self.body)
        with self.assertRaisesRegex(ValueError, 'symlink'): self.unpack(target)


if __name__ == '__main__':
    unittest.main(verbosity=2)
