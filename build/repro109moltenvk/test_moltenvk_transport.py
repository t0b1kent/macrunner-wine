"""Real MoltenVK source transport and unpack; only curl process uses inert disk bodies."""
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
import build_moltenvk as mv
import private_curl


class SourceTransport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ['REPRO109_TEST_TMP'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.out = self.root / 'reports'; self.out.mkdir()
        self.body = self.root / 'owned.tar.gz'
        with tarfile.open(self.body, 'w:gz') as archive:
            data = b'OWNED SOURCE FIXTURE; NEVER COMPILED'
            entry = tarfile.TarInfo('MoltenVK-1.4.1/OWNED.txt'); entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        self.lock = dict(url='https://github.com/KhronosGroup/MoltenVK/archive/refs/tags/v1.4.1.tar.gz',
                         sha256=mv.sha(self.body))
        self.calls = []; self.redirect = None

    def curl(self, argv, **kwargs):
        self.assertEqual(argv[:2], ['/usr/bin/curl', '--disable'])
        self.assertNotIn(b'Authorization:', kwargs['input'])
        self.assertFalse({'RESULTS_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN'} & set(kwargs['env']))
        url = json.loads(next(line.split('=', 1)[1].strip() for line in kwargs['input'].decode().splitlines()
                             if line.startswith('url =')))
        self.calls.append(url); target = Path(argv[argv.index('--output') + 1])
        if self.redirect and url == self.lock['url']:
            code = 302; extra = 'Location: ' + self.redirect + '\r\n'; target.write_bytes(b'')
        else:
            code = 200; extra = 'Content-Length: ' + str(self.body.stat().st_size) + '\r\n'
            target.write_bytes(self.body.read_bytes())
        return subprocess.CompletedProcess(argv, 0, ('HTTP/1.1 ' + str(code) + ' OWNED\r\n' + extra +
            '\r\n' + private_curl.MARKER + str(code) + '\n' + url + '\n').encode(), b'')

    def download(self):
        target = self.root / 'downloaded.tar.gz'
        with mock.patch.object(private_curl.subprocess, 'run', autospec=True, side_effect=self.curl), \
             mock.patch.object(mv.public_archive.time, 'sleep', autospec=True):
            result = mv.download_moltenvk(self.lock, target, self.out)
        return target, result

    def test_exact_official_redirect_download_and_unpack(self):
        self.redirect = 'https://codeload.github.com/KhronosGroup/MoltenVK/tar.gz/refs/tags/v1.4.1'
        target, receipt = self.download()
        source = mv.shared_driver().unpack(target, self.root / 'source')
        self.assertEqual((source / 'OWNED.txt').read_bytes(), b'OWNED SOURCE FIXTURE; NEVER COMPILED')
        self.assertEqual(receipt['state'], 'PRESENT'); self.assertEqual(len(self.calls), 2)
        evidence = os.environ.get('REPRO109_MOLTENVK_EVIDENCE')
        if evidence:
            import shutil
            dest = Path(evidence) / (f'{sys.version_info.major}-{sys.version_info.minor}-opt{sys.flags.optimize}')
            dest.mkdir(parents=True, exist_ok=False)
            shutil.copytree(self.out, dest / 'reports'); shutil.copyfile(self.body, dest / 'owned.tar.gz')

    def test_foreign_publisher_refused_before_transport(self):
        self.lock['url'] = 'https://github.com/foreign/MoltenVK/archive/version.tar.gz'
        with self.assertRaisesRegex(ValueError, 'Foreign MoltenVK'): self.download()
        self.assertEqual(self.calls, [])

    def test_unrelated_allowed_tool_host_refused_for_this_component(self):
        self.redirect = 'https://files.pythonhosted.org/owned.tar.gz'
        with self.assertRaisesRegex(ValueError, 'redirect destination refused'): self.download()
        self.assertEqual(len(self.calls), 1)

    def test_release_asset_host_refused_for_source_archive(self):
        self.redirect = 'https://release-assets.githubusercontent.com/owned.tar.gz'
        with self.assertRaisesRegex(ValueError, 'redirect destination refused'): self.download()
        self.assertEqual(len(self.calls), 1)

    def test_sha_mismatch_never_promoted(self):
        self.lock['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'archive checksum'): self.download()
        self.assertEqual(len(self.calls), 1)
        receipt = json.loads((self.out / 'public-archives/moltenvk/receipt.json').read_bytes())
        self.assertEqual(receipt['state'], 'FAILED')
        self.assertEqual(len(receipt['attempts']), 1)
        attempt = receipt['attempts'][0]
        self.assertFalse(attempt['retryable'])
        self.assertEqual(attempt['failure_reason'], 'archive checksum or size differs')
        body = self.out / attempt['raw_body']['path']
        self.assertEqual(body.read_bytes(), self.body.read_bytes())
        self.assertEqual(attempt['raw_body']['sha256'], mv.sha(self.body))
        self.assertFalse((self.root / 'downloaded.tar.gz').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
