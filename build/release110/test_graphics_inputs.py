import importlib.util
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import zipfile

spec = importlib.util.spec_from_file_location('graphics_inputs', Path(__file__).with_name('graphics_inputs.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class InputArchiveTests(unittest.TestCase):
    def test_transient_download_preserves_partial_bytes_then_verifies_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []
            def child(*args, **kwargs):
                calls.append(args)
                kwargs['stdout'].write(b'partial' if len(calls) == 1 else b'exact')
                return SimpleNamespace(returncode=1 if len(calls) == 1 else 0,
                                       stderr=b'gh: HTTP 503' if len(calls) == 1 else b'')
            with patch.object(module.subprocess, 'run', side_effect=child), patch.object(module.time, 'sleep'):
                module.download_artifact(123, root / 'input.zip', hashlib.sha256(b'exact').hexdigest(), root)
            self.assertEqual((root / 'input.zip').read_bytes(), b'exact')
            self.assertEqual((root / 'input.zip.attempt-1').read_bytes(), b'partial')
            self.assertEqual(len(calls), 2)

    def test_corrupt_bytes_and_permanent_download_errors_do_not_retry(self):
        for rc, diagnostic in [(0, b''), (1, b'gh: HTTP 403')]:
            with self.subTest(rc=rc), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                def child(*args, **kwargs):
                    kwargs['stdout'].write(b'wrong')
                    return SimpleNamespace(returncode=rc, stderr=diagnostic)
                with patch.object(module.subprocess, 'run', side_effect=child) as run:
                    with self.assertRaises(ValueError):
                        module.download_artifact(123, root / 'input.zip', '0' * 64, root)
                self.assertEqual(run.call_count, 1)
                self.assertFalse((root / 'input.zip').exists())

    def test_transient_download_is_bounded_to_three_attempts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = SimpleNamespace(returncode=1, stderr=b'gh: HTTP 503')
            with patch.object(module.subprocess, 'run', return_value=child) as run, patch.object(module.time, 'sleep'):
                with self.assertRaisesRegex(ValueError, 'download failed'):
                    module.download_artifact(123, root / 'input.zip', '0' * 64, root)
            self.assertEqual(run.call_count, 3)
            self.assertEqual(len(list(root.glob('input.zip.attempt-*'))), 3)

    def test_exact_report_and_tar_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with zipfile.ZipFile(root / 'input.zip', 'w') as stream:
                stream.writestr('reports/RESULT.json', '{"status":"fixture"}')
                stream.writestr('llvm15-prefix.tar.gz', b'fixture')
            module.unpack_zip(root / 'input.zip', root / 'restored')
            self.assertEqual(module.only(root / 'restored', 'RESULT.json').read_text(), '{"status":"fixture"}')

    def test_parent_escape_absolute_and_symlink_are_refused(self):
        for name in ['../escape', '/escape', 'a\\escape', 'symlink']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                row = zipfile.ZipInfo(name)
                if name == 'symlink':
                    row.external_attr = 0o120777 << 16
                with zipfile.ZipFile(root / 'input.zip', 'w') as stream:
                    stream.writestr(row, b'fixture')
                with self.assertRaisesRegex(ValueError, 'Unsafe'):
                    module.unpack_zip(root / 'input.zip', root / 'restored')
                self.assertFalse((root / 'restored').exists())

    def test_duplicate_archive_match_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                module.only(root, '*.tar.gz')
