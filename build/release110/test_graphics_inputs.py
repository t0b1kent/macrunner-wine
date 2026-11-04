import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('graphics_inputs', Path(__file__).with_name('graphics_inputs.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class InputArchiveTests(unittest.TestCase):
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
