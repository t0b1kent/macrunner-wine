"""Offline controls for the macOS-15 Wine route; no downloaded source execution."""
import copy
import json
import os
from pathlib import Path
import sys
sys.dont_write_bytecode = True
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_full as full


class GitHubWine15(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='wine-gh15-', dir=os.environ['REPRO109_TEST_TMP'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sdk = self.root / 'sdk'
        (self.sdk / 'usr/lib/system').mkdir(parents=True)
        self.out = self.root / 'reports'
        self.out.mkdir()

    def export_file(self, content):
        (self.sdk / 'usr/lib/system/libsystem.tbd').write_bytes(content)

    def test_complete_exports_counted(self):
        self.export_file(b'[ _os_custom_x18_abi_enabled, _os_set_custom_x18_abi_enabled ]')
        row = full.check_sdk_exports(self.sdk, self.out)
        self.assertEqual(row['status'], 'PRESENT')
        self.assertEqual(set(row['counts'].values()), {1})
        self.assertEqual(row['source_downloads'], 0)

    def test_one_export_is_not_a_complete_abi(self):
        self.export_file(b'_os_custom_x18_abi_enabled')
        with self.assertRaisesRegex(ValueError, '_os_set_custom_x18_abi_enabled'):
            full.check_sdk_exports(self.sdk, self.out)
        row = json.loads((self.out / 'sdk-x18-exports.json').read_bytes())
        self.assertEqual(row['counts']['_os_custom_x18_abi_enabled'], 1)
        self.assertEqual(row['counts']['_os_set_custom_x18_abi_enabled'], 0)

    def test_similar_name_does_not_count(self):
        self.export_file(b'_os_custom_x18_abi_enabled_other _os_set_custom_x18_abi_enabled_other')
        with self.assertRaisesRegex(ValueError, 'lacks Wine'):
            full.check_sdk_exports(self.sdk, self.out)
        row = json.loads((self.out / 'sdk-x18-exports.json').read_bytes())
        self.assertEqual(set(row['counts'].values()), {0})

    def test_profile_preserves_source_and_compiler_pins(self):
        original = dict(toolchain=dict(xcode='fixture', llvm_mingw='pinned', llvm_mingw_sha256='a' * 64),
                        revision='b' * 40, source=dict(sha256='c' * 64))
        before = copy.deepcopy(original)
        selected = full.apply_profile(original, 'github-macos15-arm64')
        self.assertEqual(original, before)
        self.assertEqual(selected['revision'], original['revision'])
        self.assertEqual(selected['source'], original['source'])
        self.assertEqual(selected['toolchain']['llvm_mingw_sha256'], 'a' * 64)
        self.assertEqual(selected['toolchain']['xcode'], '26.3')
        self.assertEqual(selected['toolchain']['sdk'], '26.2')

    def test_sdk_refusal_precedes_vendor_download_or_build(self):
        dep = SimpleNamespace(read_lock=lambda: dict(toolchain={}),
                              toolchain_preflight=mock.Mock(return_value=(self.sdk, 'clang', 'clang++')),
                              build=mock.Mock(), command=mock.Mock())
        wine = SimpleNamespace(build=mock.Mock())
        mv = SimpleNamespace(build=mock.Mock())
        drivers = [dep, wine, mv]
        work = self.root / 'work'
        with mock.patch.object(full, 'cloud_guard'), mock.patch.object(full, 'load_driver', side_effect=drivers):
            with self.assertRaisesRegex(ValueError, 'lacks Wine'):
                full.build(work, dict(minutes=1), profile='github-macos15-arm64')
        dep.build.assert_not_called()
        wine.build.assert_not_called()
        mv.build.assert_not_called()
        dep.command.assert_not_called()
        result = json.loads((work / 'reports/RESULT.json').read_bytes())
        self.assertEqual(result['first_failure']['phase'], 'SDK_PREFLIGHT')
        self.assertEqual(result['status'], 'FAILED')

    def test_local_build_is_rejected_before_work_or_tool_execution(self):
        work = self.root / 'local'
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(full, 'load_driver') as load:
            with self.assertRaisesRegex(ValueError, 'only in the cloud'):
                full.build(work, dict(minutes=1), profile='github-macos15-arm64')
        load.assert_not_called()
        self.assertFalse(work.exists())


if __name__ == '__main__':
    unittest.main()
