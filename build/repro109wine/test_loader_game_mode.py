"""Offline source checks. No compiler, loader execution or signing."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('loader_game_mode_wine', HERE / 'build_wine.py')
wine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wine)
FIXTURE = HERE / 'fixtures/wine_info.plist.in'
BASE_SHA = '222e2ea91b09c6130172b3f4200aaf2ed145d7001396a763ab1d43a784c1b4bd'
KEYS = dict(GCSupportsGameMode=True, LSSupportsGameMode=True,
            LSApplicationCategoryType='public.app-category.games')


class LoaderGameMode(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='loader-source-', dir=os.environ['REPRO109_TEST_TMP'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.target = self.source / 'loader/wine_info.plist.in'
        self.target.parent.mkdir(parents=True)
        self.reports = self.root / 'reports'
        self.reports.mkdir()
        self.before = FIXTURE.read_bytes()
        self.target.write_bytes(self.before)

    def apply(self):
        return wine.prepare_loader_game_mode(self.source, self.reports)

    def test_public_git_fixture_pin(self):
        self.assertEqual(len(self.before), 1054)
        self.assertEqual(hashlib.sha256(self.before).hexdigest(), BASE_SHA)
        self.assertEqual(wine.blob(self.before), 'cc2653e4400e435b9a8fb51fe4e7486aec891fc4')

    def test_accepted_boolean_keys_and_existing_fields(self):
        before = plistlib.loads(self.before)
        record = self.apply()
        after = self.target.read_bytes()
        actual = plistlib.loads(after)
        self.assertEqual(actual, dict(before, **KEYS))
        for name in ['GCSupportsGameMode', 'LSSupportsGameMode']:
            self.assertIs(actual[name], True)
        self.assertEqual(actual['LSApplicationCategoryType'], 'public.app-category.games')
        self.assertEqual(record['before_sha256'], BASE_SHA)
        self.assertEqual(record['after_sha256'], hashlib.sha256(after).hexdigest())
        self.assertEqual(record['status'], 'LOADER_GAME_MODE_SOURCE_PREPARED_NOT_LINKED')
        self.assertEqual(record['external_bundle'], 'NOT_ASSEMBLED')
        self.assertEqual(json.loads((self.reports / 'loader-game-mode-source.json').read_bytes()), record)

    def test_configure_substitution_retains_keys(self):
        self.apply()
        configured = self.target.read_bytes().replace(b'@PACKAGE_VERSION@', b'11.0')
        actual = plistlib.loads(configured)
        self.assertEqual(actual['CFBundleVersion'], '11.0')
        self.assertEqual(actual['CFBundleShortVersionString'], '11.0')
        self.assertEqual({k: actual[k] for k in KEYS}, KEYS)

    def test_source_drift_rejected_before_write(self):
        data = self.before.replace(b'WineApplication', b'OtherApplication')
        self.target.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'source drift'):
            self.apply()
        self.assertEqual(self.target.read_bytes(), data)
        self.assertEqual(list(self.reports.iterdir()), [])

    def test_existing_keys_rejected_as_drift(self):
        data = self.before.replace(b'</dict>', b'<key>GCSupportsGameMode</key><false/></dict>')
        self.target.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'source drift'):
            self.apply()
        self.assertEqual(self.target.read_bytes(), data)

    def test_second_application_rejected(self):
        self.apply()
        after = self.target.read_bytes()
        with self.assertRaisesRegex(ValueError, 'source drift'):
            self.apply()
        self.assertEqual(self.target.read_bytes(), after)

    def test_missing_source_rejected(self):
        self.target.unlink()
        with self.assertRaisesRegex(ValueError, 'ordinary file'):
            self.apply()
        self.assertEqual(list(self.reports.iterdir()), [])

    def test_symlink_source_rejected(self):
        self.target.unlink()
        retained = self.root / 'retained.plist'
        retained.write_bytes(self.before)
        self.target.symlink_to(retained)
        with self.assertRaisesRegex(ValueError, 'ordinary file'):
            self.apply()
        self.assertEqual(retained.read_bytes(), self.before)
        self.assertEqual(list(self.reports.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
