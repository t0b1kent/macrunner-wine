"""Offline byte-pinned source controls for the public Wine 1.0.8 transition."""
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_wine as wine

class PublicBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='public-base-', dir=os.environ['REPRO109_TEST_TMP'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'; self.source.mkdir()
        self.lock = wine.inputs()
        fixtures = {
            'dlls/msvcrt/string.c': 'release108-string.c',
            'include/wine/arm64_memmove.h': 'release108-arm64_memmove.h',
            'include/Makefile.in': 'release108-include-Makefile.in',
        }
        for row in self.lock['base_release_sources']:
            original = HERE / 'fixtures' / fixtures[row['path']] if row['path'] in fixtures else HERE / 'fixtures/release108-base' / row['path']
            target = self.source / row['path']; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)

    def test_real_public_sources_and_header_registration(self):
        result = wine.check_release_sources(self.source, self.lock)
        self.assertEqual((result['state'], result['files'], result['overlay_files']), ('PRESENT', 20, 0))
        out = self.root / 'reports'; out.mkdir()
        header = wine.check_header_sources(self.source, self.lock, out, baseline=wine.source_headers(self.source))
        self.assertEqual(header['status'], 'PRESENT')
        self.assertEqual(header['missing_sources'], [])
        self.assertIn('include/wine/arm64_memmove.h', header['required_headers'])

    def test_all_released_sources_drift_refused(self):
        for row in self.lock['base_release_sources']:
            with self.subTest(path=row['path']):
                target = self.source / row['path']; original = target.read_bytes()
                target.write_bytes(original + b'\n')
                with self.assertRaises(ValueError):
                    wine.check_release_sources(self.source, self.lock)
                target.write_bytes(original)

    def test_missing_and_symlink_refused(self):
        target = self.source / 'include/wine/arm64_memmove.h'
        saved = target.with_suffix('.saved'); target.rename(saved)
        with self.assertRaises(ValueError):
            wine.check_release_sources(self.source, self.lock)
        target.symlink_to(saved.name)
        with self.assertRaises(ValueError):
            wine.check_release_sources(self.source, self.lock)

    def test_unregistered_header_refused(self):
        target = self.source / 'include/Makefile.in'
        data = target.read_text(); line = '\twine/arm64_memmove.h \\\n'
        self.assertEqual(data.count(line), 1)
        target.write_text(data.replace(line, ''))
        out = self.root / 'reports'; out.mkdir()
        with self.assertRaises(ValueError):
            wine.check_header_sources(self.source, self.lock, out, baseline=wine.source_headers(self.source))

    def test_old_revision_overlay_duplicate_and_wrong_pin_refused(self):
        cases = []
        old = copy.deepcopy(self.lock); old['revision'] = 'f71ab7cafda22762acbbff593420c543909cd7b5'; cases.append(old)
        overlay = copy.deepcopy(self.lock); overlay['overlay'] = [{}]; cases.append(overlay)
        duplicate = copy.deepcopy(self.lock); duplicate['required_base_files'][-1] = duplicate['required_base_files'][0]; cases.append(duplicate)
        pin = copy.deepcopy(self.lock); pin['base_release_sources'][0]['git_blob'] = '0' * 40; cases.append(pin)
        for number, value in enumerate(cases):
            with self.subTest(case=number):
                recipe = self.root / ('recipe-' + str(number)); recipe.mkdir()
                (recipe / 'wine.lock.json').write_text(json.dumps(value))
                with mock.patch.object(wine, 'RECIPE', recipe), self.assertRaises(ValueError):
                    wine.inputs()

    def test_pinned_base_and_late_patch_scope(self):
        self.assertEqual(self.lock['overlay'], [])
        self.assertEqual(len(self.lock['required_base_files']), 797)
        self.assertEqual(len(self.lock['base_release_sources']), 20)
        late = wine.late_source.inputs()
        self.assertEqual(late['wine_revision'], self.lock['revision'])
        self.assertEqual(late['patch_sha256'], '0d5ea043c78fd408cb85d6688a98df28600ba929eb7d22cc92ab201dafe39a12')

if __name__ == '__main__':
    unittest.main()
