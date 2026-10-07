"""Regression controls for the actual deps7 source/tool/link boundaries."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build_deps as deps
from source_fixes import apply_source_fixes, gnutls_test_links, lame_exports


class Deps8Tests(unittest.TestCase):
    def test_fontconfig_uses_required_meson_from_official_metadata(self):
        row = next(x for x in deps.read_lock()['components'] if x['name'] == 'meson')
        self.assertEqual(row['version'], '1.11.0')
        self.assertEqual(row['url'], deps.MESON_SDIST)
        self.assertEqual(row['sha256'], 'dffdd0915ceb028541fe3bed77d63ba35e78514591c043736b450d62634eeb31')
        with self.assertRaises(AssertionError):
            deps.official(row['url'].replace('1.11.0', '1.9.1'))

    def test_lame_removes_only_one_obsolete_export(self):
        value, count = lame_exports(b'lame_init\nlame_init_old\nlame_close\n')
        self.assertEqual(value, b'lame_init\nlame_close\n')
        self.assertEqual(count, 1)
        for data in [b'lame_init\n', b'lame_init_old\nlame_init_old\n', b'not_lame_init_old\n']:
            with self.assertRaisesRegex(ValueError, 'expected=1'):
                lame_exports(data)

    def test_gnutls_common_and_sibling_test_link_inputs(self):
        original = (b'LDADD = ../lib/libgnutls.la \\\n libutils.la\n'
                    b'mini_dtls_fragments_LDADD = ../lib/libgnutls.la extra.la\n'
                    b'other_LDADD = unrelated.la\n')
        value, count = gnutls_test_links(original)
        self.assertEqual(count, 2)
        self.assertEqual(value.count(b'$(top_builddir)/gl/libgnu.la'), 2)
        self.assertIn(b'other_LDADD = unrelated.la\n', value)
        for data in [b'LDADD = unrelated.la\n', value]:
            with self.assertRaisesRegex(ValueError, 'expected>=1'):
                gnutls_test_links(data)

    def test_source_fix_keeps_raw_before_after_and_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, reports = root/'source', root/'reports'
            (source/'include').mkdir(parents=True)
            reports.mkdir()
            original = b'lame_init\nlame_init_old\nlame_close\n'
            (source/'include/libmp3lame.sym').write_bytes(original)
            events = []
            apply_source_fixes(dict(name='lame', version='3.100'), source, reports,
                               lambda *a, **kw: events.append(kw))
            self.assertEqual((reports/'lame-source-fix-before.raw').read_bytes(), original)
            self.assertEqual((reports/'lame-source-fix-after.raw').read_bytes(), b'lame_init\nlame_close\n')
            self.assertEqual(events[0]['input_sha256'], hashlib.sha256(original).hexdigest())
            self.assertEqual(events[0]['patch_sha256'], deps.file_sha(reports/'lame-source-fix.patch'))
            with self.assertRaisesRegex(ValueError, 'version'):
                apply_source_fixes(dict(name='lame', version='other'), source, reports, lambda *a, **kw: None)

    def test_selected_generators_are_tools_and_foreign_source_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, reports, prefix = root/'source', root/'reports', root/'prefix'
            intro = source/'_repro_build/meson-info/intro-buildsystem_files.json'
            intro.parent.mkdir(parents=True)
            reports.mkdir()
            (prefix/'bin').mkdir(parents=True)
            (source/'meson.build').write_text('project("fixture", "c")')
            for name in ['flex', 'bison']:
                (prefix/'bin'/name).write_bytes(name.encode())
            inputs = [str(source/'meson.build'), str(prefix/'bin/flex'), str(prefix/'bin/bison')]
            intro.write_text(json.dumps(inputs))
            receipt = deps.meson_source_ownership(source, reports, 'gstreamer', prefix)
            self.assertEqual(receipt['source_files'], 1)
            self.assertEqual({x['name'] for x in receipt['build_tools']}, {'flex', 'bison'})
            for bad in [prefix/'bin/foreign.c', root/'foreign/flex', Path('/usr/bin/flex')]:
                intro.write_text(json.dumps([*inputs, str(bad)]))
                with self.assertRaisesRegex(AssertionError, 'foreign source'):
                    deps.meson_source_ownership(source, reports, 'gstreamer', prefix)
            intro.write_text(json.dumps([str(source/'meson.build'), '/usr/bin/xxd']))
            receipt = deps.meson_source_ownership(source, reports, 'libvmaf', prefix)
            self.assertEqual(receipt['build_tools'][0]['owner'], 'PLATFORM_TOOL')
            with self.assertRaises(AssertionError):
                deps.meson_source_ownership(source, reports, 'glib', prefix)
            (prefix/'bin/flex').unlink()
            (prefix/'bin/flex').symlink_to('/usr/bin/xxd')
            with self.assertRaisesRegex(AssertionError, 'owned prefix'):
                deps.meson_source_ownership(source, reports, 'gstreamer', prefix)

    def test_ccache_closure_is_optional_and_wine_compilers_are_direct(self):
        lock = deps.read_lock()
        optional = json.loads((deps.HERE/'optional-ccache.lock.json').read_text())
        names = {x['name'] for x in optional['components']}
        self.assertEqual(len(names), 8)
        self.assertFalse(names.intersection(x['name'] for x in lock['components']))
        self.assertNotIn('ccache', lock['wine_required'])
        wine = (deps.HERE.parent/'repro109wine/build_wine.py').read_text()
        self.assertFalse('ccache' in wine.lower(), 'Wine recipe must not require or invoke ccache')


if __name__ == '__main__':
    unittest.main()
