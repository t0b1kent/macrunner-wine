"""Offline controls of actual manifest composition and sequential source drivers."""
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_full as full

DEP = full.load_driver('wine2_test_deps', full.REPO / 'repro109deps/build_deps.py')
WINE = full.load_driver('wine2_test_wine', full.HERE / 'build_wine.py')
MV_LOCK = json.loads((full.REPO / 'repro109moltenvk/moltenvk.lock.json').read_bytes())


def fixture(root):
    prefix, mv = root / 'deps/prefix', root / 'moltenvk/prefix'
    prefix.mkdir(parents=True); mv.mkdir(parents=True)
    (prefix / 'bin').mkdir(); (prefix / 'bin/pkg-config').write_bytes(b'fixture only; never executed')
    files = {'lib/libMoltenVK.dylib': b'fixture-dylib', 'lib/pkgconfig/MoltenVK.pc': b'prefix=${pcfiledir}/../..\n',
             'include/MoltenVK/vk_mvk_moltenvk.h': b'fixture-header',
             'share/licenses/MoltenVK/LICENSE': b'fixture-license', 'bin/cmake': b'fixture-bootstrap'}
    for name, data in files.items():
        target = mv / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
    required = ['bison', 'flex', 'pkgconf', 'gettext', 'glib', 'gstreamer', 'gst-plugins-base', 'ffmpeg',
                'freetype', 'fontconfig', 'libpng', 'gnutls', 'libusb', 'sdl2', 'Vulkan-Headers']
    component = dict(version='fixture', recipe_sha256='a' * 64, build_rc=0,
                     sources=[dict(url='https://ftp.gnu.org/gnu/bison/bison-3.8.2.tar.xz', sha256='b' * 64)])
    base = dict(schema=1, source_built=True, status='PARTIAL_DEPENDENCIES_BUILT_NOT_WINE_READY',
                failures=[], skipped_components=[], install_skipped=0, remaining_wine_required=['MoltenVK'],
                files=DEP.inventory(prefix), components={name: copy.deepcopy(component) for name in required})
    sources = [dict(name='MoltenVK', url=MV_LOCK['url'], archive_sha256=MV_LOCK['sha256'])]
    bootstrap = {row['name']: row for row in json.loads((full.REPO / 'repro109deps/deps.lock.json').read_bytes())['components']}
    for name in ['cmake', 'ninja']:
        sources.append(dict(name=name, url=bootstrap[name]['url'], archive_sha256=bootstrap[name]['sha256']))
    for row in MV_LOCK['external']:
        sources.append(dict(name=row['name'], url=row['url'], archive_sha256='c' * 64,
                       expected_git_sha1=row['revision'], actual_git_sha1=row['revision'] + '\n',
                       archive_sha256_state='MEASURED_IN_CLOUD_NOT_PREPINNED'))
    molten = dict(schema=1, source_built=True, status='MOLTENVK_SOURCE_BUILT_NOT_INDIANA_ACCEPTANCE',
                  first_failure=None, install_skipped=0, lock_sha256=full.digest((full.REPO / 'repro109moltenvk/moltenvk.lock.json').read_bytes()),
                  sources=sources, files=DEP.inventory(mv), components={'MoltenVK': dict(version=MV_LOCK['version'],
                  state='BUILT', source_built=True, input_sha256=MV_LOCK['sha256'],
                  selected_sha256=full.digest(files['lib/libMoltenVK.dylib']), outputs=list(files)[:3])})
    return prefix, mv, base, molten


class Compose(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='wine2-', dir=os.environ['REPRO109_TEST_TMP'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.prefix, self.mv, self.base, self.molten = fixture(self.root)

    def compose(self):
        dp, mp = self.root / 'deps.json', self.root / 'molten.json'
        dp.write_text(json.dumps(self.base)); mp.write_text(json.dumps(self.molten))
        return full.compose(self.prefix, dp, self.mv, mp, self.root / 'out', DEP, WINE)

    def test_consumer_and_original_raw_bytes(self):
        path = self.compose(); receipt = json.loads(path.read_bytes())
        self.assertEqual(len(receipt['components']), 16)
        self.assertEqual(self.prefix / 'bin/pkg-config', (self.root / 'deps/prefix/bin/pkg-config'))
        self.assertFalse((self.prefix / 'bin/cmake').exists())
        self.assertEqual((path.parent / 'deps8-original.json').read_bytes(), (self.root / 'deps.json').read_bytes())
        self.assertEqual((path.parent / 'moltenvk2-original.json').read_bytes(), (self.root / 'molten.json').read_bytes())
        self.assertTrue((self.prefix / 'share/licenses/MoltenVK-bundle/MoltenVK/LICENSE').is_file())
        self.assertEqual(WINE.dependencies(self.prefix, path, full.digest(path.read_bytes()))['files'], DEP.inventory(self.prefix))

    def test_failed_deps(self):
        self.base['failures'] = [{'phase': 'LINK'}]
        with self.assertRaisesRegex(ValueError, 'failed/skipped'): self.compose()

    def test_skipped_deps(self):
        self.base['skipped_components'] = [{'name': 'glib'}]
        with self.assertRaisesRegex(ValueError, 'failed/skipped'): self.compose()

    def test_install_skipped(self):
        self.molten['install_skipped'] = 1
        with self.assertRaisesRegex(ValueError, 'stock source build'): self.compose()

    def test_stock_molten_failure(self):
        self.molten['source_built'] = False
        with self.assertRaisesRegex(ValueError, 'stock source build'): self.compose()

    def test_deps_byte_drift(self):
        (self.prefix / 'bin/pkg-config').write_bytes(b'drift')
        with self.assertRaisesRegex(ValueError, 'raw inventory'): self.compose()

    def test_molten_byte_drift(self):
        (self.mv / 'lib/libMoltenVK.dylib').write_bytes(b'drift')
        with self.assertRaisesRegex(ValueError, 'raw inventory'): self.compose()

    def test_external_pin_drift(self):
        self.molten['sources'][3]['actual_git_sha1'] = 'd' * 40
        with self.assertRaisesRegex(ValueError, 'External Git pin'): self.compose()

    def test_external_foreign_url(self):
        self.molten['sources'][3]['url'] = 'https://example.invalid/project.git'
        with self.assertRaisesRegex(ValueError, 'External Git pin'): self.compose()

    def test_bootstrap_source_drift(self):
        self.molten['sources'][1]['archive_sha256'] = 'd' * 64
        with self.assertRaisesRegex(ValueError, 'Bootstrap archive pin'): self.compose()

    def test_duplicate_source(self):
        self.molten['sources'].append(copy.deepcopy(self.molten['sources'][3]))
        with self.assertRaisesRegex(ValueError, 'Missing/duplicate'): self.compose()

    def test_archive_pin_drift(self):
        self.molten['sources'][0]['archive_sha256'] = 'e' * 64
        with self.assertRaisesRegex(ValueError, 'archive pin'): self.compose()

    def test_selected_sha_drift(self):
        self.molten['components']['MoltenVK']['selected_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'Selected MoltenVK'): self.compose()

    def test_output_collision(self):
        target = self.prefix / 'lib/libMoltenVK.dylib'; target.parent.mkdir(); target.write_bytes(b'old')
        self.base['files'] = DEP.inventory(self.prefix)
        with self.assertRaisesRegex(ValueError, 'collision'): self.compose()

    def test_unexpected_remaining_requirement(self):
        self.base['remaining_wine_required'].append('ffmpeg')
        with self.assertRaisesRegex(ValueError, 'remaining Wine'): self.compose()

    def test_consumer_rejects_missing_required(self):
        del self.base['components']['ffmpeg']
        with self.assertRaisesRegex(AssertionError, 'Incomplete Wine'): self.compose()

    def test_absolute_symlink_escape(self):
        (self.prefix / 'external').symlink_to('/usr/bin')
        with self.assertRaisesRegex(AssertionError, 'leaves prefix'): self.compose()


class HeaderSources(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='wine-headers-', dir=os.environ['REPRO109_TEST_TMP'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'include/wine').mkdir(parents=True)
        (self.root / 'include/legacy.h').write_bytes(b'old source header')
        self.lock = dict(required_base_files=[dict(path='include/legacy.h')], overlay=[])
        self.makefile = self.root / 'include/Makefile.in'
        self.makefile.write_text('SOURCES = legacy.h\n')

    def add_header(self, name='wine/arm64_memmove.h'):
        path = self.root / 'include' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'new source header')
        return 'include/' + name

    def test_actual_failure_missing_memmove_source_preserves_receipt(self):
        name = self.add_header()
        with self.assertRaisesRegex(ValueError, 'SOURCES missing=.*arm64_memmove'):
            WINE.check_header_sources(self.root, self.lock, self.root)
        receipt = json.loads((self.root / 'header-sources.json').read_bytes())
        self.assertEqual(receipt['status'], 'FAILED')
        self.assertEqual(receipt['missing_sources'], [name])
        self.assertEqual(receipt['header_sha256'][name], WINE.sha(b'new source header'))

    def test_new_siblings_nested_and_literal_continuations(self):
        names = [self.add_header('wine/arm64_memmove.h'), self.add_header('wine/future/nested.h')]
        self.makefile.write_bytes(b'SOURCES = \\\r\n\tlegacy.h \\\r\n\twine/arm64_memmove.h \\\r\n\twine/future/nested.h # accepted literal\r\n')
        receipt = WINE.check_header_sources(self.root, self.lock)
        self.assertEqual(receipt['status'], 'PRESENT')
        self.assertEqual(receipt['required_headers'], sorted(names))
        self.assertEqual(receipt['sources_entries'], 3)

    def test_existing_unlisted_header_does_not_exempt_new_header(self):
        self.add_header('wine/new.h')
        self.makefile.write_text('SOURCES = wine/new.h\n')
        receipt = WINE.check_header_sources(self.root, self.lock)
        self.assertEqual(receipt['legacy_unlisted_headers'], ['include/legacy.h'])
        self.makefile.write_text('SOURCES =\n')
        with self.assertRaisesRegex(ValueError, 'SOURCES missing=.*wine/new.h'):
            WINE.check_header_sources(self.root, self.lock)

    def test_comment_or_other_variable_is_not_sources_registration(self):
        self.add_header()
        for text in ['SOURCES = legacy.h # wine/arm64_memmove.h\n',
                     'SOURCES = legacy.h\nOTHER = wine/arm64_memmove.h\n']:
            with self.subTest(text=text):
                self.makefile.write_text(text)
                with self.assertRaisesRegex(ValueError, 'SOURCES missing=.*arm64_memmove'):
                    WINE.check_header_sources(self.root, self.lock)

    def test_memmove_still_required_when_part_of_new_public_base(self):
        name = self.add_header()
        self.lock['required_base_files'].append(dict(path=name))
        with self.assertRaisesRegex(ValueError, 'SOURCES missing=.*arm64_memmove'):
            WINE.check_header_sources(self.root, self.lock, baseline=WINE.source_headers(self.root))

    def test_overlay_header_checked_even_when_in_baseline(self):
        name = self.add_header('wine/overlay.h')
        self.lock['required_base_files'].append(dict(path=name))
        self.lock['overlay'].append(dict(path=name))
        with self.assertRaisesRegex(ValueError, 'SOURCES missing=.*overlay.h'):
            WINE.check_header_sources(self.root, self.lock)

    def test_overlay_header_registered_but_absent_is_rejected(self):
        self.lock['overlay'].append(dict(path='include/wine/absent.h'))
        self.makefile.write_text('SOURCES = legacy.h wine/absent.h\n')
        with self.assertRaisesRegex(ValueError, 'absent headers=.*absent.h'):
            WINE.check_header_sources(self.root, self.lock)

    def test_ambiguous_or_dynamic_sources_rejected(self):
        for text in ['SOURCES = legacy.h\nSOURCES += wine/new.h\n',
                     'SOURCES = $(OTHER)\n', 'SOURCES = legacy.h \\']:
            with self.subTest(text=text):
                self.makefile.write_text(text)
                with self.assertRaises(ValueError): WINE.check_header_sources(self.root, self.lock)

    def real_108_fixture(self):
        raw = (full.HERE / 'fixtures/header-sources-108-Makefile.in').read_bytes()
        header = (full.HERE / 'fixtures/header-sources-108-arm64_memmove.h').read_bytes()
        self.assertEqual(WINE.sha(raw), 'ff23e01a4d6b80ee8b75f369db2e2cfafe23829826e9d614c135480fb7f4724f')
        self.assertEqual(WINE.sha(header), '700f78754a02e9c8b21645bd6f7d9131653e4301ca99d3b60e03d346134a1952')
        (self.root / 'include/wine/arm64_memmove.h').write_bytes(header)
        self.makefile.write_bytes(raw)
        return raw

    def test_exact_108_makefile_reproduces_memmove_omission(self):
        self.real_108_fixture()
        with self.assertRaisesRegex(ValueError, 'SOURCES missing=.*arm64_memmove'):
            WINE.check_header_sources(self.root, self.lock, self.root)
        receipt = json.loads((self.root / 'header-sources.json').read_bytes())
        self.assertEqual(receipt['sources_entries'], 1104)
        self.assertEqual(receipt['missing_sources'], ['include/wine/arm64_memmove.h'])

    def test_exact_108_makefile_with_one_registration_passes(self):
        raw = self.real_108_fixture()
        needle = b'\twine/afd.h \\\n\twine/asm.h'
        self.assertEqual(raw.count(needle), 1)
        self.makefile.write_bytes(raw.replace(needle, b'\twine/afd.h \\\n\twine/arm64_memmove.h \\\n\twine/asm.h'))
        receipt = WINE.check_header_sources(self.root, self.lock)
        self.assertEqual(receipt['status'], 'PRESENT')
        self.assertEqual(receipt['sources_entries'], 1105)
        self.assertEqual(receipt['required_headers'], ['include/wine/arm64_memmove.h'])

class Drivers(unittest.TestCase):
    def test_pinned_inputs(self):
        pinned = full.check_inputs()['files']
        self.assertEqual(len(pinned), 28)
        self.assertIn('repro109deps/port_probe.py', pinned)
        self.assertEqual(pinned['repro109deps/port_probe.py'],
                         full.digest((full.REPO / 'repro109deps/port_probe.py').read_bytes()))

    def test_profile_preserves_source_locks_and_compiler_pins(self):
        inputs = [DEP.read_lock(), WINE.inputs(), MV_LOCK]
        for original in inputs:
            saved = copy.deepcopy(original)
            selected = full.apply_profile(original, 'xcode-cloud')
            self.assertEqual(original, saved)
            self.assertEqual(selected['toolchain']['profile'], 'xcode-cloud')
            self.assertEqual(selected['toolchain']['sdk'], '27.0')
            self.assertEqual(selected['toolchain']['ld'], '27037.1')
            for key, value in original.items():
                if key != 'toolchain': self.assertEqual(selected[key], value)
            for key, value in original['toolchain'].items():
                if key.startswith('llvm_mingw'): self.assertEqual(selected['toolchain'][key], value)
            selected['toolchain']['sdk'] = 'owned mutation'
            self.assertEqual(original, saved)
        with self.assertRaisesRegex(ValueError, 'Unexpected'): full.apply_profile(inputs[0], 'foreign')

    def test_wine_local_guard_precedes_work_or_dependency_tools(self):
        with tempfile.TemporaryDirectory(dir=os.environ['REPRO109_TEST_TMP']) as directory:
            root = Path(directory) / 'fresh'
            args = SimpleNamespace(work=root)
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, 'Wine source execution'): WINE.build(args, WINE.inputs())
            self.assertFalse(root.exists())

    def test_xcode_cloud_preflight_real_parser_and_exact_measurements(self):
        self.preflight()

    def test_xcode_cloud_preflight_rejects_sdk_drift(self):
        self.preflight(sdk='26.5', failure=AssertionError)

    def test_xcode_cloud_preflight_rejects_ld_drift(self):
        self.preflight(ld='PROJECT:ld-1267.3', failure=ValueError)

    def test_xcode_cloud_preflight_rejects_clang_drift(self):
        self.preflight(clang='Apple clang version 20.0.0', failure=AssertionError)

    def preflight(self, sdk='27.0', ld='PROJECT:ld-27037.1', clang='Apple clang version 21.0.0', failure=None):
        import subprocess
        responses = {
            ('xcodebuild', '-version'): 'Xcode 27.0\nBuild version 27A266a\n',
            ('xcrun', '--show-sdk-version'): sdk,
            ('xcrun', '--show-sdk-path'): '/synthetic-sdk',
            ('xcrun', '--find', 'clang'): '/synthetic-clang',
            ('xcrun', '--find', 'clang++'): '/synthetic-clangxx',
            ('/synthetic-clang', '--version'): clang,
            ('xcrun', 'ld', '-v'): ld,
            ('sw_vers', '-buildVersion'): 'OWNED-MACOS-FIXTURE',
        }
        def disk_command(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, responses[tuple(argv)])
        with tempfile.TemporaryDirectory(dir=os.environ['REPRO109_TEST_TMP']) as directory:
            out = Path(directory)
            tool = full.apply_profile(DEP.read_lock(), 'xcode-cloud')['toolchain']
            with mock.patch.object(DEP.subprocess, 'run', autospec=True, side_effect=disk_command):
                if failure:
                    with self.assertRaises(failure): DEP.toolchain_preflight(tool, out)
                else:
                    selected = DEP.toolchain_preflight(tool, out)
                    self.assertEqual(selected, (Path('/synthetic-sdk'), '/synthetic-clang', '/synthetic-clangxx'))
                    self.assertEqual(tool['exact_pins_state'], 'MEASURED_BEFORE_SOURCES')
            receipt = json.loads((out / 'toolchain-preflight.json').read_bytes())
            self.assertEqual(receipt['status'], 'FAILED' if failure else 'PRESENT')
            self.assertEqual(len(receipt['commands']), 8)
            self.assertEqual(receipt['actual']['sdk'], sdk)

    def test_local_cloud_guard_precedes_creation_or_download(self):
        lock = full.check_inputs()
        with tempfile.TemporaryDirectory(dir=os.environ['REPRO109_TEST_TMP']) as directory:
            root = Path(directory) / 'fresh'
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(full, 'load_driver') as load:
                with self.assertRaisesRegex(ValueError, 'only in the cloud'): full.build(root, lock)
            self.assertFalse(root.exists()); load.assert_not_called()

    def test_sequential_driver_arguments_and_actual_composer(self):
        lock = full.check_inputs()
        with tempfile.TemporaryDirectory(dir=os.environ['REPRO109_TEST_TMP']) as directory:
            root = Path(directory) / 'fresh'; calls = []
            def deps_build(args, lock):
                calls.append('deps'); prefix, mv, base, molten = fixture(root)
                for part, receipt in [('deps', base), ('moltenvk', molten)]:
                    p = root / part / 'reports'; p.mkdir()
                    (p / 'dependency-manifest.json').write_text(json.dumps(receipt))
                self.assertEqual(args.work, root / 'deps')
            def molten_build(args, lock):
                calls.append('moltenvk'); self.assertEqual(args.work, root / 'moltenvk')
            def download(row, destination, out):
                calls.append('compiler'); self.assertEqual(row, lock['compiler']); destination.write_bytes(b'fixture')
            def wine_build(args, lock):
                calls.append('wine'); self.assertEqual(args.prefix, root / 'deps/prefix')
                WINE.dependencies(args.prefix, args.dependencies, args.dependencies_sha256)
                p = args.work / 'reports'; p.mkdir(parents=True)
                (p / 'RESULT.json').write_text(json.dumps(dict(status='FULL_WINE_BUILT_NOT_ACCEPTED', install_skipped=0)))
            dep = SimpleNamespace(build=deps_build, read_lock=lambda: dict(toolchain={}), command=mock.Mock(),
                                  inventory=DEP.inventory, safe_relative=DEP.safe_relative, file_sha=DEP.file_sha, official=DEP.official)
            wine = SimpleNamespace(build=wine_build, inputs=lambda: dict(toolchain={}), dependencies=WINE.dependencies,
                                   download_compiler=download)
            molten = SimpleNamespace(build=molten_build, read_lock=lambda: dict(toolchain={}))
            with mock.patch.object(full, 'cloud_guard'), mock.patch.object(full, 'load_driver', side_effect=[dep, wine, molten]):
                full.build(root, lock)
            self.assertEqual(calls, ['deps', 'moltenvk', 'compiler', 'wine'])
            result = json.loads((root / 'reports/RESULT.json').read_bytes())
            self.assertEqual(result['status'], 'FULL_WINE_SOURCE_BUILT_NOT_ACCEPTED')
            self.assertEqual(result['stands'], 'NOT_ENABLED')

    def test_first_failure_stops_later_phases(self):
        lock = full.check_inputs()
        with tempfile.TemporaryDirectory(dir=os.environ['REPRO109_TEST_TMP']) as directory:
            root = Path(directory) / 'fresh'
            dep = SimpleNamespace(build=mock.Mock(side_effect=ValueError('fixture first failure')), read_lock=lambda: dict(toolchain={}))
            wine = SimpleNamespace(build=mock.Mock()); molten = SimpleNamespace(build=mock.Mock())
            with mock.patch.object(full, 'cloud_guard'), mock.patch.object(full, 'load_driver', side_effect=[dep, wine, molten]):
                with self.assertRaisesRegex(ValueError, 'fixture first failure'): full.build(root, lock)
            molten.build.assert_not_called(); wine.build.assert_not_called()
            self.assertEqual(json.loads((root / 'reports/RESULT.json').read_bytes())['first_failure']['phase'], 'DEPS10')


class TransitiveMoltenInputs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='wine2-inputs-', dir=os.environ['REPRO109_TEST_TMP'])
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.here = self.repo / 'repro109wine'
        self.lock = full.check_inputs()
        for name in self.lock['files']:
            target = self.repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(full.REPO / name, target)
        (self.here / 'full.lock.json').write_text(json.dumps(self.lock))
        self.molten_path = self.repo / 'repro109moltenvk/moltenvk.lock.json'
        self.molten = json.loads(self.molten_path.read_bytes())

    def repin_outer_lock(self, molten):
        self.molten_path.write_text(json.dumps(molten))
        self.lock['files']['repro109moltenvk/moltenvk.lock.json'] = full.digest(self.molten_path.read_bytes())
        (self.here / 'full.lock.json').write_text(json.dumps(self.lock))
        self.assertTrue(all(full.digest((self.repo / name).read_bytes()) == expected
                            for name, expected in self.lock['files'].items()))

    def check_inputs(self):
        with mock.patch.object(full, 'REPO', self.repo), mock.patch.object(full, 'HERE', self.here):
            return full.check_inputs()

    def test_matching_outer_and_transitive_inputs_pass(self):
        self.assertEqual(len(self.check_inputs()['files']), 28)

    def test_matching_outer_lock_rejects_each_stale_shared_pin(self):
        for key in ['shared_driver_sha256', 'shared_source_fixes_sha256', 'bootstrap_lock_sha256']:
            with self.subTest(key=key):
                molten = copy.deepcopy(self.molten)
                molten[key] = '0' * 64
                self.repin_outer_lock(molten)
                with self.assertRaisesRegex(ValueError, 'Shared recipe drift: ' + key):
                    self.check_inputs()

    def test_matching_outer_lock_rejects_bootstrap_toolchain_drift(self):
        molten = copy.deepcopy(self.molten)
        molten['toolchain']['sdk'] = 'fixture drift'
        self.repin_outer_lock(molten)
        with self.assertRaisesRegex(ValueError, 'Bootstrap toolchain drift'):
            self.check_inputs()


if __name__ == '__main__':
    unittest.main(verbosity=2)
