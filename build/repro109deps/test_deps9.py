"""Controls for the four observed deps8 failures and the selected cloud route."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_deps as deps
import deps9_support as support


class Deps9Tests(unittest.TestCase):
    def test_fontconfig_exact_platform_generator_and_foreign_siblings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, reports = root/'source', root/'reports'
            intro = source/'_repro_build/meson-info/intro-buildsystem_files.json'
            intro.parent.mkdir(parents=True)
            reports.mkdir()
            own = source/'meson.build'
            own.write_text('project("fixture", "c")')
            intro.write_text(json.dumps([str(own), '/usr/bin/gperf']))
            with patch.object(deps, 'file_sha', return_value='1'*64), patch.object(Path, 'is_file', return_value=True):
                result = deps.meson_source_ownership(source, reports, 'fontconfig')
                self.assertEqual(result['source_files'], 1)
                self.assertEqual(result['build_tools'][0]['name'], 'gperf')
                self.assertEqual(result['build_tools'][0]['owner'], 'PLATFORM_TOOL')
                for name in ['/usr/bin/m4', '/opt/homebrew/bin/gperf', '/usr/local/bin/gperf', str(root/'foreign.c')]:
                    intro.write_text(json.dumps([str(own), name]))
                    with self.assertRaisesRegex(AssertionError, 'foreign source'):
                        deps.meson_source_ownership(source, reports, 'fontconfig')
                intro.write_text(json.dumps([str(own), '/usr/bin/gperf']))
                with self.assertRaisesRegex(AssertionError, 'foreign source'):
                    deps.meson_source_ownership(source, reports, 'glib')

    def sdk_fixture(self, root):
        sdk, prefix, out = root/'SDK', root/'prefix', root/'reports'
        for p in [sdk/'usr/include', sdk/'usr/lib', prefix/'lib/pkgconfig', out]:
            p.mkdir(parents=True)
        (sdk/'usr/include/zlib.h').write_text('#define ZLIB_VERSION "1.2.12"\n')
        (sdk/'usr/lib/libz.tbd').write_text('fixture platform stub')
        return sdk, prefix, out

    def test_sdk_zlib_metadata_uses_only_selected_sdk_and_exact_header_version(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk, prefix, out = self.sdk_fixture(Path(directory))
            result = support.sdk_zlib_metadata(sdk, prefix, out)
            pc = prefix/'lib/pkgconfig/zlib.pc'
            self.assertEqual(result['header_version'], '1.2.12')
            self.assertEqual(result['owner'], 'SELECTED_APPLE_SDK_NOT_SOURCE_BUILT')
            self.assertIn('Version: 1.2.12', pc.read_text())
            self.assertIn('prefix='+str(sdk.resolve())+'/usr', pc.read_text())
            self.assertEqual(result['pkg_config']['sha256'], support.sha(pc))
            self.assertEqual(len(result['inputs']), 2)
            with self.assertRaisesRegex(ValueError, 'fresh metadata'):
                support.sdk_zlib_metadata(sdk, prefix, out)

    def test_sdk_missing_file_foreign_symlink_and_nonliteral_version_are_refused(self):
        for mode in ['missing', 'foreign', 'version']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sdk, prefix, out = self.sdk_fixture(root)
                path = sdk/'usr/include/zlib.h'
                if mode == 'missing':
                    path.unlink()
                elif mode == 'foreign':
                    path.unlink()
                    (root/'foreign.h').write_text('#define ZLIB_VERSION "1.2.12"\n')
                    path.symlink_to(root/'foreign.h')
                else:
                    path.write_text('#define ZLIB_VERSION other\n')
                with self.assertRaisesRegex(ValueError, 'SDK zlib'):
                    support.sdk_zlib_metadata(sdk, prefix, out)

    def test_zlib_roundtrip_probe_uses_sdk_and_preserves_header_runtime_difference(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk, prefix, out = self.sdk_fixture(Path(directory))
            support.sdk_zlib_metadata(sdk, prefix, out)
            calls = []
            def command(argv, cwd, env, log, *rest):
                calls.append(argv)
                if len(calls) == 1:
                    (out/'sdk-zlib-probe').write_bytes(b'fixture executable')
                    log.write_text('fixture compile')
                else:
                    log.write_text('SDK_ZLIB_OK header=1.2.12 runtime=1.3\n')
            result = support.probe_sdk_zlib(prefix, dict(CC='/selected/clang', SDKROOT=str(sdk),
                                            MACOSX_DEPLOYMENT_TARGET='14.0'), out, 999, command)
            self.assertEqual(calls[0][0], '/selected/clang')
            self.assertEqual(calls[0][calls[0].index('-isysroot')+1], str(sdk))
            self.assertEqual((result['header_version'], result['runtime_version']), ('1.2.12', '1.3'))
            self.assertIn('memcmp', (out/'sdk-zlib-probe.c').read_text())
            self.assertIn('-lz', calls[0])

    def test_vmaf_archive_pin_unchanged_and_pc_version_is_observed_upstream_value(self):
        row = next(r for r in deps.read_lock()['components'] if r['name']=='libvmaf')
        self.assertEqual(row['version'], '3.1.0')
        self.assertEqual(row['sha256'], '80090e29d7fd0db472ddc663513f5be89bc936815e62b767e630c1d627279fe2')
        self.assertEqual(row['pkg_config_version'], '3.0.0')
        row = next(r for r in deps.read_lock()['components'] if r['name']=='gnutls')
        self.assertEqual(row['test_args'], ['check'])

    def test_failed_test_raw_bytes_script_and_hash_survive_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, out = root/'source', root/'reports'
            tests = source/'tests'
            tests.mkdir(parents=True)
            out.mkdir()
            raw = b'FAIL: gnutls-cli-debug.sh\nbyte-exact \xff\x00\n'
            (tests/'test-suite.log').write_bytes(raw)
            (tests/'gnutls-cli-debug.sh').write_bytes(b'exit 1\n')
            result = support.preserve_gnutls_tests(source, out, 'gnutls')
            self.assertEqual(result['state'], 'PRESENT')
            self.assertEqual((out/'gnutls-test-evidence/tests/test-suite.log').read_bytes(), raw)
            self.assertEqual(result['files'][0]['sha256'], support.sha(tests/'test-suite.log'))
            self.assertEqual({r['path'] for r in result['files']}, {'tests/test-suite.log','tests/gnutls-cli-debug.sh'})
            self.assertTrue(any(r['state']=='EMPTY' for r in result['omitted']))

    def test_test_evidence_cap_missing_and_foreign_are_explicit(self):
        for mode, expected in [('cap','DROPPED'), ('missing','FAILED'), ('foreign','FAILED')]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, out = root/'source', root/'reports'
                source.mkdir(); out.mkdir()
                if mode != 'missing':
                    tests = source/'tests'; tests.mkdir()
                    if mode=='cap':
                        (tests/'test-suite.log').write_bytes(b'0123456789')
                    else:
                        (root/'foreign.log').write_bytes(b'foreign')
                        (tests/'test-suite.log').symlink_to(root/'foreign.log')
                result = support.preserve_gnutls_tests(source, out, 'gnutls', max_bytes=3)
                self.assertEqual(result['state'], expected)
                self.assertEqual(result['bytes'], 0)

    def xcode_preflight(self, sdk='27.0', linker='27037.1'):
        tool = json.loads((deps.HERE/'xcode-cloud.lock.json').read_text())
        tool['deployment_target'] = '14.0'
        outputs = ['Xcode 27.0\nBuild version 27A266a\n', sdk+'\n', '/selected/SDK\n',
                   '/selected/clang\n', '/selected/clang++\n', 'Apple clang version 21.0.0 (fixture)\n',
                   'PROGRAM:ld PROJECT:ld-'+linker+'\n', 'fixture-macos-build\n']
        iterator = iter(outputs)
        with patch.object(deps.subprocess, 'run', side_effect=lambda *a, **kw: subprocess.CompletedProcess(a[0],0,next(iterator))), \
                patch.object(Path, 'write_text') as write:
            result, error = None, None
            try:
                result = deps.toolchain_preflight(tool, Path('/reports'))
            except (AssertionError, ValueError) as caught:
                error = str(caught)
        return result, error, json.loads(write.call_args[0][0]), tool

    def test_xcode_effective_pins_measured_without_rewriting_expected_profile(self):
        result, error, receipt, effective = self.xcode_preflight()
        self.assertIsNone(error)
        self.assertEqual(str(result[0]), '/selected/SDK')
        self.assertNotIn('xcode_build', receipt['expected'])
        self.assertEqual(effective['xcode_build'], '27A266a')
        self.assertEqual(effective['exact_pins_state'], 'MEASURED_BEFORE_SOURCES')
        self.assertEqual(effective['deployment_target'], '14.0')
        self.assertEqual(effective['python'], sys.version.split()[0])

    def test_xcode_wrong_sdk_or_old_linker_refused_before_sources(self):
        for sdk, linker in [('26.5','27037.1'), ('27.0','1267.0'), ('27.0','27037.10')]:
            _, error, report, _ = self.xcode_preflight(sdk, linker)
            self.assertIsNotNone(error)
            self.assertEqual(report['status'], 'FAILED')
            self.assertIn('actual=', error)


if __name__ == '__main__':
    unittest.main()
