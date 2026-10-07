#!/usr/bin/env python3
"""Run every owned driver branch with sealed in-memory inputs, no network or tools."""
import argparse
import builtins
import contextlib
import copy
import io
import json
import subprocess
import symtable
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import build_deps as deps


class DryRun(unittest.TestCase):
    def test_no_unresolved_global_references(self):
        path = Path(deps.__file__)
        table = symtable.symtable(path.read_text(), str(path), 'exec')
        known = set(table.get_identifiers()) | set(dir(builtins)) | {'__file__', '__name__'}
        missing = []
        def visit(scope):
            for symbol in scope.get_symbols():
                if symbol.is_referenced() and symbol.is_global() and symbol.get_name() not in known:
                    missing.append((scope.get_name(), symbol.get_name()))
            for child in scope.get_children():
                visit(child)
        visit(table)
        self.assertEqual(missing, [])

    def simulate_batch(self, failures=(), expire=False):
        lock = deps.read_lock()
        rows = lock['components']
        x264 = next(row for row in rows if row['name'] == 'x264')
        versions = {Path(name).stem: row.get('pkg_config_version', row['version'])
                    for row in rows for name in row['outputs'] if name.endswith('.pc')}
        tools = {Path(row['probe'][0]).name: row['version'] for row in rows if row.get('probe')}
        def query(argv, env=None, raw_log=None):
            if argv[0] == '/usr/bin/nm':
                return '(undefined) external _yylex (dynamically looked up)'
            if 'rev-parse' in argv:
                return x264['revision']
            if 'rev-list' in argv:
                return str(x264['revision_count'])
            if '--modversion' in argv:
                return versions[argv[-1]]
            return tools[Path(argv[0]).name]
        def sha(path):
            return x264['sha256'] if path.name == 'x264.source.tar' else '1' * 64
        def run_command(*args, **kwargs):
            if args[5] in failures:
                raise RuntimeError('MOCK_BUILD_FAILURE ' + args[5])
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(deps.os.environ, {'GITHUB_ACTIONS': 'true'}, clear=True))
            stack.enter_context(patch.object(deps.platform, 'system', return_value='Darwin'))
            stack.enter_context(patch.object(deps.platform, 'machine', return_value='arm64'))
            stack.enter_context(patch.object(deps.sys, 'version', '3.13.7 dry'))
            stack.enter_context(patch.object(deps, 'toolchain_preflight', return_value=(Path('/sdk'), '/clang', '/clang++')))
            stack.enter_context(patch.object(Path, 'exists', return_value=False))
            stack.enter_context(patch.object(Path, 'is_symlink', return_value=False))
            stack.enter_context(patch.object(Path, 'is_file', return_value=True))
            stack.enter_context(patch.object(Path, 'resolve', autospec=True, side_effect=lambda p: p))
            stack.enter_context(patch.object(Path, 'stat', return_value=SimpleNamespace(st_size=1)))
            stack.enter_context(patch.object(Path, 'glob', return_value=[]))
            for name in ['mkdir', 'touch', 'chmod', 'symlink_to', 'write_bytes']:
                stack.enter_context(patch.object(Path, name))
            writes = stack.enter_context(patch.object(Path, 'write_text'))
            stack.enter_context(patch.object(deps.shutil, 'copyfile'))
            data_copy = stack.enter_context(patch.object(deps.shutil, 'copytree'))
            downloads = stack.enter_context(patch.object(deps, 'download'))
            stack.enter_context(patch.object(deps, 'unpack', side_effect=lambda archive, root: root))
            stack.enter_context(patch.object(deps, 'file_sha', side_effect=sha))
            commands = stack.enter_context(patch.object(deps, 'command', side_effect=run_command))
            stack.enter_context(patch.object(deps, 'output', side_effect=query))
            stack.enter_context(patch.object(deps, 'event'))
            stack.enter_context(patch.object(deps, 'apply_source_fixes'))
            stack.enter_context(patch.object(deps, 'sdk_zlib_metadata'))
            stack.enter_context(patch.object(deps, 'probe_sdk_zlib'))
            stack.enter_context(patch.object(deps, 'preserve_gnutls_tests', return_value={'state': 'EMPTY', 'files': [], 'bytes': 0}))
            stack.enter_context(patch.object(deps, 'install_meson'))
            stack.enter_context(patch.object(deps, 'meson_source_ownership', return_value={'state': 'PRESENT'}))
            cmake = stack.enter_context(patch.object(deps, 'cmake_source_ownership', return_value={'state': 'PRESENT'}))
            configure = stack.enter_context(patch.object(deps, 'configure_source_ownership', return_value={'state': 'PRESENT'}))
            plugins = stack.enter_context(patch.object(deps, 'gst_plugin_probes', return_value=[{'state': 'PRESENT'}]))
            stack.enter_context(patch.object(deps, 'libvpx_install_name_probe',
                                            return_value={'identity': '@rpath/libvpx.12.dylib'}))
            stack.enter_context(patch.object(deps, 'licenses', return_value=['LICENSE']))
            stack.enter_context(patch.object(deps, 'inventory', return_value=[]))
            stack.enter_context(patch.object(Path, 'read_text', return_value='FLEX_PROBE_OK'))
            stack.enter_context(patch.object(deps.subprocess, 'run', side_effect=AssertionError('UNEXPECTED TOOL EXECUTION')))
            stack.enter_context(patch.object(deps.subprocess, 'Popen', side_effect=AssertionError('UNEXPECTED BUILD EXECUTION')))
            if expire:
                stack.enter_context(patch.object(deps.time, 'monotonic', side_effect=[0] + [10000] * 200))
            error = None
            with contextlib.redirect_stdout(io.StringIO()):
                try:
                    deps.build(argparse.Namespace(work=Path('/dry-work'), jobs=4, minutes=90), lock)
                except RuntimeError as caught:
                    error = str(caught)
        result = json.loads(writes.call_args_list[-1].args[0])
        return result, error, dict(downloads=downloads.call_count, configure=configure.call_count,
            plugins=plugins.call_count, data_copy=data_copy.call_count, cmake=cmake.call_count,
            commands=commands.call_count)

    def test_complete_47_component_build_loop_without_network_or_execution(self):
        result, error, calls = self.simulate_batch()
        rows = deps.read_lock()['components']
        self.assertIsNone(error)
        self.assertEqual(result['built_components'], 47)
        self.assertEqual(result['missing_wine_components'], ['MoltenVK'])
        self.assertEqual(result['install_skipped'], 0)
        self.assertFalse(result['wine_ready'])
        self.assertEqual(calls['downloads'], 46)
        self.assertEqual(calls['configure'], 2)
        self.assertEqual(calls['plugins'], 6)
        self.assertEqual(calls['data_copy'], 1)
        self.assertEqual(calls['cmake'], sum(row['kind'] == 'cmake' for row in rows) + 2)
        self.assertGreater(calls['commands'], 150)

    def test_failed_flex_preserves_first_failure_and_builds_independent_neighbors(self):
        result, error, _ = self.simulate_batch(('flex',))
        self.assertIn('expected=47 built; actual=40', error)
        self.assertEqual(result['built_components'], 40)
        self.assertEqual([row['component'] for row in result['failed_components']], ['flex'])
        self.assertEqual(result['first_failure']['component'], 'flex')
        self.assertEqual(result['component_states']['openssl']['state'], 'BUILT')
        self.assertEqual(result['component_states']['gnutls']['state'], 'BUILT')
        self.assertEqual(result['component_states']['gst-libav']['state'], 'NOT_ENABLED')
        self.assertEqual(len(result['component_states']), 47)
        self.assertIn('flex', result['missing_wine_components'])
        self.assertIn('gstreamer', result['missing_wine_components'])
        self.assertEqual(result['missing_wine_recipe_components'], ['MoltenVK'])
        self.assertFalse(result['wine_ready'])

    def test_two_failures_report_both_and_skip_direct_and_transitive_dependents(self):
        result, error, _ = self.simulate_batch(('flex', 'libpng'))
        self.assertIsNotNone(error)
        self.assertEqual(result['built_components'], 37)
        self.assertEqual([row['component'] for row in result['failed_components']], ['flex', 'libpng'])
        self.assertEqual(result['first_failure']['component'], 'flex')
        self.assertEqual(result['component_states']['freetype']['dependencies'], ['libpng'])
        self.assertEqual(result['component_states']['fontconfig']['dependencies'], ['freetype'])
        self.assertEqual(result['component_states']['libvpx']['state'], 'BUILT')
        self.assertEqual(len(result['component_states']), 47)

    def test_batch_deadline_is_not_enabled_and_no_new_source_is_downloaded(self):
        result, error, calls = self.simulate_batch(expire=True)
        self.assertIsNotNone(error)
        self.assertEqual(result['built_components'], 0)
        self.assertEqual(result['failed_components'], [])
        self.assertEqual(len(result['skipped_components']), 47)
        self.assertEqual(calls['downloads'], 0)
        self.assertEqual(calls['commands'], 0)
        self.assertEqual(result['component_states']['cmake']['reason'], 'BATCH_DEADLINE')

    def test_libfl_allows_only_caller_yylex_not_arbitrary_undefined_symbols(self):
        for value in ['', '(undefined) external _unexpected (dynamically looked up)',
                      '(undefined) external _yylex (dynamically looked up)\n(undefined) external _extra (dynamically looked up)']:
            with patch.object(deps, 'output', return_value=value), patch.object(deps, 'command') as command:
                with self.assertRaisesRegex(ValueError, 'expected=.*actual='):
                    deps.flex_libfl_probe(Path('/prefix'), {}, Path('/out'), 1)
            command.assert_not_called()

    def test_x265_all_depths_have_separate_source_checks_before_build(self):
        row = next(row for row in deps.read_lock()['components'] if row['name'] == 'x265')
        steps = deps.build_steps(row, Path('/source'), Path('/prefix'), Path('/sdk'), 4)
        configs = [argv for argv in steps if '-S' in argv]
        self.assertEqual([argv[argv.index('-B') + 1] for argv in configs],
                         ['_repro_10bit', '_repro_12bit', '_repro_build'])
        self.assertIn('-DMAIN12=ON', configs[1])
        self.assertIn('-DENABLE_HDR10_PLUS=ON', configs[0])
        self.assertIn('-DLINKED_10BIT=ON', configs[2])
        self.assertIn('-DLINKED_12BIT=ON', configs[2])
        self.assertIn('-DEXTRA_LIB=/source/_repro_10bit/libx265.a;/source/_repro_12bit/libx265.a', configs[2])

    def test_source_guard_and_ffmpeg_feature_loss_preserve_expected_actual(self):
        row = next(row for row in deps.read_lock()['components'] if row['name'] == 'ffmpeg')
        features = ''.join('CONFIG_' + name.upper() + '=yes\n' for name in row['ffmpeg_external'])
        for text, good in [('SRC_PATH=/source\n' + features, True),
                           ('SRC_PATH=/foreign\n' + features, False),
                           ('SRC_PATH=/source\n' + features.replace('CONFIG_LIBX264=yes', 'CONFIG_LIBX264=no'), False)]:
            with patch.object(Path, 'read_bytes', return_value=text.encode()), \
                    patch.object(Path, 'write_bytes'), patch.object(Path, 'write_text'):
                if good:
                    self.assertEqual(deps.configure_source_ownership(row, Path('/source'), Path('/out'))['state'], 'PRESENT')
                else:
                    with self.assertRaisesRegex(ValueError, 'expected=.*actual='):
                        deps.configure_source_ownership(row, Path('/source'), Path('/out'))

    def test_query_success_failure_limit_and_timeout(self):
        with patch.object(deps.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'1.0\n')):
            self.assertEqual(deps.output(['tool']), '1.0')
        for rc, raw in [(1, b'error'), (0, b'x' * (1024 * 1024 + 1))]:
            with patch.object(deps.subprocess, 'run', return_value=subprocess.CompletedProcess([], rc, raw)):
                with self.assertRaisesRegex(ValueError, 'expected.*actual'):
                    deps.output(['tool'])
        with patch.object(deps.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['tool'], 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                deps.output(['tool'])


if __name__ == '__main__':
    unittest.main()
