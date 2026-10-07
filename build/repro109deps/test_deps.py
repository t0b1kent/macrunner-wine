#!/usr/bin/env python3
"""Offline controls: do not download, build, execute third-party binaries, or create test files."""
import copy
import json
import os
import tarfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import build_deps as deps


class SourceRecipes(unittest.TestCase):
    def test_real_lock(self):
        self.assertEqual(len(deps.read_lock()['components']), 47)

    def altered_lock(self, mutate):
        value = copy.deepcopy(deps.read_lock())
        mutate(value)
        with patch.object(Path, 'read_text', return_value=json.dumps(value)):
            with self.assertRaises(AssertionError):
                deps.read_lock()

    def test_duplicate_component(self):
        self.altered_lock(lambda value: value['components'][1].update(name='cmake'))

    def test_unordered_dependency(self):
        self.altered_lock(lambda value: value['components'][0].update(depends=['ninja']))

    def test_missing_dependency(self):
        self.altered_lock(lambda value: value['components'][0].update(depends=['foreign']))

    def test_invalid_hash(self):
        self.altered_lock(lambda value: value['components'][0].update(sha256='unknown'))

    def test_foreign_source(self):
        self.altered_lock(lambda value: value['components'][0].update(url='https://example.org/cmake.tar.gz'))

    def test_foreign_github_project(self):
        with self.assertRaises(AssertionError):
            deps.official('https://github.com/other/CMake/releases/source.tar.gz')

    def test_archive_root_and_links(self):
        member = tarfile.TarInfo('pkg/configure')
        link = tarfile.TarInfo('pkg/build/configure')
        link.type, link.linkname = tarfile.SYMTYPE, '../configure'
        self.assertEqual(deps.source_root([member, link]), 'pkg')
        link.linkname = '../../foreign'
        with self.assertRaises(AssertionError):
            deps.source_root([member, link])

    def test_archive_traversal_and_absolute(self):
        for name in ['../configure', '/pkg/configure', '.']:
            with self.assertRaises(AssertionError):
                deps.source_root([tarfile.TarInfo(name)])

    def test_archive_mixed_root_and_device(self):
        with self.assertRaises(AssertionError):
            deps.source_root([tarfile.TarInfo('pkg/a'), tarfile.TarInfo('other/b')])
        device = tarfile.TarInfo('pkg/device')
        device.type = tarfile.CHRTYPE
        with self.assertRaises(AssertionError):
            deps.source_root([device])

    def test_archive_expanded_size(self):
        member = tarfile.TarInfo('pkg/a')
        member.size = deps.MAX_EXPANDED + 1
        with self.assertRaises(AssertionError):
            deps.source_root([member])

    def test_build_plan_uses_source_and_prefix(self):
        for row in deps.read_lock()['components']:
            commands = deps.build_steps(row, Path('/work/source'), Path('/work/prefix'), Path('/sdk'), 4)
            self.assertTrue(commands)
            self.assertFalse(any(Path(argv[0]).name in {'brew', 'curl', 'wget'} for argv in commands))
            self.assertFalse(any('{' in x or '}' in x for argv in commands for x in argv))
        ssl = next(row for row in deps.read_lock()['components'] if row['name'] == 'openssl')
        self.assertIn(['make', 'test'], deps.build_steps(ssl, Path('/src'), Path('/prefix'), Path('/sdk'), 4))
        self.assertEqual(ssl['deployment_target'], '26.0')

    def test_required_closure_cannot_hide_missing_component(self):
        self.altered_lock(lambda value: value['remaining_wine_required'].remove('MoltenVK'))

    def test_metadata_provenance_required(self):
        self.altered_lock(lambda value: value['components'][-1]['metadata'].update(sha256='unknown'))

    def test_meson_cannot_implicitly_download_subprojects(self):
        for row in deps.read_lock()['components']:
            if row['kind'] != 'meson':
                continue
            commands = deps.build_steps(row, Path('/work/source'), Path('/work/prefix'), Path('/sdk'), 4)
            self.assertIn('--wrap-mode=nodownload', commands[0])
            self.assertEqual(commands[0][3], str(Path('/work/source') / row.get('source_subdir', '.')))
            self.assertEqual(Path(commands[0][0]), Path('/work/prefix/bin/meson'))
        row = next(x for x in deps.read_lock()['components'] if x['name'] == 'p11-kit')
        self.assertIn('test', deps.build_steps(row, Path('/src'), Path('/prefix'), Path('/sdk'), 4)[2])
        row = next(x for x in deps.read_lock()['components'] if x['name'] == 'gnutls')
        self.assertIn('check', deps.build_steps(row, Path('/src'), Path('/prefix'), Path('/sdk'), 4)[2])

    def test_meson_tool_order_and_foreign_distributions(self):
        self.altered_lock(lambda value: next(row for row in value['components']
                         if row['name'] == 'glib').update(depends=['ninja', 'pkgconf']))
        for url in ['https://files.pythonhosted.org/packages/foreign/meson.whl',
                    'https://gitlab.freedesktop.org/foreign/fontconfig/-/archive/x.tar.gz']:
            with self.assertRaises(AssertionError):
                deps.official(url)

    def test_meson_source_ownership_rejects_foreign_file(self):
        with patch.object(Path, 'read_text', return_value=json.dumps(['/src/meson.build'])), \
             patch.object(deps.shutil, 'copyfile'), patch.object(deps, 'file_sha', return_value='0' * 64):
            self.assertEqual(deps.meson_source_ownership(Path('/src'), Path('/reports'), 'glib')['foreign_files'], 0)
        with patch.object(Path, 'read_text', return_value=json.dumps(['/foreign/meson.build'])), \
             patch.object(deps.shutil, 'copyfile'):
            with self.assertRaises(AssertionError):
                deps.meson_source_ownership(Path('/src'), Path('/reports'), 'glib')

    def test_environment_drops_foreign_flags_and_tokens(self):
        with patch.dict(os.environ, {'CFLAGS': 'foreign', 'PKG_CONFIG_PATH': '/foreign', 'GH_TOKEN': 'sentinel'}):
            env = deps.environment(Path('/prefix'), {'deployment_target': '14.0'}, '/clang', '/clang++', Path('/sdk'))
        self.assertEqual(env['PKG_CONFIG_PATH'], '')
        self.assertNotIn('foreign', env['CFLAGS'])
        self.assertNotIn('GH_TOKEN', env)
        self.assertEqual(env['CC'], '/clang')

    def test_zip_root_limits_and_rejects_links(self):
        member = zipfile.ZipInfo('fmt/include/fmt/format.h')
        self.assertEqual(deps.zip_source_root([member]), 'fmt')
        member.external_attr = 0o120777 << 16
        with self.assertRaises(AssertionError):
            deps.zip_source_root([member])
        member.external_attr, member.file_size = 0, deps.MAX_EXPANDED + 1
        with self.assertRaises(AssertionError):
            deps.zip_source_root([member])

    def test_zip_path_and_mixed_root_rejected(self):
        for name in ['../fmt/file', '/fmt/file', 'fmt\\file', '.']:
            with self.assertRaises(AssertionError):
                deps.zip_source_root([zipfile.ZipInfo(name)])
        with self.assertRaises(AssertionError):
            deps.zip_source_root([zipfile.ZipInfo('fmt/a'), zipfile.ZipInfo('foreign/b')])

    def test_cmake_tools_local_source_and_no_network_fallback(self):
        lock = deps.read_lock()
        for row in lock['components']:
            if row['kind'] != 'cmake':
                continue
            steps = deps.build_steps(row, Path('/src'), Path('/prefix'), Path('/sdk'), 4)
            self.assertEqual(steps[0][2], str(Path('/src') / row.get('source_subdir', '.')))
            self.assertIn('-DFETCHCONTENT_FULLY_DISCONNECTED=ON', steps[0])
            self.assertIn('-DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local', steps[0])
            self.assertEqual(steps[-1], ['/prefix/bin/cmake', '--install', '_repro_build'])
        optional = json.loads((deps.HERE / 'optional-ccache.lock.json').read_text())
        row = next(x for x in optional['components'] if x['name'] == 'ccache')
        self.assertNotIn('ccache', lock['wine_required'])
        self.assertNotIn('ccache', [x['name'] for x in lock['components']])
        steps = deps.build_steps(row, Path('/src'), Path('/prefix'), Path('/sdk'), 4)
        self.assertIn('-DDEPS=LOCAL', steps[0])
        self.assertEqual(steps[2][0], '/prefix/bin/ctest')
        self.assertIn('--no-tests=error', steps[2])
        self.altered_lock(lambda value: next(x for x in value['components']
                          if x['name'] == 'jpeg-turbo').update(depends=['pkgconf']))

    def test_requirement_alias_keeps_wine_consumer_name(self):
        row = next(x for x in deps.read_lock()['components'] if x['name'] == 'vulkan-headers')
        self.assertEqual(row['wine_requirement'], 'Vulkan-Headers')
        self.assertNotIn('Vulkan-Headers', deps.read_lock()['remaining_wine_required'])
        self.altered_lock(lambda value: value['components'][-1].update(wine_requirement='unknown'))
        self.altered_lock(lambda value: value['components'][-1].update(wine_requirement='ccache'))

    def test_cmake_source_guard_checks_actual_inputs(self):
        paths = [Path('/src/_repro_build/.cmake/api/v1/reply/cmakeFiles-v1-x.json'),
                 Path('/src/_repro_build/.cmake/api/v1/reply/codemodel-v2-x.json'),
                 Path('/src/_repro_build/.cmake/api/v1/reply/target-x.json')]
        def contents(path, *args, **kwargs):
            if path.name == 'CMakeCache.txt':
                return 'CMAKE_HOME_DIRECTORY:INTERNAL=/src\n'
            if path.name.startswith('cmakeFiles'):
                return json.dumps({'inputs': [{'path': '/src/CMakeLists.txt'},
                                             {'path': '/prefix/share/cmake/FindThreads.cmake'}]})
            if path.name.startswith('target'):
                return json.dumps({'sources': [{'path': '/src/main.cpp'}]})
            return '{}'
        with patch.object(Path, 'read_text', contents), patch.object(Path, 'glob', return_value=paths), \
             patch.object(Path, 'mkdir'), patch.object(deps.shutil, 'copyfile') as copies, \
             patch.object(deps, 'file_sha', return_value='0' * 64):
            result = deps.cmake_source_ownership(Path('/src'), Path('/src'), Path('/prefix'),
                                                Path('/sdk'), Path('/reports'), 'ccache')
            self.assertEqual(result['configured_files'], 3)
            self.assertEqual(result['foreign_files'], 0)
            previous_copies = copies.call_count
            with self.assertRaises(AssertionError):
                deps.cmake_source_ownership(Path('/src'), Path('/foreign'), Path('/prefix'),
                                           Path('/sdk'), Path('/reports'), 'ccache')
            self.assertEqual(copies.call_count - previous_copies, 4)
            original = contents
            def foreign_contents(path, *args, **kwargs):
                if path.name.startswith('target'):
                    return json.dumps({'sources': [{'path': '/opt/homebrew/foreign.cpp'}]})
                return original(path, *args, **kwargs)
            with patch.object(Path, 'read_text', foreign_contents):
                with self.assertRaises(AssertionError):
                    deps.cmake_source_ownership(Path('/src'), Path('/src'), Path('/prefix'),
                                               Path('/sdk'), Path('/reports'), 'ccache')


    def test_gst_plugin_output_cannot_be_omitted(self):
        self.altered_lock(lambda value: next(row for row in value['components']
                          if row['name'] == 'gstreamer')['outputs'].remove(
                              'lib/gstreamer-1.0/libgstcoreelements.dylib'))

    def test_gst_plugin_report_rejects_foreign_file_and_version(self):
        path = Path('/prefix/lib/gstreamer-1.0/libgstcoreelements.dylib')
        report = f'Plugin Details:\n  Filename  {path}\n  Version  1.28.3\n'
        self.assertEqual(deps.inspect_plugin_report(report, path, '1.28.3')['state'], 'PRESENT')
        for changed in [report.replace('/prefix/', '/foreign/'),
                        report.replace('1.28.3', '1.28.2'), '']:
            with self.assertRaises(AssertionError):
                deps.inspect_plugin_report(changed, path, '1.28.3')

    def test_gst_plugin_probe_selects_prefix_scanner_and_bounded_log(self):
        row = next(x for x in deps.read_lock()['components'] if x['name'] == 'gstreamer')
        report = ('  Filename /prefix/lib/gstreamer-1.0/libgstcoreelements.dylib\n'
                  '  Version 1.28.3\n')
        with patch.object(deps, 'command') as command, patch.object(deps, 'event'), \
                patch.object(Path, 'read_text', return_value=report), \
                patch.object(deps, 'file_sha', return_value='a' * 64):
            result = deps.gst_plugin_probes(row, Path('/src'), Path('/prefix'),
                                           {'PATH': '/prefix/bin:/usr/bin'}, Path('/out'), 100)
        self.assertEqual(len(result), 1)
        args, kwargs = command.call_args
        self.assertEqual(args[0], ['/prefix/bin/gst-inspect-1.0', '--plugin',
                                  '/prefix/lib/gstreamer-1.0/libgstcoreelements.dylib'])
        self.assertEqual(args[2]['GST_PLUGIN_SYSTEM_PATH_1_0'], '/prefix/lib/gstreamer-1.0')
        self.assertEqual(args[2]['GST_PLUGIN_PATH_1_0'], '')
        self.assertEqual(args[2]['GST_PLUGIN_SCANNER_1_0'],
                         '/prefix/libexec/gstreamer-1.0/gst-plugin-scanner')
        self.assertEqual(kwargs['timeout'], 30)


if __name__ == '__main__':
    unittest.main()
