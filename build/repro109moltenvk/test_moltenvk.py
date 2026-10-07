"""Offline negative controls. No source download, compiler, Xcode or GPU calls."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('repro_moltenvk', HERE / 'build_moltenvk.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class Controls(unittest.TestCase):
    def test_shared_source_fixes_module_is_sealed(self):
        self.malformed_lock(lambda x: x.update(shared_source_fixes_sha256='0' * 64))

    def test_expected_actual_are_lazy_and_survive_unreadable_probe(self):
        with patch.object(m, 'sha', side_effect=ValueError('read failure')):
            m.require(True, 'pin drift', expected='expected_value', actual={'observed': lambda: m.sha(Path('/unused'))})
            with self.assertRaises(ValueError) as error:
                m.require(False, 'pin drift', expected='expected_value', actual={
                    'observed': lambda: 'actual_value', 'unreadable': lambda: m.sha(Path('/unused'))})
        message = str(error.exception)
        self.assertIn('expected=expected_value', message)
        self.assertIn('actual_value', message)
        self.assertIn('NOT_EVALUATED: ValueError: read failure', message)

    def setUp(self):
        self.lock = m.read_lock()

    def malformed_lock(self, change):
        lock = copy.deepcopy(self.lock); change(lock)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lock.json'; path.write_text(json.dumps(lock))
            with self.assertRaises((ValueError, KeyError, TypeError)):
                m.read_lock(path)

    def test_lock(self):
        self.assertEqual(len(self.lock['external']), 6)
        self.assertEqual(m.shared_driver().read_lock()['requested_components'], 47)

    def test_foreign_archive(self):
        self.malformed_lock(lambda x: x.update(url='https://example.invalid/source.tar.gz'))

    def test_bad_archive_digest(self):
        self.malformed_lock(lambda x: x.update(sha256='00'))

    def test_shared_driver_drift(self):
        self.malformed_lock(lambda x: x.update(shared_driver_sha256='0' * 64))

    def test_bootstrap_drift(self):
        self.malformed_lock(lambda x: x.update(bootstrap_lock_sha256='0' * 64))

    def test_toolchain_drift(self):
        self.malformed_lock(lambda x: x['toolchain'].update(xcode='27.0'))

    def test_missing_external(self):
        self.malformed_lock(lambda x: x['external'].pop())

    def test_duplicate_external(self):
        self.malformed_lock(lambda x: x['external'].__setitem__(0, x['external'][1]))

    def test_foreign_git(self):
        self.malformed_lock(lambda x: x['external'][0].update(url='file:///tmp/foreign'))

    def test_unpinned_git(self):
        self.malformed_lock(lambda x: x['external'][0].update(revision='main'))

    def test_external_revision_files(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory); revisions = source / 'ExternalRevisions'; revisions.mkdir()
            for row in self.lock['external']:
                (revisions / (row['name'] + '_repo_revision')).write_text(row['revision'] + '\n')
            self.assertEqual(len(m.verify_external_revisions(source, self.lock)), 6)
            (revisions / 'SPIRV-Cross_repo_revision').write_text('f' * 40)
            with self.assertRaisesRegex(ValueError, 'SPIRV-Cross'):
                m.verify_external_revisions(source, self.lock)

    def test_missing_revision_file(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                m.verify_external_revisions(Path(directory), self.lock)

    def test_git_identity(self):
        revision = self.lock['external'][0]['revision']
        m.verify_git_revision(revision, revision)
        with self.assertRaisesRegex(ValueError, 'Git HEAD mismatch'):
            m.verify_git_revision(revision, 'f' * 40)

    def test_cloud_only(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(m.platform, 'system', return_value='Darwin'), patch.object(m.platform, 'machine', return_value='arm64'):
            with self.assertRaisesRegex(ValueError, 'cloud task'):
                m.cloud_guard()

    def test_user_cloud_checkout_needs_no_private_repository(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'fixture/public'}, clear=True), patch.object(m.platform, 'system', return_value='Darwin'), patch.object(m.platform, 'machine', return_value='arm64'):
            m.cloud_guard()

    def test_x86_cloud_refused(self):
        with patch.object(m.platform, 'machine', return_value='x86_64'):
            with self.assertRaisesRegex(ValueError, 'native cloud'):
                m.cloud_guard()

    def test_xcode_source_owned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = m.verify_xcode_source(' SRCROOT = ' + str(root) + '\n PROJECT_DIR = ' + str(root / 'MoltenVK') + '\n', root)
            self.assertEqual(report['inspected'], 2)
            with self.assertRaisesRegex(ValueError, 'Foreign Xcode'):
                m.verify_xcode_source(' SRCROOT = /opt/foreign\n', root)
            with self.assertRaisesRegex(ValueError, 'No Xcode'):
                m.verify_xcode_source('no settings\n', root)

    def test_native_dylib_header(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic-header'
            path.write_bytes(struct.pack('<IIIIIIII', 0xfeedfacf, 0x100000c, 0, 6, 0, 0, 0, 0))
            self.assertEqual(m.verify_dylib(path)['cpu'], 0x100000c)
            for magic, cpu, kind in [(0xcafebabe, 0x100000c, 6), (0xfeedfacf, 0x1000007, 6), (0xfeedfacf, 0x100000c, 2)]:
                path.write_bytes(struct.pack('<IIIIIIII', magic, cpu, 0, kind, 0, 0, 0, 0))
                with self.assertRaisesRegex(ValueError, 'ARM64 MH_DYLIB'):
                    m.verify_dylib(path)
            path.write_bytes(b'x')
            with self.assertRaisesRegex(ValueError, 'Truncated'):
                m.verify_dylib(path)

    def test_xcode_no_sign_and_expected_paths(self):
        args = m.xcode_args(Path('/synthetic'), 'ExternalDependencies.xcodeproj', 'ExternalDependencies-macOS', Path('/prefix'), Path('/sdk'), 4)
        self.assertIn('CODE_SIGNING_ALLOWED=NO', args)
        self.assertIn('SYMROOT=/synthetic/External/build', args)
        self.assertNotIn('-allowProvisioningUpdates', args)


class DryBuild(unittest.TestCase):
    def fixture(self, directory, fault=None):
        lock = m.read_lock()
        calls = []
        dep = m.shared_driver()

        def download(row, destination, out):
            calls.append(('download', row['name']))
            destination.write_bytes(b'OWN_SYNTHETIC_FIXTURE_NOT_UPSTREAM')

        def unpack(archive, destination):
            destination.mkdir(parents=True)
            if archive.name.startswith('MoltenVK'):
                rev = destination / 'ExternalRevisions'; rev.mkdir()
                for row in lock['external']:
                    (rev / (row['name'] + '_repo_revision')).write_text(row['revision'])
                api = destination / 'MoltenVK/MoltenVK/API'; api.mkdir(parents=True)
                (api / 'vk_mvk_moltenvk.h').write_text('OWN_SYNTHETIC_HEADER')
            else:
                (destination / 'ninja').write_text('OWN_SYNTHETIC_TOOL_NOT_EXECUTABLE')
            return destination

        def command(argv, cwd, env, log, out, component, deadline, timeout=1800):
            calls.append(('command', log.name))
            log.write_text('OWN_SYNTHETIC_COMMAND_NOT_EXECUTED\n')
            if fault == log.stem:
                raise ValueError('injected command failure')
            if log.stem == 'spirv-tools-configure':
                path = Path(argv[argv.index('-B') + 1]); path.mkdir()
                actual = argv[argv.index('-S') + 1]
                (path / 'CMakeCache.txt').write_text('CMAKE_HOME_DIRECTORY:INTERNAL=' + actual + '\n')
            if log.stem.endswith('-settings'):
                log.write_text(' SRCROOT = ' + str(cwd) + '\n PROJECT_DIR = ' + str(cwd) + '\n')
            if log.stem == 'moltenvk-build':
                library = cwd / 'Package/Release/MoltenVK/dylib/macOS/libMoltenVK.dylib'
                library.parent.mkdir(parents=True)
                library.write_bytes(struct.pack('<IIIIIIII', 0xfeedfacf, 0x100000c, 0, 6, 0, 0, 0, 0))
                if fault == 'install_skipped':
                    log.write_text('install skipped\n')
            if log.stem.endswith('-git-archive'):
                destination = next(value.split('=', 1)[1] for value in argv if value.startswith('--output='))
                Path(destination).write_bytes(b'OWN_SYNTHETIC_GIT_ARCHIVE')

        def output(argv, env=None, raw_log=None):
            if argv[-1] == '--version':
                value = 'cmake version 4.3.2' if Path(argv[0]).name == 'cmake' else '1.13.2'
            elif 'FETCH_HEAD' in argv:
                name = Path(argv[argv.index('-C') + 1]).name
                value = next(row['revision'] for row in lock['external'] if row['name'] == name)
            elif 'ls-tree' in argv:
                value = '100644 blob ' + 'a' * 40 + '\tOWN_SYNTHETIC_FILE'
            else:
                value = '/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)'
            if raw_log is not None:
                raw_log.write_text(value)
            return value

        dep.download = download; dep.unpack = unpack; dep.command = command; dep.output = output
        dep.licenses = lambda *args: []
        dep.toolchain_preflight = lambda *args: (Path('/synthetic-sdk'), '/synthetic-clang', '/synthetic-clang++')
        args = SimpleNamespace(work=Path(directory) / 'work', jobs=4, minutes=90)
        return lock, dep, args, calls

    def run_fixture(self, directory, fault=None):
        lock, dep, args, calls = self.fixture(directory, fault)
        def molten_download(lock, destination, out):
            return dep.download(dict(name='MoltenVK'), destination, out)
        with patch.object(m, 'cloud_guard', autospec=True), patch.object(m.platform, 'python_version', return_value='3.13.7'), patch.object(m, 'shared_driver', autospec=True, return_value=dep), patch.object(m, 'download_moltenvk', autospec=True, side_effect=molten_download):
            if fault:
                with self.assertRaises(ValueError):
                    m.build(args, lock)
            else:
                m.build(args, lock)
        receipt = json.loads((args.work / 'reports/dependency-manifest.json').read_text())
        return receipt, calls

    def test_full_plan_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, calls = self.run_fixture(directory)
            self.assertTrue(receipt['source_built'])
            self.assertEqual(len(receipt['sources']), 9)
            self.assertEqual(sum(name.endswith('-git-fetch.log') for kind, name in calls if kind == 'command'), 6)
            self.assertEqual(receipt['gpu_execution'], 'NOT_ENABLED')
            self.assertEqual(receipt['comparison'], 'NOT_ENABLED')
            self.assertEqual(receipt['install_skipped'], 0)

    def test_external_failure_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, calls = self.run_fixture(directory, 'SPIRV-Cross-git-fetch')
            self.assertEqual(receipt['first_failure']['component'], 'SPIRV-Cross')
            self.assertEqual(receipt['first_failure']['phase'], 'EXTERNAL_SOURCE')
            self.assertFalse(receipt['source_built'])
            self.assertNotIn(('command', 'external-build.log'), calls)

    def test_xcode_failure_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, calls = self.run_fixture(directory, 'moltenvk-build')
            self.assertEqual(receipt['first_failure']['phase'], 'XCODE_BUILD')
            self.assertFalse(receipt['source_built'])
            self.assertNotIn(('command', 'install-name.log'), calls)

    def test_install_skipped_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, calls = self.run_fixture(directory, 'install_skipped')
            self.assertEqual(receipt['install_skipped'], 1)
            self.assertFalse(receipt['source_built'])
            self.assertEqual(receipt['first_failure']['error'], 'install skipped=1')

    def test_owner_mac_does_not_create_work_or_download(self):
        with tempfile.TemporaryDirectory() as directory:
            lock, dep, args, calls = self.fixture(directory)
            with patch.dict(os.environ, {}, clear=True), patch.object(m.platform, 'system', return_value='Darwin'), patch.object(m.platform, 'machine', return_value='arm64'), patch.object(m, 'shared_driver', return_value=dep):
                with self.assertRaisesRegex(ValueError, 'cloud task'):
                    m.build(args, lock)
            self.assertFalse(args.work.exists())
            self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
