"""Inert controls for user cloud builds and unchanged local execution refusal."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import sys
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]


def load(name, path):
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FULL = load('public_cloud_full', REPO / 'repro109wine/build_full.py')
DEP = load('public_cloud_deps', REPO / 'repro109deps/build_deps.py')
MV = load('public_cloud_moltenvk', REPO / 'repro109moltenvk/build_moltenvk.py')


class PublicCloud(unittest.TestCase):
    def setUp(self):
        for target, attribute, value in [
            (FULL.platform, 'system', 'Darwin'),
            (FULL.platform, 'machine', 'arm64'),
            (FULL.platform, 'python_version', '3.13.7'),
            (sys, 'version', '3.13.7 (owned inert fixture)'),
            (sys, 'version_info', (3, 13, 7)),
        ]:
            patcher = mock.patch.object(target, attribute, value if target is sys else mock.Mock(return_value=value))
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(FULL, 'load_driver', side_effect=AssertionError('Private API must not be loaded'))
        patcher.start(); self.addCleanup(patcher.stop)

    def guards(self, profile='github'):
        tool = dict(profile=profile, python='3.13.7', python_minimum=[3, 9])
        return [lambda: FULL.cloud_guard(profile), lambda: DEP.cloud_guard(tool), MV.cloud_guard]

    def test_user_github_cloud_without_private_token_or_repository(self):
        with mock.patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'fixture/user-build'}, clear=True):
            for guard in self.guards(): guard()

    def test_user_xcode_cloud_without_private_credentials(self):
        env = dict(CI_WORKSPACE_PATH='/owned/cloud', CI_PRIMARY_REPOSITORY_PATH='/owned/cloud/repo', CI_BUILD_NUMBER='fixture')
        with mock.patch.dict(os.environ, env, clear=True):
            for guard in self.guards('xcode-cloud'): guard()

    def test_local_environment_refused_by_every_core(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            for guard in self.guards():
                with self.assertRaisesRegex(ValueError, 'cloud'): guard()

    def test_partial_cloud_environment_refused(self):
        with mock.patch.dict(os.environ, {'CI_WORKSPACE_PATH': '/owned/cloud'}, clear=True):
            for guard in self.guards():
                with self.assertRaisesRegex(ValueError, 'cloud'): guard()

    def test_x86_cloud_refused_by_every_core(self):
        with mock.patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}, clear=True), mock.patch.object(FULL.platform, 'machine', return_value='x86_64'):
            for guard in self.guards():
                with self.assertRaises(ValueError): guard()

    def test_github_python_drift_refused(self):
        with mock.patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}, clear=True), mock.patch.object(FULL.platform, 'python_version', return_value='3.13.8'), mock.patch.object(sys, 'version', '3.13.8'):
            for guard in self.guards()[:2]:
                with self.assertRaisesRegex(ValueError, 'Python'): guard()

    def test_xcode_minimum_python_preserved(self):
        env = dict(CI_WORKSPACE_PATH='/owned/cloud', CI_PRIMARY_REPOSITORY_PATH='/owned/cloud/repo', CI_BUILD_NUMBER='fixture')
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(sys, 'version_info', (3, 8, 10)):
            for guard in self.guards('xcode-cloud')[:2]:
                with self.assertRaisesRegex(ValueError, 'Python'): guard()

    def test_xcode_build_identity_preserved(self):
        env = dict(CI_WORKSPACE_PATH='/owned/cloud', CI_PRIMARY_REPOSITORY_PATH='/owned/cloud/repo')
        with mock.patch.dict(os.environ, env, clear=True):
            for guard in self.guards('xcode-cloud')[:2]:
                with self.assertRaises(ValueError): guard()

    def test_local_build_refused_before_work_or_tools(self):
        with tempfile.TemporaryDirectory(dir=os.environ['REPRO109_TEST_TMP']) as directory:
            root = Path(directory) / 'fresh'
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, 'cloud'): FULL.build(root, {})
                with self.assertRaisesRegex(ValueError, 'cloud'):
                    DEP.build(SimpleNamespace(work=root), dict(toolchain={'python': '3.13.7'}))
            self.assertFalse(root.exists())

    def test_private_provider_absent_from_core_imports_and_source_pins(self):
        for path in ['repro109wine/build_full.py', 'repro109deps/build_deps.py', 'repro109moltenvk/build_moltenvk.py']:
            tree = ast.parse((REPO / path).read_text())
            imports = [ast.unparse(node) for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
            self.assertFalse(any('private_release' in item for item in imports), path)
        lock = json.loads((REPO / 'repro109wine/full.lock.json').read_bytes())
        self.assertNotIn('repro109/private_release.py', lock['files'])

    def test_clean_core_inputs_without_private_provider_and_reject_source_drift(self):
        lock = json.loads((REPO / 'repro109wine/full.lock.json').read_bytes())
        with tempfile.TemporaryDirectory(dir=os.environ['REPRO109_TEST_TMP']) as directory:
            root = Path(directory)
            for name in list(lock['files']) + ['repro109wine/full.lock.json']:
                destination = root / name; destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(REPO / name, destination)
            self.assertFalse((root / 'repro109/private_release.py').exists())
            env = dict(PATH='/usr/bin:/bin', TMPDIR=directory, PYTHONDONTWRITEBYTECODE='1')
            for name in ['repro109wine/build_full.py', 'repro109wine/build_wine.py']:
                result = subprocess.run(['/usr/bin/python3', '-B', '-I', str(root / name), '--check-inputs'],
                    cwd=root, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', 'replace'))
                self.assertIsInstance(json.loads(result.stdout), dict)
            with (root / 'repro109deps/build_deps.py').open('ab') as stream: stream.write(b'\n# owned source drift\n')
            result = subprocess.run(['/usr/bin/python3', '-B', '-I', str(root / 'repro109wine/build_full.py'), '--check-inputs'],
                cwd=root, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'Pinned driver/lock drift: repro109deps/build_deps.py', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
