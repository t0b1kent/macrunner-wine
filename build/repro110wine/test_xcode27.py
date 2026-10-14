"""Offline Wine SDK27 and workflow controls; no downloads or compiler calls."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import build_full as full
import matrix

PROFILE = 'github-xcode27-arm64'
WORKFLOWS = ('repro109-wine-c9-xcode27-arm64.yml',
             'repro109-wine-c9-matrix-xcode27-arm64.yml')


class Xcode27Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='wine27-', dir=os.environ['REPRO109_TEST_TMP'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_profile_changes_only_toolchain(self):
        source = dict(revision='a' * 40, source=dict(sha256='b' * 64),
                      toolchain=dict(xcode='old', llvm_mingw_sha256='c' * 64))
        before = copy.deepcopy(source)
        selected = full.apply_profile(source, PROFILE)
        self.assertEqual(source, before)
        self.assertEqual(selected['revision'], source['revision'])
        self.assertEqual(selected['source'], source['source'])
        self.assertEqual(selected['toolchain']['llvm_mingw_sha256'], 'c' * 64)
        self.assertEqual(selected['toolchain']['xcode'], '27.0')
        self.assertEqual(selected['toolchain']['xcode_build'], '27A266a')
        self.assertEqual(selected['toolchain']['sdk'], '27.0')

    def test_legacy_profile_is_preserved(self):
        selected = full.apply_profile(dict(toolchain={}), 'github-macos15-arm64')
        self.assertEqual(selected['toolchain']['sdk'], '26.2')

    def test_matrix_uses_the_same_new_profile(self):
        self.assertEqual(matrix.PROFILE, PROFILE)
        self.assertEqual(matrix.STAGES, ('sdk', 'deps10', 'moltenvk2', 'compiler'))

    def test_lock_counts_standalone_ec_instead_of_package(self):
        profile = json.loads((HERE / 'github-xcode27.lock.json').read_bytes())
        self.assertEqual(profile['expected_standalone_wine'],
                         dict(ec=642, pe64=757, hexpthk=642, a64xrm=642))
        self.assertEqual(profile['runner_label'], 'xcode-27')
        self.assertEqual(profile['developer_dir'], '/Applications/Xcode_27.app/Contents/Developer')

    def test_new_profile_is_accepted_only_in_cloud(self):
        with mock.patch.object(full.platform, 'system', return_value='Darwin'), \
             mock.patch.object(full.platform, 'machine', return_value='arm64'), \
             mock.patch.object(full.platform, 'python_version', return_value='3.13.7'), \
             mock.patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}, clear=True):
            full.cloud_guard(PROFILE)

    def test_local_invocation_refuses_before_driver_load(self):
        work = self.root / 'local'
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(full, 'load_driver') as load:
            with self.assertRaisesRegex(ValueError, 'only in the cloud'):
                full.build(work, dict(minutes=1), profile=PROFILE)
        load.assert_not_called()
        self.assertFalse(work.exists())

    def test_full_cli_defaults_to_new_profile(self):
        with mock.patch.object(sys, 'argv', ['build_full.py', '--build', '--work', str(self.root / 'work')]), \
             mock.patch.object(full, 'check_inputs', return_value={}), mock.patch.object(full, 'build') as build:
            full.main()
        self.assertEqual(build.call_args.args[3], PROFILE)

    def test_missing_sdk_exports_stop_before_all_vendor_producers(self):
        sdk = self.root / 'sdk'
        (sdk / 'usr/lib/system').mkdir(parents=True)
        dep = SimpleNamespace(read_lock=lambda: dict(toolchain={}),
            toolchain_preflight=mock.Mock(return_value=(sdk, 'clang', 'clang++')),
            build=mock.Mock(), command=mock.Mock())
        wine, mv = SimpleNamespace(build=mock.Mock()), SimpleNamespace(build=mock.Mock())
        work = self.root / 'work'
        with mock.patch.object(full, 'cloud_guard'), \
             mock.patch.object(full, 'load_driver', side_effect=[dep, wine, mv]):
            with self.assertRaisesRegex(ValueError, 'lacks Wine x18 ABI exports'):
                full.build(work, dict(minutes=1), profile=PROFILE)
        for producer in [dep, wine, mv]:
            producer.build.assert_not_called()
        dep.command.assert_not_called()
        report = json.loads((work / 'reports/RESULT.json').read_bytes())
        self.assertEqual(report['first_failure']['phase'], 'SDK_PREFLIGHT')
        counts = json.loads((work / 'reports/sdk-x18-exports.json').read_bytes())['counts']
        self.assertEqual(list(counts.values()), [0, 0])

    def block(self, name):
        text = (ROOT / '.github/workflows' / name).read_text()
        step = text.split('      - name: Verify pinned Xcode 27.0 and SDK 27.0\n', 1)[1]
        block = step.split('        run: |\n', 1)[1].split('      - name:', 1)[0]
        return text, '\n'.join(line[10:] for line in block.splitlines())

    def invoke(self, block, xcode=None, sdk=None):
        tools = self.root / ('tools-' + str(len(list(self.root.iterdir()))))
        tools.mkdir()
        for name, value in [('xcodebuild', xcode), ('xcrun', sdk)]:
            if value is None:
                continue
            target = tools / name
            target.write_text('#!/bin/bash\nprintf "%s\\n" "' + value + '"\n')
            target.chmod(0o755)
        return subprocess.run(['/bin/bash', '-c', block], capture_output=True, text=True, timeout=10,
            env={'PATH': str(tools), 'DEVELOPER_DIR': '/Applications/Xcode_27.app/Contents/Developer'})

    def test_both_workflows_pin_runner_developer_directory_and_keep_dispatch(self):
        for name in WORKFLOWS:
            text, _ = self.block(name)
            self.assertIn('runs-on: xcode-27', text)
            self.assertIn('DEVELOPER_DIR: /Applications/Xcode_27.app/Contents/Developer', text)
            self.assertIn('  workflow_dispatch:', text)
            self.assertNotIn('/Applications/Xcode*.app', text)

    def test_both_actual_bash_blocks_accept_exact_toolchain(self):
        for name in WORKFLOWS:
            _, block = self.block(name)
            self.assertEqual(self.invoke(block, 'Xcode 27.0\nBuild version 27A266a', '27.0').returncode, 0)

    def test_both_blocks_reject_wrong_xcode_build(self):
        for name in WORKFLOWS:
            _, block = self.block(name)
            result = self.invoke(block, 'Xcode 27.0\nBuild version WRONG', '27.0')
            self.assertEqual(result.returncode, 1)
            self.assertIn('Pinned Xcode', result.stdout)

    def test_both_blocks_reject_wrong_sdk(self):
        for name in WORKFLOWS:
            _, block = self.block(name)
            result = self.invoke(block, 'Xcode 27.0\nBuild version 27A266a', '26.2')
            self.assertEqual(result.returncode, 1)
            self.assertIn('Pinned SDK', result.stdout)

    def test_missing_xcodebuild_is_not_success(self):
        for name in WORKFLOWS:
            _, block = self.block(name)
            self.assertEqual(self.invoke(block).returncode, 127)

    def test_missing_xcrun_is_not_success(self):
        for name in WORKFLOWS:
            _, block = self.block(name)
            self.assertEqual(self.invoke(block, 'Xcode 27.0\nBuild version 27A266a').returncode, 1)

    def test_preflight_export_probe_is_not_bypassed(self):
        text, _ = self.block(WORKFLOWS[0])
        self.assertIn('--profile github-xcode27-arm64', text)
        self.assertIn('fail-fast: false', self.block(WORKFLOWS[1])[0])
        self.assertIn('if: always()', self.block(WORKFLOWS[1])[0])


if __name__ == '__main__':
    unittest.main()
