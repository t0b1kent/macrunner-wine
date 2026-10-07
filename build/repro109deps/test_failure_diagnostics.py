#!/usr/bin/env python3
"""Offline failure controls: mocked tools and mocked receipt writes only."""
import ast
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import build_deps as deps


class FailureDiagnostics(unittest.TestCase):
    def run_preflight(self, sdk='26.5', rc=0):
        tool = deps.read_lock()['toolchain']
        values = ['Xcode 26.6\nBuild version 17F113\n', sdk+'\n',
                  '/Applications/Xcode_26.6.app/Contents/Developer/SDKs/MacOSX26.5.sdk\n',
                  '/tool/clang\n', '/tool/clang++\n', 'Apple clang (clang-2100.1.1.101)\n']
        results = [subprocess.CompletedProcess([], rc if i == 0 else 0, x) for i, x in enumerate(values)]
        with patch.object(deps.subprocess, 'run', side_effect=results) as run, \
                patch.object(Path, 'write_text') as write:
            error = None
            try:
                result = deps.toolchain_preflight(tool, Path('/out'))
            except AssertionError as exc:
                error, result = str(exc), None
        return result, error, json.loads(write.call_args[0][0]), run

    def test_actual_cloud_sdk_265_matches_pin(self):
        result, error, receipt, run = self.run_preflight()
        self.assertIsNone(error)
        self.assertEqual(receipt['status'], 'PRESENT')
        self.assertEqual(receipt['actual']['sdk'], '26.5')
        self.assertEqual(receipt['expected']['sdk'], '26.5')
        self.assertEqual(len(receipt['commands']), 6)
        self.assertEqual(result[1:], ('/tool/clang', '/tool/clang++'))
        self.assertEqual(run.call_count, 6)

    def test_sdk_drift_preserves_both_values_and_raw_stdout(self):
        result, error, receipt, _ = self.run_preflight('26.6')
        self.assertIsNone(result)
        self.assertIn('expected=26.5', error)
        self.assertIn('26.6', error)
        self.assertIn('actual=', error)
        self.assertEqual(receipt['status'], 'FAILED')
        self.assertEqual(receipt['commands'][1]['stdout'], '26.6\n')

    def test_tool_failure_preserves_rc_and_command(self):
        _, error, receipt, run = self.run_preflight(rc=9)
        self.assertIn('expected=command rc=0', error)
        self.assertIn('9', error)
        self.assertEqual(receipt['commands'][0]['rc'], 9)
        self.assertEqual(receipt['status'], 'FAILED')
        self.assertEqual(run.call_count, 1)

    def test_timeout_is_recorded(self):
        with patch.object(deps.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['xcodebuild'], 30)), \
                patch.object(Path, 'write_text') as write:
            with self.assertRaises(subprocess.TimeoutExpired):
                deps.toolchain_preflight(deps.read_lock()['toolchain'], Path('/out'))
        self.assertEqual(json.loads(write.call_args[0][0])['status'], 'FAILED')

    def test_rejected_manifest_path_has_expected_and_actual(self):
        with self.assertRaises(AssertionError) as caught:
            deps.safe_relative('../outside')
        self.assertIn('expected=', str(caught.exception))
        self.assertIn('actual=', str(caught.exception))

    def test_all_owned_driver_checks_survive_python_optimization(self):
        root = Path(__file__).resolve().parents[1]
        for directory in ['repro109deps', 'repro109wine']:
            for path in (root / directory).rglob('*.py'):
                if path.name.startswith('test_'):
                    continue
                tree = ast.parse(path.read_text())
                self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)), str(path))
                self.assertNotIn('if sys.flags.optimize:', path.read_text())


if __name__ == '__main__':
    unittest.main()
