"""Offline controls for the upstream test-suite policy of the dependency builds (a fake runner; nothing is built)."""
import gzip
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
import deps_test_policy as policy


class FakeDep:
    """command(): scripted results; a failing step raises AssertionError like the real runner."""
    def __init__(self, script, tree):
        self.script, self.tree, self.calls = list(script), tree, []

    def command(self, argv, cwd, env, log, out, component, deadline, timeout=1800):
        self.calls.append((list(argv), component))
        step = self.script.pop(0) if self.script else 'pass'
        outcome, results = step if isinstance(step, tuple) else (step, None)
        if results is not None:
            for name, value in results.items():
                trs = Path(cwd) / (name + '.trs')
                trs.parent.mkdir(parents=True, exist_ok=True)
                trs.write_text(':test-result: %s\n:global-test-result: %s\n' % (value, value))
            (Path(cwd) / 'tests').mkdir(exist_ok=True)
            (Path(cwd) / 'tests/test-suite.log').write_text('suite log for %s\n' % list(results))
        if outcome == 'fail':
            raise AssertionError("reason is None and child.returncode == 0; actual={'reason': 'None', 'child.returncode': '2'}")
        if outcome == 'timeout':
            raise AssertionError("actual={'reason': 'TIMEOUT'}")


class Policy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cwd, self.out = self.root / 'src', self.root / 'reports'
        self.cwd.mkdir()
        self.out.mkdir()
        self.allow = self.root / 'allow.json'
        self.allow.write_text(json.dumps({'schema': 1, 'allow': []}))

    def run_step(self, script, allow=None, argv=('make', 'check', '-j2', 'V=1')):
        if allow is not None:
            self.allow.write_text(json.dumps({'schema': 1, 'allow': allow}))
        dep = FakeDep(script, self.cwd)
        policy.install(dep, self.allow, listeners=lambda out, component: component + '-listeners-after-failure.txt')
        try:
            dep.command(list(argv), self.cwd, {}, self.out / 'c-3.log', self.out, 'c', 0)
            error = None
        except AssertionError as exc:
            error = exc
        data = json.loads((self.out / policy.REPORT).read_bytes()) if (self.out / policy.REPORT).is_file() else None
        return dep, error, data

    def test_a_passing_suite_keeps_its_log_and_counts(self):
        dep, error, data = self.run_step([('pass', {'tests/a': 'PASS', 'tests/b': 'SKIP'})])
        entry = data['components'][0]
        self.assertIsNone(error)
        self.assertEqual((entry['outcome'], entry['counts']), ('PASSED', {'PASS': 1, 'SKIP': 1}))
        packed = self.out / entry['first_logs'][0]['report_file']
        self.assertIn(b'suite log', gzip.decompress(packed.read_bytes()))
        self.assertEqual(len(dep.calls), 1)

    def test_a_flaky_failure_is_rechecked_once_serially_and_recorded(self):
        dep, error, data = self.run_step([('fail', {'tests/rawpk': 'FAIL', 'tests/b': 'PASS'}), ('pass', {'tests/rawpk': 'PASS', 'tests/b': 'PASS'})])
        entry = data['components'][0]
        self.assertIsNone(error)
        self.assertEqual((entry['outcome'], entry['first_failed']), ('PASSED_ON_RECHECK', ['tests/rawpk']))
        self.assertEqual(dep.calls[1][0], ['make', 'recheck', '-j1', 'V=1'])
        self.assertEqual(dep.calls[1][1], 'c-recheck')
        self.assertEqual(len(entry['first_logs']), 1)
        self.assertEqual(len(entry['recheck_logs']), 1)
        self.assertEqual(entry['listeners'], 'c-listeners-after-failure.txt')

    def test_a_test_that_fails_twice_fails_the_component(self):
        dep, error, data = self.run_step([('fail', {'tests/x': 'FAIL'}), ('fail', {'tests/x': 'FAIL'})])
        self.assertIsInstance(error, AssertionError)
        self.assertEqual(data['components'][0]['outcome'], 'FAILED_AFTER_RECHECK')
        self.assertEqual(len(dep.calls), 2)

    def test_only_a_named_test_with_a_reason_is_allowed_to_fail(self):
        entry = dict(component='c', test='tests/x', reason='needs a network the image does not have', evidence='run 1')
        dep, error, data = self.run_step([('fail', {'tests/x': 'FAIL'}), ('fail', {'tests/x': 'FAIL'})], allow=[entry])
        self.assertIsNone(error)
        self.assertEqual(data['components'][0]['outcome'], 'ALLOWLISTED')
        self.assertEqual(data['components'][0]['allowlisted'][0]['reason'], entry['reason'])
        dep, error, data = self.run_step([('fail', {'tests/x': 'FAIL', 'tests/y': 'FAIL'}), ('fail', {'tests/x': 'FAIL', 'tests/y': 'FAIL'})],
                                         allow=[entry])
        self.assertIsInstance(error, AssertionError)  # y is not named
        other = dict(entry, component='other')
        dep, error, data = self.run_step([('fail', {'tests/x': 'FAIL'}), ('fail', {'tests/x': 'FAIL'})], allow=[other])
        self.assertIsInstance(error, AssertionError)  # the pair (component, test) counts

    def test_failures_without_a_failed_test_or_with_a_time_limit_are_never_rechecked(self):
        dep, error, data = self.run_step(['fail'])
        self.assertIsInstance(error, AssertionError)
        self.assertEqual((data['components'][0]['outcome'], len(dep.calls)), ('FAILED_NO_TEST_TO_RECHECK', 1))
        self.cwd.joinpath('tests').mkdir(exist_ok=True)
        dep, error, data = self.run_step([('timeout', {'tests/x': 'FAIL'})])
        self.assertIsInstance(error, AssertionError)
        self.assertEqual(len(dep.calls), 1)

    def test_other_commands_pass_through_and_leave_no_record(self):
        dep, error, data = self.run_step(['pass'], argv=('make', '-j2'))
        self.assertIsNone(error)
        self.assertIsNone(data)
        dep, error, data = self.run_step(['pass'], argv=('make', 'install'))
        self.assertIsNone(data)

    def test_allowlist_entries_need_a_reason_and_evidence_and_are_unique(self):
        good = dict(component='c', test='t', reason='r', evidence='e')
        for bad in ([dict(good, reason='')], [dict(good, evidence=' ')], [good, good], [{'test': 't'}]):
            self.allow.write_text(json.dumps({'schema': 1, 'allow': bad}))
            with self.assertRaises(ValueError):
                policy.read_allowlist(self.allow)
        self.allow.write_text(json.dumps({'schema': 2, 'allow': []}))
        with self.assertRaises(ValueError):
            policy.read_allowlist(self.allow)

    def test_the_listener_evidence_is_bounded_and_survives_missing_tools(self):
        name = policy.default_listeners(self.out, 'c')
        text = (self.out / name).read_text()
        self.assertLessEqual(len(text), 96 * 1024)
        self.assertIn('lsof', text)
        self.assertIn('ps', text)

    def test_the_shipped_allowlist_is_empty_and_the_summary_names_each_outcome(self):
        self.assertEqual(policy.read_allowlist(HERE / 'upstream-test-allowlist.lock.json'), {})
        self.run_step([('fail', {'tests/rawpk': 'FAIL'}), ('pass', {'tests/rawpk': 'PASS'})])
        text = policy.summary(self.out)
        self.assertEqual(text['components'][0]['outcome'], 'PASSED_ON_RECHECK')
        self.assertEqual(text['components'][0]['first_failed'], ['tests/rawpk'])

    def test_build_full_installs_the_policy_before_the_dependency_phase_and_pins_its_files(self):
        source = (HERE / 'build_full.py').read_text()
        self.assertLess(source.index("policy.install(dep,"), source.index("phase = 'DEPS10'"))
        self.assertIn("policy.summary(root / 'deps/reports')", source)
        lock = json.loads((HERE / 'full.lock.json').read_bytes())['files']
        for name in ('build_full.py', 'deps_test_policy.py', 'upstream-test-allowlist.lock.json'):
            self.assertIn('repro110wine/' + name, lock)


if __name__ == '__main__':
    unittest.main(verbosity=2)
