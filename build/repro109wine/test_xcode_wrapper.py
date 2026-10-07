"""Actual full-Wine wrapper/dispatcher with an owned inert driver, no source execution."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
STUB = '''import json, os, pathlib, sys
args = sys.argv[1:]
assert (pathlib.Path(os.environ['RESULTS_DIR'])/'private-check.fixture').read_text() == 'OWNED_PRIVATE_CHECK'
work = pathlib.Path(args[args.index('--work')+1]); work.mkdir()
for part in ['reports', 'deps/reports', 'moltenvk/reports', 'wine/reports', 'wine/install', 'deps/prefix']:
    p = work/part; p.mkdir(parents=True, exist_ok=True)
    (p/'fixture.txt').write_bytes(b'owned inert wrapper fixture\\n')
(work/'reports/argv.json').write_text(json.dumps(dict(argv=args, python=sys.executable)))
(work/'reports/RESULT.json').write_text(json.dumps(dict(state='OFFLINE_FIXTURE_NOT_SOURCE_BUILT')))
sys.exit(int(os.environ.get('REPRO109_FIXTURE_RC', '0')))
'''


class Wrapper(unittest.TestCase):
    def exercise(self, rc=0, existing=False, runner_temp=False, private_rejected=False):
        with tempfile.TemporaryDirectory(dir=os.environ['REPRO109_TEST_TMP']) as directory:
            root = Path(directory); repo = root / 'repo'; workspace = root / 'workspace'; results = root / 'results'
            for p in [repo / 'jobs', repo / 'repro109wine', repo / 'repro109', workspace, results]: p.mkdir(parents=True)
            shutil.copyfile(REPO / 'jobs/repro109-wine-full.sh', repo / 'jobs/repro109-wine-full.sh')
            (repo / 'jobs/JOB').write_text('repro109-wine-full xcode-cloud\n')
            (repo / 'repro109wine/build_full.py').write_text(STUB)
            (repo / 'repro109/private_release.py').write_text(
                'import os\nfrom pathlib import Path\n'
                'def verify_private():\n'
                '    if os.environ.get("REPRO109_FIXTURE_PRIVATE_REJECT"): raise ValueError("owned private rejection")\n'
                '    (Path(os.environ["RESULTS_DIR"])/"private-check.fixture").write_text("OWNED_PRIVATE_CHECK")\n')
            lines = (REPO / 'ci_scripts/ci_post_clone.sh').read_text().splitlines()
            self.assertEqual(lines[31], 'bash "jobs/$job.sh" "$out" $args > "$out/job.txt" 2>&1 &')
            selected = lines[8:15] + [lines[16], lines[18], lines[31], lines[32], lines[43], lines[44], 'exit "$rc"']
            env = dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin', CI_WORKSPACE_PATH=str(workspace),
                CI_PRIMARY_REPOSITORY_PATH=str(repo), CI_BUILD_NUMBER='owned-wrapper', RESULTS_DIR=str(results),
                TMPDIR=str(root), REPRO109_PYTHON='/must-not-run', REPRO109_FIXTURE_RC=str(rc))
            workbase = workspace
            if runner_temp:
                workbase = root / 'runner-temp'; workbase.mkdir(); env['RUNNER_TEMP'] = str(workbase)
            work = workbase / 'repro109-wine2-work'
            if private_rejected: env['REPRO109_FIXTURE_PRIVATE_REJECT'] = '1'
            if existing:
                work.mkdir(); (work / 'untouched').write_bytes(b'previous fixture evidence')
            child = subprocess.run(['bash', '-c', '\n'.join(selected)], cwd=repo, env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                start_new_session=True)
            if private_rejected:
                self.assertNotEqual(child.returncode, 0)
                self.assertFalse(work.exists())
                self.assertFalse((results / 'build-rc.txt').exists())
                self.assertIn('owned private rejection', (results / 'job.txt').read_text())
                return
            if existing:
                self.assertNotEqual(child.returncode, 0); self.assertFalse((work / 'reports').exists())
                self.assertEqual((work / 'untouched').read_bytes(), b'previous fixture evidence'); return
            self.assertEqual(child.returncode, rc)
            self.assertEqual((results / 'build-rc.txt').read_text(), str(rc) + '\n')
            invocation = json.loads((results / 'reports/argv.json').read_bytes())
            self.assertEqual(invocation['argv'], ['--profile', 'xcode-cloud', '--build', '--work', str(work), '--jobs', '4'])
            actual_python = subprocess.check_output(['/usr/bin/python3', '-B', '-I', '-c', 'import sys; print(sys.executable)'],
                env=env, text=True, stdin=subprocess.DEVNULL, timeout=20).strip()
            self.assertEqual(invocation['python'], actual_python)
            for part in ['reports', 'deps/reports', 'moltenvk/reports', 'wine/reports']:
                self.assertEqual((results / part / 'fixture.txt').read_bytes(), b'owned inert wrapper fixture\n')
            for name in ['wine-dist', 'dependency-prefix']:
                archive = results / (name + '.tar.gz')
                self.assertEqual((results / (name + '.sha256')).read_text().split()[0],
                                 hashlib.sha256(archive.read_bytes()).hexdigest())
                with tarfile.open(archive) as stream:
                    member = next(p for p in stream.getmembers() if p.name.endswith('/fixture.txt'))
                    self.assertEqual(stream.extractfile(member).read(), b'owned inert wrapper fixture\n')
            self.assertIn('existing Xcode Cloud dispatcher owns publication', (results / 'job.txt').read_text())

    def test_success_exact_profile_selected_python_and_outputs(self): self.exercise()
    def test_failure_rc_and_all_reports_preserved(self): self.exercise(rc=7)
    def test_existing_work_refused_without_overwrite(self): self.exercise(existing=True)
    def test_runner_temp_precedence(self): self.exercise(runner_temp=True)
    def test_private_rejection_precedes_driver_or_work(self): self.exercise(private_rejected=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
