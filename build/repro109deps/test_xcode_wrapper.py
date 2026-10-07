"""Exercise the real job wrapper with owned fixture output, no fetch/build/publish."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
JOB_LINE = 'repro109-deps xcode-cloud\n'
STUB = '''import json, os, pathlib, sys
args = sys.argv[1:]
assert (pathlib.Path(os.environ['RESULTS_DIR'])/'private-check.fixture').read_text() == 'OWNED_PRIVATE_CHECK'
work = pathlib.Path(args[args.index('--work')+1])
work.mkdir()
out = work/'reports'; out.mkdir()
(out/'fixture-argv.json').write_text(json.dumps(dict(argv=args, python=sys.executable)))
(out/'RESULT.json').write_text(json.dumps(dict(state='OFFLINE_FIXTURE_NOT_SOURCE_BUILT')))
(out/'failure.raw.log').write_bytes(b'owned fixture raw evidence\\n')
prefix = work/'prefix'; prefix.mkdir()
(prefix/'fixture.txt').write_bytes(b'owned fixture bytes\\n')
sys.exit(int(os.environ.get('REPRO109_FIXTURE_RC', '0')))
'''


class XcodeWrapper(unittest.TestCase):
    def exercise(self, rc=0, existing=False, runner_temp=False, private_rejected=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, workspace, results = root/'repo', root/'workspace', root/'results'
            for path in [repo/'jobs', repo/'repro109deps', repo/'repro109', workspace, results]:
                path.mkdir(parents=True)
            shutil.copyfile(REPO/'jobs/repro109-deps.sh', repo/'jobs/repro109-deps.sh')
            (repo/'jobs/JOB').write_text(JOB_LINE)
            (repo/'repro109deps/build_deps.py').write_text(STUB)
            (repo/'repro109/private_release.py').write_text(
                'import os\nfrom pathlib import Path\n'
                'def verify_private():\n'
                '    if os.environ.get("REPRO109_FIXTURE_PRIVATE_REJECT"): raise ValueError("owned private rejection")\n'
                '    (Path(os.environ["RESULTS_DIR"])/"private-check.fixture").write_text("OWNED_PRIVATE_CHECK")\n')
            # Use the current dispatcher's byte-exact job selection and invocation.
            lines = (REPO/'ci_scripts/ci_post_clone.sh').read_text().splitlines()
            selected = lines[8:15] + [lines[16], lines[18], lines[31], lines[32],
                                      lines[43], lines[44], 'exit "$rc"']
            self.assertEqual(lines[31], 'bash "jobs/$job.sh" "$out" $args > "$out/job.txt" 2>&1 &')
            self.assertEqual(lines[43], 'wait "$jobpid"')
            env = dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin',
                       CI_WORKSPACE_PATH=str(workspace), CI_PRIMARY_REPOSITORY_PATH=str(repo),
                       CI_BUILD_NUMBER='offline-fixture', RESULTS_DIR=str(results),
                       TMPDIR=str(root), REPRO109_PYTHON='/must-not-run',
                       REPRO109_FIXTURE_RC=str(rc))
            workbase = workspace
            if runner_temp:
                workbase = root/'runner-temp'; workbase.mkdir()
                env['RUNNER_TEMP'] = str(workbase)
            work = workbase/'repro109-deps10-work'
            if private_rejected: env['REPRO109_FIXTURE_PRIVATE_REJECT'] = '1'
            if existing:
                work.mkdir()
                (work/'untouched').write_bytes(b'previous fixture evidence')
            child = subprocess.run(['bash', '-c', '\n'.join(selected)], cwd=repo, env=env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=20, start_new_session=True)
            if private_rejected:
                self.assertNotEqual(child.returncode, 0)
                self.assertFalse(work.exists())
                self.assertFalse((results/'deps-rc.txt').exists())
                self.assertIn('owned private rejection', (results/'job.txt').read_text())
                return
            if existing:
                self.assertNotEqual(child.returncode, 0)
                self.assertFalse((work/'reports').exists())
                self.assertEqual((work/'untouched').read_bytes(), b'previous fixture evidence')
                return
            self.assertEqual(child.returncode, rc)
            self.assertEqual((results/'deps-rc.txt').read_text(), str(rc)+'\n')
            self.assertEqual((results/'failure.raw.log').read_bytes(), b'owned fixture raw evidence\n')
            invocation = json.loads((results/'fixture-argv.json').read_text())
            self.assertEqual(invocation['argv'], ['--profile', 'xcode-cloud', '--build',
                             '--work', str(work), '--jobs', '12', '--minutes', '95'])
            selected_python = subprocess.check_output(
                ['/usr/bin/python3', '-B', '-I', '-c', 'import sys; print(sys.executable)'],
                env=env, text=True, stdin=subprocess.DEVNULL, timeout=20).strip()
            self.assertEqual(invocation['python'], selected_python)
            archive = results/'dependency-prefix.tar.gz'
            self.assertEqual((results/'dependency-prefix.sha256').read_text().split()[0],
                             hashlib.sha256(archive.read_bytes()).hexdigest())
            with tarfile.open(archive) as stream:
                member = next(x for x in stream.getmembers() if x.name.endswith('/fixture.txt'))
                self.assertEqual(stream.extractfile(member).read(), b'owned fixture bytes\n')
            self.assertIn('existing Xcode Cloud dispatcher owns publication',
                          (results/'job.txt').read_text())

    def test_success_exact_profile_args_interpreter_and_archived_output(self):
        self.exercise()

    def test_failure_preserves_rc_raw_reports_and_prefix(self):
        self.exercise(rc=7)

    def test_existing_work_refused_without_overwrite(self):
        self.exercise(existing=True)

    def test_runner_temp_precedence_matches_actual_wrapper(self):
        self.exercise(runner_temp=True)

    def test_private_rejection_precedes_driver_or_work(self):
        self.exercise(private_rejected=True)


if __name__ == '__main__':
    unittest.main()
