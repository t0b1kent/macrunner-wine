"""The pinned Wine revision tracks recipes in a top-level build/; the Wine build directory must still be creatable."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
import build_wine as wine


def git(*args, cwd):
    done = subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=' + 'tester' + chr(64) + 'localhost', *args], cwd=cwd,
                          capture_output=True, text=True)
    if done.returncode:
        raise RuntimeError(done.stderr)
    return done.stdout.strip()


class SourceCheckout(unittest.TestCase):
    def test_build_directory_of_the_commit_stays_out_of_the_tree_and_the_wine_build_directory_can_be_made(self):
        base = os.environ.get('REPRO109_TEST_TMP')
        with tempfile.TemporaryDirectory(dir=base if base and Path(base).is_dir() else None) as tmp:
            origin = Path(tmp) / 'origin'
            (origin / 'build/recipe').mkdir(parents=True)
            (origin / 'dlls/ntdll').mkdir(parents=True)
            (origin / 'build/recipe/x.py').write_text('x\n')
            (origin / 'dlls/ntdll/a.c').write_text('a\n')
            (origin / 'configure').write_text('c\n')
            git('init', '-q', cwd=origin)
            git('add', '-A', cwd=origin)
            git('commit', '-q', '-m', 'one', cwd=origin)
            revision = git('rev-parse', 'HEAD', cwd=origin)
            work = Path(tmp) / 'work'
            work.mkdir()
            calls = []
            def run(argv, log, cwd=None):
                calls.append(argv[:2])
                git(*argv[1:], cwd=cwd)
            wine.fetch_pinned_source(work, 'file://' + str(origin), revision, Path(tmp) / 'source.log', run)
            self.assertEqual(git('rev-parse', 'HEAD', cwd=work), revision)
            self.assertEqual(git('status', '--porcelain', cwd=work), '')
            self.assertFalse((work / 'build').exists())
            self.assertEqual((work / 'dlls/ntdll/a.c').read_text(), 'a\n')
            (work / 'build').mkdir()  # the statement the first full runs died on
            self.assertEqual(calls[:2], [['git', 'init'], ['git', 'sparse-checkout']])

    def test_build_wine_uses_the_function_and_not_a_bare_checkout(self):
        source = (HERE / 'build_wine.py').read_text()
        self.assertIn("fetch_pinned_source(src, lock['repository'], lock['revision']", source)
        self.assertNotIn("command(['git', 'fetch', '-q', '--depth=1', lock['repository']", source)
        self.assertIn("'!/build/'", source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
