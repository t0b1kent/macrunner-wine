"""Offline configure/install contract; only owned inert fixtures and native make/sh."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('wine_paths_driver', HERE / 'build_wine.py')
WINE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(WINE)
ARCHS = ['aarch64', 'arm64ec', 'x86_64', 'i386']


class BuildPaths(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='build-paths-', dir=os.environ['REPRO109_TEST_TMP'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self, name):
        root = self.root / name
        src = root / 'engine/wine'
        build = src / 'build'
        build.mkdir(parents=True)
        # This configure is our fixture, never the downloaded Wine configure.
        configure = src / 'configure'
        configure.write_text('#!' + sys.executable + '\n' + textwrap.dedent('''\
            import os, pathlib, sys
            values = dict(arg[2:].split('=', 1) for arg in sys.argv[1:] if '=' in arg)
            directories = {key: values[key] for key in ['prefix', 'bindir', 'libdir', 'datadir']}
            lines = ['srcdir = ' + os.path.relpath(pathlib.Path(__file__).resolve().parent)]
            lines += [key + ' = ' + value for key, value in directories.items()]
            lines += ['install:']
            for key, output in [('bindir', 'wine'), ('libdir', 'wine/ntdll.fixture'), ('datadir', 'wine/data.fixture')]:
                target = '$(DESTDIR)$(' + key + ')/' + output
                parent = target.rsplit('/', 1)[0]
                lines.append('\\tmkdir -p "' + parent + '"')
                lines.append('\\tprintf "%s\\\\n" "BINDIR=$(bindir)" "LIBDIR=$(libdir)" "DATADIR=$(datadir)" > "' + target + '"')
            pathlib.Path('Makefile').write_text('\\n'.join(lines) + '\\n')
            '''))
        configure.chmod(0o700)
        subprocess.run(WINE.configure_command(src, build, ARCHS), cwd=build, check=True,
                       capture_output=True, stdin=subprocess.DEVNULL, timeout=10)
        return root, src, build

    def guard(self, root):
        return subprocess.run(['sh', str(HERE / 'check-build-srcdir.sh'), str(root)],
                              capture_output=True, stdin=subprocess.DEVNULL, timeout=10)

    def test_configure_is_unchanged_after_work_root_moves(self):
        left, ls, lb = self.fixture('first work root')
        right, rs, rb = self.fixture('second work root')
        self.assertEqual(WINE.configure_command(ls, lb, ARCHS), WINE.configure_command(rs, rb, ARCHS))
        self.assertEqual((lb / 'Makefile').read_bytes(), (rb / 'Makefile').read_bytes())
        self.assertEqual(self.guard(left).returncode, 0)
        self.assertEqual(self.guard(right).returncode, 0)
        self.assertNotIn(str(left).encode(), (lb / 'Makefile').read_bytes())

    def test_real_make_destdir_preserves_package_layout_and_contents(self):
        root, source, build = self.fixture('owned work')
        expected = b'BINDIR=/bin\nLIBDIR=/lib\nDATADIR=/share\n'
        outputs = ['bin/wine', 'lib/wine/ntdll.fixture', 'share/wine/data.fixture']
        for name in ['first stage', 'moved stage']:
            stage = self.root / name
            subprocess.run(WINE.install_command(stage), cwd=build, check=True,
                           capture_output=True, stdin=subprocess.DEVNULL, timeout=10)
            self.assertEqual(sorted(str(p.relative_to(stage)) for p in stage.rglob('*') if p.is_file()), outputs)
            for output in outputs:
                self.assertEqual((stage / output).read_bytes(), expected)
                self.assertNotIn(str(stage).encode(), (stage / output).read_bytes())
        self.assertFalse((root / 'install').exists())

    def test_existing_guard_accepts_moved_own_source_and_rejects_foreign(self):
        root, source, build = self.fixture('original')
        moved = self.root / 'relocated'
        shutil.move(str(root), str(moved))
        self.assertEqual(self.guard(moved).returncode, 0)
        foreign, foreign_source, _ = self.fixture('foreign')
        mk = moved / 'engine/wine/build/Makefile'
        mk.write_text(mk.read_text().replace('srcdir = ..', 'srcdir = ' + str(foreign_source)))
        self.assertEqual(self.guard(moved).returncode, 1)


if __name__ == '__main__':
    unittest.main()
