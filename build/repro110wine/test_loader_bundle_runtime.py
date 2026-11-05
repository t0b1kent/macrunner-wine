"""Exercise the production Wine lookup function without launching Wine."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('bundle_runtime_wine', HERE / 'build_wine.py')
wine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wine)
SOURCE = HERE.parents[1] / 'loader/main.c'


class LoaderBundleRuntime(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='loader-bundle-', dir=os.environ['REPRO109_TEST_TMP'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / 'source/loader/main.c'
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(SOURCE.read_bytes())
        self.reports = self.root / 'reports'
        self.reports.mkdir()

    def test_exact_source_pin_and_preserved_original_lookup(self):
        before = self.target.read_bytes()
        row = wine.prepare_loader_bundle_runtime(self.root / 'source', self.reports)
        after = self.target.read_bytes()
        self.assertEqual(row['before_sha256'], wine.sha(before))
        self.assertIn(b'path = build_path( p, "dlls/ntdll/ntdll.so" );', after)
        self.assertIn(b'path = build_path( dir, "ntdll.so" );', after)
        self.assertEqual(json.loads((self.reports / 'loader-bundle-runtime-source.json').read_text()), row)

    def test_drift_and_repeat_are_rejected_before_write(self):
        wine.prepare_loader_bundle_runtime(self.root / 'source', self.reports)
        after = self.target.read_bytes()
        with self.assertRaisesRegex(ValueError, 'source drift'):
            wine.prepare_loader_bundle_runtime(self.root / 'source', self.reports)
        self.assertEqual(self.target.read_bytes(), after)

    def test_native_lookup_for_helper_installed_build_and_wrong_suffix(self):
        wine.prepare_loader_bundle_runtime(self.root / 'source', self.reports)
        source = self.target.read_text()
        helpers = source[source.index('static char *realpath_dirname'):source.index('static const char *get_self_exe')]
        lookup = source[source.index('static void *try_dlopen'):source.index('\n#ifdef __APPLE__', source.index('    return handle;', source.index('static void *try_dlopen')))]
        harness = '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <dlfcn.h>\n'
        harness += 'static void macrunner_zakrepit_ntdll(void) {}\n'
        harness += 'static void *probe_dlopen(const char *p, int flags) { puts(p); return (void *)1; }\n#define dlopen probe_dlopen\n'
        harness += helpers + lookup + '\nint main(int argc, char **argv) { return !try_dlopen(argv[1]); }\n'
        cfile = self.root / 'lookup.c'; cfile.write_text(harness)
        executable = self.root / 'lookup'
        sdk = subprocess.run(['xcrun', '--sdk', 'macosx', '--show-sdk-path'], capture_output=True, text=True, check=True, timeout=20).stdout.strip()
        subprocess.run(['xcrun', '--sdk', 'macosx', 'clang', '-isysroot', sdk, '-Werror', str(cfile), '-o', str(executable)], capture_output=True, check=True, timeout=30)
        cases = [
            ('App/Contents/Resources/wine-loader/MacRunner Wine Loader.app/Contents/MacOS/wine', 'App/Contents/Resources/engine/wine/lib/wine/aarch64-unix/ntdll.so'),
            ('engine/wine/lib/wine/aarch64-unix/wine', 'engine/wine/lib/wine/aarch64-unix/ntdll.so'),
            ('wine-build/loader/wine', 'wine-build/dlls/ntdll/ntdll.so'),
            ('Wrong MacRunner Wine Loader.app/Contents/MacOS/wine', 'Wrong MacRunner Wine Loader.app/Contents/MacOS/ntdll.so')]
        for path, expected in cases:
            with self.subTest(path=path):
                target = self.root / path; target.parent.mkdir(parents=True); target.write_bytes(b'lookup fixture')
                result = subprocess.run([str(executable), str(target)], capture_output=True, text=True, check=True, timeout=5)
                self.assertEqual(result.stdout.strip(), str(self.root / expected))


if __name__ == '__main__':
    unittest.main()
