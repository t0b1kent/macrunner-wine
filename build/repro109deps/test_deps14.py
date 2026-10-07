"""b30 source link rule, installed identities, and the named FreeType route."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import time
import unittest

import build_deps
import deps14_support
import private_curl
import source_download
import source_fixes

HERE = Path(__file__).resolve().parent
ARCHIVE_SHA = '7a479a3c66b9f5d5542a4c6a1b7d3768a983b1e5c14c60a9396edc9b649e015c'
SOURCE_SHA = 'b7554da31a575b282c855e44ccd25a772315ba4b10d7de0ab62f9a07dd9ebb27'


class Deps14Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected = os.environ.get('REPRO109_LIBVPX_ARCHIVE')
        if not selected:
            raise ValueError('REPRO109_LIBVPX_ARCHIVE: existing cloud source evidence required; no download')
        archive = Path(selected)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA:
            raise ValueError('Selected libvpx source archive SHA differs')
        with tarfile.open(archive, 'r:*') as stream:
            cls.original = stream.extractfile('libvpx-1.16.0/build/make/Makefile').read()
        if hashlib.sha256(cls.original).hexdigest() != SOURCE_SHA:
            raise ValueError('Selected Darwin Makefile SHA differs')

    def setUp(self):
        parent = HERE / '.offline-fixtures'
        parent.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='deps14-', dir=parent)
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def test_real_archive_transform_is_one_darwin_rule(self):
        after, count = source_fixes.libvpx_darwin_install_name(self.original)
        self.assertEqual(count, 1)
        line = b'        -Wl,-install_name,@rpath/$$(notdir $$@) \\\n'
        self.assertEqual(after.count(line), 1)
        self.assertEqual(after.replace(line, b'', 1), self.original)

    def test_real_make_expands_install_name_for_both_output_basenames(self):
        after, _ = source_fixes.libvpx_darwin_install_name(self.original)
        template = re.search(rb'^define dl_template\n.*?^endef\n', after, re.M | re.S).group()
        fixture = self.root / 'Makefile'
        fixture.write_bytes(b'LD := own-fixture-linker\nVERSION_MAJOR := 12\nEXPORTS_FILE := symbols\n' +
                            template + b'\n$(eval $(call dl_template,libvpx.12.dylib))\n' +
                            b'$(eval $(call dl_template,libvpx.99.dylib))\n')
        for name in ['libvpx.12.dylib', 'libvpx.99.dylib']:
            child = subprocess.run(['/usr/bin/make', '-n', '-f', str(fixture), name],
                                   cwd=self.root, capture_output=True, timeout=5,
                                   env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
            self.assertEqual(child.returncode, 0, child.stderr)
            self.assertIn(('-Wl,-install_name,@rpath/' + name).encode(), child.stdout)
            self.assertNotIn(b'$(', child.stdout)
            self.assertFalse((self.root / name).exists())

    def test_missing_duplicate_and_reapplied_rule_refuse(self):
        after, _ = source_fixes.libvpx_darwin_install_name(self.original)
        for source in [b'no Darwin rule\n', self.original + self.original, after]:
            with self.assertRaises(ValueError):
                source_fixes.libvpx_darwin_install_name(source)

    def apply(self, blob, version='1.16.0'):
        source = self.root / 'source'
        out = self.root / 'reports'
        target = source / 'build/make/Makefile'
        target.parent.mkdir(parents=True, exist_ok=True)
        out.mkdir(exist_ok=True)
        target.write_bytes(blob)
        events = []
        source_fixes.apply_source_fixes(dict(name='libvpx', version=version), source, out,
                                      lambda *args, **fields: events.append(fields))
        return target, out, events

    def test_real_apply_retains_exact_before_after_patch_and_event(self):
        target, out, events = self.apply(self.original)
        self.assertEqual((out / 'libvpx-source-fix-before.raw').read_bytes(), self.original)
        self.assertEqual((out / 'libvpx-source-fix-after.raw').read_bytes(), target.read_bytes())
        self.assertEqual(events[0]['input_sha256'], SOURCE_SHA)
        self.assertEqual(events[0]['output_sha256'], hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertEqual(events[0]['patch_sha256'], hashlib.sha256((out / 'libvpx-source-fix.patch').read_bytes()).hexdigest())

    def test_apply_source_fingerprint_and_version_drift_refuse_before_evidence(self):
        for blob, version in [(self.original + b'\n', '1.16.0'), (self.original, '1.17.0')]:
            with self.assertRaises(ValueError):
                self.apply(blob, version)
            self.assertFalse((self.root / 'reports/libvpx-source-fix-before.raw').exists())

    def library(self):
        prefix = self.root / 'prefix'
        (prefix / 'lib').mkdir(parents=True)
        real = prefix / 'lib/libvpx.12.dylib'
        real.write_bytes(b'OWN_FIXTURE_NOT_EXECUTABLE')
        (prefix / 'lib/libvpx.dylib').symlink_to(real.name)
        return prefix, real

    def test_exact_installed_identity_and_bare_absolute_wrong_version_refuse(self):
        _, real = self.library()
        self.assertEqual(deps14_support.validate_libvpx_install_name(str(real) + ':\n@rpath/libvpx.12.dylib\n', real),
                         '@rpath/libvpx.12.dylib')
        for identity in ['libvpx.12.dylib', str(real), '@rpath/libvpx.13.dylib', '', '@rpath/libvpx.12.dylib\nextra']:
            with self.assertRaises(ValueError):
                deps14_support.validate_libvpx_install_name(str(real) + ':\n' + identity + '\n', real)

    def test_real_probe_call_retains_bounded_read_only_argv_and_raw_sha(self):
        prefix, real = self.library()
        out = self.root / 'reports'
        out.mkdir()
        calls = []
        def own_command(argv, cwd, env, log, evidence, component, deadline, timeout):
            calls.append((argv, cwd, component, timeout))
            log.write_text(str(real) + ':\n@rpath/libvpx.12.dylib\n')
        report = deps14_support.libvpx_install_name_probe(prefix, {}, out, time.monotonic() + 5, own_command)
        self.assertEqual(calls, [(['/usr/bin/otool', '-D', str(real)], prefix, 'libvpx', 30)])
        self.assertEqual(report['raw_sha256'], hashlib.sha256((out / report['raw_path']).read_bytes()).hexdigest())

    def test_wrong_alias_and_dyld_override_refuse_before_query(self):
        prefix, _ = self.library()
        def query(*args, **kwargs):
            self.fail('invalid input queried native tool')
        with self.assertRaises(ValueError):
            deps14_support.libvpx_install_name_probe(prefix, {'DYLD_LIBRARY_PATH': '/foreign'}, self.root, 0, query)
        (prefix / 'lib/libvpx.dylib').unlink()
        (prefix / 'lib/libvpx.dylib').symlink_to('missing.dylib')
        with self.assertRaises(ValueError):
            deps14_support.libvpx_install_name_probe(prefix, {}, self.root, 0, query)

    def test_freetype_only_named_b30_mirror_added_no_wildcard(self):
        routes = source_download.read_routes()['routes']['freetype']
        hosts = routes['allowed_hosts']
        self.assertEqual(hosts, ['cfhcable.dl.sourceforge.net', 'downloads.sourceforge.net',
                                 'gigenet.dl.sourceforge.net', 'netactuate.dl.sourceforge.net',
                                 'psychz.dl.sourceforge.net'])
        self.assertTrue(private_curl._public_host_allowed('psychz.dl.sourceforge.net', set(hosts)))
        for host in ['psychz.dl.sourceforge.net.evil.invalid', 'foreign.dl.sourceforge.net', 'evil.invalid']:
            self.assertFalse(private_curl._public_host_allowed(host, set(hosts)))

    def test_build_driver_checks_identity_before_downstream_plugin_probes(self):
        source = (HERE / 'build_deps.py').read_text()
        self.assertLess(source.index("if current == 'libvpx':"), source.index("if row.get('gst_plugins'):",
                                                                            source.index("phase = 'OUTPUTS'")))


if __name__ == '__main__':
    unittest.main(verbosity=2)
