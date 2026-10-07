"""Owned archive/Git fixtures and inert transfers; never download or execute upstream source."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import preflight_sources as inputs
import source_download
import public_archive


class SourceInputs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ['REPRO109_TEST_TMP'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.body = b'owned archive fixture never executed'
        self.lock = copy.deepcopy(inputs.dep.read_lock())
        for row in self.lock['components']:
            row['sha256'] = hashlib.sha256(self.body).hexdigest()
        self.git = next(row for row in self.lock['components'] if row.get('source_kind') == 'git')
        self.git_actual = dict(revision=self.git['revision'],
                               revision_count=str(self.git['revision_count']), dirty='')

    def collect(self, failed=(), missing_tool=False):
        calls = []
        def download(row, archive, out):
            calls.append(row['name'])
            if row['name'] in failed:
                raise ValueError('owned wrong archive body')
            if missing_tool and row['name'] == 'cmake':
                raise FileNotFoundError('owned curl tool absent')
            archive.write_bytes(self.body)
            return dict(state='PRESENT', bytes=len(self.body), sha256=row['sha256'])
        def git(row, root, archive, env, out, deadline):
            calls.append(row['name']); archive.write_bytes(self.body)
            source = root / (row['name'] + '-source'); source.mkdir()
            configure = source / 'configure'; configure.write_bytes(b'inert owned mode fixture')
            configure.chmod(0o755)
            return source
        with patch.object(inputs.dep, 'cloud_guard'), \
             patch.object(inputs.dep.source_download, 'download', side_effect=download), \
             patch.object(inputs.dep, 'git_source', side_effect=git), \
             patch.object(inputs, 'git_identity', return_value=self.git_actual), \
             patch.object(inputs.dep, 'build_steps') as build, \
             patch.object(inputs.dep, 'toolchain_preflight') as compiler:
            receipt = inputs.collect(self.root/'inputs', self.lock)
            build.assert_not_called(); compiler.assert_not_called()
        return receipt, calls

    def validate(self):
        with patch.object(inputs, 'git_identity', return_value=self.git_actual):
            return inputs.validate(self.root/'inputs', self.lock)

    def test_all_47_inputs_without_any_build_or_compiler(self):
        receipt, calls = self.collect()
        self.assertEqual((receipt['archive_components'], receipt['git_components']), (46, 1))
        self.assertEqual(len(calls), 47); self.assertEqual(len(set(calls)), 47)
        self.assertEqual(receipt['status'], 'ALL_SOURCE_INPUTS_PRESENT_NOT_BUILT')
        self.assertEqual(self.validate()['present_components'], 47)

    def test_two_failed_inputs_do_not_skip_the_other_45(self):
        receipt, calls = self.collect(('cmake', 'dav1d'))
        self.assertEqual(len(calls), 47)
        self.assertEqual((receipt['present_components'], receipt['failed_components']), (45, 2))
        self.assertEqual({r['component'] for r in receipt['failures']}, {'cmake', 'dav1d'})
        self.assertIn(receipt['first_failure']['component'], {'cmake', 'dav1d'})
        with self.assertRaisesRegex(ValueError, 'incomplete'): self.validate()

    def test_missing_transfer_tool_in_empty_environment_is_one_recorded_failure(self):
        with patch.dict(os.environ, {}, clear=True):
            receipt, calls = self.collect(missing_tool=True)
        self.assertEqual(len(calls), 47)
        self.assertEqual(receipt['failed_components'], 1)
        self.assertIn('tool absent', receipt['first_failure']['error'])

    def test_wrong_cloud_is_refused_before_work_or_transfers(self):
        with patch.object(inputs.dep, 'cloud_guard', side_effect=ValueError('owned cloud refusal')), \
             patch.object(inputs.dep.source_download, 'download') as transfer:
            with self.assertRaisesRegex(ValueError, 'cloud refusal'):
                inputs.collect(self.root/'inputs', self.lock)
            transfer.assert_not_called()
        self.assertFalse((self.root/'inputs').exists())

    def test_fresh_path_refuses_before_transfer(self):
        with patch.object(inputs.dep, 'cloud_guard'), patch.object(inputs.dep.source_download, 'download') as transfer:
            with self.assertRaisesRegex(ValueError, 'Fresh'): inputs.collect(self.root, self.lock)
            transfer.assert_not_called()

    def test_consumer_collects_both_corrupt_archives_in_error(self):
        self.collect()
        for name in ['cmake', 'dav1d']:
            (self.root/'inputs'/(name+'.source.tar')).write_bytes(b'owned corruption')
        with self.assertRaises(ValueError) as error: self.validate()
        self.assertIn('cmake', str(error.exception)); self.assertIn('dav1d', str(error.exception))

    def test_missing_input_rejected(self):
        self.collect(); (self.root/'inputs/dav1d.source.tar').unlink()
        with self.assertRaisesRegex(ValueError, 'dav1d'): self.validate()

    def test_symlink_input_rejected(self):
        self.collect(); p=self.root/'inputs/dav1d.source.tar';p.unlink();p.symlink_to('cmake.source.tar')
        with self.assertRaisesRegex(ValueError, 'dav1d'): self.validate()

    def test_foreign_lock_rejected(self):
        self.collect()
        with patch.object(inputs, 'identity', return_value={'foreign':'owned'}):
            with self.assertRaisesRegex(ValueError, 'another lock'): self.validate()

    def test_changed_git_revision_or_dirty_checkout_rejected(self):
        self.collect()
        for key in ['revision', 'revision_count', 'dirty']:
            actual=dict(self.git_actual);actual[key]='owned wrong'
            with patch.object(inputs,'git_identity',return_value=actual):
                with self.assertRaisesRegex(ValueError,'Git checkout differs'):
                    inputs.validate(self.root/'inputs',self.lock)

    def test_copy_rehashes_before_unpack(self):
        self.collect(); row=self.lock['components'][0]
        (self.root/'inputs'/(row['name']+'.source.tar')).write_bytes(b'owned corruption')
        with patch.object(inputs.dep,'unpack') as unpack:
            with self.assertRaisesRegex(ValueError,'changed during copy'):
                inputs.copy_source(row,self.root/'inputs',self.root/'copy.tar',self.root/'build')
            unpack.assert_not_called()

    def test_git_copy_preserves_executable_mode(self):
        self.collect();work=self.root/'build';work.mkdir()
        with patch.object(inputs,'git_identity',return_value=self.git_actual):
            source=inputs.copy_source(self.git,self.root/'inputs',work/'x264.source.tar',work)
        self.assertEqual((source/'configure').stat().st_mode & 0o777, 0o755)

    def test_tar_restores_git_mode_and_rehashes_every_input(self):
        self.collect(); archive=self.root/'inputs.tar.gz'
        with tarfile.open(archive,'w:gz') as target:target.add(self.root/'inputs',arcname='.')
        with patch.object(inputs,'git_identity',return_value=self.git_actual):
            receipt=inputs.extract_inputs(archive,self.root/'restored',self.lock)
        self.assertEqual(receipt['present_components'],47)
        self.assertEqual((self.root/'restored/x264-source/configure').stat().st_mode & 0o777,0o755)

    def test_tar_traversal_never_writes_outside_destination(self):
        archive=self.root/'bad.tar'
        with tarfile.open(archive,'w') as target:
            row=tarfile.TarInfo('../../owned-escape');row.size=3;target.addfile(row,io.BytesIO(b'own'))
        with self.assertRaises(tarfile.FilterError):inputs.extract_inputs(archive,self.root/'restored',self.lock)
        self.assertFalse((self.root.parent/'owned-escape').exists())

    def test_full_consumer_rejects_bad_inputs_before_work_creation(self):
        self.collect(('dav1d',))
        sys.path.insert(0,str(inputs.HERE.parent/'repro109wine'))
        import build_full
        work=self.root/'full-work'
        with patch.object(build_full,'cloud_guard'):
            with self.assertRaisesRegex(ValueError,'incomplete'):
                build_full.build(work,build_full.check_inputs(),source_inputs=self.root/'inputs')
        self.assertFalse(work.exists())


class MirrorCoverage(unittest.TestCase):
    def test_all_46_archive_routes_have_exact_fallbacks(self):
        routes=source_download.read_routes()['routes']
        self.assertEqual(len(routes),46)
        for name,row in routes.items():
            with self.subTest(component=name):self.assertTrue(row['mirror_urls'])

    def test_wrong_body_then_correct_fallback_for_entire_archive_family(self):
        body=b'owned sealed source bytes'
        for name,route in source_download.read_routes()['routes'].items():
            with self.subTest(component=name), tempfile.TemporaryDirectory(dir=os.environ['REPRO109_TEST_TMP']) as temp:
                root=Path(temp);out=root/'out';out.mkdir();seen=[]
                request=dict(name=name,url=route['url'],source_urls=[route['url']]+route['mirror_urls'],
                    source_route={'allowed_hosts':route['allowed_hosts']},size=len(body),
                    sha256=hashlib.sha256(body).hexdigest())
                def transfer(url,target,limit,timeout_seconds):
                    seen.append(url);data=b'owned HTML' if len(seen)==1 else body;target.write_bytes(data)
                    return dict(curl_rc=0,http_status=200,content_length=str(len(data)))
                with patch.object(public_archive.time,'sleep'):
                    receipt=public_archive.download(request,root/'source',out,transfer=transfer)
                self.assertEqual(seen,[route['url'],route['mirror_urls'][0]])
                self.assertEqual(receipt['selected_source_index'],1)
                self.assertEqual((root/'source').read_bytes(),body)
                self.assertEqual((out/'public-archives'/name/'attempt-1.body').read_bytes(),b'owned HTML')

    def test_foreign_backup_refused_before_transport(self):
        routes=source_download.read_routes()
        bad=copy.deepcopy(routes);bad['routes']['dav1d']['mirror_urls']=['https://foreign.invalid/owned']
        path=source_download.HERE/'source-routes.lock.json';original=Path.read_text
        def read(p,*args,**kwargs):return json.dumps(bad) if p==path else original(p,*args,**kwargs)
        with patch.object(Path,'read_text',read):
            with self.assertRaisesRegex(ValueError,'mirror order/path'):source_download.read_routes()


if __name__=='__main__':unittest.main(verbosity=2)
