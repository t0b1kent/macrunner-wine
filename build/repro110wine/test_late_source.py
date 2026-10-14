"""Run exact retained Wine C + retained 0097 through real Git; no compilation."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE=Path(__file__).resolve().parent


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


late=load('late_source_under_test',HERE/'late_source.py')
wine=load('wine_source_under_test',HERE/'build_wine.py')
SCRATCH=HERE.parent.parent/'test-scratch/wine-keyboard109-tests'
SCRATCH.mkdir(parents=True,exist_ok=True)


class SourceControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='source-',dir=str(SCRATCH))
        self.root=Path(self.temp.name);self.source=self.root/'wine';self.source.mkdir()
        self.out=self.root/'reports';self.out.mkdir()
        subprocess.run(['git','init','--quiet'],cwd=self.source,stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=30)
        self.target=self.source/late.TARGET;self.target.parent.mkdir(parents=True)
        fixture=HERE/'fixtures/keyboard109-base-cocoa_app.m'
        self.assertEqual(late.sha(fixture.read_bytes()),late.BASE_SHA)
        shutil.copyfile(fixture,self.target)
        self.sentinel=self.source/'unchanged';self.sentinel.write_bytes(b'unrelated source sentinel\n')

    def tearDown(self):self.temp.cleanup()

    def apply(self):return late.apply(self.source,self.out,wine.command)

    def recipe(self):
        recipe=self.root/'recipe';(recipe/'late').mkdir(parents=True)
        shutil.copyfile(HERE/'keyboard109.lock.json',recipe/'keyboard109.lock.json')
        shutil.copyfile(HERE/'late/0097-winemac-keyboard-ascii.patch',recipe/'late/0097-winemac-keyboard-ascii.patch')
        return recipe

    def test_real_source_apply_exact_result(self):
        result=self.apply()
        self.assertEqual(result['result_bytes'],134109)
        self.assertEqual(late.sha(self.target.read_bytes()),late.RESULT_SHA)
        self.assertEqual(self.sentinel.read_bytes(),b'unrelated source sentinel\n')
        self.assertEqual(json.loads((self.out/'keyboard109-source.json').read_bytes()),result)
        self.assertEqual(wine.inputs()['revision'],result['wine_revision'])

    def test_wrong_base_refused_before_git(self):
        self.target.write_bytes(self.target.read_bytes()+b'\n')
        with self.assertRaisesRegex(ValueError,'base differs'):self.apply()
        self.assertFalse((self.out/'keyboard109-patch.log').exists())

    def test_duplicate_apply_refused_without_overwrite(self):
        self.apply();before=(self.out/'keyboard109-source.json').read_bytes()
        with self.assertRaisesRegex(ValueError,'base differs'):self.apply()
        self.assertEqual((self.out/'keyboard109-source.json').read_bytes(),before)

    def test_patch_corruption_refused(self):
        recipe=self.recipe();p=recipe/'late/0097-winemac-keyboard-ascii.patch'
        p.write_bytes(p.read_bytes()+b'\n')
        with self.assertRaisesRegex(ValueError,'patch bytes differ'):late.inputs(recipe)

    def test_missing_required_lock_refused(self):
        with self.assertRaises(FileNotFoundError):late.inputs(self.root/'missing')

    def test_wrong_revision_or_scope_refused(self):
        recipe=self.recipe();p=recipe/'keyboard109.lock.json';original=json.loads(p.read_bytes())
        for key,value in [('wine_revision','0'*40),('target','dlls/other.c')]:
            with self.subTest(key=key):
                changed=dict(original);changed[key]=value;p.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):late.inputs(recipe)

    def test_target_link_refused(self):
        self.target.unlink();self.target.symlink_to(HERE/'fixtures/keyboard109-base-cocoa_app.m')
        with self.assertRaisesRegex(ValueError,'link refused'):self.apply()

    def test_owned_git_required(self):
        (self.source/'.git').rename(self.source/'.saved-git')
        with self.assertRaisesRegex(ValueError,'Owned Wine Git'):self.apply()
        self.assertFalse((self.out/'keyboard109-patch.log').exists())


if __name__=='__main__':unittest.main(verbosity=1)
