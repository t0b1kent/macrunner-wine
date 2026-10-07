"""Apply the approved 1.0.9 keyboard source delta before Wine configure."""
import hashlib
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
TARGET='dlls/winemac.drv/cocoa_app.m'
PATCH_SHA='0d5ea043c78fd408cb85d6688a98df28600ba929eb7d22cc92ab201dafe39a12'
BASE_SHA='8f06b3d9c749d86b6393c89fdf2ea04846257d874388342f86e4b7e685b6730c'
RESULT_SHA='638fb958fe6d69f2f8f58c530a20c92fa3d3b992fa669b7f18d8e8a48da6a220'


def require(condition,message):
    if not condition:raise ValueError(message)


def sha(data):return hashlib.sha256(data).hexdigest()


def inputs(recipe=HERE):
    recipe=Path(recipe)
    lock=json.loads((recipe/'keyboard109.lock.json').read_bytes())
    require(lock['schema']==1 and lock['target']==TARGET,'Keyboard lock identity differs')
    require(lock['wine_revision']=='ce9f9ed6177d57a43f6fd1e9c8d9be87224eb08a',
            'Keyboard Wine revision differs')
    require(lock['patch']=='late/0097-winemac-keyboard-ascii.patch', 'Keyboard patch path differs')
    require(lock['patch_sha256']==PATCH_SHA and lock['base_sha256']==BASE_SHA and
            lock['result_sha256']==RESULT_SHA,'Keyboard source pins differ')
    patch=recipe/lock['patch']
    require(patch.is_file() and not patch.is_symlink(),'Keyboard patch must be regular')
    data=patch.read_bytes()
    require(len(data)==lock['patch_bytes'] and sha(data)==PATCH_SHA,'Keyboard patch bytes differ')
    names=re.findall(rb'^(?:--- a/|\+\+\+ b/)([^\r\n]+)$',data,re.M)
    require(names==[TARGET.encode(),TARGET.encode()],'Keyboard patch scope differs')
    return lock


def apply(source,out,command,recipe=HERE):
    lock=inputs(recipe)
    source=Path(source).resolve();out=Path(out)
    require((source/'.git').is_dir() and not (source/'.git').is_symlink(),
            'Owned Wine Git source required')
    target=source/TARGET
    require(all(not p.is_symlink() for p in [target,*target.parents] if p!=source.parent),
            'Keyboard source link refused')
    before=target.read_bytes()
    blob=hashlib.sha1(b'blob '+str(len(before)).encode()+b'\0'+before).hexdigest()
    require(len(before)==lock['base_bytes'] and sha(before)==BASE_SHA and
            blob==lock['base_blob'],'Keyboard source base differs')
    patch=str((Path(recipe)/lock['patch']).resolve())
    command(['git','apply','--check',patch],out/'keyboard109-patch.log',cwd=source,timeout=30)
    command(['git','apply',patch],out/'keyboard109-patch.log',cwd=source,timeout=30)
    after=target.read_bytes()
    require(len(after)==lock['result_bytes'] and sha(after)==RESULT_SHA,
            'Keyboard patched result differs')
    receipt=dict(status='SOURCE_PATCH_APPLIED_NOT_COMPILED',target=TARGET,
                 wine_revision=lock['wine_revision'],base_blob=blob,
                 base_sha256=BASE_SHA,patch_sha256=PATCH_SHA,
                 result_bytes=len(after),result_sha256=RESULT_SHA,
                 lock_sha256=sha((Path(recipe)/'keyboard109.lock.json').read_bytes()))
    with (out/'keyboard109-source.json').open('x') as stream:
        stream.write(json.dumps(receipt,indent=2)+'\n')
    return receipt
