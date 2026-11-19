"""Apply the pinned 1.1.4 candidate c34r-affinity (MACRUNNER_THREAD_AFFINITY_FAST, ntdll unix thread.c+process.c) after the c33r delta."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

def identity(path):
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError('Regular source file required: ' + str(path))
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def inputs(recipe=HERE):
    recipe = Path(recipe)
    lock = json.loads((recipe / 'release114-source.lock.json').read_bytes())
    if (lock['schema'] != 1 or lock['release'] != '1.1.4' or lock['candidate'] != 'c34r-affinity'
            or lock['after'] != 'release111-c33r' or lock['patch'] != 'late/release114-c34r-affinity.patch'
            or lock['base_revision'] != 'b812a090e2ca58c3902008929facd71f15fc3fc4'):
        raise ValueError('Candidate 1.1.4 source identity differs')
    if identity(recipe / lock['patch']) != lock['patch_identity']:
        raise ValueError('Candidate 1.1.4 source patch bytes differ')
    names = [row['path'] for row in lock['files']]
    if not names or names != sorted(set(names)) or len({name.casefold() for name in names}) != len(names):
        raise ValueError('Candidate source path order/uniqueness differs')
    for name in names:
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or str(path) != name or name.startswith('loader/'):
            raise ValueError('Unsafe or out-of-scope candidate source path')
    if any(row['before'] is None or row['after'] is None for row in lock['files']):
        raise ValueError('c34r-affinity may only modify existing files')
    return lock

def apply(source, out, command, recipe=HERE):
    source, out = Path(source), Path(out)
    lock = inputs(recipe)
    if not (source / '.git').is_dir() or (source / '.git').is_symlink():
        raise ValueError('Owned Wine Git source required')
    for row in lock['files']:
        path = source / row['path']
        if any(parent.is_symlink() for parent in [path, *path.parents] if parent != source.parent):
            raise ValueError('Candidate source link refused: ' + row['path'])
        if identity(path) != row['before']:
            raise ValueError('Candidate 1.1.4 source base differs: ' + row['path'])
    patch = str((Path(recipe) / lock['patch']).resolve())
    command(['git', 'apply', '--check', patch], out / 'release114-source.log', cwd=source, timeout=30)
    command(['git', 'apply', patch], out / 'release114-source.log', cwd=source, timeout=30)
    for row in lock['files']:
        if identity(source / row['path']) != row['after']:
            raise ValueError('Candidate 1.1.4 source result differs: ' + row['path'])
    result = dict(status='CANDIDATE_SOURCE_PATCH_APPLIED_NOT_COMPILED', release='1.1.4', candidate='c34r-affinity',
                  files=len(lock['files']), patch=lock['patch_identity'],
                  release_acceptance=False, loader_acceptance='SEPARATE', default_off='MACRUNNER_THREAD_AFFINITY_FAST=0')
    with (out / 'release114-source.json').open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    return result
