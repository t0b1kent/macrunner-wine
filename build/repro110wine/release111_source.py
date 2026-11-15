"""Apply the pinned candidate c33r Wine DLL delta after the c32r source inputs."""
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
    lock = json.loads((recipe / 'release111-source.lock.json').read_bytes())
    if (lock['schema'] != 1 or lock['release'] != '1.1.1' or lock['candidate'] != 'c33r'
            or lock['after'] != 'release110-c32r' or lock['patch'] != 'late/release111-c33r.patch'
            or lock['base_revision'] != 'b812a090e2ca58c3902008929facd71f15fc3fc4'):
        raise ValueError('Candidate release source identity differs')
    digest = lock['engine_sha256']
    if not isinstance(digest, str) or len(digest) != 64 or set(digest) - set('0123456789abcdef'):
        raise ValueError('Candidate engine digest differs')
    if identity(recipe / lock['patch']) != lock['patch_identity']:
        raise ValueError('Candidate release source patch bytes differ')
    names = [row['path'] for row in lock['files']]
    if not names or names != sorted(set(names)) or len({name.casefold() for name in names}) != len(names):
        raise ValueError('Candidate source path order/uniqueness differs')
    for name in names:
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or str(path) != name or name.startswith('loader/'):
            raise ValueError('Unsafe or out-of-scope candidate source path')
    headers = sorted(row['path'] for row in lock['files'] if row['before'] is None and row['after']
                     and row['path'].startswith('include/') and row['path'].endswith('.h'))
    if headers != lock['new_include_headers']:
        raise ValueError('Candidate include-header census differs')
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
            raise ValueError('Candidate release source base differs: ' + row['path'])
    patch = str((Path(recipe) / lock['patch']).resolve())
    command(['git', 'apply', '--check', patch], out / 'release111-source.log', cwd=source, timeout=30)
    command(['git', 'apply', patch], out / 'release111-source.log', cwd=source, timeout=30)
    for row in lock['files']:
        if identity(source / row['path']) != row['after']:
            raise ValueError('Candidate release source result differs: ' + row['path'])
    result = dict(status='CANDIDATE_SOURCE_PATCH_APPLIED_NOT_COMPILED', release='1.1.1', candidate='c33r',
                  files=len(lock['files']), engine_sha256=lock['engine_sha256'], patch=lock['patch_identity'],
                  release_acceptance=False, loader_acceptance='SEPARATE')
    with (out / 'release111-source.json').open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    return result
