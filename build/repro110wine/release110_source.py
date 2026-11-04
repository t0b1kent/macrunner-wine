"""Apply the pinned cumulative 1.1.0 c32r delta after the c12/keyboard inputs."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

def identity(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Regular source file required: ' + str(path))
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def inputs(recipe=HERE):
    recipe = Path(recipe)
    lock = json.loads((recipe / 'release110-source.lock.json').read_bytes())
    if lock['schema'] != 1 or lock['release'] != '1.1.0' or lock['patch'] != 'late/release110-c32r.patch':
        raise ValueError('Release source identity differs')
    if identity(recipe / lock['patch']) != lock['patch_identity']:
        raise ValueError('Release source patch bytes differ')
    names = [r['path'] for r in lock['files']]
    if not names or names != sorted(set(names)):
        raise ValueError('Release source path order or uniqueness differs')
    for name in names:
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or str(path) != name:
            raise ValueError('Unsafe release source path')
    return lock

def apply(source, out, command, recipe=HERE):
    source, out = Path(source), Path(out)
    lock = inputs(recipe)
    for row in lock['files']:
        path = source / row['path']
        if any(p.is_symlink() for p in [path, *path.parents] if p != source.parent):
            raise ValueError('Release source link refused: ' + row['path'])
        actual = identity(path) if path.exists() else None
        if actual != row['before']:
            raise ValueError('Release source base differs: ' + row['path'])
    patch = str((Path(recipe) / lock['patch']).resolve())
    command(['git', 'apply', '--check', patch], out / 'release110-source.log', cwd=source, timeout=30)
    command(['git', 'apply', patch], out / 'release110-source.log', cwd=source, timeout=30)
    for row in lock['files']:
        if identity(source / row['path']) != row['after']:
            raise ValueError('Release source result differs: ' + row['path'])
    result = dict(status='SOURCE_PATCH_APPLIED_NOT_COMPILED', release='1.1.0',
                  files=len(lock['files']), patch=lock['patch_identity'])
    with (out / 'release110-source.json').open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    return result
