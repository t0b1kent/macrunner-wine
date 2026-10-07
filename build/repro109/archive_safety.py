"""Validate the complete tar link graph before any archive member is written."""
from pathlib import PurePosixPath


def validate_tar(members):
    if len(members) > 200000 or sum(max(0, m.size) for m in members) > 2 * 1024**3:
        raise ValueError('Tar archive exceeds bounded member/expanded cap')
    entries = {}
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or len(member.name) > 4096:
            raise ValueError('Tar member escapes destination: ' + repr(member.name[:300]))
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()) or member.size < 0:
            raise ValueError('Tar special or negative-size member: ' + repr(member.name[:300]))
        key = path.parts
        if not key and not member.isdir():
            raise ValueError('Tar root member must be a directory')
        if key in entries:
            raise ValueError('Tar duplicate normalized member: ' + repr(member.name[:300]))
        entries[key] = member
    links = {key: m for key, m in entries.items() if m.issym() or m.islnk()}
    for key, member in entries.items():
        if any(key[:i] in links for i in range(1, len(key))):
            raise ValueError('Tar member traverses archive link: ' + repr(member.name[:300]))

    def resolve(key, owner):
        pending, resolved, visited = list(key), [], set()
        while pending:
            part = pending.pop(0)
            if part in ('', '.'):
                continue
            if part == '..':
                if not resolved:
                    raise ValueError('Tar link escapes destination: ' + repr(owner.name[:300]) +
                                     ' -> ' + repr(owner.linkname[:300]))
                resolved.pop()
                continue
            resolved.append(part)
            prefix = tuple(resolved)
            link = links.get(prefix)
            if link is None:
                continue
            if prefix in visited or len(visited) >= 40:
                raise ValueError('Tar link cycle/depth: ' + repr(owner.name[:300]) +
                                 ' via ' + repr(link.name[:300]))
            visited.add(prefix)
            target = PurePosixPath(link.linkname)
            if target.is_absolute() or not link.linkname or len(link.linkname) > 4096:
                raise ValueError('Tar absolute/empty link: ' + repr(link.name[:300]) +
                                 ' -> ' + repr(link.linkname[:300]))
            base = resolved[:-1] if link.issym() else []
            pending = base + list(target.parts) + pending
            resolved = []
        return tuple(resolved), len(visited)

    ledger = []
    for key, member in links.items():
        terminal, depth = resolve(key, member)
        target = entries.get(terminal)
        if member.islnk() and (target is None or not target.isfile()):
            raise ValueError('Tar hardlink lacks regular archive target: ' + repr(member.name[:300]))
        ledger.append(dict(member=member.name, kind='SYMLINK' if member.issym() else 'HARDLINK',
                           target=member.linkname, resolved='/'.join(terminal) or '.', hops=depth,
                           target_state='PRESENT' if target is not None else 'NOT_ENABLED'))
    return dict(state='PRESENT', members=len(members), links=len(links),
                expanded_bytes=sum(m.size for m in members), link_graph=ledger)
