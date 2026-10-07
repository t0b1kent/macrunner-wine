"""Read-only verification of the source-built libvpx Darwin install name."""
import hashlib


def validate_libvpx_install_name(text, actual):
    lines = text.splitlines()
    if lines != [str(actual) + ':', '@rpath/libvpx.12.dylib']:
        raise ValueError('libvpx LC_ID_DYLIB: expected @rpath/libvpx.12.dylib; actual raw evidence differs')
    return '@rpath/libvpx.12.dylib'


def libvpx_install_name_probe(prefix, env, out, deadline, command):
    library = prefix / 'lib/libvpx.12.dylib'
    alias = prefix / 'lib/libvpx.dylib'
    if (not library.is_file() or library.is_symlink() or not alias.is_file() or
            not library.resolve().is_relative_to(prefix.resolve()) or alias.resolve() != library.resolve()):
        raise ValueError('libvpx installed real library/alias census differs')
    if any(value for key, value in env.items() if key.startswith('DYLD_')):
        raise ValueError('libvpx identity validation refuses a DYLD override')
    log = out / 'libvpx-install-name.log'
    command(['/usr/bin/otool', '-D', str(library)], prefix, env, log, out,
            'libvpx', deadline, timeout=30)
    identity = validate_libvpx_install_name(log.read_text(), library)
    return dict(kind='DARWIN_LC_ID_DYLIB', library='lib/libvpx.12.dylib',
                identity=identity, evidence='PRESENT_BOUNDED', raw_path=log.name,
                raw_sha256=hashlib.sha256(log.read_bytes()).hexdigest())
