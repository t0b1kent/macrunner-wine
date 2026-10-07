"""Native build inputs for the three measured b28 failures; no test waivers."""
from pathlib import Path
import hashlib
import shlex
import sys

def component_environment(row, env, prefix, here, out, event):
    result = dict(env)
    if row.get('gst_plugins'):
        # Plugins reside in prefix/lib/gstreamer-1.0; CMake deps use @rpath.
        result['LDFLAGS'] = result.get('LDFLAGS', '') + ' -Wl,-rpath,@loader_path/..'
    if row['name'] == 'gnutls':
        # gnutls-cli-debug.sh invokes literal `timeout`; TIMEOUT alone is insufficient.
        wrapper = Path(prefix) / 'bin/timeout'
        if wrapper.exists() or wrapper.is_symlink():
            raise ValueError('Fresh owned timeout destination required')
        wrapper.parent.mkdir(parents=True, exist_ok=True)
        helper = Path(here) / 'native_timeout.py'
        data = ('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' -B -I ' +
                shlex.quote(str(helper)) + ' "$@"\n').encode()
        wrapper.write_bytes(data)
        wrapper.chmod(0o755)
        result['TIMEOUT'] = str(wrapper)
        event(out, component='gnutls', state='OWNED_TIMEOUT_INPUT',
              wrapper_sha256=hashlib.sha256(data).hexdigest(),
              source_sha256=hashlib.sha256(helper.read_bytes()).hexdigest(),
              purpose='BUILD_TEST_TOOL_NOT_RUNTIME_PAYLOAD')
    return result
