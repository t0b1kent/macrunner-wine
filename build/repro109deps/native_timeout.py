#!/usr/bin/env python3
"""Owned Darwin timeout for the audited GnuTLS duration/argv and --version calls."""
import math
import os
import signal
import subprocess
import sys

def run(duration, argv, grace=2):
    if not math.isfinite(duration) or not 0 < duration <= 3600 or not argv:
        raise ValueError('Bounded positive duration and command required')
    child = subprocess.Popen(argv, start_new_session=True)
    try:
        returncode = child.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=grace)
        return 124
    return returncode if returncode >= 0 else 128 - returncode

def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ['--version']:
        print('MacRunner native timeout 1; GnuTLS audited duration/argv subset')
        return 0
    try:
        return run(float(argv[0]), argv[1:])
    except (IndexError, ValueError):
        return 125
    except FileNotFoundError:
        return 127
    except PermissionError:
        return 126

if __name__ == '__main__':
    raise SystemExit(main())
