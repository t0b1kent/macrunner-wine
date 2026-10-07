/* LGPL-2.1-or-later. Native diagnostics must not acquire stderr's FILE lock:
 * NtSuspendThread may have stopped its current owner. */
#ifndef __PE32_AV_PROBE_OUTPUT_H
#define __PE32_AV_PROBE_OUTPUT_H

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void macrunner_hb_probe_output( const char *format, ... )
    __attribute__((format(printf, 1, 2)));

static void macrunner_hb_probe_output( const char *format, ... )
{
    char line[2048];
    va_list args;
    int length, saved_errno = errno;
    size_t offset = 0;

    /* Format into this call's private buffer, then write without shared FILE. */
    va_start( args, format );
    length = vsnprintf( line, sizeof(line), format, args );
    va_end( args );
    if (length < 0 || (size_t)length >= sizeof(line))
    {
        static const char dropped[] =
            "macrunner-hb-probe-output: state=DROPPED reason=record-too-long-or-format-error\n";
        memcpy( line, dropped, sizeof(dropped) - 1 );
        length = sizeof(dropped) - 1;
    }
    while (offset < (size_t)length)
    {
        ssize_t count = write( STDERR_FILENO, line + offset, length - offset );
        if (count > 0) offset += count;
        else if (count < 0 && errno == EINTR) continue;
        else break;
    }
    errno = saved_errno;
}

#endif
