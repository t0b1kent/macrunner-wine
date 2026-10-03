/* Unix-side atomic publisher for the default-off guest-PEB observer. */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "unixlib.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

_Static_assert( sizeof(struct macrunner_guest_peb_record) == 40, "guest PEB record ABI" );
_Static_assert( sizeof(struct macrunner_guest_peb_observer_params) == 144, "guest PEB observer ABI" );

#define OBSERVER_ENABLE "MACRUNNER_GUEST_PEB_OBSERVER_ENABLE"
#define OBSERVER_DIR "MACRUNNER_GUEST_PEB_OBSERVER_DIR"
#define OBSERVER_RUN_ID "MACRUNNER_GUEST_PEB_OBSERVER_RUN_ID"
#define OBSERVER_EXPECT_IMAGE "MACRUNNER_GUEST_PEB_OBSERVER_EXPECTED_IMAGE_SHA256"
#define OBSERVER_EXPECT_VIEW "MACRUNNER_GUEST_PEB_OBSERVER_EXPECTED_VIEW"
#define OBSERVER_EXPECT_WINE "MACRUNNER_GUEST_PEB_OBSERVER_EXPECTED_WINE_SHA256"

static BOOL safe_run_id( const char *value )
{
    size_t i, len;

    if (!value || !(len = strlen(value)) || len > 64) return FALSE;
    for (i = 0; i < len; i++)
        if (!((value[i] >= 'a' && value[i] <= 'z') ||
              (value[i] >= 'A' && value[i] <= 'Z') ||
              (value[i] >= '0' && value[i] <= '9') || value[i] == '-' || value[i] == '_'))
            return FALSE;
    return TRUE;
}

static BOOL lowercase_sha256( const char *value )
{
    size_t i;

    if (!value || strlen(value) != 64) return FALSE;
    for (i = 0; i < 64; i++)
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')))
            return FALSE;
    return TRUE;
}

static void digest_hex( const uint8_t digest[32], char hex[65] )
{
    static const char digits[] = "0123456789abcdef";
    unsigned int i;

    for (i = 0; i < 32; i++)
    {
        hex[i * 2] = digits[digest[i] >> 4];
        hex[i * 2 + 1] = digits[digest[i] & 15];
    }
    hex[64] = 0;
}

static void publish_collision_marker( const char *path )
{
    int fd = open( path, O_WRONLY | O_CREAT | O_EXCL, 0400 );

    if (fd >= 0)
    {
        static const char marker[] = "collision\n";
        (void)write( fd, marker, sizeof(marker) - 1 );
        (void)fsync( fd );
        close( fd );
    }
}

static void fsync_parent( const char *directory )
{
    int flags = O_RDONLY;
    int fd;

#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
    if ((fd = open( directory, flags )) >= 0)
    {
        (void)fsync( fd );
        close( fd );
    }
}

NTSTATUS macrunner_guest_peb_observe( void *args )
{
    struct macrunner_guest_peb_observer_params *params = args;
    const struct macrunner_guest_peb_record *records;
    const char *enable = getenv( OBSERVER_ENABLE );
    const char *directory, *run_id, *expected_image, *expected_view, *expected_wine, *view;
    char final_path[PATH_MAX], temp_path[PATH_MAX], collision_path[PATH_MAX];
    char environment_hex[65], image_hex[65], ntdll_hex[65], record_hex[65];
    const char *state = "PRESENT", *reason = NULL;
    FILE *file = NULL;
    int fd = -1, result;
    uint32_t i;

    if (!params || params->abi_version != MACRUNNER_GUEST_PEB_OBSERVER_ABI_VERSION ||
        params->struct_size != sizeof(*params))
        return STATUS_INVALID_PARAMETER;
    if (params->flags == MACRUNNER_GUEST_PEB_OBSERVER_FLAG_PROBE)
    {
        params->flags = enable && !strcmp( enable, "1" ) ?
                        MACRUNNER_GUEST_PEB_OBSERVER_FLAG_ACTIVE : 0;
        return STATUS_SUCCESS;
    }
    if (!enable || strcmp( enable, "1" )) return STATUS_SUCCESS;
    directory = getenv( OBSERVER_DIR );
    run_id = getenv( OBSERVER_RUN_ID );
    expected_image = getenv( OBSERVER_EXPECT_IMAGE );
    expected_view = getenv( OBSERVER_EXPECT_VIEW );
    expected_wine = getenv( OBSERVER_EXPECT_WINE );
    if (!directory || directory[0] != '/' || !safe_run_id( run_id ) ||
        !lowercase_sha256( expected_image ) || !lowercase_sha256( expected_wine ) || !expected_view)
        return STATUS_INVALID_PARAMETER;
    if (params->flags != MACRUNNER_GUEST_PEB_OBSERVER_FLAG_COMPLETE ||
        params->environment_size > MACRUNNER_GUEST_PEB_OBSERVER_MAX_BYTES ||
        params->record_count > MACRUNNER_GUEST_PEB_OBSERVER_MAX_RECORDS ||
        (params->record_count && !params->records) ||
        params->records + (uint64_t)params->record_count * sizeof(*records) < params->records)
        return STATUS_INVALID_PARAMETER;

    if (params->view == MACRUNNER_GUEST_PEB_VIEW_NATIVE &&
        (params->pointer_bits == 32 || params->pointer_bits == 64))
        view = "native";
    else if (params->view == MACRUNNER_GUEST_PEB_VIEW_WOW64 && params->pointer_bits == 32)
        view = "wow64";
    else
        return STATUS_INVALID_PARAMETER;
    records = (const struct macrunner_guest_peb_record *)(uintptr_t)params->records;
    for (i = 0; i < params->record_count; i++)
        if (records[i].ordinal != (uint32_t)i || !records[i].utf16_code_units ||
            records[i].utf16_code_units > MACRUNNER_GUEST_PEB_OBSERVER_MAX_BYTES / 2)
            return STATUS_INVALID_PARAMETER;

    digest_hex( params->environment_sha256, environment_hex );
    digest_hex( params->image_path_sha256, image_hex );
    digest_hex( params->ntdll_identity_sha256, ntdll_hex );
    if (strcmp( expected_view, view ))
    {
        state = "UNKNOWN";
        reason = "wrong_view";
    }
    else if (strcmp( expected_image, image_hex ))
    {
        state = "UNKNOWN";
        reason = "ambiguous_main";
    }

    result = snprintf( final_path, sizeof(final_path), "%s/%s.guest-peb.%llu.%s.json",
                       directory, run_id, (unsigned long long)params->process_id, view );
    if (result < 0 || (size_t)result >= sizeof(final_path)) return STATUS_NAME_TOO_LONG;
    result = snprintf( temp_path, sizeof(temp_path), "%s/.%s.guest-peb.%llu.%s.tmp",
                       directory, run_id, (unsigned long long)params->process_id, view );
    if (result < 0 || (size_t)result >= sizeof(temp_path)) return STATUS_NAME_TOO_LONG;
    result = snprintf( collision_path, sizeof(collision_path), "%s.collision", final_path );
    if (result < 0 || (size_t)result >= sizeof(collision_path)) return STATUS_NAME_TOO_LONG;

    if ((fd = open( temp_path, O_WRONLY | O_CREAT | O_EXCL, 0600 )) < 0)
    {
        if (errno == EEXIST) publish_collision_marker( collision_path );
        return errno == EEXIST ? STATUS_OBJECT_NAME_COLLISION : STATUS_UNSUCCESSFUL;
    }
    if (!(file = fdopen( fd, "w" )))
    {
        close( fd );
        unlink( temp_path );
        return STATUS_UNSUCCESSFUL;
    }
    fd = -1;

    if (fprintf( file,
                 "{\"schema\":\"macrunner-guest-peb-observer/v1\","
                 "\"state\":\"%s\",\"complete\":true,"
                 "\"hook\":\"loader_init/pre-fixup-imports/v1\","
                 "\"abi_version\":%u,\"process_id\":%llu,"
                 "\"view\":\"%s\",\"pointer_bits\":%u,"
                 "\"environment_size\":%llu,\"record_count\":%u,"
                 "\"environment_sha256\":\"%s\","
                 "\"image_path_sha256\":\"%s\","
                 "\"ntdll_identity_sha256\":\"%s\","
                 "\"wine_sha256\":\"%s\"",
                 state, params->abi_version, (unsigned long long)params->process_id,
                 view, params->pointer_bits, (unsigned long long)params->environment_size,
                 params->record_count, environment_hex, image_hex, ntdll_hex, expected_wine ) < 0)
        goto write_failed;
    if (reason)
    {
        if (fprintf( file, ",\"reason\":\"%s\",\"records\":[]", reason ) < 0)
            goto write_failed;
    }
    else
    {
        if (fputs( ",\"records\":[", file ) == EOF) goto write_failed;
        for (i = 0; i < params->record_count; i++)
        {
            digest_hex( records[i].sha256, record_hex );
            if (fprintf( file, "%s{\"ordinal\":%u,\"utf16_code_units\":%u,\"sha256\":\"%s\"}",
                         i ? "," : "", records[i].ordinal,
                         records[i].utf16_code_units, record_hex ) < 0)
                goto write_failed;
        }
        if (fputc( ']', file ) == EOF) goto write_failed;
    }
    if (fputs( "}\n", file ) == EOF || fflush( file ) || fsync( fileno(file) ) ||
        fchmod( fileno(file), 0400 ) || fsync( fileno(file) ))
        goto write_failed;
    if (fclose( file ))
    {
        file = NULL;
        goto unlink_failed;
    }
    file = NULL;

    if (link( temp_path, final_path ))
    {
        int link_error = errno;

        if (link_error == EEXIST) publish_collision_marker( collision_path );
        unlink( temp_path );
        fsync_parent( directory );
        return link_error == EEXIST ? STATUS_OBJECT_NAME_COLLISION : STATUS_UNSUCCESSFUL;
    }
    unlink( temp_path );
    fsync_parent( directory );
    return reason ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;

write_failed:
    fclose( file );
    file = NULL;
unlink_failed:
    unlink( temp_path );
    return STATUS_UNSUCCESSFUL;
}
