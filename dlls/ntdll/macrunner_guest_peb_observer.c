/*
 * Default-off, one-shot initial guest-PEB environment observer.
 *
 * The PE side performs the bounded scan so the evidence is produced by the
 * executing ntdll view.  Only fixed-width hashes, lengths, and ordinals cross
 * to Unix for publication; observation failures are deliberately ignored by
 * the loader call site.
 */

#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "rtlsupportapi.h"
#include "tomcrypt.h"

#include "ntdll_misc.h"
#include "unixlib.h"

C_ASSERT( sizeof(struct macrunner_guest_peb_record) == 40 );
C_ASSERT( sizeof(struct macrunner_guest_peb_observer_params) == 144 );

static LONG observer_started;

static BOOL readable_range( const void *address, SIZE_T size )
{
    const BYTE *cursor = address;
    const BYTE *end;

    if (!address || !size || (ULONG_PTR)address + size < (ULONG_PTR)address) return FALSE;
    end = cursor + size;
    while (cursor < end)
    {
        MEMORY_BASIC_INFORMATION info;
        const BYTE *region_end;
        ULONG protection;

        if (NtQueryVirtualMemory( NtCurrentProcess(), (void *)cursor, MemoryBasicInformation,
                                  &info, sizeof(info), NULL ))
            return FALSE;
        if (info.State != MEM_COMMIT || !info.RegionSize) return FALSE;
        protection = info.Protect & 0xff;
        if ((info.Protect & PAGE_GUARD) ||
            (protection != PAGE_READONLY && protection != PAGE_READWRITE &&
             protection != PAGE_WRITECOPY && protection != PAGE_EXECUTE_READ &&
             protection != PAGE_EXECUTE_READWRITE && protection != PAGE_EXECUTE_WRITECOPY))
            return FALSE;
        if ((ULONG_PTR)info.BaseAddress + info.RegionSize < (ULONG_PTR)info.BaseAddress) return FALSE;
        region_end = (const BYTE *)info.BaseAddress + info.RegionSize;
        if (region_end <= cursor) return FALSE;
        cursor = region_end < end ? region_end : end;
    }
    return TRUE;
}

static void sha256_buffer( const void *buffer, SIZE_T size, uint8_t digest[32] )
{
    hash_state state;

    sha256_init( &state );
    sha256_process( &state, buffer, size );
    sha256_done( &state, digest );
}

static BOOL observer_control_name( const WCHAR *record, SIZE_T units )
{
    static const WCHAR control_enable[] =
    {
        'M','A','C','R','U','N','N','E','R','_',
        'G','U','E','S','T','_','P','E','B','_',
        'O','B','S','E','R','V','E','R','_',
        'E','N','A','B','L','E',0
    };
    static const WCHAR control_dir[] =
    {
        'M','A','C','R','U','N','N','E','R','_',
        'G','U','E','S','T','_','P','E','B','_',
        'O','B','S','E','R','V','E','R','_',
        'D','I','R',0
    };
    static const WCHAR control_run_id[] =
    {
        'M','A','C','R','U','N','N','E','R','_',
        'G','U','E','S','T','_','P','E','B','_',
        'O','B','S','E','R','V','E','R','_',
        'R','U','N','_','I','D',0
    };
    static const WCHAR control_expected_image_sha256[] =
    {
        'M','A','C','R','U','N','N','E','R','_',
        'G','U','E','S','T','_','P','E','B','_',
        'O','B','S','E','R','V','E','R','_',
        'E','X','P','E','C','T','E','D','_','I','M','A','G','E','_',
        'S','H','A','2','5','6',0
    };
    static const WCHAR control_expected_view[] =
    {
        'M','A','C','R','U','N','N','E','R','_',
        'G','U','E','S','T','_','P','E','B','_',
        'O','B','S','E','R','V','E','R','_',
        'E','X','P','E','C','T','E','D','_','V','I','E','W',0
    };
    static const WCHAR control_expected_wine_sha256[] =
    {
        'M','A','C','R','U','N','N','E','R','_',
        'G','U','E','S','T','_','P','E','B','_',
        'O','B','S','E','R','V','E','R','_',
        'E','X','P','E','C','T','E','D','_','W','I','N','E','_',
        'S','H','A','2','5','6',0
    };
    static const struct
    {
        const WCHAR *name;
        SIZE_T units;
    } controls[] =
    {
        {control_enable, ARRAY_SIZE( control_enable ) - 1},
        {control_dir, ARRAY_SIZE( control_dir ) - 1},
        {control_run_id, ARRAY_SIZE( control_run_id ) - 1},
        {control_expected_image_sha256, ARRAY_SIZE( control_expected_image_sha256 ) - 1},
        {control_expected_view, ARRAY_SIZE( control_expected_view ) - 1},
        {control_expected_wine_sha256, ARRAY_SIZE( control_expected_wine_sha256 ) - 1},
    };
    SIZE_T name_units = 0, i, j;

    if (!units || record[0] == '=') return FALSE;
    while (name_units < units && record[name_units] != '=') name_units++;
    if (name_units == units) return FALSE;
    for (i = 0; i < ARRAY_SIZE(controls); i++)
    {
        SIZE_T control_units = controls[i].units;

        if (name_units != control_units) continue;
        for (j = 0; j < name_units; j++)
        {
            WCHAR left = record[j], right = controls[i].name[j];
            if (left >= 'a' && left <= 'z') left -= 'a' - 'A';
            if (left != right) break;
        }
        if (j == name_units) return TRUE;
    }
    return FALSE;
}

static BOOL scan_environment( const WCHAR *environment, SIZE_T size,
                              struct macrunner_guest_peb_record *records,
                              uint32_t *record_count, uint8_t digest[32] )
{
    SIZE_T units, position = 0;
    uint32_t count = 0;

    if (size < 2 * sizeof(WCHAR) || size > MACRUNNER_GUEST_PEB_OBSERVER_MAX_BYTES ||
        size % sizeof(WCHAR) || !readable_range( environment, size ))
        return FALSE;
    units = size / sizeof(WCHAR);
    if (environment[units - 1] || environment[units - 2]) return FALSE;
    if (units == 2)
    {
        *record_count = 0;
        sha256_buffer( environment, size, digest );
        return TRUE;
    }

    while (position < units)
    {
        SIZE_T start = position;

        while (position < units && environment[position]) position++;
        if (position == start || position >= units || count >= MACRUNNER_GUEST_PEB_OBSERVER_MAX_RECORDS)
            return FALSE;
        if (observer_control_name( environment + start, position - start )) return FALSE;
        records[count].ordinal = count;
        records[count].utf16_code_units = position - start;
        sha256_buffer( environment + start, (position - start) * sizeof(WCHAR), records[count].sha256 );
        count++;
        position++;
        if (position >= units) return FALSE;
        if (!environment[position])
        {
            if (position != units - 1) return FALSE;
            break;
        }
    }
    *record_count = count;
    sha256_buffer( environment, size, digest );
    return TRUE;
}

static BOOL ntdll_identity( uint8_t digest[32] )
{
    void *base = NULL;
    IMAGE_NT_HEADERS *nt;
    struct
    {
        uint16_t machine;
        uint16_t optional_magic;
        uint32_t timestamp;
        uint32_t image_size;
        uint32_t checksum;
    } identity = {0};

    if (!RtlPcToFileHeader( (void *)macrunner_observe_initial_guest_peb, &base ) || !base) return FALSE;
    if (!(nt = RtlImageNtHeader( base ))) return FALSE;
    identity.machine = nt->FileHeader.Machine;
    identity.optional_magic = nt->OptionalHeader.Magic;
    identity.timestamp = nt->FileHeader.TimeDateStamp;
    identity.image_size = nt->OptionalHeader.SizeOfImage;
    identity.checksum = nt->OptionalHeader.CheckSum;
    sha256_buffer( &identity, sizeof(identity), digest );
    return TRUE;
}

void macrunner_observe_initial_guest_peb(void)
{
    struct macrunner_guest_peb_observer_params params = {0};
    struct macrunner_guest_peb_record *records = NULL;
    const WCHAR *environment, *image_path;
    SIZE_T environment_size, image_path_size;
    PEB *peb = NtCurrentTeb()->Peb;

    if (InterlockedCompareExchange( &observer_started, 1, 0 )) return;
    if (!peb) return;

    params.abi_version = MACRUNNER_GUEST_PEB_OBSERVER_ABI_VERSION;
    params.struct_size = sizeof(params);
    params.flags = MACRUNNER_GUEST_PEB_OBSERVER_FLAG_PROBE;
    if (__wine_unix_call( __wine_unixlib_handle, unix_macrunner_guest_peb_observe, &params ) ||
        params.flags != MACRUNNER_GUEST_PEB_OBSERVER_FLAG_ACTIVE)
        return;
    params.flags = MACRUNNER_GUEST_PEB_OBSERVER_FLAG_COMPLETE;

#ifdef _WIN64
    if (NtCurrentTeb()->WowTebOffset)
    {
        PEB32 *wow_peb = (PEB32 *)((BYTE *)peb + page_size);
        RTL_USER_PROCESS_PARAMETERS32 *process_params;

        if (!readable_range( wow_peb, sizeof(*wow_peb) ) || !wow_peb->ProcessParameters) return;
        process_params = UlongToPtr( wow_peb->ProcessParameters );
        if (!readable_range( process_params, sizeof(*process_params) )) return;
        environment = UlongToPtr( process_params->Environment );
        environment_size = process_params->EnvironmentSize;
        image_path = UlongToPtr( process_params->ImagePathName.Buffer );
        image_path_size = process_params->ImagePathName.Length;
        params.view = MACRUNNER_GUEST_PEB_VIEW_WOW64;
        params.pointer_bits = 32;
    }
    else
#endif
    {
        RTL_USER_PROCESS_PARAMETERS *process_params = peb->ProcessParameters;

        if (!readable_range( process_params, sizeof(*process_params) )) return;
        environment = process_params->Environment;
        environment_size = process_params->EnvironmentSize;
        image_path = process_params->ImagePathName.Buffer;
        image_path_size = process_params->ImagePathName.Length;
        params.view = MACRUNNER_GUEST_PEB_VIEW_NATIVE;
        params.pointer_bits = sizeof(void *) * 8;
    }

    if (!image_path_size || image_path_size % sizeof(WCHAR) ||
        !readable_range( image_path, image_path_size ))
        return;
    if (!(records = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY,
                                     MACRUNNER_GUEST_PEB_OBSERVER_MAX_RECORDS * sizeof(*records) )))
        return;
    if (!scan_environment( environment, environment_size, records, &params.record_count,
                           params.environment_sha256 ))
        goto done;
    sha256_buffer( image_path, image_path_size, params.image_path_sha256 );
    if (!ntdll_identity( params.ntdll_identity_sha256 )) goto done;

    params.process_id = HandleToULong( NtCurrentTeb()->ClientId.UniqueProcess );
    params.environment_size = environment_size;
    params.records = (uint64_t)(ULONG_PTR)records;
    (void)__wine_unix_call( __wine_unixlib_handle, unix_macrunner_guest_peb_observe, &params );

done:
    RtlFreeHeap( GetProcessHeap(), 0, records );
}
