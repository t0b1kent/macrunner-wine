/*
 * NT threads support
 *
 * Copyright 1996, 2003 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "winternl.h"
#include "wine/debug.h"
#include "ntdll_misc.h"
#include "ddk/wdm.h"
#include "wine/exception.h"

WINE_DEFAULT_DEBUG_CHANNEL(thread);
WINE_DECLARE_DEBUG_CHANNEL(relay);
WINE_DECLARE_DEBUG_CHANNEL(pid);
WINE_DECLARE_DEBUG_CHANNEL(timestamp);

#if defined(__arm64ec__)
# define NTDLL_USER_SHARED_DATA_ADDRESS ((ULONG_PTR)0x000007FFE0000000ULL)
#else
# define NTDLL_USER_SHARED_DATA_ADDRESS WINE_USER_SHARED_DATA_ADDRESS
#endif

struct _KUSER_SHARED_DATA *user_shared_data = (void *)NTDLL_USER_SHARED_DATA_ADDRESS;

extern void macrunner_hb_exit_origin_probe_rtl_exit( ULONG status, const void *caller,
                                                      ULONG last );

static BOOL macrunner_trace_process_exit_enabled(void)
{
    static const WCHAR nameW[] =
        {'M','A','C','R','U','N','N','E','R','_',
         'T','R','A','C','E','_','P','R','O','C','E','S','S','_','E','X','I','T',0};
    WCHAR value[8];
    UNICODE_STRING name, val;

    RtlInitUnicodeString( &name, nameW );
    val.Buffer = value;
    val.Length = 0;
    val.MaximumLength = sizeof(value);
    return RtlQueryEnvironmentVariable_U( NULL, &name, &val ) == STATUS_SUCCESS &&
           value[0] && value[0] != '0';
}

struct debug_info
{
    unsigned int str_pos;       /* current position in strings buffer */
    unsigned int out_pos;       /* current position in output buffer */
    char         strings[1020]; /* buffer for temporary strings */
    char         output[1020];  /* current output line */
};

C_ASSERT( sizeof(struct debug_info) == 0x800 );

static int nb_debug_options;
static struct __wine_debug_channel *debug_options;

static inline struct debug_info *get_info(void)
{
#ifdef _WIN64
    return (struct debug_info *)((TEB32 *)((char *)NtCurrentTeb() + 0x2000) + 1);
#else
    return (struct debug_info *)(NtCurrentTeb() + 1);
#endif
}

static void init_options(void)
{
    unsigned int offset = page_size * (sizeof(void *) / 4);

    debug_options = (struct __wine_debug_channel *)((char *)NtCurrentTeb()->Peb + offset);
    while (debug_options[nb_debug_options].name[0]) nb_debug_options++;
    /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 257 — ЧТО НАСЧИТАЛА PE-СТОРОНА.
     * Печать из 32-битных модулей заработала в 256 (класс `err` включён по умолчанию), поэтому
     * впервые можно спросить саму сторону-потребителя: по какому адресу она взяла таблицу,
     * сколько каналов насчитала и какой первый. Рекурсии нет: `debug_options` уже присвоен, и
     * повторный заход в `__wine_dbg_get_channel_flags` в `init_options` не свалится. */
    MESSAGE( "macrunner-i386-dbgopts: peb=%p offset=%u options=%p nb=%d pervyj='%.15s' flags=%02x\n",
         NtCurrentTeb()->Peb, offset, debug_options, nb_debug_options,
         nb_debug_options ? debug_options[0].name : "(net)", debug_options[0].flags );
}

static int flush_output( struct debug_info *info, size_t len )
{
    int ret = __wine_dbg_write( info->output, len );

    if (ret > 0)
    {
        info->out_pos -= ret;
        memmove( info->output, info->output + ret, info->out_pos );
    }
    return ret == len ? 0 : -1;
}

/* Write long strings directly, retaining a byte to mark partial lines. */
static int append_output( struct debug_info *info, const char *str, size_t len )
{
    size_t total = len, count;
    int ret;

    if (len >= sizeof(info->output) - info->out_pos)
    {
        if (flush_output( info, info->out_pos ) < 0) return -1;
        if (len >= sizeof(info->output))
        {
            ret = __wine_dbg_write( str, len - 1 );
            if (ret != len - 1)
            {
                if (ret < 0) ret = 0;
                count = min( len - ret, sizeof(info->output) );
                memcpy( info->output, str + ret, count );
                info->out_pos = count;
                return -1;
            }
            str += len - 1;
            len = 1;
        }
    }
    memcpy( info->output + info->out_pos, str, len );
    info->out_pos += len;
    return total;
}

/***********************************************************************
 *		__wine_dbg_get_channel_flags  (NTDLL.@)
 *
 * Get the flags to use for a given channel, possibly setting them too in case of lazy init
 */
unsigned char __cdecl __wine_dbg_get_channel_flags( struct __wine_debug_channel *channel )
{
    int min, max, pos, res;
    unsigned char flags;

    if (!(channel->flags & (1 << __WINE_DBCL_INIT))) return channel->flags;

    if (!debug_options) init_options();

    flags = debug_options[nb_debug_options].flags;
    min = 0;
    max = nb_debug_options - 1;
    while (min <= max)
    {
        pos = (min + max) / 2;
        res = strcmp( channel->name, debug_options[pos].name );
        if (!res)
        {
            flags = debug_options[pos].flags;
            break;
        }
        if (res < 0) max = pos - 1;
        else min = pos + 1;
    }

    if (!(flags & (1 << __WINE_DBCL_INIT))) channel->flags = flags; /* not dynamically changeable */
    return flags;
}

/***********************************************************************
 *		__wine_dbg_strdup  (NTDLL.@)
 */
const char * __cdecl __wine_dbg_strdup( const char *str )
{
    struct debug_info *info = get_info();
    unsigned int pos = info->str_pos;
    size_t n = strlen( str ) + 1;

    assert( n <= sizeof(info->strings) );
    if (pos + n > sizeof(info->strings)) pos = 0;
    info->str_pos = pos + n;
    return memcpy( info->strings + pos, str, n );
}

/***********************************************************************
 *		__wine_dbg_header  (NTDLL.@)
 */
int __cdecl __wine_dbg_header( enum __wine_debug_class cls, struct __wine_debug_channel *channel,
                               const char *function )
{
    static const char * const classes[] = { "fixme", "err", "warn", "trace" };
    struct debug_info *info = get_info();
    char prefix[80];
    int ret = 0, len;

    if (!(__wine_dbg_get_channel_flags( channel ) & (1 << cls))) return -1;

    /* only print header if we are at the beginning of the line */
    if (info->out_pos) return 0;

    if (TRACE_ON(timestamp))
    {
        ULONG ticks = NtGetTickCount();
        len = snprintf( prefix, sizeof(prefix), "%3lu.%03lu:", ticks / 1000, ticks % 1000 );
        if (append_output( info, prefix, len ) < 0) return -1;
        ret += len;
    }
    if (TRACE_ON(pid))
    {
        len = snprintf( prefix, sizeof(prefix), "%04lx:", GetCurrentProcessId() );
        if (append_output( info, prefix, len ) < 0) return -1;
        ret += len;
    }
    len = snprintf( prefix, sizeof(prefix), "%04lx:", GetCurrentThreadId() );
    if (append_output( info, prefix, len ) < 0) return -1;
    ret += len;
    if (function && cls < ARRAY_SIZE( classes ))
    {
        len = snprintf( prefix, sizeof(prefix), "%s:%.15s:", classes[cls], channel->name );
        if (append_output( info, prefix, len ) < 0 ||
            append_output( info, function, strlen(function) ) < 0 ||
            append_output( info, " ", 1 ) < 0) return -1;
        ret += len + strlen(function) + 1;
    }
    return ret;
}

/***********************************************************************
 *		__wine_dbg_write  (NTDLL.@)
 */
int WINAPI __wine_dbg_write( const char *str, unsigned int len )
{
    struct wine_dbg_write_params params = { str, len };

    return WINE_UNIX_CALL( unix_wine_dbg_write, &params );
}

/***********************************************************************
 *		__wine_dbg_output  (NTDLL.@)
 */
int __cdecl __wine_dbg_output( const char *str )
{
    struct debug_info *info = get_info();
    const char *end = strrchr( str, '\n' );
    int ret = 0;

    if (end)
    {
        if ((ret = append_output( info, str, end + 1 - str )) < 0) return -1;
        if (flush_output( info, info->out_pos ) < 0) return -1;
        str = end + 1;
    }
    if (*str)
    {
        int tail = append_output( info, str, strlen( str ));
        if (tail < 0) return -1;
        ret += tail;
    }
    return ret;
}


/***********************************************************************
 *           set_native_thread_name
 */
void set_native_thread_name( DWORD tid, const char *name )
{
    THREAD_NAME_INFORMATION info;
    HANDLE h = GetCurrentThread();
    WCHAR nameW[64];

    if (tid != -1)
    {
        OBJECT_ATTRIBUTES attr = { .Length = sizeof(attr) };
        CLIENT_ID cid;

        cid.UniqueProcess = 0;
        cid.UniqueThread = ULongToHandle( tid );

        if (NtOpenThread( &h, THREAD_QUERY_LIMITED_INFORMATION, &attr, &cid )) return;
    }

    if (name)
    {
        mbstowcs( nameW, name, ARRAY_SIZE(nameW) );
        nameW[ARRAY_SIZE(nameW) - 1] = '\0';
    }
    else
    {
        nameW[0] = '\0';
    }

    RtlInitUnicodeString( &info.ThreadName, nameW );
    NtSetInformationThread( h, ThreadWineNativeThreadName, &info, sizeof(info) );

    if (h != GetCurrentThread())
        NtClose(h);
}


/***********************************************************************
 *           RtlExitUserThread  (NTDLL.@)
 */
void WINAPI RtlExitUserThread( ULONG status )
{
    const void *caller = __builtin_extract_return_addr( __builtin_return_address( 0 ) );
    ULONG last;

    NtQueryInformationThread( GetCurrentThread(), ThreadAmILastThread, &last, sizeof(last), NULL );
    macrunner_hb_exit_origin_probe_rtl_exit( status, caller, last );
    if (macrunner_trace_process_exit_enabled())
    {
        RTL_USER_PROCESS_PARAMETERS *params = NtCurrentTeb()->Peb->ProcessParameters;

        MESSAGE( "macrunner-rtl-thread-exit: pid=%lu tid=%lu status=0x%lx last=%lu image=%s cmd=%s\n",
                 GetCurrentProcessId(), GetCurrentThreadId(), status, last,
                 params ? debugstr_us( &params->ImagePathName ) : "(null)",
                 params ? debugstr_us( &params->CommandLine ) : "(null)" );
    }
    if (last) RtlExitUserProcess( status );
    LdrShutdownThread();
    for (;;) NtTerminateThread( GetCurrentThread(), status );
}


/***********************************************************************
 *              RtlCreateUserThread   (NTDLL.@)
 */
NTSTATUS WINAPI RtlCreateUserThread( HANDLE process, SECURITY_DESCRIPTOR *descr,
                                     BOOLEAN suspended, ULONG zero_bits,
                                     SIZE_T stack_reserve, SIZE_T stack_commit,
                                     PRTL_THREAD_START_ROUTINE start, void *param,
                                     HANDLE *handle_ptr, CLIENT_ID *id )
{
    ULONG flags = suspended ? THREAD_CREATE_FLAGS_CREATE_SUSPENDED : 0;
    ULONG_PTR buffer[offsetof( PS_ATTRIBUTE_LIST, Attributes[2] ) / sizeof(ULONG_PTR)];
    PS_ATTRIBUTE_LIST *attr_list = (PS_ATTRIBUTE_LIST *)buffer;
    struct _ACTIVATION_CONTEXT *actctx;
    HANDLE handle;
    TEB *teb;
    ULONG ret;
    NTSTATUS status;
    CLIENT_ID client_id;
    OBJECT_ATTRIBUTES attr;

    attr_list->TotalLength = sizeof(buffer);
    attr_list->Attributes[0].Attribute    = PS_ATTRIBUTE_CLIENT_ID;
    attr_list->Attributes[0].Size         = sizeof(client_id);
    attr_list->Attributes[0].ValuePtr     = &client_id;
    attr_list->Attributes[0].ReturnLength = NULL;
    attr_list->Attributes[1].Attribute    = PS_ATTRIBUTE_TEB_ADDRESS;
    attr_list->Attributes[1].Size         = sizeof(teb);
    attr_list->Attributes[1].ValuePtr     = &teb;
    attr_list->Attributes[1].ReturnLength = NULL;

    InitializeObjectAttributes( &attr, NULL, 0, NULL, descr );

    RtlGetActiveActivationContext( &actctx );
    if (actctx) flags |= THREAD_CREATE_FLAGS_CREATE_SUSPENDED;

    status = NtCreateThreadEx( &handle, THREAD_ALL_ACCESS, &attr, process, start, param,
                               flags, zero_bits, stack_commit, stack_reserve, attr_list );
    if (!status)
    {
        if (actctx)
        {
            ULONG_PTR cookie;
            RtlActivateActivationContextEx( 0, teb, actctx, &cookie );
            if (!suspended) NtResumeThread( handle, &ret );
        }
        if (id) *id = client_id;
        if (handle_ptr) *handle_ptr = handle;
        else NtClose( handle );
    }
    if (actctx) RtlReleaseActivationContext( actctx );
    return status;
}


/**********************************************************************
 *           RtlCreateUserStack (NTDLL.@)
 */
NTSTATUS WINAPI RtlCreateUserStack( SIZE_T commit, SIZE_T reserve, ULONG zero_bits,
                                    SIZE_T commit_align, SIZE_T reserve_align, INITIAL_TEB *stack )
{
    PROCESS_STACK_ALLOCATION_INFORMATION alloc;
    NTSTATUS status;

    TRACE("commit %#Ix, reserve %#Ix, zero_bits %lu, commit_align %#Ix, reserve_align %#Ix, stack %p\n",
            commit, reserve, zero_bits, commit_align, reserve_align, stack);

    if (!commit_align || !reserve_align)
        return STATUS_INVALID_PARAMETER;

    if (!commit || !reserve)
    {
        IMAGE_NT_HEADERS *nt = RtlImageNtHeader( NtCurrentTeb()->Peb->ImageBaseAddress );
        if (!reserve) reserve = nt->OptionalHeader.SizeOfStackReserve;
        if (!commit) commit = nt->OptionalHeader.SizeOfStackCommit;
    }

    reserve = (reserve + reserve_align - 1) & ~(reserve_align - 1);
    commit = (commit + commit_align - 1) & ~(commit_align - 1);

    if (reserve < commit) reserve = commit;
    if (reserve < 0x100000) reserve = 0x100000;
    reserve = (reserve + 0xffff) & ~0xffff;  /* round to 64K boundary */

    alloc.ReserveSize = reserve;
    alloc.ZeroBits = zero_bits;
    status = NtSetInformationProcess( GetCurrentProcess(), ProcessThreadStackAllocation,
                                      &alloc, sizeof(alloc) );
    if (!status)
    {
        void *addr;
        SIZE_T size = page_size;

        addr = (char *)alloc.StackBase + page_size;
        NtAllocateVirtualMemory( GetCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD );
        addr = (char *)alloc.StackBase + 2 * page_size;
        size = reserve - 2 * page_size;
        NtAllocateVirtualMemory( GetCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE );

        /* note: limit is lower than base since the stack grows down */
        stack->OldStackBase = 0;
        stack->OldStackLimit = 0;
        stack->DeallocationStack = alloc.StackBase;
        stack->StackBase = (char *)alloc.StackBase + reserve;
        stack->StackLimit = (char *)alloc.StackBase + 2 * page_size;
    }
    return status;
}


/**********************************************************************
 *           RtlFreeUserStack (NTDLL.@)
 */
void WINAPI RtlFreeUserStack( void *stack )
{
    SIZE_T size = 0;

    TRACE("stack %p\n", stack);

    NtFreeVirtualMemory( NtCurrentProcess(), &stack, &size, MEM_RELEASE );
}


/******************************************************************************
 *              RtlGetNtGlobalFlags   (NTDLL.@)
 */
ULONG WINAPI RtlGetNtGlobalFlags(void)
{
    return NtCurrentTeb()->Peb->NtGlobalFlag;
}


/******************************************************************************
 *              RtlPushFrame  (NTDLL.@)
 */
void WINAPI RtlPushFrame( TEB_ACTIVE_FRAME *frame )
{
    frame->Previous = NtCurrentTeb()->ActiveFrame;
    NtCurrentTeb()->ActiveFrame = frame;
}


/******************************************************************************
 *              RtlPopFrame  (NTDLL.@)
 */
void WINAPI RtlPopFrame( TEB_ACTIVE_FRAME *frame )
{
    NtCurrentTeb()->ActiveFrame = frame->Previous;
}


/******************************************************************************
 *              RtlGetFrame  (NTDLL.@)
 */
TEB_ACTIVE_FRAME * WINAPI RtlGetFrame(void)
{
    return NtCurrentTeb()->ActiveFrame;
}


/******************************************************************************
 *              RtlIsCurrentThread  (NTDLL.@)
 */
BOOLEAN WINAPI RtlIsCurrentThread( HANDLE handle )
{
    return handle == NtCurrentThread() || !NtCompareObjects( handle, NtCurrentThread() );
}


/***********************************************************************
 *              RtlSetThreadErrorMode  (NTDLL.@)
 */
NTSTATUS WINAPI RtlSetThreadErrorMode( DWORD mode, LPDWORD oldmode )
{
    if (mode & ~0x70)
        return STATUS_INVALID_PARAMETER_1;

    if (oldmode)
        *oldmode = NtCurrentTeb()->HardErrorMode;

    NtCurrentTeb()->HardErrorMode = mode;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              RtlGetThreadErrorMode  (NTDLL.@)
 */
DWORD WINAPI RtlGetThreadErrorMode( void )
{
    return NtCurrentTeb()->HardErrorMode;
}


/***********************************************************************
 *           _errno  (NTDLL.@)
 */
int * CDECL _errno(void)
{
    return (int *)&NtCurrentTeb()->TlsSlots[NTDLL_TLS_ERRNO];
}


/***********************************************************************
 * Fibers
 ***********************************************************************/


static GLOBAL_FLS_DATA fls_data = { { NULL }, { &fls_data.fls_list_head, &fls_data.fls_list_head } };

static RTL_CRITICAL_SECTION fls_section;
static RTL_CRITICAL_SECTION_DEBUG fls_critsect_debug =
{
    0, 0, &fls_section,
    { &fls_critsect_debug.ProcessLocksList, &fls_critsect_debug.ProcessLocksList },
            0, 0, { (DWORD_PTR)(__FILE__ ": fls_section") }
};
static RTL_CRITICAL_SECTION fls_section = { &fls_critsect_debug, -1, 0, 0, 0, 0 };

#define MAX_FLS_DATA_COUNT 0xff0

static BOOL macrunner_trace_fls_enabled(void)
{
    return FALSE;
}

static void macrunner_trace_fls_chunks( const char *phase, ULONG a, ULONG b )
{
    if (!macrunner_trace_fls_enabled()) return;
    (void)phase;
    (void)a;
    (void)b;
}

static void lock_fls_data(void)
{
    RtlEnterCriticalSection( &fls_section );
}

static void unlock_fls_data(void)
{
    RtlLeaveCriticalSection( &fls_section );
}

static unsigned int fls_chunk_size( unsigned int chunk_index )
{
    return 0x10 << chunk_index;
}

static unsigned int fls_index_from_chunk_index( unsigned int chunk_index, unsigned int index )
{
    return 0x10 * ((1 << chunk_index) - 1) + index;
}

static unsigned int fls_chunk_index_from_index( unsigned int index, unsigned int *index_in_chunk )
{
    unsigned int chunk_index = 0;

    while (index >= fls_chunk_size( chunk_index ))
        index -= fls_chunk_size( chunk_index++ );

    *index_in_chunk = index;
    return chunk_index;
}

TEB_FLS_DATA *fls_alloc_data(void)
{
    TEB_FLS_DATA *fls;

    if (!(fls = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*fls) )))
        return NULL;

    lock_fls_data();
    InsertTailList( &fls_data.fls_list_head, &fls->fls_list_entry );
    unlock_fls_data();

    return fls;
}


/***********************************************************************
 *              RtlFlsAlloc  (NTDLL.@)
 */
NTSTATUS WINAPI DECLSPEC_HOTPATCH RtlFlsAlloc( PFLS_CALLBACK_FUNCTION callback, ULONG *ret_index )
{
    unsigned int chunk_index, index, i;
    FLS_INFO_CHUNK *chunk;

    macrunner_trace_fls_chunks( "alloc-entry", 0, 0 );

    if (!NtCurrentTeb()->FlsSlots && !(NtCurrentTeb()->FlsSlots = fls_alloc_data()))
        return STATUS_NO_MEMORY;

    lock_fls_data();
    for (i = 0; i < ARRAY_SIZE(fls_data.fls_callback_chunks); ++i)
    {
        if (!fls_data.fls_callback_chunks[i] || fls_data.fls_callback_chunks[i]->count < fls_chunk_size( i ))
            break;
    }

    if ((chunk_index = i) == ARRAY_SIZE(fls_data.fls_callback_chunks))
    {
        unlock_fls_data();
        return STATUS_NO_MEMORY;
    }

    if ((chunk = fls_data.fls_callback_chunks[chunk_index]))
    {
        for (index = 0; index < fls_chunk_size( chunk_index ); ++index)
            if (!chunk->callbacks[index].callback)
                break;
        assert( index < fls_chunk_size( chunk_index ));
    }
    else
    {
        fls_data.fls_callback_chunks[chunk_index] = chunk = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY,
                offsetof(FLS_INFO_CHUNK, callbacks) + sizeof(*chunk->callbacks) * fls_chunk_size( chunk_index ));
        if (!chunk)
        {
            unlock_fls_data();
            return STATUS_NO_MEMORY;
        }

        if (chunk_index)
        {
            index = 0;
        }
        else
        {
            chunk->count = 1; /* FLS index 0 is prohibited. */
            chunk->callbacks[0].callback = (void *)~(ULONG_PTR)0;
            index = 1;
        }
    }

    ++chunk->count;
    chunk->callbacks[index].callback = callback ? callback : (PFLS_CALLBACK_FUNCTION)~(ULONG_PTR)0;

    if ((*ret_index = fls_index_from_chunk_index( chunk_index, index )) > fls_data.fls_high_index)
        fls_data.fls_high_index = *ret_index;

    macrunner_trace_fls_chunks( "alloc-exit", *ret_index, (ULONG)(ULONG_PTR)chunk );

    unlock_fls_data();

    return STATUS_SUCCESS;
}


/***********************************************************************
 *              RtlFlsFree   (NTDLL.@)
 */
NTSTATUS WINAPI DECLSPEC_HOTPATCH RtlFlsFree( ULONG index )
{
    PFLS_CALLBACK_FUNCTION callback;
    unsigned int chunk_index, idx;
    FLS_INFO_CHUNK *chunk;
    LIST_ENTRY *entry;

    lock_fls_data();

    if (!index || index > fls_data.fls_high_index)
    {
        unlock_fls_data();
        return STATUS_INVALID_PARAMETER;
    }

    chunk_index = fls_chunk_index_from_index( index, &idx );
    if (!(chunk = fls_data.fls_callback_chunks[chunk_index])
            || !(callback = chunk->callbacks[idx].callback))
    {
        unlock_fls_data();
        return STATUS_INVALID_PARAMETER;
    }

    for (entry = fls_data.fls_list_head.Flink; entry != &fls_data.fls_list_head; entry = entry->Flink)
    {
        TEB_FLS_DATA *fls = CONTAINING_RECORD(entry, TEB_FLS_DATA, fls_list_entry);

        if (fls->fls_data_chunks[chunk_index] && fls->fls_data_chunks[chunk_index][idx + 1])
        {
            if (callback != (void *)~(ULONG_PTR)0)
            {
                TRACE_(relay)("Calling FLS callback %p, arg %p.\n", callback,
                        fls->fls_data_chunks[chunk_index][idx + 1]);

                callback( fls->fls_data_chunks[chunk_index][idx + 1] );
            }
            fls->fls_data_chunks[chunk_index][idx + 1] = NULL;
        }
    }

    --chunk->count;
    chunk->callbacks[idx].callback = NULL;

    unlock_fls_data();
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              RtlFlsSetValue (NTDLL.@)
 */
NTSTATUS WINAPI DECLSPEC_HOTPATCH RtlFlsSetValue( ULONG index, void *data )
{
    unsigned int chunk_index, idx;
    TEB_FLS_DATA *fls;

    macrunner_trace_fls_chunks( "set-entry", index, (ULONG)(ULONG_PTR)data );

    if (!index || index >= MAX_FLS_DATA_COUNT)
        return STATUS_INVALID_PARAMETER;

    if (!(fls = NtCurrentTeb()->FlsSlots)
            && !(NtCurrentTeb()->FlsSlots = fls = fls_alloc_data()))
        return STATUS_NO_MEMORY;

    chunk_index = fls_chunk_index_from_index( index, &idx );

    if (!fls->fls_data_chunks[chunk_index] &&
            !(fls->fls_data_chunks[chunk_index] = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY,
            (fls_chunk_size( chunk_index ) + 1) * sizeof(*fls->fls_data_chunks[chunk_index]) )))
        return STATUS_NO_MEMORY;

    fls->fls_data_chunks[chunk_index][idx + 1] = data;

    macrunner_trace_fls_chunks( "set-exit", index, (ULONG)(ULONG_PTR)data );

    return STATUS_SUCCESS;
}


/***********************************************************************
 *              RtlFlsGetValue (NTDLL.@)
 */
NTSTATUS WINAPI DECLSPEC_HOTPATCH RtlFlsGetValue( ULONG index, void **data )
{
    unsigned int chunk_index, idx;
    TEB_FLS_DATA *fls;

    if (!index || index >= MAX_FLS_DATA_COUNT || !(fls = NtCurrentTeb()->FlsSlots))
        return STATUS_INVALID_PARAMETER;

    chunk_index = fls_chunk_index_from_index( index, &idx );

    *data = fls->fls_data_chunks[chunk_index] ? fls->fls_data_chunks[chunk_index][idx + 1] : NULL;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              RtlProcessFlsData (NTDLL.@)
 */
void WINAPI DECLSPEC_HOTPATCH RtlProcessFlsData( void *teb_fls_data, ULONG flags )
{
    TEB_FLS_DATA *fls = teb_fls_data;
    unsigned int i, index;

    macrunner_trace_fls_chunks( "process-entry", flags, (ULONG)(ULONG_PTR)teb_fls_data );

    TRACE_(thread)( "teb_fls_data %p, flags %#lx.\n", teb_fls_data, flags );

    if (flags & ~3)
        FIXME_(thread)( "Unknown flags %#lx.\n", flags );

    if (!fls)
        return;

    if (flags & 1)
    {
        lock_fls_data();
        for (i = 0; i < ARRAY_SIZE(fls->fls_data_chunks); ++i)
        {
            if (!fls->fls_data_chunks[i] || !fls_data.fls_callback_chunks[i]
                    || !fls_data.fls_callback_chunks[i]->count)
                continue;

            for (index = 0; index < fls_chunk_size( i ); ++index)
            {
                PFLS_CALLBACK_FUNCTION callback = fls_data.fls_callback_chunks[i]->callbacks[index].callback;

                if (!fls->fls_data_chunks[i][index + 1])
                    continue;

                if (callback && callback != (void *)~(ULONG_PTR)0)
                {
                    TRACE_(relay)("Calling FLS callback %p, arg %p.\n", callback,
                            fls->fls_data_chunks[i][index + 1]);

                    callback( fls->fls_data_chunks[i][index + 1] );
                }
                fls->fls_data_chunks[i][index + 1] = NULL;
            }
        }
        /* Not using RemoveEntryList() as Windows does not zero list entry here. */
        fls->fls_list_entry.Flink->Blink = fls->fls_list_entry.Blink;
        fls->fls_list_entry.Blink->Flink = fls->fls_list_entry.Flink;
        unlock_fls_data();
    }

    if (flags & 2)
    {
        for (i = 0; i < ARRAY_SIZE(fls->fls_data_chunks); ++i)
            RtlFreeHeap( GetProcessHeap(), 0, fls->fls_data_chunks[i] );

        RtlFreeHeap( GetProcessHeap(), 0, fls );
    }
}
