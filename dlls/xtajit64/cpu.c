/*
 * x86-64 emulation on ARM64
 *
 * Copyright 2024 Alexandre Julliard
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

#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/unixlib.h"
#include "wine/debug.h"

#include "xtajit64_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(xtajit);


static NTSTATUS xtajit64_unix_call( enum xtajit64_unix_funcs func, void *params )
{
    NTSTATUS status = __wine_init_unix_call();
    if (status) return status;
    return WINE_UNIX_CALL( func, params );
}

static void pack_amd64_context( struct xtajit64_amd64_context *dst, const CONTEXT *src )
{
    const M128A *xmm = &src->Xmm0;
    unsigned int i;

    dst->rax = src->Rax;
    dst->rbx = src->Rbx;
    dst->rcx = src->Rcx;
    dst->rdx = src->Rdx;
    dst->rsi = src->Rsi;
    dst->rdi = src->Rdi;
    dst->rsp = src->Rsp;
    dst->rbp = src->Rbp;
    dst->r8 = src->R8;
    dst->r9 = src->R9;
    dst->r10 = src->R10;
    dst->r11 = src->R11;
    dst->r12 = src->R12;
    dst->r13 = src->R13;
    dst->r14 = src->R14;
    dst->r15 = src->R15;
    dst->rip = src->Rip;
    dst->rflags = src->EFlags;
    dst->fs_base = 0;
    dst->gs_base = (ULONG64)(ULONG_PTR)NtCurrentTeb();
    dst->seg_cs = src->SegCs;
    dst->seg_ds = src->SegDs;
    dst->seg_es = src->SegEs;
    dst->seg_fs = src->SegFs;
    dst->seg_gs = src->SegGs;
    dst->seg_ss = src->SegSs;
    for (i = 0; i < 16; i++)
    {
        dst->xmm[i][0] = xmm[i].Low;
        dst->xmm[i][1] = (ULONG64)xmm[i].High;
    }
}

static void unpack_amd64_context( CONTEXT *dst, const struct xtajit64_amd64_context *src )
{
    M128A *xmm = &dst->Xmm0;
    unsigned int i;

    dst->Rax = src->rax;
    dst->Rbx = src->rbx;
    dst->Rcx = src->rcx;
    dst->Rdx = src->rdx;
    dst->Rsi = src->rsi;
    dst->Rdi = src->rdi;
    dst->Rsp = src->rsp;
    dst->Rbp = src->rbp;
    dst->R8 = src->r8;
    dst->R9 = src->r9;
    dst->R10 = src->r10;
    dst->R11 = src->r11;
    dst->R12 = src->r12;
    dst->R13 = src->r13;
    dst->R14 = src->r14;
    dst->R15 = src->r15;
    dst->Rip = src->rip;
    dst->EFlags = (DWORD)src->rflags;
    dst->SegCs = src->seg_cs;
    dst->SegDs = src->seg_ds;
    dst->SegEs = src->seg_es;
    dst->SegFs = src->seg_fs;
    dst->SegGs = src->seg_gs;
    dst->SegSs = src->seg_ss;
    for (i = 0; i < 16; i++)
    {
        xmm[i].Low = src->xmm[i][0];
        xmm[i].High = (LONGLONG)src->xmm[i][1];
    }
}


/**********************************************************************
 *           DispatchJump  (xtajit64.@)
 *
 * Implementation of __os_arm64x_x64_jump.
 */
void WINAPI DispatchJump(void)
{
    MESSAGE( "macrunner-xtajit64: DispatchJump reached\n" );
    NtTerminateProcess( GetCurrentProcess(), 0x6503 );
}


/**********************************************************************
 *           RetToEntryThunk  (xtajit64.@)
 *
 * Implementation of __os_arm64x_dispatch_ret.
 */
void WINAPI RetToEntryThunk(void)
{
    MESSAGE( "macrunner-xtajit64: RetToEntryThunk reached\n" );
    NtTerminateProcess( GetCurrentProcess(), 0x6504 );
}


/**********************************************************************
 *           ExitToX64  (xtajit64.@)
 *
 * Implementation of __os_arm64x_dispatch_call_no_redirect.
 */
void WINAPI ExitToX64(void)
{
    MESSAGE( "macrunner-xtajit64: ExitToX64 reached\n" );
    NtTerminateProcess( GetCurrentProcess(), 0x6505 );
}


/**********************************************************************
 *           BeginSimulation  (xtajit64.@)
 */
void WINAPI BeginSimulation(void)
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    CONTEXT *ctx = cpu ? &cpu->ContextAmd64->AMD64_Context : NULL;
    struct xtajit64_simulate_params params;
    NTSTATUS status;

    if (!cpu || !ctx)
    {
        MESSAGE( "macrunner-xtajit64: BeginSimulation REACHED but cpu/context is null cpu=%p ctx=%p\n", cpu, ctx );
        RtlRaiseStatus( STATUS_INVALID_PARAMETER );
    }

    MESSAGE( "macrunner-xtajit64: BeginSimulation REACHED rip=%p rsp=%p rax=%p rcx=%p rdx=%p insim=%lu\n",
             (void *)ctx->Rip, (void *)ctx->Rsp, (void *)ctx->Rax,
             (void *)ctx->Rcx, (void *)ctx->Rdx, (ULONG)cpu->InSimulation );

    RtlZeroMemory( &params, sizeof(params) );
    pack_amd64_context( &params.context, ctx );
    params.max_code_bytes = 4096;

    status = xtajit64_unix_call( unix_simulate, &params );
    if (!status) status = params.status;
    unpack_amd64_context( ctx, &params.context );
    cpu->InSimulation = 0;

    MESSAGE( "macrunner-xtajit64: BeginSimulation executed status=%08lx hb=%ld faulted=%lu steps=%llu blocks=%llu rip=%p rsp=%p\n",
             status, params.hb_result, params.faulted,
             (unsigned long long)params.steps, (unsigned long long)params.blocks,
             (void *)ctx->Rip, (void *)ctx->Rsp );

    if (status) RtlRaiseStatus( status );
    status = NtContinue( ctx, FALSE );
    RtlRaiseStatus( status );
}


/**********************************************************************
 *           BTCpu64FlushInstructionCache  (xtajit64.@)
 */
void WINAPI BTCpu64FlushInstructionCache( void *addr, SIZE_T size )
{
    TRACE( "%p %Ix\n", addr, size );
    (void)xtajit64_unix_call( unix_flush_instruction_cache, NULL );
}


/**********************************************************************
 *           BTCpu64IsProcessorFeaturePresent  (xtajit64.@)
 */
BOOLEAN WINAPI BTCpu64IsProcessorFeaturePresent( UINT feature )
{
    static const ULONGLONG x86_features =
        (1ull << PF_COMPARE_EXCHANGE_DOUBLE) |
        (1ull << PF_MMX_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_XMMI_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_RDTSC_INSTRUCTION_AVAILABLE) |
        (1ull << PF_XMMI64_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_NX_ENABLED) |
        (1ull << PF_SSE3_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_COMPARE_EXCHANGE128) |
        (1ull << PF_FASTFAIL_AVAILABLE) |
        (1ull << PF_RDTSCP_INSTRUCTION_AVAILABLE) |
        (1ull << PF_SSSE3_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_SSE4_1_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_SSE4_2_INSTRUCTIONS_AVAILABLE);

    return feature < 64 && (x86_features & (1ull << feature));
}


/**********************************************************************
 *           BTCpu64NotifyMemoryDirty  (xtajit64.@)
 */
void WINAPI BTCpu64NotifyMemoryDirty( void *addr, SIZE_T size )
{
    TRACE( "%p %Ix\n", addr, size );
}


/**********************************************************************
 *           BTCpu64NotifyReadFile  (xtajit64.@)
 */
void WINAPI BTCpu64NotifyReadFile( HANDLE handle, void *addr, SIZE_T size, BOOL is_post, NTSTATUS status )
{
    TRACE( "%p %p %Ix\n", handle, addr, size );
}


/**********************************************************************
 *           FlushInstructionCacheHeavy  (xtajit64.@)
 */
void WINAPI FlushInstructionCacheHeavy( void *addr, SIZE_T size )
{
    TRACE( "%p %Ix\n", addr, size );
    (void)xtajit64_unix_call( unix_flush_instruction_cache, NULL );
}


/**********************************************************************
 *           NotifyMapViewOfSection  (xtajit64.@)
 */
NTSTATUS WINAPI NotifyMapViewOfSection( void *unk1, void *addr, void *unk2, SIZE_T size,
                                        ULONG alloc_type, ULONG protect )
{
    struct xtajit64_memory_params params = { addr, size, alloc_type, protect, TRUE, STATUS_SUCCESS };

    TRACE( "%p %Ix %lx %lx\n", addr, size, alloc_type, protect );
    return xtajit64_unix_call( unix_notify_map_view, &params );
}


/**********************************************************************
 *           NotifyMemoryAlloc  (xtajit64.@)
 */
void WINAPI NotifyMemoryAlloc( void *addr, SIZE_T size, ULONG type, ULONG prot, BOOL is_post, NTSTATUS status )
{
    struct xtajit64_memory_params params = { addr, size, type, prot, is_post, status };

    TRACE( "%p %Ix\n", addr, size );
    (void)xtajit64_unix_call( unix_notify_memory_alloc, &params );
}


/**********************************************************************
 *           NotifyMemoryFree  (xtajit64.@)
 */
void WINAPI NotifyMemoryFree( void *addr, SIZE_T size, ULONG type, BOOL is_post, NTSTATUS status )
{
    struct xtajit64_memory_params params = { addr, size, type, 0, is_post, status };

    TRACE( "%p %Ix %lx\n", addr, size, type );
    (void)xtajit64_unix_call( unix_notify_memory_free, &params );
}


/**********************************************************************
 *           NotifyMemoryProtect  (xtajit64.@)
 */
void WINAPI NotifyMemoryProtect( void *addr, SIZE_T size, ULONG prot, BOOL is_post, NTSTATUS status )
{
    struct xtajit64_memory_params params = { addr, size, 0, prot, is_post, status };

    TRACE( "%p %Ix %lx\n", addr, size, prot );
    (void)xtajit64_unix_call( unix_notify_memory_protect, &params );
}


/**********************************************************************
 *           NotifyUnmapViewOfSection  (xtajit64.@)
 */
void WINAPI NotifyUnmapViewOfSection( void *addr, BOOL is_post, NTSTATUS status )
{
    struct xtajit64_memory_params params = { addr, 0, 0, 0, is_post, status };

    TRACE( "%p\n", addr );
    (void)xtajit64_unix_call( unix_notify_unmap_view, &params );
}


/**********************************************************************
 *           ProcessInit  (xtajit64.@)
 */
NTSTATUS WINAPI ProcessInit(void)
{
    NTSTATUS status = xtajit64_unix_call( unix_process_init, NULL );
    MESSAGE( "macrunner-xtajit64: ProcessInit status=%08lx\n", status );
    return status;
}


/**********************************************************************
 *           ProcessTerm  (xtajit64.@)
 */
void WINAPI ProcessTerm( HANDLE handle, BOOL is_post, NTSTATUS status )
{
    TRACE( "%p\n", handle );
    (void)xtajit64_unix_call( unix_process_term, NULL );
}


/**********************************************************************
 *           ResetToConsistentState  (xtajit64.@)
 */
void WINAPI ResetToConsistentState( EXCEPTION_RECORD *rec, CONTEXT *context, ARM64_NT_CONTEXT *arm_ctx )
{
    TRACE( "%p %p %p\n", rec, context, arm_ctx );
}


/**********************************************************************
 *           ThreadInit  (xtajit64.@)
 */
NTSTATUS WINAPI ThreadInit(void)
{
    NTSTATUS status = xtajit64_unix_call( unix_thread_init, NULL );
    MESSAGE( "macrunner-xtajit64: ThreadInit status=%08lx\n", status );
    return status;
}


/**********************************************************************
 *           ThreadTerm  (xtajit64.@)
 */
void WINAPI ThreadTerm( HANDLE handle, LONG exit_code )
{
    TRACE( "%p %lx\n", handle, exit_code );
    (void)xtajit64_unix_call( unix_thread_term, NULL );
}


/**********************************************************************
 *           UpdateProcessorInformation  (xtajit64.@)
 */
void WINAPI UpdateProcessorInformation( SYSTEM_CPU_INFORMATION *info )
{
    info->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
    info->ProcessorLevel = 21;
    info->ProcessorRevision = 1;
}


/**********************************************************************
 *           DllMain
 */
BOOL WINAPI DllMain( HINSTANCE inst, DWORD reason, void *reserved )
{
    if (reason == DLL_PROCESS_ATTACH) LdrDisableThreadCalloutsForDll( inst );
    return TRUE;
}
