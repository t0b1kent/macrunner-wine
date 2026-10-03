/*
 * Unix side of MacRunner x86-64-on-ARM64EC HyperBridge CPU module.
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#ifdef __APPLE__
# include <mach/mach.h>
# include <mach/mach_vm.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/unixlib.h"

#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_ir.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_result.h"
#include "hb_runtime.h"

#include "xtajit64_private.h"

#define XTAJIT64_DEFAULT_MAX_CODE_BYTES 4096u
#define XTAJIT64_HB_IMPORT_BASE 0x00006f0000000000ULL
#define XTAJIT64_HB_IMPORT_SIZE (4096ULL * 0x10ULL)

static BOOL trace_xtajit64_enabled(void)
{
    const char *value = getenv( "MACRUNNER_HB_TRACE_XTAJIT64" );

    return value && value[0] && value[0] != '0';
}

static BOOL xtajit64_use_jit_backend(void)
{
    const char *value = getenv( "MACRUNNER_XTAJIT64_BACKEND" );

    if (!value || !*value) value = getenv( "MACRUNNER_HB_BACKEND" );
    if (value && (!strcasecmp( value, "interp" ) || !strcasecmp( value, "interpreter" ) ||
                  !strcasecmp( value, "off" ) || !strcmp( value, "0" )))
        return FALSE;
    return TRUE;
}

static pthread_mutex_t process_mutex = PTHREAD_MUTEX_INITIALIZER;
static hb_memory_t *process_memory;
static BOOL process_ready;
static __thread hb_context_t *thread_ctx;
static __thread hb_jit_runtime_t *thread_jit;
static __thread BOOL thread_ready;

static NTSTATUS status_from_hb( hb_result_t result )
{
    switch (result)
    {
    case HB_OK: return STATUS_SUCCESS;
    case HB_ERR_OUT_OF_MEMORY: return STATUS_NO_MEMORY;
    case HB_ERR_MEMORY_FAULT: return STATUS_ACCESS_VIOLATION;
    case HB_ERR_UNSUPPORTED_OPCODE:
    case HB_ERR_UNSUPPORTED_FEATURE: return STATUS_ILLEGAL_INSTRUCTION;
    case HB_ERR_INVALID_ARG: return STATUS_INVALID_PARAMETER;
    default: return STATUS_UNSUCCESSFUL;
    }
}

static hb_perm_t protect_to_perm( ULONG protect )
{
    hb_perm_t perm = HB_PERM_NONE;
    ULONG p = protect & 0xff;

    if (p == PAGE_NOACCESS) return HB_PERM_NONE;
    if (p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
        p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE ||
        p == PAGE_EXECUTE_WRITECOPY)
        perm = (hb_perm_t)(perm | HB_PERM_READ);
    if (p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
        p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY)
        perm = (hb_perm_t)(perm | HB_PERM_WRITE);
    if (p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
        p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY)
        perm = (hb_perm_t)(perm | HB_PERM_EXEC);
    return perm;
}

static size_t native_page_size(void)
{
    static size_t page_size;

    if (!page_size) page_size = (size_t)getpagesize();
    return page_size;
}

static hb_gva_t page_floor( hb_gva_t addr )
{
    size_t page = native_page_size();
    return addr & ~((hb_gva_t)page - 1);
}

static size_t page_span( hb_gva_t addr, size_t size )
{
    size_t page = native_page_size();
    hb_gva_t base = page_floor( addr );
    hb_gva_t end = addr + size;
    hb_gva_t aligned_end;

    if (!size || end < addr) return 0;
    aligned_end = (end + page - 1) & ~((hb_gva_t)page - 1);
    return (size_t)(aligned_end - base);
}

static BOOL is_ec_code_ptr( ULONG_PTR ptr )
{
    TEB *teb = NtCurrentTeb();
    const UINT64 *map;
    ULONG_PTR page;

    if (!teb || !teb->Peb || !teb->Peb->EcCodeBitMap) return FALSE;
    map = (const UINT64 *)teb->Peb->EcCodeBitMap;
    page = ptr / native_page_size();
    return (map[page / 64] >> (page & 63)) & 1;
}

static hb_result_t native_read( void *user, hb_gva_t addr, void *out, size_t size )
{
    (void)user;
    if (!size) return HB_OK;
    if (!addr) return HB_ERR_MEMORY_FAULT;
#ifdef __APPLE__
    {
        mach_vm_size_t copied = 0;
        kern_return_t kr = mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)addr,
                                                   (mach_vm_size_t)size,
                                                   (mach_vm_address_t)(uintptr_t)out, &copied );
        return (kr == KERN_SUCCESS && copied == size) ? HB_OK : HB_ERR_MEMORY_FAULT;
    }
#else
    memcpy( out, (const void *)(uintptr_t)addr, size );
    return HB_OK;
#endif
}

static hb_result_t native_write( void *user, hb_gva_t addr, const void *in, size_t size )
{
    (void)user;
    if (!size) return HB_OK;
    if (!addr) return HB_ERR_MEMORY_FAULT;
#ifdef __APPLE__
    return mach_vm_write( mach_task_self(), (mach_vm_address_t)addr,
                          (vm_offset_t)(uintptr_t)in,
                          (mach_msg_type_number_t)size ) == KERN_SUCCESS ?
           HB_OK : HB_ERR_MEMORY_FAULT;
#else
    memcpy( (void *)(uintptr_t)addr, in, size );
    return HB_OK;
#endif
}

static uint64_t simulate_block_limit(void)
{
    const char *value = getenv( "MACRUNNER_HB_XTAJIT64_BLOCK_LIMIT" );
    char *end = NULL;
    unsigned long long parsed;

    if (!value || !*value) return 0;
    errno = 0;
    parsed = strtoull( value, &end, 0 );
    if (errno != 0 || end == value || (end && *end != '\0')) return 0;
    return (uint64_t)parsed;
}

static BOOL func_ends_in_control_transfer( const hb_ir_func_t *func )
{
    hb_ir_block_t *block;

    if (!func || !func->cfg || !func->cfg->entry) return FALSE;
    block = func->cfg->entry;
    if (!block->instr_count) return FALSE;
    switch (block->instrs[block->instr_count - 1].op)
    {
    case HB_IR_CALL:
    case HB_IR_RET:
    case HB_IR_JMP:
    case HB_IR_Jcc:
        return TRUE;
    default:
        return FALSE;
    }
}

static NTSTATUS ensure_process(void)
{
    NTSTATUS status = STATUS_SUCCESS;

    pthread_mutex_lock( &process_mutex );
    if (!process_ready)
    {
        process_memory = hb_memory_create( 0 );
        if (!process_memory) status = STATUS_NO_MEMORY;
        else
        {
            hb_memory_set_special_handlers( process_memory, native_read, native_write, NULL );
            process_ready = TRUE;
        }
    }
    pthread_mutex_unlock( &process_mutex );
    return status;
}

static NTSTATUS ensure_thread(void)
{
    NTSTATUS status;

    if ((status = ensure_process())) return status;
    if (thread_ready) return STATUS_SUCCESS;

    thread_ctx = hb_context_create( HB_ARCH_X64,
                                    xtajit64_use_jit_backend() ? HB_BACKEND_JIT : HB_BACKEND_INTERP );
    if (!thread_ctx) return STATUS_NO_MEMORY;
    thread_ctx->memory = process_memory;
    if (xtajit64_use_jit_backend())
    {
        thread_jit = hb_jit_runtime_create( thread_ctx );
        if (!thread_jit && trace_xtajit64_enabled())
        {
            fprintf( stderr, "macrunner-xtajit64-unix: jit runtime create failed; using interpreter\n" );
            fflush( stderr );
        }
    }
    thread_ready = TRUE;
    return STATUS_SUCCESS;
}

static void import_context( hb_context_t *ctx, const struct xtajit64_amd64_context *src )
{
    unsigned int i;

    ctx->regs.x64.rax = src->rax;
    ctx->regs.x64.rbx = src->rbx;
    ctx->regs.x64.rcx = src->rcx;
    ctx->regs.x64.rdx = src->rdx;
    ctx->regs.x64.rsi = src->rsi;
    ctx->regs.x64.rdi = src->rdi;
    ctx->regs.x64.rsp = src->rsp;
    ctx->regs.x64.rbp = src->rbp;
    ctx->regs.x64.r8 = src->r8;
    ctx->regs.x64.r9 = src->r9;
    ctx->regs.x64.r10 = src->r10;
    ctx->regs.x64.r11 = src->r11;
    ctx->regs.x64.r12 = src->r12;
    ctx->regs.x64.r13 = src->r13;
    ctx->regs.x64.r14 = src->r14;
    ctx->regs.x64.r15 = src->r15;
    ctx->regs.x64.rip = src->rip;
    ctx->regs.x64.rflags = src->rflags;
    ctx->pc = src->rip;
    ctx->fs_base = src->fs_base;
    ctx->gs_base = src->gs_base ? src->gs_base : (uint64_t)(uintptr_t)NtCurrentTeb();
    ctx->seg_cs = src->seg_cs;
    ctx->seg_ds = src->seg_ds;
    ctx->seg_es = src->seg_es;
    ctx->seg_fs = src->seg_fs;
    ctx->seg_gs = src->seg_gs;
    ctx->seg_ss = src->seg_ss;
    for (i = 0; i < 16; i++)
    {
        ctx->regs.x64.xmm[i][0] = src->xmm[i][0];
        ctx->regs.x64.xmm[i][1] = src->xmm[i][1];
    }
}

static void export_context( struct xtajit64_amd64_context *dst, const hb_context_t *ctx )
{
    unsigned int i;

    dst->rax = ctx->regs.x64.rax;
    dst->rbx = ctx->regs.x64.rbx;
    dst->rcx = ctx->regs.x64.rcx;
    dst->rdx = ctx->regs.x64.rdx;
    dst->rsi = ctx->regs.x64.rsi;
    dst->rdi = ctx->regs.x64.rdi;
    dst->rsp = ctx->regs.x64.rsp;
    dst->rbp = ctx->regs.x64.rbp;
    dst->r8 = ctx->regs.x64.r8;
    dst->r9 = ctx->regs.x64.r9;
    dst->r10 = ctx->regs.x64.r10;
    dst->r11 = ctx->regs.x64.r11;
    dst->r12 = ctx->regs.x64.r12;
    dst->r13 = ctx->regs.x64.r13;
    dst->r14 = ctx->regs.x64.r14;
    dst->r15 = ctx->regs.x64.r15;
    dst->rip = ctx->regs.x64.rip;
    dst->rflags = ctx->regs.x64.rflags;
    dst->fs_base = ctx->fs_base;
    dst->gs_base = ctx->gs_base;
    dst->seg_cs = ctx->seg_cs;
    dst->seg_ds = ctx->seg_ds;
    dst->seg_es = ctx->seg_es;
    dst->seg_fs = ctx->seg_fs;
    dst->seg_gs = ctx->seg_gs;
    dst->seg_ss = ctx->seg_ss;
    for (i = 0; i < 16; i++)
    {
        dst->xmm[i][0] = ctx->regs.x64.xmm[i][0];
        dst->xmm[i][1] = ctx->regs.x64.xmm[i][1];
    }
}

static size_t fetch_code( hb_memory_t *memory, uint64_t pc, uint8_t *code, size_t max_code_bytes )
{
    size_t len = 0;

    while (len < max_code_bytes)
    {
        size_t page_left = native_page_size() - (size_t)((pc + len) & (native_page_size() - 1));
        size_t chunk = max_code_bytes - len;
        size_t i;

        if (chunk > page_left) chunk = page_left;
        if (hb_memory_read( memory, pc + len, &code[len], chunk ) == HB_OK)
        {
            len += chunk;
            continue;
        }

        for (i = 0; i < chunk; i++)
        {
            if (hb_memory_read_u8( memory, pc + len, &code[len] ) != HB_OK) return len;
            len++;
        }
    }
    return len;
}

static NTSTATUS unix_process_init_impl( void *args )
{
    return ensure_process();
}

static NTSTATUS unix_thread_init_impl( void *args )
{
    return ensure_thread();
}

static NTSTATUS unix_thread_term_impl( void *args )
{
    if (thread_jit)
    {
        hb_jit_runtime_destroy( thread_jit );
        thread_jit = NULL;
    }
    if (thread_ctx)
    {
        thread_ctx->memory = NULL;
        hb_context_destroy( thread_ctx );
    }
    thread_ctx = NULL;
    thread_ready = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS unix_process_term_impl( void *args )
{
    pthread_mutex_lock( &process_mutex );
    if (process_memory) hb_memory_destroy( process_memory );
    process_memory = NULL;
    process_ready = FALSE;
    pthread_mutex_unlock( &process_mutex );
    return STATUS_SUCCESS;
}

static BOOL jit_should_fallback( hb_result_t result, const hb_exec_result_t *exec )
{
    if (result != HB_OK) return FALSE;
    if (!exec || !exec->faulted || !exec->fault_reason) return FALSE;
    return !strcmp( exec->fault_reason, "JIT codegen failed" ) ||
           !strcmp( exec->fault_reason, "JIT helper fault" );
}

static BOOL func_has_call_or_ret( const hb_ir_func_t *func )
{
    size_t b, i;

    if (!func || !func->cfg) return TRUE;
    for (b = 0; b < func->cfg->block_count; b++)
    {
        const hb_ir_block_t *block = func->cfg->blocks[b];
        if (!block) continue;
        for (i = 0; i < block->instr_count; i++)
        {
            hb_ir_op_t op = block->instrs[i].op;
            if (op == HB_IR_CALL || op == HB_IR_RET || op == HB_IR_HOST_CALL)
                return TRUE;
        }
    }
    return FALSE;
}

static hb_result_t run_translated_block( const hb_ir_func_t *func, hb_exec_result_t *out )
{
    hb_exec_result_t jit_out;
    hb_context_t saved_ctx;
    hb_result_t result;

    if (!thread_jit || func_has_call_or_ret( func ))
        return hb_runtime_run( thread_ctx, func, HB_BACKEND_INTERP, out );

    saved_ctx = *thread_ctx;
    memset( &jit_out, 0, sizeof(jit_out) );
    result = hb_jit_runtime_run( thread_jit, func, &jit_out );
    if (!jit_should_fallback( result, &jit_out ))
    {
        *out = jit_out;
        return result;
    }

    if (trace_xtajit64_enabled() || getenv( "MACRUNNER_HB_TRACE_JIT_FALLBACKS" ))
    {
        fprintf( stderr, "macrunner-xtajit64-unix: jit-fallback pc=%016llx result=%s(%d) reason=%s "
                 "steps=%llu blocks=%llu\n",
                 (unsigned long long)thread_ctx->regs.x64.rip,
                 hb_result_string( jit_out.result ), jit_out.result,
                 jit_out.fault_reason ? jit_out.fault_reason : "",
                 (unsigned long long)jit_out.steps_executed,
                 (unsigned long long)jit_out.blocks_executed );
        fflush( stderr );
    }

    *thread_ctx = saved_ctx;
    thread_ctx->memory = process_memory;
    result = hb_runtime_run( thread_ctx, func, HB_BACKEND_INTERP, out );
    return result;
}

static NTSTATUS unix_simulate_impl( void *args )
{
    struct xtajit64_simulate_params *params = args;
    uint8_t code[XTAJIT64_DEFAULT_MAX_CODE_BYTES];
    uint64_t total_steps = 0, total_blocks = 0, dispatched = 0, block_limit;
    BOOL ran_block = FALSE;
    hb_exec_result_t exec;
    hb_result_t result = HB_OK;
    NTSTATUS status;
    size_t max_code_bytes;

    if (!params) return STATUS_INVALID_PARAMETER;
    if ((status = ensure_thread())) return status;

    import_context( thread_ctx, &params->context );
    max_code_bytes = params->max_code_bytes ? params->max_code_bytes : XTAJIT64_DEFAULT_MAX_CODE_BYTES;
    if (max_code_bytes > sizeof(code)) max_code_bytes = sizeof(code);
    block_limit = simulate_block_limit();

    if (trace_xtajit64_enabled())
    {
        fprintf( stderr, "macrunner-xtajit64-unix: phase=enter rip=%016llx rsp=%016llx rcx=%016llx rdx=%016llx max=%zu\n",
                 (unsigned long long)thread_ctx->regs.x64.rip,
                 (unsigned long long)thread_ctx->regs.x64.rsp,
                 (unsigned long long)thread_ctx->regs.x64.rcx,
                 (unsigned long long)thread_ctx->regs.x64.rdx, max_code_bytes );
        fflush( stderr );
    }

    while (!block_limit || dispatched < block_limit)
    {
        hb_decoder_t *dec = NULL;
        hb_ir_func_t *func = NULL;
        hb_exec_result_t block_out;
        hb_result_t r;
        uint64_t pc = thread_ctx->regs.x64.rip;
        size_t len;
        BOOL chain;

        thread_ctx->pc = pc;
        if (is_ec_code_ptr( (ULONG_PTR)pc ))
        {
            fprintf( stderr, "macrunner-xtajit64-unix: boundary ec rip=%016llx after steps=%llu blocks=%llu\n",
                     (unsigned long long)pc, (unsigned long long)total_steps,
                     (unsigned long long)total_blocks );
            break;
        }
        if (pc >= XTAJIT64_HB_IMPORT_BASE && pc < XTAJIT64_HB_IMPORT_BASE + XTAJIT64_HB_IMPORT_SIZE)
        {
            fprintf( stderr, "macrunner-xtajit64-unix: boundary import rip=%016llx after steps=%llu blocks=%llu\n",
                     (unsigned long long)pc, (unsigned long long)total_steps,
                     (unsigned long long)total_blocks );
            break;
        }

        len = fetch_code( process_memory, pc, code, max_code_bytes );
        if (!len)
        {
            if (ran_block) break;
            memset( &exec, 0, sizeof(exec) );
            exec.result = HB_ERR_MEMORY_FAULT;
            exec.faulted = TRUE;
            exec.fault_reason = "unable to fetch executable x64 code";
            result = HB_ERR_MEMORY_FAULT;
            goto done_with_exec;
        }

        dec = hb_decoder_create( HB_ARCH_X64, code, len, pc );
        if (!dec)
        {
            result = HB_ERR_OUT_OF_MEMORY;
            goto done;
        }
        r = hb_lift_func_x64( dec, &func );
        hb_decoder_destroy( dec );
        if (r != HB_OK)
        {
            result = r;
            goto done;
        }

        chain = func_ends_in_control_transfer( func );
        memset( &block_out, 0, sizeof(block_out) );
        r = run_translated_block( func, &block_out );
        hb_ir_func_destroy( func );

        ran_block = TRUE;
        dispatched++;
        total_steps += block_out.steps_executed;
        total_blocks += block_out.blocks_executed;

        if (r != HB_OK || block_out.result != HB_OK || block_out.faulted)
        {
            if ((r == HB_ERR_UNSUPPORTED_OPCODE || block_out.result == HB_ERR_UNSUPPORTED_OPCODE) &&
                getenv( "MACRUNNER_HB_TRACE_UNSUPPORTED_BYTES" ))
            {
                uint64_t block_pc = thread_ctx->regs.x64.rip;
                uint64_t fault_pc = thread_ctx->pc;
                uint8_t fault_bytes[64];
                size_t fault_len = fetch_code( process_memory, fault_pc, fault_bytes, sizeof(fault_bytes) );
                fprintf( stderr, "macrunner-xtajit64-unix: unsupported-bytes block=%016llx pc=%016llx len=%zu bytes=",
                         (unsigned long long)block_pc, (unsigned long long)fault_pc, fault_len );
                for (size_t i = 0; i < fault_len; i++) fprintf( stderr, "%02x", fault_bytes[i] );
                fprintf( stderr, "\n" );
            }
            exec = block_out;
            exec.steps_executed = total_steps;
            exec.blocks_executed = total_blocks;
            result = r;
            goto done_with_exec;
        }
        if (!chain) break;
    }

    memset( &exec, 0, sizeof(exec) );
    exec.result = HB_OK;
    exec.steps_executed = total_steps;
    exec.blocks_executed = total_blocks;

done_with_exec:
    params->hb_result = result;
    params->faulted = exec.faulted;
    params->steps = exec.steps_executed;
    params->blocks = exec.blocks_executed;
    export_context( &params->context, thread_ctx );
    if (result != HB_OK) params->status = status_from_hb( result );
    else if (exec.result != HB_OK) params->status = status_from_hb( exec.result );
    else params->status = STATUS_SUCCESS;

    if (trace_xtajit64_enabled())
    {
        fprintf( stderr, "macrunner-xtajit64-unix: simulate hb=%s(%d) exec=%s(%d) faulted=%u steps=%llu blocks=%llu rip=%016llx rsp=%016llx reason=%s\n",
                 hb_result_string( params->hb_result ), params->hb_result,
                 hb_result_string( exec.result ), exec.result, exec.faulted,
                 (unsigned long long)params->steps, (unsigned long long)params->blocks,
                 (unsigned long long)params->context.rip,
                 (unsigned long long)params->context.rsp,
                 exec.fault_reason ? exec.fault_reason : "" );
        fflush( stderr );
    }
    return params->status;

done:
    memset( &exec, 0, sizeof(exec) );
    goto done_with_exec;
}

static NTSTATUS map_native_range( const struct xtajit64_memory_params *params )
{
    hb_gva_t base;
    size_t size;
    hb_perm_t perm;
    hb_region_t *region;
    hb_result_t result;

    if (!params) return STATUS_INVALID_PARAMETER;
    if (!params->is_post || params->status || !params->size) return STATUS_SUCCESS;
    if (ensure_process()) return STATUS_NO_MEMORY;

    base = page_floor( (hb_gva_t)(uintptr_t)params->addr );
    size = page_span( (hb_gva_t)(uintptr_t)params->addr, params->size );
    if (!base || !size) return STATUS_SUCCESS;
    perm = protect_to_perm( params->protect );

    region = hb_memory_find_region( process_memory, base );
    if (region) result = hb_memory_protect( process_memory, region->base, region->size, perm );
    else result = hb_memory_map( process_memory, base, size, perm );
    return status_from_hb( result );
}

static NTSTATUS unix_notify_memory_alloc_impl( void *args )
{
    return map_native_range( args );
}

static NTSTATUS unix_notify_map_view_impl( void *args )
{
    return map_native_range( args );
}

static NTSTATUS unix_notify_memory_protect_impl( void *args )
{
    return map_native_range( args );
}

__attribute__((visibility("default"))) void macrunner_xtajit64_notify_memory_alloc_unix( void *addr,
                                                                                         SIZE_T size,
                                                                                         ULONG type,
                                                                                         ULONG protect,
                                                                                         NTSTATUS status )
{
    struct xtajit64_memory_params params = { addr, size, type, protect, TRUE, status };
    NTSTATUS notify_status = map_native_range( &params );

    if (trace_xtajit64_enabled())
        fprintf( stderr, "macrunner-xtajit64-unix: notify-alloc addr=%p size=%#zx type=%#lx "
                 "protect=%#lx status=%08lx notify=%08lx\n",
                 addr, (size_t)size, (unsigned long)type, (unsigned long)protect,
                 (unsigned long)status, (unsigned long)notify_status );
}

__attribute__((visibility("default"))) void macrunner_xtajit64_notify_memory_protect_unix( void *addr,
                                                                                           SIZE_T size,
                                                                                           ULONG protect,
                                                                                           NTSTATUS status )
{
    struct xtajit64_memory_params params = { addr, size, 0, protect, TRUE, status };
    NTSTATUS notify_status = map_native_range( &params );

    if (trace_xtajit64_enabled())
        fprintf( stderr, "macrunner-xtajit64-unix: notify-protect addr=%p size=%#zx "
                 "protect=%#lx status=%08lx notify=%08lx\n",
                 addr, (size_t)size, (unsigned long)protect,
                 (unsigned long)status, (unsigned long)notify_status );
}

static NTSTATUS unix_notify_memory_free_impl( void *args )
{
    const struct xtajit64_memory_params *params = args;
    hb_gva_t base;

    if (!params) return STATUS_INVALID_PARAMETER;
    if (!params->is_post || params->status || !params->size) return STATUS_SUCCESS;
    if (ensure_process()) return STATUS_NO_MEMORY;
    base = page_floor( (hb_gva_t)(uintptr_t)params->addr );
    if (!hb_memory_find_region( process_memory, base )) return STATUS_SUCCESS;
    return status_from_hb( hb_memory_unmap( process_memory, base ) );
}

__attribute__((visibility("default"))) void macrunner_xtajit64_notify_memory_free_unix( void *addr,
                                                                                        SIZE_T size,
                                                                                        ULONG type,
                                                                                        NTSTATUS status )
{
    struct xtajit64_memory_params params = { addr, size, type, 0, TRUE, status };
    NTSTATUS notify_status = unix_notify_memory_free_impl( &params );

    if (trace_xtajit64_enabled())
        fprintf( stderr, "macrunner-xtajit64-unix: notify-free addr=%p size=%#zx type=%#lx "
                 "status=%08lx notify=%08lx\n",
                 addr, (size_t)size, (unsigned long)type,
                 (unsigned long)status, (unsigned long)notify_status );
}

static NTSTATUS unix_notify_unmap_view_impl( void *args )
{
    const struct xtajit64_memory_params *params = args;
    hb_gva_t base;

    if (!params) return STATUS_INVALID_PARAMETER;
    if (!params->is_post || params->status) return STATUS_SUCCESS;
    if (ensure_process()) return STATUS_NO_MEMORY;
    base = page_floor( (hb_gva_t)(uintptr_t)params->addr );
    if (!hb_memory_find_region( process_memory, base )) return STATUS_SUCCESS;
    return status_from_hb( hb_memory_unmap( process_memory, base ) );
}

static NTSTATUS unix_flush_instruction_cache_impl( void *args )
{
    return STATUS_SUCCESS;
}

const unixlib_entry_t __wine_unix_call_funcs[] =
{
    unix_process_init_impl,
    unix_thread_init_impl,
    unix_thread_term_impl,
    unix_process_term_impl,
    unix_simulate_impl,
    unix_notify_memory_alloc_impl,
    unix_notify_memory_protect_impl,
    unix_notify_memory_free_impl,
    unix_notify_map_view_impl,
    unix_notify_unmap_view_impl,
    unix_flush_instruction_cache_impl,
};

C_ASSERT( ARRAYSIZE(__wine_unix_call_funcs) == unix_funcs_count );
