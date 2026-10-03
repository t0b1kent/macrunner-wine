#include "hb_abi.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include <stdlib.h>
#include <string.h>

hb_result_t hb_abi_x64_call(hb_context_t* ctx, uint64_t target, hb_abi_x64_call_t* call, uint64_t* out) {
    if (!ctx || !call) return HB_ERR_INVALID_ARG;
    if (!ctx->memory) return HB_ERR_INVALID_ARG;
    if (call->stack_arg_count && !call->stack_args) return HB_ERR_INVALID_ARG;

    /* Simulate the state after a Windows x64 CALL:
     * [rsp]            return address
     * [rsp + 0x08..27] caller-allocated 32-byte shadow space
     * [rsp + 0x28...]  stack arguments 5+
     * Function entry RSP must be 8 mod 16. */
    uint64_t rsp = ctx->regs.x64.rsp & ~0xFULL;
    size_t stack_bytes = call->stack_arg_count * 8;
    size_t align_pad = (call->stack_arg_count & 1) ? 8 : 0;

    /* Leave mapped headroom above the entry stack frame.  MSVC prologues
     * commonly spill nonvolatile registers into caller home space before
     * subtracting their local frame (for example [rsp+0x10], [rsp+0x78]).
     * Starting exactly at stack_top makes those positive offsets fault even
     * though they are valid within the synthetic Win64 call contract.  Keep
     * this to one page: larger gaps steal real x64 stack reserve and can make
     * deep startup paths run below the mapped bridge stack.
     */
    if (ctx->memory && ctx->memory->stack_bottom && ctx->memory->stack_top &&
        rsp > ctx->memory->stack_bottom + 0x8000)
        rsp -= 0x1000;

    rsp -= 8 + 32 + stack_bytes + align_pad;

    if (!hb_memory_can_write_span(ctx->memory, rsp, 8 + 32 + stack_bytes))
        return HB_ERR_MEMORY_FAULT;

    hb_result_t r = hb_memory_write_u64(ctx->memory, rsp, 0xFFFF0000);
    if (r != HB_OK) return r;
    for (size_t i = 0; i < 4; i++) {
        r = hb_memory_write_u64(ctx->memory, rsp + 8 + i * 8, call->shadow_space[i]);
        if (r != HB_OK) return r;
    }
    for (size_t i = 0; i < call->stack_arg_count; i++) {
        r = hb_memory_write_u64(ctx->memory, rsp + 8 + 32 + i * 8, call->stack_args[i]);
        if (r != HB_OK) return r;
    }

    /* Commit guest-visible call state only after the synthetic frame is valid. */
    ctx->regs.x64.rcx = call->rcx;
    ctx->regs.x64.rdx = call->rdx;
    ctx->regs.x64.r8  = call->r8;
    ctx->regs.x64.r9  = call->r9;
    ctx->regs.x64.rsp = rsp;
    ctx->pc = target;
    ctx->regs.x64.rip = target;

    if (out) *out = 0;
    return HB_OK;
}

hb_result_t hb_abi_setup_stack(hb_context_t* ctx, size_t stack_size) {
    if (!ctx) return HB_ERR_INVALID_ARG;
    hb_result_t r = hb_memory_setup_stack(ctx->memory, 0, stack_size);
    if (r != HB_OK) return r;
    if (ctx->mode == HB_MODE_64BIT) {
        ctx->regs.x64.rsp = ctx->memory->stack_top;
    } else {
        ctx->regs.x86.esp = (uint32_t)ctx->memory->stack_top;
    }
    return HB_OK;
}

hb_result_t hb_abi_teardown_stack(hb_context_t* ctx) {
    (void)ctx;
    return HB_OK;
}
