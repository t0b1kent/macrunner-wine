#include "hb_abi.h"
#include "hb_memory.h"
#include <stdlib.h>
#include <string.h>

#define HB_X86_RETURN_SENTINEL 0xFFFF0000u

static hb_result_t validate_x86_call(hb_context_t* ctx, const uint32_t* stack_args, size_t stack_arg_count) {
    if (!ctx || ctx->arch != HB_ARCH_X86 || ctx->mode != HB_MODE_32BIT || !ctx->memory) return HB_ERR_INVALID_ARG;
    if (stack_arg_count && !stack_args) return HB_ERR_INVALID_ARG;
    return HB_OK;
}

static hb_result_t push_u32(hb_context_t* ctx, uint32_t* esp, uint32_t value) {
    *esp -= 4;
    return hb_memory_write_u32(ctx->memory, *esp, value);
}

static hb_result_t setup_x86_stack_call(hb_context_t* ctx, uint32_t target,
                                        const uint32_t* stack_args, size_t stack_arg_count) {
    hb_result_t r = validate_x86_call(ctx, stack_args, stack_arg_count);
    if (r != HB_OK) return r;

    uint32_t esp = ctx->regs.x86.esp;

    for (size_t i = stack_arg_count; i > 0; i--) {
        r = push_u32(ctx, &esp, stack_args[i - 1]);
        if (r != HB_OK) return r;
    }

    r = push_u32(ctx, &esp, HB_X86_RETURN_SENTINEL);
    if (r != HB_OK) return r;

    ctx->regs.x86.esp = esp;
    ctx->pc = target;
    ctx->regs.x86.eip = target;
    return HB_OK;
}

hb_result_t hb_abi_x86_cdecl_call(hb_context_t* ctx, uint32_t target, hb_abi_x86_cdecl_t* call, uint32_t* out) {
    if (!call) return HB_ERR_INVALID_ARG;
    hb_result_t r = setup_x86_stack_call(ctx, target, call->stack_args, call->stack_arg_count);
    if (r != HB_OK) return r;
    if (out) *out = 0;
    return HB_OK;
}

hb_result_t hb_abi_x86_stdcall_call(hb_context_t* ctx, uint32_t target, hb_abi_x86_stdcall_t* call, uint32_t* out) {
    if (!call) return HB_ERR_INVALID_ARG;
    hb_result_t r = setup_x86_stack_call(ctx, target, call->stack_args, call->stack_arg_count);
    if (r != HB_OK) return r;
    if (out) *out = 0;
    return HB_OK;
}

hb_result_t hb_abi_x86_fastcall_call(hb_context_t* ctx, uint32_t target, hb_abi_x86_fastcall_t* call, uint32_t* out) {
    if (!call) return HB_ERR_INVALID_ARG;
    hb_result_t r = setup_x86_stack_call(ctx, target, call->stack_args, call->stack_arg_count);
    if (r != HB_OK) return r;
    ctx->regs.x86.ecx = call->ecx;
    ctx->regs.x86.edx = call->edx;
    if (out) *out = 0;
    return HB_OK;
}

hb_result_t hb_abi_x86_thiscall_call(hb_context_t* ctx, uint32_t target, hb_abi_x86_thiscall_t* call, uint32_t* out) {
    if (!call) return HB_ERR_INVALID_ARG;
    hb_result_t r = setup_x86_stack_call(ctx, target, call->stack_args, call->stack_arg_count);
    if (r != HB_OK) return r;
    ctx->regs.x86.ecx = call->this_ptr;
    if (out) *out = 0;
    return HB_OK;
}
