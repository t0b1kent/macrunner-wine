#ifndef HB_ABI_H
#define HB_ABI_H

#include "hb_result.h"
#include "hb_context.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* x64 Windows ABI call */
typedef struct {
    uint64_t rcx, rdx, r8, r9;
    uint64_t* stack_args;
    size_t stack_arg_count;
    uint64_t* xmm_args; /* float args placeholder */
    size_t xmm_arg_count;
    uint64_t shadow_space[4];
    uint64_t return_value;
} hb_abi_x64_call_t;

/* x86 cdecl call */
typedef struct {
    uint32_t* stack_args;
    size_t stack_arg_count;
    uint32_t return_value;
    uint32_t caller_cleanup;
} hb_abi_x86_cdecl_t;

/* x86 stdcall call */
typedef struct {
    uint32_t* stack_args;
    size_t stack_arg_count;
    uint32_t return_value;
    uint32_t callee_cleanup;
    uint32_t ret_bytes;
} hb_abi_x86_stdcall_t;

/* x86 fastcall call: first two integer args in ECX/EDX, rest on stack. */
typedef struct {
    uint32_t ecx;
    uint32_t edx;
    uint32_t* stack_args;
    size_t stack_arg_count;
    uint32_t return_value;
} hb_abi_x86_fastcall_t;

/* x86 thiscall call: this pointer in ECX, remaining args on stack. */
typedef struct {
    uint32_t this_ptr;
    uint32_t* stack_args;
    size_t stack_arg_count;
    uint32_t return_value;
    uint32_t callee_cleanup;
} hb_abi_x86_thiscall_t;

hb_result_t hb_abi_x64_call(hb_context_t* ctx, uint64_t target, hb_abi_x64_call_t* call, uint64_t* out);
hb_result_t hb_abi_x86_cdecl_call(hb_context_t* ctx, uint32_t target, hb_abi_x86_cdecl_t* call, uint32_t* out);
hb_result_t hb_abi_x86_stdcall_call(hb_context_t* ctx, uint32_t target, hb_abi_x86_stdcall_t* call, uint32_t* out);
hb_result_t hb_abi_x86_fastcall_call(hb_context_t* ctx, uint32_t target, hb_abi_x86_fastcall_t* call, uint32_t* out);
hb_result_t hb_abi_x86_thiscall_call(hb_context_t* ctx, uint32_t target, hb_abi_x86_thiscall_t* call, uint32_t* out);

hb_result_t hb_abi_setup_stack(hb_context_t* ctx, size_t stack_size);
hb_result_t hb_abi_teardown_stack(hb_context_t* ctx);

#ifdef __cplusplus
}
#endif

#endif
