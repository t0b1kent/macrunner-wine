/* Internal PE/unix thread-origin transport, not a Windows API or guest state.
 * This slot is beyond the existing FP shadow (0x800 + <0x400) in the owned
 * ARM64EC CPU-area page. No allocation, loader lookup or signal-time init. */
#ifndef __WINE_MACRUNNER_WINCTX_PROCESS_H
#define __WINE_MACRUNNER_WINCTX_PROCESS_H
#include "wine/macrunner_winctx.h"
#define MR_WINCTX_CLOSE_ORIGIN_OFFSET 0xf00u
#define MR_WINCTX_CLOSE_ORIGIN_MAGIC 0x4d52434fu
struct mr_winctx_software_origin
{
    struct mr_winctx_software_origin *previous;
    const EXCEPTION_RECORD *record;
    ULONG_PTR entry_rsp;
    ULONG_PTR return_target;
    /* Native continuation identity is present only for direct RtlRaiseException.
     * It survives guest callbacks in this owned API frame, including nesting. */
    ULONG_PTR native_rsp, native_rip;
    ULONG kind, reserved;
    ULONG_PTR reserved2;
};
#ifdef _WIN64
C_ASSERT( sizeof(struct mr_winctx_software_origin) == 64 );
#endif
/* Only the RtlRaiseException-owned frame has this suffix. Keep every existing
   kernelbase/close origin offset and its 88-byte assembly frame unchanged. */
struct mr_winctx_software_baseline
{
    struct mr_winctx_software_origin origin;
    ULONG_PTR original_rbp;
    M128A original_xmm[10];
    ULONG_PTR original_r12, original_r13;
};
#ifdef _WIN64
C_ASSERT( sizeof(struct mr_winctx_software_baseline) == 256 );
#endif
/* Private Wine-native masked update: the public NT Boolean interface cannot
 * express a single atomic partial flag update. Never accepted with key0. */
#define MR_WINCTX_OBJECT_HANDLE_MASK_INFORMATION 0x4d520001u
struct mr_winctx_handle_mask_information { ULONG mask, flags; };
C_ASSERT( sizeof(struct mr_winctx_handle_mask_information) == 8 );

struct mr_winctx_close_origin
{
    ULONG magic, win32;
    struct mr_winctx_software_origin *software;
    ULONG return_pending, close_exception_win32; /* one-shot unix dispatch origin; same reserved word */
    ULONG_PTR return_target;
    ULONG return_flags_ready, return_pf_raw, return_af_raw, return_nzcv;
};
/* These offsets describe the ARM64EC CPU-area page, never an i386 TEB. */
#ifdef _WIN64
C_ASSERT( MR_WINCTX_CLOSE_ORIGIN_OFFSET + FIELD_OFFSET(struct mr_winctx_close_origin, return_pending) == MR_WINCTX_CLOSE_RETURN_PENDING_OFFSET );
C_ASSERT( MR_WINCTX_CLOSE_ORIGIN_OFFSET + FIELD_OFFSET(struct mr_winctx_close_origin, return_target) == MR_WINCTX_CLOSE_RETURN_TARGET_OFFSET );
C_ASSERT( MR_WINCTX_CLOSE_ORIGIN_OFFSET + FIELD_OFFSET(struct mr_winctx_close_origin, return_flags_ready) == MR_WINCTX_RETURN_FLAGS_READY_OFFSET );
C_ASSERT( MR_WINCTX_CLOSE_ORIGIN_OFFSET + FIELD_OFFSET(struct mr_winctx_close_origin, return_pf_raw) == MR_WINCTX_RETURN_PFAF_OFFSET );
C_ASSERT( MR_WINCTX_CLOSE_ORIGIN_OFFSET + FIELD_OFFSET(struct mr_winctx_close_origin, return_nzcv) == MR_WINCTX_RETURN_NZCV_OFFSET );
#endif
static inline void mr_winctx_return_flags(struct mr_winctx_close_origin *origin, ULONG_PTR result_rsp)
{
    /* Hardware queue add-parity-sp-20261006-01: PF is even byte parity.
     * Scalar nibble lookup keeps native XMM0 untouched. Core.cpp:677 uses
     * inverted PF and inverted carry for its internal JIT representation. */
    ULONG low = (ULONG)(result_rsp & 255);
    low ^= low >> 4;
    /* Individually atomic word stores prevent LLVM from packing the private
     * payload with q0 and thereby changing the guest's volatile XMM0. */
    __atomic_store_n( &origin->return_pf_raw, (0x6996u >> (low & 15)) & 1, __ATOMIC_RELAXED );
    __atomic_store_n( &origin->return_af_raw, 0, __ATOMIC_RELAXED );
    __atomic_store_n( &origin->return_nzcv, 1u << 29, __ATOMIC_RELAXED ); /* guest CF=0 */
}
static inline struct mr_winctx_close_origin *mr_winctx_close_origin(void)
{
#if defined(__aarch64__) || defined(__arm64ec__)
    void *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    if (cpu) return (struct mr_winctx_close_origin *)((BYTE *)cpu + MR_WINCTX_CLOSE_ORIGIN_OFFSET);
#endif
    return NULL;
}
static inline void mr_winctx_continue_software(const AMD64_CONTEXT *context)
{
#if defined(__aarch64__) || defined(__arm64ec__)
    struct mr_winctx_close_origin *slot = mr_winctx_close_origin();
    struct mr_winctx_software_origin *token;
    ULONG_PTR limit = (ULONG_PTR)NtCurrentTeb()->Tib.StackLimit;
    ULONG_PTR base = (ULONG_PTR)NtCurrentTeb()->Tib.StackBase;
    ULONG edits = MR_WINCTX_NV_INTEGER | MR_WINCTX_NV_FLOAT;
    void *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    ULONG *edit_mask = cpu ? (void *)((BYTE *)cpu + MR_WINCTX_NV_EDIT_MASK_OFFSET) : NULL;
    struct mr_winctx_nv_baseline *nv_baseline = cpu ? (void *)((BYTE *)cpu + MR_WINCTX_NV_BASELINE_OFFSET) : NULL;
    C_ASSERT( sizeof(struct mr_winctx_nv_baseline) == 48 );
    C_ASSERT( MR_WINCTX_NV_BASELINE_OFFSET >= MR_WINCTX_NV_EDIT_MASK_OFFSET + sizeof(ULONG) );
    C_ASSERT( MR_WINCTX_NV_BASELINE_OFFSET + sizeof(struct mr_winctx_nv_baseline) < MR_WINCTX_NV_RETURN_OFFSET );
    if (nv_baseline) __atomic_store_n(&nv_baseline->valid, 0, __ATOMIC_RELEASE);
    /* No matching dispatch baseline means an explicit authoritative context.
       A matched software dispatch imports only handler edits after the thunk. */
    if (edit_mask) __atomic_store_n(edit_mask, MR_WINCTX_NV_EDIT_MASK_VALID | edits, __ATOMIC_RELEASE);
    if (!slot || slot->magic != MR_WINCTX_CLOSE_ORIGIN_MAGIC || !(token = slot->software)) return;
    if ((ULONG_PTR)token < limit || (ULONG_PTR)(token + 1) > base || !token->native_rip) return;
    /* The captured native caller is the original ientry continuation. Nested
     * exception continuations below it keep this token. A context redirect or
     * unwind above it abandons the API frame and must not keep a stale token. */
    if (context->Rsp < token->native_rsp) return;
    if ((token->kind == 2 || token->kind == 4) &&
        (ULONG_PTR)token <= base - sizeof(struct mr_winctx_software_baseline) &&
        context->Rsp == token->native_rsp && context->Rip == token->native_rip)
    {
        const struct mr_winctx_software_baseline *baseline = (const void *)token;
        unsigned int i;
        edits = context->Rbp != baseline->original_rbp ? MR_WINCTX_NV_INTEGER : 0;
        for (i = 0; i < 10; ++i)
        {
            const M128A *value = &context->FltSave.XmmRegisters[i + 6];
            if (value->Low != baseline->original_xmm[i].Low || value->High != baseline->original_xmm[i].High)
                edits |= 2u << i;
        }
        if (edit_mask) __atomic_store_n(edit_mask, MR_WINCTX_NV_EDIT_MASK_VALID | edits, __ATOMIC_RELEASE);
        /* dispatch_exception saves x19/x20, uses them for native locals, then
           NtContinue bypasses its restoring epilogue. INTEGER=0 ignores guest
           edits. Preserve the captured R12/R13 only for this continuation.
           Other native scratch aliases have separate measured policies. */
        if (nv_baseline && !(context->ContextFlags & 2u))
        {
            nv_baseline->magic = MR_WINCTX_NV_BASELINE_MAGIC;
            nv_baseline->size = sizeof(*nv_baseline);
            nv_baseline->version = MR_WINCTX_VERSION;
            nv_baseline->native_sp = token->native_rsp;
            nv_baseline->native_pc = token->native_rip;
            nv_baseline->r12 = baseline->original_r12;
            nv_baseline->r13 = baseline->original_r13;
            __atomic_store_n(&nv_baseline->valid, 1, __ATOMIC_RELEASE);
        }
    }
    slot->software = token->previous;
    if (token->kind != 2 || context->Rsp != token->native_rsp || context->Rip != token->native_rip || !token->return_target) return;
    slot->return_target = token->return_target;
    mr_winctx_return_flags(slot, token->entry_rsp - 8);
    __atomic_store_n(&slot->return_pending, 2, __ATOMIC_RELEASE);
#else
    /* No ARM64EC CPU-area transport exists on native x86 or i386. */
    (void)context;
#endif
}
static inline BOOL mr_winctx_consume_win32_close(void)
{
    struct mr_winctx_close_origin *origin = mr_winctx_close_origin();
    BOOL win32 = origin && origin->magic == MR_WINCTX_CLOSE_ORIGIN_MAGIC && origin->win32;
    if (origin) origin->win32 = 0;
    return win32;
}

/* The ARM64EC capture's native SP can be a bridge frame, not guest entry RSP.
 * This preinitialized FEX leaf reads the actual most recent guest boundary. */
static inline ULONG_PTR mr_winctx_guest_entry_rsp(void)
{
#ifdef __arm64ec__
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    const struct mr_winctx_fp_query *query;
    ULONG_PTR (WINAPI *get_rsp)(void);
    if (!cpu) return 0;
    query = (const struct mr_winctx_fp_query *)((const BYTE *)cpu + MR_WINCTX_FP_QUERY_OFFSET);
    if (__atomic_load_n( &query->magic, __ATOMIC_ACQUIRE ) != MR_WINCTX_FP_QUERY_MAGIC ||
        query->version != MR_WINCTX_FP_QUERY_VERSION || query->size != sizeof(*query) || !query->current_rsp)
        return 0;
    get_rsp = (void *)query->current_rsp;
    return get_rsp();
#else
    return 0;
#endif
}
#endif
