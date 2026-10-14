/* MacRunner private FEX/Wine context transport. LGPL-2.1-or-later.
 * Versioned tail of an owned native context/frame; never a Windows ABI field.
 * The existing context/record offsets and disallowed ARM64EC registers stay intact.
 */
#ifndef MACRUNNER_WINCTX_ABI_H
#define MACRUNNER_WINCTX_ABI_H
#include <stdint.h>
#define MR_WINCTX_ARM_FLAG 0x01000000u
#define MR_WINCTX_ARM_X64_GROUPS 0x02000000u /* FP/RBP belongs to INTEGER */
#define MR_WINCTX_TAIL_OFFSET 0x480u
#define MR_WINCTX_MAGIC UINT64_C(0x315854434e49574d)
#define MR_WINCTX_VERSION 1u
#define MR_WINCTX_VALID_CONTROL 1u
#define MR_WINCTX_VALID_FLOAT 2u
#define MR_WINCTX_FP_SHADOW_OFFSET 0x800u
#define MR_WINCTX_FP_SHADOW_MAGIC UINT64_C(0x325450465854434d)
#define MR_WINCTX_VALID_YMM 4u
#define MR_WINCTX_FP_QUERY_OFFSET 0x9a0u
#define MR_WINCTX_FP_QUERY_MAGIC UINT64_C(0x315146505854434d)
/* Capabilities use the existing reserved uint16 at offset14. Size48 and all
   callbacks retain ABI4; older kernelbase consumers ignore the new capability. */
#define MR_WINCTX_FP_QUERY_VERSION 4u
#define MR_WINCTX_CAP_MISALIGNED_SSE 1u
#define MR_WINCTX_VIRTUAL_MXCSR_MASK 0x2ffffu
#define MR_WINCTX_GUEST_ENTRY_RSP_OFFSET 0x9d0u
#define MR_WINCTX_GUEST_ENTRY_TARGET_OFFSET 0x9d8u
#define MR_WINCTX_GUEST_ENTRY_XMM_OFFSET 0xa80u /* 0114: XMM0-5 гостя на входе в родной вызов (пишет FEX в ExitFunctionEC), 6x16 байт */
#define MR_WINCTX_CLOSE_RETURN_PENDING_OFFSET 0xf10u
#define MR_WINCTX_CLOSE_RETURN_TARGET_OFFSET 0xf18u
#define MR_WINCTX_RETURN_FLAGS_READY_OFFSET 0xf20u
#define MR_WINCTX_RETURN_PFAF_OFFSET 0xf24u
#define MR_WINCTX_RETURN_NZCV_OFFSET 0xf2cu
/* Explicit AMD64 continuation edits must survive the compiler's native
 * ARM64EC entry-thunk epilogue. It restores x29 and q6..q15 from its own
 * earlier spills. Keep this payload outside native CONTEXT register aliases;
 * FEX imports it only after that epilogue, on a return to guest code. */
#define MR_WINCTX_NV_RETURN_OFFSET 0xc00u
#define MR_WINCTX_NV_EDIT_MASK_OFFSET 0xb00u
#define MR_WINCTX_NV_EDIT_MASK_VALID 0x80000000u
/* Same-frame native software continuation baseline; no handler edits. */
#define MR_WINCTX_NV_BASELINE_OFFSET 0xb10u
#define MR_WINCTX_NV_BASELINE_MAGIC UINT64_C(0x314253585443524d)
struct mr_winctx_nv_baseline
{
    uint64_t magic;
    uint32_t size;
    uint16_t version, valid;
    uint64_t native_sp, native_pc;
    uint64_t r12, r13;
};
#define MR_WINCTX_NV_RETURN_MAGIC UINT64_C(0x31564e585443524d)
#define MR_WINCTX_NV_INTEGER 1u
#define MR_WINCTX_NV_FLOAT 0x7feu /* individual bits1..10: XMM6..15 */
struct mr_winctx_nv_return
{
    uint64_t magic;
    uint32_t size;
    uint16_t version;
    uint16_t valid;
    uint64_t native_sp; /* nested entry thunks below this frame cannot consume */
    uint64_t rbp;
    uint8_t xmm[10][16]; /* low 128 bits of XMM6..15 */
};
/* Stack-owned snapshot: x87 slots use logical ST(0)..ST(7), ten significant
 * bytes and zero padding. No native ARM64EC register aliases are present. */
struct mr_winctx_fp_snapshot
{
    uint32_t mxcsr;
    uint16_t fcw;
    uint16_t fsw;
    uint8_t ftw;
    uint8_t reserved[7];
    uint8_t x87[8][16];
};
/* Initialized once by ThreadInit, outside signal dispatch.  The native leaf
 * reads current virtual FP control; UINT32_MAX means no current guest state. */
struct mr_winctx_fp_query
{
    uint64_t magic;
    uint32_t size;
    uint16_t version;
    uint16_t capabilities;
    uint64_t current_fcw;
    uint64_t current_mxcsr;
    uint64_t capture_fp;
    uint64_t current_rsp;
};
struct mr_winctx_fp_shadow
{
    uint64_t magic;
    uint32_t size;
    uint16_t version;
    uint16_t valid; /* release-published, consumed once by the same thread */
    uint32_t mxcsr;
    uint16_t fcw;
    uint16_t fsw;
    uint8_t ftw;
    uint8_t reserved[7];
    uint8_t x87[8][16];
    uint8_t ymm[16][16];
};
/* Guest AMD64 DR state in the already owned first CHPE page.  Never ARM
 * hardware breakpoints. Native server BVR/BCR arrays carry the same six words
 * while a target is suspended or has not entered FEX yet. */
#define MR_WINCTX_DEBUG_OFFSET 0xa00u
#define MR_WINCTX_DEBUG_MAGIC UINT64_C(0x314742445854434d)
#define MR_WINCTX_DEBUG_ARM_MAGIC 0x58444231u
#define MR_WINCTX_DEBUG_VERSION 1u
struct mr_winctx_debug_state
{
    uint64_t magic;
    uint32_t size;
    uint16_t version;
    uint16_t valid;
    uint64_t dr[6]; /* DR0, DR1, DR2, DR3, DR6, DR7 */
};

/* Observed on both Windows AMD references in v5c80: a DEBUG Set with
 * DR7==0 ignores DR0..3. Do not generalize to other reserved/control bits
 * before the Windows policy matrix has been measured. */
static inline void mr_winctx_debug_disabled_policy(uint64_t dr[6])
{
    if (dr[5] == 0) dr[0] = dr[1] = dr[2] = dr[3] = 0;
}

struct mr_winctx_tail
{
    uint64_t magic;
    uint32_t size;
    uint16_t version;
    uint16_t valid;
    uint32_t eflags;
    uint32_t mxcsr;
    uint16_t fcw;
    uint16_t fsw;
    uint8_t ftw;
    uint8_t reserved[3];
};
#endif
