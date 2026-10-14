/*
 * Exception unwinding definitions
 *
 * Copyright 2023 Alexandre Julliard
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

#ifndef __WINE_NTDLL_UNWIND_H
#define __WINE_NTDLL_UNWIND_H

#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/macrunner_winctx.h"

#if defined(__aarch64__) || defined(__arm64ec__)

/* Only contexts allocated by the private transport carry this flag/tail. */
#define MR_WINCTX_ARM_YMM_FLAG 0x40u /* existing FEX native V16..V31 packing */
struct mr_winctx_arm_context
{
    ARM64_NT_CONTEXT context;
    BYTE reserved[MR_WINCTX_TAIL_OFFSET - sizeof(ARM64_NT_CONTEXT)];
    struct mr_winctx_tail tail;
};
C_ASSERT( sizeof(struct mr_winctx_tail) == 32 );
C_ASSERT( offsetof(struct mr_winctx_arm_context, tail) == MR_WINCTX_TAIL_OFFSET );

static inline const struct mr_winctx_tail *mr_winctx_get_tail( const ARM64_NT_CONTEXT *context )
{
    const struct mr_winctx_tail *tail;
    if (!(context->ContextFlags & MR_WINCTX_ARM_FLAG)) return NULL;
    tail = (const struct mr_winctx_tail *)((const BYTE *)context + MR_WINCTX_TAIL_OFFSET);
    if (tail->magic != MR_WINCTX_MAGIC || tail->version != MR_WINCTX_VERSION || tail->size != sizeof(*tail)) return NULL;
    return tail;
}

/* This callback is native ARM64EC, installed before guest entry.  No loader
   lookup, allocation, or first-use initialization occurs during dispatch. */
#ifdef __arm64ec__
static inline ULONG mr_winctx_current_fp_control(BOOL mxcsr)
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    const struct mr_winctx_fp_query *query;
    ULONG (WINAPI *get_control)(void);
    ULONG_PTR callback;
    if (!cpu) return UINT32_MAX;
    query = (const struct mr_winctx_fp_query *)((const BYTE *)cpu + MR_WINCTX_FP_QUERY_OFFSET);
    if (__atomic_load_n( &query->magic, __ATOMIC_ACQUIRE ) != MR_WINCTX_FP_QUERY_MAGIC ||
        query->version != MR_WINCTX_FP_QUERY_VERSION || query->size != sizeof(*query))
        return UINT32_MAX;
    callback = mxcsr ? query->current_mxcsr : query->current_fcw;
    if (!callback) return UINT32_MAX;
    get_control = (void *)callback;
    return get_control();
}
#define mr_winctx_current_fcw() mr_winctx_current_fp_control(FALSE)
#define mr_winctx_current_mxcsr() mr_winctx_current_fp_control(TRUE)
C_ASSERT( sizeof(struct mr_winctx_fp_query) == 48 );
C_ASSERT( MR_WINCTX_FP_QUERY_OFFSET + sizeof(struct mr_winctx_fp_query) < 0x1000 );
static inline BOOL mr_winctx_capture_fp( struct mr_winctx_fp_snapshot *snapshot )
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    const struct mr_winctx_fp_query *query;
    ULONG (WINAPI *capture)(struct mr_winctx_fp_snapshot *, ULONG);
    C_ASSERT( sizeof(struct mr_winctx_fp_snapshot) == 144 );
    if (!cpu) return FALSE;
    query = (const struct mr_winctx_fp_query *)((const BYTE *)cpu + MR_WINCTX_FP_QUERY_OFFSET);
    if (__atomic_load_n( &query->magic, __ATOMIC_ACQUIRE ) != MR_WINCTX_FP_QUERY_MAGIC ||
        query->version != MR_WINCTX_FP_QUERY_VERSION || query->size != sizeof(*query) || !query->capture_fp)
        return FALSE;
    capture = (void *)query->capture_fp;
    return capture( snapshot, sizeof(*snapshot) ) != 0;
}
#endif

/* The first CPU-area page is reserved below EmulatorStackLimit.  Context,
   CONTEXT_EX and AVX end before 0x700; this private 416-byte payload ends
   at 0x9a0.  Native EC continuation has no x87 environment or YMM-high ABI. */
static inline void mr_winctx_publish_fp_shadow_from( const AMD64_CONTEXT *context,
                                                     const struct mr_winctx_fp_snapshot *native_x87 )
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    struct mr_winctx_fp_shadow *shadow;
    unsigned short valid = MR_WINCTX_VALID_FLOAT;
    ULONG length = 0;
    const void *ymm;
    C_ASSERT( sizeof(struct mr_winctx_fp_shadow) == 416 );
    C_ASSERT( MR_WINCTX_FP_SHADOW_OFFSET + sizeof(struct mr_winctx_fp_shadow) < 0x1000 );
    if (!cpu || (context->ContextFlags & CONTEXT_AMD64_FLOATING_POINT) != CONTEXT_AMD64_FLOATING_POINT) return;
    shadow = (struct mr_winctx_fp_shadow *)((BYTE *)cpu + MR_WINCTX_FP_SHADOW_OFFSET);
    if (shadow->magic == MR_WINCTX_FP_SHADOW_MAGIC && shadow->version == MR_WINCTX_VERSION &&
        shadow->size == sizeof(*shadow))
        valid |= __atomic_load_n( &shadow->valid, __ATOMIC_ACQUIRE ) & MR_WINCTX_VALID_YMM;
    __atomic_store_n( &shadow->valid, 0, __ATOMIC_RELEASE );
    shadow->magic = MR_WINCTX_FP_SHADOW_MAGIC;
    shadow->version = MR_WINCTX_VERSION;
    shadow->size = sizeof(*shadow);
    shadow->mxcsr = context->MxCsr;
    shadow->fcw = native_x87 ? native_x87->fcw : context->FltSave.ControlWord;
    shadow->fsw = native_x87 ? native_x87->fsw : context->FltSave.StatusWord;
    shadow->ftw = native_x87 ? native_x87->ftw : context->FltSave.TagWord;
    memcpy( shadow->x87, native_x87 ? (const void *)native_x87->x87 :
            (const void *)context->FltSave.FloatRegisters, sizeof(shadow->x87) );
    if ((context->ContextFlags & CONTEXT_AMD64_XSTATE) == CONTEXT_AMD64_XSTATE)
    {
        ymm = RtlLocateExtendedFeature( (CONTEXT_EX *)(context + 1), XSTATE_AVX, &length );
        if (ymm && length >= sizeof(shadow->ymm))
        {
            memcpy( shadow->ymm, ymm, sizeof(shadow->ymm) );
            valid |= MR_WINCTX_VALID_YMM;
        }
    }
    __atomic_store_n( &shadow->valid, valid, __ATOMIC_RELEASE );
}

static inline void mr_winctx_publish_fp_shadow( const AMD64_CONTEXT *context )
{
    mr_winctx_publish_fp_shadow_from( context, NULL );
}

/* A private debug packet is accepted only with the native DEBUG group
 * and its complete marker. Bare ARM contexts retain their own ABI. */
static inline BOOL mr_winctx_debug_arm_valid( const ARM64_NT_CONTEXT *arm )
{
    return (arm->ContextFlags & CONTEXT_ARM64_DEBUG_REGISTERS) == CONTEXT_ARM64_DEBUG_REGISTERS &&
           arm->Bcr[0] == MR_WINCTX_DEBUG_ARM_MAGIC &&
           arm->Bcr[1] == MR_WINCTX_DEBUG_VERSION &&
           arm->Bcr[2] == sizeof(struct mr_winctx_debug_state);
}
static inline void mr_winctx_debug_arm_mark( ARM64_NT_CONTEXT *arm )
{
    memset( arm->Bcr, 0, sizeof(arm->Bcr) );
    arm->Bcr[0] = MR_WINCTX_DEBUG_ARM_MAGIC;
    arm->Bcr[1] = MR_WINCTX_DEBUG_VERSION;
    arm->Bcr[2] = sizeof(struct mr_winctx_debug_state);
    arm->ContextFlags |= CONTEXT_ARM64_DEBUG_REGISTERS;
}
static inline void mr_winctx_debug_pack( ARM64_NT_CONTEXT *arm, const AMD64_CONTEXT *guest )
{
    if ((guest->ContextFlags & CONTEXT_AMD64_DEBUG_REGISTERS) != CONTEXT_AMD64_DEBUG_REGISTERS) return;
    uint64_t values[6];
    memcpy( values, &guest->Dr0, sizeof(values) );
    mr_winctx_debug_disabled_policy(values);
    memcpy( arm->Bvr, values, sizeof(values) );
    mr_winctx_debug_arm_mark( arm );
}
static inline struct mr_winctx_debug_state *mr_winctx_debug_current(void)
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    C_ASSERT( sizeof(struct mr_winctx_debug_state) == 64 );
    C_ASSERT( MR_WINCTX_DEBUG_OFFSET >= MR_WINCTX_GUEST_ENTRY_TARGET_OFFSET + sizeof(uint64_t) );
    C_ASSERT( MR_WINCTX_DEBUG_OFFSET + sizeof(struct mr_winctx_debug_state) < MR_WINCTX_CLOSE_RETURN_PENDING_OFFSET );
    return cpu ? (struct mr_winctx_debug_state *)((BYTE *)cpu + MR_WINCTX_DEBUG_OFFSET) : NULL;
}
static inline void mr_winctx_debug_publish( const ARM64_NT_CONTEXT *arm )
{
    struct mr_winctx_debug_state *state = mr_winctx_debug_current();
    if (!state || !mr_winctx_debug_arm_valid(arm)) return;
    __atomic_store_n( &state->valid, 0, __ATOMIC_RELEASE );
    memcpy( state->dr, arm->Bvr, sizeof(state->dr) );
    state->magic = MR_WINCTX_DEBUG_MAGIC;
    state->size = sizeof(*state);
    state->version = MR_WINCTX_DEBUG_VERSION;
    __atomic_store_n( &state->valid, 1, __ATOMIC_RELEASE );
}
static inline void mr_winctx_debug_read_current( ARM64_NT_CONTEXT *arm )
{
    const struct mr_winctx_debug_state *state = mr_winctx_debug_current();
    if (state && __atomic_load_n(&state->valid,__ATOMIC_ACQUIRE) &&
        state->magic == MR_WINCTX_DEBUG_MAGIC && state->size == sizeof(*state) &&
        state->version == MR_WINCTX_DEBUG_VERSION)
        memcpy( arm->Bvr, state->dr, sizeof(state->dr) );
    else if (!mr_winctx_debug_arm_valid(arm))
        memset( arm->Bvr, 0, sizeof(arm->Bvr) ); /* fresh thread, no pending Set */
    mr_winctx_debug_arm_mark(arm);
}

static inline void mr_winctx_pack_tail( struct mr_winctx_arm_context *arm, const AMD64_CONTEXT *context )
{
    struct mr_winctx_tail *tail = &arm->tail;
    mr_winctx_debug_pack( &arm->context, context );
    memset( tail, 0, sizeof(*tail) );
    tail->magic = MR_WINCTX_MAGIC;
    tail->size = sizeof(*tail);
    tail->version = MR_WINCTX_VERSION;
    if ((context->ContextFlags & CONTEXT_AMD64_CONTROL) == CONTEXT_AMD64_CONTROL)
    {
        tail->valid |= MR_WINCTX_VALID_CONTROL;
        tail->eflags = context->EFlags;
    }
    if ((context->ContextFlags & CONTEXT_AMD64_FLOATING_POINT) == CONTEXT_AMD64_FLOATING_POINT)
    {
        tail->valid |= MR_WINCTX_VALID_FLOAT;
        tail->mxcsr = context->MxCsr;
        tail->fcw = context->FltSave.ControlWord;
        tail->fsw = context->FltSave.StatusWord;
        tail->ftw = context->FltSave.TagWord;
    }
    arm->context.ContextFlags |= MR_WINCTX_ARM_FLAG | MR_WINCTX_ARM_X64_GROUPS;
    if ((context->ContextFlags & CONTEXT_AMD64_XSTATE) == CONTEXT_AMD64_XSTATE)
    {
        ULONG length = 0;
        const void *ymm = RtlLocateExtendedFeature( (CONTEXT_EX *)(context + 1), XSTATE_AVX, &length );
        if (ymm && length >= sizeof(arm->context.V[0]) * 16)
        {
            memcpy( arm->context.V + 16, ymm, sizeof(arm->context.V[0]) * 16 );
            arm->context.ContextFlags |= MR_WINCTX_ARM_YMM_FLAG;
        }
    }
}

/* Caller guarantees room for CONTEXT_EX, 63-byte alignment and AVX state.
 * Use only on the extended exception frame or the reserved first CPU-area page.
 * The ordinary converters accept bare contexts and must never write this tail. */
static inline void mr_winctx_unpack_xstate( ARM64EC_NT_CONTEXT *ec, const ARM64_NT_CONTEXT *arm )
{
    const struct mr_winctx_tail *tail = mr_winctx_get_tail( arm );
    CONTEXT_EX *ex = (CONTEXT_EX *)(ec + 1);
    XSTATE *xs;
    if (!tail || !(tail->valid & MR_WINCTX_VALID_FLOAT)) return;
    ec->ContextFlags |= CONTEXT_AMD64_SEGMENTS | CONTEXT_AMD64_DEBUG_REGISTERS;
    if (!(arm->ContextFlags & MR_WINCTX_ARM_YMM_FLAG)) return;
    xs = (XSTATE *)(((ULONG_PTR)(ex + 1) + 63) & ~(ULONG_PTR)63);
    memset( ex, 0, sizeof(*ex) );
    memset( xs, 0, sizeof(*xs) );
    ex->Legacy.Offset = ex->All.Offset = -(LONG)sizeof(*ec);
    ex->Legacy.Length = sizeof(*ec);
    ex->XState.Offset = (BYTE *)xs - (BYTE *)ex;
    ex->XState.Length = sizeof(*xs);
    ex->All.Length = sizeof(*ec) + ex->XState.Offset + ex->XState.Length;
    xs->Mask = (ULONG64)1 << XSTATE_AVX;
    /* Accepted by the shared helper in either standard or compacted mode;
       AVX is the first extended feature and starts after the 64-byte header. */
    xs->CompactionMask = ((ULONG64)1 << 63) | xs->Mask;
    memcpy( &xs->YmmContext, arm->V + 16, sizeof(xs->YmmContext) );
    ec->ContextFlags |= CONTEXT_AMD64_XSTATE;
}

/* MacRunner 2026-09-04 — перенос из Wine 11.16 (commit 8c284041138d, «ntdll: Preserve exception
 * flags when converting between x64 and arm64 context flags»); у нас дерево 11.0.
 *
 * ЧТО ЧИНИТ: обе перекодировки ниже собирали результат с нуля — CONTEXT_ARM64 / CONTEXT_AMD64
 * плюс три бита состава (CONTROL/INTEGER/FLOATING_POINT). Биты ОТЧЁТНОСТИ об исключении
 * (ACTIVE / SERVICE_ACTIVE / REQUEST / REPORTING) при этом молча терялись на каждом переходе
 * между видами контекста. У нас граница x64↔arm64 проходится на каждом переключении гостя,
 * поэтому запрос «сообщи, было ли исключение» до получателя не доезжал вовсе. */
static const ULONG exception_flags_mask = CONTEXT_EXCEPTION_ACTIVE |
    CONTEXT_SERVICE_ACTIVE | CONTEXT_EXCEPTION_REQUEST | CONTEXT_EXCEPTION_REPORTING;

/* Query is published before guest entry. No loader walk or initialization. */
static inline ULONG mr_winctx_virtual_mxcsr_mask(void)
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    const struct mr_winctx_fp_query *query;
    if (!cpu) return 0;
    query = (const struct mr_winctx_fp_query *)((const BYTE *)cpu + MR_WINCTX_FP_QUERY_OFFSET);
    if (__atomic_load_n( &query->magic, __ATOMIC_ACQUIRE ) != MR_WINCTX_FP_QUERY_MAGIC ||
        query->version != MR_WINCTX_FP_QUERY_VERSION || query->size != sizeof(*query)) return 0;
    return (query->capabilities & MR_WINCTX_CAP_MISALIGNED_SSE) ? MR_WINCTX_VIRTUAL_MXCSR_MASK : 0xffff;
}

static inline ULONG ctx_flags_x64_to_arm( ULONG flags )
{
    ULONG ret = CONTEXT_ARM64 | (flags & exception_flags_mask);

    flags &= ~CONTEXT_AMD64;
    if (flags & CONTEXT_AMD64_CONTROL) ret |= CONTEXT_ARM64_CONTROL;
    if (flags & CONTEXT_AMD64_INTEGER) ret |= CONTEXT_ARM64_INTEGER;
    if (flags & CONTEXT_AMD64_FLOATING_POINT) ret |= CONTEXT_ARM64_FLOATING_POINT;
    return ret;
}

static inline ULONG ctx_flags_arm_to_x64( ULONG flags )
{
    ULONG ret = CONTEXT_AMD64 | (flags & exception_flags_mask);

    flags &= ~CONTEXT_ARM64;
    if (flags & CONTEXT_ARM64_CONTROL) ret |= CONTEXT_AMD64_CONTROL;
    if (flags & CONTEXT_ARM64_INTEGER) ret |= CONTEXT_AMD64_INTEGER;
    if (flags & CONTEXT_ARM64_FLOATING_POINT) ret |= CONTEXT_AMD64_FLOATING_POINT;
    return ret;
}

static inline UINT eflags_to_cpsr( UINT eflags )
{
    UINT ret = 0;

    if (eflags & 0x0001) ret |= 0x20000000;  /* carry */
    if (eflags & 0x0040) ret |= 0x40000000;  /* zero */
    if (eflags & 0x0080) ret |= 0x80000000;  /* negative */
    if (eflags & 0x0100) ret |= 0x00200000;  /* trap */
    if (eflags & 0x0800) ret |= 0x10000000;  /* overflow */
    return ret;
}

static inline UINT cpsr_to_eflags( UINT cpsr )
{
    UINT ret = 0x202;

    if (cpsr & 0x00200000) ret |= 0x0100;  /* trap */
    if (cpsr & 0x10000000) ret |= 0x0800;  /* overflow */
    if (cpsr & 0x20000000) ret |= 0x0001;  /* carry */
    if (cpsr & 0x40000000) ret |= 0x0040;  /* zero */
    if (cpsr & 0x80000000) ret |= 0x0080;  /* negative */
    return ret;
}

static inline UINT64 mxcsr_to_fpcsr( UINT mxcsr )
{
    UINT fpcr = 0, fpsr = 0;

    if (mxcsr & 0x0001) fpsr |= 0x0001;    /* invalid operation */
    if (mxcsr & 0x0002) fpsr |= 0x0080;    /* denormal */
    if (mxcsr & 0x0004) fpsr |= 0x0002;    /* zero-divide */
    if (mxcsr & 0x0008) fpsr |= 0x0004;    /* overflow */
    if (mxcsr & 0x0010) fpsr |= 0x0008;    /* underflow */
    if (mxcsr & 0x0020) fpsr |= 0x0010;    /* precision */

    if (mxcsr & 0x0040)    fpcr |= 0x80000;   /* denormals are zero */
    if (!(mxcsr & 0x0080)) fpcr |= 0x0100;    /* invalid operation mask */
    if (!(mxcsr & 0x0100)) fpcr |= 0x8000;    /* denormal mask */
    if (!(mxcsr & 0x0200)) fpcr |= 0x0200;    /* zero-divide mask */
    if (!(mxcsr & 0x0400)) fpcr |= 0x0400;    /* overflow mask */
    if (!(mxcsr & 0x0800)) fpcr |= 0x0800;    /* underflow mask */
    if (!(mxcsr & 0x1000)) fpcr |= 0x1000;    /* precision mask */
    if (mxcsr & 0x2000)    fpcr |= 0x800000;  /* round down */
    if (mxcsr & 0x4000)    fpcr |= 0x400000;  /* round up */
    if (mxcsr & 0x8000)    fpcr |= 0x1000000; /* flush to zero */
    return fpcr | ((UINT64)fpsr << 32);
}

static inline UINT fpcsr_to_mxcsr( UINT fpcr, UINT fpsr )
{
    UINT ret = 0;

    if (fpsr & 0x0001) ret |= 0x0001;      /* invalid operation */
    if (fpsr & 0x0002) ret |= 0x0004;      /* zero-divide */
    if (fpsr & 0x0004) ret |= 0x0008;      /* overflow */
    if (fpsr & 0x0008) ret |= 0x0010;      /* underflow */
    if (fpsr & 0x0010) ret |= 0x0020;      /* precision */
    if (fpsr & 0x0080) ret |= 0x0002;      /* denormal */

    if (fpcr & 0x0080000)    ret |= 0x0040;   /* denormals are zero */
    if (!(fpcr & 0x0000100)) ret |= 0x0080;   /* invalid operation mask */
    if (!(fpcr & 0x0000200)) ret |= 0x0200;   /* zero-divide mask */
    if (!(fpcr & 0x0000400)) ret |= 0x0400;   /* overflow mask */
    if (!(fpcr & 0x0000800)) ret |= 0x0800;   /* underflow mask */
    if (!(fpcr & 0x0001000)) ret |= 0x1000;   /* precision mask */
    if (!(fpcr & 0x0008000)) ret |= 0x0100;   /* denormal mask */
    if (fpcr & 0x0400000)    ret |= 0x4000;   /* round up */
    if (fpcr & 0x0800000)    ret |= 0x2000;   /* round down */
    if (fpcr & 0x1000000)    ret |= 0x8000;   /* flush to zero */
    return ret;
}

static inline void context_x64_to_arm( ARM64_NT_CONTEXT *arm_ctx, const ARM64EC_NT_CONTEXT *ec_ctx )
{
    UINT64 fpcsr;

    arm_ctx->ContextFlags = ctx_flags_x64_to_arm( ec_ctx->ContextFlags );
    arm_ctx->Cpsr = eflags_to_cpsr( ec_ctx->AMD64_EFlags );
    arm_ctx->X0   = ec_ctx->X0;
    arm_ctx->X1   = ec_ctx->X1;
    arm_ctx->X2   = ec_ctx->X2;
    arm_ctx->X3   = ec_ctx->X3;
    arm_ctx->X4   = ec_ctx->X4;
    arm_ctx->X5   = ec_ctx->X5;
    arm_ctx->X6   = ec_ctx->X6;
    arm_ctx->X7   = ec_ctx->X7;
    arm_ctx->X8   = ec_ctx->X8;
    arm_ctx->X9   = ec_ctx->X9;
    arm_ctx->X10  = ec_ctx->X10;
    arm_ctx->X11  = ec_ctx->X11;
    arm_ctx->X12  = ec_ctx->X12;
    arm_ctx->X13  = 0;
    arm_ctx->X14  = 0;
    arm_ctx->X15  = ec_ctx->X15;
    arm_ctx->X16  = ec_ctx->X16_0 | ((DWORD64)ec_ctx->X16_1 << 16) | ((DWORD64)ec_ctx->X16_2 << 32) | ((DWORD64)ec_ctx->X16_3 << 48);
    arm_ctx->X17  = ec_ctx->X17_0 | ((DWORD64)ec_ctx->X17_1 << 16) | ((DWORD64)ec_ctx->X17_2 << 32) | ((DWORD64)ec_ctx->X17_3 << 48);
    arm_ctx->X18  = 0;
    arm_ctx->X19  = ec_ctx->X19;
    arm_ctx->X20  = ec_ctx->X20;
    arm_ctx->X21  = ec_ctx->X21;
    arm_ctx->X22  = ec_ctx->X22;
    arm_ctx->X23  = 0;
    arm_ctx->X24  = 0;
    arm_ctx->X25  = ec_ctx->X25;
    arm_ctx->X26  = ec_ctx->X26;
    arm_ctx->X27  = ec_ctx->X27;
    arm_ctx->X28  = 0;
    arm_ctx->Fp   = ec_ctx->Fp;
    arm_ctx->Lr   = ec_ctx->Lr;
    arm_ctx->Sp   = ec_ctx->Sp;
    arm_ctx->Pc   = ec_ctx->Pc;
    memcpy( arm_ctx->V, ec_ctx->V, 16 * sizeof(arm_ctx->V[0]) );
    memset( arm_ctx->V + 16, 0, sizeof(*arm_ctx) - offsetof( ARM64_NT_CONTEXT, V[16] ));
    fpcsr = mxcsr_to_fpcsr( ec_ctx->AMD64_MxCsr );
    arm_ctx->Fpcr = fpcsr;
    arm_ctx->Fpsr = fpcsr >> 32;
}

static inline void context_arm_to_x64( ARM64EC_NT_CONTEXT *ec_ctx, const ARM64_NT_CONTEXT *arm_ctx )
{
    memset( ec_ctx, 0, sizeof(*ec_ctx) );
    ec_ctx->ContextFlags = ctx_flags_arm_to_x64( arm_ctx->ContextFlags );
    ec_ctx->AMD64_SegCs  = 0x33;
    ec_ctx->AMD64_SegDs  = 0x2b;
    ec_ctx->AMD64_SegEs  = 0x2b;
    ec_ctx->AMD64_SegFs  = 0x53;
    ec_ctx->AMD64_SegGs  = 0x2b;
    ec_ctx->AMD64_SegSs  = 0x2b;
    ec_ctx->AMD64_EFlags = cpsr_to_eflags( arm_ctx->Cpsr );
    ec_ctx->AMD64_Context.FltSave.MxCsr_Mask = mr_winctx_virtual_mxcsr_mask();
    ec_ctx->AMD64_MxCsr  = ec_ctx->AMD64_MxCsr_copy = fpcsr_to_mxcsr( arm_ctx->Fpcr, arm_ctx->Fpsr );

    ec_ctx->X8    = arm_ctx->X8;
    ec_ctx->X0    = arm_ctx->X0;
    ec_ctx->X1    = arm_ctx->X1;
    ec_ctx->X27   = arm_ctx->X27;
    ec_ctx->Sp    = arm_ctx->Sp;
    ec_ctx->Fp    = arm_ctx->Fp;
    ec_ctx->X25   = arm_ctx->X25;
    ec_ctx->X26   = arm_ctx->X26;
    ec_ctx->X2    = arm_ctx->X2;
    ec_ctx->X3    = arm_ctx->X3;
    ec_ctx->X4    = arm_ctx->X4;
    ec_ctx->X5    = arm_ctx->X5;
    ec_ctx->X19   = arm_ctx->X19;
    ec_ctx->X20   = arm_ctx->X20;
    ec_ctx->X21   = arm_ctx->X21;
    ec_ctx->X22   = arm_ctx->X22;
    ec_ctx->Pc    = arm_ctx->Pc;
    ec_ctx->Lr    = arm_ctx->Lr;
    ec_ctx->X6    = arm_ctx->X6;
    ec_ctx->X7    = arm_ctx->X7;
    ec_ctx->X9    = arm_ctx->X9;
    ec_ctx->X10   = arm_ctx->X10;
    ec_ctx->X11   = arm_ctx->X11;
    ec_ctx->X12   = arm_ctx->X12;
    ec_ctx->X15   = arm_ctx->X15;
    ec_ctx->X16_0 = arm_ctx->X16;
    ec_ctx->X16_1 = arm_ctx->X16 >> 16;
    ec_ctx->X16_2 = arm_ctx->X16 >> 32;
    ec_ctx->X16_3 = arm_ctx->X16 >> 48;
    ec_ctx->X17_0 = arm_ctx->X17;
    ec_ctx->X17_1 = arm_ctx->X17 >> 16;
    ec_ctx->X17_2 = arm_ctx->X17 >> 32;
    ec_ctx->X17_3 = arm_ctx->X17 >> 48;

    memcpy( ec_ctx->V, arm_ctx->V, sizeof(ec_ctx->V) );
    if (mr_winctx_debug_arm_valid(arm_ctx))
    {
        memcpy( &ec_ctx->AMD64_Context.Dr0, arm_ctx->Bvr, 6 * sizeof(arm_ctx->Bvr[0]) );
        ec_ctx->ContextFlags |= CONTEXT_AMD64_DEBUG_REGISTERS;
    }

    {
        const struct mr_winctx_tail *tail = mr_winctx_get_tail( arm_ctx );
        if (tail && (tail->valid & MR_WINCTX_VALID_CONTROL)) ec_ctx->AMD64_EFlags = tail->eflags;
        if (tail && (tail->valid & MR_WINCTX_VALID_FLOAT))
        {
            ec_ctx->AMD64_MxCsr = ec_ctx->AMD64_MxCsr_copy = tail->mxcsr;
            ec_ctx->AMD64_Context.FltSave.ControlWord = tail->fcw;
            ec_ctx->AMD64_Context.FltSave.StatusWord = tail->fsw;
            ec_ctx->AMD64_Context.FltSave.TagWord = tail->ftw;
        }
    }
}

#endif /* __aarch64__ || __arm64ec__ */

#endif /* __WINE_NTDLL_UNWIND_H */
