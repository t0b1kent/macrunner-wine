#include "hb_env.h"
#include "hb_gates.h"
#include "hb_probe.h"
#include "hb_runtime.h"
#include "hb_memory.h"
#include "hb_flags.h"
#include "hb_x87.h"
#include "hb_cpuid.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <math.h>

/* Регистрация кеша гейта в общем сбросе — см. hb_codegen.h. */


static const char* ir_op_name(hb_ir_op_t op);

static _Thread_local const hb_ir_instr_t* trace_current_instr;
static _Thread_local unsigned int trace_runtime_flags;

enum {
    TRACE_FLAG_MEM_WATCH     = 1u << 0,
    TRACE_FLAG_NATIVE_WRITES = 1u << 1,
    TRACE_FLAG_STACK_FAULTS  = 1u << 2,
    TRACE_FLAG_ATOMICS       = 1u << 3,
    TRACE_FLAG_FAULTS        = 1u << 4,
    TRACE_FLAG_PC            = 1u << 5,
    TRACE_FLAG_STRCPY        = 1u << 6,
    TRACE_FLAG_BRANCHES      = 1u << 7,
    TRACE_FLAG_SIMD          = 1u << 8,
    TRACE_FLAG_SIMD_DATA     = 1u << 9,
    TRACE_FLAG_BITOPS        = 1u << 10,
};

static inline void sync_arch_pc(hb_context_t* ctx) {
    if (ctx->arch == HB_ARCH_X64) ctx->regs.x64.rip = ctx->pc;
    else if (ctx->arch == HB_ARCH_X86) ctx->regs.x86.eip = (uint32_t)ctx->pc;
}

static bool trace_env_enabled(const char* name) {
    const char* val = hb_env(name);
    return val && val[0] && val[0] != '0';
}

/* MacRunner (2026-06-17 — getenv-per-instruction storm fix, Lane A HK profiled run):
 * the per-instruction interpreter trace gates below used to call hb_env() on EVERY
 * interpreted instruction even with tracing OFF (e.g. trace_bitops_selected read
 * BITOPS_START/END before checking its enable flag). hb_env() takes the libc environ
 * lock (__findenv_locked); under the multi-thread interpreter fallback that kicks in
 * when the JIT code cache fills, that became an _os_unfair_lock_lock_slow/__ulock_wait2
 * contention storm burning ~66% of CPU (HK livelocked at D3D11-device-created, never
 * reaching swapchain). Fix: snapshot every trace env var ONCE into trace_cfg and read
 * the cache thereafter. Values reflect startup env (these are debug knobs set before
 * launch; runtime env changes are intentionally not re-read). */
typedef struct {
    unsigned int flags;                                  /* TRACE_FLAG_* bitset */
    bool mw_range_set;        uint64_t mw_start, mw_end;
    bool mw_pc_set;           uint64_t mw_pc_start, mw_pc_end;
    unsigned int mw_budget;
    bool bitops_range_set;    uint64_t bitops_start, bitops_end;
    unsigned int bitops_budget;
    bool branch_range_set;    uint64_t branch_start, branch_end;
    unsigned int branch_budget;
    bool pc_list_set;         char pc_list[256];
    unsigned int pc_limit;
    unsigned int strcpy_limit;
    unsigned int simd_budget;
    bool simd_data_range_set; uint64_t simd_data_start, simd_data_end;
    unsigned int simd_data_budget;
} hb_trace_cfg_t;

static hb_trace_cfg_t trace_cfg;   /* zero-init => tracing OFF / no range = the safe default */

static void hb_trace_parse_range(const char* sname, const char* ename,
                                 bool* set, uint64_t* lo, uint64_t* hi) {
    const char* s = hb_env(sname);
    const char* e = hb_env(ename);
    if (s && s[0]) {
        *set = true;
        *lo = strtoull(s, NULL, 0);
        *hi = (e && e[0]) ? strtoull(e, NULL, 0) : *lo;
        if (*hi < *lo) *hi = *lo;
    }
}

/* clamp=true keeps the original "0<p<100000 else default" rule (mem-watch/simd budgets);
 * clamp=false keeps the original "p ? p : default" rule (bitops/branch budgets). */
static unsigned int hb_trace_parse_budget(const char* name, unsigned int dflt, bool clamp) {
    const char* v = hb_env(name);
    if (v && v[0]) {
        unsigned long p = strtoul(v, NULL, 0);
        if (clamp) { if (p > 0 && p < 100000) return (unsigned int)p; }
        else       { if (p) return (unsigned int)p; }
    }
    return dflt;
}

static void trace_cfg_load(hb_trace_cfg_t* c) {
    unsigned int flags = 0;
    if (trace_env_enabled("MACRUNNER_HB_TRACE_MEM_WATCH")) flags |= TRACE_FLAG_MEM_WATCH;
    if (trace_env_enabled("MACRUNNER_HB_TRACE_NATIVE_WRITES")) flags |= TRACE_FLAG_NATIVE_WRITES;
    if (trace_env_enabled("MACRUNNER_HB_TRACE_STACK_FAULTS")) flags |= TRACE_FLAG_STACK_FAULTS;
    if (trace_env_enabled("MACRUNNER_HB_TRACE_ATOMICS")) flags |= TRACE_FLAG_ATOMICS;
    if (trace_env_enabled("MACRUNNER_HB_TRACE_FAULTS")) flags |= TRACE_FLAG_FAULTS;
    if (trace_env_enabled("MACRUNNER_HB_TRACE_PC")) flags |= TRACE_FLAG_PC;
    if (trace_env_enabled("MACRUNNER_HB_TRACE_STRCPY_PROBE")) flags |= TRACE_FLAG_STRCPY;
    if (trace_env_enabled("MACRUNNER_HB_TRACE_BRANCHES")) flags |= TRACE_FLAG_BRANCHES;
    if (trace_env_enabled("MACRUNNER_HB_TRACE_SIMD")) flags |= TRACE_FLAG_SIMD;
    if (trace_env_enabled("MACRUNNER_HB_TRACE_SIMD_DATA")) flags |= TRACE_FLAG_SIMD_DATA;
    if (trace_env_enabled("MACRUNNER_HB_TRACE_BITOPS")) flags |= TRACE_FLAG_BITOPS;
    c->flags = flags;

    hb_trace_parse_range("MACRUNNER_HB_TRACE_MEM_WATCH_START", "MACRUNNER_HB_TRACE_MEM_WATCH_END",
                         &c->mw_range_set, &c->mw_start, &c->mw_end);
    /* ★ MacRunner 2026-09-02 — диапазон прямо в значении ручки: MACRUNNER_HB_TRACE_MEM_WATCH=0x1345d178-0x1345d17c.
     * Причина: лаунчер Diablo гибнет при ≥3 добавочных переменных окружения (стена NULL+0x3404), а START/END — ещё две. */
    if (!c->mw_range_set) {
        const char* v = hb_gate( HB_GATE_HB_TRACE_MEM_WATCH );
        const char* dash = v ? strchr(v, '-') : NULL;
        if (dash && dash > v) {
            c->mw_start = (uint64_t)strtoull(v, NULL, 0);
            c->mw_end = (uint64_t)strtoull(dash + 1, NULL, 0);
            if (c->mw_end >= c->mw_start) {
                c->mw_range_set = true; flags |= TRACE_FLAG_MEM_WATCH; c->flags = flags;
                fprintf(stderr, "macrunner-hb-mem-watch: диапазон из значения ручки lo=0x%llx hi=0x%llx\n",
                        (unsigned long long)c->mw_start, (unsigned long long)c->mw_end);
            }
        }
    }
    hb_trace_parse_range("MACRUNNER_HB_TRACE_MEM_WATCH_PC_START", "MACRUNNER_HB_TRACE_MEM_WATCH_PC_END",
                         &c->mw_pc_set, &c->mw_pc_start, &c->mw_pc_end);
    c->mw_budget = hb_trace_parse_budget("MACRUNNER_HB_TRACE_MEM_WATCH_BUDGET", 160, true);

    hb_trace_parse_range("MACRUNNER_HB_TRACE_BITOPS_START", "MACRUNNER_HB_TRACE_BITOPS_END",
                         &c->bitops_range_set, &c->bitops_start, &c->bitops_end);
    c->bitops_budget = hb_trace_parse_budget("MACRUNNER_HB_TRACE_BITOPS_BUDGET", 400, false);

    hb_trace_parse_range("MACRUNNER_HB_TRACE_BRANCH_START", "MACRUNNER_HB_TRACE_BRANCH_END",
                         &c->branch_range_set, &c->branch_start, &c->branch_end);
    c->branch_budget = hb_trace_parse_budget("MACRUNNER_HB_TRACE_BRANCH_BUDGET", 300, false);

    {
        const char* v = hb_gate( HB_GATE_HB_TRACE_PC );
        if (v && v[0]) {
            c->pc_list_set = true;
            strncpy(c->pc_list, v, sizeof(c->pc_list) - 1);
            c->pc_list[sizeof(c->pc_list) - 1] = 0;
        }
        const char* l = hb_gate( HB_GATE_HB_TRACE_PC_LIMIT );
        c->pc_limit = (l && l[0]) ? (unsigned int)strtoul(l, NULL, 0) : 80;
    }
    {
        const char* l = hb_gate( HB_GATE_HB_TRACE_STRCPY_PROBE_LIMIT );
        c->strcpy_limit = (l && l[0]) ? (unsigned int)strtoul(l, NULL, 0) : 200;
    }
    c->simd_budget = hb_trace_parse_budget("MACRUNNER_HB_TRACE_SIMD_BUDGET", 400, true);
    hb_trace_parse_range("MACRUNNER_HB_TRACE_SIMD_DATA_GUEST_START", "MACRUNNER_HB_TRACE_SIMD_DATA_GUEST_END",
                         &c->simd_data_range_set, &c->simd_data_start, &c->simd_data_end);
    c->simd_data_budget = hb_trace_parse_budget("MACRUNNER_HB_TRACE_SIMD_DATA_BUDGET", 256, true);
}

static int trace_cfg_ready;   /* 0=uninit, 1=loading, 2=ready */

static void trace_cfg_ensure(void) {
    int expected = 0;
    if (__atomic_load_n(&trace_cfg_ready, __ATOMIC_ACQUIRE) == 2) return;
    if (__atomic_compare_exchange_n(&trace_cfg_ready, &expected, 1, 0,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        trace_cfg_load(&trace_cfg);
        __atomic_store_n(&trace_cfg_ready, 2, __ATOMIC_RELEASE);
    }
    /* CAS loser: another thread is loading; trace_cfg stays zeroed (tracing OFF) for
     * this thread until it is published — harmless, the hot path only reads trace_cfg.flags. */
}

static void trace_refresh_runtime_flags(void) {
    trace_cfg_ensure();
    trace_runtime_flags = trace_cfg.flags;
}

static bool trace_mem_watch_enabled(void) {
    return (trace_runtime_flags & TRACE_FLAG_MEM_WATCH) != 0;
}

static bool trace_mem_watch_range(uint64_t addr, size_t size, uint64_t* start, uint64_t* end) {
    uint64_t last;

    if (!trace_mem_watch_enabled() || !trace_cfg.mw_range_set) return false;
    *start = trace_cfg.mw_start;
    *end = trace_cfg.mw_end;
    last = size ? addr + size - 1 : addr;
    if (last < addr) return true;
    return addr <= *end && last >= *start;
}

static bool trace_mem_watch_take_budget(void) {
    static unsigned int count;
    unsigned int limit = trace_cfg.mw_budget;

    if (++count > limit) {
        if (count == limit + 1)
            fprintf(stderr, "macrunner-hb-mem-watch: budget exhausted, silencing\n");
        return false;
    }
    return true;
}

static bool trace_mem_watch_pc_allowed(uint64_t pc) {
    if (!trace_cfg.mw_pc_set) return true;
    return pc >= trace_cfg.mw_pc_start && pc <= trace_cfg.mw_pc_end;
}

static void trace_hex_bytes(const uint8_t* bytes, size_t count) {
    for (size_t i = 0; i < count; i++) fprintf(stderr, "%02x", bytes[i]);
}

static void trace_instr_bytes(hb_context_t* ctx, const hb_ir_instr_t* instr) {
    if (!ctx || !ctx->memory || !instr) return;
    for (uint8_t i = 0; i < instr->guest_len && i < 15; i++) {
        uint8_t byte = 0;
        if (hb_memory_read_u8(ctx->memory, instr->guest_addr + i, &byte) == HB_OK)
            fprintf(stderr, "%02x", byte);
        else
            fprintf(stderr, "??");
    }
}

static void trace_mem_watch_bytes(hb_context_t* ctx, const char* phase, uint64_t addr,
                                  const void* data, size_t size, const void* before) {
    const hb_ir_instr_t* instr = trace_current_instr;
    uint64_t start = 0, end = 0;
    size_t count = size > 32 ? 32 : size;

    if (!ctx || !trace_mem_watch_range(addr, size, &start, &end)) return;
    if (!trace_mem_watch_pc_allowed(instr ? instr->guest_addr : 0)) return;
    if (!trace_mem_watch_take_budget()) return;

    fprintf(stderr,
            "macrunner-hb-mem-watch: phase=%s pc=0x%llx len=%u op=%s addr=0x%llx size=%zu "
            "watch=0x%llx-0x%llx rax=0x%llx rcx=0x%llx rdx=0x%llx rsi=0x%llx rdi=0x%llx "
            "bytes=",
            phase,
            instr ? (unsigned long long)instr->guest_addr : 0,
            instr ? instr->guest_len : 0,
            instr ? ir_op_name(instr->op) : "unknown",
            (unsigned long long)addr, size,
            (unsigned long long)start, (unsigned long long)end,
            (unsigned long long)ctx->regs.x64.rax,
            (unsigned long long)ctx->regs.x64.rcx,
            (unsigned long long)ctx->regs.x64.rdx,
            (unsigned long long)ctx->regs.x64.rsi,
            (unsigned long long)ctx->regs.x64.rdi);
    if (data && count) trace_hex_bytes((const uint8_t*)data, count);
    else fprintf(stderr, "-");
    if (before && count) {
        fprintf(stderr, " before=");
        trace_hex_bytes((const uint8_t*)before, count);
    }
    fprintf(stderr, " instr=");
    trace_instr_bytes(ctx, instr);
    fprintf(stderr, "\n");
}

static bool trace_native_write_enabled(void) {
    return (trace_runtime_flags & TRACE_FLAG_NATIVE_WRITES) != 0;
}

static bool trace_native_write_addr(uint64_t addr, size_t size) {
    uint64_t last = addr;

    if (!trace_native_write_enabled()) return false;
    if (size) {
        last = addr + size - 1;
        if (last < addr) return true;
    }
    return addr < 0x7ffe0000000ULL && last >= 0x7ffd0000000ULL;
}

static void trace_guest_native_write(hb_context_t* ctx, const char* path,
                                     uint64_t addr, uint64_t val, hb_size_t sz) {
    uint64_t ret_addr = 0;
    uint8_t src[16] = {0};
    bool have_ret = false;
    bool have_src = false;

    if (!ctx || !trace_native_write_addr(addr, (size_t)sz)) return;
    if (ctx->mode == HB_MODE_64BIT && ctx->memory) {
        have_ret = hb_memory_read(ctx->memory, (hb_gva_t)ctx->regs.x64.rsp,
                                  &ret_addr, sizeof(ret_addr)) == HB_OK;
        have_src = ctx->regs.x64.rdx >= 0x10000 &&
                   hb_memory_read(ctx->memory, (hb_gva_t)ctx->regs.x64.rdx,
                                  src, sizeof(src)) == HB_OK;
    }
    fprintf(stderr,
            "macrunner-hb-guest-native-write: path=%s pc=0x%llx addr=0x%llx size=%u "
            "value=0x%llx rsp=0x%llx ret=%s0x%llx rax=0x%llx rdx=0x%llx "
            "r8=0x%llx r9=0x%llx rdi=0x%llx rsi=0x%llx rcx=0x%llx "
            "gs=0x%llx fs=0x%llx src16=%s%02x%02x%02x%02x%02x%02x%02x%02x"
            "%02x%02x%02x%02x%02x%02x%02x%02x\n",
            path,
            (unsigned long long)ctx->pc,
            (unsigned long long)addr,
            (unsigned)sz,
            (unsigned long long)val,
            (unsigned long long)ctx->regs.x64.rsp,
            have_ret ? "" : "invalid:",
            (unsigned long long)ret_addr,
            (unsigned long long)ctx->regs.x64.rax,
            (unsigned long long)ctx->regs.x64.rdx,
            (unsigned long long)ctx->regs.x64.r8,
            (unsigned long long)ctx->regs.x64.r9,
            (unsigned long long)ctx->regs.x64.rdi,
            (unsigned long long)ctx->regs.x64.rsi,
            (unsigned long long)ctx->regs.x64.rcx,
            (unsigned long long)ctx->gs_base,
            (unsigned long long)ctx->fs_base,
            have_src ? "" : "invalid:",
            src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
            src[8], src[9], src[10], src[11], src[12], src[13], src[14], src[15]);
}

struct hb_interpreter {
    hb_context_t* ctx;
};

hb_interpreter_t* hb_interpreter_create(hb_context_t* ctx) {
    hb_interpreter_t* i = calloc(1, sizeof(hb_interpreter_t));
    if (!i) return NULL;
    i->ctx = ctx;
    return i;
}

void hb_interpreter_destroy(hb_interpreter_t* interp) {
    free(interp);
}

/* --- Register pointer helpers --- */
static uint64_t* reg_ptr_x64(hb_regs_x64_t* r, int idx) {
    switch (idx) {
        case 0: return &r->rax;
        case 1: return &r->rcx;
        case 2: return &r->rdx;
        case 3: return &r->rbx;
        case 4: return &r->rsp;
        case 5: return &r->rbp;
        case 6: return &r->rsi;
        case 7: return &r->rdi;
        case 8: return &r->r8;
        case 9: return &r->r9;
        case 10: return &r->r10;
        case 11: return &r->r11;
        case 12: return &r->r12;
        case 13: return &r->r13;
        case 14: return &r->r14;
        case 15: return &r->r15;
        case 16: return &r->rip;
        default: return NULL;
    }
}

static uint32_t* reg_ptr_x86(hb_regs_x86_t* r, int idx) {
    switch (idx) {
        case 0: return &r->eax;
        case 1: return &r->ecx;
        case 2: return &r->edx;
        case 3: return &r->ebx;
        case 4: return &r->esp;
        case 5: return &r->ebp;
        case 6: return &r->esi;
        case 7: return &r->edi;
        case 16: return &r->eip;
        default: return NULL;
    }
}

static uint64_t read_reg(hb_context_t* ctx, int idx) {
    if (ctx->mode == HB_MODE_32BIT) {
        uint32_t* p = reg_ptr_x86(&ctx->regs.x86, idx);
        return p ? *p : 0;
    }
    uint64_t* p = reg_ptr_x64(&ctx->regs.x64, idx);
    return p ? *p : 0;
}

/* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 918 — РЕГИСТРЫ MMX У ВЕКТОРНЫХ ОПЕРАЦИЙ.
 *
 * Реализации пакетных операций поголовно начинались с `!is_xmm_reg(dst)` и отказывали на
 * MMX-формах кодом INTERNAL: регистры `mm0..mm7` живут в ОТДЕЛЬНОМ файле (`hb_mmx_regs`),
 * а не среди xmm. Из-за этого тридцать безпрефиксных форм, которые декодер начал брать в
 * этой же итерации, не исполнялись.
 * Учим ЧИТАТЕЛЯ и ПИСАТЕЛЯ работать с этим файлом, а запрет снимаем одним правилом на все
 * места — какие опкоды имеют MMX-форму, решает декодер, и только он. */
static uint64_t* hb_mmx_regs(hb_context_t* ctx);   /* определена ниже по файлу */

static bool is_mm_reg(int idx) { return idx >= HB_REG_MM0 && idx <= HB_REG_MM7; }

static bool is_vec_or_mm_reg(int idx);

static bool is_xmm_reg(int idx) {
    return idx >= HB_REG_XMM0 && idx <= HB_REG_XMM31;
}

static bool is_vec_or_mm_reg(int idx) { return is_xmm_reg(idx) || is_mm_reg(idx); }


static hb_result_t read_xmm_reg(hb_context_t* ctx, int idx, uint64_t out[2]) {
    if (!ctx || !out || !is_xmm_reg(idx)) return HB_ERR_INVALID_ARG;
    if (ctx->mode == HB_MODE_32BIT) {
        unsigned n = (unsigned)(idx - HB_REG_XMM0);
        if (n >= 8) return HB_ERR_INVALID_ARG;
        out[0] = ctx->regs.x86.xmm[n][0];
        out[1] = ctx->regs.x86.xmm[n][1];
        return HB_OK;
    }
    unsigned n = (unsigned)(idx - HB_REG_XMM0);
    if (n < 16) {
        out[0] = ctx->regs.x64.xmm[n][0];
        out[1] = ctx->regs.x64.xmm[n][1];
    } else {
        out[0] = ctx->xmm_ext[n - 16][0];
        out[1] = ctx->xmm_ext[n - 16][1];
    }
    return HB_OK;
}

static hb_result_t write_xmm_reg(hb_context_t* ctx, int idx, const uint64_t in[2]) {
    if (!ctx || !in || !is_xmm_reg(idx)) return HB_ERR_INVALID_ARG;
    if (ctx->mode == HB_MODE_32BIT) {
        unsigned n = (unsigned)(idx - HB_REG_XMM0);
        if (n >= 8) return HB_ERR_INVALID_ARG;
        ctx->regs.x86.xmm[n][0] = in[0];
        ctx->regs.x86.xmm[n][1] = in[1];
        return HB_OK;
    }
    unsigned n = (unsigned)(idx - HB_REG_XMM0);
    if (n < 16) {
        ctx->regs.x64.xmm[n][0] = in[0];
        ctx->regs.x64.xmm[n][1] = in[1];
    } else {
        ctx->xmm_ext[n - 16][0] = in[0];
        ctx->xmm_ext[n - 16][1] = in[1];
    }
    return HB_OK;
}

static hb_result_t read_vec_reg_bytes(hb_context_t* ctx, int idx, uint8_t* out, size_t bytes) {
    if (!ctx || !out || !is_xmm_reg(idx) || bytes > 64) return HB_ERR_INVALID_ARG;
    memset(out, 0, bytes);
    if (ctx->mode == HB_MODE_32BIT) {
        unsigned n = (unsigned)(idx - HB_REG_XMM0);
        if (n >= 8) return HB_ERR_INVALID_ARG;
        memcpy(out, ctx->regs.x86.xmm[n], bytes < 16 ? bytes : 16);
        if (bytes > 16) memcpy(out + 16, ctx->ymm_hi[n], bytes > 32 ? 16 : bytes - 16);
        if (bytes > 32) memcpy(out + 32, ctx->zmm_hi[n], bytes - 32);
        return HB_OK;
    }
    unsigned n = (unsigned)(idx - HB_REG_XMM0);
    if (n < 16) {
        memcpy(out, ctx->regs.x64.xmm[n], bytes < 16 ? bytes : 16);
        if (bytes > 16) memcpy(out + 16, ctx->ymm_hi[n], bytes > 32 ? 16 : bytes - 16);
        if (bytes > 32) memcpy(out + 32, ctx->zmm_hi[n], bytes - 32);
    } else {
        n -= 16;
        memcpy(out, ctx->xmm_ext[n], bytes < 16 ? bytes : 16);
        if (bytes > 16) memcpy(out + 16, ctx->ymm_hi_ext[n], bytes > 32 ? 16 : bytes - 16);
        if (bytes > 32) memcpy(out + 32, ctx->zmm_hi_ext[n], bytes - 32);
    }
    return HB_OK;
}

static hb_result_t write_vec_reg_bytes(hb_context_t* ctx, int idx, const uint8_t* in, size_t bytes) {
    if (ctx && in && is_mm_reg(idx) && bytes <= 8) {
        /* Итерация 918: запись в отдельный файл MMX (см. is_mm_reg). */
        uint64_t* mm = hb_mmx_regs(ctx);
        if (!mm) return HB_ERR_INTERNAL;
        uint64_t v = 0;
        memcpy(&v, in, bytes);
        mm[idx - HB_REG_MM0] = v;
        return HB_OK;
    }
    if (!ctx || !in || !is_xmm_reg(idx) || bytes > 64) return HB_ERR_INVALID_ARG;
    uint8_t tmp[64] = {0};
    bool zero_ymm_upper = trace_current_instr && trace_current_instr->zero_ymm_upper && bytes <= 16;
    memcpy(tmp, in, bytes);
    if (ctx->mode == HB_MODE_32BIT) {
        unsigned n = (unsigned)(idx - HB_REG_XMM0);
        if (n >= 8) return HB_ERR_INVALID_ARG;
        if (bytes < 16) memcpy(ctx->regs.x86.xmm[n], tmp, bytes);
        else memcpy(ctx->regs.x86.xmm[n], tmp, 16);
        if (bytes > 16) memcpy(ctx->ymm_hi[n], tmp + 16, bytes > 32 ? 16 : bytes - 16);
        else if (zero_ymm_upper) {
            memset(ctx->ymm_hi[n], 0, sizeof(ctx->ymm_hi[n]));
            memset(ctx->zmm_hi[n], 0, sizeof(ctx->zmm_hi[n]));
        }
        if (bytes > 32) memcpy(ctx->zmm_hi[n], tmp + 32, bytes - 32);
        return HB_OK;
    }
    unsigned n = (unsigned)(idx - HB_REG_XMM0);
    if (n < 16) {
        if (bytes < 16) memcpy(ctx->regs.x64.xmm[n], tmp, bytes);
        else memcpy(ctx->regs.x64.xmm[n], tmp, 16);
        if (bytes > 16) memcpy(ctx->ymm_hi[n], tmp + 16, bytes > 32 ? 16 : bytes - 16);
        else if (zero_ymm_upper) {
            memset(ctx->ymm_hi[n], 0, sizeof(ctx->ymm_hi[n]));
            memset(ctx->zmm_hi[n], 0, sizeof(ctx->zmm_hi[n]));
        }
        if (bytes > 32) memcpy(ctx->zmm_hi[n], tmp + 32, bytes - 32);
    } else {
        n -= 16;
        if (bytes < 16) memcpy(ctx->xmm_ext[n], tmp, bytes);
        else memcpy(ctx->xmm_ext[n], tmp, 16);
        if (bytes > 16) memcpy(ctx->ymm_hi_ext[n], tmp + 16, bytes > 32 ? 16 : bytes - 16);
        else if (zero_ymm_upper) {
            memset(ctx->ymm_hi_ext[n], 0, sizeof(ctx->ymm_hi_ext[n]));
            memset(ctx->zmm_hi_ext[n], 0, sizeof(ctx->zmm_hi_ext[n]));
        }
        if (bytes > 32) memcpy(ctx->zmm_hi_ext[n], tmp + 32, bytes - 32);
    }
    return HB_OK;
}

/* Константы EVEX-разметки `target` живут в hb_ir.h — их читает и кодогенератор. */

static uint32_t evex_target_arg(const hb_ir_instr_t* instr) {
    return (uint32_t)(instr->target & HB_EVEX_TARGET_ARG_MASK);
}

static bool evex_target_present(const hb_ir_instr_t* instr) {
    return (((uint32_t)instr->target) & HB_EVEX_TARGET_PRESENT) != 0;
}

static unsigned evex_target_mask(const hb_ir_instr_t* instr) {
    return (((uint32_t)instr->target) >> HB_EVEX_TARGET_MASK_SHIFT) & 7u;
}

static bool evex_target_zero(const hb_ir_instr_t* instr) {
    return (((uint32_t)instr->target) & (1u << HB_EVEX_TARGET_ZERO_BIT)) != 0;
}

static hb_result_t write_vec_reg_bytes_evex_masked(hb_context_t* ctx,
                                                   const hb_ir_instr_t* instr,
                                                   uint8_t* bytes_inout,
                                                   size_t bytes,
                                                   unsigned lane_bytes) {
    if (!evex_target_present(instr) || evex_target_mask(instr) == 0)
        return write_vec_reg_bytes(ctx, instr->dst.reg, bytes_inout, bytes);
    if (!ctx || !bytes_inout || instr->dst.type != HB_OP_REG || !is_xmm_reg(instr->dst.reg) ||
        lane_bytes == 0 || bytes > 64 || (bytes % lane_bytes) != 0)
        return HB_ERR_INTERNAL;

    uint8_t old[64] = {0};
    hb_result_t r = read_vec_reg_bytes(ctx, instr->dst.reg, old, bytes);
    if (r != HB_OK) return r;

    uint64_t k = ctx->k[evex_target_mask(instr) & 7u];
    bool zero = evex_target_zero(instr);
    unsigned lanes = (unsigned)(bytes / lane_bytes);
    for (unsigned lane = 0; lane < lanes; lane++) {
        size_t off = (size_t)lane * lane_bytes;
        if ((k >> lane) & 1u) continue;
        if (zero) memset(bytes_inout + off, 0, lane_bytes);
        else memcpy(bytes_inout + off, old + off, lane_bytes);
    }
    return write_vec_reg_bytes(ctx, instr->dst.reg, bytes_inout, bytes);
}

static hb_result_t write_vec_reg_bytes_evex_scalar_masked(hb_context_t* ctx,
                                                          const hb_ir_instr_t* instr,
                                                          uint8_t* bytes_inout,
                                                          unsigned lane_bytes) {
    if (!evex_target_present(instr) || evex_target_mask(instr) == 0)
        return write_vec_reg_bytes(ctx, instr->dst.reg, bytes_inout, 16);
    if (!ctx || !bytes_inout || instr->dst.type != HB_OP_REG || !is_xmm_reg(instr->dst.reg) ||
        !(lane_bytes == 4 || lane_bytes == 8))
        return HB_ERR_INTERNAL;

    uint64_t k = ctx->k[evex_target_mask(instr) & 7u];
    if (k & 1u) return write_vec_reg_bytes(ctx, instr->dst.reg, bytes_inout, 16);

    if (evex_target_zero(instr)) {
        memset(bytes_inout, 0, lane_bytes);
    } else {
        uint8_t old[16] = {0};
        hb_result_t r = read_vec_reg_bytes(ctx, instr->dst.reg, old, sizeof(old));
        if (r != HB_OK) return r;
        memcpy(bytes_inout, old, lane_bytes);
    }
    return write_vec_reg_bytes(ctx, instr->dst.reg, bytes_inout, 16);
}

static bool fp_cmp_predicate(bool unordered, int cmp_eq, int cmp_lt, int cmp_le, unsigned pred) {
    switch (pred & 31u) {
        case 0: case 16: return !unordered && cmp_eq;
        case 1: case 17: return !unordered && cmp_lt;
        case 2: case 18: return !unordered && cmp_le;
        case 3: case 19: return unordered;
        case 4: case 20: return unordered || !cmp_eq;
        case 5: case 21: return unordered || !cmp_lt;
        case 6: case 22: return unordered || !cmp_le;
        case 7: case 23: return !unordered;
        case 8: case 24: return unordered || cmp_eq;
        case 9: case 25: return unordered || !(cmp_eq || cmp_lt);
        case 10: case 26: return unordered || !(cmp_eq || cmp_lt || cmp_le);
        case 11: case 27: return false;
        case 12: case 28: return !unordered && !cmp_eq;
        case 13: case 29: return !unordered && (cmp_eq || !cmp_lt);
        case 14: case 30: return !unordered && !cmp_le;
        case 15: case 31: return true;
        default: return false;
    }
}

static size_t bytes_for_size(hb_size_t size) {
    switch (size) {
        case HB_SIZE_8: return 1;
        case HB_SIZE_16: return 2;
        case HB_SIZE_32: return 4;
        case HB_SIZE_64: return 8;
        case HB_SIZE_80: return 10;
        case HB_SIZE_128: return 16;
        case HB_SIZE_256: return 32;
        case HB_SIZE_512: return 64;
        default: return 0;
    }
}

static uint64_t resolve_addr(hb_context_t* ctx, const hb_ir_operand_t* op);
static hb_result_t mem_read(hb_context_t* ctx, uint64_t addr, uint64_t* out, hb_size_t sz);

static double hb_bits_to_double(uint64_t bits) {
    double value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static uint64_t hb_double_to_bits(double value) {
    uint64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}

static float hb_bits_to_float(uint32_t bits) {
    float value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static uint32_t hb_float_to_bits(float value) {
    uint32_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}

static uint32_t hb_half_to_float_bits(uint16_t h) {
    uint32_t sign = ((uint32_t)h & 0x8000u) << 16;
    uint32_t exp = ((uint32_t)h >> 10) & 0x1fu;
    uint32_t frac = (uint32_t)h & 0x03ffu;
    if (exp == 0) {
        if (frac == 0) return sign;
        int e = -14;
        while ((frac & 0x0400u) == 0) {
            frac <<= 1;
            e--;
        }
        frac &= 0x03ffu;
        return sign | (uint32_t)(e + 127) << 23 | (frac << 13);
    }
    if (exp == 0x1fu) return sign | 0x7f800000u | (frac << 13);
    return sign | ((exp + 112u) << 23) | (frac << 13);
}

static bool hb_round_shift_should_increment(uint64_t value, unsigned shift,
                                            unsigned mode, bool sign) {
    if (shift == 0) return false;
    uint64_t mask = (shift >= 64) ? UINT64_MAX : ((1ULL << shift) - 1ULL);
    uint64_t rem = value & mask;
    if (rem == 0) return false;
    if (mode == 1) return sign;      /* round toward -inf */
    if (mode == 2) return !sign;     /* round toward +inf */
    if (mode == 3) return false;     /* truncate */
    uint64_t half = 1ULL << (shift - 1);
    uint64_t lsb = (value >> shift) & 1ULL;
    return rem > half || (rem == half && lsb);
}

static uint16_t hb_float_bits_to_half(uint32_t bits, unsigned imm) {
    bool sign_bool = (bits & 0x80000000u) != 0;
    uint16_t sign = sign_bool ? 0x8000u : 0;
    unsigned mode = (imm & 0x04u) ? 0u : (imm & 0x03u); /* MXCSR is not modeled; use nearest-even. */
    uint32_t exp = (bits >> 23) & 0xffu;
    uint32_t frac = bits & 0x7fffffu;

    if (exp == 0xffu) {
        if (frac == 0) return (uint16_t)(sign | 0x7c00u);
        uint16_t payload = (uint16_t)(frac >> 13);
        if (payload == 0) payload = 1;
        return (uint16_t)(sign | 0x7c00u | payload | 0x0200u);
    }
    if (exp == 0) {
        if (frac == 0) return sign;
        if ((mode == 1 && sign_bool) || (mode == 2 && !sign_bool)) return (uint16_t)(sign | 1u);
        return sign;
    }

    int half_exp = (int)exp - 127 + 15;
    if (half_exp >= 31) {
        if (mode == 3 || (mode == 1 && !sign_bool) || (mode == 2 && sign_bool))
            return (uint16_t)(sign | 0x7bffu);
        return (uint16_t)(sign | 0x7c00u);
    }
    if (half_exp <= 0) {
        uint64_t sig = 0x800000u | frac;
        unsigned shift = (unsigned)(14 - half_exp);
        if (shift >= 64) {
            if ((mode == 1 && sign_bool) || (mode == 2 && !sign_bool)) return (uint16_t)(sign | 1u);
            return sign;
        }
        uint64_t mant = sig >> shift;
        if (shift < 64 && hb_round_shift_should_increment(sig, shift, mode, sign_bool)) mant++;
        if (mant >= 0x400u) return (uint16_t)(sign | 0x0400u);
        return (uint16_t)(sign | (uint16_t)mant);
    }

    uint16_t mant = (uint16_t)(frac >> 13);
    if (hb_round_shift_should_increment(frac, 13, mode, sign_bool)) {
        mant++;
        if (mant == 0x400u) {
            mant = 0;
            half_exp++;
            if (half_exp >= 31) return (uint16_t)(sign | 0x7c00u);
        }
    }
    return (uint16_t)(sign | ((uint16_t)half_exp << 10) | mant);
}

/* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1077 — ОКРУГЛЕНИЕ ПО РЕГИСТРУ ГОСТЯ.
 *
 * Преобразователи ниже звали `nearbyint`, то есть округляли по режиму ХОЗЯИНА (к ближайшему
 * чётному), игнорируя биты RC регистра гостя. С 1075 регистр у нас настоящий, значит режим
 * можно и нужно соблюдать: RC — биты 13:14, четыре значения по спецификации.
 *
 * Почему это не теория: типовой приём компилятора — сохранить режим (`STMXCSR`), выставить
 * усечение и преобразовать, затем вернуть; в самом движке эта последовательность отмечена в
 * настоящей игре (`hb_arm64_codegen.c:6505`). Пока режим игнорировался, «выставить усечение»
 * не делало ничего, и `cvtps2dq` округлял к ближайшему вместо усечения. */
/* Итерация 1105, приказ 145 — ГЕЙТ-ПРИБОР вида Б, умолчание ВКЛ.
 *
 * Прибор, а не выключатель: гасится ТОЛЬКО в приёмочном переборе, чтобы узнать цену правки
 * 1075-1078 в процентах; `check-required-gates.sh` считает `=0` запрещённым вне приёмки.
 *
 * Погашенный возвращает поведение ДО 1077: округление по режиму хозяина (`nearbyint`), то есть
 * биты RC гостя игнорируются. Это ровно та работа, чью цену мы и хотим измерить — чтение поля
 * контекста и ветвление на каждом преобразовании float→int (шесть мест вызова). */
static double hb_round_by_rc(double v, unsigned rc) {
    switch (rc & 3u) {
        case 1: return floor(v);            /* к минус бесконечности */
        case 2: return ceil(v);             /* к плюс бесконечности */
        case 3: return trunc(v);            /* к нулю */
        default: return nearbyint(v);       /* к ближайшему чётному */
    }
}

static int32_t hb_float_to_i32_sse(float value, bool truncate, unsigned rc) {
    double rounded;
    if (!isfinite(value)) return INT32_MIN;
    rounded = truncate ? trunc((double)value) : hb_round_by_rc((double)value, rc);
    if (rounded < -2147483648.0 || rounded >= 2147483648.0) return INT32_MIN;
    return (int32_t)rounded;
}

static int32_t hb_double_to_i32_sse(double value, bool truncate, unsigned rc) {
    double rounded;
    if (!isfinite(value)) return INT32_MIN;
    rounded = truncate ? trunc(value) : hb_round_by_rc(value, rc);
    if (rounded < -2147483648.0 || rounded >= 2147483648.0) return INT32_MIN;
    return (int32_t)rounded;
}

static int64_t hb_float_to_i64_sse(float value, bool truncate, unsigned rc) {
    double rounded;
    if (!isfinite(value)) return INT64_MIN;
    rounded = truncate ? trunc((double)value) : hb_round_by_rc((double)value, rc);
    if (rounded < -9223372036854775808.0 || rounded >= 9223372036854775808.0) return INT64_MIN;
    return (int64_t)rounded;
}

static int64_t hb_double_to_i64_sse(double value, bool truncate, unsigned rc) {
    double rounded;
    if (!isfinite(value)) return INT64_MIN;
    rounded = truncate ? trunc(value) : hb_round_by_rc(value, rc);
    if (rounded < -9223372036854775808.0 || rounded >= 9223372036854775808.0) return INT64_MIN;
    return (int64_t)rounded;
}

static hb_result_t read_scalar_double_bits(hb_context_t* ctx, const hb_ir_operand_t* op, uint64_t* out) {
    if (!ctx || !op || !out) return HB_ERR_INVALID_ARG;
    uint64_t bits = 0;
    if (op->type == HB_OP_REG && is_xmm_reg(op->reg)) {
        uint64_t xmm[2];
        hb_result_t r = read_xmm_reg(ctx, op->reg, xmm);
        if (r != HB_OK) return r;
        bits = xmm[0];
    } else if (op->type == HB_OP_MEM) {
        uint64_t addr = resolve_addr(ctx, op);
        hb_result_t r = mem_read(ctx, addr, &bits, HB_SIZE_64);
        if (r != HB_OK) return r;
    } else {
        return HB_ERR_INTERNAL;
    }
    *out = bits;
    return HB_OK;
}

static hb_result_t read_scalar_double(hb_context_t* ctx, const hb_ir_operand_t* op, double* out) {
    uint64_t bits = 0;
    hb_result_t r = read_scalar_double_bits(ctx, op, &bits);
    if (r != HB_OK) return r;
    *out = hb_bits_to_double(bits);
    return HB_OK;
}

static hb_result_t write_scalar_double_bits(hb_context_t* ctx, const hb_ir_operand_t* op, uint64_t bits) {
    if (!ctx || !op || op->type != HB_OP_REG || !is_xmm_reg(op->reg)) return HB_ERR_INTERNAL;
    uint64_t xmm[2];
    hb_result_t r = read_xmm_reg(ctx, op->reg, xmm);
    if (r != HB_OK) return r;
    xmm[0] = bits;
    return write_xmm_reg(ctx, op->reg, xmm);
}

static hb_result_t write_scalar_double(hb_context_t* ctx, const hb_ir_operand_t* op, double value) {
    return write_scalar_double_bits(ctx, op, hb_double_to_bits(value));
}

static hb_result_t read_scalar_float_bits(hb_context_t* ctx, const hb_ir_operand_t* op, uint32_t* out) {
    if (!ctx || !op || !out) return HB_ERR_INVALID_ARG;
    uint32_t bits = 0;
    if (op->type == HB_OP_REG && is_xmm_reg(op->reg)) {
        uint64_t xmm[2];
        hb_result_t r = read_xmm_reg(ctx, op->reg, xmm);
        if (r != HB_OK) return r;
        bits = (uint32_t)xmm[0];
    } else if (op->type == HB_OP_MEM) {
        uint64_t raw = 0;
        uint64_t addr = resolve_addr(ctx, op);
        hb_result_t r = mem_read(ctx, addr, &raw, HB_SIZE_32);
        if (r != HB_OK) return r;
        bits = (uint32_t)raw;
    } else {
        return HB_ERR_INTERNAL;
    }
    *out = bits;
    return HB_OK;
}

static hb_result_t read_scalar_float(hb_context_t* ctx, const hb_ir_operand_t* op, float* out) {
    uint32_t bits = 0;
    hb_result_t r = read_scalar_float_bits(ctx, op, &bits);
    if (r != HB_OK) return r;
    *out = hb_bits_to_float(bits);
    return HB_OK;
}

static hb_result_t write_scalar_float_bits(hb_context_t* ctx, const hb_ir_operand_t* op, uint32_t bits) {
    if (!ctx || !op || op->type != HB_OP_REG || !is_xmm_reg(op->reg)) return HB_ERR_INTERNAL;
    uint64_t xmm[2];
    hb_result_t r = read_xmm_reg(ctx, op->reg, xmm);
    if (r != HB_OK) return r;
    xmm[0] = (xmm[0] & 0xffffffff00000000ULL) | bits;
    return write_xmm_reg(ctx, op->reg, xmm);
}

static hb_result_t write_scalar_float(hb_context_t* ctx, const hb_ir_operand_t* op, float value) {
    return write_scalar_float_bits(ctx, op, hb_float_to_bits(value));
}

static void write_scalar_compare_flags(hb_context_t* ctx, double lhs, double rhs) {
    hb_lazy_flags_clear(ctx);
    ctx->flags.of = false;
    ctx->flags.sf = false;
    ctx->flags.af = false;
    if (lhs != lhs || rhs != rhs) {
        ctx->flags.zf = true;
        ctx->flags.pf = true;
        ctx->flags.cf = true;
    } else {
        ctx->flags.zf = (lhs == rhs);
        ctx->flags.pf = false;
        ctx->flags.cf = (lhs < rhs);
    }
}

static float select_sse_minmax_float(float lhs, float rhs, bool is_max) {
    if (lhs != lhs || rhs != rhs) return rhs;
    return is_max ? (lhs > rhs ? lhs : rhs) : (lhs < rhs ? lhs : rhs);
}

static double select_sse_minmax_double(double lhs, double rhs, bool is_max) {
    if (lhs != lhs || rhs != rhs) return rhs;
    return is_max ? (lhs > rhs ? lhs : rhs) : (lhs < rhs ? lhs : rhs);
}

static bool hb_float_bits_is_nan(uint32_t bits) {
    return (bits & 0x7f800000u) == 0x7f800000u && (bits & 0x007fffffu) != 0;
}

static bool hb_float_bits_is_inf(uint32_t bits) {
    return (bits & 0x7fffffffu) == 0x7f800000u;
}

static bool hb_float_bits_is_zero(uint32_t bits) {
    return (bits & 0x7fffffffu) == 0;
}

static uint32_t hb_quiet_float_nan_bits(uint32_t bits) {
    return bits | 0x00400000u;
}

static bool hb_double_bits_is_nan(uint64_t bits) {
    return (bits & 0x7ff0000000000000ULL) == 0x7ff0000000000000ULL &&
           (bits & 0x000fffffffffffffULL) != 0;
}

static bool hb_double_bits_is_inf(uint64_t bits) {
    return (bits & 0x7fffffffffffffffULL) == 0x7ff0000000000000ULL;
}

static bool hb_double_bits_is_zero(uint64_t bits) {
    return (bits & 0x7fffffffffffffffULL) == 0;
}

static uint64_t hb_quiet_double_nan_bits(uint64_t bits) {
    return bits | 0x0008000000000000ULL;
}

/* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 904 — КОРЕНЬ ИЗ ОТРИЦАТЕЛЬНОГО.
 *
 * Недопустимая операция на x86 даёт QNaN indefinite со ВЗВЕДЁННЫМ знаком (fff8…/ffc0…).
 * Хозяин ARM64 на том же месте даёт умолчательный NaN со СБРОШЕННЫМ (7ff8…/7fc0…) — замерено:
 * sqrt(-4), 0/0, inf-inf, 0*inf, inf/inf все дают 7ff8000000000000.
 *
 * Для сложения/вычитания/умножения/деления это уже учтено (hb_sse_arith_invalid_double
 * возвращает fff8…), а семья корня звала sqrt() напрямую и знак теряла. Найдено счётом на
 * `c5db51dd` = vsqrtsd xmm3,xmm4,xmm5: xmm5 = -3.25e-193, мы давали 7ff8…, спецификация
 * требует fff8…. Правило то же, что у арифметики: NaN на входе — распространяем (тихим),
 * иначе NaN на выходе означает недопустимую операцию и результат равен indefinite. */
static uint64_t hb_sqrt_family_double_bits(uint64_t src, double result) {
    uint64_t out = hb_double_to_bits(result);
    if (hb_double_bits_is_nan(src)) return hb_quiet_double_nan_bits(src);
    if (hb_double_bits_is_nan(out)) return 0xfff8000000000000ULL;
    return out;
}

static uint32_t hb_sqrt_family_float_bits(uint32_t src, float result) {
    uint32_t out = hb_float_to_bits(result);
    if (hb_float_bits_is_nan(src)) return hb_quiet_float_nan_bits(src);
    if (hb_float_bits_is_nan(out)) return 0xffc00000u;
    return out;
}

static bool hb_sse_arith_invalid_float(uint32_t lhs, uint32_t rhs, hb_ir_op_t op) {
    bool lhs_inf = hb_float_bits_is_inf(lhs), rhs_inf = hb_float_bits_is_inf(rhs);
    bool lhs_zero = hb_float_bits_is_zero(lhs), rhs_zero = hb_float_bits_is_zero(rhs);
    if (op == HB_IR_FADD) return lhs_inf && rhs_inf && ((lhs ^ rhs) & 0x80000000u);
    if (op == HB_IR_FSUB) return lhs_inf && rhs_inf && !((lhs ^ rhs) & 0x80000000u);
    if (op == HB_IR_FMUL) return (lhs_inf && rhs_zero) || (rhs_inf && lhs_zero);
    if (op == HB_IR_FDIV) return (lhs_inf && rhs_inf) || (lhs_zero && rhs_zero);
    return false;
}

static bool hb_sse_arith_invalid_double(uint64_t lhs, uint64_t rhs, hb_ir_op_t op) {
    bool lhs_inf = hb_double_bits_is_inf(lhs), rhs_inf = hb_double_bits_is_inf(rhs);
    bool lhs_zero = hb_double_bits_is_zero(lhs), rhs_zero = hb_double_bits_is_zero(rhs);
    if (op == HB_IR_FADD) return lhs_inf && rhs_inf && ((lhs ^ rhs) & 0x8000000000000000ULL);
    if (op == HB_IR_FSUB) return lhs_inf && rhs_inf && !((lhs ^ rhs) & 0x8000000000000000ULL);
    if (op == HB_IR_FMUL) return (lhs_inf && rhs_zero) || (rhs_inf && lhs_zero);
    if (op == HB_IR_FDIV) return (lhs_inf && rhs_inf) || (lhs_zero && rhs_zero);
    return false;
}

static uint32_t hb_sse_arith_float_bits(uint32_t lhs, uint32_t rhs, hb_ir_op_t op) {
    bool lhs_nan = hb_float_bits_is_nan(lhs), rhs_nan = hb_float_bits_is_nan(rhs);
    if (lhs_nan || rhs_nan) {
        uint32_t chosen = lhs_nan && (!rhs_nan || ((lhs & 0x007fffffu) >= (rhs & 0x007fffffu))) ? lhs : rhs;
        return hb_quiet_float_nan_bits(chosen);
    }
    if (hb_sse_arith_invalid_float(lhs, rhs, op)) return 0xffc00000u;
    float aval = hb_bits_to_float(lhs);
    float bval = hb_bits_to_float(rhs);
    float cval = op == HB_IR_FDIV ? (aval / bval) :
                 (op == HB_IR_FMUL ? (aval * bval) :
                  (op == HB_IR_FSUB ? (aval - bval) : (aval + bval)));
    return hb_float_to_bits(cval);
}

static uint32_t hb_sse_add_float_bits_er(uint32_t lhs, uint32_t rhs, unsigned er_mode) {
    if (er_mode <= 1) return hb_sse_arith_float_bits(lhs, rhs, HB_IR_FADD);
    if (hb_float_bits_is_nan(lhs) || hb_float_bits_is_nan(rhs) ||
        hb_sse_arith_invalid_float(lhs, rhs, HB_IR_FADD))
        return hb_sse_arith_float_bits(lhs, rhs, HB_IR_FADD);

    float aval = hb_bits_to_float(lhs);
    float bval = hb_bits_to_float(rhs);
    if (isinf(aval) || isinf(bval)) return hb_sse_arith_float_bits(lhs, rhs, HB_IR_FADD);

    long double exact = (long double)aval + (long double)bval;
    float candidate = (float)exact;
    long double rounded = (long double)candidate;

    if (er_mode == 2) {
        if (rounded > exact) candidate = nextafterf(candidate, -INFINITY);
    } else if (er_mode == 3) {
        if (rounded < exact) candidate = nextafterf(candidate, INFINITY);
    } else if (er_mode == 4) {
        if (exact > 0.0L && rounded > exact) candidate = nextafterf(candidate, -INFINITY);
        else if (exact < 0.0L && rounded < exact) candidate = nextafterf(candidate, INFINITY);
    }
    return hb_float_to_bits(candidate);
}

static uint64_t hb_sse_arith_double_bits(uint64_t lhs, uint64_t rhs, hb_ir_op_t op) {
    bool lhs_nan = hb_double_bits_is_nan(lhs), rhs_nan = hb_double_bits_is_nan(rhs);
    if (lhs_nan || rhs_nan) {
        uint64_t chosen = lhs_nan && (!rhs_nan || ((lhs & 0x000fffffffffffffULL) >= (rhs & 0x000fffffffffffffULL))) ? lhs : rhs;
        return hb_quiet_double_nan_bits(chosen);
    }
    if (hb_sse_arith_invalid_double(lhs, rhs, op)) return 0xfff8000000000000ULL;
    double aval = hb_bits_to_double(lhs);
    double bval = hb_bits_to_double(rhs);
    double cval = op == HB_IR_FDIV ? (aval / bval) :
                  (op == HB_IR_FMUL ? (aval * bval) :
                   (op == HB_IR_FSUB ? (aval - bval) : (aval + bval)));
    return hb_double_to_bits(cval);
}

static int16_t sat_i16(int32_t v) {
    if (v > 32767) return 32767;
    if (v < -32768) return -32768;
    return (int16_t)v;
}

static int8_t sat_i8(int32_t v) {
    if (v > 127) return 127;
    if (v < -128) return -128;
    return (int8_t)v;
}

static uint16_t sat_u16_from_i32(int32_t v) {
    if (v < 0) return 0;
    if (v > 65535) return 65535;
    return (uint16_t)v;
}

static int64_t load_lane_signed(const uint8_t* p, unsigned lane) {
    if (lane == 1) return (int8_t)p[0];
    if (lane == 2) { int16_t v; memcpy(&v, p, sizeof(v)); return v; }
    if (lane == 4) { int32_t v; memcpy(&v, p, sizeof(v)); return v; }
    int64_t v; memcpy(&v, p, sizeof(v)); return v;
}

static uint64_t load_lane_unsigned(const uint8_t* p, unsigned lane) {
    if (lane == 1) return p[0];
    if (lane == 2) { uint16_t v; memcpy(&v, p, sizeof(v)); return v; }
    if (lane == 4) { uint32_t v; memcpy(&v, p, sizeof(v)); return v; }
    uint64_t v; memcpy(&v, p, sizeof(v)); return v;
}

static void store_lane(uint8_t* p, unsigned lane, uint64_t v) {
    if (lane == 1) p[0] = (uint8_t)v;
    else if (lane == 2) { uint16_t w = (uint16_t)v; memcpy(p, &w, sizeof(w)); }
    else if (lane == 4) { uint32_t d = (uint32_t)v; memcpy(p, &d, sizeof(d)); }
    else { uint64_t q = v; memcpy(p, &q, sizeof(q)); }
}

/* SHA-NI helpers (Intel SDM Vol 2). These are pure functions over uint32_t
 * state, kept as file-static so the per-op dispatch can call them without
 * lambda overhead. Operands are little-endian dwords. */
static inline uint32_t sha_rol(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32 - n));
}
static inline uint32_t sha_ror(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}
static inline uint32_t sha_ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
}
static inline uint32_t sha_maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}
static inline uint32_t sha_parity(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}
/* Big-sigma0 (SHA-256): ROR(x,2) ^ ROR(x,13) ^ ROR(x,22). */
static inline uint32_t sha_bigsig0(uint32_t x) {
    return sha_ror(x, 2) ^ sha_ror(x, 13) ^ sha_ror(x, 22);
}
/* Big-sigma1 (SHA-256): ROR(x,6) ^ ROR(x,11) ^ ROR(x,25). */
static inline uint32_t sha_bigsig1(uint32_t x) {
    return sha_ror(x, 6) ^ sha_ror(x, 11) ^ sha_ror(x, 25);
}
/* Small-sigma0 (SHA-256): ROR(x,7) ^ ROR(x,18) ^ SHR(x,3). */
static inline uint32_t sha_smallsig0(uint32_t x) {
    return sha_ror(x, 7) ^ sha_ror(x, 18) ^ (x >> 3);
}
/* Small-sigma1 (SHA-256): ROR(x,17) ^ ROR(x,19) ^ SHR(x,10). */
static inline uint32_t sha_smallsig1(uint32_t x) {
    return sha_ror(x, 17) ^ sha_ror(x, 19) ^ (x >> 10);
}

static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint32_t aes_subword(uint32_t w) {
    uint32_t out = 0;
    for (unsigned i = 0; i < 4; i++) out |= (uint32_t)aes_sbox[(w >> (i * 8)) & 0xffu] << (i * 8);
    return out;
}

static uint32_t aes_rotword(uint32_t w) {
    return (w >> 8) | (w << 24);
}

static uint8_t aes_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80u) ? 0x1bu : 0u));
}

static uint8_t aes_gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1u) r ^= a;
        a = aes_xtime(a);
        b >>= 1;
    }
    return r;
}

static uint8_t gf2p8_inv(uint8_t value) {
    if (!value) return 0;
    uint8_t result = 1;
    uint8_t base = value;
    unsigned exp = 254;
    while (exp) {
        if (exp & 1u) result = aes_gmul(result, base);
        base = aes_gmul(base, base);
        exp >>= 1;
    }
    return result;
}

static uint8_t gf2p8_parity8(uint8_t value) {
    value ^= (uint8_t)(value >> 4);
    value ^= (uint8_t)(value >> 2);
    value ^= (uint8_t)(value >> 1);
    return value & 1u;
}

static uint8_t gf2p8_affine_byte(uint8_t value, const uint8_t matrix[8], uint8_t imm) {
    uint8_t out = 0;
    for (unsigned bit = 0; bit < 8; bit++) {
        uint8_t b = gf2p8_parity8((uint8_t)(value & matrix[bit]));
        b ^= (uint8_t)((imm >> bit) & 1u);
        out |= (uint8_t)(b << bit);
    }
    return out;
}

static uint8_t aes_inv_sbox_byte(uint8_t v) {
    for (unsigned i = 0; i < 256; i++) {
        if (aes_sbox[i] == v) return (uint8_t)i;
    }
    return 0;
}

static void aes_sub_bytes(uint8_t s[16], bool inverse) {
    for (unsigned i = 0; i < 16; i++) {
        s[i] = inverse ? aes_inv_sbox_byte(s[i]) : aes_sbox[s[i]];
    }
}

static void aes_shift_rows(uint8_t s[16], bool inverse) {
    uint8_t t[16];
    for (unsigned row = 0; row < 4; row++) {
        for (unsigned col = 0; col < 4; col++) {
            unsigned src_col = inverse ? ((col + 4 - row) & 3u) : ((col + row) & 3u);
            t[col * 4 + row] = s[src_col * 4 + row];
        }
    }
    memcpy(s, t, sizeof(t));
}

static void aes_mix_columns(uint8_t s[16], bool inverse) {
    for (unsigned col = 0; col < 4; col++) {
        uint8_t *a = s + col * 4;
        uint8_t r0, r1, r2, r3;
        if (inverse) {
            r0 = (uint8_t)(aes_gmul(a[0], 14) ^ aes_gmul(a[1], 11) ^ aes_gmul(a[2], 13) ^ aes_gmul(a[3], 9));
            r1 = (uint8_t)(aes_gmul(a[0], 9) ^ aes_gmul(a[1], 14) ^ aes_gmul(a[2], 11) ^ aes_gmul(a[3], 13));
            r2 = (uint8_t)(aes_gmul(a[0], 13) ^ aes_gmul(a[1], 9) ^ aes_gmul(a[2], 14) ^ aes_gmul(a[3], 11));
            r3 = (uint8_t)(aes_gmul(a[0], 11) ^ aes_gmul(a[1], 13) ^ aes_gmul(a[2], 9) ^ aes_gmul(a[3], 14));
        } else {
            r0 = (uint8_t)(aes_gmul(a[0], 2) ^ aes_gmul(a[1], 3) ^ a[2] ^ a[3]);
            r1 = (uint8_t)(a[0] ^ aes_gmul(a[1], 2) ^ aes_gmul(a[2], 3) ^ a[3]);
            r2 = (uint8_t)(a[0] ^ a[1] ^ aes_gmul(a[2], 2) ^ aes_gmul(a[3], 3));
            r3 = (uint8_t)(aes_gmul(a[0], 3) ^ a[1] ^ a[2] ^ aes_gmul(a[3], 2));
        }
        a[0] = r0;
        a[1] = r1;
        a[2] = r2;
        a[3] = r3;
    }
}

static void aes_xor_key(uint8_t s[16], const uint8_t key[16]) {
    for (unsigned i = 0; i < 16; i++) s[i] ^= key[i];
}

static void aes_round128(hb_ir_vec_op_t vop, const uint8_t state[16],
                         const uint8_t key[16], uint8_t out[16]) {
    memcpy(out, state, 16);
    if (vop == HB_VEC_AESIMC) {
        aes_mix_columns(out, true);
        return;
    }
    if (vop == HB_VEC_AESENC || vop == HB_VEC_AESENCLAST) {
        aes_sub_bytes(out, false);
        aes_shift_rows(out, false);
        if (vop == HB_VEC_AESENC) aes_mix_columns(out, false);
        aes_xor_key(out, key);
        return;
    }
    if (vop == HB_VEC_AESDEC) {
        aes_shift_rows(out, true);
        aes_sub_bytes(out, true);
        aes_mix_columns(out, true);
        aes_xor_key(out, key);
        return;
    }
    if (vop == HB_VEC_AESDECLAST) {
        aes_shift_rows(out, true);
        aes_sub_bytes(out, true);
        aes_xor_key(out, key);
    }
}

static void pclmul64(uint64_t a, uint64_t b, uint8_t out[16]) {
    __uint128_t acc = 0;
    for (unsigned bit = 0; bit < 64; bit++) {
        if ((b >> bit) & 1u) acc ^= ((__uint128_t)a) << bit;
    }
    uint64_t lo = (uint64_t)acc;
    uint64_t hi = (uint64_t)(acc >> 64);
    memcpy(out, &lo, sizeof(lo));
    memcpy(out + 8, &hi, sizeof(hi));
}

static int pcmp_explicit_len(uint32_t raw, unsigned max_units) {
    int32_t signed_len = (int32_t)raw;
    int64_t len = signed_len < 0 ? -(int64_t)signed_len : (int64_t)signed_len;
    if (len > (int64_t)max_units) len = max_units;
    return (int)len;
}

static uint64_t pcmp_unit_unsigned(const uint8_t* bytes, unsigned unit, unsigned idx) {
    if (unit == 1) return bytes[idx];
    uint16_t v;
    memcpy(&v, bytes + idx * 2, sizeof(v));
    return v;
}

static int64_t pcmp_unit_signed(const uint8_t* bytes, unsigned unit, unsigned idx) {
    if (unit == 1) return (int8_t)bytes[idx];
    int16_t v;
    memcpy(&v, bytes + idx * 2, sizeof(v));
    return v;
}

static int pcmp_implicit_len(const uint8_t* bytes, unsigned unit, unsigned max_units) {
    for (unsigned i = 0; i < max_units; i++) {
        if (pcmp_unit_unsigned(bytes, unit, i) == 0) return (int)i;
    }
    return (int)max_units;
}

static uint32_t pcmpxstr_result(hb_context_t* ctx, hb_ir_vec_op_t vop,
                                const uint8_t lhs[16], const uint8_t rhs[16],
                                unsigned imm, unsigned* max_units_out,
                                int* len1_out, int* len2_out) {
    unsigned unit = (imm & 1u) ? 2 : 1;
    bool is_signed = (imm & 2u) != 0;
    unsigned max_units = 16 / unit;
    bool explicit_len = vop == HB_VEC_PCMPESTRM || vop == HB_VEC_PCMPESTRI;
    int len1 = explicit_len ? pcmp_explicit_len((uint32_t)ctx->regs.x64.rax, max_units)
                            : pcmp_implicit_len(lhs, unit, max_units);
    int len2 = explicit_len ? pcmp_explicit_len((uint32_t)ctx->regs.x64.rdx, max_units)
                            : pcmp_implicit_len(rhs, unit, max_units);
    uint32_t res1 = 0;
    unsigned aggregation = (imm >> 2) & 3u;
    for (unsigned j = 0; j < max_units; j++) {
        bool bit = false;
        if (aggregation == 0) {
            if ((int)j < len2) {
                for (int i = 0; i < len1; i++) {
                    if (pcmp_unit_unsigned(lhs, unit, (unsigned)i) ==
                        pcmp_unit_unsigned(rhs, unit, j)) { bit = true; break; }
                }
            }
        } else if (aggregation == 1) {
            if ((int)j < len2) {
                for (int i = 0; i + 1 < len1; i += 2) {
                    if (is_signed) {
                        int64_t lo = pcmp_unit_signed(lhs, unit, (unsigned)i);
                        int64_t hi = pcmp_unit_signed(lhs, unit, (unsigned)(i + 1));
                        int64_t v = pcmp_unit_signed(rhs, unit, j);
                        if (lo <= v && v <= hi) { bit = true; break; }
                    } else {
                        uint64_t lo = pcmp_unit_unsigned(lhs, unit, (unsigned)i);
                        uint64_t hi = pcmp_unit_unsigned(lhs, unit, (unsigned)(i + 1));
                        uint64_t v = pcmp_unit_unsigned(rhs, unit, j);
                        if (lo <= v && v <= hi) { bit = true; break; }
                    }
                }
            }
        } else if (aggregation == 2) {
            if ((int)j < len1 && (int)j < len2 &&
                pcmp_unit_unsigned(lhs, unit, j) == pcmp_unit_unsigned(rhs, unit, j)) bit = true;
        } else {
            if (len1 == 0) {
                bit = (int)j <= len2;
            } else if ((int)j + len1 <= len2) {
                bit = true;
                for (int i = 0; i < len1; i++) {
                    if (pcmp_unit_unsigned(lhs, unit, (unsigned)i) !=
                        pcmp_unit_unsigned(rhs, unit, (unsigned)(j + i))) { bit = false; break; }
                }
            }
        }
        if (bit) res1 |= 1u << j;
    }
    uint32_t full = max_units == 16 ? 0xffffu : 0xffu;
    uint32_t valid2 = len2 >= (int)max_units ? full : ((1u << len2) - 1u);
    uint32_t polarity = (imm >> 4) & 3u;
    uint32_t res2 = res1;
    if (polarity == 1) res2 = (~res1) & full;
    else if (polarity == 2) res2 = res1 & valid2;
    else if (polarity == 3) res2 = (~res1) & valid2;
    *max_units_out = max_units;
    *len1_out = len1;
    *len2_out = len2;
    return res2 & full;
}

static hb_result_t read_xmm_operand(hb_context_t* ctx, const hb_ir_operand_t* op, uint64_t out[2]) {
    if (!ctx || !op || !out) return HB_ERR_INVALID_ARG;
    if (op->type == HB_OP_REG && is_xmm_reg(op->reg)) return read_xmm_reg(ctx, op->reg, out);
    if (op->type == HB_OP_MEM) {
        uint64_t addr = resolve_addr(ctx, op);
        return hb_memory_read(ctx->memory, addr, out, sizeof(uint64_t) * 2);
    }
    return HB_ERR_INTERNAL;
}

static hb_result_t read_xmm_operand_bytes(hb_context_t* ctx, const hb_ir_operand_t* op,
                                          uint8_t* out, size_t bytes) {
    if (!ctx || !op || !out || bytes > 64) return HB_ERR_INVALID_ARG;
    memset(out, 0, bytes);
    if (op->type == HB_OP_REG && is_xmm_reg(op->reg)) {
        return read_vec_reg_bytes(ctx, op->reg, out, bytes);
    }
    if (op->type == HB_OP_REG && is_mm_reg(op->reg)) {
        /* Итерация 918: файл MMX отдельный и шириной ровно 8 байт. */
        const uint64_t* mm = hb_mmx_regs(ctx);
        if (!mm || bytes > 8) return HB_ERR_INTERNAL;
        memcpy(out, &mm[op->reg - HB_REG_MM0], bytes);
        return HB_OK;
    }
    if (op->type == HB_OP_MEM) {
        uint64_t addr = resolve_addr(ctx, op);
        return hb_memory_read(ctx->memory, addr, out, bytes);
    }
    return HB_ERR_INTERNAL;
}

static hb_result_t read_packed_shift_count(hb_context_t* ctx, const hb_ir_operand_t* op,
                                           unsigned* out_count) {
    if (!ctx || !op || !out_count) return HB_ERR_INVALID_ARG;
    if (op->type == HB_OP_IMM) {
        *out_count = (unsigned)(op->imm & 0xff);
        return HB_OK;
    }
    uint8_t bytes[16];
    hb_result_t r = read_xmm_operand_bytes(ctx, op, bytes, sizeof(bytes));
    if (r != HB_OK) return r;
    uint64_t raw = 0;
    memcpy(&raw, bytes, sizeof(raw));
    /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1052 — СЧЁТЧИК НЕЛЬЗЯ УСЕКАТЬ.
     * Здесь стояло `raw & 0xff`, и счётчик 0x0000000100000002 превращался в 2: команда
     * сдвигала на два разряда вместо насыщения. По спецификации счётчик берётся ЦЕЛИКОМ
     * из младших 64 бит источника, и если он больше ширины элемента, все элементы
     * обращаются в 0 (логический сдвиг) или в знак (арифметический).
     * Замер пробой с помеченными входами: при счётчике 32 мы давали верное
     * `ffff 0000 ffff 0000 ...`, а при 0x100000002 — `e000 0000 ffff 0000 ...`, то есть
     * ровно сдвиг на 2. Ограничиваем 255: любое значение выше ширины элемента ведёт себя
     * одинаково, а в `unsigned` оно помещается. */
    *out_count = (raw > 255u) ? 255u : (unsigned)raw;
    return HB_OK;
}

static void write_reg(hb_context_t* ctx, int idx, uint64_t val) {
    if (ctx->mode == HB_MODE_32BIT) {
        uint32_t* p = reg_ptr_x86(&ctx->regs.x86, idx);
        if (p) *p = (uint32_t)val;
    } else {
        uint64_t* p = reg_ptr_x64(&ctx->regs.x64, idx);
        if (p) *p = val;
    }
}

static uint64_t mask_for_size(hb_size_t size) {
    switch (size) {
        case HB_SIZE_8: return 0xffULL;
        case HB_SIZE_16: return 0xffffULL;
        case HB_SIZE_32: return 0xffffffffULL;
        default: return 0xffffffffffffffffULL;
    }
}

static uint64_t trunc_to_size(uint64_t val, hb_size_t size) {
    return val & mask_for_size(size);
}

static uint64_t read_reg_sized(hb_context_t* ctx, int idx, hb_size_t size, uint8_t reg_offset) {
    return (read_reg(ctx, idx) >> ((unsigned)reg_offset * 8u)) & mask_for_size(size);
}

static uint64_t sign_extend_from_size(uint64_t val, hb_size_t size) {
    switch (size) {
        case HB_SIZE_8:  return (uint64_t)(int64_t)(int8_t)val;
        case HB_SIZE_16: return (uint64_t)(int64_t)(int16_t)val;
        case HB_SIZE_32: return (uint64_t)(int64_t)(int32_t)val;
        default: return val;
    }
}

static unsigned bit_width_for_size(hb_size_t size) {
    switch (size) {
        case HB_SIZE_8: return 8;
        case HB_SIZE_16: return 16;
        case HB_SIZE_32: return 32;
        default: return 64;
    }
}

static unsigned popcount_u64(uint64_t value) {
    unsigned count = 0;
    while (value) {
        value &= value - 1;
        count++;
    }
    return count;
}

static bool parity_even_u8(uint8_t v) {
    return (popcount_u64(v) & 1u) == 0u;
}

static uint32_t hb_size_bytes(hb_size_t sz) {
    switch (sz) {
        case HB_SIZE_8:   return 1u;
        case HB_SIZE_16:  return 2u;
        case HB_SIZE_32:  return 4u;
        case HB_SIZE_64:  return 8u;
        case HB_SIZE_128: return 16u;
        case HB_SIZE_256: return 32u;
        case HB_SIZE_512: return 64u;
        default: return 0u;
    }
}

static void write_reg_sized(hb_context_t* ctx, int idx, uint64_t val, hb_size_t size) {
    if (ctx->mode == HB_MODE_32BIT) {
        if (size == HB_SIZE_8 || size == HB_SIZE_16) {
            uint64_t old = read_reg(ctx, idx);
            uint64_t mask = mask_for_size(size);
            write_reg(ctx, idx, (old & ~mask) | (val & mask));
        } else {
            write_reg(ctx, idx, val);
        }
        return;
    }

    if (size == HB_SIZE_32) {
        write_reg(ctx, idx, (uint32_t)val); /* x86-64 32-bit register writes zero-extend. */
    } else if (size == HB_SIZE_8 || size == HB_SIZE_16) {
        uint64_t old = read_reg(ctx, idx);
        uint64_t mask = mask_for_size(size);
        write_reg(ctx, idx, (old & ~mask) | (val & mask));
    } else {
        write_reg(ctx, idx, val);
    }
}

static void write_reg_sized_offset(hb_context_t* ctx, int idx, uint64_t val,
                                   hb_size_t size, uint8_t reg_offset) {
    if (reg_offset == 0) {
        write_reg_sized(ctx, idx, val, size);
        return;
    }
    uint64_t old = read_reg(ctx, idx);
    unsigned shift = (unsigned)reg_offset * 8u;
    uint64_t mask = mask_for_size(size) << shift;
    write_reg(ctx, idx, (old & ~mask) | ((val << shift) & mask));
}

/* Memory address resolution */
static uint64_t resolve_addr(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint64_t base = 0;
    if (op->mem.base < HB_REG_COUNT) {
        if (op->mem.base == HB_REG_RIP) base = ctx->pc;
        else base = read_reg(ctx, op->mem.base);
    }
    uint64_t index = 0;
    if (op->mem.index < HB_REG_COUNT) {
        index = read_reg(ctx, op->mem.index);
    }
    if (op->mem.segment == 0x64) base += ctx->fs_base;
    else if (op->mem.segment == 0x65) base += ctx->gs_base;
    if (ctx->mode == HB_MODE_32BIT) {
        uint32_t base32 = (uint32_t)base;
        uint32_t index32 = (uint32_t)index;
        return (uint32_t)(base32 + index32 * op->mem.scale + (uint32_t)op->mem.disp);
    }
    if (op->mem.addr32) {
        uint32_t base32 = (uint32_t)base;
        uint32_t index32 = (uint32_t)index;
        return (uint32_t)(base32 + index32 * op->mem.scale + (uint32_t)op->mem.disp);
    }
    /* Итерация 283: при 16-битной адресации (префикс 0x67 у i386) эффективный адрес
       считается по модулю 0x10000 — иначе сумма BX+SI+disp вылезет за сегмент. */
    if (op->mem.addr16 && hb_gate( HB_GATE_HB_ADDR16 ) && hb_gate( HB_GATE_HB_ADDR16 )[0]=='1') {
        uint64_t a16 = base + index * op->mem.scale + (uint64_t)op->mem.disp;
        return a16 & 0xFFFFu;
    }
    return base + index * op->mem.scale + (uint64_t)op->mem.disp;
}

/* Find block by guest address */
static hb_ir_block_t* find_block(hb_ir_cfg_t* cfg, uint64_t addr) {
    for (size_t i = 0; i < cfg->block_count; i++) {
        if (cfg->blocks[i]->guest_addr == addr) return cfg->blocks[i];
    }
    return NULL;
}

/* ★★★ MacRunner 2026-09-07, лейн ОРАКУЛ-2 — ВХОД ПО АДРЕСУ ВНУТРИ БЛОКА.
 *
 * ЗАЧЕМ. `find_block` ищет блок по адресу его НАЧАЛА. Подъёмник x86-64 режет блок ПОСЛЕ
 * перехода (на адресе проваливания), но НЕ режет его в ЦЕЛИ перехода — поэтому у случая
 * `cmp al,cl ; jb +3 ; adc ; sbb ; add` цель `0x140000007` лежит В СЕРЕДИНЕ блока
 * `0x140000004`, `find_block` даёт NULL, и цикл ниже принимает это за «управление ушло из
 * переведённой функции»: возвращает HB_OK, оставив гостя на первом же взятом переходе.
 *
 * Для ЖИВОГО пути это допустимо — диспетчер переведёт с этого pc заново. Для ЭТАЛОНА
 * дифференциального стенда это слепота по построению: эталон кончает на `0x140000007`,
 * выпуск слитой единицы доводит гостя до `0x14000000d`, и стенд объявляет расхождение
 * там, где расходится не выпуск, а ОХВАТ ЭТАЛОНА. Измерено лейном ФЛАГИ-2:
 * `MACRUNNER_HB_MERGE_BLOCKS=1` был красен на 100 % ещё ДО его правок.
 *
 * ГЕЙТ `MACRUNNER_HB_INTERP_MIDBLOCK`, УМОЛЧАНИЕ 0 — живой путь байт в байт прежний.
 * Стенд `hb_diff_case_runner` включает его САМ (setenv с overwrite=0, до первого чтения
 * гейта), поэтому «выключено по умолчанию» здесь не значит «не проверяется»: оракул
 * гоняет ВКЛЮЧЁННЫМ всегда, а ноль в окружении оставлен как отрицательный контроль.
 *
 * ГРАНИЦА ПОИСКА. Совпадение по началу блока проверяется ПЕРВЫМ и отдельно: это прежнее
 * поведение, и оно не должно зависеть от порядка блоков в CFG. Внутрь блока пускаем
 * только по адресу СТРОГО БОЛЬШЕМУ его начала — иначе `guest_addr == 0` у служебных
 * команд IR совпал бы с нулевым адресом перехода и выдал бы ложный вход. Индекс берётся
 * ПЕРВЫЙ по возрастанию: одна гостевая команда раскрывается в несколько команд IR с
 * одним и тем же `guest_addr`, и начинать надо с первой из них. */
static int interp_midblock_enabled(void) {
    return hb_gate_flag(HB_GATE_HB_INTERP_MIDBLOCK, 0);
}

/* ★ ОТРИЦАТЕЛЬНЫЕ КОНТРОЛИ САМОЙ ПРАВКИ. Без них «корпус позеленел» не отличается от
 * «прибор перестал смотреть»: вход в середину блока мог бы и не случиться ни разу, а
 * зелёный цвет читался бы как доказательство. Порчи ломают ровно ИНДЕКС начала — то
 * единственное, что правка добавила, — и корпус ОБЯЗАН на них покраснеть.
 *   SKEW = 1 -> начать на команду ПОЗЖЕ (пропустить первую команду цели)
 *   ZERO = 1 -> начать с НАЧАЛА блока (повторить уже исполненное) */
static int interp_midblock_skew(void) {
    return hb_gate_flag(HB_GATE_HB_TEST_MIDBLOCK_SKEW, 0);
}
static int interp_midblock_zero(void) {
    return hb_gate_flag(HB_GATE_HB_TEST_MIDBLOCK_ZERO, 0);
}

/* ★ ПРИБОР. Без него «отказов стало 0» неотличимо от «вход в середину ни разу не
 * понадобился»: оба дают зелёный цвет. looked считается БЕЗУСЛОВНО на каждой передаче
 * управления, hits — только на действительном входе внутрь блока, поэтому ноль второго
 * рода (смотрел, явления нет) отличается от нуля первого (управление не дошло). */
HB_PROBE_DEFINE(pr_midblock, "hb-interp-midblock",
                "передачи управления, у которых интерпретатор искал блок по гостевому "
                "адресу (looked); hits — те, где точного совпадения с НАЧАЛОМ блока не "
                "нашлось и вход состоялся ВНУТРЬ блока с ненулевой стартовой команды. "
                "hits=0 при looked>0 значит «целей внутри блока не было», а не «правка "
                "выключена»: выключенная правка даёт hits=0 И отказы rip",
                "MACRUNNER_HB_INTERP_MIDBLOCK", 0);

static hb_ir_block_t* find_block_containing(hb_ir_cfg_t* cfg, uint64_t addr, size_t* out_start) {
    if (out_start) *out_start = 0;
    HB_PROBE_LOOKED(&pr_midblock);
    hb_ir_block_t* exact = find_block(cfg, addr);
    if (exact) return exact;
    if (!interp_midblock_enabled()) return NULL;
    for (size_t i = 0; i < cfg->block_count; i++) {
        hb_ir_block_t* blk = cfg->blocks[i];
        if (addr <= blk->guest_addr) continue;
        for (size_t j = 0; j < blk->instr_count; j++) {
            if (blk->instrs[j].guest_addr == addr) {
                size_t nachalo = j;
                if (interp_midblock_zero()) nachalo = 0;
                else if (interp_midblock_skew() && j + 1 < blk->instr_count) nachalo = j + 1;
                HB_PROBE_HIT(&pr_midblock);
                if (out_start) *out_start = nachalo;
                return blk;
            }
        }
    }
    return NULL;
}

/* Memory read/write by size */
static hb_result_t mem_read(hb_context_t* ctx, uint64_t addr, uint64_t* out, hb_size_t sz) {
    switch (sz) {
        case HB_SIZE_8: {
            uint8_t v;
            hb_result_t r = hb_memory_read_u8(ctx->memory, addr, &v);
            if (r != HB_OK) return r;
            *out = v;
            if (trace_mem_watch_enabled()) trace_mem_watch_bytes(ctx, "read", addr, &v, sizeof(v), NULL);
            return HB_OK;
        }
        case HB_SIZE_16: {
            uint16_t v;
            hb_result_t r = hb_memory_read_u16(ctx->memory, addr, &v);
            if (r != HB_OK) return r;
            *out = v;
            if (trace_mem_watch_enabled()) trace_mem_watch_bytes(ctx, "read", addr, &v, sizeof(v), NULL);
            return HB_OK;
        }
        case HB_SIZE_32: {
            uint32_t v;
            hb_result_t r = hb_memory_read_u32(ctx->memory, addr, &v);
            if (r != HB_OK) return r;
            *out = v;
            if (trace_mem_watch_enabled()) trace_mem_watch_bytes(ctx, "read", addr, &v, sizeof(v), NULL);
            return HB_OK;
        }
        case HB_SIZE_64: {
            uint64_t v;
            hb_result_t r = hb_memory_read_u64(ctx->memory, addr, &v);
            if (r != HB_OK) return r;
            *out = v;
            if (trace_mem_watch_enabled()) trace_mem_watch_bytes(ctx, "read", addr, &v, sizeof(v), NULL);
            return HB_OK;
        }
        default:
            return HB_ERR_MEMORY_FAULT;
    }
}

static const hb_region_t* nearest_region(hb_memory_t* mem, uint64_t addr, int below) {
    const hb_region_t* best = NULL;
    if (!mem) return NULL;
    for (const hb_region_t* r = mem->regions; r; r = r->next) {
        uint64_t start = r->base;
        uint64_t end = r->base + r->size;
        if (below) {
            if (end <= addr && (!best || end > best->base + best->size)) best = r;
        } else {
            if (start > addr && (!best || start < best->base)) best = r;
        }
    }
    return best;
}

static void trace_stack_write_fault(hb_context_t* ctx, uint64_t addr, uint64_t val, hb_size_t sz, hb_result_t result) {
    static int budget = 0;
    if (!(trace_runtime_flags & TRACE_FLAG_STACK_FAULTS)) return;
    if (++budget > 20) return;

    hb_memory_t* mem = ctx ? ctx->memory : NULL;
    uint64_t rsp = ctx ? ctx->regs.x64.rsp : 0;
    hb_trace_rsite = HB_RSITE_INTERP;
    const hb_region_t* hit = mem ? hb_memory_find_region(mem, addr) : NULL;
    hb_trace_rsite = 0;
    const hb_region_t* below = nearest_region(mem, addr, 1);
    const hb_region_t* above = nearest_region(mem, addr, 0);

    fprintf(stderr,
            "macrunner-hb-stack-fault: result=%d addr=0x%llx size=%u value=0x%llx "
            "rip=0x%llx rsp=0x%llx stack=[0x%llx..0x%llx]\n",
            result, (unsigned long long)addr, (unsigned)sz, (unsigned long long)val,
            (unsigned long long)(ctx ? ctx->regs.x64.rip : 0),
            (unsigned long long)rsp,
            (unsigned long long)(mem ? mem->stack_bottom : 0),
            (unsigned long long)(mem ? mem->stack_top : 0));
    if (hit) {
        fprintf(stderr,
                "macrunner-hb-stack-fault: containing region base=0x%llx size=0x%zx perm=0x%x "
                "stack=%d heap=%d guard=%d allocated=%d\n",
                (unsigned long long)hit->base, hit->size, hit->perm,
                hit->is_stack, hit->is_heap, hit->is_guard, hit->allocated);
    } else {
        fprintf(stderr, "macrunner-hb-stack-fault: containing region none\n");
    }
    if (below) {
        fprintf(stderr,
                "macrunner-hb-stack-fault: below region base=0x%llx end=0x%llx size=0x%zx perm=0x%x "
                "stack=%d heap=%d guard=%d allocated=%d\n",
                (unsigned long long)below->base, (unsigned long long)(below->base + below->size),
                below->size, below->perm, below->is_stack, below->is_heap, below->is_guard, below->allocated);
    }
    if (above) {
        fprintf(stderr,
                "macrunner-hb-stack-fault: above region base=0x%llx end=0x%llx size=0x%zx perm=0x%x "
                "stack=%d heap=%d guard=%d allocated=%d\n",
                (unsigned long long)above->base, (unsigned long long)(above->base + above->size),
                above->size, above->perm, above->is_stack, above->is_heap, above->is_guard, above->allocated);
    }
}

static hb_result_t mem_write(hb_context_t* ctx, uint64_t addr, uint64_t val, hb_size_t sz) {
    hb_result_t r;
    uint8_t before[8] = {0};
    size_t bytes = (size_t)sz;
    if (bytes > sizeof(before)) bytes = sizeof(before);
    if (trace_mem_watch_enabled() && bytes)
        (void)hb_memory_read(ctx->memory, addr, before, bytes);
    trace_guest_native_write(ctx, "interp_mem_write", addr, val, sz);
    switch (sz) {
        case HB_SIZE_8:  r = hb_memory_write_u8(ctx->memory, addr, (uint8_t)val); break;
        case HB_SIZE_16: r = hb_memory_write_u16(ctx->memory, addr, (uint16_t)val); break;
        case HB_SIZE_32: r = hb_memory_write_u32(ctx->memory, addr, (uint32_t)val); break;
        case HB_SIZE_64: r = hb_memory_write_u64(ctx->memory, addr, val); break;
        default: r = HB_ERR_MEMORY_FAULT; break;
    }
    if (r != HB_OK) trace_stack_write_fault(ctx, addr, val, sz, r);
    else if (trace_mem_watch_enabled()) trace_mem_watch_bytes(ctx, "write", addr, &val, (size_t)sz, before);
    return r;
}

static double ext80_to_double(const uint8_t bytes[10]) {
    uint64_t sig;
    uint16_t se;
    bool neg;
    unsigned exp;

    memcpy(&sig, bytes, sizeof(sig));
    memcpy(&se, bytes + 8, sizeof(se));
    neg = (se & 0x8000u) != 0;
    exp = se & 0x7fffu;
    if (exp == 0 && sig == 0) {
        return neg ? -0.0 : 0.0;
    }
    if (exp == 0x7fffu) {
        return (sig == 0x8000000000000000ULL) ? (neg ? -INFINITY : INFINITY) : NAN;
    }
    {
        double frac = (double)sig / 9223372036854775808.0;
        int unbiased = (int)(exp ? exp : 1) - 16383;
        double out = ldexp(frac, unbiased);
        return neg ? -out : out;
    }
}

static hb_result_t x87_read_real_mem(hb_context_t* ctx, const hb_ir_operand_t* op, double* out) {
    uint64_t addr = resolve_addr(ctx, op);

    if (!out) return HB_ERR_INVALID_ARG;
    if (op->size == HB_SIZE_32) {
        float f;
        hb_result_t r = hb_memory_read(ctx->memory, addr, &f, sizeof(f));
        if (r != HB_OK) return r;
        *out = (double)f;
    } else if (op->size == HB_SIZE_64) {
        hb_result_t r = hb_memory_read(ctx->memory, addr, out, sizeof(*out));
        if (r != HB_OK) return r;
    } else if (op->size == HB_SIZE_80) {
        uint8_t bytes[10];
        hb_result_t r = hb_memory_read(ctx->memory, addr, bytes, sizeof(bytes));
        if (r != HB_OK) return r;
        *out = ext80_to_double(bytes);
    } else {
        return HB_ERR_UNSUPPORTED_FEATURE;
    }
    return HB_OK;
}

/* ★ 30.08, лейн УСТАНОВЩИКИ — ПОМЕТИТЬ ОТКАЗ СТЕКА x87 ВИДОМ ОТКАЗА.
 *
 * Мест PUSH в интерпретаторе ВОСЕМЬ, и все они возвращали безликий `EXEC_FAULT`.
 * Правка одного места (того, на котором споткнулись) дала бы ровно тот «один предмет
 * за прогон», который в проекте запрещён: набор конечный и перечислим, значит
 * закрывается целиком. Обёртка одна на все восемь. */
static hb_result_t x87_push_result(hb_context_t* ctx, hb_result_t r) {
    if (r == HB_ERR_EXEC_FAULT) return hb_fault_fpu_stack(ctx, 0);
    return r;
}

static hb_result_t x87_fld_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    double value;
    hb_result_t r = x87_read_real_mem(ctx, op, &value);
    if (r != HB_OK) return r;
    return x87_push_result(ctx, hb_x87_push_f64(hb_context_x87(ctx), value));
}

/* Convert an IEEE 754 double to an 80-bit extended precision encoding
 * (sign+exponent 16-bit, significand 64-bit with explicit integer bit).
 * Used by FSTP m80. The 80-bit format: bits 79 = sign, 78-64 = biased
 * exponent (15 bits), 63 = explicit integer bit (1 for normal), 62-0
 * = fraction (no hidden bit). For our double (53-bit mantissa), we have
 * to split it into explicit-int form. For subnormals/zero/inf/nan we
 * follow IEEE 754 conventions. */
static void double_to_ext80(double value, uint8_t out[10]) {
    uint64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    bool neg = (bits >> 63) & 1;
    uint64_t frac = bits & 0x000FFFFFFFFFFFFFULL;
    unsigned exp = (unsigned)((bits >> 52) & 0x7FFu);

    uint16_t se = neg ? 0x8000u : 0u;
    uint64_t sig = 0;

    if (exp == 0 && frac == 0) {
        /* Zero */
        se |= 0x0000u;
        sig = 0;
    } else if (exp == 0x7FFu) {
        /* Inf / NaN */
        se |= 0x7FFFu;
        if (frac == 0) {
            sig = 0x8000000000000000ULL;  /* Inf: integer bit set, frac=0 */
        } else {
            sig = 0x8000000000000000ULL | (frac << 11);  /* NaN: keep payload */
        }
    } else {
        /* Normal finite: convert hidden-bit double to explicit-bit 80 */
        se |= (uint16_t)(exp - 0x3FFu + 0x3FFFu);
        sig = 0x8000000000000000ULL | (frac << 11);
    }
    /* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 514 — СДВИГ НА 11 БИТ ОТСУТСТВОВАЛ.
     *
     * У `double` дробь занимает 52 бита, у 80-битного формата — 63 (плюс явный бит целого).
     * Дробь клалась в МЛАДШИЕ биты вместо старших, и записанное значение получалось другим:
     * вместо log2(e)=1.4427 в памяти лежало ~1.000217 (мантисса 0x80071547652B82FE против
     * верной 0xB8AA3B29...). Обратное преобразование `ext80_to_double` при этом ВЕРНО
     * (делит на 2^63) — то есть ошибка односторонняя, и круговой обход `fstp`+`fld` тоже
     * портил значение. Не замечали, потому что байты никто не смотрел: наша сторона
     * печатала только `data_hash` (исправлено в этой же итерации). */
    memcpy(out, &sig, sizeof(sig));
    memcpy(out + 8, &se, sizeof(se));
}

static hb_result_t x87_st0_for_store(hb_context_t* ctx, double* value,
                                      bool* masked_underflow) {
    hb_x87_state_t* x87 = hb_context_x87(ctx);
    hb_result_t r;

    if (!value || !masked_underflow) return HB_ERR_INVALID_ARG;
    *masked_underflow = false;
    r = hb_x87_st_f64(x87, 0, value);
    if (r == HB_OK) return HB_OK;
    if (r != HB_ERR_EXEC_FAULT) return r;
    r = hb_x87_stack_underflow(x87, value);
    if (r == HB_OK) *masked_underflow = true;
    return r;
}

static void x87_indefinite_ext80(uint8_t out[10]) {
    const uint64_t sig = UINT64_C(0xc000000000000000);
    const uint16_t se = UINT16_C(0xffff);
    memcpy(out, &sig, sizeof(sig));
    memcpy(out + 8, &se, sizeof(se));
}

static hb_result_t x87_fstp_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint64_t addr = resolve_addr(ctx, op);
    double value;
    bool masked_underflow;
    hb_result_t r = x87_st0_for_store(ctx, &value, &masked_underflow);
    if (r != HB_OK) return r;

    if (op->size == HB_SIZE_32) {
        float f = (float)value;
        r = hb_memory_write(ctx->memory, addr, &f, sizeof(f));
    } else if (op->size == HB_SIZE_64) {
        r = hb_memory_write(ctx->memory, addr, &value, sizeof(value));
    } else if (op->size == HB_SIZE_80) {
        uint8_t bytes[10];
        /* Итерация 516: если у ST(0) есть точная тень — пишем ЕЁ, а не пересчёт из `double`.
         * Пересчёт теряет 11 младших битов мантиссы, потому что их нет у `double`. */
        if (masked_underflow) x87_indefinite_ext80(bytes);
        else if (hb_x87_st_ext80(hb_context_x87(ctx), 0, bytes) != HB_OK)
            double_to_ext80(value, bytes);
        r = hb_memory_write(ctx->memory, addr, bytes, sizeof(bytes));
    } else {
        return HB_ERR_UNSUPPORTED_FEATURE;
    }
    if (r != HB_OK) return r;
    return hb_x87_fstp_pop(hb_context_x87(ctx));
}

static hb_result_t x87_fst_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint64_t addr = resolve_addr(ctx, op);
    double value;
    bool masked_underflow;
    hb_result_t r = x87_st0_for_store(ctx, &value, &masked_underflow);
    if (r != HB_OK) return r;

    if (op->size == HB_SIZE_32) {
        float f = (float)value;
        return hb_memory_write(ctx->memory, addr, &f, sizeof(f));
    }
    if (op->size == HB_SIZE_64) {
        return hb_memory_write(ctx->memory, addr, &value, sizeof(value));
    }
    if (op->size == HB_SIZE_80) {
        uint8_t bytes[10];
        /* Итерация 516: если у ST(0) есть точная тень — пишем ЕЁ, а не пересчёт из `double`.
         * Пересчёт теряет 11 младших битов мантиссы, потому что их нет у `double`. */
        if (masked_underflow) x87_indefinite_ext80(bytes);
        else if (hb_x87_st_ext80(hb_context_x87(ctx), 0, bytes) != HB_OK)
            double_to_ext80(value, bytes);
        return hb_memory_write(ctx->memory, addr, bytes, sizeof(bytes));
    }
    return HB_ERR_UNSUPPORTED_FEATURE;
}

/* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1047 — УПАКОВАННЫЙ BCD 80 БИТ.
 * Формат: 10 байт. Байты 0..8 несут 18 десятичных цифр, по две на байт, младшая пара
 * первой; байт 9 — знак (старший бит), остальные его разряды по спецификации не
 * определены и обязаны читаться как ноль при записи. Перечисление пробелов (1045)
 * назвало `fbld`/`fbstp` единственными настоящими дырами декодера x86-32 помимо AVX
 * и дальних переходов; лифтер и исполнитель их не имели вовсе. */
static hb_result_t x87_fbld_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint64_t addr = resolve_addr(ctx, op);
    uint8_t b[10];
    double value = 0.0;
    hb_result_t r = hb_memory_read(ctx->memory, addr, b, sizeof(b));
    if (r != HB_OK) return r;
    for (int i = 8; i >= 0; i--) {
        value = value * 100.0 + (double)((b[i] >> 4) & 0xf) * 10.0 + (double)(b[i] & 0xf);
    }
    if (b[9] & 0x80) value = -value;
    return x87_push_result(ctx, hb_x87_push_f64(hb_context_x87(ctx), value));
}

static hb_result_t x87_fbstp_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint64_t addr = resolve_addr(ctx, op);
    uint8_t b[10];
    double value;
    bool masked_underflow;
    hb_result_t r = x87_st0_for_store(ctx, &value, &masked_underflow);
    if (r != HB_OK) return r;

    memset(b, 0, sizeof(b));
    if (value < 0.0) { b[9] = 0x80; value = -value; }
    /* Округление к ближайшему — как у FBSTP при управляющем слове по умолчанию. */
    double rounded = (value < 0.0) ? -0.0 : value;
    rounded = (double)(long double)(rounded + 0.5);
    unsigned long long whole = (rounded >= 1.0e18) ? 0ULL : (unsigned long long)rounded;
    for (int i = 0; i < 9; i++) {
        unsigned lo = (unsigned)(whole % 10ULL); whole /= 10ULL;
        unsigned hi = (unsigned)(whole % 10ULL); whole /= 10ULL;
        b[i] = (uint8_t)((hi << 4) | lo);
    }
    r = hb_memory_write(ctx->memory, addr, b, sizeof(b));
    if (r != HB_OK) return r;
    return hb_x87_fstp_pop(hb_context_x87(ctx));
}

static hb_result_t x87_fild_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint64_t addr = resolve_addr(ctx, op);
    double value;

    if (op->size == HB_SIZE_16) {
        int16_t v;
        hb_result_t r = hb_memory_read(ctx->memory, addr, &v, sizeof(v));
        if (r != HB_OK) return r;
        value = (double)v;
    } else if (op->size == HB_SIZE_32) {
        int32_t v;
        hb_result_t r = hb_memory_read(ctx->memory, addr, &v, sizeof(v));
        if (r != HB_OK) return r;
        value = (double)v;
    } else if (op->size == HB_SIZE_64) {
        int64_t v;
        hb_result_t r = hb_memory_read(ctx->memory, addr, &v, sizeof(v));
        if (r != HB_OK) return r;
        /* ★ 30.08, лейн УСТАНОВЩИКИ: 64-битное целое в double НЕ ВЛЕЗАЕТ (53 бита
         * мантиссы против 64). Delphi `System.Move` копирует память парой
         * FILD m64 / FISTP m64, и округление портило по символу на фрагмент.
         * Кладём точное значение в тень 80 бит. */
        return x87_push_result(ctx, hb_x87_push_i64_exact(hb_context_x87(ctx), v));
    } else {
        return HB_ERR_UNSUPPORTED_FEATURE;
    }
    return x87_push_result(ctx, hb_x87_push_f64(hb_context_x87(ctx), value));
}

/* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 906 — СЕМЬЯ `FI`: x87 с ЦЕЛЫМ операндом.
 *
 * `FIADD/FIMUL/FICOM/FICOMP/FISUB/FISUBR/FIDIV/FIDIVR` (DA /r и DE /r с операндом в памяти)
 * отказывали `-5 UNSUPPORTED_OPCODE` на ОБЕИХ ветвях и у ОБОИХ исполнителей. Найдено доской
 * в 905, когда семейные имена впервые попали в семантическую выборку.
 *
 * Причина была на шаг раньше реализации: декодер сваливал все восемь форм в один опкод
 * `HB_INS_X87_FI` и ВЫБРАСЫВАЛ `reg_op`, поэтому отличить `FIADD` от `FIDIV` было нечем.
 * Теперь `reg_op` едет вторым операндом-непосредственным, а здесь разбирается.
 *
 * Отличие от `FADD m32fp` ровно одно: операнд читается как ЦЕЛОЕ СО ЗНАКОМ (m16int/m32int),
 * а не как вещественное. Дальше — та же арифметика над ST(0), что у вещественных форм. */
static hb_result_t x87_read_int_mem(hb_context_t* ctx, const hb_ir_operand_t* op, double* out) {
    uint64_t addr = resolve_addr(ctx, op);

    if (!out) return HB_ERR_INVALID_ARG;
    if (op->size == HB_SIZE_16) {
        int16_t v;
        hb_result_t r = hb_memory_read(ctx->memory, addr, &v, sizeof(v));
        if (r != HB_OK) return r;
        *out = (double)v;
    } else if (op->size == HB_SIZE_32) {
        int32_t v;
        hb_result_t r = hb_memory_read(ctx->memory, addr, &v, sizeof(v));
        if (r != HB_OK) return r;
        *out = (double)v;
    } else {
        return HB_ERR_UNSUPPORTED_FEATURE;
    }
    return HB_OK;
}

static hb_result_t x87_fi_mem(hb_context_t* ctx, const hb_ir_operand_t* mem,
                              const hb_ir_operand_t* sub) {
    double rhs, lhs, result;
    hb_result_t r;
    hb_x87_state_t* x87 = hb_context_x87(ctx);

    if (!mem || mem->type != HB_OP_MEM || !sub || sub->type != HB_OP_IMM)
        return HB_ERR_INTERNAL;
    r = x87_read_int_mem(ctx, mem, &rhs);
    if (r != HB_OK) return r;

    /* /2 FICOM и /3 FICOMP сравнивают, а не считают. */
    if (sub->imm == 2 || sub->imm == 3) {
        r = hb_x87_fcom(x87, rhs);
        if (r != HB_OK) return r;
        return sub->imm == 3 ? hb_x87_pop(x87) : HB_OK;
    }

    r = hb_x87_st_f64(x87, 0, &lhs);
    if (r != HB_OK) return r;
    switch (sub->imm) {
        case 0: result = lhs + rhs; break;   /* FIADD  */
        case 1: result = lhs * rhs; break;   /* FIMUL  */
        case 4: result = lhs - rhs; break;   /* FISUB  */
        case 5: result = rhs - lhs; break;   /* FISUBR */
        case 6: result = lhs / rhs; break;   /* FIDIV  */
        case 7: result = rhs / lhs; break;   /* FIDIVR */
        default: return HB_ERR_INTERNAL;
    }
    return hb_x87_set_st_f64(x87, 0, result);
}

static hb_result_t x87_fistp_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint64_t addr = resolve_addr(ctx, op);

    if (op->size == HB_SIZE_16) {
        int16_t v;
        hb_result_t r = hb_x87_fistp_i16(hb_context_x87(ctx), &v);
        if (r != HB_OK) return r;
        return hb_memory_write(ctx->memory, addr, &v, sizeof(v));
    }
    if (op->size == HB_SIZE_32) {
        int32_t v;
        hb_result_t r = hb_x87_fistp_i32(hb_context_x87(ctx), &v);
        if (r != HB_OK) return r;
        return hb_memory_write(ctx->memory, addr, &v, sizeof(v));
    }
    if (op->size == HB_SIZE_64) {
        int64_t v;
        hb_result_t r = hb_x87_fistp_i64(hb_context_x87(ctx), &v);
        if (r != HB_OK) return r;
        return hb_memory_write(ctx->memory, addr, &v, sizeof(v));
    }
    return HB_ERR_UNSUPPORTED_FEATURE;
}

/* FIST = non-popping integer store. Same encoding as FISTP but no pop. */
/* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 350 — FISTTP: усечение к нулю и снятие.
 *
 * `FISTP` округляет по управляющему слову, `FISTTP` — ВСЕГДА к нулю. Поэтому нельзя было просто
 * подставить существующую операцию: после `FNINIT` слово равно 0x037F, то есть округление к
 * ближайшему, и значения разошлись бы на половине случаев. Читаем вершину как double, усекаем
 * `trunc`, записываем и снимаем со стека. */
static hb_result_t x87_fisttp_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint64_t addr = resolve_addr(ctx, op);
    double v;
    hb_result_t r = hb_x87_st_f64(hb_context_x87(ctx), 0, &v);
    if (r != HB_OK) return r;
    v = trunc(v);

    if (op->size == HB_SIZE_16) {
        int16_t out = (int16_t)v;
        r = hb_memory_write(ctx->memory, addr, &out, sizeof(out));
    } else if (op->size == HB_SIZE_32) {
        int32_t out = (int32_t)v;
        r = hb_memory_write(ctx->memory, addr, &out, sizeof(out));
    } else if (op->size == HB_SIZE_64) {
        int64_t out = (int64_t)v;
        r = hb_memory_write(ctx->memory, addr, &out, sizeof(out));
    } else {
        return HB_ERR_INTERNAL;
    }
    if (r != HB_OK) return r;
    return hb_x87_pop(hb_context_x87(ctx));
}

static hb_result_t x87_fist_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint64_t addr = resolve_addr(ctx, op);

    if (op->size == HB_SIZE_16) {
        int16_t v;
        hb_result_t r = hb_x87_fist_i16(hb_context_x87(ctx), &v);
        if (r != HB_OK) return r;
        return hb_memory_write(ctx->memory, addr, &v, sizeof(v));
    }
    if (op->size == HB_SIZE_32) {
        int32_t v;
        hb_result_t r = hb_x87_fist_i32(hb_context_x87(ctx), &v);
        if (r != HB_OK) return r;
        return hb_memory_write(ctx->memory, addr, &v, sizeof(v));
    }
    return HB_ERR_UNSUPPORTED_FEATURE;
}

static hb_result_t x87_fldcw_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint16_t cw;
    uint64_t addr = resolve_addr(ctx, op);
    hb_result_t r = hb_memory_read(ctx->memory, addr, &cw, sizeof(cw));
    if (r != HB_OK) return r;
    return hb_x87_fldcw(hb_context_x87(ctx), cw);
}

static hb_result_t x87_fnstcw_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint16_t cw;
    uint64_t addr = resolve_addr(ctx, op);
    hb_result_t r = hb_x87_fnstcw(hb_context_x87(ctx), &cw);
    if (r != HB_OK) return r;
    return hb_memory_write(ctx->memory, addr, &cw, sizeof(cw));
}

/* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1075 — регистр режима SSE.
 * Маска 0xffbf — те же биты, что движок уже объявляет в образе `fxsave`
 * (`HB_X86_MXCSR_MASK`): всё, что вне её, на запись игнорируется. */
/* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1080 — ОБРАЗ ТАБЛИЦЫ ДЕСКРИПТОРОВ.
 *
 * `SGDT`/`SIDT` в пользовательском режиме ЗАКОННЫ (в отличие от `LGDT`/`LIDT`), и до этой
 * итерации мы на них отказывали: замер 1079 показал `-5`, то есть гость умирал на команде,
 * которую процессор исполняет. Настоящей таблицы у нас нет, поэтому отдаём ПРАВДОПОДОБНЫЙ
 * образ Windows: предел и база из ядерного диапазона. Это ОТКРЫТО названная модель, и она
 * лучше смерти: код, который сюда заглядывает (защиты от копирования, проверки на
 * виртуальную машину), получает архитектурно верную форму ответа.
 * Сверять с эталоном тут нечего: у Unicorn своя таблица, значения всё равно разойдутся. */
static hb_result_t sys_store_descriptor_table(hb_context_t* ctx, const hb_ir_operand_t* op,
                                              bool idt) {
    uint8_t image[10];
    uint64_t addr = resolve_addr(ctx, op);
    bool is32 = (ctx->arch == HB_ARCH_X86);
    uint16_t limit = idt ? 0x0fffu : 0x0057u;
    uint64_t base  = is32 ? (idt ? 0x80b95400ull : 0x80b95000ull)
                          : (idt ? 0xfffff80000001000ull : 0xfffff80000000000ull);
    size_t len = is32 ? 6u : 10u;

    memcpy(image, &limit, 2);
    memcpy(image + 2, &base, len - 2);
    return hb_memory_write(ctx->memory, addr, image, len);
}

static hb_result_t sse_ldmxcsr_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint32_t v;
    uint64_t addr = resolve_addr(ctx, op);
    hb_result_t r = hb_memory_read(ctx->memory, addr, &v, sizeof(v));
    if (r != HB_OK) return r;
    ctx->mxcsr = v & 0xffffu & 0xffbfu;
    return HB_OK;
}

static hb_result_t sse_stmxcsr_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint32_t v = ctx->mxcsr ? ctx->mxcsr : 0x1f80u;
    uint64_t addr = resolve_addr(ctx, op);
    return hb_memory_write(ctx->memory, addr, &v, sizeof(v));
}

static hb_result_t x87_fnstsw_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint16_t sw = hb_context_x87(ctx)->status_word;
    uint64_t addr = resolve_addr(ctx, op);
    return hb_memory_write(ctx->memory, addr, &sw, sizeof(sw));
}

static void x87_env_wr16(uint8_t* env, unsigned off, uint16_t v) {
    env[off + 0] = (uint8_t)(v & 0xffu);
    env[off + 1] = (uint8_t)(v >> 8);
}

static uint16_t x87_env_rd16(const uint8_t* env, unsigned off) {
    return (uint16_t)(env[off] | ((uint16_t)env[off + 1] << 8));
}

#define HB_X86_DEFAULT_MXCSR 0x1f80u
#define HB_X86_MXCSR_MASK    0xffbfu

static void x87_env_wr32(uint8_t* env, unsigned off, uint32_t v) {
    env[off + 0] = (uint8_t)(v & 0xffu);
    env[off + 1] = (uint8_t)((v >> 8) & 0xffu);
    env[off + 2] = (uint8_t)((v >> 16) & 0xffu);
    env[off + 3] = (uint8_t)(v >> 24);
}

static void x87_set_tag_entry(hb_x87_state_t* x87, unsigned phys, uint16_t tag) {
    unsigned shift = phys * 2u;
    x87->tag_word = (uint16_t)((x87->tag_word & ~(0x3u << shift)) | ((tag & 0x3u) << shift));
}

static uint16_t x87_tag_from_double(double value) {
    switch (fpclassify(value)) {
        case FP_ZERO: return 0x1u;
        case FP_NAN:
        case FP_INFINITE:
        case FP_SUBNORMAL: return 0x2u;
        case FP_NORMAL:
        default: return 0x0u;
    }
}

static uint8_t x87_fxsave_abridged_ftw(const hb_x87_state_t* x87) {
    uint8_t ftw = 0;
    for (unsigned i = 0; i < 8; i++) {
        unsigned phys = (x87->top + i) & 7u;
        if (((x87->tag_word >> (phys * 2u)) & 3u) != 3u)
            ftw |= (uint8_t)(1u << i);
    }
    return ftw;
}

static void x87_store_env32(const hb_x87_state_t* x87, uint8_t env[28]) {
    uint16_t sw = (uint16_t)((x87->status_word & ~(7u << 11)) | ((x87->top & 7u) << 11));

    memset(env, 0, 28);
    x87_env_wr16(env, 0, x87->control_word);
    x87_env_wr16(env, 4, sw);
    x87_env_wr16(env, 8, x87->tag_word);
    /* Итерация 512: смещение 12 — адрес последней команды x87 (FIP). Раньше уходил нулём,
     * и это было ЕДИНСТВЕННОЕ отличие нашего образа от эталонного (замер 511). */
    env[12] = (uint8_t)(x87->last_x87_ip);
    env[13] = (uint8_t)(x87->last_x87_ip >> 8);
    env[14] = (uint8_t)(x87->last_x87_ip >> 16);
    env[15] = (uint8_t)(x87->last_x87_ip >> 24);
}

static void x87_load_env32(hb_x87_state_t* x87, const uint8_t env[28]) {
    x87->control_word = x87_env_rd16(env, 0);
    x87->status_word = x87_env_rd16(env, 4);
    x87->tag_word = x87_env_rd16(env, 8);
    x87->top = (x87->status_word >> 11) & 7u;
}

static hb_result_t x87_fnstenv_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint8_t env[28];
    uint64_t addr = resolve_addr(ctx, op);

    x87_store_env32(hb_context_x87(ctx), env);
    return hb_memory_write(ctx->memory, addr, env, sizeof(env));
}

static hb_result_t x87_fldenv_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint8_t env[28];
    uint64_t addr = resolve_addr(ctx, op);
    hb_result_t r = hb_memory_read(ctx->memory, addr, env, sizeof(env));

    if (r != HB_OK) return r;
    x87_load_env32(hb_context_x87(ctx), env);
    return HB_OK;
}

static hb_result_t x87_fnsave_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint8_t image[108];
    hb_x87_state_t* x87 = hb_context_x87(ctx);
    uint64_t addr = resolve_addr(ctx, op);
    hb_result_t r;

    memset(image, 0, sizeof(image));
    x87_store_env32(x87, image);
    for (unsigned i = 0; i < 8; i++) {
        unsigned phys = (x87->top + i) & 7u;
        if (((x87->tag_word >> (phys * 2u)) & 3u) != 3u)
            double_to_ext80(x87->st[phys], image + 28 + i * 10);
    }
    r = hb_memory_write(ctx->memory, addr, image, sizeof(image));
    if (r != HB_OK) return r;
    return hb_x87_fninit(x87);
}

static hb_result_t x87_frstor_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint8_t image[108];
    hb_x87_state_t* x87 = hb_context_x87(ctx);
    uint64_t addr = resolve_addr(ctx, op);
    hb_result_t r = hb_memory_read(ctx->memory, addr, image, sizeof(image));

    if (r != HB_OK) return r;
    x87_load_env32(x87, image);
    for (unsigned i = 0; i < 8; i++) {
        unsigned phys = (x87->top + i) & 7u;
        x87->st[phys] = ext80_to_double(image + 28 + i * 10);
    }
    return HB_OK;
}

static hb_result_t x87_fxsave_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint8_t image[512];
    hb_x87_state_t* x87 = hb_context_x87(ctx);
    uint16_t sw = (uint16_t)((x87->status_word & ~(7u << 11)) | ((x87->top & 7u) << 11));
    uint64_t addr = resolve_addr(ctx, op);

    memset(image, 0, sizeof(image));
    x87_env_wr16(image, 0x00, x87->control_word);
    x87_env_wr16(image, 0x02, sw);
    image[0x04] = x87_fxsave_abridged_ftw(x87);
    x87_env_wr32(image, 0x18, HB_X86_DEFAULT_MXCSR);
    x87_env_wr32(image, 0x1c, HB_X86_MXCSR_MASK);
    for (unsigned i = 0; i < 8; i++) {
        unsigned phys = (x87->top + i) & 7u;
        if (((x87->tag_word >> (phys * 2u)) & 3u) != 3u)
            double_to_ext80(x87->st[phys], image + 0x20 + i * 16);
    }
    /* XMM save area (offset 0xA0). Patch H fix: mode-aware. 32-bit guests keep
     * XMM0-7 in the x86 register view; 64-bit guests keep XMM0-15 in the x64 view
     * (regs is a union, so the two live at different offsets). Reading
     * ctx->regs.x86.xmm unconditionally saved the wrong bytes -- and only 8 of the
     * 16 registers -- for x64 FXSAVE/XSAVE. Use the same accessor the SSE ops use. */
    unsigned xmm_count = (ctx->mode == HB_MODE_32BIT) ? 8u : 16u;
    for (unsigned i = 0; i < xmm_count; i++) {
        uint64_t v[2] = {0, 0};
        (void)read_xmm_reg(ctx, HB_REG_XMM0 + (int)i, v);
        memcpy(image + 0xa0 + i * 16, v, 16);
    }
    return hb_memory_write(ctx->memory, addr, image, sizeof(image));
}

static hb_result_t x87_fxrstor_mem(hb_context_t* ctx, const hb_ir_operand_t* op) {
    uint8_t image[512];
    hb_x87_state_t* x87 = hb_context_x87(ctx);
    uint64_t addr = resolve_addr(ctx, op);
    hb_result_t r = hb_memory_read(ctx->memory, addr, image, sizeof(image));

    if (r != HB_OK) return r;
    x87->control_word = x87_env_rd16(image, 0x00);
    x87->status_word = x87_env_rd16(image, 0x02);
    x87->top = (x87->status_word >> 11) & 7u;
    x87->tag_word = 0xffffu;
    for (unsigned i = 0; i < 8; i++) {
        unsigned phys = (x87->top + i) & 7u;
        if (image[0x04] & (uint8_t)(1u << i)) {
            x87->st[phys] = ext80_to_double(image + 0x20 + i * 16);
            x87_set_tag_entry(x87, phys, x87_tag_from_double(x87->st[phys]));
        } else {
            x87->st[phys] = 0.0;
            x87_set_tag_entry(x87, phys, 0x3u);
        }
    }
    /* XMM restore area -- mode-aware (see the save-side comment). Restoring into
     * ctx->regs.x86.xmm unconditionally wrote the wrong union member for x64
     * guests, so XMM registers were silently not restored after FXRSTOR/XRSTOR. */
    unsigned xmm_count = (ctx->mode == HB_MODE_32BIT) ? 8u : 16u;
    for (unsigned i = 0; i < xmm_count; i++) {
        uint64_t v[2] = {0, 0};
        memcpy(v, image + 0xa0 + i * 16, 16);
        (void)write_xmm_reg(ctx, HB_REG_XMM0 + (int)i, v);
    }
    return HB_OK;
}

static hb_result_t x87_arith_mem(hb_context_t* ctx, const hb_ir_operand_t* op, hb_ir_op_t arith_op) {
    double lhs;
    double rhs;
    double result;
    hb_result_t r = x87_read_real_mem(ctx, op, &rhs);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(hb_context_x87(ctx), 0, &lhs);
    if (r != HB_OK) return r;

    switch (arith_op) {
        case HB_IR_X87_FADD:  result = lhs + rhs; break;
        case HB_IR_X87_FMUL:  result = lhs * rhs; break;
        case HB_IR_X87_FSUB:  result = lhs - rhs; break;
        case HB_IR_X87_FSUBR: result = rhs - lhs; break;
        case HB_IR_X87_FDIV:  result = lhs / rhs; break;
        case HB_IR_X87_FDIVR: result = rhs / lhs; break;
        default: return HB_ERR_INTERNAL;
    }
    return hb_x87_set_st_f64(hb_context_x87(ctx), 0, result);
}

static hb_result_t x87_fcom_mem(hb_context_t* ctx, const hb_ir_operand_t* op, bool pop_after) {
    double rhs;
    hb_result_t r = x87_read_real_mem(ctx, op, &rhs);
    if (r != HB_OK) return r;
    r = hb_x87_fcom(hb_context_x87(ctx), rhs);
    if (r != HB_OK) return r;
    return pop_after ? hb_x87_pop(hb_context_x87(ctx)) : HB_OK;
}

static hb_result_t x87_st_index(const hb_ir_operand_t* op, unsigned* index) {
    if (!op || !index || op->type != HB_OP_IMM || op->imm < 0 || op->imm > 7) return HB_ERR_INTERNAL;
    *index = (unsigned)op->imm;
    return HB_OK;
}

/* DD D0+i / DD D8+i: copy ST(0) to ST(i), then optionally pop.
 * Register-form FST/FSTP uses the same IR operations as the memory forms,
 * with an immediate logical stack index as the destination. */
static hb_result_t x87_fst_st(hb_context_t* ctx, const hb_ir_operand_t* op,
                              bool pop_after) {
    hb_x87_state_t* x87 = hb_context_x87(ctx);
    unsigned index;
    double value;
    hb_result_t r = x87_st_index(op, &index);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r == HB_ERR_EXEC_FAULT) r = hb_x87_stack_underflow(x87, &value);
    if (r != HB_OK) return r;
    r = hb_x87_store_st_f64(x87, index, value);
    if (r != HB_OK) return r;
    return pop_after ? hb_x87_fstp_pop(x87) : HB_OK;
}

/* Итерация 516: точные 80-битные постоянные x87. Каждая ПОДТВЕРЖДЕНА замером против эталона
 * (перебор мантиссы по хешу области данных, семь из семи). Порядок кодов задаёт декодер:
 * -1=FLD1, -2=FLDZ, -3=FLDL2T, -4=FLDL2E, -5=FLDPI, -6=FLDLG2, -7=FLDLN2. */
static const uint8_t* x87_const_ext80(int code) {
    static const uint8_t t[8][10] = {
        {0},                                                              /* 0 не используется */
        {0,0,0,0,0,0,0,0x80,0xff,0x3f},                                   /* -1 FLD1   1.0 */
        {0,0,0,0,0,0,0,0,0,0},                                            /* -2 FLDZ   0.0 */
        {0xfe,0x8a,0x1b,0xcd,0x4b,0x78,0x9a,0xd4,0x00,0x40},              /* -3 FLDL2T log2(10) */
        {0xbc,0xf0,0x17,0x5c,0x29,0x3b,0xaa,0xb8,0xff,0x3f},              /* -4 FLDL2E log2(e) */
        {0x35,0xc2,0x68,0x21,0xa2,0xda,0x0f,0xc9,0x00,0x40},              /* -5 FLDPI  pi */
        {0x99,0xf7,0xcf,0xfb,0x84,0x9a,0x20,0x9a,0xfd,0x3f},              /* -6 FLDLG2 log10(2) */
        {0xac,0x79,0xcf,0xd1,0xf7,0x17,0x72,0xb1,0xfe,0x3f},              /* -7 FLDLN2 ln(2) */
    };
    int i = -code;
    if (i < 1 || i > 7) return NULL;
    return t[i];
}

static hb_result_t x87_fld_st(hb_context_t* ctx, const hb_ir_operand_t* op) {
    unsigned index;
    double value;
    /* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 516 — ПОСТОЯННЫЕ КЛАДЁМ С ТОЧНЫМ 80-БИТНЫМ.
     * Все семь значений СВЕРЕНЫ с эталоном побайтно (перебор мантиссы по хешу области данных):
     * каждое подтверждено, а не взято по памяти. `double` рядом остаётся для вычислений. */
    if (op && op->type == HB_OP_IMM && op->imm == -1)
        return x87_push_result(ctx, hb_x87_push_f64_ext(hb_context_x87(ctx), 1.0, x87_const_ext80(-1)));
    if (op && op->type == HB_OP_IMM && op->imm == -2) {
        /* FLDZ: push 0.0 and set tag to "zero" (01). */
        hb_result_t r = x87_push_result(ctx, hb_x87_push_f64_ext(hb_context_x87(ctx), 0.0, x87_const_ext80(-2)));
        if (r != HB_OK) return r;
        uint16_t shift = (uint16_t)(hb_context_x87(ctx)->top * 2u);
        hb_context_x87(ctx)->tag_word = (uint16_t)((hb_context_x87(ctx)->tag_word & ~(0x3u << shift)) |
                                                (0x1u << shift));
        return HB_OK;
    }
    /* FLD1/FLDZ/FLDL2T/FLDL2E/FLDPI/FLDLG2/FLDLN2 constants. The decoder
     * encodes the constant as a negative imm value: -1=FLD1, -2=FLDZ,
     * -3=FLDL2T (log2(10)), -4=FLDL2E (log2(e)), -5=FLDPI,
     * -6=FLDLG2 (log10(2)), -7=FLDLN2 (ln(2)). Push as a "valid" double. */
    if (op && op->type == HB_OP_IMM) {
        double cnst = 0.0;
        switch (op->imm) {
            case -3: cnst = 3.3219280948873623478703194294894; break;  /* log2(10) */
            case -4: cnst = 1.4426950408889634073599246810019; break;  /* log2(e) */
            case -5: cnst = 3.1415926535897932384626433832795; break;  /* pi */
            case -6: cnst = 0.3010299956639811952137388947245; break;  /* log10(2) */
            case -7: cnst = 0.6931471805599453094172321214582; break;  /* ln(2) */
            default: break;
        }
        if (op->imm >= -7 && op->imm <= -3) {
            return x87_push_result(ctx, hb_x87_push_f64_ext(hb_context_x87(ctx), cnst, x87_const_ext80((int)op->imm)));
        }
    }
    hb_result_t r = x87_st_index(op, &index);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(hb_context_x87(ctx), index, &value);
    if (r != HB_OK) return r;
    return x87_push_result(ctx, hb_x87_push_f64(hb_context_x87(ctx), value));
}

static hb_result_t x87_fxch(hb_context_t* ctx, const hb_ir_operand_t* op) {
    unsigned index;
    double st0;
    double sti;
    hb_result_t r = x87_st_index(op, &index);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(hb_context_x87(ctx), 0, &st0);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(hb_context_x87(ctx), index, &sti);
    if (r != HB_OK) return r;
    r = hb_x87_set_st_f64(hb_context_x87(ctx), 0, sti);
    if (r != HB_OK) return r;
    return hb_x87_set_st_f64(hb_context_x87(ctx), index, st0);
}

static hb_result_t x87_arith_st0_sti(hb_context_t* ctx, const hb_ir_operand_t* op, hb_ir_op_t arith_op) {
    unsigned index;
    double lhs;
    double rhs;
    double result;
    hb_result_t r = x87_st_index(op, &index);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(hb_context_x87(ctx), 0, &lhs);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(hb_context_x87(ctx), index, &rhs);
    if (r != HB_OK) return r;
    switch (arith_op) {
        case HB_IR_X87_FADD:  result = lhs + rhs; break;
        case HB_IR_X87_FMUL:  result = lhs * rhs; break;
        case HB_IR_X87_FSUB:  result = lhs - rhs; break;
        case HB_IR_X87_FSUBR: result = rhs - lhs; break;
        case HB_IR_X87_FDIV:  result = lhs / rhs; break;
        case HB_IR_X87_FDIVR: result = rhs / lhs; break;
        default: return HB_ERR_INTERNAL;
    }
    return hb_x87_set_st_f64(hb_context_x87(ctx), 0, result);
}

static hb_result_t x87_arith_pop_sti_st0(hb_context_t* ctx, const hb_ir_operand_t* op, hb_ir_op_t arith_op) {
    unsigned index;
    double st0;
    double sti;
    double result;
    hb_result_t r = x87_st_index(op, &index);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(hb_context_x87(ctx), 0, &st0);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(hb_context_x87(ctx), index, &sti);
    if (r != HB_OK) return r;
    switch (arith_op) {
        case HB_IR_X87_FADDP:  result = sti + st0; break;
        case HB_IR_X87_FMULP:  result = sti * st0; break;
        case HB_IR_X87_FSUBP:  result = sti - st0; break;
        case HB_IR_X87_FSUBRP: result = st0 - sti; break;
        case HB_IR_X87_FDIVP:  result = sti / st0; break;
        case HB_IR_X87_FDIVRP: result = st0 / sti; break;
        default: return HB_ERR_INTERNAL;
    }
    r = hb_x87_set_st_f64(hb_context_x87(ctx), index, result);
    if (r != HB_OK) return r;
    return hb_x87_pop(hb_context_x87(ctx));
}

static hb_result_t x87_fcom_st(hb_context_t* ctx, const hb_ir_operand_t* op, unsigned pops) {
    unsigned index;
    double rhs;
    hb_result_t r = x87_st_index(op, &index);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(hb_context_x87(ctx), index, &rhs);
    if (r != HB_OK) return r;
    r = hb_x87_fcom(hb_context_x87(ctx), rhs);
    if (r != HB_OK) return r;
    while (pops--) {
        r = hb_x87_pop(hb_context_x87(ctx));
        if (r != HB_OK) return r;
    }
    return HB_OK;
}

/* FCOMI/FCOMIP/FUCOMI/FUCOMIP — compare ST(0) to ST(i), set FPU C0/C2/C3
 * (same as FCOM/FUCOM), and ALSO mirror them to EFLAGS as ZF/PF/CF.
 *
 *   lhs < rhs  -> ZF=0 PF=0 CF=1
 *   lhs == rhs -> ZF=1 PF=0 CF=0
 *   lhs > rhs  -> ZF=0 PF=0 CF=0
 *   unordered (NaN)              -> ZF=1 PF=1 CF=1
 *
 * Per Intel SDM Vol 1 §8.1.8 (FCOMI/FCOMIP/FUCOMI/FUCOMIP) and Vol 2A
 * instruction entries. OF/SF/AF are cleared. IF is unchanged.
 *
 * `unordered` is true for FUCOMI/FUCOMIP — for the FPU SW, hb_x87_fcom
 * already produces C0=C2=C3=111 on NaN, so the unordered flag only matters
 * when the regular-FCOM "QNaN raises IE" semantic is wanted (gap matrix
 * #3 — FPU exception flags — not yet implemented). EFLAGS encoding is
 * the same for FCOMI and FUCOMI (NaN -> ZF=PF=CF=1). */
static hb_result_t x87_fcomi_st(hb_context_t* ctx, const hb_ir_operand_t* op,
                                unsigned pops, bool unordered) {
    (void)unordered; /* see comment above */
    unsigned index;
    double lhs, rhs;
    hb_result_t r = x87_st_index(op, &index);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(hb_context_x87(ctx), 0, &lhs);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(hb_context_x87(ctx), index, &rhs);
    if (r != HB_OK) return r;

    /* Update the FPU C0/C2/C3 condition flags first. */
    r = hb_x87_fcom(hb_context_x87(ctx), rhs);
    if (r != HB_OK) return r;

    /* Mirror to EFLAGS (lazy-flags cleared so values land in canonical slot). */
    hb_lazy_flags_clear(ctx);
    ctx->flags.of = false;
    ctx->flags.sf = false;
    ctx->flags.af = false;
    if (lhs != lhs || rhs != rhs) {
        ctx->flags.zf = true;
        ctx->flags.pf = true;
        ctx->flags.cf = true;
    } else if (lhs < rhs) {
        ctx->flags.zf = false;
        ctx->flags.pf = false;
        ctx->flags.cf = true;
    } else if (lhs == rhs) {
        ctx->flags.zf = true;
        ctx->flags.pf = false;
        ctx->flags.cf = false;
    } else {
        ctx->flags.zf = false;
        ctx->flags.pf = false;
        ctx->flags.cf = false;
    }

    while (pops--) {
        r = hb_x87_pop(hb_context_x87(ctx));
        if (r != HB_OK) return r;
    }
    return HB_OK;
}

static hb_result_t read_operand_value(hb_context_t* ctx, const hb_ir_operand_t* op, uint64_t* out) {
    if (!ctx || !op || !out) return HB_ERR_INVALID_ARG;
    if (op->type == HB_OP_REG) {
        *out = read_reg_sized(ctx, op->reg, op->size, op->reg_offset);
        return HB_OK;
    }
    if (op->type == HB_OP_IMM) {
        *out = (uint64_t)op->imm;
        return HB_OK;
    }
    if (op->type == HB_OP_MEM) {
        uint64_t addr = resolve_addr(ctx, op);
        return mem_read(ctx, addr, out, op->size);
    }
    return HB_ERR_INTERNAL;
}

static hb_result_t write_operand_value(hb_context_t* ctx, const hb_ir_operand_t* op, uint64_t value) {
    if (!ctx || !op) return HB_ERR_INVALID_ARG;
    if (op->type == HB_OP_REG) {
        write_reg_sized_offset(ctx, op->reg, value, op->size, op->reg_offset);
        return HB_OK;
    }
    if (op->type == HB_OP_MEM) {
        uint64_t addr = resolve_addr(ctx, op);
        return mem_write(ctx, addr, value, op->size);
    }
    return HB_ERR_INTERNAL;
}

static uint64_t bswap_sized_value(uint64_t value, hb_size_t size) {
    if (size == HB_SIZE_16) {
        uint16_t v = (uint16_t)value;
        return (uint16_t)((v >> 8) | (v << 8));
    }
    if (size == HB_SIZE_32) {
        uint32_t v = (uint32_t)value;
        return ((v & 0x000000ffU) << 24) |
               ((v & 0x0000ff00U) << 8)  |
               ((v & 0x00ff0000U) >> 8)  |
               ((v & 0xff000000U) >> 24);
    }
    if (size == HB_SIZE_64) {
        uint64_t v = value;
        return ((v & 0x00000000000000ffULL) << 56) |
               ((v & 0x000000000000ff00ULL) << 40) |
               ((v & 0x0000000000ff0000ULL) << 24) |
               ((v & 0x00000000ff000000ULL) << 8)  |
               ((v & 0x000000ff00000000ULL) >> 8)  |
               ((v & 0x0000ff0000000000ULL) >> 24) |
               ((v & 0x00ff000000000000ULL) >> 40) |
               ((v & 0xff00000000000000ULL) >> 56);
    }
    return value;
}

static hb_result_t read_seg_selector(hb_context_t* ctx, uint16_t seg, uint16_t* out) {
    if (!ctx || !out) return HB_ERR_INVALID_ARG;
    switch (seg) {
        case 0: *out = ctx->seg_es; return HB_OK;
        case 1: *out = ctx->seg_cs; return HB_OK;
        case 2: *out = ctx->seg_ss; return HB_OK;
        case 3: *out = ctx->seg_ds; return HB_OK;
        case 4: *out = ctx->seg_fs; return HB_OK;
        case 5: *out = ctx->seg_gs; return HB_OK;
        default: return HB_ERR_UNSUPPORTED_OPCODE;
    }
}

static hb_result_t write_seg_selector(hb_context_t* ctx, uint16_t seg, uint16_t value) {
    if (!ctx) return HB_ERR_INVALID_ARG;
    switch (seg) {
        case 0: ctx->seg_es = value; return HB_OK;
        case 1: ctx->seg_cs = value; return HB_OK;
        case 2: ctx->seg_ss = value; return HB_OK;
        case 3: ctx->seg_ds = value; return HB_OK;
        case 4: ctx->seg_fs = value; return HB_OK;
        case 5: ctx->seg_gs = value; return HB_OK;
        default: return HB_ERR_UNSUPPORTED_OPCODE;
    }
}

static uint64_t status_flags_mask(void) {
    return (1ULL << 0) | (1ULL << 2) | (1ULL << 4) |
           (1ULL << 6) | (1ULL << 7) | (1ULL << 11);
}

static void sync_status_flags_from_image(hb_context_t* ctx, uint64_t image) {
    ctx->flags.cf = (image & (1ULL << 0)) != 0;
    ctx->flags.pf = (image & (1ULL << 2)) != 0;
    ctx->flags.af = (image & (1ULL << 4)) != 0;
    ctx->flags.zf = (image & (1ULL << 6)) != 0;
    ctx->flags.sf = (image & (1ULL << 7)) != 0;
    ctx->flags.of = (image & (1ULL << 11)) != 0;
}

static uint64_t flags_width_mask(hb_size_t size) {
    if (size == HB_SIZE_16) return 0xffffu;
    if (size == HB_SIZE_32) return 0xffffffffu;
    return UINT64_MAX;
}

/* MacRunner 2026-08-11, лейн ЛЕСТНИЦА — регистры MMX.
 *
 * Хранилище ВНЕ `hb_context_t`: добавление полей в контекст ломало прогон целиком (итерация 303,
 * прогоны падали на 1369 строках с кодом 1) — раскладку знает не только кодогенератор через
 * offsetof, но и кто-то ещё, и виновник пока не назван. Потоковый массив даёт ту же семантику
 * и общую раскладку не трогает. Сопряжение со стеком x87 не моделируется. */
/* Итерация 518: значения берутся из КОНТЕКСТА, а не из статики потока. Смысл правки —
 * не стиль, а видимость: прежнее хранилище не сохранялось с контекстом, не попадало в
 * снимки и было невидимо для `fnsave`/`fxsave`. */
static uint64_t* hb_mmx_regs(hb_context_t* ctx) {
    static _Thread_local uint64_t mm_fallback[8];
    return ctx ? ctx->mm : mm_fallback;
}

static hb_result_t read_flags_image(hb_context_t* ctx, hb_size_t size, uint64_t* out) {
    uint64_t image;
    hb_result_t r;
    if (!ctx || !out) return HB_ERR_INVALID_ARG;
    r = hb_lazy_flags_materialize_available(ctx, HB_FLAG_BIT_ALL);
    if (r != HB_OK) return r;
    image = ctx->mode == HB_MODE_32BIT ? ctx->regs.x86.eflags : ctx->regs.x64.rflags;
    image &= ~status_flags_mask();
    image |= ctx->flags.cf ? (1ULL << 0) : 0;
    image |= ctx->flags.pf ? (1ULL << 2) : 0;
    image |= ctx->flags.af ? (1ULL << 4) : 0;
    image |= ctx->flags.zf ? (1ULL << 6) : 0;
    image |= ctx->flags.sf ? (1ULL << 7) : 0;
    image |= ctx->flags.of ? (1ULL << 11) : 0;
    image |= 0x2u;
    if (ctx->mode == HB_MODE_32BIT) ctx->regs.x86.eflags = (uint32_t)image;
    else ctx->regs.x64.rflags = image;
    *out = image & flags_width_mask(size);
    return HB_OK;
}

static hb_result_t write_flags_image(hb_context_t* ctx, hb_size_t size, uint64_t value) {
    uint64_t image;
    uint64_t mask;
    if (!ctx) return HB_ERR_INVALID_ARG;
    image = ctx->mode == HB_MODE_32BIT ? ctx->regs.x86.eflags : ctx->regs.x64.rflags;
    mask = flags_width_mask(size);
    image = (image & ~mask) | (value & mask);
    image |= 0x2u;
    if (ctx->mode == HB_MODE_32BIT) ctx->regs.x86.eflags = (uint32_t)image;
    else ctx->regs.x64.rflags = image;
    sync_status_flags_from_image(ctx, image);
    hb_lazy_flags_clear(ctx);
    return HB_OK;
}

static void trace_operand(const char* name, hb_context_t* ctx, const hb_ir_operand_t* op) {
    if (!op) return;
    if (op->type == HB_OP_MEM) {
        uint64_t addr = resolve_addr(ctx, op);
        fprintf(stderr,
                " %s={type=MEM size=%d seg=0x%x base=%d index=%d scale=%u disp=0x%llx addr=0x%llx}",
                name, op->size, op->mem.segment, op->mem.base, op->mem.index,
                op->mem.scale, (unsigned long long)op->mem.disp, (unsigned long long)addr);
    } else if (op->type == HB_OP_REG) {
        fprintf(stderr, " %s={type=REG size=%d reg=%d value=0x%llx}",
                name, op->size, op->reg, (unsigned long long)read_reg(ctx, op->reg));
    } else if (op->type == HB_OP_IMM) {
        fprintf(stderr, " %s={type=IMM size=%d imm=0x%llx}",
                name, op->size, (unsigned long long)op->imm);
    } else {
        fprintf(stderr, " %s={type=%d size=%d}", name, op->type, op->size);
    }
}

static bool trace_atomics_enabled(void) {
    return (trace_runtime_flags & TRACE_FLAG_ATOMICS) != 0;
}

static int trace_bitops_selected(const hb_ir_instr_t* instr) {
    if (!(trace_runtime_flags & TRACE_FLAG_BITOPS)) return 0;
    if (!trace_cfg.bitops_range_set) return 1;
    if (!instr) return 0;
    return instr->guest_addr >= trace_cfg.bitops_start &&
           instr->guest_addr <= trace_cfg.bitops_end;
}

static unsigned int trace_bitops_budget(void) {
    return trace_cfg.bitops_budget;
}

static const char* ir_op_name(hb_ir_op_t op) {
    switch (op) {
        case HB_IR_NOP: return "NOP";
        case HB_IR_MOV: return "MOV";
        case HB_IR_MOV_SEG: return "MOV_SEG";
        case HB_IR_LEA: return "LEA";
        case HB_IR_ADD: return "ADD";
        case HB_IR_ADC: return "ADC";
        case HB_IR_SUB: return "SUB";
        case HB_IR_SBB: return "SBB";
        case HB_IR_MUL: return "MUL";
        case HB_IR_IMUL: return "IMUL";
        case HB_IR_DIV: return "DIV";
        case HB_IR_IDIV: return "IDIV";
        case HB_IR_BT: return "BT";
        case HB_IR_BTS: return "BTS";
        case HB_IR_BTR: return "BTR";
        case HB_IR_BTC: return "BTC";
        case HB_IR_AND: return "AND";
        case HB_IR_OR: return "OR";
        case HB_IR_XOR: return "XOR";
        case HB_IR_NOT: return "NOT";
        case HB_IR_NEG: return "NEG";
        case HB_IR_SHL: return "SHL";
        case HB_IR_SHR: return "SHR";
        case HB_IR_SAR: return "SAR";
        case HB_IR_ROL: return "ROL";
        case HB_IR_ROR: return "ROR";
        case HB_IR_RCL: return "RCL";
        case HB_IR_RCR: return "RCR";
        case HB_IR_SHLD: return "SHLD";
        case HB_IR_SHRD: return "SHRD";
        case HB_IR_CMP: return "CMP";
        case HB_IR_TEST: return "TEST";
        case HB_IR_CMPXCHG: return "CMPXCHG";
        case HB_IR_CMPXCHG8B: return "CMPXCHG8B";
        case HB_IR_XCHG: return "XCHG";
        case HB_IR_XADD: return "XADD";
        case HB_IR_FENCE: return "FENCE";
        case HB_IR_LAHF: return "LAHF";
        case HB_IR_SAHF: return "SAHF";
        case HB_IR_CPUID: return "CPUID";
        case HB_IR_MMX_MOV: return "MMX_MOV";
        case HB_IR_MMX_AND: return "MMX_AND";
        case HB_IR_MMX_ANDN: return "MMX_ANDN";
        case HB_IR_MMX_OR: return "MMX_OR";
        case HB_IR_MMX_XOR: return "MMX_XOR";
        case HB_IR_MMX_SRL: return "MMX_SRL";
        case HB_IR_MMX_SRA: return "MMX_SRA";
        case HB_IR_MMX_SLL: return "MMX_SLL";
        case HB_IR_XGETBV: return "XGETBV";
        case HB_IR_RDTSC: return "RDTSC";
        case HB_IR_VERR: return "VERR";
        case HB_IR_VERW: return "VERW";
        case HB_IR_RDTSCP: return "RDTSCP";
        case HB_IR_RDRAND: return "RDRAND";
        case HB_IR_RDSEED: return "RDSEED";
        case HB_IR_SETcc: return "SETcc";
        case HB_IR_CMOVcc: return "CMOVcc";
        case HB_IR_LOAD: return "LOAD";
        case HB_IR_STORE: return "STORE";
        case HB_IR_PUSH: return "PUSH";
        case HB_IR_POP: return "POP";
        case HB_IR_PUSHF: return "PUSHF";
        case HB_IR_POPF: return "POPF";
        case HB_IR_CALL: return "CALL";
        case HB_IR_CALLF: return "CALLF";
        case HB_IR_JMPF: return "JMPF";
        case HB_IR_RETF: return "RETF";
        case HB_IR_IRET: return "IRET";
        case HB_IR_INT3: return "INT3";
        case HB_IR_INT: return "INT";
        case HB_IR_INT1: return "INT1";
        case HB_IR_INTO: return "INTO";
        case HB_IR_HLT: return "HLT";
        case HB_IR_IN: return "IN";
        case HB_IR_OUT: return "OUT";
        case HB_IR_XLAT: return "XLAT";
        case HB_IR_PUSH_SEG: return "PUSH_SEG";
        case HB_IR_POP_SEG: return "POP_SEG";
        case HB_IR_CLC: return "CLC";
        case HB_IR_STC: return "STC";
        case HB_IR_CMC: return "CMC";
        case HB_IR_CLD: return "CLD";
        case HB_IR_STD: return "STD";
        case HB_IR_CLI: return "CLI";
        case HB_IR_STI: return "STI";
        case HB_IR_ENTER: return "ENTER";
        case HB_IR_RET: return "RET";
        case HB_IR_JMP: return "JMP";
        case HB_IR_Jcc: return "Jcc";
        case HB_IR_LOOP: return "LOOP";
        case HB_IR_JRCXZ: return "JRCXZ";
        case HB_IR_SIGN_EXTEND: return "SIGN_EXTEND";
        case HB_IR_CWD: return "CWD";
        case HB_IR_MOVS: return "MOVS";
        case HB_IR_CMPS: return "CMPS";
        case HB_IR_LODS: return "LODS";
        case HB_IR_SCAS: return "SCAS";
        case HB_IR_STOS: return "STOS";
        case HB_IR_ZERO_EXTEND: return "ZERO_EXTEND";
        case HB_IR_TRUNC: return "TRUNC";
        case HB_IR_BSF: return "BSF";
        case HB_IR_TZCNT: return "TZCNT";
        case HB_IR_LZCNT: return "LZCNT";
        case HB_IR_BSR: return "BSR";
        case HB_IR_POPCNT: return "POPCNT";
        case HB_IR_BSWAP: return "BSWAP";
        case HB_IR_MOVBE: return "MOVBE";
        case HB_IR_MOVDIR64B: return "MOVDIR64B";
        case HB_IR_CRC32: return "CRC32";
        case HB_IR_ANDN: return "ANDN";
        case HB_IR_BEXTR: return "BEXTR";
        case HB_IR_BLSI: return "BLSI";
        case HB_IR_BLSMSK: return "BLSMSK";
        case HB_IR_BLSR: return "BLSR";
        case HB_IR_BZHI: return "BZHI";
        case HB_IR_MULX: return "MULX";
        case HB_IR_PDEP: return "PDEP";
        case HB_IR_PEXT: return "PEXT";
        case HB_IR_RORX: return "RORX";
        case HB_IR_SARX: return "SARX";
        case HB_IR_SHLX: return "SHLX";
        case HB_IR_SHRX: return "SHRX";
        case HB_IR_ADCX: return "ADCX";
        case HB_IR_ADOX: return "ADOX";
        case HB_IR_XMM_AND: return "XMM_AND";
        case HB_IR_XMM_SCALAR_MOV: return "XMM_SCALAR_MOV";
        case HB_IR_XMM_QWORD_LANE_MOV: return "XMM_QWORD_LANE_MOV";
        case HB_IR_XMM_ANDN: return "XMM_ANDN";
        case HB_IR_XMM_OR: return "XMM_OR";
        case HB_IR_XORPS: return "XORPS";
        case HB_IR_PCMPEQB: return "PCMPEQB";
        case HB_IR_PCMPEQW: return "PCMPEQW";
        case HB_IR_PCMPEQD: return "PCMPEQD";
        case HB_IR_PCMPGTB: return "PCMPGTB";
        case HB_IR_PCMPGTW: return "PCMPGTW";
        case HB_IR_PCMPGTD: return "PCMPGTD";
        case HB_IR_PMOVMSKB: return "PMOVMSKB";
        case HB_IR_MOVMSK: return "MOVMSK";
        case HB_IR_PUNPCK: return "PUNPCK";
        case HB_IR_PACKSSWB: return "PACKSSWB";
        case HB_IR_PACKUSWB: return "PACKUSWB";
        case HB_IR_PACKSSDW: return "PACKSSDW";
        case HB_IR_PMULLW: return "PMULLW";
        case HB_IR_PMULHW: return "PMULHW";
        case HB_IR_PMULHUW: return "PMULHUW";
        case HB_IR_PMADDWD: return "PMADDWD";
        case HB_IR_PSUBSB: return "PSUBSB";
        case HB_IR_PSUBSW: return "PSUBSW";
        case HB_IR_PSUBUSB: return "PSUBUSB";
        case HB_IR_PSUBUSW: return "PSUBUSW";
        case HB_IR_PSADBW: return "PSADBW";
        case HB_IR_PADDSB: return "PADDSB";
        case HB_IR_PADDSW: return "PADDSW";
        case HB_IR_PADDUSB: return "PADDUSB";
        case HB_IR_PADDUSW: return "PADDUSW";
        case HB_IR_PAVGB: return "PAVGB";
        case HB_IR_PAVGW: return "PAVGW";
        case HB_IR_PSHUFB: return "PSHUFB";
        case HB_IR_PINSRW: return "PINSRW";
        case HB_IR_PEXTRW: return "PEXTRW";
        case HB_IR_PINSR: return "PINSR";
        case HB_IR_PEXTR: return "PEXTR";
        case HB_IR_INSERTPS: return "INSERTPS";
        case HB_IR_EXTRACTPS: return "EXTRACTPS";
        case HB_IR_PSHUF: return "PSHUF";
        case HB_IR_FSHUF: return "FSHUF";
        case HB_IR_PSRL: return "PSRL";
        case HB_IR_PSRA: return "PSRA";
        case HB_IR_PSLL: return "PSLL";
        case HB_IR_PSRLQ: return "PSRLQ";
        case HB_IR_PSLLQ: return "PSLLQ";
        case HB_IR_PSRLDQ: return "PSRLDQ";
        case HB_IR_PSLLDQ: return "PSLLDQ";
        case HB_IR_MOVD: return "MOVD";
        case HB_IR_CVTDQ2PD: return "CVTDQ2PD";
        case HB_IR_CVTDQ2PS: return "CVTDQ2PS";
        case HB_IR_CVTPS2DQ: return "CVTPS2DQ";
        case HB_IR_CVTTPS2DQ: return "CVTTPS2DQ";
        case HB_IR_CVTPS2PD: return "CVTPS2PD";
        case HB_IR_CVTPD2PS: return "CVTPD2PS";
        case HB_IR_CVTPD2DQ: return "CVTPD2DQ";
        case HB_IR_CVTTPD2DQ: return "CVTTPD2DQ";
        case HB_IR_CVTSS2SD: return "CVTSS2SD";
        case HB_IR_CVTSD2SS: return "CVTSD2SS";
        case HB_IR_CVTSI2SD: return "CVTSI2SD";
        case HB_IR_CVTSI2SS: return "CVTSI2SS";
        case HB_IR_FSQRT: return "FSQRT";
        case HB_IR_FRSQRT: return "FRSQRT";
        case HB_IR_FRCP: return "FRCP";
        case HB_IR_FROUND: return "FROUND";
        case HB_IR_FDP: return "FDP";
        case HB_IR_FADD: return "FADD";
        case HB_IR_FSUB: return "FSUB";
        case HB_IR_FMUL: return "FMUL";
        case HB_IR_FDIV: return "FDIV";
        case HB_IR_ADDSD: return "ADDSD";
        case HB_IR_SUBSD: return "SUBSD";
        case HB_IR_DIVSD: return "DIVSD";
        case HB_IR_MULSD: return "MULSD";
        case HB_IR_MULSS: return "MULSS";
        case HB_IR_DIVSS: return "DIVSS";
        case HB_IR_FAR_BRANCH: return "FAR_BRANCH";
        case HB_IR_HADDSUB: return "HADDSUB";
        case HB_IR_MOVDUP: return "MOVDUP";
        case HB_IR_MOVQ2DQ: return "MOVQ2DQ";
        case HB_IR_MOVDQ2Q: return "MOVDQ2Q";
        case HB_IR_MASKMOV: return "MASKMOV";
        case HB_IR_CVT_MMX_FP: return "CVT_MMX_FP";
        case HB_IR_FCMP_MASK: return "FCMP_MASK";
        case HB_IR_FMIN: return "FMIN";
        case HB_IR_FMAX: return "FMAX";
        case HB_IR_COMISS: return "COMISS";
        case HB_IR_COMISD: return "COMISD";
        case HB_IR_CVTSD2SI: return "CVTSD2SI";
        case HB_IR_CVTSS2SI: return "CVTSS2SI";
        case HB_IR_CVTTSD2SI: return "CVTTSD2SI";
        case HB_IR_CVTTSS2SI: return "CVTTSS2SI";
        case HB_IR_VCVTTSS2USI: return "VCVTTSS2USI";
        case HB_IR_VCVTTSD2USI: return "VCVTTSD2USI";
        case HB_IR_PADD: return "PADD";
        case HB_IR_PSUB: return "PSUB";
        case HB_IR_VEC_PACKED: return "VEC_PACKED";
        case HB_IR_EVEX_CMP_MASK: return "EVEX_CMP_MASK";
        case HB_IR_VZEROUPPER: return "VZEROUPPER";
        case HB_IR_VZEROALL: return "VZEROALL";
        case HB_IR_FSGSBASE: return "FSGSBASE";
        case HB_IR_X87_FLD: return "X87_FLD";
        case HB_IR_X87_FST: return "X87_FST";
        case HB_IR_X87_FSTP: return "X87_FSTP";
        case HB_IR_X87_FILD: return "X87_FILD";
        case HB_IR_X87_FI: return "X87_FI";
        case HB_IR_X87_FISTP: return "X87_FISTP";
        case HB_IR_X87_FISTTP: return "X87_FISTTP";
        case HB_IR_X87_FBLD: return "X87_FBLD";
        case HB_IR_X87_FBSTP: return "X87_FBSTP";
        case HB_IR_X87_FIST: return "X87_FIST";
        case HB_IR_SGDT: return "SGDT";
        case HB_IR_SIDT: return "SIDT";
        case HB_IR_LDMXCSR: return "LDMXCSR";
        case HB_IR_STMXCSR: return "STMXCSR";
        case HB_IR_X87_FLDCW: return "X87_FLDCW";
        case HB_IR_X87_FNSTCW: return "X87_FNSTCW";
        case HB_IR_X87_FNSTSW: return "X87_FNSTSW";
        case HB_IR_X87_FLDENV: return "X87_FLDENV";
        case HB_IR_X87_EMMS: return "X87_EMMS";
        case HB_IR_X87_FNSTENV: return "X87_FNSTENV";
        case HB_IR_X87_FRSTOR: return "X87_FRSTOR";
        case HB_IR_X87_FNSAVE: return "X87_FNSAVE";
        case HB_IR_X87_FXSAVE: return "X87_FXSAVE";
        case HB_IR_X87_FXRSTOR: return "X87_FXRSTOR";
        case HB_IR_X87_FADD: return "X87_FADD";
        case HB_IR_X87_FMUL: return "X87_FMUL";
        case HB_IR_X87_FCOM: return "X87_FCOM";
        case HB_IR_X87_FCOMP: return "X87_FCOMP";
        case HB_IR_X87_FUCOM: return "X87_FUCOM";
        case HB_IR_X87_FUCOMP: return "X87_FUCOMP";
        case HB_IR_X87_FCOMI: return "X87_FCOMI";
        case HB_IR_X87_FUCOMI: return "X87_FUCOMI";
        case HB_IR_X87_FCOMIP: return "X87_FCOMIP";
        case HB_IR_X87_FUCOMIP: return "X87_FUCOMIP";
        case HB_IR_X87_FSUB: return "X87_FSUB";
        case HB_IR_X87_FSUBR: return "X87_FSUBR";
        case HB_IR_X87_FDIV: return "X87_FDIV";
        case HB_IR_X87_FDIVR: return "X87_FDIVR";
        case HB_IR_X87_FADDP: return "X87_FADDP";
        case HB_IR_X87_FMULP: return "X87_FMULP";
        case HB_IR_X87_FCOMPP: return "X87_FCOMPP";
        case HB_IR_X87_FSUBP: return "X87_FSUBP";
        case HB_IR_X87_FSUBRP: return "X87_FSUBRP";
        case HB_IR_X87_FDIVP: return "X87_FDIVP";
        case HB_IR_X87_FDIVRP: return "X87_FDIVRP";
        case HB_IR_X87_FXCH: return "X87_FXCH";
        case HB_IR_X87_FRNDINT: return "X87_FRNDINT";
        case HB_IR_X87_FFREE: return "X87_FFREE";
        case HB_IR_X87_FINCSTP: return "X87_FINCSTP";
        case HB_IR_X87_FDECSTP: return "X87_FDECSTP";
        case HB_IR_X87_FNCLEX: return "X87_FNCLEX";
        case HB_IR_X87_FNINIT: return "X87_FNINIT";
        case HB_IR_X87_FXAM: return "X87_FXAM";
        case HB_IR_X87_FSQRT: return "X87_FSQRT";
        case HB_IR_X87_F2XM1: return "X87_F2XM1";
        case HB_IR_X87_FYL2X: return "X87_FYL2X";
        case HB_IR_X87_FPTAN: return "X87_FPTAN";
        case HB_IR_X87_FPATAN: return "X87_FPATAN";
        case HB_IR_X87_FXTRACT: return "X87_FXTRACT";
        case HB_IR_X87_FPREM1: return "X87_FPREM1";
        case HB_IR_X87_FPREM: return "X87_FPREM";
        case HB_IR_X87_FYL2XP1: return "X87_FYL2XP1";
        case HB_IR_X87_FSINCOS: return "X87_FSINCOS";
        case HB_IR_X87_FSCALE: return "X87_FSCALE";
        case HB_IR_X87_FSIN: return "X87_FSIN";
        case HB_IR_X87_FCOS: return "X87_FCOS";
        case HB_IR_X87_FNOP: return "X87_FNOP";
        case HB_IR_X87_FCHS: return "X87_FCHS";
        case HB_IR_X87_FABS: return "X87_FABS";
        case HB_IR_X87_FTST: return "X87_FTST";
        case HB_IR_PUSHA: return "PUSHA";
        case HB_IR_POPA: return "POPA";
        case HB_IR_AAA: return "AAA";
        case HB_IR_AAS: return "AAS";
        case HB_IR_AAM: return "AAM";
        case HB_IR_AAD: return "AAD";
        case HB_IR_DAA: return "DAA";
        case HB_IR_DAS: return "DAS";
        case HB_IR_BOUND: return "BOUND";
        case HB_IR_ARPL: return "ARPL";
        case HB_IR_LDS: return "LDS";
        case HB_IR_LES: return "LES";
        case HB_IR_LFS: return "LFS";
        case HB_IR_LGS: return "LGS";
        case HB_IR_HOST_CALL: return "HOST_CALL";
        case HB_IR_FAULT: return "FAULT";
        case HB_IR_XTEST: return "XTEST";
        case HB_IR_UNSUPPORTED: return "UNSUPPORTED";
        default: return "UNKNOWN";
    }
}

/* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 266 — ИМЯ ОПЕРАЦИИ НАРУЖУ.
 * Номер кода операции дважды переводился в имя разбором перечисления и дважды соврал (262: 80
 * оказалось не LODS, а CWD; 266: калибровка со сдвигом дала RDSEED на первом месте с 34% — вздор).
 * Единственный надёжный источник — таблица самого движка. Открываем её, чтобы печати в
 * кодогенераторе и в среде исполнения звали её, а не гадали. */
const char* hb_ir_op_name_public(int op) { return ir_op_name((hb_ir_op_t)op); }

HB_PROBE_DEFINE(pr_exec_fault, "hb-exec-fault",
                "ОТКАЗЫ ИСПОЛНЕНИЯ, дошедшие до trace_exec_fault (интерпретатор вернул "
                "не HB_OK на команде IR): looked — все такие отказы, БЕЗ ОГЛЯДКИ на гейт "
                "печати; hits — те из них, что застали MACRUNNER_HB_TRACE_FAULTS открытым. "
                "НЕ считает: отказы выпущенного кода, отказы хоста и всё, что не проходит "
                "через интерпретатор",
                "MACRUNNER_HB_TRACE_FAULTS", 50);

static void trace_exec_fault(hb_context_t* ctx, const hb_ir_instr_t* instr,
                             hb_result_t result, uint64_t block_guest,
                             size_t ir_idx, uint64_t step_idx) {
    static unsigned int fault_count;
    /* ★★ 06.09.2026, лейн ПРИБОРЫ-3 — ЗДЕСЬ БЫЛИ ОБА КЛАССА ЛЖИ СРАЗУ.
     *
     * 1. ГЕЙТ ПЕЧАТИ ВЫШЕ СЧЁТА. `fault_count` растёт ПОСЛЕ проверки
     *    TRACE_FLAG_FAULTS (гейт MACRUNNER_HB_TRACE_FAULTS, по умолчанию выключен),
     *    поэтому в обычном прогоне отказов исполнения не считал НИКТО. Молчание
     *    значило «гейт закрыт», а читалось как «отказов не было» — и на этом маркере
     *    строятся отсчёты шести скриптов A/B.
     * 2. ПОТОЛОК 50. Он хотя бы объявлял себя строкой «budget exhausted», но НЕ
     *    называл итог: 50 напечатанных отказов и 50 000 случившихся выглядели
     *    одинаково.
     *
     * Учёт вынесен ВЫШЕ гейта, потолок печати оставлен как был. Точный итог печатает
     * перепись на выходе, и по ней видно, какой из двух нулей перед тобой:
     *     looked=0            отказов исполнения не было ВООБЩЕ
     *     looked>0, hits=0    отказы были, гейт печати закрыт            <- вот это и путали
     *     hits>0, printed=50  напечатанное — НИЖНЯЯ ГРАНИЦА (EVENTS-TRUNCATED) */
    HB_PROBE_LOOKED(&pr_exec_fault);
    if (!(trace_runtime_flags & TRACE_FLAG_FAULTS)) return;
    HB_PROBE_HIT(&pr_exec_fault);            /* отказ дожил до открытого гейта печати */
    if (++fault_count > 50) {
        if (fault_count == 51)
            fprintf(stderr, "macrunner-hb-fault: budget exhausted, silencing "
                            "(точный итог — в строке macrunner-probe: name=hb-exec-fault)\n");
        return;
    }
    hb_probe_should_print(&pr_exec_fault);   /* учесть напечатанное: иначе printed=0 */
    fprintf(stderr,
            "macrunner-hb-fault: pc=0x%llx ir_op=%s(%d) ir_idx=%zu step=%llu "
            "result=%s block=0x%llx guest=0x%llx len=%u "
            "rax=0x%llx rcx=0x%llx rdx=0x%llx rbx=0x%llx rsp=0x%llx rsi=0x%llx rdi=0x%llx",
            (unsigned long long)ctx->pc, ir_op_name(instr->op), instr->op, ir_idx,
            (unsigned long long)step_idx, hb_result_string(result),
            (unsigned long long)block_guest, (unsigned long long)instr->guest_addr,
            instr->guest_len,
            (unsigned long long)ctx->regs.x64.rax,
            (unsigned long long)ctx->regs.x64.rcx,
            (unsigned long long)ctx->regs.x64.rdx,
            (unsigned long long)ctx->regs.x64.rbx,
            (unsigned long long)ctx->regs.x64.rsp,
            (unsigned long long)ctx->regs.x64.rsi,
            (unsigned long long)ctx->regs.x64.rdi);
    if (ctx->mode == HB_MODE_64BIT) {
        fprintf(stderr,
                " rbp=0x%llx r8=0x%llx r9=0x%llx r10=0x%llx r11=0x%llx "
                "r12=0x%llx r13=0x%llx r14=0x%llx r15=0x%llx",
                (unsigned long long)ctx->regs.x64.rbp,
                (unsigned long long)ctx->regs.x64.r8,
                (unsigned long long)ctx->regs.x64.r9,
                (unsigned long long)ctx->regs.x64.r10,
                (unsigned long long)ctx->regs.x64.r11,
                (unsigned long long)ctx->regs.x64.r12,
                (unsigned long long)ctx->regs.x64.r13,
                (unsigned long long)ctx->regs.x64.r14,
                (unsigned long long)ctx->regs.x64.r15);
    }
    trace_operand("dst", ctx, &instr->dst);
    trace_operand("src1", ctx, &instr->src1);
    trace_operand("src2", ctx, &instr->src2);
    fprintf(stderr, " bytes=");
    for (uint8_t i = 0; i < instr->guest_len && i < 15; i++) {
        uint8_t byte = 0;
        if (ctx && ctx->memory && hb_memory_read_u8(ctx->memory, instr->guest_addr + i, &byte) == HB_OK)
            fprintf(stderr, "%02x", byte);
        else
            fprintf(stderr, "??");
    }
    fprintf(stderr, "\n");

    if (ctx->mode == HB_MODE_64BIT && ctx->memory) {
        uint8_t op0 = 0, op1 = 0;
        (void)hb_memory_read_u8(ctx->memory, instr->guest_addr, &op0);
        (void)hb_memory_read_u8(ctx->memory, instr->guest_addr + 1, &op1);
        if (op0 == 0xcd && op1 == 0x29) {
            fprintf(stderr,
                    "macrunner-fastfail: pc=0x%llx code=0x%llx rsp=0x%llx "
                    "rax=0x%llx rcx=0x%llx rdx=0x%llx rbp=0x%llx r10=0x%llx\n",
                    (unsigned long long)instr->guest_addr,
                    (unsigned long long)ctx->regs.x64.rcx,
                    (unsigned long long)ctx->regs.x64.rsp,
                    (unsigned long long)ctx->regs.x64.rax,
                    (unsigned long long)ctx->regs.x64.rcx,
                    (unsigned long long)ctx->regs.x64.rdx,
                    (unsigned long long)ctx->regs.x64.rbp,
                    (unsigned long long)ctx->regs.x64.r10);
            fprintf(stderr, "macrunner-fastfail-stack:");
            for (unsigned int i = 0; i < 48; i++) {
                uint64_t q = 0;
                hb_gva_t addr = ctx->regs.x64.rsp + (uint64_t)i * 8;
                if (hb_memory_read_u64(ctx->memory, addr, &q) == HB_OK)
                    fprintf(stderr, " [%u]=0x%llx", i, (unsigned long long)q);
                else
                    fprintf(stderr, " [%u]=<unmapped>", i);
            }
            fprintf(stderr, "\n");
            fprintf(stderr, "macrunner-fastfail-codeptrs:");
            for (unsigned int i = 0; i < 96; i++) {
                uint64_t q = 0;
                hb_gva_t addr = ctx->regs.x64.rsp + (uint64_t)i * 8;
                if (hb_memory_read_u64(ctx->memory, addr, &q) == HB_OK &&
                    q >= 0x140001000ULL && q < 0x140600000ULL)
                    fprintf(stderr, " [%u]=0x%llx", i, (unsigned long long)q);
            }
            fprintf(stderr, "\n");
        }
    }
}

static bool trace_pc_matches(const char* val, uint64_t guest_addr) {
    const char* p = val;
    while (p && *p) {
        char* end = NULL;
        uint64_t target = strtoull(p, &end, 0);
        if (end != p && target == guest_addr) return true;
        p = (end && end != p) ? end : p + 1;
        while (*p == ',' || *p == ';' || *p == ' ' || *p == '\t') p++;
    }
    return false;
}

static void trace_pc_probe(hb_context_t* ctx, const hb_ir_instr_t* instr) {
    static unsigned int count;
    const char* val;
    unsigned int limit;
    if (!(trace_runtime_flags & TRACE_FLAG_PC)) return;
    val = trace_cfg.pc_list_set ? trace_cfg.pc_list : NULL;
    limit = trace_cfg.pc_limit;
    if (!val || !val[0] || !ctx || ctx->mode != HB_MODE_64BIT) return;

    if (!trace_pc_matches(val, instr->guest_addr)) return;
    if (++count > limit) return;

    fprintf(stderr,
            "macrunner-hb-pcprobe: pc=0x%llx count=%u "
            "rax=0x%llx rcx=0x%llx rdx=0x%llx rbx=0x%llx rsp=0x%llx rbp=0x%llx "
            "rsi=0x%llx rdi=0x%llx r8=0x%llx r9=0x%llx r10=0x%llx r11=0x%llx "
            "flags={cf=%u zf=%u sf=%u of=%u pf=%u af=%u} "
            "lazy={pending=%u kind=%u width=%u lhs=0x%llx rhs=0x%llx result=0x%llx count=0x%llx valid=0x%x materialized=0x%x unsupported=0x%x}\n",
            (unsigned long long)instr->guest_addr, count,
            (unsigned long long)ctx->regs.x64.rax,
            (unsigned long long)ctx->regs.x64.rcx,
            (unsigned long long)ctx->regs.x64.rdx,
            (unsigned long long)ctx->regs.x64.rbx,
            (unsigned long long)ctx->regs.x64.rsp,
            (unsigned long long)ctx->regs.x64.rbp,
            (unsigned long long)ctx->regs.x64.rsi,
            (unsigned long long)ctx->regs.x64.rdi,
            (unsigned long long)ctx->regs.x64.r8,
            (unsigned long long)ctx->regs.x64.r9,
            (unsigned long long)ctx->regs.x64.r10,
            (unsigned long long)ctx->regs.x64.r11,
            ctx->flags.cf, ctx->flags.zf, ctx->flags.sf,
            ctx->flags.of, ctx->flags.pf, ctx->flags.af,
            ctx->lazy_flags.pending, (unsigned)ctx->lazy_flags.kind,
            (unsigned)ctx->lazy_flags.width,
            (unsigned long long)ctx->lazy_flags.lhs,
            (unsigned long long)ctx->lazy_flags.rhs,
            (unsigned long long)ctx->lazy_flags.result,
            (unsigned long long)ctx->lazy_flags.count,
            ctx->lazy_flags.valid_mask,
            ctx->lazy_flags.materialized_mask,
            ctx->lazy_flags.unsupported_mask);

    const uint64_t ptrs[] = {
        ctx->regs.x64.rcx, ctx->regs.x64.rdx, ctx->regs.x64.r8,
        ctx->regs.x64.r9, ctx->regs.x64.rsi, ctx->regs.x64.rdi
    };
    const char* names[] = { "rcx", "rdx", "r8", "r9", "rsi", "rdi" };
    for (unsigned int p = 0; p < 6; p++) {
        fprintf(stderr, "macrunner-hb-pcprobe-mem: %s=0x%llx bytes=", names[p],
                (unsigned long long)ptrs[p]);
        for (unsigned int i = 0; i < 24; i++) {
            uint8_t b = 0;
            if (hb_memory_read_u8(ctx->memory, ptrs[p] + i, &b) == HB_OK)
                fprintf(stderr, "%02x", b);
            else {
                fprintf(stderr, "??");
                break;
            }
        }
        fprintf(stderr, " utf16=");
        for (unsigned int i = 0; i < 12; i++) {
            uint16_t ch = 0;
            if (hb_memory_read_u16(ctx->memory, ptrs[p] + (uint64_t)i * 2, &ch) != HB_OK) {
                fprintf(stderr, "?");
                break;
            }
            if (!ch) break;
            fprintf(stderr, "%c", (ch >= 32 && ch < 127) ? (char)ch : '.');
        }
        fprintf(stderr, "\n");
    }
}

static bool trace_strcpy_probe_enabled(void) {
    return (trace_runtime_flags & TRACE_FLAG_STRCPY) != 0;
}

static size_t trace_bounded_strlen(hb_context_t* ctx, uint64_t addr, size_t limit, bool* found_nul) {
    if (found_nul) *found_nul = false;
    if (!ctx || !ctx->memory || addr < 0x10000) return 0;
    for (size_t i = 0; i < limit; i++) {
        uint8_t b = 0;
        if (hb_memory_read_u8(ctx->memory, addr + i, &b) != HB_OK) return i;
        if (b == 0) {
            if (found_nul) *found_nul = true;
            return i;
        }
    }
    return limit;
}

static void trace_ascii_bytes(hb_context_t* ctx, uint64_t addr, size_t limit) {
    fprintf(stderr, "bytes=");
    for (size_t i = 0; i < limit; i++) {
        uint8_t b = 0;
        if (!ctx || !ctx->memory || hb_memory_read_u8(ctx->memory, addr + i, &b) != HB_OK) {
            fprintf(stderr, "??");
            break;
        }
        fprintf(stderr, "%02x", b);
    }
    fprintf(stderr, " ascii=\"");
    for (size_t i = 0; i < limit; i++) {
        uint8_t b = 0;
        if (!ctx || !ctx->memory || hb_memory_read_u8(ctx->memory, addr + i, &b) != HB_OK) break;
        if (b == 0) break;
        fputc((b >= 32 && b < 127) ? (int)b : '.', stderr);
    }
    fprintf(stderr, "\"");
}

static void trace_strcpy_probe(hb_context_t* ctx, const hb_ir_instr_t* instr) {
    static unsigned int count;
    unsigned int limit;
    const char* label = NULL;
    uint64_t src = 0;
    bool have_src = false;
    bool found_nul = false;
    size_t actual_len = 0;
    uint64_t object_src = 0;

    if (!trace_strcpy_probe_enabled() || !ctx || ctx->mode != HB_MODE_64BIT || !instr) return;
    limit = trace_cfg.strcpy_limit;

    switch (instr->guest_addr) {
        case 0x1403e72e0ULL: label = "before-strlen-call"; src = ctx->regs.x64.rcx; have_src = true; break;
        case 0x1403e72e5ULL:
            label = "after-strlen-return";
            if (hb_memory_read_u64(ctx->memory, ctx->regs.x64.rbx, &object_src) == HB_OK) {
                src = object_src;
                have_src = true;
            }
            break;
        case 0x1403e72ecULL: label = "before-alloc-size"; break;
        case 0x1403e72fcULL: label = "before-safe-copy-call"; src = ctx->regs.x64.r8; have_src = true; break;
        case 0x1403fb6b0ULL: label = "safe-copy-entry"; src = ctx->regs.x64.r8; have_src = true; break;
        case 0x1403fb70dULL: label = "safe-copy-erange-a"; break;
        case 0x1403fb718ULL: label = "safe-copy-erange-b"; break;
        default: return;
    }

    if (++count > limit) {
        if (count == limit + 1) fprintf(stderr, "macrunner-strcpy-probe: budget exhausted\n");
        return;
    }

    if (have_src) actual_len = trace_bounded_strlen(ctx, src, 256, &found_nul);

    fprintf(stderr,
            "macrunner-strcpy-probe: label=%s pc=0x%llx count=%u "
            "rax=0x%llx rcx=0x%llx rdx=0x%llx rbx=0x%llx rsp=0x%llx rbp=0x%llx "
            "r8=0x%llx r9=0x%llx rsi=0x%llx rdi=0x%llx src=0x%llx "
            "actual_len256=%zu nul=%u object_src=0x%llx ",
            label,
            (unsigned long long)instr->guest_addr,
            count,
            (unsigned long long)ctx->regs.x64.rax,
            (unsigned long long)ctx->regs.x64.rcx,
            (unsigned long long)ctx->regs.x64.rdx,
            (unsigned long long)ctx->regs.x64.rbx,
            (unsigned long long)ctx->regs.x64.rsp,
            (unsigned long long)ctx->regs.x64.rbp,
            (unsigned long long)ctx->regs.x64.r8,
            (unsigned long long)ctx->regs.x64.r9,
            (unsigned long long)ctx->regs.x64.rsi,
            (unsigned long long)ctx->regs.x64.rdi,
            (unsigned long long)src,
            actual_len,
            found_nul ? 1u : 0u,
            (unsigned long long)object_src);
    if (have_src) trace_ascii_bytes(ctx, src, 64);
    fprintf(stderr, "\n");
}

static int trace_branches_enabled(void) {
    return (trace_runtime_flags & TRACE_FLAG_BRANCHES) != 0;
}

static int trace_branch_selected(const hb_ir_instr_t* instr) {
    if (!trace_cfg.branch_range_set) return 1;
    if (!instr) return 0;
    return instr->guest_addr >= trace_cfg.branch_start &&
           instr->guest_addr <= trace_cfg.branch_end;
}

static unsigned int trace_branch_budget(void) {
    return trace_cfg.branch_budget;
}

static void trace_branch_event(hb_context_t* ctx, const hb_ir_instr_t* instr,
                               const char* phase, uint64_t rsp_before,
                               uint64_t stack_qword, uint64_t target) {
    static unsigned int branch_count;
    if (!trace_branches_enabled()) return;
    if (!trace_branch_selected(instr)) return;
    if (++branch_count > trace_branch_budget()) {
        if (branch_count == trace_branch_budget() + 1)
            fprintf(stderr, "macrunner-hb-branch: budget exhausted, silencing\n");
        return;
    }
    fprintf(stderr,
            "macrunner-hb-branch: phase=%s op=%s guest=0x%llx len=%u "
            "target=0x%llx rsp_before=0x%llx rsp_after=0x%llx stack_qword=0x%llx "
            "rax=0x%llx rbx=0x%llx rbp=0x%llx rsi=0x%llx rdi=0x%llx "
            "r12=0x%llx r13=0x%llx r14=0x%llx r15=0x%llx\n",
            phase ? phase : "?", ir_op_name(instr->op),
            (unsigned long long)instr->guest_addr, instr->guest_len,
            (unsigned long long)target,
            (unsigned long long)rsp_before,
            (unsigned long long)ctx->regs.x64.rsp,
            (unsigned long long)stack_qword,
            (unsigned long long)ctx->regs.x64.rax,
            (unsigned long long)ctx->regs.x64.rbx,
            (unsigned long long)ctx->regs.x64.rbp,
            (unsigned long long)ctx->regs.x64.rsi,
            (unsigned long long)ctx->regs.x64.rdi,
            (unsigned long long)ctx->regs.x64.r12,
            (unsigned long long)ctx->regs.x64.r13,
            (unsigned long long)ctx->regs.x64.r14,
            (unsigned long long)ctx->regs.x64.r15);
}

static bool operand_is_xmm_or_vecmem(const hb_ir_operand_t* op) {
    if (!op) return false;
    if (op->type == HB_OP_REG) return is_xmm_reg(op->reg);
    return op->type == HB_OP_MEM && (op->size == 16 || op->size == 32);
}

static bool trace_simd_op_selected(const hb_ir_instr_t* instr) {
    if (!instr) return false;
    switch (instr->op) {
        case HB_IR_XMM_AND:
        case HB_IR_XMM_ANDN:
        case HB_IR_XMM_OR:
        case HB_IR_XORPS:
        case HB_IR_PCMPEQB:
        case HB_IR_PCMPEQW:
        case HB_IR_PCMPEQD:
        case HB_IR_PCMPGTB:
        case HB_IR_PCMPGTW:
        case HB_IR_PCMPGTD:
        case HB_IR_PMOVMSKB:
        case HB_IR_MOVMSK:
        case HB_IR_PUNPCK:
        case HB_IR_PACKSSWB:
        case HB_IR_PACKUSWB:
        case HB_IR_PACKSSDW:
        case HB_IR_PMULLW:
        case HB_IR_PMULHW:
        case HB_IR_PMULHUW:
        case HB_IR_PMADDWD:
        case HB_IR_PSUBSB:
        case HB_IR_PSUBSW:
        case HB_IR_PSUBUSB:
        case HB_IR_PSUBUSW:
        case HB_IR_PSADBW:
        case HB_IR_PADDSB:
        case HB_IR_PADDSW:
        case HB_IR_PADDUSB:
        case HB_IR_PADDUSW:
        case HB_IR_PAVGB:
        case HB_IR_PAVGW:
        case HB_IR_PSHUFB:
        case HB_IR_PINSRW:
        case HB_IR_PEXTRW:
        case HB_IR_PINSR:
        case HB_IR_PEXTR:
        case HB_IR_INSERTPS:
        case HB_IR_EXTRACTPS:
        case HB_IR_PSHUF:
        case HB_IR_FSHUF:
        case HB_IR_XMM_QWORD_LANE_MOV:
        case HB_IR_PSRL:
        case HB_IR_PSRA:
        case HB_IR_PSLL:
        case HB_IR_PSRLQ:
        case HB_IR_PSLLQ:
        case HB_IR_PSRLDQ:
        case HB_IR_PSLLDQ:
        case HB_IR_MOVD:
        case HB_IR_CVTDQ2PD:
        case HB_IR_CVTDQ2PS:
        case HB_IR_CVTPS2DQ:
        case HB_IR_CVTTPS2DQ:
        case HB_IR_CVTPS2PD:
        case HB_IR_CVTPD2PS:
        case HB_IR_CVTPD2DQ:
        case HB_IR_CVTTPD2DQ:
        case HB_IR_CVTSS2SD:
        case HB_IR_CVTSD2SS:
        case HB_IR_CVTSI2SD:
        case HB_IR_CVTSI2SS:
        case HB_IR_FSQRT:
        case HB_IR_FRSQRT:
        case HB_IR_FRCP:
        case HB_IR_FROUND:
        case HB_IR_FDP:
        case HB_IR_FADD:
        case HB_IR_FSUB:
        case HB_IR_FMUL:
        case HB_IR_FDIV:
        case HB_IR_ADDSD:
        case HB_IR_SUBSD:
        case HB_IR_DIVSD:
        case HB_IR_MULSD:
        case HB_IR_DIVSS:
        case HB_IR_MULSS:
        case HB_IR_FMIN:
        case HB_IR_FMAX:
        case HB_IR_COMISS:
        case HB_IR_COMISD:
        case HB_IR_CVTSD2SI:
        case HB_IR_CVTSS2SI:
        case HB_IR_CVTTSD2SI:
        case HB_IR_CVTTSS2SI:
        case HB_IR_PADD:
        case HB_IR_PSUB:
        case HB_IR_VEC_PACKED:
        case HB_IR_VZEROUPPER:
        case HB_IR_VZEROALL:
            return true;
        case HB_IR_LOAD:
            return operand_is_xmm_or_vecmem(&instr->dst) || operand_is_xmm_or_vecmem(&instr->src1);
        case HB_IR_STORE:
            return operand_is_xmm_or_vecmem(&instr->src1) || operand_is_xmm_or_vecmem(&instr->src2);
        case HB_IR_MOV:
            return operand_is_xmm_or_vecmem(&instr->dst) || operand_is_xmm_or_vecmem(&instr->src1);
        default:
            return false;
    }
}

static void trace_simd_exec(hb_context_t* ctx, const hb_ir_instr_t* instr,
                            uint64_t block_guest, size_t ir_idx, uint64_t step_idx) {
    static unsigned int simd_count;
    if (!(trace_runtime_flags & TRACE_FLAG_SIMD)) return;
    if (!trace_simd_op_selected(instr)) return;

    unsigned int limit = trace_cfg.simd_budget;
    if (++simd_count > limit) {
        if (simd_count == limit + 1)
            fprintf(stderr, "macrunner-hb-simd: budget exhausted, silencing\n");
        return;
    }

    fprintf(stderr,
            "macrunner-hb-simd: op=%s(%d) guest=0x%llx block=0x%llx ir_idx=%zu step=%llu "
            "dst=t%d/r%d/s%d src1=t%d/r%d/s%d src2=t%d/r%d/s%d bytes=",
            ir_op_name(instr->op), instr->op,
            (unsigned long long)instr->guest_addr,
            (unsigned long long)block_guest, ir_idx,
            (unsigned long long)step_idx,
            instr->dst.type, instr->dst.reg, instr->dst.size,
            instr->src1.type, instr->src1.reg, instr->src1.size,
            instr->src2.type, instr->src2.reg, instr->src2.size);
    for (uint8_t i = 0; i < instr->guest_len && i < 15; i++) {
        uint8_t byte = 0;
        if (ctx && ctx->memory && hb_memory_read_u8(ctx->memory, instr->guest_addr + i, &byte) == HB_OK)
            fprintf(stderr, "%02x", byte);
        else
            fprintf(stderr, "??");
    }
    fprintf(stderr, "\n");
}

static bool trace_simd_data_enabled(void) {
    return (trace_runtime_flags & TRACE_FLAG_SIMD_DATA) != 0;
}

static bool trace_simd_data_in_range(uint64_t guest) {
    if (!trace_cfg.simd_data_range_set) return true;
    return guest >= trace_cfg.simd_data_start && guest <= trace_cfg.simd_data_end;
}

static bool trace_simd_data_take_budget(void) {
    static unsigned int count;
    unsigned int limit = trace_cfg.simd_data_budget;
    if (++count > limit) {
        if (count == limit + 1)
            fprintf(stderr, "macrunner-hb-simd-data: budget exhausted, silencing\n");
        return false;
    }
    return true;
}

static void trace_simd_data_hex(const uint8_t* bytes, size_t count) {
    for (size_t i = 0; i < count; i++) fprintf(stderr, "%02x", bytes[i]);
}

static size_t trace_simd_operand_bytes(const hb_ir_operand_t* op, size_t fallback) {
    size_t bytes = bytes_for_size(op->size);
    if (!bytes) bytes = fallback;
    if (!bytes) bytes = 16;
    return bytes > 16 ? 16 : bytes;
}

static void trace_simd_data_operand(hb_context_t* ctx, const char* label,
                                    const hb_ir_operand_t* op, size_t fallback) {
    uint8_t bytes[16] = {0};
    size_t count = trace_simd_operand_bytes(op, fallback);

    if (op->type == HB_OP_REG && is_xmm_reg(op->reg)) {
        uint64_t xmm[2] = {0, 0};
        hb_result_t r = read_xmm_reg(ctx, op->reg, xmm);
        memcpy(bytes, xmm, sizeof(bytes));
        fprintf(stderr, " %s=xmm%d/%zu:", label, op->reg - HB_REG_XMM0, count);
        if (r == HB_OK) trace_simd_data_hex(bytes, count);
        else fprintf(stderr, "ERR%d", r);
        return;
    }

    if (op->type == HB_OP_MEM) {
        uint64_t addr = resolve_addr(ctx, op);
        hb_result_t r = hb_memory_read(ctx->memory, addr, bytes, count);
        fprintf(stderr, " %s=mem@0x%llx/%zu:", label, (unsigned long long)addr, count);
        if (r == HB_OK) trace_simd_data_hex(bytes, count);
        else fprintf(stderr, "ERR%d", r);
        return;
    }

    if (op->type == HB_OP_REG) {
        uint64_t value = read_reg_sized(ctx, op->reg, op->size, op->reg_offset);
        memcpy(bytes, &value, count > sizeof(value) ? sizeof(value) : count);
        fprintf(stderr, " %s=reg%d/%zu:", label, op->reg, count);
        trace_simd_data_hex(bytes, count);
        return;
    }

    if (op->type == HB_OP_IMM) {
        uint64_t value = (uint64_t)op->imm;
        memcpy(bytes, &value, count > sizeof(value) ? sizeof(value) : count);
        fprintf(stderr, " %s=imm/%zu:", label, count);
        trace_simd_data_hex(bytes, count);
    }
}

static void trace_simd_data_exec(hb_context_t* ctx, const hb_ir_instr_t* instr,
                                 const char* phase, uint64_t block_guest,
                                 size_t ir_idx, uint64_t step_idx) {
    if (!trace_simd_data_enabled()) return;
    if (!trace_simd_op_selected(instr)) return;
    if (!trace_simd_data_in_range(instr->guest_addr)) return;
    if (!trace_simd_data_take_budget()) return;

    size_t fallback = 16;
    if (instr->op == HB_IR_LOAD) fallback = trace_simd_operand_bytes(&instr->src1, 16);
    else if (instr->op == HB_IR_STORE) fallback = trace_simd_operand_bytes(&instr->src1, 16);
    else if (instr->op == HB_IR_MOV) fallback = trace_simd_operand_bytes(&instr->dst, 16);

    fprintf(stderr,
            "macrunner-hb-simd-data: phase=%s op=%s guest=0x%llx block=0x%llx ir_idx=%zu step=%llu",
            phase, ir_op_name(instr->op), (unsigned long long)instr->guest_addr,
            (unsigned long long)block_guest, ir_idx, (unsigned long long)step_idx);
    trace_simd_data_operand(ctx, "dst", &instr->dst, fallback);
    trace_simd_data_operand(ctx, "src1", &instr->src1, fallback);
    trace_simd_data_operand(ctx, "src2", &instr->src2, fallback);
    fprintf(stderr, "\n");
}

unsigned long long g_interp_op_count[512];
/* ★ 04.09.2026 — РАЗРЕЗ ПО ПРИЗНАКУ VEX.128.
 *
 * Состав интерпретации уже считался (g_interp_op_count), но НЕ отвечал на вопрос,
 * ради которого его смотрят сейчас: четыре сторожа в кодогенераторе отдают сюда
 * КАЖДУЮ VEX.128-команду только потому, что нативный выпуск не обнуляет старшую
 * половину приёмника. Сколько это стоит в живом прогоне — не измерено ни разу.
 *
 * Отдельный массив, а не флаг в общем: нужен именно разрез «та же операция, но
 * пришла из-под сторожа», иначе VEX-форма неотличима от устаревшей SSE, которая
 * ходит сюда по другим причинам. Цена — одна предсказуемая ветвь рядом с уже
 * стоящей инкрементацией. */
unsigned long long g_interp_zero_ymm[512];

static hb_result_t exec_instr_unlocked(hb_context_t* ctx, const hb_ir_instr_t* instr);

/* MacRunner HK Mono lane (2026-07-27): mirror codegen's DMB bracket for x86 LOCK-prefixed
 * RMW on the interpreter path. Codegen wraps every is_locked instr with DMB ISH before+after
 * (hb_arm64_codegen.c hb_arm64_codegen_instr); the interpreter consulted is_locked nowhere,
 * so a generic locked RMW (`lock or [rsp],r` — Mono's hazard-pointer fence idiom) ran with
 * NO barrier through exec_instr (live path: hb_jit_helper_exec_block_instr_for_jit →
 * hb_interpreter_exec_one_for_jit). Locked atomics (CMPXCHG/XCHG/XADD/CMPXCHG8B) were already
 * fenced (hb_jit_helper_exec_atomic_ir + per-op SEQ_CST fences below); this closes the
 * generic-op gap. Diagnostics: MACRUNNER_HB_TRACE_INTERP_LOCK=1 — one-time armed line
 * (positive liveness) + bounded aggregate (first 8, then every 2^20). */
static uint64_t g_hb_interp_lock_fenced_count;

static int hb_interp_lock_trace_enabled(void) {
    const char* v = hb_gate( HB_GATE_HB_TRACE_INTERP_LOCK );
    int cached = (v && v[0] && strcmp(v, "0")) ? 1 : 0;
    return cached;
}

/* ★★★★ MacRunner 2026-08-30, лейн УСТАНОВЩИКИ — ТРАССА СТЕКА x87 С ГОСТЕВЫМ АДРЕСОМ.
 *
 * Распаковку установщика прерывает переполнение стека x87 (итерация 50): прибор
 * `x87-overflow` печатает `pushes=320 pops=318`, то есть ДВА лишних PUSH за прогон,
 * но не говорит, КАКАЯ команда оставила значение в стеке. Счётчиков мало — нужна
 * привязка к гостевому адресу.
 *
 * Врезка сделана в `exec_instr` — единственную точку входа, где известны и операция,
 * и `ctx->pc` (тот же довод, что у соседней печати `interp-unsupported`, итерация 262).
 * Печатаем `top` и `tag_word` ДО и ПОСЛЕ каждой операции x87: по ленте видно, где
 * глубина выросла и не вернулась.
 *
 * Гейт `MACRUNNER_HB_X87_TRACE`, умолчание 0. Объём: у установщика операций x87 порядка
 * тысячи, то есть трасса мала; на горячих мишенях гейт не включать. */
static int hb_x87_trace_on(void) {
    static int cached = -1;
    if (cached < 0) cached = hb_gate_flag( HB_GATE_HB_X87_TRACE, 0);
    return cached;
}

static int hb_is_x87_op(hb_ir_op_t op) {
    return op >= HB_IR_X87_FLD && op <= HB_IR_X87_FI;
}

static hb_result_t exec_instr(hb_context_t* ctx, const hb_ir_instr_t* instr) {

    if (hb_interp_lock_trace_enabled()) {
        static int armed_printed = 0;
        if (!armed_printed) {
            armed_printed = 1;
            fprintf(stderr, "macrunner-hb-interp-lock: armed=1 hook=exec_instr\n");
            fflush(stderr);
        }
    }
    /* Префикс LOCK к операциям x87 неприменим, поэтому ветку `is_locked` здесь
     * не трогаем — трассируем только обычный путь. */
    if (hb_x87_trace_on() && instr && !instr->is_locked && hb_is_x87_op(instr->op)) {
        hb_x87_state_t* x = hb_context_x87(ctx);
        unsigned top_do = x ? x->top : 0;
        unsigned tag_do = x ? x->tag_word : 0;
        hb_result_t r = exec_instr_unlocked(ctx, instr);
        fprintf(stderr, "macrunner-hb-x87-trace: pc=0x%llx op=%s top=%u->%u tag=%04x->%04x r=%d\n",
                (unsigned long long)ctx->pc, ir_op_name(instr->op),
                top_do, x ? x->top : 0, tag_do, x ? x->tag_word : 0, (int)r);
        fflush(stderr);
        return r;
    }
    if (!instr->is_locked) {
        /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 262 — НАЗВАТЬ НЕИСПОЛНИМУЮ ОПЕРАЦИЮ.
         * Ступень 1 умирает с `exec=UNSUPPORTED_OPCODE(-5)` при `hb=OK(0)`, то есть перевод
         * прошёл, а исполнение — нет. Печать в декодере (итерация 262, первая попытка) ничего не
         * дала, что это и подтвердило. Мест возврата в интерпретаторе 31; ставим печать в
         * ЕДИНСТВЕННУЮ точку входа, где известны и код операции, и гостевой адрес. */
        hb_result_t rr = exec_instr_unlocked(ctx, instr);
        if (rr == HB_ERR_UNSUPPORTED_OPCODE || rr == HB_ERR_UNSUPPORTED_FEATURE ||
            rr == HB_ERR_EXEC_FAULT) {
            static int said;
            if (said++ < 8) {
                fprintf(stderr, "macrunner-hb-interp-unsupported: r=%d op=%s ir_op=%d guest=0x%llx len=%u "
                        "dst=%d/%d src1=%d/%d src2=%d/%d прич=%s\n", (int)rr, ir_op_name(instr->op), (int)instr->op,
                        (unsigned long long)instr->guest_addr, (unsigned)instr->guest_len,
                        (int)instr->dst.type, (int)instr->dst.size,
                        (int)instr->src1.type, (int)instr->src1.size,
                        (int)instr->src2.type, (int)instr->src2.size,
                        instr->comment ? instr->comment : "-");
                fflush(stderr);
            }
        }
        return rr;
    }
    uint64_t n = __atomic_add_fetch(&g_hb_interp_lock_fenced_count, 1, __ATOMIC_RELAXED);
    if (hb_interp_lock_trace_enabled() && (n <= 8 || (n & 0xFFFFFu) == 0)) {
        fprintf(stderr,
                "macrunner-hb-interp-lock: count=%llu op=%d pc=0x%llx instr=0x%llx\n",
                (unsigned long long)n, (int)instr->op,
                (unsigned long long)(ctx ? ctx->pc : 0),
                (unsigned long long)instr->guest_addr);
        fflush(stderr);
    }
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    hb_result_t r = exec_instr_unlocked(ctx, instr);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    return r;
}

/* СЧЁТЧИК ИНТЕРПРЕТИРУЕМЫХ ИНСТРУКЦИЙ (01.08).
 *
 * Зачем. Вопрос «какая доля гостевых инструкций исполняется интерпретатором, а не транслированным
 * кодом» — центральный для разрыва с Rosetta: интерпретация примерно стократно дороже трансляции,
 * поэтому даже пара процентов здесь весит больше, чем вся шлифовка кодогенерации. Ответить на него
 * было НЕЧЕМ: счётчиков на этом пути не существовало ни одного (проверено grep'ом — ноль мест), и
 * все прошлые нули в трассах интерпретатора означали «прибор не подключён», а не «интерпретации
 * нет». Трёхкратный выигрыш от отключения промоции семейств нашли глазами в профиле, случайно.
 *
 * Что считается. Точка выбрана здесь, а не на входе в интерпретатор целиком: сюда сходятся ОБЕ
 * ветви (exec_instr для locked и прямой вызов для остальных) И падения из транслированного кода в
 * хелперы — живой путь hb_jit_helper_exec_block_instr_for_jit -> hb_interpreter_exec_one_for_jit.
 * То есть число покрывает и «блок целиком интерпретируется», и «одна инструкция ушла в хелпер»,
 * а это как раз те 134 млн вызовов хелпера, что остались после слияния CMP/Jcc.
 *
 * Знаменатель уже есть: t_dispatch_stats_steps в hb_runtime.c — инструкции, исполненные
 * транслированными блоками. Печать отношения — там же, в переписи диспетчеризации.
 *
 * Цена. Инкремент потоковой переменной без атомарности на горячем пути; в общий итог складывается
 * не чаще раза на 2^20 инструкций, как у t_guard_* рядом. Складывать при каждом инкременте нельзя:
 * 64 потока дрались бы за одну строку кеша. */
uint64_t g_hb_interp_instr_total;
static __thread uint64_t t_hb_interp_instr;
static __thread uint64_t t_hb_interp_flushed;

#define HB_INTERP_CENSUS_PERIOD (1ull << 20)

static void hb_interp_instr_fold(void) {
    uint64_t add = t_hb_interp_instr - t_hb_interp_flushed;
    if (!add) return;
    t_hb_interp_flushed = t_hb_interp_instr;
    __atomic_add_fetch(&g_hb_interp_instr_total, add, __ATOMIC_RELAXED);
}

/* Оба читателя живут в hb_runtime.c. Поток — про критический поток, итог — про процесс:
 * по одному числу нельзя отличить «интерпретируем везде понемногу» от «один поток встал». */
uint64_t hb_interp_instr_thread_count(void) { return t_hb_interp_instr; }

uint64_t hb_interp_instr_total_count(void) {
    hb_interp_instr_fold();
    return __atomic_load_n(&g_hb_interp_instr_total, __ATOMIC_RELAXED);
}

/* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 512 — FIP: адрес последней команды x87.
 *
 * Управляющие команды указатель НЕ обновляют — потому эталон и показал адрес `fldl2e`, а не
 * стоящего следом `fnstenv`. Список ровно тот, что в SDM помечен как «не обновляет FIP/FDP».
 * Замер 511: образ окружения эталона отличался от нашего ТОЛЬКО этим полем. */
static bool x87_updates_fip(hb_ir_op_t op) {
    switch (op) {
        case HB_IR_X87_FLDCW:  case HB_IR_X87_FNSTCW:  case HB_IR_X87_FNSTSW:
        case HB_IR_X87_FLDENV: case HB_IR_X87_FNSTENV: case HB_IR_X87_FNSAVE:
        case HB_IR_X87_FRSTOR: case HB_IR_X87_FNINIT:  case HB_IR_X87_FNCLEX:
            return false;
        /* Итерация 906: семья `FI` объявлена в конце перечисления (чтобы не двигать соседей),
         * поэтому в диапазон `FLD..FISTTP` не попадает — а указатель обновлять обязана. */
        case HB_IR_X87_FI:
            return true;
        default:
            return op >= HB_IR_X87_FLD && op <= HB_IR_X87_FISTTP;
    }
}

/* ★★★★★ ИТЕРАЦИЯ 119, лейн УСТАНОВЩИКИ — ПРЕДЕЛ СТРОКОВЫХ ОПЕРАЦИЙ НАСТРАИВАЕМ.
 *
 * Замер: обычный прогон установщика останавливает НЕ гейт `MACRUNNER_HB_NO_STEP_LIMIT`
 * (проверено: с ним 78 000 вызовов, без него те же 78 000), а жёсткая константа
 * 0x100000 в цикле `MOVS`: `rep movs` длиннее миллиона элементов возвращает
 * HB_ERR_STEP_LIMIT, дальше `c0000001` из xtajit и смерть.
 *
 * Для распаковщика копия больше 4 МБ законна, значит предел бьёт по делу. Делаю его
 * настраиваемым, УМОЛЧАНИЕ ПРЕЖНЕЕ — чтобы правка ничего не меняла, пока её не
 * включили замером. */
static uint64_t hb_stringop_limit(void)
{
    static uint64_t cached;
    if (!cached) {
        const char* v = hb_gate( HB_GATE_HB_STRINGOP_LIMIT );
        unsigned long long n = 0;
        if (v && *v) n = strtoull(v, NULL, 0);
        cached = n ? (uint64_t)n : 0x100000ull;
    }
    return cached;
}

static hb_result_t exec_instr_unlocked(hb_context_t* ctx, const hb_ir_instr_t* instr) {
    /* ★ 26.08.2026 — СОСТАВ ИНТЕРПРЕТАЦИИ. Её доля на игре 0,56 % шагов, но КАКИЕ команды
     * кодогенератор не выпускает — не названо ни разу. Без списка «дожать до нуля» значит
     * перебирать сотни форм x86 вслепую; со списком сразу видно, есть ли там одна-две
     * частые, ради которых стоит браться. В горячем пути — одна инкрементация. */
    if (instr) {
        unsigned _op = (unsigned)instr->op;
        if (_op < 512) {
            g_interp_op_count[_op]++;
            if (instr->zero_ymm_upper) g_interp_zero_ymm[_op]++;
        }
    }

    if (instr && x87_updates_fip(instr->op))
        hb_context_x87(ctx)->last_x87_ip = (uint32_t)instr->guest_addr;
    hb_result_t r;
    if (!(++t_hb_interp_instr & (HB_INTERP_CENSUS_PERIOD - 1)))
        hb_interp_instr_fold();
    switch (instr->op) {
        case HB_IR_NOP:
            return HB_OK;

        case HB_IR_FENCE:
            switch ((hb_fence_kind_t)instr->src1.imm) {
                case HB_FENCE_ACQUIRE:
                    __atomic_thread_fence(__ATOMIC_ACQUIRE);
                    break;
                case HB_FENCE_RELEASE:
                    __atomic_thread_fence(__ATOMIC_RELEASE);
                    break;
                case HB_FENCE_FULL:
                default:
                    __atomic_thread_fence(__ATOMIC_SEQ_CST);
                    break;
            }
            return HB_OK;

        case HB_IR_MOV: {
            if (instr->dst.type == HB_OP_REG && instr->src1.type == HB_OP_REG &&
                is_xmm_reg(instr->dst.reg) && is_xmm_reg(instr->src1.reg)) {
                size_t bytes = bytes_for_size(instr->dst.size);
                if (bytes == 0) bytes = 16;
                unsigned lane = evex_target_arg(instr) & 0xffu;
                if (!(lane == 1 || lane == 2 || lane == 4 || lane == 8)) lane = 4;
                uint8_t src[64], dst[64];
                r = read_vec_reg_bytes(ctx, instr->src1.reg, src, bytes);
                if (r != HB_OK) return r;
                if (bytes >= 16) return write_vec_reg_bytes_evex_masked(ctx, instr, src, bytes, lane);
                r = read_vec_reg_bytes(ctx, instr->dst.reg, dst, 16);
                if (r != HB_OK) return r;
                memcpy(dst, src, bytes);
                return write_vec_reg_bytes_evex_masked(ctx, instr, dst, 16, lane);
            }
            uint64_t val = 0;
            if (instr->src1.type == HB_OP_REG)
                val = read_reg_sized(ctx, instr->src1.reg, instr->src1.size, instr->src1.reg_offset);
            else if (instr->src1.type == HB_OP_IMM) val = (uint64_t)instr->src1.imm;
            else return HB_ERR_INTERNAL;
            if (instr->dst.type == HB_OP_REG) {
                hb_size_t size = instr->dst.size ? instr->dst.size : instr->src1.size;
                if (!size) size = HB_SIZE_64;
                write_reg_sized_offset(ctx, instr->dst.reg, val, size, instr->dst.reg_offset);
            }
            else return HB_ERR_INTERNAL;
            return HB_OK;
        }

        case HB_IR_MOV_SEG: {
            if (instr->src1.type == HB_OP_IMM && instr->dst.type != HB_OP_IMM) {
                uint16_t selector = 0;
                r = read_seg_selector(ctx, (uint16_t)instr->src1.imm, &selector);
                if (r != HB_OK) return r;
                return write_operand_value(ctx, &instr->dst, selector);
            }
            if (instr->dst.type == HB_OP_IMM && instr->src1.type != HB_OP_IMM) {
                uint64_t selector = 0;
                r = read_operand_value(ctx, &instr->src1, &selector);
                if (r != HB_OK) return r;
                return write_seg_selector(ctx, (uint16_t)instr->dst.imm, (uint16_t)selector);
            }
            return HB_ERR_INTERNAL;
        }

        case HB_IR_LEA: {
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            uint64_t addr = resolve_addr(ctx, &instr->src1);
            if (instr->dst.type == HB_OP_REG) write_reg_sized(ctx, instr->dst.reg, addr, instr->dst.size);
            else return HB_ERR_INTERNAL;
            return HB_OK;
        }

        case HB_IR_ADD:
        case HB_IR_ADC:
        case HB_IR_SUB:
        case HB_IR_SBB:
        case HB_IR_AND:
        case HB_IR_OR:
        case HB_IR_XOR: {
            r = hb_flags_exec_binop_operand(ctx, instr->op, &instr->dst, &instr->src1, &instr->src2, NULL,
                                            instr->preserve_cf);
            if (r != HB_OK) return r;
            return HB_OK;
        }

        case HB_IR_IMUL: {
            uint64_t lhs = 0, rhs = 0;
            if (instr->dst.type == HB_OP_NONE) {
                r = read_operand_value(ctx, &instr->src1, &rhs);
                if (r != HB_OK) return r;
                hb_size_t size = instr->src1.size ? instr->src1.size : HB_SIZE_32;
                if (size == HB_SIZE_8) {
                    int16_t result = (int16_t)((int8_t)read_reg_sized(ctx, HB_REG_RAX, HB_SIZE_8, 0) * (int8_t)rhs);
                    write_reg_sized(ctx, HB_REG_RAX, (uint16_t)result, HB_SIZE_16);
                    ctx->flags.cf = ctx->flags.of = (result < INT8_MIN || result > INT8_MAX);
                } else if (size == HB_SIZE_16) {
                    int32_t result = (int32_t)((int16_t)read_reg_sized(ctx, HB_REG_RAX, HB_SIZE_16, 0) * (int16_t)rhs);
                    write_reg_sized(ctx, HB_REG_RAX, (uint16_t)result, HB_SIZE_16);
                    write_reg_sized(ctx, HB_REG_RDX, (uint16_t)(result >> 16), HB_SIZE_16);
                    ctx->flags.cf = ctx->flags.of = (result < INT16_MIN || result > INT16_MAX);
                } else if (size == HB_SIZE_32) {
                    int64_t result = (int64_t)(int32_t)read_reg_sized(ctx, HB_REG_RAX, HB_SIZE_32, 0) * (int64_t)(int32_t)rhs;
                    write_reg_sized(ctx, HB_REG_RAX, (uint32_t)result, HB_SIZE_32);
                    write_reg_sized(ctx, HB_REG_RDX, (uint32_t)(result >> 32), HB_SIZE_32);
                    ctx->flags.cf = ctx->flags.of = (result < INT32_MIN || result > INT32_MAX);
                } else if (size == HB_SIZE_64) {
                    __int128 result = (__int128)(int64_t)read_reg_sized(ctx, HB_REG_RAX, HB_SIZE_64, 0) * (__int128)(int64_t)rhs;
                    write_reg_sized(ctx, HB_REG_RAX, (uint64_t)result, HB_SIZE_64);
                    write_reg_sized(ctx, HB_REG_RDX, (uint64_t)(result >> 64), HB_SIZE_64);
                    ctx->flags.cf = ctx->flags.of = (result < (__int128)INT64_MIN || result > (__int128)INT64_MAX);
                } else return HB_ERR_UNSUPPORTED_OPCODE;
                hb_lazy_flags_clear(ctx);
                return HB_OK;
            }
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            r = read_operand_value(ctx, &instr->src1, &lhs);
            if (r != HB_OK) return r;
            r = read_operand_value(ctx, &instr->src2, &rhs);
            if (r != HB_OK) return r;
            hb_size_t size = instr->dst.size ? instr->dst.size : HB_SIZE_64;
            int64_t slhs = (int64_t)sign_extend_from_size(trunc_to_size(lhs, size), size);
            int64_t srhs = (int64_t)sign_extend_from_size(trunc_to_size(rhs, size), size);
            __int128 full = (__int128)slhs * (__int128)srhs;
            uint64_t result = trunc_to_size((uint64_t)full, size);
            __int128 truncated_signed = (__int128)(int64_t)sign_extend_from_size(result, size);
            write_reg_sized(ctx, instr->dst.reg, result, size);
            ctx->flags.cf = ctx->flags.of = (full != truncated_signed);
            hb_lazy_flags_clear(ctx); /* x86 leaves several flags undefined for truncated IMUL. */
            return HB_OK;
        }

        case HB_IR_MUL: {
            uint64_t src = 0;
            r = read_operand_value(ctx, &instr->src1, &src);
            if (r != HB_OK) return r;
            hb_size_t size = instr->src1.size ? instr->src1.size : HB_SIZE_32;
            src = trunc_to_size(src, size);

            if (size == HB_SIZE_8) {
                uint16_t result = (uint16_t)((uint8_t)read_reg_sized(ctx, HB_REG_RAX, HB_SIZE_8, 0) * (uint8_t)src);
                write_reg_sized(ctx, HB_REG_RAX, result, HB_SIZE_16);
                ctx->flags.cf = ctx->flags.of = ((result >> 8) != 0);
            } else if (size == HB_SIZE_16) {
                uint32_t result = (uint32_t)(uint16_t)read_reg_sized(ctx, HB_REG_RAX, HB_SIZE_16, 0) * (uint32_t)(uint16_t)src;
                write_reg_sized(ctx, HB_REG_RAX, (uint16_t)result, HB_SIZE_16);
                write_reg_sized(ctx, HB_REG_RDX, (uint16_t)(result >> 16), HB_SIZE_16);
                ctx->flags.cf = ctx->flags.of = ((result >> 16) != 0);
            } else if (size == HB_SIZE_32) {
                uint64_t result = (uint64_t)(uint32_t)read_reg_sized(ctx, HB_REG_RAX, HB_SIZE_32, 0) * (uint64_t)(uint32_t)src;
                write_reg_sized(ctx, HB_REG_RAX, (uint32_t)result, HB_SIZE_32);
                write_reg_sized(ctx, HB_REG_RDX, (uint32_t)(result >> 32), HB_SIZE_32);
                ctx->flags.cf = ctx->flags.of = ((result >> 32) != 0);
            } else if (size == HB_SIZE_64) {
                unsigned __int128 result = (unsigned __int128)read_reg_sized(ctx, HB_REG_RAX, HB_SIZE_64, 0) * (unsigned __int128)src;
                write_reg_sized(ctx, HB_REG_RAX, (uint64_t)result, HB_SIZE_64);
                write_reg_sized(ctx, HB_REG_RDX, (uint64_t)(result >> 64), HB_SIZE_64);
                ctx->flags.cf = ctx->flags.of = ((uint64_t)(result >> 64) != 0);
            } else return HB_ERR_UNSUPPORTED_OPCODE;

            hb_lazy_flags_clear(ctx);
            return HB_OK;
        }

        case HB_IR_DIV: {
            uint64_t divisor = 0;
            r = read_operand_value(ctx, &instr->src1, &divisor);
            if (r != HB_OK) return r;

            hb_size_t size = instr->src1.size ? instr->src1.size : HB_SIZE_32;
            divisor = trunc_to_size(divisor, size);
            if (!divisor) return hb_fault_divide(ctx, instr ? instr->guest_addr : 0); /* x86 #DE: divide by zero. */

            if (size == HB_SIZE_8) {
                uint16_t dividend = (uint16_t)(read_reg(ctx, HB_REG_RAX) & 0xffff);
                uint16_t quotient = dividend / (uint8_t)divisor;
                uint16_t remainder = dividend % (uint8_t)divisor;
                if (quotient > 0xffU) return hb_fault_divide(ctx, instr ? instr->guest_addr : 0);
                write_reg_sized(ctx, HB_REG_RAX, (uint16_t)((remainder << 8) | quotient), HB_SIZE_16);
            } else if (size == HB_SIZE_16) {
                uint32_t dividend = ((uint32_t)(read_reg(ctx, HB_REG_RDX) & 0xffff) << 16) |
                                    (uint32_t)(read_reg(ctx, HB_REG_RAX) & 0xffff);
                uint32_t quotient = dividend / (uint32_t)divisor;
                uint32_t remainder = dividend % (uint32_t)divisor;
                if (quotient > 0xffffU) return hb_fault_divide(ctx, instr ? instr->guest_addr : 0);
                write_reg_sized(ctx, HB_REG_RAX, quotient, HB_SIZE_16);
                write_reg_sized(ctx, HB_REG_RDX, remainder, HB_SIZE_16);
            } else if (size == HB_SIZE_32) {
                uint64_t dividend = ((uint64_t)(uint32_t)read_reg(ctx, HB_REG_RDX) << 32) |
                                    (uint64_t)(uint32_t)read_reg(ctx, HB_REG_RAX);
                uint64_t quotient = dividend / (uint32_t)divisor;
                uint64_t remainder = dividend % (uint32_t)divisor;
                if (quotient > 0xffffffffULL) return hb_fault_divide(ctx, instr ? instr->guest_addr : 0);
                write_reg_sized(ctx, HB_REG_RAX, quotient, HB_SIZE_32);
                write_reg_sized(ctx, HB_REG_RDX, remainder, HB_SIZE_32);
            } else if (size == HB_SIZE_64) {
                unsigned __int128 dividend = ((unsigned __int128)read_reg(ctx, HB_REG_RDX) << 64) |
                                             (unsigned __int128)read_reg(ctx, HB_REG_RAX);
                unsigned __int128 quotient = dividend / divisor;
                unsigned __int128 remainder = dividend % divisor;
                if (quotient > UINT64_MAX) return hb_fault_divide(ctx, instr ? instr->guest_addr : 0);
                write_reg_sized(ctx, HB_REG_RAX, (uint64_t)quotient, HB_SIZE_64);
                write_reg_sized(ctx, HB_REG_RDX, (uint64_t)remainder, HB_SIZE_64);
            } else {
                return HB_ERR_UNSUPPORTED_OPCODE;
            }

            hb_lazy_flags_clear(ctx); /* DIV leaves status flags undefined. */
            return HB_OK;
        }

        case HB_IR_IDIV: {
            uint64_t divisor_raw = 0;
            r = read_operand_value(ctx, &instr->src1, &divisor_raw);
            if (r != HB_OK) return r;
            hb_size_t size = instr->src1.size ? instr->src1.size : HB_SIZE_32;
            uint64_t divisor_bits = trunc_to_size(divisor_raw, size);
            int64_t divisor = (int64_t)sign_extend_from_size(divisor_bits, size);
            if (!divisor) return hb_fault_divide(ctx, instr ? instr->guest_addr : 0);

            if (size == HB_SIZE_8) {
                int16_t dividend = (int16_t)(read_reg(ctx, HB_REG_RAX) & 0xffff);
                int64_t quotient = dividend / (int8_t)divisor;
                int64_t remainder = dividend % (int8_t)divisor;
                if (quotient < INT8_MIN || quotient > INT8_MAX) return hb_fault_divide(ctx, instr ? instr->guest_addr : 0);
                write_reg_sized(ctx, HB_REG_RAX,
                                (uint16_t)(((uint8_t)remainder << 8) | (uint8_t)quotient),
                                HB_SIZE_16);
            } else if (size == HB_SIZE_16) {
                int32_t dividend = (int32_t)(((uint32_t)(read_reg(ctx, HB_REG_RDX) & 0xffff) << 16) |
                                             (uint32_t)(read_reg(ctx, HB_REG_RAX) & 0xffff));
                int64_t quotient = dividend / (int16_t)divisor;
                int64_t remainder = dividend % (int16_t)divisor;
                if (quotient < INT16_MIN || quotient > INT16_MAX) return hb_fault_divide(ctx, instr ? instr->guest_addr : 0);
                write_reg_sized(ctx, HB_REG_RAX, (uint16_t)quotient, HB_SIZE_16);
                write_reg_sized(ctx, HB_REG_RDX, (uint16_t)remainder, HB_SIZE_16);
            } else if (size == HB_SIZE_32) {
                int64_t dividend = (int64_t)(((uint64_t)(uint32_t)read_reg(ctx, HB_REG_RDX) << 32) |
                                             (uint64_t)(uint32_t)read_reg(ctx, HB_REG_RAX));
                int64_t quotient = dividend / (int32_t)divisor;
                int64_t remainder = dividend % (int32_t)divisor;
                if (quotient < INT32_MIN || quotient > INT32_MAX) return hb_fault_divide(ctx, instr ? instr->guest_addr : 0);
                write_reg_sized(ctx, HB_REG_RAX, (uint32_t)quotient, HB_SIZE_32);
                write_reg_sized(ctx, HB_REG_RDX, (uint32_t)remainder, HB_SIZE_32);
            } else if (size == HB_SIZE_64) {
                unsigned __int128 bits = ((unsigned __int128)read_reg(ctx, HB_REG_RDX) << 64) |
                                         (unsigned __int128)read_reg(ctx, HB_REG_RAX);
                __int128 dividend = (__int128)bits;
                __int128 quotient = dividend / (int64_t)divisor;
                __int128 remainder = dividend % (int64_t)divisor;
                if (quotient < (__int128)INT64_MIN || quotient > (__int128)INT64_MAX)
                    return hb_fault_divide(ctx, instr ? instr->guest_addr : 0);
                write_reg_sized(ctx, HB_REG_RAX, (uint64_t)quotient, HB_SIZE_64);
                write_reg_sized(ctx, HB_REG_RDX, (uint64_t)remainder, HB_SIZE_64);
            } else return HB_ERR_UNSUPPORTED_OPCODE;

            hb_lazy_flags_clear(ctx);
            return HB_OK;
        }

        case HB_IR_BT:
        case HB_IR_BTS:
        case HB_IR_BTR:
        case HB_IR_BTC: {
            uint64_t base = 0, bit_raw = 0;
            hb_ir_operand_t target = instr->src1;
            r = read_operand_value(ctx, &instr->src1, &base);
            if (r != HB_OK) return r;
            r = read_operand_value(ctx, &instr->src2, &bit_raw);
            if (r != HB_OK) return r;

            hb_size_t size = instr->src1.size ? instr->src1.size : HB_SIZE_32;
            unsigned width = (size == HB_SIZE_64) ? 64 : (size == HB_SIZE_16) ? 16 : 32;
            uint64_t bit = bit_raw & (width - 1);

            /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 277 — НЕПОСРЕДСТВЕННОЕ СМЕЩЕНИЕ
             * БЕРЁТСЯ ПО МОДУЛЮ. Поправка адреса ниже допустима ТОЛЬКО при регистровом смещении:
             * по спецификации x86 у `BT/BTS/BTR/BTC` с операндом в памяти регистровое смещение
             * может адресовать биты ЗА операндом, а непосредственное (imm8) — берётся по модулю
             * разрядности (192 mod 32 = 0). Мы применяли регистровое правило к обоим, и
             * `bts dword ptr [esp], 0xc0` правил не тот двойное слово и давал неверный CF.
             * Сверка с Unicorn называла это парой: `flag.cf expected=0 actual=1` плюс
             * разошедшийся хеш памяти. */
            if (target.type == HB_OP_MEM && bit_raw >= width &&
                instr->src2.type != HB_OP_IMM) {
                uint64_t addr = resolve_addr(ctx, &target);
                addr += (bit_raw / width) * (width / 8);
                target.mem.base = HB_REG_COUNT;
                target.mem.index = HB_REG_COUNT;
                target.mem.disp = (int64_t)addr;
                bit = bit_raw % width;
                r = read_operand_value(ctx, &target, &base);
                if (r != HB_OK) return r;
            }

            uint64_t mask = 1ULL << bit;
            uint64_t value = trunc_to_size(base, size);
            uint64_t new_value = value;
            ctx->flags.cf = (value & mask) != 0;
            hb_lazy_flags_clear(ctx);

            if (instr->op == HB_IR_BTS) {
                new_value = value | mask;
                r = write_operand_value(ctx, &target, new_value);
                if (r != HB_OK) return r;
            } else if (instr->op == HB_IR_BTR) {
                new_value = value & ~mask;
                r = write_operand_value(ctx, &target, new_value);
                if (r != HB_OK) return r;
            } else if (instr->op == HB_IR_BTC) {
                new_value = value ^ mask;
                r = write_operand_value(ctx, &target, new_value);
                if (r != HB_OK) return r;
            }
            if (trace_bitops_selected(instr)) {
                static unsigned int bitop_count;
                if (++bitop_count <= trace_bitops_budget()) {
                    uint64_t addr = 0;
                    if (target.type == HB_OP_MEM) addr = resolve_addr(ctx, &target);
                    fprintf(stderr,
                            "macrunner-hb-bitop: pc=0x%llx op=%s count=%u target_type=%d "
                            "addr=0x%llx size=%d bit_raw=0x%llx bit=%llu mask=0x%llx "
                            "old=0x%llx new=0x%llx cf=%u\n",
                            (unsigned long long)instr->guest_addr, ir_op_name(instr->op), bitop_count,
                            target.type, (unsigned long long)addr, target.size,
                            (unsigned long long)bit_raw, (unsigned long long)bit,
                            (unsigned long long)mask, (unsigned long long)value,
                            (unsigned long long)trunc_to_size(new_value, size), ctx->flags.cf);
                }
            }
            return HB_OK;
        }

        case HB_IR_CMP: {
            uint64_t a = 0;
            r = read_operand_value(ctx, &instr->src1, &a);
            if (r != HB_OK) return r;
            uint64_t b = 0;
            r = read_operand_value(ctx, &instr->src2, &b);
            if (r != HB_OK) return r;
            hb_lazy_flags_note(ctx, HB_LAZY_FLAGS_CMP, instr->src1.size, a, b, a - b, 0);
            return HB_OK;
        }

        case HB_IR_TEST: {
            uint64_t a = 0;
            r = read_operand_value(ctx, &instr->src1, &a);
            if (r != HB_OK) return r;
            uint64_t b = 0;
            r = read_operand_value(ctx, &instr->src2, &b);
            if (r != HB_OK) return r;
            hb_lazy_flags_note(ctx, HB_LAZY_FLAGS_TEST, instr->src1.size, a, b, a & b, 0);
            return HB_OK;
        }

        case HB_IR_CMPXCHG: {
            /* x86 LOCK-prefixed RMW implies a full memory barrier (TSO). ARM64 is weakly
             * ordered, so model it explicitly — otherwise a cross-thread publisher's store
             * is never observed by a spin-reader (livelock). See CLAUDE-GATE-DIAGNOSIS UPDATE 4. */
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            uint64_t dst_val = 0;
            uint64_t src_val = 0;
            hb_size_t size = instr->dst.size ? instr->dst.size : instr->src1.size;
            if (!size) size = instr->src2.size ? instr->src2.size : HB_SIZE_32;

            r = read_operand_value(ctx, &instr->src1, &dst_val);
            if (r != HB_OK) return r;
            r = read_operand_value(ctx, &instr->src2, &src_val);
            if (r != HB_OK) return r;

            uint64_t acc = read_reg_sized(ctx, HB_REG_RAX, size, 0);
            dst_val = trunc_to_size(dst_val, size);
            src_val = trunc_to_size(src_val, size);

            hb_lazy_flags_note(ctx, HB_LAZY_FLAGS_CMP, size, acc, dst_val, acc - dst_val, 0);
            if (trace_atomics_enabled()) {
                fprintf(stderr,
                        "macrunner-hb-atomic: pc=0x%llx op=CMPXCHG size=%d acc=0x%llx dst=0x%llx src=0x%llx equal=%d",
                        (unsigned long long)ctx->pc, size, (unsigned long long)acc,
                        (unsigned long long)dst_val, (unsigned long long)src_val, acc == dst_val);
                trace_operand("dstop", ctx, &instr->src1);
                trace_operand("srcop", ctx, &instr->src2);
                fprintf(stderr, "\n");
            }
            if (acc == dst_val) {
                r = write_operand_value(ctx, &instr->src1, src_val);
                if (r != HB_OK) return r;
            } else {
                write_reg_sized(ctx, HB_REG_RAX, dst_val, size);
            }
            return HB_OK;
        }

        case HB_IR_CMPXCHG8B: {
            __atomic_thread_fence(__ATOMIC_SEQ_CST); /* x86 LOCK full barrier (TSO) — see UPDATE 4 */
            if (instr->dst.size == HB_SIZE_128) {
                uint64_t mem[2] = {0, 0};
                uint64_t acc[2] = {read_reg(ctx, HB_REG_RAX), read_reg(ctx, HB_REG_RDX)};
                uint64_t src[2] = {read_reg(ctx, HB_REG_RBX), read_reg(ctx, HB_REG_RCX)};
                uint64_t addr;
                bool equal;

                if (ctx->mode != HB_MODE_64BIT || instr->dst.type != HB_OP_MEM)
                    return HB_ERR_INTERNAL;
                addr = resolve_addr(ctx, &instr->dst);
                r = hb_memory_read(ctx->memory, addr, mem, sizeof(mem));
                if (r != HB_OK) return r;
                equal = mem[0] == acc[0] && mem[1] == acc[1];
                hb_lazy_flags_clear(ctx);
                ctx->flags.zf = equal;
                if (equal) {
                    r = hb_memory_write(ctx->memory, addr, src, sizeof(src));
                    if (r != HB_OK) return r;
                } else {
                    write_reg_sized(ctx, HB_REG_RAX, mem[0], HB_SIZE_64);
                    write_reg_sized(ctx, HB_REG_RDX, mem[1], HB_SIZE_64);
                }
                return HB_OK;
            }

            uint64_t mem = 0;
            uint64_t acc = ((uint64_t)(uint32_t)read_reg(ctx, HB_REG_RDX) << 32) |
                           (uint32_t)read_reg(ctx, HB_REG_RAX);
            uint64_t src = ((uint64_t)(uint32_t)read_reg(ctx, HB_REG_RCX) << 32) |
                           (uint32_t)read_reg(ctx, HB_REG_RBX);
            bool equal;

            r = read_operand_value(ctx, &instr->dst, &mem);
            if (r != HB_OK) return r;
            equal = (mem == acc);
            hb_lazy_flags_clear(ctx);
            ctx->flags.zf = equal;
            if (equal) {
                r = write_operand_value(ctx, &instr->dst, src);
                if (r != HB_OK) return r;
            } else {
                write_reg_sized(ctx, HB_REG_RAX, (uint32_t)mem, HB_SIZE_32);
                write_reg_sized(ctx, HB_REG_RDX, (uint32_t)(mem >> 32), HB_SIZE_32);
            }
            return HB_OK;
        }

        case HB_IR_XCHG: {
            /* XCHG with a memory operand is implicitly LOCK'd on x86 → full barrier (TSO). */
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            uint64_t dst_val = 0;
            uint64_t src_val = 0;
            hb_size_t size = instr->dst.size ? instr->dst.size : instr->src1.size;
            if (!size) size = instr->src2.size ? instr->src2.size : HB_SIZE_32;

            r = read_operand_value(ctx, &instr->src1, &dst_val);
            if (r != HB_OK) return r;
            r = read_operand_value(ctx, &instr->src2, &src_val);
            if (r != HB_OK) return r;

            dst_val = trunc_to_size(dst_val, size);
            src_val = trunc_to_size(src_val, size);

            if (trace_atomics_enabled()) {
                fprintf(stderr,
                        "macrunner-hb-atomic: pc=0x%llx op=XCHG size=%d dst=0x%llx src=0x%llx",
                        (unsigned long long)ctx->pc, size, (unsigned long long)dst_val,
                        (unsigned long long)src_val);
                trace_operand("dstop", ctx, &instr->src1);
                trace_operand("srcop", ctx, &instr->src2);
                fprintf(stderr, "\n");
            }

            r = write_operand_value(ctx, &instr->src1, src_val);
            if (r != HB_OK) return r;
            r = write_operand_value(ctx, &instr->src2, dst_val);
            if (r != HB_OK) return r;
            return HB_OK;
        }

        case HB_IR_XADD: {
            /* x86 LOCK XADD implies a full memory barrier (TSO). */
            __atomic_thread_fence(__ATOMIC_SEQ_CST);
            uint64_t dst_val = 0;
            uint64_t src_val = 0;
            hb_size_t size = instr->dst.size ? instr->dst.size : instr->src1.size;
            if (!size) size = instr->src2.size ? instr->src2.size : HB_SIZE_32;

            r = read_operand_value(ctx, &instr->src1, &dst_val);
            if (r != HB_OK) return r;
            r = read_operand_value(ctx, &instr->src2, &src_val);
            if (r != HB_OK) return r;

            dst_val = trunc_to_size(dst_val, size);
            src_val = trunc_to_size(src_val, size);
            uint64_t result = trunc_to_size(dst_val + src_val, size);
            hb_lazy_flags_note(ctx, HB_LAZY_FLAGS_ADD, size, dst_val, src_val, result, 0);

            if (trace_atomics_enabled()) {
                fprintf(stderr,
                        "macrunner-hb-atomic: pc=0x%llx op=XADD size=%d dst=0x%llx src=0x%llx result=0x%llx",
                        (unsigned long long)ctx->pc, size, (unsigned long long)dst_val,
                        (unsigned long long)src_val, (unsigned long long)result);
                trace_operand("dstop", ctx, &instr->src1);
                trace_operand("srcop", ctx, &instr->src2);
                fprintf(stderr, "\n");
            }

            /* MacRunner 2026-08-17, лейн ЛЕСТНИЦА, итерация 1436 — ПОРЯДОК ЗАПИСИ ПРИ АЛИАСЕ.
             *
             * Тот же класс, что найден у MULX в 1435: два приёмника, заданных операндами, и при
             * совпадении регистров исход решает ПОРЯДОК. x86 велит:
             *     TEMP := SRC + DEST;   SRC := DEST;   DEST := TEMP
             * то есть приёмник (`src1`) пишется ПОСЛЕДНИМ, и при `xadd eax, eax` в регистре
             * остаётся СУММА. У нас приёмник писался ПЕРВЫМ, и оставалось СТАРОЕ значение.
             *
             * ЗАМЕР (`tools/hb_isa_coverage/oracles/alias_writes.c`, x86-64 под Rosetta):
             *     контроль  dst=0A0B0C0D src=00010002 -> dst=0A0C0C0F src=0A0B0C0D  СОВПАЛО
             *     ★ алиас   x=11112222 -> получено 22224444 = СУММА
             *
             * Предсказание было записано в шапке пробы ДО замера и подтвердилось.
             *
             * Нативного выпуска у XADD нет (`emit_atomic_ir_helper`), а быстрый атомарный путь
             * `hb_jit_atomic_xadd` требует указателя в ПАМЯТЬ, где совпадение с регистром
             * невозможно, — поэтому правка одна и здесь, парной не требуется.
             *
             * Оба значения посчитаны выше, перестановка записей безопасна. */
            r = write_operand_value(ctx, &instr->src2, dst_val);
            if (r != HB_OK) return r;
            r = write_operand_value(ctx, &instr->src1, result);
            if (r != HB_OK) return r;
            return HB_OK;
        }

        case HB_IR_LOAD: {
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            uint64_t addr = resolve_addr(ctx, &instr->src1);
            if (instr->dst.type == HB_OP_REG && is_xmm_reg(instr->dst.reg)) {
                uint8_t xmm[64] = {0};
                size_t bytes = bytes_for_size(instr->src1.size);
                if (bytes == 0) bytes = 16;
                unsigned lane = evex_target_arg(instr) & 0xffu;
                if (!(lane == 1 || lane == 2 || lane == 4 || lane == 8)) lane = 4;
                if (bytes < 16 && !instr->zero_upper) {
                    r = read_vec_reg_bytes(ctx, instr->dst.reg, xmm, 16);
                    if (r != HB_OK) return r;
                }
                r = hb_memory_read(ctx->memory, addr, xmm, bytes);
                if (r != HB_OK) return r;
                trace_mem_watch_bytes(ctx, "read", addr, xmm, bytes, NULL);
                return write_vec_reg_bytes_evex_masked(ctx, instr, xmm, bytes < 16 ? 16 : bytes, lane);
            }
            uint64_t val = 0;
            r = mem_read(ctx, addr, &val, instr->dst.size);
            if (r != HB_OK) return r;
            if (instr->dst.type == HB_OP_REG)
                write_reg_sized_offset(ctx, instr->dst.reg, val, instr->dst.size, instr->dst.reg_offset);
            else return HB_ERR_INTERNAL;
            return HB_OK;
        }

        case HB_IR_STORE: {
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            uint64_t addr = resolve_addr(ctx, &instr->src1);
            if (instr->src2.type == HB_OP_REG && is_xmm_reg(instr->src2.reg)) {
                uint8_t xmm[64];
                size_t bytes = bytes_for_size(instr->src1.size);
                if (bytes == 0) bytes = bytes_for_size(instr->src2.size);
                if (bytes == 0) bytes = 16;
                r = read_vec_reg_bytes(ctx, instr->src2.reg, xmm, bytes);
                if (r != HB_OK) return r;
                uint64_t first_qword = 0;
                memcpy(&first_qword, xmm, sizeof(first_qword));
                trace_guest_native_write(ctx, "interp_xmm_store", addr, first_qword, (hb_size_t)bytes);
                uint8_t before[16] = {0};
                if (trace_mem_watch_enabled())
                    (void)hb_memory_read(ctx->memory, addr, before, bytes > sizeof(before) ? sizeof(before) : bytes);
                if (evex_target_present(instr) && evex_target_mask(instr) != 0) {
                    uint64_t k = ctx->k[evex_target_mask(instr) & 7u];
                    unsigned lane = evex_target_arg(instr) & 0xffu;
                    if (!(lane == 1 || lane == 2 || lane == 4 || lane == 8)) lane = 4;
                    for (size_t off = 0; off < bytes; off += lane) {
                        if (!((k >> (off / lane)) & 1u)) continue;
                        r = hb_memory_write(ctx->memory, addr + off, xmm + off, lane);
                        if (r != HB_OK) break;
                    }
                } else {
                    r = hb_memory_write(ctx->memory, addr, xmm, bytes);
                }
                if (r != HB_OK) trace_stack_write_fault(ctx, addr, first_qword, (hb_size_t)bytes, r);
                else trace_mem_watch_bytes(ctx, "write", addr, xmm, bytes, before);
                return r;
            }
            uint64_t val = 0;
            if (instr->src2.type == HB_OP_REG)
                val = read_reg_sized(ctx, instr->src2.reg, instr->src2.size, instr->src2.reg_offset);
            else if (instr->src2.type == HB_OP_IMM) val = (uint64_t)instr->src2.imm;
            else return HB_ERR_INTERNAL;
            r = mem_write(ctx, addr, val, instr->src2.size);
            if (r != HB_OK) return r;
            return HB_OK;
        }

        case HB_IR_XMM_QWORD_LANE_MOV: {
            unsigned dst_lane = (unsigned)(instr->target & 0xff);
            unsigned src_lane = (unsigned)((instr->target >> 8) & 0xff);
            if (dst_lane > 1 || src_lane > 1) return HB_ERR_INTERNAL;
            if (instr->dst.type == HB_OP_MEM) {
                if (instr->src1.type != HB_OP_REG || !is_xmm_reg(instr->src1.reg)) return HB_ERR_INTERNAL;
                uint64_t src[2];
                r = read_xmm_reg(ctx, instr->src1.reg, src);
                if (r != HB_OK) return r;
                uint64_t addr = resolve_addr(ctx, &instr->dst);
                return hb_memory_write(ctx->memory, addr, &src[src_lane], sizeof(uint64_t));
            }
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            uint64_t dst[2];
            r = read_xmm_reg(ctx, instr->dst.reg, dst);
            if (r != HB_OK) return r;
            if (instr->src1.type == HB_OP_REG && is_xmm_reg(instr->src1.reg)) {
                uint64_t src[2];
                r = read_xmm_reg(ctx, instr->src1.reg, src);
                if (r != HB_OK) return r;
                dst[dst_lane] = src[src_lane];
            } else if (instr->src1.type == HB_OP_MEM) {
                uint64_t lane = 0;
                uint64_t addr = resolve_addr(ctx, &instr->src1);
                r = hb_memory_read(ctx->memory, addr, &lane, sizeof(lane));
                if (r != HB_OK) return r;
                dst[dst_lane] = lane;
            } else {
                return HB_ERR_INTERNAL;
            }
            r = write_xmm_reg(ctx, instr->dst.reg, dst);
            if (r != HB_OK) return r;
            if (trace_current_instr && trace_current_instr->zero_ymm_upper) {
                unsigned n = (unsigned)(instr->dst.reg - HB_REG_XMM0);
                /* Итерация 510: 32-битный режим выходил здесь досрочно и старшую половину не
                 * трогал. Правило от разрядности не зависит — AVX доступен и в 32 битах, там
                 * просто регистров восемь. Ровно так же поступает `write_vec_reg_bytes`. */
                unsigned limit = (ctx->mode == HB_MODE_32BIT) ? 8u : 16u;
                if (n < limit) memset(ctx->ymm_hi[n], 0, sizeof(ctx->ymm_hi[n]));
            }
            return HB_OK;
        }

        case HB_IR_X87_FLD:
            if (instr->src1.type == HB_OP_IMM) return x87_fld_st(ctx, &instr->src1);
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fld_mem(ctx, &instr->src1);

        case HB_IR_X87_FST:
            if (instr->dst.type == HB_OP_IMM) return x87_fst_st(ctx, &instr->dst, false);
            if (instr->dst.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fst_mem(ctx, &instr->dst);

        case HB_IR_X87_FSTP:
            if (instr->dst.type == HB_OP_IMM) return x87_fst_st(ctx, &instr->dst, true);
            if (instr->dst.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fstp_mem(ctx, &instr->dst);

        case HB_IR_X87_FILD:
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fild_mem(ctx, &instr->src1);

        case HB_IR_X87_FI:
            return x87_fi_mem(ctx, &instr->src1, &instr->src2);

        case HB_IR_X87_FISTP:
            if (instr->dst.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fistp_mem(ctx, &instr->dst);

        case HB_IR_X87_FIST:
            if (instr->dst.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fist_mem(ctx, &instr->dst);

        case HB_IR_X87_FISTTP:
            if (instr->dst.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fisttp_mem(ctx, &instr->dst);

        case HB_IR_SGDT:
            if (instr->dst.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return sys_store_descriptor_table(ctx, &instr->dst, false);

        case HB_IR_SIDT:
            if (instr->dst.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return sys_store_descriptor_table(ctx, &instr->dst, true);

        case HB_IR_LDMXCSR:
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return sse_ldmxcsr_mem(ctx, &instr->src1);

        case HB_IR_STMXCSR:
            if (instr->dst.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return sse_stmxcsr_mem(ctx, &instr->dst);

        case HB_IR_X87_FLDCW:
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fldcw_mem(ctx, &instr->src1);

        case HB_IR_X87_FNSTCW:
            if (instr->dst.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fnstcw_mem(ctx, &instr->dst);

        case HB_IR_X87_FNSTSW:
            if (instr->dst.type == HB_OP_REG) {
                return write_operand_value(ctx, &instr->dst, hb_context_x87(ctx)->status_word);
            }
            if (instr->dst.type == HB_OP_MEM) {
                return x87_fnstsw_mem(ctx, &instr->dst);
            }
            return HB_ERR_INTERNAL;

        case HB_IR_X87_FLDENV:
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fldenv_mem(ctx, &instr->src1);

        case HB_IR_X87_EMMS:   /* итерация 520: все теги в «пусто», тени гасятся */
            return hb_x87_emms(hb_context_x87(ctx));

        case HB_IR_X87_FBLD:
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fbld_mem(ctx, &instr->src1);

        case HB_IR_X87_FBSTP:
            if (instr->dst.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fbstp_mem(ctx, &instr->dst);

        case HB_IR_X87_FNSTENV:
            if (instr->dst.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fnstenv_mem(ctx, &instr->dst);

        case HB_IR_X87_FRSTOR:
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_frstor_mem(ctx, &instr->src1);

        case HB_IR_X87_FNSAVE:
            if (instr->dst.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fnsave_mem(ctx, &instr->dst);

        case HB_IR_X87_FXSAVE:
            if (instr->dst.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fxsave_mem(ctx, &instr->dst);

        case HB_IR_X87_FXRSTOR:
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fxrstor_mem(ctx, &instr->src1);

        case HB_IR_X87_FADD:
        case HB_IR_X87_FMUL:
        case HB_IR_X87_FSUB:
        case HB_IR_X87_FSUBR:
        case HB_IR_X87_FDIV:
        case HB_IR_X87_FDIVR:
            if (instr->src1.type == HB_OP_IMM) return x87_arith_st0_sti(ctx, &instr->src1, instr->op);
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_arith_mem(ctx, &instr->src1, instr->op);

        case HB_IR_X87_FCOM:
            if (instr->src1.type == HB_OP_IMM) return x87_fcom_st(ctx, &instr->src1, 0);
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fcom_mem(ctx, &instr->src1, false);

        case HB_IR_X87_FCOMP:
            if (instr->src1.type == HB_OP_IMM) return x87_fcom_st(ctx, &instr->src1, 1);
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fcom_mem(ctx, &instr->src1, true);

        case HB_IR_X87_FUCOM:
            if (instr->src1.type == HB_OP_IMM) return x87_fcom_st(ctx, &instr->src1, 0);
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fcom_mem(ctx, &instr->src1, false);

        case HB_IR_X87_FUCOMP:
            if (instr->src1.type == HB_OP_IMM) return x87_fcom_st(ctx, &instr->src1, 1);
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            return x87_fcom_mem(ctx, &instr->src1, true);

        case HB_IR_X87_FCOMI:
            return x87_fcomi_st(ctx, &instr->src1, 0, false);
        case HB_IR_X87_FUCOMI:
            return x87_fcomi_st(ctx, &instr->src1, 0, true);
        case HB_IR_X87_FCOMIP:
            return x87_fcomi_st(ctx, &instr->src1, 1, false);
        case HB_IR_X87_FUCOMIP:
            return x87_fcomi_st(ctx, &instr->src1, 1, true);

        case HB_IR_X87_FADDP:
        case HB_IR_X87_FMULP:
        case HB_IR_X87_FSUBP:
        case HB_IR_X87_FSUBRP:
        case HB_IR_X87_FDIVP:
        case HB_IR_X87_FDIVRP:
            return x87_arith_pop_sti_st0(ctx, &instr->src1, instr->op);

        case HB_IR_X87_FCOMPP:
            return x87_fcom_st(ctx, &instr->src1, 2);

        case HB_IR_X87_FXCH:
            return x87_fxch(ctx, &instr->src1);

        case HB_IR_X87_FRNDINT:
            return hb_x87_frndint(hb_context_x87(ctx));

        case HB_IR_X87_FFREE: {
            /* Гейт `MACRUNNER_HB_X87_FFREE`, умолчание 1; 0 возвращает прежнее
             * поведение (NOP) для парного замера на ОДНОМ двоичном. */
            /* Гейт MACRUNNER_HB_X87_FFREE снят 02.09.2026: выключенная ветка делала NOP
             * вместо самой команды FFREE — это не вариант, а неверная эмуляция. */
            return hb_x87_ffree(hb_context_x87(ctx), (unsigned)(instr->src1.imm & 7));
        }

        case HB_IR_X87_FINCSTP:
            return hb_x87_fincstp(hb_context_x87(ctx));

        case HB_IR_X87_FDECSTP:
            return hb_x87_fdecstp(hb_context_x87(ctx));

        case HB_IR_X87_FNCLEX:
            return hb_x87_fnclex(hb_context_x87(ctx));

        case HB_IR_X87_FNINIT:
            return hb_x87_fninit(hb_context_x87(ctx));

        case HB_IR_X87_FXAM:
            return hb_x87_fxam(hb_context_x87(ctx));

        case HB_IR_X87_FSQRT:   return hb_x87_fsqrt(hb_context_x87(ctx));
        case HB_IR_X87_F2XM1:   return hb_x87_f2xm1(hb_context_x87(ctx));
        case HB_IR_X87_FYL2X:   return hb_x87_fyl2x(hb_context_x87(ctx));
        case HB_IR_X87_FPTAN:   return hb_x87_fptan(hb_context_x87(ctx));
        case HB_IR_X87_FPATAN:  return hb_x87_fpatan(hb_context_x87(ctx));
        case HB_IR_X87_FXTRACT: return hb_x87_fxtract(hb_context_x87(ctx));
        case HB_IR_X87_FPREM1:  return hb_x87_fprem1(hb_context_x87(ctx));
        case HB_IR_X87_FPREM:   return hb_x87_fprem(hb_context_x87(ctx));
        case HB_IR_X87_FYL2XP1: return hb_x87_fyl2xp1(hb_context_x87(ctx));
        case HB_IR_X87_FSINCOS: return hb_x87_fsincos(hb_context_x87(ctx));
        case HB_IR_X87_FSCALE:  return hb_x87_fscale(hb_context_x87(ctx));
        case HB_IR_X87_FSIN:    return hb_x87_fsin(hb_context_x87(ctx));
        case HB_IR_X87_FCOS:    return hb_x87_fcos(hb_context_x87(ctx));
        case HB_IR_X87_FNOP:    return hb_x87_fnop(hb_context_x87(ctx));
        case HB_IR_X87_FCHS:    return hb_x87_fchs(hb_context_x87(ctx));
        case HB_IR_X87_FABS:    return hb_x87_fabs(hb_context_x87(ctx));
        case HB_IR_X87_FTST:    return hb_x87_ftst(hb_context_x87(ctx));

        case HB_IR_PUSHA: {
            /* PUSHA / PUSHAD — push EAX/ECX/EDX/EBX/EBP/ESI/EDI then the original ESP.
             * Order: EAX, ECX, EDX, EBX, original ESP, EBP, ESI, EDI. */
            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            uint16_t word_size = (instr->src1.size == HB_SIZE_16) ? 2 : 4;
            uint32_t esp_save = ctx->regs.x86.esp;
            uint32_t values[8];
            values[0] = ctx->regs.x86.eax;
            values[1] = ctx->regs.x86.ecx;
            values[2] = ctx->regs.x86.edx;
            values[3] = ctx->regs.x86.ebx;
            values[4] = esp_save;
            values[5] = ctx->regs.x86.ebp;
            values[6] = ctx->regs.x86.esi;
            values[7] = ctx->regs.x86.edi;
            /* PUSHA pushes registers in the order EAX, ECX, EDX, EBX, original
             * ESP, EBP, ESI, EDI. With ESP pre-decrement, the first push lands
             * at the HIGHEST address of the 8-slot block and the last push lands
             * at the LOWEST. So loop from i=0 to i=7 (NOT 7→0). */
            for (int i = 0; i < 8; i++) {
                if (word_size == 2) {
                    ctx->regs.x86.esp -= 2;
                    r = hb_memory_write_u16(ctx->memory, ctx->regs.x86.esp, (uint16_t)values[i]);
                } else {
                    ctx->regs.x86.esp -= 4;
                    r = hb_memory_write_u32(ctx->memory, ctx->regs.x86.esp, values[i]);
                }
                if (r != HB_OK) return r;
            }
            return HB_OK;
        }

        case HB_IR_POPA: {
            /* POPA / POPAD — reverse of PUSHA: pop EDI, ESI, EBP, (skip), EBX, EDX, ECX, EAX. */
            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            uint16_t word_size = (instr->dst.size == HB_SIZE_16) ? 2 : 4;
            uint32_t values[8];
            for (int i = 0; i < 8; i++) {
                if (word_size == 2) {
                    uint16_t v16 = 0;
                    r = hb_memory_read_u16(ctx->memory, ctx->regs.x86.esp, &v16);
                    if (r != HB_OK) return r;
                    values[i] = v16;
                    ctx->regs.x86.esp += 2;
                } else {
                    r = hb_memory_read_u32(ctx->memory, ctx->regs.x86.esp, &values[i]);
                    if (r != HB_OK) return r;
                    ctx->regs.x86.esp += 4;
                }
            }
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 998 — POPAW ПИСАЛ 32 БИТА.
             * `66 61` (POPAW) заполняет ТОЛЬКО DI/SI/BP/BX/DX/CX/AX, старшая половина
             * каждого регистра сохраняется. Мы же присваивали весь 32-битный регистр
             * значением, расширенным нулём, и затирали верх. Поймано семантическим стендом
             * на случае `dbe3d9e8d9ebd9ea656661`: ожидалось `eax=0x7000c48b`, вышло
             * `0xf51e2e89` — расходились eax, ebx и ecx. */
            if (word_size == 2) {
#define HB_POPA_W(reg, val) \
                ctx->regs.x86.reg = (ctx->regs.x86.reg & 0xffff0000u) | ((val) & 0xffffu)
                HB_POPA_W(edi, values[0]);
                HB_POPA_W(esi, values[1]);
                HB_POPA_W(ebp, values[2]);
                /* values[3] — снятое и отбрасываемое значение ESP. */
                HB_POPA_W(ebx, values[4]);
                HB_POPA_W(edx, values[5]);
                HB_POPA_W(ecx, values[6]);
                HB_POPA_W(eax, values[7]);
#undef HB_POPA_W
                return HB_OK;
            }
            ctx->regs.x86.edi = values[0];
            ctx->regs.x86.esi = values[1];
            ctx->regs.x86.ebp = values[2];
            /* values[3] is the discarded ESP value. */
            ctx->regs.x86.ebx = values[4];
            ctx->regs.x86.edx = values[5];
            ctx->regs.x86.ecx = values[6];
            ctx->regs.x86.eax = values[7];
            return HB_OK;
        }

        case HB_IR_AAA: {
            /* AAA — ASCII Adjust After Addition. Modifies AL/AH and AF/CF. */
            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            uint8_t al = (uint8_t)ctx->regs.x86.eax;
            bool a = ((al & 0x0fu) > 9) || ctx->flags.af;
            if (a) {
                ctx->regs.x86.eax = (ctx->regs.x86.eax & 0xffffff00u) | ((al + 6) & 0x0fu);
                ctx->regs.x86.eax = (ctx->regs.x86.eax & 0xffff00ffu) | (((ctx->regs.x86.eax >> 8) + 1) << 8);
            } else {
                ctx->regs.x86.eax = (ctx->regs.x86.eax & 0xffffff00u) | (al & 0x0fu);
            }
            ctx->flags.af = a;
            ctx->flags.cf = a;
            return HB_OK;
        }

        case HB_IR_AAS: {
            /* AAS — ASCII Adjust After Subtraction (Intel SDM Vol.2A):
             *   IF (AL AND 0Fh) > 9 OR AF:  AX -= 6; AH -= 1; AF=CF=1
             *   ELSE                         AF=CF=0
             *   AL := AL AND 0Fh
             * NOTE: Unicorn 2.1.4 diverges (decrements AH by 2). We follow the
             * SDM = real-silicon contract; AAS is EXCLUDED from the Unicorn diff
             * (see HB-I386-DECODE-COMPLETE report, "Oracle Divergences"). */
            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            uint8_t al = (uint8_t)ctx->regs.x86.eax;
            bool a = ((al & 0x0fu) > 9) || ctx->flags.af;
            if (a) {
                uint16_t ax = (uint16_t)((ctx->regs.x86.eax & 0xffffu) - 6u); /* AX -= 6 (borrow into AH) */
                uint8_t ah = (uint8_t)((ax >> 8) - 1u);                       /* AH -= 1 */
                uint8_t new_al = (uint8_t)(ax & 0x0fu);                       /* AL := AL AND 0Fh */
                ctx->regs.x86.eax = (ctx->regs.x86.eax & 0xffff0000u) | ((uint32_t)ah << 8) | new_al;
            } else {
                ctx->regs.x86.eax = (ctx->regs.x86.eax & 0xffffff00u) | (al & 0x0fu);
            }
            ctx->flags.af = a;
            ctx->flags.cf = a;
            return HB_OK;
        }

        case HB_IR_AAM: {
            /* AAM — ASCII Adjust After Multiply. AL = AL % imm8; AH = AL / imm8. */
            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            uint8_t base = (uint8_t)instr->src1.imm;
            if (base == 0) return HB_ERR_EXEC_FAULT;  /* #DE on divide by zero */
            uint8_t al = (uint8_t)ctx->regs.x86.eax;
            uint8_t ah = (uint8_t)((al / base) & 0xffu);
            uint8_t new_al = (uint8_t)(al % base);
            ctx->regs.x86.eax = (ctx->regs.x86.eax & 0xffffff00u) | new_al;
            ctx->regs.x86.eax = (ctx->regs.x86.eax & 0xffff00ffu) | ((uint32_t)ah << 8);
            /* SF/ZF/PF are set based on the new AL. */
            ctx->flags.sf = (new_al & 0x80u) != 0;
            ctx->flags.zf = new_al == 0;
            ctx->flags.pf = parity_even_u8(new_al);
            ctx->flags.cf = false;
            ctx->flags.of = false;
            ctx->flags.af = false;
            return HB_OK;
        }

        case HB_IR_AAD: {
            /* AAD — ASCII Adjust Before Division. AL = (AH * imm8 + AL) & 0xff; AH = 0. */
            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            uint8_t base = (uint8_t)instr->src1.imm;
            uint8_t al = (uint8_t)ctx->regs.x86.eax;
            uint8_t ah = (uint8_t)(ctx->regs.x86.eax >> 8);
            uint8_t new_al = (uint8_t)((ah * base + al) & 0xffu);
            ctx->regs.x86.eax = (ctx->regs.x86.eax & 0xffffff00u) | new_al;
            ctx->regs.x86.eax = (ctx->regs.x86.eax & 0xffff00ffu);
            ctx->flags.sf = (new_al & 0x80u) != 0;
            ctx->flags.zf = new_al == 0;
            ctx->flags.pf = parity_even_u8(new_al);
            ctx->flags.cf = false;
            ctx->flags.of = false;
            ctx->flags.af = false;
            return HB_OK;
        }

        case HB_IR_DAA: {
            /* DAA — Decimal Adjust AL After Addition. */
            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            uint8_t al = (uint8_t)ctx->regs.x86.eax;
            bool cf_old = ctx->flags.cf;
            bool old_cf = cf_old;
            bool old_af = ctx->flags.af;
            if (((al & 0x0fu) > 9) || old_af) {
                ctx->regs.x86.eax = (ctx->regs.x86.eax & 0xffffff00u) | ((al + 6) & 0xffu);
                ctx->flags.cf = old_cf || (al > 0xf9u);
                ctx->flags.af = true;
            } else {
                ctx->flags.af = false;
            }
            uint8_t al_after = (uint8_t)ctx->regs.x86.eax;
            if ((al_after > 0x99u) || old_cf) {
                ctx->regs.x86.eax = (ctx->regs.x86.eax & 0xffffff00u) | ((al_after + 0x60u) & 0xffu);
                ctx->flags.cf = true;
            } else {
                ctx->flags.cf = false;
            }
            uint8_t new_al = (uint8_t)ctx->regs.x86.eax;
            ctx->flags.sf = (new_al & 0x80u) != 0;
            ctx->flags.zf = new_al == 0;
            ctx->flags.pf = parity_even_u8(new_al);
            ctx->flags.of = false;
            return HB_OK;
        }

        case HB_IR_DAS: {
            /* DAS — Decimal Adjust AL After Subtraction (Intel SDM Vol.2A).
             * Second-adjust condition: IF (old_AL > 99h) OR (old_CF) THEN AL -= 60h.
             * NOTE: Unicorn 2.1.4 drops the old_AL>99h clause (gates on CF only);
             * we follow the SDM = real-silicon contract; DAS is EXCLUDED from the
             * Unicorn diff (see HB-I386-DECODE-COMPLETE report, "Oracle Divergences"). */
            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            uint8_t al = (uint8_t)ctx->regs.x86.eax;
            bool old_cf = ctx->flags.cf;
            bool old_af = ctx->flags.af;
            if (((al & 0x0fu) > 9) || old_af) {
                uint8_t new_al = (uint8_t)(al - 6);
                ctx->regs.x86.eax = (ctx->regs.x86.eax & 0xffffff00u) | new_al;
                ctx->flags.cf = old_cf || (al < 6);
                ctx->flags.af = true;
            } else {
                ctx->flags.af = false;
            }
            /* Second adjust (SDM): gate on old_AL > 99h OR old_CF. */
            if (al > 0x99u || old_cf) {
                uint8_t al_after = (uint8_t)ctx->regs.x86.eax;
                uint8_t newer_al = (uint8_t)(al_after - 0x60u);
                ctx->regs.x86.eax = (ctx->regs.x86.eax & 0xffffff00u) | newer_al;
                ctx->flags.cf = true;
            }
            uint8_t new_al = (uint8_t)ctx->regs.x86.eax;
            ctx->flags.sf = (new_al & 0x80u) != 0;
            ctx->flags.zf = new_al == 0;
            ctx->flags.pf = parity_even_u8(new_al);
            ctx->flags.of = false;
            return HB_OK;
        }

        case HB_IR_BOUND: {
            /* BOUND r16/32, m16/32&16/32 — array bounds check. Out-of-range → #BR.
             * dst = register, src1 = mBOUND (low, high pair). For the flat-memory
             * games HyperBridge targets this rarely trips; we surface the trap. */
            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            uint64_t idx = 0;
            r = read_operand_value(ctx, &instr->dst, &idx);
            if (r != HB_OK) return r;
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            uint64_t addr = resolve_addr(ctx, &instr->src1);
            hb_size_t elem = (instr->dst.size == HB_SIZE_16) ? HB_SIZE_16 : HB_SIZE_32;
            uint64_t lo = 0, hi = 0;
            r = mem_read(ctx, addr, &lo, elem);
            if (r != HB_OK) return r;
            r = mem_read(ctx, addr + hb_size_bytes(elem), &hi, elem);
            if (r != HB_OK) return r;
            uint64_t ix = (elem == HB_SIZE_16) ? (idx & 0xffffu) : (idx & 0xffffffffu);
            uint64_t l = (elem == HB_SIZE_16) ? (uint16_t)lo : (uint32_t)lo;
            uint64_t h = (elem == HB_SIZE_16) ? (uint16_t)hi : (uint32_t)hi;
            /* Intel: out-of-range if index < low OR index > high (both signed). */
            int64_t s_ix = (elem == HB_SIZE_16) ? (int16_t)ix : (int32_t)ix;
            int64_t s_lo = (elem == HB_SIZE_16) ? (int16_t)l : (int32_t)l;
            int64_t s_hi = (elem == HB_SIZE_16) ? (int16_t)h : (int32_t)h;
            if (s_ix < s_lo || s_ix > s_hi) {
                return HB_ERR_EXEC_FAULT;  /* #BR equivalent. */
            }
            return HB_OK;
        }

        case HB_IR_ARPL: {
            /* ARPL r/m16, r16 — Adjust RPL Field of Selector.
             * If dst.RPL < src.RPL: ZF=1, dst.RPL = src.RPL. Else ZF=0. */
            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            uint16_t dst = 0, src = 0;
            if (instr->src1.type == HB_OP_REG) src = (uint16_t)read_reg_sized(ctx, instr->src1.reg, HB_SIZE_16, 0);
            else if (instr->src1.type == HB_OP_IMM) src = (uint16_t)instr->src1.imm;
            else if (instr->src1.type == HB_OP_MEM) {
                uint64_t addr = resolve_addr(ctx, &instr->src1);
                r = hb_memory_read_u16(ctx->memory, addr, &src);
                if (r != HB_OK) return r;
            } else return HB_ERR_INTERNAL;
            if (instr->dst.type == HB_OP_REG) dst = (uint16_t)read_reg_sized(ctx, instr->dst.reg, HB_SIZE_16, 0);
            else if (instr->dst.type == HB_OP_MEM) {
                uint64_t addr = resolve_addr(ctx, &instr->dst);
                r = hb_memory_read_u16(ctx->memory, addr, &dst);
                if (r != HB_OK) return r;
            } else return HB_ERR_INTERNAL;
            uint8_t dpl = dst & 0x3;
            uint8_t rpl = src & 0x3;
            if (rpl > dpl) {
                uint16_t nd = (dst & ~0x3u) | rpl;
                if (instr->dst.type == HB_OP_REG) write_reg_sized(ctx, instr->dst.reg, nd, HB_SIZE_16);
                else if (instr->dst.type == HB_OP_MEM) {
                    uint64_t addr = resolve_addr(ctx, &instr->dst);
                    r = hb_memory_write_u16(ctx->memory, addr, nd);
                    if (r != HB_OK) return r;
                }
                ctx->flags.zf = true;
            } else {
                ctx->flags.zf = false;
            }
            return HB_OK;
        }

        case HB_IR_LDS:
        case HB_IR_LES:
        case HB_IR_LFS:
        case HB_IR_LGS: {
            /* Far pointer load: dst GPR = m32 offset, segment = m16 selector.
             * Memory operand is m48 (4 bytes offset + 2 bytes selector) OR m32 (FS/GS
             * ignore the high half in some encodings — but standard encoding is the
             * same 6-byte form). */
            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            if (instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            uint64_t addr = resolve_addr(ctx, &instr->src1);
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 926 — ШИРИНА ПРИЁМНИКА.
             * Под префиксом `66` форма 16-битная: смещение ДВА байта, селектор идёт следом за
             * ними, и в регистр пишутся только младшие 16 бит. Писали всегда 32, из-за чего
             * `66c40424 les ax,[esp]` затирал весь `eax` (0x5ad35e00 вместо 0x70005e00) и
             * читал селектор не с того места. Размер приходит из декодера (правка той же
             * итерации: у приёмника 4 или 2, у памяти 6). */
            bool narrow = instr->dst.size == HB_SIZE_16;
            uint32_t off = 0;
            uint16_t sel = 0;
            if (narrow) {
                uint16_t off16 = 0;
                r = hb_memory_read_u16(ctx->memory, addr, &off16);
                if (r != HB_OK) return r;
                off = off16;
                r = hb_memory_read_u16(ctx->memory, addr + 2, &sel);
            } else {
                r = hb_memory_read_u32(ctx->memory, addr, &off);
                if (r != HB_OK) return r;
                r = hb_memory_read_u16(ctx->memory, addr + 4, &sel);
            }
            if (r != HB_OK) return r;
            if (instr->dst.type == HB_OP_REG)
                write_reg_sized(ctx, instr->dst.reg, off, narrow ? HB_SIZE_16 : HB_SIZE_32);
            else return HB_ERR_INTERNAL;
            /* Set the corresponding segment selector. For LDS/LES the visible seg is
             * updated; for LFS/LGS we also update the segment base (flat-model assumes
             * base 0; we just propagate the selector and let the rest of the translator
             * continue with selector-based addressing). */
            uint16_t which;
            switch (instr->op) {
                case HB_IR_LDS: which = 3; break;  /* DS = 3 */
                case HB_IR_LES: which = 0; break;  /* ES = 0 */
                case HB_IR_LFS: which = 4; break;  /* FS = 4 */
                case HB_IR_LGS: which = 5; break;  /* GS = 5 */
                default: return HB_ERR_INTERNAL;
            }
            r = write_seg_selector(ctx, which, sel);
            if (r != HB_OK) return r;
            if (instr->op == HB_IR_LFS) ctx->fs_base = 0;
            if (instr->op == HB_IR_LGS) ctx->gs_base = 0;
            return HB_OK;
        }

        case HB_IR_PUSHF: {
            hb_size_t size = instr->src1.size ? instr->src1.size : HB_SIZE_32;
            uint64_t value = 0;
            uint64_t rsp_before = ctx->mode == HB_MODE_32BIT ? ctx->regs.x86.esp : ctx->regs.x64.rsp;
            r = read_flags_image(ctx, size, &value);
            if (r != HB_OK) return r;
            if (ctx->mode == HB_MODE_32BIT) {
                if (size == HB_SIZE_16) {
                    ctx->regs.x86.esp -= 2;
                    r = hb_memory_write_u16(ctx->memory, ctx->regs.x86.esp, (uint16_t)value);
                } else {
                    ctx->regs.x86.esp -= 4;
                    r = hb_memory_write_u32(ctx->memory, ctx->regs.x86.esp, (uint32_t)value);
                }
            } else {
                ctx->regs.x64.rsp -= 8;
                r = hb_memory_write_u64(ctx->memory, ctx->regs.x64.rsp, value);
            }
            if (r != HB_OK) {
                /* 05.09.2026: отказ записи НЕ меняет архитектурного состояния — как у
                 * настоящего процессора. Интерпретатор теперь эталон точности состояния на
                 * отказавшей команде (проба jit_fault_state_precision), и уехавший rsp
                 * читался бы гостевым обработчиком как своё состояние. */
                if (ctx->mode == HB_MODE_32BIT) ctx->regs.x86.esp = (uint32_t)rsp_before;
                else ctx->regs.x64.rsp = rsp_before;
                return r;
            }
            if (ctx->mode == HB_MODE_64BIT)
                trace_branch_event(ctx, instr, "pushf", rsp_before, value, 0);
            return HB_OK;
        }

        case HB_IR_POPF: {
            hb_size_t size = instr->src1.size ? instr->src1.size : HB_SIZE_32;
            uint64_t value = 0;
            uint64_t rsp_before = ctx->mode == HB_MODE_32BIT ? ctx->regs.x86.esp : ctx->regs.x64.rsp;
            if (ctx->mode == HB_MODE_32BIT) {
                if (size == HB_SIZE_16) {
                    uint16_t v16 = 0;
                    r = hb_memory_read_u16(ctx->memory, ctx->regs.x86.esp, &v16);
                    if (r != HB_OK) return r;
                    value = v16;
                    ctx->regs.x86.esp += 2;
                } else {
                    uint32_t v32 = 0;
                    r = hb_memory_read_u32(ctx->memory, ctx->regs.x86.esp, &v32);
                    if (r != HB_OK) return r;
                    value = v32;
                    ctx->regs.x86.esp += 4;
                }
            } else {
                r = hb_memory_read_u64(ctx->memory, ctx->regs.x64.rsp, &value);
                if (r != HB_OK) return r;
                ctx->regs.x64.rsp += 8;
            }
            r = write_flags_image(ctx, size, value);
            if (r != HB_OK) return r;
            if (ctx->mode == HB_MODE_64BIT)
                trace_branch_event(ctx, instr, "popf", rsp_before, value, value);
            return HB_OK;
        }

        case HB_IR_CLC: ctx->flags.cf = 0; return HB_OK;
        case HB_IR_STC: ctx->flags.cf = 1; return HB_OK;
        case HB_IR_XTEST:
            /* 05.09.2026 — «внутри ли транзакции». Транзакции всегда отменяются на XBEGIN
             * (hb_lift_sist_obshchee.inc), значит ответ один: ZF <- 1, CF/OF/SF/PF/AF <- 0
             * (SDM, XTEST). Ленивую запись гасим ЦЕЛИКОМ — команда переписывает все шесть
             * флагов, терять нечего; без сброса кодогенератор, зовущий этот случай через
             * помощника, материализовал бы висящую арифметику ПОВЕРХ нашего ответа. */
            hb_lazy_flags_clear(ctx);
            ctx->flags.zf = 1;
            ctx->flags.cf = 0;
            ctx->flags.of = 0;
            ctx->flags.sf = 0;
            ctx->flags.pf = 0;
            ctx->flags.af = 0;
            return HB_OK;
        case HB_IR_CMC: ctx->flags.cf = !ctx->flags.cf; return HB_OK;
        case HB_IR_CLD: {
            /* Clear DF (bit 10 of EFLAGS). */
            if (ctx->mode == HB_MODE_32BIT) ctx->regs.x86.eflags &= ~(1u << 10);
            else ctx->regs.x64.rflags &= ~(1ULL << 10);
            return HB_OK;
        }
        case HB_IR_STD: {
            if (ctx->mode == HB_MODE_32BIT) ctx->regs.x86.eflags |= (1u << 10);
            else ctx->regs.x64.rflags |= (1ULL << 10);
            return HB_OK;
        }
        /* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 466 — CLI/STI ВЕДУТ БИТ IF.
         *
         * Было «HyperBridge runs with IF=1; ignore» — и стенд ловил это как расхождение:
         * после `cli` эталон даёт `rflags` без 0x200, мы — с ним. Приказ владельца (пункт 97):
         * наблюдаемое поведение приводить к эталону, а не объявлять вне области.
         *
         * Исполнить запрет прерываний мы не можем и не должны — но ОТРАЖАТЬ его в образе
         * флагов обязаны: игры читают `eflags` через PUSHF и сравнивают. Бит 9 живёт в
         * сохранённом `eflags`/`rflags` (см. read_flags_image), туда и пишем. */
        case HB_IR_CLI:
            if (ctx->mode == HB_MODE_32BIT) ctx->regs.x86.eflags &= ~(uint32_t)0x200u;
            else                            ctx->regs.x64.rflags &= ~(uint64_t)0x200u;
            return HB_OK;
        case HB_IR_STI:
            if (ctx->mode == HB_MODE_32BIT) ctx->regs.x86.eflags |= (uint32_t)0x200u;
            else                            ctx->regs.x64.rflags |= (uint64_t)0x200u;
            return HB_OK;

        case HB_IR_PUSH_SEG: {
            /* src1.size = размер элемента, src2.imm = номер сегмента.
             * MacRunner 2026-08-16, итерация 1096: раньше здесь стоял отказ для 64-битного
             * режима, и `push fs` (`0F A0`) на x64 падал «опкод не поддержан» — это и был
             * открытый пункт доски про сегментное состояние. На x64 селекторы лежат в
             * `ctx->seg_*`, а на стек кладётся 8 байт (селектор расширяется нулями). */
            uint16_t seg = (uint16_t)instr->src2.imm;
            if (ctx->mode != HB_MODE_32BIT) {
                static const int seg_is_fs = 4;   /* порядок как у i386: ES,CS,SS,DS,FS,GS */
                uint16_t sel64 = (seg == (uint16_t)seg_is_fs) ? ctx->seg_fs
                               : (seg == 5) ? ctx->seg_gs
                               : (seg == 0) ? ctx->seg_es
                               : (seg == 1) ? ctx->seg_cs
                               : (seg == 2) ? ctx->seg_ss : ctx->seg_ds;
                /* ★ ПРЕФИКС 0x66 СЖИМАЕТ ТОЛЧОК ДО ДВУХ БАЙТОВ И В ДЛИННОМ РЕЖИМЕ.
                 * Ширина зашивалась восьмёркой; замерено оракулом на `66 0f a0`
                 * (`push fs`): rsp уменьшился на 2, у нас на 8, и образ стека
                 * расходился вместе с ним. */
                if (instr->src1.size == HB_SIZE_16) {
                    ctx->regs.x64.rsp -= 2;
                    return hb_memory_write_u16(ctx->memory, ctx->regs.x64.rsp, sel64);
                }
                ctx->regs.x64.rsp -= 8;
                return hb_memory_write_u64(ctx->memory, ctx->regs.x64.rsp, (uint64_t)sel64);
            }
            uint16_t selector = ctx->regs.x86.seg[seg] & 0xFFFFu;
            uint8_t size = (uint8_t)(instr->src1.size ? instr->src1.size : 4);
            if (size == 2) {
                ctx->regs.x86.esp -= 2;
                r = hb_memory_write_u16(ctx->memory, ctx->regs.x86.esp, selector);
            } else {
                ctx->regs.x86.esp -= 4;
                r = hb_memory_write_u32(ctx->memory, ctx->regs.x86.esp, (uint32_t)selector);
            }
            return r;
        }

        case HB_IR_POP_SEG: {
            /* i386-only: POP ES/SS/DS (32-bit user mode). */
            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            uint16_t seg = (uint16_t)instr->src2.imm;
            uint8_t size = (uint8_t)(instr->dst.size ? instr->dst.size : 4);
            uint32_t value = 0;
            if (size == 2) {
                uint16_t v16 = 0;
                r = hb_memory_read_u16(ctx->memory, ctx->regs.x86.esp, &v16);
                if (r != HB_OK) return r;
                value = v16;
                ctx->regs.x86.esp += 2;
            } else {
                r = hb_memory_read_u32(ctx->memory, ctx->regs.x86.esp, &value);
                if (r != HB_OK) return r;
                ctx->regs.x86.esp += 4;
            }
            ctx->regs.x86.seg[seg] = value & 0xFFFFu;
            return HB_OK;
        }

        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — ДАЛЬНИЕ ПЕРЕХОДЫ.
         *
         * Четыре формы одним обработчиком; `target`: бит0 — вызов, бит1 — операнды
         * лежат в памяти. Порядок в памяти и в непосредственном одинаков: сперва
         * смещение (4 байта), затем селектор (2).
         *
         * Вызов кладёт на стек ПАРУ — селектор и адрес возврата, — чтобы парный
         * `RETF` (он здесь же, ниже) снял ровно то, что положили: сначала CS,
         * потом EIP. В плоской модели переход по смещению не зависит от селектора,
         * но CS обязаны записать: гость его читает. */
        case HB_IR_FAR_BRANCH: {
            bool вызов   = (instr->target & 1u) != 0;
            bool из_пам  = (instr->target & 2u) != 0;
            uint32_t смещение = 0;
            uint16_t селектор = 0;

            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            if (из_пам) {
                uint64_t адрес = resolve_addr(ctx, &instr->src1);
                r = hb_memory_read_u32(ctx->memory, (hb_gva_t)адрес, &смещение);
                if (r != HB_OK) return r;
                r = hb_memory_read_u16(ctx->memory, (hb_gva_t)(адрес + 4), &селектор);
                if (r != HB_OK) return r;
            } else {
                смещение = (uint32_t)instr->src1.imm;
                селектор = (uint16_t)instr->src2.imm;
            }

            if (вызов) {
                uint32_t возврат = (uint32_t)(instr->guest_addr + instr->guest_len);
                uint16_t текущий_cs = ctx->regs.x86.seg[1];
                ctx->regs.x86.esp -= 4;
                r = hb_memory_write_u32(ctx->memory, ctx->regs.x86.esp, текущий_cs);
                if (r != HB_OK) return r;
                ctx->regs.x86.esp -= 4;
                r = hb_memory_write_u32(ctx->memory, ctx->regs.x86.esp, возврат);
                if (r != HB_OK) return r;
            }
            ctx->regs.x86.seg[1] = селектор;
            ctx->pc = смещение;
            sync_arch_pc(ctx);
            return HB_OK;
        }

        case HB_IR_RETF: {
            /* Far return. src1.imm = stack-adjust after pop (CA form has it, CB form is 0). */
            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            int adjust = (int)instr->src1.imm;
            uint32_t eip = 0, eflags = 0;
            uint16_t cs = 0;
            r = hb_memory_read_u32(ctx->memory, ctx->regs.x86.esp, &eip);
            if (r != HB_OK) return r;
            r = hb_memory_read_u16(ctx->memory, ctx->regs.x86.esp + 4, &cs);
            if (r != HB_OK) return r;
            r = hb_memory_read_u32(ctx->memory, ctx->regs.x86.esp + 6, &eflags);
            if (r != HB_OK) return r;
            ctx->regs.x86.esp += 12;
            ctx->regs.x86.eip = eip;
            ctx->regs.x86.seg[1] = cs;
            r = write_flags_image(ctx, HB_SIZE_32, eflags);
            if (r != HB_OK) return r;
            if (adjust) ctx->regs.x86.esp += (uint32_t)adjust;
            return HB_OK;
        }

        case HB_IR_IRET: {
            /* Interrupt return. src1.size = 16 (IRET) or 32 (IRETD). */
            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            uint8_t size = (uint8_t)(instr->src1.size ? instr->src1.size : 4);
            if (size == 2) {
                uint16_t ip = 0, cs = 0, fl = 0;
                r = hb_memory_read_u16(ctx->memory, ctx->regs.x86.esp, &ip);
                if (r != HB_OK) return r;
                r = hb_memory_read_u16(ctx->memory, ctx->regs.x86.esp + 2, &cs);
                if (r != HB_OK) return r;
                r = hb_memory_read_u16(ctx->memory, ctx->regs.x86.esp + 4, &fl);
                if (r != HB_OK) return r;
                ctx->regs.x86.esp += 6;
                ctx->regs.x86.eip = ip;
                ctx->regs.x86.seg[1] = cs;
                r = write_flags_image(ctx, HB_SIZE_16, fl);
            } else {
                uint32_t eip = 0, eflags = 0;
                uint16_t cs = 0;
                r = hb_memory_read_u32(ctx->memory, ctx->regs.x86.esp, &eip);
                if (r != HB_OK) return r;
                r = hb_memory_read_u16(ctx->memory, ctx->regs.x86.esp + 4, &cs);
                if (r != HB_OK) return r;
                r = hb_memory_read_u32(ctx->memory, ctx->regs.x86.esp + 6, &eflags);
                if (r != HB_OK) return r;
                ctx->regs.x86.esp += 12;
                ctx->regs.x86.eip = eip;
                ctx->regs.x86.seg[1] = cs;
                r = write_flags_image(ctx, HB_SIZE_32, eflags);
            }
            return r;
        }

        case HB_IR_INT3:
            /* Breakpoint. HyperBridge doesn't trap; treated as NOP. */
            return HB_OK;

        case HB_IR_INT1:
            return HB_OK;

        case HB_IR_INT: {
            /* INT n. HyperBridge doesn't dispatch to a real IDT; fault so the
             * user knows the guest used INT n. */
            (void)instr;
            return HB_ERR_UNSUPPORTED_OPCODE;
        }

        case HB_IR_INTO:
            /* Trap if OF=1. HyperBridge has no #OF trap, so we just NOP. */
            (void)instr;
            return HB_OK;

        case HB_IR_XLAT: {
            /* XLATB: AL = [EBX+AL] (or [BX+AL] with 0x67). */
            if (ctx->mode != HB_MODE_32BIT) return HB_ERR_UNSUPPORTED_OPCODE;
            uint8_t al = (uint8_t)ctx->regs.x86.eax;
            uint32_t base = (uint32_t)ctx->regs.x86.ebx;
            uint32_t addr = base + al;
            uint8_t v = 0;
            r = hb_memory_read_u8(ctx->memory, addr, &v);
            if (r != HB_OK) return r;
            ctx->regs.x86.eax = (ctx->regs.x86.eax & 0xFFFFFF00u) | v;
            return HB_OK;
        }

        case HB_IR_ENTER: {
            /* ENTER frame_size, nesting — push EBP, allocate locals. */
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 929 — ФОРМА ДЛЯ x86-64.
             * Здесь стоял отказ `mode != 32BIT`, то есть в 64-битном режиме команда не
             * исполнялась вовсе (`c8c07f6e` давал -5), хотя она в наборе есть и размер
             * операнда там по умолчанию 64 бита: толчки восьмибайтовые, кадр строится на
             * RBP/RSP. Разбор ниже общий для обеих ветвей, различаются только ширина слота
             * и регистры. Обе поправки 925 (остаток по модулю 32 и отсутствие лишнего
             * толчка при нулевой вложенности) действуют и здесь — код один. */
            uint16_t frame_size = (uint16_t)instr->src1.imm;
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 925 — ДВА ОТСТУПЛЕНИЯ ОТ
             * СПЕЦИФИКАЦИИ, оба доказаны замером против эталона.
             *
             * 1. Уровень вложенности берётся ПО МОДУЛЮ 32 (`NestingLevel = imm8 MOD 32`).
             *    Замер: `c81000ff enter 0x10,255` — эталон esp=0x71000f70, мы 0x71000bf0,
             *    то есть протолкнули 255 указателей вместо 31.
             * 2. При НУЛЕВОЙ вложенности указатель кадра на стек НЕ кладётся вовсе. У нас
             *    стояла ветвь `else`, которая его клала. Замер на самой ходовой форме,
             *    которую и выпускают компиляторы:
             *      `c8100000 enter 0x10,0`  эталон esp=0x71000fec, мы 0x71000fe8
             *    — четыре лишних байта, и весь кадр съезжает. Формы с вложенностью 1 и 2
             *    сходились, поэтому дефект и не бросался в глаза. */
            uint8_t nesting = (uint8_t)(instr->src2.imm & 31);
            bool wide = ctx->mode != HB_MODE_32BIT;
            unsigned slot = wide ? 8u : 4u;
            uint64_t bp = wide ? ctx->regs.x64.rbp : ctx->regs.x86.ebp;
            uint64_t sp = wide ? ctx->regs.x64.rsp : ctx->regs.x86.esp;
            /* Push BP. */
            sp -= slot;
            r = wide ? hb_memory_write_u64(ctx->memory, sp, bp)
                     : hb_memory_write_u32(ctx->memory, sp, (uint32_t)bp);
            if (r != HB_OK) return r;
            uint64_t frame_bp = sp;
            if (nesting > 0) {
                for (uint8_t i = 1; i < nesting; i++) {
                    uint64_t tmp = 0;
                    bp -= slot;
                    if (wide) {
                        r = hb_memory_read_u64(ctx->memory, bp, &tmp);
                    } else {
                        uint32_t t32 = 0;
                        r = hb_memory_read_u32(ctx->memory, bp, &t32);
                        tmp = t32;
                    }
                    if (r != HB_OK) return r;
                    sp -= slot;
                    r = wide ? hb_memory_write_u64(ctx->memory, sp, tmp)
                             : hb_memory_write_u32(ctx->memory, sp, (uint32_t)tmp);
                    if (r != HB_OK) return r;
                }
                /* push frame_bp — ТОЛЬКО при ненулевой вложенности (см. разбор в 925). */
                sp -= slot;
                r = wide ? hb_memory_write_u64(ctx->memory, sp, frame_bp)
                         : hb_memory_write_u32(ctx->memory, sp, (uint32_t)frame_bp);
                if (r != HB_OK) return r;
            }
            sp -= frame_size;
            if (wide) { ctx->regs.x64.rbp = frame_bp; ctx->regs.x64.rsp = sp; }
            else { ctx->regs.x86.ebp = (uint32_t)frame_bp; ctx->regs.x86.esp = (uint32_t)sp; }
            return HB_OK;
        }

        case HB_IR_PUSH: {
            uint64_t val = 0;
            uint64_t rsp_before = ctx->mode == HB_MODE_32BIT ? ctx->regs.x86.esp : ctx->regs.x64.rsp;
            r = read_operand_value(ctx, &instr->src1, &val);
            if (r != HB_OK) return r;
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 910 — PUSH r16 КЛАЛ ЛИШНЕЕ.
             * Размер операнда не спрашивался: в 32 битах всегда 4 байта, в 64 всегда 8.
             * Замер против эталона: `6651 push cx` на x86-32 — esp обязан уйти на 2
             * (0x71000ffe), уходил на 4 (0x71000ffc), и содержимое стека расходилось;
             * `6650 push ax` на x64 — на 2, уходил на 8. POP шестнадцать бит умел ТОЛЬКО
             * в 32-битном режиме (ниже), поэтому пара была несимметрична. */
            if (instr->src1.size == HB_SIZE_16) {
                if (ctx->mode == HB_MODE_32BIT) {
                    ctx->regs.x86.esp -= 2;
                    r = hb_memory_write_u16(ctx->memory, ctx->regs.x86.esp, (uint16_t)val);
                } else {
                    ctx->regs.x64.rsp -= 2;
                    r = hb_memory_write_u16(ctx->memory, ctx->regs.x64.rsp, (uint16_t)val);
                }
            } else if (ctx->mode == HB_MODE_32BIT) {
                ctx->regs.x86.esp -= 4;
                r = hb_memory_write_u32(ctx->memory, ctx->regs.x86.esp, (uint32_t)val);
            } else {
                ctx->regs.x64.rsp -= 8;
                r = hb_memory_write_u64(ctx->memory, ctx->regs.x64.rsp, val);
            }
            if (r != HB_OK) {
                /* 05.09.2026: отказ записи НЕ двигает указатель стека — см. PUSHF. */
                if (ctx->mode == HB_MODE_32BIT) ctx->regs.x86.esp = (uint32_t)rsp_before;
                else ctx->regs.x64.rsp = rsp_before;
                return r;
            }
            if (ctx->mode == HB_MODE_64BIT)
                trace_branch_event(ctx, instr, "push", rsp_before, val, 0);
            return HB_OK;
        }

        case HB_IR_POP: {
            uint64_t val = 0;
            uint64_t rsp_before = ctx->mode == HB_MODE_32BIT ? ctx->regs.x86.esp : ctx->regs.x64.rsp;
            if (ctx->mode == HB_MODE_32BIT) {
                if (instr->dst.size == HB_SIZE_16) {
                    uint16_t v16 = 0;
                    r = hb_memory_read_u16(ctx->memory, ctx->regs.x86.esp, &v16);
                    if (r != HB_OK) return r;
                    val = v16;
                    ctx->regs.x86.esp += 2;
                } else {
                    r = hb_memory_read_u32(ctx->memory, ctx->regs.x86.esp, (uint32_t*)&val);
                    if (r != HB_OK) return r;
                    ctx->regs.x86.esp += 4;
                }
            } else if (instr->dst.size == HB_SIZE_16) {
                /* Итерация 910: 16-битная форма в 64-битном режиме — её здесь не было,
                 * из-за чего `6658 pop ax` снимал со стека восемь байт и затирал весь rax. */
                uint16_t v16 = 0;
                r = hb_memory_read_u16(ctx->memory, ctx->regs.x64.rsp, &v16);
                if (r != HB_OK) return r;
                val = v16;
                ctx->regs.x64.rsp += 2;
            } else {
                r = hb_memory_read_u64(ctx->memory, ctx->regs.x64.rsp, &val);
                if (r != HB_OK) return r;
                ctx->regs.x64.rsp += 8;
            }
            if (instr->dst.type == HB_OP_REG) {
                write_reg_sized(ctx, instr->dst.reg, val, instr->dst.size);
            } else if (instr->dst.type == HB_OP_MEM) {
                uint64_t addr = resolve_addr(ctx, &instr->dst);
                r = mem_write(ctx, addr, val, instr->dst.size);
                if (r != HB_OK) return r;
            } else {
                return HB_ERR_INTERNAL;
            }
            if (ctx->mode == HB_MODE_64BIT)
                trace_branch_event(ctx, instr, "pop", rsp_before, val, val);
            return HB_OK;
        }

        case HB_IR_CALL: {
            uint64_t ret_addr = instr->guest_addr + instr->guest_len;
            uint64_t target = instr->target;
            uint64_t rsp_before = ctx->mode == HB_MODE_32BIT ? ctx->regs.x86.esp : ctx->regs.x64.rsp;
            if (instr->src1.type != HB_OP_NONE) {
                r = read_operand_value(ctx, &instr->src1, &target);
                if (r != HB_OK) return r;
            }
            if (!target) {
                fprintf(stderr, "macrunner-hb-null-branch: op=CALL addr=0x%llx len=%u src_type=%d base=%d index=%d scale=%u disp=0x%llx size=%d\n",
                        (unsigned long long)instr->guest_addr, instr->guest_len, instr->src1.type,
                        instr->src1.type == HB_OP_MEM ? (int)instr->src1.mem.base : -1,
                        instr->src1.type == HB_OP_MEM ? (int)instr->src1.mem.index : -1,
                        instr->src1.type == HB_OP_MEM ? instr->src1.mem.scale : 0,
                        instr->src1.type == HB_OP_MEM ? (unsigned long long)instr->src1.mem.disp : 0,
                        instr->src1.size);
                return hb_fault_null_exec(ctx, target, instr ? instr->guest_addr : 0);
            }
            if (ctx->mode == HB_MODE_32BIT) {
                uint32_t new_esp = ctx->regs.x86.esp - 4;
                r = hb_memory_write_u32(ctx->memory, new_esp, (uint32_t)ret_addr);
                if (r == HB_OK) ctx->regs.x86.esp = new_esp;
            } else {
                uint64_t new_rsp = ctx->regs.x64.rsp - 8;
                r = hb_memory_write_u64(ctx->memory, new_rsp, ret_addr);
                if (r == HB_OK) ctx->regs.x64.rsp = new_rsp;
            }
            if (r != HB_OK) {
                static int traced;
                if (traced++ < 8)
                    fprintf(stderr, "macrunner-hb-interpcall-fail: rsp=0x%llx r=%d target=0x%llx\n",
                            (unsigned long long)rsp_before, (int)r, (unsigned long long)target);
                return r;
            }
            ctx->pc = target;
            sync_arch_pc(ctx);
            trace_branch_event(ctx, instr, "call", rsp_before, ret_addr, target);
            return HB_OK;
        }

        case HB_IR_RET: {
            uint64_t ret_addr = 0;
            uint64_t ret_imm = instr->src1.type == HB_OP_IMM ? (uint64_t)instr->src1.imm : 0;
            uint64_t rsp_before = ctx->mode == HB_MODE_32BIT ? ctx->regs.x86.esp : ctx->regs.x64.rsp;
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 915 — 16-БИТНЫЙ ВОЗВРАТ.
             * Под префиксом `66` со стека снимаются ДВА байта, и адрес возврата 16-битный.
             * Замер эталона (914), обе ветви: `66 c3` — вершина +2 и адрес 0x5e00; мы снимали
             * полную ширину и брали полноразрядный адрес. Контроли `c3` и `c2 imm16` без
             * префикса сходились — дефект точечный. Пометка ширины приходит в `dst`. */
            bool ret16 = instr->dst.type == HB_OP_IMM && instr->dst.imm == 2;
            if (ret16) {
                uint16_t ret16v = 0;
                uint64_t sp = ctx->mode == HB_MODE_32BIT ? ctx->regs.x86.esp : ctx->regs.x64.rsp;
                r = hb_memory_read_u16(ctx->memory, sp, &ret16v);
                if (r != HB_OK) return r;
                ret_addr = ret16v;
                if (ctx->mode == HB_MODE_32BIT)
                    ctx->regs.x86.esp += 2 + (uint32_t)ret_imm;
                else
                    ctx->regs.x64.rsp += 2 + ret_imm;
            } else if (ctx->mode == HB_MODE_32BIT) {
                uint32_t ret32 = 0;
                r = hb_memory_read_u32(ctx->memory, ctx->regs.x86.esp, &ret32);
                if (r != HB_OK) return r;
                ret_addr = ret32;
                ctx->regs.x86.esp += 4 + (uint32_t)ret_imm;
            } else {
                r = hb_memory_read_u64(ctx->memory, ctx->regs.x64.rsp, &ret_addr);
                if (r != HB_OK) return r;
                ctx->regs.x64.rsp += 8 + ret_imm;
            }
            /* MacRunner 2026-08-03 — catch a poisoned return address WHERE IT IS POPPED.
             *
             * The fault that kills Hollow Knight is an execute at address 0 (code=0xc0000005
             * addr=0x0 info0=0x8, measured on LONGLIVE1), and by the time it is reported the host
             * ExceptionAddress IS the zero — it names nothing.  A `jmp` to null already had this
             * diagnostic a few lines below; `ret` did not, even though a return is the likelier way
             * to reach zero, because the value comes off the stack.  Printing here gives the guest
             * address of the RET itself plus the stack window around the slot, which together name
             * the caller.
             *
             * Two comparisons on a value already loaded, and nothing is formatted on the normal
             * path — unlike the imul census, which formatted a double on every multiply and turned
             * every run into a 36-80 s abort.  Non-canonical is included because a half-overwritten
             * slot lands there rather than on exactly zero. */
            if (ctx->mode != HB_MODE_32BIT &&
                (!ret_addr ||
                 (((int64_t)ret_addr >> 47) != 0 && ((int64_t)ret_addr >> 47) != -1)))
            {
                static unsigned int ret_guard_reports;

                if (ret_guard_reports++ < 16)
                {
                    uint64_t win[6] = { 0 };
                    unsigned int i;

                    for (i = 0; i < 6; i++)
                        if (hb_memory_read_u64(ctx->memory, rsp_before + i * 8, &win[i]) != HB_OK)
                            win[i] = 0;
                    fprintf(stderr,
                            "macrunner-hb-ret-poisoned: ret_addr=0x%llx guest_ret_at=0x%llx "
                            "rsp=0x%llx rbp=0x%llx stk=%llx,%llx,%llx,%llx,%llx,%llx\n",
                            (unsigned long long)ret_addr,
                            (unsigned long long)instr->guest_addr,
                            (unsigned long long)rsp_before,
                            (unsigned long long)ctx->regs.x64.rbp,
                            (unsigned long long)win[0], (unsigned long long)win[1],
                            (unsigned long long)win[2], (unsigned long long)win[3],
                            (unsigned long long)win[4], (unsigned long long)win[5]);
                }
            }
            ctx->pc = ret_addr;
            sync_arch_pc(ctx);
            trace_branch_event(ctx, instr, "ret", rsp_before, ret_addr, ret_addr);
            return HB_OK;
        }

        case HB_IR_JMP: {
            uint64_t target = instr->target;
            uint64_t rsp_before = ctx->mode == HB_MODE_32BIT ? ctx->regs.x86.esp : ctx->regs.x64.rsp;
            if (instr->src1.type != HB_OP_NONE) {
                r = read_operand_value(ctx, &instr->src1, &target);
                if (r != HB_OK) return r;
            }
            if (!target) {
                fprintf(stderr, "macrunner-hb-null-branch: op=JMP addr=0x%llx len=%u src_type=%d base=%d index=%d scale=%u disp=0x%llx size=%d\n",
                        (unsigned long long)instr->guest_addr, instr->guest_len, instr->src1.type,
                        instr->src1.type == HB_OP_MEM ? (int)instr->src1.mem.base : -1,
                        instr->src1.type == HB_OP_MEM ? (int)instr->src1.mem.index : -1,
                        instr->src1.type == HB_OP_MEM ? instr->src1.mem.scale : 0,
                        instr->src1.type == HB_OP_MEM ? (unsigned long long)instr->src1.mem.disp : 0,
                        instr->src1.size);
                return hb_fault_null_exec(ctx, target, instr ? instr->guest_addr : 0);
            }
            ctx->pc = target;
            sync_arch_pc(ctx);
            trace_branch_event(ctx, instr, "jmp", rsp_before, 0, target);
            return HB_OK;
        }

        case HB_IR_Jcc: {
            bool taken = false;
            uint64_t rsp_before = ctx->mode == HB_MODE_32BIT ? ctx->regs.x86.esp : ctx->regs.x64.rsp;
            r = hb_flags_eval_cond(ctx, instr->cc, &taken);
            if (r != HB_OK) return r;
            if (taken) {
                ctx->pc = instr->target;
            } else {
                ctx->pc = instr->guest_addr + instr->guest_len;
            }
            sync_arch_pc(ctx);
            trace_branch_event(ctx, instr, taken ? "jcc-taken" : "jcc-fallthrough",
                               rsp_before, instr->cc, ctx->pc);
            return HB_OK;
        }

        case HB_IR_LOOP:
        case HB_IR_JRCXZ: {
            uint64_t count = 0;
            uint64_t next = 0;
            bool taken = false;
            uint64_t rsp_before = ctx->mode == HB_MODE_32BIT ? ctx->regs.x86.esp : ctx->regs.x64.rsp;
            hb_size_t size = instr->dst.size ? instr->dst.size : HB_SIZE_64;
            r = read_operand_value(ctx, &instr->dst, &count);
            if (r != HB_OK) return r;
            count = trunc_to_size(count, size);
            if (instr->op == HB_IR_JRCXZ) {
                taken = count == 0;
            } else {
                int kind = (int)instr->src1.imm; /* E0 LOOPNE, E1 LOOPE, E2 LOOP. */
                next = trunc_to_size(count - 1, size);
                r = write_operand_value(ctx, &instr->dst, next);
                if (r != HB_OK) return r;
                taken = next != 0 &&
                        (kind == 2 || (kind == 1 ? ctx->flags.zf : !ctx->flags.zf));
            }
            ctx->pc = taken ? instr->target : instr->guest_addr + instr->guest_len;
            sync_arch_pc(ctx);
            trace_branch_event(ctx, instr,
                               taken ? (instr->op == HB_IR_JRCXZ ? "jrcxz-taken" : "loop-taken")
                                     : (instr->op == HB_IR_JRCXZ ? "jrcxz-fallthrough" : "loop-fallthrough"),
                               rsp_before, count, ctx->pc);
            return HB_OK;
        }

        case HB_IR_SHL:
        case HB_IR_SHR:
        case HB_IR_SAR:
        case HB_IR_ROL:
        case HB_IR_ROR: {
            return hb_flags_exec_binop_operand(ctx, instr->op, &instr->dst,
                                               &instr->src1, &instr->src2, NULL,
                                               instr->preserve_cf);
        }

        case HB_IR_RCL:
        case HB_IR_RCR: {
            uint64_t value = 0, raw_count = 0;
            r = read_operand_value(ctx, &instr->src1, &value);
            if (r != HB_OK) return r;
            r = read_operand_value(ctx, &instr->src2, &raw_count);
            if (r != HB_OK) return r;
            r = hb_lazy_flags_materialize(ctx, HB_FLAG_BIT_CF);
            if (r != HB_OK) return r;
            hb_size_t size = instr->dst.size ? instr->dst.size : instr->src1.size;
            if (!size) size = HB_SIZE_64;
            unsigned width = bit_width_for_size(size);
            unsigned count = (unsigned)(raw_count & (width == 64 ? 0x3fU : 0x1fU));
            unsigned ring = width + 1;
            if (width <= 16) count %= ring;
            if (count == 0) return HB_OK;

            value = trunc_to_size(value, size);
            uint64_t value_mask = mask_for_size(size);
            unsigned __int128 ring_mask = (((unsigned __int128)1) << ring) - 1;
            unsigned __int128 combined = (((unsigned __int128)(ctx->flags.cf ? 1 : 0)) << width) | value;
            if (instr->op == HB_IR_RCL) {
                combined = ((combined << count) | (combined >> (ring - count))) & ring_mask;
            } else {
                combined = ((combined >> count) | (combined << (ring - count))) & ring_mask;
            }
            uint64_t result = (uint64_t)combined & value_mask;
            bool new_cf = ((combined >> width) & 1U) != 0;
            r = write_operand_value(ctx, &instr->dst, result);
            if (r != HB_OK) return r;
            hb_lazy_flags_clear(ctx);
            ctx->flags.cf = new_cf;
            if (count == 1) {
                bool msb = ((result >> (width - 1)) & 1U) != 0;
                if (instr->op == HB_IR_RCL) {
                    ctx->flags.of = msb != ctx->flags.cf;
                } else {
                    bool next = width > 1 ? (((result >> (width - 2)) & 1U) != 0) : false;
                    ctx->flags.of = msb != next;
                }
            }
            return HB_OK;
        }

        case HB_IR_SHLD:
        case HB_IR_SHRD: {
            return hb_flags_exec_double_shift_operand(ctx, instr->op, &instr->dst,
                                                      &instr->src1, &instr->src2, NULL);
        }

        case HB_IR_NOT: {
            uint64_t a = 0;
            r = read_operand_value(ctx, &instr->src1, &a);
            if (r != HB_OK) return r;
            hb_size_t size = instr->dst.size ? instr->dst.size : instr->src1.size;
            if (!size) size = HB_SIZE_64;
            uint64_t result = ~a;
            result = trunc_to_size(result, size);
            return write_operand_value(ctx, &instr->dst, result);
        }

        case HB_IR_NEG: {
            uint64_t a = 0;
            r = read_operand_value(ctx, &instr->src1, &a);
            if (r != HB_OK) return r;
            hb_size_t size = instr->dst.size ? instr->dst.size : instr->src1.size;
            if (!size) size = HB_SIZE_64;
            a = trunc_to_size(a, size);
            uint64_t result = trunc_to_size(0 - a, size);
            r = write_operand_value(ctx, &instr->dst, result);
            if (r != HB_OK) return r;
            hb_lazy_flags_note(ctx, HB_LAZY_FLAGS_SUB, size, 0, a, result, 0);
            return HB_OK;
        }

        case HB_IR_LAHF: {
            r = hb_lazy_flags_materialize(ctx, HB_FLAG_BIT_SF | HB_FLAG_BIT_ZF |
                                               HB_FLAG_BIT_AF | HB_FLAG_BIT_PF |
                                               HB_FLAG_BIT_CF);
            if (r != HB_OK) return r;
            uint8_t ah = 0x02;
            if (ctx->flags.sf) ah |= 0x80;
            if (ctx->flags.zf) ah |= 0x40;
            if (ctx->flags.af) ah |= 0x10;
            if (ctx->flags.pf) ah |= 0x04;
            if (ctx->flags.cf) ah |= 0x01;
            if (ctx->mode == HB_MODE_32BIT) {
                ctx->regs.x86.eax = (ctx->regs.x86.eax & ~0x0000ff00U) | ((uint32_t)ah << 8);
            } else {
                ctx->regs.x64.rax = (ctx->regs.x64.rax & ~0x000000000000ff00ULL) | ((uint64_t)ah << 8);
            }
            return HB_OK;
        }

        case HB_IR_SAHF: {
            uint8_t ah = ctx->mode == HB_MODE_32BIT ?
                (uint8_t)((ctx->regs.x86.eax >> 8) & 0xffU) :
                (uint8_t)((ctx->regs.x64.rax >> 8) & 0xffU);
            hb_lazy_flags_clear(ctx);
            ctx->flags.sf = (ah & 0x80) != 0;
            ctx->flags.zf = (ah & 0x40) != 0;
            ctx->flags.af = (ah & 0x10) != 0;
            ctx->flags.pf = (ah & 0x04) != 0;
            ctx->flags.cf = (ah & 0x01) != 0;
            return HB_OK;
        }

        case HB_IR_MMX_SRL:
        case HB_IR_MMX_SRA:
        case HB_IR_MMX_SLL: {
            /* Итерация 305: сдвиги MMX по элементам. Разрядность элемента в `target` (2/4/8).
             *
             * Спецификация: величина сдвига берётся как ПОЛНОЕ 64-битное значение, и если она
             * не меньше разрядности элемента, результат — ноль (для арифметического сдвига
             * элемент заполняется знаком). Это не край, а нормальное поведение, и игры на нём
             * держатся: сдвиг на 64 — обычный способ обнулить регистр. */
            uint64_t* mm = hb_mmx_regs(ctx);
            unsigned w = instr->target ? (unsigned)instr->target : 8;
            uint64_t cnt = 0, v, res = 0;
            unsigned bits = w * 8, i;

            if (instr->dst.type != HB_OP_REG ||
                instr->dst.reg < HB_REG_MM0 || instr->dst.reg > HB_REG_MM7) {
                /* Итерация 307: печать в САМОЙ отказавшей ветке. Декодер отдаёт верные номера
                 * (проверено зондом: op1=50, op2=54 при HB_REG_MM0=49), значит до сюда доезжает
                 * что-то другое — печатаем что именно, вместо догадок. */
                static int said;
                if (said++ < 4)
                    fprintf(stderr, "macrunner-mmx-alu-reject: dst.type=%d dst.reg=%d "
                            "src1.type=%d src1.reg=%d MM0=%d MM7=%d op=%d\n",
                            (int)instr->dst.type, (int)instr->dst.reg,
                            (int)instr->src1.type, (int)instr->src1.reg,
                            (int)HB_REG_MM0, (int)HB_REG_MM7, (int)instr->op);
                return HB_ERR_UNSUPPORTED_FEATURE;
            }

            if (instr->src1.type == HB_OP_IMM) cnt = (uint64_t)instr->src1.imm;
            else if (instr->src1.type == HB_OP_REG &&
                     instr->src1.reg >= HB_REG_MM0 && instr->src1.reg <= HB_REG_MM7)
                cnt = mm[instr->src1.reg - HB_REG_MM0];
            else if (instr->src1.type == HB_OP_MEM) {
                uint64_t addr = resolve_addr(ctx, &instr->src1);
                r = hb_memory_read_u64(ctx->memory, addr, &cnt);
                if (r != HB_OK) return r;
            } else return HB_ERR_UNSUPPORTED_FEATURE;

            v = mm[instr->dst.reg - HB_REG_MM0];
            for (i = 0; i < 64; i += bits) {
                uint64_t mask = bits == 64 ? ~0ULL : ((1ULL << bits) - 1);
                uint64_t el = (v >> i) & mask;
                uint64_t out;
                if (instr->op == HB_IR_MMX_SRA) {
                    int64_t se = (int64_t)(el << (64 - bits)) >> (64 - bits);
                    out = (uint64_t)(cnt >= bits ? (se < 0 ? -1 : 0) : (se >> cnt)) & mask;
                } else if (cnt >= bits) {
                    out = 0;
                } else {
                    out = (instr->op == HB_IR_MMX_SRL ? (el >> cnt) : (el << cnt)) & mask;
                }
                res |= out << i;
            }
            mm[instr->dst.reg - HB_REG_MM0] = res;
            hb_x87_mmx_write(hb_context_x87(ctx), (unsigned)(instr->dst.reg - HB_REG_MM0), res);   /* итерация 519 */
            return HB_OK;
        }

        case HB_IR_MMX_AND:
        case HB_IR_MMX_ANDN:
        case HB_IR_MMX_OR:
        case HB_IR_MMX_XOR: {
            /* Итерация 304: побитовая логика MMX. Операнды 64 бита, флаги не пишутся.
             * PANDN — И-НЕ по ПЕРВОМУ операнду: dst = (~dst) & src. */
            uint64_t* mm = hb_mmx_regs(ctx);
            uint64_t a = 0, bv = 0;
            if (instr->dst.type != HB_OP_REG ||
                instr->dst.reg < HB_REG_MM0 || instr->dst.reg > HB_REG_MM7)
                return HB_ERR_UNSUPPORTED_FEATURE;
            a = mm[instr->dst.reg - HB_REG_MM0];
            if (instr->src1.type == HB_OP_REG &&
                instr->src1.reg >= HB_REG_MM0 && instr->src1.reg <= HB_REG_MM7) {
                bv = mm[instr->src1.reg - HB_REG_MM0];
            } else if (instr->src1.type == HB_OP_MEM) {
                uint64_t addr = resolve_addr(ctx, &instr->src1);
                r = hb_memory_read_u64(ctx->memory, addr, &bv);
                if (r != HB_OK) return r;
            } else return HB_ERR_UNSUPPORTED_FEATURE;

            switch (instr->op) {
                case HB_IR_MMX_AND:  a = a & bv; break;
                case HB_IR_MMX_ANDN: a = (~a) & bv; break;
                case HB_IR_MMX_OR:   a = a | bv; break;
                default:             a = a ^ bv; break;
            }
            mm[instr->dst.reg - HB_REG_MM0] = a;
            hb_x87_mmx_write(hb_context_x87(ctx), (unsigned)(instr->dst.reg - HB_REG_MM0), a);   /* итерация 519 */
            return HB_OK;
        }

        case HB_IR_MMX_MOV: {
            /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 303 — перенос MMX.
             *
             * MOVQ (8 байт) и MOVD (4 байта) между регистром MMX, обычным регистром и памятью.
             * Регистры MMX лежат отдельным массивом `regs.*.mm[8]`; сопряжение со стеком x87
             * НЕ моделируется — Diablo мешать их не должен, а если помешает, это выяснится
             * замером, а не догадкой. */
            unsigned size = instr->target ? (unsigned)instr->target : 8;
            uint64_t val = 0;
            uint64_t* mm = hb_mmx_regs(ctx);

            /* прочитать источник */
            if (instr->src1.type == HB_OP_REG &&
                instr->src1.reg >= HB_REG_MM0 && instr->src1.reg <= HB_REG_MM7) {
                val = mm[instr->src1.reg - HB_REG_MM0];
            } else if (instr->src1.type == HB_OP_REG) {
                val = read_reg(ctx, instr->src1.reg);
            } else if (instr->src1.type == HB_OP_MEM) {
                uint64_t addr = resolve_addr(ctx, &instr->src1);
                if (size == 8) { r = hb_memory_read_u64(ctx->memory, addr, &val); }
                else { uint32_t v32 = 0; r = hb_memory_read_u32(ctx->memory, addr, &v32); val = v32; }
                if (r != HB_OK) return r;
            } else return HB_ERR_UNSUPPORTED_FEATURE;

            if (size == 4) val &= 0xffffffffULL;

            /* записать приёмник */
            if (instr->dst.type == HB_OP_REG &&
                instr->dst.reg >= HB_REG_MM0 && instr->dst.reg <= HB_REG_MM7) {
                mm[instr->dst.reg - HB_REG_MM0] = val;
                hb_x87_mmx_write(hb_context_x87(ctx), (unsigned)(instr->dst.reg - HB_REG_MM0), val);   /* итерация 519 */
                return HB_OK;
            }
            if (instr->dst.type == HB_OP_REG) {
                /* Итерация 308: раньше сюда проваливались и регистры MMX с негодным номером
                 * (HB_REG_COUNT), и запись шла НЕ ТУДА, молча. Отказ лучше тихой порчи. */
                if (instr->dst.reg >= HB_REG_COUNT) return HB_ERR_UNSUPPORTED_FEATURE;
                write_reg(ctx, instr->dst.reg, val);
                return HB_OK;
            }
            if (instr->dst.type == HB_OP_MEM) {
                uint64_t addr = resolve_addr(ctx, &instr->dst);
                return size == 8 ? hb_memory_write_u64(ctx->memory, addr, val)
                                 : hb_memory_write_u32(ctx->memory, addr, (uint32_t)val);
            }
            return HB_ERR_UNSUPPORTED_FEATURE;
        }

        case HB_IR_CPUID: {
            uint32_t leaf = (uint32_t)read_reg(ctx, HB_REG_RAX);
            uint32_t subleaf = (uint32_t)read_reg(ctx, HB_REG_RCX);
            uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

            /* Итерация 761: описание переехало в `include/hb_cpuid.h` — ОДНА копия на
             * оба исполнителя. Прежние правки 302/510/531/584 перенесены туда дословно,
             * там же заполнен лист 13 (входящее 104, ответ на В5). */
            hb_cpuid_query(ctx, leaf, subleaf, &eax, &ebx, &ecx, &edx);

            write_reg_sized(ctx, HB_REG_RAX, eax, HB_SIZE_32);
            write_reg_sized(ctx, HB_REG_RBX, ebx, HB_SIZE_32);
            write_reg_sized(ctx, HB_REG_RCX, ecx, HB_SIZE_32);
            write_reg_sized(ctx, HB_REG_RDX, edx, HB_SIZE_32);
            return HB_OK;
        }

        case HB_IR_XGETBV: {
            uint32_t ecx = (uint32_t)read_reg(ctx, HB_REG_RCX);
            /* Итерация 510: состояние YMM объявляем только там, где AVX действительно
             * исполняется. В 32 битах его нет (VEX не поднимается), и обещать гостю
             * сохранение YMM значит звать его в тот же тупик, что и бит AVX в `cpuid`.
             * Итерация 761: значение общее с листом 13 (`hb_cpuid.h`) — размер области
             * сохранения и набор компонент обязаны быть согласованы, входящее 104. */
            uint64_t xcr0 = hb_xcr0_value(ctx, ecx);

            write_reg_sized(ctx, HB_REG_RAX, (uint32_t)xcr0, HB_SIZE_32);
            write_reg_sized(ctx, HB_REG_RDX, (uint32_t)(xcr0 >> 32), HB_SIZE_32);
            return HB_OK;
        }

        case HB_IR_VERR:
        case HB_IR_VERW: {
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 942 — ПРОВЕРКА СЕЛЕКТОРА.
             *
             * `VERR`/`VERW` отвечают не значением, а флагом ZF: годен ли селектор на чтение
             * (на запись). Ответ живёт в таблице дескрипторов, которой у нас нет, поэтому
             * здесь МОДЕЛЬ — и я называю её вслух, а не выдаю за реализацию.
             *
             * Замер под Prism (итерация 941), обе разрядности, числа совпали до бита:
             *     verr cs (0033/001b)  ZF=1      verw cs   ZF=0   кодовый сегмент не пишется
             *     verr ds (002b/0023)  ZF=1      verw ds   ZF=1
             *     verr 0xfff8          ZF=0      verw 0xfff8 ZF=0  негодный селектор
             *
             * Правило, покрывающее ВСЕ шесть замеров: годен тот селектор, который гость
             * СЕЙЧАС держит в сегментном регистре; на запись — тот же набор без кодового.
             * Обоснование не «похоже на правду», а устройство пользовательского режима
             * Windows: годных селекторов там ровно столько, сколько загружено, остальные
             * либо системные (недоступны при CPL=3), либо вне таблицы.
             *
             * ★ Граница: селектор, полученный программой ИЗВНЕ и не загруженный ни в один
             * регистр, мы объявим негодным, а настоящая машина могла бы принять. Такой
             * случай в пользовательском коде Windows не встречается, но если встретится —
             * это будет ЛОЖНЫЙ ОТКАЗ, а не молчащая порча: ZF=0 честно означает «не годен».
             * Нулевой селектор негоден всегда — это уже спецификация, а не модель. */
            uint64_t sel_val = 0;
            r = read_operand_value(ctx, &instr->src1, &sel_val);
            if (r != HB_OK) return r;
            uint16_t sel = (uint16_t)sel_val;
            bool ok = false;
            if (sel != 0) {
                if (sel == ctx->seg_ds || sel == ctx->seg_es ||
                    sel == ctx->seg_ss || sel == ctx->seg_fs || sel == ctx->seg_gs)
                    ok = true;
                else if (instr->op == HB_IR_VERR && sel == ctx->seg_cs)
                    ok = true;   /* читать кодовый можно, писать — нет */
            }
            hb_lazy_flags_clear(ctx);
            ctx->flags.zf = ok;
            return HB_OK;
        }

        case HB_IR_RDTSC:
        case HB_IR_RDTSCP: {
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 938 — СЧЁТЧИК ТАКТОВ.
             *
             * Команды не было НИГДЕ: `0F 31` на x64 попадал в `HB_INS_SYS` и давал отказ,
             * на i386 не разбирался вовсе. Замер на Prism (промышленный транслятор x86 на
             * настоящей Windows 11 ARM64) в обеих разрядностях: `rdtsc` и `rdtscp` дают
             * код исключения 00000000, то есть в пользовательском режиме ИСПОЛНЯЮТСЯ.
             * Значит наш отказ был неверен, и всякая программа со счётчиком тактов — замер
             * времени, калибровка, защита от отладчика — на нём умирала.
             *
             * Источник времени: `cntvct_el0`, тот же счётчик, что читает ядро macOS. Он
             * монотонный, доступен из пользовательского режима и не требует обращения к
             * ядру — в отличие от `clock_gettime`, который на горячем пути стоил бы дорого.
             *
             * ★ ПРО МАСШТАБ. `cntvct_el0` на Apple Silicon идёт на 24 МГц, а гость ждёт
             * счётчик порядка гигагерц. Программе, которая КАЛИБРУЕТ счётчик (замер против
             * QueryPerformanceCounter), безразличен любой постоянный множитель. Но
             * программе, которая крутит ожидание на «столько-то тактов», разница в 125 раз
             * превращает микросекунду в долю миллисекунды. Поэтому приводим к номинальным
             * 3 ГГц: множитель ровно 125, деления нет, монотонность сохраняется.
             *
             * `RDTSCP` вдобавок пишет ECX = IA32_TSC_AUX (номер процессора и узла). Отдаём
             * ноль: гость по нему различает ядра, а у нас поток к ядру не привязан, и
             * выдумывать номер значило бы обещать несуществующее постоянство. */
            uint64_t cnt;
            __asm__ volatile("mrs %0, cntvct_el0" : "=r"(cnt));
            uint64_t tsc = cnt * 125u;

            write_reg_sized(ctx, HB_REG_RAX, (uint32_t)tsc, HB_SIZE_32);
            write_reg_sized(ctx, HB_REG_RDX, (uint32_t)(tsc >> 32), HB_SIZE_32);
            if (instr->op == HB_IR_RDTSCP)
                write_reg_sized(ctx, HB_REG_RCX, 0, HB_SIZE_32);
            return HB_OK;
        }

        case HB_IR_RDRAND:
        case HB_IR_RDSEED: {
            /* Patch H: RDRAND/RDSEED r16/32/64. Destination is a register operand;
             * fill it with a fresh random value and report success (CF=1), clearing
             * OF/SF/ZF/AF/PF per the Intel SDM. arc4random_buf is a good-quality CSPRNG
             * on the host, adequate for both the "random" and "seed" flavours. */
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            hb_size_t size = instr->dst.size ? instr->dst.size : HB_SIZE_32;
            uint64_t rnd = 0;
            arc4random_buf(&rnd, sizeof(rnd));
            write_reg_sized_offset(ctx, instr->dst.reg, rnd, size, instr->dst.reg_offset);
            hb_lazy_flags_clear(ctx);
            ctx->flags.cf = true;
            ctx->flags.of = false;
            ctx->flags.sf = false;
            ctx->flags.zf = false;
            ctx->flags.af = false;
            ctx->flags.pf = false;
            return HB_OK;
        }

        case HB_IR_SETcc: {
            bool value = false;
            r = hb_flags_eval_cond(ctx, instr->cc, &value);
            if (r != HB_OK) return r;
            if (instr->dst.type == HB_OP_REG) {
                write_reg_sized_offset(ctx, instr->dst.reg, value ? 1 : 0, HB_SIZE_8,
                                       instr->dst.reg_offset);
            } else if (instr->dst.type == HB_OP_MEM) {
                uint64_t addr = resolve_addr(ctx, &instr->dst);
                r = mem_write(ctx, addr, value ? 1 : 0, HB_SIZE_8);
                if (r != HB_OK) return r;
            } else {
                return HB_ERR_INTERNAL;
            }
            return HB_OK;
        }

        case HB_IR_CMOVcc: {
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            bool value = false;
            r = hb_flags_eval_cond(ctx, instr->cc, &value);
            if (r != HB_OK) return r;
            /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 357 — ДВЕ ОШИБКИ В ОДНОЙ ВЕТВИ.
             *
             * 1. При ЛОЖНОМ условии не писалось НИЧЕГО. В x86-64 запись 32-битного приёмника
             *    обязана обнулять старшие 32 бита, и для `CMOVcc` это верно даже когда условие
             *    ложно: приёмник всё равно записывается. Замер набора x64 показал ровно это —
             *    `450f44c8`, ожидалось `reg.r9 = 0x00000000ea3e7abc`, получено
             *    `0x71c7ccdeea3e7abc`, то есть старшая половина осталась прежней.
             * 2. При ИСТИННОМ условии писалась полная ширина (`read_reg`/`write_reg`) без учёта
             *    `instr->dst.size`. Для 16-битной формы это затирало бы старшие биты, которых
             *    трогать нельзя.
             *
             * Лечение общее: читать и писать ПО РАЗМЕРУ операнда, а при ложном условии писать
             * приёмнику его же значение — для 32 бит это и даёт требуемое обнуление старшей
             * половины, для 16 и 64 остаётся тождеством. */
            {
                hb_size_t size = instr->dst.size ? instr->dst.size : HB_SIZE_64;
                uint64_t src = 0;
                if (value) {
                    if (instr->src1.type == HB_OP_REG) src = read_reg_sized(ctx, instr->src1.reg, size, 0);
                    else if (instr->src1.type == HB_OP_IMM) src = (uint64_t)instr->src1.imm;
                    else if (instr->src1.type == HB_OP_MEM) {
                        uint64_t addr = resolve_addr(ctx, &instr->src1);
                        r = mem_read(ctx, addr, &src, instr->src1.size);
                        if (r != HB_OK) return r;
                    } else {
                        return HB_ERR_INTERNAL;
                    }
                } else {
                    src = read_reg_sized(ctx, instr->dst.reg, size, 0);
                }
                write_reg_sized(ctx, instr->dst.reg, trunc_to_size(src, size), size);
            }
            return HB_OK;
        }

        case HB_IR_ZERO_EXTEND: {
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            uint64_t val = 0;
            r = read_operand_value(ctx, &instr->src1, &val);
            if (r != HB_OK) return r;
            val = trunc_to_size(val, instr->src1.size);
            write_reg_sized(ctx, instr->dst.reg, val, instr->dst.size);
            return HB_OK;
        }

        case HB_IR_SIGN_EXTEND: {
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            uint64_t val = 0;
            r = read_operand_value(ctx, &instr->src1, &val);
            if (r != HB_OK) return r;
            val = sign_extend_from_size(trunc_to_size(val, instr->src1.size), instr->src1.size);
            write_reg_sized(ctx, instr->dst.reg, val, instr->dst.size);
            return HB_OK;
        }

        case HB_IR_CWD: {
            hb_size_t size = instr->src1.size ? instr->src1.size : HB_SIZE_32;
            if (size == HB_SIZE_16) {
                uint16_t ax = (uint16_t)read_reg(ctx, HB_REG_RAX);
                write_reg_sized(ctx, HB_REG_RDX, (ax & 0x8000) ? 0xffffU : 0, HB_SIZE_16);
            } else if (size == HB_SIZE_32) {
                uint32_t eax = (uint32_t)read_reg(ctx, HB_REG_RAX);
                write_reg_sized(ctx, HB_REG_RDX, (eax & 0x80000000U) ? 0xffffffffU : 0, HB_SIZE_32);
            } else if (size == HB_SIZE_64) {
                uint64_t rax = read_reg(ctx, HB_REG_RAX);
                write_reg_sized(ctx, HB_REG_RDX, (rax & 0x8000000000000000ULL) ? UINT64_MAX : 0, HB_SIZE_64);
            } else return HB_ERR_UNSUPPORTED_OPCODE;
            return HB_OK;
        }

        case HB_IR_MOVS: {
            hb_size_t size = instr->src1.size ? instr->src1.size : HB_SIZE_32;
            /* Итерация 491: префикс повтора берём из ОТДЕЛЬНОГО поля (заведено в 490 и
             * заполняется параллельно). Старое чтение из второго операнда оставлено
             * запасным, пока описание операндов не переведено на архитектурное: так
             * переключение проверяемо на каждом шаге, а не одним прыжком. */
            uint64_t rep = instr->rep_prefix ? (uint64_t)instr->rep_prefix :
                           ((instr->src2.type == HB_OP_IMM) ? (uint64_t)instr->src2.imm : 0);
            /* Итерация 503: у MOVS/LODS/STOS повтор определён ТОЛЬКО префиксом REP (0xF3).
             * REPNE (0xF2) для них архитектурно не задан, и эталон его повтором не считает:
             * стенд поймал `movsd f2a5` — ждали rcx=0x31, мы обнуляли до 0 (замер 502).
             * Пара REPE/REPNE осмысленна лишь у CMPS/SCAS, где есть с чем сравнивать. */
            /* Итерация 506 — ОТКАТ правки 503, по замеру, а не по рассуждению. 503 исходила
             * из того, что эталон не считает `F2` повтором для MOVS/LODS/STOS. Прямой замер
             * говорит обратное: при бюджете в ОДИН шаг эталон уменьшил `rcx` 0x32 -> 0x31,
             * то есть итерацию повтора ВЫПОЛНИЛ. Значит `F2` тут работает как `REP` (SDM
             * оставляет это неопределённым, железо и эталон ведут себя именно так), а
             * расхождение было не про семантику, а про разный счёт шагов у стенда:
             * Unicorn считает каждую итерацию отдельной инструкцией. Починено в
             * `coverage.py` (`_rep_string_extra_budget`). */
            bool repeated = (rep == 0xf2 || rep == 0xf3);
            bool mode32 = ctx->mode == HB_MODE_32BIT;
            uint64_t count = repeated ? (mode32 ? ctx->regs.x86.ecx : ctx->regs.x64.rcx) : 1;
            uint64_t rsi = mode32 ? ctx->regs.x86.esi : ctx->regs.x64.rsi;
            uint64_t rdi = mode32 ? ctx->regs.x86.edi : ctx->regs.x64.rdi;
            int64_t step = (int64_t)size;
            if ((mode32 ? ctx->regs.x86.eflags : ctx->regs.x64.rflags) & (1ULL << 10))
                step = -step; /* Direction flag. */

            uint64_t iterations = 0;
            while (count > 0) {
                uint64_t value = 0;
                r = mem_read(ctx, rsi, &value, size);
                if (r != HB_OK) return r;
                r = mem_write(ctx, rdi, value, size);
                if (r != HB_OK) return r;
                rsi = (uint64_t)((int64_t)rsi + step);
                rdi = (uint64_t)((int64_t)rdi + step);
                if (repeated) count--;
                if (!repeated) break;
                if (++iterations > hb_stringop_limit()) return HB_ERR_STEP_LIMIT;
            }

            if (mode32) {
                ctx->regs.x86.esi = (uint32_t)rsi;
                ctx->regs.x86.edi = (uint32_t)rdi;
                if (repeated) ctx->regs.x86.ecx = (uint32_t)count;
            } else {
                ctx->regs.x64.rsi = rsi;
                ctx->regs.x64.rdi = rdi;
                if (repeated) ctx->regs.x64.rcx = count;
            }
            return HB_OK;
        }

        case HB_IR_CMPS: {
            hb_size_t size = instr->src1.size ? instr->src1.size : HB_SIZE_32;
            /* Итерация 491: префикс повтора берём из ОТДЕЛЬНОГО поля (заведено в 490 и
             * заполняется параллельно). Старое чтение из второго операнда оставлено
             * запасным, пока описание операндов не переведено на архитектурное: так
             * переключение проверяемо на каждом шаге, а не одним прыжком. */
            uint64_t rep = instr->rep_prefix ? (uint64_t)instr->rep_prefix :
                           ((instr->src2.type == HB_OP_IMM) ? (uint64_t)instr->src2.imm : 0);
            bool repeated = (rep == 0xf2 || rep == 0xf3);
            bool mode32 = ctx->mode == HB_MODE_32BIT;
            uint64_t count = repeated ? (mode32 ? ctx->regs.x86.ecx : ctx->regs.x64.rcx) : 1;
            uint64_t rsi = mode32 ? ctx->regs.x86.esi : ctx->regs.x64.rsi;
            uint64_t rdi = mode32 ? ctx->regs.x86.edi : ctx->regs.x64.rdi;
            int64_t step = (int64_t)size;
            if ((mode32 ? ctx->regs.x86.eflags : ctx->regs.x64.rflags) & (1ULL << 10))
                step = -step; /* Direction flag. */

            uint64_t iterations = 0;
            while (count > 0) {
                uint64_t left = 0, right = 0;
                r = mem_read(ctx, rsi, &left, size);
                if (r != HB_OK) return r;
                r = mem_read(ctx, rdi, &right, size);
                if (r != HB_OK) return r;
                left = trunc_to_size(left, size);
                right = trunc_to_size(right, size);
                hb_lazy_flags_note(ctx, HB_LAZY_FLAGS_CMP, size, left, right, left - right, 0);
                r = hb_lazy_flags_materialize(ctx, HB_FLAG_BIT_ZF | HB_FLAG_BIT_SF |
                                                   HB_FLAG_BIT_AF | HB_FLAG_BIT_PF |
                                                   HB_FLAG_BIT_CF | HB_FLAG_BIT_OF);
                if (r != HB_OK) return r;

                /* Per Intel SDM, the pointer update and count decrement happen
                 * BEFORE the termination check. The first terminating comparison
                 * (mismatch for REPE, match for REPNE) still updates pointers and
                 * decrements count, so the final state has pointers one past the
                 * element that triggered the stop. */
                rsi = (uint64_t)((int64_t)rsi + step);
                rdi = (uint64_t)((int64_t)rdi + step);
                if (repeated) count--;
                if (!repeated) break;
                if (rep == 0xf2 && ctx->flags.zf) break;  /* REPNE/REPNZ stops on match. */
                if (rep == 0xf3 && !ctx->flags.zf) break; /* REPE/REPZ stops on mismatch. */
                if (++iterations > hb_stringop_limit()) return HB_ERR_STEP_LIMIT;
            }

            if (mode32) {
                ctx->regs.x86.esi = (uint32_t)rsi;
                ctx->regs.x86.edi = (uint32_t)rdi;
                if (repeated) ctx->regs.x86.ecx = (uint32_t)count;
            } else {
                ctx->regs.x64.rsi = rsi;
                ctx->regs.x64.rdi = rdi;
                if (repeated) ctx->regs.x64.rcx = count;
            }
            return HB_OK;
        }

        case HB_IR_LODS: {
            hb_size_t size = instr->src1.size ? instr->src1.size : HB_SIZE_32;
            /* Итерация 491: префикс повтора берём из ОТДЕЛЬНОГО поля (заведено в 490 и
             * заполняется параллельно). Старое чтение из второго операнда оставлено
             * запасным, пока описание операндов не переведено на архитектурное: так
             * переключение проверяемо на каждом шаге, а не одним прыжком. */
            uint64_t rep = instr->rep_prefix ? (uint64_t)instr->rep_prefix :
                           ((instr->src2.type == HB_OP_IMM) ? (uint64_t)instr->src2.imm : 0);
            /* Итерация 503: у MOVS/LODS/STOS повтор определён ТОЛЬКО префиксом REP (0xF3).
             * REPNE (0xF2) для них архитектурно не задан, и эталон его повтором не считает:
             * стенд поймал `movsd f2a5` — ждали rcx=0x31, мы обнуляли до 0 (замер 502).
             * Пара REPE/REPNE осмысленна лишь у CMPS/SCAS, где есть с чем сравнивать. */
            /* Итерация 506: откат 503 — обоснование при MOVS выше. */
            bool repeated = (rep == 0xf2 || rep == 0xf3);
            bool mode32 = ctx->mode == HB_MODE_32BIT;
            uint64_t count = repeated ? (mode32 ? ctx->regs.x86.ecx : ctx->regs.x64.rcx) : 1;
            uint64_t rsi = mode32 ? ctx->regs.x86.esi : ctx->regs.x64.rsi;
            int64_t step = (int64_t)size;
            if ((mode32 ? ctx->regs.x86.eflags : ctx->regs.x64.rflags) & (1ULL << 10))
                step = -step; /* Direction flag. */

            uint64_t iterations = 0;
            while (count > 0) {
                uint64_t value = 0;
                r = mem_read(ctx, rsi, &value, size);
                if (r != HB_OK) return r;
                /* LODSB/LODSW write AL/AX only; LODSD zero-extends through EAX in
                 * x86-64, and LODSQ writes the full RAX. */
                if (mode32) {
                    write_reg_sized_offset(ctx, HB_REG_X86_EAX, value, size, 0);
                } else {
                    write_reg_sized_offset(ctx, HB_REG_RAX, value, size, 0);
                }
                rsi = (uint64_t)((int64_t)rsi + step);
                if (repeated) count--;
                if (!repeated) break;
                if (++iterations > hb_stringop_limit()) return HB_ERR_STEP_LIMIT;
            }

            if (mode32) {
                ctx->regs.x86.esi = (uint32_t)rsi;
                if (repeated) ctx->regs.x86.ecx = (uint32_t)count;
            } else {
                ctx->regs.x64.rsi = rsi;
                if (repeated) ctx->regs.x64.rcx = count;
            }
            return HB_OK;
        }

        case HB_IR_SCAS: {
            hb_size_t size = instr->src1.size ? instr->src1.size : HB_SIZE_32;
            /* Итерация 491: префикс повтора берём из ОТДЕЛЬНОГО поля (заведено в 490 и
             * заполняется параллельно). Старое чтение из второго операнда оставлено
             * запасным, пока описание операндов не переведено на архитектурное: так
             * переключение проверяемо на каждом шаге, а не одним прыжком. */
            uint64_t rep = instr->rep_prefix ? (uint64_t)instr->rep_prefix :
                           ((instr->src2.type == HB_OP_IMM) ? (uint64_t)instr->src2.imm : 0);
            bool repeated = (rep == 0xf2 || rep == 0xf3);
            bool mode32 = ctx->mode == HB_MODE_32BIT;
            uint64_t count = repeated ? (mode32 ? ctx->regs.x86.ecx : ctx->regs.x64.rcx) : 1;
            uint64_t rdi = mode32 ? ctx->regs.x86.edi : ctx->regs.x64.rdi;
            uint64_t acc = read_reg_sized(ctx, HB_REG_RAX, size, 0);
            int64_t step = (int64_t)size;
            if ((mode32 ? ctx->regs.x86.eflags : ctx->regs.x64.rflags) & (1ULL << 10))
                step = -step; /* Direction flag. */

            uint64_t iterations = 0;
            while (count > 0) {
                uint64_t mem = 0;
                r = mem_read(ctx, rdi, &mem, size);
                if (r != HB_OK) return r;
                mem = trunc_to_size(mem, size);
                hb_lazy_flags_note(ctx, HB_LAZY_FLAGS_CMP, size, acc, mem, acc - mem, 0);
                r = hb_lazy_flags_materialize(ctx, HB_FLAG_BIT_ZF | HB_FLAG_BIT_SF |
                                                   HB_FLAG_BIT_AF | HB_FLAG_BIT_PF |
                                                   HB_FLAG_BIT_CF | HB_FLAG_BIT_OF);
                if (r != HB_OK) return r;

                rdi = (uint64_t)((int64_t)rdi + step);
                if (repeated) count--;
                if (!repeated) break;
                if (rep == 0xf2 && ctx->flags.zf) break;  /* REPNE/REPNZ stops on match. */
                if (rep == 0xf3 && !ctx->flags.zf) break; /* REPE/REPZ stops on mismatch. */
                if (++iterations > hb_stringop_limit()) return HB_ERR_STEP_LIMIT;
            }

            if (mode32) {
                ctx->regs.x86.edi = (uint32_t)rdi;
                if (repeated) ctx->regs.x86.ecx = (uint32_t)count;
            } else {
                ctx->regs.x64.rdi = rdi;
                if (repeated) ctx->regs.x64.rcx = count;
            }
            return HB_OK;
        }

        case HB_IR_STOS: {
            hb_size_t size = instr->src1.size ? instr->src1.size : HB_SIZE_32;
            /* Итерация 491: префикс повтора берём из ОТДЕЛЬНОГО поля (заведено в 490 и
             * заполняется параллельно). Старое чтение из второго операнда оставлено
             * запасным, пока описание операндов не переведено на архитектурное: так
             * переключение проверяемо на каждом шаге, а не одним прыжком. */
            uint64_t rep = instr->rep_prefix ? (uint64_t)instr->rep_prefix :
                           ((instr->src2.type == HB_OP_IMM) ? (uint64_t)instr->src2.imm : 0);
            /* Итерация 503: у MOVS/LODS/STOS повтор определён ТОЛЬКО префиксом REP (0xF3).
             * REPNE (0xF2) для них архитектурно не задан, и эталон его повтором не считает:
             * стенд поймал `movsd f2a5` — ждали rcx=0x31, мы обнуляли до 0 (замер 502).
             * Пара REPE/REPNE осмысленна лишь у CMPS/SCAS, где есть с чем сравнивать. */
            /* Итерация 506: откат 503 — обоснование при MOVS выше. */
            bool repeated = (rep == 0xf2 || rep == 0xf3);
            bool mode32 = ctx->mode == HB_MODE_32BIT;
            uint64_t count = repeated ? (mode32 ? ctx->regs.x86.ecx : ctx->regs.x64.rcx) : 1;
            uint64_t rdi = mode32 ? ctx->regs.x86.edi : ctx->regs.x64.rdi;
            uint64_t acc = read_reg_sized(ctx, HB_REG_RAX, size, 0);
            int64_t step = (int64_t)size;
            if ((mode32 ? ctx->regs.x86.eflags : ctx->regs.x64.rflags) & (1ULL << 10))
                step = -step; /* Direction flag. */

            uint64_t iterations = 0;
            while (count > 0) {
                r = mem_write(ctx, rdi, acc, size);
                if (r != HB_OK) return r;
                rdi = (uint64_t)((int64_t)rdi + step);
                if (repeated) count--;
                if (!repeated) break;
                if (++iterations > hb_stringop_limit()) return HB_ERR_STEP_LIMIT;
            }

            if (mode32) {
                ctx->regs.x86.edi = (uint32_t)rdi;
                if (repeated) ctx->regs.x86.ecx = (uint32_t)count;
            } else {
                ctx->regs.x64.rdi = rdi;
                if (repeated) ctx->regs.x64.rcx = count;
            }
            return HB_OK;
        }

        case HB_IR_BSF: {
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            uint64_t val = 0;
            r = read_operand_value(ctx, &instr->src1, &val);
            if (r != HB_OK) return r;
            hb_size_t size = instr->dst.size ? instr->dst.size : HB_SIZE_64;
            uint64_t result = 0;
            val = trunc_to_size(val, size);
            hb_lazy_flags_clear(ctx);
            ctx->flags.zf = (val == 0);
            if (val) {
                while (((val >> result) & 1ULL) == 0) result++;
                write_reg_sized(ctx, instr->dst.reg, result, size);
            }
            return HB_OK;
        }

        case HB_IR_TZCNT: {
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            uint64_t val = 0;
            r = read_operand_value(ctx, &instr->src1, &val);
            if (r != HB_OK) return r;
            hb_size_t size = instr->dst.size ? instr->dst.size : HB_SIZE_64;
            val = trunc_to_size(val, size);
            uint64_t width = (size == HB_SIZE_32) ? 32 : (size == HB_SIZE_16) ? 16 : (size == HB_SIZE_8) ? 8 : 64;
            uint64_t result = width;
            if (val) {
                result = 0;
                while (((val >> result) & 1ULL) == 0) result++;
            }
            write_reg_sized(ctx, instr->dst.reg, result, size);
            hb_lazy_flags_clear(ctx);
            ctx->flags.zf = (result == 0);
            ctx->flags.cf = (val == 0);
            return HB_OK;
        }

        case HB_IR_LZCNT: {
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            uint64_t val = 0;
            r = read_operand_value(ctx, &instr->src1, &val);
            if (r != HB_OK) return r;
            hb_size_t size = instr->dst.size ? instr->dst.size : HB_SIZE_64;
            val = trunc_to_size(val, size);
            uint64_t width = (size == HB_SIZE_32) ? 32 : (size == HB_SIZE_16) ? 16 : (size == HB_SIZE_8) ? 8 : 64;
            uint64_t result = width;
            if (val) {
                result = 0;
                for (int64_t bit = (int64_t)width - 1; bit >= 0 && ((val >> bit) & 1ULL) == 0; bit--) result++;
            }
            write_reg_sized(ctx, instr->dst.reg, result, size);
            hb_lazy_flags_clear(ctx);
            ctx->flags.zf = (result == 0);
            ctx->flags.cf = (val == 0);
            return HB_OK;
        }

        case HB_IR_BSR: {
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            uint64_t val = 0;
            r = read_operand_value(ctx, &instr->src1, &val);
            if (r != HB_OK) return r;
            hb_size_t size = instr->dst.size ? instr->dst.size : HB_SIZE_64;
            uint64_t width = (size == HB_SIZE_32) ? 32 : (size == HB_SIZE_16) ? 16 : (size == HB_SIZE_8) ? 8 : 64;
            val = trunc_to_size(val, size);
            hb_lazy_flags_clear(ctx);
            ctx->flags.zf = (val == 0);
            if (val) {
                uint64_t result = width - 1;
                while (((val >> result) & 1ULL) == 0) result--;
                write_reg_sized(ctx, instr->dst.reg, result, size);
            }
            return HB_OK;
        }

        case HB_IR_POPCNT: {
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            uint64_t val = 0;
            r = read_operand_value(ctx, &instr->src1, &val);
            if (r != HB_OK) return r;
            hb_size_t size = instr->dst.size ? instr->dst.size : instr->src1.size;
            if (!size) size = HB_SIZE_64;
            val = trunc_to_size(val, size);
            uint64_t result = popcount_u64(val);
            write_reg_sized(ctx, instr->dst.reg, result, size);
            hb_lazy_flags_clear(ctx);
            ctx->flags.cf = false;
            ctx->flags.pf = false;
            ctx->flags.af = false;
            ctx->flags.zf = (val == 0);
            ctx->flags.sf = false;
            ctx->flags.of = false;
            return HB_OK;
        }

        case HB_IR_CRC32: {
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            uint64_t src = 0;
            r = read_operand_value(ctx, &instr->src1, &src);
            if (r != HB_OK) return r;
            hb_size_t src_size = instr->src1.size ? instr->src1.size : HB_SIZE_32;
            hb_size_t dst_size = instr->dst.size ? instr->dst.size : HB_SIZE_32;
            uint32_t crc = (uint32_t)read_reg_sized(ctx, instr->dst.reg, dst_size, 0);
            src = trunc_to_size(src, src_size);
            unsigned bytes = (src_size == HB_SIZE_8) ? 1u :
                             (src_size == HB_SIZE_16) ? 2u :
                             (src_size == HB_SIZE_64) ? 8u : 4u;
            for (unsigned byte = 0; byte < bytes; byte++) {
                crc ^= (uint8_t)(src >> (byte * 8u));
                for (unsigned bit = 0; bit < 8; bit++) {
                    crc = (crc >> 1) ^ ((crc & 1u) ? 0x82f63b78u : 0u);
                }
            }
            write_reg_sized(ctx, instr->dst.reg, (uint64_t)crc, dst_size);
            return HB_OK;
        }

        case HB_IR_ANDN:
        case HB_IR_BEXTR:
        case HB_IR_BLSI:
        case HB_IR_BLSMSK:
        case HB_IR_BLSR:
        case HB_IR_BZHI:
        case HB_IR_PDEP:
        case HB_IR_PEXT:
        case HB_IR_RORX:
        case HB_IR_SARX:
        case HB_IR_SHLX:
        case HB_IR_SHRX: {
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            hb_size_t size = instr->dst.size ? instr->dst.size : HB_SIZE_32;
            unsigned width = (size == HB_SIZE_64) ? 64u : 32u;
            uint64_t src1 = 0, src2 = 0;
            r = read_operand_value(ctx, &instr->src1, &src1);
            if (r != HB_OK) return r;
            if (instr->src2.type != HB_OP_NONE) {
                r = read_operand_value(ctx, &instr->src2, &src2);
                if (r != HB_OK) return r;
            }
            src1 = trunc_to_size(src1, size);
            src2 = trunc_to_size(src2, size);
            uint64_t result = 0;
            bool set_logic_flags = false;
            bool cf = false, of = false;
            if (instr->op == HB_IR_ANDN) {
                result = (~src1) & src2;
                set_logic_flags = true;
            } else if (instr->op == HB_IR_BEXTR) {
                unsigned start = (unsigned)(src2 & 0xffu);
                unsigned len = (unsigned)((src2 >> 8) & 0xffu);
                if (start < width && len != 0) {
                    unsigned avail = width - start;
                    if (len > avail) len = avail;
                    result = (src1 >> start) & (len >= 64 ? UINT64_MAX : ((1ULL << len) - 1ULL));
                }
                set_logic_flags = true;
            } else if (instr->op == HB_IR_BLSI) {
                result = src1 & (0ULL - src1);
                cf = src1 != 0;
                set_logic_flags = true;
            } else if (instr->op == HB_IR_BLSMSK) {
                result = src1 ^ (src1 - 1ULL);
                cf = src1 == 0;
                set_logic_flags = true;
            } else if (instr->op == HB_IR_BLSR) {
                result = src1 & (src1 - 1ULL);
                cf = src1 == 0;
                set_logic_flags = true;
            } else if (instr->op == HB_IR_BZHI) {
                unsigned index = (unsigned)(src2 & 0xffu);
                if (index >= width) {
                    result = src1;
                    cf = true;
                } else {
                    result = index == 0 ? 0 : (src1 & ((1ULL << index) - 1ULL));
                }
                set_logic_flags = true;
            } else if (instr->op == HB_IR_PEXT || instr->op == HB_IR_PDEP) {
                uint64_t src = src1, mask = src2, bit = 1;
                result = 0;
                while (mask) {
                    uint64_t lowest = mask & (0ULL - mask);
                    if (instr->op == HB_IR_PEXT) {
                        if (src & lowest) result |= bit;
                    } else {
                        if (src & bit) result |= lowest;
                    }
                    mask &= mask - 1ULL;
                    if (mask) bit <<= 1;
                }
            } else if (instr->op == HB_IR_RORX) {
                unsigned count = (unsigned)(instr->src2.imm & 0xffu) % width;
                result = count == 0 ? src1 : ((src1 >> count) | (src1 << (width - count)));
            } else {
                /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 353 — СЧЁТЧИК МАСКИРУЕТСЯ, А НЕ ОБНУЛЯЕТ.
                 *
                 * Было: `count = src2 & 0xff`, и при `count >= width` результат объявлялся нулём
                 * (для SARX — знаковым заполнением). Это поведение НЕ соответствует BMI2:
                 * `SARX`/`SHLX`/`SHRX` маскируют счётчик пятью битами при 32 разрядах и шестью
                 * при 64, ровно как соседняя `RORX` (она рядом делает `% width`). Из-за этого
                 * при большом значении регистра-счётчика мы отдавали НОЛЬ вместо значения.
                 *
                 * Замер, показавший это: три случая набора x64 — `c4e272f7c2` (sarx),
                 * `c4e271f7c2` (shlx), `c4e273f7c2` (shrx) — давали `reg.rax=0` при ожидаемых
                 * 0x1b9e, 0xc3100000 и 0x1b9e. Дамп IR подтвердил, что операнды верные
                 * (dst=rax, src1=rm, src2=vvvv), то есть виновата была арифметика счётчика. */
                unsigned count = (unsigned)(src2 & (uint64_t)(width - 1u));
                if (0) {
                    result = 0;
                } else if (instr->op == HB_IR_SARX) {
                    if (width == 64) result = (uint64_t)((int64_t)src1 >> count);
                    else result = (uint32_t)((int32_t)src1 >> count);
                } else if (instr->op == HB_IR_SHLX) {
                    result = src1 << count;
                } else {
                    result = src1 >> count;
                }
            }
            result = trunc_to_size(result, size);
            write_reg_sized(ctx, instr->dst.reg, result, size);
            if (set_logic_flags) {
                hb_lazy_flags_clear(ctx);
                ctx->flags.cf = cf;
                ctx->flags.of = of;
                ctx->flags.zf = (result == 0);
                ctx->flags.sf = ((result >> (width - 1)) & 1u) != 0;
                ctx->flags.pf = parity_even_u8((uint8_t)result);
                ctx->flags.af = false;
            }
            return HB_OK;
        }

        case HB_IR_MULX: {
            if (instr->dst.type != HB_OP_REG || instr->src1.type != HB_OP_REG) return HB_ERR_INTERNAL;
            hb_size_t size = instr->dst.size ? instr->dst.size : HB_SIZE_32;
            uint64_t src = 0;
            r = read_operand_value(ctx, &instr->src2, &src);
            if (r != HB_OK) return r;
            src = trunc_to_size(src, size);
            uint64_t implicit = read_reg_sized(ctx, HB_REG_RDX, size, 0);
            /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 356 — ПОЛОВИНЫ ПРОИЗВЕДЕНИЯ БЫЛИ
             * ПЕРЕПУТАНЫ МЕСТАМИ.
             *
             * `MULX r32a, r32b, r/m32`: `r32a` — это `ModRM.reg`, и он получает СТАРШУЮ половину;
             * `r32b` — это `VEX.vvvv`, и он получает МЛАДШУЮ. У нас было наоборот: `dst` (то есть
             * `ModRM.reg`) писался младшей половиной, а `src1` (`VEX.vvvv`) — старшей.
             *
             * Дамп IR подтвердил, что сами регистры разобраны верно: на `c4e273f6c2` получаем
             * `dst=reg0 (rax, ModRM.reg)`, `src1=reg1 (rcx, VEX.vvvv)`, `src2=reg2 (rdx)`.
             * Значит расхождение было именно в том, КУДА кладутся половины, а не в том, что
             * читается. Оба случая набора x64 (`c4e273f6c2`, `c4e2f3f6c2`) расходились по
             * `reg.rax` и `reg.rcx` одновременно — подпись перестановки, а не арифметики. */
            /* MacRunner 2026-08-17, лейн ЛЕСТНИЦА, итерация 1435 — ПОРЯДОК ЗАПИСИ ПОЛОВИН.
             *
             * Половины кладутся верно (это правка 356), но ПОРЯДОК записи был обратным, и при
             * `dst == src1` (один и тот же регистр назначен обоим приёмникам) младшая половина
             * затирала старшую. x86 требует обратного: младшая пишется первой, старшая — второй,
             * поэтому при совпадении регистров остаётся СТАРШАЯ.
             *
             * Этот дефект был СЛЕП ДЛЯ НАШЕГО ГЛАВНОГО ПРИБОРА: выпуск повторял интерпретатор
             * дословно, поэтому сличитель интерпретатор-против-выпуска не расходился ни разу
             * (27 сличений MULX, совпало 27). Обе стороны были неправы ОДИНАКОВО.
             *
             * ЗАМЕР, который спор решил (проба `tools/hb_isa_coverage/oracles/mulx_alias.c`,
             * исполнена на x86-64 под Rosetta, edx=12345678 src=9ABCDEF0):
             *     произведение 0B00EA4E242D2080, старшая 0B00EA4E, младшая 242D2080
             *     контроль (приёмники разные)  старшая 0B00EA4E, младшая 242D2080  СОВПАЛО
             *     ★ алиас dst==src1            получено 0B00EA4E = СТАРШАЯ
             *
             * Обе половины считаются ДО записи, поэтому перестановка записей безопасна. */
            if (size == HB_SIZE_64) {
                __uint128_t product = (__uint128_t)implicit * (__uint128_t)src;
                write_reg_sized(ctx, instr->src1.reg, (uint64_t)product, HB_SIZE_64);
                write_reg_sized(ctx, instr->dst.reg, (uint64_t)(product >> 64), HB_SIZE_64);
            } else {
                uint64_t product = (uint64_t)(uint32_t)implicit * (uint64_t)(uint32_t)src;
                write_reg_sized(ctx, instr->src1.reg, (uint32_t)product, HB_SIZE_32);
                write_reg_sized(ctx, instr->dst.reg, (uint32_t)(product >> 32), HB_SIZE_32);
            }
            return HB_OK;
        }

        case HB_IR_ADCX:
        case HB_IR_ADOX: {
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            r = hb_lazy_flags_materialize(ctx, HB_FLAG_BIT_ALL);
            if (r != HB_OK) return r;
            uint64_t dst = read_reg_sized(ctx, instr->dst.reg, instr->dst.size, 0);
            uint64_t src = 0;
            r = read_operand_value(ctx, &instr->src1, &src);
            if (r != HB_OK) return r;
            hb_size_t size = instr->dst.size ? instr->dst.size : HB_SIZE_32;
            dst = trunc_to_size(dst, size);
            src = trunc_to_size(src, size);
            uint64_t carry_in = (instr->op == HB_IR_ADCX) ? (ctx->flags.cf ? 1u : 0u)
                                                          : (ctx->flags.of ? 1u : 0u);
            __uint128_t sum = (__uint128_t)dst + (__uint128_t)src + carry_in;
            uint64_t result = trunc_to_size((uint64_t)sum, size);
            unsigned width = (size == HB_SIZE_64) ? 64u : 32u;
            bool carry_out = (sum >> width) != 0;
            write_reg_sized(ctx, instr->dst.reg, result, size);
            hb_lazy_flags_clear(ctx);
            if (instr->op == HB_IR_ADCX) ctx->flags.cf = carry_out;
            else ctx->flags.of = carry_out;
            return HB_OK;
        }

        case HB_IR_BSWAP: {
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            hb_size_t size = instr->dst.size ? instr->dst.size : HB_SIZE_32;
            uint64_t val = read_reg(ctx, instr->dst.reg);
            if (size == HB_SIZE_64) {
                val = ((val & 0x00000000000000ffULL) << 56) |
                      ((val & 0x000000000000ff00ULL) << 40) |
                      ((val & 0x0000000000ff0000ULL) << 24) |
                      ((val & 0x00000000ff000000ULL) << 8)  |
                      ((val & 0x000000ff00000000ULL) >> 8)  |
                      ((val & 0x0000ff0000000000ULL) >> 24) |
                      ((val & 0x00ff000000000000ULL) >> 40) |
                      ((val & 0xff00000000000000ULL) >> 56);
                write_reg_sized(ctx, instr->dst.reg, val, HB_SIZE_64);
            } else if (size == HB_SIZE_32) {
                uint32_t v = (uint32_t)val;
                v = ((v & 0x000000ffU) << 24) |
                    ((v & 0x0000ff00U) << 8)  |
                    ((v & 0x00ff0000U) >> 8)  |
                    ((v & 0xff000000U) >> 24);
                write_reg_sized(ctx, instr->dst.reg, v, HB_SIZE_32);
            } else if (size == HB_SIZE_16) {
                /* 16-битная форма (`66 0F C8`). Спецификация её поведение НЕ
                 * ОПРЕДЕЛЯЕТ, поэтому спрошено ИСПОЛНЕНИЕМ у оракула:
                 * при eax = 0x11223344 команда `bswap ax` даёт 0x11220000 —
                 * младшие 16 бит обнуляются, старшие сохраняются.
                 * Прежде здесь стоял отказ, и объявить верный размер операнда
                 * было нельзя: семь случаев падали с -5. */
                write_reg_sized(ctx, instr->dst.reg, 0, HB_SIZE_16);
            } else {
                return HB_ERR_UNSUPPORTED_OPCODE;
            }
            return HB_OK;
        }

        case HB_IR_MOVBE: {
            hb_size_t size = (hb_size_t)(instr->target ? instr->target : instr->dst.size);
            if (!(size == HB_SIZE_16 || size == HB_SIZE_32 || size == HB_SIZE_64)) {
                return HB_ERR_INTERNAL;
            }
            uint64_t value = 0;
            r = read_operand_value(ctx, &instr->src1, &value);
            if (r != HB_OK) return r;
            value = bswap_sized_value(value, size);
            return write_operand_value(ctx, &instr->dst, value);
        }

        case HB_IR_MOVDIR64B: {
            if (instr->dst.type != HB_OP_REG || instr->src1.type != HB_OP_MEM) return HB_ERR_INTERNAL;
            uint8_t bytes[64];
            uint64_t dst_addr = read_reg_sized(ctx, instr->dst.reg, HB_SIZE_64, instr->dst.reg_offset);
            uint64_t src_addr = resolve_addr(ctx, &instr->src1);
            r = hb_memory_read(ctx->memory, src_addr, bytes, sizeof(bytes));
            if (r != HB_OK) return r;
            return hb_memory_write(ctx->memory, dst_addr, bytes, sizeof(bytes));
        }

        case HB_IR_XMM_AND:
        case HB_IR_XMM_ANDN:
        case HB_IR_XMM_OR:
        case HB_IR_XORPS: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint32_t arg = evex_target_arg(instr);
            bool broadcast = (arg & HB_EVEX_ARG_BROADCAST) != 0;
            unsigned lane = arg & 0xffu;
            if (!(lane == 4 || lane == 8)) lane = 4;
            uint8_t lhs[64], rhs[64], out[64];
            r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, broadcast ? lane : bytes);
            if (r != HB_OK) return r;
            if (broadcast) {
                for (unsigned i = 1; i < (unsigned)(bytes / lane); i++)
                    memcpy(rhs + i * lane, rhs, lane);
            }
            for (size_t n = 0; n < bytes; n++) {
                if (instr->op == HB_IR_XMM_AND) out[n] = lhs[n] & rhs[n];
                else if (instr->op == HB_IR_XMM_ANDN) out[n] = (uint8_t)(~lhs[n] & rhs[n]);
                else if (instr->op == HB_IR_XMM_OR) out[n] = lhs[n] | rhs[n];
                else out[n] = lhs[n] ^ rhs[n];
            }
            return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, lane);
        }

        case HB_IR_XMM_SCALAR_MOV: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            unsigned lane = (unsigned)(instr->target & 0xffu);
            if (!(lane == 4 || lane == 8)) return HB_ERR_INTERNAL;
            uint8_t out[16] = {0};
            uint8_t scalar[8] = {0};
            if (instr->src1.type != HB_OP_NONE) {
                r = read_xmm_operand_bytes(ctx, &instr->src1, out, sizeof(out));
                if (r != HB_OK) return r;
            }
            r = read_xmm_operand_bytes(ctx, &instr->src2, scalar, lane);
            if (r != HB_OK) return r;
            memcpy(out, scalar, lane);
            return write_vec_reg_bytes_evex_scalar_masked(ctx, instr, out, lane);
        }

        case HB_IR_PCMPEQB:
        case HB_IR_PCMPEQW:
        case HB_IR_PCMPEQD: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t lbytes[64], rbytes[64], obytes[64] = {0};
            unsigned lane = instr->op == HB_IR_PCMPEQB ? 1 : (instr->op == HB_IR_PCMPEQW ? 2 : 4);
            r = read_xmm_operand_bytes(ctx, &instr->src1, lbytes, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, rbytes, bytes);
            if (r != HB_OK) return r;
            for (unsigned i = 0; i < bytes; i += lane) {
                if (!memcmp(lbytes + i, rbytes + i, lane))
                    memset(obytes + i, 0xff, lane);
            }
            return write_vec_reg_bytes_evex_masked(ctx, instr, obytes, bytes, lane);
        }

        case HB_IR_PCMPGTB:
        case HB_IR_PCMPGTW:
        case HB_IR_PCMPGTD: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t lbytes[64], rbytes[64], obytes[64] = {0};
            unsigned lane = instr->op == HB_IR_PCMPGTB ? 1 : (instr->op == HB_IR_PCMPGTW ? 2 : 4);
            r = read_xmm_operand_bytes(ctx, &instr->src1, lbytes, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, rbytes, bytes);
            if (r != HB_OK) return r;
            for (unsigned i = 0; i < bytes; i += lane) {
                bool gt = false;
                if (lane == 1) gt = *(int8_t *)(lbytes + i) > *(int8_t *)(rbytes + i);
                else if (lane == 2) {
                    int16_t a, b;
                    memcpy(&a, lbytes + i, sizeof(a));
                    memcpy(&b, rbytes + i, sizeof(b));
                    gt = a > b;
                } else {
                    int32_t a, b;
                    memcpy(&a, lbytes + i, sizeof(a));
                    memcpy(&b, rbytes + i, sizeof(b));
                    gt = a > b;
                }
                if (gt) memset(obytes + i, 0xff, lane);
            }
            return write_vec_reg_bytes_evex_masked(ctx, instr, obytes, bytes, lane);
        }

        case HB_IR_PMOVMSKB: {
            if (instr->dst.type != HB_OP_REG || instr->src1.type != HB_OP_REG ||
                !is_vec_or_mm_reg(instr->src1.reg)) return HB_ERR_INTERNAL;
            if (is_mm_reg(instr->src1.reg)) {
                const uint64_t* mm = hb_mmx_regs(ctx);
                uint8_t b8[8];
                uint32_t m8 = 0;
                unsigned i8;
                if (!mm) return HB_ERR_INTERNAL;
                memcpy(b8, &mm[instr->src1.reg - HB_REG_MM0], sizeof(b8));
                for (i8 = 0; i8 < 8; i8++)
                    if (b8[i8] & 0x80) m8 |= (uint32_t)1 << i8;
                write_reg_sized(ctx, instr->dst.reg, m8, HB_SIZE_32);
                return HB_OK;
            }
            /* ★ ШИРИНА ИСТОЧНИКА — ИЗ ОПЕРАНДА, А НЕ ЗАШИТЫЕ 16 БАЙТОВ.
             * У формы VEX.256 (`vpmovmskb rax, ymm0`) разрядов тридцать два;
             * зашитая шестнадцатка давала только младшую половину — замерено
             * 0xb5ab против 0x419db5ab у оракула. */
            uint8_t bytes[32];
            uint32_t mask = 0;
            size_t shirina = bytes_for_size(instr->src1.size);
            if (shirina != 32) shirina = 16;
            r = read_vec_reg_bytes(ctx, instr->src1.reg, bytes, shirina);
            if (r != HB_OK) return r;
            for (unsigned i = 0; i < shirina; i++)
                if (bytes[i] & 0x80) mask |= (uint32_t)1 << i;
            write_reg_sized(ctx, instr->dst.reg, mask, HB_SIZE_32);
            return HB_OK;
        }

        case HB_IR_MOVMSK: {
            if (instr->dst.type != HB_OP_REG || instr->src1.type != HB_OP_REG ||
                !is_xmm_reg(instr->src1.reg)) return HB_ERR_INTERNAL;
            uint8_t bytes[32];
            uint32_t mask = 0;
            unsigned lane = (unsigned)(instr->target & 0xff);
            size_t shirina = bytes_for_size(instr->src1.size);
            if (shirina != 32) shirina = 16;      /* та же причина, что у PMOVMSKB выше */
            if (!(lane == 4 || lane == 8)) return HB_ERR_INTERNAL;
            r = read_vec_reg_bytes(ctx, instr->src1.reg, bytes, shirina);
            if (r != HB_OK) return r;
            for (unsigned i = 0, bit = 0; i < shirina; i += lane, bit++)
                if (bytes[i + lane - 1] & 0x80) mask |= (uint32_t)1 << bit;
            write_reg_sized(ctx, instr->dst.reg, mask, HB_SIZE_32);
            return HB_OK;
        }

        case HB_IR_PUNPCK: {
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 882 — ФОРМА MMX.
             * Разбор `punpck mm, mm/m64` добавлен в декодер в 881, но здесь стояла проверка
             * «приёмник обязан быть xmm», и обе формы отвечали HB_ERR_INTERNAL (-99).
             * Ветвь построена по образцу PACKSSWB/PACKUSWB/PACKSSDW ниже (итерация 522),
             * включая запись через наложение на x87.
             * ★ Тонкость, которой нет у XMM: у MMX «половина» источника — ЧЕТЫРЕ байта, а не
             * восемь. `PUNPCKL*` берут младшие 4 байта каждого источника, `PUNPCKH*` — старшие,
             * и чередованием получают ровно 8 байт результата. Ширина полосы: BW=1, WD=2, DQ=4;
             * полосы 8 (QDQ) в MMX не существует — декодер её и не пропускает. */
            if (instr->dst.type == HB_OP_REG &&
                instr->dst.reg >= HB_REG_MM0 && instr->dst.reg <= HB_REG_MM7) {
                uint64_t* mm = hb_mmx_regs(ctx);
                uint64_t a = 0, bv = 0, res8 = 0;
                uint8_t l8[8], r8[8], o8[8] = {0};
                if (instr->src1.type == HB_OP_REG &&
                    instr->src1.reg >= HB_REG_MM0 && instr->src1.reg <= HB_REG_MM7)
                    a = mm[instr->src1.reg - HB_REG_MM0];
                else return HB_ERR_UNSUPPORTED_FEATURE;
                if (instr->src2.type == HB_OP_REG &&
                    instr->src2.reg >= HB_REG_MM0 && instr->src2.reg <= HB_REG_MM7)
                    bv = mm[instr->src2.reg - HB_REG_MM0];
                else if (instr->src2.type == HB_OP_MEM) {
                    /* У нижних распаковок операнд-память 4 байта, у верхних 8 — размер уже
                     * проставлен декодером, читаем ровно столько, сколько он назвал. */
                    size_t n = bytes_for_size(instr->src2.size);
                    if (n == 0 || n > 8) n = 8;
                    r = hb_memory_read(ctx->memory, resolve_addr(ctx, &instr->src2), &bv, n);
                    if (r != HB_OK) return r;
                } else return HB_ERR_UNSUPPORTED_FEATURE;
                memcpy(l8, &a, 8); memcpy(r8, &bv, 8);
                {
                    uint32_t target_mm = evex_target_arg(instr);
                    unsigned lane_mm = (unsigned)(target_mm & 0xff);
                    bool high_mm = (target_mm & 0x100) != 0;
                    unsigned start_mm, lanes_mm, out_mm = 0, i;
                    if (!(lane_mm == 1 || lane_mm == 2 || lane_mm == 4)) return HB_ERR_INTERNAL;
                    start_mm = high_mm ? 4u : 0u;
                    lanes_mm = 4u / lane_mm;
                    for (i = 0; i < lanes_mm; i++) {
                        unsigned off = start_mm + i * lane_mm;
                        memcpy(o8 + out_mm, l8 + off, lane_mm); out_mm += lane_mm;
                        memcpy(o8 + out_mm, r8 + off, lane_mm); out_mm += lane_mm;
                    }
                }
                memcpy(&res8, o8, 8);
                mm[instr->dst.reg - HB_REG_MM0] = res8;
                hb_x87_mmx_write(hb_context_x87(ctx),
                                 (unsigned)(instr->dst.reg - HB_REG_MM0), res8);
                return HB_OK;
            }
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t lbytes[64], rbytes[64], obytes[64] = {0};
            r = read_xmm_operand_bytes(ctx, &instr->src1, lbytes, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, rbytes, bytes);
            if (r != HB_OK) return r;
            uint32_t target = evex_target_arg(instr);
            unsigned lane = (unsigned)(target & 0xff);
            bool high = (target & 0x100) != 0;
            if (!(lane == 1 || lane == 2 || lane == 4 || lane == 8)) return HB_ERR_INTERNAL;
            for (size_t base = 0; base < bytes; base += 16) {
                unsigned start = high ? 8 : 0;
                unsigned lanes = 8 / lane;
                unsigned out_pos = (unsigned)base;
                for (unsigned i = 0; i < lanes; i++) {
                    unsigned off = (unsigned)base + start + i * lane;
                    memcpy(obytes + out_pos, lbytes + off, lane);
                    out_pos += lane;
                    memcpy(obytes + out_pos, rbytes + off, lane);
                    out_pos += lane;
                }
            }
            return write_vec_reg_bytes_evex_masked(ctx, instr, obytes, bytes, lane);
        }

        case HB_IR_PACKSSWB:
        case HB_IR_PACKUSWB:
        case HB_IR_PACKSSDW: {
            /* Итерация 522: форма MMX. Половина результата берётся из первого источника,
             * половина из второго — как и в форме XMM, только ширина восемь байт. Запись
             * проводится через наложение на x87 (519). */
            if (instr->dst.type == HB_OP_REG &&
                instr->dst.reg >= HB_REG_MM0 && instr->dst.reg <= HB_REG_MM7) {
                uint64_t* mm = hb_mmx_regs(ctx);
                uint8_t l8[8], r8[8], o8[8] = {0};
                uint64_t a = 0, bv = 0, res8 = 0;
                if (instr->src1.type == HB_OP_REG &&
                    instr->src1.reg >= HB_REG_MM0 && instr->src1.reg <= HB_REG_MM7)
                    a = mm[instr->src1.reg - HB_REG_MM0];
                else return HB_ERR_UNSUPPORTED_FEATURE;
                if (instr->src2.type == HB_OP_REG &&
                    instr->src2.reg >= HB_REG_MM0 && instr->src2.reg <= HB_REG_MM7)
                    bv = mm[instr->src2.reg - HB_REG_MM0];
                else if (instr->src2.type == HB_OP_MEM) {
                    r = hb_memory_read(ctx->memory, resolve_addr(ctx, &instr->src2), &bv, 8);
                    if (r != HB_OK) return r;
                } else return HB_ERR_UNSUPPORTED_FEATURE;
                memcpy(l8, &a, 8); memcpy(r8, &bv, 8);
                if (instr->op == HB_IR_PACKSSDW) {
                    for (unsigned i = 0; i < 2; i++) {
                        int32_t v; int16_t o;
                        memcpy(&v, l8 + i * 4, sizeof(v));
                        o = v > 32767 ? 32767 : (v < -32768 ? -32768 : (int16_t)v);
                        memcpy(o8 + i * 2, &o, sizeof(o));
                        memcpy(&v, r8 + i * 4, sizeof(v));
                        o = v > 32767 ? 32767 : (v < -32768 ? -32768 : (int16_t)v);
                        memcpy(o8 + 4 + i * 2, &o, sizeof(o));
                    }
                } else {
                    for (unsigned i = 0; i < 4; i++) {
                        int16_t v;
                        memcpy(&v, l8 + i * 2, sizeof(v));
                        o8[i] = (instr->op == HB_IR_PACKUSWB)
                              ? (uint8_t)(v > 255 ? 255 : (v < 0 ? 0 : v))
                              : (uint8_t)(int8_t)(v > 127 ? 127 : (v < -128 ? -128 : v));
                        memcpy(&v, r8 + i * 2, sizeof(v));
                        o8[4 + i] = (instr->op == HB_IR_PACKUSWB)
                              ? (uint8_t)(v > 255 ? 255 : (v < 0 ? 0 : v))
                              : (uint8_t)(int8_t)(v > 127 ? 127 : (v < -128 ? -128 : v));
                    }
                }
                memcpy(&res8, o8, 8);
                mm[instr->dst.reg - HB_REG_MM0] = res8;
                hb_x87_mmx_write(hb_context_x87(ctx),
                                 (unsigned)(instr->dst.reg - HB_REG_MM0), res8);
                return HB_OK;
            }
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t lhs[64], rhs[64], obytes[64] = {0};
            r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, bytes);
            if (r != HB_OK) return r;

            for (size_t base = 0; base < bytes; base += 16) {
                if (instr->op == HB_IR_PACKSSDW) {
                    for (unsigned i = 0; i < 4; i++) {
                        int32_t v;
                        int16_t o;
                        memcpy(&v, lhs + base + i * 4, sizeof(v));
                        o = v > 32767 ? 32767 : (v < -32768 ? -32768 : (int16_t)v);
                        memcpy(obytes + base + i * 2, &o, sizeof(o));
                    }
                    for (unsigned i = 0; i < 4; i++) {
                        int32_t v;
                        int16_t o;
                        memcpy(&v, rhs + base + i * 4, sizeof(v));
                        o = v > 32767 ? 32767 : (v < -32768 ? -32768 : (int16_t)v);
                        memcpy(obytes + base + 8 + i * 2, &o, sizeof(o));
                    }
                } else {
                    for (unsigned i = 0; i < 8; i++) {
                        int16_t v;
                        memcpy(&v, lhs + base + i * 2, sizeof(v));
                        if (instr->op == HB_IR_PACKUSWB)
                            obytes[base + i] = v < 0 ? 0 : (v > 255 ? 255 : (uint8_t)v);
                        else
                            obytes[base + i] = (uint8_t)(v > 127 ? 127 : (v < -128 ? -128 : v));
                    }
                    for (unsigned i = 0; i < 8; i++) {
                        int16_t v;
                        memcpy(&v, rhs + base + i * 2, sizeof(v));
                        if (instr->op == HB_IR_PACKUSWB)
                            obytes[base + 8 + i] = v < 0 ? 0 : (v > 255 ? 255 : (uint8_t)v);
                        else
                            obytes[base + 8 + i] = (uint8_t)(v > 127 ? 127 : (v < -128 ? -128 : v));
                    }
                }
            }
            return write_vec_reg_bytes_evex_masked(ctx, instr, obytes, bytes,
                                                   instr->op == HB_IR_PACKSSDW ? 2 : 1);
        }

        case HB_IR_PMULLW:
        case HB_IR_PMULHW:
        case HB_IR_PMULHUW:
        case HB_IR_PMADDWD: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t lhs[64], rhs[64], out[64] = {0};
            r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, bytes);
            if (r != HB_OK) return r;

            if (instr->op == HB_IR_PMADDWD) {
                for (size_t off = 0; off < bytes; off += 4) {
                    int16_t a0, a1, b0, b1;
                    int32_t value;
                    memcpy(&a0, lhs + off, sizeof(a0));
                    memcpy(&a1, lhs + off + 2, sizeof(a1));
                    memcpy(&b0, rhs + off, sizeof(b0));
                    memcpy(&b1, rhs + off + 2, sizeof(b1));
                    value = (int32_t)a0 * (int32_t)b0 + (int32_t)a1 * (int32_t)b1;
                    memcpy(out + off, &value, sizeof(value));
                }
            } else {
                for (size_t off = 0; off < bytes; off += 2) {
                    uint16_t value;
                    if (instr->op == HB_IR_PMULHUW) {
                        uint16_t a, b;
                        memcpy(&a, lhs + off, sizeof(a));
                        memcpy(&b, rhs + off, sizeof(b));
                        value = (uint16_t)(((uint32_t)a * (uint32_t)b) >> 16);
                    } else {
                        int16_t a, b;
                        memcpy(&a, lhs + off, sizeof(a));
                        memcpy(&b, rhs + off, sizeof(b));
                        int32_t p = (int32_t)a * (int32_t)b;
                        value = (uint16_t)(instr->op == HB_IR_PMULLW ? p : (p >> 16));
                    }
                    memcpy(out + off, &value, sizeof(value));
                }
            }
            return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes,
                                                   instr->op == HB_IR_PMADDWD ? 4 : 2);
        }

        case HB_IR_PADDSB:
        case HB_IR_PADDSW:
        case HB_IR_PADDUSB:
        case HB_IR_PADDUSW:
        case HB_IR_PAVGB:
        case HB_IR_PAVGW: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t lbytes[64], rbytes[64], obytes[64] = {0};
            r = read_xmm_operand_bytes(ctx, &instr->src1, lbytes, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, rbytes, bytes);
            if (r != HB_OK) return r;

            if (instr->op == HB_IR_PADDSB || instr->op == HB_IR_PADDUSB || instr->op == HB_IR_PAVGB) {
                for (unsigned i = 0; i < bytes; i++) {
                    if (instr->op == HB_IR_PAVGB) {
                        obytes[i] = (uint8_t)(((unsigned)lbytes[i] + (unsigned)rbytes[i] + 1u) >> 1);
                    } else if (instr->op == HB_IR_PADDUSB) {
                        unsigned v = (unsigned)lbytes[i] + (unsigned)rbytes[i];
                        obytes[i] = (uint8_t)(v > 255u ? 255u : v);
                    } else {
                        int v = (int)(int8_t)lbytes[i] + (int)(int8_t)rbytes[i];
                        if (v > 127) v = 127;
                        else if (v < -128) v = -128;
                        obytes[i] = (uint8_t)(int8_t)v;
                    }
                }
            } else {
                for (unsigned i = 0; i < bytes; i += 2) {
                    uint16_t a, b, value;
                    memcpy(&a, lbytes + i, sizeof(a));
                    memcpy(&b, rbytes + i, sizeof(b));
                    if (instr->op == HB_IR_PAVGW) {
                        value = (uint16_t)(((uint32_t)a + (uint32_t)b + 1u) >> 1);
                    } else if (instr->op == HB_IR_PADDUSW) {
                        uint32_t v = (uint32_t)a + (uint32_t)b;
                        value = (uint16_t)(v > 65535u ? 65535u : v);
                    } else {
                        int32_t v = (int32_t)(int16_t)a + (int32_t)(int16_t)b;
                        if (v > 32767) v = 32767;
                        else if (v < -32768) v = -32768;
                        value = (uint16_t)(int16_t)v;
                    }
                    memcpy(obytes + i, &value, sizeof(value));
                }
            }
            return write_vec_reg_bytes_evex_masked(ctx, instr, obytes, bytes,
                                                   (instr->op == HB_IR_PADDSB || instr->op == HB_IR_PADDUSB ||
                                                    instr->op == HB_IR_PAVGB) ? 1 : 2);
        }

        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — партия 4: насыщающее вычитание и PSADBW.
         * Вид взят у соседнего блока насыщающего сложения (партия 1): те же чтения
         * операндов и та же запись с шириной дорожки. Насыщение считаем в расширенном
         * типе и зажимаем, как принято выше. PSADBW складывает |a-b| по восьмёрке байт
         * и кладёт сумму в младшее слово каждой половины — остальные слова нулевые. */
        case HB_IR_PSUBSB:
        case HB_IR_PSUBSW:
        case HB_IR_PSUBUSB:
        case HB_IR_PSUBUSW:
        case HB_IR_PSADBW: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t lbytes[64], rbytes[64], obytes[64] = {0};
            r = read_xmm_operand_bytes(ctx, &instr->src1, lbytes, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, rbytes, bytes);
            if (r != HB_OK) return r;

            if (instr->op == HB_IR_PSADBW) {
                for (unsigned base = 0; base + 8 <= bytes; base += 8) {
                    uint32_t sum = 0;
                    for (unsigned i = 0; i < 8; i++) {
                        int d8 = (int)lbytes[base + i] - (int)rbytes[base + i];
                        sum += (uint32_t)(d8 < 0 ? -d8 : d8);
                    }
                    uint16_t low = (uint16_t)sum;
                    memcpy(obytes + base, &low, sizeof(low));
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, obytes, bytes, 2);
            }

            if (instr->op == HB_IR_PSUBSB || instr->op == HB_IR_PSUBUSB) {
                for (unsigned i = 0; i < bytes; i++) {
                    if (instr->op == HB_IR_PSUBUSB) {
                        int v = (int)lbytes[i] - (int)rbytes[i];
                        obytes[i] = (uint8_t)(v < 0 ? 0 : v);
                    } else {
                        int v = (int)(int8_t)lbytes[i] - (int)(int8_t)rbytes[i];
                        if (v > 127) v = 127;
                        else if (v < -128) v = -128;
                        obytes[i] = (uint8_t)(int8_t)v;
                    }
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, obytes, bytes, 1);
            }

            for (unsigned i = 0; i < bytes; i += 2) {
                uint16_t a, b, value;
                memcpy(&a, lbytes + i, sizeof(a));
                memcpy(&b, rbytes + i, sizeof(b));
                if (instr->op == HB_IR_PSUBUSW) {
                    int32_t v = (int32_t)a - (int32_t)b;
                    value = (uint16_t)(v < 0 ? 0 : v);
                } else {
                    int32_t v = (int32_t)(int16_t)a - (int32_t)(int16_t)b;
                    if (v > 32767) v = 32767;
                    else if (v < -32768) v = -32768;
                    value = (uint16_t)(int16_t)v;
                }
                memcpy(obytes + i, &value, sizeof(value));
            }
            return write_vec_reg_bytes_evex_masked(ctx, instr, obytes, bytes, 2);
        }

        case HB_IR_PSHUFB: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t src[64] = {0}, mask[64] = {0}, obytes[64] = {0};
            r = read_xmm_operand_bytes(ctx, &instr->src1, src, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, mask, bytes);
            if (r != HB_OK) return r;
            for (size_t i = 0; i < bytes; i++) {
                size_t lane_mask = bytes == 8 ? 0x07u : 0x0fu;
                size_t base = bytes == 8 ? 0 : (i & ~(size_t)0x0f);
                obytes[i] = (mask[i] & 0x80) ? 0 : src[base + (mask[i] & lane_mask)];
            }
            return write_vec_reg_bytes_evex_masked(ctx, instr, obytes, bytes, 1);
        }

        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — MMX-ФОРМЫ.
         * У MMX регистр 64-битный: четыре слова вместо восьми (маска дорожки 3, а не
         * 7) и восемь знаковых битов вместо шестнадцати. Хранилище отдельное
         * (`hb_mmx_regs`), `read_xmm_reg` его не принимает — оттого своя ветка. */
        case HB_IR_PINSRW: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            if (is_mm_reg(instr->dst.reg)) {
                uint64_t* mm = hb_mmx_regs(ctx);
                uint64_t word = 0;
                unsigned lane8 = (unsigned)(instr->target & 3u);
                uint8_t b8[8];
                if (!mm) return HB_ERR_INTERNAL;
                r = read_operand_value(ctx, &instr->src2, &word);
                if (r != HB_OK) return r;
                memcpy(b8, &mm[instr->dst.reg - HB_REG_MM0], sizeof(b8));
                b8[lane8 * 2] = (uint8_t)(word & 0xffu);
                b8[lane8 * 2 + 1] = (uint8_t)((word >> 8) & 0xffu);
                memcpy(&mm[instr->dst.reg - HB_REG_MM0], b8, sizeof(b8));
                return HB_OK;
            }
            uint64_t xmm[2], out[2] = {0, 0};
            uint8_t bytes[16];
            uint64_t word = 0;
            unsigned lane = (unsigned)(instr->target & 7u);
            r = read_xmm_operand(ctx, &instr->src1, xmm);
            if (r != HB_OK) return r;
            r = read_operand_value(ctx, &instr->src2, &word);
            if (r != HB_OK) return r;
            memcpy(bytes, xmm, sizeof(bytes));
            bytes[lane * 2] = (uint8_t)(word & 0xffu);
            bytes[lane * 2 + 1] = (uint8_t)((word >> 8) & 0xffu);
            memcpy(out, bytes, sizeof(bytes));
            return write_xmm_reg(ctx, instr->dst.reg, out);
        }

        case HB_IR_PEXTRW: {
            if (instr->dst.type != HB_OP_REG || is_xmm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            if (instr->src1.type == HB_OP_REG && is_mm_reg(instr->src1.reg)) {
                const uint64_t* mm = hb_mmx_regs(ctx);
                unsigned lane8 = (unsigned)(instr->target & 3u);
                uint8_t b8[8];
                uint16_t w8;
                if (!mm) return HB_ERR_INTERNAL;
                memcpy(b8, &mm[instr->src1.reg - HB_REG_MM0], sizeof(b8));
                w8 = (uint16_t)b8[lane8 * 2] | ((uint16_t)b8[lane8 * 2 + 1] << 8);
                return write_operand_value(ctx, &instr->dst, w8);
            }
            uint64_t xmm[2];
            uint8_t bytes[16];
            unsigned lane = (unsigned)(instr->target & 7u);
            r = read_xmm_operand(ctx, &instr->src1, xmm);
            if (r != HB_OK) return r;
            memcpy(bytes, xmm, sizeof(bytes));
            uint16_t word = (uint16_t)bytes[lane * 2] | ((uint16_t)bytes[lane * 2 + 1] << 8);
            return write_operand_value(ctx, &instr->dst, word);
        }

        case HB_IR_INSERTPS: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            uint8_t out[16], src[16] = {0};
            unsigned imm = (unsigned)(instr->target & 0xffu);
            unsigned src_lane = (imm >> 6) & 3u;
            unsigned dst_lane = (imm >> 4) & 3u;
            r = read_xmm_operand_bytes(ctx, &instr->src1, out, 16);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, src, instr->src2.type == HB_OP_MEM ? 4 : 16);
            if (r != HB_OK) return r;
            memcpy(out + dst_lane * 4, src + (instr->src2.type == HB_OP_MEM ? 0 : src_lane * 4), 4);
            for (unsigned lane = 0; lane < 4; lane++) {
                if (imm & (1u << lane)) memset(out + lane * 4, 0, 4);
            }
            return write_vec_reg_bytes(ctx, instr->dst.reg, out, 16);
        }

        case HB_IR_EXTRACTPS: {
            uint8_t src[16];
            uint32_t value;
            unsigned lane = (unsigned)(instr->target & 3u);
            r = read_xmm_operand_bytes(ctx, &instr->src1, src, 16);
            if (r != HB_OK) return r;
            memcpy(&value, src + lane * 4, sizeof(value));
            return write_operand_value(ctx, &instr->dst, value);
        }

        case HB_IR_PINSR: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            unsigned elem_size = (unsigned)(instr->target & 0xffu);
            unsigned lane = (unsigned)((instr->target >> 8) & 0xffu);
            if (!(elem_size == 1 || elem_size == 2 || elem_size == 4 || elem_size == 8)) return HB_ERR_INTERNAL;
            lane &= (16u / elem_size) - 1u;
            uint8_t out[16];
            uint64_t value = 0;
            r = read_xmm_operand_bytes(ctx, &instr->src1, out, 16);
            if (r != HB_OK) return r;
            r = read_operand_value(ctx, &instr->src2, &value);
            if (r != HB_OK) return r;
            memcpy(out + lane * elem_size, &value, elem_size);
            return write_vec_reg_bytes(ctx, instr->dst.reg, out, 16);
        }

        case HB_IR_PEXTR: {
            unsigned elem_size = (unsigned)(instr->target & 0xffu);
            unsigned lane = (unsigned)((instr->target >> 8) & 0xffu);
            if (!(elem_size == 1 || elem_size == 2 || elem_size == 4 || elem_size == 8)) return HB_ERR_INTERNAL;
            lane &= (16u / elem_size) - 1u;
            uint8_t src[16];
            uint64_t value = 0;
            r = read_xmm_operand_bytes(ctx, &instr->src1, src, 16);
            if (r != HB_OK) return r;
            memcpy(&value, src + lane * elem_size, elem_size);
            return write_operand_value(ctx, &instr->dst, value);
        }

        case HB_IR_PSHUF: {
            /* Итерация 883 — ФОРМА MMX: `PSHUFW mm, mm/m64, imm8` (признак target == 1).
             * Четыре СЛОВА по 16 бит; слово i результата берётся из слова с номером
             * `(imm >> (i*2)) & 3`. Запись — через наложение на x87, как у PUNPCK/PACK*. */
            if (instr->dst.type == HB_OP_REG &&
                instr->dst.reg >= HB_REG_MM0 && instr->dst.reg <= HB_REG_MM7 &&
                evex_target_arg(instr) == 1) {
                uint64_t* mm = hb_mmx_regs(ctx);
                uint64_t src = 0, res8 = 0;
                uint8_t ib[8], ob[8] = {0};
                unsigned imm_w, i;
                if (instr->src2.type != HB_OP_IMM) return HB_ERR_INTERNAL;
                if (instr->src1.type == HB_OP_REG &&
                    instr->src1.reg >= HB_REG_MM0 && instr->src1.reg <= HB_REG_MM7)
                    src = mm[instr->src1.reg - HB_REG_MM0];
                else if (instr->src1.type == HB_OP_MEM) {
                    r = hb_memory_read(ctx->memory, resolve_addr(ctx, &instr->src1), &src, 8);
                    if (r != HB_OK) return r;
                } else return HB_ERR_UNSUPPORTED_FEATURE;
                memcpy(ib, &src, 8);
                imm_w = (unsigned)instr->src2.imm & 0xff;
                for (i = 0; i < 4; i++) {
                    unsigned sel = (imm_w >> (i * 2)) & 3;
                    memcpy(ob + i * 2, ib + sel * 2, 2);
                }
                memcpy(&res8, ob, 8);
                mm[instr->dst.reg - HB_REG_MM0] = res8;
                hb_x87_mmx_write(hb_context_x87(ctx),
                                 (unsigned)(instr->dst.reg - HB_REG_MM0), res8);
                return HB_OK;
            }
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            if (instr->src2.type != HB_OP_IMM) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t ibytes[64], obytes[64];
            unsigned imm = (unsigned)instr->src2.imm & 0xff;
            uint32_t target = evex_target_arg(instr);
            unsigned mask_lane = 4;
            r = read_xmm_operand_bytes(ctx, &instr->src1, ibytes, bytes);
            if (r != HB_OK) return r;
            memcpy(obytes, ibytes, bytes);
            for (size_t base = 0; base < bytes; base += 16) {
                if (target == 4) {
                    mask_lane = 4;
                    for (unsigned lane = 0; lane < 4; lane++) {
                        unsigned src = (imm >> (lane * 2)) & 3;
                        memcpy(obytes + base + lane * 4, ibytes + base + src * 4, 4);
                    }
                } else if (target == 2) {
                    mask_lane = 2;
                    for (unsigned lane = 0; lane < 4; lane++) {
                        unsigned src = (imm >> (lane * 2)) & 3;
                        memcpy(obytes + base + lane * 2, ibytes + base + src * 2, 2);
                    }
                } else if (target == 0x102) {
                    mask_lane = 2;
                    for (unsigned lane = 0; lane < 4; lane++) {
                        unsigned src = (imm >> (lane * 2)) & 3;
                        memcpy(obytes + base + 8 + lane * 2,
                               ibytes + base + 8 + src * 2, 2);
                    }
                } else {
                    return HB_ERR_INTERNAL;
                }
            }
            return write_vec_reg_bytes_evex_masked(ctx, instr, obytes, bytes, mask_lane);
        }

        case HB_IR_FSHUF: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t lhs[64], rhs[64], out_bytes[64] = {0};
            uint32_t target = evex_target_arg(instr);
            unsigned lane = (unsigned)(target & 0xff);
            unsigned imm = (unsigned)((target >> 8) & 0xff);
            if (!(lane == 4 || lane == 8)) return HB_ERR_INTERNAL;
            r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, bytes);
            if (r != HB_OK) return r;
            for (size_t base = 0; base < bytes; base += 16) {
                if (lane == 4) {
                    unsigned s0 = (imm >> 0) & 3;
                    unsigned s1 = (imm >> 2) & 3;
                    unsigned s2 = (imm >> 4) & 3;
                    unsigned s3 = (imm >> 6) & 3;
                    memcpy(out_bytes + base + 0, lhs + base + s0 * 4, 4);
                    memcpy(out_bytes + base + 4, lhs + base + s1 * 4, 4);
                    memcpy(out_bytes + base + 8, rhs + base + s2 * 4, 4);
                    memcpy(out_bytes + base + 12, rhs + base + s3 * 4, 4);
                } else {
                    /* ★ У SHUFPD КАЖДАЯ 128-РАЗРЯДНАЯ ПОЛОВИНА ЧИТАЕТ СВОЮ ПАРУ РАЗРЯДОВ imm8.
                     *
                     * Спецификация (Intel SDM, VSHUFPD, 256 разрядов):
                     *   DEST[63:0]    <- imm8[0] ? SRC1[127:64]  : SRC1[63:0]
                     *   DEST[127:64]  <- imm8[1] ? SRC2[127:64]  : SRC2[63:0]
                     *   DEST[191:128] <- imm8[2] ? SRC1[255:192] : SRC1[191:128]
                     *   DEST[255:192] <- imm8[3] ? SRC2[255:192] : SRC2[191:128]
                     * Здесь обе половины читали imm8[0] и imm8[1], то есть разряды
                     * 2 и 3 не читались вовсе (а под EVEX — и 4…7).
                     *
                     * У SHUFPS наоборот: обе половины берут ОДНИ И ТЕ ЖЕ восемь
                     * разрядов — потому ветвь `lane == 4` выше и не трогается. */
                    unsigned para = (unsigned)(base / 16) * 2u;
                    unsigned s0 = (imm >> para) & 1;
                    unsigned s1 = (imm >> (para + 1)) & 1;
                    memcpy(out_bytes + base + 0, lhs + base + s0 * 8, 8);
                    memcpy(out_bytes + base + 8, rhs + base + s1 * 8, 8);
                }
            }
            return write_vec_reg_bytes_evex_masked(ctx, instr, out_bytes, bytes, lane);
        }

        case HB_IR_PSRL:
        case HB_IR_PSRA:
        case HB_IR_PSLL: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t src[32], dst[32] = {0};
            unsigned lane = (unsigned)(instr->target & 0xff);
            unsigned count = 0;
            r = read_packed_shift_count(ctx, &instr->src2, &count);
            if (r != HB_OK) return r;
            if (!(lane == 2 || lane == 4)) return HB_ERR_INTERNAL;
            r = read_xmm_operand_bytes(ctx, &instr->src1, src, bytes);
            if (r != HB_OK) return r;

            for (unsigned off = 0; off < bytes; off += lane) {
                if (lane == 2) {
                    uint16_t value;
                    memcpy(&value, src + off, sizeof(value));
                    uint16_t result = 0;
                    if (instr->op == HB_IR_PSRL) {
                        result = count >= 16 ? 0 : (uint16_t)(value >> count);
                    } else if (instr->op == HB_IR_PSLL) {
                        result = count >= 16 ? 0 : (uint16_t)(value << count);
                    } else {
                        int16_t signed_value;
                        memcpy(&signed_value, &value, sizeof(signed_value));
                        result = (uint16_t)(count >= 16 ? (signed_value < 0 ? -1 : 0)
                                                        : (int16_t)(signed_value >> count));
                    }
                    memcpy(dst + off, &result, sizeof(result));
                } else {
                    uint32_t value;
                    memcpy(&value, src + off, sizeof(value));
                    uint32_t result = 0;
                    if (instr->op == HB_IR_PSRL) {
                        result = count >= 32 ? 0 : (uint32_t)(value >> count);
                    } else if (instr->op == HB_IR_PSLL) {
                        result = count >= 32 ? 0 : (uint32_t)(value << count);
                    } else {
                        int32_t signed_value;
                        memcpy(&signed_value, &value, sizeof(signed_value));
                        result = (uint32_t)(count >= 32 ? (signed_value < 0 ? -1 : 0)
                                                        : (int32_t)(signed_value >> count));
                    }
                    memcpy(dst + off, &result, sizeof(result));
                }
            }
            return write_vec_reg_bytes(ctx, instr->dst.reg, dst, bytes);
        }

        case HB_IR_PSRLQ:
        case HB_IR_PSLLQ:
        case HB_IR_PSRLDQ:
        case HB_IR_PSLLDQ: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t src[32] = {0}, dst[32] = {0};
            unsigned count = 0;
            r = read_packed_shift_count(ctx, &instr->src2, &count);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src1, src, bytes);
            if (r != HB_OK) return r;

            if (instr->op == HB_IR_PSRLQ) {
                for (size_t off = 0; off < bytes; off += 8) {
                    uint64_t value = 0, result = 0;
                    memcpy(&value, src + off, sizeof(value));
                    result = (count > 63) ? 0 : (value >> count);
                    memcpy(dst + off, &result, sizeof(result));
                }
            } else if (instr->op == HB_IR_PSLLQ) {
                for (size_t off = 0; off < bytes; off += 8) {
                    uint64_t value = 0, result = 0;
                    memcpy(&value, src + off, sizeof(value));
                    result = (count > 63) ? 0 : (value << count);
                    memcpy(dst + off, &result, sizeof(result));
                }
            } else {
                for (size_t base = 0; base < bytes; base += 16) {
                    if (count >= 16) continue;
                    if (instr->op == HB_IR_PSRLDQ) {
                        memmove(dst + base, src + base + count, 16 - count);
                    } else {
                        memmove(dst + base + count, src + base, 16 - count);
                    }
                }
            }
            return write_vec_reg_bytes(ctx, instr->dst.reg, dst, bytes);
        }

        case HB_IR_PADD: {
            /* Итерация 521: та же арифметика для регистров MM. Ширина 8 байт, чтение и запись
             * идут через `ctx->mm`, а запись дополнительно кладётся в стек x87 наложением
             * (519) — иначе `fnsave` после MMX показал бы не то. */
            if (instr->dst.type == HB_OP_REG &&
                instr->dst.reg >= HB_REG_MM0 && instr->dst.reg <= HB_REG_MM7) {
                uint64_t* mm = hb_mmx_regs(ctx);
                unsigned lane8 = (unsigned)(instr->target & 0xff);
                uint64_t a = 0, bv = 0, res8 = 0;
                if (!(lane8 == 1 || lane8 == 2 || lane8 == 4 || lane8 == 8)) return HB_ERR_INTERNAL;
                if (instr->src1.type == HB_OP_REG &&
                    instr->src1.reg >= HB_REG_MM0 && instr->src1.reg <= HB_REG_MM7)
                    a = mm[instr->src1.reg - HB_REG_MM0];
                else return HB_ERR_UNSUPPORTED_FEATURE;
                if (instr->src2.type == HB_OP_REG &&
                    instr->src2.reg >= HB_REG_MM0 && instr->src2.reg <= HB_REG_MM7)
                    bv = mm[instr->src2.reg - HB_REG_MM0];
                else if (instr->src2.type == HB_OP_MEM) {
                    r = hb_memory_read(ctx->memory, resolve_addr(ctx, &instr->src2), &bv, 8);
                    if (r != HB_OK) return r;
                } else return HB_ERR_UNSUPPORTED_FEATURE;
                for (unsigned i = 0; i < 8; i += lane8) {
                    uint64_t m = (lane8 == 8) ? ~0ULL : ((1ULL << (lane8 * 8)) - 1ULL);
                    uint64_t sa = (a >> (i * 8)) & m, sb = (bv >> (i * 8)) & m;
                    res8 |= (((sa + sb) & m) << (i * 8));
                }
                mm[instr->dst.reg - HB_REG_MM0] = res8;
                hb_x87_mmx_write(hb_context_x87(ctx),
                                 (unsigned)(instr->dst.reg - HB_REG_MM0), res8);
                return HB_OK;
            }
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t lbytes[64], rbytes[64], obytes[64] = {0};
            unsigned lane = (unsigned)(instr->target & 0xff);
            if (!(lane == 1 || lane == 2 || lane == 4 || lane == 8)) return HB_ERR_INTERNAL;
            r = read_xmm_operand_bytes(ctx, &instr->src1, lbytes, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, rbytes, bytes);
            if (r != HB_OK) return r;
            for (unsigned i = 0; i < bytes; i += lane) {
                if (lane == 1) {
                    obytes[i] = (uint8_t)(lbytes[i] + rbytes[i]);
                } else if (lane == 2) {
                    uint16_t a, b, c;
                    memcpy(&a, lbytes + i, sizeof(a));
                    memcpy(&b, rbytes + i, sizeof(b));
                    c = (uint16_t)(a + b);
                    memcpy(obytes + i, &c, sizeof(c));
                } else if (lane == 4) {
                    uint32_t a, b, c;
                    memcpy(&a, lbytes + i, sizeof(a));
                    memcpy(&b, rbytes + i, sizeof(b));
                    c = a + b;
                    memcpy(obytes + i, &c, sizeof(c));
                } else {
                    uint64_t a, b, c;
                    memcpy(&a, lbytes + i, sizeof(a));
                    memcpy(&b, rbytes + i, sizeof(b));
                    c = a + b;
                    memcpy(obytes + i, &c, sizeof(c));
                }
            }
            return write_vec_reg_bytes_evex_masked(ctx, instr, obytes, bytes, lane);
        }

        case HB_IR_PSUB: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t lbytes[64], rbytes[64], obytes[64] = {0};
            unsigned lane = (unsigned)(instr->target & 0xff);
            if (!(lane == 1 || lane == 2 || lane == 4 || lane == 8)) return HB_ERR_INTERNAL;
            r = read_xmm_operand_bytes(ctx, &instr->src1, lbytes, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, rbytes, bytes);
            if (r != HB_OK) return r;
            for (unsigned i = 0; i < bytes; i += lane) {
                if (lane == 1) {
                    obytes[i] = (uint8_t)(lbytes[i] - rbytes[i]);
                } else if (lane == 2) {
                    uint16_t a, b, c;
                    memcpy(&a, lbytes + i, sizeof(a));
                    memcpy(&b, rbytes + i, sizeof(b));
                    c = (uint16_t)(a - b);
                    memcpy(obytes + i, &c, sizeof(c));
                } else if (lane == 4) {
                    uint32_t a, b, c;
                    memcpy(&a, lbytes + i, sizeof(a));
                    memcpy(&b, rbytes + i, sizeof(b));
                    c = a - b;
                    memcpy(obytes + i, &c, sizeof(c));
                } else {
                    uint64_t a, b, c;
                    memcpy(&a, lbytes + i, sizeof(a));
                    memcpy(&b, rbytes + i, sizeof(b));
                    c = a - b;
                    memcpy(obytes + i, &c, sizeof(c));
                }
            }
            return write_vec_reg_bytes_evex_masked(ctx, instr, obytes, bytes, lane);
        }

        case HB_IR_EVEX_CMP_MASK: {
            uint64_t meta = instr->target;
            unsigned kdst = (unsigned)(meta & 7u);
            unsigned kmask = (unsigned)((meta >> 3) & 7u);
            bool scalar = ((meta >> 6) & 1u) != 0;
            bool is_pd = ((meta >> 7) & 1u) != 0;
            bool broadcast = ((meta >> 8) & 1u) != 0;
            unsigned pred = (unsigned)((meta >> 16) & 31u);
            unsigned lane = is_pd ? 8u : 4u;
            size_t bytes = scalar ? lane : bytes_for_size(instr->src1.size);
            if (bytes == 0 || bytes > 64) bytes = scalar ? lane : 64;

            uint8_t lhs[64] = {0};
            uint8_t rhs[64] = {0};
            r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, scalar ? 16 : bytes);
            if (r != HB_OK) return r;
            if (broadcast && instr->src2.type == HB_OP_MEM) {
                uint64_t addr = resolve_addr(ctx, &instr->src2);
                r = hb_memory_read(ctx->memory, addr, rhs, lane);
                if (r != HB_OK) return r;
                for (size_t off = lane; off < bytes; off += lane) memcpy(rhs + off, rhs, lane);
            } else {
                r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, scalar ? lane : bytes);
                if (r != HB_OK) return r;
            }

            unsigned lanes = scalar ? 1u : (unsigned)(bytes / lane);
            uint64_t result = 0;
            for (unsigned lane_idx = 0; lane_idx < lanes; lane_idx++) {
                size_t off = (size_t)lane_idx * lane;
                bool cmp;
                if (is_pd) {
                    double a, b;
                    memcpy(&a, lhs + off, sizeof(a));
                    memcpy(&b, rhs + off, sizeof(b));
                    bool unordered = isnan(a) || isnan(b);
                    cmp = fp_cmp_predicate(unordered, a == b, a < b, a <= b, pred);
                } else {
                    float a, b;
                    memcpy(&a, lhs + off, sizeof(a));
                    memcpy(&b, rhs + off, sizeof(b));
                    bool unordered = isnan(a) || isnan(b);
                    cmp = fp_cmp_predicate(unordered, a == b, a < b, a <= b, pred);
                }
                if (cmp) result |= 1ull << lane_idx;
            }
            if (kmask != 0) result &= ctx->k[kmask & 7u];
            ctx->k[kdst & 7u] = result & ((lanes >= 64) ? UINT64_MAX : ((1ull << lanes) - 1ull));
            return HB_OK;
        }

        case HB_IR_VEC_PACKED: {
            hb_ir_vec_op_t vop = (hb_ir_vec_op_t)(instr->target >> 32);

            /* ★★★★★★ MacRunner 2026-08-29 — CRC32 (SSE4.2). НЕ ВЕКТОР, обрабатываем первым.
             *
             * x86 `CRC32 r32, r/m8|r/m16|r/m32` считает CRC-32C (полином Кастаньоли
             * 0x11EDC6F41, отражённый 0x82F63B78) — ТОТ ЖЕ полином, что у родных ARM64
             * `crc32cb/ch/cw`. Соответствие один в один, поэтому на ARM64 берём аппаратную
             * инструкцию, а запасной путь оставляем табличным для сборок без FEAT_CRC32.
             *
             * Размер источника задаёт форму: 1 байт (F2 0F 38 F0), 2 байта (с префиксом 66)
             * или 4 байта (F2 0F 38 F1). Приёмник — 32-битный регистр общего назначения,
             * он же первый источник (накопитель). */
            if (vop == HB_VEC_CRC32) {
                uint64_t acc64 = 0, src64 = 0;
                uint32_t acc;
                size_t src_bytes;

                r = read_operand_value(ctx, &instr->src1, &acc64);
                if (r != HB_OK) return r;
                r = read_operand_value(ctx, &instr->src2, &src64);
                if (r != HB_OK) return r;
                src_bytes = bytes_for_size(instr->src2.size);
                if (src_bytes != 1 && src_bytes != 2 && src_bytes != 4 && src_bytes != 8)
                    src_bytes = 4;
                acc = (uint32_t)acc64;
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRC32)
                switch (src_bytes) {
                case 1: acc = __builtin_arm_crc32cb(acc, (uint8_t)src64); break;
                case 2: acc = __builtin_arm_crc32ch(acc, (uint16_t)src64); break;
                case 8: acc = __builtin_arm_crc32cd(acc, (uint64_t)src64); break;
                default: acc = __builtin_arm_crc32cw(acc, (uint32_t)src64); break;
                }
#else
                {
                    size_t bi;
                    for (bi = 0; bi < src_bytes; ++bi) {
                        unsigned bit;
                        acc ^= (uint32_t)((src64 >> (bi * 8)) & 0xffu);
                        for (bit = 0; bit < 8; ++bit)
                            acc = (acc >> 1) ^ (0x82F63B78u & (uint32_t)(-(int32_t)(acc & 1u)));
                    }
                }
#endif
                /* Приёмник всегда 32-битный: старшие 32 бита обнуляются, как на x86-64. */
                return write_operand_value(ctx, &instr->dst, (uint64_t)acc);
            }

            unsigned arg = evex_target_arg(instr);
            unsigned imm = arg & 0xffu;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t dst_old[64] = {0}, lhs[64] = {0}, rhs[64] = {0}, out[64] = {0};
            if (vop >= HB_VEC_VFMADD132 && vop <= HB_VEC_VFNMSUB231) {
                if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
                unsigned lane = arg & 0xffu;
                bool scalar = (arg & 0x100u) != 0;
                if (!(lane == 4 || lane == 8)) return HB_ERR_INTERNAL;
                bytes = scalar ? 16 : bytes;
                r = read_vec_reg_bytes(ctx, instr->dst.reg, dst_old, bytes);
                if (r != HB_OK) return r;
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, bytes);
                if (r != HB_OK) return r;
                r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, scalar ? lane : bytes);
                if (r != HB_OK) return r;
                /* ★ У СКАЛЯРНОГО FMA СТАРШИЕ РАЗРЯДЫ БЕРУТСЯ ИЗ ПРИЁМНИКА.
                 *
                 * Спецификация (Intel SDM, VFMADD132SS и вся скалярная родня):
                 *   DEST[31:0]   <- округлённое произведение-со-сложением
                 *   DEST[127:32] <- DEST[127:32]     (сохраняются!)
                 *   DEST[MAXVL-1:128] <- 0
                 * Здесь хвост заполнялся из `lhs`, то есть из первого источника
                 * (VEX.vvvv). Считалась младшая дорожка верно, а разряды 32…127
                 * приходили от чужого регистра — 96 расхождений доски, вся
                 * скалярная ветвь FMA разом. */
                if (scalar) memcpy(out, dst_old, bytes);
                for (size_t off = 0; off < (scalar ? lane : bytes); off += lane) {
                    if (lane == 4) {
                        uint32_t dbits, s1bits, s2bits, rbits;
                        memcpy(&dbits, dst_old + off, sizeof(dbits));
                        memcpy(&s1bits, lhs + off, sizeof(s1bits));
                        memcpy(&s2bits, rhs + off, sizeof(s2bits));
                        float dval = hb_bits_to_float(dbits);
                        float s1 = hb_bits_to_float(s1bits);
                        float s2 = hb_bits_to_float(s2bits);
                        bool even_lane = ((off / lane) & 1u) == 0;
                        float result;
                        if (vop == HB_VEC_VFMADD132) result = fmaf(dval, s2, s1);
                        else if (vop == HB_VEC_VFMADD213) result = fmaf(s1, dval, s2);
                        else if (vop == HB_VEC_VFMADD231) result = fmaf(s1, s2, dval);
                        else if (vop == HB_VEC_VFMSUB132) result = fmaf(dval, s2, -s1);
                        else if (vop == HB_VEC_VFMSUB213) result = fmaf(s1, dval, -s2);
                        else if (vop == HB_VEC_VFMSUB231) result = fmaf(s1, s2, -dval);
                        else if (vop == HB_VEC_VFMADDSUB132) result = fmaf(dval, s2, even_lane ? -s1 : s1);
                        else if (vop == HB_VEC_VFMSUBADD132) result = fmaf(dval, s2, even_lane ? s1 : -s1);
                        else if (vop == HB_VEC_VFMADDSUB213) result = fmaf(s1, dval, even_lane ? -s2 : s2);
                        else if (vop == HB_VEC_VFMSUBADD213) result = fmaf(s1, dval, even_lane ? s2 : -s2);
                        else if (vop == HB_VEC_VFMADDSUB231) result = fmaf(s1, s2, even_lane ? -dval : dval);
                        else if (vop == HB_VEC_VFMSUBADD231) result = fmaf(s1, s2, even_lane ? dval : -dval);
                        else if (vop == HB_VEC_VFNMADD132) result = fmaf(-dval, s2, s1);
                        else if (vop == HB_VEC_VFNMADD213) result = fmaf(-s1, dval, s2);
                        else if (vop == HB_VEC_VFNMADD231) result = fmaf(-s1, s2, dval);
                        else if (vop == HB_VEC_VFNMSUB132) result = fmaf(-dval, s2, -s1);
                        else if (vop == HB_VEC_VFNMSUB213) result = fmaf(-s1, dval, -s2);
                        else result = fmaf(-s1, s2, -dval);
                        rbits = hb_float_to_bits(result);
                        memcpy(out + off, &rbits, sizeof(rbits));
                    } else {
                        uint64_t dbits, s1bits, s2bits, rbits;
                        memcpy(&dbits, dst_old + off, sizeof(dbits));
                        memcpy(&s1bits, lhs + off, sizeof(s1bits));
                        memcpy(&s2bits, rhs + off, sizeof(s2bits));
                        double dval = hb_bits_to_double(dbits);
                        double s1 = hb_bits_to_double(s1bits);
                        double s2 = hb_bits_to_double(s2bits);
                        bool even_lane = ((off / lane) & 1u) == 0;
                        double result;
                        if (vop == HB_VEC_VFMADD132) result = fma(dval, s2, s1);
                        else if (vop == HB_VEC_VFMADD213) result = fma(s1, dval, s2);
                        else if (vop == HB_VEC_VFMADD231) result = fma(s1, s2, dval);
                        else if (vop == HB_VEC_VFMSUB132) result = fma(dval, s2, -s1);
                        else if (vop == HB_VEC_VFMSUB213) result = fma(s1, dval, -s2);
                        else if (vop == HB_VEC_VFMSUB231) result = fma(s1, s2, -dval);
                        else if (vop == HB_VEC_VFMADDSUB132) result = fma(dval, s2, even_lane ? -s1 : s1);
                        else if (vop == HB_VEC_VFMSUBADD132) result = fma(dval, s2, even_lane ? s1 : -s1);
                        else if (vop == HB_VEC_VFMADDSUB213) result = fma(s1, dval, even_lane ? -s2 : s2);
                        else if (vop == HB_VEC_VFMSUBADD213) result = fma(s1, dval, even_lane ? s2 : -s2);
                        else if (vop == HB_VEC_VFMADDSUB231) result = fma(s1, s2, even_lane ? -dval : dval);
                        else if (vop == HB_VEC_VFMSUBADD231) result = fma(s1, s2, even_lane ? dval : -dval);
                        else if (vop == HB_VEC_VFNMADD132) result = fma(-dval, s2, s1);
                        else if (vop == HB_VEC_VFNMADD213) result = fma(-s1, dval, s2);
                        else if (vop == HB_VEC_VFNMADD231) result = fma(-s1, s2, dval);
                        else if (vop == HB_VEC_VFNMSUB132) result = fma(-dval, s2, -s1);
                        else if (vop == HB_VEC_VFNMSUB213) result = fma(-s1, dval, -s2);
                        else result = fma(-s1, s2, -dval);
                        rbits = hb_double_to_bits(result);
                        memcpy(out + off, &rbits, sizeof(rbits));
                    }
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, 16);
            }
            if (vop == HB_VEC_VCVTPH2PS) {
                if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
                size_t src_bytes = bytes / 2;
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, src_bytes);
                if (r != HB_OK) return r;
                for (size_t i = 0; i < src_bytes / 2; i++) {
                    uint16_t h;
                    uint32_t fbits;
                    memcpy(&h, lhs + i * 2, sizeof(h));
                    fbits = hb_half_to_float_bits(h);
                    memcpy(out + i * 4, &fbits, sizeof(fbits));
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, 16);
            }
            if (vop == HB_VEC_VCVTPS2PH) {
                size_t src_bytes = bytes_for_size(instr->src1.size);
                if (src_bytes == 0) src_bytes = 16;
                size_t result_bytes = src_bytes / 2;
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, src_bytes);
                if (r != HB_OK) return r;
                for (size_t i = 0; i < src_bytes / 4; i++) {
                    uint32_t fbits;
                    uint16_t h;
                    memcpy(&fbits, lhs + i * 4, sizeof(fbits));
                    h = hb_float_bits_to_half(fbits, imm);
                    memcpy(out + i * 2, &h, sizeof(h));
                }
                if (instr->dst.type == HB_OP_REG && is_xmm_reg(instr->dst.reg))
                    return write_vec_reg_bytes(ctx, instr->dst.reg, out, 16);
                if (instr->dst.type == HB_OP_MEM) {
                    uint64_t addr = resolve_addr(ctx, &instr->dst);
                    return hb_memory_write(ctx->memory, addr, out, result_bytes);
                }
                return HB_ERR_INTERNAL;
            }
            if (vop == HB_VEC_PCMPESTRM || vop == HB_VEC_PCMPESTRI ||
                vop == HB_VEC_PCMPISTRM || vop == HB_VEC_PCMPISTRI) {
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, 16);
                if (r != HB_OK) return r;
                r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, 16);
                if (r != HB_OK) return r;
                unsigned max_units = 0;
                int len1 = 0, len2 = 0;
                uint32_t res = pcmpxstr_result(ctx, vop, lhs, rhs, imm, &max_units, &len1, &len2);
                ctx->lazy_flags.pending = false;
                ctx->flags.cf = res != 0;
                ctx->flags.zf = len2 < (int)max_units;
                ctx->flags.sf = len1 < (int)max_units;
                ctx->flags.of = (res & 1u) != 0;
                ctx->flags.af = false;
                ctx->flags.pf = false;
                if (vop == HB_VEC_PCMPESTRI || vop == HB_VEC_PCMPISTRI) {
                    uint32_t idx = 0;
                    if ((imm >> 6) & 1u) {
                        for (int i = (int)max_units - 1; i >= 0; i--) {
                            if ((res >> i) & 1u) { idx = (uint32_t)i; break; }
                        }
                    } else {
                        idx = (uint32_t)max_units;
                        for (unsigned i = 0; i < max_units; i++) {
                            if ((res >> i) & 1u) { idx = i; break; }
                        }
                    }
                    write_reg_sized(ctx, HB_REG_RCX, idx, HB_SIZE_32);
                    return HB_OK;
                }
                unsigned unit = (imm & 1u) ? 2 : 1;
                if ((imm >> 6) & 1u) {
                    for (unsigned i = 0; i < max_units; i++) {
                        if ((res >> i) & 1u) memset(out + i * unit, 0xff, unit);
                    }
                } else {
                    uint16_t compact = (uint16_t)res;
                    memcpy(out, &compact, sizeof(compact));
                }
                return write_vec_reg_bytes(ctx, HB_REG_XMM0, out, 16);
            }
            if (vop == HB_VEC_VEXTRACTF128 || vop == HB_VEC_VEXTRACTI128) {
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, 32);
                if (r != HB_OK) return r;
                memcpy(out, lhs + ((imm & 1u) ? 16 : 0), 16);
                if (instr->dst.type == HB_OP_REG && is_xmm_reg(instr->dst.reg)) {
                    return write_vec_reg_bytes(ctx, instr->dst.reg, out, 16);
                }
                if (instr->dst.type == HB_OP_MEM) {
                    uint64_t addr = resolve_addr(ctx, &instr->dst);
                    return hb_memory_write(ctx->memory, addr, out, 16);
                }
                return HB_ERR_INTERNAL;
            }
            if (vop == HB_VEC_VINSERTF128 || vop == HB_VEC_VINSERTI128) {
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, 32);
                if (r != HB_OK) return r;
                r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, 16);
                if (r != HB_OK) return r;
                memcpy(out, lhs, 32);
                memcpy(out + ((imm & 1u) ? 16 : 0), rhs, 16);
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, 32);
            }
            if (vop == HB_VEC_VPERM2F128 || vop == HB_VEC_VPERM2I128) {
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, 32);
                if (r != HB_OK) return r;
                r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, 32);
                if (r != HB_OK) return r;
                const uint8_t* halves[4] = { lhs, lhs + 16, rhs, rhs + 16 };
                if (imm & 0x08u) memset(out, 0, 16);
                else memcpy(out, halves[imm & 3u], 16);
                if (imm & 0x80u) memset(out + 16, 0, 16);
                else memcpy(out + 16, halves[(imm >> 4) & 3u], 16);
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, 32);
            }
            if (vop == HB_VEC_VPERMQ || vop == HB_VEC_VPERMPD) {
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, 32);
                if (r != HB_OK) return r;
                for (unsigned lane = 0; lane < 4; lane++) {
                    unsigned src_lane = (imm >> (lane * 2)) & 3u;
                    memcpy(out + lane * 8, lhs + src_lane * 8, 8);
                }
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, 32);
            }
            if (vop == HB_VEC_VPSRLVD || vop == HB_VEC_VPSRLVQ ||
                vop == HB_VEC_VPSRAVD || vop == HB_VEC_VPSLLVD ||
                vop == HB_VEC_VPSLLVQ) {
                unsigned lane = (vop == HB_VEC_VPSRLVQ || vop == HB_VEC_VPSLLVQ) ? 8 : 4;
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, bytes);
                if (r != HB_OK) return r;
                r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, bytes);
                if (r != HB_OK) return r;
                for (size_t off = 0; off < bytes; off += lane) {
                    uint64_t count = load_lane_unsigned(rhs + off, lane);
                    if (lane == 8) {
                        uint64_t a;
                        uint64_t v;
                        memcpy(&a, lhs + off, sizeof(a));
                        if (count >= 64) v = 0;
                        else if (vop == HB_VEC_VPSLLVQ) v = a << count;
                        else v = a >> count;
                        memcpy(out + off, &v, sizeof(v));
                    } else if (vop == HB_VEC_VPSRAVD) {
                        int32_t a;
                        int32_t v;
                        memcpy(&a, lhs + off, sizeof(a));
                        if (count >= 32) v = a < 0 ? -1 : 0;
                        else v = a >> count;
                        memcpy(out + off, &v, sizeof(v));
                    } else {
                        uint32_t a;
                        uint32_t v;
                        memcpy(&a, lhs + off, sizeof(a));
                        if (count >= 32) v = 0;
                        else if (vop == HB_VEC_VPSLLVD) v = a << count;
                        else v = a >> count;
                        memcpy(out + off, &v, sizeof(v));
                    }
                }
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
            }
            if (vop == HB_VEC_VPERMD || vop == HB_VEC_VPERMPS) {
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, 32);
                if (r != HB_OK) return r;
                r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, 32);
                if (r != HB_OK) return r;
                for (unsigned lane = 0; lane < 8; lane++) {
                    uint32_t idx;
                    memcpy(&idx, lhs + lane * 4, sizeof(idx));
                    memcpy(out + lane * 4, rhs + ((idx & 7u) * 4), 4);
                }
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, 32);
            }
            if (vop == HB_VEC_VGATHERDPS || vop == HB_VEC_VGATHERDPD ||
                vop == HB_VEC_VGATHERQPS || vop == HB_VEC_VGATHERQPD ||
                vop == HB_VEC_VPGATHERDD || vop == HB_VEC_VPGATHERDQ ||
                vop == HB_VEC_VPGATHERQD || vop == HB_VEC_VPGATHERQQ) {
                /* ПОРЯДОК ПО СПЕЦИФИКАЦИИ (правка 04.09.2026): приёмник,
                 * ПАМЯТЬ (vsib), маска. Прежде маска стояла вторым операндом,
                 * а память третьим — наш внутренний выбор. */
                if (instr->dst.type != HB_OP_REG || !is_xmm_reg(instr->dst.reg) ||
                    instr->src2.type != HB_OP_REG || !is_xmm_reg(instr->src2.reg) ||
                    instr->src1.type != HB_OP_MEM || !instr->src1.mem.vsib ||
                    !is_xmm_reg(instr->src1.mem.index)) {
                    return HB_ERR_INTERNAL;
                }
                unsigned elem = instr->src1.mem.vsib_elem_size;
                unsigned index_size = instr->src1.mem.vsib_index_size;
                unsigned count = instr->src1.mem.vsib_count;
                if (!((elem == 4 || elem == 8) && (index_size == 4 || index_size == 8) &&
                      count > 0 && count <= 8)) return HB_ERR_INTERNAL;
                r = read_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
                if (r != HB_OK) return r;
                r = read_vec_reg_bytes(ctx, instr->src2.reg, lhs, bytes);
                if (r != HB_OK) return r;
                r = read_vec_reg_bytes(ctx, instr->src1.mem.index, rhs, index_size * count);
                if (r != HB_OK) return r;
                hb_ir_operand_t base_op = instr->src1;
                base_op.mem.index = HB_REG_COUNT;
                uint64_t base_addr = resolve_addr(ctx, &base_op);
                for (unsigned lane_i = 0; lane_i < count; lane_i++) {
                    size_t off = (size_t)lane_i * elem;
                    if (!(lhs[off + elem - 1] & 0x80)) continue;
                    int64_t idx;
                    if (index_size == 4) {
                        int32_t v;
                        memcpy(&v, rhs + lane_i * index_size, sizeof(v));
                        idx = v;
                    } else {
                        memcpy(&idx, rhs + lane_i * index_size, sizeof(idx));
                    }
                    uint64_t addr = base_addr + (uint64_t)(idx * (int64_t)instr->src1.mem.scale);
                    r = hb_memory_read(ctx->memory, addr, out + off, elem);
                    if (r != HB_OK) return r;
                }
                /* ★ ХВОСТ ПРИЁМНИКА ЗА СОБРАННОЙ ШИРИНОЙ — В НОЛЬ (найдено оракулом 05.09.2026).
                 *
                 * У форм с 128-битным qword-индексом и 32-битным элементом (`VPGATHERQD
                 * xmm1, vm64x, xmm2` и `VGATHERQPS xmm1, vm64x, xmm2`) дорожек ДВЕ, собранная
                 * ширина 8 байт, а приёмник — весь xmm. SDM: `DEST[MAXVL-1:64] := 0`.
                 * Здесь старшие 8 байт оставались прежними — сливались со старым содержимым.
                 *
                 * ЗАМЕР (tools/оракул/сверка-сборов-с-оракулом.py, 22 случая, интерпретатор,
                 * кодогенератор и Bochs на одних байтах): 20 совпали, расходились ровно эти две:
                 *   наш xmm1    c3cad1d805df3f18 5c484e1c881316e4   (хвост — старое содержимое)
                 *   оракул xmm1 c3cad1d805df3f18 0000000000000000
                 * У остальных 14 форм собранная ширина равна ширине приёмника, и правило
                 * ничего не меняет — оно общее, а не заплата на две кодировки. */
                if ((size_t)elem * count < bytes)
                    memset(out + (size_t)elem * count, 0, bytes - (size_t)elem * count);
                /* ★ МАСКА ОБНУЛЯЕТСЯ ЦЕЛИКОМ, А НЕ ТОЛЬКО У СОБРАННЫХ ДОРОЖЕК.
                 *
                 * Спецификация (Intel SDM, VGATHERDPS и вся родня) чистит разряд
                 * маски у каждой собранной дорожки, а в конце добавляет
                 * `MASK[MAXVL-1:0] <- 0`: по завершении команды регистр-маска пуст
                 * ВЕСЬ. Здесь чистились только собранные дорожки, и когда не
                 * собралось ни одной, маска оставалась нетронутой.
                 *
                 * ЗАМЕР ДО ПРАВКИ (оракул Bochs, `vpgatherdq xmm0,[xmm1*1+rax],xmm2`
                 * = c4e2e9900408, у обеих дорожек маски старший разряд нулевой):
                 *   наш xmm2 = fc336e8599b7dc4c29c51d5f73533614  (начальный, не тронут)
                 *   орк xmm2 = 00000000000000000000000000000000
                 * Приёмник при этом сходился — расходилась ровно маска. */
                memset(lhs, 0, sizeof(lhs));
                r = write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
                if (r != HB_OK) return r;
                return write_vec_reg_bytes(ctx, instr->src2.reg, lhs, bytes);
            }
            if (vop == HB_VEC_VMASKMOVDQU) {
                if (instr->dst.type != HB_OP_REG || !is_xmm_reg(instr->dst.reg) ||
                    instr->src2.type != HB_OP_REG || !is_xmm_reg(instr->src2.reg)) {
                    return HB_ERR_INTERNAL;
                }
                r = read_xmm_operand_bytes(ctx, &instr->dst, lhs, 16);
                if (r != HB_OK) return r;
                r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, 16);
                if (r != HB_OK) return r;
                uint64_t addr = ctx->regs.x64.rdi;
                for (unsigned off = 0; off < 16; off++) {
                    if (rhs[off] & 0x80u) {
                        r = hb_memory_write(ctx->memory, addr + off, lhs + off, 1);
                        if (r != HB_OK) return r;
                    }
                }
                return HB_OK;
            }
            if (vop == HB_VEC_VMASKMOVPS || vop == HB_VEC_VMASKMOVPD ||
                vop == HB_VEC_VPMASKMOVD || vop == HB_VEC_VPMASKMOVQ) {
                unsigned lane = imm == 8 ? 8 : 4;
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, bytes);
                if (r != HB_OK) return r;
                if (instr->dst.type == HB_OP_REG && is_xmm_reg(instr->dst.reg) &&
                    instr->src2.type == HB_OP_MEM) {
                    uint64_t addr = resolve_addr(ctx, &instr->src2);
                    for (size_t off = 0; off < bytes; off += lane) {
                        if (lhs[off + lane - 1] & 0x80) {
                            r = hb_memory_read(ctx->memory, addr + off, out + off, lane);
                            if (r != HB_OK) return r;
                        }
                    }
                    return write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
                }
                if (instr->dst.type == HB_OP_MEM && instr->src2.type == HB_OP_REG &&
                    is_xmm_reg(instr->src2.reg)) {
                    r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, bytes);
                    if (r != HB_OK) return r;
                    uint64_t addr = resolve_addr(ctx, &instr->dst);
                    for (size_t off = 0; off < bytes; off += lane) {
                        if (lhs[off + lane - 1] & 0x80) {
                            r = hb_memory_write(ctx->memory, addr + off, rhs + off, lane);
                            if (r != HB_OK) return r;
                        }
                    }
                    return HB_OK;
                }
                return HB_ERR_INTERNAL;
            }
            if (vop == HB_VEC_PCLMULQDQ) {
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, 16);
                if (r != HB_OK) return r;
                r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, 16);
                if (r != HB_OK) return r;
                uint64_t a, b;
                memcpy(&a, lhs + ((imm & 0x01u) ? 8 : 0), sizeof(a));
                memcpy(&b, rhs + ((imm & 0x10u) ? 8 : 0), sizeof(b));
                pclmul64(a, b, out);
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, 16);
            }
            if (vop == HB_VEC_AESKEYGENASSIST) {
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, 16);
                if (r != HB_OK) return r;
                uint32_t w1, w3, sw1, sw3, rw1, rw3;
                memcpy(&w1, lhs + 4, sizeof(w1));
                memcpy(&w3, lhs + 12, sizeof(w3));
                sw1 = aes_subword(w1);
                sw3 = aes_subword(w3);
                rw1 = aes_rotword(sw1) ^ (imm & 0xffu);
                rw3 = aes_rotword(sw3) ^ (imm & 0xffu);
                memcpy(out, &sw1, sizeof(sw1));
                memcpy(out + 4, &rw1, sizeof(rw1));
                memcpy(out + 8, &sw3, sizeof(sw3));
                memcpy(out + 12, &rw3, sizeof(rw3));
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, 16);
            }
            if (vop == HB_VEC_AESIMC || vop == HB_VEC_AESENC || vop == HB_VEC_AESENCLAST ||
                vop == HB_VEC_AESDEC || vop == HB_VEC_AESDECLAST) {
                if (bytes != 16 && bytes != 32 && bytes != 64) return HB_ERR_INTERNAL;
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, bytes);
                if (r != HB_OK) return r;
                if (vop != HB_VEC_AESIMC) {
                    r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, bytes);
                    if (r != HB_OK) return r;
                }
                for (size_t off = 0; off < bytes; off += 16) {
                    aes_round128(vop, lhs + off, rhs + off, out + off);
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, 16);
            }
            if (vop == HB_VEC_SHA1NEXTE || vop == HB_VEC_SHA1MSG1 || vop == HB_VEC_SHA1MSG2 ||
                vop == HB_VEC_SHA1RNDS4 || vop == HB_VEC_SHA256RNDS2 ||
                vop == HB_VEC_SHA256MSG1 || vop == HB_VEC_SHA256MSG2) {
                /* SHA-NI extensions. Operate on 16 bytes (4×u32) per element. */
                if (bytes != 16) return HB_ERR_INTERNAL;
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, 16);
                if (r != HB_OK) return r;
                r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, 16);
                if (r != HB_OK) return r;
                uint32_t s0[4], s1[4], d[4];
                /* DST dword layout per Intel spec (big-endian bit fields shown as
                 * little-endian dword index in our array):
                 *   s[0] = xmm[127:96], s[1] = xmm[95:64], s[2] = xmm[63:32], s[3] = xmm[31:0]
                 */
                for (unsigned k = 0; k < 4; k++) memcpy(&s0[k], lhs + (3 - k) * 4, 4);
                for (unsigned k = 0; k < 4; k++) memcpy(&s1[k], rhs + (3 - k) * 4, 4);
                switch (vop) {
                    case HB_VEC_SHA1NEXTE: {
                        /* TMP := (SRC1[127:96] ROL 30); DEST[127:96] := SRC2[127:96] + TMP;
                         * DEST[95:32] := SRC2[95:32]; DEST[31:0] := SRC2[31:0]. */
                        uint32_t a = s0[0];
                        uint32_t tmp = (a << 30) | (a >> 2);
                        d[0] = s1[0] + tmp;
                        d[1] = s1[1];
                        d[2] = s1[2];
                        d[3] = s1[3];
                        break;
                    }
                    case HB_VEC_SHA1MSG1: {
                        /* W0..W3 = SRC1 dwords; W4,W5 = SRC2[127:64].
                         * DEST[127:96] := W2 XOR W0;  DEST[95:64] := W3 XOR W1;
                         * DEST[63:32]  := W4 XOR W2;  DEST[31:0]   := W5 XOR W3. */
                        d[0] = s0[2] ^ s0[0];
                        d[1] = s0[3] ^ s0[1];
                        d[2] = s1[0] ^ s0[2];
                        d[3] = s1[1] ^ s0[3];
                        break;
                    }
                    case HB_VEC_SHA1MSG2: {
                        /* W13 := SRC2[95:64]; W14 := SRC2[63:32]; W15 := SRC2[31:0];
                         * W16 := (SRC1[127:96] XOR W13) ROL 1;
                         * W17 := (SRC1[95:64]  XOR W14) ROL 1;
                         * W18 := (SRC1[63:32]  XOR W15) ROL 1;
                         * W19 := (SRC1[31:0]   XOR W16) ROL 1;
                         * DEST[127:96] := W16; DEST[95:64] := W17;
                         * DEST[63:32]  := W18; DEST[31:0]  := W19. */
                        uint32_t w13 = s1[1], w14 = s1[2], w15 = s1[3];
                        uint32_t w16 = ((s0[0] ^ w13) << 1) | ((s0[0] ^ w13) >> 31);
                        uint32_t w17 = ((s0[1] ^ w14) << 1) | ((s0[1] ^ w14) >> 31);
                        uint32_t w18 = ((s0[2] ^ w15) << 1) | ((s0[2] ^ w15) >> 31);
                        uint32_t w19 = ((s0[3] ^ w16) << 1) | ((s0[3] ^ w16) >> 31);
                        d[0] = w16; d[1] = w17; d[2] = w18; d[3] = w19;
                        break;
                    }
                    case HB_VEC_SHA1RNDS4: {
                        /* A,B,C,D = SRC1[127:32]; W0E,W1,W2,W3 = SRC2 dwords.
                         * imm8[1:0] picks f()/K. Four rounds, then write A4,B4,C4,D4.
                         * Round 0: A_1 := f(B,C,D) + ROL(A,5) + W0E + K; E_1 := D.
                         * Round i (i=1..3): A_{i+1} := f(B_i,C_i,D_i) + ROL(A_i,5) + Wi + E_i + K;
                         *   B_{i+1} := A_i; C_{i+1} := ROL(B_i,30); D_{i+1} := C_i; E_{i+1} := D_i.
                         * Note: E_0 is implicit (the 5th state dword; carried in W0E
                         * for round 0). For rounds 1..3, E_i = D_{i-1}. */
                        static const uint32_t Ktab[4] = { 0x5A827999u, 0x6ED9EBA1u,
                                                          0x8F1BBCDCu, 0xCA62C1D6u };
                        unsigned k = imm & 0x3u;
                        uint32_t K = Ktab[k];
                        /* 5 slots: [0] = input, [1..4] = results of rounds 0..3. */
                        uint32_t Ast[5] = { s0[0], 0, 0, 0, 0 };
                        uint32_t Bst[5] = { s0[1], 0, 0, 0, 0 };
                        uint32_t Cst[5] = { s0[2], 0, 0, 0, 0 };
                        uint32_t Dst[5] = { s0[3], 0, 0, 0, 0 };
                        uint32_t Est[5] = { 0, 0, 0, 0, 0 };  /* Est[0] unused. */
                        uint32_t Ws[4]   = { s1[0], s1[1], s1[2], s1[3] };
                        for (int i = 0; i < 4; i++) {
                            uint32_t fi = (k == 0) ? sha_ch(Bst[i], Cst[i], Dst[i]) :
                                          (k == 1) ? sha_parity(Bst[i], Cst[i], Dst[i]) :
                                          (k == 2) ? sha_maj(Bst[i], Cst[i], Dst[i]) :
                                                     sha_parity(Bst[i], Cst[i], Dst[i]);
                            Ast[i + 1] = (i == 0) ? (fi + sha_rol(Ast[i], 5) + Ws[i] + K)
                                                  : (fi + sha_rol(Ast[i], 5) + Ws[i] + Est[i] + K);
                            Bst[i + 1] = Ast[i];
                            Cst[i + 1] = sha_rol(Bst[i], 30);
                            Dst[i + 1] = Cst[i];
                            Est[i + 1] = Dst[i];
                        }
                        /* Write A4, B4, C4, D4 (= Ast[4], Bst[4], Cst[4], Dst[4]). */
                        d[0] = Ast[4]; d[1] = Bst[4]; d[2] = Cst[4]; d[3] = Dst[4];
                        break;
                    }
                    case HB_VEC_SHA256MSG1: {
                        /* W4 := SRC2[31:0]; W3,W2,W1,W0 := SRC1[127:32];
                         * σ0(x) = ROR(x,7) XOR ROR(x,18) XOR (x >> 3);
                         * DEST[127:96] := W3 + σ0(W4);
                         * DEST[95:64]  := W2 + σ0(W3);
                         * DEST[63:32]  := W1 + σ0(W2);
                         * DEST[31:0]   := W0 + σ0(W1).
                         * In interp's Intel bit-numbered s0/s1:
                         *   s0[0]=SRC1[127:96]=W3, s0[1]=SRC1[95:64]=W2,
                         *   s0[2]=SRC1[63:32]=W1, s0[3]=SRC1[31:0]=W0.
                         *   s1[3]=SRC2[31:0]=W4.
                         *
                         * ★ ЗДЕСЬ ПОРЯДОК БЫЛ ПЕРЕВЁРНУТ. Стояло
                         * `d[0]=s0[3]+σ0(s1[3])`, то есть DEST[127:96] получал
                         * W0 вместо W3, и дальше со сдвигом. Прямо по строкам
                         * спецификации выше номер слагаемого совпадает с номером
                         * дорожки: d[0]=W3+σ0(W4), d[1]=W2+σ0(W3) и так далее.
                         * Замерено оракулом на `0f38ccc1`: все 16 байт xmm0
                         * расходились. */
                        uint32_t w4 = s1[3];
                        d[0] = s0[0] + sha_smallsig0(w4);
                        d[1] = s0[1] + sha_smallsig0(s0[0]);
                        d[2] = s0[2] + sha_smallsig0(s0[1]);
                        d[3] = s0[3] + sha_smallsig0(s0[2]);
                        break;
                    }
                    case HB_VEC_SHA256MSG2: {
                        /* W14 := SRC2[95:64]; W15 := SRC2[127:96];
                         * W16 := SRC1[31:0]  + σ1(W14);
                         * W17 := SRC1[63:32] + σ1(W15);
                         * W18 := SRC1[95:64] + σ1(W16);
                         * W19 := SRC1[127:96] + σ1(W17);
                         * σ1(x) = ROR(x,17) XOR ROR(x,19) XOR (x >> 10);
                         * DEST[127:96] := W19; DEST[95:64] := W18;
                         * DEST[63:32]  := W17; DEST[31:0]  := W16. */
                        uint32_t w14 = s1[1], w15 = s1[0];
                        uint32_t w16 = s0[3] + sha_smallsig1(w14);
                        uint32_t w17 = s0[2] + sha_smallsig1(w15);
                        uint32_t w18 = s0[1] + sha_smallsig1(w16);
                        uint32_t w19 = s0[0] + sha_smallsig1(w17);
                        d[0] = w19; d[1] = w18; d[2] = w17; d[3] = w16;
                        break;
                    }
                    case HB_VEC_SHA256RNDS2: {
                        /* A0,B0 := SRC2[127:64]; C0,D0 := SRC1[127:64];
                         * E0,F0 := SRC2[63:32];  G0,H0 := SRC1[63:32];
                         * WK0 := XMM0[31:0]; WK1 := XMM0[63:32].
                         * For i in 0..1:
                         *   A_{i+1} := Ch(E_i,F_i,G_i) + Σ1(E_i) + WK_i + H_i + Maj(A_i,B_i,C_i) + Σ0(A_i);
                         *   B_{i+1} := A_i; C_{i+1} := B_i; D_{i+1} := C_i;
                         *   E_{i+1} := Ch(E_i,F_i,G_i) + Σ1(E_i) + WK_i + H_i + D_i;
                         *   F_{i+1} := E_i; G_{i+1} := F_i; H_{i+1} := G_i.
                         * DEST[127:96]:=A2; DEST[95:64]:=B2;
                         * DEST[63:32] :=E2; DEST[31:0]  :=F2. */
                        uint8_t xmm0[16];
                        r = read_vec_reg_bytes(ctx, HB_REG_XMM0, xmm0, 16);
                        if (r != HB_OK) return r;
                        uint32_t WK[2];
                        memcpy(&WK[0], xmm0 + 0, 4);  /* XMM0[31:0]  = LE dword 0 (offset 0) */
                        memcpy(&WK[1], xmm0 + 4, 4);  /* XMM0[63:32] = LE dword 1 (offset 4) */
                        uint32_t A = s1[0], B = s1[1], C = s0[0], D = s0[1];
                        uint32_t E = s1[2], F = s1[3], G = s0[2], H = s0[3];
                        for (int i = 0; i < 2; i++) {
                            uint32_t ch = sha_ch(E, F, G);
                            uint32_t s1e = sha_bigsig1(E);
                            uint32_t m = sha_maj(A, B, C);
                            uint32_t s0a = sha_bigsig0(A);
                            uint32_t An = ch + s1e + WK[i] + H + m + s0a;
                            uint32_t En = ch + s1e + WK[i] + H + D;
                            /* The new state for round i+1 uses OLD A..H, not the new An/En. */
                            uint32_t Aold = A, Bold = B, Cold = C;
                            uint32_t Eold = E, Fold = F, Gold = G;
                            A = An; B = Aold; C = Bold; D = Cold;
                            E = En; F = Eold; G = Fold; H = Gold;
                        }
                        d[0] = A; d[1] = B; d[2] = E; d[3] = F;
                        break;
                    }
                    default: return HB_ERR_UNSUPPORTED_OPCODE;
                }
                for (unsigned k = 0; k < 4; k++) memcpy(out + (3 - k) * 4, &d[k], 4);
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, 16);
            }
            if (vop == HB_VEC_GF2P8MULB) {
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, bytes);
                if (r != HB_OK) return r;
                r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, bytes);
                if (r != HB_OK) return r;
                for (size_t i = 0; i < bytes; i++) out[i] = aes_gmul(lhs[i], rhs[i]);
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, 1);
            }
            if (vop == HB_VEC_GF2P8AFFINEQB || vop == HB_VEC_GF2P8AFFINEINVQB) {
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, bytes);
                if (r != HB_OK) return r;
                r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, bytes);
                if (r != HB_OK) return r;
                for (size_t i = 0; i < bytes; i++) {
                    uint8_t value = lhs[i];
                    if (vop == HB_VEC_GF2P8AFFINEINVQB) value = gf2p8_inv(value);
                    out[i] = gf2p8_affine_byte(value, rhs + (i & ~(size_t)7), (uint8_t)imm);
                }
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
            }
            bool is_broadcast = vop == HB_VEC_VPBROADCASTB || vop == HB_VEC_VPBROADCASTW ||
                                vop == HB_VEC_VPBROADCASTD || vop == HB_VEC_VPBROADCASTQ ||
                                vop == HB_VEC_VBROADCASTSS || vop == HB_VEC_VBROADCASTSD ||
                                vop == HB_VEC_VBROADCASTF32X2 || vop == HB_VEC_VBROADCASTF64X2 ||
                                vop == HB_VEC_VBROADCASTF32X4 || vop == HB_VEC_VBROADCASTF64X4 ||
                                vop == HB_VEC_VBROADCASTF32X8 || vop == HB_VEC_VBROADCASTI32X2 ||
                                vop == HB_VEC_VBROADCASTI128;
            size_t src1_bytes = bytes;
            unsigned mask_lane = 0;
            if (is_broadcast) {
                src1_bytes = vop == HB_VEC_VPBROADCASTB ? 1 :
                             vop == HB_VEC_VPBROADCASTW ? 2 :
                             vop == HB_VEC_VPBROADCASTD ? 4 :
                             vop == HB_VEC_VPBROADCASTQ ? 8 :
                             vop == HB_VEC_VBROADCASTSS ? 4 :
                             vop == HB_VEC_VBROADCASTSD ? 8 :
                             vop == HB_VEC_VBROADCASTF32X2 ? 8 :
                             vop == HB_VEC_VBROADCASTF64X2 ? 16 :
                             vop == HB_VEC_VBROADCASTF32X4 ? 16 :
                             vop == HB_VEC_VBROADCASTF64X4 ? 32 :
                             vop == HB_VEC_VBROADCASTF32X8 ? 32 :
                             vop == HB_VEC_VBROADCASTI32X2 ? 8 : 16;
                mask_lane = vop == HB_VEC_VBROADCASTF32X2 ? 4 :
                            vop == HB_VEC_VBROADCASTF32X4 ? 4 :
                            vop == HB_VEC_VBROADCASTF32X8 ? 4 :
                            vop == HB_VEC_VBROADCASTI32X2 ? 4 :
                            vop == HB_VEC_VBROADCASTF64X2 ? 8 :
                            vop == HB_VEC_VBROADCASTF64X4 ? 8 :
                            (unsigned)src1_bytes;
            }
            if (instr->src1.type != HB_OP_NONE) {
                r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, src1_bytes);
                if (r != HB_OK) return r;
            }
            if (instr->src2.type != HB_OP_NONE) {
                r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, bytes);
                if (r != HB_OK) return r;
            }

            if (is_broadcast) {
                unsigned lane = (unsigned)src1_bytes;
                if (vop == HB_VEC_VBROADCASTI128) {
                    for (size_t off = 0; off < bytes; off += 16) memcpy(out + off, lhs, 16);
                } else {
                    for (size_t off = 0; off < bytes; off += lane) memcpy(out + off, lhs, lane);
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, mask_lane ? mask_lane : lane);
            }

            if (vop == HB_VEC_VMOVSLDUP || vop == HB_VEC_VMOVSHDUP ||
                vop == HB_VEC_VMOVDDUP) {
                for (size_t base = 0; base < bytes; base += 16) {
                    if (vop == HB_VEC_VMOVDDUP) {
                        memcpy(out + base, lhs + base, 8);
                        memcpy(out + base + 8, lhs + base, 8);
                    } else {
                        unsigned first = vop == HB_VEC_VMOVSHDUP ? 1 : 0;
                        memcpy(out + base, lhs + base + first * 4, 4);
                        memcpy(out + base + 4, lhs + base + first * 4, 4);
                        memcpy(out + base + 8, lhs + base + (first + 2) * 4, 4);
                        memcpy(out + base + 12, lhs + base + (first + 2) * 4, 4);
                    }
                }
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
            }

            if (vop == HB_VEC_VPERMILPS || vop == HB_VEC_VPERMILPD) {
                unsigned lane = vop == HB_VEC_VPERMILPS ? 4 : 8;
                for (size_t block = 0; block < bytes; block += 16) {
                    unsigned lanes_per_block = 16 / lane;
                    for (unsigned j = 0; j < lanes_per_block; j++) {
                        unsigned sel;
                        if (instr->src2.type == HB_OP_NONE) {
                            sel = vop == HB_VEC_VPERMILPS
                                ? ((imm >> (2 * j)) & 3u)
                                : ((imm >> (j + (unsigned)(block / 16) * 2u)) & 1u);
                        } else if (vop == HB_VEC_VPERMILPS) {
                            uint32_t ctrl;
                            memcpy(&ctrl, rhs + block + j * lane, sizeof(ctrl));
                            sel = ctrl & 3u;
                        } else {
                            uint64_t ctrl;
                            memcpy(&ctrl, rhs + block + j * lane, sizeof(ctrl));
                            sel = (unsigned)((ctrl >> 1) & 1u);
                        }
                        memcpy(out + block + j * lane, lhs + block + sel * lane, lane);
                    }
                }
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
            }

            if (vop == HB_VEC_VCMPPS || vop == HB_VEC_VCMPPD ||
                vop == HB_VEC_VCMPSS || vop == HB_VEC_VCMPSD) {
                bool is_pd = vop == HB_VEC_VCMPPD || vop == HB_VEC_VCMPSD;
                bool scalar = vop == HB_VEC_VCMPSS || vop == HB_VEC_VCMPSD;
                unsigned lane = is_pd ? 8 : 4;
                unsigned pred = imm & 31u;
                if (scalar) memcpy(out, lhs, 16);
                for (size_t off = 0; off < bytes; off += lane) {
                    if (scalar && off >= lane) break;
                    bool unordered, cmp = false;
                    if (is_pd) {
                        double a, b;
                        memcpy(&a, lhs + off, sizeof(a));
                        memcpy(&b, rhs + off, sizeof(b));
                        unordered = isnan(a) || isnan(b);
                        switch (pred) {
                            case 0: case 16: cmp = !unordered && a == b; break;
                            case 1: case 17: cmp = !unordered && a < b; break;
                            case 2: case 18: cmp = !unordered && a <= b; break;
                            case 3: case 19: cmp = unordered; break;
                            case 4: case 20: cmp = unordered || a != b; break;
                            case 5: case 21: cmp = unordered || !(a < b); break;
                            case 6: case 22: cmp = unordered || !(a <= b); break;
                            case 7: case 23: cmp = !unordered; break;
                            case 8: case 24: cmp = unordered || a == b; break;
                            case 9: case 25: cmp = unordered || !(a >= b); break;
                            case 10: case 26: cmp = unordered || !(a > b); break;
                            case 11: case 27: cmp = false; break;
                            case 12: case 28: cmp = !unordered && a != b; break;
                            case 13: case 29: cmp = !unordered && a >= b; break;
                            case 14: case 30: cmp = !unordered && a > b; break;
                            case 15: case 31: cmp = true; break;
                        }
                    } else {
                        float a, b;
                        memcpy(&a, lhs + off, sizeof(a));
                        memcpy(&b, rhs + off, sizeof(b));
                        unordered = isnan(a) || isnan(b);
                        switch (pred) {
                            case 0: case 16: cmp = !unordered && a == b; break;
                            case 1: case 17: cmp = !unordered && a < b; break;
                            case 2: case 18: cmp = !unordered && a <= b; break;
                            case 3: case 19: cmp = unordered; break;
                            case 4: case 20: cmp = unordered || a != b; break;
                            case 5: case 21: cmp = unordered || !(a < b); break;
                            case 6: case 22: cmp = unordered || !(a <= b); break;
                            case 7: case 23: cmp = !unordered; break;
                            case 8: case 24: cmp = unordered || a == b; break;
                            case 9: case 25: cmp = unordered || !(a >= b); break;
                            case 10: case 26: cmp = unordered || !(a > b); break;
                            case 11: case 27: cmp = false; break;
                            case 12: case 28: cmp = !unordered && a != b; break;
                            case 13: case 29: cmp = !unordered && a >= b; break;
                            case 14: case 30: cmp = !unordered && a > b; break;
                            case 15: case 31: cmp = true; break;
                        }
                    }
                    memset(out + off, cmp ? 0xff : 0x00, lane);
                }
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, scalar ? 16 : bytes);
            }

            if (vop == HB_VEC_VADDSUBPS || vop == HB_VEC_VADDSUBPD) {
                bool is_pd = vop == HB_VEC_VADDSUBPD;
                unsigned lane = is_pd ? 8 : 4;
                for (size_t off = 0; off < bytes; off += lane) {
                    bool add = ((off / lane) & 1u) != 0;
                    if (is_pd) {
                        uint64_t a, b, c;
                        memcpy(&a, lhs + off, sizeof(a));
                        memcpy(&b, rhs + off, sizeof(b));
                        c = hb_sse_arith_double_bits(a, b, add ? HB_IR_FADD : HB_IR_FSUB);
                        memcpy(out + off, &c, sizeof(c));
                    } else {
                        uint32_t a, b, c;
                        memcpy(&a, lhs + off, sizeof(a));
                        memcpy(&b, rhs + off, sizeof(b));
                        c = hb_sse_arith_float_bits(a, b, add ? HB_IR_FADD : HB_IR_FSUB);
                        memcpy(out + off, &c, sizeof(c));
                    }
                }
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
            }

            if (vop == HB_VEC_VHADDPS || vop == HB_VEC_VHADDPD ||
                vop == HB_VEC_VHSUBPS || vop == HB_VEC_VHSUBPD) {
                bool is_pd = vop == HB_VEC_VHADDPD || vop == HB_VEC_VHSUBPD;
                bool sub = vop == HB_VEC_VHSUBPS || vop == HB_VEC_VHSUBPD;
                hb_ir_op_t op = sub ? HB_IR_FSUB : HB_IR_FADD;
                for (size_t base = 0; base < bytes; base += 16) {
                    if (is_pd) {
                        uint64_t a, b, c;
                        memcpy(&a, lhs + base, sizeof(a));
                        memcpy(&b, lhs + base + 8, sizeof(b));
                        c = hb_sse_arith_double_bits(a, b, op);
                        memcpy(out + base, &c, sizeof(c));
                        memcpy(&a, rhs + base, sizeof(a));
                        memcpy(&b, rhs + base + 8, sizeof(b));
                        c = hb_sse_arith_double_bits(a, b, op);
                        memcpy(out + base + 8, &c, sizeof(c));
                    } else {
                        for (unsigned pair = 0; pair < 2; pair++) {
                            uint32_t a, b, c;
                            memcpy(&a, lhs + base + pair * 8, sizeof(a));
                            memcpy(&b, lhs + base + pair * 8 + 4, sizeof(b));
                            c = hb_sse_arith_float_bits(a, b, op);
                            memcpy(out + base + pair * 4, &c, sizeof(c));
                            memcpy(&a, rhs + base + pair * 8, sizeof(a));
                            memcpy(&b, rhs + base + pair * 8 + 4, sizeof(b));
                            c = hb_sse_arith_float_bits(a, b, op);
                            memcpy(out + base + 8 + pair * 4, &c, sizeof(c));
                        }
                    }
                }
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
            }

            if (vop == HB_VEC_PTEST || vop == HB_VEC_VTESTPS || vop == HB_VEC_VTESTPD) {
                bool zf = true, cf = true;
                unsigned lane = vop == HB_VEC_VTESTPD ? 8 : 4;
                if (vop == HB_VEC_PTEST) lane = 1;
                for (size_t i = 0; i < bytes; i += lane) {
                    uint8_t a = lhs[i + lane - 1];
                    uint8_t b = rhs[i + lane - 1];
                    if (vop == HB_VEC_PTEST) {
                        if ((a & b) != 0) zf = false;
                        if (((uint8_t)~a & b) != 0) cf = false;
                    } else {
                        if ((a & b & 0x80u) != 0) zf = false;
                        if (((uint8_t)~a & b & 0x80u) != 0) cf = false;
                    }
                }
                hb_lazy_flags_clear(ctx);
                ctx->flags.zf = zf;
                ctx->flags.cf = cf;
                ctx->flags.of = ctx->flags.sf = ctx->flags.af = ctx->flags.pf = false;
                return HB_OK;
            }

            if (vop == HB_VEC_PHADDW || vop == HB_VEC_PHADDD || vop == HB_VEC_PHADDSW ||
                vop == HB_VEC_PHSUBW || vop == HB_VEC_PHSUBD || vop == HB_VEC_PHSUBSW) {
                unsigned lane = (vop == HB_VEC_PHADDW || vop == HB_VEC_PHADDSW ||
                                 vop == HB_VEC_PHSUBW || vop == HB_VEC_PHSUBSW) ? 2 : 4;
                bool sub = (vop == HB_VEC_PHSUBW || vop == HB_VEC_PHSUBD || vop == HB_VEC_PHSUBSW);
                bool sat = (vop == HB_VEC_PHADDSW || vop == HB_VEC_PHSUBSW);
                size_t lane_bytes = bytes < 16 ? 8 : 16;
                for (size_t base = 0; base < bytes; base += lane_bytes) {
                    unsigned pairs_per_src = (unsigned)(lane_bytes / (2 * lane));
                    for (unsigned s = 0; s < 2; s++) {
                        const uint8_t* src = s ? rhs + base : lhs + base;
                        for (unsigned p = 0; p < pairs_per_src; p++) {
                            int64_t a = load_lane_signed(src + p * 2 * lane, lane);
                            int64_t b = load_lane_signed(src + (p * 2 + 1) * lane, lane);
                            int64_t val = sub ? (a - b) : (a + b);
                            size_t off = base + (s * pairs_per_src + p) * lane;
                            if (sat) store_lane(out + off, lane, (uint16_t)sat_i16((int32_t)val));
                            else store_lane(out + off, lane, (uint64_t)val);
                        }
                    }
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, lane);
            }

            if (vop == HB_VEC_PMADDUBSW) {
                for (size_t i = 0; i < bytes; i += 2) {
                    int32_t v = (int32_t)lhs[i] * (int32_t)(int8_t)rhs[i] +
                                (int32_t)lhs[i + 1] * (int32_t)(int8_t)rhs[i + 1];
                    store_lane(out + i, 2, (uint16_t)sat_i16(v));
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, 2);
            }

            if (vop == HB_VEC_PSIGNB || vop == HB_VEC_PSIGNW || vop == HB_VEC_PSIGND ||
                vop == HB_VEC_PABSB || vop == HB_VEC_PABSW || vop == HB_VEC_PABSD) {
                unsigned lane = (vop == HB_VEC_PSIGNB || vop == HB_VEC_PABSB) ? 1 :
                                (vop == HB_VEC_PSIGNW || vop == HB_VEC_PABSW) ? 2 : 4;
                for (size_t i = 0; i < bytes; i += lane) {
                    int64_t a = load_lane_signed(lhs + i, lane);
                    int64_t sign = (vop == HB_VEC_PSIGNB || vop == HB_VEC_PSIGNW || vop == HB_VEC_PSIGND)
                                       ? load_lane_signed(rhs + i, lane) : 1;
                    int64_t val = sign == 0 ? 0 : (sign < 0 ? -a : (a < 0 && vop >= HB_VEC_PABSB && vop <= HB_VEC_PABSD ? -a : a));
                    store_lane(out + i, lane, (uint64_t)val);
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, lane);
            }

            if (vop == HB_VEC_PMULHRSW) {
                for (size_t i = 0; i < bytes; i += 2) {
                    int16_t a, b;
                    memcpy(&a, lhs + i, sizeof(a));
                    memcpy(&b, rhs + i, sizeof(b));
                    int32_t v = ((int32_t)a * (int32_t)b + 0x4000) >> 15;
                    store_lane(out + i, 2, (uint16_t)v);
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, 2);
            }

            if ((vop >= HB_VEC_PMOVSXBW && vop <= HB_VEC_PMOVSXDQ) ||
                (vop >= HB_VEC_PMOVZXBW && vop <= HB_VEC_PMOVZXDQ)) {
                bool sign = vop >= HB_VEC_PMOVSXBW && vop <= HB_VEC_PMOVSXDQ;
                unsigned src_lane = (vop == HB_VEC_PMOVSXBW || vop == HB_VEC_PMOVSXBD ||
                                     vop == HB_VEC_PMOVSXBQ || vop == HB_VEC_PMOVZXBW ||
                                     vop == HB_VEC_PMOVZXBD || vop == HB_VEC_PMOVZXBQ) ? 1 :
                                    (vop == HB_VEC_PMOVSXWD || vop == HB_VEC_PMOVSXWQ ||
                                     vop == HB_VEC_PMOVZXWD || vop == HB_VEC_PMOVZXWQ) ? 2 : 4;
                unsigned dst_lane = (vop == HB_VEC_PMOVSXBW || vop == HB_VEC_PMOVZXBW) ? 2 :
                                    (vop == HB_VEC_PMOVSXBD || vop == HB_VEC_PMOVSXWD ||
                                     vop == HB_VEC_PMOVZXBD || vop == HB_VEC_PMOVZXWD) ? 4 : 8;
                unsigned count = (unsigned)(bytes / dst_lane);
                for (unsigned i = 0; i < count; i++) {
                    uint64_t val = sign ? (uint64_t)load_lane_signed(lhs + i * src_lane, src_lane)
                                        : load_lane_unsigned(lhs + i * src_lane, src_lane);
                    store_lane(out + i * dst_lane, dst_lane, val);
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, dst_lane);
            }

            if (vop == HB_VEC_PMULDQ) {
                for (size_t i = 0, o = 0; i + 4 <= bytes; i += 8, o += 8) {
                    int32_t a, b;
                    memcpy(&a, lhs + i, sizeof(a));
                    memcpy(&b, rhs + i, sizeof(b));
                    int64_t v = (int64_t)a * (int64_t)b;
                    memcpy(out + o, &v, sizeof(v));
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, 8);
            }

            if (vop == HB_VEC_PCMPEQQ || vop == HB_VEC_PCMPGTQ) {
                for (size_t i = 0; i < bytes; i += 8) {
                    int64_t a, b;
                    memcpy(&a, lhs + i, sizeof(a));
                    memcpy(&b, rhs + i, sizeof(b));
                    if ((vop == HB_VEC_PCMPEQQ && a == b) || (vop == HB_VEC_PCMPGTQ && a > b))
                        memset(out + i, 0xff, 8);
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, 8);
            }

            if (vop == HB_VEC_PACKUSDW) {
                for (size_t base = 0; base < bytes; base += 16) {
                    for (unsigned i = 0; i < 4; i++) {
                        int32_t v;
                        memcpy(&v, lhs + base + i * 4, sizeof(v));
                        store_lane(out + base + i * 2, 2, sat_u16_from_i32(v));
                        memcpy(&v, rhs + base + i * 4, sizeof(v));
                        store_lane(out + base + 8 + i * 2, 2, sat_u16_from_i32(v));
                    }
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, 2);
            }

            if (vop == HB_VEC_PSUBUSB || vop == HB_VEC_PSUBUSW ||
                vop == HB_VEC_PSUBSB || vop == HB_VEC_PSUBSW) {
                bool is_unsigned = vop == HB_VEC_PSUBUSB || vop == HB_VEC_PSUBUSW;
                unsigned lane = (vop == HB_VEC_PSUBUSB || vop == HB_VEC_PSUBSB) ? 1 : 2;
                for (size_t i = 0; i < bytes; i += lane) {
                    if (is_unsigned) {
                        uint64_t a = load_lane_unsigned(lhs + i, lane);
                        uint64_t b = load_lane_unsigned(rhs + i, lane);
                        store_lane(out + i, lane, a > b ? a - b : 0);
                    } else if (lane == 1) {
                        int32_t v = (int32_t)(int8_t)lhs[i] - (int32_t)(int8_t)rhs[i];
                        out[i] = (uint8_t)sat_i8(v);
                    } else {
                        int16_t a, b;
                        memcpy(&a, lhs + i, sizeof(a));
                        memcpy(&b, rhs + i, sizeof(b));
                        store_lane(out + i, lane, (uint16_t)sat_i16((int32_t)a - (int32_t)b));
                    }
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, lane);
            }

            if ((vop >= HB_VEC_PMINSB && vop <= HB_VEC_PMULLD) ||
                vop == HB_VEC_PMINUB || vop == HB_VEC_PMINSW ||
                vop == HB_VEC_PMAXUB || vop == HB_VEC_PMAXSW) {
                bool is_max = vop == HB_VEC_PMAXSB || vop == HB_VEC_PMAXSD ||
                              vop == HB_VEC_PMAXUW || vop == HB_VEC_PMAXUD ||
                              vop == HB_VEC_PMAXUB || vop == HB_VEC_PMAXSW;
                bool is_mul = vop == HB_VEC_PMULLD;
                bool is_signed = vop == HB_VEC_PMINSB || vop == HB_VEC_PMINSD ||
                                 vop == HB_VEC_PMAXSB || vop == HB_VEC_PMAXSD ||
                                 vop == HB_VEC_PMINSW || vop == HB_VEC_PMAXSW;
                unsigned lane = (vop == HB_VEC_PMINSB || vop == HB_VEC_PMAXSB ||
                                 vop == HB_VEC_PMINUB || vop == HB_VEC_PMAXUB) ? 1 :
                                (vop == HB_VEC_PMINUW || vop == HB_VEC_PMAXUW ||
                                 vop == HB_VEC_PMINSW || vop == HB_VEC_PMAXSW) ? 2 : 4;
                for (size_t i = 0; i < bytes; i += lane) {
                    uint64_t val;
                    if (is_mul) {
                        int32_t a, b, c;
                        memcpy(&a, lhs + i, sizeof(a));
                        memcpy(&b, rhs + i, sizeof(b));
                        c = a * b;
                        val = (uint32_t)c;
                    } else if (is_signed) {
                        int64_t a = load_lane_signed(lhs + i, lane);
                        int64_t b = load_lane_signed(rhs + i, lane);
                        val = (uint64_t)(is_max ? (a > b ? a : b) : (a < b ? a : b));
                    } else {
                        uint64_t a = load_lane_unsigned(lhs + i, lane);
                        uint64_t b = load_lane_unsigned(rhs + i, lane);
                        val = is_max ? (a > b ? a : b) : (a < b ? a : b);
                    }
                    store_lane(out + i, lane, val);
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, lane);
            }

            if (vop == HB_VEC_PMULUDQ) {
                for (size_t base = 0; base < bytes; base += 16) {
                    for (unsigned i = 0; i < 2; i++) {
                        uint32_t a, b;
                        size_t src_off = base + i * 8;
                        memcpy(&a, lhs + src_off, sizeof(a));
                        memcpy(&b, rhs + src_off, sizeof(b));
                        uint64_t v = (uint64_t)a * (uint64_t)b;
                        memcpy(out + base + i * 8, &v, sizeof(v));
                    }
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, 8);
            }

            if (vop == HB_VEC_PSADBW) {
                for (size_t base = 0; base < bytes; base += 8) {
                    uint64_t sum = 0;
                    for (unsigned i = 0; i < 8; i++) {
                        int diff = (int)lhs[base + i] - (int)rhs[base + i];
                        sum += (uint64_t)(diff < 0 ? -diff : diff);
                    }
                    memcpy(out + base, &sum, sizeof(sum));
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, out, bytes, 8);
            }

            if (vop == HB_VEC_MPSADBW) {
                for (size_t base = 0; base < bytes; base += 16) {
                    /* ★ У 256-битной формы КАЖДАЯ половина берёт СВОИ разряды imm8.
                     * Спецификация VMPSADBW: младшая половина управляется imm8[2:0],
                     * старшая — imm8[5:3]. Здесь оба прохода читали imm8[2:0], то есть
                     * старшая половина считалась не по тому смещению. */
                    unsigned sdvig = (unsigned)(base / 16) * 3u;
                    unsigned lhs_base = ((imm >> (sdvig + 2)) & 1u) * 4u;
                    unsigned rhs_base = ((imm >> sdvig) & 3u) * 4u;
                    for (unsigned j = 0; j < 8; j++) {
                        uint16_t sum = 0;
                        for (unsigned k = 0; k < 4; k++) {
                            int diff = (int)lhs[base + lhs_base + j + k] -
                                       (int)rhs[base + rhs_base + k];
                            sum = (uint16_t)(sum + (uint16_t)(diff < 0 ? -diff : diff));
                        }
                        memcpy(out + base + j * 2, &sum, sizeof(sum));
                    }
                }
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
            }

            if (vop == HB_VEC_PHMINPOSUW) {
                uint16_t minv = 0xffff, mini = 0;
                for (uint16_t i = 0; i < 8; i++) {
                    uint16_t v;
                    memcpy(&v, lhs + i * 2, sizeof(v));
                    if (v < minv) { minv = v; mini = i; }
                }
                memset(out, 0, bytes);
                memcpy(out, &minv, sizeof(minv));
                memcpy(out + 2, &mini, sizeof(mini));
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
            }

            if (vop == HB_VEC_PALIGNR) {
                size_t lane_bytes = bytes < 16 ? 8 : 16;
                for (size_t base = 0; base < bytes; base += lane_bytes) {
                    uint8_t cat[32] = {0};
                    memcpy(cat, rhs + base, lane_bytes);
                    memcpy(cat + lane_bytes, lhs + base, lane_bytes);
                    for (size_t i = 0; i < lane_bytes; i++)
                        out[base + i] = (imm + i < lane_bytes * 2) ? cat[imm + i] : 0;
                }
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
            }

            if (vop == HB_VEC_PBLENDW || vop == HB_VEC_BLENDPS || vop == HB_VEC_BLENDPD ||
                vop == HB_VEC_VPBLENDD) {
                unsigned lane = (vop == HB_VEC_PBLENDW) ? 2 :
                                (vop == HB_VEC_BLENDPD ? 8 : 4);
                memcpy(out, lhs, bytes);
                for (unsigned i = 0; i < bytes / lane; i++)
                    if ((imm >> (i & 7)) & 1u) memcpy(out + i * lane, rhs + i * lane, lane);
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
            }

            if (vop == HB_VEC_PBLENDVB || vop == HB_VEC_BLENDVPS || vop == HB_VEC_BLENDVPD) {
                uint8_t mask[32] = {0};
                unsigned lane = vop == HB_VEC_PBLENDVB ? 1 : (vop == HB_VEC_BLENDVPS ? 4 : 8);
                r = read_vec_reg_bytes(ctx, HB_REG_XMM0, mask, bytes);
                if (r != HB_OK) return r;
                memcpy(out, lhs, bytes);
                for (unsigned i = 0; i < bytes; i += lane) {
                    if (mask[i + lane - 1] & 0x80) memcpy(out + i, rhs + i, lane);
                }
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
            }

            if (vop == HB_VEC_VPBLENDVB || vop == HB_VEC_VBLENDVPS || vop == HB_VEC_VBLENDVPD) {
                uint8_t mask[32] = {0};
                unsigned lane = vop == HB_VEC_VPBLENDVB ? 1 : (vop == HB_VEC_VBLENDVPS ? 4 : 8);
                int mask_reg = HB_REG_XMM0 + ((imm >> 4) & 0x0f);
                r = read_vec_reg_bytes(ctx, mask_reg, mask, bytes);
                if (r != HB_OK) return r;
                memcpy(out, lhs, bytes);
                for (unsigned i = 0; i < bytes; i += lane) {
                    if (mask[i + lane - 1] & 0x80) memcpy(out + i, rhs + i, lane);
                }
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
            }

            return HB_ERR_UNSUPPORTED_OPCODE;
        }

        case HB_IR_VZEROUPPER: {
            memset(ctx->ymm_hi, 0, sizeof(ctx->ymm_hi));
            return HB_OK;
        }

        /* Чтение и запись базы FS/GS. `target`: бит0 — GS, бит1 — запись.
         * Ширина приёмника у чтения задана самим операндом: у `rdfsbase eax`
         * старшие 32 разряда обнуляются обычным правилом x86-64. */
        case HB_IR_FSGSBASE: {
            bool gs = (instr->target & 1u) != 0;
            bool zapis = (instr->target & 2u) != 0;
            uint64_t* baza = gs ? &ctx->gs_base : &ctx->fs_base;
            if (zapis) {
                uint64_t v = 0;
                r = read_operand_value(ctx, &instr->src1, &v);
                if (r != HB_OK) return r;
                /* 32-битная форма пишет ТОЛЬКО младшие разряды базы, старшие
                 * обнуляются — база это одно 64-разрядное число, а не пара. */
                *baza = (instr->src1.size == HB_SIZE_64) ? v : (uint32_t)v;
                return HB_OK;
            }
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            write_reg_sized(ctx, instr->dst.reg, *baza,
                            instr->dst.size ? instr->dst.size : HB_SIZE_64);
            return HB_OK;
        }

        /* VZEROALL обнуляет регистры ЦЕЛИКОМ, а не только старшие половины.
         * В длинном режиме их шестнадцать, в 32-битном — восемь (остальных
         * там попросту нет, и трогать их значило бы менять невидимое гостю). */
        case HB_IR_VZEROALL: {
            const uint8_t nuli[32] = {0};
            unsigned skolko = (ctx->mode == HB_MODE_32BIT) ? 8u : 16u;
            for (unsigned i = 0; i < skolko; i++) {
                r = write_vec_reg_bytes(ctx, (int)(HB_REG_XMM0 + i), nuli, 32);
                if (r != HB_OK) return r;
            }
            return HB_OK;
        }

        case HB_IR_MOVD: {
            if (instr->dst.type == HB_OP_REG && is_xmm_reg(instr->dst.reg) &&
                instr->src1.type == HB_OP_REG && is_xmm_reg(instr->src1.reg)) {
                uint64_t xmm[2];
                uint64_t out[2] = {0, 0};
                r = read_xmm_reg(ctx, instr->src1.reg, xmm);
                if (r != HB_OK) return r;
                out[0] = xmm[0];
                return write_vec_reg_bytes(ctx, instr->dst.reg, (const uint8_t*)out, 16);
            }
            if (instr->dst.type == HB_OP_REG && is_xmm_reg(instr->dst.reg)) {
                uint64_t raw = 0;
                r = read_operand_value(ctx, &instr->src1, &raw);
                if (r != HB_OK) return r;
                uint64_t out[2] = { instr->src1.size == HB_SIZE_64 ? raw : (uint32_t)raw, 0 };
                return write_vec_reg_bytes(ctx, instr->dst.reg, (const uint8_t*)out, 16);
            }
            if (instr->src1.type == HB_OP_REG && is_xmm_reg(instr->src1.reg)) {
                uint64_t xmm[2];
                uint64_t low;
                r = read_xmm_reg(ctx, instr->src1.reg, xmm);
                if (r != HB_OK) return r;
                low = instr->dst.size == HB_SIZE_64 ? xmm[0] : (uint32_t)xmm[0];
                if (instr->dst.type == HB_OP_REG) {
                    write_reg_sized(ctx, instr->dst.reg, low, instr->dst.size == HB_SIZE_64 ? HB_SIZE_64 : HB_SIZE_32);
                    return HB_OK;
                }
                if (instr->dst.type == HB_OP_MEM) {
                    uint64_t addr = resolve_addr(ctx, &instr->dst);
                    return mem_write(ctx, addr, low, instr->dst.size == HB_SIZE_64 ? HB_SIZE_64 : HB_SIZE_32);
                }
            }
            return HB_ERR_INTERNAL;
        }

        case HB_IR_CVTDQ2PD: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            if (bytes != 16 && bytes != 32) return HB_ERR_INTERNAL;
            uint8_t in[16] = {0}, out[32] = {0};
            r = read_xmm_operand_bytes(ctx, &instr->src1, in, bytes / 2);
            if (r != HB_OK) return r;
            for (unsigned i = 0; i < bytes / 8; i++) {
                int32_t v;
                uint64_t bits;
                memcpy(&v, in + i * 4, sizeof(v));
                bits = hb_double_to_bits((double)v);
                memcpy(out + i * 8, &bits, sizeof(bits));
            }
            return write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
        }

        case HB_IR_CVTDQ2PS:
        case HB_IR_CVTPS2DQ:
        case HB_IR_CVTTPS2DQ: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            if (bytes != 16 && bytes != 32) return HB_ERR_INTERNAL;
            uint8_t ibytes[32] = {0}, obytes[32] = {0};
            r = read_xmm_operand_bytes(ctx, &instr->src1, ibytes, bytes);
            if (r != HB_OK) return r;
            if (instr->op == HB_IR_CVTDQ2PS) {
                for (unsigned i = 0; i < bytes / 4; i++) {
                    int32_t v;
                    float f;
                    uint32_t bits;
                    memcpy(&v, ibytes + i * 4, sizeof(v));
                    f = (float)v;
                    bits = hb_float_to_bits(f);
                    memcpy(obytes + i * 4, &bits, sizeof(bits));
                }
            } else {
                bool truncate = instr->op == HB_IR_CVTTPS2DQ;
                for (unsigned i = 0; i < bytes / 4; i++) {
                    uint32_t bits;
                    float f;
                    int32_t v;
                    memcpy(&bits, ibytes + i * 4, sizeof(bits));
                    f = hb_bits_to_float(bits);
                    v = hb_float_to_i32_sse(f, truncate, (ctx->mxcsr >> 13) & 3u);
                    memcpy(obytes + i * 4, &v, sizeof(v));
                }
            }
            return write_vec_reg_bytes(ctx, instr->dst.reg, obytes, bytes);
        }

        case HB_IR_CVTPS2PD: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            if (bytes != 16 && bytes != 32) return HB_ERR_INTERNAL;
            uint8_t in[16] = {0}, out[32] = {0};
            r = read_xmm_operand_bytes(ctx, &instr->src1, in, bytes / 2);
            if (r != HB_OK) return r;
            for (unsigned i = 0; i < bytes / 8; i++) {
                uint32_t bits;
                uint64_t dbits;
                memcpy(&bits, in + i * 4, sizeof(bits));
                dbits = hb_double_to_bits((double)hb_bits_to_float(bits));
                memcpy(out + i * 8, &dbits, sizeof(dbits));
            }
            return write_vec_reg_bytes(ctx, instr->dst.reg, out, bytes);
        }

        case HB_IR_CVTPD2PS: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t src_bytes = bytes_for_size(instr->src1.size);
            if (src_bytes == 0) src_bytes = 16;
            if (src_bytes != 16 && src_bytes != 32) return HB_ERR_INTERNAL;
            uint8_t in[32] = {0};
            uint8_t obytes[16] = {0};
            r = read_xmm_operand_bytes(ctx, &instr->src1, in, src_bytes);
            if (r != HB_OK) return r;
            for (unsigned i = 0; i < src_bytes / 8; i++) {
                uint64_t bits;
                uint32_t fbits;
                memcpy(&bits, in + i * 8, sizeof(bits));
                fbits = hb_float_to_bits((float)hb_bits_to_double(bits));
                memcpy(obytes + i * 4, &fbits, sizeof(fbits));
            }
            return write_vec_reg_bytes(ctx, instr->dst.reg, obytes, 16);
        }

        case HB_IR_CVTPD2DQ:
        case HB_IR_CVTTPD2DQ: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            size_t src_bytes = bytes_for_size(instr->src1.size);
            if (src_bytes == 0) src_bytes = 16;
            if (src_bytes != 16 && src_bytes != 32) return HB_ERR_INTERNAL;
            uint8_t in[32] = {0};
            uint8_t obytes[16] = {0};
            bool truncate = instr->op == HB_IR_CVTTPD2DQ;
            r = read_xmm_operand_bytes(ctx, &instr->src1, in, src_bytes);
            if (r != HB_OK) return r;
            for (unsigned i = 0; i < src_bytes / 8; i++) {
                uint64_t bits;
                double d;
                int32_t v;
                memcpy(&bits, in + i * 8, sizeof(bits));
                d = hb_bits_to_double(bits);
                v = hb_double_to_i32_sse(d, truncate, (ctx->mxcsr >> 13) & 3u);
                memcpy(obytes + i * 4, &v, sizeof(v));
            }
            return write_vec_reg_bytes(ctx, instr->dst.reg, obytes, 16);
        }

        case HB_IR_CVTSS2SD: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            float value = 0.0f;
            const hb_ir_operand_t *value_src = instr->src2.type == HB_OP_NONE ? &instr->src1 : &instr->src2;
            r = read_scalar_float(ctx, value_src, &value);
            if (r != HB_OK) return r;
            if (instr->src2.type != HB_OP_NONE) {
                uint8_t out[16] = {0};
                uint64_t bits = hb_double_to_bits((double)value);
                r = read_xmm_operand_bytes(ctx, &instr->src1, out, sizeof(out));
                if (r != HB_OK) return r;
                memcpy(out, &bits, sizeof(bits));
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, sizeof(out));
            }
            return write_scalar_double(ctx, &instr->dst, (double)value);
        }

        case HB_IR_CVTSD2SS: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            double value = 0.0;
            const hb_ir_operand_t *value_src = instr->src2.type == HB_OP_NONE ? &instr->src1 : &instr->src2;
            r = read_scalar_double(ctx, value_src, &value);
            if (r != HB_OK) return r;
            if (instr->src2.type != HB_OP_NONE) {
                uint8_t out[16] = {0};
                uint32_t bits = hb_float_to_bits((float)value);
                r = read_xmm_operand_bytes(ctx, &instr->src1, out, sizeof(out));
                if (r != HB_OK) return r;
                memcpy(out, &bits, sizeof(bits));
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, sizeof(out));
            }
            return write_scalar_float(ctx, &instr->dst, (float)value);
        }

        case HB_IR_CVTSI2SD: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            uint64_t raw = 0;
            const hb_ir_operand_t *int_src = instr->src2.type == HB_OP_NONE ? &instr->src1 : &instr->src2;
            r = read_operand_value(ctx, int_src, &raw);
            if (r != HB_OK) return r;
            double value = (int_src->size == HB_SIZE_64)
                ? (double)(int64_t)raw
                : (double)(int32_t)(uint32_t)raw;
            if (instr->src2.type != HB_OP_NONE) {
                uint8_t out[16] = {0};
                uint64_t bits = hb_double_to_bits(value);
                r = read_xmm_operand_bytes(ctx, &instr->src1, out, sizeof(out));
                if (r != HB_OK) return r;
                memcpy(out, &bits, sizeof(bits));
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, sizeof(out));
            }
            return write_scalar_double(ctx, &instr->dst, value);
        }

        case HB_IR_CVTSI2SS: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            uint64_t raw = 0;
            const hb_ir_operand_t *int_src = instr->src2.type == HB_OP_NONE ? &instr->src1 : &instr->src2;
            r = read_operand_value(ctx, int_src, &raw);
            if (r != HB_OK) return r;
            float value = (int_src->size == HB_SIZE_64)
                ? (float)(int64_t)raw
                : (float)(int32_t)(uint32_t)raw;
            if (instr->src2.type != HB_OP_NONE) {
                uint8_t out[16] = {0};
                uint32_t bits = hb_float_to_bits(value);
                r = read_xmm_operand_bytes(ctx, &instr->src1, out, sizeof(out));
                if (r != HB_OK) return r;
                memcpy(out, &bits, sizeof(bits));
                return write_vec_reg_bytes(ctx, instr->dst.reg, out, sizeof(out));
            }
            return write_scalar_float(ctx, &instr->dst, value);
        }

        case HB_IR_DIVSD: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            uint64_t lhs = 0, rhs = 0;
            r = read_scalar_double_bits(ctx, &instr->src1, &lhs);
            if (r != HB_OK) return r;
            r = read_scalar_double_bits(ctx, &instr->src2, &rhs);
            if (r != HB_OK) return r;
            return write_scalar_double_bits(ctx, &instr->dst, hb_sse_arith_double_bits(lhs, rhs, HB_IR_FDIV));
        }

        case HB_IR_ADDSD:
        case HB_IR_SUBSD: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            uint64_t lhs = 0, rhs = 0;
            r = read_scalar_double_bits(ctx, &instr->src1, &lhs);
            if (r != HB_OK) return r;
            r = read_scalar_double_bits(ctx, &instr->src2, &rhs);
            if (r != HB_OK) return r;
            return write_scalar_double_bits(ctx, &instr->dst,
                                            hb_sse_arith_double_bits(lhs, rhs,
                                                                     instr->op == HB_IR_ADDSD ? HB_IR_FADD : HB_IR_FSUB));
        }

        case HB_IR_MULSD: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            uint64_t lhs = 0, rhs = 0;
            r = read_scalar_double_bits(ctx, &instr->src1, &lhs);
            if (r != HB_OK) return r;
            r = read_scalar_double_bits(ctx, &instr->src2, &rhs);
            if (r != HB_OK) return r;
            return write_scalar_double_bits(ctx, &instr->dst, hb_sse_arith_double_bits(lhs, rhs, HB_IR_FMUL));
        }

        case HB_IR_MULSS: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            uint32_t lhs = 0, rhs = 0;
            r = read_scalar_float_bits(ctx, &instr->src1, &lhs);
            if (r != HB_OK) return r;
            r = read_scalar_float_bits(ctx, &instr->src2, &rhs);
            if (r != HB_OK) return r;
            return write_scalar_float_bits(ctx, &instr->dst, hb_sse_arith_float_bits(lhs, rhs, HB_IR_FMUL));
        }

        case HB_IR_DIVSS: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            uint32_t lhs = 0, rhs = 0;
            r = read_scalar_float_bits(ctx, &instr->src1, &lhs);
            if (r != HB_OK) return r;
            r = read_scalar_float_bits(ctx, &instr->src2, &rhs);
            if (r != HB_OK) return r;
            return write_scalar_float_bits(ctx, &instr->dst, hb_sse_arith_float_bits(lhs, rhs, HB_IR_FDIV));
        }

        case HB_IR_FSQRT:
        case HB_IR_FRSQRT:
        case HB_IR_FRCP: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            unsigned arg = evex_target_arg(instr);
            bool scalar = (arg & 0x100) != 0;
            unsigned lane = arg & 0xffu;
            size_t bytes = scalar ? 16 : bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t src[64], out_bytes[64];
            if (!(lane == 4 || lane == 8)) return HB_ERR_INTERNAL;
            if (instr->op != HB_IR_FSQRT && lane != 4) return HB_ERR_INTERNAL;
            r = read_xmm_operand_bytes(ctx, &instr->src1, out_bytes, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, src, scalar ? lane : bytes);
            if (r != HB_OK) return r;
            for (unsigned i = 0; i < (scalar ? 1U : (unsigned)(bytes / lane)); i++) {
                if (lane == 4) {
                    uint32_t bits, result_bits;
                    memcpy(&bits, src + i * 4, sizeof(bits));
                    float value = hb_bits_to_float(bits);
                    float result = sqrtf(value);
                    if (instr->op == HB_IR_FRSQRT) result = 1.0f / result;
                    else if (instr->op == HB_IR_FRCP) result = 1.0f / value;
                    result_bits = hb_sqrt_family_float_bits(bits, result);
                    memcpy(out_bytes + i * 4, &result_bits, sizeof(result_bits));
                } else {
                    uint64_t bits, result_bits;
                    memcpy(&bits, src + i * 8, sizeof(bits));
                    result_bits = hb_sqrt_family_double_bits(bits, sqrt(hb_bits_to_double(bits)));
                    memcpy(out_bytes + i * 8, &result_bits, sizeof(result_bits));
                }
            }
            if (scalar)
                return write_vec_reg_bytes_evex_scalar_masked(ctx, instr, out_bytes, lane);
            return write_vec_reg_bytes_evex_masked(ctx, instr, out_bytes, bytes, lane);
        }

        case HB_IR_FROUND: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            unsigned arg = evex_target_arg(instr);
            bool scalar = (arg & 0x100) != 0;
            unsigned lane = arg & 0xffu;
            unsigned imm = (unsigned)((instr->target >> 16) & 0xff);
            unsigned mode = (imm & 0x04u) ? 0u : (imm & 0x03u);
            size_t bytes = scalar ? 16 : bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            if (!(lane == 4 || lane == 8) || (bytes != 16 && bytes != 32)) return HB_ERR_INTERNAL;
            uint8_t out_bytes[32] = {0}, src[32] = {0};
            r = read_xmm_operand_bytes(ctx, &instr->src1, out_bytes, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, src, scalar ? lane : bytes);
            if (r != HB_OK) return r;
            for (unsigned off = 0; off < (scalar ? lane : (unsigned)bytes); off += lane) {
                if (lane == 4) {
                    uint32_t bits, rbits;
                    float value, rounded;
                    memcpy(&bits, src + off, sizeof(bits));
                    value = hb_bits_to_float(bits);
                    if (mode == 1) rounded = floorf(value);
                    else if (mode == 2) rounded = ceilf(value);
                    else if (mode == 3) rounded = truncf(value);
                    else rounded = nearbyintf(value);
                    rbits = hb_float_to_bits(rounded);
                    memcpy(out_bytes + off, &rbits, sizeof(rbits));
                } else {
                    uint64_t bits, rbits;
                    double value, rounded;
                    memcpy(&bits, src + off, sizeof(bits));
                    value = hb_bits_to_double(bits);
                    if (mode == 1) rounded = floor(value);
                    else if (mode == 2) rounded = ceil(value);
                    else if (mode == 3) rounded = trunc(value);
                    else rounded = nearbyint(value);
                    rbits = hb_double_to_bits(rounded);
                    memcpy(out_bytes + off, &rbits, sizeof(rbits));
                }
            }
            if (scalar)
                return write_vec_reg_bytes_evex_scalar_masked(ctx, instr, out_bytes, lane);
            return write_vec_reg_bytes_evex_masked(ctx, instr, out_bytes, bytes, lane);
        }

        case HB_IR_FDP: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            unsigned lane = (unsigned)(instr->target & 0xff);
            unsigned imm = (unsigned)((instr->target >> 16) & 0xff);
            size_t bytes = bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            if (!(lane == 4 || lane == 8) || (bytes != 16 && bytes != 32) || (lane == 8 && bytes != 16)) {
                return HB_ERR_INTERNAL;
            }
            uint8_t lhs[32] = {0}, rhs[32] = {0}, out_bytes[32] = {0};
            r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, bytes);
            if (r != HB_OK) return r;
            /* ★ ПОЛУБАЙТЫ imm8 У DPPS/DPPD БЫЛИ ПЕРЕПУТАНЫ МЕСТАМИ.
             *
             * Спецификация (Intel SDM, DPPS): СТАРШИЙ полубайт imm8[7:4] решает,
             * какие произведения войдут в сумму, МЛАДШИЙ imm8[3:0] — в какие
             * дорожки приёмника эта сумма ляжет; остальные дорожки обнуляются.
             * У DPPD то же самое двумя разрядами: imm8[5:4] и imm8[1:0].
             * Здесь маски стояли наоборот, и оба следствия видны разом.
             *
             * ЗАМЕР ДО ПРАВКИ (оракул Bochs, `dpps xmm0,xmm1,0xf1` = 660f3a40c1f1):
             *   наш xmm0 = ce8c471a ce8c471a ce8c471a ce8c471a
             *   орк xmm0 = 5412db61 00000000 00000000 00000000
             * То есть мы брали в сумму ОДНО произведение (младший полубайт 0001)
             * и раскладывали её по ЧЕТЫРЁМ дорожкам (старший 1111) — ровно
             * зеркальное отражение положенного. */
            for (unsigned base = 0; base < bytes; base += 16) {
                if (lane == 4) {
                    uint32_t prod[4] = {0, 0, 0, 0};
                    for (unsigned i = 0; i < 4; i++) {
                        if (imm & (1u << (4 + i))) {
                            uint32_t a, b;
                            memcpy(&a, lhs + base + i * 4, sizeof(a));
                            memcpy(&b, rhs + base + i * 4, sizeof(b));
                            prod[i] = hb_sse_arith_float_bits(a, b, HB_IR_FMUL);
                        }
                    }
                    uint32_t sum01 = hb_sse_arith_float_bits(prod[0], prod[1], HB_IR_FADD);
                    uint32_t sum23 = hb_sse_arith_float_bits(prod[2], prod[3], HB_IR_FADD);
                    uint32_t sum = hb_sse_arith_float_bits(sum01, sum23, HB_IR_FADD);
                    for (unsigned i = 0; i < 4; i++) {
                        if (imm & (1u << i)) memcpy(out_bytes + base + i * 4, &sum, sizeof(sum));
                    }
                } else {
                    uint64_t prod[2] = {0, 0};
                    for (unsigned i = 0; i < 2; i++) {
                        if (imm & (1u << (4 + i))) {
                            uint64_t a, b;
                            memcpy(&a, lhs + base + i * 8, sizeof(a));
                            memcpy(&b, rhs + base + i * 8, sizeof(b));
                            prod[i] = hb_sse_arith_double_bits(a, b, HB_IR_FMUL);
                        }
                    }
                    uint64_t sum = hb_sse_arith_double_bits(prod[0], prod[1], HB_IR_FADD);
                    for (unsigned i = 0; i < 2; i++) {
                        if (imm & (1u << i)) memcpy(out_bytes + base + i * 8, &sum, sizeof(sum));
                    }
                }
            }
            return write_vec_reg_bytes(ctx, instr->dst.reg, out_bytes, bytes);
        }

        case HB_IR_FADD:
        case HB_IR_FSUB:
        case HB_IR_FMUL:
        case HB_IR_FDIV: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            bool is_sub = instr->op == HB_IR_FSUB;
            bool is_mul = instr->op == HB_IR_FMUL;
            bool is_div = instr->op == HB_IR_FDIV;
            unsigned arg = evex_target_arg(instr);
            bool scalar = (arg & 0x100) != 0;
            bool broadcast = (arg & HB_EVEX_ARG_BROADCAST) != 0;
            unsigned er_mode = (arg & HB_EVEX_ARG_ROUND_MASK) >> HB_EVEX_ARG_ROUND_SHIFT;
            unsigned lane = arg & 0xffu;
            size_t bytes = scalar ? 16 : bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t lhs[64], rhs[64], out_bytes[64];
            if (!(lane == 4 || lane == 8)) return HB_ERR_INTERNAL;
            r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, (scalar || broadcast) ? lane : bytes);
            if (r != HB_OK) return r;
            if (broadcast) {
                for (unsigned i = 1; i < (unsigned)(bytes / lane); i++)
                    memcpy(rhs + i * lane, rhs, lane);
            }
            memcpy(out_bytes, lhs, bytes);
            for (unsigned i = 0; i < (scalar ? 1U : (unsigned)(bytes / lane)); i++) {
                if (lane == 4) {
                    uint32_t abits, bbits, cbits;
                    memcpy(&abits, lhs + i * 4, sizeof(abits));
                    memcpy(&bbits, rhs + i * 4, sizeof(bbits));
                    if (!is_div && !is_mul && !is_sub && er_mode)
                        cbits = hb_sse_add_float_bits_er(abits, bbits, er_mode);
                    else
                        cbits = hb_sse_arith_float_bits(abits, bbits,
                                                         is_div ? HB_IR_FDIV :
                                                         (is_mul ? HB_IR_FMUL :
                                                          (is_sub ? HB_IR_FSUB : HB_IR_FADD)));
                    memcpy(out_bytes + i * 4, &cbits, sizeof(cbits));
                } else {
                    uint64_t abits, bbits, cbits;
                    memcpy(&abits, lhs + i * 8, sizeof(abits));
                    memcpy(&bbits, rhs + i * 8, sizeof(bbits));
                    cbits = hb_sse_arith_double_bits(abits, bbits,
                                                      is_div ? HB_IR_FDIV :
                                                      (is_mul ? HB_IR_FMUL :
                                                       (is_sub ? HB_IR_FSUB : HB_IR_FADD)));
                    memcpy(out_bytes + i * 8, &cbits, sizeof(cbits));
                }
            }
            if (scalar)
                return write_vec_reg_bytes_evex_scalar_masked(ctx, instr, out_bytes, lane);
            return write_vec_reg_bytes_evex_masked(ctx, instr, out_bytes, bytes, lane);
        }

        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — SSE3: горизонтальные сложение и вычитание, ADDSUB.
         *
         * Горизонтальные складывают СОСЕДНИЕ дорожки внутри каждого источника, а не
         * одноимённые дорожки двух источников: для double ответ это {a0+a1, b0+b1},
         * для single {a0+a1, a2+a3, b0+b1, b2+b3}. ADDSUB работает по-обычному, но
         * чередует знак: чётные дорожки вычитаются, нечётные складываются.
         *
         * Признаки в `target`: бит0 — двойная точность, бит1 — вычитание,
         * бит2 — чередование. */
        case HB_IR_HADDSUB: {
            unsigned пр = (unsigned)(instr->target & 7u);
            bool двойная   = (пр & 1u) != 0;
            bool вычитание = (пр & 2u) != 0;
            bool чередует  = (пр & 4u) != 0;
            uint8_t a[16] = {0}, b[16] = {0}, o[16] = {0};
            unsigned лань = двойная ? 8u : 4u;
            unsigned n = 16u / лань;

            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg))
                return HB_ERR_INTERNAL;
            r = read_xmm_operand_bytes(ctx, &instr->src1, a, 16);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, b, 16);
            if (r != HB_OK) return r;

            for (unsigned i = 0; i < n; i++) {
                double x, y, z;
                const uint8_t* и1;
                unsigned p1, p2;
                if (чередует) {
                    и1 = a; p1 = i; p2 = i;          /* дорожка к дорожке */
                } else if (i < n / 2) {
                    и1 = a; p1 = i * 2; p2 = i * 2 + 1;   /* соседние в первом */
                } else {
                    и1 = b; p1 = (i - n / 2) * 2; p2 = p1 + 1;
                }
                if (двойная) {
                    uint64_t t;
                    memcpy(&t, (чередует ? a : и1) + p1 * 8, sizeof(t)); x = hb_bits_to_double(t);
                    memcpy(&t, (чередует ? b : и1) + p2 * 8, sizeof(t)); y = hb_bits_to_double(t);
                } else {
                    uint32_t t;
                    memcpy(&t, (чередует ? a : и1) + p1 * 4, sizeof(t)); x = (double)hb_bits_to_float(t);
                    memcpy(&t, (чередует ? b : и1) + p2 * 4, sizeof(t)); y = (double)hb_bits_to_float(t);
                }
                if (чередует) z = (i % 2 == 0) ? (x - y) : (x + y);
                else          z = вычитание ? (x - y) : (x + y);
                if (двойная) {
                    uint64_t t = hb_double_to_bits(z);
                    memcpy(o + i * 8, &t, sizeof(t));
                } else {
                    uint32_t t = hb_float_to_bits((float)z);
                    memcpy(o + i * 4, &t, sizeof(t));
                }
            }
            return write_vec_reg_bytes(ctx, instr->dst.reg, o, 16);
        }

        /* MOVDDUP/MOVSLDUP/MOVSHDUP: размножение дорожек.
         * Вид в `target`: 0 — младшие 64 бита в обе половины, 1 — чётные слова в
         * обе позиции пары, 2 — нечётные. */
        case HB_IR_MOVDUP: {
            unsigned вид = (unsigned)(instr->target & 3u);
            uint8_t вх[16] = {0}, o[16] = {0};
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg))
                return HB_ERR_INTERNAL;
            r = read_xmm_operand_bytes(ctx, &instr->src1, вх, вид == 0 ? 8 : 16);
            if (r != HB_OK) return r;
            if (вид == 0) {
                memcpy(o, вх, 8);
                memcpy(o + 8, вх, 8);
            } else {
                unsigned сдвиг = (вид == 1) ? 0u : 4u;
                for (unsigned i = 0; i < 2; i++) {
                    memcpy(o + i * 8,     вх + i * 8 + сдвиг, 4);
                    memcpy(o + i * 8 + 4, вх + i * 8 + сдвиг, 4);
                }
            }
            return write_vec_reg_bytes(ctx, instr->dst.reg, o, 16);
        }

        /* MOVQ2DQ xmm, mm: 64 бита MMX в младшую половину XMM, старшая обнуляется. */
        case HB_IR_MOVQ2DQ: {
            const uint64_t* mm = hb_mmx_regs(ctx);
            uint8_t o[16] = {0};
            if (instr->dst.type != HB_OP_REG || !is_xmm_reg(instr->dst.reg) ||
                instr->src1.type != HB_OP_REG || !is_mm_reg(instr->src1.reg) || !mm)
                return HB_ERR_INTERNAL;
            memcpy(o, &mm[instr->src1.reg - HB_REG_MM0], 8);
            return write_vec_reg_bytes(ctx, instr->dst.reg, o, 16);
        }

        /* MOVDQ2Q mm, xmm: младшие 64 бита XMM в MMX. */
        case HB_IR_MOVDQ2Q: {
            uint64_t* mm = hb_mmx_regs(ctx);
            uint8_t вх[16] = {0};
            if (instr->dst.type != HB_OP_REG || !is_mm_reg(instr->dst.reg) ||
                instr->src1.type != HB_OP_REG || !is_xmm_reg(instr->src1.reg) || !mm)
                return HB_ERR_INTERNAL;
            r = read_vec_reg_bytes(ctx, instr->src1.reg, вх, sizeof(вх));
            if (r != HB_OK) return r;
            memcpy(&mm[instr->dst.reg - HB_REG_MM0], вх, 8);
            return HB_OK;
        }

        /* MASKMOVQ/MASKMOVDQU: побайтовая запись по адресу в EDI/RDI под маской
         * знаковых битов второго источника. Байты с нулевым знаком НЕ пишутся —
         * это не «записать нули», а не трогать память вовсе. */
        case HB_IR_MASKMOV: {
            bool широкая = (instr->target & 1u) != 0;
            size_t ширина = широкая ? 16u : 8u;
            uint8_t данные[16] = {0}, маска[16] = {0};
            uint64_t адрес;
            r = read_xmm_operand_bytes(ctx, &instr->src1, данные, ширина);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, маска, ширина);
            if (r != HB_OK) return r;
            адрес = (ctx->mode == HB_MODE_32BIT)
                        ? (uint64_t)ctx->regs.x86.edi
                        : ctx->regs.x64.rdi;
            for (size_t i = 0; i < ширина; i++) {
                if (!(маска[i] & 0x80u)) continue;
                r = hb_memory_write(ctx->memory, (hb_gva_t)(адрес + i), &данные[i], 1);
                if (r != HB_OK) return r;
            }
            return HB_OK;
        }

        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — ПРЕОБРАЗОВАНИЯ MMX <-> ПЛАВАЮЩЕЕ.
         *
         * Шесть команд одним обработчиком; признаки в `target` уложил лифтер:
         * бит0 — направление (0 int->fp, 1 fp->int), бит1 — точность (0 single,
         * 1 double), бит2 — усечение вместо округления.
         *
         * Обе стороны всегда ДВЕ дорожки — это единственная форма у всего
         * семейства. Отсюда ширины: int-сторона неизменно 8 байт (два int32,
         * файл MMX ровно такой), fp-сторона 8 байт для single и 16 для double.
         *
         * Выход за пределы int32 по спецификации даёт «целое неопределённое» —
         * 0x80000000; отдельный случай, а не край, и на нём держатся проверки
         * диапазона в играх. NaN и бесконечность попадают туда же. */
        case HB_IR_CVT_MMX_FP: {
            unsigned пр = (unsigned)(instr->target & 7u);
            bool в_целое   = (пр & 1u) != 0;
            bool двойная   = (пр & 2u) != 0;
            bool усечение  = (пр & 4u) != 0;
            size_t байт_fp = двойная ? 16 : 8;
            uint8_t вход[16] = {0}, выход[16] = {0};

            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg))
                return HB_ERR_INTERNAL;

            r = read_xmm_operand_bytes(ctx, &instr->src1, вход,
                                       в_целое ? байт_fp : 8);
            if (r != HB_OK) return r;

            if (в_целое) {
                /* Округление и «целое неопределённое» при выходе за диапазон
                 * считают готовые помощники — те же, что у CVTTPS2DQ/CVTTPD2DQ,
                 * с текущим режимом округления из MXCSR. Своей арифметики здесь
                 * заводить не нужно и вредно: разошлась бы с соседним семейством. */
                unsigned режим = (ctx->mxcsr >> 13) & 3u;
                for (unsigned i = 0; i < 2; i++) {
                    int32_t ц;
                    if (двойная) {
                        uint64_t b; memcpy(&b, вход + i * 8, sizeof(b));
                        ц = hb_double_to_i32_sse(hb_bits_to_double(b), усечение, режим);
                    } else {
                        uint32_t b; memcpy(&b, вход + i * 4, sizeof(b));
                        ц = hb_float_to_i32_sse(hb_bits_to_float(b), усечение, режим);
                    }
                    memcpy(выход + i * 4, &ц, sizeof(ц));
                }
                if (!is_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
                {
                    uint64_t* mm = hb_mmx_regs(ctx);
                    if (!mm) return HB_ERR_INTERNAL;
                    memcpy(&mm[instr->dst.reg - HB_REG_MM0], выход, 8);
                }
                return HB_OK;
            }

            /* int -> плавающее: старшие 64 бита приёмника у CVTPI2PS сохраняются. */
            if (!is_xmm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            if (!двойная) {
                uint8_t прежнее[16];
                r = read_vec_reg_bytes(ctx, instr->dst.reg, прежнее, sizeof(прежнее));
                if (r != HB_OK) return r;
                memcpy(выход + 8, прежнее + 8, 8);
            }
            for (unsigned i = 0; i < 2; i++) {
                int32_t ц; memcpy(&ц, вход + i * 4, sizeof(ц));
                if (двойная) {
                    uint64_t b = hb_double_to_bits((double)ц);
                    memcpy(выход + i * 8, &b, sizeof(b));
                } else {
                    uint32_t b = hb_float_to_bits((float)ц);
                    memcpy(выход + i * 4, &b, sizeof(b));
                }
            }
            return write_vec_reg_bytes(ctx, instr->dst.reg, выход, 16);
        }

        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — CMPPS/CMPPD/CMPSS/CMPSD.
         *
         * Вид сравнения лежит в битах 16..23 аргумента (уложил лифтер), дорожка и
         * скалярность — там же, где у соседнего MIN/MAX. Ответ по руководству Intel:
         * дорожка целиком в единицах при истине и целиком в нулях при лжи, поэтому
         * дальше её используют как маску для ANDPS/ANDNPS.
         *
         * Восемь видов различаются двумя признаками: что считать истиной при
         * неупорядоченности (NaN) и знак самого сравнения. Виды 0..3 упорядоченные
         * (при NaN дают ложь, кроме UNORD), 4..7 — их отрицания. Пишем именно так,
         * а не через операторы C напрямую: `a < b` при NaN уже даёт нужную ложь, но
         * `!(a < b)` для NLT обязано дать истину — отрицание считаем отдельно. */
        case HB_IR_FCMP_MASK: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            uint32_t arg = evex_target_arg(instr);
            bool scalar = (arg & 0x100) != 0;
            bool broadcast = (arg & HB_EVEX_ARG_BROADCAST) != 0;
            unsigned lane = (unsigned)(arg & 0xff);
            unsigned вид = (unsigned)((arg >> 16) & 0x7u);
            size_t bytes = scalar ? 16 : bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            if (!(lane == 4 || lane == 8)) return HB_ERR_INTERNAL;
            uint8_t lhs[64], rhs[64], out_bytes[64];
            r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, (scalar || broadcast) ? lane : bytes);
            if (r != HB_OK) return r;
            if (broadcast) {
                for (unsigned i = 1; i < (unsigned)(bytes / lane); i++)
                    memcpy(rhs + i * lane, rhs, lane);
            }
            memcpy(out_bytes, lhs, bytes);
            for (unsigned i = 0; i < (scalar ? 1U : (unsigned)(bytes / lane)); i++) {
                double a, b;
                if (lane == 4) {
                    uint32_t ab, bb;
                    memcpy(&ab, lhs + i * 4, sizeof(ab));
                    memcpy(&bb, rhs + i * 4, sizeof(bb));
                    a = (double)hb_bits_to_float(ab);
                    b = (double)hb_bits_to_float(bb);
                } else {
                    uint64_t ab, bb;
                    memcpy(&ab, lhs + i * 8, sizeof(ab));
                    memcpy(&bb, rhs + i * 8, sizeof(bb));
                    a = hb_bits_to_double(ab);
                    b = hb_bits_to_double(bb);
                }
                bool неупорядочено = (a != a) || (b != b);
                bool истина;
                switch (вид & 3u) {
                    case 0: истина = !неупорядочено && (a == b); break;  /* EQ    / NEQ */
                    case 1: истина = !неупорядочено && (a <  b); break;  /* LT    / NLT */
                    case 2: истина = !неупорядочено && (a <= b); break;  /* LE    / NLE */
                    default: истина = неупорядочено;             break;  /* UNORD / ORD */
                }
                if (вид >= 4u) истина = !истина;
                if (lane == 4) {
                    uint32_t маска = истина ? 0xffffffffu : 0u;
                    memcpy(out_bytes + i * 4, &маска, sizeof(маска));
                } else {
                    uint64_t маска = истина ? 0xffffffffffffffffull : 0ull;
                    memcpy(out_bytes + i * 8, &маска, sizeof(маска));
                }
            }
            if (scalar)
                return write_vec_reg_bytes_evex_scalar_masked(ctx, instr, out_bytes, lane);
            return write_vec_reg_bytes_evex_masked(ctx, instr, out_bytes, bytes, lane);
        }

        case HB_IR_FMIN:
        case HB_IR_FMAX: {
            if (instr->dst.type != HB_OP_REG || !is_vec_or_mm_reg(instr->dst.reg)) return HB_ERR_INTERNAL;
            bool is_max = instr->op == HB_IR_FMAX;
            unsigned arg = evex_target_arg(instr);
            bool scalar = (arg & 0x100) != 0;
            bool broadcast = (arg & HB_EVEX_ARG_BROADCAST) != 0;
            unsigned lane = (unsigned)(arg & 0xff);
            size_t bytes = scalar ? 16 : bytes_for_size(instr->dst.size);
            if (bytes == 0) bytes = 16;
            uint8_t lhs[64], rhs[64], out_bytes[64];
            if (!(lane == 4 || lane == 8)) return HB_ERR_INTERNAL;
            r = read_xmm_operand_bytes(ctx, &instr->src1, lhs, bytes);
            if (r != HB_OK) return r;
            r = read_xmm_operand_bytes(ctx, &instr->src2, rhs, (scalar || broadcast) ? lane : bytes);
            if (r != HB_OK) return r;
            if (broadcast) {
                for (unsigned i = 1; i < (unsigned)(bytes / lane); i++)
                    memcpy(rhs + i * lane, rhs, lane);
            }
            memcpy(out_bytes, lhs, bytes);
            for (unsigned i = 0; i < (scalar ? 1U : (unsigned)(bytes / lane)); i++) {
                if (lane == 4) {
                    uint32_t abits, bbits, cbits;
                    memcpy(&abits, lhs + i * 4, sizeof(abits));
                    memcpy(&bbits, rhs + i * 4, sizeof(bbits));
                    cbits = hb_float_to_bits(select_sse_minmax_float(hb_bits_to_float(abits),
                                                                      hb_bits_to_float(bbits),
                                                                      is_max));
                    memcpy(out_bytes + i * 4, &cbits, sizeof(cbits));
                } else {
                    uint64_t abits, bbits, cbits;
                    memcpy(&abits, lhs + i * 8, sizeof(abits));
                    memcpy(&bbits, rhs + i * 8, sizeof(bbits));
                    cbits = hb_double_to_bits(select_sse_minmax_double(hb_bits_to_double(abits),
                                                                       hb_bits_to_double(bbits),
                                                                       is_max));
                    memcpy(out_bytes + i * 8, &cbits, sizeof(cbits));
                }
            }
            if (scalar)
                return write_vec_reg_bytes_evex_scalar_masked(ctx, instr, out_bytes, lane);
            return write_vec_reg_bytes_evex_masked(ctx, instr, out_bytes, bytes, lane);
        }

        case HB_IR_COMISS: {
            float lhs = 0.0f, rhs = 0.0f;
            r = read_scalar_float(ctx, &instr->src1, &lhs);
            if (r != HB_OK) return r;
            r = read_scalar_float(ctx, &instr->src2, &rhs);
            if (r != HB_OK) return r;
            write_scalar_compare_flags(ctx, (double)lhs, (double)rhs);
            return HB_OK;
        }

        case HB_IR_COMISD: {
            double lhs = 0.0, rhs = 0.0;
            r = read_scalar_double(ctx, &instr->src1, &lhs);
            if (r != HB_OK) return r;
            r = read_scalar_double(ctx, &instr->src2, &rhs);
            if (r != HB_OK) return r;
            write_scalar_compare_flags(ctx, lhs, rhs);
            return HB_OK;
        }

        case HB_IR_CVTSD2SI:
        case HB_IR_CVTTSD2SI: {
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            double value = 0.0;
            r = read_scalar_double(ctx, &instr->src1, &value);
            if (r != HB_OK) return r;
            if (instr->dst.size == HB_SIZE_64) {
                int64_t v = hb_double_to_i64_sse(value, instr->op == HB_IR_CVTTSD2SI, (ctx->mxcsr >> 13) & 3u);
                write_reg_sized(ctx, instr->dst.reg, (uint64_t)v, HB_SIZE_64);
            } else {
                int32_t v = hb_double_to_i32_sse(value, instr->op == HB_IR_CVTTSD2SI, (ctx->mxcsr >> 13) & 3u);
                write_reg_sized(ctx, instr->dst.reg, (uint32_t)v, HB_SIZE_32);
            }
            return HB_OK;
        }

        /* ★ CVTSS2SI СТОЯЛ В ОДНОЙ ВЕТВИ С БЕЗЗНАКОВЫМИ VCVTT*2USI.
         *
         * Он ЗНАКОВЫЙ: при выходе за диапазон приёмник получает «целое
         * неопределённое» 0x80000000 (0x8000000000000000 для 64 разрядов), а
         * не все единицы, и отрицательные значения преобразуются, а не
         * обнуляются. Здесь он шёл беззнаковым путём.
         *
         * ЗАМЕР ДО ПРАВКИ (оракул Bochs, `cvtss2si rax, xmm0` = f3480f2dc0,
         * источник примерно -1,97e14 — в int64 ВХОДИТ):
         *   наш rax = ffffffffffffffff  (беззнаковое «неопределённое»)
         *   орк rax = ffff4c6477000000  (настоящее преобразование)
         * и `cvtss2si eax, xmm0`: наш ffffffff против положенного 80000000.
         *
         * Ветвь ниже (`HB_IR_CVTTSS2SI`) уже различает округление и усечение
         * по коду операции, поэтому CVTSS2SI переезжает туда целиком. */
        case HB_IR_VCVTTSS2USI:
        case HB_IR_VCVTTSD2USI: {
            /* AVX-512: усечение к нулю с БЕЗЗНАКОВЫМ приёмником.
             *
             * Отличие от знаковых не только в типе: при выходе за диапазон и
             * при «не число» результат — «целое неопределённое», а это ВСЕ
             * ЕДИНИЦЫ, а не 0x80000000 как у знаковых. Значения из (-1, 0)
             * усекаются к нулю и НЕ являются выходом за диапазон. */
            double value = 0.0;
            bool shirokij = (instr->dst.size == HB_SIZE_64);
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            if (instr->op == HB_IR_VCVTTSS2USI) {
                float f32 = 0.0f;
                r = read_scalar_float(ctx, &instr->src1, &f32);
                if (r != HB_OK) return r;
                value = (double)f32;
            } else {
                r = read_scalar_double(ctx, &instr->src1, &value);
                if (r != HB_OK) return r;
            }
            if (shirokij) {
                uint64_t v;
                if (!(value == value) || value <= -1.0 || value >= 18446744073709551616.0)
                    v = UINT64_MAX;                 /* целое неопределённое */
                else
                    v = (value < 0.0) ? 0u : (uint64_t)value;
                write_reg_sized(ctx, instr->dst.reg, v, HB_SIZE_64);
            } else {
                uint32_t v;
                if (!(value == value) || value <= -1.0 || value >= 4294967296.0)
                    v = UINT32_MAX;
                else
                    v = (value < 0.0) ? 0u : (uint32_t)value;
                write_reg_sized(ctx, instr->dst.reg, v, HB_SIZE_32);
            }
            return HB_OK;
        }
        case HB_IR_CVTSS2SI:
        case HB_IR_CVTTSS2SI: {
            if (instr->dst.type != HB_OP_REG) return HB_ERR_INTERNAL;
            float value = 0.0f;
            r = read_scalar_float(ctx, &instr->src1, &value);
            if (r != HB_OK) return r;
            if (instr->dst.size == HB_SIZE_64) {
                int64_t v = hb_float_to_i64_sse(value, instr->op == HB_IR_CVTTSS2SI, (ctx->mxcsr >> 13) & 3u);
                write_reg_sized(ctx, instr->dst.reg, (uint64_t)v, HB_SIZE_64);
            } else {
                int32_t v = hb_float_to_i32_sse(value, instr->op == HB_IR_CVTTSS2SI, (ctx->mxcsr >> 13) & 3u);
                write_reg_sized(ctx, instr->dst.reg, (uint32_t)v, HB_SIZE_32);
            }
            return HB_OK;
        }

        case HB_IR_UNSUPPORTED:
            return HB_ERR_UNSUPPORTED_OPCODE;

        case HB_IR_FAULT:
            /* Итерация 939: отказ по привилегиям отличается от прочих ВИДОМ, потому что
             * сторона wine выбирает доставку именно по `last_fault_kind`. Без этого гость
             * получал смерть процесса вместо `0xC0000096` в своём обработчике. */
            if (instr->src1.type == HB_OP_IMM && instr->src1.imm == 3 /* PRIVILEGED */)
                return hb_fault_privileged(ctx, instr->guest_addr);
            /* Итерация 1081: вид 5 — недопустимая команда, гостю положен `c000001d`. */
            if (instr->src1.type == HB_OP_IMM && instr->src1.imm == 5 /* ILLEGAL */)
                return hb_fault_illegal(ctx, instr->guest_addr);
            return HB_ERR_EXEC_FAULT;

        default:
            return HB_ERR_UNSUPPORTED_OPCODE;
    }
}

hb_result_t hb_interpreter_exec_one_for_jit(hb_context_t* ctx, const hb_ir_instr_t* instr) {
    /* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 509 — ЗДЕСЬ ТЕРЯЛСЯ ПРИЗНАК VEX.
     *
     * `write_vec_reg_bytes` решает, обнулять ли старшую половину `ymm`, по
     * `trace_current_instr->zero_ymm_upper`. Указатель выставляет ТОЛЬКО цикл интерпретатора
     * (строка 8484). Этот вход — путь кодогенератора — звал `exec_instr` напрямую, поэтому
     * указатель был пуст, признак читался как «нет», и выпущенный код НИКОГДА не обнулял
     * старшую половину после 128-битной VEX-команды.
     *
     * Замер (итерация 509, `hb_diff_case_runner`, начальное `ymm_hi0=f043cabe…`):
     *   vaddps xmm / vmovaps xmm / vxorps xmm / vfmadd132ps / vcvtph2ps
     *   интерпретатор 0000000000000000, кодогенератор f043cabec027208f — расходятся все пять.
     * Эталон Unicorn поймать это не мог: у него нет AVX (итерация 508), так что расхождение
     * видно только сверкой наших же двух исполнителей.
     *
     * Прежнее значение сохраняем и возвращаем: вход зовётся из ловушек, и затирать чужой
     * указатель нельзя. */
    const hb_ir_instr_t* saved = trace_current_instr;
    trace_current_instr = instr;
    hb_result_t r = exec_instr(ctx, instr);
    trace_current_instr = saved;
    return r;
}

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: точка входа С ПРОИЗВОЛЬНОГО БЛОКА.
 *
 * Нужна для отката на интерпретатор при отказе кодогенерации. Раньше отказ
 * hb_arm64_codegen_block_with_cfg убивал процесс (hb_runtime.c ставил faulted=true),
 * хотя интерпретатор реализует ВСЕ операции IR и лежит в соседнем файле. Начинать с
 * cfg->entry нельзя: часть блоков уже исполнена выпущенным кодом, и повтор с начала
 * функции исказил бы состояние гостя. Поэтому старт задаётся вызывающим.
 *
 * Тело цикла не тронуто: переходы он и так выбирает по ctx->pc через find_block,
 * поэтому продолжение с середины функции для него естественно. */
hb_result_t hb_interpreter_run_from(hb_interpreter_t* interp, const hb_ir_func_t* func,
                                    hb_ir_block_t* start, hb_exec_result_t* out) {
    if (!interp || !func || !out) return HB_ERR_INVALID_ARG;
    if (!func->cfg || !func->cfg->entry) return HB_ERR_INVALID_ARG;
    memset(out, 0, sizeof(hb_exec_result_t));

    hb_context_t* ctx = interp->ctx;
    hb_ir_block_t* block = start ? start : func->cfg->entry;
    /* ★ Индекс команды, с которой начинается ТЕКУЩИЙ блок. Ноль везде, кроме входа по
     * адресу внутри блока (см. `find_block_containing`). Обнуляется сразу после того, как
     * блок начат, — иначе смещение «прилипло» бы к следующему блоку и часть его команд
     * была бы пропущена молча. */
    size_t start_i = 0;
    uint64_t steps = 0;
    uint64_t blocks_executed = 0;

    trace_refresh_runtime_flags();
    const unsigned int instr_trace_flags = trace_runtime_flags &
        (TRACE_FLAG_PC | TRACE_FLAG_STRCPY | TRACE_FLAG_SIMD | TRACE_FLAG_SIMD_DATA);

    while (block) {
        if (ctx->block_limit > 0 && blocks_executed >= ctx->block_limit) {
            out->result = HB_ERR_BLOCK_LIMIT;
            out->steps_executed = steps;
            out->blocks_executed = blocks_executed;
            out->faulted = true;
            out->fault_reason = "block limit reached";
            ctx->last_result = HB_ERR_BLOCK_LIMIT;
            return HB_ERR_BLOCK_LIMIT;
        }
        blocks_executed++;

        bool transferred = false;
        size_t nachalo = start_i;
        start_i = 0;
        for (size_t i = nachalo; i < block->instr_count; i++) {
            if (ctx->step_limit > 0 && steps >= ctx->step_limit) {
                out->result = HB_ERR_STEP_LIMIT;
                out->steps_executed = steps;
                out->blocks_executed = blocks_executed;
                return HB_OK;
            }
            steps++;

            const hb_ir_instr_t* instr = &block->instrs[i];
            trace_current_instr = instr;
            if (instr_trace_flags) {
                trace_pc_probe(ctx, instr);
                trace_strcpy_probe(ctx, instr);
                trace_simd_exec(ctx, instr, block->guest_addr, i, steps);
                trace_simd_data_exec(ctx, instr, "pre", block->guest_addr, i, steps);
            }
            hb_result_t r = exec_instr(ctx, instr);
            if (r == HB_OK && (trace_runtime_flags & TRACE_FLAG_SIMD_DATA))
                trace_simd_data_exec(ctx, instr, "post", block->guest_addr, i, steps);
            trace_current_instr = NULL;
            if (r == HB_ERR_UNSUPPORTED_OPCODE || r == HB_ERR_EXEC_FAULT) {
                trace_exec_fault(ctx, instr, r, block->guest_addr, i, steps);
                out->result = r;
                out->steps_executed = steps;
                out->blocks_executed = blocks_executed;
                out->faulted = true;
                out->fault_reason = (instr->op == HB_IR_UNSUPPORTED) ? instr->comment : "exec fault";
                return HB_OK;
            }
            if (r != HB_OK) {
                trace_exec_fault(ctx, instr, r, block->guest_addr, i, steps);
                out->result = r;
                out->steps_executed = steps;
                out->blocks_executed = blocks_executed;
                out->faulted = true;
                out->fault_reason = "memory or internal fault";
                return HB_OK;
            }

            /* MacRunner 2026-08-28: `HB_IR_FAR_BRANCH` — тоже передача управления.
             * Без него `ctx->pc`, выставленный обработчиком, ниже перезаписывался
             * адресом следующей команды, и дальний переход тихо не происходил —
             * ровно тот дефект, на который жалуется запись итерации 922 в декодере. */
            if (instr->op == HB_IR_JMP || instr->op == HB_IR_Jcc || instr->op == HB_IR_LOOP ||
                instr->op == HB_IR_JRCXZ || instr->op == HB_IR_CALL || instr->op == HB_IR_RET ||
                instr->op == HB_IR_FAR_BRANCH) {
                size_t next_start = 0;
                hb_ir_block_t* next = find_block_containing(func->cfg, ctx->pc, &next_start);
                if (!next) {
                    if (func->truncated) {
                        out->result = HB_ERR_TRANSLATION_TRUNCATED;
                        out->steps_executed = steps;
                        out->blocks_executed = blocks_executed;
                        out->faulted = true;
                        out->fault_reason = "translated function truncated before branch target";
                        ctx->last_result = HB_ERR_TRANSLATION_TRUNCATED;
                        return HB_ERR_TRANSLATION_TRUNCATED;
                    }
                    if (instr->op == HB_IR_CALL || instr->op == HB_IR_RET ||
                        instr->op == HB_IR_JMP || instr->op == HB_IR_Jcc ||
                        instr->op == HB_IR_LOOP || instr->op == HB_IR_JRCXZ ||
                        instr->op == HB_IR_FAR_BRANCH) {
                        out->result = HB_OK;
                        out->steps_executed = steps;
                        out->blocks_executed = blocks_executed;
                        return HB_OK;
                    }
                    out->result = HB_ERR_NOT_FOUND;
                    out->steps_executed = steps;
                    out->blocks_executed = blocks_executed;
                    out->faulted = true;
                    out->fault_reason = "branch target block not found";
                    return HB_OK;
                }
                block = next;
                start_i = next_start;
                transferred = true;
                break;
            }
        }

        if (transferred) {
            continue;
        } else if (block) {
            if (block->instr_count) {
                const hb_ir_instr_t* last = &block->instrs[block->instr_count - 1];
                ctx->pc = last->guest_addr + last->guest_len;
                sync_arch_pc(ctx);
                size_t next_start = 0;
                hb_ir_block_t* next = find_block_containing(func->cfg, ctx->pc, &next_start);
                if (next) {
                    block = next;
                    start_i = next_start;
                    continue;
                }
            }
            out->result = HB_OK;
            out->steps_executed = steps;
            out->blocks_executed = blocks_executed;
            return HB_OK;
        }
    }

    out->result = HB_OK;
    out->steps_executed = steps;
    out->blocks_executed = blocks_executed;
    return HB_OK;
}

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: прежнее имя сохранено как обёртка. */
hb_result_t hb_interpreter_run(hb_interpreter_t* interp, const hb_ir_func_t* func, hb_exec_result_t* out) {
    if (!func || !func->cfg) return HB_ERR_INVALID_ARG;
    return hb_interpreter_run_from(interp, func, func->cfg->entry, out);
}

/* ★★★★★ 05.09.2026 — ТОЧНОЕ ВОЗОБНОВЛЕНИЕ ПОСЛЕ ОТКАЗА В ВЫПУЩЕННОМ КОДЕ.
 *
 * Зачем отдельный вход, а не hb_interpreter_run_from. Тот начинает с ПЕРВОЙ команды блока и
 * ходит по CFG функции; здесь блок может принадлежать ЧУЖОЙ функции (сцепление уводит из
 * диспетчера на 2-6 блоков), а начинать надо с команды, которую назвала карта отказов.
 * Поэтому: один блок, с `start_index`, до конца блока или до передачи управления. Куда идти
 * дальше, решает диспетчер по `ctx->pc` — как и после любого нативного блока.
 *
 * Отказы докладываются ТАК ЖЕ, как в общем цикле (out->faulted / result / fault_reason,
 * ctx->last_result), чтобы сторона wine различала их тем же кодом. Пределы шагов/блоков
 * здесь не проверяются: возобновление доигрывает хвост ОДНОГО блока, а пределы диспетчер
 * применит на следующей диспетчеризации. */
hb_result_t hb_interpreter_resume_block(hb_context_t* ctx, const hb_ir_block_t* block,
                                        size_t start_index, hb_exec_result_t* out) {
    uint64_t steps = 0;
    if (!ctx || !block || !out) return HB_ERR_INVALID_ARG;
    memset(out, 0, sizeof(hb_exec_result_t));
    if (start_index >= block->instr_count) return HB_ERR_INVALID_ARG;

    trace_refresh_runtime_flags();
    out->blocks_executed = 1;

    for (size_t i = start_index; i < block->instr_count; i++) {
        const hb_ir_instr_t* instr = &block->instrs[i];
        hb_result_t r;
        steps++;
        trace_current_instr = instr;
        r = exec_instr(ctx, instr);
        trace_current_instr = NULL;
        if (r == HB_ERR_UNSUPPORTED_OPCODE || r == HB_ERR_EXEC_FAULT) {
            trace_exec_fault(ctx, instr, r, block->guest_addr, i, steps);
            out->result = r;
            out->steps_executed = steps;
            out->faulted = true;
            out->fault_reason = (instr->op == HB_IR_UNSUPPORTED) ? instr->comment : "exec fault";
            ctx->last_result = r;
            return HB_OK;
        }
        if (r != HB_OK) {
            trace_exec_fault(ctx, instr, r, block->guest_addr, i, steps);
            out->result = r;
            out->steps_executed = steps;
            out->faulted = true;
            out->fault_reason = "memory or internal fault";
            ctx->last_result = r;
            return HB_OK;
        }
        if (instr->op == HB_IR_JMP || instr->op == HB_IR_Jcc || instr->op == HB_IR_LOOP ||
            instr->op == HB_IR_JRCXZ || instr->op == HB_IR_CALL || instr->op == HB_IR_RET ||
            instr->op == HB_IR_FAR_BRANCH) {
            /* `ctx->pc` выставлен самой командой — диспетчер продолжит оттуда. */
            out->result = HB_OK;
            out->steps_executed = steps;
            return HB_OK;
        }
    }
    /* Провал за конец блока: как в общем цикле — pc = следующая команда. */
    {
        const hb_ir_instr_t* last = &block->instrs[block->instr_count - 1];
        ctx->pc = last->guest_addr + last->guest_len;
        sync_arch_pc(ctx);
    }
    out->result = HB_OK;
    out->steps_executed = steps;
    return HB_OK;
}
