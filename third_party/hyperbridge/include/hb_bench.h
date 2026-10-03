#ifndef HB_BENCH_H
#define HB_BENCH_H

#include "hb_result.h"
#include "hb_context.h"
#include "hb_ir.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Benchmark timers */
typedef struct {
    uint64_t decode_ns;
    uint64_t lift_ns;
    uint64_t optimize_ns;
    uint64_t codegen_ns;
    uint64_t jit_emit_ns;
    uint64_t interp_exec_ns;
    uint64_t jit_exec_ns;
    uint64_t cache_miss_ns;
    uint64_t cache_hit_ns;
    uint64_t pe_load_ns;
    uint64_t thunk_overhead_ns;
    uint64_t total_ns;
    size_t instructions_decoded;
    size_t instructions_lifted;
    size_t blocks_generated;
    size_t cache_hits;
    size_t cache_misses;
} hb_bench_result_t;

typedef struct {
    uint64_t start;
    const char* name;
} hb_bench_timer_t;

uint64_t hb_bench_now_ns(void);
hb_bench_timer_t hb_bench_start(const char* name);
uint64_t hb_bench_end(hb_bench_timer_t* timer);

hb_result_t hb_bench_run_decode(const uint8_t* code, size_t len, hb_arch_t arch, hb_bench_result_t* out);
hb_result_t hb_bench_run_lift(const uint8_t* code, size_t len, hb_arch_t arch, hb_bench_result_t* out);
hb_result_t hb_bench_run_interp(const hb_ir_func_t* func, hb_context_t* ctx, hb_bench_result_t* out);
hb_result_t hb_bench_run_jit(const hb_ir_func_t* func, hb_context_t* ctx, hb_bench_result_t* out);
hb_result_t hb_bench_run_full(const uint8_t* code, size_t len, hb_arch_t arch, hb_backend_t backend, hb_context_t* ctx, hb_bench_result_t* out);

char* hb_bench_result_to_json(const hb_bench_result_t* result);

#ifdef __cplusplus
}
#endif

#endif
