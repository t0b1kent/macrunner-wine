#include "hb_bench.h"
#include "hb_context.h"
#include "hb_ir.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

uint64_t hb_bench_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

hb_bench_timer_t hb_bench_start(const char* name) {
    hb_bench_timer_t t = { hb_bench_now_ns(), name };
    return t;
}

uint64_t hb_bench_end(hb_bench_timer_t* timer) {
    if (!timer) return 0;
    return hb_bench_now_ns() - timer->start;
}

hb_result_t hb_bench_run_decode(const uint8_t* code, size_t len, hb_arch_t arch, hb_bench_result_t* out) {
    (void)code; (void)len; (void)arch; (void)out;
    return HB_ERR_UNSUPPORTED_FEATURE;
}
hb_result_t hb_bench_run_lift(const uint8_t* code, size_t len, hb_arch_t arch, hb_bench_result_t* out) {
    (void)code; (void)len; (void)arch; (void)out;
    return HB_ERR_UNSUPPORTED_FEATURE;
}
hb_result_t hb_bench_run_interp(const hb_ir_func_t* func, hb_context_t* ctx, hb_bench_result_t* out) {
    (void)func; (void)ctx; (void)out;
    return HB_ERR_UNSUPPORTED_FEATURE;
}
hb_result_t hb_bench_run_jit(const hb_ir_func_t* func, hb_context_t* ctx, hb_bench_result_t* out) {
    (void)func; (void)ctx; (void)out;
    return HB_ERR_UNSUPPORTED_FEATURE;
}
hb_result_t hb_bench_run_full(const uint8_t* code, size_t len, hb_arch_t arch, hb_backend_t backend, hb_context_t* ctx, hb_bench_result_t* out) {
    (void)code; (void)len; (void)arch; (void)backend; (void)ctx; (void)out;
    return HB_ERR_UNSUPPORTED_FEATURE;
}

char* hb_bench_result_to_json(const hb_bench_result_t* result) {
    if (!result) return strdup("{}");
    char* buf = malloc(2048);
    if (!buf) return strdup("{}");
    snprintf(buf, 2048,
        "{\"decode_ns\":%llu,\"lift_ns\":%llu,\"codegen_ns\":%llu,\"interp_ns\":%llu,\"jit_ns\":%llu}",
        (unsigned long long)result->decode_ns,
        (unsigned long long)result->lift_ns,
        (unsigned long long)result->codegen_ns,
        (unsigned long long)result->interp_exec_ns,
        (unsigned long long)result->jit_exec_ns);
    return buf;
}
