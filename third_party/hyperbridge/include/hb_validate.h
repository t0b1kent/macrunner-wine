#ifndef HB_VALIDATE_H
#define HB_VALIDATE_H

#include "hb_result.h"
#include "hb_ir.h"
#include "hb_context.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Validation options */
typedef struct {
    bool check_ir;
    bool check_cfg;
    bool check_registers;
    bool check_memory;
    bool check_flags;
} hb_validate_opts_t;

/* Validation report */
typedef struct {
    bool passed;
    hb_result_t result;
    const char* error_message;
    uint64_t error_guest_addr;
    size_t checked_instrs;
    size_t checked_blocks;
} hb_validate_report_t;

hb_result_t hb_validate_ir(const hb_ir_func_t* func, hb_validate_report_t* out);
hb_result_t hb_validate_cfg(const hb_ir_cfg_t* cfg, hb_validate_report_t* out);
hb_result_t hhb_validate_execution(const hb_context_t* ctx, const hb_ir_func_t* func, hb_validate_report_t* out);

hb_result_t hb_validate_interpreter_vs_jit(const hb_context_t* ctx, const hb_ir_func_t* func, hb_validate_report_t* out);

char* hb_validate_report_to_json(const hb_validate_report_t* report);

#ifdef __cplusplus
}
#endif

#endif
