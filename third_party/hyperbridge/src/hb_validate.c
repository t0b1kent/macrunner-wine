#include "hb_validate.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

hb_result_t hb_validate_ir(const hb_ir_func_t* func, hb_validate_report_t* out) {
    if (!func || !out) return HB_ERR_INVALID_ARG;
    memset(out, 0, sizeof(hb_validate_report_t));
    out->result = hb_ir_func_validate(func);
    out->passed = (out->result == HB_OK);
    if (!out->passed) out->error_message = "IR validation failed";
    return HB_OK;
}

hb_result_t hb_validate_cfg(const hb_ir_cfg_t* cfg, hb_validate_report_t* out) {
    if (!cfg || !out) return HB_ERR_INVALID_ARG;
    memset(out, 0, sizeof(hb_validate_report_t));
    out->checked_blocks = cfg->block_count;
    out->passed = true;
    for (size_t i = 0; i < cfg->block_count; i++) {
        if (!cfg->blocks[i]) { out->passed = false; out->result = HB_ERR_INVALID_ARG; break; }
    }
    return HB_OK;
}

hb_result_t hhb_validate_execution(const hb_context_t* ctx, const hb_ir_func_t* func, hb_validate_report_t* out) {
    (void)ctx; (void)func; (void)out;
    return HB_ERR_UNSUPPORTED_FEATURE;
}

hb_result_t hb_validate_interpreter_vs_jit(const hb_context_t* ctx, const hb_ir_func_t* func, hb_validate_report_t* out) {
    (void)ctx; (void)func; (void)out;
    return HB_ERR_UNSUPPORTED_FEATURE;
}

char* hb_validate_report_to_json(const hb_validate_report_t* report) {
    if (!report) return strdup("{}");
    char* buf = malloc(1024);
    if (!buf) return strdup("{}");
    snprintf(buf, 1024,
        "{\"passed\":%s,\"result\":%d,\"error\":\"%s\",\"blocks\":%zu,\"instrs\":%zu}",
        report->passed ? "true" : "false",
        (int)report->result,
        report->error_message ? report->error_message : "",
        report->checked_blocks,
        report->checked_instrs);
    return buf;
}
