#ifndef HB_RESULT_H
#define HB_RESULT_H

#ifdef __cplusplus
extern "C" {
#endif

/* HyperBridge result codes */
typedef enum {
    HB_OK = 0,
    HB_ERR_INVALID_ARG = -1,
    HB_ERR_OUT_OF_MEMORY = -2,
    HB_ERR_DECODE_FAILED = -3,
    HB_ERR_LIFT_FAILED = -4,
    HB_ERR_UNSUPPORTED_OPCODE = -5,
    HB_ERR_UNSUPPORTED_FEATURE = -6,
    HB_ERR_JIT_FAILED = -7,
    HB_ERR_MEMORY_FAULT = -8,
    HB_ERR_EXEC_FAULT = -9,
    HB_ERR_STEP_LIMIT = -10,
    HB_ERR_BLOCK_LIMIT = -11,
    HB_ERR_PE_PARSE = -12,
    HB_ERR_PE_RELOC = -13,
    HB_ERR_IMPORT_UNSUPPORTED = -14,
    HB_ERR_SYSCALL_BLOCKED = -15,
    HB_ERR_TIMEOUT = -16,
    HB_ERR_CACHE_CORRUPT = -17,
    HB_ERR_NOT_FOUND = -18,
    HB_ERR_TRANSLATION_TRUNCATED = -19,
    HB_ERR_INTERNAL = -99
} hb_result_t;

static inline const char* hb_result_string(hb_result_t r) {
    switch (r) {
        case HB_OK: return "OK";
        case HB_ERR_INVALID_ARG: return "INVALID_ARG";
        case HB_ERR_OUT_OF_MEMORY: return "OUT_OF_MEMORY";
        case HB_ERR_DECODE_FAILED: return "DECODE_FAILED";
        case HB_ERR_LIFT_FAILED: return "LIFT_FAILED";
        case HB_ERR_UNSUPPORTED_OPCODE: return "UNSUPPORTED_OPCODE";
        case HB_ERR_UNSUPPORTED_FEATURE: return "UNSUPPORTED_FEATURE";
        case HB_ERR_JIT_FAILED: return "JIT_FAILED";
        case HB_ERR_MEMORY_FAULT: return "MEMORY_FAULT";
        case HB_ERR_EXEC_FAULT: return "EXEC_FAULT";
        case HB_ERR_STEP_LIMIT: return "STEP_LIMIT";
        case HB_ERR_BLOCK_LIMIT: return "BLOCK_LIMIT";
        case HB_ERR_PE_PARSE: return "PE_PARSE";
        case HB_ERR_PE_RELOC: return "PE_RELOC";
        case HB_ERR_IMPORT_UNSUPPORTED: return "IMPORT_UNSUPPORTED";
        case HB_ERR_SYSCALL_BLOCKED: return "SYSCALL_BLOCKED";
        case HB_ERR_TIMEOUT: return "TIMEOUT";
        case HB_ERR_CACHE_CORRUPT: return "CACHE_CORRUPT";
        case HB_ERR_NOT_FOUND: return "NOT_FOUND";
        case HB_ERR_TRANSLATION_TRUNCATED: return "TRANSLATION_TRUNCATED";
        case HB_ERR_INTERNAL: return "INTERNAL";
        default: return "UNKNOWN";
    }
}

#ifdef __cplusplus
}
#endif

#endif
