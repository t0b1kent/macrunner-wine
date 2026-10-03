#ifndef HB_IAT_H
#define HB_IAT_H

#include "hb_result.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HB_IAT_MAX_NAME 96
#define HB_IAT_FLAG_ALLOWLISTED 0x1u
#define HB_IAT_FLAG_APPLIED     0x2u
#define HB_IAT_FLAG_TYPED_THUNK  0x4u

typedef struct {
    uint64_t module_id;
    uint64_t iat_rva;
    void** slot;
    void* original_target;
    void* bridge_target;
    uint32_t guest_machine;
    uint32_t flags;
    char dll_name[HB_IAT_MAX_NAME];
    char import_name[HB_IAT_MAX_NAME];
} hb_iat_rewrite_entry_t;

typedef struct {
    hb_iat_rewrite_entry_t* entries;
    size_t count;
    size_t capacity;
    bool applied;
} hb_iat_rewrite_plan_t;

typedef struct {
    uint32_t rewritten_count;
    uint32_t denied_count;
    uint32_t rollback_count;
    uint32_t bridge_call_count;
} hb_iat_stats_t;

hb_result_t hb_iat_plan_init(hb_iat_rewrite_plan_t* plan, size_t capacity);
void hb_iat_plan_destroy(hb_iat_rewrite_plan_t* plan);
hb_result_t hb_iat_plan_add(hb_iat_rewrite_plan_t* plan, const hb_iat_rewrite_entry_t* entry);
hb_result_t hb_iat_plan_apply(hb_iat_rewrite_plan_t* plan, bool dry_run, hb_iat_stats_t* stats);
hb_result_t hb_iat_plan_rollback(hb_iat_rewrite_plan_t* plan, hb_iat_stats_t* stats);
hb_result_t hb_iat_plan_trace_jsonl(const hb_iat_rewrite_plan_t* plan, const char* path);
uint64_t hb_call_import(uint64_t module_id, uint64_t import_id, void* guest_context);

#ifdef __cplusplus
}
#endif

#endif
