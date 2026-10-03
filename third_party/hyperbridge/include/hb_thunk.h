#ifndef HB_THUNK_H
#define HB_THUNK_H

#include "hb_result.h"
#include "hb_context.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HB_IMPORT_THUNK_MAX 4096U
#define HB_IMPORT_THUNK_BASE 0x00006f0000000000ULL
#define HB_IMPORT_THUNK_STRIDE 0x10ULL

/* Thunk function signature */
typedef hb_result_t (*hb_thunk_fn_t)(hb_context_t* ctx);

typedef enum {
    HB_THUNK_SIG_VOID_VOID = 0,
    HB_THUNK_SIG_U32_VOID = 1,
    HB_THUNK_SIG_U32_U32 = 2,
    HB_THUNK_SIG_U64_U64_U64 = 3,
    HB_THUNK_SIG_PTR_PTR = 4,
    HB_THUNK_SIG_U64_VOID = 5,
    HB_THUNK_SIG_VOID_U32 = 6,
    HB_THUNK_SIG_BOOL_HANDLE_PTR_U32_PTR_PTR = 7,
    HB_THUNK_SIG_I32_PTR_CSTR_U64_U64 = 8
} hb_thunk_signature_id_t;

typedef struct {
    uint64_t module_id;
    hb_thunk_signature_id_t signature_id;
    void* target_ptr;
    void* native_entry;
    uint32_t generation;
    bool valid;
} hb_generated_thunk_t;

typedef struct {
    uint32_t generated;
    uint32_t released;
    uint32_t cache_hits;
    uint32_t unsupported;
    bool wx_pages_used;
} hb_thunk_stats_t;

/* Thunk registration */
typedef struct {
    uint32_t id;
    uint64_t guest_target;
    const char* dll_name;
    const char* func_name;
    hb_thunk_fn_t fn;
    const char* description;
} hb_thunk_def_t;

/* Thunk table */
typedef struct hb_thunk_table {
    hb_thunk_def_t* thunks;
    size_t count;
    size_t capacity;
} hb_thunk_table_t;

hb_thunk_table_t* hb_thunk_table_create(void);
void hb_thunk_table_destroy(hb_thunk_table_t* table);

hb_result_t hb_thunk_register(hb_thunk_table_t* table, const hb_thunk_def_t* def);
hb_result_t hb_thunk_unregister(hb_thunk_table_t* table, uint32_t id);
uint64_t hb_thunk_guest_target_from_id(uint32_t id);

hb_thunk_def_t* hb_thunk_find_by_name(hb_thunk_table_t* table, const char* dll, const char* func);
hb_thunk_def_t* hb_thunk_find_by_id(hb_thunk_table_t* table, uint32_t id);

hb_result_t hb_thunk_invoke(hb_thunk_table_t* table, uint32_t id, hb_context_t* ctx);

/* Built-in thunks */
hb_result_t hb_thunk_init_builtins(hb_thunk_table_t* table);

/* Trace */
hb_result_t hb_thunk_trace_enable(hb_thunk_table_t* table, bool enable);
bool hb_thunk_trace_is_enabled(hb_thunk_table_t* table);

hb_result_t hb_thunk_get(const hb_context_t* ctx, uint64_t module_id, hb_thunk_signature_id_t signature_id,
                         void* target_ptr, hb_generated_thunk_t* out);
hb_result_t hb_thunk_release(uint64_t module_id);
hb_result_t hb_thunk_stats(hb_thunk_stats_t* out);
hb_result_t hb_thunk_call_generated(hb_context_t* ctx, const hb_generated_thunk_t* thunk);

#ifdef __cplusplus
}
#endif

#endif
