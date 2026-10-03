#ifndef HB_CACHE_H
#define HB_CACHE_H

#include "hb_result.h"
#include "hb_ir.h"
#include "hb_codegen.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Cache key */
typedef struct {
    uint32_t version;
    uint32_t abi_version;
    uint64_t module_id;
    uint32_t page_generation;
    uint8_t arch;
    uint8_t mode;
    uint8_t backend;
    uint8_t flags;
    uint64_t code_hash;
    uint64_t guest_addr;
    uint64_t code_len;
} hb_cache_key_t;

/* Cache entry */
typedef struct {
    hb_cache_key_t key;
    uint64_t timestamp;
    bool valid;
    bool unsupported;
    const char* unsupported_reason;
    hb_ir_func_t* ir; /* may be NULL if only storing code */
    uint8_t* native_code;
    size_t native_size;
    uint64_t decode_ns;
    uint64_t lift_ns;
    uint64_t codegen_ns;
    uint32_t steps;
} hb_cache_entry_t;

/* Cache handle */
typedef struct hb_cache hb_cache_t;

typedef struct {
    uint32_t format_version;
    uint32_t abi_version;
} hb_cache_options_t;

typedef struct {
    uint64_t lookups;
    uint64_t hits;
    uint64_t misses;
    uint64_t bytes_stored;
    uint64_t entries_stored;
    uint64_t entries_loaded;
    uint64_t entries_current;
    uint64_t invalidations;
    uint64_t corrupt_entries_ignored;
} hb_cache_stats_t;

hb_cache_t* hb_cache_open(const char* root, const hb_cache_options_t* options);
hb_cache_t* hb_cache_create(const char* path);
void hb_cache_destroy(hb_cache_t* cache);
void hb_cache_close(hb_cache_t* cache);

hb_result_t hb_cache_get(hb_cache_t* cache, const hb_cache_key_t* key, hb_cache_entry_t** out);
hb_result_t hb_cache_put(hb_cache_t* cache, const hb_cache_key_t* key, hb_cache_entry_t* entry);
hb_result_t hb_cache_lookup(hb_cache_t* cache, const hb_cache_key_t* key, hb_cache_entry_t** out);
hb_result_t hb_cache_store(hb_cache_t* cache, const hb_cache_key_t* key, const uint8_t* native_blob, size_t native_size, const hb_cache_entry_t* metadata);
hb_result_t hb_cache_invalidate(hb_cache_t* cache, uint32_t version);
hb_result_t hb_cache_invalidate_module(hb_cache_t* cache, uint64_t module_id);
hb_result_t hb_cache_prune(hb_cache_t* cache, uint64_t max_bytes);
hb_result_t hb_cache_clear(hb_cache_t* cache);
hb_result_t hb_cache_stats(hb_cache_t* cache, hb_cache_stats_t* out);
void hb_cache_entry_free(hb_cache_entry_t* entry);

hb_result_t hb_cache_key_compute(const uint8_t* code, size_t len, hb_arch_t arch, uint32_t version, hb_cache_key_t* out);

/* Process-wide sharing (MACRUNNER_HB_CACHE_SHARED=1): how many distinct handles were actually
 * loaded vs how many opens were satisfied by reusing the existing one. Reported so an arm can be
 * proven to have taken the shared path rather than assumed to have. */
void hb_cache_shared_stats(unsigned long long* opens, unsigned long long* reuses);

#ifdef __cplusplus
}
#endif

#endif
