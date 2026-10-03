#ifndef HB_CACHE_EXT_H
#define HB_CACHE_EXT_H

#include "hb_result.h"
#include "hb_cache.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hb_cache_ext hb_cache_ext_t;

/* Open/close */
hb_cache_ext_t* hb_cache_ext_open(const char* root, uint64_t size_limit);
void            hb_cache_ext_close(hb_cache_ext_t* c);

/* Get native code blob. Caller must free *native_code. */
hb_result_t hb_cache_ext_get(hb_cache_ext_t* c, const hb_cache_key_t* key,
                               uint8_t** native_code, size_t* native_size,
                               uint32_t* steps);

/* Store native code blob. Copies the data; caller retains ownership. */
hb_result_t hb_cache_ext_put(hb_cache_ext_t* c, const hb_cache_key_t* key,
                             const uint8_t* native_code, size_t native_size,
                             uint32_t steps);

/* Invalidate all entries for a module */
hb_result_t hb_cache_ext_invalidate_module(hb_cache_ext_t* c, uint64_t module_id);

/* Evict to size limit (LRU) */
hb_result_t hb_cache_ext_prune(hb_cache_ext_t* c);

/* Clear everything */
hb_result_t hb_cache_ext_clear(hb_cache_ext_t* c);

/* Stats */
typedef struct {
    uint64_t lookups;
    uint64_t hits;
    uint64_t misses;
    uint64_t puts;
    uint64_t evictions;
    uint64_t bytes_stored;
    uint64_t entries_stored;
    uint64_t invalidations;
} hb_cache_ext_stats_t;

hb_result_t hb_cache_ext_stats(hb_cache_ext_t* c, hb_cache_ext_stats_t* out);

#ifdef __cplusplus
}
#endif

#endif
