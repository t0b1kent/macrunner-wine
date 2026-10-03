#ifndef HB_CACHE_EVICTION_H
#define HB_CACHE_EVICTION_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* An entry in the LRU list. Kept in-memory only; not serialized. */
typedef struct hb_cache_lru_entry {
    uint64_t module_id;
    uint64_t code_hash;
    uint64_t guest_addr;
    uint64_t timestamp;
    uint64_t native_size;
    char     path[128];
    struct hb_cache_lru_entry* next;
    struct hb_cache_lru_entry* prev;
} hb_cache_lru_entry_t;

typedef struct {
    hb_cache_lru_entry_t* head;  /* MRU */
    hb_cache_lru_entry_t* tail;  /* LRU */
    uint64_t total_size;
    uint64_t entry_count;
    uint64_t size_limit;
} hb_cache_lru_t;

hb_cache_lru_t* hb_cache_lru_create(uint64_t size_limit);
void            hb_cache_lru_destroy(hb_cache_lru_t* lru);

/* Touch (or insert) an entry, moving it to MRU position */
void hb_cache_lru_touch(hb_cache_lru_t* lru, const hb_cache_lru_entry_t* info);

/* Remove a specific entry by key */
void hb_cache_lru_remove(hb_cache_lru_t* lru, uint64_t module_id, uint64_t code_hash, uint64_t guest_addr);

/* Evict LRU entries until total_size <= size_limit.
 * Calls the provided callback for each evicted entry so the caller
 * can delete the underlying file. */
typedef void (*hb_cache_evict_cb)(const char* path, void* user_data);
void hb_cache_lru_evict(hb_cache_lru_t* lru, hb_cache_evict_cb cb, void* user_data);

/* Remove all entries. Same callback mechanism as evict. */
void hb_cache_lru_clear(hb_cache_lru_t* lru, hb_cache_evict_cb cb, void* user_data);

#ifdef __cplusplus
}
#endif

#endif
