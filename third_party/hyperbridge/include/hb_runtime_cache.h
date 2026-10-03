#ifndef HB_RUNTIME_CACHE_H
#define HB_RUNTIME_CACHE_H

#include "hb_cache_ext.h"
#include "hb_context.h"
#include "hb_ir.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Env knob MACRUNNER_HB_AOT_CACHE values */
typedef enum {
    HB_AOT_CACHE_OFF,
    HB_AOT_CACHE_READ,
    HB_AOT_CACHE_WRITE,
    HB_AOT_CACHE_READWRITE
} hb_aot_cache_mode_t;

/* Parse env knob. Default is OFF if unset, READWRITE if set to empty string. */
hb_aot_cache_mode_t hb_aot_cache_env_mode(void);

/* Attach a persistent AOT cache to a context.
 * Opens the cache lazily according to mode. If mode is OFF, does nothing. */
hb_result_t hb_aot_cache_attach(hb_context_t* ctx, hb_aot_cache_mode_t mode);

/* Detach and close the cache attached to ctx. Safe to call even if never attached. */
void hb_aot_cache_detach(hb_context_t* ctx);

/* Compute a cache key for an IR block based on original guest bytes.
 * Reads the raw x86 bytes from ctx->memory at block->guest_addr.
 * Returns HB_ERR_NOT_FOUND if guest memory is unreadable. */
hb_result_t hb_aot_cache_key_for_block(const hb_context_t* ctx,
                                       const hb_ir_block_t* block,
                                       hb_cache_key_t* out_key);

/* Convenience: store a compiled block to the context's attached cache.
 * Does nothing if ctx->aot_cache is NULL or mode is READ-only. */
hb_result_t hb_aot_cache_store_compiled(hb_context_t* ctx,
                                        const hb_cache_key_t* key,
                                        const uint8_t* native_code,
                                        size_t native_size,
                                        uint32_t steps);

#ifdef __cplusplus
}
#endif

#endif
