#ifndef HB_CACHE_MODULE_ID_H
#define HB_CACHE_MODULE_ID_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compute a stable 64-bit module identifier from a PE image in memory.
 * Uses SHA-256 of the full image bytes, then folds into 64 bits.
 * Result is stable across runs for the exact same binary,
 * and changes for any modification (recompile, patch, etc).
 *
 * pe_image: pointer to the loaded PE image bytes (raw file bytes)
 * size:    size in bytes of the image
 * out:     pointer to store the 64-bit module ID
 *
 * Returns 0 on success, -1 on failure.
 */
int hb_cache_compute_module_id(const uint8_t* pe_image, size_t size, uint64_t* out);

#ifdef __cplusplus
}
#endif

#endif
