#ifndef HB_CACHE_DIR_H
#define HB_CACHE_DIR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Resolve the canonical MacRunner HyperBridge cache directory.
 * Uses sysdir_start_search_path_enumeration(SYSDIR_DIRECTORY_CACHES)
 * on macOS, falling back to ~/.cache/macrunner-hyperbridge/.
 * The returned string is heap-allocated; caller must free().
 * Returns NULL on failure.
 */
char* hb_cache_dir_resolve(void);

/* Ensure the cache directory and its subdirectories exist.
 * Creates directories recursively (mkdir -p behavior).
 * Returns 0 on success, -1 on failure.
 */
int hb_cache_dir_ensure(const char* path);

#ifdef __cplusplus
}
#endif

#endif
