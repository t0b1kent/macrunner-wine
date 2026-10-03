#ifndef HB_MARKER_H
#define HB_MARKER_H

#include "hb_result.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HB_WINE_PE_MARKER_ABI_VERSION 1u
#define HB_PE_SECTION_EXECUTE 0x20000000u
#define HB_PE_SECTION_WRITE   0x80000000u
#define HB_PE_SECTION_DISCARD 0x02000000u

typedef enum {
    HB_MARKER_EVENT_LOAD = 1,
    HB_MARKER_EVENT_UNLOAD = 2
} hb_marker_event_t;

typedef struct {
    uint32_t abi_version;
    uint32_t machine;
    uint64_t module_id;
    uint64_t image_base;
    uint64_t section_rva;
    uint64_t section_size;
    uint32_t characteristics;
    uint32_t protect;
    char module_path[260];
} hb_wine_pe_section_marker_t;

bool hb_marker_machine_supported(uint32_t machine);
bool hb_marker_section_allowed(uint32_t machine, uint32_t characteristics, uint64_t section_size, bool allow_wx);
hb_result_t hb_marker_emit_jsonl(const char* path, hb_marker_event_t event, const hb_wine_pe_section_marker_t* marker, const char* reason);
hb_result_t hb_marker_emit_unload_jsonl(const char* path, uint64_t module_id, uint64_t image_base, const char* module_path, const char* reason);

#ifdef __cplusplus
}
#endif

#endif
