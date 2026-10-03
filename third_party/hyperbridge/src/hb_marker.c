#include "hb_marker.h"
#include "hb_pe.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

bool hb_marker_machine_supported(uint32_t machine) {
    return machine == HB_PE_MACHINE_I386 || machine == HB_PE_MACHINE_AMD64;
}

bool hb_marker_section_allowed(uint32_t machine, uint32_t characteristics, uint64_t section_size, bool allow_wx) {
    if (!hb_marker_machine_supported(machine)) return false;
    if ((characteristics & HB_PE_SECTION_EXECUTE) == 0) return false;
    if ((characteristics & HB_PE_SECTION_DISCARD) != 0) return false;
    if (!allow_wx && (characteristics & HB_PE_SECTION_WRITE) != 0) return false;
    if (section_size < 16) return false;
    return true;
}

static void json_escape(FILE* fp, const char* s) {
    if (!s) return;
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') fputc('\\', fp);
        if (*s == '\n') fputs("\\n", fp);
        else fputc(*s, fp);
    }
}

hb_result_t hb_marker_emit_jsonl(const char* path, hb_marker_event_t event, const hb_wine_pe_section_marker_t* marker, const char* reason) {
    if (!path || !marker) return HB_ERR_INVALID_ARG;
    FILE* fp = fopen(path, "a");
    if (!fp) return HB_ERR_NOT_FOUND;
    fprintf(fp, "{\"event\":\"%s\",\"abi_version\":%u,\"machine\":%u,\"module_id\":%llu,\"image_base\":%llu,\"section_rva\":%llu,\"section_size\":%llu,\"characteristics\":%u,\"protect\":%u,\"module_path\":\"",
            event == HB_MARKER_EVENT_UNLOAD ? "unload" : "load",
            marker->abi_version, marker->machine,
            (unsigned long long)marker->module_id,
            (unsigned long long)marker->image_base,
            (unsigned long long)marker->section_rva,
            (unsigned long long)marker->section_size,
            marker->characteristics, marker->protect);
    json_escape(fp, marker->module_path);
    fprintf(fp, "\",\"reason\":\"");
    json_escape(fp, reason ? reason : "");
    fprintf(fp, "\"}\n");
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    return HB_OK;
}

hb_result_t hb_marker_emit_unload_jsonl(const char* path, uint64_t module_id, uint64_t image_base, const char* module_path, const char* reason) {
    hb_wine_pe_section_marker_t marker;
    memset(&marker, 0, sizeof(marker));
    marker.abi_version = HB_WINE_PE_MARKER_ABI_VERSION;
    marker.module_id = module_id;
    marker.image_base = image_base;
    if (module_path) strncpy(marker.module_path, module_path, sizeof(marker.module_path) - 1);
    return hb_marker_emit_jsonl(path, HB_MARKER_EVENT_UNLOAD, &marker, reason);
}
