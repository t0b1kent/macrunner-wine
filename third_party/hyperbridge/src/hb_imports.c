#include "hb_pe.h"
#include "hb_thunk.h"
#include <stdlib.h>
#include <string.h>

static bool rva_span_in_image(const hb_pe_image_t* pe, uint32_t rva, size_t size) {
    if (!pe || !pe->mapped_image) return false;
    if ((size_t)rva > pe->mapped_size) return false;
    return size <= pe->mapped_size - (size_t)rva;
}

static size_t min_size(size_t a, size_t b) {
    return a < b ? a : b;
}

hb_result_t hb_imports_resolve(hb_pe_image_t* pe, hb_thunk_table_t* thunks) {
    if (!pe || !pe->mapped_image || !thunks) return HB_ERR_INVALID_ARG;

    uint32_t import_rva = pe->data_directory[HB_PE_DD_IMPORT][0];
    uint32_t import_size = pe->data_directory[HB_PE_DD_IMPORT][1];
    if (import_rva == 0 || import_size == 0) return HB_OK; /* no imports */
    if (!rva_span_in_image(pe, import_rva, import_size)) return HB_ERR_PE_PARSE;

    uint8_t* base = pe->mapped_image;
    hb_pe_import_desc_t* desc = (hb_pe_import_desc_t*)(base + import_rva);
    size_t desc_count = import_size / sizeof(*desc);

    for (size_t desc_idx = 0; desc_idx < desc_count; desc_idx++, desc++) {
        if (desc->name_rva == 0) return HB_OK;
        if (!rva_span_in_image(pe, desc->name_rva, 1)) return HB_ERR_PE_PARSE;
        const char* dll_name = hb_pe_import_dll_name(pe, desc->name_rva);
        if (!dll_name) break;

        uint32_t oft_rva = desc->original_first_thunk ? desc->original_first_thunk : desc->first_thunk;
        if (!rva_span_in_image(pe, oft_rva, sizeof(uint64_t)) ||
            !rva_span_in_image(pe, desc->first_thunk, sizeof(uint64_t))) {
            return HB_ERR_PE_PARSE;
        }
        uint64_t* orig_thunk = (uint64_t*)(base + oft_rva);
        uint64_t* iat = (uint64_t*)(base + desc->first_thunk);
        size_t max_orig = (pe->mapped_size - oft_rva) / sizeof(uint64_t);
        size_t max_iat = (pe->mapped_size - desc->first_thunk) / sizeof(uint64_t);
        size_t max_import = import_size / sizeof(uint64_t);
        size_t max_thunks = min_size(max_import, min_size(max_orig, max_iat));
        if (max_thunks == 0) return HB_ERR_PE_PARSE;

        size_t idx = 0;
        while (idx < max_thunks) {
            uint64_t entry = orig_thunk[idx];
            if (entry == 0) break;

            if (entry & 0x8000000000000000ULL) {
                /* Ordinal import — not supported in MVP */
                iat[idx] = 0xDEADBEEF;
            } else {
                const char* func_name = hb_pe_import_func_name(pe, (uint32_t)entry);
                if (func_name) {
                    hb_thunk_def_t* thunk = hb_thunk_find_by_name(thunks, dll_name, func_name);
                    if (thunk) {
                        if (!thunk->guest_target) return HB_ERR_IMPORT_UNSUPPORTED;
                        iat[idx] = thunk->guest_target;
                    } else {
                        iat[idx] = 0xDEADBEEF; /* unresolved sentinel */
                    }
                } else {
                    iat[idx] = 0xDEADBEEF;
                }
            }
            idx++;
        }
        if (idx == max_thunks) return HB_ERR_PE_PARSE;
    }

    return HB_ERR_PE_PARSE;
}
