#ifndef HB_PE_H
#define HB_PE_H

#include "hb_result.h"
#include "hb_context.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PE constants */
#define HB_PE_DOS_SIGNATURE 0x5A4D
#define HB_PE_NT_SIGNATURE 0x00004550

/* Machine types */
#define HB_PE_MACHINE_I386 0x014c
#define HB_PE_MACHINE_AMD64 0x8664
#define HB_PE_MACHINE_ARM64 0xaa64

/* Data directory indices */
#define HB_PE_DD_EXPORT 0
#define HB_PE_DD_IMPORT 1
#define HB_PE_DD_RESOURCE 2
#define HB_PE_DD_EXCEPTION 3
#define HB_PE_DD_CERTIFICATE 4
#define HB_PE_DD_BASERELOC 5
#define HB_PE_DD_DEBUG 6
#define HB_PE_DD_ARCHITECTURE 7
#define HB_PE_DD_GLOBALPTR 8
#define HB_PE_DD_TLS 9
#define HB_PE_DD_LOADCONFIG 10
#define HB_PE_DD_BOUNDIMPORT 11
#define HB_PE_DD_IAT 12
#define HB_PE_DD_DELAYIMPORT 13
#define HB_PE_DD_COMDESCRIPTOR 14

/* DOS header */
typedef struct {
    uint16_t e_magic;
    uint32_t e_lfanew;
} hb_pe_dos_t;

/* Section header */
typedef struct {
    char name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_linenumbers;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t characteristics;
} hb_pe_section_t;

/* Import descriptor */
typedef struct {
    uint32_t original_first_thunk;
    uint32_t time_date_stamp;
    uint32_t forwarder_chain;
    uint32_t name_rva;
    uint32_t first_thunk;
} hb_pe_import_desc_t;

/* PE image */
typedef struct {
    hb_pe_dos_t dos;
    uint32_t nt_signature;
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
    uint16_t magic; /* 0x10b = PE32, 0x20b = PE32+ */
    uint32_t entry_point;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t subsystem;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t dll_characteristics;
    uint64_t image_base_64;
    uint32_t base_of_code;
    uint32_t base_of_data; /* PE32 only */
    uint64_t image_base_actual;
    uint32_t number_of_rva_and_sizes;

    uint32_t data_directory[16][2]; /* rva, size */

    hb_pe_section_t* sections;
    uint16_t section_count;

    /* Import info */
    char** import_dlls;
    uint32_t import_dll_count;

    /* Raw file data (borrowed pointer, valid during load/map) */
    const uint8_t* raw_data;
    size_t raw_size;

    /* Mapped image */
    uint8_t* mapped_image;
    size_t mapped_size;
    uint64_t preferred_base;
    uint64_t mapped_base;
} hb_pe_image_t;

/* PE loader API */
hb_pe_image_t* hb_pe_load(const uint8_t* data, size_t size);
void hb_pe_unload(hb_pe_image_t* pe);

hb_result_t hb_pe_map_image(hb_pe_image_t* pe, uint64_t base);

hb_result_t hb_pe_apply_relocations(hb_pe_image_t* pe, uint64_t new_base);

hb_pe_section_t* hb_pe_find_section(hb_pe_image_t* pe, const char* name);
hb_gva_t hb_pe_rva_to_gva(hb_pe_image_t* pe, uint32_t rva);

const char* hb_pe_import_dll_name(hb_pe_image_t* pe, uint32_t rva);
const char* hb_pe_import_func_name(hb_pe_image_t* pe, uint32_t rva);

/* Import resolution */
struct hb_thunk_table;
hb_result_t hb_imports_resolve(hb_pe_image_t* pe, struct hb_thunk_table* thunks);

#ifdef __cplusplus
}
#endif

#endif
