#include "hb_env.h"
#include "hb_gates.h"
#include "hb_pe.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static size_t host_page_size(void) {
    long ps = sysconf(_SC_PAGESIZE);
    return ps > 0 ? (size_t)ps : 4096;
}

static int hb_pe_mprotect(void* addr, size_t len, int prot) {
    if (hb_gate( HB_GATE_HB_TEST_FORCE_PE_MPROTECT_FAIL )) {
        errno = EACCES;
        return -1;
    }
    return mprotect(addr, len, prot);
}

static bool pe_range_fits(size_t size, size_t offset, size_t length) {
    return offset <= size && length <= size - offset;
}

static bool pe_add_size(size_t a, size_t b, size_t* out) {
    if (a > SIZE_MAX - b) return false;
    *out = a + b;
    return true;
}

static bool pe_read_u16(const uint8_t* data, size_t size, size_t offset, uint16_t* out) {
    if (!pe_range_fits(size, offset, 2)) return false;
    *out = (uint16_t)data[offset] | ((uint16_t)data[offset + 1] << 8);
    return true;
}

static bool pe_read_u32(const uint8_t* data, size_t size, size_t offset, uint32_t* out) {
    if (!pe_range_fits(size, offset, 4)) return false;
    *out = (uint32_t)data[offset] |
           ((uint32_t)data[offset + 1] << 8) |
           ((uint32_t)data[offset + 2] << 16) |
           ((uint32_t)data[offset + 3] << 24);
    return true;
}

static bool pe_read_u64(const uint8_t* data, size_t size, size_t offset, uint64_t* out) {
    uint32_t lo, hi;
    if (offset > SIZE_MAX - 4) return false;
    if (!pe_read_u32(data, size, offset, &lo) || !pe_read_u32(data, size, offset + 4, &hi))
        return false;
    *out = (uint64_t)lo | ((uint64_t)hi << 32);
    return true;
}

static bool pe_rva_range_fits(const hb_pe_image_t* pe, uint32_t rva, size_t length) {
    return pe && rva <= pe->mapped_size && length <= pe->mapped_size - rva;
}

hb_pe_image_t* hb_pe_load(const uint8_t* data, size_t size) {
    if (!data || size < 64) return NULL;
    hb_pe_image_t* pe = calloc(1, sizeof(hb_pe_image_t));
    if (!pe) return NULL;
    pe->raw_data = data;
    pe->raw_size = size;

    /* DOS header */
    if (!pe_read_u16(data, size, 0, &pe->dos.e_magic)) { free(pe); return NULL; }
    if (pe->dos.e_magic != HB_PE_DOS_SIGNATURE) { free(pe); return NULL; }
    if (!pe_read_u32(data, size, 60, &pe->dos.e_lfanew)) { free(pe); return NULL; }

    /* NT signature */
    size_t nt_off = pe->dos.e_lfanew;
    if (!pe_range_fits(size, nt_off, 24)) { free(pe); return NULL; }
    if (!pe_read_u32(data, size, nt_off, &pe->nt_signature)) { free(pe); return NULL; }
    if (pe->nt_signature != HB_PE_NT_SIGNATURE) { free(pe); return NULL; }

    /* COFF header */
    size_t coff_off = nt_off + 4;
    if (!pe_read_u16(data, size, coff_off, &pe->machine) ||
        !pe_read_u16(data, size, coff_off + 2, &pe->number_of_sections) ||
        !pe_read_u32(data, size, coff_off + 4, &pe->time_date_stamp) ||
        !pe_read_u16(data, size, coff_off + 16, &pe->size_of_optional_header) ||
        !pe_read_u16(data, size, coff_off + 18, &pe->characteristics)) {
        free(pe);
        return NULL;
    }

    /* Optional header */
    size_t opt_off = coff_off + 20;
    if (!pe_range_fits(size, opt_off, pe->size_of_optional_header) ||
        !pe_read_u16(data, size, opt_off, &pe->magic)) {
        free(pe);
        return NULL;
    }
    if (pe->magic == 0x10b || pe->magic == 0x20b) {
        size_t fixed_min = pe->magic == 0x10b ? 96 : 112;
        size_t num_rva_off = pe->magic == 0x10b ? 92 : 108;
        size_t dir_off = pe->magic == 0x10b ? 96 : 112;

        if (pe->size_of_optional_header < fixed_min) { free(pe); return NULL; }
        if (!pe_read_u32(data, size, opt_off + 16, &pe->entry_point)) { free(pe); return NULL; }
        if (pe->magic == 0x10b) {
            uint32_t image_base32 = 0;
            if (!pe_read_u32(data, size, opt_off + 28, &image_base32)) { free(pe); return NULL; }
            pe->image_base_64 = image_base32;
        } else {
            if (!pe_read_u64(data, size, opt_off + 24, &pe->image_base_64)) { free(pe); return NULL; }
        }
        if (!pe_read_u32(data, size, opt_off + 56, &pe->size_of_image) ||
            !pe_read_u32(data, size, opt_off + 60, &pe->size_of_headers) ||
            !pe_read_u32(data, size, opt_off + num_rva_off, &pe->number_of_rva_and_sizes)) {
            free(pe);
            return NULL;
        }

        size_t available_dirs = pe->size_of_optional_header > dir_off ?
            (pe->size_of_optional_header - dir_off) / 8 : 0;
        size_t dir_count = pe->number_of_rva_and_sizes;
        if (dir_count > 16) dir_count = 16;
        if (dir_count > available_dirs) dir_count = available_dirs;
        for (size_t i = 0; i < dir_count; i++) {
            if (!pe_read_u32(data, size, opt_off + dir_off + i * 8, &pe->data_directory[i][0]) ||
                !pe_read_u32(data, size, opt_off + dir_off + i * 8 + 4, &pe->data_directory[i][1])) {
                free(pe);
                return NULL;
            }
        }
    } else {
        free(pe);
        return NULL;
    }
    pe->preferred_base = pe->image_base_64;

    /* Sections */
    size_t sec_off = 0;
    if (!pe_add_size(opt_off, pe->size_of_optional_header, &sec_off) ||
        pe->number_of_sections > (pe_range_fits(size, sec_off, 0) ? (size - sec_off) / 40 : 0)) {
        free(pe);
        return NULL;
    }
    pe->sections = pe->number_of_sections ? calloc(pe->number_of_sections, sizeof(hb_pe_section_t)) : NULL;
    if (pe->number_of_sections && !pe->sections) { free(pe); return NULL; }
    pe->section_count = pe->number_of_sections;
    for (uint16_t i = 0; i < pe->number_of_sections; i++) {
        size_t cur = sec_off + (size_t)i * 40;
        memcpy(pe->sections[i].name, data + cur, 8);
        if (!pe_read_u32(data, size, cur + 8, &pe->sections[i].virtual_size) ||
            !pe_read_u32(data, size, cur + 12, &pe->sections[i].virtual_address) ||
            !pe_read_u32(data, size, cur + 16, &pe->sections[i].size_of_raw_data) ||
            !pe_read_u32(data, size, cur + 20, &pe->sections[i].pointer_to_raw_data) ||
            !pe_read_u32(data, size, cur + 36, &pe->sections[i].characteristics)) {
            hb_pe_unload(pe);
            return NULL;
        }
    }
    return pe;
}

void hb_pe_unload(hb_pe_image_t* pe) {
    if (!pe) return;
    free(pe->sections);
    for (uint32_t i = 0; i < pe->import_dll_count; i++) free(pe->import_dlls[i]);
    free(pe->import_dlls);
    if (pe->mapped_image) munmap(pe->mapped_image, pe->mapped_size);
    free(pe);
}

hb_result_t hb_pe_map_image(hb_pe_image_t* pe, uint64_t base) {
    if (!pe || !pe->raw_data) return HB_ERR_INVALID_ARG;
    if (pe->mapped_image) { munmap(pe->mapped_image, pe->mapped_size); pe->mapped_image = NULL; }

    size_t map_size = pe->size_of_image;
    if (map_size == 0) return HB_ERR_INVALID_ARG;
    size_t page = host_page_size();
    if (map_size > SIZE_MAX - (page - 1)) return HB_ERR_PE_PARSE;
    map_size = ((map_size + page - 1) / page) * page;

    void* p = mmap((void*)base, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        p = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) return HB_ERR_OUT_OF_MEMORY;
    }
    pe->mapped_image = (uint8_t*)p;
    pe->mapped_size = map_size;
    pe->mapped_base = (uint64_t)(uintptr_t)p;


    /* Copy headers */
    size_t hdr_size = pe->size_of_headers;
    if (hdr_size > pe->raw_size) hdr_size = pe->raw_size;
    if (hdr_size > pe->mapped_size) return HB_ERR_PE_PARSE;
    memcpy(pe->mapped_image, pe->raw_data, hdr_size);

    /* Copy sections */
    for (uint16_t i = 0; i < pe->section_count; i++) {
        hb_pe_section_t* s = &pe->sections[i];
        if (s->virtual_address == 0) continue;
        size_t section_span = s->virtual_size > s->size_of_raw_data ? s->virtual_size : s->size_of_raw_data;
        if (section_span == 0) continue;
        if (s->virtual_address > pe->mapped_size ||
            section_span > pe->mapped_size - s->virtual_address)
            return HB_ERR_PE_PARSE;
        uint8_t* dest = pe->mapped_image + s->virtual_address;
        size_t raw_size = s->size_of_raw_data;
        size_t virt_size = s->virtual_size;
        if (raw_size > 0) {
            if (s->pointer_to_raw_data > pe->raw_size ||
                raw_size > pe->raw_size - s->pointer_to_raw_data)
                return HB_ERR_PE_PARSE;
            memcpy(dest, pe->raw_data + s->pointer_to_raw_data, raw_size);
        }
        if (virt_size > raw_size) {
            memset(dest + raw_size, 0, virt_size - raw_size);
        }
        /* Set permissions based on characteristics */
        int prot = PROT_READ;
        if (s->characteristics & 0x80000000) prot |= PROT_WRITE; /* IMAGE_SCN_MEM_WRITE */
        if (s->characteristics & 0x20000000) prot |= PROT_EXEC; /* IMAGE_SCN_MEM_EXECUTE */
        size_t protect_size = virt_size ? virt_size : raw_size;
        if (protect_size == 0) continue;
        uintptr_t protect_begin = (uintptr_t)dest;
        if (protect_size > UINTPTR_MAX - protect_begin) return HB_ERR_PE_PARSE;
        uintptr_t protect_end = protect_begin + protect_size;
        uintptr_t page_begin = protect_begin - (protect_begin % page);
        if (protect_end > UINTPTR_MAX - (page - 1)) return HB_ERR_PE_PARSE;
        uintptr_t page_end = ((protect_end + page - 1) / page) * page;
        protect_size = (size_t)(page_end - page_begin);
        if (hb_pe_mprotect((void*)page_begin, protect_size, prot) != 0) {
            int err = errno;
            fprintf(stderr, "hb_pe_map_image: mprotect section %.8s rva=0x%x size=0x%zx prot=0x%x failed errno=%d\n",
                    s->name, s->virtual_address, protect_size, prot, err);
            return (prot & PROT_EXEC) ? HB_ERR_JIT_FAILED : HB_ERR_MEMORY_FAULT;
        }
    }

    return HB_OK;
}

hb_result_t hb_pe_apply_relocations(hb_pe_image_t* pe, uint64_t new_base) {
    if (!pe || !pe->mapped_image) return HB_ERR_INVALID_ARG;
    if (new_base == pe->preferred_base) return HB_OK;

    uint32_t reloc_rva = pe->data_directory[HB_PE_DD_BASERELOC][0];
    uint32_t reloc_size = pe->data_directory[HB_PE_DD_BASERELOC][1];
    if (reloc_rva == 0 || reloc_size == 0) return HB_OK;
    if (!pe_rva_range_fits(pe, reloc_rva, reloc_size)) return HB_ERR_PE_PARSE;

    int64_t delta = (int64_t)new_base - (int64_t)pe->preferred_base;
    uint8_t* base = pe->mapped_image;

    uint32_t offset = 0;
    while (offset < reloc_size) {
        uint32_t page_rva, block_size;
        if (reloc_size - offset < 8) return HB_ERR_PE_PARSE;
        if (!pe_read_u32(base, pe->mapped_size, reloc_rva + offset, &page_rva) ||
            !pe_read_u32(base, pe->mapped_size, reloc_rva + offset + 4, &block_size))
            return HB_ERR_PE_PARSE;
        if (block_size < 8 || block_size > reloc_size - offset || (block_size & 1))
            return HB_ERR_PE_PARSE;

        uint32_t num_entries = (block_size - 8) / 2;

        for (uint32_t i = 0; i < num_entries; i++) {
            uint16_t entry;
            if (!pe_read_u16(base, pe->mapped_size, reloc_rva + offset + 8 + i * 2, &entry))
                return HB_ERR_PE_PARSE;
            uint16_t type = (entry >> 12) & 0xF;
            uint16_t off = entry & 0xFFF;

            if (type == 0) continue;
            if (page_rva > UINT32_MAX - off) return HB_ERR_PE_PARSE;
            uint32_t target_rva = page_rva + off;
            if (type == 3) {
                uint32_t value;
                if (!pe_rva_range_fits(pe, target_rva, 4) ||
                    !pe_read_u32(base, pe->mapped_size, target_rva, &value))
                    return HB_ERR_PE_PARSE;
                value = (uint32_t)((int64_t)value + delta);
                uint8_t* addr = base + target_rva;
                memcpy(addr, &value, sizeof(value));
            } else if (type == 10) {
                uint64_t value;
                if (!pe_rva_range_fits(pe, target_rva, 8) ||
                    !pe_read_u64(base, pe->mapped_size, target_rva, &value))
                    return HB_ERR_PE_PARSE;
                value = (uint64_t)((int64_t)value + delta);
                uint8_t* addr = base + target_rva;
                memcpy(addr, &value, sizeof(value));
            }
        }
        offset += block_size;
    }

    return HB_OK;
}

hb_pe_section_t* hb_pe_find_section(hb_pe_image_t* pe, const char* name) {
    if (!pe || !name) return NULL;
    for (uint16_t i = 0; i < pe->section_count; i++) {
        if (strncmp(pe->sections[i].name, name, 8) == 0) return &pe->sections[i];
    }
    return NULL;
}

hb_gva_t hb_pe_rva_to_gva(hb_pe_image_t* pe, uint32_t rva) {
    if (!pe) return 0;
    if (pe->mapped_base) return pe->mapped_base + rva;
    return pe->preferred_base + rva;
}

const char* hb_pe_import_dll_name(hb_pe_image_t* pe, uint32_t rva) {
    if (!pe || !pe->mapped_image || !pe_rva_range_fits(pe, rva, 1)) return NULL;
    return (const char*)(pe->mapped_image + rva);
}

const char* hb_pe_import_func_name(hb_pe_image_t* pe, uint32_t rva) {
    if (!pe || !pe->mapped_image || !pe_rva_range_fits(pe, rva, 3)) return NULL;
    return (const char*)(pe->mapped_image + rva + 2); /* skip hint */
}
