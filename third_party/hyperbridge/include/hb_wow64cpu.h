#ifndef HB_WOW64CPU_H
#define HB_WOW64CPU_H

#include "hb_context.h"
#include "hb_memory.h"
#include "hb_result.h"
#include "hb_runtime.h"
#include "hb_x87.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HB_WOW64CPU_ABI_VERSION 1u
#define HB_WOW64_MACHINE_I386 0x014cu
#define HB_WOW64_CPURESERVED_FLAG_RESET_STATE 1u

typedef struct {
    uint32_t size;
    uint32_t version;
    hb_memory_t* memory;
    void* guest32_base;
    uint8_t bop_code[2];
    uint32_t bop_size;
    uint32_t owns_memory;
    void* ir_cache;
} hb_wow64_process_t;

typedef struct {
    uint32_t size;
    uint32_t version;
    uint16_t flags;
    uint16_t machine;
    hb_wow64_process_t* process;
    hb_context_t* ctx;
    hb_jit_runtime_t* jit_rt;
} hb_wow64_thread_t;

typedef struct {
    uint32_t size;
    uint32_t version;
    uint32_t eax, ebx, ecx, edx;
    uint32_t esi, edi, esp, ebp;
    uint32_t eip, eflags;
    uint32_t fs_base, gs_base;
    uint16_t seg_cs, seg_ds, seg_es, seg_fs, seg_gs, seg_ss;
    uint32_t seg_reserved;
    hb_x87_state_t x87;
} hb_wow64_i386_context_t;

hb_result_t hb_wow64cpu_process_init(hb_wow64_process_t* process);
void hb_wow64cpu_process_destroy(hb_wow64_process_t* process);

hb_result_t hb_wow64cpu_thread_init(hb_wow64_process_t* process, hb_wow64_thread_t* thread);
void hb_wow64cpu_thread_destroy(hb_wow64_thread_t* thread);

hb_result_t hb_wow64cpu_get_bop_code(const hb_wow64_process_t* process,
                                     const uint8_t** code,
                                     uint32_t* size);

hb_result_t hb_wow64cpu_import_i386_context(hb_wow64_thread_t* thread,
                                            const hb_wow64_i386_context_t* in);
hb_result_t hb_wow64cpu_export_i386_context(const hb_wow64_thread_t* thread,
                                            hb_wow64_i386_context_t* out);
hb_result_t hb_wow64cpu_simulate(hb_wow64_thread_t* thread,
                                 hb_backend_t backend,
                                 size_t max_code_bytes,
                                 hb_exec_result_t* out);

hb_result_t hb_wow64cpu_notify_memory_alloc(hb_wow64_process_t* process,
                                            uint32_t base,
                                            size_t size,
                                            hb_perm_t perm);
hb_result_t hb_wow64cpu_notify_memory_protect(hb_wow64_process_t* process,
                                              uint32_t base,
                                              size_t size,
                                              hb_perm_t perm);
hb_result_t hb_wow64cpu_notify_memory_free(hb_wow64_process_t* process,
                                           uint32_t base,
                                           size_t size);

/* СМЕНА ФЛАГОВ ИСПОЛНЕНИЯ (DEP) НА ХОДУ.
 *
 * Игра может включить или снять DEP уже во время работы (апстрим Wine
 * называет мишень прямо: Bioshock). После этого страницы, бывшие данными,
 * становятся исполняемыми — и наоборот. Весь переведённый код был выпущен
 * при СТАРЫХ правилах, значит стал негодным.
 *
 * Смена редка (обычно один раз при запуске), поэтому верное и дешёвое
 * действие — обесценить перевод целиком, а не гадать, какие страницы задеты. */
hb_result_t hb_wow64cpu_notify_execute_flags(hb_wow64_process_t* process,
                                            uint32_t flags);

#ifdef __cplusplus
}
#endif

#endif
