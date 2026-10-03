#ifndef __XTAJIT_PRIVATE_H
#define __XTAJIT_PRIVATE_H

#include <stdint.h>
#include "windef.h"
#include "winnt.h"
#include "wine/unixlib.h"

/* ★ Ответ моста: что карта ДВИЖКА знает про гостевой адрес. */
struct xtajit_probe_params
{
    uint32_t addr;      /* вход: гостевой адрес */
    uint32_t known;     /* выход: регион найден */
    uint32_t can_read;
    uint32_t can_write;
    uint32_t can_exec;
    uint64_t host;      /* выход: хозяйский адрес по карте движка (0 = неизвестен) */
    uint64_t base;      /* выход: начало региона */
    uint64_t size;      /* выход: размер региона */
};

enum xtajit_unix_funcs
{
    unix_process_init,
    unix_thread_init,
    unix_thread_term,
    unix_process_term,
    unix_simulate,
    unix_notify_memory_alloc,
    unix_notify_memory_protect,
    unix_notify_execute_flags,
    unix_notify_memory_free,
    unix_notify_map_view,
    unix_notify_unmap_view,
    unix_flush_instruction_cache,
    /* ★ MacRunner 2026-08-28 — МОСТ К КАРТЕ ДВИЖКА.
     * PE-сторона не может звать `hb_memory_*` напрямую, а решения принимаются
     * именно по этой карте: `guest32_host_ptr` в cpu.c — простая склейка старших
     * битов и НИКОГДА не возвращает ноль, поэтому проверка через неё бесполезна
     * (дала «0 нарушений при 34 модулях», когда в карте движка было 3 региона). */
    unix_probe_guest_addr,
    unix_funcs_count
};

struct xtajit_i386_context
{
    DWORD eax, ebx, ecx, edx;
    DWORD esi, edi, esp, ebp;
    DWORD eip, eflags;
    DWORD fs_base, gs_base;
    WORD seg_cs, seg_ds, seg_es, seg_fs, seg_gs, seg_ss;
    ULONG_PTR teb32_host;
    DWORD teb32_size;
    DWORD wow32_reserved;
    WORD  x87_cw, x87_sw, x87_tw;
};

struct xtajit_simulate_params
{
    struct xtajit_i386_context context;
    ULONG max_code_bytes;
    NTSTATUS status;
    LONG hb_result;
    ULONG faulted;
    ULONG64 steps;
    ULONG64 blocks;
    /* Итерация 805: вид отказа и адрес цели. Нужны, чтобы `pass_guest_exception` заполнил
     * запись исключения так же, как это делает Windows: признак ИСПОЛНЕНИЯ и адрес перехода.
     * 0 = вида нет (см. HB_FAULT_KIND_* в hb_context.h). */
    ULONG fault_kind;
    ULONG64 fault_addr;
    ULONG fault_addr_valid;
    /* ★★★★ 27.08.2026 — ВИД ДОСТУПА И АДРЕС ДЛЯ ОБЫЧНОГО ОТКАЗА ПАМЯТИ.
     *
     * `pass_guest_exception` заполняла ExceptionInformation[0]/[1] нулями с примечанием
     * «HyperBridge does not yet report write faults» и «faulting address is not exported yet»,
     * то есть сообщала гостю «чтение по адресу 0» на КАЖДОМ нарушении доступа. Обработчик
     * игры читает ровно эти два поля: Heroes III получал ложь, пробовал чинить нулевую
     * страницу, падал снова — и рекурсия обрывалась нашей защитой depth>=3, превращая
     * ловимое исключение в фатальное.
     *
     * Правда всё это время лежала рядом: `hb_memory_last_fault()` отдаёт адрес, размер и
     * признак записи, и та же печать `macrunner-hb-helper-fault-addr` их показывает.
     * Поля дописаны В КОНЕЦ — структура ходит через unixlib, порядок трогать нельзя. */
    ULONG64 mem_fault_addr;
    ULONG mem_fault_valid;
    ULONG mem_fault_is_write;
};

struct xtajit_memory_params
{
    void *addr;
    SIZE_T size;
    ULONG type;
    ULONG protect;
    BOOL is_post;
    NTSTATUS status;
};

#endif
