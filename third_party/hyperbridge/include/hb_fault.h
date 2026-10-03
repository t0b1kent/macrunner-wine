#ifndef HB_FAULT_H
#define HB_FAULT_H

#include "hb_result.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HB_FAULT_CLASS_OUTSIDE = 0,
    HB_FAULT_CLASS_EXECUTE_GUEST = 1,
    HB_FAULT_CLASS_NATIVE_BLOCK = 2,
    HB_FAULT_CLASS_DIRTY_WRITE = 3,
    HB_FAULT_CLASS_STALE_BLOCK = 4
} hb_fault_class_t;

/* MacRunner 2026-08-05 — ТАБЛИЦА ТОЧЕК.
 *
 * Одна запись на гостевую инструкцию: где её перевод начинается в ARM-коде блока и
 * какому адресу x86 он соответствует.  Оба смещения — от начала блока, поэтому 8 байт
 * на инструкцию хватает и таблица переезжает вместе с блоком без правок.
 *
 * Зачем.  До этого гостевой адрес отказа ВЫЧИСЛЯЛСЯ пропорцией
 * `guest_start + (pc - native_start)`, что верно только при «одна инструкция x86 = одна
 * инструкция ARM» — то есть никогда: x86 переменной длины и разворачивается в несколько
 * наших.  Отсюда мусорный `guest_pc`, а при промахе мимо блоков — ноль, который дальше
 * превращался в `sp=0` и `macrunner-hb-exception-stack-write-failed`.
 *
 * Почему именно таблица, а не «канонический контекст на каждой инструкции».  Второй путь
 * выбрала Rosetta 2 и платит за него кодогенерацией — по их же формулировке это «почти
 * полностью исключает межинструкционные оптимизации», то есть налог на КАЖДОЕ исполнение.
 * Таблица платит памятью: она записывается один раз при трансляции, при исполнении её не
 * читает никто, открывают только в момент отказа.  Так делают QEMU (восстановление
 * состояния по боковым данным) и box64, у которого это даже вынесено рычагом
 * BOX64_DYNAREC_NOARCH: уровни 0/1/2 торгуют ОБЪЁМОМ ПАМЯТИ и надёжностью обработки
 * сигналов, но ни один не обещает выигрыша в скорости исполнения — его там и нет. */
typedef struct {
    uint32_t native_off;   /* смещение начала перевода инструкции от native_start */
    uint32_t guest_off;    /* смещение самой инструкции x86 от guest_start */
} hb_fault_point_t;

typedef struct {
    uint64_t native_start;
    uint64_t native_end;
    uint64_t module_id;
    uint64_t guest_start;
    uint64_t guest_end;
    uint32_t page_generation;
    bool valid;
    const hb_fault_point_t* points;  /* NULL, если блок переведён без таблицы */
    size_t point_count;
} hb_fault_block_t;

typedef struct {
    hb_fault_block_t* blocks;
    size_t count;
    size_t capacity;
    uint32_t global_generation;
    uint64_t lazy_translations;
    uint64_t dirty_invalidations;
    uint64_t stale_rejections;
} hb_fault_dispatcher_t;

typedef struct {
    hb_fault_class_t fault_class;
    uint64_t module_id;
    uint64_t guest_pc;
    uint32_t page_generation;
    /* MacRunner 2026-08-05: ноль в guest_pc раньше нельзя было отличить от «адрес и правда
     * ноль» и от «мы не знаем».  Теперь знаем: guest_pc годится ТОЛЬКО при exact=true.
     * approx=true — есть блок, но нет таблицы точек, значение получено пропорцией и
     * пригодно разве что для отладочной печати, но не для записи в CONTEXT гостя. */
    bool guest_pc_exact;
    bool guest_pc_approx;
} hb_fault_result_t;

/* ★★★ MacRunner 2026-09-04 — ОДИН ДВОИЧНЫЙ ПОИСК НА ВЕСЬ ДВИЖОК.
 *
 * ЗАЧЕМ. До сегодня такой поиск в дереве был ДВАЖДЫ и по-разному:
 *   • `point_lookup` (hb_fault.c) — покрыт тестами, из движка не звался НИ ОДНОГО раза;
 *   • `ripmap_guest_for_host_pc` (hb_runtime.c) — звался, тестами не покрыт.
 * Расхождение такой пары не поймал бы НИ ОДИН счётчик: обе возвращают правдоподобный адрес
 * ИЗ ТОГО ЖЕ блока, то есть неверный ответ неотличим от верного по виду. Реализация одна.
 *
 * `stride` — расстояние между хозяйскими смещениями в 32-битных словах: 2 у hb_fault_point_t
 * (пары native/guest лежат вперемежку), 1 у карты кодогенератора (host_off[] отдельный массив).
 *
 * Возврат false = ОТВЕТА НЕТ (пустая таблица либо смещение раньше первой записи). Молчаливый
 * ноль здесь запрещён: ноль — законный гостевой адрес, и «не знаю» обязано быть отличимо,
 * иначе в CONTEXT гостя уедет pc=0 (ровно тот отказ, ради которого таблица и заведена). */
bool hb_fault_point_index(const uint32_t* offsets, size_t stride, size_t count,
                          uint32_t native_off, size_t* out_index);

hb_result_t hb_fault_dispatcher_init(hb_fault_dispatcher_t* dispatcher, size_t capacity);
void hb_fault_dispatcher_destroy(hb_fault_dispatcher_t* dispatcher);
hb_result_t hb_fault_register_block(hb_fault_dispatcher_t* dispatcher, uint64_t native_start, uint64_t native_end, uint64_t module_id, uint64_t guest_start, uint64_t guest_end);
/* Как hb_fault_register_block, но с таблицей точек.  points должны быть отсортированы по
 * native_off по возрастанию и жить не меньше блока (кодогенератор кладёт их рядом с кодом).
 * points=NULL/count=0 равнозначно hb_fault_register_block. */
hb_result_t hb_fault_register_block_points(hb_fault_dispatcher_t* dispatcher, uint64_t native_start, uint64_t native_end, uint64_t module_id, uint64_t guest_start, uint64_t guest_end, const hb_fault_point_t* points, size_t point_count);
hb_result_t hb_fault_classify(hb_fault_dispatcher_t* dispatcher, uint64_t pc, bool is_execute, bool is_write, hb_fault_result_t* out);
hb_result_t hb_fault_mark_dirty(hb_fault_dispatcher_t* dispatcher, uint64_t module_id, uint64_t guest_page);
hb_result_t hb_fault_unload_module(hb_fault_dispatcher_t* dispatcher, uint64_t module_id);
hb_result_t hb_fault_lazy_translate(hb_fault_dispatcher_t* dispatcher, uint64_t module_id, uint64_t guest_pc, uint64_t native_start, uint64_t native_end);

#ifdef __cplusplus
}
#endif

#endif
