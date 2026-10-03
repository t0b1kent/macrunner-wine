#include "hb_fault.h"
#include <stdlib.h>
#include <string.h>

static uint64_t page_base(uint64_t addr) { return addr & ~0xfffULL; }

hb_result_t hb_fault_dispatcher_init(hb_fault_dispatcher_t* dispatcher, size_t capacity) {
    if (!dispatcher || capacity == 0) return HB_ERR_INVALID_ARG;
    memset(dispatcher, 0, sizeof(*dispatcher));
    dispatcher->blocks = calloc(capacity, sizeof(hb_fault_block_t));
    if (!dispatcher->blocks) return HB_ERR_OUT_OF_MEMORY;
    dispatcher->capacity = capacity;
    dispatcher->global_generation = 1;
    return HB_OK;
}

void hb_fault_dispatcher_destroy(hb_fault_dispatcher_t* dispatcher) {
    if (!dispatcher) return;
    free(dispatcher->blocks);
    memset(dispatcher, 0, sizeof(*dispatcher));
}

hb_result_t hb_fault_register_block(hb_fault_dispatcher_t* d, uint64_t native_start, uint64_t native_end, uint64_t module_id, uint64_t guest_start, uint64_t guest_end) {
    return hb_fault_register_block_points(d, native_start, native_end, module_id, guest_start, guest_end, NULL, 0);
}

hb_result_t hb_fault_register_block_points(hb_fault_dispatcher_t* d, uint64_t native_start, uint64_t native_end, uint64_t module_id, uint64_t guest_start, uint64_t guest_end, const hb_fault_point_t* points, size_t point_count) {
    if (!d || native_start >= native_end || guest_start >= guest_end) return HB_ERR_INVALID_ARG;
    if (d->count >= d->capacity) return HB_ERR_OUT_OF_MEMORY;
    if (!points) point_count = 0;
    d->blocks[d->count++] = (hb_fault_block_t){native_start, native_end, module_id, guest_start, guest_end, d->global_generation, true, point_count ? points : NULL, point_count};
    return HB_OK;
}

/* Точки отсортированы по native_off, поэтому берём последнюю, что не больше искомого:
 * отказ внутри развёрнутого перевода инструкции принадлежит ЕЙ, а не следующей.  Это и
 * есть та точность, которой не даёт пропорция. */
bool hb_fault_point_index(const uint32_t* offsets, size_t stride, size_t count,
                          uint32_t native_off, size_t* out_index) {
    size_t lo = 0, hi;
    if (!offsets || !stride || !count || !out_index) return false;
    /* Смещение РАНЬШЕ первой записи — это пролог блока, выпущенный до первой команды гостя.
     * Ответа тут нет по существу, и выдумывать нулевой индекс нельзя: вызывающий обязан сам
     * решить, годится ли ему «гость стоит на первой команде». */
    if (native_off < offsets[0]) return false;
    hi = count - 1;
    while (lo < hi) {
        size_t mid = lo + (hi - lo + 1) / 2;   /* верхняя середина: сходимся к последней подходящей */
        if (offsets[mid * stride] <= native_off) lo = mid; else hi = mid - 1;
    }
    *out_index = lo;
    return true;
}

/* Найти гостевое смещение по смещению в ARM-коде блока: тонкая обёртка над общим поиском.
 * hb_fault_point_t — пара из двух uint32_t, поэтому шаг между хозяйскими смещениями = 2 слова. */
static bool point_lookup(const hb_fault_block_t* b, uint64_t native_off, uint64_t* guest_off_out) {
    size_t idx;
    if (!b->points || !b->point_count) return false;
    if (native_off > 0xffffffffULL) return false;   /* блок длиннее 4 ГБ невозможен */
    if (!hb_fault_point_index(&b->points[0].native_off, 2, b->point_count,
                              (uint32_t)native_off, &idx))
        return false;
    *guest_off_out = b->points[idx].guest_off;
    return true;
}

hb_result_t hb_fault_classify(hb_fault_dispatcher_t* d, uint64_t pc, bool is_execute, bool is_write, hb_fault_result_t* out) {
    if (!d || !out) return HB_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    out->fault_class = HB_FAULT_CLASS_OUTSIDE;
    for (size_t i = 0; i < d->count; i++) {
        hb_fault_block_t* b = &d->blocks[i];
        if (!b->valid) continue;
        if (pc >= b->native_start && pc < b->native_end) {
            uint64_t guest_off;
            out->fault_class = b->page_generation == d->global_generation ? HB_FAULT_CLASS_NATIVE_BLOCK : HB_FAULT_CLASS_STALE_BLOCK;
            out->module_id = b->module_id;
            if (point_lookup(b, pc - b->native_start, &guest_off)) {
                out->guest_pc = b->guest_start + guest_off;
                out->guest_pc_exact = true;
            } else {
                /* Блок переведён без таблицы точек.  Пропорция здесь заведомо неверна —
                 * оставляем её только для отладочной печати и помечаем как негодную:
                 * в CONTEXT гостя такое писать нельзя, иначе получаем прежние pc=0/sp=0. */
                out->guest_pc = b->guest_start + (pc - b->native_start);
                out->guest_pc_approx = true;
            }
            out->page_generation = b->page_generation;
            if (out->fault_class == HB_FAULT_CLASS_STALE_BLOCK) d->stale_rejections++;
            return HB_OK;
        }
        if (pc >= b->guest_start && pc < b->guest_end) {
            /* Отказ по ГОСТЕВОМУ адресу: тут pc и есть гостевой pc, ничего восстанавливать
             * не нужно — значение точное по построению. */
            out->fault_class = is_write ? HB_FAULT_CLASS_DIRTY_WRITE : (is_execute ? HB_FAULT_CLASS_EXECUTE_GUEST : HB_FAULT_CLASS_OUTSIDE);
            out->module_id = b->module_id;
            out->guest_pc = pc;
            out->guest_pc_exact = true;
            out->page_generation = d->global_generation;
            return HB_OK;
        }
    }
    return HB_OK;
}

hb_result_t hb_fault_mark_dirty(hb_fault_dispatcher_t* d, uint64_t module_id, uint64_t guest_page) {
    if (!d) return HB_ERR_INVALID_ARG;
    d->global_generation++;
    d->dirty_invalidations++;
    guest_page = page_base(guest_page);
    for (size_t i = 0; i < d->count; i++) {
        hb_fault_block_t* b = &d->blocks[i];
        if (b->module_id == module_id && page_base(b->guest_start) == guest_page) b->page_generation = d->global_generation - 1;
    }
    return HB_OK;
}

hb_result_t hb_fault_unload_module(hb_fault_dispatcher_t* d, uint64_t module_id) {
    if (!d) return HB_ERR_INVALID_ARG;
    for (size_t i = 0; i < d->count; i++) if (d->blocks[i].module_id == module_id) d->blocks[i].valid = false;
    return HB_OK;
}

hb_result_t hb_fault_lazy_translate(hb_fault_dispatcher_t* d, uint64_t module_id, uint64_t guest_pc, uint64_t native_start, uint64_t native_end) {
    if (!d) return HB_ERR_INVALID_ARG;
    d->lazy_translations++;
    return hb_fault_register_block(d, native_start, native_end, module_id, guest_pc, guest_pc + (native_end - native_start));
}
