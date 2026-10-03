/* MacRunner 2026-08-06 — счётчик выделений hyperbridge С РАЗБИВКОЙ ПО МЕСТАМ.
 *
 * Замерено: hb_alloc=173 429 451, hb_free=611 879 — освобождается 0.35%. Блоки ИР это
 * не объясняют (живых 222 тыс., кеш вмещает 524 288). Значит выделяет что-то другое,
 * и гадать бессмысленно: считаем по адресу возврата, то есть по конкретной строке кода.
 * Верхняя пятёрка мест печатается вместе с остальными числами.
 */
#ifndef HB_ALLOC_COUNT_H
#define HB_ALLOC_COUNT_H
#include <stdlib.h>
#include <stdint.h>

#define HB_ALLOC_SITES 512
extern unsigned long long hb_alloc_calls;
extern unsigned long long hb_free_calls;
extern uintptr_t          hb_alloc_site_pc[HB_ALLOC_SITES];
extern unsigned long long hb_alloc_site_n[HB_ALLOC_SITES];
extern unsigned long long hb_alloc_site_bytes[HB_ALLOC_SITES];

static inline void hb_alloc_note(uintptr_t pc, size_t bytes) {
    size_t h = (size_t)((pc >> 4) ^ (pc >> 20)) & (HB_ALLOC_SITES - 1);
    for (size_t i = 0; i < 8; i++) {
        size_t s = (h + i) & (HB_ALLOC_SITES - 1);
        uintptr_t cur = __atomic_load_n(&hb_alloc_site_pc[s], __ATOMIC_RELAXED);
        if (cur == pc || cur == 0) {
            if (cur == 0) __atomic_store_n(&hb_alloc_site_pc[s], pc, __ATOMIC_RELAXED);
            __atomic_add_fetch(&hb_alloc_site_n[s], 1, __ATOMIC_RELAXED);
            __atomic_add_fetch(&hb_alloc_site_bytes[s], (unsigned long long)bytes, __ATOMIC_RELAXED);
            return;
        }
    }
}
#define HB_SITE ((uintptr_t)__builtin_return_address(0))

static inline void* hb_counted_malloc(size_t n, uintptr_t pc){
    __atomic_add_fetch(&hb_alloc_calls,1,__ATOMIC_RELAXED); hb_alloc_note(pc,n); return malloc(n); }
static inline void* hb_counted_calloc(size_t a,size_t b,uintptr_t pc){
    __atomic_add_fetch(&hb_alloc_calls,1,__ATOMIC_RELAXED); hb_alloc_note(pc,a*b); return calloc(a,b); }
static inline void* hb_counted_realloc(void*p,size_t n,uintptr_t pc){
    if(!p){ __atomic_add_fetch(&hb_alloc_calls,1,__ATOMIC_RELAXED); hb_alloc_note(pc,n);} return realloc(p,n); }
static inline void  hb_counted_free(void*p){ if(p) __atomic_add_fetch(&hb_free_calls,1,__ATOMIC_RELAXED); free(p); }

#define malloc(n)      hb_counted_malloc((n), HB_SITE)
#define calloc(a,b)    hb_counted_calloc((a),(b), HB_SITE)
#define realloc(p,n)   hb_counted_realloc((p),(n), HB_SITE)
#define free(p)        hb_counted_free(p)
#endif
