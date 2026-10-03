#ifndef HB_MEMORY_H
#define HB_MEMORY_H

#include "hb_result.h"
#include "hb_context.h"
#include "hb_gates.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define HB_GUEST32_SIZE 0x100000000ULL
#define HB_MEMORY_HOT_CACHE_SLOTS 16

/* MacRunner 2026-07-31 — diagnostic hand-off: the guest block address currently dispatching, written by the
 * runtime ONLY when MACRUNNER_HB_TRACE_NULL_PC is set. hb_memory.c has no ctx, and a quarter of all region
 * lookups resolve to NULL, so the open question is which guest code issues them. Gated because on Darwin a
 * TLS store is not free — _tlv_get_addr is already 7-9 % of the critical thread. */
extern __thread uint64_t hb_trace_current_block_addr;

/* Call-site tag for region lookups, so the null traffic can be attributed across translation units.
 * hb_memory_find_region alone answers NULL 90.8 % of the time and accounts for half of all nulls; these
 * constants say WHICH of its callers. Diagnostic only. */
#define HB_RSITE_JIT_HOST_SPAN  6
#define HB_RSITE_JIT_CODEGEN    7
#define HB_RSITE_INTERP         8
extern __thread int hb_trace_rsite;

/* ★ MacRunner 04.09.2026 — СПРАШИВАТЬ ПЕРЕД ТЕМ, КАК СТАВИТЬ МЕТКУ.
 *
 * Правило записано абзацем выше у hb_trace_current_block_addr («TLS store is not free»),
 * и в hb_memory.c оно соблюдается: там метка ставится только под
 * trace_hot_cache_stats_enabled(). А в hb_arm64_codegen.c два места ставили её
 * БЕЗУСЛОВНО — в том числе hb_jit_helper_host_read_span, общий вход быстрых чтений
 * помощника. Каждая такая запись на Darwin — вызов _tlv_get_addr (1,66 нс, замер
 * scripts/цена-операции), а читают метку только сводки горячего кеша, которые без
 * ручки не печатаются.
 *
 * Предикат объявлен ЗДЕСЬ, а не продублирован в двух файлах: у нас уже был случай,
 * когда прибор мерил по двум разошедшимся базам. Он полностью встраиваемый —
 * hb_gate это чтение таблицы в обычной памяти, — поэтому проверка стоит загрузку и
 * предсказанный переход, а не вызов. */
static inline int hb_trace_rsite_wanted(void)
{
    const char* v = hb_gate( HB_GATE_HB_TRACE_HOT_CACHE );
    return v && *v && *v != '0';
}

#ifdef __cplusplus
extern "C" {
#endif

/* Memory permissions */
typedef enum {
    HB_PERM_NONE = 0,
    HB_PERM_READ = 1 << 0,
    HB_PERM_WRITE = 1 << 1,
    HB_PERM_EXEC = 1 << 2
} hb_perm_t;

/* Memory region */
typedef struct hb_region {
    hb_gva_t base;
    void* host_base; /* backing address for private guest mappings */
    size_t size;
    hb_perm_t perm;
    uint64_t gen;
    uint32_t vma_flags;
    bool is_stack;
    bool is_heap;
    bool is_guard;
    bool is_guest32;
    bool allocated; /* true if hb_memory_map allocated backing memory */
    struct hb_region* next;
    struct hb_region* tree_left;
    struct hb_region* tree_right;
    uint32_t tree_prio;
} hb_region_t;

/* Memory sandbox */
typedef struct hb_memory {
    hb_region_t* regions;
    hb_region_t* region_tree;
    size_t total_size;
    size_t max_size;
    uint64_t generation;
    void* guest32_base;
    size_t guest32_size;
    bool guest32_owned;
    /* ★ MacRunner 25.08.2026 — ТЕНЕВАЯ КАРТА ПРАВ (только guest32).
     *
     * Зачем. Байтовая запись на прямом пути запрещена (вето size8), и запрет обоснован:
     * у байта direct_mem_alignment_mask() == 0, поэтому ветка помощника — та самая, где
     * права и проверялись, — не выпускается вовсе, и сырой STLRB уходит мимо HB_PERM_WRITE.
     * Защита прав была ПОБОЧНЫМ следствием проверки выравнивания.
     *
     * Карта даёт правам собственную проверку, дешёвую настолько, чтобы стоять в выпущенном
     * коде: один байт на страницу 4 КБ, индекс — сдвиг гостевого адреса на 12. Для окна
     * guest32 это 4 ГБ / 4 КБ = 1 048 576 записей, ровно 1 МБ, выделяется лениво при первом
     * отображении. Для x64 карта не заводится: адресное пространство под неё не помещается.
     *
     * Держится в согласии с регионами в ЧЕТЫРЁХ точках: hb_memory_map, hb_memory_map_private,
     * hb_memory_protect и hb_memory_sync_live_range. Других мест, меняющих region->perm, нет. */
    uint8_t* perm_map;
    size_t perm_map_pages;
    hb_gva_t stack_top;
    hb_gva_t stack_bottom;
    hb_gva_t heap_base;
    size_t heap_size;

    hb_result_t (*special_read)(void* user, hb_gva_t addr, void* out, size_t size);
    hb_result_t (*special_write)(void* user, hb_gva_t addr, const void* in, size_t size);
    void* special_user;
    /* Host-side fault recovery: when a live-VM access faults on a page the host
     * has reserved-but-not-committed (e.g. a Windows guard page below a guest
     * stack), this lets the embedder run virtual_handle_fault and commit it so
     * the access can be retried.  Returns true if the page may now be valid. */
    bool (*special_grow)(void* user, hb_gva_t addr);

    /* MRU region cache epoch. Slots are thread-local in hb_memory.c; hot_gen is
     * bumped on structural map changes so per-thread slots cannot outlive a
     * split/remove/rebuild. hot[] is kept zeroed for diagnostics/back-compat. */
    hb_region_t* hot[HB_MEMORY_HOT_CACHE_SLOTS];
    uint64_t     hot_gen;
    /* MacRunner 2026-07-31 — separate epoch for the NEGATIVE (gap) cache. Adds and removes invalidate
     * different things: an add is the only event that can turn "no region here" into a lie, and it can never
     * invalidate a cached region (every add is guarded by any_overlap). Removing/splitting only ever makes
     * more of the address space region-free, so a cached gap stays true. Keeping them apart means an add no
     * longer wipes every thread's positive cache, and the two counters do not share write traffic. */
    uint64_t     add_gen;
} hb_memory_t;

hb_memory_t* hb_memory_create(size_t max_size);
void hb_memory_init_environment(void);
void hb_memory_destroy(hb_memory_t* mem);

hb_result_t hb_memory_map(hb_memory_t* mem, hb_gva_t base, size_t size, hb_perm_t perm);
hb_result_t hb_memory_map_private(hb_memory_t* mem, hb_gva_t base, size_t size, hb_perm_t perm);
/* Replace the metadata for an existing host-owned live range with one
 * authoritative, fully covered region.  This never changes host VM protection. */
hb_result_t hb_memory_sync_live_range(hb_memory_t* mem, hb_gva_t base, size_t size, hb_perm_t perm);
hb_result_t hb_memory_unmap(hb_memory_t* mem, hb_gva_t base);
hb_result_t hb_memory_protect(hb_memory_t* mem, hb_gva_t base, size_t size, hb_perm_t perm);

hb_result_t hb_memory_guest32_reserve(hb_memory_t* mem);
void* hb_memory_guest32_base(const hb_memory_t* mem);
void* hb_memory_guest32_to_host(hb_memory_t* mem, uint32_t guest_addr);
hb_result_t hb_memory_guest32_map(hb_memory_t* mem, uint32_t base, size_t size, hb_perm_t perm);
hb_result_t hb_memory_guest32_unmap(hb_memory_t* mem, uint32_t base, size_t size);
/* Довести хозяйскую защиту страницы гостя до его карты (склейка «отказ -> доводка ->
 * повтор» для прямого доступа к памяти). HB_OK = применено, можно повторять команду. */
hb_result_t hb_memory_guest32_resync_protection(hb_memory_t* mem, uint32_t guest_addr);
/* То же по ХОЗЯЙСКОМУ адресу — для обработчика сигнала, который объекта памяти не знает. */
hb_result_t hb_memory_guest32_resync_by_host(uint64_t host_addr);
hb_result_t hb_memory_guest32_protect(hb_memory_t* mem, uint32_t base, size_t size, hb_perm_t perm);
uint64_t hb_memory_generation(const hb_memory_t* mem);
uint64_t hb_memory_region_generation(hb_memory_t* mem, hb_gva_t addr);

hb_result_t hb_memory_read(hb_memory_t* mem, hb_gva_t addr, void* out, size_t size);
hb_result_t hb_memory_write(hb_memory_t* mem, hb_gva_t addr, const void* in, size_t size);
void* hb_memory_host_ptr(hb_memory_t* mem, hb_gva_t addr, size_t size, hb_perm_t perm);

/* Теневая карта прав: адрес карты для выпущенного кода (NULL, если её нет) и запись
 * диапазона. Значение в карте — те же биты HB_PERM_*, что у региона. */
/* Карта прав, смещённая под ХОЗЯЙСКИЙ адрес: выпущенный код проверки
 * получает адрес уже переведённым в окно. Ноль — карты нет. */
uint64_t hb_memory_perm_map_host_biased(hb_memory_t* mem);

uint8_t* hb_memory_perm_map(hb_memory_t* mem);
void hb_memory_perm_map_set(hb_memory_t* mem, hb_gva_t base, size_t size, hb_perm_t perm);

/* Адрес ПОСЛЕДНЕГО отказавшего гостевого обращения в этом потоке (см. hb_memory.c).
 * Нужен, чтобы `JIT helper fault` называл адрес, а не только причину: block_pc на HK лежит
 * в коде Mono и в каждом прогоне другой. valid=0 — отказов в этом потоке ещё не было. */
void hb_memory_last_fault(uint64_t* addr, size_t* size, int* is_write, int* valid);
void hb_memory_set_special_handlers(hb_memory_t* mem,
                                    hb_result_t (*read_fn)(void* user, hb_gva_t addr, void* out, size_t size),
                                    hb_result_t (*write_fn)(void* user, hb_gva_t addr, const void* in, size_t size),
                                    void* user);
void hb_memory_set_grow_handler(hb_memory_t* mem, bool (*grow_fn)(void* user, hb_gva_t addr));

hb_result_t hb_memory_read_u8(hb_memory_t* mem, hb_gva_t addr, uint8_t* out);
hb_result_t hb_memory_read_u16(hb_memory_t* mem, hb_gva_t addr, uint16_t* out);
hb_result_t hb_memory_read_u32(hb_memory_t* mem, hb_gva_t addr, uint32_t* out);
hb_result_t hb_memory_read_u64(hb_memory_t* mem, hb_gva_t addr, uint64_t* out);

hb_result_t hb_memory_write_u8(hb_memory_t* mem, hb_gva_t addr, uint8_t val);
hb_result_t hb_memory_write_u16(hb_memory_t* mem, hb_gva_t addr, uint16_t val);
hb_result_t hb_memory_write_u32(hb_memory_t* mem, hb_gva_t addr, uint32_t val);
hb_result_t hb_memory_write_u64(hb_memory_t* mem, hb_gva_t addr, uint64_t val);

hb_result_t hb_memory_fetch(hb_memory_t* mem, hb_gva_t addr, uint8_t* out);

hb_region_t* hb_memory_find_region(hb_memory_t* mem, hb_gva_t addr);

/* ★★★★★ MacRunner 2026-08-29 — ОБХОД БЕЗ ФИЛЬТРА guest32.
 *
 * hb_memory_find_region на адресе гостя i386 отвечает NULL В ДВУХ РАЗНЫХ СЛУЧАЯХ:
 *   1) региона действительно нет в дереве;
 *   2) регион ЕСТЬ и содержит адрес, но у него is_guest32 == 0 —
 *      см. find_region_impl: `return n->is_guest32 ? n : NULL`.
 * Снаружи эти состояния неразличимы, а лечение у них противоположное. Склейка двух
 * приборов в одно значение уже стоила дня (память two-instruments-merged-into-one-number).
 *
 * Эта функция обходит ТО ЖЕ дерево и возвращает узел как есть, не глядя на метку.
 * Только для диагностики: на горячем пути не звать. */
hb_region_t* hb_memory_find_region_raw(hb_memory_t* mem, hb_gva_t addr);

/* Запрос гостевого региона со стороны хоста (ntdll), для NtQueryVirtualMemory.
 *
 * Зачем. У нас ДВА адресных пространства: гостевое (0x87ef...) и хостовое, которое выдаёт mmap.
 * hb_memory_map_private кладёт пару base/host_base в свою таблицу, а Windows-учёт знает только
 * про хостовое. Поэтому NtQueryVirtualMemory отвечает MEM_FREE по адресу внутри живого
 * UnityPlayer: гостевой адрес для него - координата чужой системы.
 *
 * Заводить вид на такой адрес нельзя (он не хостовый). Правильный ответ - спросить таблицу,
 * которая уже знает всё нужное, ПЕРЕД тем как ответить MEM_FREE.
 *
 * Возвращает 1 и заполняет выходы, если регион найден; 0 если нет. Указатель, а не слабый
 * символ: libhyperbridge.dylib собирается отдельно и обязана разрешить все символы. */
extern int (*hb_guest_region_query_cb)(uint64_t addr, uint64_t* out_base,
                                       uint64_t* out_size, uint32_t* out_perm);
bool hb_memory_can_read(hb_memory_t* mem, hb_gva_t addr, size_t size);
bool hb_memory_can_write(hb_memory_t* mem, hb_gva_t addr, size_t size);
bool hb_memory_can_exec(hb_memory_t* mem, hb_gva_t addr, size_t size);
bool hb_memory_can_read_span(hb_memory_t* mem, hb_gva_t addr, size_t size);
bool hb_memory_can_write_span(hb_memory_t* mem, hb_gva_t addr, size_t size);

hb_result_t hb_memory_setup_stack(hb_memory_t* mem, hb_gva_t top, size_t size);
hb_result_t hb_memory_setup_heap(hb_memory_t* mem, hb_gva_t base, size_t size);

#ifdef __cplusplus
}
#endif

#endif
