/* MacRunner 2026-09-07, лейн ПОВТОР-3 — ЗАПИСЬ ПОТОКА ГОСТЯ.
 * Разбор замысла — в include/hb_record.h. Здесь только устройство.
 *
 * ЧЕТЫРЕ РЕШЕНИЯ И ПРИЧИНА КАЖДОГО
 *
 * 1. Память гостя выгружается через `mach_vm_read_overwrite`, а не memcpy.
 *    Права области — снимок на момент её регистрации, и к моменту выгрузки они
 *    могут быть уже другими. memcpy по такой странице роняет прогон, а
 *    `mach_vm_read_overwrite` возвращает КОД ОШИБКИ. Прибор, который может
 *    убить измеряемое, не прибор.
 *
 * 2. Классификатора «хост против гостя» здесь НЕТ намеренно — см. заголовок.
 *
 * 3. Записи хоста ловятся ОКНАМИ вокруг доводов вызова, а не полным сличением
 *    памяти. Полное сличение стоит гигабайт на событие; окна стоят десятков
 *    килобайт. Цена — окна видят не всё, и это НЕ прячется: доля пойманного
 *    измеряется самим повтором (расхождение хода исполнения), а не объявляется.
 *
 * 4. Состояние пишется ТОЛЬКО там, где оно нужно повтору (возврат от хоста).
 *    У выхода и у возврата после перевода блока состояние движка совпадает —
 *    писать его дважды значит утроить объём записи без единого нового факта.
 *
 * ПОТОЛКИ НАЗВАНЫ ЧИСЛОМ И ПЕЧАТАЮТСЯ. Прибор без объявленного потолка врёт
 * молча: усечение выглядит как отсутствие явления.
 *
 * НА ГОРЯЧЕМ ПУТИ НЕТ БОЛЬШИХ КАДРОВ. Буфер записей — файловая статика, а не
 * массив на стеке: `hb_record_enter` зовётся с каждого входа в диспетчер, и
 * сдвиг вершины стека на десятки килобайт там упирался бы в сторожевую
 * страницу потока.
 */
#include "hb_record.h"
#include "hb_memory.h"
#include "hb_env.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif

/* ─────────────────────── настройки и их умолчания ─────────────────────── */

#define HB_REC_PAGE          4096u          /* единица карты ненулевых страниц */
#define HB_REC_MAX_WINDOWS   16             /* окон наблюдения на один выход */
#define HB_REC_WINDOW_MAX    1024u
#define HB_REC_WINDOW_DEF    256u
#define HB_REC_EVENTS_DEF    200000ull
#define HB_REC_MAXBYTES_DEF  (6ull << 30)   /* потолок выгрузки памяти */
#define HB_REC_MAXREGION_DEF (512ull << 20) /* потолок одной области */
#define HB_REC_VM_CEILING    0x00007fffffff0000ull
#define HB_REC_WBUF          (64u * 1024u)

/* ───────────────────────────── состояние ─────────────────────────────── */

struct hb_rec_window {
    uint64_t addr;
    uint32_t len;
    uint8_t  pre[HB_REC_WINDOW_MAX];
};

static int      g_rec_fd = -1;
static int      g_rec_armed;          /* гейт разобран */
static int      g_rec_on;             /* запись идёт */
static int      g_rec_done;           /* отрезок закрыт */
static uint64_t g_rec_skip_enters;
static int      g_rec_state_all;
static uint64_t g_rec_max_events;
static uint64_t g_rec_window;
static uint64_t g_rec_max_bytes;
static uint64_t g_rec_max_region;
static const char* g_rec_dir;

static uint64_t g_rec_enters_seen;    /* входов до взведения */
static uint64_t g_rec_events;
static uint64_t g_rec_host_calls;
static uint64_t g_rec_map_events;
/* Сторож от заворота: hb_record_map зовётся ИЗ hb_memory_map, а запись события
 * сама memory не трогает — но если когда-нибудь тронет, заворот съест стек
 * молча. Флаг стоит одну инструкцию и снимает целый класс отказа. */
static int g_rec_in_map;
static uint64_t g_rec_host_writes;
static uint64_t g_rec_host_write_bytes;
static uint64_t g_rec_regions;
static uint64_t g_rec_region_bytes;
static uint64_t g_rec_skipped_regions;
static uint64_t g_rec_skipped_bytes;
static uint64_t g_rec_seq;
static uint64_t g_rec_events_off;
static uint64_t g_rec_entry_pc;
static uint64_t g_rec_write_errors;
static uint64_t g_rec_windows_total;  /* сколько окон снято за отрезок */
static uint64_t g_rec_lift_returns;   /* возвратов «блок перевели», без хоста */

/* ★★★★ ПОВТОР-7: ПОМЕТКА ВСЕХ МЕСТ ВЫХОДА. Разбор — в hb_record.h.
 *
 * `g_rec_exit_written` — написан ли выход ДЛЯ ЭТОГО ЗАХОДА. По нему пометка у
 * вызывающего молчит там, где именованное место уже отчиталось; без него на
 * каждый выход `no_block` в записи лежало бы ДВА события, и число заходов
 * разошлось бы с числом выходов вдвое.
 *
 * `g_rec_no_exit` — входов, перед которыми выхода в записи НЕТ. Это и есть
 * прибор шага: до правки он равен 142 861 из 271 431 (52,6 %), после правки
 * обязан идти к нулю. Печатается БЕЗУСЛОВНО, строкой итога.
 * `g_rec_site_suppressed` — сколько выходов проглочено маской гейта: без него
 * «маска сняла пометку» и «места не случилось» выглядели бы одинаково. */
static int      g_rec_exit_written;
static uint64_t g_rec_site_mask = HB_REC_SITEBIT_ALL;
static uint64_t g_rec_exit_sites[4];      /* по HB_REC_EXIT_* */
static uint64_t g_rec_no_exit;
static uint64_t g_rec_site_suppressed;

/* Поток-хозяин записи. Один поток несёт 94,5-95,4 % работы (база, §2.2), и
 * писать надо ЕГО. Остальные потоки прибор не трогает вовсе — и это названо
 * границей, а не умолчано. */
static pthread_t g_rec_owner;
static int       g_rec_owner_set;

/* Окна, снятые на последнем выходе; сличаются на следующем входе. */
static struct hb_rec_window g_rec_win[HB_REC_MAX_WINDOWS];
static unsigned              g_rec_win_n;
static uint64_t              g_rec_last_exit_pc;
static int                   g_rec_have_exit;

static uint8_t g_rec_wbuf[HB_REC_WBUF];
static uint8_t g_rec_now[HB_REC_WINDOW_MAX];
static uint8_t g_rec_chunk[64 * 1024];

/* ───────────────────────────── мелочи ────────────────────────────────── */

static uint64_t hb_rec_env_u64(const char* name, uint64_t def)
{
    const char* v = hb_env(name);
    char* end = NULL;
    unsigned long long r;
    if (!v || !*v) return def;
    r = strtoull(v, &end, 0);
    if (end == v) return def;
    return (uint64_t)r;
}

static int hb_rec_write_all(int fd, const void* p, size_t n)
{
    const uint8_t* b = (const uint8_t*)p;
    while (n) {
        ssize_t w = write(fd, b, n);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            g_rec_write_errors++;
            return -1;
        }
        b += (size_t)w;
        n -= (size_t)w;
    }
    return 0;
}

/* Чтение памяти гостя БЕЗ риска убить прогон. Возвращает 1, если прочитано. */
static int hb_rec_read_guest(uint64_t addr, void* out, size_t len)
{
#ifdef __APPLE__
    mach_vm_size_t got = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(),
                                              (mach_vm_address_t)addr,
                                              (mach_vm_size_t)len,
                                              (mach_vm_address_t)(uintptr_t)out,
                                              &got);
    return (kr == KERN_SUCCESS && got == (mach_vm_size_t)len);
#else
    memcpy(out, (const void*)(uintptr_t)addr, len);
    return 1;
#endif
}

/* ─────────────────── выгрузка образа памяти гостя ────────────────────── */

/* Одна область: страницы, затем карта ненулевых страниц. Нулевые страницы не
 * пишутся вовсе — на образе гостя это снимает бОльшую часть объёма, а повтор
 * восстанавливает их нулями, что и есть их содержимое. */
static void hb_rec_dump_region(uint64_t base, uint64_t size, uint32_t perm,
                               hb_record_region_t* out)
{
    uint64_t pages = (size + HB_REC_PAGE - 1) / HB_REC_PAGE;
    uint64_t bmbytes = (pages + 7) / 8;
    uint8_t* bitmap;
    uint64_t off, written = 0;
    off_t data_pos, bitmap_pos;
    uint32_t flags = 0;

    memset(out, 0, sizeof(*out));
    out->base = base;
    out->size = size;
    out->perm = perm;

    bitmap = (uint8_t*)calloc(1, (size_t)(bmbytes ? bmbytes : 1));
    if (!bitmap) { out->flags = HB_REC_REG_SKIPPED; return; }

    data_pos = lseek(g_rec_fd, 0, SEEK_CUR);
    if (data_pos < 0) { free(bitmap); out->flags = HB_REC_REG_SKIPPED; return; }

    for (off = 0; off < size; off += sizeof(g_rec_chunk)) {
        uint64_t want = size - off;
        uint64_t p;
        if (want > sizeof(g_rec_chunk)) want = sizeof(g_rec_chunk);
        if (!hb_rec_read_guest(base + off, g_rec_chunk, (size_t)want)) {
            /* Не прочиталось — так и записываем: дыра, бит не ставим. Дыра,
             * выданная за нули, дороже дыры названной. */
            flags |= HB_REC_REG_HOLES;
            continue;
        }
        for (p = 0; p < want; p += HB_REC_PAGE) {
            uint64_t plen = want - p;
            uint64_t idx = (off + p) / HB_REC_PAGE;
            size_t i;
            int nonzero = 0;
            if (plen > HB_REC_PAGE) plen = HB_REC_PAGE;
            for (i = 0; i < (size_t)plen; i++)
                if (g_rec_chunk[p + i]) { nonzero = 1; break; }
            if (!nonzero) continue;
            if (hb_rec_write_all(g_rec_fd, g_rec_chunk + p, (size_t)plen) != 0) {
                free(bitmap);
                out->flags = HB_REC_REG_SKIPPED;
                return;
            }
            bitmap[idx >> 3] |= (uint8_t)(1u << (idx & 7));
            written += plen;
        }
    }

    bitmap_pos = lseek(g_rec_fd, 0, SEEK_CUR);
    if (bitmap_pos < 0 || hb_rec_write_all(g_rec_fd, bitmap, (size_t)bmbytes) != 0) {
        free(bitmap);
        out->flags = HB_REC_REG_SKIPPED;
        return;
    }
    free(bitmap);

    out->flags = flags | HB_REC_REG_DUMPED;
    out->data_off = (uint64_t)data_pos;
    out->data_bytes = written;
    out->bitmap_off = (uint64_t)bitmap_pos;
    out->bitmap_bytes = bmbytes;
}

/* Обход живой карты памяти процесса. Права берутся ТЕКУЩИЕ, а не снимок
 * регистрации: расхождение между ними уже стоило проекту прогонов. */
static void hb_rec_dump_memory(hb_record_region_t** tbl_out, uint64_t* n_out)
{
    hb_record_region_t* tbl = NULL;
    uint64_t cap = 0, n = 0;
#ifdef __APPLE__
    mach_vm_address_t addr = 0;
    mach_port_t task = mach_task_self();

    while (addr < HB_REC_VM_CEILING) {
        mach_vm_address_t region = addr;
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        uint32_t perm = 0;
        kern_return_t kr;

        kr = mach_vm_region(task, &region, &size, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &count, &object);
        if (object != MACH_PORT_NULL) mach_port_deallocate(task, object);
        if (kr != KERN_SUCCESS) break;
        if (region >= HB_REC_VM_CEILING) break;
        if (region + size < region) break;

        if (info.protection & VM_PROT_READ)    perm |= (uint32_t)HB_PERM_READ;
        if (info.protection & VM_PROT_WRITE)   perm |= (uint32_t)HB_PERM_WRITE;
        if (info.protection & VM_PROT_EXECUTE) perm |= (uint32_t)HB_PERM_EXEC;

        addr = region + size;
        if (addr <= region) break;
        if (!(perm & (uint32_t)HB_PERM_READ)) continue;

        if (n == cap) {
            uint64_t ncap = cap ? cap * 2 : 256;
            hb_record_region_t* t = (hb_record_region_t*)realloc(tbl,
                                        (size_t)ncap * sizeof(*tbl));
            if (!t) break;
            tbl = t;
            cap = ncap;
        }

        if ((uint64_t)size > g_rec_max_region ||
            g_rec_region_bytes + (uint64_t)size > g_rec_max_bytes) {
            memset(&tbl[n], 0, sizeof(tbl[n]));
            tbl[n].base = (uint64_t)region;
            tbl[n].size = (uint64_t)size;
            tbl[n].perm = perm;
            tbl[n].flags = HB_REC_REG_SKIPPED;
            g_rec_skipped_regions++;
            g_rec_skipped_bytes += (uint64_t)size;
            n++;
            continue;
        }

        hb_rec_dump_region((uint64_t)region, (uint64_t)size, perm, &tbl[n]);
        if (tbl[n].flags & HB_REC_REG_DUMPED) g_rec_region_bytes += tbl[n].data_bytes;
        n++;
    }
#else
    (void)tbl; (void)cap;
#endif
    *tbl_out = tbl;
    *n_out = n;
}

/* ────────────────────── окна наблюдения за хостом ────────────────────── */

static void hb_rec_add_window(hb_context_t* ctx, uint64_t addr)
{
    unsigned i;
    uint32_t len = (uint32_t)g_rec_window;

    if (!addr || g_rec_win_n >= HB_REC_MAX_WINDOWS) return;
    /* Указатель в первые 64 КБ адресного пространства доводом не бывает — это
     * счётчик, дескриптор или ноль, и окно на нём стоило бы проб впустую. */
    if (addr < 0x10000ull || addr >= HB_REC_VM_CEILING) return;
    addr &= ~(uint64_t)7;

    for (i = 0; i < g_rec_win_n; i++)
        if (g_rec_win[i].addr == addr) return;   /* довод повторился */

    if (!ctx || !ctx->memory ||
        !hb_memory_can_read_span(ctx->memory, (hb_gva_t)addr, len))
        return;
    if (!hb_rec_read_guest(addr, g_rec_win[g_rec_win_n].pre, len)) return;

    g_rec_win[g_rec_win_n].addr = addr;
    g_rec_win[g_rec_win_n].len = len;
    g_rec_win_n++;
    g_rec_windows_total++;
}

/* Окна ставятся на доводы вызова x64 (rcx/rdx/r8/r9), на вершину стека гостя и
 * на ОДИН уровень косвенности от доводов: возвращаемая структура сплошь и рядом
 * лежит не по адресу довода, а по указателю внутри него. Глубже не идём — это
 * уже обход графа, и цена растёт без границы. */
static void hb_rec_arm_windows(hb_context_t* ctx)
{
    const hb_regs_x64_t* r;
    unsigned base_n, i;

    g_rec_win_n = 0;
    if (!ctx) return;
    r = &ctx->regs.x64;

    hb_rec_add_window(ctx, r->rcx);
    hb_rec_add_window(ctx, r->rdx);
    hb_rec_add_window(ctx, r->r8);
    hb_rec_add_window(ctx, r->r9);
    if (r->rsp > 0x40) hb_rec_add_window(ctx, r->rsp - 0x40);
    hb_rec_add_window(ctx, r->rsp + g_rec_window);

    base_n = g_rec_win_n;
    for (i = 0; i < base_n && g_rec_win_n < HB_REC_MAX_WINDOWS; i++) {
        unsigned k;
        for (k = 0; k < 8 && g_rec_win_n < HB_REC_MAX_WINDOWS; k++) {
            uint64_t v;
            if ((k + 1) * 8 > g_rec_win[i].len) break;
            memcpy(&v, g_rec_win[i].pre + k * 8, 8);
            hb_rec_add_window(ctx, v);
        }
    }
}

/* ─────────────────────────── поток событий ───────────────────────────── */

/* Что хост написал в память гостя, видно как разница окна «до» и «после».
 * Соседние изменённые байты склеиваются в один диапазон: заголовок диапазона
 * стоит 12 байт, поэтому разрывать его ради семи совпавших байт дороже. */
/* ZAPIS-CUT-BEGIN — приёмка вырезает кусок ОТСЮДА по эти якоря
 * (scripts/тест-записи-и-повтора.sh). Тест, пересказывающий проверяемый код
 * своими словами, зеленел бы и при опечатке в оригинале; здесь разъедутся
 * якоря — и тест ОТКАЖЕТ, а не соврёт. Якоря не переименовывать. */
static uint32_t hb_rec_emit_writes(uint8_t* buf, uint32_t cap, uint32_t* n_out)
{
    uint32_t used = 0;
    uint32_t n = 0;
    unsigned i;

    for (i = 0; i < g_rec_win_n; i++) {
        uint32_t len = g_rec_win[i].len;
        const uint8_t* pre = g_rec_win[i].pre;
        uint32_t p = 0;
        if (!hb_rec_read_guest(g_rec_win[i].addr, g_rec_now, len)) continue;
        while (p < len) {
            uint32_t s, e, span, need;
            if (g_rec_now[p] == pre[p]) { p++; continue; }
            s = p;
            e = p + 1;
            for (;;) {
                uint32_t run = 0;
                while (e + run < len && g_rec_now[e + run] == pre[e + run]) run++;
                if (run >= 8 || e + run >= len) break;
                e += run + 1;              /* короткий совпавший кусок — внутрь */
            }
            span = e - s;
            need = (12u + span + 7u) & ~7u;
            if (used + need > cap) { *n_out = n; return used; }
            {
                uint64_t a = g_rec_win[i].addr + s;
                uint32_t l = span;
                memcpy(buf + used, &a, 8);
                memcpy(buf + used + 8, &l, 4);
                memcpy(buf + used + 12, g_rec_now + s, span);
                if (need > 12u + span)
                    memset(buf + used + 12 + span, 0, need - 12u - span);
            }
            used += need;
            n++;
            g_rec_host_writes++;
            g_rec_host_write_bytes += span;
            p = e;
        }
    }
    *n_out = n;
    return used;
}
/* ZAPIS-CUT-END */

static void hb_rec_state_from(hb_context_t* ctx, hb_record_state_t* st)
{
    memset(st, 0, sizeof(*st));
    st->regs = ctx->regs.x64;
    st->flags = ctx->flags;
    st->lazy = ctx->lazy_flags;
    st->gs_base = ctx->gs_base;
    st->fs_base = ctx->fs_base;
}

static void hb_rec_write_event(hb_context_t* ctx, uint16_t kind, uint32_t site,
                               uint64_t pc, int with_state,
                               const uint8_t* wbuf, uint32_t wlen, uint32_t nwrites)
{
    hb_record_event_t ev;
    hb_record_state_t st;
    uint32_t slen = with_state ? (uint32_t)sizeof(st) : 0u;

    ev.total_len = (uint32_t)sizeof(ev) + slen + wlen;
    ev.kind = kind;
    ev.flags = with_state ? (uint16_t)HB_REC_EV_STATE : (uint16_t)0;
    ev.site = site;
    ev.n_writes = nwrites;
    ev.pc = pc;
    ev.seq = g_rec_seq++;

    if (hb_rec_write_all(g_rec_fd, &ev, sizeof(ev)) != 0) return;
    if (with_state) {
        hb_rec_state_from(ctx, &st);
        if (hb_rec_write_all(g_rec_fd, &st, sizeof(st)) != 0) return;
    }
    if (wlen && hb_rec_write_all(g_rec_fd, wbuf, wlen) != 0) return;
    g_rec_events++;
}

/* ─────────────────────────── подъём и итог ───────────────────────────── */

static void hb_rec_setup(void)
{
    g_rec_armed = 1;
    g_rec_dir = hb_env("MACRUNNER_HB_RECORD_DIR");
    if (!g_rec_dir || !*g_rec_dir) return;
    g_rec_skip_enters = hb_rec_env_u64("MACRUNNER_HB_RECORD_SKIP_ENTERS", 0);
    /* Состояние на КАЖДОМ событии стоит ~488 байт. Для узкого среза это
     * дёшево и даёт повтору сверку хода исполнения на каждом шаге; для
     * длинного отрезка гейт снимает его со всего, кроме возвратов от хоста,
     * без которых повтор невозможен вовсе. */
    g_rec_state_all   = hb_rec_env_u64("MACRUNNER_HB_RECORD_STATE_ALL", 1) != 0;
    g_rec_max_events  = hb_rec_env_u64("MACRUNNER_HB_RECORD_MAX_EVENTS", HB_REC_EVENTS_DEF);
    g_rec_window      = hb_rec_env_u64("MACRUNNER_HB_RECORD_WINDOW", HB_REC_WINDOW_DEF);
    g_rec_max_bytes   = hb_rec_env_u64("MACRUNNER_HB_RECORD_MAX_BYTES", HB_REC_MAXBYTES_DEF);
    g_rec_max_region  = hb_rec_env_u64("MACRUNNER_HB_RECORD_MAX_REGION", HB_REC_MAXREGION_DEF);
    if (g_rec_window > HB_REC_WINDOW_MAX) g_rec_window = HB_REC_WINDOW_MAX;
    if (g_rec_window < 16) g_rec_window = 16;
    g_rec_window &= ~(uint64_t)7;
    /* Маска мест выхода. Умолчание — метить всё; значения 3/5/6 суть
     * отрицательные контроли, каждое названо в hb_record.h. Значение вне
     * 0..7 приравнивается к «всё», а не к «ничего»: прибор, молчащий из-за
     * опечатки в гейте, выглядел бы как отсутствие явления. */
    g_rec_site_mask = hb_rec_env_u64("MACRUNNER_HB_RECORD_EXIT_SITES",
                                     HB_REC_SITEBIT_ALL);
    if (g_rec_site_mask > HB_REC_SITEBIT_ALL) g_rec_site_mask = HB_REC_SITEBIT_ALL;
}

/* Разрешена ли пометка этого места. Одно место — один бит; OTHER и FAULT делят
 * бит, потому что оба ставятся ОДНОЙ пометкой у вызывающего и снимаются вместе. */
static int hb_rec_site_on(int site)
{
    switch (site) {
        case HB_REC_EXIT_NO_BLOCK: return (g_rec_site_mask & HB_REC_SITEBIT_NO_BLOCK) != 0;
        case HB_REC_EXIT_EXT_XFER: return (g_rec_site_mask & HB_REC_SITEBIT_EXT_XFER) != 0;
        default:                   return (g_rec_site_mask & HB_REC_SITEBIT_OTHER) != 0;
    }
}

/* ★ ЗАГОЛОВОК ОБНОВЛЯЕТСЯ ПО ХОДУ, А НЕ ТОЛЬКО В КОНЦЕ.
 *
 * Первая редакция писала числа заголовка только по достижении потолка событий —
 * и первый же смоук показал, чем это плохо: набор тестов кончился раньше потолка,
 * файл остался с `n_events=0` и выглядел пустым при 264 МБ выгруженной памяти.
 * Наши прогоны снимаются убийством ВСЕГДА, значит «итог только в конце» означает
 * «итога не будет». Цена периодического обновления — pwrite 256 байт раз в 4096
 * событий. */
static void hb_rec_flush_header(void)
{
    hb_record_header_t hdr;
    if (g_rec_fd < 0) return;

    memset(&hdr, 0, sizeof(hdr));
    {   /* Смещения проставлены в первый заход; здесь переписывается только хвост
         * чисел, поэтому они читаются из уже лежащего заголовка, а не гадаются. */
        hb_record_header_t old;
        if (pread(g_rec_fd, &old, sizeof(old), 0) == (ssize_t)sizeof(old)) hdr = old;
    }
    memcpy(hdr.magic, HB_RECORD_MAGIC, 8);
    hdr.version = HB_RECORD_VERSION;
    hdr.arch = 0;
    hdr.entry_pc = g_rec_entry_pc;
    hdr.n_regions = g_rec_regions;
    hdr.n_events = g_rec_events;
    hdr.events_off = g_rec_events_off;
    hdr.bytes_regions = g_rec_region_bytes;
    hdr.skipped_regions = g_rec_skipped_regions;
    hdr.skipped_bytes = g_rec_skipped_bytes;
    hdr.window_bytes = g_rec_window;
    hdr.page_bytes = HB_REC_PAGE;
    hdr.n_host_calls = g_rec_host_calls;
    hdr.n_host_writes = g_rec_host_writes;
    hdr.host_write_bytes = g_rec_host_write_bytes;
    hdr.state_size = (uint64_t)sizeof(hb_record_state_t);
    hdr.n_map_events = g_rec_map_events;
    if (pwrite(g_rec_fd, &hdr, sizeof(hdr), 0) != (ssize_t)sizeof(hdr))
        g_rec_write_errors++;
}

static void hb_rec_finish(void)
{
    if (g_rec_fd < 0) return;
    hb_rec_flush_header();
    fsync(g_rec_fd);
    close(g_rec_fd);
    g_rec_fd = -1;
    g_rec_on = 0;
    g_rec_done = 1;

    /* Маркер конца отрезка. Печатается ВСЕГДА и БЕЗУСЛОВНО: по нему прогон
     * снимается остановом по маркеру, и по нему же видно, что запись
     * состоялась, а не «прибор молчал». */
    fprintf(stderr,
            "macrunner-hb-record: gotovo sobytij=%llu vozvratov_hosta=%llu "
            "perevodov=%llu zapisej_hosta=%llu bajt_zapisej=%llu oblastej=%llu "
            "bajt_pamyati=%llu propuscheno_oblastej=%llu propuscheno_bajt=%llu "
            "okon=%llu oshibok_zapisi=%llu entry_pc=0x%llx "
            "maska_mest=%llu mesto0=%llu mesto1=%llu mesto2=%llu mesto3=%llu "
            "podavleno_mest=%llu vhodov_bez_vyhoda=%llu\n",
            (unsigned long long)g_rec_events, (unsigned long long)g_rec_host_calls,
            (unsigned long long)g_rec_lift_returns,
            (unsigned long long)g_rec_host_writes,
            (unsigned long long)g_rec_host_write_bytes,
            (unsigned long long)g_rec_regions,
            (unsigned long long)g_rec_region_bytes,
            (unsigned long long)g_rec_skipped_regions,
            (unsigned long long)g_rec_skipped_bytes,
            (unsigned long long)g_rec_windows_total,
            (unsigned long long)g_rec_write_errors,
            (unsigned long long)g_rec_entry_pc,
            (unsigned long long)g_rec_site_mask,
            (unsigned long long)g_rec_exit_sites[HB_REC_EXIT_NO_BLOCK],
            (unsigned long long)g_rec_exit_sites[HB_REC_EXIT_EXT_XFER],
            (unsigned long long)g_rec_exit_sites[HB_REC_EXIT_OTHER],
            (unsigned long long)g_rec_exit_sites[HB_REC_EXIT_FAULT],
            (unsigned long long)g_rec_site_suppressed,
            (unsigned long long)g_rec_no_exit);
    fflush(stderr);
}

/* Открытие файла и выгрузка образа памяти. Ровно один раз, на том выходе, где
 * взведён отрезок. */
static void hb_rec_begin(hb_context_t* ctx, uint64_t pc)
{
    char path[1024];
    hb_record_header_t hdr;
    hb_record_region_t* tbl = NULL;
    uint64_t n = 0;
    off_t tbl_pos, data_pos;

    snprintf(path, sizeof(path), "%s/zapis.bin", g_rec_dir);
    g_rec_fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (g_rec_fd < 0) {
        fprintf(stderr, "macrunner-hb-record: OTKAZ open %s errno=%d\n", path, errno);
        fflush(stderr);
        g_rec_done = 1;
        return;
    }

    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, HB_RECORD_MAGIC, 8);
    hdr.version = HB_RECORD_VERSION;
    if (hb_rec_write_all(g_rec_fd, &hdr, sizeof(hdr)) != 0) { g_rec_done = 1; return; }

    g_rec_entry_pc = pc;

    data_pos = lseek(g_rec_fd, 0, SEEK_CUR);
    hb_rec_dump_memory(&tbl, &n);
    g_rec_regions = n;
    tbl_pos = lseek(g_rec_fd, 0, SEEK_CUR);
    if (tbl && n) hb_rec_write_all(g_rec_fd, tbl, (size_t)n * sizeof(*tbl));
    free(tbl);
    g_rec_events_off = (uint64_t)lseek(g_rec_fd, 0, SEEK_CUR);

    hdr.regions_off = (uint64_t)tbl_pos;
    hdr.region_data_off = (uint64_t)data_pos;
    hdr.n_regions = n;
    hdr.events_off = g_rec_events_off;
    hdr.entry_pc = pc;
    hdr.page_bytes = HB_REC_PAGE;
    hdr.window_bytes = g_rec_window;
    hdr.state_size = (uint64_t)sizeof(hb_record_state_t);
    if (pwrite(g_rec_fd, &hdr, sizeof(hdr), 0) != (ssize_t)sizeof(hdr))
        g_rec_write_errors++;

    g_rec_on = 1;
    fprintf(stderr,
            "macrunner-hb-record: nachalo pc=0x%llx oblastej=%llu bajt=%llu "
            "propuscheno=%llu/%llu potolok_sobytij=%llu okno=%llu sostoyanie=%llu\n",
            (unsigned long long)pc, (unsigned long long)n,
            (unsigned long long)g_rec_region_bytes,
            (unsigned long long)g_rec_skipped_regions,
            (unsigned long long)g_rec_skipped_bytes,
            (unsigned long long)g_rec_max_events,
            (unsigned long long)g_rec_window,
            (unsigned long long)sizeof(hb_record_state_t));
    fflush(stderr);
    (void)ctx;
}

/* ────────────────────────── точки вызова ─────────────────────────────── */

static int hb_rec_mine(void)
{
    return g_rec_owner_set && pthread_equal(g_rec_owner, pthread_self()) != 0;
}

/* ВХОД записывается ВСЕГДА, а не только после выхода к хосту. Причина числом:
 * из мест выхода приборами покрыты два (`no_block`, `ext_xfer`), а `ret` — это
 * ещё 8,94 % диспетчеризаций (база §2.1), и он тоже возвращает управление в
 * цикл `macrunner_hb_run_x64`. Если писать только пары «выход-вход», ряд
 * событий разорвётся ровно на возвратах, и повтор не сможет сказать, дошёл он
 * до записанного места или проскочил его. Ряд входов непрерывен по построению:
 * через эту точку проходит КАЖДЫЙ заход в диспетчер. */
void hb_record_enter(hb_context_t* ctx, uint64_t pc)
{
    uint32_t wlen = 0, nwrites = 0;
    int host_return;

    if (!g_rec_armed) hb_rec_setup();
    if (!g_rec_dir || !*g_rec_dir || g_rec_done || !ctx) return;

    if (!g_rec_on) {
        /* Взведение: хозяином записи становится ПЕРВЫЙ поток, дошедший до
         * порога. Дальше прибор смотрит только на него. */
        if (g_rec_owner_set) return;
        if (g_rec_enters_seen++ < g_rec_skip_enters) return;
        g_rec_owner = pthread_self();
        g_rec_owner_set = 1;
        hb_rec_begin(ctx, pc);
        if (!g_rec_on) return;
        hb_rec_write_event(ctx, (uint16_t)HB_REC_ENTER, 0, pc, 1, NULL, 0, 0);
        g_rec_have_exit = 0;
        g_rec_exit_written = 0;
        g_rec_win_n = 0;
        return;
    }
    if (!hb_rec_mine()) return;

    /* ★ ПОВТОР-7: ВХОД, ПЕРЕД КОТОРЫМ ВЫХОДА В ЗАПИСИ НЕТ.
     * Считается ДО всякой обработки и БЕЗУСЛОВНО. Это единственное число,
     * которым видно, помечены места выхода или нет: 142 861 из 271 431 до
     * правки. Ноль здесь означает, что каждому заходу отвечает свой выход. */
    if (!g_rec_have_exit) g_rec_no_exit++;

    /* Вернулись на ДРУГОЙ адрес, чем ушли, — значит между выходом и входом
     * исполнялся хост. Вернулись на ТОТ ЖЕ — блок перевели, хост не звался.
     * Признак точный и не зависит ни от полосы адресов, ни от таблицы
     * переходников. */
    host_return = g_rec_have_exit && pc != g_rec_last_exit_pc;
    if (host_return) {
        if (g_rec_win_n) wlen = hb_rec_emit_writes(g_rec_wbuf, HB_REC_WBUF, &nwrites);
        g_rec_host_calls++;
    } else if (g_rec_have_exit) {
        g_rec_lift_returns++;
    }
    g_rec_win_n = 0;
    g_rec_have_exit = 0;
    g_rec_exit_written = 0;

    hb_rec_write_event(ctx, (uint16_t)HB_REC_ENTER, 0, pc,
                       g_rec_state_all || host_return, g_rec_wbuf, wlen, nwrites);

    if (g_rec_events >= g_rec_max_events) hb_rec_finish();
    else if ((g_rec_events & 0xFFull) == 0) hb_rec_flush_header();
}

/* Одно тело на все места выхода: событие, окна, признак пары. Раздельные тела
 * разъезжаются — именно так `hb_record_exit` и оказался единственным местом,
 * где снимаются окна, а три места выхода из пяти остались без них. */
static void hb_rec_note_exit(hb_context_t* ctx, uint64_t pc, int site)
{
    if (site < 0 || site > HB_REC_EXIT_FAULT) site = HB_REC_EXIT_OTHER;
    if (!hb_rec_site_on(site)) { g_rec_site_suppressed++; return; }

    hb_rec_write_event(ctx, (uint16_t)HB_REC_EXIT, (uint32_t)site, pc,
                       g_rec_state_all, NULL, 0, 0);
    g_rec_exit_sites[site]++;
    g_rec_last_exit_pc = pc;
    g_rec_have_exit = 1;
    g_rec_exit_written = 1;
    hb_rec_arm_windows(ctx);

    if (g_rec_events >= g_rec_max_events) hb_rec_finish();
    else if ((g_rec_events & 0xFFull) == 0) hb_rec_flush_header();
}

void hb_record_exit(hb_context_t* ctx, uint64_t pc, int site)
{
    if (!g_rec_on || g_rec_done || !ctx || !hb_rec_mine()) return;
    hb_rec_note_exit(ctx, pc, site);
}

/* ★★★★ ПОВТОР-7: ГОСТЬ ПЕРЕСТАЛ ИСПОЛНЯТЬСЯ — пометка у вызывающего.
 *
 * Молчит, если именованное место уже отчиталось за этот заход
 * (`g_rec_exit_written`): двойного события нет по построению.
 *
 * Замечание о ГРАНИЦЕ, которую легко потерять при переносе вызова: эта
 * пометка обязана стоять ДО первого хостового кода. Снятые здесь окна — это
 * «до»; если вызов уедет ниже по циклу, за место, где хост уже записал в
 * память гостя, окна снимутся ПОСЛЕ записи, сличение даст ноль изменений, и
 * прибор будет честно печатать «записей хоста нет» при том, что они были. */
void hb_record_left(hb_context_t* ctx, uint64_t pc, int faulted, int result)
{
    if (!g_rec_on || g_rec_done || !ctx || !hb_rec_mine()) return;
    if (g_rec_exit_written) return;
    hb_rec_note_exit(ctx, pc,
                     (faulted && result == HB_ERR_NOT_FOUND) ? HB_REC_EXIT_FAULT
                                                             : HB_REC_EXIT_OTHER);
}

int hb_record_active(void)
{
    return g_rec_on;
}

/* ★★★★ ИЗМЕНЕНИЕ КАРТЫ ПАМЯТИ ПО ХОДУ ОТРЕЗКА.
 *
 * Точек ТРИ, и они единственные: hb_memory_map, hb_memory_map_private,
 * hb_memory_unmap — через них движок и узнаёт о всякой области. Событие
 * пишется ПОСЛЕ того, как область заведена: если заведение не удалось, писать
 * нечего, а запись «завёл» при неудаче увела бы повтор на несуществующую
 * область и выглядела бы расхождением хода исполнения.
 *
 * Содержимое НЕ выгружается: свежевыделенная память Windows есть нули, а всё,
 * что в неё записал хост, приезжает окнами записи. Выгрузка стоила бы
 * гигабайтов на отрезок и меняла бы время измеряемого прогона. */
void hb_record_map(uint64_t base, uint64_t size, uint32_t perm, uint32_t vid)
{
    hb_record_maprec_t m;

    /* Только хозяин записи и только пока отрезок открыт. Чужой поток заводит
     * СВОИ области; подмешав их, повтор отобразил бы память, которой у него
     * в этом потоке нет, и расхождение выглядело бы как ход исполнения. */
    if (!g_rec_on || g_rec_done || !hb_rec_mine()) return;
    if (!base || !size) return;
    if (g_rec_in_map) return;
    g_rec_in_map = 1;

    m.base = base;
    m.size = size;
    m.perm = perm;
    m.vid = vid;
    hb_rec_write_event(NULL, (uint16_t)(vid == HB_REC_MAP_GONE ? HB_REC_UNMAP
                                                              : HB_REC_MAP),
                       vid, base, 0, (const uint8_t*)&m, (uint32_t)sizeof(m), 0);
    g_rec_map_events++;
    g_rec_in_map = 0;
}

void hb_record_totals(uint64_t* events, uint64_t* host_calls,
                      uint64_t* host_writes, uint64_t* bytes)
{
    if (events) *events = g_rec_events;
    if (host_calls) *host_calls = g_rec_host_calls;
    if (host_writes) *host_writes = g_rec_host_writes;
    if (bytes) *bytes = g_rec_host_write_bytes;
}
