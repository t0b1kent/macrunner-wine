#include "hb_env.h"
#include "hb_gates.h"
#include "hb_wow64cpu.h"
#include "hb_decoder.h"
#include "hb_flags.h"
#include "hb_lifter.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Регистрация кеша гейта в общем сбросе — см. hb_codegen.h. */


#define HB_WOW64CPU_DEFAULT_MAX_CODE_BYTES 4096u
#define HB_WOW64CPU_IR_CACHE_SIZE 8192u
#define HB_WOW64CPU_TEB32_PEB 0x30u
#define HB_WOW64CPU_PEB32_PROCESS_PARAMETERS 0x10u
#define HB_WOW64CPU_RTL_USER_PROCESS_PARAMETERS32_ENVIRONMENT 0x48u
#define HB_WOW64CPU_STATUS_VARIABLE_NOT_FOUND 0xc0000100u
#define HB_WOW64CPU_STATUS_BUFFER_TOO_SMALL 0xc0000023u

/* ДОРОЖКА, шаг 2, итерация 526 — ПРИБОР КЕША IR (счётчика не было ни одного).
 *
 * Меряет ровно то, чего шагу не хватало: среднюю длину пробирования И ЗАПОЛНЕНИЕ.
 * Второе важнее: put кладёт только в пустой слот и при полной таблице молча отказывает
 * (:58), а find тогда теряет условие обрыва и обходит все 8192 записи. Деградация не
 * плавная, поэтому средней длины мало — нужна доля занятых.
 *
 * Гейт MACRUNNER_HB_TRACE_IR_CACHE, умолчание ВЫКЛ. Печать периодическая И по atexit:
 * atexit не переживает снятия процесса сигналом (урок лейна ЕДИНИЦА, 24.08), а прогоны
 * здесь снимаются по времени. */
static int hb_ir_cache_stats_on(void) {
    const char* v = hb_gate( HB_GATE_HB_TRACE_IR_CACHE );
    int cached = (v && *v && *v != '0') ? 1 : 0;
    return cached;
}
static uint64_t g_irc_find, g_irc_probe, g_irc_hit, g_irc_miss;
/* итерация 540: пробы РАЗДЕЛЬНО по исходу. Смешение попаданий с промахами было
   главной оговоркой сверки с Кнутом — у успешного и неуспешного поиска разные формулы. */
static uint64_t g_irc_probe_hit, g_irc_probe_miss;
static uint64_t g_irc_put_ok, g_irc_put_full, g_irc_used;
static uint64_t g_irc_used_max, g_irc_resets;
/* Итерация 530 — РЕШАЮЩИЙ ЗАМЕР для рычага «чистить по диапазону».
 * На каждом уведомлении считаем, СКОЛЬКО записей кеша реально попало бы в [base,base+size)
 * против того, сколько выбрасывает полный сброс. Отношение и есть выигрыш рычага. */
static uint64_t g_irc_rng_calls, g_irc_rng_in, g_irc_rng_all, g_irc_rng_sz[6];
static uint64_t g_irc_purge_calls, g_irc_purge_dropped, g_irc_purge_rebuilt, g_irc_purge_fallback;
/* ДОРОЖКА, итерация 536 — ВЫТЕСНЕНИЕ ПО СОБСТВЕННОМУ УСЛОВИЮ.
 *
 * Замер 535: убрали чужие сбросы -> таблица дошла до 8192/8192, put перестал класть
 * (2 381 190 отказов), find потерял условие обрыва, 722 пробы на поиск вместо 1,70,
 * прогон 246 с вместо 71. Сбросы по уведомлениям РАБОТАЛИ КАК ВЫТЕСНЕНИЕ, и убирать их
 * можно только вместе с заменой.
 *
 * Простейшая замена, та же, что tb_flush у QEMU: заполнение выше порога -> очистить
 * таблицу целиком. Отличие от прежнего в том, что условие НАШЕ (заполнение), а не чужое
 * (уведомление о памяти), и срабатывает оно на порядки реже.
 *
 * Гейт MACRUNNER_HB_IR_CACHE_EVICT_PCT, умолчание 0 = ВЫКЛ. Значение — процент. */
static int hb_ir_cache_evict_pct(void) {
    const char* v = hb_gate( HB_GATE_HB_IR_CACHE_EVICT_PCT );
    int n = (v && *v) ? atoi(v) : 0;
    int cached = (n > 0 && n <= 100) ? n : 0;
    return cached;
}
static uint64_t g_irc_evictions;   /* итерация 532, объявлены ЗДЕСЬ: печать выше по файлу */

static void hb_ir_cache_report(void) {
    if (!g_irc_find) return;
    fprintf(stderr,
            "macrunner-hb-ir-cache: поисков=%llu проб=%llu на_поиск=%.2f попаданий=%llu (%.1f %%) "
            "занято=%llu из %u (%.1f %%) пик=%llu (%.1f %%) сбросов=%llu "
            "положено=%llu отказов_полна=%llu\n",
            (unsigned long long)g_irc_find, (unsigned long long)g_irc_probe,
            (double)g_irc_probe / (double)g_irc_find,
            (unsigned long long)g_irc_hit, 100.0 * (double)g_irc_hit / (double)g_irc_find,
            (unsigned long long)g_irc_used, (unsigned)HB_WOW64CPU_IR_CACHE_SIZE,
            100.0 * (double)g_irc_used / (double)HB_WOW64CPU_IR_CACHE_SIZE,
            (unsigned long long)g_irc_used_max,
            100.0 * (double)g_irc_used_max / (double)HB_WOW64CPU_IR_CACHE_SIZE,
            (unsigned long long)g_irc_resets,
            (unsigned long long)g_irc_put_ok, (unsigned long long)g_irc_put_full);
    if (g_irc_hit || g_irc_miss)
        fprintf(stderr,
                "macrunner-hb-ir-probes: попаданий=%llu проб_на_попадание=%.2f "
                "промахов=%llu проб_на_промах=%.2f\n",
                (unsigned long long)g_irc_hit,
                g_irc_hit ? (double)g_irc_probe_hit / (double)g_irc_hit : 0.0,
                (unsigned long long)g_irc_miss,
                g_irc_miss ? (double)g_irc_probe_miss / (double)g_irc_miss : 0.0);
    if (g_irc_rng_calls) {
        fprintf(stderr,
                "macrunner-hb-ir-range: уведомлений=%llu в_диапазоне=%llu всего_в_кеше=%llu (%.2f %%) "
                "размеры<4К=%llu <64К=%llu <1М=%llu <16М=%llu <256М=%llu больше=%llu\n",
                (unsigned long long)g_irc_rng_calls, (unsigned long long)g_irc_rng_in,
                (unsigned long long)g_irc_rng_all,
                g_irc_rng_all ? 100.0 * (double)g_irc_rng_in / (double)g_irc_rng_all : 0.0,
                (unsigned long long)g_irc_rng_sz[0], (unsigned long long)g_irc_rng_sz[1],
                (unsigned long long)g_irc_rng_sz[2], (unsigned long long)g_irc_rng_sz[3],
                (unsigned long long)g_irc_rng_sz[4], (unsigned long long)g_irc_rng_sz[5]);
    }
    if (g_irc_evictions)
        fprintf(stderr, "macrunner-hb-ir-evict: вытеснений=%llu порог=%d %%\n",
                (unsigned long long)g_irc_evictions, hb_ir_cache_evict_pct());
    if (g_irc_purge_calls) {
        fprintf(stderr,
                "macrunner-hb-ir-purge: вызовов=%llu выброшено=%llu пересборок=%llu запасной_путь=%llu\n",
                (unsigned long long)g_irc_purge_calls, (unsigned long long)g_irc_purge_dropped,
                (unsigned long long)g_irc_purge_rebuilt, (unsigned long long)g_irc_purge_fallback);
    }
    fflush(stderr);
}


typedef struct {
    uint32_t pc;
    hb_ir_func_t* func;
} hb_wow64_ir_cache_entry_t;

typedef struct {
    hb_wow64_ir_cache_entry_t entries[HB_WOW64CPU_IR_CACHE_SIZE];
    size_t used;   /* итерация 536: занятых слотов. calloc обнуляет, вести дёшево */
} hb_wow64_ir_cache_t;

static bool wow64_ir_ranges_intersect(uint64_t a_lo, size_t a_len, uint64_t b_lo, size_t b_len) {
    uint64_t a_hi = a_lo + (a_len ? (uint64_t)a_len : 1ull);
    uint64_t b_hi = b_lo + (b_len ? (uint64_t)b_len : 1ull);
    return a_lo < b_hi && b_lo < a_hi;
}

/* ★★★★★ 28.08.2026 — ОТЛОЖЕННОЕ ОСВОБОЖДЕНИЕ ФУНКЦИЙ IR (устранение use-after-free).
 *
 * Сброс кеша уничтожал функции ПРЯМО, и это ломало Diablo так:
 *   - поток команд wined3d берёт функцию через `wow64_ir_cache_find`, мьютекс отпускается,
 *     функция исполняется;
 *   - главный поток делает VirtualAlloc/Protect/Free -> `hb_wow64cpu_notify_memory_*` ->
 *     `wow64_process_ir_cache_reset` -> `hb_ir_func_destroy` для ВСЕХ записей, без мьютекса;
 *   - поток команд читает `func->cfg` из освобождённой памяти, видит 0, `hb_jit_runtime_run`
 *     отвечает HB_ERR_INVALID_ARG (hb_runtime.c:9624), xtajit переводит это в c000000d,
 *     обработчика нет — поток команд умирает, очередь встаёт, игра выходит без кадра.
 *
 * Замер называл виновника прямо: `кеш-отдал-без-cfg: pc=7799b5d0 func=0x723818000`, при том
 * что `hb_ir_func_create` создаёт cfg ВСЕГДА. Отсюда же и «след исчезает под трассой» —
 * трасса меняет тайминг, и гонка перестаёт случаться.
 *
 * Лечение: сброс больше НИЧЕГО не разрушает. Записи отвязываются под тем же мьютексом, а
 * сами функции переходят в отложенный список и живут до конца процесса. Это стоит памяти
 * (функции IR невелики, а сбросы редки — по одному на движение памяти гостя), но снимает
 * целый класс гонок: указатель, once выданный потоку, остаётся действительным всегда. */
typedef struct hb_ir_retired_s {
    struct hb_ir_retired_s* next;
    hb_ir_func_t* func;
} hb_ir_retired_t;

static hb_ir_retired_t* g_ir_retired;      /* под g_ir_cache_mutex */
static uint64_t g_ir_retired_n;

/* Вызывать ТОЛЬКО с захваченным g_ir_cache_mutex. */
static void wow64_ir_retire_locked(hb_ir_func_t* func) {
    hb_ir_retired_t* node;

    if (!func) return;
    node = (hb_ir_retired_t*)calloc(1, sizeof(*node));
    if (!node) return;   /* нет памяти на узел — просто теряем указатель, но НЕ освобождаем */
    node->func = func;
    node->next = g_ir_retired;
    g_ir_retired = node;
    g_ir_retired_n++;
}

/* MacRunner 2026-08-27, Diablo — КЕШ IR ОБЩИЙ ДЛЯ ПОТОКОВ, А ЗАЩИТЫ НЕ БЫЛО.
 *
 * Кеш живёт в `thread->process->ir_cache`, то есть один на процесс, и под Diablo с ним
 * работают минимум два потока (в журнале 0120 и 0124). Ни `find`, ни `put` не брали
 * никакой блокировки.
 *
 * Замер, который к этому привёл: на pc=0x77c78c00 ветка JIT вернула INVALID_ARG при
 *   func=0xb1f541ea0  cfg=0x0
 * — функция не NULL, а граф пуст. Свежая функция такой быть не может:
 * `hb_ir_func_create` либо создаёт cfg, либо возвращает NULL. Значит указатель вёл в
 * освобождённую память. Отпали замером: вытеснение кеша (гейт EVICT_PCT по умолчанию 0,
 * то есть выключено) и `transient_func` (объявлена ВНУТРИ цикла и сбрасывается каждую
 * итерацию). Осталась гонка на общем кеше.
 *
 * Один мьютекс на процесс: путь холодный (промах по кешу ведёт к подъёму IR, а он
 * несопоставимо дороже), поэтому цена блокировки здесь не видна. */
static pthread_mutex_t g_ir_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static size_t wow64_ir_cache_hash(uint32_t pc) {
    return (size_t)((pc >> 4) ^ (pc >> 17)) & (HB_WOW64CPU_IR_CACHE_SIZE - 1);
}

static hb_ir_func_t* wow64_ir_cache_find(hb_wow64_ir_cache_t* cache, uint32_t pc) {
    hb_ir_func_t* найдено = NULL;
    pthread_mutex_lock(&g_ir_cache_mutex);
    size_t idx, i;

    if (!cache) { pthread_mutex_unlock(&g_ir_cache_mutex); return NULL; }
    idx = wow64_ir_cache_hash(pc);
    if (hb_ir_cache_stats_on()) {
        static int armed;
        if (!armed) { armed = 1; atexit(hb_ir_cache_report); }
        g_irc_find++;
    }
    for (i = 0; i < HB_WOW64CPU_IR_CACHE_SIZE; i++) {
        hb_wow64_ir_cache_entry_t* entry = &cache->entries[(idx + i) & (HB_WOW64CPU_IR_CACHE_SIZE - 1)];
        if (hb_ir_cache_stats_on()) {
            g_irc_probe++;
            /* период 1 048 576 поисков: на Diablo это единицы печатей за прогон */
            if ((g_irc_find & 0xfffffu) == 0 && g_irc_probe) hb_ir_cache_report();
        }
        if (!entry->func) {
            if (hb_ir_cache_stats_on()) { g_irc_miss++; g_irc_probe_miss += (uint64_t)(i + 1); }
            pthread_mutex_unlock(&g_ir_cache_mutex);
        return NULL;
        }
        if (entry->pc == pc) {
            if (hb_ir_cache_stats_on()) { g_irc_hit++; g_irc_probe_hit += (uint64_t)(i + 1); }
            найдено = entry->func;
            pthread_mutex_unlock(&g_ir_cache_mutex);
            return найдено;
        }
    }
    /* таблица полна и ключа нет: обошли все слоты */
    if (hb_ir_cache_stats_on()) { g_irc_miss++; g_irc_probe_miss += (uint64_t)HB_WOW64CPU_IR_CACHE_SIZE; }
    pthread_mutex_unlock(&g_ir_cache_mutex);
    return NULL;
}

/* ★ 2026-09-03 (режим D Diablo, kan-25): снять записи кеша IR, чьи функции накрывают [lo, hi).
 * Функции НЕ разрушаются — уходят в список отставки (их может исполнять другой поток). Дыры в открытой
 * адресации допустимы: запись за дырой становится недостижимой = промах = свежий подъём. */
static unsigned wow64_ir_cache_drop_overlapping(hb_wow64_ir_cache_t* cache, uint64_t lo, uint64_t hi) {
    unsigned n = 0; size_t i;
    if (!cache) return 0;
    pthread_mutex_lock(&g_ir_cache_mutex);
    for (i = 0; i < HB_WOW64CPU_IR_CACHE_SIZE; i++) {
        hb_wow64_ir_cache_entry_t* e = &cache->entries[i];
        uint64_t a;
        if (!e->func) continue;
        a = e->func->guest_addr;
        if (wow64_ir_ranges_intersect(a, e->func->guest_len ? e->func->guest_len : 1, lo, hi - lo)) {
            wow64_ir_retire_locked(e->func);
            e->func = NULL; e->pc = 0;
            if (cache->used) cache->used--;
            n++;
        }
    }
    pthread_mutex_unlock(&g_ir_cache_mutex);
    return n;
}

static bool wow64_ir_cache_put(hb_wow64_ir_cache_t* cache, uint32_t pc, hb_ir_func_t* func) {
    pthread_mutex_lock(&g_ir_cache_mutex);
    size_t idx, i;
    int pct;

    if (!cache || !func) { pthread_mutex_unlock(&g_ir_cache_mutex); return false; }
    pct = hb_ir_cache_evict_pct();
    if (pct && cache->used * 100u >= (size_t)HB_WOW64CPU_IR_CACHE_SIZE * (size_t)pct) {
        for (i = 0; i < HB_WOW64CPU_IR_CACHE_SIZE; i++)
            if (cache->entries[i].func) {
                wow64_ir_retire_locked(cache->entries[i].func);   /* мьютекс уже наш */
                cache->entries[i].func = NULL;
                cache->entries[i].pc = 0;
            }
        cache->used = 0;
        g_irc_evictions++;
        if (hb_ir_cache_stats_on()) g_irc_used = 0;
    }
    idx = wow64_ir_cache_hash(pc);
    for (i = 0; i < HB_WOW64CPU_IR_CACHE_SIZE; i++) {
        hb_wow64_ir_cache_entry_t* entry = &cache->entries[(idx + i) & (HB_WOW64CPU_IR_CACHE_SIZE - 1)];
        if (!entry->func) {
            entry->pc = pc;
            entry->func = func;
            cache->used++;
            if (hb_ir_cache_stats_on()) {
                g_irc_put_ok++; g_irc_used++;
                if (g_irc_used > g_irc_used_max) g_irc_used_max = g_irc_used;
            }
            pthread_mutex_unlock(&g_ir_cache_mutex);
            return true;
        }
        if (entry->pc == pc) {
            /* ★★★★★ 28.08.2026 — МЬЮТЕКС НЕ ОТПУСКАЛСЯ НА ЭТОЙ ВЕТВИ.
             *
             * Все прочие выходы из `wow64_ir_cache_put` делают unlock, эта возвращала true
             * прямо из-под захваченного `g_ir_cache_mutex`. Ветвь берётся, когда два потока
             * подняли ОДИН И ТОТ ЖЕ pc: у Diablo это главный поток и поток команд wined3d,
             * которые оба исполняют гостевой код. После первого такого совпадения мьютекс
             * остаётся захваченным навсегда, и любое следующее обращение к кешу IR — из
             * ЛЮБОГО потока — встаёт на нём.
             *
             * Ровно этим объясняется и то, что след «исчезает под трассой»: трасса меняет
             * тайминг, и совпадение pc в двух потоках перестаёт случаться.
             *
             * Функция вызывающего в кеш не легла (там уже чужая под тем же ключом), поэтому
             * честный ответ — false: пусть вызывающий пометит её временной и уничтожит сам.
             * Прежнее `true` заставляло его считать функцию переданной кешу, и она утекала. */
            pthread_mutex_unlock(&g_ir_cache_mutex);
            return false;
        }
    }
    if (hb_ir_cache_stats_on()) g_irc_put_full++;
    pthread_mutex_unlock(&g_ir_cache_mutex);
    return false;
}

static void wow64_ir_cache_destroy(hb_wow64_ir_cache_t* cache) {
    size_t i;

    if (!cache) return;
    /* ★ Функции НЕ разрушаем: их может исполнять другой поток (разбор у hb_ir_retired_t).
     * Отвязываем под общим мьютексом и складываем в отложенный список. */
    pthread_mutex_lock(&g_ir_cache_mutex);
    for (i = 0; i < HB_WOW64CPU_IR_CACHE_SIZE; i++) {
        if (cache->entries[i].func) wow64_ir_retire_locked(cache->entries[i].func);
        cache->entries[i].func = NULL;
        cache->entries[i].pc = 0;
    }
    cache->used = 0;
    pthread_mutex_unlock(&g_ir_cache_mutex);
    free(cache);
}

/* Считает, что выбросила бы чистка по диапазону, и что выбрасывает полный сброс. */
static void wow64_ir_cache_note_range(hb_wow64_process_t* process, uint32_t base, size_t size) {
    const hb_wow64_ir_cache_t* c;
    size_t i;
    uint64_t lo, hi;
    if (!hb_ir_cache_stats_on() || !process || !process->ir_cache) return;
    c = (const hb_wow64_ir_cache_t*)process->ir_cache;
    lo = (uint64_t)base; hi = lo + (uint64_t)size;
    g_irc_rng_calls++;
    g_irc_rng_sz[size < 4096 ? 0 : size < 65536 ? 1 : size < 1048576 ? 2 :
                 size < 16777216 ? 3 : size < 268435456 ? 4 : 5]++;
    for (i = 0; i < HB_WOW64CPU_IR_CACHE_SIZE; i++) {
        if (!c->entries[i].func) continue;
        g_irc_rng_all++;
        if ((uint64_t)c->entries[i].pc >= lo && (uint64_t)c->entries[i].pc < hi) g_irc_rng_in++;
    }
}

/* ДОРОЖКА, шаг 2, итерация 532 — ЧИСТКА ПО ДИАПАЗОНУ вместо полного сброса.
 *
 * Основание замером (итерация 530, прогон dor-rng): на 1039 уведомлениях в диапазон
 * [base,base+size) попало 0 записей из 373 206, а полный сброс выбрасывал всё и заставлял
 * поднимать каждый блок 52 раза вместо одного.
 *
 * ★ ТОНКОСТЬ, из-за которой наивное удаление НЕВЕРНО. Таблица — открытая адресация с
 * линейным пробированием, а поиск обрывается на ПЕРВОМ пустом слоте (:39). Освободить
 * слот в середине цепочки значит сделать всё, что за ним, недостижимым. Поэтому после
 * удаления таблица ПЕРЕСОБИРАЕТСЯ: живые записи переносятся во временный массив и
 * вставляются заново. Если удалять нечего — не трогаем ничего, цепочки целы.
 *
 * Гейт MACRUNNER_HB_IR_CACHE_RANGE_PURGE, умолчание ВЫКЛ. При отказе выделения памяти —
 * запасной путь: прежний полный сброс, то есть поведение не хуже нынешнего. */
static int hb_ir_cache_range_purge_on(void) {
    const char* v = hb_gate( HB_GATE_HB_IR_CACHE_RANGE_PURGE );
    int cached = (v && *v && *v != '0') ? 1 : 0;
    return cached;
}

/* Возвращает 1, если диапазон обработан (сброс не нужен), 0 — если надо сбрасывать как раньше. */
static int wow64_ir_cache_purge_range(hb_wow64_process_t* process, uint32_t base, size_t size) {
    hb_wow64_ir_cache_t* c;
    hb_wow64_ir_cache_entry_t* tmp;
    size_t i, live = 0, dropped = 0;
    uint64_t lo;

    if (!hb_ir_cache_range_purge_on()) return 0;
    if (!process || !process->ir_cache) return 1;   /* кеша нет — сбрасывать нечего */
    c = (hb_wow64_ir_cache_t*)process->ir_cache;
    lo = (uint64_t)base;
    g_irc_purge_calls++;

    pthread_mutex_lock(&g_ir_cache_mutex);
    for (i = 0; i < HB_WOW64CPU_IR_CACHE_SIZE; i++) {
        if (!c->entries[i].func) continue;
        if (!wow64_ir_ranges_intersect((uint64_t)c->entries[i].pc, c->entries[i].func->guest_len,
                                      lo, size)) {
            continue;
        }
        wow64_ir_retire_locked(c->entries[i].func);   /* не разрушаем: см. hb_ir_retired_t */
        c->entries[i].func = NULL;
        c->entries[i].pc = 0;
        dropped++;
    }
    pthread_mutex_unlock(&g_ir_cache_mutex);
    if (!dropped) return 1;                          /* ничего не задето — цепочки целы */
    g_irc_purge_dropped += dropped;

    tmp = (hb_wow64_ir_cache_entry_t*)calloc(HB_WOW64CPU_IR_CACHE_SIZE, sizeof(*tmp));
    if (!tmp) { g_irc_purge_fallback++; return 0; }  /* запасной путь: полный сброс */
    for (i = 0; i < HB_WOW64CPU_IR_CACHE_SIZE; i++)
        if (c->entries[i].func) tmp[live++] = c->entries[i];
    memset(c->entries, 0, sizeof(c->entries));
    for (i = 0; i < live; i++) {
        size_t idx = wow64_ir_cache_hash(tmp[i].pc), k;
        for (k = 0; k < HB_WOW64CPU_IR_CACHE_SIZE; k++) {
            hb_wow64_ir_cache_entry_t* e =
                &c->entries[(idx + k) & (HB_WOW64CPU_IR_CACHE_SIZE - 1)];
            if (!e->func) { *e = tmp[i]; break; }
        }
    }
    free(tmp);
    g_irc_purge_rebuilt++;
    if (hb_ir_cache_stats_on()) g_irc_used = (g_irc_used > dropped) ? g_irc_used - dropped : 0;
    return 1;
}

static void wow64_process_ir_cache_reset(hb_wow64_process_t* process) {
    if (!process || !process->ir_cache) return;
    /* Итерация 528: без этого «занято» становилось счётчиком put и давало 3038 % —
     * ровно та ошибка, что была записана оговоркой при заведении прибора. */
    if (hb_ir_cache_stats_on()) { g_irc_used = 0; g_irc_resets++; }
    wow64_ir_cache_destroy((hb_wow64_ir_cache_t*)process->ir_cache);
    process->ir_cache = NULL;
}

static bool func_ends_in_control_transfer(const hb_ir_func_t* func) {
    if (!func || !func->cfg || !func->cfg->entry) return false;
    hb_ir_block_t* block = func->cfg->entry;
    if (!block->instr_count) return false;

    switch (block->instrs[block->instr_count - 1].op) {
        case HB_IR_CALL:
        case HB_IR_RET:
        case HB_IR_JMP:
        case HB_IR_Jcc:
            return true;
        default:
            return false;
    }
}

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ГЕЙТЫ ТРАСС КЕШИРУЮТСЯ.
 * Профиль загрузки Diablo (sample, раздел «Sort by top of stack»): __findenv_locked —
 * 2505 отсчётов, 8.7% СОБСТВЕННОГО времени, третья строка после ожидания сообщений и
 * простоя. Вызывающие названы деревом: hb_wow64cpu_simulate (+612, +632, +1016) и
 * hb_jit_helper_write_u32_tso (+108). То есть getenv дёргался на КАЖДЫЙ вызов симуляции
 * и на КАЖДУЮ 32-битную запись, а он берёт блокировку внутри libc.
 * Переменные окружения за прогон не меняются, поэтому кеш поведение сохраняет. */
static bool trace_wow64_pc_enabled(uint32_t pc) {
    static const char* spec; static int spec_done;
    static const char* all_sim; static int all_sim_done;
    char* end = NULL;
    unsigned long start, stop;

    if (!spec_done) { spec = hb_gate( HB_GATE_HB_TRACE_PC ); spec_done = 1; }
    if (!all_sim_done) { all_sim = hb_gate( HB_GATE_XTAJIT_TRACE_ALL_SIMULATE ); all_sim_done = 1; }

    if (all_sim && pc == 0x7bde072c)
        return true;

    if (!spec || !*spec) return false;
    start = strtoul(spec, &end, 0);
    if (end == spec) return false;
    if (*end == '-' || *end == ':') {
        stop = strtoul(end + 1, NULL, 0);
        return pc >= (uint32_t)start && pc <= (uint32_t)stop;
    }
    return pc == (uint32_t)start;
}

static void trace_wow64_bytes(uint32_t pc, const uint8_t* code, size_t len) {
    size_t n = len < 32 ? len : 32;

    fprintf(stderr, "macrunner-hb-wow64-sim: phase=decode pc=%08x len=%zu bytes=", pc, len);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", code[i]);
    if (len > n) fprintf(stderr, "...");
    fputc('\n', stderr);
}

static bool trace_wcslen_pattern_enabled(uint32_t pc) {
    static const char* spec; static int spec_done;   /* см. заметку выше про кеш гейтов */
    char* end = NULL;

    if (!spec_done) { spec = hb_gate( HB_GATE_HB_TRACE_WCSLEN_PATTERN ); spec_done = 1; }
    unsigned long value;

    if (!spec || !*spec) return false;
    value = strtoul(spec, &end, 0);
    if (end == spec) return false;
    return pc == (uint32_t)value;
}

static void trace_wcslen_pattern(uint32_t pc, const uint8_t* code, size_t len, bool cached, bool matched) {
    static unsigned int count;
    size_t n;

    if (++count > 16) return;
    fprintf(stderr,
            "macrunner-hb-wow64-wcslen-pattern: pc=%08x cached=%u matched=%u len=%zu bytes=",
            pc, cached ? 1u : 0u, matched ? 1u : 0u, len);
    n = len < 48 ? len : 48;
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", code ? code[i] : 0);
    if (len > n) fprintf(stderr, "...");
    fputc('\n', stderr);
}

static bool is_wow64_bop_opcode(const uint8_t* code, size_t len) {
    return len >= 2 && code[0] == 0x0f && (code[1] == 0xff || code[1] == 0xfe);
}

static bool is_wine_x86_wcslen_pattern(const uint8_t* code, size_t len) {
    static const uint8_t prologue[] = {
        0x55,                               /* push ebp */
        0x89, 0xe5,                         /* mov ebp, esp */
        0xb8, 0xfe, 0xff, 0xff, 0xff,       /* mov eax, -2 */
        0x8b, 0x4d, 0x08                    /* mov ecx, [ebp+8] */
    };
    static const uint8_t loop[] = {
        0x66, 0x83, 0x7c, 0x01, 0x02, 0x00, /* cmp word [ecx+eax+2], 0 */
        0x8d, 0x40, 0x02,                   /* lea eax, [eax+2] */
        0x75, 0xf5,                         /* jne loop */
        0xd1, 0xf8,                         /* sar eax, 1 */
        0x5d,                               /* pop ebp */
        0xc3                                /* ret */
    };
    size_t pos = 0;

    if (len >= 2 && code[0] == 0x66 && code[1] == 0x90) pos = 2; /* xchg ax, ax */
    else if (len >= 2 && code[0] == 0x8b && code[1] == 0xff) pos = 2; /* mov edi, edi */

    if (len < pos + sizeof(prologue) + sizeof(loop)) return false;
    if (memcmp(code + pos, prologue, sizeof(prologue)) != 0) return false;
    pos += sizeof(prologue);

    while (pos < len) {
        if (len - pos >= sizeof(loop) && memcmp(code + pos, loop, sizeof(loop)) == 0)
            return true;

        if (code[pos] == 0x90) {
            pos++;
            continue;
        }
        if (len - pos >= 3 && code[pos] == 0x0f && code[pos + 1] == 0x1f) {
            pos += 3;
            continue;
        }
        if (len - pos >= 7 && code[pos] == 0x66 && code[pos + 1] == 0x66 &&
            code[pos + 2] == 0x66 && code[pos + 3] == 0x66 && code[pos + 4] == 0x66) {
            pos += 7;
            continue;
        }
        return false;
    }
    return false;
}

static bool is_wine_x86_rtl_query_env_pattern(const uint8_t* code, size_t len) {
    static const uint8_t prefix[] = {
        0x55,             /* push ebp */
        0x89, 0xe5,       /* mov ebp, esp */
        0x53,             /* push ebx */
        0x57,             /* push edi */
        0x56              /* push esi */
    };
    static const uint8_t loads[] = {
        0x8b, 0x5d, 0x10, /* mov ebx, [ebp+0x10] */
        0x8b, 0x75, 0x0c, /* mov esi, [ebp+0x0c] */
        0x8b, 0x7d, 0x08  /* mov edi, [ebp+0x08] */
    };
    size_t pos = 0;

    if (len >= 2 && code[0] == 0x66 && code[1] == 0x90) pos = 2;
    else if (len >= 2 && code[0] == 0x8b && code[1] == 0xff) pos = 2;

    if (len < pos + sizeof(prefix) + 1 + sizeof(loads)) return false;
    if (memcmp(code + pos, prefix, sizeof(prefix)) != 0) return false;
    pos += sizeof(prefix);
    if (len - pos >= 3 && code[pos] == 0x83 && code[pos + 1] == 0xec && code[pos + 2] == 0x10)
        pos += 3;
    else if (code[pos] == 0x50)
        pos += 1;
    else
        return false;
    return len >= pos + sizeof(loads) && memcmp(code + pos, loads, sizeof(loads)) == 0;
}

static bool is_wine_x86_strcmp_pattern(const uint8_t* code, size_t len) {
    static const uint8_t prologue[] = {
        0x55,             /* push ebp */
        0x89, 0xe5,       /* mov ebp, esp */
        0x8b, 0x45, 0x0c, /* mov eax, [ebp+0x0c] */
        0x8b, 0x55, 0x08, /* mov edx, [ebp+0x08] */
        0x0f, 0xb6, 0x0a  /* movzx ecx, byte [edx] */
    };
    size_t pos = 0;

    if (len >= 2 && code[0] == 0x66 && code[1] == 0x90) pos = 2;
    else if (len >= 2 && code[0] == 0x8b && code[1] == 0xff) pos = 2;

    return len >= pos + sizeof(prologue) && memcmp(code + pos, prologue, sizeof(prologue)) == 0;
}

static bool try_run_wine_x86_strcmp(hb_context_t* ctx, const uint8_t* code,
                                    size_t len, hb_exec_result_t* out) {
    uint32_t esp, ret_addr, lhs, rhs;
    int32_t result = 0;
    hb_memory_t* mem;

    if (!ctx || !ctx->memory || !out || !is_wine_x86_strcmp_pattern(code, len))
        return false;

    memset(out, 0, sizeof(*out));
    mem = ctx->memory;
    esp = ctx->regs.x86.esp;
    if (hb_memory_read_u32(mem, esp, &ret_addr) != HB_OK ||
        hb_memory_read_u32(mem, esp + 4u, &lhs) != HB_OK ||
        hb_memory_read_u32(mem, esp + 8u, &rhs) != HB_OK) {
        return false;
    }

    /* ★★★ MacRunner 2026-08-23, КООРДИНАТОР — ЧИТАТЬ КУСКАМИ, А НЕ ПО БАЙТУ.
     *
     * Прежний цикл звал `hb_memory_read_u8` ДВАЖДЫ на каждый сравниваемый байт. Каждый такой
     * вызов — полный проход программной MMU: нормализация адреса, просмотр горячего кеша,
     * хозяйский указатель, три проверки гейтов, установка обработчиков сигналов, `sigsetjmp`,
     * `memcpy` одного байта, снятие ловушки. Одиннадцать шагов, восемь из них вызовы наружу.
     *
     * Профиль честной нагрузки (strcmp по 60 байт, 23.08): 86 % рабочего потока — этот путь.
     * `hb_memory_read_u8` стоит родителем у 6627 отсчётов из 7800 в `hb_memory_read_inner`.
     * На шестьдесят байт приходится СТО ДВАДЦАТЬ полных проходов.
     *
     * Лечение: брать кусок и сравнивать его в памяти хозяина. Проход MMU остаётся, но один
     * на кусок, а не на байт. Безопасность не трогаем: `hb_memory_read` делает те же проверки
     * и то же ограждение, просто один раз на 64 байта.
     *
     * Кусок уменьшается вдвое, пока не прочитается: у края области, у неотображённой
     * страницы и на коротких строках длинное чтение не пройдёт, и это НОРМА, а не отказ.
     * Дойдя до одного байта, работаем как прежде — тогда отказ настоящий.
     *
     * Гейт MACRUNNER_HB_STRCMP_CHUNK СНЯТ 02.09.2026: правка безусловна,
     * выключенная ветка возвращала известный дефект (scripts/гейты.py). */
    uint8_t bufa[64], bufb[64];
    bool done = false;
    while (!done) {
        size_t n = sizeof(bufa);
        while (n > 1 &&
               (hb_memory_read(mem, lhs, bufa, n) != HB_OK ||
                hb_memory_read(mem, rhs, bufb, n) != HB_OK))
            n >>= 1;
        if (n <= 1) {
            uint8_t a = 0, b = 0;
            if (hb_memory_read_u8(mem, lhs, &a) != HB_OK ||
                hb_memory_read_u8(mem, rhs, &b) != HB_OK)
                return false;
            if (a != b) { result = a > b ? 1 : -1; break; }
            if (!a) break;
            lhs++; rhs++;
            continue;
        }
        for (size_t i = 0; i < n; i++) {
            uint8_t a = bufa[i], b = bufb[i];
            if (a != b) { result = a > b ? 1 : -1; done = true; break; }
            if (!a) { done = true; break; }
        }
        if (!done) { lhs += (uint32_t)n; rhs += (uint32_t)n; }
    }
    for (;;) {
        uint8_t a = 0, b = 0;

        if (hb_memory_read_u8(mem, lhs, &a) != HB_OK ||
            hb_memory_read_u8(mem, rhs, &b) != HB_OK) {
            return false;
        }
        if (a != b) {
            result = a > b ? 1 : -1;
            break;
        }
        if (!a) break;
        lhs++;
        rhs++;
    }

    ctx->regs.x86.eax = (uint32_t)result;
    ctx->regs.x86.esp = esp + 4u;
    ctx->pc = ret_addr;
    ctx->regs.x86.eip = ret_addr;
    out->result = HB_OK;
    out->steps_executed = 16;
    out->blocks_executed = 1;
    return true;
}

static uint16_t wow64_fold_wchar(uint16_t ch) {
    if (ch >= 'a' && ch <= 'z') return (uint16_t)(ch - ('a' - 'A'));
    return ch;
}


/* MacRunner 2026-08-23, КООРДИНАТОР — ТА ЖЕ ПОРОДА, ЧТО У strcmp.
 *
 * Посимвольный цикл: `hb_memory_read_u16` на КАЖДЫЙ знак, а каждый такой вызов — полный
 * проход программной MMU (одиннадцать шагов, восемь вызовов наружу, `sigsetjmp` и
 * `memcpy` двух байт). Лечение то же — читать кусками.
 *
 * ★ ЧЕСТНАЯ ОГОВОРКА: на нашей нынешней мишени это НЕ ИЗМЕРИМО. В профиле честной
 * нагрузки у `wow64_guest_wcslen` и `hb_memory_read_u16` РОВНО НОЛЬ отсчётов — они
 * работают при запуске, а не в цикле. Правка сделана как однородная с `strcmp`
 * (коммит 2905949d, там 3,68 раза), а не как замеренный выигрыш. Числа за ней нет,
 * и я его не приписываю. Мишень, где широкие строки горячие, — Unity и HK.
 *
 * Гейт MACRUNNER_HB_STRCMP_CHUNK СНЯТ 02.09.2026: правка безусловна,
 * выключенная ветка возвращала известный дефект (scripts/гейты.py). */
static bool wow64_guest_wcslen(hb_memory_t* mem, uint32_t ptr, uint32_t* out_chars) {
    uint32_t chars = 0;

    if (!mem || !out_chars) return false;
    uint16_t buf[64];
    while (chars < 0x100000u) {
        size_t n = sizeof(buf) / sizeof(buf[0]);
        while (n > 1 && hb_memory_read(mem, ptr + chars * 2u, buf, n * 2u) != HB_OK)
            n >>= 1;
        if (n <= 1) {
            uint16_t ch = 0;
            if (hb_memory_read_u16(mem, ptr + chars * 2u, &ch) != HB_OK) return false;
            if (!ch) { *out_chars = chars; return true; }
            chars++;
            continue;
        }
        for (size_t i = 0; i < n; i++) {
            if (!buf[i]) { *out_chars = chars + (uint32_t)i; return true; }
        }
        chars += (uint32_t)n;
    }
    return false;
    for (;;) {
        uint16_t ch = 0;
        if (chars >= 0x100000u) return false;
        if (hb_memory_read_u16(mem, ptr + chars * 2u, &ch) != HB_OK) return false;
        if (!ch) {
            *out_chars = chars;
            return true;
        }
        chars++;
    }
}

static bool wow64_find_env_value(hb_memory_t* mem, uint32_t env, uint32_t name,
                                 uint32_t name_chars, uint32_t* value,
                                 uint32_t* value_chars) {
    uint32_t var = env;

    if (!mem || !env || !name || !name_chars || !value || !value_chars) return false;

    for (;;) {
        uint32_t len = 0;
        uint32_t first_eq = UINT32_MAX;
        bool same = true;

        if (!wow64_guest_wcslen(mem, var, &len)) return false;
        if (!len) return false;

        for (uint32_t i = 1; i < len; i++) {
            uint16_t ch = 0;
            if (hb_memory_read_u16(mem, var + i * 2u, &ch) != HB_OK) return false;
            if (ch == '=') {
                first_eq = i;
                break;
            }
        }
        if (len > name_chars && first_eq == name_chars) {
            for (uint32_t i = 0; i < name_chars; i++) {
                uint16_t lhs = 0, rhs = 0;
                if (hb_memory_read_u16(mem, var + i * 2u, &lhs) != HB_OK ||
                    hb_memory_read_u16(mem, name + i * 2u, &rhs) != HB_OK) {
                    return false;
                }
                if (wow64_fold_wchar(lhs) != wow64_fold_wchar(rhs)) {
                    same = false;
                    break;
                }
            }
            if (same) {
                *value = var + (name_chars + 1u) * 2u;
                return wow64_guest_wcslen(mem, *value, value_chars);
            }
        }
        var += (len + 1u) * 2u;
    }
}

static bool wow64_copy_guest_wstr(hb_memory_t* mem, uint32_t dst, uint32_t src, uint32_t bytes) {
    for (uint32_t i = 0; i < bytes; i++) {
        uint8_t byte = 0;
        if (hb_memory_read_u8(mem, src + i, &byte) != HB_OK ||
            hb_memory_write_u8(mem, dst + i, byte) != HB_OK) {
            return false;
        }
    }
    return true;
}

static bool try_run_wine_x86_rtl_query_env(hb_context_t* ctx, const uint8_t* code,
                                           size_t len, hb_exec_result_t* out) {
    uint32_t esp, ret_addr, env, name, value;
    uint16_t name_len = 0, value_max = 0;
    uint32_t name_buf = 0, value_buf = 0, name_chars, found_value = 0, found_chars = 0;
    uint32_t status = HB_WOW64CPU_STATUS_VARIABLE_NOT_FOUND;
    hb_memory_t* mem;

    if (!ctx || !ctx->memory || !out || !is_wine_x86_rtl_query_env_pattern(code, len))
        return false;

    memset(out, 0, sizeof(*out));
    mem = ctx->memory;
    esp = ctx->regs.x86.esp;
    if (hb_memory_read_u32(mem, esp, &ret_addr) != HB_OK ||
        hb_memory_read_u32(mem, esp + 4u, &env) != HB_OK ||
        hb_memory_read_u32(mem, esp + 8u, &name) != HB_OK ||
        hb_memory_read_u32(mem, esp + 12u, &value) != HB_OK ||
        hb_memory_read_u16(mem, name, &name_len) != HB_OK ||
        hb_memory_read_u32(mem, name + 4u, &name_buf) != HB_OK ||
        hb_memory_write_u16(mem, value, 0) != HB_OK) {
        return false;
    }

    name_chars = (uint32_t)name_len / 2u;
    if (name_chars) {
        if (!env) {
            uint32_t peb = 0, params = 0;
            if (hb_memory_read_u32(mem, (uint32_t)ctx->fs_base + HB_WOW64CPU_TEB32_PEB, &peb) != HB_OK ||
                hb_memory_read_u32(mem, peb + HB_WOW64CPU_PEB32_PROCESS_PARAMETERS, &params) != HB_OK ||
                hb_memory_read_u32(mem, params + HB_WOW64CPU_RTL_USER_PROCESS_PARAMETERS32_ENVIRONMENT, &env) != HB_OK) {
                return false;
            }
        }
        if (wow64_find_env_value(mem, env, name_buf, name_chars, &found_value, &found_chars)) {
            uint32_t value_len = found_chars * 2u;

            if (hb_memory_read_u16(mem, value + 2u, &value_max) != HB_OK ||
                hb_memory_read_u32(mem, value + 4u, &value_buf) != HB_OK ||
                hb_memory_write_u16(mem, value, (uint16_t)value_len) != HB_OK) {
                return false;
            }
            if (value_len <= value_max) {
                uint32_t copy_bytes = value_len + 2u;
                if (copy_bytes > value_max) copy_bytes = value_max;
                if (copy_bytes && !wow64_copy_guest_wstr(mem, value_buf, found_value, copy_bytes))
                    return false;
                status = 0;
            } else {
                status = HB_WOW64CPU_STATUS_BUFFER_TOO_SMALL;
            }
        }
    }

    ctx->regs.x86.eax = status;
    ctx->regs.x86.esp = esp + 16u;
    ctx->pc = ret_addr;
    ctx->regs.x86.eip = ret_addr;
    out->result = HB_OK;
    out->steps_executed = 32;
    out->blocks_executed = 1;
    return true;
}

static bool try_run_wine_x86_wcslen(hb_context_t* ctx, const uint8_t* code,
                                    size_t len, hb_exec_result_t* out) {
    uint32_t esp, ret_addr, str_addr, byte_len;
    uint32_t chars = 0;
    hb_result_t r;

    if (!ctx || !ctx->memory || !out || !is_wine_x86_wcslen_pattern(code, len))
        return false;

    memset(out, 0, sizeof(*out));
    esp = ctx->regs.x86.esp;
    r = hb_memory_read_u32(ctx->memory, esp, &ret_addr);
    if (r == HB_OK) r = hb_memory_read_u32(ctx->memory, esp + 4u, &str_addr);
    if (r != HB_OK) {
        ctx->last_result = r;
        out->result = r;
        out->faulted = true;
        out->fault_reason = "wcslen intrinsic stack read fault";
        return true;
    }

    for (;;) {
        uint16_t ch = 0;
        uint32_t addr = str_addr + chars * 2u;

        r = hb_memory_read_u16(ctx->memory, addr, &ch);
        if (r != HB_OK) {
            ctx->last_result = r;
            out->result = r;
            out->faulted = true;
            out->fault_reason = "wcslen intrinsic string read fault";
            return true;
        }
        if (!ch) break;
        chars++;
    }

    byte_len = chars * 2u;
    ctx->regs.x86.eax = chars;
    ctx->regs.x86.ecx = str_addr;
    ctx->regs.x86.esp = esp + 4u;
    ctx->pc = ret_addr;
    ctx->regs.x86.eip = ret_addr;
    hb_lazy_flags_note(ctx, HB_LAZY_FLAGS_SAR, HB_SIZE_32, byte_len, 1, chars, 1);

    out->result = HB_OK;
    out->steps_executed = 8;
    out->blocks_executed = 1;
    return true;
}

/* ★ 03.09.2026 — предел разбирался ЗАНОВО на каждый вызов: hb_env линейно перебирает
 * окружение, плюс strtoull. Это путь i386. Разбираем один раз; значение гейта не
 * меняется в течение процесса, а сброс кешей движка сюда не относится. */
/* Числовая настройка: значение берём из таблицы, разбираем только когда
 * оно ИЗМЕНИЛОСЬ. Признак изменения — сам указатель из таблицы.
 *
 * ПОЧЕМУ НЕ ОДНОРАЗОВЫЙ РАЗБОР. Ровно он тут и стоял, и приёмка на нём
 * повисла НАСМЕРТЬ: test_wow64cpu_simulate_honors_env_block_limit пишет
 * бесконечный `jmp` и надеется, что предел его оборвёт. Первый вызов
 * случался раньше теста, запоминал «предела нет», и после set_env_var
 * функция уже не смотрела на окружение — цикл становился вечным.
 * Отказ выглядел как зависший движок, а не как испорченный кеш.
 *
 * ПОЧЕМУ НЕ РЕГИСТРАЦИЯ В ОБЩЕМ СПИСКЕ. Это то самое обслуживание,
 * ради снятия которого заводилась таблица. Сверка с указателем даёт
 * то же самое даром: после hb_env_refresh запись таблицы указывает на
 * другую строку environ (или на NULL), сравнение это видит само.
 * Совпал указатель — значение то же, разбирать нечего. */
static uint64_t wow64_simulate_block_limit(void) {
    static const char* mr_razobrano;   /* какой указатель уже разобран */
    static uint64_t mr_limit;
    const char* value = hb_gate( HB_GATE_HB_WOW64_BLOCK_LIMIT );
    char* end = NULL;
    unsigned long long parsed;

    if (value == mr_razobrano) return mr_limit;
    mr_razobrano = value;
    mr_limit = 0;                                /* не задан или мусор — предела нет */
    if (!value || !*value) return mr_limit;
    errno = 0;
    parsed = strtoull(value, &end, 0);
    if (errno != 0 || end == value || (end && *end != '\0')) return mr_limit;
    mr_limit = (uint64_t)parsed;
    return mr_limit;
}

static bool valid_process(const hb_wow64_process_t* process) {
    return process &&
           process->size >= sizeof(*process) &&
           process->version == HB_WOW64CPU_ABI_VERSION &&
           process->memory &&
           process->guest32_base;
}

static bool valid_thread(const hb_wow64_thread_t* thread) {
    return thread &&
           thread->size >= sizeof(*thread) &&
           thread->version == HB_WOW64CPU_ABI_VERSION &&
           thread->machine == HB_WOW64_MACHINE_I386 &&
           thread->ctx;
}

hb_result_t hb_wow64cpu_process_init(hb_wow64_process_t* process) {
    hb_memory_t* external_memory;

    if (!process || process->size < sizeof(*process)) return HB_ERR_INVALID_ARG;
    external_memory = process->memory;
    memset((uint8_t*)process + offsetof(hb_wow64_process_t, version), 0,
           sizeof(*process) - offsetof(hb_wow64_process_t, version));

    process->version = HB_WOW64CPU_ABI_VERSION;
    process->memory = external_memory ? external_memory : hb_memory_create(0);
    if (!process->memory) return HB_ERR_OUT_OF_MEMORY;
    process->owns_memory = external_memory ? 0u : 1u;
    if (hb_memory_guest32_reserve(process->memory) != HB_OK) {
        if (process->owns_memory) hb_memory_destroy(process->memory);
        process->memory = NULL;
        return HB_ERR_OUT_OF_MEMORY;
    }

    process->guest32_base = hb_memory_guest32_base(process->memory);
    process->bop_code[0] = 0x0f;
    process->bop_code[1] = 0xff;
    process->bop_size = sizeof(process->bop_code);
    return HB_OK;
}

void hb_wow64cpu_process_destroy(hb_wow64_process_t* process) {
    if (!process) return;
    wow64_process_ir_cache_reset(process);
    if (process->memory && process->owns_memory) hb_memory_destroy(process->memory);
    process->memory = NULL;
    process->guest32_base = NULL;
    process->owns_memory = 0;
}

hb_result_t hb_wow64cpu_thread_init(hb_wow64_process_t* process, hb_wow64_thread_t* thread) {
    hb_context_t* ctx;

    if (!thread || thread->size < sizeof(*thread) || !valid_process(process)) return HB_ERR_INVALID_ARG;
    memset((uint8_t*)thread + offsetof(hb_wow64_thread_t, version), 0,
           sizeof(*thread) - offsetof(hb_wow64_thread_t, version));

    ctx = hb_context_create(HB_ARCH_X86, HB_BACKEND_INTERP);
    if (!ctx) return HB_ERR_OUT_OF_MEMORY;
    ctx->memory = process->memory;
    ctx->guest32_base = (uint64_t)(uintptr_t)hb_memory_guest32_base(process->memory);

    thread->version = HB_WOW64CPU_ABI_VERSION;
    thread->machine = HB_WOW64_MACHINE_I386;
    thread->process = process;
    thread->ctx = ctx;
    return HB_OK;
}

void hb_wow64cpu_thread_destroy(hb_wow64_thread_t* thread) {
    if (!thread) return;
    if (thread->jit_rt) {
        hb_jit_runtime_destroy(thread->jit_rt);
        thread->jit_rt = NULL;
    }
    if (thread->ctx) {
        thread->ctx->memory = NULL;
        hb_context_destroy(thread->ctx);
    }
    thread->ctx = NULL;
    thread->process = NULL;
}

hb_result_t hb_wow64cpu_get_bop_code(const hb_wow64_process_t* process,
                                     const uint8_t** code,
                                     uint32_t* size) {
    if (!valid_process(process) || !code || !size) return HB_ERR_INVALID_ARG;
    *code = process->bop_code;
    *size = process->bop_size;
    return HB_OK;
}

hb_result_t hb_wow64cpu_import_i386_context(hb_wow64_thread_t* thread,
                                            const hb_wow64_i386_context_t* in) {
    hb_context_t* ctx;

    if (!valid_thread(thread) || !in ||
        in->size < sizeof(*in) ||
        in->version != HB_WOW64CPU_ABI_VERSION) return HB_ERR_INVALID_ARG;

    ctx = thread->ctx;
    ctx->regs.x86.eax = in->eax;
    ctx->regs.x86.ebx = in->ebx;
    ctx->regs.x86.ecx = in->ecx;
    ctx->regs.x86.edx = in->edx;
    ctx->regs.x86.esi = in->esi;
    ctx->regs.x86.edi = in->edi;
    ctx->regs.x86.esp = in->esp;
    ctx->regs.x86.ebp = in->ebp;
    ctx->regs.x86.eip = in->eip;
    ctx->regs.x86.eflags = in->eflags;
    ctx->regs.x86.x87 = in->x87;
    ctx->pc = in->eip;
    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — НЕ ЗАТИРАТЬ БАЗУ FS НУЛЁМ.
     * Замер (печать ниже): первый импорт приносит fs_base=0x7f000000 (зеркало TEB,
     * отображено), ВТОРОЙ приносит 0 и затирает верное значение. После этого
     * помощник прибавляет 0, и i386-чтение fs:[0] / fs:[0x18] уходит по линейным
     * 0 и 0x18 -> MEMORY_FAULT -> цепочка SEH нечитаема -> c0000025 -> гибель.
     * Контекст при этом ОДИН И ТОТ ЖЕ (указатели совпали), то есть дело именно в
     * повторном импорте, а не в подмене объекта. Умолчание 0 — прежнее поведение. */
    {
        const char* v = hb_gate( HB_GATE_HB_KEEP_FS_BASE );
        int keep = (v && *v && *v != '0') ? 1 : 0;
        if (!keep || in->fs_base || !ctx->fs_base) ctx->fs_base = in->fs_base;
    }
    {   /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: печать объекта контекста при импорте.
         * Сравнивается с ctx= в macrunner-hb-helper-fault-addr: разные указатели ->
         * помощник работает с ДРУГИМ контекстом; одинаковые -> поле обнуляют позже. */
        static int n;
        if (n++ < 4) { fprintf(stderr, "macrunner-hb-ctx-import: ctx=%p fs_base=%#llx\n",
                               (void*)ctx, (unsigned long long)ctx->fs_base); fflush(stderr); }
    }
    ctx->gs_base = in->gs_base;
    ctx->seg_cs = in->seg_cs;
    ctx->seg_ds = in->seg_ds;
    ctx->seg_es = in->seg_es;
    ctx->seg_fs = in->seg_fs;
    ctx->seg_gs = in->seg_gs;
    ctx->seg_ss = in->seg_ss;
    return HB_OK;
}

hb_result_t hb_wow64cpu_export_i386_context(const hb_wow64_thread_t* thread,
                                            hb_wow64_i386_context_t* out) {
    const hb_context_t* ctx;

    if (!valid_thread(thread) || !out || out->size < sizeof(*out)) return HB_ERR_INVALID_ARG;
    ctx = thread->ctx;
    memset((uint8_t*)out + offsetof(hb_wow64_i386_context_t, version), 0,
           sizeof(*out) - offsetof(hb_wow64_i386_context_t, version));
    out->version = HB_WOW64CPU_ABI_VERSION;
    out->eax = ctx->regs.x86.eax;
    out->ebx = ctx->regs.x86.ebx;
    out->ecx = ctx->regs.x86.ecx;
    out->edx = ctx->regs.x86.edx;
    out->esi = ctx->regs.x86.esi;
    out->edi = ctx->regs.x86.edi;
    out->esp = ctx->regs.x86.esp;
    out->ebp = ctx->regs.x86.ebp;
    out->eip = ctx->regs.x86.eip;
    out->eflags = ctx->regs.x86.eflags;
    out->fs_base = (uint32_t)ctx->fs_base;
    out->gs_base = (uint32_t)ctx->gs_base;
    out->seg_cs = ctx->seg_cs;
    out->seg_ds = ctx->seg_ds;
    out->seg_es = ctx->seg_es;
    out->seg_fs = ctx->seg_fs;
    out->seg_gs = ctx->seg_gs;
    out->seg_ss = ctx->seg_ss;
    out->x87 = ctx->regs.x86.x87;
    return HB_OK;
}

hb_result_t hb_wow64cpu_simulate(hb_wow64_thread_t* thread,
                                 hb_backend_t backend,
                                 size_t max_code_bytes,
                                 hb_exec_result_t* out) {
    uint8_t code[HB_WOW64CPU_DEFAULT_MAX_CODE_BYTES];
    hb_context_t* ctx;
    uint64_t total_steps = 0;
    uint64_t total_blocks = 0;
    uint64_t dispatched = 0;
    uint64_t block_limit;
    bool ran_block = false;
    hb_wow64_ir_cache_t* ir_cache;
    hb_result_t result = HB_OK;

    if (!valid_thread(thread) || !out) {
        /* MacRunner 2026-08-27, Diablo — КАКОЕ ИМЕННО УСЛОВИЕ ОТКАЗАЛО.
         *
         * Замер: на eip=0x778590a6 движок вернул INVALID_ARG при steps=0 blocks=0 и
         * faulted=0 — то есть отказал ДО исполнения, и это остановило игру ровно на
         * предпоследнем шаге эталонного пути DirectDraw. Условий здесь шесть, и по
         * коду отказа их не различить. Печатаем виновника. */
        fprintf(stderr, "macrunner-hb-simarg: ОТКАЗ thread=%p out=%p valid_thread=%d\n",
                (void*)thread, (void*)out, thread ? (int)valid_thread(thread) : -1);
        fflush(stderr);
        return HB_ERR_INVALID_ARG;
    }
    ctx = thread->ctx;
    if (!valid_process(thread->process) || ctx->arch != HB_ARCH_X86 ||
        ctx->mode != HB_MODE_32BIT || ctx->memory != thread->process->memory) {
        fprintf(stderr, "macrunner-hb-simarg: ОТКАЗ eip=%08x valid_process=%d arch=%d(ждём %d) "
                        "mode=%d(ждём %d) ctx_mem=%p proc_mem=%p\n",
                (unsigned)ctx->pc, (int)valid_process(thread->process),
                (int)ctx->arch, (int)HB_ARCH_X86, (int)ctx->mode, (int)HB_MODE_32BIT,
                (void*)ctx->memory, (void*)thread->process->memory);
        fflush(stderr);
        return HB_ERR_INVALID_ARG;
    }

    memset(out, 0, sizeof(*out));
    if (backend == HB_BACKEND_AOT) backend = HB_BACKEND_INTERP;
    /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 1031 — ПРИНУДИТЕЛЬНЫЙ ИНТЕРПРЕТАТОР ДЛЯ i386.
     * xtajit просит JIT жёстко (`unixlib.c:1112`), и сравнить дороги было нечем. Замер 1030
     * показал, что часть форм чтения исполняется шагом, но не даёт ни эффекта, ни отказа;
     * интерпретатор те же байты исполняет верно (стенд, 1029). Гейт позволяет сравнить их
     * при прочих равных. По умолчанию ВЫКЛЮЧЕН — поведение прогонов без него не меняется. */
    {
        const char* v = hb_gate( HB_GATE_HB_WOW64_INTERP );
        int force_interp = (v && *v && *v != '0') ? 1 : 0;
        if (force_interp) backend = HB_BACKEND_INTERP;
    }
    if (max_code_bytes == 0 || max_code_bytes > sizeof(code)) max_code_bytes = sizeof(code);
    block_limit = wow64_simulate_block_limit();

    ir_cache = thread->process->ir_cache;
    if (!ir_cache) {
        ir_cache = calloc(1, sizeof(*ir_cache));
        thread->process->ir_cache = ir_cache;
    }

    while (!block_limit || dispatched < block_limit) {
        hb_decoder_t* dec = NULL;
        hb_ir_func_t* func = NULL;
        hb_exec_result_t block_out;
        hb_result_t r;
        uint32_t pc = ctx->regs.x86.eip;
        size_t len = 0;
        bool chain;
        bool trace_pc = trace_wow64_pc_enabled(pc);
        bool transient_func = false;

        ctx->pc = pc;
        if (trace_pc)
        {
            fprintf(stderr, "macrunner-hb-wow64-sim: phase=block-start dispatched=%llu pc=%08x esp=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x eflags=%08x\n",
                    (unsigned long long)dispatched, pc, ctx->regs.x86.esp, ctx->regs.x86.eax,
                    ctx->regs.x86.ebx, ctx->regs.x86.ecx, ctx->regs.x86.edx,
                    ctx->regs.x86.esi, ctx->regs.x86.edi, ctx->regs.x86.ebp,
                    ctx->regs.x86.eflags);
            fflush(stderr);
        }
        func = wow64_ir_cache_find(ir_cache, pc);
        if (func && !func->cfg)
        {
            /* Кеш отдал функцию с пустым cfg — значит объект уже уничтожен, а указатель в
             * таблице остался (use-after-free). Печатаем СРАЗУ, до использования. */
            fprintf(stderr, "macrunner-hb-кеш-отдал-без-cfg: pc=%08x func=%p\n",
                    (unsigned)pc, (void*)func);
            fflush(stderr);
        }
        if (func && trace_wcslen_pattern_enabled(pc))
            trace_wcslen_pattern(pc, NULL, 0, true, false);
        if (!func) {
            hb_region_t* region = hb_memory_find_region(ctx->memory, pc);
            if (region && (region->perm & HB_PERM_EXEC) && pc >= region->base && pc < region->base + region->size) {
                size_t chunk = (size_t)(region->base + region->size - pc);
                if (chunk > max_code_bytes) chunk = max_code_bytes;
                r = hb_memory_read(ctx->memory, pc, code, chunk);
                if (r == HB_OK) len = chunk;
            }
            /* If the region read stopped at a page boundary mid-instruction,
             * top up byte-by-byte across the boundary (x86 insns up to 15 B). */
            if (len < 15) {
                while (len < max_code_bytes) {
                    uint32_t guest = pc + (uint32_t)len;
                    if (!hb_memory_can_exec(ctx->memory, guest, 1)) break;
                    r = hb_memory_fetch(ctx->memory, guest, &code[len]);
                    if (r != HB_OK) break;
                    len++;
                }
            }
            if (!len) {
                if (ran_block) break;
                ctx->last_result = HB_ERR_MEMORY_FAULT;
                out->result = HB_ERR_MEMORY_FAULT;
                out->faulted = true;
                out->fault_reason = "unable to fetch executable i386 code";
                result = HB_ERR_MEMORY_FAULT;
                goto done;
            }
            if (is_wow64_bop_opcode(code, len)) break;
            if (trace_wcslen_pattern_enabled(pc))
                trace_wcslen_pattern(pc, code, len, false, is_wine_x86_wcslen_pattern(code, len));
            if (try_run_wine_x86_rtl_query_env(ctx, code, len, &block_out)) {
                ran_block = true;
                dispatched++;
                total_steps += block_out.steps_executed;
                total_blocks += block_out.blocks_executed;
                continue;
            }
            if (try_run_wine_x86_strcmp(ctx, code, len, &block_out)) {
                ran_block = true;
                dispatched++;
                total_steps += block_out.steps_executed;
                total_blocks += block_out.blocks_executed;
                continue;
            }
            if (try_run_wine_x86_wcslen(ctx, code, len, &block_out)) {
                if (block_out.faulted) {
                    *out = block_out;
                    result = block_out.result;
                    goto done;
                }
                ran_block = true;
                dispatched++;
                total_steps += block_out.steps_executed;
                total_blocks += block_out.blocks_executed;
                continue;
            }
            if (trace_pc)
            {
                trace_wow64_bytes(pc, code, len);
                fflush(stderr);
            }

            dec = hb_decoder_create(HB_ARCH_X86, code, len, pc);
            if (!dec) {
                result = HB_ERR_OUT_OF_MEMORY;
                goto done;
            }
            r = hb_lift_func_x86(dec, &func);
            hb_decoder_destroy(dec);
            /* ★★★★ 28.08.2026 — ОТКУДА БЕРЁТСЯ ФУНКЦИЯ БЕЗ cfg.
             *
             * `hb_jit_runtime_run` отказывает с INVALID_ARG по проверке `!func->cfg`
             * (hb_runtime.c:9624), и прибор ветки печатает `cfg=0x0` при живом func. А
             * `hb_ir_func_create` создаёт cfg ВСЕГДА и при неудаче возвращает NULL — то есть
             * функции с нулевым cfg взяться неоткуда. Значит либо lift вернул OK с пустым
             * cfg, либо func пришёл из кеша уже уничтоженным. Печатаем состояние сразу после
             * подъёма — это различит оба случая. Только когда cfg пуст: в здоровом прогоне
             * записи нет вовсе. */
            if (r == HB_OK && func && !func->cfg)
            {
                fprintf(stderr, "macrunner-hb-lift-без-cfg: pc=%08x func=%p len=%u\n",
                        (unsigned)pc, (void*)func, (unsigned)len);
                fflush(stderr);
            }
            if (r != HB_OK) {
                /* MacRunner 2026-08-27, Diablo: подъём кода в IR не удался. Это
                 * останавливает игру на предпоследнем шаге эталонного пути DirectDraw,
                 * поэтому печатаем адрес и код — по одному коду их не различить. */
                fprintf(stderr, "macrunner-hb-lift-отказ: pc=%08x r=%d len=%u\n",
                        (unsigned)pc, (int)r, (unsigned)len);
                fflush(stderr);
                result = r;
                goto done;
            }
            if (!wow64_ir_cache_put(ir_cache, pc, func)) transient_func = true;
            if (func && !func->cfg)
            {
                fprintf(stderr, "macrunner-hb-после-кеша-без-cfg: pc=%08x func=%p transient=%d\n",
                        (unsigned)pc, (void*)func, (int)transient_func);
                fflush(stderr);
            }
        }

        chain = func_ends_in_control_transfer(func);
        memset(&block_out, 0, sizeof(block_out));
        if (backend == HB_BACKEND_JIT || backend == HB_BACKEND_AOT) {
            if (!thread->jit_rt) {
                thread->jit_rt = hb_jit_runtime_create(ctx);
                if (!thread->jit_rt) { result = HB_ERR_OUT_OF_MEMORY; goto done; }
            }
            r = hb_jit_runtime_run(thread->jit_rt, func, &block_out);
            if (r != HB_OK) {
                /* MacRunner 2026-08-27, Diablo: ветка JIT. Приборы внутри
                 * hb_jit_runtime_run и hb_runtime_run молчат, значит результат
                 * проброшен изнутри — фиксируем ветку и адрес здесь. */
                fprintf(stderr, "macrunner-hb-ветка: JIT r=%d pc=%08x jit_rt=%p func=%p cfg=%p\n",
                        (int)r, (unsigned)pc, (void*)thread->jit_rt, (void*)func,
                        func ? (void*)func->cfg : NULL);
                fflush(stderr);
            }
        } else {
            r = hb_runtime_run(ctx, func, backend, &block_out);
            if (r != HB_OK) {
                fprintf(stderr, "macrunner-hb-ветка: RUNTIME r=%d pc=%08x backend=%d func=%p cfg=%p\n",
                        (int)r, (unsigned)pc, (int)backend, (void*)func,
                        func ? (void*)func->cfg : NULL);
                fflush(stderr);
            }
        }
        if (trace_pc)
        {
            fprintf(stderr, "macrunner-hb-wow64-sim: phase=block-done dispatched=%llu pc=%08x r=%d out=%d faulted=%u steps=%llu blocks=%llu next=%08x esp=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x eflags=%08x\n",
                    (unsigned long long)dispatched, pc, r, block_out.result, block_out.faulted,
                    (unsigned long long)block_out.steps_executed,
                    (unsigned long long)block_out.blocks_executed,
                    ctx->regs.x86.eip, ctx->regs.x86.esp,
                    ctx->regs.x86.eax, ctx->regs.x86.ebx, ctx->regs.x86.ecx,
                    ctx->regs.x86.edx, ctx->regs.x86.esi, ctx->regs.x86.edi,
                    ctx->regs.x86.ebp, ctx->regs.x86.eflags);
            fflush(stderr);
        }
        /* ★ 2026-09-03 (режим D Diablo): после выселения блока в рантайме (самоизменение) снять из кеша IR все
         * функции, накрывающие страницу выселенного блока — иначе следующий поиск по pc отдаст устаревший IR. */
        {
            static __thread uint64_t smc_seen;
            uint64_t tot = hb_jit_smc_evicted_total();
            if (tot != smc_seen) {
                uint64_t a = 0, lo, hi; uint32_t l = 0; unsigned dropped;
                static unsigned long long n_drop;
                hb_jit_smc_last_evicted(&a, &l);
                smc_seen = tot;
                lo = a & ~0xfffull; hi = ((a + (l ? l : 1) - 1) | 0xfffull) + 1;
                dropped = wow64_ir_cache_drop_overlapping(ir_cache, lo, hi);
                if (++n_drop <= 16 || (n_drop & 0xffu) == 0) {
                    fprintf(stderr, "macrunner-hb-ir-сброс-smc: n=%llu выселений=%llu блок=0x%llx+%u страница=[0x%llx,0x%llx) снято_функций=%u\n",
                            n_drop, (unsigned long long)tot, (unsigned long long)a, (unsigned)l,
                            (unsigned long long)lo, (unsigned long long)hi, dropped);
                    fflush(stderr);
                }
            }
        }
        if (transient_func) hb_ir_func_destroy(func);

        ran_block = true;
        dispatched++;
        total_steps += block_out.steps_executed;
        total_blocks += block_out.blocks_executed;

        if (r != HB_OK || block_out.result != HB_OK || block_out.faulted) {
            if (r != HB_OK) {
                fprintf(stderr, "macrunner-hb-run-отказ: pc=%08x r=%d block_res=%d faulted=%u\n",
                        (unsigned)pc, (int)r, (int)block_out.result, (unsigned)block_out.faulted);
                fflush(stderr);
            }
            *out = block_out;
            out->steps_executed = total_steps;
            out->blocks_executed = total_blocks;
            result = r;
            goto done;
        }
        if (!chain) break;
    }

    out->result = HB_OK;
    out->steps_executed = total_steps;
    out->blocks_executed = total_blocks;
done:
    return result;
}

hb_result_t hb_wow64cpu_notify_memory_alloc(hb_wow64_process_t* process,
                                            uint32_t base,
                                            size_t size,
                                            hb_perm_t perm) {
    if (!valid_process(process)) return HB_ERR_INVALID_ARG;
    wow64_ir_cache_note_range(process, base, size);
    if (!wow64_ir_cache_purge_range(process, base, size))
        wow64_process_ir_cache_reset(process);
    return hb_memory_guest32_map(process->memory, base, size, perm);
}

hb_result_t hb_wow64cpu_notify_memory_protect(hb_wow64_process_t* process,
                                              uint32_t base,
                                              size_t size,
                                              hb_perm_t perm) {
    if (!valid_process(process)) return HB_ERR_INVALID_ARG;
    wow64_ir_cache_note_range(process, base, size);
    if (!wow64_ir_cache_purge_range(process, base, size))
        wow64_process_ir_cache_reset(process);
    return hb_memory_guest32_protect(process->memory, base, size, perm);
}

hb_result_t hb_wow64cpu_notify_memory_free(hb_wow64_process_t* process,
                                           uint32_t base,
                                           size_t size) {
    if (!valid_process(process)) return HB_ERR_INVALID_ARG;
    wow64_ir_cache_note_range(process, base, size);
    if (!wow64_ir_cache_purge_range(process, base, size))
        wow64_process_ir_cache_reset(process);
    return hb_memory_guest32_unmap(process->memory, base, size);
}

hb_result_t hb_wow64cpu_notify_execute_flags(hb_wow64_process_t* process,
                                             uint32_t flags) {
    if (!valid_process(process)) return HB_ERR_INVALID_ARG;
    /* Весь перевод выпущен при ПРЕЖНИХ правах на исполнение, значит стал
     * негодным. Сбрасываем кеш перевода процесса целиком — тем же путём,
     * которым это делается при освобождении памяти.
     *
     * Почему целиком, а не по страницам: флаги DEP — свойство ПРОЦЕССА, а не
     * диапазона; какие именно страницы сменили исполнимость, из уведомления
     * не видно. Смена редка (обычно один раз при запуске), поэтому полный
     * сброс дешевле любой попытки угадать. */
    (void)flags;
    wow64_process_ir_cache_reset(process);
    return HB_OK;
}
