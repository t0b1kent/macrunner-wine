/*
 * Unix side of MacRunner i386-on-arm64 HyperBridge CPU module.
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#ifdef __APPLE__
# include <mach/mach.h>
# include <mach/mach_vm.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/unixlib.h"

#include <unistd.h>
#include "hb_memory.h"
#include "hb_env.h"
#include "hb_wow64cpu.h"
/* Итерация 805: нужен полный вид `hb_context_t` — читаем `last_fault_kind`/`last_fault_addr`. */
#include "hb_context.h"

#include "xtajit_private.h"
#include "hb_probe.h"

/* тот же слот, что у cpu.c:41 и wow64_private.h:44 */
#define XTAJIT_WOW64_TLS_GUEST32_BASE (WOW64_TLS_MAX_NUMBER - 1)

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: общий гейт шумных трасс симуляции. */
static int macrunner_trace_sim_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0)
    {
        const char *v = getenv( "MACRUNNER_XTAJIT_TRACE_SIM" );
        enabled = v && v[0] && v[0] != '0';
    }
    return enabled;
}

/* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1254 — НАКОПИТЕЛЬНЫЙ СЧЁТЧИК ГОСТЕВЫХ КОМАНД.
 *
 * Зачем. Признак остановки требует прибор, снимающий число гостевых команд за прогон. Счётчик
 * `exec.steps_executed` в движке был, а снять его было нечем: печать на строке 1168+ стоит за
 * MACRUNNER_XTAJIT_TRACE_ALL_SIMULATE и печатает НА КАЖДЫЙ вызов симуляции (построчная трасса
 * измеренно убивает прогон: 137 на 17.7 с против 444 с штатных), а печать в конце функции стоит
 * под `if (params->status || exec.faulted)` — то есть только при отказе, и в трёх проверенных
 * журналах её нет ни разу. Здесь — накопление и РЕДКАЯ печать.
 *
 * Гейт MACRUNNER_XTAJIT_STEP_TOTALS, умолчание ВКЛ (правило: правка, добавляющая работу на
 * горячем пути, идёт за гейтом; прибор приёмки обязан работать без уговоров). Это гейт ПО
 * ЗНАЧЕНИЮ, а не по наличию: выключается только явным `=0`. Гейт «по наличию» в этом проекте
 * уже давал «всегда включено» (случай драйвера CoreAudio, 04.08).
 *
 * Цена: три относительных атомарных сложения на вызов симуляции. Вызовы крупные — на прогоне
 * Diablo их 3488 за 592 с, то есть шесть в секунду.
 *
 * Печать: по СТЕПЕНЯМ ДВОЙКИ, затем раз в 1024 вызова. Первая строка выходит на первом же
 * вызове намеренно: маркер, который может не появиться, негоден как критерий — это стоило дня
 * 07.08, когда три прогона по 900 с ждали строку, печатавшуюся под четырьмя условиями сразу.
 *
 * ГРАНИЦА, без которой числа врут: тройка (calls, steps, blocks) печатается из трёх ОТДЕЛЬНЫХ
 * относительных сложений, поэтому при нескольких потоках она может быть слегка перекошена —
 * шаги соседнего потока успевают попасть в сумму раньше своего вызова. Для итога прогона это
 * безразлично (последняя строка — полная сумма), для сравнения строк между собой — нет.
 */
static int macrunner_step_totals_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0)
    {
        const char *v = getenv( "MACRUNNER_XTAJIT_STEP_TOTALS" );
        enabled = !v || (v[0] && v[0] != '0');
    }
    return enabled;
}

static unsigned long long macrunner_step_calls;
static unsigned long long macrunner_step_steps;
static unsigned long long macrunner_step_blocks;

/* ★★★ 07.09.2026, лейн ПРИБОРЫ-4 — ЧИСЛО У ЭТОГО МАРКЕРА ЕСТЬ ВЫБОРКА, А НЕ ИТОГ.
 *
 * В памяти проекта на нём стоит запись «xtajit-steps занижает в 4,7 раза»
 * (project_dispatch_is_not_on_the_measured_path_on_benches_20260825). Причина видна прямо
 * здесь: печать идёт на НОМЕРАХ-СТЕПЕНЯХ ДВОЙКИ и кратных 1024, поэтому ПОСЛЕДНЯЯ строка
 * журнала показывает состояние на 32768-м вызове, тогда как вызовов к концу прогона могло
 * быть 45 000. Читатель, берущий последнюю строку за итог, занижает — и именно так и
 * вышло. Это класс «число у маркера — выборка, а не итог».
 *
 * Второе молчание того же места: гейт MACRUNNER_XTAJIT_STEP_TOTALS стоит СЛЕВА от `||`,
 * а `exec` проверяется справа — ноль строк означал и «гейт закрыт», и «звали с NULL», и
 *  «сюда не заходили». Три причины, один ноль.
 *
 * Приборы: looked первого = ВСЕ заходы (это и есть настоящий `calls`, без выборки),
 * hits = заходы, реально учтённые; у второго hits = сколько раз строка ПЕЧАТАЛАСЬ.
 * Отношение looked к hits второго прямо говорит, насколько последняя печатная строка
 * отстала от итога. Ни одного лишнего действия на пути: два расслабленных сложения. */
HB_PROBE_DEFINE(pr_steps_zahod, "xtajit-steps-заходы",
                "заходы в macrunner_step_totals_note (looked — ВСЕ, выше гейта и выше "
                "проверки exec); hits = заход учтён, то есть гейт открыт И exec не NULL. "
                "looked — это настоящее число вызовов исполнителя, без выборки печати",
                "MACRUNNER_XTAJIT_STEP_TOTALS", 0);
HB_PROBE_DEFINE(pr_steps_pechat, "xtajit-steps",
                "учтённые заходы (looked); hits = строка macrunner-xtajit-steps РЕАЛЬНО "
                "напечатана. Печать идёт на степенях двойки и кратных 1024, поэтому "
                "последняя строка журнала — снимок, а не итог: отношение looked к hits и "
                "есть мера того, насколько снимок отстал",
                NULL, 0);

static void macrunner_step_totals_note( const hb_exec_result_t *exec )
{
    unsigned long long n, s, b;

    HB_PROBE_LOOKED(&pr_steps_zahod);
    if (!macrunner_step_totals_enabled() || !exec) return;
    HB_PROBE_HIT(&pr_steps_zahod);
    HB_PROBE_LOOKED(&pr_steps_pechat);
    n = __atomic_add_fetch( &macrunner_step_calls, 1, __ATOMIC_RELAXED );
    s = __atomic_add_fetch( &macrunner_step_steps, (unsigned long long)exec->steps_executed,
                            __ATOMIC_RELAXED );
    b = __atomic_add_fetch( &macrunner_step_blocks, (unsigned long long)exec->blocks_executed,
                            __ATOMIC_RELAXED );
    if ((n & (n - 1)) == 0 || (n & 1023u) == 0)
    {
        HB_PROBE_SAY( &pr_steps_pechat, "calls=%llu steps=%llu blocks=%llu\n", n, s, b );
        fflush( stderr );
    }
}

static pthread_mutex_t process_mutex = PTHREAD_MUTEX_INITIALIZER;
static hb_wow64_process_t process = { sizeof(process) };
static BOOL process_ready;
static __thread hb_wow64_thread_t thread = { sizeof(thread) };
static __thread BOOL thread_ready;
static __thread uint32_t teb32_guest_base;
static __thread size_t teb32_guest_size;
static __thread BOOL teb32_guest_initialized;
static __thread uint32_t teb32_tls_guest_base;
static __thread BOOL teb32_tls_initialized;
static __thread uint32_t teb32_tls_image_base;
static pthread_mutex_t teb32_alloc_mutex = PTHREAD_MUTEX_INITIALIZER;

#define XTAJIT_GUEST_PAGE_SIZE 0x1000u
#define XTAJIT_GUEST32_SHARED_DATA 0x7ffe0000u
#define XTAJIT_GUEST32_SHARED_DATA_SIZE 0x1000u
#define XTAJIT_TEB32_TLS_VECTOR_SIZE 0x1000u
#define XTAJIT_TEB32_TLS_SLOT_STRIDE 0x1000u
#define XTAJIT_TEB32_TLS_SLOT_COUNT 32u
#define XTAJIT_TEB32_TLS_MAP_SIZE \
    (XTAJIT_TEB32_TLS_VECTOR_SIZE + XTAJIT_TEB32_TLS_SLOT_STRIDE * XTAJIT_TEB32_TLS_SLOT_COUNT)

static uint32_t guest_page_floor( uint32_t addr )
{
    return addr & ~(XTAJIT_GUEST_PAGE_SIZE - 1);
}

static size_t guest_page_span( uint32_t addr, size_t size )
{
    uint32_t base = guest_page_floor( addr );
    uint64_t end = (uint64_t)addr + size;
    uint64_t aligned_end = (end + XTAJIT_GUEST_PAGE_SIZE - 1) & ~(uint64_t)(XTAJIT_GUEST_PAGE_SIZE - 1);

    if (aligned_end > UINT32_MAX + 1ULL || aligned_end < base) return 0;
    return (size_t)(aligned_end - base);
}

struct xtajit_debug_channel
{
    unsigned char flags;
    char name[15];
};

static BOOL wine_debug_enables_seh(void)
{
    const char *env = getenv( "WINEDEBUG" );
    const char *token;

    if (!env) return FALSE;
    token = env;
    while (*token)
    {
        const char *end = strchr( token, ',' );
        const char *start = token;
        const char *plus, *minus, *sign;
        size_t len;

        if (!end) end = token + strlen( token );
        sign = plus = memchr( start, '+', end - start );
        minus = memchr( start, '-', end - start );
        if (minus && (!sign || minus < sign)) sign = minus;
        if (sign && *sign == '+')
        {
            const char *name = sign + 1;
            len = end - name;
            if ((len == 3 && !memcmp( name, "seh", 3 )) ||
                (len == 3 && !memcmp( name, "all", 3 )))
                return TRUE;
        }
        token = *end ? end + 1 : end;
    }
    return FALSE;
}

static void sync_peb32_debug_options(uint32_t peb)
{
    enum
    {
        DBCL_FIXME = 0,
        DBCL_ERR   = 1,
        DBCL_TRACE = 3,
    };
    struct xtajit_debug_channel options[2];
    uint32_t addr;
    size_t size;

    if (!peb || !process.memory) return;
    addr = peb + XTAJIT_GUEST_PAGE_SIZE;

    /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 256 — ПУБЛИКОВАТЬ НАСТОЯЩУЮ ТАБЛИЦУ.
     * Ниже лежит заглушка: одна запись по умолчанию плюс канал `seh`. Из-за неё у гостя ПЕРВОЙ
     * стоит запись с пустым именем, а PE-сторона считает длину таблицы циклом
     * `while (name[0]) nb++` (`ntdll/thread.c:init_options`) — получает НОЛЬ каналов, и вся
     * отладочная печать wine из 32-битных модулей пропадает (замер 255: прогон с
     * `+ddraw,+d3d,+wgl` дал 0 строк при загруженных модулях).
     * Настоящая таблица лежит на unix-стороне по `peb + 2*page_size` (`unix/debug.c:dbg_init`),
     * и здесь она доступна: у unix-кода `NtCurrentTeb()->Peb` — это ХОЗЯЙСКИЙ 64-битный PEB.
     * Гейт по умолчанию ВЫКЛЮЧЕН: заглушка остаётся поведением по умолчанию. */
    {
        static int cure = -1;

        if (cure < 0)
        {
            const char *v = getenv( "MACRUNNER_XTAJIT_WOW64_DEBUG_CHANNELS" );
            cure = v && *v == '1';
        }
        if (cure && NtCurrentTeb() && NtCurrentTeb()->Peb)
        {
            const struct xtajit_debug_channel *src =
                (const struct xtajit_debug_channel *)((char *)NtCurrentTeb()->Peb +
                                                      2 * XTAJIT_GUEST_PAGE_SIZE);
            unsigned int n = 0;

            /* Таблица отсортирована по имени и завершается записью с ПУСТЫМ именем — её тоже
             * копируем: PE-сторона берёт из неё флаги по умолчанию. */
            static int said;
            /* Смещение таблицы у PE-стороны — `page_size * (sizeof(void*)/4)`, то есть ОДНА
             * страница для i386. Но `page_size` там системный, а на macOS ARM64 он 16 КБ, тогда
             * как unix-сторона печатала таблицу по смещению 2*4096. Класть по ОБОИМ смещениям
             * дешевле, чем гадать: лишняя копия ничего не ломает. */
            const uint32_t offsets[2] = { XTAJIT_GUEST_PAGE_SIZE, 4u * XTAJIT_GUEST_PAGE_SIZE };
            unsigned int written = 0, i;

            while (n < 250 && src[n].name[0]) n++;
            size = (size_t)(n + 1) * sizeof(*src);
            for (i = 0; i < 2; i++)
            {
                uint32_t a = peb + offsets[i];

                if (!hb_memory_can_write( process.memory, a, size )) continue;
                (void)hb_memory_write( process.memory, a, src, size );
                written++;
            }
            if (written)
            {
                if (!said)
                {
                    said = 1;
                    fprintf( stderr, "macrunner-xtajit-dbgchan-publish: kanalov=%u mest=%u "
                             "peb32=%08x src=%p pervyj='%.15s'\n", n, written, peb,
                             (const void *)src, n ? src[0].name : "(net)" );
                    fflush( stderr );
                }
                return;
            }
            fprintf( stderr, "macrunner-xtajit-dbgchan-publish: OTKAZ zapis addr=%08x size=%zu\n",
                     addr, size );
            fflush( stderr );
        }
    }

    memset( options, 0, sizeof(options) );
    options[0].flags = (1 << DBCL_ERR) | (1 << DBCL_FIXME);
    size = sizeof(options[0]);
    if (wine_debug_enables_seh())
    {
        options[0].flags |= (1 << DBCL_TRACE);
        memcpy( options[0].name, "seh", 4 );
        options[1].flags = (1 << DBCL_ERR) | (1 << DBCL_FIXME);
        size = sizeof(options);
    }
    if (hb_memory_can_write( process.memory, addr, size ))
        (void)hb_memory_write( process.memory, addr, options, size );
}

static NTSTATUS status_from_hb( hb_result_t result )
{
    switch (result)
    {
    case HB_OK: return STATUS_SUCCESS;
    case HB_ERR_OUT_OF_MEMORY: return STATUS_NO_MEMORY;
    case HB_ERR_MEMORY_FAULT: return STATUS_ACCESS_VIOLATION;
    case HB_ERR_UNSUPPORTED_OPCODE:
    case HB_ERR_UNSUPPORTED_FEATURE: return STATUS_ILLEGAL_INSTRUCTION;
    case HB_ERR_INVALID_ARG: return STATUS_INVALID_PARAMETER;
    default: return STATUS_UNSUCCESSFUL;
    }
}

static BOOL trace_native_stack_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) enabled = getenv( "MACRUNNER_XTAJIT_TRACE_STACK" ) != NULL;
    return enabled;
}

static BOOL trace_teb32_tls_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) enabled = getenv( "MACRUNNER_XTAJIT_TRACE_TEB32_TLS" ) != NULL;
    return enabled;
}

static void trace_native_stack( const char *phase, const hb_wow64_i386_context_t *ctx,
                                const hb_exec_result_t *exec, hb_result_t hb_result,
                                NTSTATUS status )
{
    volatile char marker;
    TEB *teb = NtCurrentTeb();
    uintptr_t sp = (uintptr_t)&marker;
    uintptr_t limit = teb ? (uintptr_t)teb->Tib.StackLimit : 0;
    uintptr_t base = teb ? (uintptr_t)teb->Tib.StackBase : 0;
    long slack = limit ? (long)(sp - limit) : 0;
    static __thread unsigned int count;
    unsigned int sample = count++;

    if (!trace_native_stack_enabled()) return;
    if (sample >= 128 && slack >= 0x40000 && (sample & 0x3fff)) return;

    fprintf( stderr,
             "macrunner-xtajit-stack: phase=%s count=%u native_sp=%p teb_stack=%p-%p "
             "dealloc=%p slack=%ld eip=%08x esp=%08x hb=%d exec=%d faulted=%u "
             "steps=%llu blocks=%llu status=%08x\n",
             phase, sample, (void *)sp, (void *)limit, (void *)base,
             teb ? teb->DeallocationStack : NULL, slack,
             ctx ? ctx->eip : 0, ctx ? ctx->esp : 0, hb_result,
             exec ? exec->result : HB_OK, exec ? exec->faulted : 0,
             exec ? (unsigned long long)exec->steps_executed : 0,
             exec ? (unsigned long long)exec->blocks_executed : 0,
             (unsigned int)status );
}

static void dump_guest_probe_addr( const char *name, uint32_t addr )
{
    hb_region_t *region;
    void *host;

    if (!process.memory) return;
    region = hb_memory_find_region( process.memory, addr );
    host = hb_memory_guest32_to_host( process.memory, addr );
    /* ★★★★★★ MacRunner 2026-08-29 — pid ОБЯЗАТЕЛЕН.
     * У Diablo в одном журнале ДВА процесса (базы окна 0x300000000 и 0xb00000000),
     * и все fprintf идут в общий stderr без различения. Из-за этого «область есть в
     * скане, а региона нет» читалось как противоречие — а это были РАЗНЫЕ процессы.
     * Тот же класс, что compare-probe-timestamps-before-concluding. */
    fprintf( stderr,
             "macrunner-xtajit-unix: [pid=%d] mem %s=%08x host=%p can_r=%u can_w=%u can_x=%u",
             (int)getpid(), name, addr, host,
             hb_memory_can_read( process.memory, addr, 1 ),
             hb_memory_can_write( process.memory, addr, 1 ),
             hb_memory_can_exec( process.memory, addr, 1 ) );
    if (region)
    {
        fprintf( stderr, " region=%08llx-%08llx perm=%u guest32=%u gen=%llu",
                 (unsigned long long)region->base,
                 (unsigned long long)(region->base + region->size),
                 region->perm, region->is_guest32,
                 (unsigned long long)region->gen );
    }
    else
    {
        /* ★★★★★ MacRunner 2026-08-29 — СОСЕДИ, КОГДА РЕГИОНА НЕТ.
         *
         * Замер по отчётам .ERR Diablo: 7 из 20 падений — на ПЕРВОЙ инструкции
         * функции ddraw (nop hotpatch-пролога), то есть при ВЫБОРКЕ команды.
         * В журнале при этом:
         *   mem eip=76c74700  can_x=1  region=76c54000-76c88000   покрыт
         *   mem eip=76c7472d  host=0x0 can_x=0                     НЕ покрыт
         * Хотя 76c7472d лежит ВНУТРИ 76c54000-76c88000. «region отсутствует» без
         * соседей не говорит, дыра это в середине известного диапазона или край
         * карты — а лечение у этих случаев разное.
         *
         * Ищем ближайшие регионы слева и справа: если оба есть и адрес между
         * ними — это ДЫРА, и виновата карта. Если соседей нет — область не
         * отображалась вовсе, и искать надо в уведомлениях. */
        hb_region_t *left = NULL, *right = NULL, *raw;
        uint32_t probe;

        /* ★★★★★★ СНАЧАЛА — обход дерева БЕЗ фильтра guest32.
         * find_region отвечает NULL и когда региона нет, и когда он есть без метки
         * is_guest32 (find_region_impl: `return n->is_guest32 ? n : NULL`). Два разных
         * состояния под одним ответом — ровно та склейка, что уже стоила дня. */
        raw = hb_memory_find_region_raw( process.memory, addr );
        if (raw)
        {
            fprintf( stderr, " СЫРОЙ_РЕГИОН_ЕСТЬ=%08llx-%08llx perm=%u guest32=%u gen=%llu"
                             " ВЕРДИКТ=МЕТКА_GUEST32_СНЯТА",
                     (unsigned long long)raw->base,
                     (unsigned long long)(raw->base + raw->size),
                     raw->perm, raw->is_guest32, (unsigned long long)raw->gen );
            fprintf( stderr, "\n" );
            return;
        }

        for (probe = addr & ~0xfffu; probe >= 0x10000u; probe -= 0x1000u)
        {
            if ((left = hb_memory_find_region( process.memory, probe ))) break;
            if (probe < 0x1000u + (addr > 0x100000u ? addr - 0x100000u : 0u)) break;
        }
        for (probe = (addr + 0xfffu) & ~0xfffu; probe < 0xfffff000u; probe += 0x1000u)
        {
            if ((right = hb_memory_find_region( process.memory, probe ))) break;
            if (probe > addr + 0x100000u) break;
        }
        fprintf( stderr, " РЕГИОНА_НЕТ слева=" );
        if (left) fprintf( stderr, "%08llx-%08llx(perm=%u)",
                           (unsigned long long)left->base,
                           (unsigned long long)(left->base + left->size), left->perm );
        else fprintf( stderr, "нет" );
        fprintf( stderr, " справа=" );
        if (right) fprintf( stderr, "%08llx-%08llx(perm=%u)",
                            (unsigned long long)right->base,
                            (unsigned long long)(right->base + right->size), right->perm );
        else fprintf( stderr, "нет" );
        if (left && right) fprintf( stderr, " ВЕРДИКТ=ДЫРА" );
        else fprintf( stderr, " ВЕРДИКТ=край" );
    }
    fprintf( stderr, "\n" );
}

static void dump_guest_bytes( const char *name, uint32_t addr )
{
    uint8_t bytes[16];
    size_t i;

    if (!process.memory) return;
    fprintf( stderr, "macrunner-xtajit-unix: bytes %s=%08x", name, addr );
    for (i = 0; i < sizeof(bytes); i++)
    {
        if (hb_memory_fetch( process.memory, addr + (uint32_t)i, &bytes[i] ) != HB_OK)
            break;
        fprintf( stderr, " %02x", bytes[i] );
    }
    fprintf( stderr, "\n" );
}

static void dump_guest_dwords( const char *name, uint32_t addr, unsigned int count )
{
    unsigned int i;

    fprintf( stderr, "macrunner-xtajit-unix: dwords %s=%08x", name, addr );
    for (i = 0; i < count; i++)
    {
        uint32_t value = 0;
        if (hb_memory_read( process.memory, addr + i * sizeof(value), &value, sizeof(value) ) != HB_OK)
            break;
        fprintf( stderr, " %08x", value );
    }
    fprintf( stderr, "\n" );
}

static hb_perm_t protect_to_perm( ULONG protect )
{
    hb_perm_t perm = HB_PERM_NONE;
    ULONG p = protect & 0xff;

    if (p == PAGE_NOACCESS) return HB_PERM_NONE;
    if (p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
        p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE ||
        p == PAGE_EXECUTE_WRITECOPY) perm = (hb_perm_t)(perm | HB_PERM_READ);
    if (p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
        p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY) {
        perm = (hb_perm_t)(perm | HB_PERM_WRITE);
    }
    if (p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
        p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY) {
        perm = (hb_perm_t)(perm | HB_PERM_EXEC);
    }
    return perm;
}

static NTSTATUS ensure_process(void)
{
    NTSTATUS status = STATUS_SUCCESS;

    pthread_mutex_lock( &process_mutex );
    if (!process_ready)
    {
        hb_memory_t *(*shared_memory)(void);

        process.size = sizeof(process);
        shared_memory = (hb_memory_t *(*)(void))dlsym( RTLD_DEFAULT, "macrunner_hb_wow64_guest32_memory" );
        if (shared_memory) process.memory = shared_memory();
        status = status_from_hb( hb_wow64cpu_process_init( &process ) );
        if (!status)
        {
            hb_region_t *region = hb_memory_find_region( process.memory, XTAJIT_GUEST32_SHARED_DATA );

            /* ★ MacRunner 2026-08-27, Diablo — ЗАПОЛНЯЕМ ТОЛЬКО СВЕЖУЮ СТРАНИЦУ.
             *
             * Было: карта создавалась под `if (!region)`, а `memcpy` выполнялся
             * БЕЗУСЛОВНО. При повторной инициализации регион уже есть, карта
             * пропускается — но копирование идёт всё равно, а страница к тому моменту
             * уже переведена в HB_PERM_READ строкой ниже. Отсюда отказ:
             *
             *   vhf-probe ret=c0000005 addr=0x57ffe0000 site=bus
             *   esr=0x9200004f -> DFSC=0x0f (нарушение прав), WnR=1
             *   pc в _platform_memmove — то есть пишет ХОЗЯЙСКИЙ memcpy, не игра
             *
             * KUSER_SHARED_DATA в Windows действительно read-only, и я сперва счёл
             * отказ верным поведением. Это было неправильно: писала не игра, а мы сами.
             * Содержимое страницы за время жизни процесса не меняется, поэтому при
             * готовом регионе копировать нечего. */
            if (!region)
            {
                status = status_from_hb( hb_memory_guest32_map( process.memory, XTAJIT_GUEST32_SHARED_DATA,
                                                                 XTAJIT_GUEST32_SHARED_DATA_SIZE,
                                                                 HB_PERM_READ | HB_PERM_WRITE ) );
                if (!status)
                {
                    void *guest = hb_memory_guest32_to_host( process.memory, XTAJIT_GUEST32_SHARED_DATA );

                    if (!guest) status = STATUS_ACCESS_VIOLATION;
                    else
                    {
                        memcpy( guest, (const void *)WINE_USER_SHARED_DATA_ADDRESS,
                                XTAJIT_GUEST32_SHARED_DATA_SIZE );
                        status = status_from_hb( hb_memory_guest32_protect( process.memory,
                                                                            XTAJIT_GUEST32_SHARED_DATA,
                                                                            XTAJIT_GUEST32_SHARED_DATA_SIZE,
                                                                            HB_PERM_READ ) );
                    }
                }
            }
        }
        process_ready = !status;
    }
    pthread_mutex_unlock( &process_mutex );
    return status;
}

static NTSTATUS ensure_thread(void)
{
    NTSTATUS status;

    if ((status = ensure_process())) return status;
    if (thread_ready) return STATUS_SUCCESS;

    thread.size = sizeof(thread);
    status = status_from_hb( hb_wow64cpu_thread_init( &process, &thread ) );
    thread_ready = !status;
    return status;
}

static NTSTATUS ensure_teb32_guest_mapping( size_t teb_size )
{
    const uint32_t high = 0x7f000000u;
    const uint32_t low = 0x70000000u;
    uint32_t base;
    /* ★ MacRunner 2026-08-27, Diablo — TEB64 ЛЕЖИТ НИЖЕ TEB32 И ТОЖЕ НУЖЕН ГОСТЮ.
     *
     * Регистрировалась область РОВНО под TEB32, начиная с его базы. Но 64-битный
     * TEB стоит на `WowTebOffset` ниже, и обращения к нему уходили в неотображённую
     * память. Замер (прибор macrunner-gl-teb64):
     *
     *   teb32=7f000000  host=0x37f000000  offset=-8192  итог=0x37effe000
     *
     * а область была 7eff0000-7eff2000. Два отказа из четырёх приходили именно
     * отсюда: opengl32 `wow64_thread_attach` пишет `teb->glTable` по смещению
     * 0x1238 от TEB64, то есть по 0x…7efff238 — вне карты, DFSC=0x07.
     *
     * Расширяем область вниз на 64 КБ: этого с запасом хватает на TEB64 (8 КБ) и
     * на всё, что WOW64 держит рядом, и не задевает соседей — шаг перебора баз
     * ниже тоже 64 КБ. */
    const uint32_t teb64_запас = 0x10000u;
    size_t map_size = guest_page_span( high - teb64_запас, teb_size + teb64_запас );
    hb_result_t result;

    if (teb32_guest_base) return STATUS_SUCCESS;
    if (!map_size) return STATUS_INVALID_PARAMETER;
    if (ensure_process()) return STATUS_NO_MEMORY;

    pthread_mutex_lock( &teb32_alloc_mutex );
    for (base = high; base >= low; base -= 0x10000u)
    {
        result = hb_memory_guest32_map( process.memory, base - teb64_запас, map_size,
                                        HB_PERM_READ | HB_PERM_WRITE );
        if (result == HB_OK)
        {
            teb32_guest_base = base;
            teb32_guest_size = map_size;
            break;
        }
        if (base < low + 0x10000u) break;
    }
    pthread_mutex_unlock( &teb32_alloc_mutex );

    return teb32_guest_base ? STATUS_SUCCESS : STATUS_NO_MEMORY;
}

static NTSTATUS ensure_teb32_tls_guest_mapping(void)
{
    const uint32_t high = 0x7eff0000u;
    const uint32_t low = 0x70000000u;
    uint32_t base;
    size_t map_size = guest_page_span( high, XTAJIT_TEB32_TLS_MAP_SIZE );
    hb_result_t result;

    if (teb32_tls_guest_base) return STATUS_SUCCESS;
    if (!map_size) return STATUS_INVALID_PARAMETER;
    if (ensure_process()) return STATUS_NO_MEMORY;

    pthread_mutex_lock( &teb32_alloc_mutex );
    for (base = high; base >= low; base -= 0x10000u)
    {
        result = hb_memory_guest32_map( process.memory, base, map_size,
                                        HB_PERM_READ | HB_PERM_WRITE );
        if (result == HB_OK)
        {
            teb32_tls_guest_base = base;
            break;
        }
        if (base < low + 0x10000u) break;
    }
    pthread_mutex_unlock( &teb32_alloc_mutex );

    return teb32_tls_guest_base ? STATUS_SUCCESS : STATUS_NO_MEMORY;
}

static BOOL read_guest_u16( uint32_t addr, uint16_t *value )
{
    return hb_memory_read( process.memory, addr, value, sizeof(*value) ) == HB_OK;
}

static BOOL read_guest_u32( uint32_t addr, uint32_t *value )
{
    return hb_memory_read( process.memory, addr, value, sizeof(*value) ) == HB_OK;
}

static BOOL guest_seh_chain_valid( uint32_t head )
{
    unsigned int depth;
    static int said;
    uint32_t head0 = head;

    if (!head || head == 0xffffffffu) return TRUE;
    for (depth = 0; depth < 64; depth++)
    {
        uint32_t next, handler;

        if (!hb_memory_can_read( process.memory, head, 2 * sizeof(uint32_t) ))
        {
            if (said++ < 200)
                fprintf( stderr, "macrunner-xtajit-seh-chain: ОТКАЗ голова=%08x глубина=%u звено=%08x причина=нечитаемо\n",
                         head0, depth, head );
            return FALSE;
        }
        if (!read_guest_u32( head, &next ) ||
            !read_guest_u32( head + sizeof(uint32_t), &handler ))
        {
            if (said++ < 200)
                fprintf( stderr, "macrunner-xtajit-seh-chain: ОТКАЗ глубина=%u звено=%08x причина=чтение-полей\n",
                         depth, head );
            return FALSE;
        }
        if (!handler || handler == 0xffffffffu ||
            !hb_memory_can_exec( process.memory, handler, 1 ))
        {
            if (said++ < 200)
                fprintf( stderr, "macrunner-xtajit-seh-chain: ОТКАЗ голова=%08x глубина=%u звено=%08x обработчик=%08x причина=обработчик-неисполним\n",
                         head0, depth, head, handler );
            return FALSE;
        }
        if (next == 0xffffffffu) return TRUE;
        if (!next || next == head)
        {
            if (said++ < 200)
                fprintf( stderr, "macrunner-xtajit-seh-chain: ОТКАЗ голова=%08x глубина=%u звено=%08x next=%08x причина=петля-или-ноль\n",
                         head0, depth, head, next );
            return FALSE;
        }
        head = next;
    }
    if (said++ < 200)
        fprintf( stderr, "macrunner-xtajit-seh-chain: ОТКАЗ глубина=64 звено=%08x причина=предел-глубины\n", head );
    return FALSE;
}

static BOOL is_synthetic_teb32_tls_pointer( uint32_t ptr )
{
    return teb32_tls_guest_base &&
           ptr >= teb32_tls_guest_base &&
           ptr < teb32_tls_guest_base + XTAJIT_TEB32_TLS_MAP_SIZE;
}

static void dump_guest_seh_head( const char *prefix )
{
    uint32_t head = 0, next = 0, handler = 0;

    if (!teb32_guest_base || !process.memory) return;
    if (hb_memory_read( process.memory, teb32_guest_base, &head, sizeof(head) ) != HB_OK)
        return;
    if (head && head != 0xffffffffu)
    {
        hb_memory_read( process.memory, head, &next, sizeof(next) );
        hb_memory_read( process.memory, head + sizeof(next), &handler, sizeof(handler) );
    }
    fprintf( stderr, "macrunner-xtajit-seh: %s teb32=%08x head=%08x next=%08x handler=%08x valid=%u handler_exec=%u\n",
             prefix, teb32_guest_base, head, next, handler, guest_seh_chain_valid( head ),
             handler ? hb_memory_can_exec( process.memory, handler, 1 ) : 0 );
}

static NTSTATUS setup_main_module_tls32( uint32_t peb, uint32_t *tls_pointer )
{
    enum
    {
        PEB32_IMAGE_BASE = 0x08,
        PE_DOS_E_LFANEW = 0x3c,
        PE_FILE_HEADER_SIZE = 20,
        PE32_OPTIONAL_MAGIC = 0x10b,
        PE32_TLS_DIR = 9,
        PE32_DATA_DIR_BASE = 96,
        TLS32_START_RAW = 0x00,
        TLS32_END_RAW = 0x04,
        TLS32_INDEX = 0x08,
        TLS32_ZERO_FILL = 0x10,
    };
    uint32_t image_base = 0, e_lfanew = 0, nt = 0, tls_rva = 0, tls_size = 0;
    uint32_t start_raw = 0, end_raw = 0, index_addr = 0, zero_fill = 0;
    uint32_t index = 0, data_addr, vector_addr;
    uint16_t magic = 0;
    size_t raw_size, zero_size, total_size, copy_size;
    void *dst;

    if (!tls_pointer) return STATUS_INVALID_PARAMETER;
    *tls_pointer = 0;
    if (!peb) return STATUS_SUCCESS;
    if (!read_guest_u32( peb + PEB32_IMAGE_BASE, &image_base ) || !image_base) return STATUS_SUCCESS;

    if (teb32_tls_initialized && teb32_tls_image_base == image_base)
    {
        *tls_pointer = teb32_tls_guest_base;
        return STATUS_SUCCESS;
    }

    if (!read_guest_u16( image_base, &magic ) || magic != IMAGE_DOS_SIGNATURE) return STATUS_SUCCESS;
    if (!read_guest_u32( image_base + PE_DOS_E_LFANEW, &e_lfanew )) return STATUS_SUCCESS;
    nt = image_base + e_lfanew;
    if (!read_guest_u32( nt, &tls_size ) || tls_size != IMAGE_NT_SIGNATURE) return STATUS_SUCCESS;
    if (!read_guest_u16( nt + 4 + PE_FILE_HEADER_SIZE, &magic ) ||
        magic != PE32_OPTIONAL_MAGIC) return STATUS_SUCCESS;
    if (!read_guest_u32( nt + 4 + PE_FILE_HEADER_SIZE + PE32_DATA_DIR_BASE + PE32_TLS_DIR * 8,
                         &tls_rva ) ||
        !read_guest_u32( nt + 4 + PE_FILE_HEADER_SIZE + PE32_DATA_DIR_BASE + PE32_TLS_DIR * 8 + 4,
                         &tls_size ) ||
        !tls_rva || tls_size < 0x18)
        return STATUS_SUCCESS;

    if (!read_guest_u32( image_base + tls_rva + TLS32_START_RAW, &start_raw ) ||
        !read_guest_u32( image_base + tls_rva + TLS32_END_RAW, &end_raw ) ||
        !read_guest_u32( image_base + tls_rva + TLS32_INDEX, &index_addr ) ||
        !read_guest_u32( image_base + tls_rva + TLS32_ZERO_FILL, &zero_fill ))
        return STATUS_SUCCESS;

    if (index_addr) read_guest_u32( index_addr, &index );
    if (index >= XTAJIT_TEB32_TLS_SLOT_COUNT) index = 0;
    if (ensure_teb32_tls_guest_mapping()) return STATUS_NO_MEMORY;

    vector_addr = teb32_tls_guest_base;
    data_addr = vector_addr + XTAJIT_TEB32_TLS_VECTOR_SIZE + index * XTAJIT_TEB32_TLS_SLOT_STRIDE;
    raw_size = end_raw > start_raw ? end_raw - start_raw : 0;
    zero_size = zero_fill;
    total_size = raw_size + zero_size;
    if (total_size > XTAJIT_TEB32_TLS_SLOT_STRIDE) total_size = XTAJIT_TEB32_TLS_SLOT_STRIDE;
    copy_size = raw_size < total_size ? raw_size : total_size;

    dst = hb_memory_guest32_to_host( process.memory, data_addr );
    if (!dst) return STATUS_ACCESS_VIOLATION;
    memset( dst, 0, XTAJIT_TEB32_TLS_SLOT_STRIDE );
    if (copy_size && hb_memory_read( process.memory, start_raw, dst, copy_size ) != HB_OK)
        return STATUS_SUCCESS;
    hb_memory_write( process.memory, vector_addr + index * sizeof(uint32_t),
                     &data_addr, sizeof(data_addr) );
    if (index_addr) hb_memory_write( process.memory, index_addr, &index, sizeof(index) );

    teb32_tls_initialized = TRUE;
    teb32_tls_image_base = image_base;
    *tls_pointer = vector_addr;
    return STATUS_SUCCESS;
}

/* ★ ПРИБОРЫ-5 (партия 4), 07.09.2026 — СЕМЬЯ TEB32.
 *
 * `sync_teb32_to_guest` (ниже) — правки 01-02.09.2026 «ОДНО ОТОБРАЖЕНИЕ TEB НА ПОТОК» /
 * «ОБРАТНАЯ СИНХРОНИЗАЦИЯ», доказанные замером на Half-Life (статический TLS 1/1->0/0,
 * 3/3->0/3). Все пять точек печати этой семьи под условием — где-то гейт, где-то потолок
 * n<4, где-то первый-раз-на-поле latch.
 *
 * ★ ПОПУТНАЯ НАХОДКА (не вывод из замера, а факт устройства, проверенный поимённо):
 * `MACRUNNER_HB_TEB32_ONE` (сама оптимизация «копии нет») нигде не включён —
 * `grep -rn TEB32_ONE scripts/ reports/ГЕЙТЫ-*` и вольт ГЕЙТЫ-СВОД.md дают НОЛЬ
 * совпадений. Умолчание в коде — `getenv(...)`, без `_default_on`, то есть ВЫКЛЮЧЕН.
 * Это не отменяет замер обратной синхронизации (та правка «снят» и безусловна), но
 * означает, что путь БЕЗ копии в бою НЕ ИСПОЛНЯЕТСЯ ни одним известным прогоном —
 * см. ГРАНИЦЫ отчёта. */
HB_PROBE_DEFINE(pr_teb32_mirror_skip, "xtajit-teb32-mirror-skip",
                "страницы, копируемые в mirror_host_teb32_to_guest (общепроцессное "
                "зеркало TEB32); hits = mach_vm_read_overwrite не вернул chunk байт "
                "целиком (страница подставлена нулями)",
                NULL, 0);
HB_PROBE_DEFINE(pr_teb32_fsbase_restored, "xtajit-fsbase-restored",
                "ранние выходы sync_teb32_to_guest, где вызывающий не передал "
                "TEB32 (!ctx->teb32_host); looked считает и гейт закрытым, и открытым — "
                "hits = гейт MACRUNNER_HB_FS_BASE_FROM_TEB32 (умолчание ВЫКЛЮЧЕН) "
                "открыт И зеркало уже проинициализировано (потолок 4)",
                "MACRUNNER_HB_FS_BASE_FROM_TEB32", 4);
HB_PROBE_DEFINE(pr_teb32_odno, "teb32-одно",
                "потоки, у которых хозяйский TEB32 лежит ВНУТРИ гостевого окна (условие "
                "для отказа от копии); гейт MACRUNNER_HB_TEB32_ONE, умолчание ВЫКЛЮЧЕН "
                "И нигде не задан ни одним скриптом проекта (проверено grep -rn по "
                "scripts/reports/vault, 0 совпадений) — путь БЕЗ КОПИИ в бою не "
                "исполнялся ни разу; потолок печати 4",
                "MACRUNNER_HB_TEB32_ONE", 4);
HB_PROBE_DEFINE(pr_teb32_obratno, "teb32-обратно",
                "потоки с копией TEB32, для которых сверяется указатель TLS; hits = "
                "хозяйский указатель РАСХОДИТСЯ с гостевым и переписывается (гейт снят "
                "02.09.2026, правка безусловна; потолок печати 4, said n)",
                NULL, 4);
HB_PROBE_DEFINE(pr_teb32_raskhozhdenie, "teb32-расхождение",
                "поля TEB32 (8 полей на поток), сверяемые гость/хозяин после "
                "инициализации; hits = поле разошлось И это первое расхождение ИМЕННО "
                "этого поля за процесс (latch skazano[n] — второе и далее расхождение "
                "того же поля не печатается, но looked растёт)",
                NULL, 0);

static NTSTATUS mirror_host_teb32_to_guest( uint32_t guest_base, const void *host, size_t size )
{
#ifdef __APPLE__
    const uintptr_t src_base = (uintptr_t)host;
    uint8_t buf[XTAJIT_GUEST_PAGE_SIZE];
    size_t done = 0;

    while (done < size)
    {
        uintptr_t src = src_base + done;
        size_t chunk = XTAJIT_GUEST_PAGE_SIZE - (src & (XTAJIT_GUEST_PAGE_SIZE - 1));
        mach_vm_size_t copied = 0;
        kern_return_t kr;
        hb_result_t result;

        if (chunk > size - done) chunk = size - done;
        HB_PROBE_LOOKED(&pr_teb32_mirror_skip);
        kr = mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)src,
                                     (mach_vm_size_t)chunk,
                                     (mach_vm_address_t)(uintptr_t)buf, &copied );
        if (kr != KERN_SUCCESS || copied != chunk)
        {
            HB_PROBE_HIT(&pr_teb32_mirror_skip);
            memset( buf, 0, chunk );
            fprintf( stderr, "macrunner-xtajit-unix: teb32 mirror skipped unreadable host page src=%p size=%zu kr=%d copied=%llu\n",
                     (const void *)src, chunk, kr, (unsigned long long)copied );
        }
        result = hb_memory_write( process.memory, guest_base + (uint32_t)done, buf, chunk );
        if (result != HB_OK) return status_from_hb( result );
        done += chunk;
    }
    return STATUS_SUCCESS;
#else
    return status_from_hb( hb_memory_write( process.memory, guest_base, host, size ) );
#endif
}

static NTSTATUS sync_teb32_to_guest( struct xtajit_i386_context *ctx )
{
    enum
    {
        TEB32_EXCEPTION_LIST = 0x00,
        TEB32_STACK_BASE     = 0x04,
        TEB32_STACK_LIMIT    = 0x08,
        TEB32_SUBSYSTEM_TIB  = 0x0c,
        TEB32_SELF           = 0x18,
        TEB32_CLIENT_PROCESS = 0x20,
        TEB32_CLIENT_THREAD  = 0x24,
        TEB32_TLS_POINTER    = 0x2c,
        TEB32_PEB            = 0x30,
        TEB32_WOW32_RESERVED = 0xc0,
        TEB32_ACTCTX_STACK   = 0x184,
        TEB32_ACTCTX_LIST    = 0x188,
        TEB32_ACTCTX_PTR     = 0x1a8,
        TEB32_TLS_EXPANSION  = 0xf94,
        TEB32_FLS_SLOTS      = 0xfb4,
        TEB32_TLS_SLOTS      = 0xe10,
    };
    uint32_t exception_list = 0, stack_base = 0, stack_limit = 0, subsystem_tib = 0, peb = 0;
    uint32_t wow32_reserved = ctx ? ctx->wow32_reserved : 0, self, actctx_stack, actctx_list;
    uint32_t old_flink = 0, old_blink = 0, host_teb32_low = ctx ? (uint32_t)ctx->teb32_host : 0;
    uint32_t old_tls_pointer = 0, old_tls_expansion = 0, old_fls_slots = 0;
    ACTIVATION_CONTEXT_STACK32 old_actctx_stack;
    uint32_t guest_tls_pointer = 0;
    TEB32 *host_teb32 = ctx ? (TEB32 *)(uintptr_t)ctx->teb32_host : NULL;
    uint32_t tls_pointer = host_teb32 ? host_teb32->ThreadLocalStoragePointer : 0;
    BOOL preserve_actctx_stack = FALSE;
    BOOL bez_kopii = FALSE;
    BOOL preserve_tls_pointer;
    NTSTATUS status;
    void *guest;

    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — ИСТОЧНИК НУЛЕВОЙ БАЗЫ FS.
     * Присваивание ctx->fs_base = teb32_guest_base стоит в САМОМ КОНЦЕ функции, а этот
     * ранний выход его перешагивает. Вызов unix_simulate_impl, у которого в params->context
     * нет описателя TEB32, уходит отсюда с fs_base = 0 (что передал вызывающий), и дальше
     * import_context -> hb_wow64cpu_import_i386_context кладёт этот ноль в hb_context_t.
     * Замер печатью macrunner-hb-ctx-import: 0x7f000000, 0, 0x7f000000, 0x7f000000 — второй
     * импорт затирает верную базу. После этого i386-чтение fs:[0] / fs:[0x18] уходит по
     * линейным 0 и 0x18 -> MEMORY_FAULT -> цепочка SEH нечитаема -> c0000025.
     * Зеркало TEB32 общепроцессное, поэтому при уже выполненной разметке база известна и
     * верна независимо от того, принёс ли ЭТОТ вызов описатель. Ветка teb32_guest_initialized
     * ниже до конца функции доходит и базу ставит — лечим только ранний выход.
     * Умолчание 0 = прежнее поведение; ветку включает MACRUNNER_HB_FS_BASE_FROM_TEB32=1. */
    if (!ctx || !ctx->teb32_host || !ctx->teb32_size)
    {
        static int from_teb32 = -1;
        if (from_teb32 < 0)
        {
            const char *v = getenv( "MACRUNNER_HB_FS_BASE_FROM_TEB32" );
            from_teb32 = (v && *v && *v != '0') ? 1 : 0;
        }
        HB_PROBE_LOOKED(&pr_teb32_fsbase_restored);
        if (from_teb32 && ctx && teb32_guest_initialized && !ctx->fs_base)
        {
            ctx->fs_base = teb32_guest_base;
            {
                static int n;
                if (n++ < 4)
                {
                    HB_PROBE_HIT(&pr_teb32_fsbase_restored);
                    fprintf( stderr, "macrunner-xtajit-fsbase-restored: fs_base=%08x teb32_host=%llx\n",
                             teb32_guest_base, (unsigned long long)ctx->teb32_host );
                    fflush( stderr );
                }
            }
        }
        return STATUS_SUCCESS;
    }
    /* ★★★★★★ MacRunner 2026-09-01 — ОДНО ОТОБРАЖЕНИЕ TEB НА ПОТОК.
     *
     * Гостевое окно ПЛОСКОЕ: хозяйский адрес = гостевой + guest32_base. Хозяйский
     * TEB32 лежит внутри этого окна (замер: host=0x5001F2000, база=0x500000000),
     * значит гость УЖЕ видит его по адресу 0x1F2000 — и прибор прочитал там
     * правильный TEB: Self=0x1F2000, свой поток, верный PEB. Больше того, wine сам
     * записал в Tib.Self гостевой адрес, то есть так и задумано.
     *
     * Тогда копия не нужна вовсе: направляем fs прямо на неё. Исчезает не только
     * лишняя работа по зеркалированию, но и сам класс дефекта — рассинхронизация
     * копии с оригиналом, из-за которой не работал статический TLS
     * (Half-Life, FileSystem_Stdio.dll+0x8330).
     *
     * Гейт MACRUNNER_HB_TEB32_ONE. Если TEB32 вне окна (так бывает у 32-битного
     * ребёнка 64-битного процесса — см. примечание про базу выше), спокойно уходим
     * на прежний путь с зеркалом. */
    {
        static int one = -1;

        if (one < 0)
        {
            const char *v = getenv( "MACRUNNER_HB_TEB32_ONE" );
            one = (v && *v && *v != '0') ? 1 : 0;
        }
        HB_PROBE_LOOKED(&pr_teb32_odno);
        if (one && host_teb32 && process.memory)
        {
            uintptr_t okno = (uintptr_t)hb_memory_guest32_base( process.memory );
            uintptr_t hteb = (uintptr_t)host_teb32;

            if (okno && hteb >= okno && (hteb - okno) < 0x100000000ull)
            {
                static int n;

                teb32_guest_base = (uint32_t)(hteb - okno);
                bez_kopii = TRUE;
                if (n++ < 4)
                {
                    HB_PROBE_HIT(&pr_teb32_odno);
                    fprintf( stderr, "macrunner-teb32-одно: fs=%08x host=%p окно=%p "
                             "(копии нет, доправка полей остаётся)\n",
                             teb32_guest_base, host_teb32, (void *)okno );
                    fflush( stderr );
                }
            }
        }
    }

    if (!bez_kopii && ensure_teb32_guest_mapping( ctx->teb32_size )) return STATUS_NO_MEMORY;

    if (teb32_guest_initialized)
    {
        hb_memory_read( process.memory, teb32_guest_base + TEB32_EXCEPTION_LIST,
                        &exception_list, sizeof(exception_list) );
        hb_memory_read( process.memory, teb32_guest_base + TEB32_STACK_BASE,
                        &stack_base, sizeof(stack_base) );
        hb_memory_read( process.memory, teb32_guest_base + TEB32_STACK_LIMIT,
                        &stack_limit, sizeof(stack_limit) );
        hb_memory_read( process.memory, teb32_guest_base + TEB32_SUBSYSTEM_TIB,
                        &subsystem_tib, sizeof(subsystem_tib) );
        hb_memory_read( process.memory, teb32_guest_base + TEB32_PEB,
                        &peb, sizeof(peb) );
        hb_memory_read( process.memory, teb32_guest_base + TEB32_TLS_POINTER,
                        &old_tls_pointer, sizeof(old_tls_pointer) );
        hb_memory_read( process.memory, teb32_guest_base + TEB32_TLS_EXPANSION,
                        &old_tls_expansion, sizeof(old_tls_expansion) );
        hb_memory_read( process.memory, teb32_guest_base + TEB32_FLS_SLOTS,
                        &old_fls_slots, sizeof(old_fls_slots) );
        if (!wow32_reserved)
            hb_memory_read( process.memory, teb32_guest_base + TEB32_WOW32_RESERVED,
                            &wow32_reserved, sizeof(wow32_reserved) );
        if (hb_memory_read( process.memory, teb32_guest_base + TEB32_ACTCTX_STACK,
                            &old_actctx_stack, sizeof(old_actctx_stack) ) == HB_OK)
            preserve_actctx_stack = TRUE;
    }

    /* Без копии зеркалировать нечего: fs уже смотрит на сам хозяйский TEB32. */
    if (!bez_kopii &&
        (status = mirror_host_teb32_to_guest( teb32_guest_base,
                                              (const void *)(uintptr_t)ctx->teb32_host,
                                              ctx->teb32_size )))
        return status;

    guest = hb_memory_guest32_to_host( process.memory, teb32_guest_base );
    if (!guest) return STATUS_ACCESS_VIOLATION;

    self = teb32_guest_base;
    if (teb32_guest_initialized)
    {
        if (exception_list && guest_seh_chain_valid( exception_list ))
            memcpy( (uint8_t *)guest + TEB32_EXCEPTION_LIST,
                    &exception_list, sizeof(exception_list) );
        if (stack_base) memcpy( (uint8_t *)guest + TEB32_STACK_BASE,
                                &stack_base, sizeof(stack_base) );
        if (stack_limit) memcpy( (uint8_t *)guest + TEB32_STACK_LIMIT,
                                 &stack_limit, sizeof(stack_limit) );
        if (peb) memcpy( (uint8_t *)guest + TEB32_PEB, &peb, sizeof(peb) );
        if (wow32_reserved) memcpy( (uint8_t *)guest + TEB32_WOW32_RESERVED,
                                    &wow32_reserved, sizeof(wow32_reserved) );
        if (old_tls_expansion) memcpy( (uint8_t *)guest + TEB32_TLS_EXPANSION,
                                       &old_tls_expansion, sizeof(old_tls_expansion) );
        if (old_fls_slots) memcpy( (uint8_t *)guest + TEB32_FLS_SLOTS,
                                   &old_fls_slots, sizeof(old_fls_slots) );
    }
    if (subsystem_tib && !hb_memory_can_read( process.memory, subsystem_tib, sizeof(uint32_t) ))
        subsystem_tib = 0;
    memcpy( (uint8_t *)guest + TEB32_SUBSYSTEM_TIB, &subsystem_tib, sizeof(subsystem_tib) );
    memcpy( (uint8_t *)guest + 0x18, &self, sizeof(self) ); /* TIB.Self */
    if (host_teb32)
    {
        uint32_t unique_process = host_teb32->ClientId.UniqueProcess;
        uint32_t unique_thread = host_teb32->ClientId.UniqueThread;

        if (!unique_process) unique_process = PtrToUlong( NtCurrentTeb()->ClientId.UniqueProcess );
        if (!unique_thread) unique_thread = PtrToUlong( NtCurrentTeb()->ClientId.UniqueThread );
        if (unique_process)
            memcpy( (uint8_t *)guest + TEB32_CLIENT_PROCESS,
                    &unique_process, sizeof(unique_process) );
        if (unique_thread)
            memcpy( (uint8_t *)guest + TEB32_CLIENT_THREAD,
                    &unique_thread, sizeof(unique_thread) );
    }
    if (!peb && host_teb32) peb = host_teb32->Peb;
    sync_peb32_debug_options( peb );
    setup_main_module_tls32( peb, &guest_tls_pointer );
    preserve_tls_pointer = old_tls_pointer &&
        !is_synthetic_teb32_tls_pointer( old_tls_pointer ) &&
        !(old_tls_pointer >= host_teb32_low && old_tls_pointer < host_teb32_low + ctx->teb32_size);
    if (preserve_tls_pointer)
        tls_pointer = old_tls_pointer;
    else if (guest_tls_pointer)
        tls_pointer = guest_tls_pointer;
    if (!tls_pointer || (tls_pointer >= host_teb32_low && tls_pointer < host_teb32_low + ctx->teb32_size))
        tls_pointer = teb32_guest_base + TEB32_TLS_SLOTS;
    memcpy( (uint8_t *)guest + TEB32_TLS_POINTER, &tls_pointer, sizeof(tls_pointer) );

    /* ★★★★★★ MacRunner 2026-09-01 — ОБРАТНАЯ СИНХРОНИЗАЦИЯ УКАЗАТЕЛЯ TLS.
     *
     * Имя функции честное: она зеркалит хозяйский TEB32 в гостевой и только туда.
     * Указатель на массив статического TLS живёт при этом ТОЛЬКО в гостевой копии:
     * `alloc_thread_tls` (32-битная ntdll) пишет его в свой TEB, а хозяйский TEB32
     * остаётся с нулём. Всякий, кто читает TEB через адрес от
     * NtQueryInformationThread (а это координаты слоя WoW64, то есть хозяйский
     * TEB32), видит ноль и считает поток незаведённым.
     *
     * Так ломался статический TLS: `alloc_tls_slot` обходил потоки, у всех видел
     * «нет массива», не выдавал блок НИКОМУ, и первый же доступ к статическому TLS
     * падал — Half-Life, FileSystem_Stdio.dll+0x8330, чтение [0+4].
     *
     * Возвращаем значение в хозяйский TEB32: после этого оба вида согласованы, и
     * «один TEB на поток» выполняется по существу, а не только для своего потока.
     * Гейт снят 02.09.2026: лечение доказано парным замером на одном двоичном
     * файле (статический TLS: 1/1 -> 0/0 и 3/3 -> 0/3), а выключенная ветка
     * оставляла указатель TLS рассогласованным — известно сломанное поведение.
     * Держать его за выключателем незачем: возвращаем всегда. */
    {
        HB_PROBE_LOOKED(&pr_teb32_obratno);
        if (host_teb32 && host_teb32->ThreadLocalStoragePointer != tls_pointer)
        {
            static int n;

            if (n++ < 4)
            {
                HB_PROBE_HIT(&pr_teb32_obratno);
                fprintf( stderr, "macrunner-teb32-обратно: tls было=%08x стало=%08x "
                         "гость=%08x\n", (unsigned)host_teb32->ThreadLocalStoragePointer,
                         (unsigned)tls_pointer, teb32_guest_base );
                fflush( stderr );
            }
            host_teb32->ThreadLocalStoragePointer = tls_pointer;
        }
    }

    /* ★★★★★★ 01.09.2026 — ОСТАЛЬНЫЕ ОДНОСТОРОННИЕ ПОЛЯ.
     *
     * Перепись расхождений (прибор macrunner-teb32-расхождение, Half-Life, 8 прогонов
     * подряд) дала РОВНО ДВА поля, и каждый раз одни и те же:
     *
     *     FlsSlots       гость=00291c78  хозяин=00000000
     *     ExceptionList  гость=0140fa58  хозяин=ffffffff
     *
     * `FlsSlots` — та же поломка, что была у указателя TLS: волоконное хранилище живёт
     * только в гостевой копии, а `FlsAlloc` обходит потоки ровно как `alloc_tls_slot`
     * и видит ноль. `ExceptionList` — голова цепочки SEH: у хозяина стоит ffffffff,
     * то есть «обработчиков нет», и всякий, кто разбирает исключение по хозяйскому
     * TEB32, цепочки не находит.
     *
     * Прочие шесть полей из переписи не расходились ни разу — их не трогаем.
     * Гейт снят 02.09.2026: лечение доказано замером, выключенная ветка
     * возвращала известный дефект. Правка безусловна (scripts/гейты.py). */
    {
        if (host_teb32 && teb32_guest_initialized)
        {
            uint32_t fls = 0, excl = 0;

            hb_memory_read( process.memory, teb32_guest_base + TEB32_FLS_SLOTS,
                            &fls, sizeof(fls) );
            hb_memory_read( process.memory, teb32_guest_base + TEB32_EXCEPTION_LIST,
                            &excl, sizeof(excl) );
            if (fls && host_teb32->FlsSlots != fls) host_teb32->FlsSlots = fls;
            if (excl && guest_seh_chain_valid( excl ) && host_teb32->Tib.ExceptionList != excl)
                host_teb32->Tib.ExceptionList = excl;
        }
    }
    if (trace_teb32_tls_enabled())
    {
        static __thread int tls_trace_budget = 32;
        void **native_tls = NtCurrentTeb()->ThreadLocalStoragePointer;
        uint32_t guest_slot0 = 0, guest_slot1 = 0;

        if (tls_trace_budget-- > 0)
        {
            hb_memory_read( process.memory, teb32_guest_base + TEB32_TLS_SLOTS,
                            &guest_slot0, sizeof(guest_slot0) );
            hb_memory_read( process.memory, teb32_guest_base + TEB32_TLS_SLOTS + sizeof(guest_slot0),
                            &guest_slot1, sizeof(guest_slot1) );
            fprintf( stderr,
                     "macrunner-xtajit-teb32-tls: teb32_guest=%08x host_teb32=%p "
                     "host_tls32=%08x native_tls=%p native0=%p native1=%p "
                     "guest_tls_ptr=%08x guest_slot0=%08x guest_slot1=%08x\n",
                     teb32_guest_base, host_teb32, host_teb32 ? host_teb32->ThreadLocalStoragePointer : 0,
                     native_tls, native_tls ? native_tls[0] : NULL, native_tls ? native_tls[1] : NULL,
                     tls_pointer, guest_slot0, guest_slot1 );
        }
    }

    /* ★ 01.09.2026 — ПЕРЕПИСЬ РАСХОЖДЕНИЙ. Гость меняет у себя двенадцать полей TEB,
     * а обратно возвращается пока только указатель TLS. Гадать, какие из остальных
     * реально расходятся, незачем — сравним их в живом прогоне и починим ровно те,
     * что разошлись. Печатаем ПЕРВОЕ расхождение по каждому полю, не поток строк. */
    if (host_teb32 && teb32_guest_initialized)
    {
        static int skazano[8];
        struct { const char *имя; uint32_t гость, хозяин; int n; } sverka[] = {
            { "ExceptionList",  exception_list,    host_teb32->Tib.ExceptionList,               0 },
            { "StackBase",      stack_base,        host_teb32->Tib.StackBase,                   1 },
            { "StackLimit",     stack_limit,       host_teb32->Tib.StackLimit,                  2 },
            { "TlsExpansion",   old_tls_expansion, host_teb32->TlsExpansionSlots,               3 },
            { "FlsSlots",       old_fls_slots,     host_teb32->FlsSlots,                        4 },
            { "WOW32Reserved",  wow32_reserved,    host_teb32->WOW32Reserved,                   5 },
            { "ActctxPtr",      0,                 host_teb32->ActivationContextStackPointer,   6 },
            { "SubSystemTib",   subsystem_tib,     host_teb32->Tib.SubSystemTib,                7 },
        };
        unsigned int k;

        for (k = 0; k < sizeof(sverka)/sizeof(sverka[0]); k++)
        {
            HB_PROBE_LOOKED(&pr_teb32_raskhozhdenie);
            if (sverka[k].n == 6) continue;                  /* ставится ниже, сверять рано */
            if (!sverka[k].гость) continue;                  /* гость не задавал — нечего сверять */
            if (sverka[k].гость == sverka[k].хозяин) continue;
            /* Голова цепочки SEH живёт и меняется между двумя замерами, поэтому простое
             * несовпадение здесь — не дефект. Дефект — когда у хозяина ПУСТО
             * (0 или ffffffff, «обработчиков нет»), а у гостя цепочка есть. */
            if (sverka[k].n == 0 && sverka[k].хозяин && sverka[k].хозяин != 0xffffffff)
                continue;
            if (skazano[sverka[k].n]++) continue;
            HB_PROBE_HIT(&pr_teb32_raskhozhdenie);
            fprintf( stderr, "macrunner-teb32-расхождение: поле=%s гость=%08x хозяин=%08x\n",
                     sverka[k].имя, sverka[k].гость, sverka[k].хозяин );
            fflush( stderr );
        }
    }

    actctx_stack = teb32_guest_base + TEB32_ACTCTX_STACK;
    actctx_list = teb32_guest_base + TEB32_ACTCTX_LIST;
    if (preserve_actctx_stack)
        memcpy( (uint8_t *)guest + TEB32_ACTCTX_STACK, &old_actctx_stack, sizeof(old_actctx_stack) );
    memcpy( (uint8_t *)guest + TEB32_ACTCTX_PTR, &actctx_stack, sizeof(actctx_stack) );

    memcpy( &old_flink, (uint8_t *)guest + TEB32_ACTCTX_LIST, sizeof(old_flink) );
    memcpy( &old_blink, (uint8_t *)guest + TEB32_ACTCTX_LIST + sizeof(old_flink), sizeof(old_blink) );
    if (!old_flink || (old_flink >= host_teb32_low && old_flink < host_teb32_low + ctx->teb32_size))
        memcpy( (uint8_t *)guest + TEB32_ACTCTX_LIST, &actctx_list, sizeof(actctx_list) );
    if (!old_blink || (old_blink >= host_teb32_low && old_blink < host_teb32_low + ctx->teb32_size))
        memcpy( (uint8_t *)guest + TEB32_ACTCTX_LIST + sizeof(old_flink), &actctx_list, sizeof(actctx_list) );

    teb32_guest_initialized = TRUE;
    ctx->fs_base = teb32_guest_base;
    return STATUS_SUCCESS;
}

static NTSTATUS sync_teb32_from_guest( const struct xtajit_i386_context *ctx )
{
    enum
    {
        TEB32_EXCEPTION_LIST = 0x00,
        TEB32_LAST_ERROR     = 0x34,
    };
    uint32_t exception_list, last_error;

    if (!ctx || !teb32_guest_base || !ctx->teb32_host) return STATUS_SUCCESS;
    if (hb_memory_read( process.memory, teb32_guest_base + TEB32_EXCEPTION_LIST, &exception_list,
                        sizeof(exception_list) ) != HB_OK)
        return STATUS_SUCCESS;
    /*
     * Keep the 32-bit SEH chain in the mirrored guest TEB.  Mirroring guest
     * handlers back into the native TEB makes ARM64 RtlUnwindEx try to call
     * i386 handler addresses during WOW64 NtCallbackReturn.
     */
    (void)exception_list;
    if (hb_memory_read( process.memory, teb32_guest_base + TEB32_LAST_ERROR, &last_error,
                        sizeof(last_error) ) == HB_OK)
        memcpy( (uint8_t *)(uintptr_t)ctx->teb32_host + TEB32_LAST_ERROR,
                &last_error, sizeof(last_error) );
    return STATUS_SUCCESS;
}

static void import_context( hb_wow64_i386_context_t *dst, const struct xtajit_i386_context *src )
{
    memset( dst, 0, sizeof(*dst) );
    dst->size = sizeof(*dst);
    dst->version = HB_WOW64CPU_ABI_VERSION;
    dst->eax = src->eax;
    dst->ebx = src->ebx;
    dst->ecx = src->ecx;
    dst->edx = src->edx;
    dst->esi = src->esi;
    dst->edi = src->edi;
    dst->esp = src->esp;
    dst->ebp = src->ebp;
    dst->eip = src->eip;
    dst->eflags = src->eflags;
    dst->fs_base = src->fs_base;
    dst->gs_base = src->gs_base;
    dst->seg_cs = src->seg_cs;
    dst->seg_ds = src->seg_ds;
    dst->seg_es = src->seg_es;
    dst->seg_fs = src->seg_fs;
    dst->seg_gs = src->seg_gs;
    dst->seg_ss = src->seg_ss;
    {
        /* ★★★ 2026-08-29, лейн УСТАНОВЩИКИ — МУСОР В СОСТОЯНИИ x87 ИЗ ГОСТЕВОГО КОНТЕКСТА.
         *
         * Замер зондом `macrunner-hb-x87-overflow` на установщике Diablo дал:
         *     top=0 tag=0x000b cw=0xf5bc sw=0xf5b8 im=0 pushes=323 pops=322
         * Баланс PUSH/POP равен ЕДИНИЦЕ — стек не течёт. А `cw=0xf5bc` управляющим
         * словом быть не может: у настоящего биты 13-15 нулевые (умолчание 0x037F,
         * Delphi ставит 0x1332). 0xf5bc и 0xf5b8 — это младшие 16 бит СТЕКОВЫХ адресов
         * 0x0143f5bc и 0x0143f5b8 (в том же прогоне esp=0143f7ec), усечённые полем
         * `WORD x87_cw` (xtajit_private.h:54) из DWORD `FloatSave.ControlWord`.
         *
         * Следствия: tag говорит «слоты заняты» -> следующий FILD видит переполнение;
         * im=0 -> маскированный путь hb_x87_push_f64 не применяется -> EXEC_FAULT ->
         * c0000001 -> обработчика нет -> смерть. По дороге неверная арифметика x87
         * портит вычисление длин строк у Delphi. */
        WORD cw = src->x87_cw, sw = src->x87_sw, tw = src->x87_tw;
        int bad = (cw & 0xe000u) != 0;
        if (bad) {
            static unsigned long long x87ctx_bad_n;
            static int probe = -1, sanitize = -1;
            if (probe < 0) probe = hb_env_flag("MACRUNNER_HB_X87CTX_PROBE", 0);
            if (sanitize < 0) sanitize = hb_env_flag("MACRUNNER_HB_X87CTX_SANITIZE", 0);
            if (probe && ++x87ctx_bad_n <= 8)
                fprintf(stderr, "macrunner-hb-x87ctx-bad: n=%llu cw=0x%04x sw=0x%04x tw=0x%04x\n",
                        x87ctx_bad_n, (unsigned)cw, (unsigned)sw, (unsigned)tw);
            if (sanitize) { cw = 0; sw = 0; tw = 0; }
        }
        dst->x87.control_word = cw ? cw : 0x037f;
        dst->x87.status_word = sw;
        dst->x87.tag_word = tw ? tw : 0xffff;
    }
}

static void export_context( struct xtajit_i386_context *dst, const hb_wow64_i386_context_t *src )
{
    dst->eax = src->eax;
    dst->ebx = src->ebx;
    dst->ecx = src->ecx;
    dst->edx = src->edx;
    dst->esi = src->esi;
    dst->edi = src->edi;
    dst->esp = src->esp;
    dst->ebp = src->ebp;
    dst->eip = src->eip;
    dst->eflags = src->eflags;
    dst->fs_base = src->fs_base;
    dst->gs_base = src->gs_base;
    dst->seg_cs = src->seg_cs;
    dst->seg_ds = src->seg_ds;
    dst->seg_es = src->seg_es;
    dst->seg_fs = src->seg_fs;
    dst->seg_gs = src->seg_gs;
    dst->seg_ss = src->seg_ss;
    dst->x87_cw = src->x87.control_word;
    dst->x87_sw = src->x87.status_word;
    dst->x87_tw = src->x87.tag_word;
}

/* Walk the guest32 VA range via mach_vm_region and register any already-mapped pages.
 * load_wow64_ntdll runs before xtajit initialises, so those mappings never go through
 * unix_notify_map_view_impl; HyperBridge doesn't know they're executable. */
/* ★★★★★★ MacRunner 2026-09-02 — ЗАПОЛНЕНИЕ ПРОБЕЛОВ КАРТЫ ПРИ ПЕРЕКРЫТИИ.
 * Гейт снят 02.09.2026: лечение доказано замером, выключенная ветка
 * возвращала известный дефект. Правка безусловна (scripts/гейты.py).
 * применения ниже. Счётчик — чтобы «пробелов 0» отличалось от «сюда не заходили». */
/* ★★★ 06.09.2026, лейн ПРИБОРЫ-3 — ВОСЕМЬ РАЗНЫХ ЯВЛЕНИЙ ПОД ОДНИМ ИМЕНЕМ.
 *
 * Все печати ниже носили ОДНУ метку `macrunner-xtajit-unix:` и восемь разных потолков
 * («первые 8», «первые 6»). Кто считает строки этого маркера — а его считает
 * `scripts/lane-c-real-software-matrix.sh:164` и на него ссылаются инварианты лестницы —
 * складывает восемь несравнимых выборок в одно число. Плюс общий для всех дефект:
 * после выбранного потолка прибор молчит, и «больше не было» неотличимо от «дальше не
 * печатаю».
 *
 * ИМЕНА НАЧИНАЮТСЯ С `xtajit-unix-` НАМЕРЕННО: метка остаётся
 * `macrunner-xtajit-unix-…`, прежний поиск подстроки продолжает находить ВСЕ строки,
 * и ни один потребитель не теряет половину при разведении.
 *
 * Точные итоги (без потолка) печатает перепись на выходе процесса, строкой
 * `macrunner-probe: name=… looked=… hits=…` вместе с образом по ответу dladdr. */
#include "hb_probe.h"

HB_PROBE_DEFINE(pr_x32_vhod, "xtajit-unix-восполнение-вход",
                "ВХОДЫ в xtajit_rescan_guest32_kind (запрос «достроить карту guest32 под "
                "этот адрес»): looked — все входы, БЕЗ оглядки на гейт lazy_rescan и на "
                "наличие process.memory; hits — входы, дошедшие до тела. looked>0 при "
                "hits=0 означает, что восполнение ВЫКЛЮЧЕНО, а не что его не просили",
                "MACRUNNER_XTAJIT_LAZY_RESCAN", 6);
HB_PROBE_DEFINE(pr_x32_vospolnyayu, "xtajit-unix-восполняю-карту",
                "случаи, когда карта guest32 действительно пересканируется (адрес "
                "недоступен, пара «адрес+поколение» не совпала, лимит сканов не выбран). "
                "Входы, отсечённые совпадением пары или лимитом, сюда НЕ попадают — их "
                "считает xtajit-unix-восполнение-вход",
                NULL, 8);
HB_PROBE_DEFINE(pr_x32_probel, "xtajit-unix-восполнение-пробел",
                "пробелы карты guest32, о которых движку СООБЩЕНО через "
                "hb_wow64cpu_notify_memory_alloc при переписи существующих отображений "
                "(register_preexisting_guest32_mappings). looked — вызовы самой переписи, "
                "hits — сообщённые пробелы. НЕ считает пробелы, найденные map_guest_range: "
                "их считает xtajit-unix-выделение-пробел",
                NULL, 8);
HB_PROBE_DEFINE(pr_x32_vydelenie, "xtajit-unix-выделение-пробел",
                "пробелы карты guest32, закрытые через hb_memory_guest32_map при "
                "отображении диапазона (map_guest_range). looked — вызовы map_guest_range, "
                "hits — закрытые пробелы. Это ДРУГАЯ выборка, чем "
                "xtajit-unix-восполнение-пробел; складывать их числа нельзя",
                NULL, 8);
HB_PROBE_DEFINE(pr_x32_base, "xtajit-unix-base-publish",
                "заводы потока, где ВЕРХНЯЯ половина guest32_base в слоте TLS разошлась с "
                "настоящей и была исправлена. looked — все заводы потока, дошедшие до "
                "проверки; hits — те, где расхождение НАЙДЕНО. Ноль при looked>0 значит "
                "«слот был верен», а не «проверка не работала»",
                NULL, 8);
HB_PROBE_DEFINE(pr_x32_povtor_dannye, "xtajit-unix-повтор-данные",
                "разборы отказа памяти, случившегося ДО первого выполненного шага "
                "(steps=0, blocks=0) — разбор печатает, что именно оказалось недоступно. "
                "looked — вызовы моделирования, hits — такие отказы",
                NULL, 8);
HB_PROBE_DEFINE(pr_x32_povtor, "xtajit-unix-повтор-после-восполнения",
                "ПОВТОРНЫЕ запуски моделирования: отказ памяти на нулевом шаге, после "
                "восполнения адрес стал исполнимым. looked — вызовы моделирования, hits — "
                "состоявшиеся повторы. Отказы, где восполнение НЕ помогло, сюда не входят",
                NULL, 8);

static int notify_gaps_enabled( void )
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = hb_env( "MACRUNNER_XTAJIT_NOTIFY_GAPS" );
        cached = (v && *v && *v != '0') ? 1 : 0;   /* умолчание ВЫКЛ: не доказано */
    }
    return cached;
}

static LONG refill_gaps_total;      /* добавлено областей-пробелов за процесс */
static LONG refill_gaps_overlaps;   /* сколько раз ядро отдало область поверх известной */

static void register_preexisting_guest32_mappings(void)
{
    HB_PROBE_LOOKED( &pr_x32_probel );   /* наблюдение начинается ЗДЕСЬ, не в цикле */
#ifdef __APPLE__
    uint8_t *const g32_host = (uint8_t *)hb_memory_guest32_base( process.memory );
    mach_vm_address_t addr = (mach_vm_address_t)(uintptr_t)g32_host;
    const mach_vm_address_t g32_end = addr + 0x100000000ULL;

    fprintf( stderr, "macrunner-xtajit-unix: [pid=%d] preexist-scan g32_host=%p\n",
             (int)getpid(), (void *)g32_host );
    fflush( stderr );

    while (addr < g32_end)
    {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t rinfo;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        hb_perm_t perm;
        hb_result_t result;
        uint32_t guest_base;

        if (mach_vm_region( mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&rinfo, &count, &obj ) != KERN_SUCCESS || !size)
            break;
        if (addr >= g32_end || addr < (mach_vm_address_t)(uintptr_t)g32_host) { addr += size; continue; }

        /* Skip PROT_NONE regions (the HyperBridge 4GB base reservation itself). */
        if (rinfo.protection == VM_PROT_NONE) { addr += size; continue; }

        guest_base = (uint32_t)(addr - (mach_vm_address_t)(uintptr_t)g32_host);
        perm = HB_PERM_NONE;
        if (rinfo.protection & VM_PROT_READ)    perm = (hb_perm_t)(perm | HB_PERM_READ);
        if (rinfo.protection & VM_PROT_WRITE)   perm = (hb_perm_t)(perm | HB_PERM_WRITE);
        if (rinfo.protection & VM_PROT_EXECUTE) perm = (hb_perm_t)(perm | HB_PERM_EXEC);

        result = hb_wow64cpu_notify_memory_alloc( &process, guest_base, (size_t)size, perm );
        if (result == HB_ERR_INVALID_ARG)
        {
            /* Already registered. Only call protect when mach shows EXEC (perm & HB_PERM_EXEC):
             * this can only ADD the EXEC bit to the existing HB region — needed for ntdll32
             * which is aliased with VM_PROT_EXECUTE but may have been registered without it.
             * When perm lacks EXEC (mach_prot=PROT_READ because prot_from_perm maps
             * HB_PERM_EXEC→PROT_READ for guest32), do NOT protect — that would strip
             * HB_PERM_EXEC from regions whose execute rights are correctly tracked in HB. */
            if (perm & HB_PERM_EXEC)
                result = hb_memory_guest32_protect( process.memory, guest_base, (size_t)size, perm );
        }
        /* ★★★★★★ MacRunner 2026-09-02 — ПЕРЕКРЫТИЕ ≠ «УЖЕ ЗАРЕГИСТРИРОВАНО»: ЗАПОЛНИТЬ ПРОБЕЛЫ.
         *
         * `hb_memory_guest32_map` отвергает ЛЮБОЕ перекрытие (`any_overlap` → INVALID_ARG), а
         * откат выше есть только для EXEC. Когда куча гостя дорастает соседними страницами,
         * ядро отдаёт ОДНУ область поверх уже известных 64 КБ — и восполнение для ДАННЫХ не
         * делало НИЧЕГО. Замер (Half-Life): запись 2 байт по 0x6f90636 при карте
         * 06f10000-06f20000, страница в ядре MEM_COMMIT RW, входов в восполнение 0 из 11 —
         * а если бы и вошло, карта не выросла бы.
         *
         * Здесь диапазон ядра обходится ПО КАРТЕ: известные куски пропускаются, неизвестные
         * регистрируются как есть (права — ядра). Права известных кусков НЕ трогаем: сужение
         * сломало бы учёт W^X, расширение здесь не измерено. Шаг поиска границы пробела —
         * страница гостя (4 КБ): области карты выровнены по ней. Путь холодный. */
        if (result == HB_ERR_INVALID_ARG && !(perm & HB_PERM_EXEC))
        {
            uint64_t cur = guest_base, end = (uint64_t)guest_base + (uint64_t)size;
            unsigned int dobavleno = 0;
            static LONG skazano_probely;

            __atomic_fetch_add( &refill_gaps_overlaps, 1, __ATOMIC_SEQ_CST );
            while (cur < end)
            {
                hb_region_t *r = hb_memory_find_region( process.memory, (hb_gva_t)cur );
                uint64_t stop;

                if (r)
                {
                    stop = (uint64_t)r->base + (uint64_t)r->size;
                    if (stop <= cur) stop = cur + 0x1000;            /* страховка от нулевого шага */
                }
                else
                {
                    hb_result_t rr;

                    stop = cur + 0x1000;
                    while (stop < end && !hb_memory_find_region( process.memory, (hb_gva_t)stop )) stop += 0x1000;
                    rr = hb_wow64cpu_notify_memory_alloc( &process, (uint32_t)cur, (size_t)(stop - cur), perm );
                    if (rr == HB_OK) dobavleno++;
                    (void)skazano_probely;
                    HB_PROBE_SAY( &pr_x32_probel,
                                  "[pid=%d] guest32=%08x..%08x перм=%d результат=%d\n",
                                  (int)getpid(), (uint32_t)cur, (uint32_t)stop, (int)perm, (int)rr );
                    fflush( stderr );
                }
                cur = stop;
            }
            if (dobavleno)
            {
                result = HB_OK;
                __atomic_fetch_add( &refill_gaps_total, (LONG)dobavleno, __ATOMIC_SEQ_CST );
            }
        }
        fprintf( stderr, "macrunner-xtajit-unix: [pid=%d] preexist guest32=%08x size=%lx perm=%d mach_prot=%x result=%d\n",
                 (int)getpid(), guest_base, (unsigned long)size, (int)perm, (int)rinfo.protection, (int)result );
        fflush( stderr );

        addr += size;
    }
#endif
}

/* ★★★★★ MacRunner 2026-08-28 — ВОСПОЛНЕНИЕ КАРТЫ ПО НУЖДЕ.
 *
 * `register_preexisting_guest32_mappings` зовётся из `unix_process_init_impl`, то
 * есть ОДИН раз на процесс. Но у Diablo процессов несколько (`Diablo.exe` —
 * лаунчер, порождающий второго), и замер показал: 4 процесса, 2 досканирования.
 * В процессе без него карта движка почти пуста, и любое обращение к коду модуля
 * отвечает `host=0x0 can_x=0` — отсюда `unable to fetch executable i386 code`,
 * `steps=0 blocks=0` и гибель на доставке исключения.
 *
 * Звать досканирование «почаще» — лечение симптома: неизвестно, сколько ещё точек
 * входа появится. Правильнее восполнять карту ТАМ, ГДЕ ОНА ПОДВЕЛА: если движок
 * не нашёл исполняемого кода по гостевому адресу, один раз пересканировать окно и
 * дать ему вторую попытку. Промах такого рода редок (после правки — один на
 * прогон), поэтому цена ничтожна, а поведение становится самовосстанавливающимся:
 * какой бы путь ни привёл к новому процессу, первая же нужда карту достроит.
 *
 * Гейт `MACRUNNER_XTAJIT_NO_LAZY_RESCAN=1` выключает восполнение. */
static int lazy_rescan_disabled( void )
{
    static int cached = -1;
    if (cached < 0)
    {
        /* hb_env, а НЕ getenv: getenv берёт замок libsystem и не является
         * async-signal-safe — на этом уже гибли три процесса (память
         * getenv-v-goryachem-puti-ronyal-tri-protsessa). */
        const char *v = hb_env( "MACRUNNER_XTAJIT_NO_LAZY_RESCAN" );
        cached = (v && *v && *v != '0') ? 1 : 0;
    }
    return cached;
}

/* ★★★★★★ MacRunner 2026-08-29 — ВОСПОЛНЕНИЕ ДЛЯ ЧТЕНИЯ/ЗАПИСИ, НЕ ТОЛЬКО ДЛЯ КОДА.
 *
 * Прежняя проверка спрашивала ТОЛЬКО can_exec: восполнение работало для выборки
 * команды и молчало для обращения к данным. Замер Diablo 29.08 (reports/lanes/diablo/180):
 *
 *   helper-fault-addr: guest_addr=0x7bd9a99d size=1 READ pc=0x7bd5c81f
 *   ИНВАРИАНТ: адрес=0x7bd9a99d | регион=НЕТ | can_read=0 can_exec=0 | host=0x0
 *   simulate ... steps=1094 blocks=226 ... status=c0000005
 *
 * И код (0x7bd5c81f), и данные (0x7bd9a99d) лежат в НЕОТОБРАЖЁННОЙ у нас области —
 * при том, что код оттуда ИСПОЛНЯЕТСЯ, то есть у ядра память есть. Гость получал
 * c0000005 на законном чтении собственного ntdll.
 *
 * kind: 0 — нужен код, 1 — нужны данные. */
/* ★★★★★★ MacRunner 2026-08-29 — ВЫБОР ИСПОЛНИТЕЛЯ ДЛЯ СВЕРКИ.
 *
 * Установщик Diablo (InnoSetup) строит имя файла КОДОМ и получает
 * `D:\windows\systdm32\thell320dll.dll` вместо `C:\windows\system32\shell32.dll`.
 * Байты показывают корректный UTF-16 и ровно четыре одиночных сдвига (C→D, e→d, s→t,
 * .→0), то есть строка не повреждена в памяти, а ВЫЧИСЛЕНА неверно.
 *
 * Отличить дефект вычислений в JIT от дефекта в другом месте можно только одним
 * способом: прогнать ТУ ЖЕ задачу другим исполнителем. Движок был прибит гвоздями к
 * HB_BACKEND_JIT, и сверка была невозможна.
 *
 * MACRUNNER_XTAJIT_BACKEND=interp — интерпретатор, =jit (умолчание) — прежнее поведение.
 * Интерпретатор много медленнее, поэтому это средство СВЕРКИ, а не работы. */
static int xtajit_backend( void )
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = hb_env( "MACRUNNER_XTAJIT_BACKEND" );
        cached = (v && (v[0] == 'i' || v[0] == 'I')) ? HB_BACKEND_INTERP : HB_BACKEND_JIT;
        fprintf( stderr, "macrunner-xtajit-unix: [pid=%d] исполнитель=%s\n",
                 (int)getpid(), cached == HB_BACKEND_INTERP ? "ИНТЕРПРЕТАТОР" : "JIT" );
        fflush( stderr );
    }
    return cached;
}

void xtajit_rescan_guest32_kind( uint32_t guest_addr, int kind )
{
    static LONG said;
    /* Прежде здесь стоял счётчик «не более 8 восполнений за процесс», после чего карта
     * не достраивалась НИКОГДА. Это тот же дефект, что уже ловили («досканирование раз
     * на процесс при четырёх»), лишь с порогом 8.
     *
     * Защёлка по ОДНОМУ поколению тоже неверна, и это видно замером: `hb_memory_generation`
     * растёт ТОЛЬКО на изменениях EXEC (bump_generation зовётся под `perm & HB_PERM_EXEC`).
     * Восполнение, добавившее области с правом READ, поколения не двигает — и следующий
     * промах ЧТЕНИЯ был бы отсечён навсегда. Замер 29.08: helper_fault=2, восполнений=1.
     *
     * Держим пару (АДРЕС, поколение): другой адрес получает свою попытку всегда, тот же
     * адрес при неизменившейся карте — не повторяем (даст то же самое). Зацикливания нет:
     * повтор для одного адреса возможен лишь после настоящего изменения карты. */
    static uint32_t last_addr = 0;
    static uint64_t last_gen = ~(uint64_t)0;
    static LONG scans;
    uint64_t gen;

    /* ★ 06.09.2026 — учёт СТОИТ ВЫШЕ ОБОИХ ВОЗВРАТОВ. Замысел прибора («без него
     * восполнений 0 неотличимо от сюда не заходили») был верен, но сам счётчик стоял
     * НИЖЕ гейта lazy_rescan_disabled и проверки process.memory — то есть при
     * выключенном восполнении молчал вместе с ними, и ровно та неотличимость,
     * от которой он ставился, оставалась на месте. */
    HB_PROBE_LOOKED( &pr_x32_vhod );
    if (lazy_rescan_disabled()) return;
    if (!process.memory) return;
    {
        static LONG vhodov;

        (void)vhodov;
        HB_PROBE_SAY( &pr_x32_vhod, "адрес=%08x вид=%s "
                      "can_r=%u can_w=%u can_x=%u gen=%llu\n",
                      guest_addr, kind ? "ДАННЫЕ" : "КОД",
                      hb_memory_can_read( process.memory, guest_addr, 1 ),
                      hb_memory_can_write( process.memory, guest_addr, 1 ),
                      hb_memory_can_exec( process.memory, guest_addr, 1 ),
                      (unsigned long long)hb_memory_generation( process.memory ) );
        fflush( stderr );
    }
    /* ★★★★★★ MacRunner 2026-09-02 — ДЛЯ ДАННЫХ СПРАШИВАТЬ И ЗАПИСЬ, НЕ ТОЛЬКО ЧТЕНИЕ.
     *
     * Прежнее условие для данных проверяло ТОЛЬКО can_read. Страница, которая в карте
     * есть на чтение, но не на запись, объявлялась «карта в порядке», и восполнение
     * не звалось НИКОГДА — а отказ у нас именно на записи.
     *
     * Замер (Half-Life, 4 прогона из 4, числа совпадают):
     *   отказ ЗАПИСИ в ntdll32 `heap_allocate_block+0x1e4` (зовут RtlAllocateHeap+0x4e0)
     *   edi=06f10000 (арена)  ecx=00080570  ebx=edi+ecx=06f90570 — куда пишут
     *   система: страница по edi+0x80000 ВЫДЕЛЕНА и доступна на запись (MEM_COMMIT, RW)
     *   переводчик: region=06f10000-06f20000 — у него арена всего 64 КБ
     * То есть куча выросла, хозяин страницы выделил, а карта гостя осталась прежней.
     *
     * Гейт снят 02.09.2026: лечение доказано замером, выключенная ветка
     * возвращала известный дефект. Правка безусловна (scripts/гейты.py). */
    {
        if (kind)
        {
            if (hb_memory_can_read( process.memory, guest_addr, 1 ) &&
                hb_memory_can_write( process.memory, guest_addr, 1 ))
                return;                                        /* карта в порядке */
        }
        else if (hb_memory_can_exec( process.memory, guest_addr, 1 )) return;
    }
    gen = hb_memory_generation( process.memory );
    if (guest_addr == last_addr && gen == last_gen) return;
    last_addr = guest_addr;
    last_gen = gen;
    /* Верхний предел — только страховка от патологии, и он НЕ МОЛЧАЛИВЫЙ: достижение
     * предела печатается, иначе «восполнений 0» читалось бы как «промахов не было». */
    if (__atomic_fetch_add( &scans, 1, __ATOMIC_SEQ_CST ) >= 4096)
    {
        static LONG said_cap;
        if (!said_cap++)
        {
            fprintf( stderr, "macrunner-xtajit-unix: ВОСПОЛНЕНИЕ ОСТАНОВЛЕНО — 4096 сканов, "
                             "дальше карта НЕ достраивается (адрес %08x)\n", guest_addr );
            fflush( stderr );
        }
        return;
    }

    HB_PROBE_LOOKED( &pr_x32_vospolnyayu );
    said++;
    HB_PROBE_SAY( &pr_x32_vospolnyayu,
                  "[pid=%d] ВОСПОЛНЯЮ карту — адрес %08x недоступен на %s, пересканирую окно\n",
                  (int)getpid(), guest_addr, kind ? "ЧТЕНИЕ" : "ИСПОЛНЕНИЕ" );
    fflush( stderr );
    register_preexisting_guest32_mappings();
    if (said <= 8)
    {
        fprintf( stderr, "macrunner-xtajit-unix: после восполнения адрес %08x can_x=%u can_r=%u can_w=%u "
                 "пробелов_добавлено=%ld перекрытий=%ld\n",
                 guest_addr, hb_memory_can_exec( process.memory, guest_addr, 1 ),
                 hb_memory_can_read( process.memory, guest_addr, 1 ),
                 hb_memory_can_write( process.memory, guest_addr, 1 ),
                 (long)refill_gaps_total, (long)refill_gaps_overlaps );
        fflush( stderr );
    }
}

void xtajit_rescan_guest32_if_needed( uint32_t guest_addr )
{
    xtajit_rescan_guest32_kind( guest_addr, 0 );
}

static NTSTATUS unix_process_init_impl( void *args )
{
    NTSTATUS status = ensure_process();
    if (!status) register_preexisting_guest32_mappings();
    return status;
}

/* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1225 — ПУБЛИКАЦИЯ НАСТОЯЩЕЙ БАЗЫ ЗЕРКАЛА.
 *
 * Замер (итерация 1224). 32-битный ребёнок, порождённый 64-битным процессом, падал по
 * `c0000005` при записи начального `I386_CONTEXT` на гостевой стек (`wow64/syscall.c:1098`).
 * Причина — база зеркала guest32 выводилась маской из адреса TEB32
 * (`wow64/syscall.c:1074`: `NtCurrentTeb32() & ~0xffffffff`). Числа прогона:
 *
 *     настоящая база (эта сторона)  g32_host = 0xd00000000
 *     выведенная из TEB32                     0x7ff00000000
 *     адрес отказа                            0x7ff0141fd24
 *     правильный адрес                        0x000d0141fd24
 *
 * Вывод из TEB32 верен ТОЛЬКО когда TEB32 лежит внутри зеркала. При прямом запуске 32-битной
 * программы это так, и приём работает случайно; у ребёнка 64-битного процесса TEB32 лежит в
 * хозяйской области, и маска даёт правдоподобное чужое число.
 *
 * Настоящую базу знает ровно эта сторона — она её и создаёт. Публикуем в тот слот TLS, из
 * которого её читают ОБЕ стороны (`wow64/wow64_private.h:44` и `xtajit/cpu.c:41` — слот один и
 * тот же, `WOW64_TLS_MAX_NUMBER - 1`). Вызов идёт из `BTCpuThreadInit`, то есть ДО того, как
 * `wow64.dll` начнёт переводить гостевые адреса.
 *
 * Правка ИНЕРТНА там, где всё работает: при совпадении баз слот получает то же значение, и
 * печатается только расхождение — первые 8 раз. */
static NTSTATUS unix_thread_init_impl( void *args )
{
    NTSTATUS status = ensure_thread();
    TEB *teb;

    if (status || !process_ready) return status;

    if ((teb = NtCurrentTeb()))
    {
        void *real = hb_memory_guest32_base( process.memory );

        if (real)
        {
            ULONG_PTR was = (ULONG_PTR)teb->TlsSlots[XTAJIT_WOW64_TLS_GUEST32_BASE];

            HB_PROBE_LOOKED( &pr_x32_base );   /* проверка состоялась — независимо от исхода */
            if ((was & ~(ULONG_PTR)0xffffffff) != ((ULONG_PTR)real & ~(ULONG_PTR)0xffffffff))
            {
                HB_PROBE_SAY( &pr_x32_base, "n=%u было=%p стало=%p\n",
                              (unsigned)pr_x32_base.hits, (void *)was, real );
                fflush( stderr );
            }
            teb->TlsSlots[XTAJIT_WOW64_TLS_GUEST32_BASE] = real;
        }
    }
    return status;
}

static NTSTATUS unix_thread_term_impl( void *args )
{
    if (thread_ready) hb_wow64cpu_thread_destroy( &thread );
    memset( &thread, 0, sizeof(thread) );
    thread.size = sizeof(thread);
    thread_ready = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS unix_process_term_impl( void *args )
{
    pthread_mutex_lock( &process_mutex );
    if (process_ready) hb_wow64cpu_process_destroy( &process );
    memset( &process, 0, sizeof(process) );
    process.size = sizeof(process);
    process_ready = FALSE;
    pthread_mutex_unlock( &process_mutex );
    return STATUS_SUCCESS;
}

static NTSTATUS unix_simulate_impl( void *args )
{
    /* Наблюдение обоих приборов повтора начинается ЗДЕСЬ: «моделирование звали столько-то
     * раз» — тот знаменатель, без которого ноль повторов не читается. */
    struct xtajit_simulate_params *params = args;
    hb_wow64_i386_context_t in, out;
    hb_exec_result_t exec;
    hb_result_t result;
    NTSTATUS status;
    BOOL trace_all = getenv( "MACRUNNER_XTAJIT_TRACE_ALL_SIMULATE" ) != NULL;

    HB_PROBE_LOOKED( &pr_x32_povtor_dannye );
    HB_PROBE_LOOKED( &pr_x32_povtor );

    if (!params) return STATUS_INVALID_PARAMETER;

    /* Редкий перевзвод аппаратного сторожа (MACRUNNER_HB_WATCH_EVERY=N). Вешаем на
     * UNIX-сторону: PE-часть (cpu.c) unix-символ вызвать не может — ld.lld даёт
     * «undefined symbol». Вхолостую — одна проверка и возврат. */
    { extern void macrunner_hb_watch_tick( void ); macrunner_hb_watch_tick(); }

    if (trace_all)
    {
        fprintf( stderr, "macrunner-xtajit-unix: phase=enter eip=%08x esp=%08x teb32_host=%llx teb32_size=%llu fs=%08x\n",
                 params->context.eip, params->context.esp,
                 (unsigned long long)params->context.teb32_host,
                 (unsigned long long)params->context.teb32_size,
                 params->context.fs_base );
        fflush( stderr );
    }
    if ((status = ensure_thread())) return status;
    if (trace_all)
    {
        fprintf( stderr, "macrunner-xtajit-unix: phase=after-ensure-thread eip=%08x esp=%08x\n",
                 params->context.eip, params->context.esp );
        fflush( stderr );
    }
    if ((status = sync_teb32_to_guest( &params->context ))) return status;
    if (trace_all)
    {
        fprintf( stderr, "macrunner-xtajit-unix: phase=after-sync-teb eip=%08x esp=%08x fs=%08x\n",
                 params->context.eip, params->context.esp, params->context.fs_base );
        fflush( stderr );
    }

    import_context( &in, &params->context );
    if (trace_all)
    {
        fprintf( stderr, "macrunner-xtajit-unix: phase=after-import eip=%08x esp=%08x fs=%08x\n",
                 in.eip, in.esp, in.fs_base );
        fflush( stderr );
    }
    trace_native_stack( "unix-simulate-enter", &in, NULL, HB_OK, STATUS_SUCCESS );
    if ((result = hb_wow64cpu_import_i386_context( &thread, &in )) != HB_OK)
        return status_from_hb( result );
    if (trace_all)
    {
        fprintf( stderr, "macrunner-xtajit-unix: phase=after-hb-import eip=%08x esp=%08x\n",
                 in.eip, in.esp );
        fflush( stderr );
    }

    /* 2026-09-02: поле диагностическое; обнуляем, чтобы после отказа знать, что адрес
     * помощника поставлен ЭТОЙ симуляцией (см. ПОВТОР-ДАННЫЕ ниже). */
    if (thread.ctx) thread.ctx->last_helper_guest = 0;
    memset( &exec, 0, sizeof(exec) );

    /* MacRunner: sentinel pre-sim enforce.
     * ntdll32 heap init writes 0xFFEEFFEE to heap_limit+8 = 0x7BD8E008 (in ntdll32 .text).
     * Something between sims strips WRITE from that page without going through our WoW64 hooks.
     * Force PROT_READ|PROT_WRITE + HB perm=RW|EXEC for the sentinel page before every JIT run. */
#ifdef __APPLE__
    if (process.memory && process.memory->guest32_base)
    {
        static const uint32_t SENT_G32 = 0x7BD8E000u;
        mach_vm_address_t sent_host = (mach_vm_address_t)((uint8_t *)process.memory->guest32_base + SENT_G32);
        mach_vm_address_t region_addr = sent_host;
        mach_vm_size_t    region_sz   = 0;
        vm_region_basic_info_data_64_t vri;
        mach_msg_type_number_t vri_cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        hb_region_t *sent_rgn = hb_memory_find_region( process.memory, SENT_G32 + 8 );
        int hb_can_w = sent_rgn ? !!(sent_rgn->perm & HB_PERM_WRITE) : -1;

        memset( &vri, 0, sizeof(vri) );
        mach_vm_region( mach_task_self(), &region_addr, &region_sz, VM_REGION_BASIC_INFO_64,
                        (vm_region_info_t)&vri, &vri_cnt, &obj );
        if (obj != MACH_PORT_NULL) mach_port_deallocate( mach_task_self(), obj );

        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: печать за гейтом. Она безусловная и даёт
         * 35% всего журнала (41 708 строк из 118 833 на прогоне Diablo), а лейн перешёл к
         * ЗАМЕРАМ ВРЕМЕНИ, где собственная трасса — конфаунд первого порядка.
         * Гейт MACRUNNER_XTAJIT_TRACE_SIM, умолчание ВЫКЛ: это чистая диагностика,
         * поведения она не меняет. */
        if (macrunner_trace_sim_enabled())
        {
            fprintf( stderr, "macrunner-xtajit: pre-sim-sentinel mach_prot=0x%x max_prot=0x%x hb_perm=%d hb_can_w=%d eip=%08x eax=%08x\n",
                     vri.protection, vri.max_protection,
                     sent_rgn ? (int)sent_rgn->perm : -1, hb_can_w, in.eip, in.eax );
            fflush( stderr );
        }

        if (!(vri.protection & VM_PROT_WRITE) || hb_can_w != 1)
        {
            mach_vm_protect( mach_task_self(), sent_host, 0x1000u, FALSE,
                             VM_PROT_READ | VM_PROT_WRITE );
            hb_memory_guest32_protect( process.memory, SENT_G32, 0x1000u,
                                       (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC) );
            fprintf( stderr, "macrunner-xtajit: pre-sim-sentinel ENFORCED was_prot=0x%x hb_can_w=%d\n",
                     vri.protection, hb_can_w );
        }
    }
#endif

    if (trace_all)
    {
        {
            hb_region_t *eip_rgn = process.memory ? hb_memory_find_region( process.memory, in.eip ) : NULL;
            fprintf( stderr, "macrunner-xtajit-unix: phase=before-hb-sim eip=%08x esp=%08x max=%llu "
                     "can_exec=%d rgn=%s perm=%d\n",
                     in.eip, in.esp, (unsigned long long)params->max_code_bytes,
                     process.memory ? (int)hb_memory_can_exec( process.memory, in.eip, 1 ) : -1,
                     eip_rgn ? "found" : "null",
                     eip_rgn ? (int)eip_rgn->perm : -1 );
            fflush( stderr );
        }
    }
    result = hb_wow64cpu_simulate( &thread, xtajit_backend(),
                                   params->max_code_bytes ? params->max_code_bytes : 4096,
                                   &exec );

    /* ★★★★★ MacRunner 2026-08-28 — ВОСПОЛНИТЬ КАРТУ И ПОВТОРИТЬ.
     *
     * Отказ «не удалось получить исполняемый код i386» при `steps=0 blocks=0`
     * означает, что движок не нашёл КОДА по текущему eip. Замер показал, отчего
     * это бывает: досканирование окна (`register_preexisting_guest32_mappings`)
     * зовётся один раз на процесс, а процессов у Diablo несколько — 4 процесса
     * на 2 досканирования. В процессе без него карта почти пуста, и обращение к
     * `ntdll` отвечает `host=0x0 can_x=0`, хотя модуль отображён.
     *
     * Восполняем карту ровно там, где она подвела, и даём вторую попытку. Это не
     * обход: содержимое окна берётся у ядра (`mach_vm_region`), то есть карта
     * приводится в соответствие с действительностью. Повтор безопасен —
     * `steps=0` значит, что гость не сделал ни шага, состояние не менялось. */
    /* ★★★★★★ MacRunner 2026-08-29 — ВОСПОЛНЕНИЕ И ПОВТОР: ЭТО РАЗНЫЕ ДЕЙСТВИЯ.
     *
     * Прежде оба стояли под одним условием `steps==0 && blocks==0`, и потому карта
     * не достраивалась НИ РАЗУ, если гость успел сделать хоть шаг. Замер Diablo 29.08:
     * `steps=1094 blocks=226`, отказ на ЧТЕНИИ байта 0x7bd9a99d — восполнение не звалось,
     * гость получал c0000005 на законном обращении к собственному ntdll.
     *
     * Развожу:
     *   восполнить карту — БЕЗОПАСНО ВСЕГДА: это приведение нашей карты в соответствие
     *     с картой ядра (mach_vm_region), состояние гостя не трогается;
     *   повторить симуляцию — только при steps==0 && blocks==0, как и было.
     *
     * Восполняем по АДРЕСУ ОТКАЗА, а не по eip: правда об адресе лежит в
     * hb_memory_last_fault (память guest-was-told-read-at-zero-for-every-av). */
    /* ★★★★★★ MacRunner 2026-09-02 — КРЮЧОК ВИСЕЛ НЕ НА ТОМ ПУТИ.
     *
     * Условие `result == HB_ERR_MEMORY_FAULT` покрывает лишь случай, когда сам вызов
     * симуляции вернул отказ. Но нынешний путь иной: отказ памяти превращается в
     * ГОСТЕВОЕ ИСКЛЮЧЕНИЕ, симуляция возвращает УСПЕХ, и в записи стоит `faulted=1`.
     * Тогда восполнение не звалось НИ РАЗУ.
     *
     * Замер (Half-Life, 11 прогонов из 11): отказ есть в каждом, `last_result=-8`,
     * адрес годный — а входов в восполнение НОЛЬ. Отказ при этом законный:
     *   запись 2 байта по 0x6f90636 из ntdll32 heap_allocate_block+0x1e4
     *   система: страница ВЫДЕЛЕНА и доступна на запись (MEM_COMMIT, RW)
     *   переводчик: арена в карте всего 0x6f10000-0x6f20000 (64 КБ)
     * то есть куча выросла, а карта гостя осталась прежней.
     *
     * ★ УМОЛЧАНИЕ ВКЛЮЧЕНО, и вот на каком основании. Это починка МЁРТВОГО пути:
     * замер показал 0 входов в восполнение при 11 законных отказах памяти из 11
     * прогонов, а с переносом входов стало 17 против 5. Вреда замер не показал
     * (отказов 14 против 13 — шум). Но и пользы на числе отказов не видно, поэтому
     * называть это лечением отказа Half-Life нельзя: доказано лишь то, что крючок
     * теперь срабатывает там, где раньше не срабатывал никогда.
     * Гейт снят 02.09.2026: лечение доказано замером, выключенная ветка
     * возвращала известный дефект. Правка безусловна (scripts/гейты.py). */
    {
        if ((result == HB_ERR_MEMORY_FAULT || exec.faulted) && process.memory)
        {
            uint64_t fault_addr = 0;
            size_t fault_size = 0;
            int fault_write = 0, fault_valid = 0;

            hb_memory_last_fault( &fault_addr, &fault_size, &fault_write, &fault_valid );
            if (fault_valid && fault_addr && fault_addr < 0x100000000ull)
            {
                uint32_t ad = (uint32_t)fault_addr;

                xtajit_rescan_guest32_kind( ad, 1 );

            }
        }
    }

    /* ★★★★★★ MacRunner 2026-09-02 — ВОСПОЛНИТЬ И ПОВТОРИТЬ ОТКАЗАВШУЮ КОМАНДУ (ДАННЫЕ).
     *
     * Восполнения после отказа мало: гостю уже уходит c0000005, а обращение было законным —
     * страница выделена ядром, отстала наша карта. Как страничный отказ у железа: карту
     * привели в соответствие → команду повторить, гость исключения не видит.
     *
     * ПОЧЕМУ ПОВТОР БЕЗОПАСЕН ПРИ steps>0. Отказ помощника выходит из блока по
     * `emit_return_if_helper_failed` сразу после отказавшего помощника: команды блока ДО неё
     * исполнены и выгружены в ctx ровно один раз, сама отказавшая — не завершена (запись не
     * состоялась; hb_jit_helper_push двигает esp только при удачной записи). Но `ctx->pc`
     * при этом = НАЧАЛО БЛОКА (отсюда прежние «96 байт, чтобы дойти до отказавшей команды»),
     * и повтор с начала блока удвоил бы побочные эффекты. Точный адрес даёт
     * `ctx->last_helper_guest`: его ставит `hb_jit_helper_op_note` на входе в помощник с
     * `instr` — именно так идёт запись reg→[mem] при выключенном прямом пути
     * (hb_jit_helper_exec_store_operand_lazy). Поле обнулено перед симуляцией, и требуется:
     *   - оно поставлено ЭТОЙ симуляцией, лежит в текущем блоке и исполнимо;
     *   - причина отказа — «JIT helper fault» (при сигнале снимок откатывает блок к началу,
     *     и адрес помощника был бы устаревшим);
     *   - вид отказа обычный (не сторожевая страница — ей положено дойти до гостя);
     *   - ГЛАВНОЕ: после восполнения адрес отказа доступен на нужное действие (правда ядра).
     * Одна попытка на симуляцию — зацикливания нет.
     * Остаточный риск назван: помощники без `instr` (store_sized на прямом пути, push/pop)
     * поле не ставят — при MACRUNNER_HB_JIT_DIRECT_MEM=1 адрес мог бы быть от предыдущей
     * команды блока. Долговечное лекарство — писать точный pc в выходе-по-отказу
     * кодогенератора; это правка выпуска кода, здесь она не по адресу.
     * Гейт снят 02.09.2026: лечение доказано замером, выключенная ветка
     * возвращала известный дефект. Правка безусловна (scripts/гейты.py). */
    {
        if (exec.faulted && process.memory && thread.ctx &&
            (exec.result == HB_ERR_MEMORY_FAULT || result == HB_ERR_MEMORY_FAULT) &&
            exec.fault_reason && !strcmp( exec.fault_reason, "JIT helper fault" ) &&
            thread.ctx->last_fault_kind == HB_FAULT_KIND_NONE)
        {
            extern const char *hb_ir_op_name_public( int op );
            uint64_t fa = 0; size_t fs = 0; int fw = 0, fv = 0;
            uint32_t blok = thread.ctx->regs.x86.eip;
            uint64_t tochno = thread.ctx->last_helper_guest;
            unsigned int dostupno = 0, v_bloke, ispolnimo;
            static LONG skazano, povtorov, udach;

            hb_memory_last_fault( &fa, &fs, &fw, &fv );
            if (!fs) fs = 1;
            if (fv && fa && fa < 0x100000000ull)
                dostupno = fw ? hb_memory_can_write( process.memory, (uint32_t)fa, fs )
                              : hb_memory_can_read( process.memory, (uint32_t)fa, fs );
            v_bloke = (tochno >= blok && tochno < (uint64_t)blok + 4096);
            ispolnimo = tochno && tochno < 0x100000000ull &&
                        hb_memory_can_exec( process.memory, (uint32_t)tochno, 1 );
            skazano++;
            HB_PROBE_SAY( &pr_x32_povtor_dannye,
                          "разбор: отказ=%08llx %s размер=%zu годен=%d "
                          "доступно_после_восполнения=%u команда=%08llx блок=%08x в_блоке=%u исполнимо=%u "
                          "операция=%s steps=%llu blocks=%llu\n",
                          (unsigned long long)fa, fw ? "ЗАПИСЬ" : "ЧТЕНИЕ", fs, fv, dostupno,
                          (unsigned long long)tochno, blok, v_bloke, ispolnimo,
                          hb_ir_op_name_public( thread.ctx->last_helper_op ),
                          (unsigned long long)exec.steps_executed, (unsigned long long)exec.blocks_executed );
            fflush( stderr );
            /* ★ MacRunner 2026-09-02 — ВЕТО ПО can_exec СНЯТО. Diablo (omt-on-3): отказ чтения кучи в потоке CS
             * (glsl_blitter_args_compare, wined3d+0x62ce0), восполнение сделало адрес доступным
             * (доступно_после_восполнения=1, в_блоке=1, steps=68), но повтор не состоялся: исполнимо=0 —
             * hb_memory_can_exec(778f2cee) ответил «нет», хотя прибор рядом показал область
             * 77894000-77a58000 perm=5, СОДЕРЖАЩУЮ этот адрес (РЕГИОНА_НЕТ … справа=… ВЕРДИКТ=край):
             * поиск по дереву карты промахнулся мимо узла, чьи границы адрес накрывают. Точный адрес
             * берётся из last_helper_guest — из блока, который ТОЛЬКО ЧТО исполнялся, исполнимость
             * доказана самим исполнением; если выборка кода всё же не пройдёт, сработает штатный путь
             * «ВОСПОЛНЯЮ карту — недоступен на ИСПОЛНЕНИЕ». Значение исполнимо оставлено в печати
             * разбора как диагностика промаха поиска. */
            if (fv && dostupno && v_bloke)
            {
                LONG n = ++povtorov;

                thread.ctx->regs.x86.eip = (uint32_t)tochno;
                thread.ctx->pc = tochno;
                thread.ctx->last_result = HB_OK;
                memset( &exec, 0, sizeof(exec) );
                result = hb_wow64cpu_simulate( &thread, xtajit_backend(),
                                               params->max_code_bytes ? params->max_code_bytes : 4096,
                                               &exec );
                if (!exec.faulted && result == HB_OK) udach++;
                if (n <= 8 || (n & 0x3ff) == 0)
                {
                    fprintf( stderr, "macrunner-xtajit-unix: ПОВТОР-ДАННЫЕ итог: n=%ld удач=%ld адрес=%08llx с_команды=%08llx "
                             "result=%d exec=%d faulted=%u steps=%llu blocks=%llu eip=%08x\n",
                             (long)n, (long)udach, (unsigned long long)fa, (unsigned long long)tochno,
                             (int)result, (int)exec.result, exec.faulted,
                             (unsigned long long)exec.steps_executed, (unsigned long long)exec.blocks_executed,
                             thread.ctx->regs.x86.eip );
                    fflush( stderr );
                }
            }
        }
    }

    if (result == HB_ERR_MEMORY_FAULT && exec.steps_executed == 0 && exec.blocks_executed == 0)
    {
        uint32_t eip_now = thread.ctx ? (uint32_t)thread.ctx->pc : params->context.eip;

        xtajit_rescan_guest32_if_needed( eip_now );
        if (process.memory && hb_memory_can_exec( process.memory, eip_now, 1 ))
        {
            static LONG povtor;
            povtor++;
            HB_PROBE_SAY( &pr_x32_povtor, "eip=%08x\n", eip_now );
            fflush( stderr );
            memset( &exec, 0, sizeof(exec) );
            result = hb_wow64cpu_simulate( &thread, xtajit_backend(),
                                           params->max_code_bytes ? params->max_code_bytes : 4096,
                                           &exec );
        }
    }

    if (trace_all)
    {
        fprintf( stderr, "macrunner-xtajit-unix: phase=after-hb-sim result=%d exec=%d faulted=%u steps=%llu blocks=%llu\n",
                 result, exec.result, exec.faulted,
                 (unsigned long long)exec.steps_executed,
                 (unsigned long long)exec.blocks_executed );
        fflush( stderr );
    }
    macrunner_step_totals_note( &exec );

    params->hb_result = result;
    params->faulted = exec.faulted;
    params->steps = exec.steps_executed;
    params->blocks = exec.blocks_executed;

    memset( &out, 0, sizeof(out) );
    out.size = sizeof(out);
    result = hb_wow64cpu_export_i386_context( &thread, &out );
    if (!params->status && !exec.faulted) sync_teb32_from_guest( &params->context );
    if (result == HB_OK) export_context( &params->context, &out );
    params->context.fs_base = teb32_guest_base;

    /* STEP_LIMIT is a cooperative yield; the exported i386 context is the continuation point. */
    if (params->hb_result == HB_OK && exec.result == HB_ERR_STEP_LIMIT && !exec.faulted)
        params->status = STATUS_SUCCESS;
    else if (params->hb_result != HB_OK) params->status = status_from_hb( params->hb_result );
    else if (exec.result != HB_OK) params->status = status_from_hb( exec.result );
    else params->status = status_from_hb( result );
    /* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 805 — ПЕРЕВОД `EXEC_FAULT` ДЛЯ i386.
     *
     * ЧЕМ ИЗМЕРЕНО. Прибор `hb_seh_probe32.exe` (вызов по нулю с записью в цепочке `FS:[0]`)
     * умирал с кодом 1, обработчик не звался. Журнал назвал причину числом:
     * `BTCpuSimulate publish-exception-context status=c0000001`, то есть `STATUS_UNSUCCESSFUL`.
     * А `pass_guest_exception` доставляет ТОЛЬКО `c0000005` и `c000001d` — на всё прочее
     * выходит сразу. Отсюда «цепочка найдена, обработчик исполним, но не вызван»:
     * `xtajit-seh: fault head=0141ff0c handler=00401510 valid=1 handler_exec=1`.
     *
     * Корень: `status_from_hb` переводит `MEMORY_FAULT`, но НЕ `EXEC_FAULT`, и тот попадает в
     * `default: STATUS_UNSUCCESSFUL`. Вызов по нулю и деление на ноль приходят именно как
     * `EXEC_FAULT` — ровно тот же недосмотр, что чинился на стороне x64 в итерации 770.
     *
     * Вид отказа берётся из `ctx->last_fault_kind` (заведён в 769-771 и проверен стендом).
     * ★ 04.09.2026: гейт `MACRUNNER_XTAJIT_EXEC_FAULT_STATUS` СНЯТ, перевод безусловен —
     * разбор при самой правке ниже (1473 строки вехи из 34 журналов Diablo, статус изменён
     * в 1473 из 1473). */
    /* ★★★★ 27.08.2026 — АДРЕС И ВИД ДОСТУПА ОБЫЧНОГО ОТКАЗА ПАМЯТИ.
     *
     * Ветка ниже заполняет `fault_addr` только для отказов ИСПОЛНЕНИЯ и сторожевой страницы.
     * Обычное нарушение доступа (запись/чтение по неотображённому адресу) в неё не попадает,
     * и `pass_guest_exception` до сих пор сообщала гостю жёсткие нули — «чтение по адресу 0».
     *
     * Heroes III на этом и умирал: его обработчик читает ExceptionInformation[0]/[1], получал
     * ложь, падал снова на том же месте, и на третьем витке наша защита от рекурсии
     * (`depth >= 3`) превращала ловимое исключение в фатальное.
     *
     * Значения берутся у `hb_memory_last_fault()` — того же источника, что печатает
     * `macrunner-hb-helper-fault-addr`. Гейт `MACRUNNER_XTAJIT_MEM_FAULT_INFO`, умолчание ВКЛ,
     * выключение значением `0`. */
    if (params->hb_result == HB_ERR_MEMORY_FAULT || exec.result == HB_ERR_MEMORY_FAULT)
    {
        const char *off = getenv( "MACRUNNER_XTAJIT_MEM_FAULT_INFO" );
        if (!(off && off[0] == '0'))
        {
            uint64_t fa = 0; size_t fs = 0; int fw = 0, fv = 0;
            hb_memory_last_fault( &fa, &fs, &fw, &fv );
            if (fv)
            {
                params->mem_fault_addr = fa;
                params->mem_fault_valid = 1;
                params->mem_fault_is_write = fw ? 1 : 0;
            }
        }
    }

    /* Итерация 1084: сторожевая страница приходит отказом ПАМЯТИ, а не исполнения, поэтому
     * условие расширено. Без этого вид отказа был известен, а до перевода не доходил. */
    if (thread.ctx && thread.ctx->last_fault_kind != HB_FAULT_KIND_NONE &&
        (params->hb_result == HB_ERR_EXEC_FAULT || exec.result == HB_ERR_EXEC_FAULT ||
         ((params->hb_result == HB_ERR_MEMORY_FAULT || exec.result == HB_ERR_MEMORY_FAULT) &&
          thread.ctx->last_fault_kind == HB_FAULT_KIND_GUARD_PAGE)))
    {
        /* ★★★ 2026-09-04 — ГЕЙТ `MACRUNNER_XTAJIT_EXEC_FAULT_STATUS` СНЯТ, ПЕРЕВОД БЕЗУСЛОВЕН.
         *
         * ЧЕМ ДОКАЗАНО (счёт по 34 уцелевшим журналам Diablo, reports/lanes/diablo/<тег>/run.log):
         * веха ниже печатает ОБЕ руки в каждой своей строке — `before` это ровно то, что гость
         * получил бы с гейтом ВЫКЛ, `after` — то, что получает с ВКЛ. Разбор всех строк:
         *     строк вехи 1473 в 29 прогонах из 34;
         *     статус изменён в 1473 из 1473 (100 %), и всегда одинаково: c0000001 -> c0000005,
         *     вид=2 (HB_FAULT_KIND_NULL_EXEC).
         * То есть парный замер тут не нужно ставить: он уже записан в каждом прогоне.
         *
         * ПОЧЕМУ РУКА ВЫКЛ СЛОМАНА ПО ПОСТРОЕНИЮ, а не «хуже по числу»:
         *   1) `pass_guest_exception` доставляет гостю ТОЛЬКО c0000005 и c000001d — c0000001
         *      (STATUS_UNSUCCESSFUL) не доставляется вовсе, и обработчик гостя не зовётся;
         *      именно это и намерил прибор `artifacts/hb_seh_probe32.exe` (итерация 805):
         *      «цепочка найдена, обработчик исполним, но не вызван»;
         *   2) какой NTSTATUS Windows даёт на вызов по нулю (c0000005), на UD2 (c000001d),
         *      на HLT/CLI (c0000096), на деление (c0000094), на сторожевую страницу (c0000080)
         *      и на переполнение стека x87 (c0000092) — это ЗНАЕМОЕ ЗАРАНЕЕ, вопрос спецификации,
         *      а не замера. Под такой вопрос гейт заводить нельзя: выключатель предлагает выбор
         *      там, где выбора нет (файл памяти dva-klassa-voprosov-spec-i-zamer).
         *
         * Поле вехи переименовано `гейт=` -> `безусловно=`: печатать «гейт=1» там, где гейта
         * больше нет, значит врать в журнале. Разбор старых журналов от этого не портится —
         * у них свой формат, и он остаётся верным для своего времени. */
        NTSTATUS before = params->status;

        params->fault_kind = (ULONG)thread.ctx->last_fault_kind;
        params->fault_addr = thread.ctx->last_fault_addr;
        params->fault_addr_valid = thread.ctx->last_fault_addr_valid ? 1 : 0;
        if (thread.ctx->last_fault_kind == HB_FAULT_KIND_DIVIDE)
            params->status = STATUS_INTEGER_DIVIDE_BY_ZERO;
        else if (thread.ctx->last_fault_kind == HB_FAULT_KIND_NULL_EXEC)
            params->status = STATUS_ACCESS_VIOLATION;
        /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1081 — ЕЩЁ ДВА ВИДА ОТКАЗА.
         *
         * Таблица знала ДВА вида из пяти, поэтому на i386 привилегированная команда и
         * недопустимая команда приходили гостю НЕ СВОИМ кодом. Замер: `udtest32` получил
         * `c0000001` (общий отказ) вместо `c000001d`, тогда как на x64 та же проба даёт
         * верный код. Ровно тот класс «две дороги к одному», что ловится в этом лейне
         * третью итерацию подряд: на стороне x64 доставка заведена, на стороне i386 — нет.
         *
         * `HLT`/`CLI` и родня дают `c0000096`, `UD2` и родня — `c000001d`. */
        else if (thread.ctx->last_fault_kind == HB_FAULT_KIND_PRIVILEGED)
            params->status = STATUS_PRIVILEGED_INSTRUCTION;
        else if (thread.ctx->last_fault_kind == HB_FAULT_KIND_ILLEGAL)
            params->status = STATUS_ILLEGAL_INSTRUCTION;
        else if (thread.ctx->last_fault_kind == HB_FAULT_KIND_GUARD_PAGE)
            params->status = STATUS_GUARD_PAGE_VIOLATION;   /* итерация 1084 */
        /* ★ 30.08, лейн УСТАНОВЩИКИ: отказ стека сопроцессора. Delphi держит
         * недействительную операцию НЕЗАМАСКИРОВАННОЙ (cw=0x1332, IM=0), и на
         * переполнении стека x87 гостю положен c0000092, а не общий c0000001. */
        else if (thread.ctx->last_fault_kind == HB_FAULT_KIND_FPU_STACK)
            params->status = STATUS_FLOAT_STACK_CHECK;
        fprintf( stderr, "macrunner-xtajit-fault-kind: безусловно=1 вид=%u адрес=%08llx годен=%u "
                 "статус %08x -> %08x eip=%08x\n",
                 (unsigned)params->fault_kind,
                 (unsigned long long)params->fault_addr, params->fault_addr_valid,
                 (unsigned int)before, (unsigned int)params->status, params->context.eip );
        fflush( stderr );
    }

    trace_native_stack( "unix-simulate-exit", &out, &exec, params->hb_result, params->status );
    if (params->status || exec.faulted)
    {
        if (process.memory && teb32_guest_base)
        {
            uint32_t head = 0, handler = 0;
            BOOL seh_valid;
            BOOL handler_exec;

            hb_memory_read( process.memory, teb32_guest_base, &head, sizeof(head) );
            if (head && head != 0xffffffffu)
                hb_memory_read( process.memory, head + sizeof(uint32_t), &handler, sizeof(handler) );
            seh_valid = guest_seh_chain_valid( head );
            handler_exec = handler ? hb_memory_can_exec( process.memory, handler, 1 ) : 0;
            /* ★★★★★ MacRunner 2026-08-28 — ЭТА ПРОВЕРКА МЕРИТ НЕ ТОТ МЕХАНИЗМ.
             *
             * Правило «цепочка FS:[0] пуста -> обработчика нет -> делаем отказ
             * фатальным» верно для классической 32-битной Windows. В НАШЕЙ сборке
             * оно ложно, и это проверено побайтно по образам:
             *
             *   в 14 модулях i386-windows команд установки цепочки НОЛЬ:
             *     MOV FS:[0],ESP   0        PUSH FS:[0]   0        POP FS:[0]   0
             *     (единственное вхождение — одно ЧТЕНИЕ MOV EAX,FS:[0])
             *   PE-таблица исключений (DataDirectory[3]) ПУСТА: rva=0 size=0
             *   зато у каждого модуля есть секция .eh_frame — обработчики
             *   находятся по DWARF, как это делает winegcc/clang.
             *
             * То есть `head == 0xffffffff` здесь — НОРМА, а не признак отсутствия
             * обработчика. Цена ошибки видна в замере: за день 103 превращения
             * отказа в `STATUS_NONCONTINUABLE_EXCEPTION`, и среди пострадавших —
             * функции, которые работают ЧЕРЕЗ отказ по замыслу:
             *   IsBadReadPtr / IsBadWritePtr (kernel32/virtual.c, __TRY/__EXCEPT),
             *   RtlCaptureStackBackTrace — они пробуют доступ и ловят исключение
             * своим обработчиком. Мы отнимали у них эту возможность и убивали
             * процесс.
             *
             * Сверхнативный ответ: не решать за гостя, есть ли у него обработчик.
             * Отдаём исключение, его механизм раскрутки сам разберётся — ровно как
             * на настоящей машине. Гейт оставлен, чтобы прежнее поведение было
             * доступно для парного замера: MACRUNNER_XTAJIT_SEH_CHAIN_VETO=1. */
            {
                static int veto = -1;
                if (veto < 0)
                {
                    const char *v = getenv( "MACRUNNER_XTAJIT_SEH_CHAIN_VETO" );
                    veto = (v && *v && *v != '0') ? 1 : 0;
                }
                if (veto &&
                    (params->status == STATUS_ACCESS_VIOLATION ||
                     params->status == STATUS_ILLEGAL_INSTRUCTION) &&
                    (!head || head == 0xffffffffu || !seh_valid))
                {
                    fprintf( stderr, "macrunner-xtajit-unix: no guest SEH for exception eip=%08x head=%08x valid=%u handler=%08x handler_exec=%u — not redispatching\n",
                             params->context.eip, head, seh_valid, handler, handler_exec );
                    params->status = STATUS_NONCONTINUABLE_EXCEPTION;
                }
                else if ((params->status == STATUS_ACCESS_VIOLATION ||
                          params->status == STATUS_ILLEGAL_INSTRUCTION) &&
                         (!head || head == 0xffffffffu || !seh_valid))
                {
                    static int said;
                    if (said++ < 16)
                        fprintf( stderr, "macrunner-xtajit-unix: отдаём исключение гостю eip=%08x head=%08x status=%08x (цепочка FS:[0] в этой сборке не используется)\n",
                                 params->context.eip, head, (unsigned int)params->status );
                }
            }
        }
        fprintf( stderr, "macrunner-xtajit-unix: [pid=%d] simulate hb=%s(%d) exec=%s(%d) faulted=%u steps=%llu blocks=%llu in_eip=%08x out_eip=%08x out_esp=%08x reason=%s\n",
                 (int)getpid(),
                 hb_result_string( params->hb_result ), params->hb_result,
                 hb_result_string( exec.result ), exec.result, exec.faulted,
                 (unsigned long long)exec.steps_executed,
                 (unsigned long long)exec.blocks_executed,
                 in.eip, params->context.eip, params->context.esp,
                 exec.fault_reason ? exec.fault_reason : "" );
        fprintf( stderr,
                 "macrunner-xtajit-unix: regs eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x eip=%08x eflags=%08x fs=%08x\n",
                 params->context.eax, params->context.ebx, params->context.ecx,
                 params->context.edx, params->context.esi, params->context.edi,
                 params->context.ebp, params->context.esp, params->context.eip,
                 params->context.eflags, params->context.fs_base );
        if (process.memory)
        {
            dump_guest_seh_head( "fault" );
            dump_guest_probe_addr( "eip", params->context.eip );
            dump_guest_probe_addr( "esp", params->context.esp );
            dump_guest_probe_addr( "ebp", params->context.ebp );
            dump_guest_probe_addr( "eax", params->context.eax );
            dump_guest_probe_addr( "eax+460", params->context.eax + 0x460u );
            dump_guest_probe_addr( "esi", params->context.esi );
            dump_guest_probe_addr( "edi", params->context.edi );
            dump_guest_probe_addr( "fs", params->context.fs_base );
            dump_guest_dwords( "esp", params->context.esp, 8 );
            dump_guest_dwords( "ebp-40", params->context.ebp - 0x40u, 16 );
            dump_guest_dwords( "ebp", params->context.ebp, 12 );
            if (params->context.ebp && hb_memory_can_read( process.memory, params->context.ebp, sizeof(uint32_t) ))
            {
                uint32_t caller_ebp = 0;
                if (hb_memory_read( process.memory, params->context.ebp, &caller_ebp, sizeof(caller_ebp) ) == HB_OK && caller_ebp)
                {
                    dump_guest_dwords( "caller-ebp-80", caller_ebp - 0x80u, 32 );
                    dump_guest_dwords( "caller-ebp", caller_ebp, 16 );
                }
            }
        }
        if (getenv( "MACRUNNER_HB_TRACE_PE32_BYTES" ) && process.memory)
        {
            dump_guest_bytes( "in_eip", in.eip );
            dump_guest_bytes( "out_eip", params->context.eip );
            dump_guest_bytes( "esp", params->context.esp );
        }
    }
    return params->status;
}

static NTSTATUS map_guest_range( const struct xtajit_memory_params *params )
{
    uint32_t base;
    hb_perm_t perm;
    hb_result_t result;

    HB_PROBE_LOOKED( &pr_x32_vydelenie );   /* выше всех ранних возвратов */
    if (!params) return STATUS_INVALID_PARAMETER;
    if (!params->is_post || params->status) return STATUS_SUCCESS;
    if (!params->size) return STATUS_SUCCESS;
    if (ensure_process()) return STATUS_NO_MEMORY;

    base = (uint32_t)(uintptr_t)params->addr;
    perm = protect_to_perm( params->protect );

    /* ★★★★★ MacRunner 06.09.2026, лейн ТЕНЕВАЯ-КАРТА-4 — ЗДЕСЬ ТЕРЯЕТСЯ ФАКТ РЕЗЕРВА.
     *
     * `protect_to_perm` спрашивает ТОЛЬКО `protect`. Но у Windows доступность страницы задают
     * ДВЕ величины: `protect` (что можно) и `type`/состояние (есть ли вообще страница).
     * `VirtualAlloc(MEM_RESERVE, PAGE_READWRITE)` — это «нельзя ничего», а приходит к нам как
     * `HB_PERM_READ|HB_PERM_WRITE`. Ложь расходится ПО ТРЁМ потребителям сразу: помощник
     * (`region->perm`), теневая карта (`hb_memory_perm_map_set` из того же perm) и MMU хозяина
     * (`guest32_apply_host_prot` из того же perm).
     *
     * ★ И ЭТО МЕСТО — ГЛАВНОЕ, а не `virtual.c`. Измерено 06.09: правка в `map_view`
     * (`MACRUNNER_HB_GUEST32_COMMIT_TRUTH` там же) СРАБОТАЛА (`macrunner-guest32-коммит-правда:
     * n=6 размер=10000 vprot=03` ровно перед `zond-адрес: rezerv=05AF0000`), а поведение гостя
     * НЕ изменилось: `dlls/wow64/virtual.c:307` после удачного `NtAllocateVirtualMemory` зовёт
     * `pBTCpuNotifyMemoryAlloc(addr, size, type, protect, TRUE, status)` с ИСХОДНЫМ `protect`,
     * и вот этот путь ставит права обратно. Второй источник правды побеждает первого — тот же
     * дефект, что и во всей строке 5 сравнения с box64/QEMU.
     *
     * ЧУЖОЙ ОБРАЗЕЦ. У box64 и QEMU такой развилки нет по построению: они САМИ реализуют
     * `mmap`/`mprotect` гостя, поэтому в их таблицу попадает ровно то, что попало в MMU
     * (`research/box64/src/wrapped/wrappedlibc.c:3892`, `research/qemu/linux-user/mmap.c:269`).
     * Резерв там — обычный `PROT_NONE`, и второго мнения о нём не существует.
     *
     * ГЕЙТ `MACRUNNER_HB_GUEST32_COMMIT_TRUTH`, умолчание 0. РАБОТАЕТ ТОЛЬКО НАБОРОМ с
     * `MACRUNNER_HB_GUEST32_SYNC_PROT=1`: понижение на резерве обязано иметь парное повышение
     * на `MEM_COMMIT` (`virtual.c` у `NtAllocateVirtualMemory`), иначе законная запись после
     * фиксации упрётся в нашу же таблицу. В одиночку гейт ЛОМАЕТ гостя.
     *
     * ГРАНИЦА: `PAGE_GUARD` здесь НЕ трогаем — сторож снимается срабатыванием внутри
     * `virtual_handle_fault`, точки уведомления об этом нет, и понижение сломало бы законный
     * второй доступ (проба `guard2` зонда). Смета — в отчёте лейна. */
    {
        static int mr_commit_truth = -1;
        if (mr_commit_truth < 0)
        {
            const char *v = getenv( "MACRUNNER_HB_GUEST32_COMMIT_TRUTH" );
            mr_commit_truth = (v && *v && *v != '0') ? 1 : 0;
        }
        /* MEM_COMMIT == 0x1000. Заголовков Windows на unix-стороне нет — константа названа
         * числом ЯВНО, чтобы не тянуть их ради одного бита. */
        if (mr_commit_truth && params->type && !(params->type & 0x1000u))
        {
            static unsigned mr_ct_n;
            unsigned n = ++mr_ct_n;
            if (n <= 8 || (n % 64) == 0)
                fprintf( stderr, "macrunner-xtajit-резерв-без-коммита: n=%u база=%08x размер=%llx "
                                 "type=%08x protect=%08x perm=%d -> 0\n",
                         n, base, (unsigned long long)params->size,
                         (unsigned)params->type, (unsigned)params->protect, (int)perm );
            perm = HB_PERM_NONE;
        }
    }

    result = hb_wow64cpu_notify_memory_alloc( &process, base, params->size, perm );
    /* Overlap with an existing region: the OS accepted the operation, so update HB's perm to
     * match. Covers MEM_COMMIT on a reserved range AND view mappings where the preexist scan
     * already registered the region (possibly with stale perm). */
    if (result == HB_ERR_INVALID_ARG)
        result = hb_memory_guest32_protect( process.memory, base, params->size, perm );

    /* ★★★★★ MacRunner 2026-08-29 — РАСШИРЕНИЕ РЕГИОНА, А НЕ ТОЛЬКО СМЕНА ПРАВ.
     *
     * Замер по отчёту самой игры (`crossover000902.ERR`) и трассе:
     *   NtAllocateVirtualMemory val=0a4c0000 size=10000   первое выделение
     *   NtAllocateVirtualMemory val=0a4c0000 size=20000   РАСШИРЕНИЕ вдвое
     *   helper-fault-addr: guest_addr=0xa4dfe88 size=4 READ  -> MEMORY_FAULT
     * `0xA4DFE88 = 0x0A4C0000 + 0x1FE88` — внутри ВТОРОГО выделения, но за
     * пределами первого. Гость читал законную память и получал отказ.
     *
     * Почему не лечилось прежней веткой: `hb_memory_guest32_protect` начинается с
     * `if (!guest32_range_fully_mapped(...)) return HB_ERR_NOT_FOUND;` — то есть
     * при выходе за известный регион она НЕ ДЕЛАЕТ НИЧЕГО. Права менялись только
     * там, где регион уже был целиком, а хвост расширения оставался вне карты.
     * Диагностика, печатаемая ПОСЛЕ отказа, показывала уже полный регион
     * (`0a4c0000-0a4e0000`) — потому что карта догоняла позже, и расхождение
     * выглядело необъяснимым.
     *
     * Лечение: если протект не нашёл диапазон целиком, отображаем недостающее.
     * ОС операцию уже приняла (`params->status == 0` проверен выше), значит
     * память законна и карта обязана её знать. */
    /* Любой отказ, а не только NOT_FOUND: ОС операцию ПРИНЯЛА (status проверен в
     * начале), значит память законна. Первая версия ловила только NOT_FOUND и не
     * срабатывала — protect возвращает и другие коды, когда диапазон известен лишь
     * частично. Замер после сужения условия: MEMORY_FAULT 4 -> 2, но отказ по
     * `0xa4dff8c` (тот же регион 0a4c0000, смещение 0x1FF8C) остался. */
    /* ★★★★★★ MacRunner 2026-09-02 — РАСТИТЬ КАРТУ В МОМЕНТ ВЫДЕЛЕНИЯ, А НЕ ПОСЛЕ ОТКАЗА.
     *
     * Ниже стояло: попробовать отобразить ВЕСЬ кусок, а если вышло
     * `HB_ERR_INVALID_ARG` — объявить успехом. Но `guest32_map` отвергает ЛЮБОЕ
     * перекрытие с уже известной областью. Куча растёт кусками, которые частично
     * перекрывают известное, — вся регистрация отвергалась, отказ проглатывался,
     * и карта МОЛЧА не росла. Дальше гость писал за её границу и получал c0000005
     * (`ntdll heap_allocate_block+0x1e4`, запись, 8 прогонов из 8).
     *
     * Повтор команды после восполнения (теперь безусловный) это лечит, но
     * лечит СЛЕДСТВИЕ: отказ уже случился. Здесь устраняется причина — недостающие
     * куски регистрируются сразу, обходом по пробелам, и отказу неоткуда взяться.
     *
     * ★ УМОЛЧАНИЕ ВЫКЛЮЧЕНО — замером НЕ ПОДТВЕРЖДЕНО. Half-Life, свой клон dis-hl,
     * 10 прогонов на руку вперемежку, повтор выключен в обеих: отказов 0 из 10 против
     * 0 из 10, срабатываний нового пути 0. Отказ в этой раскладке не воспроизвёлся
     * вовсе, то есть проверить было не на чём. Рассуждение о причине верное (перекрытие
     * отвергается, отказ проглатывается, карта молча не растёт), но пока это рассуждение,
     * а не измерение. Включить: MACRUNNER_XTAJIT_NOTIFY_GAPS=1. */
    if (result != HB_OK && notify_gaps_enabled())
    {
        uint64_t cur = base, end = (uint64_t)base + (uint64_t)params->size;
        unsigned int dobavleno = 0;
        static LONG skazano_notify;

        while (cur < end)
        {
            hb_region_t *r = hb_memory_find_region( process.memory, (hb_gva_t)cur );
            uint64_t stop;

            if (r)
            {
                stop = (uint64_t)r->base + (uint64_t)r->size;
                if (stop <= cur) stop = cur + 0x1000;        /* страховка от нулевого шага */
            }
            else
            {
                hb_result_t rr;

                stop = cur + 0x1000;
                while (stop < end && !hb_memory_find_region( process.memory, (hb_gva_t)stop )) stop += 0x1000;
                rr = hb_memory_guest32_map( process.memory, (uint32_t)cur, (size_t)(stop - cur), perm );
                if (rr == HB_OK) dobavleno++;
                skazano_notify++;
                HB_PROBE_SAY( &pr_x32_vydelenie, "[pid=%d] guest32=%08x..%08x "
                              "перм=%d результат=%d\n",
                              (int)getpid(), (uint32_t)cur, (uint32_t)stop, (int)perm, (int)rr );
                fflush( stderr );
            }
            cur = stop;
        }
        if (dobavleno) result = HB_OK;
    }

    if (result != HB_OK)
    {
        result = hb_memory_guest32_map( process.memory, base, params->size, perm );
        if (result == HB_OK)
        {
            static unsigned int said;
            if (said++ < 8)
                fprintf( stderr, "macrunner-карта-расширение: база=%08x размер=%zx права=%d "
                         "— регион был короче, карта дополнена\n",
                         base, (size_t)params->size, (int)perm );
        }
        /* Регион мог оказаться уже полным между проверкой и попыткой — это не отказ. */
        if (result == HB_ERR_INVALID_ARG) result = HB_OK;
    }
    return status_from_hb( result );
}

static NTSTATUS unix_notify_memory_alloc_impl( void *args )
{
    return map_guest_range( args );
}

/* MacRunner 2026-08-07 - ответ хосту на вопрос "что лежит по гостевому адресу".
 *
 * Задача, которую это закрывает. У нас ДВА адресных пространства: гостевое (0x87ef...) и
 * хостовое, которое возвращает mmap. hb_memory_map_private хранит пару base/host_base у себя,
 * а Windows-учёт видит только хостовое - поэтому NtQueryVirtualMemory отвечает MEM_FREE по
 * адресу внутри живого UnityPlayer, при работающей игре. Слепы обе проверки: и список
 * загрузчика, и опрос отображений.
 *
 * Почему запрос, а не регистрация вида. Завести вид на гостевой адрес нельзя - он не хостовый,
 * дерево видов адресует хостовое пространство. Зато таблица регионов уже знает и базу, и размер,
 * и права. Дешевле и безопаснее ОТВЕТИТЬ по существующему знанию, чем городить второй учёт.
 *
 * Живёт здесь, а не в hyperbridge: только эта сторона держит `process` с его memory. */
static int macrunner_hb_query_guest_region( uint64_t addr, uint64_t *out_base,
                                            uint64_t *out_size, uint32_t *out_perm )
{
    hb_region_t *r;

    if (!process.memory) return 0;
    r = hb_memory_find_region( process.memory, (hb_gva_t)addr );
    if (!r) return 0;
    if (out_base) *out_base = (uint64_t)r->base;
    if (out_size) *out_size = (uint64_t)r->size;
    if (out_perm) *out_perm = (uint32_t)r->perm;
    return 1;
}

/* ★ MacRunner 2026-08-28 — МОСТ: спросить карту ДВИЖКА про гостевой адрес.
 *
 * Нужен потому, что решения об отказе принимаются по `hb_memory_*`, а PE-сторона
 * видит только склейку окна (`guest32_host_ptr`), которая никогда не даёт ноль.
 * Из-за этой подмены проверка «модуль загружен -> движок его читает» показывала
 * «0 нарушений при 34 модулях», тогда как в карте движка было ТРИ региона (куча,
 * стек, TEB) и ни одного модуля. */
static NTSTATUS unix_probe_guest_addr_impl( void *args )
{
    struct xtajit_probe_params *p = args;
    hb_region_t *region;

    if (!p) return STATUS_INVALID_PARAMETER;
    p->known = p->can_read = p->can_write = p->can_exec = 0;
    p->host = p->base = p->size = 0;
    if (!process.memory) return STATUS_SUCCESS;

    region = hb_memory_find_region( process.memory, p->addr );
    p->host      = (uint64_t)(uintptr_t)hb_memory_guest32_to_host( process.memory, p->addr );
    p->can_read  = hb_memory_can_read( process.memory, p->addr, 1 );
    p->can_write = hb_memory_can_write( process.memory, p->addr, 1 );
    p->can_exec  = hb_memory_can_exec( process.memory, p->addr, 1 );
    if (region)
    {
        p->known = 1;
        p->base  = (uint64_t)region->base;
        p->size  = (uint64_t)region->size;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS unix_notify_map_view_impl( void *args )
{
    /* Связать запрос при первом уведомлении: раньше этого process.memory ещё нет. */
    if (!hb_guest_region_query_cb) hb_guest_region_query_cb = macrunner_hb_query_guest_region;
    return map_guest_range( args );
}

static NTSTATUS unix_notify_memory_protect_impl( void *args )
{
    const struct xtajit_memory_params *params = args;
    hb_result_t result;

    if (!params) return STATUS_INVALID_PARAMETER;
    if (!params->is_post || params->status || !params->size) return STATUS_SUCCESS;
    if (ensure_process()) return STATUS_NO_MEMORY;

    result = hb_wow64cpu_notify_memory_protect( &process, (uint32_t)(uintptr_t)params->addr,
                                                params->size, protect_to_perm( params->protect ) );

    /* MacRunner: sentinel guard — if any BTCpuNotifyMemoryProtect strips WRITE from the sentinel
     * page [0x7BD8E000, 0x7BD8F000) (ntdll32 heap init writes there), force it back immediately.
     * This catches both WoW64 thunk paths and native ARM64 NtProtect calls that call back here. */
#ifdef __APPLE__
    if (process.memory && !(protect_to_perm( params->protect ) & HB_PERM_WRITE))
    {
        uint32_t g32_s = (uint32_t)(uintptr_t)params->addr;
        uint32_t g32_e = g32_s + (uint32_t)params->size;
        if (g32_s < 0x7BD8F000u && g32_e > 0x7BD8E000u)
        {
            mach_vm_protect( mach_task_self(),
                             (mach_vm_address_t)((uint8_t *)process.memory->guest32_base + 0x7BD8E000u),
                             0x1000u, FALSE, VM_PROT_READ | VM_PROT_WRITE );
            hb_memory_guest32_protect( process.memory, 0x7BD8E000u, 0x1000u,
                                       (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC) );
            fprintf( stderr, "macrunner-xtajit: sentinel-guard prot=%08x g32=%08x..%08x\n",
                     (unsigned)params->protect, g32_s, g32_e );
        }
    }
#endif

    return status_from_hb( result );
}

/* СМЕНА ФЛАГОВ ИСПОЛНЕНИЯ (DEP) НА ХОДУ — перенос из апстрима Wine
 * (c57ec80d21fe, 01.07.2026). Игра может переключить DEP уже во время работы;
 * весь переведённый код был выпущен при прежних правах и стал негодным.
 * Апстрим называет мишень прямо: Bioshock. */
static NTSTATUS unix_notify_execute_flags_impl( void *args )
{
    const ULONG *flags = args;

    if (!flags) return STATUS_INVALID_PARAMETER;
    if (ensure_process()) return STATUS_NO_MEMORY;
    (void)hb_wow64cpu_notify_execute_flags( &process, (uint32_t)*flags );
    return STATUS_SUCCESS;
}

static NTSTATUS unix_notify_memory_free_impl( void *args )
{
    const struct xtajit_memory_params *params = args;
    hb_result_t result;

    if (!params) return STATUS_INVALID_PARAMETER;
    if (!params->is_post || params->status || !params->size) return STATUS_SUCCESS;
    if (ensure_process()) return STATUS_NO_MEMORY;

    result = hb_wow64cpu_notify_memory_free( &process, (uint32_t)(uintptr_t)params->addr,
                                             params->size );
    return status_from_hb( result );
}

static NTSTATUS unix_notify_unmap_view_impl( void *args )
{
    return STATUS_SUCCESS;
}

static NTSTATUS unix_flush_instruction_cache_impl( void *args )
{
    return STATUS_SUCCESS;
}

const unixlib_entry_t __wine_unix_call_funcs[] =
{
    unix_process_init_impl,
    unix_thread_init_impl,
    unix_thread_term_impl,
    unix_process_term_impl,
    unix_simulate_impl,
    unix_notify_memory_alloc_impl,
    unix_notify_memory_protect_impl,
    unix_notify_execute_flags_impl,
    unix_notify_memory_free_impl,
    unix_notify_map_view_impl,
    unix_notify_unmap_view_impl,
    unix_flush_instruction_cache_impl,
    unix_probe_guest_addr_impl,
};

C_ASSERT( ARRAYSIZE(__wine_unix_call_funcs) == unix_funcs_count );
