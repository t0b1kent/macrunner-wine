#include "hb_env.h"
#include "hb_gates.h"
#include "hb_codegen.h"
#include "hb_runtime.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#if defined(__APPLE__) && defined(__aarch64__)
#include <pthread.h>
#include <unistd.h>
#endif
#if defined(__APPLE__) && defined(__MACH__)
#include <mach/mach.h>
#include <mach/mach_vm.h>

/* Регистрация кеша гейта в общем сбросе — см. hb_codegen.h. */
#endif

#ifdef __APPLE__
#  ifndef MAP_JIT
#    define MAP_JIT 0x800
#  endif
#endif

#define HB_JIT_BUFFER_MAGIC 0x48424a4954425546ull /* HBJITBUF */

/* MacRunner 2026-07-28 (HK Mono crash): keep JIT arenas FAR above the guest address space.
 *
 * With mmap(NULL, …) the kernel picks whatever is free, which on macOS is the same low
 * region the guest reserves for itself.  Mono's code allocator asks for 64 KB
 * PAGE_EXECUTE_READWRITE blocks at SPECIFIC bases, and once one of our arenas sits there
 * the request cannot be satisfied: `macrunner-hb-guest-alloc-fail: import=VirtualAlloc
 * status=c0000018` (STATUS_CONFLICTING_ADDRESSES) at bases 0x11b150000…0x180000000 —
 * 12 of them in a single run — after which a Mono thread dies with c000007b
 * (STATUS_INVALID_IMAGE_FORMAT: the mapping it needed never landed).  Every observed
 * failure had size=0x10000, type=0x3000, protect=0x40, i.e. exactly that allocator.
 *
 * 0x2000_0000_0000 is 32 TB — far above anything Wine hands the guest, and well inside the
 * 47-bit user address space.  The hint is ADVISORY (no MAP_FIXED, which would let us
 * clobber an existing mapping): if the kernel declines it we fall back to the original
 * mmap(NULL, …).  So this can only remove collisions, never create a failure that the old
 * code would not also have had. */
#define HB_JIT_ARENA_HINT_BASE ((uintptr_t)0x200000000000ull)
#define HB_JIT_ARENA_HINT_STEP ((uintptr_t)0x100000ull) /* 1 MB, so arenas never abut */

static uintptr_t hb_jit_arena_hint = HB_JIT_ARENA_HINT_BASE;

/* ★★★★★ MacRunner 2026-08-25 — АРЕНА РЯДОМ С ПОМОЩНИКАМИ, ЧТОБЫ РАБОТАЛ ADRP.
 *
 * Найдено сличением ВЫПУЩЕННОГО кода трёх трансляторов одним прибором:
 *
 *     ADR/ADRP в коде:   Rosetta 13,3 %   Prism 1,2 %   МЫ 0,1 %
 *     MOVZ/MOVK:         Rosetta  7,2 %   Prism 6,7 %   МЫ 26,7 %
 *
 * Rosetta не СОБИРАЕТ адреса константами — она адресует относительно PC: `ADRP`+`ADD` это
 * ДВЕ команды вместо `MOVZ`+`MOVK`×3, то есть четырёх. Отсюда вчетверо меньшая доля констант.
 *
 * Почему у нас так нельзя было: подсказка арены — 0x2000_0000_0000 (32 ТБ), а модуль с
 * помощниками грузится около 0x1_1242_0000. Расстояние 32 764 ГБ при пределе ADRP ±4 ГБ.
 * То есть дело не в кодогенераторе, а в ВЫБОРЕ АДРЕСА АРЕНЫ.
 *
 * Подсказка ADVISORY (без MAP_FIXED): если ядро её отклонит, вернёмся к прежнему пути и
 * потеряем только возможность ADRP, но не работоспособность. Целимся на 1 ГБ выше модуля —
 * там свободно (Wine раздаёт гостю НИЖНИЕ адреса), и запас до предела вчетверо.
 *
 * Гейт `MACRUNNER_HB_JIT_ARENA_NEAR`, умолчание ВЫКЛЮЧЕНО: сама по себе близость арены
 * ничего не ускоряет — выигрыш появится только когда кодогенератор начнёт выпускать ADRP.
 * Это следующий шаг, и он проверяется отдельно. */
static uintptr_t hb_jit_arena_near_base(void) {
    static uintptr_t cached;
    static int done;
    if (__atomic_load_n(&done, __ATOMIC_ACQUIRE)) return cached;
    {
        const char* v = hb_gate( HB_GATE_HB_JIT_ARENA_NEAR );
        uintptr_t base = 0;
        if (v && v[0] && v[0] != '0') {
            /* Адрес НАШЕГО же кода — надёжный ориентир: помощники лежат в том же модуле. */
            uintptr_t self = (uintptr_t)(void*)&hb_jit_arena_hint;
            base = (self + (uintptr_t)0x40000000ull) & ~(uintptr_t)0xFFFFFull; /* +1 ГБ, 1 МБ */
        }
        cached = base;
        __atomic_store_n(&done, 1, __ATOMIC_RELEASE);
    }
    return cached;
}

/* Reserve the next hint slot.  Lock-free: arenas are created from several guest threads. */
/* ★ Последняя выданная база арены — нужна кодогенератору, чтобы решить, достанет ли ADRP
 * до помощника. Разбор у emit_adrp_addr в hb_arm64_codegen.c. */
static uintptr_t g_hb_jit_last_arena;

void* hb_jit_last_arena_base(void);
void* hb_jit_last_arena_base(void) {
    return (void*)__atomic_load_n(&g_hb_jit_last_arena, __ATOMIC_RELAXED);
}

static void* hb_jit_next_hint(size_t size) {
    uintptr_t step = (size + HB_JIT_ARENA_HINT_STEP - 1) & ~(HB_JIT_ARENA_HINT_STEP - 1);
    if (!step) step = HB_JIT_ARENA_HINT_STEP;
    {   /* ★ разбор у hb_jit_arena_near_base */
        uintptr_t near = hb_jit_arena_near_base();
        if (near) {
            static uintptr_t near_hint;
            static int inited;
            if (!__atomic_load_n(&inited, __ATOMIC_ACQUIRE)) {
                __atomic_store_n(&near_hint, near, __ATOMIC_RELAXED);
                __atomic_store_n(&inited, 1, __ATOMIC_RELEASE);
            }
            { uintptr_t got = __atomic_fetch_add(&near_hint, step, __ATOMIC_RELAXED);
              __atomic_store_n(&g_hb_jit_last_arena, got, __ATOMIC_RELAXED);
              return (void*)got; }
        }
    }
    { uintptr_t got = __atomic_fetch_add(&hb_jit_arena_hint, step, __ATOMIC_RELAXED);
      __atomic_store_n(&g_hb_jit_last_arena, got, __ATOMIC_RELAXED);
      return (void*)got; }
}

/* MacRunner 2026-08-03 — cached: this is called from hb_jit_buffer_commit on EVERY commit, on
 * guest threads.  Crash report wine-2026-08-02-191517.ips caught the uncached getenv holding
 * libc's environ unfair lock when SIGQUIT arrived; the quit path re-entered libc on the same
 * lock and died in _os_unfair_lock_recursive_abort.  A test-only flag does not change mid-run,
 * so read it once. */
static bool force_jit_verify_failure(void) {
    const char* value = hb_gate( HB_GATE_HB_TEST_FORCE_JIT_VERIFY_FAIL );
    int cached = (value && value[0] && value[0] != '0') ? 1 : 0;
    return cached != 0;
}

static bool jit_addr_has_prot(uintptr_t p, int required) {
    if (!p) return false;
#if defined(__APPLE__) && defined(__MACH__)
    mach_vm_address_t addr = (mach_vm_address_t)p;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &addr, &size,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info,
                                      &count, &object_name);
    if (object_name != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), object_name);
    }
    if (kr != KERN_SUCCESS) return false;
    if (p < (uintptr_t)addr || p >= (uintptr_t)(addr + size)) return false;
    return (info.protection & required) == required;
#else
    (void)required;
    return true;
#endif
}

static bool jit_range_has_prot(const void* ptr, size_t size, int required) {
    uintptr_t start = (uintptr_t)ptr;
    if (!start || size == 0) return false;
    uintptr_t end = start + size - 1;
    if (end < start) return false;
    return jit_addr_has_prot(start, required) && jit_addr_has_prot(end, required);
}

/* ── КЕШ ПРОВЕРКИ ЗАЩИТЫ БУФЕРА ───────────────────────────────────────────────────────────
 *
 * 09.08, профиль на новой базе (после кеша arm64x-метаданных верхушка сместилась):
 *     mach_vm_region      165 отсчётов
 *     jit_range_has_prot  134 отсчётов
 * вместе ~299 — крупнейшая опознанная статья после самого диспетчера. Причина:
 * `hb_jit_buffer_is_valid` зовётся из ПЯТИ мест горячего пути (reset, commit, make-writable,
 * ...), а каждый её вызов делает ДВА `mach_vm_region` (начало и конец диапазона), то есть
 * два похода в ядро на каждую операцию с буфером.
 *
 * Защита арены после создания не меняется: буфер выделен `calloc` и живёт до конца процесса.
 * Поэтому результат проверки кешируется по указателю — таблица прямого отображения, как у
 * кеша arm64x-метаданных.
 *
 * ГРАНИЦА БЕЗОПАСНОСТИ. Кеш снимает только проверку ОТОБРАЖЕНИЯ памяти; проверка `magic`
 * выполняется КАЖДЫЙ раз, как и раньше. То есть порченый буфер по-прежнему отсеивается, а
 * не отсеивается лишь случай «указатель был валиден, память с тех пор отобрана» — арены
 * в прогоне не освобождаются, а цена этой страховки измерена и велика.
 *
 * `MACRUNNER_HB_JIT_PROT_CACHE=0` возвращает прежнее поведение для контрольной руки. */
#define HB_JIT_PROT_CACHE_SIZE 16u
static const void* g_jit_prot_cache[HB_JIT_PROT_CACHE_SIZE];
static unsigned long long g_jit_prot_hits, g_jit_prot_misses;

/* УМОЛЧАНИЕ — ВЫКЛЮЧЕНО, и это результат замера, а не осторожность.
 *
 * 09.08, четыре прогона одним бинарём, руки чередовались:
 *     ВКЛ  16.903  16.285   среднее 16.594
 *     ВЫКЛ 16.370  16.048   среднее 16.209
 *     разница +2.4% (МЕДЛЕННЕЕ), порог значимости 6.2% → НЕ УСТАНОВЛЕНО
 * Кеш при этом работает: 2 490 368 обращений, 97.63% попаданий. То есть системные вызовы
 * действительно убраны, а времени это не дало — значит `mach_vm_region` на этом пути стоит
 * меньше, чем показывала доля в профиле (299 отсчётов из окна, не совпадающего с вехой).
 *
 * Включать по умолчанию нельзя: рычаг с недоказанной пользой, стоящий в дефолте, — ровно тот
 * дефект, что стоил 1.85× в SAFE_PROBE_ALWAYS. Отменяющее условие: вернуться, если метрикой
 * станет НЕ веха загрузки сборок, а фаза отрисовки (там частота операций с буфером иная),
 * либо если профиль в окне САМОЙ вехи покажет `mach_vm_region` выше 6%. */
static int jit_prot_cache_enabled(void) {
    const char* v = hb_gate( HB_GATE_HB_JIT_PROT_CACHE );
    int cached = (v && *v && *v != '0') ? 1 : 0;
    static int napechatano;
    if (!napechatano) { napechatano = 1;
    fprintf(stderr, "macrunner-gate: MACRUNNER_HB_JIT_PROT_CACHE=%d\n", cached);
    fflush(stderr);
    }
    return cached;
}

static bool hb_jit_buffer_is_valid(const hb_jit_buffer_t* buf) {
    if (!buf) return false;

    if (jit_prot_cache_enabled()) {
        unsigned slot = (unsigned)(((uintptr_t)buf >> 4) & (HB_JIT_PROT_CACHE_SIZE - 1));
        if (g_jit_prot_cache[slot] == (const void*)buf) {
            g_jit_prot_hits++;
        } else {
            if (!jit_range_has_prot(buf, sizeof(*buf), PROT_READ)) return false;
            g_jit_prot_misses++;
            g_jit_prot_cache[slot] = (const void*)buf;
        }
        {
            unsigned long long t = g_jit_prot_hits + g_jit_prot_misses;
            if (t == 1 || !(t & 0xfffull)) {
                fprintf(stderr, "macrunner-hb-jit-prot-cache: обращений=%llu попаданий=%llu "
                        "(%.2f%%) промахов=%llu\n", t, g_jit_prot_hits,
                        100.0 * (double)g_jit_prot_hits / (double)t, g_jit_prot_misses);
                fflush(stderr);
            }
        }
        return buf->magic == HB_JIT_BUFFER_MAGIC;
    }

    if (!jit_range_has_prot(buf, sizeof(*buf), PROT_READ)) return false;
    return buf->magic == HB_JIT_BUFFER_MAGIC;
}

static hb_result_t hb_jit_buffer_invalid(const char* fn, const hb_jit_buffer_t* buf) {
    fprintf(stderr, "macrunner-hb-jit-buffer-invalid: fn=%s buf=%p caller=%p\n",
            fn ? fn : "unknown", (const void*)buf, __builtin_return_address(0));
    fflush(stderr);
    return HB_ERR_INVALID_ARG;
}

#ifdef __APPLE__
/* Прежнее (молчаливое) поведение: отдать неисполняемую арену и надеяться. Только для замеров. */
static int hb_jit_allow_noexec_arena(void) {
    const char* v = hb_gate( HB_GATE_HB_JIT_ALLOW_NOEXEC_ARENA );
    int cached = (v && *v && *v != '0') ? 1 : 0;
    return cached;
}
#endif

/* ★★★ MacRunner 2026-08-23 — ДВОЙНОЕ ОТОБРАЖЕНИЕ АРЕНЫ (приём QEMU).
 *
 * Сверено по локальным исходникам: research/qemu/tcg/region.c:615
 * (`alloc_code_gen_buffer_splitwx_vmremap`) и include/tcg/tcg.h:464.
 *
 * У QEMU под Darwin арена отображается ДВАЖДЫ на одну физическую память:
 * RW для записи трансляций и RX для исполнения. Патч кода идёт по RW-адресу,
 * исполнение — по RX. MAP_JIT не используется вовсе, pthread_jit_write_protect_np
 * не нужен, mprotect на каждый commit не нужен.
 *
 * Зачем нам. Сцепление блоков у нас ЗАМЕРЕНО ВРЕДНЫМ (хуже на 3,0 % и 8,2 %), и
 * объяснение было «на macOS патч выпущенного кода дорог из-за W^X». Если цена уходит,
 * прежний вердикт снят условиями, которых больше нет, и сцепление надо перемерить.
 *
 * Умолчание ВЫКЛЮЧЕНО: включать замером, а не верой. */
static int hb_jit_splitwx_enabled(void) {
    const char* v = hb_gate( HB_GATE_HB_JIT_SPLITWX );
    int cached = (v && v[0] && v[0] != '0') ? 1 : 0;
    static int napechatano;
    if (!napechatano) { napechatano = 1;
    fprintf(stderr, "macrunner-gate: MACRUNNER_HB_JIT_SPLITWX=%d\n", cached);
    fflush(stderr);
    }
    return cached;
}

#if defined(__APPLE__) && defined(__aarch64__)
#include <mach/mach.h>

extern kern_return_t mach_vm_remap(vm_map_t target_task,
                                   mach_vm_address_t* target_address,
                                   mach_vm_size_t size,
                                   mach_vm_offset_t mask,
                                   int flags,
                                   vm_map_t src_task,
                                   mach_vm_address_t src_address,
                                   boolean_t copy,
                                   vm_prot_t* cur_protection,
                                   vm_prot_t* max_protection,
                                   vm_inherit_t inheritance);

/* Возвращает true, если удалось завести пару RW/RX. При отказе НИЧЕГО не оставляет
 * за собой и возвращает false — вызывающий идёт прежним путём через MAP_JIT. */
static bool hb_jit_arena_splitwx(hb_jit_buffer_t* buf, size_t size) {
    mach_vm_address_t buf_rw, buf_rx = 0;
    vm_prot_t cur_prot = 0, max_prot = 0;
    kern_return_t ret;

    /* RW-половина — обычная анонимная память, БЕЗ MAP_JIT. */
    void* rw = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rw == MAP_FAILED) {
        fprintf(stderr, "macrunner-hb-jit-splitwx: mmap RW отказ errno=%d (%s)\n",
                errno, strerror(errno));
        fflush(stderr);
        return false;
    }

    buf_rw = (mach_vm_address_t)(uintptr_t)rw;
    ret = mach_vm_remap(mach_task_self(), &buf_rx, size, 0, VM_FLAGS_ANYWHERE,
                        mach_task_self(), buf_rw, false,
                        &cur_prot, &max_prot, VM_INHERIT_NONE);
    if (ret != KERN_SUCCESS) {
        fprintf(stderr, "macrunner-hb-jit-splitwx: mach_vm_remap отказ ret=%d\n", (int)ret);
        fflush(stderr);
        munmap(rw, size);
        return false;
    }

    if (mprotect((void*)(uintptr_t)buf_rx, size, PROT_READ | PROT_EXEC) != 0) {
        fprintf(stderr, "macrunner-hb-jit-splitwx: mprotect RX отказ errno=%d (%s)\n",
                errno, strerror(errno));
        fflush(stderr);
        munmap((void*)(uintptr_t)buf_rx, size);
        munmap(rw, size);
        return false;
    }

    buf->writable   = (uint8_t*)(uintptr_t)buf_rw;
    buf->executable = (uint8_t*)(uintptr_t)buf_rx;
    buf->splitwx    = true;
    buf->thread_jit_write_protect = false;
    buf->is_executable = true;   /* RX-половина исполняема ВСЕГДА */
    fprintf(stderr, "macrunner-hb-jit-splitwx: ГОТОВО rw=%p rx=%p size=%zu diff=%+lld\n",
            (void*)buf->writable, (void*)buf->executable, size,
            (long long)((intptr_t)buf->executable - (intptr_t)buf->writable));
    fflush(stderr);
    return true;
}
#endif /* __APPLE__ && __aarch64__ */

/* ★★★★★ ИТЕРАЦИЯ 82, лейн МЕЛКИЕ — РЕЖИМ W^X ПОТОКОВЫЙ, А НЕ СТРАНИЧНЫЙ.
 *
 * `pthread_jit_write_protect_np` переключает режим ТЕКУЩЕГО ПОТОКА: 0 — писать можно,
 * исполнять нельзя; 1 — наоборот. Страница MAP_JIT при этом всё время `rwx` по правам,
 * поэтому поток в режиме 0, прыгнувший в арену, даёт отказ ВЫБОРКИ с подписью
 * «страница rw, max rwx» — ровно то, что видно в замерах (esr=0x8200000f, EC=0x20).
 *
 * Коммит (`hb_jit_buffer_commit`) ставит режим 1 только СВОЕМУ потоку. Если пишет один
 * поток, а исполняет другой — второй остаётся в режиме 0. Проверяем это числом, а не
 * рассуждением: печатаем поток и режим на всех четырёх площадках, потолок 32 строки. */
/* Итерация 83: СЛЕЖЕНИЕ за режимом, а не только печать.
 *
 * Готового способа спросить у ОС текущий режим W^X потока нет, поэтому ведём его сами.
 * Начальное значение 1: у нового потока запись защищена, то есть исполнять можно —
 * это и есть умолчание macOS. Нужен в обработчике отказа, чтобы сравнение
 * «поток был в режиме 0 и прыгнул в арену» стало ОДНИМ числом, а не выводом по
 * соседней строке журнала (итерация 82 именно так и восстанавливала процесс). */
__thread int hb_jit_wx_mode_current = 1;

int hb_jit_wx_mode_get(void)
{
    return hb_jit_wx_mode_current;
}

static void hb_jit_wxmode_note(const char *где, int режим)
{
#if defined(__APPLE__) && defined(__aarch64__)
    static int сказано;
    hb_jit_wx_mode_current = режим;
    if (сказано++ < 40) {
        /* pid обязателен: без него итерация 82 восстанавливала процесс по соседней
         * строке — ровно тот дефект, который я дважды ставил в укор карте загрузчика. */
        fprintf(stderr, "macrunner-hb-jit-wxmode: pid=%d tid=%llu режим=%d место=%s\n",
                (int)getpid(),
                (unsigned long long)pthread_mach_thread_np(pthread_self()), режим, где);
        fflush(stderr);
    }
#else
    (void)где; (void)режим;
#endif
}

/* ★ 06.09.2026, лейн ПРОФИЛЬ — БЕЗУСЛОВНАЯ печать границ арены JIT.
 *
 * Зачем: в профиле `sample(1)` выборки, попавшие в выпущенный код, выглядят как
 * `???  (in <unknown binary>)  [0x...]` — символизировать их нечем. До сих пор они
 * попадали в «безымянные 9,6 %», и назвать их выпущенным кодом было НЕЛЬЗЯ: тем же
 * образом выглядят кадры гостевого стека и мусор размотки.
 *
 * Печать безусловна (не под гейтом, не под потолком): арена создаётся считанные разы
 * за процесс, поэтому цена нулевая, а отсутствие строки означает ровно одно —
 * арена не создавалась. Второй, независимый источник тех же границ — `vmmap` живого
 * процесса; классификатор обязан их сверить. */
static void hb_jit_arena_say(const hb_jit_buffer_t* buf, const char* how)
{
    if (!buf) return;
    uintptr_t x = (uintptr_t)buf->executable, w = (uintptr_t)buf->writable;
    fprintf(stderr,
            "macrunner-hb-jit-arena: how=%s exec=0x%llx exec_end=0x%llx "
            "writable=0x%llx writable_end=0x%llx size=%llu splitwx=%d\n",
            how, (unsigned long long)x, (unsigned long long)(x + buf->size),
            (unsigned long long)w, (unsigned long long)(w + buf->size),
            (unsigned long long)buf->size, buf->splitwx ? 1 : 0);
    fflush(stderr);
}

hb_jit_buffer_t* hb_jit_buffer_create(size_t size) {
    hb_jit_buffer_t* buf = calloc(1, sizeof(hb_jit_buffer_t));
    if (!buf) return NULL;
    buf->size = size;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
#ifdef __APPLE__
    flags |= MAP_JIT;
#endif
    buf->dirty_start = 0;
#if defined(__APPLE__) && defined(__aarch64__)
    if (hb_jit_splitwx_enabled() && hb_jit_arena_splitwx(buf, size)) {
        buf->magic = HB_JIT_BUFFER_MAGIC;
        hb_jit_arena_say(buf, "splitwx");
        return buf;
    }
#endif
    /* Advisory high hint first (see HB_JIT_ARENA_HINT_BASE above), kernel choice second. */
    buf->writable = mmap(hb_jit_next_hint(size), size, PROT_READ | PROT_WRITE | PROT_EXEC, flags, -1, 0);
    if (buf->writable == MAP_FAILED)
        buf->writable = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, flags, -1, 0);
    if (buf->writable == MAP_FAILED) {
#ifdef __APPLE__
        /* Retry without MAP_JIT if hardened runtime lacks JIT entitlement.
         *
         * ВНИМАНИЕ (найдено 05.08.2026). Эта ветка отводит память БЕЗ PROT_EXEC и БЕЗ MAP_JIT,
         * то есть арену, из которой исполнять нельзя НИКОГДА (в vmmap видна как rw-/rw-).
         * Дальше по коду buf->executable = buf->writable, кодогенератор спокойно пишет туда
         * трансляции и прыгает в них — получаем c0000005 по адресу, не принадлежащему ни одному
         * загруженному образу (LdrFindEntryForAddress → STATUS_NO_MORE_ENTRIES, module=0).
         * Именно так игра умирала сразу после Initialize engine version: отказ приходил из
         * области "Memory Tag 22  10398c000-107990000  64.0M  rw-/rw-".
         *
         * Раньше эта ветка молчала. Теперь она кричит: молчаливая подмена рабочей арены на
         * заведомо неисполняемую — худший из возможных исходов, отказ на месте лучше.
         */
        int jit_errno = errno;
        buf->writable = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        fprintf(stderr, "macrunner-hb-jit-arena-no-mapjit: size=%zu errno=%d (%s) fallback=%p "
                        "prot=RW NOEXEC — исполнение из этой арены НЕВОЗМОЖНО\n",
                size, jit_errno, strerror(jit_errno),
                buf->writable == MAP_FAILED ? NULL : buf->writable);
        fflush(stderr);
        if (buf->writable == MAP_FAILED) {
            free(buf);
            return NULL;
        }
        if (!hb_jit_allow_noexec_arena()) {
            /* По умолчанию отказываемся: пусть вызывающий увидит NULL и упадёт осмысленно,
             * а не через сотню кадров в чужой памяти. MACRUNNER_HB_JIT_ALLOW_NOEXEC_ARENA=1
             * возвращает прежнее поведение, если оно вдруг понадобится для замера. */
            munmap(buf->writable, size);
            free(buf);
            return NULL;
        }
#else
        free(buf);
        return NULL;
#endif
    }
#if defined(__APPLE__) && defined(__aarch64__)
    if (flags & MAP_JIT) {
        buf->thread_jit_write_protect = true;
        pthread_jit_write_protect_np(0);
        hb_jit_wxmode_note("create", 0);
    }
#endif
    buf->executable = buf->writable; /* on Apple Silicon with Hardened Runtime this needs special handling */
    buf->magic = HB_JIT_BUFFER_MAGIC;
    hb_jit_arena_say(buf, "mapjit");
    return buf;
}

void hb_jit_buffer_destroy(hb_jit_buffer_t* buf) {
    if (!hb_jit_buffer_is_valid(buf)) return;
    buf->magic = 0;
    if (buf->splitwx && buf->executable && buf->executable != buf->writable)
        munmap(buf->executable, buf->size);          /* RX-половина двойного отображения */
    if (buf->writable && buf->writable != MAP_FAILED) munmap(buf->writable, buf->size);
    free(buf);
}

/* MacRunner: reuse the mapping for a fresh codegen round (no munmap/mmap).
 * Only the bump pointer is rewound; the next codegen overwrites from offset 0.
 * Make the arena writable so the next emit can write (mirrors make_writable). */
hb_result_t hb_jit_buffer_reset(hb_jit_buffer_t* buf) {
    if (!hb_jit_buffer_is_valid(buf)) return hb_jit_buffer_invalid("reset", buf);
    buf->used = 0;
    buf->dirty_start = 0;
    if (buf->splitwx) {
        /* RW-половина писуча всегда, RX-половина исполняема всегда: переключать нечего. */
        buf->is_executable = true;
        return HB_OK;
    }
#if defined(__APPLE__) && defined(__aarch64__)
    if (buf->thread_jit_write_protect) {
        pthread_jit_write_protect_np(0);
        hb_jit_wxmode_note("reset", 0);
        buf->is_executable = false;
        return HB_OK;
    }
#endif
    if (mprotect(buf->writable, buf->size, PROT_READ | PROT_WRITE) != 0) return HB_ERR_JIT_FAILED;
    buf->is_executable = false;
    return HB_OK;
}

hb_result_t hb_jit_buffer_commit(hb_jit_buffer_t* buf) {
    size_t dirty_start, dirty_end;
    if (!hb_jit_buffer_is_valid(buf)) return hb_jit_buffer_invalid("commit", buf);
    buf->is_executable = false;
    dirty_start = buf->dirty_start <= buf->used ? buf->dirty_start : 0;
    dirty_end = buf->used <= buf->size ? buf->used : buf->size;
    if (dirty_end > dirty_start)
        /* Кеш команд относится к ИСПОЛНЯЕМОМУ отображению. Без splitwx это тот же
         * адрес, со splitwx — RX-половина, и чистить надо именно её. */
        __builtin___clear_cache((char*)buf->executable + dirty_start,
                                (char*)buf->executable + dirty_end);
    buf->dirty_start = buf->used;
    if (force_jit_verify_failure()) return HB_ERR_JIT_FAILED;
    if (buf->splitwx) {
        /* Ни pthread_jit_write_protect_np, ни mprotect: половины уже в нужных правах. */
        buf->is_executable = true;
        return HB_OK;
    }
#if defined(__APPLE__) && defined(__aarch64__)
    if (buf->thread_jit_write_protect) {
        pthread_jit_write_protect_np(1);
        hb_jit_wxmode_note("commit", 1);
        buf->is_executable = true;
        return HB_OK;
    }
#endif
    if (mprotect(buf->writable, buf->size, PROT_READ | PROT_EXEC) != 0) return HB_ERR_JIT_FAILED;
    if (!jit_range_has_prot(buf->writable, buf->size, PROT_EXEC)) {
        (void)mprotect(buf->writable, buf->size, PROT_READ | PROT_WRITE);
        return HB_ERR_JIT_FAILED;
    }
    buf->is_executable = true;
    return HB_OK;
}

/* ★ MacRunner 2026-09-04 — РАЗДЕЛЕНИЕ ПРАВ СПРАШИВАЕТСЯ У ЯДРА, А НЕ У ФЛАГА.
 *
 * `buf->is_executable` описывает арену с ОДНИМ отображением: «сейчас писать» или
 * «сейчас исполнять». Под splitwx отображений два, и флаг стоит в 1 всегда — не потому,
 * что что-то открыто, а потому, что RX-половина исполняема по построению. Утверждать
 * по нему «ничего не открылось» — значит утверждать модель, которой здесь нет.
 *
 * Настоящее свойство сильнее и проверяется прямо: RW-половина НИКОГДА не исполняема,
 * RX-половина НИКОГДА не писуча. Оба ответа берутся у ядра через ту же jit_addr_has_prot,
 * которой пользуется проверка после mprotect в commit.
 *
 * Возвращает false, если арена без splitwx (спрашивать нечего) или довод негоден. */
bool hb_jit_buffer_halves_split(const hb_jit_buffer_t* buf,
                                int* rw_ispolnyaema, int* rx_pisucha) {
    if (!hb_jit_buffer_is_valid((hb_jit_buffer_t*)buf) || !buf->splitwx) return false;
    if (rw_ispolnyaema)
        *rw_ispolnyaema = jit_range_has_prot(buf->writable, buf->size, PROT_EXEC) ? 1 : 0;
    if (rx_pisucha)
        *rx_pisucha = jit_range_has_prot(buf->executable, buf->size, PROT_WRITE) ? 1 : 0;
    return true;
}

hb_result_t hb_jit_buffer_make_writable(hb_jit_buffer_t* buf) {
    if (!hb_jit_buffer_is_valid(buf)) return hb_jit_buffer_invalid("make-writable", buf);
    if (buf->splitwx) {
        buf->dirty_start = buf->used;
        buf->is_executable = true;   /* RX-половина не переставала быть исполняемой */
        return HB_OK;
    }
#if defined(__APPLE__) && defined(__aarch64__)
    if (buf->thread_jit_write_protect) {
        pthread_jit_write_protect_np(0);
        hb_jit_wxmode_note("makew", 0);
        buf->dirty_start = buf->used;
        buf->is_executable = false;
        return HB_OK;
    }
#endif
    if (mprotect(buf->writable, buf->size, PROT_READ | PROT_WRITE) != 0) return HB_ERR_JIT_FAILED;
    buf->dirty_start = buf->used;
    buf->is_executable = false;
    return HB_OK;
}

hb_result_t hb_jit_buffer_make_executable(hb_jit_buffer_t* buf) {
    return hb_jit_buffer_commit(buf);
}

void hb_jit_buffer_flush_icache(hb_jit_buffer_t* buf) {
    if (!hb_jit_buffer_is_valid(buf) || !buf->writable) return;
    __builtin___clear_cache((char*)buf->executable, (char*)buf->executable + buf->used);
}

/* --- Codegen buffer --- */
hb_codegen_buffer_t* hb_codegen_buffer_create(size_t cap) {
    hb_codegen_buffer_t* buf = calloc(1, sizeof(hb_codegen_buffer_t));
    if (!buf) return NULL;
    buf->code = calloc(1, cap);
    if (!buf->code) { free(buf); return NULL; }
    buf->capacity = cap;
    return buf;
}

void hb_codegen_buffer_destroy(hb_codegen_buffer_t* buf) {
    if (!buf) return;
    free(buf->code);
    free(buf);
}

hb_result_t hb_codegen_buffer_append(hb_codegen_buffer_t* buf, const uint8_t* bytes, size_t len) {
    if (!buf || !bytes) return HB_ERR_INVALID_ARG;
    if (buf->size + len > buf->capacity) {
        size_t new_cap = buf->capacity * 2;
        while (new_cap < buf->size + len) new_cap *= 2;
        uint8_t* new_code = realloc(buf->code, new_cap);
        if (!new_code) return HB_ERR_OUT_OF_MEMORY;
        buf->code = new_code;
        buf->capacity = new_cap;
    }
    memcpy(buf->code + buf->size, bytes, len);
    buf->size += len;
    return HB_OK;
}
