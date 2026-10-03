#include "hb_env.h"
#include "hb_gates.h"
#include "hb_memory.h"
#include "hb_record.h"   /* ★ ПОВТОР-4: изменения карты пишутся в запись */
#include "hb_probe.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <setjmp.h>
#include <signal.h>
/* Именно <sys/ucontext.h>, а НЕ <ucontext.h>: последний закрыт проверкой
 * «The deprecated ucontext routines require _XOPEN_SOURCE to be defined». Нам нужны только
 * определения структур (uc_mcontext->__ss.__pc), а не getcontext/makecontext. */
#include <sys/ucontext.h>
#include "hb_alloc_count.h"

/* Регистрация кеша гейта в общем сбросе — см. hb_codegen.h. */


/* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 327 — УКАЗАТЕЛЬ ОГРАЖДЕНИЯ БЕЗ ДИНАМИЧЕСКОЙ TLS.
 *
 * Профиль 325-326: `_tlv_get_addr` даёт 10.87 % работы, и ВСЕ вызывающие — горячий путь памяти
 * (`hb_memory_read_inner`, `hb_memory_write_inner`, помощники загрузки и сохранения). Причина
 * та же, что уже описана выше для горячего кеша: на Darwin у `__thread` в динамически
 * загруженной библиотеке нет быстрого пути, каждое обращение — настоящий вызов в libdyld.
 *
 * Приём тот же — таблица прямого отображения по `pthread_self()` (на arm64 это чтение
 * TPIDRRO_EL0, одна инструкция). НО с важным отличием от горячего кеша: там столкновение слотов
 * стоит медленного чтения и безвредно, а ЗДЕСЬ потеря указателя означает, что ограждение не
 * сработает и отказ станет смертельным. Поэтому при столкновении откатываемся на `__thread`:
 * поток либо владеет слотом, либо пользуется своей переменной — указатель не теряется никогда.
 *
 * Выключатель `MACRUNNER_HB_TLS_SAFEJMP=0` возвращает прежний путь целиком, для A/B. */
#define HB_SAFE_JMP_SLOTS 256
static sigjmp_buf* g_safe_jmp_tab[HB_SAFE_JMP_SLOTS];
static uint64_t    g_safe_jmp_owner[HB_SAFE_JMP_SLOTS];
static __thread sigjmp_buf* g_safe_copy_jmp = NULL;   /* и запасной путь, и путь при выключенном гейте */

static int hb_tls_safejmp_enabled(void) {
    const char* v = hb_gate( HB_GATE_HB_TLS_SAFEJMP );
    int cached = (v && *v == '1') ? 1 : 0;
    static int napechatano;
    if (!napechatano) { napechatano = 1;
    fprintf(stderr, "macrunner-gate: MACRUNNER_HB_TLS_SAFEJMP=%d\n", cached);
    fflush(stderr);
    }
    return cached;
}

static inline unsigned hb_safe_jmp_slot(uint64_t self) {
    return (unsigned)((self >> 6) & (HB_SAFE_JMP_SLOTS - 1));
}

static inline sigjmp_buf* hb_safe_jmp_get(void) {
    uint64_t self;
    unsigned sl;
    if (!hb_tls_safejmp_enabled()) return g_safe_copy_jmp;
    self = (uint64_t)(uintptr_t)pthread_self();
    sl = hb_safe_jmp_slot(self);
    if (g_safe_jmp_owner[sl] == self) return g_safe_jmp_tab[sl];
    return g_safe_copy_jmp;              /* слот занят чужим потоком — свой запасной путь */
}

/* MacRunner 2026-08-22, КООРДИНАТОР — ОДИН ВЫЗОВ ДЕСКРИПТОРА ВМЕСТО ДВУХ.
 *
 * Замер: `_tlv_get_addr` — крупнейшая статья пути i386 (14,13 %), и 63,5 % её семплов идут
 * с ограждённого копирования: `hb_safe_jmp_set` 627, плюс те же обращения, вписанные в
 * `hb_flags_read_operand_value` 220, `hb_memory_write_inner` 174, `hb_memory_read_inner` 143.
 * Все они — ОДНА переменная `g_safe_copy_jmp`.
 *
 * На macOS каждое обращение к `__thread` — косвенный вызов через дескриптор, а ограждение
 * обращается ДВАЖДЫ: взвести перед копированием и снять после. Адрес ячейки за это время не
 * меняется, значит его хватает взять один раз.
 *
 * Слот у `MACRUNNER_HB_TLS_SAFEJMP` закрепляется здесь же, ровно как в `hb_safe_jmp_set`,
 * поэтому обе стороны гейта видят одну и ту же ячейку и `hb_safe_jmp_get` читает её же.
 *
 * ★ Ноля тут не добиться: обработчик сигнала обязан найти ячейку, а у него на руках нет
 * ничего, кроме потока. Замену на таблицу по `pthread_self` уже мерили (итерация 328) —
 * доля в профиле падала, ВРЕМЯ становилось хуже на 1,57 %. Здесь не замена, а вдвое реже. */
static inline sigjmp_buf** hb_safe_jmp_cell(void) {
    uint64_t self;
    unsigned sl;
    if (!hb_tls_safejmp_enabled()) return &g_safe_copy_jmp;
    self = (uint64_t)(uintptr_t)pthread_self();
    sl = hb_safe_jmp_slot(self);
    if (g_safe_jmp_owner[sl] == self || g_safe_jmp_owner[sl] == 0) {
        g_safe_jmp_owner[sl] = self;
        return &g_safe_jmp_tab[sl];
    }
    return &g_safe_copy_jmp;
}

static inline void hb_safe_jmp_set(sigjmp_buf* j) {
    uint64_t self;
    unsigned sl;
    if (!hb_tls_safejmp_enabled()) { g_safe_copy_jmp = j; return; }
    self = (uint64_t)(uintptr_t)pthread_self();
    sl = hb_safe_jmp_slot(self);
    if (g_safe_jmp_owner[sl] == self || g_safe_jmp_owner[sl] == 0) {
        g_safe_jmp_owner[sl] = self;
        g_safe_jmp_tab[sl] = j;
        return;
    }
    g_safe_copy_jmp = j;                 /* столкновение — не теряем указатель, а храним у себя */
}
static struct sigaction g_prev_segv;
static struct sigaction g_prev_bus;
/* ТИП — БАЙТ, а не int: `__atomic_test_and_set` по определению работает с ОДНИМ БАЙТОМ
 * по адресу, и быстрый путь ниже читает ТОТ ЖЕ объект. С `int` чтение брало бы четыре
 * байта, и совпадение с записанным байтом держалось бы на порядке байтов машины. */
static unsigned char g_sig_handlers_installed = 0;

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: см. заметку про MACRUNNER_HB_FAST_SIGJMP ниже.
 * При быстром ограждении маска сигналов в sigsetjmp НЕ сохраняется, поэтому разблокировать
 * сигнал обязан обработчик — иначе после первого же отказа SIGSEGV останется заблокирован
 * и следующий станет смертельным. Расход платится только на ОТКАЗЕ, а он редок. */
/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — ПЛОЩАДКА ПРИЗЕМЛЕНИЯ вместо выпрыгивания.
 *
 * Входящее, пункты 32/36: штатный выход из обработчика на macOS идёт через `_sigtramp`,
 * который после нашего обработчика делает `__in_sigtramp = 0` и `__sigreturn`. Выход
 * длинным переходом ЭТОТ путь минует: флаг остаётся выставленным, PAC-токен sigreturn не
 * тратится, альтернативный стек не сбрасывается. Накопление и даёт `brk #1` в `_sigtramp`
 * (в исходнике Apple там стоит `__builtin_trap()` с комментарием «sigreturn returning is a
 * fatal error»).
 *
 * Приём V8 (пункт 37): не выпрыгивать, а поменять `__pc` прямо в `ucontext` и вернуться
 * обычным `return` — `_sigtramp` сам позовёт `sigreturn`, и ядро применит изменённый
 * контекст. Оговорка пункта 34 («нельзя чинить PC внутри платформенного memcpy») здесь НЕ
 * нарушается: мы не ПРОДОЛЖАЕМ memcpy, а бросаем его ровно так же, как бросал длинный
 * переход, — но уходим законным путём.
 *
 * Умолчание ВЫКЛ: прежнее поведение сохраняется дословно. */
static int hb_sig_landing_enabled(void) {
    static int v = -1;
    if (v < 0) {
        const char* s = hb_gate( HB_GATE_HB_SIG_LANDING_PAD );
        v = (s && *s && *s != '0') ? 1 : 0;
        fprintf(stderr, "macrunner-gate: MACRUNNER_HB_SIG_LANDING_PAD=%d\n", v);
        fflush(stderr);
    }
    return v;
}


/* MacRunner 2026-08-22, лейн ЛЕСТНИЦА, итерация 2660 (наряд Л-220) — ПРИЗНАК ВМЕСТО ГЕЙТА.
 *
 * Гейт требовал, чтобы КАЖДЫЙ хозяин процесса знал, что выставить: стенду 1, wine 0.
 * Спросить можно у самого процесса, и спрашивать не у кого-то, а у ядра: при установке
 * своего обработчика мы уже читаем прежний (`sigaction(SIGSEGV, NULL, &old)`, ниже).
 * Если прежний — не умолчание и не «игнорировать», значит SEGV УЖЕ ЧЕЙ-ТО, и забирать
 * отказ себе нельзя: под wine это `segv_handler` (`signal_arm64.c:4256`), и перехват
 * лишает его собственного пути (замер координатора: дверь=1 -> exit=1 и зависание,
 * дверь=0 -> exit=0 и 35 562 пс против 112 828 без гейтов).
 * У самостоятельного стенда движка прежнего обработчика НЕТ — там дверь нужна, и признак
 * это видит сам, без переменной окружения.
 *
 * Переменная оставлена НАД признаком: явное слово хозяина побеждает, иначе нечем ставить
 * A/B. Не задана — решает признак. */
static int mem_segv_owned_by_host(void) {
    void* h = (void*)(uintptr_t)g_prev_segv.sa_sigaction;
    return h && h != (void*)SIG_DFL && h != (void*)SIG_IGN;
}


/* Площадка: сюда ядро приводит поток ПОСЛЕ штатного sigreturn. Здесь мы уже вне
 * обработчика, сигнальный кадр закрыт, и длинный переход безопасен. */
static void hb_copy_fault_landing(void) {
    /* Итерация 168: СВИДЕТЕЛЬ. Два захода (166, 167) судили площадку, не доказав, что она
     * исполняется, и потому недействительны. Здесь мы уже ВНЕ обработчика — sigreturn
     * отработал, — поэтому fprintf безопасен. */
    static int n;
    if (n++ < 8) { fprintf(stderr, "macrunner-hb-landing-copy: n=%d\n", n); fflush(stderr); }
    sigjmp_buf* j = hb_safe_jmp_get();
    hb_safe_jmp_set(NULL);
    if (j) siglongjmp(*j, 1);
    abort();
}


/* ★★★ MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 978 — ДЕТЕКТОР САМОИЗМЕНЕНИЯ ЧЕРЕЗ
 * ЗАПРЕТ ЗАПИСИ (приказ 117), примитив и обработчик.
 *
 * Почему именно так, а не поколениями в воронке записи: воронок записи ТРИ вида, и одна
 * (`hb_memory_host_ptr` с правом записи) отдаёт СЫРОЙ хозяйский указатель — 17 мест только в
 * `hb_arm64_codegen.c` (замер 977). Перехват в воронке неполон по устройству, а неполный
 * детектор хуже честного хеша: он молча пропускает изменение.
 *
 * Устройство:
 *   защитить  — снять право записи с хозяйской страницы, содержащей гостевую кодовую;
 *   отказ     — обработчик поднимает ПОКОЛЕНИЕ страницы, возвращает право и ВОЗВРАЩАЕТСЯ;
 *               команда записи выполнится заново уже успешно (стандартный приём, без
 *               доисполнения вручную);
 *   проверка  — на входе в блок сравнить поколение страницы с отпечатком блока: одна
 *               загрузка и сравнение вместо хеша по всем байтам (приказ 123).
 *
 * ★ Про 16 КБ против 4 КБ: хозяйская страница крупнее гостевой, поэтому защита захватывает
 * соседние гостевые страницы. Это ИЗБЫТОЧНОСТЬ, а не пропуск: лишние отказы стоят времени,
 * верности не вредят. Ловушка (б) приказа 117 проверяется пробой `smctwin.exe`.
 * ★ Арену MAP_JIT не трогаем: защищаются только ГОСТЕВЫЕ страницы.
 * Гейт `MACRUNNER_HB_SMC_PROTECT` по умолчанию ВЫКЛЮЧЕН — включается замером. */
#define HB_SMC_PAGE_SLOTS 4096u

struct hb_smc_page { uint64_t base; uint32_t gen; uint32_t armed; };
static struct hb_smc_page g_smc_pages[HB_SMC_PAGE_SLOTS];
static uint64_t g_smc_prot_faults, g_smc_prot_armed;

static size_t hb_smc_host_page_size(void) {
    static size_t sz;
    if (!sz) { long v = sysconf(_SC_PAGESIZE); sz = v > 0 ? (size_t)v : 16384u; }
    return sz;
}

static unsigned hb_smc_slot_for(uint64_t page_base) {
    uint64_t h = page_base >> 12;
    h ^= h >> 17; h *= 0x9e3779b97f4a7c15ULL; h ^= h >> 29;
    return (unsigned)(h & (HB_SMC_PAGE_SLOTS - 1));
}

/* Итерация 982: во время самопроверки НАШ обработчик обязан пропустить отказ дальше —
 * иначе он его съест, вернёт право записи, и самопроверка увидит успех там, где был отказ. */
static volatile int g_smc_selftest_active;

int hb_smc_protect_enabled(void) {
    const char* v = hb_gate( HB_GATE_HB_SMC_PROTECT );
    int cached = (v && v[0] && v[0] != '0') ? 1 : 0;
    return cached;
}

uint32_t hb_smc_page_generation(uint64_t host_addr) {
    uint64_t base = host_addr & ~(uint64_t)(hb_smc_host_page_size() - 1);
    struct hb_smc_page* p = &g_smc_pages[hb_smc_slot_for(base)];
    return (p->base == base) ? p->gen : 0u;
}

/* Снять право записи с хозяйской страницы, содержащей адрес. Возвращает 1, если защита
 * поставлена (или уже стояла). Слот занят чужой страницей — отказываемся, а не вытесняем:
 * вытеснение оставило бы страницу защищённой без записи о ней, и отказ стал бы вечным. */
int hb_smc_arm_page(void* host_addr) {
    size_t ps = hb_smc_host_page_size();
    uint64_t base = (uint64_t)(uintptr_t)host_addr & ~(uint64_t)(ps - 1);
    struct hb_smc_page* p = &g_smc_pages[hb_smc_slot_for(base)];
    if (!hb_smc_protect_enabled()) return 0;
    if (p->base && p->base != base) return 0;
    if (p->base == base && p->armed) return 1;
    if (mprotect((void*)(uintptr_t)base, ps, PROT_READ | PROT_EXEC) != 0) {
        /* Итерация 980: печатаем ПРИЧИНУ отказа — она и есть ответ на вопрос, легла ли
         * защита вообще. Первые 8 раз, безусловно. */
        static int said_fail;
        if (said_fail++ < 8) {
            fprintf(stderr, "macrunner-hb-smc-arm: ОТКАЗ base=%p size=%zu errno=%d\n",
                    (void*)(uintptr_t)base, ps, errno);
            fflush(stderr);
        }
        return 0;
    }
    p->base = base; p->armed = 1; g_smc_prot_armed++;
    /* ★ Итерация 983 — СПРОСИТЬ У ЯДРА, а не провоцировать отказ.
     * Вопрос прежний: `mprotect` вернул успех — действуют ли новые права? Прошлая попытка
     * отвечала записью под `hb_safe_jmp` и дважды уронила прогон (982): прыжок из
     * обработчика в чужом кадре небезопасен. `mach_vm_region` отвечает на тот же вопрос
     * запросом, без сигнала, прыжка и записи. Печать первые 4 раза.
     * Ожидание: prot=5 (READ|EXECUTE). Если 7 (READ|WRITE|EXECUTE) — права не применились. */
    { static int said_q;
      if (said_q++ < 4) {
          mach_vm_address_t q_addr = (mach_vm_address_t)base;
          mach_vm_size_t q_size = 0;
          vm_region_basic_info_data_64_t q_info;
          mach_msg_type_number_t q_cnt = VM_REGION_BASIC_INFO_COUNT_64;
          mach_port_t q_obj = MACH_PORT_NULL;
          kern_return_t kr = mach_vm_region(mach_task_self(), &q_addr, &q_size,
                                            VM_REGION_BASIC_INFO_64,
                                            (vm_region_info_t)&q_info, &q_cnt, &q_obj);
          fprintf(stderr, "macrunner-hb-smc-query: base=%p kr=%d region=%p size=%llu "
                  "prot=%d maxprot=%d (ждём prot=5)\n",
                  (void*)(uintptr_t)base, (int)kr, (void*)(uintptr_t)q_addr,
                  (unsigned long long)q_size, (int)q_info.protection, (int)q_info.max_protection);
          fflush(stderr);
      } }
    { static int said_ok;
      if (said_ok++ < 8) {
          fprintf(stderr, "macrunner-hb-smc-arm: защищено base=%p size=%zu всего=%llu\n",
                  (void*)(uintptr_t)base, ps, (unsigned long long)g_smc_prot_armed);
          fflush(stderr);
      } }
    return 1;
}

/* Возвращает 1, если отказ наш: адрес попал в защищённую кодовую страницу. Поднимает
 * поколение и возвращает право записи — команда гостя выполнится заново. */
static int hb_smc_handle_write_fault(void* fault_addr) {
    if (g_smc_selftest_active) return 0;
    size_t ps = hb_smc_host_page_size();
    uint64_t base = (uint64_t)(uintptr_t)fault_addr & ~(uint64_t)(ps - 1);
    struct hb_smc_page* p;
    if (!fault_addr || !hb_smc_protect_enabled()) return 0;
    p = &g_smc_pages[hb_smc_slot_for(base)];
    if (p->base != base || !p->armed) return 0;
    /* ★★★ MacRunner 2026-08-16, лейн ПАМЯТЬ — ВОЗВРАТ ПРАВА ЗАПИСИ БЕЗ EXEC.
     *
     * Было `mprotect(R|W|X)` одной строкой, и она НЕ МОЖЕТ здесь пройти: W^X на этой платформе
     * отвергает R|W|X всегда. Замер (проба `smcprot.c`, 16.08), три случая из трёх:
     *
     *     страница RW  → arm mprotect(R|X)=0 | возврат R|W|X = EACCES(13) | возврат R|W = 0
     *     страница RX  → arm mprotect(R|X)=0 | возврат R|W|X = EACCES(13) | возврат R|W = 0
     *     арена MAP_JIT→ mprotect любой = EACCES(13)  (её и не трогаем, см. шапку)
     *
     * Последствие прежнего кода: страница ЗАЩИЩАЕТСЯ и НЕ ОТПУСКАЕТСЯ. Возврат 0 читается
     * вызывающим как «отказ не наш», отказ уходит дальше, а страница остаётся без права записи
     * навсегда — то есть детектор при включении становится ловушкой, причём молчащей: на этом
     * пути не было ни одной печати, в отличие от пути постановки защиты.
     *
     * Теперь: пробуем прежний R|W|X (вдруг платформа позволит), при отказе — R|W. Если не вышло
     * и это, печатаем ОБА errno и честно возвращаем 0.
     *
     * ★ ЧЕГО ЭТА ПРАВКА НЕ ДЕЛАЕТ: с возвратом R|W страница теряет право ИСПОЛНЕНИЯ, и вернуть
     * его некому — проверка поколения на входе в блок EXEC не восстанавливает. То есть гость
     * запишет в свою кодовую страницу успешно, а исполнить её потом не сможет. Это ОСТАВШАЯСЯ
     * половина дефекта, она названа в отчёте лейна и не закрыта: закрывать её надо на стороне
     * входа в блок (чужая половина), и без прогона такое не проверить. Гейт по-прежнему ВЫКЛ. */
    if (mprotect((void*)(uintptr_t)base, ps, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        int e_rwx = errno;

        if (mprotect((void*)(uintptr_t)base, ps, PROT_READ | PROT_WRITE) != 0) {
            static int said_r;
            if (said_r++ < 8) {
                fprintf(stderr, "macrunner-hb-smc-release: ОТКАЗ base=%p rwx_errno=%d rw_errno=%d"
                        " — страница осталась защищённой\n",
                        (void*)(uintptr_t)base, e_rwx, errno);
                fflush(stderr);
            }
            return 0;
        }
        { static int said_x;
          if (said_x++ < 8) {
              fprintf(stderr, "macrunner-hb-smc-release: EXEC СНЯТ base=%p (rwx errno=%d);"
                      " вернуть право исполнения некому\n",
                      (void*)(uintptr_t)base, e_rwx);
              fflush(stderr);
          } }
    }
    p->armed = 0; p->gen++; g_smc_prot_faults++;
    { static int said_f;
      if (said_f++ < 8) {
          fprintf(stderr, "macrunner-hb-smc-fault: пойман base=%p поколение=%u всего=%llu\n",
                  (void*)(uintptr_t)base, p->gen, (unsigned long long)g_smc_prot_faults);
          fflush(stderr);
      } }
    return 1;
}

/* Итерация 984: текущие права страницы по адресу. Запрос, а не провокация (см. 983). */
int hb_smc_query_prot(uint64_t host_addr) {
    mach_vm_address_t a = (mach_vm_address_t)host_addr;
    mach_vm_size_t sz = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    if (mach_vm_region(mach_task_self(), &a, &sz, VM_REGION_BASIC_INFO_64,
                       (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) return -1;
    return (int)info.protection;
}

void hb_smc_protect_stats(uint64_t* armed, uint64_t* faults) {
    if (armed) *armed = g_smc_prot_armed;
    if (faults) *faults = g_smc_prot_faults;
}

/* MacRunner 2026-08-29 — ВЫВОД ИЗ ОБРАБОТЧИКА СИГНАЛА БЕЗ ЗАМКОВ STDIO.
 *
 * `fprintf` не async-signal-safe: берёт замок потока stdio. Если сигнал пришёл,
 * когда этот же поток уже печатал и держал замок, обработчик встаёт на нём же —
 * разбудить некому, прерванный код не продолжится, пока обработчик не вернётся.
 * Тупик: CPU 0 %, тишина в журнале. Так вставал каждый восьмой прогон Diablo.
 *
 * `vsnprintf` пишет в нашу память, `write` разрешён POSIX внутри обработчика. */
static void hb_sig_printf(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (n < 0) return;
    if (n > (int)sizeof(buf) - 1) n = (int)sizeof(buf) - 1;
    if (n > 0) { ssize_t r = write(2, buf, (size_t)n); (void)r; }
}

/* ═══ ПЕРЕПИСЬ ОТКАЗОВ — БЕЗ ПРЕДЕЛА ПЕЧАТИ ═══
 *
 * ЗАЧЕМ. Подробная печать отказа ограничена двенадцатью строками. Из-за этого
 * замер 03.09 дал «11 отказов из 12 по одному адресу» — и это упор в предел,
 * а не свойство отказов: предел не отличает петлю от её отсутствия. Прибор,
 * который замолкает раньше, чем ответит на вопрос, — слепой прибор.
 *
 * Перепись считает ВСЕ отказы, с разбивкой по паре «адрес + pc». Сводка
 * печатается по достижении порога и дальше кратно ему, поэтому длина журнала
 * растёт логарифмом от числа отказов, а не линейно.
 *
 * Таблица маленькая и фиксированная: в сигнальном обработчике нельзя ни
 * выделять память, ни брать замок. Переполнение не теряется молча — лишние
 * пары считаются отдельной строкой «прочие». */
#define HB_OTKAZ_PAR 32

struct hb_otkaz_para { uint64_t addr, pc, n; };
static struct hb_otkaz_para g_otkaz[HB_OTKAZ_PAR];
/* Первый порог НИЗКИЙ намеренно. С порогом 4096 перепись промолчала — то
 * есть я завёл ту же слепоту, от которой лечил: прибор, который молчит,
 * не отличает «отказов мало» от «прибор не сработал». Дальше порог
 * удваивается, поэтому журнал растёт логарифмом. */
static uint64_t g_otkaz_vsego, g_otkaz_prochie, g_otkaz_porog = 16;

static void hb_vhod_snyat(void);
static void hb_vhod_svodka(void);

static void hb_otkaz_uchest(const siginfo_t* info, const void* context)
{
    uint64_t addr = info ? (uint64_t)(uintptr_t)info->si_addr : 0;
    uint64_t pc = 0;
    uint64_t vsego;
    int i;

#if defined(__APPLE__) && defined(__aarch64__)
    if (context) {
        const ucontext_t* uc = (const ucontext_t*)context;
        if (uc->uc_mcontext) pc = (uint64_t)uc->uc_mcontext->__ss.__pc;
    }
#else
    (void)context;
#endif

    vsego = __atomic_add_fetch(&g_otkaz_vsego, 1, __ATOMIC_RELAXED);

    for (i = 0; i < HB_OTKAZ_PAR; i++) {
        if (g_otkaz[i].n && g_otkaz[i].addr == addr && g_otkaz[i].pc == pc) {
            __atomic_add_fetch(&g_otkaz[i].n, 1, __ATOMIC_RELAXED);
            break;
        }
        if (!g_otkaz[i].n) {
            g_otkaz[i].addr = addr; g_otkaz[i].pc = pc;
            __atomic_store_n(&g_otkaz[i].n, 1, __ATOMIC_RELAXED);
            break;
        }
    }
    if (i == HB_OTKAZ_PAR) __atomic_add_fetch(&g_otkaz_prochie, 1, __ATOMIC_RELAXED);

    if (vsego < __atomic_load_n(&g_otkaz_porog, __ATOMIC_RELAXED)) return;
    __atomic_store_n(&g_otkaz_porog, vsego * 2, __ATOMIC_RELAXED);   /* дальше кратно */

    hb_sig_printf("macrunner-hb-перепись-отказов: всего=%llu прочих_пар=%llu\n",
                  (unsigned long long)vsego, (unsigned long long)g_otkaz_prochie);
    hb_vhod_svodka();
    for (i = 0; i < HB_OTKAZ_PAR; i++) {
        uint64_t n = __atomic_load_n(&g_otkaz[i].n, __ATOMIC_RELAXED);
        if (!n) continue;
        hb_sig_printf("macrunner-hb-отказ: addr=%#llx pc=%#llx n=%llu доля=%llu%%\n",
                      (unsigned long long)g_otkaz[i].addr,
                      (unsigned long long)g_otkaz[i].pc,
                      (unsigned long long)n,
                      (unsigned long long)(100u * n / (vsego ? vsego : 1)));
    }
}

static void safe_copy_signal_handler_telo(int sig, siginfo_t* info, void* context) {
    /* Итерация 981: БЕЗУСЛОВНЫЙ счётчик на входе в обработчик. Вопрос, который он решает:
     * приходит ли отказ вообще. Ноль записей при защищённой странице означает, что запись
     * не дошла до оборудования — то есть защита к моменту записи уже снята или память
     * пишется через другое отображение. */
    /* MacRunner 2026-08-22, лейн ЛЕСТНИЦА, приказ 214 — ПЕЧАТАЕМ PC, А НЕ ТОЛЬКО ADDR.
     * Без PC отказ отвечает «куда обратились» и молчит про «кто обратился», а именно это
     * и есть искомое: наш выпущенный код, помощник на C или чужая библиотека. Разбор
     * addr=0x7be048bc встал ровно здесь — адрес был известен с первого прогона, виновник
     * потребовал возни с lldb, который останавливается на ПЕРЕХВАЧЕННЫХ отказах. */
    { static int said_any; if (said_any++ < 12) {
        unsigned long long fpc = 0, flr = 0;
#if defined(__APPLE__) && defined(__aarch64__)
        if (context) {
            const ucontext_t* uc = (const ucontext_t*)context;
            if (uc->uc_mcontext) {
                fpc = (unsigned long long)uc->uc_mcontext->__ss.__pc;
                fpc = (unsigned long long)(fpc & ~0ULL);
                flr = (unsigned long long)uc->uc_mcontext->__ss.__lr;
            }
        }
#else
        (void)context;
#endif
        /* Имя, а не число: двоичный собран PIE, поэтому сырой pc без сдвига образа
         * ни о чём не говорит — я на этом сам ошибся, посчитав pc «вне текста».
         * dladdr отвечает прямо: какой образ и какой ближайший символ. */
        {
            Dl_info dpc, dlr;
            int okpc = fpc ? dladdr((const void*)(uintptr_t)fpc, &dpc) : 0;
            int oklr = flr ? dladdr((const void*)(uintptr_t)flr, &dlr) : 0;
            hb_sig_printf(
                    "macrunner-hb-sig: сигнал=%d addr=%p code=%d pc=%#llx lr=%#llx "
                    "pc_img=%s pc_sym=%s lr_img=%s lr_sym=%s\n",
                    sig, info ? info->si_addr : NULL, info ? info->si_code : 0, fpc, flr,
                    okpc && dpc.dli_fname ? dpc.dli_fname : "?",
                    okpc && dpc.dli_sname ? dpc.dli_sname : "?",
                    oklr && dlr.dli_fname ? dlr.dli_fname : "?",
                    oklr && dlr.dli_sname ? dlr.dli_sname : "?");
        }
        /* ★★★★★ MacRunner 2026-08-24 — РАЗМАТЫВАНИЕ СТЕКА: КТО ВИНОВАТ, А НЕ ГДЕ УПАЛО.
         *
         * `pc` отвечает, где произошёл отказ, `lr` — кто позвал ЭТУ функцию. Но memmove —
         * листовая: она не заводит кадр и не трогает x29, поэтому её `lr` показывает
         * ВЫЗЫВАЮЩЕГО, а вот кто позвал вызывающего — уже нет. 24.08 это стоило половины
         * дня: `lr_sym=hb_memory_write_inner` был верен, я закрыл в этой функции все семь
         * ветвей записи, и падение не сдвинулось ни на байт.
         *
         * ARM64 на macOS хранит кадры простой цепочкой: [x29] = предыдущий x29,
         * [x29+8] = адрес возврата. Идём по ней, пока адреса растут и попадают в
         * отображённое; `dladdr` переводит каждый в образ и ближайший символ.
         *
         * Чтение чужой памяти в обработчике сигнала опасно само по себе, поэтому шагов
         * не больше 24 и каждый указатель проверяется на выравнивание и рост. */
#if defined(__APPLE__) && defined(__aarch64__)
        if (context) {
            const ucontext_t* uc = (const ucontext_t*)context;
            if (uc->uc_mcontext) {
                unsigned long long fp = (unsigned long long)uc->uc_mcontext->__ss.__fp;
                unsigned long long prev = 0;
                hb_sig_printf( "macrunner-hb-sig-stack:\n");
                for (int d = 0; d < 24 && fp && fp > prev && (fp & 7u) == 0; d++) {
                    const unsigned long long* fr = (const unsigned long long*)(uintptr_t)fp;
                    unsigned long long nfp = fr[0], ret = fr[1];
                    Dl_info di;
                    int ok = ret ? dladdr((const void*)(uintptr_t)ret, &di) : 0;
                    const char* img = ok && di.dli_fname ? strrchr(di.dli_fname, '/') : NULL;
                    hb_sig_printf( "  #%-2d %#018llx  %s  %s\n", d, ret,
                            img ? img + 1 : (ok && di.dli_fname ? di.dli_fname : "?"),
                            ok && di.dli_sname ? di.dli_sname : "?");
                    prev = fp; fp = nfp;
                }
            }
        }
#endif
         } }
    /* Итерация 978: НАША запись в защищённую кодовую страницу проверяется ПЕРВОЙ — это
     * законное событие, а не отказ, и уводить его в путь безопасного копирования нельзя. */
    if (info && info->si_addr && hb_smc_handle_write_fault(info->si_addr)) return;

    /* MacRunner 2026-08-22, лейн ЛЕСТНИЦА, итерация 2651 (приказ 219, Л1) —
     * ★ ВТОРАЯ ДВЕРЬ БЫЛА ЗАБИТА ТОЛЬКО В СТЕНДЕ.
     *
     * Сторож `run_jit_block_with_signal_guard` (hb_runtime.c) ставит площадку приземления
     * на КАЖДОМ исполнении блока и умеет превратить отказ в выпущенном коде в аккуратный
     * `HB_ERR_MEMORY_FAULT`. Дверь к нему публичная — `hb_jit_runtime_handle_signal_fault`,
     * объявлена в `include/hb_runtime.h`. В wine её зовёт `segv_handler`
     * (`signal_arm64.c:4256`, 8 упоминаний), а ЭТОТ обработчик — не звал НИ РАЗУ.
     *
     * Цена молчания измерена: с четырьмя гейтами прямой памяти
     * (`JIT_DIRECT_MEM`, `JIT_DIRECT_SCALAR_MEM`, `JIT_NATIVE_MEM_IR`, `NATIVE_MEM_I386`)
     * стенд умирал `сигнал=11 addr=0x70000000 code=2`, `pc` в буфере выпуска, итога не
     * печатал вовсе. Проба-виновник — `jit_store_unmapped_faults` (hb_test_runner.c:7639):
     * она КЛАДЁТ `rbx=0x70000000` при памяти 1 МБ и требует `out.result == HB_ERR_MEMORY_FAULT`,
     * то есть проверяет ровно этот договор. Без гейтов запись уходит в помощника и договор
     * соблюдён; с гейтами она укладывается в выпуск, отказывает — и приземлиться некуда.
     *
     * Порядок и обе стороны (`pc` и `lr`) — как в wine. Перехватить чужой отказ дверь не
     * может по построению: она сама отклоняет всё, у чего `pc` вне блока и вне плиты
     * выпуска. Проверено тем же прогоном: отказ в `_platform_memmove` она не забрала.
     * На быстром пути НЕ СТОИТ НИЧЕГО — исполняется только по отказу. */
#if defined(__APPLE__) && defined(__aarch64__)
    {
        extern int hb_jit_runtime_handle_signal_fault(uint64_t pc, uint64_t fault_addr,
                                                      int signal, const void* host_context);
        const ucontext_t* uc = (const ucontext_t*)context;

        if (uc && uc->uc_mcontext)
        {
            uint64_t jpc = (uint64_t)uc->uc_mcontext->__ss.__pc;
            uint64_t jlr = (uint64_t)uc->uc_mcontext->__ss.__lr;
            uint64_t jaddr = (uint64_t)(uintptr_t)(info ? info->si_addr : NULL);

            /* ★★ КООРДИНАТОР 22.08 18:5x — ДВЕРЬ ЗА ГЕЙТОМ, УМОЛЧАНИЕ 0. ПРИЧИНА ИЗМЕРЕНА.
             *
             * Правка ЛЕСТНИЦЫ (итерация 2651) верна для СТЕНДА движка: `hb_test_runner` —
             * самостоятельный двоичный, обработчика wine у него нет, и без этой двери отказ
             * в выпущенном коде убивал процесс. С ней приёмка доходит до конца.
             *
             * Но в прогоне ПОД WINE дверь вредна, и это показано числом. Стенд i386 с четырьмя
             * гейтами прямой памяти, стенд с контролем ответа:
             *
             *     дверь=0   exit=0   35 562 пс   ВЕРНО      (без гейтов 112 828 пс)
             *     дверь=1   не доходит: exit=1, затем зависание
             *
             * Причина по устройству: под wine дверь УЖЕ ЗВАНА — `segv_handler`
             * (`signal_arm64.c:4256`, 8 упоминаний). Этот обработчик стоит РАНЬШЕ и, забрав
             * отказ себе, лишает wine его собственного пути обработки. У самостоятельного
             * стенда конкурента нет, поэтому там она и помогает.
             *
             * Умолчание 0 сохраняет поведение под wine дословно. Стенду достаточно
             * `MACRUNNER_HB_MEM_SEGV_JIT_DOOR=1`. Правильное решение — не гейт, а признак
             * «есть ли обработчик wine», и это работа ЛЕСТНИЦЫ, приказ 220. */
            /* ГЕЙТ СНЯТ 03.09.2026. Он спрашивал «чей сигнал», а решать надо
             * «ЧЕЙ КОД ОТКАЗАЛ». Умолчание было `!mem_segv_owned_by_host()`:
             * раз у wine есть свой обработчик — не лезем. Под игрой он есть
             * всегда, значит дверь была закрыта всегда, и отказ из выпущенного
             * кода уходил в обработчик wine, который про гостевую память не
             * знает. Он ничего не чинил, команда повторялась — ПЕТЛЯ.
             *
             * ЗАМЕР (первый профиль i386, reports/профиль-i386/заход3):
             * 89,4 % рабочей выборки в segv_handler, 11 отказов из 12 по ОДНОМУ
             * адресу 0x3004 с ОДНИМ pc; поток занимал ядро на 93,9 %.
             *
             * Гейт ничего не защищал: hb_jit_runtime_handle_signal_fault сам
             * проверяет, лежит ли pc в диапазоне выпущенного блока и плиты, и
             * отказывается со счётчиком иначе (hb_runtime.c). То есть отбор по
             * происхождению уже сделан внутри, а гейт лишь держал дверь.
             *
             * И приёмка всё это время шла С ОТКРЫТОЙ дверью
             * (Makefile: MACRUNNER_HB_MEM_SEGV_JIT_DOOR=1 ./hb_test_runner),
             * а игра — с закрытой: проверяли одну сборку, поставляли другую. */
            if (hb_jit_runtime_handle_signal_fault(jpc, jaddr, sig, context) ||
                hb_jit_runtime_handle_signal_fault(jlr, jaddr, sig, context))
                return;
        }
    }
#endif
    if (hb_safe_jmp_get()) {
        sigset_t only;
        /* Пункт 37: на macOS si_code == 0 означает «сигнал не аппаратный» (raise/kill).
         * Такой перехватывать нельзя — он не наш. Под тем же гейтом, чтобы умолчание
         * осталось дословно прежним. */
        if (hb_sig_landing_enabled() && info && info->si_code <= 0) goto chain;
        sigemptyset(&only);
        sigaddset(&only, sig);
        sigprocmask(SIG_UNBLOCK, &only, NULL);
        if (hb_sig_landing_enabled() && context) {
            ucontext_t* uc = (ucontext_t*)context;
            /* Свидетель ТОЧКИ РЕШЕНИЯ: отдельно от свидетеля площадки, чтобы различать
             * «ветка не взята» и «взята, но перенаправление не сработало». */
            static int nd;
            if (nd++ < 8) { hb_sig_printf( "macrunner-hb-landing-copy-arm: n=%d\n", nd);  }
            uc->uc_mcontext->__ss.__pc = (uintptr_t)&hb_copy_fault_landing;
            return;                 /* ШТАТНЫЙ выход: _sigtramp доведёт sigreturn */
        }
        hb_vhod_snyat();   /* побег мимо обёртки — отметку снять здесь */
        siglongjmp(*hb_safe_jmp_get(), 1);
    }
chain:
    if (sig == SIGSEGV && g_prev_segv.sa_sigaction) {
        g_prev_segv.sa_sigaction(sig, info, context);
    } else if (sig == SIGBUS && g_prev_bus.sa_sigaction) {
        g_prev_bus.sa_sigaction(sig, info, context);
    } else {
        signal(sig, SIG_DFL);
        raise(sig);
    }
}

/* ═══ ВХОД И ВЫХОД СЧИТАЮТСЯ ОТДЕЛЬНО ═══
 *
 * Профиль i386 показал поток, держащий ядро внутри обработчика, при том что
 * входов за прогон всего 32 (наш) и 256 (wine). Столько входов не дают
 * тридцати секунд — значит ОДИН вход не возвращается. Разность «вошло минус
 * вышло» это доказывает, а занятые слоты называют, КАКОЙ именно отказ заклинил.
 *
 * Слот занимается на входе и освобождается на выходе. Побег через siglongjmp
 * снимает отметку сам (иначе он читался бы как зависание). */
#define HB_VHOD_SLOTOV 16

struct hb_vhod { uint64_t tid, addr, pc, zanyat; };
static struct hb_vhod g_vhod[HB_VHOD_SLOTOV];
static uint64_t g_vhodov, g_vyhodov;
static __thread int g_moj_slot = -1;

static void hb_vhod_snyat(void)
{
    if (g_moj_slot >= 0) {
        __atomic_store_n(&g_vhod[g_moj_slot].zanyat, 0, __ATOMIC_RELAXED);
        g_moj_slot = -1;
        __atomic_add_fetch(&g_vyhodov, 1, __ATOMIC_RELAXED);
    }
}

static void safe_copy_signal_handler(int sig, siginfo_t* info, void* context)
{
    uint64_t pc = 0;
    int i;

#if defined(__APPLE__) && defined(__aarch64__)
    if (context) {
        const ucontext_t* uc = (const ucontext_t*)context;
        if (uc->uc_mcontext) pc = (uint64_t)uc->uc_mcontext->__ss.__pc;
    }
#endif
    __atomic_add_fetch(&g_vhodov, 1, __ATOMIC_RELAXED);
    for (i = 0; i < HB_VHOD_SLOTOV; i++) {
        uint64_t o = 0;
        if (__atomic_compare_exchange_n(&g_vhod[i].zanyat, &o, 1, 0,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            g_vhod[i].tid = (uint64_t)(uintptr_t)pthread_self();
            g_vhod[i].addr = info ? (uint64_t)(uintptr_t)info->si_addr : 0;
            g_vhod[i].pc = pc;
            g_moj_slot = i;
            break;
        }
    }

    hb_otkaz_uchest(info, context);
    safe_copy_signal_handler_telo(sig, info, context);
    hb_vhod_snyat();
}

/* Сводка зовётся переписью: печатает разность и НАЗЫВАЕТ зависшие входы. */
static void hb_vhod_svodka(void)
{
    uint64_t vh = __atomic_load_n(&g_vhodov, __ATOMIC_RELAXED);
    uint64_t vy = __atomic_load_n(&g_vyhodov, __ATOMIC_RELAXED);
    int i;

    /* СЕБЯ НЕ СЧИТАТЬ. Сводка зовётся ИЗНУТРИ обработчика, поэтому его
     * собственный слот занят всегда — без этой поправки прибор показывал
     * «ЗАСТРЯЛО=1» на каждом прогоне и называл текущий отказ зависшим. */
    hb_sig_printf("macrunner-hb-вход-выход: вошло=%llu вышло=%llu ЗАСТРЯЛО=%lld\n",
                  (unsigned long long)vh, (unsigned long long)vy,
                  (long long)(vh - vy - 1));
    for (i = 0; i < HB_VHOD_SLOTOV; i++) {
        if (i == g_moj_slot) continue;              /* это мы сами */
        if (!__atomic_load_n(&g_vhod[i].zanyat, __ATOMIC_RELAXED)) continue;
        hb_sig_printf("macrunner-hb-застрял: tid=%#llx addr=%#llx pc=%#llx\n",
                      (unsigned long long)g_vhod[i].tid,
                      (unsigned long long)g_vhod[i].addr,
                      (unsigned long long)g_vhod[i].pc);
    }
}


static int hb_fast_sigjmp_enabled(void) {
    static int enabled = -1;
    if (enabled < 0) {
        const char* v = hb_gate( HB_GATE_HB_FAST_SIGJMP );
        /* ★ MacRunner 2026-08-17, лейн ЛЕСТНИЦА, итерация 1710. УМОЛЧАНИЕ ПЕРЕВЕДЕНО В ВКЛ.
         * Замер этого дня на стенде Diablo ступень 1 (веха = первый полноэкранный растр):
         *     гейт ВКЛ   45,12 ± 0,18 с (n=5)
         *     гейт ВЫКЛ  64,70 с (n=2)      → выключенное умолчание стоило 19,58 с
         * Разрыв в сто с лишним sd. Единица в sigsetjmp заставляет Apple-овский код сохранять
         * маску сигналов и альтернативный стек (sigprocmask + __sigaltstack); при нуле не
         * сохраняем ничего, а разблокировку делает сам обработчик — см. SIG_UNBLOCK выше.
         * Прежнее умолчание ВЫКЛ означало, что лечение есть, а прогон его не получает: ровно
         * тот класс, что в правилах проекта помечен как главная потеря времени.
         * Откат: MACRUNNER_HB_FAST_SIGJMP=0. */
        enabled = (v && v[0]) ? (v[0] != '0') : 1;
        /* MacRunner 2026-08-17, лейн ЛЕСТНИЦА, итерация 1513 — ДОКАЗАТЕЛЬСТВО ДОСТАВКИ ГЕЙТА.
         * Приказ 162 требует доказывать доставку гейта, а не заявлять её. Наличие строки в
         * двоичном (проверено 1510) доказывает, что гейт СОБРАН, но не что он ДОЕХАЛ: прогон с
         * потерянной переменной выглядит точно так же — ровно это случилось 17.08 утром, когда
         * из окружения пропали восемь переменных и набор молча не стартовал.
         * Печать срабатывает ОДИН раз за процесс (значение кладётся в static), стоит ноль.
         * fprintf, а не ERR/MESSAGE: каналы wine до наших журналов не доходят. */
        fprintf(stderr, "macrunner-gate: MACRUNNER_HB_FAST_SIGJMP=%d\n", enabled);
        fflush(stderr);
    }
    return enabled;
}

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: СОХРАНЯТЬ УСЛОВИЯ ПРЕЖНЕГО ОБРАБОТЧИКА.
 *
 * Мы ставим свой обработчик SIGSEGV/SIGBUS ОДИН РАЗ НА ПРОЦЕСС и не снимаем его никогда,
 * то есть перехватываем эти сигналы у Wine навсегда. Ставили с `sa_flags = SA_SIGINFO`:
 * без `SA_ONSTACK` и с пустой маской. А обработчик Wine написан в расчёте на
 * альтернативный сигнальный стек и на свою маску — и вызывается у нас ПРЯМЫМ вызовом,
 * то есть исполняется в чужих условиях.
 *
 * Это выглядело правдоподобной причиной `brk #1` в `_sigtramp`+76. Правка перенимает у
 * прежнего обработчика `SA_ONSTACK` и его маску; гейт `MACRUNNER_HB_SIGCHAIN_KEEP_FLAGS`,
 * умолчание ВЫКЛ.
 *
 * ★ ИЗМЕРЕНО 10.08 (итерация 149): ЭФФЕКТА НЕТ. Двенадцать прогонов, шесть на руку, при
 * обусловливании на моду руки неотличимы — в моде 316 по одному отказу в обеих, в моде 860
 * по нулю в обеих, разброса внутри клеток нет. Версия «обработчик исполняется в чужих
 * условиях» ОПРОВЕРГНУТА. Код оставлен выключенным как отрицательный результат: он
 * безвреден и избавляет следующего от повторной проверки той же догадки. */
static int hb_sigchain_keep_flags_enabled(void) {
    static int enabled = -1;
    if (enabled < 0) { const char* v = hb_gate( HB_GATE_HB_SIGCHAIN_KEEP_FLAGS );
                       enabled = (v && v[0] && v[0] != '0') ? 1 : 0; }
    return enabled;
}

/* Итерация 2660: признак обязан быть ПРОВЕРЯЕМЫМ, а не догадкой. Печатаем один раз,
 * кто владел SIGSEGV до нас: образ и ближайший символ. Под wine здесь ожидается его
 * `ntdll.so`, у самостоятельного стенда — «нет». dladdr зовём ЗДЕСЬ, а не в обработчике:
 * в обработчике он не async-signal-safe. */
static void mem_segv_probe_prev_owner(void) {
    Dl_info di;
    void* h = (void*)(uintptr_t)g_prev_segv.sa_sigaction;
    int named = (h && h != (void*)SIG_DFL && h != (void*)SIG_IGN) ? dladdr(h, &di) : 0;
    fprintf(stderr, "macrunner-hb-segv-prev: владелец=%s обработчик=%p образ=%s символ=%s дверь=%d\n",
            mem_segv_owned_by_host() ? "ЧУЖОЙ" : "нет",
            h,
            named && di.dli_fname ? di.dli_fname : "-",
            named && di.dli_sname ? di.dli_sname : "-",
            1);   /* дверь снята: обработчик JIT спрашивается всегда */
    fflush(stderr);
}

static void install_sig_handlers(void) {
    /* ★★★ MacRunner 2026-09-04 — СНАЧАЛА ЧТЕНИЕ, И ТОЛЬКО ПОТОМ АТОМАРНАЯ ЗАПИСЬ.
     *
     * Здесь стоял голый `__atomic_test_and_set`. Он выполняется на КАЖДОЕ ограждённое
     * копирование памяти гостя, то есть на всём протяжении прогона, хотя обработчики
     * ставятся ОДИН раз за процесс: 1 350 565 888 постановок ограждения за 38 с работы
     * стенда benchz-pe32 (счётчик `macrunner-hb-fence-census`, ряд монотонен, один
     * процесс). Это не проверка флага — это чтение-изменение-запись по общей строке кеша.
     *
     * ЦЕНА НАЗВАНА ЧИСЛОМ, а не «дорого», и названа НАСТОЯЩИМ КОДОМ, а не подобием.
     * Кратная форма прибора (`scripts/цена-операции атом16`, шестнадцать RMW по разным
     * строкам кеша) давала 1,32 нс — и ЗАВЫСИЛА вчетверо: в движке флаг один и живёт
     * в кеше первого уровня. Настоящее число снято `tests/hb_fence_cost_bench`, который
     * зовёт сам `hb_memory_read`/`hb_memory_write` по области guest32:
     *     чтение 4 Б   25,58 -> 25,24 нс   (−0,34 нс)
     *     запись 4 Б   32,60 -> 32,31 нс   (−0,29 нс)
     * Пять пар вперемежку, ПОСЛЕ быстрее в 5 из 5 на обеих руках, разброс 0,5-2,8 %.
     *
     * ПРОИЗВЕДЕНИЕ: 35 544 949 постановок/с (перепись стенда benchz-pe32, медиана 321
     * интервала, разброс 1,7 %) × 0,31 нс = 1,1 % времени стенда i386. Даром: ни гейта,
     * ни смены поведения.
     *
     * Правка БЕЗУСЛОВНА и гейта не имеет: доказанное лечение — не леса. Семантика не
     * меняется и даже усиливается — путь установки по-прежнему арбитрируется тем же RMW
     * (гонку разрешает он), а быстрый путь читает с `acquire`, чего прежний `relaxed`
     * не давал. В выпущенном коде проверено глазами: фаст-пат стал `ldaprb`+`cbz`+`ret`
     * ЧЕТЫРЬМЯ командами и БЕЗ пролога кадра — прежде пролог ставился до RMW. */
    if (__atomic_load_n(&g_sig_handlers_installed, __ATOMIC_ACQUIRE)) return;
    if (__atomic_test_and_set(&g_sig_handlers_installed, __ATOMIC_RELAXED)) return;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = safe_copy_signal_handler;
    sa.sa_flags = SA_SIGINFO;
    if (hb_sigchain_keep_flags_enabled()) {
        struct sigaction old_segv, old_bus;
        memset(&old_segv, 0, sizeof(old_segv));
        memset(&old_bus, 0, sizeof(old_bus));
        sigaction(SIGSEGV, NULL, &old_segv);
        sigaction(SIGBUS, NULL, &old_bus);
        g_prev_segv = old_segv;
        g_prev_bus = old_bus;
        sa.sa_flags = SA_SIGINFO | (old_segv.sa_flags & SA_ONSTACK);
        sa.sa_mask = old_segv.sa_mask;
        sigaction(SIGSEGV, &sa, NULL);
        sa.sa_flags = SA_SIGINFO | (old_bus.sa_flags & SA_ONSTACK);
        sa.sa_mask = old_bus.sa_mask;
        sigaction(SIGBUS, &sa, NULL);
        mem_segv_probe_prev_owner();
        return;
    }
    sigaction(SIGSEGV, &sa, &g_prev_segv);
    sigaction(SIGBUS, &sa, &g_prev_bus);
    mem_segv_probe_prev_owner();
}
#endif

#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

/* MacRunner 2026-06-23 (ABZU native-twin probe): targeted trace for the .data
 * global at guest VA 0x1429413d8 (RVA 0x29413d8). Logs, for each read/write that
 * touches the window, the region HB resolves (base/host_base/perm) and the host
 * pointer actually used — to confirm whether the RIP-relative STORE and LOAD of
 * the SAME guest RVA resolve to DIFFERENT host addresses. Env-gated. */
#define MACRUNNER_HB_DATADIVERGE_LO  0x142941000ULL
#define MACRUNNER_HB_DATADIVERGE_HI  0x142942000ULL
typedef struct hb_memory_environment {
    int trace_datadiverge;
    int disable_hot_cache;
    int trace_guest32_alias;
    int trace_native_writes;
    int trace_live_vm_access_fail;
    int live_vm_write_mach;
    int trace_store80;
    int trace_memcpy_len;
    int trace_jit_helper_fail;
    /* A/B arm selector for the hb_memory_protect multi-region path, so both arms
     * live in ONE binary: the list walk that shipped, or the treap range walk.
     * See the memmeter block below for why this is a switch and not two builds. */
    int memprotect_walk_list;
    unsigned long long trace_guest_write_start;
    unsigned long long trace_guest_write_stop;
} hb_memory_environment_t;

static hb_memory_environment_t macrunner_hb_memory_environment;
static int macrunner_hb_memory_environment_initialized;

static int hb_memory_env_enabled(const char* name) {
    const char* value = hb_env(name);
    return value && value[0] && value[0] != '0';
}

void hb_memory_init_environment(void) {
    const char* live_fail;
    const char* live_mach;
    const char* guest_write;
    const char* trace_memcpy_len;
    char* endp = NULL;
    unsigned long long start = 0, stop = 0;

    if (__atomic_load_n(&macrunner_hb_memory_environment_initialized, __ATOMIC_ACQUIRE)) return;

    macrunner_hb_memory_environment.trace_datadiverge =
        hb_memory_env_enabled("MACRUNNER_HB_TRACE_DATADIVERGE");
    macrunner_hb_memory_environment.disable_hot_cache =
        hb_memory_env_enabled("MACRUNNER_HB_DISABLE_HOT_CACHE");
    macrunner_hb_memory_environment.trace_guest32_alias =
        hb_memory_env_enabled("MACRUNNER_HB_TRACE_GUEST32_ALIAS");
    macrunner_hb_memory_environment.trace_native_writes =
        hb_memory_env_enabled("MACRUNNER_HB_TRACE_NATIVE_WRITES");
    live_fail = hb_gate( HB_GATE_HB_TRACE_LIVE_VM_ACCESS_FAIL );
    if (!live_fail || !live_fail[0]) live_fail = hb_gate( HB_GATE_HB_TRACE_LIVE_VM_WRITE_FAIL );
    macrunner_hb_memory_environment.trace_live_vm_access_fail =
        live_fail && live_fail[0] && live_fail[0] != '0';
    live_mach = hb_gate( HB_GATE_HB_LIVE_VM_WRITE_MACH );
    macrunner_hb_memory_environment.live_vm_write_mach =
        live_mach && live_mach[0] && atoi(live_mach) != 0;
    macrunner_hb_memory_environment.trace_store80 =
        hb_gate( HB_GATE_HB_TRACE_STORE80 ) != NULL;
    trace_memcpy_len = hb_gate( HB_GATE_HB_TRACE_MEMCPY_LEN );
    macrunner_hb_memory_environment.trace_memcpy_len =
        trace_memcpy_len && trace_memcpy_len[0];
    macrunner_hb_memory_environment.trace_jit_helper_fail =
        hb_gate( HB_GATE_HB_TRACE_JIT_HELPER_FAIL ) != NULL;
    /* Default is the treap range walk.  MACRUNNER_HB_MEMPROTECT_WALK=list selects
     * the pre-fix full-list scan, which is the control arm of the A/B. */
    {
        const char* walk = hb_gate( HB_GATE_HB_MEMPROTECT_WALK );
        macrunner_hb_memory_environment.memprotect_walk_list =
            walk && walk[0] == 'l';
    }

    guest_write = hb_gate( HB_GATE_HB_TRACE_GUEST_WRITE );
    if (guest_write && guest_write[0]) {
        start = strtoull(guest_write, &endp, 0);
        if (endp != guest_write)
            stop = (*endp == '-' || *endp == ':') ? strtoull(endp + 1, NULL, 0) : start + 1;
        else
            start = 0;
    }
    macrunner_hb_memory_environment.trace_guest_write_start = start;
    macrunner_hb_memory_environment.trace_guest_write_stop = stop;
    __atomic_store_n(&macrunner_hb_memory_environment_initialized, 1, __ATOMIC_RELEASE);
}

/* ---------------------------------------------------------------------------
 * memmeter -- direct measurement of the region-map cost.
 *
 * WHY IT EXISTS.  A `sample` of a live HK run put 913 of 2795 critical-path
 * samples inside hb_memory_protect as a childless leaf, and that was read as
 * "the O(N) list walk is long".  That is an INFERENCE from a sample ratio: it
 * assumes both which branch was hot and how long the list is.  Neither had been
 * measured.  These counters measure both, so the next run settles it instead of
 * arguing about it.
 *
 * DISCIPLINE, learned from this lane's own losses:
 *  - ALWAYS ON, not env-gated.  Only one HK title slot exists and three lanes
 *    compete for it, so every foreign lane's run must yield this data for free.
 *    The counters are relaxed atomic adds; the clock is read on 1 call in 64.
 *  - PERIODIC, not atexit.  A run killed by its timeout emits no atexit summary,
 *    and two of this lane's A/Bs were already lost that way.
 *  - fprintf, not snprintf into a fixed buffer.  The 1024-byte buffers in this
 *    tree return SILENTLY on overflow; a report line that can vanish is worse
 *    than none.  One fprintf is atomic under the FILE lock.
 *  - Counts are exact and uncapped.  A zero is a real zero.
 *
 * The decisive ratios the line reports:
 *    mp_visit / mp_walk   = nodes touched per multi-region protect  (walk length)
 *    regions              = live region count N at report time
 *    splits               = regions created by splitting, which NOTHING ever
 *                           merges back, so N only grows.
 */
static unsigned long long mm_mp_calls;      /* hb_memory_protect entries          */
static unsigned long long mm_mp_fast;
extern unsigned long long hb_ir_blocks_created;
extern unsigned long long hb_ir_blocks_destroyed;
unsigned long long hb_alloc_calls;
unsigned long long hb_free_calls;
uintptr_t          hb_alloc_site_pc[HB_ALLOC_SITES];
unsigned long long hb_alloc_site_n[HB_ALLOC_SITES];
unsigned long long hb_alloc_site_bytes[HB_ALLOC_SITES];

/* Верхняя пятёрка мест выделения: адрес возврата разрешается в имя оффлайн через
 * `atos -o ntdll.so -l <база>`, как и прочие хостовые адреса в этом проекте. */
static void hb_dump_alloc_sites(void) {
    unsigned top[5] = {0,0,0,0,0};
    for (size_t i = 0; i < HB_ALLOC_SITES; i++) {
        unsigned long long n = __atomic_load_n(&hb_alloc_site_n[i], __ATOMIC_RELAXED);
        if (!n) continue;
        for (int k = 0; k < 5; k++) {
            if (n > __atomic_load_n(&hb_alloc_site_n[top[k]], __ATOMIC_RELAXED)) {
                for (int j = 4; j > k; j--) top[j] = top[j-1];
                top[k] = (unsigned)i; break;
            }
        }
    }
    for (int k = 0; k < 5; k++) {
        unsigned long long n = __atomic_load_n(&hb_alloc_site_n[top[k]], __ATOMIC_RELAXED);
        if (!n) continue;
        fprintf(stderr, "macrunner-hb-alloc-site: rank=%d pc=%p calls=%llu bytes=%llu\n",
                k, (void*)__atomic_load_n(&hb_alloc_site_pc[top[k]], __ATOMIC_RELAXED), n,
                __atomic_load_n(&hb_alloc_site_bytes[top[k]], __ATOMIC_RELAXED));
    }
    fflush(stderr);
}
static unsigned long long mm_mp_skipped;    /* сэкономленные вызовы mprotect */

/* MACRUNNER_HB_REDUNDANT_MPROTECT=1 возвращает прежнее поведение (звать ядро всегда). */
static unsigned long long mm_mp_reenter;    /* contained-in-one-region split path */
static unsigned long long mm_mp_exact;      /* exact base+size region             */
static unsigned long long mm_mp_walk;       /* reached the multi-region walk      */
static unsigned long long mm_mp_visit;      /* nodes examined by that walk        */
static unsigned long long mm_mp_apply;      /* regions whose perm was written     */
static unsigned long long mm_mp_notfound;   /* walk matched nothing               */
static unsigned long long mm_mp_ns;         /* ns in protect, sampled 1/64        */
static unsigned long long mm_mp_ns_n;       /* how many calls that ns covers      */
static unsigned long long mm_slr_calls;     /* hb_memory_sync_live_range entries  */
static unsigned long long mm_slr_fast;      /* early return, map already correct  */
static unsigned long long mm_slr_scan;      /* nodes examined by its list scans   */
static unsigned long long mm_slr_repl;      /* took the replace+rebuild path      */
static unsigned long long mm_slr_ns;
static unsigned long long mm_slr_ns_n;
static unsigned long long mm_maps;          /* hb_memory_t instances created      */
static unsigned long long mm_ovl_calls;     /* any_overlap() calls (both map paths)*/
static unsigned long long mm_ovl_scan;      /* list nodes it examined              */
static unsigned long long mm_splits;        /* split_region_at allocations        */
static unsigned long long mm_rebuilds;      /* rebuild_region_tree calls          */
static unsigned long long mm_rebuild_nodes; /* nodes reinserted by those rebuilds */

#define MM_CLOCK_MASK      0x3fULL              /* time 1 call in 64 */
#define MM_REPORT_PERIOD_NS 5000000000ULL       /* one line per 5 s */
#define MM_REGION_WALK_CAP 4000000ULL   /* torn-list guard; the map is never this big */

/* The report cadence is TIME-based, not count-based.  A count trigger has to
 * guess the call rate: pick 262144 and a run that calls protect 100 times a
 * second emits its first line 45 minutes in, i.e. never, while a run calling it
 * a million times a second drowns the log.  Both failures are silent.  Keyed on
 * time, the line spacing is also directly usable as a time series. */
static unsigned long long mm_last_report_ns;

static bool mm_due(unsigned long long now) {
    unsigned long long last = __atomic_load_n(&mm_last_report_ns, __ATOMIC_RELAXED);
    if (now - last < MM_REPORT_PERIOD_NS) return false;
    /* One winner per period; losers skip rather than pile up duplicate lines. */
    return __atomic_compare_exchange_n(&mm_last_report_ns, &last, now, false,
                                       __ATOMIC_RELAXED, __ATOMIC_RELAXED);
}

static unsigned long long mm_now_ns(void) {
#ifdef __APPLE__
    return (unsigned long long)clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
#endif
}

static void mm_report(hb_memory_t* mem, const char* where) {
    unsigned long long n = 0;
    struct timeval tv;

    /* This walk is as safe as any_overlap(), which already runs unlocked on the
     * normal path -- but it runs once per 262144 calls, so cap it rather than
     * risk spinning on a list observed mid-mutation. */
    for (hb_region_t* r = mem ? mem->regions : NULL; r; r = r->next) {
        if (++n >= MM_REGION_WALK_CAP) break;
    }

    gettimeofday(&tv, NULL);
    /* `mem=` and `maps=` matter because the region map is PER GUEST THREAD --
     * macrunner_hb.c assigns ctx->memory = hb_memory_create(0) on each x64
     * context, and HK has been measured with 115 of them.  The global counters
     * aggregate across every map (so mp_visit/mp_walk, the walk length, is
     * map-agnostic and sound), but `regions` is one map's list length, and
     * without an identity a growth curve would silently interleave 115 of them. */
    fprintf(stderr,
            "macrunner-hb-memmeter: where=%s mem=%p maps=%llu epoch=%lld.%03d regions=%llu "
            "mp_calls=%llu mp_fast=%llu mp_skipped=%llu hb_alloc=%llu hb_free=%llu hb_live=%lld "
            "ir_created=%llu ir_destroyed=%llu ir_live=%lld "
            "mp_reenter=%llu mp_exact=%llu mp_walk=%llu "
            "mp_visit=%llu mp_apply=%llu mp_notfound=%llu mp_ns=%llu mp_ns_n=%llu "
            "slr_calls=%llu slr_fast=%llu slr_scan=%llu slr_repl=%llu slr_ns=%llu slr_ns_n=%llu "
            "ovl_calls=%llu ovl_scan=%llu "
            "splits=%llu rebuilds=%llu rebuild_nodes=%llu walk=%s\n",
            where, (void*)mem, __atomic_load_n(&mm_maps, __ATOMIC_RELAXED),
            (long long)tv.tv_sec, (int)(tv.tv_usec / 1000), n,
            __atomic_load_n(&mm_mp_calls, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_mp_fast, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_mp_skipped, __ATOMIC_RELAXED),
            __atomic_load_n(&hb_alloc_calls, __ATOMIC_RELAXED),
            __atomic_load_n(&hb_free_calls, __ATOMIC_RELAXED),
            (long long)(__atomic_load_n(&hb_alloc_calls, __ATOMIC_RELAXED) -
                        __atomic_load_n(&hb_free_calls, __ATOMIC_RELAXED)),
            __atomic_load_n(&hb_ir_blocks_created, __ATOMIC_RELAXED),
            __atomic_load_n(&hb_ir_blocks_destroyed, __ATOMIC_RELAXED),
            (long long)(__atomic_load_n(&hb_ir_blocks_created, __ATOMIC_RELAXED) -
                        __atomic_load_n(&hb_ir_blocks_destroyed, __ATOMIC_RELAXED)),
            __atomic_load_n(&mm_mp_reenter, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_mp_exact, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_mp_walk, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_mp_visit, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_mp_apply, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_mp_notfound, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_mp_ns, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_mp_ns_n, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_slr_calls, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_slr_fast, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_slr_scan, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_slr_repl, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_slr_ns, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_slr_ns_n, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_ovl_calls, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_ovl_scan, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_splits, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_rebuilds, __ATOMIC_RELAXED),
            __atomic_load_n(&mm_rebuild_nodes, __ATOMIC_RELAXED),
            macrunner_hb_memory_environment.memprotect_walk_list ? "list" : "tree");
    hb_dump_alloc_sites();
    fflush(stderr);
}

static int macrunner_hb_trace_datadiverge_enabled(void) {
    return macrunner_hb_memory_environment.trace_datadiverge;
}
static int macrunner_hb_datadiverge_hit(uint64_t addr, size_t size) {
    if (!macrunner_hb_trace_datadiverge_enabled()) return 0;
    if (addr + size < addr) return 0;
    return !(addr + size <= MACRUNNER_HB_DATADIVERGE_LO || addr >= MACRUNNER_HB_DATADIVERGE_HI);
}

static int macrunner_hb_disable_hot_cache_enabled(void) {
    return macrunner_hb_memory_environment.disable_hot_cache;
}

typedef struct hb_hot_cache_tls {
    hb_memory_t* mem;
    uint64_t epoch;
    hb_region_t* slot[HB_MEMORY_HOT_CACHE_SLOTS];
} hb_hot_cache_tls_t;

/* MacRunner 2026-08-03 — the per-thread hot cache without dynamic TLS.
 *
 * Measured on a live boot (10 s sample, storm phase): the busiest thread spent 8484 of its 8521
 * samples at `_tlv_get_addr + 0`, reached from hb_memory_read on EVERY guest memory read, itself
 * reached from the interpreter.  That is not "called often" — offset 0 with 99.6 % of a thread's
 * samples is a stall.  On Darwin a `__thread` variable in a dynamically loaded dylib has no fast
 * path: each access is a real call into libdyld, and this one sits on the hottest path we have.
 *
 * pthread_self() on arm64 reads TPIDRRO_EL0 — one instruction, no call, no lock.  A direct-mapped
 * table keyed on it gives the same per-thread cache without ever entering libdyld.  A collision
 * costs a cache reset (the entry carries its owner and is reset when it does not match), which is
 * exactly what an epoch change already does, so a collision is a slow read and never a wrong one.
 *
 * Gate MACRUNNER_HB_TLS_HOTCACHE=0 restores the __thread version for A/B. */
#define HB_HOT_CACHE_THREAD_SLOTS 256
static hb_hot_cache_tls_t g_hot_cache_tab[HB_HOT_CACHE_THREAD_SLOTS];
static uint64_t g_hot_cache_owner[HB_HOT_CACHE_THREAD_SLOTS];

/* MacRunner 2026-08-23, КООРДИНАТОР — НОМЕР ПОТОКА ОДНОЙ КОМАНДОЙ.
 *
 * Профиль честной нагрузки: `pthread_self` — 5,9 % рабочего потока, и весь он приходит
 * ИЗ ЭТОЙ ФУНКЦИИ (580 отсчётов из 595 родителем стоит `hot_cache_lookup`). Слот кеша
 * ищется по номеру потока на КАЖДЫЙ просмотр, а `pthread_self` на macOS — переход во
 * внешнюю функцию libsystem.
 *
 * Таблице нужен не pthread_t, а любое УСТОЙЧИВОЕ РАЗЛИЧАЮЩЕЕ число потока: значение
 * только хешируется и сравнивается само с собой.
 *
 * ★ `__builtin_thread_pointer()` ДЛЯ ЭТОГО НЕ ГОДИТСЯ, и это проверено, а не предположено:
 * на macOS он читает `TPIDR_EL0`, а там не номер потока — четыре потока дали ДВА разных
 * значения, и один поток дважды дал разное (0x2005 и 0x2007). Взял бы его — получил бы
 * общий слот кеша у разных потоков, то есть чужую область в ответе.
 * Годится `TPIDRRO_EL0`: четыре потока — четыре устойчивых различных значения.
 * Компилируется в одну команду `mrs`.
 *
 * Смена источника безопасна и при уже заполненной таблице: несовпадение владельца слота
 * обрабатывается сбросом слота — ровно та же ветвь, что при первом обращении потока.
 *
 * Гейт MACRUNNER_HB_TP_THREAD_ID СНЯТ 02.09.2026: правка безусловна,
 * выключенная ветка возвращала известный дефект (scripts/гейты.py). */
static inline uint64_t hb_thread_id_fast(void) {
#if defined(__aarch64__) && defined(__APPLE__)
    uint64_t v;
    __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(v));
    /* Младшие три бита на Darwin несут номер ядра и меняются при переезде потока между
     * ядрами — маскируем, иначе один поток получал бы разные слоты. Проверено: с маской
     * четыре потока дают четыре различных устойчивых значения. */
    return v & ~(uint64_t)7;
#endif
    return (uint64_t)(uintptr_t)pthread_self();
}

static hb_hot_cache_tls_t* hb_hot_cache_slot(void) {
    uint64_t self;
    size_t i;

    self = hb_thread_id_fast();
    i = (size_t)((self >> 6) * 11400714819323198485ull >> 56) & (HB_HOT_CACHE_THREAD_SLOTS - 1);
    if (g_hot_cache_owner[i] != self) {
        g_hot_cache_owner[i] = self;
        g_hot_cache_tab[i].mem = NULL;
        g_hot_cache_tab[i].epoch = 0;
        memset(g_hot_cache_tab[i].slot, 0, sizeof(g_hot_cache_tab[i].slot));
    }
    return &g_hot_cache_tab[i];
}

static uint64_t hot_cache_epoch(hb_memory_t* mem) {
    return __atomic_load_n(&mem->hot_gen, __ATOMIC_ACQUIRE);
}

static void hot_cache_reset_tls(hb_memory_t* mem, uint64_t epoch) {
    hb_hot_cache_tls_t* const tls = hb_hot_cache_slot();
    tls->mem = mem;
    tls->epoch = epoch;
    memset(tls->slot, 0, sizeof(tls->slot));
}

/* MacRunner 2026-07-31 — is the region hot cache actually working?
 *
 * Clean critical-thread profile (instruments off) puts the guest-MMU group at 10.5 %:
 * find_region_normalized 3.0 % + hb_memory_read 5.4 % + hb_memory_write 2.1 %. The lookup already has an
 * O(log n) treap AND this per-thread MRU cache in front of it, so the cost is either cache misses falling
 * through to the treap or the cache being wiped. The wipe is the suspicious part: hot_cache_reset_tls clears
 * EVERY slot whenever the region epoch changes, and Mono maps and unmaps constantly, so a high reset rate
 * would mean the cache is permanently cold no matter how good its locality is.
 *
 * Three counters answer it from one run: lookups, hits, and resets. Gated and per-thread, reported every
 * 8 M lookups. hit_pct says whether the cache earns its keep; resets_per_1k_lookups says whether epoch churn
 * is destroying it. */
static __thread uint64_t t_hc_lookups, t_hc_hits, t_hc_resets, t_hc_next;

/* MacRunner 2026-07-31 — first measurement said 67.7 % hits / 0.04 resets per 1k lookups, so epoch churn is
 * NOT what costs us; the misses are. Two follow-up questions decide what to do about them, and both are
 * answerable in one run:
 *
 *   (a) How deep do HITS sit? The scan is 16 slots wide and linear. If hits concentrate in slot 0-1 the
 *       remaining 14 comparisons are dead weight on every miss.
 *   (b) Are MISSES curable by capacity? A miss that resolves to a real region (hot_cache_insert runs) can be
 *       caught by a bigger cache. A miss where the treap returns NULL — an unmapped guest address — can never
 *       be cached at any size, and needs a negative cache instead. t_hc_shadow is a 64-deep true-LRU shadow
 *       of the same reference stream, so the depth at which a missed region is found in it prices slots=32/64
 *       exactly, without rebuilding. */
#define HC_SHADOW 64
static __thread int t_hc_depth_hist[HB_MEMORY_HOT_CACHE_SLOTS];
static __thread uint64_t t_hc_miss_resolved, t_hc_shadow_absent;
static __thread hb_region_t* t_hc_shadow[HC_SHADOW];
static __thread uint64_t t_hc_shadow_hist[HC_SHADOW];
static __thread int t_hc_miss_pending;

static int trace_hot_cache_stats_enabled(void);
__thread uint64_t hb_trace_current_block_addr;
/* Which C caller produces the NULL answers. The guest-PC histogram came back diffuse (top block <=4 % of
 * 112.9 M), so the nulls are not one loop; the remaining question is whether they are a PROBE whose NULL is a
 * normal answer (hb_memory_host_ptr deciding the JIT cannot take a direct pointer) rather than a failed access.
 * One TLS tag set at each of the five resolve call sites answers it. */
enum { RSITE_OTHER = 0, RSITE_READ, RSITE_WRITE, RSITE_HOST_PTR, RSITE_FIND_REGION, RSITE_CHECK_PERM,
       RSITE_JIT_HOST_SPAN, RSITE_JIT_CODEGEN, RSITE_INTERP, RSITE_N };
static const char* const rsite_names[RSITE_N] = {
    "other", "read", "write", "host_ptr", "find_region", "check_perm",
    "jit_host_span", "jit_codegen", "interp"
};
__thread int hb_trace_rsite;
#define t_rsite hb_trace_rsite
static __thread uint64_t t_null_by_site[RSITE_N], t_lookup_by_site[RSITE_N];
static __thread uint64_t t_gap_hits, t_gap_fills, t_gap_flushes;
/* Итерация 183: СКОЛЬКО РАЗ ОТРАБОТАЛ ОПРОВЕРГАТЕЛЬ. Без него «0 нарушений» неотличимо
 * от «проверка не исполнялась»: у дерева из одного узла сверочный обход почти бесплатен,
 * и по времени включённый VERIFY не отличается от выключенного (460 против 457 мс). */
static __thread uint64_t t_gap_verified;  /* negative cache, defined below */
/* Express the saving in the unit that actually costs time: dependent, cache-cold pointer loads. A failed treap
 * walk over ~24000 regions is ~15-20 of them; the gap scan it replaces is a linear MRU array. Counting both
 * makes the trade a measured ratio instead of an argument from region count. */
static __thread uint64_t t_walk_nodes_fail, t_walk_fail, t_walk_nodes_ok, t_walk_ok, t_gap_scanned;

/* MacRunner 2026-07-31 — 97.4 % of the misses resolve to NULL: 167.7 M lookups per run for guest addresses
 * that NO region contains. A bigger cache cannot help those (measured: slots=64 would buy 0.3 points), so the
 * question is who asks. Bucket the unresolved addresses by 16 MB and keep one example each — if they cluster in
 * one or two buckets this is a single unregistered range (the guest stack is the obvious suspect: stack traffic
 * is the most frequent memory traffic any program has), which is a completely different and much cheaper fix
 * than tuning the cache. */
/* First cut of this sampler was first-come-first-served over 20 slots: twenty cold startup addresses took the
 * table and 99.96 % of the traffic fell into "other", so it measured nothing. Misra-Gries instead — a matching
 * key increments, a free slot is claimed, and an unmatched key decrements every counter. Any bucket holding
 * more than 1/32 of the stream is guaranteed to survive in the table, which is exactly the question. */
#define HC_NULLBUCKETS 32
static __thread uint64_t t_hc_null_key[HC_NULLBUCKETS], t_hc_null_cnt[HC_NULLBUCKETS];
static __thread uint64_t t_hc_null_ex[HC_NULLBUCKETS], t_hc_null_ex_last[HC_NULLBUCKETS];
static __thread uint64_t t_hc_null_other, t_hc_null_total;

/* Which guest block issues the unmapped lookups. Same Misra-Gries discipline as the address buckets: any
 * block responsible for more than 1/32 of the null stream is guaranteed to survive in the table. If they
 * concentrate in one or two blocks, the 166 M nulls are a loop, not diffuse probing — which is the difference
 * between a caching problem and a spin-wait worth far more than the cache. */
#define HC_PCSLOTS 32
static __thread uint64_t t_pc_key[HC_PCSLOTS], t_pc_cnt[HC_PCSLOTS], t_pc_addr[HC_PCSLOTS];
static __thread uint64_t t_pc_total, t_pc_evicted;

static void null_pc_note(hb_gva_t addr) {
    uint64_t pc = hb_trace_current_block_addr;
    int free_slot = -1;
    t_pc_total++;
    for (int i = 0; i < HC_PCSLOTS; i++) {
        if (t_pc_cnt[i] && t_pc_key[i] == pc) { t_pc_cnt[i]++; return; }
        if (!t_pc_cnt[i] && free_slot < 0) free_slot = i;
    }
    if (free_slot >= 0) {
        t_pc_key[free_slot] = pc;
        t_pc_cnt[free_slot] = 1;
        t_pc_addr[free_slot] = (uint64_t)addr;
        return;
    }
    t_pc_evicted++;
    for (int i = 0; i < HC_PCSLOTS; i++) t_pc_cnt[i]--;
}

/* Set MACRUNNER_HB_NULL_SPAN_RECHECK=1 to restore the redundant re-lookup for an A/B. */
static int null_span_recheck_enabled(void) {
    const char* e = hb_gate( HB_GATE_HB_NULL_SPAN_RECHECK );
    int cached = e && *e && *e != '0';
    return cached;
}

static int trace_null_pc_enabled(void) {
    const char* e = hb_gate( HB_GATE_HB_TRACE_NULL_PC );
    int cached = e && *e && *e != '0';
    return cached;
}

static void hot_cache_note_unresolved(hb_gva_t addr) {
    uint64_t key = (uint64_t)addr >> 24;   /* 16 MB granularity */
    int free_slot = -1;
    if (!trace_hot_cache_stats_enabled()) return;
    if (trace_null_pc_enabled()) null_pc_note(addr);
    if (t_rsite < RSITE_N) t_null_by_site[t_rsite]++;
    /* the 16 MB address buckets already answered their question (two clusters, ~32 buckets); keep the code but
     * do not pay its 32-slot loop on every null unless asked */
    if (!hb_gate( HB_GATE_HB_TRACE_NULL_BUCKETS )) return;
    t_hc_null_total++;
    for (int i = 0; i < HC_NULLBUCKETS; i++) {
        if (t_hc_null_cnt[i] && t_hc_null_key[i] == key) {
            t_hc_null_cnt[i]++;
            t_hc_null_ex_last[i] = (uint64_t)addr;
            return;
        }
        if (!t_hc_null_cnt[i] && free_slot < 0) free_slot = i;
    }
    if (free_slot >= 0) {
        t_hc_null_key[free_slot] = key;
        t_hc_null_cnt[free_slot] = 1;
        t_hc_null_ex[free_slot] = (uint64_t)addr;
        t_hc_null_ex_last[free_slot] = (uint64_t)addr;
        return;
    }
    t_hc_null_other++;
    for (int i = 0; i < HC_NULLBUCKETS; i++) t_hc_null_cnt[i]--;
}

static void hot_shadow_touch(hb_region_t* region, int* out_depth) {
    int depth = -1;
    for (int i = 0; i < HC_SHADOW; i++) {
        if (t_hc_shadow[i] != region) continue;
        depth = i;
        break;
    }
    if (out_depth) *out_depth = depth;
    if (depth == 0) return;
    int from = depth < 0 ? HC_SHADOW - 1 : depth;
    for (int i = from; i > 0; i--) t_hc_shadow[i] = t_hc_shadow[i - 1];
    t_hc_shadow[0] = region;
}

static int trace_hot_cache_stats_enabled(void) {
    /* ОДНА БАЗА: предикат живёт в hb_memory.h (hb_trace_rsite_wanted), потому что его
     * спрашивает и hb_arm64_codegen.c перед тем, как ставить метку hb_trace_rsite.
     * Разбор ручки здесь не повторяется — иначе две копии однажды разойдутся. */
    return hb_trace_rsite_wanted();
}

/* Called from the resolve path with the region the treap returned, i.e. only after a real miss. */
static void hot_cache_note_resolved(hb_region_t* region) {
    int depth = -1;
    if (!trace_hot_cache_stats_enabled() || !t_hc_miss_pending) return;
    t_hc_miss_pending = 0;
    t_hc_miss_resolved++;
    hot_shadow_touch(region, &depth);
    if (depth < 0) t_hc_shadow_absent++;
    else t_hc_shadow_hist[depth]++;
}

static void hot_cache_note(int hit_depth, int reset, hb_region_t* hit_region) {
    if (!trace_hot_cache_stats_enabled()) return;
    t_hc_lookups++;
    if (t_rsite < RSITE_N) t_lookup_by_site[t_rsite]++;
    if (reset) t_hc_resets++;
    if (hit_depth >= 0) {
        t_hc_hits++;
        if (hit_depth < HB_MEMORY_HOT_CACHE_SLOTS) t_hc_depth_hist[hit_depth]++;
        hot_shadow_touch(hit_region, NULL);
        t_hc_miss_pending = 0;
    } else {
        t_hc_miss_pending = 1;
    }
    if (t_hc_lookups < t_hc_next) return;
    t_hc_next = t_hc_lookups + 8000000ull;

    uint64_t misses = t_hc_lookups - t_hc_hits;
    /* Cumulative hit rate a cache of N slots would have reached: real hits (all within 16) plus the missed
     * regions the 64-deep shadow found shallower than N. */
    uint64_t deeper = 0;
    for (int i = HB_MEMORY_HOT_CACHE_SLOTS; i < HC_SHADOW; i++) deeper += t_hc_shadow_hist[i];
    uint64_t d32 = 0;
    for (int i = HB_MEMORY_HOT_CACHE_SLOTS; i < 32; i++) d32 += t_hc_shadow_hist[i];
    double scan = 0.0;
    for (int i = 0; i < HB_MEMORY_HOT_CACHE_SLOTS; i++) scan += (double)t_hc_depth_hist[i] * (i + 1);
    fprintf(stderr, "macrunner-hb-hotcache: lookups=%llu hits=%llu hit_pct=%.2f resets=%llu "
                    "resets_per_1k_lookups=%.2f miss=%llu miss_resolved=%llu miss_null=%llu "
                    "miss_null_pct_of_miss=%.2f avg_hit_depth=%.2f hit_pct_if_32=%.2f hit_pct_if_64=%.2f "
                    "shadow_absent=%llu\n",
            (unsigned long long)t_hc_lookups, (unsigned long long)t_hc_hits,
            t_hc_lookups ? 100.0 * (double)t_hc_hits / (double)t_hc_lookups : 0.0,
            (unsigned long long)t_hc_resets,
            t_hc_lookups ? 1000.0 * (double)t_hc_resets / (double)t_hc_lookups : 0.0,
            (unsigned long long)misses, (unsigned long long)t_hc_miss_resolved,
            (unsigned long long)(misses - t_hc_miss_resolved),
            misses ? 100.0 * (double)(misses - t_hc_miss_resolved) / (double)misses : 0.0,
            t_hc_hits ? scan / (double)t_hc_hits : 0.0,
            t_hc_lookups ? 100.0 * (double)(t_hc_hits + d32) / (double)t_hc_lookups : 0.0,
            t_hc_lookups ? 100.0 * (double)(t_hc_hits + deeper) / (double)t_hc_lookups : 0.0,
            (unsigned long long)t_hc_shadow_absent);
    fprintf(stderr, "macrunner-hb-negcache: walk_fail=%llu nodes_per_failed_walk=%.1f "
                    "walk_ok=%llu nodes_per_ok_walk=%.1f gap_entries_scanned_per_hit=%.2f\n",
            (unsigned long long)t_walk_fail,
            t_walk_fail ? (double)t_walk_nodes_fail / (double)t_walk_fail : 0.0,
            (unsigned long long)t_walk_ok,
            t_walk_ok ? (double)t_walk_nodes_ok / (double)t_walk_ok : 0.0,
            t_gap_hits ? (double)t_gap_scanned / (double)t_gap_hits : 0.0);
    fprintf(stderr, "macrunner-hb-negcache: gap_hits=%llu gap_fills=%llu gap_flushes=%llu "
                    "gap_hits_per_1k_lookups=%.1f verified=%llu\n",
            (unsigned long long)t_gap_hits, (unsigned long long)t_gap_fills,
            (unsigned long long)t_gap_flushes,
            t_hc_lookups ? 1000.0 * (double)t_gap_hits / (double)t_hc_lookups : 0.0,
            (unsigned long long)t_gap_verified);
    fprintf(stderr, "macrunner-hb-nullsite:");
    for (int i = 0; i < RSITE_N; i++)
        fprintf(stderr, " %s=%llu/%llu", rsite_names[i], (unsigned long long)t_null_by_site[i],
                (unsigned long long)t_lookup_by_site[i]);
    fprintf(stderr, "\n");
    if (trace_null_pc_enabled()) {
        fprintf(stderr, "macrunner-hb-nullpc: total=%llu evicted=%llu", (unsigned long long)t_pc_total,
                (unsigned long long)t_pc_evicted);
        for (int i = 0; i < HC_PCSLOTS; i++) {
            if (t_pc_cnt[i] < t_pc_total / 100) continue;   /* >= 1 % of the null stream */
            fprintf(stderr, " [block=0x%llx n>=%llu pct>=%.1f ex_addr=0x%llx]",
                    (unsigned long long)t_pc_key[i], (unsigned long long)t_pc_cnt[i],
                    t_pc_total ? 100.0 * (double)t_pc_cnt[i] / (double)t_pc_total : 0.0,
                    (unsigned long long)t_pc_addr[i]);
        }
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "macrunner-hb-hotcache-null: total=%llu evicted=%llu",
            (unsigned long long)t_hc_null_total, (unsigned long long)t_hc_null_other);
    for (int i = 0; i < HC_NULLBUCKETS; i++) {
        if (t_hc_null_cnt[i] < t_hc_null_total / 200) continue;   /* >=0.5 % of the stream */
        fprintf(stderr, " [0x%llx000000 n>=%llu pct>=%.1f first=0x%llx last=0x%llx]",
                (unsigned long long)t_hc_null_key[i], (unsigned long long)t_hc_null_cnt[i],
                t_hc_null_total ? 100.0 * (double)t_hc_null_cnt[i] / (double)t_hc_null_total : 0.0,
                (unsigned long long)t_hc_null_ex[i], (unsigned long long)t_hc_null_ex_last[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "macrunner-hb-hotcache-depth:");
    for (int i = 0; i < HB_MEMORY_HOT_CACHE_SLOTS; i++)
        fprintf(stderr, " d%d=%d", i, t_hc_depth_hist[i]);
    fprintf(stderr, "\n");
    fflush(stderr);
}

/* MacRunner 2026-07-31 — the negative cache.
 *
 * Measured on a live HK boot: 97 % of hot-cache misses resolve to NULL — 166 M lookups per run for guest
 * addresses NO region contains, ~25 % of all lookups, each paying the full 16-slot scan AND a failed treap
 * walk. A bigger positive cache cannot touch them (slots=64 was worth 0.3 points), because the answer being
 * cached is the absence of a region.
 *
 * A failed treap walk already computes the exact answer for free: the last node we went LEFT at is the
 * successor (smallest base > addr) and the last we went RIGHT at is the predecessor, so [lo,hi) is a genuine
 * region-free gap — regions are non-overlapping and the treap is keyed by base. One entry therefore covers a
 * whole gap rather than one address, which is why 8 slots suffice for a stream spread over ~32 buckets.
 *
 * Soundness rests on two things: the epoch (bumped now on add as well as on remove/split/rebuild), and
 * skipping this entirely when guest32 is active, since that path's NULL means "found but not guest32", which
 * is a different statement. */
#define HB_GAP_SLOTS 8
typedef struct { hb_gva_t lo, hi; } hb_gap_ent_t;
static __thread struct {
    hb_memory_t* mem;
    uint64_t epoch;
    int count;
    hb_gap_ent_t e[HB_GAP_SLOTS];
} g_gap_tls;
/* Default OFF. The first A/B (both arms sampled at guest+164 s, same build) measured the negative cache
 * WORSE: find_region* self 4.05 % vs 1.96 %, dispatches at 300 s 532 M vs 560 M — despite it provably
 * skipping 99.4 % of a 17.2-node walk. The suspected cause is now addressed (duplicate acquire loads on a
 * shared line, plus adds wiping the positive cache), but the default stays where the evidence is until a
 * fresh A/B says otherwise. */
static int verify_neg_cache_enabled(void) {
    const char* e = hb_gate( HB_GATE_HB_VERIFY_NEG_CACHE );
    int cached = e && *e && *e != '0';
    return cached;
}

static int neg_cache_enabled(void) {
    const char* e = hb_gate( HB_GATE_HB_NEG_CACHE );
    int cached = e && *e && *e != '0';
    return cached;
}


/* MacRunner 2026-08-22, лейн РЕГИСТРЫ, итерация 183 — НЕГАТИВНЫЙ КЕШ ДЛЯ guest32.
 *
 * Итерация 182 записала, что путь guest32 исключён из негативного кеша «БЕЗ единой строки
 * объяснения». ЭТО НЕВЕРНО, и я отзываю: объяснение стоит в шапке этого же блока (строка
 * ~1062) — «that path's NULL means "found but not guest32", which is a different statement».
 * Довод о КОРРЕКТНОСТИ, а не упущение.
 *
 * Но довод шире, чем требуется. Двусмысленный NULL возвращается РОВНО в одном месте —
 * `find_region_impl`, ветвь guest32: `return n->is_guest32 ? n : NULL;`. Этот возврат
 * немедленный и до `gap_lookup` НЕ доходит. Если же обход ветви guest32 исчерпал дерево,
 * управление проваливается на общий путь — а там уже установлено, что адрес не содержит
 * НИ ОДНА область (дерево одно и то же, см. комментарий у общего обхода). Это ровно то
 * утверждение, которое негативный кеш и хранит.
 *
 * Поэтому гейт РАЗРЕШАЕТ кеш на guest32. Умолчание 0 — поведение байт-в-байт прежнее.
 * Проверять НЕ рассуждением: в движке уже есть опровергатель `MACRUNNER_HB_VERIFY_NEG_CACHE`,
 * который сверяет каждый ответ кеша с полным обходом и печатает `negcache-VIOLATION`.
 * Цена вопроса измерена в 182: 8 000 000 неудачных обходов против ОДНОГО на x86-64. */
static int neg_cache_g32_enabled(void) {
    const char* e = hb_gate( HB_GATE_HB_NEG_CACHE_G32 );
    int cached = e && *e && *e != '0';
    return cached;
}

static bool gap_lookup(hb_memory_t* mem, hb_gva_t addr, uint64_t epoch) {
    if (!neg_cache_enabled()) return false;
    if (mem->guest32_base && !neg_cache_g32_enabled()) return false;
    if (g_gap_tls.mem != mem || g_gap_tls.epoch != epoch) {
        g_gap_tls.mem = mem;
        g_gap_tls.epoch = epoch;
        g_gap_tls.count = 0;
        t_gap_flushes++;
        return false;
    }
    for (int i = 0; i < g_gap_tls.count; i++) {
        t_gap_scanned++;
        if (addr < g_gap_tls.e[i].lo || addr >= g_gap_tls.e[i].hi) continue;
        if (i) {
            hb_gap_ent_t tmp = g_gap_tls.e[i];
            g_gap_tls.e[i] = g_gap_tls.e[0];
            g_gap_tls.e[0] = tmp;
        }
        t_gap_hits++;
        return true;
    }
    return false;
}

static void gap_insert(hb_memory_t* mem, hb_gva_t lo, hb_gva_t hi, uint64_t epoch) {
    if (!neg_cache_enabled() || hi <= lo) return;
    if (mem->guest32_base && !neg_cache_g32_enabled()) return;
    if (g_gap_tls.mem != mem || g_gap_tls.epoch != epoch) {
        g_gap_tls.mem = mem;
        g_gap_tls.epoch = epoch;
        g_gap_tls.count = 0;
    }
    for (int i = g_gap_tls.count < HB_GAP_SLOTS ? g_gap_tls.count : HB_GAP_SLOTS - 1; i > 0; i--)
        g_gap_tls.e[i] = g_gap_tls.e[i - 1];
    g_gap_tls.e[0].lo = lo;
    g_gap_tls.e[0].hi = hi;
    if (g_gap_tls.count < HB_GAP_SLOTS) g_gap_tls.count++;
    t_gap_fills++;
}

/* MacRunner 2026-07-31 — take the thread-local address ONCE.
 * On Darwin every __thread access from a dylib goes through _tlv_get_addr, which is 6.31 % of the critical
 * thread even after removing my own instrumentation. This function touched g_hot_cache_tls for .mem, .epoch
 * and then .slot[i] across a 16-iteration loop, so nothing but the optimiser was stopping it from paying that
 * call repeatedly. One local pointer makes the rest plain loads. */
static hb_region_t* hot_cache_lookup(hb_memory_t* mem, hb_gva_t addr) {
    hb_hot_cache_tls_t* const tls = hb_hot_cache_slot();
    int did_reset = 0;
    if (macrunner_hb_disable_hot_cache_enabled()) return NULL;
    uint64_t epoch = hot_cache_epoch(mem);
    if (tls->mem != mem || tls->epoch != epoch) {
        hot_cache_reset_tls(mem, epoch);
        did_reset = 1;
    }

    for (int i = 0; i < HB_MEMORY_HOT_CACHE_SLOTS; i++) {
        hb_region_t* c = tls->slot[i];
        if (c && addr >= c->base && addr < c->base + c->size) {
            if (i != 0) {
                tls->slot[i] = tls->slot[0];
                tls->slot[0] = c;
            }
            /* MacRunner 2026-08-23, КООРДИНАТОР — ГЕЙТ НА МЕСТО ВЫЗОВА.
             * Гейт внутри `hot_cache_note` стоит первой строкой, но САМ ВЫЗОВ платится
             * на КАЖДОМ обращении к памяти. В профиле i386 после правки горячего кеша
             * это 2,1 % рабочего потока при выключенном приборе. Тот же класс, что часы
             * и зонды: цена снаружи гейта, а не в нём. Здесь гейт — чтение статической
             * переменной, то есть загрузка и ветвление вместо вызова. */
            if (trace_hot_cache_stats_enabled()) hot_cache_note(i, did_reset, c);
            return c;
        }
    }
    if (trace_hot_cache_stats_enabled()) hot_cache_note(-1, did_reset, NULL);
    return NULL;
}

static void hot_cache_insert(hb_memory_t* mem, hb_region_t* region) {
    hb_hot_cache_tls_t* const tls = hb_hot_cache_slot();
    if (!region || macrunner_hb_disable_hot_cache_enabled()) return;
    uint64_t epoch = hot_cache_epoch(mem);
    if (tls->mem != mem || tls->epoch != epoch)
        hot_cache_reset_tls(mem, epoch);

    for (int i = 0; i < HB_MEMORY_HOT_CACHE_SLOTS; i++) {
        if (tls->slot[i] == region) {
            if (i != 0) {
                tls->slot[i] = tls->slot[0];
                tls->slot[0] = region;
            }
            return;
        }
    }

    for (int i = HB_MEMORY_HOT_CACHE_SLOTS - 1; i > 0; i--)
        tls->slot[i] = tls->slot[i - 1];
    tls->slot[0] = region;
}


static size_t page_align(size_t sz) {
    return (sz + 4095) & ~4095;
}

static size_t hb_host_page_size(void) {
    static size_t cached = 0;
    if (!cached) {
        long v = sysconf(_SC_PAGESIZE);
        cached = v > 0 ? (size_t)v : 4096;
    }
    return cached;
}

static uintptr_t host_page_floor(uintptr_t addr) {
    size_t page = hb_host_page_size();
    return addr & ~(uintptr_t)(page - 1);
}

static uintptr_t host_page_ceil(uintptr_t addr) {
    size_t page = hb_host_page_size();
    return (addr + page - 1) & ~(uintptr_t)(page - 1);
}

static hb_gva_t page_floor_gva(hb_gva_t addr) {
    return addr & ~(hb_gva_t)4095;
}

static hb_gva_t page_ceil_gva(hb_gva_t addr) {
    return (addr + 4095) & ~(hb_gva_t)4095;
}

static bool range_overflows(hb_gva_t base, size_t size) {
    return size && base + (hb_gva_t)size <= base;
}

static bool trace_guest32_alias_enabled(void) {
    return macrunner_hb_memory_environment.trace_guest32_alias;
}

static void trace_guest32_alias(const char* reason, const hb_memory_t* mem,
                                uintptr_t original, uintptr_t base,
                                uintptr_t normalized, size_t size) {
    static int budget = 128;
    int left;

    if (!trace_guest32_alias_enabled()) return;
    if (original < 0x100000000ULL && (original & 0xffffffffULL) != 0x0050006fULL) return;
    left = __atomic_fetch_sub(&budget, 1, __ATOMIC_RELAXED);
    if (left <= 0) return;
    fprintf(stderr,
            "macrunner-hb-guest32-alias: reason=%s mem=%p guest32_base=%p "
            "original=0x%llx normalized=0x%llx size=%zu window=[0x%llx,0x%llx)\n",
            reason, (const void*)mem, mem ? mem->guest32_base : NULL,
            (unsigned long long)original, (unsigned long long)normalized, size,
            (unsigned long long)base, (unsigned long long)(base + HB_GUEST32_SIZE));
}

static bool normalize_guest32_mirror_addr(hb_memory_t* mem, hb_gva_t* addr, size_t size) {
    uintptr_t base, value, original;

    if (!mem || !addr) return true;
    value = (uintptr_t)*addr;
    if (!mem->guest32_base) {
        trace_guest32_alias("no_guest32_base", mem, value, 0, value, size);
        return true;
    }
    base = (uintptr_t)mem->guest32_base;
    original = value;
    if (value < base || value >= base + HB_GUEST32_SIZE) {
        trace_guest32_alias("out_of_window", mem, original, base, original, size);
        return true;
    }

    value -= base;
    if (size && value + size > HB_GUEST32_SIZE) {
        trace_guest32_alias("overflow", mem, original, base, value, size);
        return false;
    }
    trace_guest32_alias("normalized", mem, original, base, value, size);
    *addr = (hb_gva_t)value;
    return true;
}

static int prot_from_perm(hb_perm_t perm, bool guest32) {
    int prot = PROT_NONE;
    if (perm & HB_PERM_READ) prot |= PROT_READ;
    if (perm & HB_PERM_WRITE) prot |= PROT_WRITE;
    if (perm & HB_PERM_EXEC) {
        prot |= guest32 ? PROT_READ : PROT_EXEC;
    }
    return prot;
}

static void* region_host_ptr(const hb_region_t* r, hb_gva_t addr) {
    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: БЕЗУСЛОВНЫЙ ЗОНД НА ВЫХОД ЗА ГРАНИЦЫ.
     *
     * Вычисление ниже не проверяет, лежит ли адрес ВНУТРИ области. Если найденная
     * область его не содержит, `addr - r->base` уходит в переполнение беззнакового
     * и даёт мусорный хостовый адрес. Именно такой наблюдался в моде 316 (итерация
     * 150): `si_addr=0x47f3251c9efee000`, копия шла страница за страницей по
     * неотображённой памяти, а программа не доходила даже до регистрации класса.
     *
     * Зонд безусловный (правило проекта: критерием может быть только то, что
     * печатается всегда), но с потолком в 8 строк — условие аварийное и повторов
     * не требует. Две сравнения на вызов против мусорного memcpy — цена ничтожная. */
    if (addr < r->base || (r->size && addr - r->base >= r->size)) {
        static unsigned oob_n;
        if (oob_n++ < 8) {
            fprintf(stderr,
                    "macrunner-hb-region-oob: n=%u addr=0x%llx base=0x%llx size=0x%llx "
                    "host_base=%p perm=%d guest32=%d gen=%llu -> host=%p\n",
                    oob_n, (unsigned long long)addr, (unsigned long long)r->base,
                    (unsigned long long)r->size, r->host_base, (int)r->perm,
                    (int)r->is_guest32, (unsigned long long)r->gen,
                    (void*)((uint8_t*)r->host_base + (addr - r->base)));
            fflush(stderr);
        }
    }
    return (uint8_t*)r->host_base + (addr - r->base);
}

#ifdef __APPLE__
static bool guest32_copy_needs_mach(const hb_region_t* r, hb_gva_t addr, size_t size) {
    uintptr_t host;

    if (!r || !r->is_guest32 || !r->host_base || !size) return false;
    host = (uintptr_t)region_host_ptr(r, addr);

    /* x86 code can freely perform unaligned multi-byte accesses.  On macOS,
     * optimized host copies from the guest32 mirror can surface those as
     * native SIGBUS instead of a controlled HyperBridge memory result. */
    if (size > 1 && (host & ((size < sizeof(uint64_t) ? size : sizeof(uint64_t)) - 1)))
        return true;

    return host_page_floor(host) != host_page_floor(host + size - 1);
}

static hb_result_t mach_copy_from_host(void* out, const void* host, size_t size) {
    mach_vm_size_t copied = 0;
    kern_return_t kr;

    kr = mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)(uintptr_t)host,
                                (mach_vm_size_t)size,
                                (mach_vm_address_t)(uintptr_t)out, &copied);
    return (kr == KERN_SUCCESS && copied == size) ? HB_OK : HB_ERR_MEMORY_FAULT;
}

static hb_result_t mach_copy_to_host(void* host, const void* in, size_t size) {
    kern_return_t kr;

    kr = mach_vm_write(mach_task_self(), (mach_vm_address_t)(uintptr_t)host,
                       (vm_offset_t)(uintptr_t)in, (mach_msg_type_number_t)size);
    return kr == KERN_SUCCESS ? HB_OK : HB_ERR_MEMORY_FAULT;
}

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: гейт быстрого пути для НЕВЫРОВНЕННЫХ обращений.
 *
 * Профиль живого гостя в фазе загрузки Diablo показал, что время уходит в ядро:
 * mach_vm_read_overwrite 480 отсчётов, mach_copy_from_host 479, mach_vm_write 268.
 * Причина — guest32_copy_needs_mach() отправляет в mach ЛЮБОЕ невыровненное обращение
 * и любое пересечение страницы, а x86-код обращается к памяти невыровненно свободно.
 * Получается системный вызов там, где должна быть одна инструкция загрузки.
 *
 * Опасение в исходном комментарии (невыровненная копия даст нативный SIGBUS вместо
 * управляемого отказа) снимается тем, что ограждение УЖЕ стоит: вызывающая сторона
 * оборачивает memcpy в sigsetjmp и при отказе откатывается на mach (hb_memory.c ~2113
 * для чтения и ~2339 для записи). Гейт лишь распространяет готовое ограждение на
 * невыровненный случай.
 *
 * Умолчание ВЫКЛ: это правка КОРРЕКТНОСТИ доступа к памяти, и включать её можно только
 * по измерению, а не по правдоподобию. Проверка кешируется — getenv в горячем пути уже
 * виден в том же профиле (172 отсчёта), второй такой заводить нельзя. */
static bool guest32_fast_unaligned_enabled(void) {
    static int enabled = -1;
    if (enabled < 0) {
        const char* v = hb_gate( HB_GATE_HB_GUEST32_FAST_UNALIGNED );
        enabled = (v && v[0] && v[0] != '0') ? 1 : 0;
        /* MacRunner 2026-08-17, лейн ЛЕСТНИЦА, итерация 1513 — ДОКАЗАТЕЛЬСТВО ДОСТАВКИ ГЕЙТА.
         * Приказ 162 требует доказывать доставку гейта, а не заявлять её. Наличие строки в
         * двоичном (проверено 1510) доказывает, что гейт СОБРАН, но не что он ДОЕХАЛ: прогон с
         * потерянной переменной выглядит точно так же — ровно это случилось 17.08 утром, когда
         * из окружения пропали восемь переменных и набор молча не стартовал.
         * Печать срабатывает ОДИН раз за процесс (значение кладётся в static), стоит ноль.
         * fprintf, а не ERR/MESSAGE: каналы wine до наших журналов не доходят. */
        fprintf(stderr, "macrunner-gate: MACRUNNER_HB_GUEST32_FAST_UNALIGNED=%d\n", enabled);
        fflush(stderr);
    }
    return enabled != 0;
}

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: КОПИРОВАТЬ И ПРИ ПРОМАХЕ ГОРЯЧЕГО КЕША.
 *
 * Быстрый путь стоял под условием `is_hit && guest32_direct_copy_safe(...)`, где
 * is_hit — это ПОПАДАНИЕ В ГОРЯЧИЙ КЕШ (hb_memory.c:2086: region = hot_cache_lookup();
 * is_hit = region != NULL; и лишь затем при промахе region добирается через
 * find_region_after_hot_miss). То есть промах кеша отправлял обращение в ядро, хотя
 * область УЖЕ НАЙДЕНА и копирование по ней ничем не отличается от попадания.
 * Условие смешивает «нашлось быстро» с «копировать безопасно» — а безопасность зависит
 * от свойств области (is_guest32, host_base, выравнивание), что guest32_direct_copy_safe
 * и проверяет, плюс сверху стоит ограждение sigsetjmp с откатом на mach.
 *
 * Улика: в цепочке профиля в mach уходит hb_memory_read_u8, ОДНОБАЙТОВОЕ чтение, для
 * которого проверка выравнивания заведомо ложна — значит гонит именно промах кеша.
 * После снятия getenv рабочий поток на 93.8% состоит из mach_msg2_trap.
 *
 * Гейт MACRUNNER_HB_GUEST32_COPY_ON_MISS, умолчание ВЫКЛ: правка касается доступа к
 * памяти, включать только по измерению. */
/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ОГРАЖДЕНИЕ ТОЛЬКО ТАМ, ГДЕ ОНО НУЖНО.
 *
 * Ограждение `sigsetjmp`/`siglongjmp` существует ради одного случая: страница может
 * оказаться `PROT_NONE`, и тогда отказ внутри `memcpy` сигнальный сторож не поймает
 * (счётчик команд в libc, вне области JIT). Но право доступа мы ЗНАЕМ заранее — оно
 * лежит в `r->perm`, а `prot_from_perm()` отображает его прямо в защиту страницы.
 * Если доступ разрешён, `PROT_NONE` невозможен по построению и выпрыгивать неоткуда.
 *
 * Зачем: многократный выход длинным переходом из обработчика сигнала резко повышает
 * частоту отказа в `_sigtramp` (измерено, итерации 143 и 145). Убрав ограждение там,
 * где оно заведомо не сработает, убираем и выходы, и их цену — не теряя ускорения.
 *
 * Гейт `MACRUNNER_HB_GUEST32_COPY_NO_FENCE`, умолчание ВЫКЛ, чтобы мерить A/B. */
/* MacRunner 2026-08-24, КООРДИНАТОР — СКОЛЬКО РАЗ ОГРАЖДЕНИЕ РЕАЛЬНО СПАСЛО.
 *
 * Ограждение `sigsetjmp` на каждом копировании стоит 11,41 % (замер 24.08), а числа
 * срабатываний НЕ БЫЛО: печать `vhf-probe` ограничена восемью строками, а
 * `guard-census` считает СНИМОК БЛОКА, другой механизм. Решать о снятии,
 * не зная, сработало ли оно хоть раз, нельзя.
 *
 * `fence_armed`  — сколько раз ограждение поставлено (цена).
 * `fence_taken`  — сколько раз по нему ушли длинным переходом (польза).
 * Печать по завершении и каждые 2^22 постановки. Гейта нет: два инкремента
 * без ветвления дешевле, чем проверка гейта. */
static uint64_t g_fence_armed, g_fence_taken, g_fence_presync;

void hb_fence_census(const char* why);
void hb_fence_census(const char* why) {
    fprintf(stderr, "macrunner-hb-fence-census: why=%s armed=%llu taken=%llu presync=%llu taken_per_1e6=%.3f\n",
            why ? why : "?", (unsigned long long)g_fence_armed,
            (unsigned long long)g_fence_taken, (unsigned long long)g_fence_presync,
            g_fence_armed ? 1e6 * (double)g_fence_taken / (double)g_fence_armed : 0.0);
    fflush(stderr);
}

static bool guest32_copy_no_fence_enabled(void) {
    static int enabled = -1;
    if (enabled < 0) { const char* v = hb_gate( HB_GATE_HB_GUEST32_COPY_NO_FENCE );
                       enabled = (v && v[0] && v[0] != '0') ? 1 : 0;
                       fprintf(stderr, "macrunner-gate: MACRUNNER_HB_GUEST32_COPY_NO_FENCE=%d\n",
                               enabled);
                       fflush(stderr); }
    return enabled != 0;
}

/* Разрешает ли наш учёт областей этот доступ. У guest32 право EXEC даёт PROT_READ
 * (см. prot_from_perm), поэтому исполняемая область читается законно. */
static bool guest32_copy_perm_ok(const hb_region_t* r, bool write) {
    if (!r) return false;
    if (write) return (r->perm & HB_PERM_WRITE) != 0;
    return (r->perm & (HB_PERM_READ | HB_PERM_EXEC)) != 0;
}

/* ★ ИТЕРАЦИЯ 1702, ПРИКАЗ 169. Гейт БОЛЬШЕ НЕ ВЛИЯЕТ на выбор пути: `is_hit` убран из всех
 * трёх условий, быстрый путь стоит под одной лишь безопасностью. Функция оставлена ЖИВОЙ
 * намеренно — она печатает маркер, и по нему видно, что в прогоне передан УСТАРЕВШИЙ гейт.
 * Удалить её значит превратить переменную в сценариях в молчаливо неработающую, а это ровно
 * тот класс отказов, который в проекте помечен как главная потеря времени. */
__attribute__((unused)) static bool guest32_copy_on_miss_enabled(void) {
    static int enabled = -1;
    if (enabled < 0) {
        const char* v = hb_gate( HB_GATE_HB_GUEST32_COPY_ON_MISS );
        enabled = (v && v[0] && v[0] != '0') ? 1 : 0;
        /* MacRunner 2026-08-17, лейн ЛЕСТНИЦА, итерация 1513 — ДОКАЗАТЕЛЬСТВО ДОСТАВКИ ГЕЙТА.
         * Приказ 162 требует доказывать доставку гейта, а не заявлять её. Наличие строки в
         * двоичном (проверено 1510) доказывает, что гейт СОБРАН, но не что он ДОЕХАЛ: прогон с
         * потерянной переменной выглядит точно так же — ровно это случилось 17.08 утром, когда
         * из окружения пропали восемь переменных и набор молча не стартовал.
         * Печать срабатывает ОДИН раз за процесс (значение кладётся в static), стоит ноль.
         * fprintf, а не ERR/MESSAGE: каналы wine до наших журналов не доходят. */
        fprintf(stderr, "macrunner-gate: MACRUNNER_HB_GUEST32_COPY_ON_MISS=%d (УСТАРЕЛ с итерации 1702: путь выбирается по безопасности, гейт ни на что не влияет)\n", enabled);
        fflush(stderr);
    }
    return enabled != 0;
}

static bool guest32_direct_copy_safe(const hb_region_t* r, hb_gva_t addr, size_t size) {
    if (!r || !r->is_guest32 || !r->host_base) return false;
    if (guest32_fast_unaligned_enabled()) return true;
    return !guest32_copy_needs_mach(r, addr, size);
}

/* ★★★ MacRunner 2026-08-18, лейн ЛЕСТНИЦА, итерация 2295, приказ 171 — ПРИБОР СВЕРКИ ПРАВ.
 *
 * Зачем. Снятие ограждения sigsetjmp (гейт GUEST32_COPY_NO_FENCE, −0,96 с из 45,2) держится
 * на ОДНОЙ посылке: `region->perm` верно отражает НАСТОЯЩУЮ защиту страницы. В проекте эта
 * посылка уже дважды оказывалась ложной:
 *   1  mprotect рапортует успех, а prot остаётся R-X — отказ на первой же записи;
 *   2  guest32: смена прав на 4 КБ проходит, а соседние 4 КБ внутри 16 КБ задеваются.
 * Пока посылка не проверена ЧИСЛОМ, умолчание не меняется.
 *
 * Что считает. При каждом прямом копировании берёт настоящую защиту страницы через
 * mach_vm_region и сравнивает с тем, что наш учёт РАЗРЕШИЛ (guest32_copy_perm_ok):
 *   опасное расхождение — учёт разрешил, у страницы права НЕТ  -> memcpy упал бы;
 *   мягкое расхождение  — у страницы право есть, учёт не даёт  -> лишний mach-путь.
 * Крайние страницы диапазона проверяются обе: дефект 2 задевал именно соседнюю.
 *
 * ПРИБОР, В БОЙ НЕ ИДЁТ: mach_vm_region на каждое копирование — та самая цена, ради снятия
 * которой всё и делалось. Гейт MACRUNNER_HB_GUEST32_PERM_AUDIT, умолчание ВЫКЛ.
 *
 * Отрицательный контроль ОБЯЗАТЕЛЕН (приказ 171): прибор, не поймавший подложенное
 * расхождение, своим нулём ничего не доказывает. Самопроверка ниже заводит СВОЮ страницу
 * PROT_READ, заявляет на неё право записи и требует, чтобы сравнение это поймало. Своя
 * страница, а не гостевая: подложить PROT_NONE в живую память прогона — рискованно и
 * необязательно, проверяется-то сама функция сравнения. */
static bool guest32_perm_audit_enabled(void) {
    static int enabled = -1;
    if (enabled < 0) {
        const char* v = hb_gate( HB_GATE_HB_GUEST32_PERM_AUDIT );
        enabled = (v && v[0] && v[0] != '0') ? 1 : 0;
        fprintf(stderr, "macrunner-gate: MACRUNNER_HB_GUEST32_PERM_AUDIT=%d\n", enabled);
        fflush(stderr);
    }
    return enabled != 0;
}

/* Итерация 2299: `guest32_page_prot` удалён — его целиком заменил
 * `guest32_perm_compare_page_ex`, который отдаёт не только защиту, но и факт отображения.
 * Оставлять функцию «на будущее» нельзя: сборка идёт с -Werror -Wunused-function, и она
 * ЛОМАЕТ сборку — что и произошло на этой правке. */

/* 0 — согласие, 1 — ОПАСНОЕ расхождение (учёт разрешил, страница не даёт),
 * 2 — мягкое (страница даёт, учёт не разрешил), -1 — опросить не удалось. */
/* Итерация 2299: наружу отдаются ТРИ факта о странице, а не один вердикт. Замер 2298 нашёл
 * 14 опасных расхождений на семи адресах, и вердиктом их не объяснить: «права нет» покрывает
 * и «страница отображена как R--», и «страница не отображена вовсе» — это разные дефекты с
 * разным лечением. Первую гипотезу (ленивый коммит) я уже отверг сверкой страниц; вторую
 * гадать не буду — пусть скажет прибор. */
static int guest32_perm_compare_page_ex(uintptr_t host, bool claim, bool write,
                                        vm_prot_t* out_actual, vm_prot_t* out_max,
                                        int* out_mapped) {
    mach_vm_address_t a = (mach_vm_address_t)host_page_floor(host);
    mach_vm_size_t sz = 0;
    vm_region_basic_info_data_64_t ri;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    vm_prot_t need = write ? VM_PROT_WRITE : VM_PROT_READ;
    bool have;
    memset(&ri, 0, sizeof(ri));
    if (out_mapped) *out_mapped = -1;
    if (mach_vm_region(mach_task_self(), &a, &sz, VM_REGION_BASIC_INFO_64,
                       (vm_region_info_t)&ri, &cnt, &obj) != KERN_SUCCESS)
        return -1;
    if (a > (mach_vm_address_t)host_page_floor(host)) {
        /* Ближайшая область НАЧИНАЕТСЯ ПОЗЖЕ — наша страница не отображена вовсе. */
        if (out_actual) *out_actual = VM_PROT_NONE;
        if (out_max) *out_max = VM_PROT_NONE;
        if (out_mapped) *out_mapped = 0;
        return claim ? 1 : 0;
    }
    if (out_actual) *out_actual = ri.protection;
    if (out_max) *out_max = ri.max_protection;
    if (out_mapped) *out_mapped = 1;
    have = (ri.protection & need) != 0;
    if (claim && !have) return 1;
    if (!claim && have) return 2;
    return 0;
}

static int guest32_perm_compare_page(uintptr_t host, bool claim, bool write) {
    return guest32_perm_compare_page_ex(host, claim, write, NULL, NULL, NULL);
}

static void guest32_perm_audit_selftest(void) {
    size_t page = hb_host_page_size();
    void* p = mmap(NULL, page, PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
    int verdict;
    if (p == MAP_FAILED) {
        fprintf(stderr, "macrunner-hb-permaudit-selftest: mmap ОТКАЗ, контроль НЕ проведён\n");
        fflush(stderr);
        return;
    }
    /* Заявляем право ЗАПИСИ на странице, где его заведомо нет. Прибор обязан вернуть 1. */
    verdict = guest32_perm_compare_page((uintptr_t)p, true, true);
    fprintf(stderr,
            "macrunner-hb-permaudit-selftest: подложено=запись-на-PROT_READ verdict=%d %s\n",
            verdict, verdict == 1 ? "ПОЙМАНО" : "ПРОПУЩЕНО-ПРИБОР-НЕГОДЕН");
    fflush(stderr);
    munmap(p, page);
}

static void guest32_perm_audit(const hb_region_t* r, hb_gva_t addr, size_t size, bool write) {
    static unsigned long long calls, agree, danger, soft, unknown, printed;
    static int selftest_done;
    uintptr_t host;
    bool claim;
    int v_first, v_last;
    vm_prot_t a_prot = VM_PROT_NONE, a_max = VM_PROT_NONE;
    int a_mapped = -1;

    if (!guest32_perm_audit_enabled()) return;
    if (!r || !r->host_base || !size) return;
    if (!selftest_done) { selftest_done = 1; guest32_perm_audit_selftest(); }

    host = (uintptr_t)region_host_ptr(r, addr);
    claim = guest32_copy_perm_ok(r, write);
    v_first = guest32_perm_compare_page_ex(host, claim, write, &a_prot, &a_max, &a_mapped);
    v_last = (host_page_floor(host) == host_page_floor(host + size - 1))
                 ? v_first
                 : guest32_perm_compare_page(host + size - 1, claim, write);
    calls++;
    if (v_first < 0 || v_last < 0) unknown++;
    else if (v_first == 1 || v_last == 1) {
        danger++;
        if (printed++ < 8) {
            /* Итерация 2299: печатаем ФАКТЫ о странице. mapped=0 — страница не отображена
             * вовсе; mapped=1 с prot без нужного бита — отображена, но право снято.
             * max=0x… показывает, разрешал ли ядру такую защиту сам маппинг. */
            fprintf(stderr,
                    "macrunner-hb-permaudit-РАСХОЖДЕНИЕ: n=%llu write=%d gva=0x%llx host=%p "
                    "perm=%d size=%zu стр1=%d стр2=%d mapped=%d prot=0x%x max=0x%x\n",
                    danger, (int)write, (unsigned long long)addr, (void*)host,
                    (int)r->perm, size, v_first, v_last, a_mapped,
                    (unsigned)a_prot, (unsigned)a_max);
            fflush(stderr);
        }
    }
    else if (v_first == 2 || v_last == 2) soft++;
    else agree++;

    /* Итог печатается периодически: прогон обрывается по бюджету, «в конце» напечатать
     * некому. Период 200 000 — на веху i386 это единицы строк. */
    if ((calls % 200000ULL) == 0) {
        fprintf(stderr,
                "macrunner-hb-permaudit-итог: копирований=%llu согласие=%llu ОПАСНЫХ=%llu "
                "мягких=%llu неопрошено=%llu\n",
                calls, agree, danger, soft, unknown);
        fflush(stderr);
    }
}

/* ★★★ MacRunner 2026-08-24, КООРДИНАТОР — ВОЗВРАТУ mprotect ВЕРИТЬ НЕЛЬЗЯ.
 *
 * Прибор MACRUNNER_HB_GUEST32_PERM_AUDIT поймал на приёмке:
 *   perm=3 (наш учёт: READ|WRITE)  против  prot=0x5 (у страницы: READ|EXEC), max=0x7
 * то есть право записи снято и не возвращено, а `mprotect` до этого отрапортовал успех.
 * В памяти проекта это записано дважды (`mprotect-reports-success-without-write`,
 * `guest32: смена прав на 4 КБ проходит, а соседние 4 КБ внутри 16 КБ задеваются`).
 *
 * Следствие было такое: снятие ограждения копирования (GUEST32_COPY_NO_FENCE) даёт
 * Bus error на приёмке, потому что ограждение всё это время МОЛЧА чинило расхождение —
 * ловило отказ и звало эту самую функцию заново.
 *
 * Лечение: после `mprotect` СПРОСИТЬ У ЯДРА через `mach_vm_region` — тот же приём, что
 * уже применён в `hb_smc_arm_page` (итерация 983), без сигнала и без провоцирующей записи.
 * Не совпало — возвращаем отказ, и вызывающий откатывает учёт (`exact->perm = old_perm`),
 * вместо того чтобы дальше считать право действующим.
 *
 * Гейт MACRUNNER_HB_SYNC_VERIFY СНЯТ 02.09.2026: правка безусловна,
 * выключенная ветка возвращала известный дефект (scripts/гейты.py).
 * Выключается для замера цены самой проверки. */
static uint64_t g_sync_verify_checked, g_sync_verify_mismatch;

/* ★★★ 06.09.2026, лейн ТЕНЕВАЯ-КАРТА-2 — ПОЧИНКА ОТМЕНЯЕТ ПРАВКУ WINE, ЕСЛИ ЕЁ НЕ ЗАПРЕТИТЬ.
 *
 * `guest32_sync_host_protection` поднимает права хозяйской страницы до `r->perm`. Пока
 * `r->perm` был ЕДИНСТВЕННЫМ источником прав, это чинило расхождение. После правки Wine
 * (`MACRUNNER_HB_GUEST32_WINE_PROT`, virtual.c у `done:`) источник прав другой и он ПОЛНЕЕ:
 * он знает `VPROT_COMMITTED`, `VPROT_GUARD`, `VPROT_WRITEWATCH`, а `r->perm` — нет.
 * Значит любая «починка» из `r->perm` теперь не восстанавливает правду, а СТИРАЕТ её:
 * резерв без коммита получит PROT_READ|PROT_WRITE обратно, и правка Wine даст ноль.
 *
 * Гейт MACRUNNER_HB_GUEST32_NO_REPAIR, умолчание 0. Возврат HB_OK, а не отказ: вызывающие
 * после починки ПОВТОРЯЮТ доступ, и повтор честно упрётся в права хозяина — то есть отказ
 * дойдёт до гостя как c0000005 вместо молчаливой записи.
 *
 * ВНИМАНИЕ: в одиночку гейт вреден. Без WINE_PROT правды в хозяйских правах нет, и запрет
 * починки просто отнимает лечение известного расхождения (замер 24.08: Bus error в
 * `hb_copy_width`). Только набором. */
static int guest32_no_repair_enabled(void) {
    static int cached = -1;
    if (cached < 0) {
        const char* v = hb_gate( HB_GATE_HB_GUEST32_NO_REPAIR );
        cached = (v && *v && *v != '0') ? 1 : 0;
    }
    return cached;
}

static hb_result_t guest32_sync_host_protection(const hb_region_t* r, hb_gva_t addr, size_t size) {
    uintptr_t host;
    uintptr_t start;
    uintptr_t end;
    int want;

    if (!r || !r->is_guest32 || !r->host_base || !size) return HB_ERR_INVALID_ARG;
    if (guest32_no_repair_enabled()) {
        static uint64_t skipped;
        uint64_t n = ++skipped;
        if (n <= 8) {
            fprintf(stderr, "macrunner-hb-no-repair: пропуск n=%llu base=0x%llx perm=0x%x\n",
                    (unsigned long long)n, (unsigned long long)r->base, (unsigned)r->perm);
            fflush(stderr);
        }
        return HB_OK;
    }
    host = (uintptr_t)region_host_ptr(r, addr);
    start = host_page_floor(host);
    end = host_page_ceil(host + size);
    want = prot_from_perm(r->perm, true);
    if (mprotect((void*)start, end - start, want) != 0)
        return HB_ERR_MEMORY_FAULT;

    mach_vm_address_t q_addr = (mach_vm_address_t)start;
    mach_vm_size_t q_size = 0;
    vm_region_basic_info_data_64_t q_info;
    mach_msg_type_number_t q_cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t q_obj = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &q_addr, &q_size,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&q_info, &q_cnt, &q_obj);
    g_sync_verify_checked++;
    if (kr == KERN_SUCCESS && (q_info.protection & want) != want) {
        /* Ядро НЕ применило запрошенные права, хотя mprotect вернул 0. */
        static int said;
        if (said++ < 8) {
            fprintf(stderr, "macrunner-hb-sync-НЕ-ПРИМЕНЕНО: start=%p size=%zu "
                            "хотели=0x%x стало=0x%x max=0x%x perm=0x%x\n",
                    (void*)start, (size_t)(end - start), (unsigned)want,
                    (unsigned)q_info.protection, (unsigned)q_info.max_protection,
                    (unsigned)r->perm);
            fflush(stderr);
        }
        g_sync_verify_mismatch++;
        return HB_ERR_MEMORY_FAULT;
    }
    return HB_OK;
}

void hb_sync_verify_census(void);
void hb_sync_verify_census(void) {
    fprintf(stderr, "macrunner-hb-sync-verify: проверок=%llu расхождений=%llu\n",
            (unsigned long long)g_sync_verify_checked,
            (unsigned long long)g_sync_verify_mismatch);
    fflush(stderr);
}
#endif

static uint32_t region_prio(hb_gva_t base) {
    uint64_t x = (uint64_t)base;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return (uint32_t)x;
}

/* MacRunner 2026-08-29 — ГЛУБИНА РЕКУРСИИ ОГРАНИЧЕНА.
 *
 * Отчёт macOS о падении Diablo.exe (KERN_PROTECTION_FAILURE at 0x3006c7ff0,
 * 15 байт до конца региона стека) показал стек из tree_insert поверх
 * rebuild_region_tree <- hb_memory_guest32_unmap <- unix_notify_memory_free_impl:
 * рекурсия переполнила стек и снесла процесс.
 *
 * Приоритеты здесь — splitmix-хеш базы, в норме глубина O(log N). Тысячи кадров
 * означают, что список регионов или дерево зациклены. Полная переделка вставки
 * в итеративную ЛОМАЕТ приёмку (проверено: 485/0 держится только без неё), а
 * настоящая цель — не дать порче структуры снести процесс. Счётчик глубины даёт
 * ровно это, ничего не меняя в самом алгоритме. */
#define HB_TREE_MAX_DEPTH 192

static unsigned long long mm_tree_depth_exceeded;

static void tree_insert_depth(hb_region_t** root, hb_region_t* r, unsigned depth) {
    if (depth >= HB_TREE_MAX_DEPTH) {
        if (__atomic_fetch_add(&mm_tree_depth_exceeded, 1, __ATOMIC_RELAXED) == 0) {
            fprintf(stderr,
                    "macrunner-hb-дерево-глубина: ПРЕДЕЛ %u при вставке base=0x%llx — "
                    "структура повреждена, узел не подвешен\n",
                    (unsigned)HB_TREE_MAX_DEPTH, (unsigned long long)r->base);
            fflush(stderr);
        }
        return;
    }
    if (!*root) {
        *root = r;
        return;
    }

    if (r->base < (*root)->base) {
        tree_insert_depth(&(*root)->tree_left, r, depth + 1);
        if ((*root)->tree_left && (*root)->tree_left->tree_prio < (*root)->tree_prio) {
            hb_region_t* n = (*root)->tree_left;
            (*root)->tree_left = n->tree_right;
            n->tree_right = *root;
            *root = n;
        }
    } else {
        tree_insert_depth(&(*root)->tree_right, r, depth + 1);
        if ((*root)->tree_right && (*root)->tree_right->tree_prio < (*root)->tree_prio) {
            hb_region_t* n = (*root)->tree_right;
            (*root)->tree_right = n->tree_left;
            n->tree_left = *root;
            *root = n;
        }
    }
}

static void tree_insert(hb_region_t** root, hb_region_t* r) {
    tree_insert_depth(root, r, 0);
}

static void clear_hot_cache(hb_memory_t* mem) {
    if (!mem) return;
    memset(mem->hot, 0, sizeof(mem->hot));
    __atomic_add_fetch(&mem->hot_gen, 1, __ATOMIC_RELEASE);
    /* MacRunner 2026-07-31 — invalidate the NEGATIVE cache here too, conservatively.
     *
     * Splitting the epochs was right in principle (an add cannot invalidate a cached region) but it assumed
     * every add goes through insert_region_head. It does not: the VM-map sync path appends straight to
     * mem->regions and calls rebuild_region_tree, bumping only hot_gen. With the negative cache keyed solely on
     * add_gen, those regions materialised INSIDE cached gaps with nothing to invalidate them — 2118 verified
     * violations on a live boot (267 distinct addresses, all adjacent 64 KB commits), zero in the
     * single-threaded unit suite, which is why it took the real workload to expose it.
     *
     * Removes and splits do not strictly need to invalidate a gap, so this over-invalidates slightly; that is
     * the correct trade against a stale gap reporting mapped memory as unmapped. Plain adds still bump only
     * add_gen, so the positive cache keeps the hit rate the split bought it. */
    __atomic_add_fetch(&mem->add_gen, 1, __ATOMIC_RELEASE);
}

static void rebuild_region_tree(hb_memory_t* mem) {
    if (!mem) return;
    __atomic_add_fetch(&mm_rebuilds, 1, __ATOMIC_RELAXED);
    mem->region_tree = NULL;

    /* Цикл в списке заставлял обход крутиться вечно, вставляя одни и те же узлы:
     * каждая повторная вставка обнуляет tree_left/tree_right уже подвешенного
     * узла, дерево замыкается на себя, и следующий спуск уходит без дна.
     * Предел заведомо выше любого настоящего числа регионов. */
    unsigned seen = 0;
    for (hb_region_t* r = mem->regions; r; r = r->next) {
        if (++seen > (8u * 1024u * 1024u)) {
            fprintf(stderr, "macrunner-hb-список-регионов: ЦИКЛ, обход прерван\n");
            fflush(stderr);
            break;
        }
        __atomic_add_fetch(&mm_rebuild_nodes, 1, __ATOMIC_RELAXED);
        r->tree_left = NULL;
        r->tree_right = NULL;
        r->tree_prio = region_prio(r->base);
        tree_insert(&mem->region_tree, r);
    }
    clear_hot_cache(mem);
}

static void bump_generation(hb_memory_t* mem, hb_region_t* r) {
    if (!mem) return;
    mem->generation++;
    if (r) r->gen = mem->generation;
}

static void insert_region_head(hb_memory_t* mem, hb_region_t* r) {
    r->next = mem->regions;
    mem->regions = r;
    r->tree_left = NULL;
    r->tree_right = NULL;
    r->tree_prio = region_prio(r->base);
    tree_insert(&mem->region_tree, r);
    /* Bump ONLY the negative-cache epoch: a gap entry must not outlive the gap, but the positive cache is
     * provably unaffected by an add, so wiping it here (as the first cut did) was pure loss — it cost every
     * thread its 16 slots and wrote a cache line 54 threads read on every lookup. */
    __atomic_add_fetch(&mem->add_gen, 1, __ATOMIC_RELEASE);
}

static bool range_overlaps(hb_gva_t a_base, size_t a_size, hb_gva_t b_base, size_t b_size) {
    hb_gva_t a_top = a_base + (hb_gva_t)a_size;
    hb_gva_t b_top = b_base + (hb_gva_t)b_size;
    return a_base < b_top && b_base < a_top;
}

/* The last unmeasured O(N) walk on a hot-ish path.  hb_memory_protect's walk is
 * now measured (40 % of protect calls, ~9 500 nodes each) and sync_live_range is
 * measured and cold (6 calls in 66 s).  This one guards both map paths, and with
 * `regions` reaching 16 000+ inside the first minute of an HK boot it is the
 * obvious next suspect -- so count it rather than argue about it. */
static bool any_overlap(hb_memory_t* mem, hb_gva_t base, size_t size) {
    unsigned long long scan = 0;
    bool hit = false;

    for (hb_region_t* r = mem ? mem->regions : NULL; r; r = r->next) {
        scan++;
        if (range_overlaps(base, size, r->base, r->size)) { hit = true; break; }
    }
    __atomic_add_fetch(&mm_ovl_calls, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&mm_ovl_scan, scan, __ATOMIC_RELAXED);
    return hit;
}

static hb_result_t split_region_at(hb_memory_t* mem, hb_gva_t addr) {
    hb_region_t* r;
    hb_region_t* n;
    hb_gva_t top;

    if (!mem) return HB_ERR_INVALID_ARG;
    r = hb_memory_find_region(mem, addr);
    if (!r) return HB_OK;
    top = r->base + r->size;
    if (addr == r->base || addr >= top) return HB_OK;
    n = calloc(1, sizeof(*n));
    if (!n) return HB_ERR_OUT_OF_MEMORY;
    /* Every split adds a region permanently: nothing in this file ever merges two
     * adjacent regions back together, so N is monotonically non-decreasing. */
    __atomic_add_fetch(&mm_splits, 1, __ATOMIC_RELAXED);

    *n = *r;
    n->base = addr;
    n->size = (size_t)(top - addr);
    if (r->host_base) n->host_base = region_host_ptr(r, addr);
    n->tree_left = NULL;
    n->tree_right = NULL;
    n->tree_prio = region_prio(n->base);
    n->next = r->next;

    r->size = (size_t)(addr - r->base);
    r->next = n;
    tree_insert(&mem->region_tree, n);
    clear_hot_cache(mem);
    return HB_OK;
}

static hb_result_t split_all_regions_at(hb_memory_t* mem, hb_gva_t addr) {
    hb_region_t* r;
    hb_gva_t top;

    if (!mem) return HB_ERR_INVALID_ARG;
    r = hb_memory_find_region(mem, addr);
    if (!r) return HB_OK;
    top = r->base + r->size;
    if (addr <= r->base || addr >= top) return HB_OK;
    return split_region_at(mem, addr);
}

/* MacRunner 2026-08-04 — MEASUREMENT ARM for the 25 s heap-corruption reproducer.
 *
 * libmalloc's own verdict is "BUG IN CLIENT OF LIBMALLOC: memory corruption of free block", and the
 * value it finds in the free block is always an address in 0x8-0xC GB — the range HB maps guest
 * memory into, i.e. exactly what `hb_region_t::host_base` holds.  Regions are unlinked and freed
 * from several places while readers can still hold the node (hot cache, treap walkers), so a region
 * is the prime suspect for the block that gets written after free.
 *
 * This gate answers ONE question and nothing else: with region nodes never returned to the
 * allocator, does the corruption still happen?  It LEAKS by design and is DEFAULT OFF; it is a
 * measurement, not a fix.  If the death disappears the writer is a stale region pointer and the
 * real work is lifetime management; if it persists, regions are exonerated for a run's cost. */
static int region_free_quarantine(void) {
    const char* e = hb_gate( HB_GATE_HB_REGION_FREE_QUARANTINE );
    int cached = (e && *e && *e != '0') ? 1 : 0;
    return cached;
}

static uint64_t g_region_quarantined;

static void region_free(hb_region_t* r) {
    if (!r) return;
    /* Positive control. The first quarantine run printed nothing, which is ambiguous by
     * construction: "the gate never reached the child" and "no region is ever freed in the first
     * 25 s" look identical from the log. This one-shot fires on the FIRST region free whatever the
     * gate says, so the next run can tell those apart instead of guessing. */
    {
        static uint64_t seen;
        uint64_t n = __atomic_add_fetch(&seen, 1, __ATOMIC_RELAXED);
        if (n == 1 || (n & 0xffffu) == 0)
            fprintf(stderr, "macrunner-hb-region-free-seen: n=%llu gate=%d r=%p host_base=%p\n",
                    (unsigned long long)n, region_free_quarantine(), (void*)r, r->host_base);
    }
    if (region_free_quarantine()) {
        uint64_t n = __atomic_add_fetch(&g_region_quarantined, 1, __ATOMIC_RELAXED);
        if (n == 1 || (n & 0xffffu) == 0)
            fprintf(stderr, "macrunner-hb-region-quarantine: leaked=%llu last=%p host_base=%p\n",
                    (unsigned long long)n, (void*)r, r->host_base);
        return;
    }
    free(r);
}

static hb_result_t remove_region_node(hb_memory_t* mem, hb_region_t* target) {
    hb_region_t** p;

    if (!mem || !target) return HB_ERR_INVALID_ARG;
    p = &mem->regions;
    while (*p) {
        if (*p == target) {
            *p = target->next;
            mem->total_size -= target->size;
            clear_hot_cache(mem);
            region_free(target);
            rebuild_region_tree(mem);
            return HB_OK;
        }
        p = &(*p)->next;
    }
    return HB_ERR_NOT_FOUND;
}

static bool guest32_range_fully_mapped(hb_memory_t* mem, hb_gva_t start, hb_gva_t top) {
    hb_gva_t cur = start;

    while (cur < top) {
        hb_region_t* r = hb_memory_find_region(mem, cur);
        if (!r || !r->is_guest32 || r->base > cur) return false;
        cur = r->base + r->size;
    }
    return true;
}

static bool trace_bad_native_write_enabled(void) {
    return macrunner_hb_memory_environment.trace_native_writes;
}



#ifdef __APPLE__
static bool trace_live_vm_access_fail_enabled(void) {
    return macrunner_hb_memory_environment.trace_live_vm_access_fail;
}

static void trace_live_vm_access_fail(const char* op, hb_gva_t addr, size_t size,
                                      kern_return_t access_kr, const hb_region_t* cached) {
    mach_vm_address_t region = (mach_vm_address_t)addr;
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t region_kr;

    if (!trace_live_vm_access_fail_enabled()) return;

    memset(&info, 0, sizeof(info));
    region_kr = mach_vm_region(mach_task_self(), &region, &region_size,
                               VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info,
                               &count, &object);
    if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    fprintf(stderr,
            "macrunner-hb-live-vm-access-fail: op=%s addr=0x%llx size=%zu access_kr=%d "
            "mach_kr=%d mach_region=0x%llx mach_end=0x%llx mach_prot=0x%x "
            "cached_base=0x%llx cached_end=0x%llx cached_perm=0x%x\n",
            op, (unsigned long long)addr, size, access_kr, region_kr,
            (unsigned long long)region, (unsigned long long)(region + region_size),
            info.protection,
            cached ? (unsigned long long)cached->base : 0,
            cached ? (unsigned long long)(cached->base + cached->size) : 0,
            cached ? cached->perm : 0);
}

static hb_result_t write_live_vm_region(hb_memory_t* mem, hb_gva_t addr, const void* in, size_t size,
                                        const hb_region_t* region) {
    mach_port_t task = mach_task_self();
    kern_return_t kr = mach_vm_write(task, (mach_vm_address_t)addr,
                                     (vm_offset_t)(uintptr_t)in,
                                     (mach_msg_type_number_t)size);

    if (kr == KERN_SUCCESS) return HB_OK;
    trace_live_vm_access_fail("write", addr, size, kr, region);

    /* Windows guard-page / stack growth: the page is reserved in Wine's view
     * but not yet committed by macOS, so mach_vm_write faults.  Let the embedder
     * run virtual_handle_fault to commit the page (and grow the guest stack),
     * then retry once. */
    if (mem && mem->special_grow && mem->special_grow(mem->special_user, addr)) {
        kr = mach_vm_write(task, (mach_vm_address_t)addr, (vm_offset_t)(uintptr_t)in,
                           (mach_msg_type_number_t)size);
        if (kr == KERN_SUCCESS) return HB_OK;
        trace_live_vm_access_fail("write-after-grow", addr, size, kr, region);
    }

    if (region && (region->perm & HB_PERM_WRITE)) {
        mach_vm_address_t protect_base = (mach_vm_address_t)host_page_floor((uintptr_t)addr);
        mach_vm_address_t protect_top = (mach_vm_address_t)host_page_ceil((uintptr_t)addr + size);
        mach_vm_size_t protect_size = protect_top - protect_base;
        mach_vm_address_t query_addr = (mach_vm_address_t)addr;
        mach_vm_size_t query_size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        vm_prot_t restore_prot = VM_PROT_READ;
        kern_return_t query_kr;

        memset(&info, 0, sizeof(info));
        query_kr = mach_vm_region(task, &query_addr, &query_size, VM_REGION_BASIC_INFO_64,
                                  (vm_region_info_t)&info, &count, &object);
        if (object != MACH_PORT_NULL) mach_port_deallocate(task, object);
        if (query_kr == KERN_SUCCESS && query_addr <= addr &&
            query_addr + query_size >= addr + size)
            restore_prot = info.protection;

        kr = mach_vm_protect(task, protect_base, protect_size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
        if (kr == KERN_SUCCESS) {
            kr = mach_vm_write(task, (mach_vm_address_t)addr, (vm_offset_t)(uintptr_t)in,
                               (mach_msg_type_number_t)size);
            if (restore_prot)
                (void)mach_vm_protect(task, protect_base, protect_size, FALSE, restore_prot);
            if (kr == KERN_SUCCESS) return HB_OK;
            trace_live_vm_access_fail("write-after-protect", addr, size, kr, region);
        } else {
            trace_live_vm_access_fail("write-protect", addr, size, kr, region);
        }
    }
    return HB_ERR_MEMORY_FAULT;
}
#endif

static bool live_vm_write_mach_enabled(void) {
    return macrunner_hb_memory_environment.live_vm_write_mach;
}

static void trace_bad_native_write(const char* path, hb_gva_t addr, const void* in, size_t size) {
    uint64_t sample = 0;
    size_t copy = size < sizeof(sample) ? size : sizeof(sample);

    if (!trace_bad_native_write_enabled()) return;
    if (addr < 0x7ffd0000000ULL || addr >= 0x7ffe0000000ULL) return;
    if (copy) memcpy(&sample, in, copy);
    fprintf(stderr,
            "macrunner-hb-native-write: path=%s addr=0x%llx size=%zu sample=0x%llx\n",
            path, (unsigned long long)addr, size, (unsigned long long)sample);
}

static bool trace_guest_write_match(hb_gva_t addr, size_t size) {
    unsigned long long start, stop;
    hb_gva_t top;

    start = __atomic_load_n(&macrunner_hb_memory_environment.trace_guest_write_start,
                            __ATOMIC_RELAXED);
    stop  = __atomic_load_n(&macrunner_hb_memory_environment.trace_guest_write_stop,
                            __ATOMIC_RELAXED);
    if (start == stop) return false;
    top = addr + size;
    if (top < addr) top = UINT64_MAX;
    return addr < (hb_gva_t)stop && top > (hb_gva_t)start;
}

static void trace_guest_write(const char* path, hb_gva_t addr, const void* in, size_t size) {
    uint64_t sample = 0;
    size_t copy = size < sizeof(sample) ? size : sizeof(sample);

    if (!trace_guest_write_match(addr, size)) return;
    if (copy) memcpy(&sample, in, copy);
    fprintf(stderr,
            "macrunner-hb-guest-write: path=%s addr=0x%llx size=%zu sample=0x%llx\n",
            path, (unsigned long long)addr, size, (unsigned long long)sample);
}

static hb_region_t* find_region_normalized(hb_memory_t* mem, hb_gva_t addr);
static hb_region_t* find_region_after_hot_miss(hb_memory_t* mem, hb_gva_t addr);
static bool check_perm_region(hb_memory_t* mem, hb_gva_t addr, size_t size, hb_perm_t p, hb_region_t** out);

/* MacRunner 2026-07-31 — every instance starts at a globally unique epoch.
 *
 * The per-thread caches key their validity on (mem pointer, hot_gen). calloc gives hot_gen = 0, so a destroyed
 * hb_memory_t whose address malloc later hands back produces a NEW instance that a stale TLS table matches
 * exactly — classic ABA. For the positive cache that means serving pointers to regions freed with the previous
 * instance; it is why hb_test_runner:19370 fails the moment anything else is cached on the same key. Seeding
 * from a global counter makes the pair unique for the process, so no reused address can alias.
 *
 * The stride keeps instances apart even after per-instance bumps: an instance would need 2^32 region mutations
 * to reach its successor's seed. */
static uint64_t g_memory_epoch_seq;

hb_memory_t* hb_memory_create(size_t max_size) {
    hb_memory_t* mem = calloc(1, sizeof(hb_memory_t));
    if (!mem) return NULL;
    hb_memory_init_environment();
    __atomic_add_fetch(&mm_maps, 1, __ATOMIC_RELAXED);
    mem->max_size = max_size;
    mem->hot_gen = __atomic_add_fetch(&g_memory_epoch_seq, 1, __ATOMIC_RELAXED) << 32;
    mem->add_gen = mem->hot_gen;   /* same ABA protection for the negative cache */
    return mem;
}

void hb_memory_destroy(hb_memory_t* mem) {
    if (!mem) return;
    hb_region_t* r = mem->regions;
    while (r) {
        hb_region_t* n = r->next;
        if (r->allocated) munmap(r->host_base, r->size);
        region_free(r);
        r = n;
    }
    if (mem->guest32_base && mem->guest32_owned) munmap(mem->guest32_base, mem->guest32_size);
    free(mem);
}

static unsigned long mm_map_overlap_total;
static unsigned mm_map_overlap_shown;

unsigned long macrunner_hb_memory_map_overlap_count(void)
{
    return __atomic_load_n(&mm_map_overlap_total, __ATOMIC_RELAXED);
}

/* ★ ТЕНЕВАЯ КАРТА ПРАВ — см. объяснение у полей в hb_memory.h.
 *
 * Карта заводится только когда известно окно guest32: её размер прямо задан размером окна,
 * а для x64 такой границы нет. Отсутствие карты — законное состояние, и выпущенный код
 * обязан его переживать: NULL означает «проверять нечем, иди прежним путём». */
#define HB_PERM_MAP_PAGE_SHIFT 12u

static void hb_memory_perm_map_ensure(hb_memory_t* mem) {
    size_t pages;
    if (!mem || mem->perm_map) return;
    if (!mem->guest32_base || !mem->guest32_size) return;
    pages = mem->guest32_size >> HB_PERM_MAP_PAGE_SHIFT;
    if (!pages) return;
    mem->perm_map = (uint8_t*)calloc(pages, 1);
    mem->perm_map_pages = mem->perm_map ? pages : 0;
}

/* Указатель карты, СМЕЩЁННЫЙ под ХОЗЯЙСКИЙ адрес.
 *
 * Выпущенный код проверки прав получает X21 уже переведённым в хозяйское окно
 * (emit_x86_ea_to_host прибавляет guest32_base), а карта размерена ГОСТЕВЫМИ
 * страницами. Индексировать её хозяйской страницей — вылет за массив: при базе
 * 0x7100000000 индекс 118 489 088 против 1 048 576 записей.
 *
 * Вычитать базу в выпущенном коде значило бы две лишние команды на каждой
 * итерации горячего цикла. Смещение — величина постоянная на всё время жизни
 * окна, поэтому считается здесь один раз, и доступ остаётся в одну команду.
 *
 * Ноль возвращается, когда карты или окна нет: выпущенный код различает этот
 * случай через CBZ, и подменять его смещённым мусором нельзя. */
uint64_t hb_memory_perm_map_host_biased(hb_memory_t* mem) {
    uint64_t baza;

    if (!mem || !mem->perm_map || !mem->guest32_base) return 0;
    baza = (uint64_t)(uintptr_t)mem->guest32_base;
    /* Невыровненная база сдвинула бы индекс на пол-страницы, и проверка стала
     * бы врать в обе стороны. Такого не бывает (окно резервируется по
     * странице), но молчаливо полагаться на это нельзя. */
    if (baza & ((1u << HB_PERM_MAP_PAGE_SHIFT) - 1u)) return 0;
    return (uint64_t)(uintptr_t)mem->perm_map - (baza >> HB_PERM_MAP_PAGE_SHIFT);
}

uint8_t* hb_memory_perm_map(hb_memory_t* mem) {
    return mem ? mem->perm_map : NULL;
}

void hb_memory_perm_map_set(hb_memory_t* mem, hb_gva_t base, size_t size, hb_perm_t perm) {
    size_t first, last, i;
    if (!mem || !size) return;
    hb_memory_perm_map_ensure(mem);
    if (!mem->perm_map) return;
    /* Диапазон округляется НАРУЖУ: страница, задетая хотя бы частично, получает права
     * записи только если они есть у всего, что на неё попало. Поэтому при сужении прав
     * запись сначала обнуляется, а расширение идёт по фактическому региону. */
    first = (size_t)(base >> HB_PERM_MAP_PAGE_SHIFT);
    last  = (size_t)((base + size - 1) >> HB_PERM_MAP_PAGE_SHIFT);
    if (first >= mem->perm_map_pages) return;
    if (last >= mem->perm_map_pages) last = mem->perm_map_pages - 1;
    for (i = first; i <= last; i++) mem->perm_map[i] = (uint8_t)perm;
}

hb_result_t hb_memory_map(hb_memory_t* mem, hb_gva_t base, size_t size, hb_perm_t perm) {
    if (!mem) return HB_ERR_INVALID_ARG;
    if (!size || range_overflows(base, page_align(size))) return HB_ERR_INVALID_ARG;
    size_t alloc_size = page_align(size);
    hb_region_t* r = calloc(1, sizeof(hb_region_t));
    if (!r) return HB_ERR_OUT_OF_MEMORY;
    if (base == 0) {
        int prot = prot_from_perm(perm, false);
        void* p = mmap(NULL, alloc_size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { free(r); return HB_ERR_OUT_OF_MEMORY; }
        r->base = (hb_gva_t)(uintptr_t)p;
        r->host_base = p;
        r->allocated = true;
    } else {
        /* MacRunner 2026-08-16, лейн ПАМЯТЬ — УЧЁТ ПЕРЕКРЫВАЮЩИХСЯ РЕГИСТРАЦИЙ.
         *
         * `hb_memory_map_private` отвергает перекрытие (`any_overlap`, строка 1831), а этот путь
         * НЕ проверяет ничего. Измерено пробой `ovl.c`: две регистрации одного диапазона обе
         * дают HB_OK, после чего слой отвечает по СТАРШЕЙ области — повторная регистрация с
         * УЖЕСТОЧЁННЫМИ правами (r--) молча теряется, `can_write` продолжает отвечать 1.
         *
         * Живой вызывающий (`macrunner_hb.c:17015-17018`) спрашивает `find_region(base)` и зовёт
         * `map` только при отсутствии области — то есть точное совпадение базы прикрыто. НЕ
         * прикрыто частичное перекрытие: диапазон с другой базой, заходящий в чужую область.
         *
         * Поведение НЕ меняю (вызывающие в большинстве своём приводят результат к void, и отказ
         * здесь был бы правкой вслепую без прогона). Считаю и печатаю первые восемь: проверка —
         * ОДИН поиск по дереву на карту, и только по хвосту диапазона, потому что базу
         * вызывающий уже искал сам. */
        hb_region_t* tail_owner = hb_memory_find_region(mem, base + (hb_gva_t)alloc_size - 1);

        if (tail_owner) {
            unsigned long n = __atomic_add_fetch(&mm_map_overlap_total, 1, __ATOMIC_RELAXED);
            if (mm_map_overlap_shown < 8) {
                mm_map_overlap_shown++;
                fprintf(stderr,
                        "macrunner-hb-map-overlap: base=0x%llx size=%zu perm=0x%x nakryto="
                        "0x%llx+0x%llx perm=0x%x vsego=%lu\n",
                        (unsigned long long)base, alloc_size, (unsigned)perm,
                        (unsigned long long)tail_owner->base,
                        (unsigned long long)tail_owner->size,
                        (unsigned)tail_owner->perm, n);
                fflush(stderr);
            }
        }
        r->base = base;
        r->host_base = NULL;
        r->allocated = false;
    }
    r->size = alloc_size;
    r->perm = perm;
    hb_memory_perm_map_set(mem, base, size, perm);   /* карта прав — вместе с регионом */
    r->gen = mem->generation;
    insert_region_head(mem, r);
    mem->total_size += alloc_size;
    /* ★ Область ЗАВЕДЕНА — только теперь её видит запись. Гейт внутри. */
    hb_record_map((uint64_t)r->base, (uint64_t)alloc_size, (uint32_t)perm,
                  HB_REC_MAP_SHARED);
    return HB_OK;
}

int (*hb_guest_region_query_cb)(uint64_t, uint64_t*, uint64_t*, uint32_t*) = NULL;

hb_result_t hb_memory_map_private(hb_memory_t* mem, hb_gva_t base, size_t size, hb_perm_t perm) {
    if (!mem || !base) return HB_ERR_INVALID_ARG;
    size_t alloc_size = page_align(size);
    if (!alloc_size || range_overflows(base, alloc_size)) return HB_ERR_INVALID_ARG;
    if (any_overlap(mem, base, alloc_size)) return HB_ERR_INVALID_ARG;
    hb_region_t* r = calloc(1, sizeof(hb_region_t));
    if (!r) return HB_ERR_OUT_OF_MEMORY;

    int prot = prot_from_perm(perm, false);

    void* p = mmap(NULL, alloc_size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { free(r); return HB_ERR_OUT_OF_MEMORY; }

    r->base = base;
    r->host_base = p;
    r->allocated = true;
    r->size = alloc_size;
    r->perm = perm;
    hb_memory_perm_map_set(mem, base, size, perm);   /* карта прав — вместе с регионом */
    r->gen = mem->generation;
    insert_region_head(mem, r);
    mem->total_size += alloc_size;
    hb_record_map((uint64_t)base, (uint64_t)alloc_size, (uint32_t)perm,
                  HB_REC_MAP_PRIVATE);
    return HB_OK;
}

static hb_result_t hb_memory_sync_live_range_inner(hb_memory_t* mem, hb_gva_t base, size_t size,
                                                   hb_perm_t perm) {
    hb_region_t* replacement;
    hb_region_t** link;
    hb_gva_t top;
    hb_result_t res;
    unsigned long long scan = 0; /* folded into mm_slr_scan once, see protect_range_t */

    if (!mem || !size || range_overflows(base, size)) return HB_ERR_INVALID_ARG;
    top = base + (hb_gva_t)size;

    /* Replay is frequent.  Once the authoritative live region has replaced
     * the old VM-map fragments, avoid another O(N) split/remove/tree rebuild. */
    for (hb_region_t* exact = mem->regions; exact; exact = exact->next) {
        bool other_overlap = false;

        scan++;
        if (exact->allocated || exact->is_guest32 || exact->base != base ||
            exact->size != size || exact->perm != perm)
            continue;
        for (hb_region_t* other = mem->regions; other; other = other->next) {
            scan++;
            if (other != exact && range_overlaps(base, size, other->base, other->size)) {
                other_overlap = true;
                break;
            }
        }
        if (!other_overlap) {
            __atomic_add_fetch(&mm_slr_scan, scan, __ATOMIC_RELAXED);
            __atomic_add_fetch(&mm_slr_fast, 1, __ATOMIC_RELAXED);
            return HB_OK;
        }
    }

    /* This API is deliberately limited to Wine/macOS-owned live mappings.
     * Guest32 and private HB allocations have real backing/protection semantics
     * and must continue through their dedicated map/protect paths. */
    for (hb_region_t* r = mem->regions; r; r = r->next) {
        scan++;
        if (range_overlaps(base, size, r->base, r->size) &&
            (r->allocated || r->is_guest32)) {
            __atomic_add_fetch(&mm_slr_scan, scan, __ATOMIC_RELAXED);
            return HB_ERR_INVALID_ARG;
        }
    }
    __atomic_add_fetch(&mm_slr_scan, scan, __ATOMIC_RELAXED);

    __atomic_add_fetch(&mm_slr_repl, 1, __ATOMIC_RELAXED);
    replacement = calloc(1, sizeof(*replacement));
    if (!replacement) return HB_ERR_OUT_OF_MEMORY;

    res = split_all_regions_at(mem, base);
    if (res != HB_OK) {
        region_free(replacement);
        rebuild_region_tree(mem);
        return res;
    }
    res = split_all_regions_at(mem, top);
    if (res != HB_OK) {
        region_free(replacement);
        rebuild_region_tree(mem);
        return res;
    }

    /* Drop every old live fragment inside the authoritative range.  This also
     * removes holes/fragmentation from VM-map snapshots: the replacement below
     * guarantees that every byte of the guest allocation resolves to one HB
     * region with the requested permission. */
    link = &mem->regions;
    while (*link) {
        hb_region_t* r = *link;
        if (!r->allocated && !r->is_guest32 &&
            r->base >= base && r->base < top) {
            *link = r->next;
            mem->total_size -= r->size;
            clear_hot_cache(mem);
            region_free(r);
            continue;
        }
        link = &r->next;
    }

    replacement->base = base;
    replacement->size = size;
    replacement->perm = perm;
    hb_memory_perm_map_set(mem, replacement->base, replacement->size, perm);
    replacement->allocated = false;
    replacement->host_base = NULL;
    replacement->next = mem->regions;
    mem->regions = replacement;
    mem->total_size += size;
    bump_generation(mem, replacement);
    rebuild_region_tree(mem);
    return HB_OK;
}

hb_result_t hb_memory_sync_live_range(hb_memory_t* mem, hb_gva_t base, size_t size, hb_perm_t perm) {
    unsigned long long n = __atomic_add_fetch(&mm_slr_calls, 1, __ATOMIC_RELAXED);
    bool timed = (n & MM_CLOCK_MASK) == 0;
    unsigned long long t0 = timed ? mm_now_ns() : 0;
    hb_result_t r = hb_memory_sync_live_range_inner(mem, base, size, perm);

    if (timed) {
        unsigned long long t1 = mm_now_ns();
        __atomic_add_fetch(&mm_slr_ns, t1 - t0, __ATOMIC_RELAXED);
        __atomic_add_fetch(&mm_slr_ns_n, 1, __ATOMIC_RELAXED);
        if (mm_due(t1)) mm_report(mem, "synclive");
    }
    return r;
}

/* Итерация 1091: общее окно памяти гостя на процесс (см. пояснение внутри функции). */
static void* g_guest32_shared_base;
/* Последнее окно guest32 процесса. Нужно потому, что обработчик сигнала живёт в ntdll и
 * до объекта памяти (он в xtajit) не дотягивается, а знает только ХОЗЯЙСКИЙ адрес отказа. */
static hb_memory_t* g_guest32_mem;
static uintptr_t g_guest32_host_base;

hb_result_t hb_memory_guest32_reserve(hb_memory_t* mem) {
    const size_t reserve_size = (size_t)(HB_GUEST32_SIZE * 2ULL);
    uintptr_t raw_base;
    uintptr_t aligned;
    size_t prefix;
    size_t suffix;
    void* raw;

    if (!mem) return HB_ERR_INVALID_ARG;
    if (mem->guest32_base) return HB_OK;

    /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1091 — ОДНО ОКНО НА ПРОЦЕСС.
     *
     * Окно резервируется на КАЖДЫЙ экземпляр памяти, а экземпляр заводится на КАЖДЫЙ гостевой
     * поток (комментарий к `memmeter` в этом же файле: «карта областей — на гостевой поток…
     * на HK измерено 115 штук»). Значит один и тот же гостевой адрес живёт в нескольких
     * хостовых окнах сразу, и смена прав в одном невидима коду, работающему с другим.
     *
     * Так и вышло со сторожевой страницей (замеры 1087-1090): Wine честно взвёл `PROT_NONE`
     * по адресу окна A (`actual=0`), а гость читал окно B и отказа не получил. Это шире одной
     * команды: мимо может уйти ЛЮБАЯ смена прав.
     *
     * Гейт `MACRUNNER_HB_GUEST32_SHARED_WINDOW`, умолчание ВЫКЛ: правка трогает раскладку
     * памяти гостя, и включать её надо замером, а не верой. Проигравший гонку возвращает своё
     * резервирование системе и берёт общее. */
    {
        static const char* shared_gate;
        static int shared_on = -1;
        if (shared_on < 0) {
            shared_gate = hb_gate( HB_GATE_HB_GUEST32_SHARED_WINDOW );
            shared_on = (shared_gate && *shared_gate && *shared_gate != '0') ? 1 : 0;
        }
        if (shared_on) {
            void* shared = __atomic_load_n(&g_guest32_shared_base, __ATOMIC_ACQUIRE);
            if (shared) {
                mem->guest32_base = shared;
                mem->guest32_size = (size_t)HB_GUEST32_SIZE;
                mem->guest32_owned = false;   /* окно чужое: не отдавать его при разрушении */
                return HB_OK;
            }
        }
    }

    /* ★★★★★★ MacRunner 2026-09-02 — ЗАКРЕПЛЕНИЕ БАЗЫ ГОСТЕВОГО ОКНА.
     *
     * ЗАЧЕМ. Окно берётся `mmap(NULL, ...)`, то есть адрес выбирает ядро, и от прогона
     * к прогону база разная: за сутки замеров видел 0x300000000, 0x500000000,
     * 0xa00000000, 0xb00000000, 0xc00000000, 0xd00000000. Гостевые адреса при этом
     * привязаны к базе, и отказы, зависящие от раскладки, то появляются, то нет.
     *
     * Чего это стоило: целый вечер 01.09 ушёл на «отказ не воспроизводится, мерить не с
     * чем»; каждая пересборка перекидывала прогон в режим без отказа. Один и тот же
     * двоичный файл давал 8 отказов из 8 и 0 из 10 — не потому, что что-то починили, а
     * потому, что окно легло иначе. Пока база пляшет, ВЕСЬ класс layout-зависимых
     * отказов неизмерим, и это мешает не одной задаче, а всем.
     *
     * КАК. `MACRUNNER_HB_GUEST32_BASE=0x500000000` — подсказка адреса. Передаём её
     * в `mmap` как hint. ЗАМЕР показал: одной подсказки мало — просили 0x500000000,
     * ядро дало 0x7100000000 и 0xd00000000. Поэтому занимаем жёстко (`MAP_FIXED`),
     * но лишь убедившись через mach_vm_region, что диапазон свободен: `MAP_FIXED`
     * поверх занятого молча затёр бы чужое отображение. Печатаем, что просили и что дали,
     * — иначе «закрепил» неотличимо от «не сработало».
     *
     * Умолчание — прежнее поведение: без переменной ничего не меняется. */
    {
        static const char *baza_env;
        static int baza_read;
        void *hint = NULL;

        if (!baza_read)
        {
            baza_read = 1;
            baza_env = getenv("MACRUNNER_HB_GUEST32_BASE");
        }
        if (baza_env && *baza_env)
        {
            unsigned long long v = strtoull(baza_env, NULL, 0);

            /* Подсказка обязана быть выровнена на размер окна, иначе выравнивание ниже
             * сдвинет базу и закрепление окажется мнимым. */
            if (v && (v & (HB_GUEST32_SIZE - 1)) == 0) hint = (void *)(uintptr_t)v;
        }

        raw = MAP_FAILED;

        /* Подсказки мало: ядро её игнорирует (замер — просили 0x500000000, дали
         * 0x7100000000 и 0xd00000000). Занимаем жёстко, но ТОЛЬКО убедившись, что
         * диапазон свободен: `MAP_FIXED` поверх занятого затрёт чужое отображение.
         * Проверка — у самого ядра, через mach_vm_region. */
        if (hint)
        {
            mach_vm_address_t a = (mach_vm_address_t)(uintptr_t)hint;
            mach_vm_size_t sz = 0;
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj = MACH_PORT_NULL;
            int svobodno;

            if (mach_vm_region(mach_task_self(), &a, &sz, VM_REGION_BASIC_INFO_64,
                               (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS)
                svobodno = 1;                       /* выше нет ничего вовсе */
            else
                svobodno = (a >= (mach_vm_address_t)(uintptr_t)hint + reserve_size);

            if (svobodno)
                raw = mmap(hint, reserve_size, PROT_NONE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1, 0);
            {
                static int skazano_fix;
                if (!skazano_fix++)
                {
                    fprintf(stderr, "macrunner-hb-окно-закрепление: свободно=%d итог=%s (pid=%d)\n",
                            svobodno, raw == MAP_FAILED ? "не вышло, беру любое" : "занято жёстко",
                            (int)getpid());
                    fflush(stderr);
                }
            }
        }

        if (raw == MAP_FAILED)
            raw = mmap(NULL, reserve_size, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (raw == MAP_FAILED) return HB_ERR_OUT_OF_MEMORY;

        {
            static int skazano;
            if (baza_env && !skazano++)   /* молчим, когда гейта не просили */
            {
                fprintf(stderr, "macrunner-hb-окно-гейт: перем=%s подсказка=%p (pid=%d)\n",
                        baza_env ? baza_env : "(нет)", hint, (int)getpid());
                fflush(stderr);
            }
        }
        if (hint)
        {
            uintptr_t dali = ((uintptr_t)raw + HB_GUEST32_SIZE - 1) & ~(uintptr_t)(HB_GUEST32_SIZE - 1);
            fprintf(stderr, "macrunner-hb-окно-база: просили=%p дали=%p %s (pid=%d)\n",
                    hint, (void *)dali,
                    dali == (uintptr_t)hint ? "ЗАКРЕПЛЕНО" : "ядро дало другое",
                    (int)getpid());
            fflush(stderr);
        }
    }

    raw_base = (uintptr_t)raw;
    aligned = (raw_base + HB_GUEST32_SIZE - 1) & ~(uintptr_t)(HB_GUEST32_SIZE - 1);
    prefix = aligned - raw_base;
    suffix = reserve_size - (size_t)HB_GUEST32_SIZE - prefix;

    if (prefix) munmap(raw, prefix);
    if (suffix) munmap((void*)(aligned + HB_GUEST32_SIZE), suffix);
    /* ★★★★★ ИТЕРАЦИЯ 85, лейн УСТАНОВЩИКИ — СКОЛЬКО ОКОН И ОДНА ЛИ У НИХ БАЗА.
     *
     * Комментарий выше (лейн ЛЕСТНИЦА, 16.08) говорит: окно резервируется на КАЖДЫЙ
     * экземпляр памяти, экземпляр — на каждый гостевой поток, «на HK измерено 115».
     * Гейт общего окна выключен по умолчанию. Для разбора порчи `WowTebOffset` это
     * решающее: если окон много, то и хозяйских TEB в них много, и весь разбор
     * (итерации 64-84) шёл по ОДНОМУ окну из N.
     *
     * Печать безусловная, но по разу на резервирование — за прогон это единицы строк. */
    {
        static unsigned mr_win_n;
        g_guest32_mem = mem;
        g_guest32_host_base = (uintptr_t)mem->guest32_base;
        fprintf(stderr, "macrunner-hb-guest32-окно: n=%u база=%p размер=%llx pid=%d\n",
                ++mr_win_n, (void*)aligned, (unsigned long long)HB_GUEST32_SIZE, (int)getpid());
        fflush(stderr);
    }

    mem->guest32_base = (void*)aligned;
    mem->guest32_size = (size_t)HB_GUEST32_SIZE;
    mem->guest32_owned = true;
    /* Итерация 1091: публикуем окно как общее, если гейт включён. Гонку разрешаем сравнением
     * с обменом: проигравший отдаёт своё окно системе и берёт победившее. */
    {
        const char* g = hb_gate( HB_GATE_HB_GUEST32_SHARED_WINDOW );
        if (g && *g && *g != '0') {
            void* expected = NULL;
            if (!__atomic_compare_exchange_n(&g_guest32_shared_base, &expected,
                                             mem->guest32_base, false,
                                             __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                munmap(mem->guest32_base, (size_t)HB_GUEST32_SIZE);
                mem->guest32_base = expected;
                mem->guest32_owned = false;
            }
        }
    }
    /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 1018 (приказ 142) — назвать окно поимённо.
     * Печать одноразовая, под тем же гейтом, что и зонд входа в чтение. */
    {
        const char* v = hb_gate( HB_GATE_HB_TRACE_READ_ENTRY );
        if (v && *v && *v != '0') {
            {
                /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1090 — ЧЬЁ ЭТО ОКНО.
                 * Замер 1089: окон ДВА, у разных экземпляров памяти. Версия — что это две
                 * копии движка: `libhyperbridge.a` линкуется и в `ntdll.so`, и в `xtajit.so`
                 * (факт, стоивший лейну девяти итераций в 1015-1030). Печатаем имя модуля,
                 * из которого сделано резервирование, — это отвечает одним словом. */
                Dl_info _dli;
                const char *_who = (dladdr((void *)&hb_memory_guest32_reserve, &_dli) && _dli.dli_fname)
                                 ? _dli.dli_fname : "?";
                fprintf(stderr, "macrunner-hb-guest32-owner: pid=%d модуль=%s mem=%p\n",
                        (int)getpid(), _who, (void *)mem);
                fflush(stderr);
            }
            fprintf(stderr, "macrunner-hb-guest32-reserve: pid=%d base=%p size=0x%llx prot=PROT_NONE mem=%p\n",
                    (int)getpid(), mem->guest32_base, (unsigned long long)HB_GUEST32_SIZE, (void*)mem);
            fflush(stderr);
        }
    }
    return HB_OK;
}

void* hb_memory_guest32_base(const hb_memory_t* mem) {
    return mem ? mem->guest32_base : NULL;
}

void* hb_memory_guest32_to_host(hb_memory_t* mem, uint32_t guest_addr) {
    hb_region_t* r;

    if (!mem || !mem->guest32_base) return NULL;
    r = hb_memory_find_region(mem, guest_addr);
    if (!r || !r->is_guest32 || !r->host_base) return NULL;
    return region_host_ptr(r, guest_addr);
}

/* ═════════════════════════════════════════════════════════════════════════════════════════
 * ★★★★★ 06.09.2026, лейн ТЕНЕВАЯ-КАРТА — ПРАВА ХОЗЯЙСКОЙ СТРАНИЦЫ ОКНА СТАНОВЯТСЯ ПРАВДОЙ.
 *
 * ЗАЧЕМ. Окно гостя резервируется `PROT_NONE` (`hb_memory_guest32_reserve`), то есть MMU
 * хозяина ГОТОВ ловить обращения к неотображённому. Сплошь доступным на запись окно делает
 * `hb_memory_guest32_map`: он открывает `PROT_READ|PROT_WRITE` при ЛЮБЫХ правах гостя, а
 * права кладёт только в `r->perm`. `hb_memory_guest32_unmap` хозяйскую страницу не отзывает
 * вовсе. Следствие измерено стендом 06.09 (`--fast-family i386_perm`, набор
 * нативная-память-i386): запись в `PAGE_NOACCESS`, запись в область только-для-чтения и
 * запись в ОСВОБОЖДЁННУЮ память проходят МОЛЧА, чтение `PAGE_NOACCESS` — тоже. Отказ при
 * этом даёт не цель, а следующая команда: `otkaz=0bf00ff0` вместо `otkaz=00a20000`.
 *
 * Что при правдивых правах ловит MMU — доказано тем же прогоном: две пробы из шести зелены
 * с пометкой `сигнал=1` (область понижена `protect`-ом либо не открывалась никогда). То есть
 * механизм уже работает, ему не хватает только правды в правах.
 *
 * ПРАВИЛО ХОЗЯЙСКОЙ СТРАНИЦЫ — ИЛИ ПРАВ ПОДСТРАНИЦ. Гостевая страница 4 КБ, хозяйская на
 * macOS ARM64 — 16 КБ, значит в одной хозяйской лежат до четырёх гостевых с РАЗНЫМИ правами.
 * Точно выразить их MMU не может — это внешнее ограничение железа, и его нет и у x64:
 * Wine объединяет подстраницы через ИЛИ (`get_host_page_vprot`), QEMU так же («sum the prot»,
 * research/qemu/linux-user/mmap.c:210-221). Берём то же правило: иначе отображение соседней
 * страницы `PAGE_NOACCESS` закрыло бы работающую соседку и сломало бы гостя.
 *
 * ГЕЙТ `MACRUNNER_HB_GUEST32_HOST_PERM`, умолчание ВЫКЛ: правка трогает права гостевой
 * памяти, включать замером. При выключенном гейте поведение ДОСЛОВНО прежнее.
 * ═════════════════════════════════════════════════════════════════════════════════════════ */
static int guest32_host_perm_enabled(void) {
    static int on = -1;
    if (on < 0) {
        const char* v = hb_gate( HB_GATE_HB_GUEST32_HOST_PERM );
        on = (v && v[0] && v[0] != '0') ? 1 : 0;   /* по ЗНАЧЕНИЮ: =0 обязан выключать */
    }
    return on;
}

/* Права хозяйской страницы = ИЛИ прав всех гостевых 4-КБ подстраниц в ней. */
static hb_perm_t guest32_host_page_perm(hb_memory_t* mem, hb_gva_t page_start, size_t host_page) {
    hb_perm_t acc = HB_PERM_NONE;
    hb_gva_t cur;

    for (cur = page_start; cur < page_start + host_page; cur += 4096u) {
        hb_region_t* r = hb_memory_find_region(mem, cur);
        if (r && r->is_guest32 && cur >= r->base && cur - r->base < r->size)
            acc = (hb_perm_t)(acc | r->perm);
    }
    return acc;
}

/* Приводит защиту хозяйских страниц окна на [start, top) к правам гостя. Соседние страницы
 * той же хозяйской страницы учитываются правилом ИЛИ (см. разбор выше). Подряд идущие
 * хозяйские страницы с одинаковой защитой сливаются в один `mprotect`. */
static hb_result_t guest32_apply_host_prot(hb_memory_t* mem, hb_gva_t start, hb_gva_t top) {
    uintptr_t win = (uintptr_t)mem->guest32_base;
    size_t host_page = hb_host_page_size();
    hb_gva_t p_first, p_end, p;
    hb_gva_t run_start;
    int run_prot;

    if (!win) return HB_ERR_INVALID_ARG;
    p_first = (hb_gva_t)host_page_floor((uintptr_t)start);
    p_end   = (hb_gva_t)host_page_ceil((uintptr_t)top);
    if (p_end > (hb_gva_t)HB_GUEST32_SIZE) p_end = (hb_gva_t)HB_GUEST32_SIZE;
    if (p_end <= p_first) return HB_OK;

    /* ★ ЗОНД 06.09, лейн ТЕНЕВАЯ-КАРТА-2: кто и когда открывает страницу обратно.
     * Правка Wine ставит на резерв без коммита PROT_NONE, а гость всё равно пишет молча —
     * значит защиту снимает КТО-ТО ПОСЛЕ. Печать безусловная, первые 24 вызова, чтобы
     * увидеть порядок относительно `macrunner-guest32-wineprot`. */
    {
        static unsigned zond_n;
        unsigned nn = ++zond_n;
        if (nn <= 24)
            fprintf(stderr, "macrunner-hb-applyprot: n=%u [%08llx..%08llx)\n", nn,
                    (unsigned long long)p_first, (unsigned long long)p_end), fflush(stderr);
    }

    run_start = p_first;
    run_prot = prot_from_perm(guest32_host_page_perm(mem, p_first, host_page), true);
    for (p = p_first + host_page; ; p += host_page) {
        int prot = (p < p_end) ? prot_from_perm(guest32_host_page_perm(mem, p, host_page), true)
                               : -1;
        if (prot != run_prot) {
            if (mprotect((void*)(win + run_start), (size_t)(p - run_start), run_prot) != 0)
                return HB_ERR_MEMORY_FAULT;
            if (p >= p_end) break;
            run_start = p;
            run_prot = prot;
        }
        if (p >= p_end) break;
    }
    return HB_OK;
}

hb_result_t hb_memory_guest32_map(hb_memory_t* mem, uint32_t base, size_t size, hb_perm_t perm) {
    size_t alloc_size;
    void* host;
    hb_region_t* r;
    uintptr_t host_start;
    uintptr_t host_top;

    if (!mem || !size) return HB_ERR_INVALID_ARG;
    if ((base & 4095u) || (size & 4095u)) return HB_ERR_INVALID_ARG;
    alloc_size = page_align(size);
    if ((uint64_t)base + alloc_size > HB_GUEST32_SIZE) return HB_ERR_INVALID_ARG;
    if (any_overlap(mem, base, alloc_size)) return HB_ERR_INVALID_ARG;
    if (hb_memory_guest32_reserve(mem) != HB_OK) return HB_ERR_OUT_OF_MEMORY;

    host = (uint8_t*)mem->guest32_base + base;
    host_start = host_page_floor((uintptr_t)host);
    host_top = host_page_ceil((uintptr_t)host + alloc_size);
    if (!guest32_host_perm_enabled() &&
        mprotect((void*)host_start, host_top - host_start, PROT_READ | PROT_WRITE) != 0) {
        return HB_ERR_MEMORY_FAULT;
    }

    r = calloc(1, sizeof(*r));
    if (!r) return HB_ERR_OUT_OF_MEMORY;

    r->base = base;
    r->host_base = host;
    r->size = alloc_size;
    r->perm = perm;
    hb_memory_perm_map_set(mem, base, size, perm);   /* карта прав — вместе с регионом */
    r->is_guest32 = true;
    r->allocated = false;
    r->gen = mem->generation;
    if (perm & HB_PERM_EXEC) bump_generation(mem, r);
    insert_region_head(mem, r);
    mem->total_size += alloc_size;
    /* Защиту ставим ПОСЛЕ вставки: правило ИЛИ обязано видеть новую область. */
    if (guest32_host_perm_enabled()) {
        hb_result_t pr = guest32_apply_host_prot(mem, (hb_gva_t)base,
                                                 (hb_gva_t)base + (hb_gva_t)alloc_size);
        if (pr != HB_OK) {
            /* ★ remove_region_node САМ вычитает total_size, чистит горячий кеш, освобождает
             * область и перестраивает дерево — повторять ничего нельзя, иначе total_size
             * уедет на два размера вниз. Карту прав снимаем отдельно: её ставил map. */
            hb_memory_perm_map_set(mem, base, size, HB_PERM_NONE);
            remove_region_node(mem, r);
            return pr;
        }
    }
    return HB_OK;
}

hb_result_t hb_memory_guest32_protect(hb_memory_t* mem, uint32_t base, size_t size, hb_perm_t perm) {
    hb_gva_t start;
    hb_gva_t top;
    hb_result_t res;
    bool touched_exec = false;

    if (!mem || !size) return HB_ERR_INVALID_ARG;

#ifdef __APPLE__
    /* MacRunner sentinel trace: log every call that touches the sentinel page [0x7BD8E000, 0x7BD8F000). */
    if ((hb_gva_t)base <= 0x7BD8E000u && (hb_gva_t)base + (hb_gva_t)size > 0x7BD8E000u) {
        fprintf(stderr, "macrunner-hb-sentinel-protect: caller base=%08x size=%zx perm=%d\n",
                base, size, (int)perm);
        fflush(stderr);
    }
#endif
    start = page_floor_gva(base);
    top = page_ceil_gva((hb_gva_t)base + (hb_gva_t)size);
    if (top > HB_GUEST32_SIZE || top <= start) return HB_ERR_INVALID_ARG;

    res = split_region_at(mem, start);
    if (res != HB_OK) return res;
    res = split_region_at(mem, top);
    if (res != HB_OK) return res;
    if (!guest32_range_fully_mapped(mem, start, top)) {
        /* ★★★★★ ИТЕРАЦИЯ 131, лейн УСТАНОВЩИКИ — ФОРМА ДЫРЫ.
         * Замер 129-130: для 0x5D44000+0x84000 отказывают ОБА пути — смена прав
         * (нужен полностью отображённый) и отображение (нужен свободный). Значит
         * диапазон отображён ЧАСТИЧНО, и надо увидеть, чего именно не хватает. */
        static unsigned mr_hole_n;
        if (mr_hole_n++ < 6) {
            hb_gva_t cur = start;
            unsigned shown = 0;
            fprintf(stderr, "macrunner-hb-dyra: diapazon=[%08llx..%08llx)\n",
                    (unsigned long long)start, (unsigned long long)top);
            while (cur < top && shown < 12) {
                hb_region_t* rr = hb_memory_find_region(mem, cur);
                if (!rr || !rr->is_guest32 || rr->base > cur) {
                    fprintf(stderr, "   DYRA s %08llx (region=%s guest32=%d)\n",
                            (unsigned long long)cur, rr ? "est" : "net",
                            rr ? (int)rr->is_guest32 : -1);
                    if (rr && rr->base > cur) cur = rr->base; else break;
                } else {
                    fprintf(stderr, "   est [%08llx..%08llx) perm=%d\n",
                            (unsigned long long)rr->base,
                            (unsigned long long)(rr->base + rr->size), (int)rr->perm);
                    cur = rr->base + rr->size;
                }
                shown++;
            }
            fflush(stderr);
        }
        return HB_ERR_NOT_FOUND;
    }

    for (hb_region_t* r = mem->regions; r; r = r->next) {
        if (!r->is_guest32 || r->base < start || r->base >= top) continue;
        if ((r->perm | perm) & HB_PERM_EXEC) touched_exec = true;
        r->perm = perm;
    hb_memory_perm_map_set(mem, base, size, perm);   /* карта прав — вместе с регионом */
#ifdef __APPLE__
        /* ★ 06.09: при гейте GUEST32_HOST_PERM защиту ставит guest32_apply_host_prot ПОСЛЕ
         * цикла — по правилу ИЛИ и разом на весь диапазон. Поэлементный
         * `guest32_sync_host_protection` правила ИЛИ не знает: он мажет ВСЮ хозяйскую
         * страницу правами ОДНОЙ области и закрыл бы соседку в той же странице 16 КБ. */
        if (!guest32_host_perm_enabled() &&
            r->host_base && guest32_sync_host_protection(r, r->base, r->size) != HB_OK)
            return HB_ERR_MEMORY_FAULT;
#endif
    }
#ifdef __APPLE__
    if (guest32_host_perm_enabled()) {
        hb_result_t pr = guest32_apply_host_prot(mem, start, top);
        if (pr != HB_OK) return pr;
    }
#endif
    if (touched_exec) bump_generation(mem, NULL);
    return HB_OK;
}

/* ★★★★★★ 02.09.2026 — СКЛЕЙКА: ДОВЕСТИ ЗАЩИТУ И ПОВТОРИТЬ.
 *
 * ЗАЧЕМ. Прямой доступ к памяти гостя (MACRUNNER_HB_NATIVE_MEM_I386) даёт впятеро больше
 * прямого выпуска (13,8 % -> 68,8 % у расширения), но прогон детерминированно кончается
 * раньше: 13 283 / 13 283 / 13 285 строк против 17 400 у помощника, и в руке с прямым
 * путём 6 исключений c0000005 против нуля. Первое — по адресу 0x7105d0161e, то есть
 * база окна + гостевой 0x05d0161e, внутри образа vgui.dll во время правки импортов.
 *
 * ПРИЧИНА. Помощник ходит ЧЕРЕЗ карту и попутно доводит хозяйскую защиту до прав гостя.
 * Прямой путь ходит МИМО карты, по хозяйскому отображению, где право ещё старое: гость уже
 * сделал страницу образа записываемой, а mprotect на неё ещё не позвали. Хозяйский MMU
 * честно отказывает.
 *
 * ЛЕЧЕНИЕ. То же, что у восполнения карты: на отказе внутри окна guest32 довести защиту из
 * карты гостя и ПОВТОРИТЬ команду. Это не проверка прав в выпущенном коде (она стоила бы
 * ровно того, ради чего прямой путь и заводили) — это ленивая доводка по отказу, как делают
 * FEX и QEMU: хозяйский MMU плюс обработчик.
 *
 * Возвращает HB_OK, если область нашлась и защита применена — тогда вызывающий обязан
 * вернуться из обработчика БЕЗ сдвига pc, и команда исполнится заново. */
hb_result_t hb_memory_guest32_resync_protection(hb_memory_t* mem, uint32_t guest_addr) {
    hb_region_t* r;

    if (!mem) return HB_ERR_INVALID_ARG;
    r = find_region_normalized(mem, (hb_gva_t)guest_addr);
    if (!r || !r->is_guest32 || !r->host_base) return HB_ERR_NOT_FOUND;
    return guest32_sync_host_protection(r, (hb_gva_t)guest_addr, 1);
}

/* Вход для обработчика сигнала: он знает только хозяйский адрес отказа. Если адрес лежит
 * внутри окна guest32 — довести защиту и сказать «повторяй». Иначе HB_ERR_NOT_FOUND, и
 * обработчик продолжает как раньше. */
hb_result_t hb_memory_guest32_resync_by_host(uint64_t host_addr) {
    uintptr_t base = g_guest32_host_base;

    if (!g_guest32_mem || !base) return HB_ERR_NOT_FOUND;
    if ((uintptr_t)host_addr < base || (uintptr_t)host_addr >= base + HB_GUEST32_SIZE)
        return HB_ERR_NOT_FOUND;
    return hb_memory_guest32_resync_protection(g_guest32_mem,
                                               (uint32_t)((uintptr_t)host_addr - base));
}

hb_result_t hb_memory_guest32_unmap(hb_memory_t* mem, uint32_t base, size_t size) {
    hb_gva_t start;
    hb_gva_t top;
    hb_result_t res;
    bool touched_exec = false;
    hb_region_t* r;

    if (!mem || !size) return HB_ERR_INVALID_ARG;
    start = page_floor_gva(base);
    top = page_ceil_gva((hb_gva_t)base + (hb_gva_t)size);
    if (top > HB_GUEST32_SIZE || top <= start) return HB_ERR_INVALID_ARG;

    res = split_region_at(mem, start);
    if (res != HB_OK) return res;
    res = split_region_at(mem, top);
    if (res != HB_OK) return res;
    if (!guest32_range_fully_mapped(mem, start, top)) return HB_ERR_NOT_FOUND;

    r = mem->regions;
    while (r) {
        hb_region_t* next = r->next;
        if (r->is_guest32 && r->base >= start && r->base < top) {
            if (r->perm & HB_PERM_EXEC) touched_exec = true;
            remove_region_node(mem, r);
        }
        r = next;
    }
    if (touched_exec) bump_generation(mem, NULL);
    rebuild_region_tree(mem);
#ifdef __APPLE__
    /* ★ 06.09: сегодня хозяйская страница НЕ отзывается вовсе — освобождённая память
     * остаётся записываемой, и проба `i386_jit_store_after_unmap_faults` это ловит
     * (запись легла молча, отказ дала лишь следующая команда). Правило ИЛИ здесь тоже
     * обязательно: соседняя ЖИВАЯ область в той же хозяйской странице 16 КБ права не теряет. */
    if (guest32_host_perm_enabled()) {
        hb_result_t pr = guest32_apply_host_prot(mem, start, top);
        if (pr != HB_OK) return pr;
    }
#endif
    return HB_OK;
}

uint64_t hb_memory_generation(const hb_memory_t* mem) {
    return mem ? mem->generation : 0;
}

uint64_t hb_memory_region_generation(hb_memory_t* mem, hb_gva_t addr) {
    hb_region_t* r = hb_memory_find_region(mem, addr);
    return r ? r->gen : 0;
}

hb_result_t hb_memory_unmap(hb_memory_t* mem, hb_gva_t base) {
    if (!mem) return HB_ERR_INVALID_ARG;
    hb_region_t** p = &mem->regions;
    while (*p) {
        if ((*p)->base == base) {
            hb_region_t* d = *p;
            *p = d->next;
            mem->total_size -= d->size;
            hb_record_map((uint64_t)d->base, (uint64_t)d->size, (uint32_t)d->perm,
                          HB_REC_MAP_GONE);
            if (d->allocated) munmap(d->host_base, d->size);
            if (d->is_guest32 && (d->perm & HB_PERM_EXEC)) bump_generation(mem, NULL);
            clear_hot_cache(mem);
            free(d);
            rebuild_region_tree(mem);
            return HB_OK;
        }
        p = &(*p)->next;
    }
    return HB_ERR_NOT_FOUND;
}

/*
 * Applying a protection change to every region inside [start, top).
 *
 * This used to walk mem->regions end to end.  A `sample` of a live Hollow Knight
 * run in its slow regime (2026-07-29) put 913 of 2795 samples on the critical-path
 * thread inside hb_memory_protect, in a call-free loop -- 33 % of that thread, and
 * more than every guest memory read, write and region lookup in the whole process
 * put together (164 + 158 + 102), despite VirtualProtect being far rarer than
 * memory access.  That ratio only happens if the list is long, so the walk is the
 * cost, not the call rate.
 *
 * mem->region_tree is a treap keyed by base, so the same set can be reached in
 * O(log N + k).  The visitor only edits r->perm and host protection -- it never
 * changes the tree shape -- so an in-order traversal is safe here.  Two splits
 * have already run before this point, so no region straddles either boundary.
 *
 * One deliberate difference from the old loop: regions are now visited in base
 * order rather than list order.  Every region in range is still visited, and the
 * per-region work is unchanged; only *which* region reports the first mprotect
 * failure can differ, and an error is an error either way.
 */
typedef struct {
    hb_gva_t start;
    hb_gva_t top;
    hb_perm_t perm;
    bool found;
    bool touched_exec;
    hb_result_t res;
    /* Per-call, on the stack, folded into the globals ONCE at the end.  A shared
     * atomic per visited node would charge the list arm N contended RMWs per call
     * against the tree arm's ~log N, i.e. the instrument would manufacture part of
     * the very difference it is measuring. */
    unsigned long long visited;
    unsigned long long applied;
} protect_range_t;

/* The per-region work, shared verbatim by both traversals.  The A/B arms must
 * differ ONLY in how regions are reached -- if the bodies could drift, a timing
 * difference would not be attributable to the traversal. */
static void protect_apply_region(hb_region_t* node, protect_range_t* w) {
    hb_gva_t rtop;
    hb_perm_t old_perm;

    if (node->base < w->start || node->base >= w->top) return;
    rtop = node->base + node->size;
    if (rtop > w->top) return;

    w->applied++;
    w->found = true;
    old_perm = node->perm;
    if ((old_perm | w->perm) & HB_PERM_EXEC) w->touched_exec = true;

    /*
     * Non-allocated, non-guest32 regions describe Wine-owned live process
     * views.  Their host VM protection is owned by Wine/macOS.  Keep this
     * path metadata-only: applying HB_PERM_* with mprotect() would break
     * Wine's view manager and can make guest x64 code host-executable.
     */
    if (!node->allocated && !node->is_guest32) {
        node->perm = w->perm;
        return;
    }

    node->perm = w->perm;
    if (node->is_guest32) {
#ifdef __APPLE__
        if (node->host_base) {
            hb_result_t sync_r = guest32_sync_host_protection(node, node->base, node->size);
            if ((w->perm & HB_PERM_WRITE) && !(old_perm & HB_PERM_WRITE)) {
                fprintf(stderr,
                        "macrunner-hb-protect-rw-gated: class=guest32 base=0x%llx "
                        "size=%zu old_perm=0x%x new_perm=0x%x sync=%d\n",
                        (unsigned long long)node->base, node->size,
                        (unsigned)old_perm, (unsigned)w->perm, (int)sync_r);
                fflush(stderr);
            }
            if (sync_r != HB_OK) w->res = HB_ERR_MEMORY_FAULT;
        }
#endif
        return;
    }

    if (node->host_base) {
        int prot = prot_from_perm(w->perm, false);
        if (mprotect(node->host_base, node->size, prot) != 0) {
            w->res = HB_ERR_MEMORY_FAULT;
            return;
        }
        if ((w->perm & HB_PERM_WRITE) && !(old_perm & HB_PERM_WRITE)) {
            /* ПОТОЛОК ПЕЧАТИ (итерация 19, лейн ПАМЯТЬ). Печать была БЕЗУСЛОВНОЙ и на каждый
             * возврат права записи: проба многопоточности (4000 смен прав) дала 4000 строк —
             * 427 КБ вывода на 6 полезных чисел. Это ровно тот класс, что записан в правилах
             * проекта первым: построчная трасса убивает прогон и топит результат. Первые
             * восемь, затем каждая 65536-я — событие остаётся видимым, объём падает. */
            static unsigned long long g_rw_gated;
            unsigned long long n = ++g_rw_gated;

            if (n <= 8 || (n & 0xffffull) == 0) {
                fprintf(stderr,
                        "macrunner-hb-protect-rw-gated: n=%llu class=allocated base=0x%llx "
                        "size=%zu old_perm=0x%x new_perm=0x%x prot=0x%x\n",
                        n, (unsigned long long)node->base, node->size,
                        (unsigned)old_perm, (unsigned)w->perm, prot);
                fflush(stderr);
            }
        }
    }
}

/* ARM "tree": reach the in-range regions through the treap, pruning both sides.
 * Keyed by base, so a node at or above `top` prunes its whole right subtree and
 * one below `start` prunes its left. */
static void protect_range_visit(hb_region_t* node, protect_range_t* w) {
    if (!node || w->res != HB_OK) return;
    w->visited++;

    if (node->base >= w->start) protect_range_visit(node->tree_left, w);
    if (node->base < w->top) protect_range_visit(node->tree_right, w);
    if (w->res != HB_OK) return;

    protect_apply_region(node, w);
}

/* ARM "list": the walk that shipped -- every region in the map, every call.
 * Kept as a live control arm so the A/B is one binary and one deploy. */
static void protect_range_walk_list(hb_memory_t* mem, protect_range_t* w) {
    for (hb_region_t* r = mem->regions; r; r = r->next) {
        w->visited++;
        if (w->res != HB_OK) return;
        protect_apply_region(r, w);
    }
}

/* MacRunner 2026-08-16, лейн ПАМЯТЬ — УЧЁТ ОТКАЗОВ ЗАЩИТЫ ПАМЯТИ.
 *
 * Замер стенда `hb_memory_contract_test`: `mprotect` на macOS ARM64 отказывает с EINVAL(22) на
 * любом диапазоне мельче 16 КБ или не выровненном по 16 КБ, а гость Windows размечает права по
 * 4 КБ. `hb_memory_protect` тогда возвращает HB_ERR_MEMORY_FAULT, и на прогоне это не видно
 * ничем: отказ уходит вызывающему и растворяется.
 *
 * Прибор висит ТОЛЬКО на пути отказа: успешная защита (на прогоне HK их 1 823 296) не платит ни
 * инструкции. Первые восемь печатаются с адресом, размером и errno, дальше — только счёт, чтобы
 * не превратить прибор в шторм (уроки проекта: построчная трасса убивает прогон).
 *
 * Спросить итог: `macrunner_hb_memory_protect_fail_count()`. */
static unsigned long mm_protect_fail_total;
static unsigned mm_protect_fail_shown;

static void note_protect_fail(hb_gva_t base, size_t size, hb_perm_t perm, int err)
{
    unsigned long n = __atomic_add_fetch(&mm_protect_fail_total, 1, __ATOMIC_RELAXED);

    if (mm_protect_fail_shown < 8) {
        mm_protect_fail_shown++;
        fprintf(stderr,
                "macrunner-hb-protect-fail: base=0x%llx size=%zu perm=0x%x errno=%d vsego=%lu%s\n",
                (unsigned long long)base, size, (unsigned)perm, err, n,
                (err == 22 && (size < 0x4000u || (base & 0x3fffu))) ? " (мельче/не по 16 КБ)" : "");
        fflush(stderr);
    } else if ((n % 100000ul) == 0) {
        fprintf(stderr, "macrunner-hb-protect-fail: vsego=%lu\n", n);
        fflush(stderr);
    }
}

unsigned long macrunner_hb_memory_protect_fail_count(void)
{
    return __atomic_load_n(&mm_protect_fail_total, __ATOMIC_RELAXED);
}

static hb_result_t hb_memory_protect_inner(hb_memory_t* mem, hb_gva_t base, size_t size,
                                           hb_perm_t perm) {
    hb_gva_t start;
    hb_gva_t top;
    hb_region_t* exact;
    hb_result_t res;
    bool found = false;
    bool touched_exec = false;

    if (!mem || !size) return HB_ERR_INVALID_ARG;
    if (range_overflows(base, (hb_gva_t)size)) return HB_ERR_INVALID_ARG;

    start = page_floor_gva(base);
    top = page_ceil_gva(base + (hb_gva_t)size);
    if (top <= start) return HB_ERR_INVALID_ARG;

    exact = hb_memory_find_region(mem, start);
    if (exact && start >= exact->base && top <= exact->base + exact->size &&
        exact->perm == perm) {
        __atomic_add_fetch(&mm_mp_fast, 1, __ATOMIC_RELAXED);
        if (!exact->allocated && !exact->is_guest32) return HB_OK;
        if (exact->is_guest32) {
#ifdef __APPLE__
            if (exact->host_base &&
                guest32_sync_host_protection(exact, exact->base, exact->size) != HB_OK)
                return HB_ERR_MEMORY_FAULT;
#endif
            return HB_OK;
        }
        if (exact->host_base) {
            /* MacRunner 2026-08-06 — не звать ядро, когда менять нечего.
             *
             * Сюда мы попадаем ровно потому, что exact->perm УЖЕ равен запрошенному perm
             * (условие входа в быстрый путь). Значит защита хостовой области уже та, что
             * нужна, и mprotect ничего не изменит — но заплатит полную цену: ядро режет и
             * сшивает карту областей на каждый вызов.
             *
             * Замерено на прогоне HK 06.08: 1 823 296 вызовов hb_memory_protect, из них
             * 991 044 (54%) — этот самый быстрый путь. Отображений памяти у процесса
             * выросло с 8 до 643, подкачка раздулась до двадцати файлов по гигабайту, и
             * при живом прогоне свободного места на диске оставалось 20 ГБ из 53.
             * Розетта и Призм так не делают — они не переключают права тысячи раз в секунду.
             *
             * Выключатель на случай, если где-то защиту меняют мимо нашего учёта и
             * повторный mprotect служил незаметной починкой. */
            /* Гейт MACRUNNER_HB_REDUNDANT_MPROTECT снят 02.09.2026: право уже верное,
             * лишний вызов ядра не делаем никогда. */
            __atomic_add_fetch(&mm_mp_skipped, 1, __ATOMIC_RELAXED);
        }
        return HB_OK;
    }

    /*
     * A protection change wholly contained by one region needs at most two
     * splits.  Re-enter after those splits so the exact-region path below
     * updates only the requested segment.  Falling through used to scan every
     * node in mem->regions even though the treap had already identified the
     * sole containing region.  Mono heap realloc traffic makes this the common
     * case, so that O(n) walk dominated the swapchain creator thread before its
     * first Present.
     *
     * Keep the full-list fallback for ranges that genuinely span multiple
     * regions or holes.
     */
    if (exact && start >= exact->base && top <= exact->base + exact->size &&
        (start != exact->base || top != exact->base + exact->size)) {
        __atomic_add_fetch(&mm_mp_reenter, 1, __ATOMIC_RELAXED);
        res = split_all_regions_at(mem, start);
        if (res != HB_OK) return res;
        res = split_all_regions_at(mem, top);
        if (res != HB_OK) return res;
        /* Re-enter the inner body, not the wrapper: this is one external call. */
        return hb_memory_protect_inner(mem, start, (size_t)(top - start), perm);
    }

    if (exact && exact->base == start && exact->size == (size_t)(top - start)) {
        hb_perm_t old_perm = exact->perm;

        __atomic_add_fetch(&mm_mp_exact, 1, __ATOMIC_RELAXED);

        if (!exact->allocated && !exact->is_guest32) {
            if ((old_perm | perm) & HB_PERM_EXEC) bump_generation(mem, exact);
            exact->perm = perm;
            /* ★★★ MacRunner 2026-08-24, КООРДИНАТОР — УЧЁТ БЕЗ СИНХРОНИЗАЦИИ ЛЖЁТ.
             *
             * Было: `perm` менялся ТОЛЬКО в учёте, страница оставалась с прежней защитой.
             * Прибор PERM_AUDIT поймал следствие на приёмке:
             *     perm=3 (наш учёт: READ|WRITE)  против  prot=0x5 (у страницы: READ|EXEC)
             * при max=0x7 — то есть право записи можно вернуть, но никто не вернул.
             *
             * Отсюда Bus error при снятом ограждении копирования: ограждение всё это время
             * молча чинило расхождение, ловя отказ и синхронизируя права заново.
             *
             * Область не наша (`!allocated`), поэтому менять защиту мы вправе только если
             * отображение известно. Отказ ядра НЕ роняем: у чужой памяти свои правила,
             * а прежнее поведение было «не трогать вовсе». Печатаем, чтобы расхождение
             * перестало быть невидимым. */
            if (exact->host_base) {
                int want = prot_from_perm(perm, exact->is_guest32);
                uintptr_t h = (uintptr_t)exact->host_base;
                uintptr_t s = host_page_floor(h);
                uintptr_t e = host_page_ceil(h + exact->size);
                if (mprotect((void*)s, e - s, want) != 0) {
                    static int said;
                    if (said++ < 8) {
                        fprintf(stderr, "macrunner-hb-perm-sync-отказ: base=0x%llx size=%zu "
                                        "хотели=0x%x errno=%d\n",
                                (unsigned long long)exact->base, exact->size,
                                (unsigned)want, errno);
                        fflush(stderr);
                    }
                }
            }
            return HB_OK;
        }

        /* MacRunner 2026-08-16, лейн ПАМЯТЬ — УЧЁТ МЕНЯЕТСЯ ТОЛЬКО ПОСЛЕ УСПЕХА.
         *
         * Было: `exact->perm = perm` стояло ЗДЕСЬ, то есть до `mprotect` ниже. При отказе ядра
         * вызывающий получал HB_ERR_MEMORY_FAULT («права не изменены»), а слой уже считал их
         * изменёнными — и дальше отказывал в записи туда, куда хост писать разрешает. Измерено
         * стендом на 4 КБ внутри 16 КБ: `protect = -8`, `can_write = 0`, хост НЕ защитил.
         *
         * Для guest32 порядок обратный по необходимости: `guest32_sync_host_protection` читает
         * `r->perm`, поэтому там значение ставится до вызова и откатывается при отказе. */
        if (exact->is_guest32) {
            exact->perm = perm;
#ifdef __APPLE__
            if (exact->host_base) {
                hb_result_t sync_r = guest32_sync_host_protection(exact, exact->base, exact->size);
                if ((perm & HB_PERM_WRITE) && !(old_perm & HB_PERM_WRITE)) {
                    fprintf(stderr,
                            "macrunner-hb-protect-rw-gated: class=guest32 base=0x%llx "
                            "size=%zu old_perm=0x%x new_perm=0x%x sync=%d\n",
                            (unsigned long long)exact->base, exact->size,
                            (unsigned)old_perm, (unsigned)perm, (int)sync_r);
                    fflush(stderr);
                }
                if (sync_r != HB_OK) { exact->perm = old_perm; return HB_ERR_MEMORY_FAULT; }
            }
#endif
            if ((old_perm | perm) & HB_PERM_EXEC) bump_generation(mem, exact);
            return HB_OK;
        }

        if (exact->host_base) {
            int prot = prot_from_perm(perm, false);
            if (mprotect(exact->host_base, exact->size, prot) != 0) {
                note_protect_fail(exact->base, exact->size, perm, errno);
                return HB_ERR_MEMORY_FAULT;   /* учёт НЕ тронут: ставим его ниже, после успеха */
            }
            if ((perm & HB_PERM_WRITE) && !(old_perm & HB_PERM_WRITE)) {
                fprintf(stderr,
                        "macrunner-hb-protect-rw-gated: class=allocated base=0x%llx "
                        "size=%zu old_perm=0x%x new_perm=0x%x prot=0x%x\n",
                        (unsigned long long)exact->base, exact->size,
                        (unsigned)old_perm, (unsigned)perm, prot);
                fflush(stderr);
            }
        }
        exact->perm = perm;
        if ((old_perm | perm) & HB_PERM_EXEC) bump_generation(mem, exact);
        return HB_OK;
    }

    res = split_all_regions_at(mem, start);
    if (res != HB_OK) return res;
    res = split_all_regions_at(mem, top);
    if (res != HB_OK) return res;

    {
        protect_range_t walk;
        walk.start = start;
        walk.top = top;
        walk.perm = perm;
        walk.found = false;
        walk.touched_exec = false;
        walk.res = HB_OK;
        walk.visited = 0;
        walk.applied = 0;
        __atomic_add_fetch(&mm_mp_walk, 1, __ATOMIC_RELAXED);
        if (macrunner_hb_memory_environment.memprotect_walk_list)
            protect_range_walk_list(mem, &walk);
        else
            protect_range_visit(mem->region_tree, &walk);
        __atomic_add_fetch(&mm_mp_visit, walk.visited, __ATOMIC_RELAXED);
        __atomic_add_fetch(&mm_mp_apply, walk.applied, __ATOMIC_RELAXED);
        if (walk.res != HB_OK) return walk.res;
        found = walk.found;
        touched_exec = walk.touched_exec;
    }

    if (!found) {
        __atomic_add_fetch(&mm_mp_notfound, 1, __ATOMIC_RELAXED);
        return HB_ERR_NOT_FOUND;
    }
    if (touched_exec) bump_generation(mem, NULL);
    return HB_OK;
}

hb_result_t hb_memory_protect(hb_memory_t* mem, hb_gva_t base, size_t size, hb_perm_t perm) {
    unsigned long long n = __atomic_add_fetch(&mm_mp_calls, 1, __ATOMIC_RELAXED);
    bool timed = (n & MM_CLOCK_MASK) == 0;
    unsigned long long t0 = timed ? mm_now_ns() : 0;
    hb_result_t r = hb_memory_protect_inner(mem, base, size, perm);

    /* Карта обновляется ТОЛЬКО при успехе: отказавший protect прав не менял, а карта,
     * обогнавшая регионы, разрешила бы запись туда, где её не разрешили. */
    if (r == HB_OK) hb_memory_perm_map_set(mem, base, size, perm);

    if (timed) {
        unsigned long long t1 = mm_now_ns();
        __atomic_add_fetch(&mm_mp_ns, t1 - t0, __ATOMIC_RELAXED);
        __atomic_add_fetch(&mm_mp_ns_n, 1, __ATOMIC_RELAXED);
        if (mm_due(t1)) mm_report(mem, "protect");
    }
    return r;
}

/* MacRunner 2026-08-09 — АДРЕС отказавшего обращения, а не только его причина.
 *
 * `set_helper_fault_result` печатает `reason="JIT helper fault"`, а `runtime-fail` — `block_pc`.
 * На HK этот pc лежит в коде, сгенерированном Mono, и в каждом прогоне другой (0x51ffae4e3,
 * 0x16ba44773, 0x17ff32e33), поэтому по нему не сужается ничего. Адрес обращения не сохранялся
 * НИГДЕ: HB_ERR_MEMORY_FAULT возвращается из двадцати мест этого файла, и ни одно не пишет
 * addr. Здесь он кладётся в поток-локальную ячейку на трёх публичных входах гостевого доступа
 * (read/write/host_ptr) — путь помощника идёт через них.
 *
 * Обёртка, а не правка двадцати возвратов: так адрес фиксируется на ЛЮБОМ неуспехе, включая
 * будущие, и ни один путь не может остаться неучтённым по забывчивости. */
/* ★ MacRunner 2026-08-24, лейн ПОТОКОВЫЕ — ЧЕТЫРЕ ПОТОКОВЫЕ ПЕРЕМЕННЫЕ СВЕДЕНЫ В ОДНУ.
 *
 * Было четыре отдельных `__thread`, и они ВСЕГДА пишутся вместе. На Darwin у каждой свой
 * дескриптор, поэтому одна запись отказа стоила ЧЕТЫРЁХ косвенных вызовов `_tlv_get_addr`.
 * Счётчик по машинному коду (`tools/dorozhka/schet-tlv.py --imena`) намерил ровно это:
 *
 *     _g_hb_fault_size 15 мест, _g_hb_fault_write 15, _g_hb_fault_valid 15,
 *     _g_hb_fault_addr 5  —  ВСЕГО 50 из 346 обращений модуля (14,5 %),
 *     разложенных по 15 функциям (обе функции ниже встраиваются в каждого вызывающего)
 *
 * Одна структура — один дескриптор: вызов остаётся ОДИН, а поля берутся смещением от
 * возвращённого адреса.
 *
 * ★ ЧЕСТНО О ЦЕНЕ: это ХОЛОДНЫЙ путь. `hb_memory_note_fault` зовётся только под
 * `if (r != HB_OK)`, и классификатор мест (`--goryachie`) относит все 50 к УСЛОВНЫМ.
 * Значит правка улучшает счётчик и размер кода и НЕ ОБЯЗАНА улучшить время. Заявлять
 * по ней выигрыш нельзя — ровно тот класс ошибки, который в проекте уже оплачен.
 *
 * Потоковость СОХРАНЕНА и обязана быть: адрес отказа читается тем же потоком, который
 * его получил; общая на процесс ячейка перепутала бы отказы разных потоков. */
typedef struct {
    hb_gva_t addr;
    size_t   size;
    int      write;
    int      valid;
} hb_fault_rec_t;

static __thread hb_fault_rec_t g_hb_fault;

/* ★ АДРЕС БЕРЁТСЯ ОДИН РАЗ — иначе структура не помогает.
 *
 * Проверено дизассемблером после первой редакции этой правки: сведение четырёх переменных
 * в одну структуру САМО ПО СЕБЕ вызовов не убирает. Компилятор не может доказать, что
 * переходник `_tlv_get_addr` чист, и зовёт его ЗАНОВО НА КАЖДОЕ ПОЛЕ:
 *
 *     adrp x8,…; add x8,x8,#0x678;  ldr x10,[x8]; mov x0,x8; blr x10   ; поле 1
 *                                   ldr  x9,[x8]; mov x0,x8; blr  x9   ; поле 2  ...
 *
 * Взятие `&g_hb_fault` в местную переменную заставляет его позвать переходник ОДИН раз,
 * а поля читать смещением от полученного указателя. */
void hb_memory_last_fault(uint64_t* addr, size_t* size, int* is_write, int* valid) {
    const hb_fault_rec_t* f = &g_hb_fault;
    if (addr)     *addr     = (uint64_t)f->addr;
    if (size)     *size     = f->size;
    if (is_write) *is_write = f->write;
    if (valid)    *valid    = f->valid;
}

static void hb_memory_note_fault(hb_gva_t addr, size_t size, int is_write) {
    hb_fault_rec_t* f = &g_hb_fault;
    f->addr  = addr;
    f->size  = size;
    f->write = is_write;
    f->valid = 1;
}

/* ★★ MacRunner 2026-08-22, лейн РАЗРЫВ, итерация 223 — memcpy С ПЕРЕМЕННЫМ РАЗМЕРОМ УХОДИТ В БИБЛИОТЕКУ.
 *
 * Профиль рабочего потока развёрнутого диста (10 снимков, 27 343 отсчёта) показал
 * `_platform_memmove` 8,80 %, и по разбору вызывающих 655 отсчётов приходят из
 * `hb_memory_read_inner`, 546 из `hb_memory_write_inner` — вместе 1201, то есть 4,39 %
 * рабочего потока на копировании ОДНОГО-ВОСЬМИ байт.
 *
 * Причина не в объёме, а в типе: `size` здесь переменная времени выполнения, и компилятор
 * обязан звать библиотечный `memmove` вместо одной команды загрузки-сохранения. При
 * ПОСТОЯННОМ размере тот же `memcpy` встраивается в `ldr`/`str`.
 *
 * Гейт `MACRUNNER_HB_FIXED_WIDTH_COPY`, умолчание 0, с печатью — доставка доказуема журналом.
 * Семантику не меняет: та же копия тех же байт, отличается только форма вызова.
 * Выпуск JIT не трогается, поэтому в ключ кеша трансляций вносить нечего.
 *
 * Ожидание записываю ДО замера: 4,39 % по доле профиля. Но доля у нас плохой предсказатель —
 * за 22.08 занижение доходило до 2,9 раза (снимок контекста: ждали 1,70 %, получили 4,92 %). */
static int hb_fixed_width_copy_enabled(void) {
    const char* v = hb_gate( HB_GATE_HB_FIXED_WIDTH_COPY );
    int cached = (v && v[0] && v[0] != '0') ? 1 : 0;
    static int napechatano;
    if (!napechatano) { napechatano = 1;
    fprintf(stderr, "macrunner-gate: MACRUNNER_HB_FIXED_WIDTH_COPY=%d\n", cached);
    fflush(stderr);
    }
    return cached;
}

__attribute__((always_inline))
static inline void hb_copy_width(void* dst, const void* src, size_t size) {
    if (hb_fixed_width_copy_enabled()) {
        switch (size) {
            case 1: memcpy(dst, src, 1); return;
            case 2: memcpy(dst, src, 2); return;
            case 4: memcpy(dst, src, 4); return;
            case 8: memcpy(dst, src, 8); return;
            default: break;
        }
    }
    memcpy(dst, src, size);
}


static hb_result_t hb_memory_read_inner(hb_memory_t* mem, hb_gva_t addr, void* out, size_t size);
static hb_result_t hb_memory_write_inner(hb_memory_t* mem, hb_gva_t addr, const void* in, size_t size);
static void* hb_memory_host_ptr_inner(hb_memory_t* mem, hb_gva_t addr, size_t size, hb_perm_t perm);

hb_result_t hb_memory_read(hb_memory_t* mem, hb_gva_t addr, void* out, size_t size) {
    hb_result_t r = hb_memory_read_inner(mem, addr, out, size);
    if (r != HB_OK) hb_memory_note_fault(addr, size, 0);
    return r;
}

hb_result_t hb_memory_write(hb_memory_t* mem, hb_gva_t addr, const void* in, size_t size) {
    hb_result_t r = hb_memory_write_inner(mem, addr, in, size);
    if (r != HB_OK) hb_memory_note_fault(addr, size, 1);
    return r;
}

void* hb_memory_host_ptr(hb_memory_t* mem, hb_gva_t addr, size_t size, hb_perm_t perm) {
    void* p = hb_memory_host_ptr_inner(mem, addr, size, perm);
    /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 1019 (приказ 142) — ВТОРОЙ ВХОД.
     * Зонд 1017 стоял только на hb_memory_read_inner и показал, что гостевые чтения i386
     * туда не приходят. Этот вход — второй способ получить память, и его надо измерить
     * тем же способом, а не предполагать. Тот же гейт. */
    {
        static __thread unsigned macrunner_hp_probe;
        const char* v = hb_gate( HB_GATE_HB_TRACE_READ_ENTRY );
        int macrunner_hp_on = (v && *v && *v != '0') ? 1 : 0;
        if (macrunner_hp_on && macrunner_hp_probe < 8) {
            macrunner_hp_probe++;
            fprintf(stderr, "macrunner-hb-hostptr: addr=0x%llx size=%zu perm=%d -> %p\n",
                    (unsigned long long)addr, size, (int)perm, p);
            fflush(stderr);
        }
    }
    if (!p) hb_memory_note_fault(addr, size, (perm & HB_PERM_WRITE) ? 1 : 0);
    return p;
}

static hb_result_t hb_memory_read_inner(hb_memory_t* mem, hb_gva_t addr, void* out, size_t size) {
    hb_region_t* region = NULL;
    bool is_hit = false;
    int dv_hit = macrunner_hb_datadiverge_hit((uint64_t)addr, size);
    if (!mem || !out) return HB_ERR_INVALID_ARG;
    if (!normalize_guest32_mirror_addr(mem, &addr, size)) return HB_ERR_MEMORY_FAULT;
    /* Итерация 1025: зонд перенесён СЮДА, ниже нормализации зеркала. Раньше он стоял на входе и
     * печатал адрес ДО перевода, а у 32-битного гостя туда приходит ХОЗЯЙСКИЙ адрес окна (≥ 4 ГБ) —
     * мой же фильтр «< 4 ГБ» отбрасывал именно те чтения, которые искал. Отсюда неверный вывод
     * 1017/1023 «гостевые чтения сюда не доходят». */
    {
        static __thread unsigned macrunner_rd2_probe;
        const char* v = hb_gate( HB_GATE_HB_TRACE_READ_ENTRY );
        int macrunner_rd2_on = (v && *v && *v != '0') ? 1 : 0;
        if (macrunner_rd2_on && addr < 0x100000000ULL && macrunner_rd2_probe < 8) {
            macrunner_rd2_probe++;
            fprintf(stderr, "macrunner-hb-readnorm: addr=0x%llx size=%zu guest32_base=%p\n",
                    (unsigned long long)addr, size, mem ? mem->guest32_base : NULL);
            fflush(stderr);
        }
    }
    if (trace_hot_cache_stats_enabled()) t_rsite = RSITE_READ;   /* diagnostic: TLS write, gated */
    region = hot_cache_lookup(mem, addr);
    is_hit = region != NULL;
    (void)is_hit;   /* итерация 1702: попадание в кеш больше НЕ решает, идти ли быстрым путём */
    if (!region) {
        region = find_region_after_hot_miss(mem, addr);
    }
    if (dv_hit) fprintf(stderr, "macrunner-hb-dv-read-mem: gva=0x%llx size=%zu region=%p base=0x%llx host_base=%p rperm=%d\n", (unsigned long long)addr, size, (void*)region, region?(unsigned long long)region->base:0, region?region->host_base:NULL, region?(int)region->perm:-1);
/* MacRunner 2026-07-31 — do not re-derive a NULL we already have.
 *
 * Call-site attribution on a live boot: hb_memory_find_region answers NULL 94.7 % of the time and accounts for
 * 47.8 % of ALL null lookups, and the arithmetic closes exactly — its 63.0 M nulls equal read's 49.9 M plus
 * write's 12.3 M. The reason is right here: a read/write that misses calls can_read_span/can_write_span, which
 * calls check_perm_span, which looks up THE SAME address again. check_perm_span bails on the first null, so
 * when region is already NULL that second lookup is provably NULL as well (same addr — normalize was applied
 * before both — and same epoch), and can_read_span can only return false.
 *
 * So skip it: ~62 M full lookups per run, each a 16-slot scan plus a 17.2-node treap walk, that exist only to
 * recompute a value the caller is holding. Unlike caching the miss, this removes the work rather than making
 * it cheaper. Gated so it can be A/B'd. */
    if (!region || addr + size > region->base + region->size || !(region->perm & HB_PERM_READ)) {
        if ((region || null_span_recheck_enabled()) && hb_memory_can_read_span(mem, addr, size)) {
            uint8_t* dst = out;
            hb_gva_t cur = addr;
            size_t remaining = size;
            while (remaining) {
                hb_region_t* r = hb_memory_find_region(mem, cur);
                size_t chunk = (size_t)(r->base + r->size - cur);
                hb_result_t rr;
                if (chunk > remaining) chunk = remaining;
                rr = hb_memory_read(mem, cur, dst, chunk);
                if (rr != HB_OK) return rr;
                cur += chunk;
                dst += chunk;
                remaining -= chunk;
            }
            return HB_OK;
        }
        if (mem->special_read && mem->special_read(mem->special_user, addr, out, size) == HB_OK) return HB_OK;
        return HB_ERR_MEMORY_FAULT;
    }
#ifdef __APPLE__
    if (region && !region->allocated && !region->host_base) {
        memcpy(out, (const void*)(uintptr_t)addr, size);
        if (dv_hit) fprintf(stderr, "macrunner-hb-dv-read-mem: -> identity val=0x%llx\n", (unsigned long long)(size==8?*(const uint64_t*)out:0));
        return HB_OK;
    }
#endif
    if (region && region->host_base) {
#ifdef __APPLE__
        if (region->is_guest32)
        {
            const void* host = region_host_ptr(region, addr);
            /* Use memcpy only when live-memory mode is enabled AND the access is
             * known safe (aligned, single page).  In all other cases use the Mach
             * read path so a PROT_NONE host page returns HB_ERR_MEMORY_FAULT
             * instead of crashing inside memcpy (PC in libc = outside JIT slab =
             * signal guard misses it = recursive c0000005 fault loop). */
            /* MacRunner 2026-08-17, лейн ЛЕСТНИЦА, итерация 1702, приказ 169.
             * `is_hit` УБРАН. Он отвечал на вопрос «нашлось ли быстро», а не «безопасно ли
             * копировать» — безопасность проверяет ОТДЕЛЬНЫЙ множитель ниже. Из-за этого
             * заведомо безопасное чтение при промахе горячего кеша уходило в ядро:
             * замер 17.08 дал mach_vm_read_overwrite 42,8-42,9 % рабочего потока против
             * 0,4-0,5 % при обходе. Третий случай этого класса в проекте. */
            /* MacRunner 2026-08-23, КООРДИНАТОР — ВЫЗОВ СНЯТ С ГОРЯЧЕГО ПУТИ.
             * Он стоял здесь ТОЛЬКО чтобы один раз напечатать маркер устаревшего гейта —
             * соседний комментарий сам говорит «гейт ни на что не влияет». Цена: 2,0 %
             * рабочего потока на честной нагрузке, вызов на КАЖДОЕ чтение байта.
             * Маркер печатается при первом обращении к памяти вообще (см. ниже по файлу),
             * поэтому наблюдаемость не теряется. */
            if (guest32_direct_copy_safe(region, addr, size))
            {
                sigjmp_buf jmp;
                /* 2026-08-23: гейт вынесен СЮДА. Внутри он проверяется после восьми
                 * местных переменных, значит компилятор ставит пролог кадра до него и
                 * платит его всегда. В профиле i386 это 1,8 % при выключенном приборе. */
                if (guest32_perm_audit_enabled())
                    guest32_perm_audit(region, addr, size, false);  /* приказ 171, прибор, по гейту */
                /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ограждение НЕ НУЖНО НИ В ОДНОМ из
                 * двух случаев, и это доводит направление 3 до конца.
                 *   право есть  -> PROT_NONE невозможен, копируем прямо;
                 *   права нет   -> memcpy УПАДЁТ заведомо, поэтому не пробуем вовсе,
                 *                  а сразу идём mach-путём, который вернёт код ошибки.
                 * В итерации 146 я оставил второй случай под ограждением — оттуда и
                 * уцелевший выход длинным переходом (illegal-insn 1 из 2). */
                if (guest32_copy_no_fence_enabled())
                {
                    if (!guest32_copy_perm_ok(region, false))
                        return mach_copy_from_host(out, host, size);
                    hb_copy_width(out, host, size);
                    return HB_OK;
                }
                install_sig_handlers();
                /* 2026-08-22: адрес ячейки берём ОДИН раз — разбор у hb_safe_jmp_cell.
                 * `volatile` обязателен: местная переменная, пережившая siglongjmp. */
                sigjmp_buf** volatile jcell = hb_safe_jmp_cell();
                *jcell = &jmp;
                /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: единица заставляет Apple-овский sigsetjmp
                 * сохранять маску сигналов И альтернативный стек — это sigprocmask 3883 плюс
                 * __sigaltstack 3462, около 90% рабочего потока после снятия mach-пути.
                 * С нулём не сохраняем ничего, а разблокировку берёт на себя обработчик. */
                g_fence_armed++;
                if ((g_fence_armed & 0x3fffffull) == 0) hb_fence_census("period");
                if (sigsetjmp(jmp, hb_fast_sigjmp_enabled() ? 0 : 1) == 0)
                {
                    hb_copy_width(out, host, size);
                    *jcell = NULL;
                    return HB_OK;
                }
                else
                {
                    g_fence_taken++;    /* ★ ограждение СРАБОТАЛО — длинный переход */
                    *jcell = NULL;
                    return mach_copy_from_host(out, host, size);
                }
            }
            return mach_copy_from_host(out, host, size);
        }
        if (guest32_copy_needs_mach(region, addr, size))
            return mach_copy_from_host(out, region_host_ptr(region, addr), size);
#endif
        hb_copy_width(out, region_host_ptr(region, addr), size);
        if (dv_hit) fprintf(stderr, "macrunner-hb-dv-read-mem: -> region val=0x%llx\n", (unsigned long long)(size==8?*(const uint64_t*)out:0));
        return HB_OK;
    }
    if (dv_hit) fprintf(stderr, "macrunner-hb-dv-read-mem: -> identity(fallback) val=0x%llx\n", (unsigned long long)(size==8?*(const uint64_t*)out:0));
    hb_copy_width(out, (void*)(uintptr_t)addr, size);
    return HB_OK;
}

__thread uint64_t hb_memory_watch_guest_pc, hb_memory_watch_guest_esp, hb_memory_watch_guest_ecx, hb_memory_watch_guest_edi, hb_memory_watch_guest_edx;
/* ★ MacRunner 2026-09-02 — сторож записи в общем пути hb_memory_write (сюда приходят и lazy-store, и запасные пути tso-писателей):
 * диапазон MACRUNNER_HB_JIT_WATCH_STORE=lo-hi; гостевой pc — из TLS (ставит hb_jit_helper_exec_store_operand_lazy). */
static void hb_memory_write_watch(hb_memory_t* mem, hb_gva_t addr, const void* in, size_t size) {
    static int done = 0, ok = 0; static uint64_t lo = 1, hi = 0; static unsigned long long n, n_zero;
    if (!done) {
        const char* e = hb_gate( HB_GATE_HB_JIT_WATCH_STORE ); const char* dash = e ? strchr(e, '-') : NULL;
        if (dash && dash > e) { lo = strtoull(e, NULL, 0); hi = strtoull(dash + 1, NULL, 0); ok = (hi >= lo); }
        done = 1;
    }
    if (!ok || addr + size <= lo || addr > hi) return;
    if (!ok || addr + size <= lo || addr > hi) return;
    {
        int zero = 1; size_t q; for (q = 0; q < size; q++) if (((const unsigned char*)in)[q]) { zero = 0; break; }
        ++n;
        if (zero && ++n_zero > 8) return;             /* обнуление печатаем 8 раз, остальное — только ненулевые записи (до 256) */
        if (n <= 4096 && (!zero || n_zero <= 8)) {
            static unsigned long long printed; uint32_t ret0 = 0, ret1 = 0, ret2 = 0;
            char hexs[33]; for (q = 0; q < size && q < 16; q++) snprintf(hexs + 2*q, 3, "%02x", ((const unsigned char*)in)[q]);
            uint32_t ret14 = 0, ret18 = 0;
            if (mem) { hb_memory_read_u32(mem, hb_memory_watch_guest_esp, &ret0); hb_memory_read_u32(mem, hb_memory_watch_guest_esp + 4, &ret1); hb_memory_read_u32(mem, hb_memory_watch_guest_esp + 8, &ret2); }
            if (mem) { hb_memory_read_u32(mem, hb_memory_watch_guest_esp + 0x14, &ret14); hb_memory_read_u32(mem, hb_memory_watch_guest_esp + 0x18, &ret18); }
            if (++printed <= 256)
                fprintf(stderr, "macrunner-hb-watch-store-mem: n=%llu addr=0x%llx size=%zu байты=%s guest=0x%llx esp=0x%llx [esp]=%08x [esp+4]=%08x [esp+8]=%08x [esp+14]=%08x [esp+18]=%08x ecx=0x%llx edi=0x%llx\n",
                        n, (unsigned long long)addr, size, hexs, (unsigned long long)hb_memory_watch_guest_pc, (unsigned long long)hb_memory_watch_guest_esp,
                        ret0, ret1, ret2, ret14, ret18, (unsigned long long)hb_memory_watch_guest_ecx, (unsigned long long)hb_memory_watch_guest_edi);
        }
    }
}
/* ── Приборы ветви отказа записи ───────────────────────────────────────────────
 * Ноль у этих приборов раньше значил две разные вещи. Теперь LOOKED стоит на
 * входе в холодную ветвь «быстрым путём не вышло», а HIT — на самом отказе:
 *     looked=0            ветвь не исполнялась вовсе -> NOT-OBSERVED
 *     looked>0, hits=0    ветвь шла, отказов не было -> NO-EVENTS (честный ноль)
 * Потолок печати не усекает молча: hits считается всегда, и перепись объявит
 * EVENTS-TRUNCATED с числом как НИЖНЕЙ ГРАНИЦЕЙ. */
HB_PROBE_DEFINE(pr_write_deny, "hb-write-deny",
                "записи гостя, отклонённые слоем памяти: нет области, либо выход за её "
                "границу, либо нет права записи — и ни special_write, ни рост стека "
                "не спасли. Тяжёлый диапазон 0x3f0000000..0x401000000 считает ОТДЕЛЬНЫЙ "
                "прибор hb-write-deny-heavy, здесь его нет",
                NULL, 8);

HB_PROBE_DEFINE(pr_write_deny_heavy, "hb-write-deny-heavy",
                "то же, что hb-write-deny, но ТОЛЬКО в диапазоне гостевого окна "
                "0x3f0000000..0x401000000: он печатался без потолка и потому вынесен "
                "в свою популяцию, иначе одно число смешивало бы две разные выборки",
                NULL, 0);

static hb_result_t hb_memory_write_inner(hb_memory_t* mem, hb_gva_t addr, const void* in, size_t size) {
    hb_region_t* region = NULL;
    bool is_hit = false;
    int grow_retried = 0;
    if (!mem || !in) return HB_ERR_INVALID_ARG;
    hb_memory_write_watch(mem, addr, in, size);
    if (!normalize_guest32_mirror_addr(mem, &addr, size)) return HB_ERR_MEMORY_FAULT;
    trace_bad_native_write("hb_memory_write", addr, in, size);
    trace_guest_write("hb_memory_write", addr, in, size);
    /* HK lockstep: log the realloc-copy store that writes 0x80 into the 0x3xx offset array during
     * the r13=0x11 insert window (g_hk_tg), with the guest instruction rva — catches GPR AND SSE. */
    {
        extern int g_hk_tg; extern uint64_t g_hk_cur_ga;
        if (g_hk_tg && size >= 8 && macrunner_hb_memory_environment.trace_store80) {
            const uint8_t* b8 = (const uint8_t*)in;
            for (size_t o = 0; o + 8 <= size; o += 8) {
                uint64_t v; memcpy(&v, b8 + o, 8);
                if ((v & 0xffffffffull) == 0x80ull) {
                    static int n80 = 0;
                    if (n80 < 24) {
                        fprintf(stderr, "store80mem: addr=%llx off=%zu size=%zu val=%llx guest_rva=%llx\n",
                            (unsigned long long)(addr + o), o, size, (unsigned long long)v,
                            (unsigned long long)(g_hk_cur_ga - 0x87efc510000ull));
                        fflush(stderr); n80++;
                    }
                }
            }
        }
    }
    /* Memcpy length/extent audit (env MACRUNNER_HB_TRACE_MEMCPY_LEN set): the over-write goes
     * through hb_memory_write (interpreted SSE stores).  Track the LONGEST monotonic +0x10 run
     * of 16-byte writes in the high guest-heap slab range: max_run*0x10 = largest contiguous
     * memcpy.  ~16 MB => bounded per-slab (legit); ~3.5 GB => one unbounded copy (runaway). */
    {
        if (macrunner_hb_memory_environment.trace_memcpy_len &&
            size && size <= 64 && addr >= 0x300000000ull && addr < 0x400000000ull) {
            /* longest CONTIGUOUS forward byte-run (any stride <=0x40): a "run" continues while
             * each write starts within 0x40 of the previous. max_bytes = largest single memcpy. */
            static unsigned long long n, max_bytes, max_at;
            static hb_gva_t prev, run_start, alo = ~0ull, ahi;
            unsigned long long cur;
            n++;
            if (addr < alo) alo = addr;
            if (addr + size > ahi) ahi = addr + size;
            if (n == 1 || !(addr >= prev && addr - prev <= 0x40)) run_start = addr;
            cur = (unsigned long long)(addr + size - run_start);
            if (cur > max_bytes) { max_bytes = cur; max_at = addr; }
            prev = addr;
            if (n <= 4 || (n % 4000000ull) == 0) {
                fprintf(stderr, "macrunner-hb-memcpy-w: n=%llu addr=%llx sz=%zu span=%llx "
                        "cur_run=0x%llx max_bytes=0x%llx max_at=%llx\n",
                        n, (unsigned long long)addr, size, (unsigned long long)(ahi - alo),
                        cur, max_bytes, (unsigned long long)max_at);
                fflush(stderr);
            }
        }
    }
grow_retry:
    if (trace_hot_cache_stats_enabled()) t_rsite = RSITE_WRITE;   /* diagnostic: TLS write, gated */
    region = hot_cache_lookup(mem, addr);
    is_hit = region != NULL;
    (void)is_hit;   /* итерация 1702: попадание в кеш больше НЕ решает, идти ли быстрым путём */
    if (!region) {
        region = find_region_after_hot_miss(mem, addr);
    }
    if (macrunner_hb_datadiverge_hit((uint64_t)addr, size)) {
        fprintf(stderr, "macrunner-hb-dv-write: gva=0x%llx size=%zu region=%p base=0x%llx rsize=0x%llx host_base=%p rperm=%d val=0x%llx\n",
                (unsigned long long)addr, size, (void*)region,
                region ? (unsigned long long)region->base : 0,
                region ? (unsigned long long)region->size : 0,
                region ? region->host_base : NULL,
                region ? (int)region->perm : -1,
                (unsigned long long)(size==8?*(const uint64_t*)in:0));
    }
#ifdef __APPLE__
    if ((addr & 0xfff) >= 0xfe0 && macrunner_hb_memory_environment.trace_jit_helper_fail) {
        static int t;
        if (t++ < 12) {
            int branch = (!region || addr + size > region->base + region->size || !(region->perm & HB_PERM_WRITE)) ? 0
                       : (!region->allocated && !region->host_base) ? (region->perm & HB_PERM_EXEC ? 2 : 1)
                       : region->host_base ? 3 : 4;
            fprintf(stderr, "macrunner-hb-wedge-write: addr=0x%llx size=%zu region=%p base=0x%llx rsize=0x%llx "
                    "perm=%d alloc=%d host=%p branch=%d\n",
                    (unsigned long long)addr, size, (void*)region,
                    region ? (unsigned long long)region->base : 0,
                    region ? (unsigned long long)region->size : 0,
                    region ? (int)region->perm : -1, region ? (int)region->allocated : -1,
                    region ? region->host_base : NULL, branch);
        }
    }
#endif
    if (!region || addr + size > region->base + region->size || !(region->perm & HB_PERM_WRITE)) {
        /* ★ НАБЛЮДЕНИЕ НАЧИНАЕТСЯ ЗДЕСЬ, а не у самого отказа. Ниже, у
         * macrunner-hb-write-deny, стоит HIT; если бы LOOKED стоял там же,
         * оба счётчика молчали бы вместе и ноль опять значил бы две разные
         * вещи. Место выбрано ХОЛОДНОЕ: сюда попадают только записи, не
         * прошедшие быстрым путём, — горячий путь (59 % времени HK) не задет. */
        HB_PROBE_LOOKED(&pr_write_deny);
        HB_PROBE_LOOKED(&pr_write_deny_heavy);
#ifdef __APPLE__
        /* MacRunner sentinel trace: log write blocked on sentinel range or null-zone. */
        if ((addr >= 0x7BD8E000u && addr < 0x7BD8F000u) || addr < 0x1000u) {
            fprintf(stderr,
                    "macrunner-hb-write-blocked: addr=%08llx size=%zu "
                    "region=%s perm=%d no_w=%d\n",
                    (unsigned long long)addr, size,
                    region ? "found" : "null",
                    region ? (int)region->perm : -1,
                    region ? !(region->perm & HB_PERM_WRITE) : 1);
            fflush(stderr);
        }
#endif
        if ((region || null_span_recheck_enabled()) && hb_memory_can_write_span(mem, addr, size)) {
            const uint8_t* src = in;
            hb_gva_t cur = addr;
            size_t remaining = size;
            while (remaining) {
                hb_region_t* r = hb_memory_find_region(mem, cur);
                size_t chunk = (size_t)(r->base + r->size - cur);
                hb_result_t rr;
                if (chunk > remaining) chunk = remaining;
                rr = hb_memory_write(mem, cur, src, chunk);
                if (rr != HB_OK) return rr;
                cur += chunk;
                src += chunk;
                remaining -= chunk;
            }
            return HB_OK;
        }
        if (mem->special_write && mem->special_write(mem->special_user, addr, in, size) == HB_OK) return HB_OK;
        /* Guest stack growth below the recorded region bottom (x64 CALL/PUSH at
         * rsp already under region->base): the page may be Wine-reserved guard
         * space that virtual_handle_fault can commit.  Let the embedder grow,
         * then redo the region lookup and the whole write once. */
        if (!grow_retried && mem->special_grow && mem->special_grow(mem->special_user, addr)) {
            grow_retried = 1;
            goto grow_retry;
        }
        {
            /* ★ БЫЛО: `static int traced; if (heavy || traced++ < 8) fprintf(...)`.
             * Два дефекта в одной строке, оба дают ноль, который читается как
             * «отказов не было»:
             *   1. потолок 8 усекал МОЛЧА — из журнала нельзя было узнать,
             *      восьмёрка это всё или первые восемь из миллиона;
             *   2. `heavy ||` короткозамыкает, поэтому при тяжёлом адресе
             *      `traced++` НЕ выполнялся — счётчик считал не то, что казалось.
             * Стало: учёт ВСЕГДА (hits), печать под потолком, и потолок
             * объявляет число НИЖНЕЙ ГРАНИЦЕЙ в переписи (EVENTS-TRUNCATED).
             * Populyacii две, потому что их и было две: тяжёлый диапазон
             * печатался БЕЗ потолка. */
            int heavy = (addr >= 0x3f0000000ULL && addr < 0x401000000ULL);
            HB_PROBE_SAY(heavy ? &pr_write_deny_heavy : &pr_write_deny,
                    "addr=0x%llx size=%zu region=%p base=0x%llx "
                    "rsize=0x%llx perm=%d alloc=%d host=%p\n",
                    (unsigned long long)addr, size, (void*)region,
                    region ? (unsigned long long)region->base : 0,
                    region ? (unsigned long long)region->size : 0,
                    region ? (int)region->perm : -1,
                    region ? (int)region->allocated : -1,
                    region ? region->host_base : NULL);
        }
        return HB_ERR_MEMORY_FAULT;
    }
#ifdef __APPLE__
    if (region && !region->allocated && !region->host_base) {
        if (!(region->perm & HB_PERM_EXEC) && !live_vm_write_mach_enabled()) {
            /* ★ То же, что в ветви окна гостя ниже: право в НАШЕЙ таблице не значит, что
             * страница отображена у хозяина. Голая запись падала бы SIGBUS внутри memmove,
             * мимо обработки отказов. mach_copy_to_host возвращает код вместо падения. */
            hb_result_t idw = mach_copy_to_host((void*)(uintptr_t)addr, in, size);
            if (idw != HB_OK) return idw;
            return HB_OK;
        }
        hb_result_t result = write_live_vm_region(mem, addr, in, size, region);
        if (result == HB_OK && (region->perm & HB_PERM_EXEC)) bump_generation(mem, region);
        return result;
    }
#endif
    if (region && region->host_base) {
#ifdef __APPLE__
        if (region->is_guest32)
        {
            void* host = region_host_ptr(region, addr);
            if (region->perm & HB_PERM_EXEC)
            {
                // executable/translated -> NOT bare memcpy, call special_write (SMC invalidation)
                if (mem->special_write && mem->special_write(mem->special_user, addr, in, size) == HB_OK) return HB_OK;
                hb_result_t result = mach_copy_to_host(host, in, size);
                if (result != HB_OK) {
                    hb_result_t sync_r = HB_ERR_MEMORY_FAULT;
                    if (region->perm & HB_PERM_WRITE) {
                        sync_r = guest32_sync_host_protection(region, addr, size);
                        if (sync_r == HB_OK) result = mach_copy_to_host(host, in, size);
                    }
#ifdef __APPLE__
                    /* MacRunner sentinel trace: log mach_copy_to_host failure on sentinel page. */
                    if (addr >= 0x7BD8E000u && addr < 0x7BD8F000u) {
                        mach_vm_address_t dbg_addr = (mach_vm_address_t)(uintptr_t)host;
                        mach_vm_size_t dbg_sz = 0;
                        vm_region_basic_info_data_64_t dbg_ri;
                        mach_msg_type_number_t dbg_cnt = VM_REGION_BASIC_INFO_COUNT_64;
                        mach_port_t dbg_obj = MACH_PORT_NULL;
                        memset(&dbg_ri, 0, sizeof(dbg_ri));
                        mach_vm_region(mach_task_self(), &dbg_addr, &dbg_sz, VM_REGION_BASIC_INFO_64,
                                       (vm_region_info_t)&dbg_ri, &dbg_cnt, &dbg_obj);
                        if (dbg_obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), dbg_obj);
                        fprintf(stderr,
                                "macrunner-hb-sentinel-write-fail: addr=%08llx perm=%d "
                                "mach_prot=0x%x max_prot=0x%x sync_r=%d retry_r=%d\n",
                                (unsigned long long)addr, (int)region->perm,
                                (int)dbg_ri.protection, (int)dbg_ri.max_protection,
                                (int)sync_r, (int)result);
                        fflush(stderr);
                    }
#endif
                }
                if (result != HB_OK) return result;
            }
            /* итерация 1702, приказ 169: `is_hit` убран и здесь — то же условие, тот же класс. */
            else if (guest32_direct_copy_safe(region, addr, size) &&
                     guest32_copy_no_fence_enabled())
            {
                /* Право есть — копируем прямо; права нет — не пробуем падать, а идём
                 * mach-путём. Ограждение не нужно ни в одном из двух случаев. */
                void* w_host = region_host_ptr(region, addr);
                if (guest32_perm_audit_enabled())
                    guest32_perm_audit(region, addr, size, true);  /* приказ 171, прибор, по гейту */
                if (!guest32_copy_perm_ok(region, true))
                {
                    hb_result_t w_res = mach_copy_to_host(w_host, in, size);
                    if (w_res != HB_OK) return w_res;
                }
                else
                {
                    /* ★★★ MacRunner 2026-08-24, КООРДИНАТОР — БЕЗ ОГРАЖДЕНИЯ ПРАВА НАДО
                     * ПРИВЕСТИ В ПОРЯДОК ЗАРАНЕЕ, А НЕ ЛОВИТЬ ОТКАЗ ПОСЛЕ.
                     *
                     * Прибор PERM_AUDIT на приёмке: perm=3 (учёт: READ|WRITE) против
                     * prot=0x5 (страница: READ|EXEC), max=0x7. Учёт разрешает запись,
                     * защита её не даёт — и `hb_copy_width` роняет процесс по Bus error.
                     * С ограждением этот отказ ловился `siglongjmp` и чинился
                     * `guest32_sync_host_protection`; сняв ограждение, мы сняли и починку.
                     *
                     * У QEMU на этом месте таблица флагов страниц и проверка ДО доступа
                     * (research/qemu/accel/tcg/user-exec.c:772, `page_get_flags`), а при
                     * неудаче — сигнал ГОСТЮ, а не смерть процесса. Таблицы у нас пока нет
                     * (шаг 21 карты), поэтому приводим права одним `mprotect` — он дешевле
                     * `mach_vm_region` и делает ровно то, что делало ограждение, но заранее.
                     *
                     * Ставится ТОЛЬКО когда ограждение снято: с ограждением цена не нужна. */
                    if (guest32_copy_no_fence_enabled())
                    {
                        static _Thread_local const hb_region_t* last_synced;
                        static _Thread_local hb_perm_t last_perm;
                        if (last_synced != region || last_perm != region->perm)
                        {
                            {
                                hb_result_t sr = guest32_sync_host_protection(region, region->base, region->size);
                                static int said;
                                if (said++ < 8) {
                                    fprintf(stderr, "macrunner-hb-presync: base=0x%llx size=%zu perm=0x%x ret=%d\n",
                                            (unsigned long long)region->base, region->size,
                                            (unsigned)region->perm, (int)sr);
                                    fflush(stderr);
                                }
                            }
                            last_synced = region;
                            last_perm = region->perm;
                            g_fence_presync++;
                        }
                    }
                    /* ★★★★★ MacRunner 2026-08-24 — ПРАВО В РЕГИОНЕ ≠ СТРАНИЦА ОТОБРАЖЕНА.
                     *
                     * Эта ветвь означала «право на запись есть, копируем прямо». Но право
                     * записано в НАШЕЙ таблице областей, а страница у хозяина может быть ещё
                     * не отображена — Windows коммитит такие по обращению. Тогда голый
                     * hb_copy_width падает SIGBUS ВНУТРИ хозяйского memmove, то есть мимо
                     * всей обработки отказов гостя, и процесс умирает.
                     *
                     * Поймано слиянием блоков: длинная единица доходит до записи, до которой
                     * короткий блок не доходил. Улика — `lr_sym=hb_memory_write_inner ->
                     * _platform_memmove`, адрес 0xC00405158 при базе окна 0xC00000000, то
                     * есть совершенно легальный гостевой адрес 0x405158 в районе .data.
                     *
                     * Имя гейта вводило в заблуждение: `GUEST32_COPY_NO_FENCE` управлял
                     * только предварительной синхронизацией прав, а ограждения не было НИ ПРИ
                     * КАКОМ его значении. Теперь при выключенном гейте (умолчание) запись
                     * идёт через mach_copy_to_host — он возвращает КОД ОШИБКИ вместо падения,
                     * и при отказе мы синхронизируем права и повторяем, ровно как это уже
                     * сделано ветвью выше для исполняемых областей. */
                    if (!guest32_copy_no_fence_enabled()) {
                        hb_result_t w_res = mach_copy_to_host(w_host, in, size);
                        if (w_res != HB_OK) {
                            hb_result_t sr = guest32_sync_host_protection(region, addr, size);
                            if (sr == HB_OK) w_res = mach_copy_to_host(w_host, in, size);
                        }
                        if (w_res != HB_OK) return w_res;
                    } else {
                        hb_copy_width(w_host, in, size);
                    }
                }
            }
            else if (guest32_direct_copy_safe(region, addr, size))
            {
                sigjmp_buf jmp;
                if (guest32_perm_audit_enabled())
                    guest32_perm_audit(region, addr, size, true);  /* приказ 171, прибор, по гейту */
                install_sig_handlers();
                /* 2026-08-22: адрес ячейки берём ОДИН раз — разбор у hb_safe_jmp_cell.
                 * `volatile` обязателен: местная переменная, пережившая siglongjmp. */
                sigjmp_buf** volatile jcell = hb_safe_jmp_cell();
                *jcell = &jmp;
                /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: единица заставляет Apple-овский sigsetjmp
                 * сохранять маску сигналов И альтернативный стек — это sigprocmask 3883 плюс
                 * __sigaltstack 3462, около 90% рабочего потока после снятия mach-пути.
                 * С нулём не сохраняем ничего, а разблокировку берёт на себя обработчик. */
                g_fence_armed++;
                if ((g_fence_armed & 0x3fffffull) == 0) hb_fence_census("period");
                if (sigsetjmp(jmp, hb_fast_sigjmp_enabled() ? 0 : 1) == 0)
                {
                    hb_copy_width(host, in, size);
                    *jcell = NULL;
                }
                else
                {
                    g_fence_taken++;    /* ★ ограждение СРАБОТАЛО — длинный переход (запись) */
                    *jcell = NULL;
                    hb_result_t result = mach_copy_to_host(host, in, size);
                    if (result != HB_OK) {
                        hb_result_t sync_r = HB_ERR_MEMORY_FAULT;
                        if (region->perm & HB_PERM_WRITE) {
                            sync_r = guest32_sync_host_protection(region, addr, size);
                            if (sync_r == HB_OK) result = mach_copy_to_host(host, in, size);
                        }
#ifdef __APPLE__
                        /* MacRunner sentinel trace: log mach_copy_to_host failure on sentinel page. */
                        if (addr >= 0x7BD8E000u && addr < 0x7BD8F000u) {
                            mach_vm_address_t dbg_addr = (mach_vm_address_t)(uintptr_t)host;
                            mach_vm_size_t dbg_sz = 0;
                            vm_region_basic_info_data_64_t dbg_ri;
                            mach_msg_type_number_t dbg_cnt = VM_REGION_BASIC_INFO_COUNT_64;
                            mach_port_t dbg_obj = MACH_PORT_NULL;
                            memset(&dbg_ri, 0, sizeof(dbg_ri));
                            mach_vm_region(mach_task_self(), &dbg_addr, &dbg_sz, VM_REGION_BASIC_INFO_64,
                                           (vm_region_info_t)&dbg_ri, &dbg_cnt, &dbg_obj);
                            if (dbg_obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), dbg_obj);
                            fprintf(stderr,
                                    "macrunner-hb-sentinel-write-fail: addr=%08llx perm=%d "
                                    "mach_prot=0x%x max_prot=0x%x sync_r=%d retry_r=%d\n",
                                    (unsigned long long)addr, (int)region->perm,
                                    (int)dbg_ri.protection, (int)dbg_ri.max_protection,
                                    (int)sync_r, (int)result);
                            fflush(stderr);
                        }
#endif
                    }
                    if (result != HB_OK) return result;
                }
            }
            else
            {
                hb_result_t result = mach_copy_to_host(host, in, size);
                if (result != HB_OK) {
                    hb_result_t sync_r = HB_ERR_MEMORY_FAULT;
                    if (region->perm & HB_PERM_WRITE) {
                        sync_r = guest32_sync_host_protection(region, addr, size);
                        if (sync_r == HB_OK) result = mach_copy_to_host(host, in, size);
                    }
#ifdef __APPLE__
                    /* MacRunner sentinel trace: log mach_copy_to_host failure on sentinel page. */
                    if (addr >= 0x7BD8E000u && addr < 0x7BD8F000u) {
                        mach_vm_address_t dbg_addr = (mach_vm_address_t)(uintptr_t)host;
                        mach_vm_size_t dbg_sz = 0;
                        vm_region_basic_info_data_64_t dbg_ri;
                        mach_msg_type_number_t dbg_cnt = VM_REGION_BASIC_INFO_COUNT_64;
                        mach_port_t dbg_obj = MACH_PORT_NULL;
                        memset(&dbg_ri, 0, sizeof(dbg_ri));
                        mach_vm_region(mach_task_self(), &dbg_addr, &dbg_sz, VM_REGION_BASIC_INFO_64,
                                       (vm_region_info_t)&dbg_ri, &dbg_cnt, &dbg_obj);
                        if (dbg_obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), dbg_obj);
                        fprintf(stderr,
                                "macrunner-hb-sentinel-write-fail: addr=%08llx perm=%d "
                                "mach_prot=0x%x max_prot=0x%x sync_r=%d retry_r=%d\n",
                                (unsigned long long)addr, (int)region->perm,
                                (int)dbg_ri.protection, (int)dbg_ri.max_protection,
                                (int)sync_r, (int)result);
                        fflush(stderr);
                    }
#endif
                }
                if (result != HB_OK) return result;
            }
            if (region->perm & HB_PERM_EXEC) bump_generation(mem, region);
            return HB_OK;
        }
        if (guest32_copy_needs_mach(region, addr, size))
        {
            hb_result_t result = mach_copy_to_host(region_host_ptr(region, addr), in, size);
            if (result != HB_OK) return result;
            if (region->perm & HB_PERM_EXEC) bump_generation(mem, region);
            return HB_OK;
        }
#endif
        /* ★★★★★ MacRunner 2026-08-24 — ПОСЛЕДНИЕ ДВЕ НЕЗАЩИЩЁННЫЕ ЗАПИСИ.
         *
         * Обе пишут голым hb_copy_width: одна по host_base области, другая — вообще без
         * области, по адресу как есть. Право на запись проверено ВЫШЕ по нашей таблице
         * областей, но отображена ли страница у хозяина — нет; Windows коммитит такие по
         * обращению. Отказ приходит SIGBUS'ом внутри хозяйского memmove, мимо всей обработки
         * отказов гостя, и процесс умирает молча.
         *
         * Ветвей записи в этой функции семь. Шесть уже шли через mach_copy_to_host или под
         * sigsetjmp; эти две остались голыми — их и ловило слияние блоков, доводя исполнение
         * до записи, до которой короткий блок не доходил. */
        {
            hb_result_t hw = mach_copy_to_host(region_host_ptr(region, addr), in, size);
            if (hw != HB_OK) return hw;
        }
        if (region->perm & HB_PERM_EXEC) bump_generation(mem, region);
        return HB_OK;
    }
    {
        hb_result_t nw = mach_copy_to_host((void*)(uintptr_t)addr, in, size);
        if (nw != HB_OK) return nw;
    }
    return HB_OK;
}

static void* hb_memory_host_ptr_inner(hb_memory_t* mem, hb_gva_t addr, size_t size, hb_perm_t perm) {
    hb_region_t* region;
    int dv_hit = macrunner_hb_datadiverge_hit((uint64_t)addr, size);

    if (!mem || !size) return NULL;
    if (!normalize_guest32_mirror_addr(mem, &addr, size)) return NULL;
    if (trace_hot_cache_stats_enabled()) t_rsite = RSITE_HOST_PTR;   /* diagnostic: TLS write, gated */
    region = find_region_normalized(mem, addr);
    if (dv_hit) {
        fprintf(stderr, "macrunner-hb-dv-read-host_ptr: gva=0x%llx size=%zu want_perm=%d region=%p base=0x%llx rsize=0x%llx host_base=%p rperm=%d\n",
                (unsigned long long)addr, size, (int)perm, (void*)region,
                region ? (unsigned long long)region->base : 0,
                region ? (unsigned long long)region->size : 0,
                region ? region->host_base : NULL,
                region ? (int)region->perm : -1);
    }
    if (!region || addr + size > region->base + region->size) { if (dv_hit) fprintf(stderr, "macrunner-hb-dv-read-host_ptr: NO-REGION -> NULL (live fallback)\n"); return NULL; }
    if ((region->perm & perm) != perm) { if (dv_hit) fprintf(stderr, "macrunner-hb-dv-read-host_ptr: PERM-MISMATCH -> NULL (live fallback)\n"); return NULL; }
#ifdef __APPLE__
    if (region->host_base && region->is_guest32 && (perm & HB_PERM_WRITE) &&
        guest32_copy_needs_mach(region, addr, size))
        return NULL;
#endif
    if (region->host_base) { void* p = region_host_ptr(region, addr); if (dv_hit) fprintf(stderr, "macrunner-hb-dv-read-host_ptr: -> region host=%p\n", p); return p; }
    if ((perm & HB_PERM_WRITE) && (region->perm & HB_PERM_EXEC)) { if (dv_hit) fprintf(stderr, "macrunner-hb-dv-read-host_ptr: EXEC-write-guard -> NULL\n"); return NULL; }
    if (dv_hit) fprintf(stderr, "macrunner-hb-dv-read-host_ptr: -> identity host=%p\n", (void*)(uintptr_t)addr);
    return (void*)(uintptr_t)addr;
}

void hb_memory_set_special_handlers(hb_memory_t* mem,
                                    hb_result_t (*read_fn)(void* user, hb_gva_t addr, void* out, size_t size),
                                    hb_result_t (*write_fn)(void* user, hb_gva_t addr, const void* in, size_t size),
                                    void* user) {
    if (!mem) return;
    mem->special_read = read_fn;
    mem->special_write = write_fn;
    mem->special_user = user;
}

/* MacRunner 2026-08-16, лейн ПАМЯТЬ, итерация 6 — СМОТРОВОЕ ОКНО В СПЕЦИАЛЬНЫЕ ОБРАБОТЧИКИ.
 *
 * Зачем. Стенд поймал падение записи через слой по адресу 0x1 с сигналом SIGBUS — это ПЕРЕХОД
 * по адресу 1, а не запись не туда. Гашение обработчиков падение снимает, значит виноват
 * косвенный вызов `mem->special_write` (2964) или `mem->special_grow` (2969). При этом ставить
 * их в том процессе НЕКОМУ: `hb_memory_create` зовёт `calloc`, а `set_*` не зовёт никто.
 * Остаётся затирание структуры. Чтобы найти затирающего, нужно видеть поля снаружи.
 *
 * Только чтение, ничего не меняет. */
void macrunner_hb_memory_debug_handlers(const hb_memory_t* mem,
                                        void** out_read, void** out_write,
                                        void** out_grow, void** out_user) {
    if (out_read)  *out_read  = mem ? (void*)mem->special_read  : NULL;
    if (out_write) *out_write = mem ? (void*)mem->special_write : NULL;
    if (out_grow)  *out_grow  = mem ? (void*)mem->special_grow  : NULL;
    if (out_user)  *out_user  = mem ? mem->special_user : NULL;
}

void hb_memory_set_grow_handler(hb_memory_t* mem, bool (*grow_fn)(void* user, hb_gva_t addr)) {
    if (!mem) return;
    mem->special_grow = grow_fn;
}

#define RW_U(bits) \
hb_result_t hb_memory_read_u##bits(hb_memory_t* mem, hb_gva_t addr, uint##bits##_t* out) { \
    return hb_memory_read(mem, addr, out, sizeof(uint##bits##_t)); \
} \
hb_result_t hb_memory_write_u##bits(hb_memory_t* mem, hb_gva_t addr, uint##bits##_t val) { \
    return hb_memory_write(mem, addr, &val, sizeof(uint##bits##_t)); \
}

RW_U(8)
RW_U(16)
RW_U(32)
RW_U(64)

/* MacRunner 2026-08-16, лейн ПАМЯТЬ — ВЫБОРКА КОМАНДЫ ПРОВЕРЯЕТ ПРАВО ИСПОЛНЕНИЯ.
 *
 * Было: `return hb_memory_read_u8(...)`, то есть выборка кода спрашивала право ЧТЕНИЯ. Стенд
 * `tests/hb_memory_contract_test.c` показал расхождение слоя с самим собой на трёх наборах прав
 * из семи: на `r--` и `rw-` предикат `can_exec` запрещал, а `fetch` ВЫБИРАЛ БАЙТ. То есть NX
 * на этом пути не действовал вовсе: неисполняемая страница выбиралась как код.
 *
 * Единственный в движке вызывающий — `hb_wow64cpu.c:758-759`, где `can_exec` стоит СТРОКОЙ ВЫШЕ
 * `fetch`. Для него правка тождественна (та же проверка, что он уже делает сам), поэтому она
 * заведомо не меняет поведения i386-пути, а дыру для любого будущего вызывающего закрывает.
 * Гейта нет намеренно: выключенный гейт — главная потеря времени этого проекта, а правка инертна.
 *
 * ОСТАЁТСЯ НЕЗАКРЫТЫМ (осознанно): страница `--x` — исполняемая, но не читаемая. `can_exec` её
 * разрешает, `hb_memory_read_u8` отказывает, потому что путь чтения построен вокруг
 * `HB_PERM_READ`. Замер стенда: `host_ptr(addr,1,HB_PERM_EXEC)` на такой странице возвращает
 * валидный указатель и разыменование проходит — то есть починить можно. Но при тождественном
 * отображении (`host_base == NULL`, гостевой адрес = хостовой) защиту страницы ставил не мы, и
 * сырое разыменование обменяло бы честный `HB_ERR_MEMORY_FAULT` на SIGSEGV хоста. Такой обмен
 * без прогона не делаю. */
hb_result_t hb_memory_fetch(hb_memory_t* mem, hb_gva_t addr, uint8_t* out) {
    if (!hb_memory_can_exec(mem, addr, 1)) {
        hb_memory_note_fault(addr, 1, 0);
        return HB_ERR_MEMORY_FAULT;
    }
    return hb_memory_read_u8(mem, addr, out);
}

/* Обход дерева БЕЗ фильтра is_guest32 — см. пояснение у объявления в hb_memory.h. */
hb_region_t* hb_memory_find_region_raw(hb_memory_t* mem, hb_gva_t addr) {
    hb_region_t* n;
    if (!mem) return NULL;
    for (n = mem->region_tree; n; ) {
        if (addr < n->base) n = n->tree_left;
        else if (addr >= n->base + n->size) n = n->tree_right;
        else return n;
    }
    return NULL;
}

hb_region_t* hb_memory_find_region(hb_memory_t* mem, hb_gva_t addr) {
    if (!mem) return NULL;
    if (!normalize_guest32_mirror_addr(mem, &addr, 1)) return NULL;
    /* Only claim the generic tag when no caller identified itself, otherwise the external tags below would be
     * overwritten by the very wrapper they call. Callers reset to 0 after use. */
    if (trace_hot_cache_stats_enabled() && t_rsite < RSITE_JIT_HOST_SPAN) t_rsite = RSITE_FIND_REGION;
    return find_region_normalized(mem, addr);
}

/* MacRunner 2026-07-31 — hb_memory_read/hb_memory_write already ran hot_cache_lookup and only call this on a
 * miss, yet the unconditional lookup below then ran the SAME 16-slot linear scan a second time. That second
 * scan can only ever miss: same addr, and either the epoch is unchanged (same slots -> same verdict) or it
 * changed (hot_cache_reset_tls NULLs every slot -> empty scan). So it is pure waste, ~32 % of every lookup in
 * the run paying a 16-deep pointer chase twice. use_hot=false skips it on those known-miss paths; the gate
 * exists only so the redundancy can be re-armed for an A/B. */
static int hot_miss_skip_disabled(void) {
    const char* e = hb_gate( HB_GATE_HB_NO_HOT_MISS_SKIP );
    int cached = e && *e && *e != '0';
    return cached;
}

/* MacRunner 2026-08-22, КООРДИНАТОР — ГОРЯЧИЙ КЕШ ПАМЯТИ НА i386 НЕ ПОПАДАЛ НИ РАЗУ.
 *
 * Прибор `MACRUNNER_HB_TRACE_HOT_CACHE`, один и тот же стенд, обе стороны:
 *
 *     i386     80 000 001 обращений,          0 попаданий      0,00 %
 *     x86-64   16 000 001 обращений, 15 999 957 попаданий    100,00 %
 *
 * Причина видна в этой самой функции: ветвь guest32 стоит ПЕРЕД `use_hot` и, найдя область
 * обходом дерева, возвращает её НЕ ПОЛОЖИВ В КЕШ. Единственная вставка живёт ниже, во втором
 * обходе, куда 32-битный гость не доходит никогда. Кеш остаётся пуст навсегда.
 *
 * Чего это стоило. `hb_memory_read_inner` и `hb_memory_write_inner` зовут `hot_cache_lookup`
 * ПЕРВЫМ делом, и на i386 он всегда промахивался: линейный просмотр 16 ячеек впустую, а
 * следом полный обход дерева. В профиле рабочего потока это `hot_cache_lookup` 10,1 %,
 * `find_region_impl` 9,5 % и `hot_cache_note` 3,0 % — около 22 % на пустом месте.
 *
 * Правка семантики НЕ меняет: возвращается та же область, что и раньше, — просто она
 * запоминается. Правило `is_guest32 ? n : NULL` сохранено и применяется к попаданию тоже.
 * Не найдено обходом — проваливаемся дальше, ровно как прежде.
 *
 * Гейт MACRUNNER_HB_GUEST32_HOT_CACHE СНЯТ 02.09.2026: правка безусловна,
 * выключенная ветка возвращала известный дефект (scripts/гейты.py).
 * сличение двух рук В ОДНОМ двоичном, а не подменой модуля. */
static hb_region_t* find_region_impl(hb_memory_t* mem, hb_gva_t addr, bool use_hot) {
    if (!mem) return NULL;
    if (mem->guest32_base && addr < HB_GUEST32_SIZE) {
        hb_region_t* n;
        if (use_hot) {
            hb_region_t* hot = hot_cache_lookup(mem, addr);
            if (hot) return hot->is_guest32 ? hot : NULL;
        }
        n = mem->region_tree;
        while (n) {
            if (addr < n->base) {
                n = n->tree_left;
            } else if (addr >= n->base + n->size) {
                n = n->tree_right;
            } else {
                if (n->is_guest32) hot_cache_insert(mem, n);
                return n->is_guest32 ? n : NULL;
            }
        }
    }

    if (use_hot) {
        hb_region_t* hot = hot_cache_lookup(mem, addr);
        if (hot) return hot;
    }

    /* ONE acquire load of the negative epoch for the whole resolve, not one per helper. */
    uint64_t add_epoch = __atomic_load_n(&mem->add_gen, __ATOMIC_ACQUIRE);
    if (gap_lookup(mem, addr, add_epoch)) {
        /* Falsify the bracket instead of arguing for it: with MACRUNNER_HB_VERIFY_NEG_CACHE the gap answer is
         * checked against the full walk it replaced, and any disagreement is printed with the entry that lied.
         * A gap hit claims "no region contains addr"; if the treap finds one, the bracket is wrong. */
        if (verify_neg_cache_enabled()) {
            t_gap_verified++;
            for (hb_region_t* v = mem->region_tree; v; ) {
                if (addr < v->base) v = v->tree_left;
                else if (addr >= v->base + v->size) v = v->tree_right;
                else {
                    fprintf(stderr, "macrunner-hb-negcache-VIOLATION: addr=0x%llx claimed unmapped but region "
                                    "[0x%llx,0x%llx) contains it; gap[0]=[0x%llx,0x%llx) epoch=%llu\n",
                            (unsigned long long)addr, (unsigned long long)v->base,
                            (unsigned long long)(v->base + v->size),
                            (unsigned long long)g_gap_tls.e[0].lo, (unsigned long long)g_gap_tls.e[0].hi,
                            (unsigned long long)add_epoch);
                    fflush(stderr);
                    return v;
                }
            }
        }
        return NULL;
    }

    /* MacRunner (2026-06-17, HK first-frame perf): O(log n) treap walk instead of an O(n)
     * linear scan of mem->regions.  mem->region_tree is the SAME treap the guest32 path
     * walks above: keyed by base, maintained on every add (insert_region_head -> tree_insert)
     * and rebuilt on remove (rebuild_region_tree).  Regions are non-overlapping (every add is
     * guarded by any_overlap), so the containing region is UNIQUE and this walk returns
     * exactly the region the old linear scan would (identical result, just O(log n)).  Once the
     * module_from_pc mach-scan was fixed, find_region_normalized became the #1 main-thread
     * hotspot (~33% during Mono ReloadAssembly) — the guest's region list grows large under
     * Mono so the per-memory-access linear scan dominated. */
    hb_gva_t gap_lo = 0, gap_hi = ~(hb_gva_t)0;
    uint64_t nodes = 0;
    for (hb_region_t* n = mem->region_tree; n; ) {
        nodes++;
        if (addr < n->base) {
            if (n->base < gap_hi) gap_hi = n->base;      /* last left turn = successor */
            n = n->tree_left;
        } else if (addr >= n->base + n->size) {
            if (n->base + n->size > gap_lo) gap_lo = n->base + n->size;  /* last right turn = predecessor */
            n = n->tree_right;
        } else {
            if (trace_hot_cache_stats_enabled()) { t_walk_nodes_ok += nodes; t_walk_ok++; }
            hot_cache_insert(mem, n);
            if (trace_hot_cache_stats_enabled()) hot_cache_note_resolved(n);
            return n;
        }
    }
    if (trace_hot_cache_stats_enabled()) { t_walk_nodes_fail += nodes; t_walk_fail++; }
    gap_insert(mem, gap_lo, gap_hi, add_epoch);
    if (trace_hot_cache_stats_enabled()) hot_cache_note_unresolved(addr);
    return NULL;
}

static hb_region_t* find_region_normalized(hb_memory_t* mem, hb_gva_t addr) {
    return find_region_impl(mem, addr, true);
}

/* For callers that just missed in the hot cache themselves. */
static hb_region_t* find_region_after_hot_miss(hb_memory_t* mem, hb_gva_t addr) {
    return find_region_impl(mem, addr, hot_miss_skip_disabled());
}

static bool check_perm_region(hb_memory_t* mem, hb_gva_t addr, size_t size, hb_perm_t p, hb_region_t** out) {
    hb_region_t* r;
    if (!normalize_guest32_mirror_addr(mem, &addr, size)) return false;
    if (trace_hot_cache_stats_enabled()) t_rsite = RSITE_CHECK_PERM;   /* diagnostic: TLS write, gated */
    r = find_region_normalized(mem, addr);
    if (out) *out = r;
    if (!r) return false;
    if (addr + size > r->base + r->size) return false;
    return (r->perm & p) != 0;
}

static bool check_perm(hb_memory_t* mem, hb_gva_t addr, size_t size, hb_perm_t p) {
    return check_perm_region(mem, addr, size, p, NULL);
}

static bool check_perm_span(hb_memory_t* mem, hb_gva_t addr, size_t size, hb_perm_t p) {
    hb_gva_t cur = addr;
    size_t remaining = size;

    if (!mem) return false;
    if (!normalize_guest32_mirror_addr(mem, &cur, size)) return false;
    while (remaining) {
        hb_region_t* r = hb_memory_find_region(mem, cur);
        size_t chunk;

        if (!r || !(r->perm & p)) return false;
        chunk = (size_t)(r->base + r->size - cur);
        if (chunk > remaining) chunk = remaining;
        cur += chunk;
        remaining -= chunk;
    }
    return true;
}

bool hb_memory_can_read(hb_memory_t* mem, hb_gva_t addr, size_t size) {
    return check_perm(mem, addr, size, HB_PERM_READ);
}
bool hb_memory_can_write(hb_memory_t* mem, hb_gva_t addr, size_t size) {
    return check_perm(mem, addr, size, HB_PERM_WRITE);
}
bool hb_memory_can_exec(hb_memory_t* mem, hb_gva_t addr, size_t size) {
    return check_perm(mem, addr, size, HB_PERM_EXEC);
}

bool hb_memory_can_read_span(hb_memory_t* mem, hb_gva_t addr, size_t size) {
    return check_perm_span(mem, addr, size, HB_PERM_READ);
}

bool hb_memory_can_write_span(hb_memory_t* mem, hb_gva_t addr, size_t size) {
    return check_perm_span(mem, addr, size, HB_PERM_WRITE);
}

hb_result_t hb_memory_setup_stack(hb_memory_t* mem, hb_gva_t top, size_t size) {
    if (!mem) return HB_ERR_INVALID_ARG;
    (void)top;
    hb_result_t r = hb_memory_map(mem, 0, size, HB_PERM_READ | HB_PERM_WRITE);
    if (r != HB_OK) return r;
    hb_region_t* rg = mem->regions;
    if (!rg) return HB_ERR_INTERNAL;
    rg->is_stack = true;
    mem->stack_bottom = rg->base;
    mem->stack_top = rg->base + rg->size;
    return HB_OK;
}

hb_result_t hb_memory_setup_heap(hb_memory_t* mem, hb_gva_t base, size_t size) {
    if (!mem) return HB_ERR_INVALID_ARG;
    (void)base;
    hb_result_t r = hb_memory_map(mem, 0, size, HB_PERM_READ | HB_PERM_WRITE);
    if (r != HB_OK) return r;
    hb_region_t* rg = mem->regions;
    if (!rg) return HB_ERR_INTERNAL;
    rg->is_heap = true;
    mem->heap_base = rg->base;
    mem->heap_size = rg->size;
    return HB_OK;
}
