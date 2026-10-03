#include "hb_env.h"
#include "hb_gates.h"

/* Гейт из таблицы. Кеш по месту снят: значение и так лежит в массиве,
 * а кеш требовал переменной, регистрации её адреса в общем списке и
 * участия в сбросе — три сущности там, где хватает одной загрузки.
 * Выражение оставлено ДОСЛОВНО прежним: пусто или не задан — умолчание,
 * первый символ '0' — ноль. Оно не совпадает с hb_env_flag, и подгонять
 * его под соседа значило бы тихо переменить смысл шести десятков гейтов. */
static inline int runtime_gate_flag(enum hb_gate_id id, int default_value)
{
    const char* env = hb_gate( id );
    return (env && *env) ? (*env != '0') : default_value;
}

#include "hb_runtime.h"
#include <mach/mach_time.h>
#include "hb_probe.h"   /* приборы, у которых «не смотрел» и «не было» — РАЗНЫЕ ответы */
#include <sys/time.h>
#include "hb_codegen.h"
#include "hb_memory.h"
#include "hb_thunk.h"   /* HB_IMPORT_THUNK_BASE — арена переходников импорта */
#include "hb_record.h" /* ★ 07.09.2026, лейн ПОВТОР-3 — запись потока гостя (три вызова ниже) */
#include "hb_contract_telemetry.h"
#include <setjmp.h>
#include <signal.h>   /* sigprocmask/sigemptyset/sigaddset — маска перед siglongjmp из обработчика */
#include <stdio.h>
#if defined(__aarch64__)
#include <arm_acle.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>
#include <unistd.h>   /* write(2) — async-signal-safe объявление гейта TLS_SLOT_CACHE */
#if defined(__APPLE__)
#include <malloc/malloc.h>
#include <sys/ucontext.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include "hb_alloc_count.h"



/* Регистрация кеша гейта в общем сбросе — см. hb_codegen.h. */


/* Выборочная самопроверка round-trip: определения ниже, у прочих гейтов рантайма. */
static bool reloc_selfcheck_now(void);
static unsigned long long g_selfcheck_done, g_selfcheck_skipped;
#endif

/* 28 — итерация 1095: шесть привилегированных команд получили свои опкоды вместо общего
 * `HB_INS_PRIV` (поведение прежнее), перечень опкодов сдвинулся.
 *
 * ★★★★★★★ 29 — 05.09.2026: блокирующие RMW (lock add/sub/and/or/xor/adc/sbb/neg/not/
 * bts/btr/btc) выпускаются НЕ строкой, а вызовом неделимого помощника. Прежний выпуск
 * был НЕАТОМАРЕН и терял приращения (стенд: 3 969 из 400 000 на i386, 583 на x64).
 * Правка БЕЗУСЛОВНА и гейта не имеет, поэтому в ключ её внести можно только номером
 * версии — иначе блок, переведённый ДО правки, поднимется из постоянного кеша ПОСЛЕ
 * неё и вернёт потерю обратно, молча и без единого признака в журнале. */
/* 30 (05.09.2026): у блоба постоянного кеша появился хвост с картой отказов (host_off/host_instr),
 * см. ripmap_trailer_append/parse. Блоб без хвоста этой версией не читается — пересобирается. */
#define HB_RUNTIME_PERSISTENT_CACHE_VERSION 30u
#define HB_RUNTIME_PERSISTENT_CACHE_FLAG_DIRECT_MEM   0x01u
#define HB_RUNTIME_PERSISTENT_CACHE_FLAG_DIRECT_STACK 0x02u
#define HB_RUNTIME_PERSISTENT_CACHE_FLAG_DIRECT_SCALAR_SCAN 0x04u
#define HB_RUNTIME_PERSISTENT_CACHE_FLAG_DIRECT_SCALAR_MEM  0x08u
#define HB_RUNTIME_PERSISTENT_CACHE_FLAG_BLOCK_CHAIN 0x10u
#define HB_RUNTIME_PERSISTENT_CACHE_FLAG_INDIRECT_IC 0x20u
#define HB_RUNTIME_PERSISTENT_CACHE_FLAG_NATIVE_MEMMOVE 0x40u

#define HB_RUNTIME_CACHE_BLOCK_SENTINEL  0x48425254424c4b31ull /* HBRTBLK1 */
#define HB_RUNTIME_CACHE_HELPER_SENTINEL 0x48425254484c5000ull /* HBRTHLP + id */
#define HB_RUNTIME_CACHE_HELPER_MASK     0xfffffffffffff000ull
#define HB_RUNTIME_CACHE_INSTR_SENTINEL  0x48425254494e0000ull /* HBRTIN + index */
#define HB_RUNTIME_CACHE_INSTR_MASK      0xffffffffffff0000ull
/* Key bit distinguishing entries written by the table-driven store path from the legacy one. */
#define HB_PERSIST_FLAG_RELOC            0x80u

extern void hb_jit_helper_exec_interp_ir(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_load_operand_lazy(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_store_operand_lazy(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_call_operand(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_xfg_dispatch_call(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_jmp_operand(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_cmp_test_operand_lazy(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_binop_operand_lazy(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_mul_div_operand(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_double_shift_operand(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_extend_operand_lazy(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_mov_operand_lazy(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_not_operand_lazy(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_neg_operand_lazy(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_bit_scan(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_loop_branch(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_ir_block(hb_context_t* ctx, const hb_ir_block_t* block);
extern void hb_jit_helper_exec_load_cmp_jcc_block(hb_context_t* ctx, const hb_ir_block_t* block);
extern void hb_jit_helper_exec_cmp_setcc_ret_block(hb_context_t* ctx, const hb_ir_block_t* block);
extern void hb_jit_helper_exec_unity_string_bsearch_loop(hb_context_t* ctx, const hb_ir_block_t* block);
extern void hb_jit_helper_exec_unity_freelist_fill_loop(hb_context_t* ctx, const hb_ir_block_t* block);
extern void hb_jit_helper_exec_unity_u32_ptr_compare(hb_context_t* ctx, const hb_ir_block_t* block);
extern void hb_jit_helper_exec_mono_metadata_bsearch_loop(hb_context_t* ctx, const hb_ir_block_t* block);
extern void hb_jit_helper_exec_mono_string_hash(hb_context_t* ctx, const hb_ir_block_t* block);
extern void hb_jit_helper_exec_mono_string_equal(hb_context_t* ctx, const hb_ir_block_t* block);
extern void hb_jit_helper_exec_mono_metadata_rowptr_entry(hb_context_t* ctx, const hb_ir_block_t* block);
extern void hb_jit_helper_exec_mono_metadata_decode_row_loop(hb_context_t* ctx, const hb_ir_block_t* block);
extern void hb_jit_helper_exec_mono_metadata_decode_row_entry(hb_context_t* ctx, const hb_ir_block_t* block);
extern void hb_jit_helper_exec_mono_metadata_decode_col(hb_context_t* ctx, const hb_ir_block_t* block);
extern void hb_jit_helper_exec_mono_metadata_coded_index_search(hb_context_t* ctx, const hb_ir_block_t* block);
extern uint64_t hb_jit_helper_try_native_memmove(hb_context_t* ctx, const hb_ir_block_t* block);

typedef struct hb_cached_helper_stub {
    size_t arg1_mov_off;
    size_t helper_mov_off;
    uint8_t helper_id;
    uint16_t instr_index;
    bool arg1_is_instr;
} hb_cached_helper_stub_t;

typedef struct hb_jit_signal_fault_frame {
    struct hb_jit_signal_fault_frame* prev;
    /* Liveness cookie for the stale-frame guard (see jit_signal_fault_claim): set when the
     * frame is armed, cleared when it is popped.  A frame reached through a stale
     * g_jit_signal_fault_frame whose stack slot was reused reads as garbage here. */
    uint64_t stale_cookie;
    hb_jit_runtime_t* rt;
    hb_context_t* ctx;
    hb_block_cache_entry_t* entry;
    /* ★★★★★ 05.09.2026 — СНИМКА КОНТЕКСТА В КАДРЕ БОЛЬШЕ НЕТ.
     *
     * Здесь лежал `hb_context_t snapshot` (2616 байт), из которого путь отказа откатывал
     * гостя к состоянию ДО блока, чтобы переиграть блок интерпретатором с начала. Цена —
     * копия 760 байт и обнуление 728 байт на КАЖДОЙ диспетчеризации: 41,9 + 8,7 нс из
     * 100 нс перехода (dispatch_baseline, 05.09). Ветвь, ради которой это платилось, не
     * сработала ни разу из 22,0 млн (04.09) и 75,5 млн (05.09) диспетчеризаций.
     *
     * Замена — как у QEMU (cpu_restore_state) и FEX (RestoreRIPFromHostPC): позиция
     * отказавшей команды ВОССТАНАВЛИВАЕТСЯ по карте `host_off -> instr` (ripmap, строится
     * безусловно), а регистры гостя и так лежат в `ctx` — выпущенный код пишет их в память
     * на каждой команде. Интерпретатор продолжает С ОТКАЗАВШЕЙ КОМАНДЫ (hb_interpreter_resume_block),
     * а не с начала блока: ни отката, ни повторного исполнения уже выполненных команд.
     * Что читается на пути отказа, см. `run_jit_block_with_signal_guard`. */
    uint64_t steps;
    uint64_t blocks_executed;
    uint64_t host_pc;
    /* Хозяйский адрес, по которому спрашивать КАРТУ: равен host_pc, когда отказ в самом
     * выпущенном коде; при отказе в помощнике обработчик приходит с LR — адресом СЛЕДУЮЩЕГО
     * слова после `blr`, и если `blr` стоит последним словом команды, LR уже лежит в коде
     * следующей команды. Поэтому для LR карту спрашивают по LR-4 — самому `blr`. */
    uint64_t map_pc;
    uint64_t fault_addr;
    uint64_t host_gpr[31];
    uint64_t host_sp;
    uint64_t host_fault_pc;
    uint64_t host_pstate;
    uint64_t dispatched_guest;
    uint64_t dispatched_native;
    size_t dispatched_native_size;
    uint64_t fault_guest_pc;
    uint64_t fault_arch_pc;
    uint64_t fault_indirect_ic_guest;
    uint64_t fault_indirect_ic_native;
    uint32_t native_word;
    bool native_word_valid;
    bool active_guard_claim;
    uint8_t aa_dst_pre[32];
    uint8_t aa_src_pre[32];
    uint8_t aa_dst_post[32];
    uint8_t aa_src_post[32];
    uint32_t aa_dst_pre_valid;
    uint32_t aa_src_pre_valid;
    uint32_t aa_dst_post_valid;
    uint32_t aa_src_post_valid;
    /* Значения rcx/rdx/r8 ДО блока для пробы aa (раньше читались из снимка). */
    uint64_t aa_pre_rcx;
    uint64_t aa_pre_rdx;
    uint64_t aa_pre_r8;
    bool aa_enabled;
    bool host_context_valid;
    int signal;
    sigjmp_buf env;
} hb_jit_signal_fault_frame_t;

static __thread hb_jit_signal_fault_frame_t* g_jit_signal_fault_frame;

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — ВТОРАЯ ДВЕРЬ ПЛОЩАДКИ ПРИЗЕМЛЕНИЯ.
 *
 * Итерация 166 измерила механистическим признаком (число ловушек по `pc=_sigtramp+76`),
 * что площадка в `hb_memory.c` смертей не убирает: 5 из 9 против 4 из 9. Причина найдена
 * чтением — выходов длинным переходом ДВА, а закрыт был один. Здесь второй: сторож отказов
 * JIT ниже по файлу уходит через `siglongjmp(frame->env, 1)` прямо из обработчика сигнала,
 * то есть так же минует `__in_sigtramp = 0` и `sigreturn`, и трамплин Apple добирается до
 * своего `__builtin_trap()` («sigreturn returning is a fatal error»).
 *
 * Приём тот же, что и у первой двери: поменять `__pc` в контексте на площадку и вернуться
 * из обработчика ОБЫЧНЫМ `return`. Возврат ненулевого значения здесь означает именно это —
 * вызывающий (`segv_handler`, `signal_arm64.c:3929`) делает `return;`, и `_sigtramp`
 * доводит `sigreturn`. Длинный переход выполняется уже НА площадке, вне обработчика.
 *
 * Гейт общий с первой дверью (`MACRUNNER_HB_SIG_LANDING_PAD`), чтобы мерить обе разом.
 * Умолчание ВЫКЛ: прежнее поведение дословно. */
static int hb_rt_sig_landing_enabled(void) {
    const char* s = hb_gate( HB_GATE_HB_SIG_LANDING_PAD );
    int v = (s && *s && *s != '0') ? 1 : 0;
    return v;
}

static __thread hb_jit_signal_fault_frame_t* g_rt_landing_frame;

static void hb_rt_fault_landing(void) {
    /* Итерация 168: СВИДЕТЕЛЬ, см. заметку у площадки в hb_memory.c. Здесь мы уже вне
     * обработчика — sigreturn отработал, — поэтому fprintf безопасен. */
    static int n;
    if (n++ < 8) { fprintf(stderr, "macrunner-hb-landing-jit: n=%d\n", n); fflush(stderr); }
    hb_jit_signal_fault_frame_t* f = g_rt_landing_frame;
    g_rt_landing_frame = NULL;
    if (f) siglongjmp(f->env, 1);
    abort();
}

/* ── Кеш адреса потокового слота в контексте ────────────────────────────────────
 *
 * Замер 08.08 (sample, 30 с, прибор dispatch_stats ВЫКЛЮЧЕН): _tlv_get_addr — 5.6%
 * активного времени, из них 18.3% приходится на run_jit_block_with_signal_guard.
 * Причина: кадр кладётся и снимается на КАЖДОМ исполнении блока, а на macOS обращение
 * к __thread в динамически загруженном модуле — это вызов dyld.
 *
 * Саму переменную убрать нельзя: обработчик сигнала читает её, не имея контекста.
 * Поэтому кешируется её АДРЕС — но НЕ в другой потоковой переменной (первая версия
 * правки так и делала и была бессмысленной: кеш TLS в TLS не убирает вызов, а добавляет
 * второй), а в hb_context_t, который уже лежит в регистре x19.
 *
 * КОРРЕКТНОСТЬ опирается на «один контекст на поток». Допущение проверено:
 * dlls/xtajit64/unixlib.c — `static __thread hb_context_t *thread_ctx`. Если оно
 * когда-нибудь нарушится, обработчик прочитает чужой кадр молча, поэтому правка стоит
 * Гейт MACRUNNER_HB_TLS_SLOT_CACHE СНЯТ 02.09.2026: правка безусловна,
 * выключенная ветка возвращала известный дефект (scripts/гейты.py).
 *
 * Ожидаемый приз ~1%. Он мал, но постоянен и бесплатен: после встраивания памяти
 * верхушка профиля стала плоской, и дальше выигрывают накопленные проценты. */
/* MacRunner 2026-08-18, лейн ЛЕСТНИЦА, итерация 2469 (приказ владельца 200) — ПРОВЕРКА ГОДНОСТИ.
 *
 * Владелец задал единственный правильный вопрос про этот кеш: может ли он протухнуть. Кешируется
 * адрес ПОТОКОВОЙ переменной, а контексты заведены в таблице по идентификатору потока
 * (`macrunner_hb.c:2613`, ключ `tid`). Значит опасность ровно одна: тот же контекст, поданный из
 * ДРУГОГО потока, — тогда кеш вернёт чужой слот. Переезд между ядрами безопасен: адрес
 * потоковой переменной от ядра не зависит.
 *
 * Доказывать отсутствие рассуждением не буду — проверяю замером. `MACRUNNER_HB_TLS_SLOT_VERIFY=1`
 * читает И кеш, И потоковую переменную, сверяет их и считает расхождения. Это МЕДЛЕННЕЕ обеих
 * рук, и в бой не годится: рука измерения, а не кандидат в умолчание. Печать безусловная —
 * счётчик, которого никто не видит, за месяц шесть раз выдавал «ноль» за «не работало». */
static int tls_slot_verify_enabled(void) {
    /* getenv напрямую, а НЕ runtime_env_flag_cached: тот объявлен ниже по файлу (строка 1450),
     * и вызов отсюда даёт отказ сборки. Соседний tls_slot_cache_enabled устроен так же. */
    const char* v = hb_gate( HB_GATE_HB_TLS_SLOT_VERIFY );
    int cached = (v && *v && *v != '0') ? 1 : 0;
    return cached;
}

static uint64_t g_tls_slot_checks;
static uint64_t g_tls_slot_mismatch;

unsigned long long macrunner_hb_tls_slot_checks(void) {
    return (unsigned long long)__atomic_load_n(&g_tls_slot_checks, __ATOMIC_RELAXED);
}

unsigned long long macrunner_hb_tls_slot_mismatch(void) {
    return (unsigned long long)__atomic_load_n(&g_tls_slot_mismatch, __ATOMIC_RELAXED);
}

static inline hb_jit_signal_fault_frame_t** jit_signal_slot(hb_context_t* ctx) {
    if (ctx) {
        if (!ctx->jit_signal_frame_slot)
            ctx->jit_signal_frame_slot = (void*)&g_jit_signal_fault_frame;
        if (tls_slot_verify_enabled()) {
            void* живой = (void*)&g_jit_signal_fault_frame;
            uint64_t n = __atomic_add_fetch(&g_tls_slot_checks, 1, __ATOMIC_RELAXED);
            if (ctx->jit_signal_frame_slot != живой) {
                uint64_t k = __atomic_add_fetch(&g_tls_slot_mismatch, 1, __ATOMIC_RELAXED);
                if (k <= 4 || (k % 65536) == 0) {
                    static const char с[] = "macrunner-hb-tls-slot-mismatch\n";
                    (void)!write(2, с, sizeof(с) - 1);
                }
            }
            if ((n % 4000000ull) == 0) {
                static const char с[] = "macrunner-hb-tls-slot-alive\n";
                (void)!write(2, с, sizeof(с) - 1);
            }
        }
        return (hb_jit_signal_fault_frame_t**)ctx->jit_signal_frame_slot;
    }
    return &g_jit_signal_fault_frame;
}
static unsigned int g_jit_signal_fault_reports;

/* MacRunner 2026-08-03 — stale-guard-frame protection.
 *
 * g_jit_signal_fault_frame points into the guard function's STACK.  It is popped on exactly two
 * paths: normal return from exec() and the siglongjmp recovery branch.  Any fault that leaves the
 * guarded region through wine's exception machinery instead (declined claim -> forwarded SEH ->
 * unwind past the guard) abandons the frame: the thread-local keeps pointing at dead stack.  The
 * next fault anywhere in the JIT slab then passes the wide range check and siglongjmps into a dead
 * sigsetjmp env on a reused stack — resurrecting execution mid-frame, smashing canaries
 * (__stack_chk_fail in run_jit_block_with_signal_guard, wine-2026-08-02-044217.ips) and spraying a
 * 2.6 KB snapshot restore over live memory.  Suspected feeder of the whole exit=5/exit=29 heap
 * corruption class.
 *
 * Two conservative checks, both sound (no false stale-positives), both turn a guaranteed-
 * catastrophe jump into an ordinary declined claim:
 *   cookie — armed frames carry it, popped frames clear it, reused stack destroys it;
 *   sp     — a legitimate claim faults DEEPER than the frame (descending stack: interrupted
 *            sp < frame address).  interrupted sp above the frame ⇒ the frame is dead.
 * Kill switch: MACRUNNER_HB_GUARD_STALE_CHECK=0 restores the old behaviour. */
#define HB_GUARD_FRAME_COOKIE 0x4842475541524421ULL /* "HBGUARD!" */
static uint64_t g_guard_stale_declines;

/* Defined next to block_guest_span below; block_cache_put tracks every newly
 * cached translation for SMC reverify (HK Mono/JIT stale-translation fix). */
static void smc_track_entry(hb_jit_runtime_t* rt, hb_block_cache_entry_t* entry,
                            const hb_ir_block_t* block);
static unsigned int g_jit_aa_sigbus_reports;
static unsigned int g_jit_sigill_ownership_reports;

static uint64_t g_dispatch_stats_blocks;
static uint64_t g_dispatch_stats_dispatches;
static uint64_t g_dispatch_stats_steps;
static uint64_t g_dispatch_stats_start_ns;
static int g_dispatch_stats_atexit_registered;
static __thread uint64_t t_dispatch_stats_blocks;
static __thread uint64_t t_dispatch_stats_dispatches;
static __thread uint64_t t_dispatch_stats_steps;
static __thread uint64_t t_dispatch_stats_flushed_blocks;
static __thread uint64_t t_dispatch_stats_flushed_dispatches;
static __thread uint64_t t_dispatch_stats_flushed_steps;
static __thread uint64_t t_dispatch_stats_next_report;

/* MacRunner 2026-08-01 — how often is the fault-recovery branch actually TAKEN? Deliberately
 * ungated.
 *
 * Every dispatch pays for that branch in advance: a 790-byte frame memset, a 760-byte
 * hb_ctx_snapshot_save and a sigsetjmp, so that `hb_ctx_snapshot_restore` can roll the guest back
 * if the block faults. Whether that price is worth paying is one number — recoveries per
 * dispatch — and nothing in the tree reports it.
 *
 * The existing observation that it is nearly free ("20 480 faults and ripmap_check printed
 * nothing") is not evidence: ripmap_check sits behind MACRUNNER_HB_RIPMAP and prints once per
 * 1024 calls, so its silence is equally consistent with the gate being off. That is the trap this
 * lane hit three times already — a zero from an instrument nobody proved was switched on. Hence:
 * no env gate, no dependency on trace_dispatch_stats_enabled(), counted on the same line as the
 * dispatches it is a ratio of.
 *
 * Cost is an increment and a mask test per dispatch against a 760-byte copy already there, and one
 * fprintf per 2^20 dispatches. Per-thread counters, folded into a global only at flush time, so 64
 * threads do not contend on a cache line every dispatch. Printed periodically rather than at exit
 * because these runs die on the timeout's SIGKILL and never reach atexit. */
static uint64_t g_guard_dispatch_total;
static uint64_t g_guard_recover_total;

/* The live wire beside the zero — see guard_census_flush.
 *
 * A recovery count of zero is only evidence if the instrument could have moved, and the honest
 * way to show that is a counter on the SAME mechanism that does. These sit on the fault-claim
 * entry point, one fault apart from the recovery branch: claim_calls counts every time the signal
 * handler consults the guard, and claim_taken every time it hands control to siglongjmp. Faults
 * run at ~2000/s, five orders below the dispatch rate, so plain atomics are affordable here in a
 * way they would not be on the dispatch path. */
static uint64_t g_guard_claim_calls;
static uint64_t g_guard_claim_declined_frame;
static uint64_t g_guard_claim_declined_range;
static uint64_t g_guard_claim_taken;
/* MacRunner 2026-08-09 — счётчики переписи ПЕРЕЕХАЛИ из __thread в hb_jit_runtime_t.
 *
 * Замер: профиль по потокам внутри отрисовки показал `_tlv_get_addr` 7.1% и 12.0% на двух
 * рабочих потоках, при том что весь выпущенный код там же занимает около 5%. На Darwin arm64
 * каждое обращение к `__thread` идёт через вызов `_tlv_get_addr` (быстрая модель TLS здесь
 * молча игнорируется), а `++t_guard_dispatch` стоял на КАЖДОМ диспатче блока без всякого
 * гейта — до 2.5 млрд обращений за прогон ради печати раз в 2²⁰.
 *
 * `hb_jit_runtime_t` — структура ПОТОКОВАЯ (свой рантайм на поток), поэтому семантика
 * «один инкремент на диспатч, без двойного счёта при siglongjmp» сохраняется: это по-прежнему
 * счётчик своего потока, просто достаётся обычной загрузкой по указателю, который и так лежит
 * в регистре. Выпущенный код смещений этой структуры не использует (offsetof по ней в
 * кодогенераторе — ноль), так что дописывание полей безопасно. */

/* Power of two: the hot-path test below is a mask, not a division. */
#define HB_GUARD_CENSUS_PERIOD (1ull << 20)

/* ★ 06.09.2026, лейн ПОВТОР-2 — ИТОГ ПЕРЕПИСИ ГРАНИЦ ЕДЕТ НА ЧУЖОЙ СТРОКЕ.
 *
 * Своя строка `macrunner-hb-xborder` печатается только когда событие СЛУЧИЛОСЬ.
 * Значит её отсутствие означает сразу две разные вещи: «границ не было» и
 * «прибора нет в этом двоичном» — ровно тот неотличимый ноль, ради которого
 * писан hb_probe.h. Строка guard-census печатается БЕЗУСЛОВНО раз в 2^20
 * диспетчеризаций, поэтому итог подвешен к ней: есть строка с xb_total=0 —
 * смотрел, событий нет; нет самой строки — движок не исполнялся.
 * Поля дописаны В КОНЕЦ: разборщики читают её как key=value. */
static void hb_xborder_totals(uint64_t* all, uint64_t* host, uint64_t* guest);
/* ★ 07.09.2026, лейн ПОВТОРНЫЙ-ВЫПУСК — по той же причине, что и xborder выше: своя
 * строка вышла бы только на atexit, а прогоны снимаются убийством. Определение — рядом
 * с самой переписью (povtor_itog), здесь только объявление. */
void hb_povtor_itog_print(const char* why);

static void guard_census_flush(hb_jit_runtime_t* rt, const char* why) {
    uint64_t d_add = rt->guard_dispatch - rt->guard_flushed_dispatch;
    uint64_t r_add = rt->guard_recover - rt->guard_flushed_recover;
    uint64_t d_tot, r_tot;

    rt->guard_flushed_dispatch = rt->guard_dispatch;
    rt->guard_flushed_recover = rt->guard_recover;
    d_tot = d_add ? __atomic_add_fetch(&g_guard_dispatch_total, d_add, __ATOMIC_RELAXED)
                  : __atomic_load_n(&g_guard_dispatch_total, __ATOMIC_RELAXED);
    r_tot = r_add ? __atomic_add_fetch(&g_guard_recover_total, r_add, __ATOMIC_RELAXED)
                  : __atomic_load_n(&g_guard_recover_total, __ATOMIC_RELAXED);

    uint64_t xb_all = 0, xb_host = 0, xb_guest = 0;
    hb_xborder_totals(&xb_all, &xb_host, &xb_guest);

    /* recover_per_1e6 is the whole point: it is the share of dispatches whose snapshot was used
     * for anything, scaled so a cold branch is readable instead of rounding to 0.00 %. */
    fprintf(stderr,
            "macrunner-hb-guard-census: why=%s thread_dispatch=%llu thread_recover=%llu "
            "thread_recover_per_1e6=%.3f total_dispatch=%llu total_recover=%llu "
            "total_recover_per_1e6=%.3f claim_calls=%llu claim_taken=%llu "
            "claim_declined_frame=%llu claim_declined_range=%llu "
            "xb_total=%llu xb_host=%llu xb_guest=%llu xb_other=%llu\n",
            why,
            (unsigned long long)rt->guard_dispatch, (unsigned long long)rt->guard_recover,
            rt->guard_dispatch ? 1000000.0 * (double)rt->guard_recover / (double)rt->guard_dispatch : 0.0,
            (unsigned long long)d_tot, (unsigned long long)r_tot,
            d_tot ? 1000000.0 * (double)r_tot / (double)d_tot : 0.0,
            (unsigned long long)__atomic_load_n(&g_guard_claim_calls, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_guard_claim_taken, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_guard_claim_declined_frame, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_guard_claim_declined_range, __ATOMIC_RELAXED),
            (unsigned long long)xb_all, (unsigned long long)xb_host,
            (unsigned long long)xb_guest, (unsigned long long)(xb_all - xb_host - xb_guest));

    /* ★★★ ПУЛЬС ПЕРЕПИСИ ПРИБОРОВ (лейн ОСНАСТКА, 07.09.2026).
     *
     * Перепись hb_probe стояла ТОЛЬКО на atexit, а прогоны снимаются убийством —
     * замер лейна ПОВТОР-2: строк `macrunner-probe` в 300 журналах run.log НОЛЬ при
     * строках движка в 40 из 40. То есть КАЖДЫЙ прибор на HB_PROBE_DEFINE в боевом
     * прогоне молчал, и его молчание было неотличимо от «явления нет».
     *
     * Это место выбрано не случайно: guard_census_flush — БЕЗУСЛОВНАЯ периодическая
     * печать (раз в 2^20 диспетчеризаций), у неё нет ни гейта, ни зависимости от
     * trace_dispatch_stats_enabled(). Подвесив перепись сюда, мы делаем УСТРОЙСТВО, а
     * не обход для одного прибора: подключился к hb_probe.h — доехал до журнала.
     *
     * Решение печатать принимает САМ пульс (смена состояния / степень двойки /
     * не дублировать одинаковое), и он ПОЛНОСТЬЮ молчит, пока приборов ноль. Поэтому
     * прогоны без единого прибора — сегодня это весь движок — не меняются ничем:
     * цена здесь ровно один вызов с проверкой счётчика на ноль. Разбор — в
     * hb_probe.h у hb_probe_census_pulse. */
    hb_probe_census_pulse(stderr, why);
    hb_povtor_itog_print(why);
}

static uint32_t jit_block_step_count(const hb_ir_block_t* block);
static void trace_jit_code_cache_full_once(hb_jit_runtime_t* rt,
                                           const char* reason,
                                           size_t needed);
static int runtime_block_chain_enabled(void);
static int runtime_single_lookup_enabled(void);
static int runtime_indirect_ic_enabled(void);

/* Счётчик интерпретируемых инструкций живёт в hb_interpreter.c — там его горячая точка.
 * Отдельного заголовка у интерпретатора нет, поэтому объявление здесь, рядом с прочими
 * межмодульными. Обоснование самого счётчика — в комментарии у exec_instr_unlocked. */
uint64_t hb_interp_instr_thread_count(void);
uint64_t hb_interp_instr_total_count(void);

static int translation_cache_trace_enabled(void) {
    return hb_contract_telemetry_enabled();
}

static void translation_cache_trace_summary(void) {
    (void)hb_contract_telemetry_emit_summary(stderr);
}

static void translation_cache_register_atexit(void) {
    hb_contract_telemetry_register_atexit();
}

static uint64_t runtime_now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Terminal-op histogram slots — declared here because dispatch_stats_flush_thread below reports them;
 * the classifier that fills them, and the reasoning for classifying on the LAST instruction, are at
 * dispatch_stats_note_terminal. */
enum {
    HB_TERM_JMP_DIR = 0, HB_TERM_JMP_IND, HB_TERM_JCC, HB_TERM_CALL_DIR, HB_TERM_CALL_IND,
    HB_TERM_RET, HB_TERM_LOOP, HB_TERM_XFER_MID, HB_TERM_OTHER, HB_TERM_N
};
static const char* const hb_term_slot_names[HB_TERM_N] = {
    "jmp_dir", "jmp_ind", "jcc", "call_dir", "call_ind", "ret", "loop", "xfer_mid", "other"
};
static __thread uint64_t t_dispatch_term[HB_TERM_N];
static __thread uint64_t t_jcc_disp, t_jcc_win, t_jcc_r256, t_jcc_back, t_jcc_far;
/* ЕДИНИЦА, итерация 52 — КОРЗИНЫ ПО РАССТОЯНИЮ НАЗАД.
 * Итерация 51 показала: 95,47 % условных переходов по ИСПОЛНЕНИЮ смотрят НАЗАД, и
 * продление единицы вперёд их не берёт (потолок упал 18,5 % -> 0,41 %). Следующий вопрос —
 * можно ли взять их, начиная единицу РАНЬШЕ. Ответ зависит от того, КАК ДАЛЕКО назад:
 * тесная петля в десятки байт укладывается в единицу, а прыжок на килобайты — нет.
 * Корзины: <64, <256, <4096, >=4096 байт. */
static __thread uint64_t t_jcc_b64, t_jcc_b256, t_jcc_b4k, t_jcc_bfar;  /* ЕДИНИЦА, итерация 43 — см. пояснение у dispatch_stats_note_terminal */

/* Scan-length accounting for the O(N) CFG lookup every dispatch opens with — see find_block. */
static __thread uint64_t t_findblock_calls;
static __thread uint64_t t_findblock_iters;
static __thread uint64_t t_findblock_max_n;

/* MacRunner 2026-07-30 — WHY CHAINING DECLINES, counted per reason instead of guessed.
 *
 * The W^X fix stopped chaining from killing the guest, but avg_chain stayed at exactly 1.0000 over
 * 450 000 dispatches: the mechanism is safe and inert. patch_block_tail has eleven separate ways to
 * return false and the dispatcher can also decline to call it at all, so naming the culprit by reading is
 * a guess. One counter per exit tells it from a single run, which is the same discipline that turned the
 * dispatcher question into avg_chain rather than an eight-run A/B.
 *
 * `site_*` covers the call site (chain_patch_enabled is gated on ctx->step_limit and ctx->block_limit
 * being zero, so a title that sets either never patches at all), the rest are patch_block_tail's exits in
 * source order. Per-thread and non-atomic, like every other counter here. */
/* ★★★ 04.09.2026 — ОДИН СПИСОК, А НЕ ДВА ПАРАЛЛЕЛЬНЫХ.
 *
 * Здесь жили ДВА списка — перечисление и массив имён, — связанные ТОЛЬКО порядком
 * строк, и в комментарии выше честно стояло «массив имён позиционный». Это тот самый
 * класс, который уже стоил нам гейтов: сдвиг на одну позицию не ломает сборку и не
 * ломает тесты, он просто заставляет КАЖДЫЙ счётчик печататься под ЧУЖИМ ИМЕНЕМ.
 * Заметить это можно только сличая глазами тридцать строк с тридцатью.
 *
 * Правило от имени к строке здесь НЕ выводится ("refused_near" у REFUSED, "write_off"
 * у WRITEGATE, "кадр" у FRAME), поэтому строка несёт обе половины сразу — но она ОДНА,
 * и разойтись им теперь нечем. Это не проверка, а невозможность. Порядок строк ниже
 * задаёт и значения перечисления, и порядок печати. */
#define HB_CHAIN_DECLINE(X) \
    X(CHAIN_SITE_CALLED,        "site_called") \
    X(CHAIN_SITE_PATCH_OFF,     "site_patch_off") \
    X(CHAIN_SITE_NO_ENTRY,      "site_no_entry") \
    X(CHAIN_DECL_GATE,          "gate") \
    X(CHAIN_DECL_INVALID,       "invalid") \
    X(CHAIN_DECL_NOMETA,        "nometa") \
    X(CHAIN_DECL_ALREADY,       "already") \
    X(CHAIN_DECL_TERMINAL,      "terminal") \
    X(CHAIN_DECL_BACKEDGE,      "backedge") \
    X(CHAIN_DECL_SLOT_CUR,      "slot_cur") \
    X(CHAIN_DECL_SLOT_NEXT,     "slot_next") \
    X(CHAIN_DECL_TRAMP,         "tramp") \
    X(CHAIN_DECL_REACH,         "reach") \
    X(CHAIN_DECL_WRITEGATE,     "write_off") \
    X(CHAIN_DECL_WPROT,         "wprot") \
    X(CHAIN_DECL_XPROT,         "xprot") \
    X(CHAIN_DECL_CAPPED,        "capped") \
    X(CHAIN_DECL_REFUSED,       "refused_near") \
    X(CHAIN_DECL_PATCHED,       "PATCHED") \
    X(CHAIN_DECL_ALREADY_OTHER, "already_OTHER") \
    X(CHAIN_DECL_PATCHED2,      "PATCHED2") \
    X(CHAIN_DECL_NO_SLOT2,      "no_slot2") \
    /* Разбивка already_OTHER по завершителю блока-ИСТОЧНИКА: у `Jcc` целей две по \
     * построению, у `JMP reg`/`CALL reg` цель меняется на каждом исполнении, а у \
     * прямых `JMP`/`CALL` цель одна — там чужая цель означает пересоздание блока. */ \
    X(CHAIN_DECL_OTHER_JCC,      "other_Jcc") \
    X(CHAIN_DECL_OTHER_INDIRECT, "other_INDIRECT") \
    X(CHAIN_DECL_OTHER_DIRECT,   "other_direct") \
    X(CHAIN_DECL_PATCHED_DIRECT, "PATCHED_DIRECT") \
    X(CHAIN_DECL_NO_DIRECT,      "no_direct") \
    /* ★ 03.09.2026 — своя причина у пропуска импортного трамплина: он считался \
     * как REFUSED («отказ по близкому ребру»), две причины под одной подписью. */ \
    X(CHAIN_DECL_IMPORT_THUNK,   "import_thunk") \
    /* ★ 04.09.2026 — кадр конца ребра не тот, который разбирает трамплин. */ \
    X(CHAIN_DECL_FRAME,          "кадр") \
    /* ★★ 04.09.2026 — РАСЦЕПИТЬ НЕ УДАЛОСЬ, А ЗАПИСЬ ВСЁ РАВНО ЗАБЫТА. \
     * Названо лейном «Mono роняет себя при сцеплении». В \
     * block_cache_prepare_replace_entry ветвь `if (!made_writable)` обнуляет meta, \
     * то есть ТЕРЯЕТ и указатель на входящий трамплин, и смещения обеих заплат. \
     * Пока сцепление выключено — терять нечего. Но если сцепление ВКЛЮЧЕНО, а \
     * hb_jit_buffer_make_writable отказал, заплаты остаются стоять НАВСЕГДА и \
     * ведут в код, который вот-вот заменят, а отменить их уже нечем. Ветвь \
     * молчала: одно событие с двумя совершенно разными смыслами, и различить их \
     * было нельзя. Считаем ТОЛЬКО опасный смысл. */ \
    X(CHAIN_DECL_NOUNCHAIN,      "РАСЦЕПИТЬ_НЕ_СМОГЛИ")

enum {
#define HB_CHAIN_DECLINE_ENUM(imya, stroka) imya,
    HB_CHAIN_DECLINE(HB_CHAIN_DECLINE_ENUM)
#undef HB_CHAIN_DECLINE_ENUM
    CHAIN_DECL_N
};

/* Пролог, который единственно и умеет разбирать зашитый эпилог трамплина:
 * `STP X19, X20, [SP, #-48]!`. Кодировка снята из кодогенератора (там же
 * рядом лежит форма на 80 байт), а не вычислена руками. */
#define HB_CHAIN_FRAME48_PUSH 0xa9bd53f3u

/* ★ 04.09.2026 — ПЕРЕПИСЬ РЁБЕР ПО ДВУМ ПРИЗНАКАМ СРАЗУ, независимо от того,
 * какой запрет включён.
 *
 * Опыт «граница функции или вызов» сравнивает две руки, и у него есть способ
 * оказаться ПУСТЫМ: если рёбер «чужая функция, а завершитель НЕ вызов» в игре
 * не бывает вовсе, то запрет по границе тождественно равен запрету по вызову,
 * и совпадение рук ничего не докажет. Отличить «таких рёбер нет» от «запрет
 * сработал» можно только счётчиком, который считает ОБЕ руки одинаково.
 *
 * Считаются ПОПЫТКИ сшивки (каждая диспетчеризация ребра), а не различные
 * рёбра: patch_block_tail зовётся на каждом проходе. Для вопроса «встречается
 * ли класс вообще» этого достаточно, и ноль здесь — настоящий ноль. */
enum { EDGE_CLS_SAME_CALL = 0, EDGE_CLS_SAME_OTHER,
       EDGE_CLS_CROSS_CALL, EDGE_CLS_CROSS_OTHER,
       EDGE_CLS_NO_FUNC,            /* функция не передана — классифицировать нечем */
       /* ФОРМА выхода за функцию: она отвечает, что именно запрещает рука B. */
       EDGE_CLS_LEAVE,              /* источник в этой функции, приёмник вне */
       EDGE_CLS_RETURN,             /* источник вне, приёмник в этой функции */
       EDGE_CLS_FOREIGN,            /* оба вне — ребро внутри ЧУЖОЙ функции */
       /* ★ ПРИЁМНИК ПОД ОТПЕЧАТКОМ SMC. Диспетчер сверяет отпечаток блока на
        * КАЖДОМ заходе (smc_reverify_entry) и выселяет устаревший перевод.
        * Сшитое ребро этот заход снимает — значит перевод цели больше никто не
        * сверяет. Класс считается отдельно, потому что цена вопроса — «есть ли
        * такие цели вообще»: ноль здесь убивает гипотезу без единого прогона. */
       EDGE_CLS_SMC_TARGET,
       EDGE_CLS_N };
static const char* const hb_edge_cls_names[EDGE_CLS_N] = {
    "same_CALL", "same_other", "cross_CALL", "cross_other", "no_func",
    "f_leave", "f_return", "f_foreign", "smc_target"
};
static __thread uint64_t t_edge_cls[EDGE_CLS_N];

/* ★ 04.09.2026 — «ДОШЛИ ЛИ ДО ПЕРЕХОДНИКА ИМПОРТА ПО ЦЕПОЧКЕ».
 *
 * Смерть прогона со сцеплением x64 наступает на переходнике импорта
 * (`reason=import-thunk`, KERNEL32!RaiseException), а без сцепления тот же
 * переходник отрабатывает 1634 раза без единого отказа. Вопрос «а цепочка вообще
 * туда доходит?» пять раз пытались решить рассуждением. Он решается замером:
 * запоминаем ПОСЛЕДНИЙ заход в выпущенный код (с какого блока вошли и сколько
 * блоков он исполнил) и печатаем это в тот момент, когда диспетчер выходит без
 * блока на адресе арены переходников.
 *
 * `delta > 1` означает, что заход исполнил НЕСКОЛЬКО блоков, то есть управление
 * шло по сшитым рёбрам; `delta == 1` — что последний блок был вызван диспетчером
 * обычным порядком. Различить эти два случая иначе нечем. */
static __thread uint64_t t_last_run_entry;   /* гостевой адрес блока, с которого вошли */
static __thread uint64_t t_last_run_delta;   /* сколько блоков исполнил этот заход */

/* Роды переходников импорта на пути сшивки — считаются БЕЗУСЛОВНО и печатаются в
 * общей строке переписи. Печать у самого места отказа ограничена (первые четыре и
 * далее каждый 4096-й), а вопрос «сколько их какого рода» требует итога. */
static uint64_t g_thunk_arena, g_thunk_ff25, g_thunk_ff25_chained;
/* MacRunner 25.08.2026 — КУДА УХОДЯТ ДИСПЕТЧЕРИЗАЦИИ.
 * Сцепление сшивает 99,85 % мест, до которых доходит (site_called против already), но
 * через диспетчер по-прежнему идёт ~29 % блоков, и ПОЛОВИНА их не доходит до места
 * сшивки вовсе — выходит из цикла раньше. Чтение кода тут даёт догадку: выходов
 * семнадцать. Один счётчик на выход называет виновника за один прогон — та же
 * дисциплина, что превратила вопрос о диспетчере в avg_chain. */
enum {
    RUNEXIT_NO_BLOCK = 0,   /* блока для pc нет — выход из функции либо внешний вызов */
    RUNEXIT_RET,            /* возврат: блок возврата не в кеше (или гейт RET выключен) */
    RUNEXIT_EXT_XFER,       /* цель не найдена, терминал — передача управления наружу */
    RUNEXIT_NOT_FOUND,      /* цель не найдена и это не передача управления */
    RUNEXIT_SEQ_END,        /* блок кончился последовательно, сшивать нечего */
    RUNEXIT_N
};
static const char* const hb_runexit_names[RUNEXIT_N] = {
    "no_block", "ret", "ext_xfer", "not_found", "seq_end"
};
static _Thread_local uint64_t t_runexit[RUNEXIT_N];

/* ─────────────────────────────────────────────────────────────────────────────
 * ★ 06.09.2026, лейн ПОВТОР-2 — ГРАНИЦА НАРУЖУ: К ХОСТУ ИЛИ В ГОСТЕВОЙ КОД.
 *
 * `t_runexit` считает выходы из цикла исполнения, но НЕ РАЗЛИЧАЕТ два случая,
 * которые для записи потока гостя противоположны:
 *
 *   к ХОСТУ  — переходник импорта; дальше исполняет НЕ наш транслятор, и при
 *              повторе сюда надо подставить ЗАПИСАННЫЙ результат;
 *   в ГОСТЯ  — блока на этот pc просто нет, сейчас его поднимут и переведут;
 *              записывать тут нечего, повтор пройдёт это сам.
 *
 * Без разделения число записываемых событий — вилка 1,11-3,95 млн
 * (reports/ПОВТОР-ПОТОКА-ГОСТЯ-06.09.2026.md §2.1), а строить запись по вилке
 * значит строить вслепую.
 *
 * БЕЗ ГЕЙТА — намеренно, по образцу guard_census_flush выше. Гейт, который надо
 * не забыть включить, трижды за одни сутки давал ноль, прочитанный как «явления
 * нет» (CLAUDE.md, «ВЫКЛЮЧЕННЫЙ ГЕЙТ»). Цена безусловности: два сравнения на
 * выход, а выходов ~8 % диспетчеризаций.
 *
 * ПЕЧАТЬ ПЕРИОДИЧЕСКАЯ, НЕ atexit. Перепись hb_probe стоит на atexit, а наши
 * прогоны снимаются убийством: строки `macrunner-probe-census` нет НИ В ОДНОМ
 * из 300 просмотренных журналов при 40 из 40 со строками движка. Прибор,
 * который печатается только на atexit, у нас молчит всегда.
 *
 * КЛАССЫ — только то, что решается ТОЧНЫМ диапазоном, без чтения памяти; всё
 * прочее честно называется «не опознан» и печатается образцами, а не
 * приписывается к удобной стороне.  */
/* XBORDER-CUT-BEGIN — приёмка вырезает кусок ОТСЮДА по эти якоря
 * (scripts/тест-переписи-границ.sh). Тест, пересказывающий проверяемый код
 * своими словами, зеленел бы и при опечатке в оригинале; здесь разъедутся
 * якоря — и тест ОТКАЖЕТ, а не соврёт. Якоря не переименовывать. */
/* ★★★ РЕШАЕТ ЧИТАЕМОСТЬ ПАМЯТИ ГОСТЯ, А НЕ ДИАПАЗОН АДРЕСОВ.
 *
 * Первая редакция решала по полосе гостевых образов 0x87e00000000..0x88000000000
 * (константа из signal_arm64.c:4032,4095). Проверка по архиву показала, что
 * полоса ЗАВИСИТ ОТ СБОРКИ и не является свойством движка:
 *     laneA-LIV-OFF-2, laneA-ETAZH-LOCAL, laneA-ZAM-ON-3   вход гостя 0x87ef41f2b80
 *     laneA-SX64B-STAT-CT1, laneA-SX64-SMOKE-ON            вход гостя 0x eb3942b80
 * Это разные порядки (8,7 ТБ против 63 ГБ). Классификатор на зашитой полосе
 * объявил бы ВЕСЬ гостевой код второй группы прогонов «не опознанным» — то есть
 * молча соврал бы ровно там, где его показания и нужны.
 *
 * Поэтому вопрос задаётся памяти: читается ли по этому адресу гостевая память.
 * Читается — адрес гостевой; не читается — не гостевой. Полоса при этом
 * по-прежнему СЧИТАЕТСЯ (in_band/out_band), но НИЧЕГО НЕ РЕШАЕТ: это наблюдение
 * за географией, а не приговор. */
enum {
    XB_ARENA = 0,       /* арена переходников импорта -> ХОСТ (точный диапазон) */
    XB_FF25,            /* память гостя читается, там `ff 25` -> ХОСТ (заглушка импорта) */
    XB_GUEST,           /* память гостя читается, не заглушка -> ГОСТЬ */
    XB_UNREADABLE,      /* память гостя НЕ читается -> адрес не гостевой */
    XB_NOPROBE,         /* потолок проб выбран -> НЕИЗВЕСТНО, и это сказано вслух */
    XB_N
};
/* Классы различены НАМЕРЕННО. «Потолок выбран», «не прочиталось» и «прочитал,
 * это не заглушка» — три РАЗНЫХ ответа; слипшись, они дали бы ноль ff25,
 * неотличимый от честного. */
static const char* const hb_xborder_names[XB_N] = {
    "arena", "ff25", "guest", "unreadable", "noprobe"
};
/* Счёт по (место выхода) x (класс). Мест два: no_block и ext_xfer. */
static uint64_t g_xborder[2][XB_N];
static uint64_t g_xborder_probes;           /* сколько раз ЧИТАЛИ память гостя */
/* НАБЛЮДЕНИЕ за географией: сколько выходов попало в «классическую» полосу.
 * Ничего не решает — см. разбор у enum. Нужно, чтобы сдвиг полосы между
 * сборками был ВИДЕН числом, а не обнаруживался через месяц по странному нулю. */
static uint64_t g_xborder_in_band, g_xborder_out_band;
/* Потолок проб памяти объявлен ЧИСЛОМ и печатается в каждой строке: усечение не
 * должно быть молчаливым (hb_probe, пункт 2). Достигнут потолок — растёт класс
 * XB_NOPROBE, и по нему видно, что ff25/guest стали НИЖНИМИ ГРАНИЦАМИ.
 * 2^24 против ~4 млн выходов до вехи: потолок заведомо не связывает, но он ЕСТЬ
 * и назван, потому что прибор без объявленного потолка врёт молча. */
#define HB_XBORDER_PROBE_CAP (1ull << 24)
/* Полоса гостевых образов ОДНОЙ из сборок. Только для наблюдения. */
#define HB_XBORDER_BAND_LO   0x87e00000000ull
#define HB_XBORDER_BAND_HI   0x88000000000ull

static void hb_xborder_totals(uint64_t* all_out, uint64_t* host_out, uint64_t* guest_out)
{
    uint64_t host = 0, guest = 0, all = 0;
    int s, c;
    for (s = 0; s < 2; s++)
        for (c = 0; c < XB_N; c++) {
            uint64_t v = __atomic_load_n(&g_xborder[s][c], __ATOMIC_RELAXED);
            all += v;
            if (c == XB_ARENA || c == XB_FF25) host += v;
            else if (c == XB_GUEST) guest += v;
            /* XB_UNREADABLE и XB_NOPROBE НЕ приписываются ни к кому: «адрес не
             * гостевой» ещё не значит «к хосту», а «не смотрел» не значит ничего.
             * Остаток виден как other = total - host - guest. */
        }
    if (all_out)   *all_out = all;
    if (host_out)  *host_out = host;
    if (guest_out) *guest_out = guest;
}

static void hb_xborder_report(const char* why)
{
    uint64_t host = 0, guest = 0, all = 0;
    int s, c;
    hb_xborder_totals(&all, &host, &guest);
    fprintf(stderr,
            "macrunner-hb-xborder: why=%s total=%llu host=%llu guest=%llu other=%llu "
            "host_pct=%.2f",
            why, (unsigned long long)all, (unsigned long long)host,
            (unsigned long long)guest,
            (unsigned long long)(all - host - guest),
            all ? 100.0 * (double)host / (double)all : 0.0);
    for (s = 0; s < 2; s++)
        for (c = 0; c < XB_N; c++)
            fprintf(stderr, " %s_%s=%llu", s ? "extxfer" : "noblock", hb_xborder_names[c],
                    (unsigned long long)__atomic_load_n(&g_xborder[s][c], __ATOMIC_RELAXED));
    fprintf(stderr, " probes=%llu probe_cap=%llu in_band=%llu out_band=%llu\n",
            (unsigned long long)__atomic_load_n(&g_xborder_probes, __ATOMIC_RELAXED),
            (unsigned long long)HB_XBORDER_PROBE_CAP,
            (unsigned long long)__atomic_load_n(&g_xborder_in_band, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_xborder_out_band, __ATOMIC_RELAXED));
    fflush(stderr);
}

/* site: 0 = RUNEXIT_NO_BLOCK, 1 = RUNEXIT_EXT_XFER. Зовётся БЕЗУСЛОВНО с обоих
 * мест — «не смотрел» и «не было» обязаны остаться разными ответами. */
static void hb_xborder_note(hb_jit_runtime_t* rt, uint64_t pc, int site)
{
    int cls;
    uint64_t n;

    /* Наблюдение за географией — считается всегда, ни на что не влияет. */
    if (pc >= HB_XBORDER_BAND_LO && pc < HB_XBORDER_BAND_HI)
        __atomic_add_fetch(&g_xborder_in_band, 1, __ATOMIC_RELAXED);
    else
        __atomic_add_fetch(&g_xborder_out_band, 1, __ATOMIC_RELAXED);

    if (pc >= HB_IMPORT_THUNK_BASE &&
        pc <  HB_IMPORT_THUNK_BASE + (uint64_t)HB_IMPORT_THUNK_MAX * HB_IMPORT_THUNK_STRIDE) {
        /* Арена — точный диапазон, память читать не нужно. По архиву это
         * подавляющее большинство выходов, поэтому проверка стоит ПЕРВОЙ:
         * горячий путь не платит за чтение памяти. */
        cls = XB_ARENA;
    } else {
        /* Заглушка `ff 25` лежит в гостевом образе и ведёт к ХОСТУ; слить её с
         * гостевым кодом значило бы занизить ровно то число, ради которого
         * прибор писан. Различить их можно только байтами. */
        uint64_t np = __atomic_add_fetch(&g_xborder_probes, 1, __ATOMIC_RELAXED);
        if (np > HB_XBORDER_PROBE_CAP || !rt || !rt->ctx || !rt->ctx->memory) {
            cls = XB_NOPROBE;
        } else {
            uint8_t b0 = 0, b1 = 0;
            if (hb_memory_read_u8(rt->ctx->memory, (hb_gva_t)pc, &b0) == HB_OK &&
                hb_memory_read_u8(rt->ctx->memory, (hb_gva_t)(pc + 1), &b1) == HB_OK)
                cls = (b0 == 0xff && b1 == 0x25) ? XB_FF25 : XB_GUEST;
            else
                cls = XB_UNREADABLE;
        }
    }

    n = __atomic_add_fetch(&g_xborder[site][cls], 1, __ATOMIC_RELAXED);

    /* Нечитаемые адреса печатаются образцами: их география нигде не записана, и
     * угадывать её вместо измерения — та самая ошибка вывода, что стоила суток. */
    if (cls == XB_UNREADABLE && (n <= 8 || (n & (n - 1)) == 0)) {
        fprintf(stderr, "macrunner-hb-xborder-unreadable: n=%llu site=%s pc=0x%llx\n",
                (unsigned long long)n, site ? "ext_xfer" : "no_block",
                (unsigned long long)pc);
        fflush(stderr);
    }

    {   /* Первые восемь событий отличают «никогда» от «редко»; дальше период,
         * чтобы горячая ветвь не утопила журнал собственным замером. Период
         * 2^18 выбран так, чтобы до вехи (~2,5 млн событий) легло ~10 отметок:
         * по ним число на момент вехи считается интерполяцией, а не догадкой. */
        static uint64_t g_xborder_events;
        uint64_t e = __atomic_add_fetch(&g_xborder_events, 1, __ATOMIC_RELAXED);
        if (e <= 8 || (e & 0x3FFFFull) == 0) hb_xborder_report("period");
    }
}
/* XBORDER-CUT-END */

static const char* const hb_chain_decline_names[CHAIN_DECL_N] = {
#define HB_CHAIN_DECLINE_IMYA(imya, stroka) stroka,
    HB_CHAIN_DECLINE(HB_CHAIN_DECLINE_IMYA)
#undef HB_CHAIN_DECLINE_IMYA
};
static __thread uint64_t t_chain_decline[CHAIN_DECL_N];

/* Defined with the other block helpers further down; needed by the classifier above it. */
static const hb_ir_instr_t* first_control_transfer_instr(const hb_ir_block_t* block);

static int trace_dispatch_stats_enabled(void) {
    const char* env = hb_gate( HB_GATE_HB_TRACE_DISPATCH_STATS );
    int cached = env && *env && *env != '0';
    return cached;
}

static void dispatch_stats_flush_thread(int force);

static void dispatch_stats_summary(void) {
    uint64_t blocks, dispatches, steps, start, now, elapsed;
    double seconds;
    if (!trace_dispatch_stats_enabled()) return;
    dispatch_stats_flush_thread(1);
    blocks = __atomic_load_n(&g_dispatch_stats_blocks, __ATOMIC_RELAXED);
    dispatches = __atomic_load_n(&g_dispatch_stats_dispatches, __ATOMIC_RELAXED);
    steps = __atomic_load_n(&g_dispatch_stats_steps, __ATOMIC_RELAXED);
    start = __atomic_load_n(&g_dispatch_stats_start_ns, __ATOMIC_RELAXED);
    now = runtime_now_ns();
    elapsed = (start && now > start) ? now - start : 0;
    seconds = elapsed ? (double)elapsed / 1000000000.0 : 0.0;
/* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 327 — PID В ПЕЧАТЬ СЧЁТЧИКА.
 *
 * Без pid этот прибор ОБМАНЫВАЕТ, и я на нём обманулся. Под wine в один журнал пишут несколько
 * процессов — игра, `explorer.exe`, `services.exe`, — а `g_dispatch_stats_*` у каждого свои.
 * В журнале это выглядит как единый ряд: итог рос до 210.52 млн шагов к 17-й секунде, а
 * ПОСЛЕДНЯЯ строка показывала 177.73 млн, то есть меньше. Кто берёт последнюю строку за итог
 * прогона (а это естественный способ), меряет чужой процесс. Шесть рук из восьми дали ровно
 * 177 728 055 — это не «детерминированная стена игры», а постоянная работа фонового процесса.
 *
 * Один %d закрывает весь класс: ряды разделяются по pid без догадок о монотонности. */
    fprintf(stderr,
            "macrunner-hb-dispatch-stats: pid=%d wall_s=%.3f dispatches=%llu blocks=%llu steps=%llu "
            "dispatches_per_s=%.1f blocks_per_s=%.1f steps_per_s=%.1f\n",
            (int)getpid(),
            seconds, (unsigned long long)dispatches, (unsigned long long)blocks,
            (unsigned long long)steps,
            seconds > 0.0 ? (double)dispatches / seconds : 0.0,
            seconds > 0.0 ? (double)blocks / seconds : 0.0,
            seconds > 0.0 ? (double)steps / seconds : 0.0);
    fflush(stderr);
}

/* MacRunner 2026-07-30 — register ONCE PER THREAD, because this is called from dispatch_stats_add on
 * every single dispatch and everything below it is once-only work behind a CAS. The unconditional
 * runtime_now_ns() ahead of that CAS therefore bought a clock_gettime per dispatch: measured at 21 of
 * 536 samples, 3.9 % of the critical thread, in the SPEEDDIG1 profile
 * (dispatch_stats_add -> clock_gettime). An instrument that charges 4 % for being switched on makes
 * every timing arm it appears in pessimistic, which is the opposite of its job. */
static __thread int t_dispatch_stats_registered;

static void dispatch_stats_register(void) {
    uint64_t now;
    int expected = 0;
    if (!trace_dispatch_stats_enabled()) return;
    if (t_dispatch_stats_registered) return;
    t_dispatch_stats_registered = 1;
    now = runtime_now_ns();
    if (now) {
        uint64_t zero = 0;
        (void)__atomic_compare_exchange_n(&g_dispatch_stats_start_ns, &zero, now, false,
                                          __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    }
    if (__atomic_compare_exchange_n(&g_dispatch_stats_atexit_registered, &expected, 1,
                                    false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        atexit(dispatch_stats_summary);
    }
}

static uint64_t dispatch_stats_report_interval(void) {
    static int parsed;
    static uint64_t interval;
    if (!parsed) {
        const char* env = hb_gate( HB_GATE_HB_TRACE_DISPATCH_STATS_INTERVAL );
        interval = env && *env ? strtoull(env, NULL, 0) : 1000000ull;
        if (interval < 1000ull) interval = 1000ull;
        parsed = 1;
    }
    return interval;
}

/* Промахи стража трамплина; снимаются в tramp_snyat_svidetelya (ниже). */
static uint64_t g_tramp_promah;

static void dispatch_stats_flush_thread(int force) {
    uint64_t add_blocks, add_dispatches, add_steps;
    uint64_t total_blocks, total_dispatches, total_steps, start, now, elapsed;
    double seconds;
    if (!trace_dispatch_stats_enabled()) return;
    if (!force && t_dispatch_stats_dispatches < t_dispatch_stats_next_report) return;

    add_blocks = t_dispatch_stats_blocks - t_dispatch_stats_flushed_blocks;
    add_dispatches = t_dispatch_stats_dispatches - t_dispatch_stats_flushed_dispatches;
    add_steps = t_dispatch_stats_steps - t_dispatch_stats_flushed_steps;
    if (!add_blocks && !add_dispatches && !add_steps && !force) return;

    total_blocks = add_blocks
        ? __atomic_add_fetch(&g_dispatch_stats_blocks, add_blocks, __ATOMIC_RELAXED)
        : __atomic_load_n(&g_dispatch_stats_blocks, __ATOMIC_RELAXED);
    total_dispatches = add_dispatches
        ? __atomic_add_fetch(&g_dispatch_stats_dispatches, add_dispatches, __ATOMIC_RELAXED)
        : __atomic_load_n(&g_dispatch_stats_dispatches, __ATOMIC_RELAXED);
    total_steps = add_steps
        ? __atomic_add_fetch(&g_dispatch_stats_steps, add_steps, __ATOMIC_RELAXED)
        : __atomic_load_n(&g_dispatch_stats_steps, __ATOMIC_RELAXED);
    t_dispatch_stats_flushed_blocks = t_dispatch_stats_blocks;
    t_dispatch_stats_flushed_dispatches = t_dispatch_stats_dispatches;
    t_dispatch_stats_flushed_steps = t_dispatch_stats_steps;

    if (!t_dispatch_stats_next_report)
        t_dispatch_stats_next_report = dispatch_stats_report_interval();
    while (t_dispatch_stats_next_report <= t_dispatch_stats_dispatches)
        t_dispatch_stats_next_report += dispatch_stats_report_interval();

    start = __atomic_load_n(&g_dispatch_stats_start_ns, __ATOMIC_RELAXED);
    now = runtime_now_ns();
    elapsed = (start && now > start) ? now - start : 0;
    seconds = elapsed ? (double)elapsed / 1000000000.0 : 0.0;
    fprintf(stderr,
            "macrunner-hb-dispatch-stats: pid=%d wall_s=%.3f total_dispatches=%llu total_blocks=%llu total_steps=%llu "
            "dispatches_per_s=%.1f blocks_per_s=%.1f steps_per_s=%.1f "
            "thread_dispatches=%llu thread_blocks=%llu thread_steps=%llu\n",
            (int)getpid(),
            seconds, (unsigned long long)total_dispatches, (unsigned long long)total_blocks,
            (unsigned long long)total_steps,
            seconds > 0.0 ? (double)total_dispatches / seconds : 0.0,
            seconds > 0.0 ? (double)total_blocks / seconds : 0.0,
            seconds > 0.0 ? (double)total_steps / seconds : 0.0,
            (unsigned long long)t_dispatch_stats_dispatches,
            (unsigned long long)t_dispatch_stats_blocks,
            (unsigned long long)t_dispatch_stats_steps);
    /* avg_chain is thread_blocks/thread_dispatches: exactly 1.00 when every block transition returns
     * to the dispatcher, above 1 as chaining takes hold. Printed here so it needs no arithmetic at
     * read time, and per-thread so a parked thread cannot dilute the critical one. The terminal
     * histogram beside it is the ceiling — see dispatch_stats_note_terminal. */
    {
        uint64_t d = t_dispatch_stats_dispatches;
        uint64_t chainable = t_dispatch_term[HB_TERM_JMP_DIR];
        uint64_t classified = 0;
        int i;
        for (i = 0; i < HB_TERM_N; i++) classified += t_dispatch_term[i];
        fprintf(stderr, "macrunner-hb-трамплин: промахов=%llu\n",
                (unsigned long long)__atomic_load_n(&g_tramp_promah, __ATOMIC_RELAXED));
        fprintf(stderr, "macrunner-hb-chainlen: thread_dispatches=%llu thread_blocks=%llu "
                        "avg_chain=%.4f chainable_pct=%.2f",
                (unsigned long long)d, (unsigned long long)t_dispatch_stats_blocks,
                d ? (double)t_dispatch_stats_blocks / (double)d : 0.0,
                classified ? 100.0 * (double)chainable / (double)classified : 0.0);
        for (i = 0; i < HB_TERM_N; i++)
            fprintf(stderr, " %s=%llu", hb_term_slot_names[i],
                    (unsigned long long)t_dispatch_term[i]);
        fprintf(stderr, "\n");
        /* ЕДИНИЦА, итерация 43: та же перепись, что в лифтере, но по ВХОДАМ в блок. */
        {   /* БЕЗУСЛОВНО: условие if (t_jcc_disp) скрыло бы ноль, а ноль тут и есть вопрос.
             * term=%llu печатается рядом как контроль: если term ненулевой, а jcc нулевой,
             * значит учёт не исполняется, хотя соседняя строка того же блока его считает. */
            fprintf(stderr,
                    "macrunner-edinica-jcc-disp: term=%llu jcc=%llu v_okne=%llu (%.2f %%) r256=%llu (%.2f %%) "
                    "nazad=%llu (%.2f %%) daleko=%llu\n",
                    (unsigned long long)t_dispatch_term[HB_TERM_JCC],
                    (unsigned long long)t_jcc_disp, (unsigned long long)t_jcc_win,
                    t_jcc_disp ? 100.0 * (double)t_jcc_win / (double)t_jcc_disp : 0.0,
                    (unsigned long long)t_jcc_r256,
                    t_jcc_disp ? 100.0 * (double)t_jcc_r256 / (double)t_jcc_disp : 0.0,
                    (unsigned long long)t_jcc_back,
                    t_jcc_disp ? 100.0 * (double)t_jcc_back / (double)t_jcc_disp : 0.0,
                    (unsigned long long)t_jcc_far);
            fprintf(stderr,
                    "macrunner-edinica-jcc-nazad: nazad=%llu <64=%llu (%.2f %%) <256=%llu (%.2f %%) "
                    "<4096=%llu (%.2f %%) >=4096=%llu (%.2f %%)\n",
                    (unsigned long long)t_jcc_back,
                    (unsigned long long)t_jcc_b64,
                    t_jcc_back ? 100.0 * (double)t_jcc_b64 / (double)t_jcc_back : 0.0,
                    (unsigned long long)t_jcc_b256,
                    t_jcc_back ? 100.0 * (double)t_jcc_b256 / (double)t_jcc_back : 0.0,
                    (unsigned long long)t_jcc_b4k,
                    t_jcc_back ? 100.0 * (double)t_jcc_b4k / (double)t_jcc_back : 0.0,
                    (unsigned long long)t_jcc_bfar,
                    t_jcc_back ? 100.0 * (double)t_jcc_bfar / (double)t_jcc_back : 0.0);
        }
        /* Why chaining declined, per reason — see the enum at hb_chain_decline_names. Printed only when
         * something has been counted, so a non-chaining run does not carry a line of zeros. */
        {
            uint64_t any = 0;
            for (i = 0; i < CHAIN_DECL_N; i++) any += t_chain_decline[i];
            if (any) {
                fprintf(stderr, "macrunner-hb-chaindecline:");
                for (i = 0; i < CHAIN_DECL_N; i++)
                    if (t_chain_decline[i])
                        fprintf(stderr, " %s=%llu", hb_chain_decline_names[i],
                                (unsigned long long)t_chain_decline[i]);
                fprintf(stderr, "\n");
            }
            /* ★ 04.09.2026 — ПЕРЕПИСЬ РЁБЕР. Печатается БЕЗУСЛОВНО, как только
             * сцепление вообще пробовало сшивать (any != 0): ноль в столбце
             * `cross_other` — это ответ («таких рёбер нет»), а не отсутствие
             * замера, и скрывать его условием нельзя. */
            /* ★ 05.09.2026 — СКОЛЬКО ЕДИНИЦ САМИ ПИШУТ ВЫХОДНОЙ pc.
             * Без этого числа лечение «конец единицы обязан записать pc» было бы
             * неотличимо от «такой единицы не встретилось»: молчащий прибор и
             * отсутствие явления — разные вещи, и это записанное правило. */
            /* ★ 05.09.2026, вторая редакция — ПЕРЕПИСЬ ПРЯМЫХ ЕДИНИЦ ДВУМЯ ЧИСЛАМИ.
             * Одного числа мало: оно не различает «прямых единиц не встретилось» и
             * «запись не сработала». `прямых=N из_них_с_pc=N` — доказательство, что
             * класс «единица не объявляет свой выход» закрыт в этом прогоне;
             * разность — прямое число дефектов, а не повод для догадки. */
            {
                extern unsigned long long g_cg_tail_pc_written;
                extern unsigned long long g_cg_straight_units;
                extern unsigned long long g_cg_straight_units_pc;
                extern unsigned long long g_cg_straight_units_idiom;
                unsigned long long pr = __atomic_load_n(&g_cg_straight_units, __ATOMIC_RELAXED);
                unsigned long long pp = __atomic_load_n(&g_cg_straight_units_pc, __ATOMIC_RELAXED);
                unsigned long long pi = __atomic_load_n(&g_cg_straight_units_idiom, __ATOMIC_RELAXED);
                fprintf(stderr,
                        "macrunner-hb-tailpc: единиц_с_записью_pc=%llu прямых_единиц=%llu "
                        "из_них_с_pc=%llu без_pc=%llu из_них_свёрткой=%llu\n",
                        (unsigned long long)__atomic_load_n(&g_cg_tail_pc_written,
                                                            __ATOMIC_RELAXED),
                        pr, pp, pr - pp, pi);
            }
            if (any) {
                fprintf(stderr, "macrunner-hb-chainedge-cls:");
                for (i = 0; i < EDGE_CLS_N; i++)
                    fprintf(stderr, " %s=%llu", hb_edge_cls_names[i],
                            (unsigned long long)t_edge_cls[i]);
                fprintf(stderr, " thunk_арена=%llu thunk_ff25=%llu thunk_ff25_сшито=%llu\n",
                        (unsigned long long)__atomic_load_n(&g_thunk_arena, __ATOMIC_RELAXED),
                        (unsigned long long)__atomic_load_n(&g_thunk_ff25, __ATOMIC_RELAXED),
                        (unsigned long long)__atomic_load_n(&g_thunk_ff25_chained,
                                                            __ATOMIC_RELAXED));
            }
        }
        {   /* Состав интерпретации: КАКИЕ команды кодогенератор не выпускает.
             * Доля известна (0,56 % шагов на игре), состав — нет. Без него «дожать до
             * нуля» означает перебирать сотни форм x86 вслепую. */
            extern unsigned long long g_interp_op_count[512];
            extern unsigned long long g_interp_zero_ymm[512];
            extern const char* hb_ir_op_name_public(int op);
            unsigned oi; int shown = 0;
            uint64_t vex128 = 0, vsego_i = 0;
            for (oi = 0; oi < 512; oi++) {
                if (!g_interp_op_count[oi]) continue;
                if (!shown) { fprintf(stderr, "macrunner-hb-interp-ops:"); shown = 1; }
                /* ИМЯ, а не номер: номера читались сверкой с hb_ir.h вручную, и один
                 * такой разбор уже стоил половины захода. */
                fprintf(stderr, " %s=%llu", hb_ir_op_name_public((int)oi),
                        (unsigned long long)g_interp_op_count[oi]);
                vsego_i += g_interp_op_count[oi];
                vex128 += g_interp_zero_ymm[oi];
            }
            if (shown) { fprintf(stderr, "\n"); fflush(stderr); }
            /* ★ 04.09.2026 — ЦЕНА ЧЕТЫРЁХ СТОРОЖЕЙ `zero_ymm_upper`, названная числом.
             * Печатается ТОЛЬКО когда класс встретился: строка нулей в прогоне без AVX
             * ничего не сообщает, а место в журнале занимает. */
            if (vex128) {
                fprintf(stderr, "macrunner-hb-interp-vex128: всего=%llu из=%llu доля=%.2f %%",
                        (unsigned long long)vex128, (unsigned long long)vsego_i,
                        vsego_i ? 100.0 * (double)vex128 / (double)vsego_i : 0.0);
                for (oi = 0; oi < 512; oi++)
                    if (g_interp_zero_ymm[oi])
                        fprintf(stderr, " %s=%llu", hb_ir_op_name_public((int)oi),
                                (unsigned long long)g_interp_zero_ymm[oi]);
                fprintf(stderr, "\n"); fflush(stderr);
            }
        }
        {   /* Куда ушли диспетчеризации, не дошедшие до места сшивки. */
            uint64_t any_exit = 0;
            for (i = 0; i < RUNEXIT_N; i++) any_exit += t_runexit[i];
            if (any_exit) {
                fprintf(stderr, "macrunner-hb-runexit:");
                for (i = 0; i < RUNEXIT_N; i++)
                    if (t_runexit[i])
                        fprintf(stderr, " %s=%llu", hb_runexit_names[i],
                                (unsigned long long)t_runexit[i]);
                fprintf(stderr, " total=%llu\n", (unsigned long long)any_exit);
            }
        }
        /* ИНТЕРПРЕТАЦИЯ ПРОТИВ ТРАНСЛЯЦИИ — доля, которой у нас до 01.08 не было ничем измерить.
         *
         * Числитель считается в hb_interpreter.c на exec_instr_unlocked: туда сходятся и блоки,
         * исполняемые интерпретатором целиком, и одиночные инструкции, упавшие из транслированного
         * кода в хелпер. Знаменатель — steps выше: инструкции, исполненные транслированными блоками.
         * interp_pct считается от СУММЫ, поэтому это доля всех исполненных инструкций, а не
         * отношение к трансляции: у второго нет верхней границы и его нельзя читать глазом.
         *
         * Печатается и поток, и процесс: интерпретация, размазанная по 64 потокам, и один вставший
         * поток дают одно и то же общее число, а стоят совершенно разного. */
        {
            uint64_t ti = hb_interp_instr_thread_count();
            uint64_t tot_i = hb_interp_instr_total_count();
            uint64_t ts = t_dispatch_stats_steps;
            fprintf(stderr,
                    "macrunner-hb-interp-census: thread_interp=%llu thread_steps=%llu "
                    "thread_interp_pct=%.4f total_interp=%llu total_steps=%llu total_interp_pct=%.4f\n",
                    (unsigned long long)ti, (unsigned long long)ts,
                    (ti + ts) ? 100.0 * (double)ti / (double)(ti + ts) : 0.0,
                    (unsigned long long)tot_i, (unsigned long long)total_steps,
                    (tot_i + total_steps) ? 100.0 * (double)tot_i / (double)(tot_i + total_steps) : 0.0);
        }
        /* The O(N) CFG scan every dispatch opens with on the default path — see find_block. */
        fprintf(stderr, "macrunner-hb-findblock: thread_calls=%llu thread_iters=%llu avg_scan=%.2f "
                        "max_block_count=%llu scans_per_dispatch=%.2f\n",
                (unsigned long long)t_findblock_calls, (unsigned long long)t_findblock_iters,
                t_findblock_calls ? (double)t_findblock_iters / (double)t_findblock_calls : 0.0,
                (unsigned long long)t_findblock_max_n,
                d ? (double)t_findblock_calls / (double)d : 0.0);
    }
    fflush(stderr);
}

/* MacRunner 2026-07-30 — TERMINAL-OP HISTOGRAM of dispatched blocks: the chaining CEILING as a
 * number rather than an argument.
 *
 * blocks/dispatches (already reported above as thread_blocks/thread_dispatches) says whether chaining
 * is happening. It does not say how much chaining could ever happen, and that is the figure which
 * decides whether the dispatcher round trip is worth attacking this way at all: block_terminal_is_chainable
 * admits ONLY a direct HB_IR_JMP, so every dispatched block whose terminal is Jcc, RET, an indirect
 * jump or a call is ineligible no matter how well the trampoline works. In compiled x86 the executed
 * terminals are dominated by Jcc backedges and CALL/RET, so the ceiling may be far below the 297-339
 * of ~535 samples the profile attributes to dispatch overhead.
 *
 * Classified on the LAST instruction, deliberately: that is the exact expression
 * block_terminal_is_chainable uses, so jmp_dir is the eligible population and not an approximation of
 * it. xfer_mid counts blocks whose first control transfer is NOT the last instruction, where the
 * last-instruction model does not hold at all — reported separately so it cannot quietly inflate any
 * other bucket. Per-thread and non-atomic, following the t_dispatch_stats_* convention right above:
 * summing over 64 threads would mix in the parked ones, and rule two here is that the critical thread
 * is the measurement. */
static int trace_null_pc_enabled_rt(void) {
    const char* e = hb_gate( HB_GATE_HB_TRACE_NULL_PC );
    int cached = e && *e && *e != '0';
    return cached;
}

/* Классификация вынесена сюда из `dispatch_stats_note_terminal` БЕЗ изменения правил: тот же
 * разбор понадобился второму потребителю — разбивке попаданий первого уровня по виду
 * завершителя (наряд, пункт 4: «доля попаданий ОТДЕЛЬНО для ret и для непрямых jmp/call»).
 * Две копии switch разошлись бы при первой же правке. */
static int term_slot_of(const hb_ir_block_t* block) {
    const hb_ir_instr_t* last;
    const hb_ir_instr_t* transfer;
    if (!block || block->instr_count == 0) return HB_TERM_OTHER;
    last = &block->instrs[block->instr_count - 1];
    transfer = first_control_transfer_instr(block);
    if (transfer && transfer != last) return HB_TERM_XFER_MID;
    switch (last->op) {
    case HB_IR_JMP:  return (last->src1.type == HB_OP_NONE) ? HB_TERM_JMP_DIR : HB_TERM_JMP_IND;
    case HB_IR_CALL: return (last->src1.type == HB_OP_NONE) ? HB_TERM_CALL_DIR : HB_TERM_CALL_IND;
    case HB_IR_Jcc:  return HB_TERM_JCC;
    case HB_IR_RET:  return HB_TERM_RET;
    case HB_IR_LOOP:
    case HB_IR_JRCXZ: return HB_TERM_LOOP;
    default:         return HB_TERM_OTHER;
    }
}

/* ГЕЙТ `MACRUNNER_HB_L1_TERM_STATS`, умолчание ВЫКЛЮЧЕНО: считает на горячем пути, поэтому
 * включается только на замер. */
static int l1_term_stats_enabled(void) {
    const char* s = hb_gate( HB_GATE_HB_L1_TERM_STATS );
    int v = (s && *s) ? (atoi(s) != 0) : 0;
    return v;
}

static __thread int t_l1_prev_term = HB_TERM_OTHER;
/* ЕДИНИЦА, итерация 43 — перепись «цель jcc в окне», ВЗВЕШЕННАЯ ИСПОЛНЕНИЕМ.
 *
 * Зачем ещё одна. Счётчик лейна в hb_lift_x86.c взводится при ПОДЪЁМЕ блока и потому даёт
 * долю по лифтам: 89,4 % на стенде. Потолок рычага считался произведением этой доли на
 * долю jcc среди ИСПОЛНЕНИЙ (71,08 %) — то есть перемножались статика и динамика. Законно
 * это только если холодный и горячий код одинаковы по доле близких целей, а причина
 * думать иначе есть: горячее — это циклы, обратное ребро цикла идёт НАЗАД и в окно вперёд
 * не попадает. Здесь тот же предикат считается на КАЖДОМ входе в блок.
 *
 * Окно — те же 4096 байт (HB_WOW64CPU_DEFAULT_MAX_CODE_BYTES), отсчёт от начала блока:
 * лифтер зовётся с base_addr, равным адресу блока, поэтому предикат воспроизводится точно.
 * Едет на существующем гейте MACRUNNER_HB_TRACE_DISPATCH_STATS, своего не завожу. */
static __thread uint64_t t_l1_hit_term[HB_TERM_N], t_l1_miss_term[HB_TERM_N];

static void dispatch_stats_note_terminal(const hb_ir_block_t* block) {
    int slot = term_slot_of(block);
    /* Запоминаем вид завершителя ТОЛЬКО что отправленного блока: следующий поиск в кеше
     * порождён именно им, и его попадание/промах приписывается сюда. */
    if (l1_term_stats_enabled()) t_l1_prev_term = slot;
    if (!trace_dispatch_stats_enabled()) return;
    t_dispatch_term[slot]++;
    if (slot == HB_TERM_JCC && block->instr_count) {
        const hb_ir_instr_t* last = &block->instrs[block->instr_count - 1];
        uint64_t base = block->guest_addr;
        uint64_t tg = last->target;
        t_jcc_disp++;
        if (tg < base) {
            uint64_t d = base - tg;
            t_jcc_back++;
            if (d < 64u) t_jcc_b64++;
            else if (d < 256u) t_jcc_b256++;
            else if (d < 4096u) t_jcc_b4k++;
            else t_jcc_bfar++;
        }
        else if (tg - base < 4096u) { t_jcc_win++; if (tg - base < 256u) t_jcc_r256++; }
        else t_jcc_far++;
    }
}

static void dispatch_stats_add(uint64_t dispatches, uint64_t blocks, uint64_t steps) {
    hb_contract_telemetry_record_dispatch(dispatches, blocks, steps);
    if (!trace_dispatch_stats_enabled()) return;
    dispatch_stats_register();
    if (!t_dispatch_stats_next_report)
        t_dispatch_stats_next_report = dispatch_stats_report_interval();
    t_dispatch_stats_dispatches += dispatches;
    t_dispatch_stats_blocks += blocks;
    t_dispatch_stats_steps += steps;
    dispatch_stats_flush_thread(0);
}

/* --- In-memory block cache helpers --- */
static size_t block_cache_hash(uint64_t addr) {
    return (size_t)((addr ^ (addr >> 32)));
}

/* Ёмкость кеша блоков. Умолчание — прежние 524 288, поведение без переменной НЕ меняется.
 * `MACRUNNER_HB_BLOCK_CACHE_SIZE=<степень двойки>` уменьшает её для замера. */
/* MacRunner 2026-08-09 — ПОДСКАЗКА «среда вложенная», а не общий потолок.
 *
 * Глобальное уменьшение до 8192 опровергнуто замером (итерация 87): кеш переполняется на
 * +6.4 с и прогон не доходит до вехи, потому что занятость РАЗНАЯ — медиана 12, максимум
 * 131 643 (итерация 83). Значит ёмкость выбирается ПО МЕСТУ: рабочей среде прежние 524 288,
 * вложенным — малая.
 *
 * Подсказка потоковая, а не параметр: `hb_jit_runtime_create` объявлена в публичном
 * заголовке и зовётся ещё из hb_wow64cpu.c и xtajit64/unixlib.c — менять её подпись значило
 * бы трогать три модуля ради одного признака. Вызывающий ставит флаг перед созданием и
 * снимает после. */
__thread int hb_jit_next_runtime_nested;

static size_t block_cache_capacity(void) {
    static size_t big, small;
    if (!big) {
        const char* v = hb_gate( HB_GATE_HB_BLOCK_CACHE_SIZE );
        long long n = v && *v ? atoll(v) : 0;
        big = (n >= 1024 && !(n & (n - 1))) ? (size_t)n : (size_t)HB_BLOCK_CACHE_SIZE;
        {
            const char* s = hb_gate( HB_GATE_HB_BLOCK_CACHE_NESTED );
            long long m = s && *s ? atoll(s) : 0;
            small = (m >= 1024 && !(m & (m - 1))) ? (size_t)m : big;
        }
    }
    return hb_jit_next_runtime_nested ? small : big;
}

/* ГЕЙТ `MACRUNNER_HB_L1_CACHE`, умолчание ВКЛЮЧЕНО (см. описание слота в hb_runtime.h).
 *
 * Гейт ЗНАЧЕНИЕМ, а не наличием: `=0` гасит. Проверка «по наличию» уже кусала проект (драйвер
 * CoreAudio вешал загрузку на 43 с, потому что `${VAR:-0}` при заданной пустой переменной
 * читалось как «включено»).
 *
 * ПОРЯДОК ГАШЕНИЯ для приёмочного перебора: гасить ПЕРВЫМ из моих правок — он самый дешёвый
 * по последствиям (только скорость, поведение не меняется вовсе). Признак вредности назван
 * заранее и точно: доля попаданий НИЖЕ 45.2 % (вывод из замера 1786 против 3947 пс,
 * итерация 2). Ниже порога первый уровень добавляет пробу и не окупает её. */
static int l1_cache_enabled(void) {
    const char* s = hb_gate( HB_GATE_HB_L1_CACHE );
    int v = (s && *s) ? (atoi(s) != 0) : 1;
    return v;
}

/* ГЕЙТ `MACRUNNER_HB_L1_VERIFY`, умолчание ВЫКЛЮЧЕНО. Только для приёмки.
 *   =1  каждое попадание первого уровня перепроверяется полным обходом таблицы; расхождение
 *       печатается громко и считается;
 *   =2  то же, плюс УМЫШЛЕННАЯ ПОРЧА одного слота на каждом 4096-м обращении.
 *
 * Второе значение существует потому, что «сверка не нашла расхождений» само по себе не
 * доказывает НИЧЕГО: сверка могла быть слепой. Рука `=2` обязана дать ненулевой счётчик —
 * если и она даёт ноль, недействительна сверка, а не первый уровень. */
static int l1_verify_mode(void) {
    const char* s = hb_gate( HB_GATE_HB_L1_VERIFY );
    int v = (s && *s) ? atoi(s) : 0;
    return v;
}

static uint64_t g_l1_verify_checks, g_l1_verify_mismatch, g_l1_verify_poisoned,
                g_l1_verify_poison_rejected;

/* ГЕЙТ `MACRUNNER_HB_L1_SLOTS`, умолчание 16384 (256 КБ при слоте 16 Б).
 *
 * Умолчание 4096 ОТМЕНЕНО замером на НАСТОЯЩИХ адресах корпуса (итерация 4,
 * `tools/dispatch/l1_sim.py`, 4 985 106 адресов). Доля блоков, занимающих слот в одиночку —
 * верхняя граница доли попаданий — против порога окупаемости 45.2 %:
 *     окно 1024 блока:  4096 слотов 80.27 %   16384 слотов 91.31 %   65536 слотов 91.31 %
 *     окно 3485:        4096       42.41 %    16384       74.00 %    65536       85.51 %
 *     окно 8656:        4096       11.93 %    16384       48.90 %    65536       60.43 %
 *     окно 123327:      4096        0.00 %    16384        0.05 %    65536       13.88 %
 * 4096 слотов проваливаются ниже порога уже на 3485 блоках. 65536 не взяты из-за памяти
 * (см. порог ленивого выделения ниже).
 * Только степень двойки и не меньше 256; иначе берётся умолчание.
 * Замер повозкой при круговом обходе (худший случай, никакой временно́й близости):
 *   рабочее множество 1024 блока  → доля попаданий 96.72 %
 *   4096                          → 42.41 %   (теория случайного отображения: e^-1 = 36.8 %)
 *   16384                         → 1.35 %    (теория: e^-4 = 1.83 %)
 * Совпадение с теорией — проверка того, что замешивание работает, а не подгонка. */
static uint32_t l1_slots(void) {
    static uint32_t v;
    if (!v) {
        const char* s = hb_gate( HB_GATE_HB_L1_SLOTS );
        long long n = (s && *s) ? atoll(s) : 0;
        v = (n >= 256 && !(n & (n - 1))) ? (uint32_t)n : HB_BLOCK_L1_SIZE;
    }
    return v;
}

static hb_block_cache_t* block_cache_create(void) {
    {
        hb_block_cache_t *bc = calloc(1, sizeof(hb_block_cache_t));
        size_t n = block_cache_capacity();

        if (!bc) return NULL;
        bc->entries = calloc(n, sizeof(*bc->entries));
        if (!bc->entries) { free(bc); return NULL; }
        bc->size = n;
        bc->size_mask = n - 1;
        /* Отказ выделения первого уровня — НЕ отказ создания кеша: без него поиск работает
         * ровно как прежде, поэтому нехватка памяти здесь не должна валить среду. */
        /* Первый уровень здесь НЕ выделяется — только по надобности, см. l1_maybe_alloc. */
        return bc;
    }
}

static size_t block_cache_entry_index(const hb_block_cache_t* cache,
                                      const hb_block_cache_entry_t* entry) {
    if (!cache || !entry || entry < cache->entries ||
        entry >= cache->entries + cache->size)
        return SIZE_MAX;
    return (size_t)(entry - cache->entries);
}

static hb_block_chain_meta_t* block_cache_chain_meta(hb_block_cache_t* cache,
                                                     hb_block_cache_entry_t* entry,
                                                     bool create) {
    size_t idx;
    if (!cache || !entry) return NULL;
    idx = block_cache_entry_index(cache, entry);
    if (idx == SIZE_MAX) return NULL;
    if (!cache->chain_meta && create)
        cache->chain_meta = calloc(cache->size, sizeof(*cache->chain_meta));
    return cache->chain_meta ? &cache->chain_meta[idx] : NULL;
}

static const hb_block_chain_meta_t* block_cache_chain_meta_const(
    const hb_block_cache_t* cache, const hb_block_cache_entry_t* entry) {
    size_t idx;
    if (!cache || !entry || !cache->chain_meta) return NULL;
    idx = block_cache_entry_index(cache, entry);
    if (idx == SIZE_MAX) return NULL;
    return &cache->chain_meta[idx];
}

/* MacRunner 2026-08-09 — СКОЛЬКО КЛОНОВ ЖИВО ПРЯМО СЕЙЧАС.
 *
 * `ir_live` считает ВСЕ блоки IR, а не только клоны кеша блоков, поэтому приписывать ему
 * владельца по рассуждению нельзя: на кеше IR такая же оценка ошиблась в 200 раз (итерация
 * 80). Здесь считается ровно то, что утверждается: клоны, созданные для кеша блоков, минус
 * освобождённые при вытеснении. Разница — сколько их держат кеши в этот момент. */
unsigned long long hb_block_clones_live;
unsigned long long hb_jit_runtimes_live;

static hb_ir_block_t* block_clone_for_cache(const hb_ir_block_t* block) {
    hb_ir_block_t* copy;
    hb_ir_instr_t* instrs;

    if (!block) return NULL;
    copy = hb_ir_block_create(block->id, block->guest_addr);
    if (!copy) return NULL;
    {
        unsigned long long n = __atomic_add_fetch(&hb_block_clones_live, 1, __ATOMIC_RELAXED);
        if (n == 1 || (n & 0xffffull) == 0) {
            fprintf(stderr, "macrunner-hb-blockclones: живых=%llu\n", n);
            fflush(stderr);
        }
    }
    if (block->instr_count > copy->instr_cap) {
        instrs = calloc(block->instr_count, sizeof(hb_ir_instr_t));
        if (!instrs) {
            hb_ir_block_destroy(copy);
            return NULL;
        }
        free(copy->instrs);
        copy->instrs = instrs;
        copy->instr_cap = block->instr_count;
    }
    if (block->instr_count)
        memcpy(copy->instrs, block->instrs, block->instr_count * sizeof(hb_ir_instr_t));
    copy->instr_count = block->instr_count;
    /* This path fills `instrs` by memcpy rather than through hb_ir_emit, so it must carry the
     * memo itself. The copy is instruction-for-instruction identical, so the source's answer is
     * valid for it; if the source was never asked, UNCOMPUTED propagates and the clone resolves it
     * on first use. Cached blocks are the ones the dispatcher actually sees, so getting this wrong
     * would be invisible in translation and wrong at run time. */
    copy->first_transfer_idx = block->first_transfer_idx;
    return copy;
}

/* Освобождение карты «хозяйский pc -> гостевая команда». Определение ниже по файлу, рядом с
 * ripmap_attach; объявление здесь, потому что снимать карту обязаны ВСЕ пути, где запись кеша
 * перестаёт описывать свой код, а три из них лежат выше. */
static void ripmap_release(hb_block_cache_entry_t* entry);

static void block_cache_release_owned_block(hb_block_cache_entry_t* entry,
                                            const hb_ir_block_t* replacement) {
    if (!entry || !entry->owns_block || !entry->block || entry->block == replacement)
        return;
    hb_ir_block_destroy((hb_ir_block_t*)entry->block);
    __atomic_sub_fetch(&hb_block_clones_live, 1, __ATOMIC_RELAXED);
    entry->owns_block = false;
}

/* ★★★ MacRunner 2026-09-04 — АРЕНА ПЕРВЫМ ДОВОДОМ, И ОНА ОБЯЗАТЕЛЬНА.
 *
 * Довод добавлен НЕ для удобства, а чтобы забыть перевод адреса было нельзя: под
 * раздельным W^X (MACRUNNER_HB_JIT_SPLITWX) арена отображена дважды, кеш блоков и
 * `meta->in_trampoline` хранят RX-адрес, а RX-половина на запись закрыта. Все пять мест,
 * которые правят УЖЕ ВЫПУЩЕННЫЙ код — снятие сшивки, обе щели, основная заплата,
 * литерал трамплина, — писали по RX и роняли процесс на первой же сшивке (1/1,
 * `сигнал=10 pc_sym=patch_block_tail`). Прежняя подпись позволяла дописать шестое
 * место и не вспомнить: теперь такой вызов НЕ СОБИРАЕТСЯ.
 *
 * `arena == NULL` — законный случай и означает «пишем не в арену»: так зовёт
 * `chain_trampoline_build_at`, собирающий трамплин в местном буфере на стеке.
 *
 * ПЕРЕВОДИТСЯ ТОЛЬКО ПРИЁМНИК. Разбор — у hb_jit_rx_to_rw в hb_codegen.h. */
/* «Гейт включён» одной строкой: у нас 265 гейтов и одна и та же тройка проверок
 * повторяется сотнями мест. */
static int hb_gate_on(int gate) {
    const char* v = hb_gate(gate);
    return v && v[0] && v[0] != '0';
}

static void arm64_store_u32(const hb_jit_buffer_t* arena, uint8_t* p, uint32_t insn) {
    if (!p) return;
    p = hb_jit_rx_to_rw(arena, p);
    if (!p) return;              /* адрес не из арены — писать некуда, молчать нельзя было бы */
    p[0] = (uint8_t)(insn & 0xffu);
    p[1] = (uint8_t)((insn >> 8) & 0xffu);
    p[2] = (uint8_t)((insn >> 16) & 0xffu);
    p[3] = (uint8_t)((insn >> 24) & 0xffu);
}

/* Чистка кеша команд ПО ОБОИМ ОТОБРАЖЕНИЯМ, когда их два.
 *
 * Записали по RW — грязные строки данных лежат на RW-адресе; исполнять будут RX-адрес.
 * QEMU держит для этого `flush_idcache_range(rx, rw, len)`: `dc cvau` по RW, `ic ivau`
 * по RX. `__builtin___clear_cache` раздельно этого не выражает, поэтому зовём его на оба
 * адреса — цена платится только на заплате, а не на горячем пути. Без splitwx адрес один
 * и второго вызова не будет. */
static void block_cache_clear_icache(const hb_jit_buffer_t* arena, uint8_t* start, size_t len) {
    uint8_t* rw;
    if (!start || !len) return;
    __builtin___clear_cache((char*)start, (char*)start + len);
    rw = hb_jit_rx_to_rw(arena, start);
    if (rw && rw != start)
        __builtin___clear_cache((char*)rw, (char*)rw + len);
}

static void block_cache_unchain_entry(hb_block_cache_t* cache,
                                      hb_block_cache_entry_t* entry) {
    static const uint32_t arm64_nop = 0xd503201fu;
    hb_block_chain_meta_t* meta;
    uint8_t* patch;

    meta = block_cache_chain_meta(cache, entry, false);
    if (!entry || !entry->native_code || !meta)
        return;
    if (!meta->target_code && !meta->slot2_target_code)
        return;
    /* ОБЕ щели. Оставить вторую заплату на месте значило бы оставить переход в код
     * вытесненного блока — ровно тот висячий переход, ради которого и заведён трамплин. */
    if (meta->target_code &&
        meta->patch_offset + sizeof(uint32_t) <= entry->native_size) {
        patch = entry->native_code + meta->patch_offset;
        arm64_store_u32(cache->jit_mem, patch, arm64_nop);
        if (meta->patch_offset + 2 * sizeof(uint32_t) <= entry->native_size)
            arm64_store_u32(cache->jit_mem, patch + sizeof(uint32_t), arm64_nop);
        block_cache_clear_icache(cache->jit_mem, patch, 2 * sizeof(uint32_t));
    }
    if (meta->slot2_target_code &&
        meta->slot2_patch_offset + sizeof(uint32_t) <= entry->native_size) {
        patch = entry->native_code + meta->slot2_patch_offset;
        arm64_store_u32(cache->jit_mem, patch, arm64_nop);
        if (meta->slot2_patch_offset + 2 * sizeof(uint32_t) <= entry->native_size)
            arm64_store_u32(cache->jit_mem, patch + sizeof(uint32_t), arm64_nop);
        block_cache_clear_icache(cache->jit_mem, patch, 2 * sizeof(uint32_t));
    }
    memset(meta, 0, sizeof(*meta));
}

/* ═══ ОБСЛУЖИВАНИЕ ОТЗЫВА: СЧЁТ ПОСЕЩЁННОГО ПРОТИВ СЧЁТА ИЗМЕНЁННОГО ═══
 *
 * Приборы заведены 06.09.2026, лейн СЦЕПЛЕНИЕ. Вопрос ровно один и он числовой:
 * СКОЛЬКО слотов обход посещает и СКОЛЬКО рёбер при этом действительно меняет.
 * Читать это из исходника нельзя — ровно на таком чтении («вызов лишний, вон он»)
 * проект уже ошибался, и разбор Астры повторяет запрет дословно: «нельзя просто
 * удалить вызов по одному комментарию».
 *
 * ДВА СЧЁТЧИКА, А НЕ ОДИН (hb_probe.h, п. 1). `looked` растёт БЕЗУСЛОВНО на входе
 * в функцию, `hits` — только когда ребро СОВПАЛО. Тогда «слотов не посещали» и
 * «прибор не исполнялся» дают разные ответы, а не общий ноль.
 *
 * Время меряется mach_absolute_time (без системного вызова) и ТОЛЬКО под гейтом:
 * на выключенном приборе остаётся один предсказуемый переход. */
/* Повторный перевод ОДНОГО гостевого адреса. Отдельный прибор, потому что его ноль
 * значит совсем другое, чем ноль обхода: «заносили N раз и ни разу не поверх
 * существующей записи». Постановка LOOKED — у входа в block_cache_insert. */
HB_PROBE_DEFINE(pr_retranslate, "hb-povtornyj-perevod",
                "занесения в кеш блоков: looked = все занесения, hits = те из них, что "
                "легли ПОВЕРХ живой записи с тем же гостевым адресом (то есть повторный "
                "перевод одного адреса). Выселения по сбросу диапазона сюда НЕ входят",
                NULL, 4);

HB_PROBE_DEFINE(pr_unchain, "hb-unchain-obhod",
                "проходы block_cache_unchain_references: looked = вызовов обхода, "
                "hits = записей кеша, чья цель совпала с телом выселяемого блока "
                "(то есть рёбер, действительно снятых обходом)",
                NULL, 8);

static uint64_t g_unchain_calls;        /* вызовов обхода                                  */
static uint64_t g_unchain_visited;      /* слотов ПОСМОТРЕНО (тело цикла)                   */
static uint64_t g_unchain_matched;      /* рёбер СОВПАЛО (реально снято)                    */
static uint64_t g_unchain_overflow;     /* вызовов, ушедших на полный обход таблицы          */
static uint64_t g_unchain_ticks;        /* mach-тики внутри функции (только под гейтом)      */
static uint64_t g_unchain_skipped;      /* вызовов, снятых гейтом HB_UNCHAIN_WALK=0          */

/* Выселения по ПРИЧИНАМ — вторая половина вопроса Астры: «почему кеш вообще
 * выселяет эти блоки?». Причины разведены по МЕСТУ ВЫЗОВА, а не по догадке. */
enum {
    EVICT_RETRANSLATE = 0,  /* тот же гостевой адрес переведён заново (block_cache_insert)   */
    EVICT_RANGE,            /* сброс по гостевому диапазону (VirtualProtect RW->RX, SMC)     */
    EVICT_N
};
static uint64_t g_evict_reason[EVICT_N];
static uint64_t g_retrans_same_bytes;   /* повторный перевод, гостевые байты НЕ изменились   */
static uint64_t g_retrans_diff_bytes;   /* повторный перевод, байты изменились               */
static uint64_t g_evict_had_tramp;      /* у выселяемого БЫЛ входной трамплин (были рёбра)   */
static uint64_t g_evict_no_tramp;       /* трамплина не было — входящих рёбер быть не могло  */

static int unchain_stats_enabled(void) {
    static int cached = -1;
    if (cached < 0) cached = runtime_gate_flag( HB_GATE_HB_UNCHAIN_STATS, 0 );
    return cached;
}

/* Гейт САМОГО ОБХОДА. Умолчание 1 = сегодняшнее поведение без изменений; «0» снимает
 * обход целиком. Умолчание не меняется до тех пор, пока замер не назовёт число
 * изменённых рёбер: гейт, чья польза не измерена, включённым не становится. */
static int unchain_walk_enabled(void) {
    static int cached = -1;
    if (cached < 0) cached = runtime_gate_flag( HB_GATE_HB_UNCHAIN_WALK, 1 );
    return cached;
}

static void block_cache_unchain_references(hb_block_cache_t* cache, const uint8_t* target_code) {
    uint64_t t0 = 0;
    int stats;

    /* БЕЗУСЛОВНО и ВЫШЕ всех if — иначе оба счётчика замолчат вместе и различие
     * «не смотрел / не было» пропадёт (hb_probe.h, главное правило постановки). */
    HB_PROBE_LOOKED(&pr_unchain);
    stats = unchain_stats_enabled();
    if (stats) {
        __atomic_add_fetch(&g_unchain_calls, 1, __ATOMIC_RELAXED);
        t0 = mach_absolute_time();
    }

    if (!cache || !target_code) return;

    if (!unchain_walk_enabled()) {
        /* Обход снят. Отзыв остаётся ОДИН — атомарная запись литерала входного
         * трамплина у вызывающего (block_cache_prepare_replace_entry): все входящие
         * рёбра идут через него, потому что все три установщика (основная щель,
         * вторая щель, прямое ребро) берут цель у chain_trampoline_for. */
        if (stats) {
            __atomic_add_fetch(&g_unchain_skipped, 1, __ATOMIC_RELAXED);
            __atomic_add_fetch(&g_unchain_ticks, mach_absolute_time() - t0, __ATOMIC_RELAXED);
        }
        return;
    }

    if (cache->used_overflow) {
        if (stats) __atomic_add_fetch(&g_unchain_overflow, 1, __ATOMIC_RELAXED);
        for (size_t i = 0; i < cache->size; i++) {
            hb_block_cache_entry_t* entry = &cache->entries[i];
            const hb_block_chain_meta_t* meta = block_cache_chain_meta_const(cache, entry);
            if (stats) __atomic_add_fetch(&g_unchain_visited, 1, __ATOMIC_RELAXED);
            if (entry->valid && meta &&
                (meta->target_code == target_code || meta->slot2_target_code == target_code)) {
                if (stats) __atomic_add_fetch(&g_unchain_matched, 1, __ATOMIC_RELAXED);
                HB_PROBE_SAY(&pr_unchain, "совпало цель=%p щель1=%p щель2=%p\n",
                             (const void*)target_code, (const void*)meta->target_code,
                             (const void*)meta->slot2_target_code);
                block_cache_unchain_entry(cache, entry);
            }
        }
        if (stats) __atomic_add_fetch(&g_unchain_ticks, mach_absolute_time() - t0, __ATOMIC_RELAXED);
        return;
    }
    for (size_t i = 0; i < cache->used_count; i++) {
        hb_block_cache_entry_t* entry = &cache->entries[cache->used_slots[i]];
        const hb_block_chain_meta_t* meta = block_cache_chain_meta_const(cache, entry);
        if (stats) __atomic_add_fetch(&g_unchain_visited, 1, __ATOMIC_RELAXED);
        if (entry->valid && meta &&
            (meta->target_code == target_code || meta->slot2_target_code == target_code)) {
            if (stats) __atomic_add_fetch(&g_unchain_matched, 1, __ATOMIC_RELAXED);
            HB_PROBE_SAY(&pr_unchain, "совпало цель=%p щель1=%p щель2=%p\n",
                         (const void*)target_code, (const void*)meta->target_code,
                         (const void*)meta->slot2_target_code);
            block_cache_unchain_entry(cache, entry);
        }
    }
    if (stats) __atomic_add_fetch(&g_unchain_ticks, mach_absolute_time() - t0, __ATOMIC_RELAXED);
}

void hb_unchain_stats(uint64_t* calls, uint64_t* visited, uint64_t* matched,
                      uint64_t* skipped, uint64_t* overflow, uint64_t* ns) {
    mach_timebase_info_data_t tb;
    if (calls)    *calls    = __atomic_load_n(&g_unchain_calls,    __ATOMIC_RELAXED);
    if (visited)  *visited  = __atomic_load_n(&g_unchain_visited,  __ATOMIC_RELAXED);
    if (matched)  *matched  = __atomic_load_n(&g_unchain_matched,  __ATOMIC_RELAXED);
    if (skipped)  *skipped  = __atomic_load_n(&g_unchain_skipped,  __ATOMIC_RELAXED);
    if (overflow) *overflow = __atomic_load_n(&g_unchain_overflow, __ATOMIC_RELAXED);
    if (ns) {
        mach_timebase_info(&tb);
        *ns = (uint64_t)((double)__atomic_load_n(&g_unchain_ticks, __ATOMIC_RELAXED) *
                         (double)tb.numer / (double)(tb.denom ? tb.denom : 1));
    }
}

/* Итог обслуживания отзыва. Печатается при разрушении рантайма — как и итог первого
 * уровня кеша по соседству: иначе среда, отработавшая своё, унесла бы числа с собой. */
static void unchain_stats_report(void) {
    mach_timebase_info_data_t tb;
    double ns;
    uint64_t calls, visited, matched;

    if (!unchain_stats_enabled()) return;
    calls   = __atomic_load_n(&g_unchain_calls,   __ATOMIC_RELAXED);
    visited = __atomic_load_n(&g_unchain_visited, __ATOMIC_RELAXED);
    matched = __atomic_load_n(&g_unchain_matched, __ATOMIC_RELAXED);
    mach_timebase_info(&tb);
    ns = (double)__atomic_load_n(&g_unchain_ticks, __ATOMIC_RELAXED) *
         (double)tb.numer / (double)(tb.denom ? tb.denom : 1);
    fprintf(stderr,
            "macrunner-hb-unchain-итог: обход=%d вызовов=%llu снято_гейтом=%llu "
            "посещено=%llu совпало=%llu полный_обход=%llu нс=%.0f нс_на_вызов=%.1f "
            "посещено_на_вызов=%.1f\n",
            unchain_walk_enabled(),
            (unsigned long long)calls,
            (unsigned long long)__atomic_load_n(&g_unchain_skipped, __ATOMIC_RELAXED),
            (unsigned long long)visited, (unsigned long long)matched,
            (unsigned long long)__atomic_load_n(&g_unchain_overflow, __ATOMIC_RELAXED),
            ns, calls ? ns / (double)calls : 0.0,
            calls ? (double)visited / (double)calls : 0.0);
    fprintf(stderr,
            "macrunner-hb-evict-причины: повторный_перевод=%llu (байты_те_же=%llu "
            "байты_иные=%llu) сброс_диапазона=%llu был_трамплин=%llu без_трамплина=%llu\n",
            (unsigned long long)__atomic_load_n(&g_evict_reason[EVICT_RETRANSLATE], __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_retrans_same_bytes, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_retrans_diff_bytes, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_evict_reason[EVICT_RANGE], __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_evict_had_tramp, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_evict_no_tramp, __ATOMIC_RELAXED));
    fflush(stderr);
}

/* Defined next to chain_trampoline_build, which explains the whole arrangement; declared here
 * because eviction is the other half of it and comes first in this file. */
static uint64_t* chain_trampoline_slot(uint8_t* tramp);
static uint8_t* chain_trampoline_bailout(uint8_t* tramp);

static void block_cache_prepare_replace_entry(hb_jit_runtime_t* rt, hb_block_cache_t* cache,
                                              hb_block_cache_entry_t* entry) {
    int made_writable = 0;

    if (!entry || !entry->valid) return;
    /* MacRunner 2026-07-30 — the eviction literal store USED TO HAPPEN OUTSIDE THE WRITABLE BRACKET, and
     * that is the same defect class already fixed in chain_trampoline_for: a plain store into the JIT arena
     * while it is mapped read+execute.
     *
     * It fires exactly when a trampoline exists for the evicted block, which is precisely the variable the
     * bisection isolated. MACRUNNER_HB_CHAIN_PATCH=0 boots because it never creates a trampoline, so
     * `self->in_trampoline` is always NULL and this store never runs; every arm that creates one wedges —
     * including CHAIN_WRITE=0, which installs no tail patches at all and therefore rules out both the patch
     * and the chained execution as causes. Note the W^X cycle below runs in the booting arm too (it is gated
     * only on runtime_block_chain_enabled()), so the cycle itself was never the difference — the unbracketed
     * store was.
     *
     * Both writes now share ONE bracket. The ordering the original comment cared about is preserved inside
     * it: the literal is retired BEFORE the unchain walk, so the window in which a predecessor could still
     * enter dead code stays closed. */
    /* ★ 04.09.2026 — ПРИНУЖДЕНИЕ К ОТКАЗУ РОВНО ЗДЕСЬ, А НЕ В hb_jit_buffer_make_writable.
     *
     * Первая редакция ставила гейт внутрь самого make_writable — и валила весь прогон:
     * его зовут отовсюду, отказ везде сразу не оставляет от работы ничего, и сводка
     * счётчиков даже не успевала напечататься. Принуждение обязано быть УЖЕ, чем прибор,
     * который оно испытывает: здесь оно назначает отказ ТОЛЬКО этой скобке — ровно той,
     * чью молчащую ветвь и надо заставить сработать. */
    if (runtime_block_chain_enabled() && rt && rt->jit_mem && cache &&
        !hb_gate_on( HB_GATE_HB_TEST_FORCE_WPROT_FAIL ) &&
        hb_jit_buffer_make_writable(rt->jit_mem) == HB_OK) {
        hb_block_chain_meta_t* self = block_cache_chain_meta(cache, entry, false);
        made_writable = 1;
        if (unchain_stats_enabled())
            __atomic_add_fetch((self && self->in_trampoline) ? &g_evict_had_tramp
                                                             : &g_evict_no_tramp,
                               1, __ATOMIC_RELAXED);
        /* One store retires every inbound chain at once. A literal is data, so no i-cache maintenance is
         * needed for it — but it is still arena memory and still needs the arena writable. */
        /* ★ ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ (MACRUNNER_HB_TEST_NO_TRAMP_REVOKE=1, умолчание 0).
         *
         * Заведён 06.09.2026 по требованию разбора: «намеренно отключённый отзыв ОБЯЗАН
         * дать обнаруживаемое исполнение старой версии». Без него утверждение «обход
         * лишний, отзыв делает трамплин» непроверяемо — оно опирается на то, что
         * литерал и есть единственный работающий отзыв, а это ровно то, что надо
         * доказать. С гейтом=1 литерал НЕ переписывается: входящие рёбра продолжают
         * вести в тело, которое сейчас заменят. Если после этого старая версия НЕ
         * исполняется — значит отзыв делает не литерал, и вывод неверен.
         *
         * Гейт только для стенда. В прогоне игры он даёт исполнение мёртвого кода. */
        if (self && self->in_trampoline &&
            hb_gate_on( HB_GATE_HB_TEST_NO_TRAMP_REVOKE )) {
            /* контроль: отзыв намеренно НЕ делается */
        } else if (self && self->in_trampoline) {
            /* ★ 04.09.2026 — ПРИЁМНИК переводится в RW, ЗНАЧЕНИЕ остаётся RX.
             * `in_trampoline` — адрес ИСПОЛНЕНИЯ, и `bail` считается от него: туда
             * будут прыгать. А сам литерал лежит в арене, значит писать по нему под
             * splitwx нельзя — RX-половина закрыта на запись. Разница ровно в этом:
             * один и тот же трамплин даёт два адреса разного назначения. */
            uint64_t* slot = (uint64_t*)hb_jit_rx_to_rw(
                                 rt->jit_mem,
                                 (uint8_t*)chain_trampoline_slot(self->in_trampoline));
            uint8_t* bail = chain_trampoline_bailout(self->in_trampoline);
            if (slot && bail)
                __atomic_store_n(slot, (uint64_t)(uintptr_t)bail, __ATOMIC_RELEASE);
        }
        block_cache_unchain_references(cache, entry->native_code);
        block_cache_unchain_entry(cache, entry);
        (void)hb_jit_buffer_make_executable(rt->jit_mem);
    }
    if (!made_writable) {
        hb_block_chain_meta_t* meta = block_cache_chain_meta(cache, entry, false);
        /* ★★ 04.09.2026 — У ОДНОГО СОБЫТИЯ БЫЛО ДВА СМЫСЛА, И ОНО МОЛЧАЛО ОБА РАЗА.
         *
         * Сюда попадают два совершенно разных случая. Первый — сцепление выключено:
         * заплат нет, трамплина нет, обнулять нечего и терять нечего. Второй —
         * сцепление ВКЛЮЧЕНО, а hb_jit_buffer_make_writable отказал: заплаты стоят,
         * входящий трамплин ведёт в код, который вот-вот заменят, и memset ниже
         * СТИРАЕТ единственные указатели, которыми их можно было бы снять. После
         * этого заплаты остаются навсегда, а отменить их нечем.
         *
         * Различить их было нельзя: ветвь не оставляла следа. Считаем ТОЛЬКО опасный
         * смысл — тот, где действительно есть что терять. Обнуление оставлено как
         * было намеренно: слот сейчас же займёт другой блок, и наследовать чужую
         * разметку сцепления было бы хуже; правильное лечение — ОТКАЗАТЬСЯ занимать
         * слот, а это отдельная правка с разбором обоих вызывающих. Счётчик скажет,
         * стоит ли она того: сегодня он обязан быть нулём.
         *
         * Заставить его сработать можно: MACRUNNER_HB_TEST_FORCE_WPROT_FAIL=1. */
        if (meta && (meta->target_code || meta->slot2_target_code || meta->in_trampoline))
            t_chain_decline[CHAIN_DECL_NOUNCHAIN]++;
        if (meta) memset(meta, 0, sizeof(*meta));
    }
}

static void block_cache_destroy(hb_block_cache_t* cache) {
    if (!cache) return;
    for (size_t i = 0; i < cache->size; i++) {
        block_cache_release_owned_block(&cache->entries[i], NULL);
        ripmap_release(&cache->entries[i]);   /* иначе карта уезжает вместе с кешем в утечку */
    }
    /* Итог первого уровня печатается ПРИ РАЗРУШЕНИИ, а не только по степеням двойки: иначе
     * среда, отработавшая, скажем, 700 000 обращений, унесла бы свою долю попаданий с собой,
     * и приёмка увидела бы только последнюю степень двойки. */
    if (cache->l1 && (cache->l1_hits + cache->l1_misses)) {
        uint64_t total = cache->l1_hits + cache->l1_misses;
        fprintf(stderr,
                "macrunner-hb-l1cache-итог: кеш=%p обращений=%llu попаданий=%llu "
                "доля=%.2f%% порог=45.20%%\n",
                (void*)cache, (unsigned long long)total,
                (unsigned long long)cache->l1_hits,
                100.0 * (double)cache->l1_hits / (double)total);
    }
    if (l1_verify_mode() && (g_l1_verify_checks || g_l1_verify_poisoned)) {
        fprintf(stderr,
                "macrunner-hb-l1verify-итог: проверок=%llu расхождений=%llu порчено=%llu "
                "порча-отвергнута=%llu\n",
                (unsigned long long)g_l1_verify_checks,
                (unsigned long long)g_l1_verify_mismatch,
                (unsigned long long)g_l1_verify_poisoned,
                (unsigned long long)g_l1_verify_poison_rejected);
    }
    if (l1_term_stats_enabled()) {
        int k;
        for (k = 0; k < HB_TERM_N; k++) {
            uint64_t tot = t_l1_hit_term[k] + t_l1_miss_term[k];
            if (!tot) continue;
            fprintf(stderr, "macrunner-hb-l1term: %s обращений=%llu попаданий=%llu доля=%.2f%%\n",
                    hb_term_slot_names[k], (unsigned long long)tot,
                    (unsigned long long)t_l1_hit_term[k],
                    100.0 * (double)t_l1_hit_term[k] / (double)tot);
        }
    }
    free(cache->l1);
    free(cache->used_slots);
    free(cache->chain_meta);
    free(cache->entries);
    free(cache);
}

/* ★★★★ 07.09.2026, лейн ПОВТОРНЫЙ-ВЫПУСК — ПРИЧИНА ПОВТОРНОГО ВЫПУСКА, ПО ИМЕНАМ.
 *
 * ЧТО ИЗВЕСТНО ДО ЭТОГО ПРИБОРА. Лейн КЕШ намерил: 3 699 999 выпусков блоков на
 * 168 662 различных гостевых адреса = 21,94x, то есть 95,44 % выпусков — повтор
 * ВНУТРИ одного процесса. Его перепись ГЛОБАЛЬНА и потому отвечает только «повтор
 * был», а на вопрос «почему» у неё ответа нет по построению. Лейн СЦЕПЛЕНИЕ отдельно
 * доказал, что выселения по ёмкости и по коллизии НЕ СУЩЕСТВУЕТ как пути.
 *
 * ЧТО СЧИТАЕТ ЭТОТ. Каждое занесение блока в кеш (`block_cache_put` — единственная
 * точка материализации, через неё идут и выпуск кодогенератором, и подъём с диска)
 * относится РОВНО К ОДНОЙ из четырёх корзин:
 *
 *     ПЕРВЫЙ        адрес материализуется впервые за процесс
 *     СБРОС         тот же кеш, но ИНОЕ поколение -> запись снёс block_cache_reset
 *     ВЫСЕЛЕНИЕ     тот же кеш, ТО ЖЕ поколение -> запись сняли поимённо
 *                   (диапазон/SMC/повторный перевод)
 *     ЧУЖОЙ_КЕШ     адрес уже материализован ДРУГИМ кешем блоков
 *
 * Корзины взаимно исключающие и покрывают все занесения: сумма четырёх обязана
 * равняться числу учтённых занесений. Строка итога печатает обе величины рядом —
 * расхождение есть признак дыры в учёте, и его надо видеть, а не выводить из
 * такого учёта проценты.
 *
 * ПОЧЕМУ НЕ УКАЗАТЕЛЬ КЕША, А НОМЕР. Кеш переиспользуется (`hb_jit_runtime_reset`
 * сохраняет то же выделение), а разрушенный кеш отдаёт свой адрес обратно
 * распределителю — значит «тот же указатель» и «тот же кеш» разные утверждения.
 * Номер выдаётся один раз на выделение и от переиспользования адреса не зависит.
 *
 * ПОТОЛОК ОБЪЯВЛЕН. Таблица 2^21 записей по 16 байт = 33 МБ, выделяется ТОЛЬКО при
 * включённом гейте. Заполнение выше 3/4 поднимает `_full`, и тогда числа — НИЖНЯЯ
 * ГРАНИЦА; строка итога говорит это сама. На HK различных адресов ~169 000, то есть
 * запас 12x.
 *
 * ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ. `tests/povtor_prichina_probe.c` — четыре руки, по одной на
 * корзину: прибор обязан показать ноль в трёх остальных. Прибор, о котором не
 * доказано, что он умеет показать ноль там, где явления нет, — не прибор.
 *
 * ЦЕНА. Одна хеш-вставка на занесение (~230 000 за прогон HK при включённом кеше
 * трансляций, ~3,7 млн при выключенном). При выключенном гейте — одно чтение
 * статической переменной и возврат. */

HB_PROBE_DEFINE(pr_povtor, "hb-povtor-prichina",
                "занесения блока в кеш (block_cache_put): выпуск кодогенератором и "
                "подъём с диска, все пути; корзина у каждого ровно одна",
                "MACRUNNER_HB_POVTOR_STATS", 0);

/* Список корзин — в hb_runtime.h, ОДИН на учёт и на повозку (см. HB_POVTOR_KORZINY). */
#define POVTOR_PERVYJ    HB_POVTOR_K_PERVYJ
#define POVTOR_SBROS     HB_POVTOR_K_SBROS
#define POVTOR_VYSELENIE HB_POVTOR_K_VYSELENIE
#define POVTOR_CHUZHOJ   HB_POVTOR_K_CHUZHOJ
#define POVTOR_N         HB_POVTOR_K_N
static uint64_t g_povtor[POVTOR_N];

enum { HB_POVTOR_BITS = 21, HB_POVTOR_SLOTS = 1u << HB_POVTOR_BITS };
typedef struct { uint64_t pc; uint32_t cache_id; uint32_t gen; } hb_povtor_slot_t;
static hb_povtor_slot_t* g_povtor_tab;
static int g_povtor_full, g_povtor_oom;
static uint64_t g_povtor_unique;
static uint32_t g_povtor_next_cache_id;

/* ★★ ВТОРАЯ ТАБЛИЦА, КЛЮЧ = (КЕШ, АДРЕС). Без неё «сброс» и «чужой кеш» РАЗДЕЛИТЬ
 * ТОЧНО НЕЛЬЗЯ, и первая редакция прибора это скрывала.
 *
 * Одна таблица помнит только ПОСЛЕДНЕГО хозяина адреса. Тогда путь «кеш A перевёл ->
 * кеш B перевёл -> кеш A сбросили -> кеш A перевёл заново» на последнем шаге даёт
 * «чужой кеш», хотя причина была СБРОС. То есть при одной таблице `sbros` — нижняя
 * граница, а `chuzhoj_kesh` — верхняя, и порядок работ по ним назначать нельзя.
 *
 * Здесь хранится, держал ли ЭТОТ кеш ЭТОТ адрес и в каком поколении. Тогда:
 *   пара НЕ найдена, адрес найден глобально -> ЧУЖОЙ КЕШ (этот кеш его и не имел)
 *   пара найдена, поколение иное            -> СБРОС     (этот кеш имел и потерял)
 *   пара найдена, поколение то же           -> ВЫСЕЛЕНИЕ (сняли поимённо)
 * Разделение становится взаимно исключающим по ФАКТУ, а не по последнему писавшему.
 *
 * Ёмкость 2^23 при ~3,7 млн пар на прогоне HK: запас чуть больше двух раз. Потолок
 * объявлен тем же флагом `_full`, и строка итога печатает его. */
enum { HB_POVTOR_PAIR_BITS = 23, HB_POVTOR_PAIR_SLOTS = 1u << HB_POVTOR_PAIR_BITS };
typedef struct { uint64_t pc; uint32_t cache_id; uint32_t gen; } hb_povtor_pair_t;
static hb_povtor_pair_t* g_povtor_pary;
static int g_povtor_pary_full;
static uint64_t g_povtor_par_unique;

/* Учёт СБРОСОВ и того, что они уносят. Доля «сброс» без этого числа остаётся
 * следствием без причины: неизвестно, много ли сбросов или они редки и разорительны. */
static uint64_t g_reset_events, g_reset_entries, g_reset_max_entries;
/* Сбросы, унёсшие НОЛЬ записей: их цена — холостой вызов, а не повторный перевод.
 * Отдельной корзиной, иначе среднее «записей на сброс» смешивает два разных явления. */
static uint64_t g_reset_empty;
/* Сбросы и снесённые ими записи, РАЗДЕЛЬНО ПО МЕСТУ вызова. Список мест — в hb_runtime.h. */
static uint64_t g_reset_mesto[HB_POVTOR_M_N], g_reset_mesto_zapisej[HB_POVTOR_M_N];
static const char* const povtor_mesta_imena[HB_POVTOR_M_N] = {
#define HB_POVTOR_MESTO_NAME(imya, podpis) podpis,
    HB_POVTOR_MESTA(HB_POVTOR_MESTO_NAME)
#undef HB_POVTOR_MESTO_NAME
};
/* Место ТЕКУЩЕГО сброса. Потоковое: block_cache_reset вызывается синхронно из
 * hb_jit_runtime_reset_at того же потока, промежуточных точек нет. */
static _Thread_local int t_reset_mesto;

/* Подавление гашения кеша косвенных на пути повторного перевода — ТОЛЬКО для
 * отрицательного контроля приёмки. Без этой руки «слот чист» после правки было бы
 * неотличимо от «слот и так не заполнялся», и правка не была бы доказана ничем. */
static int ic_clear_suppressed_for_test(void) {
    static int cached = -1;
    if (cached < 0) {
        const char* v = hb_gate( HB_GATE_HB_TEST_NO_IC_CLEAR_ON_RETRANSLATE );
        cached = (v && *v && *v != '0') ? 1 : 0;
    }
    return cached;
}

static int povtor_stats_enabled(void) {
    static int cached = -1;
    if (cached < 0) {
        const char* v = hb_gate( HB_GATE_HB_POVTOR_STATS );
        cached = (v && *v && *v != '0') ? 1 : 0;
    }
    return cached;
}

/* Номер кеша. Выдаётся лениво и один раз; ноль означает «ещё не выдан», поэтому
 * нумерация начинается с единицы. */
static uint32_t povtor_cache_id(hb_block_cache_t* cache) {
    if (!cache->census_id)
        cache->census_id = __atomic_add_fetch(&g_povtor_next_cache_id, 1, __ATOMIC_RELAXED);
    return cache->census_id;
}

/* Спросить таблицу пар и обновить её. Возвращает корзину повтора.
 * При переполнении или нехватке памяти отвечает ЧУЖОЙ КЕШ и поднимает флаг: это
 * названо в строке итога, поэтому усечение не выдаётся за наблюдение. */
static int povtor_para(uint32_t id, uint64_t pc, uint32_t gen) {
    uint64_t h;
    unsigned i;

    if (!__atomic_load_n(&g_povtor_pary, __ATOMIC_ACQUIRE)) {
        hb_povtor_pair_t* t = (hb_povtor_pair_t*)calloc(HB_POVTOR_PAIR_SLOTS, sizeof(*t));
        hb_povtor_pair_t* pusto = NULL;
        if (!t) { __atomic_store_n(&g_povtor_pary_full, 1, __ATOMIC_RELAXED); return POVTOR_CHUZHOJ; }
        if (!__atomic_compare_exchange_n(&g_povtor_pary, &pusto, t, false,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            free(t);
    }
    if (__atomic_load_n(&g_povtor_pary_full, __ATOMIC_RELAXED)) return POVTOR_CHUZHOJ;

    /* Ключ смешивает НОМЕР КЕША и адрес: две разные пары обязаны расходиться по слотам,
     * иначе кеши слиплись бы и разделение исчезло. */
    h = pc ^ ((uint64_t)id * 0x9E3779B97F4A7C15ull);
    h ^= h >> 33; h *= 0xff51afd7ed558ccdull;
    h ^= h >> 33; h *= 0xc4ceb9fe1a85ec53ull;
    h ^= h >> 33;

    for (i = 0; i < 64; i++) {
        uint64_t slot = (h + i) & (HB_POVTOR_PAIR_SLOTS - 1);
        hb_povtor_pair_t* q = &__atomic_load_n(&g_povtor_pary, __ATOMIC_RELAXED)[slot];
        uint64_t cur = __atomic_load_n(&q->pc, __ATOMIC_RELAXED);
        if (cur == pc && __atomic_load_n(&q->cache_id, __ATOMIC_RELAXED) == id) {
            uint32_t was = __atomic_load_n(&q->gen, __ATOMIC_RELAXED);
            __atomic_store_n(&q->gen, gen, __ATOMIC_RELAXED);
            return (was != gen) ? POVTOR_SBROS : POVTOR_VYSELENIE;
        }
        if (cur == 0) {
            uint64_t expect = 0;
            if (__atomic_compare_exchange_n(&q->pc, &expect, pc, false,
                                            __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
                uint64_t u;
                __atomic_store_n(&q->cache_id, id, __ATOMIC_RELAXED);
                __atomic_store_n(&q->gen, gen, __ATOMIC_RELAXED);
                u = __atomic_add_fetch(&g_povtor_par_unique, 1, __ATOMIC_RELAXED);
                if (u > (HB_POVTOR_PAIR_SLOTS / 4) * 3)
                    __atomic_store_n(&g_povtor_pary_full, 1, __ATOMIC_RELAXED);
                return POVTOR_CHUZHOJ;   /* этот кеш адреса и не имел */
            }
        }
    }
    __atomic_store_n(&g_povtor_pary_full, 1, __ATOMIC_RELAXED);
    return POVTOR_CHUZHOJ;
}

/* Отнести одно занесение к корзине. Возвращает номер корзины, -1 = не учтено. */
static int povtor_note(hb_block_cache_t* cache, uint64_t pc) {
    uint64_t h;
    unsigned i;
    uint32_t id;
    int korzina;

    HB_PROBE_LOOKED(&pr_povtor);
    if (!povtor_stats_enabled() || !cache || !pc) return -1;

    /* Заведение таблицы без замка: проигравший гонку освобождает свою копию. Замок
     * здесь означал бы pthread.h в файле, где его нет, и лишнюю зависимость ради
     * события, которое случается один раз за процесс. */
    if (!__atomic_load_n(&g_povtor_tab, __ATOMIC_ACQUIRE)) {
        hb_povtor_slot_t* t = (hb_povtor_slot_t*)calloc(HB_POVTOR_SLOTS, sizeof(*t));
        hb_povtor_slot_t* pusto = NULL;
        if (!t) { __atomic_store_n(&g_povtor_oom, 1, __ATOMIC_RELAXED); return -1; }
        if (!__atomic_compare_exchange_n(&g_povtor_tab, &pusto, t, false,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            free(t);
    }
    if (!__atomic_load_n(&g_povtor_tab, __ATOMIC_ACQUIRE)) return -1;
    if (__atomic_load_n(&g_povtor_full, __ATOMIC_RELAXED)) return -1;

    id = povtor_cache_id(cache);

    /* fmix64 (murmur3) — тот же приём, что у переписи адресов лейна КЕШ: гостевые
     * адреса плотны и выровнены, младшие разряды сами по себе дали бы длинные цепочки. */
    h = pc;
    h ^= h >> 33; h *= 0xff51afd7ed558ccdull;
    h ^= h >> 33; h *= 0xc4ceb9fe1a85ec53ull;
    h ^= h >> 33;

    for (i = 0; i < 64; i++) {
        uint64_t slot = (h + i) & (HB_POVTOR_SLOTS - 1);
        hb_povtor_slot_t* s = &__atomic_load_n(&g_povtor_tab, __ATOMIC_RELAXED)[slot];
        uint64_t cur = __atomic_load_n(&s->pc, __ATOMIC_RELAXED);
        if (cur == pc) {
            /* Адрес уже материализовался в процессе. ЧЕМ ИМЕННО — спрашиваем у таблицы
             * пар, а не у последнего писавшего: см. разбор у g_povtor_pary. */
            korzina = povtor_para(id, pc, cache->reset_gen);
            __atomic_store_n(&s->cache_id, id, __ATOMIC_RELAXED);
            __atomic_store_n(&s->gen, cache->reset_gen, __ATOMIC_RELAXED);
            __atomic_add_fetch(&g_povtor[korzina], 1, __ATOMIC_RELAXED);
            HB_PROBE_HIT(&pr_povtor);
            return korzina;
        }
        if (cur == 0) {
            uint64_t expect = 0;
            if (__atomic_compare_exchange_n(&s->pc, &expect, pc, false,
                                            __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
                uint64_t u;
                __atomic_store_n(&s->cache_id, id, __ATOMIC_RELAXED);
                __atomic_store_n(&s->gen, cache->reset_gen, __ATOMIC_RELAXED);
                /* Пару заводим и на первом занесении — иначе следующий повтор в ЭТОМ ЖЕ
                 * кеше не нашёл бы её и лёг бы в «чужой кеш». */
                (void)povtor_para(id, pc, cache->reset_gen);
                __atomic_add_fetch(&g_povtor[POVTOR_PERVYJ], 1, __ATOMIC_RELAXED);
                HB_PROBE_HIT(&pr_povtor);
                u = __atomic_add_fetch(&g_povtor_unique, 1, __ATOMIC_RELAXED);
                if (u > (HB_POVTOR_SLOTS / 4) * 3)
                    __atomic_store_n(&g_povtor_full, 1, __ATOMIC_RELAXED);
                return POVTOR_PERVYJ;
            }
            if (expect == pc) continue;  /* другой поток занял слот тем же адресом */
        }
    }
    __atomic_store_n(&g_povtor_full, 1, __ATOMIC_RELAXED);
    return -1;
}

/* Итог. Печатается БЕЗУСЛОВНО при включённом гейте — подвешен к guard-census
 * (безусловная строка раз в 2^20 диспетчеризаций) и к разрушению среды. Причина
 * ровно та, что записана в задаче лейна: перепись hb_probe стоит на `atexit`, а
 * прогоны снимаются убийством — 0 строк в 300 журналах. */
static void povtor_itog(const char* why) {
    uint64_t summa = 0, vsego;
    int k;

    if (!povtor_stats_enabled()) return;
    for (k = 0; k < POVTOR_N; k++) summa += __atomic_load_n(&g_povtor[k], __ATOMIC_RELAXED);
    vsego = __atomic_load_n(&pr_povtor.looked, __ATOMIC_RELAXED);

    fprintf(stderr,
            "macrunner-hb-povtor-prichina-itog: why=%s zanesenij=%llu uchteno=%llu "
            "pervyj=%llu sbros=%llu vyselenie=%llu chuzhoj_kesh=%llu "
            "razlichnyh=%llu keshej=%u potolok=%d oom=%d par=%llu "
            "sbrosov=%llu sneseno_zapisej=%llu sbros_vholostuyu=%llu maks_za_sbros=%llu\n",
            why,
            (unsigned long long)vsego, (unsigned long long)summa,
            (unsigned long long)__atomic_load_n(&g_povtor[POVTOR_PERVYJ], __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_povtor[POVTOR_SBROS], __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_povtor[POVTOR_VYSELENIE], __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_povtor[POVTOR_CHUZHOJ], __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_povtor_unique, __ATOMIC_RELAXED),
            (unsigned)__atomic_load_n(&g_povtor_next_cache_id, __ATOMIC_RELAXED),
            __atomic_load_n(&g_povtor_full, __ATOMIC_RELAXED) |
                (__atomic_load_n(&g_povtor_pary_full, __ATOMIC_RELAXED) << 1), g_povtor_oom,
            (unsigned long long)__atomic_load_n(&g_povtor_par_unique, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_reset_events, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_reset_entries, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_reset_empty, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_reset_max_entries, __ATOMIC_RELAXED));
    for (k = 0; k < HB_POVTOR_M_N; k++)
        fprintf(stderr, "macrunner-hb-povtor-mesto-sbrosa: mesto=%s sbrosov=%llu zapisej=%llu\n",
                povtor_mesta_imena[k],
                (unsigned long long)__atomic_load_n(&g_reset_mesto[k], __ATOMIC_RELAXED),
                (unsigned long long)__atomic_load_n(&g_reset_mesto_zapisej[k], __ATOMIC_RELAXED));
    fflush(stderr);
}

/* Наружу — для приёмки и для повозки отрицательного контроля. */
uint64_t hb_povtor_korzina(int k) {
    if (k < 0 || k >= POVTOR_N) return 0;
    return __atomic_load_n(&g_povtor[k], __ATOMIC_RELAXED);
}
uint64_t hb_povtor_sbrosov(void) { return __atomic_load_n(&g_reset_events, __ATOMIC_RELAXED); }
uint64_t hb_povtor_sneseno(void) { return __atomic_load_n(&g_reset_entries, __ATOMIC_RELAXED); }
void hb_povtor_itog_print(const char* why) { povtor_itog(why); }

/* MacRunner: eager reset for per-thread runtime reuse. Free every owned cloned
 * block (zero UAF risk — no cross-generation lazy free) and clear all entries so
 * the next callback regenerates translations from current guest code.
 *
 * Lever #3: only the slots occupied this generation (tracked in used_slots) can have
 * valid==true / owns_block, so clearing just those is equivalent to the old full-table
 * memset but O(count) instead of O(524288). Post-condition is identical: every slot
 * valid==false, no owned block leaked, count==0. used_overflow keeps the old full clear
 * as a safety net when the tracking array could not grow. */
static void block_cache_reset(hb_block_cache_t* cache) {
    bool unchain;
    if (!cache) return;
    /* ★ 07.09.2026, лейн ПОВТОРНЫЙ-ВЫПУСК — УЧЁТ ЗДЕСЬ, А НЕ У ВЫЗЫВАЮЩЕГО.
     * Поколение растёт БЕЗУСЛОВНО на каждом сбросе, включая холостой: иначе повтор
     * после холостого сброса лёг бы в корзину «выселение», и две разные причины
     * смешались бы под одним именем. Число снесённых записей берётся ДО очистки. */
    {
        uint64_t zhivyh = (uint64_t)cache->count;
        uint64_t bylo;
        cache->reset_gen++;
        __atomic_add_fetch(&g_reset_events, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&g_reset_entries, zhivyh, __ATOMIC_RELAXED);
        if (!zhivyh) __atomic_add_fetch(&g_reset_empty, 1, __ATOMIC_RELAXED);
        if (t_reset_mesto >= 0 && t_reset_mesto < HB_POVTOR_M_N) {
            __atomic_add_fetch(&g_reset_mesto[t_reset_mesto], 1, __ATOMIC_RELAXED);
            __atomic_add_fetch(&g_reset_mesto_zapisej[t_reset_mesto], zhivyh, __ATOMIC_RELAXED);
        }
        bylo = __atomic_load_n(&g_reset_max_entries, __ATOMIC_RELAXED);
        while (zhivyh > bylo &&
               !__atomic_compare_exchange_n(&g_reset_max_entries, &bylo, zhivyh, false,
                                            __ATOMIC_RELAXED, __ATOMIC_RELAXED)) { }
    }
    unchain = runtime_block_chain_enabled();
    if (cache->used_overflow) {
        for (size_t i = 0; i < cache->size; i++) {
            if (unchain) block_cache_unchain_entry(cache, &cache->entries[i]);
            block_cache_release_owned_block(&cache->entries[i], NULL);
            ripmap_release(&cache->entries[i]);
        }
        memset(cache->entries, 0, cache->size * sizeof(*cache->entries));
        if (cache->chain_meta)
            memset(cache->chain_meta, 0,
                   cache->size * sizeof(*cache->chain_meta));
        cache->used_overflow = false;
    } else {
        for (size_t i = 0; i < cache->used_count; i++) {
            size_t slot = cache->used_slots[i];
            hb_block_cache_entry_t* e = &cache->entries[slot];
            if (unchain) block_cache_unchain_entry(cache, e);
            block_cache_release_owned_block(e, NULL);
            /* ★ 04.09.2026 — СБРОС ТЕЧЁТ КАРТАМИ. Сброс зовётся раз на вложенный кадр run_x64
             * (13777 раз за прогон ABZU), а карту снимало ровно одно место из пяти — вытеснение.
             * Пока карта строилась под гейтом, утечки не было видно; она безусловна — снимаем. */
            ripmap_release(e);
            memset(e, 0, sizeof(*e));
            if (cache->chain_meta)
                memset(&cache->chain_meta[slot], 0, sizeof(cache->chain_meta[slot]));
        }
    }
    cache->used_count = 0;
    cache->count = 0;
}

/* Отчёт о доле попаданий первого уровня. Печатается на степенях двойки и далее раз в 2^20,
 * через stderr — канал `ERR` wine до наших журналов не доходит (проверено: строк `err:` нет
 * НИ В ОДНОМ прогоне за всю историю). Первая строка выходит на ПЕРВОМ же обращении, чтобы
 * «прибор молчит» нельзя было спутать с «доля нулевая». */

/* Указатель слота первого уровня. ЗАМЕШИВАНИЕ, а не голый сдвиг — и вот почему, числами.
 *
 * Первая редакция брала `(addr >> 4) & 4095`. Замер повозкой (`tests/dispatch_l1_stress`)
 * показал провал: при 256 и 1024 блоках доля попаданий 96.72 %, а при 4096 и выше — РОВНО
 * 0.00 %. Причина арифметическая: блоки в повозке разнесены на 64 байта, значит `addr >> 4`
 * кратно четырём, и занятым оказывается лишь КАЖДЫЙ ЧЕТВЁРТЫЙ слот — три четверти таблицы
 * не используются вовсе, а на четверти идёт круговое вытеснение.
 *
 * Живой корпус тем же болен, только слабее: у 4 985 082 переведённых блоков (итерация 2)
 * адреса не выровнены на 16, но и не равномерны. Голый сдвиг отдаёт слоту ровно те разряды,
 * которые у соседних блоков совпадают.
 *
 * Умножение на нечётную константу переносит энтропию младших разрядов в старшие — приём Кнута,
 * тот же по смыслу, что у `tb_jmp_cache_hash_func` QEMU.
 *
 * Сдвиг 32, а НЕ 52. С 52 из произведения оставалось ровно 12 разрядов, и таблица шире 4096
 * слотов использовала только первые 4096: замер это и показал — доля попаданий 41.71 % ОДНА
 * И ТА ЖЕ при 4096, 16384 и 65536 слотах, чего при работающей ёмкости быть не может. */
/* ★★★ MacRunner 2026-08-24, КООРДИНАТОР — ХЕШ БЛОКА ОДНОЙ АППАРАТНОЙ КОМАНДОЙ.
 *
 * Дизассемблер рантайма Rosetta (`disasm_runtime_br_miss.s`, прислан владельцем):
 *     crc32cx w23, wzr, x22      ; ★ хеш гостевого PC — ОДНА команда
 *     and     w23, w23, w20      ; маска из закреплённого регистра
 * У нас на том же месте умножение на константу Кнута со сдвигами — четыре команды
 * (`lsr`, `mul`, `lsr`, `and`).
 *
 * `__crc32cd` доступна на нашем железе без дополнительных флагов сборки — проверено
 * отдельной пробой 24.08. Это та же CRC32C, что берёт Rosetta.
 *
 * Гейт `MACRUNNER_HB_CRC32_HASH`, умолчание ВЫКЛЮЧЕНО: ключ распределения по слотам
 * меняется, значит меняется и раскладка кеша — включать замером, а не верой.
 * Ветвление здесь читает статическую переменную; если замер покажет выигрыш,
 * следующим шагом ветвление убирается совсем. */
static int crc32_hash_enabled(void) {
    const char* v = hb_gate( HB_GATE_HB_CRC32_HASH );
    int cached = (v && v[0] && v[0] != '0') ? 1 : 0;
    static int napechatano;
    if (!napechatano) { napechatano = 1;
    fprintf(stderr, "macrunner-gate: MACRUNNER_HB_CRC32_HASH=%d\n", cached);
    fflush(stderr);
    }
    return cached;
}

static inline size_t l1_index(uint64_t addr, uint32_t mask) {
#if defined(__aarch64__)
    if (crc32_hash_enabled())
        return (size_t)__crc32cd(0u, addr) & mask;
#endif
    return (size_t)(((addr >> 2) * 0x9E3779B97F4A7C15ull) >> 32) & mask;
}


static void l1_report(hb_block_cache_t* cache) {
    uint64_t total = cache->l1_hits + cache->l1_misses;
    if (total == 0) return;
    /* Порог 4096: без него первая строка выходила на ОДНОМ обращении, и крошечные среды
     * (в наборе их сотни) заваливали журнал строками про два обращения. Итог при разрушении
     * печатается ВСЕГДА, так что мелкая среда всё равно не теряется. */
    if (total < 4096) return;
    if ((total & (total - 1)) != 0 && (total & 0xfffffu) != 0) return;
    fprintf(stderr,
            "macrunner-hb-l1cache: кеш=%p обращений=%llu попаданий=%llu промахов=%llu "
            "доля=%.2f%% порог=45.20%% слотов=%u\n",
            (void*)cache, (unsigned long long)total,
            (unsigned long long)cache->l1_hits, (unsigned long long)cache->l1_misses,
            100.0 * (double)cache->l1_hits / (double)total, (unsigned)(cache->l1_mask + 1));
}

/* ГЕЙТ `MACRUNNER_HB_L1_LAZY`, умолчание 256 обращений. Первый уровень выделяется ТОЛЬКО
 * среде, которая столько раз в кеш сходила.
 *
 * Без этого правка была бы тяжёлым регрессом по памяти, и вот арифметика. Сред за прогон
 * 116 736, и НИ ОДНА не разрушается (итерация 84, записано в hb_runtime.h). Первый уровень
 * на среду стоил бы:
 *     4096 слотов   64 КБ  × 116 736 =   7.1 ГБ
 *     16384        256 КБ  × 116 736 =  28.5 ГБ
 *     65536          1 МБ  × 116 736 = 114.0 ГБ
 * При этом занятость кеша блоков — МЕДИАНА 12 записей (итерация 83): подавляющее
 * большинство сред не делает и десятка обращений, а страницы первого уровня заняло бы.
 *
 * Порог 256 выше медианы в двадцать раз, так что платят только те среды, где первому
 * уровню есть что кешировать. `=0` гасит ленивость (выделять сразу), большое значение —
 * фактически гасит сам первый уровень. */
static uint32_t l1_lazy_threshold(void) {
    static uint32_t v; static int init;
    if (!init) {
        const char* s = hb_gate( HB_GATE_HB_L1_LAZY );
        long long n = (s && *s) ? atoll(s) : -1;
        v = (n >= 0) ? (uint32_t)n : 256u;
        init = 1;
    }
    return v;
}

static void l1_maybe_alloc(hb_block_cache_t* cache) {
    uint32_t n;
    if (cache->l1 || !l1_cache_enabled()) return;
    if (cache->l1_hits + cache->l1_misses < l1_lazy_threshold()) return;
    n = l1_slots();
    cache->l1 = calloc(n, sizeof(hb_block_l1_slot_t));
    cache->l1_mask = cache->l1 ? n - 1 : 0;
}

static hb_block_cache_entry_t* block_cache_find(hb_block_cache_t* cache, uint64_t addr) {
    if (!cache) return NULL;
    if (cache->l1) {
        hb_block_l1_slot_t* s = &cache->l1[l1_index(addr, cache->l1_mask)];
        hb_block_cache_entry_t* e = s->entry;
        int vmode = l1_verify_mode();
        int poisoned_now = 0;
        if (vmode == 2 && ((cache->l1_hits + cache->l1_misses) & 0xfffu) == 0xfffu && e) {
            /* Порча: слот начинает указывать на СОСЕДНЮЮ запись таблицы. Так подделывается
             * ровно тот отказ, ради которого сверка и написана — попадание, отдающее не тот
             * блок. Правило дерева: отсутствие отказа доказывает что-то только тогда, когда
             * показано, что отказ был бы виден. */
            size_t idx = block_cache_entry_index(cache, e);
            if (idx != SIZE_MAX && cache->size > 1) {
                s->entry = &cache->entries[(idx + 1) & cache->size_mask];
                e = s->entry;
                g_l1_verify_poisoned++;
                poisoned_now = 1;
            }
        }
        if (s->guest_addr == addr && e && e->valid && e->guest_addr == addr) {
            if (vmode) {
                hb_block_cache_entry_t* truth = NULL;
                size_t j, base = block_cache_hash(addr);
                for (j = 0; j < cache->size; j++) {
                    size_t probe = (base + j) & cache->size_mask;
                    if (!cache->entries[probe].valid) break;
                    if (cache->entries[probe].guest_addr == addr) {
                        truth = &cache->entries[probe];
                        break;
                    }
                }
                g_l1_verify_checks++;
                if (truth != e) {
                    g_l1_verify_mismatch++;
                    fprintf(stderr,
                            "macrunner-hb-l1verify-РАСХОЖДЕНИЕ: адрес=0x%llx первый-уровень=%p "
                            "таблица=%p расхождений=%llu из %llu проверок\n",
                            (unsigned long long)addr, (void*)e, (void*)truth,
                            (unsigned long long)g_l1_verify_mismatch,
                            (unsigned long long)g_l1_verify_checks);
                }
            }
            cache->l1_hits++;
            if (l1_term_stats_enabled()) t_l1_hit_term[t_l1_prev_term]++;
            l1_report(cache);
            return e;
        }
        /* Сюда попадаем, когда попадание ОТВЕРГНУТО. Для руки `=2` это и есть искомое
         * доказательство: слот был испорчен намеренно, и три проверки его не пропустили —
         * ответ будет взят из полной таблицы ниже. Счётчик нужен потому, что первая редакция
         * печатала «порчено=19, расхождений=0» и это читалось как «сверка слепа»; на деле
         * расхождению неоткуда взяться — порча превращается в промах, а не в неверный ответ. */
        if (poisoned_now) g_l1_verify_poison_rejected++;
    }
    size_t idx = block_cache_hash(addr);
    for (size_t i = 0; i < cache->size; i++) {
        size_t probe = (idx + i) & cache->size_mask;
        if (!cache->entries[probe].valid) break;
        if (cache->entries[probe].guest_addr == addr) {
            if (cache->l1) {
                hb_block_l1_slot_t* s = &cache->l1[l1_index(addr, cache->l1_mask)];
                s->guest_addr = addr;
                s->entry = &cache->entries[probe];
            }
            cache->l1_misses++;
            if (l1_term_stats_enabled()) t_l1_miss_term[t_l1_prev_term]++;
            l1_maybe_alloc(cache);
            l1_report(cache);
            return &cache->entries[probe];
        }
    }
    /* Промах засчитывается и когда блока нет вовсе: иначе доля попаданий считалась бы от
     * одних удачных поисков и всегда выглядела бы выше, чем есть. */
    cache->l1_misses++;
    l1_maybe_alloc(cache);
    l1_report(cache);
    return NULL;
}

/* A chained block may fault after leaving the entry protected by the guard.
 * Resolve its actual owner after siglongjmp, outside signal context. */
static hb_block_cache_entry_t* block_cache_find_native_pc(hb_block_cache_t* cache,
                                                          uint64_t native_pc) {
    if (!cache || !native_pc) return NULL;
    for (size_t i = 0; i < cache->size; i++) {
        hb_block_cache_entry_t* entry = &cache->entries[i];
        uintptr_t start, end;
        if (!entry->valid || !entry->native_code || !entry->native_size) continue;
        start = (uintptr_t)entry->native_code;
        end = start + entry->native_size;
        if (end >= start && (uintptr_t)native_pc >= start && (uintptr_t)native_pc < end)
            return entry;
    }
    return NULL;
}

int hb_jit_runtime_native_block_info(hb_jit_runtime_t* rt, uint64_t native_pc,
                                     uint64_t* guest_addr, uint64_t* native_start,
                                     size_t* native_size) {
    hb_block_cache_entry_t* entry;

    if (guest_addr) *guest_addr = 0;
    if (native_start) *native_start = 0;
    if (native_size) *native_size = 0;
    if (!rt || !native_pc) return 0;
    entry = block_cache_find_native_pc(rt->block_cache, native_pc);
    if (!entry) return 0;
    if (guest_addr) *guest_addr = entry->guest_addr;
    if (native_start) *native_start = (uint64_t)(uintptr_t)entry->native_code;
    if (native_size) *native_size = entry->native_size;
    return 1;
}

static bool block_cache_is_full(const hb_block_cache_t* cache) {
    return cache && cache->count >= cache->size;
}

/* ★★★ ЕДИНИЦА, 2026-08-24, итерация 2 — ПОРОДА ВХОДА В СЕРЕДИНУ ЕДИНИЦЫ.
 *
 * Итерация 1 измерила по кешу на диске: при слиянии глубины 4 от 31 до 62 % блоков
 * начинаются ВНУТРИ промежутка другой единицы. Но кеш на диске не различает две породы:
 *
 *   (а) адрес достижим только ПРОВАЛОМ  -> при слиянии идёт встроенно, вход не нужен
 *   (б) адрес достижим ПЕРЕХОДОМ извне  -> нужен отдельный вход, иначе дубль трансляции
 *
 * Разделяет их только живой прогон, и ровно здесь: занесение НОВОГО блока по адресу,
 * который уже лежит внутри переведённой единицы, — это и есть порода (б), состоявшийся
 * дубль. Считаем их и объём выпущенного кода, который они стоили.
 *
 * Гейт `MACRUNNER_HB_TRACE_SIDE_ENTRY`, умолчание ВЫКЛ. Проход по таблице на КАЖДОЕ
 * занесение — это O(ёмкость), поэтому по умолчанию не платим ничего.
 *
 * ОГОВОРКА ПРИБОРА: промежуток берётся разыменованием `entry->block`, а при
 * `owns_block == false` владелец блока другой. Для диагностического гейта принято;
 * при переносе в умолчание span надо хранить в самой записи. */
static bool block_guest_span(const hb_ir_block_t* block, uint64_t* start, size_t* len);
static uint64_t g_se_puts, g_se_inside, g_se_inside_bytes, g_se_bytes;

static int se_trace_on(void) {
    const char* v = hb_gate( HB_GATE_HB_TRACE_SIDE_ENTRY );
    int cached = (v && *v && *v != '0') ? 1 : 0;
    return cached;
}

static void se_report(void) {
    if (!g_se_puts) return;
    fprintf(stderr,
            "macrunner-edinica-side: zaneseno=%llu vnutri_edinicy=%llu (%.2f %%) "
            "bayt_vnutri=%llu iz %llu (%.2f %%)\n",
            (unsigned long long)g_se_puts, (unsigned long long)g_se_inside,
            100.0 * (double)g_se_inside / (double)g_se_puts,
            (unsigned long long)g_se_inside_bytes, (unsigned long long)g_se_bytes,
            g_se_bytes ? 100.0 * (double)g_se_inside_bytes / (double)g_se_bytes : 0.0);
    fflush(stderr);
}

static hb_block_cache_entry_t* block_cache_put(hb_jit_runtime_t* rt, hb_block_cache_t* cache,
                                               uint64_t addr, uint8_t* code,
                                               size_t size, uint32_t steps,
                                               const hb_ir_block_t* block, bool fused,
                                               bool owns_block) {
    if (!cache) return NULL;
    /* ★ 07.09.2026, лейн ПОВТОРНЫЙ-ВЫПУСК — ПРИЧИНА ПОВТОРА, ОДНА НА ЗАНЕСЕНИЕ.
     * Стоит ЗДЕСЬ, потому что block_cache_put — единственная точка материализации
     * блока: через неё идут и выпуск кодогенератором, и подъём с диска, и свёртки.
     * Разложить занесение по причинам ниже, у ветвей вставки и обновления, нельзя:
     * ветвь «чужой кеш» не отличается от «первый» ничем, что видно в этой функции. */
    (void)povtor_note(cache, addr);
    /* ★ ЕДИНИЦА: адрес, по которому заводится блок, ЕСТЬ наблюдавшийся вход.
     * Отсюда реестр и наполняется; лифтер по нему режет слияние. Внутри — отказ,
     * если слияние выключено, так что по умолчанию это ничего не стоит. */
    hb_known_entry_note(addr);
    if (se_trace_on()) {
        static int armed;
        size_t k;
        if (!armed) { armed = 1; atexit(se_report); }
        g_se_puts++;
        g_se_bytes += (uint64_t)size;
        for (k = 0; k < cache->size; k++) {
            const hb_block_cache_entry_t* e = &cache->entries[k];
            uint64_t st; size_t ln;
            if (!e->valid || !e->block || e->guest_addr == addr) continue;
            if (!block_guest_span(e->block, &st, &ln)) continue;
            if (addr > st && addr < st + ln) {
                g_se_inside++;
                g_se_inside_bytes += (uint64_t)size;
                break;
            }
        }
        /* ЕДИНИЦА, итерация 9: печать на СТЕПЕНЯХ ДВОЙКИ плюс период 4096.
         * Причина — замер 8: обе руки со слиянием упали до 4096-го занесения, `atexit`
         * не сработал, и упавшие руки не дали НИ ОДНОГО числа. У падающей конфигурации
         * улику надо снимать рано, иначе её нет вовсе. */
        if ((g_se_puts & (g_se_puts - 1)) == 0 || (g_se_puts & 0xfffull) == 0) se_report();
    }
    /* ★ 06.09.2026, лейн СЦЕПЛЕНИЕ — ЧТОБЫ НОЛЬ «повторный_перевод» НЕ ВРАЛ.
     *
     * Счётчик EVICT_RETRANSLATE стоит в ветви «Update existing entry» ниже. Стенд
     * unchain_walk_probe эту ветвь не проходит НИ РАЗУ, то есть ненулевым счётчик не
     * показан ничем, и его ноль на мишени прочтётся как «повторных переводов нет» —
     * ровно тот класс лжи, ради которого заведён hb_probe.
     *
     * LOOKED стоит здесь, БЕЗУСЛОВНО, на каждом занесении. Тогда
     *     looked=0            занесений не было вовсе
     *     looked>0, hits=0    заносили, но существующую запись не обновляли НИ РАЗУ
     * и эти два ответа перестают быть одним нулём. */
    HB_PROBE_LOOKED(&pr_retranslate);
    size_t idx = block_cache_hash(addr);
    /* ★★★ MacRunner 2026-08-18, лейн ЛЕСТНИЦА, итерация 2436 (приказ владельца 195, пункт 2) —
     * КАРТА ОБЛАСТЕЙ JIT ДЛЯ ПРОФИЛИРОВЩИКА.
     *
     * Замер 2429: `sample` не различает наш выпущенный код — 99,91 % отсчётов рабочего потока
     * он приписал `__wine_unix_call_dispatcher`, то есть точке входа, за которой лежит всё
     * исполнение гостя. Под `???` при этом ноль: неизвестность замаскирована под осмысленное имя,
     * и любая доля выпущенного кода, снятая этим прибором, недостоверна (числа 2309 и 09.08
     * отозваны).
     *
     * Механизма регистрации у нас нет вовсе (замер 2435: ни `__jit_debug_register_code`, ни
     * `perf map`, ни `jitdump` — ноль вхождений). Но здесь, в единственной точке занесения блока
     * в кеш, уже известны ХОЗЯЙСКИЙ адрес, размер и ГОСТЕВОЙ адрес. Пишем их в файл — тем же
     * форматом, что Unity пишет `pmip_*.txt` (проверен на HK, итерация 2431), чтобы обе карты
     * читались одним разбором:
     *
     *     <начало>;<конец>;guest=0x<гостевой адрес>
     *
     * Тогда цепочка замыкается: хозяйский адрес из `sample` → эта карта → гостевой адрес →
     * `pmip` → имя управляемого метода. Ни одно звено не надо изобретать.
     *
     * За гейтом `MACRUNNER_HB_JIT_MAP`, умолчание ВЫКЛ: это запись в файл на КАЖДЫЙ
     * скомпилированный блок, то есть горячий путь компиляции. Файл открывается один раз. */
    {
        static int карта_гейт = -1;
        static FILE* карта;
        if (карта_гейт < 0) {
            const char* v = hb_gate( HB_GATE_HB_JIT_MAP );
            карта_гейт = (v && *v && *v != '0') ? 1 : 0;
            if (карта_гейт) {
                char путь[256];
                snprintf(путь, sizeof(путь), "/tmp/hbjit_%d.map", (int)getpid());
                карта = fopen(путь, "w");
                fprintf(stderr, "macrunner-hb-jit-map: файл=%s открыт=%d\n", путь, карта ? 1 : 0);
                fflush(stderr);
            }
        }
        if (карта_гейт && карта && code && size) {
            fprintf(карта, "%016llX;%016llX;guest=0x%llX\n",
                    (unsigned long long)(uintptr_t)code,
                    (unsigned long long)((uintptr_t)code + size),
                    (unsigned long long)addr);
        }
    }
    for (size_t i = 0; i < cache->size; i++) {
        size_t probe = (idx + i) & cache->size_mask;
        if (!cache->entries[probe].valid) {
            cache->entries[probe].guest_addr = addr;
            cache->entries[probe].native_code = code;
            cache->entries[probe].native_size = size;
            cache->entries[probe].steps = steps;
            cache->entries[probe].hit_count = 0;
            if (cache->chain_meta)
                memset(&cache->chain_meta[probe], 0, sizeof(cache->chain_meta[probe]));
            cache->entries[probe].block = block;
            cache->entries[probe].owns_block = owns_block;
            cache->entries[probe].fused = fused;
            cache->entries[probe].valid = true;
            cache->count++;
            /* MacRunner 2026-08-09 — ЗАНЯТОСТЬ КЕША БЛОКОВ ПО КАЖДОМУ КЕШУ.
             *
             * Счётчики `count`/`used_count` в структуре уже были (с 22.06, для быстрого
             * сброса), но НЕ ПЕЧАТАЛИСЬ. Без них выбор ёмкости — угадывание: на кеше IR
             * такая же оценка «по рассуждению» ошиблась в 200 раз (итерация 80).
             *
             * Таблица по заголовку — ~29 МБ ВИРТУАЛЬНЫХ на среду при ленивом заполнении,
             * а сред за прогон 34 386 (итерация 50). Печать раз в 4096 занесений. */
            {
                static unsigned long long ins;
                if (++ins == 1 || (ins & 0xfffull) == 0) {
                    fprintf(stderr, "macrunner-hb-blockcache: кеш=%p занято=%zu из %u занесений=%llu\n",
                            (void*)cache, cache->count, (unsigned)cache->size, ins);
                    fflush(stderr);
                }
            }
            /* lever #3: remember this newly-occupied slot so block_cache_reset clears only
             * used slots. Only this new-insert branch sets valid=true, so recording here
             * captures every occupied slot exactly once per generation. */
            if (cache->used_count >= cache->used_cap) {
                size_t ncap = cache->used_cap ? cache->used_cap * 2 : 256;
                uint32_t* n = realloc(cache->used_slots, ncap * sizeof(*n));
                if (n) { cache->used_slots = n; cache->used_cap = ncap; }
            }
            if (cache->used_count < cache->used_cap)
                cache->used_slots[cache->used_count++] = (uint32_t)probe;
            else
                cache->used_overflow = true;  /* tracking full -> reset does the safe full memset */
            smc_track_entry(rt, &cache->entries[probe], block);
            hb_contract_telemetry_record_translation(true);
            return &cache->entries[probe];
        }
        if (cache->entries[probe].guest_addr == addr) {
            /* Update existing entry */
            bool keep_existing_owner = cache->entries[probe].owns_block &&
                                       cache->entries[probe].block == block;
            /* ПРИЧИНА ВЫСЕЛЕНИЯ: тот же гостевой адрес переводится ЗАНОВО.
             * Старый отпечаток гостевых байтов запоминаем ДО замены — он и отвечает
             * на вопрос «изменилась ли семантика»: тот же отпечаток означает
             * повторный выпуск ОДНОЙ И ТОЙ ЖЕ версии блока, то есть работу,
             * которой могло не быть вовсе. */
            uint64_t staryj_otpechatok = cache->entries[probe].smc_hash;
            HB_PROBE_SAY(&pr_retranslate, "guest=0x%llx старое_тело=%p новое=%p\n",
                         (unsigned long long)addr,
                         (const void*)cache->entries[probe].native_code, (const void*)code);
            if (unchain_stats_enabled())
                __atomic_add_fetch(&g_evict_reason[EVICT_RETRANSLATE], 1, __ATOMIC_RELAXED);
            if (runtime_block_chain_enabled())
                block_cache_prepare_replace_entry(rt, cache, &cache->entries[probe]);
            block_cache_release_owned_block(&cache->entries[probe], block);
            /* ★★★ КАРТА ОТНОСИТСЯ К ПРЕЖНЕМУ КОДУ И ПРЕЖНЕМУ БЛОКУ. Ниже заменяются и
             * native_code, и block; оставить старую карту — значит отвечать на отказ
             * ПРАВДОПОДОБНЫМ гостевым адресом чужого блока. Это хуже утечки: неверный
             * ответ такого вида не отличит ни один счётчик. Свежую поставит ripmap_attach,
             * а у тех мест занесения, где карты нет вовсе (помощники, свёртки циклов),
             * запись честно останется без карты — и резолвер скажет «не знаю». */
            ripmap_release(&cache->entries[probe]);
            cache->entries[probe].native_code = code;
            cache->entries[probe].native_size = size;
            cache->entries[probe].steps = steps;
            if (cache->chain_meta)
                memset(&cache->chain_meta[probe], 0, sizeof(cache->chain_meta[probe]));
            cache->entries[probe].block = block;
            cache->entries[probe].owns_block = owns_block || keep_existing_owner;
            cache->entries[probe].fused = fused;
            smc_track_entry(rt, &cache->entries[probe], block);
            /* Отпечаток НОВОГО тела уже проставлен smc_track_entry. Ноль с любой из
             * сторон означает «блок не отслеживается» — такой случай в счёт не идёт
             * вовсе, иначе неотслеженные попали бы в «байты те же» и завысили долю. */
            if (unchain_stats_enabled() && staryj_otpechatok &&
                cache->entries[probe].smc_hash)
                __atomic_add_fetch(staryj_otpechatok == cache->entries[probe].smc_hash
                                       ? &g_retrans_same_bytes : &g_retrans_diff_bytes,
                                   1, __ATOMIC_RELAXED);
            /* ★★★ 07.09.2026, лейн ПОВТОРНЫЙ-ВЫПУСК — ПРАВИЛЬНОСТЬ: ГАСИТЬ КЕШ КОСВЕННЫХ.
             *
             * Дефект назван лейном СЦЕПЛЕНИЕ и им же оставлен нетронутым: из ТРЁХ путей,
             * снимающих запись кеша, кеш косвенных чистили ДВА —
             *   hb_jit_invalidate_guest_range  -> hb_ic_slots_clear_all() при dropped
             *   smc_evict_entry                -> hb_ic_slots_clear_all() безусловно
             * а этот, повторный перевод того же адреса, — НЕТ. Слот кеша косвенных держит
             * СЫРОЙ нативный адрес (см. оговорку о гонке у hb_ic_slot_t), арена только
             * растёт и старое тело остаётся отображённым, значит косвенный переход уходил
             * бы в ПРЕЖНЮЮ версию блока. Это исполнение старого кода, а не потеря скорости.
             *
             * ЧИСТИМ НЕ ВСЕГДА, и это не экономия, а точность. Отпечаток гостевых байтов
             * отвечает, изменилась ли семантика:
             *   отпечатки совпали   — выпущена ТА ЖЕ версия блока, старое тело ей
             *                         равносильно, гасить нечего;
             *   не совпали ЛИБО хоть один ноль (блок не отслеживается, доказать
             *                         равносильность нечем) — гасим.
             * Ноль трактуется в сторону гашения намеренно: неизвестность здесь обязана
             * стоить работы, а не правильности.
             *
             * Гейт MACRUNNER_HB_TEST_NO_IC_CLEAR_ON_RETRANSLATE=1 возвращает поведение ДО
             * правки — он существует ТОЛЬКО как отрицательный контроль приёмки
             * (tests/ic_retranslate_probe.c) и в прогонах игры не ставится: без него
             * «слот чист» было бы неотличимо от «слот и так не заполнялся». */
            if (runtime_indirect_ic_enabled() && !ic_clear_suppressed_for_test()) {
                uint64_t novyj_otpechatok = cache->entries[probe].smc_hash;
                if (!staryj_otpechatok || !novyj_otpechatok ||
                    staryj_otpechatok != novyj_otpechatok)
                    hb_ic_slots_clear_all();
            }
            hb_contract_telemetry_record_translation(false);
            return &cache->entries[probe];
        }
    }
    return NULL;
}

/* ★ 07.09.2026, лейн ПОВТОРНЫЙ-ВЫПУСК — ВХОД ДЛЯ ПРИЁМКИ В ВЕТВЬ «Update existing entry».
 *
 * ЗАЧЕМ ОН НУЖЕН, И ПОЧЕМУ ЭТО НЕ ПОДЛОГ. Ветвь повторного перевода из диспетчера НЕ
 * достижима по построению: put случается только после промаха поиска, а промах означает,
 * что живой записи с этим адресом нет. Достигают её ДРУГИЕ занесения — свёртки и помощники
 * (block_cache_put по body->guest_addr и соседям), и воспроизвести их на стенде значило бы
 * собрать распознаваемый узор memmove/сортировки. Это подтверждено числами дважды:
 * прибор hb-povtornyj-perevod даёт looked>0, hits=0 и у повозки лейна СЦЕПЛЕНИЕ (1024/0),
 * и у моей повозки причин (448/0).
 *
 * Поэтому приёмка зовёт ТУ ЖЕ функцию block_cache_put с тем же адресом — синтетичен здесь
 * только ВЫЗЫВАЮЩИЙ, а исполняемый код ветви настоящий, тот самый. Возвращает прежний
 * нативный адрес, чтобы повозка могла спросить у кеша косвенных именно про него.
 *
 * Живёт только при MACRUNNER_HB_POVTOR_STATS: это не путь прогона, и включать его
 * молча нельзя. */
uint8_t* hb_test_povtornyj_perevod(hb_jit_runtime_t* rt, uint64_t addr,
                                   uint8_t* novoe_telo, size_t razmer) {
    hb_block_cache_entry_t* e;
    uint8_t* staroe;
    if (!rt || !rt->block_cache || !povtor_stats_enabled()) return NULL;
    e = block_cache_find(rt->block_cache, addr);
    if (!e || !e->valid) return NULL;
    staroe = e->native_code;
    /* Тот же адрес, ДРУГОЕ тело: block_cache_put уходит в ветвь обновления записи. */
    if (!block_cache_put(rt, rt->block_cache, addr, novoe_telo, razmer,
                         e->steps, e->block, e->fused, false))
        return NULL;
    return staroe;
}

static int runtime_env_enabled(const char* name) {
    const char* val = hb_env(name);
    return val && *val && *val != '0';
}



static int runtime_env_enabled_default_on(const char* name) {
    const char* val = hb_env(name);
    return !val || !*val || *val != '0';
}

/* ═══ СЦЕПЛЕНИЕ БЛОКОВ — УМОЛЧАНИЕ ПО АРХИТЕКТУРЕ ═══
 *
 * Условие, которое здесь стояло («умолчание 0, пока замер не сдвинет; решает avg_chain,
 * и он ровно 1.0000»), ВЫПОЛНЕНО — и выполнено по-разному на двух архитектурах.
 * Поэтому и умолчание разное; образец — jit_direct_stack_enabled_for в кодогенераторе.
 *
 * i386 — ВКЛЮЧЕНО. Корень (трамплин читал зашитое смещение 544 вместо ctx->pc)
 * убран 04.09; avg_chain 1,0000 → 6,5850. Замерено ДВАЖДЫ, время до вехи 12 000 строк
 * на Half-Life, дист сверен по отпечатку:
 *     6 пар: ВЫКЛ 7,21 с → ВКЛ 6,44 с   −10,62 %
 *     4 пары: ВЫКЛ 6,60 с → ВКЛ 5,95 с   −9,92 %
 * Прогоны со сцеплением уходят ДАЛЬШЕ (17 323 строки против 15 697), отказов доступа
 * меньше 64 за 150 с в ОБЕИХ руках — шторма нет, клина нет.
 *
 * x64 — ВКЛЮЧЕНО С 05.09.2026, ГЕЙТ MACRUNNER_HB_BLOCK_CHAIN_X64 УДАЛЁН.
 *
 * Довод, по которому x64 держали выключенным («измеренно ломает Hollow Knight 2/2
 * побайтово»), ОПРОВЕРГНУТ: ломало не сцепление, а прямая единица без перехода,
 * которая не объявляла свой выход. Её pc чинил диспетчер на C — ветвь
 * «Sequential block end», — а сцепление именно её и снимает, поэтому цель ребра
 * исполнялась ДВАЖДЫ. Лечение (codegen_emit_tail_pc_if_needed) безусловно и
 * доказано серией; разбор — reports/сцепление/i8const-ПОЧИНЕНО-05.09.2026.md.
 *
 * ЗАМЕР, ПО КОТОРОМУ УМОЛЧАНИЕ СДВИНУТО (05.09.2026, ОДИН двоичный файл, руки
 * разведены только гейтом и СВОИМ хранилищем перевода на руку — общий корень
 * заставил бы вторую руку поднимать блоки, собранные первой):
 *     Hollow Knight, 5 пар ВРАЗБИВКУ. Мера — секунды ОТ СТРОКИ ДВИЖКА
 *     (`macrunner-hb-сборка`) ДО ВЕХИ (`create method=CreateSwapChainForHwnd`);
 *     обвязка (раскладка префикса, службы) в меру НЕ ВХОДИТ — штатная
 *     `time_to_swapchain` её включает и на одном прогоне дала 365 с при 121,8 с
 *     честных, то есть выглядела бы катастрофой.
 *         ВЫКЛ 136,0 136,8 137,0 137,1 137,7   медиана 137,0
 *         ВКЛ  117,0 121,1 121,2 121,7 121,8   медиана 121,2      -11,5 %
 *     Популяции НЕ ПЕРЕСЕКАЮТСЯ: худший ВКЛ на 14,2 с быстрее лучшего ВЫКЛ.
 *     Разброс числом: ВЫКЛ 1,7 с (1,24 %), ВКЛ 4,8 с (3,98 %).
 *     Веха взята 5 из 5 в ОБЕИХ руках, `Begin MonoManager` 5 из 5, утверждение
 *     Mono `i8const` 0 из 10, c0000005 0 из 10.
 *     avg_chain (отдельная пара, прибор в обеих руках): 1,0000 -> 3,0788 на
 *     занятом потоке, до 33,9140 на другом; в руке ВЫКЛ `1.0000` — ЕДИНСТВЕННОЕ
 *     значение во всём журнале.
 *     AI War 2 (тоже гость x86-64) — вреда нет; разбор в отчёте.
 *     i386 (Diablo, Half-Life, установщик GTA VC) гейт НЕ ЧИТАЛИ ВОВСЕ — у них
 *     ctx->arch == HB_ARCH_X86, ветвь ниже; они служат контролем ПЕРЕСБОРКИ.
 *
 * ★★★★★★★ УСЛОВИЕ СНЯТИЯ ВЫПОЛНЕНО 05.09.2026 — ГЕЙТ УДАЛЁН, СЦЕПЛЕНИЕ x64 БЕЗУСЛОВНО.
 *
 * Гейт держала ТОЛЬКО приёмка: на одном двоичном файле, где он был единственной
 * переменной, `make test` давал 491/2 без гейта и 484/9 с ним (обе пары чисел
 * воспроизведены 05.09 на свежей сборке — отрицательный контроль есть). Семь
 * отказов разобраны поимённо и закрыты, каждый по своей причине, без подгонки:
 *
 *   ДВА (hb_test_runner.c: block_limit_explicit_fault, notepad_plus_long_init_no_silent_abort)
 *   — настоящие дефекты ДОКЛАДА о сроке, оба в движке:
 *     · выход по пределу БЛОКОВ внутри цепочки докладывался как HB_OK / faulted=0
 *       (предел виден только в out.result), тогда как тот же предел, замеченный
 *       диспетчером в вершине цикла, идёт через set_runtime_fault_result. Теперь
 *       путь ОДИН: у обработки ctx->last_result после захода в выпущенный код стоит
 *       развилка по РОДУ предела — БЛОК -> set_runtime_fault_result (faulted=1,
 *       r=BLOCK_LIMIT, last_result), ШАГ -> HB_OK без faulted (ритм, а не отказ:
 *       иначе wow64 делал из него исключение гостя, i386 умирал c0000001).
 *       Образец — QEMU: срок icount проверяется в НАЧАЛЕ каждого TB
 *       (gen_tb_start: icount_decr < 0 -> exit_tb(TB_EXIT_REQUESTED)), а причину
 *       выхода разбирает ОДНО место (cpu_tb_exec / cpu_handle_interrupt), кто бы её
 *       ни заметил — цикл или блок;
 *     · выпущенный счёт «проверить блок -> блок++ -> проверить шаг -> шаг+=N»
 *       засчитывал блок, упёршийся в ШАГ-срок: при step_limit=3 получалось blocks=4
 *       при steps=3. Теперь ОБА среза проверяются ДО списания ОБОИХ счётчиков
 *       (emit_block_counter_accounting; как icount — команда допускается, лишь если
 *       бюджет позволяет, и только тогда бюджет расходуется), размер выпуска тот же.
 *
 *   ПЯТЬ (тесты продвижения семей) — закрепляли место останова диспетчера на границе
 *   единицы перевода, которой в договоре движка нет. Переписаны на СВОЙСТВО: петля
 *   доведена до конца ОДНИМ свёрнутым блоком (диспетчеризаций ровно три за всю
 *   последовательность), запись кеша fused=true, конечное состояние гостя прежнее.
 *   Разбор с числами — у promote_pair_run_to_exit в hb_test_runner.c. В этой форме
 *   тесты проходят И со сцеплением, И без него — закреплён инвариант, а не новое
 *   место останова.
 *
 * Приёмка после этого: 491 passed, 2 failed в ОБЕИХ руках (гейт=1 и без гейта) —
 * ровно записанное здесь условие; после удаления гейта — те же 491/2. Замер выигрыша
 * повторять не требовалось: он записан выше и подтверждён на выложенной сборке
 * (reports/сцепление/ГЕЙТ-x64-СНЯТ-05.09.2026.md).
 *
 * ВНИМАНИЕ вызывающим: MACRUNNER_HB_BLOCK_CHAIN относится ТОЛЬКО к i386. */
static int runtime_block_chain_enabled_for(hb_arch_t arch) {
    if (arch != HB_ARCH_X86) return 1;   /* x64 — безусловно, разбор выше */
    {
        const char* v = hb_gate( HB_GATE_HB_BLOCK_CHAIN );
        if (v && *v) return *v != '0';
        return 1;
    }
}

/* «Может ли сцепление быть включено хоть на одной архитектуре».
 *
 * Для путей УБОРКИ (сброс кеша, выселение, расцепление ссылок) и для ключа стойкого
 * кеша. Они обязаны быть консервативными: пропустить расцепление опаснее, чем лишний
 * раз его выполнить, а перестраховка в ключе кеша лишь обесценивает лишние записи. */
static int runtime_block_chain_possible(void) {
    return runtime_block_chain_enabled_for(HB_ARCH_X86) ||
           runtime_block_chain_enabled_for(HB_ARCH_X64);
}

/* Прежняя форма — только там, где архитектуры под рукой нет. */
static int runtime_block_chain_enabled(void) {
    return runtime_block_chain_possible();
}

static int runtime_single_lookup_enabled(void) {
    return runtime_gate_flag( HB_GATE_HB_SINGLE_LOOKUP, 0);
}

/* MacRunner 2026-07-30 — BISECT HANDLE for the chaining exit=5.
 *
 * Arming MACRUNNER_HB_BLOCK_CHAIN changes three things at once, which is why 5/5 runs dying told us
 * nothing about WHICH: at emit time it adds a 4-NOP chain slot and 7 instructions of block/step counter
 * accounting to every block (hb_arm64_codegen.c, same env var), and at run time it lets
 * patch_block_tail rewrite block tails to branch through a trampoline.
 *
 * Setting MACRUNNER_HB_CHAIN_PATCH=0 keeps the whole emit side and disables only the run-time patching.
 * If a run then BOOTS, the emitted shape is innocent and the defect is in the patch/trampoline/eviction
 * machinery; if it still dies at exit=5, the defect is in the emitted block itself — the slot or the
 * counter accounting — which would be the more surprising answer and worth knowing before touching the
 * trampoline again. One 45-second run decides it, because these deaths are fast. */
/* Second half of that bisect, now that CHAIN_PATCH=0 has cleared the emit side (it booted to
 * Begin MonoManager at +61.3 s and 19.15 M dispatches, where every patching arm dies at exit=5 within a
 * second of the first dispatch).
 *
 * The patch path still does two separable things: it lazily COMMITS a 128-byte trampoline into the JIT
 * arena for the target, and it WRITES two instructions over the predecessor's chain slot — i.e. it
 * modifies code that other threads may be executing, on a W^X MAP_JIT mapping, with i-cache maintenance.
 * MACRUNNER_HB_CHAIN_WRITE=0 keeps the trampoline commit and skips only that write, so a boot tells us
 * the arena allocation is fine and the live-code modification is fatal, while another exit=5 points at
 * committing into the arena while the guest runs. */
/* MacRunner 2026-07-30 — third bisect handle, for the wedge that appears once chaining actually engages.
 *
 * With the slot predicate fixed, chaining works (avg_chain 5.19, 12033 tails patched) and the boot wedges
 * deterministically at ~+53 s, 2/2, with identical counters — a repeatable state, not a race. The leading
 * explanation is a chained CYCLE: a guest loop whose blocks are chained in both directions runs natively and
 * correctly, but re-enters the dispatcher only on a mispredict, so a hot loop with a rare exit edge spins in
 * the arena while ctx->block_count climbs. That is exactly the observed shape — blocks high, dispatches low,
 * then silence.
 *
 * MACRUNNER_HB_CHAIN_FORWARD_ONLY=1 declines to patch when the successor's guest address is not strictly
 * greater than the predecessor's, which is the shape of a loop backedge. If the wedge disappears while
 * avg_chain stays above 1, the cycle explanation is confirmed and forward-only chaining is a usable subset;
 * if the wedge survives, the cause is instead the 5x larger steps/blocks deltas feeding back through
 * out->steps_executed into macrunner_hb_run_x64's loop, and the cycle idea is refuted. Default 0, so it
 * changes nothing until a measurement says otherwise. */
static int runtime_chain_forward_only_enabled(void) {
    return runtime_gate_flag( HB_GATE_HB_CHAIN_FORWARD_ONLY, 0);
}

/* MacRunner 2026-07-30 — bisect on HOW MUCH chaining is survivable, after both kind-based splits failed.
 *
 * Restricting WHICH edges get chained has now been tried twice and neither changed the wedge: the widened
 * terminal set and the original direct-JMP-only set both die, and forward-only chaining (which removed
 * 258 640 backedges and dropped avg_chain from 5.19 to 1.37) wedges identically. So the next axis is
 * quantity, not kind. MACRUNNER_HB_CHAIN_MAX_PATCHES=N stops after N successful patches; 0 means unlimited.
 *
 * If a small N boots and unlimited wedges, the wedge is cumulative — a resource or state effect — and the
 * cap is itself a shippable subset of chaining. If even a handful of patches wedges, then
 * MACRUNNER_HB_TRACE_CHAIN_EDGE=1 has already logged those few cur->next guest pairs and the culprit edge
 * is named outright. Either way the answer is one run, which is why this is the axis to bisect. */
static uint64_t runtime_chain_max_patches(void) {
    static int parsed;
    static uint64_t limit;
    if (!parsed) {
        const char* env = hb_gate( HB_GATE_HB_CHAIN_MAX_PATCHES );
        limit = (env && *env) ? strtoull(env, NULL, 0) : 0;
        parsed = 1;
    }
    return limit;
}

/* MacRunner 2026-08-18 — С КАКОГО НОМЕРА печатать рёбра.
 *
 * Прогон с потолком 16384 умер на +36,1 с, НЕ напечатав ни одного ребра у потолка: до 16 352
 * заплат он не доживает. Значит смертельная заплата лежит в окне (8192, 16352), а печать
 * первых 64 до него не достаёт. MACRUNNER_HB_CHAIN_EDGE_FROM=N печатает ВСЕ рёбра начиная с
 * номера N — с N=8192 в журнал попадает ровно то окно, где прогон переходит от живого к
 * мёртвому (8192 — последний потолок, который выживает). 0 = выключено, поведение прежнее. */
/* MacRunner 2026-08-18 — НЕ сцеплять с заглушкой таблицы импорта.
 *
 * Итерация 2447 измерила: на момент смерти установлено 12 914 заплат, и приёмник последней
 * начинается байтами `ff 25 62 6b 08 00` с заполнителем `cc cc` следом — это `JMP [RIP+disp]`,
 * то есть переходник импорта. Зашивать прямой переход в такой блок опасно: адрес за ним правит
 * загрузчик (отложенное связывание, перенаправление ARM64EC), а сцепление снимает возврат в
 * диспетчер, который эту правку и подхватывал.
 *
 * 04.09.2026: приём стал БЕЗУСЛОВНЫМ, переменная снята — разбор у самого места применения.
 */
/* ★ 04.09.2026 — СПРАШИВАЕМ АРЕНУ, А НЕ НЮХАЕМ БАЙТЫ.
 *
 * Первая редакция распознавала переходник по двум байтам `ff 25` (JMP [RIP+disp32]).
 * Это узор ПЕ-шной заглушки импорта, и для неё он верен. Но у нас есть ВТОРОЙ род
 * переходников — своя арена (`HB_IMPORT_THUNK_BASE`, шаг `HB_IMPORT_THUNK_STRIDE`),
 * куда загрузчик направляет динамически разрешаемые импорты; её элементы никаким
 * `ff 25` не начинаются, и узор их не видел.
 *
 * Замер 04.09 на Hollow Knight: со сцеплением x64 прогон ВИСНЕТ ровно на строках
 * `dynamic-import-target: KERNEL32.dll!EnterCriticalSection guest=0x6f0000003e30`,
 * и 0x6f0000003e30 — это элемент 995 нашей арены. Узор его пропускал, ребро
 * сшивалось, возврат в диспетчер исчезал, а вместе с ним и подхват правки,
 * которую загрузчик пишет за переходником.
 *
 * Проверка диапазона ТОЧНА и не требует чтения памяти гостя: адрес принадлежит
 * арене или нет. Байтовый узор оставлен вторым, для ПЕ-шных заглушек — это
 * разные роды переходников, и один другого не заменяет. */
/* ★ 04.09.2026 — РОД ПЕРЕХОДНИКА НАЗЫВАЕТСЯ, А НЕ СУММИРУЕТСЯ.
 *
 * Два рода лежали под одним ответом `true`, и запрет был у них общий — а причины
 * РАЗНЫЕ, и лечатся они по-разному (разбор у места применения). Пока ответ один,
 * «сколько отказов какого рода» посчитать нечем, и решать, что с ними делать,
 * приходится вслепую. */
enum { HB_THUNK_NONE = 0, HB_THUNK_ARENA, HB_THUNK_PE_FF25 };

static int chain_target_thunk_kind(hb_jit_runtime_t* rt, uint64_t addr) {
    uint8_t b0 = 0, b1 = 0;

    if (addr >= HB_IMPORT_THUNK_BASE &&
        addr <  HB_IMPORT_THUNK_BASE + (uint64_t)HB_IMPORT_THUNK_MAX * HB_IMPORT_THUNK_STRIDE)
        return HB_THUNK_ARENA;

    if (!rt || !rt->ctx || !rt->ctx->memory) return HB_THUNK_NONE;
    if (hb_memory_read_u8(rt->ctx->memory, (hb_gva_t)addr, &b0) != HB_OK) return HB_THUNK_NONE;
    if (hb_memory_read_u8(rt->ctx->memory, (hb_gva_t)(addr + 1), &b1) != HB_OK) return HB_THUNK_NONE;
    /* JMP [RIP+disp32] — заглушка импорта в самом PE */
    return (b0 == 0xff && b1 == 0x25) ? HB_THUNK_PE_FF25 : HB_THUNK_NONE;
}

static bool chain_target_is_import_thunk(hb_jit_runtime_t* rt, uint64_t addr) {
    return chain_target_thunk_kind(rt, addr) != HB_THUNK_NONE;
}

/* ★ 05.09.2026 — ЗАПРЕТ СЦЕПЛЕНИЯ ПО ЗАВЕРШИТЕЛЮ-ВЫЗОВУ СНЯТ (леса разобраны).
 *
 * Ручка MACRUNNER_HB_CHAIN_CALL_TERM заводилась 04.09 как лечение клина x64: с
 * запретом прогон гиб на переходнике импорта, без запрета — на `reason=runtime
 * pc=0x87ef31b9a30`. Настоящая причина того клина названа и вылечена 05.09 в корне
 * (прямая единица не объявляла свой выход, цель ребра исполнялась дважды —
 * reports/сцепление/i8const-ПОЧИНЕНО-05.09.2026.md), и довод запрета держался на уже
 * устранённом дефекте. Перепись рёбер HK: запрет отвергал 9,0 млн из 20,8 млн
 * обращений к сшивке.
 *
 * ЗАМЕР 05.09 на одном двоичном файле (9f6a9234391c), руки вразбивку, своё хранилище
 * перевода на руку, мера — секунды от строки движка до вехи swapchain, Hollow Knight:
 *     CT1 (запрет): 124,3 117,6 128,2 с — медиана 124,3, разброс 10,6 с (8,49 %); CT0 (снят): 116,6 117,4 120,1 — медиана 117,4, разброс 3,5 с (2,98 %). По парам +7,7 / +0,2 / +8,1 с в пользу снятия, прогревы 122,1 против 117,8; веха 8/8, i8const 0/8, c0000005 0/8. Ни в одной паре запрет не помог.
 * Запрет ничего не давал, ребро из блока с CALL сшивается как любое другое.
 * Отчёт: reports/сцепление/ГЕЙТ-x64-СНЯТ-05.09.2026.md.
 *
 * ИСТОРИЯ, которую снятие ручки НЕ отменяет (замер 04.09, по два прогона на руку,
 * тройка (reason, pc, last_block) из `macrunner-hb-run-exit`, дист со сверенным отпечатком):
 *   CALL_TERM=1 (запрет): reason=import-thunk pc=0x6f0000003c60 last_block=0x87ef31c0c07 blocks≈0x2a0d5
 *   CALL_TERM=0 (снят):   reason=runtime      pc=0x87ef31b9a30 last_block=0x87ef31badb6 blocks≈0xaa8d
 * Тройки разошлись, вторая совпала байт в байт с ребром `cur=0x87ef31badb6 ->
 * next=0x87ef31b9a30` из разбора у места применения: запрет ПЕРЕНОСИЛ место отказа,
 * то есть брал настоящий класс рёбер — но лечил следствие (см. выше, корень вылечен).
 *
 * ✗ ОТОЗВАНО (04.09), РУКА «ГРАНИЦА ФУНКЦИИ». Опыт «отвергать ребро, у которого
 * источник и приёмник в РАЗНЫХ функциях» на ветви x64 ПОСТАВИТЬ НЕЛЬЗЯ, и это показал
 * сам прибор: у гостя x64 каждая поднятая функция состоит из ОДНОГО блока
 * (`macrunner-hb-findblock: max_block_count=1` на 637 450 обращений — внешний цикл
 * зовёт `macrunner_hb_lift_one_block`). Перепись рёбер: из 264 246 попыток сшивки ОБА
 * конца лежат в CFG текущей функции у 228 (0,086 %), и это самопетли. Значит запрет по
 * границе — это «сцепление выключить», а не опыт о границе. Вместе с этим закрыто и
 * подозрение на `rt->cur_func_addr`: на x64 оно описывает ОДИН БЛОК, а не функцию. */

static uint64_t chain_edge_from(void) {
    static int parsed;
    static uint64_t from;
    if (!parsed) {
        const char* env = hb_gate( HB_GATE_HB_CHAIN_EDGE_FROM );
        from = env && *env ? strtoull(env, NULL, 0) : 0ull;
        parsed = 1;
    }
    return from;
}

static int trace_chain_edge_enabled(void) {
    return runtime_gate_flag( HB_GATE_HB_TRACE_CHAIN_EDGE, 0);
}

/* MacRunner 2026-07-30 — log edges NEAR one guest address instead of just the first 64.
 *
 * The fault is deterministic at guest pc 0x87ef2469a30 (mono-2.0-bdwgc.dll+0x69a30, entered with garbage
 * rcx/rdx identical across three runs), but with ~11 000 tails patched a first-64 cap never reaches that
 * region, so "is the faulting block reached by a chain" stayed unanswerable. MACRUNNER_HB_CHAIN_EDGE_NEAR
 * takes that guest address and logs every edge whose predecessor or successor lies within +-64 KB of it.
 * Observation only — it decides whether the chain even touches the block that dies, which five mechanism
 * guesses could not. */
/* MacRunner 2026-08-01 — WARM-UP GATE: дифференциал ВНУТРИ одного прогона.
 *
 * Межпроцессное сравнение (сцепление вкл против выкл, два запуска) ответа дать не может: два
 * процесса получают разные базы выделения. Замер: 137638 расхождений на 23774 сопоставленных пары,
 * из них 70 % — это оба значения указатели с разницей, кратной 0x10000, то есть сдвиг базы; и в
 * сцепленной руке 8228 различных блоков против 1409 в контрольной, то есть сами исполнения
 * разошлись. Отделить порчу от недетерминизма так нельзя.
 *
 * Двойное исполнение блока тоже не годится: запись в память произошла бы дважды.
 *
 * Поэтому: не патчить НИ ОДНОЙ цепочки, пока не пройдено N диспетчеризаций. В одном процессе, при
 * одних базах, потоках и таймингах, у каждого блока появляются записи ДО включения (эталон) и
 * ПОСЛЕ (проверяемое). Значение, которого нет в эталонной популяции ТОГО ЖЕ блока, сдвигом базы
 * уже не объясняется.
 *
 * 0 = выключено: сцеплять сразу, прежнее поведение. */
static uint64_t g_dispatch_ticks;

static uint64_t runtime_chain_after_n(void) {
    static int parsed;
    static uint64_t n;
    if (!parsed) {
        const char* env = hb_gate( HB_GATE_HB_CHAIN_AFTER_N );
        n = (env && *env) ? strtoull(env, NULL, 0) : 0;
        parsed = 1;
    }
    return n;
}

static int chain_warmup_passed(void) {
    uint64_t n = runtime_chain_after_n();
    if (!n) return 1;
    return __atomic_load_n(&g_dispatch_ticks, __ATOMIC_RELAXED) >= n;
}

static uint64_t runtime_chain_edge_near(void) {
    static int parsed;
    static uint64_t addr;
    if (!parsed) {
        const char* env = hb_gate( HB_GATE_HB_CHAIN_EDGE_NEAR );
        addr = (env && *env) ? strtoull(env, NULL, 0) : 0;
        parsed = 1;
    }
    return addr;
}

/* Refuse to chain exactly the edges the near-filter selects. If the fault then vanishes, the defect belongs
 * to this block pair; if it merely relocates to another chained edge, the defect is general to chaining. */
static int runtime_chain_refuse_near(void) {
    return runtime_gate_flag( HB_GATE_HB_CHAIN_REFUSE_NEAR, 0);
}

static int chain_edge_is_near(uint64_t a, uint64_t b) {
    uint64_t c = runtime_chain_edge_near();
    if (!c) return 0;
    return (a > c ? a - c : c - a) <= 0x10000ull || (b > c ? b - c : c - b) <= 0x10000ull;
}

/* ★★★ 04.09.2026 — ПРИБОР «ГОСТЕВЫЕ СЛОВА В ТОЧКЕ ГОСТЯ» (slotprobe).
 *
 * ЗАЧЕМ. Mono роняет себя утверждением `(code - cfg->native_code - offset) <= max_len`:
 * насчитано 14 при ВЫПУЩЕННЫХ 10 (доказано разбором двоичного файла и курсором в rcx).
 * Значит уехало одно из ТРЁХ гостевых значений, и назвать его регистрами нельзя — они
 * живут в памяти гостя: `code` = [rsp+0x1228], `offset` = [rsp+0x37c],
 * `cfg->native_code` = [[rsp+0x1590]+0x278]. Печати гостевых СЛОВ у нас не было вовсе.
 *
 * ПОЧЕМУ НЕ ПРОСТО «напечатать три слова на ребре». Три числа без опоры не называют
 * виновного: нужен эталон. Опора здесь ВНУТРИ одного прогона и не требует второго
 * процесса: в голове цикла Mono сам кладёт `offset = code - native_code`, то есть в
 * точке разбора switch тождество `s0 - s2 - s1 == 0` обязано выполняться. Поэтому
 * прибор снимает те же слова в НЕСКОЛЬКИХ точках гостя, а не в одной.
 *
 * ПОЧЕМУ КОЛЬЦО. Точки головы цикла горячие (десятки тысяч проходов), а нужна одна —
 * смертельная. Гейт DUMP_AT называет адрес-спусковой крючок (у Mono это ветвь ПРОВАЛА
 * утверждения, куда управление приходит РОВНО ОДИН РАЗ), и в этот миг печатаются
 * последние N снимков. Объём печати ограничен кольцом, а не удачей.
 *
 * ГЕЙТЫ (движок ничего не знает про Mono, адреса задаются снаружи):
 *   MACRUNNER_HB_CHAIN_PROBE_SLOTS  = "rsp+0x1228:8,rsp+0x37c:4,[rsp+0x1590]+0x278:8,rsp+0x380:4"
 *   MACRUNNER_HB_CHAIN_PROBE_AT     = "0x87ef358075a,0x87ef35ba6a7"   (где снимать)
 *   MACRUNNER_HB_CHAIN_PROBE_DUMP_AT= "0x87ef3611f02"                 (где вывалить кольцо)
 *   MACRUNNER_HB_CHAIN_PROBE_RING   = 64                              (глубина кольца)
 * Без DUMP_AT каждый снимок печатается сразу.
 *
 * Грамматика слота:  (rsp|<абс>)[+|-<смещ>]:<4|8>   либо   [(rsp|<абс>)+<смещ>]+<смещ>:<4|8>
 */
#define HB_SLOTPROBE_SLOTS_MAX 8
#define HB_SLOTPROBE_PCS_MAX   8
#define HB_SLOTPROBE_RING_MAX  1024

typedef struct {
    int      indirect;   /* [база+off1] + off2 */
    int      rsp_base;   /* 1 — база гостевой rsp, 0 — абсолютный адрес */
    int64_t  off1;
    int64_t  off2;
    int      width;      /* 4 или 8 */
} hb_slotprobe_spec_t;

typedef struct {
    uint64_t n, pc, rsp;
    uint64_t v[HB_SLOTPROBE_SLOTS_MAX];
    unsigned char ok[HB_SLOTPROBE_SLOTS_MAX];
} hb_slotprobe_rec_t;

static hb_slotprobe_spec_t g_slotprobe_spec[HB_SLOTPROBE_SLOTS_MAX];
static unsigned            g_slotprobe_nspec;
static uint64_t            g_slotprobe_pc[HB_SLOTPROBE_PCS_MAX];
static unsigned            g_slotprobe_npc;
static uint64_t            g_slotprobe_dump_pc;
static unsigned            g_slotprobe_ring_n = 64;
/* 0 — ещё не разбирали, 1 — выключен (быстрый путь), 2 — включён */
static int                 g_slotprobe_state;

static const char* slotprobe_skip_sp(const char* p) { while (*p == ' ' || *p == '\t') p++; return p; }

/* «rsp+0x10» / «0x1234» / «rsp» — возвращает 0 при разборе впустую */
static int slotprobe_parse_addr(const char* p, const char** endp, int* rsp_base, int64_t* off) {
    char* e = NULL;
    int64_t v = 0;
    p = slotprobe_skip_sp(p);
    if (strncmp(p, "rsp", 3) == 0) { *rsp_base = 1; p += 3; }
    else                           { *rsp_base = 0; }
    p = slotprobe_skip_sp(p);
    if (*p == '+' || *p == '-') {
        int neg = (*p == '-');
        p++;
        p = slotprobe_skip_sp(p);
        v = (int64_t)strtoull(p, &e, 0);
        if (e == p) return 0;
        if (neg) v = -v;
        p = e;
    } else if (!*rsp_base) {
        v = (int64_t)strtoull(p, &e, 0);
        if (e == p) return 0;
        p = e;
    }
    *off = v;
    *endp = p;
    return 1;
}

static int slotprobe_parse_item(const char* p, hb_slotprobe_spec_t* sp) {
    char* e = NULL;
    long w;
    memset(sp, 0, sizeof *sp);
    p = slotprobe_skip_sp(p);
    if (*p == '[') {
        sp->indirect = 1;
        p++;
        if (!slotprobe_parse_addr(p, &p, &sp->rsp_base, &sp->off1)) return 0;
        p = slotprobe_skip_sp(p);
        if (*p != ']') return 0;
        p++;
        p = slotprobe_skip_sp(p);
        if (*p == '+' || *p == '-') {
            int neg = (*p == '-');
            p++;
            p = slotprobe_skip_sp(p);
            sp->off2 = (int64_t)strtoull(p, &e, 0);
            if (e == p) return 0;
            if (neg) sp->off2 = -sp->off2;
            p = e;
        }
    } else {
        if (!slotprobe_parse_addr(p, &p, &sp->rsp_base, &sp->off1)) return 0;
    }
    p = slotprobe_skip_sp(p);
    if (*p != ':') return 0;
    p++;
    w = strtol(p, &e, 0);
    if (e == p || (w != 4 && w != 8)) return 0;
    sp->width = (int)w;
    return 1;
}

/* Разбор списков через запятую. При негодном элементе ОТКАЗЫВАЕТ ВСЛУХ, а не молча
 * пропускает: «прибор молчит» и «явления нет» различать надо, это записанное правило. */
static void slotprobe_init(void) {
    const char* s = hb_gate( HB_GATE_HB_CHAIN_PROBE_SLOTS );
    const char* at = hb_gate( HB_GATE_HB_CHAIN_PROBE_AT );
    const char* dump = hb_gate( HB_GATE_HB_CHAIN_PROBE_DUMP_AT );
    const char* ring = hb_gate( HB_GATE_HB_CHAIN_PROBE_RING );
    char buf[512];
    char* tok;
    char* save = NULL;

    g_slotprobe_nspec = 0;
    g_slotprobe_npc = 0;
    g_slotprobe_dump_pc = 0;

    if (!s || !*s) { __atomic_store_n(&g_slotprobe_state, 1, __ATOMIC_RELEASE); return; }

    snprintf(buf, sizeof buf, "%s", s);
    for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        hb_slotprobe_spec_t sp;
        if (g_slotprobe_nspec >= HB_SLOTPROBE_SLOTS_MAX) break;
        if (!slotprobe_parse_item(tok, &sp)) {
            fprintf(stderr, "macrunner-hb-slotprobe-OTKAZ: ne razobran slot <%s>\n", tok);
            fflush(stderr);
            continue;
        }
        g_slotprobe_spec[g_slotprobe_nspec++] = sp;
    }
    if (!g_slotprobe_nspec) {
        fprintf(stderr, "macrunner-hb-slotprobe-OTKAZ: ni odnogo godnogo slota, pribor VYKLYUCHEN\n");
        fflush(stderr);
        __atomic_store_n(&g_slotprobe_state, 1, __ATOMIC_RELEASE);
        return;
    }

    if (at && *at) {
        save = NULL;
        snprintf(buf, sizeof buf, "%s", at);
        for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
            if (g_slotprobe_npc >= HB_SLOTPROBE_PCS_MAX) break;
            g_slotprobe_pc[g_slotprobe_npc++] = strtoull(slotprobe_skip_sp(tok), NULL, 0);
        }
    }
    if (dump && *dump) g_slotprobe_dump_pc = strtoull(dump, NULL, 0);
    if (ring && *ring) {
        unsigned long r = strtoul(ring, NULL, 0);
        if (r >= 1 && r <= HB_SLOTPROBE_RING_MAX) g_slotprobe_ring_n = (unsigned)r;
    }
    if (!g_slotprobe_npc && !g_slotprobe_dump_pc) {
        fprintf(stderr, "macrunner-hb-slotprobe-OTKAZ: ne zadano NI ODNOJ tochki (AT/DUMP_AT)\n");
        fflush(stderr);
        __atomic_store_n(&g_slotprobe_state, 1, __ATOMIC_RELEASE);
        return;
    }
    fprintf(stderr, "macrunner-hb-slotprobe-GOTOV: slotov=%u tochek=%u vyval=0x%llx kolco=%u\n",
            g_slotprobe_nspec, g_slotprobe_npc,
            (unsigned long long)g_slotprobe_dump_pc, g_slotprobe_ring_n);
    fflush(stderr);
    __atomic_store_n(&g_slotprobe_state, 2, __ATOMIC_RELEASE);
}

static void slotprobe_print(const hb_slotprobe_rec_t* r, const char* tag, unsigned k) {
    unsigned i;
    fprintf(stderr, "macrunner-hb-slotprobe:%s k=%u n=%llu pc=0x%llx rsp=0x%llx",
            tag, k, (unsigned long long)r->n, (unsigned long long)r->pc,
            (unsigned long long)r->rsp);
    for (i = 0; i < g_slotprobe_nspec; i++) {
        if (r->ok[i]) fprintf(stderr, " s%u=0x%llx", i, (unsigned long long)r->v[i]);
        else          fprintf(stderr, " s%u=NECHITAEM", i);
    }
    fprintf(stderr, "\n");
}

static __thread hb_slotprobe_rec_t* t_slotprobe_ring;
static __thread unsigned            t_slotprobe_head;    /* куда писать следующий */
static __thread uint64_t            t_slotprobe_seen;    /* всего снимков в потоке */
static __thread unsigned            t_slotprobe_dumps;

static void chain_slot_probe(hb_context_t* ctx) {
    hb_slotprobe_rec_t rec;
    unsigned i;
    int is_dump, is_at = 0;
    uint64_t pc;

    if (__builtin_expect(__atomic_load_n(&g_slotprobe_state, __ATOMIC_ACQUIRE) != 2, 1)) {
        if (__atomic_load_n(&g_slotprobe_state, __ATOMIC_ACQUIRE) == 0) slotprobe_init();
        if (__atomic_load_n(&g_slotprobe_state, __ATOMIC_ACQUIRE) != 2) return;
    }
    if (!ctx || ctx->mode != HB_MODE_64BIT) return;

    pc = ctx->pc;
    is_dump = (g_slotprobe_dump_pc != 0 && pc == g_slotprobe_dump_pc);
    for (i = 0; i < g_slotprobe_npc; i++)
        if (pc == g_slotprobe_pc[i]) { is_at = 1; break; }
    if (!is_at && !is_dump) return;

    memset(&rec, 0, sizeof rec);
    rec.n = ++t_slotprobe_seen;
    rec.pc = pc;
    rec.rsp = ctx->regs.x64.rsp;
    for (i = 0; i < g_slotprobe_nspec; i++) {
        const hb_slotprobe_spec_t* sp = &g_slotprobe_spec[i];
        uint64_t a = (sp->rsp_base ? rec.rsp : 0) + (uint64_t)sp->off1;
        uint64_t v = 0;
        if (sp->indirect) {
            uint64_t p = 0;
            if (hb_memory_read_u64(ctx->memory, (hb_gva_t)a, &p) != HB_OK) continue;
            a = p + (uint64_t)sp->off2;
        }
        if (sp->width == 8) {
            if (hb_memory_read_u64(ctx->memory, (hb_gva_t)a, &v) != HB_OK) continue;
        } else {
            uint32_t w = 0;
            if (hb_memory_read_u32(ctx->memory, (hb_gva_t)a, &w) != HB_OK) continue;
            v = w;
        }
        rec.v[i] = v;
        rec.ok[i] = 1;
    }

    if (!g_slotprobe_dump_pc) { slotprobe_print(&rec, "", 0); fflush(stderr); return; }

    if (!t_slotprobe_ring) {
        t_slotprobe_ring = (hb_slotprobe_rec_t*)calloc(g_slotprobe_ring_n, sizeof(hb_slotprobe_rec_t));
        if (!t_slotprobe_ring) { slotprobe_print(&rec, " BEZ-KOLCA", 0); fflush(stderr); return; }
    }
    t_slotprobe_ring[t_slotprobe_head] = rec;
    t_slotprobe_head = (t_slotprobe_head + 1) % g_slotprobe_ring_n;

    if (is_dump && t_slotprobe_dumps < 4) {
        unsigned k;
        t_slotprobe_dumps++;
        fprintf(stderr, "macrunner-hb-slotprobe-VYVAL: spuskovoj pc=0x%llx snimkov=%llu kolco=%u\n",
                (unsigned long long)pc, (unsigned long long)t_slotprobe_seen, g_slotprobe_ring_n);
        for (k = 0; k < g_slotprobe_ring_n; k++) {
            unsigned idx = (t_slotprobe_head + k) % g_slotprobe_ring_n;
            if (!t_slotprobe_ring[idx].n) continue;   /* кольцо ещё не заполнено */
            slotprobe_print(&t_slotprobe_ring[idx], " KOLCO", k);
        }
        fflush(stderr);
    }
}

static uint64_t g_chain_patches_installed;

/* Сколько раз цепочка вышла на ВХОДЕ прямой единицы (см. прибор ниже). */
static uint64_t g_chain_tail_repeat;

/* MacRunner 2026-08-18 — СЛЕД сцепленных гостевых адресов, чтобы падение можно было спросить.
 *
 * Одиннадцать прогонов зажали порог: больше ~11 000 переписанных хвостов — смерть на +34,2 с,
 * меньше — прогон живёт весь бюджет. Момент смерти НЕ двигается, значит решает состояние на
 * момент конкретного события, а не накопление само по себе. Прямой вопрос к этому событию —
 * «сцеплён ли блок, в котором произошло исключение», — до сих пор был недоступен: печать рёбер
 * даёт адреса, а базы образов гуляют от прогона к прогону, и сопоставить их не с чем.
 *
 * След — открытая адресация на 65 536 ячеек, восемь проб, без удаления. Промах возможен при
 * переполнении, поэтому вместе с ответом печатается и заполненность: «нет» при заполненном
 * следе читать нельзя. Гонки безвредны: две записи одного адреса дают тот же результат. */
#define HB_CHAIN_SEEN_SLOTS 65536u
static uint64_t g_chain_seen[HB_CHAIN_SEEN_SLOTS];
/* Приёмник ребра — в парном массиве, а не в структуре: одна запись остаётся 8-байтовой, значит
 * гонка двух потоков даёт либо старое, либо новое значение, но не половину каждого. Пара
 * «источник/приёмник» может при этом разъехаться на один такт; для вопроса «куда вела заплата
 * этого блока» это несущественно, а атомарной пары не нужно. */
static uint64_t g_chain_seen_next[HB_CHAIN_SEEN_SLOTS];
static uint64_t g_chain_seen_used;

static uint32_t chain_seen_slot(uint64_t addr) {
    uint64_t h = (addr ^ (addr >> 32)) * 0x9E3779B97F4A7C15ull;
    return (uint32_t)(h >> 40) & (HB_CHAIN_SEEN_SLOTS - 1);
}

static void chain_seen_add(uint64_t addr, uint64_t next) {
    uint32_t h = chain_seen_slot(addr), i;
    if (!addr) return;
    for (i = 0; i < 8; i++) {
        uint32_t k = (h + i) & (HB_CHAIN_SEEN_SLOTS - 1);
        uint64_t cur = __atomic_load_n(&g_chain_seen[k], __ATOMIC_RELAXED);
        if (cur == addr) {
            /* Хвост можно перенацелить (см. `meta->target_code` выше) — держим ПОСЛЕДНИЙ
             * приёмник, потому что именно по нему уходило управление в момент падения. */
            __atomic_store_n(&g_chain_seen_next[k], next, __ATOMIC_RELAXED);
            return;
        }
        if (!cur) {
            __atomic_store_n(&g_chain_seen_next[k], next, __ATOMIC_RELAXED);
            __atomic_store_n(&g_chain_seen[k], addr, __ATOMIC_RELAXED);
            __atomic_add_fetch(&g_chain_seen_used, 1, __ATOMIC_RELAXED);
            return;
        }
    }
}

unsigned long long macrunner_hb_chain_target_of(unsigned long long addr) {
    uint32_t h = chain_seen_slot((uint64_t)addr), i;
    if (!addr) return 0ull;
    for (i = 0; i < 8; i++) {
        uint32_t k = (h + i) & (HB_CHAIN_SEEN_SLOTS - 1);
        uint64_t cur = __atomic_load_n(&g_chain_seen[k], __ATOMIC_RELAXED);
        if (cur == (uint64_t)addr)
            return (unsigned long long)__atomic_load_n(&g_chain_seen_next[k], __ATOMIC_RELAXED);
        if (!cur) return 0ull;
    }
    return 0ull;
}

int macrunner_hb_chain_addr_was_patched(unsigned long long addr) {
    uint32_t h = chain_seen_slot((uint64_t)addr), i;
    if (!addr) return 0;
    for (i = 0; i < 8; i++) {
        uint32_t k = (h + i) & (HB_CHAIN_SEEN_SLOTS - 1);
        uint64_t cur = __atomic_load_n(&g_chain_seen[k], __ATOMIC_RELAXED);
        if (cur == (uint64_t)addr) return 1;
        if (!cur) return 0;
    }
    return 0;
}

unsigned long long macrunner_hb_chain_patches_installed(void) {
    return (unsigned long long)__atomic_load_n(&g_chain_patches_installed, __ATOMIC_RELAXED);
}

unsigned long long macrunner_hb_chain_seen_used(void) {
    return (unsigned long long)__atomic_load_n(&g_chain_seen_used, __ATOMIC_RELAXED);
}

/* MacRunner 2026-07-30 — observe the guest state ACROSS a chained transition, which is the one thing none
 * of the cap/kind arms could see.
 *
 * Established by bisection: no patch boots to Begin MonoManager, while 1, 8 and 11 458 patches all wedge,
 * and refusing self edges or backedges changes nothing. So the first chained transition is already fatal
 * and the question is no longer WHICH edge but WHAT it does. block_delta > 1 is exactly the signal that a
 * chain executed inside one native dispatch, so printing ctx->pc beside the predecessor's guest_addr there
 * separates the two remaining possibilities: a PC that is not a sane guest address means the trampoline is
 * corrupting control flow (and since the encodings are clang-verified byte for byte, that would point at the
 * native_code+12 entry contract or the frame, not the instruction bytes), while a sane PC means nothing is
 * corrupted and the loss is the per-dispatch host work a chained transition skips. */
static int chain_edge_is_near(uint64_t a, uint64_t b);

/* rax..r15: the 16 general-purpose guest registers, in hb_regs_x64_t order. */
#define HB_TRACE_GPR_N 16

static const char* const hb_trace_gpr_names[HB_TRACE_GPR_N] = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"
};

static void trace_chain_transition(const hb_context_t* ctx, const hb_block_cache_entry_t* cur,
                                   uint64_t block_delta, uint64_t step_delta,
                                   uint64_t before_rcx, uint64_t before_rdx,
                                   uint64_t before_rbp, uint64_t before_rsp,
                                   const uint64_t* before_gpr) {
    static uint64_t shown;
    int near;
    if (!trace_chain_edge_enabled() || !ctx || !cur) return;

    /* MacRunner 2026-07-31 — the failure dump says the corrupted register is RBP, not rcx/rdx.
     * A chaining run dies at +50.9 s with `rbp=0x8` at mono-2.0-bdwgc.dll rva 0x6adc2, and that dump appears
     * 0x in the baseline and lean-frame controls, so it belongs to chaining. This alert is deliberately NOT
     * subject to the 32-line cap below: the cap is why the first 32 transitions all looked clean while the
     * one that matters was never printed. */
    if (before_rbp >= 0x10000 && ctx->regs.x64.rbp < 0x10000) {
        /* The "v2" tag settles a contradiction by evidence instead of by argument: GPRDIFF sits in
         * this same branch, is present in the deployed .so, and printed 0 times while this line
         * printed 7233. That is impossible if the running binary is the deployed one -- so tag the
         * line that DOES print. A log carrying the untagged text proves the loaded module is not
         * the one being deployed, and no further reasoning about the code is worth anything until
         * that is settled. */
        fprintf(stderr, "macrunner-hb-chain-RBP-VIOLATION-v2: from=0x%llx pc_after=0x%llx blocks=%llu steps=%llu "
                        "rbp %llx->%llx rsp %llx->%llx rcx %llx->%llx\n",
                (unsigned long long)cur->guest_addr, (unsigned long long)ctx->pc,
                (unsigned long long)block_delta, (unsigned long long)step_delta,
                (unsigned long long)before_rbp, (unsigned long long)ctx->regs.x64.rbp,
                (unsigned long long)before_rsp, (unsigned long long)ctx->regs.x64.rsp,
                (unsigned long long)before_rcx, (unsigned long long)ctx->regs.x64.rcx);
        /* WHICH registers the transition loses, not just the three an earlier hypothesis named.
         * The point of the classification is that it discriminates between two causes that the
         * rbp-only print could not tell apart: a wholesale wipe of the context (a memset, a restore
         * from a zeroed pre-image) would zero EVERY register, while a specific store path would
         * zero a small, repeatable subset. Printing survivors as well as casualties is what makes
         * that readable -- "5 of 16 zeroed" is evidence, "rbp went to 0" is an anecdote. */
        if (before_gpr) {
            const uint64_t* after = &ctx->regs.x64.rax;
            unsigned zeroed = 0, changed = 0, i;
            fprintf(stderr, "macrunner-hb-chain-GPRDIFF: from=0x%llx",
                    (unsigned long long)cur->guest_addr);
            for (i = 0; i < HB_TRACE_GPR_N; i++) {
                if (before_gpr[i] == after[i]) continue;
                changed++;
                if (after[i] == 0 && before_gpr[i] != 0) zeroed++;
                fprintf(stderr, " %s=%llx->%llx", hb_trace_gpr_names[i],
                        (unsigned long long)before_gpr[i], (unsigned long long)after[i]);
            }
            fprintf(stderr, " | changed=%u zeroed=%u of %u\n", changed, zeroed,
                    (unsigned)HB_TRACE_GPR_N);
        }
        fflush(stderr);
    }

    near = chain_edge_is_near(cur->guest_addr, ctx->pc);
    if (!near && __atomic_add_fetch(&shown, 1, __ATOMIC_RELAXED) > 32) return;
    /* rcx/rdx are the two registers that come back identically garbage in every failing run
     * (rcx=0xf0e0993f rdx=0x320eec31), so printing them either side of the chained run says whether the
     * chain corrupts them or inherits them already wrong. */
    fprintf(stderr, "macrunner-hb-chaintransit:%s from=0x%llx pc_after=0x%llx blocks=%llu steps=%llu "
                    "rcx %llx->%llx rdx %llx->%llx rbp %llx->%llx rsp %llx->%llx\n",
            near ? " NEAR" : "",
            (unsigned long long)cur->guest_addr, (unsigned long long)ctx->pc,
            (unsigned long long)block_delta, (unsigned long long)step_delta,
            (unsigned long long)before_rcx, (unsigned long long)ctx->regs.x64.rcx,
            (unsigned long long)before_rdx, (unsigned long long)ctx->regs.x64.rdx,
            (unsigned long long)before_rbp, (unsigned long long)ctx->regs.x64.rbp,
            (unsigned long long)before_rsp, (unsigned long long)ctx->regs.x64.rsp);
    fflush(stderr);
}

/* MacRunner 25.08.2026 — ВОЗВРАТ БЕЗ ВЫХОДА НАРУЖУ.
 * `RET` уходил из цикла исполнения ВСЕГДА: ветка ниже возвращала управление вызывающему
 * ещё до поиска блока возврата. Каждый возврат гостя стоил полного круга через хозяина,
 * тогда как `JMP`/`CALL` продолжали цикл по кешу блоков. Гейт держит и вторую половину
 * рычага — заполнение слота кеша косвенных для сайта `RET` (кодогенератор ставит туда
 * зонд под MACRUNNER_HB_INDIRECT_IC_RET). */
static int runtime_chain_direct_enabled(void) {
    return runtime_gate_flag( HB_GATE_HB_CHAIN_DIRECT, 0);
}

static int runtime_chain_two_slots_enabled(void) {
    return runtime_gate_flag( HB_GATE_HB_CHAIN_TWO_SLOTS, 0);
}

static int runtime_indirect_ic_ret_enabled(void) {
    return runtime_gate_flag( HB_GATE_HB_INDIRECT_IC_RET, 0);
}

static int runtime_indirect_ic_enabled(void) {
    return runtime_gate_flag( HB_GATE_HB_INDIRECT_IC, 0);
}

static int trace_dispatch_gate_enabled(void) {
    return runtime_gate_flag( HB_GATE_HB_TRACE_DISPATCH_GATE, 0);
}

static int runtime_direct_scalar_scan_enabled_for_key(void) {
    const char* val = hb_gate( HB_GATE_HB_JIT_DIRECT_SCALAR_SCAN );
    if (val && *val)
        return *val != '0';
    return runtime_env_enabled_default_on("MACRUNNER_HB_JIT_DIRECT_SCALAR_SCAN");
}

static int runtime_direct_scalar_mem_enabled_for_key(void) {
    const char* val = hb_gate( HB_GATE_HB_JIT_DIRECT_SCALAR_MEM );
    if (val && *val)
        return *val != '0';
    return runtime_env_enabled("MACRUNNER_HB_JIT_DIRECT_MEM");
}

static uint8_t runtime_jit_flags(void) {
    uint8_t flags = 0;
    if (runtime_env_enabled("MACRUNNER_HB_JIT_DIRECT_MEM"))
        flags |= HB_RUNTIME_PERSISTENT_CACHE_FLAG_DIRECT_MEM;
    if (runtime_env_enabled("MACRUNNER_HB_JIT_DIRECT_STACK"))
        flags |= HB_RUNTIME_PERSISTENT_CACHE_FLAG_DIRECT_STACK;
    if (runtime_direct_scalar_scan_enabled_for_key())
        flags |= HB_RUNTIME_PERSISTENT_CACHE_FLAG_DIRECT_SCALAR_SCAN;
    if (runtime_direct_scalar_mem_enabled_for_key())
        flags |= HB_RUNTIME_PERSISTENT_CACHE_FLAG_DIRECT_SCALAR_MEM;
    if (runtime_block_chain_enabled())
        flags |= HB_RUNTIME_PERSISTENT_CACHE_FLAG_BLOCK_CHAIN;
    if (runtime_indirect_ic_enabled())
        flags |= HB_RUNTIME_PERSISTENT_CACHE_FLAG_INDIRECT_IC;
    if (runtime_env_enabled("MACRUNNER_HB_NATIVE_MEMMOVE"))
        flags |= HB_RUNTIME_PERSISTENT_CACHE_FLAG_NATIVE_MEMMOVE;
    return flags;
}

static uint8_t macrunner_hb_runtime_persistent_cache_flags;

void hb_runtime_init_environment(void) {
    macrunner_hb_runtime_persistent_cache_flags = runtime_jit_flags();
}

static bool native_blob_has_helper_call(const uint8_t* code, size_t size) {
    if (!code) return true;
    for (size_t i = 0; i + sizeof(uint32_t) <= size; i += sizeof(uint32_t)) {
        uint32_t insn;
        memcpy(&insn, code + i, sizeof(insn));
        if ((insn & 0xfffffc1fu) == 0xd63f0000u) return true; /* BLR Xn */
    }
    return false;
}

/* Declarations for the 24 helpers registered below; they live in hb_arm64_codegen.c. */
extern void     hb_jit_helper_adjust_stack(hb_context_t* ctx, uint64_t delta);
extern void     hb_jit_helper_cpuid(hb_context_t* ctx);
extern uint64_t hb_jit_helper_eval_cond_lazy(hb_context_t* ctx, uint64_t cc);
extern void     hb_jit_helper_exec_atomic_ir(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern uint64_t hb_jit_helper_exec_binop_lazy(hb_context_t* ctx, uint64_t op, uint64_t dst_reg,
                                              uint64_t src1_reg, uint64_t src2_is_reg,
                                              uint64_t src2_value, uint64_t size);
extern void     hb_jit_helper_exec_cmovcc_lazy(hb_context_t* ctx, uint64_t cc,
                                               uint64_t dst_reg, uint64_t src_is_reg,
                                               uint64_t src_value, uint64_t size);
extern void     hb_jit_helper_exec_cmovcc_operand_lazy(hb_context_t* ctx, uint64_t cc, const hb_ir_instr_t* instr);
extern void     hb_jit_helper_exec_four_block_loop(hb_context_t* ctx,
                                                   const hb_ir_block_t* first,
                                                   const hb_ir_block_t* second,
                                                   const hb_ir_block_t* third,
                                                   const hb_ir_block_t* fourth);
extern void     hb_jit_helper_exec_i32_less_tiebreaker(hb_context_t* ctx,
                                                       const hb_ir_block_t* entry,
                                                       const hb_ir_block_t* equal,
                                                       const hb_ir_block_t* less);
extern void hb_jit_helper_exec_popf_ir(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void hb_jit_helper_exec_pushf_ir(hb_context_t* ctx, const hb_ir_instr_t* instr);
extern void     hb_jit_helper_exec_setcc_lazy(hb_context_t* ctx, uint64_t cc,
                                              uint64_t dst_reg);
extern void     hb_jit_helper_exec_setcc_operand_lazy(hb_context_t* ctx, uint64_t cc, const hb_ir_instr_t* instr);
extern void     hb_jit_helper_exec_two_block_loop(hb_context_t* ctx,
                                                  const hb_ir_block_t* first,
                                                  const hb_ir_block_t* second);
extern void     hb_jit_helper_exec_unity_sort_inner_loop(hb_context_t* ctx,
                                                         const hb_ir_block_t* sort);
extern void     hb_jit_helper_lahf(hb_context_t* ctx);
extern void     hb_jit_helper_load_to_reg_sized(hb_context_t* ctx, uint64_t addr,
                                                 uint64_t dst_reg, uint64_t dst_size,
                                                 uint64_t dst_reg_offset);
extern uint64_t hb_jit_helper_load_u64(hb_context_t* ctx, uint64_t addr);
extern uint64_t hb_jit_helper_pop(hb_context_t* ctx);
extern void     hb_jit_helper_push(hb_context_t* ctx, uint64_t val);
extern void     hb_jit_helper_sahf(hb_context_t* ctx);
extern void     hb_jit_helper_store_sized(hb_context_t* ctx, uint64_t addr,
                                          uint64_t val, uint64_t size);
extern void     hb_jit_helper_store_u128(hb_context_t* ctx, uint64_t addr,
                                         uint64_t lo, uint64_t hi);
extern void     hb_jit_helper_xgetbv(hb_context_t* ctx);

static void* helper_addr_for_cache_id(uint8_t id) {
    switch (id) {
        case 1: return (void*)hb_jit_helper_exec_ir_block;
        case 2: return (void*)hb_jit_helper_exec_load_cmp_jcc_block;
        case 3: return (void*)hb_jit_helper_exec_cmp_setcc_ret_block;
        case 4: return (void*)hb_jit_helper_exec_unity_string_bsearch_loop;
        case 5: return (void*)hb_jit_helper_exec_unity_freelist_fill_loop;
        case 6: return (void*)hb_jit_helper_exec_unity_u32_ptr_compare;
        case 7: return (void*)hb_jit_helper_exec_mono_metadata_bsearch_loop;
        case 8: return (void*)hb_jit_helper_exec_mono_string_hash;
        case 9: return (void*)hb_jit_helper_exec_mono_string_equal;
        case 10: return (void*)hb_jit_helper_exec_mono_metadata_rowptr_entry;
        case 11: return (void*)hb_jit_helper_exec_mono_metadata_decode_row_loop;
        case 12: return (void*)hb_jit_helper_exec_mono_metadata_decode_row_entry;
        case 13: return (void*)hb_jit_helper_exec_mono_metadata_decode_col;
        case 14: return (void*)hb_jit_helper_exec_mono_metadata_coded_index_search;
        case 15: return (void*)hb_jit_helper_exec_interp_ir;
        case 16: return (void*)hb_jit_helper_exec_load_operand_lazy;
        case 17: return (void*)hb_jit_helper_exec_store_operand_lazy;
        case 18: return (void*)hb_jit_helper_exec_call_operand;
        case 19: return (void*)hb_jit_helper_exec_xfg_dispatch_call;
        case 20: return (void*)hb_jit_helper_exec_jmp_operand;
        case 21: return (void*)hb_jit_helper_exec_cmp_test_operand_lazy;
        case 22: return (void*)hb_jit_helper_exec_binop_operand_lazy;
        case 23: return (void*)hb_jit_helper_exec_mul_div_operand;
        case 24: return (void*)hb_jit_helper_exec_double_shift_operand;
        case 25: return (void*)hb_jit_helper_exec_extend_operand_lazy;
        case 26: return (void*)hb_jit_helper_exec_mov_operand_lazy;
        case 27: return (void*)hb_jit_helper_exec_not_operand_lazy;
        case 28: return (void*)hb_jit_helper_exec_neg_operand_lazy;
        case 29: return (void*)hb_jit_helper_exec_bit_scan;
        case 30: return (void*)hb_jit_helper_exec_loop_branch;
        case 31: return (void*)hb_jit_helper_try_native_memmove;
        /* MacRunner 2026-07-29: 24 helpers were emitted by codegen but absent here, so any
         * block calling one could not be persisted. Measured as the single largest cause of
         * declined stores — mh_unkhelper=3931, ahead of the x2/x3/x4 veto (2746) and the site
         * cap (573). Registering them is a far smaller change than the patcher work that
         * preceded it, and it was invisible until the rejection counters existed. */
        case 32: return (void*)hb_jit_helper_adjust_stack;
        case 33: return (void*)hb_jit_helper_cpuid;
        case 34: return (void*)hb_jit_helper_eval_cond_lazy;
        case 35: return (void*)hb_jit_helper_exec_atomic_ir;
        case 36: return (void*)hb_jit_helper_exec_binop_lazy;
        case 37: return (void*)hb_jit_helper_exec_cmovcc_lazy;
        case 38: return (void*)hb_jit_helper_exec_cmovcc_operand_lazy;
        case 39: return (void*)hb_jit_helper_exec_four_block_loop;
        case 40: return (void*)hb_jit_helper_exec_i32_less_tiebreaker;
        case 41: return (void*)hb_jit_helper_exec_popf_ir;
        case 42: return (void*)hb_jit_helper_exec_pushf_ir;
        case 43: return (void*)hb_jit_helper_exec_setcc_lazy;
        case 44: return (void*)hb_jit_helper_exec_setcc_operand_lazy;
        case 45: return (void*)hb_jit_helper_exec_two_block_loop;
        case 46: return (void*)hb_jit_helper_exec_unity_sort_inner_loop;
        case 47: return (void*)hb_jit_helper_lahf;
        case 48: return (void*)hb_jit_helper_load_to_reg_sized;
        case 49: return (void*)hb_jit_helper_load_u64;
        case 50: return (void*)hb_jit_helper_pop;
        case 51: return (void*)hb_jit_helper_push;
        case 52: return (void*)hb_jit_helper_sahf;
        case 53: return (void*)hb_jit_helper_store_sized;
        case 54: return (void*)hb_jit_helper_store_u128;
        case 55: return (void*)hb_jit_helper_xgetbv;
        default: return NULL;
    }
}

static uint8_t helper_cache_id_for_addr(uint64_t addr) {
    for (uint8_t id = 1; id <= 55; id++) {
        if ((uintptr_t)helper_addr_for_cache_id(id) == (uintptr_t)addr) return id;
    }
    return 0;
}

unsigned hb_runtime_helper_id_for_addr(uint64_t addr) {
    return helper_cache_id_for_addr(addr);
}

void hb_runtime_fill_helper_table(void** table, unsigned slots) {
    if (!table) return;
    for (unsigned id = 1; id <= 55u && id < slots; id++)
        table[id] = helper_addr_for_cache_id((uint8_t)id);
}

static bool helper_cache_id_uses_instr_arg1(uint8_t id) {
    return id >= 15 && id <= 30;
}

static bool arm64_mov_imm64_at(const uint8_t* code, size_t size, size_t off,
                               int rd, uint64_t* value) {
    uint32_t insn[4];
    uint64_t v;
    if (!code || off + sizeof(insn) > size || rd < 0 || rd > 31) return false;
    memcpy(&insn[0], code + off, 4);
    memcpy(&insn[1], code + off + 4, 4);
    memcpy(&insn[2], code + off + 8, 4);
    memcpy(&insn[3], code + off + 12, 4);
    if ((insn[0] & 0xffe0001fu) != (0xd2800000u | (uint32_t)rd) ||
        (insn[1] & 0xffe0001fu) != (0xf2a00000u | (uint32_t)rd) ||
        (insn[2] & 0xffe0001fu) != (0xf2c00000u | (uint32_t)rd) ||
        (insn[3] & 0xffe0001fu) != (0xf2e00000u | (uint32_t)rd))
        return false;
    v = ((uint64_t)((insn[0] >> 5) & 0xffffu)) |
        ((uint64_t)((insn[1] >> 5) & 0xffffu) << 16) |
        ((uint64_t)((insn[2] >> 5) & 0xffffu) << 32) |
        ((uint64_t)((insn[3] >> 5) & 0xffffu) << 48);
    if (value) *value = v;
    return true;
}

static void arm64_patch_mov_imm64_at(uint8_t* code, size_t size, size_t off,
                                     int rd, uint64_t value) {
    uint32_t insn[4];
    if (!code || off + sizeof(insn) > size || rd < 0 || rd > 31) return;
    insn[0] = 0xd2800000u | (uint32_t)(((value >> 0) & 0xffffu) << 5) | (uint32_t)rd;
    insn[1] = 0xf2a00000u | (uint32_t)(((value >> 16) & 0xffffu) << 5) | (uint32_t)rd;
    insn[2] = 0xf2c00000u | (uint32_t)(((value >> 32) & 0xffffu) << 5) | (uint32_t)rd;
    insn[3] = 0xf2e00000u | (uint32_t)(((value >> 48) & 0xffffu) << 5) | (uint32_t)rd;
    memcpy(code + off, &insn[0], 4);
    memcpy(code + off + 4, &insn[1], 4);
    memcpy(code + off + 8, &insn[2], 4);
    memcpy(code + off + 12, &insn[3], 4);
}

/* MacRunner 2026-07-29: count `blr x23` sites — helper calls — in emitted code.
 *
 * native_blob_single_arg_helper_stub() below bails on the SECOND one, so a block with two
 * helper calls can never be persisted. On HK that restriction shows up as stores=117 against
 * store_skips=40495: the persistent cache retains 0.3 % of what it compiles, and a cold start
 * therefore needs 476 s to reach the menu where Rosetta needs under 45 s. This exists purely to
 * attribute the skips, so the decision to generalise the patcher rests on a number rather than
 * on the assumption that multi-helper blocks are the common case. */
static size_t native_blob_helper_call_count(const uint8_t* code, size_t size) {
    size_t count = 0;
    if (!code) return 0;
    for (size_t off = 0; off + 4 <= size; off += 4) {
        uint32_t insn;
        memcpy(&insn, code + off, sizeof(insn));
        if (insn == (0xd63f0000u | (23u << 5))) count++;
    }
    return count;
}

static bool native_blob_single_arg_helper_stub(const uint8_t* code, size_t size,
                                               const hb_ir_block_t* block,
                                               bool canonical,
                                               hb_cached_helper_stub_t* out) {
    size_t blr_off = SIZE_MAX;
    size_t arg1_off = SIZE_MAX;
    uint8_t helper_id = 0;
    size_t arg1_count = 0;
    uint64_t helper_value = 0;
    uint16_t instr_index = 0;
    bool arg1_is_instr = false;

    if (!code || !size || !block) return false;
    for (size_t off = 0; off + 4 <= size; off += 4) {
        uint32_t insn;
        memcpy(&insn, code + off, sizeof(insn));
        if (insn == (0xd63f0000u | (23u << 5))) {
            if (blr_off != SIZE_MAX) return false;
            blr_off = off;
        }
    }
    if (blr_off == SIZE_MAX || blr_off < 16) return false;
    if (!arm64_mov_imm64_at(code, size, blr_off - 16, 23, &helper_value)) return false;
    if (canonical) {
        if ((helper_value & HB_RUNTIME_CACHE_HELPER_MASK) != HB_RUNTIME_CACHE_HELPER_SENTINEL)
            return false;
        helper_id = (uint8_t)(helper_value & 0xffu);
        if (!helper_addr_for_cache_id(helper_id)) return false;
    } else {
        helper_id = helper_cache_id_for_addr(helper_value);
        if (!helper_id) return false;
    }

    for (size_t off = 0; off + 16 <= size; off += 4) {
        uint64_t value = 0;
        if (arm64_mov_imm64_at(code, size, off, 2, &value) ||
            arm64_mov_imm64_at(code, size, off, 3, &value) ||
            arm64_mov_imm64_at(code, size, off, 4, &value))
            return false;
        if (arm64_mov_imm64_at(code, size, off, 1, &value)) {
            if (helper_cache_id_uses_instr_arg1(helper_id)) {
                if (canonical) {
                    if ((value & HB_RUNTIME_CACHE_INSTR_MASK) == HB_RUNTIME_CACHE_INSTR_SENTINEL) {
                        uint64_t idx = value & ~HB_RUNTIME_CACHE_INSTR_MASK;
                        if (idx >= block->instr_count || idx > UINT16_MAX) return false;
                        instr_index = (uint16_t)idx;
                        arg1_is_instr = true;
                        arg1_off = off;
                        arg1_count++;
                    }
                } else {
                    for (uint32_t idx = 0; idx < block->instr_count; idx++) {
                        if (value == (uint64_t)(uintptr_t)&block->instrs[idx]) {
                            instr_index = (uint16_t)idx;
                            arg1_is_instr = true;
                            arg1_off = off;
                            arg1_count++;
                            break;
                        }
                    }
                }
            } else {
                uint64_t expected = canonical ? HB_RUNTIME_CACHE_BLOCK_SENTINEL
                                              : (uint64_t)(uintptr_t)block;
                if (value == expected) {
                    arg1_off = off;
                    arg1_count++;
                }
            }
        }
    }
    if (arg1_count != 1 || arg1_off == SIZE_MAX) return false;
    if (out) {
        out->arg1_mov_off = arg1_off;
        out->helper_mov_off = blr_off - 16;
        out->helper_id = helper_id;
        out->instr_index = instr_index;
        out->arg1_is_instr = arg1_is_instr;
    }
    return true;
}

/* MacRunner 2026-07-29 — MULTI-HELPER PERSISTENCE.
 *
 * native_blob_single_arg_helper_stub() returns false the moment it sees a second `blr x23`, so a
 * block containing two helper calls can never be written to the persistent cache. On Hollow
 * Knight that shows up as stores=117 against store_skips=40495: the cache retains 0.3 % of what
 * it compiles and has therefore reached a steady state where it can never learn the rest. A cold
 * start needs 476 s to the menu — 232 s of it in the Mono load phase — while Rosetta, which
 * translates once and keeps the result, gets there in under 45 s.
 *
 * This finds EVERY helper site instead of bailing at the second, scoping each site's `mov x1`
 * search to the window between the previous `blr` and this one. Everything the single-stub
 * matcher rejected for safety is preserved: a `mov` into x2/x3/x4 anywhere in the block still
 * rejects the whole block, each site must resolve to a known helper id, and each must have
 * exactly one arg1 in its window.
 *
 * DEFAULT OFF. This patches emitted machine code: a mistake here executes wrong instructions
 * rather than failing loudly, so it ships behind MACRUNNER_HB_CACHE_MULTI_HELPER=1 and gets
 * proven by an A/B before it becomes the default.
 *
 * ★★★ MacRunner 2026-08-23, лейн РАЗРЫВ, итерация 320 (по приказу 227) — ЧИСЛА ВЫШЕ УСТАРЕЛИ,
 * А НАПРАВЛЕНИЕ ЗАКРЫТО. Не чините починенное.
 *
 * 1. «Удержание 0,3 % (stores=117 против store_skips=40495)» — это состояние на 29.07.
 *    Замер 23.08 на HK с ЭТИМ ГЕЙТОМ ВЫКЛЮЧЕННЫМ даёт RETENTION_PCT = 66,4 (та же величина:
 *    hk-boot-phases.py:182 считает 100*stores/(stores+skips)). Разница в 200 раз.
 *    Подняла удержание НЕ эта ветвь, а правка про род x23 того же дня: путь сохранения читал
 *    `reloc.reg == 23` как «адрес помощника», хотя x23 — ещё и черновик emit_mask_x_reg_to_size.
 *    Она сняла 53 655 отказов «unknown helper» за загрузку — 90 % всех отказов.
 *
 * 2. «476 с до меню» — тоже 29.07. Сегодняшние прогоны той же мишени идут за 104-113 с.
 *
 * 3. ГЛАВНОЕ: рост удержания времени НЕ ПОКУПАЕТ. Архив hk-cachefix-ab-20260729-232553,
 *    обе руки, доставка доказана их же критерием (rl_x23val только в починенной,
 *    rl_unkhelper 64 623 -> 0):
 *        база-хол  73,4 % / xinput 134,0 с     почин-хол  96,5 % / 134,8 с
 *        база-тёпл 38,2 % / xinput 138,2 с     почин-тёпл 83,2 % / 136,3 с
 *    Удержание вдвое лучше, компиляций на четверть меньше, вехи НЕ СДВИНУЛИСЬ. Это измеренный
 *    ноль, а не «выигрыш не показан». Причина: выпущенный код — 1,55 % рабочего потока,
 *    путь чтения памяти — 86 %.
 *
 * Приказ 227 (23.08): умолчание НЕ переводим, направление закрыто числом. Следующему, кто
 * захочет вернуться сюда: сперва перемерьте удержание — оно уже 66 %, а не 0,3 %. */
#define HB_MULTI_HELPER_MAX 16

static bool native_blob_multi_helper_enabled(void) {
    const char* v = hb_gate( HB_GATE_HB_CACHE_MULTI_HELPER );
    int cached = (v && v[0] && v[0] != '0') ? 1 : 0;
    return cached != 0;
}

/* Why a multi-helper block still could not be persisted. Measured because the first A/B cut
 * multi-helper skips from 118547 to 43909 — a threefold improvement, but 44k blocks are still
 * being dropped and there are four different reasons that could be doing it. Attributing them
 * is the difference between a targeted second pass and another guess. */
typedef enum {
    HB_MH_OK = 0,
    HB_MH_TOO_MANY,      /* more helper sites than HB_MULTI_HELPER_MAX */
    HB_MH_WIDE_ARG,      /* pointer moved into x2/x3/x4 somewhere in the block */
    HB_MH_UNKNOWN_HELPER,/* helper address/id not in the cacheable set */
    HB_MH_ARG_SHAPE      /* not exactly one recognised arg1 in this site's window */
} hb_mh_reason_t;

/* Collect one stub per helper call site. Returns false if any site fails to resolve, so a
 * partially-understood block is never persisted. */
static bool native_blob_helper_stubs(const uint8_t* code, size_t size,
                                     const hb_ir_block_t* block, bool canonical,
                                     hb_cached_helper_stub_t* out, size_t* out_count,
                                     hb_mh_reason_t* out_reason) {
    size_t blrs[HB_MULTI_HELPER_MAX];
    size_t n = 0;

    if (out_reason) *out_reason = HB_MH_OK;
    if (!code || !size || !block || !out || !out_count) return false;

    for (size_t off = 0; off + 4 <= size; off += 4) {
        uint32_t insn;
        memcpy(&insn, code + off, sizeof(insn));
        if (insn == (0xd63f0000u | (23u << 5))) {
            if (n >= HB_MULTI_HELPER_MAX) {
                if (out_reason) *out_reason = HB_MH_TOO_MANY;
                return false;
            }
            blrs[n++] = off;
        }
    }
    if (!n) return false;

    /* Global safety check, unchanged from the single-stub matcher: a pointer moved into any of
     * x2/x3/x4 means an argument shape this code does not understand well enough to rewrite. */
    for (size_t off = 0; off + 16 <= size; off += 4) {
        uint64_t value = 0;
        if (arm64_mov_imm64_at(code, size, off, 2, &value) ||
            arm64_mov_imm64_at(code, size, off, 3, &value) ||
            arm64_mov_imm64_at(code, size, off, 4, &value)) {
            if (out_reason) *out_reason = HB_MH_WIDE_ARG;
            return false;
        }
    }

    for (size_t i = 0; i < n; i++) {
        size_t blr_off = blrs[i];
        size_t win_lo = (i == 0) ? 0 : blrs[i - 1] + 4;
        uint64_t helper_value = 0;
        uint8_t helper_id;
        size_t arg1_off = SIZE_MAX;
        size_t arg1_count = 0;
        uint16_t instr_index = 0;
        bool arg1_is_instr = false;

        if (blr_off < 16 || blr_off - 16 < win_lo) return false;
        if (!arm64_mov_imm64_at(code, size, blr_off - 16, 23, &helper_value)) return false;
        if (canonical) {
            if ((helper_value & HB_RUNTIME_CACHE_HELPER_MASK) != HB_RUNTIME_CACHE_HELPER_SENTINEL)
                return false;
            helper_id = (uint8_t)(helper_value & 0xffu);
            if (!helper_addr_for_cache_id(helper_id)) {
                if (out_reason) *out_reason = HB_MH_UNKNOWN_HELPER;
                return false;
            }
        } else {
            helper_id = helper_cache_id_for_addr(helper_value);
            if (!helper_id) {
                if (out_reason) *out_reason = HB_MH_UNKNOWN_HELPER;
                return false;
            }
        }

        for (size_t off = win_lo; off + 16 <= size && off < blr_off; off += 4) {
            uint64_t value = 0;
            if (!arm64_mov_imm64_at(code, size, off, 1, &value)) continue;
            if (helper_cache_id_uses_instr_arg1(helper_id)) {
                if (canonical) {
                    if ((value & HB_RUNTIME_CACHE_INSTR_MASK) == HB_RUNTIME_CACHE_INSTR_SENTINEL) {
                        uint64_t idx = value & ~HB_RUNTIME_CACHE_INSTR_MASK;
                        if (idx >= block->instr_count || idx > UINT16_MAX) return false;
                        instr_index = (uint16_t)idx;
                        arg1_is_instr = true;
                        arg1_off = off;
                        arg1_count++;
                    }
                } else {
                    for (uint32_t idx = 0; idx < block->instr_count; idx++) {
                        if (value == (uint64_t)(uintptr_t)&block->instrs[idx]) {
                            instr_index = (uint16_t)idx;
                            arg1_is_instr = true;
                            arg1_off = off;
                            arg1_count++;
                            break;
                        }
                    }
                }
            } else {
                uint64_t expected = canonical ? HB_RUNTIME_CACHE_BLOCK_SENTINEL
                                              : (uint64_t)(uintptr_t)block;
                if (value == expected) {
                    arg1_off = off;
                    arg1_count++;
                }
            }
        }
        if (arg1_count != 1 || arg1_off == SIZE_MAX) {
            if (out_reason) *out_reason = HB_MH_ARG_SHAPE;
            return false;
        }

        out[i].arg1_mov_off = arg1_off;
        out[i].helper_mov_off = blr_off - 16;
        out[i].helper_id = helper_id;
        out[i].instr_index = instr_index;
        out[i].arg1_is_instr = arg1_is_instr;
    }
    *out_count = n;
    return true;
}

/* ---- persistence driven by the relocation table ---------------------------
 * MacRunner 2026-07-29.
 *
 * Everything above this line tries to RECOGNISE the emitted code: find the `blr x23`, walk
 * backwards 16 bytes for the helper mov, scan a window for an arg1 mov, insist there is exactly
 * one, and veto the block if anything moved an imm64 into x2/x3/x4. Measured on Hollow Knight,
 * that matcher rejects 62 % of everything the JIT compiles, and the attribution says the
 * rejections are its own artefacts rather than properties of the code:
 *
 *   mh_argshape  24585 (46 %)  — the lazy-flag and setcc paths put `instr->cc`, an integer, in
 *                                x1 and the pointer in x2, so "exactly one recognised arg1"
 *                                comes out zero. These are the densest paths in Mono output.
 *   mh_widearg   11759 (22 %)  — the veto matches the mov PATTERN and never looks at the value.
 *                                Ten of the eighteen x2/x3/x4 sites move a small constant
 *                                (`instr->dst.reg`, `dst.size`, a 0/1 flag) that needs no
 *                                relocation at all.
 *   mh_toomany    3202 (6 %)   — a 16-site cap in the matcher, against a 256-entry table.
 *
 * Codegen already records every one of these sites as it emits them (hb_codegen.h), so none of
 * this recognition is necessary. Reading the table instead:
 *
 *   store — classify each recorded site BY VALUE, register-agnostic: this block, one of its
 *           instructions, a registered helper, a value provably too small to be a host pointer
 *           (leave it), or an unresolvable host pointer (decline the block, and only this last
 *           case describes the guest code rather than this implementation).
 *   load  — scan for the 4-instruction form whose immediate is one of the sentinels and patch it
 *           back, taking the destination register from the encoded instruction. No windows, no
 *           pairing, no site cap, nothing to recognise.
 *
 * SOUNDNESS. This is only complete if the table sees every value that can differ between the run
 * that stores a block and the run that loads it. It does: a whole-file grep of the 103
 * emit_mov_imm64() call sites for `(uint64_t)(uintptr_t)` gives 46 hits, at x1 (38), x2 (5),
 * x3 (2), x4 (1), plus x23 for helper addresses — and codegen_note_reloc() records exactly those
 * five registers. The other 33 sites (x5, x6, x20, x21, x22) carry only guest-derived values
 * (`src1.imm`, `target`, `guest_addr`, `mem.disp`, `dst.size`), which the cache key already
 * covers. If that grep ever stops holding, the reloc_desync counter below is what will say so.
 *
 * DEFAULT OFF behind MACRUNNER_HB_CACHE_RELOC=1, like the multi-helper path before it: this
 * rewrites emitted machine code, where a mistake executes wrong instructions instead of failing
 * loudly. The round-trip self-check is kept and now exercises the new load path. */

/* macOS arm64 maps __PAGEZERO over the low 4 GB, so no host pointer can live below it. A value
 * under this floor is provably not a pointer into anything that moves between runs. */
#define HB_RELOC_HOST_PTR_FLOOR 0x100000000ull
/* ...and user virtual addresses are 47-bit, so nothing at or above 2^48 is one either. That
 * second half is not pedantry: `emit_mov_imm64(buf, 1, (uint64_t)instr->src1.imm)` and the
 * mem.disp sites pass SIGNED guest values through a uint64_t cast, so a displacement of -8 —
 * about as common as x86 gets — arrives here as 0xfffffffffffffff8. Testing only the low floor
 * would class every negative immediate as an unresolvable host pointer and decline the block.
 * Sign-extended constants are stable across runs and need no relocation at all. */
#define HB_RELOC_HOST_PTR_CEIL  0x0001000000000000ull

/* x23 is the helper-call target register AND codegen's scratch for a large `mem.disp`. Named so
 * the one remaining mention of it is visibly a counter and not a classifier. */
#define HB_RELOC_SCRATCH_REG_X23 23

/* Sound in the direction that matters: it may call a genuine pointer "maybe", never a provable
 * non-pointer. Everything it returns true for is declined rather than mis-restored. */
static bool reloc_value_may_be_host_pointer(uint64_t v) {
    return v >= HB_RELOC_HOST_PTR_FLOOR && v < HB_RELOC_HOST_PTR_CEIL;
}

/* Mirrors the switch in hb_contract_telemetry_record_reloc_decline(). */
typedef enum {
    HB_RELOC_OK = 0,
    HB_RELOC_DECLINE_OVERFLOW = 1,      /* table overflowed — not trustworthy for this block */
    HB_RELOC_DECLINE_UNKNOWN_HELPER = 2,/* x23 value is not a registered helper */
    HB_RELOC_DECLINE_HOSTPTR = 3,       /* host pointer that is not this block or its instrs */
    HB_RELOC_DECLINE_COLLISION = 4,     /* a literal already looks like a sentinel */
    HB_RELOC_DECLINE_DESYNC = 5,        /* table offset does not decode as the recorded mov */
    HB_RELOC_DECLINE_ROUNDTRIP = 6      /* store->load did not reproduce the original bytes */
} hb_reloc_decline_t;


/* Decode a 4-instruction MOVZ/MOVK immediate without being told which register to expect —
 * the load path has only the bytes. The destination comes out of the MOVZ and is then verified
 * against the remaining three by the existing decoder, so a coincidental byte pattern that is
 * not a well-formed sequence is still rejected. */
static bool arm64_mov_imm64_any_at(const uint8_t* code, size_t size, size_t off,
                                   int* rd_out, uint64_t* value) {
    uint32_t first;
    int rd;
    if (!code || off + 16 > size) return false;
    memcpy(&first, code + off, sizeof(first));
    rd = (int)(first & 0x1fu);
    if (!arm64_mov_imm64_at(code, size, off, rd, value)) return false;
    if (rd_out) *rd_out = rd;
    return true;
}

static bool reloc_value_is_sentinel(uint64_t v) {
    return v == HB_RUNTIME_CACHE_BLOCK_SENTINEL ||
           (v & HB_RUNTIME_CACHE_INSTR_MASK) == HB_RUNTIME_CACHE_INSTR_SENTINEL ||
           (v & HB_RUNTIME_CACHE_HELPER_MASK) == HB_RUNTIME_CACHE_HELPER_SENTINEL;
}

typedef enum {
    HB_RELOC_VAL_LITERAL,   /* not a sentinel — leave it alone */
    HB_RELOC_VAL_RESOLVED,  /* a sentinel, restored against this block */
    HB_RELOC_VAL_CORRUPT    /* a sentinel that does not resolve — refuse the whole blob */
} hb_reloc_val_t;

static hb_reloc_val_t reloc_sentinel_restore(uint64_t v, const hb_ir_block_t* block,
                                             uint64_t* out) {
    if (v == HB_RUNTIME_CACHE_BLOCK_SENTINEL) {
        *out = (uint64_t)(uintptr_t)block;
        return HB_RELOC_VAL_RESOLVED;
    }
    if ((v & HB_RUNTIME_CACHE_INSTR_MASK) == HB_RUNTIME_CACHE_INSTR_SENTINEL) {
        uint64_t idx = v & ~HB_RUNTIME_CACHE_INSTR_MASK;
        if (!block->instrs || idx >= block->instr_count) return HB_RELOC_VAL_CORRUPT;
        *out = (uint64_t)(uintptr_t)&block->instrs[idx];
        return HB_RELOC_VAL_RESOLVED;
    }
    if ((v & HB_RUNTIME_CACHE_HELPER_MASK) == HB_RUNTIME_CACHE_HELPER_SENTINEL) {
        void* addr = helper_addr_for_cache_id((uint8_t)(v & 0xffu));
        if (!addr) return HB_RELOC_VAL_CORRUPT;
        *out = (uint64_t)(uintptr_t)addr;
        return HB_RELOC_VAL_RESOLVED;
    }
    return HB_RELOC_VAL_LITERAL;
}

/* Is this value one of the block's own instruction pointers? Pointer arithmetic rather than a
 * scan over instr_count, so the cost does not grow with block length. */
static bool reloc_instr_index(const hb_ir_block_t* block, uint64_t value, uint64_t* idx_out) {
    uintptr_t base, v, delta;
    size_t stride;
    if (!block || !block->instrs || !block->instr_count) return false;
    base = (uintptr_t)block->instrs;
    v = (uintptr_t)value;
    if (v < base) return false;
    stride = sizeof(block->instrs[0]);
    delta = v - base;
    if (delta % stride) return false;
    delta /= stride;
    if (delta >= block->instr_count || delta > UINT16_MAX) return false;
    *idx_out = (uint64_t)delta;
    return true;
}

/* CENSUS of the one decline that is left. After the relocation table landed, Hollow Knight measured
 * stores=239364 store_skips=8841 with rl_hostptr=8841 and every other reason exactly 0 — so these
 * blocks are the entire missing 3.5 %, and what they point AT decides whether that is recoverable.
 *
 * The claim above is that they are other IR blocks handed to the fused hot-family helpers. If so
 * they are nameable: a foreign block is reachable through this block's CFG, and it also carries a
 * guest_addr that is identical in every run. If instead they are heap or arena addresses, they are
 * not nameable and the 3.5 % is a ceiling rather than a gap.
 *
 * Measurement only — the caller declines either way. Buckets match
 * hb_contract_telemetry_record_hostptr_census(). */
/* CENSUS v1 WAS VOID — kept written down because the failure is more instructive than the result.
 *
 * v1 bucketed the declined value against block->succ and block->pred and reported, very
 * consistently, hp_succ=0 hp_pred=0 hp_succinstr=0 hp_other=8485 with the four summing exactly to
 * rl_hostptr. The sum checking out is what made it look sound. It was not: hb_ir_cfg_add_edge() has
 * ZERO callers in the engine, so succ_count and pred_count are 0 for every block that has ever
 * existed here, and those three buckets were unreachable by construction. "Not found via the CFG"
 * was a tautology, not a measurement -- the same class of mistake as reading a counter behind a
 * gate that was never switched on.
 *
 * v2 therefore measures something that cannot be empty: the DESTINATION REGISTER, which the
 * relocation table records for every site and which the decline path already has in hand. reg tells
 * us the calling convention position -- 1/2/3/4 are helper arguments, so a block pointer handed to
 * a fused hot-family helper lands in one of those, while an address that is not an argument at all
 * lands elsewhere. Plus a one-shot dump of the first few actual values next to `block` and
 * `block->instrs`, because at this point looking at the numbers beats bucketing against a guess. */
static int reloc_hostptr_census_bucket(const hb_ir_block_t* block, uint64_t value, uint8_t reg) {
    static int dumped;

    /* MacRunner 2026-08-09 — потолок поднят с 6 до 256.
     *
     * Шести значений хватило, чтобы увидеть ОДИН И ТОТ ЖЕ сдвиг 0x2ca000000 между прогонами,
     * то есть что это адреса переезжающей целиком области, а не указатели в кучу хоста. Но
     * шесть — это выборка, а отказов 521 410. Потолок 256 даёт распределение по областям и
     * показывает, ВСЕ ли сайты лежат в одной переезжающей полосе; при 256 строках журнал не
     * тонет (для сравнения: rtmeter давал 36 тысяч строк). */
    if (hb_contract_telemetry_enabled() &&
        __atomic_fetch_add(&dumped, 1, __ATOMIC_RELAXED) < 256) {
        fprintf(stderr,
                "macrunner-hb-hostptr-sample: value=0x%llx reg=%u block=%p instrs=%p"
                " instr_count=%zu succ_count=%zu\n",
                (unsigned long long)value, (unsigned)reg, (const void*)block,
                block ? (const void*)block->instrs : NULL,
                block ? block->instr_count : (size_t)0,
                block ? block->succ_count : (size_t)0);
        fflush(stderr);
    }

    /* MacRunner 2026-08-09 — ПЕРЕПИСЬ ПО ПОЛОСАМ на ВСЕХ сайтах, а не дамп первых N.
     *
     * Дамп показал: первые 256 значений лежат в одной полосе 0x6 и в окне ~4 МБ, а между
     * прогонами все сдвинуты на одну величину 0x2ca000000 — то есть это адреса внутри одного
     * переезжающего образа. Но дамп берёт ПЕРВЫЕ N, значит выборка смещена к началу
     * трансляции, и на все 521 410 отказов вывод не переносится.
     *
     * Счётчик ниже считает КАЖДЫЙ сайт по старшим битам (полоса 4 ГБ). Если полоса окажется
     * одна — «один образ» доказано на полном счёте, и отказ `rl_hostptr` чинится одной базой.
     * Если полос много — правка «база+смещение» так просто не закроет вопрос, и это надо
     * узнать ДО того, как её писать. */
    {
        enum { HP_BAND_MAX = 12 };
        static uint32_t band_key[HP_BAND_MAX];
        static uint64_t band_cnt[HP_BAND_MAX];
        static unsigned band_n;
        static uint64_t band_total;
        uint32_t band = (uint32_t)(value >> 32);
        unsigned i;

        /* Границы ПО КАЖДОЙ полосе: размер окна отличает образ (единицы МБ) от арены JIT
         * (128 МБ) и от кучи. Плюс первые значения В КАЖДОЙ полосе, а не первые вообще —
         * именно из-за «первых вообще» дамп в итерации 65 не увидел полосу 0x5 (36% сайтов). */
        static uint64_t band_lo[HP_BAND_MAX], band_hi[HP_BAND_MAX];
        static unsigned band_shown[HP_BAND_MAX];

        for (i = 0; i < band_n; i++) if (band_key[i] == band) break;
        if (i == band_n && band_n < HP_BAND_MAX) {
            band_key[band_n] = band; band_lo[band_n] = value; band_hi[band_n] = value; band_n++;
        }
        if (i < HP_BAND_MAX) {
            band_cnt[i]++;
            if (value < band_lo[i]) band_lo[i] = value;
            if (value > band_hi[i]) band_hi[i] = value;
            if (band_shown[i] < 3) {
                band_shown[i]++;
                fprintf(stderr, "macrunner-hb-hostptr-band-sample: полоса=0x%x value=0x%llx reg=%u\n",
                        band, (unsigned long long)value, (unsigned)reg);
                fflush(stderr);
            }
        }

        if (++band_total == 1 || (band_total & 0xffffull) == 0) {
            unsigned k;
            fprintf(stderr, "macrunner-hb-hostptr-bands: всего=%llu полос=%u",
                    (unsigned long long)band_total, band_n);
            for (k = 0; k < band_n; k++)
                fprintf(stderr, " 0x%x:%llu[0x%llx..0x%llx]", band_key[k],
                        (unsigned long long)band_cnt[k],
                        (unsigned long long)band_lo[k], (unsigned long long)band_hi[k]);
            fprintf(stderr, "\n");
            fflush(stderr);
        }
    }

    switch (reg) {
        case 1: return 0;
        case 2: return 1;
        case 3: return 2;
        default: return 3;  /* 4, 23, or anything else — split further only if this points there */
    }
}

/* A literal that already looks like a sentinel would be indistinguishable from one we wrote, so
 * the load-time scan would rewrite it. Declining such a block makes that scan unambiguous by
 * construction rather than by probability. Sentinels sit at 0x4842_5254_xxxx_xxxx, far above any
 * plausible small constant and far from any macOS heap pointer, so this should never fire — the
 * counter says whether "should" is true. */
static bool reloc_blob_has_stray_sentinel(const uint8_t* code, size_t size) {
    for (size_t off = 0; off + 16 <= size; off += 4) {
        int rd = 0;
        uint64_t v = 0;
        if (arm64_mov_imm64_any_at(code, size, off, &rd, &v) && reloc_value_is_sentinel(v))
            return true;
    }
    return false;
}

static bool native_blob_reloc_load(const uint8_t* code, size_t size,
                                   const hb_ir_block_t* block,
                                   const uint8_t** out_code,
                                   uint8_t** owned_code) {
    uint8_t* patched = NULL;
    if (!code || !size || !block || !out_code || !owned_code) return false;
    *out_code = code;
    *owned_code = NULL;

    for (size_t off = 0; off + 16 <= size; off += 4) {
        int rd = 0;
        uint64_t v = 0, restored = 0;
        if (!arm64_mov_imm64_any_at(code, size, off, &rd, &v)) continue;
        switch (reloc_sentinel_restore(v, block, &restored)) {
            case HB_RELOC_VAL_LITERAL:
                continue;
            case HB_RELOC_VAL_CORRUPT:
                /* A sentinel we cannot resolve means the entry does not belong to this block.
                 * Fail the load so the dispatcher recompiles; never hand back code with a
                 * sentinel still in it, which would branch to 0x4842525448... */
                free(patched);
                return false;
            case HB_RELOC_VAL_RESOLVED:
                break;
        }
        if (!patched) {
            patched = malloc(size);
            if (!patched) return false;
            memcpy(patched, code, size);
        }
        arm64_patch_mov_imm64_at(patched, size, off, rd, restored);
    }
    if (patched) {
        *out_code = patched;
        *owned_code = patched;
    }
    return true;
}

static bool native_blob_reloc_store(const hb_codegen_buffer_t* buf,
                                    const hb_ir_block_t* block,
                                    const uint8_t** out_code,
                                    uint8_t** owned_code,
                                    hb_reloc_decline_t* why) {
    const uint8_t* code;
    size_t size;
    uint8_t* patched = NULL;
    size_t patched_sites = 0, literal_sites = 0, highhalf_sites = 0, x23_value_sites = 0;

    if (why) *why = HB_RELOC_OK;
    if (!buf || !buf->code || !buf->size || !block || !out_code || !owned_code) return false;
    code = buf->code;
    size = buf->size;
    *out_code = code;
    *owned_code = NULL;

    /* An overflowed table is missing sites, and a missing site is exactly the silent failure
     * this design exists to avoid. hb_codegen.h sets the cap at 256 against a measured 4.9 sites
     * per block, so this is a guard, not a path. */
    if (buf->reloc_overflow) {
        if (why) *why = HB_RELOC_DECLINE_OVERFLOW;
        return false;
    }
    if (reloc_blob_has_stray_sentinel(code, size)) {
        if (why) *why = HB_RELOC_DECLINE_COLLISION;
        return false;
    }
    if (!buf->reloc_count) {
        /* Nothing to relocate: the blob is position-independent as emitted. */
        hb_contract_telemetry_record_reloc_store(0, 0);
        return true;
    }

    patched = malloc(size);
    if (!patched) return false;
    memcpy(patched, code, size);

    for (size_t i = 0; i < buf->reloc_count; i++) {
        const hb_codegen_reloc_t* rl = &buf->relocs[i];
        uint64_t seen = 0, idx = 0, sentinel;

        /* The table must describe the code it came from. If a later pass rewrote these bytes,
         * or an offset drifted, this catches it here instead of at some unrelated cache hit. */
        if (!arm64_mov_imm64_at(code, size, rl->off, (int)rl->reg, &seen) || seen != rl->value) {
            if (why) *why = HB_RELOC_DECLINE_DESYNC;
            goto decline;
        }

        /* By KIND, not by register. `reg == 23` used to stand in for "helper address" and was
         * wrong: emit_mask_x_reg_to_size() uses x23 as scratch and emits `mov x23, 0xffffffff`
         * for the zero-extension every 32-bit x86 operand needs — a plain 32-bit ADD produces
         * exactly that one relocation. Looking 0xffffffff up in the helper table failed and
         * declined the whole block: 53 655 on Hollow Knight, 90 % of every decline. A mask is a
         * constant, so it now falls through to the value classification below, lands under the
         * 4 GB floor, and is left alone — which is all it ever needed. */
        if (rl->kind == HB_RELOC_KIND_HELPER) {
            uint8_t id = helper_cache_id_for_addr(rl->value);
            if (!id) {
                if (why) *why = HB_RELOC_DECLINE_UNKNOWN_HELPER;
                goto decline;
            }
            sentinel = HB_RUNTIME_CACHE_HELPER_SENTINEL | id;
        } else if (rl->value == (uint64_t)(uintptr_t)block) {
            sentinel = HB_RUNTIME_CACHE_BLOCK_SENTINEL;
        } else if (reloc_instr_index(block, rl->value, &idx)) {
            sentinel = HB_RUNTIME_CACHE_INSTR_SENTINEL | idx;
        } else if (!reloc_value_may_be_host_pointer(rl->value)) {
            /* Provably not a host pointer — a condition code, an opcode, a register number, a
             * size, or a sign-extended negative guest constant. Identical in every run, so it
             * needs no relocation. This is the case the old matcher threw whole blocks away
             * for. Counted split by half so the next run says which rule earned the retention. */
            literal_sites++;
            if (rl->value >= HB_RELOC_HOST_PTR_CEIL) highhalf_sites++;
            /* The site the register-based test used to declare an unknown helper. Counting only —
             * the classification above is on kind, and scripts/hb-check-reloc-invariant.sh fails
             * the build if `rl->reg == 23` ever decides anything again. */
            if (rl->reg == HB_RELOC_SCRATCH_REG_X23) x23_value_sites++;
            continue;
        } else {
            /* A host pointer this block cannot name: `first`/`second`/`sort`/`entry` point into
             * OTHER IR blocks, which will not exist at load time. Genuinely un-persistable, and
             * the only decline here that is about the code rather than about this matcher. */
            hb_contract_telemetry_record_hostptr_census(
                reloc_hostptr_census_bucket(block, rl->value, rl->reg));
            if (why) *why = HB_RELOC_DECLINE_HOSTPTR;
            goto decline;
        }

        arm64_patch_mov_imm64_at(patched, size, rl->off, (int)rl->reg, sentinel);
        patched_sites++;
    }

    /* SELF-CHECK, kept from the multi-helper path and now covering the new load path.
     *
     * Patching emitted machine code is the one class of change here that fails silently: a wrong
     * offset does not crash the patcher, it executes wrong instructions later and far from the
     * cause. So prove the transformation is invertible before trusting it — run the actual load
     * path over the patched form and require the result to be byte-identical to what codegen
     * produced. One extra pass and a memcmp per stored block, paid at compile time, never on the
     * hot path. */
    if (!reloc_selfcheck_now()) {
        g_selfcheck_skipped++;
    } else {
        const uint8_t* back = NULL;
        uint8_t* owned_back = NULL;
        bool sound;

        g_selfcheck_done++;
        if (!native_blob_reloc_load(patched, size, block, &back, &owned_back)) {
            if (why) *why = HB_RELOC_DECLINE_ROUNDTRIP;
            goto decline;
        }
        sound = (memcmp(back, code, size) == 0);
        free(owned_back);
        if (!sound) {
            if (why) *why = HB_RELOC_DECLINE_ROUNDTRIP;
            goto decline;
        }
    }

    hb_contract_telemetry_record_reloc_store((unsigned long)patched_sites,
                                             (unsigned long)literal_sites);
    hb_contract_telemetry_record_reloc_highhalf((unsigned long)highhalf_sites);
    hb_contract_telemetry_record_reloc_x23_value((unsigned long)x23_value_sites);
    *out_code = patched;
    *owned_code = patched;
    return true;

decline:
    free(patched);
    *out_code = code;
    *owned_code = NULL;
    return false;
}

/* MacRunner 2026-07-30 — timed wrapper. Follows the _inner convention already used in
 * hb_memory_protect_inner: the body has many exits and wrapping is safer than threading a stop
 * through each one. This is the half of a compile that contains the round-trip self-check, which
 * re-runs the whole load path and memcmps it for every stored block. */
static bool native_blob_prepare_cache_store_inner(const hb_codegen_buffer_t* buf,
                                            const uint8_t* code, size_t size,
                                            const hb_ir_block_t* block,
                                            const uint8_t** out_code,
                                            uint8_t** owned_code);

static uint64_t hb_time_now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static bool native_blob_prepare_cache_store(const hb_codegen_buffer_t* buf,
                                            const uint8_t* code, size_t size,
                                            const hb_ir_block_t* block,
                                            const uint8_t** out_code,
                                            uint8_t** owned_code) {
    uint64_t t0 = hb_time_now_ns();
    bool r = native_blob_prepare_cache_store_inner(buf, code, size, block, out_code, owned_code);
    uint64_t t1 = hb_time_now_ns();
    if (t1 > t0) hb_contract_telemetry_add_time(1, t1 - t0);
    return r;
}

static bool native_blob_prepare_cache_store_inner(const hb_codegen_buffer_t* buf,
                                            const uint8_t* code, size_t size,
                                            const hb_ir_block_t* block,
                                            const uint8_t** out_code,
                                            uint8_t** owned_code) {
    hb_cached_helper_stub_t stub;
    uint8_t* patched;
    if (!code || !size || !out_code || !owned_code) return false;
    *out_code = code;
    *owned_code = NULL;

    /* ★ 26.08.2026 — ГЕЙТ УДАЛЁН, путь по таблице перемещений теперь единственный.
     *
     * Прежний `MACRUNNER_HB_CACHE_RELOC` (умолчание OFF) держал взаперти вот что: без него
     * кеш трансляций ЧИТАЛСЯ, но не пополнялся НИ ОДНИМ блоком — stores=0, все 4999 записей
     * отвергал распознаватель выпущенного кода (mh_argshape 3027 из 3151). С путём по
     * таблице: stores=4999, bytes_stored=1 994 932, файл кеша 2,0 → 6,5 МБ, приёмка та же
     * (474/11 обеими руками), игра цела (код=0, 45 растров).
     *
     * Выигрыша во времени нет и быть не может: вся трансляция прогона стоит 12 мс при длине
     * прогона 56 000 мс. Путь включён потому, что чинит поломку, а не ради скорости — и
     * гейта не заслуживает: он не разделяет безопасное и небезопасное и не включает прибор. */
    if (buf) {
        hb_reloc_decline_t why = HB_RELOC_OK;
        if (native_blob_reloc_store(buf, block, out_code, owned_code, &why)) return true;
        hb_contract_telemetry_record_reloc_decline((int)why);
        return false;
    }

    if (native_blob_multi_helper_enabled() && native_blob_has_helper_call(code, size)) {
        hb_cached_helper_stub_t stubs[HB_MULTI_HELPER_MAX];
        size_t count = 0;
        hb_mh_reason_t mh_reason = HB_MH_OK;
        if (native_blob_helper_stubs(code, size, block, false, stubs, &count, &mh_reason) && count > 1) {
            patched = malloc(size);
            if (!patched) return false;
            memcpy(patched, code, size);
            for (size_t i = 0; i < count; i++) {
                arm64_patch_mov_imm64_at(patched, size, stubs[i].arg1_mov_off, 1,
                                         stubs[i].arg1_is_instr
                                             ? (HB_RUNTIME_CACHE_INSTR_SENTINEL | stubs[i].instr_index)
                                             : HB_RUNTIME_CACHE_BLOCK_SENTINEL);
                arm64_patch_mov_imm64_at(patched, size, stubs[i].helper_mov_off, 23,
                                         HB_RUNTIME_CACHE_HELPER_SENTINEL | stubs[i].helper_id);
            }

            /* SELF-CHECK, and the reason this is safe to ship at all.
             *
             * Patching emitted machine code is the one class of change here that fails silently:
             * a wrong offset does not crash the patcher, it executes wrong instructions later and
             * far from the cause. So prove the transformation is invertible before trusting it —
             * re-derive the stubs from the patched form exactly as the load path will
             * (canonical=true) and patch them back. If the result is not byte-identical to what
             * codegen produced, this block's round trip is not sound and we decline to persist
             * something we cannot faithfully restore.
             *
             * One extra scan and memcmp per stored block, paid at compile time, never on the hot
             * path. Cheap insurance against the only failure mode here that has no symptom. */
            if (!reloc_selfcheck_now()) {
                /* Пропущено по частоте — см. reloc_selfcheck_rate(). */
            } else {
                hb_cached_helper_stub_t back[HB_MULTI_HELPER_MAX];
                size_t back_count = 0;
                uint8_t* restored = malloc(size);
                bool sound = false;

                if (restored) {
                    memcpy(restored, patched, size);
                    if (native_blob_helper_stubs(patched, size, block, true, back, &back_count, NULL) &&
                        back_count == count) {
                        for (size_t i = 0; i < back_count; i++) {
                            arm64_patch_mov_imm64_at(restored, size, back[i].arg1_mov_off, 1,
                                                     back[i].arg1_is_instr
                                                         ? (uint64_t)(uintptr_t)&block->instrs[back[i].instr_index]
                                                         : (uint64_t)(uintptr_t)block);
                            arm64_patch_mov_imm64_at(restored, size, back[i].helper_mov_off, 23,
                                                     (uint64_t)(uintptr_t)helper_addr_for_cache_id(back[i].helper_id));
                        }
                        sound = (memcmp(restored, code, size) == 0);
                    }
                    free(restored);
                }
                if (!sound) {
                    free(patched);
                    goto multi_helper_declined;
                }
            }

            *out_code = patched;
            *owned_code = patched;
            return true;
        }
    }
multi_helper_declined:;
    if (!native_blob_has_helper_call(code, size)) return true;
    if (!native_blob_single_arg_helper_stub(code, size, block, false, &stub))
        return false;
    patched = malloc(size);
    if (!patched) return false;
    memcpy(patched, code, size);
    arm64_patch_mov_imm64_at(patched, size, stub.arg1_mov_off, 1,
                             stub.arg1_is_instr
                                 ? (HB_RUNTIME_CACHE_INSTR_SENTINEL | stub.instr_index)
                                 : HB_RUNTIME_CACHE_BLOCK_SENTINEL);
    arm64_patch_mov_imm64_at(patched, size, stub.helper_mov_off, 23,
                             HB_RUNTIME_CACHE_HELPER_SENTINEL | stub.helper_id);
    *out_code = patched;
    *owned_code = patched;
    return true;
}

static bool native_blob_prepare_cache_load(const uint8_t* code, size_t size,
                                           const hb_ir_block_t* block,
                                           const uint8_t** out_code,
                                           uint8_t** owned_code) {
    hb_cached_helper_stub_t stub;
    uint8_t* patched;
    if (!code || !size || !out_code || !owned_code) return false;
    *out_code = code;
    *owned_code = NULL;

    /* The table-driven load needs nothing but the sentinels the store path wrote, so it also
     * reads blobs the older matchers produced — they use the same encoding. The persistent key
     * still carries a mode bit (HB_PERSIST_FLAG_RELOC) so the two arms of an A/B can never share
     * entries in the other direction: a reloc-stored blob can hold sentinels in x2/x3/x4, which
     * the legacy load below does not know to restore. */
    /* путь по таблице — единственный, см. пояснение у native_blob_reloc_store */
        return native_blob_reloc_load(code, size, block, out_code, owned_code);

    /* Mirror of the multi-helper store path. A block written with several sentinel-patched sites
     * can only be loaded by code that patches all of them back, so the two must agree exactly:
     * restoring only the first would leave the rest jumping to a sentinel value. */
    if (native_blob_multi_helper_enabled() && native_blob_has_helper_call(code, size)) {
        hb_cached_helper_stub_t stubs[HB_MULTI_HELPER_MAX];
        size_t count = 0;
        if (native_blob_helper_stubs(code, size, block, true, stubs, &count, NULL) && count > 1) {
            patched = malloc(size);
            if (!patched) return false;
            memcpy(patched, code, size);
            for (size_t i = 0; i < count; i++) {
                arm64_patch_mov_imm64_at(patched, size, stubs[i].arg1_mov_off, 1,
                                         stubs[i].arg1_is_instr
                                             ? (uint64_t)(uintptr_t)&block->instrs[stubs[i].instr_index]
                                             : (uint64_t)(uintptr_t)block);
                arm64_patch_mov_imm64_at(patched, size, stubs[i].helper_mov_off, 23,
                                         (uint64_t)(uintptr_t)helper_addr_for_cache_id(stubs[i].helper_id));
            }
            *out_code = patched;
            *owned_code = patched;
            return true;
        }
    }
    if (!native_blob_has_helper_call(code, size)) return true;
    if (!native_blob_single_arg_helper_stub(code, size, block, true, &stub))
        return false;
    patched = malloc(size);
    if (!patched) return false;
    memcpy(patched, code, size);
    arm64_patch_mov_imm64_at(patched, size, stub.arg1_mov_off, 1,
                             stub.arg1_is_instr
                                 ? (uint64_t)(uintptr_t)&block->instrs[stub.instr_index]
                                 : (uint64_t)(uintptr_t)block);
    arm64_patch_mov_imm64_at(patched, size, stub.helper_mov_off, 23,
                             (uint64_t)(uintptr_t)helper_addr_for_cache_id(stub.helper_id));
    *out_code = patched;
    *owned_code = patched;
    return true;
}

static bool block_guest_span(const hb_ir_block_t* block, uint64_t* start, size_t* len) {
    uint64_t lo, hi;
    uint32_t steps;
    if (!block || !block->instr_count || !start || !len) return false;
    steps = jit_block_step_count(block);
    if (!steps || steps > block->instr_count) return false;
    lo = block->instrs[0].guest_addr;
    hi = lo;
    for (uint32_t i = 0; i < steps; i++) {
        const hb_ir_instr_t* instr = &block->instrs[i];
        uint64_t end = instr->guest_addr + instr->guest_len;
        if (instr->guest_addr < lo) lo = instr->guest_addr;
        if (end > hi) hi = end;
    }
    if (hi <= lo || hi - lo > 4096u) return false;
    *start = lo;
    *len = (size_t)(hi - lo);
    return true;
}

/* ---- SMC (self-modifying code) translation reverify ----------------------
 * MacRunner 2026-07-27 — HK Mono/JIT stale-translation fix.
 * The in-memory block cache was keyed purely by guest address: a cached
 * translation kept executing even after the guest (Mono's JIT) rewrote the
 * underlying bytes, because no path — guest write, NtProtectVirtualMemory,
 * NtFlushInstructionCache — ever invalidated it (see
 * reports/phase4-hollow-knight/MONO-SMC-STALE-TRANSLATION-MECHANISM-20260727.md).
 * Fix: for blocks whose guest span is writable+executable (the only spans
 * that CAN change — Mono/JIT code heaps are RWX), hash the guest bytes at
 * translation time and re-verify on every cache hit; a mismatch evicts the
 * entry so the dispatch loop retranslates from current bytes.  Static RX
 * code stays untracked and pays nothing.  Default ON; kill switch
 * MACRUNNER_HB_SMC_REVERIFY=0; diagnostics MACRUNNER_HB_TRACE_SMC_REVERIFY=1. */

/* Частота самопроверки round-trip при сохранении блока в кеш.
 *
 * Обе самопроверки (реloc-форма и форма с хелперами) повторяют ВЕСЬ путь загрузки и
 * сравнивают результат с тем, что выпустил кодогенератор, — на каждый сохраняемый блок.
 * Комментарии рядом с ними честно пишут: «about 240000 full round trips per cold start,
 * correct by design and never once measured». Сегодня замер показал, что 61% времени
 * холодного старта уходит в трансляцию (45.5 с против 17.8 с на прогретом кеше), и эта
 * самопроверка — один из двух её кусков.
 *
 * Выключателем это делать нельзя: проверка ловит единственный класс отказа, у которого нет
 * симптома, — неверно пропатченный код исполняется молча и падает далеко от причины.
 * Поэтому здесь ЧАСТОТА: 1 — каждый блок (прежнее поведение, умолчание), N — каждый N-й,
 * 0 — не проверять вовсе. Выборочная проверка сохраняет почти всю страховку: систематическая
 * ошибка патчинга проявится на первых же десятках блоков, а не спрячется в одном из ста.
 */
static unsigned reloc_selfcheck_rate(void) {
    const char* v = hb_gate( HB_GATE_HB_RELOC_SELFCHECK_RATE );
    int rate = (v && *v) ? atoi(v) : 1;
    if (rate < 0) rate = 1;
    return (unsigned)rate;
}

static bool reloc_selfcheck_now(void) {
    static unsigned long long seen;
    unsigned rate = reloc_selfcheck_rate();
    unsigned long long n = __atomic_add_fetch(&seen, 1ull, __ATOMIC_RELAXED);
    if (rate == 0) return false;
    if (rate == 1) return true;
    return (n % rate) == 0;
}

static int smc_trace_enabled(void) {
    return runtime_gate_flag( HB_GATE_HB_TRACE_SMC_REVERIFY, 0);
}

/* Примитив защиты страниц живёт в hb_memory.c (итерация 978). */
extern int      hb_smc_protect_enabled(void);
extern int      hb_smc_arm_page(void* host_addr);
extern uint32_t hb_smc_page_generation(uint64_t host_addr);
extern int      hb_smc_query_prot(uint64_t host_addr);

static uint64_t smc_fnv1a(const uint8_t* p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

static uint64_t g_smc_tracked, g_smc_reverified, g_smc_evicted, g_smc_unreadable;
/* MacRunner 19.08, лейн ЛЕСТНИЦА итерация 2551 — ЗАКАЗ 2 лейна ЧТЕЦ-QEMU (137).
 * ВОПРОС: какова длина областей, по которым считается сверка SMC. Его итерация 133 мерила
 * .text файлов DLL и получила медиану 13 байт, но 135 сама себя отозвала: гейт выше пускает
 * СЮДА только области W+X, то есть код, порождённый JIT-ом Mono. Про него не известно ничего.
 * Гистограмма по ЗАПИСЯМ в кеш (не по попаданиям — частоту даёт замер 2418: 2593 сверки/228 с).
 * Печать безусловная: на первой записи и по периоду, латиницей — кириллицу рвёт strings. */
static void smc_len_dump(void);
static void atexit_smc_len_register(void);
static uint64_t g_smc_len_hist[5];   /* <64, <256, <1K, <4K, >=4K */
static uint64_t g_smc_len_total, g_smc_len_max;
static void smc_len_report(const char* когда)
{
    fprintf(stderr,
        "macrunner-smc-span %s total=%llu max=%llu lt64=%llu lt256=%llu lt1k=%llu lt4k=%llu ge4k=%llu unreadable=%llu\n",
        когда,
        (unsigned long long)g_smc_len_total, (unsigned long long)g_smc_len_max,
        (unsigned long long)g_smc_len_hist[0], (unsigned long long)g_smc_len_hist[1],
        (unsigned long long)g_smc_len_hist[2], (unsigned long long)g_smc_len_hist[3],
        (unsigned long long)g_smc_len_hist[4], (unsigned long long)g_smc_unreadable);
}
static void smc_len_dump(void) { smc_len_report("TOTAL"); }
static void atexit_smc_len_register(void) { atexit(smc_len_dump); }
static void smc_len_note(size_t len)
{
    unsigned k = len < 64 ? 0u : len < 256 ? 1u : len < 1024 ? 2u : len < 4096 ? 3u : 4u;
    g_smc_len_hist[k]++;
    g_smc_len_total++;
    if ((uint64_t)len > g_smc_len_max) g_smc_len_max = (uint64_t)len;
    if (g_smc_len_total == 1ull) { smc_len_report("FIRST"); atexit_smc_len_register(); }
    else if ((g_smc_len_total & 0xFFFull) == 0ull) smc_len_report("TICK");
}

void hb_jit_smc_reverify_stats(uint64_t* tracked, uint64_t* reverified,
                               uint64_t* evicted, uint64_t* unreadable) {
    if (tracked) *tracked = g_smc_tracked;
    if (reverified) *reverified = g_smc_reverified;
    if (evicted) *evicted = g_smc_evicted;
    if (unreadable) *unreadable = g_smc_unreadable;
}

/* Hash the CURRENT guest bytes of [start, start+len).  Returns 0 when the
 * span is unreadable — treated as unverifiable, never evicts blind. */
static uint64_t smc_hash_current(hb_jit_runtime_t* rt, uint64_t start, size_t len) {
    /* MacRunner 19.08, лейн ЛЕСТНИЦА итерация 2547 — БУФЕР СО СТЕКА В ОБЛАСТЬ ПОТОКА.
     * Перебор всех проб стека в ntdll.so (23 функции) показал: этот буфер ровно 4096 байт,
     * то есть САМ порог, за которым компилятор ставит ___chkstk_darwin — любые прочие
     * локальные выталкивают кадр за него. Через встраивание сюда кадр smc_reverify_entry
     * = 4176 байт, и он платит пробу стека на КАЖДОМ вызове, хотя сверка хеша делается
     * редко (замер 2418: 2593 сверки за 228 с). Цена измерена: 74 выборки chkstk с
     * smc_reverify_entry в родителях = 0,30 % рабочего потока.
     * Область потока, а не статик: сверка идёт из нескольких потоков одновременно.
     * Поведение не меняется — размер 4096 тут не семантика страницы, а верхний предел
     * (len > sizeof(bytes) -> 0), и он сохранён. */
    static __thread uint8_t bytes[4096];
    if (!rt || !rt->ctx || !rt->ctx->memory || !len || len > sizeof(bytes)) return 0;
    /* ★ Отображение проверяем ДО чтения — см. разбор у jit_cache_key_for_block: быстрый путь
     * hb_memory_read на macOS копирует хозяйским memcpy и падает SIGBUS вне обработки отказов,
     * если регион заявлен шире, чем отображён. Слияние блоков растит span и попадает туда. */
    if (!hb_memory_can_read_span(rt->ctx->memory, start, len)) return 0;
    if (hb_memory_read(rt->ctx->memory, start, bytes, len) != HB_OK) return 0;
    return smc_fnv1a(bytes, len);
}

/* ★ 2026-09-03: гейт отпечатка по всей функции (см. комментарий в smc_track_entry). Значение, не наличие. */
static int hb_smc_func_span_enabled(void) {
    const char* v = hb_gate( HB_GATE_HB_SMC_FUNC_SPAN );
    int cached = (v && v[0]) ? (v[0] != '0') : 1;
    return cached;
}

/* ★ 2026-09-03: гейт отслеживания SMC по записываемости (см. комментарий в smc_track_block). Значение, не наличие. */
static int hb_smc_track_writable_enabled(void) {
    const char* v = hb_gate( HB_GATE_HB_SMC_TRACK_WRITABLE );
    int cached = (v && v[0]) ? (v[0] != '0') : 1;
    return cached;
}

static void smc_track_entry(hb_jit_runtime_t* rt, hb_block_cache_entry_t* entry,
                            const hb_ir_block_t* block) {
    uint64_t start = 0;
    size_t len = 0;
    hb_region_t* region;
    uint64_t h;
    if (!entry) return;
    entry->smc_hash = 0;
    entry->smc_span_start = 0;
    entry->smc_span_len = 0;
    if (!rt || !rt->ctx || !rt->ctx->memory || !block)
        return;
    if (!block_guest_span(block, &start, &len)) return;
    /* ★ 2026-09-03 (kan-27): отпечаток по ВСЕЙ поднятой функции. Хронология kan-27: патчуемый `call` Storm SCode
     * лежит в блоке без своей записи кеша (проваливание внутри функции 0x64600cc), его байты не хешировались никогда,
     * функция переподнималась лишь при случайном выселении соседа — после ущерба (первая запись за буфер на строке
     * 48631, выселение соседа на 48655). IR функции зависит от всех её байтов — их и сверяем.
     * Гейт MACRUNNER_HB_SMC_FUNC_SPAN (значение; умолчание ВКЛ) — на время парного замера, после снять. */
    if (hb_smc_func_span_enabled() && rt->cur_func_len && start >= rt->cur_func_addr &&
        start + len <= rt->cur_func_addr + rt->cur_func_len) {
        start = rt->cur_func_addr; len = rt->cur_func_len;
    }
    region = hb_memory_find_region(rt->ctx->memory, start);
    if (!region) return;
    /* ★ MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 972 — БЛОК ЧЕРЕЗ ГРАНИЦУ ОБЛАСТИ
     * МОЛЧА ОСТАВАЛСЯ БЕЗ ПРИСМОТРА.
     *
     * Здесь стояло `if (start + len > region->base + region->size) return;` — то есть блок,
     * чей диапазон выходит за область, не получал хеша ВОВСЕ, и самоизменение в нём не
     * обнаруживалось ни при каких условиях, без единой записи в журнал.
     *
     * Замер (итерация 971, `artifacts/smcedge.exe`): две соседние области, функция попёрек
     * границы (три байта в первой, три во второй), патч — и гость получает СТАРОЕ значение
     *     before=1111 (верно)   after=1111, а ожидалось 3333   verdict=MISSED
     * Контроль `artifacts/smctwin.exe` (тот же патч в пределах ОДНОЙ области) проходит.
     * Две пробы различаются одним признаком и расходятся в исходе.
     *
     * Почему это важно именно нам: куча кода Mono растёт последовательными выделениями, то
     * есть границы областей в ней есть по устройству, а блок поперёк такой границы исполнялся
     * бы устаревшим переводом сколь угодно долго.
     *
     * Лечение консервативное: смотрим область НАЧАЛА и область ПОСЛЕДНЕГО байта; отслеживаем,
     * если хоть одна из них W+X. Ошибаться будем в сторону ЛИШНЕГО присмотра, а не пропуска —
     * лишний хеш стоит времени, пропуск стоит верности. Чтение всего диапазона делает
     * `smc_hash_current`; если оно не удастся, вернётся 0, и блок останется неотслеженным
     * ровно как прежде. */
    {
        hb_region_t* last = region;
        if (len && start + len - 1 > region->base + region->size - 1)
            last = hb_memory_find_region(rt->ctx->memory, start + len - 1);
        if (!last) return;
        /* ★★★ MacRunner 2026-09-03, режим D Diablo (kan-23) — ОТСЛЕЖИВАТЬ ЛЮБУЮ ЗАПИСЫВАЕМУЮ ОБЛАСТЬ.
         *
         * Условие «W и X» было мертво для гостя 32 бит: права области в карте guest32 — это права
         * ХОЗЯЙСКОГО отображения (perm=3, R|W), а не гостевые PAGE_EXECUTE_READWRITE; X у гостевого
         * кода в карте не бывает никогда, потому что исполняет его JIT, а не процессор. Замер kan-23:
         * `macrunner-smc-span FIRST total=1` — за весь прогон отслежен ОДИН блок. Следствие: Storm
         * SCode (SVid) патчит rel32 вызова в своём сгенерированном драйвере при каждой смене ширины
         * прямоугольника (SCodeExecute, 1500c5d9), а наш перевод исполнял старое смещение — тело на
         * 320 юнитов вместо 64, дрейф 256 байт/строку, переполнение буфера Smacker, порча узла кучи,
         * отказ heap_allocate_block после заставки. Образы PE лежат R|X (perm=5) и остаются вне
         * присмотра, как и прежде: меняться под нами может только то, что записываемо.
         * Гейт MACRUNNER_HB_SMC_TRACK_WRITABLE (значение; умолчание ВКЛ) — только на время парного
         * замера, после доказательства снять. */
        if (hb_smc_track_writable_enabled()) {
            if (!(region->perm & HB_PERM_WRITE) && !(last->perm & HB_PERM_WRITE))
                return;  /* немодифицируемая область: код не может измениться под нами */
        } else if ((region->perm & (HB_PERM_WRITE | HB_PERM_EXEC)) != (HB_PERM_WRITE | HB_PERM_EXEC) &&
            (last->perm & (HB_PERM_WRITE | HB_PERM_EXEC)) != (HB_PERM_WRITE | HB_PERM_EXEC))
            return;  /* static RX code cannot change under us: leave untracked */
    }
    h = smc_hash_current(rt, start, len);
    if (!h) { g_smc_unreadable++; return; }
    smc_len_note(len);
    entry->smc_span_start = start;
    entry->smc_span_len = (uint32_t)len;
    entry->smc_hash = h;
    entry->smc_gen = 0;
    entry->smc_gen_valid = 0;
    /* Итерация 979: если защита включена — снять право записи со страниц ОБОИХ концов блока
     * и запомнить поколение первой. Тогда на входе хватит сравнения одного числа, а хеш
     * останется полномочным судьёй на случай, когда поколение разошлось. */
    if (hb_smc_protect_enabled()) {
        void* hp_first = hb_memory_host_ptr(rt->ctx->memory, start, 1, HB_PERM_READ);
        void* hp_last  = hb_memory_host_ptr(rt->ctx->memory, start + len - 1, 1, HB_PERM_READ);
        if (hp_first && hb_smc_arm_page(hp_first)) {
            if (hp_last && hp_last != hp_first) hb_smc_arm_page(hp_last);
            entry->smc_gen = hb_smc_page_generation((uint64_t)(uintptr_t)hp_first);
            entry->smc_gen_valid = 1;
        }
    }
    g_smc_tracked++;
}

/* MacRunner 2026-08-01 — FEX-style guest-position reconstruction, built alongside the old path.
 *
 * FEX carries no context snapshot: a fault is resolved by folding the faulting host PC through a
 * per-block (host delta -> guest RIP delta) table, so rollback granularity is one guest
 * instruction and work completed before it is never discarded. Our equivalent needs no emitted
 * table — the guest side is block->instrs[i].guest_addr, and host_off[i] now records where that
 * instruction's code begins.
 *
 * Nothing is removed yet. This runs in parallel with the snapshot path and reports disagreements,
 * because five hypotheses about the chaining defect were refuted by measurement today and
 * replacing a mechanism on the strength of a sixth would be the same mistake. */
static void ripmap_attach(hb_block_cache_entry_t* entry, const hb_codegen_buffer_t* buf);

/* ★★★★★ 05.09.2026 — СНИМОК УДАЛЁН, ГЕЙТЫ УДАЛЕНЫ. Что здесь было и куда делось.
 *
 * `MACRUNNER_HB_NO_SNAPSHOT` (не снимать снимок), `MACRUNNER_HB_SNAPSHOT_MEASURE_SKIP`
 * (замерочная рука: объявить снимок годным, но не снимать), `MACRUNNER_HB_CHAIN_SCOPED_ROLLBACK`
 * (не откатывать, если отказал не отправленный блок) и `MACRUNNER_HB_RIPMAP` (сличать
 * ответ карты со снимком) — все четыре были про ОДИН механизм: откат гостя к копии
 * состояния до блока. Копия снята безусловно, откат невозможен по построению, гейты
 * сняты вместе с ним. Замер, на котором стоит решение, — в отчёте
 * reports/СНИМОК-СНЯТ-ТОЧНОЕ-ВОЗОБНОВЛЕНИЕ-05.09.2026.md.
 *
 * Как у QEMU (cpu_restore_state -> restore_state_to_opc: позиция и cc_op из боковых данных
 * перевода, регистры уже в памяти — globals синхронизируются перед всякой операцией с
 * побочным эффектом) и у FEX (ReconstructThreadState: RIP по таблице RIPEntries блока,
 * регистры из статических регистров хозяина, отката нет): отказ разрешается ПОЗИЦИЕЙ, а
 * не копией. Наша особенность — регистры гостя живут в памяти `ctx` на каждой команде,
 * поэтому реконструкция сводится к одному двоичному поиску по карте.
 *
 * Кадр (`hb_jit_signal_fault_frame_t`) остаётся: по нему обработчик сигнала узнаёт СВОИ
 * отказы (claim_calls=7924 за прогон HK 05.09 — все чужие, отклонены по кадру). */

/* Точных возобновлений и отказов, где карта не ответила. Второе число — единственное, что
 * решает, годна ли схема: ненулевое означает, что какой-то блок исполняется БЕЗ карты, и его
 * отказ переигрывается с входа (см. run_jit_block_with_signal_guard). */
static uint64_t t_resume_exact, t_resume_unresolved;

static void ripmap_selftest(const hb_block_cache_entry_t* e);

/* ★★★★★ MacRunner 2026-09-04 — УЧЁТ КАРТ: сколько записей КЕША её несут, сколько нет и почему.
 *
 * «Прибор молчит» здесь особенно опасно: карта отвечает молча и правдоподобно, а её ОТСУТСТВИЕ
 * до сегодня было неотличимо от «блок не спрашивали». Три причины отказа считаются порознь,
 * поэтому ноль в `g_ripmap_no_map` означает именно «карта есть у всех», а не «не считалось». */
static uint64_t g_ripmap_attached;      /* записей кеша с картой */
static uint64_t g_ripmap_no_map_overflow; /* > HB_CODEGEN_MAX_HOST_OFF команд в блоке */
static uint64_t g_ripmap_no_map_empty;    /* кодогенератор не записал ни одной точки */
static uint64_t g_ripmap_no_map_oom;      /* не хватило памяти под карту */
static uint64_t g_ripmap_released;        /* карт освобождено (сверка утечки: attached-released) */
/* Байты, занятые картами. Цена безусловной карты — единственное, чем она платит, и её надо
 * НАЗЫВАТЬ ЧИСЛОМ, а не «немного памяти»: 6 байт на команду блока плюс один заголовок
 * аллокатора. Счётчик накопительный (не убывает при освобождении) — он отвечает на вопрос
 * «сколько выделено за прогон», а живой объём считается как (attached-released)*средний. */
static uint64_t g_ripmap_bytes;

/* Освободить карту записи кеша.
 *
 * ★ ЗАЧЕМ ОТДЕЛЬНОЙ ФУНКЦИЕЙ, а не двумя free по месту. До сегодня освобождение стояло РОВНО
 * В ОДНОМ месте из четырёх, где запись кеша перестаёт описывать свой код:
 *   • block_cache_evict_entry           — освобождало (единственное);
 *   • block_cache_reset                 — НЕТ (а он зовётся раз на вложенный кадр run_x64,
 *                                          13777 раз за прогон ABZU) -> утечка;
 *   • block_cache_destroy               — НЕТ -> утечка;
 *   • ветка «Update existing entry» в block_cache_put — НЕТ, и это ХУЖЕ утечки: native_code и
 *     block заменяются, а СТАРАЯ карта остаётся. Двоичный поиск по ней вернул бы правдоподобный
 *     гостевой адрес ЧУЖОГО блока — тот самый неверный ответ, который счётчиком не отличить.
 * Пока карта строилась только под гейтом, ни одно из трёх не могло сработать в обычном прогоне.
 * Карта стала безусловной — значит закрываем все четыре одним местом. */
static void ripmap_release(hb_block_cache_entry_t* entry) {
    if (!entry) return;
    if (entry->host_off) { free(entry->host_off); g_ripmap_released++; }
    /* host_instr НЕ освобождается: он указывает В ТУ ЖЕ выделенную область (см. ripmap_attach). */
    entry->host_off = NULL;
    entry->host_instr = NULL;
    entry->host_off_count = 0;
}

/* Скопировать карту, записанную кодогенератором, в запись кеша — та живёт дольше буфера.
 *
 * ★★★ БЕЗУСЛОВНО с 04.09.2026. Прежде стояло `if (!ripmap_needed()) return;`, то есть в
 * обычном прогоне карты не было НИ У ОДНОГО блока, и «точный гостевой pc» был недоступен,
 * даже когда за него готовы были заплатить. Это вопрос ПРАВИЛЬНОСТИ (единственный способ
 * назвать команду, на которой отказ, внутри сцеплённой цепочки), а не скорости: при
 * исполнении карту не читает никто, она открывается только на пути отказа. Цена — память:
 * 6 байт на команду блока, разом (см. ниже), и один malloc на блок.
 *
 * ОДНО ВЫДЕЛЕНИЕ НА ОБЕ ТАБЛИЦЫ. Было два malloc; при 6 байтах полезных данных на команду
 * накладные расходы аллокатора (заголовок + округление) удваивались впустую. host_instr[]
 * кладётся сразу за host_off[]: выравнивание uint16_t не строже uint32_t, значит хвост
 * массива u32 годен под массив u16 по построению. Освобождает это ripmap_release. */
/* Карт, поднятых из ПОСТОЯННОГО кеша (хвост блоба), — отдельно от скомпилированных в
 * процессе: до 05.09.2026 блок из кеша карты НЕ ИМЕЛ вовсе, и на прогретом прогоне это
 * было большинство исполняемых блоков. Ноль здесь при ненулевых попаданиях кеша значит,
 * что хвост не читается, и точного возобновления у таких блоков нет. */
static uint64_t g_ripmap_from_cache;

static void ripmap_attach_raw(hb_block_cache_entry_t* entry,
                              const uint32_t* host_off, const uint16_t* host_instr,
                              uint16_t count, bool overflow) {
    size_t n, bytes;
    uint8_t* mem;
    if (!entry) return;
    /* Повторное занесение по тому же адресу переиспользует запись кеша: старую карту снимаем,
     * иначе при отказе выделения ниже осталась бы карта ПРЕДЫДУЩЕГО кода. */
    ripmap_release(entry);
    if (overflow) { g_ripmap_no_map_overflow++; return; }
    if (!count || !host_off || !host_instr) { g_ripmap_no_map_empty++; return; }
    n = (size_t)count;
    bytes = n * (sizeof(uint32_t) + sizeof(uint16_t));
    mem = (uint8_t*)malloc(bytes);
    if (!mem) { g_ripmap_no_map_oom++; return; }
    entry->host_off = (uint32_t*)(void*)mem;
    entry->host_instr = (uint16_t*)(void*)(mem + n * sizeof(uint32_t));
    memcpy(entry->host_off, host_off, n * sizeof(uint32_t));
    memcpy(entry->host_instr, host_instr, n * sizeof(uint16_t));
    /* Set last: the resolver takes a non-zero count as "both arrays are populated". */
    entry->host_off_count = count;
    g_ripmap_attached++;
    g_ripmap_bytes += bytes;
    ripmap_selftest(entry);
}

static void ripmap_attach(hb_block_cache_entry_t* entry, const hb_codegen_buffer_t* buf) {
    if (!entry || !buf) return;
    ripmap_attach_raw(entry, buf->host_off, buf->host_instr, buf->host_off_count,
                      buf->host_off_overflow);
}

/* ★★★★★ 05.09.2026 — КАРТА ЕДЕТ В ПОСТОЯННЫЙ КЕШ ХВОСТОМ БЛОБА.
 *
 * Зачем. Точное возобновление после отказа живёт картой `host_off -> instr`, а карта
 * строилась только кодогенератором. Блок, поднятый из translation-cache.bin, кода не
 * генерирует — и карты у него не было. На прогретом прогоне HK таких блоков большинство
 * (хранилище перевода — своё на руку, прогрев его заполняет), то есть без хвоста
 * «снимок снят» означало бы «большинство отказов переигрываются с входа блока».
 *
 * Укладка (всё little-endian, начало хвоста выровнено на 4):
 *   [код: code_size байт][набивка до 4]
 *   [uint32 host_off[n]][uint16 host_instr[n]][набивка до 4]
 *   [подвал 16 байт: uint32 'HBRM' | uint32 code_size | uint32 n | uint32 overflow]
 * Подвал читается с конца блоба; magic и арифметика сходятся — или блоб отвергается
 * целиком (перекомпиляция), никакого «карты нет, код возьмём». Версия ключа
 * HB_RUNTIME_PERSISTENT_CACHE_VERSION сдвинута, поэтому блоб без подвала этой сборке не
 * встречается по построению — но проверка стоит всё равно: она и есть отрицательный
 * контроль в приёмке (persistent_cache_blob_without_trailer_is_rejected). */
#define HB_RIPMAP_TRAILER_MAGIC 0x4d524248u   /* 'HBRM' */
#define HB_RIPMAP_FOOTER_BYTES  16u

static size_t ripmap_trailer_align4(size_t v) { return (v + 3u) & ~(size_t)3u; }

static bool ripmap_trailer_append(const uint8_t* code, size_t code_size,
                                  const hb_codegen_buffer_t* buf,
                                  uint8_t** out_blob, size_t* out_size) {
    size_t n, code_pad, map_bytes, total, pos;
    uint8_t* blob;
    uint32_t footer[4];
    if (!code || !code_size || !buf || !out_blob || !out_size) return false;
    n = buf->host_off_overflow ? 0u : (size_t)buf->host_off_count;
    code_pad = ripmap_trailer_align4(code_size);
    map_bytes = ripmap_trailer_align4(n * sizeof(uint32_t) + n * sizeof(uint16_t));
    total = code_pad + map_bytes + HB_RIPMAP_FOOTER_BYTES;
    blob = (uint8_t*)calloc(1, total);
    if (!blob) return false;
    memcpy(blob, code, code_size);
    pos = code_pad;
    if (n) {
        memcpy(blob + pos, buf->host_off, n * sizeof(uint32_t));
        memcpy(blob + pos + n * sizeof(uint32_t), buf->host_instr, n * sizeof(uint16_t));
    }
    pos += map_bytes;
    footer[0] = HB_RIPMAP_TRAILER_MAGIC;
    footer[1] = (uint32_t)code_size;
    footer[2] = (uint32_t)n;
    footer[3] = buf->host_off_overflow ? 1u : 0u;
    memcpy(blob + pos, footer, sizeof(footer));
    *out_blob = blob;
    *out_size = total;
    return true;
}

/* Разобрать хвост. Возврат false = блоб не наш или искалечен; тогда его нельзя исполнять. */
static bool ripmap_trailer_parse(const uint8_t* blob, size_t blob_size,
                                 size_t* code_size, const uint32_t** host_off,
                                 const uint16_t** host_instr, uint16_t* count,
                                 bool* overflow) {
    uint32_t footer[4];
    size_t n, cs, code_pad, map_bytes;
    if (!blob || blob_size < HB_RIPMAP_FOOTER_BYTES || !code_size) return false;
    memcpy(footer, blob + blob_size - HB_RIPMAP_FOOTER_BYTES, sizeof(footer));
    if (footer[0] != HB_RIPMAP_TRAILER_MAGIC) return false;
    cs = footer[1];
    n = footer[2];
    if (!cs || n > HB_CODEGEN_MAX_HOST_OFF || (footer[3] && n)) return false;
    code_pad = ripmap_trailer_align4(cs);
    map_bytes = ripmap_trailer_align4(n * sizeof(uint32_t) + n * sizeof(uint16_t));
    if (code_pad + map_bytes + HB_RIPMAP_FOOTER_BYTES != blob_size) return false;
    *code_size = cs;
    if (host_off)   *host_off   = n ? (const uint32_t*)(const void*)(blob + code_pad) : NULL;
    if (host_instr) *host_instr = n ? (const uint16_t*)(const void*)(blob + code_pad + n * sizeof(uint32_t)) : NULL;
    if (count)      *count      = (uint16_t)n;
    if (overflow)   *overflow   = footer[3] != 0;
    return true;
}

/* Поднять карту из блоба в запись кеша: копия (блоб освободят), счётчик отдельный. */
static void ripmap_attach_from_trailer(hb_block_cache_entry_t* entry, const uint8_t* blob,
                                       size_t blob_size) {
    size_t cs = 0; const uint32_t* ho = NULL; const uint16_t* hi = NULL;
    uint16_t n = 0; bool ov = false;
    uint32_t off_copy[HB_CODEGEN_MAX_HOST_OFF];
    uint16_t instr_copy[HB_CODEGEN_MAX_HOST_OFF];
    if (!entry || !ripmap_trailer_parse(blob, blob_size, &cs, &ho, &hi, &n, &ov)) return;
    /* Массивы в блобе выровнены только на 4/2 байта — копируем в выровненные буферы,
     * чтобы не полагаться на невыровненное чтение uint16_t в середине блоба. */
    if (n) { memcpy(off_copy, ho, n * sizeof(uint32_t)); memcpy(instr_copy, hi, n * sizeof(uint16_t)); }
    ripmap_attach_raw(entry, n ? off_copy : NULL, n ? instr_copy : NULL, n, ov);
    if (entry->host_off_count) g_ripmap_from_cache++;
}

uint64_t hb_jit_ripmap_from_cache(void) { return g_ripmap_from_cache; }

/* САМОПРОВЕРКА ХВОСТА — с отрицательным контролем внутри. Возврат 0 = всё сошлось:
 *   1. блоб, собранный append, разбирается parse в те же массивы и ту же длину кода;
 *   2. блоб с испорченным magic ОТВЕРГАЕТСЯ;
 *   3. усечённый блоб ОТВЕРГАЕТСЯ;
 *   4. блок с переполнением карты даёт n=0 и overflow=1 — «карты нет», а не мусор.
 * Ненулевой возврат называет номер шага. Зовётся из приёмки (hb_test_runner). */
int hb_jit_ripmap_trailer_selftest(void) {
    hb_codegen_buffer_t buf;
    uint8_t code[13] = { 1,2,3,4,5,6,7,8,9,10,11,12,13 };  /* нарочно не кратно 4 */
    uint8_t* blob = NULL; size_t blob_size = 0;
    size_t cs = 0; const uint32_t* ho = NULL; const uint16_t* hi = NULL; uint16_t n = 0; bool ov = true;
    uint32_t off[3]; uint16_t idx[3];
    memset(&buf, 0, sizeof(buf));
    buf.host_off[0] = 0;  buf.host_instr[0] = 0;
    buf.host_off[1] = 4;  buf.host_instr[1] = 1;
    buf.host_off[2] = 8;  buf.host_instr[2] = 3;   /* слияние: запись 2 -> команда 3 */
    buf.host_off_count = 3;
    if (!ripmap_trailer_append(code, sizeof(code), &buf, &blob, &blob_size)) return 1;
    if (!ripmap_trailer_parse(blob, blob_size, &cs, &ho, &hi, &n, &ov)) { free(blob); return 2; }
    if (cs != sizeof(code) || n != 3 || ov || !ho || !hi) { free(blob); return 3; }
    memcpy(off, ho, sizeof(off)); memcpy(idx, hi, sizeof(idx));
    if (off[0] != 0 || off[1] != 4 || off[2] != 8 || idx[0] != 0 || idx[1] != 1 || idx[2] != 3) { free(blob); return 4; }
    if (memcmp(blob, code, sizeof(code)) != 0) { free(blob); return 5; }
    /* отрицательный контроль 1: magic */
    blob[blob_size - HB_RIPMAP_FOOTER_BYTES] ^= 0x5a;
    if (ripmap_trailer_parse(blob, blob_size, &cs, NULL, NULL, NULL, NULL)) { free(blob); return 6; }
    blob[blob_size - HB_RIPMAP_FOOTER_BYTES] ^= 0x5a;
    /* отрицательный контроль 2: усечение на 4 байта — арифметика не сходится */
    if (ripmap_trailer_parse(blob, blob_size - 4, &cs, NULL, NULL, NULL, NULL)) { free(blob); return 7; }
    /* отрицательный контроль 3: блоб без хвоста вовсе (голый код) */
    if (ripmap_trailer_parse(code, sizeof(code), &cs, NULL, NULL, NULL, NULL)) { free(blob); return 8; }
    free(blob); blob = NULL;
    /* переполнение карты: карты нет, но блоб годен */
    buf.host_off_overflow = true;
    if (!ripmap_trailer_append(code, sizeof(code), &buf, &blob, &blob_size)) return 9;
    n = 7; ov = false;
    if (!ripmap_trailer_parse(blob, blob_size, &cs, &ho, &hi, &n, &ov)) { free(blob); return 10; }
    if (n != 0 || !ov || cs != sizeof(code)) { free(blob); return 11; }
    free(blob);
    return 0;
}

uint64_t hb_jit_ripmap_bytes(void) { return g_ripmap_bytes; }

void hb_jit_ripmap_stats(uint64_t* attached, uint64_t* released,
                         uint64_t* no_map_overflow, uint64_t* no_map_empty,
                         uint64_t* no_map_oom) {
    if (attached) *attached = g_ripmap_attached;
    if (released) *released = g_ripmap_released;
    if (no_map_overflow) *no_map_overflow = g_ripmap_no_map_overflow;
    if (no_map_empty) *no_map_empty = g_ripmap_no_map_empty;
    if (no_map_oom) *no_map_oom = g_ripmap_no_map_oom;
}

/* ГЕЙТ `MACRUNNER_HB_RIPMAP_SELFTEST`, умолчание ВЫКЛЮЧЕНО. Только приёмка и разбор.
 *
 * Зачем. Снимок контекста — самая дорогая статья перехода: 2832 байта, 41 131 пс (итерация 1).
 * Замена ему в дереве УЖЕ написана — восстановление гостевого адреса по карте (`ripmap`), и
 * гейт `MACRUNNER_HB_NO_SNAPSHOT` тоже есть. Не хватает единственного: доказательства, что
 * карта отвечает ВЕРНО. Пока его нет, переставлять умолчание нельзя — комментарий в самом
 * дереве говорит «never default this on».
 *
 * Разбор `ripmap_guest_for_host_pc` называет ровно две вещи, от которых зависит верность:
 *   1. `host_off` обязана быть неубывающей — иначе двоичный поиск даёт произвольный ответ;
 *   2. выбранный индекс берётся из `host_instr[best]`, а НЕ равен `best` (слияния команд их
 *      разводят). Ошибка здесь возвращает правдоподобный адрес ИЗ ТОГО ЖЕ блока — то есть
 *      такой, который счётчиком не отличить от верного.
 *
 * Поэтому проверка исчерпывающая и без единого отказа: для КАЖДОГО хостового смещения блока
 * (шаг 4 байта — длина команды ARM64) двоичный поиск сверяется с прямым перебором, и отдельно
 * проверяется монотонность. Расхождения считаются и печатаются с адресом блока.
 *
 * Отсутствие расхождений само по себе ничего не доказывало бы, поэтому счётчик проверенных
 * смещений печатается рядом: ноль проверенных смещений — это «окно не открылось», а не «верно».
 */
static int ripmap_selftest_enabled(void) {
    const char* s = hb_gate( HB_GATE_HB_RIPMAP_SELFTEST );
    int v = (s && *s) ? (atoi(s) != 0) : 0;
    return v;
}

static uint64_t g_ripmap_st_blocks, g_ripmap_st_offsets, g_ripmap_st_disorder, g_ripmap_st_mismatch;
/* Блоки, где указатель карты РАСХОДИТСЯ с номером команды (`host_instr[k] != k`). Это ровно
 * те блоки, в которых сработало слияние — то есть единственные, где ошибка «взять best вместо
 * host_instr[best]» проявилась бы. Нулевое значение означает, что опасное окно НЕ ОТКРЫВАЛОСЬ
 * и самопроверка про эту опасность не сказала НИЧЕГО. */
static uint64_t g_ripmap_st_fused_blocks;

static uint64_t ripmap_guest_for_host_pc(const hb_block_cache_entry_t* entry, uint64_t host_pc);

static void ripmap_selftest(const hb_block_cache_entry_t* e) {
    uint64_t base, off;
    size_t k;
    if (!ripmap_selftest_enabled()) return;
    if (!e || !e->host_off || !e->host_instr || !e->host_off_count || !e->block ||
        !e->native_code || !e->native_size)
        return;

    for (k = 1; k < e->host_off_count; k++)
        if (e->host_off[k] < e->host_off[k - 1]) {
            g_ripmap_st_disorder++;
            fprintf(stderr, "macrunner-hb-ripmap-БЕСПОРЯДОК: блок=0x%llx k=%zu %u < %u\n",
                    (unsigned long long)e->guest_addr, k,
                    (unsigned)e->host_off[k], (unsigned)e->host_off[k - 1]);
            break;
        }

    for (k = 0; k < e->host_off_count; k++)
        if (e->host_instr[k] != (uint16_t)k) { g_ripmap_st_fused_blocks++; break; }

    if (!g_ripmap_st_blocks) {
        /* Разбор ПЕРВОГО блока целиком — иначе про «расхождений N» приходится гадать, что
         * именно разошлось. Печатается один раз за прогон. */
        fprintf(stderr, "macrunner-hb-ripmap-разбор: блок=0x%llx команд=%u записей=%u выпуск=%zu Б\n",
                (unsigned long long)e->guest_addr, (unsigned)e->block->instr_count,
                (unsigned)e->host_off_count, e->native_size);
        for (k = 0; k < e->host_off_count && k < 8; k++)
            fprintf(stderr, "macrunner-hb-ripmap-разбор:   запись %zu смещение=%u команда=%u адрес=0x%llx\n",
                    k, (unsigned)e->host_off[k], (unsigned)e->host_instr[k],
                    (unsigned long long)(e->host_instr[k] < e->block->instr_count
                        ? e->block->instrs[e->host_instr[k]].guest_addr : 0));
    }

    base = (uint64_t)(uintptr_t)e->native_code;
    g_ripmap_st_blocks++;
    for (off = 0; off + 4 <= e->native_size; off += 4) {
        uint64_t got = ripmap_guest_for_host_pc(e, base + off);
        uint64_t ref = 0;
        /* ЭТАЛОН ДОЛЖЕН ПОВТОРЯТЬ НАМЕРЕНИЕ, А НЕ БЫТЬ СТРОЖЕ. Первая редакция отвечала
         * «неразрешимо», когда ни одна запись не покрывает смещение, — и дала 2048 «расхождений»
         * на смещениях 0..12. Разбор показал: это ПРОЛОГ блока, выпущенный до первой команды
         * гостя. Боевой код там возвращает адрес ПЕРВОЙ команды (у него `best` заведён нулём и
         * промах его не сбрасывает), и это верно по существу: в прологе ни одна команда гостя
         * ещё не выполнена, значит гость стоит на первой. Эталон приведён к тому же. */
        size_t best = 0;
        for (k = 0; k < e->host_off_count; k++)
            if ((uint64_t)e->host_off[k] <= off) best = k;
        if (e->host_instr[best] < e->block->instr_count)
            ref = e->block->instrs[e->host_instr[best]].guest_addr;
        g_ripmap_st_offsets++;
        if (got != ref) {
            g_ripmap_st_mismatch++;
            if (g_ripmap_st_mismatch <= 8)
                fprintf(stderr,
                        "macrunner-hb-ripmap-РАСХОЖДЕНИЕ: блок=0x%llx смещение=%llu "
                        "двоичный=0x%llx перебор=0x%llx\n",
                        (unsigned long long)e->guest_addr, (unsigned long long)off,
                        (unsigned long long)got, (unsigned long long)ref);
        }
    }
    /* Печать на степенях двойки И раз в 256: без первой мелкая повозка (десятки блоков) не
     * напечатала бы НИЧЕГО, и это читалось бы как «самопроверка не нашла ошибок», хотя на деле
     * она просто молчала. Ровно эта ловушка уже стоила прогона в наборе hb_test_runner. */
    if ((g_ripmap_st_blocks & (g_ripmap_st_blocks - 1)) == 0 ||
        (g_ripmap_st_blocks & 0xffu) == 0)
        fprintf(stderr,
                "macrunner-hb-ripmap-самопроверка: блоков=%llu смещений=%llu "
                "беспорядков=%llu расхождений=%llu блоков-со-слиянием=%llu\n",
                (unsigned long long)g_ripmap_st_blocks, (unsigned long long)g_ripmap_st_offsets,
                (unsigned long long)g_ripmap_st_disorder, (unsigned long long)g_ripmap_st_mismatch,
                (unsigned long long)g_ripmap_st_fused_blocks);
}

/* host_pc -> exact guest address of the instruction being executed, or 0 if unresolvable.
 *
 * ★ 04.09.2026: сам двоичный поиск переехал в hb_fault_point_index — он один на движок и
 * покрыт тестами (прежде здесь была вторая, отдельная его редакция; см. разбор у объявления).
 * Смещение до ПЕРВОЙ записи (пролог блока) поиск честно объявляет неразрешимым, а мы отвечаем
 * адресом первой команды: в прологе ни одна команда гостя ещё не исполнена, значит гость стоит
 * на ней. Это НЕ догадка — это единственное состояние, в котором пролог может быть прерван. */
/* ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ ПРИБОРА ТОЧНОСТИ — только для приёмки.
 *
 * `MACRUNNER_HB_TEST_RIPMAP_SKEW=1` заставляет резолвер отвечать ПРЕДЫДУЩЕЙ записью карты,
 * то есть называть команду на одну раньше отказавшей. Проба jit_fault_state_precision обязана
 * при этом покраснеть (возобновление повторит уже исполненную команду: rsp уедет на слот,
 * счётчик в памяти прирастёт дважды). Прибор, который не краснеет от заведомой порчи, — не
 * прибор. Имя с `_TEST_` — как у MACRUNNER_HB_TEST_FORCE_JIT_VERIFY_FAIL: это не гейт
 * поведения, а рычаг приёмки; в прогоне игры он не задан и стоит одно чтение таблицы на
 * ПУТИ ОТКАЗА, не на горячем. */
static int ripmap_test_skew(void) {
    const char* s = hb_gate( HB_GATE_HB_TEST_RIPMAP_SKEW );
    return (s && *s && *s != '0') ? 1 : 0;
}

/* Разрешить хозяйский pc в (адрес команды, её номер в блоке). Возврат 0 — «не знаю»:
 * карты нет, pc вне кода блока, индекс за пределами блока. Гостевой адрес 0 входом
 * блока не бывает, так что ноль различает «нет ответа» полностью. */
static uint64_t ripmap_resolve(const hb_block_cache_entry_t* entry, uint64_t host_pc,
                               size_t* instr_index) {
    size_t best = 0;
    uint16_t instr;
    uint64_t off;
    if (instr_index) *instr_index = 0;
    if (!entry || !entry->host_off || !entry->host_instr || !entry->host_off_count ||
        !entry->block)
        return 0;
    if (!entry->native_code || host_pc < (uint64_t)(uintptr_t)entry->native_code) return 0;
    off = host_pc - (uint64_t)(uintptr_t)entry->native_code;
    if (off >= entry->native_size) return 0;
    (void)hb_fault_point_index(entry->host_off, 1, entry->host_off_count,
                               (uint32_t)off, &best);
    if (best > 0 && ripmap_test_skew()) best--;   /* нарочная порча, см. выше */
    /* best indexes the MAP, not the instruction list -- the two diverge in any block where a
     * fusion fired, so the instruction index has to be read out of the map rather than assumed
     * equal to it. Getting this wrong returns a plausible-looking address from the same block,
     * which is exactly the kind of wrong answer a counter cannot flag as wrong. */
    instr = entry->host_instr[best];
    if (instr >= entry->block->instr_count) return 0;
    if (instr_index) *instr_index = instr;
    return entry->block->instrs[instr].guest_addr;
}

static uint64_t ripmap_guest_for_host_pc(const hb_block_cache_entry_t* entry, uint64_t host_pc) {
    return ripmap_resolve(entry, host_pc, NULL);
}

/* ★★★★★ MacRunner 2026-09-04 — ПОДКЛЮЧЕНИЕ ТАБЛИЦЫ К ДВИЖКУ.
 *
 * До сегодня «хозяйский pc -> гостевая команда» существовало в дереве ДВАЖДЫ и оба раза
 * вхолостую:
 *   • hb_fault.c (`point_lookup`, `hb_fault_classify`) — вызовы ТОЛЬКО из tests/hb_test_runner.c;
 *   • здешняя карта (`ripmap_*`) — строилась лишь под гейтом, резолвер был `static`, и снаружи
 *     спросить точный адрес было НЕЧЕМ: единственная публичная дверь
 *     (`hb_jit_runtime_native_block_info`) возвращает вход блока.
 * Здесь дверь открывается. Разбор ответов — у объявления в hb_runtime.h.
 *
 * Счётчики отвечают на вопрос «а спрашивали ли»: без них ноль точных ответов неотличим от
 * ноля обращений, и «прибор молчит» опять сошло бы за «явления нет». */
static uint64_t g_gpc_calls, g_gpc_exact, g_gpc_approx, g_gpc_outside;

/* Разбор отказов по тому, ЧТО удалось узнать о месте. Три исхода врозь: «карта ответила»,
 * «блок нашли, карты нет» и «блок не нашли вовсе» требуют разного лечения, а сумма их
 * молчала бы одинаково. */
static uint64_t g_fault_exact_hits, g_fault_exact_no_map, g_fault_exact_no_block;

void hb_jit_fault_pc_stats(uint64_t* exact, uint64_t* no_map, uint64_t* no_block) {
    if (exact) *exact = g_fault_exact_hits;
    if (no_map) *no_map = g_fault_exact_no_map;
    if (no_block) *no_block = g_fault_exact_no_block;
}

int hb_jit_runtime_guest_pc_for_host_pc(hb_jit_runtime_t* rt, uint64_t host_pc,
                                        hb_fault_result_t* out) {
    hb_block_cache_entry_t* entry;
    uint64_t guest;

    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    out->fault_class = HB_FAULT_CLASS_OUTSIDE;
    g_gpc_calls++;
    if (!rt || !host_pc) { g_gpc_outside++; return 0; }
    entry = block_cache_find_native_pc(rt->block_cache, host_pc);
    if (!entry) { g_gpc_outside++; return 0; }

    out->fault_class = HB_FAULT_CLASS_NATIVE_BLOCK;
    guest = ripmap_guest_for_host_pc(entry, host_pc);
    if (guest) {
        /* Ноль резолвер отдаёт и при «карты нет», и при «индекс за пределами блока», поэтому
         * ненулевое значение — единственный признак настоящего ответа. Гостевой адрес 0 входом
         * блока не бывает (ctx->pc == 0 в этом дереве всюду трактуется как «нет адреса»), так
         * что различение полное, а не приблизительное. */
        out->guest_pc = guest;
        out->guest_pc_exact = true;
        g_gpc_exact++;
        return 1;
    }
    /* Блок ЕСТЬ, но карты нет либо она не покрывает смещение: блок вытеснен и переставлен,
     * это блок-помощник (свёртка цикла, сравнение) либо в нём больше HB_CODEGEN_MAX_HOST_OFF
     * команд. Отдаём вход блока и ЯВНО помечаем как негодный для CONTEXT: тихая подмена
     * «вход блока» -> «точный pc» и есть тот неверный ответ, который счётчиком не поймать. */
    out->guest_pc = entry->guest_addr;
    out->guest_pc_approx = true;
    g_gpc_approx++;
    return 0;
}

void hb_jit_guest_pc_stats(uint64_t* calls, uint64_t* exact, uint64_t* approx,
                           uint64_t* outside) {
    if (calls) *calls = g_gpc_calls;
    if (exact) *exact = g_gpc_exact;
    if (approx) *approx = g_gpc_approx;
    if (outside) *outside = g_gpc_outside;
}

/* `ripmap_check` (сличение ответа карты с pc снимка под MACRUNNER_HB_RIPMAP) СНЯТА 05.09.2026
 * вместе со снимком: сличать стало не с чем. Её работу делает `ripmap_selftest` (полный
 * перебор смещений против прямого поиска) и проба `jit_fault_exact_resume_*` в приёмке —
 * та проверяет не совпадение двух наших ответов, а СОСТОЯНИЕ гостя после отказа против
 * интерпретатора. */

static void block_cache_evict_entry(hb_jit_runtime_t* rt, hb_block_cache_t* cache,
                                    hb_block_cache_entry_t* entry) {
    size_t idx;
    if (!cache || !entry || !entry->valid) return;
    idx = block_cache_entry_index(cache, entry);
    /* ПРИЧИНА ВЫСЕЛЕНИЯ: сброс по гостевому диапазону — самоизменяемый код и переход
     * страницы RW->RX. Это выселение по СМЕНЕ СОДЕРЖИМОГО, в отличие от повторного
     * перевода того же адреса выше. */
    if (unchain_stats_enabled())
        __atomic_add_fetch(&g_evict_reason[EVICT_RANGE], 1, __ATOMIC_RELAXED);
    if (runtime_block_chain_enabled())
        block_cache_prepare_replace_entry(rt, cache, entry);
    block_cache_release_owned_block(entry, NULL);
    ripmap_release(entry);
    memset(entry, 0, sizeof(*entry));
    if (cache->chain_meta && idx != SIZE_MAX)
        memset(&cache->chain_meta[idx], 0, sizeof(cache->chain_meta[idx]));
    if (cache->count) cache->count--;
}

/* ★★★ MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 987 — СБРОС ТРАНСЛЯЦИЙ ПО ГОСТЕВОМУ
 * ДИАПАЗОНУ (приказ 129).
 *
 * Зачем: аккуратный порождатель кода (Mono, .NET, всякий JIT) не пишет в исполняемую
 * страницу — он выделяет RW, пишет, переводит в RX и исполняет. Наше отслеживание требует
 * W и X ОДНОВРЕМЕННО, поэтому такую страницу не видит НИ В ОДНОЙ фазе, и после правки
 * исполняется устаревший перевод. Замер: `artifacts/smcvp.exe` даёт round2=1111 вместо 2222.
 *
 * Момент перехода RW -> RX известен точно — он приходит в перехват `VirtualProtect`
 * (`macrunner_hb.c:32171`), крючок стои́т с давних пор и до сих пор трансляции не сбрасывал.
 * Отсюда сброс БЕЗ единого отказа по записи: вся запись случается в фазе, когда страница
 * ещё не была кодом.
 *
 * Выселяем всё, чей гостевой диапазон пересекается с заданным. Слоты инлайн-кеша чистим
 * разом: выселенный блок мог лежать в них сырым адресом, и переход туда после освобождения
 * памяти — исполнение чужих байтов. */
/* MacRunner 2026-08-18 — БЕЗУСЛОВНЫЙ счёт инвалидаций.
 *
 * Прогон 2456 дал ноль строк `macrunner-hb-инвалидация`, но это НЕ ноль вызовов: та печать идёт
 * периодом в 200, значит молчание означает «меньше двухсот», а не «не было». Ровно эта подмена
 * за месяц шесть раз выдавала «механизм не работал» за «прибор не печатал». Счётчики ниже
 * инкрементируются всегда — два расслабленных сложения на редком пути, — и печатаются в момент
 * падения, где ноль читается как настоящий ноль. */
static uint64_t g_inval_calls;
static uint64_t g_inval_dropped;

unsigned long long macrunner_hb_inval_calls(void) {
    return (unsigned long long)__atomic_load_n(&g_inval_calls, __ATOMIC_RELAXED);
}

unsigned long long macrunner_hb_inval_dropped(void) {
    return (unsigned long long)__atomic_load_n(&g_inval_dropped, __ATOMIC_RELAXED);
}

/* Была ли инвалидация, накрывшая ИМЕННО сцепленный адрес. Проход по следу дорог (65 536 ячеек),
 * поэтому делается только при непустом выбросе — таких вызовов единицы. */
static uint64_t g_inval_hit_chained;

unsigned long long macrunner_hb_inval_hit_chained(void) {
    return (unsigned long long)__atomic_load_n(&g_inval_hit_chained, __ATOMIC_RELAXED);
}

uint64_t hb_jit_invalidate_guest_range(hb_jit_runtime_t* rt, uint64_t start, uint64_t len) {
    hb_block_cache_t* cache;
    uint64_t end = start + len;
    uint64_t dropped = 0;
    size_t i;
    if (!rt || !len) return 0;
    /* ★ 2026-08-18, итерация 2416 (приказ 191, Y1) — СЧИТАТЬ ВСЕ ОБРАЩЕНИЯ, А НЕ ТОЛЬКО УДАЧНЫЕ.
     *
     * Замер 2412 считал только вызовы, дошедшие до перебора кеша, и дал ноль печатей на Diablo.
     * FEX объясняет свою беду записями Mono в исполняемые страницы (разбор 2415), поэтому
     * считать надо КАЖДОЕ обращение к инвалидации, включая ранние выходы: без этого «редко»
     * может оказаться артефактом места, куда я поставил счётчик. Печать первых 3 и далее
     * периодом — по уроку 2400 (порог сам себя выдаёт за свойство явления). */
    {
        const char* v = hb_gate( HB_GATE_HB_INVAL_STATS );
        int гейт2 = (v && *v && *v != '0') ? 1 : 0;
        if (гейт2) {
            static _Thread_local uint64_t обращений, байт, период2;
            обращений++; байт += len;
            if (обращений <= 3 || ++период2 >= 500ul) {
                период2 = 0;
                fprintf(stderr, "macrunner-hb-инвал-вход: обращений=%llu байт=%llu средний_диапазон=%.0f\n",
                        (unsigned long long)обращений, (unsigned long long)байт,
                        обращений ? (double)байт / (double)обращений : 0.0);
                fflush(stderr);
            }
        }
    }
    cache = rt->block_cache;
    if (!cache || !cache->entries) return 0;
    for (i = 0; i < cache->size; i++) {
        hb_block_cache_entry_t* e = &cache->entries[i];
        uint64_t e_start, e_end;
        if (!e->valid) continue;
        e_start = e->smc_span_len ? e->smc_span_start : e->guest_addr;
        e_end   = e->smc_span_len ? e_start + e->smc_span_len : e_start + 1;
        if (e_end <= start || e_start >= end) continue;
        block_cache_evict_entry(rt, cache, e);
        dropped++;
    }
    __atomic_add_fetch(&g_inval_calls, 1, __ATOMIC_RELAXED);
    if (dropped) {
        uint32_t i;
        __atomic_add_fetch(&g_inval_dropped, dropped, __ATOMIC_RELAXED);
        for (i = 0; i < HB_CHAIN_SEEN_SLOTS; i++) {
            uint64_t a = __atomic_load_n(&g_chain_seen[i], __ATOMIC_RELAXED);
            if (a && a >= start && a < start + len) {
                __atomic_add_fetch(&g_inval_hit_chained, 1, __ATOMIC_RELAXED);
                break;
            }
        }
    }
    if (dropped) hb_ic_slots_clear_all();
    /* ★ 2026-08-18, лейн ЛЕСТНИЦА, итерация 2412 (приказ владельца 190) — СКОЛЬКО МЫ СБРАСЫВАЕМ.
     *
     * Две разведки дали противоположные советы про обратные списки связей: одна — заводить,
     * другая — не заводить и проверять годность при переходе. Владелец велел решать замером
     * НАШЕЙ нагрузки: много связей и редкий сброс → выгодны списки; мало связей и частый сброс
     * → выгодна проверка при входе.
     *
     * Здесь меряем вторую половину вопроса — ЧАСТОТУ сброса: сколько раз звали инвалидацию,
     * сколько блоков выбросили, и по какому диапазону. Гейт `MACRUNNER_HB_INVAL_STATS`,
     * печать периодом; на горячем пути только инкременты. */
    {
        const char* v = hb_gate( HB_GATE_HB_INVAL_STATS );
        int гейт = (v && *v && *v != '0') ? 1 : 0;
        if (гейт) {
            static _Thread_local uint64_t вызовов, выброшено, пусто, период;
                    вызовов++;
            выброшено += dropped;
            if (!dropped) пусто++;
            if (++период >= 200ul) {
                период = 0;
                fprintf(stderr,
                        "macrunner-hb-инвалидация: вызовов=%llu выброшено=%llu впустую=%llu "
                        "среднее=%.2f\n",
                        (unsigned long long)вызовов, (unsigned long long)выброшено,
                        (unsigned long long)пусто,
                        вызовов ? (double)выброшено / (double)вызовов : 0.0);
                fflush(stderr);
            }
        }
    }
    return dropped;
}

/* Returns the entry to dispatch, or NULL when the cached translation no
 * longer matches the current guest bytes (entry evicted; caller falls
 * through to the translate path). */
/* MacRunner 2026-07-28 — SMC re-lift gate.  Evicting the block-cache entry is only
 * HALF the invalidation: the lifted IR that the dispatch loop falls back to
 * (find_block(func->cfg, pc)) comes from macrunner_hb.c's address-keyed ir_cache,
 * which has no byte validation, so retranslating in place recompiles the SAME stale
 * IR and re-tracks it against the NEW bytes — permanently stale, silently.  See
 * reports/phase4-hollow-knight/HK-SMC-STALE-IR-CACHE-SECOND-CACHE-GAP-20260728.md.
 * With this gate an eviction EXITS the dispatch (like the "no block for PC" exit) so
 * the caller re-lifts from current bytes.  Kill switch MACRUNNER_HB_SMC_RELIFT=0. */
static uint64_t g_smc_relift_exits;
static uint64_t g_smc_relift_suppressed;

uint64_t hb_jit_smc_relift_exits(void) { return g_smc_relift_exits; }
/* ★ 2026-09-03 (режим D Diablo): ВТОРАЯ ПОЛОВИНА инвалидации. Выселение записи кеша блоков не трогает
 * pc-ключевой кеш функций IR в hb_wow64cpu.c (там нет проверки байтов) — после выхода «на перелифт» цикл
 * wow64 брал из него ту же устаревшую функцию. Отдаём наружу последний выселенный диапазон и счётчик;
 * цикл wow64 по ним снимает записи, накрывающие страницу выселенного блока. */
static uint64_t g_smc_last_evict_addr; static uint32_t g_smc_last_evict_len;
uint64_t hb_jit_smc_evicted_total(void) { return g_smc_evicted; }
void hb_jit_smc_last_evicted(uint64_t* addr, uint32_t* len) { if (addr) *addr = g_smc_last_evict_addr; if (len) *len = g_smc_last_evict_len; }
uint64_t hb_jit_smc_relift_suppressed(void) { return g_smc_relift_suppressed; }

/* MacRunner 2026-07-28 — LIVELOCK GUARD on the re-lift exit.
 * An eviction is only *believed* to mean "the guest rewrote this code".  A hash
 * mismatch can also arise without any guest write (the span's host backing moved,
 * an overlapping remap, an unstable read).  If such a mismatch reproduces after the
 * re-lift, the outer loop would exit → re-lift → exit forever with ZERO steps
 * executed: a thread that is alive, running and never advancing — precisely the bug
 * this fix exists to remove.  NOT observed; this is insurance against an unproven
 * failure mode, and it is deliberately cheap.  hb_test_runner cannot exercise it at
 * all (whole-suite totals: evicted=0 relift_exits=0), so the exit path is unvalidated
 * by unit test — see HK-SMC-RELIFT-UNIT-CONTROL-INCONCLUSIVE-20260728.md.
 *
 * Guard: only ZERO-PROGRESS exits accumulate a streak.  Any exit that follows real
 * forward progress (steps > 0) resets it, so a legitimate rewrite-heavy workload —
 * Mono patching call sites between blocks — is never throttled.  After
 * SMC_RELIFT_MAX_CONSECUTIVE zero-progress exits we stop exiting and fall through to
 * the pre-fix in-place retranslate: degraded (possibly stale) rather than wedged. */
#define SMC_RELIFT_MAX_CONSECUTIVE 8
static __thread unsigned g_smc_relift_streak;

static bool smc_relift_should_exit(uint64_t steps) {
    if (steps > 0) {              /* progress was made: this is not a livelock */
        g_smc_relift_streak = 0;
        g_smc_relift_exits++;
        return true;
    }
    if (g_smc_relift_streak >= SMC_RELIFT_MAX_CONSECUTIVE) {
        g_smc_relift_suppressed++;
        return false;
    }
    g_smc_relift_streak++;
    g_smc_relift_exits++;
    return true;
}

static hb_block_cache_entry_t* smc_reverify_entry(hb_jit_runtime_t* rt,
                                                  hb_block_cache_entry_t* entry,
                                                  bool* evicted) {
    uint64_t now;
    /* ★ 2026-08-18, лейн ЛЕСТНИЦА, итерация 2419 — ЦЕНА СВЕРКИ ХЕША.
     *
     * Замер 2418: у HK 2593 сверки за 228 с и 16 выселений. FEX жалуется именно на сверку
     * («значительная инвалидация и рывки»), а не на число выселений, поэтому меряем ВРЕМЯ.
     * Приём тот же, что дал ответ по SBB (2403): mach_absolute_time вокруг тела, за гейтом
     * `MACRUNNER_HB_SMC_TIME` — два чтения часов на сверку сами по себе цена. */
    uint64_t smc_t0 = 0;
    const char* v = hb_gate( HB_GATE_HB_SMC_TIME );
    int smc_time_gate = (v && *v && *v != '0') ? 1 : 0;
    if (smc_time_gate) smc_t0 = mach_absolute_time();
    if (evicted) *evicted = false;
    if (!entry || !entry->smc_hash) return entry;
    g_smc_reverified++;
    /* Positive-liveness aggregate: proves the instrument is executing even when
     * nothing is ever evicted ("not logged" != "did not happen").  Bounded:
     * first track, 1000th track, then every 2^24 reverifications. */
    if (smc_trace_enabled() &&
        (g_smc_reverified == 1 || g_smc_reverified == 1000 ||
         (g_smc_reverified & 0xffffffu) == 0))
        fprintf(stderr,
                "macrunner-hb-smc-reverify: progress tracked=%llu reverified=%llu "
                "evicted=%llu unreadable=%llu\n",
                (unsigned long long)g_smc_tracked, (unsigned long long)g_smc_reverified,
                (unsigned long long)g_smc_evicted, (unsigned long long)g_smc_unreadable);
    /* Итерация 979: БЫСТРОЕ ПРИНЯТИЕ. Если страница защищена и её поколение не менялось с
     * момента постановки отпечатка, записи в неё не было — хешировать нечего. Расхождение
     * поколений НЕ означает, что блок изменился (страница крупнее блока), поэтому дальше
     * идёт прежний хеш, и он остаётся полномочным судьёй. */
    if (entry->smc_gen_valid && hb_smc_protect_enabled()) {
        void* hp = hb_memory_host_ptr(rt->ctx->memory, entry->smc_span_start, 1, HB_PERM_READ);
        /* ★★★ MacRunner 2026-08-16, лейн ПАМЯТЬ, итерация 18 — ВОЗВРАТ ПРАВА ИСПОЛНЕНИЯ.
         *
         * Это вторая половина самоизменения, та самая, про которую в моём же отчёте стояло
         * «вернуть право исполнения некому». Теперь есть и место, и доказательство.
         *
         * Механика. `hb_smc_handle_write_fault` (hb_memory.c:271) при записи гостя отпускает
         * страницу в `R|W` — с `R|W|X` платформа отказывает EACCES, это W^X. Страница остаётся
         * БЕЗ права исполнения, и раньше вернуть его было некому. Но `hb_smc_arm_page`
         * (hb_memory.c:190) ставит ровно `PROT_READ|PROT_EXEC` — то есть повторное взведение
         * И ЕСТЬ возврат исполнения. Не хватало только вызвать его на входе в блок.
         *
         * Что доказано пробой `tests/pamyat_smc_exec_restore.c` (16.08), без прогона игры:
         *     R|X -> исполнение прошло -> R|W -> переписали код -> R|X -> исполнение ПРОШЛО
         *     прямой R|W|X            -> EACCES (W^X)
         * То есть чередование работает, и команда после возврата исполняется. Проба кладёт
         * настоящий `ret` и ВЫЗЫВАЕТ его — иначе «mprotect вернул 0» ничего бы не значило.
         *
         * Вызов идемпотентен: если страница уже взведена, `arm_page` возвращает 1, ничего не
         * делая. Работа добавляется только после ЗАПИСИ гостя в кодовую страницу, то есть редко.
         * Гейт прежний — `hb_smc_protect_enabled()`, по умолчанию ВЫКЛ, отдельного не завожу.
         *
         * ЧЕГО НЕ ДОКАЗАНО: что окно между записью и этим вызовом никогда не задевает гостя.
         * Здесь блок только входит в исполнение, значит право нужно ИМЕННО сейчас; но замерить
         * это можно лишь приёмочным прогоном с включённым гейтом. */
        if (hp) {
            static unsigned long long g_smc_reexec;
            if (hb_smc_arm_page(hp) && (++g_smc_reexec <= 8 || (g_smc_reexec & 0xffffu) == 0))
                fprintf(stderr, "macrunner-hb-smc-reexec: страница взведена заново host=%p всего=%llu\n",
                        hp, (unsigned long long)g_smc_reexec);
        }
        /* Итерация 984: быстрое принятие ВРЕМЕННО отключено — оно коротило путь, и хеш не
         * считался вовсе (выселений 0). Печатаем состояние и проваливаемся к хешу, чтобы
         * увидеть права страницы в момент, когда изменение УЖЕ произошло. */
        { static int said_fa;
          if (said_fa++ < 4 && hp) {
              fprintf(stderr, "macrunner-hb-smc-check: guest=0x%llx host=%p prot=%d "
                      "поколение_страницы=%u отпечаток=%u\n",
                      (unsigned long long)entry->smc_span_start, hp,
                      hb_smc_query_prot((uint64_t)(uintptr_t)hp),
                      hb_smc_page_generation((uint64_t)(uintptr_t)hp), entry->smc_gen);
              fflush(stderr);
          } }
    }
    now = smc_hash_current(rt, entry->smc_span_start, entry->smc_span_len);
    if (!now) { g_smc_unreadable++; return entry; }
    if (now == entry->smc_hash) return entry;
    /* Итерация 984: хеш РАЗОШЁЛСЯ — гость точно записал. Спрашиваем права страницы ИМЕННО
     * СЕЙЧАС: если 5 (READ|EXECUTE), защита стояла и запись должна была дать отказ, которого
     * не было; если 7 — право записи кто-то вернул до записи гостя. */
    if (hb_smc_protect_enabled()) {
        static int said_p;
        if (said_p++ < 4) {
            void* hp = hb_memory_host_ptr(rt->ctx->memory, entry->smc_span_start, 1, HB_PERM_READ);
            fprintf(stderr, "macrunner-hb-smc-prot-at-evict: guest=0x%llx host=%p prot=%d\n",
                    (unsigned long long)entry->smc_span_start, hp,
                    hp ? hb_smc_query_prot((uint64_t)(uintptr_t)hp) : -2);
            fflush(stderr);
        }
    }
    g_smc_evicted++;
    g_smc_last_evict_addr = entry->guest_addr; g_smc_last_evict_len = entry->smc_span_len;
    /* ★ 2026-09-03: безусловная печать первых 8 выселений и каждого 256-го — прямое свидетельство,
     * что самоизменение поймано (режим D: ждём guest=0x0646xxxx — драйвер SCode Storm). */
    if (g_smc_evicted <= 8 || (g_smc_evicted & 0xffu) == 0)
        fprintf(stderr, "macrunner-hb-smc-выселение: n=%llu guest=0x%llx span=%u old=%016llx new=%016llx\n",
                (unsigned long long)g_smc_evicted, (unsigned long long)entry->guest_addr, entry->smc_span_len,
                (unsigned long long)entry->smc_hash, (unsigned long long)now);
    /* Выселенный блок мог лежать в пер-сайтовых слотах инлайн-кеша сырым нативным
     * адресом. Не почистить — значит оставить переход в освобождённую память. Слотов
     * десятки тысяч, а выселения редки, поэтому чистим все разом, без учёта того,
     * какой именно слот держал этот блок. */
    hb_ic_slots_clear_all();
    if (smc_trace_enabled() &&
        (g_smc_evicted <= 16 || (g_smc_evicted & 0xffffu) == 0))
        fprintf(stderr,
                "macrunner-hb-smc-reverify: evict guest=0x%llx span=%u old=%016llx "
                "new=%016llx evicted=%llu reverified=%llu\n",
                (unsigned long long)entry->guest_addr, entry->smc_span_len,
                (unsigned long long)entry->smc_hash, (unsigned long long)now,
                (unsigned long long)g_smc_evicted, (unsigned long long)g_smc_reverified);
    block_cache_evict_entry(rt, rt->block_cache, entry);
    if (evicted) *evicted = true;
    if (smc_time_gate && smc_t0) {
        static _Thread_local uint64_t такты, штук, период;
        такты += mach_absolute_time() - smc_t0; штук++;
        if (++период >= 500ul) {
            период = 0;
            fprintf(stderr, "macrunner-hb-smc-время: сверок=%llu тактов=%llu среднее=%.2f\n",
                    (unsigned long long)штук, (unsigned long long)такты,
                    штук ? (double)такты / (double)штук : 0.0);
            fflush(stderr);
        }
    }
    return NULL;
}

/* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1105 — ГЕЙТЫ ВИДА Б МЕНЯЮТ IR, ЗНАЧИТ И КЛЮЧ.
 *
 * ИСТОРИЯ: три гейта приёмки (`FENCE_I386`, `UD_DELIVERY`, `PUSH_SEG_X64`) сидели
 * в ЛИФТЕРЕ и при погашении давали ДРУГОЙ IR на тех же байтах, поэтому их значения
 * пришлось вносить в ключ кэша. 02.09.2026 они сняты: выключенная ветка отдавала
 * «неподдержанный опкод» на верно разобранной команде — заведомо сломанное
 * поведение, которому выключатель не нужен. Правило ниже остаётся в силе для
 * ОСТАЛЬНЫХ гейтов вида Б.
 * сидят в ЛИФТЕРЕ: при погашенном гейте те же байты гостя дают ДРУГОЙ IR. Ключ постоянного кэша
 * считается по байтам, разрядности и номеру версии — то есть у двух армов он совпал бы, и второй
 * арм подхватил бы чужую трансляцию. Это не разброс, это подмена измеряемого: арм «выключено»
 * втихую исполнял бы код, выпущенный армом «включено».
 *
 * Правило приёмки «чистить кэш перед каждым армом» записано в ГЕЙТЫ-ПРИЁМКИ.md, но правило,
 * оставшееся прозой, игнорируется — это уже проверено на самом лейне (весь день 05.08 прогоны
 * шли мимо преполёта, хотя правило было написано 01.08). Поэтому защита ставится в код: каждый
 * погашенный гейт сдвигает номер версии, и записи разных армов физически не встречаются.
 *
 * Гейт MXCSR сюда НЕ входит намеренно: он читается в помощнике во время исполнения и IR не
 * меняет (в `hb_arm64_codegen.c` слова `mxcsr` нет ни разу — преобразования уходят в помощника). */
/* ★★★ НОМЕР СЧИТАЕТСЯ СВЁРТКОЙ, А НЕ СУММОЙ СТЕПЕНЕЙ ДВОЙКИ (лейн РЕГИСТРЫ, 22.08).
 *
 * Прежняя схема давала каждому гейту слагаемое 1000·2^n. На 22 гейтах она ИСЧЕРПАНА и была
 * уже неисправна — оба дефекта измерены, а не предположены:
 *
 *   ПЕРЕПОЛНЕНИЕ. Сумма всех приращений 4 194 303 000 плюс стамп раскладки до 1 024 000 000
 *   даёт 5 218 303 000 при потолке unsigned 4 294 967 295 — на 923 335 705 выше. Сочетание
 *   гейтов могло завернуться и совпасть с ДРУГИМ сочетанием. Вдобавок результат клался в
 *   `int cached`, куда значения выше 2^31 не помещаются вовсе.
 *
 *   НАЛОЖЕНИЕ НА СТАМП РАСКЛАДКИ. Стамп добавляет k·1 000 000, k∈[1,1024]; в единицах по 1000
 *   это k·1000, а гейты дают 22-битное число в ТЕХ ЖЕ единицах. Значит разница гейтов ровно
 *   в 1000·Δk неотличима от сдвига раскладки на Δk. Комментарий ниже утверждал, что
 *   пересечения нет («гейты до 1 023 000»): это было верно на десяти гейтах и перестало быть
 *   верным на одиннадцатом — молча, потому что утверждение осталось прозой и никем не
 *   проверялось.
 *
 * Здесь вместо суммы — свёртка FNV-1a по парам «имя гейта, его состояние». Гейтов может быть
 * сколько угодно, наложения на раскладку нет по построению, и новый гейт больше не требует
 * помнить свободную степень двойки.
 *
 * СОСТОЯНИЕ ТРОИЧНОЕ: не задан / «0» / прочее. Именно троичное: у `MACRUNNER_HB_FORCE_LAZY_LOAD`
 * и `..._STORE` «не задан» и «0» дают РАЗНЫЙ выпуск — установлено замером (сличение снимков
 * выпуска), а не прочтением кода. Двоичная схема эти состояния склеила бы.
 *
 * ЦЕНА, которую надо знать вслух. (1) Гейт, выставленный ЯВНО в своё умолчание, даёт номер,
 * отличный от незаданного, — лишний холодный кеш, но НЕ порча: разные номера безопасны всегда,
 * опасны одинаковые. (2) Свёртка может совпасть с вероятностью ~2^-32 на пару сочетаний, тогда
 * как прежняя схема на своих 22 битах была ТОЧНОЙ. Обмен сознательный: точность на 22 битах не
 * растягивается на 38 гейтов, а 2^-32 ниже любого другого риска в этом месте. */
#define HB_KEY_FNV_PRIME 0x100000001b3ull
        /* Гейты, снятые 02.09.2026, убраны и отсюда: держать в ключе кэша
         * переменные, которые больше ничего не меняют, значит зря дробить кэш. */
#define HB_KEY_GATE(name) do {                                                     \
        const char* g_ = hb_env(name);                                             \
        unsigned st_ = (!g_ || !*g_) ? 0u : (*g_ == '0' ? 1u : 2u);                \
        const char* p_;                                                            \
        for (p_ = (name); *p_; ++p_)                                               \
            mix = (mix ^ (uint64_t)(unsigned char)*p_) * HB_KEY_FNV_PRIME;         \
        mix = (mix ^ (uint64_t)st_) * HB_KEY_FNV_PRIME;                            \
    } while (0)

static unsigned persistent_cache_version(void) {
    static int cached = -1;
    if (cached < 0) {
        uint64_t mix = 0xcbf29ce484222325ull;   /* смещение FNV-1a */
        mix = (mix ^ (uint64_t)HB_RUNTIME_PERSISTENT_CACHE_VERSION) * HB_KEY_FNV_PRIME;
        /* ★★★ 06.09.2026, лейн КЕШ — ОТПЕЧАТОК СБОРКИ В НОМЕР.
         *
         * Всё, что было в номере до этой строки, — величины ВРЕМЕНИ ИСПОЛНЕНИЯ (гейты) и
         * ОДНА величина времени компиляции (раскладка `hb_context_t`, слагаемое `lay` ниже).
         * Самой СБОРКИ в номере не было. Значит две разные сборки движка при одинаковых
         * гейтах и неизменной раскладке давали ОДИН номер — и записи одной подходили другой
         * по ключу. Правка кодогенератора, не сдвинувшая ни гейт, ни раскладку (а таких
         * большинство: другая последовательность команд на тот же смысл), оставалась
         * НЕВИДИМОЙ для ключа.
         *
         * Разделение по сборкам держалось на вызывающем: `scripts/laneA-run-hk.sh:9-12`
         * делает корень по SHA ntdll.so. Но лейны A/B задают корень СВОИМ именем
         * (`flagi-ZAM-0`, `nm-on`, `chainx64b-ct1-s0`), и такой корень переживает пересборку.
         *
         * `hb_build_stamp` — md5 СОДЕРЖИМОГО исходников движка, порождается Makefile'ом и
         * уже печатается первой строкой прогона (`macrunner-hb-сборка: отпечаток=`). Отсюда
         * два следствия: чужая запись не подойдёт по ключу, а журнал прогона называет ту же
         * сборку, что и ключ, — сверять можно ГЛАЗАМИ, не веря на слово.
         *
         * ЦЕНА, названная вслух: любая правка ЛЮБОГО исходника hyperbridge (хоть комментария
         * в hb_bench.c) обнуляет постоянный кеш. Первый прогон после правки — холодный.
         * По замеру 06.09 это 3,2 с из ~34 с до вехи; неверный выпуск из чужой сборки стоит
         * дороже в любом исчислении, и главное — он не виден. */
        {
            extern const char hb_build_stamp[];   /* ПОРОЖДАЕТСЯ сборкой, см. STAMP_C */
            const char* p;
            for (p = hb_build_stamp; *p; ++p)
                mix = (mix ^ (uint64_t)(unsigned char)*p) * HB_KEY_FNV_PRIME;
        }
        /* FENCE_I386 / UD_DELIVERY / PUSH_SEG_X64 убраны из ключа 02.09.2026 вместе
         * с самими гейтами: команды разбираются всегда, разных IR на одних и тех
         * же байтах больше не бывает, и держать в ключе переменные, которые ничего
         * не меняют, значит зря дробить кэш. */
        /* MacRunner 2026-08-18, лейн РЕГИСТРЫ — ЗАКРЕПЛЕНИЕ РЕГИСТРОВ В КЛЮЧ КЕША.
         *
         * Гейты, влияющие на ВЫПУСК, уже кодируются в ключе: `runtime_jit_flags()` держит семь
         * штук (прямая память, прямой стек, сцепление, инлайн-кеш, memmove), плюс отдельный бит
         * режима блобов. Закрепление регистров меняет выпуск не меньше — а в ключ не входило.
         *
         * Чем это грозило. (1) Замер: блок, переведённый с закреплением, лежит под ключом,
         * неотличимым от обычного, и «контрольная» рука A/B молча исполняла бы закреплённый код.
         * Ровно от этого стоит соседний комментарий: «две руки A/B не могут делить записи».
         * (2) ПРАВИЛЬНОСТЬ: решение закреплять зависит ещё и от того, откатывает ли путь отказа
         * состояние гостя (`hb_runtime_fault_rolls_back_state`). Блок, закреплённый в процессе,
         * где откат был, мог бы подняться из кеша в процессе с `MACRUNNER_HB_NO_SNAPSHOT=1`,
         * где закрепление НЕБЕЗОПАСНО, — и вето уже ничем не поможет, решение принято раньше и
         * в другом процессе. Поэтому в версию входят и три гейта отката.
         *
         * Все пять сдвигают номер, то есть записи разных сочетаний физически не встречаются. */
        HB_KEY_GATE("MACRUNNER_HB_STATIC_REGS");
        /* 05.09.2026: три гейта отката (NO_SNAPSHOT, CHAIN_SCOPED_ROLLBACK,
         * SNAPSHOT_MEASURE_SKIP) удалены вместе со снимком — отката больше нет ни в одном
         * процессе, и «блок, закреплённый при откате» невозможен. Вместо них версию сдвинул
         * HB_RUNTIME_PERSISTENT_CACHE_VERSION: у блоба появился хвост с картой отказов. */
        /* Маска разрядности одной командой (MACRUNNER_HB_MASK_IMM) меняет ВЫПУСК: там, где
         * было movz+and, стоит одна ubfm. Блоки двух видов самосогласованы каждый по себе,
         * но смешивать их в одном файле кеша незачем — и, главное, замер обеих рук обязан
         * идти по РАЗНЫМ записям, иначе вторая рука поднимет выпуск первой и померит её. */
        HB_KEY_GATE("MACRUNNER_HB_MASK_IMM");
        /* Таблица помощников (MACRUNNER_HB_HELPER_TABLE) тоже меняет ВЫПУСК: вместо
         * четырёхсловной укладки адреса стоит одно чтение по смещению от ctx. Смещение
         * зависит от РАСКЛАДКИ hb_context_t, то есть от сборки, — тем более записи двух
         * видов не должны встречаться в одном файле кеша. */
        HB_KEY_GATE("MACRUNNER_HB_HELPER_TABLE");
        HB_KEY_GATE("MACRUNNER_HB_SHARED_EPILOGUE");
        HB_KEY_GATE("MACRUNNER_HB_CTX_ARG_REUSE");
        HB_KEY_GATE("MACRUNNER_HB_CBZ_FOLD");
        /* Проверка масок записей помощника (лейн РЕГИСТРЫ, итерация 120) меняет ВЫПУСК:
         * цель `blr` становится проверяющей обёрткой вместо самого помощника. Обёртка
         * внутренняя, реестр её не знает — такие блоки в постоянный кеш не лягут, и это
         * правильно. В версию гейт входит, чтобы записи двух видов физически не встречались. */
        HB_KEY_GATE("MACRUNNER_HB_SRA_MASK_VERIFY");
        /* Маска записей помощника в перечитывании (итерация 121) меняет ВЫПУСК: после вызова
         * перечитывается меньше регистров. Умолчание ВКЛ — сдвигает ВЫКЛЮЧЕНИЕ, как у
         * MACRUNNER_HB_STATIC_REGS_CALLS. */
        /* Нативный выпуск NOT (итерация 129) меняет ВЫПУСК: вместо вызова помощника три
         * команды. Блок при этом теряет вызов, а значит и банк закрепления другой — записи
         * двух видов в одном файле кеша смешивать нельзя. */
        HB_KEY_GATE("MACRUNNER_HB_NATIVE_NOT");
        /* Пара вместо двух записей масок ленивых флагов (итерация 133) меняет ВЫПУСК. */
        HB_KEY_GATE("MACRUNNER_HB_LAZY_STP_MASKS");
        /* MacRunner 2026-08-23, КООРДИНАТОР — ДВА ГЕЙТА ВЫПУСКА, КОТОРЫХ В КЛЮЧЕ НЕ БЫЛО.
         *
         * Оба меняют ВЫПУЩЕННЫЙ КОД, а в ключ не входили. Значит блок, переведённый ими,
         * лежал под ключом, неотличимым от обычного, и «контрольная» рука подняла бы
         * правленый код из кеша. Поймано при замере байтовых чтений: две руки на разных
         * корнях давали одинаковые числа, потому что вторая читала чужие трансляции.
         *
         * Слито 23.08 на схему HB_KEY_GATE лейна РЕГИСТРЫ: она свёртывает имя и состояние
         * (нет / =0 / включён), поэтому масштабируется на 40 гейтов, тогда как прежние
         * уникальные веса упирались в 22 бита. MACRUNNER_HB_JIT_NATIVE_MEM_IR в их списке
         * уже был — добавлены только два недостающих. */
        HB_KEY_GATE("MACRUNNER_HB_NATIVE_MEM_I386");
        HB_KEY_GATE("MACRUNNER_HB_NATIVE_MEM_BYTE_LOADS");
        /* Постоянные ленивых флагов из таблицы (итерация 135) меняют ВЫПУСК. */
        HB_KEY_GATE("MACRUNNER_HB_LAZY_CONST_TABLE");
        /* Снятие лишней маски с непосредственных (итерация 141) меняет ВЫПУСК. */
        HB_KEY_GATE("MACRUNNER_HB_IMM_NO_REMASK");
        /* ★ СРАЩИВАНИЕ CMP/SUB/TEST + Jcc (MACRUNNER_HB_JCC_FUSE_FULL) меняет ВЫПУСК: вместо
         * вызова hb_jit_helper_eval_cond_lazy стоят SUBS/ANDS и b.cond по РОДНЫМ NZCV.
         * В ключе его НЕ БЫЛО — найдено лейном РЕГИСТРЫ 22.08 (итерация 143) наблюдением:
         * версия не двигалась при включённом гейте. Это тот же пробел, что итерация 23
         * закрывала для пяти гейтов закрепления: записи сращённые и несращённые ложились бы
         * под ОДИН ключ, и контрольная рука A/B подняла бы чужой выпуск. */
        HB_KEY_GATE("MACRUNNER_HB_JCC_FUSE_FULL");

        /* ★ СНЯТИЕ МЁРТВЫХ ЗАПИСЕЙ ЛЕНИВЫХ ФЛАГОВ (MACRUNNER_HB_DEADLAZY_SKIP) меняет ВЫПУСК:
         * второй проход не выпускает записи, помеченные разбором первого. Гейт УЧЁТА
         * (MACRUNNER_HB_DEADLAZY_COUNT) в ключе намеренно ОТСУТСТВУЕТ — он не меняет ни слова,
         * и его внесение дало бы ложные промахи кеша. */
        HB_KEY_GATE("MACRUNNER_HB_DEADLAZY_SKIP");

        /* ★ ПЕРЕХОД ПО РЕГИСТРУ ВМЕСТО ПАРЫ CMP+B.cond (MACRUNNER_HB_CBZ_BRANCH, лейн
         * ФЛАГИ-ЖИВОСТЬ 07.09) меняет ВЫПУСК: ядро предиката становится одной командой
         * CBZ/CBNZ. Умолчание у него 1, поэтому в ключе он нужен ровно затем, чтобы рука
         * A/B с гейтом 0 не поднимала записи, выпущенные рукой с гейтом 1. */
        HB_KEY_GATE("MACRUNNER_HB_CBZ_BRANCH");
        /* ★ ЗНАКОВОЕ УСЛОВИЕ ЧЕРЕЗ TBZ/TBNZ (MACRUNNER_HB_TBZ_BRANCH, лейн ФЛАГИ-ЖИВОСТЬ
         * 07.09) меняет ВЫПУСК: пара «производитель + JS/JNS» перестаёт уходить к
         * помощнику и сращивается. Умолчание 1; в ключе нужен ради A/B. */
        HB_KEY_GATE("MACRUNNER_HB_TBZ_BRANCH");
        /* ★ ТАБЛИЦА УСЛОВИЙ ЛОГИЧЕСКОГО ПРОИЗВОДИТЕЛЯ (MACRUNNER_HB_LOGIC_CC_MAP,
         * лейн ФЛАГИ-ЖИВОСТЬ 07.09) меняет ВЫПУСК: восемь условий после TEST/AND/OR/XOR
         * либо переименовываются, либо становятся постоянными и проверка исчезает.
         * Умолчание 1; в ключе нужен ради A/B. */
        HB_KEY_GATE("MACRUNNER_HB_LOGIC_CC_MAP");

        /* ★ ЖИВОСТЬ ФЛАГОВ ПО БИТАМ (MACRUNNER_HB_FLAG_LIVENESS_CFG, лейн ФЛАГИ-ЖИВОСТЬ
         * 07.09) меняет ВЫПУСК, но ТОЛЬКО когда открыт сам MACRUNNER_HB_FLAG_LIVENESS —
         * то есть это ровно тот класс подчинённого гейта, который сплошной перебор в один
         * слой объявляет несуществующим (так 22.08 едва не потеряли FLAG_LIVENESS_AF).
         * Вносится по этой причине сразу, а не по результату перебора. */
        HB_KEY_GATE("MACRUNNER_HB_FLAG_LIVENESS_CFG");

        /* ★★★ ШЕСТНАДЦАТЬ ГЕЙТОВ, НАЙДЕННЫХ СПЛОШНЫМ ПЕРЕБОРОМ (лейн РЕГИСТРЫ, 22.08).
         *
         * Приказ 216 назвал три забытых гейта. Перебор нашёл ШЕСТНАДЦАТЬ, и три названных в
         * него вошли. Список получен не чтением кода, а ПРИБОРОМ: для каждого из 103 гейтов,
         * читаемых эмиттером, снимок выпуска `hb_regsurvey` снимался при гейте «1» и «0» и
         * сличался с базой на двух корпусах (общий x64 и настоящий ntdll, 3532 блока).
         * Значения MOVZ/MOVK гасились — иначе ASLR даёт 7,63 % ложных различий.
         *
         * Прибор проверен на себе: повтор той же среды совпадает, выдуманное имя гейта не
         * даёт различий, заведомо меняющий выпуск MASK_IMM — даёт.
         *
         * ★ ОДИН ПРОХОД НЕДОСТАТОЧЕН. Первый перебор (каждый гейт против умолчаний) нашёл
         * только пять: гейт, действующий ЛИШЬ в сочетании с другим, в одиночку невидим —
         * `FLAG_LIVENESS_AF` не делает ничего, пока выключен сам `FLAG_LIVENESS`. Второй
         * проход шёл поверх богатой базы (все 27 известных гейтов включены) и добавил
         * одиннадцать. Именно так в список попал названный приказом `FLAG_LIVENESS_AF`,
         * которого в первом проходе НЕ БЫЛО, — и это же значит, что перебор в один слой
         * объявил бы его несуществующим.
         *
         * ★ ТРИ ЛОЖНЫХ СРАБАТЫВАНИЯ СНЯТЫ. `BLOCK_CHAIN`, `INDIRECT_IC` и
         * `JIT_DIRECT_SCALAR_MEM` в перебор попали, но в ключе они УЖЕ ЕСТЬ — через поле
         * `key->flags` (`runtime_jit_flags`), причём не литералами, а вызовами
         * `runtime_block_chain_enabled()` и соседей. Поиск по строкам их не видел. Здесь их
         * нет намеренно: внести значило бы задвоить.
         *
         * ГРАНИЦА СПИСКА: гейт, меняющий выпуск только на коде, которого в обоих корпусах нет,
         * перебор не найдёт. Список закрыт по этим корпусам, а не вообще. */
        HB_KEY_GATE("MACRUNNER_HB_FLAG_LIVENESS");
        HB_KEY_GATE("MACRUNNER_HB_LEAN_FRAME");
        HB_KEY_GATE("MACRUNNER_HB_LEAN_REMAP_ONLY");
        HB_KEY_GATE("MACRUNNER_HB_JIT_HELPER_STORE_FENCE");
        HB_KEY_GATE("MACRUNNER_HB_JIT_DIRECT_STORE_FENCE");
        HB_KEY_GATE("MACRUNNER_HB_JIT_NATIVE_MEM_IR");
        HB_KEY_GATE("MACRUNNER_HB_JIT_NATIVE_MEM_SHAPE");
        /* Найден СТОРОЖЕМ, а не мной: `..._QWORD_LOADS` действует лишь когда включён сам
         * `JIT_NATIVE_MEM_IR`, поэтому в переборе поверх умолчаний он невидим, а в моём
         * втором проходе богатая база ещё не содержала `JIT_NATIVE_MEM_IR` — его туда как раз
         * этот проход и добавлял. Сторож нашёл его сразу, как только шестнадцать предыдущих
         * легли в ключ и вошли в богатую базу. Это ровно тот случай, ради которого сторож и
         * пишется: глазами такую цепочку не закрыть, она углубляется с каждым слоем. */
        HB_KEY_GATE("MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS");
        HB_KEY_GATE("MACRUNNER_HB_JIT_NATIVE_MEM_SIDE");
        HB_KEY_GATE("MACRUNNER_HB_DIRECT_BYTE_STORE_UNSAFE");
        /* ★ 27.08.2026 — оба меняют ВЫПУСК: теневая карта добавляет проверку прав перед
         * байтовой записью, а разведение предикатов решает, попадёт ли операция на прямой
         * путь вообще. Без них в ключе две руки A/B делили бы записи кеша. */
        HB_KEY_GATE("MACRUNNER_HB_FORCE_LAZY_LOAD");
        HB_KEY_GATE("MACRUNNER_HB_FORCE_LAZY_STORE");
        HB_KEY_GATE("MACRUNNER_HB_TSO_RELAXED_LOADS");
        HB_KEY_GATE("MACRUNNER_HB_TSO_RELAXED_STORES");

        /* ★ РАСКЛАДКА hb_context_t ЗАПЕЧАТАНА В НОМЕР (лейн РЕГИСТРЫ, 19.08).
         *
         * Выпущенный код зашивает смещения полей контекста в 65 местах (`offsetof(hb_context_t`
         * в `hb_arm64_codegen.c`), и все они попадают в постоянный кеш КАК ЕСТЬ — релокация их
         * не чинит, потому что это не адреса.
         *
         * Значит сдвиг любого поля (вставка в середину структуры — ровно то, о чём предупреждает
         * комментарий в самом `hb_context.h`) делал сохранённые блоки НЕВЕРНЫМИ, а не
         * несовместимыми: они грузились и читали чужие смещения. Отказ при этом был бы не в
         * момент правки, а через недели, у того, кто структуру не трогал.
         *
         * Теперь раскладка входит в ту же свёртку, что и гейты, поэтому прежняя оговорка про
         * «не пересекается с гейтами» больше не нужна: пересекаться нечему. Ловится любой
         * сдвиг, меняющий `lay`. */
        {
            size_t lay = sizeof(hb_context_t)
                       + offsetof(hb_context_t, helper_table) * 3u
                       + offsetof(hb_context_t, regs) * 7u;
            mix = (mix ^ (uint64_t)lay) * HB_KEY_FNV_PRIME;
        }
        /* Финальное перемешивание (murmur3 fmix64): без него младшие биты FNV слабо
         * расходятся, и соседние сочетания давали бы близкие номера. */
        mix ^= mix >> 33; mix *= 0xff51afd7ed558ccdull;
        mix ^= mix >> 33; mix *= 0xc4ceb9fe1a85ec53ull;
        mix ^= mix >> 33;
        /* Номер ВСЕГДА >= 1 000 000: на это опирается сторож проверки 6ж («раскладка
         * запечатана»). Верхняя граница держит значение внутри int — прежняя схема этого
         * не гарантировала. */
        cached = (int)(1000000u + (unsigned)(mix % (0x7FFFFFFFu - 1000000u)));
    }
    return (unsigned)cached;
}
#undef HB_KEY_GATE
#undef HB_KEY_FNV_PRIME

/* Версия ключа постоянного кеша наружу — чтобы разделение арм можно было НАБЛЮДАТЬ, а не
 * принимать на веру. Разные сочетания гейтов обязаны давать разные номера. */
unsigned hb_runtime_persistent_cache_version(void) { return persistent_cache_version(); }

static hb_result_t persistent_cache_key_for_block(hb_jit_runtime_t* rt,
                                                  const hb_ir_block_t* block,
                                                  hb_cache_key_t* key) {
    uint64_t start = 0;
    size_t len = 0;
    /* итерация 2547: та же правка, что в smc_hash_current — 4096 ровно порог chkstk */
    static __thread uint8_t bytes[4096];
    hb_result_t r;
    if (!rt || !rt->ctx || !block || !key) return HB_ERR_INVALID_ARG;
    if (!block_guest_span(block, &start, &len)) return HB_ERR_UNSUPPORTED_FEATURE;
    /* ★★★ MacRunner 2026-09-03, режим D Diablo (kan-34) — КОД ИЗ ЗАПИСЫВАЕМОЙ ОБЛАСТИ НА ДИСК НЕ КЛАДЁМ И С ДИСКА НЕ БЕРЁМ.
     *
     * Ключ постоянного кеша считается по ТЕКУЩИМ байтам, а IR блока поднят раньше. Для кода, который гость
     * переписывает (Storm SCode патчит rel32 входа в развёрнутое тело при каждой смене ширины), между подъёмом
     * и ключом байты уже успевают измениться: на диск ложится blob со СТАРОЙ целью под ключом НОВЫХ байт —
     * отравленная запись, и каждый следующий прогон/перелифт находит её раньше кодогенерации. Замер kan-34:
     * после выселения и свежего подъёма (jmp → 0x648344c) тело исполняется с юнита 0, а 0x648344c не ищется
     * вовсе. Образы PE лежат R|X и не меняются — им кеш по-прежнему служит. Доказано парным замером
     * kan-37/38 (03.09) на отравленном тёплом корне: с исключением записей за буфер 0, с диском — 72. Безусловно. */
    {
        hb_region_t* pr = hb_memory_find_region(rt->ctx->memory, start);
        hb_region_t* pl = len ? hb_memory_find_region(rt->ctx->memory, start + len - 1) : pr;
        if ((pr && (pr->perm & HB_PERM_WRITE)) || (pl && (pl->perm & HB_PERM_WRITE)))
            return HB_ERR_UNSUPPORTED_FEATURE;
    }
    /* ★★★★★ MacRunner 2026-08-24 — ПРОВЕРИТЬ ОТОБРАЖЕНИЕ ДО ЧТЕНИЯ.
     *
     * `hb_memory_read` на macOS имеет быстрый путь: у региона без `host_base` чтение идёт
     * ПРЯМЫМ memcpy по гостевому адресу как хозяйскому. Границу РЕГИОНА он проверяет, но
     * регион бывает заявлен больше, чем реально отображено, — и тогда memcpy падает SIGBUS
     * внутри libsystem_platform, то есть в ХОЗЯЙСКОМ коде, мимо всей обработки отказов
     * гостя.
     *
     * Пока единица трансляции была короткой (3,14 команды), хвост почти никогда не выходил
     * за отображённое. Слияние блоков растит span — и прогон начал падать ДО того, как
     * слияние успевало сработать хоть раз: первым же обращением сюда, при вычислении ключа
     * кеша. Улика: `сигнал=10 addr=0x300405158 pc_img=/usr/lib/system/libsystem_platform.dylib`.
     *
     * Ключ кеша — не то место, ради которого стоит рисковать падением: если участок не
     * читается целиком, блок просто не кешируется. */
    if (!hb_memory_can_read_span(rt->ctx->memory, start, len))
        return HB_ERR_UNSUPPORTED_FEATURE;
    r = hb_memory_read(rt->ctx->memory, start, bytes, len);
    if (r != HB_OK) return r;
    r = hb_cache_key_compute(bytes, len, rt->ctx->arch, persistent_cache_version(), key);
    if (r != HB_OK) return r;
    key->guest_addr = block->guest_addr;
    key->mode = (uint8_t)rt->ctx->mode;
    key->backend = (uint8_t)HB_BACKEND_JIT;
    key->flags = rt->persistent_cache_flags;
    /* Blobs written by the table-driven store can carry sentinels in registers the legacy load
     * path never restores, so the two must not read each other's entries. Keying on the mode
     * makes a mixed cache directory a miss rather than a wrong translation. */
    key->flags |= HB_PERSIST_FLAG_RELOC;   /* путь по таблице — единственный */
    return HB_OK;
}

static hb_result_t jit_commit_blob(hb_jit_runtime_t* rt, const uint8_t* code, size_t size,
                                   uint8_t** out_dest) {
    hb_result_t r;
    uint8_t* dest;
    if (!rt || !rt->jit_mem || !code || !size || !out_dest) return HB_ERR_INVALID_ARG;
    if (rt->jit_mem->used + size > rt->jit_mem->size) {
        rt->code_cache_full = true;
        trace_jit_code_cache_full_once(rt, "jit-buffer-full", size);
        return HB_ERR_UNSUPPORTED_FEATURE;
    }
    r = hb_jit_buffer_make_writable(rt->jit_mem);
    if (r != HB_OK) return r;
    dest = rt->jit_mem->writable + rt->jit_mem->used;
    memcpy(dest, code, size);
    rt->jit_mem->used += size;
    rt->jit_mem->used = (rt->jit_mem->used + 15) & ~15;
    r = hb_jit_buffer_commit(rt->jit_mem);
    if (r != HB_OK) return r;
    /* Наружу отдаём ИСПОЛНЯЕМЫЙ адрес: со splitwx это RX-половина. */
    *out_dest = hb_jit_rw_to_rx(rt->jit_mem, dest);
    return HB_OK;
}

static int trace_jit_blocks_enabled(void) {
    const char* env = hb_gate( HB_GATE_HB_TRACE_JIT_BLOCKS );
    int cached = env && *env && *env != '0';
    return cached;
}

static int trace_jit_helper_fault_enabled(void) {
    const char* env = hb_gate( HB_GATE_HB_TRACE_JIT_HELPER_FAIL );
    int cached = env && *env && *env != '0';
    return cached;
}

static int trace_x86_low_pc_enabled(void) {
    const char* env = hb_gate( HB_GATE_HB_TRACE_X86_LOW_PC );
    int cached = env && *env && *env != '0';
    return cached;
}

static uint64_t trace_jit_native_addr(void) {
    static int parsed = 0;
    static uint64_t addr = 0;
    if (!parsed) {
        const char* env = hb_gate( HB_GATE_HB_TRACE_JIT_NATIVE_ADDR );
        if (env && *env) addr = strtoull(env, NULL, 0);
        parsed = 1;
    }
    return addr;
}

static uint64_t trace_jit_native_range_start(void) {
    static int parsed = 0;
    static uint64_t addr = 0;
    if (!parsed) {
        const char* env = hb_gate( HB_GATE_HB_TRACE_JIT_NATIVE_RANGE_START );
        if (env && *env) addr = strtoull(env, NULL, 0);
        parsed = 1;
    }
    return addr;
}

static uint64_t trace_jit_native_range_end(void) {
    static int parsed = 0;
    static uint64_t addr = 0;
    if (!parsed) {
        const char* env = hb_gate( HB_GATE_HB_TRACE_JIT_NATIVE_RANGE_END );
        if (env && *env) addr = strtoull(env, NULL, 0);
        parsed = 1;
    }
    return addr;
}

static uint64_t trace_jit_guest_addr(void) {
    static int parsed = 0;
    static uint64_t addr = 0;
    if (!parsed) {
        const char* env = hb_gate( HB_GATE_HB_TRACE_JIT_GUEST_ADDR );
        if (env && *env) addr = strtoull(env, NULL, 0);
        parsed = 1;
    }
    return addr;
}

static uint64_t trace_jit_guest_addr2(void) {
    static int parsed = 0;
    static uint64_t addr = 0;
    if (!parsed) {
        const char* env = hb_gate( HB_GATE_HB_TRACE_JIT_GUEST_ADDR2 );
        if (env && *env) addr = strtoull(env, NULL, 0);
        parsed = 1;
    }
    return addr;
}

static uint64_t trace_jit_guest_range_start(void) {
    static int parsed = 0;
    static uint64_t addr = 0;
    if (!parsed) {
        const char* env = hb_gate( HB_GATE_HB_TRACE_JIT_GUEST_RANGE_START );
        if (env && *env) addr = strtoull(env, NULL, 0);
        parsed = 1;
    }
    return addr;
}

static uint64_t trace_jit_guest_range_end(void) {
    static int parsed = 0;
    static uint64_t addr = 0;
    if (!parsed) {
        const char* env = hb_gate( HB_GATE_HB_TRACE_JIT_GUEST_RANGE_END );
        if (env && *env) addr = strtoull(env, NULL, 0);
        parsed = 1;
    }
    return addr;
}

static int trace_jit_blocks_budget_allows(int force) {
    static int count;
    static int exhausted;
    const char* env = hb_gate( HB_GATE_HB_TRACE_JIT_BLOCK_BUDGET );
    int limit = env && *env ? atoi(env) : 2000;
    if (!trace_jit_blocks_enabled()) return 0;
    if (force || limit <= 0) return 1;
    if (count < limit) {
        count++;
        return 1;
    }
    if (!exhausted) {
        exhausted = 1;
        fprintf(stderr, "macrunner-hb-jit-block: trace budget exhausted at %d entries, silencing\n", limit);
        fflush(stderr);
    }
    return 0;
}

static void trace_jit_block(uint64_t guest_pc, const uint8_t* native, size_t native_size,
                            const hb_ir_block_t* block) {
    uint64_t watch = trace_jit_native_addr();
    uint64_t range_start = trace_jit_native_range_start();
    uint64_t range_end = trace_jit_native_range_end();
    uint64_t guest_watch = trace_jit_guest_addr();
    uint64_t guest_watch2 = trace_jit_guest_addr2();
    uint64_t guest_range_start = trace_jit_guest_range_start();
    uint64_t guest_range_end = trace_jit_guest_range_end();
    int matched = watch && (uintptr_t)native <= (uintptr_t)watch &&
                  (uintptr_t)watch < (uintptr_t)native + native_size;
    int range_matched = range_start && range_end && range_start < range_end &&
                        (uintptr_t)native < (uintptr_t)range_end &&
                        (uintptr_t)native + native_size > (uintptr_t)range_start;
    int guest_range_matched = guest_range_start && guest_range_end &&
                              guest_range_start < guest_range_end &&
                              guest_pc < guest_range_end;
    int guest_matched = (guest_watch && guest_pc == guest_watch) ||
                        (guest_watch2 && guest_pc == guest_watch2);
    const hb_ir_instr_t* first = (block && block->instr_count) ? &block->instrs[0] : NULL;
    const hb_ir_instr_t* last = (block && block->instr_count) ?
                                &block->instrs[block->instr_count - 1] : NULL;

    if (!guest_matched && (guest_watch || guest_watch2) && block) {
        for (size_t i = 0; i < block->instr_count; i++) {
            const hb_ir_instr_t* instr = &block->instrs[i];
            uint64_t start = instr->guest_addr;
            uint64_t end = start + instr->guest_len;
            if ((guest_watch && (guest_watch == start || (instr->guest_len && guest_watch >= start && guest_watch < end))) ||
                (guest_watch2 && (guest_watch2 == start || (instr->guest_len && guest_watch2 >= start && guest_watch2 < end)))) {
                guest_matched = 1;
                break;
            }
        }
    }
    if (guest_range_matched && block) {
        guest_range_matched = 0;
        for (size_t i = 0; i < block->instr_count; i++) {
            const hb_ir_instr_t* instr = &block->instrs[i];
            uint64_t start = instr->guest_addr;
            uint64_t end = start + (instr->guest_len ? instr->guest_len : 1);
            if (start < guest_range_end && end > guest_range_start) {
                guest_range_matched = 1;
                break;
            }
        }
    }
    matched = matched || guest_matched || range_matched || guest_range_matched;
    if (!trace_jit_blocks_budget_allows(matched)) return;
    fprintf(stderr, "macrunner-hb-jit-block: guest=%p native=%p-%p size=%zu instrs=%zu "
            "first_op=%u first_guest=%p last_op=%u last_guest=%p last_target=%p%s\n",
            (void*)(uintptr_t)guest_pc, native, native + native_size, native_size,
            block ? block->instr_count : 0,
            first ? (unsigned)first->op : 0, first ? (void*)(uintptr_t)first->guest_addr : NULL,
            last ? (unsigned)last->op : 0, last ? (void*)(uintptr_t)last->guest_addr : NULL,
            last ? (void*)(uintptr_t)last->target : NULL, matched ? " match=1" : "");
    if (matched && block) {
        for (size_t i = 0; i < block->instr_count; i++) {
            const hb_ir_instr_t* instr = &block->instrs[i];
            fprintf(stderr, "macrunner-hb-jit-block-ir: guest=%p op=%u target=%p len=%u\n",
                    (void*)(uintptr_t)instr->guest_addr, (unsigned)instr->op,
                    (void*)(uintptr_t)instr->target, (unsigned)instr->guest_len);
            fprintf(stderr,
                    "macrunner-hb-jit-block-ir-operands: guest=%p "
                    "dst{t=%u sz=%u reg=%u off=%u imm=%lld mem=(base=%u index=%u scale=%u disp=%lld seg=%u addr32=%u)} "
                    "src1{t=%u sz=%u reg=%u off=%u imm=%lld mem=(base=%u index=%u scale=%u disp=%lld seg=%u addr32=%u)} "
                    "src2{t=%u sz=%u reg=%u off=%u imm=%lld mem=(base=%u index=%u scale=%u disp=%lld seg=%u addr32=%u)} cc=%u\n",
                    (void*)(uintptr_t)instr->guest_addr,
                    (unsigned)instr->dst.type, (unsigned)instr->dst.size,
                    (unsigned)instr->dst.reg, (unsigned)instr->dst.reg_offset,
                    (long long)instr->dst.imm, (unsigned)instr->dst.mem.base,
                    (unsigned)instr->dst.mem.index, (unsigned)instr->dst.mem.scale,
                    (long long)instr->dst.mem.disp, (unsigned)instr->dst.mem.segment,
                    (unsigned)instr->dst.mem.addr32,
                    (unsigned)instr->src1.type, (unsigned)instr->src1.size,
                    (unsigned)instr->src1.reg, (unsigned)instr->src1.reg_offset,
                    (long long)instr->src1.imm, (unsigned)instr->src1.mem.base,
                    (unsigned)instr->src1.mem.index, (unsigned)instr->src1.mem.scale,
                    (long long)instr->src1.mem.disp, (unsigned)instr->src1.mem.segment,
                    (unsigned)instr->src1.mem.addr32,
                    (unsigned)instr->src2.type, (unsigned)instr->src2.size,
                    (unsigned)instr->src2.reg, (unsigned)instr->src2.reg_offset,
                    (long long)instr->src2.imm, (unsigned)instr->src2.mem.base,
                    (unsigned)instr->src2.mem.index, (unsigned)instr->src2.mem.scale,
                    (long long)instr->src2.mem.disp, (unsigned)instr->src2.mem.segment,
                    (unsigned)instr->src2.mem.addr32,
                    (unsigned)instr->cc);
        }
    }
    fflush(stderr);
}

static bool trace_runtime_read_x64_reg(const hb_context_t* ctx, hb_reg_t reg, uint64_t* value) {
    if (!ctx || !value || ctx->mode != HB_MODE_64BIT) return false;
    switch (reg) {
        case HB_REG_RAX: *value = ctx->regs.x64.rax; return true;
        case HB_REG_RCX: *value = ctx->regs.x64.rcx; return true;
        case HB_REG_RDX: *value = ctx->regs.x64.rdx; return true;
        case HB_REG_RBX: *value = ctx->regs.x64.rbx; return true;
        case HB_REG_RSP: *value = ctx->regs.x64.rsp; return true;
        case HB_REG_RBP: *value = ctx->regs.x64.rbp; return true;
        case HB_REG_RSI: *value = ctx->regs.x64.rsi; return true;
        case HB_REG_RDI: *value = ctx->regs.x64.rdi; return true;
        case HB_REG_R8:  *value = ctx->regs.x64.r8; return true;
        case HB_REG_R9:  *value = ctx->regs.x64.r9; return true;
        case HB_REG_R10: *value = ctx->regs.x64.r10; return true;
        case HB_REG_R11: *value = ctx->regs.x64.r11; return true;
        case HB_REG_R12: *value = ctx->regs.x64.r12; return true;
        case HB_REG_R13: *value = ctx->regs.x64.r13; return true;
        case HB_REG_R14: *value = ctx->regs.x64.r14; return true;
        case HB_REG_R15: *value = ctx->regs.x64.r15; return true;
        case HB_REG_RIP: *value = ctx->pc; return true;
        default: return false;
    }
}

static bool trace_runtime_mem_addr(const hb_context_t* ctx, const hb_ir_instr_t* instr,
                                   const hb_ir_operand_t* op, uint64_t* addr) {
    uint64_t base = 0, index = 0;
    if (!ctx || !op || !addr || op->type != HB_OP_MEM) return false;
    if (op->mem.base < HB_REG_COUNT &&
        !trace_runtime_read_x64_reg(ctx, op->mem.base, &base))
        return false;
    if (op->mem.index < HB_REG_COUNT &&
        !trace_runtime_read_x64_reg(ctx, op->mem.index, &index))
        return false;
    if (op->mem.base == HB_REG_RIP && instr)
        base = instr->guest_addr + instr->guest_len;
    *addr = base + index * (op->mem.scale ? op->mem.scale : 1) + op->mem.disp;
    if (op->mem.addr32) *addr = (uint32_t)*addr;
    return true;
}

static void trace_jit_helper_fault_operand(const hb_context_t* ctx, const hb_ir_instr_t* instr,
                                           const char* role, const hb_ir_operand_t* op) {
    uint64_t addr = 0, value = 0;
    hb_result_t read = HB_ERR_INVALID_ARG;
    size_t read_size;

    if (!ctx || !instr || !role || !op || op->type != HB_OP_MEM) return;
    if (!trace_runtime_mem_addr(ctx, instr, op, &addr)) return;
    read_size = op->size && op->size < sizeof(value) ? op->size : sizeof(value);
    if (ctx->memory && read_size)
        read = hb_memory_read(ctx->memory, addr, &value, read_size);
    fprintf(stderr,
            "macrunner-hb-jit-helper-fail-mem: guest=%p role=%s addr=%p size=%u "
            "read=%s value=%p base=%u index=%u scale=%u disp=%lld\n",
            (void*)(uintptr_t)instr->guest_addr, role, (void*)(uintptr_t)addr,
            (unsigned)op->size, hb_result_string(read), (void*)(uintptr_t)value,
            (unsigned)op->mem.base, (unsigned)op->mem.index, (unsigned)op->mem.scale,
            (long long)op->mem.disp);
}

static void trace_jit_helper_fault_block(const hb_context_t* ctx, const hb_ir_block_t* block) {
    static unsigned reports;
    if (!ctx || !block || reports++ >= 32) return;
    fprintf(stderr,
            "macrunner-hb-jit-helper-fail: result=%s block=%p instrs=%zu pc=%p "
            "rax=%p rcx=%p rdx=%p rbx=%p rsp=%p rbp=%p rsi=%p rdi=%p "
            "r8=%p r9=%p r10=%p r11=%p r12=%p r13=%p r14=%p r15=%p\n",
            hb_result_string(ctx->last_result), (void*)(uintptr_t)block->guest_addr,
            block->instr_count, (void*)(uintptr_t)ctx->pc,
            (void*)(uintptr_t)ctx->regs.x64.rax, (void*)(uintptr_t)ctx->regs.x64.rcx,
            (void*)(uintptr_t)ctx->regs.x64.rdx, (void*)(uintptr_t)ctx->regs.x64.rbx,
            (void*)(uintptr_t)ctx->regs.x64.rsp, (void*)(uintptr_t)ctx->regs.x64.rbp,
            (void*)(uintptr_t)ctx->regs.x64.rsi, (void*)(uintptr_t)ctx->regs.x64.rdi,
            (void*)(uintptr_t)ctx->regs.x64.r8, (void*)(uintptr_t)ctx->regs.x64.r9,
            (void*)(uintptr_t)ctx->regs.x64.r10, (void*)(uintptr_t)ctx->regs.x64.r11,
            (void*)(uintptr_t)ctx->regs.x64.r12, (void*)(uintptr_t)ctx->regs.x64.r13,
            (void*)(uintptr_t)ctx->regs.x64.r14, (void*)(uintptr_t)ctx->regs.x64.r15);
    for (size_t i = 0; i < block->instr_count; i++) {
        const hb_ir_instr_t* instr = &block->instrs[i];
        fprintf(stderr,
                "macrunner-hb-jit-helper-fail-ir: index=%zu guest=%p len=%u op=%u target=%p "
                "dst{t=%u sz=%u reg=%u imm=%lld mem=(base=%u index=%u scale=%u disp=%lld addr32=%u)} "
                "src1{t=%u sz=%u reg=%u imm=%lld mem=(base=%u index=%u scale=%u disp=%lld addr32=%u)} "
                "src2{t=%u sz=%u reg=%u imm=%lld mem=(base=%u index=%u scale=%u disp=%lld addr32=%u)} cc=%u\n",
                i, (void*)(uintptr_t)instr->guest_addr, (unsigned)instr->guest_len,
                (unsigned)instr->op, (void*)(uintptr_t)instr->target,
                (unsigned)instr->dst.type, (unsigned)instr->dst.size,
                (unsigned)instr->dst.reg, (long long)instr->dst.imm,
                (unsigned)instr->dst.mem.base, (unsigned)instr->dst.mem.index,
                (unsigned)instr->dst.mem.scale, (long long)instr->dst.mem.disp,
                (unsigned)instr->dst.mem.addr32,
                (unsigned)instr->src1.type, (unsigned)instr->src1.size,
                (unsigned)instr->src1.reg, (long long)instr->src1.imm,
                (unsigned)instr->src1.mem.base, (unsigned)instr->src1.mem.index,
                (unsigned)instr->src1.mem.scale, (long long)instr->src1.mem.disp,
                (unsigned)instr->src1.mem.addr32,
                (unsigned)instr->src2.type, (unsigned)instr->src2.size,
                (unsigned)instr->src2.reg, (long long)instr->src2.imm,
                (unsigned)instr->src2.mem.base, (unsigned)instr->src2.mem.index,
                (unsigned)instr->src2.mem.scale, (long long)instr->src2.mem.disp,
                (unsigned)instr->src2.mem.addr32, (unsigned)instr->cc);
        trace_jit_helper_fault_operand(ctx, instr, "dst", &instr->dst);
        trace_jit_helper_fault_operand(ctx, instr, "src1", &instr->src1);
        trace_jit_helper_fault_operand(ctx, instr, "src2", &instr->src2);
    }
    fflush(stderr);
}

static void trace_x86_low_pc_after_block(const hb_context_t* ctx,
                                         const hb_ir_block_t* block,
                                         uint64_t steps,
                                         uint64_t blocks_executed) {
    static unsigned reports;
    if (!ctx || !block || !trace_x86_low_pc_enabled()) return;
    if (ctx->arch != HB_ARCH_X86 && ctx->mode != HB_MODE_32BIT) return;
    if (ctx->pc >= 0x10000u || reports++ >= 16) return;

    fprintf(stderr,
            "macrunner-hb-x86-low-pc: pc=%p block=%p instrs=%zu steps=%llu blocks=%llu "
            "eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x eflags=%08x\n",
            (void*)(uintptr_t)ctx->pc, (void*)(uintptr_t)block->guest_addr,
            block->instr_count, (unsigned long long)steps,
            (unsigned long long)blocks_executed, ctx->regs.x86.eax,
            ctx->regs.x86.ebx, ctx->regs.x86.ecx, ctx->regs.x86.edx,
            ctx->regs.x86.esi, ctx->regs.x86.edi, ctx->regs.x86.ebp,
            ctx->regs.x86.esp, ctx->regs.x86.eflags);
    for (size_t i = 0; i < block->instr_count; i++) {
        const hb_ir_instr_t* instr = &block->instrs[i];
        fprintf(stderr,
                "macrunner-hb-x86-low-pc-ir: index=%zu guest=%p len=%u op=%u target=%p "
                "dst{t=%u sz=%u reg=%u imm=%lld mem=(base=%u index=%u scale=%u disp=%lld addr32=%u)} "
                "src1{t=%u sz=%u reg=%u imm=%lld mem=(base=%u index=%u scale=%u disp=%lld addr32=%u)} "
                "src2{t=%u sz=%u reg=%u imm=%lld mem=(base=%u index=%u scale=%u disp=%lld addr32=%u)} cc=%u\n",
                i, (void*)(uintptr_t)instr->guest_addr, (unsigned)instr->guest_len,
                (unsigned)instr->op, (void*)(uintptr_t)instr->target,
                (unsigned)instr->dst.type, (unsigned)instr->dst.size,
                (unsigned)instr->dst.reg, (long long)instr->dst.imm,
                (unsigned)instr->dst.mem.base, (unsigned)instr->dst.mem.index,
                (unsigned)instr->dst.mem.scale, (long long)instr->dst.mem.disp,
                (unsigned)instr->dst.mem.addr32,
                (unsigned)instr->src1.type, (unsigned)instr->src1.size,
                (unsigned)instr->src1.reg, (long long)instr->src1.imm,
                (unsigned)instr->src1.mem.base, (unsigned)instr->src1.mem.index,
                (unsigned)instr->src1.mem.scale, (long long)instr->src1.mem.disp,
                (unsigned)instr->src1.mem.addr32,
                (unsigned)instr->src2.type, (unsigned)instr->src2.size,
                (unsigned)instr->src2.reg, (long long)instr->src2.imm,
                (unsigned)instr->src2.mem.base, (unsigned)instr->src2.mem.index,
                (unsigned)instr->src2.mem.scale, (long long)instr->src2.mem.disp,
                (unsigned)instr->src2.mem.addr32, (unsigned)instr->cc);
    }
    fflush(stderr);
}

static bool trace_jit_block_contains_guest(const hb_ir_block_t* block, uint64_t guest) {
    if (!block || !guest) return false;
    if (block->guest_addr == guest) return true;
    for (size_t i = 0; i < block->instr_count; i++) {
        const hb_ir_instr_t* instr = &block->instrs[i];
        uint64_t start = instr->guest_addr;
        uint64_t end = start + instr->guest_len;
        if (guest == start || (instr->guest_len && guest >= start && guest < end))
            return true;
    }
    return false;
}

#define JIT_WATCH_RING_N 16
typedef struct {
    uint64_t guest, fire, rax, rcx, rdx, rsp;
} jit_watch_ring_t;
static jit_watch_ring_t jit_watch_ring[JIT_WATCH_RING_N];
static uint64_t jit_watch_ring_idx;

static void trace_jit_cached_watch_block_once(hb_jit_runtime_t* rt, const hb_block_cache_entry_t* entry) {
    static uint64_t dumped_guest;
    static uint64_t fires;
    uint64_t guest = trace_jit_guest_addr();
    uint64_t guest2 = trace_jit_guest_addr2();
    uint64_t f;
    hb_context_t* ctx = rt ? rt->ctx : NULL;
    int matched;
    if (!entry || !entry->valid || !entry->block || !trace_jit_blocks_enabled())
        return;
    matched = (guest && trace_jit_block_contains_guest(entry->block, guest)) ||
              (guest2 && trace_jit_block_contains_guest(entry->block, guest2));
    if (!matched)
        return;
    /* MacRunner 2026-07-28 (HK Mono/JIT [B] bisection): the watched dispatch must
     * carry the LIVE registers — the OK-arm's rcx is the manufactured object and
     * the wrapper post-call block's rax is the checked function's return; without
     * values the watch can only say "reached", not "with what".  Two sinks:
     * (1) bounded live prints (first 128 fires + power-of-ten milestones) for the
     * boot baseline; (2) a 16-entry ring of the MOST RECENT fires, dumped at
     * run-exit — the faulting call's dispatch is exactly what the live cap would
     * otherwise lose (measured: ~25 fires/min at boot, invoke at ~+30 min). */
    f = ++fires;
    {
        jit_watch_ring_t* slot = &jit_watch_ring[jit_watch_ring_idx % JIT_WATCH_RING_N];
        slot->guest = entry->guest_addr;
        slot->fire = f;
        slot->rax = ctx ? ctx->regs.x64.rax : 0;
        slot->rcx = ctx ? ctx->regs.x64.rcx : 0;
        slot->rdx = ctx ? ctx->regs.x64.rdx : 0;
        slot->rsp = ctx ? ctx->regs.x64.rsp : 0;
        jit_watch_ring_idx++;
    }
    if (f > 128 && f != 1000 && f != 10000 && f != 100000 && f != 1000000)
        return;
    if (f > 128 && dumped_guest == entry->block->guest_addr)
        return;
    dumped_guest = entry->block->guest_addr;
    fprintf(stderr, "macrunner-hb-jit-watch: guest=%p fire=%llu rax=%p rcx=%p rdx=%p rsp=%p\n",
            (void*)(uintptr_t)entry->guest_addr, (unsigned long long)f,
            ctx ? (void*)(uintptr_t)ctx->regs.x64.rax : NULL,
            ctx ? (void*)(uintptr_t)ctx->regs.x64.rcx : NULL,
            ctx ? (void*)(uintptr_t)ctx->regs.x64.rdx : NULL,
            ctx ? (void*)(uintptr_t)ctx->regs.x64.rsp : NULL);
    fflush(stderr);
    trace_jit_block(entry->guest_addr, entry->native_code, entry->native_size, entry->block);
}

void hb_jit_watch_ring_dump(void) {
    uint64_t n = jit_watch_ring_idx < JIT_WATCH_RING_N ? jit_watch_ring_idx : JIT_WATCH_RING_N;
    uint64_t start = jit_watch_ring_idx - n;
    uint64_t k;
    fprintf(stderr, "macrunner-hb-jit-watch-ring: total=%llu shown=%llu\n",
            (unsigned long long)jit_watch_ring_idx, (unsigned long long)n);
    for (k = 0; k < n; k++) {
        const jit_watch_ring_t* slot = &jit_watch_ring[(start + k) % JIT_WATCH_RING_N];
        fprintf(stderr, "macrunner-hb-jit-watch-ring: guest=%p fire=%llu rax=%p rcx=%p rdx=%p rsp=%p\n",
                (void*)(uintptr_t)slot->guest, (unsigned long long)slot->fire,
                (void*)(uintptr_t)slot->rax, (void*)(uintptr_t)slot->rcx,
                (void*)(uintptr_t)slot->rdx, (void*)(uintptr_t)slot->rsp);
    }
    fflush(stderr);
}

static int trace_jit_hot_blocks_enabled(void) {
    const char* env = hb_gate( HB_GATE_HB_TRACE_JIT_HOT_BLOCKS );
    int cached = env && *env && *env != '0';
    return cached;
}

static uint64_t trace_jit_hot_interval(void) {
    static int parsed;
    static uint64_t interval;
    if (!parsed) {
        const char* env = hb_gate( HB_GATE_HB_TRACE_JIT_HOT_BLOCK_INTERVAL );
        interval = env && *env ? strtoull(env, NULL, 0) : 500000ULL;
        if (interval < 1000ULL) interval = 1000ULL;
        parsed = 1;
    }
    return interval;
}

static int trace_jit_hot_bytes_enabled(void) {
    const char* env = hb_gate( HB_GATE_HB_TRACE_JIT_HOT_BYTES );
    int cached = env && *env && *env != '0';
    return cached;
}

static size_t trace_jit_hot_bytes_len(void) {
    static int parsed;
    static size_t len;
    if (!parsed) {
        const char* env = hb_gate( HB_GATE_HB_TRACE_JIT_HOT_BYTES_LEN );
        len = env && *env ? (size_t)strtoull(env, NULL, 0) : 16;
        if (len < 1) len = 16;
        if (len > 128) len = 128;
        parsed = 1;
    }
    return len;
}

static void trace_jit_hot_guest_bytes(hb_context_t* ctx, uint64_t guest_addr) {
    uint8_t byte;
    size_t len;
    if (!trace_jit_hot_bytes_enabled() || !ctx || !ctx->memory) return;
    len = trace_jit_hot_bytes_len();
    fprintf(stderr, " bytes=");
    for (size_t i = 0; i < len; i++) {
        if (hb_memory_read_u8(ctx->memory, (hb_gva_t)(guest_addr + i), &byte) != HB_OK) {
            fprintf(stderr, "%s??", i ? " " : "");
            break;
        }
        fprintf(stderr, "%s%02x", i ? " " : "", byte);
    }
}

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА, итерация 194: КТО зовёт горячий блок.
 * Все 48 верхних блоков лежат внутри ntdll32 (CRT + куча), а вызывающий — ниже 48-го
 * ранга, поэтому рейтингом его не достать в принципе. Гейт печатает адрес возврата:
 * на ВХОДЕ в функцию (блок с guest_addr == PC) [esp] и есть адрес возврата.
 * Задавать ТОЧКУ ВХОДА функции, а не тело цикла — в теле esp уже смещён прологом. */
static uint64_t trace_jit_caller_watch_pc(void) {
    static int parsed;
    static uint64_t pc;
    if (!parsed) {
        const char* e = hb_gate( HB_GATE_HB_TRACE_JIT_CALLER_PC );
        pc = (e && *e) ? strtoull(e, NULL, 0) : 0;
        parsed = 1;
    }
    return pc;
}

static int trace_jit_caller_budget(void) {
    static int parsed;
    static int budget;
    if (!parsed) {
        const char* e = hb_gate( HB_GATE_HB_TRACE_JIT_CALLER_BUDGET );
        budget = (e && *e) ? (int)strtol(e, NULL, 0) : 40;
        if (budget < 1) budget = 40;
        parsed = 1;
    }
    return budget;
}

/* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 250 — блоки ДИАПАЗОНА, но из ПРАВИЛЬНОГО потока.
 * В 249 та же печать стояла в сводке и дала ноль: сводку печатает поток, первым перешагнувший
 * интервал, и обходит она кеш ЭТОГО потока, тогда как код игры идёт в своём. Здесь мы на каждом
 * исполнении блока и с `rt` текущего потока, поэтому блок игры попадёт в печать. Каждый блок
 * печатаем один раз — при первом исполнении. */
static void trace_block_range_probe(hb_block_cache_entry_t* entry) {
    static int parsed;
    static uint64_t lo, hi;
    static uint64_t seen[4096];
    static uint64_t hits[4096];
    static uint64_t calls;
    static unsigned seen_n;
    static unsigned budget = 4096;

    if (!parsed) {
        const char* a = hb_gate( HB_GATE_HB_TRACE_BLOCK_RANGE_LO );
        const char* b = hb_gate( HB_GATE_HB_TRACE_BLOCK_RANGE_HI );
        lo = (a && *a) ? strtoull(a, NULL, 0) : 0;
        hi = (b && *b) ? strtoull(b, NULL, 0) : 0;
        parsed = 1;
        /* БЕЗУСЛОВНЫЙ свидетель взведения. Итерация 250: два замера подряд дали ноль строк
         * только потому, что переменных не было в окружении ребёнка, а молчащий прибор
         * неотличим от отсутствия явления. Печать состояния гейта снимает это навсегда. */
        fprintf(stderr, "macrunner-hb-block-range-armed: pid=%d lo=0x%llx hi=0x%llx взведён=%d\n",
                (int)getpid(), (unsigned long long)lo, (unsigned long long)hi, hi > lo);
        fflush(stderr);
    }
    if (hi <= lo || !entry) return;
    if (entry->guest_addr < lo || entry->guest_addr > hi) return;
    /* Дедупликация: печатаем каждый адрес один раз. Таблица конечна, поэтому при её переполнении
     * печать ПРЕКРАЩАЕТСЯ, а не превращается в поток (адрес вне таблицы иначе печатался бы на
     * каждом исполнении). Бюджет — вторая страховка на случай широкого диапазона в контроле. */
    /* Итерация 250: считаем ИСПОЛНЕНИЯ каждого блока участка. Признак из 248 — блок с числом
     * порядка 32 734 называет точку приземления обратной дуги. Таблица общая на процесс:
     * гонка счётчиков здесь безразлична, порядок величины она не меняет. */
    unsigned idx = seen_n;
    for (unsigned i = 0; i < seen_n; i++) if (seen[i] == entry->guest_addr) { idx = i; break; }
    if (idx == seen_n) {
        if (seen_n >= 4096 || !budget) return;
        seen[seen_n++] = entry->guest_addr;
        budget--;
        fprintf(stderr, "macrunner-hb-block-in-range: pid=%d guest=%p первое_исполнение steps=%u size=%zu\n",
                (int)getpid(), (void*)(uintptr_t)entry->guest_addr, entry->steps, entry->native_size);
        fflush(stderr);
    }
    hits[idx]++;
    /* Итерация 250: печать по СТЕПЕНЯМ ДВОЙКИ вместо периодического сброса. Период приходится
     * угадывать против неизвестного порядка величины — при 10 000 не сработал ни разу, потому
     * что участок исполняется реже. Степени двойки дают полную кривую роста при любом итоге и
     * стоят ~16 строк на блок. Сравнивать надо с 32 734 — числом окон из итерации 246. */
    if ((hits[idx] & (hits[idx] - 1)) == 0)
        fprintf(stderr, "macrunner-hb-range-pow2: pid=%d guest=%p hits=%llu\n",
                (int)getpid(), (void*)(uintptr_t)entry->guest_addr, (unsigned long long)hits[idx]);
    (void)calls;
}

static void trace_jit_caller_probe(hb_jit_runtime_t* rt, hb_block_cache_entry_t* entry) {
    static int emitted;
    trace_block_range_probe(entry);
    uint64_t want = trace_jit_caller_watch_pc();
    uint32_t ret = 0;
    uint64_t esp;

    if (!want || !rt || !rt->ctx || !entry || entry->guest_addr != want) return;
    if (emitted >= trace_jit_caller_budget()) return;
    emitted++;
    /* Итерация 194: у 32-битного гостя стек лежит в regs.x86.esp — члены union НЕ
     * перекрываются, и первая версия зонда читала regs.x64.rsp, получая ровно 0x0
     * все 40 раз. Зонд при этом «работал»: срабатываний было ровно 40. */
    esp = (uint64_t)rt->ctx->regs.x86.esp;
    if (hb_memory_read_u32(rt->ctx->memory, (hb_gva_t)esp, &ret) != HB_OK) ret = 0;
    /* Итерация 194: назвать МОДУЛЬ вызывающего. Ни одна предпочтительная база модулей игры
     * не покрывает адреса возврата (они легли в 0x016bd000-0x016bf000), значит модуль
     * ПЕРЕСЕЛЁН, а списка 32-битных модулей у нас под рукой нет. Поэтому идём от самого
     * адреса: вниз по 64 КБ до заголовка MZ, оттуда SizeOfImage — он в этой игре у каждого
     * модуля свой и потому годится как отпечаток (Diablo.exe 0x2b2000, ddraw 0x596000,
     * Storm 0x45000, diabloui 0x4b000, SMACKW32 0x1a000). */
    {
        /* Шаг 4 КБ, а НЕ 64 КБ: в этом дереве секции выравниваются по 16 КБ, и модуль с
         * базой вида 0x016b4000 при 64-килобайтном шаге просто не попадётся — первый
         * замер так и вышел, дав base=0x400000 (Diablo.exe) с rva=0x12be14c, что больше
         * его же SizeOfImage 0x2b2000, то есть заведомо не он. */
        uint64_t base = (uint64_t)(ret & ~0xfffu);
        uint32_t sig = 0, lfanew = 0, sizeimg = 0;
        int found = 0;
        for (int i = 0; i < 8192 && base >= 0x10000ULL; i++, base -= 0x1000ULL) {
            if (hb_memory_read_u32(rt->ctx->memory, (hb_gva_t)base, &sig) != HB_OK) continue;
            if ((sig & 0xffffu) != 0x5a4du) continue;
            if (hb_memory_read_u32(rt->ctx->memory, (hb_gva_t)(base + 0x3c), &lfanew) != HB_OK) break;
            if (lfanew > 0x1000u) continue;
            if (hb_memory_read_u32(rt->ctx->memory, (hb_gva_t)(base + lfanew + 0x50), &sizeimg) != HB_OK) break;
            /* Заголовок обязан ПОКРЫВАТЬ адрес, иначе это чужой модуль ниже по памяти. */
            if ((uint64_t)ret >= base + (uint64_t)sizeimg) { sizeimg = 0; continue; }
            found = 1;
            break;
        }
        /* Заголовка над адресом возврата НЕТ ни при шаге 64 КБ, ни при 4 КБ на 32 МБ вниз
         * (found=0 все 40 раз). Поэтому опознаём модуль по САМИМ БАЙТАМ КОДА: печатаем
         * окно вокруг адреса возврата и ищем эту последовательность в файлах модулей —
         * приём не зависит ни от заголовка, ни от переселения. */
        fprintf(stderr, "macrunner-hb-jit-caller-bytes: ret=0x%08x", (unsigned int)ret);
        for (int k = -8; k < 16; k++) {
            uint32_t w = 0;
            if (hb_memory_read_u32(rt->ctx->memory, (hb_gva_t)((uint64_t)ret + k), &w) != HB_OK) {
                fprintf(stderr, " ??");
                continue;
            }
            fprintf(stderr, "%s%02x", k == 0 ? " | " : " ", (unsigned int)(w & 0xffu));
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "macrunner-hb-jit-caller: pc=0x%llx esp=0x%llx ret=0x%08x "
                "base=0x%08x rva=0x%08x sizeimg=0x%x found=%d\n",
                (unsigned long long)entry->guest_addr, (unsigned long long)esp,
                (unsigned int)ret, (unsigned int)(found ? base : 0),
                (unsigned int)(found ? (uint64_t)ret - base : 0),
                (unsigned int)sizeimg, found);
    }
    fflush(stderr);
}

static void trace_jit_hot_block_tick(hb_jit_runtime_t* rt, hb_block_cache_entry_t* entry) {
    /* MacRunner 2026-08-10, итерация 194: ширина списка КЭШИРУЕТСЯ.
     * До этой правки getenv стоял ВЫШЕ раннего возврата и потому выполнялся на КАЖДОЙ
     * диспетчеризации блока даже при выключенной трассировке — налог на все прогоны.
     * Это регресс, внесённый мной же в итерации 190. */
    static size_t top_count;
    trace_jit_caller_probe(rt, entry);
    if (!top_count) {
        const char* tv = hb_gate( HB_GATE_HB_TRACE_JIT_HOT_BLOCK_TOP );
        top_count = 12;
        if (tv && *tv) {
            long n = strtol(tv, NULL, 0);
            if (n > 0) top_count = (size_t)(n > 64 ? 64 : n);
        }
    }
    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ширина списка настраивается.
     * Итерация 190 назвала клин — гость молотит форматирование строк в ntdll32, — но все
     * двенадцать верхних блоков оказались ВНУТРИ ntdll32, а вызывающий лежит снаружи.
     * Чтобы его увидеть, список нужен шире. Умолчание 12 — прежнее поведение. */

    /* ★ MacRunner 2026-08-18, лейн ЛЕСТНИЦА, итерация 2309 — МАССИВ ОБЪЯВЛЕН ПОСЛЕ ВОЗВРАТА.
     * Свой профиль x64 (первый в лейне) показал `trace_jit_hot_block_tick` 3,74 % рабочего
     * потока — при ВЫКЛЮЧЕННОЙ трассировке. Причина того же рода, что уже чинили здесь в
     * итерации 194 с `getenv`: работа стояла ВЫШЕ раннего возврата. Тогда убрали `getenv`,
     * а обнуление `top[64]` (64 указателя = 512 байт на КАЖДОЙ диспетчеризации блока)
     * осталось. Перенос за проверку гейта поведения не меняет: до возврата массив не
     * читается. Правка чисто скоростная, поведение гостя не затрагивает. */
    if (!rt || !entry || !trace_jit_hot_blocks_enabled()) return;

    hb_block_cache_entry_t* top[64] = {0};

    entry->hit_count++;
    rt->hot_trace_blocks++;
    if (!rt->hot_trace_next)
        rt->hot_trace_next = trace_jit_hot_interval();
    if (rt->hot_trace_blocks < rt->hot_trace_next) return;
    rt->hot_trace_next += trace_jit_hot_interval();

    for (size_t i = 0; i < rt->block_cache->size; i++) {
        hb_block_cache_entry_t* candidate = &rt->block_cache->entries[i];
        if (!candidate->valid || !candidate->hit_count) continue;
        for (size_t j = 0; j < top_count; j++) {
            if (!top[j] || candidate->hit_count > top[j]->hit_count) {
                for (size_t k = top_count - 1; k > j; k--) top[k] = top[k - 1];
                top[j] = candidate;
                break;
            }
        }
    }

    /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 249 — ВСЕ блоки заданного ДИАПАЗОНА.
     * Верхние N ранжируют по числу попаданий, и блок игры туда не попадёт: его витки
     * (десятки тысяч) тонут против миллионов у циклов CRT в ntdll32. А вопрос ровно в том,
     * какие блоки заведены внутри участка 0x41aac5-0x41abb6 и сколько раз исполнены —
     * это назовёт точку приземления обратной дуги. Кеш здесь уже обойдён целиком, значит
     * второй проход бесплатен. Диапазон задаётся парой переменных, по умолчанию выключено. */
    {
        static int rng_parsed;
        static uint64_t rng_lo, rng_hi;

        if (!rng_parsed) {
            const char* a = hb_gate( HB_GATE_HB_TRACE_BLOCK_RANGE_LO );
            const char* b = hb_gate( HB_GATE_HB_TRACE_BLOCK_RANGE_HI );
            rng_lo = (a && *a) ? strtoull(a, NULL, 0) : 0;
            rng_hi = (b && *b) ? strtoull(b, NULL, 0) : 0;
            rng_parsed = 1;
        }
        if (rng_hi > rng_lo) {
            for (size_t i = 0; i < rt->block_cache->size; i++) {
                hb_block_cache_entry_t* c = &rt->block_cache->entries[i];
                if (!c->valid) continue;
                if (c->guest_addr < rng_lo || c->guest_addr > rng_hi) continue;
                fprintf(stderr, "macrunner-hb-block-in-range: guest=%p hits=%llu steps=%u size=%zu\n",
                        (void*)(uintptr_t)c->guest_addr,
                        (unsigned long long)c->hit_count, c->steps, c->native_size);
            }
        }
    }
    fprintf(stderr, "macrunner-hb-jit-hot-blocks: total=%llu interval=%llu used=%zu\n",
            (unsigned long long)rt->hot_trace_blocks,
            (unsigned long long)trace_jit_hot_interval(),
            rt->jit_mem ? rt->jit_mem->used : 0);
    for (size_t i = 0; i < top_count && top[i]; i++) {
        fprintf(stderr, "macrunner-hb-jit-hot-block: rank=%zu guest=%p hits=%llu native=%p "
                "size=%zu steps=%u",
                i + 1, (void*)(uintptr_t)top[i]->guest_addr,
                (unsigned long long)top[i]->hit_count,
                top[i]->native_code, top[i]->native_size, top[i]->steps);
        trace_jit_hot_guest_bytes(rt->ctx, top[i]->guest_addr);
        fprintf(stderr, "\n");
    }
    fflush(stderr);
}

/* Per-thread JIT runtime construction cost.
 *
 * HK builds one of these per guest thread -- 115 have been counted -- and each
 * one mmaps a 128 MB JIT buffer and opens the persistent cache.  A burst of 15
 * was observed inside the 58.5 s PhysX-ready-to-XInput stretch, which is the
 * largest unexplained block in the deterministic boot prefix, and nothing has
 * ever timed this path.  One line per construction (≈115 lines/run) says whether
 * it is seconds or microseconds, and costs nothing to leave on. */
static unsigned long long mm_rt_created;
static unsigned long long mm_rt_total_ns;

static unsigned long long mm_rt_now_ns(void) {
#ifdef __APPLE__
    return (unsigned long long)clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
#endif
}

hb_jit_runtime_t* hb_jit_runtime_create(hb_context_t* ctx) {
    unsigned long long rt_t0 = mm_rt_now_ns();
    unsigned long long rt_buf_ns = 0, rt_cache_ns = 0, rt_mark;
    hb_jit_runtime_t* rt = calloc(1, sizeof(hb_jit_runtime_t));
    const char* size_env;
    size_t jit_size = 128u * 1024u * 1024u;
    if (!rt) return NULL;
    /* MacRunner 2026-08-22, лейн ЛЕСТНИЦА, приказ 214 — ОКНО ГОСТЯ ПОДТЯГИВАЕТСЯ ЗДЕСЬ.
     * `ctx->guest32_base` заполнялся РОВНО В ОДНОМ месте: hb_wow64cpu.c:560, на подключении
     * потока wow64cpu. Любой другой владелец контекста (стенд движка, диагностический прогон)
     * отображает память через hb_memory_guest32_map, но поле оставалось нулём — а выпущенный
     * i386-код читает ИМЕННО его: emit_x86_ea_to_host() = UXTW(EA) + ctx->guest32_base.
     * Ноль превращал перевод в тождество, и первое же обращение по гостевому адресу уходило
     * в __PAGEZERO (ниже 4 ГБ, отображён БЕЗ ПРАВ) -> SIGSEGV code=2 SEGV_ACCERR.
     * Так весь стенд движка умирал на test_jit_x86_ret_imm16_uses_guest_return_slot:
     * addr=0x140fb4c РАВЕН гостевому esp пробы, потому что перевода не было вовсе.
     *
     * Место выбрано здесь, а не в hb_runtime_run: часть владельцев зовёт hb_jit_runtime_run
     * напрямую, минуя hb_runtime_run (например
     * test_jit_x86_cached_helper_owns_ir_after_transient_func_destroy), и правка в hb_runtime_run
     * такие пути НЕ покрывала — проверено прогоном: отказ переезжал на следующую пробу.
     * hb_jit_runtime_create — общий узел: через него проходят и JIT, и AOT, и прямые владельцы.
     * Инвариант делаем самоподдерживающимся: окно есть — поле заполнено. В бою это no-op,
     * поле уже стоит с подключения потока. */
    /* ★★★ MacRunner 2026-08-24, КООРДИНАТОР — ОСНОВАНИЕ ПОДТЯГИВАЕТСЯ, КОГДА ОКНО СМЕНИЛОСЬ.
     *
     * Было условие `!ctx->guest32_base`: поле заполнялось, ПОКА ОНО НОЛЬ. Если окно гостя
     * пересоздано по другому адресу, в контексте оставалось СТАРОЕ основание, а выпущенный
     * i386-код читает именно его (emit_x86_ea_to_host = UXTW(EA) + ctx->guest32_base).
     *
     * Как поймано: приёмка со снятым ограждением падала Bus error, lldb дал точный адрес
     *     EXC_BAD_ACCESS (code=2, address=0xb0050006f), _platform_memmove+448 strb w6,[x3]
     * при том, что прибор PERM_AUDIT видел ту же гостевую ячейку по адресу 0xc0050006f:
     *     0xb00000000 + 0x50006f   против   0xc00000000 + 0x50006f
     * то есть ДВА разных основания на одну ячейку. Расхождение perm=3 / prot=0x5, которое
     * я до того считал причиной, — следствие: права смотрели на одну страницу, писали в другую.
     *
     * Ограждение всё это время ловило именно эти промахи и уводило на mach-путь, где адрес
     * считается заново от region->host_base. Поэтому со снятым ограждением дефект вылезал,
     * а с ограждением был невидим.
     *
     * Обновляем при РАСХОЖДЕНИИ, а не только при нуле. Печатаем смену: если окно ездит
     * в бою, это надо знать. */
    if (ctx && ctx->arch == HB_ARCH_X86 && ctx->memory) {
        void* g32w = hb_memory_guest32_base(ctx->memory);
        uint64_t now = (uint64_t)(uintptr_t)g32w;
        if (now && now != ctx->guest32_base) {
            if (ctx->guest32_base) {
                fprintf(stderr, "macrunner-hb-guest32-base-СМЕНА: было=0x%llx стало=0x%llx\n",
                        (unsigned long long)ctx->guest32_base, (unsigned long long)now);
                fflush(stderr);
            }
            ctx->guest32_base = now;
            /* Карта прав живёт в том же окне и обновляется теми же вызовами, что и
            * регионы, поэтому её адрес берётся здесь же — одним местом с базой окна. */
            /* СМЕЩЁННЫЙ указатель: проверка прав получает адрес уже хозяйским,
             * см. разбор у hb_memory_perm_map_host_biased. */
            ctx->perm_map_ptr = hb_memory_perm_map_host_biased(ctx->memory);
        }
    }
    hb_runtime_init_environment();
    /* PATHB43 2026-08-03 — every host-base derivation from dispatcher cells proved unreliable
     * (the cells hold inner labels, not nm symbols; one attribution was already retracted over
     * it).  Print the authoritative image base ONCE per process, straight from dyld, so offline
     * resolution of any host pc/lr in a run log starts from truth instead of anchor guessing. */
    {
        static unsigned int host_image_printed;
        if (!host_image_printed++) {
            extern const char hb_build_stamp[];   /* ПОРОЖДАЕТСЯ сборкой */
            Dl_info di;
            /* ★ 04.09.2026 — ОТПЕЧАТОК СБОРКИ рядом с базой образа, и по той же причине.
             * База отвечает на «где выполнялось», отпечаток — на «ЧТО выполнялось».
             * Второй вопрос за один день четырежды оказывался важнее первого: замер
             * шёл на дистрибутиве десятичасовой давности и был бы засчитан за
             * результат правки. Печатается без гейта: одна строка на процесс, а
             * гейт — ровно тот способ, которым такая проверка не делается никогда. */
            fprintf(stderr, "macrunner-hb-сборка: отпечаток=%s\n", hb_build_stamp);
            if (dladdr((void*)(uintptr_t)hb_jit_runtime_create, &di))
                fprintf(stderr, "macrunner-hb-host-image: base=%p path=%s\n",
                        di.dli_fbase, di.dli_fname ? di.dli_fname : "?");
            else
                /* Silence must stay distinguishable from "code never ran". */
                fprintf(stderr, "macrunner-hb-host-image: dladdr-failed fn=%p\n",
                        (void*)(uintptr_t)hb_jit_runtime_create);
            fflush(stderr);
        }
    }
    rt->ctx = ctx;
    rt->persistent_cache_flags = macrunner_hb_runtime_persistent_cache_flags;
    size_env = hb_gate( HB_GATE_HB_JIT_BUFFER_SIZE );
    if (size_env && *size_env) {
        unsigned long long parsed = strtoull(size_env, NULL, 0);
        if (parsed >= 65536ULL && parsed <= 512ULL * 1024ULL * 1024ULL)
            jit_size = (size_t)parsed;
    }
    rt_mark = mm_rt_now_ns();
    rt->jit_mem = hb_jit_buffer_create(jit_size);
    rt_buf_ns = mm_rt_now_ns() - rt_mark;
    if (!rt->jit_mem) { free(rt); return NULL; }
    rt->block_cache = block_cache_create();
    /* Арена — кешу СРАЗУ: его `native_code` это её адреса, и снятие сшивки под
     * раздельным W^X обязано знать, куда переводить приёмник записи. Порядок важен:
     * hb_jit_buffer_create выше по этой же функции. */
    if (rt->block_cache) rt->block_cache->jit_mem = rt->jit_mem;
    if (!rt->block_cache) {
        hb_jit_buffer_destroy(rt->jit_mem);
        free(rt);
        return NULL;
    }
    const char* cache_root = hb_gate( HB_GATE_HB_TRANSLATION_CACHE_ROOT );
    const char* cache_env = hb_gate( HB_GATE_HB_TRANSLATION_CACHE );
    int cache_enabled = (cache_env && *cache_env) ? (*cache_env != '0') :
                        (cache_root && *cache_root);
    if (cache_enabled) {
        hb_cache_options_t options;
        memset(&options, 0, sizeof(options));
        rt_mark = mm_rt_now_ns();
        rt->persistent_cache = hb_cache_open(cache_root && *cache_root ? cache_root : NULL, &options);
        rt_cache_ns = mm_rt_now_ns() - rt_mark;
        hb_contract_telemetry_record_open(rt->persistent_cache != NULL);
        translation_cache_register_atexit();
        if (translation_cache_trace_enabled()) {
            fprintf(stderr, "macrunner-hb-translation-cache-open: root=%s status=%s\n",
                    cache_root && *cache_root ? cache_root : "build/hyperbridge-cache",
                    rt->persistent_cache ? "ok" : "failed");
            fflush(stderr);
        }
    }
    /* MacRunner 2026-08-04 — WHEN does the heap go bad?  A time bracket, not another guess.
     *
     * libmalloc's own verdict is "memory corruption of free block", but its periodic MallocCheckHeap
     * finds nothing (banners prove it was armed) — it does not cover the xzone allocator that
     * actually traps.  malloc_zone_check() does validate the live zones, and it can be called from
     * ORDINARY context, which matters: the trap fires ~25 s in, during a storm of ~40 runtime
     * creations, and this is called once per creation.  The first creation that reports ok=0 brackets
     * the corruption between two known points instead of leaving the whole run as the suspect.
     *
     * Gated (MACRUNNER_HB_ZONE_CHECK=1) and default OFF: a full zone walk is not free. */
    {
        const char* e = hb_gate( HB_GATE_HB_ZONE_CHECK );
        int zone_check_cached = (e && *e && *e != '0') ? 1 : 0;
        if (zone_check_cached) {
            static uint64_t zc_calls, zc_bad;
            uint64_t k = __atomic_add_fetch(&zc_calls, 1, __ATOMIC_RELAXED);
            int ok = malloc_zone_check(NULL) ? 1 : 0;
            if (!ok) __atomic_add_fetch(&zc_bad, 1, __ATOMIC_RELAXED);
            fprintf(stderr, "macrunner-hb-zonecheck: call=%llu ok=%d bad_total=%llu\n",
                    (unsigned long long)k, ok,
                    (unsigned long long)__atomic_load_n(&zc_bad, __ATOMIC_RELAXED));
            fflush(stderr);
        }
    }

    {
        unsigned long long total = mm_rt_now_ns() - rt_t0;
        unsigned long long n = __atomic_add_fetch(&mm_rt_created, 1, __ATOMIC_RELAXED);
        unsigned long long sum = __atomic_add_fetch(&mm_rt_total_ns, total, __ATOMIC_RELAXED);
        /* 2026-08-03 — the paradox probe.  Six runs printed this line 20-28 times while the
         * host-image block ABOVE in this same function printed zero, on carriers whose files
         * verifiably contain both strings.  Embedding dladdr into THIS line removes every
         * degree of freedom: same call site, same fprintf.  The path names the file the
         * EXECUTING copy of hb lives in — which no strings/mtime check on dist can do. */
        /* 2026-08-09 — ЗАГНАН ПОД ГЕЙТ. Зонд был БЕЗУСЛОВНЫМ, а вызывается он на КАЖДОЕ
         * создание среды JIT. Замер того дня: на дереве PE floor40 таких созданий 145, на
         * свежем — 36 337, то есть в 250 раз больше. И на каждое из них зонд делал `dladdr`
         * (поиск символа по адресу), `fprintf` и `fflush`.
         *
         * Цена диагностики, оставленной в дефолте, уже стоила сегодня 1.85× в
         * SAFE_PROBE_ALWAYS. Здесь тот же класс: строка писалась ради одного вопроса от
         * 03.08 (какой файл несёт исполняемую копию hb) и осталась навсегда.
         *
         * Умолчание 0. `MACRUNNER_HB_RTMETER=1` возвращает зонд целиком, включая dladdr. */
        const char* v = hb_gate( HB_GATE_HB_RTMETER );
        int rtmeter_on = (v && *v && *v != '0') ? 1 : 0;
        if (rtmeter_on) {
            Dl_info rt_di;
            const char* rt_img = dladdr((void*)(uintptr_t)hb_jit_runtime_create, &rt_di)
                                 ? (rt_di.dli_fname ? rt_di.dli_fname : "noname") : "dladdr-failed";
            fprintf(stderr,
                    "macrunner-hb-rtmeter: n=%llu total_ms=%.2f jitbuf_ms=%.2f cacheopen_ms=%.2f "
                    "cum_total_ms=%.2f jit_size=%zu img=%s\n",
                    n, (double)total / 1e6, (double)rt_buf_ns / 1e6,
                    (double)rt_cache_ns / 1e6, (double)sum / 1e6, jit_size, rt_img);
            fflush(stderr);
        } else {
            (void)sum; (void)total; (void)n; (void)jit_size;
        }
    }
    {
        /* Печать с ОБЕИХ сторон и по СОБСТВЕННОМУ счётчику событий, а не по значению живых.
         * Первая редакция печатала только на разрушении и только при кратности 256 живых —
         * и не напечатала НИ РАЗУ, потому что среды в основном не разрушаются, а идут в пул.
         * Это четвёртый за вечер случай одной и той же ошибки: гейт печати на величине, а не
         * на событии. */
        static unsigned long long ev;
        unsigned long long n = __atomic_add_fetch(&hb_jit_runtimes_live, 1, __ATOMIC_RELAXED);
        if (++ev == 1 || (ev & 0x3ffull) == 0) {
            fprintf(stderr, "macrunner-hb-rt-live: событий=%llu живых сред=%llu\n", ev, n);
            fflush(stderr);
        }
    }
    return rt;
}

/* MacRunner 2026-08-09 — СКОЛЬКО СРЕД ЖИВО ОДНОВРЕМЕННО.
 *
 * Оценка «853 кеша блоков × 29 МБ ≈ 24.7 ГБ» (итерация 83) молча предполагает, что среды
 * живут одновременно. Сегодня две мои оценки уже оказались завышены на порядки (кеш IR — в
 * 200 раз, итерация 80), поэтому это проверяется, а не принимается: живые = создано минус
 * разрушено. Если живых единицы, виновата НЕ сумма, а ЧАСТОТА создания. */
void hb_jit_runtime_destroy(hb_jit_runtime_t* rt) {
    if (!rt) return;
    {
        static unsigned long long dev;
        unsigned long long n = __atomic_sub_fetch(&hb_jit_runtimes_live, 1, __ATOMIC_RELAXED);
        if (++dev == 1 || (dev & 0x3ffull) == 0) {
            fprintf(stderr, "macrunner-hb-rt-dead: событий=%llu живых сред=%llu\n", dev, n);
            fflush(stderr);
        }
    }
    if (rt->persistent_cache) translation_cache_trace_summary();
    if (smc_trace_enabled() && (g_smc_tracked || g_smc_evicted || g_smc_unreadable))
        fprintf(stderr,
                "macrunner-hb-smc-reverify: summary tracked=%llu reverified=%llu "
                "evicted=%llu unreadable=%llu relift_exits=%llu relift_suppressed=%llu\n",
                (unsigned long long)g_smc_tracked, (unsigned long long)g_smc_reverified,
                (unsigned long long)g_smc_evicted, (unsigned long long)g_smc_unreadable,
                (unsigned long long)g_smc_relift_exits,
                (unsigned long long)g_smc_relift_suppressed);
    unchain_stats_report();
    hb_povtor_itog_print("rt-destroy");
    hb_cache_close(rt->persistent_cache);
    hb_jit_buffer_destroy(rt->jit_mem);
    block_cache_destroy(rt->block_cache);
    free(rt->jit_signal_quarantine);
    free(rt);
}

/* MacRunner: reset for per-thread reuse instead of destroy+recreate per callback.
 * Reuses the 128MB MAP_JIT arena (no munmap/mmap) + the block_cache allocation;
 * eagerly frees owned blocks and rewinds the arena so translations regenerate
 * from current guest code (SMC-safe). Re-points ctx to the new per-callback ctx
 * (generated code embeds ctx state, so a full regenerate against the live ctx is
 * required — which the cleared caches + rewound arena guarantee). */
void hb_jit_runtime_reset(hb_jit_runtime_t* rt, hb_context_t* ctx) {
    hb_jit_runtime_reset_at(rt, ctx, HB_POVTOR_M_PROCHEE);
}

/* ★ 07.09.2026, лейн ПОВТОРНЫЙ-ВЫПУСК — ТО ЖЕ САМОЕ, НО С ИМЕНЕМ МЕСТА.
 * Место передаётся ПАРАМЕТРОМ, а не выставляется отдельным вызовом заранее: пара
 * «пометить, потом сделать» рассыпается молча, стоит появиться раннему возврату между
 * ними, и учёт начинает врать, не ломаясь. */
void hb_jit_runtime_reset_at(hb_jit_runtime_t* rt, hb_context_t* ctx, int mesto) {
    if (!rt) return;
    t_reset_mesto = (mesto >= 0 && mesto < HB_POVTOR_M_N) ? mesto : HB_POVTOR_M_PROCHEE;
    rt->ctx = ctx;
    if (rt->jit_mem) hb_jit_buffer_reset(rt->jit_mem);
    if (rt->block_cache) block_cache_reset(rt->block_cache);
    rt->hot_trace_blocks = 0;
    rt->hot_trace_next = 0;
    rt->code_cache_full = false;
    rt->code_cache_full_reports = 0;
    t_reset_mesto = HB_POVTOR_M_PROCHEE;
}

/* Find block by guest address */
/* MacRunner 2026-07-30 — this is a LINEAR SCAN over every block in the lifted function, comparing
 * guest addresses, and on the default configuration the dispatch loop begins with it unconditionally
 * (hb_jit_runtime_run_legacy, "hb_ir_block_t* block = find_block(func->cfg, ctx->pc)") BEFORE the O(1)
 * hash lookup block_cache_find that follows a few lines later. So today every guest block transition
 * pays a scan whose length is the function's block count.
 *
 * Whether that matters is a number, not an argument, so count it instead of reasoning about it: the
 * scan length is accumulated once per CALL rather than per iteration, which keeps the added cost O(1)
 * and leaves the loop itself untouched. Reported per thread beside avg_chain. If avg_scan comes back
 * in the hundreds, MACRUNNER_HB_SINGLE_LOOKUP=1 — which reorders the fast path to consult the hash
 * FIRST and reach find_block only on a miss — is worth far more than block chaining, and unlike
 * chaining it patches no code. This is the same shape as the hb_memory_protect O(N) walk that turned
 * out to be 27 % of a run. (Counters declared up with t_dispatch_term, which reports them.) */
/* ★ Кольцо пути: последние блоки перед отказом. Только диагностика, за гейтом. */
#define HB_PATH_RING 32
typedef struct { uint64_t pc; uint64_t rbx; } hb_path_entry_t;
static __thread hb_path_entry_t t_path[HB_PATH_RING];
static __thread unsigned t_path_head;

static int trace_path_enabled(void) {
    const char* e = hb_gate( HB_GATE_HB_TRACE_PATH );
    int cached = e && *e && *e != '0';
    return cached;
}

static int buf_arch_is_x86(const hb_context_t* ctx) {
    return ctx && ctx->arch == HB_ARCH_X86;
}

void hb_runtime_dump_path(void);
void hb_runtime_dump_path(void) {
    unsigned i, n;
    if (!trace_path_enabled()) return;
    n = t_path_head < HB_PATH_RING ? t_path_head : HB_PATH_RING;
    fprintf(stderr, "macrunner-hb-ПУТЬ: [pid=%d] последние %u блоков (свежий первым)\n",
            (int)getpid(), n);
    for (i = 1; i <= n; i++) {
        const hb_path_entry_t* e = &t_path[(t_path_head - i) & (HB_PATH_RING - 1)];
        fprintf(stderr, "macrunner-hb-ПУТЬ:  [-%u] pc=%#llx ebx=%#llx\n",
                i - 1, (unsigned long long)e->pc, (unsigned long long)e->rbx);
    }
    fflush(stderr);
}

static hb_ir_block_t* find_block(const hb_ir_cfg_t* cfg, uint64_t addr) {
    size_t n = cfg->block_count;
    if (n > t_findblock_max_n) t_findblock_max_n = n;
    for (size_t i = 0; i < n; i++) {
        if (cfg->blocks[i]->guest_addr == addr) {
            t_findblock_calls++;
            t_findblock_iters += (uint64_t)i + 1;
            return cfg->blocks[i];
        }
    }
    t_findblock_calls++;
    t_findblock_iters += (uint64_t)n;
    return NULL;
}

static bool is_control_transfer_op(hb_ir_op_t op) {
    return op == HB_IR_CALL || op == HB_IR_RET || op == HB_IR_JMP ||
           op == HB_IR_Jcc || op == HB_IR_LOOP || op == HB_IR_JRCXZ;
}

/* MacRunner 2026-08-01 — memoised, because this linear scan was the top self-time item on the
 * critical thread.
 *
 * Profiled with the dispatch-stats instrument OFF (it inflates the caller by ~10 points), the two
 * hot PCs inside hb_jit_runtime_run together carried 24.2 % / 18.6 % of the critical thread's
 * samples across two samples of one run. Disassembly identifies one of them as this loop: a
 * 184-byte-stride walk testing each op against the control-transfer bitmask — i.e. hb_ir_instr_t
 * is 184 bytes, so a 3-instruction block touches ~552 bytes of cold-ish memory purely to answer
 * "where is the terminal", on EVERY dispatch.
 *
 * The answer cannot change: it is a pure function of `instrs`, which is fixed once translation
 * finishes. So compute it once and keep it on the block. hb_ir_emit invalidates the memo, so a
 * block still being built can never serve a stale answer.
 *
 * The write is a benign race by construction: two threads racing on the same block compute the
 * SAME value from the same immutable input, so a torn read is impossible (aligned int32) and a
 * lost update only costs a recompute. No lock, no atomic ordering requirement. */
/* A/B by ENVIRONMENT ONLY — one binary, no deploy between arms, which is the only way to compare
 * two arms of a boot whose marker time already spans 210-628 s without also varying the build.
 * Default 1 (memoised); MACRUNNER_HB_TERMINAL_MEMO=0 restores the per-dispatch scan. */
static const hb_ir_instr_t* first_control_transfer_instr(const hb_ir_block_t* block) {
    int32_t idx;
    if (!block) return NULL;


    idx = block->first_transfer_idx;
    if (idx == HB_IR_TRANSFER_NONE) return NULL;
    if (idx >= 0)
        return (size_t)idx < block->instr_count ? &block->instrs[idx] : NULL;

    for (size_t i = 0; i < block->instr_count; i++) {
        if (is_control_transfer_op(block->instrs[i].op)) {
            ((hb_ir_block_t*)block)->first_transfer_idx = (int32_t)i;
            return &block->instrs[i];
        }
    }
    ((hb_ir_block_t*)block)->first_transfer_idx = HB_IR_TRANSFER_NONE;
    return NULL;
}

/* ★★★ ЕДИНИЦА 2026-08-24 — ЗАВЕРШИТЕЛЬ СЛИТОЙ ЕДИНИЦЫ.
 *
 * Прежняя редакция брала при включённом слиянии ПОСЛЕДНЮЮ команду блока с доводом
 * «лифтер рвётся ровно на несливаемом переходе, значит last и есть завершитель».
 * Довод верен ТОЛЬКО для блоков, построенных лифтером i386. Он неверен для блоков,
 * где за переходом идут ещё команды: кодогенератор их НЕ ВЫПУСКАЕТ (обрыв в
 * `codegen_instr_limit_before_fallthrough`, hb_arm64_codegen.c), а рантайм объявлял
 * завершителем именно их.
 *
 * Цена была ровно один отказ приёмки — `hb_test_runner.c:7291`,
 * `jit_x64_mid_block_control_transfer_stops_fallthrough`: блок
 * `MOV RBX,0x1111; CALL RAX; MOV RBX,0x2222`, завершителем объявлялся второй MOV,
 * и косвенный вызов переставал опознаваться как передача управления.
 *
 * Здесь повторено ТО ЖЕ правило, что у кодогенератора: первый переход, который не
 * является условным ВНУТРЬ этой же единицы. Правила два, и они обязаны совпадать;
 * если одно поменяют, второе разъедется молча. */
static bool merged_block_has_instr_at(const hb_ir_block_t* block, uint64_t tgt) {
    for (size_t i = 0; i < block->instr_count; i++)
        if (block->instrs[i].guest_addr == tgt) return true;
    return false;
}

static const hb_ir_instr_t* merged_terminal_instr(const hb_ir_block_t* block) {
    if (!block || !block->instr_count) return NULL;
    for (size_t i = 0; i < block->instr_count; i++) {
        const hb_ir_instr_t* in = &block->instrs[i];
        if (!is_control_transfer_op(in->op)) continue;
        /* условный переход ВНУТРЬ единицы выпуск не обрывает */
        if (in->op == HB_IR_Jcc && merged_block_has_instr_at(block, in->target)) continue;
        return in;
    }
    return &block->instrs[block->instr_count - 1];
}

/* MacRunner 2026-07-30 — a chainable terminal must be a DIRECT jump, and the src1 test is what
 * makes it one.
 *
 * This accepted any HB_IR_JMP, which is wrong in a way that would not have shown up as a crash.
 * hb_arm64_codegen.c:4625 splits the op on exactly this field: src1.type == HB_OP_NONE emits
 * emit_set_pc_imm64(instr->target) — one fixed successor, known at translation time — while
 * src1.type != HB_OP_NONE emits emit_native_indirect_jmp, which computes the target into x20 at run
 * time. The same test appears at the indirect-IC call site in the dispatcher below.
 *
 * Chaining an indirect jump means patch_block_tail nails its tail to whichever block happened to
 * follow it the first time it ran; every later execution with a different computed target then runs
 * the wrong guest code, silently, with no fault to notice. Indirect jumps are how vtable, switch and
 * import dispatch work, so this would have fired constantly the moment MACRUNNER_HB_BLOCK_CHAIN was
 * armed — a hazard entirely separate from the eviction one the chain-entry trampoline removes. */
/* MacRunner 2026-07-30 — WIDENED, because the direct-JMP-only rule capped chaining at 7.4 % of
 * dispatches and the PC guard removes the reason for the rule.
 *
 * Measured over 205.8 M dispatched blocks on HK's critical thread (run SPEEDDIG1): jcc 71.1 %,
 * ret 9.1 %, call_dir 8.0 %, jmp_dir 7.4 %, call_ind 2.8 %, jmp_ind 1.6 %. Only jmp_dir was eligible,
 * so the whole mechanism could address at most 7.4 % of the round trips that make up ~54 % of that
 * thread. The single-successor restriction existed because the tail patch branched unconditionally:
 * anything with more than one possible successor would have run the wrong guest block.
 *
 * chain_trampoline_build now checks ctx->pc against the target's guest_addr before branching, so a
 * wrong guess costs four instructions and a normal dispatch instead of silent corruption. That admits
 * Jcc (either edge), and indirect jumps and calls with it — the case that was outright unsafe before.
 *
 * RET stays out on purpose: its successor is a return address that differs per call site, so it would
 * mispredict nearly always and pay the guard for nothing. That leaves 90.9 % of terminals eligible
 * against 7.4 %. MACRUNNER_HB_CHAIN_WIDE=0 restores the direct-JMP-only set for an A/B of the widening
 * on its own. */
static int chain_no_call_enabled(void) {
    return runtime_gate_flag( HB_GATE_HB_CHAIN_NO_CALL, 0);
}

static bool block_terminal_is_chainable(const hb_ir_block_t* block) {
    const hb_ir_instr_t* terminal;
    if (!block || block->instr_count == 0) return false;
    terminal = &block->instrs[block->instr_count - 1];
    /* MacRunner 2026-08-18 — ОТДЕЛЬНО отключаемый вызов.
     *
     * Узкое сцепление (`CHAIN_WIDE=0`) прогон переживает, но заплат в нём 6 982 — меньше 8 192,
     * при которых прогон выживал и с широким. Поэтому тот прогон не отличает «спасли, убрав
     * вызовы» от «не дотянули до опасного количества». `MACRUNNER_HB_CHAIN_NO_CALL=1` убирает
     * ТОЛЬКО вызовы, оставляя Jcc: в скомпилированном x86 условные переходы преобладают, значит
     * число заплат останется выше порога, и смешение снимается. */
    if (terminal->op == HB_IR_CALL && chain_no_call_enabled()) return false;
    return terminal->op == HB_IR_JMP || terminal->op == HB_IR_Jcc ||
           terminal->op == HB_IR_CALL;
}

/* MacRunner 2026-07-30 — this must recognise a slot that has ALREADY been patched, and until it did, it
 * made block chaining unmeasurable and self-limiting at the same time.
 *
 * It sniffs the emitted bytes rather than carrying a flag, which is the right call: the persistent
 * translation cache restores blobs, so anything derived from the bytes survives a cache load for free
 * while a struct field would have to be serialised. What was wrong is that it demanded all four words
 * still be NOP — and patch_block_tail overwrites the first two with `MOV X0, X19` / `B <trampoline>`.
 * So every successfully chained block stopped satisfying it, with two consequences measured on HK
 * (`macrunner-hb-chaindecline`, 6365 tails patched):
 *
 *   - `native_accounting = chain_accounting && entry_has_chain_slot(cached, NULL)` went false for exactly
 *     the chained blocks, so the dispatcher counted blocks_executed++ instead of reading the ctx->block_count
 *     delta the emitted accounting maintains. avg_chain was therefore pinned at 1.0000 by construction, no
 *     matter how well chaining worked — the metric was blind to its own subject.
 *   - a patched block was rejected as a chain TARGET (slot_next=47054), so chaining throttled itself.
 *
 * Accepting both shapes fixes both. Re-patching a patched slot is harmless and in fact useful (it re-aims
 * the chain at a new successor); the `meta->target_code` early return upstream is what keeps it from
 * happening needlessly. */
/* Слова щели второй цели. `cmp` и `b` берём из готовых помощников ниже по файлу
 * (arm64_cmp_x, arm64_b_to) — здесь только те две команды, которых там не было. */
#define HB_CHAIN_SLOT2_WORDS 6u

static uint32_t arm64_movz_x(int rd, uint16_t imm16, unsigned shift16) {
    return 0xd2800000u | ((uint32_t)shift16 << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}
static uint32_t arm64_movk_x(int rd, uint16_t imm16, unsigned shift16) {
    return 0xf2800000u | ((uint32_t)shift16 << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}
static uint32_t arm64_bne_skip_two(void) {   /* B.NE +12 — перепрыгнуть MOV и переход */
    return 0x54000061u;
}
static uint32_t arm64_cmp_x(int rn, int rm);
static uint32_t arm64_b_to(const uint8_t* from, const uint8_t* to);

/* MacRunner 25.08.2026 — ПРЯМОЕ РЕБРО: щель ищется по СМЫСЛУ, а не по таблице.
 *
 * Кодогенератор кладёт два NOP сразу за `str x21, [x19,#pc]` — за каждой записью pc с
 * ЗАРАНЕЕ ИЗВЕСТНЫМ адресом (обычный Jcc, все сплавы, прямой вызов). Значит рантайму не
 * нужен канал позиций: щель всегда стоит на этом месте, а её цель лежит в предшествующих
 * `movz/movk x21`, откуда и читается. Никакой сверки `pc` в исполнении — переход прямой,
 * ровно как у Rosetta с её 22 665 `B.cond`.
 *
 * Разбор идёт один раз на попытку сшивки и только по нужной цели; в горячем пути его нет. */
static bool find_direct_edge_slot(const hb_block_cache_entry_t* entry, uint64_t want,
                                  size_t* out_off) {
    static const uint32_t nop = 0xd503201fu;
    /* STR Xt,[Xn,#imm12*8]: 1111 1001 00 imm12 Rn Rt. Ждём Rt=21, Rn=19, imm12=offsetof(pc)/8. */
    const uint32_t str_base = 0xf9000000u
                            | ((uint32_t)(offsetof(hb_context_t, pc) / 8u) << 10)
                            | (19u << 5);
    size_t i;

    if (!entry || !entry->native_code || entry->native_size < 16) return false;

    for (i = 0; i + 12 <= entry->native_size; i += 4) {
        uint32_t insn, w1, w2;
        uint64_t val = 0;
        bool seen = false;
        size_t back;
        int src;

        memcpy(&insn, entry->native_code + i, 4);
        /* Обычный `Jcc` пишет провал через x21, а взятие через x20 — принимаем оба. */
        if (insn != (str_base | 21u) && insn != (str_base | 20u)) continue;
        src = (int)(insn & 0x1fu);
        memcpy(&w1, entry->native_code + i + 4, 4);
        memcpy(&w2, entry->native_code + i + 8, 4);
        if (w1 != nop || w2 != nop) continue;      /* щель занята или её нет */

        /* Назад по movz/movk x21 — собираем непосредственное. */
        for (back = i; back >= 4; back -= 4) {
            uint32_t m;
            unsigned sh;
            uint16_t imm;
            memcpy(&m, entry->native_code + back - 4, 4);
            if ((int)(m & 0x1f) != src) break;
            sh  = (m >> 21) & 3u;
            imm = (uint16_t)((m >> 5) & 0xffffu);
            if ((m & 0xff800000u) == 0xd2800000u) {          /* MOVZ — начало набора */
                val |= (uint64_t)imm << (16u * sh);
                seen = true;
                break;
            }
            if ((m & 0xff800000u) == 0xf2800000u) {          /* MOVK — продолжение */
                val |= (uint64_t)imm << (16u * sh);
                continue;
            }
            break;
        }
        if (!seen || val != want) continue;
        if (out_off) *out_off = i + 4u;                      /* сама щель — сразу за записью */
        return true;
    }
    return false;
}

/* Все три определены ниже — здесь только объявления, чтобы заплата стояла рядом с разбором. */
static uint8_t* chain_trampoline_for(hb_jit_runtime_t* rt, hb_block_cache_entry_t* entry);
static bool arm64_branch_reaches(const uint8_t* from, const uint8_t* to);
static uint32_t arm64_b_to(const uint8_t* from, const uint8_t* to);
static uint32_t arm64_mov_reg_u32(int rd, int rn);

/* Занять прямое ребро: два слова на месте двух NOP. Порядок тот же, что у основной
 * заплаты, — трамплин ждёт контекст в x0. */
static bool chain_patch_direct_edge(hb_jit_runtime_t* rt, hb_block_cache_entry_t* cur,
                                    hb_block_cache_entry_t* next, size_t off) {
    uint8_t* p;
    uint8_t* target;

    if (!rt || !cur || !next) return false;
    target = chain_trampoline_for(rt, next);
    if (!target) return false;
    p = cur->native_code + off;
    if (!arm64_branch_reaches(p + 4u, target)) return false;
    if (hb_jit_buffer_make_writable(rt->jit_mem) != HB_OK) return false;
    arm64_store_u32(rt->jit_mem, p + 4, arm64_b_to(p + 4, target));       /* переход пишем ПЕРВЫМ... */
    block_cache_clear_icache(rt->jit_mem, p + 4, sizeof(uint32_t));
    arm64_store_u32(rt->jit_mem, p + 0, arm64_mov_reg_u32(0, 19));        /* ...а вход в щель — ПОСЛЕДНИМ */
    block_cache_clear_icache(rt->jit_mem, p, 2 * sizeof(uint32_t));
    return hb_jit_buffer_make_executable(rt->jit_mem) == HB_OK;
}

/* MacRunner 25.08.2026 — ЩЕЛЬ ВТОРОЙ ЦЕЛИ: адрес ВЫЧИСЛЯЕТСЯ, а не ищется.
 * Кодогенератор кладёт её пятью словами НЕПОСРЕДСТВЕННО перед основной щелью, а основная
 * стоит в последних 32 байтах — значит вторая начинается на `native_size - 52`. Поиск по
 * образцу (первая попытка) был и дорог, и бесполезен: горячие условные переходы выпускают
 * сплавы, и своего эпилога у ветви провала не было вовсе. */
static bool entry_chain_slot_at(const hb_block_cache_entry_t* entry, size_t pos);

#define HB_CHAIN_SLOT2_BYTES (HB_CHAIN_SLOT2_WORDS * 4u)

static size_t entry_second_slot_offset(const hb_block_cache_entry_t* entry) {
    static const uint32_t arm64_nop = 0xd503201fu;
    size_t off;
    unsigned i;
    uint32_t w;

    if (!entry || !entry->native_code) return 0;
    if (entry->native_size < 32u + HB_CHAIN_SLOT2_BYTES) return 0;
    off = entry->native_size - 32u - HB_CHAIN_SLOT2_BYTES;
    /* Щель свободна ровно тогда, когда все её слова — NOP. Занятую распознаём по первому
     * слову (`movz x21`), и тогда занимать нечего: цель уже прописана. */
    for (i = 0; i < HB_CHAIN_SLOT2_WORDS; i++) {
        memcpy(&w, entry->native_code + off + i * 4u, sizeof(w));
        if (w != arm64_nop) return 0;
    }
    return off;
}

/* Щель опознаётся по ОДНОМУ месту, native_size - 32.
 *
 * ЗАМЕР 03.09.2026: попаданий 14 000 000, промахов 0 — щель есть у КАЖДОГО
 * блока и ровно на каноническом месте. Гипотеза «sra_emit_restore и лёгкий
 * кадр вытесняют щель из окна опознания» ОПРОВЕРГНУТА, искать причину
 * avg_chain=1,0000 надо не здесь. */
static bool entry_has_chain_slot(const hb_block_cache_entry_t* entry, size_t* offset) {
    if (!entry || !entry->native_code || entry->native_size < 32) return false;
    size_t pos = entry->native_size - 32;
    if (offset) *offset = pos;
    return entry_chain_slot_at(entry, pos);
}

/* Тот же образец, но по произвольной позиции — общий для обеих щелей. */
static bool entry_chain_slot_at(const hb_block_cache_entry_t* entry, size_t pos) {
    static const uint32_t arm64_nop = 0xd503201fu;
    static const uint32_t arm64_mov_x0_x19 = 0xaa1303e0u;
    static const uint32_t epilogue[4] = {
        0xa9427bf7u, 0xa9415bf5u, 0xa8c353f3u, 0xd65f03c0u
    };
    uint32_t w[4];
    uint32_t insn;
    bool pristine, patched;

    if (!entry || !entry->native_code || pos + 32 > entry->native_size) return false;
    for (size_t i = 0; i < 4; i++)
        memcpy(&w[i], entry->native_code + pos + i * 4, sizeof(w[i]));

    pristine = (w[0] == arm64_nop && w[1] == arm64_nop && w[2] == arm64_nop && w[3] == arm64_nop);
    /* B is 0b000101<imm26>; the trampoline branch is unconditional and always in range by construction. */
    patched = (w[0] == arm64_mov_x0_x19 && (w[1] & 0xfc000000u) == 0x14000000u &&
               w[2] == arm64_nop && w[3] == arm64_nop);
    if (!pristine && !patched) return false;

    for (size_t i = 0; i < 4; i++) {
        memcpy(&insn, entry->native_code + pos + 16 + i * 4, sizeof(insn));
        if (insn != epilogue[i]) return false;
    }
    return true;
}

static bool arm64_branch_reaches(const uint8_t* from, const uint8_t* to) {
    intptr_t off;
    if (!from || !to) return false;
    off = (intptr_t)(to - from);
    return (off % 4) == 0 && off >= -(intptr_t)0x08000000 && off < (intptr_t)0x08000000;
}

static uint32_t arm64_b_to(const uint8_t* from, const uint8_t* to) {
    intptr_t off = (intptr_t)(to - from);
    return 0x14000000u | (uint32_t)(((off / 4) & 0x03ffffffu));
}

static uint32_t arm64_mov_reg_u32(int rd, int rn) {
    return 0xaa0003e0u | ((uint32_t)rn << 16) | (uint32_t)rd;
}

/* MacRunner 2026-07-30 — CHAIN-ENTRY TRAMPOLINE.
 *
 * Why this exists: patch_block_tail below writes a direct `B` to next->native_code+12, i.e. a raw
 * pointer into the JIT arena. When the target is evicted its arena memory is reused, so every branch
 * still pointing at it becomes a jump into unrelated code. Eviction does try to undo those patches
 * (block_cache_unchain_references), but that path needs the arena writable and silently gives up
 * when it is not — and undoing a patch means rewriting INSTRUCTIONS, which on ARM64 obliges us to
 * get i-cache maintenance right against threads that may be executing them. That combination is why
 * MACRUNNER_HB_BLOCK_CHAIN has been default-off and marked unsafe, and why it has been armed in
 * 0 of 218 runs — leaving every guest block transition to pay a full dispatcher round trip, which
 * the profile shows as 297-339 of ~535 samples on the critical thread inside hb_jit_runtime_run.
 *
 * The trampoline removes the hazard instead of tracking it. Predecessors branch to a per-target stub
 *
 *      LDR X16, <literal>
 *      BR  X16
 *      <literal>            ; live entry, or this target's bail-out
 *
 * and eviction becomes ONE 8-byte store to the literal. Every inbound chain is redirected at once,
 * however many there are, so single-slot metadata stops being a limitation. A literal is data, not
 * code, so no i-cache maintenance is involved in the switch at all — which is the part that made
 * patching the branch itself hard to do safely.
 *
 * The bail-out is generated per target rather than shared because it has to name the guest address
 * to resume at:
 *
 *      LDR X1, <literal>            ; guest_addr
 *      STR X1, [X0, #pc]            ; X0 holds ctx — the chain slot's MOV X0, X19 put it there
 *      LDP X23, LR,  [SP, #32]      ; the same epilogue every block ends with, so the frame the
 *      LDP X21, X22, [SP, #16]      ; ORIGINATING block pushed is unwound exactly as on a normal
 *      LDP X19, X20, [SP], #48      ; return, and the dispatcher resumes at ctx->pc
 *      RET
 *
 * Space is committed BEFORE the instructions are built, and the instructions are then written
 * knowing the final address. That is not fussiness: the literal must be 8-byte aligned for the
 * eviction store to be atomic, and the offset that achieves that is only knowable once the arena
 * has handed out an address. */

#define HB_CHAIN_TRAMPOLINE_BYTES 128

/* Промахи стража трамплина. Свидетеля ставит сам трамплин одной командой на
 * холодном пути (hb_context.h, chain_mispredict); здесь он только снимается.
 * Ноль промахов при ненулевом PATCHED означает, что прошитая ветвь НЕ
 * ДОСТИГАЕТСЯ — это и есть то различение, которого не было. */
static void tramp_snyat_svidetelya(hb_context_t* ctx)
{
    uint64_t n;
    if (!ctx || !ctx->chain_mispredict) return;
    n = __atomic_add_fetch(&g_tramp_promah, 1, __ATOMIC_RELAXED);
    if (n <= 8 || (n & (n - 1)) == 0)   /* первые восемь и дальше кратно двум */
        fprintf(stderr, "macrunner-hb-трамплин-промах: n=%llu ждали=%#llx было=%#llx "
                        "pc_в_C=%#llx eip=%#x arch=%d\n",
                (unsigned long long)n,
                (unsigned long long)ctx->chain_mispredict,
                (unsigned long long)ctx->chain_mispredict_pc,
                (unsigned long long)ctx->pc,
                (unsigned)ctx->regs.x86.eip,
                (int)ctx->arch);
    ctx->chain_mispredict = 0;
    ctx->chain_mispredict_pc = 0;
}

static uint32_t arm64_ldr_x_literal(int rt_reg, ptrdiff_t byte_delta) {
    /* LDR Xt, <label> — imm19 counts instructions, not bytes. */
    uint32_t imm19 = (uint32_t)((byte_delta / 4) & 0x7ffff);
    return 0x58000000u | (imm19 << 5) | (uint32_t)rt_reg;
}

static uint32_t arm64_br_reg(int rn) { return 0xd61f0000u | ((uint32_t)rn << 5); }

static uint32_t arm64_str_x_off(int rt_reg, int rn, unsigned byte_off) {
    return 0xf9000000u | (((uint32_t)(byte_off / 8) & 0xfffu) << 10) |
           ((uint32_t)rn << 5) | (uint32_t)rt_reg;
}

static uint32_t arm64_ldr_x_off(int rt_reg, int rn, unsigned byte_off) {
    return 0xf9400000u | (((uint32_t)(byte_off / 8) & 0xfffu) << 10) |
           ((uint32_t)rn << 5) | (uint32_t)rt_reg;
}

/* CMP Xn, Xm — SUBS XZR, Xn, Xm. */
static uint32_t arm64_cmp_x(int rn, int rm) {
    return 0xeb000000u | ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | 31u;
}

/* B.<cond> to an absolute address. cond 1 == NE. */
static uint32_t arm64_bcond_to(const uint8_t* from, const uint8_t* to, uint32_t cond) {
    intptr_t off = (intptr_t)(to - from);
    return 0x54000000u | ((uint32_t)((off / 4) & 0x7ffff) << 5) | (cond & 0xfu);
}

/* MacRunner 2026-07-30 — PC-GUARDED CHAIN: one layout helper, because three functions have to agree
 * about where the literals live and a silent disagreement between them would corrupt control flow.
 *
 * Offsets are derived from `dest`'s own address so both literals land 8-aligned — the eviction store
 * has to be a single atomic 8-byte write, and only the arena knows the final address. */
struct hb_chain_tramp_layout {
    size_t expect_lit;   /* .quad this target's guest_addr */
    size_t live_lit;     /* .quad live entry, or this trampoline's eviction bail-out */
    size_t mispredict;   /* bare epilogue: leave ctx->pc alone, return to the dispatcher */
    size_t evict_bail;   /* set ctx->pc to guest_addr, then epilogue */
    size_t total;
};

static bool chain_tramp_layout(const uint8_t* dest, struct hb_chain_tramp_layout* out) {
    size_t off;
    if (!dest || ((uintptr_t)dest & 3u) != 0) return false;

    /* guard (6 instrs) then the mispredict epilogue (4 instrs) */
    out->mispredict = 6 * 4;
    off = out->mispredict + 6 * 4;   /* +2: свидетель промаха, см. hb_context.h */
    while ((((uintptr_t)dest + off) & 7u) != 0) off += 4;
    out->expect_lit = off;
    out->live_lit = off + 8;
    out->evict_bail = off + 16;
    out->total = out->evict_bail + 6 * 4;
    return out->total <= HB_CHAIN_TRAMPOLINE_BYTES;
}

/* Lays out, at `dest`: trampoline (LDR/BR + literal) followed by this target's bail-out.
 * Returns the trampoline address, or NULL if the layout cannot be aligned within the block. */
/* Builds into `out` the trampoline that will LIVE at `at`. The two are separated so the whole thing can be
 * assembled in a local buffer and handed to jit_commit_blob in one shot: every displacement below is
 * computed from `at`, every store goes to `out`. That keeps `jit_commit_blob` the only writer that ever
 * toggles the arena's W^X state — see chain_trampoline_for. */
static uint8_t* chain_trampoline_build_at(uint8_t* out, const uint8_t* at, uint8_t* live_entry,
                                          uint64_t guest_addr) {
    static const uint32_t epilogue[4] = {
        0xa9427bf7u, /* LDP X23, LR,  [SP, #32] */
        0xa9415bf5u, /* LDP X21, X22, [SP, #16] */
        0xa8c353f3u, /* LDP X19, X20, [SP], #48 */
        0xd65f03c0u  /* RET */
    };
    struct hb_chain_tramp_layout L;
    uint8_t* mis;
    uint8_t* bail;
    size_t i;

    if (!out || !at || !live_entry) return NULL;
    if (!chain_tramp_layout(at, &L)) return NULL;

    mis = out + L.mispredict;
    bail = out + L.evict_bail;

    /* The guard. X0 holds ctx — the predecessor's chain slot put it there with MOV X0, X19 — and the
     * predecessor's terminal has already stored its computed next PC into ctx->pc. So comparing that
     * against this target's own guest_addr asks exactly the right question: "is this the successor I
     * was chained for?" A match branches into the target's live code; a mismatch falls into a bare
     * epilogue and lets the dispatcher resolve ctx->pc as it always would.
     *
     * That check is what makes chaining safe for terminals with more than one successor. A Jcc that
     * takes its other edge, an indirect jump through a different vtable slot, an indirect call to a
     * different callee: each simply mispredicts and pays four extra instructions instead of executing
     * the wrong guest block. X16/X17 are IP0/IP1, scratch at any call boundary. */
    /* ЗАШИТОЕ ЧИСЛО УБРАНО 03.09.2026. Здесь стояло 544 с комментарием
     * «offsetof(hb_context_t, pc)». В тот же день поле `pc` уехало на 560 —
     * я вставил перед ним два поля срока, нарушив записанное в самом
     * заголовке правило «дописывать только в конец». Страж стал читать
     * соседнее поле и промахиваться ВСЕГДА: 12 959 019 промахов из
     * 12 974 008, avg_chain=1,0000, и полдня поисков не там.
     *
     * Число, которое обязано совпадать с раскладкой структуры, не должно
     * писаться рукой: компилятор знает ответ и не забывает его обновить. */
    arm64_store_u32(NULL, out + 0, arm64_ldr_x_off(16, 0,
                                     (uint32_t)offsetof(hb_context_t, pc)));
    arm64_store_u32(NULL, out + 4, arm64_ldr_x_literal(17, (ptrdiff_t)(L.expect_lit - 4)));
    arm64_store_u32(NULL, out + 8, arm64_cmp_x(16, 17));
    arm64_store_u32(NULL, out + 12, arm64_bcond_to(at + 12, at + L.mispredict, 1 /* NE */));
    arm64_store_u32(NULL, out + 16, arm64_ldr_x_literal(16, (ptrdiff_t)(L.live_lit - 16)));
    arm64_store_u32(NULL, out + 20, arm64_br_reg(16));

    /* Mispredict: unwind the frame the ORIGINATING block pushed, exactly as a normal return would, and
     * leave ctx->pc as the terminal set it. */
    /* СВИДЕТЕЛЬ ПРОМАХА — одна команда, только на холодном пути. x17 уже
     * держит ожидаемый гостевой адрес (его загрузил страж), x0 — ctx. */
    arm64_store_u32(NULL, mis + 0, arm64_str_x_off(17, 0,
                                    (uint32_t)offsetof(hb_context_t, chain_mispredict)));
    arm64_store_u32(NULL, mis + 4, arm64_str_x_off(16, 0,
                                    (uint32_t)offsetof(hb_context_t, chain_mispredict_pc)));
    for (i = 0; i < 4; i++)
        arm64_store_u32(NULL, mis + 8 + i * 4, epilogue[i]);
    memset(out + L.mispredict + 24, 0, L.expect_lit - (L.mispredict + 24)); /* alignment padding */

    /* Eviction bail-out: reached only because eviction flipped live_lit to point here, in which case
     * the guard has already confirmed ctx->pc == guest_addr; the store keeps that true for a resumed
     * dispatch and costs nothing. */
    arm64_store_u32(NULL, bail + 0,
                    arm64_ldr_x_literal(1, (ptrdiff_t)L.expect_lit - (ptrdiff_t)L.evict_bail));
    arm64_store_u32(NULL, bail + 4, arm64_str_x_off(1, 0,
                                     (uint32_t)offsetof(hb_context_t, pc)));
    for (i = 0; i < 4; i++)
        arm64_store_u32(NULL, bail + 8 + i * 4, epilogue[i]);

    __atomic_store_n((uint64_t*)(void*)(out + L.expect_lit), guest_addr, __ATOMIC_RELAXED);
    __atomic_store_n((uint64_t*)(void*)(out + L.live_lit), (uint64_t)(uintptr_t)live_entry,
                     __ATOMIC_RELAXED);
    return out;
}

/* Where the literal that selects live-entry vs bail-out lives, for a trampoline at `tramp`. */
static uint64_t* chain_trampoline_slot(uint8_t* tramp) {
    struct hb_chain_tramp_layout L;
    if (!chain_tramp_layout(tramp, &L)) return NULL;
    return (uint64_t*)(void*)(tramp + L.live_lit);
}

/* Address of this trampoline's bail-out, i.e. what the literal is set to on eviction. */
static uint8_t* chain_trampoline_bailout(uint8_t* tramp) {
    struct hb_chain_tramp_layout L;
    if (!chain_tramp_layout(tramp, &L)) return NULL;
    return tramp + L.evict_bail;
}

/* Get, or lazily create, the trampoline through which others reach `entry`. */
/* ★ ВХОД В ЦЕЛЬ СВЯЗЫВАНИЯ — ИСКАТЬ, А НЕ ПРЕДПОЛАГАТЬ. Гейт `MACRUNNER_HB_CHAIN_ENTRY_EXACT`,
 * умолчание ВКЛЮЧЕНО.
 *
 * Что найдено сплошной проверкой пути связывания (итерация 8). Связывание входило в цель по
 * ЖЁСТКОЙ константе `entry->native_code + 12`. Она верна ровно для одной формы пролога:
 *
 *     STP X19,X20,[SP,#-48]!    \
 *     STP X21,X22,[SP,#16]       |  12 байт — их связывание и пропускает,
 *     STP X23,LR,[SP,#32]       /   потому что кадр уже толкнул блок-источник
 *     MOV X19, X0               <-- сюда, на 12-м байте, и метит вход
 *
 * Но пролог УСЛОВНЫЙ (`hb_arm64_codegen.c:1189`): при бережливом кадре
 * (`MACRUNNER_HB_LEAN_FRAME`, плюс `rmap_active == HB_RMAP_ARMED`) три `STP` НЕ выпускаются, и
 * пролог сжимается до ОДНОЙ команды — 4 байта. Тогда `+12` попадает уже не в пролог, а на
 * восьмой байт переведённого кода гостя, то есть в середину чужой команды.
 *
 * На пути связывания в этом файле слова «lean» нет ВООБЩЕ — согласование двух гейтов не
 * проверялось ничем. Это в точности класс отказа, записанный в наряде: «регистры портились,
 * rcx 5000000000000 -> f0e0993f, rbp 1186a1f10 -> 8». Заметим: это НЕ усечение указателя
 * (0x1186a1f10, усечённое до 32 бит, дало бы 0x86a1f10, а не 8) — значения не обрезаны, а
 * ЗАТЁРТЫ чужим кодом, что и должно случиться при входе в середину блока.
 *
 * Лечение — не подпорка, а снятие допущения: `MOV X19, X0` имеет ровно одну кодировку
 * (ORR X19, XZR, X0 = 0xAA0003F3), и вход ищется по ней среди первых четырёх слов блока.
 * Не нашли — не связываем. Гейт `=0` возвращает прежнюю константу для сравнения рук. */
static int chain_entry_exact_enabled(void) {
    const char* s = hb_gate( HB_GATE_HB_CHAIN_ENTRY_EXACT );
    int v = (s && *s) ? (atoi(s) != 0) : 1;
    return v;
}

static uint64_t g_chain_entry_found_12, g_chain_entry_found_other, g_chain_entry_not_found;

#define HB_CHAIN_ENTRY_MOV_X19_X0 0xAA0003F3u

static long chain_entry_offset(const hb_block_cache_entry_t* entry) {
    size_t i;
    if (!entry || !entry->native_code) return -1;
    if (!chain_entry_exact_enabled()) return 12;
    for (i = 0; i < 4; i++) {
        uint32_t word;
        if ((i + 1) * 4 > entry->native_size) break;
        memcpy(&word, entry->native_code + i * 4, sizeof(word));
        if (word == HB_CHAIN_ENTRY_MOV_X19_X0) {
            if (i * 4 == 12) g_chain_entry_found_12++;
            else {
                g_chain_entry_found_other++;
                if (g_chain_entry_found_other <= 8)
                    fprintf(stderr,
                            "macrunner-hb-chainentry: блок=0x%llx вход НЕ на 12-м байте, а на %zu "
                            "(жёсткая константа промахнулась бы в середину кода)\n",
                            (unsigned long long)entry->guest_addr, i * 4);
            }
            return (long)(i * 4);
        }
    }
    g_chain_entry_not_found++;
    if (g_chain_entry_not_found <= 8)
        fprintf(stderr, "macrunner-hb-chainentry: блок=0x%llx MOV X19,X0 не найден в первых "
                        "четырёх словах — НЕ связываем\n",
                (unsigned long long)entry->guest_addr);
    return -1;
}

static uint8_t* chain_trampoline_for(hb_jit_runtime_t* rt, hb_block_cache_entry_t* entry) {
    hb_block_chain_meta_t* meta;
    uint8_t zeros[HB_CHAIN_TRAMPOLINE_BYTES];
    uint8_t* dest = NULL;

    if (!rt || !rt->block_cache || !entry || !entry->native_code) return NULL;
    meta = block_cache_chain_meta(rt->block_cache, entry, true);
    if (!meta) return NULL;
    if (meta->in_trampoline) return meta->in_trampoline;

    /* MacRunner 2026-07-30 — the make_writable/commit bracket around the BUILD is what was missing, and
     * it is why block chaining has never booted.
     *
     * jit_commit_blob makes the arena writable only for its own memcpy of `zeros` and then calls
     * hb_jit_buffer_commit, which re-protects it. chain_trampoline_build then wrote 20 instruction words
     * straight into that just-re-protected page — a plain store to non-writable JIT memory, which takes
     * the process down with no guest-visible exception. That matches the signature exactly: exit=5 within
     * a second of the first dispatch, no SIGSEGV/SIGBUS/quarantine/interp-fallback line anywhere.
     * patch_block_tail below has always bracketed its own two stores this way; this path did not.
     *
     * Bisected rather than guessed (HK, 45-second arms): emit side alone (MACRUNNER_HB_CHAIN_PATCH=0)
     * boots to Begin MonoManager with 19.15 M dispatches, while committing the trampoline with the tail
     * write still disabled (MACRUNNER_HB_CHAIN_WRITE=0) dies at exit=5 — and in that arm no trampoline is
     * ever branched to, so only building one can be at fault. */
    /* MacRunner 2026-07-30 — assembled in a LOCAL buffer and committed in ONE jit_commit_blob call, so no
     * writer outside jit_commit_blob ever toggles the arena's W^X state.
     *
     * The earlier version reserved the space, then wrote the instructions straight into the arena behind a
     * second make_writable/commit bracket. That bracket was itself suspect: measured across five arms, the
     * only configuration that boots is the one performing ZERO extra cycles (MACRUNNER_HB_CHAIN_PATCH=0),
     * while one extra cycle — whether from this build or from the tail patch — wedges the guest, even though
     * the chained transition it installs provably executes correctly
     * (`chaintransit: from=0x87ef3e43250 pc_after=0x87ef3e4325c blocks=4`). And such a bracket flushes
     * nothing: make_writable sets dirty_start = used, so the paired commit sees an empty dirty range and
     * skips __builtin___clear_cache, leaving correctness to the explicit block_cache_clear_icache below.
     *
     * jit_commit_blob places the blob at writable + used, so the address is predictable before the call;
     * the layout is computed for THAT address and the result verified against what we actually got, because
     * emitting a trampoline whose literals are relative to the wrong address would be silent corruption. */
    {
        uint8_t built[HB_CHAIN_TRAMPOLINE_BYTES];
        /* Трамплин считает смещение от адреса, по которому будет ИСПОЛНЯТЬСЯ. */
        const uint8_t* predicted = hb_jit_rw_to_rx(rt->jit_mem,
                                       rt->jit_mem->writable + rt->jit_mem->used);

        memset(zeros, 0, sizeof(zeros));
        memset(built, 0, sizeof(built));
        long entry_off = chain_entry_offset(entry);
        if (entry_off < 0) return NULL;
        if (!chain_trampoline_build_at(built, predicted, entry->native_code + entry_off,
                                       entry->guest_addr))
            return NULL;
        if (jit_commit_blob(rt, built, sizeof(built), &dest) != HB_OK || !dest) return NULL;
        if (dest != predicted) return NULL; /* layout was computed for another address — refuse to chain */
    }
    block_cache_clear_icache(rt->jit_mem, dest, HB_CHAIN_TRAMPOLINE_BYTES);
    meta->in_trampoline = dest;
    return dest;
}

/* `chain_scoped_rollback_enabled` (MACRUNNER_HB_CHAIN_SCOPED_ROLLBACK) снята 05.09.2026 вместе
 * со снимком: отката больше нет ни для своего блока, ни для чужого, различать нечего. */

/* Занять щель второй цели: пять слов, вписанных на месте пяти NOP.
 *   movz x21,#lo16 / movk x21,#hi16,lsl 16 / cmp x20,x21 / b.ne +8 / b трамплин
 * `x20` к этому месту содержит `ctx->pc`, поэтому сшитой оказывается ТА ветвь, чей адрес
 * совпал, а другая спокойно доходит до основной щели и эпилога. Порядок записи важен:
 * переход пишется ПОСЛЕДНИМ, до него щель для исполнения остаётся набором NOP. */
static bool chain_patch_slot2(hb_jit_runtime_t* rt, hb_block_cache_entry_t* cur,
                              hb_block_cache_entry_t* next, hb_block_chain_meta_t* meta,
                              size_t off) {
    uint8_t* p;
    uint8_t* target;
    uint64_t ga;

    if (!rt || !cur || !next || !meta || !off) return false;
    ga = next->guest_addr;
    if (ga > 0xffffffffull) return false;      /* в две команды помещается только 32-битная цель */

    target = chain_trampoline_for(rt, next);
    if (!target) return false;

    p = cur->native_code + off;
    /* Переход — последнее слово щели, от него и считаем досягаемость. */
    if (!arm64_branch_reaches(p + 5u * 4u, target)) return false;

    /* Арена открывается на запись и закрывается обратно — писать в неё вне этой скобки
     * нельзя (проверено падениями 5/5 на прошлых заплатах). */
    if (hb_jit_buffer_make_writable(rt->jit_mem) != HB_OK) return false;

    /* ПОРЯДОК ВАЖЕН: сначала пишем всё, кроме перехода, и только последним словом —
     * сам переход. До этого момента щель для другого потока остаётся набором NOP плюс
     * безобидная арифметика: прыгнуть в полузаполненную щель невозможно. */
    arm64_store_u32(rt->jit_mem, p + 0,  arm64_movz_x(21, (uint16_t)(ga & 0xffffu), 0));
    arm64_store_u32(rt->jit_mem, p + 4,  arm64_movk_x(21, (uint16_t)((ga >> 16) & 0xffffu), 1));
    arm64_store_u32(rt->jit_mem, p + 8,  arm64_cmp_x(20, 21));
    arm64_store_u32(rt->jit_mem, p + 16, arm64_mov_reg_u32(0, 19));   /* MOV X0, X19 — трамплин ждёт ctx */
    arm64_store_u32(rt->jit_mem, p + 20, arm64_b_to(p + 20, target));
    block_cache_clear_icache(rt->jit_mem, p + 16, 2 * sizeof(uint32_t));
    arm64_store_u32(rt->jit_mem, p + 12, arm64_bne_skip_two());       /* последней — сама развилка */
    block_cache_clear_icache(rt->jit_mem, p, HB_CHAIN_SLOT2_BYTES);
    if (hb_jit_buffer_make_executable(rt->jit_mem) != HB_OK) return false;

    meta->slot2_guest_addr   = ga;
    meta->slot2_target_code  = target;
    meta->slot2_patch_offset = off;
    t_chain_decline[CHAIN_DECL_PATCHED2]++;
    return true;
}

static bool patch_block_tail(hb_jit_runtime_t* rt, hb_block_cache_entry_t* cur,
                             hb_block_cache_entry_t* next, const hb_ir_func_t* func) {
    if (!chain_warmup_passed()) return false;
    hb_block_chain_meta_t* meta;
    uint8_t* target;
    uint8_t* patch;
    size_t patch_offset;
    bool ok;

    /* РЕШЕНИЕ о сшивке — по архитектуре ГОСТЯ, а не «вообще». На x64 сцепление
     * измеренно ломает Hollow Knight (2/2, mono-2.0-bdwgc.dll rva=0x6adb6), разбор
     * при объявлении runtime_block_chain_enabled_for. Проверка `rt` идёт первой:
     * без неё контекст не прочитать. */
    if (!rt || !rt->jit_mem || !cur || !next ||
        !runtime_block_chain_enabled_for(rt->ctx ? rt->ctx->arch : HB_ARCH_X64)) {
        t_chain_decline[CHAIN_DECL_GATE]++;
        return false;
    }
    /* ★ 04.09.2026 — НЕ СШИВАТЬ РЕБРО ИЗ БЛОКА, ОКАНЧИВАЮЩЕГОСЯ ВЫЗОВОМ.
     *
     * Названо прибором, а не чтением. Трасса рёбер (MACRUNNER_HB_TRACE_CHAIN_EDGE)
     * в прогоне Hollow Knight выдала ровно два ребра, ведущих в место смерти:
     *     n=12858 cur=0x87ef31badb6 -> next=0x87ef31b9a30
     *     n=12859 cur=0x87ef31badc9 -> next=0x87ef31b9a30   (тот же трамплин)
     * и байты обоих источников кончаются `e8 <rel32>` — прямым CALL.
     *
     * ЧТО ИЗМЕРЕНО, А ЧТО НЕТ — РАЗДЕЛЕНО НАМЕРЕННО.
     *
     * ИЗМЕРЕНО: запрет переносит отказ на ДРУГОЕ место (был `c000007b` в
     * mono-2.0-bdwgc rva=0x6adb6, стал `reason=import-thunk`). Переезд места —
     * и есть признак, что класс рёбер закрыт; «прогон всё равно умер» таким
     * признаком не является, на чём я один раз уже ошибся и снял работающее.
     *
     * МЕХАНИЗМ НЕ ДОКАЗАН. Первое объяснение («приёмник пишет в чужой кадр»)
     * я записал сюда и оно НЕВЕРНО: теневое пространство Windows x64 лежит в
     * ГОСТЕВОМ стеке и идёт через наш путь к памяти, хозяйского кадра оно не
     * касается вовсе.
     *
     * КАНДИДАТ, И ЕГО ЖЕ ЧАСТИЧНОЕ ОПРОВЕРЖЕНИЕ — записано, чтобы следующий не
     * пошёл по кругу. Сцепление переносит управление ЧЕРЕЗ ГРАНИЦУ ФУНКЦИИ:
     * диспетчер ищет следующий блок в CFG ТЕКУЩЕЙ функции (`find_block(func->cfg,
     * ctx->pc)`) и при промахе честно выходит наружу как «external call
     * boundary», чтобы вызываемую подняли отдельной функцией. Сцеплённое ребро
     * этот выход снимает, и `rt->cur_func_addr`/`cur_func_len` продолжают
     * описывать ВЫЗЫВАЮЩУЮ.
     *
     * НО: единственный найденный их читатель — расширение диапазона SMC — берёт
     * их ТОЛЬКО ПРИ ВЛОЖЕНИИ (`start >= cur_func_addr && start+len <= ...+len`).
     * Чужая функция в этот диапазон не попадает, значит расширение просто НЕ
     * СРАБОТАЕТ. Это осторожно, а не неверно. Стало быть механизм клина
     * по-прежнему НЕ НАЗВАН, и объяснять его этим полем нельзя.
     *
     * ✗ ОТОЗВАНО 04.09.2026 — «ЧТО РЕШИТ ВОПРОС: отвергать ребро, у которого
     * источник и приёмник в РАЗНЫХ функциях». Этот опыт на ветви x64 ПОСТАВИТЬ
     * НЕЛЬЗЯ, и это сказал прибор, а не рассуждение: у гостя x64 поднятая функция
     * состоит из ОДНОГО блока (`max_block_count=1`, 637 450 обращений; внешний
     * цикл зовёт `macrunner_hb_lift_one_block`). Перепись рёбер: ОБА конца в CFG
     * текущей функции у 228 попыток из 264 246 — и это самопетли. Значит «запрет
     * по границе» тождествен «сцепление выключить», и сравнивать в нём нечего.
     * Разбор и обе тройки — у записи о снятии запрета по вызову (05.09.2026, выше по файлу).
     *
     * Эталоны это место закрывают отдельной машинерией: у box64 вторичные точки
     * входа (SEP) плюс теневой стек возвратов CALLRET, у FEX — backpatch самого
     * места вызова. У нас нет ни того, ни другого.
     *
     * ★ 04.09.2026 — ЧТО ЗАМЕРЕНО ВМЕСТО ЭТОГО, и куда идти дальше.
     *
     *  · Запрет по вызову ПЕРЕНОСИТ отказ (тройки у записи о снятии запрета),
     *    то есть класс настоящий; но он НЕ ДОСТАТОЧЕН — прогон всё равно гибнет.
     *  · СИМПТОМ КЛИНА НАЗВАН: со сцеплением x64 сам Mono валится на СВОЁМ
     *    утверждении `mini-amd64.c:7388, (code - cfg->native_code - offset) <=
     *    max_len ... mono_arch_output_basic_block, wrong maximal instruction len`,
     *    после чего зовёт `RaiseException(0xE0000001, NONCONTINUABLE)`; раскрутка
     *    проходит 21 кадр, обработчика не находит (упирается в сторожевой адрес
     *    возврата 0xffff0000) и отдаёт c0000144 -> EXEC_FAULT. В контрольном
     *    прогоне БЕЗ сцепления, вдевятеро длиннее, этого утверждения НЕТ НИ РАЗУ.
     *    То есть гость считает НЕВЕРНОЕ ЧИСЛО, а отказ переходника импорта —
     *    следствие, а не причина.
     *  · СКОЛЬКО СЦЕПЛЕНИЯ ПЕРЕНОСИМО: с потолком 4096 и 8192 заплат прогон живёт
     *    все 150 с и доходит до `Initialize engine version`; без потолка гибнет на
     *    ~19 с, поставив 9914 заплат. Смертельная заплата лежит в (8192, 9914].
     *
     * ЗАКРЫТЫ ЧИСЛОМ, ЧТОБЫ СЛЕДУЮЩИЙ НЕ ШЁЛ ПО КРУГУ (все — на тех же прогонах):
     *  · «пропущена сверка отпечатка SMC у цели» — класс ПУСТ (smc_target=0);
     *  · «кадр источника/приёмника не тот, что разбирает трамплин» — 0 случаев;
     *  · «отказ помощника проглочен цепочкой» — 0 случаев;
     *  · «вход в цель не на 12-м байте» — 0 случаев;
     *  · «устаревший rip в середине цепочки» — закрыто ВЫПУСКОМ: кодогенератор
     *    пишет rip перед щелью сцепления (hb_arm64_codegen.c);
     *  · «сцепление доводит до переходника импорта» — доводит, 32 768+ раз за
     *    прогон и без вреда (macrunner-hb-chain-thunk-exit). */
    /* ★ 04.09.2026 — ОПЫТ, КОТОРЫЙ РАЗДЕЛЯЕТ «ГРАНИЦУ ФУНКЦИИ» И «ВЫЗОВ».
     *
     * `func` — функция, чей диспетчер сейчас исполняется. Параметром, а не через
     * `rt->cur_func_addr`: вложенный вход в диспетчер поле перетирает, а параметр
     * принадлежит этому кадру.
     *
     * ★ ПРИНАДЛЕЖНОСТЬ СПРАШИВАЕТСЯ У CFG, А НЕ У `func->guest_len`. Первая
     * редакция сравнивала адрес приёмника с диапазоном [guest_addr, +guest_len)
     * и намерила cross_other=100934 — а `guest_len` это ОКНО ДЕКОДЕРА (256 байт
     * на блок, hb_lift_x64.c: `hb_ir_func_create(dec->base_addr, dec->code_len)`),
     * не протяжённость функции. Тем сравнением всякий переход дальше окна читался
     * как «чужая функция», то есть прибор мерил не то, что назван мерить.
     * Верный вопрос — тот же, что задаёт себе сам диспетчер: есть ли блок с таким
     * гостевым адресом в CFG ТЕКУЩЕЙ функции (`find_block`).
     *
     * Перепись ведётся ВСЕГДА и одинаково в обеих руках — см. hb_edge_cls_names:
     * без неё совпадение рук нельзя отличить от «класса рёбер не существует».
     * Форма выхода (leave/return/foreign) считается отдельно, потому что запрет
     * руки B снимает все три сразу, а виноватой может быть одна. */
    {
        const hb_ir_block_t* cb = (const hb_ir_block_t*)cur->block;
        const hb_ir_instr_t* t = (cb && cb->instr_count)
                               ? &cb->instrs[cb->instr_count - 1] : NULL;
        int is_call = (t && (t->op == HB_IR_CALL || t->op == HB_IR_CALLF));
        int cross;

        if (!func || !func->cfg) {
            cross = -1;                      /* нечем судить — считаем отдельно */
            t_edge_cls[EDGE_CLS_NO_FUNC]++;
        } else {
            int cur_in  = find_block(func->cfg, cur->guest_addr)  != NULL;
            int next_in = find_block(func->cfg, next->guest_addr) != NULL;
            cross = !(cur_in && next_in);
            t_edge_cls[cross ? (is_call ? EDGE_CLS_CROSS_CALL : EDGE_CLS_CROSS_OTHER)
                             : (is_call ? EDGE_CLS_SAME_CALL  : EDGE_CLS_SAME_OTHER)]++;
            if (cross)
                t_edge_cls[cur_in ? EDGE_CLS_LEAVE
                                  : (next_in ? EDGE_CLS_RETURN : EDGE_CLS_FOREIGN)]++;
        }

        /* ✗ ОТОЗВАНО 04.09.2026 — «сшитое ребро пропускает сверку отпечатка SMC».
         * Из всего, что делает круг через диспетчер и чего сшитое ребро не делает,
         * смысловым выглядела ровно сверка отпечатка цели (`smc_reverify_entry`) с
         * выселением устаревшего перевода. Класс оказался ПУСТ: `smc_target=0` на
         * 264 246 попыток сшивки, то есть НИ ОДНА цель сцепления под отпечатком не
         * стоит (отслеживаются только записываемые+исполняемые области). Запрет
         * заводить не за что; счётчик остаётся — им гипотеза и убита, и он же
         * поймает день, когда такие цели появятся. */
        if (next->smc_hash) t_edge_cls[EDGE_CLS_SMC_TARGET]++;

        /* ★ 04.09.2026 — КАДР ОБОИХ КОНЦОВ ОБЯЗАН БЫТЬ ТОТ, КОТОРЫЙ РАЗБИРАЕТ ТРАМПЛИН.
         *
         * Трамплин зашивает эпилог из 48-байтового кадра (`LDP X19,X20,[SP],#48`,
         * см. chain_trampoline_build_at) в ДВУХ местах: на промахе стража и на
         * выходе выселения. Кодогенератор же выпускает ТРИ формы пролога
         * (hb_arm64_codegen.c: 48 байт, 80 байт при big_frame, и вовсе без кадра
         * при бережливом). Согласование этих форм со сцеплением не проверялось
         * ничем.
         *
         * Почему обязаны совпасть ОБА конца:
         *  · ИСТОЧНИК — потому что кадр толкает он, а на промахе стража его
         *    разбирает трамплин своим зашитым эпилогом. Кадр 80 против разбора 48
         *    оставит SP на 32 байта не там, а `LDP X23,LR,[SP,#32]` прочитает LR
         *    из чужого слота — возврат в мусор.
         *  · ПРИЁМНИК — потому что на ВЗЯТОЙ ветви вход идёт мимо его пролога
         *    (chain_entry_offset ищет `MOV X19,X0`), а его собственный эпилог
         *    отработает целиком и снимет СВОЙ размер с кадра, толкнутого чужим
         *    прологом.
         *
         * Это не настройка и не гейт: ребро с несовпадающим кадром неверно всегда.
         * Счётчик стоит рядом, чтобы «ноль» отличался от «не проверялось». */
        {
            uint32_t w_cur = 0, w_next = 0;
            if (cur->native_size  >= 4) memcpy(&w_cur,  cur->native_code,  4);
            if (next->native_size >= 4) memcpy(&w_next, next->native_code, 4);
            if (w_cur != HB_CHAIN_FRAME48_PUSH || w_next != HB_CHAIN_FRAME48_PUSH) {
                static uint64_t n_frame;
                uint64_t n = __atomic_add_fetch(&n_frame, 1, __ATOMIC_RELAXED);
                if (n <= 8 || (n & (n - 1)) == 0) {
                    fprintf(stderr, "macrunner-hb-chain-кадр: n=%llu cur=0x%llx w_cur=%08x "
                            "next=0x%llx w_next=%08x (трамплин разбирает только %08x)\n",
                            (unsigned long long)n, (unsigned long long)cur->guest_addr,
                            w_cur, (unsigned long long)next->guest_addr, w_next,
                            (unsigned)HB_CHAIN_FRAME48_PUSH);
                    fflush(stderr);
                }
                t_chain_decline[CHAIN_DECL_FRAME]++;
                return false;
            }
        }

        (void)cross;   /* перепись выше — единственный потребитель признака */
        /* Запрета по завершителю-вызову здесь больше нет (05.09.2026, замер у бывшей
         * ручки runtime_chain_call_term_ban): is_call дальше служит только переписи. */
    }
    if (!cur->valid || !next->valid || !cur->native_code || !next->native_code) {
        t_chain_decline[CHAIN_DECL_INVALID]++;
        return false;
    }
    meta = block_cache_chain_meta(rt->block_cache, cur, true);
    if (!meta) { t_chain_decline[CHAIN_DECL_NOMETA]++; return false; }
    if (meta->target_code) {
        t_chain_decline[CHAIN_DECL_ALREADY]++;
        /* Слот сцепления ОДИН на блок (четыре NOP перед эпилогом, см. entry_has_chain_slot).
         * У блока с условным переходом целей две — сшить можно только одну, и вторая
         * возвращается в цикл каждый раз. Отдельный счётчик отвечает, дерутся ли цели
         * за слот, или он просто занят той же самой. */
        if (meta->guest_addr == next->guest_addr)
            return true;   /* уже сшито ровно с этой целью */
        t_chain_decline[CHAIN_DECL_ALREADY_OTHER]++;
        {   /* Чем лечить — зависит от завершителя источника, не от догадки. */
            const hb_ir_block_t* cb = cur->block;
            const hb_ir_instr_t* t = (cb && cb->instr_count) ?
                                     &cb->instrs[cb->instr_count - 1] : NULL;
            if (!t) { /* нечем классифицировать */ }
            else if (t->op == HB_IR_Jcc) t_chain_decline[CHAIN_DECL_OTHER_JCC]++;
            else if ((t->op == HB_IR_JMP || t->op == HB_IR_CALL) &&
                     t->src1.type != HB_OP_NONE && t->src1.type != HB_OP_IMM)
                t_chain_decline[CHAIN_DECL_OTHER_INDIRECT]++;
            else t_chain_decline[CHAIN_DECL_OTHER_DIRECT]++;
        }
        if (runtime_chain_two_slots_enabled()) {
            /* Первая щель занята ЧУЖОЙ целью. У блока с условным переходом есть вторая —
             * её и займём, вместо того чтобы отказывать (что и делали 4,7 млн раз). */
            if (meta->slot2_target_code)
                return meta->slot2_guest_addr == next->guest_addr;
            {
                size_t off2 = entry_second_slot_offset(cur);
                if (off2 && chain_patch_slot2(rt, cur, next, meta, off2))
                    return true;
                t_chain_decline[CHAIN_DECL_NO_SLOT2]++;
            }
        }
        if (runtime_chain_direct_enabled()) {
            /* ПРЯМОЕ РЕБРО: щель стоит у самой записи `pc`, цель совпадает по построению,
             * проверки в исполнении нет вовсе. Ищем ту, что метит ровно в наш блок. */
            size_t offd = 0;
            if (find_direct_edge_slot(cur, next->guest_addr, &offd) &&
                chain_patch_direct_edge(rt, cur, next, offd)) {
                t_chain_decline[CHAIN_DECL_PATCHED_DIRECT]++;
                return true;
            }
            t_chain_decline[CHAIN_DECL_NO_DIRECT]++;
        }
        return false;
        /* "Already chained to this same successor?" — answered by the guest address stored
         * alongside, not by the code pointer. meta->target_code holds the TRAMPOLINE address
         * (assigned from `target` below), never next->native_code + 16, so the old comparison
         * was unconditionally false: a tail that was already patched always reported failure and
         * could never be re-aimed. The trampoline also enters its target at +12
         * (chain_trampoline_for) while update_indirect_ic uses +16, so no single constant would
         * have made the pointer form right either. */
        return meta->guest_addr == next->guest_addr;
    }
    if (!block_terminal_is_chainable(cur->block)) {
        t_chain_decline[CHAIN_DECL_TERMINAL]++;
        return false;
    }
    if (runtime_chain_refuse_near() && chain_edge_is_near(cur->guest_addr, next->guest_addr)) {
        t_chain_decline[CHAIN_DECL_REFUSED]++;
        return false;
    }
    /* ★ 04.09.2026 — БЕЗУСЛОВНО, ГЕЙТ СНЯТ.
     *
     * Разбор выше (18.08) назвал причину верно, но оставил её под переменной с
     * умолчанием 0 — то есть защита не работала ни в одном обычном прогоне. Замер
     * 04.09 на Hollow Knight: со сцеплением x64 прогон гибнет, и `run-exit` прямо
     * говорит `reason=import-thunk`, pc=0x6f0000003c60, байты `ff 15 ...` —
     * косвенный вызов через таблицу импорта.
     *
     * Это не настройка. Прямой переход в переходник импорта неверен ВСЕГДА:
     * адрес за ним правит загрузчик (отложенное связывание, перенаправление
     * ARM64EC), а сцепление снимает тот самый возврат в диспетчер, который эту
     * правку подхватывал. Условие, при котором сшивать можно, назвать нельзя —
     * значит гейту здесь не место. */
    /* ★ 04.09.2026, ТРЕТИЙ УРОВЕНЬ — РАЗВЕДЕНЫ ДВА РОДА ПЕРЕХОДНИКОВ.
     *
     * Запрет был общий, а причины у родов РАЗНЫЕ, и одна из них при разборе не
     * подтвердилась.
     *
     * (1) ЗАГЛУШКА В САМОМ PE (`ff 25` = JMP [RIP+disp32]). Довод запрета был:
     *     «адрес за переходником правит загрузчик, а сцепление снимает возврат в
     *     диспетчер, который правку подхватывал». Разбор показывает, что подхват
     *     диспетчером тут ни при чём: у заглушки СВОЙ переведённый блок, и он
     *     ЧИТАЕТ ячейку IAT на каждом исполнении — перевод `jmp [rip+disp]`
     *     косвенный, адрес в нём не зашит. Значит после правки загрузчика блок
     *     заглушки сам вычислит НОВЫЙ `ctx->pc`, а страж трамплина у следующего
     *     ребра сверит его с ожидаемым и промахнётся в диспетчер. Терять этот
     *     класс рёбер не за что: обесценивание уже встроено в устройство.
     *     Отпечаток SMC тоже ничего не теряет — байты `ff 25 disp32` не меняются,
     *     меняется ЯЧЕЙКА, а она в отпечаток блока и не входила никогда.
     *
     * (2) НАША АРЕНА (`HB_IMPORT_THUNK_BASE`). Здесь запрет остаётся, и это НЕ
     *     та же причина. Смысл арены исполняется ВНЕ диспетчера: внешний цикл
     *     (macrunner_hb_run_x64) узнаёт адрес арены, вызывает нативную реализацию
     *     импорта и не возвращается в выпущенный код вовсе. Сшитое ребро в арену
     *     обошло бы эту семантику целиком — это не устаревший адрес, а ПОТЕРЯ
     *     реализации вызова. Условия, при котором так можно, не существует.
     *
     * ЗАМЕРЕНО 04.09 (Hollow Knight, сцепление x64, дист со сверенным отпечатком),
     * счётчики в строке `macrunner-hb-chainedge-cls`:
     *   · thunk_арена = 0     — род (2) на этом заголовке НЕ ВСТРЕЧАЕТСЯ НИ РАЗУ.
     *     То есть все 41 прежних отказа `import_thunk` были родом (1), а разбор,
     *     заведший проверку диапазона арены, приписывал их не тому роду.
     *   · thunk_ff25 = 3, thunk_ff25_сшито = 3 — с ручкой все три ребра сшиты,
     *     `import_thunk` из строки отказов исчезает, заплат 9918 против 9914.
     *   · тройка (reason, pc, last_block) НЕ СДВИНУЛАСЬ: та же, что в руке с
     *     запретом (import-thunk / 0x6f0000003c60 / 0x87ef31c0c07), пять прогонов.
     *     Значит класс возвращён и нового отказа не внёс.
     * Почему 41 отказ превращается в 3 заплаты: сшитое ребро на следующих
     * проходах отсекается раньше, по `meta->target_code` (already).
     *
     * Ручка MACRUNNER_HB_CHAIN_IMPORT_GUARD пока остаётся с умолчанием 0. Не
     * потому, что довод слаб, а потому, что доказательство «не сломалось» снято
     * на заголовке, который в той руке всё равно гибнул по другой причине.
     *
     * ★ 05.09.2026 — ПОСЫЛКА ЭТОГО АБЗАЦА УСТАРЕЛА, И ЭТО ЗАПИСАНО, А НЕ ОСТАВЛЕНО
     * ВРАТЬ. Здесь стояло «на умолчания это не влияет: MACRUNNER_HB_BLOCK_CHAIN_X64
     * сам по себе выключен». Гейт УДАЛЁН, сцепление x64 включено безусловно и
     * доходит до живого прогона (Hollow Knight берёт swapchain со сцеплением, серия
     * 5 пар). Значит условие «безусловным приём делается тем, кто доведёт сцепление
     * x64 до живого прогона» ВЫПОЛНЕНО — но выполнение условия не есть замер:
     * заплаты по этой ручке считаны 41 -> 3, а времени до вехи ей никто не мерил.
     * Поэтому умолчание 0 сохранено, и снимать его надо СВОИМ замером, а не тем.
     * На i386 ручка по-прежнему ничего не меняет.
     *
     * Счётчики родов разведены БЕЗУСЛОВНО — без них «41 отказ» не говорит, какого
     * он рода, и ноль по арене не отличался бы от «не считалось». */
    {
        int kind = chain_target_thunk_kind(rt, next->guest_addr);
        if (kind != HB_THUNK_NONE) {
            static uint64_t skipped;
            uint64_t k;
            int allow = (kind == HB_THUNK_PE_FF25) &&
                        runtime_gate_flag( HB_GATE_HB_CHAIN_IMPORT_GUARD, 0);

            if (kind == HB_THUNK_ARENA) __atomic_add_fetch(&g_thunk_arena, 1, __ATOMIC_RELAXED);
            else                        __atomic_add_fetch(&g_thunk_ff25,  1, __ATOMIC_RELAXED);
            if (allow) __atomic_add_fetch(&g_thunk_ff25_chained, 1, __ATOMIC_RELAXED);

            k = __atomic_add_fetch(&skipped, 1, __ATOMIC_RELAXED);
            if (k <= 4 || (k % 4096) == 0) {
                fprintf(stderr, "macrunner-hb-chain-skip-import: n=%llu next=0x%llx род=%s "
                        "сшито=%d\n",
                        (unsigned long long)k, (unsigned long long)next->guest_addr,
                        kind == HB_THUNK_ARENA ? "арена" : "ff25", allow);
                fflush(stderr);
            }
            if (!allow) {
                t_chain_decline[CHAIN_DECL_IMPORT_THUNK]++;
                return false;
            }
        }
    }
    if (runtime_chain_forward_only_enabled() && next->guest_addr <= cur->guest_addr) {
        t_chain_decline[CHAIN_DECL_BACKEDGE]++;
        return false;
    }
    if (!entry_has_chain_slot(cur, &patch_offset)) {
        t_chain_decline[CHAIN_DECL_SLOT_CUR]++;
        return false;
    }
    if (!entry_has_chain_slot(next, NULL)) {
        t_chain_decline[CHAIN_DECL_SLOT_NEXT]++;
        return false;
    }

    /* Through the trampoline, not at the code: see chain_trampoline_build above. Falling back to
     * the raw address would reintroduce exactly the dangling-branch hazard this exists to remove,
     * so a trampoline we cannot create means we do not chain. */
    target = chain_trampoline_for(rt, next);
    if (!target) { t_chain_decline[CHAIN_DECL_TRAMP]++; return false; }
    patch = cur->native_code + patch_offset;
    if (!arm64_branch_reaches(patch + sizeof(uint32_t), target)) {
        t_chain_decline[CHAIN_DECL_REACH]++;
        return false;
    }

    /* Bisect stop: the trampoline above is committed, the block tail is left alone. */

    {
        uint64_t cap = runtime_chain_max_patches();
        uint64_t n = __atomic_add_fetch(&g_chain_patches_installed, 1, __ATOMIC_RELAXED);
        if (cap && n > cap) {
            __atomic_sub_fetch(&g_chain_patches_installed, 1, __ATOMIC_RELAXED);
            t_chain_decline[CHAIN_DECL_CAPPED]++;
            return false;
        }
        /* MacRunner 2026-08-18 — печатать ещё и рёбра У САМОГО ПОТОЛКА.
         *
         * Бисект 2446 зажал порог между 8192 (жив) и 16384 (мёртв): фатальна заплата с номером
         * из этого промежутка. Печать первых 64 до неё не доходит НИКОГДА, и именно поэтому
         * девять прогонов не назвали ни одного ребра. Условие ниже добавляет последние 32 перед
         * потолком: с MAX_PATCHES=16384 в журнал попадут заплаты 16353…16384 — те самые, после
         * которых прогон умирает, вместе с гостевыми байтами обоих концов. */
        if (trace_chain_edge_enabled() &&
            (n <= 64 || (cap && n + 32 > cap) ||
             (chain_edge_from() && n >= chain_edge_from()) ||
             chain_edge_is_near(cur->guest_addr, next->guest_addr))) {
            /* MacRunner 2026-08-04 — печатаем ещё и гостевые байты обоих концов ребра.
             *
             * Бисект по MACRUNNER_HB_CHAIN_MAX_PATCHES показал, что ОДНОГО пропатченного ребра
             * достаточно, чтобы загрузка умерла (exit=3 на +52 с), и это ребро детерминировано —
             * одни и те же cur/next от прогона к прогону.  Адреса сами по себе ничего не
             * называют: базы гостевых модулей в лог не попадают.  А байты называют — узор
             * ищется по файлам игры и даёт модуль и функцию, как это уже дважды сработало
             * (mono_sha1_update, микшер UnityPlayer).  Читаем охраняемо, тем же способом, что
             * и hot-bytes, и только под гейтом трассы рёбер. */
            fprintf(stderr, "macrunner-hb-chainedge: n=%llu cur=0x%llx next=0x%llx tramp=%p",
                    (unsigned long long)n, (unsigned long long)cur->guest_addr,
                    (unsigned long long)next->guest_addr, (void*)target);
            if (rt->ctx && rt->ctx->memory) {
                const char* label[2] = { " cur_bytes=", " next_bytes=" };
                uint64_t addr[2] = { cur->guest_addr, next->guest_addr };
                int k;
                for (k = 0; k < 2; k++) {
                    uint8_t byte;
                    size_t i;
                    fprintf(stderr, "%s", label[k]);
                    for (i = 0; i < 16; i++) {
                        if (hb_memory_read_u8(rt->ctx->memory, (hb_gva_t)(addr[k] + i), &byte) != HB_OK) {
                            fprintf(stderr, "%s??", i ? " " : "");
                            break;
                        }
                        fprintf(stderr, "%s%02x", i ? " " : "", byte);
                    }
                }
            }
            fprintf(stderr, "\n");
            fflush(stderr);
        }
    }

    if (hb_jit_buffer_make_writable(rt->jit_mem) != HB_OK) {
        t_chain_decline[CHAIN_DECL_WPROT]++;
        return false;
    }
    arm64_store_u32(rt->jit_mem, patch, arm64_mov_reg_u32(0, 19)); /* MOV X0, X19 (ctx) */
    arm64_store_u32(rt->jit_mem, patch + sizeof(uint32_t),
                    arm64_b_to(patch + sizeof(uint32_t), target));
    block_cache_clear_icache(rt->jit_mem, patch, 2 * sizeof(uint32_t));
    ok = hb_jit_buffer_make_executable(rt->jit_mem) == HB_OK;
    if (!ok) { t_chain_decline[CHAIN_DECL_XPROT]++; return false; }
    t_chain_decline[CHAIN_DECL_PATCHED]++;
    chain_seen_add(cur->guest_addr, next->guest_addr);

    meta->guest_addr = next->guest_addr;
    meta->target_code = target;
    meta->patch_offset = patch_offset;
    return true;
}

static void update_indirect_ic(hb_context_t* ctx, hb_block_cache_entry_t* target,
                               bool enabled) {
    hb_ic_slot_t* slot;

    if (!ctx) return;

    /* Слот того косвенного сайта, с которого пришёл промах. Сгенерированный код кладёт
     * его перед сверкой; ноль означает «сайт транслирован без пер-сайтового кеша»
     * (гейт выключен либо слоты кончились) — тогда работаем по общим полям, как раньше. */
    slot = (hb_ic_slot_t*)(uintptr_t)ctx->indirect_ic_slot;

    /* MacRunner ЛЕСТНИЦА 2026-08-09 — УЛИКА для инлайн-кеша косвенных переходов.
     *
     * До этого у кеша не было ни одного прибора: `hb_ic_slot_stats()` написана и её не звал
     * НИКТО. Поэтому A/B по нему был заведомо недействителен — по правилу проекта гейт без
     * доказанной активности считается выключенным. А активности и не было: мастер-гейт
     * MACRUNNER_HB_INDIRECT_IC имеет умолчание 0, и emit_indirect_ic_probe выходил первой
     * строкой, тогда как MACRUNNER_HB_INDIRECT_IC_PERSITE (умолчание 1) сам по себе мёртв.
     *
     * Печать безусловная и по периоду: если мастер выключен, `allocated=0` и `slots=0` —
     * это и есть доказательство, что кеш не работает, а не догадка о нём.
     * Здесь обычный контекст, не обработчик сигнала, поэтому fprintf допустим. */
    {
        static uint64_t ic_misses, ic_with_slot;
        uint64_t n = __atomic_add_fetch(&ic_misses, 1ull, __ATOMIC_RELAXED);

        if (slot) __atomic_add_fetch(&ic_with_slot, 1ull, __ATOMIC_RELAXED);
        if (n <= 4 || !(n & 0xffffu)) {
            uint64_t allocated = 0, exhausted = 0, cleared = 0;

            hb_ic_slot_stats(&allocated, &exhausted, &cleared);
            fprintf(stderr, "macrunner-hb-indirect-ic: misses=%llu with_slot=%llu "
                    "sites_allocated=%llu exhausted=%llu cleared=%llu enabled=%d\n",
                    (unsigned long long)n,
                    (unsigned long long)__atomic_load_n(&ic_with_slot, __ATOMIC_RELAXED),
                    (unsigned long long)allocated, (unsigned long long)exhausted,
                    (unsigned long long)cleared, (int)enabled);
            fflush(stderr);
        }
    }

    if (!enabled || !target || !target->valid || !target->native_code ||
        !block_terminal_is_chainable(target->block) || !entry_has_chain_slot(target, NULL)) {
        if (slot) {
            /* Порядок гашения тот же, что в hb_ic_slots_clear_all: сперва натив. */
            __atomic_store_n(&slot->native, 0ull, __ATOMIC_RELAXED);
            __atomic_store_n(&slot->guest, 0ull, __ATOMIC_RELAXED);
        }
        ctx->indirect_ic_guest_addr = 0;
        ctx->indirect_ic_native_code = 0;
        return;
    }

    if (slot) {
        /* Заполнение в обратном порядке: гостевой адрес встаёт ПОСЛЕДНИМ, поэтому
         * сверка по нему никогда не пропустит к ещё не записанному нативному адресу. */
        __atomic_store_n(&slot->native,
                         (uint64_t)(uintptr_t)(target->native_code + 16), __ATOMIC_RELAXED);
        __atomic_store_n(&slot->guest, target->guest_addr, __ATOMIC_RELAXED);
        return;
    }

    ctx->indirect_ic_guest_addr = target->guest_addr;
    ctx->indirect_ic_native_code = (uint64_t)(uintptr_t)(target->native_code + 16);
}

/* ЕДИНИЦА, итерация 47 — ПРЕДПОСЫЛКА БЕЗОПАСНОСТИ для слияния блоков.
 *
 * Считалось до сих пор: у блока ровно один переход, и он последний. Тогда «шагов до первого
 * перехода» = весь блок, и block_guest_span (:3044) по этим шагам даёт диапазон гостевых
 * байтов, которым ключуется кеш трансляций и по которому идёт перепроверка SMC.
 *
 * Со слиянием (MACRUNNER_HB_MERGE_BLOCKS, лифтер hb_lift_x86.c) переходов в блоке несколько.
 * Прежняя формула вернула бы шаги до ПЕРВОГО из них, диапазон покрыл бы только первый
 * подблок — и запись гостя в продолжение слитой единицы прошла бы мимо перепроверки.
 * Устаревший перевод продолжил бы исполняться МОЛЧА. Это не гипотеза о будущем: ровно так
 * ключ и считается сегодня (hb_cache_key_compute <- block_guest_span <- эта функция).
 *
 * Поэтому при включённом слиянии считаем до ПОСЛЕДНЕГО перехода, то есть по всей единице.
 * Гейт нужен: без него изменилось бы поведение блоков с переходом в середине (HB_TERM_XFER_MID),
 * которые встречаются и без слияния, а на них завязан подсчёт шагов у соседних лейнов.
 *
 * Предохранитель уже есть и остаётся: block_guest_span отвергает диапазон больше 4096 байт,
 * поэтому слишком длинная слитая единица просто не попадёт в кеш — это безопасный отказ. */
static int merge_blocks_enabled(void) {
    const char* v = hb_gate( HB_GATE_HB_MERGE_BLOCKS );
    int cached = (v && *v && *v != '0') ? 1 : 0;
    return cached;
}

static bool codegen_is_transfer_op_rt(hb_ir_op_t op) {
    return op == HB_IR_CALL || op == HB_IR_RET || op == HB_IR_JMP ||
           op == HB_IR_Jcc || op == HB_IR_LOOP || op == HB_IR_JRCXZ;
}

static uint32_t jit_block_step_count(const hb_ir_block_t* block) {
    const hb_ir_instr_t* transfer = first_control_transfer_instr(block);
    if (!block) return 0;
    if (!transfer) return (uint32_t)block->instr_count;
    if (merge_blocks_enabled()) {
        size_t i, last = (size_t)(transfer - block->instrs);
        for (i = last + 1; i < block->instr_count; i++)
            if (codegen_is_transfer_op_rt(block->instrs[i].op)) last = i;
        return (uint32_t)(last + 1);
    }
    return (uint32_t)((size_t)(transfer - block->instrs) + 1);
}

static void sync_arch_pc_after_jit_block(hb_context_t* ctx) {
    if (!ctx) return;
    if (ctx->arch == HB_ARCH_X64) ctx->regs.x64.rip = ctx->pc;
    else if (ctx->arch == HB_ARCH_X86) ctx->regs.x86.eip = (uint32_t)ctx->pc;
}

static void set_helper_fault_result(hb_exec_result_t* out, hb_context_t* ctx,
                                    uint64_t steps, uint64_t blocks_executed) {
    /* MacRunner 2026-08-27 — НАЗВАТЬ ОПЕРАЦИЮ ПОМОЩНИКА, а не только код отказа.
     *
     * Прибор место=4480 говорит UNSUPPORTED_FEATURE, но мест, где ставится last_result,
     * сто семьдесят четыре — по коду источник не найти. Приборы на __LINE__ в трёх файлах
     * дали ноль срабатываний при трёх отказах: значит присваивание, а не return.
     *
     * Для этого уже заведены last_helper_op и last_helper_guest (итерация 265) — печатаем
     * их здесь, где отказ и так виден. */
    if (ctx && ctx->last_result != HB_OK) {
        static unsigned int hw_n;
        unsigned int hn = ++hw_n;
        extern const char* hb_ir_op_name_public(int op);
        if (hn <= 12) {
            fprintf(stderr, "macrunner-hb-helper-why: n=%u результат=%d операция=%s(%d) гость=0x%llx pc=0x%llx\n",
                    hn, (int)ctx->last_result,
                    ctx->last_helper_op >= 0 ? hb_ir_op_name_public(ctx->last_helper_op) : "-",
                    ctx->last_helper_op,
                    (unsigned long long)ctx->last_helper_guest,
                    (unsigned long long)ctx->pc);
            fflush(stderr);
        }
    }
    out->result = ctx->last_result;
    { /* Итерация 307: назвать МЕСТО. Печать безусловная, первые 4 раза на место. */
      static int said_4480; extern const char* hb_result_string(int);
      if (out->result != HB_OK && said_4480++ < 4)
        fprintf(stderr, "macrunner-hb-result-site: место=4480 результат=%s(%d) pc=%#llx\n",
                hb_result_string(out->result), (int)out->result,
                0ULL); }
    out->steps_executed = steps;
    out->blocks_executed = blocks_executed;
    out->faulted = true;
    out->fault_reason = "JIT helper fault";

    /* MacRunner 2026-08-09 — назвать АДРЕС, а не только причину.
     *
     * `runtime-fail` печатает block_pc, но на HK он лежит в коде, сгенерированном Mono, и в
     * каждом прогоне другой (0x51ffae4e3, 0x16ba44773, 0x17ff32e33) — сузить по нему нечего.
     * Адрес обращения теперь пишется в hb_memory.c на трёх публичных входах; здесь он просто
     * называется. Печать безусловная и одна на отказ: отказ этот смертельный (за ним exit=5),
     * так что шуметь нечему. */
    {
        uint64_t fa = 0; size_t fs = 0; int fw = 0, fv = 0;
        hb_memory_last_fault(&fa, &fs, &fw, &fv);
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: печатаем ещё и базу сегмента FS.
         * Отказ ступени 1 приходит по guest_addr=0x18 из инструкции movl %fs:0x18,%edi.
         * Различаем две версии: база неверна (fs_base != TEB32) или база верна, но этот
         * путь её не применяет (fs_base верна, а адрес всё равно 0x18). */
        {
            /* Итерация 265: имя последней операции помощника — она и есть причина отказа. */
            /* 2026-08-22: обе величины переехали из потоковых в `ctx` — разбор у полей в
             * hb_context.h. Здесь `ctx` уже на руках, так что печать не изменилась. */
            const int lho = ctx ? ctx->last_helper_op : -1;
            const unsigned long long lhg = ctx ? ctx->last_helper_guest : 0ull;
            fprintf(stderr, "macrunner-hb-helper-fault-addr: valid=%d guest_addr=%#llx size=%zu %s "
                    "pc=%#llx last_result=%d fs_base=%#llx ctx=%p помощник_op=%d guest=%#llx\n",
                    fv, (unsigned long long)fa, fs, fw ? "WRITE" : "READ",
                    (unsigned long long)(ctx ? ctx->pc : 0), ctx ? (int)ctx->last_result : 0,
                    (unsigned long long)(ctx ? ctx->fs_base : 0), (void*)ctx,
                    lho, lhg);
            {
                extern const char* hb_ir_op_name_public(int op);
                fprintf(stderr, "macrunner-hb-helper-fault-op: name=%s op=%d guest=%#llx\n",
                        lho >= 0 ? hb_ir_op_name_public(lho) : "-", lho, lhg);
            }

            /* ★★★★★★ MacRunner 2026-08-29 — ИНВАРИАНТ: ВСЕ ИСТОЧНИКИ ИСТИНЫ РАЗОМ.
             *
             * Разбирать по одному («может perm_map? может кеш? может gen?») —
             * прогон за гипотезу. Источников всего четыре, и в момент отказа они
             * ОБЯЗАНЫ совпадать. Печатаем их вместе: расхождение видно сразу, без
             * перебора.
             *
             * Так уже был найден отказ по `0xA4DFE88`: адрес лежал внутри региона
             * `0a4c0000-0a4e0000` с правами RW, `can_r=1` — и всё равно
             * MEMORY_FAULT. Значит расходятся не ОС и карта, а карта регионов и
             * то, что реально проверяет помощник. */
            if (fv && ctx && ctx->memory)
            {
                const hb_region_t* reg = hb_memory_find_region( ctx->memory, (hb_gva_t)fa );
                int can_r  = hb_memory_can_read( ctx->memory, (hb_gva_t)fa, fs ? fs : 1 );
                int can_x  = hb_memory_can_exec( ctx->memory, (hb_gva_t)fa, 1 );
                int span   = hb_memory_can_read_span( ctx->memory, (hb_gva_t)fa, fs ? fs : 1 );
                void* host = ctx->memory ? (void*)hb_memory_guest32_to_host( ctx->memory, (uint32_t)fa ) : NULL;

                /* pid: у Diablo в одном журнале несколько процессов, без него
                 * строки разных процессов читаются как противоречие одного. */
                fprintf(stderr,
                        "macrunner-hb-ИНВАРИАНТ: [pid=%d] адрес=%#llx размер=%zu | регион=%s",
                        (int)getpid(), (unsigned long long)fa, fs, reg ? "ЕСТЬ" : "НЕТ");
                if (reg)
                    fprintf(stderr, " [%08llx..%08llx perm=%d]",
                            (unsigned long long)reg->base,
                            (unsigned long long)(reg->base + reg->size), (int)reg->perm);
                fprintf(stderr, " | can_read=%d can_exec=%d span=%d | host=%p | gen=%u\n",
                        can_r, can_x, span, host,
                        (unsigned)__atomic_load_n(&ctx->memory->hot_gen, __ATOMIC_ACQUIRE));
                fflush(stderr);
                /* ★ След пути: без него по одному снимку регистров нельзя сказать,
                 * ГДЕ испортилось значение — только что оно испорчено. */
                hb_runtime_dump_path();
            }
        }
        fflush(stderr);
    }
}

static hb_result_t set_runtime_fault_result(hb_exec_result_t* out, hb_context_t* ctx,
                                            hb_result_t result, uint64_t steps,
                                            uint64_t blocks_executed,
                                            const char* reason) {
    /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 306 — НАЗВАТЬ МЕСТО ОТКАЗА.
     *
     * Печать декодера (итерация 262) безусловна и НЕ срабатывает, значит `UNSUPPORTED_OPCODE`
     * приходит не из декодера, а из лифтера, интерпретатора или кодогенератора. По `out_eip`
     * место не найти: это точка остановки, а весь блок вокруг неё разбирается зондом без
     * отказа (проверено покомандно на 96 байтах — 28 команд, отказов ноль).
     *
     * Здесь единственная верхняя точка, через которую отказ становится результатом прогона.
     * Печатаем PC и последнюю операцию помощника; первые 8 раз, без гейта — событие фатальное. */
    if (result != HB_OK) {
        static int said;
        if (said++ < 8) {
            const int lho = ctx ? ctx->last_helper_op : -1;   /* было потоковой, 2026-08-22 */
            extern const char* hb_ir_op_name_public(int op);
            fprintf(stderr, "macrunner-hb-fault-where: result=%d причина=%s pc=%#llx шагов=%llu блоков=%llu "
                    "последняя_операция=%s(%d)\n",
                    (int)result, reason ? reason : "-",
                    (unsigned long long)(ctx ? ctx->pc : 0),
                    (unsigned long long)steps, (unsigned long long)blocks_executed,
                    lho >= 0 ? hb_ir_op_name_public(lho) : "-", lho);
            fflush(stderr);
        }
    }
    if (ctx) ctx->last_result = result;
    out->result = result;
    { /* Итерация 307: назвать МЕСТО. Печать безусловная, первые 4 раза на место. */
      static int said_4550; extern const char* hb_result_string(int);
      if (out->result != HB_OK && said_4550++ < 4)
        fprintf(stderr, "macrunner-hb-result-site: место=4550 результат=%s(%d) pc=%#llx\n",
                hb_result_string(out->result), (int)out->result,
                0ULL); }
    out->steps_executed = steps;
    out->blocks_executed = blocks_executed;
    out->faulted = true;
    out->fault_reason = reason;
    return result;
}

/* ── Перепись причин ухода в интерпретатор ────────────────────────────────────
 *
 * Замер 08.08: 176 500 276 шагов исполнены интерпретатором, а не транслированным кодом.
 * Интерпретируемый шаг дороже транслированного в десятки раз, так что эти проценты по
 * числу шагов превращаются в куда большую долю времени. Тринадцать точек в этом файле
 * возвращают отказ JIT со СВОЕЙ причиной, но никто их не считал — и потому неизвестно,
 * закрывается ли это конечным списком неподдержанных команд (тогда лечится массовым
 * покрытием ISA, как уже делалось для опкодов) или это единичный горячий случай.
 *
 * Причины — строковые литералы, их адреса стабильны, поэтому ключом служит указатель:
 * ни разбора строк, ни выделений на пути отказа. Гейт MACRUNNER_HB_TRACE_INTERP_REASON.
 */
#define HB_INTERP_REASON_MAX 48
static const char* g_interp_reason_key[HB_INTERP_REASON_MAX];
static unsigned long long g_interp_reason_cnt[HB_INTERP_REASON_MAX];
static unsigned g_interp_reason_n;
static unsigned long long g_interp_reason_total;

static int interp_reason_trace_enabled(void) {
    const char* v = hb_gate( HB_GATE_HB_TRACE_INTERP_REASON );
    int cached = (v && *v && *v != '0') ? 1 : 0;
    return cached;
}

static void interp_reason_note(const char* reason) {
    unsigned i;
    if (!interp_reason_trace_enabled()) return;
    if (!reason) reason = "(без причины)";
    for (i = 0; i < g_interp_reason_n; i++) {
        if (g_interp_reason_key[i] == reason) { g_interp_reason_cnt[i]++; goto counted; }
    }
    if (g_interp_reason_n < HB_INTERP_REASON_MAX) {
        i = g_interp_reason_n++;
        g_interp_reason_key[i] = reason;
        g_interp_reason_cnt[i] = 1;
    }
counted:
    /* MacRunner 2026-08-09 — ПЕРИОД СНИЖЕН С 200 000 ДО 4096 + первая печать.
     *
     * С периодом 200 000 прибор молчал ВЕСЬ прогон: гейт стоял, а строк ноль, и по правилу
     * лейна результат нельзя засчитать ни в какую сторону. 176 млн из комментария выше — это
     * ШАГИ интерпретатора, а отказов JIT (блоков) на порядки меньше, и до 200 000 они за
     * измеряемое окно не добирают. Тот же класс, что счётчик module_machine с периодом 50 000,
     * который печатал только холодное первое обращение. */
    ++g_interp_reason_total;
    if (g_interp_reason_total == 1 || (g_interp_reason_total & 0xfffull) == 0) {
        unsigned k;
        fprintf(stderr, "macrunner-hb-interp-reason: всего=%llu различных=%u\n",
                g_interp_reason_total, g_interp_reason_n);
        for (k = 0; k < g_interp_reason_n; k++)
            fprintf(stderr, "macrunner-hb-interp-reason:   %8llu (%5.2f%%) %s\n",
                    g_interp_reason_cnt[k],
                    100.0 * (double)g_interp_reason_cnt[k] / (double)g_interp_reason_total,
                    g_interp_reason_key[k] ? g_interp_reason_key[k] : "?");
        fflush(stderr);
    }
}

static hb_result_t set_jit_interp_fallback_result(hb_exec_result_t* out,
                                                  hb_result_t result,
                                                  uint64_t steps,
                                                  uint64_t blocks_executed,
                                                  const char* reason) {
    interp_reason_note(reason);
    out->result = result;
    { /* Итерация 307: назвать МЕСТО. Печать безусловная, первые 4 раза на место. */
      static int said_4625; extern const char* hb_result_string(int);
      if (out->result != HB_OK && said_4625++ < 4)
        fprintf(stderr, "macrunner-hb-result-site: место=4625 результат=%s(%d) pc=%#llx\n",
                hb_result_string(out->result), (int)out->result,
                0ULL); }
    out->steps_executed = steps;
    out->blocks_executed = blocks_executed;
    out->faulted = true;
    out->fault_reason = reason;
    return HB_OK;
}

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: назвать операцию, которую кодогенератор не переварил.
 * Отказ кодогенерации и так смертелен (out->faulted = true), поэтому печать безусловная и
 * стоит на уже проигранном пути. Имён у операций IR нет, печатаем НОМЕР и гостевой адрес —
 * номер сопоставляется с перечислением в hb_ir.h. Первые четыре отказа, дальше молчим. */
static void codegen_fail_note(const hb_ir_block_t* blk, hb_result_t r) {
    static int n;
    size_t k;
    if (n >= 4) return;
    n++;
    fprintf(stderr, "macrunner-hb-codegen-fail: n=%d r=%d instrs=%zu ops=",
            n, (int)r, blk ? (size_t)blk->instr_count : (size_t)0);
    if (blk) {
        for (k = 0; k < blk->instr_count && k < 48; k++)
            fprintf(stderr, "%d@%#llx ", (int)blk->instrs[k].op,
                    (unsigned long long)blk->instrs[k].guest_addr);
    }
    fprintf(stderr, "\n");
    fflush(stderr);
}

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ★ ОТКАТ НА ИНТЕРПРЕТАТОР — ГЛАВНЫЙ ЗОНТИК.
 *
 * До этой правки отказ кодогенерации УБИВАЛ процесс: ниже ставилось faulted=true и
 * fault_reason="JIT codegen failed", вызывающая сторона переводила это в c000001d, и гость
 * умирал. Так Diablo умирал на cvtsi2sd в нашей же crtdll.dll (итерация 99).
 *
 * При этом интерпретатор реализует ВСЕ операции IR и лежит в этом же дереве. Пробел
 * кодогенерации обязан быть МЕДЛЕННЫМ ПУТЁМ, а не смертью — тогда любая невиданная форма
 * команды (x87, редкие кодировки, всё, чего нет в матрице) перестаёт быть смертельной.
 *
 * Стартуем с ТЕКУЩЕГО блока, а не с входа функции: часть блоков уже исполнена выпущенным
 * кодом, и повтор с начала исказил бы состояние гостя.
 *
 * Гейт MACRUNNER_HB_INTERP_FALLBACK СНЯТ 02.09.2026: правка безусловна,
 * выключенная ветка возвращала известный дефект (scripts/гейты.py).
 * Умолчание именно ВКЛ: альтернатива откату — гибель процесса, поэтому «безопасное»
 * умолчание здесь как раз включённое. */
/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ИСПЫТАТЕЛЬНЫЙ крючок для отката.
 * Непроверенная страховка бесполезна, а настоящих пробелов кодогенерации на Diablo уже нет
 * (семьи преобразований и сдвигов закрыты в итерации 100). Поэтому отказ можно вызвать
 * искусственно: MACRUNNER_HB_CODEGEN_FAIL_EVERY=N объявляет каждый N-й блок непереваренным.
 * Только для проверки, умолчание 0 = выключено. */
static int hb_codegen_fail_every(void) {
    static int every = -1;
    if (every < 0) {
        const char* v = hb_gate( HB_GATE_HB_CODEGEN_FAIL_EVERY );
        every = (v && v[0]) ? atoi(v) : 0;
        if (every < 0) every = 0;
    }
    return every;
}

static int hb_codegen_should_fail_now(void) {
    static unsigned long long seen;
    int every = hb_codegen_fail_every();
    if (!every) return 0;
    return (++seen % (unsigned long long)every) == 0;
}

/* MacRunner 2026-08-22, КООРДИНАТОР — ПЕРЕИГРОВКА БЛОКА ПОСЛЕ АППАРАТНОГО ОТКАЗА.
 *
 * Сторож блока умеет забрать отказ в выпущенном коде (дверь `hb_jit_runtime_handle_signal_fault`,
 * в обработчик `hb_memory.c` её завела ЛЕСТНИЦА итерацией 2651) — но дальше возвращал
 * `HB_ERR_UNSUPPORTED_FEATURE` с пометкой «interpreter fallback», а САМОЙ переигровки не делал.
 * Пометку обязан был отработать вызывающий, и `hb_runtime_run` её не отрабатывает.
 *
 * Из-за этого проба `jit_store_unmapped_faults` (hb_test_runner.c:7639) получает
 * `UNSUPPORTED_FEATURE` вместо `HB_ERR_MEMORY_FAULT`, хотя договор именно такой: запись по
 * неотображённому адресу — это ОТКАЗ ГОСТЯ, а не «возможность не поддержана».
 *
 * Механизм переигровки уже есть и включён по умолчанию — `hb_codegen_fail_to_interp`,
 * им же лечится провал кодогенерации. Снимок гостя сторож к этому моменту уже восстановил,
 * значит интерпретатор пройдёт блок с начала и сделает то же обращение программным путём,
 * где проверка прав есть и отказ становится штатным.
 *
 * ★ Блок переигрывается ЦЕЛИКОМ, поэтому записи, успевшие пройти до отказа, повторятся.
 * Это ограничение всего пути отката по блоку, а не новое: снимок восстанавливает регистры,
 * но не память, и `hb_codegen_fail_to_interp` живёт с тем же допущением с самого начала.
 * Точное возобновление с отказавшей команды требует карты позиций (она есть, гейт выключен —
 * см. `ripmap`), и это отдельная работа.
 *
 * Гейт MACRUNNER_HB_JIT_SIGNAL_INTERP_RETRY СНЯТ 02.09.2026: правка безусловна,
 * выключенная ветка возвращала известный дефект (scripts/гейты.py). */
static hb_result_t hb_codegen_fail_to_interp(hb_context_t* ctx, const hb_ir_func_t* func,
                                             hb_ir_block_t* block, hb_exec_result_t* out,
                                             uint64_t steps, uint64_t blocks_executed) {
    hb_interpreter_t* it;
    hb_exec_result_t sub;
    hb_result_t r;
    static unsigned int note_n;

    it = hb_interpreter_create(ctx);
    if (!it) return HB_ERR_OUT_OF_MEMORY;
    r = hb_interpreter_run_from(it, func, block, &sub);
    hb_interpreter_destroy(it);

    if (note_n < 8) {
        note_n++;
        fprintf(stderr, "macrunner-hb-interp-fallback: n=%u блоков_до=%llu шагов_до=%llu "
                        "интерп_шагов=%llu интерп_блоков=%llu faulted=%d r=%d\n",
                note_n, (unsigned long long)blocks_executed, (unsigned long long)steps,
                (unsigned long long)sub.steps_executed, (unsigned long long)sub.blocks_executed,
                (int)sub.faulted, (int)r);
        fflush(stderr);
    }

    *out = sub;
    out->steps_executed += steps;
    out->blocks_executed += blocks_executed;
    return r;
}

static bool jit_sigbus_invalidate_enabled(void) {
    const char* env = hb_gate( HB_GATE_HB_JIT_SIGBUS_INVALIDATE );
    int enabled = env && env[0] && env[0] != '0';
    return enabled != 0;
}

static bool jit_sigill_ownership_enabled(void) {
    const char* env = hb_gate( HB_GATE_HB_JIT_SIGILL_OWNERSHIP );
    int enabled = env && env[0] && env[0] != '0';
    return enabled != 0;
}

static bool jit_signal_quarantine_enabled(void) {
    return jit_sigbus_invalidate_enabled() || jit_sigill_ownership_enabled();
}

static bool jit_signal_quarantine_enabled_for(int signal) {
    if (signal == SIGBUS) return jit_sigbus_invalidate_enabled();
    if (signal == SIGILL) return jit_sigill_ownership_enabled();
    return false;
}

static bool jit_aa_sigbus_probe_enabled(void) {
    const char* env = hb_gate( HB_GATE_HB_AA_SIGBUS_PROBE );
    int enabled = env && env[0] && env[0] != '0';
    return enabled != 0;
}

static bool jit_aa_force_mono_simd_copy_interp_enabled(void) {
    const char* env = hb_gate( HB_GATE_HB_AA_FORCE_MONO_SIMD_COPY_INTERP );
    int enabled = env && env[0] && env[0] != '0';
    return enabled != 0;
}

static bool jit_aa_mono_simd_copy_gate_probe_enabled(void) {
    const char* env = hb_gate( HB_GATE_HB_AA_MONO_SIMD_COPY_GATE_PROBE );
    int enabled = env && env[0] && env[0] != '0';
    return enabled != 0;
}

static bool jit_aa_mono_4ee14b_transparency_probe_enabled(void) {
    const char* env = hb_gate( HB_GATE_HB_AA_MONO_4EE14B_TRANSPARENCY_PROBE );
    int enabled = env && env[0] && env[0] != '0';
    return enabled != 0;
}

static bool jit_aa_is_mono_simd_copy_block(hb_context_t* ctx,
                                           const hb_block_cache_entry_t* entry,
                                           uint8_t bytes[16],
                                           uint64_t* rva_out) {
    static const uint8_t sig_4ee14b[16] = {
        0x0f, 0x1f, 0x44, 0x00, 0x00, /* nop dword ptr [rax+rax] */
        0xf3, 0x0f, 0x6f, 0x0a,       /* movdqu xmm1, xmmword ptr [rdx] */
        0xf3, 0x0f, 0x6f, 0x52, 0x10, /* movdqu xmm2, xmmword ptr [rdx+0x10] */
        0xf3, 0x0f                    /* next movdqu */
    };
    static const uint8_t sig_4ee150[16] = {
        0xf3, 0x0f, 0x6f, 0x0a,
        0xf3, 0x0f, 0x6f, 0x52, 0x10,
        0xf3, 0x0f, 0x6f, 0x5a, 0x20,
        0xf3, 0x0f
    };
    uint64_t rva;
    if (!ctx || !ctx->memory || !entry || !entry->guest_addr)
        return false;
    if (!(ctx->codegen_flags & HB_CONTEXT_CODEGEN_MONO_MODULE) ||
        !ctx->codegen_module_base || entry->guest_addr < ctx->codegen_module_base)
        return false;
    rva = entry->guest_addr - ctx->codegen_module_base;
    if (rva != 0x4ee14bull && rva != 0x4ee150ull)
        return false;
    for (size_t i = 0; i < 16; i++) {
        if (hb_memory_read_u8(ctx->memory, (hb_gva_t)(entry->guest_addr + i),
                              &bytes[i]) != HB_OK)
            return false;
    }
    if (rva_out) *rva_out = rva;
    if (rva == 0x4ee14bull)
        return memcmp(bytes, sig_4ee14b, sizeof(sig_4ee14b)) == 0;
    return memcmp(bytes, sig_4ee150, sizeof(sig_4ee150)) == 0;
}

static void jit_aa_probe_mono_simd_copy_gate(hb_jit_runtime_t* rt,
                                             hb_block_cache_entry_t* cached,
                                             uint64_t steps,
                                             uint64_t blocks_executed) {
    static unsigned int reports;
    hb_context_t* ctx;
    uint8_t bytes[16] = {0};
    uint64_t rva = 0;

    if (!jit_aa_mono_simd_copy_gate_probe_enabled() || !rt || !cached)
        return;
    ctx = rt->ctx;
    if (!jit_aa_is_mono_simd_copy_block(ctx, cached, bytes, &rva))
        return;
    if (reports++ < 16) {
        fprintf(stderr,
                "macrunner-hb-aa-mono-simd-gate-probe: would_force=1 module_base=%p "
                "rva=0x%llx guest=%p native=%p-%p steps=%llu blocks=%llu "
                "dst=%p src=%p len=%llu "
                "bytes=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
                (void*)(uintptr_t)ctx->codegen_module_base,
                (unsigned long long)rva,
                (void*)(uintptr_t)cached->guest_addr,
                cached->native_code, cached->native_code + cached->native_size,
                (unsigned long long)steps, (unsigned long long)blocks_executed,
                (void*)(uintptr_t)ctx->regs.x64.rcx,
                (void*)(uintptr_t)ctx->regs.x64.rdx,
                (unsigned long long)ctx->regs.x64.r8,
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15]);
        fflush(stderr);
    }
}

static bool jit_aa_force_mono_simd_copy_interp(hb_jit_runtime_t* rt,
                                               hb_block_cache_entry_t* cached,
                                               hb_exec_result_t* out,
                                               uint64_t steps,
                                               uint64_t blocks_executed) {
    static unsigned int reports;
    hb_context_t* ctx;
    uint8_t bytes[16] = {0};
    uint64_t rva = 0;

    if (!jit_aa_force_mono_simd_copy_interp_enabled() || !rt || !cached || !out)
        return false;
    if (!cached->block)
        return false;
    ctx = rt->ctx;
    if (!jit_aa_is_mono_simd_copy_block(ctx, cached, bytes, &rva))
        return false;

    ctx->pc = cached->guest_addr;
    tramp_snyat_svidetelya(ctx);
    sync_arch_pc_after_jit_block(ctx);
    if (reports++ < 16) {
        fprintf(stderr,
                "macrunner-hb-aa-force-mono-simd-interp: module_base=%p rva=0x%llx "
                "guest=%p native=%p-%p "
                "steps=%llu blocks=%llu dst=%p src=%p len=%llu "
                "bytes=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
                (void*)(uintptr_t)ctx->codegen_module_base,
                (unsigned long long)rva,
                (void*)(uintptr_t)cached->guest_addr,
                cached->native_code, cached->native_code + cached->native_size,
                (unsigned long long)steps, (unsigned long long)blocks_executed,
                (void*)(uintptr_t)ctx->regs.x64.rcx,
                (void*)(uintptr_t)ctx->regs.x64.rdx,
                (unsigned long long)ctx->regs.x64.r8,
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15]);
        fflush(stderr);
    }
    hb_jit_helper_exec_ir_block(ctx, cached->block);
    if (ctx->last_result != HB_OK) {
        out->result = ctx->last_result;
        { /* Итерация 307: назвать МЕСТО. Печать безусловная, первые 4 раза на место. */
          static int said_4907; extern const char* hb_result_string(int);
          if (out->result != HB_OK && said_4907++ < 4)
            fprintf(stderr, "macrunner-hb-result-site: место=4907 результат=%s(%d) pc=%#llx\n",
                    hb_result_string(out->result), (int)out->result,
                    0ULL); }
        out->steps_executed = steps;
        out->blocks_executed = blocks_executed;
        out->faulted = true;
        out->fault_reason = "A/B forced Mono RVA-scoped SIMD-copy inline interpreter fault";
    }
    return true;
}

static uint32_t jit_aa_capture_window(hb_memory_t* memory, uint64_t address,
                                      uint8_t bytes[32]) {
    uint32_t valid = 0;
    if (!memory || !address) return 0;
    for (unsigned int i = 0; i < 32; i++) {
        uint8_t byte = 0;
        if (hb_memory_read_u8(memory, (hb_gva_t)(address + i), &byte) == HB_OK) {
            bytes[i] = byte;
            valid |= (uint32_t)1u << i;
        }
    }
    return valid;
}

static void jit_aa_format_window(const uint8_t bytes[32], uint32_t valid,
                                 char text[65]) {
    static const char hex[] = "0123456789abcdef";
    for (unsigned int i = 0; i < 32; i++) {
        if (valid & ((uint32_t)1u << i)) {
            text[i * 2] = hex[bytes[i] >> 4];
            text[i * 2 + 1] = hex[bytes[i] & 15];
        } else {
            text[i * 2] = '?';
            text[i * 2 + 1] = '?';
        }
    }
    text[64] = 0;
}

#define JIT_AA_MONO_4EE14B_WINDOW 256u

typedef struct jit_aa_mono_4ee14b_window {
    uint8_t bytes[JIT_AA_MONO_4EE14B_WINDOW];
    uint8_t valid[JIT_AA_MONO_4EE14B_WINDOW];
    size_t size;
    uint64_t hash;
    unsigned int valid_count;
} jit_aa_mono_4ee14b_window_t;

static uint64_t jit_aa_hash_bytes(const void* data, size_t size) {
    const uint8_t* p = (const uint8_t*)data;
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < size; i++) {
        h ^= (uint64_t)p[i];
        h *= 1099511628211ull;
    }
    return h;
}

static void jit_aa_mono_4ee14b_capture_window(hb_memory_t* memory, uint64_t address,
                                              size_t size,
                                              jit_aa_mono_4ee14b_window_t* out) {
    memset(out, 0, sizeof(*out));
    if (!memory || !address) return;
    if (size > JIT_AA_MONO_4EE14B_WINDOW) size = JIT_AA_MONO_4EE14B_WINDOW;
    out->size = size;
    out->hash = 1469598103934665603ull;
    for (size_t i = 0; i < size; i++) {
        uint8_t byte = 0;
        if (hb_memory_read_u8(memory, (hb_gva_t)(address + i), &byte) == HB_OK) {
            out->bytes[i] = byte;
            out->valid[i] = 1;
            out->valid_count++;
        }
        out->hash ^= (uint64_t)out->valid[i];
        out->hash *= 1099511628211ull;
        if (out->valid[i]) {
            out->hash ^= (uint64_t)byte;
            out->hash *= 1099511628211ull;
        }
    }
}

static bool jit_aa_mono_4ee14b_restore_window(hb_memory_t* memory, uint64_t address,
                                              const jit_aa_mono_4ee14b_window_t* in) {
    bool ok = true;
    if (!memory || !address || !in) return false;
    for (size_t i = 0; i < in->size; i++) {
        if (!in->valid[i]) continue;
        if (hb_memory_write(memory, (hb_gva_t)(address + i), &in->bytes[i], 1) != HB_OK)
            ok = false;
    }
    return ok;
}

static bool jit_aa_mono_4ee14b_windows_equal(const jit_aa_mono_4ee14b_window_t* a,
                                             const jit_aa_mono_4ee14b_window_t* b) {
    if (!a || !b || a->size != b->size || a->valid_count != b->valid_count ||
        a->hash != b->hash)
        return false;
    for (size_t i = 0; i < a->size; i++) {
        if (a->valid[i] != b->valid[i]) return false;
        if (a->valid[i] && a->bytes[i] != b->bytes[i]) return false;
    }
    return true;
}

static void jit_aa_mono_4ee14b_format32(const jit_aa_mono_4ee14b_window_t* w,
                                        char text[65]) {
    uint8_t bytes[32] = {0};
    uint32_t valid = 0;
    if (w) {
        size_t n = w->size < 32 ? w->size : 32;
        for (size_t i = 0; i < n; i++) {
            bytes[i] = w->bytes[i];
            if (w->valid[i]) valid |= (uint32_t)1u << i;
        }
    }
    jit_aa_format_window(bytes, valid, text);
}

static bool jit_aa_mono_4ee14b_gpr_equal(const hb_regs_x64_t* a,
                                         const hb_regs_x64_t* b) {
    return a->rax == b->rax && a->rbx == b->rbx &&
           a->rcx == b->rcx && a->rdx == b->rdx &&
           a->rsi == b->rsi && a->rdi == b->rdi &&
           a->rsp == b->rsp && a->rbp == b->rbp &&
           a->r8  == b->r8  && a->r9  == b->r9  &&
           a->r10 == b->r10 && a->r11 == b->r11 &&
           a->r12 == b->r12 && a->r13 == b->r13 &&
           a->r14 == b->r14 && a->r15 == b->r15 &&
           a->rip == b->rip && a->rflags == b->rflags;
}

static void jit_aa_mono_4ee14b_transparency_probe(hb_jit_runtime_t* rt,
                                                  hb_block_cache_entry_t* cached,
                                                  uint64_t steps,
                                                  uint64_t blocks_executed) {
    typedef void (*jit_block_t)(hb_context_t*);
    static unsigned int reports;
    hb_context_t* ctx;
    hb_context_t pre_ctx, jit_ctx, interp_ctx;
    hb_jit_signal_fault_frame_t frame;
    jit_aa_mono_4ee14b_window_t pre_dst, pre_src, jit_dst, jit_src, interp_dst, interp_src;
    uint8_t bytes[16] = {0};
    uint64_t rva = 0;
    uint64_t dst, src, len;
    size_t window;
    int jit_signal = 0;
    hb_result_t interp_result;
    bool restore_pre_ok;
    char pre_dst_text[65], jit_dst_text[65], interp_dst_text[65];
    char pre_src_text[65], jit_src_text[65], interp_src_text[65];

    if (!jit_aa_mono_4ee14b_transparency_probe_enabled() || !rt || !cached ||
        !cached->native_code || !cached->block || reports >= 8)
        return;
    ctx = rt->ctx;
    if (!jit_aa_is_mono_simd_copy_block(ctx, cached, bytes, &rva) ||
        rva != 0x4ee14bull)
        return;

    reports++;
    pre_ctx = *ctx;
    dst = pre_ctx.regs.x64.rcx;
    src = pre_ctx.regs.x64.rdx;
    len = pre_ctx.regs.x64.r8;
    window = len < 128 ? 128 : (size_t)len;
    if (window > JIT_AA_MONO_4EE14B_WINDOW) window = JIT_AA_MONO_4EE14B_WINDOW;
    jit_aa_mono_4ee14b_capture_window(pre_ctx.memory, dst, window, &pre_dst);
    jit_aa_mono_4ee14b_capture_window(pre_ctx.memory, src, window, &pre_src);

    memset(&frame, 0, sizeof(frame));
    { hb_jit_signal_fault_frame_t** _slot = jit_signal_slot(ctx); frame.prev = *_slot; }
    frame.rt = rt;
    frame.ctx = ctx;
    frame.entry = cached;
    frame.steps = steps;
    frame.blocks_executed = blocks_executed;
    frame.aa_enabled = false;
    frame.stale_cookie = HB_GUARD_FRAME_COOKIE;
    *jit_signal_slot(ctx) = &frame;
    if (sigsetjmp(frame.env, 0) == 0) {
        jit_block_t exec = (jit_block_t)(void*)cached->native_code;
        exec(ctx);
    } else {
        jit_signal = frame.signal ? frame.signal : -1;
        *ctx = pre_ctx;
    }
    *jit_signal_slot(ctx) = frame.prev;
    frame.stale_cookie = 0;
    jit_ctx = *ctx;
    jit_aa_mono_4ee14b_capture_window(pre_ctx.memory, dst, window, &jit_dst);
    jit_aa_mono_4ee14b_capture_window(pre_ctx.memory, src, window, &jit_src);

    *ctx = pre_ctx;
    (void)jit_aa_mono_4ee14b_restore_window(pre_ctx.memory, dst, &pre_dst);
    hb_jit_helper_exec_ir_block(ctx, cached->block);
    interp_result = ctx->last_result;
    interp_ctx = *ctx;
    jit_aa_mono_4ee14b_capture_window(pre_ctx.memory, dst, window, &interp_dst);
    jit_aa_mono_4ee14b_capture_window(pre_ctx.memory, src, window, &interp_src);

    *ctx = pre_ctx;
    restore_pre_ok = jit_aa_mono_4ee14b_restore_window(pre_ctx.memory, dst, &pre_dst);
    jit_aa_mono_4ee14b_format32(&pre_dst, pre_dst_text);
    jit_aa_mono_4ee14b_format32(&jit_dst, jit_dst_text);
    jit_aa_mono_4ee14b_format32(&interp_dst, interp_dst_text);
    jit_aa_mono_4ee14b_format32(&pre_src, pre_src_text);
    jit_aa_mono_4ee14b_format32(&jit_src, jit_src_text);
    jit_aa_mono_4ee14b_format32(&interp_src, interp_src_text);

    fprintf(stderr,
            "macrunner-hb-mono-4ee14b-diff: seq=%u module_base=%p rva=0x%llx "
            "guest=%p native=%p-%p instrs=%zu steps=%llu blocks=%llu "
            "pre_pc=%p pre_rip=%p dst=%p src=%p len=%llu window=%zu "
            "jit_signal=%d interp_result=%s restore_pre=%u "
            "pc_equal=%u rip_equal=%u gpr_equal=%u regs_equal=%u xmm_hash_equal=%u "
            "dst_equal=%u src_equal=%u "
            "jit_pc=%p interp_pc=%p jit_rip=%p interp_rip=%p "
            "jit_rcx=%p interp_rcx=%p jit_rdx=%p interp_rdx=%p "
            "jit_r8=%p interp_r8=%p jit_r15=%p interp_r15=%p "
            "jit_last=%s interp_last=%s "
            "pre_dst=%s jit_dst=%s interp_dst=%s "
            "pre_src=%s jit_src=%s interp_src=%s "
            "dst_hash_pre=%016llx dst_hash_jit=%016llx dst_hash_interp=%016llx "
            "src_hash_pre=%016llx src_hash_jit=%016llx src_hash_interp=%016llx\n",
            reports,
            (void*)(uintptr_t)pre_ctx.codegen_module_base,
            (unsigned long long)rva,
            (void*)(uintptr_t)cached->guest_addr,
            cached->native_code, cached->native_code + cached->native_size,
            cached->block->instr_count,
            (unsigned long long)steps, (unsigned long long)blocks_executed,
            (void*)(uintptr_t)pre_ctx.pc,
            (void*)(uintptr_t)pre_ctx.regs.x64.rip,
            (void*)(uintptr_t)dst, (void*)(uintptr_t)src,
            (unsigned long long)len, window,
            jit_signal, hb_result_string(interp_result),
            restore_pre_ok ? 1u : 0u,
            jit_ctx.pc == interp_ctx.pc ? 1u : 0u,
            jit_ctx.regs.x64.rip == interp_ctx.regs.x64.rip ? 1u : 0u,
            jit_aa_mono_4ee14b_gpr_equal(&jit_ctx.regs.x64, &interp_ctx.regs.x64) ? 1u : 0u,
            memcmp(&jit_ctx.regs.x64, &interp_ctx.regs.x64, sizeof(jit_ctx.regs.x64)) == 0 ? 1u : 0u,
            jit_aa_hash_bytes(jit_ctx.regs.x64.xmm, sizeof(jit_ctx.regs.x64.xmm)) ==
                jit_aa_hash_bytes(interp_ctx.regs.x64.xmm, sizeof(interp_ctx.regs.x64.xmm)) ? 1u : 0u,
            jit_aa_mono_4ee14b_windows_equal(&jit_dst, &interp_dst) ? 1u : 0u,
            jit_aa_mono_4ee14b_windows_equal(&jit_src, &interp_src) ? 1u : 0u,
            (void*)(uintptr_t)jit_ctx.pc, (void*)(uintptr_t)interp_ctx.pc,
            (void*)(uintptr_t)jit_ctx.regs.x64.rip, (void*)(uintptr_t)interp_ctx.regs.x64.rip,
            (void*)(uintptr_t)jit_ctx.regs.x64.rcx, (void*)(uintptr_t)interp_ctx.regs.x64.rcx,
            (void*)(uintptr_t)jit_ctx.regs.x64.rdx, (void*)(uintptr_t)interp_ctx.regs.x64.rdx,
            (void*)(uintptr_t)jit_ctx.regs.x64.r8, (void*)(uintptr_t)interp_ctx.regs.x64.r8,
            (void*)(uintptr_t)jit_ctx.regs.x64.r15, (void*)(uintptr_t)interp_ctx.regs.x64.r15,
            hb_result_string(jit_ctx.last_result), hb_result_string(interp_ctx.last_result),
            pre_dst_text, jit_dst_text, interp_dst_text,
            pre_src_text, jit_src_text, interp_src_text,
            (unsigned long long)pre_dst.hash, (unsigned long long)jit_dst.hash,
            (unsigned long long)interp_dst.hash,
            (unsigned long long)pre_src.hash, (unsigned long long)jit_src.hash,
            (unsigned long long)interp_src.hash);
    fflush(stderr);
}

typedef struct hb_jit_aa_vm_region {
    uint64_t start;
    uint64_t end;
    int protection;
    int max_protection;
    int status;
} hb_jit_aa_vm_region_t;

static hb_jit_aa_vm_region_t jit_aa_query_vm_region(uint64_t address) {
    hb_jit_aa_vm_region_t result;
    memset(&result, 0, sizeof(result));
#if defined(__APPLE__)
    {
        mach_vm_address_t region = (mach_vm_address_t)address;
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        memory_object_name_t object = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(mach_task_self(), &region, &size,
                                          VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&info, &count, &object);
        result.status = kr;
        if (kr == KERN_SUCCESS) {
            result.start = (uint64_t)region;
            result.end = (uint64_t)(region + size);
            result.protection = info.protection;
            result.max_protection = info.max_protection;
        }
        if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    }
#else
    (void)address;
    result.status = -1;
#endif
    return result;
}

static bool jit_signal_quarantine_contains(const hb_jit_runtime_t* rt, uint64_t guest_addr) {
    if (!rt || !guest_addr) return false;
    for (size_t i = 0; i < rt->jit_signal_quarantine_count; i++)
        if (rt->jit_signal_quarantine[i] == guest_addr) return true;
    return false;
}

static bool jit_signal_quarantine_add(hb_jit_runtime_t* rt, uint64_t guest_addr) {
    uint64_t* entries;
    size_t capacity;
    if (!rt || !guest_addr) return false;
    if (jit_signal_quarantine_contains(rt, guest_addr)) return true;
    if (rt->jit_signal_quarantine_count == rt->jit_signal_quarantine_capacity) {
        capacity = rt->jit_signal_quarantine_capacity ?
                   rt->jit_signal_quarantine_capacity * 2 : 16;
        if (capacity < rt->jit_signal_quarantine_capacity) return false;
        entries = realloc(rt->jit_signal_quarantine, capacity * sizeof(*entries));
        if (!entries) return false;
        rt->jit_signal_quarantine = entries;
        rt->jit_signal_quarantine_capacity = capacity;
    }
    rt->jit_signal_quarantine[rt->jit_signal_quarantine_count++] = guest_addr;
    return true;
}

static int jit_signal_fault_claim(hb_jit_signal_fault_frame_t* frame,
                                  uint64_t pc, uint64_t map_pc,
                                  uint64_t fault_addr, int signal,
                                  uint32_t native_word, bool native_word_valid,
                                  bool active_guard_claim,
                                  const void* host_context) {
    if (!frame || !frame->rt || !frame->rt->jit_mem || !frame->entry ||
        !frame->entry->native_code || !frame->entry->native_size)
        return 0;

    /* Stale-frame guard — see the HB_GUARD_FRAME_COOKIE comment at the top of the file.
     * Both checks are sound: a live claim always carries the cookie and always faults DEEPER
     * than the frame, so declining here can only suppress a jump into dead stack. */
    const char* stale_kind = NULL;
    uint64_t isp = 0;

    if (frame->stale_cookie != HB_GUARD_FRAME_COOKIE)
        stale_kind = "cookie";
#if defined(__APPLE__) && defined(__aarch64__)
    if (!stale_kind && host_context) {
        const ucontext_t* uc = (const ucontext_t*)host_context;
        if (uc->uc_mcontext) {
            isp = uc->uc_mcontext->__ss.__sp;
            if (isp > (uint64_t)(uintptr_t)frame)
                stale_kind = "sp";
        }
    }
#endif
    if (stale_kind) {
        uint64_t n = __atomic_add_fetch(&g_guard_stale_declines, 1, __ATOMIC_RELAXED);
        if (n <= 8 || (n & 0xfffu) == 0)
            fprintf(stderr,
                    "macrunner-hb-guard-stale-frame: kind=%s n=%llu frame=%p cookie=%016llx "
                    "isp=%016llx pc=%016llx sig=%d\n",
                    stale_kind, (unsigned long long)n, (void*)frame,
                    (unsigned long long)frame->stale_cookie,
                    (unsigned long long)isp, (unsigned long long)pc, signal);
        return 0;
    }

    frame->host_pc = pc;
    frame->map_pc = map_pc ? map_pc : pc;
    frame->fault_addr = fault_addr;
    frame->signal = signal;
    frame->native_word = native_word;
    frame->native_word_valid = native_word_valid;
    frame->active_guard_claim = active_guard_claim;
    if (frame->ctx) {
        frame->fault_guest_pc = frame->ctx->pc;
        if (frame->ctx->arch == HB_ARCH_X64)
            frame->fault_arch_pc = frame->ctx->regs.x64.rip;
        else if (frame->ctx->arch == HB_ARCH_X86)
            frame->fault_arch_pc = frame->ctx->regs.x86.eip;
        frame->fault_indirect_ic_guest = frame->ctx->indirect_ic_guest_addr;
        frame->fault_indirect_ic_native = frame->ctx->indirect_ic_native_code;
    }
#if defined(__APPLE__) && defined(__aarch64__)
    if (host_context) {
        const ucontext_t* context = (const ucontext_t*)host_context;
        if (context->uc_mcontext) {
            for (unsigned int i = 0; i < 29; i++)
                frame->host_gpr[i] = context->uc_mcontext->__ss.__x[i];
            frame->host_gpr[29] = context->uc_mcontext->__ss.__fp;
            frame->host_gpr[30] = context->uc_mcontext->__ss.__lr;
            frame->host_sp = context->uc_mcontext->__ss.__sp;
            frame->host_fault_pc = context->uc_mcontext->__ss.__pc;
            frame->host_pstate = context->uc_mcontext->__ss.__cpsr;
            frame->host_context_valid = true;
        }
    }
#else
    (void)host_context;
#endif
    {
        static int traced;
        if (traced++ < 8 && hb_gate( HB_GATE_HB_TRACE_JIT_HELPER_FAIL ))
            fprintf(stderr, "macrunner-hb-jit-native-sigfault: host_pc=0x%llx fault=0x%llx sig=%d active_guard=%u\n",
                    (unsigned long long)pc, (unsigned long long)fault_addr, signal,
                    active_guard_claim ? 1u : 0u);
    }
#if defined(__APPLE__) && defined(__aarch64__)
    /* Вторая дверь: уходим ШТАТНО (см. заметку у hb_rt_fault_landing выше). */
    if (hb_rt_sig_landing_enabled() && host_context) {
        ucontext_t* uc = (ucontext_t*)(uintptr_t)host_context;
        if (uc->uc_mcontext) {
            static int nd;
            if (nd++ < 8) { fprintf(stderr, "macrunner-hb-landing-jit-arm: n=%d\n", nd); fflush(stderr); }
            g_rt_landing_frame = frame;
            uc->uc_mcontext->__ss.__pc = (uintptr_t)&hb_rt_fault_landing;
            return 1;
        }
    }
#endif
    /* ★★★★★ 05.09.2026 — ВЕРНУТЬ МАСКУ СИГНАЛОВ ПЕРЕД ДЛИННЫМ ПЕРЕХОДОМ.
     *
     * Ограждение взводится `sigsetjmp(env, 0)` — без сохранения маски, иначе на каждой
     * диспетчеризации стоял бы системный вызов. Но обработчик входит с ЗАБЛОКИРОВАННЫМ
     * сигналом (обработчики поставлены без SA_NODEFER: hb_memory.c:844, signal_arm64.c:8530),
     * а `siglongjmp` из него минует `sigreturn`, который эту блокировку снимает. Итог: после
     * ПЕРВОГО же восстановления SIGSEGV/SIGBUS остаётся заблокирован в потоке навсегда, и
     * второй отказ доставить некому — поток крутится на отказавшей команде (замер: приёмка
     * на второй пробе с сигналом висла на 97 % ЦП, sample показывал 1665 из 1665 выборок в
     * `ldr` выпущенного кода). Дефект ДОБИБЛИОТЕЧНЫЙ: со снимком путь был тот же, просто
     * восстановление за прогон случалось 0 раз и второго не бывало.
     *
     * Лечение — как у QEMU (accel/tcg/user-exec.c: sigprocmask(SIG_SETMASK, old_set) перед
     * cpu_loop_exit_sigsegv): вернуть маску, с которой поток был прерван, — из ucontext.
     * Это один системный вызов НА ПУТИ ОТКАЗА, горячий путь не трогается. */
#if defined(__APPLE__) && defined(__aarch64__)
    if (host_context) {
        const ucontext_t* uc_mask = (const ucontext_t*)host_context;
        sigprocmask(SIG_SETMASK, &uc_mask->uc_sigmask, NULL);
    } else
#endif
    {
        sigset_t unblock;
        sigemptyset(&unblock);
        sigaddset(&unblock, signal);
        sigprocmask(SIG_UNBLOCK, &unblock, NULL);
    }
    siglongjmp(frame->env, 1);
    return 1;
}

int hb_jit_runtime_handle_signal_fault(uint64_t pc, uint64_t fault_addr, int signal,
                                       const void* host_context) {
    hb_jit_signal_fault_frame_t* frame = g_jit_signal_fault_frame;
    uintptr_t native_start, native_end, slab_start, slab_end;

    /* Counted before any decline, so "the handler never consults the guard" and "it consults and
     * refuses" stay distinguishable — they argue for the same conclusion but by different routes. */
    __atomic_add_fetch(&g_guard_claim_calls, 1, __ATOMIC_RELAXED);

    if (!frame || !frame->rt || !frame->rt->jit_mem || !frame->entry ||
        !frame->entry->native_code || !frame->entry->native_size) {
        __atomic_add_fetch(&g_guard_claim_declined_frame, 1, __ATOMIC_RELAXED);
        return 0;
    }

    native_start = (uintptr_t)frame->entry->native_code;
    native_end = native_start + frame->entry->native_size;
    slab_start = (uintptr_t)frame->rt->jit_mem->executable;
    slab_end = slab_start + frame->rt->jit_mem->used;
    if (native_end < native_start || slab_end < slab_start) {
        __atomic_add_fetch(&g_guard_claim_declined_range, 1, __ATOMIC_RELAXED);
        return 0;
    }
    if (!((uintptr_t)pc >= native_start && (uintptr_t)pc < native_end) &&
        !((uintptr_t)pc >= slab_start && (uintptr_t)pc < slab_end)) {
        __atomic_add_fetch(&g_guard_claim_declined_range, 1, __ATOMIC_RELAXED);
        return 0;
    }

    __atomic_add_fetch(&g_guard_claim_taken, 1, __ATOMIC_RELAXED);
    {
        /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1093 — ПОСЛЕДНЕЕ НЕИССЛЕДОВАННОЕ ЗВЕНО.
         *
         * Этот крючок стоит ПЕРЕД обработчиком Wine (`signal_arm64.c:4581`) и, вернув
         * «обработано», до него не пускает. Счётчики рядом уже считают отказы крючка, но
         * НИКТО их не печатает, поэтому по журналу нельзя отличить «крючок не звали» от
         * «крючок забрал отказ себе». Печатаем адрес отказа и итог — первые 16 раз. */
        static unsigned claim_n;
        unsigned n = __atomic_add_fetch(&claim_n, 1, __ATOMIC_RELAXED);
        /* Дверь зовут ДВАЖДЫ: сперва с pc отказа, потом с LR. Если `pc` не равен
         * настоящему pc из контекста — это вторая дверь, отказ случился в помощнике,
         * а `pc` здесь = адрес возврата после `blr`. Карту спрашивать по самому `blr`
         * (LR-4): он принадлежит отказавшей команде, а LR может лежать уже в следующей. */
        uint64_t map_pc = pc;
#if defined(__APPLE__) && defined(__aarch64__)
        if (host_context) {
            const ucontext_t* uc_ = (const ucontext_t*)host_context;
            if (uc_->uc_mcontext && (uint64_t)uc_->uc_mcontext->__ss.__pc != pc && pc >= 4)
                map_pc = pc - 4;
        }
#endif
        int r = jit_signal_fault_claim(frame, pc, map_pc, fault_addr, signal, 0, false,
                                       false, host_context);
        if (n <= 16) {
            fprintf(stderr, "macrunner-hb-claim-probe: pid=%d n=%u pc=%#llx fault=%#llx sig=%d итог=%d\n",
                    (int)getpid(), n, (unsigned long long)pc,
                    (unsigned long long)fault_addr, signal, r);
            fflush(stderr);
        }
        return r;
    }
}

int hb_jit_runtime_handle_owned_sigill(uint64_t pc, uint32_t native_word,
                                       int native_word_valid,
                                       const void* host_context) {
    hb_jit_signal_fault_frame_t* frame = g_jit_signal_fault_frame;

    /* The caller has already applied MACRUNNER_HB_JIT_SIGILL_OWNERSHIP.  An
     * active guard is the ownership authority here, not Mach VM membership:
     * the observed failure is a generated tail branch into an old zero RX page
     * outside both the guarded entry and the current JIT slab. */
    /* The second route into the recovery branch. Counted on the same pair of counters so
     * claim_taken means "siglongjmp was attempted", by whichever door. */
    __atomic_add_fetch(&g_guard_claim_calls, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&g_guard_claim_taken, 1, __ATOMIC_RELAXED);
    return jit_signal_fault_claim(frame, pc, pc, 0, SIGILL, native_word,
                                  native_word_valid != 0, true, host_context);
}

static void jit_aa_report_sigbus(const hb_jit_signal_fault_frame_t* frame,
                                 const hb_block_cache_entry_t* faulted) {
    const hb_context_t* entry_ctx;
    const hb_block_cache_entry_t* native_entry;
    hb_jit_aa_vm_region_t fault_region, dst_region, src_region;
    char dst_pre[65], src_pre[65], dst_post[65], src_post[65], guest_text[65];
    uint8_t guest_bytes[32] = {0};
    uint32_t guest_valid;
    uint32_t native_words[5] = {0};
    unsigned int native_valid = 0;
    uint64_t dst, src, length, dst_end, src_end, fault_guest;
    unsigned int seq;

    if (!frame || !frame->aa_enabled || frame->signal != SIGBUS) return;
    seq = __sync_add_and_fetch(&g_jit_aa_sigbus_reports, 1);
    if (seq > 8) return;

    entry_ctx = frame->ctx;   /* снимка нет: память та же, значения ДО блока — в кадре */
    native_entry = faulted ? faulted : frame->entry;
    fault_guest = faulted ? faulted->guest_addr : frame->entry->guest_addr;
    dst = frame->aa_pre_rcx;
    src = frame->aa_pre_rdx;
    length = frame->aa_pre_r8;
    dst_end = length > UINT64_MAX - dst ? UINT64_MAX : dst + length;
    src_end = length > UINT64_MAX - src ? UINT64_MAX : src + length;

    jit_aa_format_window(frame->aa_dst_pre, frame->aa_dst_pre_valid, dst_pre);
    jit_aa_format_window(frame->aa_src_pre, frame->aa_src_pre_valid, src_pre);
    jit_aa_format_window(frame->aa_dst_post, frame->aa_dst_post_valid, dst_post);
    jit_aa_format_window(frame->aa_src_post, frame->aa_src_post_valid, src_post);
    guest_valid = jit_aa_capture_window(entry_ctx->memory, fault_guest, guest_bytes);
    jit_aa_format_window(guest_bytes, guest_valid, guest_text);

    if (native_entry && native_entry->native_code && native_entry->native_size) {
        uintptr_t start = (uintptr_t)native_entry->native_code;
        uintptr_t end = start + native_entry->native_size;
        uintptr_t center = (uintptr_t)frame->host_pc & ~(uintptr_t)3;
        for (int i = -2; i <= 2; i++) {
            uintptr_t at = center + (intptr_t)i * 4;
            if (at >= start && at + sizeof(uint32_t) <= end) {
                memcpy(&native_words[i + 2], (const void*)at, sizeof(uint32_t));
                native_valid |= 1u << (i + 2);
            }
        }
    }

    fault_region = jit_aa_query_vm_region(frame->fault_addr);
    dst_region = jit_aa_query_vm_region(dst);
    src_region = jit_aa_query_vm_region(src);
    fprintf(stderr,
            "macrunner-hb-aa-sigbus-state: seq=%u signal=%d block_entry=%p fault_guest=%p "
            "native_entry=%p hostpc=%p fault=%p steps=%llu blocks=%llu "
            "dst=%p-%p src=%p-%p len=%llu\n",
            seq, frame->signal, (void*)(uintptr_t)frame->entry->guest_addr,
            (void*)(uintptr_t)fault_guest,
            native_entry ? (void*)native_entry->native_code : NULL,
            (void*)(uintptr_t)frame->host_pc, (void*)(uintptr_t)frame->fault_addr,
            (unsigned long long)frame->steps,
            (unsigned long long)frame->blocks_executed,
            (void*)(uintptr_t)dst, (void*)(uintptr_t)dst_end,
            (void*)(uintptr_t)src, (void*)(uintptr_t)src_end,
            (unsigned long long)length);
    fprintf(stderr,
            "macrunner-hb-aa-sigbus-entry-gpr: seq=%u pc=%p rip=%p rflags=%llx "
            "rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx rsp=%llx rbp=%llx\n",
            seq, (void*)(uintptr_t)entry_ctx->pc,
            (void*)(uintptr_t)entry_ctx->regs.x64.rip,
            (unsigned long long)entry_ctx->regs.x64.rflags,
            (unsigned long long)entry_ctx->regs.x64.rax,
            (unsigned long long)entry_ctx->regs.x64.rbx,
            (unsigned long long)entry_ctx->regs.x64.rcx,
            (unsigned long long)entry_ctx->regs.x64.rdx,
            (unsigned long long)entry_ctx->regs.x64.rsi,
            (unsigned long long)entry_ctx->regs.x64.rdi,
            (unsigned long long)entry_ctx->regs.x64.rsp,
            (unsigned long long)entry_ctx->regs.x64.rbp);
    fprintf(stderr,
            "macrunner-hb-aa-sigbus-entry-ext: seq=%u r8=%llx r9=%llx r10=%llx r11=%llx "
            "r12=%llx r13=%llx r14=%llx r15=%llx\n",
            seq, (unsigned long long)entry_ctx->regs.x64.r8,
            (unsigned long long)entry_ctx->regs.x64.r9,
            (unsigned long long)entry_ctx->regs.x64.r10,
            (unsigned long long)entry_ctx->regs.x64.r11,
            (unsigned long long)entry_ctx->regs.x64.r12,
            (unsigned long long)entry_ctx->regs.x64.r13,
            (unsigned long long)entry_ctx->regs.x64.r14,
            (unsigned long long)entry_ctx->regs.x64.r15);
    fprintf(stderr,
            "macrunner-hb-aa-sigbus-memory: seq=%u dst_valid_pre=%08x dst_pre=%s "
            "dst_valid_native_post=%08x dst_native_post=%s src_valid_pre=%08x src_pre=%s "
            "src_valid_native_post=%08x src_native_post=%s\n",
            seq, frame->aa_dst_pre_valid, dst_pre, frame->aa_dst_post_valid, dst_post,
            frame->aa_src_pre_valid, src_pre, frame->aa_src_post_valid, src_post);
    fprintf(stderr,
            "macrunner-hb-aa-sigbus-insn: seq=%u guest_pc=%p guest_valid=%08x guest32=%s "
            "native_pc=%p native_valid=%02x native_w_m2_p2=%08x,%08x,%08x,%08x,%08x\n",
            seq, (void*)(uintptr_t)fault_guest, guest_valid, guest_text,
            (void*)(uintptr_t)frame->host_pc, native_valid,
            native_words[0], native_words[1], native_words[2], native_words[3], native_words[4]);
    fprintf(stderr,
            "macrunner-hb-aa-sigbus-vm: seq=%u fault_region=%p-%p prot=%x max=%x status=%d "
            "dst_region=%p-%p prot=%x max=%x status=%d src_region=%p-%p prot=%x max=%x status=%d\n",
            seq, (void*)(uintptr_t)fault_region.start, (void*)(uintptr_t)fault_region.end,
            fault_region.protection, fault_region.max_protection, fault_region.status,
            (void*)(uintptr_t)dst_region.start, (void*)(uintptr_t)dst_region.end,
            dst_region.protection, dst_region.max_protection, dst_region.status,
            (void*)(uintptr_t)src_region.start, (void*)(uintptr_t)src_region.end,
            src_region.protection, src_region.max_protection, src_region.status);
    fprintf(stderr,
            "macrunner-hb-aa-sigbus-ucontext-0: seq=%u valid=%u pc=%llx sp=%llx pstate=%llx "
            "x0=%llx x1=%llx x2=%llx x3=%llx x4=%llx x5=%llx x6=%llx x7=%llx\n",
            seq, frame->host_context_valid ? 1u : 0u,
            (unsigned long long)frame->host_fault_pc,
            (unsigned long long)frame->host_sp,
            (unsigned long long)frame->host_pstate,
            (unsigned long long)frame->host_gpr[0], (unsigned long long)frame->host_gpr[1],
            (unsigned long long)frame->host_gpr[2], (unsigned long long)frame->host_gpr[3],
            (unsigned long long)frame->host_gpr[4], (unsigned long long)frame->host_gpr[5],
            (unsigned long long)frame->host_gpr[6], (unsigned long long)frame->host_gpr[7]);
    for (unsigned int base = 8; base < 31; base += 8) {
        unsigned int last = base + 7 < 31 ? base + 7 : 30;
        fprintf(stderr,
                "macrunner-hb-aa-sigbus-ucontext-n: seq=%u range=x%u-x%u "
                "v=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
                seq, base, last,
                (unsigned long long)frame->host_gpr[base],
                (unsigned long long)frame->host_gpr[base + 1],
                (unsigned long long)frame->host_gpr[base + 2],
                (unsigned long long)frame->host_gpr[base + 3],
                (unsigned long long)frame->host_gpr[base + 4],
                (unsigned long long)frame->host_gpr[base + 5],
                (unsigned long long)frame->host_gpr[base + 6],
                (unsigned long long)(base + 7 < 31 ? frame->host_gpr[base + 7] : 0));
    }
    fflush(stderr);
}

/* MacRunner 2026-07-30 — the per-block context snapshot, minus the part the JIT cannot touch.
 *
 * Stable baseline from three loop iterations: run_jit_block_with_signal_guard 96/99/102 samples on
 * the critical thread with _platform_memmove 65/69/80 of them, i.e. the copy below is the largest
 * identified cost left on that thread now that promotion is off.
 *
 * sizeof(hb_context_t) is 2616 bytes, and bytes [1472, 2496) — xmm_ext, ymm_hi_ext, zmm_hi_ext —
 * are one contiguous 1024-byte block the header calls "Interpreter-only ... for AVX-512 ZMM16..31".
 * Verified rather than trusted: a grep of the whole engine finds those three fields referenced ONLY
 * in hb_interpreter.c and hb_context.c, with zero mentions in hb_arm64_codegen.c or in this file.
 * So emitted code cannot change them, and not snapshotting them is not an approximation — it is the
 * correct rule, restore-what-changed.
 *
 * BOTH sides must skip the same range. The memset above no longer zeroes `snapshot`, so the
 * un-copied bytes hold whatever was on the stack; a full-struct restore would push that garbage into
 * the live context. Hence a matching pair rather than a lone optimisation on the save path.
 *
 * DEFAULT FLIPPED ON 2026-07-30, after the measurement this gate was waiting for. Run SNAPSHOT760 with the
 * widened window (760 bytes instead of the full 2616): on the critical thread `_platform_memmove` self time
 * fell from 81/536 = 15.1 % to 16/498 = 3.2 %, and run_jit_block_with_signal_guard's own self time from
 * 10.6 % to 7.8 % — a within-run before/after on the exact item the change targets. Time to
 * `Restored language` came in at 369.0 s against 448.4 s and 490.3 s for the two previous best runs and a
 * 593 +- 78 s project baseline, with the Mono phase at 109.7 s against 135.5/150.5 s, and ZERO
 * `HyperBridge run failed` lines.
 *
 * The marker time is n=1, so the load-bearing evidence is the profile share, not the clock.
 * MACRUNNER_HB_SNAPSHOT_SKIP_INTERP=0 restores the full-struct copy in one env var if anything downstream
 * disagrees. */
/* MacRunner 2026-07-30 — the window starts at ymm_hi, not xmm_ext, which nearly triples what it skips.
 *
 * Two things had to be established first. (1) This gate is DEFAULT OFF, so every run measured this week has
 * been copying the whole 2616-byte struct (`*dst = *src`), not the 1592 the comment above describes — the
 * profile's 15.1 % `_platform_memmove` is the cost of the FULL copy. (2) The interpreter-only AVX region is
 * not just xmm_ext..zmm_hi_ext but starts three fields earlier: ymm_hi [640,896), zmm_hi [896,1408) and the
 * AVX-512 opmask k [1408,1472) are contiguous with xmm_ext [1472,1728), ymm_hi_ext [1728,1984) and
 * zmm_hi_ext [1984,2496) — one unbroken 1856-byte run of interpreter EVEX/AVX state.
 *
 * Safe because the emitter cannot reach it, checked exhaustively rather than by sampling: the COMPLETE set of
 * `offsetof(hb_context_t, …)` in hb_arm64_codegen.c is block_count, flags, guest32_base,
 * indirect_ic_guest_addr, indirect_ic_native_code, last_result, lazy_flags, pc, step_count — plus the regs
 * union — and every one of those lies outside [640,2496): regs [32,432), flags [432,438),
 * lazy_flags [440,504), step_count [512,520), block_count [528,536), pc [544,552), last_result [584,588),
 * guest32_base [2496,2504), codegen_flags [2504,2508), indirect_ic_* [2512,2528). ymm_hi/zmm_hi/k are
 * referenced 0 times in the emitter and only from hb_interpreter.c and hb_context.c.
 *
 * Result: the snapshot copies [0,640) + [2496,2616) = 760 bytes instead of 2616, a 71 % cut on a path taken
 * on every single dispatch. Still one gate, still both sides skipping the same range. */
/* ★★★★★ 05.09.2026 — ВСЁ, ЧТО СТОЯЛО ЗДЕСЬ, УДАЛЕНО ВМЕСТЕ СО СНИМКОМ:
 *   HB_CTX_INTERP_ONLY_BEGIN/END        — окно копии 760 байт из 2616;
 *   hb_ctx_snapshot_save/restore        — сама копия и откат;
 *   hb_runtime_fault_rolls_back_state   — ответ кодогенератору «откатит ли отказ состояние»
 *                                         (теперь ответ один и навсегда: НЕТ; закрепление
 *                                         регистров в блоке, способном отказать, запрещено
 *                                         безусловно — см. вето в hb_arm64_codegen.c);
 *   snapshot_measure_skip_save          — замерочная рука.
 * Разбор 2026-07-30 выше оставлен как история: он объясняет, ПОЧЕМУ копия была 760 байт,
 * а не 2616, и это знание пригодится, если кто-то снова захочет копировать контекст.
 *
 * Правило «отказ = состояние гостя ТОЧНО на отказавшей команде» держится на двух вещах:
 *   1. выпущенный код пишет регистры гостя в `ctx` на каждой команде (файл регистров в
 *      памяти; закрепление x25-x28 — гейт MACRUNNER_HB_STATIC_REGS, умолчание ВЫКЛ, и в
 *      блоках с обращениями к памяти оно ветируется);
 *   2. команда, способная отказать, НЕ меняет архитектурное состояние до отказавшего
 *      обращения (push: сначала запись, потом rsp; pop/ret: сначала чтение). Это
 *      проверяет проба jit_fault_state_precision в приёмке — против интерпретатора,
 *      с отрицательным контролем MACRUNNER_HB_TEST_RIPMAP_SKEW. */

/* Геометрия кадра НАРУЖУ — разбор у объявления в hb_runtime.h. Снимка и обнуления больше
 * нет, и прибор `scripts/цена-операции.c` получает честные нули, а не выдуманные байты:
 * кадр стоит теперь ровно то, что стоит sigsetjmp плюс семь явных записей полей. */
void hb_jit_guard_frame_geometry(size_t* frame_size,
                                 size_t* memset_head, size_t* memset_tail,
                                 size_t* snap_head, size_t* snap_tail) {
    if (frame_size)  *frame_size  = sizeof(hb_jit_signal_fault_frame_t);
    if (memset_head) *memset_head = 0;
    if (memset_tail) *memset_tail = 0;
    if (snap_head)   *snap_head   = 0;
    if (snap_tail)   *snap_tail   = 0;
}


/* MacRunner 2026-08-24, лейн КАДР итерация 37 — доля ДИСПЕТЧЕРИЗАЦИЙ у бережливых блоков.
 *
 * Зачем. Все доли, которыми лейн располагал, СТАТИЧЕСКИЕ: 40,14 % скомпилированных блоков
 * (счётчик выпуска) и 91,1 % записей кеша. Вывести из них исполняемую долю нельзя —
 * проверено двумя путями и обе попытки провалились (итерация 36): смесь классов даёт
 * L = -79,7 %, а отсечение по длине двигает долю лишь с 91,1 до 83,2 %. Господствует
 * смещение кеша, изнутри кеша не поправимое.
 *
 * Почему именно здесь. Комментарий у dispatch_stats_note_terminal ниже: «одна на нативную
 * диспетчеризацию, и на старом пути, и на быстром». Второе место вызова (:6490) — внутри
 * гейтованной пробы прозрачности, на обычном прогоне мёртво.
 *
 * Признак. Бережливый блок начинается с MOV x11,x0 = 0xAA0003EB, блок с кадром —
 * с STP x19,x20,[sp,#-48]! = 0xA9BD53F3. Проверено разбором обоих кешей: 2036 + 199 = 2235,
 * третьей формы нет. Считаю и третью корзину — если она не нулевая, признак негоден.
 *
 * Печать периодическая И по выходу: atexit не срабатывает, когда прогон снят по пределу
 * времени (итерация 33 потеряла так руку Z). */
static unsigned long long g_lean_disp_lean, g_lean_disp_framed, g_lean_disp_other;

static void lean_dispatch_report(const char* why) {
    unsigned long long l = __atomic_load_n(&g_lean_disp_lean, __ATOMIC_RELAXED);
    unsigned long long f = __atomic_load_n(&g_lean_disp_framed, __ATOMIC_RELAXED);
    unsigned long long o = __atomic_load_n(&g_lean_disp_other, __ATOMIC_RELAXED);
    unsigned long long t = l + f + o;
    if (!t) return;
    fprintf(stderr,
            "macrunner-hb-lean-dispatch (%s): всего=%llu бережливых=%llu (%.2f %%) "
            "с-кадром=%llu (%.2f %%) прочих=%llu\n",
            why, t, l, 100.0 * (double)l / (double)t,
            f, 100.0 * (double)f / (double)t, o);
    fflush(stderr);
}

static void lean_dispatch_atexit(void) { lean_dispatch_report("выход"); }

static int lean_dispatch_census_enabled(void) {
    static int v = -1;
    if (v < 0) {
        const char* e = hb_gate( HB_GATE_HB_LEAN_DISPATCH_CENSUS );
        v = (e && *e && *e != '0') ? 1 : 0;
        if (v) atexit(lean_dispatch_atexit);
    }
    return v;
}

/* ★★★★★ ЛЕЙН ПРИБОРЫ, 25.08 — ЦЕНА ДИСПЕТЧЕРА (место №4 карты времени).
 *
 * Зачем именно так. Входящее 12:45 показало выпуск Rosetta на том же модуле: `RET` в
 * диспетчер — НОЛЬ, блок прыгает прямо в блок. У нас 1940 RET на 74 937 слов. То есть
 * разница не в длине выпущенного кода (он и весит всего 1,55 % времени), а в том, что
 * после КАЖДОГО блока управление возвращается в цикл. Сколько это стоит — не мерено.
 *
 * Что меряем. Вокруг единственного места, где блок ИСПОЛНЯЕТСЯ
 * (`run_jit_block_with_signal_guard`), берём два отсчёта: время ВНУТРИ блока. Время
 * снаружи, то есть работа самого цикла, получается вычитанием из общего времени серии
 * диспетчеризаций.
 *
 * ★ ВЫБОРОЧНО, а не на каждой. Прибор `MACRUNNER_HB_TRACE_DISPATCH_STATS` стоит +5,47 %
 * САМ ПО СЕБЕ именно потому, что трогает каждую диспетчеризацию. Здесь часы читаются
 * ОДИН РАЗ НА 64, и это записано в число: доля считается по выборке, а не по всем.
 * Дисциплина взята у счётчиков hb_memory.c, где она уже оплачена.
 *
 * ★ ПЕЧАТЬ ТОЛЬКО ПО ВЫХОДУ. Печать из горячего пути в этой же сессии повесила прогон
 * на 8,5 минуты (см. server.c): поток берёт блокировку stderr, которую держит другой,
 * ушедший в ожидание. Здесь из горячего пути не печатается ничего.
 *
 * Гейт `MACRUNNER_HB_TRACE_DISPATCH_COST`, умолчание ВЫКЛ. */
#define MR_DC_STEP 64                  /* часы читаются на одной диспетчеризации из 64 */
static unsigned long long mr_dc_samples, mr_dc_in_ns, mr_dc_span_ns, mr_dc_dispatches;
static unsigned long long mr_dc_prev_ns;
static int mr_dc_on = -1;

static inline int mr_dc_enabled(void)
{
    if (mr_dc_on < 0) {
        const char* v = hb_gate( HB_GATE_HB_TRACE_DISPATCH_COST );
        mr_dc_on = (v && *v && *v != '0') ? 1 : 0;
    }
    return mr_dc_on;
}

static void mr_dc_report(void)
{
    /* ★ ПОПРАВКА НА ШАГ ВЫБОРКИ. Первая редакция делила in_ms на span_ms напрямую и
     * занижала долю РОВНО В 64 РАЗА: время «внутри блока» снято у ОДНОЙ диспетчеризации,
     * а окно между соседними выборками покрывает все 64. Напечатанные 0,39 % на деле
     * означали 25 %. Множитель обязан стоять в самой печати, иначе следующий читатель
     * повторит ошибку. */
    double in_ms = (double)mr_dc_in_ns / 1e6, sp_ms = (double)mr_dc_span_ns / 1e6;
    double share = (sp_ms > 0.0) ? 100.0 * MR_DC_STEP * in_ms / sp_ms : 0.0;
    fprintf(stderr,
            "macrunner-dispatch-cost: pid=%d dispatches=%llu samples=%llu step=%d "
            "in_block_ms=%.3f span_ms=%.3f in_share=%.2f%% dispatcher_share=%.2f%%\n",
            (int)getpid(), mr_dc_dispatches, mr_dc_samples, MR_DC_STEP,
            in_ms, sp_ms, share, 100.0 - share);
    fflush(stderr);
}

/* Возвращает отсчёт, если эта диспетчеризация попала в выборку, иначе 0. */
static inline unsigned long long mr_dc_before(void)
{
    struct timespec ts;
    unsigned long long n;
    static int atexit_done;

    if (!mr_dc_enabled()) return 0;
    if (!atexit_done) { atexit_done = 1; atexit(mr_dc_report); }
    n = __atomic_add_fetch(&mr_dc_dispatches, 1, __ATOMIC_RELAXED);
    if (n & (MR_DC_STEP - 1)) return 0;          /* одна из MR_DC_STEP */
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}

static inline void mr_dc_after(unsigned long long t0)
{
    struct timespec ts;
    unsigned long long t1;

    if (!t0) return;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    t1 = (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
    __atomic_add_fetch(&mr_dc_in_ns, t1 - t0, __ATOMIC_RELAXED);
    __atomic_add_fetch(&mr_dc_samples, 1, __ATOMIC_RELAXED);
    /* ПРОМЕЖУТОК между соседними выборками покрывает 64 диспетчеризации целиком —
     * и работу блока, и работу цикла. Доля «внутри блока» = in_ns / span_ns. */
    if (mr_dc_prev_ns) __atomic_add_fetch(&mr_dc_span_ns, t1 - mr_dc_prev_ns, __ATOMIC_RELAXED);
    mr_dc_prev_ns = t1;
}

/* MacRunner 2026-08-27 — ЗАПАСНОЙ БЛОК ДЛЯ ПЕРЕИГРОВКИ (правка итерации 2656).
 *
 * Комментарий у set_jit_interp_fallback_result называл эту правку и оставлял её ждать
 * замера: сюда управление попадает, когда переигровка невозможна, а невозможна она по
 * условию frame.entry->block — поле законно бывает пустым (проверяется на NULL примерно
 * в 25 местах этого файла). Тогда наша собственная ошибка выпуска выходит наружу как
 * UNSUPPORTED_FEATURE, то есть выглядит отказом ГОСТЯ, и приёмка показывает 13 отказов.
 *
 * У всех четырёх мест вызова непустой блок УЖЕ вычислен строками выше:
 * `stable_block = cached->block ?: block` (9688, 9891, 10254, 10528). Принимаем его
 * параметром и переигрываем им, когда entry->block пуст. */
static hb_result_t run_jit_block_with_signal_guard(hb_jit_runtime_t* rt,
                                                   const hb_ir_func_t* func,
                                                   hb_block_cache_entry_t* cached,
                                                   const hb_ir_block_t* stable_block,
                                                   hb_exec_result_t* out,
                                                   uint64_t steps,
                                                   uint64_t blocks_executed) {
    typedef void (*jit_block_t)(hb_context_t*);
    hb_jit_signal_fault_frame_t frame;
    hb_context_t* ctx;
    hb_block_cache_entry_t* faulted;
    uint64_t fault_guest_exact = 0;   /* 0 = карта не ответила; см. разбор у присваивания */
    size_t fault_instr_index = 0;     /* номер отказавшей команды в faulted->block */
    jit_block_t exec;

    if (!rt || !rt->ctx || !cached || !cached->native_code || !out)
        return HB_ERR_INVALID_ARG;

    ctx = rt->ctx;
    /* MacRunner 2026-08-18, лейн ЛЕСТНИЦА итерация 2538: гейт переехал на МЕСТО ВЫЗОВА.
     * Замер (2 снимка, 24738 выборок рабочего потока): при ВЫКЛЮЧЕННЫХ гейтах эти два
     * зонда стоили 1,89 % — и платилось не тело, а ПРОЛОГ. У transparency_probe в кадре
     * три hb_context_t по 2616 байт = 7848, поэтому компилятор ставит ___chkstk_darwin;
     * 170 из 502 выборок chkstk имели родителем именно его (33,9 % всех).
     * Приём «перенести гейт вверх по телу», которым мы чинили это дважды (см. коммент
     * в trace_jit_hot_block_tick от 10.08), здесь НЕ РАБОТАЕТ: пролог компилятор ставит
     * перед первой строкой тела, куда бы гейт ни переехал. Лечит только это. */
    if (jit_aa_mono_simd_copy_gate_probe_enabled())
        jit_aa_probe_mono_simd_copy_gate(rt, cached, steps, blocks_executed);
    if (jit_aa_mono_4ee14b_transparency_probe_enabled())
        jit_aa_mono_4ee14b_transparency_probe(rt, cached, steps, blocks_executed);
    if (jit_aa_force_mono_simd_copy_interp(rt, cached, out, steps, blocks_executed))
        return HB_OK;
    if (jit_signal_quarantine_enabled() &&
        (rt->jit_signal_disable ||
         jit_signal_quarantine_contains(rt, cached->guest_addr))) {
        ctx->pc = cached->guest_addr;
        tramp_snyat_svidetelya(ctx);
    sync_arch_pc_after_jit_block(ctx);
        return set_jit_interp_fallback_result(
            out, HB_ERR_UNSUPPORTED_FEATURE, steps, blocks_executed,
            rt->jit_signal_disable ?
                "JIT disabled after unmapped native signal; interpreter fallback" :
                "JIT native-signal block quarantined; interpreter fallback");
    }
    /* MacRunner 2026-07-30 — this runs on EVERY guest block dispatch, and a profile of the thread
     * that actually drives startup found it: of 273 samples inside hb_jit_runtime_run, 39 were
     * _platform_memset and 47 _platform_memmove, both under this function — 31 % of the critical
     * path spent on bookkeeping rather than on the guest.
     *
     * The memset zeroes the whole frame, whose largest member by far is `snapshot`, a full
     * hb_context_t at 2616 bytes — and that member is then completely overwritten by the assignment
     * a few lines below. Zeroing it is pure waste, so skip it: that is about two thirds of the
     * zeroing on a path taken millions of times per startup.
     *
     * Written as two ranges around the member rather than as a list of field initialisers so a field
     * added later still gets zeroed by construction: it necessarily falls in one range or the other.
     * The whole correctness argument is that `snapshot` is unconditionally assigned below, which is
     * checkable at a glance.
     *
     * The 2616-byte COPY is deliberately NOT touched here. It is the pre-image the fault path
     * restores with `*ctx = frame.snapshot`, so eliding it needs a policy for blocks that have never
     * faulted — a behaviour change that wants its own measurement, not a drive-by. */
    /* ★★★★★ 05.09.2026 — КАДР БЕЗ ОБНУЛЕНИЯ И БЕЗ СНИМКА.
     *
     * Было: memset 728 байт вокруг снимка + копия 760 байт снимка на КАЖДОЙ диспетчеризации
     * (8,7 + 41,9 нс из 100, dispatch_baseline 05.09). Стало: семь явных записей полей.
     *
     * Правило, которое это делает верным: КАЖДОЕ поле кадра, читаемое на пути отказа, либо
     * пишется здесь, либо пишется обработчиком сигнала В jit_signal_fault_claim ДО siglongjmp
     * (host_pc, map_pc, fault_addr, signal, native_word*, active_guard_claim, host_gpr[]/
     * host_sp/host_pstate под host_context_valid, fault_guest_pc/fault_arch_pc/fault_indirect_*).
     * Поля aa_* читаются только под aa_enabled, и под ним же заполняются. Нового поля без
     * явной записи быть не должно — это теперь ПРАВИЛО ФАЙЛА, а не свойство memset. */
    { hb_jit_signal_fault_frame_t** _slot = jit_signal_slot(ctx); frame.prev = *_slot; }
    frame.rt = rt;
    frame.ctx = ctx;
    frame.entry = cached;
    frame.steps = steps;
    frame.blocks_executed = blocks_executed;
    frame.signal = 0;
    frame.host_pc = 0;
    frame.map_pc = 0;
    frame.fault_addr = 0;
    frame.native_word_valid = false;
    frame.active_guard_claim = false;
    frame.host_context_valid = false;
    frame.aa_enabled = jit_aa_sigbus_probe_enabled();
    if (frame.aa_enabled) {
        frame.aa_pre_rcx = ctx->regs.x64.rcx;
        frame.aa_pre_rdx = ctx->regs.x64.rdx;
        frame.aa_pre_r8 = ctx->regs.x64.r8;
        frame.aa_dst_post_valid = 0;
        frame.aa_src_post_valid = 0;
        frame.aa_dst_pre_valid = jit_aa_capture_window(ctx->memory, frame.aa_pre_rcx, frame.aa_dst_pre);
        frame.aa_src_pre_valid = jit_aa_capture_window(ctx->memory, frame.aa_pre_rdx, frame.aa_src_pre);
    }
    frame.stale_cookie = HB_GUARD_FRAME_COOKIE;
    *jit_signal_slot(ctx) = &frame;

    /* Counted here, before sigsetjmp, so it is one increment per dispatch on both the returning
     * path and the faulting one. Per-thread through `rt` (see the census comment above), so the
     * guard's own re-entry through siglongjmp cannot double-count it — and the increment costs a
     * plain load/store instead of a `_tlv_get_addr` call on every dispatch. */
    if ((++rt->guard_dispatch & (HB_GUARD_CENSUS_PERIOD - 1)) == 0)
        guard_census_flush(rt, "period");

    if (sigsetjmp(frame.env, 0) == 0) {
        exec = (jit_block_t)(void*)cached->native_code;
        frame.dispatched_guest = cached->guest_addr;
        frame.dispatched_native = (uint64_t)(uintptr_t)exec;
        frame.dispatched_native_size = cached->native_size;
        /* One call per native dispatch, which is what makes this the right place for it: every
         * dispatch reaches here exactly once, on the legacy path and the fast path alike. */
        dispatch_stats_note_terminal(cached->block);
        if (lean_dispatch_census_enabled() && cached->native_size >= 4) {
            uint32_t w0_lean;
            unsigned long long n_lean;
            memcpy(&w0_lean, cached->native_code, sizeof(w0_lean));
            if (w0_lean == 0xAA0003EBu)
                n_lean = __atomic_add_fetch(&g_lean_disp_lean, 1, __ATOMIC_RELAXED);
            else if (w0_lean == 0xA9BD53F3u)
                n_lean = __atomic_add_fetch(&g_lean_disp_framed, 1, __ATOMIC_RELAXED);
            else
                n_lean = __atomic_add_fetch(&g_lean_disp_other, 1, __ATOMIC_RELAXED);
            if ((n_lean & (n_lean - 1)) == 0 || (n_lean & 0x3FFFFFull) == 0)
                lean_dispatch_report("ход");
        }
        if (trace_null_pc_enabled_rt()) hb_trace_current_block_addr = cached->guest_addr;
        exec(ctx);
        *jit_signal_slot(ctx) = frame.prev;
        frame.stale_cookie = 0;
        return HB_OK;
    }

    /* Reached only via siglongjmp, i.e. the snapshot is about to be used. The first few print
     * individually because "does it ever happen at all" is the question, and a purely periodic
     * report cannot distinguish never from rarely; after that the period keeps a hot branch from
     * drowning the log in its own measurement. */
    ++rt->guard_recover;
    if (rt->guard_recover <= 8 || (rt->guard_recover & 0xfffu) == 0)
        guard_census_flush(rt, "recover");

    *jit_signal_slot(ctx) = frame.prev;
    frame.stale_cookie = 0;
    if (frame.aa_enabled && frame.signal == SIGBUS) {
        frame.aa_dst_post_valid = jit_aa_capture_window(ctx->memory, frame.aa_pre_rcx, frame.aa_dst_post);
        frame.aa_src_post_valid = jit_aa_capture_window(ctx->memory, frame.aa_pre_rdx, frame.aa_src_post);
    }
    /* MacRunner 2026-07-31 — a snapshot may only roll back the block it describes.
     *
     * hb_ctx_snapshot_save() runs ONCE per dispatch (above). Unchained, a dispatch is one block
     * and the contract holds. Chained, one dispatch retires 2-6 blocks (traces show blocks=2,3,4,6)
     * while the snapshot still describes the state before the FIRST — so restoring it after a fault
     * in a later block discards guest work that legitimately completed. With 3.6 M faults per run
     * (99.3% BUS_ADRALN) this is a hot path, not an edge case, and it matches every symptom: damage
     * accumulating across consecutive edges, values identical run to run because they are STALE
     * rather than random, and the REFUSE_NEAR differential reporting the defect as general to
     * chaining — any chain longer than one block has it.
     *
     * frame.entry is the block the snapshot was taken for; block_cache_find_native_pc() recovers
     * the block that actually faulted. When they differ, the snapshot is simply not a valid
     * pre-image, and applying it is worse than leaving the context alone: ctx->pc is maintained by
     * every terminator, so the dispatcher can carry on from where the guest really is.
     *
     * Gated, default OFF, because "do not roll back" leaves the faulting block's partial effects in
     * place — the lesser of two wrongs, but a behaviour change that has to be measured rather than
     * assumed. */
    faulted = block_cache_find_native_pc(rt->block_cache, frame.host_pc);
    /* ★★★★★ MacRunner 2026-09-04 — ТОЧНАЯ ГОСТЕВАЯ КОМАНДА ОТКАЗА, БЕЗУСЛОВНО.
     *
     * Считается ОДИН раз и здесь, потому что здесь впервые известен блок, в котором отказ.
     * Ниже по функции гостевой адрес отказа печатают и пишут в ctx->pc ЧЕТЫРЕ разных места,
     * и все они до сегодня брали `cached->guest_addr` — вход блока, ОТПРАВЛЕННОГО на
     * исполнение. Внутри сцеплённой цепочки это неверно по построению: сцеплённое ребро в
     * диспетчер не возвращается, за одну диспетчеризацию уходит 2-6 блоков, и отказ в
     * четвёртом из них назывался адресом первого.
     *
     * Безусловно, потому что это ПРАВИЛЬНОСТЬ, а не скорость: путь холодный (сюда попадают
     * только через siglongjmp), чтение карты — один двоичный поиск, гейта тут быть не может.
     * `0` значит «не знаю» и ниже всюду проверяется: подставлять вход блока молча запрещено. */
    fault_guest_exact = ripmap_resolve(faulted, frame.map_pc, &fault_instr_index);
    if (fault_guest_exact) g_fault_exact_hits++;
    else if (faulted) g_fault_exact_no_map++;   /* блок есть, карты нет: помощник/переполнение */
    else g_fault_exact_no_block++;              /* pc вне живых блоков этой среды */
    /* ★★★★★ 05.09.2026 — ПОЗИЦИЯ ВМЕСТО ОТКАТА (как QEMU cpu_restore_state и FEX
     * RestoreRIPFromHostPC). Регистры гостя уже лежат в `ctx` — выпущенный код пишет их
     * в память на каждой команде, — а команда, способная отказать, архитектурное состояние
     * до отказа не меняет (проверяется пробой jit_fault_state_precision). Значит состояние
     * в `ctx` и есть состояние гостя НА ОТКАЗАВШЕЙ КОМАНДЕ; недоставало только её адреса,
     * и его даёт карта. Откатывать нечего и незачем.
     *
     * Карта не ответила -> `ctx->pc` остаётся ВХОДОМ отправленного блока (его пишет пролог),
     * и ниже блок переигрывается с входа, как до 05.09, — с оговоркой, что уже выполненные
     * команды повторятся. Счётчик t_resume_unresolved называет, сколько раз это случилось;
     * ноль в нём при ненулевом t_resume_exact — единственное доказательство, что схема
     * полна, а не «обычно работает». */
    if (fault_guest_exact) {
        ctx->pc = fault_guest_exact;
        tramp_snyat_svidetelya(ctx);
        sync_arch_pc_after_jit_block(ctx);
        t_resume_exact++;
    } else {
        t_resume_unresolved++;
    }
    /* Печать с ПЕРВОГО раза: «срабатывает ли холодная ветвь и отвечает ли карта» — периодический
     * отчёт не отличит «никогда» от «редко». */
    if ((t_resume_exact + t_resume_unresolved) <= 16 ||
        ((t_resume_exact + t_resume_unresolved) & 0xffu) == 0)
        fprintf(stderr,
                "macrunner-hb-resume: exact=%llu unresolved=%llu guest=0x%llx instr=%zu sig=%d "
                "host_pc=0x%llx map_pc=0x%llx entry_guest=0x%llx faulted_guest=0x%llx\n",
                (unsigned long long)t_resume_exact, (unsigned long long)t_resume_unresolved,
                (unsigned long long)fault_guest_exact, fault_instr_index, frame.signal,
                (unsigned long long)frame.host_pc, (unsigned long long)frame.map_pc,
                (unsigned long long)(frame.entry ? frame.entry->guest_addr : 0),
                (unsigned long long)(faulted ? faulted->guest_addr : 0));
    if (jit_signal_quarantine_enabled_for(frame.signal)) {
        hb_block_cache_entry_t* quarantine_entry = faulted ? faulted : cached;
        uint64_t fault_guest = quarantine_entry ? quarantine_entry->guest_addr : 0;
        bool quarantined = fault_guest && jit_signal_quarantine_add(rt, fault_guest);
        const char* record = frame.signal == SIGILL ? "sigill-own" : "sigbus-invalidate";

        if (frame.signal == SIGBUS) jit_aa_report_sigbus(&frame, faulted);

        /* The snapshot is the only complete architectural checkpoint. Resume
         * from its entry; the interpreter advances to the quarantined block
         * without executing that native block again.
         *
         * ★★★ MacRunner 2026-09-04 — КУДА ВОЗВРАЩАТЬСЯ, ЗАВИСИТ ОТ ТОГО, ОТКАТИЛИ ЛИ СОСТОЯНИЕ.
         *
         * Прежде здесь стояло безусловное `ctx->pc = cached->guest_addr`, и оно ЗАТИРАЛО точный
         * адрес, который ветвь без снимка (`!frame.snapshot_valid`) только что положила в ctx->pc
         * по карте. То есть под MACRUNNER_HB_NO_SNAPSHOT карта отвечала — и её ответ выбрасывался.
         *
         * Правило простое и проверяемое по одной переменной:
         *   • состояние ОТКАЧЕНО к снимку -> регистры описывают момент ДО блока, значит и pc
         *     обязан быть входом того же блока: `cached->guest_addr`, как было;
         *   • состояние НЕ откачено -> регистры описывают момент ОТКАЗА, и единственный
         *     согласованный с ними pc — точный адрес отказавшей команды;
         *   • карта не ответила -> берём вход ОТКАЗАВШЕГО блока (он ближе входа отправленного),
         *     а если и его нет — прежний `cached->guest_addr`. Ни одна ветвь не выдаёт
         *     недостоверный адрес молча: `fault_guest_exact` уже отличает «не знаю» от адреса. */
        /* 05.09.2026: отката нет, значит регистры описывают момент ОТКАЗА, и единственный
         * согласованный с ними pc — точный адрес отказавшей команды; без карты — вход
         * ОТКАЗАВШЕГО блока (ближе входа отправленного), а без него — прежний cached. */
        ctx->pc = fault_guest_exact ? fault_guest_exact
                                    : (faulted ? faulted->guest_addr : cached->guest_addr);
        tramp_snyat_svidetelya(ctx);
    sync_arch_pc_after_jit_block(ctx);
        if (!quarantined) rt->jit_signal_disable = true;
        fprintf(stderr,
                "macrunner-hb-jit-%s: hostpc=%p fault=%p signal=%d "
                "fault_guest=%p resume_guest=%p mapped=%u quarantined=%u "
                "active_guard=%u disable_jit=%u count=%zu\n",
                record,
                (void*)(uintptr_t)frame.host_pc,
                (void*)(uintptr_t)frame.fault_addr,
                frame.signal,
                (void*)(uintptr_t)fault_guest,
                (void*)(uintptr_t)ctx->pc,   /* КУДА возобновляем на самом деле, а не вход cached */
                faulted ? 1u : 0u, quarantined ? 1u : 0u,
                frame.active_guard_claim ? 1u : 0u,
                rt->jit_signal_disable ? 1u : 0u,
                rt->jit_signal_quarantine_count);
        fflush(stderr);
    }
    if (frame.signal == SIGILL && g_jit_sigill_ownership_reports++ < 32) {
        hb_block_cache_entry_t* source = faulted ? faulted : cached;
        uintptr_t native_start = source ? (uintptr_t)source->native_code : 0;
        uintptr_t native_end = source ? native_start + source->native_size : 0;
        uintptr_t arena_start = rt->jit_mem ? (uintptr_t)rt->jit_mem->executable : 0;
        uintptr_t arena_end = rt->jit_mem && rt->jit_mem->size <= UINTPTR_MAX - arena_start ?
                              arena_start + rt->jit_mem->size : 0;
        uintptr_t arena_used_end = rt->jit_mem && rt->jit_mem->used <= UINTPTR_MAX - arena_start ?
                                   arena_start + rt->jit_mem->used : 0;
        uintptr_t word_pc = (uintptr_t)frame.host_pc & ~(uintptr_t)3;
        hb_jit_aa_vm_region_t fault_region = jit_aa_query_vm_region(frame.host_pc);
        hb_jit_aa_vm_region_t dispatch_region = jit_aa_query_vm_region(frame.dispatched_native);
        hb_jit_aa_vm_region_t x21_region = jit_aa_query_vm_region(
            frame.host_context_valid ? frame.host_gpr[21] : 0);
        uint32_t native_word = frame.native_word;
        bool word_valid = frame.native_word_valid;
        char guest_bytes[64] = {0};
        char* p = guest_bytes;

        if (!word_valid && faulted && native_end >= native_start && word_pc >= native_start &&
            word_pc <= native_end && native_end - word_pc >= sizeof(native_word)) {
            memcpy(&native_word, (const void*)word_pc, sizeof(native_word));
            word_valid = true;
        }
        if (source && ctx && ctx->memory) {
            for (int i = 0; i < 16 && (size_t)(p - guest_bytes) < sizeof(guest_bytes) - 3; i++) {
                uint8_t b = 0;
                if (hb_memory_read_u8(ctx->memory,
                                      (hb_gva_t)(source->guest_addr + (uint64_t)i), &b) != HB_OK)
                    break;
                p += snprintf(p, sizeof(guest_bytes) - (size_t)(p - guest_bytes),
                              "%s%02x", i ? " " : "", b);
            }
        }
        fprintf(stderr,
                "macrunner-hb-jit-sigill-native: guest=%p owner_native=%p-%p "
                "hostpc=%p offset=%#llx mapped=%u active_guard=%u "
                "word_valid=%u word=%08x x20=%#llx x21=%#llx lr=%#llx gbytes=%s\n",
                (void*)(uintptr_t)(source ? source->guest_addr : 0),
                (void*)native_start, (void*)native_end,
                (void*)(uintptr_t)frame.host_pc,
                (unsigned long long)(faulted && (uintptr_t)frame.host_pc >= native_start ?
                                     (uintptr_t)frame.host_pc - native_start : 0),
                faulted ? 1u : 0u, frame.active_guard_claim ? 1u : 0u,
                word_valid ? 1u : 0u, native_word,
                (unsigned long long)(frame.host_context_valid ? frame.host_gpr[20] : 0),
                (unsigned long long)(frame.host_context_valid ? frame.host_gpr[21] : 0),
                (unsigned long long)(frame.host_context_valid ? frame.host_gpr[30] : 0),
                guest_bytes);
        fflush(stderr);

        fprintf(stderr,
                "macrunner-hb-jit-sigill-dispatch: dispatch_guest=%p "
                "dispatch_native=%p-%p current_guest=%p current_native=%p-%p "
                "hostpc=%p x8=%#llx x28=%#llx lr=%#llx "
                "fault_ctx_pc=%p fault_arch_pc=%p ic_guest=%p ic_native=%p "
                "arena=%p-%p used_end=%p in_arena=%u in_used=%u\n",
                (void*)(uintptr_t)frame.dispatched_guest,
                (void*)(uintptr_t)frame.dispatched_native,
                (void*)(uintptr_t)(frame.dispatched_native + frame.dispatched_native_size),
                (void*)(uintptr_t)(source ? source->guest_addr : 0),
                (void*)native_start, (void*)native_end,
                (void*)(uintptr_t)frame.host_pc,
                (unsigned long long)(frame.host_context_valid ? frame.host_gpr[8] : 0),
                (unsigned long long)(frame.host_context_valid ? frame.host_gpr[28] : 0),
                (unsigned long long)(frame.host_context_valid ? frame.host_gpr[30] : 0),
                (void*)(uintptr_t)frame.fault_guest_pc,
                (void*)(uintptr_t)frame.fault_arch_pc,
                (void*)(uintptr_t)frame.fault_indirect_ic_guest,
                (void*)(uintptr_t)frame.fault_indirect_ic_native,
                (void*)arena_start, (void*)arena_end, (void*)arena_used_end,
                arena_end >= arena_start && (uintptr_t)frame.host_pc >= arena_start &&
                    (uintptr_t)frame.host_pc < arena_end ? 1u : 0u,
                arena_used_end >= arena_start && (uintptr_t)frame.host_pc >= arena_start &&
                    (uintptr_t)frame.host_pc < arena_used_end ? 1u : 0u);
        fflush(stderr);

        fprintf(stderr,
                "macrunner-hb-jit-sigill-vm: hostpc=%p region=%p-%p prot=%#x max=%#x kr=%d "
                "dispatch=%p region=%p-%p prot=%#x max=%#x kr=%d "
                "x21=%p region=%p-%p prot=%#x max=%#x kr=%d same_host_x21=%u\n",
                (void*)(uintptr_t)frame.host_pc,
                (void*)(uintptr_t)fault_region.start, (void*)(uintptr_t)fault_region.end,
                fault_region.protection, fault_region.max_protection, fault_region.status,
                (void*)(uintptr_t)frame.dispatched_native,
                (void*)(uintptr_t)dispatch_region.start, (void*)(uintptr_t)dispatch_region.end,
                dispatch_region.protection, dispatch_region.max_protection, dispatch_region.status,
                (void*)(uintptr_t)(frame.host_context_valid ? frame.host_gpr[21] : 0),
                (void*)(uintptr_t)x21_region.start, (void*)(uintptr_t)x21_region.end,
                x21_region.protection, x21_region.max_protection, x21_region.status,
                frame.host_context_valid && frame.host_pc == frame.host_gpr[21] ? 1u : 0u);
        fflush(stderr);

        /* MOVDQA/MOVDQU stores lower through one codegen family.  Record every
         * exact DMB ISHST; STR X20,[X21]; STR X22,[X21,#8] instance in the
         * guarded source block.  The ordinal maps monotonically to the guest
         * SIMD stores and proves whether the encoder emitted a branch/zero word
         * at the RCX+0x60 trigger without changing generated execution. */
        if (source && source->native_code && source->native_size >= 12) {
            unsigned int stores = 0;
            for (size_t off = 0; off + 12 <= source->native_size; off += 4) {
                uint32_t words[7] = {0};
                uint32_t w0, w1, w2;
                size_t window_start;
                size_t window_size;

                memcpy(&w0, source->native_code + off, 4);
                memcpy(&w1, source->native_code + off + 4, 4);
                memcpy(&w2, source->native_code + off + 8, 4);
                if (w0 != 0xd5033abfu || w1 != 0xf90002b4u || w2 != 0xf90006b6u)
                    continue;
                window_start = off >= 8 ? off - 8 : 0;
                window_size = source->native_size - window_start;
                if (window_size > sizeof(words)) window_size = sizeof(words);
                memcpy(words, source->native_code + window_start, window_size);
                fprintf(stderr,
                        "macrunner-hb-jit-sigill-simd-store: ordinal=%u site=%p "
                        "offset=%#zx window_start=%#zx words=%08x,%08x,%08x,%08x,%08x,%08x,%08x\n",
                        stores, source->native_code + off, off, window_start,
                        words[0], words[1], words[2], words[3], words[4], words[5], words[6]);
                stores++;
            }
            fprintf(stderr,
                    "macrunner-hb-jit-sigill-simd-store-summary: guest=%p native=%p-%p "
                    "stores=%u expected_store_words=d5033abf,f90002b4,f90006b6\n",
                    (void*)(uintptr_t)source->guest_addr, source->native_code,
                    source->native_code + source->native_size, stores);
            fflush(stderr);
        }

        /* A SIGILL target outside the source entry is normally reached by a
         * direct/indirect native branch.  Decode the bounded source blob after
         * siglongjmp (never in the signal handler) and report only an edge whose
         * resolved target equals the fault PC.  This identifies the emitting
         * branch family without dumping the whole block or guessing from UDF #0. */
        if (source && source->native_code && source->native_size && frame.host_pc) {
            unsigned int matches = 0;
            for (size_t off = 0; off + sizeof(uint32_t) <= source->native_size; off += 4) {
                uint32_t insn;
                uintptr_t site = (uintptr_t)source->native_code + off;
                uintptr_t target = 0;
                unsigned int reg = 0;
                const char* kind = NULL;

                memcpy(&insn, source->native_code + off, sizeof(insn));
                if ((insn & 0xfc000000u) == 0x14000000u ||
                    (insn & 0xfc000000u) == 0x94000000u) {
                    int32_t imm26 = (int32_t)(insn & 0x03ffffffu);
                    if (imm26 & 0x02000000) imm26 |= (int32_t)~0x03ffffffu;
                    target = (uintptr_t)((intptr_t)site + (intptr_t)imm26 * 4);
                    kind = (insn & 0x80000000u) ? "BL" : "B";
                } else if ((insn & 0xff000010u) == 0x54000000u) {
                    int32_t imm19 = (int32_t)((insn >> 5) & 0x7ffffu);
                    if (imm19 & 0x40000) imm19 |= (int32_t)~0x7ffffu;
                    target = (uintptr_t)((intptr_t)site + (intptr_t)imm19 * 4);
                    kind = "B.cond";
                } else if ((insn & 0xfffffc1fu) == 0xd61f0000u ||
                           (insn & 0xfffffc1fu) == 0xd63f0000u ||
                           (insn & 0xfffffc1fu) == 0xd65f0000u) {
                    reg = (insn >> 5) & 31u;
                    if (frame.host_context_valid && reg < 31) target = frame.host_gpr[reg];
                    if ((insn & 0xfffffc1fu) == 0xd61f0000u) kind = "BR";
                    else if ((insn & 0xfffffc1fu) == 0xd63f0000u) kind = "BLR";
                    else kind = "RET";
                }
                if (kind && target == (uintptr_t)frame.host_pc && matches++ < 8) {
                    fprintf(stderr,
                            "macrunner-hb-jit-sigill-branch-source: guest=%p site=%p "
                            "offset=%#zx word=%08x kind=%s reg=%u target=%p matched=1\n",
                            (void*)(uintptr_t)source->guest_addr, (void*)site, off, insn,
                            kind, reg, (void*)target);
                }
            }
            if (!matches) {
                uint32_t tail[4] = {0};
                size_t tail_size = source->native_size < sizeof(tail) ?
                                   source->native_size : sizeof(tail);
                memcpy((uint8_t*)tail + sizeof(tail) - tail_size,
                       source->native_code + source->native_size - tail_size, tail_size);
                fprintf(stderr,
                        "macrunner-hb-jit-sigill-branch-source: guest=%p owner_native=%p-%p "
                        "hostpc=%p matched=0 tail=%08x,%08x,%08x,%08x\n",
                        (void*)(uintptr_t)source->guest_addr,
                        source->native_code, source->native_code + source->native_size,
                        (void*)(uintptr_t)frame.host_pc,
                        tail[0], tail[1], tail[2], tail[3]);
            }
            fflush(stderr);
        }

        /* Search every live cache entry, not only the guarded entry.  This is
         * bounded to the used-slot index and runs after siglongjmp, so it is
         * signal-safe and does not turn SIGILL handling into a Mach-VM scan. */
        if (rt->block_cache && frame.host_pc) {
            unsigned int matches = 0;
            size_t scanned_entries = 0;
            for (size_t used = 0; used < rt->block_cache->used_count; used++) {
                size_t slot = rt->block_cache->used_slots[used];
                hb_block_cache_entry_t* entry;
                if (slot >= rt->block_cache->size) continue;
                entry = &rt->block_cache->entries[slot];
                if (!entry->valid || !entry->native_code || !entry->native_size) continue;
                scanned_entries++;
                for (size_t off = 0; off + sizeof(uint32_t) <= entry->native_size; off += 4) {
                    uint32_t insn;
                    uintptr_t site = (uintptr_t)entry->native_code + off;
                    uintptr_t target = 0;
                    unsigned int reg = 0;
                    const char* kind = NULL;
                    memcpy(&insn, entry->native_code + off, sizeof(insn));
                    if ((insn & 0xfc000000u) == 0x14000000u ||
                        (insn & 0xfc000000u) == 0x94000000u) {
                        int32_t imm26 = (int32_t)(insn & 0x03ffffffu);
                        if (imm26 & 0x02000000) imm26 |= (int32_t)~0x03ffffffu;
                        target = (uintptr_t)((intptr_t)site + (intptr_t)imm26 * 4);
                        kind = (insn & 0x80000000u) ? "BL" : "B";
                    } else if ((insn & 0xff000010u) == 0x54000000u) {
                        int32_t imm19 = (int32_t)((insn >> 5) & 0x7ffffu);
                        if (imm19 & 0x40000) imm19 |= (int32_t)~0x7ffffu;
                        target = (uintptr_t)((intptr_t)site + (intptr_t)imm19 * 4);
                        kind = "B.cond";
                    } else if ((insn & 0xfffffc1fu) == 0xd61f0000u) {
                        reg = (insn >> 5) & 31u;
                        if (frame.host_context_valid && reg < 31) target = frame.host_gpr[reg];
                        kind = "BR";
                    }
                    if (kind && target == (uintptr_t)frame.host_pc && matches++ < 16) {
                        fprintf(stderr,
                                "macrunner-hb-jit-sigill-branch-all: guest=%p native=%p-%p "
                                "site=%p offset=%#zx word=%08x kind=%s reg=%u target=%p\n",
                                (void*)(uintptr_t)entry->guest_addr,
                                entry->native_code, entry->native_code + entry->native_size,
                                (void*)site, off, insn, kind, reg, (void*)target);
                    }
                }
            }
            fprintf(stderr,
                    "macrunner-hb-jit-sigill-branch-all-summary: hostpc=%p "
                    "entries=%zu matches=%u used_slots=%zu cache_count=%zu\n",
                    (void*)(uintptr_t)frame.host_pc, scanned_entries, matches,
                    rt->block_cache->used_count, rt->block_cache->count);
            fflush(stderr);
        }
    }
    if (g_jit_signal_fault_reports++ < 64) {
        /* MacRunner: dump the guest x86 bytes at the block entry (steps=0 means the
         * fault is at/near the first instruction) + the fault-address alignment, to
         * pin a misaligned LOCK atomic (SIGBUS=10 from JIT atomic lowered to LDXR/STXR
         * on an unaligned address). */
        char gb[64]; gb[0]=0;
        if (ctx && ctx->memory) {
            char *p = gb; uint64_t ga = cached->guest_addr;
            for (int i = 0; i < 16 && (size_t)(p-gb) < sizeof(gb)-3; i++) {
                uint8_t b = 0;
                if (hb_memory_read_u8(ctx->memory, (hb_gva_t)(ga + i), &b) != HB_OK) break;
                p += snprintf(p, sizeof(gb)-(p-gb), "%s%02x", i?" ":"", b);
            }
        }
        {
            /* Dump the native ARM64 words around the faulting host pc (JIT code is
             * host-mapped readable) to see if the 8-byte load was lowered to an
             * alignment-requiring instruction (LDAR/LDXR/atomic) vs a plain LDR. */
            const hb_block_cache_entry_t* native_entry = faulted ? faulted : cached;
            const uint32_t *hp = (const uint32_t *)(uintptr_t)(frame.host_pc & ~3ull);
            if (frame.host_pc >= (uint64_t)(uintptr_t)(native_entry->native_code + 8) &&
                frame.host_pc + 12 <=
                    (uint64_t)(uintptr_t)(native_entry->native_code + native_entry->native_size))
                fprintf(stderr, "macrunner-hb-jit-natinsn: hostpc=%p w[-2..+2]= %08x %08x [%08x] %08x %08x\n",
                        (void*)(uintptr_t)frame.host_pc,
                        hp[-2], hp[-1], hp[0], hp[1], hp[2]);
        }
        fprintf(stderr,
                "macrunner-hb-jit-regs: rax=%llx rcx=%llx rdx=%llx rbx=%llx rsp=%llx rbp=%llx "
                "rsi=%llx rdi=%llx r12=%llx fault=%llx rdx+8=%llx\n",
                (unsigned long long)ctx->regs.x64.rax, (unsigned long long)ctx->regs.x64.rcx,
                (unsigned long long)ctx->regs.x64.rdx, (unsigned long long)ctx->regs.x64.rbx,
                (unsigned long long)ctx->regs.x64.rsp, (unsigned long long)ctx->regs.x64.rbp,
                (unsigned long long)ctx->regs.x64.rsi, (unsigned long long)ctx->regs.x64.rdi,
                (unsigned long long)ctx->regs.x64.r12,
                (unsigned long long)frame.fault_addr,
                (unsigned long long)(ctx->regs.x64.rdx + 8));
        fprintf(stderr,
                "macrunner-hb-jit-signal-fallback: guest=%p native=%p-%p "
                "pc=%p fault=%p signal=%d steps=%llu blocks=%llu fault_align=%llu gbytes=%s\n",
                (void*)(uintptr_t)cached->guest_addr, cached->native_code,
                cached->native_code + cached->native_size,
                (void*)(uintptr_t)frame.host_pc,
                (void*)(uintptr_t)frame.fault_addr, frame.signal,
                (unsigned long long)frame.steps,
                (unsigned long long)frame.blocks_executed,
                (unsigned long long)(frame.fault_addr & 0xf), gb);
        fflush(stderr);
    }
    /* ★ ТОЛЬКО SIGSEGV, и это измерено, а не выбрано.
     *
     * Первая редакция брала любой сигнал — и настоящая нагрузка встала: стенд i386 с теми же
     * четырьмя гейтами дал `exit=1` вместо прежних 19 975 пс. Причина в журнале одной строкой:
     * `jit-signal-interp-retry: n=1 guest=0x7b7dc47a fault=0x37b82d344 sig=10`, то есть SIGBUS —
     * невыровненное обращение. Интерпретатор такое обращение выполняет УСПЕШНО, отказа нет,
     * `out->faulted` не выставлен, и цикл диспетчеризации спокойно берёт тот же блок снова.
     * Прежний ответ `UNSUPPORTED_FEATURE` выводил из JIT целиком, потому и не зацикливался.
     *
     * У SIGSEGV этой беды нет по построению: интерпретатор упрётся в тот же неотображённый
     * адрес программным путём, выставит отказ, и вызывающий вернётся — цикл останавливает сам
     * отказ. Ровно этот случай и нужен пробе `jit_store_unmapped_faults`.
     *
     * SIGBUS и SIGILL остаются на прежнем пути. Им нужен не повтор, а карантин блока
     * (`jit_signal_quarantine_add`, гейты `SIGBUS_INVALIDATE` / `SIGILL_OWNERSHIP`), и это
     * отдельная работа с отдельным замером. */
    /* ★ 27.08: берём запасной блок, когда у записи кеша своего нет. Гейт
     * MACRUNNER_HB_GUARD_STABLE_BLOCK, умолчание ВЫКЛ до замера. */
    const hb_ir_block_t* retry_block = (frame.entry && frame.entry->block)
                                       ? frame.entry->block : NULL;
    if (!retry_block && stable_block) {
        const char* v = hb_gate( HB_GATE_HB_GUARD_STABLE_BLOCK );
        int gate = (v && *v && *v != '0') ? 1 : 0;
        if (gate) {
            static unsigned int sb_n;
            unsigned int sn = ++sb_n;
            if (sn <= 8 || !(sn % 1000)) {
                fprintf(stderr, "macrunner-hb-guard-stable-block: n=%u запись без блока, "
                        "переигрываем запасным guest=%#llx\n",
                        sn, (unsigned long long)stable_block->guest_addr);
                fflush(stderr);
            }
            retry_block = stable_block;
        }
    }

    /* ★★★★★ 05.09.2026 — ТОЧНОЕ ВОЗОБНОВЛЕНИЕ: интерпретатор продолжает С ОТКАЗАВШЕЙ
     * КОМАНДЫ, а не с входа блока.
     *
     * Карта назвала команду (fault_guest_exact != 0) и у отказавшего блока есть IR — значит
     * состояние в `ctx` точное на границе этой команды, и интерпретатор доигрывает остаток
     * блока: отказавшую команду он выполняет программно (hb_memory_*), где отказ памяти
     * становится штатным HB_ERR_MEMORY_FAULT с адресом (hb_memory_last_fault) и доставляется
     * гостю тем же путём, что и раньше; невыровненное обращение (SIGBUS от LDAR/STLR) он
     * просто выполняет; недопустимое слово выпуска (SIGILL) — исполняет семантику IR.
     * Поэтому здесь ВСЕ ТРИ сигнала, а не только SIGSEGV: прежний запрет на SIGBUS
     * («интерпретатор выполнит успешно и цикл возьмёт тот же блок снова») был про переигровку
     * С ВХОДА; при возобновлении с команды продвижение гарантировано на каждом отказе.
     *
     * Ни одна уже выполненная команда не повторяется — это и есть отличие от снимка, при
     * котором `add [mem],1` перед отказом исполнялся дважды. */
    if (fault_guest_exact && faulted && faulted->block &&
        fault_instr_index < faulted->block->instr_count) {
        hb_result_t rr;
        static unsigned resume_n;
        if (++resume_n <= 8) {
            fprintf(stderr, "macrunner-hb-resume-interp: n=%u guest=%#llx instr=%zu/%zu fault=%#llx sig=%d\n",
                    resume_n, (unsigned long long)fault_guest_exact, fault_instr_index,
                    faulted->block->instr_count, (unsigned long long)frame.fault_addr, frame.signal);
            fflush(stderr);
        }
        rr = hb_interpreter_resume_block(ctx, faulted->block, fault_instr_index, out);
        out->steps_executed += frame.steps;
        out->blocks_executed += frame.blocks_executed;
        /* Договор: после отказа `ctx->last_result` несёт причину (проба
         * jit_store_unmapped_faults проверяет ровно это). Интерпретатор ставит его сам на
         * отказе; здесь — только страховка на путь, где он вернул результат без faulted. */
        if (out->result != HB_OK) ctx->last_result = out->result;
        return rr;
    }

    if (frame.signal == SIGSEGV && func && retry_block) {
        static unsigned retry_n;
        if (++retry_n <= 8) {
            fprintf(stderr, "macrunner-hb-jit-signal-interp-retry: n=%u guest=%#llx fault=%#llx sig=%d "
                    "(карта не ответила: переигровка С ВХОДА, уже выполненные команды повторятся)\n",
                    retry_n, (unsigned long long)frame.entry->guest_addr,
                    (unsigned long long)frame.fault_addr, frame.signal);
            fflush(stderr);
        }
        /* Снятие константности здесь и только здесь. Довод: `hb_interpreter_run_from`
         * объявлен без `const` исторически, но блок он ИСПОЛНЯЕТ, а не правит — тот же
         * указатель по этому же пути уже ходит при провале кодогенерации. Менять подпись
         * интерпретатора ради одного вызова значит тянуть волну правок через весь
         * `hb_interpreter.c`; когда её будут делать, этот cast снимется вместе с ней. */
        {
            hb_result_t rr = hb_codegen_fail_to_interp(ctx, func,
                                                       (hb_ir_block_t*)retry_block, out,
                                                       frame.steps, frame.blocks_executed);
            /* Снимок восстановил контекст к состоянию ДО блока, а вместе с ним обнулил
             * `ctx->last_result`. Договор же требует, чтобы после отказа поле несло его
             * причину: проба `jit_store_unmapped_faults` проверяет ровно это, и так же
             * ведёт себя путь помощника, где поле ставится на месте отказа. Ставим здесь,
             * не трогая общий путь провала кодогенерации — у того своя история. */
            if (out->result != HB_OK) ctx->last_result = out->result;
            return rr;
        }
    }
    /* MacRunner 2026-08-22, лейн ЛЕСТНИЦА, итерация 2656 — ПОЧЕМУ ЗДЕСЬ НЕ НАДО ПЕРЕИМЕНОВЫВАТЬ.
     *
     * В 2655 я поставила сюда гейт, объявлявший всякий SIGSEGV/SIGBUS отказом памяти гостя, —
     * и СНИМАЮ его же. Два довода, оба проверяемые.
     *
     * 1. Он ни разу не сработал. Пара прогонов (гейт 0 и 1, четыре гейта прямой памяти,
     *    под обёрткой без ASLR) дала 441/43 и побайтно одинаковые множества отказов.
     *
     * 2. Он лечил бы не то. Сюда управление попадает, когда переигровка невозможна, а
     *    невозможна она по условию `frame.entry->block` — поле законно бывает пустым
     *    (в этом файле оно проверяется на NULL примерно в 25 местах). При этом у ВСЕХ ЧЕТЫРЁХ
     *    мест вызова охранника непустой блок УЖЕ ЕСТЬ: `stable_block = cached->block ? : block`
     *    вычисляется за 12-70 строк до вызова (8727/8739, 8928/8953, 9189/9259, 9461/9532).
     *    То есть остаточный случай чинится ПЕРЕДАЧЕЙ этого блока в охранника — тогда блок
     *    переигрывается интерпретатором и код отказа получается настоящий, — а не
     *    переименованием чужого сигнала в «отказ памяти».
     *
     * Разница не косметическая: переименование объявило бы отказом ГОСТЯ и нашу собственную
     * ошибку выпуска, то есть спрятало бы дефект движка ровно там, где приёмка должна его
     * показывать. Правильная правка названа выше; она ждёт замера, а не гейта. */
    return set_jit_interp_fallback_result(out, HB_ERR_UNSUPPORTED_FEATURE,
                                          frame.steps, frame.blocks_executed,
                                          "JIT native signal fault; interpreter fallback");
}

static void trace_jit_code_cache_full_once(hb_jit_runtime_t* rt,
                                           const char* reason,
                                           size_t needed) {
    if (!rt || !rt->jit_mem || !rt->block_cache) return;
    if (rt->code_cache_full_reports++) return;
    fprintf(stderr, "macrunner-hb-jit-code-cache-full: reason=%s used=%zu size=%zu "
            "needed=%zu entries=%zu capacity=%u\n",
            reason ? reason : "unknown", rt->jit_mem->used, rt->jit_mem->size,
            needed, rt->block_cache->count, (unsigned)rt->block_cache->size);
    fflush(stderr);
}

static void try_promote_copy_scan_counted_loop(hb_jit_runtime_t* rt, hb_context_t* ctx,
                                               const hb_ir_block_t* block) {
    const hb_ir_block_t* body = NULL;
    const hb_ir_block_t* guard = NULL;
    hb_block_cache_entry_t* body_entry = NULL;

    if (!rt || !rt->block_cache || !rt->jit_mem || rt->code_cache_full ||
        block_cache_is_full(rt->block_cache) || !ctx || !block || !block->instr_count)
        return;

    /* MacRunner 2026-08-27 — ПОЧЕМУ СВЁРТКА ЦИКЛА НЕ БЕРЁТСЯ.
     *
     * Шесть отказов приёмки из тринадцати ждут blocks_executed == 1, а получают 2..5.
     * Прибор внутри emit_two_block_loop_helper не сработал ни разу — значит до помощника
     * дело не доходит, отсев раньше. Здесь он и есть: форма блока должна быть ровно
     * 2 или 5 команд с Jcc в конце. Печатаем, что пришло на вход. */
    {
        static unsigned int shape_n;
        unsigned int sn = ++shape_n;
        const hb_ir_instr_t* tail = &block->instrs[block->instr_count - 1];

        if (sn <= 24) {
            fprintf(stderr, "macrunner-hb-loop-shape: n=%u команд=%zu последняя=%d Jcc=%d guest=%#llx\n",
                    sn, block->instr_count, (int)tail->op, (int)HB_IR_Jcc,
                    (unsigned long long)block->guest_addr);
            fflush(stderr);
        }
    }

    const hb_ir_instr_t* last = &block->instrs[block->instr_count - 1];
    if (block->instr_count == 2 && last->op == HB_IR_Jcc) {
        body_entry = block_cache_find(rt->block_cache, last->target);
        if (!body_entry || !body_entry->block || body_entry->fused) return;
        body = body_entry->block;
        guard = block;
    } else if (block->instr_count == 5 && last->op == HB_IR_Jcc) {
        hb_block_cache_entry_t* guard_entry =
            block_cache_find(rt->block_cache, last->guest_addr + last->guest_len);
        if (!guard_entry || !guard_entry->block) return;
        body_entry = block_cache_find(rt->block_cache, block->guest_addr);
        if (!body_entry || body_entry->fused) return;
        body = block;
        guard = guard_entry->block;
    } else {
        return;
    }

    hb_codegen_buffer_t* code_buf = hb_codegen_buffer_create(1024);
    if (!code_buf) return;
    hb_arm64_codegen_t* cg = hb_arm64_codegen_create(ctx);
    if (!cg) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }

    hb_result_t r = hb_arm64_codegen_copy_scan_counted_loop(cg, body, guard, code_buf);
    hb_arm64_codegen_destroy(cg);
    if (r != HB_OK) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }

    if (hb_jit_buffer_make_writable(rt->jit_mem) != HB_OK) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }
    size_t needed = code_buf->size;
    if (rt->jit_mem->used + needed > rt->jit_mem->size) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }

    size_t emitted_size = code_buf->size;
    uint8_t* dest = rt->jit_mem->writable + rt->jit_mem->used;
    memcpy(dest, code_buf->code, emitted_size);
    rt->jit_mem->used += emitted_size;
    rt->jit_mem->used = (rt->jit_mem->used + 15) & ~15;
    hb_codegen_buffer_destroy(code_buf);

    if (hb_jit_buffer_commit(rt->jit_mem) != HB_OK) return;
    /* дальше dest используется только как АДРЕС ИСПОЛНЕНИЯ */
    dest = hb_jit_rw_to_rx(rt->jit_mem, dest);
    hb_contract_telemetry_record_compile();
    /* A fused hot-family block: written straight into jit_mem, never offered to the persistent
     * cache. Counted here so it stops looking like a cache decline. */
    hb_contract_telemetry_record_promote_compile();
    block_cache_put(rt, rt->block_cache, body->guest_addr, dest, emitted_size,
                    (uint32_t)(body->instr_count + guard->instr_count), body, true, false);
    if (trace_jit_blocks_enabled()) {
        fprintf(stderr, "macrunner-hb-jit-fusion: kind=copy-scan-counted body=%p guard=%p "
                "native=%p-%p size=%zu\n",
                (void*)(uintptr_t)body->guest_addr, (void*)(uintptr_t)guard->guest_addr,
                dest, dest + emitted_size, emitted_size);
        fflush(stderr);
    }
}

static void try_promote_bounded_scan_loop(hb_jit_runtime_t* rt, hb_context_t* ctx,
                                          const hb_ir_block_t* block) {
    const hb_ir_block_t* guard = NULL;
    const hb_ir_block_t* body = NULL;
    hb_block_cache_entry_t* guard_entry = NULL;

    if (!rt || !rt->block_cache || !rt->jit_mem || rt->code_cache_full ||
        block_cache_is_full(rt->block_cache) || !ctx || !block || !block->instr_count)
        return;

    const hb_ir_instr_t* last = &block->instrs[block->instr_count - 1];
    if (block->instr_count == 2 && last->op == HB_IR_Jcc) {
        hb_block_cache_entry_t* body_entry =
            block_cache_find(rt->block_cache, last->guest_addr + last->guest_len);
        guard_entry = block_cache_find(rt->block_cache, block->guest_addr);
        if (!body_entry || !body_entry->block || !guard_entry || guard_entry->fused) return;
        guard = block;
        body = body_entry->block;
    } else if (block->instr_count == 3 && last->op == HB_IR_Jcc) {
        guard_entry = block_cache_find(rt->block_cache, last->target);
        if (!guard_entry || !guard_entry->block || guard_entry->fused) return;
        guard = guard_entry->block;
        body = block;
    } else {
        return;
    }

    hb_codegen_buffer_t* code_buf = hb_codegen_buffer_create(1024);
    if (!code_buf) return;
    hb_arm64_codegen_t* cg = hb_arm64_codegen_create(ctx);
    if (!cg) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }

    hb_result_t r = hb_arm64_codegen_bounded_scan_loop(cg, guard, body, code_buf);
    hb_arm64_codegen_destroy(cg);
    if (r != HB_OK) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }

    if (hb_jit_buffer_make_writable(rt->jit_mem) != HB_OK) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }
    size_t needed = code_buf->size;
    if (rt->jit_mem->used + needed > rt->jit_mem->size) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }

    size_t emitted_size = code_buf->size;
    uint8_t* dest = rt->jit_mem->writable + rt->jit_mem->used;
    memcpy(dest, code_buf->code, emitted_size);
    rt->jit_mem->used += emitted_size;
    rt->jit_mem->used = (rt->jit_mem->used + 15) & ~15;
    hb_codegen_buffer_destroy(code_buf);

    if (hb_jit_buffer_commit(rt->jit_mem) != HB_OK) return;
    /* дальше dest используется только как АДРЕС ИСПОЛНЕНИЯ */
    dest = hb_jit_rw_to_rx(rt->jit_mem, dest);
    hb_contract_telemetry_record_compile();
    /* A fused hot-family block: written straight into jit_mem, never offered to the persistent
     * cache. Counted here so it stops looking like a cache decline. */
    hb_contract_telemetry_record_promote_compile();
    block_cache_put(rt, rt->block_cache, guard->guest_addr, dest, emitted_size,
                    (uint32_t)(guard->instr_count + body->instr_count), guard, true, false);
    if (trace_jit_blocks_enabled()) {
        fprintf(stderr, "macrunner-hb-jit-fusion: kind=bounded-byte-scan guard=%p body=%p "
                "native=%p-%p size=%zu\n",
                (void*)(uintptr_t)guard->guest_addr, (void*)(uintptr_t)body->guest_addr,
                dest, dest + emitted_size, emitted_size);
        fflush(stderr);
    }
}

static bool same_plain_runtime_reg_operand(const hb_ir_operand_t* a,
                                           const hb_ir_operand_t* b) {
    return a && b &&
           a->type == HB_OP_REG && b->type == HB_OP_REG &&
           a->reg == b->reg && a->size == b->size &&
           a->reg_offset == b->reg_offset;
}

static bool runtime_exact_reg_operand(const hb_ir_operand_t* op,
                                      hb_reg_t reg,
                                      hb_size_t size) {
    return op && op->type == HB_OP_REG && op->reg == reg &&
           op->size == size && op->reg_offset == 0;
}

static bool runtime_exact_mem_operand(const hb_ir_operand_t* op,
                                      hb_reg_t base,
                                      hb_reg_t index,
                                      uint8_t scale,
                                      int64_t disp,
                                      hb_size_t size) {
    return op && op->type == HB_OP_MEM && op->size == size &&
           op->mem.base == base && op->mem.index == index &&
           op->mem.scale == scale && op->mem.disp == disp &&
           op->mem.segment == 0 && !op->mem.addr32;
}

static bool zero_extend_mem8_to_reg32(const hb_ir_instr_t* instr) {
    return instr && instr->op == HB_IR_ZERO_EXTEND &&
           instr->dst.type == HB_OP_REG && instr->dst.size == HB_SIZE_32 &&
           instr->src1.type == HB_OP_MEM && instr->src1.size == HB_SIZE_8;
}

static bool add_imm1_same_reg64(const hb_ir_instr_t* instr) {
    return instr && instr->op == HB_IR_ADD &&
           instr->dst.type == HB_OP_REG && instr->dst.size == HB_SIZE_64 &&
           same_plain_runtime_reg_operand(&instr->dst, &instr->src1) &&
           instr->src2.type == HB_OP_IMM && instr->src2.imm == 1;
}

static bool test_same_reg32(const hb_ir_instr_t* instr, const hb_ir_operand_t* reg) {
    return instr && reg && instr->op == HB_IR_TEST &&
           instr->src1.type == HB_OP_REG && instr->src1.size == HB_SIZE_32 &&
           same_plain_runtime_reg_operand(&instr->src1, &instr->src2) &&
           same_plain_runtime_reg_operand(&instr->src1, reg);
}

static bool byte_compare_loop_pair(const hb_ir_block_t* cmp_block,
                                   const hb_ir_block_t* backedge_block) {
    const hb_ir_instr_t *lhs, *rhs, *sub, *cmp_jcc;
    const hb_ir_instr_t *inc, *test, *back_jcc;
    if (!cmp_block || !backedge_block ||
        cmp_block->instr_count != 4 || backedge_block->instr_count != 3)
        return false;

    lhs = &cmp_block->instrs[0];
    rhs = &cmp_block->instrs[1];
    sub = &cmp_block->instrs[2];
    cmp_jcc = &cmp_block->instrs[3];
    inc = &backedge_block->instrs[0];
    test = &backedge_block->instrs[1];
    back_jcc = &backedge_block->instrs[2];

    if (!zero_extend_mem8_to_reg32(lhs) || !zero_extend_mem8_to_reg32(rhs))
        return false;
    if (sub->op != HB_IR_SUB ||
        !same_plain_runtime_reg_operand(&sub->dst, &lhs->dst) ||
        !same_plain_runtime_reg_operand(&sub->src1, &lhs->dst) ||
        !same_plain_runtime_reg_operand(&sub->src2, &rhs->dst))
        return false;
    if (cmp_jcc->op != HB_IR_Jcc ||
        (cmp_jcc->cc != HB_CC_E && cmp_jcc->cc != HB_CC_NE) ||
        cmp_jcc->guest_addr + cmp_jcc->guest_len != backedge_block->guest_addr)
        return false;
    if (!add_imm1_same_reg64(inc) ||
        !test_same_reg32(test, &rhs->dst) ||
        back_jcc->op != HB_IR_Jcc ||
        (back_jcc->cc != HB_CC_E && back_jcc->cc != HB_CC_NE) ||
        back_jcc->target != cmp_block->guest_addr)
        return false;
    return true;
}

static void try_promote_byte_compare_loop(hb_jit_runtime_t* rt, hb_context_t* ctx,
                                          const hb_ir_block_t* block) {
    const hb_ir_block_t* cmp_block = NULL;
    const hb_ir_block_t* backedge_block = NULL;
    hb_block_cache_entry_t* cmp_entry = NULL;

    if (!rt || !rt->block_cache || !rt->jit_mem || rt->code_cache_full ||
        block_cache_is_full(rt->block_cache) || !ctx || !block || !block->instr_count)
        return;

    const hb_ir_instr_t* last = &block->instrs[block->instr_count - 1];
    if (block->instr_count == 4 && last->op == HB_IR_Jcc) {
        hb_block_cache_entry_t* backedge_entry =
            block_cache_find(rt->block_cache, last->guest_addr + last->guest_len);
        cmp_entry = block_cache_find(rt->block_cache, block->guest_addr);
        if (!backedge_entry || !backedge_entry->block || !cmp_entry || cmp_entry->fused) return;
        cmp_block = block;
        backedge_block = backedge_entry->block;
    } else if (block->instr_count == 3 && last->op == HB_IR_Jcc) {
        cmp_entry = block_cache_find(rt->block_cache, last->target);
        if (!cmp_entry || !cmp_entry->block || cmp_entry->fused) return;
        cmp_block = cmp_entry->block;
        backedge_block = block;
    } else {
        return;
    }

    if (!byte_compare_loop_pair(cmp_block, backedge_block)) return;

    hb_codegen_buffer_t* code_buf = hb_codegen_buffer_create(1024);
    if (!code_buf) return;
    hb_arm64_codegen_t* cg = hb_arm64_codegen_create(ctx);
    if (!cg) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }

    hb_result_t r = hb_arm64_codegen_two_block_loop_helper(cg, cmp_block, backedge_block, code_buf);
    hb_arm64_codegen_destroy(cg);
    if (r != HB_OK) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }

    if (hb_jit_buffer_make_writable(rt->jit_mem) != HB_OK) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }
    size_t needed = code_buf->size;
    if (rt->jit_mem->used + needed > rt->jit_mem->size) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }

    size_t emitted_size = code_buf->size;
    uint8_t* dest = rt->jit_mem->writable + rt->jit_mem->used;
    memcpy(dest, code_buf->code, emitted_size);
    rt->jit_mem->used += emitted_size;
    rt->jit_mem->used = (rt->jit_mem->used + 15) & ~15;
    hb_codegen_buffer_destroy(code_buf);

    if (hb_jit_buffer_commit(rt->jit_mem) != HB_OK) return;
    /* дальше dest используется только как АДРЕС ИСПОЛНЕНИЯ */
    dest = hb_jit_rw_to_rx(rt->jit_mem, dest);
    hb_contract_telemetry_record_compile();
    /* A fused hot-family block: written straight into jit_mem, never offered to the persistent
     * cache. Counted here so it stops looking like a cache decline. */
    hb_contract_telemetry_record_promote_compile();
    block_cache_put(rt, rt->block_cache, cmp_block->guest_addr, dest, emitted_size,
                    (uint32_t)(cmp_block->instr_count + backedge_block->instr_count),
                    cmp_block, true, false);
    if (trace_jit_blocks_enabled()) {
        fprintf(stderr, "macrunner-hb-jit-fusion: kind=byte-compare-loop cmp=%p backedge=%p "
                "native=%p-%p size=%zu\n",
                (void*)(uintptr_t)cmp_block->guest_addr,
                (void*)(uintptr_t)backedge_block->guest_addr,
                dest, dest + emitted_size, emitted_size);
        fflush(stderr);
    }
}

static bool sub_imm_same_reg64(const hb_ir_instr_t* instr,
                               const hb_ir_operand_t* reg,
                               int64_t imm) {
    return instr && reg && instr->op == HB_IR_SUB &&
           instr->dst.type == HB_OP_REG && instr->dst.size == HB_SIZE_64 &&
           same_plain_runtime_reg_operand(&instr->dst, reg) &&
           same_plain_runtime_reg_operand(&instr->src1, reg) &&
           instr->src2.type == HB_OP_IMM && instr->src2.imm == imm;
}

static bool load_test_nonzero_qword_block(const hb_ir_block_t* block,
                                          hb_ir_operand_t* index_reg,
                                          uint64_t* fallthrough,
                                          uint64_t* nonzero_target) {
    if (!block || block->instr_count != 3) return false;
    const hb_ir_instr_t* load = &block->instrs[0];
    const hb_ir_instr_t* test = &block->instrs[1];
    const hb_ir_instr_t* jcc = &block->instrs[2];
    if (load->op != HB_IR_LOAD ||
        load->dst.type != HB_OP_REG || load->dst.size != HB_SIZE_64 ||
        load->src1.type != HB_OP_MEM || load->src1.size != HB_SIZE_64 ||
        load->src1.mem.index >= HB_REG_COUNT || load->src1.mem.scale != 8)
        return false;
    if (test->src1.type != HB_OP_REG || test->src1.size != HB_SIZE_64 ||
        !same_plain_runtime_reg_operand(&test->src1, &test->src2) ||
        !same_plain_runtime_reg_operand(&test->src1, &load->dst))
        return false;
    if (jcc->op != HB_IR_Jcc || jcc->cc != HB_CC_NE) return false;
    if (index_reg) *index_reg = hb_ir_reg(load->src1.mem.index, HB_SIZE_64);
    if (fallthrough) *fallthrough = jcc->guest_addr + jcc->guest_len;
    if (nonzero_target) *nonzero_target = jcc->target;
    return true;
}

static bool dec_to_test_block(const hb_ir_block_t* block,
                              const hb_ir_operand_t* index_reg,
                              uint64_t* test_target) {
    if (!block || !index_reg || block->instr_count != 2) return false;
    const hb_ir_instr_t* sub = &block->instrs[0];
    const hb_ir_instr_t* jmp = &block->instrs[1];
    if (!sub_imm_same_reg64(sub, index_reg, 1)) return false;
    if (jmp->op != HB_IR_JMP) return false;
    if (test_target) *test_target = jmp->target;
    return true;
}

static bool test_nonnegative_backedge_block(const hb_ir_block_t* block,
                                            const hb_ir_operand_t* index_reg,
                                            uint64_t load_target) {
    if (!block || !index_reg || block->instr_count != 2) return false;
    const hb_ir_instr_t* test = &block->instrs[0];
    const hb_ir_instr_t* jcc = &block->instrs[1];
    return test && test->op == HB_IR_TEST &&
           same_plain_runtime_reg_operand(&test->src1, index_reg) &&
           same_plain_runtime_reg_operand(&test->src2, index_reg) &&
           jcc->op == HB_IR_Jcc && jcc->cc == HB_CC_NS && jcc->target == load_target;
}

static void try_promote_null_qword_scan_loop(hb_jit_runtime_t* rt, hb_context_t* ctx,
                                             const hb_ir_block_t* block) {
    const hb_ir_block_t* load_block = NULL;
    const hb_ir_block_t* dec_block = NULL;
    const hb_ir_block_t* test_block = NULL;
    hb_block_cache_entry_t* load_entry = NULL;
    hb_ir_operand_t index_reg = hb_ir_none();
    uint64_t dec_addr = 0;
    uint64_t test_addr = 0;

    if (!rt || !rt->block_cache || !rt->jit_mem || rt->code_cache_full ||
        block_cache_is_full(rt->block_cache) || !ctx || !block)
        return;

    if (load_test_nonzero_qword_block(block, &index_reg, &dec_addr, NULL)) {
        load_block = block;
        hb_block_cache_entry_t* dec_entry = block_cache_find(rt->block_cache, dec_addr);
        if (!dec_entry || !dec_entry->block ||
            !dec_to_test_block(dec_entry->block, &index_reg, &test_addr))
            return;
        hb_block_cache_entry_t* test_entry = block_cache_find(rt->block_cache, test_addr);
        if (!test_entry || !test_entry->block) return;
        dec_block = dec_entry->block;
        test_block = test_entry->block;
        load_entry = block_cache_find(rt->block_cache, load_block->guest_addr);
    } else if (block->instr_count == 2 && block->instrs[1].op == HB_IR_Jcc) {
        test_block = block;
        uint64_t load_addr = block->instrs[1].target;
        load_entry = block_cache_find(rt->block_cache, load_addr);
        if (!load_entry || !load_entry->block ||
            !load_test_nonzero_qword_block(load_entry->block, &index_reg, &dec_addr, NULL))
            return;
        hb_block_cache_entry_t* dec_entry = block_cache_find(rt->block_cache, dec_addr);
        if (!dec_entry || !dec_entry->block ||
            !dec_to_test_block(dec_entry->block, &index_reg, &test_addr) ||
            test_addr != test_block->guest_addr)
            return;
        load_block = load_entry->block;
        dec_block = dec_entry->block;
    } else {
        return;
    }

    if (!load_entry || load_entry->fused ||
        !test_nonnegative_backedge_block(test_block, &index_reg, load_block->guest_addr))
        return;

    hb_codegen_buffer_t* code_buf = hb_codegen_buffer_create(1024);
    if (!code_buf) return;
    hb_arm64_codegen_t* cg = hb_arm64_codegen_create(ctx);
    if (!cg) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }
    hb_result_t r = hb_arm64_codegen_four_block_loop_helper(cg, load_block, dec_block,
                                                            test_block, NULL, code_buf);
    hb_arm64_codegen_destroy(cg);
    if (r != HB_OK) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }

    if (hb_jit_buffer_make_writable(rt->jit_mem) != HB_OK) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }
    size_t needed = code_buf->size;
    if (rt->jit_mem->used + needed > rt->jit_mem->size) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }
    size_t emitted_size = code_buf->size;
    uint8_t* dest = rt->jit_mem->writable + rt->jit_mem->used;
    memcpy(dest, code_buf->code, emitted_size);
    rt->jit_mem->used += emitted_size;
    rt->jit_mem->used = (rt->jit_mem->used + 15) & ~15;
    hb_codegen_buffer_destroy(code_buf);

    if (hb_jit_buffer_commit(rt->jit_mem) != HB_OK) return;
    /* дальше dest используется только как АДРЕС ИСПОЛНЕНИЯ */
    dest = hb_jit_rw_to_rx(rt->jit_mem, dest);
    hb_contract_telemetry_record_compile();
    /* A fused hot-family block: written straight into jit_mem, never offered to the persistent
     * cache. Counted here so it stops looking like a cache decline. */
    hb_contract_telemetry_record_promote_compile();
    block_cache_put(rt, rt->block_cache, load_block->guest_addr, dest, emitted_size,
                    (uint32_t)(load_block->instr_count + dec_block->instr_count +
                               test_block->instr_count),
                    load_block, true, false);
    if (trace_jit_blocks_enabled()) {
        fprintf(stderr, "macrunner-hb-jit-fusion: kind=null-qword-scan load=%p dec=%p test=%p "
                "native=%p-%p size=%zu\n",
                (void*)(uintptr_t)load_block->guest_addr,
                (void*)(uintptr_t)dec_block->guest_addr,
                (void*)(uintptr_t)test_block->guest_addr,
                dest, dest + emitted_size, emitted_size);
        fflush(stderr);
    }
}

static bool load_cmp_jne_i32_entry_block(const hb_ir_block_t* block,
                                         uint64_t* equal_addr,
                                         uint64_t* less_addr) {
    if (!block || block->instr_count != 3) return false;
    const hb_ir_instr_t* load = &block->instrs[0];
    const hb_ir_instr_t* cmp = &block->instrs[1];
    const hb_ir_instr_t* jcc = &block->instrs[2];
    if (load->op != HB_IR_LOAD ||
        load->dst.type != HB_OP_REG || load->dst.size != HB_SIZE_32 ||
        load->src1.type != HB_OP_MEM || load->src1.size != HB_SIZE_32)
        return false;
    if (cmp->op != HB_IR_CMP ||
        cmp->src1.type != HB_OP_MEM || cmp->src1.size != HB_SIZE_32 ||
        !same_plain_runtime_reg_operand(&cmp->src2, &load->dst))
        return false;
    if (jcc->op != HB_IR_Jcc || jcc->cc != HB_CC_NE) return false;
    if (equal_addr) *equal_addr = jcc->guest_addr + jcc->guest_len;
    if (less_addr) *less_addr = jcc->target;
    return true;
}

static bool cmp_setcc_ret_block(const hb_ir_block_t* block, hb_cc_t cc,
                                hb_ir_operand_t* setcc_dst) {
    if (!block || block->instr_count != 3) return false;
    const hb_ir_instr_t* cmp = &block->instrs[0];
    const hb_ir_instr_t* setcc = &block->instrs[1];
    const hb_ir_instr_t* ret = &block->instrs[2];
    if (cmp->op != HB_IR_CMP ||
        cmp->src1.type != HB_OP_REG || cmp->src1.size != HB_SIZE_64 ||
        cmp->src2.type != HB_OP_REG || cmp->src2.size != HB_SIZE_64)
        return false;
    if (setcc->op != HB_IR_SETcc || setcc->cc != cc || setcc->dst.size != HB_SIZE_8 ||
        ret->op != HB_IR_RET)
        return false;
    if (setcc_dst) *setcc_dst = setcc->dst;
    return true;
}

static bool setcc_ret_block(const hb_ir_block_t* block, hb_cc_t cc,
                            const hb_ir_operand_t* expected_dst) {
    if (!block || !expected_dst || block->instr_count != 2) return false;
    const hb_ir_instr_t* setcc = &block->instrs[0];
    const hb_ir_instr_t* ret = &block->instrs[1];
    return setcc->op == HB_IR_SETcc && setcc->cc == cc &&
           same_plain_runtime_reg_operand(&setcc->dst, expected_dst) &&
           ret->op == HB_IR_RET;
}

static const hb_ir_block_t* find_comparator_entry_pred(const hb_ir_block_t* block,
                                                       uint64_t* equal_addr,
                                                       uint64_t* less_addr) {
    if (load_cmp_jne_i32_entry_block(block, equal_addr, less_addr))
        return block;
    if (!block) return NULL;
    for (size_t i = 0; i < block->pred_count; i++) {
        const hb_ir_block_t* pred = block->pred[i];
        if (load_cmp_jne_i32_entry_block(pred, equal_addr, less_addr))
            return pred;
    }
    return NULL;
}

static const hb_ir_block_t* find_comparator_entry_near_cache(hb_block_cache_t* cache,
                                                             const hb_ir_block_t* equal_block,
                                                             uint64_t* equal_addr,
                                                             uint64_t* less_addr) {
    hb_ir_operand_t ignored = hb_ir_none();
    if (!cache || !equal_block || !cmp_setcc_ret_block(equal_block, HB_CC_B, &ignored))
        return NULL;
    for (uint64_t back = 1; back <= 16; back++) {
        hb_block_cache_entry_t* entry = block_cache_find(cache, equal_block->guest_addr - back);
        if (!entry || !entry->block) continue;
        uint64_t candidate_equal = 0;
        uint64_t candidate_less = 0;
        if (load_cmp_jne_i32_entry_block(entry->block, &candidate_equal, &candidate_less) &&
            candidate_equal == equal_block->guest_addr) {
            if (equal_addr) *equal_addr = candidate_equal;
            if (less_addr) *less_addr = candidate_less;
            return entry->block;
        }
    }
    return NULL;
}

static void try_promote_i32_less_tiebreaker_comparator(hb_jit_runtime_t* rt, hb_context_t* ctx,
                                                       const hb_ir_block_t* block) {
    if (!rt || !rt->block_cache || !rt->jit_mem || rt->code_cache_full ||
        block_cache_is_full(rt->block_cache) || !ctx || !block)
        return;

    uint64_t equal_addr = 0;
    uint64_t less_addr = 0;
    const hb_ir_block_t* entry_block = find_comparator_entry_pred(block, &equal_addr, &less_addr);
    if (!entry_block)
        entry_block = find_comparator_entry_near_cache(rt->block_cache, block, &equal_addr, &less_addr);
    if (!entry_block) return;

    hb_block_cache_entry_t* entry = block_cache_find(rt->block_cache, entry_block->guest_addr);
    hb_block_cache_entry_t* equal = block_cache_find(rt->block_cache, equal_addr);
    hb_block_cache_entry_t* less = block_cache_find(rt->block_cache, less_addr);
    if (!entry || entry->fused || !equal || !equal->block)
        return;

    hb_ir_operand_t setcc_dst = hb_ir_none();
    if (!cmp_setcc_ret_block(equal->block, HB_CC_B, &setcc_dst))
        return;
    if (less && less->block && !setcc_ret_block(less->block, HB_CC_L, &setcc_dst))
        less = NULL;

    hb_codegen_buffer_t* code_buf = hb_codegen_buffer_create(1024);
    if (!code_buf) return;
    hb_arm64_codegen_t* cg = hb_arm64_codegen_create(ctx);
    if (!cg) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }
    hb_result_t r = hb_arm64_codegen_i32_less_tiebreaker_helper(
        cg, entry_block, equal->block, less && less->block ? less->block : NULL, code_buf);
    hb_arm64_codegen_destroy(cg);
    if (r != HB_OK) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }
    if (hb_jit_buffer_make_writable(rt->jit_mem) != HB_OK) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }
    size_t needed = code_buf->size;
    if (rt->jit_mem->used + needed > rt->jit_mem->size) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }
    size_t emitted_size = code_buf->size;
    uint8_t* dest = rt->jit_mem->writable + rt->jit_mem->used;
    memcpy(dest, code_buf->code, emitted_size);
    rt->jit_mem->used += emitted_size;
    rt->jit_mem->used = (rt->jit_mem->used + 15) & ~15;
    hb_codegen_buffer_destroy(code_buf);

    if (hb_jit_buffer_commit(rt->jit_mem) != HB_OK) return;
    /* дальше dest используется только как АДРЕС ИСПОЛНЕНИЯ */
    dest = hb_jit_rw_to_rx(rt->jit_mem, dest);
    hb_contract_telemetry_record_compile();
    /* A fused hot-family block: written straight into jit_mem, never offered to the persistent
     * cache. Counted here so it stops looking like a cache decline. */
    hb_contract_telemetry_record_promote_compile();
    block_cache_put(rt, rt->block_cache, entry_block->guest_addr, dest, emitted_size,
                    (uint32_t)(entry_block->instr_count + equal->block->instr_count +
                               (less && less->block ? less->block->instr_count : 0)),
                    entry_block, true, false);
    if (trace_jit_blocks_enabled()) {
        fprintf(stderr, "macrunner-hb-jit-fusion: kind=i32-less-tiebreaker entry=%p equal=%p less=%p "
                "native=%p-%p size=%zu\n",
                (void*)(uintptr_t)entry_block->guest_addr,
                (void*)(uintptr_t)equal->block->guest_addr,
                (void*)(uintptr_t)(less && less->block ? less->block->guest_addr : 0),
                dest, dest + emitted_size, emitted_size);
        fflush(stderr);
    }
}

static bool unity_sort_inner_block(const hb_ir_block_t* block, uint64_t* cont_addr) {
    if (!block || block->instr_count != 7) return false;
    const hb_ir_instr_t* i = block->instrs;

    if (i[0].op != HB_IR_LOAD ||
        !runtime_exact_reg_operand(&i[0].dst, HB_REG_RAX, HB_SIZE_64) ||
        !runtime_exact_mem_operand(&i[0].src1, HB_REG_RDI, HB_REG_COUNT, 1, 0, HB_SIZE_64))
        return false;
    if (i[1].op != HB_IR_MOV ||
        !runtime_exact_reg_operand(&i[1].dst, HB_REG_RCX, HB_SIZE_64) ||
        !runtime_exact_reg_operand(&i[1].src1, HB_REG_R15, HB_SIZE_64))
        return false;
    if (i[2].op != HB_IR_STORE ||
        !runtime_exact_mem_operand(&i[2].src1, HB_REG_R14, HB_REG_COUNT, 1, 0, HB_SIZE_64) ||
        !runtime_exact_reg_operand(&i[2].src2, HB_REG_RAX, HB_SIZE_64))
        return false;
    if (i[3].op != HB_IR_MOV ||
        !runtime_exact_reg_operand(&i[3].dst, HB_REG_R14, HB_SIZE_64) ||
        !runtime_exact_reg_operand(&i[3].src1, HB_REG_RDI, HB_SIZE_64))
        return false;
    if (i[4].op != HB_IR_LOAD ||
        !runtime_exact_reg_operand(&i[4].dst, HB_REG_RDX, HB_SIZE_64) ||
        !runtime_exact_mem_operand(&i[4].src1, HB_REG_RDI, HB_REG_COUNT, 1, -8, HB_SIZE_64))
        return false;
    if (i[5].op != HB_IR_SUB ||
        !runtime_exact_reg_operand(&i[5].dst, HB_REG_RDI, HB_SIZE_64) ||
        !runtime_exact_reg_operand(&i[5].src1, HB_REG_RDI, HB_SIZE_64) ||
        i[5].src2.type != HB_OP_IMM || i[5].src2.imm != 8)
        return false;
    if (i[6].op != HB_IR_CALL ||
        !runtime_exact_reg_operand(&i[6].src1, HB_REG_RBP, HB_SIZE_64))
        return false;

    if (cont_addr) *cont_addr = i[6].guest_addr + i[6].guest_len;
    return true;
}

static bool unity_sort_cont_block(const hb_ir_block_t* block,
                                  uint64_t sort_addr,
                                  uint64_t* fallthrough_addr) {
    if (!block || block->instr_count != 2) return false;
    const hb_ir_instr_t* i = block->instrs;

    if (i[0].op != HB_IR_TEST ||
        !runtime_exact_reg_operand(&i[0].src1, HB_REG_RAX, HB_SIZE_8) ||
        !runtime_exact_reg_operand(&i[0].src2, HB_REG_RAX, HB_SIZE_8))
        return false;
    if (i[1].op != HB_IR_Jcc || i[1].cc != HB_CC_NE || i[1].target != sort_addr)
        return false;
    if (fallthrough_addr) *fallthrough_addr = i[1].guest_addr + i[1].guest_len;
    return true;
}

static const hb_ir_block_t* find_unity_sort_inner_near_cont(hb_block_cache_t* cache,
                                                            const hb_ir_block_t* cont) {
    if (!cache || !cont) return NULL;
    for (uint64_t back = 1; back <= 64; back++) {
        hb_block_cache_entry_t* entry = block_cache_find(cache, cont->guest_addr - back);
        uint64_t candidate_cont = 0;
        if (entry && entry->block &&
            unity_sort_inner_block(entry->block, &candidate_cont) &&
            candidate_cont == cont->guest_addr)
            return entry->block;
    }
    return NULL;
}

static bool unity_sort_comparator_ready(hb_context_t* ctx,
                                        const hb_ir_block_t* cmp) {
    static const uint8_t unity_cmp_bytes[] = {
        0x8b, 0x02,             /* mov eax, [rdx] */
        0x39, 0x01,             /* cmp [rcx], eax */
        0x75, 0x07,             /* jne +7 */
        0x48, 0x3b, 0xca,       /* cmp rcx, rdx */
        0x0f, 0x92, 0xc0,       /* setb al */
        0xc3,                   /* ret */
        0x0f, 0x9c, 0xc0,       /* setl al */
        0xc3                    /* ret */
    };
    uint8_t bytes[sizeof(unity_cmp_bytes)];
    uint64_t equal_addr = 0;
    uint64_t less_addr = 0;
    if (!ctx || !ctx->memory || !cmp ||
        !load_cmp_jne_i32_entry_block(cmp, &equal_addr, &less_addr))
        return false;
    if (equal_addr != cmp->guest_addr + 0x06 || less_addr != cmp->guest_addr + 0x0d)
        return false;
    if (hb_memory_read(ctx->memory, cmp->guest_addr, bytes, sizeof(bytes)) != HB_OK)
        return false;
    return memcmp(bytes, unity_cmp_bytes, sizeof(bytes)) == 0;
}

static int trace_unity_sort_promote_enabled(void) {
    const char* env = hb_gate( HB_GATE_HB_TRACE_UNITY_SORT_PROMOTE );

    if (env && *env && *env != '0') return 1;
    return trace_jit_blocks_enabled();
}

static void trace_unity_sort_promote(const char* reason,
                                     const hb_ir_block_t* block,
                                     const hb_ir_block_t* sort,
                                     const hb_ir_block_t* cont,
                                     const hb_ir_block_t* cmp,
                                     uint64_t rbp) {
    static unsigned count;
    if (!trace_unity_sort_promote_enabled() || count++ >= 2000)
        return;
    fprintf(stderr,
            "macrunner-hb-unity-sort-promote: reason=%s block=%p block_instrs=%zu "
            "sort=%p cont=%p cmp=%p rbp=%p\n",
            reason ? reason : "unknown",
            block ? (void*)(uintptr_t)block->guest_addr : NULL,
            block ? block->instr_count : 0,
            sort ? (void*)(uintptr_t)sort->guest_addr : NULL,
            cont ? (void*)(uintptr_t)cont->guest_addr : NULL,
            cmp ? (void*)(uintptr_t)cmp->guest_addr : NULL,
            (void*)(uintptr_t)rbp);
    fflush(stderr);
}

static void try_promote_unity_sort_inner_loop(hb_jit_runtime_t* rt, hb_context_t* ctx,
                                              const hb_ir_block_t* block) {
    const hb_ir_block_t* sort = NULL;
    const hb_ir_block_t* cont = NULL;
    hb_block_cache_entry_t* sort_entry = NULL;
    uint64_t cont_addr = 0;
    uint64_t ignored_fallthrough = 0;

    if (!rt || !rt->block_cache || !rt->jit_mem || rt->code_cache_full ||
        block_cache_is_full(rt->block_cache) || !ctx || !block ||
        ctx->mode != HB_MODE_64BIT)
        return;

    if ((block->instr_count == 7 &&
         block->instrs[block->instr_count - 1].op == HB_IR_CALL) ||
        (block->instr_count == 2 &&
         block->instrs[block->instr_count - 1].op == HB_IR_Jcc)) {
        trace_unity_sort_promote("enter", block, NULL, NULL, NULL,
                                 ctx->regs.x64.rbp);
    }

    if (unity_sort_inner_block(block, &cont_addr)) {
        sort = block;
        hb_block_cache_entry_t* cont_entry = block_cache_find(rt->block_cache, cont_addr);
        if (!cont_entry || !cont_entry->block) {
            trace_unity_sort_promote("sort-cont-miss", block, sort, NULL, NULL,
                                     ctx->regs.x64.rbp);
            return;
        }
        cont = cont_entry->block;
    } else if (block->instr_count == 2 && block->instrs[1].op == HB_IR_Jcc) {
        sort = find_unity_sort_inner_near_cont(rt->block_cache, block);
        if (!sort || !unity_sort_inner_block(sort, &cont_addr) ||
            cont_addr != block->guest_addr) {
            trace_unity_sort_promote("guard-sort-miss", block, sort, block, NULL,
                                     ctx->regs.x64.rbp);
            return;
        }
        cont = block;
    } else {
        return;
    }

    if (!unity_sort_cont_block(cont, sort->guest_addr, &ignored_fallthrough)) {
        trace_unity_sort_promote("guard-shape-miss", block, sort, cont, NULL,
                                 ctx->regs.x64.rbp);
        return;
    }
    sort_entry = block_cache_find(rt->block_cache, sort->guest_addr);
    if (!sort_entry || sort_entry->fused) {
        trace_unity_sort_promote(sort_entry ? "sort-already-fused" : "sort-entry-miss",
                                 block, sort, cont, NULL, ctx->regs.x64.rbp);
        return;
    }

    hb_block_cache_entry_t* cmp_entry = block_cache_find(rt->block_cache, ctx->regs.x64.rbp);
    if (!cmp_entry || !cmp_entry->block) {
        trace_unity_sort_promote("cmp-entry-miss", block, sort, cont, NULL,
                                 ctx->regs.x64.rbp);
        return;
    }
    if (!unity_sort_comparator_ready(ctx, cmp_entry->block)) {
        trace_unity_sort_promote("cmp-shape-miss", block, sort, cont, cmp_entry->block,
                                 ctx->regs.x64.rbp);
        return;
    }
    trace_unity_sort_promote("emit", block, sort, cont, cmp_entry->block,
                             ctx->regs.x64.rbp);

    hb_codegen_buffer_t* code_buf = hb_codegen_buffer_create(1024);
    if (!code_buf) return;
    hb_arm64_codegen_t* cg = hb_arm64_codegen_create(ctx);
    if (!cg) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }
    hb_result_t r = hb_arm64_codegen_unity_sort_inner_loop_helper(
        cg, sort, code_buf);
    hb_arm64_codegen_destroy(cg);
    if (r != HB_OK) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }
    if (hb_jit_buffer_make_writable(rt->jit_mem) != HB_OK) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }
    size_t needed = code_buf->size;
    if (rt->jit_mem->used + needed > rt->jit_mem->size) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }
    size_t emitted_size = code_buf->size;
    uint8_t* dest = rt->jit_mem->writable + rt->jit_mem->used;
    memcpy(dest, code_buf->code, emitted_size);
    rt->jit_mem->used += emitted_size;
    rt->jit_mem->used = (rt->jit_mem->used + 15) & ~15;
    hb_codegen_buffer_destroy(code_buf);

    if (hb_jit_buffer_commit(rt->jit_mem) != HB_OK) return;
    /* дальше dest используется только как АДРЕС ИСПОЛНЕНИЯ */
    dest = hb_jit_rw_to_rx(rt->jit_mem, dest);
    hb_contract_telemetry_record_compile();
    /* A fused hot-family block: written straight into jit_mem, never offered to the persistent
     * cache. Counted here so it stops looking like a cache decline. */
    hb_contract_telemetry_record_promote_compile();
    block_cache_put(rt, rt->block_cache, sort->guest_addr, dest, emitted_size,
                    (uint32_t)(sort->instr_count + cont->instr_count),
                    sort, true, false);
    if (trace_jit_blocks_enabled()) {
        fprintf(stderr,
                "macrunner-hb-jit-fusion: kind=unity-sort-inner sort=%p cont=%p cmp=%p "
                "native=%p-%p size=%zu\n",
                (void*)(uintptr_t)sort->guest_addr,
                (void*)(uintptr_t)cont->guest_addr,
                (void*)(uintptr_t)cmp_entry->block->guest_addr,
                dest, dest + emitted_size, emitted_size);
        fflush(stderr);
    }
}

static bool block_contains_lock_rmw_ir(const hb_ir_block_t* block) {
    if (!block) return false;
    for (size_t i = 0; i < block->instr_count; i++) {
        hb_ir_op_t op = block->instrs[i].op;
        if (op == HB_IR_CMPXCHG || op == HB_IR_CMPXCHG8B ||
            op == HB_IR_XCHG || op == HB_IR_XADD)
            return true;
    }
    return false;
}

static bool small_terminal_jcc_self_loop(const hb_ir_block_t* block) {
    if (!block || block->instr_count < 2 || block->instr_count > 16) return false;
    const hb_ir_instr_t* last = &block->instrs[block->instr_count - 1];
    if (last->op != HB_IR_Jcc || last->target != block->guest_addr) return false;
    if (block_contains_lock_rmw_ir(block)) return false;
    for (size_t i = 0; i + 1 < block->instr_count; i++) {
        hb_ir_op_t op = block->instrs[i].op;
        if (op == HB_IR_CALL || op == HB_IR_RET || op == HB_IR_JMP ||
            op == HB_IR_Jcc || op == HB_IR_LOOP || op == HB_IR_JRCXZ)
            return false;
    }
    return true;
}

static void try_promote_self_loop(hb_jit_runtime_t* rt, hb_context_t* ctx,
                                  const hb_ir_block_t* block) {
    bool has_lock_rmw = block_contains_lock_rmw_ir(block);
    if (!rt || !rt->block_cache || !rt->jit_mem || rt->code_cache_full ||
        block_cache_is_full(rt->block_cache) || !ctx ||
        has_lock_rmw || !small_terminal_jcc_self_loop(block))
        return;
    hb_block_cache_entry_t* entry = block_cache_find(rt->block_cache, block->guest_addr);
    if (!entry || entry->fused) return;

    hb_codegen_buffer_t* code_buf = hb_codegen_buffer_create(1024);
    if (!code_buf) return;
    hb_arm64_codegen_t* cg = hb_arm64_codegen_create(ctx);
    if (!cg) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }

    hb_result_t r = hb_arm64_codegen_two_block_loop_helper(cg, block, block, code_buf);
    hb_arm64_codegen_destroy(cg);
    if (r != HB_OK) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }

    if (hb_jit_buffer_make_writable(rt->jit_mem) != HB_OK) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }
    size_t needed = code_buf->size;
    if (rt->jit_mem->used + needed > rt->jit_mem->size) {
        hb_codegen_buffer_destroy(code_buf);
        return;
    }

    size_t emitted_size = code_buf->size;
    uint8_t* dest = rt->jit_mem->writable + rt->jit_mem->used;
    memcpy(dest, code_buf->code, emitted_size);
    rt->jit_mem->used += emitted_size;
    rt->jit_mem->used = (rt->jit_mem->used + 15) & ~15;
    hb_codegen_buffer_destroy(code_buf);

    if (hb_jit_buffer_commit(rt->jit_mem) != HB_OK) return;
    /* дальше dest используется только как АДРЕС ИСПОЛНЕНИЯ */
    dest = hb_jit_rw_to_rx(rt->jit_mem, dest);
    hb_contract_telemetry_record_compile();
    /* A fused hot-family block: written straight into jit_mem, never offered to the persistent
     * cache. Counted here so it stops looking like a cache decline. */
    hb_contract_telemetry_record_promote_compile();
    block_cache_put(rt, rt->block_cache, block->guest_addr, dest, emitted_size,
                    (uint32_t)block->instr_count, block, true, false);
    if (trace_jit_blocks_enabled()) {
        fprintf(stderr, "macrunner-hb-jit-fusion: kind=self-loop block=%p "
                "native=%p-%p size=%zu\n",
                (void*)(uintptr_t)block->guest_addr, dest, dest + emitted_size, emitted_size);
        fflush(stderr);
    }
}

/* MacRunner 2026-07-30 — one kill switch for all seven families, so the question they raise can be
 * answered by measurement instead of by reading.
 *
 * What a profile of the thread that drives startup shows: try_promote_hot_block_families is 40
 * samples at the top of stack, and under the helper it installs —
 * hb_jit_helper_exec_two_block_loop — sits hb_jit_helper_exec_ir_block_once, then
 * exec_instr_unlocked, then mem_read → hb_memory_read → find_region_normalized. That is the
 * INTERPRETER, with a region lookup per guest memory access.
 *
 * Reading the helper confirms the shape: it tries three hand-written fast paths
 * (test/jne epilogue, cmp/rol/test, vector store) and, when none of them matches, runs a
 * budgeted while loop interpreting the IR block by block. So a promoted hot loop is not translated
 * to ARM64 at all — it becomes a call into an interpreter — while an unpromoted block goes through
 * run_jit_block_with_signal_guard and executes native code.
 *
 * Which of those is faster is not obvious and must not be guessed: the fused path saves dispatch and
 * guard overhead per iteration, the plain path executes real instructions. Hence a gate rather than a
 * deletion. Default 1, so this commit changes nothing until the A/B says which way to set it. */
/* ═══ ПРОДВИЖЕНИЕ ПО ОДНОЙ СЕМЬЕ ═══
 *
 * Гейт MACRUNNER_HB_PROMOTE_FAMILIES принимает три вида значения:
 *   "0" или не задан  — ни одной семьи (умолчание, см. замер ниже);
 *   "1"               — все семь, как было до 03.09.2026;
 *   список имён       — только названные, через запятую или пробел.
 *
 * Имена ровно те, что печатает macrunner-hb-jit-fusion: kind=…, чтобы список
 * составлялся по журналу прогона, а не по чтению кода.
 *
 * ЗАЧЕМ. 30.07.2026 умолчание перевернули в 0: продвижение делало прогон
 * ВТРОЕ длиннее (771 и 780 с против 250 с). Продолжением там же названо
 * «включать по одной семье, когда каждую можно померить отдельно» — и это
 * полтора месяца оставалось невыполнимым, потому что гейт был булев.
 *
 * Замер 03.09.2026, Half-Life, 120 с, продвижение ВКЛ — срабатывают ТРИ
 * семьи из семи: bounded-byte-scan 295, copy-scan-counted 230, self-loop 174.
 * Остальные четыре не срабатывают ни разу. При этом 174 продвижения
 * self-loop дают 1 700 000 заходов в hb_jit_helper_exec_two_block_loop, и
 * ВСЕ 100 % проваливаются в запасной путь: три быстрых пути внутри него не
 * подходят ни разу. Запасной путь — hb_interpreter_exec_one_for_jit, то есть
 * интерпретатор по одной команде. Эта семья берёт горячий цикл и переводит
 * его с выпущенного ARM64-кода на интерпретацию. На Diablo то же самое:
 * 1 920 000 заходов, 0 % быстрых.
 *
 * Семь новых гейтов не завожу: их и так 733, и правило прямое — гейт без
 * доказательства не заводить. Расширен существующий. */
enum {
    PF_COPY_SCAN,
    PF_BOUNDED_SCAN,
    PF_BYTE_COMPARE,
    PF_NULL_QWORD,
    PF_I32_TIE,
    PF_UNITY_SORT,
    PF_SELF_LOOP,
    PF_N
};

static const char* const pf_imya[PF_N] = {
    "copy-scan-counted",
    "bounded-byte-scan",
    "byte-compare-loop",
    "null-qword-scan",
    "i32-less-tiebreaker",
    "unity-sort-inner",
    "self-loop",
};

static int pf_vklyuchena(int semya)
{
    /* Кеш привязан к УКАЗАТЕЛЮ из таблицы, а не к признаку «уже разобрано».
     * Признак не переживает hb_env_refresh: тесты меняют окружение на ходу,
     * и с одноразовым разбором значение застревает на первом прочтении за
     * процесс. Сегодня ровно это повесило приёмку насмерть на пределе блоков.
     * Совпал указатель — значение то же, разбирать нечего. */
    static const char* razobrano = (const char*)-1;
    static unsigned char vkl[PF_N];
    const char* v = hb_gate( HB_GATE_HB_PROMOTE_FAMILIES );

    if (v != razobrano)
    {
        int i;

        razobrano = v;
        for (i = 0; i < PF_N; i++) vkl[i] = 0;
        if (!v || !*v || (v[0] == '0' && v[1] == '\0')) return 0;   /* vkl только что обнулены */
        if (v[0] == '1' && v[1] == '\0')
        {
            for (i = 0; i < PF_N; i++) vkl[i] = 1;
        }
        else
        {
            /* Список имён. Совпадение ПОЛНОЕ, а не по подстроке: иначе
             * "self-loop" совпало бы внутри чужого имени, и мы бы включили
             * не ту семью — ровно тот класс ошибки, что уже давал три ложных
             * вывода за заход при счёте вех по подстроке. */
            for (i = 0; i < PF_N; i++)
            {
                size_t dlina = strlen( pf_imya[i] );
                const char* p = v;
                while ((p = strstr( p, pf_imya[i] )) != NULL)
                {
                    char do_ = (p == v) ? ',' : p[-1];
                    char posle = p[dlina];
                    if ((do_ == ',' || do_ == ' ') && (posle == '\0' || posle == ',' || posle == ' '))
                    {
                        vkl[i] = 1;
                        break;
                    }
                    p += dlina;
                }
            }
        }
    }
    return vkl[semya];
}

static int promote_families_enabled(void) {
    /* Default flipped to 0 on 2026-07-30. Measured, three runs:
     *   promotion on   771.0 s and 780.0 s to the language marker
     *   promotion off  250.3 s
     * plus the profile of the critical thread, 113 -> 35 samples in hb_jit_runtime_run, with every
     * component falling together (two_block_loop 34->0, signal guard 32->5, memmove 25->4,
     * find_region 8->0). The two "on" runs landing within 9 s of each other is what makes this a
     * bimodal distribution rather than noise, and it retro-explains the 272/321/463/528/750/804 s
     * spread that made every A/B this month unreadable: fast runs were the ones where promotion
     * never caught a hot loop.
     *
     * =1 restores the old behaviour. The three hand-written fast paths inside
     * hb_jit_helper_exec_two_block_loop are presumably a win where they match; what loses is the
     * interpreter fallback they sit in front of. Re-enabling per-family, once each family can be
     * measured on its own, is the follow-up. */
    /* «Включена хоть одна семья» — прежний смысл этой функции сохранён:
     * её зовут как дешёвый отсев до всякой работы.
     *
     * ★ 2026-09-06, лейн ГЕЙТЫ — ОТВЕТ КОНСТАНТОЙ ВМЕСТО СЕМИ ВЫЗОВОВ.
     * Профиль HK x64 после снятия набора нативной памяти (sample 10 мс, критический
     * поток, знаменатель — занятое время): pf_vklyuchena 38 отсчётов = 2,22 %, из них
     * 30 под этой функцией. Строк она не сравнивает — гейт уже читается таблицей
     * (hb_gate) и уже кеширован по указателю; платится СЕМЬ невстроенных вызовов на
     * КАЖДУЮ диспетчеризацию, чтобы вернуть значение, которое за прогон не меняется.
     * Зовут отсюда: try_promote_hot_block_families() и should_retry_cached_promotion(),
     * а последняя стоит на каждой диспетчеризации (см. её же комментарий).
     *
     * Кеш привязан к УКАЗАТЕЛЮ из таблицы — тем же приёмом и по той же причине, что в
     * pf_vklyuchena: признак «уже разобрано» не переживает hb_env_refresh(), тесты
     * меняют окружение на ходу, и с одноразовым разбором значение застревало бы на
     * первом чтении за процесс (это уже вешало приёмку насмерть).
     *
     * ТОЖДЕСТВО: при совпавшем указателе pf_vklyuchena вернула бы РОВНО те же vkl[],
     * значит и «есть ли среди них единица» — то же самое. При несовпавшем идём прежним
     * перебором, который сам же и обновит разбор. */
    static const char* razobrano_lyuboj = (const char*)-1;
    static int lyuboj;
    const char* v = hb_gate( HB_GATE_HB_PROMOTE_FAMILIES );
    int i;

    if (v == razobrano_lyuboj) return lyuboj;

    lyuboj = 0;
    for (i = 0; i < PF_N; i++) if (pf_vklyuchena( i )) { lyuboj = 1; break; }
    razobrano_lyuboj = v;
    return lyuboj;
}

/* Порог горячести для промоции. Ноль означает «пробовать сразу», как было раньше. */
static uint64_t promote_hot_threshold(void) {
    static int cached = -1;
    static uint64_t value;
    if (cached < 0) {
        const char* v = hb_gate( HB_GATE_HB_PROMOTE_HOT_THRESHOLD );
        /* Умолчание НОЛЬ, и вот почему. Промоция срабатывает при СОЗДАНИИ записи кеша,
         * когда `hit_count` ещё нулевой, — то есть порог гасил бы её целиком (проверено:
         * приёмка падала с 473/12 до 465/20 даже при пороге 1). Дорогой была не первая
         * попытка, а ПОВТОРЫ на каждом проходе, и их снимает `promote_tried`. Порог
         * оставлен настройкой для случая, когда промоцию захотят двигать по горячести. */
        value = (v && *v) ? strtoull(v, NULL, 0) : 0ull;
        cached = 1;
    }
    return value;
}

static void try_promote_hot_block_families(hb_jit_runtime_t* rt, hb_context_t* ctx,
                                           const hb_ir_block_t* block) {
    if (!promote_families_enabled()) return;
    /* Одна попытка на блок: семь распознавателей с выделением буфера каждый — слишком
     * дорого, чтобы повторять их на каждом проходе. Шаблон блока не меняется. */
    {
        /* ★ ДВЕ СТУПЕНИ ЗАЩИТЫ ОТ ЛИШНЕЙ РАБОТЫ.
         *
         * 1. ПОРОГ ГОРЯЧЕСТИ. Дорогую перетрансляцию заводят по СЧЁТЧИКУ, а не по факту
         *    диспетчеризации — так устроено во всякой многоуровневой трансляции. Холодный
         *    блок не платит ничего; счётчик `hit_count` уже растёт на каждом попадании.
         * 2. ОДНА ПОПЫТКА. Шаблон блока не меняется: не подошёл сейчас — не подойдёт никогда.
         *
         * До этого семь распознавателей, каждый с буфером на 1024 байта и своим
         * кодогенератором, заводились на КАЖДОМ проходе. Отсюда замеренные «−3x к старту». */
        hb_block_cache_entry_t* pe = (rt && rt->block_cache && block)
                                   ? block_cache_find(rt->block_cache, block->guest_addr) : NULL;
        if (pe) {
            if (pe->promote_tried) return;
            if (pe->hit_count < promote_hot_threshold()) return;
            pe->promote_tried = true;
        }
    }
    if (pf_vklyuchena( PF_COPY_SCAN )) try_promote_copy_scan_counted_loop(rt, ctx, block);
    if (pf_vklyuchena( PF_BOUNDED_SCAN )) try_promote_bounded_scan_loop(rt, ctx, block);
    if (pf_vklyuchena( PF_BYTE_COMPARE )) try_promote_byte_compare_loop(rt, ctx, block);
    if (pf_vklyuchena( PF_NULL_QWORD )) try_promote_null_qword_scan_loop(rt, ctx, block);
    if (pf_vklyuchena( PF_I32_TIE )) try_promote_i32_less_tiebreaker_comparator(rt, ctx, block);
    if (pf_vklyuchena( PF_UNITY_SORT )) try_promote_unity_sort_inner_loop(rt, ctx, block);
    if (pf_vklyuchena( PF_SELF_LOOP )) try_promote_self_loop(rt, ctx, block);
}

static bool should_retry_cached_promotion(const hb_block_cache_entry_t* entry) {
    /* This gate is a retry for promotion, so with promotion off there is nothing to retry into.
     * Without this line it fires on EVERY dispatch: the backoff below reads entry->hit_count,
     * but hit_count is only ever incremented at trace_jit_hot_block_tick():2771, which sits
     * BELOW that function's `!trace_jit_hot_blocks_enabled()` early return at :2770. Tracing is
     * off in every normal run, so hit_count stays 0 for the life of the entry, `hit_count < 4`
     * is permanently true, and each dispatch pays an extra block_cache_find() into a 36 MB
     * (524288 x ~72 B) open-addressed table — a likely DRAM access — plus a call to
     * try_promote_hot_block_families() that returns immediately because promote_families_enabled()
     * is 0. Pure cost, no effect.
     *
     * Found while accounting per-block dispatch cost: ~350-500 host instructions and ~1.5 KB of
     * memset/memcpy traffic per guest block, against a translated block averaging 34 ARM64
     * instructions. Halving the hash probing is small against that, but it is free and it is on
     * the hottest path in the engine. */
    if (!promote_families_enabled()) return false;
    if (!entry || entry->fused) return false;
    if (entry->hit_count < 4) return true;
    return (entry->hit_count & (entry->hit_count - 1)) == 0;
}

hb_result_t hb_jit_runtime_compile(hb_jit_runtime_t* rt, const hb_ir_func_t* func) {
    (void)rt; (void)func;
    /* Compilation is done on-demand per-block in hb_jit_runtime_run for MVP */
    return HB_OK;
}

/* ★ 2379: предобъявление гейта удалено вместе с ним самим. */

static hb_result_t hb_jit_runtime_run_legacy(hb_jit_runtime_t* rt, const hb_ir_func_t* func, hb_exec_result_t* out) {
    if (!rt || !func || !func->cfg || !out) return HB_ERR_INVALID_ARG;
    memset(out, 0, sizeof(hb_exec_result_t));

    hb_context_t* ctx = rt->ctx;
    uint64_t steps = 0;
    uint64_t blocks_executed = 0;
    bool dispatch_stats_enabled_run = trace_dispatch_stats_enabled() != 0;
    ctx->last_result = HB_OK;
    if (dispatch_stats_enabled_run)
        dispatch_stats_register();

    while (1) {
        /* ★★★ 2026-08-18, лейн ЛЕСТНИЦА, итерация 2379 (приказ владельца 185) —
         * СЛЕДИЛКА ABZU УБРАНА (копия 1 из 2).
         *
         * Наблюдатель контрольного потока ABZU/UE4 с двадцатью жёсткими адресами ОДНОЙ сборки
         * (0x140145ec8 … 0x14014607b, 0x14057fd10 и родня). Находки записаны; в другой
         * раскладке эти адреса не значат ничего. Стоял за гейтом, то есть на горячем пути
         * стоил проверки флага на каждом обороте цикла исполнения блоков.
         *
         * Границы куска считаны ПО СКОБКАМ от известной точки: 2378 показал, чем кончается
         * поиск ключевого слова назад — вырезанными 25 КБ чужого кода. */
        if (ctx->step_limit > 0 && steps >= ctx->step_limit) {
            out->result = HB_ERR_STEP_LIMIT;
            { /* Итерация 307: назвать МЕСТО. Печать безусловная, первые 4 раза на место. */
              static int said_7215; extern const char* hb_result_string(int);
              if (out->result != HB_OK && said_7215++ < 4)
                fprintf(stderr, "macrunner-hb-result-site: место=7215 результат=%s(%d) pc=%#llx\n",
                        hb_result_string(out->result), (int)out->result,
                        0ULL); }
            out->steps_executed = steps;
            out->blocks_executed = blocks_executed;
            return HB_OK;
        }
        if (ctx->block_limit > 0 && blocks_executed >= ctx->block_limit) {
            return set_runtime_fault_result(out, ctx, HB_ERR_BLOCK_LIMIT, steps,
                                            blocks_executed, "block limit reached");
        }

        /* MacRunner 2026-08-03 — the one choke point every guest transition passes through.
         *
         * The fault that kills Hollow Knight is an execute at address 0 (code=0xc0000005 addr=0x0
         * info0=0x8).  Instrumenting RET does not catch it: the interpreter's RET guard fired zero
         * times across a full run, and on the translated path emit_native_ret bypasses the pop
         * helper entirely, so there is no single RET to watch.  Here there is — native return,
         * helper return and indirect jump all arrive at this dispatch with the new guest pc in
         * ctx->pc.  Two comparisons, and nothing is formatted unless the pc is already impossible. */
        if (!ctx->pc || (((int64_t)ctx->pc >> 47) != 0 && ((int64_t)ctx->pc >> 47) != -1)) {
            static unsigned int null_pc_reports;
            if (null_pc_reports++ < 16) {
                uint64_t win[6] = { 0 };
                unsigned int wi;
                for (wi = 0; wi < 6; wi++)
                    if (hb_memory_read_u64(ctx->memory, ctx->regs.x64.rsp + wi * 8, &win[wi]) != HB_OK)
                        win[wi] = 0;
                fprintf(stderr,
                        "macrunner-hb-dispatch-null-pc: pc=0x%llx rsp=0x%llx rbp=0x%llx "
                        "rax=0x%llx rcx=0x%llx r8=0x%llx r15=0x%llx "
                        "stk=%llx,%llx,%llx,%llx,%llx,%llx\n",
                        (unsigned long long)ctx->pc,
                        (unsigned long long)ctx->regs.x64.rsp,
                        (unsigned long long)ctx->regs.x64.rbp,
                        (unsigned long long)ctx->regs.x64.rax,
                        (unsigned long long)ctx->regs.x64.rcx,
                        (unsigned long long)ctx->regs.x64.r8,
                        (unsigned long long)ctx->regs.x64.r15,
                        (unsigned long long)win[0], (unsigned long long)win[1],
                        (unsigned long long)win[2], (unsigned long long)win[3],
                        (unsigned long long)win[4], (unsigned long long)win[5]);
            }
        }
        /* ★★★★★ MacRunner 2026-08-29 — СЛЕД ПУТИ ДО ОТКАЗА.
         *
         * Отказ Diablo в wined3d_cs_run+0x14a: чтение [ebx+0x1c88] при ebx=0x120, тогда
         * как в прологе той же функции чтение через ebx прошло. По одному снимку регистров
         * НЕЛЬЗЯ сказать, где ebx испортился: симуляция вошла по 0x7bd75682 и сделала
         * 25 256 шагов. Кольцо последних блоков отвечает на это за один прогон — тем же
         * приёмом, что уже сработал с name-the-caller-by-guest-return-address.
         *
         * Цена: две записи в TLS на блок, под гейтом MACRUNNER_HB_TRACE_PATH. */
        if (trace_path_enabled()) {
            t_path[t_path_head & (HB_PATH_RING - 1)].pc = ctx->pc;
            t_path[t_path_head & (HB_PATH_RING - 1)].rbx =
                (buf_arch_is_x86(ctx) ? (uint64_t)ctx->regs.x86.ebx : ctx->regs.x64.rbx);
            t_path_head++;
        }
        hb_ir_block_t* block = find_block(func->cfg, ctx->pc);
        if (!block) {
            if (func->truncated) {
                return set_runtime_fault_result(out, ctx, HB_ERR_TRANSLATION_TRUNCATED,
                                                steps, blocks_executed,
                                                "translated function truncated before current PC");
            }
            out->result = HB_OK;
            { /* Итерация 307: назвать МЕСТО. Печать безусловная, первые 4 раза на место. */
              static int said_7264; extern const char* hb_result_string(int);
              if (out->result != HB_OK && said_7264++ < 4)
                fprintf(stderr, "macrunner-hb-result-site: место=7264 результат=%s(%d) pc=%#llx\n",
                        hb_result_string(out->result), (int)out->result,
                        0ULL); }
            out->steps_executed = steps;
            out->blocks_executed = blocks_executed;
            return HB_OK; /* No block for PC — function exit or external call */
        }

        blocks_executed++;

        /* Check in-memory block cache */
        hb_block_cache_entry_t* cached = block_cache_find(rt->block_cache, ctx->pc);
        bool smc_evicted = false;
        cached = smc_reverify_entry(rt, cached, &smc_evicted);
        if (smc_evicted && smc_relift_should_exit(steps)) {
            /* Guest bytes changed under this translation: the caller's lifted IR is
             * stale too.  Exit so it re-lifts from current bytes. */
            out->result = HB_OK;
            { /* Итерация 307: назвать МЕСТО. Печать безусловная, первые 4 раза на место. */
              static int said_7279; extern const char* hb_result_string(int);
              if (out->result != HB_OK && said_7279++ < 4)
                fprintf(stderr, "macrunner-hb-result-site: место=7279 результат=%s(%d) pc=%#llx\n",
                        hb_result_string(out->result), (int)out->result,
                        0ULL); }
            out->steps_executed = steps;
            out->blocks_executed = blocks_executed;
            return HB_OK;
        }
        if (cached) {
            if (trace_jit_block_contains_guest(block, trace_jit_guest_addr())) {
                trace_unity_sort_promote("cache-hit-watch", block, NULL, NULL, NULL,
                                         ctx->mode == HB_MODE_64BIT ? ctx->regs.x64.rbp : 0);
            }
            if (block && ((block->instr_count == 7 &&
                           block->instrs[block->instr_count - 1].op == HB_IR_CALL) ||
                          (block->instr_count == 2 &&
                           block->instrs[block->instr_count - 1].op == HB_IR_Jcc))) {
                trace_unity_sort_promote("cache-hit-gate", block, NULL, NULL, NULL,
                                         ctx->mode == HB_MODE_64BIT ? ctx->regs.x64.rbp : 0);
            }
            if (should_retry_cached_promotion(cached)) {
                const hb_ir_block_t* stable_block = cached->block ? cached->block : block;
                try_promote_hot_block_families(rt, ctx, stable_block);
                cached = block_cache_find(rt->block_cache, ctx->pc);
                if (!cached) {
                    /* MacRunner FIX#2a: non-latching (live block_cache_is_full gates). */
                    trace_jit_code_cache_full_once(rt, "block-cache-promote-lost-entry", 0);
                    return set_jit_interp_fallback_result(out, HB_ERR_UNSUPPORTED_FEATURE,
                                                          steps, blocks_executed,
                                                          "JIT block cache lost promoted entry; interpreter fallback");
                }
            }
            trace_jit_cached_watch_block_once(rt, cached);
            unsigned long long mr_dc_t0 = mr_dc_before();
            /* ★ 27.08: тот же stable_block, что вычисляют строки выше, но в области
             * видимости вызова: там он объявлен во вложенном блоке. */
            const hb_ir_block_t* guard_stable = (cached && cached->block)
                                                ? cached->block
                                                : (func && func->cfg ? find_block(func->cfg, ctx->pc) : NULL);
            hb_result_t run_result = run_jit_block_with_signal_guard(rt, func, cached, guard_stable, out,
                                                                      steps, blocks_executed);
            mr_dc_after(mr_dc_t0);
            if (run_result != HB_OK || out->faulted) return run_result;
            trace_jit_hot_block_tick(rt, cached);
            steps += cached->steps;
            if (dispatch_stats_enabled_run)
                dispatch_stats_add(1, 1, cached->steps);
        } else {
            if (rt->code_cache_full || block_cache_is_full(rt->block_cache)) {
                /* MacRunner FIX#2a: do NOT latch code_cache_full here — the block-cache
                 * full state is already re-checked live via block_cache_is_full() in
                 * every JIT guard, so a transient hash-table fill no longer permanently
                 * disables JIT (which it did while the exec buffer was 82% free). The
                 * genuine hard limit (exec buffer full) still latches at jit_commit_blob. */
                trace_jit_code_cache_full_once(rt, "block-cache-full", 0);
                return set_jit_interp_fallback_result(out, HB_ERR_UNSUPPORTED_FEATURE,
                                                      steps, blocks_executed,
                                                      "JIT code cache full; interpreter fallback");
            }

            hb_cache_key_t persistent_key;
            bool have_persistent_key = false;
            bool loaded_from_persistent = false;
            uint8_t* dest = NULL;
            size_t emitted_size = 0;
            hb_result_t r;

            if (rt->persistent_cache &&
                persistent_cache_key_for_block(rt, block, &persistent_key) == HB_OK) {
                hb_cache_entry_t* disk_entry = NULL;
                have_persistent_key = true;
                r = hb_cache_lookup(rt->persistent_cache, &persistent_key, &disk_entry);
                if (r == HB_OK && disk_entry && disk_entry->valid) {
                    const uint8_t* load_code = NULL;
                    uint8_t* owned_load_code = NULL;
                    hb_ir_block_t* load_block = block_clone_for_cache(block);
                    /* 05.09.2026: блоб = код + хвост с картой отказов. Сначала подвал: он
                     * называет длину КОДА; блоб без подвала (или с искалеченным) — не наш,
                     * исполнять его нельзя, блок перекомпилируется. Карта прикрепляется к
                     * записи ПОСЛЕ block_cache_put — до него записи ещё нет. */
                    size_t blob_code_size = 0;
                    bool blob_ok = ripmap_trailer_parse(disk_entry->native_code,
                                                        disk_entry->native_size,
                                                        &blob_code_size, NULL, NULL, NULL, NULL);
                    emitted_size = blob_ok ? blob_code_size : 0;
                    if (blob_ok && load_block &&
                        native_blob_prepare_cache_load(disk_entry->native_code,
                                                       blob_code_size,
                                                       load_block, &load_code,
                                                       &owned_load_code) &&
                        (r = jit_commit_blob(rt, load_code, emitted_size, &dest)) == HB_OK) {
                        cached = block_cache_put(rt, rt->block_cache, ctx->pc, dest, emitted_size,
                                                 disk_entry->steps ? disk_entry->steps
                                                                    : jit_block_step_count(load_block),
                                                 load_block, false, true);
                        if (cached) {
                            ripmap_attach_from_trailer(cached, disk_entry->native_code,
                                                       disk_entry->native_size);
                            load_block = NULL;
                            loaded_from_persistent = true;
                            hb_contract_telemetry_record_cache_hit(emitted_size);
                            /* ★ 06.09 лейн КЕШ: адрес — в перепись, чтобы «подъёмов с диска»
                             * и «различных блоков» стали двумя разными числами. */
                            hb_contract_telemetry_record_hit_pc((uint64_t)ctx->pc);
                        }
                    }
                    free(owned_load_code);
                    if (load_block) hb_ir_block_destroy(load_block);
                } else {
                    hb_contract_telemetry_record_cache_miss();
                }
                hb_cache_entry_free(disk_entry);
            }

            if (!loaded_from_persistent) {
                hb_ir_block_t* compile_block = NULL;
                /* Compile block into codegen buffer */
                hb_codegen_buffer_t* code_buf = hb_codegen_buffer_create(4096);
                if (!code_buf) return HB_ERR_OUT_OF_MEMORY;
                compile_block = block_clone_for_cache(block);
                if (!compile_block) {
                    hb_codegen_buffer_destroy(code_buf);
                    return HB_ERR_OUT_OF_MEMORY;
                }

                hb_arm64_codegen_t* cg = hb_arm64_codegen_create(ctx);
                if (!cg) {
                    hb_ir_block_destroy(compile_block);
                    hb_codegen_buffer_destroy(code_buf);
                    return HB_ERR_OUT_OF_MEMORY;
                }

                r = hb_arm64_codegen_block_with_cfg(cg, compile_block, func->cfg, code_buf);
                hb_arm64_codegen_destroy(cg);
                if (r == HB_OK && hb_codegen_should_fail_now()) r = HB_ERR_UNSUPPORTED_OPCODE;
                if (r != HB_OK) {
                    codegen_fail_note(compile_block, r);
                    hb_ir_block_destroy(compile_block);
                    hb_codegen_buffer_destroy(code_buf);
                        return hb_codegen_fail_to_interp(ctx, func, block, out,
                                                         steps, blocks_executed);
                    out->result = r;
                    { /* Итерация 307: назвать МЕСТО. Печать безусловная, первые 4 раза на место. */
                      static int said_7398; extern const char* hb_result_string(int);
                      if (out->result != HB_OK && said_7398++ < 4)
                        fprintf(stderr, "macrunner-hb-result-site: место=7398 результат=%s(%d) pc=%#llx\n",
                                hb_result_string(out->result), (int)out->result,
                                0ULL); }
                    out->steps_executed = steps;
                    out->blocks_executed = blocks_executed;
                    out->faulted = true;
                    out->fault_reason = "JIT codegen failed";
                    return HB_OK;
                }

                emitted_size = code_buf->size;
                r = jit_commit_blob(rt, code_buf->code, emitted_size, &dest);
                if (r != HB_OK) {
                    hb_ir_block_destroy(compile_block);
                    hb_codegen_buffer_destroy(code_buf);
                    return set_jit_interp_fallback_result(out, HB_ERR_UNSUPPORTED_FEATURE,
                                                          steps, blocks_executed,
                                                          "JIT code cache full; interpreter fallback");
                }
                hb_contract_telemetry_record_compile();
                hb_contract_telemetry_record_compile_pc((uint64_t)ctx->pc);
                /* Measure the relocation table before anything depends on it. */
                hb_contract_telemetry_record_reloc((unsigned long)code_buf->reloc_count,
                                                   code_buf->reloc_overflow ? 1 : 0);

                if (rt->persistent_cache && have_persistent_key &&
                    code_buf->code && code_buf->size) {
                    const uint8_t* store_code = NULL;
                    uint8_t* owned_store_code = NULL;
                    hb_cache_entry_t metadata;
                    if (native_blob_prepare_cache_store(code_buf, code_buf->code, code_buf->size,
                                                        compile_block, &store_code,
                                                        &owned_store_code)) {
                        uint8_t* blob = NULL;
                        size_t blob_size = 0;
                        memset(&metadata, 0, sizeof(metadata));
                        metadata.steps = jit_block_step_count(compile_block);
                        /* 05.09.2026: в кеш уходит код + хвост с картой отказов; без хвоста
                         * блок с диска не имел бы точного возобновления после отказа. */
                        if (ripmap_trailer_append(store_code, code_buf->size, code_buf,
                                                  &blob, &blob_size)) {
                            r = hb_cache_store(rt->persistent_cache, &persistent_key, blob,
                                               blob_size, &metadata);
                            if (r == HB_OK) {
                                hb_contract_telemetry_record_cache_store(code_buf->size);
                            }
                            free(blob);
                        }
                        free(owned_store_code);
                    } else {
                        /* Attribute the skip: >1 helper call is the structural restriction in
                         * native_blob_single_arg_helper_stub; anything else is a single stub
                         * whose shape was not recognised. See native_blob_helper_call_count.
                         *
                         * Skipped entirely in table-driven mode: the mh_* reasons describe the
                         * old matcher, which did not run, and re-deriving them here would both
                         * cost a scan and put numbers in the log that mean nothing. The rl_*
                         * counters carry the attribution instead. */
                        if (1) {
                            /* уже учтено в native_blob_prepare_cache_store */
                        } else if (native_blob_helper_call_count(code_buf->code, code_buf->size) > 1) {
                            hb_contract_telemetry_record_cache_store_skip_multi();
                            {   /* re-derive the reason for attribution only */
                                hb_cached_helper_stub_t why[HB_MULTI_HELPER_MAX];
                                size_t whyn = 0; hb_mh_reason_t r = HB_MH_OK;
                                (void)native_blob_helper_stubs(code_buf->code, code_buf->size,
                                                               compile_block, false, why, &whyn, &r);
                                hb_contract_telemetry_record_mh_reason((int)r);
                            }
                        }
                        else
                            hb_contract_telemetry_record_cache_store_skip_unmatched();
                        hb_contract_telemetry_record_cache_store_skip();
                    }
                } else if (rt->persistent_cache && have_persistent_key) {
                    hb_contract_telemetry_record_cache_store_skip();
                }
                /* Store in block cache */
                cached = block_cache_put(rt, rt->block_cache, ctx->pc, dest, emitted_size,
                                         jit_block_step_count(compile_block), compile_block,
                                         false, true);
                /* ★★★★★ MacRunner 2026-09-04 — ЧТЕНИЕ ОСВОБОЖДЁННОГО БУФЕРА.
                 * `hb_codegen_buffer_destroy(code_buf)` стояло ВЫШЕ этой строки (оно делает
                 * free(buf), hb_jit.c:570), а `ripmap_attach` читает из `code_buf` поля
                 * host_off/host_instr/host_off_count — то есть карта копировалась из УЖЕ
                 * ОСВОБОЖДЁННОЙ памяти. Не падало единственно потому, что attach выходил по
                 * гейту РАНЬШЕ, чем трогал буфер; с MACRUNNER_HB_RIPMAP=1 или
                 * MACRUNNER_HB_NO_SNAPSHOT=1 это чтение происходило на КАЖДОМ переведённом
                 * блоке — вот почему у обоих гейтов не могло быть верного замера.
                 * Порядок закреплён: копия карты, и только потом освобождение буфера. */
                ripmap_attach(cached, code_buf);
                hb_codegen_buffer_destroy(code_buf);
                if (!cached) {
                    hb_ir_block_destroy(compile_block);
                    /* MacRunner FIX#2a: non-latching (live block_cache_is_full gates). */
                    trace_jit_code_cache_full_once(rt, "block-cache-put-failed", emitted_size);
                }
                trace_jit_block(ctx->pc, dest, emitted_size, block);
            } else if (trace_jit_blocks_enabled()) {
                fprintf(stderr, "macrunner-hb-translation-cache-hit: guest=%p native=%p-%p size=%zu\n",
                        (void*)(uintptr_t)ctx->pc, dest, dest + emitted_size, emitted_size);
                fflush(stderr);
            }

            if (!cached) {
                rt->code_cache_full = true;
                trace_jit_code_cache_full_once(rt, "block-cache-put-failed", emitted_size);
                return set_jit_interp_fallback_result(out, HB_ERR_UNSUPPORTED_FEATURE,
                                                      steps, blocks_executed,
                                                      "JIT code cache full; interpreter fallback");
            }

            if (!cached->fused) {
                const hb_ir_block_t* stable_block = cached->block ? cached->block : block;
                if (trace_jit_block_contains_guest(stable_block, trace_jit_guest_addr())) {
                    trace_unity_sort_promote("cache-put-watch", stable_block, NULL, NULL, NULL,
                                             ctx->mode == HB_MODE_64BIT ? ctx->regs.x64.rbp : 0);
                }
                if (stable_block && ((stable_block->instr_count == 7 &&
                                       stable_block->instrs[stable_block->instr_count - 1].op == HB_IR_CALL) ||
                                      (stable_block->instr_count == 2 &&
                                       stable_block->instrs[stable_block->instr_count - 1].op == HB_IR_Jcc))) {
                    trace_unity_sort_promote("cache-put-gate", stable_block, NULL, NULL, NULL,
                                             ctx->mode == HB_MODE_64BIT ? ctx->regs.x64.rbp : 0);
                }
                try_promote_hot_block_families(rt, ctx, stable_block);
                cached = block_cache_find(rt->block_cache, ctx->pc);
                if (!cached) {
                    rt->code_cache_full = true;
                    trace_jit_code_cache_full_once(rt, "block-cache-promote-lost-entry", emitted_size);
                    return set_jit_interp_fallback_result(out, HB_ERR_UNSUPPORTED_FEATURE,
                                                          steps, blocks_executed,
                                                          "JIT block cache lost promoted entry; interpreter fallback");
                }
            }
            trace_jit_cached_watch_block_once(rt, cached);

            /* Execute */
            unsigned long long mr_dc_t0 = mr_dc_before();
            /* ★ 27.08: тот же stable_block, что вычисляют строки выше, но в области
             * видимости вызова: там он объявлен во вложенном блоке. */
            const hb_ir_block_t* guard_stable = (cached && cached->block)
                                                ? cached->block
                                                : (func && func->cfg ? find_block(func->cfg, ctx->pc) : NULL);
            hb_result_t run_result = run_jit_block_with_signal_guard(rt, func, cached, guard_stable, out,
                                                                      steps, blocks_executed);
            mr_dc_after(mr_dc_t0);
            if (run_result != HB_OK || out->faulted) return run_result;
            trace_jit_hot_block_tick(rt, cached);
            steps += cached->steps ? cached->steps : jit_block_step_count(block);
            if (dispatch_stats_enabled_run)
                dispatch_stats_add(1, 1, cached->steps ? cached->steps : jit_block_step_count(block));
        }
        tramp_snyat_svidetelya(ctx);
    sync_arch_pc_after_jit_block(ctx);
        trace_x86_low_pc_after_block(ctx, block, steps, blocks_executed);
        if (ctx->last_result != HB_OK) {
            if (trace_jit_helper_fault_enabled()) {
                static int t;
                if (t++ < 8)
                    fprintf(stderr, "macrunner-hb-block-fault-pc: pc=0x%llx last=%d guest_addr=0x%llx\n",
                            (unsigned long long)ctx->pc, (int)ctx->last_result,
                            block ? (unsigned long long)block->guest_addr : 0);
                trace_jit_helper_fault_block(ctx, block);
            }
            /* ★ ПРЕДЕЛ, ЗАМЕЧЕННЫЙ ВНУТРИ ЦЕПОЧКИ, ДОКЛАДЫВАЕТСЯ ТЕМ ЖЕ ПУТЁМ,
             * ЧТО И БЕЗ СЦЕПЛЕНИЯ (05.09.2026). Развилка по РОДУ предела.
             *
             * ШАГ — это ритм, а не отказ. Собственная проверка диспетчера без
             * сцепления делает `out->result = HB_ERR_STEP_LIMIT; return HB_OK` без
             * faulted; выпущенный код (emit_srok_vyhod) ставит ctx->last_result и
             * приходит СЮДА, в путь отказа помощника, где wow64 делал из шаг-срока
             * исключение гостя (i386 умирал c0000001, «результат=STEP_LIMIT(-10)
             * операция=STORE»). Поэтому шаг-срок и здесь возвращает HB_OK без
             * faulted — как диспетчер без сцепления.
             *
             * БЛОК — это отказ. Путь без сцепления докладывает предел блоков через
             * set_runtime_fault_result (faulted=1, r=HB_ERR_BLOCK_LIMIT,
             * ctx->last_result=BLOCK_LIMIT — см. проверку у начала цикла). Прежде
             * внутрицепочечный выход по этому же пределу возвращал HB_OK/faulted=0,
             * и одно событие докладывалось двумя способами по тому, кто его заметил
             * (замер 05.09: гейт=1 давал по block_limit r=HB_OK вместо r=BLOCK_LIMIT).
             * Теперь оба места докладывают ОДИНАКОВО — это тот же принцип, что icount
             * у QEMU (cpu_handle_interrupt): причина выхода по сроку выводится
             * единообразно, замечен ли срок в цикле или внутри блока. */
            if (ctx && ctx->last_result == HB_ERR_BLOCK_LIMIT) {
                return set_runtime_fault_result(out, ctx, HB_ERR_BLOCK_LIMIT, steps,
                                                blocks_executed, "block limit reached");
            }
            if (ctx && ctx->last_result == HB_ERR_STEP_LIMIT) {
                out->result = HB_ERR_STEP_LIMIT;
                out->steps_executed = steps;
                out->blocks_executed = blocks_executed;
                ctx->last_result = HB_OK;
                return HB_OK;
            }
            set_helper_fault_result(out, ctx, steps, blocks_executed);
            return HB_OK;
        }

        /* Determine if we should continue or stop */
        if (block->instr_count == 0) {
            out->result = HB_OK;
            { /* Итерация 307: назвать МЕСТО. Печать безусловная, первые 4 раза на место. */
              static int said_7542; extern const char* hb_result_string(int);
              if (out->result != HB_OK && said_7542++ < 4)
                fprintf(stderr, "macrunner-hb-result-site: место=7542 результат=%s(%d) pc=%#llx\n",
                        hb_result_string(out->result), (int)out->result,
                        0ULL); }
            out->steps_executed = steps;
            out->blocks_executed = blocks_executed;
            return HB_OK;
        }

        const hb_ir_instr_t* transfer = first_control_transfer_instr(block);
        const hb_ir_instr_t* last = &block->instrs[block->instr_count - 1];
        /* ЕДИНИЦА, итерация 48. Без слияния «первый переход» и есть завершитель блока.
         * Со слиянием первый переход — условный, а завершает единицу ПОСЛЕДНЯЯ команда
         * (лифтер рвётся ровно на несливаемом переходе). Если оставить первый, то единица,
         * оканчивающаяся на RET, не была бы опознана как возврат, и симуляция пошла бы
         * дальше вместо того, чтобы вернуться вызывающему. Гейт тот же, MERGE_BLOCKS. */
        const hb_ir_instr_t* terminal = merge_blocks_enabled() ? merged_terminal_instr(block)
                                                        : (transfer ? transfer : last);
        if (terminal->op == HB_IR_RET) {
            out->result = HB_OK;
            { /* Итерация 307: назвать МЕСТО. Печать безусловная, первые 4 раза на место. */
              static int said_7552; extern const char* hb_result_string(int);
              if (out->result != HB_OK && said_7552++ < 4)
                fprintf(stderr, "macrunner-hb-result-site: место=7552 результат=%s(%d) pc=%#llx\n",
                        hb_result_string(out->result), (int)out->result,
                        0ULL); }
            out->steps_executed = steps;
            out->blocks_executed = blocks_executed;
            return HB_OK;
        }

        /* For CALL/JMP/Jcc, PC was updated by JIT code; find next block */
        /* ★ 05.09.2026 — ТО ЖЕ, ЧТО В ЖИВОМ ДИСПЕТЧЕРЕ (разбор там же). */
        const uint64_t seq_next = last->guest_addr + last->guest_len;
        const bool seq_end = !is_control_transfer_op(terminal->op);
        if (seq_end && ctx->pc == block->guest_addr) {
            ctx->pc = seq_next;
            if (ctx->arch == HB_ARCH_X64) ctx->regs.x64.rip = ctx->pc;
            else if (ctx->arch == HB_ARCH_X86) ctx->regs.x86.eip = (uint32_t)ctx->pc;
        }
        hb_ir_block_t* next = find_block(func->cfg, ctx->pc);
        if (!next) {
            if (func->truncated) {
                return set_runtime_fault_result(out, ctx, HB_ERR_TRANSLATION_TRUNCATED,
                                                steps, blocks_executed,
                                                "translated function truncated before branch target");
            }
            if (is_control_transfer_op(terminal->op)) {
                out->result = HB_OK;
                out->steps_executed = steps;
                out->blocks_executed = blocks_executed;
                return HB_OK; /* External branch/call/return boundary */
            }
            /* Прямой конец переведённого куска — ШТАТНЫЙ выход, но только когда pc и
             * есть адрес провала; иначе цель действительно не найдена. */
            if (seq_end && ctx->pc == seq_next) {
                out->result = HB_OK;
                out->steps_executed = steps;
                out->blocks_executed = blocks_executed;
                return HB_OK;
            }
            out->result = HB_ERR_NOT_FOUND;
            out->steps_executed = steps;
            out->blocks_executed = blocks_executed;
            out->faulted = true;
            out->fault_reason = "branch target block not found";
            return HB_OK;
        }
        /* Единица без перехода: pc уже переведён выше, цель найдена — продолжаем ею. */
        continue;
    }
}

/* MacRunner 2026-07-30 — CHAIN LENGTH: this wrapper used to count it here, and the number it produced
 * did not mean what it said. It divided blocks executed by calls to THIS function, describing that as
 * "blocks per dispatcher entry, exactly 1.0 when every transition goes through the dispatcher". But
 * the dispatcher is the while (1) loop inside hb_jit_runtime_run_inner: one call to this function
 * retires as many blocks as the guest runs before it leaves the lifted function, so the ratio was
 * blocks-per-lifted-function-entry and was already far above 1 with chaining off. Read as documented
 * it would have reported chaining as working on a build where it does nothing.
 *
 * The denominator has to be native dispatches, and that counter already exists, per-thread and
 * wall-clock stamped: dispatch_stats (MACRUNNER_HB_TRACE_DISPATCH_STATS=1) increments dispatches once
 * per dispatch and blocks by the real retired count, on the legacy path as well as the fast path, so
 * thread_blocks/thread_dispatches is the honest avg_chain. It is printed as avg_chain= there, beside
 * the terminal histogram that gives the ceiling. Duplicating it here bought a wrong second opinion. */
/* ★★★ MacRunner 2026-08-24, КООРДИНАТОР — ОСНОВАНИЕ ОКНА ДОЛЖНО ОТВЕЧАТЬ ТЕКУЩЕЙ ПАМЯТИ.
 *
 * `ctx->guest32_base` — то, что выпущенный i386-код прибавляет к 32-битному адресу
 * (`emit_x86_ea_to_host` = UXTW(EA) + ctx->guest32_base). Окно заводится НА КАЖДЫЙ
 * объект hb_memory_t (`hb_memory.c:2641`), а `ctx->memory` присваивается прямым полем
 * из полудюжины мест — общей точки, где можно было бы обновить основание, НЕТ.
 *
 * Отсюда дефект: контекст пережил смену памяти и продолжал прибавлять СТАРОЕ окно.
 * Поймано на приёмке через lldb:
 *     EXC_BAD_ACCESS (code=2, address=0xb0050006f), _platform_memmove+448
 * при том, что прибор PERM_AUDIT видел ту же ячейку по 0xc0050006f — то есть
 *     0xb00000000 + 0x50006f   против   0xc00000000 + 0x50006f
 * Ограждение `sigsetjmp` ловило эти промахи и уводило на mach-путь, где адрес считается
 * заново от region->host_base, — поэтому со снятым ограждением дефект вылезал наружу,
 * а с ограждением был невидим ГОДАМИ.
 *
 * Инвариант делаем самоподдерживающимся на входе в исполнение: два чтения и сравнение
 * на серию блоков, а не на блок. */
static inline void hb_sync_guest32_base(hb_context_t* ctx) {
    if (!ctx || ctx->arch != HB_ARCH_X86 || !ctx->memory) return;
    {
        uint64_t now = (uint64_t)(uintptr_t)hb_memory_guest32_base(ctx->memory);
        if (now && now != ctx->guest32_base) {
            if (ctx->guest32_base) {
                static int said;
                if (said++ < 8) {
                    fprintf(stderr, "macrunner-hb-guest32-base-СМЕНА: было=0x%llx стало=0x%llx\n",
                            (unsigned long long)ctx->guest32_base, (unsigned long long)now);
                    fflush(stderr);
                }
            }
            ctx->guest32_base = now;
            /* Карта прав живёт в том же окне и обновляется теми же вызовами, что и
            * регионы, поэтому её адрес берётся здесь же — одним местом с базой окна. */
            /* СМЕЩЁННЫЙ указатель: проверка прав получает адрес уже хозяйским,
             * см. разбор у hb_memory_perm_map_host_biased. */
            ctx->perm_map_ptr = hb_memory_perm_map_host_biased(ctx->memory);
        }
    }
}

/* ★★★ 06.09.2026, лейн ПРОФИЛЬ — ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ ПРОФИЛЯ. Балласт.
 *
 * Прибор, о котором НЕ доказано, что он умеет ошибиться, — не прибор. Профиль
 * `sample(1)` + классификатор относит выборки по категориям; чтобы этому отнесению
 * можно было верить, нужна нагрузка ЗАВЕДОМОГО размера в ЗАВЕДОМОЙ категории —
 * и проверка, что профиль нашёл её ТАМ и в ПРАВИЛЬНОЙ ДОЛЕ.
 *
 * Устройство: пустой цикл известной длины на входе в диспетчер, с собственным
 * замером времени (mach_absolute_time вокруг тела) и счётчиком вызовов. Итог
 * печатается на выходе процесса. Тогда есть ДВА независимых числа:
 *     доля балласта по профилю   (выборки в кадре macrunner_profil_ballast)
 *     доля балласта по часам     (накопленные наносекунды / занятое время потока)
 * Их совпадение и есть доказательство прибора; расхождение — его опровержение.
 *
 * По умолчанию гейт пуст, функция не зовётся, выпуск не меняется: MACRUNNER_PROFIL_BALLAST
 * задаёт число итераций на вход в диспетчер, 0 или отсутствие = выключено.
 * noinline — обязателен: слитый в вызывающего балласт не получит своего кадра в профиле
 * и «не найдётся» по причине, не имеющей отношения к классификатору. */
static unsigned long long g_ballast_calls;
static unsigned long long g_ballast_ticks;
static unsigned long long g_ballast_sink;

/* ПЕРИОДИЧЕСКАЯ печать нужна, чтобы сверять долю НА ОКНЕ СЪЁМКИ, а не на всём прогоне:
 * профиль снят за 20-25 с в середине, а итог на выходе относится ко всему процессу.
 * Печатается стенное время (gettimeofday), чтобы совместить с моментом снимка. */
__attribute__((noinline)) static void macrunner_profil_ballast(unsigned n)
{
    uint64_t t0 = mach_absolute_time();
    volatile unsigned long long acc = 0;
    for (unsigned i = 0; i < n; i++) acc += i ^ (acc >> 3);
    __atomic_add_fetch(&g_ballast_sink, (unsigned long long)acc, __ATOMIC_RELAXED);
    { unsigned long long t = __atomic_add_fetch(&g_ballast_ticks, mach_absolute_time() - t0,
                                                __ATOMIC_RELAXED);
      unsigned long long c = __atomic_add_fetch(&g_ballast_calls, 1, __ATOMIC_RELAXED);
      if ((c & 0xFFFFu) == 0) {
          mach_timebase_info_data_t tb; mach_timebase_info(&tb);
          struct timeval tv; gettimeofday(&tv, NULL);
          fprintf(stderr, "macrunner-profil-ballast-tick: epoch=%ld.%06d вызовов=%llu время_мс=%.3f\n",
                  (long)tv.tv_sec, (int)tv.tv_usec, c,
                  (double)t * tb.numer / (tb.denom ? tb.denom : 1) / 1e6);
          fflush(stderr);
      }
    }
}

static void macrunner_profil_ballast_svodka(void)
{
    unsigned long long c = __atomic_load_n(&g_ballast_calls, __ATOMIC_RELAXED);
    unsigned long long t = __atomic_load_n(&g_ballast_ticks, __ATOMIC_RELAXED);
    mach_timebase_info_data_t tb; mach_timebase_info(&tb);
    double ns = (double)t * tb.numer / (tb.denom ? tb.denom : 1);
    fprintf(stderr, "macrunner-profil-ballast: вызовов=%llu время_нс=%.0f время_мс=%.3f "
                    "на_вызов_нс=%.1f\n", c, ns, ns / 1e6, c ? ns / c : 0.0);
    fflush(stderr);
}

static unsigned macrunner_profil_ballast_n(void)
{
    static int gotov = 0;
    static unsigned n = 0;
    if (!gotov) {
        const char* v = getenv("MACRUNNER_PROFIL_BALLAST");
        n = (v && *v) ? (unsigned)strtoul(v, NULL, 0) : 0u;
        if (n) {
            atexit(macrunner_profil_ballast_svodka);
            fprintf(stderr, "macrunner-profil-ballast: ВКЛЮЧЁН n=%u итераций на вход в диспетчер\n", n);
            fflush(stderr);
        }
        gotov = 1;
    }
    return n;
}

hb_result_t hb_jit_runtime_run(hb_jit_runtime_t* rt, const hb_ir_func_t* func, hb_exec_result_t* out) {
    { unsigned _b = macrunner_profil_ballast_n(); if (_b) macrunner_profil_ballast(_b); }
    /* ★ 07.09.2026, лейн ПОВТОР-3 — ЗАПИСЬ. Ставится ВЫШЕ ветки на legacy, потому
     * что ряд входов обязан быть непрерывным: разрыв в нём читается повтором как
     * «проскочили записанное место». Стоимость при выключенном гейте — две
     * загрузки статики (hb_record.c). */
    if (rt && rt->ctx) hb_record_enter(rt->ctx, rt->ctx->pc);
    if (rt) hb_sync_guest32_base(rt->ctx);
    if (rt && func) { rt->cur_func_addr = func->guest_addr; rt->cur_func_len = func->guest_len; }
    /* Порог разогрева считается здесь: через эту точку проходит КАЖДЫЙ вход в диспетчер,
     * в отличие от зондов, один из которых лежит на редкой ветви. */
    __atomic_add_fetch(&g_dispatch_ticks, 1, __ATOMIC_RELAXED);

    /* По архитектуре ГОСТЯ — см. runtime_block_chain_enabled_for. */
    int block_chain = runtime_block_chain_enabled_for(rt && rt->ctx ? rt->ctx->arch
                                                                  : HB_ARCH_X64);
    int single_lookup_gate = runtime_single_lookup_enabled();
    int indirect_ic_gate = runtime_indirect_ic_enabled();
    int dispatch_stats_gate = trace_dispatch_stats_enabled();
    static int dispatch_gate_trace_count;
    if (dispatch_gate_trace_count < 16 && trace_dispatch_gate_enabled()) {
        dispatch_gate_trace_count++;
        fprintf(stderr,
                "macrunner-hb-dispatch-gate: block_chain=%d single_lookup=%d "
                "indirect_ic=%d dispatch_stats=%d legacy=%d\n",
                block_chain, single_lookup_gate, indirect_ic_gate, dispatch_stats_gate,
                (!block_chain && !single_lookup_gate && !indirect_ic_gate));
        fflush(stderr);
    }
    if (!block_chain && !single_lookup_gate && !indirect_ic_gate)
        return hb_jit_runtime_run_legacy(rt, func, out);

    if (!rt || !func || !func->cfg || !out) {
        /* MacRunner 2026-08-27, Diablo — ЧТО ИМЕННО ПУСТО.
         *
         * Замер: на pc=0x778590a6 возврат INVALID_ARG останавливает игру ровно на
         * предпоследнем шаге эталонного пути DirectDraw (эталон CrossOver после
         * SetDisplayMode делает CreateSurface, мы — нет). Условий четыре, по коду
         * возврата их не различить. */
        fprintf(stderr, "macrunner-hb-jitrun-пусто: rt=%p func=%p cfg=%p out=%p\n",
                (void*)rt, (void*)func, func ? (void*)func->cfg : NULL, (void*)out);
        fflush(stderr);
        return HB_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(hb_exec_result_t));

    hb_context_t* ctx = rt->ctx;
    uint64_t steps = 0;
    uint64_t blocks_executed = 0;
    bool chain_accounting = block_chain != 0;
    /* ★★★★★ MacRunner 2026-08-25 — СЦЕПЛЕНИЕ ПРИ НЕНУЛЕВОМ ПРЕДЕЛЕ ШАГОВ.
     *
     * Прежнее условие требовало `step_limit == 0`, и это выключало сцепление ВСЕГДА: предел
     * шагов по умолчанию 10 000 000 для x86 (hb_context.c:27), нулём он не бывает. Признак в
     * журнале — `site_patch_off=21205053` как ЕДИНСТВЕННАЯ причина отказа и `avg_chain=1.0000`.
     * Гейт `MACRUNNER_HB_BLOCK_CHAIN=1` этого не менял, поэтому механизм годами считался
     * бесполезным, хотя просто не включался.
     *
     * Запрет был по существу: сцепленные блоки идут ДРУГ В ДРУГА, не возвращаясь в этот цикл,
     * поэтому счётчик шагов между возвратами не растёт и предел соблюдается НЕТОЧНО.
     *
     * Но неточность мала и измерена: `avg_chain = 3,0468`, то есть в среднем три блока между
     * возвратами. Для защиты ОТ ЗАВИСАНИЯ (бесконечный цикл в госте) погрешность в единицы
     * блоков несущественна — предел всё равно сработает, просто чуть позже.
     *
     * Цена вопроса: со снятым пределом сцепление даёт −23,09 % времени (6 пар из 6, разброс
     * 2,21 %), диспетчеризаций 31 486 782 → 10 334 551, косвенных переходов 10 201 166 → 355.
     *
     * Гейт `MACRUNNER_HB_CHAIN_WITH_LIMIT`, умолчание ВЫКЛЮЧЕНО: точность предела меняется,
     * и это должно быть осознанным выбором, а не побочным следствием. */
    /* ★★★★★ ЗДЕСЬ ЛЕЖИТ −23,09 %, И ОНО ПОКА НЕДОСТУПНО В РАБОТЕ.
     *
     * Условие требует `step_limit == 0`, а умолчание предела шагов для x86 —
     * 10 000 000 (hb_context.c:27). Значит сцепление выключено ВСЕГДА, и
     * `MACRUNNER_HB_BLOCK_CHAIN=1` этого не меняет: в журнале
     * `site_patch_off` остаётся единственной причиной отказа, `avg_chain=1.0000`.
     *
     * Со снятым пределом (`MACRUNNER_HB_X86_STEP_LIMIT=0`) механизм оживает:
     *     avg_chain          1.0000 → 3.0468
     *     диспетчеризаций 31 486 782 → 10 334 551
     *     косвенных jmp   10 201 166 → 355
     *     ВРЕМЯ                       −23,09 %   (6 пар из 6, разброс 2,21 %)
     *
     * ★ Почему условие нельзя просто ослабить (проверено 25.08): сцепленные блоки идут
     * друг в друга, не возвращаясь в этот цикл, поэтому счётчик шагов между возвратами не
     * растёт и предел НЕ СРАБАТЫВАЕТ ВОВСЕ — прогон висит до внешнего таймаута (exit=124).
     * Запрет обратных рёбер (`CHAIN_FORWARD_ONLY=1`) от зависания не спасает и попутно
     * гасит само сцепление: весь выигрыш дают именно циклы, а они идут назад.
     *
     * Нужен сторож, который НЕ опирается на счётчик шагов диспетчера: например, проверка
     * времени или числа сцеплённых переходов внутри самой цепочки, у точки входа в блок.
     * Пока такого сторожа нет, условие оставлено прежним. */
    /* СВЯЗКА СНЯТА. Требование «предела нет» стояло здесь потому, что предел
     * действовал только между блоками, а сцеплённые блоки в диспетчер не
     * возвращаются. Теперь предел выражен сроком и соблюдается ВНУТРИ
     * выпущенного кода (emit_srok_vyhod), поэтому сцепление и предел
     * совместимы. */
    bool chain_patch_enabled = chain_accounting;
    bool single_lookup = single_lookup_gate != 0;
    bool indirect_ic_enabled = indirect_ic_gate;   /* та же снятая связка */
    bool dispatch_fastpath = chain_accounting || single_lookup || indirect_ic_enabled;
    bool dispatch_stats_enabled_run = dispatch_stats_gate != 0;
    ctx->last_result = HB_OK;
    if (dispatch_stats_enabled_run)
        dispatch_stats_register();
    if (!indirect_ic_enabled) {
        ctx->indirect_ic_guest_addr = 0;
        ctx->indirect_ic_native_code = 0;
    }

    while (1) {
        /* ═══ СРОК: предел прогона в шкале накопительного счётчика ═══
         *
         * Предел задан в местных steps/blocks_executed, а выпущенный код ведёт
         * ctx->step_count/block_count. Перевод делается здесь — там, где обе
         * величины известны. Ноль предела и уже исчерпанный бюджет дают
         * UINT64_MAX («срока нет»): в первом случае предела действительно нет,
         * во втором сработает проверка диспетчера ниже по циклу.
         *
         * Пересчёт каждый круг, а не однократно перед циклом: это дешевле, чем
         * доказывать, что местный счётчик и счётчик контекста нигде не
         * расходятся (интерпретаторный путь ведёт их по-разному). */
        ctx->step_deadline = (ctx->step_limit > steps)
                             ? ctx->step_count + (ctx->step_limit - steps)
                             : UINT64_MAX;
        ctx->block_deadline = (ctx->block_limit > blocks_executed)
                              ? ctx->block_count + (ctx->block_limit - blocks_executed)
                              : UINT64_MAX;
        /* ★ 04.09.2026 — ПРИБОР ГОСТЕВЫХ СЛОВ. Вершина цикла — ЕДИНСТВЕННОЕ узкое
         * место, через которое проходит КАЖДЫЙ переход гостя: и вход в блок, и
         * возврат из сцепленной цепочки. Выключенный прибор стоит одного сравнения. */
        chain_slot_probe(ctx);
        /* ★★★ 2026-08-18, лейн ЛЕСТНИЦА, итерация 2379 (приказ владельца 185) —
         * СЛЕДИЛКА ABZU УБРАНА (копия 2 из 2).
         *
         * Наблюдатель контрольного потока ABZU/UE4 с двадцатью жёсткими адресами ОДНОЙ сборки
         * (0x140145ec8 … 0x14014607b, 0x14057fd10 и родня). Находки записаны; в другой
         * раскладке эти адреса не значат ничего. Стоял за гейтом, то есть на горячем пути
         * стоил проверки флага на каждом обороте цикла исполнения блоков.
         *
         * Границы куска считаны ПО СКОБКАМ от известной точки: 2378 показал, чем кончается
         * поиск ключевого слова назад — вырезанными 25 КБ чужого кода. */
        if (ctx->step_limit > 0 && steps >= ctx->step_limit) {
            out->result = HB_ERR_STEP_LIMIT;
            out->steps_executed = steps;
            out->blocks_executed = blocks_executed;
            return HB_OK;
        }
        if (ctx->block_limit > 0 && blocks_executed >= ctx->block_limit) {
            return set_runtime_fault_result(out, ctx, HB_ERR_BLOCK_LIMIT, steps,
                                            blocks_executed, "block limit reached");
        }

        hb_block_cache_entry_t* cached = NULL;
        hb_ir_block_t* block = NULL;
        bool smc_evicted = false;
        if (dispatch_fastpath) {
            cached = block_cache_find(rt->block_cache, ctx->pc);
            /* SMC reverify BEFORE borrowing cached->block: an eviction destroys
             * the owned block, so borrowing must happen after (or not at all). */
            cached = smc_reverify_entry(rt, cached, &smc_evicted);
            if (cached && cached->block)
                block = (hb_ir_block_t*)cached->block;
        }
        if (smc_evicted && smc_relift_should_exit(steps)) {
            /* Guest bytes changed under this translation: the caller's lifted IR is
             * stale too.  Exit so it re-lifts from current bytes (see the SMC re-lift
             * gate comment at smc_reverify_entry). */
            out->result = HB_OK;
            out->steps_executed = steps;
            out->blocks_executed = blocks_executed;
            return HB_OK;
        }
        if (!block)
            block = find_block(func->cfg, ctx->pc);
        if (!block) {
            if (func->truncated) {
                return set_runtime_fault_result(out, ctx, HB_ERR_TRANSLATION_TRUNCATED,
                                                steps, blocks_executed,
                                                "translated function truncated before current PC");
            }
            out->result = HB_OK;
            out->steps_executed = steps;
            out->blocks_executed = blocks_executed;
            t_runexit[RUNEXIT_NO_BLOCK]++;
            hb_xborder_note(rt, ctx->pc, 0);   /* к ХОСТУ или в гостевой код — см. hb_xborder_note */
            hb_record_exit(ctx, ctx->pc, 0);   /* ★ ПОВТОР-3 — запись выхода наружу */
            /* ★ 04.09.2026 — ВЫХОД НА ПЕРЕХОДНИК ИМПОРТА: по цепочке или нет.
             * Это ровно тот выход, через который прогон со сцеплением x64 уходит
             * умирать (`reason=import-thunk`). Печатаем свидетеля последнего захода
             * в выпущенный код: delta>1 значит, что до переходника доехали ПО СШИТЫМ
             * рёбрам, delta==1 — что последний блок вызвал диспетчер. Печать
             * ограничена, но первые восемь случаев видны всегда. */
            if (runtime_block_chain_enabled_for(ctx->arch) &&
                chain_target_is_import_thunk(rt, ctx->pc)) {
                static uint64_t n_thunk_exit;
                uint64_t n = __atomic_add_fetch(&n_thunk_exit, 1, __ATOMIC_RELAXED);
                if (n <= 8 || (n & (n - 1)) == 0) {
                    fprintf(stderr, "macrunner-hb-chain-thunk-exit: n=%llu pc=0x%llx "
                            "последний_заход=0x%llx блоков_за_заход=%llu\n",
                            (unsigned long long)n, (unsigned long long)ctx->pc,
                            (unsigned long long)t_last_run_entry,
                            (unsigned long long)t_last_run_delta);
                    fflush(stderr);
                }
            }
            return HB_OK; /* No block for PC — function exit or external call */
        }

        if (!chain_accounting) blocks_executed++;

        /* Check in-memory block cache */
        if (!cached)
            cached = block_cache_find(rt->block_cache, ctx->pc);
        /* Non-fastpath resolves block from the CFG (not the entry), so reverify
         * here is borrow-safe; fastpath already reverified above. */
        if (!dispatch_fastpath) {
            cached = smc_reverify_entry(rt, cached, &smc_evicted);
            if (smc_evicted && smc_relift_should_exit(steps)) {
                out->result = HB_OK;
                out->steps_executed = steps;
                out->blocks_executed = blocks_executed;
                return HB_OK;
            }
        }
        uint64_t run_block_delta = 1;
        if (cached) {
            if (trace_jit_block_contains_guest(block, trace_jit_guest_addr())) {
                trace_unity_sort_promote("cache-hit-watch", block, NULL, NULL, NULL,
                                         ctx->mode == HB_MODE_64BIT ? ctx->regs.x64.rbp : 0);
            }
            if (block && ((block->instr_count == 7 &&
                           block->instrs[block->instr_count - 1].op == HB_IR_CALL) ||
                          (block->instr_count == 2 &&
                           block->instrs[block->instr_count - 1].op == HB_IR_Jcc))) {
                trace_unity_sort_promote("cache-hit-gate", block, NULL, NULL, NULL,
                                         ctx->mode == HB_MODE_64BIT ? ctx->regs.x64.rbp : 0);
            }
            if (should_retry_cached_promotion(cached)) {
                const hb_ir_block_t* stable_block = cached->block ? cached->block : block;
                try_promote_hot_block_families(rt, ctx, stable_block);
                cached = block_cache_find(rt->block_cache, ctx->pc);
                if (!cached) {
                    /* MacRunner FIX#2a: non-latching (live block_cache_is_full gates). */
                    trace_jit_code_cache_full_once(rt, "block-cache-promote-lost-entry", 0);
                    return set_jit_interp_fallback_result(out, HB_ERR_UNSUPPORTED_FEATURE,
                                                          steps, blocks_executed,
                                                          "JIT block cache lost promoted entry; interpreter fallback");
                }
            }
            if (cached->block)
                block = (hb_ir_block_t*)cached->block;
            trace_jit_cached_watch_block_once(rt, cached);
            bool native_accounting = chain_accounting && entry_has_chain_slot(cached, NULL);
            uint64_t before_steps = native_accounting ? ctx->step_count : 0;
            uint64_t before_blocks = native_accounting ? ctx->block_count : 0;
            uint64_t before_rcx = ctx->regs.x64.rcx;
            uint64_t before_rdx = ctx->regs.x64.rdx;
            uint64_t before_rbp = ctx->regs.x64.rbp;
            uint64_t before_rsp = ctx->regs.x64.rsp;
            /* Whole GPR file, so the violation print can say WHICH registers a chained transition
             * loses rather than only the three that an earlier hypothesis happened to name. rax..r15
             * are 16 contiguous uint64_t in hb_regs_x64_t (rip and rflags follow), so one copy takes
             * them all; the static assert keeps that true if the struct is ever reordered. */
            uint64_t before_gpr[HB_TRACE_GPR_N];
            _Static_assert(offsetof(hb_regs_x64_t, r15) - offsetof(hb_regs_x64_t, rax) ==
                               (HB_TRACE_GPR_N - 1) * sizeof(uint64_t),
                           "guest GPRs are no longer 16 contiguous words -- fix before_gpr");
            /* 05.09.2026: копия 128 Б — ТОЛЬКО под прибором, который её читает
             * (trace_chain_transition возвращается первой строкой без гейта). До этого
             * платилась на каждой диспетчеризации ради выключенного прибора. */
            if (trace_chain_edge_enabled())
                memcpy(before_gpr, &ctx->regs.x64.rax, sizeof before_gpr);
            /* Entry-state probe for ONE guest block, so the same line can be compared with chaining on and
             * off. The chained arm shows rcx/rdx arriving as f0e0993f/320eec31 — the exact values the fault
             * reports — and this says what they are when the block is reached the ordinary way. */
            /* 2026-08-01 — ALL-BLOCKS mode. The single-address form caught only FOUR entries in a
             * 900 s run (two threads, twice each), which is far too few to locate a first divergence:
             * the differential needs the block to be entered many times, and this one is not hot.
             *
             * When MACRUNNER_HB_CHAIN_EDGE_NEAR is 0/unset the filter is dropped and every dispatched
             * block is recorded. Alignment between the two arms is NOT by the global sequence number
             * -- chaining changes how many dispatcher entries there are, which is the whole point of
             * it -- but by (guest_addr, k-th occurrence of that address), which the comparison script
             * does. So the emitted line only needs the address and a global index. */
            __atomic_add_fetch(&g_dispatch_ticks, 1, __ATOMIC_RELAXED);
            if (trace_chain_edge_enabled() &&
                (runtime_chain_edge_near() == 0 ||
                 cached->guest_addr == runtime_chain_edge_near())) {
                static uint64_t seen;
                /* Full GPR file and a high cap, because this probe is now one half of a
                 * DIFFERENTIAL: the same guest block is entered in a chained run and an unchained
                 * one, and the first sequence number whose registers disagree names the exact
                 * point where chaining departs from correct execution.
                 *
                 * Four registers and a cap of 8 could not do that. Register deltas across a
                 * transition are dominated by legitimate guest work -- 8-9 of 16 change per
                 * chained transition -- so nothing short of the whole file compared against the
                 * unchained baseline separates corruption from ordinary execution. */
                uint64_t n_ = __atomic_add_fetch(&seen, 1, __ATOMIC_RELAXED);
                if (n_ <= 200000) {  /* all-blocks mode needs a much larger budget */
                    const uint64_t* g = &ctx->regs.x64.rax;
                    unsigned gi;
                    fprintf(stderr, "macrunner-hb-blockentry: n=%llu phase=%d guest=0x%llx",
                            (unsigned long long)n_, chain_warmup_passed() ? 1 : 0,
                                (unsigned long long)cached->guest_addr);
                    for (gi = 0; gi < HB_TRACE_GPR_N; gi++)
                        fprintf(stderr, " %s=%llx", hb_trace_gpr_names[gi],
                                (unsigned long long)g[gi]);
                    fprintf(stderr, "\n");
                    fflush(stderr);
                }
            }
            unsigned long long mr_dc_t0 = mr_dc_before();
            /* ★ 27.08: тот же stable_block, что вычисляют строки выше, но в области
             * видимости вызова: там он объявлен во вложенном блоке. */
            const hb_ir_block_t* guard_stable = (cached && cached->block)
                                                ? cached->block
                                                : (func && func->cfg ? find_block(func->cfg, ctx->pc) : NULL);
            hb_result_t run_result = run_jit_block_with_signal_guard(rt, func, cached, guard_stable, out,
                                                                      steps, blocks_executed);
            mr_dc_after(mr_dc_t0);
            if (run_result != HB_OK || out->faulted) return run_result;
            trace_jit_hot_block_tick(rt, cached);
            if (native_accounting) {
                uint64_t block_delta = ctx->block_count - before_blocks;
                uint64_t step_delta = ctx->step_count - before_steps;
                /* Свидетель для вопроса «дошли ли до переходника по цепочке» — см.
                 * t_last_run_entry. Пишется БЕЗУСЛОВНО, и при block_delta==0 тоже:
                 * иначе «один блок» и «не считалось» слились бы в одно значение. */
                t_last_run_entry = cached->guest_addr;
                t_last_run_delta = block_delta ? block_delta : 1;
                if (block_delta) {
                    run_block_delta = block_delta;
                    blocks_executed += block_delta;
                    steps += step_delta;
                    if (block_delta > 1) {
                        trace_chain_transition(ctx, cached, block_delta, step_delta,
                                               before_rcx, before_rdx, before_rbp, before_rsp,
                                               before_gpr);
                        /* ★★★★★★★ 05.09.2026 — ПРИБОР ПЕРЕИМЕНОВАН, ПОТОМУ ЧТО ВРАЛ ИМЕНЕМ.
                         *
                         * Заводился он как `macrunner-hb-povtor-hvosta` — «цепочка вышла, а pc
                         * стоит на входе прямой единицы, значит её сейчас исполнят ВТОРОЙ РАЗ».
                         * Условие НЕОБХОДИМОЕ, но НЕ ДОСТАТОЧНОЕ, и это стоило отдельного
                         * разбора: ровно то же состояние даёт ЗАКОННЫЙ ПРИХОД — предыдущий
                         * блок цепочки прыгнул на вход прямой единицы, записал pc и вернулся в
                         * диспетчер, а единица ещё не исполнялась ни разу. Прибор эти два
                         * случая не различает ПО ПОСТРОЕНИЮ: и там и там pc равен входу.
                         *
                         * Замер 05.09 на Hollow Knight со сцеплением x64: событий 16 000+ за
                         * прогон, при этом игра доходит до swapchain и утверждение Mono
                         * молчит — то есть это приходы, а не повторы. Читать это число как
                         * «остаток дефекта» было бы ошибкой того же класса, что ложное
                         * совпадение по подстроке.
                         *
                         * ЧЕМ ВОПРОС ЗАКРЫТ ВМЕСТО ЭТОГО: переписью НА ВЫПУСКЕ —
                         * `macrunner-hb-tailpc: прямых_единиц=N из_них_с_pc=N без_pc=0`.
                         * Она отвечает точно и без догадок: если КАЖДАЯ прямая единица
                         * получила запись pc, ни одна из них физически не может оставить pc на
                         * своём входе, и все события ниже — приходы.
                         *
                         * Прибор оставлен: приход в прямую единицу — это ещё и МЕСТО ОБРЫВА
                         * цепочки, то есть материал для следующего шага по avg_chain. */
                        {
                            hb_block_cache_entry_t* tail_e = block_cache_find(rt->block_cache, ctx->pc);
                            if (tail_e && tail_e->block && tail_e->guest_addr == ctx->pc &&
                                tail_e->block->instr_count &&
                                first_control_transfer_instr(tail_e->block) == NULL) {
                                uint64_t nn = __atomic_add_fetch(&g_chain_tail_repeat, 1,
                                                                 __ATOMIC_RELAXED);
                                if (nn == 1 || (nn % 1000) == 0)
                                    fprintf(stderr,
                                            "macrunner-hb-prihod-v-pryamuyu-edinicu: n=%llu pc=0x%llx "
                                            "ot=0x%llx blocks=%llu\n",
                                            (unsigned long long)nn, (unsigned long long)ctx->pc,
                                            (unsigned long long)cached->guest_addr,
                                            (unsigned long long)block_delta);
                            }
                        }
                    }
                    if (dispatch_stats_enabled_run) dispatch_stats_add(1, block_delta, step_delta);
                } else {
                    blocks_executed++;
                    steps += cached->steps;
                    if (dispatch_stats_enabled_run) dispatch_stats_add(1, 1, cached->steps);
                    native_accounting = false;
                }
            } else {
                steps += cached->steps;
                if (chain_accounting) blocks_executed++;
                if (dispatch_stats_enabled_run) dispatch_stats_add(1, 1, cached->steps);
            }
        } else {
            if (rt->code_cache_full || block_cache_is_full(rt->block_cache)) {
                /* MacRunner FIX#2a: do NOT latch code_cache_full here — the block-cache
                 * full state is already re-checked live via block_cache_is_full() in
                 * every JIT guard, so a transient hash-table fill no longer permanently
                 * disables JIT (which it did while the exec buffer was 82% free). The
                 * genuine hard limit (exec buffer full) still latches at jit_commit_blob. */
                trace_jit_code_cache_full_once(rt, "block-cache-full", 0);
                return set_jit_interp_fallback_result(out, HB_ERR_UNSUPPORTED_FEATURE,
                                                      steps, blocks_executed,
                                                      "JIT code cache full; interpreter fallback");
            }

            hb_cache_key_t persistent_key;
            bool have_persistent_key = false;
            bool loaded_from_persistent = false;
            uint8_t* dest = NULL;
            size_t emitted_size = 0;
            hb_result_t r;

            if (rt->persistent_cache &&
                persistent_cache_key_for_block(rt, block, &persistent_key) == HB_OK) {
                hb_cache_entry_t* disk_entry = NULL;
                have_persistent_key = true;
                r = hb_cache_lookup(rt->persistent_cache, &persistent_key, &disk_entry);
                if (r == HB_OK && disk_entry && disk_entry->valid) {
                    const uint8_t* load_code = NULL;
                    uint8_t* owned_load_code = NULL;
                    hb_ir_block_t* load_block = block_clone_for_cache(block);
                    /* 05.09.2026: блоб = код + хвост с картой отказов. Сначала подвал: он
                     * называет длину КОДА; блоб без подвала (или с искалеченным) — не наш,
                     * исполнять его нельзя, блок перекомпилируется. Карта прикрепляется к
                     * записи ПОСЛЕ block_cache_put — до него записи ещё нет. */
                    size_t blob_code_size = 0;
                    bool blob_ok = ripmap_trailer_parse(disk_entry->native_code,
                                                        disk_entry->native_size,
                                                        &blob_code_size, NULL, NULL, NULL, NULL);
                    emitted_size = blob_ok ? blob_code_size : 0;
                    if (blob_ok && load_block &&
                        native_blob_prepare_cache_load(disk_entry->native_code,
                                                       blob_code_size,
                                                       load_block, &load_code,
                                                       &owned_load_code) &&
                        (r = jit_commit_blob(rt, load_code, emitted_size, &dest)) == HB_OK) {
                        cached = block_cache_put(rt, rt->block_cache, ctx->pc, dest, emitted_size,
                                                 disk_entry->steps ? disk_entry->steps
                                                                    : jit_block_step_count(load_block),
                                                 load_block, false, true);
                        if (cached) {
                            ripmap_attach_from_trailer(cached, disk_entry->native_code,
                                                       disk_entry->native_size);
                            load_block = NULL;
                            loaded_from_persistent = true;
                            hb_contract_telemetry_record_cache_hit(emitted_size);
                            /* ★ 06.09 лейн КЕШ: адрес — в перепись, чтобы «подъёмов с диска»
                             * и «различных блоков» стали двумя разными числами. */
                            hb_contract_telemetry_record_hit_pc((uint64_t)ctx->pc);
                        }
                    }
                    free(owned_load_code);
                    if (load_block) hb_ir_block_destroy(load_block);
                } else {
                    hb_contract_telemetry_record_cache_miss();
                }
                hb_cache_entry_free(disk_entry);
            }

            if (!loaded_from_persistent) {
                hb_ir_block_t* compile_block = NULL;
                /* Compile block into codegen buffer */
                hb_codegen_buffer_t* code_buf = hb_codegen_buffer_create(4096);
                if (!code_buf) return HB_ERR_OUT_OF_MEMORY;
                compile_block = block_clone_for_cache(block);
                if (!compile_block) {
                    hb_codegen_buffer_destroy(code_buf);
                    return HB_ERR_OUT_OF_MEMORY;
                }

                hb_arm64_codegen_t* cg = hb_arm64_codegen_create(ctx);
                if (!cg) {
                    hb_ir_block_destroy(compile_block);
                    hb_codegen_buffer_destroy(code_buf);
                    return HB_ERR_OUT_OF_MEMORY;
                }

                r = hb_arm64_codegen_block_with_cfg(cg, compile_block, func->cfg, code_buf);
                hb_arm64_codegen_destroy(cg);
                if (r == HB_OK && hb_codegen_should_fail_now()) r = HB_ERR_UNSUPPORTED_OPCODE;
                if (r != HB_OK) {
                    codegen_fail_note(compile_block, r);
                    hb_ir_block_destroy(compile_block);
                    hb_codegen_buffer_destroy(code_buf);
                        return hb_codegen_fail_to_interp(ctx, func, block, out,
                                                         steps, blocks_executed);
                    out->result = r;
                    out->steps_executed = steps;
                    out->blocks_executed = blocks_executed;
                    out->faulted = true;
                    out->fault_reason = "JIT codegen failed";
                    return HB_OK;
                }

                emitted_size = code_buf->size;
                r = jit_commit_blob(rt, code_buf->code, emitted_size, &dest);
                if (r != HB_OK) {
                    hb_ir_block_destroy(compile_block);
                    hb_codegen_buffer_destroy(code_buf);
                    return set_jit_interp_fallback_result(out, HB_ERR_UNSUPPORTED_FEATURE,
                                                          steps, blocks_executed,
                                                          "JIT code cache full; interpreter fallback");
                }
                hb_contract_telemetry_record_compile();
                hb_contract_telemetry_record_compile_pc((uint64_t)ctx->pc);
                /* Measure the relocation table before anything depends on it. */
                hb_contract_telemetry_record_reloc((unsigned long)code_buf->reloc_count,
                                                   code_buf->reloc_overflow ? 1 : 0);

                if (rt->persistent_cache && have_persistent_key &&
                    code_buf->code && code_buf->size) {
                    const uint8_t* store_code = NULL;
                    uint8_t* owned_store_code = NULL;
                    hb_cache_entry_t metadata;
                    if (native_blob_prepare_cache_store(code_buf, code_buf->code, code_buf->size,
                                                        compile_block, &store_code,
                                                        &owned_store_code)) {
                        uint8_t* blob = NULL;
                        size_t blob_size = 0;
                        memset(&metadata, 0, sizeof(metadata));
                        metadata.steps = jit_block_step_count(compile_block);
                        /* 05.09.2026: в кеш уходит код + хвост с картой отказов; без хвоста
                         * блок с диска не имел бы точного возобновления после отказа. */
                        if (ripmap_trailer_append(store_code, code_buf->size, code_buf,
                                                  &blob, &blob_size)) {
                            r = hb_cache_store(rt->persistent_cache, &persistent_key, blob,
                                               blob_size, &metadata);
                            if (r == HB_OK) {
                                hb_contract_telemetry_record_cache_store(code_buf->size);
                            }
                            free(blob);
                        }
                        free(owned_store_code);
                    } else {
                        /* Attribute the skip: >1 helper call is the structural restriction in
                         * native_blob_single_arg_helper_stub; anything else is a single stub
                         * whose shape was not recognised. See native_blob_helper_call_count.
                         *
                         * Skipped entirely in table-driven mode: the mh_* reasons describe the
                         * old matcher, which did not run, and re-deriving them here would both
                         * cost a scan and put numbers in the log that mean nothing. The rl_*
                         * counters carry the attribution instead. */
                        if (1) {
                            /* уже учтено в native_blob_prepare_cache_store */
                        } else if (native_blob_helper_call_count(code_buf->code, code_buf->size) > 1) {
                            hb_contract_telemetry_record_cache_store_skip_multi();
                            {   /* re-derive the reason for attribution only */
                                hb_cached_helper_stub_t why[HB_MULTI_HELPER_MAX];
                                size_t whyn = 0; hb_mh_reason_t r = HB_MH_OK;
                                (void)native_blob_helper_stubs(code_buf->code, code_buf->size,
                                                               compile_block, false, why, &whyn, &r);
                                hb_contract_telemetry_record_mh_reason((int)r);
                            }
                        }
                        else
                            hb_contract_telemetry_record_cache_store_skip_unmatched();
                        hb_contract_telemetry_record_cache_store_skip();
                    }
                } else if (rt->persistent_cache && have_persistent_key) {
                    hb_contract_telemetry_record_cache_store_skip();
                }
                /* Store in block cache */
                cached = block_cache_put(rt, rt->block_cache, ctx->pc, dest, emitted_size,
                                         jit_block_step_count(compile_block), compile_block,
                                         false, true);
                /* ★★★★★ MacRunner 2026-09-04 — ЧТЕНИЕ ОСВОБОЖДЁННОГО БУФЕРА.
                 * `hb_codegen_buffer_destroy(code_buf)` стояло ВЫШЕ этой строки (оно делает
                 * free(buf), hb_jit.c:570), а `ripmap_attach` читает из `code_buf` поля
                 * host_off/host_instr/host_off_count — то есть карта копировалась из УЖЕ
                 * ОСВОБОЖДЁННОЙ памяти. Не падало единственно потому, что attach выходил по
                 * гейту РАНЬШЕ, чем трогал буфер; с MACRUNNER_HB_RIPMAP=1 или
                 * MACRUNNER_HB_NO_SNAPSHOT=1 это чтение происходило на КАЖДОМ переведённом
                 * блоке — вот почему у обоих гейтов не могло быть верного замера.
                 * Порядок закреплён: копия карты, и только потом освобождение буфера. */
                ripmap_attach(cached, code_buf);
                hb_codegen_buffer_destroy(code_buf);
                if (!cached) {
                    hb_ir_block_destroy(compile_block);
                    /* MacRunner FIX#2a: non-latching (live block_cache_is_full gates). */
                    trace_jit_code_cache_full_once(rt, "block-cache-put-failed", emitted_size);
                }
                trace_jit_block(ctx->pc, dest, emitted_size, block);
            } else if (trace_jit_blocks_enabled()) {
                fprintf(stderr, "macrunner-hb-translation-cache-hit: guest=%p native=%p-%p size=%zu\n",
                        (void*)(uintptr_t)ctx->pc, dest, dest + emitted_size, emitted_size);
                fflush(stderr);
            }

            if (!cached) {
                rt->code_cache_full = true;
                trace_jit_code_cache_full_once(rt, "block-cache-put-failed", emitted_size);
                return set_jit_interp_fallback_result(out, HB_ERR_UNSUPPORTED_FEATURE,
                                                      steps, blocks_executed,
                                                      "JIT code cache full; interpreter fallback");
            }

            if (!cached->fused) {
                const hb_ir_block_t* stable_block = cached->block ? cached->block : block;
                if (trace_jit_block_contains_guest(stable_block, trace_jit_guest_addr())) {
                    trace_unity_sort_promote("cache-put-watch", stable_block, NULL, NULL, NULL,
                                             ctx->mode == HB_MODE_64BIT ? ctx->regs.x64.rbp : 0);
                }
                if (stable_block && ((stable_block->instr_count == 7 &&
                                       stable_block->instrs[stable_block->instr_count - 1].op == HB_IR_CALL) ||
                                      (stable_block->instr_count == 2 &&
                                       stable_block->instrs[stable_block->instr_count - 1].op == HB_IR_Jcc))) {
                    trace_unity_sort_promote("cache-put-gate", stable_block, NULL, NULL, NULL,
                                             ctx->mode == HB_MODE_64BIT ? ctx->regs.x64.rbp : 0);
                }
                try_promote_hot_block_families(rt, ctx, stable_block);
                cached = block_cache_find(rt->block_cache, ctx->pc);
                if (!cached) {
                    rt->code_cache_full = true;
                    trace_jit_code_cache_full_once(rt, "block-cache-promote-lost-entry", emitted_size);
                    return set_jit_interp_fallback_result(out, HB_ERR_UNSUPPORTED_FEATURE,
                                                          steps, blocks_executed,
                                                          "JIT block cache lost promoted entry; interpreter fallback");
                }
            }
            if (cached->block)
                block = (hb_ir_block_t*)cached->block;
            trace_jit_cached_watch_block_once(rt, cached);

            /* Execute */
            bool native_accounting = chain_accounting && entry_has_chain_slot(cached, NULL);
            uint64_t before_steps = native_accounting ? ctx->step_count : 0;
            uint64_t before_blocks = native_accounting ? ctx->block_count : 0;
            uint64_t before_rcx = ctx->regs.x64.rcx;
            uint64_t before_rdx = ctx->regs.x64.rdx;
            uint64_t before_rbp = ctx->regs.x64.rbp;
            uint64_t before_rsp = ctx->regs.x64.rsp;
            /* Whole GPR file, so the violation print can say WHICH registers a chained transition
             * loses rather than only the three that an earlier hypothesis happened to name. rax..r15
             * are 16 contiguous uint64_t in hb_regs_x64_t (rip and rflags follow), so one copy takes
             * them all; the static assert keeps that true if the struct is ever reordered. */
            uint64_t before_gpr[HB_TRACE_GPR_N];
            _Static_assert(offsetof(hb_regs_x64_t, r15) - offsetof(hb_regs_x64_t, rax) ==
                               (HB_TRACE_GPR_N - 1) * sizeof(uint64_t),
                           "guest GPRs are no longer 16 contiguous words -- fix before_gpr");
            /* 05.09.2026: копия 128 Б — ТОЛЬКО под прибором, который её читает
             * (trace_chain_transition возвращается первой строкой без гейта). До этого
             * платилась на каждой диспетчеризации ради выключенного прибора. */
            if (trace_chain_edge_enabled())
                memcpy(before_gpr, &ctx->regs.x64.rax, sizeof before_gpr);
            /* Entry-state probe for ONE guest block, so the same line can be compared with chaining on and
             * off. The chained arm shows rcx/rdx arriving as f0e0993f/320eec31 — the exact values the fault
             * reports — and this says what they are when the block is reached the ordinary way. */
            if (trace_chain_edge_enabled() && cached->guest_addr == runtime_chain_edge_near()) {
                static uint64_t seen;
                /* Full GPR file and a high cap, because this probe is now one half of a
                 * DIFFERENTIAL: the same guest block is entered in a chained run and an unchained
                 * one, and the first sequence number whose registers disagree names the exact
                 * point where chaining departs from correct execution.
                 *
                 * Four registers and a cap of 8 could not do that. Register deltas across a
                 * transition are dominated by legitimate guest work -- 8-9 of 16 change per
                 * chained transition -- so nothing short of the whole file compared against the
                 * unchained baseline separates corruption from ordinary execution. */
                uint64_t n_ = __atomic_add_fetch(&seen, 1, __ATOMIC_RELAXED);
                if (n_ <= 4096) {
                    const uint64_t* g = &ctx->regs.x64.rax;
                    unsigned gi;
                    fprintf(stderr, "macrunner-hb-blockentry: n=%llu phase=%d guest=0x%llx",
                            (unsigned long long)n_, chain_warmup_passed() ? 1 : 0,
                                (unsigned long long)cached->guest_addr);
                    for (gi = 0; gi < HB_TRACE_GPR_N; gi++)
                        fprintf(stderr, " %s=%llx", hb_trace_gpr_names[gi],
                                (unsigned long long)g[gi]);
                    fprintf(stderr, "\n");
                    fflush(stderr);
                }
            }
            unsigned long long mr_dc_t0 = mr_dc_before();
            /* ★ 27.08: тот же stable_block, что вычисляют строки выше, но в области
             * видимости вызова: там он объявлен во вложенном блоке. */
            const hb_ir_block_t* guard_stable = (cached && cached->block)
                                                ? cached->block
                                                : (func && func->cfg ? find_block(func->cfg, ctx->pc) : NULL);
            hb_result_t run_result = run_jit_block_with_signal_guard(rt, func, cached, guard_stable, out,
                                                                      steps, blocks_executed);
            mr_dc_after(mr_dc_t0);
            if (run_result != HB_OK || out->faulted) return run_result;
            trace_jit_hot_block_tick(rt, cached);
            if (native_accounting) {
                uint64_t block_delta = ctx->block_count - before_blocks;
                uint64_t step_delta = ctx->step_count - before_steps;
                /* Свидетель для вопроса «дошли ли до переходника по цепочке» — см.
                 * t_last_run_entry. Пишется БЕЗУСЛОВНО, и при block_delta==0 тоже:
                 * иначе «один блок» и «не считалось» слились бы в одно значение. */
                t_last_run_entry = cached->guest_addr;
                t_last_run_delta = block_delta ? block_delta : 1;
                if (block_delta) {
                    run_block_delta = block_delta;
                    blocks_executed += block_delta;
                    steps += step_delta;
                    if (block_delta > 1)
                        trace_chain_transition(ctx, cached, block_delta, step_delta,
                                               before_rcx, before_rdx, before_rbp, before_rsp,
                                               before_gpr);
                    if (dispatch_stats_enabled_run) dispatch_stats_add(1, block_delta, step_delta);
                } else {
                    blocks_executed++;
                    steps += cached->steps ? cached->steps : jit_block_step_count(block);
                    if (dispatch_stats_enabled_run)
                        dispatch_stats_add(1, 1, cached->steps ? cached->steps : jit_block_step_count(block));
                }
            } else {
                steps += cached->steps ? cached->steps : jit_block_step_count(block);
                if (chain_accounting) blocks_executed++;
                if (dispatch_stats_enabled_run)
                    dispatch_stats_add(1, 1, cached->steps ? cached->steps : jit_block_step_count(block));
            }
        }
        tramp_snyat_svidetelya(ctx);
    sync_arch_pc_after_jit_block(ctx);
        trace_x86_low_pc_after_block(ctx, block, steps, blocks_executed);
        if (ctx->last_result != HB_OK) {
            /* ★ 04.09.2026 — ОТКАЗ ПОМОЩНИКА, ЗАМЕЧЕННЫЙ ПОСЛЕ СЦЕПЛЁННОГО ЗАХОДА.
             *
             * Щель сцепления выпускается БЕЗУСЛОВНО (hb_arm64_codegen.c: после
             * выгрузки и синхронизации rip, без проверки last_result), поэтому блок,
             * чей помощник уже поставил отказ, всё равно уходит по сшитому ребру
             * дальше. Без сцепления такой блок возвращался сюда, и отказ становился
             * исключением гостя либо откатом на интерпретатор ПРЯМО ТУТ; со
             * сцеплением следующие блоки исполняются поверх неудавшейся операции.
             *
             * Это единственный из отброшенных кругом путей, который меняет СМЫСЛ, а
             * не учёт, — и он проверяется числом: delta>1 значит, что отказ замечен
             * после захода, исполнившего несколько блоков, то есть блоки ПОСЛЕ
             * отказавшего уже отработали. Ноль отличим от «не считалось»: счётчик
             * общий, печать ограничена. */
            if (run_block_delta > 1) {
                static uint64_t n_late;
                uint64_t n = __atomic_add_fetch(&n_late, 1, __ATOMIC_RELAXED);
                if (n <= 8 || (n & (n - 1)) == 0) {
                    fprintf(stderr, "macrunner-hb-chain-otkaz-posle-cepochki: n=%llu "
                            "rezultat=%d vhod=0x%llx blokov=%llu pc=0x%llx\n",
                            (unsigned long long)n, (int)ctx->last_result,
                            (unsigned long long)t_last_run_entry,
                            (unsigned long long)run_block_delta,
                            (unsigned long long)ctx->pc);
                    fflush(stderr);
                }
            }
            if (trace_jit_helper_fault_enabled()) {
                static int t;
                if (t++ < 8)
                    fprintf(stderr, "macrunner-hb-block-fault-pc: pc=0x%llx last=%d guest_addr=0x%llx\n",
                            (unsigned long long)ctx->pc, (int)ctx->last_result,
                            block ? (unsigned long long)block->guest_addr : 0);
                trace_jit_helper_fault_block(ctx, block);
            }
            /* ★ ПРЕДЕЛ, ЗАМЕЧЕННЫЙ ВНУТРИ ЦЕПОЧКИ, ДОКЛАДЫВАЕТСЯ ТЕМ ЖЕ ПУТЁМ,
             * ЧТО И БЕЗ СЦЕПЛЕНИЯ (05.09.2026). Развилка по РОДУ предела.
             *
             * ШАГ — это ритм, а не отказ. Собственная проверка диспетчера без
             * сцепления делает `out->result = HB_ERR_STEP_LIMIT; return HB_OK` без
             * faulted; выпущенный код (emit_srok_vyhod) ставит ctx->last_result и
             * приходит СЮДА, в путь отказа помощника, где wow64 делал из шаг-срока
             * исключение гостя (i386 умирал c0000001, «результат=STEP_LIMIT(-10)
             * операция=STORE»). Поэтому шаг-срок и здесь возвращает HB_OK без
             * faulted — как диспетчер без сцепления.
             *
             * БЛОК — это отказ. Путь без сцепления докладывает предел блоков через
             * set_runtime_fault_result (faulted=1, r=HB_ERR_BLOCK_LIMIT,
             * ctx->last_result=BLOCK_LIMIT — см. проверку у начала цикла). Прежде
             * внутрицепочечный выход по этому же пределу возвращал HB_OK/faulted=0,
             * и одно событие докладывалось двумя способами по тому, кто его заметил
             * (замер 05.09: гейт=1 давал по block_limit r=HB_OK вместо r=BLOCK_LIMIT).
             * Теперь оба места докладывают ОДИНАКОВО — это тот же принцип, что icount
             * у QEMU (cpu_handle_interrupt): причина выхода по сроку выводится
             * единообразно, замечен ли срок в цикле или внутри блока. */
            if (ctx && ctx->last_result == HB_ERR_BLOCK_LIMIT) {
                return set_runtime_fault_result(out, ctx, HB_ERR_BLOCK_LIMIT, steps,
                                                blocks_executed, "block limit reached");
            }
            if (ctx && ctx->last_result == HB_ERR_STEP_LIMIT) {
                out->result = HB_ERR_STEP_LIMIT;
                out->steps_executed = steps;
                out->blocks_executed = blocks_executed;
                ctx->last_result = HB_OK;
                return HB_OK;
            }
            set_helper_fault_result(out, ctx, steps, blocks_executed);
            return HB_OK;
        }
        if (chain_accounting && run_block_delta > 1) {
            continue;
        }

        /* Determine if we should continue or stop */
        if (block->instr_count == 0) {
            out->result = HB_OK;
            out->steps_executed = steps;
            out->blocks_executed = blocks_executed;
            return HB_OK;
        }

        const hb_ir_instr_t* transfer = first_control_transfer_instr(block);
        const hb_ir_instr_t* last = &block->instrs[block->instr_count - 1];
        /* ЕДИНИЦА, итерация 48. Без слияния «первый переход» и есть завершитель блока.
         * Со слиянием первый переход — условный, а завершает единицу ПОСЛЕДНЯЯ команда
         * (лифтер рвётся ровно на несливаемом переходе). Если оставить первый, то единица,
         * оканчивающаяся на RET, не была бы опознана как возврат, и симуляция пошла бы
         * дальше вместо того, чтобы вернуться вызывающему. Гейт тот же, MERGE_BLOCKS. */
        const hb_ir_instr_t* terminal = merge_blocks_enabled() ? merged_terminal_instr(block)
                                                        : (transfer ? transfer : last);
        if (terminal->op == HB_IR_RET) {
            /* Блок возврата уже в кеше — продолжаем цикл вместо выхода к вызывающему.
             * Если его там нет (возврат в чужой код, в хозяина, в нетранслированное),
             * ведём себя как прежде: наружу. Это и есть предохранитель — никакой
             * догадки о цели, только точное попадание в кеш блоков. */
            if (runtime_indirect_ic_ret_enabled() && dispatch_fastpath) {
                hb_block_cache_entry_t* ret_cached = block_cache_find(rt->block_cache, ctx->pc);
                if (ret_cached && ret_cached->block && ret_cached->valid &&
                    ret_cached->native_code) {
                    if (indirect_ic_enabled) update_indirect_ic(ctx, ret_cached, true);
                    continue;
                }
            }
            t_runexit[RUNEXIT_RET]++;
            out->result = HB_OK;
            out->steps_executed = steps;
            out->blocks_executed = blocks_executed;
            return HB_OK;
        }

        /* For CALL/JMP/Jcc, PC was updated by JIT code; resolve the next block once. */
        hb_block_cache_entry_t* next_cached = NULL;
        hb_ir_block_t* next;
        /* ★★★★★★★ 05.09.2026 — ПЕРЕВОД pc ЕДИНИЦЫ БЕЗ ПЕРЕХОДА ПОДНЯТ СЮДА, ДО ПОИСКА,
         * И ТОЛЬКО ЕСЛИ ЕДИНИЦА pc НЕ ДВИГАЛА.
         *
         * Поиск цели ниже идёт по ctx->pc для ЛЮБОГО завершителя. Для единицы, которая
         * не кончается переходом, это работало лишь потому, что pc оставался на ЕЁ
         * СОБСТВЕННОМ входе: `find_block` возвращал её же, а настоящий перевод делался
         * ниже, в конце цикла. То есть диспетчер ТРЕБОВАЛ, чтобы выпущенный код pc не
         * трогал, — а сцепление требует обратного (цепочка сюда не возвращается, и цель
         * ребра без перехода осталась бы на своём входе, то есть была бы исполнена
         * ВТОРОЙ РАЗ; измерено на Mono: 14 выпущенных байт вместо 10).
         *
         * Условие `ctx->pc == block->guest_addr` — это и есть «единица pc не двигала».
         * Безусловное присваивание ЗАТИРАЛО БЫ адрес, который единица успела выставить
         * сама (интерпретаторный возврат, помощник, дальний переход): замер 05.09 —
         * Hollow Knight гибнет на инициализации kernelbase, 2 прогона из 2 побайтово,
         * до Mono не доходит вовсе. Прежний код тем же условием пользовался НЕЯВНО. */
        const uint64_t seq_next = last->guest_addr + last->guest_len;
        const bool seq_end = !is_control_transfer_op(terminal->op);
        if (seq_end && ctx->pc == block->guest_addr) {
            ctx->pc = seq_next;
            if (ctx->arch == HB_ARCH_X64) ctx->regs.x64.rip = ctx->pc;
            else if (ctx->arch == HB_ARCH_X86) ctx->regs.x86.eip = (uint32_t)ctx->pc;
        }
        if (dispatch_fastpath) {
            next_cached = block_cache_find(rt->block_cache, ctx->pc);
            next = (next_cached && next_cached->block)
                ? (hb_ir_block_t*)next_cached->block
                : find_block(func->cfg, ctx->pc);
        } else {
            next = find_block(func->cfg, ctx->pc);
        }
        if (!next) {
            if (func->truncated) {
                return set_runtime_fault_result(out, ctx, HB_ERR_TRANSLATION_TRUNCATED,
                                                steps, blocks_executed,
                                                "translated function truncated before branch target");
            }
            if (is_control_transfer_op(terminal->op)) {
                out->result = HB_OK;
                out->steps_executed = steps;
                out->blocks_executed = blocks_executed;
                t_runexit[RUNEXIT_EXT_XFER]++;
                hb_xborder_note(rt, ctx->pc, 1);   /* к ХОСТУ или в гостевой код */
                hb_record_exit(ctx, ctx->pc, 1);   /* ★ ПОВТОР-3 — запись выхода наружу */
                return HB_OK; /* External branch/call/return boundary */
            }
            /* Прямой конец переведённого куска: следующей единицы нет — ШТАТНЫЙ выход,
             * тот же, что прежде давал хвост цикла. Но ТОЛЬКО когда pc и есть адрес
             * провала: если единица увела pc куда-то ещё, «цель не найдена» — по-прежнему
             * отказ, и глушить его нельзя. */
            if (seq_end && ctx->pc == seq_next) {
                t_runexit[RUNEXIT_SEQ_END]++;
                out->result = HB_OK;
                out->steps_executed = steps;
                out->blocks_executed = blocks_executed;
                return HB_OK;
            }
            out->result = HB_ERR_NOT_FOUND;
            out->steps_executed = steps;
            out->blocks_executed = blocks_executed;
            out->faulted = true;
            t_runexit[RUNEXIT_NOT_FOUND]++;
            out->fault_reason = "branch target block not found";
            return HB_OK;
        }
        if (terminal->op == HB_IR_JMP || terminal->op == HB_IR_Jcc ||
            terminal->op == HB_IR_CALL || terminal->op == HB_IR_LOOP ||
            terminal->op == HB_IR_JRCXZ) {
            if (chain_accounting) {
                if (!chain_patch_enabled) t_chain_decline[CHAIN_SITE_PATCH_OFF]++;
                else if (!cached || !next_cached) t_chain_decline[CHAIN_SITE_NO_ENTRY]++;
                else t_chain_decline[CHAIN_SITE_CALLED]++;
            }
            if (chain_patch_enabled && cached && next_cached)
                (void)patch_block_tail(rt, cached, next_cached, func);
            if (indirect_ic_enabled &&
                (terminal->op == HB_IR_JMP || terminal->op == HB_IR_CALL) &&
                terminal->src1.type != HB_OP_NONE)
                update_indirect_ic(ctx, next_cached, true);
            /* Continue with the target block */
            continue;
        }

        /* Единица без перехода: pc уже переведён выше, цель найдена — продолжаем ею.
         * Прежде здесь стоял ВТОРОЙ, отдельный перевод pc с повторным поиском; он был
         * единственным местом, где это делалось, и потому его отсутствие на сцепленном
         * ребре ничем не восполнялось. */
        continue;
    }
}


/* ★ итерация 2379: гейт `MACRUNNER_HB_TRACE_JCC57FD` удалён вместе с обеими следилками
 * ABZU — включать ему больше нечего. Границы функции взяты ПО СКОБКАМ, размер куска
 * проверен сторожем (2378: поиск `static` назад вырезал 25 КБ). */
hb_result_t hb_runtime_run(hb_context_t* ctx, const hb_ir_func_t* func, hb_backend_t backend, hb_exec_result_t* out) {
    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — КОНТРОЛЬ ПРИБОРА, не диагностика.
     * Печать fs_base в месте отказа (итерация 74) собралась и развернулась, но в журнал
     * не попала. Прежде чем читать её отсутствие как факт, проверяю сам механизм: эта
     * строка стоит в заведомо исполняемом месте и печатается ПЕРВЫЕ ТРИ раза.
     * Появилась в журнале — печати работают, и молчание fs_base значимо.
     * Не появилась — молчит МЕХАНИЗМ, и все выводы «в журнале нет» недействительны. */
    {
        static int ctrl;
        if (ctrl < 3) {
            ctrl++;
            fprintf(stderr, "macrunner-lestnica-ctrl: hb_runtime_run n=%d backend=%d fs_base=%#llx\n",
                    ctrl, (int)backend, (unsigned long long)(ctx ? ctx->fs_base : 0));
            fflush(stderr);
        }
    }
    if (!ctx || !func || !out) return HB_ERR_INVALID_ARG;

    memset(out, 0, sizeof(hb_exec_result_t));
    switch (backend) {
        case HB_BACKEND_INTERP: {
            hb_interpreter_t* i = hb_interpreter_create(ctx);
            if (!i) return HB_ERR_OUT_OF_MEMORY;
            hb_result_t r = hb_interpreter_run(i, func, out);
            hb_interpreter_destroy(i);
            return r;
        }
        case HB_BACKEND_JIT:
        case HB_BACKEND_AOT: {
            hb_jit_runtime_t* rt = hb_jit_runtime_create(ctx);
            if (!rt) return HB_ERR_OUT_OF_MEMORY;
            hb_result_t r = hb_jit_runtime_run(rt, func, out);
            hb_jit_runtime_destroy(rt);
            return r;
        }
    }
    /* MacRunner 2026-08-27, Diablo — НЕИЗВЕСТНЫЙ BACKEND.
     *
     * Сюда попадают, когда значение backend не совпало ни с одним случаем switch.
     * Замер: на pc=0x778590a6 возврат отсюда даёт INVALID_ARG при block_res=0 и
     * faulted=0 (memset выше уже отработал) и останавливает Diablo ровно на
     * предпоследнем шаге эталонного пути DirectDraw. Печатаем само значение —
     * по коду возврата его не узнать. */
    fprintf(stderr, "macrunner-hb-backend-неизвестен: backend=%d (INTERP=%d JIT=%d AOT=%d) pc=%08x\n",
            (int)backend, (int)HB_BACKEND_INTERP, (int)HB_BACKEND_JIT, (int)HB_BACKEND_AOT,
            (unsigned)ctx->pc);
    fflush(stderr);
    return HB_ERR_INVALID_ARG;
}
