#ifndef HB_RUNTIME_H
#define HB_RUNTIME_H

#include "hb_result.h"
#include "hb_context.h"
#include "hb_fault.h"
#include "hb_ir.h"
#include "hb_codegen.h"
#include "hb_cache.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Execution result */
typedef struct {
    int exit_code;
    hb_result_t result;
    uint64_t steps_executed;
    uint64_t blocks_executed;
    uint64_t duration_ns;
    bool timed_out;
    bool faulted;
    const char* fault_reason;
} hb_exec_result_t;

/* Interpreter */
typedef struct hb_interpreter hb_interpreter_t;

hb_interpreter_t* hb_interpreter_create(hb_context_t* ctx);
void hb_interpreter_destroy(hb_interpreter_t* interp);
hb_result_t hb_interpreter_run(hb_interpreter_t* interp, const hb_ir_func_t* func, hb_exec_result_t* out);
/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: старт с произвольного блока — для отката на
 * интерпретатор при отказе кодогенерации (см. hb_interpreter.c). */
hb_result_t hb_interpreter_run_from(hb_interpreter_t* interp, const hb_ir_func_t* func,
                                    hb_ir_block_t* start, hb_exec_result_t* out);
/* ★★★★★ 05.09.2026 — ТОЧНОЕ ВОЗОБНОВЛЕНИЕ ПОСЛЕ ОТКАЗА В ВЫПУЩЕННОМ КОДЕ.
 * Доиграть ОДИН блок с команды `start_index` до его конца (или до передачи управления —
 * тогда `ctx->pc` уже выставлен командой). Соседние блоки не ищет и не исполняет: остаток
 * работы возвращается диспетчеру через `ctx->pc`. Отказ команды докладывается как в общем
 * цикле: `out->faulted`, `out->result`, `ctx->last_result`. Именно так снимок контекста
 * заменён позицией: карта отказов называет команду, интерпретатор продолжает с неё. */
hb_result_t hb_interpreter_resume_block(hb_context_t* ctx, const hb_ir_block_t* block,
                                        size_t start_index, hb_exec_result_t* out);

/* In-memory block cache entry */
typedef struct {
    uint64_t guest_addr;
    uint8_t* native_code;
    size_t native_size;
    uint32_t steps;
    uint64_t hit_count;
    const hb_ir_block_t* block;
    bool owns_block;
    bool fused;
    /* ★ 25.08.2026 — ПРОМОЦИЮ ПРОБУЮТ ОДИН РАЗ.
     * `try_promote_hot_block_families` звалась на КАЖДОЙ диспетчеризации блока, и каждый из
     * семи распознавателей заводил буфер на 1024 байта и кодогенератор, чтобы почти всегда
     * не узнать свой шаблон и всё уничтожить. Отсюда замеренные «−3x к старту»: 771 с против
     * 250 с. Блок, чей шаблон не подошёл, не подойдёт и в следующий раз — состав команд у него
     * тот же. Помечаем и больше не пробуем. */
    bool promote_tried;
    bool valid;
    /* MacRunner 2026-07-27 (HK Mono/JIT stale-translation fix): FNV-1a over the
     * guest byte span captured at translation time.  Only tracked for spans in
     * writable+executable regions (JIT-on-JIT / Mono code heaps); 0 = untracked.
     * Re-verified on every cache hit; mismatch evicts and retranslates. */
    uint64_t smc_span_start;
    uint64_t smc_hash;
    uint32_t smc_span_len;
    /* Итерация 979: отпечаток ПОКОЛЕНИЯ страницы (приказ 123). Сравнение одного числа
     * заменяет хеш по всем байтам блока, когда защита страниц включена. */
    uint32_t smc_gen;
    uint8_t  smc_gen_valid;
    /* MacRunner 2026-08-01 — host half of the FEX-style fault map (see hb_codegen.h).
     * host_off[i] is the offset into native_code where guest instruction i begins; the guest
     * half is block->instrs[i].guest_addr. Owned by the entry, freed on eviction. Строится
     * БЕЗУСЛОВНО (с 04.09.2026), а с 05.09 ещё и едет в постоянный кеш хвостом блоба: это
     * единственный источник точной позиции отказа, снимка контекста больше нет. */
    uint32_t* host_off;
    /* Instruction index for host_off[n] -- see hb_codegen.h: fusions make it differ from n. */
    uint16_t* host_instr;
    uint16_t host_off_count;
} hb_block_cache_entry_t;

typedef struct {
    uint64_t guest_addr;
    uint8_t* target_code;
    size_t patch_offset;
    /* 2026-07-30: this entry's own chain-entry trampoline — what OTHER blocks branch to in order
     * to reach it. Created lazily on the first inbound chain and never moved, so eviction only has
     * to rewrite the trampoline's literal instead of hunting down every inbound branch. */
    uint8_t* in_trampoline;
    /* MacRunner 25.08.2026 — ВТОРАЯ ЩЕЛЬ. У блока, кончающегося условным переходом, целей
     * две, а щель в общем эпилоге одна: сшивалась только ветвь, дошедшая до него, вторая
     * возвращалась в диспетчер каждый раз (прибор: already_OTHER == already, 100 %).
     * Под MACRUNNER_HB_CHAIN_TWO_SLOTS кодогенератор даёт ветви провала свой эпилог со
     * своей щелью; эта пара полей описывает её. Ноль в `slot2_patch_offset` означает
     * «второй щели у блока нет» — так ведут себя все блоки со старой укладкой. */
    uint64_t slot2_guest_addr;
    uint8_t* slot2_target_code;
    size_t   slot2_patch_offset;
} hb_block_chain_meta_t;

/* MacRunner (2026-06-17 — FIX#2a, HK rank-7 livelock): the block-cache hash table was
 * the JIT limiter (filled 65536/65536 during Mono ReloadAssembly while the 128MB JIT
 * exec buffer was only ~18% used), tripping the sticky code_cache_full latch -> JIT
 * permanently disabled -> everything fell to the slow cache-full re-dispatch fallback.
 * Sized so the 128MB exec buffer (~347K blocks @ ~377B) is the real limiter, not this
 * table. calloc'd per-thread (~56B/entry => ~29MB virtual/thread, lazy zero-fill so
 * physical is pay-as-touched; idle worker threads touch almost none). */
#define HB_BLOCK_CACHE_SIZE 524288

/* In-memory block cache */
/* MacRunner 2026-08-09 — ЁМКОСТЬ ПО МЕСТУ.
 *
 * Замер занятости (итерация 83): МЕДИАНА 12 занятых записей из 524 288, средняя 0.0%,
 * а таблица стоит ~29 МБ виртуальных на среду. Сред за прогон 116 736 и ни одна не
 * разрушается (итерация 84) — отсюда ≈3.3 ТБ адресного пространства и отказ гостя на
 * `VirtualAlloc`. Освобождать среды по порогу нельзя: проверено, прогон гибнет втрое
 * раньше (итерация 86), потому что на среду ещё ссылаются. Значит уменьшаем ЦЕНУ среды,
 * не трогая время жизни — тот же приём, что сработал для кеша IR (итерация 76: смерть
 * снята, веха −11.4%).
 *
 * `entries` вынесен в отдельное выделение, ёмкость хранится в самой структуре. */
typedef struct {
    hb_block_cache_entry_t *entries;
    size_t size;
    size_t size_mask;
    size_t count;
    /* MacRunner 2026-06-22 (lever #3, ABZU first-frame): hb_jit_runtime_reset runs once per
     * nested run_x64 frame (13777x in ABZU's _initterm grind). The old block_cache_reset
     * memset the whole entries[] array (~29MB) and looped all 524288 slots every frame,
     * faulting in + writing every page and defeating the lazy zero-fill (~11.3% self-time).
     * Track the slots actually occupied this generation so reset clears ONLY those (== count).
     * used_overflow falls back to the full memset if the tracking array can't grow (OOM-safe);
     * correctness invariant preserved: after reset every slot has valid==false. */
    uint32_t* used_slots;
    size_t used_count;
    size_t used_cap;
    bool used_overflow;
    /* Block chaining is experimental/env-gated. Keep the hot cache entry at
     * baseline size when the flag is off; allocate side metadata only on use. */
    hb_block_chain_meta_t* chain_meta;
    /* MacRunner 2026-08-16, лейн ДИСПЕТЧ — ПЕРВЫЙ УРОВЕНЬ ПОИСКА (по образцу tb_jmp_cache QEMU).
     *
     * Зачем. Таблица `entries` весит 524288 * 112 = 56 МБ и мимо всех уровней кеша процессора:
     * замерено 3947 пс на обращение против 1786 пс у таблицы на 64 КБ (итерация 2).
     *
     * Почему НЕ уменьшение самой таблицы: занятость доходит до 131 643 записей (итерация 83),
     * а уменьшение до 8192 уже опровергнуто замером (итерация 87 — переполнение, веха не
     * достигнута). Значит первый уровень ДОБАВЛЯЕТСЯ перед полной таблицей, ничего не убирая.
     *
     * Почему запись 16 байт, а не вся `hb_block_cache_entry_t`: у QEMU 4096 записей это 32 КБ
     * ровно потому, что запись там указатель. 4096 наших записей по 112 Б дали бы 458 КБ —
     * мимо L1d, и большей части выигрыша не было бы.
     *
     * Устаревшее попадание НЕВОЗМОЖНО без единой чистки: `entries` выделяется один раз и не
     * перевыделяется, а на попадании сверяются ТРИ вещи — адрес в слоте, `valid` записи и
     * адрес в самой записи. Запись, переиспользованная под другой адрес, отсекается третьей
     * проверкой; переведённая заново под тот же адрес — та, что и нужна. */
    struct hb_block_l1_slot* l1;
    uint32_t l1_mask;                /* ёмкость−1; ёмкость задаётся MACRUNNER_HB_L1_SLOTS */
    uint64_t l1_hits;
    uint64_t l1_misses;
    /* ★ MacRunner 2026-09-04 — АРЕНА, В КОТОРУЮ СМОТРЯТ `native_code` ЗАПИСЕЙ.
     *
     * Поле не «удобство»: под раздельным W^X (MACRUNNER_HB_JIT_SPLITWX) у арены ДВА
     * отображения, и снятие сшивки — `block_cache_unchain_entry` — обязано писать по
     * RW-адресу, а `native_code` хранит RX. Runtime у этой функции под рукой нет и
     * протаскивать его через `block_cache_reset` пришлось бы через три слоя. Ссылка на
     * арену лежит здесь по существу: указатели `native_code` — это её адреса.
     * Ставится сразу после block_cache_create(); NULL означает «арены нет», и тогда
     * перевод — тождество, как и без splitwx. */
    const hb_jit_buffer_t* jit_mem;
    /* ★ 07.09.2026, лейн ПОВТОРНЫЙ-ВЫПУСК — ДВА ПОЛЯ, БЕЗ КОТОРЫХ ПРИЧИНУ ПОВТОРА НЕ НАЗВАТЬ.
     *
     * Перепись лейна КЕШ считает адреса ГЛОБАЛЬНО и потому не отличает «тот же кеш потерял
     * запись» от «второй кеш перевёл то же самое». Оба поля нужны РОВНО для этого различения
     * и читаются только прибором (`povtor_note`), на исполнение не влияют:
     *   census_id — плотный номер кеша, выдаётся при первом занесении; сравнение указателей
     *               не годится, потому что кеш переиспользуется и адрес совпадает;
     *   reset_gen — растёт в block_cache_reset. Повтор при ТОМ ЖЕ номере кеша, но ИНОМ
     *               поколении, есть повтор ПО СБРОСУ; при том же поколении — по выселению.
     * Порядок причин становится взаимно исключающим, а не «одно из двух». */
    uint32_t census_id;
    uint32_t reset_gen;
} hb_block_cache_t;

#define HB_BLOCK_L1_BITS 14u   /* 16384 слотов; умолчание выбрано замером на настоящих адресах */
#define HB_BLOCK_L1_SIZE (1u << HB_BLOCK_L1_BITS)

typedef struct hb_block_l1_slot {
    uint64_t guest_addr;
    hb_block_cache_entry_t* entry;
} hb_block_l1_slot_t;

/* JIT executor */
typedef struct {
    hb_context_t* ctx;
    hb_jit_buffer_t* jit_mem;
    hb_block_cache_t* block_cache;
    /* ★ 2026-09-03 (режим D Diablo): диапазон ФУНКЦИИ, исполняемой сейчас (ставит hb_jit_runtime_run) — отпечаток
     * самоизменения берётся по всей поднятой функции, а не по блоку входа: патч в блоке без своей записи кеша
     * (проваливание внутри функции) иначе не виден вовсе. */
    uint64_t cur_func_addr;
    size_t   cur_func_len;
    uint64_t hot_trace_blocks;
    uint64_t hot_trace_next;
    uint64_t code_cache_full_reports;
    hb_cache_t* persistent_cache;
    uint8_t persistent_cache_flags;
    bool code_cache_full;
    /* Default-off native-signal recovery quarantine, shared by the SIGBUS
     * invalidation and SIGILL ownership paths. This deliberately survives
     * hb_jit_runtime_reset(): retrying a native block that already faulted would
     * recreate the same signal loop after the code cache is reset. */
    uint64_t* jit_signal_quarantine;
    size_t jit_signal_quarantine_count;
    size_t jit_signal_quarantine_capacity;
    bool jit_signal_disable;

    /* MacRunner 2026-08-09 — перепись охранного диспетчера. Раньше это были четыре
     * `static __thread` в hb_runtime.c, и `++t_guard_dispatch` на КАЖДОМ диспатче стоил вызова
     * `_tlv_get_addr` (на Darwin arm64 быстрая модель TLS игнорируется): 7-12% рабочего потока
     * по профилю в сцене против ~5% на весь выпущенный код. Рантайм и так потоковый, поэтому
     * поля просто переехали сюда — семантика та же, цена обычная загрузка.
     * Дописаны В КОНЕЦ: выпущенный код смещений этой структуры не использует. */
    uint64_t guard_dispatch;
    uint64_t guard_recover;
    uint64_t guard_flushed_dispatch;
    uint64_t guard_flushed_recover;
}hb_jit_runtime_t;

hb_jit_runtime_t* hb_jit_runtime_create(hb_context_t* ctx);
void hb_runtime_init_environment(void);
void hb_jit_runtime_destroy(hb_jit_runtime_t* rt);
/* MacRunner: reset a runtime for reuse by another callback on the same thread
 * (per-thread pool) instead of destroy+recreate per callback. Eagerly frees the
 * block_cache's owned blocks + clears it, rewinds the jit arena bump pointer, and
 * re-points ctx — translations are fully regenerated (SMC-safe, no stale code). */
void hb_jit_runtime_reset(hb_jit_runtime_t* rt, hb_context_t* ctx);

/* ★ 07.09.2026, лейн ПОВТОРНЫЙ-ВЫПУСК — КОРЗИНЫ ПРИЧИН ПОВТОРНОГО ВЫПУСКА.
 *
 * Список ОДИН, здесь: и учёт в hb_runtime.c, и повозка отрицательного контроля
 * читают его отсюда. Два параллельных списка (перечисление и имена) уже стоили
 * проекту гейтов — см. разбор у HB_CHAIN_DECLINE. Порядок строк задаёт и значения,
 * и порядок печати.
 *
 *   ПЕРВЫЙ     адрес материализуется впервые за процесс
 *   СБРОС      тот же кеш, иное поколение -> запись снёс block_cache_reset
 *   ВЫСЕЛЕНИЕ  тот же кеш, то же поколение -> запись сняли поимённо
 *   ЧУЖОЙ      адрес уже материализован ДРУГИМ кешем блоков
 *
 * Корзины взаимно исключающие: сумма равна числу учтённых занесений. */
#define HB_POVTOR_KORZINY(X)     X(HB_POVTOR_K_PERVYJ,    "pervyj")     X(HB_POVTOR_K_SBROS,     "sbros")     X(HB_POVTOR_K_VYSELENIE, "vyselenie")     X(HB_POVTOR_K_CHUZHOJ,   "chuzhoj_kesh")

#define HB_POVTOR_ENUM_ITEM(imya, podpis) imya,
enum { HB_POVTOR_KORZINY(HB_POVTOR_ENUM_ITEM) HB_POVTOR_K_N };
#undef HB_POVTOR_ENUM_ITEM

/* ★ МЕСТА СБРОСА. Доля «сброс» без имени места есть следствие без причины: сбросов
 * три разных вида, и лечатся они по-разному. Список ОДИН, как и у корзин.
 *   VLOZH_TLS   вложенный кадр run_x64 взял среду из потокового пула
 *   VLOZH_GLOB  вложенный кадр взял среду из общего пула (переезд на другой поток)
 *   VNESH       ВНЕШНИЙ кадр run_x64 переиспользовал потоковую среду
 *   PROCHEE     всё остальное (повозки, будущие места) */
#define HB_POVTOR_MESTA(X)     X(HB_POVTOR_M_PROCHEE,    "prochee")     X(HB_POVTOR_M_VLOZH_TLS,  "vlozh_tls")     X(HB_POVTOR_M_VLOZH_GLOB, "vlozh_glob")     X(HB_POVTOR_M_VNESH,      "vnesh")

#define HB_POVTOR_MESTO_ITEM(imya, podpis) imya,
enum { HB_POVTOR_MESTA(HB_POVTOR_MESTO_ITEM) HB_POVTOR_M_N };
#undef HB_POVTOR_MESTO_ITEM

/* Сброс с указанием МЕСТА. hb_jit_runtime_reset — это она же с HB_POVTOR_M_PROCHEE. */
void hb_jit_runtime_reset_at(hb_jit_runtime_t* rt, hb_context_t* ctx, int mesto);

uint64_t hb_povtor_korzina(int k);      /* число занесений в корзину k */
uint64_t hb_povtor_sbrosov(void);       /* вызовов block_cache_reset */
uint64_t hb_povtor_sneseno(void);       /* живых записей, снесённых сбросами */
void hb_povtor_itog_print(const char* why);

/* ★ ВХОД ДЛЯ ПРИЁМКИ: повторное занесение ТОГО ЖЕ гостевого адреса с другим телом —
 * та самая ветвь «Update existing entry», из диспетчера недостижимая (обоснование у
 * определения). Возвращает ПРЕЖНИЙ нативный адрес либо NULL, если записи нет или гейт
 * MACRUNNER_HB_POVTOR_STATS выключен. В прогонах не вызывается ничем. */
uint8_t* hb_test_povtornyj_perevod(hb_jit_runtime_t* rt, uint64_t addr,
                                   uint8_t* novoe_telo, size_t razmer);
hb_result_t hb_jit_runtime_compile(hb_jit_runtime_t* rt, const hb_ir_func_t* func);
hb_result_t hb_jit_runtime_run(hb_jit_runtime_t* rt, const hb_ir_func_t* func, hb_exec_result_t* out);
int hb_jit_runtime_handle_signal_fault(uint64_t pc, uint64_t fault_addr, int signal,
                                       const void* host_context);
/* SIGILL ownership is selected by ntdll's cached, default-off gate.  Unlike the
 * generic range-based path this claims any active TLS JIT guard: generated code
 * can branch through a stale/corrupt native target outside the current slab.
 * The signal handler supplies the already-probed instruction word so the
 * runtime never dereferences an arbitrary fault PC after siglongjmp(). */
int hb_jit_runtime_handle_owned_sigill(uint64_t pc, uint32_t native_word,
                                       int native_word_valid,
                                       const void* host_context);
/* Resolve an address inside the owning thread's live JIT block cache.  This is
 * read-only diagnostic metadata: callers must use the runtime on its owner
 * thread and must not retain the result across hb_jit_runtime_reset(). */
int hb_jit_runtime_native_block_info(hb_jit_runtime_t* rt, uint64_t native_pc,
                                     uint64_t* guest_addr, uint64_t* native_start,
                                     size_t* native_size);

/* ★★★★★ MacRunner 2026-09-04 — ЕДИНСТВЕННАЯ ДВЕРЬ «ХОЗЯЙСКИЙ PC -> ГОСТЕВАЯ КОМАНДА».
 *
 * ЗАЧЕМ. Соседняя `hb_jit_runtime_native_block_info` отвечает АДРЕСОМ ВХОДА блока, и это
 * единственное, что до сегодня умел спросить кто-либо снаружи. Внутри сцеплённой цепочки
 * такой ответ неверен по построению: сцеплённое ребро в диспетчер не возвращается, значит
 * `ctx->pc` называет блок, ОТПРАВЛЕННЫЙ на исполнение, а отказ произошёл в одном из
 * следующих. Отсюда и «доставка исключения не туда», и невозможность дать Mono точный
 * обратный адрес.
 *
 * ЧЕСТНЫЙ ТРОЙНОЙ ОТВЕТ, в терминах hb_fault_result_t:
 *   guest_pc_exact  = 1 -> `guest_pc` есть адрес ТОЙ САМОЙ команды x86; годится в CONTEXT;
 *   guest_pc_approx = 1 -> блок найден, но карта не отвечает (вытеснена, блок-помощник,
 *                          переполнение таблицы). `guest_pc` = вход блока, только для печати;
 *   оба 0             -> `host_pc` не принадлежит ни одному живому блоку этой среды.
 * `guest_pc` при «оба 0» равен нулю, но полагаться следует на ФЛАГИ: ноль — законный адрес,
 * и молчаливый ноль ровно эту таблицу когда-то и заставили завести.
 *
 * Возврат: 1 тогда и только тогда, когда `guest_pc_exact`. `out` заполняется ВСЕГДА.
 * Звать только на потоке-владельце среды; результат не переживает hb_jit_runtime_reset. */
int hb_jit_runtime_guest_pc_for_host_pc(hb_jit_runtime_t* rt, uint64_t host_pc,
                                        hb_fault_result_t* out);

/* Счётчики двери выше. Ноль в `exact` при ненулевом `calls` — это «спрашивали, ответить не
 * смогли», а НЕ «не спрашивали»: без такого различения счётчик доказывает лишь молчание. */
void hb_jit_guest_pc_stats(uint64_t* calls, uint64_t* exact, uint64_t* approx,
                           uint64_t* outside);

/* Учёт карт по записям кеша: сколько поставлено, сколько снято (утечка = поставлено минус
 * снято на пустом кеше) и по каким причинам карты нет. Три причины врозь — иначе «карт нет»
 * не отличить от «блоков не было». */
/* Разбор ОТКАЗОВ в выпущенном коде по тому, что удалось узнать о месте: карта ответила /
 * блок нашли, карты нет / блока не нашли. Врозь, потому что лечение у трёх исходов разное. */
void hb_jit_fault_pc_stats(uint64_t* exact, uint64_t* no_map, uint64_t* no_block);

/* Всего байт, выделенных под карты за прогон. Цена безусловной карты названа числом. */
uint64_t hb_jit_ripmap_bytes(void);
/* Карт, поднятых из ПОСТОЯННОГО кеша (хвост блоба, 05.09.2026). Ноль при ненулевых
 * попаданиях кеша = блоки с диска идут без карты, точного возобновления у них нет. */
uint64_t hb_jit_ripmap_from_cache(void);
/* Самопроверка хвоста блоба (с отрицательным контролем внутри): 0 = сошлось, иначе номер шага. */
int hb_jit_ripmap_trailer_selftest(void);

void hb_jit_ripmap_stats(uint64_t* attached, uint64_t* released,
                         uint64_t* no_map_overflow, uint64_t* no_map_empty,
                         uint64_t* no_map_oom);

/* ГЕОМЕТРИЯ КАДРА ОГРАЖДЕНИЯ — наружу, чтобы прибор цены НЕ ПОВТОРЯЛ ЕЁ ЧИСЛАМИ.
 *
 * Зачем. `scripts/цена-операции.c` мерил memset 790 Б и memcpy 760 Б, взяв числа из
 * комментария hb_runtime.c. Обе величины протухли: кадр вырос, снимок вырос. Настоящий
 * снимок вдвое с лишним больше, то есть прибор занижал ровно ту статью, ради которой писан.
 * Это тот же класс, что «зашитые смещения структур запрещены» и «прибор мерял нативную libc»:
 * прибор, повторяющий геометрию числами, расходится с кодом при первой правке структуры
 * и после этого меряет выдуманное.
 *
 * Отдаются РОВНО те величины, которые платит `run_jit_block_with_signal_guard`:
 *   frame_size    — sizeof кадра (для честного расположения на стеке);
 *   memset_head/tail — два обнуляемых куска вокруг снимка (сам снимок не обнуляется);
 *   snap_head/tail   — два копируемых куска снимка (середина ymm_hi..guest32_base не копируется).
 * Любой указатель может быть NULL. */
void hb_jit_guard_frame_geometry(size_t* frame_size,
                                 size_t* memset_head, size_t* memset_tail,
                                 size_t* snap_head, size_t* snap_tail);

/* SMC reverify diagnostics (2026-07-27): process-wide counters.  Any pointer
 * may be NULL.  Read-only; values are best-effort under multithreading. */
/* Итерация 987: сбросить трансляции, чьи гостевые байты попадают в диапазон.
 * Возвращает число выселенных. Зовётся из перехвата `VirtualProtect` на переходе RW -> RX. */
uint64_t hb_jit_invalidate_guest_range(hb_jit_runtime_t* rt, uint64_t start, uint64_t len);

void hb_jit_smc_reverify_stats(uint64_t* tracked, uint64_t* reverified,
                               uint64_t* evicted, uint64_t* unreadable);

/* ОБСЛУЖИВАНИЕ ОТЗЫВА СЦЕПЛЕНИЯ — посещено против изменено (лейн СЦЕПЛЕНИЕ, 06.09.2026).
 *
 * `visited` — сколько записей кеша обход ПОСМОТРЕЛ; `matched` — сколько рёбер он
 * действительно снял. Разведены намеренно: весь вопрос пункта 1 разбора Астры в том,
 * что первое число велико, а второе может быть нулём — и тогда обход есть чистая
 * трата. Числа набираются только при MACRUNNER_HB_UNCHAIN_STATS=1; при выключенном
 * гейте возвращаются нули, и чтобы это не читалось как «событий не было», рядом
 * стоит `calls` вместе с прибором hb-unchain-obhod (у него looked>0 доказывает,
 * что функция исполнялась). Любой указатель может быть NULL. */
void hb_unchain_stats(uint64_t* calls, uint64_t* visited, uint64_t* matched,
                      uint64_t* skipped, uint64_t* overflow, uint64_t* ns);

/* SMC re-lift gate (2026-07-28): number of dispatch exits taken because a cached
 * translation's guest bytes changed, forcing the caller to re-lift from current bytes.
 * Kill switch MACRUNNER_HB_SMC_RELIFT=0. */
uint64_t hb_jit_smc_relift_exits(void);
uint64_t hb_jit_smc_evicted_total(void);
void hb_jit_smc_last_evicted(uint64_t* addr, uint32_t* len);
uint64_t hb_jit_smc_relift_suppressed(void);

/* Unified runtime entry */
hb_result_t hb_runtime_run(hb_context_t* ctx, const hb_ir_func_t* func, hb_backend_t backend, hb_exec_result_t* out);

#ifdef __cplusplus
}
#endif

/* `hb_runtime_fault_rolls_back_state` УДАЛЕНА 05.09.2026 вместе со снимком контекста:
 * путь отказа состояние гостя НЕ откатывает никогда, и кодогенератор больше не спрашивает —
 * вето на закрепление регистров в блоке, способном отказать, безусловно. */

/* Версия ключа постоянного кеша. Разные сочетания гейтов, влияющих на ВЫПУСК, обязаны давать
 * разные номера — иначе руки A/B делят записи, а блок, переведённый при одном наборе, может
 * подняться из кеша при другом. */
unsigned hb_runtime_persistent_cache_version(void);

/* Нумерация помощников — та же, что у часовых постоянного кеша (`helper_addr_for_cache_id`).
 * Кодогенератор живёт в другой единице трансляции, поэтому доступ через эти две функции,
 * а не копией списка: копия разошлась бы молча, и блок поехал бы звать не того помощника. */
unsigned hb_runtime_helper_id_for_addr(uint64_t addr);
void hb_runtime_fill_helper_table(void** table, unsigned slots);

#endif
