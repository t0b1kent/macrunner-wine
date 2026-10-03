#ifndef HB_CODEGEN_H
#define HB_CODEGEN_H

#include "hb_result.h"
#include "hb_ir.h"
#include "hb_context.h"
#include "hb_regalloc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* MacRunner 2026-07-29 — RELOCATION TABLE.
 *
 * The persistent cache has to turn absolute host addresses in emitted code into something a
 * later process can restore. Until now it did that by RE-DISCOVERING the sites afterwards:
 * scanning for `blr x23`, matching the shape of the surrounding movs, and rejecting anything it
 * did not recognise. That is why 89 % of unstored blocks were multi-helper ones, and why four
 * separate rejection reasons exist at all.
 *
 * Codegen already knows every one of these offsets at the instant it writes them. Recording them
 * here removes the search — and with it the site cap, the x2/x3/x4 veto, the helper-id lookup
 * and the arg1 window matching, which are all artefacts of guessing after the fact rather than
 * properties of the code. This is the shape the literature uses for persistent code caches:
 * emit relocatable host code, keep the relocation list beside it.
 *
 * Recorded centrally in emit_mov_imm64() for x1 and x23, so none of the 62 helper-call sites or
 * 37 pointer-mov sites needs to change — a migration that size is where mistakes hide.
 */
/* 256, not 64. Measured on Hollow Knight: 39434 blocks produced 194322 sites — 4.9 per block on
 * average — and 127 blocks overflowed a 64-entry table. The old single-stub matcher handled
 * exactly ONE site, which is why it rejected almost everything: a block with one relocation is
 * the exception here, not the rule. A table that silently truncates is worse than no table, so
 * the cap is set well clear of the measured distribution and overflow stays counted. */
#define HB_CODEGEN_MAX_RELOCS 256

/* What the recorded value MEANS, stated by the emitter rather than guessed from the register.
 *
 * The store path used to read `reg == 23` as "this is a helper address", because emit_call_helper()
 * is the obvious producer of x23. It is not the only one. emit_mask_x_reg_to_size() uses x23 as its
 * scratch register at 22 of its 25 call sites, and for a 32-bit operand it emits
 * `mov x23, 0xffffffff` — the zero-extension every 32-bit x86 operation needs. A plain 32-bit ADD
 * produces exactly one relocation, and it is that. The store path looked 0xffffffff up in the
 * helper id table, found nothing, and declined the whole block: 53 655 of them on Hollow Knight,
 * 90 % of all declines and 24.6 % of every block that reached the cache.
 *
 * It is also why registering the 24 missing helpers (05f3f3f9) moved retention by nothing — the
 * old matcher only ever inspected the real `blr x23` target, while the table sees every x23 write.
 * (A large `mem.disp` is parked in x23 too, at hb_arm64_codegen.c:993, but only when direct-mem is
 * enabled, which it is not on Hollow Knight. The mask is the one that fires.)
 *
 * That is the same mistake `mh_widearg` was: matching the register instead of the value. Codegen
 * knows which one it is emitting, so it says so here and nothing downstream has to infer it. */
typedef enum {
    HB_RELOC_KIND_VALUE = 0,  /* an ordinary immediate — classified by value at store time */
    HB_RELOC_KIND_HELPER = 1  /* a C helper entry address — only ever from emit_call_helper() */
} hb_codegen_reloc_kind_t;

/* Сколько разных наборов выгрузок может иметь свой общий эпилог в одном блоке.
 * Наборов не больше 16 (четыре закрепляемых регистра); восьми хватает с запасом, а при
 * переполнении место выпускает эпилог по-старому, встроенным. */
#define HB_SHARED_EPI_MAX 8u
#define HB_PEND_EPI_MAX 32u

typedef struct {
    size_t off;      /* byte offset of the 4-instruction MOVZ/MOVK sequence */
    uint8_t reg;     /* destination register: 1/2/3/4 (arguments) or 23 (helper target, scratch) */
    uint8_t kind;    /* hb_codegen_reloc_kind_t — fits in existing padding, so the table is free */
    uint64_t value;  /* absolute value written, resolved against the block at store time */
} hb_codegen_reloc_t;

/* Code generation result */
#define HB_CODEGEN_MAX_HOST_OFF 512

typedef struct {
    uint8_t* code;
    size_t size;
    size_t capacity;
    hb_codegen_reloc_t relocs[HB_CODEGEN_MAX_RELOCS];
    size_t reloc_count;
    bool reloc_overflow;  /* more sites than the table holds — do not trust it for this block */
    hb_arch_t arch;  /* guest architecture — defaults to HB_ARCH_X64 (=0) */
    /* MacRunner 2026-07-31 — scratch-register remap for frameless blocks.
     * Measured: the per-block prologue/epilogue is a callee-saved frame costing 12 memory accesses per
     * dispatch, and 48.3 % of blocks never call anything, so they preserve registers against a call that
     * never happens. Such a block can instead take its scratch from the caller-saved bank and carry no frame.
     * The 596 call sites hard-code x19-x23, so the substitution happens in the leaf encoders instead.
     * rmap_active is the guard: a zero-initialised buffer means IDENTITY, never "everything becomes x0". */
    uint8_t rmap_active;
    uint8_t emitted_call;  /* set by emit_blr: a lean block must not contain one */
    uint8_t rmap[32];
    /* MacRunner 2026-08-01 — host-offset map, the half of FEX's JITCodeTail we do not have.
     *
     * FEX carries no context snapshot at all: each block ends with a table of (host-PC delta,
     * guest-RIP delta) pairs, one per guest opcode, and a fault is resolved by folding the
     * faulting host PC through that table into the exact guest RIP. Rollback granularity is one
     * guest instruction, so work completed before the faulting instruction is never discarded —
     * and no sigsetjmp, no 760-byte snapshot and no 790-byte frame memset are needed per block.
     *
     * We already hold the guest side: block->instrs[i].guest_addr. Only the host side is missing.
     * host_off[i] is the buffer offset where instruction i's code begins, recorded as it is
     * emitted; (host_pc - native_code) then binary-searches to i and yields the guest address.
     *
     * Recorded unconditionally (a few stores per instruction, no branches on the hot path) but
     * used only behind a gate, so the new mechanism can be verified against the existing
     * snapshot path before anything is removed. host_off_overflow marks a block with more
     * instructions than the table holds — such a block simply keeps the old path. */
    uint32_t host_off[HB_CODEGEN_MAX_HOST_OFF];
    /* The instruction index that produced host_off[n]. NOT redundant with n: fusions consume
     * 2-4 instructions and record only the first, so the entry counter runs behind the loop
     * index. Indexing block->instrs[] by the entry number instead of by this value returns a
     * different guest instruction's address in every block where a fusion fired -- which, with
     * CMP/Jcc fused, is the common case rather than a corner one. */
    uint16_t host_instr[HB_CODEGEN_MAX_HOST_OFF];
    uint16_t host_off_count;
    bool host_off_overflow;
    /* MacRunner 2026-08-22, лейн РЕГИСТРЫ, итерация 159 — РЕШЕНИЕ О МЁРТВОЙ ЗАПИСИ ЛЕНИВЫХ
     * ФЛАГОВ, принятое по ВЫПУЩЕННОМУ коду первого прохода.
     *
     * Бит на команду блока: 1 = все записи этой команды в область ленивых флагов позже
     * перезаписываются, и до перезаписи их никто не читает. Такую запись второй проход
     * вправе не выпускать.
     *
     * ★ РЕШЕНИЕ ПРИНИМАЕТСЯ ПО КОМАНДЕ, А НЕ ПО СЛОТУ. Замер итерации 153 показал, что
     * из четырёх пар записи мертвы порознь: (#440,#448), (#472,#480), (#488,#496) —
     * 5833 раза, а (#456,#464) — 2719. Причина не в чтениях, а в том, что при
     * `lazy_kind_result_only` пара lhs просто НЕ ПИШЕТСЯ. Снимать запись по мёртвости
     * ОДНОГО слота значило бы потерять живые соседние. */
    uint64_t deadlazy_skip[8];   /* 512 команд — столько же, сколько мест в host_off */
    uint16_t deadlazy_marked;
    /* MacRunner 2026-08-18, лейн РЕГИСТРЫ — ЗАЩЁЛКА СТАТИЧЕСКОГО ЗАКРЕПЛЕНИЯ.
     *
     * Пролог и эпилог обязаны согласиться о форме кадра. Спрашивать гейт дважды нельзя:
     * решение зависит ещё и от `rmap_active`, а тот в этом файле переустанавливается по ходу
     * выпуска (строки 4099-4106 сохраняют и возвращают его вокруг вставки). Пролог,
     * посчитавший кадр расширенным, и эпилог, посчитавший обычным, разъедутся на 32 байта
     * стека — это не расхождение семантики, которое поймает сличение, а порча возврата.
     *
     * Поэтому решение принимается ОДИН раз, в прологе, и записывается сюда; эпилог только
     * читает. Часовой 0xA5 — по образцу rmap_active: буфер в этом дереве нигде не обнуляется
     * целиком, и голый 0/1 читал бы мусор со стека. */
    uint8_t sra_armed;
    /* Какие регистры гостя закреплены В ЭТОМ блоке — разряд на регистр (HB_REG_RAX=0 …).
     * Набор ПОБЛОЧНЫЙ, а не постоянный: замер на 685 131 настоящем блоке показал, что
     * 77 % пар «блок-регистр» убыточны (одно-два обращения при цене 2-4 команды), и
     * сплошное закрепление на блоках короче 20 слов даёт МИНУС 3,96 %. Выбор по блоку
     * поднимает результат с 1,37 % до 2,04 % и, главное, убирает отрицательные случаи. */
    uint16_t sra_mask;
    /* Из какого банка взяты регистры хозяина: HB_SRA_BANK_SAVED (x25-x28, блок сохраняет их
     * сам) или HB_SRA_BANK_SCRATCH (x11-x15, сохранять не надо). Решает признак «зовёт ли
     * блок помощника», известный после первого прохода. Обоснование — в hb_regalloc.h. */
    uint8_t sra_bank;
    /* Какие из закреплённых блок ПИШЕТ — их и только их надо выгрузить в память перед
     * выходом. Считается первым проходом по настоящим записям в слот. */
    uint16_t sra_dirty;
    /* ═══ ЖИВОСТЬ ПО ОТРЕЗКАМ МЕЖДУ ВЫЗОВАМИ ═══
     *
     * Блок с вызовами делится вызовами на отрезки. Внутри отрезка закреплённый регистр живёт
     * в регистре хозяина; на границе он обязан согласоваться с памятью, потому что помощник
     * работает с состоянием гостя напрямую.
     *
     * Первая редакция согласовывала ГРУБО: перед каждым вызовом выгружала все грязные, после
     * каждого перечитывала ВСЕ закреплённые. Это верно, но дорого — на настоящих блоках дало
     * 0,14 % вместо 0,47 %, обещанных моделью по отрезкам.
     *
     * Здесь то же самое, но по делу:
     *   перед вызовом k  — выгрузить те, что записаны В ОТРЕЗКЕ k;
     *   после вызова k   — перечитать те, что используются в отрезках ПОСЛЕ k;
     *   в эпилоге        — выгрузить записанные В ТЕКУЩЕМ отрезке (номер = сколько вызовов уже
     *                      выпущено), а не «все грязные блока».
     *
     * Последнее — не мелочь. Регистр, записанный в отрезке 0, выгруженный перед вызовом и
     * НЕ перечитанный (дальше не нужен), держит в регистре хозяина устаревшее значение:
     * помощник мог поменять память. Выгрузка «всех грязных блока» в эпилоге затёрла бы
     * изменение помощника. Поэтому маска эпилога — отрезковая. */
    uint16_t sra_seg_written[HB_SRA_MAX_SEGMENTS];  /* записаны в отрезке k */
    uint16_t sra_reload_after[HB_SRA_MAX_SEGMENTS]; /* нужны после вызова k */
    uint8_t  sra_seg_count;    /* отрезков размечено (0 = разметки нет, работаем грубо) */
    uint8_t  sra_call_index;   /* сколько вызовов уже выпущено во втором проходе */
    /* ═══ СЧЁТ ПРИ ВЫПУСКЕ вместо прохода по буферу ═══
     *
     * Разбор стоил 5,3 % времени трансляции против 0,9 % у перевыпуска (замер по процессорному
     * времени, разделение рук полное): он шёл по КАЖДОМУ блоку, включая 85 %, где закреплять
     * нечего. Кодировщик и так знает базу и смещение в момент выпуска — значит проход по
     * буферу лишний.
     *
     * ★ ОПАСНОСТЬ, ради которой заведено `sra_cnt_size`: буфер ПЕРЕВЫПУСКАЕТСЯ. Бережливый
     * кадр сбрасывает `size` и выпускает заново, второй проход закрепления тоже, и запасной
     * путь вето банка тоже. Счётчики, набранные при выпуске, сложились бы ДВАЖДЫ, и отбор
     * получил бы завышенные числа — то есть закрепление там, где оно убыточно, причём молча.
     *
     * Защита не в том, чтобы найти все точки сброса (их несколько, и завтра добавится ещё), а
     * в том, что счётчики НЕСУТ РАЗМЕР, которому соответствуют. Не совпал с текущим — счётчики
     * недействительны, и отбор честно уходит на проход по буферу. Пропущенная точка сброса
     * может стоить только лишнего прохода, но не неверного числа. */
    size_t   sra_cnt_size;                        /* размер буфера, которому отвечают счётчики */
    unsigned sra_cnt_n[HB_SRA_COUNT_REGS];        /* обращений к регистру гостя */
    unsigned sra_cnt_wr[HB_SRA_COUNT_REGS];       /* из них записей */
    uint16_t sra_cnt_seg_used[HB_SRA_MAX_SEGMENTS];
    uint16_t sra_cnt_seg_written[HB_SRA_MAX_SEGMENTS];
    uint8_t  sra_cnt_seg;                         /* текущий отрезок при выпуске */
    uint8_t  sra_cnt_overflow;                    /* отрезков больше предела */
    /* MacRunner 2026-08-19, лейн РЕГИСТРЫ — ОБЩИЙ ЭПИЛОГ СРЕДНЕБЛОЧНОГО ВОЗВРАТА.
     *
     * Замер по 400 000 настоящих блоков: пролог выпускается 400 000 раз (ровно по блоку),
     * а эпилог — 1 127 544, то есть 2,82 раза на блок. Дублирует его
     * `emit_return_if_helper_failed`: после КАЖДОГО вызова помощника стоит проверка отказа
     * со СВОИМ полным эпилогом. Лишних выходов 727 544, каждый стоит 3 ldp + ret; переход
     * к уже выпущенному эпилогу оставляет одно слово — экономия 6,80 % ВСЕГО кода.
     *
     * `shared_epi_off` — смещение первого среднеблочного эпилога в этом блоке,
     * `shared_epi_valid` означает, что он выпущен и на него можно переходить назад.
     * Сбрасываются в `emit_prologue`, то есть на каждый блок: буфер живёт дольше блока.
     *
     * `sra_spill_full` — на общей точке выгружается ВЕСЬ закреплённый набор, а не «грязный»
     * отрезка. Иначе была бы тихая порча: эпилог выпускается на ПЕРВОМ отказе с набором
     * грязных, накопившимся к тому месту, а переходят на него и с пятого, где грязных
     * больше. Выгрузка лишнего безвредна — закреплённые регистры заливаются на входе в блок
     * и всегда содержат годное значение. */
    /* MacRunner 2026-08-19, лейн РЕГИСТРЫ — «x0 ещё содержит ctx».
     *
     * Блок вызывается из C с `ctx` в первом аргументе, и пролог делает `mov x19, x0`
     * (400 000 раз на 400 000 блоков — ровно по блоку). Значит ДО первой записи в x0
     * там уже лежит ctx, и `mov x0, x19` перед первым вызовом помощника лишний.
     * Замер по настоящему кешу: лишний в 230 464 блоках из 231 776 с вызовом = 99,4 %,
     * то есть 0,72 % всего выпущенного кода.
     *
     * ★ ПРИЗНАК ГАСИТСЯ В ЕДИНСТВЕННОЙ ВОРОНКЕ ВЫПУСКА (emit_u32), а не перечислением
     * мест. Перечисление здесь негодно по существу: пропустить одно место значит передать
     * помощнику мусор вместо ctx, а мест, пишущих x0, десятки. Через воронку проходит
     * КАЖДОЕ выпущенное слово, поэтому полнота — по построению. Разбор консервативный:
     * при сомнении признак гасится, то есть ошибка уводит в лишнюю пересылку, а не в порчу. */
    uint8_t  x0_holds_ctx;
    /* ★ ОБЩИЙ ЭПИЛОГ — ПО НАБОРУ ВЫГРУЗОК, а не один на блок.
     *
     * Первая редакция (итерация 58) держала ОДИН эпилог на блок и выгружала на нём весь
     * закреплённый набор. Это оказалось НЕВЕРНО и дало расхождение по `rax` на настоящем
     * коде: проверка отказа стоит в окне между вызовом помощника и перезаливкой, где
     * закреплённые регистры хозяина устарели, — полная выгрузка затирала свежий `ctx`.
     *
     * Просто убрать полную выгрузку тоже нельзя: замер показал, что общий эпилог тогда
     * СНИМАЕТ четыре выгрузки из 47, то есть регистр, грязный на пятом отказе, но не на
     * первом, назад не запишется. Молчаливая недовыгрузка.
     *
     * Поэтому эпилогов несколько — по одному на КАЖДЫЙ встретившийся набор выгрузок.
     * Место с набором M переходит на эпилог, выпущенный для M; набор новый — выпускается
     * свой. Наборов не больше 16 (четыре закрепляемых регистра), на практике один-два.
     * Без закрепления набор всегда 0, и всё вырождается в один эпилог на блок. */
    /* ОТЛОЖЕННЫЕ переходы к общему эпилогу: место затребовало эпилог, но тело ещё не
     * выпущено. Замыкаются, когда тело появится (обычный выход блока), либо принудительно
     * при завершении блока — см. epi_close_pending. Без замыкания это БИТЫЙ КОД, поэтому
     * замыкание сделано обёрткой вокруг кодогенерации блока, а не «не забыть». */
    size_t   pend_epi_pos[HB_PEND_EPI_MAX];
    uint16_t pend_epi_mask[HB_PEND_EPI_MAX];
    uint8_t  pend_epi_count;
    size_t   shared_epi_off[HB_SHARED_EPI_MAX];
    uint16_t shared_epi_mask[HB_SHARED_EPI_MAX];
    uint8_t  shared_epi_count;
    uint16_t sra_spill_forced;      /* набор, навязанный общей точке */
    uint8_t  sra_spill_forced_on;
    uint8_t  sra_slot_ready;                      /* смещения слотов уже посчитаны */
    uint32_t sra_slot[HB_SRA_COUNT_REGS];         /* смещения слотов в hb_context_t */
    /* MacRunner 2026-08-24: база окна гостя закреплена в X28 на весь блок
     * (гейт MACRUNNER_HB_PIN_GUEST32_BASE). Поле в КОНЦЕ — смещения прежних сохранены. */
    int pinned_g32_base;
    int ea_want_fused;/* вызывающий выпускает доступ сам и умеет слитную форму */
    int ea_guest32;   /* X21 держит ГОСТЕВОЙ адрес: база окна ещё не прибавлена */
    int ea_known32;   /* адрес гостя уже 32-битный: обрезка не нужна (2026-08-24) */
} hb_codegen_buffer_t;

/* ARM64 codegen */
typedef struct hb_arm64_codegen hb_arm64_codegen_t;

hb_arm64_codegen_t* hb_arm64_codegen_create(hb_context_t* ctx);
void hb_arm64_codegen_destroy(hb_arm64_codegen_t* cg);

hb_result_t hb_arm64_codegen_func(hb_arm64_codegen_t* cg, const hb_ir_func_t* func, hb_codegen_buffer_t* out);
hb_result_t hb_arm64_codegen_block(hb_arm64_codegen_t* cg, const hb_ir_block_t* block, hb_codegen_buffer_t* out);
hb_result_t hb_arm64_codegen_block_with_cfg(hb_arm64_codegen_t* cg, const hb_ir_block_t* block,
                                            const hb_ir_cfg_t* cfg, hb_codegen_buffer_t* out);

/* ★ ДИАГНОСТИЧЕСКИЙ ВХОД ЛЕЙНА CFG — маски по НАСТОЯЩЕМУ графу на ПОЛНОМ массиве команд,
 * без проекции на предел выпуска. Нужен потому, что приёмок ДВЕ и смешивать их нельзя:
 *   статическая  — решатель обязан краснеть от пересечения ВСЕГДА;
 *   сквозная     — снятие обязано ДОЙТИ ДО ЭМИТТЕРА.
 * Если сквозная зелена лишь потому, что неизвестный контракт перехода держит ВСЕ БИТЫ,
 * она контролем удаления НЕ СЧИТАЕТСЯ. Возвращает число заполненных позиций, 0 = граф
 * недоступен (гейт закрыт, построение неполно). Только для приборов, выпуск не трогает. */
size_t hb_cfg_masks_probe(const hb_ir_block_t* block, const hb_ir_cfg_t* cfg,
                          uint32_t* out_val, uint32_t* out_pub,
                          uint32_t* out_jcc_val, uint32_t* out_jcc_pub,
                          size_t max, size_t* out_passes);
hb_result_t hb_arm64_codegen_copy_scan_counted_loop(hb_arm64_codegen_t* cg,
                                                    const hb_ir_block_t* body,
                                                    const hb_ir_block_t* guard,
                                                    hb_codegen_buffer_t* out);
hb_result_t hb_arm64_codegen_bounded_scan_loop(hb_arm64_codegen_t* cg,
                                               const hb_ir_block_t* guard,
                                               const hb_ir_block_t* body,
                                               hb_codegen_buffer_t* out);
hb_result_t hb_arm64_codegen_two_block_loop_helper(hb_arm64_codegen_t* cg,
                                                   const hb_ir_block_t* first,
                                                   const hb_ir_block_t* second,
                                                   hb_codegen_buffer_t* out);
hb_result_t hb_arm64_codegen_four_block_loop_helper(hb_arm64_codegen_t* cg,
                                                    const hb_ir_block_t* first,
                                                    const hb_ir_block_t* second,
                                                    const hb_ir_block_t* third,
                                                    const hb_ir_block_t* fourth,
                                                    hb_codegen_buffer_t* out);
hb_result_t hb_arm64_codegen_i32_less_tiebreaker_helper(hb_arm64_codegen_t* cg,
                                                        const hb_ir_block_t* entry,
                                                        const hb_ir_block_t* equal,
                                                        const hb_ir_block_t* less,
                                                        hb_codegen_buffer_t* out);
hb_result_t hb_arm64_codegen_unity_sort_inner_loop_helper(hb_arm64_codegen_t* cg,
                                                          const hb_ir_block_t* sort,
                                                          hb_codegen_buffer_t* out);
hb_result_t hb_arm64_codegen_instr(hb_arm64_codegen_t* cg, const hb_ir_instr_t* instr, hb_codegen_buffer_t* out);

/* JIT buffer management */
typedef struct {
    uint8_t* writable;
    uint8_t* executable;
    size_t size;
    size_t used;
    size_t dirty_start;
    bool is_executable;
    bool thread_jit_write_protect;
    /* MacRunner 2026-08-23 — ДВОЙНОЕ ОТОБРАЖЕНИЕ (приём QEMU, region.c:615).
     * writable и executable указывают на ОДНУ И ТУ ЖЕ физическую память, отображённую
     * дважды: RW для записи и RX для исполнения. Тогда W^X переключать не нужно вовсе —
     * ни pthread_jit_write_protect_np, ни mprotect на каждый commit.
     * Поле в КОНЦЕ структуры: смещения прежних полей сохранены. */
    bool splitwx;
    uint64_t magic;
} hb_jit_buffer_t;

/* MacRunner 2026-08-23 — перевод адреса записи в адрес исполнения.
 * Без двойного отображения возвращает то же самое, поэтому вызов безопасен везде.
 * Со splitwx: писать надо по RW-адресу, а ОТДАВАТЬ наружу (в кеш блоков, в трамплины,
 * в печать) — RX-адрес, иначе прыжок уйдёт в неисполняемую половину. */
static inline uint8_t* hb_jit_rw_to_rx(const hb_jit_buffer_t* b, uint8_t* rw) {
    if (!b || !b->splitwx || !rw) return rw;
    return rw + ((uint8_t*)b->executable - (uint8_t*)b->writable);
}

/* ★★★ MacRunner 2026-09-04 — ОБРАТНЫЙ перевод: адрес ИСПОЛНЕНИЯ -> адрес ЗАПИСИ.
 *
 * Его НЕ БЫЛО, и это роняло раздельный W^X на первой же сшивке блоков. Кеш блоков и
 * `meta->in_trampoline` хранят RX-адрес (так и надо: по нему исполняют). Все заплаты
 * после commit — трамплинный слот, обе щели, снятие сшивки — писали ПО НЕМУ ЖЕ, а
 * RX-половина на запись закрыта. Отказ воспроизводится 1/1:
 *     macrunner-hb-sig: сигнал=10 addr=0x111818290 pc_sym=patch_block_tail
 * `hb_jit_buffer_make_writable` тут не помогает и помочь не может: под splitwx он
 * пустышка по построению — половины уже в нужных правах, переключать нечего.
 *
 * ★ ПЕРЕВОДИТЬ НАДО ТОЛЬКО ПРИЁМНИК ЗАПИСИ, И БОЛЬШЕ НИЧЕГО. Вся адресная
 * арифметика — досягаемость перехода, кодирование относительного перехода,
 * чистка кеша команд, значение, которое кладут в слот, — считается по адресу
 * ИСПОЛНЕНИЯ. Перевести их заодно значит промахнуться ровно на дельту двух
 * отображений, и промах будет МОЛЧАЛИВЫМ: `arm64_branch_reaches` пройдёт,
 * слово соберётся, а прыжок уйдёт в чужое место. Поэтому перевод спрятан
 * ВНУТРЬ записи слова (см. arm64_store_u32 в hb_runtime.c) — снаружи указатель
 * остаётся исполняемым, и спутать нечего.
 *
 * NULL означает «адрес не из RX-половины арены» — это отказ, а не «пиши как есть»:
 * молча писать по непереведённому адресу и есть тот дефект, против которого всё это. */
static inline uint8_t* hb_jit_rx_to_rw(const hb_jit_buffer_t* b, uint8_t* rx) {
    ptrdiff_t off;
    if (!b || !b->splitwx || !rx) return rx;
    off = rx - (uint8_t*)b->executable;
    if (off < 0 || (size_t)off >= b->size) return NULL;
    return (uint8_t*)b->writable + off;
}

hb_jit_buffer_t* hb_jit_buffer_create(size_t size);
void hb_jit_buffer_destroy(hb_jit_buffer_t* buf);
/* MacRunner: reset the bump pointer to reuse the (already-mmap'd) arena for a
 * fresh round of codegen without munmap/mmap. Translations are regenerated, so
 * callers MUST also clear any cache that points into this arena (block_cache). */
hb_result_t hb_jit_buffer_reset(hb_jit_buffer_t* buf);
hb_result_t hb_jit_buffer_commit(hb_jit_buffer_t* buf);
hb_result_t hb_jit_buffer_make_writable(hb_jit_buffer_t* buf);
/* Разделение прав ПОД splitwx, спрошенное у ядра: разбор при определении в hb_jit.c.
 * false — арена не раздельная, ответы не заполнены. */
bool hb_jit_buffer_halves_split(const hb_jit_buffer_t* buf,
                                int* rw_ispolnyaema, int* rx_pisucha);
hb_result_t hb_jit_buffer_make_executable(hb_jit_buffer_t* buf);
void hb_jit_buffer_flush_icache(hb_jit_buffer_t* buf);

/* Пер-сайтовый инлайн-кеш косвенных переходов.
 *
 * Слот заводится на КАЖДЫЙ косвенный переход в момент его трансляции и живёт столько
 * же, сколько сгенерированный код: сгенерированный код держит его абсолютный адрес
 * константой. Слот выровнен на 16 байт, чтобы пара (гость, натив) читалась одним ldp,
 * если позже понадобится.
 *
 * ОГОВОРКА О ГОНКЕ, которую нельзя потерять. В слоте лежит СЫРОЙ нативный адрес. Если
 * блок выселили (самомодификация, smc_evict), а слот не почистили, переход уйдёт в
 * освобождённую память. Поэтому hb_ic_slots_clear_all() зовётся из тех же мест, где
 * обнулялись общие поля, и из эвикции. Полностью гонку это не закрывает: поток,
 * успевший прочитать нативный адрес до чистки, уже прыгнет. Ровно тот же риск
 * принимает сцепление блоков, которое патчит переходы в чужой код. Новым классом риска
 * это не является, и стоит за своим гейтом. (Гейт MACRUNNER_HB_CHAIN_SCOPED_ROLLBACK,
 * который здесь упоминался, удалён 05.09.2026 вместе со снимком контекста: отказ в чужом
 * блоке цепочки теперь разрешается точной позицией по карте, откатывать нечего.) */
typedef struct {
    uint64_t guest;
    uint64_t native;
} hb_ic_slot_t;

hb_ic_slot_t* hb_ic_slot_alloc(void);
void hb_ic_slots_clear_all(void);
void hb_ic_slot_stats(uint64_t* allocated, uint64_t* exhausted, uint64_t* cleared);
/* ★ 07.09.2026, лейн ПОВТОРНЫЙ-ВЫПУСК — ОРАКУЛ ДЛЯ ПРИЁМКИ, не горячий путь.
 * Отвечает, держит ли ХОТЬ ОДИН слот названный нативный адрес. Нужен затем, что
 * счётчик `cleared` доказывает лишь ВЫЗОВ чистки, а не её результат: приёмка,
 * проверяющая счётчик, зеленела бы и при чистке, не убравшей ничего. Здесь
 * проверяется сам предмет — остался в кеше сырой указатель на старое тело или нет. */
bool hb_ic_slot_derzhit_native(uint64_t native);
/* Сколько слотов держат НЕНУЛЕВОЙ нативный адрес. Тоже оракул приёмки: он отличает
 * «кеш почищен» от «кеш и так был пуст», а без этого различения ноль после правки
 * не значил бы ничего. */
uint64_t hb_ic_slotov_zanyato(void);

/* Generic codegen helpers */
hb_codegen_buffer_t* hb_codegen_buffer_create(size_t cap);
void hb_codegen_buffer_destroy(hb_codegen_buffer_t* buf);
hb_result_t hb_codegen_buffer_append(hb_codegen_buffer_t* buf, const uint8_t* bytes, size_t len);

#ifdef __cplusplus
}
#endif

/* Сброс кешей гейтов кодогенератора. ТОЛЬКО ДЛЯ ПРОБ: гейт читается из окружения один раз
 * за процесс, поэтому `setenv` в пробе, выполненный после первого чтения, не действует.
 * Возвращает число сброшенных кешей; ОТРИЦАТЕЛЬНОЕ значение — реестр переполнялся, то есть
 * сброс НЕПОЛНЫЙ. Разбор и замер, ради которых заведено, — в hb_arm64_codegen.c у реестра. */
/* Регистрация кеша гейта, кеширующего ВРУЧНУЮ (значение наследуется или флаг
 * тестовый): без неё hb_arm64_codegen_gate_cache_reset() такой кеш не видит
 * и значение застревает на первом прочтении за процесс. */
void hb_gate_cache_register(int* cache);
int hb_arm64_codegen_gate_cache_reset(void);

#endif
