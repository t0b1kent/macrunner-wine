#ifndef HB_CONTEXT_H
#define HB_CONTEXT_H

#include "hb_result.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Guest architecture */
typedef enum {
    HB_ARCH_X64,
    HB_ARCH_X86
} hb_arch_t;

/* Execution backend */
typedef enum {
    HB_BACKEND_INTERP,
    HB_BACKEND_JIT,
    HB_BACKEND_AOT
} hb_backend_t;

/* Guest CPU mode */
typedef enum {
    HB_MODE_64BIT,
    HB_MODE_32BIT
} hb_mode_t;

/* Feature flags */
typedef struct {
    bool hyperbridge_enabled;
    int  mode; /* 0=off, 1=probe, 2=function, 3=module, 4=app */
    hb_arch_t arch;
    hb_backend_t backend;
    bool cache_enabled;
    bool trace_enabled;
    bool fallback_enabled;
} hb_config_t;

#define HB_CONTEXT_CODEGEN_MONO_MODULE 0x00000001u

/* Guest register file x64 */
typedef struct {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi;
    uint64_t rsp, rbp;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
    uint64_t rip;
    uint64_t rflags;
    /* XMM state stores the low 128 bits of XMM/YMM registers. */
    uint64_t xmm[16][2];
} hb_regs_x64_t;

typedef struct {
    uint16_t control_word;
    uint16_t status_word;
    uint16_t tag_word;
    uint16_t reserved0;
    uint32_t top;
    /* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 512 — АДРЕС ПОСЛЕДНЕЙ КОМАНДЫ x87 (FIP).
     * Занимаем бывшее `reserved1`, чтобы раскладка структуры не поехала: она входит в
     * состояние гостя, и её размер завязан на снимки. Поле пишется в образ окружения по
     * смещению 12 (`fnstenv`/`fnsave`). Замер 511: образ эталона совпал с нашим ВО ВСЁМ,
     * кроме этого поля — `FIP=0x100006`, адрес `fldl2e` из преамбулы. */
    uint32_t last_x87_ip;
    double st[8];
    /* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 516 — ТЕНЬ 80 БИТ (вариант B сметы 515).
     *
     * Считаем по-прежнему в `double`, но рядом храним точное 80-битное значение — там, где
     * оно пришло с полной точностью (постоянные FPU, `fld m80`, `frstor`, `fxrstor`). Бит в
     * `st_ext_valid` гасится при ЛЮБОЙ записи из арифметики, поэтому тень не может «протухнуть»
     * незаметно: она либо точна, либо объявлена негодной.
     *
     * Это же поле даёт 64-битную целую мантиссу, которой не хватало для наложения MMX. */
    uint8_t st_ext[8][10];
    uint8_t st_ext_valid;
} hb_x87_state_t;

/* Guest register file x86 */
typedef struct {
    uint32_t eax, ebx, ecx, edx;
    uint32_t esi, edi;
    uint32_t esp, ebp;
    uint32_t eip;
    uint32_t eflags;
    hb_x87_state_t x87;
    uint64_t xmm[8][2];
    /* Segment registers (i386-only — required by PUSH/POP ES/CS/SS/DS,
     * far CALL/JMP, RETF, IRET, etc.). Lane A only consumes eax..edi so
     * appending these at the END of the struct is safe (existing offsets
     * preserved). seg[0]=ES, seg[1]=CS, seg[2]=SS, seg[3]=DS, seg[4]=FS, seg[5]=GS. */
    uint16_t seg[6];

} hb_regs_x86_t;

/* Flags */
typedef struct {
    bool zf, sf, cf, of, pf, af;
} hb_flags_t;

typedef enum {
    HB_FLAG_BIT_ZF = 1u << 0,
    HB_FLAG_BIT_SF = 1u << 1,
    HB_FLAG_BIT_CF = 1u << 2,
    HB_FLAG_BIT_OF = 1u << 3,
    HB_FLAG_BIT_PF = 1u << 4,
    HB_FLAG_BIT_AF = 1u << 5,
    HB_FLAG_BIT_ALL = HB_FLAG_BIT_ZF | HB_FLAG_BIT_SF | HB_FLAG_BIT_CF |
                      HB_FLAG_BIT_OF | HB_FLAG_BIT_PF | HB_FLAG_BIT_AF
} hb_flag_bit_t;

typedef enum {
    HB_LAZY_FLAGS_NONE,
    HB_LAZY_FLAGS_ADD,
    HB_LAZY_FLAGS_ADC,
    HB_LAZY_FLAGS_SUB,
    HB_LAZY_FLAGS_SBB,
    HB_LAZY_FLAGS_AND,
    HB_LAZY_FLAGS_OR,
    HB_LAZY_FLAGS_XOR,
    HB_LAZY_FLAGS_SHL,
    HB_LAZY_FLAGS_SHR,
    HB_LAZY_FLAGS_SAR,
    HB_LAZY_FLAGS_CMP,
    HB_LAZY_FLAGS_TEST,
    HB_LAZY_FLAGS_UNKNOWN,
    /* Итерация 389 — INC/DEC. Считаются как ADD/SUB, но CF не заявляют, поэтому он остаётся
     * прежним. Дописаны В КОНЕЦ намеренно: значения выше уже могли попасть в сохранённые
     * записи кеша, и вставка в середину сдвинула бы их (тот же приём, что с HB_IR_X87_FISTTP). */
    HB_LAZY_FLAGS_INC,
    HB_LAZY_FLAGS_DEC
} hb_lazy_flags_kind_t;

typedef struct {
    bool pending;
    hb_lazy_flags_kind_t kind;
    uint8_t width;
    uint64_t lhs;
    uint64_t rhs;
    uint64_t result;
    uint64_t count;
    uint32_t valid_mask;
    uint32_t unsupported_mask;
    uint32_t materialized_mask;
} hb_lazy_flags_t;

/* Guest virtual address */
typedef uint64_t hb_gva_t;

/* Forward declaration for AOT cache handle */
struct hb_cache_ext;

/* Runtime context */
typedef struct hb_context hb_context_t;

/* Нумерация помощников: 1…55, нулевой слот не используется (0 = «не помощник»). */
#define HB_HELPER_TABLE_SLOTS 64u
/* Видов ленивых флагов шестнадцать (hb_lazy_flags_kind_t). Слот на вид. */
#define HB_LAZY_CONST_SLOTS 16u

/* ═══ ПЕРЕПИСЬ БЛОКИРУЮЩИХ ОПЕРАЦИЙ ГОСТЯ (05.09.2026) ═══
 *
 * ЗАЧЕМ. Величина любого решения про атомарные = ЧАСТОТА × ЦЕНА. Цена мерена
 * (reports/LSE-В-PE-МОДУЛЯХ-ПОСЫЛКА-ОПРОВЕРГНУТА-04.09.2026.md), частота — нет,
 * и это единственный несделанный сомножитель. Догадка тут не годится: одна
 * `lock cmpxchg` в цикле ожидания исполняется миллион раз, а сто разных
 * `lock or` — по разу.
 *
 * ПОЧЕМУ СЧЁТЧИКИ ЖИВУТ В КОНТЕКСТЕ, А НЕ В ГЛОБАЛЬНОМ МАССИВЕ. Выпущенный код
 * не может носить в себе хозяйский адрес: постоянный кеш правит только те
 * значения, которые умеет назвать (помощник / блок / команда), а всё прочее,
 * похожее на указатель, ОТКЛОНЯЕТ блок целиком (HB_RELOC_DECLINE_HOSTPTR,
 * hb_runtime.c:3279). Прибор, меняющий кешируемость ровно тех блоков, которые
 * он измеряет, — негодный прибор. Контекст же уже лежит в X19, поэтому счёт
 * стоит три команды без единой константы: ldr/add/str по смещению.
 *
 * Побочно контекст — ПОТОЧНЫЙ, поэтому счёт не требует атомарных команд: гонки
 * нет по построению. Это важно вдвойне, ведь мерим мы именно атомарные — прибор
 * на LSE искажал бы предмет замера.
 *
 * ★ Дописано В КОНЕЦ структуры — правило `helper_table`/`lazy_hdr`/`step_deadline`. */
typedef enum {
    HB_LKC_ADD = 0,   /* lock add/inc (inc лифтится в ADD) */
    HB_LKC_SUB,       /* lock sub/dec */
    HB_LKC_OR,
    HB_LKC_AND,
    HB_LKC_XOR,
    HB_LKC_BTS,
    HB_LKC_BTR,
    HB_LKC_BTC,
    HB_LKC_ADC_SBB,   /* lock adc/sbb — переноса нет ни у LSE, ни у пары */
    HB_LKC_NEG_NOT,
    HB_LKC_OTHER,     /* прочее с префиксом LOCK, выпущенное строкой */
    HB_LKC_N_INLINE,  /* ← граница: выше — выпущено СТРОКОЙ, ниже — ПОМОЩНИКОМ */

    /* Семья помощника. Она исполняется на C (`hb_jit_helper_exec_atomic_ir`), и
     * ИМЕННО В НЕЙ у нас LSE стоит БЕЗУСЛОВНО: Apple clang по умолчанию `apple-m1`,
     * поэтому `__atomic_compare_exchange_n(SEQ_CST)` выпускается как `casal`,
     * `__atomic_exchange_n` как `swpal`, `__atomic_fetch_add` как `ldaddal`. */
    HB_LKC_H_CMPXCHG = HB_LKC_N_INLINE,
    HB_LKC_H_CMPXCHG8B,
    HB_LKC_H_XCHG,
    HB_LKC_H_XADD,
    /* ★ ВТОРОЙ ЧЛЕН ФОРМУЛЫ. Цена CAS зависит от ИСХОДА сравнения, и знаки у двух
     * форм противоположны: у монитора неудача ВТРОЕ ДЕШЕВЛЕ удачи (1,426 против
     * 4,319 нс — записи нет, барьера освобождения нет), у `casal` неудача ВТРОЕ
     * ДОРОЖЕ (18,490 против 5,924). Перепись без этого разделения не даёт величину
     * даже с точностью до знака. */
    HB_LKC_H_CAS_OK,
    HB_LKC_H_CAS_FAIL,
    /* ★★★★★★★ 05.09.2026 — ВРЕД ОТ НЕАТОМАРНОГО СТРОЧНОГО ПУТИ, СНЯТЫЙ НА ЖИВОМ ПРОГОНЕ.
     *
     * Строчный путь терял приращения (стенд: 3 969 из 400 000 на i386). Стенд — не игра;
     * вопрос «а сколько теряется в НАСТОЯЩЕЙ игре» числом закрыт не был, и по построению
     * закрыт быть не мог: потерянное приращение неотличимо от законного значения ПОСЛЕ
     * того, как оно потеряно.
     *
     * Отвечает на него ЭТОТ счётчик, и отвечает уже на ВЫЛЕЧЕННОМ движке. В неделимом
     * помощнике окно старого пути воспроизводится точно — «прочитать значение, посчитать,
     * записать», — но записывает НЕДЕЛИМАЯ команда, и она возвращает СТАРОЕ значение.
     * Если оно не совпало с прочитанным в начале окна, значит в это самое окно вклинился
     * другой поток: старый путь здесь СЧИТАЛ БЫ ОТ УСТАРЕВШЕГО значения и потерял бы
     * приращение. Один такой случай = одно приращение, которое было бы потеряно.
     *
     * Это НИЖНЯЯ оценка, и надо сказать почему: окно детектора чуть короче старого — в
     * нём нет разбора кода операции и второго разрешения адреса при записи. */
    HB_LKC_H_RACE,
    /* Сколько раз быстрый ярус отступил в общую блокировку (нет хозяйского указателя:
     * невыровнено, пересекает строку кеша или адрес не отображён). Ярус остаётся
     * неделимым, но проходит через взаимное исключение; ноль здесь означает, что в
     * прогоне работал только быстрый. */
    HB_LKC_H_SPLIT,
    HB_LKC_N
} hb_lock_census_slot_t;

/* Сумма переписи по всем живым и всем УЖЕ УШЕДШИМ контекстам. `poteryano` —
 * сколько контекстов не поместилось в список (потолок прибора, обязан быть 0). */
void hb_lock_census_collect(uint64_t* out, unsigned slots, unsigned long long* poteryano);
/* Печать сводки переписи одной строкой `macrunner-hb-lock-census:`. */
void hb_lock_census_print(const char* povod);

struct hb_context {
    hb_arch_t arch;
    hb_mode_t mode;
    hb_backend_t backend;
    hb_config_t config;

    union {
        hb_regs_x64_t x64;
        hb_regs_x86_t x86;
    } regs;

    hb_flags_t flags;
    hb_lazy_flags_t lazy_flags;

    /* Memory sandbox handle */
    struct hb_memory* memory;

    /* Step counter */
    uint64_t step_count;
    uint64_t step_limit;

    /* Block counter */
    uint64_t block_count;
    uint64_t block_limit;


    /* Guest program counter */
    hb_gva_t pc;

    /* Guest segment bases. Windows x64 uses GS for the TEB. */
    uint64_t fs_base;
    uint64_t gs_base;

    /* Guest segment selectors. i386 CONTEXT capture stores these with MOV Sreg. */
    uint16_t seg_cs, seg_ds, seg_es, seg_fs, seg_gs, seg_ss;

    /* Exit status */
    int exit_code;
    hb_result_t last_result;

    /* Trace buffer */
    struct hb_trace* trace;

    /* Cache handle */
    struct hb_cache* cache;

    /* Thunk table */
    struct hb_thunk_table* thunks;

    /* AOT cache */
    uint64_t module_id;
    struct hb_cache_ext* aot_cache;

    /* User data */
    void* user_data;

    /* YMM high halves for interpreter AVX/AVX2 semantics. Appended to keep
       existing hb_context_t offsets stable for the ARM64 JIT lane. */
    uint64_t ymm_hi[16][2];

    /* ZMM bits 256..511 plus AVX-512 opmask state. Appended for interpreter
       EVEX semantics; existing XMM/YMM storage remains unchanged. */
    uint64_t zmm_hi[16][4];
    uint64_t k[8];

    /* Interpreter-only low/high storage for AVX-512 ZMM16..31. Kept appended so
       earlier hb_context_t offsets remain stable for existing ARM64 JIT code. */
    uint64_t xmm_ext[16][2];
    uint64_t ymm_hi_ext[16][2];
    uint64_t zmm_hi_ext[16][4];

    /* x86-32 guest address space base in the host virtual address space.
     * Set once at thread init from hb_memory_guest32_base(). Used by the
     * ARM64 JIT to convert 32-bit guest EAs to host pointers. Zero for x64. */
    uint64_t guest32_base;
    /* ★ 25.08.2026 — адрес ТЕНЕВОЙ КАРТЫ ПРАВ для выпущенного кода (см. hb_memory.h).
     * Ноль означает «карты нет» — тогда байтовая запись идёт прежним путём, через
     * помощника. Поле добавлено в конец группы, чтобы прежние смещения не поехали. */
    uint64_t perm_map_ptr;

    /* Per-current-block codegen policy. Appended so existing JIT offsets stay stable. */
    uint32_t codegen_flags;

    /* Dispatch fast-path state. Appended-only: generated code reaches these through
     * offsetof(), and default-off runs leave them unused. */
    uint64_t indirect_ic_guest_addr;
    uint64_t indirect_ic_native_code;

    /* Пер-сайтовый инлайн-кеш косвенных переходов (MACRUNNER_HB_INDIRECT_IC_PERSITE).
     * Два поля выше — ОДНА запись на весь процесс: каждый косвенный сайт вытесняет
     * все остальные, поэтому попаданий почти нет и гейт стоял выключенным. Здесь
     * сгенерированный код перед проверкой кладёт адрес СВОЕГО слота, и путь промаха
     * в hb_runtime.c заполняет именно его, а не общие поля. Дописано в конец: код
     * добирается сюда через offsetof(), выключенный гейт оставляет поле нулевым. */
    uint64_t indirect_ic_slot;

    /* Адрес потокового слота сигнального кадра, закешированный на поток
     * (MACRUNNER_HB_TLS_SLOT_CACHE). Дописано в конец: генерируемый код сюда не ходит. */
    void* jit_signal_frame_slot;

    /* Current PE module base for host-side block policy/probes. Appended-only:
     * generated code does not read this field. Zero when the current block has no
     * module classification. */
    uint64_t codegen_module_base;

    /* x87 state for x64 guests.  The legacy x86 register file embeds its x87
     * state, but the x64 register file historically did not.  Keep this field
     * appended so every established hb_context_t/JIT offset remains stable. */
    hb_x87_state_t x87_64;

    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: закешированная запись снимка контекста x64
     * этого потока. Позволяет пометить снимок грязным БЕЗ взятия мьютекса на каждый блок
     * (замер: сам мьютекс стоит ~10% времени). Дописано в конец — смещения не сдвигаются,
     * выпущенный код сюда не ходит. */
    void* x64_snapshot_entry;

    /* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 518 — РЕГИСТРЫ MMX В КОНТЕКСТЕ.
     *
     * До этого они жили в `static _Thread_local uint64_t mm_store[8]` внутри
     * `hb_interpreter.c` — то есть ВНЕ состояния гостя. Следствия были видны гостю: MMX не
     * сохранялся и не восстанавливался вместе с контекстом, не попадал в снимки и не был
     * виден `fnsave`/`fxsave`.
     *
     * Дописано в конец — установившиеся смещения не сдвигаются, выпущенный код сюда не ходит.
     * Наложение на стек x87 (архитектурно `MM(i)` — мантисса `ST(i)`) делается следующим
     * шагом: тень 80 бит из 516 даёт для него 64-битное целое поле. */
    uint64_t mm[8];

    /* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 769 — ПРИРОДА ОТКАЗА ИСПОЛНЕНИЯ.
     *
     * `HB_ERR_EXEC_FAULT` возвращается из мест с РАЗНОЙ гостевой семантикой: деление на
     * ноль и переполнение частного (архитектурно оба — #DE), переход по нулевому адресу,
     * отказ сторожа выпущенного кода. Наверху (`macrunner_hb.c`) это один и тот же код
     * возврата, поэтому доставить гостю правильное исключение было НЕЧЕМ: нужен либо
     * #DE (STATUS_INTEGER_DIVIDE_BY_ZERO), либо нарушение доступа.
     *
     * Поле заполняется ровно на пути отказа и читается ТОЛЬКО при `result == EXEC_FAULT`.
     * Дописано в конец — установившиеся смещения не сдвигаются. */
    uint32_t last_fault_kind;
    uint64_t last_fault_addr;
    /* Итерация 795: признак «адрес известен». Без него доставка не отличает «адреса нет» от
     * «адрес равен нулю», а у перехода по нулю он именно нулевой — и гость получал вместо
     * нуля адрес команды (замер 794: `addr=5368714641` вместо 0). Проверка на ноль здесь
     * негодна по существу, нужен отдельный признак. */
    uint8_t last_fault_addr_valid;
    /* Итерация 799: адрес КОМАНДЫ, вызвавшей отказ. Отдельно от `last_fault_addr`, который у
     * перехода по нулю равен ЦЕЛИ (нулю). Без этого доставка подставляла начало блока, и
     * таблица областей не находила `__try`: замер 798 — область `0x1400014bc..0x1400014bf`
     * (сам вызов), а сообщали `0x1400014b8`. */
    uint64_t last_fault_pc;
    /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1075 — MXCSR КАК НАСТОЯЩЕЕ СОСТОЯНИЕ.
     *
     * Раньше регистра не было вовсе: `LDMXCSR` был пустышкой, а `STMXCSR` писал в память
     * ПОСТОЯННУЮ 0x1f80 (`hb_decode_x64.c:4089-4090`). Замер 1069 это поймал: `stmxcsr`
     * расходится с эталоном по `data_hash`. Настоящему коду это не безразлично — в самом
     * движке записано, что игра делает `STMXCSR / cvtss2si / LDMXCSR`
     * (`hb_arm64_codegen.c:6505`), то есть сохраняет режим, меняет и возвращает.
     *
     * ★ Дописано В КОНЕЦ структуры, а не в середину: этот файл несколько раз повторяет, что
     * смещения `hb_context_t` завязаны на кодогенератор ARM64, и вставка в середину сдвинула
     * бы всё, что ниже. Сначала я вставил в середину и поймал себя ДО сборки — правило
     * записано в самом файле, читать его надо было раньше правки.
     *
     * Поле здесь, а НЕ в `hb_x87_state_t`: у той структуры раскладка входит в снимки. */
    uint32_t mxcsr;

    /* MacRunner 2026-08-19, лейн РЕГИСТРЫ — ТАБЛИЦА АДРЕСОВ ПОМОЩНИКОВ.
     *
     * Каждый вызов помощника укладывал его адрес ЧЕТЫРЬМЯ командами перед `blr`:
     * 875 517 раз на 685 131 настоящем блоке = 3 502 068 команд = 9,24 % всего
     * выпущенного кода. Адрес — константа времени сборки, а нумерация помощников уже
     * существует (`helper_addr_for_cache_id`, 1…55) и уже применяется в часовых
     * постоянного кеша. Отсюда `ldr x23, [x19, #таб + id*8]` — одна команда вместо
     * четырёх, экономия 6,93 % кода.
     *
     * ПОБОЧНО: адрес перестаёт стоять в коде, значит для этих мест не нужна запись в
     * таблице релокаций. Именно неизвестный помощник (`HB_RELOC_DECLINE_UNKNOWN_HELPER`)
     * был причиной отказов при сохранении блоков в кеш.
     *
     * ★ Дописано В КОНЕЦ структуры — правило записано выше и не мной. */
    void* helper_table[HB_HELPER_TABLE_SLOTS];
    /* MacRunner 2026-08-22, лейн РЕГИСТРЫ, итерация 135 — ПОСТОЯННЫЕ ЛЕНИВЫХ ФЛАГОВ ТАБЛИЦЕЙ.
     *
     * Замер на мишени приказа 2: укладка констант — 32,0 % выпуска, и 34 из её 78 слов идут в
     * `x16`/`x17`, то есть в ЗАГОЛОВОК и МАСКИ ленивых флагов. Обе величины выводятся из
     * `kind` — набор конечный, шестнадцать видов. Значит их можно не укладывать двумя
     * `movz`/`movk`, а читать одним `ldr` от `x19`, ровно как `helper_table` уже сделала с
     * адресами помощников.
     *
     * ★ Дописано В КОНЕЦ структуры — то же правило, что у `helper_table`: вставка в середину
     * сдвинула бы смещения, зашитые в уже сохранённый выпуск. Раскладка запечатана в версию
     * ключа кеша (`persistent_cache_version`), так что рост структуры даёт честный промах,
     * а не порчу. */
    uint64_t lazy_hdr[HB_LAZY_CONST_SLOTS];    /* 1 | (kind << 32) */
    uint64_t lazy_masks[HB_LAZY_CONST_SLOTS];  /* (unsupported << 32) | valid */

    /* MacRunner 2026-08-22, КООРДИНАТОР — ДИАГНОСТИКА ПОМОЩНИКА БЕЗ ПОТОКОВЫХ ПЕРЕМЕННЫХ.
     *
     * Замер: `_tlv_get_addr` — крупнейшая статья ОБОИХ путей (i386 14,13 %, x86-64 17,13 %),
     * и 34 % её приходят из `hb_jit_helper_exec_binop_operand_lazy`. Причина видна в машинном
     * коде: `hb_jit_helper_op_note` трогала ПЯТЬ потоковых переменных, а macOS на каждую даёт
     * отдельный косвенный вызов через дескриптор (`adrp`/`ldr`/`ldr`/`blr` — пять раз подряд,
     * f9fc..fa78). Микростенд: 0,41 нс на вызов, то есть ~2 нс на КАЖДЫЙ вызов помощника, а их
     * 21 вид на горячем пути.
     *
     * Три из пяти переменных писались и НЕ ЧИТАЛИСЬ НИГДЕ (`g_hb_helper_calls_total`,
     * `_calls_focus`, `_focus` — проверено сплошным поиском). Две оставшиеся читает ровно один
     * потребитель: печать смертельного отказа в `hb_runtime.c`, а у неё `ctx` уже на руках.
     * Значит место им здесь: запись идёт по указателю, который помощник и так держит в
     * регистре, — ноль вызовов вместо пяти, диагностика цела.
     *
     * ★ Дописано В КОНЕЦ — правило `helper_table` и `lazy_hdr`: вставка в середину сдвинула бы
     * смещения, зашитые в уже сохранённый выпуск. Версию ключа кеша НЕ двигаю сознательно:
     * выпущенный код этих полей не касается ни разу, существующие смещения не поехали, значит
     * сохранённые трансляции остаются верными и прогрев кеша не теряется. */
    int last_helper_op;                  /* hb_ir_op последней команды, ушедшей в помощника */
    unsigned long long last_helper_guest;/* её адрес у гостя */

    /* ═══ ПРОМАХ СТРАЖА ТРАМПЛИНА ═══
     *
     * Замер 03.09 дал противоречие, неразрешимое имевшимися приборами:
     * PATCHED=16437 при site_called=12 975 392 и avg_chain=1,0000 — рёбра
     * прошиты, а сцепления нет. Два объяснения, «прошитая ветвь не
     * достигается» и «страж промахивается всегда», различить было НЕЧЕМ: путь
     * промаха в трамплине это голый эпилог, неотличимый от обычного конца
     * блока.
     *
     * Стоит ОДНУ команду и только на ХОЛОДНОМ пути: x17 уже держит ожидаемый
     * гостевой адрес, x0 — контекст, значит промах записывает его сюда, а
     * считает C. На горячем пути попадания — ноль.
     *
     * Дописано в КОНЕЦ структуры: смещения зашиты в сохранённые трансляции. */
    uint64_t chain_mispredict;      /* ожидаемый гостевой адрес (x17) */
    uint64_t chain_mispredict_pc;   /* фактический ctx->pc (x16) — чтобы
                                     * видеть НА ЧТО они разошлись */

    /* ═══ СРОК: предел, выраженный в единицах СЧЁТЧИКА ═══
     *
     * Предел задан в шагах ПРОГОНА (местная переменная steps диспетчера), а
     * выпущенный код ведёт НАКОПИТЕЛЬНЫЙ step_count. Из-за этого проверка
     * предела жила только в диспетчере, а сцепление блоков её обходило — и
     * потому сцепление было выключено связкой step_limit==0 && block_limit==0.
     *
     * Срок снимает расхождение единиц: диспетчер, который знает и остаток
     * бюджета, и текущий счётчик, один раз переводит предел в ту же шкалу.
     * Выпущенному коду тогда не нужны понятия «прогон», «бюджет» и «предел» —
     * он сравнивает два числа. UINT64_MAX означает «срока нет»: сравнение
     * никогда не срабатывает, ветвь всегда предсказана. */
    uint64_t step_deadline;
    uint64_t block_deadline;
    /* ↑ ПЕРЕНЕСЕНО В КОНЕЦ 03.09.2026. Стояли перед `pc` и сдвинули его
     * с 544 на 560, а трамплин сцепления читал зашитое 544. Правило
     * «дописывать только в конец» записано в этом файле трижды. */

    /* Перепись блокирующих операций гостя — разбор у HB_LKC_* выше.
     * Пишется ВЫПУЩЕННЫМ кодом (ldr/add/str от X19), читается C. */
    uint64_t lock_census[HB_LKC_N];
};

/* Природа отказа исполнения (`ctx->last_fault_kind`). Ноль — «не заполнено». */
enum {
    HB_FAULT_KIND_NONE      = 0,
    HB_FAULT_KIND_DIVIDE    = 1,  /* #DE: деление на ноль ИЛИ переполнение частного */
    HB_FAULT_KIND_NULL_EXEC = 2,  /* переход/вызов по нулевому адресу */
    HB_FAULT_KIND_PRIVILEGED = 3, /* привилегированная команда при CPL=3 */
    HB_FAULT_KIND_GUARD_PAGE = 4, /* обращение к странице PAGE_GUARD: гостю положен 80000001 */
    /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1081 — НЕДОПУСТИМАЯ КОМАНДА (#UD).
     * `UD2` и родня — не «мы не умеем», а команда, которую сам процессор объявляет
     * недопустимой; гостю положен `c000001d`. Раньше она приходила как «опкод не
     * поддержан», то есть неотличимо от НАШЕГО пробела, и поток умирал. */
    HB_FAULT_KIND_ILLEGAL   = 5,
    /* ★★★★ MacRunner 2026-08-30, лейн УСТАНОВЩИКИ — ОТКАЗ СТЕКА x87 (#IA со знаком стека).
     *
     * Установщик Diablo (Delphi) ставит управляющее слово 0x1332, у которого бит IM = 0,
     * то есть недействительная операция НЕ ЗАМАСКИРОВАНА. При переполнении стека x87
     * `hb_x87_push_f64` честно отдаёт `EXEC_FAULT` — но вида отказа не было, и статус
     * падал в `default: STATUS_UNSUCCESSFUL` (`c0000001`). Гость видел «общий отказ»
     * вместо исключения сопроцессора и обработчика не звал.
     * Замер 30.08: `x87-overflow: top=0 tag=0x7fff cw=0x1332 sw=0x0000 im=0
     * pushes=320 pops=318` -> `interp-unsupported: r=-9 op=X87_FILD guest=0x403019`.
     * Гостю на это положен `c0000092` (STATUS_FLOAT_STACK_CHECK). */
    HB_FAULT_KIND_FPU_STACK = 6
};

/* Пометить отказ делением и вернуть код. Одна точка на оба исполнителя — семантика
 * команды у нас записана дважды (интерпретатор и помощник кодогенератора), и правка
 * одной копии уже дважды давала рассинхронизацию. */
/* Итерация 794: адрес КОМАНДЫ, а не блока. `ctx->pc` в момент работы помощника указывает на
 * начало блока, и гость, прибавив к нему длину `idiv`, попадал в середину другой команды —
 * замер 793: отдали 0x140001524, тогда как `idiv` лежит по 0x14000152b. */
static inline hb_result_t hb_fault_divide(hb_context_t* ctx, uint64_t instr_addr) {
    if (ctx) {
        ctx->last_fault_kind = HB_FAULT_KIND_DIVIDE;
        ctx->last_fault_addr = instr_addr ? instr_addr : ctx->pc;
        ctx->last_fault_addr_valid = 1;
        ctx->last_fault_pc = instr_addr ? instr_addr : ctx->pc;
    }
    return HB_ERR_EXEC_FAULT;
}

/* Переход или вызов по нулевому адресу. На настоящей Windows это нарушение доступа с
 * признаком ИСПОЛНЕНИЯ по адресу цели, а не чтение; Mono ловит его своим обработчиком и
 * превращает в управляемое исключение. `target` сохраняется, чтобы доставка называла
 * адрес, а не подставляла PC. */
static inline hb_result_t hb_fault_null_exec(hb_context_t* ctx, uint64_t target,
                                             uint64_t instr_addr) {
    if (ctx) {
        ctx->last_fault_kind = HB_FAULT_KIND_NULL_EXEC;
        ctx->last_fault_addr = target;
        ctx->last_fault_addr_valid = 1;
        ctx->last_fault_pc = instr_addr ? instr_addr : ctx->pc;
    }
    return HB_ERR_EXEC_FAULT;
}

/* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 939 — ПРИВИЛЕГИРОВАННАЯ КОМАНДА.
 *
 * Замер на Prism (настоящая Windows 11 ARM64, приказ 112 пункт 3) назвал код точно и
 * одинаково в обеих разрядностях: шестнадцать команд — `in`, `out`, `insb`, `outsb`, `hlt`,
 * `cli`, `sti`, `clts`, `invd`, `wbinvd`, `wrmsr`, `rdmsr`, `lldt`, `ltr`, `lmsw`, `invlpg` —
 * дают гостю `0xC0000096` (EXCEPTION_PRIV_INSTRUCTION).
 *
 * До этого они возвращали безликий `-5`/`EXEC_FAULT` без вида отказа, и сторона wine не имела
 * по чему их различить: все три ветви доставки смотрят именно на `last_fault_kind`. Программа,
 * поставившая обработчик на привилегированную команду (а это ходовой приём защиты от
 * отладчика), видела смерть процесса вместо своего обработчика.
 *
 * Адреса ЦЕЛИ у такого отказа нет — команда не обращается к памяти, — поэтому
 * `last_fault_addr` заполняется адресом самой команды, как у деления. */
static inline hb_result_t hb_fault_illegal(hb_context_t* ctx, uint64_t instr_addr) {
    if (ctx) {
        ctx->last_fault_kind = HB_FAULT_KIND_ILLEGAL;
        ctx->last_fault_addr = instr_addr ? instr_addr : ctx->pc;
        ctx->last_fault_addr_valid = 1;
        ctx->last_fault_pc = instr_addr ? instr_addr : ctx->pc;
    }
    return HB_ERR_EXEC_FAULT;
}

/* Отказ стека сопроцессора. Адреса цели нет — команда не обращается к памяти, — поэтому
 * как у деления и привилегии кладём адрес самой команды. */
static inline hb_result_t hb_fault_fpu_stack(hb_context_t* ctx, uint64_t instr_addr) {
    if (ctx) {
        ctx->last_fault_kind = HB_FAULT_KIND_FPU_STACK;
        ctx->last_fault_addr = instr_addr ? instr_addr : ctx->pc;
        ctx->last_fault_addr_valid = 1;
        ctx->last_fault_pc = instr_addr ? instr_addr : ctx->pc;
    }
    return HB_ERR_EXEC_FAULT;
}

static inline hb_result_t hb_fault_privileged(hb_context_t* ctx, uint64_t instr_addr) {
    if (ctx) {
        ctx->last_fault_kind = HB_FAULT_KIND_PRIVILEGED;
        ctx->last_fault_addr = instr_addr ? instr_addr : ctx->pc;
        ctx->last_fault_addr_valid = 1;
        ctx->last_fault_pc = instr_addr ? instr_addr : ctx->pc;
    }
    return HB_ERR_EXEC_FAULT;
}

static inline hb_x87_state_t* hb_context_x87(hb_context_t* ctx) {
    if (!ctx) return NULL;
    return ctx->mode == HB_MODE_64BIT ? &ctx->x87_64 : &ctx->regs.x86.x87;
}

static inline const hb_x87_state_t* hb_context_x87_const(const hb_context_t* ctx) {
    if (!ctx) return NULL;
    return ctx->mode == HB_MODE_64BIT ? &ctx->x87_64 : &ctx->regs.x86.x87;
}

hb_context_t* hb_context_create(hb_arch_t arch, hb_backend_t backend);
void hb_context_destroy(hb_context_t* ctx);
hb_result_t hb_context_reset(hb_context_t* ctx);
hb_result_t hb_context_set_pc(hb_context_t* ctx, hb_gva_t pc);
hb_result_t hb_context_set_step_limit(hb_context_t* ctx, uint64_t limit);
hb_result_t hb_context_set_block_limit(hb_context_t* ctx, uint64_t limit);

#ifdef __cplusplus
}
#endif

#endif
