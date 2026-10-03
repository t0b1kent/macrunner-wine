#include "hb_x87.h"
#include "hb_env.h"
#include "hb_gates.h"
#include <limits.h>
#include <stdio.h>
#include <math.h>
#include <string.h>

#define HB_X87_DEFAULT_CW 0x037f
#define HB_X87_EMPTY_TAG  0x3
#define HB_X87_STATUS_EXCEPTION_MASK 0x00ffu
#define HB_X87_STATUS_BUSY_MASK      0x8000u
#define HB_X87_CONTROL_INVALID_MASK  0x0001u
#define HB_X87_STATUS_INVALID        0x0001u
#define HB_X87_STATUS_STACK_FAULT    0x0040u
#define HB_X87_STATUS_C1             0x0200u

/* ★ ЗОНД ПЕРЕПОЛНЕНИЯ СТЕКА x87 — гейт MACRUNNER_HB_X87_PROBE=1, умолчание 0.
 *
 * Установщик Diablo умирает на FILD, потому что стек x87 ПОЛОН. Починка 29.08 сделала
 * переполнение маскированным, но Delphi ставит управляющее слово $1332, где маска
 * недействительной операции СНЯТА, — и маскированный путь до него не доходит.
 * Приборов x87 в движке не было ни одного: неизвестно ни реальное CW, ни баланс
 * PUSH/POP. Зонд печатает и то и другое, первые 8 переполнений, только под гейтом. */
static unsigned long long hb_x87_push_n, hb_x87_pop_n, hb_x87_ovf_n;
static int hb_x87_probe_on(void) {
    static int cached = -1;
    if (cached < 0) cached = hb_gate_flag( HB_GATE_HB_X87_PROBE, 0);
    return cached;
}

static unsigned phys_st(const hb_x87_state_t* x87, unsigned index) {
    return (x87->top + index) & 7u;
}

static void set_top(hb_x87_state_t* x87, unsigned top) {
    x87->top = top & 7u;
    x87->status_word = (uint16_t)((x87->status_word & ~(7u << 11)) | (x87->top << 11));
}

static bool tag_is_empty(const hb_x87_state_t* x87, unsigned phys) {
    return ((x87->tag_word >> (phys * 2u)) & 0x3u) == HB_X87_EMPTY_TAG;
}

static void set_tag(hb_x87_state_t* x87, unsigned phys, uint16_t tag) {
    uint16_t shift = (uint16_t)(phys * 2u);
    x87->tag_word = (uint16_t)((x87->tag_word & ~(0x3u << shift)) | ((tag & 0x3u) << shift));
}

static void set_condition_bits(hb_x87_state_t* x87, unsigned c0, unsigned c1,
                               unsigned c2, unsigned c3) {
    const uint16_t mask = (uint16_t)~((1u << 8) | (1u << 9) | (1u << 10) | (1u << 14));
    x87->status_word = (uint16_t)((x87->status_word & mask)
                                  | ((c0 & 1u) << 8) | ((c1 & 1u) << 9)
                                  | ((c2 & 1u) << 10) | ((c3 & 1u) << 14));
}

/*
 * x87 tag word encoding (per Intel SDM, Vol. 1, §8.1.5):
 *   00 = Valid (normal finite nonzero)
 *   01 = Zero (true +/-0.0)
 *   10 = Special (NaN, +/-inf, denormal, unsupported)
 *   11 = Empty
 *
 * fpclassify is the canonical way to determine the class of a double — keeps
 * the rule centralized rather than re-deriving it at every store site.
 */
static uint16_t tag_from_f64(double value) {
    switch (fpclassify(value)) {
        case FP_ZERO:      return 0x1u;  /* 01 = zero */
        case FP_NAN:       /* fallthrough */
        case FP_INFINITE:  /* fallthrough */
        case FP_SUBNORMAL: return 0x2u;  /* 10 = special */
        case FP_NORMAL:    /* fallthrough */
        default:           return 0x0u;  /* 00 = valid */
    }
}

void hb_x87_reset(hb_x87_state_t* x87) {
    if (!x87) return;
    memset(x87, 0, sizeof(*x87));
    x87->control_word = HB_X87_DEFAULT_CW;
    x87->tag_word = 0xffff;
    set_top(x87, 0);
}

hb_result_t hb_x87_fnclex(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    x87->status_word = (uint16_t)(x87->status_word &
        ~(HB_X87_STATUS_EXCEPTION_MASK | HB_X87_STATUS_BUSY_MASK));
    return HB_OK;
}

hb_result_t hb_x87_fninit(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    hb_x87_reset(x87);
    return HB_OK;
}

/* FINCSTP / FDECSTP — rotate TOP by +/-1, no value changes. The 8 physical
 * slots stay where they are; only the "ST(0)" pointer moves. Per Intel SDM,
 * this does NOT push or pop — it just changes which slot is ST(0). */
/* ★★★★ MacRunner 2026-08-30, лейн УСТАНОВЩИКИ — FFREE ST(i).
 *
 * Delphi заканчивает большой `FillChar` идиомой `FFREE ST(0); FINCSTP` (в установщике
 * Diablo это `40328e: dd c0` и `403290: d9 f7`). `FFREE` помечает слот свободным, а
 * `FINCSTP` двигает вершину — вместе это «снять значение, ничего не записывая».
 *
 * У нас `FFREE` поднимался в NOP (`hb_lift_x86.c`, комментарий «We model as NOP»),
 * поэтому тег слота оставался занятым, а вершина уходила дальше. Каждый вызов
 * `FillChar` терял один слот; на восьмом стек оказывался полон, и следующий `FILD`
 * в `System.Move` давал переполнение -> c0000092 -> InnoSetup отменял распаковку.
 * Замер: `x87-overflow: top=0 tag=0x7fff pushes=320 pops=318`, а трасса показала
 * `pc=0x40328e op=X87_FINCSTP top=7->0 tag=7fff->7fff` — тег не изменился.
 *
 * По руководству Intel FFREE меняет ТОЛЬКО тег; значение, вершина и флаги не трогаются. */
hb_result_t hb_x87_ffree(hb_x87_state_t* x87, unsigned index) {
    unsigned phys;

    if (!x87 || index >= 8) return HB_ERR_INVALID_ARG;
    phys = phys_st(x87, index);
    set_tag(x87, phys, HB_X87_EMPTY_TAG);
    x87->st_ext_valid &= (uint8_t)~(1u << phys);
    return HB_OK;
}

hb_result_t hb_x87_fincstp(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    set_top(x87, (x87->top + 1u) & 7u);
    return HB_OK;
}

hb_result_t hb_x87_fdecstp(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    set_top(x87, (x87->top - 1u) & 7u);
    return HB_OK;
}

/* FXAM — examine ST(0). Intel encodes the class in C3:C2:C0 and the
 * operand sign in C1:
 *   000 unsupported, 001 NaN, 010 normal, 011 infinity,
 *   100 zero, 101 empty, 110 denormal.
 */
hb_result_t hb_x87_fxam(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;

    unsigned phys = x87->top;
    double value = x87->st[phys];
    bool empty = tag_is_empty(x87, phys);
    unsigned c0, c2, c3;
    unsigned c1 = (!empty && signbit(value)) ? 1u : 0u;

    if (empty) {
        c3 = 1u; c2 = 0u; c0 = 1u;
    } else {
        switch (fpclassify(value)) {
            case FP_NAN:       c3 = 0u; c2 = 0u; c0 = 1u; break;
            case FP_INFINITE:  c3 = 0u; c2 = 1u; c0 = 1u; break;
            case FP_ZERO:      c3 = 1u; c2 = 0u; c0 = 0u; break;
            case FP_SUBNORMAL: c3 = 1u; c2 = 1u; c0 = 0u; break;
            case FP_NORMAL:    c3 = 0u; c2 = 1u; c0 = 0u; break;
            default:           c3 = 0u; c2 = 0u; c0 = 0u; break;
        }
    }

    set_condition_bits(x87, c0, c1, c2, c3);
    return HB_OK;
}

static void set_fprem_condition_bits(hb_x87_state_t* x87, double quotient) {
    if (!isfinite(quotient) || fabs(quotient) > (double)LLONG_MAX) {
        set_condition_bits(x87, 0, 0, 1, 0);
        return;
    }

    long long q = (long long)quotient;
    unsigned low = (unsigned)((q < 0 ? -q : q) & 7);
    set_condition_bits(x87, (low >> 2) & 1u, low & 1u, 0, (low >> 1) & 1u);
}

/* QNaN indefinite для x87: знак 1, экспонента все единицы, старший бит мантиссы 1.
 * Собираем через объединение, а не литералом: NAN из math.h не гарантирует знак. */
static double hb_x87_indefinite_f64(void) {
    union { uint64_t u; double d; } v;
    v.u = 0xFFF8000000000000ull;
    return v.d;
}

hb_result_t hb_x87_push_f64(hb_x87_state_t* x87, double value) {
    unsigned top;

    if (!x87) return HB_ERR_INVALID_ARG;
    ++hb_x87_push_n;
    top = (x87->top - 1u) & 7u;

    /* ★★★★★★ MacRunner 2026-08-29 — ПЕРЕПОЛНЕНИЕ СТЕКА x87 НЕ ОБРЫВАЕТ ИСПОЛНЕНИЕ.
     *
     * Здесь стоял безусловный `return HB_ERR_EXEC_FAULT`, и любой лишний PUSH убивал
     * прогон. На настоящем x86 это не так: переполнение стека — «недействительная
     * операция» со ЗНАКОМ СТЕКА, и исключение #IA по умолчанию ЗАМАСКИРОВАНО (бит IM
     * управляющего слова, начальное значение 0x037F — все маски взведены). Маскированное
     * поведение по руководству Intel (том 1, 8.5.1): установить IE и SF в статусном слове,
     * C1 = 1 (переполнение, а не потеря значимости), записать в приёмник QNaN indefinite
     * и ПРОДОЛЖИТЬ. Прерывать работу процессор обязан только при снятой маске.
     *
     * Чего это стоило: установщик Diablo (Delphi/InnoSetup) считает на x87 длины и
     * смещения строк. Обрыв на PUSH давал неверные вычисления, и имя DLL приходило с
     * испорченным ПЕРВЫМ БАЙТОМ КАЖДОГО ФРАГМЕНТА склейки:
     *   C:\windows\system32\shell32.dll  ->  D:\windows\systdm32\thell320dll
     *      ^          ^       ^         ^      (позиции 0, 15, 20, 27 — начала фрагментов)
     * Эталон (CrossOver) на том же файле грузит `shell32.dll` тринадцать раз без единого
     * искажения — то есть дефект был наш.
     *
     * Признак в журнале: `interp-unsupported: r=-9 op=X87_FILD`, где -9 это EXEC_FAULT,
     * а вовсе не «не поддержано»: FILD реализован, падал именно PUSH. */
    if (!tag_is_empty(x87, top)) {
        const uint16_t IE = 0x0001u, SF = 0x0040u, C1 = 0x0200u, ES = 0x0080u, B = 0x8000u;
        if (hb_x87_probe_on() && ++hb_x87_ovf_n <= 8)
            fprintf(stderr, "macrunner-hb-x87-overflow: n=%llu top=%u tag=0x%04x cw=0x%04x sw=0x%04x im=%u pushes=%llu pops=%llu\n",
                    hb_x87_ovf_n, x87->top, (unsigned)x87->tag_word, (unsigned)x87->control_word,
                    (unsigned)x87->status_word, (unsigned)(x87->control_word & 1u),
                    hb_x87_push_n, hb_x87_pop_n);
        const uint16_t IM = 0x0001u;                 /* маска недействительной операции */
        x87->status_word |= (uint16_t)(IE | SF | C1);
        if (!(x87->control_word & IM)) {
            /* Маска снята — исключение доходит до гостя, как на железе. */
            x87->status_word |= (uint16_t)(ES | B);
            return HB_ERR_EXEC_FAULT;
        }
        /* Маскированный путь: приёмник получает QNaN indefinite, работа продолжается. */
        set_top(x87, top);
        x87->st[top] = hb_x87_indefinite_f64();
        x87->st_ext_valid &= (uint8_t)~(1u << top);
        set_tag(x87, top, tag_from_f64(x87->st[top]));   /* NaN -> метка «особое» */
        return HB_OK;
    }
    set_top(x87, top);
    x87->st[top] = value;
    x87->st_ext_valid &= (uint8_t)~(1u << top);   /* итерация 516: тень гасим */
    set_tag(x87, top, tag_from_f64(value));
    return HB_OK;
}

hb_result_t hb_x87_push_f64_ext(hb_x87_state_t* x87, double value, const uint8_t ext[10]) {
    hb_result_t r = hb_x87_push_f64(x87, value);
    if (r != HB_OK || !ext) return r;
    memcpy(x87->st_ext[x87->top], ext, 10);
    x87->st_ext_valid |= (uint8_t)(1u << x87->top);
    return HB_OK;
}

/* ★★★★★★ MacRunner 2026-08-30, лейн УСТАНОВЩИКИ — FILD m64 / FISTP m64 БЕЗ ПОТЕРИ БИТ.
 *
 * Delphi копирует память ЧЕРЕЗ x87: `System.Move` в цикле делает
 * `fildll (%ecx,%eax)` / `fistpll (%ecx,%edx)` — по 8 байт как 64-битное целое
 * (в установщике Diablo это адреса 0x403030/0x403033).
 *
 * У настоящего x87 регистр 80-битный: мантисса 64 бита, и такой перенос ТОЧЕН.
 * У нас `x87->st[]` объявлен `double` — мантисса 53 бита. Значение, которому нужно
 * больше 53 бит, ОКРУГЛЯЕТСЯ, и копия отличается от оригинала.
 *
 * Замер (не гипотеза): все ЧЕТЫРЕ наблюдённые порчи имени DLL воспроизводятся
 * точным вычислением `(int64)(double)v` над теми же 8 байтами UTF-16:
 *
 *   "C:\w" 0077005c003a0043 -> ...0044   C -> D   (нужно 55 бит, теряем 2)
 *   "em32" 00320033006d0065 -> ...0064   e -> d   (54 бита, теряем 1)
 *   "shel" 006c006500680073 -> ...0074   s -> t   (55 бит, теряем 2)
 *   ".dll" 006c006c0064002e -> ...0030   . -> 0   (55 бит, теряем 2)
 *
 * Отсюда и формула порчи `(v+2)&~3`, замеченная раньше: это округление к
 * ближайшему при потере двух младших бит. Портится ВСЕГДА младшее 16-битное
 * слово фрагмента — то есть первый символ каждого копируемого куска.
 *
 * ВАЖНО: соседний комментарий выше (переполнение стека, 29.08) приписывает эту же
 * порчу обрыву на PUSH. Это неверно: обрыв убран, порча осталась — в прогоне 30.08
 * `x87ctx-bad 0`, `interp-unsupported 0`, а порча те же 6 строк.
 *
 * Лечение — не менять тип `st[]` (на macOS ARM64 `long double` это тот же двойной
 * формат, шире не станет), а положить ТОЧНОЕ значение в уже готовую тень 80 бит
 * (механизм итерации 516) и брать его обратно при FISTP, пока регистр не тронут
 * арифметикой: любая запись в регистр тень гасит (строки 300, 313).
 *
 * Гейт `MACRUNNER_HB_X87_EXACT_I64`, умолчание 1; 0 даёт прежнее поведение
 * для парного замера на ОДНОМ двоичном. */
static void hb_x87_ext80_from_i64(int64_t v, uint8_t out[10]) {
    uint64_t u;
    unsigned sign = 0;
    int p;
    uint16_t se;

    memset(out, 0, 10);
    if (v == 0) return;                       /* +0.0: экспонента и мантисса нули */
    if (v < 0) { sign = 1; u = (uint64_t)(-(v + 1)) + 1u; } else u = (uint64_t)v;
    p = 63;
    while (!((u >> p) & 1u)) --p;             /* старший установленный бит */
    u <<= (unsigned)(63 - p);                 /* явная единица в бит 63 */
    se = (uint16_t)(((uint16_t)sign << 15) | (uint16_t)(16383 + p));
    memcpy(out, &u, 8);
    memcpy(out + 8, &se, 2);
}

/* Возвращает 1, если тень описывает ТОЧНОЕ целое, помещающееся в int64. */
static int hb_x87_i64_from_ext80(const uint8_t in[10], int64_t* out) {
    uint64_t m, mag;
    uint16_t se;
    unsigned sign;
    int e, p;

    memcpy(&m, in, 8);
    memcpy(&se, in + 8, 2);
    sign = (unsigned)((se >> 15) & 1u);
    e = (int)(se & 0x7FFFu);
    if (e == 0 && m == 0) { *out = 0; return 1; }
    if (e == 0 || e == 0x7FFF) return 0;      /* денормаль, бесконечность, NaN */
    if (!(m >> 63)) return 0;                 /* нет явной единицы — не нормаль */
    p = e - 16383;
    if (p < 0 || p > 62) return 0;            /* дробное или вне диапазона int64 */
    if (63 - p > 0 && (m & (((uint64_t)1 << (63 - p)) - 1u)) != 0) return 0;  /* не целое */
    mag = m >> (unsigned)(63 - p);
    *out = sign ? -(int64_t)mag : (int64_t)mag;
    return 1;
}

hb_result_t hb_x87_push_i64_exact(hb_x87_state_t* x87, int64_t value) {
    uint8_t ext[10];

    hb_x87_ext80_from_i64(value, ext);
    return hb_x87_push_f64_ext(x87, (double)value, ext);
}

hb_result_t hb_x87_st_ext80(const hb_x87_state_t* x87, unsigned index, uint8_t out[10]) {
    unsigned phys;
    if (!x87 || !out || index >= 8) return HB_ERR_INVALID_ARG;
    phys = phys_st(x87, index);
    if (!(x87->st_ext_valid & (1u << phys))) return HB_ERR_UNSUPPORTED_FEATURE;
    memcpy(out, x87->st_ext[phys], 10);
    return HB_OK;
}

hb_result_t hb_x87_pop(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    ++hb_x87_pop_n;
    if (tag_is_empty(x87, x87->top)) return HB_ERR_EXEC_FAULT;
    set_tag(x87, x87->top, HB_X87_EMPTY_TAG);
    set_top(x87, (x87->top + 1u) & 7u);
    return HB_OK;
}

/* Once FSTP has completed its destination store, the architectural pop occurs
 * even when the masked source underflow left the old TOP slot empty. */
hb_result_t hb_x87_fstp_pop(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    ++hb_x87_pop_n;
    set_tag(x87, x87->top, HB_X87_EMPTY_TAG);
    set_top(x87, (x87->top + 1u) & 7u);
    return HB_OK;
}

/* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 891 — ЧТЕНИЕ ПУСТОГО РЕГИСТРА СТЕКА.
 *
 * Здесь стоял безусловный `HB_ERR_EXEC_FAULT`, то есть команда СВАЛИВАЛАСЬ. Это неверно:
 * после `FNINIT` управляющее слово маскирует недопустимую операцию, и переполнение стека вниз
 * обязано поставить IE и SF, снять C1 и дать «неопределённость» QNaN — исполнение при этом
 * продолжается. Отказ правилен только при СНЯТОЙ маске.
 *
 * Ровно это делает `hb_x87_stack_underflow()`, написанный в дереве заранее и НЕ ВЫЗЫВАВШИЙСЯ
 * ниоткуда (0 вызовов на момент правки) — его же комментарий обещает «materialize the masked
 * invalid response for an empty x87 source».
 *
 * Правка одноточечная намеренно: `hb_x87_st_f64` — единственная дверь чтения ИСТОЧНИКА, через
 * неё идут все 39 мест (25 в этом файле, 14 в интерпретаторе). Патчить их по одному значило бы
 * развести расхождение. `FXAM` пустоту смотрит отдельно (`tag_is_empty`) и не затронут.
 *
 * Замер до правки: `fadd st(4)` при пустом ST(4) -> result=-9, при занятом -> 0; эталон
 * исполняет и не падает. По стенду это 86 отказов из 92. */
hb_result_t hb_x87_st_f64(hb_x87_state_t* x87, unsigned index, double* out) {
    unsigned phys;

    if (!x87 || !out || index >= 8) return HB_ERR_INVALID_ARG;
    phys = phys_st(x87, index);
    if (tag_is_empty(x87, phys)) return hb_x87_stack_underflow(x87, out);
    *out = x87->st[phys];
    return HB_OK;
}

hb_result_t hb_x87_set_st_f64(hb_x87_state_t* x87, unsigned index, double value) {
    unsigned phys;

    if (!x87 || index >= 8) return HB_ERR_INVALID_ARG;
    phys = phys_st(x87, index);
    /* Итерация 891, вторая половина: ПУСТОЙ ПРИЁМНИК арифметики. Формы с выталкиванием
     * (`faddp st(i), st(0)` и родня) пишут результат в ST(i); если тот пуст, это то же
     * маскированное переполнение стека, а не повод свалить команду: ответ — «неопределённость»
     * в приёмник, затем штатное выталкивание. Отказ остаётся только при СНЯТОЙ маске, и об этом
     * судит сам `hb_x87_stack_underflow`.
     * Замер до правки: 18 отказов, все формы с `p` (faddp, fsubp, fdivp, fmulp, fsubrp, fdivrp). */
    if (tag_is_empty(x87, phys)) {
        double indefinite;
        hb_result_t ru = hb_x87_stack_underflow(x87, &indefinite);
        if (ru != HB_OK) return ru;          /* маска снята — отказ правилен */
        value = indefinite;
    }
    x87->st[phys] = value;
    x87->st_ext_valid &= (uint8_t)~(1u << phys);   /* итерация 516 */
    set_tag(x87, phys, tag_from_f64(value));
    return HB_OK;
}

/* FST/FSTP may write an empty destination register.  This differs from
 * arithmetic result replacement, where an empty ST(i) is itself underflow. */
hb_result_t hb_x87_store_st_f64(hb_x87_state_t* x87, unsigned index, double value) {
    unsigned phys;

    if (!x87 || index >= 8) return HB_ERR_INVALID_ARG;
    phys = phys_st(x87, index);
    x87->st[phys] = value;
    x87->st_ext_valid &= (uint8_t)~(1u << phys);   /* итерация 516 */
    set_tag(x87, phys, tag_from_f64(value));
    return HB_OK;
}

/* Materialize the masked-invalid response for an empty x87 source.  The
 * instruction owns any subsequent destination write/pop so memory faults
 * still suppress the pop.  With IM clear, preserve the synchronous fault. */
hb_result_t hb_x87_stack_underflow(hb_x87_state_t* x87, double* indefinite) {
    const uint64_t indefinite_bits = UINT64_C(0xfff8000000000000);

    if (!x87 || !indefinite) return HB_ERR_INVALID_ARG;
    x87->status_word = (uint16_t)((x87->status_word |
        HB_X87_STATUS_INVALID | HB_X87_STATUS_STACK_FAULT) & ~HB_X87_STATUS_C1);
    if (!(x87->control_word & HB_X87_CONTROL_INVALID_MASK)) return HB_ERR_EXEC_FAULT;
    memcpy(indefinite, &indefinite_bits, sizeof(*indefinite));
    return HB_OK;
}

hb_result_t hb_x87_fcom(hb_x87_state_t* x87, double rhs) {
    double lhs;
    uint16_t sw;

    if (!x87) return HB_ERR_INVALID_ARG;
    if (hb_x87_st_f64(x87, 0, &lhs) != HB_OK) return HB_ERR_EXEC_FAULT;

    sw = (uint16_t)(x87->status_word & ~(uint16_t)((1u << 8) | (1u << 10) | (1u << 14)));
    if (isnan(lhs) || isnan(rhs)) {
        sw |= (uint16_t)((1u << 8) | (1u << 10) | (1u << 14));
    } else if (lhs < rhs) {
        sw |= (uint16_t)(1u << 8);
    } else if (lhs == rhs) {
        sw |= (uint16_t)(1u << 14);
    }
    x87->status_word = sw;
    return HB_OK;
}

hb_result_t hb_x87_fldcw(hb_x87_state_t* x87, uint16_t control_word) {
    if (!x87) return HB_ERR_INVALID_ARG;
    x87->control_word = control_word;
    return HB_OK;
}

hb_result_t hb_x87_fnstcw(const hb_x87_state_t* x87, uint16_t* out) {
    if (!x87 || !out) return HB_ERR_INVALID_ARG;
    *out = x87->control_word;
    return HB_OK;
}

/* Итерация 891: снят const — чтение ST(0) теперь может выставить флаги маскированного
 * переполнения стека (см. hb_x87_st_f64). Побочных действий помимо этих флагов нет. */
static hb_result_t round_st0(hb_x87_state_t* x87, double* out) {
    double value;
    uint16_t rc;

    if (!x87 || !out) return HB_ERR_INVALID_ARG;
    if (hb_x87_st_f64(x87, 0, &value) != HB_OK) return HB_ERR_EXEC_FAULT;

    rc = (uint16_t)((x87->control_word >> 10) & 3u);
    switch (rc) {
        case 0: *out = nearbyint(value); break;
        case 1: *out = floor(value); break;
        case 2: *out = ceil(value); break;
        default: *out = trunc(value); break;
    }
    return HB_OK;
}

hb_result_t hb_x87_frndint(hb_x87_state_t* x87) {
    double rounded;

    if (!x87) return HB_ERR_INVALID_ARG;
    if (round_st0(x87, &rounded) != HB_OK) return HB_ERR_EXEC_FAULT;
    return hb_x87_set_st_f64(x87, 0, rounded);
}

hb_result_t hb_x87_fistp_i16(hb_x87_state_t* x87, int16_t* out) {
    double rounded;

    if (!out) return HB_ERR_INVALID_ARG;
    if (round_st0(x87, &rounded) != HB_OK) return HB_ERR_EXEC_FAULT;
    if (rounded > (double)INT16_MAX || rounded < (double)INT16_MIN) return HB_ERR_EXEC_FAULT;
    *out = (int16_t)rounded;
    return hb_x87_pop(x87);
}

hb_result_t hb_x87_fistp_i32(hb_x87_state_t* x87, int32_t* out) {
    double rounded;

    if (!out) return HB_ERR_INVALID_ARG;
    if (round_st0(x87, &rounded) != HB_OK) return HB_ERR_EXEC_FAULT;
    if (rounded > (double)INT_MAX || rounded < (double)INT_MIN) return HB_ERR_EXEC_FAULT;
    *out = (int32_t)rounded;
    return hb_x87_pop(x87);
}

hb_result_t hb_x87_fistp_i64(hb_x87_state_t* x87, int64_t* out) {
    double rounded;

    if (!out) return HB_ERR_INVALID_ARG;
    /* ★ 30.08 — сначала ТОЧНАЯ тень: если регистр после FILD не трогали арифметикой,
     * отдаём исходные 64 бита без округления через double. См. пояснение выше. */
    /* Гейт MACRUNNER_HB_X87_EXACT_I64 снят 02.09.2026: выключенная ветка теряла
     * точность, приводя i64 к double. Точный путь безусловен. */
    uint8_t ext[10];
    int64_t exact;
    if (hb_x87_st_ext80(x87, 0, ext) == HB_OK && hb_x87_i64_from_ext80(ext, &exact)) {
        *out = exact;
        return hb_x87_pop(x87);
    }
    if (round_st0(x87, &rounded) != HB_OK) return HB_ERR_EXEC_FAULT;
    if (rounded > (double)LLONG_MAX || rounded < (double)LLONG_MIN) return HB_ERR_EXEC_FAULT;
    *out = (int64_t)rounded;
    return hb_x87_pop(x87);
}

/* FIST = non-popping integer store: round ST(0) to integer, write to memory,
 * leave the FPU stack unchanged. Per Intel SDM, FIST raises IE if the rounded
 * result is out-of-range or the source is NaN/Inf; on real chips the IE bit
 * is set in SW, but we do not yet track exception flags (gap matrix #3).
 * We still return HB_ERR_EXEC_FAULT for the out-of-range case because most
 * caller code paths treat that as a real fault. */
hb_result_t hb_x87_fist_i16(hb_x87_state_t* x87, int16_t* out) {
    double rounded;

    if (!out) return HB_ERR_INVALID_ARG;
    if (round_st0(x87, &rounded) != HB_OK) return HB_ERR_EXEC_FAULT;
    if (rounded > (double)INT16_MAX || rounded < (double)INT16_MIN) return HB_ERR_EXEC_FAULT;
    *out = (int16_t)rounded;
    return HB_OK;
}

hb_result_t hb_x87_fist_i32(hb_x87_state_t* x87, int32_t* out) {
    double rounded;

    if (!out) return HB_ERR_INVALID_ARG;
    if (round_st0(x87, &rounded) != HB_OK) return HB_ERR_EXEC_FAULT;
    if (rounded > (double)INT_MAX || rounded < (double)INT_MIN) return HB_ERR_EXEC_FAULT;
    *out = (int32_t)rounded;
    return HB_OK;
}

/* ============================================================
 * D9 F0-FF transcendentals (libm-backed).
 *
 * Each function reads ST(0) (and ST(1) for binary ops), replaces the result
 * in the documented slot, and pops or pushes per Intel SDM. We do not yet
 * raise exception flags for edge cases (denormal, invalid, partial-remainder
 * C0..C3 bits); that is gap matrix #3 (status word exception bits). The
 * fuzzer accepts this.
 *
 * Note: real x87 uses 80-bit extended precision internally; we use double
 * (53-bit mantissa). The fuzz harness runs at random doubles, so single-ulp
 * mismatches from libm vs x87 are accepted. fyl2x/fyl2xp1/cordic-precision
 * transcendentals typically agree to < 1ulp on well-conditioned inputs.
 * ============================================================ */

hb_result_t hb_x87_fsqrt(hb_x87_state_t* x87) {
    double value, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;
    result = sqrt(value);
    /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 904 — знак QNaN indefinite.
     * Хозяин ARM64 на sqrt(отрицательное) даёт 7ff8…, x86 требует fff8… (знак взведён) —
     * ту же константу этот файл уже использует при опустошении стека. Вход-NaN не трогаем:
     * его x86 распространяет, а не заменяет на indefinite. */
    {
        uint64_t src_bits, res_bits;
        memcpy(&src_bits, &value, sizeof(src_bits));
        memcpy(&res_bits, &result, sizeof(res_bits));
        if ((res_bits & UINT64_C(0x7ff0000000000000)) == UINT64_C(0x7ff0000000000000) &&
            (res_bits & UINT64_C(0x000fffffffffffff)) != 0 &&
            !((src_bits & UINT64_C(0x7ff0000000000000)) == UINT64_C(0x7ff0000000000000) &&
              (src_bits & UINT64_C(0x000fffffffffffff)) != 0)) {
            const uint64_t indefinite_bits = UINT64_C(0xfff8000000000000);
            memcpy(&result, &indefinite_bits, sizeof(result));
        }
    }
    return hb_x87_set_st_f64(x87, 0, result);
}

hb_result_t hb_x87_f2xm1(hb_x87_state_t* x87) {
    /* ST(0) = 2^ST(0) - 1. No pop. */
    double value, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;
    result = exp2(value) - 1.0;
    return hb_x87_set_st_f64(x87, 0, result);
}

hb_result_t hb_x87_fyl2x(hb_x87_state_t* x87) {
    /* ST(1) = ST(1) * log2(ST(0)); pop 1. */
    double a, b, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &a);   /* log2 arg */
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(x87, 1, &b);   /* multiplier */
    if (r != HB_OK) return r;
    result = b * log2(a);
    r = hb_x87_set_st_f64(x87, 1, result);
    if (r != HB_OK) return r;
    return hb_x87_pop(x87);
}

hb_result_t hb_x87_fptan(hb_x87_state_t* x87) {
    /* ST(0) = tan(ST(0)); push 1.0. */
    double value, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;
    result = tan(value);
    r = hb_x87_set_st_f64(x87, 0, result);
    if (r != HB_OK) return r;
    return hb_x87_push_f64(x87, 1.0);
}

hb_result_t hb_x87_fpatan(hb_x87_state_t* x87) {
    /* ST(1) = atan2(ST(1), ST(0)); pop 1.
     * Note: Intel's FPATAN computes arctan(ST(1)/ST(0)) — that's atan2 with
     * ST(1) as Y and ST(0) as X, which keeps the correct quadrant when X<0. */
    double y, x, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &x);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(x87, 1, &y);
    if (r != HB_OK) return r;
    result = atan2(y, x);
    r = hb_x87_set_st_f64(x87, 1, result);
    if (r != HB_OK) return r;
    return hb_x87_pop(x87);
}

hb_result_t hb_x87_fxtract(hb_x87_state_t* x87) {
    /* ★ 05.09.2026 — ПОЛОВИНКИ КЛАЛИСЬ НАОБОРОТ.
     *
     * Спецификация (Intel SDM, том 2, FXTRACT): «stores the exponent in ST(0),
     * and pushes the significand onto the register stack» — то есть ПОСЛЕ
     * команды ST(0) = МАНТИССА (её только что положили сверху), ST(1) =
     * ПОРЯДОК. Здесь стояло обратное: ST(0) := мантисса, а затем на стек
     * клался порядок, — и он оказывался наверху. Комментарий описывал ту же
     * перестановку, поэтому расхождения кода и записи не было видно.
     *
     * Замер (оракул Bochs, вход ST(0) = log2(e) = 1,4426950408889634,
     * хвост `FSTP qword [rdi]`): процессор кладёт в память 1,4426950408889634
     * (мантисса, порядок 0), мы клали 0 (порядок). Ошибка ровно в порядке
     * двух присваиваний; сами величины считались верно.
     *
     * Файл общий для обеих ветвей, поэтому дефект был и на i386, и на x64 —
     * но виден стал только когда x64 научился ЗВАТЬ FXTRACT: до 05.09 декодер
     * x64 сваливал весь диапазон D9 E0..FF в заглушку-NOP. */
    /* ST(0) = exponent, затем PUSH significand -> ST(0) = мантисса, ST(1) = порядок.
     * Мантисса — |x|, нормированная в [1, 2), со знаком x. Снятия нет. */
    double value, sign, mag, exponent, significand;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;

    sign = (signbit(value) != 0) ? -1.0 : 1.0;
    mag = fabs(value);
    if (mag == 0.0) {
        /* x87 returns -inf for exponent and +0/-0 for significand. */
        exponent = -INFINITY;
        significand = (sign < 0.0) ? -0.0 : 0.0;
    } else if (isinf(mag)) {
        exponent = INFINITY;
        significand = sign * INFINITY;
    } else if (isnan(mag)) {
        exponent = nan("");
        significand = nan("");
    } else {
        /* ST(0) = sign * mag / 2^ilogb — gives value in [1, 2).
         * We avoid the ilogb() macro (it expands to a function pointer on
         * some platforms) by using log2/frexp directly. */
        double l2 = log2(mag);
        int ilogb_v = (int)floor(l2);
        /* Edge case: if mag is a power of 2, log2 is exact integer; l2 may
         * be 1 ulp below due to rounding, so ilogb_v can be off by 1.
         * Snap by re-checking via scalbn reconstruction. */
        if (scalbn(1.0, ilogb_v) > mag) ilogb_v -= 1;
        else if (scalbn(1.0, ilogb_v + 1) <= mag) ilogb_v += 1;
        significand = sign * scalbn(mag, -ilogb_v);
        exponent = (double)ilogb_v;
    }
    r = hb_x87_set_st_f64(x87, 0, exponent);
    if (r != HB_OK) return r;
    return hb_x87_push_f64(x87, significand);
}

hb_result_t hb_x87_fprem1(hb_x87_state_t* x87) {
    /* IEEE partial remainder: quotient is rounded to nearest-even. No pop. */
    double a, b, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &a);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(x87, 1, &b);
    if (r != HB_OK) return r;
    /* C99 remainder() implements IEEE 754 remainder, equivalent to FPREM1. */
    result = remainder(a, b);
    r = hb_x87_set_st_f64(x87, 0, result);
    if (r != HB_OK) return r;
    set_fprem_condition_bits(x87, (a - result) / b);
    return HB_OK;
}

hb_result_t hb_x87_fprem(hb_x87_state_t* x87) {
    /* 8087-style partial remainder: ST(0) = ST(0) - N*ST(1) where N is the
     * integer quotient rounded toward 0 (truncation). C99 fmod() matches. */
    double a, b, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &a);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(x87, 1, &b);
    if (r != HB_OK) return r;
    result = fmod(a, b);
    r = hb_x87_set_st_f64(x87, 0, result);
    if (r != HB_OK) return r;
    set_fprem_condition_bits(x87, trunc(a / b));
    return HB_OK;
}

hb_result_t hb_x87_fyl2xp1(hb_x87_state_t* x87) {
    /* ST(1) = ST(1) * log2(ST(0) + 1); pop 1. */
    double a, b, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &a);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(x87, 1, &b);
    if (r != HB_OK) return r;
    result = b * log2(a + 1.0);
    r = hb_x87_set_st_f64(x87, 1, result);
    if (r != HB_OK) return r;
    return hb_x87_pop(x87);
}

hb_result_t hb_x87_fsincos(hb_x87_state_t* x87) {
    /* ST(0) = sin(ST(0)); push cos(ST(0)). No pop. */
    double value, s, c;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;
    s = sin(value);
    c = cos(value);
    r = hb_x87_set_st_f64(x87, 0, s);
    if (r != HB_OK) return r;
    return hb_x87_push_f64(x87, c);
}

hb_result_t hb_x87_fscale(hb_x87_state_t* x87) {
    /* ST(0) = ST(0) * 2^trunc(ST(1)). No pop. */
    double a, b, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &a);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(x87, 1, &b);
    if (r != HB_OK) return r;
    result = scalbn(a, (int)trunc(b));
    return hb_x87_set_st_f64(x87, 0, result);
}

hb_result_t hb_x87_fsin(hb_x87_state_t* x87) {
    double value, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;
    result = sin(value);
    return hb_x87_set_st_f64(x87, 0, result);
}

hb_result_t hb_x87_fcos(hb_x87_state_t* x87) {
    double value, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;
    result = cos(value);
    return hb_x87_set_st_f64(x87, 0, result);
}

/* D9 D0/E0/E1/E4 — stack-top sign / abs / test. These operate on ST(0) only.
 * Per Intel SDM: FCHS inverts sign, FABS clears sign, FTST compares ST(0)
 * to +0.0 and sets C0/C2/C3 in the FPU status word, FNOP is a true no-op
 * (no register reads, no flag changes). */

hb_result_t hb_x87_fnop(hb_x87_state_t* x87) {
    /* FNOP does nothing. We accept a NULL pointer for symmetry with the
     * call sites, but there is no state to mutate. */
    (void)x87;
    return HB_OK;
}

hb_result_t hb_x87_fchs(hb_x87_state_t* x87) {
    double value, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;
    result = -value;
    return hb_x87_set_st_f64(x87, 0, result);
}

hb_result_t hb_x87_fabs(hb_x87_state_t* x87) {
    double value, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;
    result = fabs(value);
    return hb_x87_set_st_f64(x87, 0, result);
}

hb_result_t hb_x87_ftst(hb_x87_state_t* x87) {
    double value;
    uint16_t sw;

    if (!x87) return HB_ERR_INVALID_ARG;
    if (hb_x87_st_f64(x87, 0, &value) != HB_OK) return HB_ERR_EXEC_FAULT;

    /* FTST compares ST(0) to +0.0. Like FCOM with rhs=0.0, except C1 is
     * always cleared (FTST cannot raise stack-underflow on C1 the way
     * FCOM can on an empty operand). We follow the simpler FCOM path
     * which already handles +0/-0/Normal/NaN correctly. */
    sw = (uint16_t)(x87->status_word & ~(uint16_t)((1u << 8) | (1u << 10) | (1u << 14)));
    if (isnan(value)) {
        sw |= (uint16_t)((1u << 8) | (1u << 10) | (1u << 14));
    } else if (value < 0.0) {
        sw |= (uint16_t)(1u << 8);
    } else if (value == 0.0) {
        sw |= (uint16_t)(1u << 14);
    }
    x87->status_word = sw;
    return HB_OK;
}

/* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 519 — НАЛОЖЕНИЕ MMX НА СТЕК x87.
 *
 * Архитектурно `MM(i)` — это мантисса `ST(i)`, а запись в MMX помечает ВСЕ восемь регистров
 * занятыми и ставит экспоненту в `0xFFFF`. Правило не взято по памяти, а ИЗМЕРЕНО у эталона
 * побайтным восстановлением образа `fnstenv`:
 *
 *   fninit                            тег-слово 0xffff  (всё пусто)
 *   fninit + movd mm0,eax             тег-слово 0x5556  ← ST0=особое, ST1..7=ноль
 *   fninit + movd mm0,eax + emms      тег-слово 0xffff
 *
 * `0x5556` читается однозначно: запись в MMX сняла «пусто» со ВСЕХ регистров, а `fnstenv`
 * пересчитал тег по содержимому — у ST0 экспонента `0xFFFF` (особое), у остальных ноль. */
static uint16_t tag_by_content(const hb_x87_state_t* x87, unsigned phys) {
    if (x87->st_ext_valid & (1u << phys)) {
        uint16_t e = (uint16_t)(x87->st_ext[phys][8] | ((uint16_t)x87->st_ext[phys][9] << 8));
        if ((e & 0x7fffu) == 0x7fffu) return 2u;   /* особое: бесконечность/NaN/MMX */
    }
    if (x87->st[phys] == 0.0) return 1u;           /* ноль */
    if (isnan(x87->st[phys]) || isinf(x87->st[phys])) return 2u;
    return 0u;                                     /* занято */
}

hb_result_t hb_x87_mmx_write(hb_x87_state_t* x87, unsigned idx, uint64_t value) {
    unsigned i;
    if (!x87 || idx >= 8) return HB_ERR_INVALID_ARG;
    memcpy(x87->st_ext[idx], &value, 8);
    x87->st_ext[idx][8] = 0xff;
    x87->st_ext[idx][9] = 0xff;
    x87->st_ext_valid |= (uint8_t)(1u << idx);
    x87->st[idx] = NAN;
    x87->tag_word = 0;
    for (i = 0; i < 8; i++)
        x87->tag_word = (uint16_t)(x87->tag_word | (uint16_t)(tag_by_content(x87, i) << (2u * i)));
    return HB_OK;
}

hb_result_t hb_x87_emms(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    x87->tag_word = 0xffff;      /* все пусты — измерено у эталона */
    x87->st_ext_valid = 0;
    return HB_OK;
}
