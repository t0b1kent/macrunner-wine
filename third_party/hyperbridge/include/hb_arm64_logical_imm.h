#ifndef HB_ARM64_LOGICAL_IMM_H
#define HB_ARM64_LOGICAL_IMM_H

/* ─── ЛОГИЧЕСКОЕ НЕПОСРЕДСТВЕННОЕ ARM64 (поля N:immr:imms) ────────────────────
 *
 * Одна кодировка обслуживает ТРИ места, где кодогенератор выпускал лишние слова:
 *   • константа одним словом:  ORR Xd, XZR, #imm   вместо MOVZ+MOVK×3;
 *   • операция берёт значение внутрь: AND/ORR/EOR Xd, Xn, #imm вместо
 *     «материализовать регистр, потом регистровая форма»;
 *   • проверка выравнивания: TST Xn, #imm вместо MOV маски + ANDS.
 *
 * Алгоритм тот же, что у LLVM `AArch64_AM::processLogicalImmediate`: найти
 * НАИМЕНЬШИЙ размер элемента, при котором значение повторяется, и убедиться, что
 * элемент — повёрнутая непрерывная полоса единиц. Значения 0 и ~0 в этой форме
 * непредставимы по устройству кодировки — это внешнее ограничение ISA, а не наше.
 *
 * ★ ПОЧЕМУ ОТДЕЛЬНЫМ ЗАГОЛОВКОМ, а не статикой внутри кодогенератора: иначе его
 * нечем проверить. `tests/hb_logical_imm_test.c` включает этот файл напрямую,
 * перебирает ВСЕ 8192 сочетания (N,immr,imms), декодирует каждое ПО БУКВЕ ISA
 * (независимый обратный ход, а не тот же код) и требует, чтобы кодировщик вернул
 * ровно эти поля. Отрицательный контроль там же: 0, ~0 и непредставимые маски
 * обязаны быть отвергнуты, а намеренно испорченный кодировщик — покраснеть.
 */

#include <stdint.h>
#include <stdbool.h>

static inline bool hb_arm64_is_mask64(uint64_t v) {
    return v != 0 && (((v + 1) & v) == 0);
}

static inline bool hb_arm64_is_shifted_mask64(uint64_t v) {
    return v != 0 && hb_arm64_is_mask64((v - 1) | v);
}

/* Возвращает поля упакованными: (N << 12) | (immr << 6) | imms. */
static inline bool hb_arm64_logical_imm(uint64_t value, bool is64, uint32_t* out_enc) {
    unsigned size, rot, cto, i;
    uint64_t mask, nimms;

    if (!out_enc) return false;
    if (!is64) {
        if ((value >> 32) != 0) return false;
        value |= value << 32;   /* повторить до 64 бит: поиск ведётся в общем виде */
    }
    if (value == 0 || value == ~(uint64_t)0) return false;

    size = 64;
    do {
        size /= 2;
        mask = (((uint64_t)1 << size) - 1);
        if ((value & mask) != ((value >> size) & mask)) { size *= 2; break; }
    } while (size > 2);

    mask = (~(uint64_t)0) >> (64 - size);
    value &= mask;

    if (hb_arm64_is_shifted_mask64(value)) {
        i = (unsigned)__builtin_ctzll(value);
        cto = (unsigned)__builtin_ctzll(~(value >> i));
    } else {
        unsigned clo;
        value |= ~mask;
        if (!hb_arm64_is_shifted_mask64(~value)) return false;
        clo = (unsigned)__builtin_clzll(~value);
        i = 64 - clo;
        cto = clo + (unsigned)__builtin_ctzll(~value) - (64 - size);
    }
    rot = (size - i) & (size - 1);
    nimms = (~(uint64_t)(size - 1)) << 1;
    nimms |= (uint64_t)(cto - 1);
    {
        /* Для 32-битной формы поле N обязано быть нулевым: элемент шире 32 бит там
         * не выражается, и такое значение просто не кодируемо. */
        uint32_t n = (uint32_t)(((nimms >> 6) & 1) ^ 1);
        if (!is64 && n) return false;
        *out_enc = (n << 12) | (rot << 6) | (uint32_t)(nimms & 0x3f);
    }
    return true;
}

/* Разложить упакованные поля по местам в слове команды (биты N, immr, imms). */
static inline uint32_t hb_arm64_logical_fields(uint32_t enc) {
    return (((enc >> 12) & 1u) << 22) | (((enc >> 6) & 0x3fu) << 16) | ((enc & 0x3fu) << 10);
}

#endif /* HB_ARM64_LOGICAL_IMM_H */
