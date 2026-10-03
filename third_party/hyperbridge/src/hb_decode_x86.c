#include "hb_env.h"
#include "hb_gates.h"
#include "hb_decoder.h"
#include "hb_zamok_pravilo.h"
#include "hb_vex_formy.h"
#include "hb_ir.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define HB_X86_DEFAULT_MXCSR 0x1f80u

typedef struct {
    const uint8_t* code;
    size_t len;
    size_t pos;
    uint64_t addr;
    bool addr16_active;   /* итерация 283: действует префикс 0x67 (16-битная адресация) */
} hb_dec_t;

/* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 363 — ПРЕФИКС 0x66 УСЕКАЕТ ЦЕЛЬ ДО 16 БИТ.
 *
 * В 32-битном режиме префикс размера операнда делает ближний переход 16-битным, и `EIP`
 * усекается: `EIP = цель & 0xFFFF`. Мы этого не делали, и стенд поймал ровно это на случае
 * `65667402` (`je` с префиксами `65 66`): ожидалось `reg.eip = 0x0000000e`, получено
 * `0x0010000e` — то есть у нас остался полный адрес.
 *
 * Случай был невидим, пока 288 переходов не вернулись в сравнение (итерация 362): до этого
 * оракул падал на выборке команды по целевому адресу, и сравнения не было вовсе.
 *
 * ЧЕГО ЭТА ПРАВКА НЕ ДЕЛАЕТ, называю прямо: при `0x66` формы `E9`, `E8` и `0F 8x` читают
 * смещение как **rel16**, а не rel32 — здесь по-прежнему читается 4 байта. Это отдельный
 * дефект того же префикса, он остаётся. */
static inline uint64_t hb_x86_near_target(uint64_t target, bool operand16) {
    return operand16 ? (target & 0xFFFFu) : target;
}

static inline bool can_read(hb_dec_t* d, size_t n) {
    return d->pos + n <= d->len;
}

static inline uint8_t read_u8(hb_dec_t* d) {
    return d->code[d->pos++];
}

static inline int8_t read_s8(hb_dec_t* d) {
    return (int8_t)d->code[d->pos++];
}

static inline int16_t read_s16(hb_dec_t* d) {
    uint16_t lo = (uint16_t)(d->code[d->pos] | (d->code[d->pos+1] << 8u));
    d->pos += 2;
    return (int16_t)lo;
}

static inline int32_t read_s32(hb_dec_t* d) {
    uint32_t lo = d->code[d->pos] | (d->code[d->pos+1] << 8u)
                 | (d->code[d->pos+2] << 16u) | (d->code[d->pos+3] << 24u);
    d->pos += 4;
    return (int32_t)lo;
}

static inline int reg8_idx(int base, uint8_t* byte_offset) {
    if (byte_offset) *byte_offset = 0;
    if (base >= 4 && base <= 7) {
        if (byte_offset) *byte_offset = 1;
        return base - 4; /* AH/CH/DH/BH alias byte 1 of EAX/ECX/EDX/EBX. */
    }
    return base;
}

/* 0F38 map: SSSE3 family (subset that has a non-VEC HB_INS_*). */
static int ssse3_0f38_opcode(uint8_t op) {
    switch (op) {
        case 0x00: return HB_INS_PSHUFB;
        case 0x01: return HB_INS_PHADDW;
        case 0x02: return HB_INS_PHADDD;
        case 0x03: return HB_INS_PHADDSW;
        case 0x04: return HB_INS_PMADDUBSW;
        case 0x05: return HB_INS_PHSUBW;
        case 0x06: return HB_INS_PHSUBD;
        case 0x07: return HB_INS_PHSUBSW;
        case 0x08: return HB_INS_PSIGNB;
        case 0x09: return HB_INS_PSIGNW;
        case 0x0a: return HB_INS_PSIGND;
        case 0x0b: return HB_INS_PMULHRSW;
        case 0x1c: return HB_INS_PABSB;
        case 0x1d: return HB_INS_PABSW;
        case 0x1e: return HB_INS_PABSD;
        default: return 0;
    }
}

/* 0F38 map: SSE4.1 / SSE4.2 / AES / GF2P8MULB user-mode subset. */
static int sse41_0f38_opcode(uint8_t op) {
    switch (op) {
        /* 0x2a отсутствовал: сводился к сборному коду, хотя x64 его знает
         * (hb_decode_x64.c:3916). Решение то же — HB_INS_MOVNTDQA. */
        case 0x2a: return HB_INS_MOVNTDQA;
        case 0x10: return HB_INS_PBLENDVB;
        case 0x14: return HB_INS_BLENDVPS;
        case 0x15: return HB_INS_BLENDVPD;
        case 0x17: return HB_INS_PTEST;
        case 0x20: return HB_INS_PMOVSXBW;
        case 0x21: return HB_INS_PMOVSXBD;
        case 0x22: return HB_INS_PMOVSXBQ;
        case 0x23: return HB_INS_PMOVSXWD;
        case 0x24: return HB_INS_PMOVSXWQ;
        case 0x25: return HB_INS_PMOVSXDQ;
        case 0x28: return HB_INS_PMULDQ;
        case 0x29: return HB_INS_PCMPEQQ;
        case 0x2b: return HB_INS_PACKUSDW;
        case 0x30: return HB_INS_PMOVZXBW;
        case 0x31: return HB_INS_PMOVZXBD;
        case 0x32: return HB_INS_PMOVZXBQ;
        case 0x33: return HB_INS_PMOVZXWD;
        case 0x34: return HB_INS_PMOVZXWQ;
        case 0x35: return HB_INS_PMOVZXDQ;
        case 0x37: return HB_INS_PCMPGTQ;
        case 0x38: return HB_INS_PMINSB;
        case 0x39: return HB_INS_PMINSD;
        case 0x3a: return HB_INS_PMINUW;
        case 0x3b: return HB_INS_PMINUD;
        case 0x3c: return HB_INS_PMAXSB;
        case 0x3d: return HB_INS_PMAXSD;
        case 0x3e: return HB_INS_PMAXUW;
        case 0x3f: return HB_INS_PMAXUD;
        case 0x40: return HB_INS_PMULLD;
        case 0x41: return HB_INS_PHMINPOSUW;
        case 0xcf: return HB_INS_GF2P8MULB;
        case 0xf0: return HB_INS_CRC32;
        case 0xf1: return HB_INS_CRC32;
        case 0xf6: return HB_INS_ADCX;
        case 0xf7: return HB_INS_ADOX;
        case 0xdb: return HB_INS_AESIMC;
        case 0xdc: return HB_INS_AESENC;
        case 0xdd: return HB_INS_AESENCLAST;
        case 0xde: return HB_INS_AESDEC;
        case 0xdf: return HB_INS_AESDECLAST;
        /* SHA-NI */
        case 0xc8: return HB_INS_SHA1NEXTE;
        case 0xc9: return HB_INS_SHA1MSG1;
        case 0xca: return HB_INS_SHA1MSG2;
        case 0xcb: return HB_INS_SHA256RNDS2;
        case 0xcc: return HB_INS_SHA256MSG1;
        case 0xcd: return HB_INS_SHA256MSG2;
        default: return 0;
    }
}

/* 0F3A map: SSE4.1 imm8 forms + AES + PCLMULQDQ + SHA1RNDS4. */
static int sse41_0f3a_opcode(uint8_t op) {
    switch (op) {
        case 0x0c: return HB_INS_BLENDPS;
        case 0x0d: return HB_INS_BLENDPD;
        case 0x0e: return HB_INS_PBLENDW;
        case 0x0f: return HB_INS_PALIGNR;
        /* 0x42 отсутствовал: доска видела «op mismatch HB=vec, CS=mpsadbw».
         * Хвост этого пути читает непосредственный байт, поэтому длина верна. */
        case 0x42: return HB_INS_MPSADBW;
        case 0x44: return HB_INS_PCLMULQDQ;
        case 0x60: return HB_INS_PCMPESTRM;
        case 0x61: return HB_INS_PCMPESTRI;
        case 0x62: return HB_INS_PCMPISTRM;
        case 0x63: return HB_INS_PCMPISTRI;
        case 0xcc: return HB_INS_SHA1RNDS4;
        case 0xdf: return HB_INS_AESKEYGENASSIST;
        default: return 0;
    }
}

static inline void set_reg(hb_decoded_t* out, int slot, int r, uint8_t sz) {
    if (slot == 1) {
        out->op1.present = true;
        out->op1.is_reg = true;
        out->op1.reg = r;
        out->op1.size = sz;
    } else if (slot == 2) {
        out->op2.present = true;
        out->op2.is_reg = true;
        out->op2.reg = r;
        out->op2.size = sz;
    } else if (slot == 3) {
        out->op3.present = true;
        out->op3.is_reg = true;
        out->op3.reg = r;
        out->op3.size = sz;
    }
}

static inline void set_reg_ex(hb_decoded_t* out, int slot, int r, uint8_t sz, uint8_t reg_offset) {
    set_reg(out, slot, r, sz);
    if (slot == 1) out->op1.reg_offset = reg_offset;
    else if (slot == 2) out->op2.reg_offset = reg_offset;
    else if (slot == 3) out->op3.reg_offset = reg_offset;
}

static inline void set_imm(hb_decoded_t* out, int slot, int64_t v, uint8_t sz) {
    if (slot == 1) {
        out->op1.present = true;
        out->op1.is_imm = true;
        out->op1.imm = v;
        out->op1.size = sz;
    } else if (slot == 2) {
        out->op2.present = true;
        out->op2.is_imm = true;
        out->op2.imm = v;
        out->op2.size = sz;
    } else if (slot == 3) {
        out->op3.present = true;
        out->op3.is_imm = true;
        out->op3.imm = v;
        out->op3.size = sz;
    }
}

static inline void mark_mm_operand(hb_decoded_t* out, int slot) {
    /* Итерация 303: то же, что mark_xmm_operand, но для регистров MMX (64 бита). */
    if (slot == 1 && out->op1.is_reg) { out->op1.reg += HB_REG_MM0; out->op1.size = 8; }
    else if (slot == 2 && out->op2.is_reg) { out->op2.reg += HB_REG_MM0; out->op2.size = 8; }
}

/* РАЗМЕТКА ВЕКТОРА НЕ УМЕНЬШАЕТ РАЗМЕР.
 *
 * Здесь стояло безусловное `size = 16`, и оно ЗАТИРАЛО ширину, только что
 * поставленную разбором операндов. У ветви i386 форма берётся из общей
 * таблицы, где ширина записана (s1/s2/s3 = 16/32/64), `parse_modrm` её
 * ставил — а следующая строка возвращала 16. Оттого `vaddps ymm` давал на
 * i386 оп=16 против 32 у x64, и доска считала это расхождением операндов:
 * 469 против 64. Замер до и после — в записи дня.
 *
 * Правило простое: пометить регистр как векторный можно всегда, а вот
 * СУЖАТЬ уже известную ширину нельзя никогда. */
static inline void mark_xmm_operand(hb_decoded_t* out, int slot) {
    if (slot == 1 && out->op1.is_reg) {
        out->op1.reg += HB_REG_XMM0;
        if (out->op1.size < 16) out->op1.size = 16;
    } else if (slot == 2 && out->op2.is_reg) {
        out->op2.reg += HB_REG_XMM0;
        if (out->op2.size < 16) out->op2.size = 16;
    } else if (slot == 3 && out->op3.is_reg) {
        out->op3.reg += HB_REG_XMM0;
        if (out->op3.size < 16) out->op3.size = 16;
    }
}

static inline void mark_xmm_operands(hb_decoded_t* out) {
    mark_xmm_operand(out, 1);
    mark_xmm_operand(out, 2);
    mark_xmm_operand(out, 3);
}

/* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1064 — ВЕКТОР ШИРЕ 128 БИТ НА i386.
 * `mark_xmm_operands` ставит только признак «вектор», размер оставляя прежним, и для форм
 * VEX с L=1 (256 бит) этого мало. Помощники перенесены из ветви x64 (`hb_decode_x64.c:224`)
 * буква в букву, чтобы описание операнда у одной и той же команды не расходилось по ветвям. */
static inline void mark_vec_operand(hb_decoded_t* out, int slot, uint8_t bytes) {
    mark_xmm_operand(out, slot);
    if (slot == 1 && out->op1.is_reg) out->op1.size = bytes;
    else if (slot == 2 && out->op2.is_reg) out->op2.size = bytes;
    else if (slot == 3 && out->op3.is_reg) out->op3.size = bytes;
}

/* РАЗМЕТКА РЕГИСТРА-МАСКИ (k0..k7) — 04.09.2026.
 *
 * Приёмник у семьи VCMP под EVEX — регистр-маска, а не вектор и не число.
 * За неимением класса он клался НЕПОСРЕДСТВЕННЫМ (`set_imm(out, 1, kdst, 1)`),
 * и доска честно ругалась. Класс заведён (HB_REG_K0..K7), место в состоянии
 * было давно (`uint64_t k[8]`). */
static inline void mark_k_operand(hb_decoded_t* out, int slot) {
    if (slot == 1 && out->op1.is_reg) out->op1.reg += HB_REG_K0;
    else if (slot == 2 && out->op2.is_reg) out->op2.reg += HB_REG_K0;
    else if (slot == 3 && out->op3.is_reg) out->op3.reg += HB_REG_K0;
}

static inline void mark_vec_operands(hb_decoded_t* out, uint8_t bytes) {
    mark_vec_operand(out, 1, bytes);
    mark_vec_operand(out, 2, bytes);
    mark_vec_operand(out, 3, bytes);
    if (out->op1.is_mem) out->op1.size = bytes;
    if (out->op2.is_mem) out->op2.size = bytes;
    if (out->op3.is_mem) out->op3.size = bytes;
}

/* ═══ ОБЩИЙ СПИСОК ФОРМ VEX/EVEX — ОДИН НА ОБЕ АРХИТЕКТУРЫ ═══
 *
 * Соответствие «кодировка -> команда» не пишется здесь руками. Оно лежит в
 * hb_vex_formy.h, ПОРОЖДЁННОМ перебором пространства кодировок и подачей
 * каждой живому декодеру x64 (tools/оракул/свод-vex.c). Причина: в
 * hb_decode_x64.c это соответствие записано 125 раз в трёх формах на 1280
 * строках, и перенос руками дал бы расхождение не в отсутствии формы, а в её
 * СЕМАНТИКЕ.
 *
 * Отставание i386 («100 % при 587 непокрытых формах») было именно потому, что
 * у каждой ветви список свой. Теперь он один: правка в x64 достаётся i386
 * перепорождением, без единой правки здесь.
 *
 * Поиск: открытая адресация на 4096 слотов. Ключ 19 бит (вид, карта, pp, L'L,
 * код, расширение), форм около тысячи; прямое отображение стоило бы полмегабайта. */
struct hb_vex_forma {
    uint8_t vid, map, pp, l, w, op, ext, mod;
    /* КЛАСС регистра отдельно от РАЗМЕРА: у vmovss третий операнд
     * шириной 4 байта, но регистр векторный; у blsi операнды тоже
     * по 4, но обычные. Прежде класс выводился из `размер >= 16`. */
    int ins;
    uint8_t lane, s1, s2, s3, store, imm8;
    uint8_t v1, v2, v3;
    /* РОЛЬ каждого операнда: 0 нет, 1 reg, 2 rm, 3 vvvv, 4 imm.
     * Порядок полей НЕ одинаков у разных команд: у shrx vvvv — второй
     * источник, у blsi он ПРИЁМНИК, у vmovd приёмник и источник
     * переставлены. Прежде порядок выводился из наличия третьего
     * операнда, и эти три случая давали не те регистры. */
    uint8_t r1, r2, r3;
};

#define HB_VEX_SLOTOV 16384u   /* форм стало больше: 1257 */

static const struct hb_vex_forma* hb_najti_formu(unsigned vid, unsigned map,
                                                 unsigned pp, unsigned l,
                                                 unsigned w, unsigned op,
                                                 unsigned ext, unsigned mod)
{
    static const struct hb_vex_forma formy[] = {
#define X(v, m, p, ll, ww, o, e, md, ins, lane, a, b2, c, st, im, w1, w2, w3, q1, q2, q3) \
        { v, m, p, ll, ww, o, e, md, ins, lane, a, b2, c, st, im, w1, w2, w3, q1, q2, q3 },
        HB_VEX_FORMY(X)
#undef X
    };
    static short ukaz[HB_VEX_SLOTOV];
    static unsigned kl_sloty[HB_VEX_SLOTOV];
    static int gotov;
    unsigned h, prob;

    /* Расширение 15 в ключе означает «любое». Раньше такие формы
     * РАЗМНОЖАЛИСЬ в восемь слотов: 1013 форм давали 8104 записи на таблицу в
     * 4096, она переполнялась, и цикл вставки крутился ВЕЧНО. Теперь запись
     * одна, а поиск идёт дважды: сперва точное расширение, потом «любое».
     * Плюс предел проб — зависание стало невозможным, а не «маловероятным». */
    /* MOD в ключе: имя команды может ЗАВИСЕТЬ от того, регистр источник или
     * память (vmovhlps против vmovlps, vmovlhps против vmovhps). Значение 3 —
     * регистр, 0 — память, 15 — «всё равно». */
    /* Бит 4 был свободен: mod занимает 0-3, ext 5-8. Туда встаёт W —
     * без него 117 новых форм столкнулись бы с уже занятыми ключами. */
    #define HB_VEX_KL(v, m, p, l2, w2, o, e, md) \
        (((unsigned)(v) << 24) | ((unsigned)(m) << 21) | ((unsigned)(p) << 19) | \
         ((unsigned)(l2) << 17) | ((unsigned)(o) << 9) | ((unsigned)(e) << 5) | \
         ((unsigned)(w2) << 4) | (unsigned)(md))

    if (!gotov) {
        size_t vi; unsigned e2;
        for (e2 = 0; e2 < HB_VEX_SLOTOV; e2++) ukaz[e2] = -1;
        for (vi = 0; vi < sizeof(formy) / sizeof(formy[0]); vi++) {
            unsigned k2 = HB_VEX_KL(formy[vi].vid, formy[vi].map, formy[vi].pp,
                                    formy[vi].l, formy[vi].w, formy[vi].op,
                                    formy[vi].ext == 255 ? 15u : formy[vi].ext,
                                    formy[vi].mod == 255 ? 15u : formy[vi].mod);
            unsigned hh = (k2 * 2654435761u) & (HB_VEX_SLOTOV - 1u);
            unsigned pr = 0;
            while (ukaz[hh] >= 0 && kl_sloty[hh] != k2 && pr < HB_VEX_SLOTOV) {
                hh = (hh + 1u) & (HB_VEX_SLOTOV - 1u); pr++;
            }
            if (pr < HB_VEX_SLOTOV) { kl_sloty[hh] = k2; ukaz[hh] = (short)vi; }
        }
        gotov = 1;   /* гонка безвредна: все пишут одно и то же */
    }

    {
        /* Четыре попытки: точное расширение и точный MOD, затем ослабление
         * каждого — от самого частного к самому общему. */
        unsigned popytki[4], i2;
        popytki[0] = HB_VEX_KL(vid, map, pp, l, w, op, ext & 7u, mod);
        popytki[1] = HB_VEX_KL(vid, map, pp, l, w, op, 15u, mod);
        popytki[2] = HB_VEX_KL(vid, map, pp, l, w, op, ext & 7u, 15u);
        popytki[3] = HB_VEX_KL(vid, map, pp, l, w, op, 15u, 15u);
        for (i2 = 0; i2 < 4; i2++) {
            h = (popytki[i2] * 2654435761u) & (HB_VEX_SLOTOV - 1u);
            for (prob = 0; prob < HB_VEX_SLOTOV && ukaz[h] >= 0; prob++) {
                if (kl_sloty[h] == popytki[i2]) return &formy[ukaz[h]];
                h = (h + 1u) & (HB_VEX_SLOTOV - 1u);
            }
        }
    }
    return NULL;
}

static inline void set_mem(hb_decoded_t* out, int slot,
                           int base, int index, uint8_t scale, int64_t disp, uint8_t sz) {
    if (slot == 1) {
        out->op1.present = true;
        out->op1.is_mem = true;
        out->op1.mem.base = base;
        out->op1.mem.index = index;
        out->op1.mem.scale = scale;
        out->op1.mem.disp = disp;
        out->op1.mem.segment = out->segment_prefix;
        out->op1.mem.addr32 = out->address32_prefix;
        out->op1.size = sz;
    } else if (slot == 2) {
        out->op2.present = true;
        out->op2.is_mem = true;
        out->op2.mem.base = base;
        out->op2.mem.index = index;
        out->op2.mem.scale = scale;
        out->op2.mem.disp = disp;
        out->op2.mem.segment = out->segment_prefix;
        out->op2.mem.addr32 = out->address32_prefix;
        out->op2.size = sz;
    } else if (slot == 3) {
        out->op3.present = true;
        out->op3.is_mem = true;
        out->op3.mem.base = base;
        out->op3.mem.index = index;
        out->op3.mem.scale = scale;
        out->op3.mem.disp = disp;
        out->op3.mem.segment = out->segment_prefix;
        out->op3.mem.addr32 = out->address32_prefix;
        out->op3.size = sz;
    }
}

/* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 283 — 16-БИТНАЯ АДРЕСАЦИЯ (префикс 0x67).
 * Набор конечный: восемь форм r/m при mod 00/01/10, SIB не бывает, масштаба нет.
 *   0 [BX+SI]  1 [BX+DI]  2 [BP+SI]  3 [BP+DI]  4 [SI]  5 [DI]  6 disp16|[BP]  7 [BX]
 * Разбор без усечения адреса был бы ХУЖЕ честного отказа, поэтому операнд помечается
 * `addr16`, а вычислитель обязан взять адрес по модулю 0x10000.
 *
 * Итерация 873: вынесено в ОДНУ функцию. Прежде таблица жила только в `parse_modrm`, а
 * `parse_modrm_ext` (группы F6/F7, C0/C1/D0/D1/D3, 80/81/83 — MUL, DIV, NEG, сдвиги, ADC/SBB)
 * шла мимо неё и разбирала 16-битную адресацию как 32-битную. Это не только неверная база:
 * при mod==2 смещение читалось ЧЕТЫРЬМЯ байтами вместо двух, то есть ломалась ДЛИНА команды и
 * дальше поток разъезжался. По стенду x86-32 — 84 расхождения операндов и 43 длины.
 * Урок про «семантику в двух местах» ровно об этом: копий быть не должно. */
static hb_result_t parse_modrm16(hb_dec_t* d, uint8_t mod, uint8_t rm,
                                 int* out_base, int* out_index, int64_t* out_disp) {
    int base = -1, index = -1;
    int64_t disp = 0;
    switch (rm) {
        case 0: base = 3; index = 6; break;   /* BX+SI */
        case 1: base = 3; index = 7; break;   /* BX+DI */
        case 2: base = 5; index = 6; break;   /* BP+SI */
        case 3: base = 5; index = 7; break;   /* BP+DI */
        case 4: base = 6; break;              /* SI */
        case 5: base = 7; break;              /* DI */
        case 6: if (mod == 0) base = -1; else base = 5; break;  /* disp16 | BP */
        default: base = 3; break;             /* BX */
    }
    if (mod == 1) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        disp = read_s8(d);
    } else if (mod == 2 || (rm == 6 && mod == 0)) {
        if (!can_read(d, 2)) return HB_ERR_DECODE_FAILED;
        disp = (int16_t)read_s16(d);
    }
    *out_base = base;
    *out_index = index;
    *out_disp = disp;
    return HB_OK;
}


/* В 32 битах расширяющих битов REX нет: номер регистра — это он сам.
 * Заглушка нужна общему тексту разбора VSIB, где у x64 стоит reg_idx. */
static inline int reg_idx(int r, bool rex_b) { (void)rex_b; return r; }

#include "hb_decode_vsib_obshchee.inc"
#include "hb_decode_tsx_obshchee.inc"
static hb_result_t parse_modrm(hb_dec_t* d, uint8_t modrm,
                               uint8_t def_size, hb_decoded_t* out,
                               int dst_slot, int src_slot,
                               bool mem_is_dst) {
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t reg_op = (modrm >> 3) & 7;
    uint8_t rm = modrm & 7;

    out->has_modrm = true;
    out->mod = mod;
    out->reg_op = reg_op;
    out->rm = rm;

    uint8_t sz = def_size;
    uint8_t reg_offset = 0;
    int reg = (sz == 1) ? reg8_idx(reg_op, &reg_offset) : reg_op;

    if (mod == 3) {
        uint8_t rm_offset = 0;
        int rm_reg = (sz == 1) ? reg8_idx(rm, &rm_offset) : rm;
        if (mem_is_dst) {
            set_reg_ex(out, dst_slot, rm_reg, sz, rm_offset);
            set_reg_ex(out, src_slot, reg, sz, reg_offset);
        } else {
            set_reg_ex(out, dst_slot, reg, sz, reg_offset);
            set_reg_ex(out, src_slot, rm_reg, sz, rm_offset);
        }
        return HB_OK;
    }

    int base = -1, index = -1;
    uint8_t scale = 1;
    int64_t disp = 0;

    /* Таблица 16-битной адресации — в parse_modrm16 (одна копия на оба разбора modrm). */
    if (d->addr16_active) {
        hb_result_t r16 = parse_modrm16(d, mod, rm, &base, &index, &disp);
        if (r16 != HB_OK) return r16;
        if (mem_is_dst) {
            set_mem(out, dst_slot, base, index, 1, disp, sz);
            set_reg_ex(out, src_slot, reg, sz, reg_offset);
            out->op1.mem.addr16 = (dst_slot == 1);
            out->op2.mem.addr16 = (dst_slot == 2);
        } else {
            set_reg_ex(out, dst_slot, reg, sz, reg_offset);
            set_mem(out, src_slot, base, index, 1, disp, sz);
            out->op1.mem.addr16 = (src_slot == 1);
            out->op2.mem.addr16 = (src_slot == 2);
        }
        return HB_OK;
    }

    if (rm == 4) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t sib = read_u8(d);
        out->has_sib = true;
        out->sib_scale = (sib >> 6) & 3;
        out->sib_index = (sib >> 3) & 7;
        out->sib_base = sib & 7;
        scale = (uint8_t)(1u << out->sib_scale);
        int si = out->sib_index;
        if (out->sib_index == 4) index = -1; else index = si;
        int sb = out->sib_base;
        if (out->sib_base == 5) {
            if (mod == 0) base = -1; else base = sb;
        } else {
            base = sb;
        }
    } else if (rm == 5 && mod == 0) {
        /* disp32 only, no base */
        base = -1;
    } else {
        base = rm;
    }

    if (mod == 1) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        disp = read_s8(d);
    } else if (mod == 2 || (rm == 5 && mod == 0) || (rm == 4 && out->sib_base == 5 && mod == 0)) {
        if (!can_read(d, 4)) return HB_ERR_DECODE_FAILED;
        disp = read_s32(d);
    }

    if (mem_is_dst) {
        set_mem(out, dst_slot, base, index, scale, disp, sz);
        set_reg_ex(out, src_slot, reg, sz, reg_offset);
    } else {
        set_reg_ex(out, dst_slot, reg, sz, reg_offset);
        set_mem(out, src_slot, base, index, scale, disp, sz);
    }
    return HB_OK;
}

/* РАСКЛАДКА ОПЕРАНДОВ ПО РОЛЯМ — ОДНА на обе ветви, VEX и EVEX.
 *
 * Прежде она стояла только в ветви VEX, и EVEX продолжал выводить порядок из
 * наличия третьего операнда: `vmovss` под EVEX давал приёмником xmm0 вместо
 * xmm1 (таблица роли знала верно, применял их только один путь). Ровно тот же
 * вид отставания, что мы чиним весь день, — поэтому текст один.
 *
 * Возвращает 1, если роли заданы и раскладка сделана; 0 — если ролей нет и
 * вызывающему надо идти прежним путём. */
static int hb_razlozhit_po_rolyam(hb_dec_t* d, const struct hb_vex_forma* f,
                                  uint8_t modrm, unsigned vex_v,
                                  hb_decoded_t* out, hb_result_t* vr) {
    const uint8_t rol[3] = { f->r1, f->r2, f->r3 };
    const uint8_t szs[3] = { f->s1, f->s2, f->s3 };
    int sl_reg = 0, sl_rm = 0, sl_v = 0, sl_imm = 0, k;

    if (!f->r1 && !f->r2 && !f->r3) return 0;
    for (k = 0; k < 3; k++) {
        if (rol[k] == 1) sl_reg = k + 1;
        else if (rol[k] == 2) sl_rm = k + 1;
        else if (rol[k] == 3) sl_v = k + 1;
        else if (rol[k] == 4) sl_imm = k + 1;
    }
    if (sl_reg && sl_rm) {
        /* parse_modrm кладёт reg в первый слот, rm во второй; при mem_is_dst
         * наоборот. Порядок выбираем так, чтобы слоты вышли на свои места. */
        if (sl_rm < sl_reg)
            *vr = parse_modrm(d, modrm, szs[sl_rm - 1], out, sl_rm, sl_reg, true);
        else
            *vr = parse_modrm(d, modrm, szs[sl_rm - 1], out, sl_reg, sl_rm, false);
        if (*vr != HB_OK) return 1;
    } else if (sl_rm) {
        /* Роли reg НЕТ: поле reg у таких форм — РАСШИРЕНИЕ кода. Но
         * parse_modrm пишет ОБА поля, и один слот дважды означает, что второе
         * затрёт первое. Отдаём расширению СВОБОДНЫЙ слот и снимаем его. */
        int svob = 0;
        for (k = 1; k <= 3; k++)
            if (k != sl_rm && k != sl_v && k != sl_imm) { svob = k; break; }
        if (svob) {
            *vr = parse_modrm(d, modrm, szs[sl_rm - 1], out, svob, sl_rm, false);
            if (*vr != HB_OK) return 1;
            if (svob == 1) out->op1.present = false;
            else if (svob == 2) out->op2.present = false;
            else out->op3.present = false;
        } else {
            *vr = parse_modrm(d, modrm, szs[sl_rm - 1], out, sl_rm, sl_rm, false);
            if (*vr != HB_OK) return 1;
        }
    }
    if (sl_v) set_reg(out, sl_v, vex_v, szs[sl_v - 1]);
    if (sl_imm) {
        if (!can_read(d, 1)) { *vr = HB_ERR_DECODE_FAILED; return 1; }
        set_imm(out, sl_imm, read_u8(d), 1);
    }
    /* ТОЧНЫЙ размер каждому слоту: parse_modrm берёт один размер на оба. */
    for (k = 0; k < 3; k++) {
        if (!rol[k] || !szs[k]) continue;
        if (k == 0 && out->op1.present && !out->op1.is_mem) out->op1.size = szs[0];
        else if (k == 1 && out->op2.present && !out->op2.is_mem) out->op2.size = szs[1];
        else if (k == 2 && out->op3.present && !out->op3.is_mem && !out->op3.is_imm)
            out->op3.size = szs[2];
    }
    *vr = HB_OK;
    return 1;
}


static hb_result_t parse_modrm_ext(hb_dec_t* d, uint8_t modrm,
                                   uint8_t def_size, hb_decoded_t* out,
                                   int op_slot) {
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t rm = modrm & 7;
    out->has_modrm = true;
    out->mod = mod;
    out->rm = rm;
    uint8_t sz = def_size;

    if (mod == 3) {
        uint8_t rm_offset = 0;
        int rm_reg = (sz == 1) ? reg8_idx(rm, &rm_offset) : rm;
        set_reg_ex(out, op_slot, rm_reg, sz, rm_offset);
        return HB_OK;
    }

    int base = -1, index = -1;
    uint8_t scale = 1;
    int64_t disp = 0;

    /* Итерация 873: ветвь 16-битной адресации ЗДЕСЬ ОТСУТСТВОВАЛА. Через этот разбор идут
     * группы (F6/F7 — MUL/DIV/NEG/NOT, C0/C1/D0/D1/D3 — сдвиги и повороты, 80/81/83 — ADC/SBB
     * и прочие), и под префиксом 0x67 они разбирались по 32-битным правилам: неверная база
     * (`[bx+si]` читалось как `[eax]`) и, что хуже, при mod==2 смещение бралось четырьмя
     * байтами вместо двух — ломалась ДЛИНА команды. */
    if (d->addr16_active) {
        hb_result_t r16 = parse_modrm16(d, mod, rm, &base, &index, &disp);
        if (r16 != HB_OK) return r16;
        set_mem(out, op_slot, base, index, 1, disp, sz);
        if (op_slot == 1) out->op1.mem.addr16 = true;
        else if (op_slot == 2) out->op2.mem.addr16 = true;
        else if (op_slot == 3) out->op3.mem.addr16 = true;
        return HB_OK;
    }

    if (rm == 4) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t sib = read_u8(d);
        out->has_sib = true;
        out->sib_scale = (sib >> 6) & 3;
        out->sib_index = (sib >> 3) & 7;
        out->sib_base = sib & 7;
        scale = (uint8_t)(1u << out->sib_scale);
        int si = out->sib_index;
        if (out->sib_index == 4) index = -1; else index = si;
        int sb = out->sib_base;
        if (out->sib_base == 5) {
            if (mod == 0) base = -1; else base = sb;
        } else {
            base = sb;
        }
    } else if (rm == 5 && mod == 0) {
        base = -1;
    } else {
        base = rm;
    }

    if (mod == 1) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        disp = read_s8(d);
    } else if (mod == 2 || (rm == 5 && mod == 0) || (rm == 4 && out->sib_base == 5 && mod == 0)) {
        if (!can_read(d, 4)) return HB_ERR_DECODE_FAILED;
        disp = read_s32(d);
    }

    set_mem(out, op_slot, base, index, scale, disp, sz);
    return HB_OK;
}

static hb_result_t decode_x87(hb_dec_t* d, uint8_t opcode, hb_decoded_t* out) {
    uint8_t modrm;
    uint8_t mod;
    uint8_t reg_op;
    uint8_t size = 0;
    int fi_sub = -1;   /* итерация 906: вид действия семьи `FI`, -1 = не она */

    if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
    modrm = read_u8(d);
    mod = (modrm >> 6) & 3u;
    reg_op = (modrm >> 3) & 7u;
    out->writes_flags = false;

    if (opcode == 0xdf && modrm == 0xe0) {
        out->opcode = HB_INS_X87_FNSTSW;
        set_reg(out, 1, HB_REG_X86_EAX, 2);
        return HB_OK;
    }
    if (mod == 3) {
        uint8_t sti = modrm & 7u;
        if (opcode == 0xd8) {
            if (modrm >= 0xc0 && modrm <= 0xc7) out->opcode = HB_INS_X87_FADD;
            else if (modrm >= 0xc8 && modrm <= 0xcf) out->opcode = HB_INS_X87_FMUL;
            else if (modrm >= 0xd0 && modrm <= 0xd7) out->opcode = HB_INS_X87_FCOM;
            else if (modrm >= 0xd8 && modrm <= 0xdf) out->opcode = HB_INS_X87_FCOMP;
            else if (modrm >= 0xe0 && modrm <= 0xe7) out->opcode = HB_INS_X87_FSUB;
            else if (modrm >= 0xe8 && modrm <= 0xef) out->opcode = HB_INS_X87_FSUBR;
            else if (modrm >= 0xf0 && modrm <= 0xf7) out->opcode = HB_INS_X87_FDIV;
            else if (modrm >= 0xf8) out->opcode = HB_INS_X87_FDIVR;
            else return HB_ERR_UNSUPPORTED_OPCODE;
            set_imm(out, 1, sti, 1);
            return HB_OK;
        }
        if (opcode == 0xd9) {
            if (modrm == 0xe8) {
                /* FLD1: push 1.0 */
                out->opcode = HB_INS_X87_FLD;
                set_imm(out, 1, -1, 1);
                return HB_OK;
            }
            if (modrm == 0xee) {
                /* FLDZ: push 0.0 */
                out->opcode = HB_INS_X87_FLD;
                set_imm(out, 1, -2, 1);
                return HB_OK;
            }
            if (modrm == 0xe9) {
                /* FLDL2T: push log2(10) */
                out->opcode = HB_INS_X87_FLD;
                set_imm(out, 1, -3, 1);
                return HB_OK;
            }
            if (modrm == 0xea) {
                /* FLDL2E: push log2(e) */
                out->opcode = HB_INS_X87_FLD;
                set_imm(out, 1, -4, 1);
                return HB_OK;
            }
            if (modrm == 0xeb) {
                /* FLDPI: push pi */
                out->opcode = HB_INS_X87_FLD;
                set_imm(out, 1, -5, 1);
                return HB_OK;
            }
            if (modrm == 0xec) {
                /* FLDLG2: push log10(2) */
                out->opcode = HB_INS_X87_FLD;
                set_imm(out, 1, -6, 1);
                return HB_OK;
            }
            if (modrm == 0xed) {
                /* FLDLN2: push ln(2) */
                out->opcode = HB_INS_X87_FLD;
                set_imm(out, 1, -7, 1);
                return HB_OK;
            }
            if (modrm >= 0xc0 && modrm <= 0xc7) out->opcode = HB_INS_X87_FLD;
            else if (modrm >= 0xc8 && modrm <= 0xcf) out->opcode = HB_INS_X87_FXCH;
            else if (modrm == 0xfc) {
                /* FRNDINT — must come before the 0xf8..0xff FUCOMPI range. */
                out->opcode = HB_INS_X87_FRNDINT;
                return HB_OK;
            }
            else if (modrm == 0xd0) {
                /* FNOP — FPU no-op. */
                out->opcode = HB_INS_X87_FNOP;
                return HB_OK;
            }
            else if (modrm >= 0xd1 && modrm <= 0xd7) out->opcode = HB_INS_X87_FSTP; /* FSTPNCE — undocumented */
            else if (modrm >= 0xd8 && modrm <= 0xdf) out->opcode = HB_INS_X87_FSTP;
            else if (modrm == 0xe0) { out->opcode = HB_INS_X87_FCHS; return HB_OK; }
            else if (modrm == 0xe1) { out->opcode = HB_INS_X87_FABS; return HB_OK; }
            else if (modrm == 0xe4) { out->opcode = HB_INS_X87_FTST; return HB_OK; }
            else if (modrm == 0xe5) { out->opcode = HB_INS_X87_FXAM; return HB_OK; }
            else if (modrm == 0xf6) { out->opcode = HB_INS_X87_FDECSTP; return HB_OK; }
            else if (modrm == 0xf7) { out->opcode = HB_INS_X87_FINCSTP; return HB_OK; }
            else if (modrm >= 0xe8 && modrm <= 0xee) out->opcode = HB_INS_X87_FLD;  /* FLD1/FLDL2T/.../FLDZ */
            else if (modrm == 0xf0) { out->opcode = HB_INS_X87_F2XM1;   return HB_OK; }
            else if (modrm == 0xf1) { out->opcode = HB_INS_X87_FYL2X;   return HB_OK; }
            else if (modrm == 0xf2) { out->opcode = HB_INS_X87_FPTAN;   return HB_OK; }
            else if (modrm == 0xf3) { out->opcode = HB_INS_X87_FPATAN;  return HB_OK; }
            else if (modrm == 0xf4) { out->opcode = HB_INS_X87_FXTRACT; return HB_OK; }
            else if (modrm == 0xf5) { out->opcode = HB_INS_X87_FPREM1;  return HB_OK; }
            else if (modrm == 0xf8) { out->opcode = HB_INS_X87_FPREM;   return HB_OK; }
            else if (modrm == 0xf9) { out->opcode = HB_INS_X87_FYL2XP1; return HB_OK; }  /* per capstone, D9 F9 = FYL2XP1 */
            else if (modrm == 0xfa) { out->opcode = HB_INS_X87_FSQRT;   return HB_OK; }
            else if (modrm == 0xfb) { out->opcode = HB_INS_X87_FSINCOS; return HB_OK; }
            else if (modrm == 0xfc) { out->opcode = HB_INS_X87_FRNDINT; return HB_OK; }
            else if (modrm == 0xfd) { out->opcode = HB_INS_X87_FSCALE;  return HB_OK; }
            else if (modrm == 0xfe) { out->opcode = HB_INS_X87_FSIN;    return HB_OK; }
            else if (modrm == 0xff) { out->opcode = HB_INS_X87_FCOS;    return HB_OK; }
            else return HB_ERR_UNSUPPORTED_OPCODE;
            set_imm(out, 1, sti, 1);
            return HB_OK;
        }
        if (opcode == 0xde) {
            if (modrm >= 0xc0 && modrm <= 0xc7) out->opcode = HB_INS_X87_FADDP;
            else if (modrm >= 0xc8 && modrm <= 0xcf) out->opcode = HB_INS_X87_FMULP;
            else if (modrm == 0xd9) out->opcode = HB_INS_X87_FCOMPP;
            /* DE D0+i — ПСЕВДОНИМ FCOMP ST(i); ПОСЛЕ проверки на 0xd9 (FCOMPP). */
            else if (modrm >= 0xd0 && modrm <= 0xd7) out->opcode = HB_INS_X87_FCOMP;
            else if (modrm >= 0xe0 && modrm <= 0xe7) out->opcode = HB_INS_X87_FSUBRP;
            else if (modrm >= 0xe8 && modrm <= 0xef) out->opcode = HB_INS_X87_FSUBP;
            else if (modrm >= 0xf0 && modrm <= 0xf7) out->opcode = HB_INS_X87_FDIVRP;
            else if (modrm >= 0xf8) out->opcode = HB_INS_X87_FDIVP;
            else return HB_ERR_UNSUPPORTED_OPCODE;
            set_imm(out, 1, sti, 1);
            return HB_OK;
        }
        if (opcode == 0xdb) {
            /* Итерация 888 — FENI (DB E0), FDISI (DB E1), FSETPM (DB E4).
             * Команды 8087, обессмысленные уже на 80287: маскирование прерываний сопроцессора
             * и переключение в защищённый режим делает сам процессор. На всём, что новее 8087,
             * они не делают НИЧЕГО.
             * ★ Это не объявлено по справочнику, а ИЗМЕРЕНО эталоном: состояние после каждой из
             * трёх совпало с состоянием после двух `nop` той же длины по всем сверяемым полям
             * (регистры, xmm, флаги, хеши памяти и стека, `fpu`). Контроль в том же замере —
             * `fisttp`, он отличается по `data_hash` и `fpu`, то есть сравнение чувствительное,
             * а не пустое.
             * Поэтому отображаем на уже существующий x87-NOP: свой опкод здесь не нужен. */
            if (modrm == 0xe0 || modrm == 0xe1 || modrm == 0xe4) {
                out->opcode = HB_INS_X87_FNOP;
                return HB_OK;
            }
            /* У FNCLEX и FNINIT операндов НЕТ ВОВСЕ. Ранний возврат, как у
             * FNOP выше: иначе общий `set_imm(out, 1, sti, 1)` в конце ветви
             * дописывал им МЁРТВЫЙ непосредственный операнд — лифтер его не
             * читает (`hb_ir_emit(b, HB_IR_X87_FNINIT)` без операндов), а
             * доска считала расхождением с эталоном. */
            if (modrm == 0xe2 || modrm == 0xe3) {
                out->opcode = (modrm == 0xe2) ? HB_INS_X87_FNCLEX : HB_INS_X87_FNINIT;
                return HB_OK;
            }
            if (0) ;
            else if (modrm >= 0xc0 && modrm <= 0xc7) out->opcode = HB_INS_X87_FCMOV; /* FCMOVNB */
            else if (modrm >= 0xc8 && modrm <= 0xcf) out->opcode = HB_INS_X87_FCMOV; /* FCMOVNE */
            else if (modrm >= 0xd0 && modrm <= 0xd7) out->opcode = HB_INS_X87_FCMOV; /* FCMOVNBE */
            else if (modrm >= 0xd8 && modrm <= 0xdf) out->opcode = HB_INS_X87_FCMOV; /* FCMOVNU */
            else if (modrm >= 0xe8 && modrm <= 0xef) out->opcode = HB_INS_X87_FUCOMI;
            else if (modrm >= 0xf0 && modrm <= 0xf7) out->opcode = HB_INS_X87_FCOMI;
            else return HB_ERR_UNSUPPORTED_OPCODE;
            set_imm(out, 1, sti, 1);
            return HB_OK;
        }
        if (opcode == 0xda) {
            /* FCMOVB/FCMOVE/FCMOVBE/FCMOVU + FUCOMPP (Pentium Pro+). */
            if (modrm >= 0xc0 && modrm <= 0xc7) out->opcode = HB_INS_X87_FCMOV; /* FCMOVB */
            else if (modrm >= 0xc8 && modrm <= 0xcf) out->opcode = HB_INS_X87_FCMOV; /* FCMOVE */
            else if (modrm >= 0xd0 && modrm <= 0xd7) out->opcode = HB_INS_X87_FCMOV; /* FCMOVBE */
            else if (modrm >= 0xd8 && modrm <= 0xdf) out->opcode = HB_INS_X87_FCMOV; /* FCMOVU */
            else if (modrm == 0xe9) {
                /* FUCOMPP ST(0), ST(1) — pop twice. */
                out->opcode = HB_INS_X87_FCOMPP;
                set_imm(out, 1, 1, 1);
                return HB_OK;
            }
            else return HB_ERR_UNSUPPORTED_OPCODE;
            set_imm(out, 1, sti, 1);
            return HB_OK;
        }
        if (opcode == 0xdc) {
            /* FADD/FSUB/FMUL/FDIV ST(i), ST (mod=3 form). */
            if (modrm >= 0xc0 && modrm <= 0xc7) out->opcode = HB_INS_X87_FADD;
            else if (modrm >= 0xc8 && modrm <= 0xcf) out->opcode = HB_INS_X87_FMUL;
            /* DC D0+i / DC D8+i — ПСЕВДОНИМЫ FCOM ST(i) / FCOMP ST(i). На x64
             * они были с самого начала (hb_decode_x64.c, общая ветвь 0xd8/0xdc),
             * здесь их не было ВОВСЕ: i386 отвечал HB_ERR_UNSUPPORTED_OPCODE.
             * Сравнение ничего не пишет в стек, поэтому вопрос о направлении
             * приёмника у DC (ST(i) против ST(0)) этих двух групп не касается. */
            else if (modrm >= 0xd0 && modrm <= 0xd7) out->opcode = HB_INS_X87_FCOM;
            else if (modrm >= 0xd8 && modrm <= 0xdf) out->opcode = HB_INS_X87_FCOMP;
            else if (modrm >= 0xe0 && modrm <= 0xe7) out->opcode = HB_INS_X87_FSUB;
            else if (modrm >= 0xe8 && modrm <= 0xef) out->opcode = HB_INS_X87_FSUBR;
            else if (modrm >= 0xf0 && modrm <= 0xf7) out->opcode = HB_INS_X87_FDIV;
            else if (modrm >= 0xf8) out->opcode = HB_INS_X87_FDIVR;
            else return HB_ERR_UNSUPPORTED_OPCODE;
            set_imm(out, 1, sti, 1);
            return HB_OK;
        }
        if (opcode == 0xdd) {
            /* FFREE / FST / FSTP / FUCOM / FUCOMP (mod=3 form). */
            if (modrm >= 0xc0 && modrm <= 0xc7) {
                out->opcode = HB_INS_X87_FFREE;
                set_imm(out, 1, sti, 1);
                return HB_OK;
            }
            /* DD C8+i — ПСЕВДОНИМ FXCH ST(i). Разбор — в hb_decode_x64.c у 0xdf. */
            else if (modrm >= 0xc8 && modrm <= 0xcf) {
                out->opcode = HB_INS_X87_FXCH;
                set_imm(out, 1, sti, 1);
                return HB_OK;
            }
            else if (modrm >= 0xd0 && modrm <= 0xd7) {
                out->opcode = HB_INS_X87_FST;
                set_imm(out, 1, sti, 1);
                return HB_OK;
            }
            else if (modrm >= 0xd8 && modrm <= 0xdf) {
                out->opcode = HB_INS_X87_FSTP;
                set_imm(out, 1, sti, 1);
                return HB_OK;
            }
            else if (modrm >= 0xe0 && modrm <= 0xe7) {
                out->opcode = HB_INS_X87_FUCOM;
                set_imm(out, 1, sti, 1);
                return HB_OK;
            }
            else if (modrm >= 0xe8 && modrm <= 0xef) {
                out->opcode = HB_INS_X87_FUCOMP;
                set_imm(out, 1, sti, 1);
                return HB_OK;
            }
            return HB_ERR_UNSUPPORTED_OPCODE;
        }
        if (opcode == 0xdf) {
            /* FFREEP ST(i) and FUCOMPI/FCOMPI (mod=3 form). */
            if (modrm >= 0xc0 && modrm <= 0xc7) {
                out->opcode = HB_INS_X87_FFREEP;
                set_imm(out, 1, sti, 1);
                return HB_OK;
            }
            /* DF C8+i, DF D0+i, DF D8+i — ПСЕВДОНИМЫ FXCH ST(i) и FSTP ST(i).
             * Тот же текст, что и в hb_decode_x64.c: одна карта команд на обе
             * ветви, иначе i386 снова отстанет от x64 (это уже случалось —
             * соответствие было записано руками ТРИЖДЫ). Разбор и список
             * замеров — в комментарии у 0xdf в hb_decode_x64.c. */
            else if (modrm >= 0xc8 && modrm <= 0xcf) {
                out->opcode = HB_INS_X87_FXCH;
                set_imm(out, 1, sti, 1);
                return HB_OK;
            }
            else if (modrm >= 0xd0 && modrm <= 0xdf) {
                out->opcode = HB_INS_X87_FSTP;
                set_imm(out, 1, sti, 1);
                return HB_OK;
            }
            else if (modrm >= 0xe8 && modrm <= 0xef) {
                out->opcode = HB_INS_X87_FUCOMPI;
                set_imm(out, 1, sti, 1);
                return HB_OK;
            }
            else if (modrm >= 0xf0 && modrm <= 0xf7) {
                out->opcode = HB_INS_X87_FCOMPI;
                set_imm(out, 1, sti, 1);
                return HB_OK;
            }
            return HB_ERR_UNSUPPORTED_OPCODE;
        }
        return HB_ERR_UNSUPPORTED_OPCODE;
    }

    switch (opcode) {
        case 0xd8:
        case 0xdc:
            size = (opcode == 0xd8) ? 4 : 8;
            switch (reg_op) {
                case 0: out->opcode = HB_INS_X87_FADD; break;
                case 1: out->opcode = HB_INS_X87_FMUL; break;
                case 2: out->opcode = HB_INS_X87_FCOM; break;
                case 3: out->opcode = HB_INS_X87_FCOMP; break;
                case 4: out->opcode = HB_INS_X87_FSUB; break;
                case 5: out->opcode = HB_INS_X87_FSUBR; break;
                case 6: out->opcode = HB_INS_X87_FDIV; break;
                case 7: out->opcode = HB_INS_X87_FDIVR; break;
            }
            break;
        case 0xd9:
            if (reg_op == 0) { out->opcode = HB_INS_X87_FLD; size = 4; }
            else if (reg_op == 2) { out->opcode = HB_INS_X87_FST; size = 4; }
            else if (reg_op == 3) { out->opcode = HB_INS_X87_FSTP; size = 4; }
            else if (reg_op == 4) { out->opcode = HB_INS_X87_FLDENV; size = 28; }
            else if (reg_op == 5) { out->opcode = HB_INS_X87_FLDCW; size = 2; }
            else if (reg_op == 6) { out->opcode = HB_INS_X87_FNSTENV; size = 28; }
            else if (reg_op == 7) { out->opcode = HB_INS_X87_FNSTCW; size = 2; }
            else return HB_ERR_UNSUPPORTED_OPCODE;
            break;
        case 0xda:
            /* FIADD/FIMUL/FICOM/FICOMP/FISUB/FISUBR/FIDIV/FIDIVR m32int.
             * Итерация 906: восемь одинаковых строк выбрасывали `reg_op`, и различить формы
             * дальше по дороге было НЕЧЕМ — лифтер не мог поднять опкод, все восемь команд
             * отказывали `-5`. Вид действия кладём вторым операндом (слот 1 занимает память,
             * её заполняет parse_modrm_ext ниже). */
            out->opcode = HB_INS_X87_FI; size = 4; fi_sub = (int)reg_op;
            break;
        case 0xdb:
            /* Итерация 887: `FISTTP m32int` (DB /1). Ветви `reg_op == 1` не было ни у одного из
             * трёх опкодов (DB/DD/DF) — три пробела из восьми оставшихся у x87. Декодер x64 их
             * разбирает (`hb_decode_x64.c:815,828,837`), лифтер и интерпретатор умеют с
             * итерации 350, где записана и суть команды: FISTP округляет по управляющему слову,
             * а FISTTP ВСЕГДА усекает к нулю. То есть недоставало ровно этой строки. */
            if (reg_op == 0) { out->opcode = HB_INS_X87_FILD; size = 4; }
            else if (reg_op == 1) { out->opcode = HB_INS_X87_FISTTP; size = 4; }
            else if (reg_op == 2) { out->opcode = HB_INS_X87_FIST; size = 4; }
            else if (reg_op == 3) { out->opcode = HB_INS_X87_FISTP; size = 4; }
            else if (reg_op == 5) { out->opcode = HB_INS_X87_FLD; size = 10; }  /* FLD m80 (extended) */
            else if (reg_op == 7) { out->opcode = HB_INS_X87_FSTP; size = 10; } /* FSTP m80 (extended) */
            else return HB_ERR_UNSUPPORTED_OPCODE;
            break;
        case 0xde:
            /* FIADD/FIMUL/FICOM/FICOMP/FISUB/FISUBR/FIDIV/FIDIVR m16int (см. 0xda выше). */
            out->opcode = HB_INS_X87_FI; size = 2; fi_sub = (int)reg_op;
            break;
        case 0xdd:
            if (reg_op == 0) { out->opcode = HB_INS_X87_FLD; size = 8; }
            else if (reg_op == 1) { out->opcode = HB_INS_X87_FISTTP; size = 8; }  /* итер. 887: DD /1 m64int */
            else if (reg_op == 2) { out->opcode = HB_INS_X87_FST; size = 8; }
            else if (reg_op == 3) { out->opcode = HB_INS_X87_FSTP; size = 8; }
            else if (reg_op == 4) { out->opcode = HB_INS_X87_FRSTOR; size = 108; }
            else if (reg_op == 6) { out->opcode = HB_INS_X87_FNSAVE; size = 108; }
            else if (reg_op == 7) { out->opcode = HB_INS_X87_FNSTSW; size = 2; }
            else return HB_ERR_UNSUPPORTED_OPCODE;
            break;
        case 0xdf:
            if (reg_op == 0) { out->opcode = HB_INS_X87_FILD; size = 2; }
            else if (reg_op == 1) { out->opcode = HB_INS_X87_FISTTP; size = 2; }  /* итер. 887: DF /1 m16int */
            else if (reg_op == 2) { out->opcode = HB_INS_X87_FIST; size = 2; }
            else if (reg_op == 3) { out->opcode = HB_INS_X87_FISTP; size = 2; }
            /* Итерация 1047: DF /4 FBLD и DF /6 FBSTP — упакованный BCD, 10 байт.
             * Раньше проваливались в общий отказ: перечисление 1045 назвало их
             * единственными настоящими пробелами декодера, не считая AVX и дальних переходов. */
            else if (reg_op == 4) { out->opcode = HB_INS_X87_FBLD; size = 10; }
            else if (reg_op == 6) { out->opcode = HB_INS_X87_FBSTP; size = 10; }
            else if (reg_op == 5) { out->opcode = HB_INS_X87_FILD; size = 8; }
            else if (reg_op == 7) { out->opcode = HB_INS_X87_FISTP; size = 8; }
            else return HB_ERR_UNSUPPORTED_OPCODE;
            break;
        default:
            return HB_ERR_UNSUPPORTED_OPCODE;
    }

    {
        hb_result_t r = parse_modrm_ext(d, modrm, size, out, 1);
        /* Итерация 906: вид действия семьи `FI` — вторым операндом, ПОСЛЕ разбора памяти
         * (она занимает слот 1). Без этого лифтеру нечем отличить FIADD от FIDIV. */
        if (r == HB_OK && fi_sub >= 0) set_imm(out, 2, fi_sub, 1);
        return r;
    }
}

static int cond_from_cc(uint8_t cc) {
    switch (cc) {
        case 0: return HB_COND_O;
        case 1: return HB_COND_NO;
        case 2: return HB_COND_B;
        case 3: return HB_COND_AE;
        case 4: return HB_COND_E;
        case 5: return HB_COND_NE;
        case 6: return HB_COND_BE;
        case 7: return HB_COND_A;
        case 8: return HB_COND_S;
        case 9: return HB_COND_NS;
        case 10: return HB_COND_P;
        case 11: return HB_COND_NP;
        case 12: return HB_COND_L;
        case 13: return HB_COND_GE;
        case 14: return HB_COND_LE;
        case 15: return HB_COND_G;
        default: return HB_COND_NONE;
    }
}

static hb_result_t decode_one(hb_dec_t* d, hb_decoded_t* out) {
    if (d->pos >= d->len) return HB_ERR_DECODE_FAILED;

    uint64_t addr = d->addr;

    memset(out, 0, sizeof(hb_decoded_t));
    out->addr = addr;

    bool operand16 = false;
    bool address16 = false;
    bool prefix_f0 = false;
    bool prefix_f2 = false;
    bool prefix_f3 = false;
    uint8_t opcode = 0;

    while (can_read(d, 1)) {
        uint8_t b = d->code[d->pos];
        if (b == 0x26 || b == 0x2e || b == 0x36 || b == 0x3e ||
            b == 0x64 || b == 0x65 || b == 0x66 || b == 0x67 ||
            b == 0xf0 || b == 0xf2 || b == 0xf3)
        {
            if (b == 0x66) operand16 = true;
            else if (b == 0x67) { address16 = true; d->addr16_active = true; }
            else if (b == 0xf0) prefix_f0 = true;
            else if (b == 0xf2) prefix_f2 = true;
            else if (b == 0xf3) prefix_f3 = true;
            /* ВСЕ ШЕСТЬ префиксов сегмента, а не только FS и GS.
             *
             * Классические 0x26/0x2e/0x36/0x3e съедались МОЛЧА, и при
             * нескольких префиксах побеждал не последний, как требует
             * спецификация, а последний из двух записываемых. Замер:
             * `65 64 2e 20 00` — эталон даёт cs, мы давали fs.
             *
             * Безопасно: интерпретатор особо разбирает только 0x64 и 0x65
             * (прибавляет базу), у прочих в плоском 32-битном режиме база и
             * есть ноль. Описание становится точным, вычисление адреса не
             * меняется. */
            else if (b == 0x26 || b == 0x2e || b == 0x36 || b == 0x3e ||
                     b == 0x64 || b == 0x65) out->segment_prefix = b;
            d->pos++;
        }
        else break;
    }

    /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 920 — ПРЕФИКС БЛОКИРОВКИ ТЕРЯЛСЯ.
     * `prefix_f0` здесь распознавался и использовался только для отказов, а в поле
     * `out->lock_prefix` НЕ КЛАЛСЯ — в отличие от ветви x64 (`hb_decode_x64.c:966`), где оно
     * заполняется и лифтер по нему помечает команды `is_locked`, а кодогенератор ставит
     * барьер. Комментарий у самого поля объясняет, зачем: Mono крутит хазард-указатели через
     * `lock or [rsp],r` как барьер запись->чтение, и без него перечитывание на ARM64 берёт
     * устаревшее значение, а цикл живёт вечно.
     * Найдено сверкой префиксов, заведённой в этой же итерации: эталон пишет `lock add`, наш
     * декодер отвечал `lock_prefix=false`. До этого префиксы не сверялись вовсе. */
    out->lock_prefix = prefix_f0;

    /* F2/F3 (REPNE/REPZ) are ignored on most non-string ops per Intel SDM
     * Vol 2 (and used as XACQUIRE/XRELEASE for HLE; we don't model HLE).
     * We KEEP prefix_f2/prefix_f3 for the 0F escape map and for string
     * ops, since the 0F SSE/SSE2/SSE3 family uses F2/F3 as the operand-type
     * selector (MOVSD vs MOVSS, HADDPS vs HSUBPS, ...). */
    if (can_read(d, 1) && d->code[d->pos] != 0x0F) {
        uint8_t o = d->code[d->pos];
        bool is_string_op = (o >= 0x6C && o <= 0x6F) ||  /* INS/OUTS */
                            (o >= 0xA4 && o <= 0xA7) ||  /* MOVS/CMPS */
                            (o >= 0xAA && o <= 0xAF) ||  /* STOS/LODS/SCAS */
                            o == 0x90;                   /* NOP/PAUSE */
        if (!is_string_op) {
            prefix_f2 = false;
            prefix_f3 = false;
        }
    }

    if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
    opcode = read_u8(d);

    /* NOP/cache-hint family. MSVC/Wine use prefixed NOPs (for example
       66 90 at i386 ntdll!LdrInitializeThunk) for alignment. */
    if (opcode == 0x90) {
        out->opcode = HB_INS_NOP;
        return HB_OK;
    }
    if (opcode == 0x9B) {
        /* FWAIT waits for pending x87 exceptions. HyperBridge does not model
           asynchronous x87 exceptions yet, so it is a serialization no-op. */
        out->opcode = HB_INS_NOP;
        return HB_OK;
    }
    if (opcode == 0x60 || opcode == 0x61) {
        /* PUSHA / PUSHAD (0x60) and POPA / POPAD (0x61).
         * PUSHAD is the 32-bit form (default in 32-bit mode); PUSHA is the 16-bit
         * form (selected with the 0x66 operand-size prefix). Likewise for POPA. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = (opcode == 0x60) ? HB_INS_PUSHA : HB_INS_POPA;
        out->writes_flags = false;
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 998 — 16-БИТНАЯ ФОРМА НЕ ДОХОДИЛА.
         * Интерпретатор выбирает ширину по `size` операнда (`== HB_SIZE_16`, а это 2).
         * Было: у PUSHA размер задавался единицей (это HB_SIZE_8), у POPA операнд вообще не
         * помечался присутствующим — `operand_from_dec` возвращал пустой, и размер терялся.
         * В обоих случаях 16-битная форма молча исполнялась как 32-битная. Поймано
         * семантическим стендом на `dbe3d9e8d9ebd9ea656661` (POPAW): расходились eax, ebx, ecx.
         * Теперь размер операнда несёт саму ширину, и значение то же — для обеих команд. */
        set_imm(out, 1, operand16 ? 2 : 4, operand16 ? 2 : 4);
        return HB_OK;
    }
    if (opcode == 0x06 || opcode == 0x0E || opcode == 0x16 || opcode == 0x1E) {
        /* PUSH ES/CS/SS/DS — segment register push (32-bit user mode only).
         * 64-bit mode #UDs these; we reject by checking that we're not in 64-bit
         * (the caller should not invoke hb_decode_x86 in that mode anyway, but
         * we still validate the prefix set: LOCK, REP/REPNE, and address-size
         * override are illegal). */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_PUSH_SEG;
        out->writes_flags = false;
        out->stack_delta = operand16 ? 2 : 4;
        /* Encode the segment selector in op2.imm — the lift+interpreter use it
         * to identify which segment (0=ES, 1=CS, 2=SS, 3=DS, 4=FS, 5=GS). */
        set_imm(out, 1, 0, out->stack_delta);
        set_imm(out, 2, (opcode >> 3) & 7, 1);
        return HB_OK;
    }
    if (opcode == 0x07 || opcode == 0x17 || opcode == 0x1F) {
        /* POP ES/SS/DS — segment register pop. POP CS is undefined in 32-bit
         * user mode and #UDs; POP FS/GS (0x0F A1 / 0x0F A9) is the 0F-escape
         * form, handled in the 0F map. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_POP_SEG;
        out->writes_flags = false;
        out->stack_delta = -(int)(operand16 ? 2 : 4);
        set_imm(out, 1, 0, operand16 ? 2 : 4);
        set_imm(out, 2, (opcode >> 3) & 7, 1);
        return HB_OK;
    }
    if (opcode == 0xF8 || opcode == 0xF9 || opcode == 0xF5 ||
        opcode == 0xFA || opcode == 0xFB ||
        opcode == 0xFC || opcode == 0xFD) {
        /* Flag ops: CLC (F8), STC (F9), CMC (F5), CLI (FA), STI (FB),
         * CLD (FC), STD (FD). */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->writes_flags = true;
        switch (opcode) {
            case 0xF8: out->opcode = HB_INS_CLC; return HB_OK;
            case 0xF9: out->opcode = HB_INS_STC; return HB_OK;
            case 0xF5: out->opcode = HB_INS_CMC; return HB_OK;
            case 0xFA: out->opcode = HB_INS_CLI; return HB_OK;
            case 0xFB: out->opcode = HB_INS_STI; return HB_OK;
            case 0xFC: out->opcode = HB_INS_CLD; return HB_OK;
            case 0xFD: out->opcode = HB_INS_STD; return HB_OK;
            default: return HB_ERR_UNSUPPORTED_OPCODE;
        }
    }
    if (opcode == 0x98) {
        /* CBW / CWDE — sign-extend AL into AX (16-bit opsize) or AX into EAX
         * (32-bit opsize). Valid in 32-bit user mode; no prefix allowed. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_CWDE;
        out->reads_flags = false;
        out->writes_flags = false;
        /* Итерация 262: тот же дефект, что у 0x99 — лифтер `HB_INS_CWDE` выбирает ширину по
         * `dec->op1.size` (1 → CBW, 2 → CWDE), а `set_imm(..., 1)` давал единицу ВСЕГДА, то есть
         * `CWDE` молча исполнялась как `CBW`. */
        set_reg(out, 1, HB_REG_RAX, operand16 ? 1 : 2);
        return HB_OK;
    }
    if (opcode == 0x99) {
        /* CDQ / CWDE / CQO — Sign-Extend EAX into EDX:EAX (CDQ) for 32-bit
         * opsize, sign-extend AX into DX:EAX (CWD) for 16-bit opsize, or
         * sign-extend RAX into RDX:RAX (CQO) for 64-bit opsize. HyperBridge
         * names the i386 default op as CWD (matches the existing x64 naming);
         * the lift reads op1.size to choose. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_CWD;
        out->reads_flags = false;
        out->writes_flags = false;
        /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 262 — РАЗМЕР В ОПЕРАНД, А НЕ В ЗНАЧЕНИЕ.
         * Было `set_imm(out, 1, operand16 ? 2 : 4, 1)`: нужный размер клался в ЗНАЧЕНИЕ
         * непосредственного операнда, а его `size` оставался единицей. Лифтер же и интерпретатор
         * читают именно `op1.size` (об этом прямо сказано в комментарии выше и в лифтере), и
         * `CWD` приходила с размером 1. Интерпретатор обрабатывает 16/32/64 и на единицу
         * возвращает `HB_ERR_UNSUPPORTED_OPCODE` — на этом умирала ступень 1 Diablo:
         * `exec=UNSUPPORTED_OPCODE(-5)` на `0x448ef0`, байт `99` (CDQ).
         * Декодер x64 делает это верно (`hb_decode_x64.c:3009`), i386 — нет. */
        set_reg(out, 1, HB_REG_RAX, operand16 ? 2 : 4);
        return HB_OK;
    }
    if (opcode == 0xCF) {
        /* IRET / IRETD — interrupt return. 16-bit opsize = IRET (pops IP+CS+FLAGS),
         * 32-bit opsize = IRETD (pops EIP+CS+EFLAGS). */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_IRET;
        out->reads_flags = true;
        out->writes_flags = true;
        out->is_ret = true;
        out->stack_delta = -(int)(operand16 ? 6 : 12);
        return HB_OK;
    }
    if (opcode == 0xCE) {
        /* INTO — interrupt 4 if OF=1. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_INTO;
        out->reads_flags = true;
        return HB_OK;
    }
    if (opcode == 0xCC) {
        /* INT3 — debug breakpoint (3-byte form, also reachable as INT 3). */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_INT3;
        return HB_OK;
    }
    if (opcode == 0xCD) {
        /* INT n — vectored software interrupt. imm8 vector. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t vector = read_u8(d);
        out->opcode = HB_INS_INT;
        out->reads_flags = true;
        out->writes_flags = true;
        set_imm(out, 1, vector, 1);
        return HB_OK;
    }
    if (opcode == 0xF1) {
        /* INT1 / ICEBP — debug breakpoint (1-byte form, ICEBP). */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_INT1;
        return HB_OK;
    }
    if (opcode == 0xCA) {
        /* RETF imm16 — far return, with stack-adjust. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        if (!can_read(d, 2)) return HB_ERR_DECODE_FAILED;
        uint16_t imm = (uint16_t)read_s16(d);
        out->opcode = HB_INS_RETF;
        out->is_ret = true;
        out->ret_imm = imm;
        out->writes_flags = true;
        out->reads_flags = true;
        return HB_OK;
    }
    if (opcode == 0xCB) {
        /* RETF — far return, no stack-adjust. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_RETF;
        out->is_ret = true;
        out->writes_flags = true;
        out->reads_flags = true;
        return HB_OK;
    }
    if (opcode == 0x9A || opcode == 0xEA) {
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 922 — ДАЛЬНИЙ ВЫЗОВ И ПЕРЕХОД
         * СООБЩАЛИ УСПЕХ И НЕ ДЕЛАЛИ НИЧЕГО.
         *
         * Разбирались как обычные `CALL`/`JMP`, причём первым источником шёл СЕГМЕНТ. Лифтера
         * для дальней формы на этой ветви нет вовсе. Замер:
         *   `9a04030201 lcall 0x0102:0x00020304`  result=0, eip НЕ сдвинулся, стек не тронут
         *   контроль `e800000000 near call`       result=0, eip=0x00100005, esp -4  (верно)
         * То есть управление не передавалось и адрес возврата не клался, а движок отвечал
         * «выполнено». Программа поехала бы дальше с испорченным потоком управления, и это
         * не видно ни в каком журнале.
         *
         * Сегментных дескрипторов мы не моделируем, поэтому честный ответ — ОТКАЗ, как у
         * `LAR`/`LSL` в 921. Отказ виден сразу; позовёт настоящая программа — реализуем по
         * замеру, а не по догадке. Длина этих форм починена в 916 и остаётся верной для
         * того, кто будет их реализовывать.
         *
         * ★ MacRunner 2026-08-28 — РЕАЛИЗОВАНО, отказ снят.
         *
         * Довод «не моделируем дескрипторы» верен наполовину: дескрипторы нужны, чтобы
         * ПРОВЕРИТЬ переход и сменить базу сегмента, но в плоской модели Windows база CS
         * нулевая, а права на исполнение по новому адресу проверяет хозяйский MMU. Чего
         * недоставало на деле — передать управление и записать CS; теперь это делает
         * `HB_IR_FAR_BRANCH` в интерпретаторе: для вызова кладёт пару (CS, адрес
         * возврата) — ровно ту, что снимает парный `RETF` рядом, — и ставит `ctx->pc`
         * вместе с `seg[1]`. Формы через память (`FF /3`, `FF /5`) разбирались и
         * раньше, но не поднимались; закрыты тем же лифтом. */

    }
    if (opcode == 0xEA) {
        /* JMP ptr16:32 — far direct jump. Imm32 offset + imm16 segment. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
                /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 916 — ДАЛЬНИЙ УКАЗАТЕЛЬ ПОД `66`.
         * Смещение дальнего указателя следует за размером ОПЕРАНДА: под `66` это
         * `ptr16:16` (два байта смещения), без него `ptr16:32` (четыре). Читали четыре
         * всегда — под `66` съедали два лишних байта (полный перебор: 12 строк). */
        uint32_t offset;
        uint16_t segment;
        if (operand16) {
            if (!can_read(d, 2 + 2)) return HB_ERR_DECODE_FAILED;
            offset = (uint16_t)read_s16(d);
        } else {
            if (!can_read(d, 4 + 2)) return HB_ERR_DECODE_FAILED;
            offset = (uint32_t)read_s32(d);
        }
        segment = (uint16_t)read_s16(d);
        /* ★ MacRunner 2026-08-28 — БЫЛ `HB_INS_JMP`, ТО ЕСТЬ ОБЫЧНЫЙ ПЕРЕХОД.
         * Ровно то, на что жалуется запись итерации 922 выше: дальняя форма
         * выдавала себя за ближнюю, селектор уходил в первый операнд и терялся.
         * Теперь это своя команда с собственным лифтом и семантикой. */
        out->opcode = HB_INS_JMP_FAR_IMM;
        out->writes_flags = false;
        set_imm(out, 1, (int64_t)(uint32_t)offset, operand16 ? 2 : 4);
        set_imm(out, 2, (int64_t)segment, 2);
        return HB_OK;
    }
    if (opcode == 0x9A) {
        /* CALL ptr16:32 — дальний вызов с непосредственным. Разбор тот же, что у
         * `EA` выше (смещение по ширине операнда, затем селектор), различает их
         * только команда: вызов дополнительно кладёт на стек пару (CS, возврат). */
        uint32_t offset;
        uint16_t segment;
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        if (operand16) {
            if (!can_read(d, 2 + 2)) return HB_ERR_DECODE_FAILED;
            offset = (uint16_t)read_s16(d);
        } else {
            if (!can_read(d, 4 + 2)) return HB_ERR_DECODE_FAILED;
            offset = (uint32_t)read_s32(d);
        }
        segment = (uint16_t)read_s16(d);
        out->opcode = HB_INS_CALL_FAR_IMM;
        out->writes_flags = false;
        set_imm(out, 1, (int64_t)(uint32_t)offset, operand16 ? 2 : 4);
        set_imm(out, 2, (int64_t)segment, 2);
        return HB_OK;
    }
    if (opcode == 0xD6) {
        /* SALC (Set AL on Carry, undocumented opcode 0xD6). Implemented as
         * MOV AL, 0xFF if CF=1 else 0x00. We decode it and let the lift
         * materialize the SETC semantics. The 0x66 prefix is silently
         * ignored for this 8-bit-only opcode (Capstone accepts it). */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_SALC;
        out->reads_flags = true;
        out->writes_flags = false;
        return HB_OK;
    }
    if (opcode == 0xD7) {
        /* XLATB / XLAT — AL = [EBX+AL] (or [BX+AL] with 0x67). */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_XLAT;
        out->writes_flags = false;
        return HB_OK;
    }
    if (opcode == 0xC8) {
        /* ENTER imm16, imm8 — make stack frame for procedure parameters. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        if (!can_read(d, 3)) return HB_ERR_DECODE_FAILED;
        uint16_t frame_size = (uint16_t)read_s16(d);
        uint8_t nesting = read_u8(d);
        out->opcode = HB_INS_ENTER;
        out->writes_flags = true;
        out->reads_flags = true;
        set_imm(out, 1, frame_size, 2);
        set_imm(out, 2, nesting, 1);
        return HB_OK;
    }
    if (opcode >= 0x6C && opcode <= 0x6F) {
        /* INS/OUTS — string port I/O (privileged; #GP unless CPL<=IOPL).
         * Decoded as IN/OUT for the lift/interpret to raise a fault; op size
         * tracks operand16 (16-bit for 0x66 on INSW, 8-bit for INSB, 32-bit
         * for INSD, ditto for OUTS). */
        /* ★ MacRunner 2026-08-28 — REP/REPNE ЗАКОННЫ ЗДЕСЬ.
         * Отсекались вместе с LOCK, хотя `F3 6C` (REP INSB) и `F2 6E` (REPNE OUTSB)
         * — обычные строковые формы с префиксом повторения; capstone их принимает.
         * Само обращение к порту мы не моделируем (см. IN/OUT ниже), но РАЗБОР
         * обязан быть верным, иначе движок отвечает «не знаю команду» вместо
         * «не умею порты», и длина потока команд теряется. LOCK по-прежнему
         * недопустим. */
        if (prefix_f0) return HB_ERR_UNSUPPORTED_OPCODE;
        if (opcode == 0x6C) out->opcode = HB_INS_INS;
        else if (opcode == 0x6D) out->opcode = HB_INS_INS;
        else if (opcode == 0x6E) out->opcode = HB_INS_OUTS;
        else out->opcode = HB_INS_OUTS;
        if (opcode == 0x6C) set_imm(out, 1, 1, 1);
        else if (opcode == 0x6D) set_imm(out, 1, operand16 ? 2 : 4, 1);
        else if (opcode == 0x6E) set_imm(out, 1, 1, 1);
        else set_imm(out, 1, operand16 ? 2 : 4, 1);
        out->reads_flags = (opcode >= 0x6E);
        out->writes_flags = (opcode < 0x6E);
        return HB_OK;
    }
    if (opcode == 0xE4 || opcode == 0xE5 || opcode == 0xEC || opcode == 0xED) {
        /* IN — port I/O (privileged). HyperBridge doesn't model it; raise fault
         * rather than silently producing wrong state. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_IN;
        out->writes_flags = true;
        if (opcode == 0xE4 || opcode == 0xE5) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t port = read_u8(d);
            set_imm(out, 1, port, 1);
        }
        return HB_OK;
    }
    if (opcode == 0xE6 || opcode == 0xE7 || opcode == 0xEE || opcode == 0xEF) {
        /* OUT — port I/O (privileged). HyperBridge doesn't model it. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_OUT;
        out->reads_flags = true;
        if (opcode == 0xE6 || opcode == 0xE7) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t port = read_u8(d);
            set_imm(out, 1, port, 1);
        }
        return HB_OK;
    }
    if (opcode == 0xF4) {
        /* HLT — privileged. HyperBridge raises a fault (HB_ERR_EXEC_FAULT or
         * UNSUPPORTED_FEATURE) so the user knows the binary did something it
         * shouldn't. We do not silently NOP this. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_HLT;
        return HB_OK;
    }
    if (opcode == 0x27) {
        /* DAA — Decimal Adjust AL after Addition. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_DAA;
        out->reads_flags = true;
        out->writes_flags = true;
        return HB_OK;
    }
    if (opcode == 0x2F) {
        /* DAS — Decimal Adjust AL after Subtraction. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_DAS;
        out->reads_flags = true;
        out->writes_flags = true;
        return HB_OK;
    }
    if (opcode == 0x37) {
        /* AAA — ASCII Adjust After Addition. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_AAA;
        out->reads_flags = true;
        out->writes_flags = true;
        return HB_OK;
    }
    if (opcode == 0x3F) {
        /* AAS — ASCII Adjust After Subtraction. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_AAS;
        out->reads_flags = true;
        out->writes_flags = true;
        return HB_OK;
    }
    if (opcode == 0xD4) {
        /* AAM — ASCII Adjust After Multiply. imm8 (base) is mandatory. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t base = read_u8(d);
        out->opcode = HB_INS_AAM;
        out->reads_flags = false;
        out->writes_flags = true;
        set_imm(out, 1, base, 1);
        return HB_OK;
    }
    if (opcode == 0xD5) {
        /* AAD — ASCII Adjust Before Division. imm8 (base) is mandatory. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t base = read_u8(d);
        out->opcode = HB_INS_AAD;
        out->reads_flags = false;
        out->writes_flags = true;
        set_imm(out, 1, base, 1);
        return HB_OK;
    }
    if (opcode == 0x62) {
        /* ★★★★★★ EVEX НА i386 (04.09.2026).
         *
         * Здесь 0x62 разбирался только как BOUND, а при mod==11 честно
         * отказывал — но mod==11 после 0x62 это ИМЕННО EVEX: BOUND требует
         * память и с mod==11 не существует. То есть разграничитель уже стоял,
         * просто вторая ветвь не была написана.
         *
         * Машинерия масок в дереве СКВОЗНАЯ и уже работает: декодер отдаёт
         * evex_mask/evex_zero, лифтер x64 упаковывает их
         * (hb_lift_x64.c:88-92), интерпретатор применяет
         * (write_vec_reg_bytes_evex_masked). Не хватало только ветви i386.
         *
         * Соответствие берётся из ОБЩЕГО списка (вид 1 = EVEX), порождённого
         * с декодера x64 — здесь не решается ничего, что уже решено там.
         *
         * Раскладка EVEX: 62 P0 P1 P2 опкод modrm...
         *   P0 = R X B R' 0 0 m m      (карта в младших двух битах)
         *   P1 = W v v v v 1 p p
         *   P2 = z L'L b V' a a a      (aaa — номер регистра-маски)
         * В 32 битах законно: R=X=B=R'=1, W=0, vvvv=1111, V'=1. */
        /* Признак EVEX, точный для 32 бит:
         *   P0 старшая тетрада = 1111 (R=X=B=R'=1, расширений регистров нет),
         *   P0 биты 3-2 = 00, младшие два бита (карта) не ноль,
         *   P1 бит 2 = 1 — обязателен по спецификации.
         * Байт с тетрадой 1111 даёт mod=11, а BOUND требует ПАМЯТЬ и с mod=11
         * не существует — значит разделение однозначно, без догадок. */
        /* Требование «старшая тетрада = 1111» было ИЗБЫТОЧНЫМ: оно отсекало
         * формы с нулевым битом расширения регистра (например
         * `62 e1 7d 48 6f 00`, vmovdqa32 zmm0, [eax]) — 2 пробела на доске.
         * Достаточно того, что отсекает BOUND: старшие ДВА бита равны 11,
         * то есть mod=11, а BOUND требует ПАМЯТЬ и с mod=11 не существует. */
        if (can_read(d, 2) &&
            (d->code[d->pos] & 0xC0) == 0xC0 &&
            (d->code[d->pos] & 0x0C) == 0 && (d->code[d->pos] & 0x03) != 0 &&
            (d->code[d->pos + 1] & 0x04) != 0) {
            uint8_t p0 = read_u8(d), p1 = read_u8(d), p2 = read_u8(d);
            uint8_t evex_map = (uint8_t)(p0 & 3);
            uint8_t evex_pp = (uint8_t)(p1 & 3);
            uint8_t evex_ll = (uint8_t)((p2 >> 5) & 3);
            uint8_t evex_v = (uint8_t)((~p1 >> 3) & 7);
            uint8_t evex_w = (uint8_t)((p1 >> 7) & 1);
            uint8_t evex_b = (uint8_t)((p2 >> 4) & 1);   /* рассылка / округление */
            uint8_t evex_op, evex_modrm, evex_ext;
            const struct hb_vex_forma* f;

            /* см. выше: W у EVEX — тоже продолжение кода операции. */
            if (!can_read(d, 2)) return HB_ERR_DECODE_FAILED;
            evex_op = read_u8(d);
            evex_modrm = read_u8(d);
            evex_ext = (uint8_t)((evex_modrm >> 3) & 7);

            f = hb_najti_formu(1, evex_map, evex_pp, evex_ll, evex_w, evex_op, evex_ext,
                                 (unsigned)((evex_modrm >> 6) == 3 ? 3 : 0));
            if (!f) return HB_ERR_UNSUPPORTED_OPCODE;

            out->writes_flags = false;
            out->evex = true;      /* признак, по которому лифтер берёт маску */
            out->opcode = f->ins;
            out->evex_mask_lane = f->lane;
            out->evex_mask = (uint8_t)(p2 & 7);        /* aaa — регистр-маска */
            out->evex_zero = (p2 & 0x80) ? true : false;
            {
                hb_result_t vr;
                if (hb_razlozhit_po_rolyam(d, f, evex_modrm, evex_v, out, &vr)) {
                if (vr != HB_OK) return vr;
            } else if (f->s3 == 1) {
                    /* тот же случай: третий операнд размером 1 — непосредственный */
                    vr = parse_modrm(d, evex_modrm, f->s2, out, 1, 2, f->store != 0);
                    if (vr != HB_OK) return vr;
                    if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                    set_imm(out, 3, read_u8(d), 1);
                } else if (f->s3) {
                    vr = parse_modrm(d, evex_modrm, f->s3, out, 1, 3, false);
                    if (vr != HB_OK) return vr;
                    set_reg(out, 2, evex_v, f->s2);
                } else {
                    vr = parse_modrm(d, evex_modrm, f->store ? f->s1 : f->s2,
                                     out, 1, 2, f->store != 0);
                    if (vr != HB_OK) return vr;
                }
            }
            /* ТОЧНЫЙ размер из формы, а не «не меньше 16»: parse_modrm
             * получает ОДИН размер на оба операнда, поэтому приёмник у
             * рассылок выходил шириной с ИСТОЧНИК. */
            /* Класс из формы: 1 векторный, 2 МАСКА (k0..k7). */
            if (f->v1 == 2) mark_k_operand(out, 1);
            else if (f->v1) mark_vec_operand(out, 1, f->s1);
            if (f->v2 == 2) mark_k_operand(out, 2);
            else if (f->v2) mark_vec_operand(out, 2, f->s2);
            if (f->v3 == 2) mark_k_operand(out, 3);
            else if (f->v3) mark_vec_operand(out, 3, f->s3);
            /* БИТ b — здесь он не читался ВОВСЕ. При mod==3 он означает
             * управление округлением, и тогда L'L задаёт РЕЖИМ, а не длину:
             * операция всегда 512-битная (мы давали 16). При памяти означает
             * РАССЫЛКУ: читается ОДИН элемент шириной с дорожку и множится на
             * весь вектор (мы объявляли операнд во весь вектор, то есть
             * прочитали бы 64 байта вместо 4 — неверный доступ к памяти).
             * Ставится ПОСЛЕ разметки, иначе она затрёт. Списка опкодов не
             * нужно: рассылка в интерпретаторе общая (read_xmm_operand_bytes
             * берёт `broadcast ? lane : bytes` для любой команды). */
            if (evex_b) {
                if ((evex_modrm >> 6) == 3) {
                    out->evex_rounding = (uint8_t)(evex_ll + 1);
                    if (out->op1.is_reg) out->op1.size = 64;
                    if (out->op2.is_reg) out->op2.size = 64;
                    if (out->op3.is_reg) out->op3.size = 64;
                } else {
                    uint8_t lane = f->lane ? f->lane : 4;
                    out->evex_broadcast = true;
                    if (out->op1.is_mem) out->op1.size = lane;
                    if (out->op2.is_mem) out->op2.size = lane;
                    if (out->op3.is_mem) out->op3.size = lane;
                }
            }
            if (f->imm8 && f->s3 != 1) {   /* см. оговорку выше: не читать дважды */
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                out->has_imm8 = true;
                out->imm8 = read_u8(d);
            }
            return HB_OK;
        }

        /* BOUND r16/32, m16/32&16/32 — array bounds check. 0x62 is also the EVEX
         * prefix in 64-bit mode; in 32-bit mode (this decoder) it is BOUND only. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_BOUND;
        out->writes_flags = false;
        /* dst is the register; the memory operand is encoded as a 2-elem mBOUND
         * (low, high). The lift expects dst.size to be the index size and src1
         * to be a normal m16/32. parse_modrm_ext produces a single-element mem
         * operand; the interpreter reads 2 elements from that address. */
        return parse_modrm(d, modrm, operand16 ? 2 : 4, out, 1, 2, false);
    }
    if (opcode == 0x63) {
        /* ARPL r/m16, r16 — Adjust RPL Field of Segment Selector (in 32-bit mode;
         * MOVSXD in 64-bit mode, which this decoder does not handle). */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_ARPL;
        out->writes_flags = true;
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 911 — ПРИЁМНИК ЭТО r/m, А НЕ reg.
         * Форма `ARPL r/m16, r16`: приёмник в поле rm, источник в поле reg — как у соседей
         * `cmpxchg`/`xadd`, которые тут же передают последним параметром `true`. Разбирали
         * наоборот, и замер против эталона это показал:
         *   `63c1 arpl cx, ax` — эталон оставляет eax=0x70001000 и ZF=0 (RPL приёмника 2 не
         *   меньше RPL источника 0), мы писали в eax 0x70001002 и ставили ZF=1, то есть
         *   правили ИСТОЧНИК по условию, вывернутому наизнанку.
         * Сама логика в интерпретаторе верна — перепутано было, что считать приёмником.
         * 38 случаев корпуса на x86-32; на x64 опкод 0x63 это MOVSXD, там расхождения нет. */
        return parse_modrm(d, modrm, 2, out, 1, 2, true);
    }
    if (opcode == 0xC4 || opcode == 0xC5) {
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ПАРТИЯ 2 остатка лифтера x86-32 — VEX.
         *
         * В 32-битном режиме 0xC4 и 0xC5 — это LES и LDS, и отличить их от префикса VEX
         * можно ровно одним признаком: у VEX старшие два бита следующего байта равны
         * единицам (в LES/LDS это означало бы регистровый операнд, что для загрузки
         * дальнего указателя недопустимо — обработчики ниже такой случай и отвергают).
         *
         * Разбираем только то, ради чего партия и делается: группу BMI1/BMI2 в картах
         * 2 (0F38) и 3 (0F3A). Всё прочее под VEX отдаём как неподдержанное — откат на
         * интерпретатор это покрывает. В 32 битах REX отсутствует, vex_w обязан быть 0,
         * размер операнда всегда 4 байта. Эталон — `hb_decode_x64.c:1330`. */
        if (can_read(d, 1) && (d->code[d->pos] & 0xC0) == 0xC0) {
            uint8_t vex_map, vex_pp, vex_v, vex_opcode, modrm, ext;
            uint8_t vex_w = 0;   /* двухбайтовая форма C5 задаёт W=0 всегда */
            uint8_t vex_l;   /* итерация 886: бит L. 0 = 128 бит, 1 = 256 бит (ymm) */
            if (opcode == 0xC5) {
                uint8_t b1 = read_u8(d);
                vex_map = 1;
                vex_pp  = b1 & 3;
                vex_l   = (uint8_t)((b1 >> 2) & 1);
                vex_v   = (uint8_t)((~b1 >> 3) & 7);   /* vvvv инвертирован; в 32 битах значимы 3 бита */
            } else {
                uint8_t b1, b2;
                if (!can_read(d, 2)) return HB_ERR_DECODE_FAILED;
                b1 = read_u8(d);
                b2 = read_u8(d);
                vex_map = b1 & 0x1f;
                /* W НЕ отвергается: у VEX это ПРОДОЛЖЕНИЕ КОДА ОПЕРАЦИИ, а не
                 * REX.W. Прежний комментарий путал их и отрезал 820 форм —
                 * весь ряд FMA двойной точности, VPERMQ/VPERMPD, VPSLLVQ,
                 * сборы по квадрословам, PEXTRQ/PINSRQ. */
                vex_pp  = b2 & 3;
                vex_w   = (uint8_t)((b2 >> 7) & 1);
                vex_l   = (uint8_t)((b2 >> 2) & 1);
                vex_v   = (uint8_t)((~b2 >> 3) & 7);
            }
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            vex_opcode = read_u8(d);

            /* Итерация 886 — VZEROUPPER (`C5 F8 77`). Обрабатывать ОБЯЗАТЕЛЬНО до чтения
             * modrm: у этой формы байта modrm НЕТ, и чтение съело бы следующую команду,
             * исказив длину.
             * ★ L решает, КАКАЯ это команда: L=1 — VZEROALL (обнуляет регистры целиком),
             * L=0 — VZEROUPPER (только старшие половины). Прежде VZEROALL оставался
             * неподдержанным «чтобы не исполнить не ту команду»; теперь он есть, и
             * ветвь x64 (`hb_decode_x64.c`) разбирает его так же — один разбор на обе. */
            if (vex_map == 1 && vex_opcode == 0x77) {
                out->opcode = vex_l ? HB_INS_VZEROALL : HB_INS_VZEROUPPER;
                out->writes_flags = false;
                return HB_OK;
            }

            /* СБОРЫ — ДО чтения modrm: общий текст читает его сам (там SIB
             * с векторным индексом, а не обычный операнд). У ветви i386
             * этого не было ВОВСЕ, и интерпретатор отвечал -99 на всех
             * четырёх формах: он требует признаков VSIB, а декодер их не
             * заполнял. Замер: x64 давал vsib=1 elem=4 idx=4 cnt=8,
             * i386 — все нули. */
            if (vex_map == 2) {
                hb_result_t itog_g;
                if (hb_sbor_vex(d, vex_opcode, vex_w, vex_l,
                                (uint8_t)(vex_l ? 32 : 16), vex_v,
                                false, false, false, out, &itog_g))
                    return itog_g;
            }

            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            modrm = read_u8(d);
            ext = (uint8_t)((modrm >> 3) & 7);
            out->writes_flags = false;

            /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1064 — VEX КАРТА 1, ПЕРЕСЫЛКИ.
             *
             * Карта 1 на i386 отсутствовала целиком (кроме `VZEROUPPER`), и это был ВЕСЬ
             * остаток пробелов доски x86-32 — 9 форм из настоящего KeePass:
             * `vmovups ymm1,[eax]` (`c5fc1008`), `vmovaps [edx+ecx],ymm0`, `vmovntps`.
             * Опкод IR тот же, что у ветви x64 (`HB_INS_SSE_MOV`, `hb_decode_x64.c:1059`),
             * исполнитель у нас общий — значит хватает работы в декодере.
             *
             * Условия узкие и все проверяемые: `vvvv` обязан быть 1111 (иначе #UD у этих
             * форм — поэтому `vex_v == 0` после инверсии), `pp` 0 или 1 (упакованные
             * одинарной и двойной точности), у `2B` регистровая форма недопустима — это
             * ТОЛЬКО запись в память. Ширина: L=1 -> 32 байта, L=0 -> 16.
             * Скалярные формы (`pp` 2 и 3, `vmovss`/`vmovsd`) НЕ трогаю: у них третий
             * операнд через `vvvv`, это отдельная работа, и в замере их нет. */
            if (vex_map == 1 && vex_v == 0 && (vex_pp == 0 || vex_pp == 1) &&
                (vex_opcode == 0x10 || vex_opcode == 0x11 ||
                 vex_opcode == 0x28 || vex_opcode == 0x29 || vex_opcode == 0x2B)) {
                bool vex_store = (vex_opcode == 0x11 || vex_opcode == 0x29 || vex_opcode == 0x2B);
                uint8_t vex_vsz = vex_l ? 32 : 16;
                hb_result_t vr;

                if (vex_opcode == 0x2B && (modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
                out->opcode = HB_INS_SSE_MOV;
                out->evex_mask_lane = (vex_pp == 0) ? 4 : 8;
                vr = parse_modrm(d, modrm, vex_vsz, out, 1, 2, vex_store);
                if (vr != HB_OK) return vr;
                mark_vec_operands(out, vex_vsz);
                return HB_OK;
            }

            {
                const struct hb_vex_forma* f =
                    hb_najti_formu(0, vex_map, vex_pp, vex_l, vex_w, vex_opcode, ext,
                                   (unsigned)((modrm >> 6) == 3 ? 3 : 0));
                if (f) {
                    hb_result_t vr;
                    out->opcode = f->ins;
                    out->evex_mask_lane = f->lane;
                    if (hb_razlozhit_po_rolyam(d, f, modrm, vex_v, out, &vr)) {
                        if (vr != HB_OK) return vr;
                    } else if (f->s3 == 1) {
                        /* ★ ТРЕТИЙ ОПЕРАНД РАЗМЕРОМ 1 — ЭТО НЕПОСРЕДСТВЕННЫЙ
                         * БАЙТ, а не регистр vvvv (04.09.2026).
                         *
                         * Раньше любой ненулевой третий операнд считался
                         * регистром, и байт из потока НЕ ЧИТАЛСЯ. Длина
                         * выходила короче ровно на единицу, следующая команда
                         * начиналась не с того байта, и интерпретатор с
                         * выпуском отвечали -99 (внутренняя ошибка) — 48 мест
                         * по замеру: vpshufd, vpshufhw, vpshuflw. Доска же
                         * видела это как «расхождение длины HB=4, CS=5».
                         * Один корень, два разных симптома. */
                        vr = parse_modrm(d, modrm, f->s2, out, 1, 2, f->store != 0);
                        if (vr != HB_OK) return vr;
                        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                        set_imm(out, 3, read_u8(d), 1);
                    } else if (f->s3) {
                        vr = parse_modrm(d, modrm, f->s3, out, 1, 3, false);
                        if (vr != HB_OK) return vr;
                        set_reg(out, 2, vex_v, f->s2);
                    } else {
                        vr = parse_modrm(d, modrm, f->store ? f->s1 : f->s2,
                                         out, 1, 2, f->store != 0);
                        if (vr != HB_OK) return vr;
                    }
                    /* КЛАСС из формы, размер из формы — раздельно. */
                    if (f->v1 == 2) mark_k_operand(out, 1);
                    else if (f->v1) mark_vec_operand(out, 1, f->s1);
                    if (f->v2 == 2) mark_k_operand(out, 2);
                    else if (f->v2) mark_vec_operand(out, 2, f->s2);
                    if (f->v3 == 2) mark_k_operand(out, 3);
                    else if (f->v3) mark_vec_operand(out, 3, f->s3);
                    if (f->imm8 && f->s3 != 1) {
                        /* Четвёртый операнд: байт ПОСЛЕ трёх занятых слотов.
                         * Условие `s3 != 1` обязательно: когда третий слот САМ
                         * есть непосредственный байт, он уже прочитан выше, и
                         * без этой оговорки байт читался ДВАЖДЫ — длина
                         * выходила на единицу длиннее (vpermilps: 7 против 6).
                         * (vshufps, vroundps и родня). Без него длина короче
                         * на единицу, и следующая команда читается не с того
                         * байта. */
                        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                        out->has_imm8 = true;
                        out->imm8 = read_u8(d);
                    }
                    return HB_OK;
                }
            }

            if (vex_map == 2) {
                if (vex_pp == 0 && vex_opcode == 0xf2) {          /* ANDN r32a, r32b, r/m32 */
                    hb_result_t r;
                    out->opcode = HB_INS_ANDN;
                    out->writes_flags = true;
                    r = parse_modrm(d, modrm, 4, out, 1, 3, false);
                    if (r != HB_OK) return r;
                    set_reg(out, 2, vex_v, 4);
                    return HB_OK;
                }
                if (vex_pp == 0 && vex_opcode == 0xf3) {          /* BLSR / BLSMSK / BLSI */
                    hb_result_t r;
                    if (ext == 1) out->opcode = HB_INS_BLSR;
                    else if (ext == 2) out->opcode = HB_INS_BLSMSK;
                    else if (ext == 3) out->opcode = HB_INS_BLSI;
                    else return HB_ERR_UNSUPPORTED_OPCODE;
                    out->writes_flags = true;
                    r = parse_modrm_ext(d, modrm, 4, out, 2);
                    if (r != HB_OK) return r;
                    set_reg(out, 1, vex_v, 4);
                    return HB_OK;
                }
                if (vex_opcode == 0xf5 || vex_opcode == 0xf7 ||
                    (vex_pp == 3 && vex_opcode == 0xf6)) {
                    hb_result_t r;
                    int third_is_vv = 1;                          /* куда кладётся vvvv */
                    if (vex_pp == 0 && vex_opcode == 0xf5)      { out->opcode = HB_INS_BZHI;  out->writes_flags = true; }
                    else if (vex_pp == 0 && vex_opcode == 0xf7) { out->opcode = HB_INS_BEXTR; out->writes_flags = true; }
                    else if (vex_pp == 1 && vex_opcode == 0xf7)   out->opcode = HB_INS_SHLX;
                    else if (vex_pp == 2 && vex_opcode == 0xf7)   out->opcode = HB_INS_SARX;
                    else if (vex_pp == 3 && vex_opcode == 0xf7)   out->opcode = HB_INS_SHRX;
                    else if (vex_pp == 2 && vex_opcode == 0xf5) { out->opcode = HB_INS_PEXT; third_is_vv = 0; }
                    else if (vex_pp == 3 && vex_opcode == 0xf5) { out->opcode = HB_INS_PDEP; third_is_vv = 0; }
                    else if (vex_pp == 3 && vex_opcode == 0xf6) { out->opcode = HB_INS_MULX; third_is_vv = 0; }
                    else return HB_ERR_UNSUPPORTED_OPCODE;
                    if (!third_is_vv) {
                        r = parse_modrm(d, modrm, 4, out, 1, 3, false);
                        if (r != HB_OK) return r;
                        set_reg(out, 2, vex_v, 4);
                        return HB_OK;
                    }
                    r = parse_modrm(d, modrm, 4, out, 1, 2, false);
                    if (r != HB_OK) return r;
                    set_reg(out, 3, vex_v, 4);
                    return HB_OK;
                }
                return HB_ERR_UNSUPPORTED_OPCODE;
            }
            if (vex_map == 3 && vex_pp == 3 && vex_opcode == 0xf0) {   /* RORX r32, r/m32, imm8 */
                hb_result_t r = parse_modrm(d, modrm, 4, out, 1, 2, false);
                if (r != HB_OK) return r;
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                out->opcode = HB_INS_RORX;
                set_imm(out, 3, read_u8(d), 1);
                return HB_OK;
            }
            return HB_ERR_UNSUPPORTED_OPCODE;
        }
    }
    if (opcode == 0xC5) {
        /* LDS r16/32, m16:32 — Load Far Pointer. (In 64-bit mode, 0xC5 is the
         * VEX 2-byte prefix, so this is i386-only.) */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
                /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 926 — РАЗМЕР ПРИЁМНИКА У ЗАГРУЗКИ
         * ДАЛЬНЕГО УКАЗАТЕЛЯ. Форма `LxS r16/32, m16:32`: в РЕГИСТР идёт только смещение
         * (4 байта, под `66` — два), а шесть байт — это размер операнда в ПАМЯТИ. Мы ставили
         * шесть обоим. Проверено исполнением: `c40424 les eax,[esp]` кладёт в eax
         * 0x5ad35e00 — ровно то же, что контрольный `8b0424 mov eax,[esp]`, то есть смещение
         * читается верно и правится ОПИСАНИЕ. Эталон эти формы исполнять отказывается
         * (нужна настоящая таблица дескрипторов), поэтому сверка идёт по контрольной
         * пересылке. 20 строк столбца операндов. */
        out->opcode = HB_INS_LDS;
        out->writes_flags = false;
        /* op1 is the destination GPR, op2 is the m48 (offset:selector) memory. */
        hb_result_t rr = parse_modrm(d, modrm, 6, out, 1, 2, false);
        if (rr != HB_OK) return rr;
        out->op1.size = operand16 ? 2 : 4;   /* итерация 926: в регистр идёт только смещение */
        return HB_OK;
    }
    if (opcode == 0xC4) {
        /* LES r16/32, m16:32 — Load Far Pointer. (In 64-bit mode, 0xC4 is the
         * VEX 3-byte prefix, so this is i386-only.) */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
                /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 926 — РАЗМЕР ПРИЁМНИКА У ЗАГРУЗКИ
         * ДАЛЬНЕГО УКАЗАТЕЛЯ. Форма `LxS r16/32, m16:32`: в РЕГИСТР идёт только смещение
         * (4 байта, под `66` — два), а шесть байт — это размер операнда в ПАМЯТИ. Мы ставили
         * шесть обоим. Проверено исполнением: `c40424 les eax,[esp]` кладёт в eax
         * 0x5ad35e00 — ровно то же, что контрольный `8b0424 mov eax,[esp]`, то есть смещение
         * читается верно и правится ОПИСАНИЕ. Эталон эти формы исполнять отказывается
         * (нужна настоящая таблица дескрипторов), поэтому сверка идёт по контрольной
         * пересылке. 20 строк столбца операндов. */
        out->opcode = HB_INS_LES;
        out->writes_flags = false;
        hb_result_t rr = parse_modrm(d, modrm, 6, out, 1, 2, false);
        if (rr != HB_OK) return rr;
        out->op1.size = operand16 ? 2 : 4;   /* итерация 926: в регистр идёт только смещение */
        return HB_OK;
    }
    if (opcode == 0x86 || opcode == 0x87) {
        /* XCHG r/m8,r8 and r/m16/32,r16/32.  LOCK is consumed by the
           prefix scanner; reject prefixes this decoder cannot model. */
        if (prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        /* ЛЕСА СНЯТЫ 04.09.2026. Здесь стояло местное вето «под 0x67 берём
         * только регистровую форму». Оно было верным, пока parse_modrm не
         * умел 16-битную адресацию; итерация 283 научила его (внутри стоит
         * `if (d->addr16_active) -> parse_modrm16`), а местных сторожей никто
         * не снял. Из-за них `67 86 01` и `67 8c 01` отказывали, тогда как
         * `67 00/88/8d/84` с той же памятью разбирались — замер показал
         * ровно эту пару. Лечение общее, значит сторож лишний. */
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_XCHG;
        out->writes_flags = false;
        return parse_modrm(d, modrm, opcode == 0x86 ? 1 : (operand16 ? 2 : 4),
                           out, 1, 2, true);
    }
    if (opcode == 0x8C || opcode == 0x8E) {
        /* MOV r/m16,Sreg and MOV Sreg,r/m16.  Segment selector operands stay
           16-bit even with an operand-size prefix. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        /* ЛЕСА СНЯТЫ 04.09.2026. Здесь стояло местное вето «под 0x67 берём
         * только регистровую форму». Оно было верным, пока parse_modrm не
         * умел 16-битную адресацию; итерация 283 научила его (внутри стоит
         * `if (d->addr16_active) -> parse_modrm16`), а местных сторожей никто
         * не снял. Из-за них `67 86 01` и `67 8c 01` отказывали, тогда как
         * `67 00/88/8d/84` с той же памятью разбирались — замер показал
         * ровно эту пару. Лечение общее, значит сторож лишний. */
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        uint8_t seg = (modrm >> 3) & 7;
        hb_result_t r;
        if (seg > 5) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_MOV_SEG;
        out->writes_flags = false;
        if (opcode == 0x8C) {
            r = parse_modrm_ext(d, modrm, 2, out, 1);
            /* Итерация 933: при РЕГИСТРОВОМ приёмнике селектор расширяется нулём на всю
             * ширину (см. разбор в hb_decode_x64.c); ширина 2 — только у памяти. */
            if (r == HB_OK && !out->op1.is_mem) out->op1.size = operand16 ? 2 : 4;
            if (r != HB_OK) return r;
            set_imm(out, 2, seg, 2);
        } else {
            set_imm(out, 1, seg, 2);
            r = parse_modrm_ext(d, modrm, 2, out, 2);
            if (r != HB_OK) return r;
        }
        return HB_OK;
    }
    if (opcode >= 0x91 && opcode <= 0x97) {
        /* XCHG EAX/AX, r32/r16.  0x90 is the EAX,EAX NOP alias above. */
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_XCHG;
        out->writes_flags = false;
        set_reg(out, 1, HB_REG_RAX, operand16 ? 2 : 4);
        set_reg(out, 2, opcode & 7, operand16 ? 2 : 4);
        return HB_OK;
    }
    if (opcode == 0x9C || opcode == 0x9D) {
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = opcode == 0x9C ? HB_INS_PUSHF : HB_INS_POPF;
        out->writes_flags = opcode == 0x9D;
        out->stack_delta = operand16 ? 2 : 4;
        set_imm(out, 1, 0, operand16 ? 2 : 4);
        return HB_OK;
    }
    if (opcode == 0x9F) {
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_LAHF;
        out->reads_flags = true;
        return HB_OK;
    }
    if (opcode == 0x9E) {
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_SAHF;
        out->writes_flags = true;
        return HB_OK;
    }
    if (opcode == 0xA4 || opcode == 0xA5) {
        /* MOVS m8/m16/m32. REP is carried as an immediate mode. */
        if (prefix_f0) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_MOVS;
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 911 — АРХИТЕКТУРНОЕ ОПИСАНИЕ
         * СТРОКОВЫХ ФОРМ, перенос работы 493-501 и 896 с ветви x64 (там это уже сделано).
         * Здесь операнд объявлялся РЕГИСТРОМ (указателем), а префикс повтора занимал второй
         * слот, хотя с 490 он живёт в отдельном поле `rep_prefix` и слот свободен. Эталон
         * описывает эти команды ПАМЯТЬЮ по [esi]/[edi] — отсюда 100 расхождений операндов на
         * этой ветви (77 «тип op0: у нас регистр, у эталона память» + 23 у lods/scas).
         * ★ Поведение проверено ДО правки и оно ВЕРНО: movsb/movsd/lodsb/lodsd/stosb/stosd/
         * cmpsb/scasb, формы с rep/repe и 16-битная movsw — все СОШЛИСЬ с эталоном на обеих
         * ветвях. То есть правится ОПИСАНИЕ, а не счёт.
         * Безопасность потребителя: интерпретатор берёт размер из `src1.size`, адреса — из
         * контекста, префикс — из `rep_prefix` (чтение из второго операнда там помечено
         * запасным «пока описание не переведено»). Порядок операндов — из МАССИВА эталона. */
        {
            uint8_t sz = (opcode == 0xA4) ? 1 : (operand16 ? 2 : 4);
            set_mem(out, 1, HB_REG_RDI, -1, 1, 0, sz);
            set_mem(out, 2, HB_REG_RSI, -1, 1, 0, sz);
        }
        /* Итерация 490: тот же префикс — в отдельное поле. Пока никто не читает,
         * поведение не меняется; переключение потребителей следующим шагом. */
        out->rep_prefix = prefix_f2 ? 0xf2 : prefix_f3 ? 0xf3 : 0;
        out->writes_flags = false;
        return HB_OK;
    }
    if (opcode == 0xA6 || opcode == 0xA7) {
        /* CMPS m8/m16/m32. REPNE/REPE are carried as an immediate mode. */
        if (prefix_f0) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_CMPS;
        /* Итерация 911: см. MOVS выше. Порядок эталона: mem[esi], mem[edi]. */
        {
            uint8_t sz = (opcode == 0xA6) ? 1 : (operand16 ? 2 : 4);
            set_mem(out, 1, HB_REG_RSI, -1, 1, 0, sz);
            set_mem(out, 2, HB_REG_RDI, -1, 1, 0, sz);
        }
        /* Итерация 490: тот же префикс — в отдельное поле. Пока никто не читает,
         * поведение не меняется; переключение потребителей следующим шагом. */
        out->rep_prefix = prefix_f2 ? 0xf2 : prefix_f3 ? 0xf3 : 0;
        out->reads_flags = true;
        out->writes_flags = true;
        return HB_OK;
    }
    if (opcode == 0xAC || opcode == 0xAD) {
        /* LODS m8/m16/m32. REP is carried as an immediate mode. */
        if (prefix_f0) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_LODS;
        /* Итерация 911: см. MOVS выше. Порядок эталона: reg(al), mem[esi]. */
        {
            uint8_t sz = (opcode == 0xAC) ? 1 : (operand16 ? 2 : 4);
            set_reg(out, 1, HB_REG_RAX, sz);
            set_mem(out, 2, HB_REG_RSI, -1, 1, 0, sz);
        }
        /* Итерация 490: тот же префикс — в отдельное поле. Пока никто не читает,
         * поведение не меняется; переключение потребителей следующим шагом. */
        out->rep_prefix = prefix_f2 ? 0xf2 : prefix_f3 ? 0xf3 : 0;
        out->writes_flags = false;
        return HB_OK;
    }
    if (opcode == 0xAE || opcode == 0xAF) {
        /* SCAS m8/m16/m32. REPNE/REPE are carried as an immediate mode. */
        if (prefix_f0) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_SCAS;
        /* Итерация 911: см. MOVS выше. Порядок эталона: reg(al), mem[edi]. */
        {
            uint8_t sz = (opcode == 0xAE) ? 1 : (operand16 ? 2 : 4);
            set_reg(out, 1, HB_REG_RAX, sz);
            set_mem(out, 2, HB_REG_RDI, -1, 1, 0, sz);
        }
        /* Итерация 490: тот же префикс — в отдельное поле. Пока никто не читает,
         * поведение не меняется; переключение потребителей следующим шагом. */
        out->rep_prefix = prefix_f2 ? 0xf2 : prefix_f3 ? 0xf3 : 0;
        out->reads_flags = true;
        out->writes_flags = true;
        return HB_OK;
    }
    if (opcode == 0xAA || opcode == 0xAB) {
        /* STOS m8/m16/m32. REP is carried as an immediate mode. */
        if (prefix_f0) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_STOS;
        /* Итерация 911: см. MOVS выше. Порядок эталона ОБРАТНЫЙ: mem[edi], reg(al). */
        {
            uint8_t sz = (opcode == 0xAA) ? 1 : (operand16 ? 2 : 4);
            set_mem(out, 1, HB_REG_RDI, -1, 1, 0, sz);
            set_reg(out, 2, HB_REG_RAX, sz);
        }
        /* Итерация 490: тот же префикс — в отдельное поле. Пока никто не читает,
         * поведение не меняется; переключение потребителей следующим шагом. */
        out->rep_prefix = prefix_f2 ? 0xf2 : prefix_f3 ? 0xf3 : 0;
        out->writes_flags = false;
        return HB_OK;
    }

    if (opcode == 0x0F) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t op2 = read_u8(d);
        if (((op2 == 0x2B) && !prefix_f2 && !prefix_f3) ||
            ((op2 == 0xE7) && operand16 && !prefix_f2 && !prefix_f3)) {
            /* MOVNTPS/MOVNTPD/MOVNTDQ: decode as the same 128-bit store IR as
             * regular packed SSE moves.  The non-temporal cache hint does not
             * change guest-visible state; register ModRM forms are invalid. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
            out->opcode = HB_INS_SSE_MOV;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, true);
            if (r != HB_OK) return r;
            mark_xmm_operands(out);
            return HB_OK;
        }
        /* Итерация 1081: `0F 0B` (UD2), `0F B9` (UD1), `0F FF` (UD0). Ветвь x64 их
         * разбирает (`hb_decode_x64.c:3629`), i386 не разбирал ВОВСЕ — расходились ветви. */
        if (op2 == 0x0B || op2 == 0xB9 || op2 == 0xFF) {
            out->opcode = HB_INS_UD;
            out->writes_flags = false;
            return HB_OK;
        }
        if (op2 == 0x1F) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_NOP;
            return parse_modrm_ext(d, modrm, 1, out, 1);
        }
        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — ВЕСЬ РЯД 0F 18..0F 1F.
         *
         * Разбирались только `0F 0D`, `0F 18` и `0F 1F`, а `0F 19`..`0F 1E` — нет,
         * хотя это официально «зарезервированные NOP» той же группы: Intel прямо
         * велит трактовать их как многобайтовый NOP.
         *
         * Сюда же попадают MPX (`0F 1A`/`0F 1B` под 66/F2/F3 — BNDMOV/BNDCL/BNDCU/
         * BNDCN) и CET (`F3 0F 1E` — ENDBR32). Это НЕ заглушка: на процессоре без
         * этих расширений они по спецификации исполняются именно как NOP, а MPX
         * из архитектуры вовсе изъят. Гость проверяет их наличие через CPUID и,
         * не увидев, не полагается на их действие. Длина при этом обязана быть
         * верной — её и даёт разбор модрм. */
        if (op2 == 0x0D || (op2 >= 0x18 && op2 <= 0x1F)) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_NOP;
            return parse_modrm_ext(d, modrm, 1, out, 1);
        }
        /* MacRunner 2026-08-28 — EXTRQ/INSERTQ (SSE4a, только AMD).
         *
         *   66 0F 78 /r ib ib  EXTRQ xmm, imm8, imm8      66 0F 79 /r  EXTRQ xmm, xmm
         *   F2 0F 78 /r ib ib  INSERTQ xmm, xmm, imm8, imm8   F2 0F 79 /r  INSERTQ xmm, xmm
         *
         * Разбираем честно (длина верна, форма с двумя непосредственными длиннее на
         * два байта), исполнение даёт внятный отказ. Реализовывать нет смысла: это
         * расширение только AMD, наличие которого гость узнаёт из CPUID, а мы его
         * не объявляем — значит настоящая программа его и не позовёт. Разбор нужен
         * ради длины: без него поток команд рассыпается на первой же такой. */
        if ((operand16 || prefix_f2) && (op2 == 0x78 || op2 == 0x79)) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_UNAVAILABLE_EXT;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (op2 == 0x78) {
                if (!can_read(d, 2)) return HB_ERR_DECODE_FAILED;
                (void)read_u8(d);
                (void)read_u8(d);
            }
            return HB_OK;
        }
        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — ПРИВИЛЕГИРОВАННЫЕ И СИСТЕМНЫЕ.
         *
         *   0F 02 LAR    0F 03 LSL     чтение прав и предела сегмента
         *   0F 05 SYSCALL 0F 07 SYSRET  0F 34 SYSENTER 0F 35 SYSEXIT
         *   0F 33 RDPMC   0F 37 GETSEC
         *   0F A6 MONTMUL 0F A7 XSTORE  (расширения VIA)
         *   0F 78 VMREAD  0F 79 VMWRITE (без префиксов — иначе это SSE4a)
         *
         * Разбираем ЧЕСТНО: длина верна, команда названа. Исполнение при этом даёт
         * внятный отказ через `HB_IR_UNSUPPORTED` с причиной — а не тихо «успех»,
         * как было с дальними переходами до 922.
         *
         * Почему не реализуем: все они переводят процессор в другое кольцо или
         * читают состояние, которого у нас нет (дескрипторные таблицы, счётчики
         * производительности, состояние гипервизора). Гость под Windows их и не
         * зовёт: системные вызовы идут через наш шлюз, а не через SYSENTER. Если
         * настоящая программа позовёт — отказ будет виден сразу и с именем, и
         * тогда реализуем по замеру. */
        /* ★ 28.08: 66/F2/F3 здесь НЕЗНАЧИМЫ (кроме 0F 78/79 — там они выбирают
         * SSE4a, и та ветка стоит выше). Требование их отсутствия отсекало LAR/LSL
         * под 66 и F2/F3 — по три случая на команду в сплошном переборе. */
        if ((op2 == 0x02 || op2 == 0x03 || op2 == 0xA6 || op2 == 0xA7) ||
            (!operand16 && !prefix_f2 && (op2 == 0x78 || op2 == 0x79))) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_SYS_PRIV;
            out->writes_flags = (op2 == 0x02 || op2 == 0x03);
            return parse_modrm(d, modrm, 4, out, 1, 2, false);
        }
        if (op2 == 0x05 || op2 == 0x07 || op2 == 0x33 ||
            op2 == 0x34 || op2 == 0x35 || op2 == 0x37) {
            /* ★ Вид отказа различаем по железу, а не валим всё в одну кучу:
             *   0F 05 SYSCALL и 0F 07 SYSRET в 32-битном режиме НЕ СУЩЕСТВУЮТ
             *     (это команды длинного режима) — процессор даёт #UD;
             *   0F 33 RDPMC, 0F 34 SYSENTER, 0F 35 SYSEXIT, 0F 37 GETSEC
             *     существуют, но нам нечем их исполнить — привилегированный отказ.
             * Разница видна гостю: `c000001d` против `0xC0000096`, и обработчики
             * у него для них разные. */
            out->opcode = (op2 == 0x05 || op2 == 0x07) ? HB_INS_UNAVAILABLE_EXT
                                                       : HB_INS_SYS_PRIV;
            out->writes_flags = false;
            return HB_OK;
        }
        if (op2 == 0x0E) {
            /* FEMMS (3DNow!): то же, что EMMS — сброс состояния файла MMX.
             * У AMD он «быстрый», но наблюдаемое действие ровно то же. */
            out->opcode = HB_INS_X87_EMMS;
            out->writes_flags = false;
            return HB_OK;
        }
        if (op2 == 0xAE) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t ext = (modrm >> 3) & 7;
            /* PTWRITE r/m32 — F3 0F AE /4. Отдельная ветвь ниже по файлу была
             * НЕДОСТИЖИМА: сюда 0F AE приходит раньше. Тот же урок, что с
             * местными вето: место в потоке важнее правильности условия. */
            if (prefix_f3 && ext == 4) {
                out->opcode = HB_INS_PTWRITE;
                out->writes_flags = false;
                return parse_modrm_ext(d, modrm, operand16 ? 2 : 4, out, 1);
            }
            if (mod == 3) {
                if ((modrm & 7) == 0 && (ext == 5 || ext == 6 || ext == 7)) {
                    out->opcode = HB_INS_FENCE;
                    set_imm(out, 1, ext == 5 ? HB_FENCE_ACQUIRE :
                                    ext == 6 ? HB_FENCE_FULL : HB_FENCE_RELEASE, 1);
                    return HB_OK;
                }
                return HB_ERR_UNSUPPORTED_OPCODE;
            }
            if (ext == 0) {
                out->opcode = HB_INS_X87_FXSAVE;
                return parse_modrm_ext(d, modrm, HB_SIZE_512, out, 1);
            }
            if (ext == 1) {
                out->opcode = HB_INS_X87_FXRSTOR;
                return parse_modrm_ext(d, modrm, HB_SIZE_512, out, 1);
            }
            if (ext == 2) {
                out->opcode = HB_INS_LDMXCSR;   /* итерация 1075: больше не пустышка */
                return parse_modrm_ext(d, modrm, 4, out, 1);
            }
            /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1075 — НАСТОЯЩИЙ MXCSR.
             * Было: `/2` пустышка, `/3` запись ПОСТОЯННОЙ 0x1f80. Теперь пара работает
             * с полем состояния — значит `STMXCSR` после `LDMXCSR` отдаёт записанное. */
            if (ext == 3) {
                out->opcode = HB_INS_STMXCSR;
                return parse_modrm_ext(d, modrm, 4, out, 1);
            }
            if (ext == 7) {
                out->opcode = HB_INS_NOP;
                return parse_modrm_ext(d, modrm, 1, out, 1);
            }
            return HB_ERR_UNSUPPORTED_OPCODE;
        }
        d->pos--;
    }

    if (prefix_f0) {
        if (opcode <= 0x3B && ((opcode & 7) <= 1)) {
            int ins;
            switch (opcode & 0x38) {
                case 0x00: ins = HB_INS_ADD; break;
                case 0x08: ins = HB_INS_OR;  break;
                case 0x10: ins = HB_INS_ADC; break;
                case 0x18: ins = HB_INS_SBB; break;
                case 0x20: ins = HB_INS_AND; break;
                case 0x28: ins = HB_INS_SUB; break;
                case 0x30: ins = HB_INS_XOR; break;
                default: return HB_ERR_UNSUPPORTED_OPCODE;
            }
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
            out->opcode = ins;
            out->writes_flags = true;
            return parse_modrm(d, modrm, (opcode & 1) ? (operand16 ? 2 : 4) : 1,
                               out, 1, 2, true);
        }
        if (opcode == 0x80 || opcode == 0x81 || opcode == 0x82 || opcode == 0x83) {
            /* MacRunner 2026-08-28 — 0x82 это устаревший псевдоним 0x80.
             * В 32-битном режиме он ЗАКОНЕН и ведёт себя ровно как 0x80 (операнд
             * байтовый, непосредственное — байт); недопустим он только в 64-битном.
             * Сплошной перебор против capstone показал его как дыру сразу для
             * восьми мнемоник — add/or/adc/sbb/and/sub/xor/cmp разом, потому что
             * вид задаёт поле reg модрм. Старые сборки (эпоха Diablo) его
             * выпускали. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t ext = (modrm >> 3) & 7;
            if ((modrm >> 6) == 3 || ext == 7) return HB_ERR_UNSUPPORTED_OPCODE;
            if (ext == 0) out->opcode = HB_INS_ADD;
            else if (ext == 1) out->opcode = HB_INS_OR;
            else if (ext == 2) out->opcode = HB_INS_ADC;
            else if (ext == 3) out->opcode = HB_INS_SBB;
            else if (ext == 4) out->opcode = HB_INS_AND;
            else if (ext == 5) out->opcode = HB_INS_SUB;
            else out->opcode = HB_INS_XOR;
            out->writes_flags = true;
            uint8_t sz = (opcode == 0x80 || opcode == 0x82) ? 1 : (operand16 ? 2 : 4);
            hb_result_t r = parse_modrm_ext(d, modrm, sz, out, 1);
            if (r != HB_OK) return r;
            if (opcode == 0x80 || opcode == 0x82) {
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                set_imm(out, 2, read_s8(d), 1);
            } else if (opcode == 0x81) {
                if (!can_read(d, sz)) return HB_ERR_DECODE_FAILED;
                set_imm(out, 2, sz == 2 ? (int64_t)read_s16(d) : (int64_t)read_s32(d), sz);
            } else {
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                set_imm(out, 2, (int64_t)read_s8(d), sz);
            }
            return HB_OK;
        }
        if (opcode == 0xF6 || opcode == 0xF7) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t ext = (modrm >> 3) & 7;
            if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
            if (ext == 2) out->opcode = HB_INS_NOT;
            else if (ext == 3) out->opcode = HB_INS_NEG;
            else return HB_ERR_UNSUPPORTED_OPCODE;
            out->writes_flags = (ext == 3);
            return parse_modrm_ext(d, modrm, opcode == 0xF6 ? 1 : (operand16 ? 2 : 4), out, 1);
        }
        if (opcode == 0xFE) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t ext = (modrm >> 3) & 7;
            if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
            if (ext == 0) out->opcode = HB_INS_INC;
            else if (ext == 1) out->opcode = HB_INS_DEC;
            else return HB_ERR_UNSUPPORTED_OPCODE;
            out->writes_flags = true;
            return parse_modrm_ext(d, modrm, 1, out, 1);
        }
        /* Итерация 284: сюда доходят двухбайтовые команды, для которых F2/F3 НЕ часть
         * кодировки — все прочие (MOVSS, MOVSD, POPCNT, CVT-семейство, MOVQ) разобраны выше и сюда не
         * попадают. Настоящий процессор такой префикс здесь игнорирует, поэтому и мы должны:
         * иначе 118 случаев корпуса (movzx, movsx, bswap, shld, shrd, bt-семья) отвергались. */
        if (opcode == 0x0F) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t op2 = read_u8(d);
            if (op2 == 0xB0 || op2 == 0xB1 || op2 == 0xC0 || op2 == 0xC1) {
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                uint8_t modrm = read_u8(d);
                if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
                out->opcode = (op2 == 0xB0 || op2 == 0xB1) ? HB_INS_CMPXCHG : HB_INS_XADD;
                out->writes_flags = true;
                /* Итерация 908: 16-битная форма (префикс 66) — см. CMOVcc ниже. */
                return parse_modrm(d, modrm,
                                   (op2 == 0xB0 || op2 == 0xC0) ? 1 : (operand16 ? 2 : 4),
                                   out, 1, 2, true);
            }
            if (op2 == 0xC7) {
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                uint8_t modrm = read_u8(d);
                if (((modrm >> 3) & 7) != 1 || (modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
                out->opcode = HB_INS_CMPXCHG8B;
                out->writes_flags = true;
                return parse_modrm_ext(d, modrm, 8, out, 1);
            }
            /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 286 — LOCK ДЛЯ BTS/BTR/BTC.
             * Список разрешённых для `LOCK` двухбайтовых команд содержал только `CMPXCHG`,
             * `XADD` и `CMPXCHG8B`. По спецификации x86 `LOCK` допустим также с `BTS`, `BTR`,
             * `BTC` — и в форме `0F AB/B3/BB`, и в форме `0F BA /5,/6,/7` с непосредственным
             * смещением. `BT` (`0F A3`, `0F BA /4`) не допускает: он ничего не пишет.
             * Приёмник обязан быть в памяти — регистровая форма ловит #UD, её отвергаем. */
            if (op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB) {
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                uint8_t modrm = read_u8(d);
                if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
                out->opcode = (op2 == 0xAB) ? HB_INS_BTS : (op2 == 0xB3) ? HB_INS_BTR : HB_INS_BTC;
                out->writes_flags = true;
                return parse_modrm(d, modrm, operand16 ? 2 : 4, out, 1, 2, true);
            }
            if (op2 == 0xBA) {
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                uint8_t modrm = read_u8(d);
                uint8_t ext = (modrm >> 3) & 7;
                if ((modrm >> 6) == 3 || ext < 5) return HB_ERR_UNSUPPORTED_OPCODE;
                out->opcode = (ext == 5) ? HB_INS_BTS : (ext == 6) ? HB_INS_BTR : HB_INS_BTC;
                out->writes_flags = true;
                hb_result_t rb = parse_modrm_ext(d, modrm, operand16 ? 2 : 4, out, 1);
                if (rb != HB_OK) return rb;
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                set_imm(out, 2, read_u8(d), 1);
                return HB_OK;
            }
            return HB_ERR_UNSUPPORTED_OPCODE;
        }
        if (opcode == 0xFF) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t ext = (modrm >> 3) & 7;
            if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
            if (ext == 0) {
                out->opcode = HB_INS_INC;
                out->writes_flags = true;
                return parse_modrm_ext(d, modrm, operand16 ? 2 : 4, out, 1);
            }
            if (ext == 1) {
                out->opcode = HB_INS_DEC;
                out->writes_flags = true;
                return parse_modrm_ext(d, modrm, operand16 ? 2 : 4, out, 1);
            }
            return HB_ERR_UNSUPPORTED_OPCODE;
        }
        return HB_ERR_UNSUPPORTED_OPCODE;
    }

    if (opcode == 0x0F && (prefix_f2 || prefix_f3)) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t op2 = read_u8(d);
        if (prefix_f3 && op2 == 0xB8) {
            /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: партия 2 — POPCNT r16/32, r/m16/32
             * (`F3 0F B8 /r`). Не VEX; лежит рядом с TZCNT/LZCNT, разбор тот же. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_POPCNT;
            out->writes_flags = true;
            return parse_modrm(d, modrm, operand16 ? 2 : 4, out, 1, 2, false);
        }
        if (prefix_f3 && (op2 == 0xBC || op2 == 0xBD)) {
            /* TZCNT/LZCNT r16/32, r/m16/32. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = (op2 == 0xBC) ? HB_INS_TZCNT : HB_INS_LZCNT;
            out->writes_flags = true;
            hb_result_t r = parse_modrm(d, modrm, operand16 ? 2 : 4, out, 1, 2, false);
            if (r != HB_OK) return r;
            return HB_OK;
        }
        if (op2 == 0x70) {
            /* PSHUFLW/PSHUFHW xmm, xmm/m128, imm8. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = prefix_f2 ? HB_INS_PSHUFLW : HB_INS_PSHUFHW;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 3, read_u8(d), 1);
            return HB_OK;
        }
        if (op2 == 0xC6 && !prefix_f2 && !prefix_f3) {
            /* SHUFPS/SHUFPD xmm, xmm/m128, imm8. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = operand16 ? HB_INS_SHUFPD : HB_INS_SHUFPS;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 3, read_u8(d), 1);
            return HB_OK;
        }
        if (prefix_f3 && op2 == 0x7E) {
            /* MOVQ xmm, xmm/m64. Ported from the x64 SSE transfer family. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_MOVD;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 8, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = 8;
            return HB_OK;
        }
        if (prefix_f2 && op2 == 0xE6) {
            /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: партия 3 — CVTPD2DQ xmm, xmm/m128
             * (`F2 0F E6`). Соседний `F3 0F E6` (CVTDQ2PD) уже разбирался, а этот нет. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_CVTPD2DQ;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if (prefix_f3 && op2 == 0xE6) {
            /* CVTDQ2PD xmm, xmm/m64. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_CVTDQ2PD;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 8, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = 8;
            return HB_OK;
        }
        if (prefix_f3 && op2 == 0x5B) {
            /* CVTTPS2DQ xmm, xmm/m128. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_CVTTPS2DQ;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if ((prefix_f2 || prefix_f3) && op2 == 0x2A) {
            /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: CVTSI2SS/CVTSI2SD xmm, r/m32.
             * Ровно на этой команде умирал Diablo: наша i386 crtdll.dll собрана
             * современным clang и пользуется SSE2, а декодер x86-32 семью скалярных
             * преобразований не знал (в декодере x64 она есть — оттуда и порядок операндов).
             * Приёмник — XMM, источник ЦЕЛЫЙ (регистр или память 4 байта), как у 0F 6E MOVD. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = prefix_f3 ? HB_INS_CVTSI2SS : HB_INS_CVTSI2SD;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 4, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            out->op2.size = 4;
            return HB_OK;
        }
        if ((prefix_f2 || prefix_f3) && (op2 == 0x2C || op2 == 0x2D)) {
            /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: обратная сторона той же семьи —
             * CVTTSS2SI/CVTTSD2SI (0x2C, усечение) и CVTSS2SI/CVTSD2SI (0x2D, округление).
             * Приёмник ЦЕЛЫЙ регистр 4 байта, источник XMM/память (4 при F3, 8 при F2). */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t mem_size = prefix_f3 ? 4 : 8;
            if (op2 == 0x2C) out->opcode = prefix_f3 ? HB_INS_CVTTSS2SI : HB_INS_CVTTSD2SI;
            else             out->opcode = prefix_f3 ? HB_INS_CVTSS2SI  : HB_INS_CVTSD2SI;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, mem_size, out, 1, 2, false);
            if (r != HB_OK) return r;
            out->op1.size = 4;
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = mem_size;
            return HB_OK;
        }
        if (op2 == 0x5A) {
            /* F3/F2 scalar converts: CVTSS2SD and CVTSD2SS. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t mem_size = prefix_f3 ? 4 : 8;
            out->opcode = prefix_f3 ? HB_INS_CVTSS2SD : HB_INS_CVTSD2SS;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, mem_size, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = mem_size;
            return HB_OK;
        }
        if (op2 == 0x58 || op2 == 0x5C) {
            /* Scalar ADD/SUB: ADDSS/SUBSS and ADDSD/SUBSD. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t mem_size = prefix_f3 ? 4 : 8;
            if (prefix_f3) out->opcode = (op2 == 0x58) ? HB_INS_ADDSS : HB_INS_SUBSS;
            else out->opcode = (op2 == 0x58) ? HB_INS_ADDSD : HB_INS_SUBSD;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, mem_size, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = mem_size;
            return HB_OK;
        }
        if (prefix_f2 && op2 == 0x5E) {
            /* DIVSD xmm, xmm/m64. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_DIVSD;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 8, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = 8;
            return HB_OK;
        }
        if (prefix_f2 && op2 == 0x59) {
            /* MULSD xmm, xmm/m64. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_MULSD;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 8, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = 8;
            return HB_OK;
        }
        if (prefix_f3 && (op2 == 0x5E || op2 == 0x59)) {
            /* DIVSS/MULSS xmm, xmm/m32. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = (op2 == 0x5E) ? HB_INS_DIVSS : HB_INS_MULSS;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 4, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = 4;
            return HB_OK;
        }
        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — семейство сравнений SSE (0F C2).
         *
         * Отказ Diablo `c000001d` по адресу 78A0D6F7 внутри DDrawCompat пришёл НЕ от
         * `MOVSD`, на который указывал eip (тот разбирается ниже, `op2 == 0x10`), а от
         * `f2 0f c2 f1 00` дальше по блоку — сравнения с непосредственным видом. Все
         * прежние вхождения `0xC2` в этом файле относятся к обычному `RET`; семейства
         * сравнений не было вовсе, и движок честно отвечал "не поддерживаю", что
         * `status_from_hb` превращает в STATUS_ILLEGAL_INSTRUCTION.
         *
         * Вид сравнения задаёт imm8 (0=EQ 1=LT 2=LE 3=UNORD 4=NEQ 5=NLT 6=NLE 7=ORD),
         * ответ — маска из сплошных единиц или нулей во всю дорожку. Разбор буква в
         * букву по соседям `0F 5D` (MIN/MAX, прямо ниже) и `0F C6` (SHUFPS): тот же
         * порядок parse_modrm -> mark_xmm_operand -> set_imm. */
        if (op2 == 0xC2) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t mem_size = prefix_f3 ? 4 : 8;
            out->opcode = prefix_f3 ? HB_INS_CMPSS : HB_INS_CMPSD;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, mem_size, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = mem_size;
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 3, read_u8(d), 1);
            return HB_OK;
        }
        if (op2 == 0x5D || op2 == 0x5F) {
            /* Scalar MIN/MAX: MINSS/MAXSS and MINSD/MAXSD. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t mem_size = prefix_f3 ? 4 : 8;
            if (prefix_f3) out->opcode = (op2 == 0x5D) ? HB_INS_MINSS : HB_INS_MAXSS;
            else out->opcode = (op2 == 0x5D) ? HB_INS_MINSD : HB_INS_MAXSD;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, mem_size, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = mem_size;
            return HB_OK;
        }
        if (op2 == 0x10 || op2 == 0x11 || op2 == 0x28 || op2 == 0x29 ||
            op2 == 0x6F || op2 == 0x7F) {
            /* MOVUPS/MOVAPS/MOVDQA/MOVDQU and scalar MOVSS/MOVSD variants. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            bool scalar_move = (op2 == 0x10 || op2 == 0x11);
            uint8_t move_size = scalar_move ? (prefix_f3 ? 4 : 8) : 16;
            out->opcode = HB_INS_SSE_MOV;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, move_size, out, 1, 2,
                                        (op2 == 0x11 || op2 == 0x29 || op2 == 0x7F));
            if (r != HB_OK) return r;
            mark_xmm_operands(out);
            if (scalar_move) {
                if (out->op1.is_reg) out->op1.size = move_size;
                if (out->op2.is_reg) out->op2.size = move_size;
                if (out->op1.is_mem) out->op1.size = move_size;
                if (out->op2.is_mem) out->op2.size = move_size;
            }
            /* ПРЕФИКС F2/F3 ТАМ, ГДЕ ФОРМЫ С НИМ НЕ СУЩЕСТВУЕТ — тот же текст,
             * что и на x64 (hb_decode_x64.c, тот же блок): у `0F 10/11` законны
             * все четыре сочетания, у `0F 28/29` — только NP и 66, у `0F 6F/7F`
             * F3 законен (MOVDQU), а F2 нет. Замерено оракулом Bochs. */
            if (((op2 == 0x28 || op2 == 0x29) && (prefix_f2 || prefix_f3)) ||
                ((op2 == 0x6F || op2 == 0x7F) && prefix_f2)) {
                out->opcode = HB_INS_UNAVAILABLE_EXT;
            }
            return HB_OK;
        }
        if (op2 == 0x38) {
            /* F2/F3 0F 38 — CRC32 (F2 only), ADCX (66 only). The dispatch is
             * the same shape as the no-prefix 0F 38 path: ssse3_0f38_opcode
             * and sse41_0f38_opcode lookups. For F2 we accept CRC32 (F0/F1);
             * for F3 we accept ADOX (F7). For unrecognized F2/F3 0F 38 forms
             * we fall through to the next 0F 38 block (no prefix). */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t op3 = read_u8(d);
            if (prefix_f2) {
                if (op3 == 0xf0 || op3 == 0xf1) {
                    /* CRC32 r32, r/m8 / CRC32 r32, r/m32. */
                    if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                    uint8_t modrm = read_u8(d);
                    out->opcode = HB_INS_CRC32;
                    out->writes_flags = true;
                    hb_result_t r = parse_modrm(d, modrm, 4, out, 1, 2, false);
                    if (r != HB_OK) return r;
                    /* Mark src as r/m8 (CRC32 F0) or r/m32 (CRC32 F1). */
                    if (op3 == 0xf0 && out->op2.is_reg) {
                        uint8_t ro = 0;
                        out->op2.reg = reg8_idx(out->op2.reg, &ro);
                        out->op2.reg_offset = ro;
                        out->op2.size = 1;
                    } else if (op3 == 0xf0) {
                        out->op2.size = 1;
                    } else if (operand16) {
                        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 948 — ИСТОЧНИК ПОД 66.
                         * `66 F2 0F 38 F1` — это `CRC32 r32, r/m16`: приёмник остаётся
                         * тридцатидвухбитным (это чинилось в 935), а ИСТОЧНИК становится
                         * двухбайтовым. Мы брали четыре, то есть считали сумму по лишним двум
                         * байтам — и получали ДРУГОЕ ЧИСЛО, а не просто иную запись.
                         * Ветвь x64 источник сужает верно; отставала снова эта, четвёртый
                         * такой случай за день. */
                        out->op2.size = 2;
                    }
                    return HB_OK;
                }
            }
            /* ★ MOVDIRI и в ЭТОЙ ветви: команда игнорирует 66/F2/F3, а разбор
             * 0F38 в файле идёт ДВУМЯ развилками — ранней (по префиксу) и
             * поздней. Случай, добавленный только в позднюю, доставался лишь
             * бесприставочной форме; `f2 0f38f910` и `f3 0f38f910` перехватывала
             * ранняя и отдавала БЕЗЫМЯННЫЙ код. */
            if (op3 == 0xf9) {
                uint8_t modrm_di;
                hb_result_t rdi;
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                modrm_di = read_u8(d);
                if ((modrm_di >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
                out->opcode = HB_INS_MOVDIRI;
                out->writes_flags = false;
                rdi = parse_modrm(d, modrm_di, 4, out, 1, 2, true);
                if (rdi != HB_OK) return rdi;
                return HB_OK;
            }
            if (prefix_f3) {
                if (op3 == 0xf6) {
                    /* F3 0F 38 F6 = ADOX r32, r/m32. */
                    if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                    uint8_t modrm = read_u8(d);
                    out->opcode = HB_INS_ADOX;
                    out->writes_flags = true;
                    return parse_modrm(d, modrm, 4, out, 1, 2, false);
                }
            }
            /* Unrecognized F2/F3 0F 38: fall through to no-prefix dispatch. */
            d->pos--;
            return HB_ERR_UNSUPPORTED_OPCODE;
        }
        if (op2 == 0x3A) {
            /* F2/F3 0F 3A: no defined forms (SSE4.1 imm8 + AESKEYGENASSIST
             * use 66 prefix, not F2/F3). We reject. */
            return HB_ERR_UNSUPPORTED_OPCODE;
        }
        /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 285 — ПРОПУСТИТЬ, А НЕ ОТВЕРГНУТЬ.
         * Сюда доходят двухбайтовые команды, для которых F2/F3 НЕ часть кодировки: формы
         * MOVSS, MOVSD, POPCNT, TZCNT, LZCNT, PSHUFLW, PSHUFHW и CVT-семейство разобраны выше.
         * Настоящий процессор такой префикс здесь игнорирует. Возвращаем прочитанный байт и
         * отдаём разбор общему обработчику — по корпусу это 118 случаев.
         * В итерации 284 эта же правка встала НЕ СЮДА (замена по первому совпадению попала в
         * разбор x87, строка 627) и заодно сломала там законный отказ. */
        d->pos--;
    }

    if (opcode == 0x0F) {
        size_t saved_pos = d->pos;
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t op2 = read_u8(d);
        /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 302 — CPUID (`0F A2`).
         *
         * В 32-битном декодере его НЕ БЫЛО ВООБЩЕ, при том что x86-64 сторона его знает
         * (`hb_decode_x64.c:3290`). На нём встала ступень 1 Diablo: игра определяет процессор
         * (`mov eax,1; cpuid; shr edx,23; and edx,1` — признак MMX) и получает
         * UNSUPPORTED_OPCODE. Байт 0xA2 в двухбайтовом пространстве x86-32 свободен: занят
         * только ОДНОбайтовый 0xA2 (`MOV moffs`), это другая таблица.
         *
         * Разбор ставим ДО таблиц 0F38/0F3A и до векторных путей — урок MOVBE (итерация 187):
         * «добавил обработчик» и «обработчик достижим» разные утверждения, а перехватывает тот,
         * кто стоит раньше. Команда без операндов и без ModRM, флаги не пишет. */
        if (op2 == 0xA2) {
            out->opcode = HB_INS_CPUID;
            out->writes_flags = false;
            return HB_OK;
        }
        if (op2 == 0x06 || op2 == 0x08 || op2 == 0x09 || op2 == 0x30 || op2 == 0x32 || op2 == 0xAA) {
            /* CLTS, INVD, WBINVD, WRMSR, RDMSR, RSM — замер Prism в 32 битах: 0xC0000096
             * у всех шести (на x64 у `rsm` иначе — c000001d, там его нет в наборе). */
            out->opcode = HB_INS_PRIV;
            out->writes_flags = false;
            return HB_OK;
        }
        if (op2 == 0x31) {
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 938 — RDTSC на i386 НЕ РАЗБИРАЛСЯ
             * ВОВСЕ (`op=NONE`, длина 0). Замер Prism в 32-битном госте: code=00000000, то
             * есть исполняется. Ветвь Diablo — 32-битная, и счётчик тактов там ходовой. */
            out->opcode = HB_INS_RDTSC;
            out->writes_flags = false;
            return HB_OK;
        }
        /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 303 — ПЕРЕНОСЫ MMX.
         *
         * Ступень 1 Diablo за проверкой процессора уходит в путь MMX и упирается в `0F 6F 06`
         * (`MOVQ mm0,[esi]`). В 32-битном декодере MMX не было вовсе; на стороне x86-64
         * беспрефиксные `0F 6F/7F` уже разбираются как MMX (`hb_decode_x64.c:4565`), берём ту же
         * развязку по префиксу: БЕЗ префикса — MMX, с `66` — SSE (MOVDQA), с `F3` — MOVDQU.
         *
         *   0F 6E  MOVD mm, r/m32     0F 7E  MOVD r/m32, mm
         *   0F 6F  MOVQ mm, mm/m64    0F 7F  MOVQ mm/m64, mm
         *   0F 77  EMMS               (состояние x87 мы не помечаем — переносим как NOP)
         */
        if (!operand16 && !prefix_f2 && !prefix_f3 &&
            (op2 == 0x6E || op2 == 0x6F || op2 == 0x7E || op2 == 0x7F)) {
            int store = (op2 == 0x7E || op2 == 0x7F);
            int movd  = (op2 == 0x6E || op2 == 0x7E);
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            hb_result_t r;
            out->opcode = HB_INS_MMX_MOV;
            out->writes_flags = false;
            r = parse_modrm(d, modrm, movd ? 4 : 8, out, 1, 2, store);
            if (r != HB_OK) return r;
            /* Регистровое поле ModRM — всегда MMX. Второй операнд — MMX только если он регистр
             * (форма mm,mm); при памяти его помечать нечем и не надо. */
            mark_mm_operand(out, store ? 2 : 1);
            if ((modrm >> 6) == 3 && !movd) mark_mm_operand(out, store ? 1 : 2);
            return HB_OK;
        }
        /* Итерация 304, партия 2 MMX — побитовая логика.
         *
         * Стена ступени 1 после взятых переносов: `0F DB CD` (`PAND mm1,mm5`). Формы такие же,
         * как у переносов: без префикса — MMX (операнды 8 байт), с `66` — SSE над XMM, поэтому
         * развязка та же и стоит ДО векторных таблиц.
         *
         *   0F DB PAND   0F DF PANDN   0F EB POR   0F EF PXOR
         */
        if (!operand16 && !prefix_f2 && !prefix_f3 &&
            (op2 == 0xDB || op2 == 0xDF || op2 == 0xEB || op2 == 0xEF)) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            hb_result_t r;
            out->opcode = op2 == 0xDB ? HB_INS_MMX_AND :
                          op2 == 0xDF ? HB_INS_MMX_ANDN :
                          op2 == 0xEB ? HB_INS_MMX_OR : HB_INS_MMX_XOR;
            out->writes_flags = false;
            r = parse_modrm(d, modrm, 8, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_mm_operand(out, 1);
            if ((modrm >> 6) == 3) mark_mm_operand(out, 2);
            return HB_OK;
        }
        /* Итерация 305, партия 3 MMX — СДВИГИ, обе формы.
         *
         * Стена ступени 1 после взятой логики: `0F D3 C1` (`PSRLQ mm0,mm1`). Величина сдвига —
         * либо регистр MMX (формы D1/D2/D3, E1/E2, F1/F2/F3), либо непосредственная
         * (`0F 71/72/73 /r ib`, где вид сдвига задаёт поле reg модрм). Разрядность элемента
         * кладём в СУЩЕСТВУЮЩЕЕ поле `ret_imm` (2 — слово, 4 — двойное, 8 — учетверённое):
         * своего поля под это в `hb_decoded_t` нет, а ДОБАВЛЯТЬ поля в общие структуры нельзя —
         * итерация 303 показала, что это роняет прогон целиком. `ret_imm` осмыслен только для
         * RET, здесь он свободен.
         *
         * Сдвиг БОЛЬШЕ разрядности обнуляет элемент (для арифметического — заполняет знаком);
         * это спецификация, а не край, и в семантике учтено. */
        if (!operand16 && !prefix_f2 && !prefix_f3 &&
            (op2 == 0xD1 || op2 == 0xD2 || op2 == 0xD3 ||
             op2 == 0xE1 || op2 == 0xE2 ||
             op2 == 0xF1 || op2 == 0xF2 || op2 == 0xF3)) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            hb_result_t r;
            out->opcode = (op2 == 0xD1 || op2 == 0xD2 || op2 == 0xD3) ? HB_INS_MMX_SRL :
                          (op2 == 0xE1 || op2 == 0xE2) ? HB_INS_MMX_SRA : HB_INS_MMX_SLL;
            out->ret_imm = (op2 == 0xD1 || op2 == 0xE1 || op2 == 0xF1) ? 2 :
                           (op2 == 0xD2 || op2 == 0xE2 || op2 == 0xF2) ? 4 : 8;
            out->writes_flags = false;
            r = parse_modrm(d, modrm, 8, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_mm_operand(out, 1);
            if ((modrm >> 6) == 3) mark_mm_operand(out, 2);
            return HB_OK;
        }
        if (!operand16 && !prefix_f2 && !prefix_f3 &&
            (op2 == 0x71 || op2 == 0x72 || op2 == 0x73)) {
            /* Непосредственный сдвиг: вид задаёт поле reg модрм (2=SRL, 4=SRA, 6=SLL). */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t ext = (uint8_t)((modrm >> 3) & 7);
            if ((modrm >> 6) != 3) return HB_ERR_UNSUPPORTED_OPCODE;
            if (ext != 2 && ext != 4 && ext != 6) return HB_ERR_UNSUPPORTED_OPCODE;
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            out->opcode = ext == 2 ? HB_INS_MMX_SRL : ext == 4 ? HB_INS_MMX_SRA : HB_INS_MMX_SLL;
            out->ret_imm = op2 == 0x71 ? 2 : op2 == 0x72 ? 4 : 8;
            out->writes_flags = false;
            out->op1.is_reg = 1;
            out->op1.reg = (modrm & 7) + HB_REG_MM0;
            out->op1.size = 8;
            out->op2.is_imm = 1;
            out->op2.imm = read_u8(d);
            out->op2.size = 1;
            return HB_OK;
        }
        if (!operand16 && !prefix_f2 && !prefix_f3 && op2 == 0x77) {
            /* Итерация 520: комментарий ниже устарел — состояние x87 мы теперь моделируем,
             * и `emms` обязан пометить все регистры пустыми (замер эталона: тег-слово
             * 0xffff). Прежде переносился как NOP, из-за чего тег оставался 0x5556. */
            out->opcode = HB_INS_X87_EMMS;
            out->writes_flags = false;
            return HB_OK;
        }
        if (op2 == 0x38) {
            /* 0F38: SSSE3 (no-prefix = MMX, 0x66 = SSE), SSE4.1, AES, GF2P8MULB. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t op3 = read_u8(d);
            /* ★ MOVDIRI (0F38 F9) — СВОЙ случай, И ДО РАЗБОРА ПРЕФИКСОВ.
             *
             * Команда ИГНОРИРУЕТ 66/F2/F3. Стоя ниже, случай доставался
             * только бесприставочной форме, а `f2 0f38f910` и `f3 0f38f910`
             * перехватывала более ранняя ветвь и давала БЕЗЫМЯННЫЙ код.
             *
             * Приёмник у него ПАМЯТЬ, источник — регистр общего назначения, а
             * общий хвост этого пути разбирает операнды как 16-байтовые
             * векторные. Через таблицу форма получила бы верное имя и неверные
             * операнды — это хуже, чем сборный код, потому что выглядит
             * правильно. Решение то же, что у x64 (hb_decode_x64.c:3871). */
            if (op3 == 0xf9) {
                uint8_t modrm_di;
                hb_result_t rdi;
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                modrm_di = read_u8(d);
                if ((modrm_di >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
                out->opcode = HB_INS_MOVDIRI;
                out->writes_flags = false;
                rdi = parse_modrm(d, modrm_di, 4, out, 1, 2, true);
                if (rdi != HB_OK) return rdi;
                return HB_OK;
            }
            int vec_opcode;
            if (operand16 && op3 == 0xF8) {
                /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: партия 3 — MOVDIR64B r32, m512
                 * (`66 0F 38 F8 /r`). Приёмник — обычный регистр-указатель, источник —
                 * 64 байта памяти, поэтому пометки XMM здесь НЕ ставим. */
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                uint8_t modrm = read_u8(d);
                if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
                out->opcode = HB_INS_MOVDIR64B;
                out->writes_flags = false;
                return parse_modrm(d, modrm, 4, out, 1, 2, false);
            }
            /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — MOVBE ПРОТИВ CRC32 ПО ПРЕФИКСУ.
             *
             * Найдено замером (итерация 187): байты `0F 38 F0/F1` БЕЗ префикса — это MOVBE,
             * а CRC32 требует `F2`. Зонд `hb_x86_probe` показывал на них `op=CRC32`, тогда
             * как эталонный зонд x64 на тех же байтах даёт `MOVBE`, а на `F2 0F 38 F0` —
             * `CRC32`. Причина: таблица `sse41_0f38_opcode` отдаёт CRC32 для F0/F1
             * безусловно, а её зовёт и БЕСПРЕФИКСНЫЙ путь.
             *
             * Поэтому разбираем F0/F1 здесь, ДО таблицы. Иначе обработчик MOVBE в лифтере
             * недостижим: декодер до него просто не доводит. Ровно тот случай, про который
             * в матрице записано «добавил» и «достижимо» — разные вещи.
             *
             * Форма как в эталоне (`hb_decode_x64.c`), без REX: регистр-память, `mod == 3`
             * недопустим, направление задаёт F1. */
            if (op3 == 0xf0 || op3 == 0xf1) {
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                uint8_t modrm = read_u8(d);
                if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
                uint8_t size = operand16 ? 2 : 4;
                out->opcode = HB_INS_MOVBE;
                out->writes_flags = false;
                hb_result_t r = parse_modrm(d, modrm, size, out, 1, 2, op3 == 0xf1);
                if (r != HB_OK) return r;
                out->op1.size = size;
                out->op2.size = size;
                return HB_OK;
            }
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 948 — ADCX НЕ ВЕКТОРНАЯ КОМАНДА,
             * а лежит в той же таблице. `66 0F 38 F6` — это `ADCX r32, r/m32`, сложение с
             * переносом над ОБЩИМИ регистрами; префикс 66 у неё ОБЯЗАТЕЛЬНЫЙ и ширину не
             * меняет. Таблица `sse41_0f38_opcode` отдаёт её наравне с векторными, и общий
             * путь награждал её размером 16 и регистром XMM0:
             *     `660f38f6c0 adcx eax,eax`   было: size=16 reg=XMM0   стало: size=4 reg=EAX
             * то есть мы прибавляли бы в регистр SSE вместо `eax`. Соседний `ADOX` (под F3)
             * разобран отдельно и верен — здесь тот же приём для парной команды.
             * Ветвь x64 обе разбирает верно; отставала снова эта.
             * Третий случай за день, когда табличное правило накрывает исключение: до этого
             * семья SHA (947) и `PALIGNR` (946). */
            if (operand16 && op3 == 0xf6) {
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                uint8_t modrm_adcx = read_u8(d);
                out->opcode = HB_INS_ADCX;
                out->writes_flags = true;
                return parse_modrm(d, modrm_adcx, 4, out, 1, 2, false);
            }
            vec_opcode = ssse3_0f38_opcode(op3);
            if (!vec_opcode) vec_opcode = sse41_0f38_opcode(op3);
            if (vec_opcode) {
                /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 924 — MMX-ФОРМЫ SSSE3 ПОРТИЛИ
                 * РЕГИСТР XMM.
                 *
                 * Размер был зашит шестнадцатью, а операнды помечались как `xmm` независимо от
                 * префикса. Без `66` эти команды работают с регистрами MMX (8 байт), и мы
                 * писали результат НЕ В ТОТ ФАЙЛ РЕГИСТРОВ. Замер против эталона:
                 *   `0f3805c1 phsubw mm0,mm1`  эталон: xmm0 = d097b45b… (НЕ ТРОНУТ)
                 *                              мы:     xmm0 = 1c3ca9d5… (перезаписан)
                 * то же у `phaddw`, `pshufb`, `pabsb`; контроли `660f3805`/`660f3800` (формы
                 * xmm) сходились. Перебор дал 100 строк «наш 16, эталон 8» — крупнейшая кучка
                 * столбца операндов на этой ветви, и она оказалась порчей, а не описанием.
                 * Ветвь x64 эти формы разбирает верно (все 15 из 15) — правка по её образцу:
                 * размер и база регистров зависят от префикса `66`. */
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                uint8_t modrm = read_u8(d);
                out->opcode = vec_opcode;
                out->writes_flags = false;
                /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 947 — СЕМЬЯ SHA ЕСТЬ
                 * ИСКЛЮЧЕНИЕ ИЗ ПРАВИЛА 924, И ЭТО МОЙ ЖЕ НЕДОСМОТР.
                 * Правило «без 66 на карте 0F38 — это форма MMX» верно для SSSE3, но `SHA`
                 * (`0F 38 C8`-`CD`: sha1nexte, sha1msg1, sha1msg2, sha256rnds2, sha256msg1,
                 * sha256msg2) существует ТОЛЬКО без префикса и работает с XMM. Распространив
                 * правило на всю таблицу, я увёл шесть команд в восьмибайтовый банк MM:
                 * они писали бы в mm0 вместо xmm0 — та же порча регистрового файла, ради
                 * устранения которой правка 924 и делалась, только в обратную сторону.
                 * Перебор насчитал 290 строк «наш 8, эталон 16» — крупнейшая кучка столбца.
                 */
                bool sha_form = (op3 >= 0xc8 && op3 <= 0xcd);
                uint8_t vec_bytes = (operand16 || sha_form) ? 16 : 8;
                hb_result_t r = parse_modrm(d, modrm, vec_bytes, out, 1, 2, false);
                if (r != HB_OK) return r;
                if (operand16 || sha_form) {
                    mark_xmm_operand(out, 1);
                    mark_xmm_operand(out, 2);
                } else {
                    mark_mm_operand(out, 1);
                    if ((modrm >> 6) == 3) mark_mm_operand(out, 2);
                }
                return HB_OK;
            }
            /* Unrecognized 0F38 opcode: decode as a generic VEC. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_VEC;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if (op2 == 0x3A) {
            /* 0F3A: SSE4.1 imm8 + AES + PCLMULQDQ (all SSE = 0x66 prefix). */
            if (!can_read(d, 2)) return HB_ERR_DECODE_FAILED;
            uint8_t op3 = read_u8(d);
            uint8_t modrm = read_u8(d);
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 946 — БЕЗ ПРЕФИКСА 66 ЗДЕСЬ НЕ SSE.
             * Блок работал при ЛЮБОМ префиксе и всё приводил к xmm, хотя комментарий рядом
             * сам пишет «all SSE = 0x66 prefix». Без префикса на карте 0F3A законны ровно две
             * команды:
             *     0F 3A 0F  PALIGNR mm, mm/m64, imm8   — форма MMX, восемь байт
             *     0F 3A CC  SHA1RNDS4 xmm, xmm/m128, imm8 — xmm, шестнадцать
             * Мы же на `0f3a0fc07f` писали в xmm0 шестнадцатью байтами: и не тот банк
             * регистров, и не та ширина. Ровно класс итераций 918/919 (безпрефиксные формы
             * MMX), пропущенный потому, что те правились на карте 0F38, а эта — 0F3A.
             * Остальные опкоды карты без 66 не определены — честный отказ. */
            if (!operand16) {
                if (op3 == 0x0F) {
                    out->opcode = HB_INS_PALIGNR;
                    hb_result_t rmm = parse_modrm(d, modrm, 8, out, 1, 2, false);
                    if (rmm != HB_OK) return rmm;
                    if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                    set_imm(out, 3, read_u8(d), 1);
                    mark_mm_operand(out, 1);
                    if ((modrm >> 6) == 3) mark_mm_operand(out, 2);
                    return HB_OK;
                }
                if (op3 != 0xCC) return HB_ERR_UNSUPPORTED_OPCODE;
            }
            int vec_opcode = sse41_0f3a_opcode(op3);
            out->opcode = vec_opcode ? vec_opcode : HB_INS_VEC;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 3, read_u8(d), 1);
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if (operand16 && op2 == 0x70) {
            /* PSHUFD xmm, xmm/m128, imm8. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_PSHUFD;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 3, read_u8(d), 1);
            return HB_OK;
        }
        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — MMX-ФОРМЫ PINSRW/PEXTRW/PMOVMSKB.
         *
         * Тот же класс, что у сдвигов XMM по регистру: XMM-форма (под 66) написана
         * ниже, а парной MMX (без префикса) не существовало. Сплошной перебор против
         * capstone дал по два случая на каждую. Опкоды берём те же — ширину различает
         * интерпретатор по номеру регистра (`is_mm_reg`), а проставляет её здесь
         * `mark_mm_operand`. */
        if (!operand16 && !prefix_f2 && !prefix_f3 && op2 == 0xC4) {
            /* PINSRW mm, r/m16, imm8. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_PINSRW;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 2, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_mm_operand(out, 1);
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 3, read_u8(d), 1);
            return HB_OK;
        }
        if (!operand16 && !prefix_f2 && !prefix_f3 && op2 == 0xC5) {
            /* PEXTRW r32, mm, imm8. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_PEXTRW;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 4, out, 1, 2, false);
            if (r != HB_OK) return r;
            if (!out->op2.is_reg) return HB_ERR_UNSUPPORTED_OPCODE;
            mark_mm_operand(out, 2);
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 3, read_u8(d), 1);
            return HB_OK;
        }
        if (!operand16 && !prefix_f2 && !prefix_f3 && op2 == 0xD7) {
            /* PMOVMSKB r32, mm: восемь знаковых битов вместо шестнадцати. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_PMOVMSKB;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 4, out, 1, 2, false);
            if (r != HB_OK) return r;
            out->op1.size = 4;
            mark_mm_operand(out, 2);
            return HB_OK;
        }
        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — ПРЕОБРАЗОВАНИЯ MMX <-> ПЛАВАЮЩЕЕ.
         *
         * Шесть команд, которых не было ни в 32-битной ветке, ни в 64-битной как
         * настоящих (x64 сваливает `0F 2A/2C/2D` в общую корзину `HB_INS_VEC`, а её
         * лифтер не знает — см. запись про разбор против исполнимости). Здесь пишем
         * их полноценно.
         *
         *   0F 2A  CVTPI2PS  xmm, mm/m64   два int32 -> два float в младшие 64 бита
         *   0F 2C  CVTTPS2PI mm,  xmm/m64  два float -> два int32, УСЕЧЕНИЕ
         *   0F 2D  CVTPS2PI  mm,  xmm/m64  то же, округление по текущему режиму
         *   66 0F 2A  CVTPI2PD  xmm, mm/m64   два int32 -> два double
         *   66 0F 2C  CVTTPD2PI mm,  xmm/m128 два double -> два int32, УСЕЧЕНИЕ
         *   66 0F 2D  CVTPD2PI  mm,  xmm/m128 то же, с округлением
         *
         * Ширина операнда в памяти разная: у форм с MMX-источником это 8 байт, у
         * CVTTPD2PI/CVTPD2PI источник — полный XMM, то есть 16. */
        if ((!operand16 && !prefix_f2 && !prefix_f3 &&
             (op2 == 0x2A || op2 == 0x2C || op2 == 0x2D)) ||
            (operand16 && (op2 == 0x2A || op2 == 0x2C || op2 == 0x2D))) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            bool в_плавающее = (op2 == 0x2A);
            uint8_t mem_size;
            if (op2 == 0x2A) {
                out->opcode = operand16 ? HB_INS_CVTPI2PD : HB_INS_CVTPI2PS;
                mem_size = 8;                     /* источник — mm/m64 */
            } else if (op2 == 0x2C) {
                out->opcode = operand16 ? HB_INS_CVTTPD2PI : HB_INS_CVTTPS2PI;
                mem_size = operand16 ? 16 : 8;    /* источник — xmm/m128 либо m64 */
            } else {
                out->opcode = operand16 ? HB_INS_CVTPD2PI : HB_INS_CVTPS2PI;
                mem_size = operand16 ? 16 : 8;
            }
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, mem_size, out, 1, 2, false);
            if (r != HB_OK) return r;
            if (в_плавающее) {
                mark_xmm_operand(out, 1);         /* приёмник XMM */
                if (out->op2.is_reg) mark_mm_operand(out, 2);
            } else {
                mark_mm_operand(out, 1);          /* приёмник MMX */
                if (out->op2.is_reg) mark_xmm_operand(out, 2);
            }
            if (out->op2.is_mem) out->op2.size = mem_size;
            return HB_OK;
        }
        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — SSE3 И ПЕРЕКЛАДКА MMX<->XMM.
         *
         * Тринадцать команд, которых в 32-битной ветке не было. В 64-битной они
         * «разбираются», но лишь в общую корзину `HB_INS_VEC`, которую лифтер не
         * знает, — то есть исполнить их не может ни одна ветка. Пишем как
         * настоящие.
         *
         *   66 0F 7C HADDPD    F2 0F 7C HADDPS    горизонтальное сложение
         *   66 0F 7D HSUBPD    F2 0F 7D HSUBPS    горизонтальное вычитание
         *   66 0F D0 ADDSUBPD  F2 0F D0 ADDSUBPS  вычитание и сложение через дорожку
         *   F2 0F 12 MOVDDUP   F3 0F 12 MOVSLDUP  F3 0F 16 MOVSHDUP  размножение
         *   F3 0F D6 MOVQ2DQ   F2 0F D6 MOVDQ2Q   перекладка между файлами
         *   0F F7    MASKMOVQ  66 0F F7 MASKMOVDQU  запись по маске в [edi]
         *
         * MOVDDUP берёт из памяти 8 байт, остальные векторные — 16. */
        if ((operand16 || prefix_f2) && (op2 == 0x7C || op2 == 0x7D || op2 == 0xD0)) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0x7C)      out->opcode = operand16 ? HB_INS_HADDPD : HB_INS_HADDPS;
            else if (op2 == 0x7D) out->opcode = operand16 ? HB_INS_HSUBPD : HB_INS_HSUBPS;
            else                  out->opcode = operand16 ? HB_INS_ADDSUBPD : HB_INS_ADDSUBPS;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = 16;
            return HB_OK;
        }
        if ((prefix_f2 && op2 == 0x12) || (prefix_f3 && (op2 == 0x12 || op2 == 0x16))) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t mem_size;
            if (prefix_f2) { out->opcode = HB_INS_MOVDDUP;  mem_size = 8;  }
            else if (op2 == 0x12) { out->opcode = HB_INS_MOVSLDUP; mem_size = 16; }
            else { out->opcode = HB_INS_MOVSHDUP; mem_size = 16; }
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, mem_size, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = mem_size;
            return HB_OK;
        }
        if ((prefix_f3 || prefix_f2) && op2 == 0xD6) {
            /* MOVQ2DQ xmm, mm (F3) и MOVDQ2Q mm, xmm (F2) — только регистровая форма. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if ((modrm >> 6) != 3) return HB_ERR_UNSUPPORTED_OPCODE;
            out->opcode = prefix_f3 ? HB_INS_MOVQ2DQ : HB_INS_MOVDQ2Q;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 8, out, 1, 2, false);
            if (r != HB_OK) return r;
            if (prefix_f3) { mark_xmm_operand(out, 1); mark_mm_operand(out, 2); }
            else           { mark_mm_operand(out, 1);  mark_xmm_operand(out, 2); }
            return HB_OK;
        }
        if ((!operand16 && !prefix_f2 && !prefix_f3 && op2 == 0xF7) ||
            (operand16 && op2 == 0xF7)) {
            /* MASKMOVQ mm, mm и MASKMOVDQU xmm, xmm: запись по маске байтов в [edi].
             * Приёмник неявный, оба явных операнда — источники. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if ((modrm >> 6) != 3) return HB_ERR_UNSUPPORTED_OPCODE;
            out->opcode = operand16 ? HB_INS_MASKMOVDQU : HB_INS_MASKMOVQ;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, operand16 ? 16 : 8, out, 1, 2, false);
            if (r != HB_OK) return r;
            if (operand16) { mark_xmm_operand(out, 1); mark_xmm_operand(out, 2); }
            else           { mark_mm_operand(out, 1);  mark_mm_operand(out, 2); }
            return HB_OK;
        }
        if (operand16 && op2 == 0xC4) {
            /* PINSRW xmm, r/m16, imm8. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_PINSRW;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 2, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 3, read_u8(d), 1);
            return HB_OK;
        }
        if (operand16 && op2 == 0xC5) {
            /* PEXTRW r32, xmm, imm8. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_PEXTRW;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 4, out, 1, 2, false);
            if (r != HB_OK) return r;
            if (!out->op2.is_reg) return HB_ERR_UNSUPPORTED_OPCODE;
            mark_xmm_operand(out, 2);
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 3, read_u8(d), 1);
            return HB_OK;
        }
        if (operand16 && (op2 == 0xF8 || op2 == 0xF9 || op2 == 0xFA || op2 == 0xFB)) {
            /* Packed integer subtract family: PSUBB/PSUBW/PSUBD/PSUBQ xmm, xmm/m128. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0xF8) out->opcode = HB_INS_PSUBB;
            else if (op2 == 0xF9) out->opcode = HB_INS_PSUBW;
            else if (op2 == 0xFA) out->opcode = HB_INS_PSUBD;
            else out->opcode = HB_INS_PSUBQ;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        /* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 521 — ФОРМА MMX семьи сложений.
         * Раньше семья разбиралась ТОЛЬКО с префиксом 0x66, то есть в виде XMM; без префикса
         * (это и есть форма MMX, `paddd mm0,mm1`) случай проваливался в UNSUPPORTED_OPCODE.
         * Замер 517: из восьми представителей MMX в 32 битах не шли ровно эти две семьи. */
        if (!operand16 && !prefix_f2 && !prefix_f3 &&
            (op2 == 0xFC || op2 == 0xFD || op2 == 0xFE || op2 == 0xD4)) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0xFC) out->opcode = HB_INS_PADDB;
            else if (op2 == 0xFD) out->opcode = HB_INS_PADDW;
            else if (op2 == 0xFE) out->opcode = HB_INS_PADDD;
            else out->opcode = HB_INS_PADDQ;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 8, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_mm_operand(out, 1);
            if ((modrm >> 6) == 3) mark_mm_operand(out, 2);
            return HB_OK;
        }
        if (operand16 && (op2 == 0xFC || op2 == 0xFD || op2 == 0xFE || op2 == 0xD4)) {
            /* Packed integer add family: PADDB/PADDW/PADDD/PADDQ xmm, xmm/m128. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0xFC) out->opcode = HB_INS_PADDB;
            else if (op2 == 0xFD) out->opcode = HB_INS_PADDW;
            else if (op2 == 0xFE) out->opcode = HB_INS_PADDD;
            else out->opcode = HB_INS_PADDQ;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if (operand16 && op2 == 0xE6) {
            /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: партия 3 — CVTTPD2DQ xmm, xmm/m128
             * (`66 0F E6`), усечение к нулю. Пара к `F2 0F E6` выше. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_CVTTPD2DQ;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if (operand16 && (op2 == 0xE8 || op2 == 0xE9 || op2 == 0xD8 || op2 == 0xD9 ||
                          op2 == 0xF6)) {
            /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — партия 4: насыщающее ВЫЧИТАНИЕ и
             * PSADBW, xmm/m128. Замер 188: без этой ветки коды давали decode=-5, то есть
             * до лифтера не доходили вовсе; форма та же, что у семейства PADDS выше. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0xE8) out->opcode = HB_INS_PSUBSB;
            else if (op2 == 0xE9) out->opcode = HB_INS_PSUBSW;
            else if (op2 == 0xD8) out->opcode = HB_INS_PSUBUSB;
            else if (op2 == 0xD9) out->opcode = HB_INS_PSUBUSW;
            else out->opcode = HB_INS_PSADBW;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if (operand16 && (op2 == 0xEC || op2 == 0xED || op2 == 0xDC || op2 == 0xDD ||
                          op2 == 0xE0 || op2 == 0xE3)) {
            /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: партия 1 закрытия остатка лифтера x86-32.
             * Насыщающее сложение и среднее: PADDSB/PADDSW/PADDUSB/PADDUSW/PAVGB/PAVGW
             * xmm, xmm/m128. Разбор тот же, что у семейства PADDB выше. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0xEC) out->opcode = HB_INS_PADDSB;
            else if (op2 == 0xED) out->opcode = HB_INS_PADDSW;
            else if (op2 == 0xDC) out->opcode = HB_INS_PADDUSB;
            else if (op2 == 0xDD) out->opcode = HB_INS_PADDUSW;
            else if (op2 == 0xE0) out->opcode = HB_INS_PAVGB;
            else out->opcode = HB_INS_PAVGW;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if (operand16 && (op2 == 0xD5 || op2 == 0xE5 || op2 == 0xE4 || op2 == 0xF5)) {
            /* SSE2 packed 16-bit multiply family, xmm, xmm/m128. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0xD5) out->opcode = HB_INS_PMULLW;
            else if (op2 == 0xE5) out->opcode = HB_INS_PMULHW;
            else if (op2 == 0xE4) out->opcode = HB_INS_PMULHUW;
            else out->opcode = HB_INS_PMADDWD;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 918 — БЕЗПРЕФИКСНЫЕ ФОРМЫ MMX,
         * ВТОРАЯ ПАРТИЯ. Продолжение работы 881/883 (PUNPCK, PSHUFW) и переноса 907 на x64.
         *
         * Полный перебор (входящее 110) дал на этой ветви 38 опкодов, где эталон исполняет
         * MMX-форму, а мы отказываем. Здесь взяты те 30, у которых оба операнда — регистры
         * MMX и нет непосредственного: тогда разбор совпадает с уже написанным для SSE2,
         * различаются только размер (8 против 16) и база регистров.
         * ВНЕ этой партии намеренно оставлены семь форм иного устройства — `pinsrw`/`pextrw`
         * (непосредственное и ОБЩИЙ регистр), `pmovmskb` (приёмник — общий регистр),
         * `movntq`/`maskmovq` (память), `cvtpi2ps`/`cvtps2pi`/`cvttps2pi` (смешивают mm и
         * xmm). Их надо разбирать по одной, а не общим правилом.
         * Ветвь x64 эти формы уже берёт — сверял по ней, а не по справочнику. */
        if (!operand16 && !prefix_f2 && !prefix_f3 &&
            (op2 == 0x64 || op2 == 0x65 || op2 == 0x66 ||
             op2 == 0x74 || op2 == 0x75 || op2 == 0x76 ||
             op2 == 0xD5 || (op2 >= 0xD8 && op2 <= 0xDA) ||
             (op2 >= 0xDC && op2 <= 0xDE) ||
             op2 == 0xE0 || op2 == 0xE3 || op2 == 0xE4 || op2 == 0xE5 ||
             op2 == 0xE8 || op2 == 0xE9 || op2 == 0xEA ||
             op2 == 0xEC || op2 == 0xED || op2 == 0xEE ||
             (op2 >= 0xF4 && op2 <= 0xF6) || (op2 >= 0xF8 && op2 <= 0xFB))) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            switch (op2) {
                case 0x64: out->opcode = HB_INS_PCMPGTB; break;
                case 0x65: out->opcode = HB_INS_PCMPGTW; break;
                case 0x66: out->opcode = HB_INS_PCMPGTD; break;
                case 0x74: out->opcode = HB_INS_PCMPEQB; break;
                case 0x75: out->opcode = HB_INS_PCMPEQW; break;
                case 0x76: out->opcode = HB_INS_PCMPEQD; break;
                case 0xD5: out->opcode = HB_INS_PMULLW;  break;
                case 0xD8: out->opcode = HB_INS_PSUBUSB; break;
                case 0xD9: out->opcode = HB_INS_PSUBUSW; break;
                case 0xDA: out->opcode = HB_INS_PMINUB;  break;
                case 0xDC: out->opcode = HB_INS_PADDUSB; break;
                case 0xDD: out->opcode = HB_INS_PADDUSW; break;
                case 0xDE: out->opcode = HB_INS_PMAXUB;  break;
                case 0xE0: out->opcode = HB_INS_PAVGB;   break;
                case 0xE3: out->opcode = HB_INS_PAVGW;   break;
                case 0xE4: out->opcode = HB_INS_PMULHUW; break;
                case 0xE5: out->opcode = HB_INS_PMULHW;  break;
                case 0xE8: out->opcode = HB_INS_PSUBSB;  break;
                case 0xE9: out->opcode = HB_INS_PSUBSW;  break;
                case 0xEA: out->opcode = HB_INS_PMINSW;  break;
                case 0xEC: out->opcode = HB_INS_PADDSB;  break;
                case 0xED: out->opcode = HB_INS_PADDSW;  break;
                case 0xEE: out->opcode = HB_INS_PMAXSW;  break;
                case 0xF4: out->opcode = HB_INS_PMULUDQ; break;
                case 0xF5: out->opcode = HB_INS_PMADDWD; break;
                case 0xF6: out->opcode = HB_INS_PSADBW;  break;
                case 0xF8: out->opcode = HB_INS_PSUBB;   break;
                case 0xF9: out->opcode = HB_INS_PSUBW;   break;
                case 0xFA: out->opcode = HB_INS_PSUBD;   break;
                default:   out->opcode = HB_INS_PSUBQ;   break;
            }
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 8, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_mm_operand(out, 1);
            if ((modrm >> 6) == 3) mark_mm_operand(out, 2);
            return HB_OK;
        }
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 919 — SSE2-ФОРМЫ ПЯТЁРКИ.
         * `PMINUB/PMAXUB/PMINSW/PMAXSW/PMULUDQ` на этой ветви не разбирались и с префиксом
         * `66` (замер: `660fdac1` давал decode=-5 при живом контроле `660ffcc1 paddb xmm`).
         * MMX-формы добавлены в 918, лифтер — в этой же итерации; недоставало этой ветви. */
        if (operand16 && (op2 == 0xDA || op2 == 0xDE || op2 == 0xEA ||
                          op2 == 0xEE || op2 == 0xF4)) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = op2 == 0xDA ? HB_INS_PMINUB :
                          op2 == 0xDE ? HB_INS_PMAXUB :
                          op2 == 0xEA ? HB_INS_PMINSW :
                          op2 == 0xEE ? HB_INS_PMAXSW : HB_INS_PMULUDQ;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if (operand16 && (op2 == 0x64 || op2 == 0x65 || op2 == 0x66 ||
                          op2 == 0x74 || op2 == 0x75 || op2 == 0x76)) {
            /* PCMPGTB/W/D and PCMPEQB/W/D xmm, xmm/m128. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0x64) out->opcode = HB_INS_PCMPGTB;
            else if (op2 == 0x65) out->opcode = HB_INS_PCMPGTW;
            else if (op2 == 0x66) out->opcode = HB_INS_PCMPGTD;
            else if (op2 == 0x74) out->opcode = HB_INS_PCMPEQB;
            else if (op2 == 0x75) out->opcode = HB_INS_PCMPEQW;
            else out->opcode = HB_INS_PCMPEQD;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if ((op2 == 0x14 || op2 == 0x15) && !prefix_f2 && !prefix_f3) {
            /* UNPCKLPS/UNPCKLPD/UNPCKHPS/UNPCKHPD, xmm, xmm/m128. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0x14) out->opcode = operand16 ? HB_INS_UNPCKLPD : HB_INS_UNPCKLPS;
            else out->opcode = operand16 ? HB_INS_UNPCKHPD : HB_INS_UNPCKHPS;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if (op2 == 0xC6 && !prefix_f2 && !prefix_f3) {
            /* SHUFPS/SHUFPD xmm, xmm/m128, imm8. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = operand16 ? HB_INS_SHUFPD : HB_INS_SHUFPS;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 3, read_u8(d), 1);
            return HB_OK;
        }
        if (operand16 && op2 == 0xD7) {
            /* PMOVMSKB r32, xmm: extract byte sign bits into a zero-extended mask. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_PMOVMSKB;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 4, out, 1, 2, false);
            if (r != HB_OK) return r;
            out->op1.size = 4;
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if ((!operand16 && !prefix_f2 && !prefix_f3 && op2 == 0x50) ||
            (operand16 && op2 == 0x50)) {
            /* MOVMSKPS/MOVMSKPD r32, xmm: extract packed FP sign bits. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = operand16 ? HB_INS_MOVMSKPD : HB_INS_MOVMSKPS;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 4, out, 1, 2, false);
            if (r != HB_OK) return r;
            if (!out->op2.is_reg) return HB_ERR_UNSUPPORTED_OPCODE;
            mark_xmm_operand(out, 2);
            out->op1.size = 4;
            return HB_OK;
        }
        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — СДВИГИ XMM СО СЧЁТЧИКОМ В РЕГИСТРЕ.
         *
         * Diablo умирал с c000001d на `66 0f f3 dc` = PSLLQ xmm3,xmm4 по адресу
         * 78a0d735 (смещение +62 от начала блока — оттого прежнее окно печати в 48
         * байт его и не показывало). Не одна команда, а ровно восемь: вся
         * регистровая форма семейства отсутствовала, при том что
         *
         *   - MMX-форма (`0F D1` без 66) разбирается ниже,
         *   - XMM-форма с непосредственным (`66 0F 71/72/73`) разбирается здесь же,
         *   - интерпретатор УЖЕ умеет счётчик из регистра: ветка не-IMM в
         *     `read_packed_shift_count` (`hb_interpreter.c`) написана и даже
         *     доработана до правильного насыщения при счётчике больше ширины.
         *
         * То есть готово было всё, кроме одного пропущенного случая в разборе:
         * условие соседней ветки требовало `!operand16`, а эта не существовала
         * вовсе. Опкоды берём те же, что у формы с непосредственным, — тогда лифтер
         * и интерпретатор принимают её без единой правки (`operand_from_dec(dec, 2)`
         * там уже безразличен к виду операнда). */
        if (operand16 && !prefix_f2 && !prefix_f3 &&
            (op2 == 0xD1 || op2 == 0xD2 || op2 == 0xD3 ||
             op2 == 0xE1 || op2 == 0xE2 ||
             op2 == 0xF1 || op2 == 0xF2 || op2 == 0xF3)) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            switch (op2) {
                case 0xD1: out->opcode = HB_INS_PSRLW; break;
                case 0xD2: out->opcode = HB_INS_PSRLD; break;
                case 0xD3: out->opcode = HB_INS_PSRLQ; break;
                case 0xE1: out->opcode = HB_INS_PSRAW; break;
                case 0xE2: out->opcode = HB_INS_PSRAD; break;
                case 0xF1: out->opcode = HB_INS_PSLLW; break;
                case 0xF2: out->opcode = HB_INS_PSLLD; break;
                default:   out->opcode = HB_INS_PSLLQ; break;
            }
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = 16;
            return HB_OK;
        }
        if (operand16 && (op2 == 0x71 || op2 == 0x72 || op2 == 0x73)) {
            /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: сдвиги XMM на непосредственное значение.
             * Вторая недостача в том же блоке crtdll.dll: по 0x79d2b860 лежит
             * 66 0f 73 f5 20, то есть PSLLQ xmm5,0x20. Эталон — hb_decode_x64.c:4378,
             * оттуда же таблица расширений: 0F 71/72 берут /2,/4,/6, а 0F 73 ещё и
             * байтовые сдвиги /3 и /7. Приёмник только регистр, потом байт-константа. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t ext = (modrm >> 3) & 7;
            if (op2 == 0x71 && ext == 2) out->opcode = HB_INS_PSRLW;
            else if (op2 == 0x71 && ext == 4) out->opcode = HB_INS_PSRAW;
            else if (op2 == 0x71 && ext == 6) out->opcode = HB_INS_PSLLW;
            else if (op2 == 0x72 && ext == 2) out->opcode = HB_INS_PSRLD;
            else if (op2 == 0x72 && ext == 4) out->opcode = HB_INS_PSRAD;
            else if (op2 == 0x72 && ext == 6) out->opcode = HB_INS_PSLLD;
            else if (op2 == 0x73 && ext == 2) out->opcode = HB_INS_PSRLQ;
            else if (op2 == 0x73 && ext == 3) out->opcode = HB_INS_PSRLDQ;
            else if (op2 == 0x73 && ext == 6) out->opcode = HB_INS_PSLLQ;
            else if (op2 == 0x73 && ext == 7) out->opcode = HB_INS_PSLLDQ;
            else return HB_ERR_UNSUPPORTED_OPCODE;
            out->writes_flags = false;
            hb_result_t r = parse_modrm_ext(d, modrm, 16, out, 1);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 2, read_u8(d), 1);
            return HB_OK;
        }
        if (operand16 && op2 == 0x6E) {
            /* MOVD xmm, r/m32. Ported from the x64 SSE transfer family. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_MOVD;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 4, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            out->op2.size = 4;
            return HB_OK;
        }
        if (operand16 && op2 == 0x7E) {
            /* MOVD r/m32, xmm. Ported from the x64 SSE transfer family. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_MOVD;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 4, out, 1, 2, true);
            if (r != HB_OK) return r;
            out->op1.size = 4;
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if (operand16 && op2 == 0xD6) {
            /* MOVQ xmm/m64, xmm. Ported from the x64 SSE transfer family. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_MOVD;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 8, out, 1, 2, true);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op1.is_mem) out->op1.size = 8;
            return HB_OK;
        }
        if (!prefix_f2 && !prefix_f3 && (op2 == 0x12 || op2 == 0x13 || op2 == 0x16 || op2 == 0x17)) {
            /* MOVLPS/MOVLPD and MOVHPS/MOVHPD memory forms move one qword lane.
             * Register 0F 12/16 aliases MOVHLPS/MOVLHPS.
             */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if ((modrm >> 6) == 3) {
                if (operand16 || op2 == 0x13 || op2 == 0x17) return HB_ERR_UNSUPPORTED_OPCODE;
                out->opcode = op2 == 0x12 ? HB_INS_MOVHLPS : HB_INS_MOVLHPS;
                out->writes_flags = false;
                hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
                if (r != HB_OK) return r;
                mark_xmm_operand(out, 1);
                mark_xmm_operand(out, 2);
                return HB_OK;
            }
            if (op2 == 0x16 || op2 == 0x17) {
                out->opcode = operand16 ? HB_INS_MOVHPD : HB_INS_MOVHPS;
                out->writes_flags = false;
                hb_result_t r = parse_modrm(d, modrm, 8, out, 1, 2, op2 == 0x17);
                if (r != HB_OK) return r;
                mark_xmm_operand(out, op2 == 0x17 ? 2 : 1);
                if (op2 == 0x17) out->op1.size = 8;
                else out->op2.size = 8;
                return HB_OK;
            }
            out->opcode = HB_INS_SSE_MOV;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 8, out, 1, 2, op2 == 0x13);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, op2 == 0x13 ? 2 : 1);
            if (op2 == 0x13) out->op2.size = 8;
            else out->op1.size = 8;
            return HB_OK;
        }
        if ((!operand16 && op2 == 0x5B) || (operand16 && op2 == 0x5B)) {
            /* CVTDQ2PS/CVTPS2DQ xmm, xmm/m128. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = operand16 ? HB_INS_CVTPS2DQ : HB_INS_CVTDQ2PS;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if (op2 == 0x5A) {
            /* CVTPS2PD/CVTPD2PS xmm, xmm/m64/m128. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t mem_size = operand16 ? 16 : 8;
            out->opcode = operand16 ? HB_INS_CVTPD2PS : HB_INS_CVTPS2PD;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, mem_size, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = mem_size;
            return HB_OK;
        }
        if (op2 == 0x58 || op2 == 0x5C) {
            /* Packed ADD/SUB: ADDPS/SUBPS and ADDPD/SUBPD. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (operand16) out->opcode = (op2 == 0x58) ? HB_INS_ADDPD : HB_INS_SUBPD;
            else out->opcode = (op2 == 0x58) ? HB_INS_ADDPS : HB_INS_SUBPS;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if ((op2 == 0x59 || op2 == 0x5E) && !prefix_f2 && !prefix_f3) {
            /* Packed MUL/DIV: MULPS/DIVPS and MULPD/DIVPD. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (operand16) out->opcode = (op2 == 0x59) ? HB_INS_MULPD : HB_INS_DIVPD;
            else out->opcode = (op2 == 0x59) ? HB_INS_MULPS : HB_INS_DIVPS;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — пакетная половина того же семейства
         * (CMPPS/CMPPD, 0F C2 без F2/F3). Скалярная половина лежит в группе префиксов
         * выше; здесь ветвление то же, что у соседнего `0F 5D`: 66 -> double. */
        if (op2 == 0xC2) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = operand16 ? HB_INS_CMPPD : HB_INS_CMPPS;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = 16;
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 3, read_u8(d), 1);
            return HB_OK;
        }
        if (op2 == 0x5D || op2 == 0x5F) {
            /* Packed MIN/MAX: MINPS/MAXPS and MINPD/MAXPD. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (operand16) out->opcode = (op2 == 0x5D) ? HB_INS_MINPD : HB_INS_MAXPD;
            else out->opcode = (op2 == 0x5D) ? HB_INS_MINPS : HB_INS_MAXPS;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if ((op2 == 0x2E || op2 == 0x2F) && !prefix_f2 && !prefix_f3) {
            /* COMISS/UCOMISS and COMISD/UCOMISD share ordered flag semantics here. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = operand16 ? HB_INS_COMISD : HB_INS_COMISS;
            out->writes_flags = true;
            hb_result_t r = parse_modrm(d, modrm, operand16 ? 8 : 4, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = operand16 ? 8 : 4;
            return HB_OK;
        }
        /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 287 — СЕМЕЙСТВО PACK С НАСЫЩЕНИЕМ.
         * `66 0F 63/67/6B` (PACKSSWB, PACKUSWB, PACKSSDW, xmm, xmm/m128) есть в декодере x64
         * (`hb_decode_x64.c:4291`), а в i386 отсутствовало — то же расхождение двух декодеров,
         * что было с `CDQ` в итерации 262. Промежуточное представление и интерпретатор эти
         * операции знают, не хватало только разбора. */
        /* Итерация 522: форма MMX семьи упаковки с насыщением (`packsswb`/`packuswb`/`packssdw`
         * mm, mm/m64). Как и у семьи сложений в 521, разбор существовал только для формы XMM
         * с префиксом `0x66`. */
        if (!operand16 && !prefix_f2 && !prefix_f3 &&
            (op2 == 0x63 || op2 == 0x67 || op2 == 0x6B)) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0x63) out->opcode = HB_INS_PACKSSWB;
            else if (op2 == 0x67) out->opcode = HB_INS_PACKUSWB;
            else out->opcode = HB_INS_PACKSSDW;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 8, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_mm_operand(out, 1);
            if ((modrm >> 6) == 3) mark_mm_operand(out, 2);
            return HB_OK;
        }
        if (operand16 && (op2 == 0x63 || op2 == 0x67 || op2 == 0x6B)) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0x63) out->opcode = HB_INS_PACKSSWB;
            else if (op2 == 0x67) out->opcode = HB_INS_PACKUSWB;
            else out->opcode = HB_INS_PACKSSDW;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 881 — MMX-ФОРМА PUNPCK.
         * Ниже разбиралась только форма SSE2 (с префиксом 0x66, регистры xmm, 128 бит), а
         * БЕЗПРЕФИКСНАЯ форма `mm, mm/m64` не бралась вовсе: по стенду 6 случаев из 39
         * оставшихся пробелов x86-32 (`0f60c0` punpcklbw mm0,mm0; `0f6000`; `670f60c0` …).
         * Ветвь x64 её разбирает — там это ссылка, а не догадка.
         * `0x6C`/`0x6D` (PUNPCKLQDQ/HQDQ) сюда НЕ входят: в MMX их не существует, они
         * появились только в SSE2, и принимать их без префикса было бы ошибкой в другую сторону. */
        /* Итерация 883 — `PSHUFW mm, mm/m64, imm8` (0F 70 /r ib БЕЗ префикса).
         * Префиксные формы разбираются в других местах (0x66 -> PSHUFD, F2 -> PSHUFLW,
         * F3 -> PSHUFHW), а безпрефиксная MMX-форма не бралась вовсе: 6 случаев из 33.
         * ★ Первую попытку я поставил внутрь блока `if (opcode == 0x0F && (prefix_f2 ||
         * prefix_f3))` — там условие «префиксов нет» недостижимо, и ветвь была МЁРТВЫМ кодом
         * (замер: decode=-5 при живых контролях). Здесь блок общий, рядом с MMX-формой PUNPCK. */
        if (op2 == 0x70 && !operand16 && !prefix_f2 && !prefix_f3) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_PSHUFW;
            out->writes_flags = false;
            hb_result_t rw = parse_modrm(d, modrm, 8, out, 1, 2, false);
            if (rw != HB_OK) return rw;
            mark_mm_operand(out, 1);
            if ((modrm >> 6) == 3) mark_mm_operand(out, 2);
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 3, read_u8(d), 1);
            return HB_OK;
        }
        if (!operand16 && !prefix_f2 && !prefix_f3 &&
            ((op2 >= 0x60 && op2 <= 0x62) || (op2 >= 0x68 && op2 <= 0x6A))) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0x60) out->opcode = HB_INS_PUNPCKLBW;
            else if (op2 == 0x61) out->opcode = HB_INS_PUNPCKLWD;
            else if (op2 == 0x62) out->opcode = HB_INS_PUNPCKLDQ;
            else if (op2 == 0x68) out->opcode = HB_INS_PUNPCKHBW;
            else if (op2 == 0x69) out->opcode = HB_INS_PUNPCKHWD;
            else out->opcode = HB_INS_PUNPCKHDQ;
            out->writes_flags = false;
            /* 8 байт и БЕЗ mark_xmm_operand: операнды здесь mm, а не xmm. */
            hb_result_t rmm = parse_modrm(d, modrm, 8, out, 1, 2, false);
            if (rmm != HB_OK) return rmm;
            /* Итерация 882 — БЕЗ ЭТОГО ОПЕРАНДЫ УХОДИЛИ КАК ОБЫЧНЫЕ РЕГИСТРЫ.
             * В 881 я добавил разбор, но не пометил операнды как MMX, и `mm0` был неотличим от
             * `eax`: интерпретатор отвечал `HB_ERR_INTERNAL` (-99) на ОБЕИХ формах, и на
             * регистровой тоже. Идиома взята у соседнего MMX_MOV: поле reg модрм — всегда mm,
             * второй операнд — mm только когда он регистр (при памяти помечать нечего. */
            mark_mm_operand(out, 1);
            if ((modrm >> 6) == 3) mark_mm_operand(out, 2);
            /* У НИЖНИХ распаковок источник в памяти — 32 бита, а не 64: спецификация пишет их
             * как `PUNPCKLBW/LWD/LDQ mm, mm/m32` (берутся только младшие 4 байта). У ВЕРХНИХ
             * (`PUNPCKHBW/HWD/HDQ`) источник `mm/m64`. Замер: `0f6000` эталон даёт dword (4),
             * `0f6800` — qword (8); без этой поправки 4 из 6 новых команд расходились. */
            if (op2 <= 0x62 && out->op2.is_mem) out->op2.size = 4;
            return HB_OK;
        }
        if (operand16 && ((op2 >= 0x60 && op2 <= 0x62) ||
                          (op2 >= 0x68 && op2 <= 0x6A) ||
                          op2 == 0x6C || op2 == 0x6D)) {
            /* SSE2 PUNPCK low/high integer unpack family, xmm, xmm/m128. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0x60) out->opcode = HB_INS_PUNPCKLBW;
            else if (op2 == 0x61) out->opcode = HB_INS_PUNPCKLWD;
            else if (op2 == 0x62) out->opcode = HB_INS_PUNPCKLDQ;
            else if (op2 == 0x6C) out->opcode = HB_INS_PUNPCKLQDQ;
            else if (op2 == 0x68) out->opcode = HB_INS_PUNPCKHBW;
            else if (op2 == 0x69) out->opcode = HB_INS_PUNPCKHWD;
            else if (op2 == 0x6A) out->opcode = HB_INS_PUNPCKHDQ;
            else out->opcode = HB_INS_PUNPCKHQDQ;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        if (op2 == 0x10 || op2 == 0x11 || op2 == 0x28 || op2 == 0x29 ||
            op2 == 0x6F || op2 == 0x7F) {
            /* Packed 128-bit XMM moves: MOVUPS/MOVAPS/MOVDQA/MOVDQU. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_SSE_MOV;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2,
                                        (op2 == 0x11 || op2 == 0x29 || op2 == 0x7F));
            if (r != HB_OK) return r;
            mark_xmm_operands(out);
            return HB_OK;
        }
        if (op2 == 0x51) {
            /* SQRTPS/SQRTPD/SQRTSS/SQRTSD xmm, xmm/mem. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            size_t mem_size = 16;
            if (prefix_f2) { out->opcode = HB_INS_SQRTSD; mem_size = 8; }
            else if (prefix_f3) { out->opcode = HB_INS_SQRTSS; mem_size = 4; }
            else if (operand16) out->opcode = HB_INS_SQRTPD;
            else out->opcode = HB_INS_SQRTPS;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, mem_size, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = mem_size;
            return HB_OK;
        }
        if ((op2 == 0x52 || op2 == 0x53) && !operand16 && !prefix_f2) {
            /* RSQRTPS/RSQRTSS/RCPPS/RCPSS xmm, xmm/mem. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            size_t mem_size = prefix_f3 ? 4 : 16;
            if (op2 == 0x52) out->opcode = prefix_f3 ? HB_INS_RSQRTSS : HB_INS_RSQRTPS;
            else out->opcode = prefix_f3 ? HB_INS_RCPSS : HB_INS_RCPPS;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, mem_size, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            if (out->op2.is_mem) out->op2.size = mem_size;
            return HB_OK;
        }
        if ((!operand16 && op2 >= 0x54 && op2 <= 0x57) ||
            (operand16 && op2 >= 0x54 && op2 <= 0x57) ||
            (operand16 && (op2 == 0xDB || op2 == 0xDF || op2 == 0xEB || op2 == 0xEF))) {
            /* Packed XMM bitwise logical family: AND/ANDN/OR/XOR, PS/PD and integer forms. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0x54 || op2 == 0xDB) out->opcode = HB_INS_XMM_AND;
            else if (op2 == 0x55 || op2 == 0xDF) out->opcode = HB_INS_XMM_ANDN;
            else if (op2 == 0x56 || op2 == 0xEB) out->opcode = HB_INS_XMM_OR;
            else out->opcode = (operand16 && op2 == 0xEF) ? HB_INS_PXOR : HB_INS_XORPS;
            out->writes_flags = false;
            hb_result_t r = parse_modrm(d, modrm, 16, out, 1, 2, false);
            if (r != HB_OK) return r;
            mark_xmm_operand(out, 1);
            mark_xmm_operand(out, 2);
            return HB_OK;
        }
        d->pos = saved_pos;
    }

    /* Per Intel SDM Vol 2: when the form is register-only (ModRM.mod == 3), the
     * 0x67 address-size override prefix is silently ignored. We also let 0x67
     * through to the dispatcher for the shift/rotate groups (C0/C1/D0-D3)
     * since the modrm parser will produce the correct base/index/width even
     * with 16-bit addressing. Other 0x67 forms in 32-bit mode are still
     * rejected. */
    bool suppress_addr16 = false;
    if (address16 && can_read(d, 1)) {
        uint8_t peek = d->code[d->pos];
        if ((peek >> 6) == 3) suppress_addr16 = true;
    }
    /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 281 — 0x67 У КОМАНД БЕЗ ОБРАЩЕНИЯ К ПАМЯТИ.
     * Проверка выше подглядывает байт ModRM, но у целого класса команд его НЕТ: `PUSH/POP reg`,
     * `INC/DEC reg`, `XCHG eAX,reg`, `MOV reg,imm`, `Jcc`, `CALL/JMP rel`, флаговые. Для них
     * подглядывался случайный следующий байт, и `67 54` (`push esp`) отвергалось как
     * неподдержанное, хотя префикс размера адреса тут не значит ничего — обращения к памяти нет.
     * Нашла сверка с Unicorn: случай `67 65 54` числился «не исполнился у нас». */
    /* Итерация 283: формы с ModRM и памятью теперь разбираются как 16-битная адресация,
     * поэтому отвергать их больше не нужно. */
    if (address16 && !suppress_addr16) {
        if (can_read(d, 1) && (d->code[d->pos] >> 6) != 3) suppress_addr16 = true;
        else if ((opcode >= 0x40 && opcode <= 0x5F) ||      /* INC/DEC/PUSH/POP reg */
            (opcode >= 0x90 && opcode <= 0x97) ||      /* NOP, XCHG eAX,reg    */
            opcode == 0x98 || opcode == 0x99 ||        /* CWDE, CDQ            */
            opcode == 0x9C || opcode == 0x9D ||        /* PUSHF, POPF          */
            (opcode >= 0xB0 && opcode <= 0xBF) ||      /* MOV reg, imm         */
            (opcode >= 0x70 && opcode <= 0x7F) ||      /* Jcc rel8             */
            opcode == 0x68 || opcode == 0x6A ||        /* PUSH imm             */
            opcode == 0xC2 || opcode == 0xC3 ||        /* RET                  */
            opcode == 0xCC || opcode == 0xF5 ||        /* INT3, CMC            */
            (opcode >= 0xF8 && opcode <= 0xFD) ||      /* CLC/STC/CLI/STI/CLD/STD */
            opcode == 0xE8 || opcode == 0xE9 || opcode == 0xEB ||
            /* Итерация 282: АККУМУЛЯТОРНЫЕ ФОРМЫ. `ADD/OR/ADC/SBB/AND/SUB/XOR/CMP AL|eAX, imm`
             * — это опкоды вида 0x04/0x05, 0x0C/0x0D … 0x3C/0x3D: ModRM у них тоже НЕТ, память
             * не адресуется, значит `0x67` для них ничего не значит. В правке 281 я перечислил
             * только регистровые и переходы и пропустил эту группу — 18 случаев корпуса.
             * Плюс `TEST AL|eAX, imm` (0xA8/0xA9) той же природы. */
            (opcode <= 0x3D && ((opcode & 7) == 4 || (opcode & 7) == 5)) ||
            opcode == 0xA8 || opcode == 0xA9) {
            suppress_addr16 = true;
        }
    }
    if ((operand16 && !((opcode <= 0x3D) && ((opcode & 7) <= 5)) &&
          !(opcode >= 0x50 && opcode <= 0x5F) &&
          !(opcode >= 0x70 && opcode <= 0x7F) &&
          !(opcode >= 0x88 && opcode <= 0x8B) && opcode != 0x8D &&
          opcode != 0x0F &&
          !(opcode >= 0xA0 && opcode <= 0xA3) && !(opcode >= 0xB0 && opcode <= 0xBF) &&
          !(opcode >= 0x40 && opcode <= 0x4F) &&
          opcode != 0x68 && opcode != 0x6A &&
          opcode != 0x8F && opcode != 0xC2 && opcode != 0xC3 &&
          opcode != 0x9C && opcode != 0x9D && opcode != 0x9E && opcode != 0x9F &&
          opcode != 0x80 && opcode != 0x81 && opcode != 0x82 && opcode != 0x83 &&
          opcode != 0x84 && opcode != 0x85 && opcode != 0xA8 && opcode != 0xA9 &&
          opcode != 0xF6 && opcode != 0xF7 &&
          opcode != 0x69 && opcode != 0x6B &&
          opcode != 0xC0 && opcode != 0xC1 &&
          opcode != 0xFE && opcode != 0xFF &&
          !(opcode >= 0xD0 && opcode <= 0xD3) &&
          opcode != 0xD6 && opcode != 0xD7 &&
          opcode != 0xC6 && opcode != 0xC7 && opcode != 0xC9 &&
          !(opcode >= 0xE0 && opcode <= 0xE3) &&
          opcode != 0xE8 && opcode != 0xE9 && opcode != 0xEB &&
          !(opcode >= 0xD8 && opcode <= 0xDF) &&
          !(opcode >= 0x6C && opcode <= 0x6F)) ||
        (address16 && !suppress_addr16 &&
                       opcode != 0xC0 && opcode != 0xC1 &&
                       !(opcode >= 0xD0 && opcode <= 0xD3) &&
                       /* Итерация 916: `moffs` (A0-A3) теперь разбирается с 2-байтовым
                        * смещением, а у `leave` (C9) префикс `67` вовсе ни на что не влияет —
                        * исполнение эталона даёт 2 съеденных байта, то есть просто префикс
                        * плюс опкод. Обе формы из отказа изъяты. */
                       !(opcode >= 0xA0 && opcode <= 0xA3) && opcode != 0xC9 &&
                       opcode != 0x0F) ||
        /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 284 — F2/F3 ПЕРЕД ДВУХБАЙТОВЫМИ.
         * Отказ ловил `opcode == 0x0F`, то есть ВСЕ двухбайтовые команды с этими префиксами:
         * `movzx`, `movsx`, `bswap`, `shld`, `shrd`, `bt/bts/btr/btc`, `imul` — 118 случаев
         * корпуса. Формы, где префикс ЧАСТЬ кодировки (`F3 0F 10` MOVSS, `F2 0F 10` MOVSD,
         * `F3 0F B8` POPCNT и прочие SSE), разбираются РАНЬШЕ этой проверки и сюда не доходят —
         * проверено зондом. Значит всё, что дошло, это команда, для которой префикс не значим,
         * и настоящий процессор его игнорирует. Пропускаем. */
        (prefix_f2 && opcode != 0x90 && opcode != 0xC3 && opcode != 0xC2 && opcode != 0x0F &&
                     !(opcode >= 0x6C && opcode <= 0x6F)) ||
        (prefix_f3 && opcode != 0x90 && opcode != 0xC3 && opcode != 0xC2 && opcode != 0x0F &&
                     !(opcode >= 0x6C && opcode <= 0x6F))) {
        return HB_ERR_UNSUPPORTED_OPCODE;
    }

    if (opcode >= 0xd8 && opcode <= 0xdf) {
        return decode_x87(d, opcode, out);
    }

    if (opcode == 0x04 || opcode == 0x05 || opcode == 0x0C || opcode == 0x0D ||
        opcode == 0x14 || opcode == 0x15 || opcode == 0x1C || opcode == 0x1D ||
        opcode == 0x24 || opcode == 0x25 || opcode == 0x2C || opcode == 0x2D ||
        opcode == 0x34 || opcode == 0x35 || opcode == 0x3C || opcode == 0x3D) {
        switch (opcode & 0x3c) {
            case 0x04: out->opcode = HB_INS_ADD; break;
            case 0x0c: out->opcode = HB_INS_OR;  break;
            case 0x14: out->opcode = HB_INS_ADC; break;
            case 0x1c: out->opcode = HB_INS_SBB; break;
            case 0x24: out->opcode = HB_INS_AND; break;
            case 0x2c: out->opcode = HB_INS_SUB; break;
            case 0x34: out->opcode = HB_INS_XOR; break;
            case 0x3c: out->opcode = HB_INS_CMP; break;
        }
        uint8_t size = (opcode & 1) ? (operand16 ? 2 : 4) : 1;
        out->writes_flags = true;
        if (!can_read(d, size)) return HB_ERR_DECODE_FAILED;
        set_reg(out, 1, 0, size);
        set_imm(out, 2, size == 1 ? read_s8(d) : size == 2 ? read_s16(d) : (int64_t)read_s32(d), size);
        return HB_OK;
    }

    /* Group: MOV */
    if (opcode == 0x88) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_MOV;
        out->writes_flags = false;
        return parse_modrm(d, modrm, 1, out, 1, 2, true);
    }
    if (opcode == 0x89) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_MOV;
        out->writes_flags = false;
        return parse_modrm(d, modrm, operand16 ? 2 : 4, out, 1, 2, true);
    }
    if (opcode == 0x8A) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_MOV;
        out->writes_flags = false;
        return parse_modrm(d, modrm, 1, out, 1, 2, false);
    }
    if (opcode == 0x8B) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_MOV;
        out->writes_flags = false;
        return parse_modrm(d, modrm, operand16 ? 2 : 4, out, 1, 2, false);
    }
    if (opcode == 0x8D) {
        /* LEA r16/32, m */
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_LEA;
        out->writes_flags = false;
        return parse_modrm(d, modrm, operand16 ? 2 : 4, out, 1, 2, false);
    }
    if (opcode >= 0xB0 && opcode <= 0xB7) {
        /* MOV r8, imm8 */
        uint8_t reg_offset = 0;
        int reg = reg8_idx(opcode & 7, &reg_offset);
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        int8_t imm = read_s8(d);
        out->opcode = HB_INS_MOV;
        out->writes_flags = false;
        set_reg_ex(out, 1, reg, 1, reg_offset);
        set_imm(out, 2, imm, 1);
        return HB_OK;
    }
    if (opcode >= 0xB8 && opcode <= 0xBF) {
        /* MOV r16/32, imm16/32 */
        int reg = opcode & 7;
        uint8_t sz = operand16 ? 2 : 4;
        if (!can_read(d, sz)) return HB_ERR_DECODE_FAILED;
        out->opcode = HB_INS_MOV;
        out->writes_flags = false;
        set_reg(out, 1, reg, sz);
        set_imm(out, 2, sz == 2 ? (int64_t)read_s16(d) : (int64_t)read_s32(d), sz);
        return HB_OK;
    }
    if (opcode >= 0xA0 && opcode <= 0xA3) {
        /* MOV AL/EAX <-> moffs. In x86 this is an absolute 32-bit offset;
           segment prefixes still apply, e.g. FS:A1 for TEB loads. */
        uint8_t sz = (opcode == 0xA0 || opcode == 0xA2) ? 1 : (operand16 ? 2 : 4);
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 916 — ШИРИНА СМЕЩЕНИЯ У moffs.
         * Смещение здесь следует за размером АДРЕСА (префикс `67`), а не операнда: при
         * `67` это два байта, без него четыре — так в спецификации, и так его читает эталон
         * (полный перебор: 36 строк расхождения длины, `67 a0 c0 7f` — эталон 4, мы 6).
         * Прежний код читал четыре байта всегда, поэтому под `67` съедал два лишних. */
        uint32_t moffs;
        if (address16) {
            if (!can_read(d, 2)) return HB_ERR_DECODE_FAILED;
            moffs = (uint16_t)read_s16(d);
        } else {
            if (!can_read(d, 4)) return HB_ERR_DECODE_FAILED;
            moffs = (uint32_t)read_s32(d);
        }
        out->opcode = HB_INS_MOV;
        out->writes_flags = false;
        if (opcode == 0xA0 || opcode == 0xA1) {
            set_reg(out, 1, HB_REG_RAX, sz);
            set_mem(out, 2, -1, -1, 1, moffs, sz);
        } else {
            set_mem(out, 1, -1, -1, 1, moffs, sz);
            set_reg(out, 2, HB_REG_RAX, sz);
        }
        return HB_OK;
    }
    /* XABORT imm8 (C6 F8 ib) и XBEGIN rel16/32 (C7 F8 iw/id) — транзакционная память.
     * Байт F8 стоит НА МЕСТЕ modrm, но modrm-ом не является: у групп C6/C7
     * поле reg служит расширением кода, и значение 0xF8 (reg=7, mod=11) для
     * них выделено под эти две команды. Разбирались как обычная группа и
     * оттого отвергались. Вскрыто починенным прибором 04.09.2026.
     * ★ 05.09.2026 — общий текст с ветвью x64 (hb_decode_tsx_obshchee.inc): здесь
     * ширина смещения под 66 была верна, у копии x64 — нет; текст теперь один. */
    {
        hb_result_t itog_tsx;
        if (hb_tsx_gruppa11(d, opcode, operand16, out, &itog_tsx)) return itog_tsx;
    }
    if (opcode == 0xC6) {
        /* MOV r/m8, imm8 */
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        if (((modrm >> 3) & 7) != 0) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_MOV;
        out->writes_flags = false;
        hb_result_t r = parse_modrm_ext(d, modrm, 1, out, 1);
        if (r != HB_OK) return r;
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        set_imm(out, 2, read_s8(d), 1);
        return HB_OK;
    }
    if (opcode == 0xC7) {
        /* MOV r/m16/32, imm16/32 */
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        if (((modrm >> 3) & 7) != 0) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_MOV;
        out->writes_flags = false;
        uint8_t sz = operand16 ? 2 : 4;
        hb_result_t r = parse_modrm_ext(d, modrm, sz, out, 1);
        if (r != HB_OK) return r;
        if (!can_read(d, sz)) return HB_ERR_DECODE_FAILED;
        set_imm(out, 2, sz == 2 ? (int64_t)read_s16(d) : (int64_t)read_s32(d), sz);
        return HB_OK;
    }

    /* Group: 0x80/0x81/0x83 immediate group. Operand-size prefix selects
       r/m16 for 0x81/0x83; 0x80 remains byte-sized. */
    if (opcode == 0x80 || opcode == 0x81 || opcode == 0x82 || opcode == 0x83) {
            /* MacRunner 2026-08-28 — 0x82 это устаревший псевдоним 0x80.
             * В 32-битном режиме он ЗАКОНЕН и ведёт себя ровно как 0x80 (операнд
             * байтовый, непосредственное — байт); недопустим он только в 64-битном.
             * Сплошной перебор против capstone показал его как дыру сразу для
             * восьми мнемоник — add/or/adc/sbb/and/sub/xor/cmp разом, потому что
             * вид задаёт поле reg модрм. Старые сборки (эпоха Diablo) его
             * выпускали. */
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        uint8_t ext = (modrm >> 3) & 7;
        uint8_t sz = (opcode == 0x80 || opcode == 0x82) ? 1 : (operand16 ? 2 : 4);

        if (ext == 0) out->opcode = HB_INS_ADD;
        else if (ext == 1) out->opcode = HB_INS_OR;
        else if (ext == 2) out->opcode = HB_INS_ADC;
        else if (ext == 3) out->opcode = HB_INS_SBB;
        else if (ext == 4) out->opcode = HB_INS_AND;
        else if (ext == 5) out->opcode = HB_INS_SUB;
        else if (ext == 6) out->opcode = HB_INS_XOR;
        else if (ext == 7) out->opcode = HB_INS_CMP;
        out->writes_flags = true;

        hb_result_t r = parse_modrm_ext(d, modrm, sz, out, 1);
        if (r != HB_OK) return r;

        if (opcode == 0x80 || opcode == 0x82) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 2, read_s8(d), 1);
        } else if (opcode == 0x81) {
            if (!can_read(d, sz)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 2, sz == 2 ? (int64_t)read_s16(d) : (int64_t)read_s32(d), sz);
        } else { /* 0x83 */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 2, (int64_t)read_s8(d), sz);
        }
        return HB_OK;
    }

    if (opcode == 0x69 || opcode == 0x6B) {
        /* IMUL r16/32, r/m16/32, imm16/32/8. Mirrors the x64 69/6B path. */
        uint8_t sz = operand16 ? 2 : 4;
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_IMUL;
        out->writes_flags = true;
        hb_result_t r = parse_modrm(d, modrm, sz, out, 1, 2, false);
        if (r != HB_OK) return r;
        if (opcode == 0x69) {
            if (!can_read(d, sz)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 3, sz == 2 ? (int64_t)read_s16(d) : (int64_t)read_s32(d), sz);
        } else {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 3, (int64_t)read_s8(d), sz);
        }
        return HB_OK;
    }

    if (opcode <= 0x3B && ((opcode & 7) <= 3)) {
        int ins;
        uint8_t modrm, size;
        switch (opcode & 0x38) {
            case 0x00: ins = HB_INS_ADD; break;
            case 0x08: ins = HB_INS_OR;  break;
            case 0x10: ins = HB_INS_ADC; break;
            case 0x18: ins = HB_INS_SBB; break;
            case 0x20: ins = HB_INS_AND; break;
            case 0x28: ins = HB_INS_SUB; break;
            case 0x30: ins = HB_INS_XOR; break;
            case 0x38: ins = HB_INS_CMP; break;
            default: return HB_ERR_UNSUPPORTED_OPCODE;
        }
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        modrm = read_u8(d);
        size = (opcode & 1) ? (operand16 ? 2 : 4) : 1;
        out->opcode = ins;
        out->writes_flags = true;
        return parse_modrm(d, modrm, size, out, 1, 2, (opcode & 2) == 0);
    }

    /* Group: ADD */
    if (opcode == 0x00) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_ADD; out->writes_flags = true;
        return parse_modrm(d, modrm, 1, out, 1, 2, true);
    }
    if (opcode == 0x01) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_ADD; out->writes_flags = true;
        return parse_modrm(d, modrm, 4, out, 1, 2, true);
    }
    if (opcode == 0x02) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_ADD; out->writes_flags = true;
        return parse_modrm(d, modrm, 1, out, 1, 2, false);
    }
    if (opcode == 0x03) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_ADD; out->writes_flags = true;
        return parse_modrm(d, modrm, 4, out, 1, 2, false);
    }
    if (opcode == 0x04) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        out->opcode = HB_INS_ADD; out->writes_flags = true;
        set_reg(out, 1, 0, 1);
        set_imm(out, 2, read_s8(d), 1);
        return HB_OK;
    }
    if (opcode == 0x05) {
        out->opcode = HB_INS_ADD; out->writes_flags = true;
        if (!can_read(d, 4)) return HB_ERR_DECODE_FAILED;
        set_reg(out, 1, 0, 4);
        set_imm(out, 2, (int64_t)read_s32(d), 4);
        return HB_OK;
    }

    /* Group: SUB */
    if (opcode == 0x28) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_SUB; out->writes_flags = true;
        return parse_modrm(d, modrm, 1, out, 1, 2, true);
    }
    if (opcode == 0x29) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_SUB; out->writes_flags = true;
        return parse_modrm(d, modrm, 4, out, 1, 2, true);
    }
    if (opcode == 0x2A) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_SUB; out->writes_flags = true;
        return parse_modrm(d, modrm, 1, out, 1, 2, false);
    }
    if (opcode == 0x2B) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_SUB; out->writes_flags = true;
        return parse_modrm(d, modrm, 4, out, 1, 2, false);
    }
    if (opcode == 0x2C) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        out->opcode = HB_INS_SUB; out->writes_flags = true;
        set_reg(out, 1, 0, 1);
        set_imm(out, 2, read_s8(d), 1);
        return HB_OK;
    }
    if (opcode == 0x2D) {
        out->opcode = HB_INS_SUB; out->writes_flags = true;
        if (!can_read(d, 4)) return HB_ERR_DECODE_FAILED;
        set_reg(out, 1, 0, 4);
        set_imm(out, 2, (int64_t)read_s32(d), 4);
        return HB_OK;
    }

    /* Group: CMP */
    if (opcode == 0x38) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_CMP; out->writes_flags = true;
        return parse_modrm(d, modrm, 1, out, 1, 2, true);
    }
    if (opcode == 0x39) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_CMP; out->writes_flags = true;
        return parse_modrm(d, modrm, 4, out, 1, 2, true);
    }
    if (opcode == 0x3A) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_CMP; out->writes_flags = true;
        return parse_modrm(d, modrm, 1, out, 1, 2, false);
    }
    if (opcode == 0x3B) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_CMP; out->writes_flags = true;
        return parse_modrm(d, modrm, 4, out, 1, 2, false);
    }
    if (opcode == 0x3C) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        out->opcode = HB_INS_CMP; out->writes_flags = true;
        set_reg(out, 1, 0, 1);
        set_imm(out, 2, read_s8(d), 1);
        return HB_OK;
    }
    if (opcode == 0x3D) {
        out->opcode = HB_INS_CMP; out->writes_flags = true;
        if (!can_read(d, 4)) return HB_ERR_DECODE_FAILED;
        set_reg(out, 1, 0, 4);
        set_imm(out, 2, (int64_t)read_s32(d), 4);
        return HB_OK;
    }

    /* Group: PUSH / POP */
    if (opcode >= 0x50 && opcode <= 0x57) {
        out->opcode = HB_INS_PUSH;
        out->stack_delta = -(int)(operand16 ? 2 : 4);
        set_reg(out, 1, opcode & 7, operand16 ? 2 : 4);
        return HB_OK;
    }
    if (opcode >= 0x58 && opcode <= 0x5F) {
        out->opcode = HB_INS_POP;
        out->stack_delta = operand16 ? 2 : 4;
        set_reg(out, 1, opcode & 7, operand16 ? 2 : 4);
        return HB_OK;
    }
    if (opcode == 0x8F) {
        /* POP r/m32. Used by i386 ntdll SEH restore paths such as
           "pop dword ptr fs:[0]". */
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        if (((modrm >> 3) & 7) != 0) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_POP;
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 925 — ФОРМА `8F /0` ПОД `66`.
         * Ширина была зашита четвёркой. Регистровая форма `58+r` починена в 910, а эта —
         * нет; замер: `668fc0 pop ax` — эталон esp +2 и в eax пишутся только младшие 16 бит
         * (0x70005e00), мы снимали 4 байта и писали весь регистр (0x5ad35e00). */
        out->stack_delta = operand16 ? 2 : 4;
        return parse_modrm_ext(d, modrm, operand16 ? 2 : 4, out, 1);
    }
    if (opcode == 0x68) {
        out->opcode = HB_INS_PUSH;
        out->stack_delta = -(int)(operand16 ? 2 : 4);
        /* Итерация 910: защита требовала ЧЕТЫРЕ доступных байта и для 2-байтовой формы, из-за
         * чего `66 68 imm16` в конце буфера (или страницы) не декодировался вовсе — замер:
         * `6668ff00` не исполнился, eip не сдвинулся. Спрашиваем ровно столько, сколько читаем. */
        if (operand16) {
            if (!can_read(d, 2)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 1, (int64_t)read_s16(d), 2);
        } else {
            if (!can_read(d, 4)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 1, (int64_t)read_s32(d), 4);
        }
        return HB_OK;
    }
    if (opcode == 0x6A) {
        out->opcode = HB_INS_PUSH;
        out->stack_delta = -(int)(operand16 ? 2 : 4);
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        int8_t v = read_s8(d);
        set_imm(out, 1, v, operand16 ? 2 : 4);
        return HB_OK;
    }

    /* Group: INC reg (0x40-0x47) -- in x86 these are real INC, not REX */
    if (opcode >= 0x40 && opcode <= 0x47) {
        out->opcode = HB_INS_INC;
        out->writes_flags = true;
        set_reg(out, 1, opcode & 7, operand16 ? 2 : 4);
        return HB_OK;
    }
    /* Group: DEC reg (0x48-0x4F) -- in x86 these are real DEC, not REX */
    if (opcode >= 0x48 && opcode <= 0x4F) {
        out->opcode = HB_INS_DEC;
        out->writes_flags = true;
        set_reg(out, 1, opcode & 7, operand16 ? 2 : 4);
        return HB_OK;
    }

    /* Group: JMP */
    if (opcode == 0xEB) {
        out->opcode = HB_INS_JMP;
        out->is_branch = true;
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        int8_t rel = read_s8(d);
        out->branch_target = hb_x86_near_target(addr + d->pos + rel, operand16);
        return HB_OK;
    }
    if (opcode == 0xE9) {
        out->opcode = HB_INS_JMP;
        out->is_branch = true;
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 912 — СМЕЩЕНИЕ 16 БИТ (префикс 66).
         * Смещение читалось четырьмя байтами независимо от префикса, поэтому `66 e9 cw` не
         * декодировался вовсе (буфера в 2 байта не хватало под can_read(4)) — тот же класс,
         * что `push imm16` в 910. Маскирование цели через `operand16` тут уже было, то есть
         * про 16-битную форму знали, а ширину смещения пропустили.
         * Найдено сплошным перебором по префиксам (входящее 109, пункт 1). */
        if (operand16) {
            if (!can_read(d, 2)) return HB_ERR_DECODE_FAILED;
            int16_t rel16 = read_s16(d);
            out->branch_target = hb_x86_near_target(addr + d->pos + rel16, operand16);
            return HB_OK;
        }
        if (!can_read(d, 4)) return HB_ERR_DECODE_FAILED;
        int32_t rel = read_s32(d);
        out->branch_target = hb_x86_near_target(addr + d->pos + rel, operand16);
        return HB_OK;
    }
    if (opcode >= 0xE0 && opcode <= 0xE3) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        int8_t rel = read_s8(d);
        /* 0xE3 is LOOPNE in 64-bit mode but JECXZ/JCXZ in 32-bit. For
         * i386-only decode we use HB_INS_JRCXZ; the lift/interpret key off
         * op1.size (4 = ECX in 32-bit, 2 = CX in 16-bit). */
        out->opcode = opcode == 0xE3 ? HB_INS_JRCXZ : HB_INS_LOOP;
        out->is_branch = true;
        out->is_conditional = true;
        out->branch_target = hb_x86_near_target(addr + d->pos + rel, operand16);
        out->reads_flags = opcode == 0xE0 || opcode == 0xE1;
        set_reg(out, 1, HB_REG_RCX, address16 ? 2 : 4);
        set_imm(out, 2, opcode - 0xE0, 1);
        return HB_OK;
    }

    /* Group: CALL */
    if (opcode == 0xE8) {
        out->opcode = HB_INS_CALL;
        out->is_call = true;
        /* MacRunner 2026-08-15, итерация 913 — ПОПРАВКА К СВОЕМУ ЖЕ РЕШЕНИЮ 912.
         * В 912 я оставил `66 E8` недекодируемым, решив, что чистый отказ лучше неверного
         * стека. Полный перебор (входящее 110) показал, что решение было принято по
         * АРТЕФАКТУ: отказ случался только на коротком буфере. При хвосте — а в настоящем
         * потоке команд хвост есть всегда — мы команду ДЕКОДИРОВАЛИ, длиной 6 вместо 4, то
         * есть съедали два лишних байта и пускали блок под откос. Неверная длина хуже
         * неверного стека: она рассыпает ВСЁ, что идёт следом.
         * Читаем два байта. Остаток (на стек кладётся 4 байта вместо 2, признака размера в
         * `hb_ir_instr_t` нет) назван в сводке и закрывается отдельно. */
        if (operand16) {
            if (!can_read(d, 2)) return HB_ERR_DECODE_FAILED;
            int16_t rel16 = read_s16(d);
            out->stack_delta = -2;
            out->branch_target = hb_x86_near_target(addr + d->pos + rel16, operand16);
            return HB_OK;
        }
        out->stack_delta = -4;
        if (!can_read(d, 4)) return HB_ERR_DECODE_FAILED;
        int32_t rel = read_s32(d);
        out->branch_target = hb_x86_near_target(addr + d->pos + rel, operand16);
        return HB_OK;
    }

    /* Group: RET */
    if (opcode == 0xC3) {
        out->opcode = HB_INS_RET;
        out->is_ret = true;
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 915 — ШИРИНА ВОЗВРАТА.
         * Под префиксом `66` возврат снимает со стека ДВА байта и берёт 16-битный адрес.
         * Замер эталона (914): `66 c3` — esp +2 и eip=0x5e00, у нас было +4 и полный адрес.
         * Ширина едет отсюда через `stack_delta` и дальше пометкой в IR. */
        out->stack_delta = operand16 ? 2 : 4;
        return HB_OK;
    }
    if (opcode == 0xC2) {
        out->opcode = HB_INS_RET;
        out->is_ret = true;
        out->stack_delta = operand16 ? 2 : 4;
        if (!can_read(d, 2)) return HB_ERR_DECODE_FAILED;
        uint16_t imm = (uint16_t)(read_u8(d) | (read_u8(d) << 8));
        out->ret_imm = imm;
        return HB_OK;
    }
    if (opcode == 0xC9) {
        if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
        out->opcode = HB_INS_LEAVE;
        out->writes_flags = false;
        out->stack_delta = operand16 ? 2 : 4;
        set_reg(out, 1, HB_REG_RBP, operand16 ? 2 : 4);
        return HB_OK;
    }

    /* Group: Jcc short */
    if (opcode >= 0x70 && opcode <= 0x7F) {
        out->opcode = HB_INS_Jcc;
        out->is_branch = true;
        out->is_conditional = true;
        out->cond = cond_from_cc(opcode & 0x0F);
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        int8_t rel = read_s8(d);
        out->branch_target = hb_x86_near_target(addr + d->pos + rel, operand16);
        out->reads_flags = true;
        return HB_OK;
    }

    /* Two-byte opcode: 0x0F ... */
    if (opcode == 0x0F) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t op2 = read_u8(d);
        /* Jcc near */
        if (op2 >= 0x80 && op2 <= 0x8F) {
            out->opcode = HB_INS_Jcc;
            out->is_branch = true;
            out->is_conditional = true;
            out->cond = cond_from_cc(op2 & 0x0F);
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 913 — ДЛИНА Jcc rel16.
             * Смещение читалось четырьмя байтами независимо от префикса `66`, поэтому
             * `66 0F 8x cw` получал длину 7 вместо 5 — в настоящем потоке команд мы съели бы
             * ДВА ЛИШНИХ БАЙТА и пустили блок под откос. Самая крупная семья расхождений
             * длины у полного перебора: 96 строк из 200 на этой ветви (входящее 110).
             * Маскирование цели через `operand16` тут уже стояло — знали про 16-битную форму
             * и пропустили ширину смещения; тот же класс, что `push imm16` (910) и
             * `jmp rel16` (912). */
            if (operand16) {
                if (!can_read(d, 2)) return HB_ERR_DECODE_FAILED;
                int16_t rel16 = read_s16(d);
                out->branch_target = hb_x86_near_target(addr + d->pos + rel16, operand16);
                out->reads_flags = true;
                return HB_OK;
            }
            if (!can_read(d, 4)) return HB_ERR_DECODE_FAILED;
            int32_t rel = read_s32(d);
            out->branch_target = hb_x86_near_target(addr + d->pos + rel, operand16);
            out->reads_flags = true;
            return HB_OK;
        }
        if (op2 == 0x00 || op2 == 0x01) {
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 937 — ГРУППЫ 6 И 7 ИСПОЛНЯЛИСЬ
             * КАК ПЕРЕСЫЛКА СЕГМЕНТА. Здесь стояло `out->opcode = HB_INS_MOV_SEG` с
             * комментарием «the runtime will #GP for the privileged ones». Такого места в
             * исполнителе НЕТ: `MOV_SEG` от групп 6/7 неотличим от обычного `8C`/`8E`, и
             * `lift` возвращал 0 — то есть команда не отказывала, а РАБОТАЛА, двигая сегмент.
             *
             * Замер пробником, регистровые формы, режим x86 против x64:
             *   `0f00d0 lldt ax`   x86: op=MOV_SEG lift=0   x64: op=SYS lift=-6
             *   `0f00d8 ltr  ax`   x86: op=MOV_SEG lift=0   x64: op=SYS lift=-6
             *   `0f01f0 lmsw ax`   x86: op=MOV_SEG lift=0   x64: op=SYS lift=-6
             *   `0f01d0 xgetbv`    x86: op=MOV_SEG lift=0   x64: op=XGETBV lift=0
             * Первые три обязаны дать отказ привилегии, четвёртая — вернуть XCR0 в EDX:EAX.
             * Ни того, ни другого на i386 не происходило: девять разных команд, включая
             * `verr`/`verw`/`smsw`/`monitor`/`swapgs`, выполняли ОДНО И ТО ЖЕ действие.
             *
             * Тот же класс, что `LAR`/`LSL` (итерация 921) и `far call/jmp`: приёмник тихо
             * переписывается вместо отказа. Лечим тем же способом, каким лечит x64, —
             * `HB_INS_SYS`, у которого нет случая в лифтере, поэтому исполнение честно даёт
             * `-6`, а ДЛИНА при этом сохраняется (отказ в декодере длину бы потерял).
             *
             * `XGETBV` переносим по-настоящему: исполнитель уже считает `hb_xcr0_value` с
             * учётом разрядности (в 32 битах 0x3 — только x87+SSE), так что реализация
             * бесплатна и строго лучше пересылки. Позвать его штатный гость не должен —
             * `hb_cpuid.h:105` снимает OSXSAVE в 32 битах, — но код, который зовёт XGETBV
             * безусловно, получит верное значение, а не мусор.
             * Найдено разбором столбца мнемоники полного перебора: `mov <- sldt` 12 строк,
             * `mov <- sgdt` 8, `mov <- enclv` 3. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0x01 && modrm == 0xD0) {
                out->opcode = HB_INS_XGETBV;
                return HB_OK;
            }
            /* ★ 05.09.2026 — XEND (D5) и XTEST (D6) ДО разбора группы 7 по членам: у них
             * reg=2, и они уходили в PRIV — отказ по привилегии на командах кольца 3.
             * Общий текст с ветвью x64 (hb_decode_tsx_obshchee.inc). */
            if (op2 == 0x01 && hb_tsx_0f01(modrm, out)) return HB_OK;
            if (op2 == 0x01 && modrm == 0xF9) {
                out->opcode = HB_INS_RDTSCP;   /* итерация 938, замер Prism: исполняется */
                return HB_OK;
            }
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 941 — ТЕ ЖЕ ЧЛЕНЫ, ЧТО НА x64.
             * Итерация 937 увела обе группы в общий отказ целиком — это было верно против
             * прежней молчащей пересылки, но грубо: замер под Prism в 32-битном госте дал
             * ровно те же числа, что в 64-битном (`sldt` 0x0000, `str` 0x0040,
             * `smsw` 0x80010031, отказов ноль). Разбираем по членам, значения измеренные. */
            {
                int gext = (modrm >> 3) & 7;
                bool greg = (modrm >> 6) == 3;
                uint8_t gsz = greg ? (uint8_t)(operand16 ? 2 : 4) : 2;
                if (op2 == 0x00 && (gext == 0 || gext == 1)) {
                    hb_result_t r;
                    out->opcode = HB_INS_MOV;
                    out->writes_flags = false;
                    r = parse_modrm_ext(d, modrm, gsz, out, 1);
                    if (r != HB_OK) return r;
                    set_imm(out, 2, gext == 0 ? 0 : 0x40, gsz);
                    return HB_OK;
                }
                /* Итерация 1080: `0F 01 /0`, `/1` — образ таблицы дескрипторов, 6 байт в
                 * 32-битном режиме (предел 2 + база 4). Законны в пользовательском режиме;
                 * прежний отказ убивал гостя (замер 1079 на ветви x64, здесь то же). */
                if (op2 == 0x01 && (gext == 0 || gext == 1) && (modrm >> 6) != 3) {
                    out->opcode = (gext == 0) ? HB_INS_SGDT : HB_INS_SIDT;
                    return parse_modrm_ext(d, modrm, 6, out, 1);
                }
                if (op2 == 0x01 && gext == 4) {
                    hb_result_t r;
                    out->opcode = HB_INS_MOV;
                    out->writes_flags = false;
                    r = parse_modrm_ext(d, modrm, gsz, out, 1);
                    if (r != HB_OK) return r;
                    set_imm(out, 2, gsz == 2 ? 0x0031 : 0x80010031, gsz);
                    return HB_OK;
                }
                if (op2 == 0x00 && (gext == 4 || gext == 5)) {
                    out->opcode = (gext == 4) ? HB_INS_VERR : HB_INS_VERW;
                    out->writes_flags = true;
                    return parse_modrm_ext(d, modrm, 2, out, 1);
                }
                if ((op2 == 0x00 && (gext == 2 || gext == 3)) ||
                    (op2 == 0x01 && (gext == 2 || gext == 3 || gext == 6 || gext == 7))) {
                    /* Итерация 1095: имена вместо общего ярлыка, отказ прежний. */
                    out->opcode = (op2 == 0x00) ? ((gext == 2) ? HB_INS_LLDT : HB_INS_LTR)
                               : (gext == 2) ? HB_INS_LGDT : (gext == 3) ? HB_INS_LIDT
                               : (gext == 6) ? HB_INS_LMSW : HB_INS_INVLPG;
                    out->opcode = HB_INS_PRIV;
                    out->writes_flags = false;
                    if (greg) return HB_OK;
                    return parse_modrm_ext(d, modrm, operand16 ? 2 : 4, out, 1);
                }
            }
            out->opcode = HB_INS_SYS;
            out->writes_flags = false;
            if ((modrm >> 6) == 3) return HB_OK;
            return parse_modrm_ext(d, modrm, operand16 ? 2 : 4, out, 1);
        }
        if (op2 == 0x02 || op2 == 0x03) {
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 921 — `LAR`/`LSL` РАЗБИРАЛИСЬ КАК
             * `MOV`, И ЭТО МОЛЧА ПОРТИЛО ПРИЁМНИК.
             *
             * `LAR` читает права доступа дескриптора сегмента, `LSL` — его предел; обе при
             * недоступном селекторе ОСТАВЛЯЮТ приёмник нетронутым и сбрасывают ZF. Мы же
             * поднимали их как обычную пересылку. Замер против эталона на этой ветви:
             *   `0f02c1 lar eax,ecx`  эталон: eax=0x70001000 (не тронут), ZF=0
             *                         мы:     eax=0x00000002 (скопирован ecx), ZF=1
             * То есть команда, которая НИЧЕГО не должна была записать, переписывала регистр.
             *
             * Таблиц дескрипторов у нас нет, и выдумывать ответ нельзя: «всякий селектор
             * недоступен» — такое же непроверенное утверждение, как и прежняя пересылка,
             * только тише. Поэтому отказываем ЧЕСТНО, как это уже делает ветвь x64 (там обе
             * попадают в `HB_INS_SYS` и дают `-5` при исполнении). Чистый отказ виден сразу;
             * если настоящая программа их позовёт, мы это увидим и реализуем ПО ЗАМЕРУ.
             * Найдено разбором столбца мнемоники: `mov -> lar` и `mov -> lsl`, 28 строк. */
            return HB_ERR_UNSUPPORTED_OPCODE;
        }
        if (op2 == 0x05) {
            /* SYSCALL — only valid in 64-bit mode. In 32-bit i386 this is #UD. */
            return HB_ERR_UNSUPPORTED_OPCODE;
        }
        if (op2 == 0x06) {
            /* CLTS — clear task-switched flag, privileged. */
            return HB_ERR_UNSUPPORTED_OPCODE;
        }
        if (op2 == 0xA0 || op2 == 0xA1 || op2 == 0xA8 || op2 == 0xA9) {
            /* PUSH/POP FS/GS (0F-escape form). Valid in 32-bit user mode; #UD in
             * 64-bit mode (we never get here in that mode anyway).
             *
             * ★ MacRunner 2026-08-28: F2/F3 здесь НЕ «illegal», а НЕЗНАЧИМЫ —
             * процессор их игнорирует, capstone разбирает `f2 0f a0` как обычный
             * `push fs`. Это ровно тот довод, что записан в итерации 284 выше про
             * F2/F3 перед двухбайтовыми: форма, где префикс часть кодировки,
             * разбирается раньше, а сюда доходит только незначимый. LOCK остаётся
             * недопустимым — он требует операнда в памяти. */
            if (prefix_f0) return HB_ERR_UNSUPPORTED_OPCODE;
            bool is_push = (op2 == 0xA0 || op2 == 0xA8);
            int seg = (op2 == 0xA0 || op2 == 0xA1) ? 4 /* FS */ : 5 /* GS */;
            out->opcode = is_push ? HB_INS_PUSH_SEG : HB_INS_POP_SEG;
            out->writes_flags = false;
            out->stack_delta = is_push ? (operand16 ? 2 : 4) : -(int)(operand16 ? 2 : 4);
            set_imm(out, 1, 0, operand16 ? 2 : 4);
            set_imm(out, 2, seg, 1);
            return HB_OK;
        }
        if (op2 == 0xA4 || op2 == 0xA5 || op2 == 0xAC || op2 == 0xAD) {
            /* SHLD/SHRD r/m16/32, r16/32, imm8/CL. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = (op2 == 0xA4 || op2 == 0xA5) ? HB_INS_SHLD : HB_INS_SHRD;
            out->writes_flags = true;
            hb_result_t r = parse_modrm(d, modrm, operand16 ? 2 : 4, out, 1, 2, true);
            if (r != HB_OK) return r;
            if (op2 == 0xA4 || op2 == 0xAC) {
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                set_imm(out, 3, read_u8(d), 1);
            } else {
                set_reg(out, 3, HB_REG_X86_ECX, 1);
            }
            return HB_OK;
        }
        if (op2 >= 0x90 && op2 <= 0x9F) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_SETcc;
            out->cond = cond_from_cc(op2 & 0x0F);
            out->reads_flags = true;
            hb_result_t r = parse_modrm_ext(d, modrm, 1, out, 1);
            if (r != HB_OK) return r;
            return HB_OK;
        }
        if (op2 >= 0x40 && op2 <= 0x4F) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_CMOVcc;
            out->cond = cond_from_cc(op2 & 0x0F);
            out->reads_flags = true;
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 908 — ПРЕФИКС 66 ИГНОРИРОВАЛСЯ.
             * Размер был зашит четвёркой, поэтому `cmovcc r16` считался 32-битным. На этой
             * ветви идёт ступень 1, и 16-битные формы для кода 1996 года не экзотика.
             * Дефект был НЕВИДИМ доске: расхождение операндов вычёркивает случай из
             * семантической выборки, поэтому поведение никто не сверял. */
            hb_result_t r = parse_modrm(d, modrm, operand16 ? 2 : 4, out, 1, 2, false);
            if (r != HB_OK) return r;
            return HB_OK;
        }
        if (op2 == 0xB0 || op2 == 0xB1 || op2 == 0xC0 || op2 == 0xC1) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = (op2 == 0xB0 || op2 == 0xB1) ? HB_INS_CMPXCHG : HB_INS_XADD;
            out->writes_flags = true;
            /* Итерация 908: 16-битная форма (префикс 66) — см. CMOVcc выше. */
            hb_result_t r = parse_modrm(d, modrm,
                                        (op2 == 0xB0 || op2 == 0xC0) ? 1 : (operand16 ? 2 : 4),
                                        out, 1, 2, true);
            if (r != HB_OK) return r;
            return HB_OK;
        }
        /* ═══ ПРОБЕЛЫ, ВСКРЫТЫЕ ПОЧИНЕННЫМ ПРИБОРОМ 04.09.2026 ═══
         *
         * Пока tests/x86_isa_coverage.py подавал ОДИН байт modrm (`c0`) на все
         * случаи, список пробелов печатался ПУСТЫМ: 6189 случаев и «всё
         * покрыто». После разведения хвостов — 29 241 случай и девять имён,
         * которые capstone берёт, а мы отвергали. Вот они. */
        if (op2 == 0xB2) {
            /* LSS r16/32, m16:32 — родня LFS/LGS (0F B4/B5), просто не дописана. */
            if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            {
                uint8_t modrm = read_u8(d);
                hb_result_t rr;
                if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
                out->opcode = HB_INS_LSS;
                out->writes_flags = false;
                rr = parse_modrm(d, modrm, 6, out, 1, 2, false);
                if (rr != HB_OK) return rr;
                out->op1.size = operand16 ? 2 : 4;
                return HB_OK;
            }
        }
        if (op2 == 0xC3 && !operand16 && !prefix_f2 && !prefix_f3) {
            /* MOVNTI m32, r32 — запись мимо кеша. Только память. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            {
                uint8_t modrm = read_u8(d);
                if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
                out->opcode = HB_INS_MOVNTI;
                out->writes_flags = false;
                return parse_modrm(d, modrm, operand16 ? 2 : 4, out, 2, 1, false);
            }
        }
        if (op2 == 0xE7 && !operand16 && !prefix_f2 && !prefix_f3) {
            /* MOVNTQ m64, mm — форма MMX. Под 0x66 это MOVNTDQ, она разбирается
             * раньше; сюда доходит только беспрефиксная. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            {
                uint8_t modrm = read_u8(d);
                if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
                out->opcode = HB_INS_MOVNTQ;
                out->writes_flags = false;
                return parse_modrm(d, modrm, 8, out, 2, 1, false);
            }
        }
        if (op2 == 0xF0 && prefix_f2) {
            /* LDDQU xmm, m128 — чтение без выравнивания. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            {
                uint8_t modrm = read_u8(d);
                if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
                out->opcode = HB_INS_LDDQU;
                out->writes_flags = false;
                return parse_modrm(d, modrm, 16, out, 1, 2, false);
            }
        }
        if (op2 == 0x0F) {
            /* 3DNow!: `0F 0F <modrm> <imm8>`, где ИМЕННО imm8 задаёт команду.
             * Семья снята AMD в 2010-м; разбираем её одним кодом, чтобы длина
             * была верной и поток не разъезжался — это важнее имени. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            {
                uint8_t modrm = read_u8(d);
                hb_result_t rr;
                out->opcode = HB_INS_TDNOW;
                out->writes_flags = false;
                rr = parse_modrm(d, modrm, 8, out, 1, 2, false);
                if (rr != HB_OK) return rr;
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                set_imm(out, 3, read_u8(d), 1);
                return HB_OK;
            }
        }
        if (op2 == 0xB4 || op2 == 0xB5) {
            /* LFS / LGS r16/32, m16:32. 0F B4=LFS, 0F B5=LGS. */
            if (prefix_f0 || prefix_f2 || prefix_f3) return HB_ERR_UNSUPPORTED_OPCODE;
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if ((modrm >> 6) == 3) return HB_ERR_UNSUPPORTED_OPCODE;
                    /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 926 — РАЗМЕР ПРИЁМНИКА У ЗАГРУЗКИ
         * ДАЛЬНЕГО УКАЗАТЕЛЯ. Форма `LxS r16/32, m16:32`: в РЕГИСТР идёт только смещение
         * (4 байта, под `66` — два), а шесть байт — это размер операнда в ПАМЯТИ. Мы ставили
         * шесть обоим. Проверено исполнением: `c40424 les eax,[esp]` кладёт в eax
         * 0x5ad35e00 — ровно то же, что контрольный `8b0424 mov eax,[esp]`, то есть смещение
         * читается верно и правится ОПИСАНИЕ. Эталон эти формы исполнять отказывается
         * (нужна настоящая таблица дескрипторов), поэтому сверка идёт по контрольной
         * пересылке. 20 строк столбца операндов. */
        out->opcode = (op2 == 0xB4) ? HB_INS_LFS : HB_INS_LGS;
            out->writes_flags = false;
            hb_result_t rr = parse_modrm(d, modrm, 6, out, 1, 2, false);
        if (rr != HB_OK) return rr;
        out->op1.size = operand16 ? 2 : 4;   /* итерация 926: в регистр идёт только смещение */
        return HB_OK;
        }
        if (op2 == 0xC7) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: партия 3 — у кода `0F C7` три жильца.
             * /1 с ПАМЯТЬЮ — CMPXCHG8B (было), /6 и /7 с РЕГИСТРОМ — RDRAND и RDSEED.
             * Две прежние попытки положить их в другие места оказались недостижимы
             * (путь LOCK и блок ниже по файлу): этот обработчик перехватывает C7 первым.
             * Замер показал обе промашки как decode=-5 — прибор сработал, догадка нет. */
            if ((modrm >> 6) == 3) {
                uint8_t ext = (uint8_t)((modrm >> 3) & 7);
                if (ext != 6 && ext != 7) return HB_ERR_UNSUPPORTED_OPCODE;
                out->opcode = (ext == 6) ? HB_INS_RDRAND : HB_INS_RDSEED;
                out->writes_flags = true;
                return parse_modrm_ext(d, modrm, operand16 ? 2 : 4, out, 1);
            }
            if (((modrm >> 3) & 7) != 1) return HB_ERR_UNSUPPORTED_OPCODE;
            out->opcode = HB_INS_CMPXCHG8B;
            out->writes_flags = true;
            hb_result_t r = parse_modrm_ext(d, modrm, 8, out, 1);
            if (r != HB_OK) return r;
            return HB_OK;
        }
        if (op2 == 0xBA) {
            /* Group 8: BT/BTS/BTR/BTC r/m16/32, imm8. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t ext = (modrm >> 3) & 7;
            if (ext == 4) out->opcode = HB_INS_BT;
            else if (ext == 5) out->opcode = HB_INS_BTS;
            else if (ext == 6) out->opcode = HB_INS_BTR;
            else if (ext == 7) out->opcode = HB_INS_BTC;
            else return HB_ERR_UNSUPPORTED_OPCODE;
            out->writes_flags = true;
            hb_result_t r = parse_modrm_ext(d, modrm, operand16 ? 2 : 4, out, 1);
            if (r != HB_OK) return r;
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            set_imm(out, 2, read_u8(d), 1);
            return HB_OK;
        }
        if (op2 == 0xAF) {
            /* IMUL r16/32, r/m16/32. Mirrors the x64 0F AF path. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = HB_INS_IMUL;
            out->writes_flags = true;
            hb_result_t r = parse_modrm(d, modrm, operand16 ? 2 : 4, out, 1, 2, false);
            if (r != HB_OK) return r;
            return HB_OK;
        }
        if (op2 == 0xA3 || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB) {
            /* BT/BTS/BTR/BTC r/m16/32, r16/32. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            if (op2 == 0xA3) out->opcode = HB_INS_BT;
            else if (op2 == 0xAB) out->opcode = HB_INS_BTS;
            else if (op2 == 0xB3) out->opcode = HB_INS_BTR;
            else out->opcode = HB_INS_BTC;
            out->writes_flags = true;
            hb_result_t r = parse_modrm(d, modrm, operand16 ? 2 : 4, out, 1, 2, true);
            if (r != HB_OK) return r;
            return HB_OK;
        }
        if (op2 == 0xBC || op2 == 0xBD) {
            /* BSF/BSR r16/32, r/m16/32. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            out->opcode = (op2 == 0xBC) ? HB_INS_BSF : HB_INS_BSR;
            out->writes_flags = true;
            hb_result_t r = parse_modrm(d, modrm, operand16 ? 2 : 4, out, 1, 2, false);
            if (r != HB_OK) return r;
            return HB_OK;
        }
        if (op2 >= 0xC8 && op2 <= 0xCF) {
            /* BSWAP: ширина СЛЕДУЕТ РАЗРЯДНОСТИ.
             *
             * История: 04.09.2026 я поставил верный размер, получил СЕМЬ
             * отказов исполнения и откатил — интерпретатор 16-битной формы не
             * знал. Теперь знает: поведение спрошено у оракула (при
             * eax=0x11223344 `bswap ax` даёт 0x11220000), реализовано, и
             * размер можно объявлять честно.
             *
             * Прежняя оговорка (оставлена для памяти): */
            /* BSWAP r32 — размер ВСЕГДА 4, и это ОСОЗНАННОЕ расхождение с
             * дизассемблером.
             *
             * ПРОБОВАЛ 04.09.2026 и ОТКАТИЛ. capstone под `66 0F C8` объявляет
             * операнд шириной 2 — это 8 расхождений на доске. Поставил 2 —
             * получил СЕМЬ НОВЫХ ОТКАЗОВ ИСПОЛНЕНИЯ (result=-5): 16-битной
             * формы исполнитель не знает, и правка перенесла беду с колонки
             * «расхождение» в колонку «не выполнили».
             *
             * По сути: поведение BSWAP с 16-битным операндом в спецификации
             * НЕ ОПРЕДЕЛЕНО, а железо меняет местами байты во ВСЕМ 32-битном
             * регистре. «Размер 2» — соглашение ОТОБРАЖЕНИЯ, годное для
             * дизассемблера; наш декодер кормит ИСПОЛНИТЕЛЬ, и ему нужна
             * ширина настоящего действия. Гнаться за числом на доске ценой
             * отказа исполнения — ровно то, чего делать нельзя. */
            out->opcode = HB_INS_BSWAP;
            out->writes_flags = false;
            set_reg(out, 1, op2 - 0xC8, operand16 ? 2 : 4);
            return HB_OK;
        }
        if (op2 == 0x20 || op2 == 0x21 || op2 == 0x22 || op2 == 0x23) {
            /* MOV r32, CRn/DRn (0F 20/21 read) and MOV CRn/DRn, r32 (0F 22/23 write).
             * Privileged in 32-bit user mode; runtime raises #GP. We decode as
             * MOV_CR/MOV_DR; the lift/codegen route the privileged form. */
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            bool write = (op2 == 0x22 || op2 == 0x23);
            out->opcode = (op2 == 0x20 || op2 == 0x22) ? HB_INS_MOV_CR : HB_INS_MOV_DR;
            out->writes_flags = false;
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 916 — ПОЛЕ mod ЗДЕСЬ ИГНОРИРУЕТСЯ.
             * У `MOV CRn/DRn` операнд ВСЕГДА регистр: процессор трактует `mod` как 11
             * независимо от его значения, поэтому ни SIB, ни смещения за модрм НЕТ.
             * Общий разбор модрм этого не знает и при `mod=00, rm=101` читал ещё четыре
             * байта смещения, при `rm=100` — байт SIB. Полный перебор: 24 строки расхождения
             * длины, последняя семья на этой ветви (`0f2005` — эталон 3, мы 7).
             * Разбираем сами: одна модрм и ничего больше. */
            set_reg(out, 1, (modrm >> 3) & 7, 4);   /* поле reg — номер CRn/DRn */
            set_reg(out, 2, modrm & 7, 4);          /* поле rm  — обычный регистр */
            hb_result_t r = HB_OK;
            if (r != HB_OK) return r;
            if (write) {
                /* For write form (0F 22/23), ModRM.reg = CRn/DRn index and
                 * ModRM.rm = r32. parse_modrm_ext gives r32 in op1, r/m in op2;
                 * but for write the source is r32 and the destination is the
                 * control register. Swap so dst = CRn/DRn, src = r32. */
                __typeof__(out->op1) saved = out->op1;
                out->op1 = out->op2;
                out->op2 = saved;
            }
            return HB_OK;
        }
        if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF) {
            if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
            uint8_t modrm = read_u8(d);
            uint8_t src_size = (op2 == 0xB6 || op2 == 0xBE) ? 1 : 2;
            out->opcode = (op2 == 0xB6 || op2 == 0xB7) ? HB_INS_MOVZX : HB_INS_MOVSX;
            out->writes_flags = false;
            /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 269 — ПРЕФИКС 66 У ПРИЁМНИКА.
             * Размер приёмника был зашит четвёркой, поэтому `66 0f b7 c0` (`movzx ax, ax`)
             * записывал ВЕСЬ регистр вместо младшей половины и затирал старшие 16 бит.
             * Сверка с Unicorn назвала это полем: `reg.eax expected=0x70001000 actual=0x00001000`. */
            hb_result_t r = parse_modrm(d, modrm, operand16 ? 2 : 4, out, 1, 2, false);
            if (r != HB_OK) return r;
            if (src_size == 1 && out->op2.is_reg) {
                uint8_t src_offset = 0;
                out->op2.reg = reg8_idx(out->rm, &src_offset);
                out->op2.reg_offset = src_offset;
            }
            out->op2.size = src_size;
            return HB_OK;
        }
        return HB_ERR_UNSUPPORTED_OPCODE;
    }

    /* Group: ROL/ROR/SHL/SHR/SAR by imm8 (C0/C1) */
    if (opcode == 0xC0 || opcode == 0xC1) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        uint8_t ext = (modrm >> 3) & 7;
        if (ext == 0) out->opcode = HB_INS_ROL;
        else if (ext == 1) out->opcode = HB_INS_ROR;
        else if (ext == 2) out->opcode = HB_INS_RCL;
        else if (ext == 3) out->opcode = HB_INS_RCR;
        else if (ext == 4) out->opcode = HB_INS_SHL;
        else if (ext == 5) out->opcode = HB_INS_SHR;
        else if (ext == 6) out->opcode = HB_INS_SHL; /* SAL alias for SHL (Intel SDM) */
        else if (ext == 7) out->opcode = HB_INS_SAR;
        else return HB_ERR_UNSUPPORTED_OPCODE;
        out->writes_flags = true;
        uint8_t sz = (opcode == 0xC0) ? 1 : (operand16 ? 2 : 4);
        hb_result_t r = parse_modrm_ext(d, modrm, sz, out, 1);
        if (r != HB_OK) return r;
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        set_imm(out, 2, read_u8(d) & 0x1F, 1);
        return HB_OK;
    }

    /* Group: ROL/ROR/SHL/SHR/SAR by 1 (D0/D1) */
    if (opcode == 0xD0 || opcode == 0xD1) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        uint8_t ext = (modrm >> 3) & 7;
        if (ext == 0) out->opcode = HB_INS_ROL;
        else if (ext == 1) out->opcode = HB_INS_ROR;
        else if (ext == 2) out->opcode = HB_INS_RCL;
        else if (ext == 3) out->opcode = HB_INS_RCR;
        else if (ext == 4) out->opcode = HB_INS_SHL;
        else if (ext == 5) out->opcode = HB_INS_SHR;
        else if (ext == 6) out->opcode = HB_INS_SHL; /* SAL alias for SHL (Intel SDM) */
        else if (ext == 7) out->opcode = HB_INS_SAR;
        else return HB_ERR_UNSUPPORTED_OPCODE;
        out->writes_flags = true;
        uint8_t sz = (opcode == 0xD0) ? 1 : (operand16 ? 2 : 4);
        hb_result_t r = parse_modrm_ext(d, modrm, sz, out, 1);
        if (r != HB_OK) return r;
        set_imm(out, 2, 1, 1);
        return HB_OK;
    }

    /* Group: ROL/ROR/SHL/SHR/SAR by CL (D2/D3) */
    if (opcode == 0xD2 || opcode == 0xD3) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        uint8_t ext = (modrm >> 3) & 7;
        if (ext == 0) out->opcode = HB_INS_ROL;
        else if (ext == 1) out->opcode = HB_INS_ROR;
        else if (ext == 2) out->opcode = HB_INS_RCL;
        else if (ext == 3) out->opcode = HB_INS_RCR;
        else if (ext == 4) out->opcode = HB_INS_SHL;
        else if (ext == 5) out->opcode = HB_INS_SHR;
        else if (ext == 6) out->opcode = HB_INS_SHL; /* SAL alias for SHL (Intel SDM) */
        else if (ext == 7) out->opcode = HB_INS_SAR;
        else return HB_ERR_UNSUPPORTED_OPCODE;
        out->writes_flags = true;
        uint8_t sz = (opcode == 0xD2) ? 1 : (operand16 ? 2 : 4);
        hb_result_t r = parse_modrm_ext(d, modrm, sz, out, 1);
        if (r != HB_OK) return r;
        set_reg(out, 2, HB_REG_X86_ECX, 1); /* CL */
        return HB_OK;
    }

    /* Group: 0xFE byte INC/DEC. Mirrors the x64 FE /0,/1 path. */
    if (opcode == 0xFE) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        uint8_t ext = (modrm >> 3) & 7;
        if (ext == 0) out->opcode = HB_INS_INC;
        else if (ext == 1) out->opcode = HB_INS_DEC;
        else return HB_ERR_UNSUPPORTED_OPCODE;
        out->writes_flags = true;
        return parse_modrm_ext(d, modrm, 1, out, 1);
    }

    /* Group: TEST / NOT / NEG / MUL / IMUL / DIV / IDIV (F6/F7). */
    if (opcode == 0xF6 || opcode == 0xF7) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        uint8_t ext = (modrm >> 3) & 7;
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 910 — ПРЕФИКС 66 В ГРУППЕ F6/F7.
         * Размер был зашит четвёркой, поэтому ВСЯ группа (`NOT/NEG/MUL/IMUL/DIV/IDIV/TEST`)
         * при префиксе `66` считалась 32-битной. Замер против эталона на этой ветви:
         *   `66f7d1 not cx`  эталон ecx=0x0000fffd, мы давали 0xfffffffd — инвертированы
         *                    все 32 бита вместо шестнадцати;
         *   `66f7e1 mul cx`  эталон eax=0x70002000, мы давали 0xe0002000.
         * Контроли `mul ecx`, `div ecx` и `inc cx` (группа FF) сходились — дефект точечный.
         * Ветвь x64 эту группу разбирает верно; неверна была только эта.
         * Невидимо доске по механике 908: расхождение операндов вычёркивает случай из
         * семантической выборки. */
        uint8_t sz = (opcode == 0xF6) ? 1 : (operand16 ? 2 : 4);
        /* ★ MacRunner 2026-08-28 — `/1` ЭТО ТОТ ЖЕ `TEST`.
         * В руководстве Intel расширение `/1` группы F6/F7 помечено как
         * неопределённое, но настоящие процессоры исполняют его в точности как
         * `/0` (недокументированный псевдоним; capstone его так и разбирает).
         * Это была последняя дыра сплошного перебора: `f7 8b ...` из случайных
         * потоков. Кодирование одинаковое, поэтому и разбор общий. */
        if (ext == 0 || ext == 1) {
            out->opcode = HB_INS_TEST;
            out->writes_flags = true;
            hb_result_t r = parse_modrm_ext(d, modrm, sz, out, 1);
            if (r != HB_OK) return r;
            if (opcode == 0xF6) {
                if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
                set_imm(out, 2, read_s8(d), 1);
            } else if (operand16) {
                /* TEST r/m16, imm16 — непосредственное ДВА байта, а не четыре: иначе
                 * поехала бы и длина команды. */
                if (!can_read(d, 2)) return HB_ERR_DECODE_FAILED;
                set_imm(out, 2, (int64_t)read_s16(d), 2);
            } else {
                if (!can_read(d, 4)) return HB_ERR_DECODE_FAILED;
                set_imm(out, 2, (int64_t)read_s32(d), 4);
            }
            return HB_OK;
        }
        if (ext == 2) out->opcode = HB_INS_NOT;
        else if (ext == 3) out->opcode = HB_INS_NEG;
        else if (ext == 4) out->opcode = HB_INS_MUL;
        else if (ext == 5) out->opcode = HB_INS_IMUL;
        else if (ext == 6) out->opcode = HB_INS_DIV;
        else if (ext == 7) out->opcode = HB_INS_IDIV;
        else return HB_ERR_UNSUPPORTED_OPCODE;
        out->writes_flags = (ext == 3 || ext == 4 || ext == 5);
        return parse_modrm_ext(d, modrm, sz, out, 1);
    }

    /* Group: 0xFF */
    if (opcode == 0xFF) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        uint8_t ext = (modrm >> 3) & 7;
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 949 — ВСЯ ГРУППА `FF` ИГНОРИРОВАЛА 66.
         *
         * Размер был зашит четвёркой во всех пяти членах, а префикс 66 делает их
         * шестнадцатибитными: `inc/dec/call/jmp/push r/m16`. У `call` и `push` вдобавок
         * менялся бы СДВИГ ВЕРШИНЫ СТЕКА — два байта вместо четырёх, — и это тот самый класс
         * молчащей порчи стека, что уже ловился на `push cx` и `enter` (910, 925).
         * Перебор показал только `call`/`jmp` (по 6 строк), потому что у остальных членов
         * расхождение видно не по размеру операнда; но причина одна на всю группу, и лечить
         * её надо разом, а не по пойманным.
         * Замер до правки: `66ffd0 call ax` — наш размер 4, эталон 2. */
        uint8_t ff_sz = operand16 ? 2 : 4;
        int ff_delta = operand16 ? -2 : -4;
        if (ext == 0) {
            out->opcode = HB_INS_INC;
            out->writes_flags = true;
            return parse_modrm_ext(d, modrm, ff_sz, out, 1);
        }
        if (ext == 1) {
            out->opcode = HB_INS_DEC;
            out->writes_flags = true;
            return parse_modrm_ext(d, modrm, ff_sz, out, 1);
        }
        if (ext == 2) {
            out->opcode = HB_INS_CALL;
            out->is_call = true;
            out->stack_delta = ff_delta;
            return parse_modrm_ext(d, modrm, ff_sz, out, 1);
        }
        if (ext == 4) {
            out->opcode = HB_INS_JMP;
            out->is_branch = true;
            return parse_modrm_ext(d, modrm, ff_sz, out, 1);
        }
        /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1063 — ДАЛЬНИЕ ФОРМЫ ЧЕРЕЗ ПАМЯТЬ.
         *
         * `FF /3` (call m16:32) и `FF /5` (jmp m16:32) не декодировались вовсе — это 9 из 18
         * пробелов доски x86-32, все из настоящего двоичного KeePass. Ветвь x64 их уже
         * принимает, и принимает как `HB_INS_SYS` (строки 5534 и 5546 в `hb_decode_x64.c`) —
         * это заведённое в проекте обозначение «команда разобрана, семантика честно отказана»:
         * случая в лифтере нет, исполнение даёт `-5`. Смена сегмента кода нами не моделируется,
         * так что притворяться исполнением нельзя, а не узнавать команду — тем более.
         *
         * Операнд — пара «селектор:смещение»: 6 байт (2+4), с префиксом 66 — 4 байта (2+2).
         * Регистровая форма (mod=11) архитектурно недопустима, процессор даёт #UD. */
        if (ext == 3 || ext == 5) {
            if ((modrm & 0xC0) == 0xC0) return HB_ERR_UNSUPPORTED_OPCODE;
            out->opcode = (ext == 3) ? HB_INS_CALL_FAR_MEM : HB_INS_JMP_FAR_MEM;
            out->is_branch = true;
            if (ext == 3) out->is_call = true;
            return parse_modrm_ext(d, modrm, operand16 ? 4 : 6, out, 1);
        }
        if (ext == 6) {
            out->opcode = HB_INS_PUSH;
            out->stack_delta = ff_delta;
            return parse_modrm_ext(d, modrm, ff_sz, out, 1);
        }
        return HB_ERR_UNSUPPORTED_OPCODE;
    }

    /* TEST (subset) */
    if (opcode == 0x84) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_TEST; out->writes_flags = true;
        return parse_modrm(d, modrm, 1, out, 1, 2, true);
    }
    if (opcode == 0x85) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_TEST; out->writes_flags = true;
        return parse_modrm(d, modrm, operand16 ? 2 : 4, out, 1, 2, true);
    }
    if (opcode == 0xA8) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        out->opcode = HB_INS_TEST; out->writes_flags = true;
        set_reg(out, 1, 0, 1);
        set_imm(out, 2, read_s8(d), 1);
        return HB_OK;
    }
    if (opcode == 0xA9) {
        out->opcode = HB_INS_TEST; out->writes_flags = true;
        uint8_t sz = operand16 ? 2 : 4;
        if (!can_read(d, sz)) return HB_ERR_DECODE_FAILED;
        set_reg(out, 1, 0, sz);
        set_imm(out, 2, sz == 2 ? (int64_t)read_s16(d) : (int64_t)read_s32(d), sz);
        return HB_OK;
    }

    /* AND (subset) */
    if (opcode == 0x20) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_AND; out->writes_flags = true;
        return parse_modrm(d, modrm, 1, out, 1, 2, true);
    }
    if (opcode == 0x21) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_AND; out->writes_flags = true;
        return parse_modrm(d, modrm, 4, out, 1, 2, true);
    }
    if (opcode == 0x22) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_AND; out->writes_flags = true;
        return parse_modrm(d, modrm, 1, out, 1, 2, false);
    }
    if (opcode == 0x23) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_AND; out->writes_flags = true;
        return parse_modrm(d, modrm, 4, out, 1, 2, false);
    }

    /* OR (subset) */
    if (opcode == 0x08) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_OR; out->writes_flags = true;
        return parse_modrm(d, modrm, 1, out, 1, 2, true);
    }
    if (opcode == 0x09) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_OR; out->writes_flags = true;
        return parse_modrm(d, modrm, 4, out, 1, 2, true);
    }
    if (opcode == 0x0A) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_OR; out->writes_flags = true;
        return parse_modrm(d, modrm, 1, out, 1, 2, false);
    }
    if (opcode == 0x0B) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_OR; out->writes_flags = true;
        return parse_modrm(d, modrm, 4, out, 1, 2, false);
    }

    /* XOR (subset) */
    if (opcode == 0x30) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_XOR; out->writes_flags = true;
        return parse_modrm(d, modrm, 1, out, 1, 2, true);
    }
    if (opcode == 0x31) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_XOR; out->writes_flags = true;
        return parse_modrm(d, modrm, 4, out, 1, 2, true);
    }
    if (opcode == 0x32) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_XOR; out->writes_flags = true;
        return parse_modrm(d, modrm, 1, out, 1, 2, false);
    }
    if (opcode == 0x33) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        uint8_t modrm = read_u8(d);
        out->opcode = HB_INS_XOR; out->writes_flags = true;
        return parse_modrm(d, modrm, 4, out, 1, 2, false);
    }

    /* Unsupported */
    return HB_ERR_UNSUPPORTED_OPCODE;
}


hb_result_t hb_decode_x86(const uint8_t* code, size_t len, uint64_t addr, hb_decoded_t* out) {
    if (!code || !out || len == 0) return HB_ERR_INVALID_ARG;

    hb_dec_t d = { code, len, 0, addr, false };
    hb_result_t r = decode_one(&d, out);

    /* ★ MacRunner 2026-08-28 — НЕДОПУСТИМОЕ СОЧЕТАНИЕ ПРЕФИКСА И КОМАНДЫ.
     *
     * Сплошной перебор против capstone оставлял двадцать случаев вида «LOCK SAR»,
     * «LOCK TEST», «SHA под F2/F3». На железе все они дают #UD: LOCK допустим лишь
     * со списком команд чтение-изменение-запись, а SHA определены как `NP 0F 38 C8`,
     * то есть без префикса вовсе. Соблазн был счесть наш отказ верным — поведение
     * гостя ведь то же.
     *
     * Но цена разная, и это решает дело:
     *   отказ РАЗБОРА  — движок не знает ДЛИНУ, рушится весь блок трансляции, и
     *                    гость получает c000001d на НАЧАЛЕ блока. Ровно та беда, из-за
     *                    которой сегодня искали виновную команду по неверному адресу
     *                    (окно печати в 48 байт, PSLLQ лежал на смещении +62).
     *   разбор + #UD   — длина верна, блок цел, исключение приходит ТОЧНО на этой
     *                    команде, как на настоящей машине.
     *
     * Отличаем недопустимое сочетание от настоящей дыры так: убираем мешающий
     * префикс и пробуем снова. Разобралось — значит команду мы знаем, недопустимо
     * лишь сочетание; отдаём её с `HB_INS_UNAVAILABLE_EXT` (лифт даёт #UD) и длиной,
     * увеличенной на снятые префиксы. Не разобралось — это настоящая дыра, и отказ
     * остаётся отказом. */
    if (r == HB_ERR_UNSUPPORTED_OPCODE && !hb_gate( HB_GATE_HB_NO_PREFIX_RETRY )) {
        size_t голова = 0;
        bool мешающий = false;
        while (голова < len && голова < 15) {
            uint8_t b = code[голова];
            if (b == 0xF0 || b == 0xF2 || b == 0xF3) { мешающий = true; голова++; continue; }
            if (b == 0x66 || b == 0x67 || b == 0x2E || b == 0x36 ||
                b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) { голова++; continue; }
            break;
        }
        if (мешающий && голова < len) {
            uint8_t без[24];
            size_t n = 0, i;
            for (i = 0; i < len && n < sizeof(без); i++) {
                uint8_t b = code[i];
                if (i < голова && (b == 0xF0 || b == 0xF2 || b == 0xF3)) continue;
                без[n++] = b;
            }
            {
                hb_decoded_t проба;
                hb_dec_t d2 = { без, n, 0, addr, false };
                if (decode_one(&d2, &проба) == HB_OK) {
                    size_t снято = 0;
                    for (i = 0; i < голова; i++)
                        if (code[i] == 0xF0 || code[i] == 0xF2 || code[i] == 0xF3) снято++;
                    *out = проба;
                    out->opcode = HB_INS_UNAVAILABLE_EXT;
                    out->writes_flags = false;
                    /* Длину берём из позиции разборщика: `decode_one` поля `len`
                     * не заполняет — оно проставляется ниже, в конце этой функции. */
                    out->len = (uint8_t)(d2.pos + снято);
                    out->addr = addr;
                    return HB_OK;
                }
            }
        }
    }

    if (r != HB_OK) {
        out->len = (uint8_t)(d.pos > 0 ? d.pos : 1);
        /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 262 — НАЗВАТЬ НЕРАСПОЗНАННУЮ ИНСТРУКЦИЮ.
         * Ступень 1 умирает с `exec=UNSUPPORTED_OPCODE(-5)`, и по одному лишь `out_eip` её не
         * опознать: это точка остановки, а не адрес отказа. Мест возврата этого кода около 240
         * (декодер i386 — 119, x64 — 81, интерпретатор — 31, кодогенератор — 8), поэтому печать
         * ставим в ЕДИНСТВЕННУЮ верхнюю точку декодера, где известны и адрес, и сами байты.
         * Первые 8 раз, без гейта: событие редкое и всегда фатальное. */
        if (r == HB_ERR_UNSUPPORTED_OPCODE) {
            static int said;
            if (said++ < 8) {
                size_t n = len < 12 ? len : 12, k;
                fprintf(stderr, "macrunner-hb-decode-unsupported: addr=0x%llx len=%u bytes=",
                        (unsigned long long)addr, (unsigned)out->len);
                for (k = 0; k < n; k++) fprintf(stderr, "%02x ", code[k]);
                fprintf(stderr, "\n");
                fflush(stderr);
            }
        }
        if (r == HB_ERR_UNSUPPORTED_OPCODE) out->opcode = HB_INS_UNSUPPORTED;
        memcpy(out->bytes, code, out->len > 15 ? 15 : out->len);
        return r;
    }

    out->len = (uint8_t)d.pos;
    /* ЗАКОННОСТЬ ПРЕФИКСА LOCK — ровно тем же правилом, что и на x64:
     * hb_zamok_pravilo.h, список hb_zamki.h снят с процессора. Ответ такой же,
     * как у соседнего разбора «недопустимое сочетание префикса и команды»
     * выше по файлу: длина верна, блок цел, #UD приходит на самой команде. */
    if (!hb_zamok_zakonen(out)) {
        out->opcode = HB_INS_UNAVAILABLE_EXT;
        out->writes_flags = false;
    }
    memcpy(out->bytes, code, out->len > 15 ? 15 : out->len);
    return HB_OK;
}
