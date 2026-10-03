#include "hb_env.h"
#include "hb_vec_sootv.h"
#include "hb_gates.h"
#include <stdlib.h>
#include "hb_lifter.h"
#include "hb_ir.h"
#include <string.h>

/* ═══ МАСКА EVEX ДОХОДИТ ДО IR — ЗЕРКАЛО x64 ═══
 *
 * У лифтера i386 не было НИ ОДНОГО упоминания маски: декодер её извлекал, а
 * здесь она терялась, и все формы EVEX исполнялись бы без маски — то есть
 * НЕВЕРНО, а не «не поддержано». Это опаснее отказа: молчаливая порча.
 *
 * Упаковка ровно та же, что у x64 (hb_lift_x64.c:82-96): номер регистра-маски
 * в биты 24-26, признак обнуления в бит 27, признак «маска задана» в бит 28.
 * Одинаковая раскладка обязательна — поле читает ОБЩИЙ интерпретатор
 * (write_vec_reg_bytes_evex_masked), один на обе архитектуры. */
static bool is_evex_decoded_x86(const hb_decoded_t* dec) {
    return dec && dec->evex;
}

static uint64_t evex_target_arg_x86(const hb_decoded_t* dec, uint64_t arg) {
    if (!is_evex_decoded_x86(dec)) return arg;
    return (arg & 0x00ffffffu) |
           ((uint64_t)(dec->evex_mask & 7u) << 24) |
           (dec->evex_zero ? (1ULL << 27) : 0) |
           (1ULL << 28);
}

static void set_evex_target_arg_x86(hb_ir_instr_t* i, const hb_decoded_t* dec,
                                    uint64_t arg) {
    if (i && is_evex_decoded_x86(dec)) i->target = evex_target_arg_x86(dec, arg);
}

/* Регистрация кеша гейта в общем сбросе — см. hb_codegen.h. */

static hb_size_t size_from_dec(uint8_t sz) {
    switch (sz) {
        case 1: return HB_SIZE_8;
        case 2: return HB_SIZE_16;
        case 4: return HB_SIZE_32;
        case 8: return HB_SIZE_64;
        /* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 514 — 80 БИТ ТЕРЯЛИСЬ МОЛЧА.
         * Строки `case 10` здесь не было, и `fld m80`/`fstp m80` уезжали в `default`,
         * то есть в ОДИНАРНУЮ точность. Видно стало только когда исполнитель научился
         * печатать записанные байты: по адресу лежало `3baab83f` — это float32 от
         * log2(e), четыре байта вместо десяти. В x64-лифтере строка есть с самого начала,
         * поэтому дефект был только 32-битным. */
        case 10: return HB_SIZE_80;
        case 16: return HB_SIZE_128;
        default: return HB_SIZE_32;
    }
}

static hb_reg_t map_x86_reg_to_ir(int reg) {
    if (reg >= HB_REG_XMM0 && reg <= HB_REG_XMM7) return (hb_reg_t)reg;
    /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 308 — ПРОПУСК РЕГИСТРОВ MMX.
     *
     * Декодер отдаёт уже готовый номер ПП (`mark_mm_operand` прибавляет HB_REG_MM0), как и для
     * XMM строкой выше. Без этого пропуска номера 49-56 падали в `default: HB_REG_COUNT`, и
     * дальше было два разных вреда:
     *   - `MMX_AND` честно отказывал (UNSUPPORTED_FEATURE) — на этом стояла ступень 1;
     *   - `MMX_MOV` НЕ отказывал, а писал в несуществующий регистр по запасной ветке, то есть
     *     портил состояние молча. Второе опаснее первого и без этой находки не всплыло бы.
     *
     * Искалось это шестью зондами подряд: печать в декодере молчала, в общей точке отказа
     * молчала, в моей же ветке отказа молчала — и назвал причину только зонд, печатающий
     * ТИПЫ И РАЗМЕРЫ операндов (`macrunner-hb-interp-unsupported`, `dst=0/8`, то есть тип
     * REG при негодном номере). */
    if (reg >= HB_REG_MM0 && reg <= HB_REG_MM7) return (hb_reg_t)reg;
    switch (reg) {
        case HB_REG_X86_EAX: return HB_REG_RAX;
        case HB_REG_X86_ECX: return HB_REG_RCX;
        case HB_REG_X86_EDX: return HB_REG_RDX;
        case HB_REG_X86_EBX: return HB_REG_RBX;
        case HB_REG_X86_ESP: return HB_REG_RSP;
        case HB_REG_X86_EBP: return HB_REG_RBP;
        case HB_REG_X86_ESI: return HB_REG_RSI;
        case HB_REG_X86_EDI: return HB_REG_RDI;
        case HB_REG_X86_EIP: return HB_REG_RIP;
        case HB_REG_X86_XMM0: return HB_REG_XMM0;
        case HB_REG_X86_XMM1: return HB_REG_XMM1;
        case HB_REG_X86_XMM2: return HB_REG_XMM2;
        case HB_REG_X86_XMM3: return HB_REG_XMM3;
        case HB_REG_X86_XMM4: return HB_REG_XMM4;
        case HB_REG_X86_XMM5: return HB_REG_XMM5;
        case HB_REG_X86_XMM6: return HB_REG_XMM6;
        case HB_REG_X86_XMM7: return HB_REG_XMM7;
        default: return HB_REG_COUNT;
    }
}

static hb_ir_operand_t operand_from_dec(const hb_decoded_t* dec, int slot) {
    const hb_decoded_t* d = dec;
    bool is_reg = (slot == 1) ? d->op1.is_reg : (slot == 2) ? d->op2.is_reg : d->op3.is_reg;
    bool is_imm = (slot == 1) ? d->op1.is_imm : (slot == 2) ? d->op2.is_imm : d->op3.is_imm;
    bool is_mem = (slot == 1) ? d->op1.is_mem : (slot == 2) ? d->op2.is_mem : d->op3.is_mem;
    uint8_t sz_raw = (slot == 1) ? d->op1.size : (slot == 2) ? d->op2.size : d->op3.size;
    uint8_t reg_offset = (slot == 1) ? d->op1.reg_offset : (slot == 2) ? d->op2.reg_offset : d->op3.reg_offset;
    hb_size_t sz = size_from_dec(sz_raw);
    if (is_reg) {
        int reg = (slot == 1) ? d->op1.reg : (slot == 2) ? d->op2.reg : d->op3.reg;
        hb_ir_operand_t op = hb_ir_reg(map_x86_reg_to_ir(reg), sz);
        op.reg_offset = reg_offset;
        return op;
    }
    if (is_imm) {
        int64_t imm = (slot == 1) ? d->op1.imm : (slot == 2) ? d->op2.imm : d->op3.imm;
        return hb_ir_imm(imm, sz);
    }
    if (is_mem) {
        int base = (slot == 1) ? d->op1.mem.base : (slot == 2) ? d->op2.mem.base : d->op3.mem.base;
        int index = (slot == 1) ? d->op1.mem.index : (slot == 2) ? d->op2.mem.index : d->op3.mem.index;
        uint8_t scale = (slot == 1) ? d->op1.mem.scale : (slot == 2) ? d->op2.mem.scale : d->op3.mem.scale;
        int64_t disp = (slot == 1) ? d->op1.mem.disp : (slot == 2) ? d->op2.mem.disp : d->op3.mem.disp;
        uint8_t segment = (slot == 1) ? d->op1.mem.segment : (slot == 2) ? d->op2.mem.segment : d->op3.mem.segment;
        bool addr32 = (slot == 1) ? d->op1.mem.addr32 : (slot == 2) ? d->op2.mem.addr32 : d->op3.mem.addr32;
        hb_ir_operand_t op = hb_ir_mem_segment(
            base >= 0 ? map_x86_reg_to_ir(base) : HB_REG_COUNT,
            index >= 0 ? map_x86_reg_to_ir(index) : HB_REG_COUNT,
            scale, disp, sz, segment);
        op.mem.addr32 = addr32;
        /* ПРИЗНАКИ SIB С ВЕКТОРНЫМ ИНДЕКСОМ — ветвь x64 переносит их восемью
         * строками, i386 не переносил НИ ОДНОЙ. Из-за этого сборы не работали:
         * декодер (после правки 04.09.2026) признаки заполнял, а до
         * интерпретатора они не доходили, и он отвечал -99 — он их ТРЕБУЕТ.
         * Замер: x64 доходил до памяти (-8, отказ ожидаемый), i386 падал на
         * проверке (-99). */
        op.mem.vsib = (slot == 1) ? d->op1.mem.vsib
                    : (slot == 2) ? d->op2.mem.vsib : d->op3.mem.vsib;
        op.mem.vsib_index_size = (slot == 1) ? d->op1.mem.vsib_index_size
                               : (slot == 2) ? d->op2.mem.vsib_index_size
                                             : d->op3.mem.vsib_index_size;
        op.mem.vsib_elem_size = (slot == 1) ? d->op1.mem.vsib_elem_size
                              : (slot == 2) ? d->op2.mem.vsib_elem_size
                                            : d->op3.mem.vsib_elem_size;
        op.mem.vsib_count = (slot == 1) ? d->op1.mem.vsib_count
                          : (slot == 2) ? d->op2.mem.vsib_count
                                        : d->op3.mem.vsib_count;
        /* Итерация 283: 16-битная адресация — признак идёт до вычислителя, он усекает адрес. */
        op.mem.addr16 = (slot == 1) ? d->op1.mem.addr16 : (slot == 2) ? d->op2.mem.addr16 : d->op3.mem.addr16;
        return op;
    }
    return hb_ir_none();
}

#include "hb_lift_vec_opory.inc"

static hb_cc_t cc_from_dec(int cond) {
    switch (cond) {
        case HB_COND_E:  return HB_CC_E;
        case HB_COND_NE: return HB_CC_NE;
        case HB_COND_S:  return HB_CC_S;
        case HB_COND_NS: return HB_CC_NS;
        case HB_COND_G:  return HB_CC_G;
        case HB_COND_GE: return HB_CC_GE;
        case HB_COND_L:  return HB_CC_L;
        case HB_COND_LE: return HB_CC_LE;
        case HB_COND_A:  return HB_CC_A;
        case HB_COND_AE: return HB_CC_AE;
        case HB_COND_B:  return HB_CC_B;
        case HB_COND_BE: return HB_CC_BE;
        case HB_COND_O:  return HB_CC_O;
        case HB_COND_NO: return HB_CC_NO;
        case HB_COND_P:  return HB_CC_P;
        case HB_COND_NP: return HB_CC_NP;
        default: return HB_CC_E;
    }
}

/* Итерация 390: признак под гейтом. Правка убирает 3 расхождения `dec`, но вносит 51 отказ
 * `result=0 OK` на inc/dec — подпись рассинхронизации сторон, причина пока не найдена.
 * Причина найдена в 391 — вторая копия таблицы масок в кодогенераторе. Умолчание ВКЛ. */
/* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1105 — ГЕЙТЫ ВИДА Б (приказ 145).
 *
 * ЭТО ПРИБОР, А НЕ ВЫКЛЮЧАТЕЛЬ. Умолчание ВКЛЮЧЕНО; гасится ТОЛЬКО в приёмочном переборе,
 * чтобы узнать цену правки правильности в процентах. В обычной сборке не выключается никогда —
 * `check-required-gates.sh` считает значение `=0` запрещённым вне приёмки.
 *
 * Почему это подчёркнуто трижды: нас уже кусало ровно обратное — общий кэш трансляций,
 * связывание блоков и доставка отказа были написаны, проверены и ЛЕЖАЛИ ВЫКЛЮЧЕННЫМИ.
 *
 * ЧТО ЗНАЧИТ «ВЫКЛЮЧЕНО» — выбрано так, чтобы арм мерил ЦЕНУ, а не воспроизводил аварию:
 *   FENCE_I386=0   выпускается NOP вместо барьера. До правки 1066 команда падала с
 *                  HB_ERR_UNSUPPORTED_OPCODE — такой арм мерил бы смерть, а не цену барьера.
 *   UD_DELIVERY=0  возвращается прежний отказ «неподдержанный опкод»: дешевле сделать
 *                  нечего, и арм показывает поведение до правки 1081 честно.
 *
 * NB: оба гейта живут в ЛИФТЕРЕ, то есть меняют IR, который ложится в постоянный кэш
 * трансляций. Кэш ОБЯЗАН чиститься перед каждым армом — это записано в
 * `reports/lanes/ГЕЙТЫ-ПРИЁМКИ.md`, раздел 1.4. Тёплый кэш соседнего арма подсунул бы чужой
 * IR под тем же номером версии, и это была бы подмена измеряемого, а не разброс. */
/* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 510 — ПРИЗНАК VEX НА 32 БИТАХ НЕ СТАВИЛСЯ.
 *
 * `zero_ymm_upper` встречался в `hb_lift_x64.c` четыре раза и в `hb_lift_x86.c` — НИ РАЗУ,
 * при том что 32-битный декодер VEX знает (36 упоминаний). Итог: 32-битный гость, пишущий
 * 128-битной VEX-командой, получал старшую половину `ymm` от прошлого значения.
 *
 * Внутренняя сверка это НЕ ловила: интерпретатор и кодогенератор вели себя одинаково
 * неправильно (замер 509: обе стороны `3c522d699e3ff8e8` там, где должен быть ноль), а эталон
 * Unicorn AVX не исполняет вовсе (508). Нашлось только прямым вопросом «а выполняется ли
 * правило», заданным обеим сторонам сразу.
 *
 * Ставим централизованно в единственной точке выпуска, а не по местам: правило одно на всю
 * архитектуру — 128-битная VEX-запись в регистр обнуляет биты 128..255 приёмника. */
static bool x86_is_vex_decoded(const hb_decoded_t* dec) {
    return dec && dec->len > 0 && (dec->evex || dec->bytes[0] == 0xc4 || dec->bytes[0] == 0xc5);
}

static inline hb_ir_instr_t* emit(hb_ir_builder_t* b, hb_ir_instr_t* i, const hb_decoded_t* dec) {
    (void)b;
    if (i) {
        i->guest_addr = dec->addr; i->guest_len = dec->len;
        if (!i->zero_ymm_upper && x86_is_vex_decoded(dec) && i->dst.type == HB_OP_REG &&
            i->dst.reg >= HB_REG_XMM0 && i->dst.reg <= HB_REG_XMM31)
            i->zero_ymm_upper = true;
    }
    return i;
}

/* Разворот ОБЩЕГО списка соответствий — тот же текст, что в ветви x64.
 * Прежде здесь жил рукописный kTable[] на 69 строк против 213 у x64:
 * ветвь i386 отставала на 145 соответствий, и доска этого не называла. */
static hb_ir_vec_op_t vec_op_from_ins(int opcode) {
    switch (opcode) {
#define X(ins, vec) case ins: return vec;
        HB_VEC_SOOTV(X)
#undef X
        default: break;
    }
    return 0;
}

static bool is_legacy_scalar_sse_mem_load(const hb_decoded_t* dec) {
    bool has_scalar_prefix = false;

    if (!dec) return false;
    for (uint8_t i = 0; i + 1 < dec->len && i < sizeof(dec->bytes); i++) {
        uint8_t byte = dec->bytes[i];
        if (byte == 0xf2 || byte == 0xf3) has_scalar_prefix = true;
        if (byte == 0x0f) return has_scalar_prefix && dec->bytes[i + 1] == 0x10;
    }
    return false;
}

#define HB_EVEX_TARGET_ARG(d, im) evex_target_arg_x86((d), (im))
/* Те же опоры под своими именами: у ветви i386 они с суффиксом. */
#define evex_target_arg(d, a)        evex_target_arg_x86((d), (a))
#define set_evex_target_arg(i, d, a) set_evex_target_arg_x86((i), (d), (a))
#define is_vex_decoded(d)            x86_is_vex_decoded((d))
#include "hb_lift_vec_obshchee.inc"
#include "hb_lift_sist_obshchee.inc"


/* ═══ ИСТОЧНИКИ: ДВА ОПЕРАНДА ИЛИ ТРИ ═══
 *
 * У старой формы SSE операндов два, и ПРИЁМНИК ЖЕ служит первым источником:
 * `packsswb xmm1, xmm2` это `xmm1 = pack(xmm1, xmm2)`. У формы VEX их три —
 * приёмник, регистр vvvv и r/m: `vpacksswb xmm3, xmm5, xmm6` это
 * `xmm3 = pack(xmm5, xmm6)`, и приёмник источником НЕ является.
 *
 * Лифтер писал `src1 = dst` безусловно, поэтому у всех трёхоперандных форм
 * первый источник брался неверно. Разбор при этом был правильный — расхождение
 * всплывало только на СЕМАНТИЧЕСКОЙ сверке (vpacksswb, vunpcklpd), то есть
 * молча давало неверный результат. */
/* ИСТОЧНИКИ ПО ЧИСЛУ ОПЕРАНДОВ — ЕДИНСТВЕННОЕ место, где это решается.
 *
 * У формы VEX ТРИ операнда, и приёмник источником НЕ является. Ветви лифтера
 * зашивали `i->src1 = dst; i->src2 = src;` — старую двухоперандную форму SSE.
 *
 * 04.09.2026 этот помощник существовал, но звали его ДВЕ ветви из двадцати
 * четырёх: вчера я починил ту, где расхождение было видно на доске, а не
 * КЛАСС. Остальные 22 продолжали брать приёмник первым источником, и доска
 * этого не показывала — прежний оракул (Unicorn) сам не читает vvvv и потому
 * соглашался с любой ошибкой на формах VEX.
 *
 * Нашлось сразу, как только оракулом стал Bochs: `vpxor xmm3, xmm5, xmm6`
 * давал у нас `xmm3 ^ xmm5` вместо `xmm5 ^ xmm6` — проверено вручную
 * побайтно (bf^01=be, 10^e9=f9, cf^0b=c4, 63^d6=b5).
 *
 * Помощник верен и для СТАРЫХ двухоперандных форм: когда третьего операнда
 * нет, он сам берёт приёмник первым источником. Поэтому перевод безопасен
 * для всех ветвей без разбора. */
static void hb_istochniki(const hb_decoded_t* dec, hb_ir_instr_t* i) {
    if (!i) return;
    if (dec->op3.is_reg || dec->op3.is_mem) {
        i->src1 = operand_from_dec(dec, 2);
        i->src2 = operand_from_dec(dec, 3);
    } else {
        /* ВНИМАНИЕ. Здесь стоял вызов САМОГО СЕБЯ — бесконечная рекурсия,
         * которую я внёс 04.09.2026 массовой заменой: шаблон, переводивший
         * ветви лифтера с зашитого `src1 = dst` на этого помощника, совпал и
         * с ЭТИМИ ДВУМЯ СТРОКАМИ ВНУТРИ САМОГО ПОМОЩНИКА.
         *
         * Стоило это часа: зонд доски крутился на 98,7 % и выглядел как
         * «доска долго считает». Нашлось снятием стека (sample), а не
         * рассуждением: `hb_istochniki + 28,32` — двухкомандный цикл.
         *
         * Урок: массовая замена по образцу обязана ИСКЛЮЧАТЬ тело того, во
         * что переводит. Проверка дешёвая — grep на имя внутри самой функции. */
        i->src1 = i->dst;
        i->src2 = operand_from_dec(dec, 2);
    }
}
hb_result_t hb_lift_x86(const hb_decoded_t* dec, hb_ir_builder_t* b) {
    if (!dec || !b) return HB_ERR_INVALID_ARG;

    switch (dec->opcode) {
        case HB_INS_MOV: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            if (dec->op1.is_mem && (dec->op2.is_reg || dec->op2.is_imm)) {
                emit(b, hb_ir_emit_store(b, dst, src), dec);
            } else if (dec->op1.is_reg && dec->op2.is_mem) {
                emit(b, hb_ir_emit_load(b, dst, src), dec);
            } else {
                emit(b, hb_ir_emit_mov(b, dst, src), dec);
            }
            return HB_OK;
        }
        case HB_INS_MOV_SEG: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_unop(b, HB_IR_MOV_SEG, dst, src), dec);
            return HB_OK;
        }
        case HB_INS_SSE_MOV: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            /* Дорожка маски: у EVEX её задаёт декодер, у прочих форм её нет. */
            unsigned evex_lane = dec->evex_mask_lane ? dec->evex_mask_lane : 0;
            if (dec->op1.is_mem && dec->op2.is_reg) {
                hb_ir_instr_t* i = emit(b, hb_ir_emit_store(b, dst, src), dec);
                set_evex_target_arg_x86(i, dec, evex_lane);
            } else if (dec->op1.is_reg && dec->op2.is_mem) {
                hb_ir_instr_t* i = emit(b, hb_ir_emit_load(b, dst, src), dec);
                if (i) i->zero_upper = is_legacy_scalar_sse_mem_load(dec);
                set_evex_target_arg_x86(i, dec, evex_lane);
            } else {
                hb_ir_instr_t* i = emit(b, hb_ir_emit_mov(b, dst, src), dec);
                set_evex_target_arg_x86(i, dec, evex_lane);
            }
            return HB_OK;
        }
        case HB_INS_MOVHLPS:
        case HB_INS_MOVLHPS:
        case HB_INS_MOVHPS:
        case HB_INS_MOVHPD: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_XMM_QWORD_LANE_MOV);
            if (i) {
                bool store = dec->op1.is_mem;
                unsigned dst_lane = (dec->opcode == HB_INS_MOVLHPS ||
                                     (!store && (dec->opcode == HB_INS_MOVHPS || dec->opcode == HB_INS_MOVHPD))) ? 1 : 0;
                unsigned src_lane = (dec->opcode == HB_INS_MOVHLPS ||
                                     (store && (dec->opcode == HB_INS_MOVHPS || dec->opcode == HB_INS_MOVHPD))) ? 1 : 0;
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->target = dst_lane | (src_lane << 8);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MOVD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_MOVD);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_SQRTPS:
        case HB_INS_SQRTPD:
        case HB_INS_SQRTSS:
        case HB_INS_SQRTSD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_FSQRT);
            if (i) {
                unsigned lane = (dec->opcode == HB_INS_SQRTPD || dec->opcode == HB_INS_SQRTSD) ? 8 : 4;
                bool scalar = (dec->opcode == HB_INS_SQRTSS || dec->opcode == HB_INS_SQRTSD);
                i->dst = dst;
                hb_istochniki(dec, i);
                i->target = lane | (scalar ? 0x100 : 0);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_RSQRTPS:
        case HB_INS_RSQRTSS:
        case HB_INS_RCPPS:
        case HB_INS_RCPSS: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            bool is_rsqrt = (dec->opcode == HB_INS_RSQRTPS || dec->opcode == HB_INS_RSQRTSS);
            bool scalar = (dec->opcode == HB_INS_RSQRTSS || dec->opcode == HB_INS_RCPSS);
            hb_ir_instr_t *i = hb_ir_emit(b, is_rsqrt ? HB_IR_FRSQRT : HB_IR_FRCP);
            if (i) {
                i->dst = dst;
                hb_istochniki(dec, i);
                i->target = 4 | (scalar ? 0x100 : 0);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_XMM_AND:
        case HB_INS_XMM_ANDN:
        case HB_INS_XMM_OR:
        case HB_INS_XORPS:
        case HB_INS_PXOR: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_op_t op = HB_IR_XORPS;
            if (dec->opcode == HB_INS_XMM_AND) op = HB_IR_XMM_AND;
            else if (dec->opcode == HB_INS_XMM_ANDN) op = HB_IR_XMM_ANDN;
            else if (dec->opcode == HB_INS_XMM_OR) op = HB_IR_XMM_OR;
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) { i->dst = dst; hb_istochniki(dec, i); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PCMPEQB:
        case HB_INS_PCMPEQW:
        case HB_INS_PCMPEQD: {
            hb_ir_op_t op = HB_IR_PCMPEQB;
            if (dec->opcode == HB_INS_PCMPEQW) op = HB_IR_PCMPEQW;
            else if (dec->opcode == HB_INS_PCMPEQD) op = HB_IR_PCMPEQD;
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) { i->dst = dst; hb_istochniki(dec, i); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PCMPGTB:
        case HB_INS_PCMPGTW:
        case HB_INS_PCMPGTD: {
            hb_ir_op_t op = HB_IR_PCMPGTB;
            if (dec->opcode == HB_INS_PCMPGTW) op = HB_IR_PCMPGTW;
            else if (dec->opcode == HB_INS_PCMPGTD) op = HB_IR_PCMPGTD;
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) { i->dst = dst; hb_istochniki(dec, i); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PMOVMSKB: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PMOVMSKB);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MOVMSKPS:
        case HB_INS_MOVMSKPD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_MOVMSK);
            if (i) {
                i->dst = dst;
                i->src1 = src;
                i->target = dec->opcode == HB_INS_MOVMSKPD ? 8 : 4;
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_UNPCKLPS:
        case HB_INS_UNPCKLPD:
        case HB_INS_UNPCKHPS:
        case HB_INS_UNPCKHPD: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PUNPCK);
            if (i) {
                bool packed_double = (dec->opcode == HB_INS_UNPCKLPD || dec->opcode == HB_INS_UNPCKHPD);
                bool high = (dec->opcode == HB_INS_UNPCKHPS || dec->opcode == HB_INS_UNPCKHPD);
                i->dst = operand_from_dec(dec, 1);
                hb_istochniki(dec, i);
                i->target = (packed_double ? 8 : 4) | (high ? 0x100 : 0);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PUNPCKLBW:
        case HB_INS_PUNPCKLWD:
        case HB_INS_PUNPCKLDQ:
        case HB_INS_PUNPCKLQDQ:
        case HB_INS_PUNPCKHBW:
        case HB_INS_PUNPCKHWD:
        case HB_INS_PUNPCKHDQ:
        case HB_INS_PUNPCKHQDQ: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PUNPCK);
            if (i) {
                unsigned lane = 1;
                if (dec->opcode == HB_INS_PUNPCKLWD || dec->opcode == HB_INS_PUNPCKHWD) lane = 2;
                else if (dec->opcode == HB_INS_PUNPCKLDQ || dec->opcode == HB_INS_PUNPCKHDQ) lane = 4;
                else if (dec->opcode == HB_INS_PUNPCKLQDQ || dec->opcode == HB_INS_PUNPCKHQDQ) lane = 8;
                bool high = (dec->opcode == HB_INS_PUNPCKHBW || dec->opcode == HB_INS_PUNPCKHWD ||
                             dec->opcode == HB_INS_PUNPCKHDQ || dec->opcode == HB_INS_PUNPCKHQDQ);
                i->dst = operand_from_dec(dec, 1);
                hb_istochniki(dec, i);
                i->target = lane | (high ? 0x100 : 0);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PSHUFB: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PSHUFB);
            if (i) { i->dst = dst; hb_istochniki(dec, i); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PHADDW: case HB_INS_PHADDD: case HB_INS_PHADDSW:
        case HB_INS_PHSUBW: case HB_INS_PHSUBD: case HB_INS_PHSUBSW:
        case HB_INS_PMADDUBSW:
        case HB_INS_PSIGNB:  case HB_INS_PSIGNW:  case HB_INS_PSIGND:
        case HB_INS_PMULHRSW:
        case HB_INS_PABSB:   case HB_INS_PABSW:   case HB_INS_PABSD:
        case HB_INS_PTEST:
        case HB_INS_PMOVSXBW: case HB_INS_PMOVSXBD: case HB_INS_PMOVSXBQ:
        case HB_INS_PMOVSXWD: case HB_INS_PMOVSXWQ: case HB_INS_PMOVSXDQ:
        case HB_INS_PMULDQ: case HB_INS_PCMPEQQ: case HB_INS_PACKUSDW:
        case HB_INS_PMOVZXBW: case HB_INS_PMOVZXBD: case HB_INS_PMOVZXBQ:
        case HB_INS_PMOVZXWD: case HB_INS_PMOVZXWQ: case HB_INS_PMOVZXDQ:
        case HB_INS_PCMPGTQ:
        case HB_INS_PMINSB: case HB_INS_PMINSD: case HB_INS_PMINUW: case HB_INS_PMINUD:
        case HB_INS_PMAXSB: case HB_INS_PMAXSD: case HB_INS_PMAXUW: case HB_INS_PMAXUD:
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 919 — ПЯТЬ, КОТОРЫХ НЕ БЫЛО ВОВСЕ.
         * `PMINUB/PMAXUB/PMINSW/PMAXSW/PMULUDQ` не поднимались на этой ветви НИ В КАКОЙ форме:
         * ни MMX (обнажилось правкой декодера 918), ни SSE2 — `660fdac1 pminub xmm` тоже давал
         * `-5`. Декодер их знал, интерпретатор умеет (через общий путь VEC_PACKED с подвидом
         * `HB_VEC_*`), а ЛИФТЕРА не было — ровно тот же случай, что с семьёй упаковки в 522.
         * Ветвь x64 поднимает их этим же общим путём; здесь недоставало двух строк. */
        case HB_INS_PMINUB: case HB_INS_PMAXUB:
        case HB_INS_PMINSW: case HB_INS_PMAXSW: case HB_INS_PMULUDQ:
        case HB_INS_PMULLD: case HB_INS_PHMINPOSUW:
        case HB_INS_PALIGNR: case HB_INS_PBLENDW:
        case HB_INS_BLENDPS: case HB_INS_BLENDPD:
        case HB_INS_PBLENDVB: case HB_INS_BLENDVPS: case HB_INS_BLENDVPD:
        case HB_INS_PCLMULQDQ: case HB_INS_AESKEYGENASSIST:
        case HB_INS_AESIMC: case HB_INS_AESENC: case HB_INS_AESENCLAST:
        case HB_INS_AESDEC: case HB_INS_AESDECLAST:
        case HB_INS_GF2P8MULB:
        case HB_INS_CRC32:
        case HB_INS_ADCX:
        case HB_INS_ADOX:
        case HB_INS_SHA1NEXTE: case HB_INS_SHA1MSG1: case HB_INS_SHA1MSG2:
        case HB_INS_SHA256RNDS2: case HB_INS_SHA256MSG1: case HB_INS_SHA256MSG2:
        case HB_INS_SHA1RNDS4: {
            /* Тело было СВОИМ: рукописный kTable[] на 69 соответствий и один
             * булев признак `unary` вместо разбора формы операндов. Ветвь x64
             * на том же месте держала 213 соответствий и подробное дерево, и
             * i386 отставал по обоим. Теперь текст ОДИН на обе ветви. */
            {
                hb_result_t itog_k;
                if (hb_evex_cmp_mask(dec, b, &itog_k)) return itog_k;
            }

            return hb_vek_obshchij(dec, b);
        }
        case HB_INS_PINSRW: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PINSRW);
            if (i) {
                i->dst = dst;
                hb_istochniki(dec, i);
                i->target = (uint64_t)dec->op3.imm & 7u;
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PEXTRW: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PEXTRW);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->target = (uint64_t)dec->op3.imm & 7u;
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PADDB:
        case HB_INS_PADDW:
        case HB_INS_PADDD:
        case HB_INS_PADDQ:
        case HB_INS_PSUBB:
        case HB_INS_PSUBW:
        case HB_INS_PSUBD:
        case HB_INS_PSUBQ: {
            hb_ir_instr_t *i = hb_ir_emit(b, (dec->opcode == HB_INS_PADDB ||
                                             dec->opcode == HB_INS_PADDW ||
                                             dec->opcode == HB_INS_PADDD ||
                                             dec->opcode == HB_INS_PADDQ) ? HB_IR_PADD : HB_IR_PSUB);
            if (i) {
                unsigned lane = 1;
                if (dec->opcode == HB_INS_PADDW || dec->opcode == HB_INS_PSUBW) lane = 2;
                else if (dec->opcode == HB_INS_PADDD || dec->opcode == HB_INS_PSUBD) lane = 4;
                else if (dec->opcode == HB_INS_PADDQ || dec->opcode == HB_INS_PSUBQ) lane = 8;
                hb_ir_operand_t dst = operand_from_dec(dec, 1);
                i->dst = dst;
                hb_istochniki(dec, i);
                i->target = lane;
            }
            emit(b, i, dec);
            return HB_OK;
        }
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: партия 1 закрытия остатка лифтера x86-32.
         * Насыщающее сложение и среднее. Операции IR были в дереве с самого начала, эталон
         * подъёма — x64-лифтер (`hb_lift_x64.c:810` и `:826`); здесь тот же вид, только
         * первый источник берётся из приёмника, как принято в этом файле. */
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — партия 4: подъём насыщающего вычитания
         * и PSADBW. Вид как у семейства PADDS ниже: первый источник берётся из приёмника. */
        /* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 522 — ПОДЪЁМ СЕМЬИ УПАКОВКИ.
         * Декодер её знал (итерация 287 добавила форму XMM, 522 — форму MMX), интерпретатор
         * знал тоже, а ЛИФТЕРА не было ни для одной формы — оттого `UNSUPPORTED_OPCODE`
         * приходил уже после успешного разбора. Вид как у соседей: первый источник берётся
         * из приёмника. */
        case HB_INS_PACKSSWB:
        case HB_INS_PACKUSWB:
        case HB_INS_PACKSSDW: {
            hb_ir_instr_t *i = hb_ir_emit(b, dec->opcode == HB_INS_PACKSSWB ? HB_IR_PACKSSWB :
                                             dec->opcode == HB_INS_PACKUSWB ? HB_IR_PACKUSWB :
                                                                              HB_IR_PACKSSDW);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                hb_istochniki(dec, i);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PSUBSB:
        case HB_INS_PSUBSW:
        case HB_INS_PSUBUSB:
        case HB_INS_PSUBUSW:
        case HB_INS_PSADBW: {
            hb_ir_op_t op = HB_IR_PSUBSB;
            if (dec->opcode == HB_INS_PSUBSW) op = HB_IR_PSUBSW;
            else if (dec->opcode == HB_INS_PSUBUSB) op = HB_IR_PSUBUSB;
            else if (dec->opcode == HB_INS_PSUBUSW) op = HB_IR_PSUBUSW;
            else if (dec->opcode == HB_INS_PSADBW) op = HB_IR_PSADBW;
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) {
                hb_ir_operand_t dst = operand_from_dec(dec, 1);
                i->dst = dst;
                hb_istochniki(dec, i);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PADDSB:
        case HB_INS_PADDSW:
        case HB_INS_PADDUSB:
        case HB_INS_PADDUSW:
        case HB_INS_PAVGB:
        case HB_INS_PAVGW: {
            hb_ir_op_t op = HB_IR_PADDSB;
            if (dec->opcode == HB_INS_PADDSW) op = HB_IR_PADDSW;
            else if (dec->opcode == HB_INS_PADDUSB) op = HB_IR_PADDUSB;
            else if (dec->opcode == HB_INS_PADDUSW) op = HB_IR_PADDUSW;
            else if (dec->opcode == HB_INS_PAVGB) op = HB_IR_PAVGB;
            else if (dec->opcode == HB_INS_PAVGW) op = HB_IR_PAVGW;
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) {
                hb_ir_operand_t dst = operand_from_dec(dec, 1);
                i->dst = dst;
                hb_istochniki(dec, i);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — MOVBE, остаток набора x86-32.
         *
         * Сверка с эталоном (`hb_lift_x64.c`) по списку из матрицы дала на 10.08 ровно
         * ШЕСТЬ настоящих пробелов, а не 29 и не 56: MOVBE, PSUBSB, PSUBSW, PSUBUSB,
         * PSUBUSW, PSADBW. Остальные имена из матрицы либо уже закрыты прошлыми партиями,
         * либо не существуют как коды операций вовсе (`PSLL`, `PSRL` — их нет ни в эталоне,
         * ни в заголовках; настоящие это PSLLW/PSLLD/PSLLQ, и они на месте).
         *
         * Здесь закрывается только MOVBE: для него код `HB_IR_MOVBE` объявлен, и перенос
         * из эталона прямой. Пять оставшихся идут у x64 через векторный путь `HB_VEC_*`,
         * которого в лифтере x86-32 НЕТ, а собственных `HB_IR_PSUB*`/`HB_IR_PSADBW` в
         * заголовках не существует — это отдельная работа по устройству, а не копия.
         * Записываю прямо, чтобы «29 операций» не считались закрытыми целиком. */
        case HB_INS_MOVBE: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_MOVBE);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->target = dec->op1.size ? dec->op1.size : dec->op2.size;
            }
            emit(b, i, dec);
            return HB_OK;
        }
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ПАРТИЯ 2 остатка лифтера x86-32.
         * Группа BMI1/BMI2 плюс POPCNT. Разбор добавлен в `hb_decode_x86.c` (VEX с
         * развязкой от LES/LDS), операции IR были в дереве с самого начала. Эталон
         * подъёма — `hb_lift_x64.c:1661`; здесь то же самое без ветки vex_w, потому
         * что в 32 битах размер операнда всегда 4 байта. */
        case HB_INS_ANDN:
        case HB_INS_BEXTR:
        case HB_INS_BLSI:
        case HB_INS_BLSMSK:
        case HB_INS_BLSR:
        case HB_INS_BZHI:
        case HB_INS_PDEP:
        case HB_INS_PEXT:
        case HB_INS_RORX:
        case HB_INS_SARX:
        case HB_INS_SHLX:
        case HB_INS_SHRX: {
            hb_ir_op_t op = dec->opcode == HB_INS_ANDN ? HB_IR_ANDN :
                            dec->opcode == HB_INS_BEXTR ? HB_IR_BEXTR :
                            dec->opcode == HB_INS_BLSI ? HB_IR_BLSI :
                            dec->opcode == HB_INS_BLSMSK ? HB_IR_BLSMSK :
                            dec->opcode == HB_INS_BLSR ? HB_IR_BLSR :
                            dec->opcode == HB_INS_BZHI ? HB_IR_BZHI :
                            dec->opcode == HB_INS_PDEP ? HB_IR_PDEP :
                            dec->opcode == HB_INS_PEXT ? HB_IR_PEXT :
                            dec->opcode == HB_INS_RORX ? HB_IR_RORX :
                            dec->opcode == HB_INS_SARX ? HB_IR_SARX :
                            dec->opcode == HB_INS_SHLX ? HB_IR_SHLX : HB_IR_SHRX;
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->src2 = operand_from_dec(dec, 3);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MULX: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_MULX);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->src2 = operand_from_dec(dec, 3);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_POPCNT: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_POPCNT);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ПАРТИЯ 3 — остаток матрицы.
         * Два преобразования упакованных double в dword, перенос 64 байт и два
         * источника случайных чисел. Все пять с одним источником или без него. */
        case HB_INS_CVTPD2DQ:
        case HB_INS_CVTTPD2DQ:
        case HB_INS_MOVDIR64B: {
            hb_ir_op_t op = dec->opcode == HB_INS_CVTPD2DQ ? HB_IR_CVTPD2DQ :
                            dec->opcode == HB_INS_CVTTPD2DQ ? HB_IR_CVTTPD2DQ : HB_IR_MOVDIR64B;
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_RDRAND:
        case HB_INS_RDSEED: {
            hb_ir_instr_t *i = hb_ir_emit(b, dec->opcode == HB_INS_RDRAND ? HB_IR_RDRAND
                                                                          : HB_IR_RDSEED);
            if (i) i->dst = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }
        /* Итерация 886: обнуление старших половин ymm. Операция IR уже есть и не зависит от
         * разрядности (`hb_interpreter.c`: memset по ctx->ymm_hi), образец — лифтер x64.
         * ★ Стоит ПЕРЕД группой перестановок, а не внутри неё: вставленный между метками
         * `case` и телом, он разрывал провал (fallthrough), и PSHUFD/PSHUFLW/PSHUFHW начинали
         * выпускать VZEROUPPER вместо перестановки — стенд поймал это тремя расхождениями. */
        case HB_INS_VZEROUPPER:
            emit(b, hb_ir_emit(b, HB_IR_VZEROUPPER), dec);
            return HB_OK;
        case HB_INS_VZEROALL:
            emit(b, hb_ir_emit(b, HB_IR_VZEROALL), dec);
            return HB_OK;
        case HB_INS_PSHUFD:
        case HB_INS_PSHUFLW:
        case HB_INS_PSHUFHW:
        case HB_INS_PSHUFW: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PSHUF);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->src2 = operand_from_dec(dec, 3);
                /* Итерация 883: признак 1 — MMX-форма (64 бита, четыре СЛОВА). Прежние:
                 * 4 = PSHUFD (двойные слова), 2 = PSHUFLW, 0x102 = PSHUFHW. */
                i->target = dec->opcode == HB_INS_PSHUFW ? 1 :
                            (dec->opcode == HB_INS_PSHUFD ? 4 :
                             (dec->opcode == HB_INS_PSHUFLW ? 2 : 0x102));
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PMULLW:
        case HB_INS_PMULHW:
        case HB_INS_PMULHUW:
        case HB_INS_PMADDWD: {
            hb_ir_op_t op = HB_IR_PMULLW;
            if (dec->opcode == HB_INS_PMULHW) op = HB_IR_PMULHW;
            else if (dec->opcode == HB_INS_PMULHUW) op = HB_IR_PMULHUW;
            else if (dec->opcode == HB_INS_PMADDWD) op = HB_IR_PMADDWD;
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) { i->dst = dst; hb_istochniki(dec, i); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_SHUFPS:
        case HB_INS_SHUFPD: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_FSHUF);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 1);
                i->src2 = operand_from_dec(dec, 2);
                i->target = (dec->opcode == HB_INS_SHUFPD ? 8 : 4) |
                            (((uint64_t)dec->op3.imm & 0xffu) << 8);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_LEA: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_lea(b, dst, src), dec);
            return HB_OK;
        }
        case HB_INS_ADD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_binop(b, HB_IR_ADD, dst, dst, src), dec);
            return HB_OK;
        }
        case HB_INS_ADC: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_binop(b, HB_IR_ADC, dst, dst, src), dec);
            return HB_OK;
        }
        case HB_INS_SUB: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_binop(b, HB_IR_SUB, dst, dst, src), dec);
            return HB_OK;
        }
        case HB_INS_SBB: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_binop(b, HB_IR_SBB, dst, dst, src), dec);
            return HB_OK;
        }
        case HB_INS_CMP: {
            hb_ir_operand_t a = operand_from_dec(dec, 1);
            hb_ir_operand_t b_op = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_cmp(b, a, b_op), dec);
            return HB_OK;
        }
        case HB_INS_TEST: {
            hb_ir_operand_t a = operand_from_dec(dec, 1);
            hb_ir_operand_t b_op = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_test(b, a, b_op), dec);
            return HB_OK;
        }
        case HB_INS_CMPXCHG: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_binop(b, HB_IR_CMPXCHG, dst, dst, src), dec);
            return HB_OK;
        }
        case HB_INS_CMPXCHG8B: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            emit(b, hb_ir_emit_unop(b, HB_IR_CMPXCHG8B, dst, dst), dec);
            return HB_OK;
        }
        case HB_INS_XCHG: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_binop(b, HB_IR_XCHG, dst, dst, src), dec);
            return HB_OK;
        }
        case HB_INS_XADD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_binop(b, HB_IR_XADD, dst, dst, src), dec);
            return HB_OK;
        }
        case HB_INS_AND: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_binop(b, HB_IR_AND, dst, dst, src), dec);
            return HB_OK;
        }
        case HB_INS_OR: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_binop(b, HB_IR_OR, dst, dst, src), dec);
            return HB_OK;
        }
        case HB_INS_XOR: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_binop(b, HB_IR_XOR, dst, dst, src), dec);
            return HB_OK;
        }
        case HB_INS_INC: {
            /* Итерация 389: CF у INC/DEC не меняется — помечаем команду, иначе
             * обычные ADD/SUB его перезапишут. */
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t one = hb_ir_imm(1, dst.size);
            hb_ir_instr_t* ins = emit(b, hb_ir_emit_binop(b, HB_IR_ADD, dst, dst, one), dec);
            if (ins) ins->preserve_cf = true;
            return HB_OK;
        }
        case HB_INS_DEC: {
            /* Итерация 389: CF у INC/DEC не меняется — помечаем команду, иначе
             * обычные ADD/SUB его перезапишут. */
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t one = hb_ir_imm(1, dst.size);
            hb_ir_instr_t* ins = emit(b, hb_ir_emit_binop(b, HB_IR_SUB, dst, dst, one), dec);
            if (ins) ins->preserve_cf = true;
            return HB_OK;
        }
        case HB_INS_SHL:
        case HB_INS_SHR:
        case HB_INS_SAR:
        case HB_INS_ROL:
        case HB_INS_ROR:
        case HB_INS_RCL:
        case HB_INS_RCR: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_op_t ir_op = (dec->opcode == HB_INS_SHL) ? HB_IR_SHL :
                               (dec->opcode == HB_INS_SHR) ? HB_IR_SHR :
                               (dec->opcode == HB_INS_SAR) ? HB_IR_SAR :
                               (dec->opcode == HB_INS_ROL) ? HB_IR_ROL :
                               (dec->opcode == HB_INS_ROR) ? HB_IR_ROR :
                               (dec->opcode == HB_INS_RCL) ? HB_IR_RCL : HB_IR_RCR;
            emit(b, hb_ir_emit_binop(b, ir_op, dst, dst, src), dec);
            return HB_OK;
        }
        case HB_INS_SHLD:
        case HB_INS_SHRD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_operand_t count = operand_from_dec(dec, 3);
            hb_ir_instr_t *i = hb_ir_emit(b, dec->opcode == HB_INS_SHLD ? HB_IR_SHLD : HB_IR_SHRD);
            if (i) { i->dst = dst; i->src1 = src; i->src2 = count; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_NOT: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            emit(b, hb_ir_emit_unop(b, HB_IR_NOT, dst, dst), dec);
            return HB_OK;
        }
        case HB_INS_NEG: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            emit(b, hb_ir_emit_unop(b, HB_IR_NEG, dst, dst), dec);
            return HB_OK;
        }
        case HB_INS_MMX_SRL:
        case HB_INS_MMX_SRA:
        case HB_INS_MMX_SLL: {
            /* Итерация 305: разрядность элемента приходит из декодера в ret_imm. */
            hb_ir_op_t o = dec->opcode == HB_INS_MMX_SRL ? HB_IR_MMX_SRL :
                           dec->opcode == HB_INS_MMX_SRA ? HB_IR_MMX_SRA : HB_IR_MMX_SLL;
            hb_ir_instr_t* i = hb_ir_emit(b, o);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->target = dec->ret_imm;
            }
            emit(b, i, dec);
            return HB_OK;
        }

        case HB_INS_MMX_AND:
        case HB_INS_MMX_ANDN:
        case HB_INS_MMX_OR:
        case HB_INS_MMX_XOR: {
            /* Итерация 304: приёмник он же первый источник, как у x86-логики. */
            hb_ir_op_t o = dec->opcode == HB_INS_MMX_AND  ? HB_IR_MMX_AND  :
                           dec->opcode == HB_INS_MMX_ANDN ? HB_IR_MMX_ANDN :
                           dec->opcode == HB_INS_MMX_OR   ? HB_IR_MMX_OR   : HB_IR_MMX_XOR;
            hb_ir_instr_t* i = hb_ir_emit(b, o);
            if (i) { i->dst = operand_from_dec(dec, 1); i->src1 = operand_from_dec(dec, 2); }
            emit(b, i, dec);
            return HB_OK;
        }

        case HB_INS_MMX_MOV: {
            /* Итерация 303: перенос MMX. Операнды уже расставлены декодером
             * (op1 приёмник, op2 источник), семантика — в интерпретаторе. */
            hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_MMX_MOV);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->target = dec->op1.size ? dec->op1.size : dec->op2.size;
            }
            emit(b, i, dec);
            return HB_OK;
        }

        case HB_INS_CPUID: {
            /* Итерация 302: форма как на стороне x86-64 (hb_lift_x64.c:1985). */
            emit(b, hb_ir_emit(b, HB_IR_CPUID), dec);
            return HB_OK;
        }

        case HB_INS_XGETBV: {
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 937 — парная половина правки
             * декодера (`hb_decode_x86.c`, группа `0F 01`). Декодер один без лифтера дал бы
             * ОТКАЗ вместо реализации — ровно та ветвь, что уже дважды оказывалась мёртвой
             * (итерации 907 и 919: расширил перечисление, не расширив условие вокруг).
             * Форма один в один с x64 (`hb_lift_x64.c:2036`); исполнитель считает XCR0 с
             * учётом разрядности сам (`hb_interpreter.c:5541` → `hb_xcr0_value`), поэтому в
             * 32 битах вернётся 0x3 — x87+SSE, без обещания YMM. */
            emit(b, hb_ir_emit(b, HB_IR_XGETBV), dec);
            return HB_OK;
        }

        case HB_INS_RDTSC: {
            /* Итерация 938: счётчик тактов. Обе ветви поднимают одинаково — работа целиком
             * в исполнителе, потому что источник времени один на процесс. */
            emit(b, hb_ir_emit(b, HB_IR_RDTSC), dec);
            return HB_OK;
        }

        case HB_INS_RDTSCP: {
            emit(b, hb_ir_emit(b, HB_IR_RDTSCP), dec);
            return HB_OK;
        }

        case HB_INS_LAHF: {
            emit(b, hb_ir_emit(b, HB_IR_LAHF), dec);
            return HB_OK;
        }
        case HB_INS_SAHF: {
            emit(b, hb_ir_emit(b, HB_IR_SAHF), dec);
            return HB_OK;
        }
        case HB_INS_CWD: {
            /* CWD / CDQ / CQO — sign-extend EAX/AX/RAX into EDX:EAX/DX:AX/RDX:RAX.
             * op1.size carries the operand size: 2 → CWD, 4 → CDQ, 8 → CQO. */
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_CWD);
            if (i) i->src1 = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_CWDE: {
            /* CBW / CWDE — sign-extend AL into AX (16-bit opsize) or AX into EAX
             * (32-bit opsize). op1.size carries the source width: 1 → CBW (AL→AX),
             * 2 → CWDE (AX→EAX). Implement as SIGN_EXTEND of AX/AL into EAX. */
            hb_size_t src_size = (dec->op1.size == 1) ? HB_SIZE_8 : HB_SIZE_16;
            hb_ir_operand_t src = hb_ir_reg(HB_REG_RAX, src_size);
            hb_ir_operand_t dst = hb_ir_reg(HB_REG_RAX, HB_SIZE_32);
            hb_ir_instr_t *i = hb_ir_emit_unop(b, HB_IR_SIGN_EXTEND, dst, src);
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_IMUL: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_operand_t imm = operand_from_dec(dec, 3);
            if (src.type == HB_OP_NONE)
                emit(b, hb_ir_emit_unop(b, HB_IR_IMUL, hb_ir_none(), dst), dec);
            else if (imm.type != HB_OP_NONE)
                emit(b, hb_ir_emit_binop(b, HB_IR_IMUL, dst, src, imm), dec);
            else
                emit(b, hb_ir_emit_binop(b, HB_IR_IMUL, dst, dst, src), dec);
            return HB_OK;
        }
        case HB_INS_MUL: {
            hb_ir_operand_t src = operand_from_dec(dec, 1);
            emit(b, hb_ir_emit_unop(b, HB_IR_MUL, hb_ir_none(), src), dec);
            return HB_OK;
        }
        case HB_INS_DIV: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_DIV);
            if (i) i->src1 = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_IDIV: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_IDIV);
            if (i) i->src1 = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PUSH: {
            hb_ir_operand_t src = operand_from_dec(dec, 1);
            emit(b, hb_ir_emit_push(b, src), dec);
            return HB_OK;
        }
        case HB_INS_POP: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            emit(b, hb_ir_emit_pop(b, dst), dec);
            return HB_OK;
        }
        case HB_INS_PUSHF: {
            hb_ir_operand_t size_op = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PUSHF);
            if (i) i->src1 = size_op;
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_POPF: {
            hb_ir_operand_t size_op = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_POPF);
            if (i) i->src1 = size_op;
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_LEAVE: {
            hb_ir_operand_t sp = hb_ir_reg(HB_REG_RSP, HB_SIZE_32);
            hb_ir_operand_t bp32 = hb_ir_reg(HB_REG_RBP, HB_SIZE_32);
            hb_ir_operand_t bp = operand_from_dec(dec, 1);

            emit(b, hb_ir_emit_mov(b, sp, bp32), dec);
            emit(b, hb_ir_emit_pop(b, bp), dec);
            return HB_OK;
        }
        case HB_INS_CALL: {
            hb_ir_instr_t *i = hb_ir_emit_call(b, dec->branch_target);
            if (i && dec->op1.present) i->src1 = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_RET: {
            hb_ir_instr_t *i = hb_ir_emit_ret(b);
            if (i && dec->ret_imm) i->src1 = hb_ir_imm(dec->ret_imm, HB_SIZE_16);
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 915 — ПОМЕТКА ШИРИНЫ ВОЗВРАТА.
             * Своего поля под ширину в `hb_ir_instr_t` нет, а ДОБАВЛЯТЬ поля в общие
             * структуры нельзя (итерация 303: такая правка роняла прогон целиком). У `RET`
             * приёмник не используется — кладём пометку туда. Значение 2 читают и
             * интерпретатор, и кодогенератор (последний отводит форму помощнику). */
            if (i && dec->stack_delta == 2) i->dst = hb_ir_imm(2, HB_SIZE_16);
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_JMP: {
            hb_ir_instr_t *i = hb_ir_emit_jmp(b, dec->branch_target);
            if (i && dec->op1.present) i->src1 = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_Jcc: {
            hb_cc_t cc = cc_from_dec(dec->cond);
            emit(b, hb_ir_emit_jcc(b, cc, dec->branch_target), dec);
            return HB_OK;
        }
        case HB_INS_LOOP:
        case HB_INS_JRCXZ: {
            hb_ir_instr_t *i = hb_ir_emit(b, dec->opcode == HB_INS_LOOP ? HB_IR_LOOP : HB_IR_JRCXZ);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->target = dec->branch_target;
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_SETcc: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            emit(b, hb_ir_emit_setcc(b, cc_from_dec(dec->cond), dst), dec);
            return HB_OK;
        }
        case HB_INS_CMOVcc: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_cmovcc(b, cc_from_dec(dec->cond), dst, src), dec);
            return HB_OK;
        }
        case HB_INS_BT:
        case HB_INS_BTS:
        case HB_INS_BTR:
        case HB_INS_BTC: {
            hb_ir_op_t op = HB_IR_BT;
            if (dec->opcode == HB_INS_BTS) op = HB_IR_BTS;
            else if (dec->opcode == HB_INS_BTR) op = HB_IR_BTR;
            else if (dec->opcode == HB_INS_BTC) op = HB_IR_BTC;
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) {
                i->src1 = operand_from_dec(dec, 1);
                i->src2 = operand_from_dec(dec, 2);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MOVZX: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_ZERO_EXTEND);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MOVSX: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_SIGN_EXTEND);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MOVS: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_MOVS);
            if (i) {
                i->rep_prefix = dec->rep_prefix;  /* итерация 491: тот же префикс, отдельным полем */
                i->src1 = operand_from_dec(dec, 1);
                i->src2 = operand_from_dec(dec, 2);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_CMPS: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_CMPS);
            if (i) {
                i->rep_prefix = dec->rep_prefix;  /* итерация 491: тот же префикс, отдельным полем */
                i->src1 = operand_from_dec(dec, 1);
                i->src2 = operand_from_dec(dec, 2);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_LODS: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_LODS);
            if (i) {
                i->rep_prefix = dec->rep_prefix;  /* итерация 491: тот же префикс, отдельным полем */
                i->src1 = operand_from_dec(dec, 1);
                i->src2 = operand_from_dec(dec, 2);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_SCAS: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_SCAS);
            if (i) {
                i->rep_prefix = dec->rep_prefix;  /* итерация 491: тот же префикс, отдельным полем */
                i->src1 = operand_from_dec(dec, 1);
                i->src2 = operand_from_dec(dec, 2);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_STOS: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_STOS);
            if (i) {
                i->rep_prefix = dec->rep_prefix;  /* итерация 491: тот же префикс, отдельным полем */
                i->src1 = operand_from_dec(dec, 1);
                i->src2 = operand_from_dec(dec, 2);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_BSF:
        case HB_INS_TZCNT: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, dec->opcode == HB_INS_BSF ? HB_IR_BSF : HB_IR_TZCNT);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_LZCNT: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_LZCNT);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_BSR: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_BSR);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_BSWAP: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_BSWAP);
            if (i) i->dst = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_CVTDQ2PD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_CVTDQ2PD);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_CVTDQ2PS:
        case HB_INS_CVTPS2DQ:
        case HB_INS_CVTTPS2DQ: {
            hb_ir_op_t op = HB_IR_CVTDQ2PS;
            if (dec->opcode == HB_INS_CVTPS2DQ) op = HB_IR_CVTPS2DQ;
            else if (dec->opcode == HB_INS_CVTTPS2DQ) op = HB_IR_CVTTPS2DQ;
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: сдвиги XMM на непосредственное значение.
         * Эталон — hb_lift_x64.c:1212 и :1237. Отличие 32-битного режима: VEX тут не бывает,
         * поэтому форма всегда двухоперандная — источник совпадает с приёмником, а второй
         * операнд это байт-константа из слота 2. Поле target несёт ширину элемента (2 или 4),
         * как и в x64. */
        case HB_INS_PSRLW:
        case HB_INS_PSRAW:
        case HB_INS_PSLLW:
        case HB_INS_PSRLD:
        case HB_INS_PSRAD:
        case HB_INS_PSLLD: {
            hb_ir_op_t op = HB_IR_PSRL;
            if (dec->opcode == HB_INS_PSRAW || dec->opcode == HB_INS_PSRAD) op = HB_IR_PSRA;
            else if (dec->opcode == HB_INS_PSLLW || dec->opcode == HB_INS_PSLLD) op = HB_IR_PSLL;
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) {
                i->dst = dst;
                hb_istochniki(dec, i);
                i->target = (dec->opcode == HB_INS_PSRLW ||
                             dec->opcode == HB_INS_PSRAW ||
                             dec->opcode == HB_INS_PSLLW) ? 2 : 4;
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PSRLQ:
        case HB_INS_PSLLQ:
        case HB_INS_PSRLDQ:
        case HB_INS_PSLLDQ: {
            hb_ir_op_t op = HB_IR_PSRLDQ;
            if (dec->opcode == HB_INS_PSRLQ) op = HB_IR_PSRLQ;
            else if (dec->opcode == HB_INS_PSLLQ) op = HB_IR_PSLLQ;
            else if (dec->opcode == HB_INS_PSLLDQ) op = HB_IR_PSLLDQ;
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) {
                i->dst = dst;
                hb_istochniki(dec, i);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: семья скалярных преобразований целое<->плавающее.
         * Эталон — hb_lift_x64.c (CVTSI2SD 545, CVTSI2SS 561, CVTSD2SI/CVTTSD2SI 649,
         * CVTSS2SI/CVTTSS2SI 658). Форм VEX в 32-битном режиме тут не бывает, поэтому
         * src2 всегда пуст — в отличие от x64, где есть трёхоперандная форма. */
        case HB_INS_CVTSI2SD:
        case HB_INS_CVTSI2SS: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, dec->opcode == HB_INS_CVTSI2SD
                                             ? HB_IR_CVTSI2SD : HB_IR_CVTSI2SS);
            if (i) { i->dst = dst; i->src1 = src; i->src2 = hb_ir_none(); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_CVTSD2SI:
        case HB_INS_CVTTSD2SI:
        case HB_INS_CVTSS2SI:
        case HB_INS_VCVTTSS2USI:
        case HB_INS_VCVTTSD2USI: {
            /* Беззнаковое усечение — отдельный узел IR, не разновидность
             * знакового: другой диапазон и другое «неопределённое». */
            /* УЗЕЛ ВЫБИРАЛСЯ ТОЛЬКО ИЗ ДВУХ БЕЗЗНАКОВЫХ, хотя ветвь берёт
             * ПЯТЬ команд: знаковые CVTSD2SI/CVTTSD2SI/CVTSS2SI поднимались
             * как беззнаковые. Разница видна ровно при выходе за диапазон:
             * у знаковых «целое неопределённое» это 0x80000000, у
             * беззнаковых — ЕДИНИЦЫ. Замер с оракулом: ожидалось 0x80000000,
             * получали 0xffffffff. Дефект существовал давно; вскрылся, когда
             * размер приёмника стал верным и случай дошёл до сличения. */
            hb_ir_op_t op;
            switch (dec->opcode) {
                case HB_INS_VCVTTSS2USI: op = HB_IR_VCVTTSS2USI; break;
                case HB_INS_VCVTTSD2USI: op = HB_IR_VCVTTSD2USI; break;
                case HB_INS_CVTSD2SI:    op = HB_IR_CVTSD2SI;    break;
                case HB_INS_CVTTSD2SI:   op = HB_IR_CVTTSD2SI;   break;
                default:                 op = HB_IR_CVTSS2SI;    break;
            }
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t* i = hb_ir_emit(b, op);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_CVTTSS2SI: {
            hb_ir_op_t op = HB_IR_CVTSD2SI;
            if (dec->opcode == HB_INS_CVTTSD2SI) op = HB_IR_CVTTSD2SI;
            else if (dec->opcode == HB_INS_CVTSS2SI) op = HB_IR_CVTSS2SI;
            else if (dec->opcode == HB_INS_CVTTSS2SI) op = HB_IR_CVTTSS2SI;
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        /* ★★★★★ MacRunner 2026-08-25 — CVTPS2PD/CVTPD2PS ПОПАДАЛИ В БЛОК СДВИГОВ.
         *
         * Их метки стояли перед `case HB_INS_PSRLW:` и проваливались в обработку сдвигов
         * XMM — команда преобразования выполнялась как сдвиг, приёмник получал мусор.
         * Проверено пробой: `cvtdq2pd` отрабатывал верно (xmm0 = double 4.0 и -2.0), а
         * следом `cvtpd2ps` оставлял xmm1 НУЛЁМ.
         *
         * Что это описка, а не замысел, видно прямо здесь: умолчание ниже — `HB_IR_CVTPS2PD`,
         * и следующей строкой стоит проверка на `HB_INS_CVTPD2PS`, до которой команда при
         * прежних метках не доходила никогда. Обе ветви были мёртвым кодом.
         *
         * SSE2 на пути игр, поэтому цена ошибки не теоретическая. */
        case HB_INS_CVTPS2PD:
        case HB_INS_CVTPD2PS:
        case HB_INS_CVTSS2SD:
        case HB_INS_CVTSD2SS: {
            hb_ir_op_t op = HB_IR_CVTPS2PD;
            if (dec->opcode == HB_INS_CVTPD2PS) op = HB_IR_CVTPD2PS;
            else if (dec->opcode == HB_INS_CVTSS2SD) op = HB_IR_CVTSS2SD;
            else if (dec->opcode == HB_INS_CVTSD2SS) op = HB_IR_CVTSD2SS;
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) {
                i->dst = dst;
                i->src1 = src;
                if (dec->opcode == HB_INS_CVTSS2SD || dec->opcode == HB_INS_CVTSD2SS)
                    i->src2 = hb_ir_none();
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_ADDPS:
        case HB_INS_ADDPD:
        case HB_INS_ADDSS:
        case HB_INS_ADDSD:
        case HB_INS_SUBPS:
        case HB_INS_SUBPD:
        case HB_INS_SUBSS:
        case HB_INS_SUBSD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            bool is_sub = (dec->opcode == HB_INS_SUBPS || dec->opcode == HB_INS_SUBPD ||
                           dec->opcode == HB_INS_SUBSS || dec->opcode == HB_INS_SUBSD);
            hb_ir_instr_t *i = hb_ir_emit(b, is_sub ? HB_IR_FSUB : HB_IR_FADD);
            if (i) {
                unsigned lane = (dec->opcode == HB_INS_ADDPD || dec->opcode == HB_INS_SUBPD ||
                                 dec->opcode == HB_INS_ADDSD || dec->opcode == HB_INS_SUBSD) ? 8 : 4;
                bool scalar = (dec->opcode == HB_INS_ADDSS || dec->opcode == HB_INS_SUBSS ||
                               dec->opcode == HB_INS_ADDSD || dec->opcode == HB_INS_SUBSD);
                i->dst = dst;
                hb_istochniki(dec, i);
                i->target = lane | (scalar ? 0x100 : 0);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MULPS:
        case HB_INS_MULPD:
        case HB_INS_DIVPS:
        case HB_INS_DIVPD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            bool is_div = (dec->opcode == HB_INS_DIVPS || dec->opcode == HB_INS_DIVPD);
            hb_ir_instr_t *i = hb_ir_emit(b, is_div ? HB_IR_FDIV : HB_IR_FMUL);
            if (i) {
                unsigned lane = (dec->opcode == HB_INS_MULPD || dec->opcode == HB_INS_DIVPD) ? 8 : 4;
                i->dst = dst;
                hb_istochniki(dec, i);
                i->target = lane;
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_DIVSD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_DIVSD);
            if (i) { i->dst = dst; hb_istochniki(dec, i); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MULSD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_MULSD);
            if (i) { i->dst = dst; hb_istochniki(dec, i); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_DIVSS: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_DIVSS);
            if (i) { i->dst = dst; hb_istochniki(dec, i); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MULSS: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_MULSS);
            if (i) { i->dst = dst; hb_istochniki(dec, i); }
            emit(b, i, dec);
            return HB_OK;
        }
        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — сравнения SSE в IR.
         *
         * Вид сравнения (imm8) кладём в биты 16..23 аргумента: 0..7 занимает ширина
         * дорожки, бит 8 — скалярность, бит 9 — рассылка, 10..12 — округление
         * (`hb_ir.h:617`). Дорожка и скалярность считаются ровно как у соседнего
         * MIN/MAX, чтобы одна и та же запись читалась обоими исполнителями. */
        /* СНЯТО 04.09.2026: SSE3, перекладка MMX<->XMM, запись по маске и
         * преобразования MMX<->плавающее ПЕРЕЕХАЛИ в общий текст
         * (`hb_lift_vec_obshchee.inc`, hb_vek_osobye). Здесь они жили только
         * на этой ветви, а на x64 их не было ВОВСЕ — тот самый вид отставания,
         * от которого общий текст и заведён. Дубликата не оставляем: две копии
         * одного разбора — это и есть механизм отставания. */
        case HB_INS_CMPPS:
        case HB_INS_CMPPD:
        case HB_INS_CMPSS:
        case HB_INS_CMPSD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_FCMP_MASK);
            if (i) {
                unsigned lane = (dec->opcode == HB_INS_CMPPD ||
                                 dec->opcode == HB_INS_CMPSD) ? 8 : 4;
                bool scalar = (dec->opcode == HB_INS_CMPSS ||
                               dec->opcode == HB_INS_CMPSD);
                i->dst = dst;
                hb_istochniki(dec, i);
                i->target = lane | (scalar ? 0x100u : 0u) |
                            (((uint64_t)dec->op3.imm & 0xffu) << 16);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MINPS:
        case HB_INS_MAXPS:
        case HB_INS_MINPD:
        case HB_INS_MAXPD:
        case HB_INS_MINSS:
        case HB_INS_MAXSS:
        case HB_INS_MINSD:
        case HB_INS_MAXSD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, (dec->opcode == HB_INS_MAXPS ||
                                             dec->opcode == HB_INS_MAXPD ||
                                             dec->opcode == HB_INS_MAXSS ||
                                             dec->opcode == HB_INS_MAXSD) ? HB_IR_FMAX : HB_IR_FMIN);
            if (i) {
                unsigned lane = (dec->opcode == HB_INS_MINPD || dec->opcode == HB_INS_MAXPD ||
                                 dec->opcode == HB_INS_MINSD || dec->opcode == HB_INS_MAXSD) ? 8 : 4;
                bool scalar = (dec->opcode == HB_INS_MINSS || dec->opcode == HB_INS_MAXSS ||
                               dec->opcode == HB_INS_MINSD || dec->opcode == HB_INS_MAXSD);
                i->dst = dst;
                hb_istochniki(dec, i);
                i->target = lane | (scalar ? 0x100 : 0);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_COMISS:
        case HB_INS_COMISD: {
            hb_ir_operand_t lhs = operand_from_dec(dec, 1);
            hb_ir_operand_t rhs = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, dec->opcode == HB_INS_COMISD ? HB_IR_COMISD : HB_IR_COMISS);
            if (i) { i->src1 = lhs; i->src2 = rhs; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_NOP: {
            emit(b, hb_ir_emit(b, HB_IR_NOP), dec);
            return HB_OK;
        }
        /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1066 — БАРЬЕРЫ ПАМЯТИ НА i386.
         *
         * Декодер их разбирал (`hb_decode_x86.c:1664`, `0F AE /5,/6,/7` -> `HB_INS_FENCE`
         * с видом барьера в непосредственном), интерпретатор их исполнял
         * (`hb_interpreter.c:3693`), а случая в ЭТОМ лифтере не было — и команда падала с
         * `HB_ERR_UNSUPPORTED_OPCODE`. Ровно тот же класс, что записан в памяти проекта:
         * семантика живёт в двух местах, правка одной копии даёт рассинхронизацию.
         *
         * Замер до правки (`0faef8`, `sfence`, тот же вызов, что и сплошной перебор):
         * `interp_error:0/-5`. Ветвь x64 этот случай имеет с самого начала
         * (`hb_lift_x64.c:2368`) — переношу буква в букву.
         *
         * Цена в настоящем коде не теоретическая: `sfence`/`lfence`/`mfence` стоят в любом
         * коде без блокировок — CRT, распределители, Mono. */
        /* Итерация 1075: регистр режима SSE. Приёмник/источник — память, как у слова x87. */
        /* Итерация 1080: образ таблицы дескрипторов — приёмник в памяти. */
        /* Итерация 1081: `UD2` и родня — недопустимая команда по спецификации, а не наш
         * пробел. Поднимаем отказ ОТДЕЛЬНОГО вида, чтобы сторона wine отдала гостю
         * `c000001d`, а не убивала поток «неподдержанным опкодом». */
        case HB_INS_UD:
            /* Гейт снят 02.09.2026: выключенная ветка отдавала «неподдержанный опкод»
             * (или NOP) на команде, которая разобрана верно, — это заведомо сломанное
             * поведение, и держать его за выключателем незачем. Разбираем всегда. */
            emit(b, hb_ir_emit_fault_illegal(b, "UD2/undefined opcode"), dec);
            return HB_OK;
        /* Итерация 1095: шесть привилегированных получили свои имена; поведение прежнее —
         * тот же отказ по привилегиям, что и у общего `HB_INS_PRIV`. */
        case HB_INS_LLDT:
        case HB_INS_LTR:
        case HB_INS_LGDT:
        case HB_INS_LIDT:
        case HB_INS_LMSW:
        case HB_INS_INVLPG:
            emit(b, hb_ir_emit_fault_priv(b, "privileged descriptor-table instruction"), dec);
            return HB_OK;
        case HB_INS_SGDT:
            emit(b, hb_ir_emit_unop(b, HB_IR_SGDT, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_SIDT:
            emit(b, hb_ir_emit_unop(b, HB_IR_SIDT, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_LDMXCSR:
            emit(b, hb_ir_emit_unop(b, HB_IR_LDMXCSR, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_STMXCSR:
            emit(b, hb_ir_emit_unop(b, HB_IR_STMXCSR, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_FENCE: {
            /* Гейт снят 02.09.2026: выключенная ветка отдавала «неподдержанный опкод»
             * (или NOP) на команде, которая разобрана верно, — это заведомо сломанное
             * поведение, и держать его за выключателем незачем. Разбираем всегда. */
            emit(b, hb_ir_emit_fence(b, (hb_fence_kind_t)dec->op1.imm), dec);
            return HB_OK;
        }
        case HB_INS_X87_FLD:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FLD, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FST:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FST, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_X87_FSTP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FSTP, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        /* Итерация 906: семья `FI` — операнд в памяти ЦЕЛЫЙ, вид действия во втором операнде
         * (`reg_op`, положен декодером). До этой правки для опкода не было ветви вовсе, и
         * восемь команд отказывали `-5` у обоих исполнителей. */
        case HB_INS_X87_FI:
            emit(b, hb_ir_emit_binop(b, HB_IR_X87_FI, hb_ir_none(),
                                     operand_from_dec(dec, 1), operand_from_dec(dec, 2)), dec);
            return HB_OK;
        case HB_INS_X87_FILD:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FILD, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FISTP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FISTP, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        /* Итерация 887: перенос из лифтера x64 (там добавлено итерацией 350). Операция IR общая,
         * интерпретатор её знает; приёмник в памяти — как у FISTP выше. Каждый case здесь со
         * своим return, поэтому вставка между ними провал не разрывает (урок 886). */
        case HB_INS_X87_FISTTP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FISTTP, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_X87_FIST:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FIST, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_X87_FLDCW:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FLDCW, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FNSTCW:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FNSTCW, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_X87_FNSTSW:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FNSTSW, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_X87_FLDENV:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FLDENV, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        /* Итерация 1047: BCD 80 бит. FBLD читает память и кладёт в стек x87,
         * FBSTP пишет и снимает — как FILD/FISTP, только формат другой. */
        case HB_INS_X87_FBLD:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FBLD, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FBSTP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FBSTP, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_X87_FNSTENV:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FNSTENV, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_X87_FRSTOR:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FRSTOR, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FNSAVE:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FNSAVE, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_X87_FXSAVE:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FXSAVE, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_X87_FXRSTOR:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FXRSTOR, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FADD:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FADD, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FMUL:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FMUL, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FCOM:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FCOM, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FCOMP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FCOMP, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FSUB:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FSUB, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FSUBR:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FSUBR, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FDIV:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FDIV, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FDIVR:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FDIVR, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FADDP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FADDP, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FMULP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FMULP, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FCOMPP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FCOMPP, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FSUBP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FSUBP, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FSUBRP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FSUBRP, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FDIVP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FDIVP, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FDIVRP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FDIVRP, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FXCH:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FXCH, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FRNDINT:
            emit(b, hb_ir_emit(b, HB_IR_X87_FRNDINT), dec);
            return HB_OK;
        case HB_INS_X87_FINCSTP:
            emit(b, hb_ir_emit(b, HB_IR_X87_FINCSTP), dec);
            return HB_OK;
        case HB_INS_X87_FDECSTP:
            emit(b, hb_ir_emit(b, HB_IR_X87_FDECSTP), dec);
            return HB_OK;
        case HB_INS_X87_FUCOM:
        case HB_INS_X87_FUCOMP:
        case HB_INS_X87_FUCOMI:
        case HB_INS_X87_FUCOMPI:
        case HB_INS_X87_FCOMI:
        case HB_INS_X87_FCOMPI:
            /* FUCOM/FUCOMP/FUCOMI/FUCOMPI: unordered compares (set C0/C2/C3
             * to 111 for NaN; the regular FCOM does NOT do that, FUCOM does).
             * FCOMI/FCOMIP/FUCOMI/FUCOMIP also write EFLAGS (gap matrix #8
             * now closed: FCOMI-family is wired through dedicated IR ops
             * HB_IR_X87_FCOMI/FUCOMI/FCOMIP/FUCOMIP that write EFLAGS). */
            {
                int op = (int)dec->opcode;
                hb_ir_op_t ir;
                switch (op) {
                    case (int)HB_INS_X87_FUCOM:   ir = HB_IR_X87_FUCOM;   break;
                    case (int)HB_INS_X87_FUCOMP:  ir = HB_IR_X87_FUCOMP;  break;
                    case (int)HB_INS_X87_FUCOMI:  ir = HB_IR_X87_FUCOMI;  break;
                    case (int)HB_INS_X87_FUCOMPI: ir = HB_IR_X87_FUCOMIP; break;
                    case (int)HB_INS_X87_FCOMI:   ir = HB_IR_X87_FCOMI;   break;
                    case (int)HB_INS_X87_FCOMPI:  ir = HB_IR_X87_FCOMIP;  break;
                    default: return HB_ERR_INTERNAL;
                }
                emit(b, hb_ir_emit_unop(b, ir, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            }
            return HB_OK;
        case HB_INS_X87_FNCLEX:
            emit(b, hb_ir_emit(b, HB_IR_X87_FNCLEX), dec);
            return HB_OK;
        case HB_INS_X87_FNINIT:
            emit(b, hb_ir_emit(b, HB_IR_X87_FNINIT), dec);
            return HB_OK;
        case HB_INS_X87_EMMS:   /* итерация 520 */
            emit(b, hb_ir_emit(b, HB_IR_X87_EMMS), dec);
            return HB_OK;
        case HB_INS_X87_FXAM:
            emit(b, hb_ir_emit(b, HB_IR_X87_FXAM), dec);
            return HB_OK;
        case HB_INS_X87_FSQRT:
            emit(b, hb_ir_emit(b, HB_IR_X87_FSQRT), dec);
            return HB_OK;
        case HB_INS_X87_F2XM1:
            emit(b, hb_ir_emit(b, HB_IR_X87_F2XM1), dec);
            return HB_OK;
        case HB_INS_X87_FYL2X:
            emit(b, hb_ir_emit(b, HB_IR_X87_FYL2X), dec);
            return HB_OK;
        case HB_INS_X87_FPTAN:
            emit(b, hb_ir_emit(b, HB_IR_X87_FPTAN), dec);
            return HB_OK;
        case HB_INS_X87_FPATAN:
            emit(b, hb_ir_emit(b, HB_IR_X87_FPATAN), dec);
            return HB_OK;
        case HB_INS_X87_FXTRACT:
            emit(b, hb_ir_emit(b, HB_IR_X87_FXTRACT), dec);
            return HB_OK;
        case HB_INS_X87_FPREM1:
            emit(b, hb_ir_emit(b, HB_IR_X87_FPREM1), dec);
            return HB_OK;
        case HB_INS_X87_FPREM:
            emit(b, hb_ir_emit(b, HB_IR_X87_FPREM), dec);
            return HB_OK;
        case HB_INS_X87_FYL2XP1:
            emit(b, hb_ir_emit(b, HB_IR_X87_FYL2XP1), dec);
            return HB_OK;
        case HB_INS_X87_FSINCOS:
            emit(b, hb_ir_emit(b, HB_IR_X87_FSINCOS), dec);
            return HB_OK;
        case HB_INS_X87_FSCALE:
            emit(b, hb_ir_emit(b, HB_IR_X87_FSCALE), dec);
            return HB_OK;
        case HB_INS_X87_FSIN:
            emit(b, hb_ir_emit(b, HB_IR_X87_FSIN), dec);
            return HB_OK;
        case HB_INS_X87_FCOS:
            emit(b, hb_ir_emit(b, HB_IR_X87_FCOS), dec);
            return HB_OK;
        case HB_INS_X87_FNOP:
            /* FNOP — FPU no-op. No state change. */
            emit(b, hb_ir_emit(b, HB_IR_X87_FNOP), dec);
            return HB_OK;
        case HB_INS_X87_FCHS:
            /* FCHS — complement sign of ST(0). */
            emit(b, hb_ir_emit(b, HB_IR_X87_FCHS), dec);
            return HB_OK;
        case HB_INS_X87_FABS:
            /* FABS — clear sign of ST(0). */
            emit(b, hb_ir_emit(b, HB_IR_X87_FABS), dec);
            return HB_OK;
        case HB_INS_X87_FTST:
            /* FTST — compare ST(0) to +0.0, set C0/C2/C3 in FPU SW. */
            emit(b, hb_ir_emit(b, HB_IR_X87_FTST), dec);
            return HB_OK;
        case HB_INS_X87_FFREE: {
            /* ★ 30.08: было NOP — и это стоило установщика. См. hb_x87_ffree(). */
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_X87_FFREE);
            if (i) i->src1 = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_X87_MISC:
            /* Safety net: should be unreachable now that FNOP/FCHS/FABS/FTST
             * are split out into their own opcodes. If we ever land here,
             * a newly added x87 instruction needs a case above. */
            emit(b, hb_ir_emit(b, HB_IR_NOP), dec);  /* stand-in */
            return HB_OK;
        case HB_INS_X87_FFREEP: {
            /* FFREEP ST(i) = освободить ST(i) И снять со стека. Снятие здесь —
             * это ровно сдвиг вершины (значения FFREE уже не принадлежат), то есть
             * FINCSTP. Пары хватает, отдельной операции не нужно. */
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_X87_FFREE);
            if (i) i->src1 = operand_from_dec(dec, 1);
            emit(b, i, dec);
            emit(b, hb_ir_emit(b, HB_IR_X87_FINCSTP), dec);
            return HB_OK;
        }
        case HB_INS_X87_FCMOV:
            /* FCMOVcc ST, ST(i): conditional move based on EFLAGS. Model
             * as NOP since condition code is not yet tracked per FCMOV
             * variant. NOTE: this used to be HB_IR_X87_FNINIT. */
            emit(b, hb_ir_emit(b, HB_IR_NOP), dec);
            return HB_OK;
        case HB_INS_PUSHA: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PUSHA);
            if (i) i->src1 = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_POPA: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_POPA);
            if (i) i->dst = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_AAA:
            emit(b, hb_ir_emit(b, HB_IR_AAA), dec);
            return HB_OK;
        case HB_INS_AAS:
            emit(b, hb_ir_emit(b, HB_IR_AAS), dec);
            return HB_OK;
        case HB_INS_AAM: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_AAM);
            if (i) i->src1 = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_AAD: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_AAD);
            if (i) i->src1 = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_DAA:
            emit(b, hb_ir_emit(b, HB_IR_DAA), dec);
            return HB_OK;
        case HB_INS_DAS:
            emit(b, hb_ir_emit(b, HB_IR_DAS), dec);
            return HB_OK;
        case HB_INS_BOUND: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_BOUND);
            if (i) { i->dst = operand_from_dec(dec, 1); i->src1 = operand_from_dec(dec, 2); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_ARPL: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_ARPL);
            if (i) { i->dst = operand_from_dec(dec, 1); i->src1 = operand_from_dec(dec, 2); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_LDS: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_LDS);
            if (i) { i->dst = operand_from_dec(dec, 1); i->src1 = operand_from_dec(dec, 2); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_LES: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_LES);
            if (i) { i->dst = operand_from_dec(dec, 1); i->src1 = operand_from_dec(dec, 2); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_LFS: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_LFS);
            if (i) { i->dst = operand_from_dec(dec, 1); i->src1 = operand_from_dec(dec, 2); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_LGS: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_LGS);
            if (i) { i->dst = operand_from_dec(dec, 1); i->src1 = operand_from_dec(dec, 2); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PUSH_SEG: {
            /* op1.size = element size, op2.imm = segment selector. */
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PUSH_SEG);
            if (i) {
                i->src1 = operand_from_dec(dec, 1);
                i->src2 = operand_from_dec(dec, 2);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_POP_SEG: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_POP_SEG);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src2 = operand_from_dec(dec, 2);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_CLC:
            emit(b, hb_ir_emit(b, HB_IR_CLC), dec);
            return HB_OK;
        case HB_INS_STC:
            emit(b, hb_ir_emit(b, HB_IR_STC), dec);
            return HB_OK;
        case HB_INS_CMC:
            emit(b, hb_ir_emit(b, HB_IR_CMC), dec);
            return HB_OK;
        case HB_INS_CLD:
            emit(b, hb_ir_emit(b, HB_IR_CLD), dec);
            return HB_OK;
        case HB_INS_STD:
            emit(b, hb_ir_emit(b, HB_IR_STD), dec);
            return HB_OK;
        case HB_INS_CLI:
            emit(b, hb_ir_emit(b, HB_IR_CLI), dec);
            return HB_OK;
        case HB_INS_STI:
            emit(b, hb_ir_emit(b, HB_IR_STI), dec);
            return HB_OK;





        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — дальние переходы, все четыре формы.
         * `target`: бит0 — это вызов (класть возврат на стек), бит1 — операнды в
         * памяти, а не непосредственные. Для формы с памятью адрес приходит в src1
         * как обычный операнд памяти: там лежат смещение (4 байта) и селектор (2). */
        /* Привилегированные и системные: разбор верен, исполнить не можем.
         * Честный отказ с именем причины лучше тихого «успеха» — так гость
         * получит исключение там же, где настоящая машина сменила бы кольцо. */
        case HB_INS_SYS_PRIV: {
            /* Гость обязан получить ИСКЛЮЧЕНИЕ в свой обработчик, а не наш
             * внутренний отказ: на железе привилегированная команда в кольце 3
             * даёт #GP, то есть `0xC0000096` (STATUS_PRIVILEGED_INSTRUCTION).
             * `hb_ir_emit_fault_priv` ставит вид 3, который сторона wine
             * доставляет именно так (см. итерацию 939). */
            emit(b, hb_ir_emit_fault_priv(b, "привилегированная или системная команда"), dec);
            return HB_OK;
        }
        case HB_INS_UNAVAILABLE_EXT: {
            /* Расширение, которого на этой машине нет (SSE4a — только AMD). Гость
             * узнаёт о нём из CPUID, мы его не объявляем, поэтому правильный ответ
             * железа — #UD, то есть `c000001d`. Разбор при этом честный: длина
             * верна, поток команд не рассыпается. */
            emit(b, hb_ir_emit_fault_illegal(b, "расширение недоступно на этой машине"), dec);
            return HB_OK;
        }
        case HB_INS_CALL_FAR_IMM:
        case HB_INS_JMP_FAR_IMM: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_FAR_BRANCH);
            if (i) {
                i->src1 = hb_ir_imm((int64_t)dec->op1.imm, HB_SIZE_32);
                i->src2 = hb_ir_imm((int64_t)dec->op2.imm, HB_SIZE_16);
                i->target = (dec->opcode == HB_INS_CALL_FAR_IMM) ? 1u : 0u;
            }
            emit(b, i, dec);
            return HB_OK;
        }

        case HB_INS_SALC: {
            /* SALC (undocumented 0xD6): AL = 0xFF if CF=1 else 0x00.
             * Implemented as SETB AL. */
            hb_ir_operand_t al = hb_ir_reg(HB_REG_RAX, HB_SIZE_8);
            emit(b, hb_ir_emit_setcc(b, HB_CC_B, al), dec);
            return HB_OK;
        }
        case HB_INS_ENTER: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_ENTER);
            if (i) {
                i->src1 = operand_from_dec(dec, 1);
                i->src2 = operand_from_dec(dec, 2);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_HLT:
            /* Privileged: lift as fault so the user knows. */
            emit(b, hb_ir_emit_fault_priv(b, "HLT in user-mode guest"), dec);
            return HB_OK;
        case HB_INS_MOV_CR:
        case HB_INS_MOV_DR:
            /* Privileged: in 32-bit user mode, MOV CRn/DRn raises #GP(0).
             * Lift as fault so the runtime can translate it correctly. */
            emit(b, hb_ir_emit_fault_priv(b,
                (dec->opcode == HB_INS_MOV_CR) ? "MOV CRn in user-mode guest"
                                               : "MOV DRn in user-mode guest"),
                dec);
            return HB_OK;
        case HB_INS_VERR:
        case HB_INS_VERW: {
            hb_ir_instr_t* i = hb_ir_emit(b, dec->opcode == HB_INS_VERR ? HB_IR_VERR : HB_IR_VERW);
            if (i) i->src1 = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }

        case HB_INS_PRIV:
            emit(b, hb_ir_emit_fault_priv(b, "privileged instruction in user-mode guest"), dec);
            return HB_OK;
        case HB_INS_IN:
            /* Privileged port I/O. Lift as fault. */
            emit(b, hb_ir_emit_fault_priv(b, "IN port I/O in user-mode guest"), dec);
            return HB_OK;
        case HB_INS_OUT:
            emit(b, hb_ir_emit_fault_priv(b, "OUT port I/O in user-mode guest"), dec);
            return HB_OK;
        case HB_INS_INS:
        case HB_INS_OUTS:
            /* String port I/O (INSB/INSW/INSD/OUTSB/OUTSW/OUTSD). Privileged;
             * lift as fault. */
            emit(b, hb_ir_emit_fault_priv(b,
                (dec->opcode == HB_INS_INS) ? "INS port I/O in user-mode guest"
                                            : "OUTS port I/O in user-mode guest"), dec);
            return HB_OK;
        default:
            /* ПРЕЖДЕ ЧЕМ СДАТЬСЯ — спросить общий список. Раньше сюда
             * приходили 145 векторных команд, которые ветвь x64 поднимает
             * без запинки: список case здесь просто отставал, и дописывать
             * его руками значило заводить отставание заново. Теперь путь
             * открывает САМ список: добавленное однажды служит обеим
             * ветвям, дописывать нечего. */
            /* Сравнение EVEX с приёмником-маской — ПЕРВЫМ: у него свой
             * узел, и общий список векторных его не знает. Прежде дверь
             * стояла только в отдельной ветви, куда VCMPPS не доходит, и
             * команда падала в «не умею» (замер: у x64 result=0 и маска
             * менялась, у i386 result=-1 и ни одна). */
            {
                hb_result_t itog_k2;
                if (hb_evex_cmp_mask(dec, b, &itog_k2)) return itog_k2;
            }
            {
                hb_result_t itog_s;
                if (hb_sist_obshchee(dec, b, &itog_s)) return itog_s;
            }
            {
                hb_result_t itog;
                if (hb_vek_osobye(dec, b, &itog)) return itog;
            }
            if (vec_op_from_ins(dec->opcode) != 0)
                return hb_vek_obshchij(dec, b);
            emit(b, hb_ir_emit_unsupported(b, hb_opcode_name(dec->opcode), dec->addr,
                                    (uint8_t*)dec->bytes, dec->len), dec);
            return HB_ERR_UNSUPPORTED_FEATURE;
    }
}

/* MacRunner 2026-08-24, лейн ЕДИНИЦА — ПЕРЕПИСЬ ЦЕЛЕЙ УСЛОВНОГО ПЕРЕХОДА (п.3 наряда).
 *
 * Вопрос: у какой доли jcc ОБЕ цели лежат в окне декодирования. Это оценка сверху на то,
 * что способно поглотить укрупнение единицы трансляции, не расширяя декодирование.
 *
 * Почему окно, а не «уже переведённый кусок»: второе — состояние кеша блоков на момент
 * трансляции, то есть рантайм, гонка и зависимость от порядка. Итерация 11 на этом уже
 * обожглась (набор из кеша оказался неполным на 71,8 % и смещённым). Окно локально,
 * известно тут же и воспроизводимо между прогонами.
 *
 * Печать БЕЗУСЛОВНАЯ по выходу процесса, без потолка «первые N»: доля из потолка не
 * получается в принципе (итерация 10). Счётчики атомарные — лифтер зовётся из нескольких
 * потоков. Гейт MACRUNNER_EDINICA_JCC, умолчание ВЫКЛ. */
#include <stdio.h>

static unsigned long long g_ed_blocks, g_ed_jcc, g_ed_ft_in, g_ed_tg_in, g_ed_both_in;
/* итерация 18: корзины по РАССТОЯНИЮ до взятой цели от начала окна.
 * Нужны, чтобы выбрать радиус правки: 89,4 % измерены при окне 4096, а разумная
 * правка захочет меньше. Знак важен: цель ПЕРЕД началом окна (обратный переход,
 * цикл) в окно не попадает по построению. */
static unsigned long long g_ed_d[7];  /* назад | 0..63 | 64..255 | 256..1023 | 1024..4095 | >=4096 | цель<база */
static int g_ed_on = -1;

static void ed_report(void) {
    fprintf(stderr,
            "macrunner-edinica-jcc: блоков=%llu jcc=%llu провал_в_окне=%llu цель_в_окне=%llu обе_в_окне=%llu\n",
            (unsigned long long)__atomic_load_n(&g_ed_blocks, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_ed_jcc, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_ed_ft_in, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_ed_tg_in, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_ed_both_in, __ATOMIC_RELAXED));
    fprintf(stderr,
            "macrunner-edinica-dist: назад=%llu 0_63=%llu 64_255=%llu 256_1023=%llu 1024_4095=%llu вперёд_4096=%llu\n",
            (unsigned long long)__atomic_load_n(&g_ed_d[0], __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_ed_d[1], __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_ed_d[2], __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_ed_d[3], __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_ed_d[4], __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_ed_d[5], __ATOMIC_RELAXED));
    fflush(stderr);
}

static void ed_note(const hb_decoder_t* dec, const hb_decoded_t* d) {
    uint64_t lo, hi, ft, tg;
    int fi, ti;
    if (g_ed_on < 0) {
        const char* v = hb_gate( HB_GATE_EDINICA_JCC );
        g_ed_on = (v && *v && *v != '0') ? 1 : 0;
        if (g_ed_on) atexit(ed_report);
    }
    if (!g_ed_on || !dec || !d) return;
    {
        /* итерация 35: печать НЕ ТОЛЬКО по atexit. Мишень Diablo снимают по бюджету, и
         * atexit не срабатывает — прогон ed1 доставил гейт (улика в КОНФИГУРАЦИЯ.txt),
         * а переписи дал НОЛЬ строк. Печатаем на степенях двойки, как соседние приборы. */
        unsigned long long n = __atomic_add_fetch(&g_ed_blocks, 1, __ATOMIC_RELAXED);
        if ((n & (n - 1)) == 0 || (n & 1023u) == 0) ed_report();  /* итерация 38: порог 1024 был выше масштаба мишени (826 диспетчеризаций) */
    }
    if (!d->is_conditional) return;
    lo = dec->base_addr;
    hi = dec->base_addr + (uint64_t)dec->code_len;
    ft = dec->base_addr + (uint64_t)dec->pos;   /* провал: позиция ПОСЛЕ разобранной команды */
    tg = d->branch_target;                      /* взятая цель, уже разрешённая декодером */
    fi = (ft >= lo && ft < hi);
    ti = (tg >= lo && tg < hi);
    __atomic_add_fetch(&g_ed_jcc, 1, __ATOMIC_RELAXED);
    if (fi) __atomic_add_fetch(&g_ed_ft_in, 1, __ATOMIC_RELAXED);
    if (ti) __atomic_add_fetch(&g_ed_tg_in, 1, __ATOMIC_RELAXED);
    if (fi && ti) __atomic_add_fetch(&g_ed_both_in, 1, __ATOMIC_RELAXED);
    {
        int k;
        if (tg < lo)              k = 0;                     /* назад, до начала окна */
        else {
            uint64_t off = tg - lo;
            if      (off < 64u)   k = 1;
            else if (off < 256u)  k = 2;
            else if (off < 1024u) k = 3;
            else if (off < 4096u) k = 4;
            else                  k = 5;                     /* вперёд за окно */
        }
        __atomic_add_fetch(&g_ed_d[k], 1, __ATOMIC_RELAXED);
    }
}

/* ЕДИНИЦА, итерация 46 — ЧАСТЬ А наряда: продолжать единицу трансляции ЗА условный переход.
 *
 * Почему это законно само по себе: у условного перехода ВСЕГДА есть провал, и декодировать
 * его дальше — та же работа, что декодировать следующий блок, только без выхода в диспетчер.
 * Цель «в окне» здесь НЕ требуется: она решает, окупится ли слияние, а не можно ли его делать.
 *
 * Что эта часть НЕ делает. Кодогенератор пока обрывает выпуск на первом переходе
 * (hb_arm64_codegen.c:15712, codegen_instr_limit_before_fallthrough), поэтому выпущенный код
 * НЕ меняется: команды за переходом просто не выпускаются. Это сделано намеренно — часть А
 * безопасна по построению и служит ЗАМЕРОМ: сколько раз единицу удалось бы удлинить и
 * насколько. Часть Б (настоящий b.cond на внутреннюю метку) идёт отдельно, после замера.
 *
 * Одно последствие всё же есть, и его надо знать: длина блока входит в ключ кеша трансляций
 * (block_guest_span -> hb_cache_key_compute), поэтому при включённом гейте ключи другие.
 * Гейт MACRUNNER_HB_MERGE_BLOCKS, умолчание ВЫКЛ; предел MACRUNNER_HB_MERGE_MAX, умолчание 4. */
static int g_mg_on = -1;
static int g_mg_max = 4;
static uint64_t g_mg_blocks, g_mg_merges, g_mg_tgt_in, g_mg_hist[9];

static void mg_report(void) {
    unsigned i;
    if (!g_mg_blocks && !g_mg_merges) return;
    fprintf(stderr, "macrunner-edinica-merge: blokov_prodleno=%llu sliyanii=%llu cel_v_okne=%llu (%.2f %%) gist=",
            (unsigned long long)g_mg_blocks, (unsigned long long)g_mg_merges,
            (unsigned long long)g_mg_tgt_in,
            g_mg_merges ? 100.0 * (double)g_mg_tgt_in / (double)g_mg_merges : 0.0);
    for (i = 0; i < 9; i++) fprintf(stderr, "%s%llu", i ? "/" : "", (unsigned long long)g_mg_hist[i]);
    fprintf(stderr, "\n");
    fflush(stderr);
}

static int mg_enabled(void) {
    if (g_mg_on < 0) {
        const char* v = hb_gate( HB_GATE_HB_MERGE_BLOCKS );
        const char* m = hb_gate( HB_GATE_HB_MERGE_MAX );
        g_mg_max = (m && *m) ? atoi(m) : 4;
        if (g_mg_max < 0) g_mg_max = 0;
        g_mg_on = (v && *v && *v != '0') ? 1 : 0;
        if (g_mg_on) atexit(mg_report);
    }
    return g_mg_on;
}

/* ★★★★★ MacRunner 2026-09-04 — РЕШЕНИЕ «ПРОДЛЕВАТЬ ЛИ ЕДИНИЦУ» ОДНО НА ОБЕ ВЕТВИ.
 *
 * ЗАЧЕМ ОТДЕЛЬНОЙ ФУНКЦИЕЙ. До сегодня часть А слияния (продление единицы за условный
 * переход) была написана ТОЛЬКО в лифтере i386, а лифтер x64 обрывал единицу на первом
 * же переходе (hb_lift_x64.c, «For MVP: single basic block per function»). Ответ на вопрос
 * задания «почему слияние не применяется у x64» — вот он: его туда просто не переносили.
 * Копировать сюда второй экземпляр правил нельзя: сегодня же в этом дереве нашлась пара
 * разошедшихся двоичных поисков (hb_fault.c против hb_runtime.c), где расхождение не ловил
 * ни один счётчик. Поэтому правило одно, а зовут его оба лифтера.
 *
 * УСЛОВИЯ, И ПОЧЕМУ ИМЕННО ТАКИЕ:
 *   • только УСЛОВНЫЙ переход: у безусловного перехода, вызова и возврата провала нет,
 *     и декодировать дальше значило бы поднимать чужой код;
 *   • провал обязан лежать В ОКНЕ разбора, иначе за ним ничего не прочитать;
 *   • глубина ограничена MACRUNNER_HB_MERGE_MAX (умолчание 4);
 *   • не сливать через адрес, на который УЖЕ переходили извне: провал станет внутренностью
 *     единицы, а кеш блоков ищет строго по адресу входа и такого входа не найдёт — хвост
 *     переведётся второй раз. Замер по кешу: при глубине 4 внутрь единицы попадает 31-62 %
 *     начал блоков (гейт MACRUNNER_HB_MERGE_CUT_AT_ENTRY, умолчание ВЫКЛ с 02.09.2026, hb_ir.c:
 *     резать надо ЯВНО включив его вместе со слиянием).
 *
 * Возврат 1 = продлевать. Счётчики ведёт сама функция, поэтому «слияний 0» отличимо от
 * «никто не спрашивал»: g_mg_merges растёт только здесь. */
int hb_lift_edinica_prodlit(const hb_decoder_t* dec, const hb_decoded_t* d, size_t merged) {
    uint64_t tg;
    if (!dec || !d) return 0;
    if (!mg_enabled()) return 0;
    if (!d->is_conditional) return 0;
    if ((int)merged >= g_mg_max) return 0;
    if (dec->pos >= dec->code_len) return 0;
    if (hb_known_entry_is(dec->base_addr + (uint64_t)dec->pos)) return 0;
    tg = d->branch_target;
    if (tg >= dec->base_addr && tg - dec->base_addr < (uint64_t)dec->code_len)
        __atomic_add_fetch(&g_mg_tgt_in, 1, __ATOMIC_RELAXED);
    if (merged == 0) __atomic_add_fetch(&g_mg_blocks, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&g_mg_merges, 1, __ATOMIC_RELAXED);
    return 1;
}

hb_result_t hb_lift_func_x86(hb_decoder_t* dec, hb_ir_func_t** out) {
    if (!dec || !out) return HB_ERR_INVALID_ARG;

    hb_ir_func_t* func = hb_ir_func_create(dec->base_addr, dec->code_len);
    if (!func) return HB_ERR_OUT_OF_MEMORY;

    hb_ir_block_t* block = hb_ir_block_create(0, dec->base_addr);
    if (!block) {
        hb_ir_func_destroy(func);
        return HB_ERR_OUT_OF_MEMORY;
    }
    hb_ir_cfg_add_block(func->cfg, block);
    func->cfg->entry = block;

    hb_ir_builder_t* b = hb_ir_builder_create(func);
    if (!b) {
        hb_ir_func_destroy(func);
        return HB_ERR_OUT_OF_MEMORY;
    }
    hb_ir_builder_set_block(b, block);

    hb_decoded_t d;
    size_t count = 0;
    const size_t instr_limit = 10000;
    size_t merged = 0;
    while (hb_decode_next(dec, &d) == HB_OK || d.opcode == HB_INS_UNSUPPORTED) {
        size_t pre_instr = block->instr_count;
        hb_result_t r = hb_lift_x86(&d, b);
        if (r != HB_OK && r != HB_ERR_UNSUPPORTED_FEATURE) {
            hb_ir_builder_destroy(b);
            hb_ir_func_destroy(func);
            return r;
        }
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 920 — ПЕРЕНОС ПРЕФИКСА БЛОКИРОВКИ.
         * Перенесено с ветви x64 (`hb_lift_x64.c:2358`), где это сделано лейном A 17.06:
         * все команды, поднятые из операции с `LOCK`, помечаются `is_locked`, и кодогенератор
         * обрамляет их барьером. Здесь этого не было вовсе — вместе с тем, что декодер поле
         * не заполнял (починено в этой же итерации), барьер на i386 терялся молча. */
        if (d.lock_prefix) {
            for (size_t k = pre_instr; k < block->instr_count; k++)
                block->instrs[k].is_locked = true;
        }
        /* ★ ПЕРЕПИСЬ ДЛЯ ГРАФА АНАЛИЗА — та же точка и та же строка, что на ветви x64.
         * Граф ОДИН на обе разрядности: копия правил в двух лифтерах уже расходилась
         * молча (продление единицы жило только здесь). */
        hb_cfg_ledger_note(func, d.addr, d.len, pre_instr, block->instr_count - pre_instr,
                           d.is_branch, d.is_conditional, d.is_call, d.is_ret,
                           d.is_branch && d.branch_target != 0, d.branch_target);
        count++;
        if (d.is_branch || d.is_ret || d.is_call) {
            ed_note(dec, &d);
            /* ★ ЕДИНИЦА 24.08 — цель ВНЕ окна разбора это будущий вход: заносим упреждающе,
             * чтобы будущая единица резалась ДО того, как накроет его, а не после дубля.
             * Цель ВНУТРИ окна не заносим: она и есть повод для слияния. */
            if (d.is_branch && d.branch_target &&
                !(d.branch_target >= dec->base_addr &&
                  d.branch_target - dec->base_addr < (uint64_t)dec->code_len))
                hb_known_entry_note(d.branch_target);
            if (hb_lift_edinica_prodlit(dec, &d, merged)) { merged++; continue; }
            /* Гистограмма глубины осталась ПРИБОРОМ ВЕТВИ i386: счётчик статический в этом
             * файле, а с ветви x64 он недоступен. Общие счётчики (blokov_prodleno, sliyanii,
             * cel_v_okne) ведёт сама hb_lift_edinica_prodlit и потому они покрывают ОБЕ ветви —
             * это надо знать, читая mg_report: гистограмма и остальные числа считают разное. */
            __atomic_add_fetch(&g_mg_hist[merged < 8 ? merged : 8], 1, __ATOMIC_RELAXED);
            break;
        }
        if (count >= instr_limit) {
            if (dec->pos < dec->code_len) {
                func->truncated = true;
                func->truncation_reason = "x86 lifter instruction limit";
            }
            break;
        }
    }

    hb_cfg_build(func, block);   /* см. разбор у зеркальной строки в hb_lift_x64.c */

    hb_ir_builder_destroy(b);
    *out = func;
    return HB_OK;
}
