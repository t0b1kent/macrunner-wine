#include "hb_env.h"
#include <stdlib.h>
#include "hb_lifter.h"
#include "hb_vec_sootv.h"
#include "hb_ir.h"
#include <string.h>
#include "hb_alloc_count.h"

/* Регистрация кеша гейта в общем сбросе — см. hb_codegen.h. */


static hb_size_t size_from_dec(uint8_t sz) {
    switch (sz) {
        case 1: return HB_SIZE_8;
        case 2: return HB_SIZE_16;
        case 4: return HB_SIZE_32;
        case 8: return HB_SIZE_64;
        case 10: return HB_SIZE_80;
        case 16: return HB_SIZE_128;
        case 32: return HB_SIZE_256;
        case 64: return HB_SIZE_512;
        default: return HB_SIZE_64;
    }
}

static hb_ir_operand_t operand_from_dec(const hb_decoded_t* dec, int slot) {
    const hb_decoded_t* d = dec; /* for field access */
    bool is_reg = (slot == 1) ? d->op1.is_reg : (slot == 2) ? d->op2.is_reg : d->op3.is_reg;
    bool is_imm = (slot == 1) ? d->op1.is_imm : (slot == 2) ? d->op2.is_imm : d->op3.is_imm;
    bool is_mem = (slot == 1) ? d->op1.is_mem : (slot == 2) ? d->op2.is_mem : d->op3.is_mem;
    uint8_t sz_raw = (slot == 1) ? d->op1.size : (slot == 2) ? d->op2.size : d->op3.size;
    uint8_t reg_offset = (slot == 1) ? d->op1.reg_offset : (slot == 2) ? d->op2.reg_offset : d->op3.reg_offset;
    hb_size_t sz = size_from_dec(sz_raw);
    if (is_reg) {
        int reg = (slot == 1) ? d->op1.reg : (slot == 2) ? d->op2.reg : d->op3.reg;
        hb_ir_operand_t op = hb_ir_reg((hb_reg_t)reg, sz);
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
        bool rip_relative = (slot == 1) ? d->op1.mem.rip_relative : (slot == 2) ? d->op2.mem.rip_relative : d->op3.mem.rip_relative;
        uint64_t rip_target = (slot == 1) ? d->op1.mem.rip_target : (slot == 2) ? d->op2.mem.rip_target : d->op3.mem.rip_target;
        bool vsib = (slot == 1) ? d->op1.mem.vsib : (slot == 2) ? d->op2.mem.vsib : d->op3.mem.vsib;
        uint8_t vsib_index_size = (slot == 1) ? d->op1.mem.vsib_index_size : (slot == 2) ? d->op2.mem.vsib_index_size : d->op3.mem.vsib_index_size;
        uint8_t vsib_elem_size = (slot == 1) ? d->op1.mem.vsib_elem_size : (slot == 2) ? d->op2.mem.vsib_elem_size : d->op3.mem.vsib_elem_size;
        uint8_t vsib_count = (slot == 1) ? d->op1.mem.vsib_count : (slot == 2) ? d->op2.mem.vsib_count : d->op3.mem.vsib_count;
        if (rip_relative) {
            base = -1;
            disp += (int64_t)rip_target;
        }
        hb_ir_operand_t op = hb_ir_mem_segment(
            (hb_reg_t)(base >= 0 ? base : HB_REG_COUNT),
            (hb_reg_t)(index >= 0 ? index : HB_REG_COUNT),
            scale, disp, sz, segment);
        op.mem.addr32 = addr32;
        op.mem.vsib = vsib;
        op.mem.vsib_index_size = vsib_index_size;
        op.mem.vsib_elem_size = vsib_elem_size;
        op.mem.vsib_count = vsib_count;
        return op;
    }
    return hb_ir_none();
}


static bool is_vex_decoded(const hb_decoded_t* dec) {
    return dec && dec->len > 0 && (dec->evex || dec->bytes[0] == 0xc4 || dec->bytes[0] == 0xc5);
}

static bool is_evex_decoded(const hb_decoded_t* dec) {
    return dec && dec->evex;
}

static uint64_t evex_target_arg(const hb_decoded_t* dec, uint64_t arg) {
    if (!is_evex_decoded(dec)) return arg;
    return (arg & 0x00ffffffu) |
           ((uint64_t)(dec->evex_mask & 7u) << 24) |
           (dec->evex_zero ? (1ULL << 27) : 0) |
           (1ULL << 28);
}

static void set_evex_target_arg(hb_ir_instr_t* i, const hb_decoded_t* dec, uint64_t arg) {
    if (i && is_evex_decoded(dec)) i->target = evex_target_arg(dec, arg);
}

#define HB_EVEX_ARG_BROADCAST 0x200u
#define HB_EVEX_ARG_ROUND_SHIFT 10
#define HB_EVEX_ARG_ROUND_MASK  0x1c00u


#include "hb_lift_vec_opory.inc"

static hb_ir_vec_op_t vec_op_from_ins(int opcode) {
    /* Соответствие живёт в ОБЩЕМ списке hb_vec_sootv.h и разворачивается
     * здесь же и в ветви i386. Прежде оно было записано руками трижды, и
     * ветвь i386 отставала на 145 строк — незаметно, потому что доска
     * называла число отказов подъёма, но не их имена. */
    switch (opcode) {
#define X(ins, vec) case ins: return vec;
        HB_VEC_SOOTV(X)
#undef X
        default: break;
    }
    return 0;   /* как и прежде: 0 значит «не векторная» */
}

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
        default: return HB_CC_E; /* fallback */
    }
}

/* Итерация 390: признак под гейтом. Правка убирает 3 расхождения `dec`, но вносит 51 отказ
 * `result=0 OK` на inc/dec — подпись рассинхронизации сторон, причина пока не найдена.
 * Причина найдена в 391 — вторая копия таблицы масок в кодогенераторе. Умолчание ВКЛ. */
/* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1105 — ГЕЙТЫ ВИДА Б (приказ 145).
 * Прибор, а не выключатель: умолчание ВКЛ, гасится только в приёмочном переборе ради цены.
 * Полное обоснование и правило «что значит выключено» — в hb_lift_x86.c рядом с близнецами
 * этих функций; здесь вторая ветвь того же гейта, имена гейтов ОБЩИЕ на обе ветви.
 *
 * PUSH_SEG_X64=0 — прежний отказ «неподдержанный опкод» (поведение до правки 1096). Дешевле
 * этой правки сделать нечего, поэтому «выключено» = «как было», и если гость `push fs` не
 * исполняет, арм совпадёт с базовым — это и есть ответ «цена ноль». */
static inline hb_ir_instr_t* emit(hb_ir_builder_t* b, hb_ir_instr_t* i, const hb_decoded_t* dec) {
    (void)b;
    if (i) {
        i->guest_addr = dec->addr;
        i->guest_len = dec->len;
        if (is_vex_decoded(dec) && dec->op1.is_reg &&
            dec->op1.reg >= HB_REG_XMM0 && dec->op1.reg <= HB_REG_XMM31 &&
            dec->op1.size == 16) {
            i->zero_ymm_upper = true;
        }
    }
    return i;
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

#define HB_EVEX_TARGET_ARG(d, im) evex_target_arg((d), (im))
#include "hb_lift_vec_obshchee.inc"
#include "hb_lift_sist_obshchee.inc"

hb_result_t hb_lift_x64(const hb_decoded_t* dec, hb_ir_builder_t* b) {
    if (!dec || !b) return HB_ERR_INVALID_ARG;

    switch (dec->opcode) {
        case HB_INS_MOV: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            if (dec->op1.is_mem && (dec->op2.is_reg || dec->op2.is_imm)) {
                /* MOV [mem], reg/imm */
                emit(b, hb_ir_emit_store(b, dst, src), dec);
            } else if (dec->op1.is_reg && dec->op2.is_mem) {
                /* MOV reg, [mem] */
                emit(b, hb_ir_emit_load(b, dst, src), dec);
            } else {
                /* MOV reg, reg/imm or other forms */
                emit(b, hb_ir_emit_mov(b, dst, src), dec);
            }
            return HB_OK;
        }

        case HB_INS_MOVDIR64B: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_MOVDIR64B);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MOV_SEG: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_unop(b, HB_IR_MOV_SEG, dst, src), dec);
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
        case HB_INS_CVTSI2SD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_CVTSI2SD);
            if (i) {
                i->dst = dst;
                if (is_vex_decoded(dec) && dec->op3.present) {
                    i->src1 = operand_from_dec(dec, 2);
                    i->src2 = operand_from_dec(dec, 3);
                } else {
                    i->src1 = operand_from_dec(dec, 2);
                    i->src2 = hb_ir_none();
                }
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_CVTSI2SS: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_CVTSI2SS);
            if (i) {
                i->dst = dst;
                if (is_vex_decoded(dec) && dec->op3.present) {
                    i->src1 = operand_from_dec(dec, 2);
                    i->src2 = operand_from_dec(dec, 3);
                } else {
                    i->src1 = operand_from_dec(dec, 2);
                    i->src2 = hb_ir_none();
                }
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MULSD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src1 = vector_src1_from_dec(dec, dst);
            hb_ir_operand_t src2 = vector_src2_from_dec(dec);
            hb_ir_instr_t *i = hb_ir_emit(b, is_vex_decoded(dec) ? HB_IR_FMUL : HB_IR_MULSD);
            if (i) { i->dst = dst; i->src1 = src1; i->src2 = src2; if (is_vex_decoded(dec)) i->target = dec->evex ? evex_target_arg(dec, 8 | 0x100) : (8 | 0x100); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MULSS: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src1 = vector_src1_from_dec(dec, dst);
            hb_ir_operand_t src2 = vector_src2_from_dec(dec);
            hb_ir_instr_t *i = hb_ir_emit(b, is_vex_decoded(dec) ? HB_IR_FMUL : HB_IR_MULSS);
            if (i) { i->dst = dst; i->src1 = src1; i->src2 = src2; if (is_vex_decoded(dec)) i->target = dec->evex ? evex_target_arg(dec, 4 | 0x100) : (4 | 0x100); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_DIVSS: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src1 = vector_src1_from_dec(dec, dst);
            hb_ir_operand_t src2 = vector_src2_from_dec(dec);
            hb_ir_instr_t *i = hb_ir_emit(b, is_vex_decoded(dec) ? HB_IR_FDIV : HB_IR_DIVSS);
            if (i) { i->dst = dst; i->src1 = src1; i->src2 = src2; if (is_vex_decoded(dec)) i->target = dec->evex ? evex_target_arg(dec, 4 | 0x100) : (4 | 0x100); }
            emit(b, i, dec);
            return HB_OK;
        }
        /* MacRunner 2026-08-28, лейн ЛЕСТНИЦА — сравнения SSE в IR.
         *
         * Вид сравнения (imm8) кладём в биты 16..23 аргумента: 0..7 занимает ширина
         * дорожки, бит 8 — скалярность, бит 9 — рассылка, 10..12 — округление
         * (`hb_ir.h:617`). Дорожка и скалярность считаются ровно как у соседнего
         * MIN/MAX, чтобы одна и та же запись читалась обоими исполнителями. */
        case HB_INS_CMPPS:
        case HB_INS_CMPPD:
        case HB_INS_CMPSS:
        case HB_INS_CMPSD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_FCMP_MASK);
            if (i) {
                unsigned lane = (dec->opcode == HB_INS_CMPPD ||
                                 dec->opcode == HB_INS_CMPSD) ? 8 : 4;
                bool scalar = (dec->opcode == HB_INS_CMPSS ||
                               dec->opcode == HB_INS_CMPSD);
                i->dst = dst;
                i->src1 = dst;
                i->src2 = src;
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
            hb_ir_operand_t src = operand_from_dec(dec, 2);
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
                i->src1 = vector_src1_from_dec(dec, dst);
                i->src2 = has_vex_src(dec) ? operand_from_dec(dec, 3) : src;
                uint64_t arg = lane | (scalar ? 0x100 : 0);
                if (dec->evex_broadcast) arg |= HB_EVEX_ARG_BROADCAST;
                i->target = evex_target_arg(dec, arg);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_COMISS: {
            hb_ir_operand_t lhs = operand_from_dec(dec, 1);
            hb_ir_operand_t rhs = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_COMISS);
            if (i) { i->src1 = lhs; i->src2 = rhs; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_COMISD: {
            hb_ir_operand_t lhs = operand_from_dec(dec, 1);
            hb_ir_operand_t rhs = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_COMISD);
            if (i) { i->src1 = lhs; i->src2 = rhs; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_CVTSD2SI:
        case HB_INS_CVTTSD2SI: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, dec->opcode == HB_INS_CVTSD2SI ? HB_IR_CVTSD2SI : HB_IR_CVTTSD2SI);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_CVTSS2SI:
        case HB_INS_VCVTTSS2USI:
        case HB_INS_VCVTTSD2USI: {
            /* Беззнаковое усечение — отдельный узел IR, не разновидность
             * знакового: другой диапазон и другое «неопределённое». */
            /* ТОТ ЖЕ ДЕФЕКТ, ЧТО В ВЕТВИ i386 (найден 04.09.2026 сверкой с
             * оракулом): узел выбирался только из двух БЕЗЗНАКОВЫХ, хотя
             * ветвь берёт и знаковую CVTSS2SI. Разница видна ровно при выходе
             * за диапазон: у знаковых «целое неопределённое» это 0x80000000,
             * у беззнаковых — ЕДИНИЦЫ. */
            hb_ir_op_t op;
            switch (dec->opcode) {
                case HB_INS_VCVTTSS2USI: op = HB_IR_VCVTTSS2USI; break;
                case HB_INS_VCVTTSD2USI: op = HB_IR_VCVTTSD2USI; break;
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
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, dec->opcode == HB_INS_CVTSS2SI ? HB_IR_CVTSS2SI : HB_IR_CVTTSS2SI);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_XMM_AND:
        case HB_INS_XMM_ANDN:
        case HB_INS_XMM_OR:
        case HB_INS_XORPS:
        case HB_INS_PXOR: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src1 = vector_src1_from_dec(dec, dst);
            hb_ir_operand_t src2 = vector_src2_from_dec(dec);
            hb_ir_op_t op = HB_IR_XORPS;
            if (dec->opcode == HB_INS_XMM_AND) op = HB_IR_XMM_AND;
            else if (dec->opcode == HB_INS_XMM_ANDN) op = HB_IR_XMM_ANDN;
            else if (dec->opcode == HB_INS_XMM_OR) op = HB_IR_XMM_OR;
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) {
                unsigned lane = dec->evex_mask_lane ? dec->evex_mask_lane : 4;
                uint64_t arg = lane;
                if (dec->evex_broadcast) arg |= HB_EVEX_ARG_BROADCAST;
                i->dst = dst; i->src1 = src1; i->src2 = src2; set_evex_target_arg(i, dec, arg);
            }
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
            hb_ir_operand_t src1 = vector_src1_from_dec(dec, dst);
            hb_ir_operand_t src2 = vector_src2_from_dec(dec);
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) { i->dst = dst; i->src1 = src1; i->src2 = src2; }
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
            hb_ir_operand_t src1 = vector_src1_from_dec(dec, dst);
            hb_ir_operand_t src2 = vector_src2_from_dec(dec);
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) { i->dst = dst; i->src1 = src1; i->src2 = src2; }
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
                i->src1 = vector_src1_from_dec(dec, i->dst);
                i->src2 = vector_src2_from_dec(dec);
                i->target = evex_target_arg(dec, (packed_double ? 8 : 4) | (high ? 0x100 : 0));
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
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PUNPCK);
            if (i) {
                unsigned lane = 1;
                if (dec->opcode == HB_INS_PUNPCKLWD || dec->opcode == HB_INS_PUNPCKHWD) lane = 2;
                else if (dec->opcode == HB_INS_PUNPCKLDQ || dec->opcode == HB_INS_PUNPCKHDQ) lane = 4;
                else if (dec->opcode == HB_INS_PUNPCKLQDQ || dec->opcode == HB_INS_PUNPCKHQDQ) lane = 8;
                bool high = (dec->opcode == HB_INS_PUNPCKHBW || dec->opcode == HB_INS_PUNPCKHWD ||
                             dec->opcode == HB_INS_PUNPCKHDQ || dec->opcode == HB_INS_PUNPCKHQDQ);
                i->dst = dst;
                i->src1 = vector_src1_from_dec(dec, dst);
                i->src2 = has_vex_src(dec) ? operand_from_dec(dec, 3) : src;
                i->target = evex_target_arg(dec, lane | (high ? 0x100 : 0));
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PACKSSWB:
        case HB_INS_PACKUSWB:
        case HB_INS_PACKSSDW: {
            hb_ir_op_t op = HB_IR_PACKSSWB;
            if (dec->opcode == HB_INS_PACKUSWB) op = HB_IR_PACKUSWB;
            else if (dec->opcode == HB_INS_PACKSSDW) op = HB_IR_PACKSSDW;
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src1 = vector_src1_from_dec(dec, dst);
            hb_ir_operand_t src2 = vector_src2_from_dec(dec);
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) { i->dst = dst; i->src1 = src1; i->src2 = src2; i->target = evex_target_arg(dec, 0); }
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
            hb_ir_operand_t src1 = vector_src1_from_dec(dec, dst);
            hb_ir_operand_t src2 = vector_src2_from_dec(dec);
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) { i->dst = dst; i->src1 = src1; i->src2 = src2; i->target = evex_target_arg(dec, 0); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PADDSB:
        case HB_INS_PADDSW:
        case HB_INS_PADDUSB:
        case HB_INS_PADDUSW: {
            hb_ir_op_t op = HB_IR_PADDSB;
            if (dec->opcode == HB_INS_PADDSW) op = HB_IR_PADDSW;
            else if (dec->opcode == HB_INS_PADDUSB) op = HB_IR_PADDUSB;
            else if (dec->opcode == HB_INS_PADDUSW) op = HB_IR_PADDUSW;
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src1 = vector_src1_from_dec(dec, dst);
            hb_ir_operand_t src2 = vector_src2_from_dec(dec);
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) { i->dst = dst; i->src1 = src1; i->src2 = src2; i->target = evex_target_arg(dec, 0); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PAVGB:
        case HB_INS_PAVGW: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src1 = vector_src1_from_dec(dec, dst);
            hb_ir_operand_t src2 = vector_src2_from_dec(dec);
            hb_ir_instr_t *i = hb_ir_emit(b, dec->opcode == HB_INS_PAVGB ? HB_IR_PAVGB : HB_IR_PAVGW);
            if (i) { i->dst = dst; i->src1 = src1; i->src2 = src2; i->target = evex_target_arg(dec, 0); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PSHUFB: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src1 = vector_src1_from_dec(dec, dst);
            hb_ir_operand_t src2 = vector_src2_from_dec(dec);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PSHUFB);
            if (i) { i->dst = dst; i->src1 = src1; i->src2 = src2; i->target = evex_target_arg(dec, 0); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PHADDW:
        case HB_INS_PHADDD:
        case HB_INS_PHADDSW:
        case HB_INS_PHSUBW:
        case HB_INS_PHSUBD:
        case HB_INS_PHSUBSW:
        case HB_INS_PMADDUBSW:
        case HB_INS_PSIGNB:
        case HB_INS_PSIGNW:
        case HB_INS_PSIGND:
        case HB_INS_PMULHRSW:
        case HB_INS_PABSB:
        case HB_INS_PABSW:
        case HB_INS_PABSD:
        case HB_INS_PTEST:
        case HB_INS_PMOVSXBW:
        case HB_INS_PMOVSXBD:
        case HB_INS_PMOVSXBQ:
        case HB_INS_PMOVSXWD:
        case HB_INS_PMOVSXWQ:
        case HB_INS_PMOVSXDQ:
        case HB_INS_PMULDQ:
        case HB_INS_PCMPEQQ:
        case HB_INS_PACKUSDW:
        case HB_INS_PMOVZXBW:
        case HB_INS_PMOVZXBD:
        case HB_INS_PMOVZXBQ:
        case HB_INS_PMOVZXWD:
        case HB_INS_PMOVZXWQ:
        case HB_INS_PMOVZXDQ:
        case HB_INS_PCMPGTQ:
        case HB_INS_PMINSB:
        case HB_INS_PMINSD:
        case HB_INS_PMINUW:
        case HB_INS_PMINUD:
        case HB_INS_PMAXSB:
        case HB_INS_PMAXSD:
        case HB_INS_PMAXUW:
        case HB_INS_PMAXUD:
        case HB_INS_PMULLD:
        case HB_INS_PHMINPOSUW:
        case HB_INS_MPSADBW:
        case HB_INS_PALIGNR:
        case HB_INS_PBLENDW:
        case HB_INS_BLENDPS:
        case HB_INS_BLENDPD:
        case HB_INS_PBLENDVB:
        case HB_INS_BLENDVPS:
        case HB_INS_BLENDVPD:
        case HB_INS_PSUBUSB:
        case HB_INS_PSUBUSW:
        case HB_INS_PSUBSB:
        case HB_INS_PSUBSW:
        case HB_INS_PMINUB:
        case HB_INS_PMINSW:
        case HB_INS_PMAXUB:
        case HB_INS_PMAXSW:
        case HB_INS_PMULUDQ:
        case HB_INS_PSADBW:
        case HB_INS_VPBROADCASTB:
        case HB_INS_VPBROADCASTW:
        case HB_INS_VPBROADCASTD:
        case HB_INS_VPBROADCASTQ:
        case HB_INS_VBROADCASTSS:
        case HB_INS_VBROADCASTSD:
        case HB_INS_VBROADCASTF32X2:
        case HB_INS_VBROADCASTF64X2:
        case HB_INS_VBROADCASTF32X4:
        case HB_INS_VBROADCASTF64X4:
        case HB_INS_VBROADCASTF32X8:
        case HB_INS_VBROADCASTI32X2:
        case HB_INS_VBROADCASTI128:
        case HB_INS_VPBLENDD:
        case HB_INS_VPERMQ:
        case HB_INS_VPERMPD:
        case HB_INS_VPERMILPS:
        case HB_INS_VPERMILPD:
        case HB_INS_VBLENDVPS:
        case HB_INS_VBLENDVPD:
        case HB_INS_VPBLENDVB:
        case HB_INS_VINSERTF128:
        case HB_INS_VINSERTI128:
        case HB_INS_VEXTRACTF128:
        case HB_INS_VEXTRACTI128:
        case HB_INS_VPERM2F128:
        case HB_INS_VPERM2I128:
        case HB_INS_VPSRLVD:
        case HB_INS_VPSRLVQ:
        case HB_INS_VPSRAVD:
        case HB_INS_VPSLLVD:
        case HB_INS_VPSLLVQ:
        case HB_INS_PCLMULQDQ:
        case HB_INS_VPCLMULQDQ:
        case HB_INS_AESKEYGENASSIST:
        case HB_INS_AESIMC:
        case HB_INS_AESENC:
        case HB_INS_AESENCLAST:
        case HB_INS_AESDEC:
        case HB_INS_AESDECLAST:
        case HB_INS_VAESENC:
        case HB_INS_VAESENCLAST:
        case HB_INS_VAESDEC:
        case HB_INS_VAESDECLAST:
        case HB_INS_GF2P8MULB:
        case HB_INS_VGF2P8MULB:
        case HB_INS_GF2P8AFFINEQB:
        case HB_INS_GF2P8AFFINEINVQB:
        case HB_INS_VGF2P8AFFINEQB:
        case HB_INS_VGF2P8AFFINEINVQB:
        case HB_INS_VMPSADBW:
        case HB_INS_VPERMD:
        case HB_INS_VPERMPS:
        case HB_INS_VMASKMOVPS:
        case HB_INS_VMASKMOVPD:
        case HB_INS_VPMASKMOVD:
        case HB_INS_VPMASKMOVQ:
        case HB_INS_VGATHERDPS:
        case HB_INS_VGATHERDPD:
        case HB_INS_VGATHERQPS:
        case HB_INS_VGATHERQPD:
        case HB_INS_VPGATHERDD:
        case HB_INS_VPGATHERDQ:
        case HB_INS_VPGATHERQD:
        case HB_INS_VPGATHERQQ:
        case HB_INS_PCMPESTRM:
        case HB_INS_PCMPESTRI:
        case HB_INS_PCMPISTRM:
        case HB_INS_PCMPISTRI:
        case HB_INS_VTESTPS:
        case HB_INS_VTESTPD:
        case HB_INS_VFMADD132PS:
        case HB_INS_VFMADD132PD:
        case HB_INS_VFMADD132SS:
        case HB_INS_VFMADD132SD:
        case HB_INS_VFMADD213PS:
        case HB_INS_VFMADD213PD:
        case HB_INS_VFMADD213SS:
        case HB_INS_VFMADD213SD:
        case HB_INS_VFMADD231PS:
        case HB_INS_VFMADD231PD:
        case HB_INS_VFMADD231SS:
        case HB_INS_VFMADD231SD:
        case HB_INS_VFMSUB132PS:
        case HB_INS_VFMSUB132PD:
        case HB_INS_VFMSUB132SS:
        case HB_INS_VFMSUB132SD:
        case HB_INS_VFMSUB213PS:
        case HB_INS_VFMSUB213PD:
        case HB_INS_VFMSUB213SS:
        case HB_INS_VFMSUB213SD:
        case HB_INS_VFMSUB231PS:
        case HB_INS_VFMSUB231PD:
        case HB_INS_VFMSUB231SS:
        case HB_INS_VFMSUB231SD:
        case HB_INS_VFMADDSUB132PS:
        case HB_INS_VFMADDSUB132PD:
        case HB_INS_VFMSUBADD132PS:
        case HB_INS_VFMSUBADD132PD:
        case HB_INS_VFMADDSUB213PS:
        case HB_INS_VFMADDSUB213PD:
        case HB_INS_VFMSUBADD213PS:
        case HB_INS_VFMSUBADD213PD:
        case HB_INS_VFMADDSUB231PS:
        case HB_INS_VFMADDSUB231PD:
        case HB_INS_VFMSUBADD231PS:
        case HB_INS_VFMSUBADD231PD:
        case HB_INS_VFNMADD132PS:
        case HB_INS_VFNMADD132PD:
        case HB_INS_VFNMADD132SS:
        case HB_INS_VFNMADD132SD:
        case HB_INS_VFNMSUB132PS:
        case HB_INS_VFNMSUB132PD:
        case HB_INS_VFNMSUB132SS:
        case HB_INS_VFNMSUB132SD:
        case HB_INS_VFNMADD213PS:
        case HB_INS_VFNMADD213PD:
        case HB_INS_VFNMADD213SS:
        case HB_INS_VFNMADD213SD:
        case HB_INS_VFNMSUB213PS:
        case HB_INS_VFNMSUB213PD:
        case HB_INS_VFNMSUB213SS:
        case HB_INS_VFNMSUB213SD:
        case HB_INS_VFNMADD231PS:
        case HB_INS_VFNMADD231PD:
        case HB_INS_VFNMADD231SS:
        case HB_INS_VFNMADD231SD:
        case HB_INS_VFNMSUB231PS:
        case HB_INS_VFNMSUB231PD:
        case HB_INS_VFNMSUB231SS:
        case HB_INS_VFNMSUB231SD:
        case HB_INS_VCVTPH2PS:
        case HB_INS_VCVTPS2PH:
        case HB_INS_VCMPPS:
        case HB_INS_VCMPPD:
        case HB_INS_VCMPSS:
        case HB_INS_VCMPSD:
        case HB_INS_VHADDPS:
        case HB_INS_VHADDPD:
        case HB_INS_VHSUBPS:
        case HB_INS_VHSUBPD:
        case HB_INS_VADDSUBPS:
        case HB_INS_VADDSUBPD:
        case HB_INS_VMOVSLDUP:
        case HB_INS_VMOVSHDUP:
        case HB_INS_VMOVDDUP:
        case HB_INS_SHA1NEXTE:
        case HB_INS_SHA1MSG1:
        case HB_INS_SHA1MSG2:
        case HB_INS_SHA256RNDS2:
        case HB_INS_SHA256MSG1:
        case HB_INS_SHA256MSG2:
        case HB_INS_SHA1RNDS4: {
            {
                hb_result_t itog_k;
                if (hb_evex_cmp_mask(dec, b, &itog_k)) return itog_k;
            }
            /* Тело переехало в общий hb_lift_vec_obshchee.inc: тот же текст
             * разворачивается и в ветви i386, отставать больше нечему. */
            return hb_vek_obshchij(dec, b);
        }
        case HB_INS_VZEROUPPER:
            emit(b, hb_ir_emit(b, HB_IR_VZEROUPPER), dec);
            return HB_OK;
        case HB_INS_VZEROALL:
            emit(b, hb_ir_emit(b, HB_IR_VZEROALL), dec);
            return HB_OK;
        /* База FS/GS. Приёмник (или источник у записи) — регистр общего
         * назначения; сама база живёт в контексте (`ctx->fs_base`/`gs_base`).
         * Форм только в длинном режиме, поэтому ветви i386 здесь нет. */
        case HB_INS_RDFSBASE:
        case HB_INS_RDGSBASE:
        case HB_INS_WRFSBASE:
        case HB_INS_WRGSBASE: {
            bool zapis = (dec->opcode == HB_INS_WRFSBASE || dec->opcode == HB_INS_WRGSBASE);
            bool gs = (dec->opcode == HB_INS_RDGSBASE || dec->opcode == HB_INS_WRGSBASE);
            hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_FSGSBASE);
            if (i) {
                if (zapis) { i->dst = hb_ir_none(); i->src1 = operand_from_dec(dec, 1); }
                else       { i->dst = operand_from_dec(dec, 1); i->src1 = hb_ir_none(); }
                i->target = (gs ? 1u : 0u) | (zapis ? 2u : 0u);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        /* EMMS/FEMMS: ветвь i386 поднимала их с итерации 520, здесь их не было —
         * декодер x64 клал обе в корзину MMX, и блок отказывал целиком. */
        case HB_INS_X87_EMMS:
            emit(b, hb_ir_emit(b, HB_IR_X87_EMMS), dec);
            return HB_OK;
        case HB_INS_PSHUFW:   /* итерация 907: MMX-форма, признак 1 — четыре СЛОВА в 64 битах */
        case HB_INS_PSHUFD:
        case HB_INS_PSHUFLW:
        case HB_INS_PSHUFHW: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PSHUF);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->src2 = operand_from_dec(dec, 3);
                uint64_t target = dec->opcode == HB_INS_PSHUFW ? 1 :
                                  dec->opcode == HB_INS_PSHUFD ? 4 :
                                  (dec->opcode == HB_INS_PSHUFLW ? 2 : 0x102);
                i->target = evex_target_arg(dec, target);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_SHUFPS:
        case HB_INS_SHUFPD: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_FSHUF);
            if (i) {
                hb_ir_operand_t dst = operand_from_dec(dec, 1);
                i->dst = dst;
                i->src1 = vector_src1_from_dec(dec, dst);
                i->src2 = vector_src2_from_dec(dec);
                i->target = evex_target_arg(dec, (dec->opcode == HB_INS_SHUFPD ? 8 : 4) |
                                                (((uint64_t)dec_imm8(dec) & 0xffu) << 8));
            }
            emit(b, i, dec);
            return HB_OK;
        }
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
                if (is_vex_decoded(dec) && dec->op3.is_imm) {
                    i->src1 = operand_from_dec(dec, 2);
                    i->src2 = operand_from_dec(dec, 3);
                } else {
                    i->src1 = vector_src1_from_dec(dec, dst);
                    i->src2 = vector_src2_from_dec(dec);
                }
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
                if (is_vex_decoded(dec) && dec->op3.is_imm) {
                    i->src1 = operand_from_dec(dec, 2);
                    i->src2 = operand_from_dec(dec, 3);
                } else {
                    i->src1 = vector_src1_from_dec(dec, dst);
                    i->src2 = vector_src2_from_dec(dec);
                }
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PADDB:
        case HB_INS_PADDW:
        case HB_INS_PADDD:
        case HB_INS_PADDQ: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PADD);
            if (i) {
                unsigned lane = 1;
                if (dec->opcode == HB_INS_PADDW) lane = 2;
                else if (dec->opcode == HB_INS_PADDD) lane = 4;
                else if (dec->opcode == HB_INS_PADDQ) lane = 8;
                i->dst = operand_from_dec(dec, 1);
                i->src1 = vector_src1_from_dec(dec, i->dst);
                i->src2 = vector_src2_from_dec(dec);
                i->target = evex_target_arg(dec, lane);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_PSUBB:
        case HB_INS_PSUBW:
        case HB_INS_PSUBD:
        case HB_INS_PSUBQ: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PSUB);
            if (i) {
                unsigned lane = 1;
                if (dec->opcode == HB_INS_PSUBW) lane = 2;
                else if (dec->opcode == HB_INS_PSUBD) lane = 4;
                else if (dec->opcode == HB_INS_PSUBQ) lane = 8;
                i->dst = operand_from_dec(dec, 1);
                i->src1 = vector_src1_from_dec(dec, i->dst);
                i->src2 = vector_src2_from_dec(dec);
                i->target = evex_target_arg(dec, lane);
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
        case HB_INS_LAHF: {
            emit(b, hb_ir_emit(b, HB_IR_LAHF), dec);
            return HB_OK;
        }
        case HB_INS_SAHF: {
            emit(b, hb_ir_emit(b, HB_IR_SAHF), dec);
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
        case HB_INS_ENTER: {
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 929 — ЛИФТЕРА НЕ БЫЛО ВОВСЕ.
             * Декодер x64 команду берёт (`hb_decode_x64.c:3322`), интерпретатор с этой же
             * итерации умеет обе ширины — а ветви в лифтере не было, и `c8100000` давал
             * `-5` при живых контролях `leave`, `push rbp`, `ret`. Тот же случай, что с
             * семьёй упаковки в 522 и пятёркой min/max в 919: разбор успешен, отказ приходит
             * после него. Тело перенесено с ветви x86-32 без изменений. */
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_ENTER);
            if (i) {
                i->src1 = operand_from_dec(dec, 1);
                i->src2 = operand_from_dec(dec, 2);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_LEAVE: {
            hb_size_t sz = size_from_dec(dec->op1.size);
            hb_ir_operand_t sp = hb_ir_reg(HB_REG_RSP, sz);
            hb_ir_operand_t bp_same_size = hb_ir_reg(HB_REG_RBP, sz);
            hb_ir_operand_t bp = operand_from_dec(dec, 1);
            emit(b, hb_ir_emit_mov(b, sp, bp_same_size), dec);
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
        case HB_INS_MOVZX: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_ZERO_EXTEND);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MOVSX:
        case HB_INS_MOVSXD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_SIGN_EXTEND);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_CDQE: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_SIGN_EXTEND);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_CWD: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_CWD);
            if (i) i->src1 = operand_from_dec(dec, 1);
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
        case HB_INS_POPCNT: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_POPCNT);
            if (i) { i->dst = dst; i->src1 = src; }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_CRC32:
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
        case HB_INS_SHRX:
        case HB_INS_ADCX:
        case HB_INS_ADOX: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_op_t op = dec->opcode == HB_INS_CRC32 ? HB_IR_CRC32 :
                            dec->opcode == HB_INS_ANDN ? HB_IR_ANDN :
                            dec->opcode == HB_INS_BEXTR ? HB_IR_BEXTR :
                            dec->opcode == HB_INS_BLSI ? HB_IR_BLSI :
                            dec->opcode == HB_INS_BLSMSK ? HB_IR_BLSMSK :
                            dec->opcode == HB_INS_BLSR ? HB_IR_BLSR :
                            dec->opcode == HB_INS_BZHI ? HB_IR_BZHI :
                            dec->opcode == HB_INS_PDEP ? HB_IR_PDEP :
                            dec->opcode == HB_INS_PEXT ? HB_IR_PEXT :
                            dec->opcode == HB_INS_RORX ? HB_IR_RORX :
                            dec->opcode == HB_INS_SARX ? HB_IR_SARX :
                            dec->opcode == HB_INS_SHLX ? HB_IR_SHLX :
                            dec->opcode == HB_INS_SHRX ? HB_IR_SHRX :
                            dec->opcode == HB_INS_ADCX ? HB_IR_ADCX : HB_IR_ADOX;
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) {
                i->dst = dst;
                i->src1 = src;
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
        case HB_INS_BSWAP: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_BSWAP);
            if (i) i->dst = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }
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
        case HB_INS_MOVD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_MOVD);
            if (i) {
                i->dst = dst;
                i->src1 = src;
                i->zero_ymm_upper = is_vex_decoded(dec) && dst.type == HB_OP_REG &&
                                    dst.reg >= HB_REG_XMM0 && dst.reg <= HB_REG_XMM31;
            }
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
        case HB_INS_CVTPS2PD:
        case HB_INS_CVTPD2PS:
        case HB_INS_CVTPD2DQ:
        case HB_INS_CVTTPD2DQ:
        case HB_INS_CVTSS2SD:
        case HB_INS_CVTSD2SS: {
            hb_ir_op_t op = HB_IR_CVTPS2PD;
            if (dec->opcode == HB_INS_CVTPD2PS) op = HB_IR_CVTPD2PS;
            else if (dec->opcode == HB_INS_CVTPD2DQ) op = HB_IR_CVTPD2DQ;
            else if (dec->opcode == HB_INS_CVTTPD2DQ) op = HB_IR_CVTTPD2DQ;
            else if (dec->opcode == HB_INS_CVTSS2SD) op = HB_IR_CVTSS2SD;
            else if (dec->opcode == HB_INS_CVTSD2SS) op = HB_IR_CVTSD2SS;
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, op);
            if (i) {
                i->dst = dst;
                if (is_vex_decoded(dec) && dec->op3.present) {
                    i->src1 = operand_from_dec(dec, 2);
                    i->src2 = operand_from_dec(dec, 3);
                } else {
                    i->src1 = operand_from_dec(dec, 2);
                    i->src2 = hb_ir_none();
                }
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
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            bool is_sub = (dec->opcode == HB_INS_SUBPS || dec->opcode == HB_INS_SUBPD ||
                           dec->opcode == HB_INS_SUBSS || dec->opcode == HB_INS_SUBSD);
            hb_ir_instr_t *i = hb_ir_emit(b, is_sub ? HB_IR_FSUB : HB_IR_FADD);
            if (i) {
                unsigned lane = (dec->opcode == HB_INS_ADDPD || dec->opcode == HB_INS_SUBPD ||
                                 dec->opcode == HB_INS_ADDSD || dec->opcode == HB_INS_SUBSD) ? 8 : 4;
                bool scalar = (dec->opcode == HB_INS_ADDSS || dec->opcode == HB_INS_SUBSS ||
                               dec->opcode == HB_INS_ADDSD || dec->opcode == HB_INS_SUBSD);
                i->dst = dst;
                i->src1 = vector_src1_from_dec(dec, dst);
                i->src2 = has_vex_src(dec) ? operand_from_dec(dec, 3) : src;
                uint64_t arg = lane | (scalar ? 0x100 : 0);
                if (dec->evex_broadcast) arg |= HB_EVEX_ARG_BROADCAST;
                if (dec->evex_rounding) arg |= ((uint64_t)(dec->evex_rounding & 7u) << HB_EVEX_ARG_ROUND_SHIFT);
                i->target = evex_target_arg(dec, arg);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MULPS:
        case HB_INS_MULPD:
        case HB_INS_DIVPS:
        case HB_INS_DIVPD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            bool is_div = (dec->opcode == HB_INS_DIVPS || dec->opcode == HB_INS_DIVPD);
            hb_ir_instr_t *i = hb_ir_emit(b, is_div ? HB_IR_FDIV : HB_IR_FMUL);
            if (i) {
                unsigned lane = (dec->opcode == HB_INS_MULPD || dec->opcode == HB_INS_DIVPD) ? 8 : 4;
                i->dst = dst;
                i->src1 = vector_src1_from_dec(dec, dst);
                i->src2 = has_vex_src(dec) ? operand_from_dec(dec, 3) : src;
                uint64_t arg = lane;
                if (dec->evex_broadcast) arg |= HB_EVEX_ARG_BROADCAST;
                i->target = evex_target_arg(dec, arg);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_SQRTPS:
        case HB_INS_SQRTPD:
        case HB_INS_SQRTSS:
        case HB_INS_SQRTSD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_FSQRT);
            if (i) {
                unsigned lane = (dec->opcode == HB_INS_SQRTPD || dec->opcode == HB_INS_SQRTSD) ? 8 : 4;
                bool scalar = (dec->opcode == HB_INS_SQRTSS || dec->opcode == HB_INS_SQRTSD);
                i->dst = dst;
                i->src1 = vector_src1_from_dec(dec, dst);
                i->src2 = has_vex_src(dec) ? operand_from_dec(dec, 3) : src;
                i->target = evex_target_arg(dec, lane | (scalar ? 0x100 : 0));
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_RSQRTPS:
        case HB_INS_RSQRTSS:
        case HB_INS_RCPPS:
        case HB_INS_RCPSS: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            bool is_rsqrt = (dec->opcode == HB_INS_RSQRTPS || dec->opcode == HB_INS_RSQRTSS);
            bool scalar = (dec->opcode == HB_INS_RSQRTSS || dec->opcode == HB_INS_RCPSS);
            hb_ir_instr_t *i = hb_ir_emit(b, is_rsqrt ? HB_IR_FRSQRT : HB_IR_FRCP);
            if (i) {
                i->dst = dst;
                i->src1 = vector_src1_from_dec(dec, dst);
                i->src2 = has_vex_src(dec) ? operand_from_dec(dec, 3) : src;
                i->target = 4 | (scalar ? 0x100 : 0);
            }
            emit(b, i, dec);
            return HB_OK;
        }






        case HB_INS_DIVSD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            hb_ir_instr_t *i = hb_ir_emit(b, is_vex_decoded(dec) ? HB_IR_FDIV : HB_IR_DIVSD);
            if (i) {
                i->dst = dst;
                i->src1 = is_vex_decoded(dec) ? vector_src1_from_dec(dec, dst) : dst;
                i->src2 = is_vex_decoded(dec) ? vector_src2_from_dec(dec) : src;
                if (is_vex_decoded(dec)) i->target = dec->evex ? evex_target_arg(dec, 8 | 0x100) : (8 | 0x100);
            }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_CPUID: {
            emit(b, hb_ir_emit(b, HB_IR_CPUID), dec);
            return HB_OK;
        }

        case HB_INS_VERR:
        case HB_INS_VERW: {
            hb_ir_instr_t* i = hb_ir_emit(b, dec->opcode == HB_INS_VERR ? HB_IR_VERR : HB_IR_VERW);
            if (i) i->src1 = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }

        case HB_INS_PRIV:
        case HB_INS_IN:
        case HB_INS_OUT:
        case HB_INS_INS:
        case HB_INS_OUTS:
        case HB_INS_HLT:
            /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 939 — НА x64 СЛУЧАЯ НЕ БЫЛО ВОВСЕ.
             * Декодер эти пять узнаёт (`op=IN/OUT/INS/OUTS/HLT`, длина верна), а лифтер до них
             * не доходил, и они падали в общий отказ `-5` без вида. Ветвь x86-32 узлы отказа
             * для них имела с самого начала — расхождение двух ветвей на одном и том же классе.
             * Замер на Prism в обеих разрядностях: все пять дают `0xC0000096`. */
            emit(b, hb_ir_emit_fault_priv(b, "privileged instruction in user-mode guest"), dec);
            return HB_OK;
        case HB_INS_XGETBV: {
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
        case HB_INS_RDRAND:
            /* dst = r/m register (slot 1); interpreter fills it with a random
             * value and sets CF=1 / clears OF/SF/ZF/AF/PF (Patch H). */
            emit(b, hb_ir_emit_unop(b, HB_IR_RDRAND, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_RDSEED:
            emit(b, hb_ir_emit_unop(b, HB_IR_RDSEED, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_X87_FNCLEX:
        case HB_INS_X87_FNINIT:
            /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 345 — БЫЛО `HB_IR_NOP`.
             *
             * Путь x86-32 выпускает здесь настоящий `HB_IR_X87_FNINIT`, а путь x64 — пустышку,
             * то есть сопроцессор не инициализировался вовсе: управляющее слово оставалось 0
             * вместо 0x037F. Разные пути для одной команды — это расхождение само по себе. */
            emit(b, hb_ir_emit(b, HB_IR_X87_FNINIT), dec);
            return HB_OK;

        /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 345 — ПЕРЕНОС ВОСЬМИ ОПКОДОВ x87.
         *
         * Замер: декодер x64 выдаёт 66 опкодов x87, лифтер обрабатывал 56, а 10 выдавались и
         * НЕ поднимались (FCMOV, FFREE, FFREEP, FI, FISTTP, FLDCW, FLDENV, FNSAVE, FNSTENV,
         * FRSTOR). Восемь из них уже реализованы на пути x86-32 — переносим дословно; FI и
         * FISTTP отсутствуют у обоих лифтеров и требуют собственной работы.
         *
         * Три из восьми — заглушки NOP и на x86: условное перемещение и освобождение регистра
         * стека мы не моделируем. Заглушка честнее отказа: отказ роняет весь блок. */
        case HB_INS_X87_FCMOV:
            emit(b, hb_ir_emit(b, HB_IR_NOP), dec);
            return HB_OK;
        /* ★ 30.08, лейн УСТАНОВЩИКИ: те же две команды были NOP и на стороне x64.
         * Набор конечен (два файла подъёма) — закрываю оба разом, а не по одному.
         * Разбор дефекта: hb_x87_ffree(). */
        case HB_INS_X87_FFREE: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_X87_FFREE);
            if (i) i->src1 = operand_from_dec(dec, 1);
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_X87_FFREEP: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_X87_FFREE);
            if (i) i->src1 = operand_from_dec(dec, 1);
            emit(b, i, dec);
            emit(b, hb_ir_emit(b, HB_IR_X87_FINCSTP), dec);
            return HB_OK;
        }
        case HB_INS_X87_FLDCW:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FLDCW, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FLDENV:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FLDENV, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FNSAVE:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FNSAVE, operand_from_dec(dec, 1), hb_ir_none()), dec);
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
        case HB_INS_X87_FLD:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FLD, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FST:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FST, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_X87_FSTP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FSTP, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        /* Итерация 907: безпрефиксные формы MMX. Тела перенесены с ветви x86-32 (итерации
         * 303-305, 883), где они работают; IR и интерпретатор общие, поэтому здесь нужна
         * ровно раздача, которой не было — до этого опкоды сваливались в HB_INS_MMX и
         * отказывали `-5`. */
        case HB_INS_MMX_SRL:
        case HB_INS_MMX_SRA:
        case HB_INS_MMX_SLL: {
            /* Разрядность элемента приходит из декодера в ret_imm. */
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
            hb_ir_op_t o = dec->opcode == HB_INS_MMX_AND  ? HB_IR_MMX_AND  :
                           dec->opcode == HB_INS_MMX_ANDN ? HB_IR_MMX_ANDN :
                           dec->opcode == HB_INS_MMX_OR   ? HB_IR_MMX_OR   : HB_IR_MMX_XOR;
            hb_ir_instr_t* i = hb_ir_emit(b, o);
            if (i) { i->dst = operand_from_dec(dec, 1); i->src1 = operand_from_dec(dec, 2); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_MMX_MOV: {
            hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_MMX_MOV);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->target = dec->op1.size ? dec->op1.size : dec->op2.size;
            }
            emit(b, i, dec);
            return HB_OK;
        }
        /* Итерация 906: семья `FI` — то же, что на ветви x86-32 (см. hb_lift_x86.c). */
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
        case HB_INS_X87_FNSTSW:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FNSTSW, operand_from_dec(dec, 1), hb_ir_none()), dec);
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
        /* ★ ОПЕРАНД У FCOMPP/FUCOMPP ЗДЕСЬ НЕ ПЕРЕДАВАЛСЯ ВОВСЕ.
         * Исполнитель берёт номер регистра из `src1` (`x87_st_index`), а тут
         * стоял `hb_ir_emit` без операндов — src1 пуст, и обе формы отвечали
         * -99 (внутренняя ошибка). Ветвь i386 передавала операнд с самого
         * начала (`hb_lift_x86.c`), то есть отставала ровно эта. Декодер номер
         * кладёт: у `de d9` и `da e9` это ST(1). */
        case HB_INS_X87_FCOMPP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FCOMPP, hb_ir_none(),
                                    operand_from_dec(dec, 1)), dec);
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
        case HB_INS_X87_FXSAVE:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FXSAVE, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_X87_FXRSTOR:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FXRSTOR, hb_ir_none(), operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FRNDINT:
            emit(b, hb_ir_emit(b, HB_IR_X87_FRNDINT), dec);
            return HB_OK;
        /* x87 FCMOVcc / FFREE / FFREEP — the x64 decoder doesn't produce
         * these today (they're rare on 64-bit code) but the lifter should
         * still handle them in case the decoder is ever extended. Until
         * then the existing FCMOV/FFREEP NOP stand-ins keep the build
         * green. Listed here only as documentation; the actual handlers
         * remain above. */
        /* FUCOM family — gap matrix #8 fix. */
        case HB_INS_X87_FUCOM:   /* итерация 892: тоже читает src1 в интерпретаторе */
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FUCOM, hb_ir_none(),
                                    operand_from_dec(dec, 1)), dec);
            return HB_OK;
        /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 892 — ОПЕРАНД СЕМЬИ СРАВНЕНИЙ.
         * Здесь операции выпускались БЕЗ операнда (`hb_ir_emit`), а интерпретатор читает
         * `instr->src1` (`x87_fcomi_st(ctx, &instr->src1, …)`) — отсюда `HB_ERR_INTERNAL`
         * на 37 случаях в наборе x86-64. Лифтер x86 делает это правильно и служит образцом:
         * индекс `ST(i)` передаётся первым источником.
         * Признак, по которому это отличается от переполнения стека (891): отказ был и при
         * ЗАНЯТОМ регистре — `dbe9 fucomi st(1)` давал -99 на x64 и 0 на x86. */
        case HB_INS_X87_FUCOMP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FUCOMP, hb_ir_none(),
                                    operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FCOMI:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FCOMI, hb_ir_none(),
                                    operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FUCOMI:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FUCOMI, hb_ir_none(),
                                    operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FCOMPI:  /* decoder alias for FCOMIP */
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FCOMIP, hb_ir_none(),
                                    operand_from_dec(dec, 1)), dec);
            return HB_OK;
        case HB_INS_X87_FUCOMPI: /* decoder alias for FUCOMIP */
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FUCOMIP, hb_ir_none(),
                                    operand_from_dec(dec, 1)), dec);
            return HB_OK;
        /* D9 F0-FF transcendentals — gap matrix #6. */
        case HB_INS_X87_FSQRT:   emit(b, hb_ir_emit(b, HB_IR_X87_FSQRT), dec);   return HB_OK;
        case HB_INS_X87_F2XM1:   emit(b, hb_ir_emit(b, HB_IR_X87_F2XM1), dec);   return HB_OK;
        case HB_INS_X87_FYL2X:   emit(b, hb_ir_emit(b, HB_IR_X87_FYL2X), dec);   return HB_OK;
        case HB_INS_X87_FPTAN:   emit(b, hb_ir_emit(b, HB_IR_X87_FPTAN), dec);   return HB_OK;
        case HB_INS_X87_FPATAN:  emit(b, hb_ir_emit(b, HB_IR_X87_FPATAN), dec);  return HB_OK;
        case HB_INS_X87_FXTRACT: emit(b, hb_ir_emit(b, HB_IR_X87_FXTRACT), dec); return HB_OK;
        case HB_INS_X87_FPREM1:  emit(b, hb_ir_emit(b, HB_IR_X87_FPREM1), dec);  return HB_OK;
        case HB_INS_X87_FPREM:   emit(b, hb_ir_emit(b, HB_IR_X87_FPREM), dec);   return HB_OK;
        case HB_INS_X87_FYL2XP1: emit(b, hb_ir_emit(b, HB_IR_X87_FYL2XP1), dec); return HB_OK;
        case HB_INS_X87_FSINCOS: emit(b, hb_ir_emit(b, HB_IR_X87_FSINCOS), dec); return HB_OK;
        case HB_INS_X87_FSCALE:  emit(b, hb_ir_emit(b, HB_IR_X87_FSCALE), dec);  return HB_OK;
        case HB_INS_X87_FSIN:    emit(b, hb_ir_emit(b, HB_IR_X87_FSIN), dec);    return HB_OK;
        case HB_INS_X87_FCOS:    emit(b, hb_ir_emit(b, HB_IR_X87_FCOS), dec);    return HB_OK;
        /* Environment + control — same as x86. */
        case HB_INS_X87_FXAM:    emit(b, hb_ir_emit(b, HB_IR_X87_FXAM), dec);    return HB_OK;
        case HB_INS_X87_FINCSTP: emit(b, hb_ir_emit(b, HB_IR_X87_FINCSTP), dec); return HB_OK;
        case HB_INS_X87_FDECSTP: emit(b, hb_ir_emit(b, HB_IR_X87_FDECSTP), dec); return HB_OK;
        /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1075 — FNSTCW БЕЗ ПРИЁМНИКА.
         * ТРЕТИЙ случай того же класса за две итерации (после `FIST`, 1068): лифтер x64
         * выпускал команду без операндов, а интерпретатор требует приёмник в памяти
         * (`hb_interpreter.c`, `if (instr->dst.type != HB_OP_MEM) return HB_ERR_INTERNAL`).
         * Замер до правки: `d938` (`fnstcw [rax]`) -> `interp_error:0/-99`.
         * Найдено СПЛОШНОЙ проверкой класса, а не по случаю: из 21 нуль-операндного выпуска
         * лифтера x64 операнд требуется ровно у этого одного. Ветвь i386 выпускает верно. */
        case HB_INS_X87_FNSTCW:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FNSTCW, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
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
        /* ★ 05.09.2026 — У ВЕТВИ i386 ЭТОТ СЛУЧАЙ БЫЛ С САМОГО НАЧАЛА
         * (`hb_lift_x86.c`), у x64 его не было вовсе. Опкод ставит декодер, когда
         * КОМАНДА разобрана верно, а НЕДОПУСТИМО СОЧЕТАНИЕ — расширение, которого
         * на машине нет, либо префикс LOCK на команде, которой он не положен
         * (hb_zamok_pravilo.h). Ответ железа тот же, что у UD2: #UD, c000001d, и
         * приходит он ТОЧНО на этой команде, потому что длина разобрана честно. */
        case HB_INS_UNAVAILABLE_EXT:
            emit(b, hb_ir_emit_fault_illegal(b, "недопустимое сочетание префикса и команды"), dec);
            return HB_OK;
        /* Итерация 1095: шесть привилегированных получили свои имена; поведение прежнее —
         * тот же отказ по привилегиям, что и у общего `HB_INS_PRIV`. */
        /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1096 — `PUSH FS/GS` НА x64.
         * У ветви i386 случай есть с самого начала (`hb_lift_x86.c:1848`), у x64 не было
         * ВОВСЕ — пятый за серию случай «две дороги к одному». Это же стояло на доске
         * открытым пунктом «нужно сегментное состояние x64»: состояние есть
         * (`ctx->seg_fs`/`seg_gs`), не хватало ровно этих строк. */
        case HB_INS_PUSH_SEG: {
            hb_ir_instr_t *i;
            /* Гейт снят 02.09.2026: выключенная ветка отдавала «неподдержанный опкод»
             * (или NOP) на команде, которая разобрана верно, — это заведомо сломанное
             * поведение, и держать его за выключателем незачем. Разбираем всегда. */
            i = hb_ir_emit(b, HB_IR_PUSH_SEG);
            if (i) { i->src1 = operand_from_dec(dec, 1); i->src2 = operand_from_dec(dec, 2); }
            emit(b, i, dec);
            return HB_OK;
        }
        case HB_INS_POP_SEG: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_POP_SEG);
            if (i) { i->dst = operand_from_dec(dec, 1); i->src2 = operand_from_dec(dec, 2); }
            emit(b, i, dec);
            return HB_OK;
        }
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

        /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1068 — FIST БЕЗ ПРИЁМНИКА.
         *
         * Здесь выпускалась команда БЕЗ ОПЕРАНДОВ, а интерпретатор требует приёмник в памяти
         * (`hb_interpreter.c:4335`: `if (instr->dst.type != HB_OP_MEM) return HB_ERR_INTERNAL`).
         * Дефект жил незамеченным, потому что декодер x64 до этой же итерации НИКОГДА не
         * отдавал `FIST` — он ставил `FST` (см. `hb_decode_x64.c`, `DB /2` и `DF /2`). Починив
         * декодер, я тут же получил `interp_error:0/-99` — второй слой той же болезни.
         * Ветвь i386 выпускает верно (`hb_lift_x86.c:1533`), переношу её форму. */
        case HB_INS_X87_FIST:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FIST, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        /* D9 D0/E0/E1/E4 — same handlers as x86. */
        case HB_INS_X87_FNOP:    emit(b, hb_ir_emit(b, HB_IR_X87_FNOP), dec);    return HB_OK;
        case HB_INS_X87_FCHS:    emit(b, hb_ir_emit(b, HB_IR_X87_FCHS), dec);    return HB_OK;
        case HB_INS_X87_FABS:    emit(b, hb_ir_emit(b, HB_IR_X87_FABS), dec);    return HB_OK;
        case HB_INS_X87_FTST:    emit(b, hb_ir_emit(b, HB_IR_X87_FTST), dec);    return HB_OK;
        /* MISC safety net — same as x86. */
        case HB_INS_X87_MISC:
            emit(b, hb_ir_emit(b, HB_IR_NOP), dec);
            return HB_OK;
        /* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 475 — CLI/STI подняты и на x64.
         * На i386 они поднимались (`hb_lift_x86.c:1701`), на x64 — нет, и отказ выдавался
         * лифтером как UNSUPPORTED_OPCODE ещё до интерпретатора (замер 472). Замер 474 показал,
         * что эталон эти команды ИСПОЛНЯЕТ: в согласии сторон (2198 случаев) их ноль.
         * Обработчики уже есть — CLI/STI ведут бит IF с итерации 466. Это перенос, не семантика. */
        case HB_INS_CLI:
            emit(b, hb_ir_emit(b, HB_IR_CLI), dec);
            return HB_OK;
        case HB_INS_STI:
            emit(b, hb_ir_emit(b, HB_IR_STI), dec);
            return HB_OK;
        case HB_INS_NOP: {
            emit(b, hb_ir_emit(b, HB_IR_NOP), dec);
            return HB_OK;
        }
        /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 349 — ФЛАГОВЫЕ КОМАНДЫ БЫЛИ ТОЛЬКО У x86.
         *
         * Декодер x64 выдаёт `CLC`, `STC`, `CMC` (по два упоминания в `hb_decode_x64.c`), а
         * лифтер x64 не имел для них ни одной ветви — отсюда `UNSUPPORTED_OPCODE` при живом
         * декодере. Замер до правки: `f8`, `f9`, `f5` дают `r=0` при `HB_DIFF_ARCH=x86` и
         * `r=-5` при `x64`, на одних и тех же байтах. Операции IR (`HB_IR_CLC/STC/CMC`) общие,
         * интерпретатор их знает — перенос дословный, как у `CLD`/`STD` рядом. */
        /* Итерация 350: декодер x64 выдаёт FISTTP (4 упоминания), лифтер не поднимал — 4 отказа
         * UNSUPPORTED_OPCODE в наборе. Операнд-приёмник в памяти, как у FISTP рядом. */
        case HB_INS_X87_FISTTP:
            emit(b, hb_ir_emit_unop(b, HB_IR_X87_FISTTP, operand_from_dec(dec, 1), hb_ir_none()), dec);
            return HB_OK;
        case HB_INS_CLC: {
            emit(b, hb_ir_emit(b, HB_IR_CLC), dec);
            return HB_OK;
        }
        case HB_INS_STC: {
            emit(b, hb_ir_emit(b, HB_IR_STC), dec);
            return HB_OK;
        }
        case HB_INS_CMC: {
            emit(b, hb_ir_emit(b, HB_IR_CMC), dec);
            return HB_OK;
        }
        case HB_INS_CLD: {
            emit(b, hb_ir_emit(b, HB_IR_CLD), dec);
            return HB_OK;
        }
        case HB_INS_STD: {
            emit(b, hb_ir_emit(b, HB_IR_STD), dec);
            return HB_OK;
        }
        case HB_INS_FENCE: {
            emit(b, hb_ir_emit_fence(b, (hb_fence_kind_t)dec->op1.imm), dec);
            return HB_OK;
        }
        default:
            /* Прежде чем сдаться — ОСОБЫЕ формы и ОБЩИЙ список.
             * Обе двери ведут в один текст hb_lift_vec_obshchee.inc, поэтому
             * добавленное однажды служит и x64, и i386: отставать нечему. */
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

hb_result_t hb_lift_func_x64(hb_decoder_t* dec, hb_ir_func_t** out) {
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
    size_t merged = 0;   /* сколько условных переходов уже поглощено этой единицей */
    while (hb_decode_next(dec, &d) == HB_OK || d.opcode == HB_INS_UNSUPPORTED) {
        size_t pre_instr = block->instr_count;
        hb_result_t r = hb_lift_x64(&d, b);
        if (r != HB_OK && r != HB_ERR_UNSUPPORTED_FEATURE) {
            hb_ir_builder_destroy(b);
            hb_ir_func_destroy(func);
            return r;
        }
        /* MacRunner Lane A (2026-06-17): propagate the x86 LOCK prefix (0xF0) to every IR
         * instr lifted from this op, so codegen brackets it with a DMB barrier.  Mono's
         * hazard-pointer loops use `lock or [rsp],r` purely as a store->load fence; without
         * the barrier the re-read is reordered/stale on ARM64 and the loop livelocks. */
        if (d.lock_prefix) {
            for (size_t k = pre_instr; k < block->instr_count; k++)
                block->instrs[k].is_locked = true;
        }
        /* ★ ПЕРЕПИСЬ ДЛЯ ГРАФА АНАЛИЗА — ровно в той точке, где уже известны и гостевые
         * байты, и диапазон порождённых IR-команд. Заносится КАЖДАЯ декодированная
         * команда, включая ту, у которой ir_count == 0: восстановить это потом по
         * повторяющимся guest_addr нельзя (одна гостевая команда даёт несколько IR,
         * а пустая потерялась бы). При закрытом гейте функция выходит первой строкой. */
        hb_cfg_ledger_note(func, d.addr, d.len, pre_instr, block->instr_count - pre_instr,
                           d.is_branch, d.is_conditional, d.is_call, d.is_ret,
                           d.is_branch && d.branch_target != 0, d.branch_target);
        count++;
        if (d.is_branch || d.is_ret || d.is_call) {
            /* ★★★ MacRunner 2026-09-04, лейн ЕДИНИЦА — ЗДЕСЬ СТОЯЛ БЕЗУСЛОВНЫЙ ОБРЫВ.
             *
             * Было: `/ * For MVP: single basic block per function. * / break;` — единица
             * трансляции кончалась на ПЕРВОМ переходе, вызове или возврате. Замер по корпусу
             * fixtures/x64 (117 настоящих PE x86-64, линейный обход .text): 2,046 команды и
             * 6,329 байта на единицу. Все места, где мы платим дороже эталонов, висят на
             * переходе; у box64 предел единицы 32760 команд, у FEX — 5000.
             *
             * ПОЧЕМУ ОБРЫВ НЕ СНЯТ СОВСЕМ, а только за условным переходом. У безусловного
             * перехода, вызова и возврата ПРОВАЛА НЕТ: байты за ними принадлежат другой
             * единице (а часто и не коду вовсе — там выравнивание и данные). Поднимать их
             * значило бы переводить чужое. За условным переходом провал есть ВСЕГДА, и
             * продолжить разбор — та же работа, что разобрать следующий блок, только без
             * выхода в диспетчер.
             *
             * Правило продления общее с ветвью i386 (hb_lift_edinica_prodlit, hb_lift_x86.c) —
             * второй экземпляр правил в этом дереве уже приводил к молча разошедшейся паре.
             *
             * Продление СВЯЗАНО с выпуском: пока гейт MACRUNNER_HB_MERGE_BLOCKS выключен,
             * кодогенератор всё равно обрывает выпуск на первом переходе
             * (codegen_instr_limit_before_fallthrough, hb_arm64_codegen.c) — то есть при
             * выключенном гейте поведение ровно прежнее, байт в байт. */
            /* ★ СТОРОЖ СЛИЯНИЯ ОБЯЗАН ПОЛУЧАТЬ ЕДУ И ЗДЕСЬ. Цель перехода ВНЕ окна разбора —
             * это будущий вход блока: заносим упреждающе, чтобы будущая единица резалась ДО
             * того, как накроет его, а не после состоявшегося дубля перевода. Без этой строки
             * на ветви x64 реестр входов оставался бы ПУСТ, и рез (MERGE_CUT_AT_ENTRY) был бы
             * односторонним: слияние x64 включено, а защита от него — нет. Цель ВНУТРИ окна не
             * заносим: она и есть повод для слияния. Перенесено с ветви i386. */
            if (d.is_branch && d.branch_target &&
                !(d.branch_target >= dec->base_addr &&
                  d.branch_target - dec->base_addr < (uint64_t)dec->code_len))
                hb_known_entry_note(d.branch_target);
            if (hb_lift_edinica_prodlit(dec, &d, merged)) { merged++; continue; }
            break;
        }
        if (count >= instr_limit) {
            if (dec->pos < dec->code_len) {
                func->truncated = true;
                func->truncation_reason = "x64 lifter instruction limit";
            }
            break;
        }
    }

    /* ★ ПОСТРОЕНИЕ ГРАФА АНАЛИЗА — после окончания разбора и ДО публикации IR.
     * Отказ построения означает «анализ недоступен» (`acfg->complete == 0`), а не
     * граф с потерянной дугой, и на успешность самого перевода не влияет. */
    hb_cfg_build(func, block);

    hb_ir_builder_destroy(b);
    *out = func;
    return HB_OK;
}
