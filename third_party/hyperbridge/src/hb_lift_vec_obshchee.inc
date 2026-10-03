/* ОБЩИЙ ПОДЪЁМ ВЕКТОРНОЙ КОМАНДЫ — один текст на ОБЕ ветви.
 *
 * ЗАЧЕМ. Разбор формы операндов (какая команда унарная, какая берёт
 * приёмник первым источником, какая трёхоперандная по VEX) был записан
 * ДВАЖДЫ: подробным деревом в hb_lift_x64.c и одним булевым признаком
 * `unary` в hb_lift_x86.c. Ветвь i386 отставала, и отставание было
 * невидимым: доска называла ЧИСЛО отказов подъёма, но не имена.
 *
 * ЗАМЕР, НАЗВАВШИЙ КОРЕНЬ. Из 107 кодировок, которых i386 не поднимал,
 * 104 поднимает x64, и НИ ОДНОЙ нет у обоих. Команды все реализованы —
 * отставала одна ветвь.
 *
 * ПОЧЕМУ ТЕКСТОВЫМ ВКЛЮЧЕНИЕМ, А НЕ ФУНКЦИЕЙ В .c. Тело опирается на
 * `operand_from_dec` и `emit`, а они у ветвей СВОИ: имена регистров в
 * 32 и 64 битах разные. Включение связывается с опорами ТОЙ единицы
 * трансляции, куда вошло, — поэтому текст один, а связывание два.
 *
 * Единица, включающая этот файл, обязана определить:
 *   operand_from_dec(dec, n)      свои операнды
 *   emit(b, i, dec)               свой выпуск
 *   vec_op_from_ins(opcode)       разворот общего списка hb_vec_sootv.h
 *   HB_EVEX_TARGET_ARG(dec, imm)  свою упаковку маски EVEX
 */
#ifndef HB_LIFT_VEC_OBSHCHEE_VKLYUCHENO
#define HB_LIFT_VEC_OBSHCHEE_VKLYUCHENO


static hb_result_t hb_vek_obshchij(const hb_decoded_t* dec, hb_ir_builder_t* b) {
    hb_ir_vec_op_t op = vec_op_from_ins(dec->opcode);
    hb_ir_operand_t dst = operand_from_dec(dec, 1);
    hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_VEC_PACKED);
    if (i) {
        uint64_t imm = dec_imm8(dec);
        i->dst = dst;
        i->src1 = hb_ir_none();
        i->src2 = hb_ir_none();
        if (dec->opcode == HB_INS_PTEST ||
            dec->opcode == HB_INS_VTESTPS || dec->opcode == HB_INS_VTESTPD) {
            i->src1 = dst;
            i->src2 = operand_from_dec(dec, 2);
        /* VMASKMOVDQU здесь БЫЛ и был сломан: путь VEC_PACKED ждёт маску в
         * `src2`, а ветка клала её в `src1` — исполнитель отвечал -99 на всех
         * формах. Второй путь к той же команде уже есть и работает: узел
         * HB_IR_MASKMOV, которым i386 поднимает `MASKMOVQ`/`MASKMOVDQU`.
         * Двух дорог к одной команде быть не должно — эта убрана, обе ветви
         * лифтера теперь ведут форму VEX туда же, куда и старую.
         *
         * MPSADBW/PALIGNR/PBLENDW/BLENDPS/BLENDPD жили здесь отдельной веткой
         * `src1 = приёмник`. Для старой формы SSE это верно, но для формы VEX —
         * нет: там первый источник в `vvvv`. Ветка была ЛЕСАМИ вокруг изъяна
         * декодера, который `vvvv` у этих форм не читал вовсе; изъян снят
         * (hb_decode_x64.c, карта 0F3A), и ветка стала не только лишней, но и
         * вредной — общий `else` ниже даёт ОБЕ формы верно:
         * `vector_src1_from_dec` возвращает приёмник ровно тогда, когда третьего
         * операнда-регистра нет, то есть у старой формы. */
        } else if (dec->opcode == HB_INS_PABSB || dec->opcode == HB_INS_PABSW ||
                   dec->opcode == HB_INS_PABSD) {
            i->src1 = vector_src2_from_dec(dec);
        } else if ((dec->opcode >= HB_INS_PMOVSXBW && dec->opcode <= HB_INS_PMOVSXDQ) ||
                    (dec->opcode >= HB_INS_PMOVZXBW && dec->opcode <= HB_INS_PMOVZXDQ) ||
                    dec->opcode == HB_INS_PHMINPOSUW ||
                    (dec->opcode >= HB_INS_VPBROADCASTB && dec->opcode <= HB_INS_VBROADCASTI128) ||
                    dec->opcode == HB_INS_VMOVSLDUP ||
                    dec->opcode == HB_INS_VMOVSHDUP ||
                    dec->opcode == HB_INS_VMOVDDUP ||
                    dec->opcode == HB_INS_AESKEYGENASSIST ||
                    dec->opcode == HB_INS_AESIMC) {
            i->src1 = operand_from_dec(dec, 2);
        } else if (dec->opcode == HB_INS_VPERMQ || dec->opcode == HB_INS_VPERMPD ||
                   dec->opcode == HB_INS_VEXTRACTF128 || dec->opcode == HB_INS_VEXTRACTI128 ||
                   ((dec->opcode == HB_INS_VPERMILPS || dec->opcode == HB_INS_VPERMILPD) &&
                    dec->op3.is_imm)) {
            i->src1 = operand_from_dec(dec, 2);
        } else if ((dec->opcode == HB_INS_VCMPPS || dec->opcode == HB_INS_VCMPPD ||
                    dec->opcode == HB_INS_VCMPSS || dec->opcode == HB_INS_VCMPSD) &&
                   dec->op3.is_imm) {
            /* MacRunner: legacy (non-VEX) CMP{PS,PD,SS,SD} = 2-operand form
             * `cmpXXps dst, src, imm8`: dst is ALSO the first compare operand,
             * src is op2, the imm8 predicate is op3 (read via dec_imm8). The VEX
             * 3-operand form (src1=op2, src2=op3-reg, imm8 separate) is handled
             * by the branch below. Without this, src2 was set to op3 = the imm8,
             * read as a vector operand -> INTERNAL/memory fault. */
            i->src1 = dst;
            i->src2 = operand_from_dec(dec, 2);
        } else if (dec->opcode == HB_INS_VPBLENDD ||
                   dec->opcode == HB_INS_VBLENDVPS || dec->opcode == HB_INS_VBLENDVPD ||
                   dec->opcode == HB_INS_VPBLENDVB ||
                   dec->opcode == HB_INS_VINSERTF128 || dec->opcode == HB_INS_VINSERTI128 ||
                   dec->opcode == HB_INS_VPERM2F128 || dec->opcode == HB_INS_VPERM2I128 ||
                   dec->opcode == HB_INS_VPSRLVD || dec->opcode == HB_INS_VPSRLVQ ||
                   dec->opcode == HB_INS_VPSRAVD ||
                   dec->opcode == HB_INS_VPSLLVD || dec->opcode == HB_INS_VPSLLVQ ||
                   dec->opcode == HB_INS_VPCLMULQDQ ||
                    dec->opcode == HB_INS_VPERMD || dec->opcode == HB_INS_VPERMPS ||
                    dec->opcode == HB_INS_VPERMILPS || dec->opcode == HB_INS_VPERMILPD ||
                    dec->opcode == HB_INS_VCMPPS || dec->opcode == HB_INS_VCMPPD ||
                    dec->opcode == HB_INS_VCMPSS || dec->opcode == HB_INS_VCMPSD ||
                    dec->opcode == HB_INS_VMASKMOVPS || dec->opcode == HB_INS_VMASKMOVPD ||
                    dec->opcode == HB_INS_VPMASKMOVD || dec->opcode == HB_INS_VPMASKMOVQ ||
                    dec->opcode == HB_INS_VAESENC || dec->opcode == HB_INS_VAESENCLAST ||
                   dec->opcode == HB_INS_VAESDEC || dec->opcode == HB_INS_VAESDECLAST ||
                   dec->opcode == HB_INS_VGF2P8MULB ||
                   dec->opcode == HB_INS_VGF2P8AFFINEQB ||
                   dec->opcode == HB_INS_VGF2P8AFFINEINVQB ||
                   dec->opcode == HB_INS_VMPSADBW ||
                    (dec->opcode >= HB_INS_VGATHERDPS && dec->opcode <= HB_INS_VPGATHERQQ)) {
            i->src1 = operand_from_dec(dec, 2);
            i->src2 = operand_from_dec(dec, 3);
        } else if (dec->opcode >= HB_INS_VFMADD132PS &&
                   dec->opcode <= HB_INS_VFNMSUB231SD) {
            i->src1 = operand_from_dec(dec, 2);
            i->src2 = operand_from_dec(dec, 3);
            imm = fma_target_from_ins(dec->opcode);
        } else if (dec->opcode == HB_INS_VCVTPH2PS || dec->opcode == HB_INS_VCVTPS2PH) {
            i->src1 = operand_from_dec(dec, 2);
        } else if (dec->opcode == HB_INS_PCMPESTRM || dec->opcode == HB_INS_PCMPESTRI ||
                   dec->opcode == HB_INS_PCMPISTRM || dec->opcode == HB_INS_PCMPISTRI) {
            i->dst = (dec->opcode == HB_INS_PCMPESTRI || dec->opcode == HB_INS_PCMPISTRI)
                   ? hb_ir_reg(HB_REG_RCX, HB_SIZE_32)
                   : hb_ir_reg(HB_REG_XMM0, HB_SIZE_128);
            i->src1 = operand_from_dec(dec, 1);
            i->src2 = operand_from_dec(dec, 2);
        } else if (dec->opcode == HB_INS_AESENC || dec->opcode == HB_INS_AESENCLAST ||
                   dec->opcode == HB_INS_AESDEC || dec->opcode == HB_INS_AESDECLAST ||
                   dec->opcode == HB_INS_GF2P8MULB ||
                   dec->opcode == HB_INS_GF2P8AFFINEQB ||
                   dec->opcode == HB_INS_GF2P8AFFINEINVQB) {
            i->src1 = dst;
            i->src2 = operand_from_dec(dec, 2);
        } else {
            i->src1 = vector_src1_from_dec(dec, dst);
            i->src2 = vector_src2_from_dec(dec);
        }
        i->target = vec_target(op, HB_EVEX_TARGET_ARG(dec, imm));
    }
    emit(b, i, dec);
    return HB_OK;
}

/* ОСОБЫЕ ВЕКТОРНЫЕ ФОРМЫ — те, что не сводятся к общему списку.
 *
 * Половинчатые пересылки (movlps/movhps/movlhps), округление, скалярное
 * произведение, вставка и извлечение по непосредственному. У них своя форма
 * операндов, поэтому таблицей «команда -> операция» они не покрываются.
 *
 * Жили ОТДЕЛЬНЫМИ ветвями в hb_lift_x64.c, а в hb_lift_x86.c не жили вовсе:
 * замер показал 20 таких кодировок, которые x64 поднимает, а i386 нет.
 * Тела нейтральны — только operand_from_dec и emit, — поэтому текст один.
 *
 * Возвращает false, если команда не её; тогда вызывающий пробует дальше. */
static bool hb_vek_osobye(const hb_decoded_t* dec, hb_ir_builder_t* b,
                          hb_result_t* itog) {
    switch (dec->opcode) {
        case HB_INS_MOVDIRI: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_store(b, dst, src), dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_SSE_MOV:
        case HB_INS_MOVNTDQA: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            unsigned evex_lane = dec->evex_mask_lane ? dec->evex_mask_lane : 0;
            if (dec->op1.is_mem && dec->op2.is_reg) {
                hb_ir_instr_t* i = emit(b, hb_ir_emit_store(b, dst, src), dec);
                set_evex_target_arg(i, dec, evex_lane);
            } else if (is_vex_decoded(dec) && dec->op1.is_reg &&
                       dec->op1.reg >= HB_REG_XMM0 && dec->op1.reg <= HB_REG_XMM31 &&
                       ((dec->op2.is_mem && (dec->op2.size == 4 || dec->op2.size == 8)) ||
                        (dec->op3.present && (dec->op3.size == 4 || dec->op3.size == 8)))) {
                hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_XMM_SCALAR_MOV);
                if (i) {
                    i->dst = dst;
                    i->src1 = dec->op3.present ? src : hb_ir_none();
                    i->src2 = dec->op3.present ? operand_from_dec(dec, 3) : src;
                    i->target = evex_target_arg(dec, dec->op3.present ? dec->op3.size : dec->op2.size);
                    if (!dec->op3.present && dec->op2.is_mem) i->zero_upper = true;
                }
                emit(b, i, dec);
            } else if (dec->op1.is_reg && dec->op2.is_mem) {
                hb_ir_instr_t* i = emit(b, hb_ir_emit_load(b, dst, src), dec);
                if (i) {
                    i->zero_upper = is_legacy_scalar_sse_mem_load(dec);
                    set_evex_target_arg(i, dec, evex_lane);
                }
            } else {
                hb_ir_instr_t* i = emit(b, hb_ir_emit_mov(b, dst, src), dec);
                set_evex_target_arg(i, dec, evex_lane);
            }
            *itog = HB_OK; return true;
        }
        case HB_INS_VMOVHLPS:
        case HB_INS_VMOVLHPS: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src1 = operand_from_dec(dec, 2);
            hb_ir_instr_t *copy = hb_ir_emit_mov(b, dst, src1);
            emit(b, copy, dec);
            hb_ir_instr_t *lane = hb_ir_emit(b, HB_IR_XMM_QWORD_LANE_MOV);
            if (lane) {
                unsigned dst_lane = dec->opcode == HB_INS_VMOVLHPS ? 1 : 0;
                unsigned src_lane = dec->opcode == HB_INS_VMOVHLPS ? 1 : 0;
                lane->dst = dst;
                lane->src1 = operand_from_dec(dec, 3);
                lane->target = dst_lane | (src_lane << 8);
                lane->zero_ymm_upper = true;
            }
            emit(b, lane, dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_VMOVLPS:
        case HB_INS_VMOVHPS:
        case HB_INS_VMOVLPD:
        case HB_INS_VMOVHPD: {
            bool store = dec->op1.is_mem;
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            unsigned lane_id = (dec->opcode == HB_INS_VMOVHPS ||
                                dec->opcode == HB_INS_VMOVHPD) ? 1 : 0;
            if (!store) {
                hb_ir_instr_t *copy = hb_ir_emit_mov(b, dst, src);
                emit(b, copy, dec);
            }
            hb_ir_instr_t *lane = hb_ir_emit(b, HB_IR_XMM_QWORD_LANE_MOV);
            if (lane) {
                lane->dst = dst;
                lane->src1 = store ? src : operand_from_dec(dec, 3);
                lane->target = lane_id | (lane_id << 8);
                lane->zero_ymm_upper = !store;
            }
            emit(b, lane, dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_ROUNDPS:
        case HB_INS_ROUNDPD:
        case HB_INS_ROUNDSS:
        case HB_INS_ROUNDSD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            bool scalar = dec->opcode == HB_INS_ROUNDSS || dec->opcode == HB_INS_ROUNDSD;
            unsigned lane = (dec->opcode == HB_INS_ROUNDPD || dec->opcode == HB_INS_ROUNDSD) ? 8 : 4;
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_FROUND);
            if (i) {
                i->dst = dst;
                i->src1 = vector_src1_from_dec(dec, dst);
                i->src2 = has_vex_src(dec) ? operand_from_dec(dec, 3) : src;
                i->target = lane | (scalar ? 0x100 : 0) | ((uint64_t)dec_imm8(dec) << 16);
            }
            emit(b, i, dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_DPPS:
        case HB_INS_DPPD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            unsigned lane = dec->opcode == HB_INS_DPPD ? 8 : 4;
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_FDP);
            if (i) {
                i->dst = dst;
                i->src1 = has_vex_src(dec) ? operand_from_dec(dec, 2) : dst;
                i->src2 = has_vex_src(dec) ? operand_from_dec(dec, 3) : src;
                i->target = lane | ((uint64_t)dec_imm8(dec) << 16);
            }
            emit(b, i, dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_INSERTPS: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_INSERTPS);
            if (i) {
                i->dst = dst;
                i->src1 = has_vex_src(dec) ? operand_from_dec(dec, 2) : dst;
                i->src2 = has_vex_src(dec) ? operand_from_dec(dec, 3) : operand_from_dec(dec, 2);
                i->target = dec_imm8(dec);
            }
            emit(b, i, dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_EXTRACTPS: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_EXTRACTPS);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->target = dec_imm8(dec);
            }
            emit(b, i, dec);
            *itog = HB_OK; return true;
        }
        /* ★ ФОРМЫ MMX ВСТАВКИ И ИЗВЛЕЧЕНИЯ СЛОВА — СВОИ УЗЛЫ.
         * Общий HB_IR_PINSR/HB_IR_PEXTR пишет и читает РОВНО 16 байт, поэтому
         * приёмник-MMX им не выражается. Узлы HB_IR_PINSRW/HB_IR_PEXTRW умеют
         * оба файла регистров — ветвь i386 через них и поднимала; ветвь x64
         * форму MMX не разбирала вовсе, а теперь разбирает. */
        case HB_INS_PINSRW:
            if (dec->op1.is_reg && dec->op1.reg >= HB_REG_MM0 && dec->op1.reg <= HB_REG_MM7) {
                hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_PINSRW);
                if (i) {
                    i->dst = operand_from_dec(dec, 1);
                    i->src1 = vector_src1_from_dec(dec, i->dst);
                    i->src2 = vector_src2_from_dec(dec);
                    i->target = (uint64_t)dec_imm8(dec) & 7u;
                }
                emit(b, i, dec);
                *itog = HB_OK; return true;
            }
            goto vstavka_obshchaya;
        case HB_INS_PEXTRW:
            if (dec->op2.is_reg && dec->op2.reg >= HB_REG_MM0 && dec->op2.reg <= HB_REG_MM7) {
                hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_PEXTRW);
                if (i) {
                    i->dst = operand_from_dec(dec, 1);
                    i->src1 = operand_from_dec(dec, 2);
                    i->target = (uint64_t)dec_imm8(dec) & 7u;
                }
                emit(b, i, dec);
                *itog = HB_OK; return true;
            }
            goto izvlechenie_obshchee;

        /* SSE3 и перекладка MMX<->XMM — ОДИН текст на обе ветви.
         *
         * Всё это жило только в hb_lift_x86.c, а ветвь x64 не поднимала ни одной
         * из тринадцати команд: её декодер сваливал их в общие корзины, и лифтеру
         * нечего было брать. Декодер x64 научен (hb_decode_x64.c), подъём —
         * здесь, чтобы отставать было нечему.
         *
         * Признаки в `target` те же, что были у i386:
         *   HADDSUB: бит0 — двойная точность, бит1 — вычитание, бит2 — чередование;
         *   MOVDUP:  0 MOVDDUP, 1 MOVSLDUP, 2 MOVSHDUP;
         *   MASKMOV: бит0 — ширина (0 — MMX 8 байт, 1 — XMM 16);
         *   CVT_MMX_FP: бит0 — направление, бит1 — точность, бит2 — усечение. */
        case HB_INS_HADDPS:
        case HB_INS_HADDPD:
        case HB_INS_HSUBPS:
        case HB_INS_HSUBPD:
        case HB_INS_ADDSUBPS:
        case HB_INS_ADDSUBPD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_HADDSUB);
            if (i) {
                unsigned pr = 0;
                switch (dec->opcode) {
                    case HB_INS_HADDPS:   pr = 0;         break;
                    case HB_INS_HADDPD:   pr = 1;         break;
                    case HB_INS_HSUBPS:   pr = 2;         break;
                    case HB_INS_HSUBPD:   pr = 2 | 1;     break;
                    case HB_INS_ADDSUBPS: pr = 4;         break;
                    default:              pr = 4 | 1;     break;
                }
                i->dst = dst;
                i->src1 = vector_src1_from_dec(dec, dst);
                i->src2 = vector_src2_from_dec(dec);
                i->target = pr;
            }
            emit(b, i, dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_MOVDDUP:
        case HB_INS_MOVSLDUP:
        case HB_INS_MOVSHDUP: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_MOVDUP);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->src2 = hb_ir_none();
                i->target = (dec->opcode == HB_INS_MOVDDUP) ? 0 :
                            (dec->opcode == HB_INS_MOVSLDUP) ? 1 : 2;
            }
            emit(b, i, dec);
            *itog = HB_OK; return true;
        }
        /* MASKMOVQ / MASKMOVDQU / VMASKMOVDQU — побайтовая запись по маске в [RDI].
         * Форма VEX прежде уходила в общий путь вектора, где маску ждут в другом
         * операнде (-99 на всех формах); старые формы на x64 не поднимались вовсе. */
        case HB_INS_MASKMOVQ:
        case HB_INS_MASKMOVDQU:
        case HB_INS_VMASKMOVDQU: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_MASKMOV);
            if (i) {
                i->dst = hb_ir_none();
                i->src1 = operand_from_dec(dec, 1);
                i->src2 = operand_from_dec(dec, 2);
                i->target = (dec->opcode == HB_INS_MASKMOVQ) ? 0 : 1;
            }
            emit(b, i, dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_MOVQ2DQ:
        case HB_INS_MOVDQ2Q: {
            hb_ir_instr_t *i = hb_ir_emit(b, dec->opcode == HB_INS_MOVQ2DQ
                                             ? HB_IR_MOVQ2DQ : HB_IR_MOVDQ2Q);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->src2 = hb_ir_none();
            }
            emit(b, i, dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_CVTPI2PS:
        case HB_INS_CVTPI2PD:
        case HB_INS_CVTPS2PI:
        case HB_INS_CVTPD2PI:
        case HB_INS_CVTTPS2PI:
        case HB_INS_CVTTPD2PI: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_CVT_MMX_FP);
            if (i) {
                unsigned pr;
                switch (dec->opcode) {
                    case HB_INS_CVTPI2PS:  pr = 0;         break;
                    case HB_INS_CVTPI2PD:  pr = 2;         break;
                    case HB_INS_CVTPS2PI:  pr = 1;         break;
                    case HB_INS_CVTPD2PI:  pr = 1 | 2;     break;
                    case HB_INS_CVTTPS2PI: pr = 1 | 4;     break;
                    default:               pr = 1 | 2 | 4; break;
                }
                i->dst  = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->src2 = hb_ir_none();
                i->target = pr;
            }
            emit(b, i, dec);
            *itog = HB_OK; return true;
        }

        /* ★ НЕСОХРАНЯЮЩИЕ ЗАПИСИ И НЕВЫРОВНЕННОЕ ЧТЕНИЕ.
         * Декодер знал их с 04.09.2026, а лифтера не было НИ У ОДНОЙ ветви:
         * пять форм отвечали отказом подъёма. Подсказка «не сохранять в кеше»
         * для нас не значит ничего — остаётся обычная запись/чтение, и разница
         * с MOVNTDQ/MOVDQU только в этом. */
        case HB_INS_MOVNTI:
        case HB_INS_MOVNTQ:
        case HB_INS_MOVNTSS:
        case HB_INS_MOVNTSD: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_store(b, dst, src), dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_LDDQU: {
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_operand_t src = operand_from_dec(dec, 2);
            emit(b, hb_ir_emit_load(b, dst, src), dec);
            *itog = HB_OK; return true;
        }

        case HB_INS_PINSRB:
        vstavka_obshchaya:
        case HB_INS_PINSRD:
        case HB_INS_PINSRQ: {
            unsigned elem_size = 4;
            if (dec->opcode == HB_INS_PINSRB) elem_size = 1;
            else if (dec->opcode == HB_INS_PINSRW) elem_size = 2;
            else if (dec->opcode == HB_INS_PINSRQ) elem_size = 8;
            hb_ir_operand_t dst = operand_from_dec(dec, 1);
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PINSR);
            if (i) {
                i->dst = dst;
                i->src1 = has_vex_src(dec) ? operand_from_dec(dec, 2) : dst;
                i->src2 = has_vex_src(dec) ? operand_from_dec(dec, 3) : operand_from_dec(dec, 2);
                i->target = elem_size | ((uint64_t)dec_imm8(dec) << 8);
            }
            emit(b, i, dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_PEXTRB:
        izvlechenie_obshchee:
        case HB_INS_PEXTRD:
        case HB_INS_PEXTRQ: {
            unsigned elem_size = 4;
            if (dec->opcode == HB_INS_PEXTRB) elem_size = 1;
            else if (dec->opcode == HB_INS_PEXTRW) elem_size = 2;
            else if (dec->opcode == HB_INS_PEXTRQ) elem_size = 8;
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_PEXTR);
            if (i) {
                i->dst = operand_from_dec(dec, 1);
                i->src1 = operand_from_dec(dec, 2);
                i->target = elem_size | ((uint64_t)dec_imm8(dec) << 8);
            }
            emit(b, i, dec);
            *itog = HB_OK; return true;
        }
        default:
            return false;
    }
}

/* СРАВНЕНИЕ EVEX С ПРИЁМНИКОМ-МАСКОЙ — общий текст на обе ветви.
 *
 * Узел HB_IR_EVEX_CMP_MASK и его исполнение существовали давно (интерпретатор
 * считает сравнение и пишет ctx->k[kdst], применяя маску записи). Не хватало
 * двух вещей: КЛАССА регистров k в разборе — приёмник клался непосредственным
 * — и самой этой ветви в лифтере i386, где её не было ВОВСЕ.
 *
 * Возвращает false, если команда не её. */
static bool hb_evex_cmp_mask(const hb_decoded_t* dec, hb_ir_builder_t* b,
                             hb_result_t* itog) {
    if (dec->evex && (dec->opcode == HB_INS_VCMPPS || dec->opcode == HB_INS_VCMPPD ||
                      dec->opcode == HB_INS_VCMPSS || dec->opcode == HB_INS_VCMPSD)) {
        hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_EVEX_CMP_MASK);
        if (i) {
            bool is_pd = dec->opcode == HB_INS_VCMPPD || dec->opcode == HB_INS_VCMPSD;
            bool scalar = dec->opcode == HB_INS_VCMPSS || dec->opcode == HB_INS_VCMPSD;
            /* Номер маски-приёмника. Раньше он приходил НЕПОСРЕДСТВЕННЫМ —
             * заглушка за неимением класса регистров k. 04.09.2026 класс
             * заведён (HB_REG_K0..K7), и приёмник приходит РЕГИСТРОМ.
             * Старую форму оставляем как запасной путь: если где-то
             * ещё придёт число, номер возьмётся из него. */
            uint64_t kdst = dec->op1.is_reg
                ? ((uint64_t)(dec->op1.reg - (int)HB_REG_K0) & 7u)
                : (dec->op1.is_imm ? ((uint64_t)dec->op1.imm & 7u) : 0);
            uint64_t kmask = dec->evex_mask & 7u;
            uint64_t pred = dec_imm8(dec) & 31u;
            i->src1 = operand_from_dec(dec, 2);
            i->src2 = operand_from_dec(dec, 3);
            i->target = kdst | (kmask << 3) | (scalar ? (1u << 6) : 0) |
                        (is_pd ? (1u << 7) : 0) | (dec->evex_broadcast ? (1u << 8) : 0) |
                        (pred << 16);
        }
        emit(b, i, dec);
        *itog = HB_OK; return true;
            }

    return false;
}

#endif /* HB_LIFT_VEC_OBSHCHEE_VKLYUCHENO */
