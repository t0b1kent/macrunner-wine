/* РАЗБОР SIB С ВЕКТОРНЫМ ИНДЕКСОМ (VSIB) — один текст на обе ветви.
 *
 * У ветви i386 его не было ВОВСЕ (grep по vsib: ноль совпадений), и потому
 * СБОРЫ там не работали: декодер не заполнял признаки, а интерпретатор их
 * требует и отвечал -99 (внутренняя ошибка). Замер: vpgatherdd на x64 даёт
 * vsib=1 elem=4 idx=4 cnt=8, на i386 — все нули.
 *
 * Единица, включающая файл, обязана определить: can_read, read_u8, read_s8,
 * read_s32, set_reg_ex, set_mem, reg_idx. Флаги REX у ветви i386 передаются
 * нулями — в 32 битах их нет, и это не оговорка, а закон.
 */
#ifndef HB_DECODE_VSIB_OBSHCHEE_VKLYUCHENO
#define HB_DECODE_VSIB_OBSHCHEE_VKLYUCHENO

static hb_result_t parse_vsib_modrm(hb_dec_t* d, uint8_t modrm,
                                    bool rex_r, bool rex_x, bool rex_b,
                                    uint8_t mem_size, hb_decoded_t* out,
                                    int dst_slot, int mem_slot,
                                    uint8_t index_size, uint8_t elem_size,
                                    uint8_t elem_count) {
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t reg_op = (modrm >> 3) & 7;
    uint8_t rm = modrm & 7;
    if (mod == 3 || rm != 4) return HB_ERR_UNSUPPORTED_OPCODE;
    if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
    uint8_t sib = read_u8(d);
    out->has_modrm = true;
    out->mod = mod;
    out->reg_op = reg_op;
    out->rm = rm;
    out->has_sib = true;
    out->sib_scale = (sib >> 6) & 3;
    out->sib_index = (sib >> 3) & 7;
    out->sib_base = sib & 7;

    int base = -1;
    uint8_t scale = (uint8_t)(1u << out->sib_scale);
    int index = HB_REG_XMM0 + (int)(out->sib_index | (rex_x ? 8 : 0));
    int sb = reg_idx(out->sib_base, rex_b);
    if (out->sib_base == 5) {
        if (mod == 0) base = -1;
        else base = sb;
    } else {
        base = sb;
    }

    int64_t disp = 0;
    if (mod == 1) {
        if (!can_read(d, 1)) return HB_ERR_DECODE_FAILED;
        disp = read_s8(d);
    } else if (mod == 2 || (out->sib_base == 5 && mod == 0)) {
        if (!can_read(d, 4)) return HB_ERR_DECODE_FAILED;
        disp = read_s32(d);
    }

    set_reg_ex(out, dst_slot, reg_idx(reg_op, rex_r), mem_size, 0);
    set_mem(out, mem_slot, base, index, scale, disp, mem_size);
    if (mem_slot == 1) {
        out->op1.mem.vsib = true;
        out->op1.mem.vsib_index_size = index_size;
        out->op1.mem.vsib_elem_size = elem_size;
        out->op1.mem.vsib_count = elem_count;
    } else if (mem_slot == 2) {
        out->op2.mem.vsib = true;
        out->op2.mem.vsib_index_size = index_size;
        out->op2.mem.vsib_elem_size = elem_size;
        out->op2.mem.vsib_count = elem_count;
    } else {
        out->op3.mem.vsib = true;
        out->op3.mem.vsib_index_size = index_size;
        out->op3.mem.vsib_elem_size = elem_size;
        out->op3.mem.vsib_count = elem_count;
    }
    return HB_OK;
}

/* СБОРЫ (семьи VPGATHER и VGATHER) — общий текст на обе ветви.
 *
 * Размеры элемента, индекса и число элементов считаются ПО КОДУ и битам W/L.
 * У ветви i386 этого не было вовсе: декодер не заполнял признаки VSIB, и
 * интерпретатор отвечал -99 на всех четырёх формах.
 *
 * Возвращает false, если код не из семьи сборов. */
static bool hb_sbor_vex(hb_dec_t* d, uint8_t vex_opcode, bool vex_w, bool vex_l,
                        uint8_t vec_size, unsigned vex_v,
                        bool rex_r, bool rex_x, bool rex_b,
                        hb_decoded_t* out, hb_result_t* itog) {
    uint8_t elem = 4, index = 4, count = 0, dest_size = vec_size;
    if (!(vex_opcode >= 0x90 && vex_opcode <= 0x93)) return false;
    if (vex_opcode == 0x90) {
        out->opcode = vex_w ? HB_INS_VPGATHERDQ : HB_INS_VPGATHERDD;
        elem = vex_w ? 8 : 4;
        index = 4;
        count = (uint8_t)(dest_size / elem);
    } else if (vex_opcode == 0x91) {
        out->opcode = vex_w ? HB_INS_VPGATHERQQ : HB_INS_VPGATHERQD;
        elem = vex_w ? 8 : 4;
        index = 8;
        if (!vex_w) {
            count = vex_l ? 4 : 2;
            dest_size = 16;
        } else {
            count = (uint8_t)(dest_size / elem);
        }
    } else if (vex_opcode == 0x92) {
        out->opcode = vex_w ? HB_INS_VGATHERDPD : HB_INS_VGATHERDPS;
        elem = vex_w ? 8 : 4;
        index = 4;
        count = (uint8_t)(dest_size / elem);
    } else {
        out->opcode = vex_w ? HB_INS_VGATHERQPD : HB_INS_VGATHERQPS;
        elem = vex_w ? 8 : 4;
        index = 8;
        if (!vex_w) {
            count = vex_l ? 4 : 2;
            dest_size = 16;
        } else {
            count = (uint8_t)(dest_size / elem);
        }
    }
    if (!can_read(d, 1)) { *itog = HB_ERR_DECODE_FAILED; return true; }
    uint8_t modrm = read_u8(d);
    /* ПОРЯДОК ПО СПЕЦИФИКАЦИИ: приёмник, ПАМЯТЬ (vsib), маска.
     *
     * Прежде было «приёмник, маска, память» — наш внутренний выбор, неточный
     * против описания команды (`VPGATHERDD xmm1, vm32x, xmm2`). Сама сборка
     * при этом работала: сверено сквозным замером с оракулом. Меняем порядок
     * в ОДНОМ месте — общий текст на обе ветви — и правим ожидание
     * интерпретатора. */
    hb_result_t r = parse_vsib_modrm(d, modrm, rex_r, rex_x, rex_b,
                                     dest_size, out, 1, 2,
                                     index, elem, count);
    if (r != HB_OK) { *itog = r; return true; }
    set_reg(out, 3, vex_v, dest_size);
    mark_vec_operand(out, 1, dest_size);
    mark_vec_operand(out, 3, dest_size);
    if (out->op2.is_mem) out->op2.size = dest_size;
    *itog = HB_OK; return true;

    return true;
}

#endif /* HB_DECODE_VSIB_OBSHCHEE_VKLYUCHENO */
