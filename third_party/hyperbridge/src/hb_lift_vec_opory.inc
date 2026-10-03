/* ОПОРЫ ОБЩЕГО ПОДЪЁМА ВЕКТОРА — один текст на обе ветви.
 *
 * Пять чистых помощников: все зависят только от разобранной команды и от
 * operand_from_dec той единицы трансляции, куда включены. Разрядности в них
 * нет вовсе, потому и текст один.
 *
 * Включать ПОСЛЕ operand_from_dec и ДО первого употребления.
 */
#ifndef HB_LIFT_VEC_OPORY_VKLYUCHENO
#define HB_LIFT_VEC_OPORY_VKLYUCHENO

static bool has_vex_src(const hb_decoded_t* dec) {
    return dec->op3.present && !dec->op3.is_imm;
}

static uint8_t dec_imm8(const hb_decoded_t* dec) {
    if (dec->has_imm8) return dec->imm8;
    if (dec->op3.present && dec->op3.is_imm) return (uint8_t)dec->op3.imm;
    return 0;
}

static hb_ir_operand_t vector_src1_from_dec(const hb_decoded_t* dec, hb_ir_operand_t legacy_dst) {
    return has_vex_src(dec) ? operand_from_dec(dec, 2) : legacy_dst;
}

static hb_ir_operand_t vector_src2_from_dec(const hb_decoded_t* dec) {
    return has_vex_src(dec) ? operand_from_dec(dec, 3) : operand_from_dec(dec, 2);
}

static uint64_t vec_target(hb_ir_vec_op_t op, uint64_t arg) {
    return ((uint64_t)op << 32) | arg;
}

/* Разбор FMA — чистая функция от кода команды: какая скалярная, какая
 * двойной точности, какой знак у слагаемого. Разрядности в ней нет. */
static uint32_t fma_target_from_ins(int opcode) {
    bool scalar = opcode == HB_INS_VFMADD132SS || opcode == HB_INS_VFMADD132SD ||
                  opcode == HB_INS_VFMADD213SS || opcode == HB_INS_VFMADD213SD ||
                  opcode == HB_INS_VFMADD231SS || opcode == HB_INS_VFMADD231SD ||
                  opcode == HB_INS_VFMSUB132SS || opcode == HB_INS_VFMSUB132SD ||
                  opcode == HB_INS_VFMSUB213SS || opcode == HB_INS_VFMSUB213SD ||
                  opcode == HB_INS_VFMSUB231SS || opcode == HB_INS_VFMSUB231SD ||
                  opcode == HB_INS_VFNMADD132SS || opcode == HB_INS_VFNMADD132SD ||
                  opcode == HB_INS_VFNMSUB132SS || opcode == HB_INS_VFNMSUB132SD ||
                  opcode == HB_INS_VFNMADD213SS || opcode == HB_INS_VFNMADD213SD ||
                  opcode == HB_INS_VFNMSUB213SS || opcode == HB_INS_VFNMSUB213SD ||
                  opcode == HB_INS_VFNMADD231SS || opcode == HB_INS_VFNMADD231SD ||
                  opcode == HB_INS_VFNMSUB231SS || opcode == HB_INS_VFNMSUB231SD;
    bool fp64 = opcode == HB_INS_VFMADD132PD || opcode == HB_INS_VFMADD132SD ||
                opcode == HB_INS_VFMADD213PD || opcode == HB_INS_VFMADD213SD ||
                opcode == HB_INS_VFMADD231PD || opcode == HB_INS_VFMADD231SD ||
                opcode == HB_INS_VFMSUB132PD || opcode == HB_INS_VFMSUB132SD ||
                opcode == HB_INS_VFMSUB213PD || opcode == HB_INS_VFMSUB213SD ||
                opcode == HB_INS_VFMSUB231PD || opcode == HB_INS_VFMSUB231SD ||
                opcode == HB_INS_VFMADDSUB132PD || opcode == HB_INS_VFMSUBADD132PD ||
                opcode == HB_INS_VFMADDSUB213PD || opcode == HB_INS_VFMSUBADD213PD ||
                opcode == HB_INS_VFMADDSUB231PD || opcode == HB_INS_VFMSUBADD231PD ||
                opcode == HB_INS_VFNMADD132PD || opcode == HB_INS_VFNMADD132SD ||
                opcode == HB_INS_VFNMSUB132PD || opcode == HB_INS_VFNMSUB132SD ||
                opcode == HB_INS_VFNMADD213PD || opcode == HB_INS_VFNMADD213SD ||
                opcode == HB_INS_VFNMSUB213PD || opcode == HB_INS_VFNMSUB213SD ||
                opcode == HB_INS_VFNMADD231PD || opcode == HB_INS_VFNMADD231SD ||
                opcode == HB_INS_VFNMSUB231PD || opcode == HB_INS_VFNMSUB231SD;
    return (fp64 ? 8u : 4u) | (scalar ? 0x100u : 0u);
}

#endif /* HB_LIFT_VEC_OPORY_VKLYUCHENO */
