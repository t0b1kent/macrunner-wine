#ifndef HB_FLAGS_H
#define HB_FLAGS_H

#include "hb_context.h"
#include "hb_ir.h"

#ifdef __cplusplus
extern "C" {
#endif

void hb_lazy_flags_clear(hb_context_t* ctx);
void hb_lazy_flags_note(hb_context_t* ctx, hb_lazy_flags_kind_t kind,
                        hb_size_t width, uint64_t lhs, uint64_t rhs,
                        uint64_t result, uint64_t count);
hb_result_t hb_lazy_flags_materialize_available(hb_context_t* ctx, uint32_t mask);
hb_result_t hb_lazy_flags_materialize(hb_context_t* ctx, uint32_t mask);
hb_result_t hb_flags_eval_cond(hb_context_t* ctx, hb_cc_t cc, bool* out);

uint64_t hb_context_read_reg_value(hb_context_t* ctx, uint64_t idx);
void hb_context_write_reg_value(hb_context_t* ctx, uint64_t idx, uint64_t val);
void hb_context_write_reg_value_sized(hb_context_t* ctx, uint64_t idx, uint64_t val, hb_size_t size);

uint64_t hb_flags_exec_binop(hb_context_t* ctx, hb_ir_op_t op,
                             uint64_t dst_reg, uint8_t dst_reg_offset,
                             uint64_t src1_reg, uint8_t src1_reg_offset,
                             bool src2_is_reg, uint64_t src2_value,
                             uint8_t src2_reg_offset,
                             hb_size_t size, bool preserve_cf);
void hb_flags_exec_cmp_test(hb_context_t* ctx, hb_ir_op_t op,
                            bool src1_is_reg, uint64_t src1_value, uint8_t src1_reg_offset,
                            bool src2_is_reg, uint64_t src2_value, uint8_t src2_reg_offset,
                            hb_size_t size);
hb_result_t hb_flags_read_operand_value(hb_context_t* ctx, const hb_ir_operand_t* op, uint64_t* out);
hb_result_t hb_flags_write_operand_value(hb_context_t* ctx, const hb_ir_operand_t* op, uint64_t value);
hb_result_t hb_flags_exec_binop_operand(hb_context_t* ctx, hb_ir_op_t op,
                                         const hb_ir_operand_t* dst, const hb_ir_operand_t* src1,
                                         const hb_ir_operand_t* src2, uint64_t* out,
                                         bool preserve_cf);
hb_result_t hb_flags_exec_double_shift_operand(hb_context_t* ctx, hb_ir_op_t op,
                                               const hb_ir_operand_t* dst,
                                               const hb_ir_operand_t* src,
                                               const hb_ir_operand_t* count_op,
                                               uint64_t* out);

#ifdef __cplusplus
}
#endif

#endif
