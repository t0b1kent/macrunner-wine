#ifndef HB_LIFTER_H
#define HB_LIFTER_H

#include "hb_result.h"
#include "hb_ir.h"
#include "hb_decoder.h"

#ifdef __cplusplus
extern "C" {
#endif

hb_result_t hb_lift_x64(const hb_decoded_t* dec, hb_ir_builder_t* b);
hb_result_t hb_lift_x86(const hb_decoded_t* dec, hb_ir_builder_t* b);

/* Продлевать ли единицу трансляции за этот условный переход. Одно правило на обе ветви —
 * разбор у определения в hb_lift_x86.c. Гейт MACRUNNER_HB_MERGE_BLOCKS, умолчание ВЫКЛ. */
int hb_lift_edinica_prodlit(const hb_decoder_t* dec, const hb_decoded_t* d, size_t merged);

hb_result_t hb_lift_func_x64(hb_decoder_t* dec, hb_ir_func_t** out);
hb_result_t hb_lift_func_x86(hb_decoder_t* dec, hb_ir_func_t** out);

#ifdef __cplusplus
}
#endif

#endif
