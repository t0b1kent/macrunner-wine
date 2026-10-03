#ifndef HB_CONTRACT_TELEMETRY_H
#define HB_CONTRACT_TELEMETRY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t open_ok;
    uint64_t open_fail;
    uint64_t hits;
    uint64_t misses;
    uint64_t stores;
    uint64_t store_skips;
    /* MacRunner 2026-07-29: why a compiled block could not be persisted. Measured on HK:
     * stores=117 against store_skips=40495, i.e. the persistent cache retains 0.3 % of what it
     * compiles, which is the dominant reason a cold start takes 476 s to the menu while Rosetta
     * — which translates ahead of time and keeps its result — reaches it in under 45 s.
     * native_blob_prepare_cache_store rejects any block whose code contains more than one
     * `blr x23`, so these counters size the fix before anyone rewrites the patcher. */
    uint64_t store_skip_multi_helper;   /* >1 helper call in the block */
    uint64_t store_skip_unmatched;      /* single helper, but arg1/helper mov not recognised */
    /* 2026-07-29: why a MULTI-helper block was still declined after the generalisation. The
     * first A/B cut multi-helper skips 118547 -> 43909; these four say what the remaining 44k
     * are, because each needs a different fix and guessing between them is how this project
     * loses days. */
    uint64_t mh_too_many;      /* more helper sites than the 16-site cap */
    uint64_t mh_wide_arg;      /* pointer moved into x2/x3/x4 somewhere in the block */
    uint64_t mh_unknown_helper;/* helper not in the cacheable set */
    uint64_t mh_arg_shape;     /* not exactly one recognised arg1 in a site's window */
    /* 2026-07-29: the relocation table itself, measured before anything is allowed to depend
     * on it. reloc_overflow > 0 means the 64-site cap is real and must be raised before the
     * store path switches from scanning to the table. */
    uint64_t reloc_blocks;     /* compiled blocks that produced a table */
    uint64_t reloc_sites;      /* total recorded sites across those blocks */
    uint64_t reloc_overflow;   /* blocks whose table overflowed */
    /* 2026-07-29: the table-driven store path. The three mh_* reasons above are all artefacts of
     * a matcher that tried to RECOGNISE the emitted code; reading the table instead removes them
     * by construction, so these counters exist to prove that claim rather than assert it. Every
     * decline below is a block the table could not resolve, and rl_hostptr is the only one that
     * describes the guest code rather than this implementation. */
    uint64_t rl_stores;        /* blocks persisted via the relocation table */
    uint64_t rl_literal_sites; /* recorded sites left alone — provably not host pointers */
    uint64_t rl_highhalf_sites;/* of those, ones accepted only by the 2^48 ceiling (sign-extended
                                * negative guest constants). Split out so the next run says what
                                * that rule was worth rather than leaving it folded in. */
    uint64_t rl_patched_sites; /* recorded sites rewritten to a sentinel */
    uint64_t rl_x23_value;     /* x23 sites that are NOT helper addresses (a large mem.disp parked
                                * there as scratch) and are now classified by value. The register
                                * used to imply "helper", so each of these declined a whole block:
                                * this counter is the direct measure of that fix. */
    uint64_t rl_hostptr;       /* declined: host pointer that is not this block or its instrs */
    /* 2026-07-30 — CENSUS of that one decline, which is now the ONLY one left. Measured mix after
     * the table landed: stores=239364 store_skips=8841 rl_hostptr=8841, every other reason exactly
     * 0 — those blocks are the whole of the missing 3.5 %. What they point AT decides whether the
     * gap is closable, so it gets measured rather than assumed. The four buckets sum to
     * rl_hostptr, so a mismatch means the buckets are wrong rather than the conclusion. */
    /* v1 bucketed against block->succ/pred and was VOID: hb_ir_cfg_add_edge() has no
     * callers, so those arrays are empty for every block and the buckets could only ever
     * read 0. v2 buckets by destination register, which the table records for every site
     * and which therefore cannot come back empty. 1/2/3 are helper argument positions. */
    uint64_t rl_hp_succ;       /* reg x1 — first helper argument */
    uint64_t rl_hp_pred;       /* reg x2 */
    uint64_t rl_hp_succ_instr; /* reg x3 */
    uint64_t rl_hp_other;      /* x4, x23, anything else */
    uint64_t rl_unknown_helper;/* declined: a KIND_HELPER value is not a registered helper */
    uint64_t rl_overflow;      /* declined: the table overflowed, so it is not trustworthy */
    uint64_t rl_desync;        /* declined: table offset does not decode as the recorded mov */
    uint64_t rl_collision;     /* declined: a literal already looks like a sentinel */
    uint64_t rl_roundtrip;     /* declined: store->load did not reproduce the original bytes */
    uint64_t bytes_loaded;
    uint64_t bytes_stored;
    /* Compiles from the try_promote_* hot-block-family fusions. Seven of the nine record_compile()
     * sites are these, and NONE of them touches the persistent cache: they write straight into
     * jit_mem and block_cache_put(fused). They are therefore in the retention denominator with no
     * path to the numerator, which made "retention" 10 points lower than the store path's own hit
     * rate. Counted so `compile_count - reloc_blocks - promo_compiles == 0` is checkable rather
     * than a gap somebody has to rediscover. */
    uint64_t promo_compiles;
    /* 2026-07-30 — WHERE COMPILE TIME GOES. The arithmetic that should have been done first:
     * cold compiles 251907 blocks in 740.6 s and warm 50020 in 271.0 s, i.e. 185-400 blocks per
     * second. A block translator doing 300/s is very slow, and 260000 blocks at that rate IS the
     * ~800 s cold start — the sum closes with no remainder. It also explains every negative result
     * of the day: the cache cannot help a COLD run, which must compile everything once, while warm
     * really is 2.9x faster because it compiles 4.5x fewer blocks.
     *
     * Correlation is not causation though — compile_count may simply be a proxy for how much code
     * the game ran. These two say whether the time is actually spent INSIDE compiling, split at the
     * one boundary worth splitting: emitting the code, versus preparing it for the cache. The
     * latter contains our own round-trip self-check, which re-runs the whole load path and memcmps
     * it for EVERY stored block — about 240000 full round trips per cold start, correct by design
     * and never once measured. */
    uint64_t t_codegen_ns;
    uint64_t t_store_ns;
    uint64_t compile_count;
    uint64_t translation_count;
    uint64_t distinct_translation_count;
    uint64_t dispatches;
    uint64_t blocks;
    uint64_t steps;
    /* ★ 06.09.2026, лейн КЕШ — перепись гостевых адресов, на которых блок материализован.
     * `*_seen` — событий, `*_unique` — различных адресов, разность = ПОВТОРЫ ВНУТРИ ПРОЦЕССА.
     * `*_full` = 1 означает, что таблица переполнилась и `unique` — НИЖНЯЯ ГРАНИЦА. */
    uint64_t compile_pc_seen;
    uint64_t compile_pc_unique;
    uint64_t hit_pc_seen;
    uint64_t hit_pc_unique;
    uint64_t pcset_full;
} hb_contract_telemetry_counts_t;

int hb_contract_telemetry_enabled(void);
void hb_contract_telemetry_register_atexit(void);
int hb_contract_telemetry_emit_summary(FILE* stream);

void hb_contract_telemetry_record_open(bool ok);
void hb_contract_telemetry_record_cache_hit(uint64_t bytes_loaded);
void hb_contract_telemetry_record_cache_miss(void);
void hb_contract_telemetry_record_cache_store(uint64_t bytes_stored);
void hb_contract_telemetry_record_cache_store_skip(void);
void hb_contract_telemetry_record_cache_store_skip_multi(void);
void hb_contract_telemetry_record_cache_store_skip_unmatched(void);
void hb_contract_telemetry_record_mh_reason(int reason);
void hb_contract_telemetry_record_reloc(unsigned long sites, int overflow);
void hb_contract_telemetry_record_reloc_store(unsigned long patched, unsigned long literal);
void hb_contract_telemetry_record_reloc_highhalf(unsigned long sites);
void hb_contract_telemetry_record_reloc_x23_value(unsigned long sites);
void hb_contract_telemetry_record_reloc_decline(int reason);
/* bucket: 0 = reg x1, 1 = x2, 2 = x3, 3 = anything else. Called only alongside a HOSTPTR
 * decline, so the four always sum to rl_hostptr. */
void hb_contract_telemetry_record_hostptr_census(int bucket);
/* which: 0 = codegen, 1 = cache-store preparation (includes the round-trip self-check). */
void hb_contract_telemetry_add_time(int which, uint64_t ns);
void hb_contract_telemetry_record_compile(void);
/* Call beside record_compile() from any path that cannot reach the persistent store. */
void hb_contract_telemetry_record_promote_compile(void);
void hb_contract_telemetry_record_translation(bool distinct);
/* Гостевой адрес, на котором блок материализован: выпуском кодогенератора и подъёмом с диска.
 * Перепись различных адресов -> повторный перевод внутри процесса числом, а не догадкой. */
void hb_contract_telemetry_record_compile_pc(uint64_t pc);
void hb_contract_telemetry_record_hit_pc(uint64_t pc);
void hb_contract_telemetry_record_dispatch(uint64_t dispatches, uint64_t blocks, uint64_t steps);

void hb_contract_telemetry_snapshot(hb_contract_telemetry_counts_t* out);
int hb_contract_telemetry_format_summary(char* buf, size_t size,
                                         const hb_contract_telemetry_counts_t* counts);
void hb_contract_telemetry_reset_for_test(void);

#ifdef __cplusplus
}
#endif

#endif
