#include "hb_env.h"
#include "hb_gates.h"
#include "hb_context.h"
void hb_codegen_fill_lazy_const_tables(uint64_t* hdr, uint64_t* masks, unsigned slots);
#include "hb_runtime.h"
#include "hb_memory.h"
#include "hb_x87.h"
#include "hb_trace.h"
#include "hb_cache.h"
#include "hb_thunk.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

static uint64_t read_x64_block_limit_env(void) {
    const char* value = hb_gate( HB_GATE_HB_X64_BLOCK_LIMIT );
    if (!value || !*value) return 0;

    errno = 0;
    char* end = NULL;
    unsigned long long parsed = strtoull(value, &end, 0);
    if (errno != 0 || end == value) return 0;
    return (uint64_t)parsed;
}

/* ★★★★★ MacRunner 2026-08-25 — ПРЕДЕЛ ШАГОВ ВЫКЛЮЧАЕТ СЦЕПЛЕНИЕ БЛОКОВ.
 *
 * `chain_patch_enabled` требует `ctx->step_limit == 0` (hb_runtime.c), а умолчание здесь —
 * 10 000 000. Значит сцепление было выключено ВСЕГДА, у всех, и гейт
 * `MACRUNNER_HB_BLOCK_CHAIN=1` этого не менял: в журнале `site_patch_off` оставался
 * единственной причиной отказа, `avg_chain=1.0000`.
 *
 * Со снятым пределом механизм оживает:
 *     avg_chain          1.0000 → 3.0468
 *     диспетчеризаций 31 486 782 → 10 334 551
 *     косвенных jmp   10 201 166 → 355
 *     ВРЕМЯ                       −23,09 %   (6 пар из 6, разброс 2,21 %)
 *
 * Зачем предел был: НЕ защита от зависания, а периодический возврат в диспетчер (сигналы,
 * APC, смена потока). Проверено 25.08: со `step_limit=0` длинный прогон (150 с) проходит
 * чисто, `exit=0`. Зависание возникает только когда предел ЗАДАН, но не срабатывает —
 * то есть при попытке ослабить условие сцепления, не убрав сам предел.
 *
 * Гейт `MACRUNNER_HB_NO_STEP_LIMIT=1` обнуляет умолчание. Умолчание самого гейта —
 * ВЫКЛЮЧЕНО: снятие предела меняет поведение на зацикленном госте, и это должно быть
 * осознанным выбором. Внешний тормоз остаётся: таймаут прогона в mr-run.sh. */
static int no_step_limit_enabled(void) {
    const char* v = hb_gate( HB_GATE_HB_NO_STEP_LIMIT );
    int cached = (v && v[0] && v[0] != '0') ? 1 : 0;
    return cached;
}

static uint64_t read_step_limit_env(hb_arch_t arch) {
    const char* name = (arch == HB_ARCH_X86) ? "MACRUNNER_HB_X86_STEP_LIMIT" : "MACRUNNER_HB_STEP_LIMIT";
    const char* value = hb_env(name);
    uint64_t fallback = no_step_limit_enabled() ? 0ULL
                      : ((arch == HB_ARCH_X86) ? 10000000ULL : 1000000ULL);

    if (!value || !*value) return fallback;

    errno = 0;
    char* end = NULL;
    unsigned long long parsed = strtoull(value, &end, 0);
    if (errno != 0 || end == value) return fallback;
    return (uint64_t)parsed;
}

/* ═══ УЧЁТ КОНТЕКСТОВ ДЛЯ ПЕРЕПИСИ БЛОКИРУЮЩИХ ОПЕРАЦИЙ ═══
 *
 * Счётчики переписи живут в контексте (по потоку), значит сложить их может только
 * тот, кто знает все контексты. Список здесь и нигде больше.
 *
 * Запись — под замком, чтение — без: слагаемые растут монотонно, поэтому сумма,
 * снятая на ходу, занижена не более чем на прирост за время обхода. Точности
 * «сколько именно на этой миллисекунде» перепись не обещает и не нуждается в ней.
 *
 * ★ ПОТОЛОК ПРИБОРА НАЗВАН ЧИСЛОМ, а не оставлен молчаливым: сверх 256 контекстов
 * счёт ведётся в g_lkc_perepolneno и ПЕЧАТАЕТСЯ. Прибор, который молча теряет
 * слагаемые, врёт вниз — ровно тот класс, что записан в reports/00-ПЕРЕД-ЛЮБЫМ-ДЕЛОМ.md. */
#define HB_LKC_MAX_CTX 256
static hb_context_t* g_lkc_ctx[HB_LKC_MAX_CTX];
static unsigned g_lkc_ctx_n;
static uint64_t g_lkc_ushedshie[HB_LKC_N];   /* счёт контекстов, которых уже нет */
static unsigned long long g_lkc_perepolneno;
static pthread_mutex_t g_lkc_zamok = PTHREAD_MUTEX_INITIALIZER;

static void lkc_zapisat(hb_context_t* ctx) {
    pthread_mutex_lock(&g_lkc_zamok);
    if (g_lkc_ctx_n < HB_LKC_MAX_CTX) g_lkc_ctx[g_lkc_ctx_n++] = ctx;
    else g_lkc_perepolneno++;
    pthread_mutex_unlock(&g_lkc_zamok);
}

static void lkc_snyat(hb_context_t* ctx) {
    unsigned i;
    pthread_mutex_lock(&g_lkc_zamok);
    for (i = 0; i < g_lkc_ctx_n; i++) {
        if (g_lkc_ctx[i] != ctx) continue;
        /* Счёт умершего потока НЕ ТЕРЯЕТСЯ: он переливается в отдельную копилку.
         * Иначе перепись занижала бы ровно на потоки, успевшие отработать и уйти. */
        for (unsigned s = 0; s < (unsigned)HB_LKC_N; s++)
            g_lkc_ushedshie[s] += ctx->lock_census[s];
        g_lkc_ctx[i] = g_lkc_ctx[--g_lkc_ctx_n];
        break;
    }
    pthread_mutex_unlock(&g_lkc_zamok);
}

void hb_lock_census_collect(uint64_t* out, unsigned slots, unsigned long long* poteryano) {
    unsigned i, s;
    if (!out) return;
    for (s = 0; s < slots; s++) out[s] = 0;
    pthread_mutex_lock(&g_lkc_zamok);
    for (s = 0; s < slots && s < (unsigned)HB_LKC_N; s++) out[s] = g_lkc_ushedshie[s];
    for (i = 0; i < g_lkc_ctx_n; i++)
        for (s = 0; s < slots && s < (unsigned)HB_LKC_N; s++)
            out[s] += g_lkc_ctx[i]->lock_census[s];
    if (poteryano) *poteryano = g_lkc_perepolneno;
    pthread_mutex_unlock(&g_lkc_zamok);
}

hb_context_t* hb_context_create(hb_arch_t arch, hb_backend_t backend) {
    hb_context_t* ctx = calloc(1, sizeof(hb_context_t));
    if (!ctx) return NULL;
    lkc_zapisat(ctx);
    ctx->arch = arch;
    ctx->mode = (arch == HB_ARCH_X64) ? HB_MODE_64BIT : HB_MODE_32BIT;
    ctx->backend = backend;
    ctx->config.arch = arch;
    ctx->config.backend = backend;
    ctx->step_limit = read_step_limit_env(arch);
    ctx->block_limit = (arch == HB_ARCH_X64) ? read_x64_block_limit_env() : 0;
    /* «Срока нет». Ноль означал бы «стой немедленно»: выпущенный код читает
     * срок безусловно, поэтому умолчание обязано быть максимумом, а не нулём.
     * Действующее значение выставляет диспетчер перед входом в выпущенный код. */
    ctx->step_deadline = UINT64_MAX;
    ctx->block_deadline = UINT64_MAX;
    ctx->exit_code = 0;
    ctx->last_result = HB_OK;
    hb_x87_reset(hb_context_x87(ctx));
    /* Таблица адресов помощников — заполняется ВСЕГДА, независимо от гейта выпуска:
     * стоит 55 записей на создание контекста, а условное заполнение дало бы вторую
     * величину, которую пришлось бы держать согласованной с первой. */
    hb_runtime_fill_helper_table(ctx->helper_table, HB_HELPER_TABLE_SLOTS);
    /* Постоянные ленивых флагов — таблицей, а не укладкой в выпуске (итерация 135).
     * Значения обязаны совпадать с тем, что укладывает запасной путь: заполняет их сам
     * кодогенератор из своей же таблицы масок, чтобы разойтись было нечем. */
    hb_codegen_fill_lazy_const_tables(ctx->lazy_hdr, ctx->lazy_masks, HB_LAZY_CONST_SLOTS);
    return ctx;
}

void hb_context_destroy(hb_context_t* ctx) {
    if (!ctx) return;
    lkc_snyat(ctx);
    if (ctx->memory) hb_memory_destroy(ctx->memory);
    if (ctx->trace) hb_trace_destroy(ctx->trace);
    if (ctx->cache) hb_cache_destroy(ctx->cache);
    if (ctx->thunks) hb_thunk_table_destroy(ctx->thunks);
    free(ctx);
}

hb_result_t hb_context_reset(hb_context_t* ctx) {
    if (!ctx) return HB_ERR_INVALID_ARG;
    memset(&ctx->regs, 0, sizeof(ctx->regs));
    hb_x87_reset(hb_context_x87(ctx));
    memset(ctx->ymm_hi, 0, sizeof(ctx->ymm_hi));
    memset(ctx->zmm_hi, 0, sizeof(ctx->zmm_hi));
    memset(ctx->k, 0, sizeof(ctx->k));
    memset(ctx->xmm_ext, 0, sizeof(ctx->xmm_ext));
    memset(ctx->ymm_hi_ext, 0, sizeof(ctx->ymm_hi_ext));
    memset(ctx->zmm_hi_ext, 0, sizeof(ctx->zmm_hi_ext));
    memset(&ctx->flags, 0, sizeof(ctx->flags));
    memset(&ctx->lazy_flags, 0, sizeof(ctx->lazy_flags));
    ctx->step_count = 0;
    ctx->block_count = 0;
    ctx->pc = 0;
    ctx->exit_code = 0;
    ctx->last_result = HB_OK;
    ctx->indirect_ic_guest_addr = 0;
    ctx->indirect_ic_native_code = 0;
    ctx->codegen_module_base = 0;
    ctx->jit_signal_frame_slot = NULL;
    return HB_OK;
}

hb_result_t hb_context_set_pc(hb_context_t* ctx, hb_gva_t pc) {
    if (!ctx) return HB_ERR_INVALID_ARG;
    ctx->pc = pc;
    if (ctx->mode == HB_MODE_64BIT) ctx->regs.x64.rip = pc;
    else ctx->regs.x86.eip = (uint32_t)pc;
    return HB_OK;
}

hb_result_t hb_context_set_step_limit(hb_context_t* ctx, uint64_t limit) {
    if (!ctx) return HB_ERR_INVALID_ARG;
    ctx->step_limit = limit;
    return HB_OK;
}

hb_result_t hb_context_set_block_limit(hb_context_t* ctx, uint64_t limit) {
    if (!ctx) return HB_ERR_INVALID_ARG;
    ctx->block_limit = limit;
    return HB_OK;
}
