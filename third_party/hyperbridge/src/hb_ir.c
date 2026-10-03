#include "hb_env.h"
#include "hb_gates.h"
#include "hb_ir.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "hb_alloc_count.h"

/* --- IR Function --- */
hb_ir_func_t* hb_ir_func_create(uint64_t guest_addr, size_t guest_len) {
    hb_ir_func_t* func = calloc(1, sizeof(hb_ir_func_t));
    if (!func) return NULL;
    func->guest_addr = guest_addr;
    func->guest_len = guest_len;
    func->cfg = hb_ir_cfg_create();
    if (!func->cfg) {
        free(func);
        return NULL;
    }
    return func;
}

void hb_ir_func_destroy(hb_ir_func_t* func) {
    if (!func) return;
    if (func->acfg) hb_cfg_analysis_destroy(func->acfg);
    if (func->cfg) hb_ir_cfg_destroy(func->cfg);
    if (func->flat_instrs) {
        free(func->flat_instrs);
    }
    free((void*)func->unsupported_reason);
    free(func);
}

/* --- IR Block --- */
/* MacRunner 2026-08-06 — учёт блоков ИР.
 *
 * Зачем. Разбор кучи живого процесса (heap PID) на 90-й секунде прогона HK показал
 * 73 576 196 ЖИВЫХ выделений на 22.6 ГБ, средний размер 307.7 байт, все "non-object",
 * то есть обычный malloc нашего кода. Скорость роста — около 800 тысяч выделений в
 * секунду. Физический след процесса 7.3 ГБ за 31 секунду, подкачка раздувалась до 68 ГБ,
 * свободное место на диске падало с 80 до 18 ГБ.
 *
 * hb_ir_block_create делает ДВА выделения на блок: сам блок (80 байт) и массив из 16
 * инструкций (16 * 184 = 2944 байта). Если создания не уравновешены уничтожениями,
 * это и есть источник. Счётчики отвечают на вопрос однозначно: разница между ними —
 * количество утёкших блоков, а не предположение о нём. */
/* ★ ЗАМЕР 02.09.2026 — СЛИЯНИЕ БЛОКОВ ПРИРОСТА НЕ ДАЁТ.
 *
 * Мера: ВРЕМЯ ДО ФИКСИРОВАННОЙ ТОЧКИ (12 000 строк журнала), а не работа за
 * фиксированное время — прежний замер по `steps` был негоден: в руке ВКЛ счётчик
 * выдавал одно и то же число трижды до единицы, значит между руками несопоставим.
 * Три пары, один двоичный файл, закреплённая раскладка, у каждой руки свой свежий
 * корень кеша (MERGE_BLOCKS в ключ кеша не входит).
 *
 *   ВЫКЛ  41,02 с в среднем (40,60 / 41,28 / 41,18)
 *   ВКЛ   40,85 с в среднем (41,31 / 40,58 / 40,65)
 *   разница -0,42 % при собственном разбросе руки ~1,7 % — то есть в шуме.
 *
 * Блоков слияние действительно убирает (-4,2 %), но на времени это не сказывается.
 * Мишень одна (Half-Life), поэтому приём не удалён, а помечен: включать только
 * после замера на ВТОРОЙ мишени. Инструмент: scripts/замер-до-вехи.sh.
 */
/* ★★★ ЕДИНИЦА 2026-08-24 — реестр наблюдавшихся входов (объявление в hb_ir.h).
 *
 * Открытая адресация, 8192 слота, БЕЗ вытеснения: реестр только растёт, а при
 * заполнении перестаёт принимать новые адреса. Переполнение НЕ делает работу неверной —
 * оно лишь возвращает поведение к нынешнему (единица накроет чужой вход и хвост
 * переведётся дважды). Поэтому счётчик отказов печатается: молчаливое переполнение
 * выглядело бы как «приём не работает».
 *
 * Гейт `MACRUNNER_HB_MERGE_CUT_AT_ENTRY`, умолчание ВЫКЛ (приведено к умолчанию родителя
 * 02.09.2026 — см. разбор у `ke_on` ниже; ★ 04.09.2026: строка выше говорила «умолчание ВКЛ»
 * ещё двое суток после правки, и на этом расхождении провалился тест
 * `edinica_merge_cut_at_known_entry` — он полагался на ВКЛ). Реестр вообще не ведётся,
 * пока не включено само слияние (`MACRUNNER_HB_MERGE_BLOCKS`): без него резать нечего,
 * и платить за учёт незачем. Выключение гейта при включённом слиянии — это КОНТРОЛЬНАЯ
 * РУКА замера: тот же двоичный, то же слияние, разница только в резке. */
/* Ёмкость: 65536. Обоснование числом, а не «на глаз»: у Diablo в кеше трансляций
 * 7236 блоков (итерация 1), то есть при 8192 слотах заполнение было бы 88 % — реестр
 * переполнялся бы к концу прогона и рез молча переставал бы работать. При 65536
 * заполнение 11 %. Цена — 512 КБ, разово и только при включённом слиянии. */
#define HB_KE_SIZE 65536u
static uint64_t g_ke[HB_KE_SIZE];
static unsigned g_ke_used;
static uint64_t g_ke_notes, g_ke_full, g_ke_cuts, g_ke_asks;
static int g_ke_on = -1;

static int ke_on(void) {
    if (g_ke_on < 0) {
        const char* m = hb_gate( HB_GATE_HB_MERGE_BLOCKS );
        const char* c = hb_gate( HB_GATE_HB_MERGE_CUT_AT_ENTRY );
        int merge = (m && *m && *m != '0') ? 1 : 0;
        /* Умолчание приведено к ВЫКЛ 02.09.2026, как у родителя MERGE_BLOCKS: раньше
         * здесь стояло ВКЛ при выключенном родителе — приём выглядел включённым,
         * будучи мёртвым. Замер (см. шапку) прироста не показал. */
        int cut = (c && *c && *c != '0') ? 1 : 0;
        g_ke_on = (merge && cut) ? 1 : 0;
        if (g_ke_on) atexit(hb_known_entry_report);
    }
    return g_ke_on;
}

/* Ноль как ключ не используется: слот со значением 0 считается пустым, а гостевой
 * адрес 0 входом быть не может (страница не отображается). */
static unsigned ke_slot(uint64_t a) {
    uint64_t h = a * 0x9e3779b97f4a7c15ull;
    return (unsigned)((h >> 33) & (HB_KE_SIZE - 1));
}

/* ★ УПРЕЖДАЮЩАЯ запись: цель перехода — вход БУДУЩИЙ.
 * Учёт только в `block_cache_put` узнаёт вход постфактум: единица уже переведена, дубль
 * уже случился. Цель прямого перехода известна РАНЬШЕ — при подъёме блока-источника.
 * Заносим её, и будущая единица режется ДО того, как накроет этот вход.
 *
 * Почему только цель ВНЕ текущего окна разбора: цель ВНУТРИ окна — это как раз то, ради
 * чего слияние и делается (внутренний b.cond вместо диспетчеризации). Занести её значило
 * бы запретить слияние самому себе. */
void hb_known_entry_note(uint64_t guest_addr) {
    unsigned i, k;
    if (!ke_on() || !guest_addr) return;
    g_ke_notes++;
    /* ЕДИНИЦА, итерация 9: печать на степенях двойки. `atexit` не срабатывает у падающей
     * руки, а именно она и интересна — замер 8 не дал по ней ни одного числа. */
    if ((g_ke_notes & (g_ke_notes - 1)) == 0 || (g_ke_notes & 0x3ffull) == 0)
        hb_known_entry_report();
    k = ke_slot(guest_addr);
    for (i = 0; i < HB_KE_SIZE; i++) {
        uint64_t* p = &g_ke[(k + i) & (HB_KE_SIZE - 1)];
        if (*p == guest_addr) return;
        if (!*p) { *p = guest_addr; g_ke_used++; return; }
    }
    g_ke_full++;
}

int hb_known_entry_is(uint64_t guest_addr) {
    unsigned i, k;
    if (!ke_on() || !guest_addr) return 0;
    g_ke_asks++;
    k = ke_slot(guest_addr);
    for (i = 0; i < HB_KE_SIZE; i++) {
        uint64_t v = g_ke[(k + i) & (HB_KE_SIZE - 1)];
        if (v == guest_addr) { g_ke_cuts++; return 1; }
        if (!v) return 0;
    }
    return 0;
}

void hb_known_entry_report(void) {
    if (!g_ke_notes && !g_ke_asks) return;
    fprintf(stderr,
            "macrunner-edinica-entry: zaneseno=%llu razlichnyh=%u iz %u perepolnenii=%llu "
            "sprosov=%llu rezov=%llu (%.2f %%)\n",
            (unsigned long long)g_ke_notes, g_ke_used, (unsigned)HB_KE_SIZE,
            (unsigned long long)g_ke_full, (unsigned long long)g_ke_asks,
            (unsigned long long)g_ke_cuts,
            g_ke_asks ? 100.0 * (double)g_ke_cuts / (double)g_ke_asks : 0.0);
    fflush(stderr);
}

/* ★★★★★★★ ЕДИНИЦА 04.09.2026 — ПРАВИЛО «ВНУТРЕННИЙ ЛИ ЭТО ПЕРЕХОД» ОДНО НА ОБЕ СТОРОНЫ.
 *
 * КАКОЙ ОТКАЗ ЭТО ПРЕДОТВРАЩАЕТ. С `MACRUNNER_HB_MERGE_BLOCKS=1` детерминированно падала
 * двухпоточная проба спина `jit_x64_tso_spin_reader_observes_publisher`. Замер пробой
 * (одиночный поток, тот же код читателя `mov eax,[rsi]; lfence; test eax,eax; je -9`):
 *
 *   слияние ВЫКЛ:  flag=0 -> blocks=50 steps=200 (крутится, упёрся в предел) ✔
 *                  flag=1 -> blocks=1  pc=+9  rax=1                          ✔
 *   слияние ВКЛ:   flag=0 -> blocks=1  pc=+11 rax=0   (вышел из цикла с ПЕРВОГО раза!)
 *                  flag=1 -> faulted=1 «branch target block not found»
 *
 * ПРИЧИНА — НЕ ПОРЯДОК ПАМЯТИ, А ДВА ЭКЗЕМПЛЯРА ОДНОГО ПРАВИЛА, РАЗОШЕДШИЕСЯ:
 *   • выпуск (`codegen_instr_limit_before_fallthrough`) считал условный переход
 *     ВНУТРЕННИМ только при цели ВПЕРЁД (`j > i`): цель НАЗАД — точка схода, в которую
 *     управление приходит двумя путями, и линейный кодогенератор её не выдерживает.
 *     Поэтому на `je -9` выпуск единицу ОБРЫВАЛ и писал `ctx->pc` = цель перехода;
 *   • рантайм (`merged_terminal_instr`) спрашивал лишь «есть ли в единице команда по
 *     этому адресу», направление не смотрел. Переход назад он считал внутренним, а
 *     завершителем единицы объявлял ПОСЛЕДНЮЮ команду — не переход. Дальше ветка
 *     «Sequential block end» ЗАТИРАЛА `ctx->pc` концом единицы, и спин-цикл выходил
 *     наружу, не дождавшись флага. При невзятом переходе тот же разлад давал NOT_FOUND.
 *
 * Копия правила уже подводила этот лейн (разбор у `hb_lift_edinica_prodlit`: два
 * разошедшихся двоичных поиска). Поэтому текст правила ОДИН и лежит здесь, а зовут его
 * обе стороны: `hb_arm64_codegen.c` при выпуске и `hb_runtime.c` при диспетчеризации.
 *
 * УСЛОВИЯ (ровно те, по которым выпуск ставит `b.cond` на метку, а не выходит в диспетчер):
 *   • это условный переход;
 *   • цель совпадает с НАЧАЛОМ команды этой же единицы (попадания «в диапазон» мало:
 *     адрес может лечь в середину команды);
 *   • цель ВПЕРЁД (`j > i`) — переход назад выпуск не сращивает;
 *   • обе команды попадают в таблицу смещений выпуска (`HB_EDINICA_MAX_INSTR`), иначе
 *     заплату ставить некуда;
 *   • прыжок не длиннее `MACRUNNER_HB_MERGE_SKIP_MAX` (умолчание -1 = без предела). */
static int edinica_skip_max(void) {
    static int cached = -2;
    if (cached == -2) {
        const char* v = hb_gate( HB_GATE_HB_MERGE_SKIP_MAX );
        cached = (v && *v) ? atoi(v) : -1;
        fprintf(stderr, "macrunner-gate: MACRUNNER_HB_MERGE_SKIP_MAX=%d\n", cached);
        fflush(stderr);
    }
    return cached;
}

int hb_edinica_target_index(const hb_ir_block_t* b, uint64_t tgt, size_t* out_i) {
    if (!b) return 0;
    for (size_t i = 0; i < b->instr_count && i < HB_EDINICA_MAX_INSTR; i++) {
        if (b->instrs[i].guest_addr == tgt) { if (out_i) *out_i = i; return 1; }
    }
    return 0;
}

int hb_edinica_perehod_vnutrennij(const hb_ir_block_t* block, size_t i) {
    size_t j = 0;
    int lim;
    if (!block || i >= block->instr_count || i >= HB_EDINICA_MAX_INSTR) return 0;
    if (block->instrs[i].op != HB_IR_Jcc) return 0;
    if (!hb_edinica_target_index(block, block->instrs[i].target, &j)) return 0;
    if (j <= i) return 0;                 /* назад — точка схода, выпуск её не сращивает */
    lim = edinica_skip_max();
    if (lim < 0) return 1;
    return (long)(j - i - 1) <= (long)lim;
}

unsigned long long hb_ir_blocks_created;
unsigned long long hb_ir_blocks_destroyed;

hb_ir_block_t* hb_ir_block_create(uint64_t id, uint64_t guest_addr) {
    hb_ir_block_t* block = calloc(1, sizeof(hb_ir_block_t));
    if (!block) return NULL;
    block->id = id;
    block->guest_addr = guest_addr;
    /* calloc would leave this 0, which is a VALID index and would claim instruction 0 is a
     * control transfer. Set the sentinel explicitly. */
    block->first_transfer_idx = HB_IR_TRANSFER_UNCOMPUTED;
    block->instr_cap = 16;
    block->instrs = calloc(block->instr_cap, sizeof(hb_ir_instr_t));
    if (!block->instrs) {
        free(block);
        return NULL;
    }
    __atomic_add_fetch(&hb_ir_blocks_created, 1, __ATOMIC_RELAXED);
    return block;
}

void hb_ir_block_destroy(hb_ir_block_t* block) {
    if (block) __atomic_add_fetch(&hb_ir_blocks_destroyed, 1, __ATOMIC_RELAXED);
    if (!block) return;
    free(block->instrs);
    free(block->succ);
    free(block->pred);
    free(block);
}

/* --- IR CFG --- */
hb_ir_cfg_t* hb_ir_cfg_create(void) {
    hb_ir_cfg_t* cfg = calloc(1, sizeof(hb_ir_cfg_t));
    if (!cfg) return NULL;
    cfg->block_cap = 8;
    cfg->blocks = calloc(cfg->block_cap, sizeof(hb_ir_block_t*));
    if (!cfg->blocks) {
        free(cfg);
        return NULL;
    }
    return cfg;
}

void hb_ir_cfg_destroy(hb_ir_cfg_t* cfg) {
    if (!cfg) return;
    for (size_t i = 0; i < cfg->block_count; i++) {
        hb_ir_block_destroy(cfg->blocks[i]);
    }
    free(cfg->blocks);
    free(cfg);
}

void hb_ir_cfg_add_block(hb_ir_cfg_t* cfg, hb_ir_block_t* block) {
    if (!cfg || !block) return;
    if (cfg->block_count >= cfg->block_cap) {
        size_t new_cap = cfg->block_cap * 2;
        hb_ir_block_t** new_blocks = realloc(cfg->blocks, new_cap * sizeof(hb_ir_block_t*));
        if (!new_blocks) return;
        cfg->blocks = new_blocks;
        cfg->block_cap = new_cap;
    }
    cfg->blocks[cfg->block_count++] = block;
}

void hb_ir_cfg_add_edge(hb_ir_cfg_t* cfg, hb_ir_block_t* from, hb_ir_block_t* to) {
    if (!cfg || !from || !to) return;
    /* Add to succ */
    from->succ = realloc(from->succ, (from->succ_count + 1) * sizeof(hb_ir_block_t*));
    from->succ[from->succ_count++] = to;
    /* Add to pred */
    to->pred = realloc(to->pred, (to->pred_count + 1) * sizeof(hb_ir_block_t*));
    to->pred[to->pred_count++] = from;
}

/* ═══════════════════════════════════════════════════════════════════════════════════
 * ГРАФ АНАЛИЗА — ПОСТРОИТЕЛЬ. Лейн CFG, 07.09.2026.
 *
 * Разбор устройства — в hb_ir.h у объявления структур. Здесь только два напоминания,
 * оба стоили нам времени раньше:
 *
 * 1. ★ `hb_ir_cfg_add_edge` НЕ ПРОВЕРЯЕТ результат `realloc` (см. выше, :291-295).
 *    Здесь проверяется всё: неудача выделения означает `complete = 0`, то есть
 *    «анализ недоступен, публикацию сохранить», а НЕ граф с потерянной дугой.
 *    Потерянная дуга страшнее отсутствующего графа: она выглядит как разрешение
 *    снять запись флагов, которую на самом деле кто-то читает.
 *
 * 2. ★ `func->guest_len` — это ДЛИНА ОКНА ДЕКОДЕРА, а не список прочитанных команд
 *    (предупреждение стоит в macrunner_hb.c:13647). Поэтому «цель известна» решается
 *    ТОЛЬКО по переписи действительно декодированных команд, а окно нужно лишь чтобы
 *    отличить «в окне, но не поднята» от «вне окна».
 * ═══════════════════════════════════════════════════════════════════════════════════ */

int hb_ir_instr_touches_guest_memory(const hb_ir_instr_t* in) {
    if (!in) return 1;
    return in->dst.type == HB_OP_MEM || in->src1.type == HB_OP_MEM || in->src2.type == HB_OP_MEM;
}

int hb_cfg_analysis_enabled(void) {
    static int cached = -1;
    if (cached < 0) {
        /* Граф строится и при явном гейте построения, и когда его просит потребитель
         * (живость флагов по настоящему графу). Частично включённый набор хуже
         * выключенного: потребитель без построителя молча считал бы ноль. */
        cached = (hb_gate_flag( HB_GATE_HB_ANALYSIS_CFG, 0) != 0) ||
                 (hb_gate_flag( HB_GATE_HB_FLAG_LIVENESS_GRAPH, 0) != 0);
    }
    return cached;
}

static int cfg_test_gate(enum hb_gate_id id) { return hb_gate_flag(id, 0) != 0; }

#define CFG_GROW(arr, n, cap, type)                                            \
    do {                                                                       \
        if ((n) >= (cap)) {                                                    \
            size_t nc = (cap) ? (cap) * 2 : 8;                                 \
            type* np = (type*)realloc((arr), nc * sizeof(type));               \
            if (!np) return 0;                                                 \
            (arr) = np; (cap) = nc;                                            \
        }                                                                      \
    } while (0)

static hb_cfg_analysis_t* cfg_analysis_get(hb_ir_func_t* func) {
    if (!func) return NULL;
    if (!func->acfg) {
        func->acfg = (hb_cfg_analysis_t*)calloc(1, sizeof(hb_cfg_analysis_t));
        if (func->acfg) func->acfg->complete = 0;
    }
    return func->acfg;
}

void hb_cfg_analysis_destroy(hb_cfg_analysis_t* a) {
    if (!a) return;
    free(a->guest);
    free(a->nodes);
    free(a->edges);
    free(a->obs);
    free(a->pred_count);
    free(a);
}

/* Заносится КАЖДАЯ декодированная гостевая команда, включая ту, что не породила IR. */
void hb_cfg_ledger_note(hb_ir_func_t* func, uint64_t addr, unsigned len,
                        size_t ir_first, size_t ir_count,
                        int is_branch, int is_cond, int is_call, int is_ret,
                        int has_target, uint64_t target) {
    hb_cfg_analysis_t* a;
    hb_cfg_guest_t* g;
    if (!hb_cfg_analysis_enabled()) return;
    a = cfg_analysis_get(func);
    if (!a) return;
    if (a->guest_n >= a->guest_cap) {
        size_t nc = a->guest_cap ? a->guest_cap * 2 : 16;
        hb_cfg_guest_t* np = (hb_cfg_guest_t*)realloc(a->guest, nc * sizeof(hb_cfg_guest_t));
        if (!np) { a->incomplete_reason = "перепись: отказ выделения"; return; }
        a->guest = np; a->guest_cap = nc;
    }
    g = &a->guest[a->guest_n++];
    memset(g, 0, sizeof(*g));
    g->addr = addr;
    g->len = (uint8_t)len;
    g->ir_first = (uint32_t)ir_first;
    g->ir_count = (uint32_t)ir_count;
    g->is_branch = (uint8_t)(is_branch != 0);
    g->is_cond = (uint8_t)(is_cond != 0);
    g->is_call = (uint8_t)(is_call != 0);
    g->is_ret = (uint8_t)(is_ret != 0);
    g->has_target = (uint8_t)(has_target != 0);
    g->target = target;
}

/* Индекс гостевой команды, НАЧИНАЮЩЕЙСЯ по этому адресу. -1 если такой нет.
 * Совпадение только с НАЧАЛОМ: адрес внутри байтов x86-команды задаёт другой поток
 * команд, и округлять его нельзя. */
static int cfg_guest_index_at(const hb_cfg_analysis_t* a, uint64_t addr) {
    size_t i;
    for (i = 0; i < a->guest_n; i++)
        if (a->guest[i].addr == addr) return (int)i;
    return -1;
}

static int cfg_add_edge(hb_cfg_analysis_t* a, uint32_t from, int32_t to,
                        uint32_t site_ir, uint64_t site_guest, uint64_t target_guest,
                        uint8_t kind, uint8_t state) {
    hb_cfg_edge_t* e;
    CFG_GROW(a->edges, a->edge_n, a->edge_cap, hb_cfg_edge_t);
    e = &a->edges[a->edge_n++];
    e->from = from; e->to = to;
    e->site_ir = site_ir; e->site_guest = site_guest; e->target_guest = target_guest;
    e->kind = kind; e->state = state;
    switch (state) {
        case HB_CFG_T_KNOWN_LOCAL:        a->n_known_local++; break;
        case HB_CFG_T_UNKNOWN_NOT_LIFTED: a->n_unknown_not_lifted++; break;
        case HB_CFG_T_UNKNOWN_OUTSIDE:    a->n_unknown_outside++; break;
        case HB_CFG_T_UNKNOWN_TRANSFER:   a->n_unknown_transfer++; break;
        default:                          a->n_unknown_incomplete++; break;
    }
    return 1;
}

/* Состояние цели по её АДРЕСУ. Порядок проверок закреплён: сперва перепись, потом окно. */
static uint8_t cfg_target_state(const hb_ir_func_t* func, const hb_cfg_analysis_t* a,
                                uint64_t tgt, int* out_g) {
    int gi = cfg_guest_index_at(a, tgt);
    if (out_g) *out_g = gi;
    if (gi >= 0) return HB_CFG_T_KNOWN_LOCAL;
    if (tgt >= func->guest_addr && tgt - func->guest_addr < (uint64_t)func->guest_len)
        return HB_CFG_T_UNKNOWN_NOT_LIFTED;
    return HB_CFG_T_UNKNOWN_OUTSIDE;
}

int hb_cfg_build(hb_ir_func_t* func, const hb_ir_block_t* block) {
    hb_cfg_analysis_t* a;
    uint8_t* leader = NULL;
    size_t i, g, n_nodes = 0;
    int32_t* g_to_node = NULL;
    int skew = cfg_test_gate( HB_GATE_HB_TEST_CFG_SKEW_TARGET );
    int drop_taken = cfg_test_gate( HB_GATE_HB_TEST_CFG_DROP_TAKEN );
    int drop_fall = cfg_test_gate( HB_GATE_HB_TEST_CFG_DROP_FALL );
    int dup_edge = cfg_test_gate( HB_GATE_HB_TEST_CFG_DUP_EDGE );
    int no_pred = cfg_test_gate( HB_GATE_HB_TEST_CFG_NO_PRED );

    if (!hb_cfg_analysis_enabled()) return 0;
    if (!func || !block) return 0;
    a = cfg_analysis_get(func);
    if (!a) return 0;
    a->complete = 0;
    if (a->guest_n == 0) { a->incomplete_reason = "перепись пуста"; return 0; }

    /* Перепись обязана покрывать массив команд подряд и без дыр — иначе резать нечего. */
    {
        uint32_t expect = 0;
        for (g = 0; g < a->guest_n; g++) {
            if (a->guest[g].ir_first != expect) {
                a->incomplete_reason = "перепись разошлась с массивом команд";
                return 0;
            }
            expect += a->guest[g].ir_count;
        }
        if (expect != (uint32_t)block->instr_count) {
            a->incomplete_reason = "перепись не покрывает массив команд целиком";
            return 0;
        }
    }

    leader = (uint8_t*)calloc(a->guest_n, 1);
    g_to_node = (int32_t*)malloc(a->guest_n * sizeof(int32_t));
    if (!leader || !g_to_node) {
        free(leader); free(g_to_node);
        a->incomplete_reason = "лидеры: отказ выделения";
        return 0;
    }

    /* ЛИДЕРЫ. Вход; каждая прямая цель, совпавшая с началом действительно декодированной
     * команды; провал после условной передачи; команда после всякого terminator'а, если
     * она всё же присутствует в массиве. */
    leader[0] = 1;
    for (g = 0; g < a->guest_n; g++) {
        const hb_cfg_guest_t* gi = &a->guest[g];
        if (gi->is_branch && gi->has_target) {
            uint64_t tgt = gi->target + (skew ? 1u : 0u);
            int t = cfg_guest_index_at(a, tgt);
            if (t >= 0) leader[t] = 1;
        }
        if ((gi->is_branch || gi->is_call || gi->is_ret) && g + 1 < a->guest_n)
            leader[g + 1] = 1;
    }

    /* УЗЛЫ: диапазоны между лидерами. Резать только между гостевыми командами. */
    for (g = 0; g < a->guest_n; g++) {
        if (!leader[g]) { g_to_node[g] = (int32_t)(n_nodes - 1); continue; }
        {
            hb_cfg_node_t* nd;
            CFG_GROW(a->nodes, a->node_n, a->node_cap, hb_cfg_node_t);
            nd = &a->nodes[a->node_n++];
            nd->g_first = (uint32_t)g;
            nd->g_end = (uint32_t)g + 1;          /* доправится ниже */
            nd->ir_first = a->guest[g].ir_first;
            nd->ir_end = a->guest[g].ir_first;    /* доправится ниже */
            nd->guest_first = a->guest[g].addr;
            nd->guest_end = a->guest[g].addr + a->guest[g].len;
            n_nodes = a->node_n;
            g_to_node[g] = (int32_t)(n_nodes - 1);
        }
    }
    for (g = 0; g < a->guest_n; g++) {
        hb_cfg_node_t* nd = &a->nodes[g_to_node[g]];
        if ((uint32_t)g + 1 > nd->g_end) nd->g_end = (uint32_t)g + 1;
        if (a->guest[g].ir_first + a->guest[g].ir_count > nd->ir_end)
            nd->ir_end = a->guest[g].ir_first + a->guest[g].ir_count;
        if (a->guest[g].addr + a->guest[g].len > nd->guest_end)
            nd->guest_end = a->guest[g].addr + a->guest[g].len;
    }

    /* ДУГИ: по ПОСЛЕДНЕЙ гостевой команде узла. */
    for (i = 0; i < a->node_n; i++) {
        const hb_cfg_node_t* nd = &a->nodes[i];
        uint32_t last_g = nd->g_end - 1;
        const hb_cfg_guest_t* t = &a->guest[last_g];
        uint32_t site_ir = t->ir_count ? t->ir_first + t->ir_count - 1 : t->ir_first;
        uint64_t next_addr = t->addr + t->len;
        int ok = 1;

        if (t->is_branch && t->is_cond) {
            /* Условный переход даёт РОВНО ДВЕ нормальные альтернативы. */
            if (!drop_taken) {
                uint64_t tgt = t->target + (skew ? 1u : 0u);
                int tg = -1;
                uint8_t st = t->has_target ? cfg_target_state(func, a, tgt, &tg)
                                           : (uint8_t)HB_CFG_T_UNKNOWN_TRANSFER;
                ok &= cfg_add_edge(a, (uint32_t)i, tg >= 0 ? g_to_node[tg] : -1,
                                   site_ir, t->addr, t->has_target ? tgt : 0,
                                   HB_CFG_E_TAKEN, st);
            }
            if (!drop_fall) {
                int fg = -1;
                uint8_t st = cfg_target_state(func, a, next_addr, &fg);
                ok &= cfg_add_edge(a, (uint32_t)i, fg >= 0 ? g_to_node[fg] : -1,
                                   site_ir, t->addr, next_addr, HB_CFG_E_FALL, st);
            }
        } else if (t->is_branch && !t->is_cond) {
            if (t->has_target) {
                uint64_t tgt = t->target + (skew ? 1u : 0u);
                int tg = -1;
                uint8_t st = cfg_target_state(func, a, tgt, &tg);
                ok &= cfg_add_edge(a, (uint32_t)i, tg >= 0 ? g_to_node[tg] : -1,
                                   site_ir, t->addr, tgt, HB_CFG_E_JUMP, st);
            } else {
                /* Косвенный переход: одна наблюдённая цель не делает набор целей полным. */
                ok &= cfg_add_edge(a, (uint32_t)i, -1, site_ir, t->addr, 0,
                                   HB_CFG_E_TRANSFER, HB_CFG_T_UNKNOWN_TRANSFER);
            }
        } else if (t->is_call || t->is_ret) {
            /* ★ НЕ рисуем «CALL -> следующая команда» обычным падением: между ними
             * исполняется вызванное, и его контракт нам неизвестен. */
            ok &= cfg_add_edge(a, (uint32_t)i, -1, site_ir, t->addr, 0,
                               HB_CFG_E_TRANSFER, HB_CFG_T_UNKNOWN_TRANSFER);
        } else if (last_g + 1 < a->guest_n) {
            /* Узел кончился, потому что дальше начинается лидер: обычное падение. */
            int fg = -1;
            uint8_t st = cfg_target_state(func, a, next_addr, &fg);
            ok &= cfg_add_edge(a, (uint32_t)i, fg >= 0 ? g_to_node[fg] : -1,
                               site_ir, t->addr, next_addr, HB_CFG_E_FALL, st);
        } else {
            /* Разбор оборван окном/пределом: явный выход с причиной, не пустая маска. */
            uint8_t st = func->truncated ? (uint8_t)HB_CFG_T_UNKNOWN_INCOMPLETE
                                         : (uint8_t)HB_CFG_T_UNKNOWN_OUTSIDE;
            ok &= cfg_add_edge(a, (uint32_t)i, -1, site_ir, t->addr, next_addr,
                               HB_CFG_E_END, st);
        }
        if (!ok) {
            free(leader); free(g_to_node);
            a->incomplete_reason = "дуги: отказ выделения";
            return 0;
        }
    }

    if (dup_edge && a->edge_n > 0) {
        hb_cfg_edge_t e = a->edges[0];
        if (!cfg_add_edge(a, e.from, e.to, e.site_ir, e.site_guest, e.target_guest,
                          e.kind, e.state)) {
            free(leader); free(g_to_node);
            a->incomplete_reason = "порча: отказ выделения";
            return 0;
        }
    }

    /* НАБЛЮДАТЕЛИ: точки, где посторонний может прочитать состояние ДО commit. */
    for (i = 0; i < block->instr_count; i++) {
        const hb_ir_instr_t* in = &block->instrs[i];
        uint8_t reason;
        if (hb_ir_instr_touches_guest_memory(in)) reason = HB_CFG_OBS_MEM;
        else if (in->op == HB_IR_INT || in->op == HB_IR_INT3 || in->op == HB_IR_INTO)
            reason = HB_CFG_OBS_TRAP;
        else if (in->op == HB_IR_HOST_CALL || in->op == HB_IR_UNSUPPORTED)
            reason = HB_CFG_OBS_HELPER;
        else continue;
        {
            hb_cfg_obs_t* o;
            uint32_t node = 0, k;
            for (k = 0; k < a->node_n; k++)
                if (i >= a->nodes[k].ir_first && i < a->nodes[k].ir_end) { node = k; break; }
            CFG_GROW(a->obs, a->obs_n, a->obs_cap, hb_cfg_obs_t);
            o = &a->obs[a->obs_n++];
            o->node = node; o->ir = (uint32_t)i;
            o->guest = in->guest_addr; o->reason = reason;
        }
    }

    /* ОБРАТНЫЙ СЧЁТ входов. */
    if (!no_pred) {
        a->pred_count = (uint32_t*)calloc(a->node_n ? a->node_n : 1, sizeof(uint32_t));
        if (!a->pred_count) {
            free(leader); free(g_to_node);
            a->incomplete_reason = "обратный счёт: отказ выделения";
            return 0;
        }
        a->pred_n = a->node_n;
        for (i = 0; i < a->edge_n; i++)
            if (a->edges[i].to >= 0) a->pred_count[a->edges[i].to]++;
    }

    free(leader);
    free(g_to_node);
    a->complete = 1;
    a->incomplete_reason = NULL;
    /* Алиас для кодогенератора: он получает `cfg`, а владелец графа — `func`. */
    if (func->cfg) func->cfg->acfg = a;
    return 1;
}

/* Независимая проверка. Ожидания берутся ИЗ ПЕРЕПИСИ, а не из уже построенных дуг —
 * иначе проверка подтверждала бы сама себя. */
int hb_cfg_validate(const hb_cfg_analysis_t* a, const hb_ir_block_t* block,
                    const char** why) {
    size_t i, g;
    uint32_t cover = 0;
    size_t expect_edges = 0;

    if (why) *why = NULL;
    if (!a || !block) { if (why) *why = "нет графа"; return 0; }
    if (!a->complete) { if (why) *why = a->incomplete_reason ? a->incomplete_reason : "граф неполон"; return 0; }

    /* 1. Разбиение покрывает массив ровно один раз и идёт подряд. */
    for (i = 0; i < a->node_n; i++) {
        if (a->nodes[i].ir_first != cover) { if (why) *why = "узлы не подряд"; return 0; }
        if (a->nodes[i].ir_end < a->nodes[i].ir_first) { if (why) *why = "пустой узел"; return 0; }
        cover = a->nodes[i].ir_end;
    }
    if (cover != (uint32_t)block->instr_count) { if (why) *why = "узлы не покрывают массив"; return 0; }

    /* 2. Число альтернатив у каждого terminator'а — ПО ПЕРЕПИСИ. */
    for (i = 0; i < a->node_n; i++) {
        const hb_cfg_guest_t* t = &a->guest[a->nodes[i].g_end - 1];
        if (t->is_branch && t->is_cond) expect_edges += 2;
        else expect_edges += 1;
    }
    if (expect_edges != a->edge_n) { if (why) *why = "число дуг не совпало с ожидаемым по переписи"; return 0; }

    /* 2б. ★ АДРЕСНАЯ СВЕРКА, А НЕ ТОЛЬКО СЧЁТ. Первая редакция проверки считала одни
     * дуги — и намеренная порча «цель на байт мимо» (TEST_CFG_SKEW_TARGET) осталась
     * ЗЕЛЁНОЙ: число дуг не менялось, состояние цели тоже. Зелёная порча означает
     * негодный контроль, а не безвредную порчу, поэтому чинится контроль.
     * Ожидание берётся ИЗ ПЕРЕПИСИ: цель взятой ветви = `target` декодера, цель провала
     * = адрес за командой. Никакого обращения к уже построенным дугам. */
    for (i = 0; i < a->node_n; i++) {
        const hb_cfg_guest_t* t = &a->guest[a->nodes[i].g_end - 1];
        size_t j;
        int seen_taken = 0, seen_fall = 0;
        if (!(t->is_branch && t->is_cond)) continue;
        for (j = 0; j < a->edge_n; j++) {
            if (a->edges[j].from != (uint32_t)i) continue;
            if (a->edges[j].kind == HB_CFG_E_TAKEN) {
                seen_taken++;
                if (t->has_target && a->edges[j].target_guest != t->target) {
                    if (why) *why = "цель взятой ветви разошлась с переписью";
                    return 0;
                }
            } else if (a->edges[j].kind == HB_CFG_E_FALL) {
                seen_fall++;
                if (a->edges[j].target_guest != t->addr + t->len) {
                    if (why) *why = "цель провала разошлась с переписью";
                    return 0;
                }
            }
        }
        if (seen_taken != 1 || seen_fall != 1) {
            if (why) *why = "у условного перехода не ровно две альтернативы";
            return 0;
        }
    }

    /* 3. Дуги не дублируются: (from, kind, target) уникальны. */
    for (i = 0; i < a->edge_n; i++) {
        size_t j;
        for (j = i + 1; j < a->edge_n; j++)
            if (a->edges[i].from == a->edges[j].from &&
                a->edges[i].kind == a->edges[j].kind &&
                a->edges[i].target_guest == a->edges[j].target_guest) {
                if (why) *why = "дуга продублирована";
                return 0;
            }
    }

    /* 4. Обратный счёт согласован с прямым. */
    if (a->pred_n != a->node_n) { if (why) *why = "обратный счёт не заполнен"; return 0; }
    {
        uint32_t sum_pred = 0, sum_succ = 0;
        for (i = 0; i < a->pred_n; i++) sum_pred += a->pred_count[i];
        for (i = 0; i < a->edge_n; i++) if (a->edges[i].to >= 0) sum_succ++;
        if (sum_pred != sum_succ) { if (why) *why = "сумма входов не равна сумме внутренних выходов"; return 0; }
    }

    /* 5. Каждая гостевая команда принадлежит ровно одному узлу. */
    for (g = 0; g < a->guest_n; g++) {
        size_t own = 0;
        for (i = 0; i < a->node_n; i++)
            if (g >= a->nodes[i].g_first && g < a->nodes[i].g_end) own++;
        if (own != 1) { if (why) *why = "гостевая команда не в одном узле"; return 0; }
    }
    return 1;
}

/* --- IR Builder --- */
hb_ir_builder_t* hb_ir_builder_create(hb_ir_func_t* func) {
    hb_ir_builder_t* b = calloc(1, sizeof(hb_ir_builder_t));
    if (!b) return NULL;
    b->func = func;
    if (func->cfg && func->cfg->block_count > 0) {
        b->current_block = func->cfg->blocks[0];
    }
    return b;
}

void hb_ir_builder_destroy(hb_ir_builder_t* b) {
    free(b);
}

void hb_ir_builder_set_block(hb_ir_builder_t* b, hb_ir_block_t* block) {
    if (b) b->current_block = block;
}

hb_ir_instr_t* hb_ir_emit(hb_ir_builder_t* b, hb_ir_op_t op) {
    if (!b || !b->current_block) return NULL;
    hb_ir_block_t* blk = b->current_block;
    if (blk->instr_count >= blk->instr_cap) {
        size_t new_cap = blk->instr_cap * 2;
        hb_ir_instr_t* new_instrs = realloc(blk->instrs, new_cap * sizeof(hb_ir_instr_t));
        if (!new_instrs) return NULL;
        blk->instrs = new_instrs;
        blk->instr_cap = new_cap;
    }
    hb_ir_instr_t* instr = &blk->instrs[blk->instr_count++];
    memset(instr, 0, sizeof(hb_ir_instr_t));
    instr->op = op;
    /* The memo describes a fixed instruction list; appending changes that list, so drop it. This
     * is the ONLY mutation path (hb_ir_block_create is the only other writer), which is what makes
     * the memo safe to trust in the dispatcher. */
    blk->first_transfer_idx = HB_IR_TRANSFER_UNCOMPUTED;
    return instr;
}

#define EMIT_OP(name, op_code) \
    hb_ir_instr_t* hb_ir_emit_##name(hb_ir_builder_t* b, hb_ir_operand_t dst, hb_ir_operand_t src) { \
        hb_ir_instr_t* i = hb_ir_emit(b, op_code); \
        if (i) { i->dst = dst; i->src1 = src; } \
        return i; \
    }

EMIT_OP(mov, HB_IR_MOV)
EMIT_OP(lea, HB_IR_LEA)

hb_ir_instr_t* hb_ir_emit_binop(hb_ir_builder_t* b, hb_ir_op_t op, hb_ir_operand_t dst, hb_ir_operand_t a, hb_ir_operand_t b_op) {
    hb_ir_instr_t* i = hb_ir_emit(b, op);
    if (i) { i->dst = dst; i->src1 = a; i->src2 = b_op; }
    return i;
}

hb_ir_instr_t* hb_ir_emit_unop(hb_ir_builder_t* b, hb_ir_op_t op, hb_ir_operand_t dst, hb_ir_operand_t src) {
    hb_ir_instr_t* i = hb_ir_emit(b, op);
    if (i) { i->dst = dst; i->src1 = src; }
    return i;
}

hb_ir_instr_t* hb_ir_emit_load(hb_ir_builder_t* b, hb_ir_operand_t dst, hb_ir_operand_t addr) {
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_LOAD);
    if (i) { i->dst = dst; i->src1 = addr; }
    return i;
}

hb_ir_instr_t* hb_ir_emit_store(hb_ir_builder_t* b, hb_ir_operand_t addr, hb_ir_operand_t src) {
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_STORE);
    if (i) { i->src1 = addr; i->src2 = src; }
    return i;
}

hb_ir_instr_t* hb_ir_emit_fence(hb_ir_builder_t* b, hb_fence_kind_t kind) {
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_FENCE);
    if (i) i->src1 = hb_ir_imm((int64_t)kind, HB_SIZE_8);
    return i;
}

hb_ir_instr_t* hb_ir_emit_call(hb_ir_builder_t* b, uint64_t target) {
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_CALL);
    if (i) { i->target = target; i->src1 = hb_ir_none(); }
    return i;
}

hb_ir_instr_t* hb_ir_emit_ret(hb_ir_builder_t* b) {
    return hb_ir_emit(b, HB_IR_RET);
}

hb_ir_instr_t* hb_ir_emit_jmp(hb_ir_builder_t* b, uint64_t target) {
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_JMP);
    if (i) { i->target = target; i->src1 = hb_ir_none(); }
    return i;
}

hb_ir_instr_t* hb_ir_emit_jcc(hb_ir_builder_t* b, hb_cc_t cc, uint64_t target) {
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_Jcc);
    if (i) { i->cc = cc; i->target = target; }
    return i;
}

hb_ir_instr_t* hb_ir_emit_push(hb_ir_builder_t* b, hb_ir_operand_t src) {
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_PUSH);
    if (i) { i->src1 = src; }
    return i;
}

hb_ir_instr_t* hb_ir_emit_pop(hb_ir_builder_t* b, hb_ir_operand_t dst) {
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_POP);
    if (i) { i->dst = dst; }
    return i;
}

hb_ir_instr_t* hb_ir_emit_cmp(hb_ir_builder_t* b, hb_ir_operand_t a, hb_ir_operand_t b_op) {
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_CMP);
    if (i) { i->src1 = a; i->src2 = b_op; }
    return i;
}

hb_ir_instr_t* hb_ir_emit_test(hb_ir_builder_t* b, hb_ir_operand_t a, hb_ir_operand_t b_op) {
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_TEST);
    if (i) { i->src1 = a; i->src2 = b_op; }
    return i;
}

hb_ir_instr_t* hb_ir_emit_setcc(hb_ir_builder_t* b, hb_cc_t cc, hb_ir_operand_t dst) {
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_SETcc);
    if (i) { i->cc = cc; i->dst = dst; }
    return i;
}

hb_ir_instr_t* hb_ir_emit_cmovcc(hb_ir_builder_t* b, hb_cc_t cc, hb_ir_operand_t dst, hb_ir_operand_t src) {
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_CMOVcc);
    if (i) { i->cc = cc; i->dst = dst; i->src1 = src; }
    return i;
}

hb_ir_instr_t* hb_ir_emit_host_call(hb_ir_builder_t* b, uint32_t thunk_id) {
    (void)thunk_id;
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_HOST_CALL);
    if (i) { /* thunk id stored in imm? placeholder */ }
    return i;
}

hb_ir_instr_t* hb_ir_emit_fault(hb_ir_builder_t* b, hb_result_t reason, const char* msg) {
    /* ★ MacRunner 2026-08-15, итерация 939 — аргумент `reason` здесь ВЫБРАСЫВАЛСЯ.
     * Вызывающие честно выбирали коды (-6 для портов, -8 для `HLT` и `MOV CRn`), а функция
     * их не сохраняла, и все отказы становились одинаковыми. Сохраняем, чтобы разбор был
     * возможен; сам разбор пока делает только ветвь привилегий (см. `hb_ir_emit_fault_priv`),
     * остальные значения лежат для будущего и уже не теряются. */
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_FAULT);
    if (i) { i->comment = msg; i->src2 = hb_ir_imm((uint64_t)(int64_t)reason, HB_SIZE_32); }
    return i;
}

hb_ir_instr_t* hb_ir_emit_fault_priv(hb_ir_builder_t* b, const char* msg) {
    /* Признак кладём в src1 как непосредственное: узел `FAULT` операндов не имеет, поле
     * свободно, и исполнителю достаточно одного сравнения. Значение равно виду отказа
     * (`HB_FAULT_KIND_PRIVILEGED`), чтобы не заводить второй словарь. */
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_FAULT);
    if (i) { i->comment = msg; i->src1 = hb_ir_imm(3 /* HB_FAULT_KIND_PRIVILEGED */, HB_SIZE_32); }
    return i;
}

hb_ir_instr_t* hb_ir_emit_fault_illegal(hb_ir_builder_t* b, const char* msg) {
    /* Итерация 1081: то же устройство, что у привилегированного отказа, но вид 5 (#UD). */
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_FAULT);
    if (i) { i->comment = msg; i->src1 = hb_ir_imm(5 /* HB_FAULT_KIND_ILLEGAL */, HB_SIZE_32); }
    return i;
}

hb_ir_instr_t* hb_ir_emit_unsupported(hb_ir_builder_t* b, const char* feature, uint64_t guest_addr, uint8_t* bytes, size_t len) {
    (void)bytes;
    (void)len;
    hb_ir_instr_t* i = hb_ir_emit(b, HB_IR_UNSUPPORTED);
    if (i) {
        i->guest_addr = guest_addr;
        i->comment = feature;
        b->func->has_unsupported = true;
        free((void*)b->func->unsupported_reason);
        b->func->unsupported_reason = strdup(feature);
    }
    return i;
}

/* --- Operand helpers --- */
hb_ir_operand_t hb_ir_reg(hb_reg_t reg, hb_size_t size) {
    hb_ir_operand_t op = {0};
    op.type = HB_OP_REG;
    op.size = size;
    op.reg = reg;
    return op;
}

hb_ir_operand_t hb_ir_imm(int64_t val, hb_size_t size) {
    hb_ir_operand_t op = {0};
    op.type = HB_OP_IMM;
    op.size = size;
    op.imm = val;
    return op;
}

hb_ir_operand_t hb_ir_mem(hb_reg_t base, hb_reg_t index, uint8_t scale, int64_t disp, hb_size_t size) {
    return hb_ir_mem_segment(base, index, scale, disp, size, 0);
}

hb_ir_operand_t hb_ir_mem_segment(hb_reg_t base, hb_reg_t index, uint8_t scale,
                                  int64_t disp, hb_size_t size, uint8_t segment) {
    hb_ir_operand_t op = {0};
    op.type = HB_OP_MEM;
    op.size = size;
    op.mem.base = base;
    op.mem.index = index;
    op.mem.scale = scale;
    op.mem.disp = disp;
    op.mem.segment = segment;
    op.mem.addr32 = false;
    return op;
}

hb_ir_operand_t hb_ir_label(uint64_t id) {
    hb_ir_operand_t op = {0};
    op.type = HB_OP_LABEL;
    op.label = id;
    return op;
}

hb_ir_operand_t hb_ir_none(void) {
    hb_ir_operand_t op = {0};
    op.type = HB_OP_NONE;
    return op;
}

/* --- Register names --- */
static const char* reg_names[] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15",
    "rip",
    "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
    "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15",
    "xmm16","xmm17","xmm18","xmm19","xmm20","xmm21","xmm22","xmm23",
    "xmm24","xmm25","xmm26","xmm27","xmm28","xmm29","xmm30","xmm31"
};

const char* hb_reg_name(hb_reg_t reg) {
    if (reg < HB_REG_COUNT) return reg_names[reg];
    return "?";
}

static const char* reg_x86_names[] = {
    "eax","ecx","edx","ebx","esp","ebp","esi","edi",
    "eip",
    "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7"
};

const char* hb_reg_x86_name(hb_reg_x86_t reg) {
    if (reg < HB_REG_X86_COUNT) return reg_x86_names[reg];
    return "?";
}

/* --- Serialization --- */
char* hb_ir_func_to_json(const hb_ir_func_t* func) {
    if (!func) return strdup("{}");
    size_t cap = 4096;
    char* buf = malloc(cap);
    if (!buf) return NULL;
    int n = snprintf(buf, cap,
        "{\n  \"guest_addr\": \"0x%llx\",\n  \"guest_len\": %zu,\n  \"blocks\": %zu,\n  \"has_unsupported\": %s,\n  \"unsupported_reason\": \"%s\"\n}",
        (unsigned long long)func->guest_addr,
        func->guest_len,
        func->cfg ? func->cfg->block_count : 0,
        func->has_unsupported ? "true" : "false",
        func->unsupported_reason ? func->unsupported_reason : ""
    );
    if (n < 0 || (size_t)n >= cap) {
        free(buf);
        return strdup("{}");
    }
    return buf;
}

char* hb_ir_func_to_string(const hb_ir_func_t* func) {
    if (!func) return strdup("(null)");
    size_t cap = 4096;
    char* buf = malloc(cap);
    if (!buf) return NULL;
    int n = snprintf(buf, cap, "func @0x%llx (%zu bytes)\n",
        (unsigned long long)func->guest_addr, func->guest_len);
    if (func->cfg) {
        for (size_t i = 0; i < func->cfg->block_count; i++) {
            hb_ir_block_t* blk = func->cfg->blocks[i];
            n += snprintf(buf + n, cap - n, "  block %llu @0x%llx (%zu instrs)\n",
                (unsigned long long)blk->id,
                (unsigned long long)blk->guest_addr,
                blk->instr_count);
            if (n < 0 || (size_t)n >= cap) break;
        }
    }
    return buf;
}

hb_result_t hb_ir_func_validate(const hb_ir_func_t* func) {
    if (!func) return HB_ERR_INVALID_ARG;
    if (!func->cfg) return HB_ERR_INVALID_ARG;
    if (func->cfg->block_count == 0) return HB_ERR_INVALID_ARG;
    if (func->has_unsupported && !func->unsupported_reason) return HB_ERR_INVALID_ARG;
    return HB_OK;
}
