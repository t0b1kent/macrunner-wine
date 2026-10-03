/* hb_probe.c — реализация прибора, не способного выдать неотличимый ноль.
 * Разбор замысла и границ — в include/hb_probe.h. */

#include "hb_probe.h"

#include <stdlib.h>
#include <string.h>

#if defined(__has_include)
#  if __has_include(<dlfcn.h>)
#    include <dlfcn.h>
#    define HB_PROBE_EST_DLADDR 1
#  endif
#endif
#ifndef HB_PROBE_EST_DLADDR
#  define HB_PROBE_EST_DLADDR 0
#endif

/* ── Реестр ────────────────────────────────────────────────────────────────────
 * Список, а не массив: приборы объявляются по всему дереву, число заранее не
 * известно. Свой экземпляр в каждом образе, который слинковал libhyperbridge.a —
 * и это НУЖНОЕ свойство: перепись ntdll.so и перепись xtajit.so различны, и
 * заголовок каждой называет свой образ по ответу загрузчика. */
static hb_probe_t *g_spisok = NULL;
static unsigned    g_registered = 0;
static unsigned    g_otkaz_registracii = 0;   /* приборы, отвергнутые при записи */
static int         g_atexit_postavlen = 0;

/* Конструкторы одного образа исполняются последовательно, но приборы правятся из
 * рабочих потоков. Счётчики — атомарно, список — только на этапе конструкторов. */
#define HB_ATOM_INC(x) __atomic_add_fetch(&(x), 1, __ATOMIC_RELAXED)
#define HB_ATOM_GET(x) __atomic_load_n(&(x), __ATOMIC_RELAXED)

/* ── Пульс переписи: состояние механизма ──────────────────────────────────────
 * Разбор замысла — в hb_probe.h у объявления hb_probe_census_pulse. */
static unsigned long long g_pulse_no;        /* номер пульса, для степеней двойки */
static unsigned long long g_last_otpechatok; /* отпечаток последней НАПЕЧАТАННОЙ переписи */
static int      g_otpechatok_est;            /* был ли уже хоть один отпечаток */
static unsigned g_census_printed;            /* сколько раз перепись напечаталась */
static int      g_final_napechatan;          /* защёлка: окончательная — ровно одна */
static int      g_v_pechati;                 /* один печатающий за раз (потоки + рекурсия) */

unsigned hb_probe_count(void) { return g_registered; }
unsigned hb_probe_census_printed_count(void) { return HB_ATOM_GET(g_census_printed); }

static void hb_probe_census_do(FILE *out, const char *why, int final);

static void hb_probe_atexit_census(void)
{
    /* Штатный выход: ОДНА окончательная перепись. Защёлка внутри census_do —
     * без неё atexit и последний пульс дали бы два итога, и читатель не знал бы,
     * который из них окончательный. */
    hb_probe_census_do(stderr, "exit", 1);
}

/* Отпечаток переписи. Считается по ЧИСЛАМ и СОСТОЯНИЯМ всех приборов: если он не
 * изменился, печатать нечего — вторая точно такая же перепись не добавила бы ни
 * одного факта, а в журнале выглядела бы как новое наблюдение. */
static unsigned long long hb_probe_otpechatok(void)
{
    unsigned long long h = 1469598103934665603ULL;   /* FNV-1a, 64 бита */
    hb_probe_t *p;
    for (p = g_spisok; p; p = p->next) {
        unsigned long long v[4];
        unsigned i;
        v[0] = HB_ATOM_GET(p->looked);
        v[1] = HB_ATOM_GET(p->hits);
        v[2] = HB_ATOM_GET(p->printed);
        v[3] = (unsigned long long)hb_probe_state(p);
        for (i = 0; i < 4; i++) { h ^= v[i]; h *= 1099511628211ULL; }
    }
    h ^= (unsigned long long)g_registered;
    h *= 1099511628211ULL;
    return h;
}

/* Меняется ли ХОТЬ ОДНО состояние против прошлой печати. Состояние — предмет
 * переписи; ради него она и печатается вне расписания. */
static unsigned long long hb_probe_otpechatok_sostoyanij(void)
{
    unsigned long long h = 1469598103934665603ULL;
    hb_probe_t *p;
    for (p = g_spisok; p; p = p->next) {
        h ^= (unsigned long long)hb_probe_state(p);
        h *= 1099511628211ULL;
    }
    h ^= (unsigned long long)g_registered;
    return h;
}
static unsigned long long g_last_sostoyaniya;

static int hb_probe_stepen_dvojki(unsigned long long n)
{
    return n != 0 && (n & (n - 1)) == 0;
}

void hb_probe_census_pulse(FILE *out, const char *why)
{
    unsigned long long n, otp, sost;
    int nado;

    /* ★ ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ ВСТРОЕН: приборов нет — молчим ПОЛНОСТЬЮ.
     * Пустая перепись «всего=0, всё по нулям» неотличима от переписи исправного
     * образа, где приборы просто молчат. Лекарство от неотличимого нуля не смеет
     * заводить новый. */
    if (g_registered == 0) return;

    n = __atomic_add_fetch(&g_pulse_no, 1, __ATOMIC_RELAXED);
    sost = hb_probe_otpechatok_sostoyanij();

    /* Печатаем: (а) при СМЕНЕ СОСТОЯНИЯ — это предмет переписи; (б) на пульсах
     * с номером-степенью двойки — чтобы величины не устаревали на порядки. */
    nado = 0;
    if (!g_otpechatok_est) nado = 1;
    else if (sost != g_last_sostoyaniya) nado = 1;
    else if (hb_probe_stepen_dvojki(n)) nado = 1;
    if (!nado) return;

    /* Одинаковую подряд не печатаем ни при каком поводе. */
    otp = hb_probe_otpechatok();
    if (g_otpechatok_est && otp == g_last_otpechatok) return;

    hb_probe_census_do(out, why ? why : "pulse", 0);
}

void hb_probe_register(hb_probe_t *p, const void *anchor)
{
    if (!p) { g_otkaz_registracii++; return; }
    /* Пустое имя или пустая популяция — прибор негоден. Не молчим: считаем отказы,
     * и самопроверка сделает всю перепись недействительной. Так «прибор объявлен
     * кое-как» перестаёт быть тихой потерей. */
    if (!p->name || !p->name[0] || !p->population || !p->population[0]) {
        g_otkaz_registracii++;
        return;
    }
    p->anchor = anchor ? anchor : (const void *)p;
    p->next = g_spisok;
    g_spisok = p;
    g_registered++;

    if (!g_atexit_postavlen) {
        g_atexit_postavlen = 1;
        atexit(hb_probe_atexit_census);
    }
}

/* ── Классификатор ─────────────────────────────────────────────────────────────
 * Чистая функция от трёх чисел. Отдельно — чтобы самопроверка кормила её заведомо
 * плохими входами, не заводя настоящих приборов и не трогая реестр. */
hb_probe_state_t hb_probe_state(const hb_probe_t *p)
{
    unsigned long long looked, hits, printed;
    if (!p) return HB_PROBE_INCONSISTENT;
    looked  = HB_ATOM_GET(((hb_probe_t *)p)->looked);
    hits    = HB_ATOM_GET(((hb_probe_t *)p)->hits);
    printed = HB_ATOM_GET(((hb_probe_t *)p)->printed);

    /* Невозможное состояние: явление учтено там, где наблюдение не начиналось.
     * Значит HB_PROBE_LOOKED стоит ВНУТРИ условия — учёт в точке решения вместо
     * точки действия. Прибор доносит на себя. */
    if (hits > looked) return HB_PROBE_INCONSISTENT;
    if (printed > hits) return HB_PROBE_INCONSISTENT;

    if (looked == 0) return HB_PROBE_NOT_OBSERVED;   /* «не смотрел» */
    if (hits == 0)   return HB_PROBE_NO_EVENTS;      /* «смотрел, не было» — честный ноль */
    /* Считалось, но поштучно НЕ печаталось (HB_PROBE_HIT без HB_PROBE_SAY): hits ТОЧЕН.
     * Раньше этот случай уходил в EVENTS-TRUNCATED, чья легенда объявляет число нижней
     * границей — а это неправда: усечена печать, не счёт. Разбор у enum в заголовке. */
    if (printed == 0)   return HB_PROBE_EVENTS_COUNTED;
    if (printed < hits) return HB_PROBE_EVENTS_TRUNCATED; /* число = НИЖНЯЯ ГРАНИЦА */
    return HB_PROBE_EVENTS;
}

const char *hb_probe_state_name(hb_probe_state_t s)
{
    switch (s) {
    case HB_PROBE_NOT_OBSERVED:     return "NOT-OBSERVED";
    case HB_PROBE_NO_EVENTS:        return "NO-EVENTS";
    case HB_PROBE_EVENTS:           return "EVENTS";
    case HB_PROBE_EVENTS_COUNTED:   return "EVENTS-COUNTED";
    case HB_PROBE_EVENTS_TRUNCATED: return "EVENTS-TRUNCATED";
    case HB_PROBE_INCONSISTENT:     return "INCONSISTENT";
    }
    return "INCONSISTENT";
}

/* ── Учёт ──────────────────────────────────────────────────────────────────── */

void hb_probe_looked(hb_probe_t *p) { if (p) HB_ATOM_INC(p->looked); }
void hb_probe_hit(hb_probe_t *p)    { if (p) HB_ATOM_INC(p->hits);   }

int hb_probe_should_print(hb_probe_t *p)
{
    if (!p) return 0;
    if (p->cap && HB_ATOM_GET(p->printed) >= (unsigned long long)p->cap) return 0;
    HB_ATOM_INC(p->printed);
    return 1;
}

/* ── Где живёт прибор: ответ ЗАГРУЗЧИКА, а не строка автора ───────────────────
 * dladdr() по адресу внутри образа возвращает путь того образа, который РЕАЛЬНО
 * загружен. Соврать этим нельзя: адрес принадлежит тому, кто его содержит. */
static const char *hb_probe_gde(const void *anchor)
{
#if HB_PROBE_EST_DLADDR
    Dl_info info;
    if (anchor && dladdr(anchor, &info) && info.dli_fname && info.dli_fname[0])
        return info.dli_fname;
    return "?-dladdr-ne-otvetil";
#else
    (void)anchor;
    return "?-dladdr-nedostupen";
#endif
}

/* ── Самопроверка ──────────────────────────────────────────────────────────────
 * Прибор ОБЯЗАН покраснеть на заведомо плохом входе, иначе его зелёный ничего не
 * стоит. Здесь классификатор гоняется по случаям, каждый из которых когда-то был
 * настоящей потерей времени. */
struct hb_probe_sluchaj {
    const char *opisanie;
    unsigned long long looked, hits, printed;
    hb_probe_state_t zhdyom;
};

static const struct hb_probe_sluchaj HB_PROBE_SLUCHAI[] = {
    /* ГЛАВНОЕ РАЗЛИЧИЕ, ради которого всё написано: два разных нуля. */
    { "не смотрел (управление не дошло)",        0,  0,  0, HB_PROBE_NOT_OBSERVED },
    { "смотрел, явления нет — честный ноль",   100,  0,  0, HB_PROBE_NO_EVENTS },
    /* Потолок не смеет усечь молча. */
    { "потолок обрезал: число — нижняя граница", 100, 50,  8, HB_PROBE_EVENTS_TRUNCATED },
    { "явление есть, напечатано всё",          100,  7,  7, HB_PROBE_EVENTS },
    /* ★ 06.09.2026 — счётчик без печати НЕ смеет метиться «нижней границей»:
     * hits точен, поштучной печати просто нет по замыслу (HB_PROBE_HIT). */
    { "считалось, поштучно не печаталось",     100,  7,  0, HB_PROBE_EVENTS_COUNTED },
    { "одно явление, печати нет",                1,  1,  0, HB_PROBE_EVENTS_COUNTED },
    /* Учёт в точке решения вместо точки действия. */
    { "LOOKED внутри условия (hits > looked)",    0,  5,  0, HB_PROBE_INCONSISTENT },
    { "напечатано больше, чем случилось",        10,  1,  4, HB_PROBE_INCONSISTENT },
    /* Границы: один-единственный случай не должен путаться с нулём. */
    { "ровно одно наблюдение, ровно одно явление", 1,  1,  1, HB_PROBE_EVENTS },
    { "одно наблюдение, явления нет",              1,  0,  0, HB_PROBE_NO_EVENTS },
};

int hb_probe_selftest(FILE *out)
{
    unsigned i;
    int provaleno = 0;
    if (!out) out = stderr;

    for (i = 0; i < sizeof(HB_PROBE_SLUCHAI) / sizeof(HB_PROBE_SLUCHAI[0]); i++) {
        const struct hb_probe_sluchaj *s = &HB_PROBE_SLUCHAI[i];
        hb_probe_t proba;
        hb_probe_state_t got;
        memset(&proba, 0, sizeof(proba));
        proba.name = "selftest";
        proba.population = "искусственный вход самопроверки";
        proba.looked = s->looked;
        proba.hits = s->hits;
        proba.printed = s->printed;
        got = hb_probe_state(&proba);
        if (got != s->zhdyom) {
            provaleno++;
            fprintf(out,
                "macrunner-probe-selftest: PROVAL sluchaj=%u \"%s\" "
                "looked=%llu hits=%llu printed=%llu zhdali=%s poluchili=%s\n",
                i, s->opisanie, s->looked, s->hits, s->printed,
                hb_probe_state_name(s->zhdyom), hb_probe_state_name(got));
        }
    }

    /* Отдельно: потолок обязан РЕАЛЬНО ограничивать печать, а hits — расти сверх него.
     * Проверяется поведением should_print, а не только классификатором. */
    {
        hb_probe_t proba;
        unsigned n, napechatano = 0;
        memset(&proba, 0, sizeof(proba));
        proba.name = "selftest-cap";
        proba.population = "искусственный вход самопроверки потолка";
        proba.cap = 3;
        for (n = 0; n < 10; n++) {
            hb_probe_looked(&proba);
            hb_probe_hit(&proba);
            if (hb_probe_should_print(&proba)) napechatano++;
        }
        if (napechatano != 3 || proba.hits != 10 ||
            hb_probe_state(&proba) != HB_PROBE_EVENTS_TRUNCATED) {
            provaleno++;
            fprintf(out,
                "macrunner-probe-selftest: PROVAL potolok: napechatano=%u (zhdali 3) "
                "hits=%llu (zhdali 10) sostoyanie=%s (zhdali EVENTS-TRUNCATED)\n",
                napechatano, proba.hits,
                hb_probe_state_name(hb_probe_state(&proba)));
        }
    }

    /* Без потолка печатается всё, и состояние НЕ должно быть «усечено». */
    {
        hb_probe_t proba;
        unsigned n, napechatano = 0;
        memset(&proba, 0, sizeof(proba));
        proba.name = "selftest-nocap";
        proba.population = "искусственный вход самопроверки без потолка";
        proba.cap = 0;
        for (n = 0; n < 10; n++) {
            hb_probe_looked(&proba);
            hb_probe_hit(&proba);
            if (hb_probe_should_print(&proba)) napechatano++;
        }
        if (napechatano != 10 || hb_probe_state(&proba) != HB_PROBE_EVENTS) {
            provaleno++;
            fprintf(out,
                "macrunner-probe-selftest: PROVAL bez potolka: napechatano=%u (zhdali 10) "
                "sostoyanie=%s (zhdali EVENTS)\n",
                napechatano, hb_probe_state_name(hb_probe_state(&proba)));
        }
    }

    /* Приборы, отвергнутые при регистрации (пустая популяция или имя), — это
     * потерянные приборы. Молчать о них нельзя. */
    if (g_otkaz_registracii) {
        provaleno++;
        fprintf(out, "macrunner-probe-selftest: PROVAL registracii: otvergnuto priborov=%u "
                     "(pustoe imya libo pustaya populyaciya)\n", g_otkaz_registracii);
    }

    return provaleno;
}

/* ── Перепись ──────────────────────────────────────────────────────────────── */

void hb_probe_census(FILE *out)
{
    /* Прямой вызов (приёмка, отладка) — это ИТОГ, но не «окончательный» в смысле
     * защёлки: защёлка стережёт только автоматический выход, чтобы atexit и пульс
     * не дали двух итогов. Явный вызов печатает всегда. */
    hb_probe_census_do(out, "vyzov", 0);
}

static void hb_probe_census_do(FILE *out, const char *why, int final)
{
    hb_probe_t *p;
    int provaleno;
    unsigned n_not_observed = 0, n_no_events = 0, n_events = 0,
             n_counted = 0, n_truncated = 0, n_inconsistent = 0, vsego = 0;

    if (!out) out = stderr;

    /* ОДНА ОКОНЧАТЕЛЬНАЯ. Пульс печатает снимки (final=0), atexit — итог (final=1).
     * Без защёлки на штатном выходе печаталось бы два итога подряд, и читателю
     * пришлось бы гадать, который из них авторитетный. */
    if (final) {
        if (__atomic_exchange_n(&g_final_napechatan, 1, __ATOMIC_SEQ_CST)) return;
    }

    /* Один печатающий за раз: пульс приходит из РАЗНЫХ ПОТОКОВ (guard_census_flush
     * потоковый). Две переписи, перемешанные построчно, — не улика, а мусор.
     * Проигравший поток молча уходит: через пульс он вернётся сюда же. */
    if (__atomic_exchange_n(&g_v_pechati, 1, __ATOMIC_ACQUIRE)) {
        if (final) __atomic_store_n(&g_final_napechatan, 0, __ATOMIC_SEQ_CST);
        return;
    }

    provaleno = hb_probe_selftest(out);

    /* Заголовок печатается ВСЕГДА, даже если приборов ноль. Пустой список у
     * ожидаемого образа — это ОТВЕТ («в этом двоичном приборов нет»), а не
     * молчание, которое читают как «не дошло».
     * ★ why/final/seq — чтобы СНИМОК и ИТОГ нельзя было спутать: снимок сделан на
     * ходу и его числа устареют, итог снят на выходе. Раньше различить было нечем,
     * потому что перепись была ровно одна и только на atexit — то есть в боевом
     * прогоне НИ ОДНОЙ. */
    fprintf(out,
        "macrunner-probe-census: obraz=%s priborov=%u selftest=%s why=%s final=%d seq=%u\n",
        hb_probe_gde((const void *)(uintptr_t)&hb_probe_census),
        g_registered,
        provaleno == 0 ? "OK" : "FAILED",
        why ? why : "?",
        final,
        HB_ATOM_GET(g_census_printed) + 1);

    if (provaleno != 0) {
        fprintf(out,
            "macrunner-probe-census: PEREPIS NEDEJSTVITELNA — samoproverka klassifikatora "
            "provalena v %d sluchayah. Chisla nizhe chitat NELZYA.\n", provaleno);
    }

    fprintf(out,
        "macrunner-probe-census: legenda NOT-OBSERVED=upravlenie ne doshlo | "
        "NO-EVENTS=smotrel, yavleniya net | EVENTS=est, napechatano vsyo | "
        "EVENTS-COUNTED=est, chislo TOCHNOE, poshtuchno ne pechatalos | "
        "EVENTS-TRUNCATED=est, chislo NIZHNYAYA GRANICA | INCONSISTENT=pribor neispraven\n");

    for (p = g_spisok; p; p = p->next) {
        hb_probe_state_t s = provaleno ? HB_PROBE_INCONSISTENT : hb_probe_state(p);
        vsego++;
        switch (s) {
        case HB_PROBE_NOT_OBSERVED:     n_not_observed++; break;
        case HB_PROBE_NO_EVENTS:        n_no_events++;    break;
        case HB_PROBE_EVENTS:           n_events++;       break;
        case HB_PROBE_EVENTS_COUNTED:   n_counted++;      break;
        case HB_PROBE_EVENTS_TRUNCATED: n_truncated++;    break;
        case HB_PROBE_INCONSISTENT:     n_inconsistent++; break;
        }
        fprintf(out,
            "macrunner-probe: name=%s state=%s looked=%llu hits=%llu printed=%llu "
            "cap=%u gate=%s where=%s at=%s:%d counts=\"%s\"\n",
            p->name,
            hb_probe_state_name(s),
            HB_ATOM_GET(p->looked), HB_ATOM_GET(p->hits), HB_ATOM_GET(p->printed),
            p->cap,
            p->gate ? p->gate : "-bezuslovnyj-",
            hb_probe_gde(p->anchor),
            p->file, p->line,
            p->population);
    }

    fprintf(out,
        "macrunner-probe-census: itog vsego=%u NOT-OBSERVED=%u NO-EVENTS=%u "
        "EVENTS=%u EVENTS-COUNTED=%u EVENTS-TRUNCATED=%u INCONSISTENT=%u "
        "why=%s final=%d\n",
        vsego, n_not_observed, n_no_events, n_events, n_counted, n_truncated,
        n_inconsistent, why ? why : "?", final);

    /* Отпечатки обновляются ПОСЛЕ печати: иначе неудачная печать (закрытый поток)
     * убедила бы механизм, что перепись уже выдана. */
    g_last_otpechatok = hb_probe_otpechatok();
    g_last_sostoyaniya = hb_probe_otpechatok_sostoyanij();
    g_otpechatok_est = 1;
    HB_ATOM_INC(g_census_printed);
    __atomic_store_n(&g_v_pechati, 0, __ATOMIC_RELEASE);
}
