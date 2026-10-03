/*
 *	Process synchronisation
 *
 * Copyright 1996, 1997, 1998 Marcus Meissner
 * Copyright 1997, 1998, 1999 Alexandre Julliard
 * Copyright 1999, 2000 Juergen Schmied
 * Copyright 2003 Eric Pouech
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <limits.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/debug.h"
#include "wine/list.h"
#include "wine/exception.h"
#include "ntdll_misc.h"

WINE_DEFAULT_DEBUG_CHANNEL(sync);
WINE_DECLARE_DEBUG_CHANNEL(relay);

static const char *crit_section_get_name( const RTL_CRITICAL_SECTION *crit );

/* Diagnostic-only observer for the ABZU heap/loader critical-section inversion.
 * Keep this allocation-free and fail-closed: it runs from the critical-section
 * implementation itself and must not recursively perturb unrelated locks. */
/* NOTE: this runs INSIDE the critical-section implementation, so it must not take a
 * lock.  RtlQueryEnvironmentVariable_U() acquires the PEB lock, i.e. it re-enters
 * RtlEnterCriticalSection( peb->FastPebLock ) — and during early ldr init FastPebLock
 * is still NULL, so wine faults reading crit->SpinCount at NULL+0x20.  That fault is
 * dispatched through code that locks again => the recursive fault storm that killed
 * regedit/regsvr32/services (99% CPU, game never started).  Scan the environment
 * block by hand instead: no lock, no re-entry. */
static BOOL macrunner_hb_heap_cs_observer_enabled(void)
{
    static LONG state;
    static const WCHAR keyW[] =
        {'M','A','C','R','U','N','N','E','R','_','H','B','_','H','E','A','P','_','C','S','_',
         'O','B','S','E','R','V','E','R','=',0};
    LONG current = state;
    const WCHAR *p;
    PEB *peb;

    if (current) return current == 1;

    peb = NtCurrentTeb()->Peb;
    if (!peb || !peb->ProcessParameters) return FALSE;      /* not ready: do not latch */
    p = peb->ProcessParameters->Environment;
    if (!p) return FALSE;

    while (*p)
    {
        const WCHAR *a = p, *b = keyW;

        while (b[0] && a[0] && a[0] == b[0]) { a++; b++; }
        if (!b[0])                                          /* key matched, a = value */
        {
            state = (a[0] && a[0] != '0') ? 1 : 2;
            return state == 1;
        }
        while (*p) p++;                                     /* next NUL-separated entry */
        p++;
    }
    state = 2;
    return FALSE;
}

/* ПРОВЕРКА САМОГО ПЕЧАТНИКА. Аномалия — гонка: по заказу не возникает, а строка
 * «ИТОГ … строк_кольца» существует именно для того, чтобы 192 строки нельзя было
 * прочесть как 192 события. Проверять её на глаз — это снова догадка. Гейт
 * MACRUNNER_HB_CS_ANOMALY_TEST=1 зовёт печатника один раз на 20-й учтённой операции,
 * когда в кольце уже есть записи. Окружение читается ТЕМ ЖЕ ручным обходом без
 * замка: обычное чтение здесь входит повторно и роняет процесс (см. выше). */
/* Два гейта для ДОКАЗАТЕЛЬСТВА поправки на базу (см. macrunner_hb_cs_hold_add).
 *   MACRUNNER_HB_CS_BAZA_TEST=1  — пропустить ПЕРВЫЙ вход по каждой паре
 *                                  «поток+секция»: это и есть «начал считать с
 *                                  середины», то самое условие из выдачи ABZU;
 *   MACRUNNER_HB_CS_NO_BAZA=1    — отключить поправку (прежнее поведение).
 * Парный замер на ОДНОМ двоичном файле: с поправкой аномалий быть не должно,
 * без неё — должны появиться. Иначе поправка недоказана. */
static BOOL macrunner_hb_cs_env_flag( const WCHAR *keyW )
{
    const WCHAR *p;
    PEB *peb = NtCurrentTeb()->Peb;

    if (!peb || !peb->ProcessParameters) return FALSE;
    p = peb->ProcessParameters->Environment;
    if (!p) return FALSE;
    while (*p)
    {
        const WCHAR *a = p, *b = keyW;

        while (b[0] && a[0] && a[0] == b[0]) { a++; b++; }
        if (!b[0]) return a[0] && a[0] != '0';
        while (*p) p++;
        p++;
    }
    return FALSE;
}

static BOOL macrunner_hb_cs_baza_test_enabled(void)
{
    static LONG state;
    static const WCHAR keyW[] =
        {'M','A','C','R','U','N','N','E','R','_','H','B','_','C','S','_',
         'B','A','Z','A','_','T','E','S','T','=',0};
    if (!state) state = macrunner_hb_cs_env_flag( keyW ) ? 1 : 2;
    return state == 1;
}

static BOOL macrunner_hb_cs_no_baza(void)
{
    static LONG state;
    static const WCHAR keyW[] =
        {'M','A','C','R','U','N','N','E','R','_','H','B','_','C','S','_',
         'N','O','_','B','A','Z','A','=',0};
    if (!state) state = macrunner_hb_cs_env_flag( keyW ) ? 1 : 2;
    return state == 1;
}

static BOOL macrunner_hb_cs_anomaly_test_enabled(void)
{
    static LONG state;
    static const WCHAR keyW[] =
        {'M','A','C','R','U','N','N','E','R','_','H','B','_','C','S','_',
         'A','N','O','M','A','L','Y','_','T','E','S','T','=',0};
    LONG current = state;
    const WCHAR *p;
    PEB *peb;

    if (current) return current == 1;

    peb = NtCurrentTeb()->Peb;
    if (!peb || !peb->ProcessParameters) return FALSE;
    p = peb->ProcessParameters->Environment;
    if (!p) return FALSE;

    while (*p)
    {
        const WCHAR *a = p, *b = keyW;

        while (b[0] && a[0] && a[0] == b[0]) { a++; b++; }
        if (!b[0])
        {
            state = (a[0] && a[0] != '0') ? 1 : 2;
            return state == 1;
        }
        while (*p) p++;
        p++;
    }
    state = 2;
    return FALSE;
}

/* Process gate.  wineboot / regedit / services are SEPARATE processes that load the
 * same ntdll, and wine hands out TIDs per process — so a regedit thread can carry the
 * very same 0x00a4 id as the guest main thread.  Instrumenting them drowned the
 * registry import (99% CPU, no game).  Only ever observe the game process. */
/* ★ 01.09.2026: имя мишени было ЗАШИТО как "abzugame". ABZU — 64-битная UE4 через
 * путь ARM64EC, у нас она сегодня вовсе не стартует, а значит вся ветка наблюдения
 * за ожиданием мертва для действующих мишеней (Diablo, UT99, Heroes III).
 * Имя теперь задаётся через MACRUNNER_HB_HEAP_CS_TARGET; умолчание оставлено
 * прежним, чтобы старые прогоны не изменились. Защита нужна: наблюдение за
 * wineboot/regedit/services топило импорт реестра (99 % ЦП, игра не стартовала). */
static BOOL macrunner_hb_heap_cs_target_process(void)
{
    static LONG state;
    static WCHAR targetW[32] = {'a','b','z','u','g','a','m','e',0};
    static LONG target_read;
    LONG current = state;

    if (!InterlockedCompareExchange( &target_read, 1, 0 ))
    {
        static const WCHAR keyW[] =
            {'M','A','C','R','U','N','N','E','R','_','H','B','_','H','E','A','P','_',
             'C','S','_','T','A','R','G','E','T','=',0};
        PEB *peb = NtCurrentTeb()->Peb;
        const WCHAR *e = (peb && peb->ProcessParameters)
                       ? peb->ProcessParameters->Environment : NULL;
        while (e && *e)
        {
            const WCHAR *a = e, *b = keyW;

            while (b[0] && a[0] && a[0] == b[0]) { a++; b++; }
            if (!b[0] && a[0])
            {
                unsigned int i = 0;
                while (a[i] && i < 31) { targetW[i] = a[i] | 0x20; i++; }
                targetW[i] = 0;
                break;
            }
            while (*e) e++;
            e++;
        }
    }
    const UNICODE_STRING *img;
    const WCHAR *p, *end;
    PEB *peb;

    if (current > 0) return current == 1;

    peb = NtCurrentTeb()->Peb;
    if (!peb || !peb->ProcessParameters) return FALSE;      /* not ready: do not latch */
    img = &peb->ProcessParameters->ImagePathName;
    if (!img->Buffer || !img->Length) return FALSE;

    end = img->Buffer + img->Length / sizeof(WCHAR);
    for (p = img->Buffer; p < end; p++)
    {
        const WCHAR *a = p, *b = targetW;

        while (b[0] && a < end && (a[0] | 0x20) == b[0]) { a++; b++; }
        if (!b[0]) { state = 1; return TRUE; }
    }
    state = 2;
    return FALSE;
}

/* Do NOT gate on a TID: the guest TIDs are not stable across runs (0xa4/0xa8 in one
 * run, 0x9c/0xa0 in the next), so a hardcoded pair silently observes nothing.  And do
 * NOT stream every ENTER/LEAVE either: the process heap CS is taken on every
 * allocation, so any first-N budget burns long before the deadlock.
 *
 * Instead keep O(1) state: who currently HOLDS each tracked section (with the caller
 * PC that acquired it), plus per-section-pointer enter/leave counters.  On contention
 * we dump the holder — that is exactly the crux: the acquire PC of the thread that is
 * sitting on the lock.  The counters are the (a)/(b) discriminator: a second, distinct
 * section pointer with leaves != enters would mean Enter and Leave hit two different
 * EC/native views of the same logical CS. */
/* ARM64X ships TWO code bodies of this file — the native aarch64 one and the arm64ec one
 * (the guest reaches the latter through HB's native import dispatch).  Each body has its
 * own copy of the statics below, so an acquire made through the other view is invisible
 * here — which would look exactly like the CS fields moving with no call.  Tag every line
 * with the view so the log settles it. */
#ifdef __arm64ec__
# define MACRUNNER_HB_CS_VIEW "EC"
#else
# define MACRUNNER_HB_CS_VIEW "NATIVE"
#endif

#define MACRUNNER_HB_CS_HOLD_SLOTS 64
#define MACRUNNER_HB_CS_STAT_SLOTS 8

struct macrunner_hb_cs_hold
{
    LONG  tid;
    void *crit;
    void *caller;
    LONG  depth;
    LONG  baza;      /* насколько секция была занята ДО того, как мы начали считать */
};
static struct macrunner_hb_cs_hold macrunner_hb_cs_holds[MACRUNNER_HB_CS_HOLD_SLOTS];

struct macrunner_hb_cs_stat
{
    void *crit;
    LONG  enters;
    LONG  leaves;
};
static struct macrunner_hb_cs_stat macrunner_hb_cs_stats[MACRUNNER_HB_CS_STAT_SLOTS];

static struct macrunner_hb_cs_stat *macrunner_hb_cs_stat_for( void *crit )
{
    int i;

    for (i = 0; i < MACRUNNER_HB_CS_STAT_SLOTS; i++)
    {
        if (macrunner_hb_cs_stats[i].crit == crit) return &macrunner_hb_cs_stats[i];
        if (!macrunner_hb_cs_stats[i].crit &&
            !InterlockedCompareExchangePointer( &macrunner_hb_cs_stats[i].crit, crit, NULL ))
            return &macrunner_hb_cs_stats[i];
        if (macrunner_hb_cs_stats[i].crit == crit) return &macrunner_hb_cs_stats[i];
    }
    return NULL;
}

/* ★★★ MacRunner 2026-09-01 — БАЗА УДЕРЖАНИЯ, иначе прибор врёт ровно на единицу.
 *
 * Постоянное удержание кучи глубиной 1 устанавливается РАНО (см. примечание к
 * кольцу head ниже), задолго до того, как наблюдатель начинает считать. Поэтому его
 * глубина навсегда меньше настоящей на столько, на сколько секция уже была занята,
 * и условие `RecursionCount != depth` срабатывает на исправном коде.
 *
 * Историческая выдача (ABZU, 13.07): все три «аномалии» расходились РОВНО на 1 —
 * `our_depth=1 BUT rec=2`, `our_depth=0 BUT rec=1`, один поток, одна секция, а в
 * кольце по ней здоровые пары ENTER/LEAVE. Это была не гонка, а начало счёта с
 * середины. Теперь при первом появлении пары «поток+секция» запоминаем базу и
 * сравниваем с её учётом; ложная тревога такого рода стала невозможна.
 *
 * return: собственная глубина после операции; *baza — уже занятая до нас глубина. */
static LONG macrunner_hb_cs_hold_add( LONG tid, void *crit, void *caller, LONG rec, LONG *baza )
{
    int i;

    *baza = 0;
    for (i = 0; i < MACRUNNER_HB_CS_HOLD_SLOTS; i++)
    {
        struct macrunner_hb_cs_hold *h = &macrunner_hb_cs_holds[i];

        if (h->tid == tid && h->crit == crit) { *baza = h->baza; return ++h->depth; }
    }
    for (i = 0; i < MACRUNNER_HB_CS_HOLD_SLOTS; i++)
    {
        struct macrunner_hb_cs_hold *h = &macrunner_hb_cs_holds[i];

        if (!InterlockedCompareExchange( &h->tid, tid, 0 ))
        {
            h->crit = crit;
            h->caller = caller;
            h->depth = 1;
            h->baza = (rec > 1 && !macrunner_hb_cs_no_baza()) ? rec - 1 : 0;
            *baza = h->baza;
            /* Ненулевая база — это и есть причина прежних «аномалий» на единицу.
             * Печатаем один раз на пару, чтобы утверждение опиралось на прогон. */
            if (h->baza)
                MESSAGE( "macrunner-hb-heap-cs-observer: %s tid=%04lx section=%p %s=%ld rec=%ld\n",
                         "БАЗА", tid, crit, "база", h->baza, rec );
            return 1;
        }
    }
    return -1;                                   /* table full */
}

static LONG macrunner_hb_cs_hold_del( LONG tid, void *crit, LONG *baza )
{
    int i;

    *baza = 0;
    for (i = 0; i < MACRUNNER_HB_CS_HOLD_SLOTS; i++)
    {
        struct macrunner_hb_cs_hold *h = &macrunner_hb_cs_holds[i];

        if (h->tid == tid && h->crit == crit)
        {
            LONG left = --h->depth;

            *baza = h->baza;

            if (left <= 0)
            {
                h->crit = NULL;
                h->caller = NULL;
                InterlockedExchange( &h->tid, 0 );
            }
            return left;
        }
    }
    return -1;                                   /* leave without a recorded enter */
}

/* RECORDING must not depend on the PEB.  The env/image gates only become true once
 * ProcessParameters exist, and the acquisition we are hunting happens BEFORE that: an
 * early, un-latched ENTER is invisible, and if it is never left the ledger still looks
 * balanced while the lock stays held — exactly what run g/h showed (heap enters ==
 * leaves, no hold record, yet OwningThread=main, RecursionCount=1).  So: record from
 * the very first critical-section op, using nothing but the section name and atomics;
 * gate only the PRINTING (below) on the env/process checks.  The tables are per-process
 * statics, so recording inside wineboot/regedit costs a few atomics and prints nothing. */
static BOOL macrunner_hb_heap_cs_tracked( RTL_CRITICAL_SECTION *crit, const char **name )
{
    if (!crit) return FALSE;
    *name = crit_section_get_name( crit );
    if (!*name) return FALSE;
    return strstr( *name, "main process heap section" ) || strstr( *name, "loader_section" );
}

/* Ring of the last N ops on the tracked sections, with the lock fields sampled BEFORE
 * and AFTER each one, plus per-TID counters.  The global ledger cannot see a
 * cross-thread skew (main enters once more, another thread leaves once more => sum
 * balances while the lock stays held), and it cannot see fields moving without a call.
 * Discriminator:
 *   OwningThread changes with no Enter between two samples  => direct memory corruption
 *   LockCount / RecursionCount inconsistent with the calls  => race on the same CS */
#define MACRUNNER_HB_CS_RING 64
#define MACRUNNER_HB_CS_TID_SLOTS 32

/* One sample per hook call.  *_REQ fires BEFORE the mutation, *_OK AFTER it, so a pair
 * gives before/after; and if the fields differ between an *_OK and the NEXT *_REQ on the
 * same section, they moved with no call in between => the CS memory is being written
 * from outside the CS API. */
struct macrunner_hb_cs_event
{
    LONG  seq;
    LONG  tid;
    const char *phase;
    void *crit;
    void *caller;
    LONG  lock, rec, own;
};
static struct macrunner_hb_cs_event macrunner_hb_cs_ring[MACRUNNER_HB_CS_RING];
static LONG macrunner_hb_cs_ring_seq;

/* The permanent depth-1 hold on the process heap is established EARLY, long before the
 * tail ring window.  Keep the first ops too: that is where rec goes 0 -> 1 and never
 * comes back, and the caller PC there is the answer. */
#define MACRUNNER_HB_CS_HEAD 96
static struct macrunner_hb_cs_event macrunner_hb_cs_head[MACRUNNER_HB_CS_HEAD];

struct macrunner_hb_cs_tidstat
{
    LONG tid;
    LONG enters;
    LONG leaves;
};
static struct macrunner_hb_cs_tidstat macrunner_hb_cs_tidstats[MACRUNNER_HB_CS_TID_SLOTS];

static struct macrunner_hb_cs_tidstat *macrunner_hb_cs_tidstat_for( LONG tid )
{
    int i;

    for (i = 0; i < MACRUNNER_HB_CS_TID_SLOTS; i++)
    {
        if (macrunner_hb_cs_tidstats[i].tid == tid) return &macrunner_hb_cs_tidstats[i];
        if (!macrunner_hb_cs_tidstats[i].tid &&
            !InterlockedCompareExchange( &macrunner_hb_cs_tidstats[i].tid, tid, 0 ))
            return &macrunner_hb_cs_tidstats[i];
        if (macrunner_hb_cs_tidstats[i].tid == tid) return &macrunner_hb_cs_tidstats[i];
    }
    return NULL;
}

/* Self-triggering trap: fires at the exact op where the lock fields stop agreeing with
 * the call sequence.  Dumps the ring so the preceding ops (and their caller PCs) are
 * visible.  One-shot-ish (cap 3) and reentrancy-guarded — it runs on the CS hot path. */
static void macrunner_hb_cs_anomaly( const char *phase, RTL_CRITICAL_SECTION *crit,
                                     void *caller, LONG tid, LONG depth )
{
    static LONG fired, printing;
    LONG total, first, s, nomer, strok = 0;

    /* 2026-09-01: прибор печатает ДО 64 строк кольца на ОДНО событие.  Читая журнал,
     * я принял 192 строки за 192 аномалии — их было три.  Ошибка не в глазах: прибор
     * нигде не называл ни свой порядковый номер, ни длину своей выдачи.  Теперь
     * называет и то и другое, и счёт строк больше не выдаёт себя за счёт событий. */
    nomer = InterlockedIncrement( &fired );
    if (nomer > 3) return;
    if (InterlockedCompareExchange( &printing, 1, 0 )) return;

    MESSAGE( "macrunner-hb-heap-cs-observer: *** ANOMALY *** %s=%ld/3 view=%s %s "
         "tid=%04lx section=%p caller=%p our_depth=%ld  BUT lock=%ld rec=%ld own=%04lx\n",
         "аномалия", nomer, MACRUNNER_HB_CS_VIEW, phase, tid, crit, caller, depth,
         crit->LockCount, crit->RecursionCount,
         (LONG)HandleToULong( crit->OwningThread ) );

    total = macrunner_hb_cs_ring_seq;
    first = total > MACRUNNER_HB_CS_RING ? total - MACRUNNER_HB_CS_RING + 1 : 1;
    for (s = first; s <= total; s++)
    {
        struct macrunner_hb_cs_event *e = &macrunner_hb_cs_ring[(s - 1) % MACRUNNER_HB_CS_RING];

        if (e->seq != s) continue;
        MESSAGE( "macrunner-hb-heap-cs-observer:   ANOM-RING view=%s seq=%ld tid=%04lx %s section=%p "
             "lock=%ld rec=%ld own=%04lx caller=%p\n",
             MACRUNNER_HB_CS_VIEW, e->seq, e->tid, e->phase, e->crit, e->lock, e->rec, e->own,
             e->caller );
        strok++;
    }
    /* Итог СВОЕЙ выдачи — чтобы «строк в журнале» нельзя было прочесть как «событий». */
    MESSAGE( "macrunner-hb-heap-cs-observer: %s %s=%ld/3 %s=%ld (%s=%ld, %s %ld)\n",
         "ИТОГ", "аномалия", nomer, "строк_кольца", strok,
         "событий", nomer, "НЕ", strok + 1 );
    InterlockedExchange( &printing, 0 );
}

static void macrunner_hb_heap_cs_observe( const char *phase, RTL_CRITICAL_SECTION *crit,
                                          void *caller )
{
    struct macrunner_hb_cs_tidstat *ts;
    struct macrunner_hb_cs_stat *stat;
    struct macrunner_hb_cs_event *ev;
    const char *name;
    LONG tid, seq, depth, baza = 0;
    BOOL done;

    /* Проверка печатника — см. macrunner_hb_cs_anomaly_test_enabled выше. */
    if (macrunner_hb_cs_anomaly_test_enabled())
    {
        static LONG uchtjono, probano;
        if (InterlockedIncrement( &uchtjono ) >= 20 &&
            !InterlockedCompareExchange( &probano, 1, 0 ))
            macrunner_hb_cs_anomaly( "PROBA_OK", crit, caller,
                                     (LONG)GetCurrentThreadId(), 7 );
    }

    if (!macrunner_hb_heap_cs_tracked( crit, &name )) return;
    if (phase[0] != 'E' && phase[0] != 'L') return;
    done = (phase[6] == 'O');                    /* ENTER_OK / LEAVE_OK vs *_REQ */


    tid = (LONG)GetCurrentThreadId();

    /* sample the fields FIRST — for *_REQ this is the true "before" */
    seq = InterlockedIncrement( &macrunner_hb_cs_ring_seq );
    ev = &macrunner_hb_cs_ring[(seq - 1) % MACRUNNER_HB_CS_RING];
    ev->seq    = seq;
    ev->tid    = tid;
    ev->phase  = phase;
    ev->crit   = crit;
    ev->caller = caller;
    ev->lock   = crit->LockCount;
    ev->rec    = crit->RecursionCount;
    ev->own    = (LONG)HandleToULong( crit->OwningThread );

    if (seq <= MACRUNNER_HB_CS_HEAD) macrunner_hb_cs_head[seq - 1] = *ev;

    if (!done) return;                           /* counters only on the completed op */

    stat = macrunner_hb_cs_stat_for( crit );
    ts = macrunner_hb_cs_tidstat_for( tid );

    /* Испытание поправки: пропускаем ПЕРВЫЙ вход по паре, имитируя поздний старт. */
    if (phase[0] == 'E' && done && macrunner_hb_cs_baza_test_enabled())
    {
        static struct { LONG tid; void *crit; } propushcheno[16];
        int i;

        for (i = 0; i < 16; i++)
            if (propushcheno[i].tid == tid && propushcheno[i].crit == crit) break;
        if (i == 16)
        {
            for (i = 0; i < 16; i++)
                if (!InterlockedCompareExchange( &propushcheno[i].tid, tid, 0 ))
                {
                    propushcheno[i].crit = crit;
                    return;                       /* первый вход НЕ учитываем */
                }
        }
    }

    if (phase[0] == 'E')
    {
        if (stat) InterlockedIncrement( &stat->enters );
        if (ts) InterlockedIncrement( &ts->enters );
        depth = macrunner_hb_cs_hold_add( tid, crit, caller, crit->RecursionCount, &baza );

        /* after a completed Enter the lock must reflect our depth ПЛЮС базу */
        if (depth > 0 && (crit->RecursionCount != depth + baza ||
                          (LONG)HandleToULong( crit->OwningThread ) != tid))
            macrunner_hb_cs_anomaly( "ENTER_OK", crit, caller, tid, depth );
    }
    else
    {
        if (stat) InterlockedIncrement( &stat->leaves );
        if (ts) InterlockedIncrement( &ts->leaves );
        depth = macrunner_hb_cs_hold_del( tid, crit, &baza );

        /* ★★★ MacRunner 2026-08-29 — ПРОВЕРКА БЫЛА НЕВЕРНА ПО СУЩЕСТВУ.
         *
         * Прежнее условие исходило из «мы отпустили последнюю рекурсию => секция
         * ОБЯЗАНА быть свободна». Это не так: как только LeaveCriticalSection
         * обнулила OwningThread и уменьшила LockCount, ЛЮБОЙ другой поток вправе
         * немедленно захватить секцию. Наблюдатель же читает поля ПОСЛЕ этого
         * момента и видит законного нового владельца.
         *
         * Прибор выдал ровно такую последовательность и был принят за гонку:
         *   seq=12060 tid=013c LEAVE_REQ own=013c
         *   seq=12061 tid=0138 ENTER_OK  own=0138   <- законный захват
         *   seq=12062 tid=013c LEAVE_OK  own=0138   <- «аномалия»
         * Полдня ушло бы на поиск несуществующей гонки в куче ntdll.
         *
         * Настоящая аномалия здесь только одна: секция ещё числится за НАМИ,
         * хотя мы вышли из последней рекурсии. Чужой владелец — не наше дело. */
        if (depth == 0 && baza == 0 &&
            (LONG)HandleToULong( crit->OwningThread ) == tid)
            macrunner_hb_cs_anomaly( "LEAVE_OK", crit, caller, tid, depth );
    }
}

static void macrunner_hb_heap_cs_observe_wait( RTL_CRITICAL_SECTION *crit, void *caller );

/* ARM64EC uses x18 as the TEB platform register, while the diagnostic observer can
 * cross into host C code which follows the macOS ABI and does not preserve x18.
 * Keep the save value live across the complete helper call; restoring only at the
 * outer PE-call bridge is too early for observer calls made from inside PE code. */
#if defined(__aarch64__) || defined(__arm64ec__)
static inline ULONG_PTR macrunner_hb_save_teb_x18(void)
{
    ULONG_PTR teb;

    __asm__ volatile( "mov %0, x18" : "=r" (teb) : : "memory" );
    return teb;
}

static inline void macrunner_hb_restore_teb_x18( ULONG_PTR teb )
{
    __asm__ volatile( "mov x18, %0" : : "r" (teb) : "x18", "memory" );
}

static void macrunner_hb_heap_cs_observe_preserving_x18( const char *phase,
                                                          RTL_CRITICAL_SECTION *crit,
                                                          void *caller )
{
    ULONG_PTR teb = macrunner_hb_save_teb_x18();

    macrunner_hb_heap_cs_observe( phase, crit, caller );
    macrunner_hb_restore_teb_x18( teb );
}

static void macrunner_hb_heap_cs_observe_wait_preserving_x18( RTL_CRITICAL_SECTION *crit,
                                                               void *caller )
{
    ULONG_PTR teb = macrunner_hb_save_teb_x18();

    macrunner_hb_heap_cs_observe_wait( crit, caller );
    macrunner_hb_restore_teb_x18( teb );
}
#else
#define macrunner_hb_heap_cs_observe_preserving_x18 macrunner_hb_heap_cs_observe
#define macrunner_hb_heap_cs_observe_wait_preserving_x18 macrunner_hb_heap_cs_observe_wait
#endif

/* Contention capture — this is where the crux is answered.  Print the waiter, then the
 * HOLDER's acquire caller PC (from the hold table), then the enter/leave ledger for
 * every section pointer we have seen. */
static void macrunner_hb_heap_cs_observe_wait( RTL_CRITICAL_SECTION *crit, void *caller )
{
    static LONG waits, printing;
    const char *name;
    LONG owner, seq;
    int i;

    if (!macrunner_hb_heap_cs_tracked( crit, &name )) return;
    if (!macrunner_hb_heap_cs_observer_enabled()) return;   /* printing is gated, not recording */
    if (!macrunner_hb_heap_cs_target_process()) return;
    if (InterlockedCompareExchange( &printing, 1, 0 )) return;
    seq = InterlockedIncrement( &waits );
    if (seq > 200) { InterlockedExchange( &printing, 0 ); return; }

    owner = (LONG)HandleToULong( crit->OwningThread );
    /* state=%p exposes an ARM64X dual-.data split: if two threads print different
     * table addresses, the native and EC views have separate copies of this state —
     * which is hypothesis (b), mixed EC/native view, in its purest form. */
    MESSAGE( "macrunner-hb-heap-cs-observer: seq=%ld phase=WAIT_BLOCK tid=%04lx caller=%p "
         "section=%p name=%s lock=%ld recursion=%ld owner=%04lx state=%p\n",
         seq, GetCurrentThreadId(), caller, crit, name,
         crit->LockCount, crit->RecursionCount, owner, macrunner_hb_cs_stats );

    for (i = 0; i < MACRUNNER_HB_CS_HOLD_SLOTS; i++)
    {
        struct macrunner_hb_cs_hold *h = &macrunner_hb_cs_holds[i];

        if (!h->tid || !h->crit) continue;
        MESSAGE( "macrunner-hb-heap-cs-observer:   HOLD tid=%04lx section=%p depth=%ld "
             "acquired_at=%p%s\n", h->tid, h->crit, h->depth, h->caller,
             h->tid == owner ? "   <== BLOCKER" : "" );
    }
    for (i = 0; i < MACRUNNER_HB_CS_STAT_SLOTS; i++)
    {
        struct macrunner_hb_cs_stat *s = &macrunner_hb_cs_stats[i];

        if (!s->crit) continue;
        MESSAGE( "macrunner-hb-heap-cs-observer:   LEDGER section=%p enters=%ld leaves=%ld "
             "unmatched=%ld\n", s->crit, s->enters, s->leaves, s->enters - s->leaves );
    }
    /* per-TID: the global ledger balances even when one thread entered once more and
     * another left once more — that skew only shows up here */
    for (i = 0; i < MACRUNNER_HB_CS_TID_SLOTS; i++)
    {
        struct macrunner_hb_cs_tidstat *t = &macrunner_hb_cs_tidstats[i];

        if (!t->tid) continue;
        MESSAGE( "macrunner-hb-heap-cs-observer:   PERTID tid=%04lx enters=%ld leaves=%ld "
             "skew=%ld\n", t->tid, t->enters, t->leaves, t->enters - t->leaves );
    }
    /* FIRST ops — where the permanent hold is born */
    {
        LONG total = macrunner_hb_cs_ring_seq;
        LONG n = total < MACRUNNER_HB_CS_HEAD ? total : MACRUNNER_HB_CS_HEAD;

        for (i = 0; i < n; i++)
        {
            struct macrunner_hb_cs_event *e = &macrunner_hb_cs_head[i];

            if (!e->seq) continue;
            MESSAGE( "macrunner-hb-heap-cs-observer:   HEAD seq=%ld tid=%04lx %s section=%p "
                 "lock=%ld rec=%ld own=%04lx caller=%p\n",
                 e->seq, e->tid, e->phase, e->crit, e->lock, e->rec, e->own, e->caller );
        }
    }
    /* last ops, oldest first */
    {
        LONG total = macrunner_hb_cs_ring_seq;
        LONG first = total > MACRUNNER_HB_CS_RING ? total - MACRUNNER_HB_CS_RING + 1 : 1;
        LONG s, strok = 0;

        for (s = first; s <= total; s++)
        {
            struct macrunner_hb_cs_event *e =
                &macrunner_hb_cs_ring[(s - 1) % MACRUNNER_HB_CS_RING];

            if (e->seq != s) continue;           /* overwritten mid-dump */
            MESSAGE( "macrunner-hb-heap-cs-observer:   RING seq=%ld tid=%04lx %s section=%p "
                 "lock=%ld rec=%ld own=%04lx caller=%p\n",
                 e->seq, e->tid, e->phase, e->crit, e->lock, e->rec, e->own, e->caller );
            strok++;
        }
        /* Своё число — иначе строки журнала читаются как события. Тот же изъян
         * уже стоил разбора: 192 строки были приняты за 192 аномалии. */
        MESSAGE( "macrunner-hb-heap-cs-observer: %s %s=%ld/200 %s=%ld (%s=%ld, %s %ld)\n",
             "ИТОГ", "ожидание", seq, "строк_кольца", strok,
             "событий", seq, "НЕ", strok );
    }
    InterlockedExchange( &printing, 0 );
}

static const char *debugstr_timeout( const LARGE_INTEGER *timeout )
{
    if (!timeout) return "(infinite)";
    return wine_dbgstr_longlong( timeout->QuadPart );
}

/******************************************************************
 *              RtlRunOnceInitialize (NTDLL.@)
 */
void WINAPI RtlRunOnceInitialize( RTL_RUN_ONCE *once )
{
    once->Ptr = NULL;
}

/******************************************************************
 *              RtlRunOnceBeginInitialize (NTDLL.@)
 */
DWORD WINAPI RtlRunOnceBeginInitialize( RTL_RUN_ONCE *once, ULONG flags, void **context )
{
    if (flags & RTL_RUN_ONCE_CHECK_ONLY)
    {
        ULONG_PTR val = (ULONG_PTR)ReadPointerAcquire( &once->Ptr );

        if (flags & RTL_RUN_ONCE_ASYNC) return STATUS_INVALID_PARAMETER;
        if ((val & 3) != 2) return STATUS_UNSUCCESSFUL;
        if (context) *context = (void *)(val & ~3);
        return STATUS_SUCCESS;
    }

    for (;;)
    {
        ULONG_PTR next, val = (ULONG_PTR)ReadPointerAcquire( &once->Ptr );

        switch (val & 3)
        {
        case 0:  /* first time */
            if (!InterlockedCompareExchangePointer( &once->Ptr,
                                                    (flags & RTL_RUN_ONCE_ASYNC) ? (void *)3 : (void *)1, 0 ))
                return STATUS_PENDING;
            break;

        case 1:  /* in progress, wait */
            if (flags & RTL_RUN_ONCE_ASYNC) return STATUS_INVALID_PARAMETER;
            next = val & ~3;
            if (InterlockedCompareExchangePointer( &once->Ptr, (void *)((ULONG_PTR)&next | 1),
                                                   (void *)val ) == (void *)val)
                NtWaitForKeyedEvent( 0, &next, FALSE, NULL );
            break;

        case 2:  /* done */
            if (context) *context = (void *)(val & ~3);
            return STATUS_SUCCESS;

        case 3:  /* in progress, async */
            if (!(flags & RTL_RUN_ONCE_ASYNC)) return STATUS_INVALID_PARAMETER;
            return STATUS_PENDING;
        }
    }
}

/******************************************************************
 *              RtlRunOnceComplete (NTDLL.@)
 */
DWORD WINAPI RtlRunOnceComplete( RTL_RUN_ONCE *once, ULONG flags, void *context )
{
    if ((ULONG_PTR)context & 3) return STATUS_INVALID_PARAMETER;

    if (flags & RTL_RUN_ONCE_INIT_FAILED)
    {
        if (context) return STATUS_INVALID_PARAMETER;
        if (flags & RTL_RUN_ONCE_ASYNC) return STATUS_INVALID_PARAMETER;
    }
    else context = (void *)((ULONG_PTR)context | 2);

    for (;;)
    {
        ULONG_PTR val = (ULONG_PTR)ReadPointerAcquire( &once->Ptr );

        switch (val & 3)
        {
        case 1:  /* in progress */
            if (InterlockedCompareExchangePointer( &once->Ptr, context, (void *)val ) != (void *)val) break;
            val &= ~3;
            while (val)
            {
                ULONG_PTR next = *(ULONG_PTR *)val;
                NtReleaseKeyedEvent( 0, (void *)val, FALSE, NULL );
                val = next;
            }
            return STATUS_SUCCESS;

        case 3:  /* in progress, async */
            if (!(flags & RTL_RUN_ONCE_ASYNC)) return STATUS_INVALID_PARAMETER;
            if (InterlockedCompareExchangePointer( &once->Ptr, context, (void *)val ) != (void *)val) break;
            return STATUS_SUCCESS;

        default:
            return STATUS_UNSUCCESSFUL;
        }
    }
}


/***********************************************************************
 * Critical sections
 ***********************************************************************/


static void *no_debug_info_marker = (void *)(ULONG_PTR)-1;

static BOOL crit_section_has_debuginfo( const RTL_CRITICAL_SECTION *crit )
{
    return crit->DebugInfo != NULL && crit->DebugInfo != no_debug_info_marker;
}

static const char *crit_section_get_name( const RTL_CRITICAL_SECTION *crit )
{
    if (crit_section_has_debuginfo( crit ))
        return (char *)crit->DebugInfo->Spare[0];
    return "?";
}

static inline HANDLE get_semaphore( RTL_CRITICAL_SECTION *crit )
{
    if ((ULONG_PTR)crit->LockSemaphore > 1) return crit->LockSemaphore;
    return NULL;
}

static inline NTSTATUS wait_semaphore( RTL_CRITICAL_SECTION *crit, int timeout )
{
    LARGE_INTEGER time = {.QuadPart = timeout * (LONGLONG)-10000000};
    HANDLE sem = get_semaphore( crit );

    if (sem) return NtWaitForSingleObject( sem, FALSE, &time );
    else
    {
        LONG *lock = (LONG *)&crit->LockSemaphore;
        while (!InterlockedCompareExchange( lock, 0, 1 ))
        {
            static const LONG zero;
            /* this may wait longer than specified in case of multiple wake-ups */
            if (RtlWaitOnAddress( lock, &zero, sizeof(LONG), &time ) == STATUS_TIMEOUT)
                return STATUS_TIMEOUT;
        }
        return STATUS_WAIT_0;
    }
}

static ULONG crit_sect_default_flags(void)
{
    if (NtCurrentTeb()->Peb->OSMajorVersion > 6 ||
        (NtCurrentTeb()->Peb->OSMajorVersion == 6 && NtCurrentTeb()->Peb->OSMinorVersion >= 2)) return 0;
    return RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO;
}

/******************************************************************************
 *      RtlInitializeCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlInitializeCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    return RtlInitializeCriticalSectionEx( crit, 0, crit_sect_default_flags() );
}


/******************************************************************************
 *      RtlInitializeCriticalSectionAndSpinCount   (NTDLL.@)
 */
NTSTATUS WINAPI RtlInitializeCriticalSectionAndSpinCount( RTL_CRITICAL_SECTION *crit, ULONG spincount )
{
    return RtlInitializeCriticalSectionEx( crit, spincount, crit_sect_default_flags() );
}


/******************************************************************************
 *      RtlInitializeCriticalSectionEx   (NTDLL.@)
 */
NTSTATUS WINAPI RtlInitializeCriticalSectionEx( RTL_CRITICAL_SECTION *crit, ULONG spincount, ULONG flags )
{
    if (flags & (RTL_CRITICAL_SECTION_FLAG_DYNAMIC_SPIN|RTL_CRITICAL_SECTION_FLAG_STATIC_INIT))
        FIXME("(%p,%lu,0x%08lx) semi-stub\n", crit, spincount, flags);

    /* FIXME: if RTL_CRITICAL_SECTION_FLAG_STATIC_INIT is given, we should use
     * memory from a static pool to hold the debug info. Then heap.c could pass
     * this flag rather than initialising the process heap CS by hand. If this
     * is done, then debug info should be managed through Rtlp[Allocate|Free]DebugInfo
     * so (e.g.) MakeCriticalSectionGlobal() doesn't free it using HeapFree().
     */
    if (!(flags & RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO))
        crit->DebugInfo = no_debug_info_marker;
    else
    {
        crit->DebugInfo = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(RTL_CRITICAL_SECTION_DEBUG ));
        if (crit->DebugInfo)
        {
            crit->DebugInfo->Type = 0;
            crit->DebugInfo->CreatorBackTraceIndex = 0;
            crit->DebugInfo->CriticalSection = crit;
            crit->DebugInfo->ProcessLocksList.Blink = &crit->DebugInfo->ProcessLocksList;
            crit->DebugInfo->ProcessLocksList.Flink = &crit->DebugInfo->ProcessLocksList;
            crit->DebugInfo->EntryCount = 0;
            crit->DebugInfo->ContentionCount = 0;
            memset( crit->DebugInfo->Spare, 0, sizeof(crit->DebugInfo->Spare) );
        }
    }
    crit->LockCount      = -1;
    crit->RecursionCount = 0;
    crit->OwningThread   = 0;
    crit->LockSemaphore  = 0;
    if (NtCurrentTeb()->Peb->NumberOfProcessors <= 1) spincount = 0;
    crit->SpinCount = spincount & ~0x80000000;
    return STATUS_SUCCESS;
}


/******************************************************************************
 *      RtlSetCriticalSectionSpinCount   (NTDLL.@)
 */
ULONG WINAPI RtlSetCriticalSectionSpinCount( RTL_CRITICAL_SECTION *crit, ULONG spincount )
{
    ULONG oldspincount = crit->SpinCount;
    if (NtCurrentTeb()->Peb->NumberOfProcessors <= 1) spincount = 0;
    crit->SpinCount = spincount;
    return oldspincount;
}


/******************************************************************************
 *      RtlDeleteCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlDeleteCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    HANDLE sem;

    crit->LockCount      = -1;
    crit->RecursionCount = 0;
    crit->OwningThread   = 0;
    if (crit_section_has_debuginfo( crit ))
    {
        /* only free the ones we made in here */
        if (!crit->DebugInfo->Spare[0])
        {
            RtlFreeHeap( GetProcessHeap(), 0, crit->DebugInfo );
            crit->DebugInfo = NULL;
        }
    }
    else crit->DebugInfo = NULL;

    if ((sem = get_semaphore( crit ))) NtClose( sem );
    crit->LockSemaphore = 0;
    return STATUS_SUCCESS;
}


/******************************************************************************
 *      RtlpWaitForCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlpWaitForCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    unsigned int timeout = 5;

    /* Don't allow blocking on a critical section during process termination */
    if (RtlDllShutdownInProgress())
    {
        WARN( "process %s is shutting down, returning STATUS_SUCCESS\n",
              debugstr_w(NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer) );
        return STATUS_SUCCESS;
    }

    for (;;)
    {
        NTSTATUS status = wait_semaphore( crit, timeout );

        if (status == STATUS_WAIT_0) break;
        if (status != WAIT_TIMEOUT) return status;

        /* Recover from orphaned state: no owner, and only this waiter left.
         * This can happen if a fault/async unwind interrupts lock acquisition
         * after LockCount increment but before OwningThread assignment. */
        if (!crit->OwningThread)
        {
            LONG lock_count = crit->LockCount;
            if (lock_count > 0 &&
                InterlockedCompareExchange( &crit->LockCount, 0, lock_count ) == lock_count)
            {
                WARN( "recovered orphan critical section %p %s in thread %04lx (lock_count=%ld)\n",
                      crit, debugstr_a(crit_section_get_name(crit)),
                      GetCurrentThreadId(), lock_count );
                break;
            }
        }

        timeout = (TRACE_ON(relay) ? 300 : 60);

        ERR( "section %p %s wait timed out in thread %04lx, blocked by %04lx, retrying (%u sec)\n",
             crit, debugstr_a(crit_section_get_name(crit)), GetCurrentThreadId(), HandleToULong(crit->OwningThread), timeout );
    }
    if (crit_section_has_debuginfo( crit )) crit->DebugInfo->ContentionCount++;
    return STATUS_SUCCESS;
}


/******************************************************************************
 *      RtlpUnWaitCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlpUnWaitCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    NTSTATUS ret;
    HANDLE sem = get_semaphore( crit );

    if (sem) ret = NtReleaseSemaphore( sem, 1, NULL );
    else
    {
        LONG *lock = (LONG *)&crit->LockSemaphore;
        InterlockedExchange( lock, 1 );
        RtlWakeAddressSingle( lock );
        ret = STATUS_SUCCESS;
    }
    if (ret) RtlRaiseStatus( ret );
    return ret;
}


/******************************************************************************
 *      RtlEnterCriticalSection   (NTDLL.@)
 */
/* raw acquire, no observation — RtlTryEnterCriticalSection wraps this and observes */
static BOOL macrunner_try_enter_crit( RTL_CRITICAL_SECTION *crit )
{
    BOOL ret = FALSE;

    if (InterlockedCompareExchange( &crit->LockCount, 0, -1 ) == -1)
    {
        crit->OwningThread   = ULongToHandle(GetCurrentThreadId());
        crit->RecursionCount = 1;
        ret = TRUE;
    }
    else if (crit->OwningThread == ULongToHandle(GetCurrentThreadId()))
    {
        InterlockedIncrement( &crit->LockCount );
        crit->RecursionCount++;
        ret = TRUE;
    }
    return ret;
}

NTSTATUS WINAPI RtlEnterCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    void *caller = __builtin_return_address( 0 );

    macrunner_hb_heap_cs_observe_preserving_x18( "ENTER_REQ", crit, caller );
    if (crit->SpinCount)
    {
        ULONG count;

        if (macrunner_try_enter_crit( crit ))
        {
            macrunner_hb_heap_cs_observe_preserving_x18( "ENTER_OK", crit, caller );
            return STATUS_SUCCESS;
        }
        for (count = crit->SpinCount; count > 0; count--)
        {
            if (crit->LockCount > 0) break;  /* more than one waiter, don't bother spinning */
            if (crit->LockCount == -1)       /* try again */
            {
                if (InterlockedCompareExchange( &crit->LockCount, 0, -1 ) == -1) goto done;
            }
            YieldProcessor();
        }
    }

    if (InterlockedIncrement( &crit->LockCount ))
    {
        NTSTATUS status;

        if (crit->OwningThread == ULongToHandle(GetCurrentThreadId()))
        {
            crit->RecursionCount++;
            macrunner_hb_heap_cs_observe_preserving_x18( "ENTER_OK", crit, caller );
            return STATUS_SUCCESS;
        }

        /* Now wait for it.
         * If wait fails (e.g. APC/interruption), undo the waiter increment
         * done above, otherwise the critical section can stay permanently
         * contended with OwningThread == 0. */
        macrunner_hb_heap_cs_observe_wait_preserving_x18( crit, caller );
        if ((status = RtlpWaitForCriticalSection( crit )))
        {
            InterlockedDecrement( &crit->LockCount );
            RtlRaiseStatus( status );
        }
    }
done:
    crit->OwningThread   = ULongToHandle(GetCurrentThreadId());
    crit->RecursionCount = 1;
    macrunner_hb_heap_cs_observe_preserving_x18( "ENTER_OK", crit, caller );
    return STATUS_SUCCESS;
}


/******************************************************************************
 *      RtlTryEnterCriticalSection   (NTDLL.@)
 */
BOOL WINAPI RtlTryEnterCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    void *caller = __builtin_return_address( 0 );
    BOOL ret = macrunner_try_enter_crit( crit );

    /* RtlEnterCriticalSection observes its own success (and uses the raw helper above,
     * so this does not double count).  This entry point is the OTHER writer of
     * OwningThread: an external caller of it is invisible to the Enter hook. */
    if (ret) macrunner_hb_heap_cs_observe_preserving_x18( "ENTER_OK", crit, caller );
    return ret;
}


/******************************************************************************
 *      RtlIsCriticalSectionLocked   (NTDLL.@)
 */
BOOL WINAPI RtlIsCriticalSectionLocked( RTL_CRITICAL_SECTION *crit )
{
    return crit->RecursionCount != 0;
}


/******************************************************************************
 *      RtlIsCriticalSectionLockedByThread   (NTDLL.@)
 */
BOOL WINAPI RtlIsCriticalSectionLockedByThread( RTL_CRITICAL_SECTION *crit )
{
    return crit->OwningThread == ULongToHandle(GetCurrentThreadId()) &&
           crit->RecursionCount;
}


/******************************************************************************
 *      RtlLeaveCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlLeaveCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    void *caller = __builtin_return_address( 0 );

    macrunner_hb_heap_cs_observe_preserving_x18( "LEAVE_REQ", crit, caller );
    if (--crit->RecursionCount)
    {
        if (crit->RecursionCount > 0) InterlockedDecrement( &crit->LockCount );
        else ERR( "section %p %s is not acquired\n", crit, debugstr_a( crit_section_get_name( crit )));
    }
    else
    {
        crit->OwningThread = 0;
        if (InterlockedDecrement( &crit->LockCount ) >= 0)
        {
            /* someone is waiting */
            RtlpUnWaitCriticalSection( crit );
        }
    }
    macrunner_hb_heap_cs_observe_preserving_x18( "LEAVE_OK", crit, caller );
    return STATUS_SUCCESS;
}

/******************************************************************
 *              RtlRunOnceExecuteOnce (NTDLL.@)
 */
DWORD WINAPI RtlRunOnceExecuteOnce( RTL_RUN_ONCE *once, PRTL_RUN_ONCE_INIT_FN func,
                                    void *param, void **context )
{
    DWORD ret = RtlRunOnceBeginInitialize( once, 0, context );

    if (ret != STATUS_PENDING) return ret;

    if (!func( once, param, context ))
    {
        RtlRunOnceComplete( once, RTL_RUN_ONCE_INIT_FAILED, NULL );
        return STATUS_UNSUCCESSFUL;
    }

    return RtlRunOnceComplete( once, 0, context ? *context : NULL );
}

struct srw_lock
{
    /* bit 0 - if the lock is held exclusive. bit 1.. - number of exclusive waiters. */
    short exclusive_waiters;

    /* Number of owners.
     *
     * Sadly Windows has no equivalent to FUTEX_WAIT_BITSET, so in order to wake
     * up *only* exclusive or *only* shared waiters (and thus avoid spurious
     * wakeups), we need to wait on two different addresses.
     * RtlAcquireSRWLockShared() needs to know the values of "exclusive_waiters"
     * and "owners", but RtlAcquireSRWLockExclusive() only needs to know the
     * value of "owners", so the former can wait on the entire structure, and
     * the latter waits only on the "owners" member. Note then that "owners"
     * must not be the first element in the structure.
     */
    unsigned short owners;
};
C_ASSERT( sizeof(struct srw_lock) == 4 );

/***********************************************************************
 *              RtlInitializeSRWLock (NTDLL.@)
 *
 * NOTES
 *  Please note that SRWLocks do not keep track of the owner of a lock.
 *  It doesn't make any difference which thread for example unlocks an
 *  SRWLock (see corresponding tests). This implementation uses two
 *  keyed events (one for the exclusive waiters and one for the shared
 *  waiters) and is limited to 2^15-1 waiting threads.
 */
void WINAPI RtlInitializeSRWLock( RTL_SRWLOCK *lock )
{
    lock->Ptr = NULL;
}

/***********************************************************************
 *              RtlAcquireSRWLockExclusive (NTDLL.@)
 *
 * NOTES
 *  Unlike RtlAcquireResourceExclusive this function doesn't allow
 *  nested calls from the same thread. "Upgrading" a shared access lock
 *  to an exclusive access lock also doesn't seem to be supported.
 */
void WINAPI RtlAcquireSRWLockExclusive( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };

    InterlockedExchangeAdd16( &u.s->exclusive_waiters, 2 );

    for (;;)
    {
        union { struct srw_lock s; LONG l; } old, new;
        BOOL wait;

        do
        {
            old.s = *u.s;
            new.s = old.s;

            if (!old.s.owners)
            {
                /* Not locked exclusive or shared. We can try to grab it. */
                new.s.owners = 1;
                new.s.exclusive_waiters -= 2;
                new.s.exclusive_waiters |= 1;
                wait = FALSE;
            }
            else
            {
                wait = TRUE;
            }
        } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

        if (!wait) return;
        RtlWaitOnAddress( &u.s->owners, &new.s.owners, sizeof(short), NULL );
    }
}

/***********************************************************************
 *              RtlAcquireSRWLockShared (NTDLL.@)
 *
 * NOTES
 *   Do not call this function recursively - it will only succeed when
 *   there are no threads waiting for an exclusive lock!
 */
void WINAPI RtlAcquireSRWLockShared( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };

    for (;;)
    {
        union { struct srw_lock s; LONG l; } old, new;
        BOOL wait;

        do
        {
            old.s = *u.s;
            new = old;

            if (!old.s.exclusive_waiters)
            {
                /* Not locked exclusive, and no exclusive waiters.
                 * We can try to grab it. */
                ++new.s.owners;
                wait = FALSE;
            }
            else
            {
                wait = TRUE;
            }
        } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

        if (!wait) return;
        RtlWaitOnAddress( u.s, &new.s, sizeof(struct srw_lock), NULL );
    }
}

/***********************************************************************
 *              RtlReleaseSRWLockExclusive (NTDLL.@)
 */
void WINAPI RtlReleaseSRWLockExclusive( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };
    union { struct srw_lock s; LONG l; } old, new;

    do
    {
        old.s = *u.s;
        new = old;

        if (!(old.s.exclusive_waiters & 1)) ERR("Lock %p is not owned exclusive!\n", lock);

        new.s.owners = 0;
        new.s.exclusive_waiters &= ~1;
    } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

    if (new.s.exclusive_waiters)
        RtlWakeAddressSingle( &u.s->owners );
    else
        RtlWakeAddressAll( u.s );
}

/***********************************************************************
 *              RtlReleaseSRWLockShared (NTDLL.@)
 */
void WINAPI RtlReleaseSRWLockShared( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };
    union { struct srw_lock s; LONG l; } old, new;

    do
    {
        old.s = *u.s;
        new = old;

        if (old.s.exclusive_waiters & 1) ERR("Lock %p is owned exclusive!\n", lock);
        else if (!old.s.owners) ERR("Lock %p is not owned shared!\n", lock);

        --new.s.owners;
    } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

    if (!new.s.owners)
        RtlWakeAddressSingle( &u.s->owners );
}

/***********************************************************************
 *              RtlTryAcquireSRWLockExclusive (NTDLL.@)
 *
 * NOTES
 *  Similarly to AcquireSRWLockExclusive, recursive calls are not allowed
 *  and will fail with a FALSE return value.
 */
BOOLEAN WINAPI RtlTryAcquireSRWLockExclusive( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };
    union { struct srw_lock s; LONG l; } old, new;
    BOOLEAN ret;

    do
    {
        old.s = *u.s;
        new.s = old.s;

        if (!old.s.owners)
        {
            /* Not locked exclusive or shared. We can try to grab it. */
            new.s.owners = 1;
            new.s.exclusive_waiters |= 1;
            ret = TRUE;
        }
        else
        {
            ret = FALSE;
        }
    } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

    return ret;
}

/***********************************************************************
 *              RtlTryAcquireSRWLockShared (NTDLL.@)
 */
BOOLEAN WINAPI RtlTryAcquireSRWLockShared( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };
    union { struct srw_lock s; LONG l; } old, new;
    BOOLEAN ret;

    do
    {
        old.s = *u.s;
        new.s = old.s;

        if (!old.s.exclusive_waiters)
        {
            /* Not locked exclusive, and no exclusive waiters.
             * We can try to grab it. */
            ++new.s.owners;
            ret = TRUE;
        }
        else
        {
            ret = FALSE;
        }
    } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

    return ret;
}

/***********************************************************************
 *           RtlInitializeConditionVariable   (NTDLL.@)
 *
 * Initializes the condition variable with NULL.
 *
 * PARAMS
 *  variable [O] condition variable
 *
 * RETURNS
 *  Nothing.
 */
void WINAPI RtlInitializeConditionVariable( RTL_CONDITION_VARIABLE *variable )
{
    variable->Ptr = NULL;
}

/***********************************************************************
 *           RtlWakeConditionVariable   (NTDLL.@)
 *
 * Wakes up one thread waiting on the condition variable.
 *
 * PARAMS
 *  variable [I/O] condition variable to wake up.
 *
 * RETURNS
 *  Nothing.
 *
 * NOTES
 *  The calling thread does not have to own any lock in order to call
 *  this function.
 */
void WINAPI RtlWakeConditionVariable( RTL_CONDITION_VARIABLE *variable )
{
    InterlockedIncrement( (LONG *)&variable->Ptr );
    RtlWakeAddressSingle( variable );
}

/***********************************************************************
 *           RtlWakeAllConditionVariable   (NTDLL.@)
 *
 * See WakeConditionVariable, wakes up all waiting threads.
 */
void WINAPI RtlWakeAllConditionVariable( RTL_CONDITION_VARIABLE *variable )
{
    InterlockedIncrement( (LONG *)&variable->Ptr );
    RtlWakeAddressAll( variable );
}

/***********************************************************************
 *           RtlSleepConditionVariableCS   (NTDLL.@)
 *
 * Atomically releases the critical section and suspends the thread,
 * waiting for a Wake(All)ConditionVariable event. Afterwards it enters
 * the critical section again and returns.
 *
 * PARAMS
 *  variable  [I/O] condition variable
 *  crit      [I/O] critical section to leave temporarily
 *  timeout   [I]   timeout
 *
 * RETURNS
 *  see NtWaitForKeyedEvent for all possible return values.
 */
NTSTATUS WINAPI RtlSleepConditionVariableCS( RTL_CONDITION_VARIABLE *variable, RTL_CRITICAL_SECTION *crit,
                                             const LARGE_INTEGER *timeout )
{
    int value = *(int *)&variable->Ptr;
    NTSTATUS status;

    RtlLeaveCriticalSection( crit );
    status = RtlWaitOnAddress( &variable->Ptr, &value, sizeof(value), timeout );
    RtlEnterCriticalSection( crit );
    return status;
}

/***********************************************************************
 *           RtlSleepConditionVariableSRW   (NTDLL.@)
 *
 * Atomically releases the SRWLock and suspends the thread,
 * waiting for a Wake(All)ConditionVariable event. Afterwards it enters
 * the SRWLock again with the same access rights and returns.
 *
 * PARAMS
 *  variable  [I/O] condition variable
 *  lock      [I/O] SRWLock to leave temporarily
 *  timeout   [I]   timeout
 *  flags     [I]   type of the current lock (exclusive / shared)
 *
 * RETURNS
 *  see NtWaitForKeyedEvent for all possible return values.
 *
 * NOTES
 *  the behaviour is undefined if the thread doesn't own the lock.
 */
NTSTATUS WINAPI RtlSleepConditionVariableSRW( RTL_CONDITION_VARIABLE *variable, RTL_SRWLOCK *lock,
                                              const LARGE_INTEGER *timeout, ULONG flags )
{
    int value = *(int *)&variable->Ptr;
    NTSTATUS status;

    if (flags & RTL_CONDITION_VARIABLE_LOCKMODE_SHARED)
        RtlReleaseSRWLockShared( lock );
    else
        RtlReleaseSRWLockExclusive( lock );

    status = RtlWaitOnAddress( &variable->Ptr, &value, sizeof(value), timeout );

    if (flags & RTL_CONDITION_VARIABLE_LOCKMODE_SHARED)
        RtlAcquireSRWLockShared( lock );
    else
        RtlAcquireSRWLockExclusive( lock );
    return status;
}

/* RtlWaitOnAddress() and RtlWakeAddress*(), hereafter referred to as "Win32
 * futexes", offer futex-like semantics with a variable set of address sizes,
 * but are limited to a single process. They are also fair—the documentation
 * specifies this, and tests bear it out.
 *
 * On Windows they are implemented using NtAlertThreadByThreadId and
 * NtWaitForAlertByThreadId, which manipulate a single flag (similar to an
 * auto-reset event) per thread. This can be tested by attempting to wake a
 * thread waiting in RtlWaitOnAddress() via NtAlertThreadByThreadId.
 */

struct futex_entry
{
    struct list entry;
    const void *addr;
    DWORD tid;
};

struct futex_queue
{
    struct list queue;
    LONG lock;
};

static struct futex_queue futex_queues[256];

static struct futex_queue *get_futex_queue( const void *addr )
{
    ULONG_PTR val = (ULONG_PTR)addr;

    return &futex_queues[(val >> 4) % ARRAY_SIZE(futex_queues)];
}

static void spin_lock( LONG *lock )
{
    while (InterlockedCompareExchange( lock, -1, 0 ))
        YieldProcessor();
}

static void spin_unlock( LONG *lock )
{
    InterlockedExchange( lock, 0 );
}

static BOOL compare_addr( const void *addr, const void *cmp, SIZE_T size )
{
    switch (size)
    {
        case 1:
            return (*(const UCHAR *)addr == *(const UCHAR *)cmp);
        case 2:
            return (*(const USHORT *)addr == *(const USHORT *)cmp);
        case 4:
            return (*(const ULONG *)addr == *(const ULONG *)cmp);
        case 8:
            return (*(const ULONG64 *)addr == *(const ULONG64 *)cmp);
    }

    return FALSE;
}

/***********************************************************************
 *           RtlWaitOnAddress   (NTDLL.@)
 */
NTSTATUS WINAPI RtlWaitOnAddress( const void *addr, const void *cmp, SIZE_T size,
                                  const LARGE_INTEGER *timeout )
{
    struct futex_queue *queue = get_futex_queue( addr );
    struct futex_entry entry;
    NTSTATUS ret;

    TRACE("addr %p cmp %p size %#Ix timeout %s\n", addr, cmp, size, debugstr_timeout( timeout ));

    if (size != 1 && size != 2 && size != 4 && size != 8)
        return STATUS_INVALID_PARAMETER;

    entry.addr = addr;
    entry.tid = GetCurrentThreadId();

    spin_lock( &queue->lock );

    /* Do the comparison inside of the spinlock, to reduce spurious wakeups. */

    if (!compare_addr( addr, cmp, size ))
    {
        spin_unlock( &queue->lock );
        return STATUS_SUCCESS;
    }

    if (!queue->queue.next)
        list_init( &queue->queue );
    list_add_tail( &queue->queue, &entry.entry );

    spin_unlock( &queue->lock );

    ret = NtWaitForAlertByThreadId( NULL, timeout );

    /* We may have already been removed by a call to RtlWakeAddressSingle() or RtlWakeAddressAll(). */
    if (entry.addr)
    {
        spin_lock( &queue->lock );
        if (entry.addr)
            list_remove( &entry.entry );
        spin_unlock( &queue->lock );
    }

    TRACE("returning %#lx\n", ret);

    if (ret == STATUS_ALERTED) ret = STATUS_SUCCESS;
    return ret;
}

/***********************************************************************
 *           RtlWakeAddressAll    (NTDLL.@)
 */
void WINAPI RtlWakeAddressAll( const void *addr )
{
    struct futex_queue *queue = get_futex_queue( addr );
    struct futex_entry *entry, *next;
    unsigned int count = 0;
    HANDLE tids[256];

    TRACE("%p\n", addr);

    if (!addr) return;

    spin_lock( &queue->lock );

    if (!queue->queue.next)
        list_init(&queue->queue);

    LIST_FOR_EACH_ENTRY_SAFE( entry, next, &queue->queue, struct futex_entry, entry )
    {
        if (entry->addr == addr)
        {
            entry->addr = NULL;
            list_remove( &entry->entry );
            if (count == ARRAY_SIZE(tids))
            {
                NtAlertMultipleThreadByThreadId( tids, count, NULL, NULL );
                count = 0;
            }
            tids[count++] = (HANDLE)(ULONG_PTR)entry->tid;
        }
    }

    /* Try not to make a system call while holding a spinlock (even if that can be responsible for spurious wake
     * up scenario). */
    spin_unlock( &queue->lock );
    if (count)
        NtAlertMultipleThreadByThreadId( tids, count, NULL, NULL );
}

/***********************************************************************
 *           RtlWakeAddressSingle (NTDLL.@)
 */
void WINAPI RtlWakeAddressSingle( const void *addr )
{
    struct futex_queue *queue = get_futex_queue( addr );
    struct futex_entry *entry;
    DWORD tid = 0;

    TRACE("%p\n", addr);

    if (!addr) return;

    spin_lock( &queue->lock );

    if (!queue->queue.next)
        list_init(&queue->queue);

    LIST_FOR_EACH_ENTRY( entry, &queue->queue, struct futex_entry, entry )
    {
        if (entry->addr == addr)
        {
            /* Try to buffer wakes, so that we don't make a system call while
             * holding a spinlock. */
            tid = entry->tid;

            /* Remove this entry from the queue, so that a simultaneous call to
             * RtlWakeAddressSingle() will not also wake it—two simultaneous
             * calls must wake at least two waiters if they exist. */
            entry->addr = NULL;
            list_remove( &entry->entry );
            break;
        }
    }

    spin_unlock( &queue->lock );

    if (tid) NtAlertThreadByThreadId( (HANDLE)(DWORD_PTR)tid );
}

/*************************************************************************
 *           RtlInitializeSListHead (NTDLL.@)
 */
void WINAPI RtlInitializeSListHead(PSLIST_HEADER list)
{
#ifdef _WIN64
    list->Alignment = list->Region = 0;
    list->Header16.HeaderType = 1;  /* we use the 16-byte header */
#else
    list->Alignment = 0;
#endif
}

/*************************************************************************
 *           RtlQueryDepthSList (NTDLL.@)
 */
WORD WINAPI RtlQueryDepthSList(PSLIST_HEADER list)
{
#ifdef _WIN64
    return list->Header16.Depth;
#else
    return list->Depth;
#endif
}

/*************************************************************************
 *           RtlFirstEntrySList (NTDLL.@)
 */
PSLIST_ENTRY WINAPI RtlFirstEntrySList(const SLIST_HEADER* list)
{
#ifdef _WIN64
    return (SLIST_ENTRY *)((ULONG_PTR)list->Header16.NextEntry << 4);
#else
    return list->Next.Next;
#endif
}

/*************************************************************************
 *           RtlInterlockedFlushSList (NTDLL.@)
 */
PSLIST_ENTRY WINAPI RtlInterlockedFlushSList(PSLIST_HEADER list)
{
    SLIST_HEADER old, new;

#ifdef _WIN64
    if (!list->Header16.NextEntry) return NULL;
    new.Alignment = new.Region = 0;
    new.Header16.HeaderType = 1;  /* we use the 16-byte header */
    do
    {
        old = *list;
        new.Header16.Sequence = old.Header16.Sequence + 1;
    } while (!InterlockedCompareExchange128((__int64 *)list, new.Region, new.Alignment, (__int64 *)&old));
    return (SLIST_ENTRY *)((ULONG_PTR)old.Header16.NextEntry << 4);
#else
    if (!list->Next.Next) return NULL;
    new.Alignment = 0;
    do
    {
        old = *list;
        new.Sequence = old.Sequence + 1;
    } while (InterlockedCompareExchange64((__int64 *)&list->Alignment, new.Alignment,
                                          old.Alignment) != old.Alignment);
    return old.Next.Next;
#endif
}

/*************************************************************************
 *           RtlInterlockedPushEntrySList (NTDLL.@)
 */
PSLIST_ENTRY WINAPI RtlInterlockedPushEntrySList(PSLIST_HEADER list, PSLIST_ENTRY entry)
{
    SLIST_HEADER old, new;

#ifdef _WIN64
    new.Header16.NextEntry = (ULONG_PTR)entry >> 4;
    do
    {
        old = *list;
        entry->Next = (SLIST_ENTRY *)((ULONG_PTR)old.Header16.NextEntry << 4);
        new.Header16.Depth = old.Header16.Depth + 1;
        new.Header16.Sequence = old.Header16.Sequence + 1;
    } while (!InterlockedCompareExchange128((__int64 *)list, new.Region, new.Alignment, (__int64 *)&old));
    return (SLIST_ENTRY *)((ULONG_PTR)old.Header16.NextEntry << 4);
#else
    new.Next.Next = entry;
    do
    {
        old = *list;
        entry->Next = old.Next.Next;
        new.Depth = old.Depth + 1;
        new.Sequence = old.Sequence + 1;
    } while (InterlockedCompareExchange64((__int64 *)&list->Alignment, new.Alignment,
                                          old.Alignment) != old.Alignment);
    return old.Next.Next;
#endif
}

/*************************************************************************
 *           RtlInterlockedPopEntrySList (NTDLL.@)
 */
PSLIST_ENTRY WINAPI RtlInterlockedPopEntrySList(PSLIST_HEADER list)
{
    SLIST_HEADER old, new;
    PSLIST_ENTRY entry;

#ifdef _WIN64
    do
    {
        old = *list;
        if (!(entry = (SLIST_ENTRY *)((ULONG_PTR)old.Header16.NextEntry << 4))) return NULL;
        /* entry could be deleted by another thread */
        __TRY
        {
            new.Header16.NextEntry = (ULONG_PTR)entry->Next >> 4;
            new.Header16.Depth = old.Header16.Depth - 1;
            new.Header16.Sequence = old.Header16.Sequence + 1;
        }
        __EXCEPT_PAGE_FAULT
        {
        }
        __ENDTRY
    } while (!InterlockedCompareExchange128((__int64 *)list, new.Region, new.Alignment, (__int64 *)&old));
#else
    do
    {
        old = *list;
        if (!(entry = old.Next.Next)) return NULL;
        /* entry could be deleted by another thread */
        __TRY
        {
            new.Next.Next = entry->Next;
            new.Depth = old.Depth - 1;
            new.Sequence = old.Sequence + 1;
        }
        __EXCEPT_PAGE_FAULT
        {
        }
        __ENDTRY
    } while (InterlockedCompareExchange64((__int64 *)&list->Alignment, new.Alignment,
                                          old.Alignment) != old.Alignment);
#endif
    return entry;
}

/*************************************************************************
 *           RtlInterlockedPushListSListEx (NTDLL.@)
 */
PSLIST_ENTRY WINAPI RtlInterlockedPushListSListEx(PSLIST_HEADER list, PSLIST_ENTRY first,
                                                  PSLIST_ENTRY last, ULONG count)
{
    SLIST_HEADER old, new;

#ifdef _WIN64
    new.Header16.NextEntry = (ULONG_PTR)first >> 4;
    do
    {
        old = *list;
        new.Header16.Depth = old.Header16.Depth + count;
        new.Header16.Sequence = old.Header16.Sequence + 1;
        last->Next = (SLIST_ENTRY *)((ULONG_PTR)old.Header16.NextEntry << 4);
    } while (!InterlockedCompareExchange128((__int64 *)list, new.Region, new.Alignment, (__int64 *)&old));
    return (SLIST_ENTRY *)((ULONG_PTR)old.Header16.NextEntry << 4);
#else
    new.Next.Next = first;
    do
    {
        old = *list;
        new.Depth = old.Depth + count;
        new.Sequence = old.Sequence + 1;
        last->Next = old.Next.Next;
    } while (InterlockedCompareExchange64((__int64 *)&list->Alignment, new.Alignment,
                                          old.Alignment) != old.Alignment);
    return old.Next.Next;
#endif
}

/*************************************************************************
 *           RtlInterlockedPushListSList (NTDLL.@)
 */
DEFINE_FASTCALL_WRAPPER(RtlInterlockedPushListSList, 16)
PSLIST_ENTRY FASTCALL RtlInterlockedPushListSList(PSLIST_HEADER list, PSLIST_ENTRY first,
                                                  PSLIST_ENTRY last, ULONG count)
{
    return RtlInterlockedPushListSListEx(list, first, last, count);
}

/***********************************************************************
 *           RtlInitializeResource  (NTDLL.@)
 *
 * xxxResource() functions implement multiple-reader-single-writer lock.
 * The code is based on information published in WDJ January 1999 issue.
 */
void WINAPI RtlInitializeResource(LPRTL_RWLOCK rwl)
{
    if (!rwl) return;
    rwl->iNumberActive = 0;
    rwl->uExclusiveWaiters = 0;
    rwl->uSharedWaiters = 0;
    rwl->hOwningThreadId = 0;
    rwl->dwTimeoutBoost = 0; /* no info on this one, default value is 0 */
    RtlInitializeCriticalSectionEx( &rwl->rtlCS, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO );
    rwl->rtlCS.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": RTL_RWLOCK.rtlCS");
    NtCreateSemaphore( &rwl->hExclusiveReleaseSemaphore, SEMAPHORE_ALL_ACCESS, NULL, 0, 65535 );
    NtCreateSemaphore( &rwl->hSharedReleaseSemaphore, SEMAPHORE_ALL_ACCESS, NULL, 0, 65535 );
}

/***********************************************************************
 *           RtlDeleteResource   (NTDLL.@)
 */
void WINAPI RtlDeleteResource(LPRTL_RWLOCK rwl)
{
    if (!rwl) return;
    RtlEnterCriticalSection( &rwl->rtlCS );
    if( rwl->iNumberActive || rwl->uExclusiveWaiters || rwl->uSharedWaiters )
        ERR("Deleting active MRSW lock (%p), expect failure\n", rwl );
    rwl->hOwningThreadId = 0;
    rwl->uExclusiveWaiters = rwl->uSharedWaiters = 0;
    rwl->iNumberActive = 0;
    NtClose( rwl->hExclusiveReleaseSemaphore );
    NtClose( rwl->hSharedReleaseSemaphore );
    RtlLeaveCriticalSection( &rwl->rtlCS );
    rwl->rtlCS.DebugInfo->Spare[0] = 0;
    RtlDeleteCriticalSection( &rwl->rtlCS );
}

/***********************************************************************
 *          RtlAcquireResourceExclusive	(NTDLL.@)
 */
BYTE WINAPI RtlAcquireResourceExclusive(LPRTL_RWLOCK rwl, BYTE fWait)
{
    BYTE retVal = 0;

    if (!rwl) return 0;

    for (;;)
    {
        RtlEnterCriticalSection( &rwl->rtlCS );
        if( rwl->iNumberActive == 0 ) /* lock is free */
        {
            rwl->iNumberActive = -1;
            retVal = 1;
        }
        else if( rwl->iNumberActive < 0 ) /* exclusive lock in progress */
        {
            if( rwl->hOwningThreadId == ULongToHandle(GetCurrentThreadId()) )
            {
                retVal = 1;
                rwl->iNumberActive--;
                break;
            }
        wait:
            if( fWait )
            {
                NTSTATUS status;

                rwl->uExclusiveWaiters++;

                RtlLeaveCriticalSection( &rwl->rtlCS );
                status = NtWaitForSingleObject( rwl->hExclusiveReleaseSemaphore, FALSE, NULL );
                if( HIWORD(status) ) break;
                continue; /* restart the acquisition to avoid deadlocks */
            }
        }
        else  /* one or more shared locks are in progress */
            if( fWait )
                goto wait;

        if( retVal == 1 ) rwl->hOwningThreadId = ULongToHandle(GetCurrentThreadId());
        break;
    }
    RtlLeaveCriticalSection( &rwl->rtlCS );
    return retVal;
}

/***********************************************************************
 *          RtlAcquireResourceShared  (NTDLL.@)
 */
BYTE WINAPI RtlAcquireResourceShared(LPRTL_RWLOCK rwl, BYTE fWait)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BYTE retVal = 0;

    if (!rwl) return 0;
    for (;;)
    {
        RtlEnterCriticalSection( &rwl->rtlCS );
        if( rwl->iNumberActive < 0 )
        {
            if( rwl->hOwningThreadId == ULongToHandle(GetCurrentThreadId()) )
            {
                rwl->iNumberActive--;
                retVal = 1;
                break;
            }

            if( fWait )
            {
                rwl->uSharedWaiters++;
                RtlLeaveCriticalSection( &rwl->rtlCS );
                status = NtWaitForSingleObject( rwl->hSharedReleaseSemaphore, FALSE, NULL );
                if( HIWORD(status) ) break;
                continue;
            }
        }
        else
        {
            if( status != STATUS_WAIT_0 ) /* otherwise RtlReleaseResource() has already done it */
                rwl->iNumberActive++;
            retVal = 1;
        }
        break;
    }
    RtlLeaveCriticalSection( &rwl->rtlCS );
    return retVal;
}


/***********************************************************************
 *           RtlReleaseResource  (NTDLL.@)
 */
void WINAPI RtlReleaseResource(LPRTL_RWLOCK rwl)
{
    RtlEnterCriticalSection( &rwl->rtlCS );

    if( rwl->iNumberActive > 0 ) /* have one or more readers */
    {
	if( --rwl->iNumberActive == 0 )
	{
	    if( rwl->uExclusiveWaiters )
	    {
		rwl->uExclusiveWaiters--;
		NtReleaseSemaphore( rwl->hExclusiveReleaseSemaphore, 1, NULL );
	    }
	}
    }
    else if( rwl->iNumberActive < 0 ) /* have a writer, possibly recursive */
    {
	if( ++rwl->iNumberActive == 0 )
	{
	    rwl->hOwningThreadId = 0;
	    if( rwl->uExclusiveWaiters )
	    {
		rwl->uExclusiveWaiters--;
		NtReleaseSemaphore( rwl->hExclusiveReleaseSemaphore, 1, NULL );
	    }
	    else if( rwl->uSharedWaiters )
            {
                UINT n = rwl->uSharedWaiters;
                rwl->iNumberActive = rwl->uSharedWaiters; /* prevent new writers from joining until
                                                           * all queued readers have done their thing */
                rwl->uSharedWaiters = 0;
                NtReleaseSemaphore( rwl->hSharedReleaseSemaphore, n, NULL );
            }
	}
    }
    RtlLeaveCriticalSection( &rwl->rtlCS );
}


/***********************************************************************
 *           RtlDumpResource		(NTDLL.@)
 */
void WINAPI RtlDumpResource(LPRTL_RWLOCK rwl)
{
    if (!rwl) return;
    ERR( "%p: active count = %i waiting readers = %i waiting writers = %i owner thread = %p",
         rwl, rwl->iNumberActive, rwl->uSharedWaiters, rwl->uExclusiveWaiters, rwl->hOwningThreadId );
    ERR( "\n" );
}


struct barrier_impl
{
    LONG spin_count;
    LONG total_thread_count;
    volatile LONG reached_thread_count;
    volatile LONG structure_lock_count;
    volatile LONG waiting_thread_count;
    volatile LONG wait_barrier_complete;
};

C_ASSERT( sizeof(struct barrier_impl) <= sizeof(RTL_BARRIER) );

/***********************************************************************
 *           RtlInitBarrier  (NTDLL.@)
 */
NTSTATUS WINAPI RtlInitBarrier( RTL_BARRIER *barrier, LONG thread_count, LONG spin_count )
{
    struct barrier_impl *b = (struct barrier_impl *)barrier;

    TRACE( "barrier %p, thread_count %ld, spin_count %ld.\n", barrier, thread_count, spin_count );

    if (!barrier) return STATUS_INVALID_PARAMETER;
    b->total_thread_count = thread_count;
    b->spin_count = spin_count;
    b->reached_thread_count = 0;
    b->structure_lock_count = 0;
    b->waiting_thread_count = 0;
    b->wait_barrier_complete = 0;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           RtlDeleteBarrier  (NTDLL.@)
 */
void WINAPI RtlDeleteBarrier( RTL_BARRIER *barrier )
{
    struct barrier_impl *b = (struct barrier_impl *)barrier;
    LONG count;

    TRACE( "barrier %p.\n", barrier );

    if (!barrier) return;
    if (ReadAcquire( &b->reached_thread_count ) < b->total_thread_count && b->structure_lock_count)
    {
        /* On Windows this case will make RtlDeleteBarrier and the threads joining after wait forever,
         * unless the threads joining after will have SYNCHRONIZATION_BARRIER_FLAGS_NO_DELETE. */
        ERR( "called before the barrier wait is satisfied.\n" );
    }
    while ((count = ReadAcquire( &b->structure_lock_count )))
        RtlWaitOnAddress( (void *)&b->structure_lock_count, &count, sizeof(b->structure_lock_count), NULL );
}


/***********************************************************************
 *           RtlBarrier  (NTDLL.@)
 */
BOOLEAN WINAPI RtlBarrier( RTL_BARRIER *barrier, ULONG flags )
{
    static unsigned int once;
    static const LONG zero;

    struct barrier_impl *b = (struct barrier_impl *)barrier;
    unsigned int spin_count, count;
    BOOL ret = FALSE;

    TRACE( "barrier %p, flags %#lx.\n", barrier, flags );

    if (flags & ~0x10000 && !once++) FIXME( "Unknown flags %#lx.\n", flags );
    if (!barrier) return FALSE;

    /* Incrementing reached_thread_count may trigger RTL_BARRIER data desrtuction from another thread,
     * so lock RtlDeleteBarrier with waiting_thread_count before that. */
    if (flags & 0x10000) InterlockedIncrement( &b->structure_lock_count );

    /* On Windows the long wait doesn't consume CPU with any spin count, so probably the spin count
     * is limited or not used at all. */
    spin_count = min( 2000, (unsigned int)b->spin_count );

    /* Wait for previous wait iteration to complete. */
    count = 0;
    while (ReadAcquire( &b->reached_thread_count ) == b->total_thread_count)
    {
        if (count < spin_count)
        {
            ++count;
            YieldProcessor();
            continue;
        }
        RtlWaitOnAddress( (void *)&b->reached_thread_count, &b->total_thread_count,
                          sizeof(b->reached_thread_count), NULL );
    }
    InterlockedIncrement( &b->waiting_thread_count );
    if (InterlockedIncrement( &b->reached_thread_count ) == b->total_thread_count)
    {
        WriteRelease( &b->wait_barrier_complete, 1 );
        RtlWakeAddressAll( (const void *)&b->wait_barrier_complete );
        ret = TRUE;
        goto done;
    }
    count = 0;
    while (ReadAcquire( &b->reached_thread_count ) < b->total_thread_count )
    {
        if (count < spin_count)
        {
            ++count;
            YieldProcessor();
            continue;
        }
        RtlWaitOnAddress( (void *)&b->wait_barrier_complete, &zero, sizeof(b->wait_barrier_complete), NULL );
    }

done:
    if (!InterlockedDecrement( &b->waiting_thread_count ))
    {
        WriteRelease( &b->wait_barrier_complete, 0 );
        WriteRelease( &b->reached_thread_count, 0 );
        RtlWakeAddressAll( (const void *)&b->reached_thread_count );
    }

    if (flags & 0x10000 && !InterlockedDecrement( &b->structure_lock_count ))
    {
        /* Now RTL_BARRIER structure contents may become invalid. Signaling on its address should be fine, the worst
         * (unlikely) case it will wake something unrelated on reused address but that should be a legitimate spurious
         * wakeup case. */
        RtlWakeAddressAll( (const void *)&b->structure_lock_count );
    }
    return ret;
}
