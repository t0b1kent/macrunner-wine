/*
 * ARM64 signal handling routines
 *
 * Copyright 2010-2013 André Hentschel
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

#ifdef __aarch64__

#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <setjmp.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wine/exception.h"
#include "ntdll_misc.h"
#include "wine/debug.h"
#include "ntsyscalls.h"

WINE_DEFAULT_DEBUG_CHANNEL(seh);
WINE_DECLARE_DEBUG_CHANNEL(relay);

#define MACRUNNER_HB_IMPORT_BASE 0x00006f0000000000ULL
#define MACRUNNER_HB_IMPORT_LIMIT (MACRUNNER_HB_IMPORT_BASE + 4096 * 0x10ULL)
#define MACRUNNER_HB_UNIX_DISPATCHER_WINDOW 0x20000ULL
#define MACRUNNER_HB_HOST_BOUNDARY_MIN 0x0000000100000000ULL
#define MACRUNNER_HB_HOST_BOUNDARY_MAX 0x0000008000000000ULL
#define MACRUNNER_HB_SYSCALL_FRAME_SIZE 0x330ULL

extern void *__wine_syscall_dispatcher;
/* Filled by the unix side at load time; NULL when unavailable, so every use must check. */
extern int (*macrunner_hb_guest_image_lookup)( UINT64 pc, UINT64 *base, UINT64 *size );
extern int (*macrunner_hb_guest_ctx_lookup)( DWORD tid, UINT64 *guest_pc, UINT64 *guest_sp );
extern int (*macrunner_hb_known_stack_lookup)( UINT64 sp, UINT64 *lo, UINT64 *hi, int *kind );

static const EXCEPTION_RECORD *macrunner_hb_current_exception_record;

extern void macrunner_hb_exit_origin_seh_handler_observe( const char *kind,
                                                           const void *handler,
                                                           ULONG_PTR control_pc,
                                                           ULONG_PTR establisher_frame,
                                                           DWORD disposition );

struct macrunner_hb_syscall_frame
{
    ULONG64 x[29];
    ULONG64 fp;
    ULONG64 lr;
    ULONG64 sp;
    ULONG64 pc;
    ULONG cpsr;
    ULONG restore_flags;
    struct macrunner_hb_syscall_frame *prev_frame;
    void *syscall_cfa;
};

static inline struct macrunner_hb_syscall_frame *macrunner_hb_current_syscall_frame(void)
{
    TEB *teb = NtCurrentTeb();

    if (!teb) return NULL;
    return *(struct macrunner_hb_syscall_frame **)((char *)teb + 0x378);
}

static inline BOOL macrunner_hb_is_import_thunk_pc( DWORD64 pc )
{
    return pc >= MACRUNNER_HB_IMPORT_BASE && pc < MACRUNNER_HB_IMPORT_LIMIT;
}

static inline DWORD64 macrunner_hb_normalize_arm64ec_host_pc( DWORD64 pc )
{
    if ((pc & 1) && pc >= MACRUNNER_HB_HOST_BOUNDARY_MIN && pc < MACRUNNER_HB_HOST_BOUNDARY_MAX)
        return pc & ~(DWORD64)1;
    return pc;
}

static inline BOOL macrunner_hb_is_x64_main_process(void)
{
    TEB *teb = NtCurrentTeb();
    IMAGE_NT_HEADERS *nt;

    if (!teb || teb->WowTebOffset || !teb->Peb || !teb->Peb->ImageBaseAddress)
        return FALSE;
    if (!(nt = RtlImageNtHeader( teb->Peb->ImageBaseAddress )))
        return FALSE;
    return nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
           nt->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64EC;
}

static inline BOOL macrunner_hb_near_unix_dispatcher( DWORD64 pc, const void *dispatcher )
{
    ULONG_PTR center = (ULONG_PTR)dispatcher;

    if (!center) return FALSE;
    if (center > MACRUNNER_HB_UNIX_DISPATCHER_WINDOW &&
        pc >= center - MACRUNNER_HB_UNIX_DISPATCHER_WINDOW &&
        pc < center + MACRUNNER_HB_UNIX_DISPATCHER_WINDOW)
        return TRUE;
    return pc >= center && pc < center + MACRUNNER_HB_UNIX_DISPATCHER_WINDOW;
}

static BOOL macrunner_hb_trace_arm64_seh_invalid_disposition(void)
{
    static unsigned int count;
    return count++ < 64;
}

static LONG CALLBACK macrunner_hb_pe_scan_fault( EXCEPTION_POINTERS *ep );
static BOOL macrunner_hb_find_pc_section( DWORD64 pc, char section_name[9],
                                          DWORD *section_characteristics );
static int macrunner_hb_arm64x_code_range_kind( ULONG_PTR base, DWORD64 pc );
static void macrunner_hb_nullcall_diagnose( CONTEXT *context );

static inline BOOL macrunner_hb_is_unix_dispatcher_boundary_pc( DWORD64 pc )
{
    if (!macrunner_hb_is_x64_main_process()) return FALSE;
    return macrunner_hb_near_unix_dispatcher( pc, __wine_syscall_dispatcher ) ||
           macrunner_hb_near_unix_dispatcher( pc, (const void *)__wine_unix_call_dispatcher );
}

static inline BOOL macrunner_hb_is_non_module_host_boundary_pc( DWORD64 pc )
{
    LDR_DATA_TABLE_ENTRY *module;

    if (!macrunner_hb_is_x64_main_process()) return FALSE;
    if (pc < MACRUNNER_HB_HOST_BOUNDARY_MIN || pc >= MACRUNNER_HB_HOST_BOUNDARY_MAX)
        return FALSE;
    return LdrFindEntryForAddress( (void *)(ULONG_PTR)pc, &module ) != STATUS_SUCCESS;
}

static inline BOOL macrunner_hb_is_null_lr_boundary( DWORD64 pc, const CONTEXT *context )
{
    if (!macrunner_hb_is_x64_main_process() || !context) return FALSE;
    if (context->Lr) return FALSE;
    return pc == 0 || pc == ~(DWORD64)3;
}

static inline BOOL macrunner_hb_is_host_boundary_pc( DWORD64 pc, const CONTEXT *context )
{
    if (!macrunner_hb_is_x64_main_process()) return FALSE;
    if (!context) return FALSE;
    return pc == 0 || (context->Lr == 0 && (pc == ~(DWORD64)3 || pc == 0));
}

static inline BOOL macrunner_hb_current_exception_is_datatype_misalignment(void)
{
    const EXCEPTION_RECORD *rec = macrunner_hb_current_exception_record;

    return rec && rec->ExceptionCode == STATUS_DATATYPE_MISALIGNMENT && !rec->ExceptionFlags;
}

static BOOL macrunner_hb_is_plausible_recovered_pc( DWORD64 pc, const char **reason )
{
    TEB *teb = NtCurrentTeb();
    ULONG_PTR stack_lo = teb ? (ULONG_PTR)teb->Tib.StackLimit : 0;
    ULONG_PTR stack_hi = teb ? (ULONG_PTR)teb->Tib.StackBase : 0;
    char section_name[9];
    DWORD section_characteristics;

    if (!pc) { if (reason) *reason = "pc-null"; return FALSE; }
    if ((pc & 3) || pc == ~(DWORD64)3) { if (reason) *reason = "pc-unaligned"; return FALSE; }
    if (pc < 0x10000) { if (reason) *reason = "pc-low"; return FALSE; }
    if (stack_lo && stack_hi && pc >= stack_lo && pc < stack_hi)
    {
        if (reason) *reason = "pc-in-stack";
        return FALSE;
    }
    if (macrunner_hb_is_import_thunk_pc( pc )) return TRUE;
    if (pc >= MACRUNNER_HB_HOST_BOUNDARY_MIN &&
        macrunner_hb_find_pc_section( pc, section_name, &section_characteristics ))
    {
        LDR_DATA_TABLE_ENTRY *module = NULL;

        if (!(section_characteristics & IMAGE_SCN_MEM_EXECUTE))
        {
            if (reason) *reason = "pc-nonexec-section";
            return FALSE;
        }
        /* ★★★ 2026-08-18, лейн ЛЕСТНИЦА, итерация 2375 (приказ владельца 185, класс Б) —
         * КОНСТАНТА БОЛЬШЕ НЕ ПРИНИМАЕТ РЕШЕНИЕ ТАМ, ГДЕ ЕСТЬ ТАБЛИЦА.
         *
         * Было: `pc < HOST_BOUNDARY_MAX` → «полоса эмулятора» → отказ. Замер 2365 показал, что
         * полос гостевых образов ДВЕ (~0xEB, 59 ГБ и ~0x87E, 8,5 ТБ), а граница 512 ГБ проходит
         * между ними: HK попадает выше, блокнот x64 — ниже, и его законный адрес отвергался.
         *
         * Сюда мы приходим ТОЛЬКО когда секция уже найдена (условие выше), то есть модуль
         * известен. Значит на вопрос «чей это код» отвечает таблица: `arm64x_code_range_kind`
         * ниже даёт `pc-x64-code-range` для x64-половины — тот самый ответ, ради которого
         * константа и стояла, но верный для ЛЮБОЙ раскладки адресов.
         *
         * Диапазон остаётся быстрым предфильтром выше (`pc >= HOST_BOUNDARY_MIN`), но
         * окончательное решение теперь за таблицей. Замер 2366: для 0xEBBA3C344 таблица даёт
         * `win32u.dll`, `kind=0` — то есть отказ сохранится, но по правильному основанию. */
        if (0)
        {
            /* ★ 2026-08-18, лейн ЛЕСТНИЦА, итерация 2366 — ЗАМЕР ПЕРЕД ПРАВКОЙ, НЕ ВМЕСТО НЕЁ.
             *
             * Полос гостевых образов у нас ДВЕ (замер 2365 и комментарий virtual.c:885): ~0xEB…
             * (59 ГБ) и ~0x87E… (8,5 ТБ). Граница этой проверки — 512 ГБ — проходит между ними,
             * поэтому блокнот x64 (образ 0xEBBA20000) объявляется «полосой эмулятора», а HK нет.
             *
             * Прежде чем менять условие, печатаем, что об этом адресе знает загрузчик: имя
             * модуля, его базу и род кодового диапазона ARM64X. Если модуль найден и это гостевой
             * образ — значит различать можно ПО МОДУЛЮ, а не по адресу, и правка будет опираться
             * на замер. Если не найден — версия отпадает, и я узнаю это ценой одного прогона. */
            {
                static unsigned int band_noted;
                LDR_DATA_TABLE_ENTRY *band_mod = NULL;
                NTSTATUS band_st = LdrFindEntryForAddress( (void *)(ULONG_PTR)pc, &band_mod );

                if (band_noted++ < 8)
                    MESSAGE( "macrunner-hb-band-probe: pc=%p status=%08lx module=%s base=%p "
                             "kind=%d секция=%s\n",
                             (void *)(ULONG_PTR)pc, (ULONG)band_st,
                             (band_st == STATUS_SUCCESS && band_mod)
                                 ? debugstr_w( band_mod->BaseDllName.Buffer ) : "(нет)",
                             (band_st == STATUS_SUCCESS && band_mod) ? band_mod->DllBase : NULL,
                             (band_st == STATUS_SUCCESS && band_mod)
                                 ? macrunner_hb_arm64x_code_range_kind( (ULONG_PTR)band_mod->DllBase, pc )
                                 : -1,
                             section_name );
            }
            if (reason) *reason = "pc-emulator-band";
            return FALSE;
        }
        if (LdrFindEntryForAddress( (void *)(ULONG_PTR)pc, &module ) == STATUS_SUCCESS &&
            module && macrunner_hb_arm64x_code_range_kind( (ULONG_PTR)module->DllBase, pc ) == 0)
        {
            if (reason) *reason = "pc-x64-code-range";
            return FALSE;
        }
        return TRUE;
    }

    if (reason) *reason = "pc-not-code";
    return FALSE;
}

static BOOL macrunner_hb_find_pc_section( DWORD64 pc, char section_name[9],
                                          DWORD *section_characteristics )
{
    LDR_DATA_TABLE_ENTRY *module = NULL;
    IMAGE_NT_HEADERS *nt;
    ULONG_PTR base, rva;
    IMAGE_SECTION_HEADER *sec;
    WORD i;

    if (section_name) memset( section_name, 0, 9 );
    if (section_characteristics) *section_characteristics = 0;
    if (!pc) return FALSE;
    if (LdrFindEntryForAddress( (void *)(ULONG_PTR)pc, &module ) != STATUS_SUCCESS || !module)
        return FALSE;

    __TRY
    {
        base = (ULONG_PTR)module->DllBase;
        nt = RtlImageNtHeader( module->DllBase );
        if (!base || !nt || pc < base || pc >= base + nt->OptionalHeader.SizeOfImage) return FALSE;
        rva = (ULONG_PTR)pc - base;
        sec = IMAGE_FIRST_SECTION( nt );
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        {
            ULONG_PTR start = sec->VirtualAddress;
            ULONG_PTR end = start + max( sec->Misc.VirtualSize, sec->SizeOfRawData );

            if (!start || rva < start || rva >= end) continue;
            if (section_name) memcpy( section_name, sec->Name, 8 );
            if (section_characteristics) *section_characteristics = sec->Characteristics;
            return TRUE;
        }
    }
    __EXCEPT(macrunner_hb_pe_scan_fault) {}
    __ENDTRY
    return FALSE;
}

static inline void macrunner_hb_stop_unwind_at_boundary( DISPATCHER_CONTEXT *dispatch, CONTEXT *context )
{
    dispatch->ImageBase = 0;
    dispatch->FunctionEntry = NULL;
    dispatch->HandlerData = NULL;
    dispatch->EstablisherFrame = 0;
    dispatch->LanguageHandler = NULL;
    context->ContextFlags |= CONTEXT_UNWOUND_TO_CALL;
}

static BOOL macrunner_hb_is_plausible_recovered_pc( DWORD64 pc, const char **reason );
static BOOL macrunner_hb_pc_in_host_unix_window( DWORD64 pc );

static BOOL macrunner_hb_leaf_lr_guard_enabled(void);
static BOOL macrunner_hb_recover_no_frame_enabled(void);

/* MacRunner 2026-08-03 — which assignment produced an unusable resume PC.
 *
 * Three hypotheses about the source of the pc==lr stack resume have now been refuted by
 * measurement (host-frame acceptance, the interpreter RET, the leaf-lr unwind), each costing a
 * build and a run.  Guessing a fourth is worse value than making the code say it: every site that
 * writes context->Pc calls this, and only a site that writes something which is NOT code prints.
 * The site id is the marker — the next run names the line instead of confirming a guess. */
static void macrunner_hb_note_pc_set( int site, DWORD64 newpc, DWORD64 sp )
{
    static unsigned int noted;
    /* ★ 2026-08-18, лейн ЛЕСТНИЦА, итерация 2363 — ПЕЧАТАТЬ ПРИЧИНУ, А НЕ ТОЛЬКО ЗНАЧЕНИЕ.
     *
     * `macrunner_hb_is_plausible_recovered_pc` умеет назвать, ЧЕМ ей не угодил адрес
     * (`pc-in-stack`, `pc-nonexec-section`, `pc-emulator-band`, `pc-x64-code-range`,
     * `pc-not-code`), но её звали с NULL — и наружу выходило одно значение. На блокноте x64
     * это стоило мне двух версий подряд: кадр объявлялся то чужим, то испорченным, тогда как
     * замер 2362 показал, что кадр согласован, а отвергает его именно эта проверка.
     * Ответ у прибора был всё это время; выводим его. */
    const char *why = "(нет)";

    if (macrunner_hb_is_plausible_recovered_pc( newpc, &why )) return;
    if (macrunner_hb_pc_in_host_unix_window( newpc )) return;
    if (noted++ >= 24) return;
    MESSAGE( "macrunner-hb-pc-set-bad: site=%d pc=%p sp=%016I64x причина=%s\n",
             site, (void *)(ULONG_PTR)newpc, sp, why );
}

static inline BOOL macrunner_hb_unwind_leaf_via_lr( DISPATCHER_CONTEXT *dispatch, CONTEXT *context,
                                                    DWORD64 pc, DWORD64 lr )
{
    if (!lr || lr == pc || lr == pc + 4 || lr == ~(DWORD64)3) return FALSE;

    /* MacRunner 2026-08-03 — an lr that is not a code address must not become the resume point.
     *
     * This function resumes a "leaf" frame by trusting x30 wholesale: the four tests above reject
     * only the degenerate values.  When the frame is not actually a leaf — or x30 has been reused
     * as scratch — lr can hold an ordinary data pointer, and setting Pc from it resumes execution
     * inside data.  Measured: 7.05 M faults on ONE page, 98 % of a run's total, every sample
     * identical with pc == lr == 0x1111cada8, an address inside a 16 MB rw- region flanked by a
     * 32 KB --- guard, i.e. a thread stack.  pc == lr is the tell: Pc was set FROM lr right here.
     *
     * The same file already knows how to judge this — macrunner_hb_is_plausible_recovered_pc
     * rejects stack addresses and anything outside loaded code — it was simply never asked.  The
     * host-window exemption keeps yesterday's fix intact: a return into our own unix ntdll.so is
     * legitimate and is not a PE module, so the plain plausibility test would reject it too.
     *
     * Gated so one binary runs both arms; the storm makes the difference impossible to miss. */
    if (macrunner_hb_leaf_lr_guard_enabled() &&
        !macrunner_hb_is_plausible_recovered_pc( lr, NULL ) &&
        !macrunner_hb_pc_in_host_unix_window( lr ))
    {
        static unsigned int leaf_lr_rejects;

        if (leaf_lr_rejects++ < 16)
            MESSAGE( "macrunner-hb-leaf-lr-reject: pc=%p lr=%p sp=%016I64x\n",
                     (void *)(ULONG_PTR)pc, (void *)(ULONG_PTR)lr, context ? context->Sp : 0 );
        return FALSE;
    }

    dispatch->ImageBase = 0;
    dispatch->FunctionEntry = NULL;
    dispatch->HandlerData = NULL;
    dispatch->EstablisherFrame = context->Sp;
    dispatch->LanguageHandler = NULL;
    context->Pc = lr;
    macrunner_hb_note_pc_set( 1, context->Pc, context->Sp );
    context->ContextFlags |= CONTEXT_UNWOUND_TO_CALL;
    return TRUE;
}

static inline BOOL macrunner_hb_unwind_made_no_progress( DWORD64 pc, DWORD64 prev_sp,
                                                         DWORD64 prev_fp, const CONTEXT *context )
{
    if (!context) return TRUE;
    if (context->Pc == pc || context->Pc == pc + 4) return TRUE;
    if (context->Sp == prev_sp) return TRUE;
    /* fp staying EQUAL is valid for a frameless function (it never establishes
     * its own frame pointer, so unwinding it leaves the caller's fp untouched);
     * only fp moving strictly BACKWARD (down-stack) signals a corrupt unwind.
     * Using <= here false-rejected genuine native unwinds of frameless DXMT
     * ARM64 frames (sp advanced, pc -> real caller, fp unchanged).
     * fp landing on exactly 0 is the ABI frame-chain terminator (outermost/
     * frameless-leaf frame with no caller fp to report), not a backward jump
     * into bogus memory -- do not flag it as corrupt. */
    if (prev_fp && context->Fp && context->Fp < prev_fp) return TRUE;
    return FALSE;
}

static inline BOOL macrunner_hb_pc_inside_syscall_frame( DWORD64 pc,
                                                         const struct macrunner_hb_syscall_frame *frame )
{
    ULONG_PTR base = (ULONG_PTR)frame;

    return base && pc >= base && pc < base + MACRUNNER_HB_SYSCALL_FRAME_SIZE;
}

static void macrunner_hb_restore_syscall_prev_frame_context( CONTEXT *context,
                                                             const struct macrunner_hb_syscall_frame *prev )
{
    context->Fp = prev->fp;
    context->Lr = prev->lr;
    context->Sp = prev->sp;
    context->Pc = prev->pc;
    /* ★ 2026-08-18, лейн ЛЕСТНИЦА, итерация 2362 — НАЗВАТЬ ИСТОЧНИК КАДРА.
     *
     * Замер 2360-2361 на блокноте x64: сюда приходит `prev->pc = 0xEBBA3C344`, ровно на 4 байта
     * (одну команду ARM64) дальше адреса, с которого граница только что восстановилась. Прибор
     * `pc-set-bad` печатает ЗНАЧЕНИЕ, но молчит о том, ОТКУДА кадр, — а различить надо две
     * разные беды: кадр принадлежит другому вызову либо кадр перезаписан.
     *
     * Печатаем адрес самой структуры и её sp/fp/lr: если `prev` лежит вне стека потока или её
     * sp не согласован с текущим, кадр чужой; если согласован, а pc негоден — кадр испорчен.
     * Печать под тем же условием, что и `pc-set-bad`, чтобы не шуметь на здоровых путях. */
    if (!macrunner_hb_is_plausible_recovered_pc( context->Pc, NULL ))
    {
        static unsigned int frame_noted;
        if (frame_noted++ < 8)
            MESSAGE( "macrunner-hb-prev-frame-src: prev=%p prev_pc=%p prev_sp=%016I64x "
                     "prev_fp=%016I64x prev_lr=%p\n",
                     (void *)prev, (void *)(ULONG_PTR)prev->pc, prev->sp, prev->fp,
                     (void *)(ULONG_PTR)prev->lr );
    }
    macrunner_hb_note_pc_set( 2, context->Pc, context->Sp );
    context->Cpsr = prev->cpsr;
    memcpy( &context->X19, &prev->x[19], 10 * sizeof(prev->x[0]) );
    context->ContextFlags |= CONTEXT_CONTROL | CONTEXT_INTEGER;
}

static BOOL macrunner_hb_unwind_syscall_data_boundary( DISPATCHER_CONTEXT *dispatch,
                                                       CONTEXT *context,
                                                       struct macrunner_hb_syscall_frame *frame )
{
    struct macrunner_hb_syscall_frame *prev;
    static unsigned int report_count;
    DWORD tid = HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );

    if (!frame || !macrunner_hb_pc_inside_syscall_frame( context->Pc, frame ))
        return FALSE;
    if (!(prev = frame->prev_frame) || !prev->pc || !prev->sp)
        return FALSE;
    if (macrunner_hb_pc_inside_syscall_frame( prev->pc, frame ))
        return FALSE;

    if (report_count++ < 64)
        MESSAGE( "macrunner-hb-seh-syscall-data-boundary: tid=%04lx pc=%p frame=%p "
                 "bad_frame_pc=%p bad_frame_lr=%p prev=%p prev_pc=%p prev_lr=%p "
                 "prev_sp=%p resume=prev-frame\n",
                 tid, (void *)(ULONG_PTR)context->Pc, frame,
                 (void *)(ULONG_PTR)frame->pc, (void *)(ULONG_PTR)frame->lr,
                 prev, (void *)(ULONG_PTR)prev->pc, (void *)(ULONG_PTR)prev->lr,
                 (void *)(ULONG_PTR)prev->sp );

    macrunner_hb_restore_syscall_prev_frame_context( context, prev );
    macrunner_hb_stop_unwind_at_boundary( dispatch, context );
    return TRUE;
}

/* MacRunner 2026-08-02 — the resume candidate at a native-dispatch boundary can legitimately be a
 * HOST address, and until now every acceptance test below refused one.
 *
 * Measured, not inferred: HK dies at +670.9 s with `prev_frame == NULL`, so the recovery falls back
 * to the current frame (source=current-frame).  That frame's pc is 0x107092d40, which resolves to
 * `macrunner_hb_call_direct_native_target+0x8e0` in our own unix ntdll.so — the return site of
 * `bl __wine_unix_call_dispatcher`.  A perfectly ordinary place for the thread to be.  But every
 * test recognises code only through LdrFindEntryForAddress, i.e. only PE modules, so a host Mach-O
 * address falls through to "pc-not-code" and the recovery is refused.  Score across the whole run
 * history before this change: 360 rejects, 0 recoveries — the Fix-C machinery specified on
 * 2026-06-24 has shipped in every build since and has never once fired.
 *
 * macrunner_hb_is_unix_dispatcher_boundary_pc() misses this by margin, not by intent: its window is
 * 0x20000 and this call site sits 0x2e3f0 below the dispatcher.  Rather than widen that constant —
 * it guards other decisions — this uses its own, wider window and its own marker.
 *
 * The TEB stack check further down is skipped for such a frame on purpose: Tib.StackLimit/StackBase
 * describe the GUEST stack, while a thread inside a unix call is legitimately on the HOST stack.
 * The same run shows sp=0x112bcc880 against stack=0x115ec0000-0x116ec0000 — not corruption, just two
 * different stacks being compared.
 *
 * Gated so ONE binary runs both arms: MACRUNNER_HB_RECOVER_HOST_FRAME=0 restores the old refusal. */
#define MACRUNNER_HB_HOST_FRAME_WINDOW 0x80000ULL

static BOOL macrunner_hb_query_env_uint( const WCHAR *nameW, unsigned int *value );

/* ★★★★★★ MacRunner 2026-08-31 — ЧТЕНИЕ ОКРУЖЕНИЯ ЗАПРЕЩЕНО В ПУТИ ОТКАЗА.
 *
 * КОРЕНЬ, найденный инструментом за один прогон. Цепочка отказа целиком:
 *   combase!start_rpcss -> NdrClientCall2 -> NdrpClientCall2
 *     -> ntdll!dispatch_exception -> ntdll!virtual_unwind
 *       -> macrunner_hb_register_wow64_arm64_pe_pdata
 *         -> macrunner_hb_pdata_scan_safe -> macrunner_hb_query_env_uint
 *           -> RtlQueryEnvironmentVariable_U   <-- ЧТЕНИЕ ОКРУЖЕНИЯ
 *   -> отказ ВЫБОРКИ на 0x7ffd0…, страница rw при max rwx, РАЗДЕЛЯЕМАЯ.
 *
 * То есть ленивый гейт впервые читал окружение ВНУТРИ раскрутки стека при уже
 * идущей диспетчеризации исключения. Ровно этот класс записан в памяти проекта:
 * «getenv в горячем пути ронял ТРИ процесса — лечится СНИМКОМ окружения, не кешем».
 *
 * ПОЧЕМУ ОДИН ПОМОЩНИК, А НЕ ПРАВКА ШЕСТИ МЕСТ. Узор `static BOOL initialized,
 * enabled; if (!initialized) { … }` скопирован в файле шесть раз, и правка по месту
 * не переносится на седьмой (см. память: zaplatka-na-meste-ne-perenositsya —
 * find_entry_by_name, кириллица в именах, прибор только на segv). Поэтому все гейты
 * идут через ЭТУ функцию, и запрет действует сразу для всех, включая будущие.
 *
 * ПОВЕДЕНИЕ. Пока путь отказа активен, окружение не читается и возвращается
 * умолчание, а гейт НЕ запоминается — значение будет прочитано при первом же
 * безопасном обращении. Так гейт, заданный владельцем, не теряется. */
static volatile int macrunner_hb_in_fault_path;

static BOOL macrunner_hb_gate( int *cached, const WCHAR *nameW, BOOL dflt )
{
    unsigned int value;

    if (*cached >= 0) return *cached != 0;
    if (macrunner_hb_in_fault_path) return dflt;      /* НЕ запоминаем */
    *cached = macrunner_hb_query_env_uint( nameW, &value ) ? (value != 0) : (dflt != 0);
    return *cached != 0;
}


static BOOL macrunner_hb_recover_no_frame_enabled(void)
{
    static const WCHAR gateW[] =
        {'M','A','C','R','U','N','N','E','R','_','H','B','_','R','E','C','O','V','E','R',
         '_','N','O','_','F','R','A','M','E',0};
    static int cached = -1;
    return macrunner_hb_gate( &cached, gateW, TRUE );
}

static BOOL macrunner_hb_leaf_lr_guard_enabled(void)
{
    static const WCHAR gateW[] =
        {'M','A','C','R','U','N','N','E','R','_','H','B','_','L','E','A','F','_','L','R',
         '_','G','U','A','R','D',0};
    static int cached = -1;
    return macrunner_hb_gate( &cached, gateW, TRUE );
}

static BOOL macrunner_hb_recover_host_frame_enabled(void)
{
    static const WCHAR gateW[] =
        {'M','A','C','R','U','N','N','E','R','_','H','B','_','R','E','C','O','V','E','R',
         '_','H','O','S','T','_','F','R','A','M','E',0};
    static int cached = -1;
    return macrunner_hb_gate( &cached, gateW, TRUE );
}

/* Kill switch for the MZ back-scan in the nullcall diagnostic below:
 * MACRUNNER_HB_NULLCALL_MZSCAN=0 disables it. */
static BOOL macrunner_hb_nullcall_mzscan_enabled(void)
{
    static const WCHAR gateW[] =
        {'M','A','C','R','U','N','N','E','R','_','H','B','_','N','U','L','L','C','A','L','L',
         '_','M','Z','S','C','A','N',0};
    static int cached = -1;
    return macrunner_hb_gate( &cached, gateW, TRUE );
}

static BOOL macrunner_hb_pc_in_host_unix_window( DWORD64 pc )
{
    ULONG_PTR centres[2];
    unsigned int i;

    centres[0] = (ULONG_PTR)__wine_syscall_dispatcher;
    centres[1] = (ULONG_PTR)__wine_unix_call_dispatcher;
    for (i = 0; i < ARRAY_SIZE(centres); i++)
    {
        ULONG_PTR centre = centres[i];

        if (centre <= MACRUNNER_HB_HOST_FRAME_WINDOW) continue;
        if (pc >= centre - MACRUNNER_HB_HOST_FRAME_WINDOW &&
            pc < centre + MACRUNNER_HB_HOST_FRAME_WINDOW)
            return TRUE;
    }
    return FALSE;
}

/* ★ 2026-08-31 — СВОДНОЕ СЛОВО `not-x64-main-process` СТОИЛО ТРЁХ РАССЛЕДОВАНИЙ.
 *
 * Лейн ЛЕСТНИЦА (18.08, итерация 2355) уже добавил сюда печать сырых величин, и это
 * помогло: по ним видно, что отказывает ровно проверка машины. Но само слово `reason=`
 * осталось общим на три условия — и читали именно его. За ним пошли ЛЕСТНИЦА 18.08,
 * лейн УСТАНОВЩИКИ 31.08 (написал гейт, чтобы принять 0xAA64) и едва не пошёл я.
 *
 * Поэтому причина вычисляется ИЗ ТЕХ ЖЕ УСЛОВИЙ, что и сам предикат: разойтись они не
 * могут. И там, где вывод уже оплачен, он записан прямо в вывод прибора: отказ по
 * ARM64-машине ВЕРЕН. Механизм восстановления — про кадры x86-трансляции; в чисто
 * нативном ARM64-процессе транслятора нет, и включать его там нельзя.
 * Замер 31.08: во всех 10 журналах мишеней отказ один и тот же —
 * `wowteb=0 peb=1 image=1 machine=0xaa64`, то есть только проверка машины.
 * Кто прыгает в частную RW-страницу в таких процессах — отдельная задача, НЕ эта. */
static const char *macrunner_hb_boundary_reject_reason( CONTEXT *context )
{
    TEB *teb = NtCurrentTeb();
    IMAGE_NT_HEADERS *nt;

    if (!context) return "no-context";
    if (!teb) return "no-teb";
    if (teb->WowTebOffset) return "wow64-thread";
    if (!teb->Peb) return "no-peb";
    if (!teb->Peb->ImageBaseAddress) return "no-image";
    if (!(nt = RtlImageNtHeader( teb->Peb->ImageBaseAddress ))) return "no-pe-header";
    switch (nt->FileHeader.Machine)
    {
    case IMAGE_FILE_MACHINE_AMD64:
    case IMAGE_FILE_MACHINE_ARM64EC:
        return "predicate-passed-reject-elsewhere";
    case IMAGE_FILE_MACHINE_ARM64:
        /* ОТКАЗ ВЕРЕН — не «чините» его добавлением 0xAA64 в перечень. */
        return "main-image-arm64-REJECT-IS-CORRECT-x86-recovery-not-applicable";
    case IMAGE_FILE_MACHINE_I386:
        return "main-image-i386";
    default:
        return "main-image-other-machine";
    }
}

static BOOL macrunner_hb_recover_native_dispatch_boundary( DISPATCHER_CONTEXT *dispatch,
                                                           CONTEXT *context, DWORD64 pc )
{
    struct macrunner_hb_syscall_frame *frame, *resume;
    TEB *teb = NtCurrentTeb();
    ULONG_PTR stack_lo = teb ? (ULONG_PTR)teb->Tib.StackLimit : 0;
    ULONG_PTR stack_hi = teb ? (ULONG_PTR)teb->Tib.StackBase : 0;
    const char *bad_pc = NULL, *source = "current-frame";
    BOOL host_frame = FALSE;
    static unsigned int report_count, reject_count;
    DWORD tid = teb ? HandleToULong( teb->ClientId.UniqueThread ) : 0;
    LDR_DATA_TABLE_ENTRY *module = NULL;
    IMAGE_NT_HEADERS *nt;
    char section_name[9];
    DWORD section_characteristics = 0;

    if (!context || !macrunner_hb_is_x64_main_process())
    {
        if (reject_count++ < 16)
        {
            /* ★ 2026-08-18, лейн ЛЕСТНИЦА, итерация 2355 — РАЗЛИЧИТЬ, ЧТО ИМЕННО ОТКАЗАЛО.
             *
             * Дымовой набор (2353) нашёл этот отказ у блокнота x64: 52 с, `c0000005`, и
             * `reason=not-x64-main-process`. Но предикат (строка 96) отказывает по ТРЁМ разным
             * причинам — нет TEB/PEB/образа, поток числится WOW64 (`WowTebOffset`), либо машина
             * главного образа не AMD64/ARM64EC, — а печать называет их одним словом.
             *
             * По правилу «маркер, не различающий причины, для вывода негоден» печатаем сами
             * величины: `WowTebOffset`, наличие PEB и образа, и `Machine` заголовка. Прогон
             * блокнота стоит 52 с, так что это дешевле любой догадки. */
            TEB *dbg_teb = NtCurrentTeb();
            IMAGE_NT_HEADERS *dbg_nt = (dbg_teb && dbg_teb->Peb && dbg_teb->Peb->ImageBaseAddress)
                                       ? RtlImageNtHeader( dbg_teb->Peb->ImageBaseAddress ) : NULL;
            MESSAGE( "macrunner-hb-native-dispatch-boundary-reject: tid=%04lx "
                     "pc=%p frame=%p reason=%s wowteb=%u peb=%d image=%d machine=0x%x "
                     "imagebase=%p sizeofimage=0x%x pid=%04lx образ=%s\n",
                     tid, (void *)(ULONG_PTR)pc, NULL,
                     macrunner_hb_boundary_reject_reason( context ),
                     dbg_teb ? (unsigned)dbg_teb->WowTebOffset : 0u,
                     (dbg_teb && dbg_teb->Peb) ? 1 : 0,
                     (dbg_teb && dbg_teb->Peb && dbg_teb->Peb->ImageBaseAddress) ? 1 : 0,
                     dbg_nt ? (unsigned)dbg_nt->FileHeader.Machine : 0u,
                     (dbg_teb && dbg_teb->Peb) ? dbg_teb->Peb->ImageBaseAddress : NULL,
                     dbg_nt ? (unsigned)dbg_nt->OptionalHeader.SizeOfImage : 0u,
                     dbg_teb ? HandleToULong( dbg_teb->ClientId.UniqueProcess ) : 0ul,
                     (dbg_teb && dbg_teb->Peb && dbg_teb->Peb->ProcessParameters)
                         ? debugstr_w( dbg_teb->Peb->ProcessParameters->ImagePathName.Buffer )
                         : "(нет)" );
        }
        return FALSE;
    }
    if (!(frame = macrunner_hb_current_syscall_frame()))
    {
        /* MacRunner 2026-08-03 — "no syscall frame" is not the same as "nothing to resume from".
         *
         * This early return is what stands between the scene activation and the menu.  Compared
         * line by line against the run that reached the MAIN MENU on 2026-07-28: both emit the
         * same eleven `Couldn't find a UIManager`, both start the same extra loader thread, both
         * reopen the translation cache — and only ours carries, in that exact window,
         * `reason=no-current-syscall-frame` followed by `action=stop-unwind`.  The exception is
         * then never delivered, the thread that was about to drive PreselectOption.HighlightDefault
         * dies, and the run stops at 7 of the 135 language-flow events the successful run produced.
         *
         * Today's host-frame acceptance cannot help here — it lives further down, past this
         * return.  A thread faulting outside any unix call still has a link register, and that is
         * the same kind of candidate this function already accepts when prev_frame is NULL and it
         * falls back to the current frame.  So offer it to the SAME acceptance tests instead of
         * refusing before them: if they reject it, behaviour is byte-identical to before.
         *
         * Gated; MACRUNNER_HB_RECOVER_NO_FRAME=0 restores the plain refusal. */
        DWORD64 lr = context->Lr;

        if (!macrunner_hb_recover_no_frame_enabled() || !lr || lr == pc ||
            (!macrunner_hb_is_plausible_recovered_pc( lr, NULL ) &&
             !macrunner_hb_pc_in_host_unix_window( lr )))
        {
            if (reject_count++ < 16)
                MESSAGE( "macrunner-hb-native-dispatch-boundary-reject: tid=%04lx "
                         "pc=%p frame=%p lr=%p reason=no-current-syscall-frame\n",
                         tid, (void *)(ULONG_PTR)pc, NULL, (void *)(ULONG_PTR)lr );
            return FALSE;
        }
        if (report_count++ < 32)
            MESSAGE( "macrunner-hb-no-frame-resume: tid=%04lx pc=%p lr=%p sp=%016I64x\n",
                     tid, (void *)(ULONG_PTR)pc, (void *)(ULONG_PTR)lr, context->Sp );
        dispatch->ImageBase = 0;
        dispatch->FunctionEntry = NULL;
        dispatch->HandlerData = NULL;
        dispatch->EstablisherFrame = context->Sp;
        dispatch->LanguageHandler = NULL;
        context->Pc = lr;
        context->ContextFlags |= CONTEXT_UNWOUND_TO_CALL;
        return TRUE;
    }

    resume = frame->prev_frame;
    if (resume && resume != frame && resume->pc && resume->sp)
        source = "prev-frame";
    else
        resume = frame;

    if (!resume->pc || !resume->sp)
    {
        if (reject_count++ < 16)
            MESSAGE( "macrunner-hb-native-dispatch-boundary-reject: tid=%04lx "
                     "pc=%p frame=%p frame_pc=%p frame_lr=%p prev=%p source=%s reason=%s\n",
                     tid, (void *)(ULONG_PTR)pc, frame, (void *)(ULONG_PTR)frame->pc,
                     (void *)(ULONG_PTR)frame->lr, frame->prev_frame, source,
                      !resume->pc ? "resume-pc-null" : "resume-sp-null" );
        return FALSE;
    }
    if (resume == frame && !frame->prev_frame &&
        LdrFindEntryForAddress( (void *)(ULONG_PTR)resume->pc, &module ) == STATUS_SUCCESS &&
        module && macrunner_hb_arm64x_code_range_kind( (ULONG_PTR)module->DllBase, resume->pc ) == 0)
    {
        /* MacRunner 2026-08-03 — the frame is real, its pc is guest x64 code, and there is no prev
         * to unwind to.  This refusal is what drops the exception and kills the thread that would
         * have driven PreselectOption.HighlightDefault: the run stops at 7 of the 135
         * language-flow events the 2026-07-28 menu run produced, and this rejection sits in
         * exactly that window while the July log has none.
         *
         * The engine knows where the guest stands even when the host frame chain ends; the PE side
         * does not.  Ask it and report.  Reporting only, deliberately: resuming ARM64 execution at
         * a guest x64 address would be wrong, and the correct target — delivering into the guest
         * SEH chain, as the 2026-06-24 Fix-C spec describes — needs that position as its input.
         * This measurement says whether the position is available at all before anything is built
         * on top of it. */
        if (macrunner_hb_guest_ctx_lookup)
        {
            UINT64 gpc = 0, gsp = 0;

            if (macrunner_hb_guest_ctx_lookup( tid, &gpc, &gsp ) && report_count++ < 32)
                MESSAGE( "macrunner-hb-guest-position: tid=%04lx frame_pc=%p "
                         "guest_pc=%p guest_sp=%p\n",
                         tid, (void *)(ULONG_PTR)frame->pc,
                         (void *)(ULONG_PTR)gpc, (void *)(ULONG_PTR)gsp );
        }
        if (reject_count++ < 16)
            MESSAGE( "macrunner-hb-native-dispatch-boundary-reject: tid=%04lx "
                     "pc=%p frame=%p frame_pc=%p frame_lr=%p prev=%p source=%s "
                     "reason=current-x64-frame-no-prev\n",
                     tid, (void *)(ULONG_PTR)pc, frame, (void *)(ULONG_PTR)frame->pc,
                     (void *)(ULONG_PTR)frame->lr, frame->prev_frame, source );
        return FALSE;
    }
    if (resume != frame && macrunner_hb_pc_inside_syscall_frame( resume->pc, frame ))
        return FALSE;

    if (!macrunner_hb_is_plausible_recovered_pc( resume->pc, &bad_pc ))
    {
        if (!macrunner_hb_find_pc_section( resume->pc, section_name, &section_characteristics ))
            bad_pc = "pc-not-code";
        else if (!(section_characteristics & IMAGE_SCN_MEM_EXECUTE))
            bad_pc = "pc-nonexec-section";
        else if (LdrFindEntryForAddress( (void *)(ULONG_PTR)resume->pc, &module ) != STATUS_SUCCESS ||
                 !module || !(nt = RtlImageNtHeader( module->DllBase )))
            bad_pc = "pc-module-missing";
        else if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
                 nt->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64EC)
            bad_pc = NULL;
        else if (bad_pc && !strcmp( bad_pc, "pc-x64-code-range" ))
            bad_pc = NULL;
        else if (bad_pc && strcmp( bad_pc, "pc-x64-code-range" ))
            bad_pc = "pc-not-recoverable-code";
    }

    if (bad_pc && macrunner_hb_recover_host_frame_enabled() &&
        macrunner_hb_pc_in_host_unix_window( resume->pc ))
    {
        static unsigned int host_accept_count;

        if (host_accept_count++ < 32)
            MESSAGE( "macrunner-hb-native-dispatch-host-frame-accept: tid=%04lx pc=%p "
                     "resume_pc=%p resume_lr=%p resume_sp=%p source=%s was=%s\n",
                     tid, (void *)(ULONG_PTR)pc, (void *)(ULONG_PTR)resume->pc,
                     (void *)(ULONG_PTR)resume->lr, (void *)(ULONG_PTR)resume->sp,
                     source, bad_pc );
        bad_pc = NULL;
        host_frame = TRUE;
    }

    if (bad_pc)
    {
        if (reject_count++ < 16)
            MESSAGE( "macrunner-hb-native-dispatch-boundary-reject: tid=%04lx "
                     "pc=%p frame=%p frame_pc=%p frame_lr=%p prev=%p prev_pc=%p "
                     "prev_lr=%p prev_sp=%p source=%s reason=%s\n",
                     tid, (void *)(ULONG_PTR)pc, frame, (void *)(ULONG_PTR)frame->pc,
                     (void *)(ULONG_PTR)frame->lr, frame->prev_frame,
                     (void *)(ULONG_PTR)resume->pc, (void *)(ULONG_PTR)resume->lr,
                     (void *)(ULONG_PTR)resume->sp, source,
                     bad_pc ? bad_pc : "bad-prev-pc" );
        return FALSE;
    }
    /* ★★★★★ ИТЕРАЦИЯ 143 (лейн УСТАНОВЩИКИ) — `teb->Tib.Stack*` НЕ ЕДИНСТВЕННЫЙ СТЕК.
     *
     * Замер 142: состояние отвергнуто как `bad-prev-sp` при prev_sp=0x11220FB70 и
     * stack=0x1111D8000-0x1121D0000. Отвергнутый диапазон ровно 0xFF8000 = 16 МБ —
     * похоже, TEB в тот момент держал МОСТОВОЙ стек (движок подменяет поля TEB на
     * время вызова ARM64-PE, `unix/macrunner_hb.c` ~19870), а исходный отложен в
     * `macrunner_hb_original_stack_*`. Тогда отказ ложный.
     *
     * Печать ниже стоит и при ВЫКЛЮЧЕННОМ гейте: это и есть замер — она называет,
     * чей это стек, не меняя поведения. Приём (гейт `MACRUNNER_HB_KNOWN_STACK`,
     * умолчание 0) включается отдельно, уже зная ответ. */
    {
        static int mr_ks_gate = -1, mr_ks_n;
        if (!host_frame && stack_lo && stack_hi &&
            (resume->sp < stack_lo || resume->sp + 0x10 < resume->sp ||
             resume->sp + 0x10 > stack_hi) && macrunner_hb_known_stack_lookup)
        {
            UINT64 ks_lo = 0, ks_hi = 0;
            int ks_kind = 0;
            int ks_ok = macrunner_hb_known_stack_lookup( resume->sp, &ks_lo, &ks_hi, &ks_kind );

            if (mr_ks_n++ < 16)
                MESSAGE( "macrunner-hb-known-stack: sp=%p чей=%s извест=%p-%p teb=%p-%p\n",
                         (void *)(ULONG_PTR)resume->sp,
                         ks_kind == 1 ? "мостовой" : ks_kind == 2 ? "исходный" : "НИ-ОДИН",
                         (void *)(ULONG_PTR)ks_lo, (void *)(ULONG_PTR)ks_hi,
                         (void *)stack_lo, (void *)stack_hi );
            if (mr_ks_gate < 0)
            {
                /* getenv на PE-стороне ntdll не линкуется — та же идиома, что ниже (~1580). */
                static const WCHAR nameW[] = {'M','A','C','R','U','N','N','E','R','_','H','B','_','K','N','O','W','N','_','S','T','A','C','K',0};
                WCHAR value[4] = { 0 };
                UNICODE_STRING nm, val;

                RtlInitUnicodeString( &nm, nameW );
                val.Buffer = value;
                val.Length = 0;
                val.MaximumLength = sizeof(value);
                mr_ks_gate = (RtlQueryEnvironmentVariable_U( NULL, &nm, &val ) != STATUS_VARIABLE_NOT_FOUND &&
                              value[0] && value[0] != '0') ? 1 : 0;
            }
            if (ks_ok && mr_ks_gate)
            {
                /* стек опознан — отказа нет, границы расширяем на него */
                stack_lo = (ULONG_PTR)ks_lo;
                stack_hi = (ULONG_PTR)ks_hi;
            }
        }
    }

    if (!host_frame && stack_lo && stack_hi &&
        (resume->sp < stack_lo || resume->sp + 0x10 < resume->sp ||
         resume->sp + 0x10 > stack_hi))
    {
        if (reject_count++ < 16)
            MESSAGE( "macrunner-hb-native-dispatch-boundary-reject: tid=%04lx "
                     "pc=%p frame=%p frame_pc=%p prev=%p prev_pc=%p prev_sp=%p "
                     "stack=%p-%p source=%s reason=bad-prev-sp\n",
                     tid, (void *)(ULONG_PTR)pc, frame, (void *)(ULONG_PTR)frame->pc,
                     frame->prev_frame, (void *)(ULONG_PTR)resume->pc,
                     (void *)(ULONG_PTR)resume->sp, (void *)stack_lo, (void *)stack_hi,
                     source );
        return FALSE;
    }

    if (report_count++ < 32)
        MESSAGE( "macrunner-hb-native-dispatch-boundary-recovered: tid=%04lx "
                 "pc=%p image=%p frame=%p frame_pc=%p frame_lr=%p prev=%p "
                 "guest_pc=%p guest_lr=%p guest_sp=%p source=%s stack=%p-%p\n",
                 tid, (void *)(ULONG_PTR)pc, dispatch ? (void *)(ULONG_PTR)dispatch->ImageBase : NULL,
                 frame, (void *)(ULONG_PTR)frame->pc, (void *)(ULONG_PTR)frame->lr,
                 frame->prev_frame, (void *)(ULONG_PTR)resume->pc, (void *)(ULONG_PTR)resume->lr,
                 (void *)(ULONG_PTR)resume->sp, source, (void *)stack_lo, (void *)stack_hi );

    /* PATHB33 2026-08-03: with the host-frame acceptance a NULL-call incident recovers here
     * and never reaches the stop-unwind path where the naming dump lived — and the process
     * still died unhandled 2.2 s later with nothing printed.  Name the NULL slot from this
     * path too.  Fault-time registers are still in *context (the restore below overwrites
     * them), and pc==0 keeps this off every non-NULL-call recovery.  Fire-once per process:
     * one incident is enough and the dump is ~40 lines. */
    if (!pc && macrunner_hb_current_exception_record &&
        macrunner_hb_current_exception_record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        !macrunner_hb_current_exception_record->ExceptionAddress)
    {
        static unsigned int nullcall_diag_fired;
        if (!nullcall_diag_fired++)
            macrunner_hb_nullcall_diagnose( context );
    }

    macrunner_hb_restore_syscall_prev_frame_context( context, resume );
    context->ContextFlags |= CONTEXT_UNWOUND_TO_CALL;
    dispatch->EstablisherFrame = context->Sp;
    dispatch->LanguageHandler = NULL;
    dispatch->HandlerData = NULL;
    return TRUE;
}

static BOOL macrunner_hb_fix_syscall_data_boundary_exception( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    struct macrunner_hb_syscall_frame *frame, *prev;
    static unsigned int report_count;
    DWORD tid = HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );

    if (!rec || !context) return FALSE;
    if (rec->ExceptionCode != STATUS_DATATYPE_MISALIGNMENT || rec->ExceptionFlags)
        return FALSE;
    if (!macrunner_hb_is_x64_main_process()) return FALSE;
    if (!(frame = macrunner_hb_current_syscall_frame())) return FALSE;
    if (!macrunner_hb_pc_inside_syscall_frame( context->Pc, frame )) return FALSE;
    if (!(prev = frame->prev_frame) || !prev->pc || !prev->sp) return FALSE;
    if (macrunner_hb_pc_inside_syscall_frame( prev->pc, frame )) return FALSE;

    if (report_count++ < 64)
        MESSAGE( "macrunner-hb-arm64ec-syscall-data-repair: tid=%04lx pc=%p lr=%p "
                 "frame=%p bad_frame_pc=%p bad_frame_lr=%p prev=%p prev_pc=%p "
                 "prev_lr=%p prev_sp=%p resume=continue-prev-frame\n",
                 tid, (void *)(ULONG_PTR)context->Pc, (void *)(ULONG_PTR)context->Lr,
                 frame, (void *)(ULONG_PTR)frame->pc, (void *)(ULONG_PTR)frame->lr,
                 prev, (void *)(ULONG_PTR)prev->pc, (void *)(ULONG_PTR)prev->lr,
                 (void *)(ULONG_PTR)prev->sp );

    macrunner_hb_restore_syscall_prev_frame_context( context, prev );
    rec->ExceptionAddress = (void *)(ULONG_PTR)context->Pc;
    return TRUE;
}

static BOOL macrunner_hb_is_arm64ec_unwind_scaffold_overshoot( ULONG64 establisher_frame,
                                                               void *end_frame )
{
    struct macrunner_hb_syscall_frame *frame;
    TEB *teb = NtCurrentTeb();
    ULONG_PTR stack_lo = teb ? (ULONG_PTR)teb->Tib.StackLimit : 0;
    ULONG_PTR stack_hi = teb ? (ULONG_PTR)teb->Tib.StackBase : 0;
    ULONG_PTR end = (ULONG_PTR)end_frame;
    ULONG64 delta;

    if (!macrunner_hb_is_x64_main_process()) return FALSE;
    if (!end_frame || !stack_lo || !stack_hi) return FALSE;
    if (end < stack_lo || end > stack_hi) return FALSE;
    if (establisher_frame < stack_lo || establisher_frame > stack_hi) return FALSE;
    if (establisher_frame <= end) return FALSE;

    delta = establisher_frame - end;
    if (delta > 0x800) return FALSE;

    if (!(frame = macrunner_hb_current_syscall_frame())) return FALSE;
    if (!frame->pc || !frame->sp) return FALSE;
    if (frame->sp < stack_lo || frame->sp > stack_hi) return FALSE;
    return TRUE;
}

static void macrunner_hb_trace_tagged_exception_context( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    static unsigned int report_count;

    if (!rec || !context) return;
    if (rec->ExceptionCode != STATUS_DATATYPE_MISALIGNMENT && !(context->Pc & 1) && !(context->Lr & 1))
        return;
    if (report_count++ >= 64) return;

    MESSAGE( "macrunner-hb-arm64ec-exception-context: code=%08lx flags=%08lx pc=%p lr=%p "
             "sp=%016I64x x64main=%u\n",
             rec->ExceptionCode, rec->ExceptionFlags, (void *)context->Pc, (void *)context->Lr,
             context->Sp, macrunner_hb_is_x64_main_process() );
}

static void macrunner_hb_copy_unicode_ascii( char *dst, size_t dst_len, const UNICODE_STRING *src )
{
    unsigned int i, len;

    if (!dst_len) return;
    dst[0] = 0;
    if (!src || !src->Buffer) return;

    len = min( src->Length / sizeof(WCHAR), (dst_len - 1) );
    for (i = 0; i < len; i++)
    {
        WCHAR ch = src->Buffer[i];
        dst[i] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '?';
    }
    dst[len] = 0;
}

static BOOL macrunner_hb_is_unityplayer_module( const LDR_DATA_TABLE_ENTRY *module )
{
    static const WCHAR nameW[] =
        {'U','n','i','t','y','P','l','a','y','e','r','.','d','l','l'};
    unsigned int i, len;

    if (!module || !module->BaseDllName.Buffer) return FALSE;
    if (module->SizeOfImage < 0x1f404a8 + sizeof(ULONG64)) return FALSE;
    len = module->BaseDllName.Length / sizeof(WCHAR);
    if (len != ARRAY_SIZE(nameW)) return FALSE;

    for (i = 0; i < len; i++)
    {
        WCHAR a = module->BaseDllName.Buffer[i];
        WCHAR b = nameW[i];

        if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
        if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
        if (a != b) return FALSE;
    }
    return TRUE;
}

static BOOL macrunner_hb_query_env_uint( const WCHAR *nameW, unsigned int *value )
{
    WCHAR buffer[32];
    UNICODE_STRING name, val;
    unsigned int i, result = 0;

    RtlInitUnicodeString( &name, nameW );
    val.Length = 0;
    val.MaximumLength = sizeof(buffer);
    val.Buffer = buffer;
    if (RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_SUCCESS)
        return FALSE;

    buffer[min( val.Length / sizeof(WCHAR), ARRAY_SIZE(buffer) - 1 )] = 0;
    for (i = 0; buffer[i] >= '0' && buffer[i] <= '9'; i++)
        result = result * 10 + buffer[i] - '0';
    if (value) *value = result;
    return i > 0;
}

static BOOL macrunner_hb_trace_first_chance_enabled( unsigned int *budget )
{
    static BOOL initialized, enabled;
    static unsigned int trace_budget;
    static const WCHAR traceW[] =
        {'M','A','C','R','U','N','N','E','R','_','H','B','_','T','R','A','C','E','_',
         'F','I','R','S','T','_','C','H','A','N','C','E',0};
    static const WCHAR budgetW[] =
        {'M','A','C','R','U','N','N','E','R','_','H','B','_','T','R','A','C','E','_',
         'F','I','R','S','T','_','C','H','A','N','C','E','_','B','U','D','G','E','T',0};
    unsigned int value;

    if (!initialized)
    {
        if (macrunner_hb_query_env_uint( traceW, &value ) && value)
        {
            enabled = TRUE;
            trace_budget = 256;
            if (macrunner_hb_query_env_uint( budgetW, &value ) && value)
                trace_budget = value;
        }
        initialized = TRUE;
    }
    if (budget) *budget = trace_budget;
    return enabled;
}

static void macrunner_hb_trace_first_chance_exception( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    static unsigned int report_count;
    unsigned int budget;
    TEB *teb = NtCurrentTeb();
    LDR_DATA_TABLE_ENTRY *module = NULL;
    LDR_DATA_TABLE_ENTRY *lr_module = NULL;
    NTSTATUS ldr_status;
    NTSTATUS lr_ldr_status;
    ULONG_PTR pc, lr, module_base = 0, lr_module_base = 0, rva = 0, lr_rva = 0;
    char module_name[96] = "-";
    char lr_module_name[96] = "-";

    if (!rec || !context || !teb) return;
    if (!macrunner_hb_trace_first_chance_enabled( &budget )) return;
    if (report_count++ >= budget) return;
    if (!macrunner_hb_is_x64_main_process()) return;

    pc = (ULONG_PTR)context->Pc;
    lr = (ULONG_PTR)context->Lr;
    ldr_status = LdrFindEntryForAddress( (void *)pc, &module );
    if (ldr_status == STATUS_SUCCESS && module)
    {
        module_base = (ULONG_PTR)module->DllBase;
        rva = pc - module_base;
        macrunner_hb_copy_unicode_ascii( module_name, sizeof(module_name), &module->BaseDllName );
    }
    lr_ldr_status = LdrFindEntryForAddress( (void *)lr, &lr_module );
    if (lr_ldr_status == STATUS_SUCCESS && lr_module)
    {
        lr_module_base = (ULONG_PTR)lr_module->DllBase;
        lr_rva = lr - lr_module_base;
        macrunner_hb_copy_unicode_ascii( lr_module_name, sizeof(lr_module_name),
                                         &lr_module->BaseDllName );
    }

    MESSAGE( "macrunner-hb-seh-first-chance: tid=%04lx code=%08lx flags=%08lx "
             "addr=%p pc=%p lr=%p sp=%016I64x fp=%p ldr=%08lx module=%p "
             "rva=%08Ix name=%s lr_ldr=%08lx lr_module=%p lr_rva=%08Ix lr_name=%s "
             "stack=%p-%p params=%lu info0=%016I64x info1=%016I64x\n",
             HandleToULong( teb->ClientId.UniqueThread ), rec->ExceptionCode, rec->ExceptionFlags,
             rec->ExceptionAddress, (void *)pc, (void *)lr,
             context->Sp, (void *)(ULONG_PTR)context->Fp, ldr_status, (void *)module_base,
             rva, module_name, lr_ldr_status, (void *)lr_module_base, lr_rva, lr_module_name,
             teb->Tib.StackLimit, teb->Tib.StackBase, rec->NumberParameters,
             rec->NumberParameters > 0 ? rec->ExceptionInformation[0] : 0,
             rec->NumberParameters > 1 ? rec->ExceptionInformation[1] : 0 );

    /* MacRunner: any fault inside UnityPlayer -> dump its graphics IAT slots, to
     * see whether D3D11CreateDevice[1a02070] is the rebound thunk (non-NULL) or 0
     * (the create-fn guard at UnityPlayer 0x8e276f `cmpq $0,[1a02070]` bails E_FAIL
     * if NULL -> device @1f40460 stays NULL -> QI fault at 0x8e2acb). */
    if (module_base && rva && macrunner_hb_is_unityplayer_module( module ) && rva < module->SizeOfImage)
    {
        char *u = (char *)module_base;
        __TRY {
            MESSAGE( "macrunner-hb-unityiat: faultrva=0x%llx D3D11On12[1a02068]=%p D3D11CreateDevice[1a02070]=%p "
                     "CreateDXGIFactory2[1a02098]=%p CreateDXGIFactory[1a020a0]=%p device[1f40460]=%p factory[1f404a8]=%p\n",
                     (unsigned long long)rva,
                     (void *)*(ULONG64 *)(u + 0x1a02068), (void *)*(ULONG64 *)(u + 0x1a02070),
                     (void *)*(ULONG64 *)(u + 0x1a02098), (void *)*(ULONG64 *)(u + 0x1a020a0),
                     (void *)*(ULONG64 *)(u + 0x1f40460), (void *)*(ULONG64 *)(u + 0x1f404a8) );
        } __EXCEPT(macrunner_hb_pe_scan_fault) { } __ENDTRY
    }

    /* NULL/low call (execute AV at addr ~0): the immediate caller is lost
     * (lr=0 for a tail-br), so walk the saved fp-chain to recover the calling
     * frame's module/rva — pins which DXMT/D3D11 function jumped through a NULL
     * pointer. Also dump x8/x9 (likely-NULL call targets) + x19/x0 (object). */
    if (pc < 0x10000)
    {
        ULONG_PTR fp = (ULONG_PTR)context->Fp;
        int lvl;
        for (lvl = 0; lvl < 5 && fp && !(fp & 7); lvl++)
        {
            ULONG_PTR caller_fp = 0, caller_lr = 0, crva = 0, cbase = 0;
            LDR_DATA_TABLE_ENTRY *cmod = NULL;
            char cname[96] = "-";
            __TRY { caller_fp = ((const ULONG_PTR *)fp)[0]; caller_lr = ((const ULONG_PTR *)fp)[1]; }
            __EXCEPT(macrunner_hb_pe_scan_fault) { break; }
            __ENDTRY
            if (LdrFindEntryForAddress( (void *)caller_lr, &cmod ) == STATUS_SUCCESS && cmod)
            {
                cbase = (ULONG_PTR)cmod->DllBase;
                crva = caller_lr - cbase;
                macrunner_hb_copy_unicode_ascii( cname, sizeof(cname), &cmod->BaseDllName );
            }
            MESSAGE( "macrunner-hb-nullcall-frame: lvl=%d fp=%p caller_lr=%p module=%s base=%p rva=0x%llx "
                     "x8=%p x9=%p x19=%p x0=%p x1=%p\n",
                     lvl, (void *)fp, (void *)caller_lr, cname, (void *)cbase, (unsigned long long)crva,
                     (void *)(ULONG_PTR)context->X[8], (void *)(ULONG_PTR)context->X[9],
                     (void *)(ULONG_PTR)context->X[19], (void *)(ULONG_PTR)context->X[0],
                     (void *)(ULONG_PTR)context->X[1] );
            if (caller_fp <= fp) break;
            fp = caller_fp;
        }
        /* The execute-at-0 fault is in NATIVE ARM64EC code (a blr/br to a 0 target),
         * so dump the registers NATIVELY (the earlier x64-EC decode was garbage).
         * Map each to module/rva: r30=Lr (native caller after the blr), r16/r17 =
         * branch-target/veneer regs (which is 0?), r29=Fp, r31=Sp, r32=Pc. */
        {
            ULONG_PTR regs[33];
            int i;
            for (i = 0; i < 29; i++) regs[i] = (ULONG_PTR)context->X[i];
            regs[29] = (ULONG_PTR)context->Fp;
            regs[30] = (ULONG_PTR)context->Lr;
            regs[31] = (ULONG_PTR)context->Sp;
            regs[32] = (ULONG_PTR)context->Pc;
            for (i = 0; i < 33; i++)
            {
                ULONG_PTR v = regs[i], rva = 0; LDR_DATA_TABLE_ENTRY *m = NULL; char mn[64] = "-";
                if (v && LdrFindEntryForAddress( (void *)v, &m ) == STATUS_SUCCESS && m)
                { rva = v - (ULONG_PTR)m->DllBase; macrunner_hb_copy_unicode_ascii( mn, sizeof(mn), &m->BaseDllName ); }
                MESSAGE( "macrunner-hb-nullcall-natreg: r%d=%p %s+0x%llx\n",
                         i, (void *)v, mn, (unsigned long long)rva );
            }
        }
    }
}

static BOOL macrunner_hb_fix_tagged_arm64ec_misalignment( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    static unsigned int report_count;
    DWORD64 pc, fixed_pc;

    if (!rec || !context) return FALSE;
    if (rec->ExceptionCode != STATUS_DATATYPE_MISALIGNMENT) return FALSE;
    if (rec->ExceptionFlags) return FALSE;
    if (!macrunner_hb_is_x64_main_process()) return FALSE;

    pc = context->Pc;
    if (!(pc & 1)) return FALSE;
    if (pc < MACRUNNER_HB_HOST_BOUNDARY_MIN || pc >= MACRUNNER_HB_HOST_BOUNDARY_MAX)
        return FALSE;
    if (context->Lr && context->Lr != pc) return FALSE;

    fixed_pc = pc & ~(DWORD64)1;
    if (report_count++ < 64)
        MESSAGE( "macrunner-hb-arm64ec-tagged-pc: exception=%08lx pc=%p lr=%p fixed=%p sp=%016I64x\n",
                 rec->ExceptionCode, (void *)pc, (void *)context->Lr, (void *)fixed_pc, context->Sp );

    context->Pc = fixed_pc;
    macrunner_hb_note_pc_set( 3, context->Pc, context->Sp );
    if (context->Lr == pc) context->Lr = fixed_pc;
    rec->ExceptionAddress = (void *)(ULONG_PTR)fixed_pc;
    return TRUE;
}

/*******************************************************************
 *         syscalls
 */
#define SYSCALL_ENTRY(id,name,args) __ASM_SYSCALL_FUNC( id, name )
ALL_SYSCALLS
#undef SYSCALL_ENTRY


/**************************************************************************
 *		__chkstk (NTDLL.@)
 *
 * Supposed to touch all the stack pages, but we shouldn't need that.
 */
__ASM_GLOBAL_FUNC( __chkstk, "ret")


/***********************************************************************
 *		RtlCaptureContext (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( RtlCaptureContext,
                    "str xzr, [x0, #0x8]\n\t"        /* context->X0 */
                    "stp x1, x2, [x0, #0x10]\n\t"    /* context->X1,X2 */
                    "stp x3, x4, [x0, #0x20]\n\t"    /* context->X3,X4 */
                    "stp x5, x6, [x0, #0x30]\n\t"    /* context->X5,X6 */
                    "stp x7, x8, [x0, #0x40]\n\t"    /* context->X7,X8 */
                    "stp x9, x10, [x0, #0x50]\n\t"   /* context->X9,X10 */
                    "stp x11, x12, [x0, #0x60]\n\t"  /* context->X11,X12 */
                    "stp x13, x14, [x0, #0x70]\n\t"  /* context->X13,X14 */
                    "stp x15, x16, [x0, #0x80]\n\t"  /* context->X15,X16 */
                    "stp x17, x18, [x0, #0x90]\n\t"  /* context->X17,X18 */
                    "stp x19, x20, [x0, #0xa0]\n\t"  /* context->X19,X20 */
                    "stp x21, x22, [x0, #0xb0]\n\t"  /* context->X21,X22 */
                    "stp x23, x24, [x0, #0xc0]\n\t"  /* context->X23,X24 */
                    "stp x25, x26, [x0, #0xd0]\n\t"  /* context->X25,X26 */
                    "stp x27, x28, [x0, #0xe0]\n\t"  /* context->X27,X28 */
                    "stp x29, xzr, [x0, #0xf0]\n\t"  /* context->Fp,Lr */
                    "mov x1, sp\n\t"
                    "stp x1, x30, [x0, #0x100]\n\t"  /* context->Sp,Pc */
                    "stp q0,  q1,  [x0, #0x110]\n\t" /* context->V[0-1] */
                    "stp q2,  q3,  [x0, #0x130]\n\t" /* context->V[2-3] */
                    "stp q4,  q5,  [x0, #0x150]\n\t" /* context->V[4-5] */
                    "stp q6,  q7,  [x0, #0x170]\n\t" /* context->V[6-7] */
                    "stp q8,  q9,  [x0, #0x190]\n\t" /* context->V[8-9] */
                    "stp q10, q11, [x0, #0x1b0]\n\t" /* context->V[10-11] */
                    "stp q12, q13, [x0, #0x1d0]\n\t" /* context->V[12-13] */
                    "stp q14, q15, [x0, #0x1f0]\n\t" /* context->V[14-15] */
                    "stp q16, q17, [x0, #0x210]\n\t" /* context->V[16-17] */
                    "stp q18, q19, [x0, #0x230]\n\t" /* context->V[18-19] */
                    "stp q20, q21, [x0, #0x250]\n\t" /* context->V[20-21] */
                    "stp q22, q23, [x0, #0x270]\n\t" /* context->V[22-23] */
                    "stp q24, q25, [x0, #0x290]\n\t" /* context->V[24-25] */
                    "stp q26, q27, [x0, #0x2b0]\n\t" /* context->V[26-27] */
                    "stp q28, q29, [x0, #0x2d0]\n\t" /* context->V[28-29] */
                    "stp q30, q31, [x0, #0x2f0]\n\t" /* context->V[30-31] */
                    "mov w1, #0x400000\n\t"          /* CONTEXT_ARM64 */
                    "movk w1, #0x7\n\t"              /* CONTEXT_FULL */
                    "str w1, [x0]\n\t"               /* context->ContextFlags */
                    "mrs x1, NZCV\n\t"
                    "str w1, [x0, #0x4]\n\t"         /* context->Cpsr */
                    "mrs x1, FPCR\n\t"
                    "str w1, [x0, #0x310]\n\t"       /* context->Fpcr */
                    "mrs x1, FPSR\n\t"
                    "str w1, [x0, #0x314]\n\t"       /* context->Fpsr */
                    "ret" )


/**********************************************************************
 * ARM64EC frame fallback for the plain-ARM64 dispatcher.
 *
 * ARM64X hybrid builtins keep the unwind data of their ARM64EC ranges in
 * the CHPE ExtraRFETable (AMD64 RUNTIME_FUNCTION/UNWIND_INFO format); the
 * ARM64-side RtlLookupFunctionEntry only consults the native ARM64 .pdata,
 * so unwinding through an EC frame used to raise STATUS_INVALID_DISPOSITION
 * and recurse (the c0000026 storms).  Walk the frame here by interpreting
 * the AMD64 unwind ops directly on the ARM64 context through the fixed
 * ARM64EC register mapping.  EC handlers are not invoked (frame walk only).
 */

struct macrunner_ec_runtime_function
{
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};

struct macrunner_ec_opcode
{
    BYTE offset;
    BYTE code : 4;
    BYTE info : 4;
};

struct macrunner_ec_unwind_info
{
    BYTE version : 3;
    BYTE flags : 5;
    BYTE prolog;
    BYTE count;
    BYTE frame_reg : 4;
    BYTE frame_offset : 4;
    struct macrunner_ec_opcode opcodes[1];
};

#ifndef UNW_FLAG_CHAININFO
#define UNW_FLAG_CHAININFO 4
#endif

#define MACRUNNER_EC_UWOP_PUSH_NONVOL     0
#define MACRUNNER_EC_UWOP_ALLOC_LARGE     1
#define MACRUNNER_EC_UWOP_ALLOC_SMALL     2
#define MACRUNNER_EC_UWOP_SET_FPREG       3
#define MACRUNNER_EC_UWOP_SAVE_NONVOL     4
#define MACRUNNER_EC_UWOP_SAVE_NONVOL_FAR 5
#define MACRUNNER_EC_UWOP_EPILOG          6
#define MACRUNNER_EC_UWOP_SAVE_XMM128     8
#define MACRUNNER_EC_UWOP_SAVE_XMM128_FAR 9
#define MACRUNNER_EC_UWOP_PUSH_MACHFRAME  10

/* x64 register number -> ARM64 context slot per the ARM64EC mapping */
static DWORD64 *macrunner_ec_int_reg( CONTEXT *context, unsigned int reg )
{
    switch (reg)
    {
    case 0:  return &context->X8;   /* rax */
    case 1:  return &context->X0;   /* rcx */
    case 2:  return &context->X1;   /* rdx */
    case 3:  return &context->X27;  /* rbx */
    case 4:  return &context->Sp;   /* rsp */
    case 5:  return &context->Fp;   /* rbp */
    case 6:  return &context->X25;  /* rsi */
    case 7:  return &context->X26;  /* rdi */
    case 8:  return &context->X2;   /* r8 */
    case 9:  return &context->X3;   /* r9 */
    case 10: return &context->X4;   /* r10 */
    case 11: return &context->X5;   /* r11 */
    case 12: return &context->X19;  /* r12 */
    case 13: return &context->X20;  /* r13 */
    case 14: return &context->X21;  /* r14 */
    case 15: return &context->X22;  /* r15 */
    }
    return NULL;
}

static int macrunner_ec_opcode_size( struct macrunner_ec_opcode op )
{
    switch (op.code)
    {
    case MACRUNNER_EC_UWOP_ALLOC_LARGE:
        return 2 + (op.info != 0);
    case MACRUNNER_EC_UWOP_SAVE_NONVOL:
    case MACRUNNER_EC_UWOP_SAVE_XMM128:
    case MACRUNNER_EC_UWOP_EPILOG:
        return 2;
    case MACRUNNER_EC_UWOP_SAVE_NONVOL_FAR:
    case MACRUNNER_EC_UWOP_SAVE_XMM128_FAR:
        return 3;
    default:
        return 1;
    }
}

static LONG CALLBACK macrunner_hb_pe_scan_fault( EXCEPTION_POINTERS *ep );

static IMAGE_ARM64EC_METADATA *macrunner_ec_module_metadata( ULONG_PTR base )
{
    const IMAGE_NT_HEADERS *nt;
    const IMAGE_LOAD_CONFIG_DIRECTORY *cfg;
    ULONG size;

    if (!base) return NULL;
    if (!(nt = RtlImageNtHeader( (void *)base ))) return NULL;
    cfg = RtlImageDirectoryEntryToData( (void *)base, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size );
    if (!cfg || size <= offsetof( IMAGE_LOAD_CONFIG_DIRECTORY, CHPEMetadataPointer )) return NULL;
    if (cfg->CHPEMetadataPointer <= base ||
        cfg->CHPEMetadataPointer >= base + nt->OptionalHeader.SizeOfImage)
        return NULL;
    return (IMAGE_ARM64EC_METADATA *)(ULONG_PTR)cfg->CHPEMetadataPointer;
}

/* ★★★★★ ИТЕРАЦИЯ 151, лейн УСТАНОВЩИКИ — ТИП ДИАПАЗОНА ЛЕЖИТ В ДВУХ БИТАХ, НЕ В ОДНОМ.
 *
 * Формат ARM64X: младшие два бита `StartOffset` — тип диапазона:
 *     0 = ARM64, 1 = ARM64EC, 2 = AMD64(x64).
 * Wine объявляет поле как `NativeCode : 1` (include/winnt.h:4082), то есть ОДИН бит,
 * и чтение через него даёт для ЧИСТОГО ARM64 (тип 0) `NativeCode = 0` — «не нативный»,
 * то есть x64. Ошибка ровно на нашем случае: встроенные модули собраны ARM64.
 *
 * Замер, которым это поймано: карта `msvcrt.dll` (метаданные RVA 0xf9aa8, версия 2)
 * содержит ТРИ записи — по одной каждого типа; `__getmainargs` (RVA 0x15798) лежит в
 * записи 0, диапазон 0x1000..0x75b70, тип 0 = ARM64. Бит 0 у неё равен нулю, поэтому
 * предикат объявлял её x64 — при том что живые байты по этому адресу (замер 150)
 * ARM64. Отсюда и отказ строгого гейта девяти законным целям.
 *
 * ЭТАЛОН РЯДОМ, В ЭТОМ ЖЕ ДЕРЕВЕ: `dlls/ntdll/unix/virtual.c:4218-4220` — код самого
 * Wine — читает ДВА бита (`StartOffset & ~3`, `(StartOffset & 0x3) != 1`). Разошлись
 * только три наши копии; правим все три разом, как и предписано правилом про
 * функции-близнецы.
 *
 * Гейт MACRUNNER_HB_ARM64X_2BIT СНЯТ 02.09.2026: правка безусловна,
 * выключенная ветка возвращала известный дефект (scripts/гейты.py).
 * возвращает прежнее однобитное чтение — это контрольная рука для замера. */
static int macrunner_hb_arm64x_2bit(void)
{
    static int gate = -1;

    if (gate < 0)
    {
        static const WCHAR nameW[] = {'M','A','C','R','U','N','N','E','R','_','H','B','_',
                                      'A','R','M','6','4','X','_','2','B','I','T',0};
        WCHAR value[4] = { 0 };
        UNICODE_STRING nm, val;

        RtlInitUnicodeString( &nm, nameW );
        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        /* умолчание ВКЛ: переменной нет -> 1; явный "0" -> 0 */
        gate = (RtlQueryEnvironmentVariable_U( NULL, &nm, &val ) != STATUS_VARIABLE_NOT_FOUND &&
                value[0] == '0') ? 0 : 1;
    }
    return gate;
}

static int macrunner_hb_arm64x_code_range_kind( ULONG_PTR base, DWORD64 pc )
{
    IMAGE_ARM64EC_METADATA *metadata = macrunner_ec_module_metadata( base );
    IMAGE_NT_HEADERS *nt;
    const IMAGE_CHPE_RANGE_ENTRY *map;
    DWORD64 rva;
    ULONG i, max_count;

    if (!metadata || !metadata->CodeMap || !metadata->CodeMapCount || pc < base) return -1;
    if (!(nt = RtlImageNtHeader( (void *)base )) || !nt->OptionalHeader.SizeOfImage) return -1;
    if (pc >= base + nt->OptionalHeader.SizeOfImage) return -1;
    if (metadata->CodeMap >= nt->OptionalHeader.SizeOfImage) return -1;

    max_count = (nt->OptionalHeader.SizeOfImage - metadata->CodeMap) / sizeof(*map);
    if (metadata->CodeMapCount > max_count) return -1;
    rva = pc - base;
    map = (const IMAGE_CHPE_RANGE_ENTRY *)(base + metadata->CodeMap);

    __TRY
    {
        for (i = 0; i < metadata->CodeMapCount; i++)
        {
            IMAGE_CHPE_RANGE_ENTRY entry;
            ULONG start, end;

            memcpy( &entry, &map[i], sizeof(entry) );
            start = macrunner_hb_arm64x_2bit() ? (entry.StartOffset & ~3u)
                                                : (entry.StartOffset & ~1u);
            if (entry.Length > ~start) continue;
            end = start + entry.Length;
            if (rva >= start && rva < end)
                return macrunner_hb_arm64x_2bit() ? (((entry.StartOffset & 3u) == 2u) ? 0 : 1)
                                                  : (entry.NativeCode ? 1 : 0);
        }
    }
    __EXCEPT(macrunner_hb_pe_scan_fault) {}
    __ENDTRY
    return -1;
}

static BOOL macrunner_hb_pc_unsafe_for_arm64_unwind( DISPATCHER_CONTEXT *dispatch,
                                                     CONTEXT *context, DWORD64 pc )
{
    TEB *teb = NtCurrentTeb();
    ULONG_PTR stack_lo = teb ? (ULONG_PTR)teb->Tib.StackLimit : 0;
    ULONG_PTR stack_hi = teb ? (ULONG_PTR)teb->Tib.StackBase : 0;
    ULONG_PTR sp = context ? (ULONG_PTR)context->Sp : 0;

    /* ★★★ 2026-08-18, итерация 2375 (приказ 185, класс Б) — ПОРЯДОК ПЕРЕВЁРНУТ.
     *
     * Было: всё ниже 512 ГБ объявлялось небезопасным для нативной раскрутки, и только потом
     * спрашивался род кодового диапазона. При двух полосах образов (замер 2365) это отсекало
     * целые модули по адресу, а не по свойству: у блокнота x64 и образ, и хозяйский ntdll
     * лежат ниже границы.
     *
     * Стало: сперва достоверный источник — таблица модулей через `arm64x_code_range_kind`;
     * константа применяется ТОЛЬКО когда модуль неизвестен (нет `dispatch->ImageBase`), то есть
     * как быстрый ответ на вопрос, на который иначе ответить нечем. */
    if (dispatch && dispatch->ImageBase)
    {
        if (macrunner_hb_arm64x_code_range_kind( dispatch->ImageBase, pc ) == 0)
            return TRUE;
    }
    else if (pc < MACRUNNER_HB_HOST_BOUNDARY_MAX) return TRUE;
    if (stack_lo && stack_hi && (!sp || sp < stack_lo || sp + 0x10 > stack_hi))
        return TRUE;
    return FALSE;
}

static BOOL macrunner_ec_virtual_unwind_frame( DISPATCHER_CONTEXT *dispatch, CONTEXT *context,
                                               DWORD64 pc )
{
    /* lld-built ARM64X hybrids carry NO unwind data at all for their EC
     * ranges (ExtraRFETable=0, x64-view exception dir zeroed by the ARM64X
     * fixups), so unwind by EPILOGUE SCAN: interpret forward from pc a
     * strict whitelist of ARM64 epilogue instructions until ret/br x30.
     * Any other instruction bails out to the old invalid-disposition path. */
    CONTEXT walk = *context;
    const DWORD *insn;
    unsigned int steps;
    BOOL done = FALSE, lr_restored = FALSE;
    const char *bad_pc = NULL;

    /* pc was just executing (it is a live frame address) — instructions
     * there are mapped; no LDR registration required (guest-arena module
     * copies are not in the loader list). */
    if (pc < 0x10000 || (pc & 3)) return FALSE;
    insn = (const DWORD *)(ULONG_PTR)pc;

    for (steps = 0; steps < 64 && !done; steps++, insn++)
    {
        DWORD op = *insn;

        /* the frame's own call instruction (pc points AT the bl/blr that
         * called the faulting child) — step over it */
        if (steps == 0 && ((op & 0xfc000000u) == 0x94000000u ||   /* bl */
                           (op & 0xfffffc1fu) == 0xd63f0000u))    /* blr */
            continue;

        if ((op & 0xffc003e0u) == 0xa94003e0u)        /* ldp xA, xB, [sp, #imm] */
        {
            unsigned int rt = op & 0x1f, rt2 = (op >> 10) & 0x1f;
            int imm = ((int)((op >> 15) & 0x7f) << 25) >> 22;  /* signed imm7 * 8 */
            if (rt < 31)  walk.X[rt]  = *(DWORD64 *)(walk.Sp + imm);
            if (rt2 < 31) walk.X[rt2] = *(DWORD64 *)(walk.Sp + imm + 8);
            if (rt == 30 || rt2 == 30) lr_restored = TRUE;
        }
        else if ((op & 0xffc003e0u) == 0xa8c003e0u)   /* ldp xA, xB, [sp], #imm (post-index) */
        {
            unsigned int rt = op & 0x1f, rt2 = (op >> 10) & 0x1f;
            int imm = ((int)((op >> 15) & 0x7f) << 25) >> 22;
            if (rt < 31)  walk.X[rt]  = *(DWORD64 *)walk.Sp;
            if (rt2 < 31) walk.X[rt2] = *(DWORD64 *)(walk.Sp + 8);
            walk.Sp += imm;
            if (rt == 30 || rt2 == 30) lr_restored = TRUE;
        }
        else if ((op & 0xffc003e0u) == 0xf94003e0u)   /* ldr xA, [sp, #imm] */
        {
            unsigned int rt = op & 0x1f;
            DWORD64 imm = ((op >> 10) & 0xfff) * 8;
            if (rt < 31) walk.X[rt] = *(DWORD64 *)(walk.Sp + imm);
            if (rt == 30) lr_restored = TRUE;
        }
        else if ((op & 0xffe00fe0u) == 0xf84007e0u)   /* ldr xA, [sp], #imm (post-index) */
        {
            unsigned int rt = op & 0x1f;
            int imm = ((int)((op >> 12) & 0x1ff) << 23) >> 23;
            if (rt < 31) walk.X[rt] = *(DWORD64 *)walk.Sp;
            walk.Sp += imm;
            if (rt == 30) lr_restored = TRUE;
        }
        else if ((op & 0xff8003ffu) == 0x910003ffu)   /* add sp, sp, #imm[, lsl #12] */
        {
            DWORD64 imm = (op >> 10) & 0xfff;
            if (op & 0x400000) imm <<= 12;
            walk.Sp += imm;
        }
        else if ((op & 0xff8003ffu) == 0x910003bfu)   /* add sp, x29, #imm (incl. mov sp, x29) */
        {
            DWORD64 imm = (op >> 10) & 0xfff;
            if (op & 0x400000) imm <<= 12;
            walk.Sp = walk.Fp + imm;
        }
        else if (op == 0xd65f03c0u || op == 0xd61f03c0u ||  /* ret / br x30 */
                 (op & 0xfffffc1fu) == 0xd61f0000u)         /* br xN: tail thunk */
        {
            /* pc points at this frame's own call, so the live lr belongs to
             * the callee — the scan must have reloaded lr from the stack for
             * the walk to be valid */
            if (!lr_restored) return FALSE;
            done = TRUE;
            break;
        }
        else if ((op & 0xfffff01fu) == 0xd503201fu) ; /* hint family: nop/pac/bti */
        else return FALSE;                            /* not a clean epilogue */
    }
    if (!done) return FALSE;
    if (macrunner_hb_is_plausible_recovered_pc( walk.Lr, &bad_pc ) && walk.Lr == pc)
        bad_pc = "pc-no-progress";
    if (bad_pc)
    {
        static unsigned int bad_count;
        if (bad_count++ < 32)
            MESSAGE( "macrunner-hb-seh-ec-unwind-bail: reason=%s pc=%p image=%p "
                     "new_pc=%p sp=%016I64x stack=%p-%p\n",
                     bad_pc, (void *)(ULONG_PTR)pc, (void *)(ULONG_PTR)dispatch->ImageBase,
                     (void *)(ULONG_PTR)walk.Lr, walk.Sp,
                     NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
        return FALSE;
    }

    *context = walk;
    context->Pc = walk.Lr;
    macrunner_hb_note_pc_set( 4, context->Pc, context->Sp );
    context->ContextFlags |= CONTEXT_UNWOUND_TO_CALL;

    dispatch->EstablisherFrame = context->Sp;
    dispatch->LanguageHandler = NULL;
    dispatch->HandlerData = NULL;

    {
        static unsigned int trace_count;
        if (trace_count++ < 16)
            MESSAGE( "macrunner-hb-seh-ec-unwind: epilogue-scan pc=%p image=%p -> new pc=%p sp=%016I64x\n",
                 (void *)pc, (void *)dispatch->ImageBase, (void *)context->Pc, context->Sp );
    }
    return TRUE;
}

/* Fallback unwinder for MID-FUNCTION EC frames with no unwind data, where the
 * epilogue-scan above bails because pc is not at an epilogue (e.g. rpcrt4 RVA
 * 0x3E600 in the 0x6ba RPC_S_SERVER_UNAVAILABLE SEH cascade — a `bl` site, not a
 * ret).  lld ARM64X has ExtraRFETable=0 so there is genuinely no metadata; the
 * only remaining signal is the ARM64 frame-pointer (x29) chain that ABI-compliant
 * EC prologues maintain: [x29]=caller x29, [x29+8]=return address.  Heavily
 * validated (16-aligned, in the thread stack, chain climbs upward, return addr
 * is plausible code) so a frameless function or garbage fp bails to the old
 * invalid-disposition path instead of unwinding into nonsense. */
static BOOL macrunner_ec_fp_chain_unwind( DISPATCHER_CONTEXT *dispatch, CONTEXT *context, DWORD64 pc )
{
    TEB *teb = NtCurrentTeb();
    ULONG_PTR stack_lo = (ULONG_PTR)teb->Tib.StackLimit;
    ULONG_PTR stack_hi = (ULONG_PTR)teb->Tib.StackBase;
    ULONG_PTR fp = (ULONG_PTR)context->Fp;
    ULONG_PTR sp = (ULONG_PTR)context->Sp;
    ULONG_PTR new_fp = 0, new_pc = 0;
    const char *bail = NULL;
    BOOL stop_unwind = FALSE;

    /* MacRunner 2026-08-27 — НУЛЕВОЙ fp ЭТО КОНЕЦ ЦЕПОЧКИ, А НЕ ПОВОД ИСКАТЬ ДАЛЬШЕ.
     *
     * Замер: Heroes III и UT99 умирают ОДИНАКОВО, на одном и том же кадре.
     *
     *   fpchain: pc=0x6FFFFB05081C fp=0x1121CF390 -> new pc=0x6FFFFB051A9C new fp=0x0
     *   unwind-step n=4 pc=6ffffb051a9c
     *   unwind-step n=5 pc=1121cf990        <- адрес ВНУТРИ стека, то есть мусор
     *   NtRaiseException: noncontinuable exception   (UT99: c000000d)
     *
     * Ниже по коду `new_fp == 0` не проверяется вовсе (условие `new_fp && ...`), поэтому
     * ноль спокойно записывается в контекст. На следующем шаге он попадает сюда — и уходил
     * в fallback, то есть разматывание продолжалось другим путём и брало со стека мусор как
     * адрес возврата.
     *
     * Ноль в fp означает ровно одно: кадров больше нет. Останавливаемся ЧИСТО, как уже
     * делает ветвь fp-out-of-stack. Невыровненный fp — другой случай (кадр испорчен, а не
     * кончился), ему прежний fallback оставлен.
     *
     * Тот же вывод записан в разборе ABZU от 13.06: «fp вне [StackLimit,StackBase] ЛИБО
     * нулевой -> завершать разматывание чисто, а не пере-доставлять исключение».
     *
     * Гейт MACRUNNER_HB_FP_NULL_ENDS_UNWIND, умолчание ВЫКЛ до замера на двух мишенях. */
    if (!fp)
    {
        static int gate = -1;

        if (gate < 0)
        {
            /* getenv на PE-стороне ntdll не линкуется (ld.lld: undefined symbol) — читаем
             * так же, как остальные гейты этого слоя. */
            static const WCHAR nameW[] = {'M','A','C','R','U','N','N','E','R','_','H','B','_',
                                          'F','P','_','N','U','L','L','_','E','N','D','S','_',
                                          'U','N','W','I','N','D',0};
            WCHAR value[4] = { 0 };
            UNICODE_STRING name, val;

            RtlInitUnicodeString( &name, nameW );
            val.Buffer = value;
            val.Length = 0;
            val.MaximumLength = sizeof(value);
            gate = (RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND &&
                    value[0] && value[0] != '0') ? 1 : 0;
        }
        bail = "fp-null-or-unaligned";
        if (gate) stop_unwind = TRUE;
    }
    else if (fp & 0xf) bail = "fp-null-or-unaligned";
    else if (fp < stack_lo || fp + 0x10 > stack_hi)
    {
        bail = "fp-out-of-stack";
        stop_unwind = TRUE;
    }
    else
    {
        const char *pc_reason = NULL;

        new_fp = ((const ULONG_PTR *)fp)[0];   /* saved caller x29 */
        new_pc = ((const ULONG_PTR *)fp)[1];   /* saved lr / return address */
        if (!new_pc || new_pc == pc || (new_pc & 3) || new_pc < 0x10000) bail = "bad-new-pc";
        else if (!macrunner_hb_is_plausible_recovered_pc( new_pc, &pc_reason ))
        {
            bail = pc_reason ? pc_reason : "bad-new-pc";
            stop_unwind = TRUE;
        }
        else if (new_fp && (new_fp <= fp || (new_fp & 0xf) || new_fp + 0x10 > stack_hi)) bail = "bad-new-fp";
    }
    if (bail)
    {
        static unsigned int fpb;
        if (fpb++ < 16)
            MESSAGE( "macrunner-hb-seh-ec-fpchain-bail: reason=%s pc=%p fp=%p sp=%p lr=%p "
                     "stack=%p-%p new_fp=%p new_pc=%p action=%s\n",
                     bail, (void *)pc, (void *)fp, (void *)sp, (void *)(ULONG_PTR)context->Lr,
                     (void *)stack_lo, (void *)stack_hi, (void *)new_fp, (void *)new_pc,
                     stop_unwind ? "stop-unwind" : "fallback" );
        if (stop_unwind)
        {
            macrunner_hb_stop_unwind_at_boundary( dispatch, context );
            return TRUE;
        }
        return FALSE;
    }

    context->Sp  = fp + 0x10;
    context->Fp  = new_fp;
    context->Lr  = new_pc;
    context->Pc  = new_pc;
    macrunner_hb_note_pc_set( 5, context->Pc, context->Sp );
    context->ContextFlags |= CONTEXT_UNWOUND_TO_CALL;
    dispatch->EstablisherFrame = context->Sp;
    dispatch->LanguageHandler = NULL;
    dispatch->HandlerData = NULL;
    {
        static unsigned int fp_trace;
        if (fp_trace++ < 16)
            MESSAGE( "macrunner-hb-seh-ec-fpchain: pc=%p fp=%p -> new pc=%p new fp=%p sp=%016I64x\n",
                     (void *)pc, (void *)fp, (void *)new_pc, (void *)new_fp, context->Sp );
    }
    return TRUE;
}

static BOOL macrunner_hb_arm64_no_pdata_frameless_unwind( DISPATCHER_CONTEXT *dispatch,
                                                          CONTEXT *context, DWORD64 pc );

static BOOL macrunner_hb_try_arm64_unwind_methods( DISPATCHER_CONTEXT *dispatch,
                                                   CONTEXT *context, DWORD64 pc )
{
    if (macrunner_hb_pc_unsafe_for_arm64_unwind( dispatch, context, pc ))
    {
        static unsigned int unsafe_count;
        TEB *teb = NtCurrentTeb();
        ULONG_PTR stack_lo = teb ? (ULONG_PTR)teb->Tib.StackLimit : 0;
        ULONG_PTR stack_hi = teb ? (ULONG_PTR)teb->Tib.StackBase : 0;
        int kind = dispatch && dispatch->ImageBase ?
            macrunner_hb_arm64x_code_range_kind( dispatch->ImageBase, pc ) : -1;

        if (macrunner_hb_recover_native_dispatch_boundary( dispatch, context, pc ))
            return TRUE;

        if (unsafe_count++ < 32)
            MESSAGE( "macrunner-hb-arm64-unwind-unsafe-boundary: pc=%p image=%p "
                     "kind=%d sp=%016I64x stack=%p-%p action=stop-unwind\n",
                     (void *)(ULONG_PTR)pc,
                     dispatch ? (void *)(ULONG_PTR)dispatch->ImageBase : NULL,
                     kind, context ? context->Sp : 0, (void *)stack_lo, (void *)stack_hi );
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: БЕЗУСЛОВНЫЙ зонд про область под PC.
         * Ступень 1 упирается сюда с image=0 kind=-1 при sp ВНУТРИ границ стека, причём
         * три прогона дали три разные базы ASLR и ОДНО смещение 0xC60 — значит область
         * отображена, но образом не заведена. Спрашиваем ядро напрямую: что здесь лежит.
         * Печать безусловная (первые 8), чтобы не повторить историю с маркером-лотереей. */
        {
            static unsigned int vm_probe;
            if (vm_probe++ < 8)
            {
                MEMORY_BASIC_INFORMATION mbi;
                SIZE_T retlen = 0;
                NTSTATUS qs = NtQueryVirtualMemory( NtCurrentProcess(), (void *)(ULONG_PTR)pc,
                                                    MemoryBasicInformation, &mbi, sizeof(mbi), &retlen );
                if (!qs)
                    MESSAGE( "macrunner-hb-unsafe-vmprobe: pc=%p alloc_base=%p base=%p size=%p "
                             "state=%08x protect=%08x alloc_prot=%08x type=%08x смещение=%p\n",
                             (void *)(ULONG_PTR)pc, mbi.AllocationBase, mbi.BaseAddress,
                             (void *)mbi.RegionSize, (unsigned int)mbi.State,
                             (unsigned int)mbi.Protect, (unsigned int)mbi.AllocationProtect,
                             (unsigned int)mbi.Type,
                             (void *)((ULONG_PTR)pc - (ULONG_PTR)mbi.AllocationBase) );
                else
                    MESSAGE( "macrunner-hb-unsafe-vmprobe: pc=%p ЗАПРОС ОТКАЗАЛ status=%08x\n",
                             (void *)(ULONG_PTR)pc, (unsigned int)qs );
            }
        }
        macrunner_hb_stop_unwind_at_boundary( dispatch, context );
        return TRUE;
    }

    return macrunner_ec_virtual_unwind_frame( dispatch, context, pc ) ||
           macrunner_hb_arm64_no_pdata_frameless_unwind( dispatch, context, pc ) ||
           macrunner_ec_fp_chain_unwind( dispatch, context, pc );
}


/**********************************************************************
 *           virtual_unwind
 */
static LONG CALLBACK macrunner_hb_pe_scan_fault( EXCEPTION_POINTERS *ep );

/* Arena exception-data index consult (operator (c1)->(c2)): recover the
 * RUNTIME_FUNCTION for a pc in a mapped-but-UNREGISTERED guest-arena module
 * alias.  The arena alias is an execution-view (deliberately not in the loader
 * list, to preserve module identity), but it is a full contiguous image copy
 * carrying the real ARM64 .pdata — so we locate the image base (MZ-scan down
 * from pc; [base,pc] is wholly mapped, the scan never reads below base) and
 * binary-search its exception directory exactly as RtlLookupFunctionEntry would
 * for a registered module.  This is the native RtlAddFunctionTable semantics for
 * out-of-list code; a map-time-populated sorted range index will later replace
 * the per-call scan with O(log n) lookup (same RUNTIME_FUNCTION result). */
static void macrunner_hb_arena_consult_function_entry( DWORD64 pc, RUNTIME_FUNCTION **entry_out,
                                                       ULONG_PTR *base_out )
{
    ULONG_PTR img_floor = pc & ~0x0fffffffULL;   /* 256MB-aligned backstop */
    ULONG_PTR base = 0, p;
    RUNTIME_FUNCTION *table;
    ULONG size = 0, rva, count;
    LONG lo, hi, found = -1;

    *entry_out = NULL;
    if (pc < 0x10000 || (pc & 3)) return;
    if (pc < MACRUNNER_HB_HOST_BOUNDARY_MAX) return;

    __TRY
    {
        for (p = pc & ~0xfffULL; p >= img_floor; p -= 0x1000)
            if (*(const USHORT *)p == 0x5a4d) { base = p; break; }   /* 'MZ' header */
    }
    __EXCEPT(macrunner_hb_pe_scan_fault) { base = 0; }
    __ENDTRY
    if (!base || !RtlImageNtHeader( (void *)base )) return;
    table = RtlImageDirectoryEntryToData( (void *)base, TRUE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &size );
    if (!table || size < sizeof(*table)) return;
    count = size / sizeof(*table);
    rva = (ULONG)(pc - base);
    /* largest BeginAddress <= rva (the function containing pc) */
    lo = 0; hi = (LONG)count - 1;
    while (lo <= hi)
    {
        LONG mid = lo + (hi - lo) / 2;
        if (table[mid].BeginAddress <= rva) { found = mid; lo = mid + 1; }
        else hi = mid - 1;
    }
    if (found < 0) return;
    *entry_out = &table[found];
    *base_out  = base;
    {
        static unsigned int t;
        if (t++ < 16)
            MESSAGE( "macrunner-hb-arena-fde: pc=%p base=%p rva=%#x begin=%#x count=%lu\n",
                 (void *)pc, (void *)base, rva, table[found].BeginAddress, (unsigned long)count );
    }
}

/* MacRunner Lane A (2026-06-12): WOW64/i386 ARM64-PE pdata unwind machinery, RESTORED
 * from stash@{1} (lane-a-forward-fixes) in its delta-#4 form — aaf425d had deleted it
 * (246 lines) while consolidating bulk-CFI, regressing the i386 unwind path (80000002).
 * Gated !macrunner_hb_is_x64_main_process() at the call site so HK/x64 keeps using
 * arena-fde (the f69cdbc cascade fix is untouched).  ARM64 PE modules loaded by the
 * WOW64 layer above HOST_BOUNDARY_MAX are not tracked by the PE-side LDR; ARM64X
 * counterparts (ucrtbase) also have DataDirectory[3] -> .reloc, so scan section
 * headers for a ".pdata" section by name. */
static LONG CALLBACK macrunner_hb_pe_scan_fault( EXCEPTION_POINTERS *ep )
{
    (void)ep;
    return EXCEPTION_EXECUTE_HANDLER;
}

/* ARM64 RUNTIME_FUNCTION end-RVA: use FunctionLength (in 4-byte units) from the packed
 * header (Flag != 0) or from the XDATA block (Flag == 0). */
#define MACRUNNER_HB_ARM64_FUNC_END(entry, base_ptr) \
    ((entry)->Flag \
     ? (entry)->BeginAddress + 4u * (entry)->FunctionLength \
     : (entry)->BeginAddress + 4u * \
       ((const IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA *)((base_ptr) + (entry)->UnwindData))->FunctionLength)

static PRUNTIME_FUNCTION macrunner_hb_pdata_lookup_at_base( DWORD64 pc, DWORD64 known_base,
                                                            DWORD64 *out_image_base )
{
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY *dir;
    PRUNTIME_FUNCTION funcs, lo, hi, mid;
    char *base = (char *)(ULONG_PTR)known_base;
    DWORD count, rva;
    static unsigned int report_count;

    __TRY
    {
        nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
        if (macrunner_hb_arm64x_code_range_kind( known_base, pc ) == 0)
        {
            static unsigned int x64_range_count;

            if (out_image_base) *out_image_base = known_base;
            if (x64_range_count++ < 16)
                MESSAGE( "macrunner-hb-wow64-arm64-pdata: skip-x64-range base=%p rva=%08lx\n",
                         base, (DWORD)(pc - known_base) );
            return NULL;
        }
        dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (!dir->VirtualAddress || !dir->Size) return NULL;
        funcs = (PRUNTIME_FUNCTION)(base + dir->VirtualAddress);
        count = dir->Size / sizeof(*funcs);

        rva = (DWORD)(pc - known_base);
        if (report_count++ < 16)
            MESSAGE( "macrunner-hb-wow64-arm64-pdata: direct base=%p rva=%08lx count=%lu\n",
                     base, rva, (unsigned long)count );

        lo = funcs; hi = funcs + count;
        while (lo < hi)
        {
            mid = lo + (hi - lo) / 2;
            if (rva < mid->BeginAddress) { hi = mid; }
            else if (rva < MACRUNNER_HB_ARM64_FUNC_END(mid, base))
            {
                if (out_image_base) *out_image_base = known_base;
                return mid;
            }
            else { lo = mid + 1; }
        }

        /* DataDirectory[3] may point to wrong section (ARM64X ucrtbase: .reloc, not .pdata).
         * Scan section headers for a ".pdata" section and retry only if it differs. */
        {
            IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION( nt );
            WORD i;
            for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
            {
                if (memcmp( sec->Name, ".pdata\0\0", 8 ) != 0) continue;
                if (!sec->VirtualAddress || !sec->SizeOfRawData) continue;
                if (sec->VirtualAddress == dir->VirtualAddress) break; /* already tried */
                funcs = (PRUNTIME_FUNCTION)(base + sec->VirtualAddress);
                count = sec->SizeOfRawData / sizeof(*funcs);
                if (report_count <= 32)
                    MESSAGE( "macrunner-hb-wow64-arm64-pdata: section-fallback base=%p"
                             " rva=%08lx count=%lu\n", base, rva, (unsigned long)count );
                lo = funcs; hi = funcs + count;
                while (lo < hi)
                {
                    mid = lo + (hi - lo) / 2;
                    if (rva < mid->BeginAddress) { hi = mid; }
                    else if (rva < MACRUNNER_HB_ARM64_FUNC_END(mid, base))
                    {
                        if (out_image_base) *out_image_base = known_base;
                        return mid;
                    }
                    else { lo = mid + 1; }
                }
                break;
            }
        }
    }
    __EXCEPT(macrunner_hb_pe_scan_fault) {}
    __ENDTRY
    return NULL;
}

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — РАЗРЫВ ПЕТЛИ РЕКУРСИИ.
 *
 * Замер: i386-программа с ЛЮБЫМ оконным вызовом гибнет с кодом 253 (STATUS_STACK_OVERFLOW,
 * 0xc00000fd), 16 МБ стека израсходованы полностью, в профиле ДВЕНАДЦАТЬ вложенных
 * segv_handler в одном стеке глубиной 514 кадров. 29 записей отказа из 30 приходятся на
 * ОДИН адрес — цикл ниже (+0x90, чтение e_magic).
 *
 * Петля: отказ -> обработчик -> разматывание (virtual_unwind, строки 2530/2541) -> ему нужна
 * pdata -> этот поиск заголовка шагает назад по страницам -> попадает в неотображённую ->
 * ОТКАЗ -> обработчик -> ... Обёртка __TRY ловит падение, но НЕ отменяет вход в обработчик,
 * поэтому от рекурсии не спасает.
 *
 * Здесь страница СНАЧАЛА проверяется через ядро и пропускается, если не отображена, — тогда
 * отказа нет вовсе и петля не начинается. Умолчание 0: прежнее поведение, чужие прогоны
 * не затронуты. Критерий проверки: w1.exe возвращает свой код 31 вместо 253. */
static BOOL macrunner_hb_pdata_scan_safe(void)
{
    static BOOL initialized, enabled;

    if (!initialized)
    {
        static const WCHAR nameW[] =
            {'M','A','C','R','U','N','N','E','R','_','H','B','_','P','D','A','T','A',
             '_','S','C','A','N','_','S','A','F','E',0};
        unsigned int value = 0;

        /* ★ ИСПРАВЛЕНИЕ МОЕЙ ЖЕ ПРАВКИ (31.08, час спустя).
         *
         * Сначала я вернул здесь FALSE — «в пути отказа окружение не читаем». Смысл
         * гейта обратный: TRUE значит «ПРОВЕРЯТЬ страницу перед разыменованием».
         * FALSE отключал проверку ровно там, где она нужнее всего: обратный скан идёт
         * по 256 страницам подряд, разыменовывая каждую как IMAGE_DOS_HEADER, и в пути
         * раскрутки без проверки он гарантированно натыкается на неотображённую.
         *
         * Правильное поведение в пути отказа — САМОЕ БЕЗОПАСНОЕ: проверять. Окружение
         * при этом всё равно не читаем, значение не запоминаем. */
        if (macrunner_hb_in_fault_path) return TRUE;
        enabled = macrunner_hb_query_env_uint( nameW, &value ) && value != 0;
        initialized = TRUE;
    }
    return enabled;
}

static PRUNTIME_FUNCTION macrunner_hb_register_wow64_arm64_pe_pdata( DWORD64 pc, DWORD64 *out_image_base )
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY *dir;
    IMAGE_SECTION_HEADER *sec;
    PRUNTIME_FUNCTION funcs, lo, hi, mid;
    char *base;
    DWORD i, count, rva;
    WORD j;
    static unsigned int report_count;

    /* Путь отказа начинается ЗДЕСЬ: сюда приходит раскрутка стека при уже идущей
     * диспетчеризации исключения. Пока признак взведён, гейты окружение не читают. */
    macrunner_hb_in_fault_path++;
    if (!out_image_base) return NULL;
    if (!pc || pc <= MACRUNNER_HB_HOST_BOUNDARY_MAX) return NULL;

    base = (char *)((ULONG_PTR)pc & ~(ULONG_PTR)0xfff);
    {   /* ★ 31.08 — ПРИБОР НА ВХОДЕ. Отчёт о найденном заголовке не печатался НИ РАЗУ
         * за прогон, и это неотличимо от «функцию не звали». Печатаем сам вход. */
        static unsigned int enter_count;
        if (enter_count++ < 8)
            MESSAGE( "macrunner-hb-pdata-вход: pc=%p старт_скана=%p\n",
                     (void *)(ULONG_PTR)pc, base );
    }
    __TRY
    {
        for (i = 0; i <= 256; i++, base -= 0x1000)
        {
            if (macrunner_hb_pdata_scan_safe())
            {
                MEMORY_BASIC_INFORMATION mbi;
                SIZE_T len = 0;

                if (NtQueryVirtualMemory( NtCurrentProcess(), base, MemoryBasicInformation,
                                          &mbi, sizeof(mbi), &len ) != STATUS_SUCCESS)
                    continue;
                if (mbi.State != MEM_COMMIT) continue;
                if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) continue;
            }
            dos = (IMAGE_DOS_HEADER *)base;
            {   /* причина отсева на КАЖДОМ шаге: иначе «скан не нашёл» неотличимо от
                 * «скан не дошёл» и от «скан упал на первом же разыменовании». */
                static unsigned int step_count;
                if (step_count++ < 40)
                    MESSAGE( "macrunner-hb-pdata-шаг: i=%u base=%p magic=%04x\n",
                             i, base, (unsigned)dos->e_magic );
            }
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
            if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x800) continue;
            nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
            if (nt->OptionalHeader.SizeOfImage == 0) continue;
            if ((ULONG_PTR)base + nt->OptionalHeader.SizeOfImage <= (ULONG_PTR)pc) continue;
            if (macrunner_hb_arm64x_code_range_kind( (ULONG_PTR)base, pc ) == 0)
            {
                static unsigned int x64_range_count;

                *out_image_base = (DWORD64)(ULONG_PTR)base;
                if (x64_range_count++ < 16)
                    MESSAGE( "macrunner-hb-wow64-arm64-pdata: scan-skip-x64-range "
                             "base=%p machine=%04x pc=%p rva=%08lx\n",
                             base, nt->FileHeader.Machine, (void *)(ULONG_PTR)pc,
                             (DWORD)(pc - (DWORD64)(ULONG_PTR)base) );
                macrunner_hb_in_fault_path--;
                return NULL;
            }

            if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64)
            {
                /* Native ARM64 PE — use DataDirectory[3] directly. */
                dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                if (!dir->VirtualAddress || !dir->Size) return NULL;
                funcs = (PRUNTIME_FUNCTION)(base + dir->VirtualAddress);
                count = dir->Size / sizeof(*funcs);
            }
            else if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
            {
                /* ARM64X counterpart: machine=AMD64 in memory after update_arm64x_mapping().
                 * Verify this is really an ARM64X module by checking CHPE metadata pointer. */
                IMAGE_DATA_DIRECTORY *lc_dir =
                    &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
                BOOL is_arm64x = FALSE;
                if (lc_dir->VirtualAddress && lc_dir->Size)
                {
                    IMAGE_LOAD_CONFIG_DIRECTORY *cfg =
                        (IMAGE_LOAD_CONFIG_DIRECTORY *)(base + lc_dir->VirtualAddress);
                    DWORD lc_size = min(lc_dir->Size, cfg->Size);
                    if (lc_size > offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, CHPEMetadataPointer)
                        && cfg->CHPEMetadataPointer > (ULONG_PTR)base
                        && cfg->CHPEMetadataPointer <
                               (ULONG_PTR)base + nt->OptionalHeader.SizeOfImage)
                        is_arm64x = TRUE;
                }
                if (!is_arm64x) continue;
                /* ARM64X: DataDirectory[3] may point to wrong section (ucrtbase: .reloc).
                 * Always use section-header scan for .pdata. */
                funcs = NULL; count = 0;
                sec = IMAGE_FIRST_SECTION( nt );
                for (j = 0; j < nt->FileHeader.NumberOfSections; j++, sec++)
                {
                    if (memcmp( sec->Name, ".pdata\0\0", 8 ) != 0) continue;
                    if (!sec->VirtualAddress || !sec->SizeOfRawData) continue;
                    funcs = (PRUNTIME_FUNCTION)(base + sec->VirtualAddress);
                    count = sec->SizeOfRawData / sizeof(*funcs);
                    break;
                }
                if (!funcs || !count) return NULL;
            }
            else continue;

            if (report_count++ < 16)
                MESSAGE( "macrunner-hb-wow64-arm64-pdata: scan base=%p machine=%04x size=%08lx "
                         "pc=%p rva=%08lx count=%lu\n",
                         base, nt->FileHeader.Machine, nt->OptionalHeader.SizeOfImage,
                         (void *)(ULONG_PTR)pc,
                         (DWORD)(pc - (DWORD64)(ULONG_PTR)base),
                         (unsigned long)count );

            rva = (DWORD)(pc - (DWORD64)(ULONG_PTR)base);
            lo = funcs; hi = funcs + count;
            while (lo < hi)
            {
                mid = lo + (hi - lo) / 2;
                if (rva < mid->BeginAddress) { hi = mid; }
                else if (rva < MACRUNNER_HB_ARM64_FUNC_END(mid, base))
                {
                    *out_image_base = (DWORD64)(ULONG_PTR)base;
                    macrunner_hb_in_fault_path--;
                    return mid;
                }
                else { lo = mid + 1; }
            }
            macrunner_hb_in_fault_path--;
            return NULL;
        }
    }
    __EXCEPT(macrunner_hb_pe_scan_fault) {}
    __ENDTRY
    macrunner_hb_in_fault_path--;
    return NULL;
}

static BOOL macrunner_hb_arm64_call_insn( DWORD op )
{
    return (op & 0xfc000000u) == 0x94000000u ||   /* bl */
           (op & 0xfffffc1fu) == 0xd63f0000u;     /* blr xN */
}

static BOOL macrunner_hb_arm64_lr_preindex_slot( DWORD op, DWORD *slot, DWORD *frame_size )
{
    if ((op & 0xffe00fffu) == 0xf8000ffeu)        /* str x30, [sp, #imm]! */
    {
        int imm = ((int)((op >> 12) & 0x1ff) << 23) >> 23;
        if (imm >= 0 || imm < -0x1000 || (imm & 0xf)) return FALSE;
        *slot = 0;
        *frame_size = (DWORD)-imm;
        return TRUE;
    }

    if ((op & 0xffc003e0u) == 0xa98003e0u)        /* stp xA, xB, [sp, #imm]! */
    {
        unsigned int rt = op & 0x1f, rt2 = (op >> 10) & 0x1f;
        int imm = (((int)((op >> 15) & 0x7f) << 25) >> 25) * 8;
        if (imm >= 0 || imm < -0x1000 || (imm & 0xf)) return FALSE;
        if (rt == 30) *slot = 0;
        else if (rt2 == 30) *slot = 8;
        else return FALSE;
        *frame_size = (DWORD)-imm;
        return TRUE;
    }

    return FALSE;
}

static BOOL macrunner_hb_arm64_sp_preindex_frame( DWORD op, DWORD *frame_size )
{
    if ((op & 0xffc003e0u) == 0xa98003e0u)        /* stp xA, xB, [sp, #imm]! */
    {
        int imm = (((int)((op >> 15) & 0x7f) << 25) >> 25) * 8;
        if (imm >= 0 || imm < -0x1000 || (imm & 0xf)) return FALSE;
        *frame_size = (DWORD)-imm;
        return TRUE;
    }
    return FALSE;
}

static BOOL macrunner_hb_arm64_sp_sub_imm( DWORD op, DWORD *size )
{
    if ((op & 0xff8003ffu) == 0xd10003ffu)        /* sub sp, sp, #imm */
    {
        DWORD imm = (op >> 10) & 0xfff;
        if (op & 0x00400000u) imm <<= 12;
        if (!imm || imm > 0x20000 || (imm & 0xf)) return FALSE;
        *size = imm;
        return TRUE;
    }
    return FALSE;
}

static BOOL macrunner_hb_arm64_lr_sp_offset_slot( DWORD op, DWORD *slot )
{
    if ((op & 0xffc003e0u) == 0xa90003e0u)        /* stp xA, xB, [sp, #imm] */
    {
        unsigned int rt = op & 0x1f, rt2 = (op >> 10) & 0x1f;
        int imm = (((int)((op >> 15) & 0x7f) << 25) >> 25) * 8;
        if (imm < 0 || imm > 0x1000) return FALSE;
        if (rt == 30) *slot = (DWORD)imm;
        else if (rt2 == 30) *slot = (DWORD)(imm + 8);
        else return FALSE;
        return TRUE;
    }

    if ((op & 0xffc003e0u) == 0xf90003e0u && (op & 0x1f) == 30) /* str x30, [sp, #imm] */
    {
        *slot = ((op >> 10) & 0xfff) * 8;
        return TRUE;
    }

    return FALSE;
}

static BOOL macrunner_hb_arm64_no_pdata_frameless_unwind( DISPATCHER_CONTEXT *dispatch,
                                                          CONTEXT *context, DWORD64 pc )
{
    ULONG_PTR stack_lo = (ULONG_PTR)NtCurrentTeb()->Tib.StackLimit;
    ULONG_PTR stack_hi = (ULONG_PTR)NtCurrentTeb()->Tib.StackBase;
    ULONG_PTR sp = (ULONG_PTR)context->Sp;
    DWORD64 saved_lr = 0;
    DWORD slot = 0, frame_size = 0, scan;
    BOOL call_site = FALSE;

    if (pc < 0x10000 || (pc & 3)) return FALSE;
    if (!sp || (sp & 0xf) || sp < stack_lo || sp + 0x10 > stack_hi) return FALSE;

    __TRY
    {
        if (macrunner_hb_arm64_call_insn( *(const DWORD *)(ULONG_PTR)pc ))
            call_site = TRUE;
        else if (pc >= 4 && macrunner_hb_arm64_call_insn( *(const DWORD *)(ULONG_PTR)(pc - 4) ))
            call_site = TRUE;
        if (!call_site) return FALSE;

        for (scan = 1; scan <= 256 && pc >= scan * 4; scan++)
        {
            DWORD64 insn_pc = pc - scan * 4;
            DWORD op = *(const DWORD *)(ULONG_PTR)insn_pc;
            DWORD fwd, alloc;

            if (!macrunner_hb_arm64_lr_preindex_slot( op, &slot, &frame_size ))
            {
                BOOL found_lr_save = FALSE;

                if (!macrunner_hb_arm64_sp_preindex_frame( op, &frame_size ) &&
                    !macrunner_hb_arm64_sp_sub_imm( op, &frame_size ))
                    continue;
                for (fwd = 4; fwd <= 64 && insn_pc + fwd < pc; fwd += 4)
                {
                    DWORD fop = *(const DWORD *)(ULONG_PTR)(insn_pc + fwd);
                    if (macrunner_hb_arm64_lr_sp_offset_slot( fop, &slot ))
                    {
                        found_lr_save = TRUE;
                        break;
                    }
                }
                if (!found_lr_save || slot + sizeof(saved_lr) > frame_size) continue;
            }
            for (fwd = 4; fwd <= 1024 && insn_pc + fwd < pc; fwd += 4)
            {
                DWORD fop = *(const DWORD *)(ULONG_PTR)(insn_pc + fwd);
                if (macrunner_hb_arm64_sp_sub_imm( fop, &alloc ))
                {
                    if (frame_size > 0x20000 - alloc || slot > 0x20000 - alloc)
                        return FALSE;
                    frame_size += alloc;
                    slot += alloc;
                }
            }

            if (sp + frame_size > stack_hi) return FALSE;
            if (sp + slot + sizeof(saved_lr) > stack_hi) return FALSE;
            saved_lr = *(const DWORD64 *)(sp + slot);
            {
                const char *bad_pc = NULL, *same_reason = NULL;
                if (!macrunner_hb_is_plausible_recovered_pc( saved_lr, &bad_pc ))
                {
                    static unsigned int bad_count;
                    if (bad_count++ < 32)
                        MESSAGE( "macrunner-hb-wow64-arm64-frameless-bail: reason=%s "
                                 "pc=%p image=%p saved_lr=%p sp=%016I64x frame=%lu slot=%lu "
                                 "stack=%p-%p\n",
                                 bad_pc, (void *)(ULONG_PTR)pc,
                                 (void *)(ULONG_PTR)dispatch->ImageBase,
                                 (void *)(ULONG_PTR)saved_lr, (DWORD64)sp,
                                 (unsigned long)frame_size, (unsigned long)slot,
                                 (void *)stack_lo, (void *)stack_hi );
                    return FALSE;
                }
                if (saved_lr == pc || saved_lr == context->Lr)
                {
                    static unsigned int same_count;
                    same_reason = saved_lr == pc ? "pc-no-progress" : "pc-same-live-lr";
                    if (same_count++ < 32)
                        MESSAGE( "macrunner-hb-wow64-arm64-frameless-bail: reason=%s "
                                 "pc=%p image=%p saved_lr=%p sp=%016I64x frame=%lu slot=%lu "
                                 "stack=%p-%p\n",
                                 same_reason, (void *)(ULONG_PTR)pc,
                                 (void *)(ULONG_PTR)dispatch->ImageBase,
                                 (void *)(ULONG_PTR)saved_lr, (DWORD64)sp,
                                 (unsigned long)frame_size, (unsigned long)slot,
                                 (void *)stack_lo, (void *)stack_hi );
                    return FALSE;
                }
            }

            context->Sp = sp + frame_size;
            context->Lr = saved_lr;
            context->Pc = saved_lr;
            macrunner_hb_note_pc_set( 6, context->Pc, context->Sp );
            context->ContextFlags |= CONTEXT_UNWOUND_TO_CALL;
            dispatch->EstablisherFrame = context->Sp;
            dispatch->LanguageHandler = NULL;
            dispatch->HandlerData = NULL;

            {
                static unsigned int trace_count;
                if (trace_count++ < 16)
                    MESSAGE( "macrunner-hb-wow64-arm64-frameless: pc=%p image=%p "
                             "saved_lr=%p sp=%016I64x frame=%lu slot=%lu\n",
                             (void *)(ULONG_PTR)pc, (void *)(ULONG_PTR)dispatch->ImageBase,
                             (void *)(ULONG_PTR)saved_lr, (DWORD64)sp,
                             (unsigned long)frame_size, (unsigned long)slot );
            }
            return TRUE;
        }
    }
    __EXCEPT(macrunner_hb_pe_scan_fault) {}
    __ENDTRY

    return FALSE;
}

/* PATHB33 2026-08-03: the host-frame acceptance moved the unwind past the boundary, so the
 * stop-unwind path (which hosted this dump inline) no longer runs on a recovered NULL-call
 * incident — yet the exception is still a call to 0 and still kills the process further up
 * the stack.  Extracted so BOTH paths can name the NULL slot: the stop-unwind path in
 * virtual_unwind and the recovery path in macrunner_hb_recover_native_dispatch_boundary. */
static void macrunner_hb_nullcall_diagnose( CONTEXT *context )
            {
                /* MacRunner 2026-08-04 — probes by RANGE, not by three fixed registers.
                 *
                 * The old set {x5, x1, x19} was picked from one incident and does not generalise: the
                 * 01:08 run carried x5=1 and x1=0x109AD3C1E (a HOST address), so nothing resolved and
                 * the two instruments that actually NAME the empty slot never ran.  The guest image
                 * lives in a known band, so sweep every general register and keep whatever falls in
                 * it — that is stable across incidents in a way a hand-picked triple is not.  The
                 * band is the one every guest module address in this lane's logs sits in
                 * (0x87ef…, 0x87fff…); host pointers (0x1…) and small integers fall out by
                 * construction.  Order is preserved so the first hit stays the most likely one. */
                ULONG64 probes[8];
                unsigned probe_count = 0;
                PEB_LDR_DATA *pldr = NtCurrentTeb()->Peb->LdrData;
                void *upbase = NULL;
                unsigned pi;

                for (pi = 0; pi < 29 && probe_count < ARRAY_SIZE(probes); pi++)
                {
                    ULONG64 v = context->X[pi];

                    /* Band fixed 2026-08-04: guest module addresses in this lane are ELEVEN hex
                     * digits (0x87ef13c0000, 0x87fff5e0000), and the first cut wrote twelve —
                     * a factor of sixteen too high, so the sweep reported guest_range_hits=0 on a
                     * dump whose x1 was 0x87EF13C0000, plainly a guest base.  The zero was my
                     * constant, not the process's state. */
                    if (v < 0x87e00000000ULL || v >= 0x88000000000ULL) continue;
                    probes[probe_count++] = v;
                }
                MESSAGE( "macrunner-hb-nullcall-probes: guest_range_hits=%u first=%p second=%p\n",
                         probe_count, (void *)(ULONG_PTR)(probe_count > 0 ? probes[0] : 0),
                         (void *)(ULONG_PTR)(probe_count > 1 ? probes[1] : 0) );

                for (pi = 0; pi < probe_count && !upbase && pldr; pi++)
                {
                    LIST_ENTRY *le;
                    for (le = pldr->InLoadOrderModuleList.Flink;
                         le != &pldr->InLoadOrderModuleList; le = le->Flink)
                    {
                        LDR_DATA_TABLE_ENTRY *m =
                            CONTAINING_RECORD( le, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
                        ULONG_PTR b = (ULONG_PTR)m->DllBase;
                        if (probes[pi] >= b && probes[pi] < b + m->SizeOfImage)
                        { upbase = m->DllBase; break; }
                    }
                }
                /* MacRunner 2026-08-02 — the loader-list walk above finds nothing when the guest
                 * module sits above HOST_BOUNDARY_MAX, which is exactly where UnityPlayer lives:
                 * the comment further down already says "ARM64 PE modules loaded above
                 * HOST_BOUNDARY_MAX are not always tracked by the PE-side LDR".  Measured case:
                 * HOSTFRAME1 at +807.9 s printed "UnityPlayer module not found
                 * (probes 0 0x87ef13f0000 0)" — a valid guest address that simply is not in
                 * InLoadOrderModuleList — and the whole vtable dump that NAMES the null method was
                 * skipped, so the second exit=5 path stayed anonymous.  Ask the memory manager
                 * instead: for a mapped image AllocationBase IS the module base, and the query
                 * cannot fault, which matters because this runs inside the exception path. */
                /* Ask the ENGINE first.  It is the only party that actually knows where guest
                 * images live: the loader list does not contain them and the Windows VM map calls
                 * their pages MEM_FREE (measured, PATHB31).  Lock-free by construction — see
                 * macrunner_hb_guest_image_for_pc in unix/macrunner_hb.c. */
                if (!upbase && macrunner_hb_guest_image_lookup)
                {
                    for (pi = 0; pi < probe_count && !upbase; pi++)
                    {
                        UINT64 gbase = 0, gsize = 0;

                        if (!probes[pi]) continue;
                        if (!macrunner_hb_guest_image_lookup( probes[pi], &gbase, &gsize )) continue;
                        MESSAGE( "macrunner-hb-nullcall-engine: probe=%p base=%p size=%#llx\n",
                                 (void *)(ULONG_PTR)probes[pi], (void *)(ULONG_PTR)gbase,
                                 (unsigned long long)gsize );
                        if (!gbase || gsize <= 0x1a02100) continue;
                        upbase = (void *)(ULONG_PTR)gbase;
                    }
                }
                if (!upbase)
                {
                    for (pi = 0; pi < probe_count && !upbase; pi++)
                    {
                        MEMORY_BASIC_INFORMATION mbi;
                        SIZE_T len = 0;

                        if (!probes[pi]) continue;
                        if (NtQueryVirtualMemory( NtCurrentProcess(),
                                                  (void *)(ULONG_PTR)probes[pi],
                                                  MemoryBasicInformation, &mbi,
                                                  sizeof(mbi), &len ) != STATUS_SUCCESS)
                            continue;
                        /* Measured 2026-08-03 (PATHB1, +1183 s): requiring MEM_IMAGE here silently
                         * skipped everything — the guest PE is mapped by OUR loader into ordinary
                         * memory, so Type is not MEM_IMAGE.  Print what the map actually says, then
                         * judge by the PE header rather than by the mapping type. */
                        MESSAGE( "macrunner-hb-nullcall-map: probe=%p alloc_base=%p base=%p "
                                 "state=%#lx type=%#lx protect=%#lx size=%#llx\n",
                                 (void *)(ULONG_PTR)probes[pi], mbi.AllocationBase,
                                 mbi.BaseAddress, (ULONG)mbi.State, (ULONG)mbi.Type,
                                 (ULONG)mbi.Protect, (unsigned long long)mbi.RegionSize );
                        if (!mbi.AllocationBase) continue;
                        /* The header read below must not fault inside the exception path, so
                         * confirm the first page of the allocation is actually committed first. */
                        {
                            MEMORY_BASIC_INFORMATION hb;

                            if (NtQueryVirtualMemory( NtCurrentProcess(), mbi.AllocationBase,
                                                      MemoryBasicInformation, &hb,
                                                      sizeof(hb), &len ) != STATUS_SUCCESS ||
                                hb.State != MEM_COMMIT)
                                continue;
                        }
                        /* Everything below indexes fixed offsets up to 0x1a02100 with unguarded
                         * loads.  Reaching them on a module that does not span that far would
                         * fault INSIDE the exception path, which is strictly worse than printing
                         * nothing — so admit the base only after the image header says it is big
                         * enough.  RtlImageNtHeader validates the MZ/PE signatures itself. */
                        {
                            IMAGE_NT_HEADERS *unt = RtlImageNtHeader( mbi.AllocationBase );

                            if (!unt || unt->OptionalHeader.SizeOfImage <= 0x1a02100)
                            {
                                MESSAGE( "macrunner-hb-nullcall-iat: memory-map base %p rejected "
                                         "(nt=%p size=%#lx needs >0x1a02100)\n",
                                         mbi.AllocationBase, unt,
                                         (ULONG)(unt ? unt->OptionalHeader.SizeOfImage : 0) );
                                continue;
                            }
                        }
                        upbase = mbi.AllocationBase;
                        MESSAGE( "macrunner-hb-nullcall-iat: module base recovered from the memory "
                                 "map probe=%p base=%p (loader list did not list it)\n",
                                 (void *)(ULONG_PTR)probes[pi], upbase );
                    }
                }
                /* MacRunner 2026-08-03 — PATHB31 proved the memory-map fallback above is blind
                 * too: for probe=0x87ef13f0000, inside a LIVE UnityPlayer that had just printed
                 * "Loaded Objects now: 4274", NtQueryVirtualMemory said alloc_base=0
                 * state=MEM_FREE.  Engine-mapped guest images are invisible to BOTH Windows-side
                 * accountings (loader list and memory map), yet their bytes ARE readable.  So
                 * walk DOWN from the probe on 64K allocation granularity looking for the 'MZ'
                 * header directly.  Reads inside the image never fault, so the expected fault
                 * count is 0-1 (the first access below the image start); the scan aborts after
                 * 3 faults because repeated faults inside the exception path are the known
                 * wedge class (probe_image_bytes). */
                /* MacRunner 2026-08-04 — WHICH PE ntdll is executing, and is the gate on?
                 *
                 * The mzscan block below printed nothing on a run where the map block above it —
                 * same function, twenty lines earlier — printed twice.  Both are in the same source
                 * commit and both dists carry the string, so either the gate reads 0 or the running
                 * ntdll.dll is a THIRD copy (the prefix's system32 is seeded from a template and only
                 * x86_64-windows dlls are synced per run).  A build stamp settles it: it names the
                 * binary that is actually executing, which no strings/mtime check on a dist can do. */
                MESSAGE( "macrunner-hb-nullcall-stamp: built=%s %s gate=%u upbase=%p\n",
                         __DATE__, __TIME__, macrunner_hb_nullcall_mzscan_enabled() ? 1u : 0u,
                         upbase );

                if (!upbase && macrunner_hb_nullcall_mzscan_enabled())
                {
                    for (pi = 0; pi < probe_count && !upbase; pi++)
                    {
                        ULONG64 p = probes[pi] & ~0xffffULL;
                        unsigned int step, faults = 0;

                        if (probes[pi] < 0x10000) continue;
                        for (step = 0; step < 1024 && faults < 3 && p >= 0x10000; step++, p -= 0x10000)
                        {
                            ULONG64 found = 0;
                            __TRY
                            {
                                const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)(ULONG_PTR)p;
                                if (dos->e_magic == IMAGE_DOS_SIGNATURE &&
                                    dos->e_lfanew >= (LONG)sizeof(*dos) && dos->e_lfanew < 0x1000)
                                {
                                    const IMAGE_NT_HEADERS *nt =
                                        (const IMAGE_NT_HEADERS *)((const char *)dos + dos->e_lfanew);
                                    /* Downstream reads index fixed offsets up to 0x1a02100, so
                                     * only a module that spans that far is safe to accept —
                                     * same guard as the memory-map path above.  The probe must
                                     * also fall inside the image, or this is some OTHER module
                                     * below an unmapped hole. */
                                    if (nt->Signature == IMAGE_NT_SIGNATURE &&
                                        nt->OptionalHeader.SizeOfImage > 0x1a02100 &&
                                        probes[pi] - p < nt->OptionalHeader.SizeOfImage)
                                        found = p;
                                }
                            }
                            __EXCEPT(macrunner_hb_pe_scan_fault) { faults++; }
                            __ENDTRY
                            if (found) upbase = (void *)(ULONG_PTR)found;
                            if (found) break;
                        }
                        MESSAGE( "macrunner-hb-nullcall-mzscan: probe=%p base=%p steps=%u faults=%u\n",
                                 (void *)(ULONG_PTR)probes[pi], upbase, step, faults );
                    }
                }
                if (upbase)
                {
                    char *u = (char *)upbase;
                    ULONG64 base64 = (ULONG64)(ULONG_PTR)upbase;
                    unsigned ri;
                    static const int rix[5] = { 4, 3, 28, 25, 6 };
                    MESSAGE( "macrunner-hb-nullcall-iat: module_base=%p "
                             "GetParent[1a01c18]=%p ValidateRect[1a01c20]=%p "
                             "GetWindowRect[1a01cc8]=%p IsIconic[1a01ce8]=%p\n",
                             upbase,
                             (void *)*(ULONG64 *)(u + 0x1a01c18),
                             (void *)*(ULONG64 *)(u + 0x1a01c20),
                             (void *)*(ULONG64 *)(u + 0x1a01cc8),
                             (void *)*(ULONG64 *)(u + 0x1a01ce8) );
                    /* The fault is call [dxgi!CreateDXGIFactory2 IAT slot 0x1a02098].
                     * Dump the runtime values of the critical dxgi/d3d11 import slots
                     * to confirm which graphics import is NULL (unresolved). */
                    MESSAGE( "macrunner-hb-nullcall-gfximports: D3D11On12CreateDevice[1a02068]=%p "
                             "D3D11CreateDevice[1a02070]=%p CreateDXGIFactory2[1a02098]=%p "
                             "CreateDXGIFactory[1a020a0]=%p\n",
                             (void *)*(ULONG64 *)(u + 0x1a02068),
                             (void *)*(ULONG64 *)(u + 0x1a02070),
                             (void *)*(ULONG64 *)(u + 0x1a02098),
                             (void *)*(ULONG64 *)(u + 0x1a020a0) );
                    /* The IAT slots are x64->EC thunks; read each thunk's code words +
                     * its embedded EC target (typ. thunk+8) — a 0 target = unbound EC
                     * export => the execute-at-0 in the EC dispatch. */
                    {
                        ULONG64 ts[4];
                        unsigned ti;
                        ts[0] = *(ULONG64 *)(u + 0x1a02068); ts[1] = *(ULONG64 *)(u + 0x1a02070);
                        ts[2] = *(ULONG64 *)(u + 0x1a02098); ts[3] = *(ULONG64 *)(u + 0x1a020a0);
                        for (ti = 0; ti < 4; ti++)
                        {
                            const ULONG64 *t = (const ULONG64 *)(ULONG_PTR)ts[ti];
                            static const char *nm[4] = { "D3D11On12", "D3D11Create",
                                                          "CreateDXGIFactory2", "CreateDXGIFactory" };
                            if (ts[ti] < 0x10000) { MESSAGE( "macrunner-hb-gfxthunk: %s thunk=%p (low)\n", nm[ti], (void *)(ULONG_PTR)ts[ti] ); continue; }
                            MESSAGE( "macrunner-hb-gfxthunk: %s thunk=%p w0=%016llx w1=%016llx w2=%016llx w3=%016llx\n",
                                     nm[ti], (void *)(ULONG_PTR)ts[ti],
                                     (unsigned long long)t[0], (unsigned long long)t[1],
                                     (unsigned long long)t[2], (unsigned long long)t[3] );
                            /* Follow this thunk's EC target (w1 = thunk+8 literal):
                             * identify its module+rva and disasm the first insns.
                             * If the EC entry itself br's 0 (or is a bad address),
                             * this names the broken x64->EC forward target. */
                            {
                                ULONG64 tgt = t[1];
                                LDR_DATA_TABLE_ENTRY *tm = NULL; ULONG_PTR trva = 0; char tn[64] = "-";
                                unsigned int ins[8] = {0};
                                if (tgt && LdrFindEntryForAddress( (void *)(ULONG_PTR)tgt, &tm ) == STATUS_SUCCESS && tm)
                                { trva = (ULONG_PTR)tgt - (ULONG_PTR)tm->DllBase;
                                  macrunner_hb_copy_unicode_ascii( tn, sizeof(tn), &tm->BaseDllName ); }
                                __TRY { const unsigned int *c = (const unsigned int *)(ULONG_PTR)tgt;
                                        ins[0]=c[0];ins[1]=c[1];ins[2]=c[2];ins[3]=c[3];
                                        ins[4]=c[4];ins[5]=c[5];ins[6]=c[6];ins[7]=c[7]; }
                                __EXCEPT(macrunner_hb_pe_scan_fault) { ins[0]=0xdeadbeef; }
                                __ENDTRY
                                MESSAGE( "macrunner-hb-gfxtarget: %s ec_target=%p module=%s rva=0x%llx "
                                         "insns=%08x %08x %08x %08x %08x %08x %08x %08x\n",
                                         nm[ti], (void *)(ULONG_PTR)tgt, tn, (unsigned long long)trva,
                                         ins[0],ins[1],ins[2],ins[3],ins[4],ins[5],ins[6],ins[7] );
                            }
                        }
                    }
                    /* Scan candidate guest stack pointers (x3/x4/x28/...) for the
                     * return address into UnityPlayer's WndProc -> the exact call
                     * site.  A guest-range qword (module_base..+0x2200000) with the
                     * WndProc rva is the return after the faulting indirect call. */
                    for (ri = 0; ri < 5; ri++)
                    {
                        ULONG64 p = context->X[rix[ri]];
                        const ULONG64 *w;
                        unsigned k;
                        if (p < 0x10000 || p >= 0x900000000000ULL || (p & 7)) continue;
                        w = (const ULONG64 *)(ULONG_PTR)p;
                        for (k = 0; k < 48; k++)
                        {
                            ULONG64 v = w[k];
                            if (v > base64 && v < base64 + 0x2200000)
                                MESSAGE( "macrunner-hb-nullcall-ret: x%d=%p +0x%x val=%p rva=0x%llx\n",
                                         rix[ri], (void *)(ULONG_PTR)p, k * 8,
                                         (void *)(ULONG_PTR)v,
                                         (unsigned long long)(v - base64) );
                        }
                    }
                    /* The WM_PAINT handler (rva 0x7d520a) calls vtable methods on a
                     * thread-local object (rbx = x27 in the ARM64EC map; from 0x6c7860
                     * TlsGetValue).  Read [obj]=vtable and the called slots to find the
                     * NULL method + the non-null methods' rva (identifies the class). */
                    {
                        static const int orx[6] = { 27, 0, 25, 26, 3, 19 };
                        static const unsigned voff[5] = { 0x678, 0x680, 0x690, 0x698, 0x6b0 };
                        unsigned oi, vi;
                        for (oi = 0; oi < 6; oi++)
                        {
                            ULONG64 obj = context->X[orx[oi]], vt;
                            if (obj < 0x10000 || obj >= 0x900000000000ULL || (obj & 7)) continue;
                            vt = *(ULONG64 *)(ULONG_PTR)obj;
                            if (vt < 0x10000 || vt >= 0x900000000000ULL || (vt & 7)) continue;
                            for (vi = 0; vi < 5; vi++)
                            {
                                ULONG64 mp = *(ULONG64 *)(ULONG_PTR)(vt + voff[vi]);
                                MESSAGE( "macrunner-hb-nullcall-vtable: obj=x%d=%p vtable=%p rva=0x%llx "
                                         "+0x%x=%p%s%s\n",
                                         orx[oi], (void *)(ULONG_PTR)obj, (void *)(ULONG_PTR)vt,
                                         (vt > base64 && vt < base64 + 0x2200000) ?
                                             (unsigned long long)(vt - base64) : 0ULL,
                                         voff[vi], (void *)(ULONG_PTR)mp,
                                         mp ? "" : " <<NULL",
                                         (mp > base64 && mp < base64 + 0x2200000) ?
                                             " UP" : "" );
                            }
                        }
                    }
                }
                else
                    MESSAGE( "macrunner-hb-nullcall-iat: UnityPlayer module not found "
                             "(count=%u probes %p %p)\n", probe_count,
                             (void *)(ULONG_PTR)(probe_count > 0 ? probes[0] : 0),
                             (void *)(ULONG_PTR)(probe_count > 1 ? probes[1] : 0) );
            }

static NTSTATUS virtual_unwind( ULONG type, DISPATCHER_CONTEXT *dispatch, CONTEXT *context )
{
    DISPATCHER_CONTEXT_NONVOLREG_ARM64 *nonvol_regs;
    DWORD64 pc;
    DWORD64 raw_pc;
    DWORD64 lookup_pc;
    DWORD64 unwind_lr, unwind_sp, unwind_fp;
    CONTEXT unwind_context;
    void *unwind_entry;
    NTSTATUS status;
    int i;

restart:
    pc = context->Pc;
    raw_pc = pc;
    {   /* ★★★★★ MacRunner 2026-08-31 — ГДЕ ПОРТИТСЯ PC ПРИ РАСКРУТКЕ.
         *
         * Установлено приборами: наша `register_wow64_arm64_pe_pdata` получает УЖЕ
         * негодный pc (0x7ffd0…, страница данных) и честно возвращает NULL — она
         * невиновна. Значит негодный адрес продолжения вычислил шаг раскрутки ДО неё.
         * Печатаем pc на КАЖДОМ входе: первый вход покажет исходный кадр, последующие —
         * шаг, на котором адрес перестал быть кодом. Разность между «был в rpcrt4» и
         * «стал 0x7ffd0…» и есть искомое место. */
        static unsigned int uw_count;
        if (uw_count++ < 24)
            MESSAGE( "macrunner-hb-unwind-pc: n=%u type=%lu pc=%p sp=%p lr=%p\n",
                     uw_count, (unsigned long)type, (void *)(ULONG_PTR)pc,
                     (void *)(ULONG_PTR)context->Sp, (void *)(ULONG_PTR)context->Lr );
    }
    dispatch->ScopeIndex = 0;
    dispatch->ControlPc  = pc;
    dispatch->ControlPcIsUnwound = (context->ContextFlags & CONTEXT_UNWOUND_TO_CALL) != 0;
    if (dispatch->ControlPcIsUnwound) pc -= 4;
    lookup_pc = macrunner_hb_normalize_arm64ec_host_pc( pc );

    nonvol_regs = (DISPATCHER_CONTEXT_NONVOLREG_ARM64 *)dispatch->NonVolatileRegisters;
    memcpy( nonvol_regs->GpNvRegs, &context->X19, sizeof(nonvol_regs->GpNvRegs) );
    for (i = 0; i < 8; i++) nonvol_regs->FpNvRegs[i] = context->V[i + 8].D[0];

    if (lookup_pc != pc)
    {
        dispatch->FunctionEntry = RtlLookupFunctionEntry( lookup_pc, &dispatch->ImageBase, dispatch->HistoryTable );
        if (dispatch->FunctionEntry || dispatch->ImageBase)
        {
            dispatch->ControlPc = lookup_pc;
            pc = lookup_pc;
            goto unwind_with_function_entry;
        }
    }

    if (macrunner_hb_is_import_thunk_pc( pc ))
    {
        TRACE( "stopping at MacRunner HyperBridge import thunk pc %p lr %p\n",
               (void *)pc, (void *)context->Lr );
        macrunner_hb_stop_unwind_at_boundary( dispatch, context );
        return STATUS_SUCCESS;
    }

    if (macrunner_hb_is_unix_dispatcher_boundary_pc( pc ))
    {
        TRACE( "stopping at MacRunner HyperBridge Unix dispatcher boundary pc %p lr %p syscall=%p unix=%p\n",
               (void *)pc, (void *)context->Lr, __wine_syscall_dispatcher, __wine_unix_call_dispatcher );
        macrunner_hb_stop_unwind_at_boundary( dispatch, context );
        return STATUS_SUCCESS;
    }

    if (macrunner_hb_is_non_module_host_boundary_pc( pc ))
    {
        static unsigned int report_count;
        const EXCEPTION_RECORD *rec = macrunner_hb_current_exception_record;
        struct macrunner_hb_syscall_frame *frame = macrunner_hb_current_syscall_frame();
        LDR_DATA_TABLE_ENTRY *module = NULL;
        NTSTATUS ldr_status = LdrFindEntryForAddress( (void *)(ULONG_PTR)pc, &module );
        DWORD tid = HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );

        if (report_count++ < 64)
        {
            MESSAGE( "macrunner-hb-seh-host-boundary: pc=%p lr=%p sp=%016I64x\n",
                     (void *)pc, (void *)context->Lr, context->Sp );
            MESSAGE( "macrunner-hb-seh-host-boundary-detail: side=arm64 tid=%04lx pc=%p lr=%p "
                     "sp=%016I64x exception=%08lx flags=%08lx ldr_status=%08lx module=%p "
                     "exc_addr=%p info0=%Ix info1=%p "
                     "resume=stop-unwind frame=%p frame_pc=%p frame_lr=%p frame_sp=%p "
                     "frame_prev=%p frame_cfa=%p frame_flags=%08lx\n",
                     tid, (void *)pc, (void *)context->Lr, context->Sp,
                     rec ? rec->ExceptionCode : 0, rec ? rec->ExceptionFlags : 0,
                     ldr_status, module ? module->DllBase : NULL,
                     rec ? rec->ExceptionAddress : NULL,
                     (ULONG_PTR)(rec && rec->NumberParameters > 0 ? rec->ExceptionInformation[0] : 0),
                     (void *)(ULONG_PTR)(rec && rec->NumberParameters > 1 ? rec->ExceptionInformation[1] : 0),
                     frame,
                     frame ? (void *)(ULONG_PTR)frame->pc : NULL,
                     frame ? (void *)(ULONG_PTR)frame->lr : NULL,
                     frame ? (void *)(ULONG_PTR)frame->sp : NULL,
                      frame ? frame->prev_frame : NULL,
                      frame ? frame->syscall_cfa : NULL,
                      frame ? frame->restore_flags : 0 );
            /* MacRunner diag: this boundary is a native libsystem_platform call (e.g.
             * _platform_memmove) faulting on a guest pointer.  Dump x0..x8 (memmove
             * dst=x0 src=x1 len=x2) + lr + a stack window so the bad buffer/length and
             * the Wine caller can be recovered from the run log. */
            {
                const ULONG64 *stk = (const ULONG64 *)(ULONG_PTR)context->Sp;
                unsigned si;
                MESSAGE( "macrunner-hb-seh-nonmod-regs: x0=%p x1=%p x2=%p x3=%p x4=%p x5=%p "
                         "x6=%p x7=%p x8=%p x9=%p x16=%p x17=%p x18=%p lr=%p fp=%p sp=%p\n",
                         (void *)context->X[0], (void *)context->X[1], (void *)context->X[2],
                         (void *)context->X[3], (void *)context->X[4], (void *)context->X[5],
                         (void *)context->X[6], (void *)context->X[7], (void *)context->X[8],
                         (void *)context->X[9], (void *)context->X[16], (void *)context->X[17],
                         (void *)context->X[18], (void *)context->Lr, (void *)context->Fp,
                         (void *)context->Sp );
                /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1124 — СОХРАНЯЕМЫЕ РЕГИСТРЫ.
                 *
                 * Печать x0..x9 писалась под memmove (dst/src/len), и для отказа ВНУТРИ нативной
                 * функции её не хватает: виновником там бывает регистр, сохраняемый ВЫЗЫВАЕМЫМ.
                 * Замер 1122-1123 упёрся ровно в это: отказ — `ldrb w9,[x21,x9]`, x9=0x57 виден,
                 * а x21 не печатается, и отличить «таблица пуста с самого начала» от «регистр
                 * испорчен по дороге» нечем. При этом x3/x5 показывают, что цикл УЖЕ прошёл
                 * около 114 символов из 7478 — то есть сначала работал.
                 *
                 * Печатаем x19..x28: их обязан сохранять вызываемый, и порча любого из них через
                 * нашу границу перехода — отдельный класс дефекта. */
                MESSAGE( "macrunner-hb-seh-nonmod-saved: x19=%p x20=%p x21=%p x22=%p x23=%p "
                         "x24=%p x25=%p x26=%p x27=%p x28=%p\n",
                         (void *)context->X[19], (void *)context->X[20], (void *)context->X[21],
                         (void *)context->X[22], (void *)context->X[23], (void *)context->X[24],
                         (void *)context->X[25], (void *)context->X[26], (void *)context->X[27],
                         (void *)context->X[28] );
                for (si = 0; si < 24; si += 4)
                    MESSAGE( "macrunner-hb-seh-nonmod-stk: +%02x %p %p %p %p\n",
                             si * 8, (void *)stk[si], (void *)stk[si+1],
                             (void *)stk[si+2], (void *)stk[si+3] );
                /* PATHB43 2026-08-03 — registers in this context can be SYNTHESIZED by the eh
                 * dispatcher bridge (lr here already failed the bl-test twice), so the honest
                 * signal is the frame chain.  Raw addresses only; offline resolution starts
                 * from the macrunner-hb-host-image base printed by the unix side. */
                {
                    ULONG64 fp = context->Fp;
                    unsigned int fi;
                    /* Unconditional head: a zero or misaligned Fp must be VISIBLE, not silent —
                     * silence already cost one run's worth of interpretation. */
                    MESSAGE( "macrunner-hb-seh-fpchain: head fp=%p sp=%p lr=%p\n",
                             (void *)(ULONG_PTR)fp, (void *)(ULONG_PTR)context->Sp,
                             (void *)(ULONG_PTR)context->Lr );
                    for (fi = 0; fi < 16 && fp && !(fp & 7); fi++)
                    {
                        ULONG64 pair[2] = { 0, 0 };
                        BOOL ok = TRUE;
                        __TRY
                        {
                            pair[0] = ((const ULONG64 *)(ULONG_PTR)fp)[0];
                            pair[1] = ((const ULONG64 *)(ULONG_PTR)fp)[1];
                        }
                        __EXCEPT(macrunner_hb_pe_scan_fault) { ok = FALSE; }
                        __ENDTRY
                        if (!ok)
                        {
                            MESSAGE( "macrunner-hb-seh-fpchain: %u fp=%p <unreadable>\n",
                                     fi, (void *)(ULONG_PTR)fp );
                            break;
                        }
                        MESSAGE( "macrunner-hb-seh-fpchain: %u fp=%p prev=%p lr=%p\n",
                                 fi, (void *)(ULONG_PTR)fp, (void *)(ULONG_PTR)pair[0],
                                 (void *)(ULONG_PTR)pair[1] );
                        if (pair[0] <= fp) break;
                        fp = pair[0];
                    }
                }
            }
        }
        if (macrunner_hb_unwind_syscall_data_boundary( dispatch, context, frame ))
            return STATUS_SUCCESS;
        macrunner_hb_stop_unwind_at_boundary( dispatch, context );
        return STATUS_SUCCESS;
    }

    if (macrunner_hb_is_host_boundary_pc( raw_pc, context ) ||
        macrunner_hb_is_null_lr_boundary( raw_pc, context ) ||
        macrunner_hb_is_non_module_host_boundary_pc( pc ))
    {
        static unsigned int report_count;
        const EXCEPTION_RECORD *rec = macrunner_hb_current_exception_record;
        LDR_DATA_TABLE_ENTRY *module = NULL;
        LDR_DATA_TABLE_ENTRY *lr_module = NULL;
        LDR_DATA_TABLE_ENTRY *x17_module = NULL;
        NTSTATUS ldr_status = LdrFindEntryForAddress( (void *)(ULONG_PTR)pc, &module );
        NTSTATUS lr_ldr_status = LdrFindEntryForAddress( (void *)(ULONG_PTR)context->Lr, &lr_module );
        NTSTATUS x17_ldr_status =
            LdrFindEntryForAddress( (void *)(ULONG_PTR)context->X[17], &x17_module );
        DWORD tid = HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );

        if (report_count++ < 64)
        {
            MESSAGE( "macrunner-hb-seh-host-boundary: pc=%p lr=%p sp=%016I64x\n",
                     (void *)pc, (void *)context->Lr, context->Sp );
            MESSAGE( "macrunner-hb-seh-host-boundary-detail: side=arm64 tid=%04lx pc=%p lr=%p "
                     "sp=%016I64x exception=%08lx flags=%08lx ldr_status=%08lx module=%p "
                     "exc_addr=%p info0=%Ix info1=%p resume=stop-unwind\n",
                     tid, (void *)pc, (void *)context->Lr, context->Sp,
                     rec ? rec->ExceptionCode : 0, rec ? rec->ExceptionFlags : 0,
                     ldr_status, module ? module->DllBase : NULL,
                     rec ? rec->ExceptionAddress : NULL,
                     (ULONG_PTR)(rec && rec->NumberParameters > 0 ? rec->ExceptionInformation[0] : 0),
                     (void *)(ULONG_PTR)(rec && rec->NumberParameters > 1 ? rec->ExceptionInformation[1] : 0) );
            if (lr_module)
            {
                const ULONG *insn = (const ULONG *)(ULONG_PTR)context->Lr;
                MESSAGE( "macrunner-hb-seh-nullcall-native: lr_status=%08lx module=%s base=%p "
                         "lr_rva=%Ix insn[-4..0]=%08lx/%08lx/%08lx/%08lx/%08lx "
                         "x17_status=%08lx x17_module=%s x17_base=%p x17_rva=%Ix x17_value=%p\n",
                         lr_ldr_status, debugstr_w( lr_module->BaseDllName.Buffer ),
                         lr_module->DllBase,
                         context->Lr - (ULONG64)(ULONG_PTR)lr_module->DllBase,
                         insn[-4], insn[-3], insn[-2], insn[-1], insn[0],
                         x17_ldr_status,
                         x17_module ? debugstr_w( x17_module->BaseDllName.Buffer ) : "(none)",
                         x17_module ? x17_module->DllBase : NULL,
                         x17_module ? context->X[17] - (ULONG64)(ULONG_PTR)x17_module->DllBase : 0,
                         x17_module && context->X[17] + sizeof(ULONG64) <=
                             (ULONG64)(ULONG_PTR)x17_module->DllBase + x17_module->SizeOfImage
                             ? (void *)*(const ULONG64 *)(ULONG_PTR)context->X[17] : NULL );
            }
            /* MacRunner diag: a NULL-call boundary (exc_addr=0, EXECUTE) carries the
             * original fault registers here (first unwind step).  Dump them + a stack
             * window so the guest return address (a guest-range value, the call site)
             * can be recovered from the run log. */
            if (rec && rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
                !rec->ExceptionAddress)
            {
                const ULONG64 *stk = (const ULONG64 *)(ULONG_PTR)context->Sp;
                unsigned i;
                MESSAGE( "macrunner-hb-seh-host-boundary-regs: x0=%p x1=%p x2=%p x3=%p x4=%p x5=%p "
                         "x6=%p x7=%p x8=%p x9=%p x16=%p x17=%p x18=%p x19=%p x20=%p\n",
                         (void *)context->X[0], (void *)context->X[1], (void *)context->X[2],
                         (void *)context->X[3], (void *)context->X[4], (void *)context->X[5],
                         (void *)context->X[6], (void *)context->X[7], (void *)context->X[8],
                         (void *)context->X[9], (void *)context->X[16], (void *)context->X[17],
                         (void *)context->X[18], (void *)context->X[19], (void *)context->X[20] );
                MESSAGE( "macrunner-hb-seh-host-boundary-regs2: x21=%p x22=%p x23=%p x24=%p x25=%p "
                         "x26=%p x27=%p x28=%p fp=%p lr=%p sp=%p\n",
                         (void *)context->X[21], (void *)context->X[22], (void *)context->X[23],
                         (void *)context->X[24], (void *)context->X[25], (void *)context->X[26],
                         (void *)context->X[27], (void *)context->X[28], (void *)context->Fp,
                         (void *)context->Lr, (void *)context->Sp );
                for (i = 0; i < 32; i += 4)
                    MESSAGE( "macrunner-hb-seh-host-boundary-stk: +%02x %p %p %p %p\n",
                             i * 8, (void *)stk[i], (void *)stk[i+1],
                             (void *)stk[i+2], (void *)stk[i+3] );
            }
            /* The NULL call is in UnityPlayer's WndProc (rva 0x7d5170), which calls
             * USER32 imports through its IAT.  Resolve the UnityPlayer module from a
             * guest pointer (x1/x5/x19 hold guest addresses) and dump the suspect
             * IAT slots so a NULL (unresolved) import is identified directly. */
            if (rec && rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && !rec->ExceptionAddress)
                macrunner_hb_nullcall_diagnose( context );
        }
        macrunner_hb_stop_unwind_at_boundary( dispatch, context );
        return STATUS_SUCCESS;
    }

    dispatch->FunctionEntry = RtlLookupFunctionEntry( pc, &dispatch->ImageBase, dispatch->HistoryTable );
    if (!dispatch->FunctionEntry && pc < MACRUNNER_HB_HOST_BOUNDARY_MAX &&
        macrunner_hb_try_arm64_unwind_methods( dispatch, context, pc ))
        return STATUS_SUCCESS;

    /* ARM64 PE modules loaded above HOST_BOUNDARY_MAX are not always tracked by the
     * PE-side LDR, so RtlLookupFunctionEntry can miss valid ARM64/ARM64X pdata. */
    if (!dispatch->FunctionEntry && pc >= MACRUNNER_HB_HOST_BOUNDARY_MAX)
    {
        if (dispatch->ImageBase)
            dispatch->FunctionEntry = macrunner_hb_pdata_lookup_at_base(
                pc, dispatch->ImageBase, &dispatch->ImageBase );
        if (!dispatch->FunctionEntry)
            dispatch->FunctionEntry = macrunner_hb_register_wow64_arm64_pe_pdata(
                pc, &dispatch->ImageBase );
        if (!dispatch->FunctionEntry && pc >= MACRUNNER_HB_HOST_BOUNDARY_MAX + 4)
        {
            DWORD64 return_pc = pc - 4;
            DWORD64 return_image = dispatch->ImageBase;

            if (return_image)
                dispatch->FunctionEntry = macrunner_hb_pdata_lookup_at_base(
                    return_pc, return_image, &return_image );
            if (!dispatch->FunctionEntry)
                dispatch->FunctionEntry = macrunner_hb_register_wow64_arm64_pe_pdata(
                    return_pc, &return_image );
            if (dispatch->FunctionEntry)
            {
                static unsigned int return_lookup_count;
                if (return_lookup_count++ < 16)
                    MESSAGE( "macrunner-hb-wow64-arm64-pdata: return-address pc=%p "
                             "lookup_pc=%p image=%p function=%p\n",
                             (void *)(ULONG_PTR)pc, (void *)(ULONG_PTR)return_pc,
                             (void *)(ULONG_PTR)return_image, dispatch->FunctionEntry );
                pc = return_pc;
                dispatch->ControlPc = pc;
                dispatch->ImageBase = return_image;
            }
        }
    }
    /* Leaf function with no .pdata entry (normal for thunks).  Stop unwind via the
     * ordered fallback chain rather than letting RtlVirtualUnwind2 raise c0000026. */
    if (!dispatch->FunctionEntry && pc >= MACRUNNER_HB_HOST_BOUNDARY_MAX)
    {
        static unsigned int wow64_leaf_count;
        static unsigned int wow64_x64_range_count;
        BOOL resumed;

        if (dispatch->ImageBase &&
            macrunner_hb_arm64x_code_range_kind( dispatch->ImageBase, pc ) == 0 &&
            macrunner_hb_current_exception_is_datatype_misalignment())
        {
            if (wow64_x64_range_count++ < 16)
                MESSAGE( "macrunner-hb-wow64-arm64-leaf: pc=%p image=%p "
                         "x64-range stop-unwind\n",
                         (void *)(ULONG_PTR)pc, (void *)(ULONG_PTR)dispatch->ImageBase );
            macrunner_hb_stop_unwind_at_boundary( dispatch, context );
            return STATUS_SUCCESS;
        }
        if (macrunner_hb_try_arm64_unwind_methods( dispatch, context, pc ))
            return STATUS_SUCCESS;
        resumed = macrunner_hb_unwind_leaf_via_lr( dispatch, context, pc, context->Lr );
        if (wow64_leaf_count++ < 16)
            MESSAGE( "macrunner-hb-wow64-arm64-leaf: pc=%p lr=%p image=%p "
                     "%s\n",
                     (void *)(ULONG_PTR)pc, (void *)(ULONG_PTR)context->Lr,
                     (void *)(ULONG_PTR)dispatch->ImageBase,
                     resumed ? "resume=lr" : "stopping-unwind" );
        if (resumed) return STATUS_SUCCESS;
        macrunner_hb_stop_unwind_at_boundary( dispatch, context );
        return STATUS_SUCCESS;
    }

    if (!dispatch->FunctionEntry)
    {
        /* (c) EC-unwind: guest-arena module aliases are execution-views NOT in the
         * loader list (by design — registering would dup module identity), so
         * RtlLookupFunctionEntry can't find their exception data even though it is
         * present in the image.  Consult the arena exception index (native
         * RtlAddFunctionTable-style dynamic function tables, populated at arena
         * map-time) to recover the real RUNTIME_FUNCTION + image base; then the
         * normal RtlVirtualUnwind2 below unwinds the frame with genuine .pdata. */
        macrunner_hb_arena_consult_function_entry( pc, (RUNTIME_FUNCTION **)&dispatch->FunctionEntry,
                                                   &dispatch->ImageBase );
    }

unwind_with_function_entry:
    unwind_lr = context->Lr;
    unwind_sp = context->Sp;
    unwind_fp = context->Fp;
    unwind_context = *context;
    unwind_entry = dispatch->FunctionEntry;
    status = RtlVirtualUnwind2( type, dispatch->ImageBase, pc, dispatch->FunctionEntry, context,
                                NULL, &dispatch->HandlerData, &dispatch->EstablisherFrame,
                                NULL, NULL, NULL, &dispatch->LanguageHandler, 0 );
    /* Native .pdata is ground truth: a successful RtlVirtualUnwind2 driven by a
     * genuine native FunctionEntry must NOT be discarded merely because the
     * ARM64X CodeMap misclassifies pc as EC (kind=0) — a known runtime defect of
     * lld-built ARM64X hybrids (e.g. DXMT dxgi: a native rva reads kind=0 at
     * runtime even though it sits in the ARM64/native CodeMap range with valid
     * .pdata). Only fall to the heuristic EC fallbacks when there was no native
     * entry or the unwind did not succeed; the no-progress check just below
     * stays as the safety net for a genuinely bogus result. */
    if (macrunner_hb_pc_unsafe_for_arm64_unwind( dispatch, &unwind_context, pc ) &&
        !(unwind_entry && status == STATUS_SUCCESS))
    {
        *context = unwind_context;
        macrunner_hb_try_arm64_unwind_methods( dispatch, context, pc );
        return STATUS_SUCCESS;
    }
    if (macrunner_hb_unwind_made_no_progress( pc, unwind_sp, unwind_fp, context ))
    {
        static unsigned int no_progress_count;
        BOOL resumed;
        char sec_name[9];
        DWORD sec_chars;

        macrunner_hb_find_pc_section( context->Pc, sec_name, &sec_chars );
        if (no_progress_count++ < 32)
            MESSAGE( "macrunner-hb-unwind-no-progress: pc=%p after_pc=%p lr=%p "
                     "status=%08lx image=%p function=%p before_sp=%016I64x "
                     "after_sp=%016I64x before_fp=%p after_fp=%p section=%s chars=%08lx\n",
                     (void *)(ULONG_PTR)pc, (void *)(ULONG_PTR)context->Pc,
                     (void *)(ULONG_PTR)unwind_lr, status, (void *)(ULONG_PTR)dispatch->ImageBase,
                     dispatch->FunctionEntry, unwind_sp, context->Sp,
                     (void *)(ULONG_PTR)unwind_fp, (void *)(ULONG_PTR)context->Fp,
                     sec_name, sec_chars );

        if (macrunner_hb_try_arm64_unwind_methods( dispatch, context, pc ))
            return STATUS_SUCCESS;
        resumed = macrunner_hb_unwind_leaf_via_lr( dispatch, context, pc, unwind_lr );
        if (resumed) return STATUS_SUCCESS;
        macrunner_hb_stop_unwind_at_boundary( dispatch, context );
        return STATUS_SUCCESS;
    }
    if (status != STATUS_SUCCESS)
    {
        if (!dispatch->FunctionEntry &&
            macrunner_hb_try_arm64_unwind_methods( dispatch, context, pc ))
            return STATUS_SUCCESS;
        if (macrunner_hb_trace_arm64_seh_invalid_disposition())
            MESSAGE( "macrunner-hb-seh-invalid: reason=unwind-metadata-missing pc=%p lr=%p "
                 "type=%lu image=%p function=%p sp=%016I64x stack=%p-%p\n",
                 (void *)pc, (void *)context->Lr, (unsigned long)type,
                 (void *)dispatch->ImageBase, dispatch->FunctionEntry,
                 context->Sp, NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
        WARN( "exception data not found for pc %p, lr %p\n", (void *)pc, (void *)context->Lr );
        return STATUS_INVALID_DISPOSITION;
    }
    return STATUS_SUCCESS;
}


/**********************************************************************
 *           unwind_exception_handler
 *
 * Handler for exceptions happening while calling an unwind handler.
 */
EXCEPTION_DISPOSITION WINAPI unwind_exception_handler( EXCEPTION_RECORD *record, void *frame,
                                                       CONTEXT *context, DISPATCHER_CONTEXT *dispatch )
{
    DISPATCHER_CONTEXT *orig_dispatch = ((DISPATCHER_CONTEXT **)frame)[-2];

    /* copy the original dispatcher into the current one, except for the TargetPc */
    dispatch->ControlPc          = orig_dispatch->ControlPc;
    dispatch->ImageBase          = orig_dispatch->ImageBase;
    dispatch->FunctionEntry      = orig_dispatch->FunctionEntry;
    dispatch->EstablisherFrame   = orig_dispatch->EstablisherFrame;
    dispatch->LanguageHandler    = orig_dispatch->LanguageHandler;
    dispatch->HandlerData        = orig_dispatch->HandlerData;
    dispatch->HistoryTable       = orig_dispatch->HistoryTable;
    dispatch->ScopeIndex         = orig_dispatch->ScopeIndex;
    dispatch->ControlPcIsUnwound = orig_dispatch->ControlPcIsUnwound;
    *dispatch->ContextRecord     = *orig_dispatch->ContextRecord;
    memcpy( dispatch->NonVolatileRegisters, orig_dispatch->NonVolatileRegisters,
            sizeof(DISPATCHER_CONTEXT_NONVOLREG_ARM64) );
    TRACE( "detected collided unwind\n" );
    return ExceptionCollidedUnwind;
}


/**********************************************************************
 *           call_unwind_handler
 */
DWORD WINAPI call_unwind_handler( EXCEPTION_RECORD *rec, ULONG_PTR frame,
                                  CONTEXT *context, void *dispatch, PEXCEPTION_ROUTINE handler );
__ASM_GLOBAL_FUNC( call_unwind_handler,
                   "stp x29, x30, [sp, #-32]!\n\t"
                   ".seh_save_fplr_x 32\n\t"
                   ".seh_endprologue\n\t"
                   ".seh_handler unwind_exception_handler, @except\n\t"
                   "str x3, [sp, #16]\n\t"    /* frame[-2] = dispatch */
                   "blr x4\n\t"
                   "ldp x29, x30, [sp], #32\n\t"
                   "ret" )




/*******************************************************************
 *         nested_exception_handler
 */
EXCEPTION_DISPOSITION WINAPI nested_exception_handler( EXCEPTION_RECORD *rec, void *frame,
                                                       CONTEXT *context, void *dispatch )
{
    if (rec->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)) return ExceptionContinueSearch;
    return ExceptionNestedException;
}

static BOOL macrunner_hb_stack_overflow_repeat_guard( EXCEPTION_RECORD *rec, CONTEXT *orig_context )
{
    struct macrunner_hb_stack_overflow_seen
    {
        DWORD tid;
        DWORD64 pc;
        DWORD64 sp;
        DWORD64 addr;
        unsigned int repeat;
    };
    static struct macrunner_hb_stack_overflow_seen seen[32];
    static unsigned int report_count;
    TEB *teb = NtCurrentTeb();
    ULONG_PTR stack_lo = (ULONG_PTR)teb->Tib.StackLimit;
    ULONG_PTR stack_hi = (ULONG_PTR)teb->Tib.StackBase;
    DWORD tid = HandleToULong( teb->ClientId.UniqueThread );
    DWORD64 pc = orig_context->Pc;
    DWORD64 sp = orig_context->Sp;
    DWORD64 addr = (DWORD64)(ULONG_PTR)rec->ExceptionAddress;
    DWORD64 bt[4] = { orig_context->Lr, 0, 0, 0 };
    LDR_DATA_TABLE_ENTRY *module = NULL;
    ULONG_PTR module_base = 0, rva = 0;
    unsigned int i;
    struct macrunner_hb_stack_overflow_seen *slot = &seen[tid % ARRAY_SIZE(seen)];

    if (slot->tid == tid && slot->pc == pc && slot->sp == sp && slot->addr == addr) slot->repeat++;
    else
    {
        slot->tid = tid;
        slot->pc = pc;
        slot->sp = sp;
        slot->addr = addr;
        slot->repeat = 1;
    }

    if (LdrFindEntryForAddress( (void *)(ULONG_PTR)pc, &module ) == STATUS_SUCCESS && module)
    {
        module_base = (ULONG_PTR)module->DllBase;
        rva = (ULONG_PTR)pc - module_base;
    }

    __TRY
    {
        ULONG_PTR fp = (ULONG_PTR)orig_context->Fp;
        for (i = 1; i < ARRAY_SIZE(bt); i++)
        {
            if (!fp || (fp & 0xf) || fp < stack_lo || fp + 0x10 > stack_hi) break;
            bt[i] = ((const DWORD64 *)fp)[1];
            fp = ((const DWORD64 *)fp)[0];
        }
    }
    __EXCEPT(macrunner_hb_pe_scan_fault) {}
    __ENDTRY

    if (report_count++ < 32)
        MESSAGE( "macrunner-hb-seh-stack-overflow-record: repeat=%u tid=%04lx addr=%p "
                 "flags=%08lx orig_pc=%p orig_lr=%p orig_sp=%016I64x fp=%p "
                 "module=%p rva=%08Ix stack=%p-%p bt=%p,%p,%p,%p params=%lu "
                 "info0=%016I64x info1=%016I64x%s\n",
                 slot->repeat, tid, rec->ExceptionAddress, rec->ExceptionFlags,
                 (void *)(ULONG_PTR)pc, (void *)(ULONG_PTR)orig_context->Lr, sp,
                 (void *)(ULONG_PTR)orig_context->Fp, (void *)module_base, rva,
                 (void *)stack_lo, (void *)stack_hi, (void *)(ULONG_PTR)bt[0],
                 (void *)(ULONG_PTR)bt[1], (void *)(ULONG_PTR)bt[2],
                 (void *)(ULONG_PTR)bt[3], rec->NumberParameters,
                 rec->NumberParameters > 0 ? rec->ExceptionInformation[0] : 0,
                 rec->NumberParameters > 1 ? rec->ExceptionInformation[1] : 0,
                 slot->repeat >= 2 ? " bail=repeat" : "" );

    return slot->repeat >= 2;
}

/***********************************************************************
 *		call_seh_handler
 */
DWORD WINAPI call_seh_handler( EXCEPTION_RECORD *rec, ULONG_PTR frame,
                               CONTEXT *context, void *dispatch, PEXCEPTION_ROUTINE handler );
__ASM_GLOBAL_FUNC( call_seh_handler,
                   "stp x29, x30, [sp, #-16]!\n\t"
                   ".seh_save_fplr_x 16\n\t"
                   ".seh_endprologue\n\t"
                   ".seh_handler nested_exception_handler, @except\n\t"
                   "blr x4\n\t"
                   "ldp x29, x30, [sp], #16\n\t"
                   "ret" )


/**********************************************************************
 *           call_seh_handlers
 *
 * Call the SEH handlers.
 */
NTSTATUS call_seh_handlers( EXCEPTION_RECORD *rec, CONTEXT *orig_context )
{
    struct macrunner_hb_unwind_seen
    {
        DWORD64 pc;
        DWORD64 fp;
        DWORD64 sp;
    };
    EXCEPTION_REGISTRATION_RECORD *teb_frame = NtCurrentTeb()->Tib.ExceptionList;
    const EXCEPTION_RECORD *old_record = macrunner_hb_current_exception_record;
    /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 321 — КОНТЕКСТ НА ВХОДЕ.
     *
     * Итерация 320: отказ приходит на ПЕРВОМ шаге разматывания, значит разматыватель исправен,
     * а контекст ему подан уже с гостевым кадром. Печатаем Sp и Fp ДО первого шага: если Sp уже
     * гостевой — портится у источника исключения; если Sp хостовый, а кадр гостевой — расходятся
     * Sp и Fp, и виновата разметка кадра самой RtlRaiseStatus. Первые 8 раз. */
    {
        static int e_n;
        if (e_n++ < 8 && orig_context)
            MESSAGE( "macrunner-seh-entry: n=%d pc=%I64x sp=%I64x fp=%I64x lr=%I64x код=%08x "
                 "границы=%p-%p\n",
                 e_n, orig_context->Pc, orig_context->Sp, orig_context->Fp, orig_context->Lr,
                 rec ? rec->ExceptionCode : 0,
                 NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
    }
    DISPATCHER_CONTEXT_NONVOLREG_ARM64 nonvol_regs;
    UNWIND_HISTORY_TABLE table;
    DISPATCHER_CONTEXT dispatch;
    struct macrunner_hb_unwind_seen unwind_seen[32];
    unsigned int unwind_seen_count = 0;
    CONTEXT *context;
    NTSTATUS status;
    ULONG_PTR frame;
    DWORD res;
    unsigned int i;

    macrunner_hb_trace_tagged_exception_context( rec, orig_context );
    macrunner_hb_trace_first_chance_exception( rec, orig_context );
    if (rec->ExceptionCode == STATUS_STACK_OVERFLOW)
    {
        if (macrunner_hb_stack_overflow_repeat_guard( rec, orig_context ))
            return STATUS_UNHANDLED_EXCEPTION;
    }
    if (macrunner_hb_fix_tagged_arm64ec_misalignment( rec, orig_context ))
        return STATUS_SUCCESS;
    if (macrunner_hb_fix_syscall_data_boundary_exception( rec, orig_context ))
        return STATUS_SUCCESS;

    if (!(context = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*context) )))
        return STATUS_NO_MEMORY;
    *context = *orig_context;
    macrunner_hb_current_exception_record = rec;
    dispatch.TargetPc      = 0;
    dispatch.ContextRecord = context;
    dispatch.HistoryTable  = &table;
    dispatch.NonVolatileRegisters = nonvol_regs.Buffer;

    for (;;)
    {
        for (i = 0; i < unwind_seen_count; i++)
        {
            if (unwind_seen[i].pc == context->Pc &&
                unwind_seen[i].fp == context->Fp &&
                unwind_seen[i].sp == context->Sp)
            {
                if (macrunner_hb_trace_arm64_seh_invalid_disposition())
                    MESSAGE( "macrunner-hb-seh-boundary: reason=unwind-no-progress pc=%p "
                         "fp=%p sp=%016I64x rec_code=%08lx stack=%p-%p\n",
                         (void *)(ULONG_PTR)context->Pc, (void *)(ULONG_PTR)context->Fp,
                         context->Sp, rec->ExceptionCode, NtCurrentTeb()->Tib.StackLimit,
                         NtCurrentTeb()->Tib.StackBase );
                macrunner_hb_stop_unwind_at_boundary( &dispatch, context );
                goto unwind_done;
            }
        }
        if (unwind_seen_count < ARRAY_SIZE(unwind_seen))
        {
            unwind_seen[unwind_seen_count].pc = context->Pc;
            unwind_seen[unwind_seen_count].fp = context->Fp;
            unwind_seen[unwind_seen_count].sp = context->Sp;
            unwind_seen_count++;
        }
        status = virtual_unwind( UNW_FLAG_EHANDLER, &dispatch, context );
        if (status != STATUS_SUCCESS) goto done;

    unwind_done:
        if (!dispatch.EstablisherFrame) break;

        /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 320 — ШАГИ РАЗМАТЫВАНИЯ.
         *
         * Итерация 319 показала чтением: `0xb056cf580` не записан нами, а ПРОИЗВЕДЁН здесь
         * разматывателем как EstablisherFrame и лежит в гостевой области. Чтобы назвать, с
         * какого кадра разматывание туда уходит, печатаем пару (Pc, кадр) на КАЖДОМ шаге, а
         * не только на отказавшем: приём «печатать данные шага, а не факт отказа» сегодня
         * дважды дал ответ там, где печать самого отказа молчала. Первые 24 шага. */
        {
            static int uw_n;
            if (uw_n++ < 24)
                MESSAGE( "macrunner-unwind-step: n=%d pc=%I64x кадр=%I64x обработчик=%p границы=%p-%p\n",
                     uw_n, context->Pc, dispatch.EstablisherFrame,
                     dispatch.LanguageHandler,
                     NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
        }
        if (!is_valid_frame( dispatch.EstablisherFrame ))
        {
            ERR( "invalid frame %I64x (%p-%p)\n", dispatch.EstablisherFrame,
                 NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
            rec->ExceptionFlags |= EXCEPTION_STACK_INVALID;
            break;
        }

        if (dispatch.LanguageHandler)
        {
            TRACE( "calling handler %p (rec=%p, frame=%I64x context=%p, dispatch=%p)\n",
                   dispatch.LanguageHandler, rec, dispatch.EstablisherFrame, orig_context, &dispatch );
            res = call_seh_handler( rec, dispatch.EstablisherFrame, orig_context,
                                    &dispatch, dispatch.LanguageHandler );
            rec->ExceptionFlags &= EXCEPTION_NONCONTINUABLE;
            TRACE( "handler at %p returned %lu\n", dispatch.LanguageHandler, res );
            macrunner_hb_exit_origin_seh_handler_observe( "language", dispatch.LanguageHandler,
                                                          dispatch.ControlPc,
                                                          dispatch.EstablisherFrame, res );

            switch (res)
            {
            case ExceptionContinueExecution:
                status = (rec->ExceptionFlags & EXCEPTION_NONCONTINUABLE) ? STATUS_NONCONTINUABLE_EXCEPTION : STATUS_SUCCESS;
                goto done;
            case ExceptionContinueSearch:
                break;
            case ExceptionNestedException:
                rec->ExceptionFlags |= EXCEPTION_NESTED_CALL;
                TRACE( "nested exception\n" );
                break;
            case ExceptionCollidedUnwind:
                RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                                  dispatch.ControlPc, dispatch.FunctionEntry,
                                  context, &dispatch.HandlerData, &frame, NULL );
                goto unwind_done;
            default:
                if (macrunner_hb_trace_arm64_seh_invalid_disposition())
                    MESSAGE( "macrunner-hb-seh-invalid: reason=language-handler-bad-disposition "
                         "res=%lu handler=%p control_pc=%p establisher=%I64x rec_code=%08lx "
                         "sp=%016I64x stack=%p-%p\n",
                         res, dispatch.LanguageHandler, (void *)dispatch.ControlPc,
                         dispatch.EstablisherFrame, rec->ExceptionCode, context->Sp,
                         NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
                status = STATUS_INVALID_DISPOSITION;
                goto done;
            }
        }
        /* hack: call wine handlers registered in the tib list */
        else while (is_valid_frame( (ULONG_PTR)teb_frame ) && (ULONG64)teb_frame < context->Sp)
        {
            TRACE( "calling TEB handler %p (rec=%p frame=%p context=%p dispatch=%p) sp=%I64x\n",
                   teb_frame->Handler, rec, teb_frame, orig_context, &dispatch, context->Sp );
            res = call_seh_handler( rec, (ULONG_PTR)teb_frame, orig_context,
                                    &dispatch, (PEXCEPTION_ROUTINE)teb_frame->Handler );
            TRACE( "TEB handler at %p returned %lu\n", teb_frame->Handler, res );
            macrunner_hb_exit_origin_seh_handler_observe( "teb", teb_frame->Handler,
                                                          context->Pc, (ULONG_PTR)teb_frame,
                                                          res );

            switch (res)
            {
            case ExceptionContinueExecution:
                status = (rec->ExceptionFlags & EXCEPTION_NONCONTINUABLE) ? STATUS_NONCONTINUABLE_EXCEPTION : STATUS_SUCCESS;
                goto done;
            case ExceptionContinueSearch:
                break;
            case ExceptionNestedException:
                rec->ExceptionFlags |= EXCEPTION_NESTED_CALL;
                TRACE( "nested exception\n" );
                break;
            case ExceptionCollidedUnwind:
                RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                                  dispatch.ControlPc, dispatch.FunctionEntry,
                                  context, &dispatch.HandlerData, &frame, NULL );
                teb_frame = teb_frame->Prev;
                goto unwind_done;
            default:
                if (macrunner_hb_trace_arm64_seh_invalid_disposition())
                    MESSAGE( "macrunner-hb-seh-invalid: reason=teb-handler-bad-disposition "
                         "res=%lu handler=%p frame=%p rec_code=%08lx sp=%016I64x "
                         "stack=%p-%p\n",
                         res, teb_frame->Handler, teb_frame, rec->ExceptionCode,
                         context->Sp, NtCurrentTeb()->Tib.StackLimit,
                         NtCurrentTeb()->Tib.StackBase );
                status = STATUS_INVALID_DISPOSITION;
                goto done;
            }
            teb_frame = teb_frame->Prev;
        }

        if (context->Sp == (ULONG64)NtCurrentTeb()->Tib.StackBase) break;
    }
    status = STATUS_UNHANDLED_EXCEPTION;

done:
    macrunner_hb_current_exception_record = old_record;
    RtlFreeHeap( GetProcessHeap(), 0, context );
    return status;
}


/*******************************************************************
 *		KiUserExceptionDispatcher (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( KiUserExceptionDispatcher,
                   ".seh_context\n\t"
                   ".seh_endprologue\n\t"
                   "adrp x16, pWow64PrepareForException\n\t"
                   "ldr x16, [x16, #:lo12:pWow64PrepareForException]\n\t"
                   "cbz x16, 1f\n\t"
                   "add x0, sp, #0x3b0\n\t"     /* rec */
                   "mov x1, sp\n\t"             /* context */
                   "blr x16\n"
                   "1:\tadd x0, sp, #0x3b0\n\t" /* rec */
                   "mov x1, sp\n\t"             /* context */
                   "bl dispatch_exception\n\t"
                   "brk #1" )


/*******************************************************************
 *		KiUserApcDispatcher (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( KiUserApcDispatcher,
                   ".seh_context\n\t"
                   "nop\n\t"
                   ".seh_stackalloc 0x30\n\t"
                   ".seh_endprologue\n\t"
                   "ldp x16, x0, [sp]\n\t"        /* func, arg1 */
                   "ldp x1, x2, [sp, #0x10]\n\t"  /* arg2, arg3 */
                   "add x3, sp, #0x30\n\t"        /* context (FIXME) */
                   "blr x16\n\t"
                   "add x0, sp, #0x30\n\t"        /* context */
                   "ldr w1, [sp, #0x20]\n\t"      /* alertable */
                   "bl NtContinue\n\t"
                   "brk #1" )


/*******************************************************************
 *		KiUserCallbackDispatcher (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( KiUserCallbackDispatcher,
                   ".seh_pushframe\n\t"
                   "nop\n\t"
                   ".seh_stackalloc 0x20\n\t"
                   "nop\n\t"
                   ".seh_save_reg lr, 0x18\n\t"
                   ".seh_endprologue\n\t"
                   ".seh_handler user_callback_handler, @except\n\t"
                   "ldr x0, [sp]\n\t"             /* args */
                   "ldp w1, w2, [sp, #0x08]\n\t"  /* len, id */
                   "ldr x3, [x18, 0x60]\n\t"      /* peb */
                   "ldr x3, [x3, 0x58]\n\t"       /* peb->KernelCallbackTable */
                   "ldr x15, [x3, x2, lsl #3]\n\t"
                   "blr x15\n\t"
                   ".globl KiUserCallbackDispatcherReturn\n"
                   "KiUserCallbackDispatcherReturn:\n\t"
                   "mov x2, x0\n\t"               /* status */
                   "mov x1, #0\n\t"               /* ret_len */
                   "mov x0, x1\n\t"               /* ret_ptr */
                   "bl NtCallbackReturn\n\t"
                   "bl RtlRaiseStatus\n\t"
                   "brk #1" )


/**********************************************************************
 *           consolidate_callback
 *
 * Wrapper function to call a consolidate callback from a fake frame.
 * If the callback executes RtlUnwindEx (like for example done in C++ handlers),
 * we have to skip all frames which were already processed. To do that we
 * trick the unwinding functions into thinking the call came from somewhere
 * else.
 */
void WINAPI DECLSPEC_NORETURN consolidate_callback( CONTEXT *context,
                                                    void *(CALLBACK *callback)(EXCEPTION_RECORD *),
                                                    EXCEPTION_RECORD *rec );
__ASM_GLOBAL_FUNC( consolidate_callback,
                   "stp x29, x30, [sp, #-16]!\n\t"
                   ".seh_save_fplr_x 16\n\t"
                   "sub sp, sp, #0x390\n\t"
                   ".seh_stackalloc 0x390\n\t"
                   ".seh_endprologue\n\t"
                   "mov x4, sp\n\t"
                   /* copy the context onto the stack */
                   "mov x5, #0x390/16\n"
                   "1:\tldp x6, x7, [x0], #16\n\t"
                   "stp x6, x7, [x4], #16\n\t"
                   "subs x5, x5, #1\n\t"
                   "b.ne 1b\n\t"
                   "mov x0, x2\n\t"
                   "b invoke_callback" )
__ASM_GLOBAL_FUNC( invoke_callback,
                   ".seh_context\n\t"
                   ".seh_endprologue\n\t"
                   "blr x1\n\t"
                   "str x0, [sp, #0x108]\n\t" /* context->Pc */
                   "mov x0, sp\n\t"
                   "mov w1, #0\n\t"
                   "b NtContinue" )


/*******************************************************************
 *              RtlRestoreContext (NTDLL.@)
 */
void CDECL RtlRestoreContext( CONTEXT *context, EXCEPTION_RECORD *rec )
{
    {   /* ★★★★★★ MacRunner 2026-08-31 — ОТКУДА БЕРЁТСЯ ЦЕЛЬ ВОЗОБНОВЛЕНИЯ.
         *
         * Приборы установили: раскрутка 22 шагов проходит ЧИСТО, все pc в модулях,
         * а следом приходит НОВОЕ исключение с pc=0x7ffd0… — страница данных.
         * Значит негодный адрес появляется ИМЕННО ЗДЕСЬ, в точке передачи управления
         * на продолжение. Печатаем цель и того, кто её назначил. */
        static unsigned int rc_count;
        if (rc_count++ < 24 && context)
        {   /* ★ 31.08 — ЧТО ЛЕЖИТ В СЛОТЕ ВОЗВРАТА У ЦЕЛИ ВОЗОБНОВЛЕНИЯ.
             * Возобновление отдаёт законный pc, а отказ приходит позже, на `ret`.
             * Эпилог обработчика грузит x30 ИЗ СТЕКА по своему sp. Если раскрутка
             * восстановила sp не тот, слот окажется чужим — и это видно ЗДЕСЬ,
             * до передачи управления, а не постфактум по регистрам. */
            const ULONG_PTR *q = (const ULONG_PTR *)(ULONG_PTR)context->Sp;
            MESSAGE( "macrunner-hb-возобновление-стек: n=%u sp=%p [sp]=%p [sp+8]=%p "
                     "[sp+0x10]=%p [sp+0x18]=%p [sp+0x20]=%p\n",
                     rc_count, (void *)(ULONG_PTR)context->Sp,
                     (void *)q[0], (void *)q[1], (void *)q[2], (void *)q[3], (void *)q[4] );
        }
        if (rc_count <= 24)
            MESSAGE( "macrunner-hb-возобновление: n=%u цель_pc=%p sp=%p lr=%p код=%08lx флаги=%08lx\n",
                     rc_count, (void *)(ULONG_PTR)(context ? context->Pc : 0),
                     (void *)(ULONG_PTR)(context ? context->Sp : 0),
                     (void *)(ULONG_PTR)(context ? context->Lr : 0),
                     rec ? (unsigned long)rec->ExceptionCode : 0ul,
                     rec ? (unsigned long)rec->ExceptionFlags : 0ul );
    }
    EXCEPTION_REGISTRATION_RECORD *teb_frame = NtCurrentTeb()->Tib.ExceptionList;

    if (rec && rec->ExceptionCode == STATUS_LONGJUMP && rec->NumberParameters >= 1)
    {
        struct _JUMP_BUFFER *jmp = (struct _JUMP_BUFFER *)rec->ExceptionInformation[0];
        int i;

        context->X19  = jmp->X19;
        context->X20  = jmp->X20;
        context->X21  = jmp->X21;
        context->X22  = jmp->X22;
        context->X23  = jmp->X23;
        context->X24  = jmp->X24;
        context->X25  = jmp->X25;
        context->X26  = jmp->X26;
        context->X27  = jmp->X27;
        context->X28  = jmp->X28;
        context->Fp   = jmp->Fp;
        context->Pc   = jmp->Lr;
        macrunner_hb_note_pc_set( 7, context->Pc, context->Sp );
        context->Sp   = jmp->Sp;
        context->Fpcr = jmp->Fpcr;
        context->Fpsr = jmp->Fpsr;

        for (i = 0; i < 8; i++)
            context->V[8+i].D[0] = jmp->D[i];
    }
    else if (rec && rec->ExceptionCode == STATUS_UNWIND_CONSOLIDATE && rec->NumberParameters >= 1)
    {
        PVOID (CALLBACK *consolidate)(EXCEPTION_RECORD *) = (void *)rec->ExceptionInformation[0];
        TRACE( "calling consolidate callback %p (rec=%p)\n", consolidate, rec );
        consolidate_callback( context, consolidate, rec );
    }

    /* hack: remove no longer accessible TEB frames */
    while (is_valid_frame( (ULONG_PTR)teb_frame ) && (ULONG64)teb_frame < context->Sp)
    {
        TRACE( "removing TEB frame: %p\n", teb_frame );
        teb_frame = __wine_pop_frame( teb_frame );
    }

    TRACE( "returning to %I64x stack %I64x\n", context->Pc, context->Sp );
    NtContinue( context, FALSE );
}

/*******************************************************************
 *		RtlUnwindEx (NTDLL.@)
 */
void WINAPI RtlUnwindEx( PVOID end_frame, PVOID target_ip, EXCEPTION_RECORD *rec,
                         PVOID retval, CONTEXT *context, UNWIND_HISTORY_TABLE *table )
{
    EXCEPTION_REGISTRATION_RECORD *teb_frame = NtCurrentTeb()->Tib.ExceptionList;
    DISPATCHER_CONTEXT_NONVOLREG_ARM64 nonvol_regs;
    EXCEPTION_RECORD record;
    DISPATCHER_CONTEXT dispatch;
    CONTEXT new_context;
    NTSTATUS status;
    static unsigned int scaffold_skip_count;
    ULONG_PTR frame;
    DWORD i, res;

    RtlCaptureContext( context );
    new_context = *context;

    /* build an exception record, if we do not have one */
    if (!rec)
    {
        record.ExceptionCode    = STATUS_UNWIND;
        record.ExceptionFlags   = 0;
        record.ExceptionRecord  = NULL;
        record.ExceptionAddress = (void *)context->Pc;
        record.NumberParameters = 0;
        rec = &record;
    }

    rec->ExceptionFlags |= EXCEPTION_UNWINDING | (end_frame ? 0 : EXCEPTION_EXIT_UNWIND);

    TRACE( "code=%lx flags=%lx end_frame=%p target_ip=%p\n",
           rec->ExceptionCode, rec->ExceptionFlags, end_frame, target_ip );
    for (i = 0; i < min( EXCEPTION_MAXIMUM_PARAMETERS, rec->NumberParameters ); i++)
        TRACE( " info[%ld]=%016I64x\n", i, rec->ExceptionInformation[i] );
    TRACE_CONTEXT( context );

    dispatch.TargetPc         = (ULONG64)target_ip;
    dispatch.ContextRecord    = context;
    dispatch.HistoryTable     = table;
    dispatch.NonVolatileRegisters = nonvol_regs.Buffer;

    for (;;)
    {
        status = virtual_unwind( UNW_FLAG_UHANDLER, &dispatch, &new_context );
        if (status != STATUS_SUCCESS) raise_status( status, rec );

    unwind_done:
        if (!dispatch.EstablisherFrame) break;

        if (!is_valid_frame( dispatch.EstablisherFrame ))
        {
            ERR( "invalid frame %I64x (%p-%p)\n", dispatch.EstablisherFrame,
                 NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
            rec->ExceptionFlags |= EXCEPTION_STACK_INVALID;
            break;
        }

        if (dispatch.LanguageHandler)
        {
            if (end_frame && (dispatch.EstablisherFrame > (ULONG64)end_frame))
            {
                if (macrunner_hb_is_arm64ec_unwind_scaffold_overshoot( dispatch.EstablisherFrame, end_frame ))
                {
                    if (scaffold_skip_count++ < 64)
                        MESSAGE( "macrunner-hb-rtlunwind-scaffold-skip: establisher=%p "
                                 "end_frame=%p control_pc=%p handler=%p target=%p\n",
                                 (void *)(ULONG_PTR)dispatch.EstablisherFrame, end_frame,
                                 (void *)(ULONG_PTR)dispatch.ControlPc,
                                 dispatch.LanguageHandler, target_ip );
                    {   /* парная точка: КТО назначил цель. `target_ip` приходит от
                         * обработчика языка; если он вернул адрес данных, видно здесь. */
                        static unsigned int ti_count;
                        if (ti_count++ < 24)
                            MESSAGE( "macrunner-hb-цель-обработчика: n=%u target_ip=%p handler=%p ControlPc=%p\n",
                                     ti_count, target_ip, (void *)dispatch.LanguageHandler,
                                     (void *)(ULONG_PTR)dispatch.ControlPc );
                    }
                    new_context.Pc = (ULONG64)target_ip;
                    new_context.Sp = (ULONG64)end_frame;
                    *context = new_context;
                    rec->ExceptionFlags |= EXCEPTION_TARGET_UNWIND;
                    break;
                }
                ERR( "invalid end frame %I64x/%p\n", dispatch.EstablisherFrame, end_frame );
                raise_status( STATUS_INVALID_UNWIND_TARGET, rec );
            }
            if (dispatch.EstablisherFrame == (ULONG64)end_frame) rec->ExceptionFlags |= EXCEPTION_TARGET_UNWIND;

            TRACE( "calling handler %p (rec=%p, frame=%I64x context=%p, dispatch=%p)\n",
                   dispatch.LanguageHandler, rec, dispatch.EstablisherFrame,
                   dispatch.ContextRecord, &dispatch );
            res = call_unwind_handler( rec, dispatch.EstablisherFrame, dispatch.ContextRecord,
                                       &dispatch, dispatch.LanguageHandler );
            TRACE( "handler %p returned %lx\n", dispatch.LanguageHandler, res );

            switch (res)
            {
            case ExceptionContinueSearch:
                rec->ExceptionFlags &= ~EXCEPTION_COLLIDED_UNWIND;
                break;
            case ExceptionCollidedUnwind:
                new_context = *context;
                RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                                  dispatch.ControlPc, dispatch.FunctionEntry,
                                  &new_context, &dispatch.HandlerData, &frame,
                                  NULL );
                rec->ExceptionFlags |= EXCEPTION_COLLIDED_UNWIND;
                goto unwind_done;
            default:
                raise_status( STATUS_INVALID_DISPOSITION, rec );
                break;
            }
        }
        else  /* hack: call builtin handlers registered in the tib list */
        {
            while (is_valid_frame( (ULONG_PTR)teb_frame ) &&
                   (ULONG64)teb_frame < new_context.Sp &&
                   (ULONG64)teb_frame < (ULONG64)end_frame)
            {
                TRACE( "calling TEB handler %p (rec=%p, frame=%p context=%p, dispatch=%p)\n",
                       teb_frame->Handler, rec, teb_frame, dispatch.ContextRecord, &dispatch );
                res = call_unwind_handler( rec, (ULONG_PTR)teb_frame, dispatch.ContextRecord, &dispatch,
                                           (PEXCEPTION_ROUTINE)teb_frame->Handler );
                TRACE( "handler at %p returned %lu\n", teb_frame->Handler, res );
                teb_frame = __wine_pop_frame( teb_frame );

                switch (res)
                {
                case ExceptionContinueSearch:
                    rec->ExceptionFlags &= ~EXCEPTION_COLLIDED_UNWIND;
                    break;
                case ExceptionCollidedUnwind:
                    new_context = *context;
                    RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                                      dispatch.ControlPc, dispatch.FunctionEntry,
                                      &new_context, &dispatch.HandlerData,
                                      &frame, NULL );
                    rec->ExceptionFlags |= EXCEPTION_COLLIDED_UNWIND;
                    goto unwind_done;
                default:
                    raise_status( STATUS_INVALID_DISPOSITION, rec );
                    break;
                }
            }
            if ((ULONG64)teb_frame == (ULONG64)end_frame && (ULONG64)end_frame < new_context.Sp) break;
        }

        if (dispatch.EstablisherFrame == (ULONG64)end_frame) break;
        *context = new_context;
    }

    if (rec->ExceptionCode != STATUS_UNWIND_CONSOLIDATE)
    {
        context->Pc = (ULONG64)target_ip;
        macrunner_hb_note_pc_set( 8, context->Pc, context->Sp );
    }
    else if (rec->ExceptionInformation[10] == -1)
        rec->ExceptionInformation[10] = (ULONG_PTR)&nonvol_regs;

    context->X0 = (ULONG64)retval;
    RtlRestoreContext(context, rec);
}


/*************************************************************************
 *		RtlGetNativeSystemInformation (NTDLL.@)
 */
NTSTATUS WINAPI RtlGetNativeSystemInformation( SYSTEM_INFORMATION_CLASS class,
                                               void *info, ULONG size, ULONG *ret_size )
{
    return NtQuerySystemInformation( class, info, size, ret_size );
}


static ULONGLONG cpu_features_bitmap[2];
static RTL_RUN_ONCE init_once = RTL_RUN_ONCE_INIT;

static DWORD WINAPI init_cpu_features( RTL_RUN_ONCE *once, void *param, void **context )
{
    return !NtQuerySystemInformation( SystemProcessorFeaturesBitMapInformation,
                                      cpu_features_bitmap, sizeof(cpu_features_bitmap), NULL );
}


/***********************************************************************
 *           RtlIsProcessorFeaturePresent [NTDLL.@]
 */
BOOLEAN WINAPI RtlIsProcessorFeaturePresent( UINT feature )
{
    static const ULONGLONG arm64_features =
        (1ull << PF_COMPARE_EXCHANGE_DOUBLE) |
        (1ull << PF_NX_ENABLED) |
        (1ull << PF_ARM_VFP_32_REGISTERS_AVAILABLE) |
        (1ull << PF_ARM_NEON_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_SECOND_LEVEL_ADDRESS_TRANSLATION) |
        (1ull << PF_FASTFAIL_AVAILABLE) |
        (1ull << PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE) |
        (1ull << PF_ARM_64BIT_LOADSTORE_ATOMIC) |
        (1ull << PF_ARM_EXTERNAL_CACHE_AVAILABLE) |
        (1ull << PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_V8_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE2_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE2_1_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_AES_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_PMULL128_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_BITPERM_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_BF16_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_EBF16_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_B16B16_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_SHA3_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_SM4_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_I8MM_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_F32MM_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_F64MM_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_LSE2_AVAILABLE);

    if (feature < PROCESSOR_FEATURE_MAX)
        return (arm64_features & (1ull << feature)) && user_shared_data->ProcessorFeatures[feature];

    feature -= PROCESSOR_FEATURE_MAX;
    if (feature >= 8 * sizeof(cpu_features_bitmap)) return FALSE;

    RtlRunOnceExecuteOnce( &init_once, init_cpu_features, NULL, NULL );
    return !!(cpu_features_bitmap[feature / 64] & (1ull << (feature % 64)));
}


/*************************************************************************
 *		RtlWalkFrameChain (NTDLL.@)
 */
ULONG WINAPI RtlWalkFrameChain( void **buffer, ULONG count, ULONG flags )
{
    UNWIND_HISTORY_TABLE table;
    RUNTIME_FUNCTION *func;
    PEXCEPTION_ROUTINE handler;
    ULONG_PTR pc, frame, base;
    CONTEXT context;
    void *data;
    ULONG i, skip = flags >> 8, num_entries = 0;

    RtlCaptureContext( &context );

    for (i = 0; i < count; i++)
    {
        pc = context.Pc;
        if (context.ContextFlags & CONTEXT_UNWOUND_TO_CALL) pc -= 4;
        pc = macrunner_hb_normalize_arm64ec_host_pc( pc );
        func = RtlLookupFunctionEntry( pc, &base, &table );
        if (RtlVirtualUnwind2( UNW_FLAG_NHANDLER, base, pc, func, &context, NULL,
                               &data, &frame, NULL, NULL, NULL, &handler, 0 ))
            break;
        if (!context.Pc) break;
        if (!frame || !is_valid_frame( frame )) break;
        if (context.Sp == (ULONG_PTR)NtCurrentTeb()->Tib.StackBase) break;
        if (i >= skip) buffer[num_entries++] = (void *)context.Pc;
    }
    return num_entries;
}


/***********************************************************************
 *		__C_ExecuteExceptionFilter
 */
__ASM_GLOBAL_FUNC( __C_ExecuteExceptionFilter,
                   "stp x29, x30, [sp, #-96]!\n\t"
                   ".seh_save_fplr_x 96\n\t"
                   "stp x19, x20, [sp, #16]\n\t"
                   ".seh_save_regp x19, 16\n\t"
                   "stp x21, x22, [sp, #32]\n\t"
                   ".seh_save_regp x21, 32\n\t"
                   "stp x23, x24, [sp, #48]\n\t"
                   ".seh_save_regp x23, 48\n\t"
                   "stp x25, x26, [sp, #64]\n\t"
                   ".seh_save_regp x25, 64\n\t"
                   "stp x27, x28, [sp, #80]\n\t"
                   ".seh_save_regp x27, 80\n\t"
                   ".seh_endprologue\n\t"
                   "ldp x19, x20, [x3, #0]\n\t" /* nonvolatile regs */
                   "ldp x21, x22, [x3, #16]\n\t"
                   "ldp x23, x24, [x3, #32]\n\t"
                   "ldp x25, x26, [x3, #48]\n\t"
                   "ldp x27, x28, [x3, #64]\n\t"
                   "ldr x1, [x3, #80]\n\t"      /* x29 = frame */
                   "blr x2\n\t"                 /* filter */
                   "ldp x19, x20, [sp, #16]\n\t"
                   "ldp x21, x22, [sp, #32]\n\t"
                   "ldp x23, x24, [sp, #48]\n\t"
                   "ldp x25, x26, [sp, #64]\n\t"
                   "ldp x27, x28, [sp, #80]\n\t"
                   "ldp x29, x30, [sp], #96\n\t"
                   "ret")


/***********************************************************************
 *		RtlRaiseException (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( RtlRaiseException,
                   "sub x17, sp, #0x4000\n\t"
                   ".seh_nop\n\t"
                   "ldr x16, [x18, #0x10]\n\t"       /* TEB.StackLimit */
                   ".seh_nop\n\t"
                   "cmp x17, x16\n\t"
                   ".seh_nop\n\t"
                   "b.hs 1f\n\t"
                   ".seh_nop\n\t"
                   "ldr x15, [x18, #0x08]\n\t"       /* TEB.StackBase */
                   ".seh_nop\n\t"
                   "add x17, x16, #0x100000\n\t"
                   ".seh_nop\n\t"
                   "cmp x17, x15\n\t"
                   ".seh_nop\n\t"
                   "b.lo 2f\n\t"
                   ".seh_nop\n\t"
                   "mov x17, x15\n"
                   ".seh_nop\n\t"
                   "2:\tmov sp, x17\n"
                   ".seh_nop\n\t"
                   "1:\n\t"
                   "sub sp, sp, #0x3b0\n\t" /* 0x390 (context) + 0x20 */
                   ".seh_stackalloc 0x3b0\n\t"
                   "stp x29, x30, [sp]\n\t"
                   ".seh_save_fplr 0\n\t"
                   ".seh_endprologue\n\t"
                   "mov x29, sp\n\t"
                   "str x0,  [sp, #0x10]\n\t"
                   "add x0,  sp, #0x20\n\t"
                   "bl RtlCaptureContext\n\t"
                   "add x1,  sp, #0x20\n\t"      /* context pointer */
                   "add x2,  sp, #0x3b0\n\t"     /* orig stack pointer */
                   "str x2,  [x1, #0x100]\n\t"   /* context->Sp */
                   "ldr x0,  [sp, #0x10]\n\t"    /* original first parameter */
                   "str x0,  [x1, #0x08]\n\t"    /* context->X0 */
                   "ldp x4, x5, [sp]\n\t"        /* frame pointer, return address */
                   "stp x4, x5, [x1, #0xf0]\n\t" /* context->Fp, Lr */
                   "str  x5, [x1, #0x108]\n\t"   /* context->Pc */
                   "str  x5, [x0, #0x10]\n\t"    /* rec->ExceptionAddress */
                   "ldr w2, [x1]\n\t"            /* context->ContextFlags */
                   "orr w2, w2, #0x20000000\n\t" /* CONTEXT_UNWOUND_TO_CALL */
                   "str w2, [x1]\n\t"
                   "ldr x3, [x18, #0x60]\n\t"    /* peb */
                   "ldrb w2, [x3, #2]\n\t"       /* peb->BeingDebugged */
                   "cbnz w2, 1f\n\t"
                   "bl dispatch_exception\n"
                   "1:\tmov  x2, #1\n\t"
                   "bl NtRaiseException\n\t"
                   "bl RtlRaiseStatus\n\t"
                   "brk #1" )


/***********************************************************************
 *           _setjmpex (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( NTDLL__setjmpex,
                   ".seh_endprologue\n\t"
                   "str x1,       [x0]\n\t"        /* jmp_buf->Frame */
                   "stp x19, x20, [x0, #0x10]\n\t" /* jmp_buf->X19, X20 */
                   "stp x21, x22, [x0, #0x20]\n\t" /* jmp_buf->X21, X22 */
                   "stp x23, x24, [x0, #0x30]\n\t" /* jmp_buf->X23, X24 */
                   "stp x25, x26, [x0, #0x40]\n\t" /* jmp_buf->X25, X26 */
                   "stp x27, x28, [x0, #0x50]\n\t" /* jmp_buf->X27, X28 */
                   "stp x29, x30, [x0, #0x60]\n\t" /* jmp_buf->Fp,  Lr  */
                   "mov x2,  sp\n\t"
                   "str x2,       [x0, #0x70]\n\t" /* jmp_buf->Sp */
                   "mrs x2,  fpcr\n\t"
                   "mrs x3,  fpsr\n\t"
                   "stp w2, w3,   [x0, #0x78]\n\t" /* jmp_buf->Fpcr,Fpsr */
                   "stp d8,  d9,  [x0, #0x80]\n\t" /* jmp_buf->D[0-1] */
                   "stp d10, d11, [x0, #0x90]\n\t" /* jmp_buf->D[2-3] */
                   "stp d12, d13, [x0, #0xa0]\n\t" /* jmp_buf->D[4-5] */
                   "stp d14, d15, [x0, #0xb0]\n\t" /* jmp_buf->D[6-7] */
                   "mov x0, #0\n\t"
                   "ret" )


/*******************************************************************
 *		longjmp (NTDLL.@)
 */
void __cdecl NTDLL_longjmp( _JUMP_BUFFER *buf, int retval )
{
    EXCEPTION_RECORD rec;

    if (!retval) retval = 1;

    rec.ExceptionCode = STATUS_LONGJUMP;
    rec.ExceptionFlags = 0;
    rec.ExceptionRecord = NULL;
    rec.ExceptionAddress = NULL;
    rec.NumberParameters = 1;
    rec.ExceptionInformation[0] = (DWORD_PTR)buf;
    RtlUnwind( (void *)buf->Frame, (void *)buf->Lr, &rec, IntToPtr(retval) );
}


/***********************************************************************
 *           RtlUserThreadStart (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( RtlUserThreadStart,
                   "stp x29, x30, [sp, #-16]!\n\t"
                   ".seh_save_fplr_x 16\n\t"
                   ".seh_endprologue\n\t"
                   "adrp x8, pBaseThreadInitThunk\n\t"
                   "ldr x8, [x8, #:lo12:pBaseThreadInitThunk]\n\t"
                   "mov x2, x1\n\t"
                   "mov x1, x0\n\t"
                   "mov x0, #0\n\t"
                   "blr x8\n\t"
                   "brk #1\n\t"
                   ".seh_handler call_unhandled_exception_handler, @except" )

/******************************************************************
 *		LdrInitializeThunk (NTDLL.@)
 */
void WINAPI LdrInitializeThunk( CONTEXT *context, ULONG_PTR unk2, ULONG_PTR unk3, ULONG_PTR unk4 )
{
    static unsigned int macrunner_trace_count;
    unsigned int trace_index = macrunner_trace_count++;

    if (trace_index < 64)
        MESSAGE( "macrunner-hb-ldr-init: phase=before index=%u ctx=%p pc=%p lr=%p sp=%p "
                 "x0=%p x1=%p x2=%p x3=%p unk=%p/%p/%p\n",
                 trace_index, context, (void *)context->Pc, (void *)context->Lr,
                 (void *)context->Sp, (void *)context->X0, (void *)context->X1,
                 (void *)context->X2, (void *)context->X3,
                 (void *)unk2, (void *)unk3, (void *)unk4 );
    loader_init( context, (void **)&context->X0 );
    if (trace_index < 64)
        MESSAGE( "macrunner-hb-ldr-init: phase=after-loader index=%u ctx=%p pc=%p lr=%p "
                 "sp=%p entry=%p arg=%p\n",
                 trace_index, context, (void *)context->Pc, (void *)context->Lr,
                 (void *)context->Sp, (void *)context->X0, (void *)context->X1 );
    TRACE_(relay)( "\1Starting thread proc %p (arg=%p)\n", (void *)context->X0, (void *)context->X1 );
    {
        NTSTATUS status = NtContinue( context, TRUE );
        MESSAGE( "macrunner-hb-ldr-init: NtContinue returned status=%08lx index=%u ctx=%p pc=%p sp=%p\n",
                 status, trace_index, context, (void *)context->Pc, (void *)context->Sp );
    }
}


/***********************************************************************
 *           process_breakpoint
 */
__ASM_GLOBAL_FUNC( process_breakpoint,
                   ".seh_endprologue\n\t"
                   ".seh_handler process_breakpoint_handler, @except\n\t"
                   "brk #0xf000\n\t"
                   "ret\n"
                   "process_breakpoint_handler:\n\t"
                   "ldr x4, [x2, #0x108]\n\t" /* context->Pc */
                   "add x4, x4, #4\n\t"
                   "str x4, [x2, #0x108]\n\t"
                   "mov w0, #0\n\t"           /* ExceptionContinueExecution */
                   "ret" )

/***********************************************************************
 *		DbgUiRemoteBreakin   (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( DbgUiRemoteBreakin,
                   "stp x29, x30, [sp, #-16]!\n\t"
                   ".seh_save_fplr_x 16\n\t"
                   ".seh_endprologue\n\t"
                   ".seh_handler DbgUiRemoteBreakin_handler, @except\n\t"
                   "ldr x0, [x18, #0x60]\n\t"       /* NtCurrentTeb()->Peb */
                   "ldrb w0, [x0, 0x02]\n\t"        /* peb->BeingDebugged */
                   "cbz w0, 1f\n\t"
                   "bl DbgBreakPoint\n"
                   "1:\tmov w0, #0\n\t"
                   "bl RtlExitUserThread\n"
                   "DbgUiRemoteBreakin_handler:\n\t"
                   "mov sp, x1\n\t"                 /* frame */
                   "b 1b" )

/**********************************************************************
 *              DbgBreakPoint   (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( DbgBreakPoint, "brk #0xf000; ret"
                    "\n\tnop; nop; nop; nop; nop; nop; nop; nop"
                    "\n\tnop; nop; nop; nop; nop; nop" );

/**********************************************************************
 *              DbgUserBreakPoint   (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( DbgUserBreakPoint, "brk #0xf000; ret"
                    "\n\tnop; nop; nop; nop; nop; nop; nop; nop"
                    "\n\tnop; nop; nop; nop; nop; nop" );

#endif  /* __aarch64__ */
