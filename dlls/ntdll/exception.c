/*
 * NT exception handling routines
 *
 * Copyright 1999 Turchanov Sergey
 * Copyright 1999 Alexandre Julliard
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

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wine/exception.h"
#include "wine/list.h"
#include "wine/debug.h"
#include "excpt.h"
#include "ntdll_misc.h"

WINE_DEFAULT_DEBUG_CHANNEL(seh);
WINE_DECLARE_DEBUG_CHANNEL(threadname);

typedef struct
{
    struct list                 entry;
    PVECTORED_EXCEPTION_HANDLER func;
    ULONG                       count;
} VECTORED_HANDLER;

static struct list vectored_exception_handlers = LIST_INIT(vectored_exception_handlers);
static struct list vectored_continue_handlers  = LIST_INIT(vectored_continue_handlers);
static LONG vectored_exception_handler_count;
static LONG vectored_continue_handler_count;

static RTL_CRITICAL_SECTION vectored_handlers_section;
static RTL_CRITICAL_SECTION_DEBUG critsect_debug =
{
    0, 0, &vectored_handlers_section,
    { &critsect_debug.ProcessLocksList, &critsect_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": vectored_handlers_section") }
};
static RTL_CRITICAL_SECTION vectored_handlers_section = { &critsect_debug, -1, 0, 0, 0, 0 };

static PRTL_EXCEPTION_FILTER unhandled_exception_filter;

struct macrunner_hb_exit_origin_exception
{
    EXCEPTION_RECORD record;
    ULONG_PTR context_pc;
    ULONG_PTR context_sp;
    LONG vectored_disposition;
    NTSTATUS seh_status;
    const char *dispatch_stage;
    ULONG sequence;
    ULONG vectored_handlers;
    ULONG seh_handlers;
    ULONG seh_continue_execution;
    ULONG seh_continue_search;
    ULONG seh_nested;
    ULONG seh_collided;
    ULONG seh_invalid;
    BOOL valid;
};

static struct macrunner_hb_exit_origin_exception macrunner_hb_exit_origin_exception;
static LONG macrunner_hb_exit_origin_lines;

BOOL macrunner_hb_exit_origin_probe_enabled(void)
{
    static const WCHAR nameW[] =
        {'M','A','C','R','U','N','N','E','R','_','H','B','_','E','X','I','T','_',
         'O','R','I','G','I','N','_','P','R','O','B','E',0};
    static int enabled = -1;
    WCHAR value[8];
    UNICODE_STRING name, val;

    if (enabled >= 0) return enabled;
    RtlInitUnicodeString( &name, nameW );
    val.Buffer = value;
    val.Length = 0;
    val.MaximumLength = sizeof(value);
    enabled = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) == STATUS_SUCCESS &&
              value[0] && value[0] != '0';
    return enabled;
}

static BOOL macrunner_hb_exit_origin_is_current(void)
{
    return macrunner_hb_exit_origin_probe_enabled() && GetCurrentThreadId() == 0x3c;
}

static BOOL macrunner_hb_exit_origin_take_line(void)
{
    return InterlockedIncrement( &macrunner_hb_exit_origin_lines ) <= 256;
}

static ULONG_PTR macrunner_hb_exit_origin_context_pc( const CONTEXT *context )
{
#if defined(__x86_64__) || defined(_M_AMD64)
    return context->Rip;
#elif defined(__arm64ec__) || defined(__aarch64__) || defined(_M_ARM64)
    return context->Pc;
#elif defined(__i386__)
    return context->Eip;
#else
    return 0;
#endif
}

static ULONG_PTR macrunner_hb_exit_origin_context_sp( const CONTEXT *context )
{
#if defined(__x86_64__) || defined(_M_AMD64)
    return context->Rsp;
#elif defined(__arm64ec__) || defined(__aarch64__) || defined(_M_ARM64)
    return context->Sp;
#elif defined(__i386__)
    return context->Esp;
#else
    return 0;
#endif
}

static const char *macrunner_hb_exit_origin_av_operation( const EXCEPTION_RECORD *rec )
{
    if (rec->ExceptionCode != STATUS_ACCESS_VIOLATION || !rec->NumberParameters) return "not-av";
    switch (rec->ExceptionInformation[0])
    {
    case 0: return "read";
    case 1: return "write";
    case 8: return "execute";
    default: return "unknown";
    }
}

static void macrunner_hb_exit_origin_exception_begin( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    struct macrunner_hb_exit_origin_exception *state = &macrunner_hb_exit_origin_exception;
    ULONG sequence;

    if (!macrunner_hb_exit_origin_is_current()) return;
    sequence = state->sequence + 1;
    RtlZeroMemory( state, sizeof(*state) );
    state->sequence = sequence;
    state->record = *rec;
    state->context_pc = macrunner_hb_exit_origin_context_pc( context );
    state->context_sp = macrunner_hb_exit_origin_context_sp( context );
    state->vectored_disposition = EXCEPTION_CONTINUE_SEARCH;
    state->seh_status = STATUS_UNHANDLED_EXCEPTION;
    state->dispatch_stage = "entered";
    state->valid = TRUE;
    if (!macrunner_hb_exit_origin_take_line()) return;
    MESSAGE( "macrunner-hb-exit-origin: phase=exception-enter sequence=%lu guest_tid=%04lx "
             "code=0x%08lx flags=0x%08lx address=%p context_pc=%p context_sp=%p "
             "parameters=%lu operation=%s fault_address=%p info2=%p\n",
             state->sequence, GetCurrentThreadId(), rec->ExceptionCode, rec->ExceptionFlags,
             rec->ExceptionAddress, (void *)state->context_pc, (void *)state->context_sp,
             rec->NumberParameters, macrunner_hb_exit_origin_av_operation( rec ),
             rec->NumberParameters > 1 ? (void *)rec->ExceptionInformation[1] : NULL,
             rec->NumberParameters > 2 ? (void *)rec->ExceptionInformation[2] : NULL );
}

static void macrunner_hb_exit_origin_vectored_observe( void *handler, LONG disposition )
{
    struct macrunner_hb_exit_origin_exception *state = &macrunner_hb_exit_origin_exception;

    if (!macrunner_hb_exit_origin_is_current() || !state->valid) return;
    state->vectored_handlers++;
    state->vectored_disposition = disposition;
    if (!macrunner_hb_exit_origin_take_line()) return;
    MESSAGE( "macrunner-hb-exit-origin: phase=vectored-handler sequence=%lu index=%lu "
             "handler=%p disposition=%ld\n", state->sequence, state->vectored_handlers,
             handler, disposition );
}

void macrunner_hb_exit_origin_seh_handler_observe( const char *kind, const void *handler,
                                                    ULONG_PTR control_pc,
                                                    ULONG_PTR establisher_frame,
                                                    DWORD disposition )
{
    struct macrunner_hb_exit_origin_exception *state = &macrunner_hb_exit_origin_exception;

    if (!macrunner_hb_exit_origin_is_current() || !state->valid) return;
    state->seh_handlers++;
    switch (disposition)
    {
    case ExceptionContinueExecution: state->seh_continue_execution++; break;
    case ExceptionContinueSearch: state->seh_continue_search++; break;
    case ExceptionNestedException: state->seh_nested++; break;
    case ExceptionCollidedUnwind: state->seh_collided++; break;
    default: state->seh_invalid++; break;
    }
    if (!macrunner_hb_exit_origin_take_line()) return;
    MESSAGE( "macrunner-hb-exit-origin: phase=seh-handler sequence=%lu index=%lu kind=%s "
             "handler=%p control_pc=%p establisher=%p disposition=%lu\n",
             state->sequence, state->seh_handlers, kind ? kind : "unknown", handler,
             (void *)control_pc, (void *)establisher_frame, disposition );
}

static void macrunner_hb_exit_origin_dispatch_summary( const char *stage, LONG vectored,
                                                       NTSTATUS seh_status )
{
    struct macrunner_hb_exit_origin_exception *state = &macrunner_hb_exit_origin_exception;

    if (!macrunner_hb_exit_origin_is_current() || !state->valid) return;
    state->dispatch_stage = stage;
    state->vectored_disposition = vectored;
    state->seh_status = seh_status;
    if (!macrunner_hb_exit_origin_take_line()) return;
    MESSAGE( "macrunner-hb-exit-origin: phase=dispatch-summary sequence=%lu stage=%s "
             "vectored_handlers=%lu vectored_disposition=%ld seh_status=0x%08lx "
             "seh_handlers=%lu continue=%lu search=%lu nested=%lu collided=%lu invalid=%lu\n",
             state->sequence, stage, state->vectored_handlers, vectored, seh_status,
             state->seh_handlers, state->seh_continue_execution, state->seh_continue_search,
             state->seh_nested, state->seh_collided, state->seh_invalid );
}

void macrunner_hb_exit_origin_probe_rtl_exit( ULONG status, const void *caller, ULONG last )
{
    struct macrunner_hb_exit_origin_exception *state = &macrunner_hb_exit_origin_exception;
    LDR_DATA_TABLE_ENTRY *module = NULL;
    ULONG_PTR module_rva = 0;

    if (!macrunner_hb_exit_origin_is_current() ||
        !macrunner_hb_exit_origin_take_line()) return;
    if (!LdrFindEntryForAddress( caller, &module ) && module)
        module_rva = (ULONG_PTR)caller - (ULONG_PTR)module->DllBase;
    MESSAGE( "macrunner-hb-exit-origin: phase=rtl-exit guest_tid=%04lx status=0x%08lx "
             "last=%lu caller=%p caller_module=%p caller_rva=0x%Ix caller_name=%s "
             "record_valid=%u sequence=%lu dispatch_stage=%s code=0x%08lx flags=0x%08lx "
             "exception_address=%p context_pc=%p context_sp=%p operation=%s fault_address=%p "
             "vectored_handlers=%lu vectored_disposition=%ld seh_status=0x%08lx "
             "seh_handlers=%lu continue=%lu search=%lu nested=%lu collided=%lu invalid=%lu\n",
             GetCurrentThreadId(), status, last, caller, module ? module->DllBase : NULL,
             module_rva, module ? debugstr_us( &module->BaseDllName ) : "unknown",
             state->valid, state->sequence, state->dispatch_stage ? state->dispatch_stage : "none",
             state->valid ? state->record.ExceptionCode : 0,
             state->valid ? state->record.ExceptionFlags : 0,
             state->valid ? state->record.ExceptionAddress : NULL,
             (void *)state->context_pc, (void *)state->context_sp,
             state->valid ? macrunner_hb_exit_origin_av_operation( &state->record ) : "none",
             state->valid && state->record.NumberParameters > 1 ?
                 (void *)state->record.ExceptionInformation[1] : NULL,
             state->vectored_handlers, state->vectored_disposition, state->seh_status,
             state->seh_handlers, state->seh_continue_execution, state->seh_continue_search,
             state->seh_nested, state->seh_collided, state->seh_invalid );
}

static BOOL enter_vectored_handlers_section(void)
{
    LARGE_INTEGER delay;
    unsigned int retry;

    for (retry = 0; retry < 20; retry++)
    {
        if (RtlTryEnterCriticalSection( &vectored_handlers_section ))
            return TRUE;
        delay.QuadPart = -100000; /* 10 ms */
        NtDelayExecution( FALSE, &delay );
    }
    WARN( "vectored_handlers_section wait timed out after 200 ms\n" );
    return FALSE;
}

static const char *debugstr_exception_code( DWORD code )
{
    switch (code)
    {
    case CONTROL_C_EXIT: return "CONTROL_C_EXIT";
    case DBG_CONTROL_C: return "DBG_CONTROL_C";
    case DBG_PRINTEXCEPTION_C: return "DBG_PRINTEXCEPTION_C";
    case DBG_PRINTEXCEPTION_WIDE_C: return "DBG_PRINTEXCEPTION_WIDE_C";
    case EXCEPTION_ACCESS_VIOLATION: return "EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_BREAKPOINT: return "EXCEPTION_BREAKPOINT";
    case EXCEPTION_DATATYPE_MISALIGNMENT: return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND: return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO: return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT: return "EXCEPTION_FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION: return "EXCEPTION_FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW: return "EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK: return "EXCEPTION_FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW: return "EXCEPTION_FLT_UNDERFLOW";
    case EXCEPTION_GUARD_PAGE: return "EXCEPTION_GUARD_PAGE";
    case EXCEPTION_ILLEGAL_INSTRUCTION: return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR: return "EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO: return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW: return "EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION: return "EXCEPTION_INVALID_DISPOSITION";
    case EXCEPTION_INVALID_HANDLE: return "EXCEPTION_INVALID_HANDLE";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION: return "EXCEPTION_PRIV_INSTRUCTION";
    case EXCEPTION_SINGLE_STEP: return "EXCEPTION_SINGLE_STEP";
    case EXCEPTION_STACK_OVERFLOW: return "EXCEPTION_STACK_OVERFLOW";
    case EXCEPTION_WINE_ASSERTION: return "EXCEPTION_WINE_ASSERTION";
    case EXCEPTION_WINE_CXX_EXCEPTION: return "EXCEPTION_WINE_CXX_EXCEPTION";
    case EXCEPTION_WINE_NAME_THREAD: return "EXCEPTION_WINE_NAME_THREAD";
    case EXCEPTION_WINE_STUB: return "EXCEPTION_WINE_STUB";
    case RPC_S_SERVER_UNAVAILABLE: return "RPC_S_SERVER_UNAVAILABLE";
    }
    return "unknown";
}


static VECTORED_HANDLER *add_vectored_handler( struct list *handler_list, LONG *handler_count,
                                               ULONG first, PVECTORED_EXCEPTION_HANDLER func )
{
    VECTORED_HANDLER *handler = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*handler) );
    if (handler)
    {
        handler->func = RtlEncodePointer( func );
        handler->count = 1;
        if (!enter_vectored_handlers_section())
        {
            RtlFreeHeap( GetProcessHeap(), 0, handler );
            return NULL;
        }
        if (first) list_add_head( handler_list, &handler->entry );
        else list_add_tail( handler_list, &handler->entry );
        InterlockedIncrement( handler_count );
        RtlLeaveCriticalSection( &vectored_handlers_section );
    }
    return handler;
}


static ULONG remove_vectored_handler( struct list *handler_list, LONG *handler_count, VECTORED_HANDLER *handler )
{
    struct list *ptr;
    ULONG ret = FALSE;

    if (!enter_vectored_handlers_section()) return FALSE;
    LIST_FOR_EACH( ptr, handler_list )
    {
        VECTORED_HANDLER *curr_handler = LIST_ENTRY( ptr, VECTORED_HANDLER, entry );
        if (curr_handler == handler)
        {
            if (!--curr_handler->count)
            {
                list_remove( ptr );
                InterlockedDecrement( handler_count );
            }
            else handler = NULL;  /* don't free it yet */
            ret = TRUE;
            break;
        }
    }
    RtlLeaveCriticalSection( &vectored_handlers_section );
    if (ret) RtlFreeHeap( GetProcessHeap(), 0, handler );
    return ret;
}


/**********************************************************************
 *           call_vectored_handlers
 *
 * Call the vectored handlers chain.
 */
static LONG call_vectored_handlers( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    struct list *ptr;
    LONG ret = EXCEPTION_CONTINUE_SEARCH;
    EXCEPTION_POINTERS except_ptrs;
    PVECTORED_EXCEPTION_HANDLER func;
    VECTORED_HANDLER *handler, *to_free = NULL;

    except_ptrs.ExceptionRecord = rec;
    except_ptrs.ContextRecord = context;

    /* Fast path for the common case: no vectored handlers registered. */
    if (!InterlockedCompareExchange( &vectored_exception_handler_count, 0, 0 ))
        return ret;

    if (!enter_vectored_handlers_section()) return ret;
    ptr = list_head( &vectored_exception_handlers );
    while (ptr)
    {
        handler = LIST_ENTRY( ptr, VECTORED_HANDLER, entry );
        handler->count++;
        func = RtlDecodePointer( handler->func );
        RtlLeaveCriticalSection( &vectored_handlers_section );
        RtlFreeHeap( GetProcessHeap(), 0, to_free );
        to_free = NULL;

        TRACE( "calling handler at %p code=%lx flags=%lx\n",
               func, rec->ExceptionCode, rec->ExceptionFlags );
        ret = func( &except_ptrs );
        TRACE( "handler at %p returned %lx\n", func, ret );
        macrunner_hb_exit_origin_vectored_observe( func, ret );

        if (!enter_vectored_handlers_section()) return ret;
        ptr = list_next( &vectored_exception_handlers, ptr );
        if (!--handler->count)  /* removed during execution */
        {
            list_remove( &handler->entry );
            to_free = handler;
        }
        if (ret == EXCEPTION_CONTINUE_EXECUTION) break;
    }
    RtlLeaveCriticalSection( &vectored_handlers_section );
    RtlFreeHeap( GetProcessHeap(), 0, to_free );
    return ret;
}


/*******************************************************************
 *		dispatch_exception
 */
NTSTATUS WINAPI dispatch_exception( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    NTSTATUS status;
    LONG vectored_disposition;
    DWORD i;

    macrunner_hb_exit_origin_exception_begin( rec, context );

    switch (rec->ExceptionCode)
    {
    case EXCEPTION_WINE_STUB:
        if (rec->ExceptionInformation[1] >> 16)
            MESSAGE( "wine: Call from %p to unimplemented function %s.%s, aborting\n",
                     rec->ExceptionAddress,
                     (char *)rec->ExceptionInformation[0], (char *)rec->ExceptionInformation[1] );
        else
            MESSAGE( "wine: Call from %p to unimplemented function %s.%u, aborting\n",
                     rec->ExceptionAddress,
                     (char *)rec->ExceptionInformation[0], (USHORT)rec->ExceptionInformation[1] );
        break;

    case EXCEPTION_WINE_NAME_THREAD:
        if (rec->ExceptionInformation[0] == 0x1000)
        {
            const char *name = (char *)rec->ExceptionInformation[1];
            DWORD tid = (DWORD)rec->ExceptionInformation[2];

            if (tid == -1 || tid == GetCurrentThreadId())
                WARN_(threadname)( "Thread renamed to %s\n", debugstr_a(name) );
            else
                WARN_(threadname)( "Thread ID %04lx renamed to %s\n", tid, debugstr_a(name) );
            set_native_thread_name( tid, name );
        }
        break;

    case DBG_PRINTEXCEPTION_C:
        WARN( "%s\n", debugstr_an((char *)rec->ExceptionInformation[1], rec->ExceptionInformation[0] - 1) );
        break;

    case DBG_PRINTEXCEPTION_WIDE_C:
        WARN( "%s\n", debugstr_wn((WCHAR *)rec->ExceptionInformation[1], rec->ExceptionInformation[0] - 1) );
        break;

    case STATUS_ASSERTION_FAILURE:
        ERR( "assertion failure exception\n" );
        break;

    default:
        if (!TRACE_ON(seh)) WARN( "%s exception (code=%lx) raised\n",
                                  debugstr_exception_code(rec->ExceptionCode), rec->ExceptionCode );
        break;
    }

    TRACE( "code=%lx (%s) flags=%lx addr=%p\n",
           rec->ExceptionCode, debugstr_exception_code(rec->ExceptionCode),
           rec->ExceptionFlags, rec->ExceptionAddress );
    for (i = 0; i < min( EXCEPTION_MAXIMUM_PARAMETERS, rec->NumberParameters ); i++)
        TRACE( " info[%ld]=%p\n", i, (void *)rec->ExceptionInformation[i] );
    TRACE_CONTEXT( context );

    {
        static unsigned int first_chance_count;
        if (first_chance_count++ < 48)
            MESSAGE( "macrunner-hb-first-chance: code=%lx flags=%lx addr=%p info0=%Ix info1=%Ix\n",
                 rec->ExceptionCode, rec->ExceptionFlags, rec->ExceptionAddress,
                 rec->NumberParameters > 0 ? (ULONG_PTR)rec->ExceptionInformation[0] : 0,
                 rec->NumberParameters > 1 ? (ULONG_PTR)rec->ExceptionInformation[1] : 0 );
        /* ★★★★★★ MacRunner 2026-08-31 — КОНТЕКСТ, ПОКА x30 ЕЩЁ ЦЕЛ.
         *
         * Измерено: сигнал приходит, когда поток УЖЕ на негодном адресе (pc прерванного
         * равен адресу отказа) — значит переход случился РАНЬШЕ, и запись доставки ни
         * при чём, эта ветка закрыта. Первичное исключение — штатное 0x6ba (RPC не
         * отвечает), возбуждается программно и проходит здесь. Печатаем pc/sp/lr именно
         * в этот момент: сравнение с моментом отказа покажет, между какими двумя точками
         * адрес возврата перестал быть кодом. */
#ifdef __aarch64__
        if (context)
            MESSAGE( "macrunner-hb-first-chance-контекст: code=%lx pc=%p sp=%p lr=%p x19=%p x20=%p\n",
                 rec->ExceptionCode, (void *)(ULONG_PTR)context->Pc,
                 (void *)(ULONG_PTR)context->Sp, (void *)(ULONG_PTR)context->Lr,
                 (void *)(ULONG_PTR)context->X19, (void *)(ULONG_PTR)context->X20 );
#endif
    }

    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: стена ступени 1 — c000001d по ХОЗЯЙСКОМУ адресу,
     * не принадлежащему ни одному образу (image=0). «Нелегальная команда» без самой команды
     * ничего не говорит, поэтому печатаем ЧЕТЫРЕ слова ARM64 по адресу отказа. Чтение через
     * NtReadVirtualMemory, а не разыменованием: адрес может быть невалиден, и падать в
     * обработчике исключений нельзя. Только для c000001d, первые восемь раз.
     * Печать через MESSAGE: на PE-стороне ntdll нет stdio (fprintf не линкуется —
     * ld.lld: undefined symbol __acrt_iob_func), а MESSAGE идёт в stderr безусловно. */
    if (rec->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION)
    {
        static unsigned int illegal_count;
        if (illegal_count++ < 8)
        {
            ULONG words[4] = { 0 };
            SIZE_T got = 0;
            NTSTATUS st = NtReadVirtualMemory( GetCurrentProcess(), rec->ExceptionAddress,
                                               words, sizeof(words), &got );
            /* ВНИМАНИЕ: %Iu тут печатал мусор в поле адреса (сверено с соседней строкой
             * dispatch_exception, где адрес верный). Ширины приводим руками. */
            MESSAGE( "macrunner-hb-illegal-host-insn: n=%u addr=%p status=%08lx got=%lu "
                     "w0=%08lx w1=%08lx w2=%08lx w3=%08lx\n",
                     illegal_count, rec->ExceptionAddress, (ULONG)st, (unsigned long)got,
                     (unsigned long)words[0], (unsigned long)words[1],
                     (unsigned long)words[2], (unsigned long)words[3] );

            /* ★★★★★ ИТЕРАЦИЯ 158, лейн УСТАНОВЩИКИ — КТО СЮДА ПЕРЕШЁЛ.
             *
             * Пять инструментированных путей вызова на C дали ноль срабатываний
             * (итерация 157), а кодогенератор в наших прогонах никуда по вычисленной
             * цели не переходит: единственный такой переход — попадание в инлайн-кеш,
             * а его гейт `MACRUNNER_HB_INDIRECT_IC` по умолчанию 0
             * (`hb_arm64_codegen.c:2136`). Значит переход делает среда выполнения,
             * и назвать её можно ровно одним числом — адресом возврата.
             *
             * Раскрутка после отказа здесь врёт (итерация 156: в цепочке оказался
             * `__wine_dbg_output`, который эту цель звать не может), поэтому берём НЕ
             * раскрутку, а регистры самого прерванного состояния: x30 — кто позвал,
             * x16/x17 — обычные регистры косвенного перехода. Печать в ту же скобку,
             * тот же потолок 8, нового гейта нет.
             *
             * Доступ через `context->X[n]`, а не по именам полей: union в winnt.h
             * безымянный, и сборка по именам не прошла. Ограждение по
             * `__aarch64__ && !__arm64ec__` — в сборке ARM64EC этот же файл собирается
             * с AMD64-видом CONTEXT, где регистров X нет вовсе (поймано сборкой). */
#if defined(__aarch64__) && !defined(__arm64ec__)
            if (context)
                MESSAGE( "macrunner-hb-illegal-host-who: n=%u lr=%p x16=%p x17=%p "
                         "x8=%p x9=%p sp=%p pc=%p\n",
                         illegal_count,
                         (void *)(ULONG_PTR)context->X[30],
                         (void *)(ULONG_PTR)context->X[16],
                         (void *)(ULONG_PTR)context->X[17],
                         (void *)(ULONG_PTR)context->X[8],
                         (void *)(ULONG_PTR)context->X[9],
                         (void *)(ULONG_PTR)context->Sp,
                         (void *)(ULONG_PTR)context->Pc );
            /* Итерация 159: банк x19-x23 выпущенного кода. `emit_blr(buf, 23)` берёт цель
             * из x23 (`hb_arm64_codegen.c:8766,8787`), x19 — указатель контекста гостя,
             * x20/x21/x22 — временные. Без x23 итерация 158 смогла сказать лишь «переход
             * из арены JIT», но не какой именно. */
            if (context)
                MESSAGE( "macrunner-hb-illegal-host-bank: n=%u x19=%p x20=%p x21=%p "
                         "x22=%p x23=%p x0=%p x1=%p x2=%p\n",
                         illegal_count,
                         (void *)(ULONG_PTR)context->X[19],
                         (void *)(ULONG_PTR)context->X[20],
                         (void *)(ULONG_PTR)context->X[21],
                         (void *)(ULONG_PTR)context->X[22],
                         (void *)(ULONG_PTR)context->X[23],
                         (void *)(ULONG_PTR)context->X[0],
                         (void *)(ULONG_PTR)context->X[1],
                         (void *)(ULONG_PTR)context->X[2] );

            /* ★★★★★ ИТЕРАЦИЯ 160 — ЧЬЯ ОБЛАСТЬ У АДРЕСА ВОЗВРАТА.
             *
             * Итерация 159 сузила: `lr` лежит в полосе ~4,2 ГБ, не принадлежит ни одному
             * из 326 модулей карты `+loaddll`, не совпадает ни с ареной JIT (блоки прогона
             * на ~43 ГБ), ни с областью переходников импорта (её база 0x6f0000000000).
             * Смещение в странице во всех четырёх прогонах одно — 0x290. Перечислять
             * кандидатов дальше бессмысленно: спрашиваем ядро.
             *
             * Рядом уже есть такой зонд для `pc` (`macrunner-hb-unsafe-vmprobe`), но он
             * стоит в пути размотки и про `lr` не знает. Здесь тот же вопрос про адрес
             * возврата, тем же способом. Нового гейта нет, потолок общий (первые 8). */
            if (context)
            {
                MEMORY_BASIC_INFORMATION mbi;
                SIZE_T len = 0;
                void *lr = (void *)(ULONG_PTR)context->X[30];
                NTSTATUS qs = NtQueryVirtualMemory( GetCurrentProcess(), lr,
                                                    MemoryBasicInformation, &mbi, sizeof(mbi), &len );

                if (!qs)
                    MESSAGE( "macrunner-hb-illegal-host-lrmem: n=%u lr=%p alloc_base=%p base=%p "
                             "size=%p state=%08lx protect=%08lx alloc_prot=%08lx type=%08lx\n",
                             illegal_count, lr, mbi.AllocationBase, mbi.BaseAddress,
                             (void *)mbi.RegionSize, (ULONG)mbi.State, (ULONG)mbi.Protect,
                             (ULONG)mbi.AllocationProtect, (ULONG)mbi.Type );
                else
                    MESSAGE( "macrunner-hb-illegal-host-lrmem: n=%u lr=%p запрос отказал status=%08lx\n",
                             illegal_count, lr, (ULONG)qs );
            }
#endif

            /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ИМЯ виновной хозяйской библиотеки.
             * Wine эту память не учитывает (unsafe-vmprobe даёт MEM_FREE), поэтому ни
             * образа, ни символа у нас нет. Но заголовок Mach-O выровнен по странице:
             * идём НАЗАД постранично до магии 0xfeedfacf, затем читаем команды загрузки
             * и берём имя из LC_ID_DYLIB (0x0d). Всё чтение — через NtReadVirtualMemory,
             * поэтому промах по неотображённой странице безопасен. Потолок 4 МБ. */
            {
                ULONG_PTR base = (ULONG_PTR)rec->ExceptionAddress & ~(ULONG_PTR)0xfff;
                ULONG_PTR limit = base > 0x400000 ? base - 0x400000 : 0;
                ULONG magic = 0;
                BOOL found = FALSE;

                while (base > limit)
                {
                    got = 0;
                    if (!NtReadVirtualMemory( GetCurrentProcess(), (void *)base, &magic,
                                              sizeof(magic), &got ) &&
                        got == sizeof(magic) && magic == 0xfeedfacf)
                    {
                        found = TRUE;
                        break;
                    }
                    base -= 0x1000;
                }
                if (!found)
                    MESSAGE( "macrunner-hb-illegal-host-image: заголовок Mach-O не найден "
                             "в 4 МБ назад от %p\n", rec->ExceptionAddress );
                else
                {
                    ULONG hdr[8] = { 0 };          /* mach_header_64 */
                    ULONG_PTR lc = base + sizeof(hdr);
                    ULONG i, ncmds = 0;
                    char name[128];

                    NtReadVirtualMemory( GetCurrentProcess(), (void *)base, hdr, sizeof(hdr), &got );
                    ncmds = hdr[4];
                    name[0] = 0;
                    for (i = 0; i < ncmds && i < 256; i++)
                    {
                        ULONG cmd[2] = { 0 };      /* cmd, cmdsize */
                        if (NtReadVirtualMemory( GetCurrentProcess(), (void *)lc, cmd,
                                                 sizeof(cmd), &got ) || got != sizeof(cmd))
                            break;
                        if (!cmd[1]) break;
                        if (cmd[0] == 0x0d)        /* LC_ID_DYLIB */
                        {
                            ULONG name_off = 0;
                            if (!NtReadVirtualMemory( GetCurrentProcess(), (void *)(lc + 8),
                                                      &name_off, sizeof(name_off), &got ) &&
                                name_off < cmd[1])
                            {
                                SIZE_T n = sizeof(name) - 1;
                                if (n > cmd[1] - name_off) n = cmd[1] - name_off;
                                if (NtReadVirtualMemory( GetCurrentProcess(),
                                                         (void *)(lc + name_off), name, n, &got ))
                                    name[0] = 0;
                                else name[got < sizeof(name) ? got : sizeof(name) - 1] = 0;
                            }
                            break;
                        }
                        lc += cmd[1];
                    }
                    MESSAGE( "macrunner-hb-illegal-host-image: base=%p смещение=%p ncmds=%lu "
                             "имя=\"%s\"\n", (void *)base,
                             (void *)((ULONG_PTR)rec->ExceptionAddress - base),
                             (unsigned long)ncmds, name[0] ? name : "(нет LC_ID_DYLIB)" );
                }
            }
        }
    }

    vectored_disposition = call_vectored_handlers( rec, context );
    if (vectored_disposition == EXCEPTION_CONTINUE_EXECUTION)
    {
        macrunner_hb_exit_origin_dispatch_summary( "handled-vectored", vectored_disposition,
                                                   STATUS_SUCCESS );
        NtContinue( context, FALSE );
    }

    status = call_seh_handlers( rec, context );
    if (status == STATUS_SUCCESS)
    {
        macrunner_hb_exit_origin_dispatch_summary( "handled-seh", vectored_disposition, status );
        NtContinue( context, FALSE );
    }

    if (status != STATUS_UNHANDLED_EXCEPTION)
    {
        macrunner_hb_exit_origin_dispatch_summary( "invalid-disposition", vectored_disposition,
                                                   status );
        RtlRaiseStatus( status );
    }
    macrunner_hb_exit_origin_dispatch_summary( "unhandled-second-chance", vectored_disposition,
                                               status );
    return NtRaiseException( rec, context, FALSE );
}


#if defined(__WINE_PE_BUILD) && !defined(__i386__)

/*******************************************************************
 *		user_callback_handler
 *
 * Exception handler for KiUserCallbackDispatcher.
 */
EXCEPTION_DISPOSITION WINAPI user_callback_handler( EXCEPTION_RECORD *record, void *frame,
                                                    CONTEXT *context, void *dispatch )
{
    if (!(record->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)))
    {
        static unsigned int detail_count;
        if (detail_count++ < 16)
            ERR( "ignoring exception %lx addr=%p info0=%Ix info1=%Ix flags=%lx nparams=%lu\n",
                 record->ExceptionCode, record->ExceptionAddress,
                 record->NumberParameters > 0 ? (ULONG_PTR)record->ExceptionInformation[0] : 0,
                 record->NumberParameters > 1 ? (ULONG_PTR)record->ExceptionInformation[1] : 0,
                 record->ExceptionFlags, record->NumberParameters );
        else
            ERR( "ignoring exception %lx\n", record->ExceptionCode );
        RtlUnwind( frame, KiUserCallbackDispatcherReturn, record, ULongToPtr(record->ExceptionCode) );
    }
    return ExceptionContinueSearch;
}

#else

/*******************************************************************
 *		dispatch_user_callback
 *
 * Implementation of KiUserCallbackDispatcher.
 */
NTSTATUS WINAPI dispatch_user_callback( void *args, ULONG len, ULONG id )
{
    NTSTATUS status;

    __TRY
    {
        KERNEL_CALLBACK_PROC func = NtCurrentTeb()->Peb->KernelCallbackTable[id];
        status = func( args, len );
    }
    __EXCEPT_ALL
    {
        status = GetExceptionCode();
        ERR( "ignoring exception %lx\n", status );
    }
    __ENDTRY
    return status;
}

#endif


/*******************************************************************
 *		raise_status
 *
 * Implementation of RtlRaiseStatus with a specific exception record.
 */
void DECLSPEC_NORETURN raise_status( NTSTATUS status, EXCEPTION_RECORD *rec )
{
    EXCEPTION_RECORD ExceptionRec;
    static LONG macrunner_trace_count;

    ExceptionRec.ExceptionCode    = status;
    ExceptionRec.ExceptionFlags   = EXCEPTION_NONCONTINUABLE;
    ExceptionRec.ExceptionRecord  = rec;
    ExceptionRec.NumberParameters = 0;
    if (macrunner_trace_count++ < 64)
        MESSAGE( "macrunner-hb-raise-status: status=%08lx rec=%p rec_code=%08lx caller=%p\n",
             status, rec, rec ? rec->ExceptionCode : 0, __builtin_return_address(0) );
    for (;;) RtlRaiseException( &ExceptionRec );  /* never returns */
}


/***********************************************************************
 *            RtlRaiseStatus  (NTDLL.@)
 *
 * Raise an exception with ExceptionCode = status
 */
void DECLSPEC_NORETURN WINAPI RtlRaiseStatus( NTSTATUS status )
{
    static LONG macrunner_trace_count;

    if (macrunner_trace_count++ < 64)
    {
        /* ★ MacRunner 2026-08-28 — НАЗВАТЬ МОДУЛЬ, А НЕ ТОЛЬКО АДРЕС.
         *
         * Голый `caller=%p` заставляет искать владельца вручную, а карта модулей
         * по записям импорта ВРЁТ: там `base` — это адрес страницы IAT импортёра,
         * а не база модуля. На поиске виновника `c0000025` в Diablo это дало
         * ложное «wow64win.dll + 0x1584FC», где на деле лежат строки, а не код.
         * Спрашиваем загрузчик — он знает точно. */
        void *ret = __builtin_return_address(0);
        LDR_DATA_TABLE_ENTRY *mod = NULL;
        if (!LdrFindEntryForAddress( ret, &mod ) && mod)
            MESSAGE( "macrunner-hb-rtl-raise-status: status=%08lx caller=%p модуль=%s+0x%lx\n",
                 status, ret, debugstr_w(mod->BaseDllName.Buffer),
                 (ULONG_PTR)ret - (ULONG_PTR)mod->DllBase );
        else
            MESSAGE( "macrunner-hb-rtl-raise-status: status=%08lx caller=%p модуль=НЕ НАЙДЕН\n",
                 status, ret );
    }
    raise_status( status, NULL );
}


/*******************************************************************
 *		KiRaiseUserExceptionDispatcher  (NTDLL.@)
 */
NTSTATUS WINAPI KiRaiseUserExceptionDispatcher(void)
{
    DWORD code = NtCurrentTeb()->ExceptionCode;
    EXCEPTION_RECORD rec = { code };
    RtlRaiseException( &rec );
    return code;
}


/*******************************************************************
 *         RtlAddVectoredContinueHandler   (NTDLL.@)
 */
PVOID WINAPI RtlAddVectoredContinueHandler( ULONG first, PVECTORED_EXCEPTION_HANDLER func )
{
    return add_vectored_handler( &vectored_continue_handlers, &vectored_continue_handler_count, first, func );
}


/*******************************************************************
 *         RtlRemoveVectoredContinueHandler   (NTDLL.@)
 */
ULONG WINAPI RtlRemoveVectoredContinueHandler( PVOID handler )
{
    return remove_vectored_handler( &vectored_continue_handlers, &vectored_continue_handler_count, handler );
}


/*******************************************************************
 *         RtlAddVectoredExceptionHandler   (NTDLL.@)
 */
PVOID WINAPI DECLSPEC_HOTPATCH RtlAddVectoredExceptionHandler( ULONG first, PVECTORED_EXCEPTION_HANDLER func )
{
    return add_vectored_handler( &vectored_exception_handlers, &vectored_exception_handler_count, first, func );
}


/*******************************************************************
 *         RtlRemoveVectoredExceptionHandler   (NTDLL.@)
 */
ULONG WINAPI RtlRemoveVectoredExceptionHandler( PVOID handler )
{
    return remove_vectored_handler( &vectored_exception_handlers, &vectored_exception_handler_count, handler );
}


/*******************************************************************
 *         RtlSetUnhandledExceptionFilter   (NTDLL.@)
 */
void WINAPI RtlSetUnhandledExceptionFilter( PRTL_EXCEPTION_FILTER filter )
{
    unhandled_exception_filter = filter;
}


/*******************************************************************
 *         call_unhandled_exception_filter
 */
LONG WINAPI call_unhandled_exception_filter( PEXCEPTION_POINTERS eptr )
{
    if (!unhandled_exception_filter) return EXCEPTION_CONTINUE_SEARCH;
    return unhandled_exception_filter( eptr );
}

/*******************************************************************
 *         call_unhandled_exception_handler
 */
EXCEPTION_DISPOSITION WINAPI call_unhandled_exception_handler( EXCEPTION_RECORD *rec, void *frame,
                                                               CONTEXT *context, void *dispatch )
{
    EXCEPTION_POINTERS ep = { rec, context };

    switch (call_unhandled_exception_filter( &ep ))
    {
    case EXCEPTION_CONTINUE_SEARCH:
        return ExceptionContinueSearch;
    case EXCEPTION_CONTINUE_EXECUTION:
        return ExceptionContinueExecution;
    case EXCEPTION_EXECUTE_HANDLER:
        break;
    }
    NtTerminateProcess( GetCurrentProcess(), rec->ExceptionCode );
    return ExceptionContinueExecution;
}


/*************************************************************
 *            _assert
 */
void DECLSPEC_NORETURN __cdecl _assert( const char *str, const char *file, unsigned int line )
{
    ERR( "%s:%u: Assertion failed %s\n", file, line, debugstr_a(str) );
    RtlRaiseStatus( EXCEPTION_WINE_ASSERTION );
}


/*************************************************************
 *            __wine_spec_unimplemented_stub
 *
 * ntdll-specific implementation to avoid depending on kernel functions.
 * Can be removed once ntdll.spec no longer contains stubs.
 */
void __cdecl __wine_spec_unimplemented_stub( const char *module, const char *function )
{
    EXCEPTION_RECORD record;

    record.ExceptionCode    = EXCEPTION_WINE_STUB;
    record.ExceptionFlags   = EXCEPTION_NONCONTINUABLE;
    record.ExceptionRecord  = NULL;
    record.ExceptionAddress = __wine_spec_unimplemented_stub;
    record.NumberParameters = 2;
    record.ExceptionInformation[0] = (ULONG_PTR)module;
    record.ExceptionInformation[1] = (ULONG_PTR)function;
    for (;;) RtlRaiseException( &record );
}


/*************************************************************
 *            IsBadStringPtrA
 *
 * IsBadStringPtrA replacement for ntdll, to catch exception in debug traces.
 */
BOOL DECLSPEC_NOINLINE WINAPI IsBadStringPtrA( LPCSTR str, UINT_PTR max )
{
    if (!str) return TRUE;
    __TRY
    {
        volatile const char *p = str;
        while (p != str + max) if (!*p++) break;
    }
    __EXCEPT_PAGE_FAULT
    {
        return TRUE;
    }
    __ENDTRY
    return FALSE;
}

/*************************************************************
 *            IsBadStringPtrW
 *
 * IsBadStringPtrW replacement for ntdll, to catch exception in debug traces.
 */
BOOL DECLSPEC_NOINLINE WINAPI IsBadStringPtrW( LPCWSTR str, UINT_PTR max )
{
    if (!str) return TRUE;
    __TRY
    {
        volatile const WCHAR *p = str;
        while (p != str + max) if (!*p++) break;
    }
    __EXCEPT_PAGE_FAULT
    {
        return TRUE;
    }
    __ENDTRY
    return FALSE;
}

#ifdef __i386__
__ASM_STDCALL_IMPORT(IsBadStringPtrA,8)
__ASM_STDCALL_IMPORT(IsBadStringPtrW,8)
#else
__ASM_GLOBAL_IMPORT(IsBadStringPtrA)
__ASM_GLOBAL_IMPORT(IsBadStringPtrW)
#endif


/*************************************************************************
 *		RtlCaptureStackBackTrace (NTDLL.@)
 */
USHORT WINAPI RtlCaptureStackBackTrace( ULONG skip, ULONG count, void **buffer, ULONG *hash_ret )
{
    ULONG i, ret, hash;

    TRACE( "(%lu, %lu, %p, %p)\n", skip, count, buffer, hash_ret );

    skip++;  /* skip our own frame */
    ret = RtlWalkFrameChain( buffer, count + skip, skip << 8 );
    if (hash_ret)
    {
        for (i = hash = 0; i < ret; i++) hash += (ULONG_PTR)buffer[i];
        *hash_ret = hash;
    }
    return ret;
}


/*************************************************************************
 *		RtlGetCallersAddress (NTDLL.@)
 */
void WINAPI RtlGetCallersAddress( void **caller, void **parent )
{
    void *buffer[2];
    ULONG count = ARRAY_SIZE(buffer), skip = 2;  /* skip our frame and the parent */

    count = RtlWalkFrameChain( buffer, count + skip, skip << 8 );
    *caller = count > 0 ? buffer[0] : NULL;
    *parent = count > 1 ? buffer[1] : NULL;
}


/**********************************************************************
 *              RtlGetEnabledExtendedFeatures   (NTDLL.@)
 */
ULONG64 WINAPI RtlGetEnabledExtendedFeatures(ULONG64 feature_mask)
{
    return user_shared_data->XState.EnabledFeatures & feature_mask;
}

struct context_copy_range
{
    ULONG start;
    ULONG flag;
};

static const struct context_copy_range copy_ranges_amd64[] =
{
    {0x38, 0x1}, {0x3a, 0x4}, { 0x42, 0x1}, { 0x48, 0x10}, { 0x78,  0x2}, { 0x98, 0x1},
    {0xa0, 0x2}, {0xf8, 0x1}, {0x100, 0x8}, {0x2a0,    0}, {0x4b0, 0x10}, {0x4d0,   0}
};

static const struct context_copy_range copy_ranges_x86[] =
{
    {  0x4, 0x10}, {0x1c, 0x8}, {0x8c, 0x4}, {0x9c, 0x2}, {0xb4, 0x1}, {0xcc, 0x20}, {0x1ec, 0},
    {0x2cc,    0},
};

static const struct context_parameters
{
    ULONG arch_flag;
    ULONG supported_flags;
    ULONG context_size;    /* sizeof(CONTEXT) */
    ULONG legacy_size;     /* Legacy context size */
    ULONG context_ex_size; /* sizeof(CONTEXT_EX) */
    ULONG alignment;       /* Used when computing size of context. */
    ULONG true_alignment;  /* Used for actual alignment. */
    ULONG flags_offset;
    const struct context_copy_range *copy_ranges;
}
arch_context_parameters[] =
{
    {
        CONTEXT_AMD64,
        0xd8000000 | CONTEXT_AMD64_ALL | CONTEXT_AMD64_XSTATE,
        sizeof(AMD64_CONTEXT),
        sizeof(AMD64_CONTEXT),
        0x20,
        7,
        TYPE_ALIGNMENT(AMD64_CONTEXT) - 1,
        offsetof(AMD64_CONTEXT,ContextFlags),
        copy_ranges_amd64
    },
    {
        CONTEXT_i386,
        0xd8000000 | CONTEXT_I386_ALL | CONTEXT_I386_XSTATE,
        sizeof(I386_CONTEXT),
        offsetof(I386_CONTEXT,ExtendedRegisters),
        0x18,
        3,
        TYPE_ALIGNMENT(I386_CONTEXT) - 1,
        offsetof(I386_CONTEXT,ContextFlags),
        copy_ranges_x86
    },
};

static const struct context_parameters *context_get_parameters( ULONG context_flags )
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(arch_context_parameters); ++i)
    {
        if (context_flags & arch_context_parameters[i].arch_flag)
            return context_flags & ~arch_context_parameters[i].supported_flags ? NULL : &arch_context_parameters[i];
    }
    return NULL;
}

/* offset is from the start of XSAVE_AREA_HEADER. */
static int next_compacted_xstate_offset( int off, UINT64 compaction_mask, int feature_idx )
{
    const UINT64 feature_mask = (UINT64)1 << feature_idx;

    if (compaction_mask & feature_mask) off += user_shared_data->XState.Features[feature_idx].Size;
    if (user_shared_data->XState.AlignedFeatures & (feature_mask << 1))
        off = (off + 63) & ~63;
    return off;
}

/* size includes XSAVE_AREA_HEADER but not XSAVE_FORMAT (legacy save area). */
static int xstate_get_compacted_size( UINT64 mask )
{
    UINT64 compaction_mask;
    unsigned int i;
    int off;

    compaction_mask = ((UINT64)1 << 63) | mask;
    mask >>= 2;
    off = sizeof(XSAVE_AREA_HEADER);
    i = 2;
    while (mask)
    {
        if (mask == 1) return off + user_shared_data->XState.Features[i].Size;
        off = next_compacted_xstate_offset( off, compaction_mask, i );
        mask >>= 1;
        ++i;
    }
    return off;
}

static int xstate_get_size( UINT64 mask )
{
    unsigned int i;

    mask >>= 2;
    if (!mask) return sizeof(XSAVE_AREA_HEADER);
    i = 2;
    while (mask != 1)
    {
        mask >>= 1;
        ++i;
    }
    return user_shared_data->XState.Features[i].Offset + user_shared_data->XState.Features[i].Size - sizeof(XSAVE_FORMAT);
}

/**********************************************************************
 *              RtlGetExtendedContextLength2    (NTDLL.@)
 */
NTSTATUS WINAPI RtlGetExtendedContextLength2( ULONG context_flags, ULONG *length, ULONG64 compaction_mask )
{
    const struct context_parameters *p;
    ULONG64 supported_mask;
    ULONG64 size;

    TRACE( "context_flags %#lx, length %p, compaction_mask %s.\n", context_flags, length,
            wine_dbgstr_longlong(compaction_mask) );

    if (!(p = context_get_parameters( context_flags )))
        return STATUS_INVALID_PARAMETER;

    if (!(context_flags & 0x40))
    {
        *length = p->context_size + p->context_ex_size + p->alignment;
        return STATUS_SUCCESS;
    }

    if (!(supported_mask = RtlGetEnabledExtendedFeatures( ~(ULONG64)0) ))
        return STATUS_NOT_SUPPORTED;

    size = p->context_size + p->context_ex_size + 63;

    compaction_mask &= supported_mask & ~(ULONG64)3;
    if (user_shared_data->XState.CompactionEnabled) size += xstate_get_compacted_size( compaction_mask );
    else if (compaction_mask)                       size += xstate_get_size( compaction_mask );
    else                                            size += sizeof(XSAVE_AREA_HEADER);

    *length = size;
    return STATUS_SUCCESS;
}


/**********************************************************************
 *              RtlGetExtendedContextLength    (NTDLL.@)
 */
NTSTATUS WINAPI RtlGetExtendedContextLength( ULONG context_flags, ULONG *length )
{
    return RtlGetExtendedContextLength2( context_flags, length, ~(ULONG64)0 );
}


/**********************************************************************
 *              RtlInitializeExtendedContext2    (NTDLL.@)
 */
NTSTATUS WINAPI RtlInitializeExtendedContext2( void *context, ULONG context_flags, CONTEXT_EX **context_ex,
        ULONG64 compaction_mask )
{
    const struct context_parameters *p;
    ULONG64 supported_mask = 0;
    CONTEXT_EX *c_ex;

    TRACE( "context %p, context_flags %#lx, context_ex %p, compaction_mask %s.\n",
            context, context_flags, context_ex, wine_dbgstr_longlong(compaction_mask));

    if (!(p = context_get_parameters( context_flags )))
        return STATUS_INVALID_PARAMETER;

    if ((context_flags & 0x40) && !(supported_mask = RtlGetEnabledExtendedFeatures( ~(ULONG64)0 )))
        return STATUS_NOT_SUPPORTED;

    context = (void *)(((ULONG_PTR)context + p->true_alignment) & ~(ULONG_PTR)p->true_alignment);
    *(ULONG *)((BYTE *)context + p->flags_offset) = context_flags;

    *context_ex = c_ex = (CONTEXT_EX *)((BYTE *)context + p->context_size);
    c_ex->Legacy.Offset = c_ex->All.Offset = -(LONG)p->context_size;
    c_ex->Legacy.Length = context_flags & 0x20 ? p->context_size : p->legacy_size;

    if (context_flags & 0x40)
    {
        XSTATE *xs;

        compaction_mask &= supported_mask;

        xs = (XSTATE *)(((ULONG_PTR)c_ex + p->context_ex_size + 63) & ~(ULONG_PTR)63);

        c_ex->XState.Offset = (ULONG_PTR)xs - (ULONG_PTR)c_ex;
        compaction_mask &= supported_mask;

        if (user_shared_data->XState.CompactionEnabled) c_ex->XState.Length = xstate_get_compacted_size( compaction_mask );
        else if (compaction_mask & ~(ULONG64)3)         c_ex->XState.Length = xstate_get_size( compaction_mask );
        else                                            c_ex->XState.Length = sizeof(XSAVE_AREA_HEADER);

        memset( xs, 0, c_ex->XState.Length );
        if (user_shared_data->XState.CompactionEnabled)
            xs->CompactionMask = ((ULONG64)1 << 63) | compaction_mask;

        c_ex->All.Length = p->context_size + c_ex->XState.Offset + c_ex->XState.Length;
    }
    else
    {
        c_ex->XState.Offset = 25; /* According to the tests, it is just 25 if CONTEXT_XSTATE is not specified. */
        c_ex->XState.Length = 0;
        c_ex->All.Length = p->context_size + 24; /* sizeof(CONTEXT_EX) minus 8 alignment bytes on x64. */
    }

    return STATUS_SUCCESS;
}


/**********************************************************************
 *              RtlInitializeExtendedContext    (NTDLL.@)
 */
NTSTATUS WINAPI RtlInitializeExtendedContext( void *context, ULONG context_flags, CONTEXT_EX **context_ex )
{
    return RtlInitializeExtendedContext2( context, context_flags, context_ex, ~(ULONG64)0 );
}


/**********************************************************************
 *              RtlLocateExtendedFeature2    (NTDLL.@)
 */
void * WINAPI RtlLocateExtendedFeature2( CONTEXT_EX *context_ex, ULONG feature_id,
        XSTATE_CONFIGURATION *xstate_config, ULONG *length )
{
    UINT64 feature_mask = (ULONG64)1 << feature_id;
    XSAVE_AREA_HEADER *xs;
    unsigned int offset, i;

    TRACE( "context_ex %p, feature_id %lu, xstate_config %p, length %p.\n",
            context_ex, feature_id, xstate_config, length );

    if (!xstate_config)
    {
        FIXME( "NULL xstate_config.\n" );
        return NULL;
    }

    if (xstate_config != &user_shared_data->XState)
    {
        FIXME( "Custom xstate configuration is not supported.\n" );
        return NULL;
    }

    if (feature_id < 2 || feature_id >= 64)
        return NULL;

    xs = (XSAVE_AREA_HEADER *)((BYTE *)context_ex + context_ex->XState.Offset);

    if (length)
        *length = xstate_config->Features[feature_id].Size;

    if (xstate_config->CompactionEnabled)
    {
        if (!(xs->CompactionMask & feature_mask)) return NULL;
        offset = sizeof(XSAVE_AREA_HEADER);
        for (i = 2; i < feature_id; ++i)
            offset = next_compacted_xstate_offset( offset, xs->CompactionMask, i );
    }
    else
    {
        if (!(feature_mask & xstate_config->EnabledFeatures)) return NULL;
        offset = xstate_config->Features[feature_id].Offset - sizeof(XSAVE_FORMAT);
    }

    if (context_ex->XState.Length < offset + xstate_config->Features[feature_id].Size)
        return NULL;

    return (BYTE *)xs + offset;
}


/**********************************************************************
 *              RtlLocateExtendedFeature    (NTDLL.@)
 */
void * WINAPI RtlLocateExtendedFeature( CONTEXT_EX *context_ex, ULONG feature_id,
        ULONG *length )
{
    return RtlLocateExtendedFeature2( context_ex, feature_id, &user_shared_data->XState, length );
}

/**********************************************************************
 *              RtlLocateLegacyContext      (NTDLL.@)
 */
void * WINAPI RtlLocateLegacyContext( CONTEXT_EX *context_ex, ULONG *length )
{
    if (length)
        *length = context_ex->Legacy.Length;

    return (BYTE *)context_ex + context_ex->Legacy.Offset;
}

/**********************************************************************
 *              RtlSetExtendedFeaturesMask  (NTDLL.@)
 */
void WINAPI RtlSetExtendedFeaturesMask( CONTEXT_EX *context_ex, ULONG64 feature_mask )
{
    XSTATE *xs = (XSTATE *)((BYTE *)context_ex + context_ex->XState.Offset);

    xs->Mask = RtlGetEnabledExtendedFeatures( feature_mask ) & ~(ULONG64)3;
}


/**********************************************************************
 *              RtlGetExtendedFeaturesMask  (NTDLL.@)
 */
ULONG64 WINAPI RtlGetExtendedFeaturesMask( CONTEXT_EX *context_ex )
{
    XSTATE *xs = (XSTATE *)((BYTE *)context_ex + context_ex->XState.Offset);

    return xs->Mask & ~(ULONG64)3;
}


static void context_copy_ranges( BYTE *d, DWORD context_flags, BYTE *s, const struct context_parameters *p )
{
    const struct context_copy_range *range;
    unsigned int start;

    *((ULONG *)(d + p->flags_offset)) |= context_flags;

    start = 0;
    range = p->copy_ranges;
    do
    {
        if (range->flag & context_flags)
        {
            if (!start)
                start = range->start;
        }
        else if (start)
        {
            memcpy( d + start, s + start, range->start - start );
            start = 0;
        }
    }
    while (range++->start != p->context_size);
}


/***********************************************************************
 *              RtlCopyContext  (NTDLL.@)
 */
NTSTATUS WINAPI RtlCopyContext( CONTEXT *dst, DWORD context_flags, CONTEXT *src )
{
    DWORD context_size, arch_flag, flags_offset, dst_flags, src_flags;
    static const DWORD arch_mask = CONTEXT_i386 | CONTEXT_AMD64;
    const struct context_parameters *p;
    BYTE *d, *s;

    TRACE("dst %p, context_flags %#lx, src %p.\n", dst, context_flags, src);

    if (context_flags & 0x40 && !RtlGetEnabledExtendedFeatures( ~(ULONG64)0 )) return STATUS_NOT_SUPPORTED;

    arch_flag = context_flags & arch_mask;
    switch (arch_flag)
    {
    case CONTEXT_i386:
        context_size = sizeof( I386_CONTEXT );
        flags_offset = offsetof( I386_CONTEXT, ContextFlags );
        break;
    case CONTEXT_AMD64:
        context_size = sizeof( AMD64_CONTEXT );
        flags_offset = offsetof( AMD64_CONTEXT, ContextFlags );
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    d = (BYTE *)dst;
    s = (BYTE *)src;
    dst_flags = *(DWORD *)(d + flags_offset);
    src_flags = *(DWORD *)(s + flags_offset);

    if ((dst_flags & arch_mask) != arch_flag || (src_flags & arch_mask) != arch_flag)
        return STATUS_INVALID_PARAMETER;

    context_flags &= src_flags;
    if (context_flags & ~dst_flags & 0x40) return STATUS_BUFFER_OVERFLOW;

    if (context_flags & 0x40)
        return RtlCopyExtendedContext( (CONTEXT_EX *)(d + context_size), context_flags,
                                       (CONTEXT_EX *)(s + context_size) );

    if (!(p = context_get_parameters( context_flags )))
        return STATUS_INVALID_PARAMETER;

    context_copy_ranges( d, context_flags, s, p );
    return STATUS_SUCCESS;
}


/**********************************************************************
 *              RtlCopyExtendedContext      (NTDLL.@)
 */
NTSTATUS WINAPI RtlCopyExtendedContext( CONTEXT_EX *dst, ULONG context_flags, CONTEXT_EX *src )
{
    const struct context_parameters *p;
    XSAVE_AREA_HEADER *dst_xs, *src_xs;
    ULONG64 feature_mask;
    unsigned int i, off, size;

    TRACE( "dst %p, context_flags %#lx, src %p.\n", dst, context_flags, src );

    if (!(p = context_get_parameters( context_flags )))
        return STATUS_INVALID_PARAMETER;

    if (!(feature_mask = RtlGetEnabledExtendedFeatures( ~(ULONG64)0 )) && context_flags & 0x40)
        return STATUS_NOT_SUPPORTED;

    context_copy_ranges( RtlLocateLegacyContext( dst, NULL ), context_flags, RtlLocateLegacyContext( src, NULL ), p );

    if (!(context_flags & 0x40))
        return STATUS_SUCCESS;

    if (dst->XState.Length < sizeof(XSAVE_AREA_HEADER))
        return STATUS_BUFFER_OVERFLOW;

    dst_xs = (XSAVE_AREA_HEADER *)((BYTE *)dst + dst->XState.Offset);
    src_xs = (XSAVE_AREA_HEADER *)((BYTE *)src + src->XState.Offset);

    memset(dst_xs, 0, sizeof(XSAVE_AREA_HEADER));
    dst_xs->Mask = (src_xs->Mask & ~(ULONG64)3) & feature_mask;
    dst_xs->CompactionMask = user_shared_data->XState.CompactionEnabled
            ? ((ULONG64)1 << 63) | (src_xs->CompactionMask & feature_mask) : 0;


    if (dst_xs->CompactionMask) feature_mask &= dst_xs->CompactionMask;
    feature_mask = dst_xs->Mask >> 2;

    i = 2;
    off = sizeof(XSAVE_AREA_HEADER);
    while (1)
    {
        if (feature_mask & 1)
        {
            if (!dst_xs->CompactionMask) off = user_shared_data->XState.Features[i].Offset - sizeof(XSAVE_FORMAT);
            size = user_shared_data->XState.Features[i].Size;
            if (src->XState.Length < off + size || dst->XState.Length < off + size) break;
            memcpy( (BYTE *)dst_xs + off, (BYTE *)src_xs + off, size );
        }
        if (!(feature_mask >>= 1)) break;
        if (dst_xs->CompactionMask) off = next_compacted_xstate_offset( off, dst_xs->CompactionMask, i);
        ++i;
    }
    return STATUS_SUCCESS;
}
