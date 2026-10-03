/*
 * WoW64 syscall wrapping
 *
 * Copyright 2021 Alexandre Julliard
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

#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "rtlsupportapi.h"
#include "wow64win_private.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(wow);

BOOL macrunner_wow64win_cpu_hb = TRUE;

static void DECLSPEC_NORETURN stub_syscall( const char *name )
{
    EXCEPTION_RECORD record;

    /* ★ MacRunner 2026-08-28 — НАЗВАТЬ НЕРЕАЛИЗОВАННЫЙ ВЫЗОВ.
     *
     * Diablo умирал так: поток команд wined3d получает `c0000025`
     * (NONCONTINUABLE) сразу после `WINED3D_CS_OP_UNLOAD_RESOURCE`, раскрутка
     * стека не находит НИ ОДНОГО обработчика, и процесс уходит. Виновника
     * пришлось искать по карте модулей — `wow64win.dll + 0x1584FC`, — потому
     * что штатное сообщение wine «Call from %p to unimplemented function» до
     * журнала не доходит: до обработчика, который его печатает
     * (`ntdll/exception.c`), управление не добирается.
     *
     * Печатаем имя ПРЯМО ЗДЕСЬ, до подъёма исключения. Иначе «нет такого
     * системного вызова» неотличимо от любого другого падения потока команд. */
    MESSAGE( "macrunner-wow64win-заглушка: НЕРЕАЛИЗОВАН системный вызов win32u.%s\n", name );

    record.ExceptionCode    = EXCEPTION_WINE_STUB;
    record.ExceptionFlags   = EXCEPTION_NONCONTINUABLE;
    record.ExceptionRecord  = NULL;
    record.ExceptionAddress = stub_syscall;
    record.NumberParameters = 2;
    record.ExceptionInformation[0] = (ULONG_PTR)"win32u";
    record.ExceptionInformation[1] = (ULONG_PTR)name;
    for (;;) RtlRaiseException( &record );
}

#define SYSCALL_STUB(name) NTSTATUS WINAPI wow64_ ## name( UINT *args ) { stub_syscall( #name ); }
ALL_SYSCALL_STUBS

static void * const win32_syscalls[] =
{
#define SYSCALL_ENTRY(id,name,args) wow64_ ## name,
    ALL_SYSCALLS32
#undef SYSCALL_ENTRY
};

static BYTE arguments[ARRAY_SIZE(win32_syscalls)] =
{
#define SYSCALL_ENTRY(id,name,args) args,
    ALL_SYSCALLS32
#undef SYSCALL_ENTRY
};

const SYSTEM_SERVICE_TABLE sdwhwin32 =
{
    (ULONG_PTR *)win32_syscalls,
    NULL,
    ARRAY_SIZE(win32_syscalls),
    arguments
};


BOOL WINAPI DllMain( HINSTANCE inst, DWORD reason, void *reserved )
{
    BOOL (*is_hb)(void);
    UNICODE_STRING name;
    HMODULE ntdll = NULL;

    if (reason != DLL_PROCESS_ATTACH) return TRUE;

    RtlInitUnicodeString( &name, L"ntdll.dll" );
    if (LdrGetDllHandle( NULL, 0, &name, &ntdll ) ||
        !(is_hb = RtlFindExportedRoutineByName( ntdll, "macrunner_cpu_backend_is_hb" )))
    {
        MESSAGE( "macrunner-wow64win-owner: sel=MISSING — mismatched runtime\n" );
        return FALSE;
    }
    macrunner_wow64win_cpu_hb = is_hb();
    MESSAGE( "macrunner-wow64win-owner: sel=%s alias_tls=%s\n",
             macrunner_wow64win_cpu_hb ? "hb" : "ne-hb",
             macrunner_wow64win_cpu_hb ? "OWNED" : "NOT_USED" );
    LdrDisableThreadCalloutsForDll( inst );
    NtCurrentTeb()->Peb->KernelCallbackTable = user_callbacks;
    return TRUE;
}
