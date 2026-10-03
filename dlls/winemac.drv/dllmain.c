/*
 * winemac.drv entry points
 *
 * Copyright 2022 Jacek Caban for CodeWeavers
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
#include <stdio.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "ntgdi.h"
#include "macdrv_res.h"
#include "shellapi.h"
#include "winreg.h"
#include "unixlib.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(macdrv);
WINE_DECLARE_DEBUG_CHANNEL(winediag);


static HMODULE macdrv_module = 0;

/* Which winemac.drv actually ran.  Both system32 (x86_64) and syswow64 (i386) copies are
 * synced into every prefix and an aarch64 build also exists, so "which one" is half the
 * answer whenever the driver fails to come up.  ARM64EC also defines __aarch64__, so it
 * must be tested first. */
#if defined(__arm64ec__) || defined(_M_ARM64EC)
# define MACDRV_PE_ARCH "arm64ec"
#elif defined(__aarch64__)
# define MACDRV_PE_ARCH "aarch64"
#elif defined(__x86_64__)
# define MACDRV_PE_ARCH "x86_64"
#elif defined(__i386__)
# define MACDRV_PE_ARCH "i386"
#else
# define MACDRV_PE_ARCH "unknown"
#endif

/* UNGATED PE-side trace.
 *
 * Deliberately NOT ERR()/TRACE(): every run before try9 used WINEDEBUG=-all, which
 * silences __wine_dbg_output entirely -- and that is exactly how the null-user-driver
 * state stayed invisible for two days.  A trace that a debug channel can suppress is a
 * trace whose silence proves nothing, which is this lane's standing gate
 * ("not logged != did not happen").  So this writes straight to the process stderr
 * handle, where mr-run.sh's run.log already captures the unix side's fprintf output.
 *
 * Three lines, once per process, on the process-attach path only. */
static void macdrv_pe_trace( const char *fmt, ... )
{
    HANDLE handle = GetStdHandle( STD_ERROR_HANDLE );
    char buf[256];
    DWORD written;
    va_list args;
    int len;

    va_start( args, fmt );
    len = vsnprintf( buf, sizeof(buf), fmt, args );
    va_end( args );

    if (len <= 0) return;
    if (len > (int)sizeof(buf) - 1) len = sizeof(buf) - 1;   /* vsnprintf returns the WANTED length */

    if (handle && handle != INVALID_HANDLE_VALUE)
        WriteFile( handle, buf, len, &written, NULL );

    /* SECOND, INDEPENDENT PATH.  GetStdHandle(STD_ERROR_HANDLE) can legitimately be NULL
     * in a GUI process, and this trace mechanism has never been exercised in a PE in this
     * process type -- so relying on it alone would risk manufacturing exactly the silence
     * it exists to rule out.  try9 runs WINEDEBUG='-all,+winediag,err+win', so the winediag
     * channel is open; if one path is dead the other still reports.  Two paths agreeing
     * also cross-validates the mechanism for every later run. */
    ERR_(winediag)( "%s", buf );

    /* THIRD PATH, added 2026-07-29 (HK E2E lane) — because on HK BOTH paths above are
     * dead and their silence was therefore uninterpretable.  Measured: HK's run log has
     * zero dllmain_* lines while winemac.so is mapped in the process, and the two paths
     * fail for independent reasons — STD_ERROR_HANDLE is NULL in this GUI process (the
     * comment above already anticipated it), and ERR_(winediag) is suppressed because
     * these runs use WINEDEBUG=-all, not try9's '-all,+winediag,err+win'.
     * MESSAGE() goes through __wine_dbg_output unconditionally, with no channel to
     * disable, so it survives WINEDEBUG=-all — the same property that made the
     * kernelbase MUI process-attach counts readable in arbitrary run logs. */
    MESSAGE( "%s", buf );
}

/* MacRunner 2026-07-29 (HK DllMain lane).  Skip the LoadStringW menu-string loop in
 * process_attach and hand macdrv_init a NULL strings array.
 *
 * Why this gate exists, measured: with the loader change that lets winemac.drv's x64 DllMain
 * run in HK's process (loader.c needs_x64_entry), process_attach reaches
 * stage=dllmain_unixcall_init status=00000000 and then WEDGES -- 3 runs out of 3, in two
 * independent lanes, log frozen with the process alive.  `sample` on the live process caught
 * the thread with 3626/3626 samples inside macrunner_hb_route_x64_callback_fault, on a stack
 * that carries BOTH macrunner_hb_x64_dll_entry and win32u's load_display_driver ->
 * KeUserModeCallback: the DllMain is running NESTED INSIDE the display-driver load, and it
 * faulted while calling a native PE import (macrunner_hb_call_direct_native_target ->
 * macrunner_hb_call_arm64_pe_import12_for_ctx).
 *
 * The import is very likely LoadStringW and not something earlier, because macdrv_pe_trace
 * itself calls GetStdHandle+WriteFile (kernel32) immediately before and those DID work -- the
 * dllmain_unixcall_init line is in the log.  What differs about the next 12 calls is that
 * LoadStringW is a USER32 import, issued while win32u is mid-load_display_driver on this very
 * thread.  [HYPOTHESIS] that re-entry is the fault; this gate tests it by removing it.
 *
 * Passing NULL is explicitly legal: macdrv_init_core() takes `strings` NULL and skips
 * load_strings(), which is exactly what the unix self-init path already does.  Cost of NULL is
 * the Mac menu-bar strings falling back to defaults -- not input, not the driver itself.
 *
 * MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 337 — УМОЛЧАНИЕ ПЕРЕВЕДЕНО В «ПРОПУСКАТЬ».
 *
 * Гипотеза выше подтверждена замером: без гейта `DllMain` печатает `dllmain_strings_enter` и
 * НЕ ВОЗВРАЩАЕТСЯ — `LoadLibraryW(L"winemac.drv")` в `explorer` висит до конца прогона. С гейтом
 * прогон идёт дальше: `dllmain_strings_skipped` → `macdrv_init_session status=0 graphic=1` →
 * `run_cocoa_app_decide created_app=1 success=1` → `driver_set_user_driver_real`.
 *
 * Почему именно умолчание, а не переменная. Драйвер грузит `explorer`, которого запускает
 * wineserver, и переменные окружения нашего процесса до него НЕ ДОХОДЯТ: замер
 * `ps -Eww` по живому explorer даёт ноль вхождений имени гейта (контроль на инструмент пройден —
 * `PATH` тем же способом виден). Поэтому прогон игры с `MACRUNNER_WINEMAC_PE_SKIP_STRINGS=1`
 * лечения НЕ дал: гейт до нужного процесса не доехал. Гейт, который не может достичь процесса,
 * где выполняется код, равносилен выключенному.
 *
 * Цена пропуска названа выше и не изменилась: строки меню Mac берутся по умолчанию. Ни ввод, ни
 * сам драйвер от этого не страдают.
 *
 * Возврат прежнего поведения: `MACRUNNER_WINEMAC_PE_STRINGS=1`. */
static BOOL macdrv_pe_skip_strings(void)
{
    char value[8] = {0};

    if (GetEnvironmentVariableA( "MACRUNNER_WINEMAC_PE_STRINGS", value, sizeof(value) )
        && value[0] && value[0] != '0')
        return FALSE;                      /* явный возврат к загрузке строк */

    value[0] = 0;
    if (GetEnvironmentVariableA( "MACRUNNER_WINEMAC_PE_SKIP_STRINGS", value, sizeof(value) )
        && value[0] == '0')
        return FALSE;                      /* старый выключатель по-прежнему работает */

    return TRUE;                           /* умолчание: пропускать */
}

struct quit_info {
    HWND               *wins;
    UINT                capacity;
    UINT                count;
    UINT                done;
    DWORD               flags;
    BOOL                result;
    BOOL                replied;
};


static BOOL CALLBACK get_process_windows(HWND hwnd, LPARAM lp)
{
    struct quit_info *qi = (struct quit_info*)lp;
    DWORD pid;

    /* CW Hack #26261 */
    {
        static const WCHAR chrome_statustraywindowW[] = {'C','h','r','o','m','e','_','S','t','a','t','u','s','T','r','a','y','W','i','n','d','o','w',0};
        WCHAR buffer[sizeof(chrome_statustraywindowW) / sizeof(WCHAR)];
        UNICODE_STRING name = { .Buffer = buffer, .MaximumLength = sizeof(chrome_statustraywindowW) };

        if (NtUserGetClassName(hwnd, FALSE, &name) &&
            !memcmp(chrome_statustraywindowW, buffer, sizeof(chrome_statustraywindowW)))
        {
            WARN("HACK: not sending session end messages to Chrome_StatusTrayWindow hwnd %p\n", hwnd);
            return TRUE;
        }
    }

    NtUserGetWindowThread(hwnd, &pid);
    if (pid == GetCurrentProcessId())
    {
        if (qi->count >= qi->capacity)
        {
            UINT new_cap = qi->capacity * 2;
            HWND *new_wins = HeapReAlloc(GetProcessHeap(), 0, qi->wins, new_cap * sizeof(*qi->wins));
            if (!new_wins) return FALSE;
            qi->wins = new_wins;
            qi->capacity = new_cap;
        }

        qi->wins[qi->count++] = hwnd;
    }

    return TRUE;
}

#pragma pack(push,1)

typedef struct
{
    BYTE bWidth;
    BYTE bHeight;
    BYTE bColorCount;
    BYTE bReserved;
    WORD wPlanes;
    WORD wBitCount;
    DWORD dwBytesInRes;
    WORD nID;
} GRPICONDIRENTRY;

typedef struct
{
    WORD idReserved;
    WORD idType;
    WORD idCount;
    GRPICONDIRENTRY idEntries[1];
} GRPICONDIR;

#pragma pack(pop)

static void quit_reply(int reply)
{
    struct quit_result_params params = { .result = reply };
    MACDRV_CALL(quit_result, &params);
}


static void CALLBACK quit_callback(HWND hwnd, UINT msg, ULONG_PTR data, LRESULT result)
{
    struct quit_info *qi = (struct quit_info*)data;

    qi->done++;

    if (msg == WM_QUERYENDSESSION)
    {
        TRACE("got WM_QUERYENDSESSION result %Id from win %p (%u of %u done)\n", result,
              hwnd, qi->done, qi->count);

        if (!result && !IsWindow(hwnd))
        {
            TRACE("win %p no longer exists; ignoring apparent refusal\n", hwnd);
            result = TRUE;
        }

        if (!result && qi->result)
        {
            qi->result = FALSE;

            /* On the first FALSE from WM_QUERYENDSESSION, we already know the
               ultimate reply.  Might as well tell Cocoa now. */
            if (!qi->replied)
            {
                qi->replied = TRUE;
                TRACE("giving quit reply %d\n", qi->result);
                quit_reply(qi->result);
            }
        }

        if (qi->done >= qi->count)
        {
            UINT i;

            qi->done = 0;
            for (i = 0; i < qi->count; i++)
            {
                TRACE("sending WM_ENDSESSION to win %p result %d flags 0x%08lx\n", qi->wins[i],
                      qi->result, qi->flags);
                if (!SendMessageCallbackW(qi->wins[i], WM_ENDSESSION, qi->result, qi->flags,
                                          quit_callback, (ULONG_PTR)qi))
                {
                    WARN("failed to send WM_ENDSESSION to win %p; error 0x%08lx\n",
                         qi->wins[i], RtlGetLastWin32Error());
                    quit_callback(qi->wins[i], WM_ENDSESSION, (ULONG_PTR)qi, 0);
                }
            }
        }
    }
    else /* WM_ENDSESSION */
    {
        TRACE("finished WM_ENDSESSION for win %p (%u of %u done)\n", hwnd, qi->done, qi->count);

        if (qi->done >= qi->count)
        {
            if (!qi->replied)
            {
                TRACE("giving quit reply %d\n", qi->result);
                quit_reply(qi->result);
            }

            TRACE("%sterminating process\n", qi->result ? "" : "not ");
            if (qi->result)
                TerminateProcess(GetCurrentProcess(), 0);

            HeapFree(GetProcessHeap(), 0, qi->wins);
            HeapFree(GetProcessHeap(), 0, qi);
        }
    }
}


/***********************************************************************
 *              macdrv_app_quit_request
 */
NTSTATUS WINAPI macdrv_app_quit_request(void *arg, ULONG size)
{
    struct app_quit_request_params *params = arg;
    struct quit_info *qi;
    UINT i;

    qi = HeapAlloc(GetProcessHeap(), 0, sizeof(*qi));
    if (!qi)
        goto fail;

    qi->capacity = 32;
    qi->wins = HeapAlloc(GetProcessHeap(), 0, qi->capacity * sizeof(*qi->wins));
    qi->count = qi->done = 0;

    if (!qi->wins || !EnumWindows(get_process_windows, (LPARAM)qi))
        goto fail;

    qi->flags = params->flags;
    qi->result = TRUE;
    qi->replied = FALSE;

    for (i = 0; i < qi->count; i++)
    {
        TRACE("sending WM_QUERYENDSESSION to win %p\n", qi->wins[i]);
        if (!SendMessageCallbackW(qi->wins[i], WM_QUERYENDSESSION, 0, qi->flags,
                                  quit_callback, (ULONG_PTR)qi))
        {
            DWORD error = RtlGetLastWin32Error();
            BOOL invalid = (error == ERROR_INVALID_WINDOW_HANDLE);
            if (invalid)
                TRACE("failed to send WM_QUERYENDSESSION to win %p because it's invalid; assuming success\n",
                     qi->wins[i]);
            else
                WARN("failed to send WM_QUERYENDSESSION to win %p; error 0x%08lx; assuming refusal\n",
                     qi->wins[i], error);
            quit_callback(qi->wins[i], WM_QUERYENDSESSION, (ULONG_PTR)qi, invalid);
        }
    }

    /* quit_callback() will clean up qi */
    return STATUS_SUCCESS;

fail:
    WARN("failed to allocate window list\n");
    if (qi)
    {
        HeapFree(GetProcessHeap(), 0, qi->wins);
        HeapFree(GetProcessHeap(), 0, qi);
    }
    quit_reply(FALSE);
    return STATUS_SUCCESS;
}

/***********************************************************************
 *              get_first_resource
 *
 * Helper for create_app_icon_images().  Enum proc for EnumResourceNamesW()
 * which just gets the handle for the first resource and stops further
 * enumeration.
 */
static BOOL CALLBACK get_first_resource(HMODULE module, LPCWSTR type, LPWSTR name, LONG_PTR lparam)
{
    HRSRC *res_info = (HRSRC*)lparam;

    *res_info = FindResourceW(module, name, (LPCWSTR)RT_GROUP_ICON);
    return FALSE;
}


/***********************************************************************
 *              macdrv_app_icon
 */
static NTSTATUS WINAPI macdrv_app_icon(void *arg, ULONG size)
{
    struct app_icon_entry entries[64];
    HRSRC res_info;
    HGLOBAL res_data;
    GRPICONDIR *icon_dir;
    unsigned count;
    int i;

    TRACE("()\n");

    count = 0;

    res_info = NULL;
    EnumResourceNamesW(NULL, (LPCWSTR)RT_GROUP_ICON, get_first_resource, (LONG_PTR)&res_info);
    if (!res_info)
    {
        WARN("found no RT_GROUP_ICON resource\n");
        return STATUS_SUCCESS;
    }

    if (!(res_data = LoadResource(NULL, res_info)))
    {
        WARN("failed to load RT_GROUP_ICON resource\n");
        return STATUS_SUCCESS;
    }

    if (!(icon_dir = LockResource(res_data)))
    {
        WARN("failed to lock RT_GROUP_ICON resource\n");
        goto cleanup;
    }

    for (i = 0; i < icon_dir->idCount && count < ARRAYSIZE(entries); i++)
    {
        struct app_icon_entry *entry = &entries[count];
        int width = icon_dir->idEntries[i].bWidth;
        int height = icon_dir->idEntries[i].bHeight;
        BOOL found_better_bpp = FALSE;
        int j;
        LPCWSTR name;
        HGLOBAL icon_res_data;
        BYTE *icon_bits;

        if (!width) width = 256;
        if (!height) height = 256;

        /* If there's another icon at the same size but with better
           color depth, skip this one.  We end up making CGImages that
           are all 32 bits per pixel, so Cocoa doesn't get the original
           color depth info to pick the best representation itself. */
        for (j = 0; j < icon_dir->idCount; j++)
        {
            int jwidth = icon_dir->idEntries[j].bWidth;
            int jheight = icon_dir->idEntries[j].bHeight;

            if (!jwidth) jwidth = 256;
            if (!jheight) jheight = 256;

            if (j != i && jwidth == width && jheight == height &&
                icon_dir->idEntries[j].wBitCount > icon_dir->idEntries[i].wBitCount)
            {
                found_better_bpp = TRUE;
                break;
            }
        }

        if (found_better_bpp) continue;

        name = MAKEINTRESOURCEW(icon_dir->idEntries[i].nID);
        res_info = FindResourceW(NULL, name, (LPCWSTR)RT_ICON);
        if (!res_info)
        {
            WARN("failed to find RT_ICON resource %d with ID %hd\n", i, icon_dir->idEntries[i].nID);
            continue;
        }

        icon_res_data = LoadResource(NULL, res_info);
        if (!icon_res_data)
        {
            WARN("failed to load icon %d with ID %hd\n", i, icon_dir->idEntries[i].nID);
            continue;
        }

        icon_bits = LockResource(icon_res_data);
        if (icon_bits)
        {
            static const BYTE png_magic[] = { 0x89, 0x50, 0x4e, 0x47 };

            entry->width = width;
            entry->height = height;
            entry->size = icon_dir->idEntries[i].dwBytesInRes;

            if (!memcmp(icon_bits, png_magic, sizeof(png_magic)))
            {
                entry->png = (UINT_PTR)icon_bits;
                entry->icon = 0;
                count++;
            }
            else
            {
                HICON icon = CreateIconFromResourceEx(icon_bits, icon_dir->idEntries[i].dwBytesInRes,
                                                      TRUE, 0x00030000, width, height, 0);
                if (icon)
                {
                    entry->icon = HandleToUlong(icon);
                    entry->png = 0;
                    count++;
                }
                else
                    WARN("failed to create icon %d from resource with ID %hd\n", i, icon_dir->idEntries[i].nID);
            }
        }
        else
            WARN("failed to lock RT_ICON resource %d with ID %hd\n", i, icon_dir->idEntries[i].nID);

        FreeResource(icon_res_data);
    }

cleanup:
    FreeResource(res_data);

    return NtCallbackReturn(entries, count * sizeof(entries[0]), 0);
}

static NTSTATUS WINAPI macdrv_regcreateopenkeyexa(void *arg, ULONG size)
{
    struct regcreateopenkeyexa_params *params = arg;
    LONG result;

    TRACE("()\n");

    if (params->create)
    {
        result = RegCreateKeyExA(UlongToHandle(params->hkey),
                                 param_ptr(params->name),
                                 params->reserved,
                                 param_ptr(params->class),
                                 params->options,
                                 params->access,
                                 param_ptr(params->security),
                                 param_ptr(params->retkey),
                                 param_ptr(params->disposition));
    }
    else
    {
        result = RegOpenKeyExA(UlongToHandle(params->hkey),
                               param_ptr(params->name),
                               params->options,
                               params->access,
                               param_ptr(params->retkey));
    }
    *(LONG *)param_ptr(params->result) = result;
    return 0;
}

static NTSTATUS WINAPI macdrv_regqueryvalueexa(void *arg, ULONG size)
{
    struct regqueryvalueexa_params *params = arg;
    LONG result;

    TRACE("()\n");

    result = RegQueryValueExA(UlongToHandle(params->hkey),
                              param_ptr(params->name),
                              param_ptr(params->reserved),
                              param_ptr(params->type),
                              param_ptr(params->data),
                              param_ptr(params->count));

    *(LONG *)param_ptr(params->result) = result;
    return 0;
}

static NTSTATUS WINAPI macdrv_regsetvalueexa(void *arg, ULONG size)
{
    struct regsetvalueexa_params *params = arg;
    LONG result;

    TRACE("()\n");

    result = RegSetValueExA(UlongToHandle(params->hkey),
                            param_ptr(params->name),
                            params->reserved,
                            params->type,
                            param_ptr(params->data),
                            params->count);

    *(LONG *)param_ptr(params->result) = result;
    return 0;
}


static BOOL process_attach(void)
{
    struct init_params params;
    NTSTATUS status;

    struct localized_string *str;
    struct localized_string strings[] = {
        { .id = STRING_MENU_WINE },
        { .id = STRING_MENU_ITEM_HIDE_APPNAME },
        { .id = STRING_MENU_ITEM_HIDE },
        { .id = STRING_MENU_ITEM_HIDE_OTHERS },
        { .id = STRING_MENU_ITEM_SHOW_ALL },
        { .id = STRING_MENU_ITEM_QUIT_APPNAME },
        { .id = STRING_MENU_ITEM_QUIT },

        { .id = STRING_MENU_WINDOW },
        { .id = STRING_MENU_ITEM_MINIMIZE },
        { .id = STRING_MENU_ITEM_ZOOM },
        { .id = STRING_MENU_ITEM_ENTER_FULL_SCREEN },
        { .id = STRING_MENU_ITEM_BRING_ALL_TO_FRONT },

        { .id = 0 }
    };

    status = __wine_init_unix_call();
    macdrv_pe_trace( "macrunner-ui-input: stage=dllmain_unixcall_init arch=%s status=%08x\n",
                     MACDRV_PE_ARCH, (unsigned int)status );
    if (status) return FALSE;

    /* Both branches trace, and they trace on BOTH sides of the LoadStringW loop.  This lane's
     * standing gate is that a probe which only reports success cannot distinguish "did not run"
     * from "ran and hung": the wedge measured on 2026-07-29 sits between the line above and the
     * MACDRV_CALL(init) below, and nothing currently prints in that window, so the window itself
     * is what has to be made observable.  strings_enter/strings_loaded bracket the suspect. */
    if (macdrv_pe_skip_strings())
    {
        macdrv_pe_trace( "macrunner-ui-input: stage=dllmain_strings_skipped arch=%s\n",
                         MACDRV_PE_ARCH );
        params.strings = NULL;
    }
    else
    {
        macdrv_pe_trace( "macrunner-ui-input: stage=dllmain_strings_enter arch=%s\n",
                         MACDRV_PE_ARCH );
        for (str = strings; str->id; str++)
            str->len = LoadStringW(macdrv_module, str->id, (WCHAR *)&str->str, 0);
        macdrv_pe_trace( "macrunner-ui-input: stage=dllmain_strings_loaded arch=%s n=%u\n",
                         MACDRV_PE_ARCH, (unsigned int)(str - strings) );
        params.strings = strings;
    }
    params.app_icon_callback = (UINT_PTR)macdrv_app_icon;
    params.app_quit_request_callback = (UINT_PTR)macdrv_app_quit_request;
    params.regcreateopenkeyexa_callback = (UINT_PTR)macdrv_regcreateopenkeyexa;
    params.regsetvalueexa_callback = (UINT_PTR)macdrv_regsetvalueexa;
    params.regqueryvalueexa_callback = (UINT_PTR)macdrv_regqueryvalueexa;

    status = MACDRV_CALL(init, &params);
    macdrv_pe_trace( "macrunner-ui-input: stage=dllmain_macdrv_init_call arch=%s status=%08x\n",
                     MACDRV_PE_ARCH, (unsigned int)status );
    if (status) return FALSE;

    macdrv_pe_trace( "macrunner-ui-input: stage=dllmain_attach_ok arch=%s\n", MACDRV_PE_ARCH );
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
    if (reason != DLL_PROCESS_ATTACH) return TRUE;

    /* FIRST statement on the attach path: if this line is absent from a run.log, the
     * winemac.drv PE was never loaded at all -- which is precisely the 2026-07-28
     * null-user-driver finding, and it separates that from "loaded but init failed". */
    macdrv_pe_trace( "macrunner-ui-input: stage=dllmain_attach arch=%s pid=%04x inst=%p\n",
                     MACDRV_PE_ARCH, (unsigned int)GetCurrentProcessId(), instance );

    DisableThreadLibraryCalls(instance);
    macdrv_module = instance;
    return process_attach();
}
