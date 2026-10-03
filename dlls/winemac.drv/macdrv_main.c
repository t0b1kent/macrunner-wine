/*
 * MACDRV initialization code
 *
 * Copyright 1998 Patrik Stridvall
 * Copyright 2000 Alexandre Julliard
 * Copyright 2011, 2012, 2013 Ken Thomases for CodeWeavers Inc.
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

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <Security/AuthSession.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "macdrv.h"
#include "shellapi.h"
#include "wine/server.h"

WINE_DEFAULT_DEBUG_CHANNEL(macdrv);

#define IS_OPTION_TRUE(ch) \
    ((ch) == 'y' || (ch) == 'Y' || (ch) == 't' || (ch) == 'T' || (ch) == '1')

C_ASSERT(NUM_EVENT_TYPES <= sizeof(macdrv_event_mask) * 8);

static BOOL trace_ui_input_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
        enabled = getenv("MACRUNNER_TRACE_WINEMAC_INPUT") != NULL ||
                  getenv("MACRUNNER_TRACE_UI_INPUT") != NULL ||
                  getenv("MACRUNNER_TRACE_UI_EVENT_PATH") != NULL;
    return enabled;
}

static unsigned long long trace_ui_input_tid(void)
{
    uint64_t tid = 0;
    pthread_threadid_np(NULL, &tid);
    return tid;
}

int topmost_float_inactive = TOPMOST_FLOAT_INACTIVE_NONFULLSCREEN;
bool capture_displays_for_fullscreen = false;
BOOL allow_vsync = TRUE;
BOOL macrunner_display_mode_changed = FALSE;
static struct timespec macrunner_mode_change_ts;
void macrunner_note_display_mode_change(void)
{
    clock_gettime(CLOCK_MONOTONIC, &macrunner_mode_change_ts);
}
unsigned int macrunner_ms_since_display_mode_change(void)
{
    struct timespec now;
    if (!macrunner_mode_change_ts.tv_sec && !macrunner_mode_change_ts.tv_nsec) return ~0u;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (unsigned int)((now.tv_sec - macrunner_mode_change_ts.tv_sec) * 1000 + (now.tv_nsec - macrunner_mode_change_ts.tv_nsec) / 1000000);
}
BOOL allow_set_gamma = TRUE;
/* CrossOver Hack 10912: Mac Edit menu */
int mac_edit_menu = MAC_EDIT_MENU_BY_KEY;
bool left_option_is_alt = false;
bool right_option_is_alt = false;
bool left_command_is_ctrl = false;
bool right_command_is_ctrl = false;
BOOL allow_software_rendering = FALSE;
bool allow_immovable_windows = true;
bool use_confinement_cursor_clipping = true;
bool cursor_clipping_locks_windows = true;
bool use_precise_scrolling = true;
int gl_surface_mode = GL_SURFACE_IN_FRONT_OPAQUE;
bool retina_enabled = false;
bool enable_app_nap = false;

UINT64 app_icon_callback = 0;
UINT64 app_quit_request_callback = 0;
UINT64 regcreateopenkeyexa_callback = 0;
UINT64 regqueryvalueexa_callback = 0;
UINT64 regsetvalueexa_callback = 0;

CFDictionaryRef localized_strings;


/**************************************************************************
 *              debugstr_cf
 */
const char* debugstr_cf(CFTypeRef t)
{
    CFStringRef s;
    const char* ret;

    if (!t) return "(null)";

    if (CFGetTypeID(t) == CFStringGetTypeID())
        s = t;
    else
        s = CFCopyDescription(t);
    ret = CFStringGetCStringPtr(s, kCFStringEncodingUTF8);
    if (ret) ret = debugstr_a(ret);
    if (!ret)
    {
        const UniChar* u = CFStringGetCharactersPtr(s);
        if (u)
            ret = debugstr_wn((const WCHAR*)u, CFStringGetLength(s));
    }
    if (!ret)
    {
        UniChar buf[200];
        int len = min(CFStringGetLength(s), ARRAY_SIZE(buf));
        CFStringGetCharacters(s, CFRangeMake(0, len), buf);
        ret = debugstr_wn(buf, len);
    }
    if (s != t) CFRelease(s);
    return ret;
}


HKEY reg_open_key(HKEY root, const WCHAR *name, ULONG name_len)
{
    UNICODE_STRING nameW = { name_len, name_len, (WCHAR *)name };
    OBJECT_ATTRIBUTES attr;
    HANDLE ret;

    attr.Length = sizeof(attr);
    attr.RootDirectory = root;
    attr.ObjectName = &nameW;
    attr.Attributes = 0;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;

    return NtOpenKeyEx(&ret, MAXIMUM_ALLOWED, &attr, 0) ? 0 : ret;
}


HKEY open_hkcu_key(const char *name)
{
    WCHAR bufferW[256];
    static HKEY hkcu;

    if (!hkcu)
    {
        char buffer[256];
        DWORD_PTR sid_data[(sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE) / sizeof(DWORD_PTR)];
        DWORD i, len = sizeof(sid_data);
        SID *sid;

        if (NtQueryInformationToken(GetCurrentThreadEffectiveToken(), TokenUser, sid_data, len, &len))
            return 0;

        sid = ((TOKEN_USER *)sid_data)->User.Sid;
        len = snprintf(buffer, sizeof(buffer), "\\Registry\\User\\S-%u-%u", sid->Revision,
                        MAKELONG(MAKEWORD(sid->IdentifierAuthority.Value[5],
                                           sid->IdentifierAuthority.Value[4]),
                                  MAKEWORD(sid->IdentifierAuthority.Value[3],
                                            sid->IdentifierAuthority.Value[2])));
        for (i = 0; i < sid->SubAuthorityCount; i++)
            len += snprintf(buffer + len, sizeof(buffer) - len, "-%u", sid->SubAuthority[i]);

        ascii_to_unicode(bufferW, buffer, len);
        hkcu = reg_open_key(NULL, bufferW, len * sizeof(WCHAR));
    }

    return reg_open_key(hkcu, bufferW, asciiz_to_unicode(bufferW, name) - sizeof(WCHAR));
}


/* wrapper for NtCreateKey that creates the key recursively if necessary */
HKEY reg_create_key(HKEY root, const WCHAR *name, ULONG name_len,
                    DWORD options, DWORD *disposition)
{
    UNICODE_STRING nameW = { name_len, name_len, (WCHAR *)name };
    OBJECT_ATTRIBUTES attr;
    NTSTATUS status;
    HANDLE ret;

    attr.Length = sizeof(attr);
    attr.RootDirectory = root;
    attr.ObjectName = &nameW;
    attr.Attributes = 0;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;

    status = NtCreateKey(&ret, MAXIMUM_ALLOWED, &attr, 0, NULL, options, disposition);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND)
    {
        static const WCHAR registry_rootW[] = { '\\','R','e','g','i','s','t','r','y','\\' };
        DWORD pos = 0, i = 0, len = name_len / sizeof(WCHAR);

        /* don't try to create registry root */
        if (!root && len > ARRAY_SIZE(registry_rootW) &&
            !memcmp(name, registry_rootW, sizeof(registry_rootW)))
            i += ARRAY_SIZE(registry_rootW);

        while (i < len && name[i] != '\\') i++;
        if (i == len) return 0;
        for (;;)
        {
            unsigned int subkey_options = options;
            if (i < len) subkey_options &= ~(REG_OPTION_CREATE_LINK | REG_OPTION_OPEN_LINK);
            nameW.Buffer = (WCHAR *)name + pos;
            nameW.Length = (i - pos) * sizeof(WCHAR);
            status = NtCreateKey(&ret, MAXIMUM_ALLOWED, &attr, 0, NULL, subkey_options, disposition);

            if (attr.RootDirectory != root) NtClose(attr.RootDirectory);
            if (!NT_SUCCESS(status)) return 0;
            if (i == len) break;
            attr.RootDirectory = ret;
            while (i < len && name[i] == '\\') i++;
            pos = i;
            while (i < len && name[i] != '\\') i++;
        }
    }
    return ret;
}


HKEY reg_create_ascii_key(HKEY root, const char *name, DWORD options, DWORD *disposition)
{
    WCHAR buf[256];
    return reg_create_key(root, buf, asciiz_to_unicode(buf, name) - sizeof(WCHAR),
                          options, disposition);
}


BOOL reg_delete_tree(HKEY parent, const WCHAR *name, ULONG name_len)
{
    char buffer[4096];
    KEY_NODE_INFORMATION *key_info = (KEY_NODE_INFORMATION *)buffer;
    DWORD size;
    HKEY key;
    BOOL ret = TRUE;

    if (!(key = reg_open_key(parent, name, name_len))) return FALSE;

    while (ret && !NtEnumerateKey(key, 0, KeyNodeInformation, key_info, sizeof(buffer), &size))
        ret = reg_delete_tree(key, key_info->Name, key_info->NameLength);

    if (ret) ret = !NtDeleteKey(key);
    NtClose(key);
    return ret;
}


ULONG query_reg_value(HKEY hkey, const WCHAR *name, KEY_VALUE_PARTIAL_INFORMATION *info, ULONG size)
{
    UNICODE_STRING str;

    RtlInitUnicodeString(&str, name);
    if (NtQueryValueKey(hkey, &str, KeyValuePartialInformation, info, size, &size))
        return 0;

    return size - FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data);
}


/***********************************************************************
 *              get_config_key
 *
 * Get a config key from either the app-specific or the default config
 */
static inline DWORD get_config_key(HKEY defkey, HKEY appkey, const char *name,
                                   WCHAR *buffer, DWORD size)
{
    WCHAR nameW[128];
    char buf[2048];
    KEY_VALUE_PARTIAL_INFORMATION *info = (void *)buf;

    asciiz_to_unicode(nameW, name);

    if (appkey && query_reg_value(appkey, nameW, info, sizeof(buf)))
    {
        size = min(info->DataLength, size - sizeof(WCHAR));
        memcpy(buffer, info->Data, size);
        buffer[size / sizeof(WCHAR)] = 0;
        return 0;
    }

    if (defkey && query_reg_value(defkey, nameW, info, sizeof(buf)))
    {
        size = min(info->DataLength, size - sizeof(WCHAR));
        memcpy(buffer, info->Data, size);
        buffer[size / sizeof(WCHAR)] = 0;
        return 0;
    }

    return ERROR_FILE_NOT_FOUND;
}


/***********************************************************************
 *              setup_options
 *
 * Set up the Mac driver options.
 */
static void setup_options(void)
{
    static const WCHAR macdriverW[] = {'\\','M','a','c',' ','D','r','i','v','e','r',0};
    WCHAR buffer[MAX_PATH + 16], *p, *appname;
    HKEY hkey, appkey = 0;
    DWORD len;

    /* @@ Wine registry key: HKCU\Software\Wine\Mac Driver */
    hkey = open_hkcu_key("Software\\Wine\\Mac Driver");

    /* open the app-specific key */

    appname = NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer;
    if ((p = wcsrchr(appname, '/'))) appname = p + 1;
    if ((p = wcsrchr(appname, '\\'))) appname = p + 1;
    len = lstrlenW(appname);

    if (len && len < MAX_PATH)
    {
        HKEY tmpkey;
        memcpy(buffer, appname, len * sizeof(WCHAR));
        memcpy(buffer + len, macdriverW, sizeof(macdriverW));
        /* @@ Wine registry key: HKCU\Software\Wine\AppDefaults\app.exe\Mac Driver */
        if ((tmpkey = open_hkcu_key("Software\\Wine\\AppDefaults")))
        {
            appkey = reg_open_key(tmpkey, buffer, lstrlenW(buffer) * sizeof(WCHAR));
            NtClose(tmpkey);
        }
    }

    if (!get_config_key(hkey, appkey, "WindowsFloatWhenInactive", buffer, sizeof(buffer)))
    {
        static const WCHAR noneW[] = {'n','o','n','e',0};
        static const WCHAR allW[] = {'a','l','l',0};
        if (!wcscmp(buffer, noneW))
            topmost_float_inactive = TOPMOST_FLOAT_INACTIVE_NONE;
        else if (!wcscmp(buffer, allW))
            topmost_float_inactive = TOPMOST_FLOAT_INACTIVE_ALL;
        else
            topmost_float_inactive = TOPMOST_FLOAT_INACTIVE_NONFULLSCREEN;
    }

    if (!get_config_key(hkey, appkey, "CaptureDisplaysForFullscreen", buffer, sizeof(buffer)))
        capture_displays_for_fullscreen = IS_OPTION_TRUE(buffer[0]);


    if (!get_config_key(hkey, appkey, "AllowVerticalSync", buffer, sizeof(buffer)))
        allow_vsync = IS_OPTION_TRUE(buffer[0]);

    if (!get_config_key(hkey, appkey, "AllowSetGamma", buffer, sizeof(buffer)))
        allow_set_gamma = IS_OPTION_TRUE(buffer[0]);

    /* CrossOver Hack 10912: Mac Edit menu */
    if (!get_config_key(hkey, appkey, "EditMenu", buffer, sizeof(buffer)))
    {
        static const WCHAR messageW[] = {'m','e','s','s','a','g','e',0};
        static const WCHAR keyW[] = {'k','e','y',0};
        if (!wcscmp(buffer, messageW))
            mac_edit_menu = MAC_EDIT_MENU_BY_MESSAGE;
        else if (!wcscmp(buffer, keyW))
            mac_edit_menu = MAC_EDIT_MENU_BY_KEY;
        else
            mac_edit_menu = MAC_EDIT_MENU_DISABLED;
    }
    if (!get_config_key(hkey, appkey, "LeftOptionIsAlt", buffer, sizeof(buffer)))
        left_option_is_alt = IS_OPTION_TRUE(buffer[0]);
    if (!get_config_key(hkey, appkey, "RightOptionIsAlt", buffer, sizeof(buffer)))
        right_option_is_alt = IS_OPTION_TRUE(buffer[0]);

    if (!get_config_key(hkey, appkey, "LeftCommandIsCtrl", buffer, sizeof(buffer)))
        left_command_is_ctrl = IS_OPTION_TRUE(buffer[0]);
    if (!get_config_key(hkey, appkey, "RightCommandIsCtrl", buffer, sizeof(buffer)))
        right_command_is_ctrl = IS_OPTION_TRUE(buffer[0]);

    if (left_command_is_ctrl && right_command_is_ctrl && !left_option_is_alt && !right_option_is_alt)
        WARN("Both Command keys have been mapped to Control. There is no way to "
             "send an Alt key to Windows applications. Consider enabling "
             "LeftOptionIsAlt or RightOptionIsAlt.\n");

    if (!get_config_key(hkey, appkey, "AllowSoftwareRendering", buffer, sizeof(buffer)))
        allow_software_rendering = IS_OPTION_TRUE(buffer[0]);

    if (!get_config_key(hkey, appkey, "AllowImmovableWindows", buffer, sizeof(buffer)))
        allow_immovable_windows = IS_OPTION_TRUE(buffer[0]);

    if (!get_config_key(hkey, appkey, "UseConfinementCursorClipping", buffer, sizeof(buffer)))
        use_confinement_cursor_clipping = IS_OPTION_TRUE(buffer[0]);

    if (!get_config_key(hkey, appkey, "CursorClippingLocksWindows", buffer, sizeof(buffer)))
        cursor_clipping_locks_windows = IS_OPTION_TRUE(buffer[0]);

    if (!get_config_key(hkey, appkey, "UsePreciseScrolling", buffer, sizeof(buffer)))
        use_precise_scrolling = IS_OPTION_TRUE(buffer[0]);

    if (!get_config_key(hkey, appkey, "OpenGLSurfaceMode", buffer, sizeof(buffer)))
    {
        static const WCHAR transparentW[] = {'t','r','a','n','s','p','a','r','e','n','t',0};
        static const WCHAR behindW[] = {'b','e','h','i','n','d',0};
        if (!wcscmp(buffer, transparentW))
            gl_surface_mode = GL_SURFACE_IN_FRONT_TRANSPARENT;
        else if (!wcscmp(buffer, behindW))
            gl_surface_mode = GL_SURFACE_BEHIND;
        else
            gl_surface_mode = GL_SURFACE_IN_FRONT_OPAQUE;
    }

    if (!get_config_key(hkey, appkey, "EnableAppNap", buffer, sizeof(buffer)))
        enable_app_nap = IS_OPTION_TRUE(buffer[0]);

    /* Don't use appkey.  The DPI and monitor sizes should be consistent for all
       processes in the prefix. */
    if (!get_config_key(hkey, NULL, "RetinaMode", buffer, sizeof(buffer)))
        retina_enabled = IS_OPTION_TRUE(buffer[0]);

    retina_on = retina_enabled;

    if (appkey) NtClose(appkey);
    if (hkey) NtClose(hkey);
}


/***********************************************************************
 *              load_strings
 */
static void load_strings(struct localized_string *str)
{
    CFMutableDictionaryRef dict;

    dict = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks,
                                     &kCFTypeDictionaryValueCallBacks);
    if (!dict)
    {
        ERR("Failed to create localized strings dictionary\n");
        return;
    }

    while (str->id)
    {
        if (str->str && str->len)
        {
            const UniChar *ptr = param_ptr(str->str);
            CFNumberRef key = CFNumberCreate(NULL, kCFNumberIntType, &str->id);
            CFStringRef value = CFStringCreateWithCharacters(NULL, ptr, str->len);
            if (key && value)
                CFDictionarySetValue(dict, key, value);
            else
                ERR("Failed to add string ID 0x%04x %s\n", str->id, debugstr_wn(ptr, str->len));
        }
        else
            ERR("Failed to load string ID 0x%04x\n", str->id);
        str++;
    }

    localized_strings = dict;
}


/* MacRunner 2026-07-29 (HK E2E lane): the init body, split out of macdrv_init so the
 * unix side can run it WITHOUT the PE.
 *
 * Measured across every HK run of 2026-07-29 (20 run dirs under
 * reports/phase4-hollow-knight/laneA-*): in Hollow Knight's process
 * stage=macdrv_init_entry = 0 AND stage=wow64_init_entry = 0 AND
 * stage=dllmain_attach = 0 -- the PE-side MACDRV_CALL(init) never arrives, so none of
 * this ever ran there.  The SAME runs show winemac.so demonstrably ALIVE in that
 * process: macrunner-get-win-data, macrunner-winrealize: d3d_on_demand and
 * stage=create_cocoa_window all print with HK's unix pid, because DXMT reaches
 * winemac.so directly through the exported d3dmetal `macdrv_functions` table
 * (d3dmetal.c:424), which needs no unixlib call and no DllMain.
 *
 * So the driver is not missing from the process -- only its initialisation is.  This
 * function is that initialisation, callable from the unix side, and macdrv_process_selfinit()
 * below drives it from the first d3dmetal entry HK actually reaches.
 *
 * `strings` may be NULL (the self-init path has no PE to LoadStringW from); the Cocoa
 * menu builder falls back to built-in English titles, see WineLocalizedString(). */
static pthread_mutex_t macdrv_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static BOOL macdrv_process_initialised;

static NTSTATUS macdrv_init_core(struct localized_string *strings, const char *origin)
{
    SessionAttributeBits attributes;
    OSStatus status;

    pthread_mutex_lock(&macdrv_init_mutex);
    if (macdrv_process_initialised)
    {
        pthread_mutex_unlock(&macdrv_init_mutex);
        fprintf(stderr, "macrunner-ui-input: stage=macdrv_init_core_already pid=%d origin=%s\n",
                getpid(), origin);
        fflush(stderr);
        return STATUS_SUCCESS;
    }

    status = SessionGetInfo(callerSecuritySession, NULL, &attributes);
    fprintf(stderr, "macrunner-ui-input: stage=macdrv_init_session pid=%d status=%d attrs=0x%x graphic=%d origin=%s\n",
            getpid(), (int)status, (unsigned int)attributes,
            (int)((status == noErr) && (attributes & sessionHasGraphicAccess) ? 1 : 0), origin);
    fflush(stderr);
    if (status != noErr || !(attributes & sessionHasGraphicAccess))
    {
        pthread_mutex_unlock(&macdrv_init_mutex);
        fprintf(stderr, "macrunner-ui-input: stage=macdrv_init_no_graphic_access pid=%d — "
                "driver NOT initialised, Cocoa app never started, input impossible\n", getpid());
        fflush(stderr);
        return STATUS_UNSUCCESSFUL;
    }

    init_win_context();
    setup_options();
    if (strings) load_strings(strings);

    macdrv_err_on = ERR_ON(macdrv);
    {
        int cocoa_rc;

        fprintf(stderr, "macrunner-ui-input: stage=macdrv_init_start_cocoa_call pid=%d origin=%s\n",
                getpid(), origin);
        fflush(stderr);
        cocoa_rc = macdrv_start_cocoa_app(NtGetTickCount());
        fprintf(stderr, "macrunner-ui-input: stage=macdrv_init_start_cocoa_ret pid=%d rc=%d\n",
                getpid(), cocoa_rc);
        fflush(stderr);
        if (cocoa_rc)
        {
            pthread_mutex_unlock(&macdrv_init_mutex);
            ERR("Failed to start Cocoa app main loop\n");
            return STATUS_UNSUCCESSFUL;
        }
    }

    init_user_driver();
    macdrv_process_initialised = TRUE;
    pthread_mutex_unlock(&macdrv_init_mutex);

    fprintf(stderr, "macrunner-ui-input: stage=macdrv_init_user_driver_set pid=%d origin=%s\n",
            getpid(), origin);
    fflush(stderr);
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              macdrv_process_selfinit
 *
 * MacRunner 2026-07-29 (HK E2E lane): bring the Mac driver up from the UNIX side,
 * for a process whose winemac.drv PE never ran its DllMain.
 *
 * A/B: MACRUNNER_MACDRV_UNIX_SELFINIT=0 restores the previous behaviour exactly
 * (this function then does nothing and the process keeps win32u's re-entrancy
 * placeholder, which is the measured 2026-07-29 baseline).
 *
 * Safe to call from any thread and any number of times: macdrv_init_core() is
 * once-only under a mutex, and macdrv_start_cocoa_app() schedules run_cocoa_app on
 * the MAIN thread's run loop and waits at most 5 s -- it is explicitly designed to be
 * called from a secondary thread, and HK's process main thread is parked in the bare
 * CFRunLoopRun of ntdll's loader, which is exactly the state it expects.
 */
/* MacRunner 2026-07-29 (HK E2E lane): OPTIONAL DEFERRAL of the self-init above.
 *
 * The measurement that motivates it, conditioned on wall-clock >=600 s so that short
 * diagnostic probes cannot manufacture failures: self-init ABSENT -> 14/16 runs reach
 * `Loaded Objects now`, MonoManager->UnloadTime max 237.7 s, none over 300 s. Self-init
 * PRESENT -> 0/8, with a heavy tail (784.1 s and 928.5 s observed). The medians are
 * unchanged in both eras, so this is not a uniform slowdown -- a subset of runs stalls
 * 2-4x -- and every one of those stalls sits inside the Mono scene-load window that
 * self-init lands in the middle of (it fires at ~+140 s, the window is ~+54 s to ~+280 s).
 *
 * Both halves of this lane's objective have been demonstrated, never together: keys reach
 * the guest when HK has a real driver, and the menu loads when it has none. Deferring the
 * install past the scene-load window is the one intervention that can satisfy both, and it
 * wins under either reading of the cost -- if the cost is specific to the loading window,
 * deferral removes it; if the driver is simply expensive while Mono is loading, deferral
 * moves that expense to after the menu, which is exactly when this lane needs input.
 *
 * MACRUNNER_MACDRV_SELFINIT_DELAY_MS=<n> withholds the driver for n ms measured from the
 * FIRST call, i.e. from the first winemac.so entry point HK's process reaches. Unset or 0
 * is the current behaviour, byte-for-byte: the very first call initialises inline.
 *
 * Deferral only has an effect if something calls back in after the delay, so the callers in
 * d3dmetal.c retry from the recurring DXMT entry points as well as the one-shot swapchain
 * path. Deliberately NOT a timer thread: a bare pthread has no Wine TEB, and a TEB-less
 * thread reaching win32u is the documented way into the fault router that has already cost
 * these lanes six iterations (signal_arm64.c:1454). Every caller here is a Wine thread. */
static BOOL macdrv_selfinit_delay_elapsed(void)
{
    static const char *cached_env;
    static DWORD first_tick, delay_ms;
    static BOOL resolved;
    DWORD now = NtGetTickCount();

    if (!resolved)
    {
        resolved = TRUE;
        cached_env = getenv("MACRUNNER_MACDRV_SELFINIT_DELAY_MS");
        delay_ms = (cached_env && cached_env[0]) ? (DWORD)atoi(cached_env) : 0;
        first_tick = now;
        if (delay_ms)
        {
            fprintf(stderr, "macrunner-ui-input: stage=macdrv_selfinit_deferred pid=%d delay_ms=%u — "
                    "driver withheld until the scene-load window has passed\n",
                    getpid(), (unsigned int)delay_ms);
            fflush(stderr);
        }
    }
    if (!delay_ms) return TRUE;
    /* NtGetTickCount wraps every ~49.7 days; the unsigned difference stays correct across it. */
    if ((DWORD)(now - first_tick) >= delay_ms) return TRUE;

    /* Count the declines and print on a coarse ladder.
     *
     * Without this, the first deferred run could not distinguish two very different failures:
     * the retry sites are never called after the menu, or they are called and the run simply
     * did not live long enough (it got 38 s of post-menu life before teardown). Those need
     * opposite fixes -- widen the retry set, versus give the run more time -- and a zero on
     * `macdrv_selfinit_entry` is equally consistent with both.
     *
     * Powers-of-four ladder so a hot render path cannot turn this into a log flood, with the
     * elapsed time on every line so the LAST one before teardown dates the final retry. */
    {
        static unsigned long declines, next_report = 1;

        if (++declines >= next_report)
        {
            next_report *= 4;
            fprintf(stderr, "macrunner-ui-input: stage=macdrv_selfinit_waiting pid=%d declines=%lu "
                    "elapsed_ms=%u delay_ms=%u\n", getpid(), declines,
                    (unsigned int)(DWORD)(now - first_tick), (unsigned int)delay_ms);
            fflush(stderr);
        }
    }
    return FALSE;
}

/* DECLSPEC_EXPORT: winemac.so exports exactly three symbols, and win32u's placeholder
 * driver needs to reach this one by dlsym. See nulldrv_ProcessEvents() in
 * win32u/driver.c for why the call has to come from there rather than from DXMT. */
DECLSPEC_EXPORT BOOL macdrv_process_selfinit(void)
{
    static BOOL announced;   /* a duplicated log line under a race is harmless */
    static const char *gate;
    static BOOL gate_resolved;

    /* Ordered so the common case is a single BOOL read. This is now called from
     * nulldrv_ProcessEvents(), i.e. on every message-pump wait of every placeholder
     * process, so the getenv() that used to run before this check would have been an
     * O(n) environment walk per pump. */
    if (macdrv_process_initialised) return TRUE;
    if (!gate_resolved)
    {
        gate_resolved = TRUE;
        gate = getenv("MACRUNNER_MACDRV_UNIX_SELFINIT");
    }
    if (gate && gate[0] == '0')
    {
        if (!announced)
        {
            announced = TRUE;
            fprintf(stderr, "macrunner-ui-input: stage=macdrv_selfinit_disabled pid=%d\n", getpid());
            fflush(stderr);
        }
        return FALSE;
    }

    /* Checked before the entry announcement so a deferred run's log says "waiting", not
     * "initialising", at the moment it declines -- this lane has twice read an announcement
     * as proof that the thing it announces actually happened. */
    if (!macdrv_selfinit_delay_elapsed()) return FALSE;

    if (!announced)
    {
        announced = TRUE;
        fprintf(stderr, "macrunner-ui-input: stage=macdrv_selfinit_entry pid=%d tid=%llu — "
                "no PE DllMain ran in this process, initialising the driver from the unix side\n",
                getpid(), trace_ui_input_tid());
        fflush(stderr);
    }

    return !macdrv_init_core(NULL, "selfinit");
}


/***********************************************************************
 *              macdrv_init
 */
static NTSTATUS macdrv_init(void *arg)
{
    struct init_params *params = arg;

    /* MacRunner 2026-07-28 (HK input) — UNGATED, a handful of lines once per
     * process.  Measured on live HK pid 13773 (winemac.so UUID-verified against
     * the mapped image): app_icon_callback/app_quit_request_callback/both reg
     * callbacks were ALL NULL, and no run_cocoa_app source was registered on the
     * main run loop, while a real visible WineWindow existed.  dllmain.c:486
     * always passes &macdrv_app_icon, so a NULL static means this function never
     * executed its first statement.  Every rung the input ladder measured lives
     * DOWNSTREAM of this edge, so its silence was uninterpretable.  Trace the
     * whole init chain so "did not run" can never again be confused with
     * "not logged". */
    fprintf(stderr, "macrunner-ui-input: stage=macdrv_init_entry pid=%d icon_cb=%p strings=%p\n",
            getpid(), (void *)(UINT_PTR)params->app_icon_callback, params->strings);
    fflush(stderr);

    app_icon_callback = params->app_icon_callback;
    app_quit_request_callback = params->app_quit_request_callback;
    regcreateopenkeyexa_callback = params->regcreateopenkeyexa_callback;
    regqueryvalueexa_callback = params->regqueryvalueexa_callback;
    regsetvalueexa_callback = params->regsetvalueexa_callback;

    /* The callbacks above are assigned unconditionally, before the once-guard inside
     * macdrv_init_core(): if the unix self-init got here first it left them at 0, and
     * a PE that later does arrive must still be able to install the real ones. */
    return macdrv_init_core(params->strings, "dllmain");
}


/***********************************************************************
 *              ThreadDetach   (MACDRV.@)
 */
void macdrv_ThreadDetach(void)
{
    struct macdrv_thread_data *data = macdrv_thread_data();

    if (data)
    {
        if (trace_ui_input_enabled())
        {
            fprintf(stderr,
                    "macrunner-ui-input: stage=macdrv_ThreadDetach pid=%d native_tid=%llu wine_tid=%lx queue=%p fd=%d\n",
                    getpid(), trace_ui_input_tid(), (unsigned long)GetCurrentThreadId(),
                    data->queue, data->queue ? macdrv_get_event_queue_fd(data->queue) : -1);
            fflush(stderr);
        }
        macdrv_destroy_event_queue(data->queue);
        if (data->keyboard_layout_uchr)
            CFRelease(data->keyboard_layout_uchr);
        free(data);
        /* clear data in case we get re-entered from user32 before the thread is truly dead */
        NtUserGetThreadInfo()->driver_data = 0;
    }
}


/***********************************************************************
 *              set_queue_display_fd
 *
 * Store the event queue fd into the message queue
 */
static void set_queue_display_fd(int fd)
{
    HANDLE handle;
    int ret;

    if (wine_server_fd_to_handle(fd, GENERIC_READ | SYNCHRONIZE, 0, &handle))
    {
        MESSAGE("macdrv: Can't allocate handle for event queue fd\n");
        NtTerminateProcess(0, 1);
    }
    SERVER_START_REQ(set_queue_fd)
    {
        req->handle = wine_server_obj_handle(handle);
        ret = wine_server_call(req);
    }
    SERVER_END_REQ;
    if (trace_ui_input_enabled())
    {
        fprintf(stderr,
                "macrunner-ui-input: stage=set_queue_display_fd pid=%d tid=%llu fd=%d handle=%p ret=%d\n",
                getpid(), trace_ui_input_tid(), fd, handle, ret);
        fflush(stderr);
    }
    if (ret)
    {
        MESSAGE("macdrv: Can't store handle for event queue fd\n");
        NtTerminateProcess(0, 1);
    }
    NtClose(handle);
}


/***********************************************************************
 *              macdrv_init_thread_data
 */
struct macdrv_thread_data *macdrv_init_thread_data(void)
{
    struct macdrv_thread_data *data = macdrv_thread_data();
    TISInputSourceRef input_source;

    if (data) return data;

    if (!(data = calloc(1, sizeof(*data))))
    {
        ERR("could not create data\n");
        NtTerminateProcess(0, 1);
    }

    if (!(data->queue = macdrv_create_event_queue(macdrv_handle_event)))
    {
        ERR("macdrv: Can't create event queue.\n");
        NtTerminateProcess(0, 1);
    }

    macdrv_get_input_source_info(&data->keyboard_layout_uchr, &data->keyboard_type, &data->iso_keyboard, &input_source);
    data->active_keyboard_layout = macdrv_get_hkl_from_source(input_source);
    CFRelease(input_source);
    macdrv_compute_keyboard_layout(data);

    set_queue_display_fd(macdrv_get_event_queue_fd(data->queue));
    NtUserGetThreadInfo()->driver_data = (UINT_PTR)data;
    if (trace_ui_input_enabled())
    {
        fprintf(stderr,
                "macrunner-ui-input: stage=macdrv_init_thread_data pid=%d native_tid=%llu wine_tid=%lx queue=%p fd=%d\n",
                getpid(), trace_ui_input_tid(), (unsigned long)GetCurrentThreadId(),
                data->queue, macdrv_get_event_queue_fd(data->queue));
        fflush(stderr);
    }

    NtUserActivateKeyboardLayout(data->active_keyboard_layout, 0);
    return data;
}


/***********************************************************************
 *              SystemParametersInfo (MACDRV.@)
 */
BOOL macdrv_SystemParametersInfo( UINT action, UINT int_param, void *ptr_param, UINT flags )
{
    switch (action)
    {
    case SPI_GETSCREENSAVEACTIVE:
        if (ptr_param)
        {
            CFDictionaryRef assertionStates;
            IOReturn status = IOPMCopyAssertionsStatus(&assertionStates);
            if (status == kIOReturnSuccess)
            {
                CFNumberRef count = CFDictionaryGetValue(assertionStates, kIOPMAssertionTypeNoDisplaySleep);
                CFNumberRef count2 = CFDictionaryGetValue(assertionStates, kIOPMAssertionTypePreventUserIdleDisplaySleep);
                long longCount = 0, longCount2 = 0;

                if (count)
                    CFNumberGetValue(count, kCFNumberLongType, &longCount);
                if (count2)
                    CFNumberGetValue(count2, kCFNumberLongType, &longCount2);

                *(BOOL *)ptr_param = !longCount && !longCount2;
                CFRelease(assertionStates);
            }
            else
            {
                WARN("Could not determine screen saver state, error code %d\n", status);
                *(BOOL *)ptr_param = TRUE;
            }
            return TRUE;
        }
        break;

    case SPI_SETSCREENSAVEACTIVE:
        {
            static IOPMAssertionID powerAssertion = kIOPMNullAssertionID;
            if (int_param)
            {
                if (powerAssertion != kIOPMNullAssertionID)
                {
                    IOPMAssertionRelease(powerAssertion);
                    powerAssertion = kIOPMNullAssertionID;
                }
            }
            else if (powerAssertion == kIOPMNullAssertionID)
            {
                IOPMAssertionCreateWithName( kIOPMAssertionTypePreventUserIdleDisplaySleep, kIOPMAssertionLevelOn,
                                             CFSTR("Wine Process requesting no screen saver"),
                                             &powerAssertion);
            }
        }
        break;
    }
    return FALSE;
}

/* CW Hack 22310 */
NTSTATUS macdrv_SetCurrentProcessExplicitAppUserModelID(const WCHAR *aumid)
{
    if (!macdrv_set_current_process_explicit_app_user_model_id(aumid, lstrlenW(aumid)))
        return STATUS_INVALID_PARAMETER;

    return 0;
}

/* CW Hack 22310 */
NTSTATUS macdrv_GetCurrentProcessExplicitAppUserModelID(WCHAR *buffer, INT size)
{
    if (!buffer) return STATUS_INVALID_PARAMETER;

    if (!macdrv_get_current_process_explicit_app_user_model_id(buffer, size))
        return STATUS_BUFFER_TOO_SMALL;

    return 0;
}

static NTSTATUS macdrv_quit_result(void *arg)
{
    struct quit_result_params *params = arg;
    macdrv_quit_reply(params->result);
    return 0;
}


const unixlib_entry_t __wine_unix_call_funcs[] =
{
    macdrv_init,
    macdrv_quit_result,
};

C_ASSERT( ARRAYSIZE(__wine_unix_call_funcs) == unix_funcs_count );

#ifdef _WIN64

static void *wow64_ptr_from_args( const void *args, ULONG ptr )
{
    ULONG_PTR base = (ULONG_PTR)args & ~(ULONG_PTR)0xffffffff;

    return ptr ? (void *)(base | ptr) : NULL;
}

static struct localized_string *wow64_translate_strings( const void *args, ULONG ptr )
{
    const struct localized_string *src = wow64_ptr_from_args( args, ptr );
    struct localized_string *dst;
    unsigned int i, count;

    if (!src) return NULL;
    for (count = 0; src[count].id && count < 256; count++) {}
    if (src[count].id) return NULL;
    if (!(dst = calloc( count + 1, sizeof(*dst) ))) return NULL;

    for (i = 0; i < count; i++)
    {
        dst[i] = src[i];
        dst[i].str = (UINT_PTR)wow64_ptr_from_args( args, (ULONG)src[i].str );
    }
    return dst;
}

static NTSTATUS wow64_init(void *arg)
{
    struct
    {
        ULONG strings;
        UINT64 app_icon_callback;
        UINT64 app_quit_request_callback;
        UINT64 regcreateopenkeyexa_callback;
        UINT64 regqueryvalueexa_callback;
        UINT64 regsetvalueexa_callback;
    } *params32 = arg;
    struct init_params params;
    NTSTATUS status;

    /* MacRunner 2026-07-29 (HK E2E lane) — UNGATED, at most 3 lines per process.
     *
     * Measured on live HK (laneA-HK-E2E-05-a1, pid 7057): the game process has
     * aarch64-unix/winemac.so MAPPED but x86_64-windows/winemac.drv NOT mapped, and
     * NO stage=macdrv_init_entry anywhere in the run log — while a DIFFERENT process
     * (unix 7156 = wine 0020, the explorer-class one) ran the whole init chain and
     * created 4 Cocoa windows.  HK is an x86_64 PE, so its MACDRV_CALL(init) lands
     * HERE, in wow64_init, not in macdrv_init directly — and this function can return
     * BEFORE macdrv_init on a strings-translation failure, which would produce exactly
     * that signature: winemac.so mapped by __wine_init_unix_call, process_attach
     * returning FALSE, the PE unmapped again, and macdrv_init never entered.
     * dllmain.c's PE-side trace cannot settle this on its own because both of its
     * paths are dead in these runs (STD_ERROR_HANDLE is NULL in a GUI process, and
     * ERR_(winediag) is silenced by WINEDEBUG=-all), so trace it from the unix side,
     * where plain fprintf(stderr) demonstrably reaches run.log. */
    fprintf(stderr, "macrunner-ui-input: stage=wow64_init_entry pid=%d strings32=%08x\n",
            getpid(), (unsigned int)params32->strings);
    fflush(stderr);

    /* MacRunner 2026-08-13, лейн ЛЕСТНИЦА, итерация 818 — ОТСУТСТВИЕ строк НЕ ЕСТЬ ОТКАЗ.
     *
     * Здесь стояла стена ступени 1. `wow64_translate_strings` отдаёт NULL в ДВУХ разных
     * случаях: «переводить нечего» (указатель 0) и «перевести не смог». Проверка их не
     * различала, поэтому штатный NULL читался как отказ.
     *
     * Замерено на живом прогоне (d822-З2): i386-сторона печатает
     * `wow64_init_entry strings32=00000000` — то есть строки ПРОПУЩЕНЫ намеренно
     * (`macdrv_pe_skip_strings`, лекарство от зависания DllMain), — и следом
     * `wow64_init_strings_FAILED`, `macdrv_init` не вызван. Дальше по цепочке:
     * `LdrLoadDll winemac.drv status=c0000142`, USER32 остаётся без драйвера, окна нет.
     *
     * Что доказывает, что дело именно в различении, а не в самих строках: на 64-битном
     * пути ровно тот же NULL проходит штатно — `macdrv_init_entry ... strings=0x0`. */
    if (!params32->strings) params.strings = NULL;
    else if (!(params.strings = wow64_translate_strings( arg, params32->strings )))
    {
        fprintf(stderr, "macrunner-ui-input: stage=wow64_init_strings_FAILED pid=%d — "
                "returning STATUS_ACCESS_VIOLATION, macdrv_init NEVER CALLED\n", getpid());
        fflush(stderr);
        return STATUS_ACCESS_VIOLATION;
    }
    fprintf(stderr, "macrunner-ui-input: stage=wow64_init_strings_ok pid=%d strings32=%08x "
            "перевод=%p\n", getpid(), (unsigned int)params32->strings, params.strings);
    fflush(stderr);
    params.app_icon_callback = params32->app_icon_callback;
    params.app_quit_request_callback = params32->app_quit_request_callback;
    params.regcreateopenkeyexa_callback = params32->regcreateopenkeyexa_callback;
    params.regqueryvalueexa_callback = params32->regqueryvalueexa_callback;
    params.regsetvalueexa_callback = params32->regsetvalueexa_callback;
    status = macdrv_init(&params);
    free(params.strings);
    return status;
}

const unixlib_entry_t __wine_unix_call_wow64_funcs[] =
{
    wow64_init,
    macdrv_quit_result,
};

C_ASSERT( ARRAYSIZE(__wine_unix_call_wow64_funcs) == unix_funcs_count );

#endif /* _WIN64 */
