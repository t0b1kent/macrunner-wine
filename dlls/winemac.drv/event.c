/*
 * MACDRV event driver
 *
 * Copyright 1993 Alexandre Julliard
 *           1999 Noel Borthwick
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

#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "macdrv.h"
#include "oleidl.h"

WINE_DEFAULT_DEBUG_CHANNEL(event);
WINE_DECLARE_DEBUG_CHANNEL(imm);

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

/* MacRunner: bounded ProcessEvents drain probe.
 *
 * Why this exists as a SEPARATE, bounded probe rather than reusing
 * ProcessEvents_enter/_exit above: those two fprintf+fflush on EVERY call, i.e. at
 * least twice per frame in a Unity message loop, which is a multi-hundred-MB log and
 * a real slowdown on a boot that is already throughput-starved.  So the broad gate can
 * never be turned on for a full-length Hollow Knight run — and that is exactly the run
 * where the question has to be answered.
 *
 * The question: cocoa_window.m's postKeyEvent: puts the key on a SPECIFIC queue (it
 * prints `postKey_posted … queue=%p`), and only the thread that owns that queue will
 * ever dequeue it.  HK's window is realized on demand from DXMT's get_win_data, i.e.
 * on whichever thread first asks for it — not necessarily the thread that pumps
 * messages.  "Nobody drains that queue" and "the guest never pumps at all" and "it was
 * drained but the key was never posted" are three different bugs with three different
 * fixes, and until now they were indistinguishable, because macdrv_key_event=0 is
 * consistent with all three.
 *
 * Bounding: one line per (tid, queue) pair on first sight, then at log-spaced call
 * counts, so a full boot costs ~7 lines per pumping thread.  Key dequeues are printed
 * unconditionally because they are rare and are the whole point. */
static BOOL macrunner_drain_probe_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        const char *value = getenv("MACRUNNER_TRACE_WINEMAC_DRAIN");

        if (value) enabled = value[0] && value[0] != '0';
        else enabled = getenv("MACRUNNER_TRACE_WINEMAC_KEYS") != NULL ||
                       getenv("MACRUNNER_TRACE_WINEMAC_INPUT") != NULL;
    }
    return enabled;
}

/* MacRunner 2026-07-29 (HK master lane iter 9) — call-count spacing alone CANNOT answer the
 * question this probe was built for, so it now also buckets by TIME and reports the mask.
 *
 * Measured on the two runs that carry the whole ladder (HK-E2E-24-WIN32UHOOK-t1 and
 * BLACKFRAME-DRAWTRACE): keys reach -[WineWindow postKeyEvent:] and are posted to the queue
 * (postKey_posted 18 and 15) on exactly the queue this drain probe shows being drained by a
 * live thread of the same pid -- and ProcessEvents_key_dequeued is 0, macdrv_key_event is 0.
 * So the key is on the right queue, the owning thread exists, and nothing ever copies it out.
 *
 * Exactly two things do that, and the old probe could not tell them apart:
 *   (a) the thread stops calling macdrv_ProcessEvents before the key is posted;
 *   (b) it keeps calling, but with event_mask == 0 -- either because the caller's mask has no
 *       QS_KEY, or because the nested-event guard below zeroes event_mask wholesale whenever
 *       data->current_event is set.  In case (b) the while loop copies nothing, count stays 0,
 *       and the log looks identical to (a).
 * Log spacing hid this: BLACKFRAME printed calls=1/10/100 at t=821.8/831.8/837.8 and then
 * nothing, because reaching calls=1000 would have taken longer than the run -- while the first
 * key was posted at t=847.2.  "Silent because stopped" and "silent because still climbing to
 * the next decade" are not distinguishable from that.
 *
 * A 10-second bucket makes an ALIVE pump visible at ~1 line per thread per 10 s (about 110
 * lines across a full boot -- same order as the existing spacing, nowhere near per-frame), and
 * mask/event_mask/current name (b) directly.  Still behind the same gate. */
#define MACRUNNER_DRAIN_BUCKET_SECS 10

static void macrunner_note_drain(void *queue, int fd, int count, DWORD mask,
                                 unsigned long long event_mask, const void *current)
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static struct { unsigned long long tid; void *queue; unsigned long long calls;
                    long long bucket; } seen[64];
    static unsigned int used;
    unsigned long long tid = trace_ui_input_tid();
    unsigned long long calls;
    BOOL first = FALSE, new_bucket = FALSE;
    long long bucket = 0;
    struct timespec ts;
    unsigned int i;

    if (!macrunner_drain_probe_enabled()) return;

    if (!clock_gettime(CLOCK_MONOTONIC, &ts))
        bucket = (long long)ts.tv_sec / MACRUNNER_DRAIN_BUCKET_SECS;

    pthread_mutex_lock(&lock);
    for (i = 0; i < used; i++)
        if (seen[i].tid == tid && seen[i].queue == queue) break;
    if (i == used)
    {
        if (used >= 64) { pthread_mutex_unlock(&lock); return; }
        seen[used].tid = tid;
        seen[used].queue = queue;
        seen[used].calls = 0;
        seen[used].bucket = bucket - 1;
        used++;
        first = TRUE;
    }
    calls = ++seen[i].calls;
    if (seen[i].bucket != bucket)
    {
        seen[i].bucket = bucket;
        new_bucket = TRUE;
    }
    pthread_mutex_unlock(&lock);

    if (first || new_bucket || calls == 10 || calls == 100 || calls == 1000 ||
        calls == 10000 || calls == 100000 || calls == 1000000)
    {
        fprintf(stderr,
                "macrunner-ui-input: stage=ProcessEvents_drain pid=%d tid=%llu queue=%p fd=%d "
                "calls=%llu handled=%d mask=0x%x event_mask=0x%llx current=%p qs_key=%d\n",
                getpid(), tid, queue, fd, calls, count, (unsigned int)mask, event_mask, current,
                (int)((mask & QS_KEY) != 0));
        fflush(stderr);
    }
}

static BOOL return_route_observer_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        const char *value = getenv("MACRUNNER_HB_RETURN_ROUTE_OBSERVER");
        enabled = value && value[0] && value[0] != '0';
    }
    return enabled;
}

BOOL macdrv_return_route_focus_milestones_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        const char *value = getenv("MACRUNNER_HB_RETURN_ROUTE_FOCUS_MILESTONES");
        enabled = value && value[0] && value[0] != '0';
    }
    return enabled;
}

static unsigned int return_route_observer_limit(void)
{
    static unsigned int limit;

    if (!limit)
    {
        const char *value = getenv("MACRUNNER_HB_RETURN_ROUTE_OBSERVER_MAX");
        char *end;
        unsigned long parsed = value ? strtoul(value, &end, 10) : 0;

        limit = value && end != value && !*end && parsed && parsed <= 256 ? parsed : 64;
    }
    return limit;
}

void macdrv_return_route_observe(const char *stage, void *hwnd, macdrv_window window,
                                 unsigned int keycode, unsigned int vkey, int pressed,
                                 unsigned int flags, unsigned int event_time)
{
    static unsigned int records;
    struct macdrv_return_route_window_state cocoa_state;
    GUITHREADINFO gui_info = { sizeof(gui_info) };
    struct timespec now;
    DWORD gui_tid = 0;
    DWORD wine_tid = 0;
    HWND foreground = NULL;
    unsigned int ordinal;
    const char *direction;

    if (!return_route_observer_enabled()) return;
    if (keycode != 36 && vkey != VK_RETURN) return;
    ordinal = __atomic_add_fetch(&records, 1, __ATOMIC_RELAXED);
    if (ordinal > return_route_observer_limit()) return;
    memset(&cocoa_state, 0, sizeof(cocoa_state));
    macdrv_get_return_route_window_state(window, &cocoa_state);
    if (pthread_main_np())
    {
        /* win32u queries from the main run-loop thread cross the arm64x
           import-thunk SIGILL routing and freeze the loop while a guest
           thread waits in _MetalLayer_setProps dispatch_sync (2026-07-20 boot
           deadlock). GUI focus/active/foreground stay zero here; the managed
           unity-selection event carries the matching Win32 focus proof.

           ★ 2026-07-29 (HK E2E lane), MEASURED, NOT DEDUCED: GetCurrentThreadId()
           belongs in this branch too, and leaving it out of it wedged Hollow Knight
           six runs out of six.  It expands to
           HandleToULong(NtCurrentTeb()->ClientId.UniqueThread) -- an imported
           NtCurrentTeb() call followed by a load at TEB+0x48 -- and the Cocoa main
           thread is NOT a Wine thread: `main -> __wine_main -> CFRunLoopRun` parks
           the process's original thread in the run loop while Wine's own threads are
           created separately, so it has no TEB and that load faults.  HyperBridge's
           fault handler then never returns
           (macrunner_hb_primary_signal_handler -> route_x64_callback_fault ->
           redirect_arm64x_hexpthk_sigill -> pc_is_x64_guest_code_module_no_lock ->
           pc_in_graphics_arm64x_x64_range -> ldr_entry_from_pc, identical PC
           0x1148c5d68 in three samples 15 minutes apart, ~107 % CPU throughout).

           Because [NSApp run] lives on that same thread, losing it kills the whole
           process: every subsequent dispatch_sync onto the main queue -- which is how
           DXMT sets Metal layer properties -- blocks forever.  Signature in the logs
           was `wine_window_keyDown keycode=36` with NO matching `postKey_posted`,
           in exactly the runs where a Return key reached the Cocoa thread; keycode
           125 (arrow) posts cleanly every time because the keycode filter above
           returns before this point.  See
           reports/phase4-hollow-knight/HK-E2E-19-STALL-SAMPLE/. */
    }
    else
    {
        wine_tid = GetCurrentThreadId();
        if (hwnd && (gui_tid = NtUserGetWindowThread(hwnd, NULL)))
            NtUserGetGUIThreadInfo(gui_tid, &gui_info);
        foreground = NtUserGetForegroundWindow();
    }
    direction = pressed < 0 ? "proof" : pressed ? "down" : "up";
    clock_gettime(CLOCK_MONOTONIC, &now);
    fprintf(stderr,
            "macrunner-return-route: stage=%s seq=%u pid=%d native_tid=%llu wine_tid=%lu "
            "hwnd=%p keycode=%u vkey=0x%x direction=%s flags=0x%x event_time=%u "
            "monotonic_ns=%llu cocoa_window_id=%llu cocoa_hwnd=%p mapping=%d "
            "foreground_hwnd=%p active_hwnd=%p focus_hwnd=%p gui_wine_tid=%lu "
            "nsapp_active=%d nswindow_key=%d nswindow_main=%d "
            "key_window_id=%llu key_window_hwnd=%p main_window_id=%llu main_window_hwnd=%p\n",
            stage, ordinal, getpid(), trace_ui_input_tid(), (unsigned long)wine_tid,
            hwnd, keycode, vkey, direction, flags, event_time,
            (unsigned long long)now.tv_sec * 1000000000ull + now.tv_nsec,
            cocoa_state.cocoa_window_id, cocoa_state.window_hwnd,
            hwnd && cocoa_state.window_hwnd == hwnd,
            foreground, gui_info.hwndActive, gui_info.hwndFocus,
            (unsigned long)gui_tid, cocoa_state.app_active, cocoa_state.window_key,
            cocoa_state.window_main, cocoa_state.key_window_id,
            cocoa_state.key_window_hwnd, cocoa_state.main_window_id,
            cocoa_state.main_window_hwnd);
    fflush(stderr);
}

pthread_mutex_t ime_composition_rect_mutex = PTHREAD_MUTEX_INITIALIZER;
CGRect ime_composition_rect;

/* return the name of an Mac event */
static const char *dbgstr_event(int type)
{
    static const char * const event_names[] = {
        "APP_ACTIVATED",
        "APP_DEACTIVATED",
        "APP_QUIT_REQUESTED",
        "CLIENT_SURFACE_PRESENTED", /* CW HACK 22435 */
        "DISPLAYS_CHANGED",
        "EDIT_MENU_COMMAND", /* CrossOver Hack 10912: Mac Edit menu */
        "HOTKEY_PRESS",
        "IM_SET_TEXT",
        "KEY_PRESS",
        "KEY_RELEASE",
        "KEYBOARD_CHANGED",
        "LOST_PASTEBOARD_OWNERSHIP",
        "MOUSE_BUTTON",
        "MOUSE_MOVED_RELATIVE",
        "MOUSE_MOVED_ABSOLUTE",
        "MOUSE_SCROLL",
        "QUERY_EVENT",
        "QUERY_EVENT_NO_PREEMPT_WAIT",
        "REASSERT_WINDOW_POSITION",
        "RELEASE_CAPTURE",
        "STATUS_ITEM_MOUSE_BUTTON",
        "STATUS_ITEM_MOUSE_MOVE",
        "WINDOW_BROUGHT_FORWARD",
        "WINDOW_CLOSE_REQUESTED",
        "WINDOW_DID_MINIMIZE",
        "WINDOW_DID_UNMINIMIZE",
        "WINDOW_DRAG_BEGIN",
        "WINDOW_DRAG_END",
        "WINDOW_FRAME_CHANGED",
        "WINDOW_GOT_FOCUS",
        "WINDOW_LOST_FOCUS",
        "WINDOW_MAXIMIZE_REQUESTED",
        "WINDOW_MINIMIZE_REQUESTED",
        "WINDOW_RESIZE_ENDED",
        "WINDOW_RESTORE_REQUESTED",
        "MACRUNNER_WINSHOW_ACTIVATE",
    };
    C_ASSERT(ARRAYSIZE(event_names) == NUM_EVENT_TYPES);

    if (0 <= type && type < NUM_EVENT_TYPES) return event_names[type];
    return wine_dbg_sprintf("Unknown event %d", type);
}


/***********************************************************************
 *              get_event_mask
 */
static macdrv_event_mask get_event_mask(DWORD mask)
{
    macdrv_event_mask event_mask = 0;

    if ((mask & QS_ALLINPUT) == QS_ALLINPUT) return -1;

    if (mask & QS_HOTKEY)
        event_mask |= event_mask_for_type(HOTKEY_PRESS);

    if (mask & QS_KEY)
    {
        /* CrossOver Hack 10912: Mac Edit menu */
        event_mask |= event_mask_for_type(EDIT_MENU_COMMAND);
        event_mask |= event_mask_for_type(KEY_PRESS);
        event_mask |= event_mask_for_type(KEY_RELEASE);
        event_mask |= event_mask_for_type(KEYBOARD_CHANGED);
    }

    if (mask & QS_MOUSEBUTTON)
    {
        event_mask |= event_mask_for_type(MOUSE_BUTTON);
        event_mask |= event_mask_for_type(MOUSE_SCROLL);
    }

    if (mask & QS_MOUSEMOVE)
    {
        event_mask |= event_mask_for_type(MOUSE_MOVED_RELATIVE);
        event_mask |= event_mask_for_type(MOUSE_MOVED_ABSOLUTE);
    }

    if (mask & QS_POSTMESSAGE)
    {
        event_mask |= event_mask_for_type(APP_ACTIVATED);
        event_mask |= event_mask_for_type(APP_DEACTIVATED);
        event_mask |= event_mask_for_type(APP_QUIT_REQUESTED);
        event_mask |= event_mask_for_type(CLIENT_SURFACE_PRESENTED); /* CW HACK 22435 */
        event_mask |= event_mask_for_type(DISPLAYS_CHANGED);
        event_mask |= event_mask_for_type(IM_SET_TEXT);
        event_mask |= event_mask_for_type(LOST_PASTEBOARD_OWNERSHIP);
        event_mask |= event_mask_for_type(STATUS_ITEM_MOUSE_BUTTON);
        event_mask |= event_mask_for_type(STATUS_ITEM_MOUSE_MOVE);
        event_mask |= event_mask_for_type(WINDOW_DID_UNMINIMIZE);
        event_mask |= event_mask_for_type(WINDOW_FRAME_CHANGED);
        event_mask |= event_mask_for_type(WINDOW_GOT_FOCUS);
        event_mask |= event_mask_for_type(WINDOW_LOST_FOCUS);
        event_mask |= event_mask_for_type(MACRUNNER_WINSHOW_ACTIVATE);
    }

    if (mask & QS_SENDMESSAGE)
    {
        event_mask |= event_mask_for_type(QUERY_EVENT);
        event_mask |= event_mask_for_type(QUERY_EVENT_NO_PREEMPT_WAIT);
        event_mask |= event_mask_for_type(REASSERT_WINDOW_POSITION);
        event_mask |= event_mask_for_type(RELEASE_CAPTURE);
        event_mask |= event_mask_for_type(WINDOW_BROUGHT_FORWARD);
        event_mask |= event_mask_for_type(WINDOW_CLOSE_REQUESTED);
        event_mask |= event_mask_for_type(WINDOW_DRAG_BEGIN);
        event_mask |= event_mask_for_type(WINDOW_DRAG_END);
        event_mask |= event_mask_for_type(WINDOW_MAXIMIZE_REQUESTED);
        event_mask |= event_mask_for_type(WINDOW_MINIMIZE_REQUESTED);
        event_mask |= event_mask_for_type(WINDOW_RESIZE_ENDED);
        event_mask |= event_mask_for_type(WINDOW_RESTORE_REQUESTED);
    }

    return event_mask;
}

static void post_ime_update( HWND hwnd, UINT cursor_pos, WCHAR *comp_str, WCHAR *result_str )
{
    NtUserMessageCall( hwnd, WINE_IME_POST_UPDATE, cursor_pos, (LPARAM)comp_str,
                       result_str, NtUserImeDriverCall, FALSE );
}

/***********************************************************************
 *              macdrv_im_set_text
 */
static void macdrv_im_set_text(const macdrv_event *event)
{
    HWND hwnd = macdrv_get_window_hwnd(event->window);
    WCHAR *text = NULL;

    TRACE_(imm)("win %p/%p himc %p text %s complete %u\n", hwnd, event->window, event->im_set_text.himc,
                debugstr_cf(event->im_set_text.text), event->im_set_text.complete);

    if (event->im_set_text.text)
    {
        CFIndex length = CFStringGetLength(event->im_set_text.text);
        if (!(text = malloc((length + 1) * sizeof(WCHAR)))) return;
        if (length) CFStringGetCharacters(event->im_set_text.text, CFRangeMake(0, length), text);
        text[length] = 0;
    }

    if (event->im_set_text.complete) post_ime_update(hwnd, -1, NULL, text);
    else post_ime_update(hwnd,
                         MAKELONG(event->im_set_text.cursor_begin, event->im_set_text.cursor_end),
                         text, NULL);

    free(text);
}


/**************************************************************************
 *              drag_operations_to_dropeffects
 */
static DWORD drag_operations_to_dropeffects(uint32_t ops)
{
    DWORD effects = 0;
    if (ops & (DRAG_OP_COPY | DRAG_OP_GENERIC))
        effects |= DROPEFFECT_COPY;
    if (ops & DRAG_OP_MOVE)
        effects |= DROPEFFECT_MOVE;
    if (ops & (DRAG_OP_LINK | DRAG_OP_GENERIC))
        effects |= DROPEFFECT_LINK;
    return effects;
}


/**************************************************************************
 *              dropeffect_to_drag_operation
 */
static uint32_t dropeffect_to_drag_operation(DWORD effect, uint32_t ops)
{
    if (effect & DROPEFFECT_LINK && ops & DRAG_OP_LINK) return DRAG_OP_LINK;
    if (effect & DROPEFFECT_COPY && ops & DRAG_OP_COPY) return DRAG_OP_COPY;
    if (effect & DROPEFFECT_MOVE && ops & DRAG_OP_MOVE) return DRAG_OP_MOVE;
    if (effect & DROPEFFECT_LINK && ops & DRAG_OP_GENERIC) return DRAG_OP_GENERIC;
    if (effect & DROPEFFECT_COPY && ops & DRAG_OP_GENERIC) return DRAG_OP_GENERIC;

    return DRAG_OP_NONE;
}


/**************************************************************************
 *              query_drag_drop_drop
 */
static BOOL query_drag_drop_drop(macdrv_query *query)
{
    HWND hwnd = macdrv_get_window_hwnd(query->window);
    struct macdrv_win_data *data;

    if (!(data = get_win_data(hwnd)))
    {
        WARN("no win_data for win %p/%p\n", hwnd, query->window);
        return FALSE;
    }

    release_win_data(data);

    NtUserMessageCall(hwnd, WINE_DRAG_DROP_DROP, 0, 0, NULL, NtUserDragDropCall, FALSE);
    return TRUE;
}

/**************************************************************************
 *              query_drag_drop_enter
 */
static BOOL query_drag_drop_enter(macdrv_query *query)
{
    CFTypeRef pasteboard = query->drag_drop.pasteboard;
    struct format_entry *entries;
    UINT entries_size;

    if (!(entries = get_format_entries(pasteboard, &entries_size))) return FALSE;
    NtUserMessageCall(0, WINE_DRAG_DROP_ENTER, entries_size, (LPARAM)entries, NULL, NtUserDragDropCall, FALSE);
    free(entries);

    return TRUE;
}

/**************************************************************************
 *              query_drag_drop_leave
 */
static BOOL query_drag_drop_leave(macdrv_query *query)
{
    NtUserMessageCall(0, WINE_DRAG_DROP_LEAVE, 0, 0, NULL, NtUserDragDropCall, FALSE);
    return TRUE;
}


/**************************************************************************
 *              query_drag_drop_drag
 */
static BOOL query_drag_drop_drag(macdrv_query *query)
{
    HWND hwnd = macdrv_get_window_hwnd(query->window);
    struct macdrv_win_data *data = get_win_data(hwnd);
    DWORD effect;
    POINT point;

    if (!data)
    {
        WARN("no win_data for win %p/%p\n", hwnd, query->window);
        return FALSE;
    }

    effect = drag_operations_to_dropeffects(query->drag_drop.ops);
    point.x = query->drag_drop.x + data->rects.visible.left;
    point.y = query->drag_drop.y + data->rects.visible.top;
    release_win_data(data);

    effect = NtUserMessageCall(hwnd, WINE_DRAG_DROP_DRAG, MAKELONG(point.x, point.y), effect, NULL, NtUserDragDropCall, FALSE);
    if (!effect) return FALSE;

    query->drag_drop.ops = dropeffect_to_drag_operation(effect, query->drag_drop.ops);
    return TRUE;
}


/***********************************************************************
 *      SetIMECompositionRect (MACDRV.@)
 */
BOOL macdrv_SetIMECompositionRect(HWND hwnd, RECT rect)
{
    TRACE("hwnd %p, rect %s\n", hwnd, wine_dbgstr_rect(&rect));
    pthread_mutex_lock(&ime_composition_rect_mutex);
    ime_composition_rect = cgrect_from_rect(rect);
    pthread_mutex_unlock(&ime_composition_rect_mutex);
    return TRUE;
}


/***********************************************************************
 *      NotifyIMEStatus (MACDRV.@)
 */
void macdrv_NotifyIMEStatus( HWND hwnd, UINT status )
{
    TRACE_(imm)( "hwnd %p, status %#x\n", hwnd, status );
    if (!status) macdrv_clear_ime_text();
}


/***********************************************************************
 *              macdrv_query_event
 *
 * Handler for QUERY_EVENT and QUERY_EVENT_NO_PREEMPT_WAIT queries.
 */
static void macdrv_query_event(HWND hwnd, const macdrv_event *event)
{
    BOOL success = FALSE;
    macdrv_query *query = event->query_event.query;

    switch (query->type)
    {
        case QUERY_DRAG_DROP_ENTER:
            TRACE("QUERY_DRAG_DROP_ENTER\n");
            success = query_drag_drop_enter(query);
            break;
        case QUERY_DRAG_DROP_LEAVE:
            TRACE("QUERY_DRAG_DROP_LEAVE\n");
            success = query_drag_drop_leave(query);
            break;
        case QUERY_DRAG_DROP_DRAG:
            TRACE("QUERY_DRAG_DROP_DRAG\n");
            success = query_drag_drop_drag(query);
            break;
        case QUERY_DRAG_DROP_DROP:
            TRACE("QUERY_DRAG_DROP_DROP\n");
            success = query_drag_drop_drop(query);
            break;
        case QUERY_PASTEBOARD_DATA:
            TRACE("QUERY_PASTEBOARD_DATA\n");
            success = query_pasteboard_data(hwnd, query->pasteboard_data.type);
            break;
        case QUERY_RESIZE_SIZE:
            TRACE("QUERY_RESIZE_SIZE\n");
            success = query_resize_size(hwnd, query);
            break;
        case QUERY_RESIZE_START:
            TRACE("QUERY_RESIZE_START\n");
            success = query_resize_start(hwnd);
            break;
        case QUERY_MIN_MAX_INFO:
            TRACE("QUERY_MIN_MAX_INFO\n");
            success = query_min_max_info(hwnd);
            break;
        default:
            FIXME("unrecognized query type %d\n", query->type);
            break;
    }

    TRACE("success %d\n", success);
    query->status = success;
    macdrv_set_query_done(query);
}


/***********************************************************************
 *              macdrv_handle_event
 */
void macdrv_handle_event(const macdrv_event *event)
{
    HWND hwnd = macdrv_get_window_hwnd(event->window);
    const macdrv_event *prev;
    struct macdrv_thread_data *thread_data = macdrv_thread_data();

    TRACE("%s for hwnd/window %p/%p\n", dbgstr_event(event->type), hwnd,
          event->window);

    if (trace_ui_input_enabled())
    {
        fprintf(stderr,
                "macrunner-ui-input: stage=macdrv_handle_event_enter pid=%d type=%d/%s hwnd=%p window=%p current=%p\n",
                getpid(), event->type, dbgstr_event(event->type), hwnd, event->window,
                thread_data ? thread_data->current_event : NULL);
        fflush(stderr);
    }

    prev = thread_data->current_event;
    thread_data->current_event = event;

    switch (event->type)
    {
    case APP_ACTIVATED:
        macdrv_app_activated();
        break;
    case APP_DEACTIVATED:
        macdrv_app_deactivated();
        break;
    case APP_QUIT_REQUESTED:
        macdrv_app_quit_requested(event);
        break;
    case CLIENT_SURFACE_PRESENTED:    /* CW HACK 22435 */
#if defined(__x86_64__)
	macdrv_client_surface_presented(event);
#else
	/* MacRunner: D3DMetal-only event; not delivered on arm64 host. */
#endif
	break;
    case DISPLAYS_CHANGED:
        macdrv_displays_changed(event);
        break;
    /* CrossOver Hack 10912: Mac Edit menu */
    case EDIT_MENU_COMMAND:
        macdrv_edit_menu_command(event);
        break;
    case HOTKEY_PRESS:
        macdrv_hotkey_press(event);
        break;
    case IM_SET_TEXT:
        macdrv_im_set_text(event);
        break;
    case KEY_PRESS:
    case KEY_RELEASE:
        macdrv_return_route_observe("macdrv-event-dequeue", hwnd, event->window,
                                    event->key.keycode, 0, event->type == KEY_PRESS,
                                    event->key.modifiers, event->key.time_ms);
        macdrv_key_event(hwnd, event);
        break;
    case KEYBOARD_CHANGED:
        macdrv_keyboard_changed(event);
        break;
    case LOST_PASTEBOARD_OWNERSHIP:
        macdrv_lost_pasteboard_ownership(hwnd);
        break;
    case MOUSE_BUTTON:
        if (trace_ui_input_enabled())
        {
            fprintf(stderr,
                    "macrunner-ui-input: stage=macdrv_handle_event_mouse hwnd=%p window=%p button=%d pressed=%d x=%d y=%d\n",
                    hwnd, event->window, event->mouse_button.button, event->mouse_button.pressed,
                    event->mouse_button.x, event->mouse_button.y);
            fflush(stderr);
        }
        macdrv_mouse_button(hwnd, event);
        break;
    case MOUSE_MOVED_RELATIVE:
    case MOUSE_MOVED_ABSOLUTE:
        macdrv_mouse_moved(hwnd, event);
        break;
    case MOUSE_SCROLL:
        macdrv_mouse_scroll(hwnd, event);
        break;
    case QUERY_EVENT:
    case QUERY_EVENT_NO_PREEMPT_WAIT:
        macdrv_query_event(hwnd, event);
        break;
    case REASSERT_WINDOW_POSITION:
        macdrv_reassert_window_position(hwnd);
        break;
    case RELEASE_CAPTURE:
        macdrv_release_capture(hwnd, event);
        break;
    case STATUS_ITEM_MOUSE_BUTTON:
        macdrv_status_item_mouse_button(event);
        break;
    case STATUS_ITEM_MOUSE_MOVE:
        macdrv_status_item_mouse_move(event);
        break;
    case WINDOW_BROUGHT_FORWARD:
        macdrv_window_brought_forward(hwnd);
        break;
    case WINDOW_CLOSE_REQUESTED:
        macdrv_window_close_requested(hwnd);
        break;
    case WINDOW_DID_MINIMIZE:
        macdrv_window_did_minimize(hwnd);
        break;
    case WINDOW_DID_UNMINIMIZE:
        macdrv_window_did_unminimize(hwnd);
        break;
    case WINDOW_DRAG_BEGIN:
        macdrv_window_drag_begin(hwnd, event);
        break;
    case WINDOW_DRAG_END:
        macdrv_window_drag_end(hwnd);
        break;
    case WINDOW_FRAME_CHANGED:
        macdrv_window_frame_changed(hwnd, event);
        break;
    case WINDOW_GOT_FOCUS:
        macdrv_window_got_focus(hwnd, event);
        if (macdrv_return_route_focus_milestones_enabled())
            macdrv_return_route_observe("macdrv-focus-state", hwnd, event->window,
                                        36, 0, -1, 0, 0);
        break;
    case WINDOW_LOST_FOCUS:
        macdrv_window_lost_focus(hwnd, event);
        if (macdrv_return_route_focus_milestones_enabled())
            macdrv_return_route_observe("macdrv-focus-state", hwnd, event->window,
                                        36, 0, -1, 0, 0);
        break;
    case WINDOW_MAXIMIZE_REQUESTED:
        macdrv_window_maximize_requested(hwnd);
        break;
    case WINDOW_MINIMIZE_REQUESTED:
        macdrv_window_minimize_requested(hwnd);
        break;
    case WINDOW_RESIZE_ENDED:
        macdrv_window_resize_ended(hwnd);
        break;
    case WINDOW_RESTORE_REQUESTED:
        macdrv_window_restore_requested(hwnd, event);
        break;
    case MACRUNNER_WINSHOW_ACTIVATE:
        macdrv_winshow_activate(hwnd);
        break;
    default:
        TRACE("    ignoring\n");
        break;
    }

    thread_data->current_event = prev;
    if (trace_ui_input_enabled())
    {
        fprintf(stderr,
                "macrunner-ui-input: stage=macdrv_handle_event_exit pid=%d type=%d/%s hwnd=%p window=%p restored=%p\n",
                getpid(), event->type, dbgstr_event(event->type), hwnd, event->window, prev);
        fflush(stderr);
    }
}


static int check_fd_events( int fd, int events )
{
    struct pollfd pfd = {.fd = fd, .events = events};
    if (poll( &pfd, 1, 0 ) <= 0) return 0;
    return pfd.revents;
}

/***********************************************************************
 *              ProcessEvents   (MACDRV.@)
 */
BOOL macdrv_ProcessEvents(DWORD mask)
{
    struct macdrv_thread_data *data = macdrv_thread_data();
    macdrv_event_mask event_mask = get_event_mask(mask);
    macdrv_event *event;
    int count = 0;
    BOOL ret;

    TRACE("mask %x\n", mask);

    if (!data)
    {
        /* This early return sits ABOVE the drain probe at the bottom, so without a note
         * here "HK never pumps messages" and "HK pumps but the pumping thread never ran
         * macdrv_init_thread_data" would both show up as zero drain lines — two different
         * bugs with two different fixes, which is the exact ambiguity this probe exists to
         * remove. queue=(nil)/fd=-1/handled=-1 is the no-thread-data signature. */
        macrunner_note_drain(NULL, -1, -1, mask, (unsigned long long)event_mask, NULL);
        return FALSE;
    }

    if (trace_ui_input_enabled())
    {
        fprintf(stderr,
                "macrunner-ui-input: stage=ProcessEvents_enter pid=%d tid=%llu mask=0x%x event_mask=0x%llx queue=%p fd=%d current=%p\n",
                getpid(), trace_ui_input_tid(), mask, (unsigned long long)event_mask, data->queue,
                macdrv_get_event_queue_fd(data->queue), data->current_event);
        fflush(stderr);
    }

    if (data->current_event && data->current_event->type != QUERY_EVENT &&
        data->current_event->type != QUERY_EVENT_NO_PREEMPT_WAIT &&
        data->current_event->type != APP_QUIT_REQUESTED &&
        data->current_event->type != WINDOW_DRAG_BEGIN)
        event_mask = 0;  /* don't process nested events */

    while (macdrv_copy_event_from_queue(data->queue, event_mask, &event))
    {
        if (macrunner_drain_probe_enabled() &&
            (event->type == KEY_PRESS || event->type == KEY_RELEASE))
        {
            fprintf(stderr,
                    "macrunner-ui-input: stage=ProcessEvents_key_dequeued pid=%d tid=%llu queue=%p type=%d/%s window=%p\n",
                    getpid(), trace_ui_input_tid(), data->queue, event->type,
                    dbgstr_event(event->type), event->window);
            fflush(stderr);
        }
        if (trace_ui_input_enabled())
        {
            fprintf(stderr,
                    "macrunner-ui-input: stage=ProcessEvents_dequeue pid=%d count=%d event=%p type=%d/%s\n",
                    getpid(), count + 1, event, event->type, dbgstr_event(event->type));
            fflush(stderr);
        }
        count++;
        macdrv_handle_event(event);
        if (trace_ui_input_enabled())
        {
            fprintf(stderr,
                    "macrunner-ui-input: stage=ProcessEvents_handled pid=%d count=%d event=%p type=%d/%s\n",
                    getpid(), count, event, event->type, dbgstr_event(event->type));
            fflush(stderr);
        }
        macdrv_release_event(event);
    }

    if (count) TRACE("processed %d events\n", count);
    /* event_mask is read AFTER the nested-event guard above, so a 0 here names that guard (or a
     * caller mask without QS_KEY) as the reason nothing was copied out -- see the probe header. */
    macrunner_note_drain(data->queue, macdrv_get_event_queue_fd(data->queue), count, mask,
                         (unsigned long long)event_mask, data->current_event);
    ret = mask == QS_ALLINPUT && !check_fd_events(macdrv_get_event_queue_fd(data->queue), POLLIN);
    if (trace_ui_input_enabled())
    {
        fprintf(stderr,
                "macrunner-ui-input: stage=ProcessEvents_exit pid=%d tid=%llu count=%d ret=%d fd_pending=%d\n",
                getpid(), trace_ui_input_tid(), count, ret,
                check_fd_events(macdrv_get_event_queue_fd(data->queue), POLLIN));
        fflush(stderr);
    }
    return ret;
}
