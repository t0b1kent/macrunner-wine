/*
 * MACDRV Cocoa initialization code
 *
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

#import <AppKit/AppKit.h>
#include <objc/runtime.h>
#include <mach/mach.h>
#include <mach/mach_time.h>

#include "macdrv_cocoa.h"
#import "cocoa_app.h"

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"


/* MacRunner ui-input trace: same env gates as the macrunner-ui-input stages. */
static BOOL macrunner_ui_input_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
        enabled = getenv("MACRUNNER_TRACE_WINEMAC_INPUT") != NULL ||
                  getenv("MACRUNNER_TRACE_UI_INPUT") != NULL ||
                  getenv("MACRUNNER_TRACE_UI_EVENT_PATH") != NULL;
    return enabled;
}

/* MacRunner 2026-07-28 (HK input): -[NSApplication run] returning is a
 * process-fatal condition for input (nothing pumps AppKit afterwards, so
 * -sendEvent: is never called again and no key or mouse event can reach
 * macdrv_key_event/macdrv_mouse_button).  Re-enter the event loop rather than
 * letting one spurious return kill input for the life of the process.  Default
 * ON; set MACRUNNER_WINEMAC_NSAPP_REENTER=0 to get the old behaviour back for
 * an A/B. */
static BOOL macrunner_nsapp_reenter_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        const char *v = getenv("MACRUNNER_WINEMAC_NSAPP_REENTER");
        enabled = !(v && v[0] == '0' && v[1] == '\0');
    }
    return enabled;
}

/* Bounds so a run loop that exits instantly can never become a hot spin. */
#define MACRUNNER_NSAPP_FAST_RETURN_MS    100
#define MACRUNNER_NSAPP_FAST_RETURN_LIMIT 8
#define MACRUNNER_NSAPP_REENTRY_LIMIT     1024

/* MacRunner 2026-07-28 (HK input investigation): in the Hollow Knight game
 * process NSApp is a STOCK NSApplication by the time run_cocoa_app runs, so
 * WineApplication.sendEvent is never installed and no macOS input ever enters
 * Wine. Hook +[NSApplication sharedApplication] at winemac.so load time
 * (AppKit arrives as our dependency, so the first in-process caller must come
 * after this constructor) and log the first caller's class + stack = the thief. */
static id (*macrunner_orig_sharedApplication)(id, SEL) = NULL;

static id macrunner_sharedApplication_hook(id self, SEL _cmd)
{
    static int logged = 0;
    id app = macrunner_orig_sharedApplication(self, _cmd);

    if (!logged && macrunner_ui_input_trace_enabled())
    {
        logged = 1;
        fprintf(stderr,
                "macrunner-ui-input: stage=first_sharedApplication caller_class=%s app=%p appclass=%s main_thread=%d\n%s\n",
                class_getName(self), (void *)app,
                app ? object_getClassName(app) : "(nil)", [NSThread isMainThread],
                [[[NSThread callStackSymbols] description] UTF8String]);
        fflush(stderr);
    }
    return app;
}

__attribute__((constructor))
static void macrunner_winemac_load_probe(void)
{
    if (!macrunner_ui_input_trace_enabled()) return;

    fprintf(stderr,
            "macrunner-ui-input: stage=winemac_so_load nsapp=%p class=%s main_thread=%d\n",
            (void *)NSApp, NSApp ? object_getClassName(NSApp) : "(nil)",
            [NSThread isMainThread]);
    fflush(stderr);

    {
        Method m = class_getClassMethod([NSApplication class], @selector(sharedApplication));
        if (m)
        {
            macrunner_orig_sharedApplication = (id (*)(id, SEL))method_getImplementation(m);
            method_setImplementation(m, (IMP)macrunner_sharedApplication_hook);
        }
    }
}


/* Condition values for an NSConditionLock. Used to signal between run_cocoa_app
   and macdrv_start_cocoa_app so the latter knows when the former is running
   the application event loop. */
enum {
    COCOA_APP_NOT_RUNNING,
    COCOA_APP_RUNNING,
};


struct cocoa_app_startup_info {
    NSConditionLock*    lock;
    unsigned long long  tickcount;
    uint64_t            uptime_ns;
    BOOL                success;
};

/* MacRunner 2026-07-28 (HK input root fix): -sendEvent: replacement used when
 * NSApp was pre-created as a STOCK NSApplication before run_cocoa_app got to
 * run (live on Hollow Knight: winemac.so loaded, driver init pending, NSApp
 * already stock — upstream then installed no controller and never entered
 * [NSApp run], so no macOS input event ever reached Wine; keyboard AND mouse
 * dead, no activation). Functionally identical to -[WineApplication sendEvent:]
 * but routes through the sharedController singleton instead of the
 * wineController ivar that only WineApplication instances have. */
static void (*macrunner_orig_sendEvent)(id, SEL, NSEvent *) = NULL;

/* MacRunner 2026-07-28 (HK input ROOT CAUSE): set once we have handed the main
 * thread to -[NSApplication run], so a second run_cocoa_app invocation can never
 * start a nested run loop on top of it. */
static BOOL macrunner_nsapp_run_entered = FALSE;

static void macrunner_sendEvent_stock_recovery(id self, SEL _cmd, NSEvent *event)
{
    WineApplicationController *controller = [WineApplicationController sharedController];

    if (macrunner_ui_input_trace_enabled())
    {
        NSEventType type = [event type];
        if (type == NSEventTypeLeftMouseDown || type == NSEventTypeLeftMouseUp ||
            type == NSEventTypeRightMouseDown || type == NSEventTypeRightMouseUp ||
            type == NSEventTypeOtherMouseDown || type == NSEventTypeOtherMouseUp ||
            type == NSEventTypeKeyDown || type == NSEventTypeKeyUp)
        {
            fprintf(stderr,
                    "macrunner-ui-input: stage=recovery_sendEvent pid=%d type=%ld\n",
                    getpid(), (long)type);
            fflush(stderr);
        }
    }

    if (![controller handleEvent:event])
    {
        macrunner_orig_sendEvent(self, _cmd, event);
        [controller didSendEvent:event];
    }
}


/***********************************************************************
 *              run_cocoa_app
 *
 * Transforms the main thread from merely idling in its run loop to
 * being a Cocoa application running its event loop.
 *
 * This will be the perform callback of a custom run loop source that
 * will be scheduled in the main thread's run loop from a secondary
 * thread by macdrv_start_cocoa_app.  This function communicates that
 * it has successfully started the application by changing the condition
 * of a shared NSConditionLock, passed in via the info parameter.
 *
 * This function never returns.  It's the new permanent home of the
 * main thread.
 */
static void run_cocoa_app(void* info)
{
    struct cocoa_app_startup_info* startup_info = info;
    NSConditionLock* lock = startup_info->lock;
    BOOL created_app = FALSE;
    BOOL should_run_nsapp = FALSE;

    @autoreleasepool
    {
        /* UNGATED on purpose: this is one line, once per process, and every run
         * that was launched without MACRUNNER_TRACE_WINEMAC_INPUT so far made the
         * whole winemac ladder unreadable — "not logged" was then indistinguishable
         * from "did not happen" and the run was wasted. */
        fprintf(stderr,
                "macrunner-ui-input: stage=run_cocoa_app_entry pid=%d nsapp=%p class=%s main_thread=%d\n",
                getpid(), (void *)NSApp, NSApp ? object_getClassName(NSApp) : "(nil)",
                (int)[NSThread isMainThread]);
        fflush(stderr);

        if (!NSApp)
        {
            [WineApplication sharedApplication];
            created_app = TRUE;

            if (macrunner_ui_input_trace_enabled())
            {
                fprintf(stderr,
                        "macrunner-ui-input: stage=run_cocoa_app_created nsapp=%p class=%s\n",
                        (void *)NSApp, NSApp ? object_getClassName(NSApp) : "(nil)");
                fflush(stderr);
            }
        }
        else if (![NSApp isKindOfClass:[WineApplication class]])
        {
            /* MacRunner 2026-07-28: NSApp pre-created as stock NSApplication
             * (HK input root). Install Wine's event dispatch anyway: delegate
             * + -sendEvent: swizzle on NSApp's class (process-local), then fall
             * through to the normal startup so [NSApp run] is entered. */
            WineApplicationController *controller = [WineApplicationController sharedController];
            Method m = class_getInstanceMethod([NSApp class], @selector(sendEvent:));

            if (macrunner_ui_input_trace_enabled())
            {
                fprintf(stderr,
                        "macrunner-ui-input: stage=run_cocoa_app_stock_recovery nsapp=%p class=%s\n",
                        (void *)NSApp, object_getClassName(NSApp));
                fflush(stderr);
            }

            if (m)
            {
                macrunner_orig_sendEvent = (void (*)(id, SEL, NSEvent *))method_getImplementation(m);
                method_setImplementation(m, (IMP)macrunner_sendEvent_stock_recovery);
            }
            [NSApp setDelegate:(id<NSApplicationDelegate>)controller];
            [controller computeEventTimeAdjustmentFromTicks:startup_info->tickcount
                                                    uptime:startup_info->uptime_ns];
            startup_info->success = TRUE;
            created_app = TRUE;
        }

        /* CrossOver hack 12205: Prevent call to NSVersionOfRunTimeLibrary() during app startup.
                                 It can crash if a Wine thread unloads a dylib simultaneously. */
        [[NSUserDefaults standardUserDefaults] registerDefaults:
            [NSDictionary dictionaryWithObject:@"YES" forKey:@"NSUseActiveDisplayForMainScreen"]];

        if ([NSApp respondsToSelector:@selector(setWineController:)])
        {
            WineApplicationController* controller = [WineApplicationController sharedController];
            [NSApp setWineController:controller];
            [controller computeEventTimeAdjustmentFromTicks:startup_info->tickcount uptime:startup_info->uptime_ns];
            startup_info->success = TRUE;
        }

        /* MacRunner 2026-07-28 (HK input ROOT CAUSE) — two defects fixed here.
         *
         * 1. The old guard was `created_app && startup_info->success`, i.e.
         *    [NSApp run] was entered ONLY when THIS invocation created NSApp.
         *    Measured on live Hollow Knight (pid 75428): the window existed, so
         *    macdrv_init -> macdrv_start_cocoa_app had returned 0, which means
         *    startup_info->success was TRUE and run_cocoa_app HAD run; yet
         *    `sample` showed the main thread parked in the bare CFRunLoopRun of
         *    ntdll's loader with ZERO AppKit frames (control: Safari shows
         *    -[NSApplication run]) and Accessibility reported 0 windows for the
         *    process while CGWindowList showed a real on-screen window. So
         *    created_app was FALSE — NSApp already existed and was already a
         *    WineApplication, so both the !NSApp branch and the stock-recovery
         *    branch were skipped. AppKit's _NSEventThread kept queueing events
         *    that nothing ever dequeued, so -sendEvent: was never called and NO
         *    key or mouse event could reach macdrv_key_event/macdrv_mouse_button.
         *    What matters is not who created NSApp but whether this process
         *    still owes AppKit an event loop.
         *
         * 2. `startup_info` points into macdrv_start_cocoa_app's STACK FRAME,
         *    and that thread is released by the unlock below — it can pop the
         *    frame before we read it. Reading startup_info->success after the
         *    unlock is a use-after-return whose value decides whether input
         *    works at all. Capture the decision BEFORE unlocking. */
        should_run_nsapp = startup_info->success && !macrunner_nsapp_run_entered;

        /* UNGATED on purpose — see stage=run_cocoa_app_entry above. */
        fprintf(stderr,
                "macrunner-ui-input: stage=run_cocoa_app_decide pid=%d nsapp=%p class=%s "
                "created_app=%d success=%d already_entered=%d will_run=%d\n",
                getpid(), (void *)NSApp, NSApp ? object_getClassName(NSApp) : "(nil)",
                (int)created_app, (int)startup_info->success,
                (int)macrunner_nsapp_run_entered, (int)should_run_nsapp);
        fflush(stderr);

        /* Retain the lock while we're using it, so macdrv_start_cocoa_app()
           doesn't deallocate it in the middle of us unlocking it. */
        [lock retain];
        [lock lock];
        [lock unlockWithCondition:COCOA_APP_RUNNING];
        [lock release];
    }

    if (should_run_nsapp)
    {
        /* MacRunner 2026-07-28 (HK input) — THE UNINSTRUMENTED EDGE.
         *
         * Upstream annotates this call "Never returns", and nothing in
         * winemac.drv calls -[NSApplication stop:] (only -terminate:, from the
         * quit path).  So there was no trace here and a return was invisible.
         *
         * But on live Hollow Knight the measured state is: window on screen,
         * `sample` shows the main thread in ntdll's apple_main_thread
         * CFRunLoopRun (loader.c:3276) with ZERO AppKit frames over 2145/2145
         * samples, and Accessibility reports 0 windows.  The window's existence
         * forces macdrv_start_cocoa_app to have returned 0 (macdrv_main.c:487-494
         * skips init_user_driver() and fails the driver otherwise), which forces
         * startup_info->success == TRUE, which forces should_run_nsapp == TRUE.
         * [HYPOTHESIS, this is the inference the traces below settle] therefore
         * [NSApp run] was entered and RETURNED, and the main thread fell back out
         * of the perform callback into the loader's run loop.
         *
         * Once that happens nothing pumps AppKit ever again: -sendEvent: is not
         * called, so no key or mouse event can reach Wine.  Re-enter, bounded, so
         * a single spurious return cannot kill input for the life of the process
         * and an instantly-returning loop cannot become a hot spin. */
        unsigned int reentry = 0;
        unsigned int fast_returns = 0;
        mach_timebase_info_data_t mach_timebase;

        mach_timebase_info(&mach_timebase);
        macrunner_nsapp_run_entered = TRUE;

        /* MacRunner 2026-07-29 (HK E2E lane) — UNGATED, once per process.
         * `will_run=1` in stage=run_cocoa_app_decide is a DECISION, not evidence that
         * [NSApp run] was entered, and `nsapp_run_returned = 0` is equally consistent
         * with "running" and with "never entered".  Say which, and record the
         * activation state at that instant, because a process that is not a regular
         * activatable app gets no key window and therefore no key events. */
        fprintf(stderr,
                "macrunner-ui-input: stage=nsapp_run_entering pid=%d policy=%ld active=%d "
                "keyWindow=%p windows=%lu\n",
                getpid(), (long)[NSApp activationPolicy], (int)[NSApp isActive],
                [NSApp keyWindow], (unsigned long)[[NSApp windows] count]);
        fflush(stderr);

        for (;;)
        {
            uint64_t started = mach_absolute_time();
            unsigned long long ran_ms;

            @autoreleasepool
            {
                [NSApp run];
            }

            ran_ms = (unsigned long long)(mach_absolute_time() - started) *
                     mach_timebase.numer / mach_timebase.denom / 1000000ull;
            reentry++;
            if (ran_ms < MACRUNNER_NSAPP_FAST_RETURN_MS) fast_returns++;
            else fast_returns = 0;

            /* UNGATED on purpose: this edge is process-fatal for input and must
             * be visible even in a run launched without the trace env var. */
            fprintf(stderr,
                    "macrunner-ui-input: stage=nsapp_run_returned pid=%d nsapp=%p class=%s "
                    "isrunning=%d ran_ms=%llu reentry=%u fast_returns=%u\n",
                    getpid(), (void *)NSApp, NSApp ? object_getClassName(NSApp) : "(nil)",
                    NSApp ? (int)[NSApp isRunning] : -1, ran_ms, reentry, fast_returns);
            fflush(stderr);

            if (!macrunner_nsapp_reenter_enabled())
            {
                fprintf(stderr,
                        "macrunner-ui-input: stage=nsapp_run_reenter_disabled pid=%d reentry=%u\n",
                        getpid(), reentry);
                fflush(stderr);
                break;
            }

            if (fast_returns >= MACRUNNER_NSAPP_FAST_RETURN_LIMIT ||
                reentry >= MACRUNNER_NSAPP_REENTRY_LIMIT)
            {
                fprintf(stderr,
                        "macrunner-ui-input: stage=nsapp_run_reenter_giving_up pid=%d "
                        "reentry=%u fast_returns=%u — input is DEAD for this process\n",
                        getpid(), reentry, fast_returns);
                fflush(stderr);
                break;
            }
        }
    }
}


/***********************************************************************
 *              macdrv_start_cocoa_app
 *
 * Tells the main thread to transform itself into a Cocoa application.
 *
 * Returns 0 on success, non-zero on failure.
 */
int macdrv_start_cocoa_app(unsigned long long tickcount)
{
@autoreleasepool
{
    int ret = -1;
    CFRunLoopSourceRef source;
    struct cocoa_app_startup_info startup_info;
    uint64_t uptime_mach = mach_absolute_time();
    mach_timebase_info_data_t mach_timebase;
    NSDate* timeLimit;
    CFRunLoopSourceContext source_context = { 0 };

    /* Make sure Cocoa is in multi-threading mode by detaching a
       do-nothing thread. */
    [NSThread detachNewThreadSelector:@selector(self)
                             toTarget:[NSThread class]
                           withObject:nil];

    startup_info.lock = [[NSConditionLock alloc] initWithCondition:COCOA_APP_NOT_RUNNING];
    startup_info.tickcount = tickcount;
    startup_info.success = FALSE;

    mach_timebase_info(&mach_timebase);
    startup_info.uptime_ns = uptime_mach * mach_timebase.numer / mach_timebase.denom;

    timeLimit = [NSDate dateWithTimeIntervalSinceNow:5];

    source_context.info = &startup_info;
    source_context.perform = run_cocoa_app;
    source = CFRunLoopSourceCreate(NULL, 0, &source_context);

    if (source && startup_info.lock && timeLimit)
    {
        CFRunLoopAddSource(CFRunLoopGetMain(), source, kCFRunLoopCommonModes);
        CFRunLoopSourceSignal(source);
        CFRunLoopWakeUp(CFRunLoopGetMain());

        if ([startup_info.lock lockWhenCondition:COCOA_APP_RUNNING beforeDate:timeLimit])
        {
            [startup_info.lock unlock];
            ret = !startup_info.success;
        }
    }

    if (source)
        CFRelease(source);
    [startup_info.lock release];
    return ret;
}
}
