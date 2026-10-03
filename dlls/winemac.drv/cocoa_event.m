/*
 * MACDRV Cocoa event queue code
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

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <libkern/OSAtomic.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "macdrv_cocoa.h"
#import "cocoa_event.h"
#import "cocoa_app.h"
#import "cocoa_window.h"

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"


static NSString* const WineEventQueueThreadDictionaryKey = @"WineEventQueueThreadDictionaryKey";

static NSString* const WineHotKeyMacIDKey       = @"macID";
static NSString* const WineHotKeyVkeyKey        = @"vkey";
static NSString* const WineHotKeyModFlagsKey    = @"modFlags";
static NSString* const WineHotKeyKeyCodeKey     = @"keyCode";
static NSString* const WineHotKeyCarbonRefKey   = @"hotKeyRef";
static const OSType WineHotKeySignature = 'Wine';

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


@implementation NSEvent (WineExtensions)

    static BOOL wine_commandKeyDown(NSUInteger flags)
    {
        return ((flags & (NSEventModifierFlagShift |
                          NSEventModifierFlagControl |
                          NSEventModifierFlagOption |
                          NSEventModifierFlagCommand)) == NSEventModifierFlagCommand);
    }

    + (BOOL) wine_commandKeyDown
    {
        return wine_commandKeyDown([self modifierFlags]);
    }

    - (BOOL) wine_commandKeyDown
    {
        return wine_commandKeyDown([self modifierFlags]);
    }

@end


@interface MacDrvEvent : NSObject
{
@public
    macdrv_event* event;
}

    - (id) initWithEvent:(macdrv_event*)event;

@end

@implementation MacDrvEvent

    - (id) initWithEvent:(macdrv_event*)inEvent
    {
        self = [super init];
        if (self)
        {
            event = macdrv_retain_event(inEvent);
        }
        return self;
    }

    - (void) dealloc
    {
        if (event) macdrv_release_event(event);
        [super dealloc];
    }

@end


@implementation WineEventQueue

    - (id) init
    {
        [self doesNotRecognizeSelector:_cmd];
        [self release];
        return nil;
    }

    - (id) initWithEventHandler:(macdrv_event_handler)handler
    {
        NSParameterAssert(handler != nil);

        self = [super init];
        if (self != nil)
        {
            struct kevent kev;
            int rc;

            fds[0] = fds[1] = kq = -1;

            event_handler = handler;
            events = [[NSMutableArray alloc] init];
            eventsLock = [[NSLock alloc] init];

            if (!events || !eventsLock)
            {
                [self release];
                return nil;
            }

            if (pipe(fds) ||
                fcntl(fds[0], F_SETFD, 1) == -1 ||
                fcntl(fds[0], F_SETFL, O_NONBLOCK) == -1 ||
                fcntl(fds[1], F_SETFD, 1) == -1 ||
                fcntl(fds[1], F_SETFL, O_NONBLOCK) == -1)
            {
                [self release];
                return nil;
            }

            kq = kqueue();
            if (kq < 0)
            {
                [self release];
                return nil;
            }

            EV_SET(&kev, fds[0], EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
            do
            {
                rc = kevent(kq, &kev, 1, NULL, 0, NULL);
            } while (rc == -1 && errno == EINTR);
            if (rc == -1)
            {
                [self release];
                return nil;
            }
        }
        return self;
    }

    - (void) dealloc
    {
        NSNumber* hotKeyMacID;

        for (hotKeyMacID in hotKeysByMacID)
        {
            NSDictionary<NSString *, id> *hotKeyDict = hotKeysByMacID[hotKeyMacID];
            EventHotKeyRef hotKeyRef = [hotKeyDict[WineHotKeyCarbonRefKey] pointerValue];
            UnregisterEventHotKey(hotKeyRef);
        }
        [hotKeysByMacID release];
        [hotKeysByWinID release];
        [events release];
        [eventsLock release];

        if (kq != -1) close(kq);
        if (fds[0] != -1) close(fds[0]);
        if (fds[1] != -1) close(fds[1]);

        [super dealloc];
    }

    - (void) signalEventAvailable
    {
        char junk = 1;
        int rc;

        do
        {
            rc = write(fds[1], &junk, 1);
        } while (rc < 0 && errno == EINTR);

        if (trace_ui_input_enabled())
        {
            fprintf(stderr,
                    "macrunner-ui-input: stage=queue_signal pid=%d tid=%llu queue=%p read_fd=%d write_fd=%d rc=%d errno=%d\n",
                    getpid(), trace_ui_input_tid(), self, fds[0], fds[1], rc,
                    rc < 0 ? errno : 0);
            fflush(stderr);
        }

        if (rc < 0 && errno != EAGAIN)
            ERR(@"%@: got error writing to event queue signaling pipe: %s\n", self, strerror(errno));
    }

    - (void) postEventObject:(MacDrvEvent*)event
    {
        NSIndexSet* indexes;
        MacDrvEvent* lastEvent;
        NSUInteger before_count;
        NSUInteger after_count;
        int event_type = event->event->type;

        [eventsLock lock];
        before_count = [events count];

        indexes = [events indexesOfObjectsPassingTest:^BOOL(id obj, NSUInteger idx, BOOL *stop){
            return ((MacDrvEvent*)obj)->event->deliver <= 0;
        }];
        [events removeObjectsAtIndexes:indexes];

        if ((event->event->type == MOUSE_MOVED_RELATIVE ||
             event->event->type == MOUSE_MOVED_ABSOLUTE) &&
            event->event->deliver == INT_MAX &&
            (lastEvent = [events lastObject]) &&
            (lastEvent->event->type == MOUSE_MOVED_RELATIVE ||
             lastEvent->event->type == MOUSE_MOVED_ABSOLUTE) &&
            lastEvent->event->deliver == INT_MAX &&
            lastEvent->event->window == event->event->window &&
            lastEvent->event->mouse_moved.drag == event->event->mouse_moved.drag)
        {
            if (event->event->type == MOUSE_MOVED_RELATIVE)
            {
                lastEvent->event->mouse_moved.x += event->event->mouse_moved.x;
                lastEvent->event->mouse_moved.y += event->event->mouse_moved.y;
            }
            else
            {
                lastEvent->event->type = MOUSE_MOVED_ABSOLUTE;
                lastEvent->event->mouse_moved.x = event->event->mouse_moved.x;
                lastEvent->event->mouse_moved.y = event->event->mouse_moved.y;
            }

            lastEvent->event->mouse_moved.time_ms = event->event->mouse_moved.time_ms;
        }
        else
            [events addObject:event];

        after_count = [events count];
        [eventsLock unlock];

        if (trace_ui_input_enabled())
        {
            fprintf(stderr,
                    "macrunner-ui-input: stage=queue_post pid=%d tid=%llu queue=%p event=%p type=%d before=%lu after=%lu deliver=%d\n",
                    getpid(), trace_ui_input_tid(), self, event->event, event_type,
                    (unsigned long)before_count, (unsigned long)after_count,
                    event->event->deliver);
            fflush(stderr);
        }

        [self signalEventAvailable];

        if (trace_ui_input_enabled())
        {
            fprintf(stderr,
                    "macrunner-ui-input: stage=queue_post_signal_done pid=%d tid=%llu queue=%p event=%p type=%d\n",
                    getpid(), trace_ui_input_tid(), self, event->event, event_type);
            fflush(stderr);
        }
    }

    - (void) postEvent:(macdrv_event*)inEvent
    {
        MacDrvEvent* event = [[MacDrvEvent alloc] initWithEvent:inEvent];
        [self postEventObject:event];
        [event release];
    }

    - (MacDrvEvent*) getEventMatchingMask:(macdrv_event_mask)mask
    {
        char buf[512];
        ssize_t rc;
        ssize_t read_bytes = 0;
        int read_errno;
        NSUInteger index;
        NSUInteger before_count;
        NSUInteger after_count;
        MacDrvEvent* ret = nil;

        /* Clear the pipe which signals there are pending events. */
        do
        {
            rc = read(fds[0], buf, sizeof(buf));
            if (rc > 0) read_bytes += rc;
        } while (rc > 0 || (rc < 0 && errno == EINTR));
        read_errno = rc < 0 ? errno : 0;
        if (rc == 0 || (rc < 0 && errno != EAGAIN))
        {
            if (rc == 0)
                ERR(@"%@: event queue signaling pipe unexpectedly closed\n", self);
            else
                ERR(@"%@: got error reading from event queue signaling pipe: %s\n", self, strerror(errno));
            return nil;
        }

        [eventsLock lock];
        before_count = [events count];

        index = 0;
        while (index < [events count])
        {
            MacDrvEvent* event = events[index];
            if (event_mask_for_type(event->event->type) & mask)
            {
                [[event retain] autorelease];
                [events removeObjectAtIndex:index];

                if (event->event->deliver == INT_MAX ||
                    OSAtomicDecrement32Barrier(&event->event->deliver) >= 0)
                {
                    ret = event;
                    break;
                }
            }
            else
                index++;
        }

        after_count = [events count];
        [eventsLock unlock];
        if (trace_ui_input_enabled() && (ret || before_count))
        {
            fprintf(stderr,
                    "macrunner-ui-input: stage=queue_get pid=%d tid=%llu queue=%p mask=0x%llx read_rc=%zd read_errno=%d read_bytes=%zd before=%lu after=%lu ret=%p type=%d\n",
                    getpid(), trace_ui_input_tid(), self, (unsigned long long)mask,
                    rc, read_errno, read_bytes, (unsigned long)before_count,
                    (unsigned long)after_count, ret ? ret->event : NULL,
                    ret ? ret->event->type : -1);
            fflush(stderr);
        }
        return ret;
    }

    - (void) discardEventsPassingTest:(BOOL (^)(macdrv_event* event))block
    {
    @autoreleasepool
    {
        NSIndexSet* indexes;

        [eventsLock lock];

        indexes = [events indexesOfObjectsPassingTest:^BOOL(id obj, NSUInteger idx, BOOL *stop){
            MacDrvEvent* event = obj;
            return block(event->event);
        }];

        [events removeObjectsAtIndexes:indexes];

        [eventsLock unlock];
    }
    }

    - (void) discardEventsMatchingMask:(macdrv_event_mask)mask forWindow:(NSWindow*)window
    {
        [self discardEventsPassingTest:^BOOL (macdrv_event* event){
            return ((event_mask_for_type(event->type) & mask) &&
                    (!window || event->window == (macdrv_window)window));
        }];
    }

    - (BOOL) query:(macdrv_query*)query timeout:(NSTimeInterval)timeout flags:(NSUInteger)flags
    {
        int type;
        macdrv_event* event;
        NSDate* timeoutDate = [NSDate dateWithTimeIntervalSinceNow:timeout];
        BOOL timedout;

        type = (flags & WineQueryNoPreemptWait) ? QUERY_EVENT_NO_PREEMPT_WAIT : QUERY_EVENT;
        event = macdrv_create_event(type, (WineWindow*)query->window);
        event->query_event.query = macdrv_retain_query(query);
        query->done = FALSE;

        [self postEvent:event];
        macdrv_release_event(event);
        timedout = ![[WineApplicationController sharedController] waitUntilQueryDone:&query->done
                                                                             timeout:timeoutDate
                                                                       processEvents:(flags & WineQueryProcessEvents) != 0];
        return !timedout && query->status;
    }

    - (BOOL) query:(macdrv_query*)query timeout:(NSTimeInterval)timeout
    {
        return [self query:query timeout:timeout flags:0];
    }

    - (void) resetMouseEventPositions:(CGPoint)pos
    {
        MacDrvEvent* event;

        pos = cgpoint_win_from_mac(pos);

        [eventsLock lock];

        for (event in events)
        {
            if (event->event->type == MOUSE_BUTTON)
            {
                event->event->mouse_button.x = pos.x;
                event->event->mouse_button.y = pos.y;
            }
            else if (event->event->type == MOUSE_SCROLL)
            {
                event->event->mouse_scroll.x = pos.x;
                event->event->mouse_scroll.y = pos.y;
            }
        }

        [eventsLock unlock];
    }

    - (BOOL) postHotKeyEvent:(UInt32)hotKeyNumber time:(double)time
    {
        NSDictionary<NSString *, id> *hotKeyDict = hotKeysByMacID[@(hotKeyNumber)];
        if (hotKeyDict)
        {
            macdrv_event* event;

            event = macdrv_create_event(HOTKEY_PRESS, nil);
            event->hotkey_press.vkey        = [hotKeyDict[WineHotKeyVkeyKey] unsignedIntValue];
            event->hotkey_press.mod_flags   = [hotKeyDict[WineHotKeyModFlagsKey] unsignedIntValue];
            event->hotkey_press.keycode     = [hotKeyDict[WineHotKeyKeyCodeKey] unsignedIntValue];
            event->hotkey_press.time_ms     = [[WineApplicationController sharedController] ticksForEventTime:time];

            [self postEvent:event];

            macdrv_release_event(event);
        }

        return hotKeyDict != nil;
    }

    static OSStatus HotKeyHandler(EventHandlerCallRef nextHandler, EventRef theEvent, void* userData)
    {
        WineEventQueue* self = userData;
        OSStatus status;
        EventHotKeyID hotKeyID;

        status = GetEventParameter(theEvent, kEventParamDirectObject, typeEventHotKeyID, NULL,
                                   sizeof(hotKeyID), NULL, &hotKeyID);
        if (status == noErr)
        {
            if (hotKeyID.signature != WineHotKeySignature ||
                ![self postHotKeyEvent:hotKeyID.id time:GetEventTime(theEvent)])
                status = eventNotHandledErr;
        }

        return status;
    }

    - (void) unregisterHotKey:(unsigned int)vkey modFlags:(unsigned int)modFlags
    {
        NSArray<NSNumber *> *winIDPair = @[@(vkey), @(modFlags)];
        NSDictionary<NSString *, id> *hotKeyDict = hotKeysByWinID[winIDPair];
        if (hotKeyDict)
        {
            EventHotKeyRef hotKeyRef = [hotKeyDict[WineHotKeyCarbonRefKey] pointerValue];
            NSNumber* macID = hotKeyDict[WineHotKeyMacIDKey];

            UnregisterEventHotKey(hotKeyRef);
            [hotKeysByMacID removeObjectForKey:macID];
            [hotKeysByWinID removeObjectForKey:winIDPair];
        }
    }

    - (int) registerHotKey:(UInt32)keyCode modifiers:(UInt32)modifiers vkey:(unsigned int)vkey modFlags:(unsigned int)modFlags
    {
        static EventHandlerRef handler;
        static UInt32 hotKeyNumber;
        OSStatus status;
        NSArray<NSNumber *> *winIDPair;
        EventHotKeyID hotKeyID;
        EventHotKeyRef hotKeyRef;
        NSDictionary<NSString *, id> *hotKeyDict;

        if (!handler)
        {
            EventTypeSpec eventType = { kEventClassKeyboard, kEventHotKeyPressed };
            status = InstallApplicationEventHandler(HotKeyHandler, 1, &eventType, self, &handler);
            if (status != noErr)
            {
                ERR(@"InstallApplicationEventHandler() failed: %d\n", status);
                handler = NULL;
                return MACDRV_HOTKEY_FAILURE;
            }
        }

        if (!hotKeysByMacID && !(hotKeysByMacID = [[NSMutableDictionary alloc] init]))
            return MACDRV_HOTKEY_FAILURE;
        if (!hotKeysByWinID && !(hotKeysByWinID = [[NSMutableDictionary alloc] init]))
            return MACDRV_HOTKEY_FAILURE;

        winIDPair = @[@(vkey), @(modFlags)];
        if (hotKeysByWinID[winIDPair])
            return MACDRV_HOTKEY_ALREADY_REGISTERED;

        hotKeyID.signature  = WineHotKeySignature;
        hotKeyID.id         = hotKeyNumber++;

        status = RegisterEventHotKey(keyCode, modifiers, hotKeyID, GetApplicationEventTarget(),
                                     kEventHotKeyExclusive, &hotKeyRef);
        if (status == eventHotKeyExistsErr)
            return MACDRV_HOTKEY_ALREADY_REGISTERED;
        if (status != noErr)
        {
            ERR(@"RegisterEventHotKey() failed: %d\n", status);
            return MACDRV_HOTKEY_FAILURE;
        }

        hotKeyDict =
        @{
                WineHotKeyMacIDKey : @(hotKeyID.id),
                 WineHotKeyVkeyKey : @(vkey),
             WineHotKeyModFlagsKey : @(modFlags),
              WineHotKeyKeyCodeKey : @(keyCode),
            WineHotKeyCarbonRefKey : [NSValue valueWithPointer:hotKeyRef]
        };
        hotKeysByMacID[@(hotKeyID.id)] = hotKeyDict;
        hotKeysByWinID[winIDPair] = hotKeyDict;

        return MACDRV_HOTKEY_SUCCESS;
    }


/***********************************************************************
 *              OnMainThread
 *
 * Run a block on the main thread synchronously.
 */
/* ★★★★★ MacRunner 2026-09-02 — OnMainThread С САМОГО ГЛАВНОГО ПОТОКА COCOA: ВЫПОЛНЯТЬ НА МЕСТЕ.
 *
 * КОРЕНЬ ТУПИКА Diablo (0 кадров; главный поток игры крутит wined3d_cs_mt_finish, 7,7 млн
 * NtDelayExecution за 220 с; поток wined3d_cs молчит после WINED3D_CS_OP_CALLBACK =
 * wined3d_device_gl_delete_opengl_contexts_cs). Нативный sample зависшего процесса, три потока:
 *   главный поток Cocoa:  -[WineContentView viewWillDraw] -> macdrv_update_opengl_context
 *                         -> OnMainThread -> dispatch_semaphore_wait      ЖДЁТ САМ СЕБЯ
 *   поток wined3d_cs:     wglDeleteContext -> macdrv_dispose_opengl_context
 *                         -> -[WineOpenGLContext setView:] -> OnMainThread -> semaphore_wait
 *                                                                          ждёт главный поток Cocoa
 *   главный поток Win32:  wined3d_cs_mt_finish -> NtDelayExecution        ждёт поток wined3d_cs
 * viewWillDraw зовёт macdrv_update_opengl_context ИЗ главного потока (правка 2026-07-29,
 * 73a7cd133; в эталоне viewWillDraw лишь ставит needsUpdate). Тот приходит сюда, а у главного
 * потока Cocoa нет очереди Wine (queue == nil) -> ветка семафора -> ожидание блока, который
 * выполнит только этот же поток -> вечно. Лечим ПРИЧИНУ здесь, а не в месте вызова: если мы уже
 * на главном потоке — блок выполняется сразу (это и есть семантика «на главном потоке»), и все
 * места вызова покрыты разом.
 *
 * ★ 2026-09-04, ГЕЙТ СНЯТ — ЛЕЧЕНИЕ БЕЗУСЛОВНО. `MACRUNNER_MAC_ONMAINTHREAD_INLINE`
 * (умолчание ВКЛ) был лесами под парный замер. Замер сделан и записан:
 * reports/research/DIABLO-ТУПИК-ONMAINTHREAD-20260902/ИТОГ.md — режим A («0 кадров, код 142»)
 * числится ПОЧИНЕННЫМ этим лечением, все три звена тупика сняты нативным `sample`, а рука ВЫКЛ
 * печатала `macrunner-onmainthread-САМОЖДАНИЕ` и стояла насмерть до конца бюджета.
 * Единственное действие выключателя — вернуть доказанный вечный тупик; такая ветка не лечит
 * ничего и при этом выглядит выбором. Ветка ВЫКЛ и функция-гейт удалены (правило проекта
 * «гейт — это леса, а не дом»).
 *
 * Веха `macrunner-onmainthread-inline` ОСТАВЛЕНА: она отвечает на ДРУГОЙ вопрос — исполнялось
 * ли лечение в этом прогоне вообще. Ответ бывает «ноль» (здоровый прогон kan-48: ни одного
 * вызова OnMainThread с главного потока Cocoa), и без вехи «ноль» неотличим от «прибора нет». */
void OnMainThread(dispatch_block_t block)
{
    if ([NSThread isMainThread])
    {
        static int n_inline;

        if (++n_inline <= 4)
        {
            fprintf(stderr, "macrunner-onmainthread-inline: n=%d главный поток Cocoa звал "
                    "OnMainThread — выполнено на месте, без ожидания себя\n", n_inline);
            fflush(stderr);
        }
        block();
        return;
    }
@autoreleasepool
{
    NSMutableDictionary* threadDict = [[NSThread currentThread] threadDictionary];
    WineEventQueue* queue = threadDict[WineEventQueueThreadDictionaryKey];
    dispatch_semaphore_t semaphore = NULL;
    __block BOOL finished;

    if (trace_ui_input_enabled())
    {
        fprintf(stderr,
                "macrunner-ui-input: stage=onmainthread_enter pid=%d tid=%llu queue=%p is_main=%d\n",
                getpid(), trace_ui_input_tid(), queue, [NSThread isMainThread]);
        fflush(stderr);
    }

    if (!queue)
    {
        semaphore = dispatch_semaphore_create(0);
        dispatch_retain(semaphore);
    }

    finished = FALSE;
    OnMainThreadAsync(^{
        block();
        finished = TRUE;
        if (queue)
            [queue signalEventAvailable];
        else
        {
            dispatch_semaphore_signal(semaphore);
            dispatch_release(semaphore);
        }
    });

    if (queue)
    {
        while (!finished)
        {
            @autoreleasepool
            {
                MacDrvEvent* macDrvEvent;
                struct kevent kev;

                while (!finished &&
                       (macDrvEvent = [queue getEventMatchingMask:event_mask_for_type(QUERY_EVENT)]))
                {
                    queue->event_handler(macDrvEvent->event);
                }

                if (!finished)
                    kevent(queue->kq, NULL, 0, &kev, 1, NULL);
            }
        }

    }
    else
    {
        dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
        dispatch_release(semaphore);
    }

    if (trace_ui_input_enabled())
    {
        fprintf(stderr,
                "macrunner-ui-input: stage=onmainthread_exit pid=%d tid=%llu queue=%p finished=%d\n",
                getpid(), trace_ui_input_tid(), queue, finished);
        fflush(stderr);
    }
}
}


/***********************************************************************
 *              macdrv_create_event_queue
 *
 * Register this thread with the application on the main thread, and set
 * up an event queue on which it can deliver events to this thread.
 */
macdrv_event_queue macdrv_create_event_queue(macdrv_event_handler handler)
{
@autoreleasepool
{
    NSMutableDictionary* threadDict = [[NSThread currentThread] threadDictionary];

    WineEventQueue* queue = threadDict[WineEventQueueThreadDictionaryKey];
    if (!queue)
    {
        queue = [[[WineEventQueue alloc] initWithEventHandler:handler] autorelease];
        if (queue)
        {
            if ([[WineApplicationController sharedController] registerEventQueue:queue])
                [threadDict setObject:queue forKey:WineEventQueueThreadDictionaryKey];
            else
                queue = nil;
        }
    }

    if (trace_ui_input_enabled())
    {
        fprintf(stderr,
                "macrunner-ui-input: stage=queue_create pid=%d tid=%llu queue=%p read_fd=%d write_fd=%d is_main=%d registered=%d\n",
                getpid(), trace_ui_input_tid(), queue, queue ? queue->fds[0] : -1,
                queue ? queue->fds[1] : -1, [NSThread isMainThread], queue != nil);
        fflush(stderr);
    }

    return (macdrv_event_queue)queue;
}
}

/***********************************************************************
 *              macdrv_destroy_event_queue
 *
 * Tell the application that this thread is exiting and destroy the
 * associated event queue.
 */
void macdrv_destroy_event_queue(macdrv_event_queue queue)
{
@autoreleasepool
{
    WineEventQueue* q = (WineEventQueue*)queue;
    NSMutableDictionary* threadDict = [[NSThread currentThread] threadDictionary];

    if (trace_ui_input_enabled())
    {
        fprintf(stderr,
                "macrunner-ui-input: stage=queue_destroy pid=%d tid=%llu queue=%p read_fd=%d write_fd=%d is_main=%d\n",
                getpid(), trace_ui_input_tid(), q, q ? q->fds[0] : -1,
                q ? q->fds[1] : -1, [NSThread isMainThread]);
        fflush(stderr);
    }

    [[WineApplicationController sharedController] unregisterEventQueue:q];
    [threadDict removeObjectForKey:WineEventQueueThreadDictionaryKey];
}
}

/***********************************************************************
 *              macdrv_get_event_queue_fd
 *
 * Get the file descriptor whose readability signals that there are
 * events on the event queue.
 */
int macdrv_get_event_queue_fd(macdrv_event_queue queue)
{
    WineEventQueue* q = (WineEventQueue*)queue;
    return q->fds[0];
}

/***********************************************************************
 *              macdrv_copy_event_from_queue
 *
 * Pull an event matching the event mask from the event queue and store
 * it in the event record pointed to by the event parameter.  If a
 * matching event was found, return non-zero; otherwise, return 0.
 *
 * The caller is responsible for calling macdrv_release_event on any
 * event returned by this function.
 */
int macdrv_copy_event_from_queue(macdrv_event_queue queue,
        macdrv_event_mask mask, macdrv_event **event)
{
@autoreleasepool
{
    WineEventQueue* q = (WineEventQueue*)queue;

    MacDrvEvent* macDrvEvent = [q getEventMatchingMask:mask];
    if (macDrvEvent)
        *event = macdrv_retain_event(macDrvEvent->event);

    if (trace_ui_input_enabled() && macDrvEvent)
    {
        fprintf(stderr,
                "macrunner-ui-input: stage=copy_event_from_queue queue=%p mask=0x%llx event=%p type=%d\n",
                q, (unsigned long long)mask, macDrvEvent->event, macDrvEvent->event->type);
        fflush(stderr);
    }

    return (macDrvEvent != nil);
}
}

/***********************************************************************
 *              macdrv_create_event
 */
macdrv_event* macdrv_create_event(int type, WineWindow* window)
{
    macdrv_event *event;

    event = calloc(1, sizeof(*event));
    event->refs = 1;
    event->deliver = INT_MAX;
    event->type = type;
    event->window = (macdrv_window)[window retain];
    return event;
}

/***********************************************************************
 *              macdrv_post_event
 */
void macdrv_post_event(macdrv_event_queue queue, macdrv_event *event)
{
@autoreleasepool
{
    if (!queue || !event) return;
    [(WineEventQueue*)queue postEvent:event];
}
}

/***********************************************************************
 *              macdrv_post_event_for_window
 */
void macdrv_post_event_for_window(int type, macdrv_window window)
{
@autoreleasepool
{
    macdrv_event *event;
    WineWindow *wine_window = (WineWindow *)window;

    if (!wine_window) return;
    if (!(event = macdrv_create_event(type, wine_window))) return;
    [[wine_window queue] postEvent:event];
    macdrv_release_event(event);
}
}

/***********************************************************************
 *              macdrv_retain_event
 */
macdrv_event* macdrv_retain_event(macdrv_event *event)
{
    OSAtomicIncrement32Barrier(&event->refs);
    return event;
}

/***********************************************************************
 *              macdrv_release_event
 *
 * Decrements the reference count of an event.  If the count falls to
 * zero, cleans up any resources, such as allocated memory or retained
 * objects, held by the event and deallocates it
 */
void macdrv_release_event(macdrv_event *event)
{
@autoreleasepool
{
    if (OSAtomicDecrement32Barrier(&event->refs) <= 0)
    {
        switch (event->type)
        {
            case IM_SET_TEXT:
                if (event->im_set_text.text)
                    CFRelease(event->im_set_text.text);
                break;
            case KEYBOARD_CHANGED:
                CFRelease(event->keyboard_changed.uchr);
                CFRelease(event->keyboard_changed.input_source);
                break;
            case QUERY_EVENT:
            case QUERY_EVENT_NO_PREEMPT_WAIT:
                macdrv_release_query(event->query_event.query);
                break;
            case WINDOW_GOT_FOCUS:
                [(NSMutableSet*)event->window_got_focus.tried_windows release];
                break;
        }

        [(WineWindow*)event->window release];
        free(event);
    }
}
}

/***********************************************************************
 *              macdrv_create_query
 */
macdrv_query* macdrv_create_query(void)
{
    macdrv_query *query;

    query = calloc(1, sizeof(*query));
    query->refs = 1;
    return query;
}

/***********************************************************************
 *              macdrv_retain_query
 */
macdrv_query* macdrv_retain_query(macdrv_query *query)
{
    OSAtomicIncrement32Barrier(&query->refs);
    return query;
}

/***********************************************************************
 *              macdrv_release_query
 */
void macdrv_release_query(macdrv_query *query)
{
    if (OSAtomicDecrement32Barrier(&query->refs) <= 0)
    {
        switch (query->type)
        {
            case QUERY_DRAG_DROP_ENTER:
            case QUERY_DRAG_DROP_LEAVE:
            case QUERY_DRAG_DROP_DRAG:
            case QUERY_DRAG_DROP_DROP:
                if (query->drag_drop.pasteboard)
                    CFRelease(query->drag_drop.pasteboard);
                break;
            case QUERY_PASTEBOARD_DATA:
                if (query->pasteboard_data.type)
                    CFRelease(query->pasteboard_data.type);
                break;
        }
        [(WineWindow*)query->window release];
        free(query);
    }
}

/***********************************************************************
 *              macdrv_set_query_done
 */
void macdrv_set_query_done(macdrv_query *query)
{
    macdrv_retain_query(query);

    OnMainThreadAsync(^{
        NSEvent* event;

        query->done = TRUE;
        macdrv_release_query(query);

        event = [NSEvent otherEventWithType:NSEventTypeApplicationDefined
                                   location:NSZeroPoint
                              modifierFlags:0
                                  timestamp:[[NSProcessInfo processInfo] systemUptime]
                               windowNumber:0
                                    context:nil
                                    subtype:WineApplicationEventWakeQuery
                                      data1:0
                                      data2:0];
        [NSApp postEvent:event atStart:TRUE];
    });
}

@end


/***********************************************************************
 *              macdrv_register_hot_key
 */
int macdrv_register_hot_key(macdrv_event_queue q, unsigned int vkey, unsigned int mod_flags,
                            unsigned int keycode, unsigned int modifiers)
{
    WineEventQueue* queue = (WineEventQueue*)q;
    __block int ret;

    OnMainThread(^{
        ret = [queue registerHotKey:keycode modifiers:modifiers vkey:vkey modFlags:mod_flags];
    });

    return ret;
}


/***********************************************************************
 *              macdrv_unregister_hot_key
 */
void macdrv_unregister_hot_key(macdrv_event_queue q, unsigned int vkey, unsigned int mod_flags)
{
    WineEventQueue* queue = (WineEventQueue*)q;

    OnMainThreadAsync(^{
        [queue unregisterHotKey:vkey modFlags:mod_flags];
    });
}
