/*
 * MacRunner i386-on-arm64 HyperBridge CPU module.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "rtlsupportapi.h"

#include "xtajit_private.h"
#include "hb_result.h"
#include "wine/asm.h"
#include "wine/debug.h"

/* ★★★★★ ИТЕРАЦИЯ 118 — ОДНА ПРОВЕРКА НА ВЕСЬ КЛАСС ЗОНДОВ.
 *
 * Итерация 117: мой зонд обхода кадров ронял прогон, потому что `guest32_host_ptr`
 * отдаёт НЕНУЛЕВОЙ адрес для любого ненулевого гостевого значения, и проверка
 * `if (!ptr)` пропускает мусор. Перебор по `cpu.c` нашёл ДЕВЯТЬ мест того же вида.
 * Чинить по одному — значит вернуться сюда ещё семь раз, поэтому общая проверка:
 * гостевой адрес должен быть выше охранной зоны, выровнен на слово и не у самого
 * верха адресного пространства. */
static inline BOOL mr_guest_addr_ok( ULONG v )
{
    return v >= 0x10000u && !(v & 3u) && v <= 0xfffffff0u;
}

void WINAPI Wow64PassExceptionToGuest( EXCEPTION_POINTERS *ptrs );

static BYTE syscall_bop[] = { 0x0f, 0xff };
static BYTE unix_bop[] = { 0x0f, 0xfe };
static BYTE *syscall_bop_guest;
static BYTE *unix_bop_guest;

#define XTAJIT_BRIDGE_STACK_SIZE  (64 * 1024 * 1024)
#define XTAJIT_BRIDGE_SEH_SLACK   0x10000
#define XTAJIT_BRIDGE_STACK_SLACK 0x200
#define XTAJIT_TLS_TEB32_HOST     13
#define XTAJIT_TLS_BRIDGE_ACTIVE  15
#define XTAJIT_TLS_BRIDGE_STACK   16
#define XTAJIT_TLS_BRIDGE_SIZE    17
#define XTAJIT_WOW64_NTCALLBACKRETURN 0x0005
#define XTAJIT_TEB_SYSCALL_FRAME_OFFSET 0x378
#define XTAJIT_SYSCALL_FRAME_PREV_OFFSET 0x110
#define XTAJIT_NESTED_CALLBACK_STACK_SLACK 0x10000
#define XTAJIT_NESTED_CALLBACK_REENTER_GUARD 0x100000
#define XTAJIT_PENDING_I386_CONTEXT_SLOTS 64
#define XTAJIT_WOW64_TLS_GUEST32_BASE (WOW64_TLS_MAX_NUMBER - 1)

#ifdef __aarch64__
typedef NTSTATUS (WINAPI *xtajit_wow64_syscall_func)( UINT num, UINT *args );
typedef void (WINAPI *xtajit_void_func)(void *);
extern NTSTATUS xtajit_arm64_call_wow64_syscall( UINT num, UINT *args, void *stack_top,
                                                 TEB *teb, xtajit_wow64_syscall_func func );
extern NTSTATUS xtajit_arm64_call_wow64_syscall_current_stack( UINT num, UINT *args, TEB *teb,
                                                               xtajit_wow64_syscall_func func );
extern void xtajit_arm64_call_void( void *stack_top, TEB *teb, xtajit_void_func func, void *arg );
/* MacRunner 2026-08-23, итерация 2687 — кадр вокруг юникс-вызова (корень 2686). */
extern NTSTATUS xtajit_arm64_call_unix_frame( UINT64 handle, UINT id, void *args, TEB *teb, void *func );
/* MacRunner 2026-08-23, лейн ЛЕСТНИЦА, итерация 2682 — лекарство по корню 2680/2681. */
extern NTSTATUS xtajit_arm64_call_wow64_syscall_current_stack_frame( UINT num, UINT *args, TEB *teb,
                                                                     void *func );

__ASM_GLOBAL_FUNC( xtajit_arm64_call_wow64_syscall,
                   "stp x29, x30, [sp, #-0xd0]!\n\t"
                   "mov x29, sp\n\t"
                   "stp x19, x20, [x29, #0x10]\n\t"
                   "stp x21, x22, [x29, #0x20]\n\t"
                   "stp x23, x24, [x29, #0x30]\n\t"
                   "stp x25, x26, [x29, #0x40]\n\t"
                   "stp x27, x28, [x29, #0x50]\n\t"
                   "stp d8,  d9,  [x29, #0x60]\n\t"
                   "stp d10, d11, [x29, #0x70]\n\t"
                   "stp d12, d13, [x29, #0x80]\n\t"
                   "stp d14, d15, [x29, #0x90]\n\t"
                   "str x18, [x29, #0xc0]\n\t"
                   "mov x20, x4\n\t"
                   "mov x19, x3\n\t"
                   "mov x22, x2\n\t"
                   "mov x18, x19\n\t"
                   "ldr x7, [x19, #0x378]\n\t"    /* previous thread_data->syscall_frame */
                   "str x7, [x29, #0xa0]\n\t"
                   "mrs x8, fpcr\n\t"
	                   "mrs x9, fpsr\n\t"
	                   "bfi x8, x9, #0, #32\n\t"
	                   "ldr x9, [x19]\n\t"            /* teb->Tib.ExceptionList */
	                   "stp x8, x9, [x29, #0xb0]\n\t"
	                   "mov x10, #-1\n\t"
	                   "str x10, [x19]\n\t"           /* hide guest32 SEH frames from native SEH */
	                   "sub x5, sp, #0x330\n\t"       /* syscall_frame on the caller stack */
	                   "str x5, [x19, #0x378]\n\t"    /* thread_data->syscall_frame */
	                   "str x19, [x5, #0x90]\n\t"     /* frame->x18 / TEB */
                   "str x30, [x5, #0xf0]\n\t"     /* frame->lr */
                   "add x8, x22, #0x10, lsl #12\n\t"
                   "str x8, [x5, #0xf8]\n\t"      /* frame->sp for KeUserModeCallback */
                   "str x20, [x5, #0x100]\n\t"    /* frame->pc / native target */
                   "str wzr, [x5, #0x10c]\n\t"    /* frame->restore_flags */
                   "add x8, x29, #0xd0\n\t"
                   "stp x7, x8, [x5, #0x110]\n\t" /* frame->prev_frame,syscall_cfa */
                   "mov sp, x22\n\t"
                   "blr x20\n\t"
                   "mov x23, x0\n\t"
                   "mov sp, x29\n\t"
                   "ldr x7, [x29, #0xa0]\n\t"
                   "str x7, [x19, #0x378]\n\t"    /* restore previous syscall_frame */
                   "ldp x8, x9, [x29, #0xb0]\n\t"
                   "str x9, [x19]\n\t"            /* restore teb->Tib.ExceptionList */
                   "msr fpcr, x8\n\t"
                   "lsr x8, x8, #32\n\t"
                   "msr fpsr, x8\n\t"
                   "ldr x18, [x29, #0xc0]\n\t"
                   "mov x0, x23\n\t"
                   "ldp d14, d15, [x29, #0x90]\n\t"
                   "ldp d12, d13, [x29, #0x80]\n\t"
                   "ldp d10, d11, [x29, #0x70]\n\t"
                   "ldp d8,  d9,  [x29, #0x60]\n\t"
                   "ldp x27, x28, [x29, #0x50]\n\t"
                   "ldp x25, x26, [x29, #0x40]\n\t"
                   "ldp x23, x24, [x29, #0x30]\n\t"
                   "ldp x21, x22, [x29, #0x20]\n\t"
                   "ldp x19, x20, [x29, #0x10]\n\t"
                   "ldp x29, x30, [sp], #0xd0\n\t"
                   "ret" )

__ASM_GLOBAL_FUNC( xtajit_arm64_call_wow64_syscall_current_stack,
                   "stp x29, x30, [sp, #-0xd0]!\n\t"
                   "mov x29, sp\n\t"
                   "stp x19, x20, [x29, #0x10]\n\t"
                   "stp x21, x22, [x29, #0x20]\n\t"
                   "stp x23, x24, [x29, #0x30]\n\t"
                   "stp x25, x26, [x29, #0x40]\n\t"
                   "stp x27, x28, [x29, #0x50]\n\t"
                   "stp d8,  d9,  [x29, #0x60]\n\t"
	                   "stp d10, d11, [x29, #0x70]\n\t"
	                   "stp d12, d13, [x29, #0x80]\n\t"
	                   "stp d14, d15, [x29, #0x90]\n\t"
	                   "mov x19, x2\n\t"
	                   "str x18, [x29, #0xa8]\n\t"
	                   "mov x18, x19\n\t"
	                   "ldr x20, [x19]\n\t"           /* teb->Tib.ExceptionList */
	                   "str x20, [x29, #0xa0]\n\t"
	                   "mov x20, #-1\n\t"
	                   "str x20, [x19]\n\t"           /* hide guest32 SEH frames from native SEH */
	                   "blr x3\n\t"
	                   "ldr x20, [x29, #0xa0]\n\t"
	                   "str x20, [x19]\n\t"           /* restore teb->Tib.ExceptionList */
	                   "ldr x18, [x29, #0xa8]\n\t"
	                   "ldp d14, d15, [x29, #0x90]\n\t"
                   "ldp d12, d13, [x29, #0x80]\n\t"
                   "ldp d10, d11, [x29, #0x70]\n\t"
                   "ldp d8,  d9,  [x29, #0x60]\n\t"
                   "ldp x27, x28, [x29, #0x50]\n\t"
                   "ldp x25, x26, [x29, #0x40]\n\t"
                   "ldp x23, x24, [x29, #0x30]\n\t"
                   "ldp x21, x22, [x29, #0x20]\n\t"
                   "ldp x19, x20, [x29, #0x10]\n\t"
                   "ldp x29, x30, [sp], #0xd0\n\t"
                   "ret" )

/* ★★★ MacRunner 2026-08-23, лейн ЛЕСТНИЦА, итерация 2682 — ПЕРЕХОДНИК БЕЗ СМЕНЫ СТЕКА, НО С КАДРОМ.
 *
 * Корень (2680/2681): смертельный обратный вызов приходит из `handle_bop_context` внутри
 * `BTCpuSimulate_impl`, и служба доходит до `KeUserModeCallback` через
 * `xtajit_arm64_call_wow64_syscall_current_stack`. Этот вариант, в отличие от переходника со
 * сменой стека, НЕ заводит `thread_data->syscall_frame`: у него нет ни `frame->sp` (строка 83
 * в соседнем переходнике, единственное вхождение `0xf8` в файле), ни `frame->lr`, ни
 * `frame->pc`, ни `prev_frame`. `Wow64KiUserCallbackDispatcher` на возврате из оконной
 * процедуры восстанавливает гостя ИМЕННО по `frame->sp` — и берёт его из чужого, устаревшего
 * кадра. Отсюда `eip=0000000d` и `info0=8` (нарушение исполнения), а дальше обработчик игры
 * уходит в `ExitProcess` с кодом 0.
 *
 * Здесь тот же кадр заводится БЕЗ смены стека: `frame->sp` берётся из текущего `sp`, потому
 * что стек мы как раз и не меняем. Прежний `syscall_frame` сохраняется и возвращается на
 * выходе, как в переходнике со сменой стека (там строки 69-70 и 92-93).
 *
 * Свободные слоты кадра 0xd0 у `_current_stack`: 0xb0..0xc8 (0x90/0x98 заняты d14/d15,
 * 0xa0 — ExceptionList, 0xa8 — x18). Прежний syscall_frame кладу в 0xb0.
 *
 * Гейт `MACRUNNER_HB_BOP_SYSCALL_FRAME`, умолчание 0: правка трогает ручной ассемблер на пути
 * КАЖДОГО системного вызова гостя, и включать её без прогона нельзя. */
__ASM_GLOBAL_FUNC( xtajit_arm64_call_wow64_syscall_current_stack_frame,
                   "stp x29, x30, [sp, #-0xd0]!\n\t"
                   "mov x29, sp\n\t"
                   "stp x19, x20, [x29, #0x10]\n\t"
                   "stp x21, x22, [x29, #0x20]\n\t"
                   "stp x23, x24, [x29, #0x30]\n\t"
                   "stp x25, x26, [x29, #0x40]\n\t"
                   "stp x27, x28, [x29, #0x50]\n\t"
                   "stp d8,  d9,  [x29, #0x60]\n\t"
                   "stp d10, d11, [x29, #0x70]\n\t"
                   "stp d12, d13, [x29, #0x80]\n\t"
                   "stp d14, d15, [x29, #0x90]\n\t"
                   "mov x19, x2\n\t"            /* teb */
                   "mov x20, x3\n\t"            /* native target */
                   "str x18, [x29, #0xa8]\n\t"
                   "mov x18, x19\n\t"
                   "ldr x7, [x19, #0x378]\n\t"   /* previous thread_data->syscall_frame */
                   "str x7, [x29, #0xb0]\n\t"
                   "ldr x21, [x19]\n\t"          /* teb->Tib.ExceptionList */
                   "str x21, [x29, #0xa0]\n\t"
                   "mov x21, #-1\n\t"
                   "str x21, [x19]\n\t"          /* hide guest32 SEH frames from native SEH */
                   "sub x5, sp, #0x330\n\t"      /* syscall_frame on the CURRENT stack */
                   "str x5, [x19, #0x378]\n\t"   /* thread_data->syscall_frame */
                   "str x19, [x5, #0x90]\n\t"    /* frame->x18 / TEB */
                   "str x30, [x5, #0xf0]\n\t"    /* frame->lr */
                   "mov x8, sp\n\t"
                   "str x8, [x5, #0xf8]\n\t"     /* frame->sp for KeUserModeCallback */
                   "str x20, [x5, #0x100]\n\t"   /* frame->pc / native target */
                   "str wzr, [x5, #0x10c]\n\t"   /* frame->restore_flags */
                   "add x8, x29, #0xd0\n\t"
                   "stp x7, x8, [x5, #0x110]\n\t" /* frame->prev_frame,syscall_cfa */
                   "blr x20\n\t"
                   "mov x23, x0\n\t"
                   "ldr x7, [x29, #0xb0]\n\t"
                   "str x7, [x19, #0x378]\n\t"   /* restore previous syscall_frame */
                   "ldr x21, [x29, #0xa0]\n\t"
                   "str x21, [x19]\n\t"          /* restore teb->Tib.ExceptionList */
                   "ldr x18, [x29, #0xa8]\n\t"
                   "mov x0, x23\n\t"
                   "ldp d14, d15, [x29, #0x90]\n\t"
                   "ldp d12, d13, [x29, #0x80]\n\t"
                   "ldp d10, d11, [x29, #0x70]\n\t"
                   "ldp d8,  d9,  [x29, #0x60]\n\t"
                   "ldp x27, x28, [x29, #0x50]\n\t"
                   "ldp x25, x26, [x29, #0x40]\n\t"
                   "ldp x23, x24, [x29, #0x30]\n\t"
                   "ldp x21, x22, [x29, #0x20]\n\t"
                   "ldp x19, x20, [x29, #0x10]\n\t"
                   "ldp x29, x30, [sp], #0xd0\n\t"
                   "ret" )

/* ★★★ MacRunner 2026-08-23, лейн ЛЕСТНИЦА, итерация 2687 — КАДР ВОКРУГ ЮНИКС-ВЫЗОВА.
 *
 * Корень (2686, дизассемблер + DWARF): смертельный обратный вызов приходит из ЮНИКС-BOP —
 * `handle_bop_context + 0x1a4` это возврат из `__wine_unix_call` (cpu.c:2496), а не из
 * диспетчера системных вызовов. Юникс-сторона `win32u` делает `KeUserModeCallback`, а кадр
 * `thread_data->syscall_frame` на этом пути не заводит НИКТО: в устройстве wine его ставят
 * только переходники СИСТЕМНОГО вызова. На возврате из оконной процедуры восстанавливать
 * нечего -> `eip=0000000d`, `info0=8`.
 *
 * Здесь тот же кадр, что в переходнике со сменой стека, но вокруг вызова с ТРЕМЯ аргументами
 * и БЕЗ смены стека: x0=handle, x1=id, x2=args, x3=teb, x4=func.
 *
 * ★ Сознательно НЕ трогаю `teb->Tib.ExceptionList`: соседние переходники его прячут, но это
 * свойство системного пути, а мне нужна ОДНА переменная — наличие кадра. */
__ASM_GLOBAL_FUNC( xtajit_arm64_call_unix_frame,
                   "stp x29, x30, [sp, #-0xd0]!\n\t"
                   "mov x29, sp\n\t"
                   "stp x19, x20, [x29, #0x10]\n\t"
                   "stp x21, x22, [x29, #0x20]\n\t"
                   "stp x23, x24, [x29, #0x30]\n\t"
                   "stp x25, x26, [x29, #0x40]\n\t"
                   "stp x27, x28, [x29, #0x50]\n\t"
                   "stp d8,  d9,  [x29, #0x60]\n\t"
                   "stp d10, d11, [x29, #0x70]\n\t"
                   "stp d12, d13, [x29, #0x80]\n\t"
                   "stp d14, d15, [x29, #0x90]\n\t"
                   "mov x19, x3\n\t"             /* teb */
                   "mov x20, x4\n\t"             /* func */
                   "mov x24, x0\n\t"             /* handle */
                   "mov x25, x1\n\t"             /* id */
                   "mov x26, x2\n\t"             /* args */
                   "str x18, [x29, #0xa8]\n\t"
                   "mov x18, x19\n\t"
                   "ldr x7, [x19, #0x378]\n\t"    /* previous thread_data->syscall_frame */
                   "str x7, [x29, #0xb0]\n\t"
                   "sub x5, sp, #0x330\n\t"
                   /* ★ Итерация 2690: ОБНУЛИТЬ ВСЮ ОБЛАСТЬ КАДРА. Замер 2689 показал, что
                    * диспетчер кадр НАХОДИТ (гостевой отказ eip=0000000d сменился хозяйским
                    * SIGSEGV с pc=0x0, подпись побайтно одинакова в двух прогонах), но
                    * восстанавливает из полей, которых я не заполняла: `sub x5, sp, #0x330`
                    * указывает на НЕинициализированную память. Переходник системного вызова
                    * заполняет те же шесть полей, но его кадр ложится в область, где остальное
                    * уже согласовано. Здесь этого нет — обнуляем 0x330 байт явно. */
                   "mov x6, x5\n\t"
                   "mov x9, #0x330\n\t"
                   "1:\n\t"
                   "str xzr, [x6], #8\n\t"
                   "subs x9, x9, #8\n\t"
                   "b.ne 1b\n\t"
                   "str x5, [x19, #0x378]\n\t"    /* thread_data->syscall_frame */
                   "str x19, [x5, #0x90]\n\t"     /* frame->x18 / TEB */
                   "str x30, [x5, #0xf0]\n\t"     /* frame->lr */
                   /* ★★ Итерация 2691 — СТЕК ОБРАТНОГО ВЫЗОВА НЕ ДОЛЖЕН ПЕРЕСЕКАТЬСЯ С КАДРОМ.
                    * Было `frame->sp = sp`, а кадр лежит в [sp-0x330, sp): первый же push
                    * обратного вызова попадает ВНУТРЬ кадра и затирает то, через что вызов
                    * обязан вернуться. Отсюда `pc=0x0` в замере 2689 — подпись побайтно
                    * одинаковая в двух прогонах. В переходнике со сменой стека этой беды нет:
                    * там кадр на стеке вызывающего, а `frame->sp` — отдельный мостовой стек.
                    * Здесь даём обратному вызову расти ВНИЗ от основания кадра. */
                   "mov x8, x5\n\t"
                   "str x8, [x5, #0xf8]\n\t"      /* frame->sp for KeUserModeCallback */
                   "str x20, [x5, #0x100]\n\t"    /* frame->pc */
                   "str wzr, [x5, #0x10c]\n\t"    /* frame->restore_flags */
                   "add x8, x29, #0xd0\n\t"
                   "stp x7, x8, [x5, #0x110]\n\t" /* frame->prev_frame,syscall_cfa */
                   "mov x0, x24\n\t"
                   "mov x1, x25\n\t"
                   "mov x2, x26\n\t"
                   "blr x20\n\t"
                   "mov x23, x0\n\t"
                   "ldr x7, [x29, #0xb0]\n\t"
                   "str x7, [x19, #0x378]\n\t"    /* restore previous syscall_frame */
                   "ldr x18, [x29, #0xa8]\n\t"
                   "mov x0, x23\n\t"
                   "ldp d14, d15, [x29, #0x90]\n\t"
                   "ldp d12, d13, [x29, #0x80]\n\t"
                   "ldp d10, d11, [x29, #0x70]\n\t"
                   "ldp d8,  d9,  [x29, #0x60]\n\t"
                   "ldp x27, x28, [x29, #0x50]\n\t"
                   "ldp x25, x26, [x29, #0x40]\n\t"
                   "ldp x23, x24, [x29, #0x30]\n\t"
                   "ldp x21, x22, [x29, #0x20]\n\t"
                   "ldp x19, x20, [x29, #0x10]\n\t"
                   "ldp x29, x30, [sp], #0xd0\n\t"
                   "ret" )

/* ★★★★★ MacRunner 2026-08-30, лейн УСТАНОВЩИКИ — ДАННЫЕ РАЗМОТКИ ДЛЯ ПЕРЕКЛЮЧАТЕЛЯ СТЕКА.
 *
 * Функция МЕНЯЕТ sp (`mov sp, x0` ниже) и зовёт гостя через `blr x19`. Директив пролога
 * у неё не было: `__ASM_GLOBAL_FUNC` ставит только `.seh_proc`/`.seh_endproc`, а без
 * `.seh_save_fplr_x`/`.seh_set_fp` размотчик считает функцию ЛИСТОВОЙ и ищет сохранённый
 * LR относительно ТЕКУЩЕГО sp — а он уже принадлежит другому стеку.
 *
 * Улика прогона 30.08 08:14 (установщик Diablo, после снятия порчи строк):
 *   frameless-bail: reason=pc-null pc=000007FFD049081C image=000007FFD0480000 saved_lr=0
 *   seh-ec-fpchain: fp=00000001121CF390 -> new pc=...491A9C     (fp — область контекста ЦП)
 *   boundary-reject: not-x64-main-process -> action=stop-unwind -> exit=1
 * `0x7FFD049081C - 0x7FFD0480000 = 0x1081c` — это `blr x19` ниже.
 *
 * `.seh_set_fp` заставляет размотчик восстанавливать `sp` ИЗ x29, а x29 здесь хранит
 * СТАРЫЙ sp (`mov x29, sp` до переключения). Это ровно те значения, что записаны в
 * памяти проекта: x29 = старый sp, LR по [x29+8], стек вызывающего x29+0x30.
 *
 * Идиома взята готовая, своя не сочинялась: `dlls/ntdll/relay.c:626-631` (call_entry_point).
 * x18 описать нельзя — в кодах размотки ARM64 его нет (только x19-x28, d8-d15, fp/lr);
 * он и не нужен: его восстанавливает эпилог, а лечение x18 живёт отдельно. */
__ASM_GLOBAL_FUNC( xtajit_arm64_call_void,
                   "stp x29, x30, [sp, #-0x30]!\n\t"
                   __ASM_SEH(".seh_save_fplr_x 0x30\n\t")
                   "mov x29, sp\n\t"
                   __ASM_SEH(".seh_set_fp\n\t")
                   "stp x19, x20, [sp, #0x10]\n\t"
                   __ASM_SEH(".seh_save_regp x19, 0x10\n\t")
                   "str x21, [sp, #0x20]\n\t"
                   __ASM_SEH(".seh_save_reg x21, 0x20\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")
                   "mov x19, x2\n\t"
                   "mov x20, sp\n\t"
                   "mov x21, x3\n\t"
                   "str x18, [sp, #0x28]\n\t"
                   "mov x18, x1\n\t"
                   "mov sp, x0\n\t"
                   "mov x0, x21\n\t"
                   "blr x19\n\t"
                   "mov sp, x20\n\t"
                   "ldr x18, [sp, #0x28]\n\t"
                   "ldr x21, [sp, #0x20]\n\t"
                   "ldp x19, x20, [sp, #0x10]\n\t"
                   "ldp x29, x30, [sp], #0x30\n\t"
                   "ret" )
#endif

struct unix_bop_stack
{
    unixlib_handle_t handle;
    UINT id;
    ULONG args;
};

struct xtajit_stack_bounds
{
    void *limit;
    void *base;
};

struct xtajit_initial_i386_context
{
    I386_CONTEXT ctx;
    NTSTATUS status;
};

struct xtajit_pending_i386_context
{
    ULONG_PTR key;     /* ключ потока по TPIDRRO_EL0 (ядро сохраняет всегда, в отличие от x18); 0 = слот свободен */
    TEB *teb;          /* только для печати */
    BOOL valid;
    I386_CONTEXT ctx;
};

static struct xtajit_pending_i386_context pending_i386_contexts[XTAJIT_PENDING_I386_CONTEXT_SLOTS];
/* ★★★★★★★ MacRunner 2026-09-02 — ОБЩЕГО СЛОТА ОТЛОЖЕННОГО КОНТЕКСТА БОЛЬШЕ НЕТ.
 *
 * Корень режимов B и C у Diablo (доказано 7 парами, веха в обеих руках): один на процесс fallback-слот, куда
 * BTCpuSetContext публиковал контекст и откуда любой поток без своего слота брал его при входе в BTCpuSimulate —
 * поток wined3d_cs уносил стартовый контекст callback главного (B), главный уносил стартовый контекст нового
 * потока (C). Слот существовал для случая «TEB неизвестен» (x18 обнулён ядром). Здесь слоты ключуются
 * идентичностью потока из TPIDRRO_EL0 — она доступна всегда, поэтому общий слот не нужен, и красть нечего.
 * Правило дня: доказанное лечение — безусловное, сломанная ветка удаляется; гейты
 * MACRUNNER_XTAJIT_PENDING_OWNER_CHECK / _NO_GLOBAL сняты вместе с вехой «ЧУЖОЙ». */
static ULONG_PTR xtajit_thread_key(void)
{
#ifdef __aarch64__
    ULONG_PTR base;
    __asm__ volatile( "mrs %0, TPIDRRO_EL0" : "=r"(base) );
    return base & ~(ULONG_PTR)7;
#else
    return 0;
#endif
}


/*
 * MacRunner ЛЕСТНИЦА, ступень 1 (2026-08-10).  Стена рунга 1 — НУЛЕВОЙ x18.
 *
 * На Apple arm64 xnu обнуляет x18 (по ABI Windows это указатель на TEB) при входе в ядро,
 * доставке сигнала и переключении контекста.  Для PE-кода это значит, что любое обращение
 * к TEB отказывает, а путь обработки отказа САМ ходит через TEB — отсюда самоподдерживающаяся
 * петля dispatch_exception <-> virtual_unwind (замерено: 3366 кадров, два адреса через один).
 *
 * Лечение уже написано и проверено в ntdll (signal_arm64ec.c, Lane A 2026-06-12), но применено
 * там только к двум прологам перехода EC — до xtajit.dll оно не доехало, а i386-гость исполняется
 * именно здесь.  Достоверный источник TEB — pthread TSD, читаемый через TPIDRRO_EL0, который xnu
 * СОХРАНЯЕТ.  Смещение слота ищем один раз, пока x18 ещё цел, и проверяем инвариантом
 * teb->Tib.Self == teb (в версии ntdll этой проверки нет — слот там берётся первый совпавший).
 *
 * Отличие от версии ntdll: мы не только возвращаем указатель, но и ВОССТАНАВЛИВАЕМ сам x18,
 * иначе вызванный отсюда код ntdll/ucrtbase продолжит падать на своих [x18,#0x60]/[x18,#0x68].
 *
 * Гейт MACRUNNER_XTAJIT_X18_FROM_TLS, умолчание ВКЛ (=0 возвращает прежнее поведение для A/B).
 * Умолчание именно ВКЛ: выключенные по умолчанию гейты в этом проекте уже трижды терялись.
 */
/* ВНИМАНИЕ: на aarch64-windows unsigned long это 32 бита, поэтому база TSD и смещение
 * держатся строго в ULONG_PTR — иначе значение TPIDRRO_EL0 обрезается. */
static ULONG_PTR     xtajit_x18_tsd_offset;
static unsigned int  xtajit_x18_tls_ok;
static unsigned int  xtajit_x18_heal_count;

static BOOL xtajit_x18_from_tls_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        static const WCHAR nameW[] =
            {'M','A','C','R','U','N','N','E','R','_','X','T','A','J','I','T','_',
             'X','1','8','_','F','R','O','M','_','T','L','S',0};
        WCHAR value[4] = { 0 };
        UNICODE_STRING name, val;

        RtlInitUnicodeString( &name, nameW );
        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        /* не найдено -> ВКЛ; найдено и равно "0" -> ВЫКЛ */
        enabled = (RtlQueryEnvironmentVariable_U( NULL, &name, &val ) == STATUS_VARIABLE_NOT_FOUND ||
                   value[0] != '0');
    }
    return enabled;
}

/* Ищем слот TSD, в котором лежит TEB.  Зовётся там, где x18 заведомо цел (ProcessInit/ThreadInit). */
static void xtajit_arm_x18_from_tls(void)
{
#ifdef __aarch64__
    TEB *teb;
    ULONG_PTR base;
    unsigned int i;

    if (xtajit_x18_tls_ok) return;
    if (!xtajit_x18_from_tls_enabled()) return;

    teb = NtCurrentTeb();
    if (!teb || (void *)teb->Tib.Self != (void *)teb) return;

    __asm__ volatile( "mrs %0, TPIDRRO_EL0" : "=r"(base) );
    base &= ~(ULONG_PTR)7;
    for (i = 0; i < 512; i++)
    {
        if (((void **)base)[i] == (void *)teb)
        {
            xtajit_x18_tsd_offset = (ULONG_PTR)i * sizeof(void *);
            xtajit_x18_tls_ok = 1;
            MESSAGE( "macrunner-xtajit-x18: armed tsd_off=%u teb=%p\n",
                     (unsigned int)xtajit_x18_tsd_offset, teb );
            return;
        }
    }
    MESSAGE( "macrunner-xtajit-x18: NOT armed teb=%p not found in tsd\n", teb );
#endif
}

/* Медленный путь: x18 обнулён ядром.  Достаём TEB из TSD и чиним сам регистр. */
static TEB *xtajit_recover_teb(void)
{
#ifdef __aarch64__
    ULONG_PTR base;
    TEB *teb;

    if (!xtajit_x18_tls_ok) return NULL;

    __asm__ volatile( "mrs %0, TPIDRRO_EL0" : "=r"(base) );
    base &= ~(ULONG_PTR)7;
    teb = (TEB *)((void **)base)[xtajit_x18_tsd_offset / sizeof(void *)];
    if (!teb || (void *)teb->Tib.Self != (void *)teb) return NULL;

    /* x18 на aarch64-windows зарезервирован под TEB, компилятор его не распределяет,
     * поэтому запись через asm переживает возврат из этой функции. */
    __asm__ volatile( "mov x18, %0" :: "r"(teb) );

    if (xtajit_x18_heal_count < 8)
        MESSAGE( "macrunner-xtajit-x18: heal #%u teb=%p\n", xtajit_x18_heal_count + 1, teb );
    xtajit_x18_heal_count++;
    return teb;
#else
    return NULL;
#endif
}

static inline TEB *xtajit_current_teb(void)
{
    TEB *teb = NtCurrentTeb();

    if (!teb) teb = xtajit_recover_teb();
    return teb;
}

static void xtajit_raise_status( NTSTATUS status )
{
    TEB *teb;
    void *old_exception_list;

    if (!status) return;

    teb = xtajit_current_teb();
    if (!teb)
    {
        RtlRaiseStatus( status );
        return;
    }

    old_exception_list = teb->Tib.ExceptionList;
    teb->Tib.ExceptionList = (void *)~(ULONG_PTR)0;
    RtlRaiseStatus( status );
    teb->Tib.ExceptionList = old_exception_list;
}

static inline TEB32 *xtajit_current_teb32(void)
{
    TEB *teb = xtajit_current_teb();
    LONG offset;
    TEB32 *cached;

    if (!teb) return NULL;

    offset = teb->WowTebOffset;
    cached = (TEB32 *)teb->TlsSlots[XTAJIT_TLS_TEB32_HOST];
    if (offset > 0 && offset < 0x100000 && !(offset & 0xfff))
    {
        TEB32 *teb32 = (TEB32 *)((char *)teb + offset);
        teb->TlsSlots[XTAJIT_TLS_TEB32_HOST] = teb32;
        return teb32;
    }
    if (cached) return cached;

    return (TEB32 *)((char *)teb + offset);
}

static inline TEB32 *xtajit_context_teb32( const struct xtajit_i386_context *ctx )
{
    if (ctx && ctx->teb32_host) return (TEB32 *)(ULONG_PTR)ctx->teb32_host;
    return xtajit_current_teb32();
}

static BOOL trace_syscalls_enabled(void);
static BOOL drop_stale_unixbop_enabled(void);   /* итерация 2694 */

/* MacRunner 2026-08-31, лейн МЕЛКИЕ, итерация 72: гейт зонда старта потока, умолчание ВЫКЛ. */
static BOOL threadstart_probe_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        static const WCHAR nameW[] =
            {'M','A','C','R','U','N','N','E','R','_','X','T','A','J','I','T','_',
             'T','H','R','E','A','D','S','T','A','R','T','_','P','R','O','B','E',0};
        UNICODE_STRING name;
        WCHAR buf[8];
        UNICODE_STRING val;

        RtlInitUnicodeString( &name, nameW );
        val.Buffer = buf;
        val.Length = 0;
        val.MaximumLength = sizeof(buf);
        enabled = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) == STATUS_SUCCESS &&
                  val.Length && buf[0] != '0';
    }
    return enabled > 0;
}

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: гейт шумной трассы симуляции, умолчание ВЫКЛ. */
static BOOL trace_sim_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        static const WCHAR nameW[] =
            {'M','A','C','R','U','N','N','E','R','_','X','T','A','J','I','T','_',
             'T','R','A','C','E','_','S','I','M',0};
        WCHAR value[4] = { 0 };
        UNICODE_STRING name, val;

        RtlInitUnicodeString( &name, nameW );
        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        enabled = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND &&
                  value[0] && value[0] != '0';
    }
    return enabled;
}

static void *guest32_host_ptr( DWORD ptr )
{
    ULONG_PTR base;
    TEB *teb;

    if (!ptr) return NULL;
    teb = xtajit_current_teb();
    base = (ULONG_PTR)teb->TlsSlots[XTAJIT_WOW64_TLS_GUEST32_BASE];
    if (!base) base = (ULONG_PTR)xtajit_current_teb32();
    base &= ~(ULONG_PTR)0xffffffff;
    return (void *)(base | ptr);
}

static BOOL native_exception_list_is_guest32( TEB *teb, ULONG_PTR *frame_ptr, ULONG_PTR *base_ptr )
{
    ULONG_PTR frame, base;

    if (!teb || !teb->Tib.ExceptionList ||
        teb->Tib.ExceptionList == (void *)~(ULONG_PTR)0)
        return FALSE;

    base = (ULONG_PTR)teb->TlsSlots[XTAJIT_WOW64_TLS_GUEST32_BASE];
    if (!base)
    {
        if (!teb->WowTebOffset) return FALSE;
        base = (ULONG_PTR)((char *)teb + teb->WowTebOffset);
    }
    base &= ~(ULONG_PTR)0xffffffff;

    frame = (ULONG_PTR)teb->Tib.ExceptionList;
    if (!base || frame < base || frame > base + 0xffffffffu - 2 * sizeof(DWORD))
        return FALSE;

    if (frame_ptr) *frame_ptr = frame;
    if (base_ptr) *base_ptr = base;
    return TRUE;
}

static void mask_native_guest32_exception_list( TEB *teb, DWORD service, const char *phase )
{
    struct seh_frame32
    {
        DWORD prev;
        DWORD handler;
    };
    ULONG_PTR frame, base;
    const struct seh_frame32 *frame32;

    if (!native_exception_list_is_guest32( teb, &frame, &base )) return;

    frame32 = (const struct seh_frame32 *)frame;
    if (trace_syscalls_enabled())
        MESSAGE( "macrunner-xtajit: mask native guest32 seh phase=%s svc=%08lx "
                 "frame=%p guest=%08lx handler=%08lx prev=%08lx\n",
                 phase, service, (void *)frame, (DWORD)(frame - base),
                 frame32->handler, frame32->prev );
    teb->Tib.ExceptionList = (void *)~(ULONG_PTR)0;
}

static BOOL guest32_can_read( DWORD guest, SIZE_T size )
{
    BYTE *ptr = guest32_host_ptr( guest );
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR start, end, region_end;
    DWORD protect;

    if (!ptr) return FALSE;
    if (!size) return TRUE;
    if (NtQueryVirtualMemory( NtCurrentProcess(), ptr, MemoryBasicInformation,
                              &mbi, sizeof(mbi), NULL ) != STATUS_SUCCESS)
        return FALSE;
    if (mbi.State != MEM_COMMIT) return FALSE;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return FALSE;
    protect = mbi.Protect & 0xff;
    if (protect != PAGE_READONLY && protect != PAGE_READWRITE &&
        protect != PAGE_WRITECOPY && protect != PAGE_EXECUTE_READ &&
        protect != PAGE_EXECUTE_READWRITE && protect != PAGE_EXECUTE_WRITECOPY)
        return FALSE;

    start = (ULONG_PTR)ptr;
    end = start + size;
    region_end = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
    return end >= start && end <= region_end;
}

static BOOL copy_guest32_dwords( DWORD guest, DWORD *dst, unsigned int count )
{
    volatile DWORD *src = guest32_host_ptr( guest );
    unsigned int i;

    if (!dst || !guest32_can_read( guest, count * sizeof(*dst) )) return FALSE;
    for (i = 0; i < count; i++) dst[i] = src[i];
    return TRUE;
}

static BOOL copy_guest32_bytes( DWORD guest, BYTE *dst, unsigned int count )
{
    volatile BYTE *src = guest32_host_ptr( guest );
    unsigned int i;

    if (!dst || !guest32_can_read( guest, count )) return FALSE;
    for (i = 0; i < count; i++) dst[i] = src[i];
    return TRUE;
}

static BOOL trace_native_stack_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        static const WCHAR nameW[] =
            {'M','A','C','R','U','N','N','E','R','_','X','T','A','J','I','T','_',
             'T','R','A','C','E','_','S','T','A','C','K',0};
        WCHAR value[4];
        UNICODE_STRING name, val;

        RtlInitUnicodeString( &name, nameW );
        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        enabled = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND;
    }
    return enabled;
}

static BOOL trace_all_simulate_enabled(void);

static BOOL trace_syscalls_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        static const WCHAR nameW[] =
            {'M','A','C','R','U','N','N','E','R','_','X','T','A','J','I','T','_',
             'T','R','A','C','E','_','S','Y','S','C','A','L','L','S',0};
        WCHAR value[4];
        UNICODE_STRING name, val;

        RtlInitUnicodeString( &name, nameW );
        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        enabled = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND ||
                  trace_native_stack_enabled() || trace_all_simulate_enabled();
    }
    return enabled;
}

static ULONG *get_ntdll_syscall_dispatcher_slot(void)
{
    static ULONG *slot;
    static BOOL tried;

    if (!tried)
    {
        static const WCHAR ntdllW[] = {'n','t','d','l','l','.','d','l','l',0};
        UNICODE_STRING name;
        HMODULE ntdll = NULL;

        tried = TRUE;
        RtlInitUnicodeString( &name, ntdllW );
        LdrGetDllHandle( NULL, 0, &name, &ntdll );
        if (ntdll)
            slot = RtlFindExportedRoutineByName( ntdll, "__wine_syscall_dispatcher" );
    }
    return slot;
}

static void trace_syscall_dispatcher_slot( const char *phase, DWORD service,
                                           const struct xtajit_i386_context *ctx )
{
    ULONG *slot;
    DWORD guest_slot = 0, guest_value = 0;
    BYTE stub[6] = { 0 };

    if (ctx && ctx->edx && copy_guest32_bytes( ctx->edx, stub, sizeof(stub) ) &&
        stub[0] == 0xff && stub[1] == 0x25)
    {
        guest_slot = stub[2] | (stub[3] << 8) | (stub[4] << 16) | (stub[5] << 24);
        copy_guest32_dwords( guest_slot, &guest_value, 1 );
    }

    if (!trace_syscalls_enabled()) return;
    slot = get_ntdll_syscall_dispatcher_slot();
    MESSAGE( "macrunner-xtajit: syscall dispatcher slot phase=%s svc=%08lx slot=%p value=%08lx guest_slot=%08lx guest_value=%08lx bop=%08lx eip=%08lx esp=%08lx eax=%08lx\n",
             phase, service, slot, slot ? *slot : 0,
             guest_slot, guest_value,
             syscall_bop_guest ? PtrToUlong( syscall_bop_guest ) : 0,
             ctx ? ctx->eip : 0, ctx ? ctx->esp : 0, ctx ? ctx->eax : 0 );
}

static BOOL trace_process_exit_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        static const WCHAR nameW[] =
            {'M','A','C','R','U','N','N','E','R','_',
             'T','R','A','C','E','_','P','R','O','C','E','S','S','_','E','X','I','T',0};
        WCHAR value[4];
        UNICODE_STRING name, val;

        RtlInitUnicodeString( &name, nameW );
        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        enabled = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND;
    }
    return enabled;
}

static BOOL trace_all_simulate_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        static const WCHAR nameW[] =
            {'M','A','C','R','U','N','N','E','R','_','X','T','A','J','I','T','_',
             'T','R','A','C','E','_','A','L','L','_','S','I','M','U','L','A','T','E',0};
        WCHAR value[4];
        UNICODE_STRING name, val;

        RtlInitUnicodeString( &name, nameW );
        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        enabled = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND;
    }
    return enabled;
}

static ULONG_PTR current_native_sp(void)
{
#ifdef __aarch64__
    ULONG_PTR sp;
    __asm__ volatile( "mov %0, sp" : "=r"(sp) );
    return sp;
#else
    volatile char marker;
    return (ULONG_PTR)&marker;
#endif
}

static ULONG_PTR current_x18(void)
{
#ifdef __aarch64__
    ULONG_PTR x18;
    __asm__ volatile( "mov %0, x18" : "=r"(x18) );
    return x18;
#else
    return 0;
#endif
}

static LONG_PTR current_native_stack_slack_teb( TEB *teb, ULONG_PTR sp )
{
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR start = (ULONG_PTR)teb;
    ULONG_PTR end = teb ? (ULONG_PTR)&teb->Tib.StackLimit + sizeof(teb->Tib.StackLimit) : 0;
    ULONG_PTR region_end, limit;
    DWORD protect;

    if (!teb || !sp) return 0;
    if (end < start) return 0;
    if (NtQueryVirtualMemory( NtCurrentProcess(), teb, MemoryBasicInformation,
                              &mbi, sizeof(mbi), NULL ) != STATUS_SUCCESS)
        return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return 0;
    protect = mbi.Protect & 0xff;
    if (protect != PAGE_READONLY && protect != PAGE_READWRITE &&
        protect != PAGE_WRITECOPY && protect != PAGE_EXECUTE_READ &&
        protect != PAGE_EXECUTE_READWRITE && protect != PAGE_EXECUTE_WRITECOPY)
        return 0;
    region_end = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
    if (end > region_end) return 0;

    limit = (ULONG_PTR)teb->Tib.StackLimit;
    return limit ? (LONG_PTR)(sp - limit) : 0;
}

static LONG_PTR current_native_stack_slack( ULONG_PTR sp )
{
    return current_native_stack_slack_teb( xtajit_current_teb(), sp );
}

static void trace_arm64_pe_call_state( const char *phase, DWORD service,
                                       ULONG_PTR target, void *stack_top, TEB *teb )
{
    ULONG_PTR sp, bridge_low = 0, bridge_size = 0, syscall_frame = 0;

    if (!trace_syscalls_enabled()) return;

    sp = current_native_sp();
    if (teb)
    {
        syscall_frame = *(ULONG_PTR *)((char *)teb + XTAJIT_TEB_SYSCALL_FRAME_OFFSET);
        bridge_low = (ULONG_PTR)teb->TlsSlots[XTAJIT_TLS_BRIDGE_STACK];
        bridge_size = (SIZE_T)teb->TlsSlots[XTAJIT_TLS_BRIDGE_SIZE];
    }

    MESSAGE( "macrunner-xtajit-arm64ec-call: phase=%s svc=%08lx target=%p "
             "x18=%p teb=%p exception_list=%p syscall_frame=%p native_sp=%p "
             "slack=%ld stack_top=%p bridge=%p-%p wow64sys=%p callback=%p\n",
             phase, service, (void *)target, (void *)current_x18(), teb,
             teb ? teb->Tib.ExceptionList : NULL, (void *)syscall_frame, (void *)sp,
             (long)current_native_stack_slack_teb( teb, sp ), stack_top, (void *)bridge_low,
             (void *)(bridge_low + bridge_size), (void *)(ULONG_PTR)Wow64SystemServiceEx,
             (void *)(ULONG_PTR)Wow64KiUserCallbackDispatcher );
}

static void trace_native_stack_teb( TEB *teb, const char *phase, DWORD eip, DWORD esp,
                                    DWORD service, NTSTATUS status )
{
    ULONG_PTR sp = current_native_sp();
    ULONG_PTR limit = teb ? (ULONG_PTR)teb->Tib.StackLimit : 0;
    ULONG_PTR base = teb ? (ULONG_PTR)teb->Tib.StackBase : 0;
    LONG_PTR slack = current_native_stack_slack_teb( teb, sp );
    static unsigned int count;
    unsigned int sample = count++;

    if (!trace_native_stack_enabled()) return;
    if (sample >= 128 && slack >= 0x40000 && (sample & 0x3fff)) return;

    MESSAGE( "macrunner-xtajit-stack: phase=%s count=%u native_sp=%p teb_stack=%p-%p "
             "dealloc=%p slack=%ld eip=%08lx esp=%08lx svc=%08lx status=%08lx\n",
                 phase, sample, (void *)sp,
                 (void *)limit, (void *)base, teb ? teb->DeallocationStack : NULL,
                 (long)slack, eip, esp, service, status );
}

static void trace_native_stack( const char *phase, DWORD eip, DWORD esp, DWORD service, NTSTATUS status )
{
    trace_native_stack_teb( xtajit_current_teb(), phase, eip, esp, service, status );
}

static void clear_wow64_reset_state(void)
{
    TEB *teb = xtajit_current_teb();
    WOW64_CPURESERVED *cpu = teb ? teb->TlsSlots[WOW64_TLS_CPURESERVED] : NULL;

    if (cpu) cpu->Flags &= ~WOW64_CPURESERVED_FLAG_RESET_STATE;
}

static struct xtajit_pending_i386_context *get_pending_i386_context_slot( TEB *teb, BOOL create )
{
    struct xtajit_pending_i386_context *free_slot = NULL;
    ULONG_PTR key = xtajit_thread_key();
    unsigned int i;

    if (!key) key = (ULONG_PTR)teb;      /* не-arm64: ключом служит TEB */
    if (!key) return NULL;
    for (i = 0; i < XTAJIT_PENDING_I386_CONTEXT_SLOTS; i++)
    {
        if (pending_i386_contexts[i].key == key) return &pending_i386_contexts[i];
        if (!pending_i386_contexts[i].key && !free_slot) free_slot = &pending_i386_contexts[i];
    }
    if (!create || !free_slot) return NULL;
    free_slot->key = key;
    free_slot->teb = teb;
    free_slot->valid = FALSE;
    return free_slot;
}

static void publish_pending_i386_context( const I386_CONTEXT *ctx )
{
    struct xtajit_pending_i386_context *pending;
    DWORD flags;

    if (!ctx) return;
    flags = ctx->ContextFlags & ~CONTEXT_i386;
    if (!(flags & CONTEXT_I386_CONTROL)) return;
    if (!(pending = get_pending_i386_context_slot( xtajit_current_teb(), TRUE )))
    {
        static LONG net_slota;
        if (InterlockedIncrement( &net_slota ) <= 4)
            MESSAGE( "macrunner-xtajit-pending: НЕТ СЛОТА (ключ потока 0 и TEB неизвестен) — контекст не отложен\n" );
        return;
    }
    pending->teb = xtajit_current_teb();
    pending->ctx = *ctx;
    pending->valid = TRUE;
}

static BOOL consume_pending_i386_context( I386_CONTEXT *ctx )
{
    struct xtajit_pending_i386_context *pending;

    if (!ctx || !(pending = get_pending_i386_context_slot( xtajit_current_teb(), FALSE )) || !pending->valid)
        return FALSE;
    *ctx = pending->ctx;
    pending->valid = FALSE;
    return TRUE;
}

static void release_pending_i386_context(void)
{
    struct xtajit_pending_i386_context *pending;

    if ((pending = get_pending_i386_context_slot( xtajit_current_teb(), FALSE )))
    {
        pending->valid = FALSE;
        pending->teb = NULL;
        pending->key = 0;
    }
}

static NTSTATUS read_current_i386_context( I386_CONTEXT *ctx )
{
    TEB *teb = xtajit_current_teb();
    WOW64_CPURESERVED *cpu = teb ? teb->TlsSlots[WOW64_TLS_CPURESERVED] : NULL;
    WOW64_CPU_AREA_INFO info;
    NTSTATUS status;

    if (!ctx || !cpu) return STATUS_INVALID_PARAMETER;
    if ((status = RtlWow64GetCpuAreaInfo( cpu, 0, &info ))) return status;
    if (info.Machine != IMAGE_FILE_MACHINE_I386) return STATUS_INVALID_PARAMETER;

    *ctx = *(I386_CONTEXT *)info.Context;
    return STATUS_SUCCESS;
}

static NTSTATUS consume_reset_i386_context( I386_CONTEXT *ctx )
{
    TEB *teb = xtajit_current_teb();
    WOW64_CPURESERVED *cpu = teb ? teb->TlsSlots[WOW64_TLS_CPURESERVED] : NULL;
    NTSTATUS status;

    if (!ctx || !cpu || !(cpu->Flags & WOW64_CPURESERVED_FLAG_RESET_STATE)) return STATUS_NOT_FOUND;
    if ((status = read_current_i386_context( ctx ))) return status;
    cpu->Flags &= ~WOW64_CPURESERVED_FLAG_RESET_STATE;
    return STATUS_SUCCESS;
}

static NTSTATUS write_current_i386_context( const I386_CONTEXT *context, BOOL reset_state )
{
    TEB *teb = xtajit_current_teb();
    WOW64_CPURESERVED *cpu = teb ? teb->TlsSlots[WOW64_TLS_CPURESERVED] : NULL;
    WOW64_CPU_AREA_INFO info;
    I386_CONTEXT *wow_frame;
    DWORD flags;
    NTSTATUS status;

    if (!cpu)
    {
        MESSAGE( "macrunner-xtajit: write_i386_ctx teb=%p tls_cpu=%p cpu=NULL ОТКАЗ\n",
                 teb, teb ? (void *)teb->TlsSlots[WOW64_TLS_CPURESERVED] : NULL );
        return STATUS_INVALID_PARAMETER;
    }
    if ((status = RtlWow64GetCpuAreaInfo( cpu, 0, &info ))) return status;
    if (info.Machine != IMAGE_FILE_MACHINE_I386) return STATUS_INVALID_PARAMETER;

    wow_frame = info.Context;
    flags = context->ContextFlags & ~CONTEXT_i386;

    /* MacRunner, лейн ЛЕСТНИЦА, итерация 2614 — КТО ПРОДВИГАЕТ КОНТЕКСТ.
     *
     * Замер 2613: контекст, восстанавливаемый после обратного вызова оконной процедуры,
     * снят уже ПОСЛЕ `ret 0x10` системного вызова (eip — адрес возврата `call [eax]`,
     * esp — на 0x14 выше, eax — ноль вместо результата 0x11ef). Состояние измерено,
     * виновник — нет.
     *
     * Здесь хранилище: `wow_frame` = `info.Context`, из `teb->TlsSlots[CPURESERVED]`.
     * `Eip`/`Esp` обновляются ТОЛЬКО при взведённом `CONTEXT_I386_CONTROL` — если вызов
     * приходит без него, в кадре остаются СТАРЫЕ значения, и это ровно тот механизм,
     * который дал бы наблюдаемое.
     *
     * Печать НЕ добавляет строк: расширяю ту, что уже была (одна на вызов, ~4571 за прогон).
     * Показываю флаги, что кладём и что там ЛЕЖАЛО — этого хватает, чтобы различить
     * «записали новое» и «не тронули, осталось старое». */
    /* ★ 2614: ПОТОК тем же полем, что в зонде обратного вызова.
     * Без него сравнение «последняя запись против захваченного» опирается на
     * НЕПРОВЕРЕННОЕ предположение об одном потоке: строки системных вызовов печатают
     * teb32=…1F2000, а зонд возврата — …1FAA64, и это может быть как разный смысл поля,
     * так и разные потоки. Печатаем ClientId.UniqueThread в обоих местах — тогда вопрос
     * закрывается числом, а не рассуждением. */
    /* ★ ИТЕРАЦИЯ 69 — ПОТОЛОК ПЕЧАТИ (по входящему координатора).
     * Эта строка печаталась БЕЗУСЛОВНО на каждом системном вызове гостя:
     * 72 682 строки за прогон, разбор дороже самого прогона. Потолок 2000 + итог
     * каждую тысячу. Гейта нет намеренно: модуль без libc, getenv не линкуется. */
    {
        static unsigned mr_wctx_n;
        /* МЕЛКИЕ, итерация 69: потолок ВРЕМЕННО поднят с 2000 до 20000 — при 2000
         * половина событий пряталась, и падающий поток не попадал в список (итерация 68).
         * Вернуть 2000 сразу после замера. */
        if (++mr_wctx_n > 2000 && mr_wctx_n % 1000 != 0) { /* тишина */ }
        else if (mr_wctx_n > 2000)
            MESSAGE( "macrunner-xtajit: write_i386_ctx-итог n=%u\n", mr_wctx_n );
        else
            MESSAGE( "macrunner-xtajit: write_i386_ctx поток=%04lx teb=%p tls_cpu=%p cpu=%p flags=%08lx "
             "control=%d eip_нов=%08lx esp_нов=%08lx eip_было=%08lx esp_было=%08lx eax_было=%08lx\n",
             (unsigned long)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread,
             teb, (void *)teb->TlsSlots[WOW64_TLS_CPURESERVED], cpu,
             (unsigned long)flags, !!(flags & CONTEXT_I386_CONTROL),
             (unsigned long)context->Eip, (unsigned long)context->Esp,
             (unsigned long)wow_frame->Eip, (unsigned long)wow_frame->Esp,
             (unsigned long)wow_frame->Eax );
    }

    if (flags & CONTEXT_I386_INTEGER)
    {
        wow_frame->Eax = context->Eax;
        wow_frame->Ebx = context->Ebx;
        wow_frame->Ecx = context->Ecx;
        wow_frame->Edx = context->Edx;
        wow_frame->Esi = context->Esi;
        wow_frame->Edi = context->Edi;
    }
    if (flags & CONTEXT_I386_CONTROL)
    {
        wow_frame->Esp    = context->Esp;
        wow_frame->Ebp    = context->Ebp;
        wow_frame->Eip    = context->Eip;
        wow_frame->EFlags = context->EFlags;
        wow_frame->SegCs  = context->SegCs;
        wow_frame->SegSs  = context->SegSs;
        if (reset_state) cpu->Flags |= WOW64_CPURESERVED_FLAG_RESET_STATE;
    }
    if (flags & CONTEXT_I386_SEGMENTS)
    {
        wow_frame->SegDs = context->SegDs;
        wow_frame->SegEs = context->SegEs;
        wow_frame->SegFs = context->SegFs;
        wow_frame->SegGs = context->SegGs;
    }
    if (flags & CONTEXT_I386_DEBUG_REGISTERS)
    {
        wow_frame->Dr0 = context->Dr0;
        wow_frame->Dr1 = context->Dr1;
        wow_frame->Dr2 = context->Dr2;
        wow_frame->Dr3 = context->Dr3;
        wow_frame->Dr6 = context->Dr6;
        wow_frame->Dr7 = context->Dr7;
    }
    if (flags & CONTEXT_I386_EXTENDED_REGISTERS)
        memcpy( wow_frame->ExtendedRegisters, context->ExtendedRegisters, sizeof(context->ExtendedRegisters) );
    if (flags & CONTEXT_I386_FLOATING_POINT)
        memcpy( &wow_frame->FloatSave, &context->FloatSave, sizeof(context->FloatSave) );
    return STATUS_SUCCESS;
}

static NTSTATUS set_current_i386_context( const I386_CONTEXT *context )
{
    return write_current_i386_context( context, TRUE );
}

static void capture_initial_i386_context( struct xtajit_initial_i386_context *initial )
{
    if (!initial) return;

    RtlZeroMemory( initial, sizeof(*initial) );
    initial->ctx.ContextFlags = CONTEXT_I386_ALL;
    if (consume_pending_i386_context( &initial->ctx ))
    {
        /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 252 — ОТЛОЖЕННЫЙ КОНТЕКСТ, УКАЗЫВАЮЩИЙ
         * НА САМ BOP. Такой контекст публикует `BTCpuSetContext`, а его зовёт
         * `Wow64KiUserCallbackDispatcher` при восстановлении orig_ctx после обратного вызова:
         * гость там стоит на инструкции системного вызова, потому что вызов ещё не завершён.
         * Если этот контекст доживает до следующего витка цикла симуляции, тот же вызов
         * исполняется ЗАНОВО. Ровно это и даёт 32 736 окон при ОДНОМ гостевом вызове
         * CreateWindowEx (все 16 блоков WIN_CreateWindowEx исполнены по разу, нативный SP
         * одинаков — вложенности нет).
         *
         * Гейт по умолчанию ВЫКЛЮЧЕН: сперва считаем явление, потом лечим. */
        /* ★★ MacRunner 2026-08-23, лейн ЛЕСТНИЦА, итерация 2694 — ЛЕЧЕНИЕ ВИДЕЛО ОДИН BOP ИЗ ДВУХ.
         * Замер: `syscall_bop_guest` = 0x00270000, `unix_bop_guest` = 0x00280000. Строк
         * `stale-pending` в журнале пять, и ВСЕ пять с `eip=00270000` — за юникс-BOP лечение не
         * срабатывало ни разу. При этом смертельный обратный вызов (2686, дизассемблер) приходит
         * именно из юникс-BOP. Отложенный контекст после такого вызова указывает на 0x00280000,
         * проверка его пропускает, и юникс-вызов может исполниться заново.
         * Гейт `MACRUNNER_XTAJIT_DROP_STALE_UNIXBOP`, умолчание 0: одна переменная за раз. */
        if ((syscall_bop_guest && initial->ctx.Eip == PtrToUlong( syscall_bop_guest )) ||
            (unix_bop_guest && initial->ctx.Eip == PtrToUlong( unix_bop_guest ) &&
             drop_stale_unixbop_enabled()))
        {
            static unsigned int stale_n;
            unsigned int n = ++stale_n;
            static int cure = -1;
            ULONG current_advanced_eip = 0;
            BOOL current_advanced_eip_valid = FALSE;

            if (cure < 0)
            {
                UNICODE_STRING name;
                WCHAR buf[8];
                UNICODE_STRING val = { 0, sizeof(buf), buf };

                /* ★★★ 30.08, лейн УСТАНОВЩИКИ — УМОЛЧАНИЕ ПЕРЕВЕДЕНО В 1.
                 *
                 * Гейт лежал выключенным, а лечит целый класс: гость возобновляется НА
                 * ПЕРЕХОДНИКЕ системного вызова и исполняет его заново. Приборы называют
                 * это прямо: `xtajit-resume: выставляли_eip=79dc378c вошли_с_eip=00270000
                 * совпало=0`.
                 *
                 * Замеры 30.08 (опора программ, восемь мишеней, один двоичный):
                 *   i386 clock   ПРОЦЕСС (0 окон)      -> ОКНО_НА_ЭКРАНЕ (2 окна, 315 растров)
                 *   i386 winver  399 диалогов #32770   -> 1 окно, ОКНО_В_ЖУРНАЛЕ
                 *   четыре нативных ARM64              -> без изменений
                 *   i386 notepad                       -> без изменений (ПРОЦЕСС)
                 * Установщик Diablo: 10 904 диалога -> 1, журнал 3 220 836 -> 16 588 строк.
                 *
                 * ОГОВОРКА, записанная выше в этом же файле: ПРЕЖНЯЯ редакция лечения
                 * ломала Diablo (`вехи ddraw 10 -> 2, отказов 0 -> 9`). Нынешняя лечит
                 * только ПОВТОР, а не любой контекст на шлюзе. Выключить: ...=0. */
                RtlInitUnicodeString( &name, L"MACRUNNER_XTAJIT_DROP_STALE_PENDING" );
                cure = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) ? 1 : (buf[0] != '0');
            }
            /* MacRunner 2026-08-27 — ЛЕЧИТЬ ТОЛЬКО ПОВТОР, А НЕ ЛЮБОЙ КОНТЕКСТ НА ШЛЮЗЕ.
             *
             * Замер обеих мишеней с прежним лечением (MACRUNNER_XTAJIT_DROP_STALE_PENDING=1):
             *
             *   Heroes III  вызовов CreateWindowEx 21 447 -> 2, окон OLE 61 -> 1, отказов 1 -> 0
             *   Diablo      вех ddraw 10 -> 2, отказов 0 -> 9   ← СЛОМАНО
             *
             * Причина видна из самого довода итерации 252: контекст, указывающий на шлюз,
             * ЗАКОНЕН, пока системный вызов не завершён — гость там и должен стоять. Прежнее
             * лечение выбрасывало его ВСЕГДА, отчего Diablo теряла законный контекст и не
             * доходила даже до SetDisplayMode.
             *
             * Повтором он становится только тогда, когда тот же самый контекст приходит
             * ВТОРОЙ раз: те же eip, esp и номер вызова. Первый отдаём как есть, второй и
             * далее — выбрасываем.
             *
             * Гейт MACRUNNER_XTAJIT_DROP_REPEATED_PENDING, умолчание ВЫКЛ. */
            {
                static int repeat_gate = -1;
                static ULONG last_eip, last_esp, last_eax;
                static unsigned int repeat_hits;
                BOOL same;

                if (repeat_gate < 0)
                {
                    UNICODE_STRING rname;
                    WCHAR rbuf[8];
                    UNICODE_STRING rval = { 0, sizeof(rbuf), rbuf };

                    RtlInitUnicodeString( &rname, L"MACRUNNER_XTAJIT_DROP_REPEATED_PENDING" );
                    repeat_gate = (!RtlQueryEnvironmentVariable_U( NULL, &rname, &rval ) &&
                                   rbuf[0] && rbuf[0] != '0') ? 1 : 0;
                }
                /* ★ ПОПРАВКА ПО ЗАМЕРУ: признак «тот же eip/esp/eax дважды» оказался
                 * недостаточным. Diablo с ним теряет вехи ddraw (10 -> 2) — у неё повтор
                 * ЗАКОНЕН, потому что вызов действительно ещё не завершён.
                 *
                 * Точный признак устаревания проверяем прямо: смотрим ТЕКУЩИЙ контекст
                 * потока. Если он уже продвинут ЗА шлюз, значит системный вызов завершён и
                 * обработчик eip продвинул — тогда отложенный контекст, всё ещё стоящий на
                 * шлюзе, устарел. Если текущий тоже на шлюзе, вызов не завершён и контекст
                 * законен.
                 *
                 * Это факт о состоянии потока, а не догадка о повторе. */
                I386_CONTEXT cur_ctx;
                BOOL current_advanced = FALSE;

                RtlZeroMemory( &cur_ctx, sizeof(cur_ctx) );
                cur_ctx.ContextFlags = CONTEXT_I386_CONTROL;
                if (!read_current_i386_context( &cur_ctx ))
                {
                    current_advanced = (cur_ctx.Eip != initial->ctx.Eip);
                    if (current_advanced)
                    {
                        current_advanced_eip = cur_ctx.Eip;
                        current_advanced_eip_valid = TRUE;
                    }
                }

                same = current_advanced;
                last_eip = initial->ctx.Eip;
                last_esp = initial->ctx.Esp;
                last_eax = initial->ctx.Eax;
                (void)last_eip; (void)last_esp; (void)last_eax;

                if (repeat_gate && same)
                {
                    unsigned int rn = ++repeat_hits;

                    if (rn <= 8 || !(rn % 4000))
                        MESSAGE( "macrunner-xtajit-repeated-pending: n=%u отложенный_eip=%08lx "
                                 "текущий_eip=%08lx eax=%08lx — вызов завершён, контекст устарел\n",
                                 rn, initial->ctx.Eip, cur_ctx.Eip, initial->ctx.Eax );
                    cure = 1;
                }
                else if (repeat_gate)
                    cure = 0;   /* первый контекст на шлюзе законен */
            }

            if (n <= 4 || !(n % 4000))
                MESSAGE( "macrunner-xtajit-stale-pending: n=%u eip=%08lx eax=%08lx esp=%08lx лечение=%d\n",
                         n, initial->ctx.Eip, initial->ctx.Eax, initial->ctx.Esp, cure );
            if (cure)
            {
                /* MacRunner 2026-08-27 — ПРАВИТЬ ТОЛЬКО Eip, А НЕ ВЫБРАСЫВАТЬ КОНТЕКСТ.
                 *
                 * Прежнее лечение брало ТЕКУЩИЙ контекст целиком, теряя регистры, которые
                 * обратный вызов только что записал в отложенный. Замер на двух мишенях:
                 *
                 *   Heroes III  вызовов 13 545 -> 2   (повтор ушёл)
                 *   Diablo      вех ddraw 10 -> 2     (сломано: потеряно состояние)
                 *
                 * Причём случаи у обеих игр в журнале ОДИНАКОВЫ (отложенный на шлюзе, текущий
                 * продвинут) — значит признак верен, а неверно лечение.
                 *
                 * Устарел в отложенном контексте РОВНО ОДИН регистр — Eip: он остался на
                 * шлюзе, потому что вызов на момент сохранения не был завершён. Всё остальное
                 * там свежее и нужное. Берём отложенный контекст как есть и подставляем
                 * продвинутый Eip из текущего. */
                /* ★ ЗАМЕР ОТВЕРГ подстановку одного Eip: Heroes III прошла 11 659 строк
                 * вместо 25 640, то есть регистры отложенного контекста устарели тоже, а не
                 * только Eip. Берём текущий контекст целиком — так и было. */
                (void)current_advanced_eip; (void)current_advanced_eip_valid;
                initial->ctx.ContextFlags = CONTEXT_I386_ALL;
                initial->status = read_current_i386_context( &initial->ctx );
                if (initial->status)
                    initial->status = RtlWow64GetThreadContext( GetCurrentThread(), &initial->ctx );
                clear_wow64_reset_state();
                return;
            }
        }
        initial->status = STATUS_SUCCESS;
        clear_wow64_reset_state();
        return;
    }

    initial->status = consume_reset_i386_context( &initial->ctx );
    if (initial->status == STATUS_NOT_FOUND)
    {
        initial->status = read_current_i386_context( &initial->ctx );
        if (initial->status)
            initial->status = RtlWow64GetThreadContext( GetCurrentThread(), &initial->ctx );
    }
    clear_wow64_reset_state();
}

static void prepare_arm64_pe_call( TEB *teb )
{
#ifdef __aarch64__
    /* HyperBridge execution can leave x18 with guest state. Rehydrate it before
     * entering ARM64 PE wow64 code; the x64 callback trampoline does the same. */
    if (teb) __asm__ volatile( "mov x18, %0" :: "r"(teb) : "memory" );
#endif
}

static NTSTATUS ensure_bridge_stack(void)
{
    TEB *teb = xtajit_current_teb();
    void *stack = NULL;
    SIZE_T size = XTAJIT_BRIDGE_STACK_SIZE + XTAJIT_BRIDGE_SEH_SLACK;
    NTSTATUS status;

    if (!teb) return STATUS_INVALID_PARAMETER;
    if (teb->TlsSlots[XTAJIT_TLS_BRIDGE_STACK]) return STATUS_SUCCESS;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &stack, 0, &size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    if (!status)
    {
        teb->TlsSlots[XTAJIT_TLS_BRIDGE_STACK] = stack;
        teb->TlsSlots[XTAJIT_TLS_BRIDGE_SIZE] = (void *)size;
    }
    return status;
}

static void release_bridge_stack(void)
{
    TEB *teb = xtajit_current_teb();
    void *stack = teb ? teb->TlsSlots[XTAJIT_TLS_BRIDGE_STACK] : NULL;
    SIZE_T size = 0;

    if (teb)
    {
        teb->TlsSlots[XTAJIT_TLS_BRIDGE_STACK] = NULL;
        teb->TlsSlots[XTAJIT_TLS_BRIDGE_SIZE] = NULL;
    }
    if (stack) NtFreeVirtualMemory( NtCurrentProcess(), &stack, &size, MEM_RELEASE );
}

static void *bridge_stack_top( TEB *teb )
{
    ULONG_PTR bridge_low = teb ? (ULONG_PTR)teb->TlsSlots[XTAJIT_TLS_BRIDGE_STACK] : 0;
    SIZE_T bridge_size = teb ? (SIZE_T)teb->TlsSlots[XTAJIT_TLS_BRIDGE_SIZE] : 0;

    if (!bridge_low || bridge_size <= XTAJIT_BRIDGE_STACK_SLACK) return NULL;
    return (void *)((bridge_low + bridge_size - XTAJIT_BRIDGE_STACK_SLACK) & ~(ULONG_PTR)0xf);
}

static void *bridge_syscall_call_stack_top( TEB *teb )
{
    ULONG_PTR top = (ULONG_PTR)bridge_stack_top( teb );
    ULONG_PTR bridge_low = teb ? (ULONG_PTR)teb->TlsSlots[XTAJIT_TLS_BRIDGE_STACK] : 0;

    if (!top || !bridge_low || top <= bridge_low + 2 * XTAJIT_NESTED_CALLBACK_STACK_SLACK)
        return NULL;
    return (void *)((top - XTAJIT_NESTED_CALLBACK_STACK_SLACK) & ~(ULONG_PTR)0xf);
}

static void *bridge_stack_top_below_current_sp( TEB *teb )
{
    ULONG_PTR low = teb ? (ULONG_PTR)teb->Tib.StackLimit : 0;
    ULONG_PTR high = teb ? (ULONG_PTR)teb->Tib.StackBase : 0;
    ULONG_PTR sp = current_native_sp();

    if (!low || !high || low >= high || sp <= low + 2 * XTAJIT_NESTED_CALLBACK_STACK_SLACK ||
        sp >= high)
        return NULL;
    return (void *)((sp - 2 * XTAJIT_NESTED_CALLBACK_STACK_SLACK) & ~(ULONG_PTR)0xf);
}

static void *bridge_stack_top_below_syscall_frame( TEB *teb )
{
    ULONG_PTR bridge_low = teb ? (ULONG_PTR)teb->TlsSlots[XTAJIT_TLS_BRIDGE_STACK] : 0;
    ULONG_PTR bridge_size = teb ? (SIZE_T)teb->TlsSlots[XTAJIT_TLS_BRIDGE_SIZE] : 0;
    ULONG_PTR bridge_high = bridge_low + bridge_size;
    ULONG_PTR stack_low = teb ? (ULONG_PTR)teb->Tib.StackLimit : 0;
    ULONG_PTR stack_high = teb ? (ULONG_PTR)teb->Tib.StackBase : 0;
    ULONG_PTR sp = current_native_sp();
    ULONG_PTR low = bridge_low;
    ULONG_PTR high = bridge_high;
    ULONG_PTR frame;
    ULONG_PTR anchor;
    ULONG_PTR prev_frame = 0;
    BOOL frame_in_bridge;
    BOOL frame_in_stack;

    if (!teb || !teb->TlsSlots[XTAJIT_TLS_BRIDGE_ACTIVE]) return NULL;

    frame = *(ULONG_PTR *)((char *)teb + XTAJIT_TEB_SYSCALL_FRAME_OFFSET);
    if (!frame) return NULL;
    anchor = frame;
    frame_in_bridge = bridge_low && bridge_high > bridge_low && frame >= bridge_low && frame < bridge_high;
    frame_in_stack = stack_low && stack_high && stack_low < stack_high &&
                     frame >= stack_low && frame < stack_high;
    if (frame_in_stack)
    {
        prev_frame = *(ULONG_PTR *)(frame + XTAJIT_SYSCALL_FRAME_PREV_OFFSET);
        if (frame_in_bridge && prev_frame > anchor && prev_frame > stack_low && prev_frame < stack_high)
            anchor = prev_frame;
    }
    if (!frame_in_bridge && prev_frame > bridge_low && prev_frame < bridge_high)
        anchor = prev_frame;
    if (!low || bridge_size <= XTAJIT_NESTED_CALLBACK_STACK_SLACK ||
        high <= low || anchor <= low || anchor >= high)
    {
        low = stack_low;
        high = stack_high;
    }
    if (!low || !high || low >= high) return NULL;
    if (anchor <= low + XTAJIT_NESTED_CALLBACK_STACK_SLACK || anchor >= high) return NULL;
    if (sp > low && sp < high)
    {
        if (sp < anchor && anchor - sp < XTAJIT_NESTED_CALLBACK_REENTER_GUARD) return NULL;
        if (sp >= anchor - XTAJIT_NESTED_CALLBACK_STACK_SLACK) return NULL;
    }

    return (void *)((anchor - XTAJIT_NESTED_CALLBACK_STACK_SLACK) & ~(ULONG_PTR)0xf);
}

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: счётчики публикаций и восстановлений границ стека
 * вынесены из тел функций, чтобы можно было сравнивать их между собой. */
static int macrunner_n_pub, macrunner_n_res, macrunner_n_imbalance;

static void publish_bridge_stack_bounds( TEB *teb, struct xtajit_stack_bounds *old )
{
    ULONG_PTR bridge_low = (ULONG_PTR)teb->TlsSlots[XTAJIT_TLS_BRIDGE_STACK];
    ULONG_PTR bridge_high = bridge_low + (SIZE_T)teb->TlsSlots[XTAJIT_TLS_BRIDGE_SIZE];
    ULONG_PTR old_low, old_high;

    old->limit = teb->Tib.StackLimit;
    old->base = teb->Tib.StackBase;
    old_low = (ULONG_PTR)old->limit;
    old_high = (ULONG_PTR)old->base;
    if (old->limit && old->base && old_low < old_high)
    {
        /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 210 — ВЫБОР ВМЕСТО СЛИЯНИЯ.
         *
         * Объединение по min/max осмысленно, только когда диапазоны смежны или пересекаются.
         * На ступени 1 они лежат в РАЗНЫХ пространствах, и замер 209 показал результат:
         *     old  = 0x10D1D8000-0x10E1CFD20   (хозяйский wow64-стек)
         *     мост = 0x5016C0000-0x5056D0000   (гостевое окно)
         *     итог = 0x10D1D8000-0x5056D0000   — около 16 ГБ, охватывающие оба
         * Такой диапазон делает проверку «SP внутри стека» всегда истинной (наблюдалось как
         * sp_in_teb=1 при SP в гостевом окне), раскрутка получает ложное «да», и хозяйский код
         * доходит до чтения нулей и возврата по нулевому LR — это pc=0 из итерации 205.
         *
         * Слепая замена границ мостовыми (ветка else ниже) уже пробовалась и дала
         * fp-out-of-stack, поэтому здесь именно ВЫБОР: берём тот диапазон, в котором сейчас
         * находится стек. Умолчание ВЫКЛ — прежнее поведение дословно. */
        static int pick_on = -1;
        int disjoint = !(old_low <= bridge_high && bridge_low <= old_high);

        if (pick_on < 0)
        {
            /* getenv в этом PE-модуле НЕТ — линковка падает с undefined symbol.
             * Способ чтения переменных здесь один: RtlQueryEnvironmentVariable_U. */
            static const WCHAR pickW[] =
                {'M','A','C','R','U','N','N','E','R','_','H','B','_','S','T','A','C','K','_',
                 'B','O','U','N','D','S','_','P','I','C','K',0};
            WCHAR value[4] = { 0 };
            UNICODE_STRING name, val;

            RtlInitUnicodeString( &name, pickW );
            val.Buffer = value;
            val.Length = 0;
            val.MaximumLength = sizeof(value);
            pick_on = (RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND &&
                       value[0] && value[0] != '0');
        }
        if (pick_on && disjoint)
        {
            ULONG_PTR sp = (ULONG_PTR)__builtin_frame_address( 0 );
            ULONG_PTR lo, hi;

            if (sp >= bridge_low && sp < bridge_high) { lo = bridge_low; hi = bridge_high; }
            else if (sp >= old_low && sp < old_high)  { lo = old_low;    hi = old_high;    }
            else                                      { lo = bridge_low; hi = bridge_high; }
            teb->Tib.StackLimit = (void *)lo;
            teb->Tib.StackBase = (void *)hi;
            if (macrunner_n_pub < 12)
                MESSAGE( "macrunner-xtajit-bounds: ВЫБОР sp=%p взято=%p-%p (old=%p-%p мост=%p-%p)\n",
                         (void *)sp, (void *)lo, (void *)hi, old->limit, old->base,
                         (void *)bridge_low, (void *)bridge_high );
        }
        else
        {
            teb->Tib.StackLimit = (void *)(old_low < bridge_low ? old_low : bridge_low);
            teb->Tib.StackBase = (void *)(old_high > bridge_high ? old_high : bridge_high);
        }
    }
    else
    {
        teb->Tib.StackLimit = (void *)bridge_low;
        teb->Tib.StackBase = (void *)bridge_high;
    }
    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: БЕЗУСЛОВНЫЙ зонд — какая ветка сработала.
     * Ветка else ЗАМЕНЯЕТ границы мостовыми, теряя настоящий стек потока; в прогоне C2
     * границы оказались 0x300424000-0x305430000 (только мост), и fp настоящего стека
     * читался как вне стека -> fp-out-of-stack -> stop-unwind. Печатаем ОБЕ ветки и
     * значения, чтобы не гадать, какая из них и почему. */
    {
        if (macrunner_n_pub++ < 12)
            MESSAGE( "macrunner-xtajit-bounds: publish n=%d ветка=%s old=%p-%p мост=%p-%p итог=%p-%p\n",
                     macrunner_n_pub, (old->limit && old->base && old_low < old_high) ? "union" : "ELSE-замена",
                     old->limit, old->base, (void *)bridge_low, (void *)bridge_high,
                     teb->Tib.StackLimit, teb->Tib.StackBase );
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: потолок печати в 12 сделал равенство
         * счётчиков бессмысленным — оба упирались в него. Сами счётчики считают ВСЕ
         * вызовы, поэтому печатаем не первые N, а САМ ФАКТ расхождения: публикация без
         * парного восстановления означает, что путь ушёл мимо restore и подменённые
         * границы стека остались висеть на потоке. */
        if (macrunner_n_pub - macrunner_n_res > 1 && macrunner_n_imbalance++ < 16)
            MESSAGE( "macrunner-xtajit-bounds: РАСХОЖДЕНИЕ publish=%d restore=%d разница=%d\n",
                     macrunner_n_pub, macrunner_n_res, macrunner_n_pub - macrunner_n_res );
    }
}

static void restore_stack_bounds( TEB *teb, const struct xtajit_stack_bounds *old )
{
    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: считаем восстановления. Если publish было
     * больше, чем restore, значит какой-то путь ушёл мимо восстановления (longjmp
     * NtCallbackReturn — заявленный в комментарии на строке 947) и подменённые границы
     * остались висеть на потоке. Расхождение счётчиков — прямая улика. */
    {
        if (macrunner_n_res++ < 12)
            MESSAGE( "macrunner-xtajit-bounds: restore n=%d вернул=%p-%p\n",
                     macrunner_n_res, old->limit, old->base );
    }
    teb->Tib.StackBase = old->base;
    teb->Tib.StackLimit = old->limit;
}

/* Окружение в этом PE-модуле читается через RtlQueryEnvironmentVariable_U: `getenv` здесь
 * не компонуется (проверено сборкой — ld.lld: undefined symbol: getenv). */
static BOOL drop_stale_unixbop_enabled(void)
{
    static int cached = -1;

    if (cached < 0)
    {
        static const WCHAR nameW[] = {'M','A','C','R','U','N','N','E','R','_','X','T','A','J','I','T','_',
                                      'D','R','O','P','_','S','T','A','L','E','_','U','N','I','X','B','O','P',0};
        WCHAR value[4] = { 0 };
        UNICODE_STRING name, val;

        RtlInitUnicodeString( &name, nameW );
        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        cached = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND &&
                 value[0] && value[0] != '0';
        MESSAGE( "macrunner-gate: MACRUNNER_XTAJIT_DROP_STALE_UNIXBOP=%d\n", cached );
    }
    return cached;
}

static BOOL unixbop_frame_enabled(void)
{
    static int cached = -1;

    if (cached < 0)
    {
        static const WCHAR nameW[] = {'M','A','C','R','U','N','N','E','R','_','H','B','_',
                                      'U','N','I','X','B','O','P','_','F','R','A','M','E',0};
        WCHAR value[4] = { 0 };
        UNICODE_STRING name, val;

        RtlInitUnicodeString( &name, nameW );
        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        cached = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND &&
                 value[0] && value[0] != '0';
        MESSAGE( "macrunner-gate: MACRUNNER_HB_UNIXBOP_FRAME=%d\n", cached );
    }
    return cached;
}

static BOOL bop_syscall_frame_enabled(void)
{
    static int cached = -1;

    if (cached < 0)
    {
        static const WCHAR nameW[] = {'M','A','C','R','U','N','N','E','R','_','H','B','_','B','O','P','_','S','Y','S','C','A','L','L','_','F','R','A','M','E',0};
        WCHAR value[4] = { 0 };
        UNICODE_STRING name, val;

        RtlInitUnicodeString( &name, nameW );
        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        cached = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND &&
                 value[0] && value[0] != '0';
        MESSAGE( "macrunner-gate: MACRUNNER_HB_BOP_SYSCALL_FRAME=%d\n", cached );
    }
    return cached;
}

/* ★ MacRunner 2026-08-23, лейн ЛЕСТНИЦА, итерация 2685 — ЗОНД ПРЯМЫХ ВЫЗОВОВ БЕЗ ПЕРЕХОДНИКА.
 * Стек больного вызова (2680) не содержит НИ ОДНОГО из трёх переходников, а они глобальные
 * ассемблерные и попали бы в стек обязательно. Без переходника служба уходит ровно в двух
 * местах, и оба под `!teb`. Зонд БЕЗУСЛОВНЫЙ (гейта нет), потолок «первые 8 и каждый 5000-й» —
 * иначе строк было бы шестизначное число. Печать через MESSAGE, как остальные зонды файла. */
#define XTAJIT_TRACE_DIRECT_SYSCALL(place) \
    do { \
        static LONG _dn; \
        LONG _k = InterlockedIncrement( &_dn ); \
        if (_k <= 8 || !(_k % 5000)) \
            MESSAGE( "macrunner-xtajit-direct-syscall: n=%ld место=%s svc=%08x teb=%p\n", \
                     (long)_k, (place), service, (void *)teb ); \
    } while (0)

static NTSTATUS dispatch_wow64_syscall( UINT service, UINT *args )
{
#ifdef __aarch64__
    TEB *teb = xtajit_current_teb();
    struct xtajit_stack_bounds old;
    void *stack_top;
    void *old_active;
    NTSTATUS status;

    /* MacRunner 2026-08-23, лейн ЛЕСТНИЦА, итерация 2682 — выбор переходника гейтом.
     * Умолчание 0 = прежний путь дословно. При 1 берётся вариант, заводящий syscall_frame,
     * без которого `KeUserModeCallback` читает `frame->sp` из чужого кадра (корень 2680/2681). */
    /* MacRunner 2026-08-23, лейн ЛЕСТНИЦА, итерация 2683 — ПОЧЕМУ ЗДЕСЬ ИСКЛЮЧЕНА ОДНА СЛУЖБА.
     * Замер 2682: с кадром смертельный обратный вызов ИСЧЕЗ (ни одного `first-chance`), но
     * прогон встал — 600 диспетчеризаций против 3448, код 142. Причина видна выше по файлу:
     * `_current_stack` берётся как ЗАПАСНОЙ путь, и один из его случаев — строка с
     * `XTAJIT_WOW64_NTCALLBACKRETURN`, то есть ВОЗВРАТ из обратного вызова. По комментарию
     * у `wow64_NtCallbackReturn` он длинным переходом уходит в УЖЕ ЖИВОЙ кадр
     * `Wow64KiUserCallbackDispatcher`. Заводя перед ним новый `syscall_frame`, я затирала
     * ровно тот кадр, в который он обязан вернуться. Поэтому кадр ставим всем, КРОМЕ него. */
    #define CALL_WOW64_SYSCALL_CURRENT_STACK(phase) \
        (trace_arm64_pe_call_state( phase, service, (ULONG_PTR)Wow64SystemServiceEx, NULL, teb ), \
         (bop_syscall_frame_enabled() && service != XTAJIT_WOW64_NTCALLBACKRETURN) \
            ? xtajit_arm64_call_wow64_syscall_current_stack_frame( service, args, teb, Wow64SystemServiceEx ) \
            : xtajit_arm64_call_wow64_syscall_current_stack( service, args, teb, Wow64SystemServiceEx ))

    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ЗЕРКАЛО зонда в Wow64SystemServiceEx.
     * Там невозможный номер 0xc0000005 уже ловится. Этот зонд стоит ВЫШЕ переходника
     * и разделяет два случая за один прогон: сработал здесь — номер испорчен ДО
     * переходника (в handle_bop_context, то есть ctx->eax); сработал только там —
     * портит сам переходник xtajit_arm64_call_wow64_syscall при смене стека. */
    if (service >= 0x4000)
    {
        static unsigned int bogus_disp_n;

        if (bogus_disp_n++ < 8)
            MESSAGE( "macrunner-xtajit-bogus-dispatch: n=%u svc=%08x args=%p — номер испорчен "
                     "ДО переходника\n", bogus_disp_n, service, (void *)args );
    }

    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: СЧЁТЧИК ПО ЭТУ СТОРОНУ ПЕРЕХОДНИКА.
     * Парный счётчик стоит на входе в `Wow64SystemServiceEx`. Если у того входов
     * БОЛЬШЕ, значит в диспетчер попадают вызовы мимо нас — и порядок в журнале
     * покажет, между какими именно. Это ровно вопрос 2 внешнего разбора: отделён ли
     * код выхода из цикла от номера системного вызова. */
    {
        static unsigned int disp_seq;
        unsigned int n = ++disp_seq;

        /* ★★★★★ MacRunner 2026-08-30 — ПОТОЛОК ПЕЧАТИ: прибор стоил больше прогона.
         *
         * Печать шла БЕЗУСЛОВНО на каждой диспетчеризации. Замер на i386 `clock.exe`:
         * 216 тыс. гостевых вызовов -> журнал 88 МБ, из них 413 243 строки `xtajit`,
         * по 205 787 строк `disp` и `wssex`. Разбор такого файла занимает у лейна
         * больше времени, чем сам прогон, — то есть прибор стал дороже измерения.
         *
         * Печатаем первые MACRUNNER_XTAJIT_DISP_LIMIT (умолчание 2000) и ИТОГ в конце
         * каждой тысячи: счёт не теряется, а объём падает на два порядка. Предел не
         * молчаливый — при его достижении печатается строка, иначе «мало строк»
         * читалось бы как «мало вызовов» (память: no silent caps).
         * MACRUNNER_XTAJIT_DISP_LIMIT=0 возвращает прежнее поведение для сверки. */
        /* Гейта здесь НЕТ намеренно: модуль собран без libc, и `getenv` не линкуется
         * (проверено сборкой: `undefined symbol: getenv`). Это ровно то ограничение,
         * из-за которого getenv запрещён в PE-модулях. Потолок задан константой. */
        enum { DISP_LIMIT = 2000 };
        if (n <= DISP_LIMIT)
            MESSAGE( "macrunner-disp: n=%u svc=%08x\n", n, service );
        else if (n == DISP_LIMIT + 1)
            MESSAGE( "macrunner-disp: ПОТОЛОК %d достигнут, дальше только каждая тысяча\n",
                     (int)DISP_LIMIT );
        else if (!(n % 1000))
            MESSAGE( "macrunner-disp: ИТОГ n=%u svc=%08x\n", n, service );
    }

    /* ★ MacRunner 2026-08-30, лейн УСТАНОВЩИКИ — КАДР УСТАНОВЩИКА НА КАЖДОЙ ДИСПЕТЧЕРИЗАЦИИ.
     *
     * Установщик Diablo создаёт своё окно, делает ещё 158 системных вызовов и выходит
     * штатным Delphi Halt с кодом 1 (итерация 47). ЧТО он проверяет перед этим — не
     * известно, а перебор гипотез уже стоил четырёх итераций.
     *
     * `macrunner-disp` печатает номер вызова, но не КТО его сделал: гостевой eip на
     * границе всегда 0x270000 (переходник). Поднимаемся по цепочке EBP и печатаем
     * ПЕРВЫЙ адрес, попавший в код установщика. Секции взяты из заголовка двоичного:
     * .text 0x401000+0xf810, .itext 0x411000+0xff4 -> код это [0x401000, 0x412000).
     *
     * Гейт `MACRUNNER_XTAJIT_DISP_FRAMES`, умолчание 0: на каждый вызов это чтение
     * гостевой памяти, и в горячем прогоне (209 тыс. вызовов у i386 clock) оно бы
     * стоило дорого. Готового прибора для этого в дереве нет — искал: кадры печатают
     * только `delay-caller`, `ismemdc-caller`, `createwin-chain` и `кадры-EBP` на
     * выходе, все привязаны к своим местам. */
    {
        static int disp_frames = -1;

        if (disp_frames < 0)
        {
            UNICODE_STRING dfn;
            WCHAR dfb[8];
            UNICODE_STRING dfv = { 0, sizeof(dfb), dfb };

            RtlInitUnicodeString( &dfn, L"MACRUNNER_XTAJIT_DISP_FRAMES" );
            disp_frames = RtlQueryEnvironmentVariable_U( NULL, &dfn, &dfv ) ? 0 : (dfb[0] != '0');
        }
        /* `dispatch_wow64_syscall` контекста ЦП не получает (только service и args),
         * поэтому опорой берём сам `args` — он указывает в гостевой стек. Просматриваем
         * окно слов и печатаем ПЕРВОЕ значение из диапазона кода установщика. Тот же
         * приём уже работает в зонде `openfile` (поле «образ:»), и там он проверен. */
        if (disp_frames && args)
        {
            const ULONG *st = (const ULONG *)args;
            unsigned int d;
            ULONG nashel = 0, vtoroj = 0;

            for (d = 0; d < 256; d++)
            {
                ULONG v = st[d];

                if (v >= 0x401000 && v < 0x412000)
                {
                    if (!nashel) nashel = v;
                    else if (v != nashel) { vtoroj = v; break; }
                }
            }
            MESSAGE( "macrunner-disp-kadr: svc=%08x ustanovshik=%08lx vtoroj=%08lx slov=%u\n",
                     service, (unsigned long)nashel, (unsigned long)vtoroj, d );
        }
    }

    /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 250 — ГОСТЕВОЙ EIP НА ГРАНИЦЕ.
     * Замер блоков доказал: вход в CreateWindowExA и в CreateWindowExW исполнен по ОДНОМУ разу,
     * а границу WOW64 гость переходит 32 736 раз и столько же окон создаётся. Остаётся проверить,
     * не повторяется ли один и тот же системный вызов с ОДНОГО адреса — тогда причина в том, что
     * возврат не продвигает EIP, и это наш дефект, а не цикл игры. Печатаем только номер создания
     * окна (0x136b), иначе строк было бы 591 501. */
    /* Итерация 251: ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ к признаку. Постоянство Eip у 0x136b доказывает
     * повтор ТОЛЬКО если у служб, вызываемых из многих мест, адреса РАЗНЫЕ. Иначе Eip на
     * границе — структурная величина (адрес переходника), и признак негоден. Берём две самые
     * частые: 0x1332 (163 684 вызова) и 0x14b5 (163 686). */
    if (service == 0x136b || service == 0x1332 || service == 0x14b5)
    {
        /* Счётчики РАЗДЕЛЬНЫЕ: у 0x1332 и 0x14b5 по 163 тысячи вызовов против 32 тысяч у
         * 0x136b, и общий счётчик отдал бы все первые печати одной службе. */
        static unsigned int seq_cw, seq_a, seq_b;
        TEB *teb = NtCurrentTeb();
        WOW64_CPURESERVED *cpu = teb ? teb->TlsSlots[WOW64_TLS_CPURESERVED] : NULL;
        WOW64_CPU_AREA_INFO info;
        unsigned int n = (service == 0x136b) ? ++seq_cw
                       : (service == 0x1332) ? ++seq_a : ++seq_b;

        if (cpu && !RtlWow64GetCpuAreaInfo( cpu, 0, &info ) && info.Machine == IMAGE_FILE_MACHINE_I386)
        {
            I386_CONTEXT *c = info.Context;

            /* Гостевой Esp РАЗЫМЕНОВЫВАТЬ НЕЛЬЗЯ: 32-битное пространство лежит по ненулевой
             * базе, и прямое чтение по нему валит процесс (проверено этой же итерацией —
             * прогон умер на 17 029-й строке вместо 3.5 млн). Печатаем только регистры. */
            /* Итерация 251: сам `Eip` на границе оказался СТРУКТУРНЫМ — отрицательный контроль
             * дал 0x00270000 у всех трёх служб, включая вызываемые из 163 тысяч мест. Поэтому
             * место вызова берём из гостевого стека, и обязательно ЧЕРЕЗ БАЗУ: прямое
             * разыменование `Esp` убило прогон в прошлой итерации. */
            const DWORD *stk = c->Esp ? guest32_host_ptr( c->Esp ) : NULL;
            /* Итерация 252: ЧТО ЛЕЖИТ ПО Eip. Если гостевой Eip на границе указывает НА саму
             * инструкцию системного вызова (не продвинут), то `Wow64KiUserCallbackDispatcher`
             * сохраняет его в orig_ctx и ПОСЛЕ обратного вызова восстанавливает — и вызов
             * исполняется заново. Это объяснило бы 32 736 окон при одном гостевом вызове. */
            const BYTE *code = c->Eip ? guest32_host_ptr( c->Eip ) : NULL;

            if (n <= 4)
                MESSAGE( "macrunner-createwin-code: svc=%04x eip=%08x байты="
                         "%02x %02x %02x %02x %02x %02x %02x %02x\n", service, (unsigned int)c->Eip,
                         code ? code[0] : 0, code ? code[1] : 0, code ? code[2] : 0,
                         code ? code[3] : 0, code ? code[4] : 0, code ? code[5] : 0,
                         code ? code[6] : 0, code ? code[7] : 0 );

            /* Итерация 252: ВЛОЖЕНЫ ли создания друг в друга. Нативный указатель стека,
             * убывающий от вызова к вызову, означал бы рекурсию через обратный вызов; ровный —
             * последовательные выдачи. Гостевой код при этом исполнен по одному разу (все 16
             * блоков WIN_CreateWindowEx), так что цикл замыкается на нашей стороне. */
            if (n <= 24 || !(n % 4000))
                MESSAGE( "macrunner-createwin-sp: n=%u svc=%04x native_sp=%p\n",
                         n, service, (void *)current_native_sp() );

            if (n <= 24 || !(n % 4000))
                MESSAGE( "macrunner-createwin-eip: n=%u svc=%04x eip=%08x esp=%08x ebp=%08x "
                         "ret0=%08x ret1=%08x ret2=%08x\n",
                         n, service, (unsigned int)c->Eip, (unsigned int)c->Esp,
                         (unsigned int)c->Ebp,
                         stk ? (unsigned int)stk[0] : 0, stk ? (unsigned int)stk[1] : 0,
                         stk ? (unsigned int)stk[2] : 0 );
        }
        else if (n <= 6)
            MESSAGE( "macrunner-createwin-eip: n=%u КОНТЕКСТ НЕДОСТУПЕН cpu=%p\n", n, cpu );
    }

    /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 255 — ВИДИТ ЛИ ГОСТЬ ТАБЛИЦУ КАНАЛОВ.
     * Отладочные каналы wine из i386-модулей до журнала не доходят ВООБЩЕ: прогон с
     * `+ddraw,+d3d,+wgl` не дал ни одной строки, при том что эти модули загружены и вызываются.
     * PE-сторона берёт таблицу по `PEB32 + page_size` (`ntdll/thread.c:init_options`), а unix
     * пишет её по `peb + 2*page_size` (`unix/debug.c:dbg_init`); при `wow_peb = peb + page_size`
     * это один и тот же адрес — но только если гость ВИДИТ эту память по тому же числовому
     * адресу. Проверяем ровно это: читаем первые записи глазами гостя. */
    {
        static int probed;

        if (!probed)
        {
            TEB32 *t32 = xtajit_current_teb32();
            ULONG peb32 = t32 ? t32->Peb : 0;
            const BYTE *opt = peb32 ? guest32_host_ptr( peb32 + 0x1000 ) : NULL;

            probed = 1;
            if (opt)
            {
                /* struct __wine_debug_channel { unsigned char flags; char name[15]; } */
                /* MacRunner 2026-08-27: сверка по одному процессу и одному адресу показала,
                 * что хозяин пишет [ff 'd3d'], а гость по ТОМУ ЖЕ адресу через 21 мс видит
                 * [03 '']. Печатаем сырые байты: если 'd3d' лежит рядом со сдвигом — это
                 * расхождение раскладки; если байтов нет вовсе — гость смотрит в другую
                 * страницу, и числовое совпадение адресов обманчиво. */
                MESSAGE( "macrunner-xtajit-dbgchan: pid=%d peb32=%08lx таблица=%p записи: "
                         "[%02x '%.15s'] [%02x '%.15s'] [%02x '%.15s']\n",
                         (int)GetCurrentProcessId(), peb32, opt, opt[0], (const char *)opt + 1,
                         opt[16], (const char *)opt + 17, opt[32], (const char *)opt + 33 );
                MESSAGE( "macrunner-xtajit-dbgchan-сырьё: %02x%02x%02x%02x%02x%02x%02x%02x "
                         "%02x%02x%02x%02x%02x%02x%02x%02x | %02x%02x%02x%02x%02x%02x%02x%02x "
                         "%02x%02x%02x%02x%02x%02x%02x%02x\n",
                         opt[0],opt[1],opt[2],opt[3],opt[4],opt[5],opt[6],opt[7],
                         opt[8],opt[9],opt[10],opt[11],opt[12],opt[13],opt[14],opt[15],
                         opt[16],opt[17],opt[18],opt[19],opt[20],opt[21],opt[22],opt[23],
                         opt[24],opt[25],opt[26],opt[27],opt[28],opt[29],opt[30],opt[31] );
            }
            else
                MESSAGE( "macrunner-xtajit-dbgchan: peb32=%08lx таблица НЕДОСТУПНА\n", peb32 );
        }
    }

    mask_native_guest32_exception_list( teb, service, "dispatch" );

    /* wow64_NtCallbackReturn longjmps to the active Wow64KiUserCallbackDispatcher frame. */
    if (service == XTAJIT_WOW64_NTCALLBACKRETURN)
    {
        if (teb) teb->Tib.ExceptionList = (void *)~(ULONG_PTR)0;
        if (teb) return CALL_WOW64_SYSCALL_CURRENT_STACK( "ntcallbackreturn-current-stack" );
        XTAJIT_TRACE_DIRECT_SYSCALL( "ntcbret-noteb" );
        return Wow64SystemServiceEx( service, args );
    }

    if (teb && teb->TlsSlots[XTAJIT_TLS_BRIDGE_ACTIVE])
    {
        if ((stack_top = bridge_stack_top_below_syscall_frame( teb )))
        {
            if (trace_native_stack_enabled())
            {
                ULONG_PTR frame = *(ULONG_PTR *)((char *)teb + XTAJIT_TEB_SYSCALL_FRAME_OFFSET);
                MESSAGE( "macrunner-xtajit-stack: active-nested-syscall-switch svc=%08x "
                         "native_sp=%p syscall_frame=%p nested_top=%p\n",
                         service, (void *)current_native_sp(), (void *)frame, stack_top );
            }
            trace_arm64_pe_call_state( "active-nested-syscall-switch", service,
                                       (ULONG_PTR)Wow64SystemServiceEx, stack_top, teb );
            return xtajit_arm64_call_wow64_syscall( service, args, stack_top, teb, Wow64SystemServiceEx );
        }
        if ((stack_top = bridge_stack_top_below_current_sp( teb )))
        {
            if (trace_native_stack_enabled())
            {
                ULONG_PTR frame = *(ULONG_PTR *)((char *)teb + XTAJIT_TEB_SYSCALL_FRAME_OFFSET);
                MESSAGE( "macrunner-xtajit-stack: active-current-syscall-switch svc=%08x "
                         "native_sp=%p syscall_frame=%p nested_top=%p bridge=%p-%p\n",
                         service, (void *)current_native_sp(), (void *)frame, stack_top,
                         teb->TlsSlots[XTAJIT_TLS_BRIDGE_STACK],
                         (void *)((ULONG_PTR)teb->TlsSlots[XTAJIT_TLS_BRIDGE_STACK] +
                                  (SIZE_T)teb->TlsSlots[XTAJIT_TLS_BRIDGE_SIZE]) );
            }
            trace_arm64_pe_call_state( "active-current-syscall-switch", service,
                                       (ULONG_PTR)Wow64SystemServiceEx, stack_top, teb );
            return xtajit_arm64_call_wow64_syscall( service, args, stack_top, teb, Wow64SystemServiceEx );
        }
        if (trace_native_stack_enabled() && (service == 0x33 || service == 0x133d))
        {
            ULONG_PTR bridge_low = (ULONG_PTR)teb->TlsSlots[XTAJIT_TLS_BRIDGE_STACK];
            ULONG_PTR bridge_size = (SIZE_T)teb->TlsSlots[XTAJIT_TLS_BRIDGE_SIZE];
            ULONG_PTR frame = *(ULONG_PTR *)((char *)teb + XTAJIT_TEB_SYSCALL_FRAME_OFFSET);
            MESSAGE( "macrunner-xtajit-stack: active-direct-no-switch svc=%08x native_sp=%p "
                     "syscall_frame=%p bridge=%p-%p teb_stack=%p-%p\n",
                     service, (void *)current_native_sp(), (void *)frame,
                     (void *)bridge_low, (void *)(bridge_low + bridge_size),
                     teb->Tib.StackLimit, teb->Tib.StackBase );
        }
        return CALL_WOW64_SYSCALL_CURRENT_STACK( "active-current-stack" );
    }
    if (!teb)
    {
        XTAJIT_TRACE_DIRECT_SYSCALL( "dispatch-noteb" );
        return Wow64SystemServiceEx( service, args );
    }
    if (ensure_bridge_stack()) return CALL_WOW64_SYSCALL_CURRENT_STACK( "ensure-stack-fallback-current-stack" );

    publish_bridge_stack_bounds( teb, &old );
    stack_top = bridge_syscall_call_stack_top( teb );
    if (!stack_top)
    {
        restore_stack_bounds( teb, &old );
        return CALL_WOW64_SYSCALL_CURRENT_STACK( "bridge-stack-null-current-stack" );
    }
    old_active = teb->TlsSlots[XTAJIT_TLS_BRIDGE_ACTIVE];
    teb->TlsSlots[XTAJIT_TLS_BRIDGE_ACTIVE] = (void *)1;
    trace_arm64_pe_call_state( "bridge-stack-dispatch", service,
                               (ULONG_PTR)Wow64SystemServiceEx, stack_top, teb );
    status = xtajit_arm64_call_wow64_syscall( service, args, stack_top, teb, Wow64SystemServiceEx );
    teb->TlsSlots[XTAJIT_TLS_BRIDGE_ACTIVE] = old_active;
    restore_stack_bounds( teb, &old );
    return status;
    #undef CALL_WOW64_SYSCALL_CURRENT_STACK
#else
    return Wow64SystemServiceEx( service, args );
#endif
}

static void dump_guest_dwords( const char *label, DWORD guest, unsigned int count )
{
    DWORD data[8] = { 0 };
    DWORD *ptr = guest32_host_ptr( guest );

    if (count > ARRAY_SIZE(data)) count = ARRAY_SIZE(data);
    copy_guest32_dwords( guest, data, count );

    MESSAGE( "macrunner-xtajit: %s guest=%08lx host=%p data=%08lx,%08lx,%08lx,%08lx,%08lx,%08lx,%08lx,%08lx\n",
             label, guest, ptr, data[0], data[1], data[2], data[3],
             data[4], data[5], data[6], data[7] );
}

static void dump_guest_bytes( const char *label, DWORD guest, unsigned int count )
{
    BYTE data[96] = { 0 };
    BYTE *ptr = guest32_host_ptr( guest );
    unsigned int i;

    if (count > ARRAY_SIZE(data)) count = ARRAY_SIZE(data);
    copy_guest32_bytes( guest, data, count );

    MESSAGE( "macrunner-xtajit: %s guest=%08lx host=%p bytes=", label, guest, ptr );
    for (i = 0; i < count; i++) MESSAGE( "%02x", data[i] );
    MESSAGE( "\n" );
}

static DWORD parse_trace_pc_value( const WCHAR *value, USHORT len )
{
    DWORD out = 0, base = 10;
    unsigned int i = 0, chars = len / sizeof(WCHAR);

    while (i < chars && (value[i] == ' ' || value[i] == '\t')) i++;
    if (i + 1 < chars && value[i] == '0' && (value[i + 1] == 'x' || value[i + 1] == 'X'))
    {
        base = 16;
        i += 2;
    }
    for (; i < chars; i++)
    {
        WCHAR ch = value[i];
        DWORD digit;
        if (!ch || ch == ' ' || ch == '\t') break;
        if (ch >= '0' && ch <= '9') digit = ch - '0';
        else if (ch >= 'a' && ch <= 'f') digit = 10 + ch - 'a';
        else if (ch >= 'A' && ch <= 'F') digit = 10 + ch - 'A';
        else break;
        if (digit >= base) break;
        out = out * base + digit;
    }
    return out;
}

static DWORD trace_stuck_pc_value(void)
{
    static int parsed;
    static DWORD pc;

    if (!parsed)
    {
        static const WCHAR nameW[] =
            {'M','A','C','R','U','N','N','E','R','_','X','T','A','J','I','T','_',
             'T','R','A','C','E','_','S','T','U','C','K','_','P','C',0};
        WCHAR value[32];
        UNICODE_STRING name, val;

        RtlInitUnicodeString( &name, nameW );
        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        if (RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND)
            pc = parse_trace_pc_value( value, val.Length );
        parsed = 1;
    }
    return pc;
}

static BOOL trace_stuck_hit_should_log( unsigned int hit )
{
    return hit <= 16 || !(hit & (hit - 1));
}

static void trace_stuck_i386_context( const struct xtajit_i386_context *ctx,
                                      unsigned long long steps, NTSTATUS status, BOOL bop2 )
{
    static unsigned int hits;
    DWORD pc = trace_stuck_pc_value();
    unsigned int hit;

    if (!pc || !ctx || ctx->eip != pc) return;
    hit = ++hits;
    if (!trace_stuck_hit_should_log( hit )) return;
    MESSAGE( "macrunner-xtajit: stuck-pc hit=%u status=%08lx steps=%llu bop2=%u "
             "eip=%08lx esp=%08lx ebp=%08lx eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx "
             "esi=%08lx edi=%08lx eflags=%08lx\n",
             hit, status, steps, bop2, ctx->eip, ctx->esp, ctx->ebp, ctx->eax, ctx->ebx,
             ctx->ecx, ctx->edx, ctx->esi, ctx->edi, ctx->eflags );
    dump_guest_dwords( "stuck ebp-40", ctx->ebp - 0x40, 8 );
    dump_guest_dwords( "stuck ebp", ctx->ebp, 8 );
    dump_guest_dwords( "stuck esp", ctx->esp, 8 );
    dump_guest_dwords( "stuck eax-40", ctx->eax - 0x40, 8 );
    dump_guest_dwords( "stuck edi-40", ctx->edi - 0x40, 8 );
}

static void dump_syscall_bop_stack( DWORD service, const struct xtajit_i386_context *ctx,
                                    DWORD ret_eip, DWORD ret_esp )
{
    DWORD raw[10] = { 0 };
    DWORD sample4[6] = { 0 };
    DWORD sample8[6] = { 0 };
    static int trace_count;

    if (trace_count >= 128 && service != 0x18 && service != 0x49 && service != 0xcf &&
        service != 0x1246 &&
        !trace_all_simulate_enabled())
        return;
    trace_count++;

    copy_guest32_dwords( ctx->esp, raw, ARRAY_SIZE(raw) );
    copy_guest32_dwords( ret_esp, sample4, ARRAY_SIZE(sample4) );
    copy_guest32_dwords( ret_esp + sizeof(DWORD), sample8, ARRAY_SIZE(sample8) );

    MESSAGE( "macrunner-xtajit: syscall bop stack svc=%08lx esp=%08lx ret=%08lx ret_esp=%08lx "
             "raw=%08lx,%08lx,%08lx,%08lx,%08lx,%08lx,%08lx,%08lx,%08lx,%08lx "
             "args4=%08lx,%08lx,%08lx,%08lx,%08lx,%08lx "
             "args8=%08lx,%08lx,%08lx,%08lx,%08lx,%08lx\n",
             service, ctx->esp, ret_eip, ret_esp,
             raw[0], raw[1], raw[2], raw[3], raw[4],
             raw[5], raw[6], raw[7], raw[8], raw[9],
             sample4[0], sample4[1], sample4[2], sample4[3], sample4[4], sample4[5],
             sample8[0], sample8[1], sample8[2], sample8[3], sample8[4], sample8[5] );

    MESSAGE( "macrunner-xtajit: syscall bop regs svc=%08lx eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx esi=%08lx edi=%08lx ebp=%08lx esp=%08lx eip=%08lx eflags=%08lx\n",
             service, ctx->eax, ctx->ebx, ctx->ecx, ctx->edx, ctx->esi, ctx->edi,
             ctx->ebp, ctx->esp, ctx->eip, ctx->eflags );
    dump_guest_dwords( "bop ebp-40", ctx->ebp - 0x40, 8 );
    dump_guest_dwords( "bop ebp", ctx->ebp, 8 );
    if (ctx->ebp)
    {
        DWORD *frame = guest32_host_ptr( ctx->ebp );
        if (frame)
        {
            dump_guest_dwords( "bop caller-ebp-40", frame[0] - 0x40, 8 );
            dump_guest_dwords( "bop caller-ebp", frame[0], 8 );
        }
    }
    dump_guest_dwords( "bop edi", ctx->edi, 4 );
    dump_guest_dwords( "bop ebx", ctx->ebx, 4 );
}

static I386_CONTEXT *host_i386_context_ptr( I386_CONTEXT *ctx )
{
    ULONG_PTR ptr = (ULONG_PTR)ctx;

    if (ptr && ptr <= 0xffffffff) return guest32_host_ptr( PtrToUlong( ctx ) );
    return ctx;
}

static BYTE *ensure_guest_bop( BYTE **slot, const BYTE *opcode )
{
    BYTE *ptr = *slot;
    SIZE_T size = 0x1000;
    NTSTATUS status;

    if (ptr) return ptr;
    ptr = NULL;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&ptr, 0, &size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    if (status) return NULL;
    ptr[0] = opcode[0];
    ptr[1] = opcode[1];
    NtFlushInstructionCache( NtCurrentProcess(), ptr, 2 );
    *slot = ptr;
    return ptr;
}

static NTSTATUS xtajit_unix_call( enum xtajit_unix_funcs func, void *params )
{
    NTSTATUS status = __wine_init_unix_call();
    if (status) return status;
    return WINE_UNIX_CALL( func, params );
}

/* ★ MacRunner 2026-08-28 — СПРОСИТЬ КАРТУ ДВИЖКА (а не склейку окна).
 *
 * `guest32_host_ptr` ниже — простая склейка старших битов окна с гостевым адресом;
 * она НИКОГДА не возвращает ноль и потому не годится для проверки «знает ли движок
 * этот адрес». Решения об отказе принимаются по карте `hb_memory_*`, и спрашивать
 * надо именно её — через мост в unixlib.
 *
 * Возвращает TRUE, если регион найден. По желанию заполняет права и хозяйский адрес. */
static BOOL xtajit_probe_guest_addr( ULONG addr, struct xtajit_probe_params *out )
{
    struct xtajit_probe_params p;

    memset( &p, 0, sizeof(p) );
    p.addr = addr;
    if (xtajit_unix_call( unix_probe_guest_addr, &p )) return FALSE;
    if (out) *out = p;
    return p.known != 0;
}


static BOOL trace_all_simulate_enabled(void);

static void pack_i386_context( struct xtajit_i386_context *dst, const I386_CONTEXT *src )
{
    TEB32 *teb32 = xtajit_current_teb32();

    dst->eax = src->Eax;
    dst->ebx = src->Ebx;
    dst->ecx = src->Ecx;
    dst->edx = src->Edx;
    dst->esi = src->Esi;
    dst->edi = src->Edi;
    dst->esp = src->Esp;
    dst->ebp = src->Ebp;
    dst->eip = src->Eip;
    dst->eflags = src->EFlags;
    dst->fs_base = PtrToUlong( teb32 );
    dst->gs_base = src->SegGs;
    dst->seg_cs = src->SegCs;
    dst->seg_ds = src->SegDs;
    dst->seg_es = src->SegEs;
    dst->seg_fs = src->SegFs;
    dst->seg_gs = src->SegGs;
    dst->seg_ss = src->SegSs;
    dst->teb32_host = (ULONG_PTR)teb32;
    /*
     * i386 ntdll keeps per-thread Wine debug buffers immediately after TEB32
     * (see ntdll/thread.c:get_info()).  Guest fs: accesses must see that
     * adjacent area too; mirroring only sizeof(TEB32) faults at fs:[0x1000].
     */
    dst->teb32_size = sizeof(*teb32) + 0x800;
    dst->wow32_reserved = teb32 ? teb32->WOW32Reserved : 0;
    dst->x87_cw = src->FloatSave.ControlWord;
    dst->x87_sw = src->FloatSave.StatusWord;
    dst->x87_tw = src->FloatSave.TagWord;
}

static void unpack_i386_context( I386_CONTEXT *dst, const struct xtajit_i386_context *src )
{
    dst->ContextFlags = CONTEXT_I386_ALL;
    dst->Eax = src->eax;
    dst->Ebx = src->ebx;
    dst->Ecx = src->ecx;
    dst->Edx = src->edx;
    dst->Esi = src->esi;
    dst->Edi = src->edi;
    dst->Esp = src->esp;
    dst->Ebp = src->ebp;
    dst->Eip = src->eip;
    dst->EFlags = src->eflags;
    dst->SegCs = src->seg_cs;
    dst->SegDs = src->seg_ds;
    dst->SegEs = src->seg_es;
    dst->SegFs = src->seg_fs;
    dst->SegGs = src->seg_gs;
    dst->SegSs = src->seg_ss;
    dst->FloatSave.ControlWord = src->x87_cw;
    dst->FloatSave.StatusWord = src->x87_sw;
    dst->FloatSave.TagWord = src->x87_tw;
}

static NTSTATUS publish_simulated_i386_context( const struct xtajit_i386_context *ctx )
{
    I386_CONTEXT host_ctx = { CONTEXT_I386_ALL };

    if (!ctx) return STATUS_INVALID_PARAMETER;
    unpack_i386_context( &host_ctx, ctx );
    return write_current_i386_context( &host_ctx, FALSE );
}

static NTSTATUS publish_simulated_i386_exception_context( const struct xtajit_i386_context *ctx )
{
    I386_CONTEXT host_ctx = { CONTEXT_I386_ALL };

    if (!ctx) return STATUS_INVALID_PARAMETER;
    unpack_i386_context( &host_ctx, ctx );
    return write_current_i386_context( &host_ctx, TRUE );
}

/* Recursion depth counter for guest exception dispatch.
 * Breaks the infinite recursion that occurs when the guest SEH handler itself faults
 * before TEB32/PEB32 are fully initialized: BTCpuSimulate → pass_guest_exception →
 * Wow64PassExceptionToGuest → BTCpuSimulate (new eip=handler) → faults → repeat.
 * Stored in TEB's TlsSlots at a private slot to keep it per-thread without __thread TLS. */
#define XTAJIT_TLS_GUEST_EXC_DEPTH 14  /* slots 15-18 taken; 0,2,4,6,9,11-14 are free */

static BOOL pass_guest_exception( const struct xtajit_simulate_params *params, NTSTATUS status )
{
    const struct xtajit_i386_context *ctx = params ? &params->context : NULL;
    EXCEPTION_RECORD rec;
    EXCEPTION_POINTERS ptrs;
    CONTEXT native_context;

    /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1083 — СПИСОК ПРОПУСКА БЫЛ НЕПОЛОН.
     *
     * Здесь стояли ДВА статуса из шести, которые движок умеет порождать. Остальные
     * отвергались, уходили в общий подъём статуса и приходили гостю НЕПРОДОЛЖАЕМЫМИ и с
     * ХОЗЯЙСКОГО адреса. Замер 1082 (проба `sixroads32`):
     *
     *     дорога нарушения доступа: flags=0 addr=004013D0   ← верно, идёт этой функцией
     *     дорога деления:           flags=1 addr=000007FFD0779E4C ← неверно, обошла её
     *
     * Обработчик гостя не может вернуть управление из непродолжаемого исключения, поэтому
     * проба умирала на третьей дороге из шести (код 148).
     *
     * Список расширен РОВНО на те статусы, которые мы порождаем сами и намеренно (виды отказа
     * `hb_context.h`: деление, переход по нулю, привилегия, недопустимая команда, сторожевая
     * страница). Всё прочее по-прежнему отвергается: внутренняя ошибка движка не должна
     * приходить гостю под видом исключения процессора. */
    if (status != STATUS_ACCESS_VIOLATION &&
        status != STATUS_ILLEGAL_INSTRUCTION &&
        status != STATUS_INTEGER_DIVIDE_BY_ZERO &&
        status != STATUS_PRIVILEGED_INSTRUCTION &&
        status != STATUS_GUARD_PAGE_VIOLATION &&
        /* ★ 30.08: шестой вид отказа — стек сопроцессора (HB_FAULT_KIND_FPU_STACK).
         * Список тем и расширяется: ровно на то, что движок порождает НАМЕРЕННО. */
        status != STATUS_FLOAT_STACK_CHECK)
        return FALSE;

    {
        TEB *teb = xtajit_current_teb();
        ULONG_PTR depth = (ULONG_PTR)teb->TlsSlots[XTAJIT_TLS_GUEST_EXC_DEPTH];
        MESSAGE( "macrunner-xtajit: pass_guest_exception tls14=%lu eip=%08lx\n",
                 (unsigned long)depth, ctx ? ctx->eip : 0 );
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: c000001d = наш транслятор не знает команду.
         * Печатаем САМИ БАЙТЫ по гостевому eip — иначе «нелегальная команда» не говорит,
         * КАКАЯ именно, а это конечное множество с эталоном (capstone), то есть массовая
         * задача, а не разовая. Зонд безусловный, только на этом статусе. */
        if (status == STATUS_ILLEGAL_INSTRUCTION && ctx)
        {
            /* ★ 27.08: ШЕСТНАДЦАТИ БАЙТ НЕ ХВАТАЕТ.
             *
             * Замер Heroes III: все три отказа дали одни и те же 16 байт, и все они —
             * базовые команды (MOV/CMP/INC), которые транслятор заведомо умеет:
             *
             *   8a 4c 07 04  MOV CL,[EDI+EAX+4] / 83 ff 20 CMP EDI,0x20
             *   88 4d 0f     MOV [EBP+0xF],CL   / fe c1    INC CL
             *   88 4c 07 04  MOV [EDI+EAX+4],CL
             *
             * Значит `eip` указывает на НАЧАЛО блока, а непонятая команда лежит дальше —
             * ровно как это уже было с `INT 0x29` (там `cd 29` стояло на смещении 3).
             * Берём 48 байт: этого хватает на десяток команд. */
            /* ★ 28.08: И СОРОКА ВОСЬМИ БАЙТ НЕ ХВАТИЛО.
             *
             * Замер Diablo: те же 48 байт по eip=78a0d6f7 разбираются ЦЕЛИКОМ — все
             * девять команд блока (movsd/movd/movdqa/cmpsd/pand/por/psrlq) проба
             * `tests/hb_x86_probe` принимает с decode:0 lift:0. Значит непонятая
             * команда лежит ЗА окном: девять команд занимают ровно 49 байт, то есть
             * окно обрывалось на первой, до которой разбор и не доходил.
             *
             * Тот же класс, что ловили дважды до этого (INT 0x29 на смещении 3,
             * Heroes III с базовыми MOV/CMP): `eip` указывает на начало блока, а не
             * на виновную команду. Берём 128 байт — это тридцать с лишним команд. */
            const BYTE *code = guest32_host_ptr( ctx->eip );
            char hex[128 * 3 + 1];
            unsigned int i;

            if (code)
            {
                for (i = 0; i < 128; i++)
                {
                    static const char d[] = "0123456789abcdef";
                    hex[i * 3 + 0] = d[code[i] >> 4];
                    hex[i * 3 + 1] = d[code[i] & 0xf];
                    hex[i * 3 + 2] = ' ';
                }
                hex[128 * 3] = 0;
                MESSAGE( "macrunner-xtajit: illegal-insn eip=%08lx bytes= %s\n", ctx->eip, hex );

                /* MacRunner 2026-08-27 — INT 0x29 ЭТО __fastfail, А НЕ НЕДОПУСТИМАЯ КОМАНДА.
                 *
                 * Замер Heroes III: 61 исключение подряд по одному адресу. Разбор байтов:
                 *
                 *     6a 07     PUSH 7          (FAST_FAIL_FATAL_APP_EXIT)
                 *     59        POP  ECX
                 *     cd 29     INT  0x29       <- __fastfail
                 *
                 * Транслятор команду не знает и отдаёт c000001d, гость её ЛОВИТ своим SEH,
                 * снова доходит до fastfail — и так по кругу, пока цепочка обработчиков не
                 * кончится, после чего процесс умирает с c0000025 «continue after
                 * noncontinuable».
                 *
                 * В Windows __fastfail устроен ровно наоборот: он НАМЕРЕННО обходит SEH,
                 * векторные обработчики и отладчик, завершая процесс сразу с
                 * STATUS_STACK_BUFFER_OVERRUN. Каскада там быть не может по построению.
                 *
                 * Делаем как в Windows: узнаём последовательность и завершаем процесс, не
                 * передавая исключение гостю.
                 *
                 * Гейт MACRUNNER_HB_FASTFAIL, умолчание ВЫКЛ до замера на двух мишенях. */
                /* ★ ПОПРАВКА ТОГО ЖЕ ЧАСА: eip указывает на НАЧАЛО блока, а не на саму
                 * команду. Байты по нему — `6a 07 59 cd 29 ...`, то есть `cd 29` стоит на
                 * смещении 3. Первая редакция сверяла только code[0..1] и не срабатывала ни
                 * разу (счётчик fastfail=0 при 60 отказах). Ищем последовательность в начале
                 * блока: PUSH imm8 / POP ECX / INT 0x29 — это и есть развёрнутый __fastfail. */
                {
                    unsigned int ff;
                    BOOL is_fastfail = FALSE;

                    /* ★ УЖЕСТОЧЕНИЕ: завершение процесса необратимо, поэтому ищем не просто
                     * байты `cd 29` где-то рядом, а КАНОНИЧЕСКУЮ форму __fastfail — код
                     * причины кладётся в ECX непосредственно перед прерыванием:
                     *
                     *     6a XX  59  cd 29     PUSH imm8 / POP ECX / INT 0x29
                     *     b9 XX XX XX XX cd 29 MOV ECX, imm32 / INT 0x29
                     *     cd 29                само прерывание в начале блока
                     *
                     * Случайное совпадение двух байтов внутри чужой команды такую форму не
                     * даёт. */
                    if (code[0] == 0xcd && code[1] == 0x29) is_fastfail = TRUE;
                    else if (code[0] == 0x6a && code[2] == 0x59 &&
                             code[3] == 0xcd && code[4] == 0x29) is_fastfail = TRUE;
                    else if (code[0] == 0xb9 && code[5] == 0xcd && code[6] == 0x29) is_fastfail = TRUE;
                    (void)ff;
                    if (is_fastfail)
                {
                    static int gate = -1;

                    if (gate < 0)
                    {
                        static const WCHAR nameW[] = {'M','A','C','R','U','N','N','E','R','_',
                                                      'H','B','_','F','A','S','T','F','A','I','L',0};
                        WCHAR value[4] = { 0 };
                        UNICODE_STRING name, val;

                        RtlInitUnicodeString( &name, nameW );
                        val.Buffer = value;
                        val.Length = 0;
                        val.MaximumLength = sizeof(value);
                        /* Умолчание ВКЛ после замера на трёх мишенях: Heroes III — каскад
                         * 61 -> 2 исключения и noncontinuable 1 -> 0; Diablo и UT99 — форма
                         * не встречается вовсе. Выключается значением "0". */
                        gate = (RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND &&
                                value[0] == '0') ? 0 : 1;
                    }
                    if (gate)
                    {
                        MESSAGE( "macrunner-xtajit: fastfail eip=%08lx код=%lu — завершаем процесс, "
                                 "как это делает Windows\n", ctx->eip, (unsigned long)ctx->ecx );
                        NtTerminateProcess( GetCurrentProcess(), STATUS_STACK_BUFFER_OVERRUN );
                    }
                }
                }
            }
            else
                MESSAGE( "macrunner-xtajit: illegal-insn eip=%08lx байты недоступны\n", ctx->eip );
        }
        if (depth >= 3)
        {
            MESSAGE( "macrunner-xtajit: pass_guest_exception depth=%lu eip=%08lx — breaking recursive guest dispatch\n",
                     (unsigned long)depth, ctx ? ctx->eip : 0 );
            /* Do NOT reset depth: leave it high so callers higher on the stack also break. */
            return FALSE;
        }
        teb->TlsSlots[XTAJIT_TLS_GUEST_EXC_DEPTH] = (void *)(depth + 1);
    }

    memset( &rec, 0, sizeof(rec) );
    memset( &native_context, 0, sizeof(native_context) );
    RtlCaptureContext( &native_context );

    rec.ExceptionCode = status;
    rec.ExceptionAddress = ULongToPtr( ctx ? ctx->eip : 0 );

    if (status == STATUS_ACCESS_VIOLATION)
    {
        rec.NumberParameters = 2;
        /* ★★★★ 27.08.2026 — СООБЩАЕМ НАСТОЯЩИЕ ВИД ДОСТУПА И АДРЕС.
         *
         * Здесь стояли жёсткие нули с примечаниями «HyperBridge does not yet report write
         * faults» и «faulting address is not exported yet», то есть КАЖДОЕ нарушение доступа
         * приходило гостю как «чтение по адресу 0». Обработчик читает ровно эти два поля.
         *
         * Heroes III: его обработчик кучи получал ложь, пробовал работать с нулевой страницей,
         * падал снова на том же месте — и на третьем витке защита `depth >= 3` ниже обрывала
         * передачу, превращая ловимое исключение в фатальное (RtlRaiseStatus → раскрутка без
         * обработчика → останов на границе x86/ARM64).
         *
         * Значения приходят из `hb_memory_last_fault()` через unixlib. Нули остаются, только
         * если источник сказал «адрес неизвестен» — то есть прежнее поведение как запасное. */
        rec.ExceptionInformation[0] = EXCEPTION_READ_FAULT;
        rec.ExceptionInformation[1] = 0;
        if (params && params->mem_fault_valid)
        {
            rec.ExceptionInformation[0] = params->mem_fault_is_write
                                        ? EXCEPTION_WRITE_FAULT : EXCEPTION_READ_FAULT;
            rec.ExceptionInformation[1] = (ULONG_PTR)params->mem_fault_addr;
        }

        if (params && params->hb_result == HB_ERR_MEMORY_FAULT && params->faulted &&
            !params->steps && !params->blocks && ctx)
        {
            rec.ExceptionInformation[0] = 8; /* execute */
            rec.ExceptionInformation[1] = ctx->eip;
        }
        /* Итерация 805: вид отказа известен точно (`ctx->last_fault_kind` со стороны Unix), и
         * для перехода по нулю Windows сообщает признак ИСПОЛНЕНИЯ и адрес ЦЕЛИ — не адрес
         * команды. Обработчики игр читают именно это поле, поэтому догадка по косвенным
         * признакам выше здесь заменяется прямым значением. */
        if (params && params->fault_kind == 2 /* HB_FAULT_KIND_NULL_EXEC */)
        {
            rec.ExceptionInformation[0] = 8; /* execute */
            rec.ExceptionInformation[1] = params->fault_addr_valid
                                        ? (ULONG_PTR)params->fault_addr : 0;
        }
    }

    ptrs.ExceptionRecord = &rec;
    ptrs.ContextRecord = &native_context;
    Wow64PassExceptionToGuest( &ptrs );
    return TRUE;
}

struct xtajit_teb32_stack_base
{
    TEB32 *teb32;
    ULONG old_base;
};

static void publish_pending_guest_stack_base( const struct xtajit_i386_context *ctx,
                                              struct xtajit_teb32_stack_base *old )
{
    TEB32 *teb32 = xtajit_context_teb32( ctx );

    old->teb32 = teb32;
    old->old_base = teb32 ? teb32->Tib.StackBase : 0;
    if (teb32 && ctx && ctx->esp) teb32->Tib.StackBase = ctx->esp;
}

static void restore_pending_guest_stack_base( const struct xtajit_teb32_stack_base *old )
{
    if (old->teb32) old->teb32->Tib.StackBase = old->old_base;
}

BOOL WINAPI DllMain( HINSTANCE inst, DWORD reason, void *reserved )
{
    if (reason == DLL_PROCESS_ATTACH) LdrDisableThreadCalloutsForDll( inst );
    return TRUE;
}

void *WINAPI BTCpuGetBopCode(void)
{
    BYTE *ptr = ensure_guest_bop( &syscall_bop_guest, syscall_bop );
    MESSAGE( "macrunner-xtajit: BTCpuGetBopCode -> %p guest=%08lx\n",
             ptr ? ptr : syscall_bop, ptr ? PtrToUlong( ptr ) : PtrToUlong( syscall_bop ) );
    return ptr ? ptr : syscall_bop;
}

void *WINAPI __wine_get_unix_opcode(void)
{
    BYTE *ptr = ensure_guest_bop( &unix_bop_guest, unix_bop );
    return ptr ? ptr : unix_bop;
}

BOOLEAN WINAPI BTCpuIsProcessorFeaturePresent( UINT feature )
{
    return RtlIsProcessorFeaturePresent( feature );
}

void WINAPI BTCpuProcessInit(void)
{
    NTSTATUS status;

    xtajit_arm_x18_from_tls();   /* пока x18 цел: запомнить, где TEB лежит в TSD */
    status = xtajit_unix_call( unix_process_init, NULL );
    MESSAGE( "macrunner-xtajit: BTCpuProcessInit status=%08lx\n", status );
    if (status) xtajit_raise_status( status );
}

void WINAPI BTCpuProcessTerm( HANDLE handle, BOOL is_post, NTSTATUS status )
{
    struct xtajit_memory_params params = { handle, 0, 0, 0, is_post, status };
    if (trace_process_exit_enabled())
        MESSAGE( "macrunner-xtajit-exit: BTCpuProcessTerm pid=%lu tid=%lu handle=%p is_post=%u status=%08lx\n",
                 GetCurrentProcessId(), GetCurrentThreadId(), handle, is_post, status );
    (void)xtajit_unix_call( unix_process_term, &params );
}

/* MacRunner 2026-08-27 — ФИКСАЦИЯ ВЕРХА ГОСТЕВОГО СТЕКА ПРИ СТАРТЕ ПОТОКА.
 *
 * Замер Heroes III: шесть отказов доступа, все с prot=0 (зарезервировано, не
 * зафиксировано), по одному на каждый из шести гостевых стеков. Каждый — вход в ядро
 * через SIGBUS, наш обработчик и mprotect.
 *
 * В Windows такого не бывает: поток получает SizeOfStackCommit сразу при создании, а
 * дальше стек растёт через страницу-сторож, и расширение делает ЯДРО — приложение
 * отказа не видит вовсе. У нас же лениво всё, поэтому первое касание каждого стека
 * стоит отказа.
 *
 * Фиксируем верхнюю часть стека сразу, как только поток стартовал и его TEB32 заполнен:
 * стек растёт вниз от StackBase, значит именно эти страницы понадобятся первыми.
 * Размер берём с запасом над SizeOfStackCommit (у Heroes3.exe он 4 КБ при странице
 * хозяина 16 КБ) — 64 КБ покрывают пролог и первые кадры.
 *
 * Гейт MACRUNNER_HB_STACK_PRECOMMIT — число КБ, 0 или отсутствие переменной оставляют
 * прежнее поведение. */
static void macrunner_xtajit_precommit_stack_top(void)
{
    static int kb = -1;
    TEB32 *teb32;
    ULONG_PTR base, low;
    SIZE_T size;
    void *addr;
    NTSTATUS status;

    if (kb < 0)
    {
        /* На PE-стороне getenv не линкуется (ld.lld: undefined symbol) — читаем так же,
         * как остальные гейты этого файла. */
        static const WCHAR nameW[] = {'M','A','C','R','U','N','N','E','R','_','H','B','_',
                                      'S','T','A','C','K','_','P','R','E','C','O','M','M','I','T',0};
        WCHAR value[8] = { 0 };
        UNICODE_STRING name, val;
        int parsed = 0, i;

        RtlInitUnicodeString( &name, nameW );
        val.Buffer = value;
        val.Length = 0;
        val.MaximumLength = sizeof(value);
        if (RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND)
            for (i = 0; i < 7 && value[i] >= '0' && value[i] <= '9'; i++)
                parsed = parsed * 10 + (value[i] - '0');
        kb = parsed;
        if (kb < 0) kb = 0;
        if (kb > 1024) kb = 1024;
    }
    if (!kb) return;

    if (!(teb32 = xtajit_current_teb32())) return;
    base = (ULONG_PTR)teb32->Tib.StackBase;
    low  = (ULONG_PTR)teb32->Tib.StackLimit;
    if (!base || base <= low) return;

    size = (SIZE_T)kb * 1024;
    if (size > base - low) size = base - low;
    if (!size) return;

    addr = (void *)(ULONG_PTR)(base - size);
    status = NtAllocateVirtualMemory( GetCurrentProcess(), &addr, 0, &size,
                                      MEM_COMMIT, PAGE_READWRITE );
    {
        static unsigned int n;
        unsigned int cur = ++n;

        if (cur <= 8 || !(cur % 64))
            MESSAGE( "macrunner-xtajit: stack-precommit n=%u база=%08lx предел=%08lx "
                     "адрес=%p размер=%08lx статус=%08lx\n",
                     cur, (unsigned long)base, (unsigned long)low, addr,
                     (unsigned long)size, (unsigned long)status );
    }
}

void WINAPI BTCpuThreadInit(void)
{
    NTSTATUS status;

    xtajit_arm_x18_from_tls();   /* идемпотентно: смещение слота одно на процесс */
    status = xtajit_unix_call( unix_thread_init, NULL );
    MESSAGE( "macrunner-xtajit: BTCpuThreadInit status=%08lx\n", status );
    if (status) xtajit_raise_status( status );
    macrunner_xtajit_precommit_stack_top();
}

void WINAPI BTCpuThreadTerm( HANDLE handle, LONG exit_code )
{
    struct xtajit_memory_params params = { handle, 0, 0, 0, TRUE, exit_code };
    release_pending_i386_context();
    release_bridge_stack();
    (void)xtajit_unix_call( unix_thread_term, &params );
}

/* Итерация 840: последний сдвиг счётчика команд, выставленный для создания окна (0x136b).
 * Ноль — значит с прошлого раза уже напечатали. Разделяет «сдвиг не записали» и
 * «записали, но к следующему входу его нет». */
static DWORD macrunner_last_bop_advance;

/* ★★★★★ ИТЕРАЦИЯ 71 — ТА ЖЕ СВЕРКА `WowTebOffset`, НО В ДРУГОМ МОДУЛЕ.
 *
 * Измерено 64-70: поле одной нити меняется 0x2000 -> 0xAA64 ровно один раз за прогон и
 * навсегда; 0xAA64 = IMAGE_FILE_MACHINE_ARM64; даёт это не установщик, а ЛЮБОЙ i386-гость
 * достаточной длины (i386 clock, 13 КБ, воспроизводит за 90 с; notepad с 1468 вызовами
 * слишком короток). Барьер против рематериализации x18 порчу не убрал — читаем не чужой TEB.
 *
 * В wow64.dll порчу первым видит зонд `до-обработчика`, но поставить точки ВНУТРЬ того
 * блока нельзя: четыре вызова функции обрушили прогон с 72 682 вызовов до 550 (проверено
 * откатом). Поэтому разделяем МОДУЛИ: тот же зонд здесь, в трансляторе, ДО входа в
 * wow64. Увидит порчу раньше — писал не путь wow64.
 *
 * Модуль без libc: getenv не линкуется, гейта нет намеренно. Печать только при изменении. */
static void mr_xt_wowoff_probe( const char *where, unsigned num )
{
    struct mr_slot { void *teb; LONG off; };
    static struct mr_slot tab[16];
    static unsigned used;
    TEB *teb = NtCurrentTeb();
    LONG now;
    unsigned i;

    __asm__ __volatile__( "" : "+r"(teb) );   /* запрет пересчёта x18 */
    if (!teb) return;
    now = teb->WowTebOffset;

    for (i = 0; i < used; i++) if (tab[i].teb == teb) break;
    if (i == used)
    {
        if (used >= 16) return;
        tab[i].teb = teb; tab[i].off = now; used++;
        MESSAGE( "macrunner-xtajit-wowoff-НАЧАЛО: точка=%s teb=%p off=%08lx num=%08x\n",
                 where, teb, (unsigned long)(ULONG)now, num );
    }
    else if (tab[i].off != now)
    {
        MESSAGE( "macrunner-xtajit-wowoff-СМЕНА: точка=%s teb=%p было=%08lx стало=%08lx num=%08x\n",
                 where, teb, (unsigned long)(ULONG)tab[i].off, (unsigned long)(ULONG)now, num );
        tab[i].off = now;
    }
}

static BOOL handle_bop_context( struct xtajit_i386_context *ctx, NTSTATUS *status, TEB *native_teb )
{
    DWORD ret_eip, ret_esp;

    if (!ctx) return FALSE;
    if (syscall_bop_guest && ctx->eip == PtrToUlong( syscall_bop_guest ))
    {
        DWORD *ret = guest32_host_ptr( ctx->esp );
        DWORD service = ctx->eax;
        UINT *args;

        mr_xt_wowoff_probe( "xtajit-до-диспетчера", (unsigned)ctx->eax );

        {
            static unsigned mr_hbc_n;
            if (++mr_hbc_n > 2000 && mr_hbc_n % 1000 != 0) { /* тишина */ }
            else if (mr_hbc_n > 2000)
                MESSAGE( "macrunner-xtajit: hbc-syscall-итог n=%u\n", mr_hbc_n );
            else
                MESSAGE( "macrunner-xtajit: hbc-syscall eip=%08lx esp=%08lx eax=%08lx ret=%p teb32=%p\n",
                         ctx->eip, ctx->esp, ctx->eax, (void *)ret, (void *)xtajit_current_teb32() );
        }
        if (!ret)
        {
            MESSAGE( "macrunner-xtajit: hbc-null-ret esp=%08lx — returning ACCESS_VIOLATION\n", ctx->esp );
            *status = STATUS_ACCESS_VIOLATION;
            return TRUE;
        }
        ret_eip = *ret;

        /* MacRunner 2026-08-27 — КТО КРУТИТ ЦИКЛ ОЖИДАНИЯ.
         *
         * Замер Diablo: после CreatePalette идут 5142 вызова NtDelayExecution (номер 0x34) за
         * 0,32 секунды — 15 773 в секунду, то есть не сон, а активный опрос. По эталону
         * CrossOver следующим шагом должен быть surface_set_palette, а у нас его нет вовсе:
         * игра ушла в цикл и не выходит. Кто зовёт — из номера вызова не видно, нужен
         * гостевой адрес возврата. Печатаем первые восемь и каждый тысячный. */
        if (service == 0x34)
        {
            static unsigned int delay_n;
            unsigned int dn = ++delay_n;

            /* ★★★ 28.08.2026 — КАРТА 32-БИТНЫХ ОБРАЗОВ, один раз за процесс.
             *
             * Кадры вызывающего Sleep(0) лежат в 0x778.. / 0x779.. / 0x78c.., а ни один
             * i386-модуль дистрибутива таких баз не имеет: их переносит загрузчик. Без карты
             * времени ВЫПОЛНЕНИЯ адрес не назвать — ровно та ловушка, из-за которой уже был
             * отозван один разбор (см. память проекта про атрибуцию по совпавшему смещению).
             *
             * Структуры записи модуля для 32-битного гостя в заголовках нет, поэтому поля
             * читаются по смещениям LDR_DATA_TABLE_ENTRY32: 0x00 Flink, 0x18 DllBase,
             * 0x20 SizeOfImage, 0x2c BaseDllName{Length, MaxLength, Buffer}. */
            if (dn == 1)
            {
                const TEB32 *teb32 = xtajit_current_teb32();
                const ULONG *peb32 = teb32 ? guest32_host_ptr( teb32->Peb ) : NULL;
                const ULONG *ldr = peb32 ? guest32_host_ptr( peb32[3] ) : NULL;   /* LdrData: смещение 0x0c */

                if (ldr)
                {
                    ULONG head = peb32[3] + 0x0c;      /* InLoadOrderModuleList */
                    ULONG cur = ldr[3];                /* Flink */
                    unsigned guard = 0;

                    while (cur && cur != head && guard++ < 64)
                    {
                        const ULONG *e = guest32_host_ptr( cur );
                        const USHORT *nu;
                        char nm[64];
                        unsigned i, len;

                        if (!e) break;
                        nu = guest32_host_ptr( e[0x30 / 4] );
                        len = nu ? (((const USHORT *)&e[0x2c / 4])[0] / sizeof(WCHAR)) : 0;
                        if (len > sizeof(nm) - 1) len = sizeof(nm) - 1;
                        for (i = 0; i < len; i++) nm[i] = (char)nu[i];
                        nm[len] = 0;
                        {
                            /* ★ MacRunner 2026-08-28 — ПРОВЕРКА ИНВАРИАНТА, А НЕ ОХОТА ЗА ОТКАЗОМ.
                             *
                             * Diablo умирал так: поток команд wined3d читал строку из
                             * `.rdata` СВОЕГО ЖЕ модуля, а движок отвечал `host=0x0` —
                             * адрес ему неизвестен, хотя модуль отображён целиком. Дальше
                             * отказ памяти -> у потока нет SEH -> статус меняется на
                             * NONCONTINUABLE -> процесс уходит. На поиск этой цепочки ушёл
                             * день, потому что искали по следу отказа.
                             *
                             * Между тем правило простое и проверяемо СРАЗУ: если модуль
                             * стоит в списке загруженных у гостя, движок ОБЯЗАН уметь его
                             * читать. Проверяем три точки — начало, середину, конец, — и
                             * при расхождении называем модуль.
                             *
                             * ⚠ 28.08 ВЕЧЕРОМ: ЭТА ПРОВЕРКА НЕДОСТОВЕРНА. `guest32_host_ptr`
                             * (`cpu.c:550`) — простая склейка старших битов окна с гостевым
                             * адресом, она НИКОГДА не возвращает ноль. Отсюда «0 нарушений при
                             * 34 модулях» — ложное спокойствие.
                             *
                             * Настоящая карта у движка, и замер через неё
                             * (`dump_guest_probe_addr` в unixlib.c) показал: в ней ТРИ региона
                             * (куча, стек, TEB) и НИ ОДНОГО модуля. `mem eip=7bd6e098 host=0x0
                             * can_x=0` при живом ntdll — отсюда и отказ чтения `.rdata`
                             * wined3d, и отказ ИСПОЛНЕНИЯ `KiUserExceptionDispatcher`.
                             *
                             * Чтобы проверка стала настоящей, нужен мост к `hb_memory_*` с
                             * PE-стороны (через unixlib) — отдельная работа. */
                            unsigned long б = (unsigned long)e[0x18 / 4];
                            unsigned long р = (unsigned long)e[0x20 / 4];
                            /* ★★★★★ 28.08 ВЕЧЕРОМ — СПРАШИВАЕМ КАРТУ ДВИЖКА, А НЕ СКЛЕЙКУ.
                             * Прежняя редакция звала `guest32_host_ptr` и потому всегда
                             * говорила «всё видно»: та функция физически не может вернуть
                             * ноль. Замер через карту движка показал ТРИ региона на 34
                             * модуля — вот это и надо ловить. */
                            const void *p0 = б ? (xtajit_probe_guest_addr( (ULONG)б, NULL ) ? (void *)1 : NULL) : NULL;
                            const void *pм = (б && р > 2) ? (xtajit_probe_guest_addr( (ULONG)(б + р / 2), NULL ) ? (void *)1 : NULL) : NULL;
                            const void *pк = (б && р > 4) ? (xtajit_probe_guest_addr( (ULONG)(б + р - 4), NULL ) ? (void *)1 : NULL) : NULL;

                            MESSAGE( "macrunner-xtajit-карта32: база=%08lx размер=%08lx %s\n", б, р, nm );
                            if (б && р && (!p0 || !pм || !pк))
                                MESSAGE( "macrunner-xtajit-ИНВАРИАНТ-НАРУШЕН: модуль %s загружен, но движку НЕ ВИДЕН "
                                         "(база=%08lx размер=%08lx начало=%s середина=%s конец=%s)\n",
                                         nm, б, р, p0 ? "ок" : "НЕТ", pм ? "ок" : "НЕТ", pк ? "ок" : "НЕТ" );
                        }
                        cur = e[0];
                    }
                }
            }

            if (dn <= 8 || !(dn % 1000))
            {
                /* ★★★ 28.08.2026 — ПОДЪЁМ ПО ЦЕПОЧКЕ EBP, как у зонда IsMemDC.
                 *
                 * `ret_eip` указывает внутрь i386 ntdll (7bd6d26c), то есть на заглушку
                 * системного вызова, а не на виновника. Замер срока сна показал, что все 5949
                 * вызовов идут с timeout=0 — это Sleep(0), активный опрос, и звать его может
                 * как игра, так и наш же i386-модуль. Три кадра выше называют вызывающего. */
                ULONG fp = ctx->ebp;
                char buf[200];
                int pos = 0;
                unsigned d;

                /* ★★★★★ ИТЕРАЦИЯ 117 — ПРОВЕРКА КАДРА, А НЕ ТОЛЬКО NULL.
                 *
                 * Замер: этот обход кадров УБИВАЛ прогон. `guest32_host_ptr` переводит
                 * ЛЮБОЕ ненулевое гостевое значение, поэтому мусорный `ebp` (замерено:
                 * 3) даёт ненулевой хозяйский указатель, проверка `if (!fr)` его
                 * пропускает, и `fr[1]` читает по `база|7` — в охранную зону нулевого
                 * указателя. Отказ приходит в xtajit.dll+0x15800, дальше BRK в
                 * libsystem_platform и выход с кодом 29.
                 *
                 * Это тот же класс, что уже стоил лейну времени в итерации 39: зонд,
                 * разыменовывающий непроверенный гостевой адрес, роняет чужую программу.
                 * Проверяем сам ГОСТЕВОЙ адрес: не ниже 0x10000 (охранная зона),
                 * выровнен на 4, и оба слова кадра помещаются в 32 бита. */
                for (d = 0; d < 4 && fp; d++)
                {
                    const ULONG *fr;

                    if (fp < 0x10000 || (fp & 3) || fp > 0xfffffff0u) break;
                    fr = guest32_host_ptr( fp );
                    if (!fr) break;
                    pos += snprintf( buf + pos, sizeof(buf) - pos, " [%u]=%08lx", d, (unsigned long)fr[1] );
                    if ((size_t)pos >= sizeof(buf)) break;
                    fp = fr[0];
                }
                MESSAGE( "macrunner-xtajit: delay-caller n=%u ret_eip=%08lx esp=%08lx кадры:%s\n",
                         dn, ret_eip, ctx->esp, buf );
            }
        }
        /* ★ MacRunner 2026-09-02 — КТО КРУТИТ NtUserWindowFromDC (режим H: лайвлок сноса GL-контекста).
         * Зеркало delay-caller: гостевая цепочка возврата по ebp, адреса проверены до разыменования. */
        if (service == 0x15fd)
        {
            static unsigned int wfdc_n;
            unsigned int wn = ++wfdc_n;
            if (wn <= 8 || !(wn % 100000))
            {
                ULONG fp = ctx->ebp;
                char buf[200];
                int pos = 0;
                unsigned d;
                for (d = 0; d < 4 && fp; d++)
                {
                    const ULONG *fr;
                    if (fp < 0x10000 || (fp & 3) || fp > 0xfffffff0u) break;
                    fr = guest32_host_ptr( fp );
                    if (!fr) break;
                    pos += snprintf( buf + pos, sizeof(buf) - pos, " [%u]=%08lx", d, (unsigned long)fr[1] );
                    if ((size_t)pos >= sizeof(buf)) break;
                    fp = fr[0];
                }
                MESSAGE( "macrunner-xtajit: wfdc-caller n=%u ret_eip=%08lx esp=%08lx кадры:%s\n",
                         wn, ret_eip, ctx->esp, buf );
            }
        }
        /* ★ MacRunner 2026-08-23, лейн ЛЕСТНИЦА, итерация 2704 — КТО ЗОВЁТ ЦИКЛ IsMemDC.
         * Замер 2703: после показа окна идёт 722 витка `NtGdiGetDCDword(method=10, IsMemDC)`,
         * ответ всегда «успех, ноль», и на каждом витке выделение памяти. Кто зовёт — не
         * знали: 32-битный gdi32 реализует через этот же вызов свою `GetObjectType`, так что
         * вызывающим может быть и не игра. `ret_eip` тут уже вычислен — печатаем его.
         * Потолок «первые 10 и каждый 200-й», как у соседних зондов. */
        if (service == 0x11ef)
        {
            static LONG _dcn;
            LONG _dk = InterlockedIncrement( &_dcn );

            if (_dk <= 10 || !(_dk % 200))
            {
                /* ★ Итерация 2705: ПОДЪЁМ ПО ЦЕПОЧКЕ EBP. Замер 2704 назвал `ret_eip=7ab8efcc`,
                 * но это заглушка системного вызова внутри самого `win32u` — на уровень мельче,
                 * чем нужно. Настоящий вызывающий на кадр выше: [ebp] — следующий кадр,
                 * [ebp+4] — адрес возврата. Идём три уровня; чужие адреса опознаются по карте
                 * образов, снятой в 2704 (ddraw 0x78f60000, wined3d 0x77b80000, Diablo 0x400000). */
                ULONG fp = ctx->ebp;
                char buf[200];
                int pos = 0;
                unsigned d;

                for (d = 0; d < 3 && fp; d++)
                {
                    const ULONG *fr = guest32_host_ptr( fp );

                    if (!fr) break;
                    pos += snprintf( buf + pos, sizeof(buf) - pos, " [%u]=%08lx", d, (unsigned long)fr[1] );
                    if ((size_t)pos >= sizeof(buf)) break;
                    fp = fr[0];
                }
                MESSAGE( "macrunner-xtajit-ismemdc-caller: n=%ld ret_eip=%08lx esp=%08lx ebp=%08lx кадры:%s\n",
                         (long)_dk, ret_eip, ctx->esp, ctx->ebp, buf );
            }
        }
        /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 223 — КТО В ГОСТЕ ЗОВЁТ СОЗДАНИЕ ОКНА.
         * Замер 222 снял подозрение со ВСЕЙ нашей стороны: дескриптор возвращается верный, а
         * игра всё равно создаёт окно заново (6233 раза, без показа и без выборки сообщений).
         * Значит смотреть надо гостевого вызывающего. `ret_eip` — адрес возврата, он уже
         * посчитан выше; печатаем его и несколько слов стека, чтобы достать кадры выше.
         * Модули для сопоставления: Diablo.exe 0x400000+0x2b2000, Storm.dll, DiabloUI.dll. */
        if (service == 0x136b)
        {
            static LONG wn;
            LONG k = InterlockedIncrement( &wn );
            /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 248 — КУДА ВЕДЁТ СЛОТ ИМПОРТА.
             * Противоречие 238 не снято: блок игры у места вызова исполняется ОДИН раз,
             * user32.CreateWindowExA не вызывается НИ РАЗУ (замер 239 на свежем модуле), а
             * системных вызовов создания окна 32 734. Всё сходится, если слот 0x479380 в
             * таблице импорта Diablo.exe указывает не на user32, а на что-то наше. Читаем
             * значение слота прямо из памяти гостя — один раз, при первом создании. */
            /* ★★★ 30.08, лейн УСТАНОВЩИКИ — ЭТОТ ЗОНД УБИВАЛ ВСЕ ЧУЖИЕ i386-ПРОГРАММЫ.
             *
             * Адрес 0x479380 вписан ЖЁСТКО: это слот таблицы импорта Diablo.exe. У любой
             * другой i386-программы его нет. `guest32_host_ptr` — чистая арифметика
             * (база + смещение), отображение она НЕ проверяет и потому отдаёт указатель
             * на неотображённую страницу, а `ldr w1,[x0]` следом валит процесс.
             *
             * Улика, по которой это найдено (i386 notepad, прогон 30.08 07:18):
             *   macrunner-vhf-probe: addr=0x300479380 pc=0x7ffd04946e8
             *                        модуль=0x7ffd0480000 смещение=0x146e8 site=bus
             *   0x7ffd0480000 = `macrunner-wow64: cpu module=...`, то есть xtajit.dll
             *   xtajit.dll+0x146e8 -> handle_bop_context, cpu.c:2711, `ldr w1,[x0]`,
             *   а двумя командами выше `mov w0,#0x9380; movk w0,#0x47,lsl#16` = 0x479380.
             * Образ notepad = 0x400000 + SizeOfImage 0x78000, кончается на 0x478000 —
             * отказавший адрес лежит ЗА образом, ровно как и предсказывает эта версия.
             *
             * Три итерации (36-38) искали причину в доставке системного вызова и в
             * переходнике wow64win, потому что база модуля в журнал не печаталась и
             * символизация делалась по угаданной базе. Сама база оказалась угадана верно,
             * неверен был выбор модуля.
             *
             * Зонд не удаляю (лейну Diablo он нужен) — ставлю гейт с умолчанием 0. */
            if (k == 1)
            {
                static int iat_probe = -1;

                if (iat_probe < 0)
                {
                    UNICODE_STRING iname;
                    WCHAR ibuf[8];
                    UNICODE_STRING ival = { 0, sizeof(ibuf), ibuf };

                    RtlInitUnicodeString( &iname, L"MACRUNNER_XTAJIT_DIABLO_IAT_PROBE" );
                    iat_probe = RtlQueryEnvironmentVariable_U( NULL, &iname, &ival ) ? 0 : (ibuf[0] != '0');
                }
                if (iat_probe)
                {
                    const ULONG *slot = guest32_host_ptr( 0x479380 );
                    MESSAGE( "macrunner-xtajit-iat-createwindow: слот=0x479380 значение=%08lx\n",
                             slot ? (unsigned long)*slot : 0xdeadbeefUL );
                }
            }

            if (k <= 3 || !(k % 2000))
            {
                /* Итерация 224: ищем кадр ИГРЫ. Первые семь слов оказались нашими модулями и
                 * аргументами (223), а непосредственный вызывающий обязан быть нашим по
                 * устройству WOW64. Поэтому просматриваем 64 слова и печатаем ТОЛЬКО те, что
                 * попадают в образ Diablo.exe (0x400000 + 0x2b2000) — это и будет место игры. */
                /* Итерация 225: СТРОГИЙ отбор. В 224 фильтр по одному числовому диапазону поймал
                 * данные — базу модуля и UTF-16 текст («DIABLO», путь), — и я объявил его негодным.
                 * Теперь два условия сразу: адрес в секции КОДА Diablo.exe И перед ним опкод
                 * вызова (E8 rel32 за 5 байт, либо FF /2 за 6 или 2). Глубина 512 слов вместо 64. */
                /* Итерация 227: ЖИВАЯ ЦЕПОЧКА вместо скана. Скан сырого стека имел два изъяна:
                 * не отличал код от данных (224) и живой кадр от мусора (226) — так проверка
                 * диска из давно завершившегося вызова была принята за кадр. Идём по ebp:
                 * [ebp] — следующий кадр, [ebp+4] — адрес возврата. Diablo.exe кадры на ebp
                 * держит (в разборе видны leal -0x10(%ebp)). Помечаем, чей это модуль. */
                ULONG fp = ctx->ebp;
                unsigned d;
                char buf[240];
                int pos = 0;

                for (d = 0; d < 10 && pos < 190; d++)
                {
                    const ULONG *frame = guest32_host_ptr( fp );
                    ULONG next, ra;
                    const char *who;

                    if (!frame || (fp & 3)) break;
                    next = frame[0];
                    ra   = frame[1];
                    who  = (ra >= 0x401000 && ra < 0x6b2000) ? "ИГРА" :
                           (ra >= 0x7a000000)                ? "wine" : "?";
                    pos += sprintf( buf + pos, " %u:%08lx(%s)", d, (unsigned long)ra, who );
                    if (next <= fp || next - fp > 0x20000) break;
                    fp = next;
                }
                buf[pos] = 0;
                MESSAGE( "macrunner-xtajit-createwin-chain: n=%d ebp=%08lx ret_eip=%08lx%s\n",
                         (int)k, (unsigned long)ctx->ebp, (unsigned long)ret_eip, pos ? buf : " ПУСТО" );
            }
        }
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ЗНАЧЕНИЕ адреса возврата, а не указатель.
         *
         * Трасса `hbc-syscall` печатает `ret=` — это `guest32_host_ptr(esp)`, то есть
         * АДРЕС ЯЧЕЙКИ, а не то, что в ней лежит. На детерминированном прогоне (итерация
         * 144) счётчик команд после последнего вызова оказался равен 0x89, то есть НОМЕРУ
         * этого вызова. Различить «испорченное пришло с гостевого стека» и «испортили мы
         * после чтения» может только само значение — печатаем его. */
        /* Печать ТОЛЬКО на аномалии: безусловная печать на каждый вызов сама меняет исход
         * (итерация 145: код выхода стал 63 вместо 5), то есть прибор возмущал явление.
         * Замер 576 адресов возврата: все правдоподобны, ни одного меньше 0x10000 —
         * значит стена НЕ в чтении адреса возврата, и зонд остаётся сторожем на будущее. */
        if (ret_eip < 0x10000)
            MESSAGE( "macrunner-xtajit: retaddr-АНОМАЛИЯ svc=%08lx ret_eip=%08lx esp=%08lx\n",
                     (unsigned long)service, (unsigned long)ret_eip, (unsigned long)ctx->esp );
        /* MacRunner 2026-08-14, лейн ЛЕСТНИЦА, итерация 856: КТО освобождает кадр.
         *
         * Стена ступени 1 — полноэкранный BitBlt 1512x982 отказывает, потому что источник
         * лежит по гостевому адресу, к моменту чтения уже отданному (MEM_FREE/NOACCESS).
         * Итерация 855 попыталась опознать освобождающего по полям TEB32 (Tib.StackBase/
         * StackLimit) — вернулись нули, зонд негоден. Здесь опознаём тем полем, которое
         * заведомо есть и уже вычислено для соседних служб: адресом возврата гостя.
         * Признак ответа: ret_eip внутри образа игры (0x401000..0x6b2000) — освобождает
         * САМА игра, значит наша ошибка в порядке (читаем после отдачи); ret_eip в
         * библиотеках wine (0x7a......+) — освобождаем МЫ.
         *
         * Ограничение вывода: не более 64 печатей. Фильтровать по РАЗМЕРУ нельзя — итерация
         * 856 это проверила и получила ноль печатей при 42 освобождениях: у MEM_RELEASE
         * (тип 0x8000) `RegionSize` на входе РАВЕН НУЛЮ, ядро освобождает всю резервацию
         * целиком, а размер 1 507 328, который печатает `macrunner-guestfree`, известен уже
         * ПОСЛЕ вызова. Отбор веду по базе на выходе, при разборе журнала. */
        if (service == 0x1e)
        {
            static int freq_seen;
            const DWORD *fargs = guest32_host_ptr( ctx->esp + 2 * sizeof(DWORD) );
            if (fargs && freq_seen < 64)
            {
                const DWORD *pbase = guest32_host_ptr( fargs[1] );
                const DWORD *psize = guest32_host_ptr( fargs[2] );
                const char *who = (ret_eip >= 0x401000 && ret_eip < 0x6b2000) ? "ИГРА" :
                                  (ret_eip >= 0x7a000000)                     ? "wine" : "?";
                /* Итерация 857: адрес возврата ОДИН И ТОТ ЖЕ у всех 36 освобождений —
                 * i386 ntdll+0x18966c, то есть внутренний переход ntdll, а не тот, кто
                 * решил освободить. Ret_eip для опознания вызывающего структурно негоден.
                 * Идём по цепочке EBP: [ebp]=следующий кадр, [ebp+4]=адрес возврата.
                 * Адреса печатаем сырыми — модуль разрешаю офлайн по базам образов PE
                 * (kernelbase 7b000000, kernel32 7b800000, ntdll 7bc00000, игра 401000). */
                char chain[300];
                int cpos = 0;
                DWORD fp = ctx->ebp;
                unsigned d;
                for (d = 0; d < 10 && cpos < 250; d++)
                {
                    const DWORD *fr;
                    DWORD next;
                    if (!fp || (fp & 3)) break;
                    if (!(fr = guest32_host_ptr( fp ))) break;
                    next = fr[0];
                    cpos += sprintf( chain + cpos, " %u:%08lx", d, (unsigned long)fr[1] );
                    if (next <= fp || next - fp > 0x20000) break;
                    fp = next;
                }
                chain[cpos] = 0;
                freq_seen++;
                MESSAGE( "macrunner-xtajit-freecaller: n=%d ret_eip=%08lx(%s) база=%08lx "
                         "размер=%lu тип=%08lx ebp=%08lx кадры:%s\n",
                         freq_seen, (unsigned long)ret_eip, who,
                         (unsigned long)(pbase ? *pbase : 0),
                         (unsigned long)(psize ? *psize : 0),
                         (unsigned long)fargs[3], (unsigned long)ctx->ebp,
                         cpos ? chain : " ПУСТО" );
            }
        }
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: кто именно завершает процесс.
         * Печатаем ТОЛЬКО на NtTerminateProcess (0x2c): адресный зонд, не общий канал. */
        if (service == 0x2c)
        {
            /* Итерация 243: печатаем и АРГУМЕНТЫ. Код завершения я до сих пор выводил из кода
             * внешней обёртки — косвенно. У NtTerminateProcess два довода: дескриптор процесса
             * и статус выхода; на стеке гостя они лежат сразу за адресом возврата. */
            /* ★ 28.08.2026 — PID В СТРОКУ ВЫХОДА.
             * Diablo.exe запускает второй экземпляр себя (лаунчер + игра), и обе терминации
             * печатались с одинаковым esp и одинаковым стеком. Без pid отличить, кто вышел —
             * обёртка или игра, — нечем, и я приписал обе лаунчеру, не проверив. */
            MESSAGE( "macrunner-xtajit: terminate-caller pid=%04lx ret_eip=%08lx esp=%08lx процесс=%08lx статус=%08lx\n",
                     (unsigned long)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess,
                     ret_eip, ctx->esp, (unsigned long)ret[2], (unsigned long)ret[3] );
            /* Итерация 444: печатаем ГОСТЕВОЙ СТЕК. Перебор кандидатов по одному исчерпан
             * (семь отвергнутых замерами), и остался единственный источник различия: ОТКУДА
             * игра решает выйти. На стеке лежат адреса возврата — по ним видна цепочка
             * вызовов, приведшая к завершению. Печатаем 16 слов, этого хватает на несколько
             * кадров стека, и только один раз (первый выход и есть точка решения). */
            {
                static int once;
                if (!once)
                {
                    const DWORD *st = ret;
                    int k;
                    once = 1;
                    MESSAGE( "macrunner-xtajit: стек-выхода:" );
                    for (k = 0; k < 16; k++) MESSAGE( " %08lx", (unsigned long)st[k] );
                    MESSAGE( "\n" );
                    /* Итерация 445: шестнадцать слов от ESP до кода игры не достали (444) —
                     * там только кадры kernelbase (7b9x). Идём по цепочке EBP: каждый кадр
                     * это пара [сохранённый EBP][адрес возврата]. Печатаем до первого адреса
                     * ВНЕ диапазона библиотек wine — он и будет кодом игры. */
                    {
                        DWORD bp = ctx->ebp;
                        int depth;
                        MESSAGE( "macrunner-xtajit: кадры-EBP:" );
                        for (depth = 0; depth < 12 && bp >= 0x10000 && bp < 0xfff00000; depth++)
                        {
                            const DWORD *fr = guest32_host_ptr( bp );
                            if (!fr) break;
                            MESSAGE( " [bp=%08lx ret=%08lx]", (unsigned long)bp,
                                     (unsigned long)fr[1] );
                            if ((fr[1] >> 24) != 0x7b) MESSAGE( " <-ВНЕ_WINE" );
                            bp = fr[0];
                        }
                        MESSAGE( "\n" );
                    }
                }
            }
        }
        ret_esp = ctx->esp + sizeof(DWORD);
        args = guest32_host_ptr( ret_esp + sizeof(DWORD) );
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ранняя смерть ступени 1 приходит
         * исключением посреди череды NtProtectVirtualMemory. Печатаем КОД и АДРЕС
         * исключения: первый аргумент — гостевой указатель на EXCEPTION_RECORD,
         * в нём ExceptionCode по +0 и ExceptionAddress по +12. */
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: три прогона из четырёх обрываются ПРЯМО НА
         * NtProtectVirtualMemory (0x50), не возвращаясь из вызова. Печатаем ДО выполнения,
         * какую область гость перезащищает: args = (handle, *base, *size, new_prot, *old). */
        if (service == 0x50 && args)
        {
            const DWORD *pbase = guest32_host_ptr( args[1] );
            const DWORD *psize = guest32_host_ptr( args[2] );

            MESSAGE( "macrunner-xtajit: protect base=%08lx size=%08lx new_prot=%08lx\n",
                     pbase ? (DWORD)*pbase : 0xffffffff,
                     psize ? (DWORD)*psize : 0xffffffff,
                     (DWORD)args[3] );
        }
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ступень 1 умирает после череды NtOpenFile
         * (0x33), возвращающих c0000034/c000003a. Печатаем ИМЯ, которое гость не нашёл —
         * зонд БЕЗУСЛОВНЫЙ: данные тут заведомо есть, гейта нет.
         * NtOpenFile(handle, access, POBJECT_ATTRIBUTES, iosb, share, options)
         * OBJECT_ATTRIBUTES32: +8 = ObjectName; UNICODE_STRING32: +0 len/maxlen, +4 buffer. */
        if (service == 0x33 && args)
        {
            const DWORD *oa = guest32_host_ptr( args[2] );
            const DWORD *us = oa ? guest32_host_ptr( oa[2] ) : NULL;
            const WCHAR *nm = us ? guest32_host_ptr( us[1] ) : NULL;
            unsigned int len = us ? (unsigned int)(us[0] & 0xffff) / sizeof(WCHAR) : 0;
            char buf[160];
            unsigned int i;

            if (len > sizeof(buf) - 1) len = sizeof(buf) - 1;
            for (i = 0; nm && i < len; i++) buf[i] = (nm[i] < 0x80) ? (char)nm[i] : '?';
            buf[nm ? i : 0] = 0;
            /* ★ 30.08, лейн УСТАНОВЩИКИ — КТО ЗОВЁТ. Имя `shell32.dll` приходит сюда
             * УЖЕ испорченным (`thell320dll.dll`), при этом `load_path` рядом цел, а
             * малая мишень i386 на 500 кругов девяти строковых путей дала порчи НОЛЬ
             * (итерация 40). Значит портит код самого установщика, и нужен его адрес.
             * Подъём по цепочке EBP — тот же, что у соседних зондов: [ebp] следующий
             * кадр, [ebp+4] адрес возврата. Зонд безусловный: NtOpenFile за прогон
             * всего 33, потока не создаст. */
            {
                char kadry[300], svoi[140];
                int pos = 0, spos = 0, nashli = 0;
                unsigned int d, w;
                ULONG fp = ctx->ebp;

                kadry[0] = 0;
                /* ★★★★★ ИТЕРАЦИЯ 117 — ЭТОТ ЗОНД УБИВАЛ ПРОГОН. Правка: проверять
                 * ГОСТЕВОЙ адрес кадра, а не только результат перевода.
                 *
                 * `guest32_host_ptr` переводит ЛЮБОЕ ненулевое гостевое значение,
                 * поэтому мусорный `ebp` даёт ненулевой хозяйский указатель, проверка
                 * `if (!fr)` его пропускает, и `fr[1]` читает по `база|7` — в охранную
                 * зону нулевого указателя. Замерено: отказ в xtajit.dll+0x15800,
                 * следом BRK в libsystem_platform.dylib, выход с кодом 29.
                 *
                 * Зонд мой же (добавлен этой сессией, «КТО ЗОВЁТ»), и он безусловный —
                 * то есть ронял чужую программу на каждом прогоне. Тот же класс, что
                 * итерация 39: жёстко вписанный адрес в зонде валил чужие i386-программы. */
                for (d = 0; d < 24 && fp && pos < (int)sizeof(kadry) - 12; d++)
                {
                    const ULONG *fr;

                    if (fp < 0x10000 || (fp & 3) || fp > 0xfffffff0u) break;
                    fr = guest32_host_ptr( fp );
                    if (!fr) break;
                    pos += snprintf( kadry + pos, sizeof(kadry) - pos, " %u:%08lx",
                                     d, (unsigned long)fr[1] );
                    fp = fr[0];
                }
                /* ★ Цепочка EBP кончается в kernelbase: до кадра САМОГО установщика она
                 * не доходит (замер 08:02 — все шесть кадров в 7bd3xxxx/7b75xxxx).
                 * Поэтому вторым способом просматриваем стек и печатаем адреса, попавшие
                 * в образ установщика. Строгий отбор здесь не нужен: цель не «найти
                 * вызывающего точно», а узнать, участвует ли его код вообще. */
                svoi[0] = 0;
                for (w = 0; w < 512 && nashli < 8 && spos < (int)sizeof(svoi) - 12; w++)
                {
                    const ULONG *sl = guest32_host_ptr( ctx->esp + w * 4 );

                    if (!sl) break;
                    if (*sl >= 0x401000 && *sl < 0x700000)
                    {
                        spos += snprintf( svoi + spos, sizeof(svoi) - spos, " %08lx",
                                          (unsigned long)*sl );
                        nashli++;
                    }
                }
                MESSAGE( "macrunner-xtajit: openfile name=\"%s\" oa=%08lx root=%08lx "
                         "ret_eip=%08lx ebp=%08lx кадры:%s | образ:%s\n",
                         buf, (DWORD)args[2], oa ? (DWORD)oa[1] : 0,
                         (unsigned long)ret_eip, (unsigned long)ctx->ebp, kadry,
                         svoi[0] ? svoi : " нет" );
            }
        }
        if (service == 0xcf && args)
        {
            const DWORD *rec = guest32_host_ptr( args[0] );

            if (rec)
                MESSAGE( "macrunner-xtajit: raise-exc code=%08lx flags=%08lx addr=%08lx arg0=%08lx\n",
                         (DWORD)rec[0], (DWORD)rec[1], (DWORD)rec[3], (DWORD)args[0] );
            else
                MESSAGE( "macrunner-xtajit: raise-exc запись недоступна arg0=%08lx\n", (DWORD)args[0] );
        }
        trace_syscall_dispatcher_slot( "entry", service, ctx );
        if (trace_syscalls_enabled())
        {
            DWORD sample[6] = { 0 };
            ULONG_PTR native_sp = current_native_sp();
            copy_guest32_dwords( ret_esp + sizeof(DWORD), sample, ARRAY_SIZE(sample) );
            dump_syscall_bop_stack( service, ctx, ret_eip, ret_esp );
            MESSAGE( "macrunner-xtajit: syscall bop pre num=%08lx ret=%08lx esp=%08lx args=%08lx native_sp=%p slack=%ld sample=%08lx,%08lx,%08lx,%08lx,%08lx,%08lx\n",
                     service, ret_eip, ret_esp, (DWORD)(ret_esp + sizeof(DWORD)),
                     (void *)native_sp, (long)current_native_stack_slack( native_sp ),
                     sample[0], sample[1], sample[2], sample[3], sample[4], sample[5] );
        }

        trace_native_stack_teb( native_teb, "syscall-bop-before-pending", ctx->eip, ctx->esp, service, 0 );
        *status = STATUS_SUCCESS;
        {
            struct xtajit_teb32_stack_base old_teb32_stack;
            NTSTATUS publish_status;

            if (trace_syscalls_enabled())
            {
                TEB *teb = xtajit_current_teb();
                TEB32 *teb32 = xtajit_context_teb32( ctx );
                TEB32 *offset_teb32 = xtajit_current_teb32();
                MESSAGE( "macrunner-xtajit: pending-cross stage=before-publish svc=%08lx "
                         "eip=%08lx esp=%08lx x18=%p teb=%p wow_offset=%ld teb32=%p "
                         "offset_teb32=%p stack_base=%08lx stack_limit=%08lx\n",
                         service, ctx->eip, ctx->esp, (void *)current_x18(), teb,
                         teb ? (long)teb->WowTebOffset : 0, teb32, offset_teb32,
                         teb32 ? teb32->Tib.StackBase : 0, teb32 ? teb32->Tib.StackLimit : 0 );
            }
            publish_status = publish_simulated_i386_context( ctx );
            if (trace_syscalls_enabled())
                MESSAGE( "macrunner-xtajit: pending-cross stage=after-publish svc=%08lx status=%08lx x18=%p teb=%p\n",
                         service, publish_status, (void *)current_x18(), xtajit_current_teb() );
            if (publish_status)
            {
                *status = publish_status;
                return TRUE;
            }
            publish_pending_guest_stack_base( ctx, &old_teb32_stack );
            if (trace_syscalls_enabled())
            {
                TEB32 *teb32 = old_teb32_stack.teb32;
                MESSAGE( "macrunner-xtajit: pending-cross stage=after-stackbase svc=%08lx "
                         "teb32=%p old_base=%08lx new_base=%08lx esp=%08lx\n",
                         service, teb32, old_teb32_stack.old_base,
                         teb32 ? teb32->Tib.StackBase : 0, ctx->esp );
            }
            prepare_arm64_pe_call( native_teb );
            if (trace_syscalls_enabled())
                MESSAGE( "macrunner-xtajit: pending-cross stage=after-prepare svc=%08lx x18=%p teb=%p\n",
                         service, (void *)current_x18(), native_teb );
            trace_arm64_pe_call_state( "before-pending-cross-process", service,
                                       (ULONG_PTR)Wow64ProcessPendingCrossProcessItems,
                                       NULL, native_teb );
            if (trace_syscalls_enabled())
                MESSAGE( "macrunner-xtajit: pending-cross stage=before-process svc=%08lx x18=%p teb=%p\n",
                         service, (void *)current_x18(), native_teb );
            Wow64ProcessPendingCrossProcessItems();
            if (trace_syscalls_enabled())
                MESSAGE( "macrunner-xtajit: pending-cross stage=after-process svc=%08lx x18=%p teb=%p\n",
                         service, (void *)current_x18(), native_teb );
            restore_pending_guest_stack_base( &old_teb32_stack );
            if (trace_syscalls_enabled())
                MESSAGE( "macrunner-xtajit: pending-cross stage=after-restore svc=%08lx x18=%p teb=%p\n",
                         service, (void *)current_x18(), native_teb );
        }
        trace_syscall_dispatcher_slot( "after-pending", service, ctx );
        trace_native_stack_teb( native_teb, "syscall-bop-after-pending", ctx->eip, ctx->esp, service, 0 );
        prepare_arm64_pe_call( native_teb );
        trace_native_stack_teb( native_teb, "syscall-bop-before-dispatch", ctx->eip, ctx->esp, service, 0 );
        ctx->eax = dispatch_wow64_syscall( service, args );
        trace_syscall_dispatcher_slot( "after-dispatch", service, ctx );
        trace_native_stack_teb( native_teb, "syscall-bop-after-dispatch", ret_eip, ret_esp, service, ctx->eax );
        {
            TEB *teb = native_teb;
            WOW64_CPURESERVED *cpu = teb ? teb->TlsSlots[WOW64_TLS_CPURESERVED] : NULL;

            if (cpu && (cpu->Flags & WOW64_CPURESERVED_FLAG_RESET_STATE))
            {
                DWORD result = ctx->eax;
                I386_CONTEXT reset_ctx = { CONTEXT_I386_ALL };
                NTSTATUS get_status;

                get_status = consume_reset_i386_context( &reset_ctx );
                if (get_status == STATUS_NOT_FOUND)
                    get_status = RtlWow64GetThreadContext( GetCurrentThread(), &reset_ctx );
                if (get_status)
                {
                    *status = get_status;
                    return TRUE;
                }
                pack_i386_context( ctx, &reset_ctx );
                ctx->eax = result;
                MESSAGE( "macrunner-xtajit: syscall bop reset-context svc=%08lx eip=%08lx esp=%08lx eax=%08lx\n",
                         service, ctx->eip, ctx->esp, ctx->eax );
                return TRUE;
            }
        }
        ctx->esp = ret_esp;
        ctx->eip = ret_eip;
        /* Итерация 840: помечаем, что для создания окна сдвиг ВЫСТАВЛЕН — чтобы на следующем
         * входе в цикл симуляции напечатать, с какого адреса он реально начался. */
        if (service == 0x136b) macrunner_last_bop_advance = ret_eip;
        /* MacRunner 2026-08-13, лейн ЛЕСТНИЦА, итерация 838 — ДОВЕСТИ СДВИГ ДО ПОТОКА.
         *
         * Замер 837: мы записываем `eip=7ab9078c` (адрес возврата) в местный контекст, а в
         * контексте ПОТОКА остаётся `00270000` — адрес переходника; так на всех повторах,
         * включая n=2000. Контекст публикуется ОДИН раз, ДО вызова службы
         * (`publish_simulated_i386_context` выше), а после — только местная запись. Если
         * внутри службы произошёл обратный вызов (оконная процедура), он поменял контекст
         * потока, и наш сдвиг до гостя не доходит: тот исполняет вызов заново.
         *
         * Наблюдаемое следствие измерено тремя приборами: 5202 создания окна при ОДНОМ `esp`,
         * дословно совпадающая цепочка кадров на всех повторах, и один-единственный вызов
         * `CreateWindowExA` со стороны игры.
         *
         * Гейт `MACRUNNER_XTAJIT_REPUBLISH_AFTER_SYSCALL`, умолчание ВЫКЛ: правка трогает
         * КАЖДЫЙ системный вызов, поэтому включается только для замера. */
        {
            static int republish = -1;

            if (republish < 0)
            {
                /* Итерация 838, поправка в ту же итерацию: `getenv` в этом модуле НЕТ —
                 * сборка упала на `undefined symbol: getenv`, и это записанная ловушка 210
                 * самого лейна. Читаем переменную тем же способом, что соседние гейты файла
                 * (`trace_sim_enabled`, строка 363) — через `RtlQueryEnvironmentVariable_U`. */
                static const WCHAR nameW[] =
                    {'M','A','C','R','U','N','N','E','R','_','X','T','A','J','I','T','_',
                     'R','E','P','U','B','L','I','S','H','_','A','F','T','E','R','_',
                     'S','Y','S','C','A','L','L',0};
                WCHAR value[4] = { 0 };
                UNICODE_STRING name, val;

                RtlInitUnicodeString( &name, nameW );
                val.Buffer = value;
                val.Length = 0;
                val.MaximumLength = sizeof(value);
                republish = RtlQueryEnvironmentVariable_U( NULL, &name, &val ) != STATUS_VARIABLE_NOT_FOUND &&
                            value[0] && value[0] != '0';
            }
            if (republish)
            {
                NTSTATUS rp = publish_simulated_i386_context( ctx );
                static LONG pn;
                LONG pk = InterlockedIncrement( &pn );

                if (pk <= 4 || !(pk % 5000))
                    MESSAGE( "macrunner-xtajit-republish: n=%ld svc=%08lx eip=%08lx esp=%08lx статус=%08lx\n",
                             (long)pk, service, (unsigned long)ctx->eip,
                             (unsigned long)ctx->esp, (unsigned long)rp );
            }
        }
        /* MacRunner 2026-08-13, лейн ЛЕСТНИЦА, итерация 837 — ПОСТАВИЛИ ПРОТИВ ТОГО, ЧТО ЕСТЬ.
         * Измерено: создание окна (0x136b) исполняется 5202 раза с ОДНИМ esp и ОДНОЙ цепочкой
         * кадров (835-836), то есть гость возвращается на сам переходник. Ветка сброса
         * состояния как причина ОТПАЛА — её печать сработала 2 раза и на службе 0x43.
         * Значит надо сверить: то, что мы записали в контекст, и то, что в нём окажется.
         * Печать ограничена, чтобы прибор не возмущал явление (урок 829). */
        if (service == 0x136b)
        {
            static LONG rn;
            LONG k = InterlockedIncrement( &rn );

            if (k <= 4 || !(k % 2000))
            {
                I386_CONTEXT back = { CONTEXT_I386_CONTROL };
                NTSTATUS st = RtlWow64GetThreadContext( GetCurrentThread(), &back );

                MESSAGE( "macrunner-xtajit-retset: n=%ld svc=%08lx поставили_eip=%08lx "
                         "поставили_esp=%08lx прочитали_eip=%08lx прочитали_esp=%08lx статус=%08lx\n",
                         (long)k, service, (unsigned long)ctx->eip, (unsigned long)ctx->esp,
                         (unsigned long)back.Eip, (unsigned long)back.Esp, (unsigned long)st );
            }
        }
        trace_syscall_dispatcher_slot( "return", service, ctx );
        if (trace_syscalls_enabled())
        {
            ULONG_PTR native_sp = current_native_sp();
            MESSAGE( "macrunner-xtajit: syscall bop svc=%08lx ret=%08lx esp=%08lx native_sp=%p slack=%ld result=%08lx status=%08lx\n",
                     service, ctx->eip, ctx->esp, (void *)native_sp,
                     (long)current_native_stack_slack( native_sp ), ctx->eax, (NTSTATUS)STATUS_SUCCESS );
        }
        return TRUE;
    }
    if (unix_bop_guest && ctx->eip == PtrToUlong( unix_bop_guest ))
    {
        DWORD *ret = guest32_host_ptr( ctx->esp );
        struct unix_bop_stack *stack;

        if (!ret)
        {
            *status = STATUS_ACCESS_VIOLATION;
            return TRUE;
        }
        ret_eip = *ret;
        ret_esp = ctx->esp + sizeof(DWORD);
        stack = guest32_host_ptr( ret_esp );
        if (!stack)
        {
            *status = STATUS_ACCESS_VIOLATION;
            return TRUE;
        }

        if (trace_syscalls_enabled())
        {
            ULONG_PTR native_sp = current_native_sp();
            MESSAGE( "macrunner-xtajit: unix bop pre handle=%p id=%u args=%08lx ret=%08lx esp=%08lx native_sp=%p slack=%ld\n",
                     (void *)(ULONG_PTR)stack->handle, stack->id, stack->args, ret_eip, ret_esp,
                     (void *)native_sp, (long)current_native_stack_slack( native_sp ) );
        }

        trace_native_stack( "unix-bop-before-dispatch", ctx->eip, ctx->esp, 0xffffffff, 0 );
        *status = STATUS_SUCCESS;
        /* ★ Итерация 2687: БЕЗУСЛОВНЫЙ зонд — какой юникс-вызов идёт перед отказом.
         * Штатная печать `unix bop pre` стоит за гейтом trace_syscalls_enabled и в журнале
         * даёт ноль строк (проверено 2686), поэтому нужен свой, с потолком. */
        {
            static LONG _un;
            LONG _k = InterlockedIncrement( &_un );
            if (_k <= 12 || !(_k % 20000))
                /* ★ Итерация 2696: добавлен ret_eip — АДРЕС ВЫЗЫВАЮЩЕГО. Сопоставить дескриптор
                 * с именем модуля не вышло дважды: он не равен ни одному `funcs`, который
                 * wow64 отдаёт гостю (проверено по журналу того же прогона). Адрес возврата
                 * называет вызывающего однозначно — по диапазону образа: Diablo.exe 0x400000,
                 * ddraw 0x78F60000, системные библиотеки 0x7B/0x77. */
                MESSAGE( "macrunner-xtajit-unixbop: n=%ld handle=%p id=%u eip=%08lx ret_eip=%08lx esp=%08lx\n",
                         (long)_k, (void *)(ULONG_PTR)stack->handle, stack->id, ctx->eip,
                         ret_eip, ctx->esp );
        }
        /* ★ MacRunner, лейн ЛЕСТНИЦА, итерация 2717 — СЧЁТЧИК КОДА 3 НА ВХОДЕ В ДИСПЕТЧЕР.
         * 2716: счётчик внутри переходника `wow64_get_pixel_formats` дал ВСЕГО 8, а на стеке
         * гостя лежит кадр ДЕВЯТОГО вызова `_get_pixel_formats` (ebp=016bf998, связи пролога
         * esp=ebp-0x2c и params=ebp-0x24 сошлись на обоих экземплярах). Вопрос ровно один:
         * покидал ли девятый вызов гостя. Считаю ЗДЕСЬ, до `__wine_unix_call`, и печатаю
         * ВХОД и ВЫХОД раздельно — вход без выхода назовёт вызов, который не вернулся.
         * Потолка НЕТ сознательно: код 3 за прогон приходит единицами (мой же урок 22.08 —
         * потолок морит редкое событие голодом, а именно им я и обожглась в 2715). */
        {
            static LONG _id3_in, _id3_out, _id3_bad;
            LONG k3 = (stack->id == 3) ? InterlockedIncrement( &_id3_in ) : 0;
            /* ★ ЛЕСТНИЦА 2718 — ЛЕВЫЙ КРАЙ ВИЛКИ НА ГОСТЕВОЙ СТОРОНЕ.
             * 2717 зажала порчу в 1 мс: 59.042 выход из unix-вызова (кадр цел), 59.043 вход
             * в диспетчер обратного вызова (кадр уже {1801005b,0000000d}). Зонд, доказавший
             * левый край, стоит ВНУТРИ хозяина (`wow64_get_pixel_formats`) и хозяином же
             * ограничен. Читаю те же два слова ЗДЕСЬ, на гостевой стороне BOP, вокруг всего
             * вызова целиком: целы после возврата -> писавший НЕ хозяин и не переходник. */
            const ULONG *fr3 = k3 ? guest32_host_ptr( stack->args ) : NULL;
            ULONG fr3_do[2] = { 0, 0 }, fr3_posle[2] = { 0, 0 };

            if (fr3) { fr3_do[0] = fr3[9]; fr3_do[1] = fr3[10]; }   /* args+0x24, args+0x28 */
            if (k3 && k3 <= 4)
            {
                /* печать через MESSAGE: в ЭТОМ модуле она доказана — строки
                 * macrunner-xtajit-unixbop из неё доходят до журнала. fprintf здесь не
                 * связывается (тот же класс, что getenv в xtajit.dll). */
                MESSAGE( "macrunner-код3-2717: ВХОД n=%ld ret_eip=%08lx esp=%08lx "
                         "args=%08lx handle=%p\n", (long)k3, (unsigned long)ret_eip,
                         (unsigned long)ctx->esp, (unsigned long)stack->args,
                         (void *)(ULONG_PTR)stack->handle );
            }
            if (unixbop_frame_enabled())
                ctx->eax = xtajit_arm64_call_unix_frame( stack->handle, stack->id,
                                                         guest32_host_ptr( stack->args ),
                                                         native_teb, (void *)__wine_unix_call );
            else
                ctx->eax = __wine_unix_call( stack->handle, stack->id, guest32_host_ptr( stack->args ) );
            if (k3)
            {
                LONG nout = InterlockedIncrement( &_id3_out );
                int plohoi3;

                if (fr3) { fr3_posle[0] = fr3[9]; fr3_posle[1] = fr3[10]; }
                plohoi3 = (fr3_posle[0] != fr3_do[0]) || (fr3_posle[1] != fr3_do[1])
                          || !(fr3_posle[1] >= 0x77850000 && fr3_posle[1] < 0x778f5000);
                if (k3 <= 4 || (plohoi3 && InterlockedIncrement( &_id3_bad ) <= 32))
                    MESSAGE( "macrunner-код3-2717: ВЫХОД n=%ld выходов=%ld eax=%08lx "
                             "кадр2718_до=%08lx %08lx кадр2718_после=%08lx %08lx плохой=%d\n",
                             (long)k3, (long)nout, (unsigned long)ctx->eax,
                             (unsigned long)fr3_do[0], (unsigned long)fr3_do[1],
                             (unsigned long)fr3_posle[0], (unsigned long)fr3_posle[1], plohoi3 );
            }
        }
        trace_native_stack( "unix-bop-after-dispatch", ret_eip, ret_esp, 0xffffffff, ctx->eax );
        ctx->esp = ret_esp + sizeof(*stack);
        ctx->eip = ret_eip;
        /* ★ MacRunner, лейн ЛЕСТНИЦА, итерация 2719 — ТРЕТЬЯ ТОЧКА ЧТЕНИЯ КАДРА.
         * 2717 зажала порчу в 1 мс, 2718 оправдала всю отлучку к хозяину (ноль плохих на
         * бюджете 32). Остался промежуток «возврат из __wine_unix_call -> вход в диспетчер
         * обратного вызова», где исполняется только наш код. Эта точка — САМЫЙ КОНЕЦ
         * обработчика BOP, после присваивания ctx->esp и ctx->eip. Испорчен уже здесь —
         * писал эпилог BOP; цел — писал JIT либо путь обратного вызова.
         * Печать: первые 4 (доказательство, что прибор вообще стреляет) плюс ЛЮБОЙ плохой,
         * бюджет 32. Потолком редкое событие не морю — свой же урок, нарушенный трижды. */
        if (stack->id == 3)
        {
            static LONG _t3_all, _t3_bad;
            const ULONG *fr = guest32_host_ptr( stack->args );
            LONG n3 = InterlockedIncrement( &_t3_all );
            int hud = !fr || !(fr[10] >= 0x77850000 && fr[10] < 0x778f5000);

            if (n3 <= 4 || (hud && InterlockedIncrement( &_t3_bad ) <= 32))
                MESSAGE( "macrunner-конец-bop-2719: n=%ld args=%08lx кадр=%08lx %08lx "
                         "esp=%08lx eip=%08lx плохой=%d\n", (long)n3,
                         (unsigned long)stack->args,
                         fr ? (unsigned long)fr[9] : 0, fr ? (unsigned long)fr[10] : 0,
                         (unsigned long)ctx->esp, (unsigned long)ctx->eip, hud );
        }
        if (trace_syscalls_enabled())
        {
            ULONG_PTR native_sp = current_native_sp();
            MESSAGE( "macrunner-xtajit: unix bop done ret=%08lx esp=%08lx native_sp=%p slack=%ld result=%08lx status=%08lx\n",
                     ctx->eip, ctx->esp, (void *)native_sp,
                     (long)current_native_stack_slack( native_sp ), ctx->eax, (NTSTATUS)STATUS_SUCCESS );
        }
        return TRUE;
    }
    return FALSE;
}

NTSTATUS WINAPI BTCpuGetContext( HANDLE thread, HANDLE process, void *unknown, I386_CONTEXT *ctx )
{
    I386_CONTEXT *host_ctx = host_i386_context_ptr( ctx );
    NTSTATUS status;

    if (ctx && !host_ctx) return STATUS_ACCESS_VIOLATION;
    /* ★ 2617: СЧЁТ НА ВХОДЕ, ДО ВСЯКИХ ВЕТВЛЕНИЙ.
     * 2616 дал «сравнений=1» на процесс, а обратных вызовов за прогон 48. Значит либо
     * функция зовётся редко, либо ветвь текущего потока не берётся. Различить можно только
     * счётом ДО ветвления: печатаем сам `thread`, `GetCurrentThread()` и их равенство. */
    {
        static LONG all_n, cur_n;
        LONG k = InterlockedIncrement( &all_n );

        if (thread == GetCurrentThread()) InterlockedIncrement( &cur_n );
        if (k <= 3 || !(k % 25))
            MESSAGE( "macrunner-xtajit: ctx-VXOD n=%ld cur=%ld thread=%p cur_thread=%p eq=%d\n",
                     (long)k, (long)cur_n, thread, GetCurrentThread(),
                     thread == GetCurrentThread() );
    }
    /* ★ MacRunner, лейн ЛЕСТНИЦА, итерация 2615 — НЕСИММЕТРИЧНЫЕ ЧТЕНИЕ И ЗАПИСЬ.
     *
     * Замер 2614 (поток 012c, вложенности нет): последняя запись контекста перед входом
     * обратного вызова положила eip=00270000 esp=016bf898, а диспетчер обратного вызова
     * прочитал eip=778f15d9 esp=016bf96c — СМЕСЬ устаревших значений (esp от одного
     * прежнего состояния, eip от другого). Из 48 возвратов оконной процедуры расходится
     * ровно один, и сразу за ним гость уходит исполнять по 0x0000000d.
     *
     * Причина видна прямо в коде и здесь же ниже: у `BTCpuSetContext` для ТЕКУЩЕГО потока
     * есть быстрый путь `set_current_i386_context` (пишет в `info.Context`), а у
     * `BTCpuGetContext` такого пути НЕТ — он всегда идёт через `RtlWow64GetThreadContext`,
     * то есть читает ДРУГУЮ копию. Пишем в одно место, читаем из другого; сходится оно
     * только пока обе копии синхронны.
     *
     * Делаем чтение симметричным записи. `ContextFlags` сохраняем: `read_current_i386_context`
     * копирует структуру целиком и затёр бы то, что запросил вызывающий. */
    /* ★ ИТЕРАЦИЯ 2616 — КАКАЯ ИЗ ДВУХ КОПИЙ ЧТО НЕСЁТ.
     *
     * 2615 показал: правка симметрии фронт не сняла (несовпадений 1 и 1, 0x0000000d 6 и 6),
     * то есть моя же гипотеза «несимметрия = причина» опровергнута. Значит спрашивать надо
     * не «какую копию читать», а «что в КАЖДОЙ копии лежит».
     *
     * Поэтому: ПОВЕДЕНИЕ ВОЗВРАЩАЮ ИСХОДНОЕ (отдаём `RtlWow64GetThreadContext`) — тогда
     * прогон сравним с семью базовыми, побайтно одинаковыми (sdib=45, окон=8), и служит
     * заодно парой к 2615. А рядом читаем ВТОРУЮ копию и печатаем ТОЛЬКО при расхождении:
     * потолок по счёту здесь не годится, событие редкое и позднее (мой урок 2612).
     */
    if (thread == GetCurrentThread() && host_ctx)
    {
        I386_CONTEXT frame_ctx;
        DWORD want = host_ctx->ContextFlags;
        NTSTATUS sf;

        status = RtlWow64GetThreadContext( thread, host_ctx );   /* исходное поведение */

        memset( &frame_ctx, 0, sizeof(frame_ctx) );
        sf = read_current_i386_context( &frame_ctx );            /* info.Context, куда ПИШЕМ */
        frame_ctx.ContextFlags = want;
        /* ★ ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ (правило: ноль обязан быть ДОКАЗАННЫМ нулём).
         * Печать расхождений включается самим расхождением, поэтому «0 расхождений»
         * неотличимо от «зонд ни разу не отработал». Считаем сравнения и сколько из них
         * совпало; строка редкая, журнал не топит. */
        {
            static LONG cmp_n, same_n;
            LONG k = InterlockedIncrement( &cmp_n );

            if (!status && !sf && frame_ctx.Eip == host_ctx->Eip &&
                frame_ctx.Esp == host_ctx->Esp) InterlockedIncrement( &same_n );
            if (k == 1 || !(k % 20000))
                MESSAGE( "macrunner-xtajit: ctx-СВЕРКА сравнений=%ld совпало=%ld status=%08lx sf=%08lx\n",
                         (long)k, (long)same_n, (unsigned long)status, (unsigned long)sf );
        }
        if (!status && !sf &&
            (frame_ctx.Eip != host_ctx->Eip || frame_ctx.Esp != host_ctx->Esp))
            MESSAGE( "macrunner-xtajit: ctx-РАСХОЖДЕНИЕ поток=%04lx "
                     "rtl_eip=%08lx rtl_esp=%08lx rtl_eax=%08lx | "
                     "кадр_eip=%08lx кадр_esp=%08lx кадр_eax=%08lx\n",
                     (unsigned long)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread,
                     (unsigned long)host_ctx->Eip, (unsigned long)host_ctx->Esp,
                     (unsigned long)host_ctx->Eax,
                     (unsigned long)frame_ctx.Eip, (unsigned long)frame_ctx.Esp,
                     (unsigned long)frame_ctx.Eax );
    }
    else status = RtlWow64GetThreadContext( thread, host_ctx );
    if (trace_all_simulate_enabled())
        MESSAGE( "macrunner-xtajit: BTCpuGetContext thread=%p status=%08lx eip=%08lx esp=%08lx\n",
                 thread, status, host_ctx ? host_ctx->Eip : 0, host_ctx ? host_ctx->Esp : 0 );
    return status;
}

NTSTATUS WINAPI BTCpuSetContext( HANDLE thread, HANDLE process, void *unknown, I386_CONTEXT *ctx )
{
    I386_CONTEXT *host_ctx = host_i386_context_ptr( ctx );
    NTSTATUS status;

    if (ctx && !host_ctx) return STATUS_ACCESS_VIOLATION;
    if (trace_all_simulate_enabled())
        MESSAGE( "macrunner-xtajit: BTCpuSetContext thread=%p eip=%08lx esp=%08lx\n",
                 thread, host_ctx ? host_ctx->Eip : 0, host_ctx ? host_ctx->Esp : 0 );
    if (thread == GetCurrentThread())
    {
        publish_pending_i386_context( host_ctx );
        status = set_current_i386_context( host_ctx );
    }
    else
        status = RtlWow64SetThreadContext( thread, host_ctx );
    if (trace_all_simulate_enabled())
        MESSAGE( "macrunner-xtajit: BTCpuSetContext status=%08lx thread=%p eip=%08lx esp=%08lx\n",
                 status, thread, host_ctx ? host_ctx->Eip : 0, host_ctx ? host_ctx->Esp : 0 );
    return status;
}

static void WINAPI BTCpuSimulate_impl( void *arg )
{
    struct xtajit_initial_i386_context *initial = arg;
    struct xtajit_simulate_params params;
    I386_CONTEXT ctx = { CONTEXT_I386_ALL };
    TEB *native_teb = xtajit_current_teb();
    NTSTATUS status;
    BOOL trace;
    BOOL progress_trace;
    BOOL trace_all;
    int current_trace_count;
    static int trace_count;

    if (initial)
    {
        ctx = initial->ctx;
        status = initial->status;
    }
    else
    {
        struct xtajit_initial_i386_context captured;

        capture_initial_i386_context( &captured );
        ctx = captured.ctx;
        status = captured.status;
    }
    if (macrunner_last_bop_advance)
    {
        static LONG en;
        LONG ek = InterlockedIncrement( &en );
        DWORD want = macrunner_last_bop_advance;

        macrunner_last_bop_advance = 0;
        if (ek <= 8 || !(ek % 5000))
            MESSAGE( "macrunner-xtajit-resume: n=%ld выставляли_eip=%08lx вошли_с_eip=%08lx "
                     "esp=%08lx совпало=%d\n", (long)ek, (unsigned long)want,
                     (unsigned long)ctx.Eip, (unsigned long)ctx.Esp, ctx.Eip == want );
    }
    /* ★★★★★ ИТЕРАЦИЯ 72, лейн МЕЛКИЕ — С ЧЕМ ПОТОК НАЧИНАЕТ ИСПОЛНЕНИЕ.
     *
     * Итерация 71 показала по байтам: точка входа потока i386 передаётся в EAX
     * (`mov %eax,0x4(%esp)` в начале RtlUserThreadStart, дальше `call *0x8(%ebp)`),
     * а падающий поток уходит по адресу 0/1/3 — то есть теряет именно это значение.
     * Контекст, который движок ВЫСТАВЛЯЕТ, на переходах 0 и 4 верен (eax=0x00405490).
     * Не измерено, с чем поток РЕАЛЬНО начинает исполнение.
     *
     * Существующий `macrunner-xtajit-resume` для этого не годится по трём причинам:
     * сверяет только EIP, срабатывает лишь при `macrunner_last_bop_advance`, и упёрся
     * в потолок «первые 8» — в архиве ровно 8 строк, все `совпало=1`, а интересующий
     * поток создаётся поздно (урок про голодание редких поздних событий).
     *
     * Счёт ПОТОКА-ЛОКАЛЬНЫЙ через табличку на 64 потока, поэтому поздние потоки не
     * голодают, а объём ограничен. Адреса НЕ вписаны: вторая ветка срабатывает на
     * САМОМ событии — возобновление по бессмысленно малому eip.
     *
     * NB `getenv` и `__thread` в этом модуле не линкуются (сказано в комментарии на
     * строке ~1075) — гейт читается штатным `RtlQueryEnvironmentVariable_U`. */
    if (threadstart_probe_enabled())
    {
        static struct { LONG tid; LONG n; } mr_ts[64];
        LONG mr_tid = (LONG)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread;
        int mr_i, mr_n = -1;

        for (mr_i = 0; mr_i < 64; mr_i++)
        {
            LONG have = mr_ts[mr_i].tid;
            if (!have && !InterlockedCompareExchange( &mr_ts[mr_i].tid, mr_tid, 0 )) have = mr_tid;
            if (have == mr_tid) { mr_n = ++mr_ts[mr_i].n; break; }
        }
        if (mr_n < 0) mr_n = 99;               /* табличка переполнена — печатаем только дикие */
        if (mr_n <= 3 || ctx.Eip < 0x10000)
            MESSAGE( "macrunner-xtajit-старт: поток=%04lx n=%d eip=%08lx esp=%08lx "
                     "eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx дикий=%d\n",
                     (unsigned long)mr_tid, mr_n, (unsigned long)ctx.Eip,
                     (unsigned long)ctx.Esp, (unsigned long)ctx.Eax,
                     (unsigned long)ctx.Ebx, (unsigned long)ctx.Ecx,
                     (unsigned long)ctx.Edx, ctx.Eip < 0x10000 );
    }
    trace_native_stack( "simulate-enter", ctx.Eip, ctx.Esp, 0xffffffff, status );
    trace_all = trace_all_simulate_enabled();
    current_trace_count = trace_count++;
    trace = trace_all;
    progress_trace = trace_syscalls_enabled() && !trace && !(current_trace_count & 0x3ffff);
    if (trace)
        MESSAGE( "macrunner-xtajit: BTCpuSimulate getctx status=%08lx eip=%08lx esp=%08lx ebp=%08lx eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx esi=%08lx edi=%08lx eflags=%08lx\n",
                 status, ctx.Eip, ctx.Esp, ctx.Ebp, ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx,
                 ctx.Esi, ctx.Edi, ctx.EFlags );
    else if (progress_trace)
        MESSAGE( "macrunner-xtajit: BTCpuSimulate progress count=%d eip=%08lx esp=%08lx eax=%08lx ecx=%08lx edx=%08lx eflags=%08lx\n",
                 trace_count, ctx.Eip, ctx.Esp, ctx.Eax, ctx.Ecx, ctx.Edx, ctx.EFlags );
    if (status) xtajit_raise_status( status );
    if (trace) dump_guest_bytes( "simulate eip-bytes", ctx.Eip, 96 );

    RtlZeroMemory( &params, sizeof(params) );
    pack_i386_context( &params.context, &ctx );
    params.max_code_bytes = 4096;

    if (!handle_bop_context( &params.context, &status, native_teb ))
    {
        status = xtajit_unix_call( unix_simulate, &params );
        if (!status) status = params.status;
        if (trace)
            MESSAGE( "macrunner-xtajit: BTCpuSimulate unix status=%08lx exit_status=%08lx hb=%ld faulted=%lu steps=%llu blocks=%llu eip=%08lx esp=%08lx ebp=%08lx eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx esi=%08lx edi=%08lx\n",
                     status, params.status, params.hb_result, params.faulted,
                     (unsigned long long)params.steps, (unsigned long long)params.blocks,
                     params.context.eip, params.context.esp, params.context.ebp,
                     params.context.eax, params.context.ebx, params.context.ecx,
                     params.context.edx, params.context.esi, params.context.edi );
        else if (progress_trace)
            MESSAGE( "macrunner-xtajit: BTCpuSimulate progress-out status=%08lx hb=%ld faulted=%lu steps=%llu blocks=%llu eip=%08lx esp=%08lx eax=%08lx ecx=%08lx edx=%08lx\n",
                     status, params.hb_result, params.faulted,
                     (unsigned long long)params.steps, (unsigned long long)params.blocks,
                     params.context.eip, params.context.esp, params.context.eax,
                     params.context.ecx, params.context.edx );
        {
            BOOL _bop2 = !status && handle_bop_context( &params.context, &status, native_teb );
            /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: за гейтом — 35% журнала (41 691 строка).
             * См. парную правку pre-sim-sentinel в unixlib.c. Умолчание ВЫКЛ. */
            if (trace_sim_enabled())
                MESSAGE( "macrunner-xtajit: sim-after status=%08lx hb=%ld faulted=%lu steps=%llu eip=%08lx esp=%08lx bop2=%d\n",
                         status, (long)params.hb_result, (ULONG)params.faulted,
                         (unsigned long long)params.steps, params.context.eip, params.context.esp, _bop2 );
            trace_stuck_i386_context( &params.context, (unsigned long long)params.steps, status, _bop2 );
            if (_bop2 && trace_syscalls_enabled())
                MESSAGE( "macrunner-xtajit: BTCpuSimulate handled bop eip=%08lx esp=%08lx eax=%08lx status=%08lx\n",
                         params.context.eip, params.context.esp, params.context.eax, status );
        }
    }
    if (status)
    {
        NTSTATUS publish_status = publish_simulated_i386_exception_context( &params.context );

        MESSAGE( "macrunner-xtajit: BTCpuSimulate publish-exception-context status=%08lx "
                 "exception=%08lx eip=%08lx esp=%08lx eax=%08lx ebp=%08lx\n",
                 publish_status, status, params.context.eip, params.context.esp,
                 params.context.eax, params.context.ebp );
        /* ★★★★★★ MacRunner 2026-09-01 — ДОВОДЫ И ВЫЗЫВАЮЩИЙ В ТОЧКЕ ОТКАЗА.
         *
         * Отказ Half-Life приходит в `ucrtbase!_memmove+0x4d0`, на команде
         * `movups (%esi,%edx,4),%xmm0`: источник это ESI, приёмник EBX, счётчик EDX,
         * остаток в ECX. Прежде я вывел вызывающего из содержимого стека около ebp и
         * ошибся — прямой замер ту версию снял. Здесь берём не догадку, а сами числа:
         * все регистры в момент отказа и слово по `ebp+4`, где у обычного пролога
         * (`push ebp; mov esp,ebp`) лежит адрес возврата вызывающего.
         *
         * Печатается только на c0000005 и не чаще четырёх раз — в норме прибор молчит. */
        if (status == 0xc0000005)
        {
            static int skazano;

            if (skazano++ < 4)
            {
                DWORD vozvrat = 0, vozvrat_esp = 0;

                copy_guest32_bytes( params.context.ebp + 4, (BYTE *)&vozvrat, sizeof(vozvrat) );
                copy_guest32_bytes( params.context.esp, (BYTE *)&vozvrat_esp, sizeof(vozvrat_esp) );
                MESSAGE( "macrunner-xtajit: отказ-регистры eax=%08lx ebx=%08lx ecx=%08lx "
                         "edx=%08lx esi=%08lx edi=%08lx ebp=%08lx esp=%08lx | "
                         "[ebp+4]=%08lx [esp]=%08lx\n",
                         params.context.eax, params.context.ebx, params.context.ecx,
                         params.context.edx, params.context.esi, params.context.edi,
                         params.context.ebp, params.context.esp, vozvrat, vozvrat_esp );
                /* ★ Спросить САМУ СИСТЕМУ, что за память по источнику и приёмнику.
                 * Инструментировать подозреваемого нельзя: прибор в nsi гасит отказ
                 * (5 прогонов из 5 становятся короткими и не падают). А этот прибор
                 * отказ НЕ гасит — с ним падало 5 из 5. */
                {
                    static const struct { const char *имя; DWORD знач; } tochki[] = {
                        { "esi", 0 }, { "ebx", 0 }, { "edi", 0 }, { "edi+0x80000", 0 } };
                    DWORD adresa[4];
                    unsigned int t;

                    adresa[0] = params.context.esi;
                    adresa[1] = params.context.ebx;
                    adresa[2] = params.context.edi;
                    adresa[3] = params.context.edi + 0x80000;
                    for (t = 0; t < 4; t++)
                    {
                        MEMORY_BASIC_INFORMATION mbi;
                        SIZE_T len = 0;
                        void *host = guest32_host_ptr( adresa[t] );

                        if (host && !NtQueryVirtualMemory( GetCurrentProcess(), host,
                                                           MemoryBasicInformation,
                                                           &mbi, sizeof(mbi), &len ))
                            /* Печатаем BaseAddress, а не только AllocationBase: они разные,
                             * и складывать AllocationBase с RegionSize нельзя — я сам на этом
                             * чуть не сделал неверный вывод. */
                            MESSAGE( "macrunner-xtajit: отказ-область %-11s=%08lx | начало=%p "
                                     "размер=%p состояние=%08lx защита=%08lx | резерв=%p тип=%08lx\n",
                                     tochki[t].имя, adresa[t], mbi.BaseAddress,
                                     (void *)mbi.RegionSize, (unsigned long)mbi.State,
                                     (unsigned long)mbi.Protect, mbi.AllocationBase,
                                     (unsigned long)mbi.Type );
                        else
                            MESSAGE( "macrunner-xtajit: отказ-область %s=%08lx host=%p "
                                     "СПРОСИТЬ НЕ УДАЛОСЬ\n", tochki[t].имя, adresa[t], host );
                    }
                }
            }
        }
        /* Итерация 306: было 32 байта — их не хватало, чтобы дойти до отказавшей команды.
         * Блок разбирается зондом покомандно (правило 304), и на 32 байтах разбор кончался
         * РАНЬШЕ отказа, из-за чего команду приходилось угадывать. 96 — как у соседней печати. */
        dump_guest_bytes( "simulate exception eip-bytes", params.context.eip, 96 );
        /* Итерация 74 (лейн МЕЛКИЕ): назвать ВЫЗЫВАЮЩЕГО, а не только место отказа.
         *
         * Замер 74 назвал точку отказа — user32.dll (i386) + 0x52904, команда
         * `mov [ecx],eax`, где `ecx` берётся из `[ebp+0x18]`, то есть ВЫХОДНОЙ УКАЗАТЕЛЬ
         * от вызывающего. Кто вызывающий и что он туда положил — не измерено, а именно
         * это и есть следующий вопрос.
         *
         * Прибора не завожу: `dump_guest_bytes` уже есть, безопасен (тот же вызов стоит
         * на `eip`, который в этой линии бывает нулевым) и ограничен 96 байтами. Довернуть
         * его на кадр дешевле, чем писать своё.
         *
         * 64 байта от `ebp` покрывают `[ebp]` (кадр вызывающего), `[ebp+4]` (АДРЕС
         * ВОЗВРАТА) и все аргументы включая `[ebp+0x18]`. Печать безусловная и стоит
         * внутри уже условного блока (только при `status`), в прогоне 73 он сработал
         * 15 раз за прогон — потолок не нужен. */
        dump_guest_bytes( "simulate exception ebp-bytes", params.context.ebp, 64 );
        dump_guest_bytes( "simulate exception esp-bytes", params.context.esp, 64 );
        MESSAGE( "macrunner-xtajit: v2-check before-pass-guest-exception status=%08lx\n", status );
        if (publish_status) xtajit_raise_status( publish_status );
        if (pass_guest_exception( &params, status ))
        {
            return;
        }
        xtajit_raise_status( status );
    }

    if (native_teb) native_teb->TlsSlots[XTAJIT_TLS_GUEST_EXC_DEPTH] = 0;  /* successful simulation: reset depth */
    unpack_i386_context( &ctx, &params.context );
    status = RtlWow64SetThreadContext( GetCurrentThread(), &ctx );
    clear_wow64_reset_state();
    trace_native_stack( "simulate-exit", ctx.Eip, ctx.Esp, 0xffffffff, status );
    if (trace)
        MESSAGE( "macrunner-xtajit: BTCpuSimulate setctx status=%08lx eip=%08lx esp=%08lx ebp=%08lx eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx esi=%08lx edi=%08lx\n",
                 status, ctx.Eip, ctx.Esp, ctx.Ebp, ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx,
                 ctx.Esi, ctx.Edi );
    if (status) xtajit_raise_status( status );
}

void WINAPI BTCpuSimulate(void)
{
    struct xtajit_initial_i386_context initial;
#ifdef __aarch64__
    TEB *teb;
    struct xtajit_stack_bounds old;
    void *stack_top;
    void *old_active;
#endif

    capture_initial_i386_context( &initial );

#ifdef __aarch64__
    teb = xtajit_current_teb();
    if (teb && (stack_top = bridge_stack_top_below_syscall_frame( teb )))
    {
        if (trace_native_stack_enabled())
        {
            ULONG_PTR frame = *(ULONG_PTR *)((char *)teb + XTAJIT_TEB_SYSCALL_FRAME_OFFSET);
            MESSAGE( "macrunner-xtajit-stack: nested-callback-switch native_sp=%p "
                     "syscall_frame=%p nested_top=%p bridge=%p-%p\n",
                     (void *)current_native_sp(), (void *)frame, stack_top,
                     teb->TlsSlots[XTAJIT_TLS_BRIDGE_STACK],
                     (void *)((ULONG_PTR)teb->TlsSlots[XTAJIT_TLS_BRIDGE_STACK] +
                              (SIZE_T)teb->TlsSlots[XTAJIT_TLS_BRIDGE_SIZE]) );
        }
        old_active = teb->TlsSlots[XTAJIT_TLS_BRIDGE_ACTIVE];
        teb->TlsSlots[XTAJIT_TLS_BRIDGE_ACTIVE] = (void *)1;
        xtajit_arm64_call_void( stack_top, teb, BTCpuSimulate_impl, &initial );
        teb->TlsSlots[XTAJIT_TLS_BRIDGE_ACTIVE] = old_active;
        return;
    }

    if (teb && !teb->TlsSlots[XTAJIT_TLS_BRIDGE_ACTIVE] &&
        !ensure_bridge_stack() && (stack_top = bridge_stack_top( teb )))
    {
        publish_bridge_stack_bounds( teb, &old );
        teb->TlsSlots[XTAJIT_TLS_BRIDGE_ACTIVE] = (void *)1;
        xtajit_arm64_call_void( stack_top, teb, BTCpuSimulate_impl, &initial );
        teb->TlsSlots[XTAJIT_TLS_BRIDGE_ACTIVE] = NULL;
        restore_stack_bounds( teb, &old );
        return;
    }
#endif
    BTCpuSimulate_impl( &initial );
}

NTSTATUS WINAPI BTCpuResetToConsistentState( EXCEPTION_POINTERS *ptrs )
{
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BTCpuTurboThunkControl( ULONG enable )
{
    return STATUS_SUCCESS;
}

void WINAPI BTCpuFlushInstructionCache2( const void *addr, SIZE_T size )
{
    (void)xtajit_unix_call( unix_flush_instruction_cache, NULL );
}

void WINAPI BTCpuFlushInstructionCacheHeavy( const void *addr, SIZE_T size )
{
    (void)xtajit_unix_call( unix_flush_instruction_cache, NULL );
}

NTSTATUS WINAPI BTCpuNotifyMapViewOfSection( void *unk1, void *addr, void *unk2,
                                             SIZE_T size, ULONG protect, ULONG status_code )
{
    struct xtajit_memory_params params = { addr, size, 0, protect, TRUE, status_code };
    return xtajit_unix_call( unix_notify_map_view, &params );
}

void WINAPI BTCpuNotifyMemoryAlloc( void *addr, SIZE_T size, ULONG type,
                                    ULONG protect, BOOL is_post, NTSTATUS status )
{
    struct xtajit_memory_params params = { addr, size, type, protect, is_post, status };
    (void)xtajit_unix_call( unix_notify_memory_alloc, &params );
}

void WINAPI BTCpuNotifyMemoryDirty( void *addr, SIZE_T size )
{
    (void)addr;
    (void)size;
}

void WINAPI BTCpuNotifyMemoryFree( void *addr, SIZE_T size, ULONG type,
                                   BOOL is_post, NTSTATUS status )
{
    struct xtajit_memory_params params = { addr, size, type, 0, is_post, status };
    (void)xtajit_unix_call( unix_notify_memory_free, &params );
}

void WINAPI BTCpuNotifyMemoryProtect( void *addr, SIZE_T size, ULONG protect,
                                      BOOL is_post, NTSTATUS status )
{
    struct xtajit_memory_params params = { addr, size, 0, protect, is_post, status };
    (void)xtajit_unix_call( unix_notify_memory_protect, &params );
}

void WINAPI BTCpuNotifyProcessExecuteFlagsChange( ULONG flags )
{
    ULONG f = flags;
    (void)xtajit_unix_call( unix_notify_execute_flags, &f );
}

void WINAPI BTCpuNotifyReadFile( HANDLE handle, void *addr, SIZE_T size,
                                 BOOL is_post, NTSTATUS status )
{
    (void)handle;
    (void)addr;
    (void)size;
    (void)is_post;
    (void)status;
}

void WINAPI BTCpuNotifyUnmapViewOfSection( void *addr, BOOL is_post, NTSTATUS status )
{
    struct xtajit_memory_params params = { addr, 0, 0, 0, is_post, status };
    (void)xtajit_unix_call( unix_notify_unmap_view, &params );
}

void WINAPI BTCpuUpdateProcessorInformation( SYSTEM_CPU_INFORMATION *info )
{
    /* wow64/system.c:412-416 гонит И SystemCpuInformation, И
     * SystemEmulationProcessorInformation в хостовый эмуляционный класс, а тот на ARM64-хосте
     * понижает архитектуру до PROCESSOR_ARCHITECTURE_ARM (ntdll/unix/system.c:3667-3668).
     * Понижение верно для Windows-on-ARM, где 32-битный гость и правда ARM; у нас гость x86,
     * и поправить обязан именно этот обработчик — как это делает сосед
     * xtajit64/cpu.c:372 (UpdateProcessorInformation) для AMD64.
     *
     * Значения выведены из НАШЕГО же CPUID, а не взяты по аналогии: hb_cpuid.h:74 объявляет
     * лист 1 EAX = 0x000306a9, то есть семейство 6, модель 0x3a, степпинг 9. По соглашению
     * Windows ProcessorLevel = семейство, ProcessorRevision = (модель << 8) | степпинг. */
    if (!info) return;
    info->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
    info->ProcessorLevel        = 6;
    info->ProcessorRevision     = 0x3a09;
}
