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

#if 0
#pragma makedep unix
#endif

#ifdef __aarch64__

#include "config.h"

/* Бесблокировочное чтение окружения: getenv не async-signal-safe и убивал процесс
 * рекурсивным захватом блокировки при наложении SIGSEGV и SIGUSR1. См. macrunner_hb.c. */
const char *macrunner_hb_getenv( const char *name );

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>
#ifdef __APPLE__
# include <dlfcn.h>
# include <mach/arm/thread_status.h>
#endif
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYSCALL_H
# include <syscall.h>
#else
# ifdef HAVE_SYS_SYSCALL_H
#  include <sys/syscall.h>
# endif
#endif
#ifdef HAVE_SYS_SIGNAL_H
# include <sys/signal.h>
#endif
#ifdef HAVE_SYS_UCONTEXT_H
# include <sys/ucontext.h>
#endif
#ifdef __APPLE__
# include <mach/mach.h>
# include <mach/mach_vm.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/asm.h"
#include "unix_private.h"
#include "macrunner_kusd.h"   /* заплатка зашитого чтения KUSER_SHARED_DATA, 08.09.2026 */
#include "macrunner_fex_kusd.h"
extern int hb_jit_wx_mode_get(void); /* итерация 83: режим W^X потока в точке отказа */

/* MacRunner 2026-08-04 — РАЗРЫВ КРУГА x18/TEB.
 *
 * На ARM64 inline `NtCurrentTeb()` из winnt.h — это БУКВАЛЬНО регистр x18:
 *     register struct _TEB *__wine_current_teb __asm__("x18");
 * Поэтому строка вида `REGn_sig(18, ctx) = (ULONG_PTR)NtCurrentTeb()` означает
 * «положить в x18 то, что сейчас в x18»: при целом x18 это пустая операция,
 * а при затёртом (macOS стирает x18 при переключении контекста) мусор
 * сохраняется как есть. Отсюда месяцы безрезультатных «восстановлений x18».
 *
 * Wine 11.14 решил это, перенеся данные потока на pthread TLS
 * (unix_private.h: get_thread_data() = pthread_getspecific(thread_data_key))
 * и таща teb по цепочке обработчиков явным параметром.
 *
 * У нас ключ уже есть — `teb_key` (unix_private.h), его заполняют
 * virtual.c:5223 и thread.c:1223, и через него же работает ЭКСПОРТИРУЕМЫЙ
 * NtCurrentTeb() в thread.c. Внутри ntdll его перекрывает inline-версия,
 * поэтому берём из ключа напрямую.
 *
 * Гейт MACRUNNER_HB_TEB_FROM_TLS СНЯТ 02.09.2026: правка безусловна,
 * выключенная ветка возвращала известный дефект (scripts/гейты.py).
 * поведение для A/B). Умолчание именно ВКЛ: правки пути к пикселю уже один раз
 * потерялись из-за выключенного по умолчанию гейта.
 */
static inline TEB *macrunner_teb_reliable(void)
{
    {
        TEB *t = pthread_getspecific( teb_key );
        if (t) return t;
    }
    return NtCurrentTeb();
}

#include "wine/debug.h"
#include "hb_probe.h"

WINE_DEFAULT_DEBUG_CHANNEL(seh);

#if defined(__APPLE__) && defined(__aarch64__)
extern bool os_custom_x18_abi_enabled(void) __attribute__((weak_import));
extern void os_set_custom_x18_abi_enabled(bool) __attribute__((weak_import));

static void macrunner_enable_windows_x18_abi(void)
{
    /* The request is per-thread and requires the loader's custom-x18 entitlement.
     * A syscall-return repair cannot preserve x18 across later context switches. */
    if (os_custom_x18_abi_enabled && os_set_custom_x18_abi_enabled &&
        !os_custom_x18_abi_enabled())
        os_set_custom_x18_abi_enabled(true);
}
#endif


#define NTDLL_DWARF_H_NO_UNWINDER
#include "dwarf.h"

extern NTSTATUS macrunner_hb_get_x64_thread_context( HANDLE handle, AMD64_CONTEXT *context );
extern NTSTATUS macrunner_hb_set_x64_thread_context( HANDLE handle, const AMD64_CONTEXT *context );
extern void macrunner_hb_trace_nullcall_site( const char *source, uint64_t host_pc, uint64_t fault_addr );
extern void macrunner_hb_trace_hk_memcpy_fault( const char *source, uint64_t host_pc, uint64_t fault_addr );
extern int hb_jit_runtime_handle_signal_fault( ULONG_PTR pc, ULONG_PTR fault_addr, int signal,
                                               const void *host_context );
extern int hb_jit_runtime_handle_owned_sigill( ULONG_PTR pc, ULONG native_word,
                                               int native_word_valid,
                                               const void *host_context );

/***********************************************************************
 * signal context platform-specific definitions
 */
#ifdef linux

/* All Registers access - only for local access */
# define REG_sig(reg_name, context) ((context)->uc_mcontext.reg_name)
# define REGn_sig(reg_num, context) ((context)->uc_mcontext.regs[reg_num])

/* Special Registers access  */
# define SP_sig(context)            REG_sig(sp, context)    /* Stack pointer */
# define PC_sig(context)            REG_sig(pc, context)    /* Program counter */
# define PSTATE_sig(context)        REG_sig(pstate, context) /* Current State Register */
# define FP_sig(context)            REGn_sig(29, context)    /* Frame pointer */
# define LR_sig(context)            REGn_sig(30, context)    /* Link Register */

static struct _aarch64_ctx *get_extended_sigcontext( const ucontext_t *sigcontext, unsigned int magic )
{
    struct _aarch64_ctx *ctx = (struct _aarch64_ctx *)sigcontext->uc_mcontext.__reserved;
    while ((char *)ctx < (char *)(&sigcontext->uc_mcontext + 1) && ctx->magic && ctx->size)
    {
        if (ctx->magic == magic) return ctx;
        ctx = (struct _aarch64_ctx *)((char *)ctx + ctx->size);
    }
    return NULL;
}

static struct fpsimd_context *get_fpsimd_context( const ucontext_t *sigcontext )
{
    return (struct fpsimd_context *)get_extended_sigcontext( sigcontext, FPSIMD_MAGIC );
}

static DWORD64 get_fault_esr( ucontext_t *sigcontext )
{
    struct esr_context *esr = (struct esr_context *)get_extended_sigcontext( sigcontext, ESR_MAGIC );
    if (esr) return esr->esr;
    return 0;
}

#elif defined(__APPLE__)

/* All Registers access - only for local access */
# define REG_sig(reg_name, context) ((context)->uc_mcontext->__ss.__ ## reg_name)
# define REGn_sig(reg_num, context) ((context)->uc_mcontext->__ss.__x[reg_num])

/* Special Registers access  */
# define SP_sig(context)            REG_sig(sp, context)    /* Stack pointer */
# define PC_sig(context)            REG_sig(pc, context)    /* Program counter */
# define PSTATE_sig(context)        REG_sig(cpsr, context)  /* Current State Register */
# define FP_sig(context)            REG_sig(fp, context)    /* Frame pointer */
# define LR_sig(context)            REG_sig(lr, context)    /* Link Register */

static DWORD64 get_fault_esr( ucontext_t *sigcontext )
{
    return sigcontext->uc_mcontext->__es.__esr;
}

#endif /* linux */

#define MACRUNNER_ARM64_CPSR_TRAP 0x00200000u

/* stack layout when calling KiUserExceptionDispatcher */
struct exc_stack_layout
{
    CONTEXT              context;        /* 000 */
    CONTEXT_EX           context_ex;     /* 390 */
    EXCEPTION_RECORD     rec;            /* 3b0 */
    ULONG64              align;          /* 448 */
    ULONG64              sp;             /* 450 */
    ULONG64              pc;             /* 458 */
    ULONG64              redzone[2];     /* 460 */
};
C_ASSERT( offsetof(struct exc_stack_layout, rec) == 0x3b0 );
C_ASSERT( sizeof(struct exc_stack_layout) == 0x470 );

/* stack layout when calling KiUserApcDispatcher */
struct apc_stack_layout
{
    void                *func;           /* 000 APC to call*/
    ULONG64              args[3];        /* 008 function arguments */
    ULONG64              alertable;      /* 020 */
    ULONG64              align;          /* 028 */
    CONTEXT              context;        /* 030 */
    ULONG64              redzone[2];     /* 3c0 */
};
C_ASSERT( offsetof(struct apc_stack_layout, context) == 0x30 );
C_ASSERT( sizeof(struct apc_stack_layout) == 0x3d0 );

/* stack layout when calling KiUserCallbackDispatcher */
struct callback_stack_layout
{
    void                *args;           /* 000 arguments */
    ULONG                len;            /* 008 arguments len */
    ULONG                id;             /* 00c function id */
    ULONG64              unknown;        /* 010 */
    ULONG64              lr;             /* 018 */
    ULONG64              sp;             /* 020 sp+pc (machine frame) */
    ULONG64              pc;             /* 028 */
    BYTE                 args_data[0];   /* 030 copied argument data*/
};
C_ASSERT( offsetof(struct callback_stack_layout, sp) == 0x20 );
C_ASSERT( sizeof(struct callback_stack_layout) == 0x30 );

struct syscall_frame
{
    ULONG64               x[29];          /* 000 */
    ULONG64               fp;             /* 0e8 */
    ULONG64               lr;             /* 0f0 */
    ULONG64               sp;             /* 0f8 */
    ULONG64               pc;             /* 100 */
    ULONG                 cpsr;           /* 108 */
    ULONG                 restore_flags;  /* 10c */
    struct syscall_frame *prev_frame;     /* 110 */
    void                 *syscall_cfa;    /* 118 */
    ULONG                 syscall_id;     /* 120 */
    ULONG                 align;          /* 124 */
    ULONG                 fpcr;           /* 128 */
    ULONG                 fpsr;           /* 12c */
    NEON128               v[32];          /* 130 */
};

C_ASSERT( sizeof( struct syscall_frame ) == 0x330 );


/* MacRunner 04.09.2026 — перенесено из Wine 11.14 (dlls/ntdll/unix/signal_arm64.c:201-213);
 * у нас дерево 11.0, где разбор ESR был написан голыми числами по месту.
 *
 * ЧТО ЧИНИТ: род отказа (чтение / запись / выполнение) определялся двумя выражениями,
 * из которых второе неверно в принципе. Бит WnR — это бит 6 поля ISS, и он ЗНАЧИТ
 * «запись» ТОЛЬКО у отказов доступа к данным (EC 0x24/0x25). У любого другого класса
 * исключения бит 6 несёт другой смысл, а проверка `esr & 0x40` смотрела на него всегда —
 * то есть отказ, который записью не был, мог уехать в кадр как EXCEPTION_WRITE_FAULT.
 * Правильный порядок: сперва класс исключения (EC, биты 31:26), и лишь внутри отказа
 * доступа к данным — WnR и код DFSC.
 *
 * Почему это важно ИМЕННО НАМ: на macOS get_fault_esr() возвращает настоящий ESR
 * (uc_mcontext->__es.__esr, см. выше), поэтому разбор здесь работает, в отличие от Linux,
 * где регистр в сигнальном контексте может вовсе отсутствовать. Род отказа мы читаем
 * дальше по коду (rec.ExceptionInformation[0]) при выборе стека и при решении, лечить ли
 * страницу; ошибка в нём — это ошибка лечения.
 *
 * DFSC=0x21 — выделенный код «отказ выравнивания», отличный от диапазона отказов прав
 * 0x0d-0x0f; у нас он уже использовался в bus_handler числом, теперь у него есть имя. */
#define ESR_ELx_EC(esr)                 (((DWORD64)(esr) >> 26) & 0x3f)
#define ESR_ELx_EC_IABT_LOW             0x20
#define ESR_ELx_EC_IABT_CUR             0x21
#define ESR_ELx_EC_PC_ALIGN             0x22
#define ESR_ELx_EC_DABT_LOW             0x24
#define ESR_ELx_EC_DABT_CUR             0x25
#define ESR_ELx_EC_SOFTSTP_LOW          0x32
#define ESR_ELx_EC_SOFTSTP_CUR          0x33
#define ESR_ELx_EC_BRK64                0x3c
#define ESR_ELx_ISS_DABT_WNR(esr)       (((esr) >> 6) & 0x01)
#define ESR_ELx_ISS_BRK_COMMENT(esr)    ((esr) & 0xffff)
#define ESR_ELx_ISS_DFSC(esr)           ((esr) & 0x3f)
#define ESR_ELx_ISS_DFSC_ALIGN_FAULT    0x21

/* MacRunner 04.09.2026: род отказа по ESR, порядок разбора взят из Wine 11.14
 * (segv_handler, dlls/ntdll/unix/signal_arm64.c:1116-1140). Вынесено в общую функцию,
 * потому что у нас разбор нужен ДВАЖДЫ — в segv_handler и в bus_handler; в 11.0 он был
 * скопирован в оба места числами, и это ровно тот случай, когда одна правка чинит одно
 * место из двух. Возвращает EXCEPTION_{READ,WRITE,EXECUTE}_FAULT. */
static ULONG_PTR macrunner_fault_access_kind( DWORD64 esr )
{
    switch (ESR_ELx_EC(esr))
    {
    case ESR_ELx_EC_IABT_LOW:
    case ESR_ELx_EC_IABT_CUR:
    case ESR_ELx_EC_PC_ALIGN:
        return EXCEPTION_EXECUTE_FAULT;
    case ESR_ELx_EC_DABT_LOW:
    case ESR_ELx_EC_DABT_CUR:
        return ESR_ELx_ISS_DABT_WNR(esr) ? EXCEPTION_WRITE_FAULT : EXCEPTION_READ_FAULT;
    default:
        return EXCEPTION_READ_FAULT;
    }
}


/***********************************************************************
 *           context_init_empty_xstate
 *
 * Initializes a context's CONTEXT_EX structure to point to an empty xstate buffer
 */
static inline void context_init_empty_xstate( CONTEXT *context, void *xstate_buffer )
{
    CONTEXT_EX *xctx;

    xctx = (CONTEXT_EX *)(context + 1);
    xctx->Legacy.Length = sizeof(CONTEXT);
    xctx->Legacy.Offset = -(LONG)sizeof(CONTEXT);
    xctx->XState.Length = 0;
    xctx->XState.Offset = (BYTE *)xstate_buffer - (BYTE *)xctx;
    xctx->All.Length = sizeof(CONTEXT) + xctx->XState.Offset + xctx->XState.Length;
    xctx->All.Offset = -(LONG)sizeof(CONTEXT);
}

void set_process_instrumentation_callback( void *callback )
{
    if (callback) FIXME( "Not supported.\n" );
}


/***********************************************************************
 *           syscall_frame_fixup_for_fastpath
 *
 * Fixes up the given syscall frame such that the syscall dispatcher
 * can return via the fast path if CONTEXT_INTEGER is set in
 * restore_flags.
 *
 * Clobbers the frame's X16 and X17 register values.
 */
static void syscall_frame_fixup_for_fastpath( struct syscall_frame *frame )
{
    frame->x[16] = frame->pc;
    frame->x[17] = frame->sp;
}

/***********************************************************************
 *           save_fpu
 *
 * Set the FPU context from a sigcontext.
 */
static void save_fpu( CONTEXT *context, const ucontext_t *sigcontext )
{
#ifdef linux
    struct fpsimd_context *fp = get_fpsimd_context( sigcontext );

    if (!fp) return;
    context->ContextFlags |= CONTEXT_FLOATING_POINT;
    context->Fpcr = fp->fpcr;
    context->Fpsr = fp->fpsr;
    memcpy( context->V, fp->vregs, sizeof(context->V) );
#elif defined(__APPLE__)
    context->ContextFlags |= CONTEXT_FLOATING_POINT;
    context->Fpcr = sigcontext->uc_mcontext->__ns.__fpcr;
    context->Fpsr = sigcontext->uc_mcontext->__ns.__fpsr;
    memcpy( context->V, sigcontext->uc_mcontext->__ns.__v, sizeof(context->V) );
#endif
}


/***********************************************************************
 *           restore_fpu
 *
 * Restore the FPU context to a sigcontext.
 */
static void restore_fpu( const CONTEXT *context, ucontext_t *sigcontext )
{
#ifdef linux
    struct fpsimd_context *fp = get_fpsimd_context( sigcontext );

    if (!fp) return;
    fp->fpcr = context->Fpcr;
    fp->fpsr = context->Fpsr;
    memcpy( fp->vregs, context->V, sizeof(fp->vregs) );
#elif defined(__APPLE__)
    sigcontext->uc_mcontext->__ns.__fpcr = context->Fpcr;
    sigcontext->uc_mcontext->__ns.__fpsr = context->Fpsr;
    memcpy( sigcontext->uc_mcontext->__ns.__v, context->V, sizeof(context->V) );
#endif
}


/***********************************************************************
 *           save_context
 *
 * Set the register values from a sigcontext.
 */
static void save_context( CONTEXT *context, const ucontext_t *sigcontext )
{
    DWORD i;

    context->ContextFlags = CONTEXT_FULL | CONTEXT_ARM64_X18;
    context->Fp   = FP_sig(sigcontext);     /* Frame pointer */
    context->Lr   = LR_sig(sigcontext);     /* Link register */
    context->Sp   = SP_sig(sigcontext);     /* Stack pointer */
    context->Pc   = PC_sig(sigcontext);     /* Program Counter */
    context->Cpsr = PSTATE_sig(sigcontext); /* Current State Register */
    for (i = 0; i <= 28; i++) context->X[i] = REGn_sig( i, sigcontext );
    save_fpu( context, sigcontext );
}


/***********************************************************************
 *           restore_context
 *
 * Build a sigcontext from the register values.
 */
static void restore_context( const CONTEXT *context, ucontext_t *sigcontext )
{
    DWORD i;

    FP_sig(sigcontext)     = context->Fp;   /* Frame pointer */
    LR_sig(sigcontext)     = context->Lr;   /* Link register */
    SP_sig(sigcontext)     = context->Sp;   /* Stack pointer */
    PC_sig(sigcontext)     = context->Pc;   /* Program Counter */
    PSTATE_sig(sigcontext) = context->Cpsr; /* Current State Register */
    for (i = 0; i <= 28; i++) REGn_sig( i, sigcontext ) = context->X[i];
    restore_fpu( context, sigcontext );
}


/***********************************************************************
 *           signal_set_full_context
 */
/* Счётчики трёх мест, которые пишут ОДНО ТОЛЬКО frame->sp. Замер показал: у нас меняется
 * sp, а lr нет — значит писала не пара lr+sp (диспетчеры), а одиночная правка поля. */
/* ПОТОКОВЫЕ. Первая редакция была обычной глобальной — тогда +1 мог прийти с ЧУЖОГО
 * потока, и вывод «на нашем потоке звали установку контекста» был бы необоснован.
 * Ровно та ошибка, что стоила сегодня дня в других местах. */
static __thread unsigned int mr_pisal_apc, mr_pisal_isk, mr_pisal_emul, mr_pisal_setctx;
/* Последнее применение контекста на ЭТОМ потоке: кто позвал и что подменил.
 * Без адреса вызывающего лечить нечего — надо знать, ОТКУДА берётся устаревший Sp. */
static __thread ULONG64 mr_ctx_zval, mr_ctx_bylo_sp, mr_ctx_stalo_sp, mr_ctx_flags;
static __thread ULONG64 mr_usr1_snyal_sp, mr_usr1_posle_sp, mr_usr1_ramka_sp;
static __thread unsigned int mr_usr1_n, mr_usr1_do_vhod, mr_usr1_posle_vhod;
static __thread BOOL macrunner_fex_suspend_pending;
#if defined(__APPLE__)
static void macrunner_signal_writef( const char *format, ... );
#endif
static __thread ULONG64 mr_usr1_do_sp, mr_usr1_pered_sp;

NTSTATUS signal_set_full_context( CONTEXT *context )
{
    struct syscall_frame *frame = get_syscall_frame();
    CHPE_V2_CPU_AREA_INFO *cpu_area = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    NTSTATUS status;

    /* Wine 11.14 cooperative suspend: acknowledge only after the emulator has
     * left simulation/callback code and released its internal locks. */
    if (macrunner_fex_suspend_pending && cpu_area && cpu_area->SuspendDoorbell &&
        !cpu_area->InSyscallCallback && !cpu_area->InSimulation)
    {
        sigset_t old_set;
#if defined(__APPLE__)
        static unsigned int acknowledged;
        unsigned int n = __atomic_add_fetch( &acknowledged, 1, __ATOMIC_RELAXED );
#endif
        pthread_sigmask( SIG_BLOCK, &server_block_set, &old_set );
        *cpu_area->SuspendDoorbell = 0;
        macrunner_fex_suspend_pending = FALSE;
#if defined(__APPLE__)
        if (n <= 32)
            macrunner_signal_writef( "mr-cooperative-ack: n=%u tid=%lx pc=%p\n",
                n, (unsigned long)NtCurrentTeb()->ClientId.UniqueThread, (void *)(ULONG_PTR)context->Pc );
#endif
        wait_suspend( context );
        status = NtSetContextThread( GetCurrentThread(), context );
        pthread_sigmask( SIG_SETMASK, &old_set, NULL );
    }
    else status = NtSetContextThread( GetCurrentThread(), context );

    if (!status && (context->ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER)
        frame->restore_flags |= CONTEXT_INTEGER;

    /* ★ СТЕНА64 08.09.2026 — ЗОНД ВОЗОБНОВЛЕНИЯ.
     *
     * Замер прибором внутри FEX доказал: `NtContinueNative` получает ВЕРНЫЙ x17
     * (= state_callret_sp, внутри стека возвратов), а на следующем отказе x17 равен
     * ровно тому PC, на который возобновлялись. Значит x17 теряет ВОЗОБНОВЛЕНИЕ, и
     * первый подозреваемый — отвод на KiUserEmulationDispatcher ниже: возврат идёт не
     * прямо на PC гостя, а через вход эмулятора, где x17 — регистр входа, а не
     * callret_sp. Печать безусловная, первые 8 раз: без неё «отвод сработал» остаётся
     * предположением. */
    {
        static __thread unsigned int mr_st64_n;
        BOOL ec  = is_arm64ec();
        BOOL ecc = ec ? is_ec_code( frame->pc ) : FALSE;
        if (++mr_st64_n <= 8)
        {
            fprintf( stderr, "macrunner-st64-resume: n=%u arm64ec=%d ec_code(pc)=%d emul_disp=%d"
                     " frame_pc=%#llx frame_sp=%#llx frame_x16=%#llx frame_x17=%#llx"
                     " ctx_pc=%#llx ctx_x17=%#llx отвод=%d\n",
                     mr_st64_n, (int)ec, (int)ecc, pKiUserEmulationDispatcher ? 1 : 0,
                     (unsigned long long)frame->pc, (unsigned long long)frame->sp,
                     (unsigned long long)frame->x[16], (unsigned long long)frame->x[17],
                     (unsigned long long)context->Pc, (unsigned long long)context->X[17],
                     (ec && !ecc && pKiUserEmulationDispatcher) ? 1 : 0 );
            fflush( stderr );
        }
    }

    if (is_arm64ec() && !is_ec_code( frame->pc ) && pKiUserEmulationDispatcher )
    {
        CONTEXT *user_context = (CONTEXT *)((frame->sp - sizeof(CONTEXT)) & ~15);

        user_context->ContextFlags = CONTEXT_FULL;
        NtGetContextThread( GetCurrentThread(), user_context );
        frame->sp = (ULONG_PTR)user_context;
        frame->pc = (ULONG_PTR)pKiUserEmulationDispatcher;
        mr_pisal_emul++;   /* кто переписал frame->sp — счётчик для кольца */
    }
    return status;
}


/***********************************************************************
 *              get_native_context
 */
void *get_native_context( CONTEXT *context )
{
    return context;
}


/***********************************************************************
 *              get_wow_context
 */
void *get_wow_context( CONTEXT *context )
{
    return get_cpu_area( main_image_info.Machine );
}


/***********************************************************************
 *              NtSetContextThread  (NTDLL.@)
 *              ZwSetContextThread  (NTDLL.@)
 */
NTSTATUS WINAPI NtSetContextThread( HANDLE handle, const CONTEXT *context )
{
    struct syscall_frame *frame = get_syscall_frame();
    NTSTATUS ret = STATUS_SUCCESS;
    BOOL self = (handle == GetCurrentThread());
    const AMD64_CONTEXT *amd64_context = (const AMD64_CONTEXT *)context;
    DWORD arm64_flags = context->ContextFlags;
    DWORD amd64_flags = amd64_context->ContextFlags;
    DWORD flags = arm64_flags & ~CONTEXT_ARM64;

    if ((amd64_flags & CONTEXT_AMD64) && !(arm64_flags & CONTEXT_ARM64))
        return macrunner_hb_set_x64_thread_context( handle, (const AMD64_CONTEXT *)context );

    if (self && (flags & CONTEXT_DEBUG_REGISTERS)) self = FALSE;

    if (!self)
    {
        ret = set_thread_context( handle, context, &self, IMAGE_FILE_MACHINE_ARM64 );
        if (ret || !self) return ret;
    }

    if (flags & CONTEXT_INTEGER)
    {
        memcpy( frame->x, context->X, sizeof(context->X[0]) * 18 );
        /* skip x18 */
        memcpy( frame->x + 19, context->X + 19, sizeof(context->X[0]) * 10 );
    }
    if (flags & CONTEXT_CONTROL)
    {
        frame->fp    = context->Fp;
        frame->lr    = context->Lr;
        mr_ctx_zval     = (ULONG64)(ULONG_PTR)__builtin_return_address(0);
        mr_ctx_bylo_sp  = (ULONG64)frame->sp;
        mr_ctx_stalo_sp = (ULONG64)context->Sp;
        mr_ctx_flags    = (ULONG64)flags;
        frame->sp    = context->Sp;
        mr_pisal_setctx++;   /* NtSetContextThread переписал sp — счётчик для кольца */
        frame->pc    = context->Pc;
        frame->cpsr  = context->Cpsr;
    }
    if (flags & CONTEXT_FLOATING_POINT)
    {
        frame->fpcr = context->Fpcr;
        frame->fpsr = context->Fpsr;
        memcpy( frame->v, context->V, sizeof(frame->v) );
    }
    if (flags & CONTEXT_ARM64_X18)
    {
        frame->x[18] = context->X[18];
    }
    if (flags & CONTEXT_DEBUG_REGISTERS) FIXME( "debug registers not supported\n" );
    frame->restore_flags |= flags & ~CONTEXT_INTEGER;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              NtGetContextThread  (NTDLL.@)
 *              ZwGetContextThread  (NTDLL.@)
 */
NTSTATUS WINAPI NtGetContextThread( HANDLE handle, CONTEXT *context )
{
    struct syscall_frame *frame = get_syscall_frame();
    DWORD needed_flags = context->ContextFlags & ~CONTEXT_ARM64;
    BOOL self = (handle == GetCurrentThread());

    /* ★★★★★★★ КОРЕНЬ СТЕНЫ, 01.09.2026 — ПОЛОВИНА УСЛОВИЯ БЫЛА ПОТЕРЯНА.
     *
     * У ARM64 `CONTEXT.ContextFlags` лежит по смещению 0x000, у `AMD64_CONTEXT` — по 0x030.
     * Вызывающий из `usr1_handler` задаёт ТОЛЬКО ARM64-поле (`CONTEXT context;` в остальном
     * не инициализирована), поэтому проверка по 0x030 читала МУСОР СО СТЕКА. Когда в мусоре
     * случайно оказывался бит CONTEXT_AMD64, снимок брался из слепка x64-эмуляции — и
     * возвращал устаревший `Sp`. Дальше `NtSetContextThread` применял его обратно,
     * `frame->sp` откатывался на позицию прошлого вызова, диспетчер возвращал гостя на
     * мёртвый кадр, и `ret` в эпилоге `kernelbase!WaitForSingleObject` уходил в данные —
     * `esr=0x8200000f`. Отсюда же и «отказ зависит от раскладки кода»: от неё зависит,
     * какой мусор лежит в этом месте стека.
     *
     * У парной `NtSetContextThread` защита УЖЕ БЫЛА и написана верно:
     *     if ((amd64_flags & CONTEXT_AMD64) && !(arm64_flags & CONTEXT_ARM64))
     * Здесь потеряли вторую половину. Восстанавливаем симметрию — это и есть лечение
     * причины, а не следствия.
     *
     * Гейт снят 02.09.2026: это восстановление ПОТЕРЯННОЙ ПОЛОВИНЫ УСЛОВИЯ —
     * у парной NtSetContextThread проверка есть, у Get её забыли, отчего читался
     * мусор со стека (корень «стены», замер 4/4 -> 0/10). Выключенная ветка
     * возвращает ровно тот дефект, поэтому выключателя у неё быть не должно. */
    if (context->ContextFlags & CONTEXT_ARM64) goto arm64_put;
    if (((AMD64_CONTEXT *)context)->ContextFlags & CONTEXT_AMD64)
    {
        NTSTATUS ret = macrunner_hb_get_x64_thread_context( handle, (AMD64_CONTEXT *)context );
        if (!ret)
            set_context_exception_reporting_flags( &((AMD64_CONTEXT *)context)->ContextFlags,
                                                   CONTEXT_SERVICE_ACTIVE );
        return ret;
    }

arm64_put:
    if (!self)
    {
        NTSTATUS ret = get_thread_context( handle, context, &self, IMAGE_FILE_MACHINE_ARM64 );
        if (ret || !self) return ret;
    }

    if (needed_flags & CONTEXT_INTEGER)
    {
        /* MacRunner 04.09.2026 — ПЕРЕНОС ИЗ АПСТРИМА (wine 4423e8ed9aa3,
         * 17.08.2026), «Fix CONTEXT_ARM64_X18 handling when setting another
         * thread's context».
         *
         * X18 НЕ входит в CONTEXT_INTEGER: у него свой признак
         * CONTEXT_ARM64_X18, потому что это регистр платформы. Путь ЗАПИСИ у
         * нас это уже знал (копирует 18 и отдельно разбирает признак), а путь
         * ЧТЕНИЯ копировал все 29 подряд и затирал X18 значением кадра.
         *
         * Для нас цена выше, чем для апстрима: на macOS x18 ЗАРЕЗЕРВИРОВАН
         * Apple, и отдать его наружу как обычный регистр — прямой путь к
         * порче состояния. */
        memcpy( context->X, frame->x, sizeof(context->X[0]) * 18 );
        /* x18 пропускаем — он идёт своим признаком ниже */
        memcpy( context->X + 19, frame->x + 19, sizeof(context->X[0]) * 10 );
        context->ContextFlags |= CONTEXT_INTEGER;
    }
    if (needed_flags & CONTEXT_ARM64_X18)
    {
        context->X[18] = frame->x[18];
        context->ContextFlags |= CONTEXT_ARM64_X18;
    }
    if (needed_flags & CONTEXT_CONTROL)
    {
        context->Fp   = frame->fp;
        context->Lr   = frame->lr;
        context->Sp   = frame->sp;
        context->Pc   = frame->pc;
        context->Cpsr = frame->cpsr;
        context->ContextFlags |= CONTEXT_CONTROL;
    }
    if (needed_flags & CONTEXT_FLOATING_POINT)
    {
        context->Fpcr = frame->fpcr;
        context->Fpsr = frame->fpsr;
        memcpy( context->V, frame->v, sizeof(context->V) );
        context->ContextFlags |= CONTEXT_FLOATING_POINT;
    }
    if (needed_flags & CONTEXT_DEBUG_REGISTERS) FIXME( "debug registers not supported\n" );
    set_context_exception_reporting_flags( &context->ContextFlags, CONTEXT_SERVICE_ACTIVE );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              set_thread_wow64_context
 */
NTSTATUS set_thread_wow64_context( HANDLE handle, const void *ctx, ULONG size )
{
    BOOL self = (handle == GetCurrentThread());
    USHORT machine;
    void *frame;

    switch (size)
    {
    case sizeof(I386_CONTEXT): machine = IMAGE_FILE_MACHINE_I386; break;
    case sizeof(ARM_CONTEXT): machine = IMAGE_FILE_MACHINE_ARMNT; break;
    default: return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (!self)
    {
        NTSTATUS ret = set_thread_context( handle, ctx, &self, machine );
        if (ret || !self) return ret;
    }

    if (!(frame = get_cpu_area( machine ))) return STATUS_INVALID_PARAMETER;

    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:
    {
        I386_CONTEXT *wow_frame = frame;
        const I386_CONTEXT *context = ctx;
        DWORD flags = context->ContextFlags & ~CONTEXT_i386;

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
            WOW64_CPURESERVED *cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPURESERVED];

            wow_frame->Esp    = context->Esp;
            wow_frame->Ebp    = context->Ebp;
            wow_frame->Eip    = context->Eip;
            wow_frame->EFlags = context->EFlags;
            wow_frame->SegCs  = context->SegCs;
            wow_frame->SegSs  = context->SegSs;
            cpu->Flags |= WOW64_CPURESERVED_FLAG_RESET_STATE;
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
        {
            memcpy( &wow_frame->ExtendedRegisters, context->ExtendedRegisters, sizeof(context->ExtendedRegisters) );
        }
        if (flags & CONTEXT_I386_FLOATING_POINT)
        {
            memcpy( &wow_frame->FloatSave, &context->FloatSave, sizeof(context->FloatSave) );
        }
        /* FIXME: CONTEXT_I386_XSTATE */
        break;
    }

    case IMAGE_FILE_MACHINE_ARMNT:
    {
        ARM_CONTEXT *wow_frame = frame;
        const ARM_CONTEXT *context = ctx;
        DWORD flags = context->ContextFlags & ~CONTEXT_ARM;

        if (flags & CONTEXT_INTEGER)
        {
            wow_frame->R0  = context->R0;
            wow_frame->R1  = context->R1;
            wow_frame->R2  = context->R2;
            wow_frame->R3  = context->R3;
            wow_frame->R4  = context->R4;
            wow_frame->R5  = context->R5;
            wow_frame->R6  = context->R6;
            wow_frame->R7  = context->R7;
            wow_frame->R8  = context->R8;
            wow_frame->R9  = context->R9;
            wow_frame->R10 = context->R10;
            wow_frame->R11 = context->R11;
            wow_frame->R12 = context->R12;
        }
        if (flags & CONTEXT_CONTROL)
        {
            wow_frame->Sp = context->Sp;
            wow_frame->Lr = context->Lr;
            wow_frame->Pc = context->Pc & ~1;
            wow_frame->Cpsr = context->Cpsr;
            if (context->Cpsr & 0x20) wow_frame->Pc |= 1; /* thumb */
        }
        if (flags & CONTEXT_FLOATING_POINT)
        {
            wow_frame->Fpscr = context->Fpscr;
            memcpy( wow_frame->D, context->D, sizeof(context->D) );
        }
        break;
    }

    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              get_thread_wow64_context
 */
NTSTATUS get_thread_wow64_context( HANDLE handle, void *ctx, ULONG size )
{
    BOOL self = (handle == GetCurrentThread());
    USHORT machine;
    void *frame;

    switch (size)
    {
    case sizeof(I386_CONTEXT): machine = IMAGE_FILE_MACHINE_I386; break;
    case sizeof(ARM_CONTEXT): machine = IMAGE_FILE_MACHINE_ARMNT; break;
    default: return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (!self)
    {
        NTSTATUS ret = get_thread_context( handle, ctx, &self, machine );
        if (ret || !self) return ret;
    }

    if (!(frame = get_cpu_area( machine ))) return STATUS_INVALID_PARAMETER;

    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:
    {
        I386_CONTEXT *wow_frame = frame, *context = ctx;
        DWORD needed_flags = context->ContextFlags & ~CONTEXT_i386;

        if (needed_flags & CONTEXT_I386_INTEGER)
        {
            context->Eax = wow_frame->Eax;
            context->Ebx = wow_frame->Ebx;
            context->Ecx = wow_frame->Ecx;
            context->Edx = wow_frame->Edx;
            context->Esi = wow_frame->Esi;
            context->Edi = wow_frame->Edi;
            context->ContextFlags |= CONTEXT_I386_INTEGER;
        }
        if (needed_flags & CONTEXT_I386_CONTROL)
        {
            context->Esp    = wow_frame->Esp;
            context->Ebp    = wow_frame->Ebp;
            context->Eip    = wow_frame->Eip;
            context->EFlags = wow_frame->EFlags;
            context->SegCs  = wow_frame->SegCs;
            context->SegSs  = wow_frame->SegSs;
            context->ContextFlags |= CONTEXT_I386_CONTROL;
        }
        if (needed_flags & CONTEXT_I386_SEGMENTS)
        {
            context->SegDs = wow_frame->SegDs;
            context->SegEs = wow_frame->SegEs;
            context->SegFs = wow_frame->SegFs;
            context->SegGs = wow_frame->SegGs;
            context->ContextFlags |= CONTEXT_I386_SEGMENTS;
        }
        if (needed_flags & CONTEXT_I386_EXTENDED_REGISTERS)
        {
            memcpy( context->ExtendedRegisters, &wow_frame->ExtendedRegisters, sizeof(context->ExtendedRegisters) );
            context->ContextFlags |= CONTEXT_I386_EXTENDED_REGISTERS;
        }
        if (needed_flags & CONTEXT_I386_FLOATING_POINT)
        {
            memcpy( &context->FloatSave, &wow_frame->FloatSave, sizeof(context->FloatSave) );
            context->ContextFlags |= CONTEXT_I386_FLOATING_POINT;
        }
        if (needed_flags & CONTEXT_I386_DEBUG_REGISTERS)
        {
            context->Dr0 = wow_frame->Dr0;
            context->Dr1 = wow_frame->Dr1;
            context->Dr2 = wow_frame->Dr2;
            context->Dr3 = wow_frame->Dr3;
            context->Dr6 = wow_frame->Dr6;
            context->Dr7 = wow_frame->Dr7;
        }
        /* FIXME: CONTEXT_I386_XSTATE */
        set_context_exception_reporting_flags( &context->ContextFlags, CONTEXT_SERVICE_ACTIVE );
        break;
    }

    case IMAGE_FILE_MACHINE_ARMNT:
    {
        ARM_CONTEXT *wow_frame = frame, *context = ctx;
        DWORD needed_flags = context->ContextFlags & ~CONTEXT_ARM;

        if (needed_flags & CONTEXT_INTEGER)
        {
            context->R0  = wow_frame->R0;
            context->R1  = wow_frame->R1;
            context->R2  = wow_frame->R2;
            context->R3  = wow_frame->R3;
            context->R4  = wow_frame->R4;
            context->R5  = wow_frame->R5;
            context->R6  = wow_frame->R6;
            context->R7  = wow_frame->R7;
            context->R8  = wow_frame->R8;
            context->R9  = wow_frame->R9;
            context->R10 = wow_frame->R10;
            context->R11 = wow_frame->R11;
            context->R12 = wow_frame->R12;
            context->ContextFlags |= CONTEXT_INTEGER;
        }
        if (needed_flags & CONTEXT_CONTROL)
        {
            context->Sp   = wow_frame->Sp;
            context->Lr   = wow_frame->Lr;
            context->Pc   = wow_frame->Pc;
            context->Cpsr = wow_frame->Cpsr;
            context->ContextFlags |= CONTEXT_CONTROL;
        }
        if (needed_flags & CONTEXT_FLOATING_POINT)
        {
            context->Fpscr = wow_frame->Fpscr;
            memcpy( context->D, wow_frame->D, sizeof(wow_frame->D) );
            context->ContextFlags |= CONTEXT_FLOATING_POINT;
        }
        set_context_exception_reporting_flags( &context->ContextFlags, CONTEXT_SERVICE_ACTIVE );
        break;
    }

    }
    return STATUS_SUCCESS;
}


#if defined(__APPLE__)
/* macOS arm64 reserves x18 for kernel scratch and clears it on sigreturn.
 * Windows arm64 ABI uses x18 = TEB, so PE code reads TEB-relative fields
 * via x18 and crashes on first access if x18 is zero. We trampoline
 * through this stub: the kernel restores x10/x16 from sigcontext like
 * any other GP reg, the stub runs in user mode AFTER sigreturn, copies
 * TEB into x18 (kernel can no longer touch us), and branches to the
 * real PE entry. Used for "fresh" PE entries (KiUserExceptionDispatcher,
 * __wine_syscall_dispatcher_return) where x10/x16 don't carry caller
 * state. */
extern void __wine_pe_x18_thunk(void);
__ASM_GLOBAL_FUNC( __wine_pe_x18_thunk,
                   __ASM_CFI(".cfi_def_cfa 31,0\n\t")
                   __ASM_CFI(".cfi_same_value 30\n\t")
                   "mov x18, x10\n\t"  /* TEB */
                   "br  x16" )         /* real PE entry */

/* Resume thunk for the x18 self-heal path in segv_handler: PE code was
 * mid-function when xnu-induced x18=NULL faulted on a TEB-relative
 * deref. We must transparently retry the faulting instruction with x18
 * restored AND with x10/x16 untouched relative to PE's expectations.
 * segv_handler stashes the original x10/x16 and the retry PC into the
 * three apple_x18_save_* fields of ntdll_thread_data (TEB-relative);
 * this stub reads them back and jumps. x17 is sacrificed as a branch
 * target — it's an intra-procedure scratch register, not preserved
 * across BLR/RET in either ABI, so the PE compiler never relies on it
 * holding meaningful state across instructions. */
extern void __wine_pe_x18_resume_thunk(void);
__ASM_GLOBAL_FUNC( __wine_pe_x18_resume_thunk,
                   __ASM_CFI(".cfi_def_cfa 31,0\n\t")
                   __ASM_CFI(".cfi_same_value 30\n\t")
                   "mov x18, x10\n\t"           /* x18 = TEB */
                   "ldr x10, [x18, #0x3d8]\n\t" /* TEB_APPLE_X18_SAVE_X10_OFFSET */
                   "ldr x16, [x18, #0x3e0]\n\t" /* TEB_APPLE_X18_SAVE_X16_OFFSET */
                   "ldr x17, [x18, #0x3e8]\n\t" /* TEB_APPLE_X18_SAVE_PC_OFFSET */
                   "br  x17" )

/* ★★★★★★ ШАГ-4 08.09.2026 — ТРАМПЛИН ПО НОМЕРУ РЕГИСТРА-ПРИЁМНИКА.
 *
 * ЗАЧЕМ. Трамплин выше приносит в жертву x17 и обосновывает это тем, что x17 —
 * внутрипроцедурный временный, в котором «компилятор PE не держит смысла между
 * командами». Для кода компилятора это верно, для РУКОПИСНОГО ассемблера — нет,
 * и это стоило нам двух стен подряд в одном прогоне:
 *
 *   стена 1  xtajit64.dll ExitToX64 (FEX Module.S:29-37):
 *              0x102f50  ldr  x17, [x18, #0x1788]
 *              0x102f58  strb w16, [x17]        <- писало в .text, x17 = адрес возврата
 *   стена 2  буфер JIT FEX 0x1131d0070 (после починки стены 1):
 *              лечение сработало на 0x100370124  ldr x10, [x18, #0x60]   (TEB->PEB)
 *              трамплин положил в x17 адрес 0x100370128, а дальше по ходу
 *              0x1131d0070  stp x7, x10, [x17, #-16]!   -> запись в страницу кода
 *
 * ★ РЕШЕНИЕ УРОВНЯ «СТАТЬИ РАСХОДА БОЛЬШЕ НЕТ». Ветвление на AArch64 обязано идти
 * ЧЕРЕЗ РЕГИСТР — команды «прыгнуть по памяти» в наборе нет, поэтому один регистр
 * пожертвовать ПРИДЁТСЯ (это ВНЕШНЕЕ ограничение набора команд, а не наша недоделка).
 * Но выбрать его можно так, чтобы он был МЁРТВ ПО ПОСТРОЕНИЮ: у ПОВТОРЯЕМОЙ
 * команды-ЗАГРУЗКИ регистр-приёмник Rt мёртв — она сама его и перепишет. Значит
 * трамплин должен ветвиться ЧЕРЕЗ Rt, а не через x17. Отсюда таблица вариантов.
 *
 * Тело общее для всех номеров: лишнее восстановление x10/x16 у вариантов r10/r16
 * тут же перекрывается адресом возврата, а он всё равно будет переписан повторяемой
 * загрузкой.
 *
 * ГРАНИЦЫ, названные прямо:
 *   Rt=18  — повтор `ldr x18,[x18,#off]` требует x18=TEB КАК БАЗЫ, через x18 же
 *            ветвиться нельзя; остаётся прежний трамплин (жертва x17);
 *   Rt=31  — xzr, приёмника нет; прежний трамплин;
 *   ЗАПИСЬ (`str Rt,[x18,#off]`) — Rt живой, мёртвого регистра не существует;
 *            прежний путь «эмулировать и пропустить», жертва x17 остаётся.
 * Оба остатка СЧИТАЮТСЯ и печатаются прибором macrunner-shag4-x18emul. */
#define MACRUNNER_X18_RESUME_THUNK(n)                                          \
    extern void __wine_pe_x18_resume_thunk_r##n(void);                         \
    __ASM_GLOBAL_FUNC( __wine_pe_x18_resume_thunk_r##n,                        \
                       __ASM_CFI(".cfi_def_cfa 31,0\n\t")                      \
                       __ASM_CFI(".cfi_same_value 30\n\t")                     \
                       "mov x18, x10\n\t"                                      \
                       "ldr x10, [x18, #0x3d8]\n\t"                            \
                       "ldr x16, [x18, #0x3e0]\n\t"                            \
                       "ldr x" #n ", [x18, #0x3e8]\n\t"                        \
                       "br  x" #n )

MACRUNNER_X18_RESUME_THUNK(0)
MACRUNNER_X18_RESUME_THUNK(1)
MACRUNNER_X18_RESUME_THUNK(2)
MACRUNNER_X18_RESUME_THUNK(3)
MACRUNNER_X18_RESUME_THUNK(4)
MACRUNNER_X18_RESUME_THUNK(5)
MACRUNNER_X18_RESUME_THUNK(6)
MACRUNNER_X18_RESUME_THUNK(7)
MACRUNNER_X18_RESUME_THUNK(8)
MACRUNNER_X18_RESUME_THUNK(9)
MACRUNNER_X18_RESUME_THUNK(10)
MACRUNNER_X18_RESUME_THUNK(11)
MACRUNNER_X18_RESUME_THUNK(12)
MACRUNNER_X18_RESUME_THUNK(13)
MACRUNNER_X18_RESUME_THUNK(14)
MACRUNNER_X18_RESUME_THUNK(15)
MACRUNNER_X18_RESUME_THUNK(16)
MACRUNNER_X18_RESUME_THUNK(19)
MACRUNNER_X18_RESUME_THUNK(20)
MACRUNNER_X18_RESUME_THUNK(21)
MACRUNNER_X18_RESUME_THUNK(22)
MACRUNNER_X18_RESUME_THUNK(23)
MACRUNNER_X18_RESUME_THUNK(24)
MACRUNNER_X18_RESUME_THUNK(25)
MACRUNNER_X18_RESUME_THUNK(26)
MACRUNNER_X18_RESUME_THUNK(27)
MACRUNNER_X18_RESUME_THUNK(28)
MACRUNNER_X18_RESUME_THUNK(29)
MACRUNNER_X18_RESUME_THUNK(30)

static void (* const apple_x18_resume_by_rt[32])(void) =
{
    __wine_pe_x18_resume_thunk_r0,  __wine_pe_x18_resume_thunk_r1,
    __wine_pe_x18_resume_thunk_r2,  __wine_pe_x18_resume_thunk_r3,
    __wine_pe_x18_resume_thunk_r4,  __wine_pe_x18_resume_thunk_r5,
    __wine_pe_x18_resume_thunk_r6,  __wine_pe_x18_resume_thunk_r7,
    __wine_pe_x18_resume_thunk_r8,  __wine_pe_x18_resume_thunk_r9,
    __wine_pe_x18_resume_thunk_r10, __wine_pe_x18_resume_thunk_r11,
    __wine_pe_x18_resume_thunk_r12, __wine_pe_x18_resume_thunk_r13,
    __wine_pe_x18_resume_thunk_r14, __wine_pe_x18_resume_thunk_r15,
    __wine_pe_x18_resume_thunk_r16, __wine_pe_x18_resume_thunk,      /* r17 == прежний */
    NULL,                           __wine_pe_x18_resume_thunk_r19,  /* r18 — нельзя */
    __wine_pe_x18_resume_thunk_r20, __wine_pe_x18_resume_thunk_r21,
    __wine_pe_x18_resume_thunk_r22, __wine_pe_x18_resume_thunk_r23,
    __wine_pe_x18_resume_thunk_r24, __wine_pe_x18_resume_thunk_r25,
    __wine_pe_x18_resume_thunk_r26, __wine_pe_x18_resume_thunk_r27,
    __wine_pe_x18_resume_thunk_r28, __wine_pe_x18_resume_thunk_r29,
    __wine_pe_x18_resume_thunk_r30, NULL                             /* r31 — xzr */
};

TEB *__wine_get_current_teb_for_x18(void)
{
    return NtCurrentTeb();
}

extern int macrunner_hb_pc_is_x64_guest_code( void *pc );
extern int macrunner_hb_pc_is_x64_guest_code_no_lock( void *pc );
extern int macrunner_hb_pc_is_x64_callback_target_no_lock( void *pc );
extern int macrunner_hb_pc_is_arm64x_native_no_lock( void *pc );
extern int macrunner_hb_pc_is_x64_guest_code_module_no_lock( void *pc );
/* Defined in macrunner_hb.c.  Nonzero while this thread is inside the signal handler; makes
 * HyperBridge's PE-header reads use the non-faulting probe.  See macrunner_hb_image_nt_header(). */
extern __thread int macrunner_hb_fault_header_probe_depth;
extern void *macrunner_hb_pe_module_from_pc_no_lock( void *pc );
extern int macrunner_hb_pc_is_pe_code_module_no_lock( void *pc );
extern ULONG64 macrunner_hb_normalize_x64_callback_pc( ULONG64 pc );
extern ULONG64 macrunner_hb_normalize_x64_tls_callback_pc( ULONG64 pc, ULONG64 image_base,
                                                           ULONG64 reason );
extern BOOL macrunner_hb_try_dispatch_x64_callback( ULONG64 target, const ULONG64 args[8],
                                                    ULONG64 *result );
extern void macrunner_hb_note_x64_guest_fault_handlers_ready(void);
/* MacRunner 2026-06-24 (HB-throughput direct-mem fast path): recover from a SIGSEGV/SIGBUS that
 * lands inside a gated direct guest-memory copy in special_read/write. siglongjmps back (does not
 * return) when the fault addr is inside the active copy's guest range; no-op otherwise. Must be
 * called at the TOP of the segv/bus handlers, before any lock. Async-signal-safe. */
extern void macrunner_hb_dmem_fault_recover( unsigned long long fault_addr );
/* MacRunner 2026-07-02: mprotect a PROT_NONE/PROT_READ page to RW when max_prot allows WRITE
 * (commit-on-fault for a reserved-but-committable or read-only-mapped guest page). Returns TRUE
 * if the page was upgraded and the faulting access should simply be retried by returning from
 * the signal handler. See macrunner_hb.c for the strict scope (never masks a genuine AV/OOB). */
extern BOOL macrunner_hb_try_commit_or_upgrade_page( unsigned long long addr );

/* Гейт «чтение не коммитит»: см. развёрнутый довод у места применения. */
extern void macrunner_hb_x64_callback_trampoline(void);
extern BOOL macrunner_hb_present_signal_probe_enabled_for_current_thread(void);
/* * lane FEX-N3 2026-09-07 -- semanticheskie obrabotchiki HyperBridge gasyatsya,
 * kogda translyator processa NE HyperBridge (MACRUNNER_CPU_BACKEND=fex|none).
 * Opredeleno v unix/loader.c: tam znachenie razbiraetsya ODIN raz, do iniciializacii CPU,
 * i tam zhe neizvestnoe znachenie peremennoj daet fatal_error, a ne tihij otkat na HB.
 * Do etoj iniciializacii funkciya vernet FALSE, to est prezhnee povedenie. */
extern BOOL macrunner_cpu_backend_disables_hb_semantics(void);
static BOOL macrunner_hb_x64_loader_enabled(void);
static BOOL macrunner_hb_trace_callback_route_enabled(void)
{
    /* Cached: this runs on the per-fault path (inlined into
     * macrunner_hb_route_x64_callback_fault), where macrunner_hb_getenv() is an O(n)
     * __findenv_locked scan.  Same idiom as
     * macrunner_hb_jit_sigill_ownership_enabled() below. */
    static int enabled = -1;

    if (enabled < 0)
    {
        const char *value = macrunner_hb_getenv( "MACRUNNER_HB_TRACE_CALLBACK_ROUTE" );
        enabled = value && value[0] && value[0] != '0';
    }
    return enabled != 0;
}

static BOOL macrunner_hb_jit_sigill_ownership_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        const char *value = macrunner_hb_getenv( "MACRUNNER_HB_JIT_SIGILL_OWNERSHIP" );
        enabled = value && value[0] && value[0] != '0';
        if (macrunner_cpu_backend_disables_hb_semantics()) enabled = 0;  /* lane FEX-N3 */
    }
    return enabled != 0;
}

static BOOL macrunner_hb_x64_fault_routing_enabled(void)
{
    if (macrunner_cpu_backend_disables_hb_semantics()) return FALSE;
    if (!macrunner_hb_x64_loader_enabled()) return FALSE;
    if (macrunner_hb_x64_guest_process()) return TRUE;

    /* PE32/WOW64 still executes the 64-bit Wine side through AMD64 guest
     * modules.  A native ARM64 ntdll thunk can therefore fault at a registered
     * x64 guest target even though the process main image is I386. */
    return is_wow64() && current_machine == IMAGE_FILE_MACHINE_ARM64 &&
           main_image_info.Machine == IMAGE_FILE_MACHINE_I386;
}

static BOOL macrunner_hb_trace_stack_setup_enabled(void)
{
    static int count;
    static int enabled = -1;

    /* Cached: the 64-sample budget below used to sit BEHIND the macrunner_hb_getenv(), so an
     * exhausted budget still paid a full environment scan on every call. */
    if (enabled < 0)
    {
        const char *value = macrunner_hb_getenv( "MACRUNNER_HB_TRACE_STACK_SETUP" );
        enabled = value && value[0] && value[0] != '0';
    }
    if (!enabled) return FALSE;
    return count++ < 64;
}

/* Both of these are consulted from inside signal/fault handlers (segv_handler,
 * bus_handler, macrunner_hb_primary_signal_handler, macrunner_hb_route_x64_callback_fault)
 * and were previously raw macrunner_hb_getenv() calls, i.e. an O(n) __findenv_locked scan on EVERY
 * fault.  run23 measured getenv at 22.1% of the faulting thread's wall time.  Caching also
 * shrinks the libc-recursion hazard noted above trace_apple_x18_heal(): the environment is
 * scanned at most once per knob instead of once per fault. */
static BOOL macrunner_hb_diag_faultvm_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) enabled = macrunner_hb_getenv( "MACRUNNER_DIAG_FAULTVM" ) ? 1 : 0;
    return enabled != 0;
}

/* ★★★ 07.09.2026, лейн ПРИБОРЫ-4 — ПРИБОРЫ ВОКРУГ ГЕЙТА, СТОИВШЕГО ДНЯ.
 *
 * CLAUDE.md, раздел «МАРКЕР-КРИТЕРИЙ ПРОВЕРЯТЬ GREP-ОМ ДО ПРОГОНА»: критерием ТРИЖДЫ
 * подряд назначался `macrunner-hb-nullcall-vtable`, три прогона по 900 с его ждали и не
 * дождались. Цена — день. Внешний агент повторил ту же ошибку независимо.
 *
 * Все три площадки этой семьи написаны одинаково и несут ОДИН И ТОТ ЖЕ дефект:
 *
 *     if (macrunner_hb_trace_nullcall_enabled() && nullcall_diag_count++ < 64)
 *                                              ^^ короткое замыкание
 *
 * счётчик стоит СПРАВА от `&&`, поэтому при закрытом гейте он не растёт ВОВСЕ. Это
 * ровно первый пункт списка врущих приборов в шапке hb_probe.h: «счётчик за коротким
 * замыканием — ноль значит до меня не дошло управление». В журнале молчание площадки
 * означало сразу три вещи: гейт закрыт (умолчание), потолок выбран, площадка не
 * достигнута — и различить их было нечем.
 *
 * Учёт разведён: гейт считает себя сам (looked = сколько раз спрашивали, hits = сколько
 * раз ответил «открыт»), каждая площадка считает СВОИ заходы отдельно. Значение гейта
 * кешируется в статике, поэтому опрос стоит одну загрузку. */
HB_PROBE_DEFINE(pr_nullcall_gate, "hb-nullcall-гейт",
                "опросы гейта MACRUNNER_HB_TRACE_NULLCALL со всех трёх площадок; "
                "hits = гейт открыт (умолчание — закрыт)",
                "MACRUNNER_HB_TRACE_NULLCALL", 0);
HB_PROBE_DEFINE(pr_nullcall_diag, "hb-nullcall-площадка-route",
                "заходы в route_x64_callback_fault при raw_pc==0 или fault<0x1000; "
                "hits = трасса выпущена (гейт открыт И потолок 64 не выбран)",
                "MACRUNNER_HB_TRACE_NULLCALL", 64);
HB_PROBE_DEFINE(pr_nullcall_segv, "hb-nullcall-площадка-segv",
                "заходы в segv_handler при EXECUTE_FAULT по адресу < 0x1000; "
                "hits = трасса выпущена (гейт открыт И потолок 16 не выбран)",
                "MACRUNNER_HB_TRACE_NULLCALL", 16);
HB_PROBE_DEFINE(pr_nullcall_prim, "hb-primary-sig",
                "заходы в первичный обработчик при pc<0x10000 или fault<0x10000 (looked — "
                "все, выше гейта); hits = строка выпущена, то есть гейт открыт И потолок "
                "16 не выбран. Метка строки сохранена побайтово",
                "MACRUNNER_HB_TRACE_NULLCALL", 16);

static BOOL macrunner_hb_trace_nullcall_enabled(void)
{
    static int enabled = -1;

    HB_PROBE_LOOKED(&pr_nullcall_gate);
    if (enabled < 0)
    {
        const char *nv = macrunner_hb_getenv( "MACRUNNER_HB_TRACE_NULLCALL" );
        enabled = nv && nv[0] && nv[0] != '0';
    }
    if (enabled != 0) HB_PROBE_HIT(&pr_nullcall_gate);
    return enabled != 0;
}

/* Presence-based, exactly as the original call sites were. */
static BOOL macrunner_hb_trace_bus_fault_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) enabled = macrunner_hb_getenv( "MACRUNNER_HB_TRACE_BUS_FAULT" ) ? 1 : 0;
    return enabled != 0;
}

/* Периодическая проба ШТОРМА accerr, а не только его первых шести отказов.
 *
 * 04.08: с MACRUNNER_HB_BLOCK_CHAIN=1 счётчик отказов уходит с базовых 110-160/с на 405 000/с,
 * скачком за 0.1 с на t~43-46 с, и держится так до конца прогона (171 млн отказов за 424 с,
 * воспроизведено 2/2).  При этом pages_distinct=32, а same_page равен почти всему счётчику,
 * то есть штормит ОДНА страница.  Назвать её нечем: существующая проба ограничена шестью
 * дампами, и все шесть снимаются задолго до начала шторма.  Поэтому — редкая выборка ВНУТРИ
 * шторма: одна строка на миллион отказов (при 405 000/с это строка раз в 2.5 с), чего хватает,
 * чтобы получить гостевой pc и адрес и опознать модуль по байтам, как это уже дважды сработало. */
static BOOL macrunner_hb_accerr_storm_sample_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) enabled = macrunner_hb_getenv( "MACRUNNER_HB_ACCERR_STORM_SAMPLE" ) ? 1 : 0;
    return enabled != 0;
}

static BOOL macrunner_hb_trace_signal_chain_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) enabled = macrunner_hb_getenv( "MACRUNNER_HB_TRACE_SIGNAL_CHAIN" ) ? 1 : 0;
    return enabled != 0;
}

/* MacRunner 2026-08-04 — ЗДЕСЬ СТОЯЛ ГЕЙТ MACRUNNER_HB_DELIVERY_STACK_BY_KSTACK, СНЯТ.
 *
 * Он уводил кадр доставки на вершину unix-стека потока, когда прерванный SP оказывался ниже
 * базы этого стека.  Правка неверна ПО РОДУ, и это выяснилось до прогонов: `frame->sp`
 * присваивается из windows-ского `context->Sp` (signal_arm64.c:458, NtSetContextThread), то
 * есть кадр доставки строится на WINDOWS-стеке, потому что по нему пойдёт PE-код
 * `KiUserExceptionDispatcher`.  Положить его на unix-стек значит запустить PE-диспетчер на
 * хостовом стеке — ровно то, чего вся проверка `is_inside_thread_stack` и избегает.
 *
 * Правильная цель уже реализована: macrunner_hb_get_callback_exception_stack() отдаёт
 * последний известный windows-SP с границы системного вызова.  Чинить надо ЕГО ОТКАЗ
 * (см. macrunner_hb_cbstack_decline), а не изобретать новую цель.  Измерено: за 25 прогонов
 * и 26 записей наложения этот механизм не сработал НИ РАЗУ (callback_stack=1 — ноль). */

static void macrunner_hb_trace_callback_target_module( const char *source, ULONG_PTR pc );

static ULONG_PTR macrunner_hb_normalize_x64_callback_target( ucontext_t *context,
                                                             ULONG_PTR target )
{
    ULONG_PTR tls_target;

    /* TLS callbacks carry the authoritative image base in x0 and reason in x1.
     * Use the image TLS table before falling back to instruction-boundary
     * heuristics, otherwise a fault PC in padding can be dispatched as code. */
    tls_target = macrunner_hb_normalize_x64_tls_callback_pc( target, REGn_sig(0, context),
                                                             REGn_sig(1, context) );
    if (tls_target != target) return tls_target;
    return macrunner_hb_normalize_x64_callback_pc( target );
}

static ULONG_PTR macrunner_hb_normalize_explicit_x64_callback_target( ucontext_t *context,
                                                                      ULONG_PTR target )
{
    /* x4 is the native caller's explicit indirect-call target, not a macOS
     * fault PC sampled from an ARM64 fetch.  Keep the instruction-boundary
     * heuristics for raw/fault PCs only; they can move valid MinGW TLS callback
     * entries such as __dyn_tls_dtor one byte backwards into padding. */
    return macrunner_hb_normalize_x64_tls_callback_pc( target, REGn_sig(0, context),
                                                       REGn_sig(1, context) );
}

static void macrunner_signal_copy_bytes( void *dst, const void *src, size_t size )
{
    volatile unsigned char *d = dst;
    const volatile unsigned char *s = src;

    while (size--) *d++ = *s++;
}

static BOOL macrunner_signal_read_memory( void *dst, const void *src, size_t size )
{
    if (!size) return TRUE;
    if (!dst || !src) return FALSE;
#ifdef __APPLE__
    {
        mach_vm_size_t out_size = 0;
        kern_return_t kr = mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)src,
                                                   (mach_vm_size_t)size,
                                                   (mach_vm_address_t)dst, &out_size );
        return kr == KERN_SUCCESS && out_size == size;
    }
#else
    if (!virtual_is_valid_code_address( (void *)src, size )) return FALSE;
    macrunner_signal_copy_bytes( dst, src, size );
    return TRUE;
#endif
}

static BOOL macrunner_signal_write_memory( void *dst, const void *src, size_t size )
{
    if (!size) return TRUE;
    if (!dst || !src) return FALSE;
#ifdef __APPLE__
    if ((mach_msg_type_number_t)size != size) return FALSE;
    return mach_vm_write( mach_task_self(), (mach_vm_address_t)dst,
                          (vm_offset_t)(uintptr_t)src,
                          (mach_msg_type_number_t)size ) == KERN_SUCCESS;
#else
    macrunner_signal_copy_bytes( dst, src, size );
    return TRUE;
#endif
}

static BOOL macrunner_signal_read_u32_aligned( ULONG_PTR pc, ULONG *instr )
{
    if (!instr || (pc & 3)) return FALSE;
    return macrunner_signal_read_memory( instr, (void *)pc, sizeof(*instr) );
}

static void macrunner_signal_writef( const char *format, ... )
{
    char buffer[512];
    va_list args;
    int len;

    va_start( args, format );
    len = vsnprintf( buffer, sizeof(buffer), format, args );
    va_end( args );
    if (len <= 0) return;
    if ((size_t)len >= sizeof(buffer)) len = sizeof(buffer) - 1;
    write( STDERR_FILENO, buffer, len );
}

/***********************************************************************
 *  ★★★ ПАКЕТ-3 (08.09.2026) — ВЛАДЕНИЕ ОТКАЗОМ И КОНТЕКСТОМ
 *
 * Смысл одной фразой: когда владелец CPU — НЕ HyperBridge, каждым отказом и
 * каждым контекстом владеет выбранный транслятор, а лечебные эвристики HB
 * молчат.  Они писались под договор HyperBridge; для FEX они не просто лишние —
 * они ТИХО подменяют данные, и отказ уезжает в сторону.  Ровно так наш трамплин
 * x18 приносил в жертву x17 и стоил нам стены x64 (T2, ШАГ-4).
 *
 * Семьи (нумерация тикетов из 20260907-ASTRA-WINE-FEX-CONTRACT-AUDIT.md):
 *   T3  — подстановка «низкий адрес это TEB+база» БЕЗ доказательства происхождения;
 *   T4  — лечение отказа записи РАНЬШЕ, чем FEX узнает о самописи (SMC);
 *   T12 — быстрый проброс переходника HEXPTHK мимо диспетчера FEX.
 * (T11 живёт в PE-половине, dlls/ntdll/signal_arm64ec.c — там свой счётчик.)
 *
 * ПРИБОР И ЕГО ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ.  Счётчиков ДВА на семью, и печатаются оба:
 *   ПОГАШЕНА  — владелец не HB, ветвь не исполнялась (ждём на руке fex);
 *   ПРОПУЩЕНА — владелец HB, ветвь работает как раньше (ждём на руке hb).
 * Прибор, молчащий на обеих руках, неотличим от «сюда не дошли», поэтому печать
 * БЕЗУСЛОВНАЯ (первые 8, дальше степени двойки), без гейта и без env.
 *
 * Единственный источник правды о владельце — macrunner_cpu_backend_disables_hb_semantics()
 * из unix/loader.c (пакет 1, T8/T9/T13).  Второй селектор здесь НЕ заводится: несколько
 * независимых селекторов — это наша собственная болезнь, названная в аудите.
 */
enum macrunner_paket3_family
{
    MACRUNNER_P3_T3_TEB_HEAL = 0,
    MACRUNNER_P3_T4_COMMIT,
    MACRUNNER_P3_T12_HEXPTHK,
    MACRUNNER_P3_FAMILY_COUNT
};

static const char * const macrunner_paket3_family_name[MACRUNNER_P3_FAMILY_COUNT] =
{
    "T3-teb-heal", "T4-commit-upgrade", "T12-hexpthk"
};

static unsigned long long macrunner_paket3_muted[MACRUNNER_P3_FAMILY_COUNT];
static unsigned long long macrunner_paket3_passed[MACRUNNER_P3_FAMILY_COUNT];

/* TRUE = семью НАДО погасить: владелец CPU не HyperBridge. */
static BOOL macrunner_paket3_mute( enum macrunner_paket3_family family )
{
    BOOL mute = macrunner_cpu_backend_disables_hb_semantics();
    unsigned long long n;

    if (mute) n = __atomic_add_fetch( &macrunner_paket3_muted[family], 1ull, __ATOMIC_RELAXED );
    else      n = __atomic_add_fetch( &macrunner_paket3_passed[family], 1ull, __ATOMIC_RELAXED );

    if (n <= 8 || !(n & (n - 1)))
        macrunner_signal_writef( "macrunner-paket3: family=%s state=%s n=%llu\n",
                                 macrunner_paket3_family_name[family],
                                 mute ? "MUTED" : "PASSED", n );
    return mute;
}

/* Семья T4 живёт в macrunner_hb.c (две точки вызова: signal_arm64.c и сам macrunner_hb.c),
 * поэтому гейт обязан стоять ВНУТРИ функции, в чужом файле.  Именованная обёртка вместо
 * вынесения enum наружу: счётчик остаётся ОДИН на обе точки, а общих типов между файлами
 * не заводится. */
BOOL macrunner_paket3_mute_t4_commit(void)
{
    return macrunner_paket3_mute( MACRUNNER_P3_T4_COMMIT );
}

struct macrunner_hb_signal_module_info
{
    void *base;
    ULONG_PTR rva;
    ULONG size;
    char name[64];
};

static void macrunner_hb_signal_copy_unicode_name( const UNICODE_STRING *src,
                                                   char *dst, size_t dst_size )
{
    size_t count, i;

    if (!dst || !dst_size) return;
    strcpy( dst, "unknown" );
    if (!src || !src->Buffer || !src->Length) return;

    count = src->Length / sizeof(WCHAR);
    if (count >= dst_size) count = dst_size - 1;
    for (i = 0; i < count; i++)
    {
        WCHAR ch = 0;

        if (!macrunner_signal_read_memory( &ch, src->Buffer + i, sizeof(ch) )) break;
        dst[i] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '?';
    }
    dst[i] = 0;
    if (!i) strcpy( dst, "unknown" );
}

static BOOL macrunner_hb_signal_find_loader_module( ULONG_PTR pc,
                                                    struct macrunner_hb_signal_module_info *info )
{
    TEB *teb = NtCurrentTeb();
    PEB_LDR_DATA *ldr;
    PEB_LDR_DATA ldr_copy;
    LIST_ENTRY *head, *entry;
    unsigned int i;

    if (!info) return FALSE;
    memset( info, 0, sizeof(*info) );
    strcpy( info->name, "unknown" );
    if (!pc || !teb || !teb->Peb) return FALSE;
    if (!(ldr = teb->Peb->LdrData)) return FALSE;
    if (!macrunner_signal_read_memory( &ldr_copy, ldr, sizeof(ldr_copy) )) return FALSE;

    head = &ldr->InMemoryOrderModuleList;
    entry = ldr_copy.InMemoryOrderModuleList.Flink;
    for (i = 0; i < 256 && entry && entry != head; i++)
    {
        LDR_DATA_TABLE_ENTRY mod;
        LDR_DATA_TABLE_ENTRY *mod_ptr =
            CONTAINING_RECORD( entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
        ULONG_PTR base, size;
        LIST_ENTRY *next;

        if (!macrunner_signal_read_memory( &mod, mod_ptr, sizeof(mod) )) break;
        base = (ULONG_PTR)mod.DllBase;
        size = mod.SizeOfImage;
        if (base && size && pc >= base && pc - base < size)
        {
            info->base = mod.DllBase;
            info->rva = pc - base;
            info->size = mod.SizeOfImage;
            macrunner_hb_signal_copy_unicode_name( &mod.BaseDllName, info->name,
                                                   sizeof(info->name) );
            return TRUE;
        }
        next = mod.InMemoryOrderLinks.Flink;
        if (next == entry) break;
        entry = next;
    }
    return FALSE;
}

void macrunner_hb_trace_x64_callback_preserve( ULONG64 target, ULONG64 saved_x26,
                                               ULONG64 current_x26, ULONG64 saved_x27,
                                               ULONG64 current_x27 )
{
    if (!macrunner_hb_trace_callback_route_enabled()) return;
    fprintf( stderr, "macrunner-hb-callback-preserve: target=%p saved_x26=%p current_x26=%p "
         "saved_x27=%p current_x27=%p\n",
         (void *)(ULONG_PTR)target, (void *)(ULONG_PTR)saved_x26,
                 (void *)(ULONG_PTR)current_x26, (void *)(ULONG_PTR)saved_x27,
                 (void *)(ULONG_PTR)current_x27 );
}

/* Evidence-only correlation for the post-Mono callback/signal corridor.  Keep
 * the signal-side path allocation-free, default-off, time-stratified, and under
 * one global record budget.  The TLS depths distinguish sequential signals from
 * actual signal/router re-entry without changing callback disposition. */
#define MACRUNNER_HB_CALLBACK_LOOP_TRACE_BUDGET 5000

enum macrunner_hb_callback_loop_event
{
    MACRUNNER_HB_CALLBACK_LOOP_SIGNAL_ENTER,
    MACRUNNER_HB_CALLBACK_LOOP_SIGNAL_EXIT,
    MACRUNNER_HB_CALLBACK_LOOP_ROUTE_ENTER,
    MACRUNNER_HB_CALLBACK_LOOP_ROUTE_EXIT,
    MACRUNNER_HB_CALLBACK_LOOP_TRAMPOLINE_ENTER,
    MACRUNNER_HB_CALLBACK_LOOP_TRAMPOLINE_EXIT,
    MACRUNNER_HB_CALLBACK_LOOP_DISPATCH_ENTER,
    MACRUNNER_HB_CALLBACK_LOOP_DISPATCH_RETURN,
    MACRUNNER_HB_CALLBACK_LOOP_DISPATCH_EXIT,
    MACRUNNER_HB_CALLBACK_LOOP_EVENT_COUNT
};

struct macrunner_hb_callback_loop_tls
{
    unsigned int signal_depth;
    unsigned int route_depth;
    unsigned int trampoline_depth;
    unsigned int dispatch_depth;
    uint64_t counts[MACRUNNER_HB_CALLBACK_LOOP_EVENT_COUNT];
    uint64_t last_emit_ns[MACRUNNER_HB_CALLBACK_LOOP_EVENT_COUNT];
};

static __thread struct macrunner_hb_callback_loop_tls macrunner_hb_callback_loop_tls;
static volatile unsigned int macrunner_hb_callback_loop_trace_records;
static volatile uint64_t macrunner_hb_callback_loop_trace_sequence;

static BOOL macrunner_hb_callback_loop_trace_enabled(void)
{
    static int enabled = -1;
    const char *value;

    if (enabled >= 0) return enabled;
    value = macrunner_hb_getenv( "MACRUNNER_HB_CALLBACK_LOOP_TRACE" );
    enabled = value && value[0] && value[0] != '0';
    return enabled;
}

static uint64_t macrunner_hb_callback_loop_now_ns(void)
{
    struct timespec ts;

    if (clock_gettime( CLOCK_MONOTONIC, &ts )) return 0;
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static uint64_t macrunner_hb_callback_loop_native_tid(void)
{
    uint64_t tid = 0;

#ifdef __APPLE__
    pthread_threadid_np( NULL, &tid );
#else
    tid = (uint64_t)(uintptr_t)pthread_self();
#endif
    return tid;
}

static BOOL macrunner_hb_callback_loop_should_emit( enum macrunner_hb_callback_loop_event event,
                                                    uint64_t count )
{
    uint64_t now = macrunner_hb_callback_loop_now_ns();

    if (count > 16 && now && now - macrunner_hb_callback_loop_tls.last_emit_ns[event] < 2000000000ull)
        return FALSE;
    macrunner_hb_callback_loop_tls.last_emit_ns[event] = now;
    return __sync_add_and_fetch( &macrunner_hb_callback_loop_trace_records, 1 ) <=
           MACRUNNER_HB_CALLBACK_LOOP_TRACE_BUDGET;
}

static void macrunner_hb_callback_loop_emit( enum macrunner_hb_callback_loop_event event,
                                             const char *stage, const char *source,
                                             int signal, unsigned int depth,
                                             ULONG_PTR pc, ULONG_PTR fault, ULONG_PTR target,
                                             ULONG_PTR lr, ULONG_PTR sp, int handled,
                                             NTSTATUS status, uint64_t blocks, uint64_t steps,
                                             uint64_t result, BOOL teb_valid )
{
    struct macrunner_hb_signal_module_info module;
    uint64_t count, sequence, native_tid;
    unsigned long guest_tid = 0;
    ULONG_PTR lookup_pc = target ? target : pc;

    if (!macrunner_hb_callback_loop_trace_enabled()) return;
    count = ++macrunner_hb_callback_loop_tls.counts[event];
    if (!macrunner_hb_callback_loop_should_emit( event, count )) return;
    sequence = __sync_add_and_fetch( &macrunner_hb_callback_loop_trace_sequence, 1 );
    native_tid = macrunner_hb_callback_loop_native_tid();
    memset( &module, 0, sizeof(module) );
    strcpy( module.name, "unknown" );
    if (teb_valid)
    {
        TEB *teb = NtCurrentTeb();

        if (teb) guest_tid = (unsigned long)(ULONG_PTR)teb->ClientId.UniqueThread;
        macrunner_hb_signal_find_loader_module( lookup_pc, &module );
    }
    macrunner_signal_writef(
        "macrunner-hb-callback-loop: seq=%llu stage=%s source=%s event_count=%llu "
        "signal=%d depth=%u reentry=%u guest_tid=%04lx native_tid=%llu pc=%p fault=%p "
        "target=%p lr=%p sp=%p handled=%d status=%08lx blocks=%llu steps=%llu "
        "result=%p module=%s base=%p rva=%p totals=%llu/%llu/%llu/%llu/%llu/%llu/%llu/%llu/%llu\n",
        (unsigned long long)sequence, stage ? stage : "unknown", source ? source : "unknown",
        (unsigned long long)count, signal, depth, depth > 1, guest_tid,
        (unsigned long long)native_tid, (void *)pc, (void *)fault, (void *)target,
        (void *)lr, (void *)sp, handled, (unsigned long)status,
        (unsigned long long)blocks, (unsigned long long)steps, (void *)(ULONG_PTR)result,
        module.name, module.base, (void *)module.rva,
        (unsigned long long)macrunner_hb_callback_loop_tls.counts[MACRUNNER_HB_CALLBACK_LOOP_SIGNAL_ENTER],
        (unsigned long long)macrunner_hb_callback_loop_tls.counts[MACRUNNER_HB_CALLBACK_LOOP_SIGNAL_EXIT],
        (unsigned long long)macrunner_hb_callback_loop_tls.counts[MACRUNNER_HB_CALLBACK_LOOP_ROUTE_ENTER],
        (unsigned long long)macrunner_hb_callback_loop_tls.counts[MACRUNNER_HB_CALLBACK_LOOP_ROUTE_EXIT],
        (unsigned long long)macrunner_hb_callback_loop_tls.counts[MACRUNNER_HB_CALLBACK_LOOP_TRAMPOLINE_ENTER],
        (unsigned long long)macrunner_hb_callback_loop_tls.counts[MACRUNNER_HB_CALLBACK_LOOP_TRAMPOLINE_EXIT],
        (unsigned long long)macrunner_hb_callback_loop_tls.counts[MACRUNNER_HB_CALLBACK_LOOP_DISPATCH_ENTER],
        (unsigned long long)macrunner_hb_callback_loop_tls.counts[MACRUNNER_HB_CALLBACK_LOOP_DISPATCH_RETURN],
        (unsigned long long)macrunner_hb_callback_loop_tls.counts[MACRUNNER_HB_CALLBACK_LOOP_DISPATCH_EXIT] );
}

struct macrunner_hb_callback_loop_signal_scope
{
    BOOL active;
    const char *source;
    int signal;
    ucontext_t *context;
    unsigned int depth;
};

static struct macrunner_hb_callback_loop_signal_scope macrunner_hb_callback_loop_signal_enter(
    const char *source, int signal, void *sigcontext )
{
    struct macrunner_hb_callback_loop_signal_scope scope = {0};

    if (!macrunner_hb_callback_loop_trace_enabled()) return scope;
    scope.active = TRUE;
    scope.source = source;
    scope.signal = signal;
    scope.context = sigcontext;
    scope.depth = ++macrunner_hb_callback_loop_tls.signal_depth;
    macrunner_hb_callback_loop_emit( MACRUNNER_HB_CALLBACK_LOOP_SIGNAL_ENTER, "signal-enter",
                                     source, signal, scope.depth, PC_sig(scope.context), 0, 0,
                                     LR_sig(scope.context), SP_sig(scope.context), -1, 0, 0, 0, 0, FALSE );
    return scope;
}

static void macrunner_hb_callback_loop_signal_leave(
    struct macrunner_hb_callback_loop_signal_scope *scope )
{
    if (!scope || !scope->active) return;
    macrunner_hb_callback_loop_emit( MACRUNNER_HB_CALLBACK_LOOP_SIGNAL_EXIT, "signal-exit",
                                     scope->source, scope->signal, scope->depth,
                                     PC_sig(scope->context), 0, 0, LR_sig(scope->context),
                                     SP_sig(scope->context), -1, 0, 0, 0, 0, FALSE );
    if (macrunner_hb_callback_loop_tls.signal_depth)
        macrunner_hb_callback_loop_tls.signal_depth--;
}

struct macrunner_hb_callback_loop_route_scope
{
    BOOL active;
    BOOL handled;
    const char *source;
    const char *disposition;
    ucontext_t *context;
    ULONG_PTR fault;
    ULONG_PTR target;
    unsigned int depth;
};

static struct macrunner_hb_callback_loop_route_scope macrunner_hb_callback_loop_route_enter(
    ucontext_t *context, ULONG_PTR fault, const char *source )
{
    static uint64_t x18_provenance_records;
    struct macrunner_hb_callback_loop_route_scope scope = {0};
    const ULONG_PTR *fault_sp;
    uint64_t provenance;

    if (!macrunner_hb_callback_loop_trace_enabled()) return scope;
    scope.active = TRUE;
    scope.source = source;
    scope.disposition = "unhandled";
    scope.context = context;
    scope.fault = fault;
    scope.depth = ++macrunner_hb_callback_loop_tls.route_depth;
    if (fault == 0x48 &&
        (provenance = __sync_add_and_fetch( &x18_provenance_records, 1 )) <= 256)
    {
        fault_sp = (const ULONG_PTR *)SP_sig(context);
        macrunner_signal_writef(
            "macrunner-hb-x18-provenance: seq=%llu native_tid=%llu guest_tid=UNKNOWN "
            "source=%s pc=%p fault=%p lr=%p sp=%p fp=%p x16=%p x17=%p x18=%p x19=%p x20=%p "
            "stack_c0=%p stack_150=%p\n",
            (unsigned long long)provenance,
            (unsigned long long)macrunner_hb_callback_loop_native_tid(), source,
            (void *)PC_sig(context), (void *)fault, (void *)LR_sig(context),
            (void *)SP_sig(context), (void *)FP_sig(context),
            (void *)REGn_sig(16, context), (void *)REGn_sig(17, context),
            (void *)REGn_sig(18, context), (void *)REGn_sig(19, context),
            (void *)REGn_sig(20, context), (void *)fault_sp[0xc0 / sizeof(*fault_sp)],
            (void *)fault_sp[0x150 / sizeof(*fault_sp)] );
    }
    macrunner_hb_callback_loop_emit( MACRUNNER_HB_CALLBACK_LOOP_ROUTE_ENTER, "route-enter",
                                     source, 0, scope.depth, PC_sig(context), fault, 0,
                                     LR_sig(context), SP_sig(context), -1, 0, 0, 0, 0, FALSE );
    return scope;
}

static void macrunner_hb_callback_loop_route_leave(
    struct macrunner_hb_callback_loop_route_scope *scope )
{
    if (!scope || !scope->active) return;
    macrunner_hb_callback_loop_emit( MACRUNNER_HB_CALLBACK_LOOP_ROUTE_EXIT, "route-exit",
                                     scope->disposition, 0, scope->depth, PC_sig(scope->context),
                                     scope->fault, scope->target, LR_sig(scope->context),
                                     SP_sig(scope->context), scope->handled, 0, 0, 0, 0, FALSE );
    if (macrunner_hb_callback_loop_tls.route_depth)
        macrunner_hb_callback_loop_tls.route_depth--;
}

void macrunner_hb_callback_loop_trace_trampoline_entry( ULONG64 target, ULONG64 lr, ULONG64 sp )
{
    unsigned int depth;

    if (!macrunner_hb_callback_loop_trace_enabled()) return;
    depth = ++macrunner_hb_callback_loop_tls.trampoline_depth;
    macrunner_hb_callback_loop_emit( MACRUNNER_HB_CALLBACK_LOOP_TRAMPOLINE_ENTER,
                                     "trampoline-enter", "asm", 0, depth, 0, 0, target,
                                     lr, sp, -1, 0, 0, 0, 0, TRUE );
}

void macrunner_hb_callback_loop_trace_trampoline_exit( ULONG64 target, BOOL handled,
                                                        ULONG64 result, ULONG64 lr, ULONG64 sp )
{
    unsigned int depth = macrunner_hb_callback_loop_tls.trampoline_depth;

    if (!macrunner_hb_callback_loop_trace_enabled()) return;
    macrunner_hb_callback_loop_emit( MACRUNNER_HB_CALLBACK_LOOP_TRAMPOLINE_EXIT,
                                     "trampoline-exit", handled ? "ret-lr" : "reject-br-target",
                                     0, depth, 0, 0, target, lr, sp, handled, 0, 0, 0, result, TRUE );
    if (macrunner_hb_callback_loop_tls.trampoline_depth)
        macrunner_hb_callback_loop_tls.trampoline_depth--;
}

void macrunner_hb_callback_loop_trace_dispatch( const char *stage, ULONG64 target,
                                                 ULONG64 original_target, NTSTATUS status,
                                                 ULONG64 blocks, ULONG64 steps, ULONG64 result )
{
    enum macrunner_hb_callback_loop_event event = MACRUNNER_HB_CALLBACK_LOOP_DISPATCH_RETURN;
    unsigned int depth;

    if (!macrunner_hb_callback_loop_trace_enabled()) return;
    if (!strcmp( stage, "enter" ))
    {
        event = MACRUNNER_HB_CALLBACK_LOOP_DISPATCH_ENTER;
        depth = ++macrunner_hb_callback_loop_tls.dispatch_depth;
    }
    else
    {
        depth = macrunner_hb_callback_loop_tls.dispatch_depth;
        if (strcmp( stage, "run-return" )) event = MACRUNNER_HB_CALLBACK_LOOP_DISPATCH_EXIT;
    }
    macrunner_hb_callback_loop_emit( event, stage, "dispatch", 0, depth, original_target, 0,
                                     target, 0, 0, !status, status, blocks, steps, result, TRUE );
    if (event == MACRUNNER_HB_CALLBACK_LOOP_DISPATCH_EXIT &&
        macrunner_hb_callback_loop_tls.dispatch_depth)
        macrunner_hb_callback_loop_tls.dispatch_depth--;
}

/* This trampoline is entered as an ARM64 PE callee when Wine native code calls
 * an x64 callback target.  Preserve the full AAPCS64 callee-saved set around
 * the HyperBridge dispatch; native callers commonly keep long-lived state in
 * x19-x28 (RtlProcessFlsData uses x26 for fls_data across FLS callbacks). */
__ASM_GLOBAL_FUNC( macrunner_hb_x64_callback_trampoline,
                   "stp x29, x30, [sp, #-0x100]!\n\t"
                   __ASM_CFI(".cfi_def_cfa_offset 0x100\n\t")
                   __ASM_CFI(".cfi_offset 29,-0x100\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xf8\n\t")
                   "mov x29, sp\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   "stp x0, x1, [x29, #0x10]\n\t"
                   "stp x2, x3, [x29, #0x20]\n\t"
                   "stp x4, x5, [x29, #0x30]\n\t"
                   "stp x6, x7, [x29, #0x40]\n\t"
                   "str x16, [x29, #0x58]\n\t"
                   "stp x19, x20, [x29, #0x60]\n\t"
                   __ASM_CFI(".cfi_rel_offset 19,0x60\n\t")
                   __ASM_CFI(".cfi_rel_offset 20,0x68\n\t")
                   "stp x21, x22, [x29, #0x70]\n\t"
                   __ASM_CFI(".cfi_rel_offset 21,0x70\n\t")
                   __ASM_CFI(".cfi_rel_offset 22,0x78\n\t")
                   "stp x23, x24, [x29, #0x80]\n\t"
                   __ASM_CFI(".cfi_rel_offset 23,0x80\n\t")
                   __ASM_CFI(".cfi_rel_offset 24,0x88\n\t")
                   "stp x25, x26, [x29, #0x90]\n\t"
                   __ASM_CFI(".cfi_rel_offset 25,0x90\n\t")
                   __ASM_CFI(".cfi_rel_offset 26,0x98\n\t")
                   "stp x27, x28, [x29, #0xa0]\n\t"
                   __ASM_CFI(".cfi_rel_offset 27,0xa0\n\t")
                   __ASM_CFI(".cfi_rel_offset 28,0xa8\n\t")
                   "stp d8,  d9,  [x29, #0xb0]\n\t"
                   "stp d10, d11, [x29, #0xc0]\n\t"
                   "stp d12, d13, [x29, #0xd0]\n\t"
                   "stp d14, d15, [x29, #0xe0]\n\t"
                   "bl " __ASM_NAME("__wine_get_current_teb_for_x18") "\n\t"
                   "str x0, [x29, #0x50]\n\t"
                   "mov x18, x0\n\t"
                   "ldr x0, [x29, #0x58]\n\t"
                   "ldr x1, [x29, #0x08]\n\t"
                   "mov x2, x29\n\t"
                   "bl " __ASM_NAME("macrunner_hb_callback_loop_trace_trampoline_entry") "\n\t"
                   "ldr x18, [x29, #0x50]\n\t"
                   "ldr x0, [x29, #0x58]\n\t"
                   "add x1, x29, #0x10\n\t"
                   "add x2, x29, #0xf0\n\t"
                   "bl " __ASM_NAME("macrunner_hb_try_dispatch_x64_callback") "\n\t"
                   "str w0, [x29, #0xf8]\n\t"
                   "ldr x18, [x29, #0x50]\n\t"
                   "ldr x0, [x29, #0x58]\n\t"
                   "ldr x1, [x29, #0x98]\n\t"
                   "mov x2, x26\n\t"
                   "ldr x3, [x29, #0xa0]\n\t"
                   "mov x4, x27\n\t"
                   "bl " __ASM_NAME("macrunner_hb_trace_x64_callback_preserve") "\n\t"
                   "ldr x18, [x29, #0x50]\n\t"
                   "ldr x0, [x29, #0x58]\n\t"
                   "ldr w1, [x29, #0xf8]\n\t"
                   "ldr x2, [x29, #0xf0]\n\t"
                   "ldr x3, [x29, #0x08]\n\t"
                   "mov x4, x29\n\t"
                   "bl " __ASM_NAME("macrunner_hb_callback_loop_trace_trampoline_exit") "\n\t"
                   "ldr x18, [x29, #0x50]\n\t"
                   "ldp d14, d15, [x29, #0xe0]\n\t"
                   "ldp d12, d13, [x29, #0xd0]\n\t"
                   "ldp d10, d11, [x29, #0xc0]\n\t"
                   "ldp d8,  d9,  [x29, #0xb0]\n\t"
                   "ldp x27, x28, [x29, #0xa0]\n\t"
                   __ASM_CFI(".cfi_same_value 27\n\t")
                   __ASM_CFI(".cfi_same_value 28\n\t")
                   "ldp x25, x26, [x29, #0x90]\n\t"
                   __ASM_CFI(".cfi_same_value 25\n\t")
                   __ASM_CFI(".cfi_same_value 26\n\t")
                   "ldp x23, x24, [x29, #0x80]\n\t"
                   __ASM_CFI(".cfi_same_value 23\n\t")
                   __ASM_CFI(".cfi_same_value 24\n\t")
                   "ldp x21, x22, [x29, #0x70]\n\t"
                   __ASM_CFI(".cfi_same_value 21\n\t")
                   __ASM_CFI(".cfi_same_value 22\n\t")
                   "ldp x19, x20, [x29, #0x60]\n\t"
                   __ASM_CFI(".cfi_same_value 19\n\t")
                   __ASM_CFI(".cfi_same_value 20\n\t")
                   "ldr w16, [x29, #0xf8]\n\t"
                   "cbnz w16, 1f\n\t"
                   /* A rejected callback was not consumed.  Restore the
                    * original call arguments and branch back to the faulting
                    * target; the normal signal path will now classify it. */
                   "ldp x0, x1, [x29, #0x10]\n\t"
                   "ldp x2, x3, [x29, #0x20]\n\t"
                   "ldp x4, x5, [x29, #0x30]\n\t"
                   "ldp x6, x7, [x29, #0x40]\n\t"
                   "ldr x17, [x29, #0x58]\n\t"
                   "ldp x29, x30, [sp], #0x100\n\t"
                   "br x17\n\t"
                   "1:\n\t"
                   "ldr x0, [x29, #0xf0]\n\t"
                   "ldp x29, x30, [sp], #0x100\n\t"
                   "ret" )

static BOOL macrunner_hb_redirect_arm64x_hexpthk_sigill( ucontext_t *context );

/* MacRunner 2026-07-29 (HK input): ALWAYS-ON re-entrancy guard for the fault router.
 *
 * Two unrelated guest hangs were sampled to the same endpoint on 2026-07-29 — a Return key
 * delivered on the Cocoa main thread, and winemac.drv's x86_64 DllMain — each pinned at
 * 413/413 and 894/895 samples inside this router's PC-classification helpers
 * (`macrunner_hb_route_x64_callback_fault` -> `…pc_is_x64_guest_code…` ->
 * `macrunner_hb_ldr_entry_from_pc`), burning a core forever while the process stayed alive
 * and its log simply stopped. That signature has cost these lanes six iterations, because a
 * silent 100 %-CPU process reads like a livelock in the guest rather than a fault loop in us.
 *
 * The mechanism: `macrunner_hb_ldr_entry_from_pc` opens with `NtCurrentTeb()->Peb`. On a
 * thread with no Wine TEB — a Cocoa callback thread is exactly that — the read itself faults,
 * and the fault handler calls this router, which calls the classifier again. Every fault
 * begets the next one. The PEB walk is already bounded (`guard++ < 4096`), so the loop is NOT
 * inside the walk and no amount of bounding it would have helped.
 *
 * `macrunner_hb_callback_loop_route_enter` does maintain a depth counter, but it early-returns
 * on `!macrunner_hb_callback_loop_trace_enabled()`, so in an ordinary run nothing counts and
 * nothing breaks the cycle; and even when tracing is on it only EMITS the depth.
 *
 * This guard is deliberately independent of that machinery and of every env gate: recursion
 * has to be stopped in production, not only under trace. On re-entry we return FALSE, which
 * lets the fault fall through to normal handling — a real, diagnosable crash instead of a
 * hang. Set MACRUNNER_HB_FAULT_REENTRY_LIMIT_OFF=1 to restore the old (hanging) behaviour for
 * an A/B. */
#define MACRUNNER_HB_FAULT_REENTRY_LIMIT 2

/* MacRunner 2026-07-29, second half of the same defect — REPEATED faults, not nested ones.
 *
 * The depth guard above stops a fault taken INSIDE the router. It does nothing for the case
 * actually caught in the wild, which is sequential: the handler classifies the fault, returns
 * to the very same instruction, that instruction faults again, forever. Each fault enters at
 * depth 1 and leaves cleanly, so the depth counter never rises and `fault-reentry-break` reads
 * 0 while the process burns a core in silence.
 *
 * Measured on HK pid 71264, wedged 435 s at 99.9 % CPU, `sample` 542 frames on the hot thread:
 * **351 of them in `_sigtramp`** — i.e. the thread is almost entirely inside signal delivery —
 * under `segv_handler -> macrunner_hb_route_x64_callback_fault ->
 * macrunner_hb_redirect_arm64x_hexpthk_sigill -> …pc_is_x64_guest_code_module_no_lock ->
 * macrunner_hb_module_from_pc -> macrunner_hb_ldr_entry_from_pc`. Every other thread in the
 * process was parked in a wait.
 *
 * So: count consecutive faults at the SAME pc. Past the limit, stop claiming to handle it and
 * return FALSE, which lets the fault reach normal handling — a diagnosable crash with the pc
 * printed, instead of a hang that looks like a guest livelock and has cost this project six
 * iterations of misdirected work.
 *
 * The counter resets whenever the pc changes, so ordinary high-volume faulting (the JIT takes
 * SIGSEGV routinely as a control-flow mechanism) is unaffected: only *no forward progress at a
 * single address* trips it. Limit is deliberately generous for the same reason. */
#define MACRUNNER_HB_FAULT_SAME_PC_LIMIT 4096

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: сообщение same-pc-break называет адрес, но не
 * говорит, ЧТО по этому адресу лежит, а стена ступени 1 решается именно этим. Прибор
 * pc-region живёт ниже по файлу и в этот путь не попадает (отказ ловит собственный
 * обработчик HyperBridge), поэтому объявляем его поиск области заранее и печатаем
 * права ровно в момент срыва. */
static BOOL macrunner_region_lookup( ULONG_PTR addr, mach_vm_address_t *out_addr,
                                     mach_vm_size_t *out_size,
                                     vm_region_submap_short_info_data_64_t *out_info );

static __thread ULONG_PTR macrunner_hb_fault_last_pc;
static __thread unsigned int macrunner_hb_fault_same_pc_count;

struct macrunner_hb_fault_reentry_guard { int engaged; };
static __thread int macrunner_hb_fault_reentry_depth;

static void macrunner_hb_fault_reentry_leave( struct macrunner_hb_fault_reentry_guard *guard )
{
    if (guard->engaged) macrunner_hb_fault_reentry_depth--;
}

static BOOL macrunner_hb_fault_reentry_disabled(void)
{
    static int cached = -1;
    const char *value;

    if (cached < 0)
    {
        value = macrunner_hb_getenv( "MACRUNNER_HB_FAULT_REENTRY_LIMIT_OFF" );
        cached = (value && value[0] && value[0] != '0') ? 1 : 0;
    }
    return cached != 0;
}

static BOOL macrunner_hb_route_x64_callback_fault( ucontext_t *context, ULONG_PTR fault_addr,
                                                   const char *source )
{
    ULONG_PTR pc, raw_pc, x4_target, x16_target;
    BOOL raw_is_guest, fault_is_guest, x4_is_guest, x16_is_guest, sigill_source;
    static int rejected_trace_count;
    struct macrunner_hb_fault_reentry_guard reentry_guard
        __attribute__((cleanup(macrunner_hb_fault_reentry_leave))) = {0};
    struct macrunner_hb_callback_loop_route_scope callback_loop_scope
        __attribute__((cleanup(macrunner_hb_callback_loop_route_leave))) =
        macrunner_hb_callback_loop_route_enter( context, fault_addr, source );

    if (!macrunner_hb_fault_reentry_disabled())
    {
        if (macrunner_hb_fault_reentry_depth >= MACRUNNER_HB_FAULT_REENTRY_LIMIT)
        {
            static int announced;

            /* Async-signal-safe writer, and announced once so a storm cannot become the
             * new hang. Print the PC so the offending classification site is identifiable
             * without a live sample. */
            if (!announced)
            {
                announced = 1;
                macrunner_signal_writef(
                    "macrunner-hb-fault-reentry-break: depth=%d source=%s pc=%p fault=%p "
                    "— recursive fault inside the router, refusing to recurse\n",
                    macrunner_hb_fault_reentry_depth, source ? source : "(none)",
                    (void *)PC_sig(context), (void *)fault_addr );
            }
            callback_loop_scope.disposition = "reentry-break";
            return FALSE;
        }
        macrunner_hb_fault_reentry_depth++;
        reentry_guard.engaged = 1;

        /* Same-pc repeat detector — see MACRUNNER_HB_FAULT_SAME_PC_LIMIT above. */
        {
            ULONG_PTR here = PC_sig(context);

            if (here != macrunner_hb_fault_last_pc)
            {
                macrunner_hb_fault_last_pc = here;
                macrunner_hb_fault_same_pc_count = 0;
            }
            else if (++macrunner_hb_fault_same_pc_count >= MACRUNNER_HB_FAULT_SAME_PC_LIMIT)
            {
                static int announced_pc;

                if (!announced_pc)
                {
                    mach_vm_address_t br_addr = 0;
                    mach_vm_size_t br_size = 0;
                    vm_region_submap_short_info_data_64_t br_info;
                    BOOL br_ok;

                    announced_pc = 1;
                    br_ok = macrunner_region_lookup( here, &br_addr, &br_size, &br_info );
                    macrunner_signal_writef(
                        "macrunner-hb-fault-same-pc-break: pc=%p fault=%p source=%s count=%u "
                        "— no forward progress at this address, refusing to keep handling\n",
                        (void *)here, (void *)fault_addr, source ? source : "(none)",
                        macrunner_hb_fault_same_pc_count );
                    macrunner_signal_writef(
                        "macrunner-hb-same-pc-region: pc=%p ok=%d region=%p-%p prot=%#x "
                        "max=%#x tag=%u share=%u exec=%s\n",
                        (void *)here, (int)br_ok,
                        (void *)(ULONG_PTR)br_addr,
                        (void *)(ULONG_PTR)(br_addr + br_size),
                        br_ok ? br_info.protection : 0,
                        br_ok ? br_info.max_protection : 0,
                        br_ok ? br_info.user_tag : 0,
                        br_ok ? br_info.share_mode : 0,
                        (br_ok && (br_info.protection & VM_PROT_EXECUTE)) ? "ДА" : "НЕТ" );
                    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: права говорят «это не код», но не
                     * говорят, ПОЧЕМУ мы сюда прыгнули. Разделяют два объяснения именно байты:
                     * нули или мусор => управление ушло по испорченному указателю; осмысленные
                     * коды команд => там настоящий код, который мы не пометили исполняемым.
                     * Страница доступна на чтение (prot=0x3), поэтому чтение безопасно. */
                    if (br_ok && (br_info.protection & VM_PROT_READ))
                    {
                        const unsigned char *p = (const unsigned char *)here;
                        macrunner_signal_writef(
                            "macrunner-hb-same-pc-bytes: pc=%p %02x %02x %02x %02x %02x %02x "
                            "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                            (void *)here, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                            p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15] );
                    }
                }
                callback_loop_scope.disposition = "same-pc-break";
                return FALSE;
            }
        }
    }

    /* A native ARM64 indirect call can land on an imported ARM64X x64 entry thunk
     * (optionally still carrying the CodeMap type tag in the low 2 bits).  Redirect
     * straight to the native ARM64 target rather than emulating the thunk as an x64
     * callback: the tag puts the PC mid-instruction (the recorded spin/OOM) and even
     * the aligned thunk cannot be JIT-executed.  This covers the SEGV/BUS fault
     * sources too (ill_handler already tries the redirect before reaching here). */
    if (macrunner_hb_redirect_arm64x_hexpthk_sigill( context ))
    {
        callback_loop_scope.handled = TRUE;
        callback_loop_scope.disposition = "arm64x-redirect";
        return TRUE;
    }

    if (!macrunner_hb_x64_fault_routing_enabled())
    {
        callback_loop_scope.disposition = "routing-disabled";
        return FALSE;
    }
    raw_pc = PC_sig(context);
    x4_target = REGn_sig(4, context);
    x16_target = REGn_sig(16, context);
    raw_is_guest = macrunner_hb_pc_is_x64_guest_code_no_lock( (void *)raw_pc );
    fault_is_guest = macrunner_hb_pc_is_x64_guest_code_no_lock( (void *)fault_addr );
    x4_is_guest = macrunner_hb_pc_is_x64_guest_code_no_lock( (void *)x4_target );
    x16_is_guest = macrunner_hb_pc_is_x64_guest_code_no_lock( (void *)x16_target );
    sigill_source = source && (!strcmp( source, "sigill" ) || !strcmp( source, "primary-ill" ));

    /* MacRunner diag: a NULL-pointer fault in the guest — either execute-at-0
     * (raw_pc==0, calling a NULL function pointer) or a NULL-page data deref
     * (fault_addr in the first page).  Pin the guest call/deref site from the
     * registered x64 context (guest RSP/RIP are not in an ARM64 reg here).  Use a
     * DEDICATED env (not the broad callback-route trace, which floods per-callback
     * stderr and starves the boot before graphics). */
    if (raw_pc == 0 || fault_addr < 0x1000)
    {
        static int nullcall_diag_count;
        HB_PROBE_LOOKED(&pr_nullcall_diag);
        if (macrunner_hb_trace_nullcall_enabled() && nullcall_diag_count++ < 64)
        {
            HB_PROBE_HIT(&pr_nullcall_diag);
            macrunner_hb_trace_nullcall_site( source, raw_pc, fault_addr );
        }
    }

    if (sigill_source)
    {
        if (!raw_is_guest)
            raw_is_guest = macrunner_hb_pc_is_x64_guest_code_module_no_lock( (void *)raw_pc );
        if (fault_addr && !fault_is_guest)
            fault_is_guest = macrunner_hb_pc_is_x64_guest_code_module_no_lock( (void *)fault_addr );
        if (!x4_is_guest)
            x4_is_guest = macrunner_hb_pc_is_x64_guest_code_module_no_lock( (void *)x4_target );
        if (!x16_is_guest)
            x16_is_guest = macrunner_hb_pc_is_x64_guest_code_module_no_lock( (void *)x16_target );
    }

    /* Wine's ARM64EC-style indirect-call path can leave the real x64 target
     * in x4 while the architectural fault PC points at dispatch residue,
     * garbage, or a few bytes into x64 text after an ARM64 fetch attempt.
     * Prefer that explicit target only when the fault PC/address already
     * identifies x64 guest execution.  Otherwise a stale native x4 register
     * can manufacture a bogus callback from an ordinary ARM64 fault. */
    if (sigill_source && x16_is_guest && (raw_is_guest || fault_is_guest))
    {
        pc = macrunner_hb_normalize_explicit_x64_callback_target( context, x16_target );
        fprintf( stderr, "MacRunner Phase F using x16 x64 callback target raw_pc=%p x16=%p normalized=%p\n",
               (void *)raw_pc, (void *)x16_target, (void *)pc );
    }
    else if (x4_is_guest && (raw_is_guest || fault_is_guest))
    {
        pc = macrunner_hb_normalize_explicit_x64_callback_target( context, x4_target );
        fprintf( stderr, "MacRunner Phase F using x4 x64 callback target raw_pc=%p x4=%p normalized=%p\n",
               (void *)raw_pc, (void *)x4_target, (void *)pc );
    }
    else if (fault_is_guest)
        pc = macrunner_hb_normalize_x64_callback_target( context, fault_addr );
    else if (raw_is_guest)
        pc = macrunner_hb_normalize_x64_callback_target( context, raw_pc );
    else
    {
        if (macrunner_hb_trace_callback_route_enabled() && rejected_trace_count++ < 96)
            fprintf( stderr, "macrunner-hb-callback-route-reject: source=%s raw_pc=%p fault=%p "
                 "lr=%p sp=%p x0=%p x1=%p x2=%p x3=%p x4=%p x16=%p x18=%p "
                 "x19=%p x20=%p x24=%p x26=%p x27=%p x28=%p\n",
                 source, (void *)raw_pc, (void *)fault_addr,
                 (void *)(ULONG_PTR)LR_sig(context), (void *)(ULONG_PTR)SP_sig(context),
                 (void *)(ULONG_PTR)REGn_sig(0, context),
                 (void *)(ULONG_PTR)REGn_sig(1, context),
                 (void *)(ULONG_PTR)REGn_sig(2, context),
                 (void *)(ULONG_PTR)REGn_sig(3, context),
                 (void *)(ULONG_PTR)x4_target,
                 (void *)(ULONG_PTR)REGn_sig(16, context),
                 (void *)(ULONG_PTR)REGn_sig(18, context),
                 (void *)(ULONG_PTR)REGn_sig(19, context),
                 (void *)(ULONG_PTR)REGn_sig(20, context),
                 (void *)(ULONG_PTR)REGn_sig(24, context),
                 (void *)(ULONG_PTR)REGn_sig(26, context),
                 (void *)(ULONG_PTR)REGn_sig(27, context),
                 (void *)(ULONG_PTR)REGn_sig(28, context) );
        callback_loop_scope.disposition = "no-x64-target";
        return FALSE;
    }

    fprintf( stderr, "MacRunner Phase F routing %s x64 callback pc=%p lr=%p sp=%p "
           "x0=%p x1=%p x2=%p x3=%p x4=%p x5=%p\n",
           source, (void *)pc, (void *)(ULONG_PTR)LR_sig(context),
           (void *)(ULONG_PTR)SP_sig(context),
           (void *)(ULONG_PTR)REGn_sig(0, context),
           (void *)(ULONG_PTR)REGn_sig(1, context),
           (void *)(ULONG_PTR)REGn_sig(2, context),
           (void *)(ULONG_PTR)REGn_sig(3, context),
           (void *)(ULONG_PTR)REGn_sig(4, context),
           (void *)(ULONG_PTR)REGn_sig(5, context) );
    if (macrunner_hb_trace_callback_route_enabled())
    {
        macrunner_hb_trace_callback_target_module( source, pc );
        fprintf( stderr, "macrunner-hb-callback-route: source=%s raw_pc=%p fault=%p normalized=%p "
             "lr=%p sp=%p x4=%p x16=%p x19=%p x26=%p x27=%p x28=%p\n",
             source, (void *)raw_pc, (void *)fault_addr, (void *)pc, (void *)(ULONG_PTR)LR_sig(context),
             (void *)(ULONG_PTR)SP_sig(context), (void *)(ULONG_PTR)x4_target,
             (void *)(ULONG_PTR)REGn_sig(16, context),
             (void *)(ULONG_PTR)REGn_sig(19, context),
             (void *)(ULONG_PTR)REGn_sig(26, context),
             (void *)(ULONG_PTR)REGn_sig(27, context),
             (void *)(ULONG_PTR)REGn_sig(28, context) );
    }
    /* Do not consume a non-x64 callback fault.  In particular, an I386 target
     * must not reach the trampoline and turn its zero-valued rejection into a
     * successful callback return to LR, which skips the active JIT epilogue. */
    if (!macrunner_hb_pc_is_x64_callback_target_no_lock( (void *)pc ))
    {
        if (macrunner_hb_trace_callback_route_enabled() && rejected_trace_count++ < 96)
            fprintf( stderr, "macrunner-hb-callback-route-reject: stage=preflight source=%s "
                 "target=%p raw_pc=%p fault=%p lr=%p sp=%p\n",
                 source, (void *)pc, (void *)raw_pc, (void *)fault_addr,
                 (void *)(ULONG_PTR)LR_sig(context), (void *)(ULONG_PTR)SP_sig(context) );
        callback_loop_scope.target = pc;
        callback_loop_scope.disposition = "preflight-reject";
        return FALSE;
    }

    /* ★ MacRunner 2026-08-17, лейн ЛЕСТНИЦА, итерация 1333 — РАЗЛИЧАТЬ ПО ОБСТОЯТЕЛЬСТВАМ,
     * А НЕ ПО АДРЕСУ.
     *
     * Три статических признака подряд были опровергнуты замером (1322, 1323, 1332): «начало
     * диапазона», «нативный диапазон» и «нативный — не обратный вызов». Каждый убивал ЗАКОННЫЙ
     * первый вход, потому что и он, и вредные повторы лежат в одном нативном диапазоне одного
     * образа.
     *
     * Отличие измерено (1327) и лежит в РЕГИСТРАХ на момент отказа:
     *     законный вход   x0 = база образа, x1 = 1   (подпись DLL_PROCESS_ATTACH)
     *     вредные повторы x0 = 0x1101f0000, x1 = 0
     *
     * Поэтому: если адрес в нативном диапазоне карты И обстоятельства НЕ похожи на вход —
     * не уводить в x64-эмуляцию. Гейт `MACRUNNER_HB_EC_ENTRY_ONLY`, умолчание ВЫКЛ, переменная
     * читается один раз и проверяется до любой работы. */
    {
        static int ec_entry_only = -1;

        if (ec_entry_only < 0)
        {
            const char *v = macrunner_hb_getenv( "MACRUNNER_HB_EC_ENTRY_ONLY" );
            ec_entry_only = (v && v[0] && v[0] != '0') ? 1 : 0;
        }
        if (ec_entry_only && macrunner_hb_pc_is_arm64x_native_no_lock( (void *)pc ))
        {
            ULONG64 a0 = REGn_sig(0, context), a1 = REGn_sig(1, context);
            void *mod = macrunner_hb_pe_module_from_pc_no_lock( (void *)pc );

            if (!(mod && a0 == (ULONG64)(ULONG_PTR)mod && a1 == 1))
            {
                static int said_eo;

                if (said_eo++ < 16)
                    fprintf( stderr, "macrunner-hb-ec-entry-only: pc=%p a0=%p a1=%p base=%p — не вход, "
                         "в эмуляцию НЕ уводим\n", (void *)pc, (void *)(ULONG_PTR)a0,
                         (void *)(ULONG_PTR)a1, mod );
                return FALSE;
            }
        }
    }

    REGn_sig(16, context) = pc;
    REGn_sig(18, context) = (ULONG_PTR)macrunner_teb_reliable();
    PC_sig(context) = (ULONG_PTR)macrunner_hb_x64_callback_trampoline;
    callback_loop_scope.target = pc;
    callback_loop_scope.handled = TRUE;
    callback_loop_scope.disposition = "routed-trampoline";
    return TRUE;
}

static BOOL macrunner_hb_wow64_i386_execute_fault( ucontext_t *context,
                                                   const EXCEPTION_RECORD *rec )
{
    ULONG_PTR pc;

    /* * lane FEX-N3: etot perehvat NE zakryt gejtom MACRUNNER_HB_X64_LOADER,
     * to est pod FEX on srabotal by na KAZHDOM execute-fault gostya i386. */
    if (macrunner_cpu_backend_disables_hb_semantics()) return FALSE;
    if (!is_wow64() || current_machine != IMAGE_FILE_MACHINE_ARM64 ||
        main_image_info.Machine != IMAGE_FILE_MACHINE_I386)
        return FALSE;
    if (!rec || rec->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ||
        rec->NumberParameters < 2 || rec->ExceptionInformation[0] != EXCEPTION_EXECUTE_FAULT)
        return FALSE;

    pc = rec->ExceptionInformation[1];
    return pc && pc == PC_sig(context) && pc <= 0xffffffffu;
}

#include "native-prefix-policy.h"
#ifdef __APPLE__
#include "direct-resume.h"
#endif

extern void __wine_syscall_dispatcher_prefix_end(void);
extern void __wine_unix_call_dispatcher_prefix_end(void);

static BOOL macrunner_native_dispatcher_prefix_owned( ULONG_PTR pc, BOOL fex )
{
    return macrunner_native_prefix_classify( pc, fex, is_arm64ec(),
            (ULONG_PTR)__wine_syscall_dispatcher, (ULONG_PTR)__wine_syscall_dispatcher_prefix_end,
            (ULONG_PTR)__wine_unix_call_dispatcher, (ULONG_PTR)__wine_unix_call_dispatcher_prefix_end );
}

static ULONG_PTR apple_x18_resume_thunk_start( ULONG_PTR pc )
{
    unsigned int i;

    if (pc & 3) return 0;
    for (i = 0; i < 32; i++)
    {
        ULONG_PTR t = (ULONG_PTR)apple_x18_resume_by_rt[i];
        if (t && pc >= t && pc - t < 20) return t;
    }
    return 0;
}

static BOOL apple_x18_pc_is_resume_thunk( ULONG_PTR pc )
{
    return apple_x18_resume_thunk_start( pc ) != 0;
}

static BOOL apple_x18_resume_context_unchanged( const CONTEXT *before, const CONTEXT *after )
{
    return before->Pc == after->Pc && before->Sp == after->Sp &&
           before->Cpsr == after->Cpsr && before->Fp == after->Fp && before->Lr == after->Lr &&
           !memcmp( before->X, after->X, sizeof(before->X) );
}

/***********************************************************************
 *  ★★★ ПАКЕТ-3, ОСТАТОК T2 — ТРАМПЛИН ОПОЗНАЁТСЯ ПО ТРАМПЛИНУ, А НЕ ПО ЗАГРУЗЧИКУ
 *
 * Три места ниже (повторный сигнал, пришедший, когда PC УЖЕ ВНУТРИ нашего трамплина)
 * защищались условием `macrunner_hb_x64_loader_enabled() && apple_x18_pc_is_resume_thunk()`.
 * Первая половина условия ЛИШНЯЯ и вредная:
 *
 *   - трамплин `__wine_pe_x18_resume_thunk` ставит НАШ обработчик сигнала на платформенную
 *     потерю x18. Он наш при ЛЮБОМ владельце CPU — FEX через него тоже проходит, что ШАГ-4
 *     доказал прямо (лечился `ldr x17,[x18,#0x1788]` из пролога FEX);
 *   - принадлежность PC трамплину — ФАКТ, читаемый из адреса, а не догадка о двигателе.
 *     Спрашивать вдобавок про загрузчик значит подменять доказательство настройкой.
 *
 * Цена лишнего условия — ГРОМКИЙ вечный цикл, и он описан в комментарии у самого места:
 * «x17 reloads the thunk address and we spin forever». Без защиты мы перезаписываем
 * apple_x18_save_pc адресом ВНУТРИ трамплина, и трамплин прыгает сам в себя.
 *
 * Кого это касается. `macrunner_hb_x64_loader_enabled()` в этом файле — СВОЯ копия,
 * читающая getenv напрямую (:2263), поэтому селектор её НЕ гасит. Значит защита работала
 * при MACRUNNER_HB_X64_LOADER=1 и молчала при 0 — то есть дыра открыта и на руке fex
 * (там загрузчик гасится), и на руке hb с X64_LOADER=0. Это ровно замечание аудита о T2:
 * «не доказано при произвольном сигнале ДАЖЕ ДЛЯ HB» (:27), лечение — «сохранение прежнего
 * resume PC по ownership thunk, НЕЗАВИСИМО ОТ CPU» (:69).
 *
 * ★ ГРАНИЦА, названная прямо: на руке hb с X64_LOADER=0 поведение МЕНЯЕТСЯ — защита теперь
 * работает там, где раньше молчала. Это не «побайтово прежнее», и потому вынесено сюда, а
 * не спрятано. Изменение может только УБРАТЬ вечный цикл: ветвь срабатывает исключительно
 * тогда, когда PC уже внутри трамплина, а это состояние иначе не разрешается вовсе.
 * Печать безусловная — сколько раз сработало, видно на каждой руке. */
static BOOL apple_x18_thunk_reentry( ULONG_PTR pc )
{
    static unsigned long long reentry_n;
    unsigned long long n;

    if (!apple_x18_pc_is_resume_thunk( pc )) return FALSE;

    n = __atomic_add_fetch( &reentry_n, 1ull, __ATOMIC_RELAXED );
    if (n <= 8 || !(n & (n - 1)))
        macrunner_signal_writef( "macrunner-paket3: family=T2-thunk-reentry state=OWNED n=%llu "
                                 "pc=%p hb_loader=%d\n",
                                 n, (void *)pc, macrunner_hb_x64_loader_enabled() ? 1 : 0 );
    return TRUE;
}

static BOOL apple_x18_restart_owned_thunk( ucontext_t *context, TEB *teb )
{
    ULONG_PTR pc = PC_sig(context);
    if (mr_direct_target( (ULONG_PTR)teb, pc ))
    {
        /* Both instructions belong to this thread's immutable veneer. */
        PC_sig(context) = pc & ~((ULONG_PTR)vm_page_size - 1);
        REGn_sig(18, context) = (ULONG_PTR)teb;
        return TRUE;
    }
    if (!apple_x18_thunk_reentry( pc )) return FALSE;
    /* Keep the selected scratch register and the original pending backing slots. */
    REGn_sig(10, context) = (ULONG_PTR)teb;
    REGn_sig(18, context) = (ULONG_PTR)teb;
    PC_sig(context) = apple_x18_resume_thunk_start( pc );
    return TRUE;
}

static BOOL macrunner_hb_x64_loader_enabled(void)
{
    const char *value = macrunner_hb_getenv( "MACRUNNER_HB_X64_LOADER" );
    return value && value[0] && value[0] != '0';
}

#define WINE_RESTORE_X18_IF_ZERO                                            \
                   "cbnz x18, 9f\n\t"                                      \
                   "sub sp, sp, #0xb0\n\t"                                 \
                   "stp x0,  x1,  [sp, #0x00]\n\t"                         \
                   "stp x2,  x3,  [sp, #0x10]\n\t"                         \
                   "stp x4,  x5,  [sp, #0x20]\n\t"                         \
                   "stp x6,  x7,  [sp, #0x30]\n\t"                         \
                   "stp x8,  x9,  [sp, #0x40]\n\t"                         \
                   "stp x10, x11, [sp, #0x50]\n\t"                         \
                   "stp x12, x13, [sp, #0x60]\n\t"                         \
                   "stp x14, x15, [sp, #0x70]\n\t"                         \
                   "stp x16, x17, [sp, #0x80]\n\t"                         \
                   "str x30, [sp, #0x90]\n\t"                              \
                   "mrs x17, NZCV\n\t"                                     \
                   "str x17, [sp, #0x98]\n\t"                              \
                   "bl " __ASM_NAME("__wine_get_current_teb_for_x18") "\n\t" \
                   "mov x18, x0\n\t"                                       \
                   "ldr x17, [sp, #0x98]\n\t"                              \
                   "msr NZCV, x17\n\t"                                     \
                   "ldr x30, [sp, #0x90]\n\t"                              \
                   "ldp x16, x17, [sp, #0x80]\n\t"                         \
                   "ldp x14, x15, [sp, #0x70]\n\t"                         \
                   "ldp x12, x13, [sp, #0x60]\n\t"                         \
                   "ldp x10, x11, [sp, #0x50]\n\t"                         \
                   "ldp x8,  x9,  [sp, #0x40]\n\t"                         \
                   "ldp x6,  x7,  [sp, #0x30]\n\t"                         \
                   "ldp x4,  x5,  [sp, #0x20]\n\t"                         \
                   "ldp x2,  x3,  [sp, #0x10]\n\t"                         \
                   "ldp x0,  x1,  [sp, #0x00]\n\t"                         \
                   "add sp, sp, #0xb0\n"                                  \
                   "9:\n\t"

#define WINE_RESTORE_X18_FROM_TEB                                           \
                   "sub sp, sp, #0xb0\n\t"                                 \
                   "stp x0,  x1,  [sp, #0x00]\n\t"                         \
                   "stp x2,  x3,  [sp, #0x10]\n\t"                         \
                   "stp x4,  x5,  [sp, #0x20]\n\t"                         \
                   "stp x6,  x7,  [sp, #0x30]\n\t"                         \
                   "stp x8,  x9,  [sp, #0x40]\n\t"                         \
                   "stp x10, x11, [sp, #0x50]\n\t"                         \
                   "stp x12, x13, [sp, #0x60]\n\t"                         \
                   "stp x14, x15, [sp, #0x70]\n\t"                         \
                   "stp x16, x17, [sp, #0x80]\n\t"                         \
                   "str x30, [sp, #0x90]\n\t"                              \
                   "mrs x17, NZCV\n\t"                                     \
                   "str x17, [sp, #0x98]\n\t"                              \
                   "bl " __ASM_NAME("__wine_get_current_teb_for_x18") "\n\t" \
                   "mov x18, x0\n\t"                                       \
                   "ldr x17, [sp, #0x98]\n\t"                              \
                   "msr NZCV, x17\n\t"                                     \
                   "ldr x30, [sp, #0x90]\n\t"                              \
                   "ldp x16, x17, [sp, #0x80]\n\t"                         \
                   "ldp x14, x15, [sp, #0x70]\n\t"                         \
                   "ldp x12, x13, [sp, #0x60]\n\t"                         \
                   "ldp x10, x11, [sp, #0x50]\n\t"                         \
                   "ldp x8,  x9,  [sp, #0x40]\n\t"                         \
                   "ldp x6,  x7,  [sp, #0x30]\n\t"                         \
                   "ldp x4,  x5,  [sp, #0x20]\n\t"                         \
                   "ldp x2,  x3,  [sp, #0x10]\n\t"                         \
                   "ldp x0,  x1,  [sp, #0x00]\n\t"                         \
                   "add sp, sp, #0xb0\n\t"

/* ★★★★★★ MacRunner 2026-08-31 — TEB БЕЗ ВЫЗОВА И БЕЗ ЗАПИСИ В СТЕК.
 *
 * НАЙДЕНО ПРИБОРОМ: аппаратный сторож на запись назвал писателя в стек гостя —
 * `__wine_syscall_dispatcher+0x8`, то есть `stp x0, x1, [sp]` вот отсюда.
 *
 * ОТКУДА ВЗЯЛСЯ. Apple резервирует x18 под ОС, поэтому Wine не читает TEB одной
 * инструкцией, как на Linux, а зовёт помощника. Вызову нужен кадр — отсюда
 * `sub sp, sp, #0xb0` и спил x0-x17, x30, NZCV. Итого на КАЖДЫЙ системный вызов:
 * вызов, ~30 инструкций и 176 байт записи (плюс столько же чтения) по стеку гостя,
 * куда целиком попадает красная зона Apple ARM64 — 128 байт ниже sp.
 *
 * КАК УСТРОЕНО У СИСТЕМЫ. Разбор /usr/lib/system/libsystem_pthread.dylib:
 *     _pthread_getspecific:  mrs x8, TPIDRRO_EL0 ; ldr x0, [x8, x0, lsl #3] ; ret
 * Маскирования НЕТ. А NtCurrentTeb() в нашей же сборке — ровно
 * `pthread_getspecific(teb_key)` (разбор ntdll.so). Значит звать нечего: тот же
 * адрес берётся здесь же, без кадра и без единой записи в память.
 *
 * ГЕЙТ MACRUNNER_HB_TEB_SLOW=1 возвращает прежний путь: парный замер идёт на ОДНОМ
 * двоичном файле, а не сравнением двух сборок.
 *
 * Быстрый путь портит только x16/x17 — оба временные (IP0/IP1). Доводы системного
 * вызова лежат в x0-x7 и переживают его без спила; ради них спил и был нужен, ведь
 * `bl` затирает x0-x17.
 */
#define WINE_LOAD_TEB_IN_X17                                                \
                     "adrp x16, " __ASM_NAME("macrunner_hb_teb_slow") "@GOTPAGE\n\t" \
                     "ldr  x16, [x16, " __ASM_NAME("macrunner_hb_teb_slow") "@GOTPAGEOFF]\n\t" \
                     "ldr  w16, [x16]\n\t"                                   \
                     "cbnz w16, 8f\n\t"                                      \
                     "adrp x17, " __ASM_NAME("teb_key") "@GOTPAGE\n\t"       \
                     "ldr  x17, [x17, " __ASM_NAME("teb_key") "@GOTPAGEOFF]\n\t" \
                     "ldr  x16, [x17]\n\t"                                   \
                     "mrs  x17, TPIDRRO_EL0\n\t"                             \
                     "ldr  x17, [x17, x16, lsl #3]\n\t"                      \
                     "mov  x18, x17\n\t"                                     \
                     "b 9f\n\t"                                              \
                     "8:\n\t"                                                \
                   "sub sp, sp, #0xb0\n\t"                                 \
                   "stp x0,  x1,  [sp, #0x00]\n\t"                         \
                   "stp x2,  x3,  [sp, #0x10]\n\t"                         \
                   "stp x4,  x5,  [sp, #0x20]\n\t"                         \
                   "stp x6,  x7,  [sp, #0x30]\n\t"                         \
                   "stp x8,  x9,  [sp, #0x40]\n\t"                         \
                   "stp x10, x11, [sp, #0x50]\n\t"                         \
                   "stp x12, x13, [sp, #0x60]\n\t"                         \
                   "stp x14, x15, [sp, #0x70]\n\t"                         \
                   "stp x16, x17, [sp, #0x80]\n\t"                         \
                   "str x30, [sp, #0x90]\n\t"                              \
                   "mrs x16, NZCV\n\t"                                     \
                   "str x16, [sp, #0x98]\n\t"                              \
                   "bl " __ASM_NAME("__wine_get_current_teb_for_x18") "\n\t" \
                   "mov x17, x0\n\t"                                       \
                   "mov x18, x0\n\t"                                       \
                   "ldr x16, [sp, #0x98]\n\t"                              \
                   "msr NZCV, x16\n\t"                                     \
                   "ldr x30, [sp, #0x90]\n\t"                              \
                   "ldr x16, [sp, #0x80]\n\t"                              \
                   "ldp x14, x15, [sp, #0x70]\n\t"                         \
                   "ldp x12, x13, [sp, #0x60]\n\t"                         \
                   "ldp x10, x11, [sp, #0x50]\n\t"                         \
                   "ldp x8,  x9,  [sp, #0x40]\n\t"                         \
                   "ldp x6,  x7,  [sp, #0x30]\n\t"                         \
                   "ldp x4,  x5,  [sp, #0x20]\n\t"                         \
                   "ldp x2,  x3,  [sp, #0x10]\n\t"                         \
                   "ldp x0,  x1,  [sp, #0x00]\n\t"                         \
                   "add sp, sp, #0xb0\n\t"                                \
                     "9:\n\t"

static volatile sig_atomic_t macrunner_fex_kusd_backend;

/* Re-execute only a side-effect-free address calculation, never the store.
 * All three instructions and the saved effective address must agree. */
static BOOL macrunner_fex_resume_address_matches( ULONG previous, ULONG instruction,
                                                ULONG next, ULONG64 base, ULONG64 address )
{
    ULONG64 immediate;
    unsigned int rn = (previous >> 5) & 31;

    /* Rt is the stored value, not the address register. Match every X-register
     * variant of STR Xt,[x16,xzr]; the ADD/SUB and saved-address checks below
     * still prove that replaying the address calculation is safe. */
    if (instruction != 0xd5033bbf || (next & ~31u) != 0xf83f6a00) return FALSE;
    if ((previous & 0xbf800000) != 0x91000000 || (previous & 31) != 16) return FALSE;
    if (rn == 16 || rn == 18 || rn == 31) return FALSE;
    immediate = (previous >> 10) & 0xfff;
    if (previous & (1u << 22)) immediate <<= 12;
    return address == ((previous & (1u << 30)) ? base - immediate : base + immediate);
}

/* ★★★ x18-compat 30.09.2026 — ДОВЕРИЕ К ABI x18 ЯДРА. Гейт MACRUNNER_HB_X18_TRUST_ABI=1, умолчание 0.
 *
 * ИЗМЕРЕНО родной пробой (artifacts/claude-hb-work/x18-compat-20260930/probe, по 10 000 повторов, macOS 27.0):
 *   sdk главного образа >= 13, режим по умолчанию: x18 обнуляется на КАЖДОМ возврате из syscall, на
 *     вытеснении и на sigreturn; x18, записанный обработчиком в ucontext, ядро при этом игнорирует;
 *   тот же двоичный с os_set_custom_x18_abi_enabled(true) на потоке ЛИБО с sdk < 13 (старый режим):
 *     ноль потерь везде, и sigreturn берёт x18 ИЗ ucontext.
 * os_custom_x18_abi_enabled() = бит 48 TPIDR_EL0 (libsystem_kernel: mrs x8,TPIDR_EL0; ubfx; ret), вызов
 * безопасен в обработчике сигнала. Бит стоит в обоих «хороших» режимах: macrunner_enable_windows_x18_abi()
 * включает его на каждом потоке Wine, а при sdk < 13 его ставит само ядро.
 *
 * Отсюда: когда бит стоит, трамплин не нужен — достаточно REGn_sig(18) = teb, ядро вернёт x18 при
 * sigreturn, а поток продолжит РОВНО с того PC, что стоит в контексте. Трамплин же жертвует x17/x16/Rt,
 * которые у FEX бывают живыми (стены 1-3; Indiana R9: NtContinue -> slowpath -> SIGUSR2 -> трамплин r16 ->
 * stur [x16] в собственный код).
 *
 * ПРИБОР, безусловный, счётчики на процесс: трамплин поставлен (через x17 / через мёртвый Rt / вестибюль EC /
 * перезапуск своего трамплина / лечение при x18 == 0) и пропущен по гейту. Строка `macrunner-x18-resume:`
 * печатается при запуске процесса (why=init), на 1, 2, 4, ... 65536 событиях и дальше каждые 65536
 * (why=count), и при выходе (why=exit, atexit). kernel_keeps — бит на ТОМ потоке, что печатает. */
struct macrunner_x18_counters
{
    int gate;   /* 0: ещё не прочитан (до signal_init_threading) = выключен; 1: выключен; 2: включён */
    unsigned long long events, skip, thunk_x17, thunk_rt, veneer, restart, heal_thunk, gate_nokeep;
};
/* Отдельная zerofill-секция: компоновщик кладёт её ПОСЛЕ __bss, поэтому адреса прежних переменных ntdll.so не
 * сдвигаются и остальные функции образа остаются прежними (сверка cmp-image.py против 1.0.5). */
static struct macrunner_x18_counters macrunner_x18 __attribute__((section("__DATA,__mr_x18,zerofill")));

static void macrunner_x18_resume_report( const char *why )
{
    macrunner_signal_writef( "macrunner-x18-resume: why=%s pid=%d gate=%d kernel_keeps=%d events=%llu skipped=%llu "
                             "thunk_x17=%llu thunk_rt=%llu veneer=%llu restart=%llu heal_thunk=%llu gate_on_kernel_zeroes=%llu\n",
                             why, (int)getpid(), macrunner_x18.gate ? macrunner_x18.gate - 1 : -1,
                             os_custom_x18_abi_enabled ? (int)os_custom_x18_abi_enabled() : -1,
                             __atomic_load_n( &macrunner_x18.events, __ATOMIC_RELAXED ),
                             __atomic_load_n( &macrunner_x18.skip, __ATOMIC_RELAXED ),
                             __atomic_load_n( &macrunner_x18.thunk_x17, __ATOMIC_RELAXED ),
                             __atomic_load_n( &macrunner_x18.thunk_rt, __ATOMIC_RELAXED ),
                             __atomic_load_n( &macrunner_x18.veneer, __ATOMIC_RELAXED ),
                             __atomic_load_n( &macrunner_x18.restart, __ATOMIC_RELAXED ),
                             __atomic_load_n( &macrunner_x18.heal_thunk, __ATOMIC_RELAXED ),
                             __atomic_load_n( &macrunner_x18.gate_nokeep, __ATOMIC_RELAXED ) );
}

static void macrunner_x18_resume_note( unsigned long long *counter )
{
    unsigned long long n;

    __atomic_add_fetch( counter, 1, __ATOMIC_RELAXED );
    n = __atomic_add_fetch( &macrunner_x18.events, 1, __ATOMIC_RELAXED );
    if (!(n & (n - 1)) || !(n & 0xffff)) macrunner_x18_resume_report( "count" );
}

static void macrunner_x18_resume_atexit(void)
{
    macrunner_x18_resume_report( "exit" );
}

/* Зовётся из signal_init_threading (главный поток, до любого кода PE): гейт читается ОДИН раз и не из обработчика. */
static void macrunner_x18_trust_abi_init(void)
{
    const char *v;

    if (macrunner_x18.gate) return;
    v = getenv( "MACRUNNER_HB_X18_TRUST_ABI" );
    macrunner_x18.gate = (v && v[0] == '0') ? 1 : 2;
    atexit( macrunner_x18_resume_atexit );
    macrunner_x18_resume_report( "init" );
}

static void setup_x18_resume_from_sigcontext( ucontext_t *context )
{
    static int rt_mode = -1;
    TEB *teb = macrunner_teb_reliable();  /* НЕ NtCurrentTeb(): на ARM64 это x18, который здесь и затёрт */
    struct ntdll_thread_data *thread_data = (struct ntdll_thread_data *)&teb->GdiTebBatch;
    ULONG_PTR pc = PC_sig(context);

    /* The resume thunk itself is vulnerable to asynchronous signals on
     * macOS: xnu clears x18 on sigreturn, and Wine may suspend/debug a
     * thread while it is between "mov x18, x10" and "br x17".  Do not
     * overwrite apple_x18_save_pc in that window, otherwise x17 reloads
     * the thunk address and we spin forever in __wine_pe_x18_resume_thunk.
     * Re-enter the thunk from the beginning with x10=TEB and preserve the
     * original saved x10/x16/pc slots. */
    if (apple_x18_restart_owned_thunk( context, teb ))
    {
        macrunner_x18_resume_note( &macrunner_x18.restart );
        return;
    }

    /* x18-compat: ядро само вернёт x18 из контекста — ни трамплина, ни жертвы регистра, PC прежний. */
    if (macrunner_x18.gate == 2)
    {
        if (os_custom_x18_abi_enabled && os_custom_x18_abi_enabled())
        {
            REGn_sig(18, context) = (ULONG_PTR)teb;
            macrunner_x18_resume_note( &macrunner_x18.skip );
            return;
        }
        macrunner_x18_resume_note( &macrunner_x18.gate_nokeep );   /* гейт включён, но на этом потоке ядро x18 стирает */
    }

    if (macrunner_fex_kusd_backend && is_arm64ec() && is_ec_code( pc ))
    {
        int saved_errno = errno;
        ULONG_PTR veneer = mr_direct_prepare( (ULONG_PTR)teb, pc );
        static unsigned int direct_resumes, allocation_failures;
        errno = saved_errno;
        if (veneer)
        {
            unsigned int n = __atomic_add_fetch( &direct_resumes, 1, __ATOMIC_RELAXED );
            PC_sig(context) = veneer;
            REGn_sig(18, context) = (ULONG_PTR)teb;
            macrunner_x18_resume_note( &macrunner_x18.veneer );
            if (n <= 24)
                macrunner_signal_writef( "mr-direct-resume: n=%u pc=%p veneer=%p\n",
                    n, (void *)pc, (void *)veneer );
            return;
        }
        if (__atomic_add_fetch( &allocation_failures, 1, __ATOMIC_RELAXED ) <= 8)
            macrunner_signal_writef( "mr-direct-resume: allocation-failed pc=%p\n", (void *)pc );
    }

    if (rt_mode < 0)
    {
        const char *v = getenv( "MACRUNNER_HB_X18_RESUME_RT" );
        rt_mode = (v && *v == '0') ? 0 : 1;
    }
    if (rt_mode && macrunner_fex_kusd_backend && macrunner_cpu_backend_disables_hb_semantics() &&
        pc >= 4 && pc <= ~(ULONG_PTR)0 - 4 && !(pc & 3) &&
        macrunner_addr_in_jit_view( (const void *)(pc - 4) ) &&
        macrunner_addr_in_jit_view( (const void *)pc ) &&
        macrunner_addr_in_jit_view( (const void *)(pc + 4) ))
    {
        ULONG previous, instruction, next;
        if (macrunner_signal_read_u32_aligned( pc - 4, &previous ) &&
            macrunner_signal_read_u32_aligned( pc, &instruction ) &&
            macrunner_signal_read_u32_aligned( pc + 4, &next ) &&
            ((previous >> 5) & 31) != 31 &&
            macrunner_fex_resume_address_matches( previous, instruction, next,
                REGn_sig((previous >> 5) & 31, context), REGn_sig(16, context) ))
        {
            static unsigned int rematerializations;
            unsigned int n = __atomic_add_fetch( &rematerializations, 1, __ATOMIC_RELAXED );
            if (n <= 16)
                fprintf( stderr, "mr-fex-resume-address: n=%u pc=%#llx resume=%#llx "
                         "rn=%u base=%#llx x16=%#llx x17=%#llx\n", n,
                         (unsigned long long)pc, (unsigned long long)(pc - 4),
                         (unsigned)((previous >> 5) & 31),
                         (unsigned long long)REGn_sig((previous >> 5) & 31, context),
                         (unsigned long long)REGn_sig(16, context),
                         (unsigned long long)REGn_sig(17, context) );
            pc -= 4;
            PC_sig(context) = pc;
        }
    }

    thread_data->apple_x18_save_x10 = REGn_sig(10, context);
    thread_data->apple_x18_save_x16 = REGn_sig(16, context);
    thread_data->apple_x18_save_pc  = PC_sig(context);
    REGn_sig(10, context) = (ULONG_PTR)teb;
    REGn_sig(18, context) = (ULONG_PTR)teb;

    /* ★★★★★★ СТЕНА64 08.09.2026 — ТОТ ЖЕ ДОВОД ШАГ-4, НО НА ПУТИ ВОЗОБНОВЛЕНИЯ.
     *
     * ШАГ-4 (выше, `emulate_apple_x18_teb_access`) доказал и починил: трамплин
     * ветвится ЧЕРЕЗ x17, а у рукописного ассемблера FEX x17 ЖИВОЙ. Но починка
     * встала ТОЛЬКО на путь эмуляции x18. Сюда, в общий возврат из сигнала, её не
     * донесли — и здесь `PC_sig = __wine_pe_x18_resume_thunk` по-прежнему жертвовал
     * x17 безусловно.
     *
     * ЗАМЕР, назвавший это место (прогон r2/r3, notepad++ x86-64, прибор внутри FEX
     * плюс наш зонд возобновления):
     *     MR-STENA64 unaligned-exit: x17=6FFEAE620FB0  <- ВЕРНЫЙ, внутри стека возвратов
     *     macrunner-st64-resume n=4:  frame_x17=0x6ffeae620fb0  отвод=0  ec_code(pc)=1
     *     macrunner-st64-slowpath n=3: x17=0x6ffeae620fb0   <- в кадре ещё верный
     *     macrunner-st64-usr2   n=3: внутри_вызова=1  x17_кадра=0x6ffeae620fb0
     *     ... и на следующем отказе x17=0x10f1eda38 = РОВНО pc возобновления.
     * То есть все наши слои отдают верный x17, и портит его последний шаг — трамплин.
     * REG_CALLRET_SP у FEX в конфигурации ARM64EC — это x17 (Arm64Emitter.h:68),
     * поэтому следом `stp x6,x10,[x17,#-0x10]!` пишет в СВОЮ ЖЕ кодовую страницу.
     *
     * ЛЕЧЕНИЕ — довод ШАГ-4 дословно: ветвиться через регистр, МЁРТВЫЙ ПО
     * ПОСТРОЕНИЮ. Здесь возобновление идёт на произвольный адрес, но если команда
     * ПО ЭТОМУ адресу — загрузка, её приёмник Rt она сама и перепишет раньше, чем
     * кто-либо его прочтёт. Значит через Rt ветвиться безопасно, и ни один живой
     * регистр не портится.
     *
     * ГРАНИЦЫ, названные прямо (внешнее ограничение набора команд, не наша
     * недоделка): ветвление на AArch64 обязано идти через регистр, поэтому когда
     * команда по адресу возврата НЕ загрузка (или Rt совпал с базой, или Rt = 18/31)
     * — мёртвого регистра не существует, и остаётся прежняя жертва x17. Остаток
     * считается и печатается ниже.
     *
     * Гейт MACRUNNER_HB_X18_RESUME_RT=0 возвращает прежнее поведение — отрицательный
     * контроль идёт НА ОДНОМ двоичном, а не сравнением двух сборок. */
    {
        unsigned int rt = 32;
        DWORD insn = 0;


        if (rt_mode && pc && !(pc & 3))
        {
            unsigned int rn, rt2;

            insn = *(const DWORD *)(ULONG_PTR)pc;
            rn  = (insn >> 5) & 0x1f;
            rt  = insn & 0x1f;
            rt2 = (insn >> 10) & 0x1f;

            /* Три семейства ЗАГРУЗОК в регистр общего назначения (бит 22 = загрузка):
             *   ldr  Rt,[Rn,#uimm]      (insn & 0x3b000000) == 0x39000000
             *   ldur/пред/пост-индекс   (insn & 0x3b200000) == 0x38000000
             *   ldp  Rt,Rt2,[Rn,...]    (insn & 0x3a000000) == 0x28000000
             * Приёмник мёртв, только если он не совпал с базой (иначе при обратной
             * записи в базу поведение не определено) и не равен x18/xzr. */
            if (!(((insn & 0x3b000000) == 0x39000000 ||
                   (insn & 0x3b200000) == 0x38000000 ||
                   (insn & 0x3a000000) == 0x28000000) && ((insn >> 22) & 1)))
                rt = 32;
            else if (rt == rn || rt == 18 || rt == 31) rt = 32;
            else if ((insn & 0x3a000000) == 0x28000000 && rt == rt2) rt = 32;
            else if (!apple_x18_resume_by_rt[rt]) rt = 32;

            /* ★★★ ОСТАТОК, КОТОРЫЙ И ЕСТЬ НАША СТЕНА: команда по адресу возврата —
             * не загрузка (замер: `d5033bbf` = `dmb ish`, начало атомарной
             * последовательности, куда FEX отвёл pc после разбора невыровненного
             * доступа). Мёртвого приёмника нет, и прежний код жертвовал x17.
             *
             * Но ВНУТРИ КОДОВОГО БУФЕРА FEX выбор не является догадкой: распределение
             * регистров задано самим FEX (FEXCore/.../Arm64Emitter.h, ветвь
             * ARCHITECTURE_arm64ec):
             *     REG_CALLRET_SP = x17   TMP1..TMP4 = x10..x13
             *     REG_PF = x9   REG_AF = x24   EC_CALL_CHECKER_PC_REG = x9
             *     EC_ENTRY_CPUAREA_REG = x17
             * x16 в этом перечне НЕ УПОМЯНУТ ВООБЩЕ — у выпущенного FEX кода он роли
             * не несёт, тогда как x17 несёт указатель стека возвратов и живёт через
             * весь блок. Поэтому в буфере жертвуем x16, а не x17.
             *
             * Готовый трамплин для этого УЖЕ ЕСТЬ — `__wine_pe_x18_resume_thunk_r16`
             * из таблицы ШАГ-4: он ветвится через x16 и x17 НЕ ТРОГАЕТ ВОВСЕ, то есть
             * x17 доезжает тем, каким его положил `usr2_handler`.
             *
             * ГРАНИЦА: только внутри области MAP_JIT. В рукописном ассемблере самого
             * `xtajit64.dll` (напр. `ExitToX64`: `mov w16,#1` / `strb w16,[x17]`)
             * ЖИВЫ ОБА, и там остаётся прежняя жертва x17. */
            if (rt == 32 && macrunner_addr_in_jit_view( (const void *)(ULONG_PTR)pc ))
                rt = 16;
        }

        {
            static unsigned long long st64_rt_n, st64_x17_n;
            unsigned long long n = (rt < 32) ? __atomic_add_fetch( &st64_rt_n, 1, __ATOMIC_RELAXED )
                                             : __atomic_add_fetch( &st64_x17_n, 1, __ATOMIC_RELAXED );
            if (n <= 8)
                fprintf( stderr, "macrunner-st64-thunk: pc=%#llx insn=%08x reshenie=%s rt=%u"
                         " zhivyh_rt=%llu ostatok_x17=%llu\n",
                         (unsigned long long)pc, (unsigned int)insn,
                         (rt < 32) ? "RT" : "X17", rt,
                         (unsigned long long)__atomic_load_n( &st64_rt_n, __ATOMIC_RELAXED ),
                         (unsigned long long)__atomic_load_n( &st64_x17_n, __ATOMIC_RELAXED ) );
        }

        PC_sig(context) = (rt < 32) ? (ULONG_PTR)apple_x18_resume_by_rt[rt]
                                    : (ULONG_PTR)__wine_pe_x18_resume_thunk;
        macrunner_x18_resume_note( (rt < 32) ? &macrunner_x18.thunk_rt : &macrunner_x18.thunk_x17 );
    }
}
#endif

/* MacRunner 04.08 16:50 — ПОЧЕМУ ВЫБОР СТЕКА ОТКАЗАЛ.
 *
 * Измерено по логам 04.08: перенаправление на стек обратного вызова срабатывает 111 раз, но из
 * 25 доставок, печатающих -record-overlap, им не воспользовалась НИ ОДНА (`callback_stack=1` — 0
 * штук). То есть на всех сбойных доставках эта функция вернула FALSE, и кадр лёг на сырой SP —
 * который в 13 случаях из 25 указывает в сам TEB. Отказов здесь четыре разных, и лечатся они
 * по-разному, поэтому нужен не факт отказа, а его причина. Код причины кладём в переменную
 * потока и печатаем в уже существующей строке. */
enum
{
    MACRUNNER_HB_CBSTACK_OK = 0,
    MACRUNNER_HB_CBSTACK_NO_TEB,        /* нет TEB */
    MACRUNNER_HB_CBSTACK_NO_FRAME,      /* нет кадра системного вызова */
    MACRUNNER_HB_CBSTACK_NO_FRAME_SP,   /* кадр есть, сохранённый SP нулевой */
    MACRUNNER_HB_CBSTACK_BAD_BOUNDS,    /* границы стека в TEB испорчены — уже затёрты */
    MACRUNNER_HB_CBSTACK_SP_IN_STACK,   /* SP на своём стеке, перенаправлять незачем */
    MACRUNNER_HB_CBSTACK_SAVED_OUT,     /* сохранённый SP вне границ стека */
    MACRUNNER_HB_CBSTACK_BACKEND_DISABLED,
};
static __thread int macrunner_hb_cbstack_decline;

static BOOL macrunner_hb_get_callback_exception_stack( ucontext_t *context, void **stack_ptr )
{
    static int report_count;
    TEB *teb;
    struct syscall_frame *frame;
    char *sp;
    char *limit, *base, *saved_sp;

    /* FEX owns its interrupted emulator stack. A stale HB syscall SP can
     * place signal delivery over a live x64 return slot on the guest stack. */
    if (macrunner_cpu_backend_disables_hb_semantics())
    { macrunner_hb_cbstack_decline = MACRUNNER_HB_CBSTACK_BACKEND_DISABLED; return FALSE; }

    teb = macrunner_teb_reliable();  /* НЕ NtCurrentTeb(): на ARM64 это x18, который здесь и затёрт */
    frame = get_syscall_frame();
    sp = (char *)SP_sig( context );

    if (!teb)        { macrunner_hb_cbstack_decline = MACRUNNER_HB_CBSTACK_NO_TEB;      return FALSE; }
    if (!frame)      { macrunner_hb_cbstack_decline = MACRUNNER_HB_CBSTACK_NO_FRAME;    return FALSE; }
    if (!frame->sp)  { macrunner_hb_cbstack_decline = MACRUNNER_HB_CBSTACK_NO_FRAME_SP; return FALSE; }
    limit = teb->Tib.StackLimit;
    base = teb->Tib.StackBase;
    if (!limit || !base || limit >= base)
    { macrunner_hb_cbstack_decline = MACRUNNER_HB_CBSTACK_BAD_BOUNDS; return FALSE; }

    if (sp >= limit && sp < base)
    { macrunner_hb_cbstack_decline = MACRUNNER_HB_CBSTACK_SP_IN_STACK; return FALSE; }
    saved_sp = (char *)(ULONG_PTR)frame->sp;
    if (saved_sp <= limit || saved_sp > base)
    { macrunner_hb_cbstack_decline = MACRUNNER_HB_CBSTACK_SAVED_OUT; return FALSE; }

    macrunner_hb_cbstack_decline = MACRUNNER_HB_CBSTACK_OK;
    if (stack_ptr) *stack_ptr = saved_sp;
    if (report_count++ < 16)
    {
        struct macrunner_hb_signal_module_info pc_info, lr_info;
        Dl_info sig_info;
        BOOL have_pc = macrunner_hb_signal_find_loader_module( (ULONG_PTR)frame->pc, &pc_info );
        BOOL have_lr = macrunner_hb_signal_find_loader_module( (ULONG_PTR)frame->lr, &lr_info );
        BOOL have_sig = dladdr( (void *)(ULONG_PTR)PC_sig( context ), &sig_info );

        macrunner_signal_writef( "macrunner-hb-callback-exception-stack: pid=%d "
                                 "pc=%p sp=%p delivery_sp=%p frame=%p frame_sp=%p "
                                 "sig_x10=%p sig_x16=%p sig_x18=%p frame_prev=%p "
                                 "frame_pc=%p frame_lr=%p kernel_stack=%p teb_stack=%p-%p\n",
                                 getpid(), (void *)(ULONG_PTR)PC_sig( context ), sp,
                                 saved_sp, frame, (void *)(ULONG_PTR)frame->sp,
                                 (void *)(ULONG_PTR)REGn_sig( 10, context ),
                                 (void *)(ULONG_PTR)REGn_sig( 16, context ),
                                 (void *)(ULONG_PTR)REGn_sig( 18, context ),
                                 frame->prev_frame,
                                 (void *)(ULONG_PTR)frame->pc,
                                 (void *)(ULONG_PTR)frame->lr,
                                 ntdll_get_thread_data()->kernel_stack, limit, base );
        macrunner_signal_writef( "macrunner-hb-callback-exception-sig-map: pid=%d "
                                 "sig_pc=%p sig_image=%s sig_base=%p sig_rva=0x%llx "
                                 "sig_symbol=%s sig_symbol_addr=%p sig_symbol_off=0x%llx "
                                 "sig_x10=%p sig_x16=%p sig_x18=%p\n",
                                 getpid(), (void *)(ULONG_PTR)PC_sig( context ),
                                 have_sig && sig_info.dli_fname ? sig_info.dli_fname : "(none)",
                                 have_sig ? sig_info.dli_fbase : NULL,
                                 have_sig && sig_info.dli_fbase ?
                                     (unsigned long long)(PC_sig( context ) - (ULONG_PTR)sig_info.dli_fbase) : 0,
                                 have_sig && sig_info.dli_sname ? sig_info.dli_sname : "(none)",
                                 have_sig ? sig_info.dli_saddr : NULL,
                                 have_sig && sig_info.dli_saddr ?
                                     (unsigned long long)(PC_sig( context ) - (ULONG_PTR)sig_info.dli_saddr) : 0,
                                 (void *)(ULONG_PTR)REGn_sig( 10, context ),
                                 (void *)(ULONG_PTR)REGn_sig( 16, context ),
                                 (void *)(ULONG_PTR)REGn_sig( 18, context ) );
        macrunner_signal_writef( "macrunner-hb-callback-exception-frame-map: pid=%d "
                                 "frame_pc=%p pc_module=%s pc_native=%p pc_rva=0x%llx "
                                 "frame_lr=%p lr_module=%s lr_native=%p lr_rva=0x%llx "
                                 "pc_found=%u lr_found=%u\n",
                                 getpid(), (void *)(ULONG_PTR)frame->pc,
                                 pc_info.name, pc_info.base,
                                 (unsigned long long)pc_info.rva,
                                 (void *)(ULONG_PTR)frame->lr,
                                 lr_info.name, lr_info.base,
                                 (unsigned long long)lr_info.rva,
                                 have_pc, have_lr );
    }
    return TRUE;
}

/***********************************************************************
 *           setup_raise_exception
 */
/* MacRunner 2026-08-03 night — WAS THE LR SLOT INSIDE A DELIVERY WRITE?
 *
 * Everything measured so far says the stalled thread RETs to &rec of a delivery layout (x30 == pc,
 * pc == rec_addr, pc - sp == 0x1020 bit-for-bit across three runs).  Two stories survive and they
 * are told apart by ONE fact: whether the stack slot the epilogue loaded LR from was inside a range
 * that this process's own delivery wrote.  Reasoning cannot settle it — the delivery that did it
 * happened long before the fault — so remember every delivery write range per thread and ask the
 * question at fault time.  Eight entries is enough: the stall follows the delivery closely, and a
 * fixed ring costs nothing on a path that already writes 1 136 bytes. */
static ULONG64 macrunner_hb_current_thread_id(void)
{
    uint64_t tid = 0;
    pthread_threadid_np( NULL, &tid );
    return (ULONG64)tid;
}

#define MACRUNNER_HB_DELIVERY_RING 8
struct macrunner_hb_delivery_note
{
    ULONG64 lo, hi, rec_addr, code, interrupted_sp, seq;
};
static __thread struct macrunner_hb_delivery_note macrunner_hb_delivery_ring[MACRUNNER_HB_DELIVERY_RING];
static __thread ULONG64 macrunner_hb_delivery_seq;

static void macrunner_hb_note_delivery( const void *lo, size_t size, const void *rec_addr,
                                        ULONG64 code, ULONG64 interrupted_sp )
{
    ULONG64 n = ++macrunner_hb_delivery_seq;
    struct macrunner_hb_delivery_note *slot =
        &macrunner_hb_delivery_ring[(n - 1) % MACRUNNER_HB_DELIVERY_RING];

    slot->lo = (ULONG64)(ULONG_PTR)lo;
    slot->hi = slot->lo + size;
    slot->rec_addr = (ULONG64)(ULONG_PTR)rec_addr;
    slot->code = code;
    slot->interrupted_sp = interrupted_sp;
    slot->seq = n;
}

/* MacRunner 2026-08-04 — the host image base, printed ONCE, from dyld itself.
 *
 * Every host address in this log (lr, saved return addresses, the stack windows) only means
 * something against ntdll.so's load base, and deriving that base from the dispatcher cells is
 * WRONG in this build — it yields an unaligned value and already produced one retracted
 * attribution.  Recovering it by hand cost a 25 s run plus a `sample`; printing it costs one line.
 *
 * It runs as a CONSTRUCTOR, on a normal thread at load time, and deliberately NOT from the signal
 * handler: dladdr takes dyld's locks, so calling it from a handler can deadlock against a signal
 * that arrived while those locks were held.  The first attempt did exactly that and the run was
 * SIGKILLed at +26 s with the line never printed — a diagnostic must not be able to kill the
 * measurement it serves. */
/* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1121 — БАЗА РЯДОМ С ОТКАЗОМ, А НЕ ОТДЕЛЬНОЙ
 * СТРОКОЙ. Отдельную строку печатает КАЖДЫЙ процесс wine (в прогоне esaonly их четырнадцать), и
 * сопоставить её с упавшим процессом нечем — из-за этого символ в 1120 остался неназванным.
 * Держим базу в глобали и печатаем ПРЯМО В СТРОКЕ ОТКАЗА: тогда разрешение адреса не требует
 * никакого сопоставления. */
static void *macrunner_hb_host_base;
static void macrunner_hb_print_host_base(void) __attribute__((constructor));
static void macrunner_hb_print_host_base(void)
{
    Dl_info di;

    /* ★★★★ 28.08.2026 — ОТВОД ЖУРНАЛА В ФАЙЛ, ПО ОДНОМУ НА ПРОЦЕСС.
     *
     * Diablo.exe оказался ЛАУНЧЕРОМ: он зовёт CreateProcessA с inherit=FALSE, поэтому дочерний
     * процесс — а это и есть настоящая игра — НЕ наследует наш вывод. Замер 28.08: дочерний
     * живёт все 240 секунд бюджета, а в журнале лейна о нём нет ни строки, и все выводы
     * (10 вех ddraw, команды wined3d) принадлежат лаунчеру, который вышел на 56-й секунде.
     *
     * `WINEDEBUGLOG` для этого не годится: в дереве он разобран только в Android-ветке
     * загрузчика (loader.c:3163, под JNI).
     *
     * Здесь: если задан `MACRUNNER_LOG_DIR`, каждый процесс дублирует свой stderr в
     * `<каталог>/proc-<pid>.log`. Переменные окружения дочерний наследует всегда, поэтому
     * файл появится и у него. Умолчание — ничего не делать. */
    {
        const char *dir = getenv( "MACRUNNER_LOG_DIR" );

        if (dir && dir[0])
        {
            char path[1024];
            int fd;

            snprintf( path, sizeof(path), "%s/proc-%d.log", dir, (int)getpid() );
            fd = open( path, O_WRONLY | O_CREAT | O_APPEND, 0644 );
            if (fd != -1)
            {
                /* ★ ВАЖНО для лейнов: это ЗАМЕНА stderr, а не копия. Пока переменная задана,
                 * журнал прогона (`run.log`) остаётся ПУСТЫМ — весь вывод уходит в файлы по
                 * процессам. Поймано замером 28.08: `строк=0` в итоге при 24 живых proc-*.log.
                 * Поэтому переменную включать только тогда, когда нужен именно разбор по
                 * процессам, и смотреть тогда `proc-<pid>.log`, а не `run.log`. */
                dup2( fd, 2 );
                if (fd != 2) close( fd );
                fprintf( stderr, "macrunner-журнал-процесса: pid=%d файл=%s\n", (int)getpid(), path );
                fflush( stderr );
            }
        }
    }

    /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1120 — PID В ПЕЧАТЬ БАЗЫ.
     *
     * Без pid эта строка НЕ ГОДИТСЯ для разрешения адреса: в одном журнале её печатает КАЖДЫЙ
     * процесс wine, и в прогоне `esaonly` их оказалось ЧЕТЫРНАДЦАТЬ с разными базами. Выбрать
     * из четырнадцати «ту самую» нечем, а урок лейна (LESSONS, строка 48) прямо требует брать
     * карту ТОГО процесса, что упал. Я на этом и споткнулся: символ
     * `macrunner_hb_arm64_pe_call12 + 284` получился подбором базы, то есть не доказан.
     *
     * Один %d закрывает класс — ровно так же, как он закрыл его для счётчика диспетчеризаций
     * (hb_runtime.c, итерация 327). */
    /* ★★★ 26.08.2026 — КАРТА ВСЕХ МОДУЛЕЙ, А НЕ ОДНОГО.
     *
     * Базы сдвигаются между прогонами. Имея в журнале только ntdll.so, я пересчитал
     * адрес отказа по базе win32u.so ИЗ ДРУГОГО ЖУРНАЛА и получил `stretch_bitmapinfo`,
     * которого на пути не было: прибор, поставленный в эту функцию, дал ноль. Заход
     * потерян на неверном сопоставлении.
     *
     * Печатаем карту здесь, в КОНСТРУКТОРЕ: `dladdr` берёт замки dyld, и вызов из
     * обработчика сигнала уже приводил к взаимоблокировке (см. шапку выше — прогон был
     * убит на +26 с). Разрешение адресов делается офлайн, по этой карте. */
    {
        extern uint32_t _dyld_image_count( void );
        extern const char *_dyld_get_image_name( uint32_t );
        extern const void *_dyld_get_image_header( uint32_t );
        uint32_t i, n = _dyld_image_count();
        for (i = 0; i < n; i++)
        {
            const char *имя = _dyld_get_image_name( i );
            const void *база = _dyld_get_image_header( i );
            const char *к;
            if (!имя || !база) continue;
            к = strrchr( имя, '/' );
            /* только наши модули: системных сотни, они шума не стоят */
            if (!strstr( имя, "/lib/wine/" ) && !strstr( имя, "MacRunner" )) continue;
            fprintf( stderr, "macrunner-hb-модуль: pid=%d base=%p %s\n",
                     (int)getpid(), база, к ? к + 1 : имя );
        }
        fflush( stderr );
    }
    if (dladdr( (void *)(ULONG_PTR)macrunner_hb_print_host_base, &di ))
    {
        macrunner_hb_host_base = di.dli_fbase;
        fprintf( stderr, "macrunner-hb-host-base: pid=%d ntdll_so=%p path=%s\n",
                 (int)getpid(), di.dli_fbase, di.dli_fname ? di.dli_fname : "?" );

        /* ПОЧЕМУ ntdll.so ДРОЖИТ. Гостевое окно и база wine закрепляются
         * (MACRUNNER_HB_GUEST32_BASE + scripts/без-aslr), а база ntdll.so нет:
         * замер дал 5 разных значений из 6 в пределах 960 КБ даже с выключенным
         * ASLR. Гадать нечем — печатаем в ОДНОЙ точке всё, что лежит ниже него:
         * какая область непосредственно предшествует и сколько всего образов.
         * Diff двух прогонов называет виновника сам.
         * Гейт MACRUNNER_HB_RASKLADKA_DUMP; вхолостую не печатает ничего. */
        if (getenv( "MACRUNNER_HB_RASKLADKA_DUMP" ))
        {
            extern uint32_t _dyld_image_count( void );
            extern const char *_dyld_get_image_name( uint32_t );
            extern const void *_dyld_get_image_header( uint32_t );
            mach_vm_address_t адрес = 0;
            uint32_t i, n = _dyld_image_count(), ниже = 0;

            for (i = 0; i < n; i++)
                if ((ULONG_PTR)_dyld_get_image_header( i ) < (ULONG_PTR)di.dli_fbase) ниже++;
            fprintf( stderr, "macrunner-раскладка-дамп: pid=%d образов=%u ниже_ntdll=%u\n",
                     (int)getpid(), n, ниже );

            /* Все области от нуля до базы ntdll.so: их суммарный размер и число
             * и есть то, что сдвигает его вверх. */
            for (;;)
            {
                mach_vm_size_t размер = 0;
                vm_region_extended_info_data_t инфо;   /* расширенная: несёт user_tag — КТО владелец */
                mach_msg_type_number_t счёт = VM_REGION_EXTENDED_INFO_COUNT;
                mach_port_t объект = MACH_PORT_NULL;

                if (mach_vm_region( mach_task_self(), &адрес, &размер, VM_REGION_EXTENDED_INFO,
                                    (vm_region_info_t)&инфо, &счёт, &объект ) != KERN_SUCCESS) break;
                if (адрес >= (mach_vm_address_t)(ULONG_PTR)di.dli_fbase) break;
                fprintf( stderr, "macrunner-раскладка-область: %llx+%llx prot=%x метка=%u\n",
                         (unsigned long long)адрес, (unsigned long long)размер,
                         инфо.protection, (unsigned)инфо.user_tag );
                адрес += размер;
            }
            fflush( stderr );
        }
    }
    else
        fprintf( stderr, "macrunner-hb-host-base: pid=%d dladdr-failed fn=%p\n",
                 (int)getpid(), (void *)(ULONG_PTR)macrunner_hb_print_host_base );
    fflush( stderr );
}

/* ★★★★★ MacRunner 2026-08-29 — ЗАЩЁЛКА ПОВТОРНОГО ВХОДА В ДОСТАВКУ.
 *
 * Классификатор корней (`scripts/корни-отказов.sh`) выделил у Diablo единственный
 * настоящий дефект среди 4113 отказов:
 *
 *   c000001d ILLEGAL_INSTRUCTION  addr=186D27758
 *     /usr/lib/system/libsystem_platform.dylib +0x3758,  d4200020 = BRK #1
 *   exception-record-overlap: write=0x10e1cead0-0x10e1cef40 size=1136
 *                             interrupted_sp=0x10e1cef40 delivery_sp=0x10e1cef40
 *
 * Запись доставки (1136 байт) кладётся вплотную под прерванный SP, а стек доставки
 * СОВПАДАЕТ с прерванным. Если во время доставки прилетает ещё один сигнал, вторая
 * запись ложится на ту же память и затирает первую — каскад, который здесь и ловится
 * прибором `overlap`.
 *
 * Решение взято у эталона и уже было записано в комментарии ниже по файлу: у Prism
 * `Wow64PrepareForException` ПЕРВОЙ операцией читает поле-защёлку в TEB и при
 * взведённой выходит, ничего не готовя. Делаем то же: поток, уже находящийся внутри
 * доставки, второй раз в неё не входит.
 *
 * Защёлка потоковая (`__thread`), поэтому не мешает другим потокам доставлять свои
 * исключения одновременно. Снимается в конце доставки — на всех путях выхода. */
static __thread int macrunner_hb_in_delivery;

static void setup_raise_exception( ucontext_t *sigcontext, EXCEPTION_RECORD *rec, CONTEXT *context )
{
    struct exc_stack_layout layout;
    struct exc_stack_layout *stack;
    void *stack_ptr = (void *)(SP_sig(sigcontext) & ~15);
    void *delivery_stack_ptr = stack_ptr;

    /* Гейт для ПАРНОГО ЗАМЕРА на одном бинаре: сравнивать сборки нельзя — в них
     * различается не только защёлка. MACRUNNER_HB_NO_DELIVERY_LATCH=1 возвращает
     * прежнее поведение (вложенная доставка разрешена). */
    {
        static int latch_off = -1;
        if (latch_off < 0)
        {
            /* ★★★ 29.08.2026 — УМОЛЧАНИЕ ВЫКЛЮЧЕНО, защёлка НЕ ПОДТВЕРЖДЕНА.
             *
             * Парный замер 6+6 прогонов на прогреве (там, где перекрытия бывают):
             *   latch    overlap=17  повтор=0
             *   nolatch  overlap=18  повтор=0
             * Защёлка не сработала НИ РАЗУ, разницы нет.
             *
             * Причина: из 35 записей прибора 34 имеют `overlap=0` — он печатает
             * КАЖДУЮ доставку, а не только перекрытия. Единственное настоящее
             * (`overlap=1136`) случилось В РУКЕ С ЗАЩЁЛКОЙ и имеет
             * `callback_stack=1`, `delivery_sp != interrupted_sp` — то есть это
             * доставка на стек обратного вызова, а не вложенный вход. Защёлка
             * такое не ловит и поймать не может.
             *
             * Код оставлен: защита от вложенной доставки верна по существу и
             * может понадобиться. Но по умолчанию ВЫКЛЮЧЕНА — включать только
             * с замером. Включение: MACRUNNER_HB_DELIVERY_LATCH=1 */
            const char *on = macrunner_hb_getenv( "MACRUNNER_HB_DELIVERY_LATCH" );
            const char *v = macrunner_hb_getenv( "MACRUNNER_HB_NO_DELIVERY_LATCH" );
            if (on && *on && *on != '0') latch_off = 0;
            else latch_off = (v && *v && *v != '0') ? 1 : 1;  /* умолчание: выключено */
        }
        if (latch_off) macrunner_hb_in_delivery = 0;
    }

    if (macrunner_hb_in_delivery)
    {
        /* Повторный вход: первая запись ещё на стеке, второй там места нет.
         * Печатаем ОДИН раз через write() — fprintf в обработчике сигнала берёт
         * замок stdio и вешает процесс (проверено сегодня же). */
        static int said;
        if (!said++)
        {
            static const char msg[] =
                "macrunner-hb-доставка-повтор: вложенная доставка исключения отклонена "
                "(защёлка повторного входа)\n";
            ssize_t ignored = write( 2, msg, sizeof(msg) - 1 );
            (void)ignored;
        }
        return;
    }
    macrunner_hb_in_delivery = 1;
    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА, итерация 204 — ПРАВКА КЛИНА СТУПЕНИ 1.
     *
     * Когда сигнал приходит на потоке, исполняющем ГОСТЕВОЙ код, ядро macOS кладёт свой
     * сигнальный кадр НИЖЕ прерванного SP, то есть на гостевой стек. Кадр гостя мы отводим
     * тоже вниз от SP — и накрываем кадр ядра. Замер 204 (`macrunner-hb-probe-sigframe`):
     *
     *     uc = SP-1000 (56 байт), mc = uc+56 (816 байт)  → кадр ядра [SP-1000, SP-128)
     *     наша запись 1136 байт                          → [SP-1136, SP)
     *
     * Поле `uc_mcontext` попадает на 184-й байт нашей записи и обнуляется; строка
     * `SP_sig(sigcontext) = stack` ниже разыменовывает ноль, пишет по адресу 0x108, отказ
     * доставить некуда (мы уже в обработчике) — процесс встаёт навсегда. Наружу это выглядело
     * как «медленность»: 31 млн блоков и полная остановка на 40-й секунде.
     *
     * Лечение: отводить кадр гостя НИЖЕ кадра ядра. Нижняя граница кадра ядра взята замером
     * (mc лежит ВЫШЕ uc), но на всякий случай берём минимум из двух — предполагать порядок
     * нельзя, на этом же и горели.
     *
     * Умолчание ВЫКЛ: прежнее поведение дословно. */
    {
        static int guard_on = -1;
        if (guard_on < 0)
        {
            const char *v = macrunner_hb_getenv( "MACRUNNER_HB_SIGFRAME_GUARD" );
            guard_on = (v && *v && *v != '0') ? 1 : 0;
        }
        if (guard_on)
        {
            char *frame_lo = (char *)sigcontext;
            char *mc_lo = (char *)sigcontext->uc_mcontext;

            if (mc_lo && mc_lo < frame_lo) frame_lo = mc_lo;
            /* Только если кадр ядра действительно лежит на этом же стеке НИЖЕ SP и близко:
             * 64 КБ — заведомо больше любого сигнального кадра и заведомо меньше стека. */
            if (frame_lo < (char *)stack_ptr && frame_lo > (char *)stack_ptr - 65536)
                delivery_stack_ptr = (void *)((ULONG_PTR)frame_lo & ~15);
        }
    }
    NTSTATUS status;
    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА, итерация 204 — ГДЕ ЛЕЖИТ КАДР ЯДРА.
     * Итерация 203 доказала арифметикой, что запись кадра гостя (SP-1136, длина 0x470)
     * накрывает `ucontext` ядра (SP-1000) и обнуляет его поле `uc_mcontext`, после чего
     * строка «SP_sig(sigcontext) = stack» пишет по адресу 0x108 и процесс встаёт навсегда.
     * Прежде чем двигать `delivery_stack_ptr` вниз, надо ИЗМЕРИТЬ протяжённость кадра ядра:
     * лежит ли `mcontext` выше или ниже `ucontext`. Предположить нельзя — сдвиг на неверную
     * величину даст тот же дефект на другом смещении. Печатаем ДО записи, потому что после
     * неё поле уже затёрто (в этом и была ловушка 202). */
    {
        static int lay_on = -1;
        static int lay_n;
        if (lay_on < 0)
        {
            const char *v = macrunner_hb_getenv( "MACRUNNER_HB_PROBE_RAISE" );
            lay_on = (v && *v && *v != '0') ? 1 : 0;
        }
        if (lay_on && lay_n++ < 8)
        {
            void *mc = (void *)sigcontext->uc_mcontext;
            macrunner_signal_writef( "macrunner-hb-probe-sigframe: n=%d uc=%p mc=%p sp=%p stack_ptr=%p "
                                     "uc_below_sp=%lld mc_minus_uc=%lld ucsz=%u mcsz=%u\n",
                                     lay_n, (void *)sigcontext, mc,
                                     (void *)(ULONG_PTR)SP_sig(sigcontext), stack_ptr,
                                     (long long)((char *)stack_ptr - (char *)sigcontext),
                                     (long long)((char *)mc - (char *)sigcontext),
                                     (unsigned)sizeof(ucontext_t), (unsigned)sizeof(_STRUCT_MCONTEXT64) );
        }
    }
    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА, итерация 205 — КТО УШЁЛ НА НОЛЬ.
     * После снятия клина (204) остался единственный настоящий отказ ступени 1:
     * `code=0xc0000005 addr=0x0 pc=0x0 lr=0x0`, то есть ХОЗЯЙСКИЙ pc равен нулю — наш
     * собственный код (выпущенный JIT-ом или переходник) ушёл по нулевому адресу.
     * Готовый прибор проекта `macrunner-hb-nullcall-site` тут не годится: он берёт состояние
     * из реестра x64-контекстов и для i386 напечатает «no registered x64 ctx». Это уже третий
     * случай, когда прибор сделан под x64 и ступень 1 не покрывает (были TSO и нативная память).
     * Поэтому печатаем регистры хозяина прямо здесь: x19 в нашем выпущенном коде держит
     * указатель на hb_context_t (см. emit_interp_ir_helper: mov x0,x19), значит по нему можно
     * будет прочитать гостевое состояние; x30/lr назовёт, был ли это вызов или переход. */
    /* Итерация 211: условие расширено с `Pc == 0` на ЛЮБОЙ отказ (первые четыре).
     * Переход на ноль вылечен правкой 210, и новая стена — `ldrh w8,[x5]` в
     * alloc_process_params+0x3c, то есть чтение поля Length у UNICODE_STRING по НЕнулевому,
     * но неотображённому указателю. Нужен сам x5: если это гостевой адрес без базы — перед
     * нами известный класс «32-битный указатель использован как хозяйский». */
    if (1)
    {
        static int nz_on = -1;
        static int nz_n;
        if (nz_on < 0)
        {
            const char *v = macrunner_hb_getenv( "MACRUNNER_HB_PROBE_RAISE" );
            nz_on = (v && *v && *v != '0') ? 1 : 0;
        }
        if (nz_on && nz_n++ < 4)
        {
            unsigned i;
            for (i = 0; i < 32; i += 8)
                macrunner_signal_writef( "macrunner-hb-probe-nullpc: n=%d x%u=%p x%u=%p x%u=%p x%u=%p "
                                         "x%u=%p x%u=%p x%u=%p x%u=%p\n",
                                         nz_n,
                                         i + 0, (void *)(ULONG_PTR)context->X[i + 0],
                                         i + 1, (void *)(ULONG_PTR)context->X[i + 1],
                                         i + 2, (void *)(ULONG_PTR)context->X[i + 2],
                                         i + 3, (void *)(ULONG_PTR)context->X[i + 3],
                                         i + 4, (void *)(ULONG_PTR)context->X[i + 4],
                                         i + 5, (void *)(ULONG_PTR)context->X[i + 5],
                                         i + 6, (void *)(ULONG_PTR)context->X[i + 6],
                                         i + 7, (void *)(ULONG_PTR)context->X[i + 7] );
            /* Итерация 206: ПРОТЯЖЁННОСТЬ обнулённого куска. Регистры сказали, что эпилог
             * восстановил нули в x19..x23 и x30, а x24..x29 целы — значит затёрта ЧАСТЬ
             * области сохранения. Печатаем окно вокруг SP: выровненный блок нулей укажет на
             * memset или копию известной длины, а нули вперемешку с живыми — на точечную
             * запись. Читаем стек, он заведомо отображён (по нему и пришёл сигнал). */
            {
                const ULONG64 *w = (const ULONG64 *)(ULONG_PTR)(context->Sp - 0x80);
                unsigned k;
                for (k = 0; k < 32; k += 4)
                    macrunner_signal_writef( "macrunner-hb-probe-nullmem: sp%+d %p %p %p %p\n",
                                             (int)(k * 8) - 0x80,
                                             (void *)(ULONG_PTR)w[k + 0], (void *)(ULONG_PTR)w[k + 1],
                                             (void *)(ULONG_PTR)w[k + 2], (void *)(ULONG_PTR)w[k + 3] );
            }
        }
    }
    /* Итерация 185: ВРЕМЯ, а не наличие. Проверка 183 доказывала лишь возврат вызова, а
     * снимок 182 говорит, что внутри функции сгорают секунды. Часы берём готовые
     * (`macrunner_hb_callback_loop_now_ns`, CLOCK_MONOTONIC) — они уже используются в этом
     * файле, значит в сигнальном контексте себя ведут. */
    uint64_t t_dbg0 = 0, t_vse0 = 0;

    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — ЗОНД ШТОРМА ИСКЛЮЧЕНИЙ.
     *
     * Итерация 159: эта функция держит ~82% отсчётов одного потока (3302 из снимка), поток
     * жжёт 99.7% ЦП, а в журнале за весь прогон ОДИН c0000005. Обе печати функции для этого
     * негодны, и обе проверены по журналу (ноль строк у каждой):
     *   - печать ниже стоит за гейтом MACRUNNER_HB_TRACE_CALLBACK_ROUTE И идёт через ERR(),
     *     а канал err до наших журналов не доходит ни в одном прогоне за историю проекта;
     *   - macrunner-hb-callback-exception-record заперта в ветке get_callback_exception_stack.
     * Здесь writef — единственная печать, которая в этом проекте работает всегда.
     *
     * Гейт MACRUNNER_HB_PROBE_RAISE, умолчание ВЫКЛ: прежнее поведение дословно. */
    {
        static int probe_on = -1;
        static int probe_n;
        if (probe_on < 0)
        {
            const char *v = macrunner_hb_getenv( "MACRUNNER_HB_PROBE_RAISE" );
            probe_on = (v && *v && *v != '0') ? 1 : 0;
        }
        if (probe_on && probe_n++ < 16)
        {
            /* Итерация 161: мало знать, ЧТО отказало (pc=0x1) — нужен ВЫЗЫВАЮЩИЙ.
             * `Lr` называет, откуда пришло управление, а find_loader_module переводит оба
             * адреса в модуль+RVA. Помощник безопасен в обработчике: он memset-ит структуру и
             * кладёт в name строку "unknown" на ЛЮБОМ пути отказа (строки 1115-1116),
             * поэтому печать имени не может уйти по мусорному указателю. */
            struct macrunner_hb_signal_module_info pc_info, lr_info;
            BOOL pc_found = macrunner_hb_signal_find_loader_module( context->Pc, &pc_info );
            BOOL lr_found = macrunner_hb_signal_find_loader_module( context->Lr, &lr_info );

            /* Итерация 162: печатаем ГОСТЕВОЙ x18 из контекста и ЖИВОЙ x18 из сигнального
             * контекста. На ARM64 Windows x18 — указатель на TEB, и разбор 161 показал, что
             * возврат приходится на RtlQueryEnvironmentVariable_U, где двумя командами выше
             * стоит `ldr x8,[x18,#0x60]`. Если x18 ноль — цепочка замыкается ЗАМЕРОМ.
             * Печатаем оба, потому что они могут расходиться: один из CONTEXT, другой из
             * ucontext, и именно на таком расхождении я уже обжигался в 161 с полем lr. */
            macrunner_signal_writef( "macrunner-hb-probe-raise: n=%d code=%#lx addr=%p pc=%p sp=%p lr=%p "
                                     "ctx_x18=%p sig_x18=%p "
                                     "pc_mod=%s pc_rva=0x%llx pc_found=%u "
                                     "lr_mod=%s lr_rva=0x%llx lr_found=%u\n",
                                     probe_n, (unsigned long)rec->ExceptionCode,
                                     rec->ExceptionAddress,
                                     (void *)(ULONG_PTR)context->Pc,
                                     (void *)(ULONG_PTR)context->Sp,
                                     (void *)(ULONG_PTR)context->Lr,
                                     (void *)(ULONG_PTR)context->X[18],
                                     (void *)(ULONG_PTR)REGn_sig(18, sigcontext),
                                     pc_info.name, (unsigned long long)pc_info.rva, pc_found,
                                     lr_info.name, (unsigned long long)lr_info.rva, lr_found );

            /* Итерация 164: ЧТО ИМЕННО лежит по адресу отказа.
             * Первое исключение ранней смерти — c000001d, «недопустимая инструкция». Слово
             * «недопустимая» может значить три разных вещи: там нули (прыгнули в пустое),
             * там мусор (испорченный указатель) или там настоящая, но неподдерживаемая
             * команда. Различает только чтение самих слов. Читаем безопасным помощником;
             * если чтение не удалось — печатаем это отдельно, потому что «не читается»
             * и «читается ноль» — тоже разные ответы. */
            {
                unsigned int insn[4];
                ULONG_PTR at = (ULONG_PTR)context->Pc & ~(ULONG_PTR)3;
                if (macrunner_signal_read_memory( insn, (void *)at, sizeof(insn) ))
                    macrunner_signal_writef( "macrunner-hb-probe-insn: n=%d at=%p w0=%#x w1=%#x w2=%#x w3=%#x\n",
                                             probe_n, (void *)at, insn[0], insn[1], insn[2], insn[3] );
                else
                    macrunner_signal_writef( "macrunner-hb-probe-insn: n=%d at=%p ЧТЕНИЕ_НЕ_УДАЛОСЬ\n",
                                             probe_n, (void *)at );
            }

            /* Итерация 161: pc=0 И lr=0 — обратного адреса в регистре НЕТ, значит вызывающий
             * может лежать только на стеке. Читаем шесть слов по sp тем же безопасным
             * помощником, которым читается список модулей, и переводим каждое в модуль+RVA.
             * Это и назовёт, кто передал управление на ноль. */
            {
                ULONG_PTR w[6];
                if (macrunner_signal_read_memory( w, (void *)(ULONG_PTR)context->Sp, sizeof(w) ))
                {
                    unsigned int i;
                    for (i = 0; i < 6; i++)
                    {
                        struct macrunner_hb_signal_module_info wi;
                        BOOL f = macrunner_hb_signal_find_loader_module( w[i], &wi );
                        if (f)
                            macrunner_signal_writef( "macrunner-hb-probe-stack: n=%d i=%u val=%p mod=%s rva=0x%llx\n",
                                                     probe_n, i, (void *)w[i], wi.name,
                                                     (unsigned long long)wi.rva );
                    }
                }
            }
        }
    }

    if (macrunner_hb_trace_callback_route_enabled())
        fprintf( stderr, "macrunner-hb-setup-raise: pid=%d code=%#lx flags=%#lx addr=%p "
             "pc=%p sp=%p stack_ptr=%p dispatcher=%p\n",
             getpid(), rec->ExceptionCode, rec->ExceptionFlags, rec->ExceptionAddress,
             (void *)(ULONG_PTR)context->Pc, (void *)(ULONG_PTR)context->Sp,
             stack_ptr, pKiUserExceptionDispatcher );

    if (rec->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        context->Cpsr &= ~MACRUNNER_ARM64_CPSR_TRAP;
        PSTATE_sig(sigcontext) &= ~MACRUNNER_ARM64_CPSR_TRAP;
    }

    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — ГДЕ ИМЕННО ЗАСТРЕВАЕТ ДОСТАВКА.
     *
     * Итерация 182: снимок ИМЕННО игрового процесса (по comm=Diablo.exe) показал 99.2% ЦП
     * и `setup_raise_exception` НА ВЕРШИНЕ стека 4133 отсчёта, при том что подъёмов за
     * прогон единицы (зонд печатает первые 16, видим 1-3). Значит функция входит и НЕ
     * возвращается. Первое тяжёлое действие в ней — `send_debug_event`, круговой обмен с
     * `wineserver`; в том же снимке `mach_msg2_trap` держит 8266 отсчётов.
     *
     * Две печати, «перед» и «после». Нет «после» — застревание названо точно, и дальше
     * искать надо в обмене с сервером, а не в сигнальном пути. Гейт общий с зондом
     * исключений, потолок 8. */
    {
        static int dbg_on = -1;
        static int dbg_n;
        if (dbg_on < 0)
        {
            const char *v = macrunner_hb_getenv( "MACRUNNER_HB_PROBE_RAISE" );
            dbg_on = (v && *v && *v != '0') ? 1 : 0;
        }
        t_dbg0 = macrunner_hb_callback_loop_now_ns();
        if (dbg_on && dbg_n++ < 8)
            macrunner_signal_writef( "macrunner-hb-dbgevent-before: n=%d code=%#lx pc=%p\n",
                                     dbg_n, (unsigned long)rec->ExceptionCode,
                                     (void *)(ULONG_PTR)context->Pc );
    }

    status = send_debug_event( rec, context, TRUE, TRUE );

    {
        static int dbg_after;
        static int dbg_on2 = -1;
        if (dbg_on2 < 0)
        {
            const char *v = macrunner_hb_getenv( "MACRUNNER_HB_PROBE_RAISE" );
            dbg_on2 = (v && *v && *v != '0') ? 1 : 0;
        }
        if (dbg_on2 && dbg_after++ < 8)
            macrunner_signal_writef( "macrunner-hb-dbgevent-after: n=%d status=%#lx мкс=%llu\n",
                                     dbg_after, (unsigned long)status,
                                     (unsigned long long)((macrunner_hb_callback_loop_now_ns() - t_dbg0) / 1000) );
    }
    if (status == DBG_CONTINUE || status == DBG_EXCEPTION_HANDLED)
    {
        restore_context( context, sigcontext );
        return;
    }

    /* fix up instruction pointer in context for EXCEPTION_BREAKPOINT */
    if (rec->ExceptionCode == EXCEPTION_BREAKPOINT) context->Pc -= 4;

    if (macrunner_hb_get_callback_exception_stack( sigcontext, &delivery_stack_ptr ))
    {
        static int callback_rec_count;
        struct macrunner_hb_signal_module_info context_info;
        BOOL have_context = macrunner_hb_signal_find_loader_module( context->Pc, &context_info );

        if (callback_rec_count++ < 16)
            macrunner_signal_writef( "macrunner-hb-callback-exception-record: pid=%d "
                                     "code=%#lx flags=%#lx addr=%p context_pc=%p context_sp=%p "
                                     "context_module=%s context_native=%p context_rva=0x%llx "
                                     "context_found=%u context_cpsr=%#lx sig_pstate=%#llx "
                                     "info0=%p info1=%p delivery_sp=%p teb_stack=%p-%p\n",
                                     getpid(), rec->ExceptionCode, rec->ExceptionFlags,
                                     rec->ExceptionAddress, (void *)(ULONG_PTR)context->Pc,
                                     (void *)(ULONG_PTR)context->Sp,
                                     context_info.name, context_info.base,
                                     (unsigned long long)context_info.rva, have_context,
                                     context->Cpsr, (unsigned long long)PSTATE_sig(sigcontext),
                                     rec->NumberParameters > 0 ? (void *)(ULONG_PTR)rec->ExceptionInformation[0] : NULL,
                                     rec->NumberParameters > 1 ? (void *)(ULONG_PTR)rec->ExceptionInformation[1] : NULL,
                                     delivery_stack_ptr,
                                     NtCurrentTeb() ? NtCurrentTeb()->Tib.StackLimit : NULL,
                                     NtCurrentTeb() ? NtCurrentTeb()->Tib.StackBase : NULL );
    }
    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — СЛЕДУЮЩЕЕ ТЯЖЁЛОЕ ДЕЙСТВИЕ.
     * Итерация 183 сняла версию «застряли в send_debug_event»: печати «до» и «после» вокруг
     * него появляются обе, по одному разу. Значит смотреть надо дальше. Здесь второе
     * тяжёлое место функции — размещение записи об исключении на гостевом стеке.
     * Гейт общий с зондом исключений, потолок 8. */
    {
        static int vse_on = -1;
        static int vse_n;
        if (vse_on < 0)
        {
            const char *v = macrunner_hb_getenv( "MACRUNNER_HB_PROBE_RAISE" );
            vse_on = (v && *v && *v != '0') ? 1 : 0;
        }
        t_vse0 = macrunner_hb_callback_loop_now_ns();
        if (vse_on && vse_n++ < 8)
            macrunner_signal_writef( "macrunner-hb-vse-before: n=%d sp=%p size=%u\n",
                                     vse_n, delivery_stack_ptr, (unsigned int)sizeof(*stack) );
    }

    {   /* ★★★★★★ MacRunner 2026-08-31 — КРАСНАЯ ЗОНА APPLE ARM64: 128 БАЙТ.
         *
         * КОРЕНЬ, доказанный одной строкой прибора:
         *   прерван_sp=0x1121cda60  запись=[0x1121cd5f0,0x1121cda60)
         *   слот(sp-8)=0x1121cda58  затирается=ДА
         * Запись доставки кроет [sp-0x470, sp) — ровно как у upstream Wine. И у Wine это
         * ВЕРНО: на Linux и Windows у ARM64 красной зоны НЕТ, под sp мертво.
         *
         * У Apple ARM64 она ЕСТЬ — 128 байт. Листовая функция вправе держать там живые
         * данные, не сдвигая sp. Наш затираемый слот (sp-8) лежит внутри этих 128 байт.
         * Отсюда и `ret` по испорченному x30: мы затираем то, что прерванный код считает
         * своим. Мои прежние зазоры 32 и 64 байта не помогали просто потому, что их НЕ
         * ХВАТАЛО — зона вдвое-вчетверо больше.
         *
         * Это отличие ПЛАТФОРМЫ, а не наша ошибка в переносе: у эталона такой правки нет
         * и быть не может, ему она не нужна.
         *
         * Гейт для парного замера на одном бинаре; 0 возвращает прежнее поведение. */
        static int rz = -1;
        if (rz < 0)
        {
            const char *e = getenv( "MACRUNNER_HB_APPLE_REDZONE" );
            rz = (e && *e) ? (int)strtol( e, NULL, 0 ) : 128;
        }
        if (rz > 0) delivery_stack_ptr = (void *)(((ULONG_PTR)delivery_stack_ptr - rz) & ~15);
    }
    stack = virtual_setup_exception( delivery_stack_ptr, sizeof(*stack), rec );
    {   /* ★★★★★★ MacRunner 2026-08-31 — ВСЕ ИСТОЧНИКИ ИСТИНЫ О РАЗМЕЩЕНИИ ЗАПИСИ.
         *
         * Измерением установлено: `call_user_exception_dispatcher` НЕ вызывается вовсе,
         * а затирающая запись идёт ИМЕННО ЗДЕСЬ, на сигнальном пути. Час работы по
         * диспетчерскому пути ушёл впустую именно потому, что я не проверил, какой путь
         * работает, прежде чем его чинить.
         *
         * Печатаем в ОДНОЙ строке всё, что определяет размещение: sp прерванного кода,
         * куда сдвинута доставка защитой, куда легла запись, её границы, наш собственный
         * sp и границы стека потока. Слот, который затирается (sp-8 у прерванного),
         * считается тут же — видно сразу, попадает он в запись или нет. */
        char here;
        static unsigned int pl_rep;
        ULONG_PTR isp = (ULONG_PTR)SP_sig(sigcontext);
        ULONG_PTR lo  = (ULONG_PTR)stack, hi = lo + sizeof(*stack);
        if (pl_rep++ < 16)
        {
            /* ★ 31.08 — PC ПРЕРВАННОГО КОДА, а не адрес отказа. Это РАЗНЫЕ вещи:
             * прибор отказа печатает, КУДА ушли, а здесь видно, ГДЕ поток был в момент
             * сигнала. Именно вторая величина называет функцию, чьи указатели лежат в
             * регистрах и чей возврат портится. Печатаем и её, и lr, и смещение от базы
             * нашего модуля — тогда символ ищется без второго прогона. */
            MESSAGE( "macrunner-hb-прерван: n=%u pc=%p lr=%p sp=%p от_базы=%p\n",
                     pl_rep, (void *)(ULONG_PTR)PC_sig(sigcontext),
                     (void *)(ULONG_PTR)REGn_sig(30, sigcontext), (void *)isp,
                     (void *)((ULONG_PTR)PC_sig(sigcontext) - (ULONG_PTR)macrunner_hb_host_base) );
            MESSAGE( "macrunner-hb-размещение: n=%u прерван_sp=%p доставка_ptr=%p "
                     "запись=[%p,%p) наш_sp=%p слот(sp-8)=%p затирается=%s "
                     "предел=%p база=%p\n",
                     pl_rep, (void *)isp, delivery_stack_ptr, (void *)lo, (void *)hi,
                     (void *)&here, (void *)(isp - 8),
                     ((isp - 8) >= lo && (isp - 8) < hi) ? "ДА" : "нет",
                     NtCurrentTeb() ? NtCurrentTeb()->Tib.StackLimit : NULL,
                     NtCurrentTeb() ? NtCurrentTeb()->Tib.StackBase : NULL );
        }
    }

    {
        static int vse_after;
        static int vse_on2 = -1;
        if (vse_on2 < 0)
        {
            const char *v = macrunner_hb_getenv( "MACRUNNER_HB_PROBE_RAISE" );
            vse_on2 = (v && *v && *v != '0') ? 1 : 0;
        }
        if (vse_on2 && vse_after++ < 8)
            macrunner_signal_writef( "macrunner-hb-vse-after: n=%d stack=%p мкс=%llu\n", vse_after, stack,
                                     (unsigned long long)((macrunner_hb_callback_loop_now_ns() - t_vse0) / 1000) );
    }

    /* MacRunner 2026-08-03 — DOES THE DELIVERY RECORD LAND ON LIVE FRAMES?
     *
     * The measurement this exists to settle.  A translated block's prologue saves X23 and LR as a
     * PAIR at [SP,#32]; its epilogue restores that pair and RETs (hb_arm64_codegen.c:756/809).  At
     * the stall the restored values are X23 = 0x00000000c0000005 and LR = a stack address — which
     * is byte-for-byte EXCEPTION_RECORD.ExceptionCode|ExceptionFlags followed by .ExceptionRecord.
     * So the block's register-save area is being overwritten by a delivery record, and the block
     * then RETs into its own stack and faults there forever (62 M faults on one page, 37 k/s).
     *
     * Two candidate sources, and they are told apart by arithmetic, not by argument:
     *   · the record is written at the interrupted SP with no reservation, so it sits ON the frame;
     *   · the record is written at frame->sp — the SP saved at an EARLIER syscall boundary, handed
     *     back by macrunner_hb_get_callback_exception_stack() above — which is HIGHER up the stack,
     *     so everything between the interrupted SP and it is live and gets flattened.
     *
     * Print the write range against the interrupted SP and let the numbers say which.  The first
     * few are printed with overlap=0 as well, deliberately: a silent instrument and an instrument
     * that found nothing are indistinguishable, and this lane has lost days to that difference. */
    /* MacRunner 04.08 16:45 — ★ ВОПРОС ВЫШЕ ЗАКРЫТ, И ОТВЕТ «НЕТ». Перепись всех 25 строк за 15
     * прогонов 04.08: `overlap=0` и `seen=0` в КАЖДОЙ. Запись кадра ни разу не легла на живые
     * кадры выше SP — да и не может: она идёт ВНИЗ от SP, а `overlap` считается против SP как
     * нижней живой границы. Прибор мерил не ту величину.
     *
     * Те же 25 строк показывают настоящую беду. В 13 случаях из 25 SP на момент сбоя лежит
     * В САМОМ TEB или сразу под ним, тогда как `teb_stack` указывает совсем другую область:
     *   · ровно `sp == teb` — в четырёх НЕЗАВИСИМЫХ прогонах (13:50, 16:07, 16:13, 16:21);
     *   · `sp == teb + 0x370` — это `&ntdll_thread_data.syscall_table` (unix_private.h:231).
     * Кадр в 1136 байт пишется вниз от SP и накрывает первые 880 байт TEB, включая
     * `Tib.StackBase/StackLimit` по смещениям 8 и 16. Доказательство прямое: в каскаде 14:11
     * первая доставка идёт при `teb_stack=0x75ea400000-0x75eb410000`, а СЛЕДУЮЩАЯ читает
     * `teb_stack=0x1-0x0` — границы уже затёрты. Дальше каскад из восьми доставок с шагом
     * ровно -3392 байта на одном потоке.
     *
     * Отсюда же снимается чтение «отрицательный room = вышли за нижнюю границу unix-стека»
     * (см. ниже): room считается против `kernel_stack`, а он у этих потоков в другой области
     * вовсе, поэтому -458 ГБ означает «другая область», а не исчерпание.
     *
     * Следующий вопрос — ПОЧЕМУ SP равен базе TEB на момент сбоя. Это замер, а не правка. */
    {
        static ULONG64 overlap_seen, overlap_printed, any_printed;
        char *w_lo = (char *)stack;
        char *w_hi = w_lo + sizeof(*stack);
        char *live_lo = (char *)stack_ptr;   /* interrupted SP — the lowest live address */
        char *teb_lo = NtCurrentTeb() ? (char *)NtCurrentTeb()->Tib.StackLimit : NULL;
        char *teb_hi = NtCurrentTeb() ? (char *)NtCurrentTeb()->Tib.StackBase : NULL;
        char *o_lo = w_lo > live_lo ? w_lo : live_lo;
        long long overlap = (w_hi > o_lo) ? (long long)(w_hi - o_lo) : 0;
        BOOL used_callback_stack = (delivery_stack_ptr != stack_ptr);
        /* MacRunner 2026-08-04 — ВНУТРИ ЛИ МЫ ОКНА ПОДМЕНЫ ГРАНИЦ СТЕКА.
         *
         * Разбор Prism (reports/research/PRISM-RE-PROGRESS.md, 10:50) показал, что вход в его
         * эмулятор проверяет, не находится ли поток УЖЕ на стеке эмулятора, сравнивая SP с
         * EmulatorStackBase/Limit из области процессора. Мы решаем тот же вопрос иначе и, похоже,
         * хуже: loader.c:408 ВРЕМЕННО подменяет teb->Tib.StackLimit/StackBase границами стека
         * эмулятора, а macrunner_hb_get_callback_exception_stack() решает, на какой стек
         * доставлять исключение, сравнивая SP именно с teb->Tib. Значит его решение зависит от
         * того, попало исключение в окно подмены или нет. Upstream 11.14 так не делает — держит
         * в блоке потока настоящий стек (unix/thread.c:1238).
         *
         * Признак вычисляется на месте, без новой памяти: если границы в блоке потока СОВПАДАЮТ
         * с границами стека эмулятора, мы внутри окна. Если все сбойные доставки окажутся внутри
         * него — гипотеза подтверждена; если разбросаны — снимается, и это тоже ответ. */
        unsigned emu_swap = 0;
        {
            TEB *t = NtCurrentTeb();
            CHPE_V2_CPU_AREA_INFO *ca = t ? t->ChpeV2CpuAreaInfo : NULL;
            if (ca && (ULONG_PTR)teb_hi == (ULONG_PTR)ca->EmulatorStackBase &&
                      (ULONG_PTR)teb_lo == (ULONG_PTR)ca->EmulatorStackLimit)
                emu_swap = 1;
        }
        /* Имя API по адресу в LR: он приходит из полосы гостевых thunk-ов (0x6f00…) и в двух
         * независимых прогонах 04.08 совпал побитово (0x6f00000057c0), но трасса импортов его не
         * называет.  Спрашиваем таблицу напрямую — это один индекс, читать её из обработчика
         * сигнала безопасно. */
        const char *lr_dll = "-", *lr_api = "-";
        UINT64 lr_target = 0;

        macrunner_hb_import_name_for_guest( (UINT64)(ULONG_PTR)LR_sig(sigcontext), &lr_dll, &lr_api,
                                            &lr_target );

        if (overlap > 0) __atomic_add_fetch( &overlap_seen, 1, __ATOMIC_RELAXED );
        if ((overlap > 0 && __atomic_fetch_add( &overlap_printed, 1, __ATOMIC_RELAXED ) < 16) ||
            __atomic_fetch_add( &any_printed, 1, __ATOMIC_RELAXED ) < 8)
            macrunner_signal_writef(
                /* MacRunner 2026-08-03 — `lr_in` is the whole question now.
                 *
                 * Measured: the faulting branch is a RET (x30 == PC in all 24 dumps, while x0, x9,
                 * x16 and x17 hold unrelated values), and the target is &rec of a delivery layout.
                 * This delivery sets SP, PC, x10 and x16 but never touches x30, so the dispatcher
                 * starts on whatever LR the interrupted code happened to hold.  Print it: if lr_in
                 * already equals rec_addr, the bad value was carried IN and the earlier delivery is
                 * where to look; if lr_in is sane, LR is being corrupted inside the dispatcher and
                 * the search moves there.  One value separates the two, so measure it rather than
                 * reason about it. */
                /* MacRunner 2026-08-03 night — WHOSE stack is this?
                 *
                 * Measured this run: three deliveries, and two of them report sp_in_teb=0 with a
                 * teb_stack (0x118f40000-0x119f40000) that does not contain the interrupted SP
                 * (0x1119cc880) — while the FIRST delivery reports a different teb_stack
                 * (0x1109d8000-0x1119d0000) that does.  So the frame is being written onto a stack
                 * that is not the current TEB's, and lr_in is 0 on exactly those two.  Print the
                 * thread id and the TEB pointer: "delivered on another thread's stack" and "this
                 * thread's TEB is wrong" are different bugs with the same symptom, and only the tid
                 * tells them apart. */
                "macrunner-hb-exception-record-overlap: tid=%llx teb=%p code=%#lx write=%p-%p size=%u "
                "interrupted_sp=%p delivery_sp=%p callback_stack=%u overlap=%lld "
                "teb_stack=%p-%p sp_in_teb=%u emu_swap=%u lr_in=%p rec_addr=%p seen=%llu "
                /* MacRunner 04.08 — остаток unix-стека, а не догадка о нём.
                 *
                 * В прогоне 09:15 первая доставка легла по sp=0x117c90370 при TEB=0x117c90000, то
                 * есть кадр размером 1136 байт пишется вниз от sp и накрывает первые 880 байт TEB;
                 * к восьмому шагу каскада поля стека в TEB читаются как 0x1-0x0, то есть затёрты.
                 * Это похоже на исчерпание unix-стека, но «похоже» здесь не годится: у потока есть
                 * готовое поле kernel_stack, и остаток считается точно.  Отрицательный room и есть
                 * доказательство выхода за нижнюю границу. */
                /* MacRunner 04.08 — ВЛОЖЕННАЯ ЛИ ЭТО ДОСТАВКА.
                 *
                 * Разбор Prism закрыл вопрос о поле TEB+0x1490: четвёрку туда кладёт функция
                 * 0x6838 в wow64.dll, а доходят до неё только Wow64RaiseException и
                 * Wow64PassExceptionToGuest.  Wow64PrepareForException читает это поле ПЕРВОЙ
                 * операцией и при четвёрке выходит, не готовя ничего.  То есть у Prism стоит
                 * защёлка повторного входа в доставку исключения — ровно против того каскада,
                 * который мы здесь и ловим.
                 *
                 * У нас учёт на поток есть (signal_depth/route_depth растут и падают парой), но
                 * ни один счётчик НЕ читается как условие — они только печатаются.  Прежде чем
                 * ставить защёлку, надо знать, случается ли смертельное наложение именно на
                 * вложенной доставке: если все записи с overlap>0 идут при глубине 1, защёлка
                 * лечила бы не ту болезнь.  Печатаем глубину прямо в этой строке. */
                "kstack=%p kstack_size=%#lx room=%lld lr_dll=%s lr_api=%s lr_target=%p "
                "sig_depth=%u route_depth=%u cbstack_decline=%d\n",
                (unsigned long long)macrunner_hb_current_thread_id(), NtCurrentTeb(),
                (unsigned long)rec->ExceptionCode, w_lo, w_hi, (unsigned)sizeof(*stack),
                live_lo, delivery_stack_ptr, used_callback_stack ? 1u : 0u, overlap,
                teb_lo, teb_hi,
                (teb_lo && teb_hi && live_lo >= teb_lo && live_lo < teb_hi) ? 1u : 0u,
                emu_swap,
                (void *)(ULONG_PTR)LR_sig(sigcontext),
                (void *)(w_lo + offsetof(struct exc_stack_layout, rec)),
                (unsigned long long)__atomic_load_n( &overlap_seen, __ATOMIC_RELAXED ),
                ntdll_get_thread_data()->kernel_stack, (unsigned long)kernel_stack_size,
                (long long)((char *)live_lo - (char *)ntdll_get_thread_data()->kernel_stack),
                lr_dll, lr_api, (void *)(ULONG_PTR)lr_target,
                macrunner_hb_callback_loop_tls.signal_depth,
                macrunner_hb_callback_loop_tls.route_depth,
                macrunner_hb_cbstack_decline );
    }

    macrunner_hb_note_delivery( stack, sizeof(*stack),
                                (const char *)stack + offsetof(struct exc_stack_layout, rec),
                                rec->ExceptionCode, (ULONG64)(ULONG_PTR)stack_ptr );

    memset( &layout, 0, sizeof(layout) );
    macrunner_signal_copy_bytes( &layout.rec, rec, sizeof(layout.rec) );
    macrunner_signal_copy_bytes( &layout.context, context, sizeof(layout.context) );
    context_init_empty_xstate( &layout.context, layout.redzone );
    layout.sp = layout.context.Sp;
    layout.pc = layout.context.Pc;
    if (!macrunner_signal_write_memory( stack, &layout, sizeof(layout) ))
    {
        /* MacRunner 2026-08-05 — ПРИБОР НЕ ДОЛЖЕН ВРАТЬ.
         *
         * Здесь стоял NtCurrentTeb(), а он на ARM64 И ЕСТЬ x18 — тот самый регистр, который
         * macOS затирает и ради которого написан macrunner_teb_reliable().  То есть строка,
         * по которой мы диагностируем срыв доставки, читала TEB ровно тем способом, чью
         * поломку и расследует: наблюдаемое teb_stack=0 могло быть не состоянием потока, а
         * ошибкой самой печати.  Печатаем ОБА значения: надёжное (pthread TLS) и сырое из
         * x18.  Их расхождение — прямая улика затёртого x18, а не косвенная. */
        TEB *rel_teb = macrunner_teb_reliable();
        TEB *raw_teb = NtCurrentTeb();
        macrunner_signal_writef( "macrunner-hb-exception-stack-write-failed: pid=%d "
                                 "code=%#lx flags=%#lx addr=%p pc=%p sp=%p "
                                 "stack=%p stack_ptr=%p teb_stack=%p-%p "
                                 "teb_rel=%p teb_x18=%p teb_mismatch=%d\n",
                                 getpid(), rec->ExceptionCode, rec->ExceptionFlags,
                                 rec->ExceptionAddress, (void *)(ULONG_PTR)context->Pc,
                                 (void *)(ULONG_PTR)context->Sp, stack, stack_ptr,
                                 rel_teb ? rel_teb->Tib.StackLimit : NULL,
                                 rel_teb ? rel_teb->Tib.StackBase : NULL,
                                 rel_teb, raw_teb, rel_teb != raw_teb );
        abort_thread(1);
    }

    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА, итерация 202.
     * ИМЕННО ЭТА запись — точка клина ступени 1. Профиль (sample, 12 с) показал 8998 сэмплов из
     * 8998 на инструкции `str x22,[x8,#0x108]`, что после разбора оказалось этой строкой:
     * x26 = ucontext, x8 = uc_mcontext (смещение 0x30 у macOS), 0x108 = __ss.__sp.
     * Вход в setup_raise_exception при этом ЕДИНСТВЕННЫЙ (зонд probe-raise, бюджет 16, напечатал
     * одну строку), то есть повторного входа нет — команда просто не завершается.
     * Печатаем САМ АДРЕС записи: он назовёт, куда мы пишем, без догадок. */
    {
        static int spset_on = -1;
        static int spset_n;
        if (spset_on < 0)
        {
            const char *v = macrunner_hb_getenv( "MACRUNNER_HB_PROBE_RAISE" );
            spset_on = (v && *v && *v != '0') ? 1 : 0;
        }
        if (spset_on && spset_n++ < 8)
            macrunner_signal_writef( "macrunner-hb-probe-spset: n=%d target=%p uc=%p stack=%p pc=%p code=%#lx\n",
                                     spset_n, (void *)&SP_sig(sigcontext), (void *)sigcontext,
                                     (void *)stack, (void *)(ULONG_PTR)context->Pc,
                                     rec->ExceptionCode );
    }
    SP_sig(sigcontext) = (ULONG_PTR)stack;
#if defined(__APPLE__)
    REGn_sig(10, sigcontext) = (ULONG_PTR)NtCurrentTeb();
    REGn_sig(16, sigcontext) = (ULONG_PTR)pKiUserExceptionDispatcher;
    PC_sig(sigcontext) = (ULONG_PTR)__wine_pe_x18_thunk;
#else
    PC_sig(sigcontext) = (ULONG_PTR)pKiUserExceptionDispatcher;
#endif
    REGn_sig(18, sigcontext) = (ULONG_PTR)macrunner_teb_reliable();
    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — ЧЕМ МЫ ВОЗВРАЩАЕМСЯ В ЯДРО.
     *
     * Итерация 168 замером сняла версию «трап рождает наш siglongjmp»: свидетели в обеих
     * дверях молчат, а ловушка в `_sigtramp+76` срабатывает. Осталась вторая: `sigreturn`
     * возвращается фатально, когда ядро НЕ ПРИНЯЛО подготовленный контекст. Здесь и стоит
     * его напечатать — ровно то, с чем мы отдаём управление.
     *
     * Печать существующая (ниже) для этого негодна дважды: она стоит под условием
     * STATUS_STACK_OVERFLOW и идёт через ERR(), а канал err до наших журналов не доходит.
     * Поэтому пишем через writef, который в этом проекте работает всегда.
     *
     * Что смотреть: `sp&15` (ARM64 требует выравнивания стека на 16), нулевой или
     * бессмысленный `pc`, пустой `x18`. Гейт общий с зондом исключений. */
    {
        static int probe_on = -1;
        static int probe_n;
        if (probe_on < 0)
        {
            const char *v = macrunner_hb_getenv( "MACRUNNER_HB_PROBE_RAISE" );
            probe_on = (v && *v && *v != '0') ? 1 : 0;
        }
        if (probe_on && probe_n++ < 16)
            macrunner_signal_writef( "macrunner-hb-probe-deliver: n=%d code=%#lx pc=%p sp=%p sp_mod16=%u "
                                     "x18=%p x16=%p stack=%p\n",
                                     probe_n, (unsigned long)rec->ExceptionCode,
                                     (void *)(ULONG_PTR)PC_sig(sigcontext),
                                     (void *)(ULONG_PTR)SP_sig(sigcontext),
                                     (unsigned int)(SP_sig(sigcontext) & 15),
                                     (void *)(ULONG_PTR)REGn_sig(18, sigcontext),
                                     (void *)(ULONG_PTR)REGn_sig(16, sigcontext),
                                     stack );
    }

    if (rec->ExceptionCode == STATUS_STACK_OVERFLOW && macrunner_hb_trace_stack_setup_enabled())
        fprintf( stderr, "macrunner-hb-stack-setup: pid=%d stack=%p sig_sp=%p saved_sp=%p "
             "stack_sp=%p stack_pc=%p teb_stack=%p-%p dealloc=%p\n",
             getpid(), stack, (void *)(ULONG_PTR)SP_sig(sigcontext),
             (void *)(ULONG_PTR)layout.context.Sp, (void *)(ULONG_PTR)layout.sp,
             (void *)(ULONG_PTR)layout.pc, NtCurrentTeb() ? NtCurrentTeb()->Tib.StackLimit : NULL,
             NtCurrentTeb() ? NtCurrentTeb()->Tib.StackBase : NULL,
             NtCurrentTeb() ? NtCurrentTeb()->DeallocationStack : NULL );

    /* Доставка подготовлена: контекст сигнала уже указывает на диспетчер гостя, и
     * возврат отсюда идёт через ядро. Снимаем защёлку ЗДЕСЬ — это единственная точка
     * выхода функции, дальше поток продолжится уже в гостевом обработчике. */
    macrunner_hb_in_delivery = 0;
}


/***********************************************************************
 *           setup_exception
 *
 * Modify the signal context to call the exception raise function.
 */
static void setup_exception( ucontext_t *sigcontext, EXCEPTION_RECORD *rec )
{
    CONTEXT context;

    rec->ExceptionAddress = (void *)PC_sig(sigcontext);
    save_context( &context, sigcontext );
    if (macrunner_hb_trace_callback_route_enabled())
        fprintf( stderr, "macrunner-hb-setup-exception: pid=%d code=%#lx addr=%p pc=%p sp=%p "
             "x4=%p x16=%p x24=%p x26=%p\n",
             getpid(), rec->ExceptionCode, rec->ExceptionAddress,
             (void *)(ULONG_PTR)PC_sig(sigcontext), (void *)(ULONG_PTR)SP_sig(sigcontext),
             (void *)(ULONG_PTR)REGn_sig(4, sigcontext),
             (void *)(ULONG_PTR)REGn_sig(16, sigcontext),
             (void *)(ULONG_PTR)REGn_sig(24, sigcontext),
             (void *)(ULONG_PTR)REGn_sig(26, sigcontext) );
    setup_raise_exception( sigcontext, rec, &context );
}


/***********************************************************************
 *           call_user_apc_dispatcher
 */
NTSTATUS call_user_apc_dispatcher( CONTEXT *context, unsigned int flags, ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3,
                                   PNTAPCFUNC func, NTSTATUS status )
{
    struct syscall_frame *frame = get_syscall_frame();
    ULONG64 sp = context ? context->Sp : frame->sp;
    struct apc_stack_layout *stack;

    if (flags) FIXME( "flags %#x are not supported.\n", flags );

    sp &= ~15;
    stack = (struct apc_stack_layout *)sp - 1;
    if (context)
    {
        memmove( &stack->context, context, sizeof(stack->context) );
        NtSetContextThread( GetCurrentThread(), &stack->context );
    }
    else
    {
        stack->context.ContextFlags = CONTEXT_FULL;
        NtGetContextThread( GetCurrentThread(), &stack->context );
        stack->context.X0 = status;
    }
    stack->func      = func;
    stack->args[0]   = arg1;
    stack->args[1]   = arg2;
    stack->args[2]   = arg3;
    stack->alertable = TRUE;

    frame->sp = (ULONG64)stack;
    frame->pc = (ULONG64)pKiUserApcDispatcher;
    mr_pisal_apc++;   /* кто переписал frame->sp — счётчик для кольца */
    frame->restore_flags |= CONTEXT_CONTROL;
    syscall_frame_fixup_for_fastpath( frame );
    return status;
}


/***********************************************************************
 *           call_raise_user_exception_dispatcher
 */
void call_raise_user_exception_dispatcher(void)
{
    get_syscall_frame()->pc = (UINT64)pKiRaiseUserExceptionDispatcher;
}


/***********************************************************************
 *           call_user_exception_dispatcher
 */
NTSTATUS call_user_exception_dispatcher( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    struct syscall_frame *frame = get_syscall_frame();
    struct exc_stack_layout *stack;
    NTSTATUS status = NtSetContextThread( GetCurrentThread(), context );

    if (status) return status;
    /* ★ 31.08 — ЗДЕСЬ БЫЛ МОЙ ЗАЗОР ПОД SP, СНЯТ. Эталон (upstream Wine,
     * call_user_exception_dispatcher на ARM64) считает адрес ровно так же —
     * `(context->Sp & ~15) - 1`, без проверок и без зазора. Мой зазор был
     * необоснованным расхождением с эталоном, и парный замер (3 прогона на
     * значения 0/32/64) дал 1/2/1 отказа — разброс больше эффекта, зависимости нет.
     * Слот, откуда `ret` берёт негодный x30 (sp-8), измерен верно; лечение — нет. */
    stack = (struct exc_stack_layout *)(context->Sp & ~15) - 1;
    {   /* ★★★★★★ MacRunner 2026-08-31 — ЗАПИСЬ НЕ ДОЛЖНА ЛОЖИТЬСЯ НА ЖИВЫЕ КАДРЫ.
         *
         * КОРЕНЬ, выведенный арифметикой: `ret` дал sp=0x1121cda60, значит кадр имел
         * базу 0x1121cda50, а его сохранённые x29/x30 лежали в [0x1121cda50, sp) —
         * ВНУТРИ области записи [Sp-0x470, Sp). Запись легла поверх ЖИВОГО кадра.
         *
         * ПОЧЕМУ У НАС, А НЕ У ЭТАЛОНА. `context->Sp` — это Sp ГОСТЯ в точке
         * возбуждения исключения. А мы, unix-сторона, исполняемся НИЖЕ по тому же
         * стеку: наши C-кадры (`RtlRaiseException` -> сюда) живут под этим Sp. У Wine
         * на обычной системе unix-сторона уходит на отдельный стек, и под Sp мертво.
         *
         * ЛЕЧЕНИЕ ВЗЯТО У СЕБЯ ЖЕ. На СИГНАЛЬНОМ пути (setup_raise_exception) такая
         * защита уже есть и работает: там считают нижнюю границу кадра ядра и двигают
         * `delivery_stack_ptr` под неё. Делаем то же для диспетчерского пути: нижняя
         * граница НАШЕГО кадра — адрес локальной переменной; если он ниже Sp, кладём
         * запись под него.
         *
         * Гейт для парного замера на ОДНОМ бинаре: MACRUNNER_HB_DELIVERY_BELOW_FRAME=0
         * возвращает прежнее поведение. Сравнивать сборки нельзя — в них различается
         * не только эта правка. */
        static int below = -1;
        if (below < 0)
        {
            const char *e = getenv( "MACRUNNER_HB_DELIVERY_BELOW_FRAME" );
            below = (e && *e) ? (*e != '0') : 0;   /* умолчание 0: замер 3 против 4, не подтверждена */
        }
        if (below)
        {
            char marker;
            char *frame_lo = &marker;
            if (frame_lo < (char *)stack && frame_lo > (char *)stack - 65536)
                stack = (struct exc_stack_layout *)(((ULONG_PTR)frame_lo & ~15)) - 1;
        }
    }
    {   /* ★★★★★★ 31.08 — ИСПОЛНЯЕМСЯ ЛИ МЫ НА ТОМ ЖЕ СТЕКЕ, ЧТО И ГОСТЬ.
         *
         * Эталон: `__wine_syscall_dispatcher` на ARM64 ПЕРЕКЛЮЧАЕТ стек —
         * `ldr x10,[x18,#0x378]; mov sp, x10` — и unix-сторона идёт по стеку ядра.
         * Тогда под `context->Sp` мертво, и запись доставки никого не задевает.
         * Если у нас переключения нет, наши C-кадры лежат под Sp — и запись их
         * затирает. Печатаем адрес НАШЕЙ локальной переменной: он и есть наш sp. */
        char here;
        static unsigned int sw_rep;
        if (sw_rep++ < 16)
            MESSAGE( "macrunner-hb-стек-сверка: n=%u наш_sp=%p context_Sp=%p "
                     "мы_%s гостя на %ld байт  frame=%p\n",
                     sw_rep, (void *)&here, (void *)(ULONG_PTR)context->Sp,
                     ((ULONG_PTR)&here < (ULONG_PTR)context->Sp) ? "НИЖЕ" : "выше",
                     (long)((ULONG_PTR)context->Sp - (ULONG_PTR)&here),
                     (void *)frame );
    }
    {   /* Сверка Sp — оставлена для контроля.
         *
         * Арифметика отказа: `ret` дал sp=0x1121cda60, значит кадр имел базу
         * 0x1121cda50 и его сохранённые x29/x30 лежали в [0x1121cda50, 0x1121cda60) —
         * ВНУТРИ области записи [Sp-0x470, Sp). То есть запись легла поверх ЖИВОГО
         * кадра. Это возможно, только если `context->Sp` ВЫШЕ настоящей вершины стека.
         * Печатаем оба: Sp из контекста и sp кадра системного вызова. Расхождение —
         * и есть корень; совпадение — версию снимаем и ищем дальше. */
        static unsigned int sp_rep;
        if (sp_rep++ < 16)
            MESSAGE( "macrunner-hb-sp-сверка: n=%u context_Sp=%p frame_sp=%p разница=%ld "
                     "запись=[%p,%p) предел_стека=%p\n",
                     sp_rep, (void *)(ULONG_PTR)context->Sp,
                     (void *)(ULONG_PTR)(frame ? frame->sp : 0),
                     frame ? (long)((ULONG_PTR)context->Sp - (ULONG_PTR)frame->sp) : 0L,
                     (void *)stack, (void *)((char *)stack + sizeof(*stack)),
                     NtCurrentTeb() ? NtCurrentTeb()->Tib.StackLimit : NULL );
    }
    memmove( &stack->context, context, sizeof(*context) );
    memmove( &stack->rec, rec, sizeof(*rec) );
    context_init_empty_xstate( &stack->context, stack->redzone );
    stack->sp = stack->context.Sp;
    stack->pc = stack->context.Pc;

    frame->pc = (ULONG64)pKiUserExceptionDispatcher;
    mr_pisal_isk++;   /* кто переписал frame->sp — счётчик для кольца */
    frame->sp = (ULONG64)stack;
    frame->restore_flags |= CONTEXT_CONTROL;
    syscall_frame_fixup_for_fastpath( frame );
    return status;
}


/***********************************************************************
 *           call_user_mode_callback
 */
extern NTSTATUS call_user_mode_callback( ULONG64 user_sp, void **ret_ptr, ULONG *ret_len,
                                         void *func, TEB *teb );
__ASM_GLOBAL_FUNC( call_user_mode_callback,
                   "stp x29, x30, [sp,#-0xd0]!\n\t"
                   __ASM_CFI(".cfi_def_cfa_offset 0xd0\n\t")
                   __ASM_CFI(".cfi_offset 29,-0xd0\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xc8\n\t")
                   "mov x29, sp\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   "stp x19, x20, [x29, #0x10]\n\t"
                   __ASM_CFI(".cfi_rel_offset 19,0x10\n\t")
                   __ASM_CFI(".cfi_rel_offset 20,0x18\n\t")
                   "stp x21, x22, [x29, #0x20]\n\t"
                   __ASM_CFI(".cfi_rel_offset 21,0x20\n\t")
                   __ASM_CFI(".cfi_rel_offset 22,0x28\n\t")
                   "stp x23, x24, [x29, #0x30]\n\t"
                   __ASM_CFI(".cfi_rel_offset 23,0x30\n\t")
                   __ASM_CFI(".cfi_rel_offset 24,0x38\n\t")
                   "stp x25, x26, [x29, #0x40]\n\t"
                   __ASM_CFI(".cfi_rel_offset 25,0x40\n\t")
                   __ASM_CFI(".cfi_rel_offset 26,0x48\n\t")
                   "stp x27, x28, [x29, #0x50]\n\t"
                   __ASM_CFI(".cfi_rel_offset 27,0x50\n\t")
                   __ASM_CFI(".cfi_rel_offset 28,0x58\n\t")
                   "stp d8,  d9,  [x29, #0x60]\n\t"
                   "stp d10, d11, [x29, #0x70]\n\t"
                   "stp d12, d13, [x29, #0x80]\n\t"
                   "stp d14, d15, [x29, #0x90]\n\t"
                   "stp x1, x2, [x29, #0xa0]\n\t" /* ret_ptr, ret_len */
                   "mov x18, x4\n\t"              /* teb */
                   "mrs x1, fpcr\n\t"
                   "mrs x2, fpsr\n\t"
                   "bfi x1, x2, #0, #32\n\t"
                   "ldr x2, [x18]\n\t"            /* teb->Tib.ExceptionList */
                   "stp x1, x2, [x29, #0xb0]\n\t"

                   "ldr x7, [x18, #0x378]\n\t"    /* thread_data->syscall_frame */
                   "sub x1, sp, #0x330\n\t"       /* sizeof(struct syscall_frame) */
                   "str x1, [x18, #0x378]\n\t"    /* thread_data->syscall_frame */
                   "add x8, x29, #0xd0\n\t"
                   "stp x7, x8, [x1, #0x110]\n\t" /* frame->prev_frame,syscall_cfa */
                   "ldr w11, [x18, #0x380]\n\t"   /* thread_data->syscall_trace */
                   "cbnz x11, 1f\n\t"
                   /* switch to user stack */
                   "mov sp, x0\n\t"               /* user_sp */
                   "br x3\n"
                   "1:\tmov x19, x18\n\t"         /* teb */
                   "mov x20, x0\n\t"              /* user_sp */
                   "mov x21, x3\n\t"              /* func */
                   "mov sp, x1\n\t"
                   "ldr x1, [x20]\n\t"            /* args */
                   "ldp w2, w0, [x20, #8]\n\t"    /* len, id */
                   "str x0, [x29, #0xc0]\n\t"     /* id */
                   "bl " __ASM_NAME("trace_usercall") "\n\t"
                   "mov x18, x19\n\t"             /* teb */
                   "mov sp, x20\n\t"              /* user_sp */
                   "br x21" )


/***********************************************************************
 *           user_mode_callback_return
 */
extern void DECLSPEC_NORETURN user_mode_callback_return( void *ret_ptr, ULONG ret_len,
                                                         NTSTATUS status, TEB *teb );
__ASM_GLOBAL_FUNC( user_mode_callback_return,
                   "ldr x4, [x3, #0x378]\n\t"     /* thread_data->syscall_frame */
                   "ldp x5, x29, [x4,#0x110]\n\t" /* prev_frame,syscall_cfa */
                   "str x5, [x3, #0x378]\n\t"     /* thread_data->syscall_frame */
                   "sub x29, x29, #0xd0\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   __ASM_CFI(".cfi_rel_offset 29,0x00\n\t")
                   __ASM_CFI(".cfi_rel_offset 30,0x08\n\t")
                   __ASM_CFI(".cfi_rel_offset 19,0x10\n\t")
                   __ASM_CFI(".cfi_rel_offset 20,0x18\n\t")
                   __ASM_CFI(".cfi_rel_offset 21,0x20\n\t")
                   __ASM_CFI(".cfi_rel_offset 22,0x28\n\t")
                   __ASM_CFI(".cfi_rel_offset 23,0x30\n\t")
                   __ASM_CFI(".cfi_rel_offset 24,0x38\n\t")
                   __ASM_CFI(".cfi_rel_offset 25,0x40\n\t")
                   __ASM_CFI(".cfi_rel_offset 26,0x48\n\t")
                   __ASM_CFI(".cfi_rel_offset 27,0x50\n\t")
                   __ASM_CFI(".cfi_rel_offset 28,0x58\n\t")
                   "ldp x5, x6, [x29, #0xb0]\n\t"
                   "str x6, [x3]\n\t"             /* teb->Tib.ExceptionList */
                   "msr fpcr, x5\n\t"
                   "lsr x5, x5, #32\n\t"
                   "msr fpsr, x5\n\t"
                   "ldp x5, x6, [x29, #0xa0]\n\t" /* ret_ptr, ret_len */
                   "str x0, [x5]\n\t"             /* ret_ptr */
                   "str w1, [x6]\n\t"             /* ret_len */
                   "ldr w11, [x3, #0x380]\n\t"    /* thread_data->syscall_trace */
                   "cbz x11, 1f\n\t"
                   "ldr w3, [x29, #0xc0]\n\t"     /* id */
                   "mov x19, x2\n\t"
                   "bl " __ASM_NAME("trace_userret") "\n\t"
                   "mov x2, x19\n"                /* status */
                   "1:\tldp x19, x20, [x29, #0x10]\n\t"
                   __ASM_CFI(".cfi_same_value 19\n\t")
                   __ASM_CFI(".cfi_same_value 20\n\t")
                   "ldp x21, x22, [x29, #0x20]\n\t"
                   __ASM_CFI(".cfi_same_value 21\n\t")
                   __ASM_CFI(".cfi_same_value 22\n\t")
                   "ldp x23, x24, [x29, #0x30]\n\t"
                   __ASM_CFI(".cfi_same_value 23\n\t")
                   __ASM_CFI(".cfi_same_value 24\n\t")
                   "ldp x25, x26, [x29, #0x40]\n\t"
                   __ASM_CFI(".cfi_same_value 25\n\t")
                   __ASM_CFI(".cfi_same_value 26\n\t")
                   "ldp x27, x28, [x29, #0x50]\n\t"
                   __ASM_CFI(".cfi_same_value 27\n\t")
                   __ASM_CFI(".cfi_same_value 28\n\t")
                   "ldp d8,  d9,  [x29, #0x60]\n\t"
                   "ldp d10, d11, [x29, #0x70]\n\t"
                   "ldp d12, d13, [x29, #0x80]\n\t"
                   "ldp d14, d15, [x29, #0x90]\n\t"
                   "mov x0, x2\n\t"               /* status */
                   "mov sp, x29\n\t"
                   "ldp x29, x30, [sp], #0xd0\n\t"
                   "ret" )


/***********************************************************************
 *           user_mode_abort_thread
 */
extern void DECLSPEC_NORETURN user_mode_abort_thread( NTSTATUS status, struct syscall_frame *frame );
__ASM_GLOBAL_FUNC( user_mode_abort_thread,
                   "ldr x1, [x1, #0x118]\n\t"    /* frame->syscall_cfa */
                   "sub x29, x1, #0xc0\n\t"
                   /* switch to kernel stack */
                   "mov sp, x29\n\t"
                   __ASM_CFI(".cfi_def_cfa 29,0xc0\n\t")
                   __ASM_CFI(".cfi_offset 29,-0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xb8\n\t")
                   __ASM_CFI(".cfi_offset 19,-0xb0\n\t")
                   __ASM_CFI(".cfi_offset 20,-0xa8\n\t")
                   __ASM_CFI(".cfi_offset 21,-0xa0\n\t")
                   __ASM_CFI(".cfi_offset 22,-0x98\n\t")
                   __ASM_CFI(".cfi_offset 23,-0x90\n\t")
                   __ASM_CFI(".cfi_offset 24,-0x88\n\t")
                   __ASM_CFI(".cfi_offset 25,-0x80\n\t")
                   __ASM_CFI(".cfi_offset 26,-0x78\n\t")
                   __ASM_CFI(".cfi_offset 27,-0x70\n\t")
                   __ASM_CFI(".cfi_offset 28,-0x68\n\t")
                   "bl " __ASM_NAME("abort_thread") )


/***********************************************************************
 *           KeUserModeCallback
 */
NTSTATUS KeUserModeCallback( ULONG id, const void *args, ULONG len, void **ret_ptr, ULONG *ret_len )
{
    struct syscall_frame *frame = get_syscall_frame();
    ULONG64 sp = (frame->sp - offsetof( struct callback_stack_layout, args_data[len] ) - 16) & ~15;
    struct callback_stack_layout *stack = (struct callback_stack_layout *)sp;
    static int macrunner_callback_trace_count;

    if (macrunner_hb_getenv( "MACRUNNER_HB_TRACE_USER_CALLBACK" ) && macrunner_callback_trace_count++ < 160)
        fprintf( stderr, "macrunner-hb-user-callback: enter id=%lu len=%lu ret_ptr_slot=%p ret_len_slot=%p "
                 "frame=%p frame_sp=%p frame_pc=%p frame_lr=%p prev=%p kernel_stack=%p teb_stack=%p-%p "
                 "user_sp=%p\n",
                 (unsigned long)id, (unsigned long)len, ret_ptr, ret_len, frame,
                 (void *)(uintptr_t)frame->sp, (void *)(uintptr_t)frame->pc,
                 (void *)(uintptr_t)frame->lr, frame->prev_frame, ntdll_get_thread_data()->kernel_stack,
                 NtCurrentTeb() ? NtCurrentTeb()->Tib.StackLimit : NULL,
                 NtCurrentTeb() ? NtCurrentTeb()->Tib.StackBase : NULL, (void *)(uintptr_t)sp );

    if ((char *)ntdll_get_thread_data()->kernel_stack + min_kernel_stack > (char *)&frame)
    {
        TEB *teb = NtCurrentTeb();
        char *local = (char *)&frame;
        char *stack_limit = teb ? teb->Tib.StackLimit : NULL;
        char *stack_base = teb ? teb->Tib.StackBase : NULL;

        if (macrunner_hb_x64_loader_enabled() && stack_limit && stack_base &&
            stack_limit < stack_base && local >= stack_limit + min_kernel_stack &&
            local < stack_base)
        {
            fprintf( stderr, "MacRunner KeUserModeCallback accepting bridge stack id=%lu kernel_stack=%p local=%p "
                   "teb_stack=%p-%p frame=%p frame_sp=%p frame_pc=%p prev=%p\n",
                   (unsigned long)id, ntdll_get_thread_data()->kernel_stack, local,
                   stack_limit, stack_base, frame, (void *)(uintptr_t)frame->sp,
                   (void *)(uintptr_t)frame->pc, frame->prev_frame );
        }
        else
        {
            fprintf( stderr, "MacRunner KeUserModeCallback stack guard id=%lu kernel_stack=%p local=%p "
                   "teb_stack=%p-%p frame=%p frame_sp=%p frame_pc=%p prev=%p\n",
                   (unsigned long)id, ntdll_get_thread_data()->kernel_stack, local,
                   stack_limit, stack_base, frame, (void *)(uintptr_t)frame->sp,
                   (void *)(uintptr_t)frame->pc, frame->prev_frame );
            return STATUS_STACK_OVERFLOW;
        }
    }

    stack->args = stack->args_data;
    stack->len  = len;
    stack->id   = id;
    stack->lr   = frame->lr;
    stack->sp   = frame->sp;
    stack->pc   = frame->pc;
    memcpy( stack->args_data, args, len );
    return call_user_mode_callback( sp, ret_ptr, ret_len, pKiUserCallbackDispatcher, NtCurrentTeb() );
}


/***********************************************************************
 *           NtCallbackReturn  (NTDLL.@)
 */
NTSTATUS WINAPI NtCallbackReturn( void *ret_ptr, ULONG ret_len, NTSTATUS status )
{
    static int macrunner_callback_return_trace_count;
    struct syscall_frame *frame = get_syscall_frame();

    if (macrunner_hb_getenv( "MACRUNNER_HB_TRACE_USER_CALLBACK" ) && macrunner_callback_return_trace_count++ < 160)
    {
        fprintf( stderr, "macrunner-hb-user-callback: return ret_ptr=%p ret_len=%lu status=%08lx "
                 "frame=%p prev=%p syscall_cfa=%p frame_sp=%p frame_pc=%p frame_lr=%p "
                 "kernel_stack=%p teb_stack=%p-%p\n",
                 ret_ptr, (unsigned long)ret_len, (unsigned long)status, frame,
                 frame ? frame->prev_frame : NULL,
                 frame ? (void *)(uintptr_t)frame->syscall_cfa : NULL,
                 frame ? (void *)(uintptr_t)frame->sp : NULL,
                 frame ? (void *)(uintptr_t)frame->pc : NULL,
                 frame ? (void *)(uintptr_t)frame->lr : NULL,
                 ntdll_get_thread_data()->kernel_stack,
                 NtCurrentTeb() ? NtCurrentTeb()->Tib.StackLimit : NULL,
                 NtCurrentTeb() ? NtCurrentTeb()->Tib.StackBase : NULL );
    }

    if (!frame->prev_frame) return STATUS_NO_CALLBACK_ACTIVE;
    if (macrunner_hb_x64_loader_enabled() && ntdll_get_thread_data()->kernel_stack &&
        (char *)frame < (char *)ntdll_get_thread_data()->kernel_stack &&
        (char *)frame->prev_frame > (char *)ntdll_get_thread_data()->kernel_stack)
    {
        if (macrunner_hb_getenv( "MACRUNNER_HB_TRACE_USER_CALLBACK" ))
            fprintf( stderr, "macrunner-hb-user-callback: return-skip-bridge-frame frame=%p "
                     "prev=%p kernel_stack=%p syscall_cfa=%p\n",
                     frame, frame->prev_frame, ntdll_get_thread_data()->kernel_stack,
                     (void *)(uintptr_t)frame->syscall_cfa );
        ntdll_get_thread_data()->syscall_frame = frame->prev_frame;
    }
    user_mode_callback_return( ret_ptr, ret_len, status, NtCurrentTeb() );
}


/***********************************************************************
 *           handle_syscall_fault
 *
 * Handle a page fault happening during a system call.
 */
static BOOL handle_syscall_fault( ucontext_t *context, EXCEPTION_RECORD *rec )
{
    struct syscall_frame *frame = get_syscall_frame();
    DWORD i;

    if (!is_inside_syscall( SP_sig(context) )) return FALSE;

    TRACE( "code=%x flags=%x addr=%p pc=%p tid=%04x\n",
           rec->ExceptionCode, rec->ExceptionFlags, rec->ExceptionAddress,
           (void *)PC_sig(context), GetCurrentThreadId() );
    for (i = 0; i < rec->NumberParameters; i++)
        TRACE( " info[%d]=%016lx\n", i, rec->ExceptionInformation[i] );

    TRACE("  x0=%016lx  x1=%016lx  x2=%016lx  x3=%016lx\n",
          (DWORD64)REGn_sig(0, context), (DWORD64)REGn_sig(1, context),
          (DWORD64)REGn_sig(2, context), (DWORD64)REGn_sig(3, context) );
    TRACE("  x4=%016lx  x5=%016lx  x6=%016lx  x7=%016lx\n",
          (DWORD64)REGn_sig(4, context), (DWORD64)REGn_sig(5, context),
          (DWORD64)REGn_sig(6, context), (DWORD64)REGn_sig(7, context) );
    TRACE("  x8=%016lx  x9=%016lx x10=%016lx x11=%016lx\n",
          (DWORD64)REGn_sig(8, context), (DWORD64)REGn_sig(9, context),
          (DWORD64)REGn_sig(10, context), (DWORD64)REGn_sig(11, context) );
    TRACE(" x12=%016lx x13=%016lx x14=%016lx x15=%016lx\n",
          (DWORD64)REGn_sig(12, context), (DWORD64)REGn_sig(13, context),
          (DWORD64)REGn_sig(14, context), (DWORD64)REGn_sig(15, context) );
    TRACE(" x16=%016lx x17=%016lx x18=%016lx x19=%016lx\n",
          (DWORD64)REGn_sig(16, context), (DWORD64)REGn_sig(17, context),
          (DWORD64)REGn_sig(18, context), (DWORD64)REGn_sig(19, context) );
    TRACE(" x20=%016lx x21=%016lx x22=%016lx x23=%016lx\n",
          (DWORD64)REGn_sig(20, context), (DWORD64)REGn_sig(21, context),
          (DWORD64)REGn_sig(22, context), (DWORD64)REGn_sig(23, context) );
    TRACE(" x24=%016lx x25=%016lx x26=%016lx x27=%016lx\n",
          (DWORD64)REGn_sig(24, context), (DWORD64)REGn_sig(25, context),
          (DWORD64)REGn_sig(26, context), (DWORD64)REGn_sig(27, context) );
    TRACE(" x28=%016lx  fp=%016lx  lr=%016lx  sp=%016lx\n",
          (DWORD64)REGn_sig(28, context), (DWORD64)FP_sig(context),
          (DWORD64)LR_sig(context), (DWORD64)SP_sig(context) );

    if (ntdll_get_thread_data()->jmp_buf)
    {
        TRACE( "returning to handler\n" );
        REGn_sig(0, context) = (ULONG_PTR)ntdll_get_thread_data()->jmp_buf;
        REGn_sig(1, context) = 1;
        PC_sig(context)      = (ULONG_PTR)longjmp;
        ntdll_set_exception_jmp_buf( NULL );
    }
    else
    {
        if (PC_sig(context) < 0x10000)
        {
            static int macrunner_lowpc_reject_count;
            if (macrunner_lowpc_reject_count++ < 64)
                fprintf( stderr, "macrunner-hb-syscall-lowpc-resume-reject: code=%08x pc=%p lr=%p sp=%p "
                     "frame=%p frame_pc=%p ret=%08x\n",
                     rec->ExceptionCode, (void *)PC_sig(context), (void *)LR_sig(context),
                     (void *)SP_sig(context), frame, frame ? (void *)(uintptr_t)frame->pc : NULL,
                     rec->ExceptionCode );
            return FALSE;
        }
        TRACE( "returning to user mode ip=%p ret=%08x\n", (void *)frame->pc, rec->ExceptionCode );
        REGn_sig(0, context)  = rec->ExceptionCode;
        SP_sig(context)       = (ULONG_PTR)frame;
#if defined(__APPLE__)
        REGn_sig(10, context) = (ULONG_PTR)NtCurrentTeb();
        REGn_sig(16, context) = (ULONG_PTR)__wine_syscall_dispatcher_return;
        PC_sig(context)       = (ULONG_PTR)__wine_pe_x18_thunk;
#else
        REGn_sig(18, context) = (ULONG_PTR)macrunner_teb_reliable();
        PC_sig(context)       = (ULONG_PTR)__wine_syscall_dispatcher_return;
#endif
    }
    return TRUE;
}


#if defined(__APPLE__)
static int get_memory_access_base_reg( DWORD insn )
{
    switch (insn & 0x3b000000)
    {
    case 0x38000000: /* load/store register: unscaled, pre/post-index, register offset */
    case 0x39000000: /* load/store register: unsigned immediate */
    case 0x28000000: /* load/store register pair: post-index */
    case 0x29000000: /* load/store register pair: offset/pre-index */
        return (insn >> 5) & 0x1f;
    default:
        break;
    }

    if ((insn & 0x3f000000) == 0x08000000) /* load/store exclusive */
        return (insn >> 5) & 0x1f;

    return -1;
}

static ULONG_PTR get_memory_access_offset( DWORD insn )
{
    if ((insn & 0x3b000000) == 0x39000000) /* load/store register: unsigned immediate */
        return ((insn >> 10) & 0xfff) << (insn >> 30);

    return 0;
}

/* ★★★ 2026-08-30, лейн УСТАНОВЩИКИ — ПРОИЗВОДНЫЕ ОТ УСТАРЕВШЕЙ КОПИИ x18.
 *
 * Одного `mov xN, x18` мало. В `Wow64KiUserCallbackDispatcher` пролог делает так:
 *     +0x2C  mov x8, x18            копия (нулевая, если сигнал стёр x18)
 *     +0x74  add x26, x8, x9        ПРОИЗВОДНАЯ от копии
 *     +0x80  ldr x19, [x8, #0x1488] первый отказ  — лечится поиском по `mov`
 *     +0x7F4 str w28, [x26]         ВТОРОЙ отказ — по `mov` НЕ находится
 * Замер 30.08: после лечения только первого места установщик уходит с 557 гостевых
 * системных вызовов на 99 356 и упирается во второй, `x26=0xaa64`.
 * Формула подстановки та же (`teb + значение`), поэтому достаточно научить поиск
 * ходить на ДВА шага: определяющая команда базы это `mov` или `add`, а её источник —
 * копия x18. Глубина 2, окно то же (32 команды на уровень). */
static BOOL macrunner_reg_traced_to_x18( DWORD *pc, int reg, unsigned int depth )
{
    unsigned int i;

    if (reg < 0 || reg > 30 || depth > 2) return FALSE;

    for (i = 1; i <= 32; i++)
    {
        DWORD *prev_pc = pc - i;
        DWORD prev;

        if (!macrunner_signal_read_memory( &prev, prev_pc, sizeof(prev) )) return FALSE;

        /* mov xD, xS  ==  orr xD, xzr, xS */
        if ((prev & 0xffe0ffe0) == 0xaa0003e0 && (prev & 0x1f) == (DWORD)reg)
        {
            int src = (prev >> 16) & 0x1f;
            if (src == 18) return TRUE;
            return macrunner_reg_traced_to_x18( prev_pc, src, depth + 1 );
        }
        /* add xD, xS, xM (сдвиг нулевой) */
        if ((prev & 0xffe0fc00) == 0x8b000000 && (prev & 0x1f) == (DWORD)reg)
        {
            int src = (prev >> 5) & 0x1f;
            if (src == 18) return TRUE;
            return macrunner_reg_traced_to_x18( prev_pc, src, depth + 1 );
        }
    }

    return FALSE;
}

/* ★★★ 2026-08-30 — ЛЕЧЕНИЕ БЕЗ ОБРАТНОГО ПОИСКА (гейт MACRUNNER_HB_X18_HEAL_ANY_SMALL=1,
 * умолчание 0).
 *
 * Обратный поиск `mov база, x18` покрывает только соседние команды: замер 30.08 показал,
 * что определяющая команда бывает за 480 команд при окне 32. А предотвратить порчу нельзя:
 * macOS стирает x18 не на возврате из сигнала, а при ПЕРЕКЛЮЧЕНИИ КОНТЕКСТА (см. коммент
 * в начале этого файла), и покрытие ШЕСТИ обработчиков ничего не изменило — часы штормят
 * теми же 24 пересылками и 1,58 млн отказов/с.
 *
 * Поэтому здесь узор ослаблен до инварианта, который и так проверяется рядом:
 * `база + смещение == адрес отказа` при малом адресе. Это ОПАСНО в общем случае —
 * настоящее разыменование нуля станет тихим обращением по TEB вместо падения, — поэтому
 * гейт отдельный и умолчание 0. Включать только для замера. */
static int macrunner_heal_any_small_base(void)
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = macrunner_hb_getenv( "MACRUNNER_HB_X18_HEAL_ANY_SMALL" );
        cached = (v && v[0] && v[0] != '0');
    }
    return cached;
}

static BOOL memory_access_base_copied_from_x18( DWORD *pc, int base_reg )
{
    return macrunner_reg_traced_to_x18( pc, base_reg, 0 );
}

static BOOL memory_access_base_loaded_wow_teb_from_x18( DWORD *pc, int base_reg )
{
    unsigned int i, j;

    for (i = 1; i <= 8; i++)
    {
        DWORD *prev_pc = pc - i;
        DWORD prev;
        int offset_reg;

        if (!macrunner_signal_read_memory( &prev, prev_pc, sizeof(prev) )) return FALSE;

        /* add xBase, x18, xOffset */
        if ((prev & 0xffe0fc00) != 0x8b000000) continue;
        if ((prev & 0x1f) != base_reg || ((prev >> 5) & 0x1f) != 18) continue;
        offset_reg = (prev >> 16) & 0x1f;

        for (j = i + 1; j <= i + 16; j++)
        {
            DWORD *load_pc = pc - j;
            DWORD load;

            if (!macrunner_signal_read_memory( &load, load_pc, sizeof(load) )) return FALSE;

            /* ldrsw xOffset, [x18, #TEB.WowTebOffset] */
            if ((load & 0xffc00000) == 0xb9800000 &&
                (load & 0x1f) == offset_reg &&
                ((load >> 5) & 0x1f) == 18 &&
                get_memory_access_offset( load ) == offsetof( TEB, WowTebOffset ))
                return TRUE;
        }
    }

    return FALSE;
}

/* MacRunner ЛЕСТНИЦА 2026-08-09 — сколько отказов на самом деле есть починка x18.
 *
 * До этого замера доля была НЕ ИЗМЕРЕНА ничем: trace_apple_x18_heal() — пустышка, а число
 * «981 x18-faults/boot» в комментарии signal_arm64ec.c:2049 датировано 12.06 и с тех пор
 * ничем не подтверждалось. Вопрос не праздный: у нас TEB лежит в x18, macOS его затирает на
 * любом входе в ядро, и каждая потеря, не перехваченная встроенным восстановлением, стоит
 * ПОЛНОГО круга через обработчик сигнала. Ни один конкурент (Rosetta/FEX/box64) такого налога
 * не платит — они не обязаны держать Windows-ABI TEB в отобранном системой регистре.
 *
 * Считаем только атомарным сложением: обработчик обязан оставаться async-signal-safe, а
 * прежняя диагностика с getenv()/fprintf() здесь уже приводила к раскрутке libc при неверном
 * x18 и превращала восстановление в прокрутку ЦП. Печать едет на готовой строке faultrate. */
ULONG64 macrunner_hb_fault_x18_heal;

static void trace_apple_x18_heal( const char *kind, ucontext_t *context, ULONG_PTR fault_addr,
                                  int base_reg, ULONG_PTR base_value, ULONG_PTR mem_offset )
{
    __atomic_add_fetch( &macrunner_hb_fault_x18_heal, 1, __ATOMIC_RELAXED );

    /* Keep the signal handler async-signal-safe. Diagnostics here used to
     * call macrunner_hb_getenv()/fprintf(), which can recurse through libc while x18 is
     * already invalid and turn recovery into a CPU spin. */
    (void)kind;
    (void)context;
    (void)fault_addr;
    (void)base_reg;
    (void)base_value;
    (void)mem_offset;
}

static BOOL macrunner_hb_trace_native_faults_enabled(void)
{
    /* Cached: called per native fault. */
    static int enabled = -1;

    if (enabled < 0)
    {
        const char *val = macrunner_hb_getenv( "MACRUNNER_HB_TRACE_FAULTS" );
        enabled = val && val[0] && val[0] != '0';
    }
    return enabled != 0;
}

static IMAGE_NT_HEADERS *macrunner_hb_native_fault_nt_header( void *module )
{
    IMAGE_DOS_HEADER *dos = module;
    IMAGE_NT_HEADERS *nt;

    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x100000) return NULL;
    nt = (IMAGE_NT_HEADERS *)((BYTE *)module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    return nt;
}

static void *macrunner_hb_native_fault_module_from_pc( ULONG_PTR pc )
{
    uintptr_t p = pc & ~(uintptr_t)0xfff;
    unsigned int i;

    for (i = 0; i < 0x100000 && p; i++, p -= 0x1000)
    {
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)p;
        IMAGE_NT_HEADERS *nt;

        if (!virtual_is_valid_code_address( dos, sizeof(*dos) ) ||
            dos->e_magic != IMAGE_DOS_SIGNATURE ||
            dos->e_lfanew <= 0 || dos->e_lfanew > 0x100000)
            continue;
        nt = (IMAGE_NT_HEADERS *)(p + dos->e_lfanew);
        if (!virtual_is_valid_code_address( nt, sizeof(*nt) ) ||
            nt->Signature != IMAGE_NT_SIGNATURE)
            continue;
        return (void *)p;
    }
    return NULL;
}

static void macrunner_hb_native_fault_module_name( void *module, char *name, size_t name_size )
{
    IMAGE_DATA_DIRECTORY *dir;
    IMAGE_EXPORT_DIRECTORY *exports;
    IMAGE_NT_HEADERS *nt;

    if (!name || !name_size) return;
    strcpy( name, "unknown" );
    if (!module || !(nt = macrunner_hb_native_fault_nt_header( module ))) return;
    dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress || !dir->Size) return;
    exports = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)module + dir->VirtualAddress);
    if (!exports->Name) return;
    snprintf( name, name_size, "%s", (const char *)module + exports->Name );
}

static void *macrunner_hb_readable_pe_module_from_pc( ULONG_PTR pc )
{
    uintptr_t p = pc & ~(uintptr_t)0xfff;
    unsigned int i;

    for (i = 0; i < 0x100000 && p; i++, p -= 0x1000)
    {
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)p;
        IMAGE_NT_HEADERS *nt;

        if (!virtual_check_buffer_for_read( dos, sizeof(*dos) ) ||
            dos->e_magic != IMAGE_DOS_SIGNATURE ||
            dos->e_lfanew <= 0 || dos->e_lfanew > 0x100000)
            continue;
        nt = (IMAGE_NT_HEADERS *)(p + dos->e_lfanew);
        if (!virtual_check_buffer_for_read( nt, sizeof(*nt) ) ||
            nt->Signature != IMAGE_NT_SIGNATURE)
            continue;
        return (void *)p;
    }
    return NULL;
}

static void macrunner_hb_trace_callback_target_module( const char *source, ULONG_PTR pc )
{
    unsigned char bytes[16] = {0};
    char hex[sizeof(bytes) * 2 + 1];
    void *module;
    char module_name[96];
    ULONG_PTR rva = 0;
    unsigned int i;

    if (!macrunner_hb_trace_callback_route_enabled()) return;
    module = macrunner_hb_readable_pe_module_from_pc( pc );
    macrunner_hb_native_fault_module_name( module, module_name, sizeof(module_name) );
    if (module) rva = pc - (ULONG_PTR)module;
    if (pc && virtual_check_buffer_for_read( (void *)pc, sizeof(bytes) ))
        memcpy( bytes, (void *)pc, sizeof(bytes) );
    for (i = 0; i < sizeof(bytes); i++) sprintf( hex + i * 2, "%02x", bytes[i] );
    hex[sizeof(hex) - 1] = 0;

    fprintf( stderr, "macrunner-hb-callback-target: source=%s pc=%p module=%s base=%p rva=0x%llx bytes=%s\n",
             source, (void *)pc, module_name, module, (unsigned long long)rva, hex );
}

/* Счётчики пути hexpthk — чтобы быстрый выход можно было доказать, а не предположить.
 *
 * Обе трассы внутри этой функции сидят под гейтами, поэтому в 24 прогонах истории у неё НОЛЬ
 * упоминаний — и это ноль от выключенного прибора, он не говорит ни что путь работает, ни что он
 * мёртв.  Между тем на чужом длинном прогоне 04.08 именно он съел 143 отсчёта из 263 внутри
 * segv_handler при шторме в 295.6 млн отказов, где адрес отказа был в libsystem_platform, то есть
 * ВНЕ гостевой полосы.
 *
 * Счётчики отвечают на два вопроса разом: как часто путь зовут вообще и какова доля вызовов вне
 * полосы (их и срезает `MACRUNNER_HB_HEXPTHK_FAST_SKIP`), а `hits` показывает, срабатывает ли
 * перенаправление хоть когда-нибудь.  Если при сотнях миллионов вызовов `hits=0`, вопрос о
 * стоимости решается сам собой.  Печать раз на 4 млн вызовов плюс первое срабатывание. */
static uint64_t macrunner_hb_hexpthk_calls;
static uint64_t macrunner_hb_hexpthk_out_of_band;
static uint64_t macrunner_hb_hexpthk_hits;

static void macrunner_hb_hexpthk_note_call( ULONG_PTR pc )
{
    uint64_t n = __atomic_add_fetch( &macrunner_hb_hexpthk_calls, 1, __ATOMIC_RELAXED );

    if (pc < 0x87e00000000ull || pc >= 0x88000000000ull)
        __atomic_add_fetch( &macrunner_hb_hexpthk_out_of_band, 1, __ATOMIC_RELAXED );
    if ((n & 0x3fffffull) == 0)
        macrunner_signal_writef( "macrunner-hb-hexpthk-census: calls=%llu out_of_band=%llu hits=%llu\n",
                                 (unsigned long long)n,
                                 (unsigned long long)__atomic_load_n( &macrunner_hb_hexpthk_out_of_band, __ATOMIC_RELAXED ),
                                 (unsigned long long)__atomic_load_n( &macrunner_hb_hexpthk_hits, __ATOMIC_RELAXED ) );
}

static void macrunner_hb_hexpthk_note_hit( ULONG_PTR pc )
{
    uint64_t n = __atomic_add_fetch( &macrunner_hb_hexpthk_hits, 1, __ATOMIC_RELAXED );

    if (n <= 8)
        macrunner_signal_writef( "macrunner-hb-hexpthk-hit: n=%llu pc=%p in_band=%d\n",
                                 (unsigned long long)n, (void *)pc,
                                 (pc >= 0x87e00000000ull && pc < 0x88000000000ull) ? 1 : 0 );
}

static BOOL macrunner_hb_redirect_arm64x_hexpthk_sigill( ucontext_t *context )
{
    static const unsigned char thunk_prefix[] = { 0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x20, 0x55, 0x5d, 0xe9 };
    unsigned char bytes[sizeof(thunk_prefix) + sizeof(LONG)];
    unsigned char pc_prefix[2];
    ULONG_PTR pc = PC_sig(context);
    ULONG_PTR candidates[5];
    unsigned int ci;
    ULONG_PTR thunk = 0, target;
    void *module;
    LONG rel;
    static int trace_candidates = -1;
    static int trace_count;

    /* ★★★ ПАКЕТ-3, T3/T4/T11/T12 — семья T12: ПЕРЕХОД ЧЕРЕЗ HEXPTHK ВЕДЁТ ВЛАДЕЛЕЦ CPU.
     *
     * Здесь мы узнаём сырые байты x64-переходника fast-forward и своей рукой переписываем
     * X16/X18/PC на нативную мишень.  Это договор HyperBridge.  У FEX тот же переход ведёт
     * его собственный пролог (engine/fex/Source/Windows/ARM64EC/Module.S:17-39,56-78), и он
     * несёт то, чего мы не выставляем вовсе: InSimulation, FPCR и SuspendDoorbell.
     *
     * Тихий отказ, если не погасить: мы уводим поток на мишень МИМО диспетчера FEX, его
     * состояние симуляции остаётся неверным, а выглядит это как удавшийся переход.
     *
     * Гасим ПЕРВЫМ оператором — до переписи счётчиков и до пяти охраняемых чтений памяти. */
    if (macrunner_paket3_mute( MACRUNNER_P3_T12_HEXPTHK )) return FALSE;

    if (trace_candidates < 0)
        trace_candidates = macrunner_hb_getenv( "MACRUNNER_HB_TRACE_HEXPTHK_CANDIDATE" ) ? 1 : 0;

    macrunner_hb_hexpthk_note_call( pc );

    /* MacRunner 04.08 — O(1)-выход, когда переходник невозможен по построению.
     *
     * Замер на ЧУЖОМ живом прогоне (INPUT-TEST, 59 минут): 295.6 млн отказов при 82 536/с и
     * busy_pct=30, причём перепись страниц отдаёт 100.0 % одной гостевой странице
     * 0x87ef13c0000, а обращается к ней хостовый pc=0x1841873f0, разрешённый через `sample` как
     * libsystem_platform.dylib+0x33f0, то есть `_platform_memmove+0x90`.  По `sample` внутри
     * segv_handler 143 отсчёта из 263 приходятся на эту функцию с `probe_image_bytes` под ней.
     *
     * Для такого отказа она НЕ МОЖЕТ сработать, и это следует из её же условий: принятый
     * кандидат обязан удовлетворять `pc ∈ [c, c+14)` (см. цикл ниже) И быть PE-кодом.  Если pc
     * лежит в системной библиотеке хоста, любой содержащий его кандидат лежит там же, PE-кодом
     * не является, и функция гарантированно возвращает FALSE — но уже после классификации модуля
     * и до пяти охраняемых чтений памяти, на каждом из 295 миллионов отказов.
     *
     * Проверка диапазона стоит одно сравнение: все наши PE-образы живут в гостевой полосе
     * 0x87e00000000…0x88000000000 (та же константа, что в пробе nullcall), хостовые библиотеки —
     * в разделяемом кеше dyld около 0x180000000.  Семантику это не меняет: выход даётся только
     * там, где принятие кандидата невозможно.
     *
     * ЗА ГЕЙТОМ, дефолт ВЫКЛ, пока не измерено A/B — сегодня две правки уже проходили первый
     * контроль и заваливались на следующих руках. */
    {
        static int fast_skip = -1;

        if (fast_skip < 0) fast_skip = macrunner_hb_getenv( "MACRUNNER_HB_HEXPTHK_FAST_SKIP" ) ? 1 : 0;
        if (fast_skip && (pc < 0x87e00000000ull || pc >= 0x88000000000ull)) return FALSE;
    }

    if (macrunner_hb_pc_is_x64_guest_code_module_no_lock( (void *)pc ))
    {
        if (macrunner_signal_read_memory( pc_prefix, (void *)pc, sizeof(pc_prefix) ) &&
            pc_prefix[0] == 0xff && pc_prefix[1] == 0x25)
        {
            if (macrunner_hb_trace_callback_route_enabled())
                fprintf( stderr, "macrunner-hb-arm64x-hexpthk-skip-import-jmp: pc=%p x4=%p x16=%p lr=%p\n",
                         (void *)pc, (void *)(ULONG_PTR)REGn_sig(4, context),
                         (void *)(ULONG_PTR)REGn_sig(16, context),
                         (void *)(ULONG_PTR)LR_sig(context) );
            return FALSE;
        }
    }

    /* The faulting ARM64X x64 entry-thunk address can arrive tagged with the CodeMap
     * type in the low 2 bits (entry_thunk | type) and/or in a register other than x16
     * (a native `blr x8` to an imported thunk leaves the target in another reg, and the
     * fault PC inside the thunk).  Probe x16 and x4 with the tag stripped, plus the
     * 16-aligned address the fault PC lies within; accept the first whose bytes are the
     * fast-forward entry-thunk prologue and that the fault PC falls within. */
    candidates[0] = REGn_sig(16, context) & ~(ULONG_PTR)3;
    candidates[1] = REGn_sig(8, context) & ~(ULONG_PTR)3;
    candidates[2] = REGn_sig(17, context) & ~(ULONG_PTR)3;
    candidates[3] = REGn_sig(4, context) & ~(ULONG_PTR)3;
    candidates[4] = pc & ~(ULONG_PTR)15;
    for (ci = 0; ci < ARRAY_SIZE(candidates); ci++)
    {
        ULONG_PTR c = candidates[ci];
        BOOL pe_code;

        if (!c || pc < c || pc >= c + sizeof(bytes)) continue;
        pe_code = macrunner_hb_pc_is_pe_code_module_no_lock( (void *)c );
        if (!pe_code)
        {
            if (trace_candidates && trace_count++ < 2048)
                fprintf( stderr, "macrunner-hb-hexpthk-candidate: pc=%p ci=%u c=%p pe_code=0 "
                         "x4=%p x8=%p x16=%p x17=%p lr=%p sp=%p\n",
                         (void *)pc, ci, (void *)c,
                         (void *)(ULONG_PTR)REGn_sig(4, context),
                         (void *)(ULONG_PTR)REGn_sig(8, context),
                         (void *)(ULONG_PTR)REGn_sig(16, context),
                         (void *)(ULONG_PTR)REGn_sig(17, context),
                         (void *)(ULONG_PTR)LR_sig(context),
                         (void *)(ULONG_PTR)SP_sig(context) );
            continue;
        }
        if (!macrunner_signal_read_memory( bytes, (void *)c, sizeof(bytes) )) continue;
        if (trace_candidates && trace_count++ < 2048)
            fprintf( stderr, "macrunner-hb-hexpthk-candidate: pc=%p ci=%u c=%p pe_code=1 "
                     "bytes=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x "
                     "match=%d x4=%p x8=%p x16=%p x17=%p lr=%p sp=%p\n",
                     (void *)pc, ci, (void *)c,
                     bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                     bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13],
                     !memcmp( bytes, thunk_prefix, sizeof(thunk_prefix) ),
                     (void *)(ULONG_PTR)REGn_sig(4, context),
                     (void *)(ULONG_PTR)REGn_sig(8, context),
                     (void *)(ULONG_PTR)REGn_sig(16, context),
                     (void *)(ULONG_PTR)REGn_sig(17, context),
                     (void *)(ULONG_PTR)LR_sig(context),
                     (void *)(ULONG_PTR)SP_sig(context) );
        if (memcmp( bytes, thunk_prefix, sizeof(thunk_prefix) )) continue;
        thunk = c;
        break;
    }
    if (!thunk) return FALSE;

    module = macrunner_hb_pe_module_from_pc_no_lock( (void *)thunk );
    if (!module || macrunner_hb_pe_module_from_pc_no_lock( (void *)pc ) != module) return FALSE;
    memcpy( &rel, bytes + sizeof(thunk_prefix), sizeof(rel) );
    target = thunk + sizeof(bytes) + rel;
    if ((target & 3) || macrunner_hb_pe_module_from_pc_no_lock( (void *)target ) != module) return FALSE;
    if (!macrunner_hb_pc_is_pe_code_module_no_lock( (void *)target )) return FALSE;

    macrunner_hb_hexpthk_note_hit( pc );
    if (macrunner_hb_trace_callback_route_enabled())
        fprintf( stderr, "macrunner-hb-arm64x-hexpthk-redirect: pc=%p thunk=%p target=%p\n",
                 (void *)pc, (void *)thunk, (void *)target );
    REGn_sig(16, context) = target;
    REGn_sig(18, context) = (ULONG_PTR)macrunner_teb_reliable();
    PC_sig(context) = target;
    return TRUE;
}

static BOOL macrunner_hb_native_fault_read_u64( ULONG_PTR addr, ULONG_PTR *out )
{
    if (!addr || !out) return FALSE;
    if (!virtual_check_buffer_for_read( (void *)addr, sizeof(*out) )) return FALSE;
    *out = *(ULONG_PTR *)addr;
    return TRUE;
}

static void macrunner_hb_native_fault_dump_qwords( const char *label, ULONG_PTR addr )
{
    ULONG_PTR values[4] = {0};
    unsigned int valid = 0, i;

    if (!macrunner_hb_trace_native_faults_enabled() || !addr) return;
    for (i = 0; i < ARRAY_SIZE(values); i++)
    {
        if (macrunner_hb_native_fault_read_u64( addr + i * sizeof(ULONG_PTR), &values[i] ))
            valid |= 1u << i;
    }
    fprintf( stderr,
             "macrunner-native-fault-mem: %s addr=0x%llx valid=0x%x q=[0x%llx,0x%llx,0x%llx,0x%llx]\n",
             label, (unsigned long long)addr, valid,
             (unsigned long long)values[0], (unsigned long long)values[1],
             (unsigned long long)values[2], (unsigned long long)values[3] );
}

static void macrunner_hb_native_fault_dump_vm_region( const char *label, ULONG_PTR addr )
{
#ifdef __APPLE__
    mach_vm_address_t region = (mach_vm_address_t)addr;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr;

    if (!macrunner_hb_trace_native_faults_enabled() || !addr) return;
    kr = mach_vm_region( mach_task_self(), &region, &size, VM_REGION_BASIC_INFO_64,
                         (vm_region_info_t)&info, &count, &object );
    if (object != MACH_PORT_NULL) mach_port_deallocate( mach_task_self(), object );
    fprintf( stderr,
             "macrunner-native-fault-vm: %s addr=0x%llx kr=%d region=0x%llx size=0x%llx prot=0x%x max=0x%x\n",
             label, (unsigned long long)addr, kr, (unsigned long long)region,
             (unsigned long long)size, kr == KERN_SUCCESS ? info.protection : 0,
             kr == KERN_SUCCESS ? info.max_protection : 0 );
#endif
}

static void macrunner_hb_trace_native_fault( const char *kind, ucontext_t *context,
                                             const EXCEPTION_RECORD *rec, DWORD64 esr )
{
    ULONG_PTR pc = PC_sig(context);
    ULONG_PTR fault_addr = rec->NumberParameters >= 2 ? rec->ExceptionInformation[1] : 0;
    ULONG_PTR insn = 0;
    void *module = NULL;
    char module_name[96];
    const char *access = "unknown";
    BOOL have_insn = FALSE;
    TEB *teb;
    struct ntdll_thread_data *thread_data;

    if (!macrunner_hb_trace_native_faults_enabled()) return;

    if (rec->NumberParameters >= 1)
    {
        if (rec->ExceptionInformation[0] == EXCEPTION_WRITE_FAULT) access = "write";
        else if (rec->ExceptionInformation[0] == EXCEPTION_EXECUTE_FAULT) access = "execute";
        else if (rec->ExceptionInformation[0] == EXCEPTION_READ_FAULT) access = "read";
    }
    if (virtual_is_valid_code_address( (void *)pc, sizeof(DWORD) ))
    {
        insn = *(DWORD *)pc;
        have_insn = TRUE;
    }
    module = macrunner_hb_native_fault_module_from_pc( pc );
    macrunner_hb_native_fault_module_name( module, module_name, sizeof(module_name) );
    teb = NtCurrentTeb();
    thread_data = teb ? (struct ntdll_thread_data *)&teb->GdiTebBatch : NULL;

    fprintf( stderr,
             "macrunner-native-fault: kind=%s code=0x%08lx access=%s fault=0x%llx "
             "pid=%d module=%s base=%p rva=0x%llx pc=0x%llx sp=0x%llx lr=0x%llx esr=0x%llx pstate=0x%llx "
             "x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx "
             "x4=0x%llx x5=0x%llx x6=0x%llx x7=0x%llx "
             "x9=0x%llx x18=0x%llx x19=0x%llx x20=0x%llx x21=0x%llx x22=0x%llx x23=0x%llx x24=0x%llx x25=0x%llx "
             "x26=0x%llx x27=0x%llx x28=0x%llx teb=%p teb_stack=%p-%p dealloc=%p kernel=%p "
             "insn_valid=%u insn=0x%08llx\n",
             kind, rec->ExceptionCode, access, (unsigned long long)fault_addr,
             getpid(), module_name, module, module ? (unsigned long long)(pc - (ULONG_PTR)module) : 0,
             (unsigned long long)pc, (unsigned long long)SP_sig(context),
             (unsigned long long)REGn_sig(30, context), (unsigned long long)esr,
             (unsigned long long)PSTATE_sig(context),
             (unsigned long long)REGn_sig(0, context), (unsigned long long)REGn_sig(1, context),
             (unsigned long long)REGn_sig(2, context), (unsigned long long)REGn_sig(3, context),
             (unsigned long long)REGn_sig(4, context), (unsigned long long)REGn_sig(5, context),
             (unsigned long long)REGn_sig(6, context), (unsigned long long)REGn_sig(7, context),
             (unsigned long long)REGn_sig(9, context), (unsigned long long)REGn_sig(18, context),
             (unsigned long long)REGn_sig(19, context), (unsigned long long)REGn_sig(20, context),
             (unsigned long long)REGn_sig(21, context), (unsigned long long)REGn_sig(22, context),
             (unsigned long long)REGn_sig(23, context), (unsigned long long)REGn_sig(24, context),
             (unsigned long long)REGn_sig(25, context),
             (unsigned long long)REGn_sig(26, context), (unsigned long long)REGn_sig(27, context),
             (unsigned long long)REGn_sig(28, context), teb,
             teb ? teb->Tib.StackLimit : NULL, teb ? teb->Tib.StackBase : NULL,
             teb ? teb->DeallocationStack : NULL, thread_data ? thread_data->kernel_stack : NULL,
             have_insn, (unsigned long long)insn );

    macrunner_hb_native_fault_dump_qwords( "x19", REGn_sig(19, context) );
    macrunner_hb_native_fault_dump_qwords( "x20", REGn_sig(20, context) );
    macrunner_hb_native_fault_dump_qwords( "x24", REGn_sig(24, context) );
    macrunner_hb_native_fault_dump_vm_region( "x24", REGn_sig(24, context) );
    macrunner_hb_native_fault_dump_qwords( "x26", REGn_sig(26, context) );
    macrunner_hb_native_fault_dump_vm_region( "x26", REGn_sig(26, context) );
    macrunner_hb_native_fault_dump_qwords( "x28+0x890", REGn_sig(28, context) + 0x890 );
    {
        ULONG_PTR fls_global = REGn_sig(28, context) + 0x890;
        ULONG_PTR fls_cb_chunk = 0, fls_data_chunk = 0;
        ULONG_PTR fls_cb_current = 0, fls_data_current = 0;
        ULONG_PTR fls_index = REGn_sig(21, context);
        BOOL have_cb_chunk = macrunner_hb_native_fault_read_u64( fls_global, &fls_cb_chunk );
        BOOL have_data_chunk = macrunner_hb_native_fault_read_u64( REGn_sig(27, context), &fls_data_chunk );

        if (have_cb_chunk)
        {
            macrunner_hb_native_fault_dump_qwords( "fls_cb_chunk0", fls_cb_chunk );
            macrunner_hb_native_fault_dump_qwords( "fls_cb_chunk0+0x20", fls_cb_chunk + 0x20 );
            macrunner_hb_native_fault_read_u64( fls_cb_chunk + fls_index, &fls_cb_current );
        }
        if (have_data_chunk)
        {
            macrunner_hb_native_fault_dump_qwords( "fls_data_chunk0", fls_data_chunk );
            macrunner_hb_native_fault_dump_qwords( "fls_data_chunk0+0x20", fls_data_chunk + 0x20 );
            macrunner_hb_native_fault_read_u64( fls_data_chunk + fls_index, &fls_data_current );
        }
        fprintf( stderr,
                 "macrunner-native-fault-fls: global=0x%llx cb_chunk=0x%llx "
                 "data_root=0x%llx data_chunk=0x%llx index=0x%llx "
                 "cb_current=0x%llx data_current=0x%llx\n",
                 (unsigned long long)fls_global, (unsigned long long)fls_cb_chunk,
                 (unsigned long long)REGn_sig(27, context), (unsigned long long)fls_data_chunk,
                 (unsigned long long)fls_index, (unsigned long long)fls_cb_current,
                 (unsigned long long)fls_data_current );
    }
    macrunner_hb_native_fault_dump_qwords( "x27", REGn_sig(27, context) );
    macrunner_hb_native_fault_dump_qwords( "x9", REGn_sig(9, context) );
    macrunner_hb_native_fault_dump_qwords( "fault", fault_addr );
}

static void macrunner_hb_trace_low_stack_symbol( const char *label, ULONG_PTR addr )
{
    Dl_info info;

    if (!addr) return;
    if (dladdr( (void *)addr, &info ) && info.dli_fname)
        fprintf( stderr, "macrunner-hb-low-stack-symbol: %s addr=%p image=%s image_base=%p "
             "symbol=%s symbol_addr=%p offset=0x%llx\n",
             label, (void *)addr, info.dli_fname, info.dli_fbase,
             info.dli_sname ? info.dli_sname : "unknown", info.dli_saddr,
             info.dli_saddr ? (unsigned long long)(addr - (ULONG_PTR)info.dli_saddr) : 0 );
}

static void macrunner_hb_trace_low_stack_vm_region( const char *label, ULONG_PTR addr )
{
    mach_vm_address_t region = (mach_vm_address_t)addr;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr;

    if (!addr) return;
    kr = mach_vm_region( mach_task_self(), &region, &size, VM_REGION_BASIC_INFO_64,
                         (vm_region_info_t)&info, &count, &object );
    if (object != MACH_PORT_NULL) mach_port_deallocate( mach_task_self(), object );
    fprintf( stderr, "macrunner-hb-low-stack-vm: %s addr=%p kr=%d region=%p size=0x%llx prot=0x%x max=0x%x\n",
         label, (void *)addr, kr, (void *)(ULONG_PTR)region,
         (unsigned long long)size, kr == KERN_SUCCESS ? info.protection : 0,
         kr == KERN_SUCCESS ? info.max_protection : 0 );
}

static BOOL macrunner_hb_is_low_stack_access_fault( ucontext_t *context, const EXCEPTION_RECORD *rec )
{
    TEB *teb = macrunner_teb_reliable();  /* НЕ NtCurrentTeb(): на ARM64 это x18, который здесь и затёрт */
    char *sp = (char *)SP_sig(context);
    char *fault;

    if (!teb || !teb->DeallocationStack || !teb->Tib.StackLimit) return FALSE;
    if (rec->NumberParameters < 2) return FALSE;
    if (macrunner_hb_get_callback_exception_stack( context, NULL )) return FALSE;
    if (sp < (char *)teb->DeallocationStack || sp >= (char *)teb->Tib.StackLimit) return FALSE;

    fault = (char *)rec->ExceptionInformation[1];
    return (fault >= (char *)teb->DeallocationStack && fault < (char *)teb->Tib.StackLimit);
}

static void *macrunner_hb_virtual_fault_stack( ucontext_t *context, const EXCEPTION_RECORD *rec )
{
    TEB *teb = NtCurrentTeb();
    char *sp = (char *)SP_sig(context);
    char *fault;

    if (!teb || !teb->DeallocationStack || !teb->Tib.StackBase) return sp;
    if (rec->NumberParameters < 2) return sp;
    if (rec->ExceptionInformation[0] == EXCEPTION_EXECUTE_FAULT) return sp;

    fault = (char *)rec->ExceptionInformation[1];
    if (fault >= (char *)teb->DeallocationStack && fault < (char *)teb->Tib.StackBase &&
        (sp < (char *)teb->DeallocationStack || sp >= (char *)teb->Tib.StackBase))
        return fault;

    return sp;
}

static BOOL macrunner_hb_trace_low_stack_fault_enabled(void)
{
    static int count;

    return count++ < 32;
}

#if defined(__APPLE__)
static void macrunner_hb_trace_signal_exception_delivery( const char *kind, ucontext_t *context,
                                                          const EXCEPTION_RECORD *rec,
                                                          BOOL low_stack_fault,
                                                          BOOL stack_overflow_fault,
                                                          void *virtual_stack )
{
    static int report_count;
    TEB *teb = NtCurrentTeb();
    char *sp = (char *)SP_sig(context);
    BOOL near_stack = FALSE;

    if (teb && teb->DeallocationStack && teb->Tib.StackLimit && teb->Tib.StackBase)
        near_stack = sp >= (char *)teb->DeallocationStack &&
                     sp < (char *)teb->Tib.StackLimit + 0x20000;
    if (!rec || (rec->ExceptionCode != STATUS_STACK_OVERFLOW &&
                 !low_stack_fault && !stack_overflow_fault && !near_stack))
        return;
    if (report_count++ >= 32) return;

    macrunner_signal_writef( "macrunner-hb-signal-to-exception: kind=%s pid=%d "
                             "code=%#lx flags=%#lx pc=%p lr=%p sp=%p fault=%p "
                             "info0=0x%llx params=%lu low_stack=%u stack_overflow=%u "
                             "vstack=%p teb_stack=%p-%p dealloc=%p\n",
                             kind, getpid(), rec->ExceptionCode, rec->ExceptionFlags,
                             (void *)(ULONG_PTR)PC_sig(context),
                             (void *)(ULONG_PTR)LR_sig(context),
                             (void *)(ULONG_PTR)SP_sig(context),
                             rec->NumberParameters > 1 ?
                                 (void *)(ULONG_PTR)rec->ExceptionInformation[1] : NULL,
                             (unsigned long long)(rec->NumberParameters > 0 ?
                                 (ULONG_PTR)rec->ExceptionInformation[0] : 0),
                             rec->NumberParameters, (unsigned int)low_stack_fault,
                             (unsigned int)stack_overflow_fault,
                             virtual_stack,
                             teb ? teb->Tib.StackLimit : NULL,
                             teb ? teb->Tib.StackBase : NULL,
                             teb ? teb->DeallocationStack : NULL );
}
#endif

static BOOL emulate_apple_x18_teb_access( ucontext_t *context, TEB *teb, DWORD insn, ULONG_PTR fault_addr )
{
    ULONG_PTR offset, value = 0;
    unsigned int size, rt;
    void *addr;
    BOOL load;
    struct ntdll_thread_data *thread_data;

    if ((insn & 0x3b000000) != 0x39000000) return FALSE; /* unsigned immediate GPR load/store */
    if (((insn >> 5) & 0x1f) != 18) return FALSE;

    offset = get_memory_access_offset( insn );
    if (offset != fault_addr || offset >= 0x4000) return FALSE;

    size = 1u << (insn >> 30);
    if (size > sizeof(ULONG_PTR) || offset + size > 0x4000) return FALSE;

    rt = insn & 0x1f;
    load = (insn >> 22) & 1;
    addr = (char *)teb + offset;

    /* ★★★★★★ ШАГ-4 08.09.2026 — ТРАМПЛИН ВОЗВРАТА ЗАТИРАЕТ x17, А У FEX ОН ЖИВОЙ.
     *
     * `__wine_pe_x18_resume_thunk` (выше в этом файле) последним действием делает
     *     ldr x17, [x18, #0x3e8]   ; адрес возврата
     *     br  x17
     * то есть x17 ПРИНОСИТСЯ В ЖЕРТВУ. Комментарий у трамплина обосновывал это тем,
     * что x17 — внутрипроцедурный временный и «компилятор PE не держит в нём смысла
     * между командами». Для кода, ВЫПУЩЕННОГО КОМПИЛЯТОРОМ, это верно. Для
     * рукописного ассемблера FEX — НЕТ.
     *
     * Замер (прогон fex-x64, ШАГ-2/ШАГ-4, xtajit64.dll ba547d4d055b4de0, RVA 0x102f4c):
     *     0x102f4c  f81f8ffe  str  x30, [sp, #-8]!      <- ExitToX64, вход
     *     0x102f50  f94bc651  ldr  x17, [x18, #0x1788]  <- TEB->ChpeV2CpuAreaInfo
     *     0x102f54  52800030  mov  w16, #1
     *     0x102f58  39000230  strb w16, [x17]           <- ОТКАЗ, esr=0x9200004f (запись)
     * В момент отказа прибор `macrunner-shag4-ec` напечатал:
     *     x18=0x7ffd01e0000  teb_unix=0x7ffd01e0000  совпали=1
     *     [x18+0x1788]=0x1111d0000 ok=1   записано_area=0x1111d0000
     *     x16=0x1  x17=0x7ffd0b02f54      <- ЭТО pc-4, адрес самой `mov w16,#1`
     * То есть x18 верен, поле верно, а x17 несёт АДРЕС ВОЗВРАТА трамплина: путь
     * `direct-emulate-load` ниже выставлял `apple_x18_save_pc = PC+4` (0x102f54),
     * а трамплин клал это значение В x17 и прыгал туда. `strb w16,[x17]` писал
     * единицу в `.text` собственного модуля -> отказ прав (DFSC=0x0f).
     *
     * ЛЕЧЕНИЕ, минимальное и доказуемое: у ЗАГРУЗКИ в x17 не эмулировать, а
     * ПОВТОРИТЬ команду (вызывающий выставит `save_pc = PC`, без +4). Жертва x17
     * тогда безвредна ПО ПОСТРОЕНИЮ: повторяемая команда сама пишет x17.
     * ЗАПИСЬ из x17 так лечить нельзя (повтор взял бы затёртый x17), поэтому там
     * поведение прежнее, а случай считается и печатается — это остаточный риск.
     *
     * Прибор безусловный, потолок 16 строк: без него «путь сработал» и «путь не
     * сработал» неразличимы (счётчик trace_apple_x18_heal печатается только на
     * n==64/512/4096 и в коротком прогоне молчит). */
    {
        static unsigned long long shag4_emul_n;    /* всего входов */
        static unsigned long long shag4_retry_n;   /* ушло в ПОВТОР через свой Rt */
        static unsigned long long shag4_x17_n;     /* ОСТАТОК: x17 всё-таки пожертвован */
        unsigned long long n = __atomic_add_fetch( &shag4_emul_n, 1, __ATOMIC_RELAXED );
        /* ★ Отказ ВНУТРИ САМОГО ТРАМПЛИНА из повтора исключён: там нельзя трогать
         * apple_x18_save_*, иначе адрес возврата перезапишется адресом трамплина и
         * выйдет вечный круг. Этот случай оставлен прежнему пути ниже — поведение
         * для backend=hb не меняется ни в одной ветви. */
        /* ★ rt==17 сюда ВХОДИТ: в таблице у него стоит прежний трамплин, который
         * ветвится ЧЕРЕЗ x17 — а x17 здесь и есть Rt, то есть регистр, который
         * повтор сам перепишет. Первая редакция правки исключала rt==17 ошибочно, и
         * замер это поймал: отказ `enter_jit` вернулся ровно один раз (pid 94662,
         * x17=pc-4), пока остальные 15 процессов шли на повторе. */
        int retry = (load && apple_x18_resume_by_rt[rt] != NULL
                     && !apple_x18_pc_is_resume_thunk( PC_sig(context) ));

        static unsigned long long shag4_rt17_n;    /* ★ отдельно: случай стены enter_jit */
        if (retry) __atomic_add_fetch( &shag4_retry_n, 1, __ATOMIC_RELAXED );
        else       __atomic_add_fetch( &shag4_x17_n,   1, __ATOMIC_RELAXED );
        if (rt == 17) __atomic_add_fetch( &shag4_rt17_n, 1, __ATOMIC_RELAXED );
        /* потолок 16 на процесс СКРЫВАЛ редкий rt==17: он приходит позже. Печатаем
         * первые четыре таких ОТДЕЛЬНО от общего потолка. */
        if (n <= 16 || (rt == 17 && __atomic_load_n( &shag4_rt17_n, __ATOMIC_RELAXED ) <= 4))
            macrunner_signal_writef(
                "macrunner-shag4-x18emul: n=%llu pid=%d pc=%p insn=%08x rt=%u load=%u "
                "size=%u off=%#llx [teb+off]=%p reshenie=%s povtorov=%llu ostatok_x17=%llu\n",
                n, (int)getpid(), (void *)(ULONG_PTR)PC_sig(context), (unsigned int)insn,
                rt, (unsigned int)(load ? 1 : 0), size, (unsigned long long)offset,
                (offset + sizeof(ULONG_PTR) <= 0x4000) ? (void *)*(ULONG_PTR *)addr : NULL,
                retry ? "POVTOR" : "EMULACIYA",
                (unsigned long long)__atomic_load_n( &shag4_retry_n, __ATOMIC_RELAXED ),
                (unsigned long long)__atomic_load_n( &shag4_x17_n,   __ATOMIC_RELAXED ) );

        if (retry)
        {
            /* Команду НЕ эмулируем, а ПОВТОРЯЕМ: возврат идёт через трамплин, который
             * ветвится через Rt — тот самый регистр, который повтор и перепишет.
             * Ни один живой регистр при этом не портится. */
            thread_data = (struct ntdll_thread_data *)&teb->GdiTebBatch;
            thread_data->apple_x18_save_x10 = REGn_sig(10, context);
            thread_data->apple_x18_save_x16 = REGn_sig(16, context);
            thread_data->apple_x18_save_pc  = PC_sig(context);   /* БЕЗ +4 — это ПОВТОР */
            trace_apple_x18_heal( "direct-retry-load", context, fault_addr, 18, 0, offset );
            REGn_sig(10, context) = (ULONG_PTR)teb;
            REGn_sig(18, context) = (ULONG_PTR)teb;
            PC_sig(context)       = (ULONG_PTR)apple_x18_resume_by_rt[rt];
            macrunner_x18_resume_note( &macrunner_x18.heal_thunk );
            return TRUE;
        }
    }

    if (load)
    {
        switch (size)
        {
        case 1: value = *(BYTE *)addr; break;
        case 2: value = *(WORD *)addr; break;
        case 4: value = *(DWORD *)addr; break;
        case 8: value = *(ULONG_PTR *)addr; break;
        default: return FALSE;
        }
        if (rt != 31) REGn_sig(rt, context) = value;
    }
    else
    {
        if (rt != 31) value = REGn_sig(rt, context);
        switch (size)
        {
        case 1: *(BYTE *)addr = value; break;
        case 2: *(WORD *)addr = value; break;
        case 4: *(DWORD *)addr = value; break;
        case 8: *(ULONG_PTR *)addr = value; break;
        default: return FALSE;
        }
    }

    /* The memory operation has been completed, but we still need to return
     * through user-mode code that rehydrates x18.  If we simply advance PC in
     * the signal context, xnu clears x18 again on sigreturn and the next
    * non-faulting x18-derived instruction can materialize a bogus pointer. */
    thread_data = (struct ntdll_thread_data *)&teb->GdiTebBatch;
    if (apple_x18_restart_owned_thunk( context, teb )) return TRUE;
    thread_data->apple_x18_save_x10 = REGn_sig(10, context);
    thread_data->apple_x18_save_x16 = REGn_sig(16, context);
    thread_data->apple_x18_save_pc  = PC_sig(context) + 4;
    trace_apple_x18_heal( load ? "direct-emulate-load" : "direct-emulate-store",
                          context, fault_addr, 18, 0, offset );
    REGn_sig(10, context) = (ULONG_PTR)teb;
    REGn_sig(18, context) = (ULONG_PTR)teb;
    PC_sig(context)       = (ULONG_PTR)__wine_pe_x18_resume_thunk;
    macrunner_x18_resume_note( &macrunner_x18.heal_thunk );
    return TRUE;
}

#else
static BOOL macrunner_hb_trace_low_stack_fault_enabled(void)
{
    return TRUE;
}

#endif


/**********************************************************************
 *		segv_handler
 *
 * Handler for SIGSEGV.
 */

/* MacRunner 2026-08-05 — есть ли право на исполнение у области под адресом.
 * Вынесено отдельно, чтобы прибор pc-region мог отфильтровать штатные страничные отказы
 * (у них PC исполняемый) и потратить бюджет печати на единственный интересный случай. */
/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ОБЯЗАТЕЛЬНО спускаться в подкарты.
 *
 * Первая версия спрашивала с depth=0 и на этом попадалась: кеш общих библиотек macOS
 * (0x180000000 и выше) — это ПОДКАРТА, и запрос глубины 0 отдаёт запись самой подкарты
 * с правами r--, а не листовое отображение конкретной библиотеки, которое r-x. Из-за
 * этого ЛЮБОЙ адрес в системной библиотеке объявлялся неисполняемым: сверено с vmmap
 * постороннего процесса, где та же libsystem_platform.dylib честно r-x/r-x.
 * Цена ошибки — 16 ложных срабатываний прибора и вывод «мы закрыли кеш от исполнения»,
 * который пришлось снимать. Спускаемся, пока запись помечена is_submap. */
static BOOL macrunner_region_lookup( ULONG_PTR addr, mach_vm_address_t *out_addr,
                                     mach_vm_size_t *out_size,
                                     vm_region_submap_short_info_data_64_t *out_info )
{
    mach_vm_address_t a = (mach_vm_address_t)addr;
    mach_vm_size_t sz = 0;
    vm_region_submap_short_info_data_64_t info;
    mach_msg_type_number_t cnt;
    natural_t depth = 0;
    unsigned int guard;

    for (guard = 0; guard < 8; guard++)
    {
        a = (mach_vm_address_t)addr;
        sz = 0;
        cnt = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
        if (mach_vm_region_recurse( mach_task_self(), &a, &sz, &depth,
                                    (vm_region_recurse_info_t)&info, &cnt ) != KERN_SUCCESS)
            return FALSE;
        if (addr < (ULONG_PTR)a || addr >= (ULONG_PTR)(a + sz)) return FALSE;
        if (!info.is_submap) break;
        depth++;
    }
    if (out_addr) *out_addr = a;
    if (out_size) *out_size = sz;
    if (out_info) *out_info = info;
    return TRUE;
}

static BOOL macrunner_pc_region_probe_enabled(void)
{
    static int enabled = -1;
    int value = __atomic_load_n( &enabled, __ATOMIC_RELAXED );

    if (value < 0)
    {
        const char *env = macrunner_hb_getenv( "MACRUNNER_HB_TRACE_PC_REGION" );
        /* Preserve the existing explicit exception investigation mode. */
        if (!env) env = macrunner_hb_getenv( "MACRUNNER_HB_PROBE_RAISE" );
        value = env && env[0] && env[0] != '0';
        __atomic_store_n( &enabled, value, __ATOMIC_RELAXED );
    }
    return value;
}

static BOOL macrunner_pc_region_is_exec( ULONG_PTR addr )
{
    vm_region_submap_short_info_data_64_t info;

    if (!macrunner_region_lookup( addr, NULL, NULL, &info )) return FALSE;
    return (info.protection & VM_PROT_EXECUTE) != 0;
}


/* MacRunner 2026-08-29 — ВЫВОД ИЗ ОБРАБОТЧИКА СИГНАЛА БЕЗ ЗАМКОВ STDIO.
 *
 * Каждый восьмой прогон Diablo вставал намертво: журнал обрывался сразу после
 * `macrunner-vhf-probe` (наша диагностика внутри segv_handler), дальше тишина до
 * будильника, CPU процесса 0 %. То есть он не крутился, а СПАЛ — на замке.
 *
 * Причина: `fprintf` не async-signal-safe. Он берёт замок потока stdio. Если
 * сигнал пришёл в тот момент, когда этот же поток уже печатал журнал и держал
 * замок, обработчик встаёт на нём же — и ждать некому: разбудить может только
 * прерванный код, а он не продолжится, пока не вернётся обработчик. Тупик.
 *
 * Тот же класс, что `getenv` в обработчике завершения, который сегодня ронял
 * Diablo, UnrealTournament и rpcss через `_os_unfair_lock_recursive_abort`.
 *
 * `vsnprintf` пишет в НАШУ память и замков stdio не берёт; `write` — один из
 * немногих вызовов, прямо разрешённых POSIX внутри обработчика. Формат у нас
 * простой (%s/%p/%x/%u/%d), плавающих чисел и позиционных аргументов нет. */
/* ==========================================================================
 * M0 — ПРИБОР «ЗАСТРЯЛ ЛИ СКАНЕР ЖИВОГО СТЕКА» (лейн СКАНЕР, 07.09.2026)
 *
 * Наряд: reports/research/20260907-ASTRA-M0-SKANER-STEKA.md
 *
 * Отвечает на ОДИН вопрос: сканирование живого стека в macrunner_hb_print_fault_regs
 * ЗАВЕРШАЕТСЯ или нет, и если нет — на каком EA и с какими правами.
 *
 * Устройство (§2 наряда):
 *   M0-E — свидетели episode: разделяемый файл, отображённый MAP_SHARED. В обработчике
 *          ТОЛЬКО записи в заранее подготовленную память. Ни printf, ни getenv, ни
 *          malloc, ни запросов карты, ни разыменования гостевых указателей РАДИ M0.
 *          Данные переживают смерть процесса — их читает наблюдатель.
 *   M0-O — внешний наблюдатель (tools/m0-stack/observe.c), сюда не входит.
 *
 * ★ НИКАКОЙ ЗАПИСИ НА КАЖДОМ w[i]. Продвижение индекса берёт наблюдатель из регистров
 *   живой команды. Иначе прибор изменил бы измеряемое (печать в горячем пути i386
 *   однажды подавила ступень лестницы).
 *
 * Гейты (читаются ОДИН раз при init, не в обработчике):
 *   MACRUNNER_M0_RECORD=1     включить запись
 *   MACRUNNER_M0_DIR=<путь>   куда положить m0-<pid>-<start>.bin и .json
 *   MACRUNNER_M0_CONTROL_CASE=<имя>  отрицательный контроль в отдельном ребёнке
 * ========================================================================== */

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>

#define MACRUNNER_M0_MAGIC     0x304D524Du      /* 'M' 'R' 'M' '0' */
#define MACRUNNER_M0_SCHEMA    1u
#define MACRUNNER_M0_THREADS   48u
#define MACRUNNER_M0_RING      64u
#define MACRUNNER_M0_RECSZ     1024u
#define MACRUNNER_M0_PAYLOAD   928u
#define MACRUNNER_M0_DEPTH     4u
#define MACRUNNER_M0_HDRSZ     4096u
#define MACRUNNER_M0_THDRSZ    512u

/* вид записи */
enum {
    M0_KIND_SIG_ENTRY   = 1,
    M0_KIND_SIG_LEAVE   = 2,
    M0_KIND_DUMP_BEGIN  = 3,
    M0_KIND_DUMP_END    = 4,
    M0_KIND_SCAN_BEGIN  = 5,
    M0_KIND_SCAN_END    = 6,
    M0_KIND_VHF_RESULT  = 7,
    M0_KIND_CONTROL     = 8
};

/* фаза (§3.2) */
enum {
    M0_PHASE_NONE = 0, M0_PHASE_HANDLER = 1, M0_PHASE_DUMP_PRE_SCAN = 2,
    M0_PHASE_SCAN_SETUP = 3, M0_PHASE_SCAN_LOOP = 4, M0_PHASE_DUMP_POST_SCAN = 5,
    M0_PHASE_DUMP_DONE = 6, M0_PHASE_HANDLER_LEAVE = 7, M0_PHASE_CONTROL = 8
};

#pragma pack(push, 8)
struct m0_rec                        /* ровно 1024 байта, разметка §3.4 */
{
    uint64_t published_ticket;       /*   0  публикуется ПОСЛЕДНИМ, release-store */
    uint64_t reserved_ticket;        /*   8 */
    uint32_t kind;                   /*  16 */
    uint32_t validity;               /*  20 */
    uint64_t tid;                    /*  24 */
    uint64_t thread_generation;      /*  32 */
    uint64_t signal_id;              /*  40 */
    uint64_t parent_signal_id;       /*  48 */
    uint64_t dump_id;                /*  56 */
    uint64_t scan_id;                /*  64 */
    uint64_t parent_scan_id;         /*  72 */
    uint64_t phase_seq;              /*  80 */
    uint32_t payload_len;            /*  88 */
    uint32_t flags;                  /*  92 */
    uint64_t t_mach;                 /*  96  mach_absolute_time на публикации */
    unsigned char payload[MACRUNNER_M0_PAYLOAD - 8];  /* 104..1023 */
};

struct m0_thread                     /* ровно 512 байт */
{
    uint64_t tid;                    /*   0  0 = слот свободен */
    uint64_t generation;             /*   8 */
    uint64_t next_signal_id;         /*  16 */
    uint64_t next_dump_id;           /*  24 */
    uint64_t next_scan_id;           /*  32 */
    uint64_t sig_enter_total;        /*  40 */
    uint64_t sig_leave_total;        /*  48 */
    uint64_t dump_enter_total;       /*  56 */
    uint64_t dump_done_total;        /*  64 */
    uint64_t scan_enter_total;       /*  72 */
    uint64_t scan_done_total;        /*  80 */
    uint64_t scan_abandoned_total;   /*  88 */
    uint64_t active_signal_id[MACRUNNER_M0_DEPTH];  /*  96 */
    uint64_t active_dump_id[MACRUNNER_M0_DEPTH];    /* 128 */
    uint64_t active_scan_id[MACRUNNER_M0_DEPTH];    /* 160 */
    uint64_t depth;                  /* 192 */
    uint64_t phase;                  /* 200 */
    uint64_t phase_seq;              /* 208 */
    uint64_t scan_sp;                /* 216 */
    uint64_t scan_verh;              /* 224 */
    uint64_t scan_predel;            /* 232 */
    uint64_t scan_ea_first;          /* 240 */
    uint64_t ring_reserve;           /* 248 */
    uint32_t overflow;               /* 256 */
    uint32_t depth_overflow;         /* 260 */
    uint32_t in_flight;              /* 264 */
    uint32_t pad0;                   /* 268 */
    uint64_t reserved[30];           /* 272..511 */
};

struct m0_header                     /* ровно 4096 байт */
{
    uint32_t magic;                  /*   0 */
    uint32_t schema;                 /*   4 */
    uint32_t endian_probe;           /*   8  0x01020304 */
    uint32_t rec_size;               /*  12 */
    uint32_t thread_slots;           /*  16 */
    uint32_t ring_records;           /*  20 */
    uint32_t thread_stride;          /*  24 */
    uint32_t header_size;            /*  28 */
    uint64_t pid;                    /*  32 */
    uint64_t proc_start_sec;         /*  40 */
    uint64_t proc_start_usec;        /*  48 */
    uint64_t nonce;                  /*  56 */
    uint64_t init_ok;                /*  64 */
    int64_t  mlock_rc;               /*  72 */
    uint64_t prefault_pages;         /*  80 */
    uint64_t control_case;           /*  88 */
    uint32_t timebase_numer;         /*  96 */
    uint32_t timebase_denom;         /* 100 */
    uint64_t unregistered;           /* 104 */
    uint64_t thread_hdr_size;        /* 112 */
    uint64_t payload_size;           /* 120 */
    char     build_marker[64];       /* 128 */
    uint64_t reserved[488];          /* 192..4095 */
};
#pragma pack(pop)

_Static_assert( sizeof(struct m0_rec)    == MACRUNNER_M0_RECSZ, "m0_rec size" );
_Static_assert( sizeof(struct m0_thread) == MACRUNNER_M0_THDRSZ, "m0_thread size" );
_Static_assert( sizeof(struct m0_header) == MACRUNNER_M0_HDRSZ, "m0_header size" );
_Static_assert( offsetof(struct m0_rec, payload) == 104, "m0_rec payload offset" );

/* полезная нагрузка: копия контекста (§3.2 primary_context/dump_context) */
struct m0_ctx_payload
{
    uint64_t x[29];        /* x0..x28 */
    uint64_t fp, lr, sp, pc, cpsr;
    uint64_t esr, far_, exception;
    uint64_t uc_sigmask;
    uint64_t ss_sp, ss_size, ss_flags;
    uint64_t si_signo, si_code, si_addr;
    uint64_t ucontext_addr, mcontext_addr;
    uint64_t signum, site_tag;
};
_Static_assert( sizeof(struct m0_ctx_payload) <= MACRUNNER_M0_PAYLOAD - 8, "ctx payload fits" );

struct m0_scan_payload
{
    uint64_t sp, verh, predel_slov, ea_first, upper_source, control_override;
    uint64_t index, shown, ea_last, outcome;
};
_Static_assert( sizeof(struct m0_scan_payload) <= MACRUNNER_M0_PAYLOAD - 8, "scan payload fits" );

static unsigned char *macrunner_m0_base;     /* NULL = запись выключена */
static struct m0_header *macrunner_m0_hdr;
static size_t macrunner_m0_len;
static int macrunner_m0_gate;                /* значение гейта, прочитано при init */

/* Управляемая подмена входов сканера — ТОЛЬКО для отрицательного контроля (§6.2 п.4).
 * В игровом прогоне остаётся нулём и ветвь недостижима. */
static ULONG_PTR macrunner_m0_control_sp;
static ULONG_PTR macrunner_m0_control_verh;
static int       macrunner_m0_control_armed;

static struct m0_thread *macrunner_m0_thread_at( unsigned i )
{
    return (struct m0_thread *)(macrunner_m0_base + MACRUNNER_M0_HDRSZ +
        (size_t)i * (MACRUNNER_M0_THDRSZ + (size_t)MACRUNNER_M0_RING * MACRUNNER_M0_RECSZ));
}

static struct m0_rec *macrunner_m0_ring_at( struct m0_thread *t, unsigned k )
{
    return (struct m0_rec *)((unsigned char *)t + MACRUNNER_M0_THDRSZ +
                             (size_t)k * MACRUNNER_M0_RECSZ);
}

/* Слот потока: линейный поиск с CAS, без TLS и без выделения памяти.
 * TLS на Darwin может уйти в helper — наряд §5 требует этого избежать. */
static struct m0_thread *macrunner_m0_slot( void )
{
    uint64_t tid = 0;
    unsigned i, start;

    if (!macrunner_m0_base) return NULL;
    if (pthread_threadid_np( NULL, &tid ) || !tid) return NULL;
    start = (unsigned)(tid % MACRUNNER_M0_THREADS);
    for (i = 0; i < MACRUNNER_M0_THREADS; i++)
    {
        struct m0_thread *t = macrunner_m0_thread_at( (start + i) % MACRUNNER_M0_THREADS );
        uint64_t cur = __atomic_load_n( &t->tid, __ATOMIC_ACQUIRE );
        if (cur == tid) return t;
        if (cur == 0)
        {
            uint64_t exp = 0;
            if (__atomic_compare_exchange_n( &t->tid, &exp, tid, 0,
                                             __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE ))
            {
                __atomic_store_n( &t->generation, (uint64_t)1, __ATOMIC_RELEASE );
                return t;
            }
            if (exp == tid) return t;
        }
    }
    __atomic_add_fetch( &macrunner_m0_hdr->unregistered, 1, __ATOMIC_RELAXED );
    return NULL;
}

/* Резервирование записи кольца. Переполнение — ЗАМОРОЗКА со sticky-признаком,
 * а не перезапись: потерянный промежуток нельзя выдать за «событий не было». */
static struct m0_rec *macrunner_m0_reserve( struct m0_thread *t, uint64_t *ticket )
{
    uint64_t r = __atomic_add_fetch( &t->ring_reserve, 1, __ATOMIC_ACQ_REL );
    if (r > MACRUNNER_M0_RING)
    {
        __atomic_store_n( &t->overflow, 1u, __ATOMIC_RELEASE );
        return NULL;
    }
    *ticket = r;
    return macrunner_m0_ring_at( t, (unsigned)(r - 1) );
}

static void macrunner_m0_publish( struct m0_rec *rec, uint64_t ticket, uint32_t kind,
                                  struct m0_thread *t, uint64_t sig_id, uint64_t dump_id,
                                  uint64_t scan_id, const void *payload, uint32_t plen )
{
    if (!rec) return;
    rec->reserved_ticket = ticket;
    rec->kind = kind;
    rec->validity = 1;
    rec->tid = __atomic_load_n( &t->tid, __ATOMIC_RELAXED );
    rec->thread_generation = t->generation;
    rec->signal_id = sig_id;
    rec->parent_signal_id = 0;
    rec->dump_id = dump_id;
    rec->scan_id = scan_id;
    rec->parent_scan_id = 0;
    rec->phase_seq = __atomic_load_n( &t->phase_seq, __ATOMIC_RELAXED );
    rec->flags = 0;
    rec->t_mach = mach_absolute_time();
    if (payload && plen)
    {
        if (plen > MACRUNNER_M0_PAYLOAD - 8) plen = MACRUNNER_M0_PAYLOAD - 8;
        memcpy( rec->payload, payload, plen );
        rec->payload_len = plen;
    }
    else rec->payload_len = 0;
    __atomic_store_n( &rec->published_ticket, ticket, __ATOMIC_RELEASE );
}

static void macrunner_m0_set_phase( struct m0_thread *t, uint64_t phase )
{
    __atomic_store_n( &t->phase, phase, __ATOMIC_RELEASE );
    __atomic_add_fetch( &t->phase_seq, 1, __ATOMIC_RELAXED );
}

static void macrunner_m0_fill_ctx( struct m0_ctx_payload *p, const ucontext_t *c,
                                   const siginfo_t *si, int signum, uint64_t site_tag )
{
    int k;
    memset( p, 0, sizeof(*p) );
    p->signum = (uint64_t)signum;
    p->site_tag = site_tag;
    if (!c) return;
    p->ucontext_addr = (uint64_t)(ULONG_PTR)c;
    p->uc_sigmask = (uint64_t)c->uc_sigmask;
    p->ss_sp = (uint64_t)(ULONG_PTR)c->uc_stack.ss_sp;
    p->ss_size = (uint64_t)c->uc_stack.ss_size;
    p->ss_flags = (uint64_t)(unsigned)c->uc_stack.ss_flags;
    if (!c->uc_mcontext) return;
    p->mcontext_addr = (uint64_t)(ULONG_PTR)c->uc_mcontext;
    for (k = 0; k < 29; k++) p->x[k] = (uint64_t)c->uc_mcontext->__ss.__x[k];
    p->fp   = (uint64_t)c->uc_mcontext->__ss.__fp;
    p->lr   = (uint64_t)c->uc_mcontext->__ss.__lr;
    p->sp   = (uint64_t)c->uc_mcontext->__ss.__sp;
    p->pc   = (uint64_t)c->uc_mcontext->__ss.__pc;
    p->cpsr = (uint64_t)c->uc_mcontext->__ss.__cpsr;
    p->esr  = (uint64_t)c->uc_mcontext->__es.__esr;
    p->far_ = (uint64_t)c->uc_mcontext->__es.__far;
    p->exception = (uint64_t)c->uc_mcontext->__es.__exception;
    if (si)
    {
        p->si_signo = (uint64_t)si->si_signo;
        p->si_code  = (uint64_t)si->si_code;
        p->si_addr  = (uint64_t)(ULONG_PTR)si->si_addr;
    }
}

/* ---- точки инструментирования (вызываются ИЗ обработчика) ---- */

static uint64_t macrunner_m0_sig_enter( const ucontext_t *c, const siginfo_t *si, int signum )
{
    struct m0_thread *t = macrunner_m0_slot();
    struct m0_ctx_payload p;
    struct m0_rec *rec;
    uint64_t ticket = 0, id, d;

    if (!t) return 0;
    d = __atomic_fetch_add( &t->depth, 1, __ATOMIC_ACQ_REL );
    if (d >= MACRUNNER_M0_DEPTH) { __atomic_store_n( &t->depth_overflow, 1u, __ATOMIC_RELEASE ); }
    id = __atomic_add_fetch( &t->next_signal_id, 1, __ATOMIC_ACQ_REL );
    __atomic_store_n( &t->in_flight, 1u, __ATOMIC_RELEASE );
    if (d < MACRUNNER_M0_DEPTH)
        __atomic_store_n( &t->active_signal_id[d], id, __ATOMIC_RELEASE );
    __atomic_add_fetch( &t->sig_enter_total, 1, __ATOMIC_ACQ_REL );
    macrunner_m0_set_phase( t, M0_PHASE_HANDLER );
    macrunner_m0_fill_ctx( &p, c, si, signum, 0 );
    rec = macrunner_m0_reserve( t, &ticket );
    macrunner_m0_publish( rec, ticket, M0_KIND_SIG_ENTRY, t, id, 0, 0, &p, (uint32_t)sizeof(p) );
    __atomic_store_n( &t->in_flight, 0u, __ATOMIC_RELEASE );
    return id;
}

static void macrunner_m0_sig_leave( uint64_t id )
{
    struct m0_thread *t;
    struct m0_rec *rec;
    uint64_t ticket = 0, d;

    if (!id) return;
    t = macrunner_m0_slot();
    if (!t) return;
    macrunner_m0_set_phase( t, M0_PHASE_HANDLER_LEAVE );
    __atomic_add_fetch( &t->sig_leave_total, 1, __ATOMIC_ACQ_REL );
    d = __atomic_load_n( &t->depth, __ATOMIC_ACQUIRE );
    if (d && d - 1 < MACRUNNER_M0_DEPTH)
        __atomic_store_n( &t->active_signal_id[d - 1], (uint64_t)0, __ATOMIC_RELEASE );
    if (d) __atomic_sub_fetch( &t->depth, 1, __ATOMIC_ACQ_REL );
    rec = macrunner_m0_reserve( t, &ticket );
    macrunner_m0_publish( rec, ticket, M0_KIND_SIG_LEAVE, t, id, 0, 0, NULL, 0 );
}

static uint64_t macrunner_m0_dump_begin( const ucontext_t *c, uint64_t site_tag )
{
    struct m0_thread *t = macrunner_m0_slot();
    struct m0_ctx_payload p;
    struct m0_rec *rec;
    uint64_t ticket = 0, id, d;

    if (!t) return 0;
    id = __atomic_add_fetch( &t->next_dump_id, 1, __ATOMIC_ACQ_REL );
    d = __atomic_load_n( &t->depth, __ATOMIC_ACQUIRE );
    if (d) d--;
    __atomic_store_n( &t->in_flight, 1u, __ATOMIC_RELEASE );
    if (d < MACRUNNER_M0_DEPTH)
        __atomic_store_n( &t->active_dump_id[d], id, __ATOMIC_RELEASE );
    __atomic_add_fetch( &t->dump_enter_total, 1, __ATOMIC_ACQ_REL );
    macrunner_m0_set_phase( t, M0_PHASE_DUMP_PRE_SCAN );
    macrunner_m0_fill_ctx( &p, c, NULL, 0, site_tag );
    rec = macrunner_m0_reserve( t, &ticket );
    macrunner_m0_publish( rec, ticket, M0_KIND_DUMP_BEGIN, t, 0, id, 0, &p, (uint32_t)sizeof(p) );
    __atomic_store_n( &t->in_flight, 0u, __ATOMIC_RELEASE );
    return id;
}

static void macrunner_m0_dump_end( uint64_t id )
{
    struct m0_thread *t;
    struct m0_rec *rec;
    uint64_t ticket = 0, d;

    if (!id) return;
    t = macrunner_m0_slot();
    if (!t) return;
    __atomic_add_fetch( &t->dump_done_total, 1, __ATOMIC_ACQ_REL );
    macrunner_m0_set_phase( t, M0_PHASE_DUMP_DONE );
    d = __atomic_load_n( &t->depth, __ATOMIC_ACQUIRE );
    if (d) d--;
    if (d < MACRUNNER_M0_DEPTH)
        __atomic_store_n( &t->active_dump_id[d], (uint64_t)0, __ATOMIC_RELEASE );
    rec = macrunner_m0_reserve( t, &ticket );
    macrunner_m0_publish( rec, ticket, M0_KIND_DUMP_END, t, 0, id, 0, NULL, 0 );
}

static uint64_t macrunner_m0_scan_begin( ULONG_PTR sp, ULONG_PTR verh, int predel,
                                         ULONG_PTR ea_first, uint64_t upper_source,
                                         uint64_t control_override )
{
    struct m0_thread *t = macrunner_m0_slot();
    struct m0_scan_payload p;
    struct m0_rec *rec;
    uint64_t ticket = 0, id, d;

    if (!t) return 0;
    id = __atomic_add_fetch( &t->next_scan_id, 1, __ATOMIC_ACQ_REL );
    d = __atomic_load_n( &t->depth, __ATOMIC_ACQUIRE );
    if (d) d--;
    __atomic_store_n( &t->in_flight, 1u, __ATOMIC_RELEASE );
    __atomic_store_n( &t->scan_sp, (uint64_t)sp, __ATOMIC_RELEASE );
    __atomic_store_n( &t->scan_verh, (uint64_t)verh, __ATOMIC_RELEASE );
    __atomic_store_n( &t->scan_predel, (uint64_t)(int64_t)predel, __ATOMIC_RELEASE );
    __atomic_store_n( &t->scan_ea_first, (uint64_t)ea_first, __ATOMIC_RELEASE );
    if (d < MACRUNNER_M0_DEPTH)
        __atomic_store_n( &t->active_scan_id[d], id, __ATOMIC_RELEASE );
    __atomic_add_fetch( &t->scan_enter_total, 1, __ATOMIC_ACQ_REL );
    macrunner_m0_set_phase( t, M0_PHASE_SCAN_LOOP );
    memset( &p, 0, sizeof(p) );
    p.sp = (uint64_t)sp; p.verh = (uint64_t)verh;
    p.predel_slov = (uint64_t)(int64_t)predel; p.ea_first = (uint64_t)ea_first;
    p.upper_source = upper_source; p.control_override = control_override;
    rec = macrunner_m0_reserve( t, &ticket );
    macrunner_m0_publish( rec, ticket, M0_KIND_SCAN_BEGIN, t, 0, 0, id, &p, (uint32_t)sizeof(p) );
    __atomic_store_n( &t->in_flight, 0u, __ATOMIC_RELEASE );
    return id;
}

static void macrunner_m0_scan_end( uint64_t id, int index, int shown, ULONG_PTR ea_last )
{
    struct m0_thread *t;
    struct m0_scan_payload p;
    struct m0_rec *rec;
    uint64_t ticket = 0, d;

    if (!id) return;
    t = macrunner_m0_slot();
    if (!t) return;
    __atomic_add_fetch( &t->scan_done_total, 1, __ATOMIC_ACQ_REL );
    macrunner_m0_set_phase( t, M0_PHASE_DUMP_POST_SCAN );
    d = __atomic_load_n( &t->depth, __ATOMIC_ACQUIRE );
    if (d) d--;
    if (d < MACRUNNER_M0_DEPTH)
        __atomic_store_n( &t->active_scan_id[d], (uint64_t)0, __ATOMIC_RELEASE );
    memset( &p, 0, sizeof(p) );
    p.index = (uint64_t)(int64_t)index; p.shown = (uint64_t)(int64_t)shown;
    p.ea_last = (uint64_t)ea_last; p.outcome = 1;
    rec = macrunner_m0_reserve( t, &ticket );
    macrunner_m0_publish( rec, ticket, M0_KIND_SCAN_END, t, 0, 0, id, &p, (uint32_t)sizeof(p) );
}

static void macrunner_m0_vhf( unsigned status, uint64_t site_tag )
{
    struct m0_thread *t = macrunner_m0_slot();
    struct m0_scan_payload p;
    struct m0_rec *rec;
    uint64_t ticket = 0;

    if (!t) return;
    memset( &p, 0, sizeof(p) );
    p.outcome = (uint64_t)status;
    p.upper_source = site_tag;
    rec = macrunner_m0_reserve( t, &ticket );
    macrunner_m0_publish( rec, ticket, M0_KIND_VHF_RESULT, t, 0, 0, 0, &p, (uint32_t)sizeof(p) );
}

/* ---- инициализация (ВНЕ обработчика) ---- */

static void macrunner_m0_write_descriptor( const char *dir, pid_t pid,
                                           unsigned long long start_sec,
                                           unsigned long long start_usec,
                                           const char *binpath )
{
    char tmp[1024], fin[1024], buf[2048];
    int fd, n;

    snprintf( fin, sizeof(fin), "%s/m0-%d-%llu.json", dir, (int)pid, start_sec );
    snprintf( tmp, sizeof(tmp), "%s/m0-%d-%llu.json.tmp", dir, (int)pid, start_sec );
    n = snprintf( buf, sizeof(buf),
        "{\"schema\":%u,\"magic\":\"MRM0\",\"pid\":%d,\"proc_start_sec\":%llu,"
        "\"proc_start_usec\":%llu,\"shared_path\":\"%s\",\"bytes\":%llu,"
        "\"header_size\":%u,\"thread_hdr_size\":%u,\"thread_slots\":%u,"
        "\"ring_records\":%u,\"rec_size\":%u,\"thread_stride\":%u,"
        "\"nonce\":%llu,\"mlock_rc\":%lld,\"control_case\":%llu,"
        "\"timebase_numer\":%u,\"timebase_denom\":%u}\n",
        MACRUNNER_M0_SCHEMA, (int)pid, start_sec, start_usec, binpath,
        (unsigned long long)macrunner_m0_len, MACRUNNER_M0_HDRSZ, MACRUNNER_M0_THDRSZ,
        MACRUNNER_M0_THREADS, MACRUNNER_M0_RING, MACRUNNER_M0_RECSZ,
        (unsigned)(MACRUNNER_M0_THDRSZ + MACRUNNER_M0_RING * MACRUNNER_M0_RECSZ),
        (unsigned long long)macrunner_m0_hdr->nonce,
        (long long)macrunner_m0_hdr->mlock_rc,
        (unsigned long long)macrunner_m0_hdr->control_case,
        macrunner_m0_hdr->timebase_numer, macrunner_m0_hdr->timebase_denom );
    fd = open( tmp, O_CREAT | O_TRUNC | O_WRONLY, 0600 );
    if (fd < 0) return;
    if (write( fd, buf, (size_t)n ) != n) { close( fd ); return; }
    close( fd );
    if (rename( tmp, fin )) unlink( tmp );
}

/* Экспорт разметки ИЗ ЭТОЙ ЖЕ СБОРКИ — декодер обязан сверять её со своей (§3.4). */
static void macrunner_m0_write_layout( const char *dir, pid_t pid )
{
    char path[1024], buf[4096];
    int fd, n;

    snprintf( path, sizeof(path), "%s/m0-layout-%d.json", dir, (int)pid );
    n = snprintf( buf, sizeof(buf),
        "{\"rec_size\":%u,\"thread_hdr_size\":%u,\"header_size\":%u,"
        "\"rec\":{\"published_ticket\":%u,\"reserved_ticket\":%u,\"kind\":%u,"
        "\"validity\":%u,\"tid\":%u,\"thread_generation\":%u,\"signal_id\":%u,"
        "\"parent_signal_id\":%u,\"dump_id\":%u,\"scan_id\":%u,\"parent_scan_id\":%u,"
        "\"phase_seq\":%u,\"payload_len\":%u,\"flags\":%u,\"t_mach\":%u,\"payload\":%u},"
        "\"thread\":{\"tid\":%u,\"generation\":%u,\"next_signal_id\":%u,\"next_dump_id\":%u,"
        "\"next_scan_id\":%u,\"sig_enter_total\":%u,\"sig_leave_total\":%u,"
        "\"dump_enter_total\":%u,\"dump_done_total\":%u,\"scan_enter_total\":%u,"
        "\"scan_done_total\":%u,\"scan_abandoned_total\":%u,\"active_signal_id\":%u,"
        "\"active_dump_id\":%u,\"active_scan_id\":%u,\"depth\":%u,\"phase\":%u,"
        "\"phase_seq\":%u,\"scan_sp\":%u,\"scan_verh\":%u,\"scan_predel\":%u,"
        "\"scan_ea_first\":%u,\"ring_reserve\":%u,\"overflow\":%u,\"depth_overflow\":%u,"
        "\"in_flight\":%u},"
        "\"ctx_payload_size\":%u,\"scan_payload_size\":%u,"
        "\"kinds\":{\"SIG_ENTRY\":1,\"SIG_LEAVE\":2,\"DUMP_BEGIN\":3,\"DUMP_END\":4,"
        "\"SCAN_BEGIN\":5,\"SCAN_END\":6,\"VHF_RESULT\":7,\"CONTROL\":8}}\n",
        MACRUNNER_M0_RECSZ, MACRUNNER_M0_THDRSZ, MACRUNNER_M0_HDRSZ,
        (unsigned)offsetof(struct m0_rec, published_ticket),
        (unsigned)offsetof(struct m0_rec, reserved_ticket),
        (unsigned)offsetof(struct m0_rec, kind),
        (unsigned)offsetof(struct m0_rec, validity),
        (unsigned)offsetof(struct m0_rec, tid),
        (unsigned)offsetof(struct m0_rec, thread_generation),
        (unsigned)offsetof(struct m0_rec, signal_id),
        (unsigned)offsetof(struct m0_rec, parent_signal_id),
        (unsigned)offsetof(struct m0_rec, dump_id),
        (unsigned)offsetof(struct m0_rec, scan_id),
        (unsigned)offsetof(struct m0_rec, parent_scan_id),
        (unsigned)offsetof(struct m0_rec, phase_seq),
        (unsigned)offsetof(struct m0_rec, payload_len),
        (unsigned)offsetof(struct m0_rec, flags),
        (unsigned)offsetof(struct m0_rec, t_mach),
        (unsigned)offsetof(struct m0_rec, payload),
        (unsigned)offsetof(struct m0_thread, tid),
        (unsigned)offsetof(struct m0_thread, generation),
        (unsigned)offsetof(struct m0_thread, next_signal_id),
        (unsigned)offsetof(struct m0_thread, next_dump_id),
        (unsigned)offsetof(struct m0_thread, next_scan_id),
        (unsigned)offsetof(struct m0_thread, sig_enter_total),
        (unsigned)offsetof(struct m0_thread, sig_leave_total),
        (unsigned)offsetof(struct m0_thread, dump_enter_total),
        (unsigned)offsetof(struct m0_thread, dump_done_total),
        (unsigned)offsetof(struct m0_thread, scan_enter_total),
        (unsigned)offsetof(struct m0_thread, scan_done_total),
        (unsigned)offsetof(struct m0_thread, scan_abandoned_total),
        (unsigned)offsetof(struct m0_thread, active_signal_id),
        (unsigned)offsetof(struct m0_thread, active_dump_id),
        (unsigned)offsetof(struct m0_thread, active_scan_id),
        (unsigned)offsetof(struct m0_thread, depth),
        (unsigned)offsetof(struct m0_thread, phase),
        (unsigned)offsetof(struct m0_thread, phase_seq),
        (unsigned)offsetof(struct m0_thread, scan_sp),
        (unsigned)offsetof(struct m0_thread, scan_verh),
        (unsigned)offsetof(struct m0_thread, scan_predel),
        (unsigned)offsetof(struct m0_thread, scan_ea_first),
        (unsigned)offsetof(struct m0_thread, ring_reserve),
        (unsigned)offsetof(struct m0_thread, overflow),
        (unsigned)offsetof(struct m0_thread, depth_overflow),
        (unsigned)offsetof(struct m0_thread, in_flight),
        (unsigned)sizeof(struct m0_ctx_payload),
        (unsigned)sizeof(struct m0_scan_payload) );
    fd = open( path, O_CREAT | O_TRUNC | O_WRONLY, 0600 );
    if (fd < 0) return;
    { ssize_t ig = write( fd, buf, (size_t)n ); (void)ig; }
    close( fd );
}

static unsigned macrunner_m0_case_id( const char *name );

/* ★★★ ГЕЙТ СЕМЬИ НЕПРОВЕРЕННЫХ ЧТЕНИЙ В ОБРАБОТЧИКЕ (лейн СКАНЕР, 07.09.2026).
 *
 * ИЗМЕРЕНО M0: в прогоне HK один поток встал на `ldr x21,[x27,x23]` внутри обхода
 * живого стека и не сдвинулся 217,8 с — 44 остановки, PC/EA/scan_id постоянны,
 * scan_done=0, карта EA = NO_READ, ESR 0x92000007 (DFSC 0x07), занятость ядра 82,1 %.
 * SP пришёл из ПРЕРВАННОГО контекста и лежал ВНЕ стека текущего TEB
 * (`macrunner-hb-чей-стек: свой=НЕТ`), верх взят из TEB -> predel_slov=4096,
 * а отображение кончилось на слове №102 (816 байт от SP).
 *
 * Значение по умолчанию — 0: семья опасных чтений ВЫКЛЮЧЕНА. Остаётся всё, что
 * читает только ucontext, плюс записи M0. Гейт открывается поимённо:
 *     MACRUNNER_HB_UNSAFE_FAULT_DUMP=1
 * Это ВРЕМЕННАЯ локализация до безопасной реализации (снимок в обработчике +
 * проверенное чтение снаружи). Гейт вокруг одного printf ничего бы не дал:
 * горячей была команда `ldr`, а не печать. */
static int macrunner_hb_unsafe_fault_dump;   /* 0 = семья опасных чтений выключена */
static unsigned long long macrunner_hb_unsafe_dump_skipped;

static void macrunner_m0_init( void )
{
    const char *g = getenv( "MACRUNNER_M0_RECORD" );
    const char *dir = getenv( "MACRUNNER_M0_DIR" );
    const char *ccase = getenv( "MACRUNNER_M0_CONTROL_CASE" );
    char path[1024];
    struct timeval tv;
    mach_timebase_info_data_t tb;
    size_t need, off;
    int fd;
    void *map;

    {   /* гейт семьи опасных чтений: ОДИН раз, вне обработчика */
        const char *u = getenv( "MACRUNNER_HB_UNSAFE_FAULT_DUMP" );
        macrunner_hb_unsafe_fault_dump = (u && *u && *u != '0') ? 1 : 0;
    }
    if (macrunner_m0_base) return;
    macrunner_m0_gate = (g && *g && *g != '0') ? 1 : 0;
    if (!macrunner_m0_gate || !dir || !*dir) return;

    need = MACRUNNER_M0_HDRSZ + (size_t)MACRUNNER_M0_THREADS *
           (MACRUNNER_M0_THDRSZ + (size_t)MACRUNNER_M0_RING * MACRUNNER_M0_RECSZ);
    gettimeofday( &tv, NULL );
    snprintf( path, sizeof(path), "%s/m0-%d-%llu.bin", dir, (int)getpid(),
              (unsigned long long)tv.tv_sec );
    fd = open( path, O_CREAT | O_EXCL | O_RDWR, 0600 );
    if (fd < 0)
    {
        fprintf( stderr, "macrunner-m0-init: pid=%d ОТКАЗ open(%s) errno=%d\n",
                 (int)getpid(), path, errno );
        return;
    }
    if (ftruncate( fd, (off_t)need )) { close( fd ); return; }
    map = mmap( NULL, need, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );
    close( fd );
    if (map == MAP_FAILED)
    {
        fprintf( stderr, "macrunner-m0-init: pid=%d ОТКАЗ mmap errno=%d\n", (int)getpid(), errno );
        return;
    }
    macrunner_m0_base = (unsigned char *)map;
    macrunner_m0_len = need;
    macrunner_m0_hdr = (struct m0_header *)map;
    memset( map, 0, need );                       /* prefault всех страниц */
    mach_timebase_info( &tb );
    macrunner_m0_hdr->magic = MACRUNNER_M0_MAGIC;
    macrunner_m0_hdr->schema = MACRUNNER_M0_SCHEMA;
    macrunner_m0_hdr->endian_probe = 0x01020304u;
    macrunner_m0_hdr->rec_size = MACRUNNER_M0_RECSZ;
    macrunner_m0_hdr->thread_slots = MACRUNNER_M0_THREADS;
    macrunner_m0_hdr->ring_records = MACRUNNER_M0_RING;
    macrunner_m0_hdr->thread_stride = MACRUNNER_M0_THDRSZ + MACRUNNER_M0_RING * MACRUNNER_M0_RECSZ;
    macrunner_m0_hdr->header_size = MACRUNNER_M0_HDRSZ;
    macrunner_m0_hdr->thread_hdr_size = MACRUNNER_M0_THDRSZ;
    macrunner_m0_hdr->payload_size = MACRUNNER_M0_PAYLOAD - 8;
    macrunner_m0_hdr->pid = (uint64_t)getpid();
    macrunner_m0_hdr->proc_start_sec = (uint64_t)tv.tv_sec;
    macrunner_m0_hdr->proc_start_usec = (uint64_t)tv.tv_usec;
    macrunner_m0_hdr->nonce = (uint64_t)mach_absolute_time();
    macrunner_m0_hdr->timebase_numer = tb.numer;
    macrunner_m0_hdr->timebase_denom = tb.denom;
    macrunner_m0_hdr->control_case = ccase ? macrunner_m0_case_id( ccase ) : 0;
    macrunner_m0_hdr->mlock_rc = mlock( map, need ) ? (int64_t)errno : 0;
    /* ★ ОТДЕЛЬНОГО обхода страниц НЕТ: memset выше уже потрогал КАЖДЫЙ байт.
     * Прежний обход писал 0 по offset 0 каждой страницы и затирал первый байт
     * magic и младшие байты записей — прибор поймал это сам своей проверкой схемы
     * (magic=0x304d5200 вместо 0x304d524d). */
    off = need;
    macrunner_m0_hdr->prefault_pages = (uint64_t)((need + 4095) / 4096);
    memcpy( macrunner_m0_hdr->build_marker, "macrunner-m0-skaner-20260907", 29 );
    macrunner_m0_hdr->init_ok = 1;
    macrunner_m0_write_layout( dir, getpid() );
    macrunner_m0_write_descriptor( dir, getpid(), (unsigned long long)tv.tv_sec,
                                   (unsigned long long)tv.tv_usec, path );
    fprintf( stderr, "macrunner-m0-init: pid=%d файл=%s байт=%llu mlock_rc=%lld слотов=%u\n",
             (int)getpid(), path, (unsigned long long)need,
             (long long)macrunner_m0_hdr->mlock_rc, MACRUNNER_M0_THREADS );
    fflush( stderr );
}

/* Область действия входа в обработчик: обычные выходы закрывает cleanup.
 * siglongjmp его ОБХОДИТ — такой episode останется без EXIT, и это честный
 * признак пробела, а не «вечный обработчик» (§4 наряда). */
struct m0_sig_scope { uint64_t id; };
static void m0_sig_scope_leave( struct m0_sig_scope *s )
{
    if (s) macrunner_m0_sig_leave( s->id );
}

static void macrunner_sig_printf( const char *fmt, ... )
{
    char buf[1024];
    va_list args;
    int n;

    va_start( args, fmt );
    n = vsnprintf( buf, sizeof(buf), fmt, args );
    va_end( args );

    if (n < 0) return;
    if (n > (int)sizeof(buf) - 1) n = sizeof(buf) - 1;   /* усечено — но не потеряно */
    if (n > 0) { ssize_t ignored = write( 2, buf, n ); (void)ignored; }
}

/* ★ ВРЕМЯ ВНУТРИ ОБРАБОТЧИКА (к переписи MACRUNNER_HB_SEGV_CENSUS).
 *
 * Спор, который надо решить числом: `sample` даёт 3630 снимков из 3630 внутри
 * segv_handler за 5 с, а перепись показывает МЕНЬШЕ 16 384 входов за 300 с. Либо каждый
 * вход очень дорог, либо раскрутка в `sample` недостоверна. Различает только доля времени,
 * проведённого В ОБРАБОТЧИКЕ. Замер снимается через cleanup-атрибут, поэтому охватывает
 * ВСЕ выходы из функции, включая ранние return'ы. */
static unsigned long long mr_segv_total_ns;
static unsigned long long mr_segv_first_ns;

struct mr_segv_timer { unsigned long long t0; };

static unsigned long long mr_segv_now_ns(void)
{
    struct timespec ts;
    if (clock_gettime( CLOCK_MONOTONIC, &ts )) return 0;
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}

static void mr_segv_timer_leave( struct mr_segv_timer *t )
{
    unsigned long long now;
    if (!t || !t->t0) return;
    now = mr_segv_now_ns();
    if (now > t->t0) __atomic_add_fetch( &mr_segv_total_ns, now - t->t0, __ATOMIC_RELAXED );
}

/* ★★★★★ 2026-08-30, лейн УСТАНОВЩИКИ — x18 ВОССТАНАВЛИВАЕТСЯ НА ЛЮБОМ ВОЗВРАТЕ В КОД.
 *
 * macOS стирает x18 при возврате из обработчика сигнала, а PE-код по Windows-ABI держит
 * там TEB. В дереве это лечится трамплином `__wine_pe_x18_resume_thunk`, но ТОЛЬКО на двух
 * путях: отправка исключения (`:2951`) и возврат из диспетчера системных вызовов (`:3420`).
 * ТРЕТИЙ путь — обычный возврат к прерванной команде — не покрыт, и именно он всё ломает.
 *
 * Что это стоило (замер 30.08): сигнал приходит между входом в
 * `Wow64KiUserCallbackDispatcher` и его прологом; после возврата x18 = 0, пролог делает
 * `mov x8, x18` и `add x26, x8, x9`, и дальше КАЖДОЕ обращение по этим регистрам
 * отказывает. Поштучное лечение сняло первое место (гостевых вызовов 557 -> 99 356), но
 * второе (`str w28,[x26]` на +0x7F4) недостижимо: определяющая команда за 480 команд, а
 * окно поиска 32. Класс снимается только тем, чтобы PE-код НИКОГДА не видел стёртый x18.
 *
 * Замер снимается через cleanup-атрибут — он охватывает ВСЕ выходы из обработчика.
 * Пропускаем случай, когда PC уже изменён: значит возврат перенаправлен другим путём,
 * и он сам ставит x18. Гейт `MACRUNNER_HB_X18_RESUME_ALWAYS=1`, умолчание 0. */
struct mr_x18_resume_scope { ucontext_t *ctx; ULONG_PTR entry_pc; int on; };

static void mr_x18_resume_leave( struct mr_x18_resume_scope *scope )
{
    if (!scope || !scope->on || !scope->ctx) return;
    if (scope->entry_pc < 0x10000) return;
    if (PC_sig(scope->ctx) != scope->entry_pc) return;   /* уже перенаправлено */
    setup_x18_resume_from_sigcontext( scope->ctx );
}

static int mr_x18_resume_always(void)
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = macrunner_hb_getenv( "MACRUNNER_HB_X18_RESUME_ALWAYS" );
        cached = (v && v[0] && v[0] != '0');
    }
    return cached;
}


/* ★★★★★ MacRunner 2026-08-31 — ОДИН ПЕЧАТНИК РЕГИСТРОВ НА ОБЕ ПЛОЩАДКИ.
 *
 * Изъян «прибор стоит только на segv» повторился ЧЕТЫРЕ раза подряд: дамп списка
 * загрузчика (лейн МЕЛКИЕ, итерация 81), запрос области (84), цепочка кадров (86) и
 * вот регистры. Каждый раз его чинили КОПИРОВАНИЕМ блока на вторую площадку — и
 * следующий прибор рождался с тем же изъяном. Копия не переносит исправление на
 * будущее (см. память проекта: zaplatka-na-meste-ne-perenositsya).
 *
 * Поэтому печать регистров вынесена в ОДНУ функцию, и обе площадки зовут её. Новый
 * регистр добавляется в одном месте и сразу появляется на обеих.
 *
 * ЧТО ПЕЧАТАЕМ И ПОЧЕМУ ИМЕННО ЭТО. Для отказа ВЫБОРКИ инструкции сохраняемых
 * регистров x19-x30 мало: переход через переходник на ARM64 идёт `ldr x16,[...]; br x16`,
 * цель лежит в X16 (у длинного переходника — X17), а X8 держит цель у косвенного
 * вызова, выпущенного clang. Без них нельзя отличить переход по переходнику от порчи
 * адреса возврата — ровно на этом встала цепочка
 * combase!start_rpcss -> NdrClientCall2 -> ndr_client_call -> страница rw. */
/* ★★★★★★ MacRunner 2026-08-31 — ЧТО ЭТО ЗА АДРЕС: ОДИН ОТВЕТ, А НЕ ПОХОД ПО ШАГАМ.
 *
 * Владелец: «почему прибор не показывает конечный путь, а водит туда-сюда». Он прав,
 * и это нарушение НАШЕГО ЖЕ правила «печатать все источники истины в одной точке».
 * Каждый шаг сегодня требовал НОВОГО прибора: сперва регистры, потом кадр по fp,
 * потом по sp, потом шаги раскрутки, потом возобновление, потом опознание области —
 * и каждый раз пересборка и прогон. Данных в журнале просто не было.
 *
 * Поэтому здесь адрес отказа сверяется СРАЗУ со всеми известными структурами процесса.
 * Ответ «это конец блока параметров процесса» должен приходить с ПЕРВОГО прогона. */
/* ★★★★★★ MacRunner 2026-09-01 — БЕЗОПАСНОЕ ЧТЕНИЕ В ОБРАБОТЧИКЕ СИГНАЛА.
 *
 * Установщик GTA Vice City (Inno Setup) «зависал» сразу после создания временной
 * папки: собственный журнал установщика не двигался десять минут, движок тоже
 * замолкал. Срез стека назвал виновника, и это МЫ:
 *
 *     segv_handler                     <- случился SIGSEGV
 *       macrunner_hb_print_fault_regs  <- наш прибор печати регистров
 *         macrunner_hb_name_address    <- наш прибор именования адреса
 *           bus_handler                <- прибор УПАЛ САМ (SIGBUS)
 *
 * Причина: прибор печатает 16 байт ПО САМОМУ АДРЕСУ и 8 байт по началу его области,
 * а зовут его для pc и x30 — то есть ровно тогда, когда адрес может быть
 * неотображён. Второй отказ приходит внутри обработчика первого, и процесс виснет.
 *
 * mach_vm_read_overwrite возвращает ошибку вместо отказа, поэтому годится там, где
 * разыменование смертельно. */
static BOOL macrunner_hb_safe_copy( ULONG_PTR addr, void *buf, size_t len )
{
    mach_vm_size_t got = 0;

    if (!addr || len > ~(ULONG_PTR)0 - addr) return FALSE;
    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)addr,
                                (mach_vm_size_t)len, (mach_vm_address_t)buf,
                                &got ) != KERN_SUCCESS)
        return FALSE;
    return got == (mach_vm_size_t)len;
}

/* Fault diagnostics must not cause a second fault, even when explicitly enabled. */
static void macrunner_hb_dump_vhf_stack( ucontext_t *context )
{
    ULONG_PTR fp = (ULONG_PTR)REGn_sig(29, context);
    ULONG_PTR sp = (ULONG_PTR)SP_sig(context);
    char line[512];
    int len;

    if (!macrunner_hb_unsafe_fault_dump) return;
    len = snprintf( line, sizeof(line), "macrunner-vhf-стек: pid=%d lr=%p",
                    (int)getpid(), (void *)(ULONG_PTR)REGn_sig(30, context) );
    for (unsigned k = 0; k < 12 && len > 0 && len < (int)sizeof(line) - 24; k++)
    {
        ULONG_PTR frame[2];

        if (fp < sp || (fp & 15) || fp - sp > 0x800000) break;
        if (!macrunner_hb_safe_copy( fp, frame, sizeof(frame) )) break;
        if (!frame[1]) break;
        len += snprintf( line + len, sizeof(line) - len, " %p", (void *)frame[1] );
        if (frame[0] <= fp) break;
        fp = frame[0];
    }
    macrunner_sig_printf( "%s\n", line );
}

static void macrunner_hb_dump_vhf_site( ucontext_t *context )
{
    ULONG_PTR pc = (ULONG_PTR)PC_sig(context);
    ULONG_PTR lr = (ULONG_PTR)REGn_sig(30, context) & ~(ULONG_PTR)3;
    unsigned int insn = 0, code[10];
    BOOL readable;

    if (!macrunner_hb_unsafe_fault_dump) return;
    readable = macrunner_hb_safe_copy( pc, &insn, sizeof(insn) );
    macrunner_sig_printf( "macrunner-vhf-selfcheck: pid=%d tid=%llu pc=%p слово_по_pc=%08x "
                          "readable=%u x0=%p x1=%p x2=%p x3=%p\n",
                          (int)getpid(), (unsigned long long)pthread_mach_thread_np( pthread_self() ),
                          (void *)pc, insn, readable,
                          (void *)(ULONG_PTR)REGn_sig(0, context), (void *)(ULONG_PTR)REGn_sig(1, context),
                          (void *)(ULONG_PTR)REGn_sig(2, context), (void *)(ULONG_PTR)REGn_sig(3, context) );
    if (lr >= 0x24 && macrunner_hb_safe_copy( lr - 0x24, code, sizeof(code) ))
        macrunner_sig_printf( "macrunner-vhf-callsite: pid=%d base=%p "
                              "%08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
                              (int)getpid(), (void *)(lr - 0x24),
                              code[0], code[1], code[2], code[3], code[4],
                              code[5], code[6], code[7], code[8], code[9] );
    macrunner_hb_dump_vhf_stack( context );
    /* x0 is an arbitrary argument (e.g. section handle 0x3c), not CPTABLEINFO. */
}

static void macrunner_hb_name_address( ULONG_PTR a, const char *what )
{
    /* ★★★★★★ 03.09.2026 — САМИ ПОЛЯ TEB И PEB ТОЖЕ ЧИТАЕМ БЕЗОПАСНО.
     *
     * Безопасное чтение уже стояло на 16 байтах ПО РАЗБИРАЕМОМУ адресу, но `teb->Peb`
     * и `peb->ProcessParameters` разыменовывались напрямую — а у мишени через WoW64
     * `Peb` приводит на 32-битный блок ПО ГОСТЕВОМУ адресу. Установщик GTA Vice City
     * умирал здесь: отказ по 0x201010, то есть ровно `PEB(0x201000) + 0x10`, поле
     * ProcessParameters 32-битного PEB. Прибор падал ВНУТРИ разбора чужого отказа и
     * уносил процесс — установка вставала после «Created temporary directory», и это
     * списывали на движок.
     *
     * Правило прежнее и теперь без исключений: в обработчике ни одного прямого
     * разыменования. */
    TEB *teb = NtCurrentTeb();
    PEB *peb = NULL;
    RTL_USER_PROCESS_PARAMETERS *pp = NULL;

    if (teb) macrunner_hb_safe_copy( (ULONG_PTR)&teb->Peb, &peb, sizeof(peb) );
    if (peb) macrunner_hb_safe_copy( (ULONG_PTR)&peb->ProcessParameters, &pp, sizeof(pp) );

    if (!a) return;
    if (teb)
    {
        ULONG_PTR lo = (ULONG_PTR)teb->Tib.StackLimit, hi = (ULONG_PTR)teb->Tib.StackBase;
        if (lo && hi && a >= lo && a < hi)
        { macrunner_sig_printf( "macrunner-vhf-что: %s=%p -> СТЕК потока (+%p от предела)\n",
                                what, (void *)a, (void *)(a - lo) ); return; }
        if (a >= (ULONG_PTR)teb && a < (ULONG_PTR)teb + 0x2000)
        { macrunner_sig_printf( "macrunner-vhf-что: %s=%p -> TEB (+%p)\n",
                                what, (void *)a, (void *)(a - (ULONG_PTR)teb) ); return; }
    }
    /* ★ 31.08 — У WoW64-ПРОЦЕССА ДВА PEB. Мишень i386 идёт через WoW64, и у неё есть
     * ВТОРОЙ, 32-битный PEB со своим блоком параметров. Первая редакция сверяла только
     * с родным и печатала «не опознан», хотя адрес лежал в 32-битном блоке. Молчание
     * прибора я тогда принял за подсказку и построил ложную догадку про разметку
     * структуры — см. память: gipotezu-stroil-ya-a-ne-pribor. */
    if (teb && teb->WowTebOffset)
    {
        TEB32 *teb32 = (TEB32 *)((char *)teb + teb->WowTebOffset);
        ULONG_PTR peb32 = teb32 ? (ULONG_PTR)teb32->Peb : 0;
        if (peb32 && a >= peb32 && a < peb32 + 0x1000)
        { macrunner_sig_printf( "macrunner-vhf-что: %s=%p -> PEB32 (WoW64, +%p)\n",
                                what, (void *)a, (void *)(a - peb32) ); return; }
        if (peb32)
        {
            /* ★ 03.09: `peb32` — ГОСТЕВОЙ адрес. Прямое разыменование здесь и убивало
             * установщик GTA Vice City: отказ по PEB32+0x10. Читаем безопасно. */
            ULONG pp32_raw = 0;
            ULONG_PTR pp32;
            macrunner_hb_safe_copy( peb32 + offsetof(PEB32, ProcessParameters),
                                    &pp32_raw, sizeof(pp32_raw) );
            pp32 = (ULONG_PTR)pp32_raw;
            if (pp32 && a >= pp32 && a < pp32 + 0x10000)
            { macrunner_sig_printf( "macrunner-vhf-что: %s=%p -> БЛОК ПАРАМЕТРОВ WoW64 "
                                    "(база=%p, +%p)\n",
                                    what, (void *)a, (void *)pp32, (void *)(a - pp32) ); return; }
        }
    }
    if (peb && a >= (ULONG_PTR)peb && a < (ULONG_PTR)peb + 0x1000)
    { macrunner_sig_printf( "macrunner-vhf-что: %s=%p -> PEB (+%p)\n",
                            what, (void *)a, (void *)(a - (ULONG_PTR)peb) ); return; }
    if (pp)
    {
        /* ★ 03.09: `pp` тоже может оказаться гостевым адресом — читаем безопасно. */
        ULONG_PTR base = (ULONG_PTR)pp;
        void *env_raw = NULL, *cmd_raw = NULL;
        ULONG_PTR env, cmd;

        macrunner_hb_safe_copy( base + offsetof(RTL_USER_PROCESS_PARAMETERS, Environment),
                                &env_raw, sizeof(env_raw) );
        macrunner_hb_safe_copy( base + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine)
                                     + offsetof(UNICODE_STRING, Buffer),
                                &cmd_raw, sizeof(cmd_raw) );
        env = (ULONG_PTR)env_raw;
        cmd = (ULONG_PTR)cmd_raw;
        if (a >= base && a < base + 0x10000)
        {
            macrunner_sig_printf( "macrunner-vhf-что: %s=%p -> БЛОК ПАРАМЕТРОВ ПРОЦЕССА "
                     "(база=%p +%p, Environment=%p, CommandLine=%p)\n",
                     what, (void *)a, (void *)base, (void *)(a - base),
                     (void *)env, (void *)cmd );
            if (env && a >= env) macrunner_sig_printf(
                     "macrunner-vhf-что:   ВНУТРИ окружения, смещение +%p\n", (void *)(a - env) );
            else if (cmd && a >= cmd) macrunner_sig_printf(
                     "macrunner-vhf-что:   ВНУТРИ командной строки, смещение +%p\n", (void *)(a - cmd) );
            return;
        }
    }
    /* Не опознан по структурам — тогда пусть СОДЕРЖИМОЕ назовёт себя само: печатаем
     * байты по адресу и в начале его 64-килобайтной области. Указатели, сигнатуры и
     * текст видно сразу, и не нужен новый прогон ради ещё одного прибора. */
    {
        ULONG_PTR reg = a & ~(ULONG_PTR)0xffff;
        unsigned char qbuf[16], rbuf[8];
        BOOL q_ok = macrunner_hb_safe_copy( a, qbuf, sizeof(qbuf) );
        BOOL r_ok = macrunner_hb_safe_copy( reg, rbuf, sizeof(rbuf) );
        const unsigned char *q = qbuf, *r = rbuf;
        {   /* ★ Спросить САМУ СИСТЕМУ, что это за область: MEM_IMAGE / MEM_MAPPED /
             * MEM_PRIVATE отвечают на вопрос «кто её создал» лучше любых догадок.
             * MEM_MAPPED значит отображение секции (разделяемая память wineserver),
             * MEM_PRIVATE — обычное выделение процесса. */
            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T len = 0;
            if (!NtQueryVirtualMemory( NtCurrentProcess(), (void *)a, MemoryBasicInformation,
                                       &mbi, sizeof(mbi), &len ))
                macrunner_sig_printf( "macrunner-vhf-что:   область по системе: AllocationBase=%p "
                         "RegionSize=%p State=%08lx Protect=%08lx AllocProtect=%08lx Type=%08lx%s\n",
                         mbi.AllocationBase, (void *)mbi.RegionSize,
                         (unsigned long)mbi.State, (unsigned long)mbi.Protect,
                         (unsigned long)mbi.AllocationProtect, (unsigned long)mbi.Type,
                         mbi.Type == 0x1000000 ? "  (MEM_IMAGE)" :
                         mbi.Type == 0x40000   ? "  (MEM_MAPPED — отображение секции)" :
                         mbi.Type == 0x20000   ? "  (MEM_PRIVATE)" : "" );
        }
        {   /* печатаем сами адреса структур — иначе «не опознан» неотличимо от
         * «сравнил не с тем». Это и подвело: адрес лежал в блоке параметров, а
         * проверка сравнивала с другим указателем. */
        macrunner_sig_printf( "macrunner-vhf-что:   для сверки: PEB=%p ProcessParameters=%p "
                 "Environment=%p CommandLine=%p StackLimit=%p StackBase=%p\n",
                 peb, pp, pp ? (void *)pp->Environment : NULL,
                 pp ? (void *)pp->CommandLine.Buffer : NULL,
                 teb ? teb->Tib.StackLimit : NULL, teb ? teb->Tib.StackBase : NULL );
    }
    if (!q_ok)
        macrunner_sig_printf( "macrunner-vhf-что: %s=%p -> не опознан; байты НЕЧИТАЕМЫ "
                 "(адрес не отображён)\n", what, (void *)a );
    else
        macrunner_sig_printf( "macrunner-vhf-что: %s=%p -> не опознан; байты по адресу: "
                 "%02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n",
                 what, (void *)a, q[0],q[1],q[2],q[3],q[4],q[5],q[6],q[7],
                 q[8],q[9],q[10],q[11],q[12],q[13],q[14],q[15] );
        if (!r_ok)
            macrunner_sig_printf( "macrunner-vhf-что:   начало области %p: НЕЧИТАЕМО\n",
                                  (void *)reg );
        else
        macrunner_sig_printf( "macrunner-vhf-что:   начало области %p: "
                 "%02x %02x %02x %02x %02x %02x %02x %02x | как текст: %c%c%c%c%c%c%c%c\n",
                 (void *)reg, r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],
                 (r[0]>31&&r[0]<127)?r[0]:'.', (r[1]>31&&r[1]<127)?r[1]:'.',
                 (r[2]>31&&r[2]<127)?r[2]:'.', (r[3]>31&&r[3]<127)?r[3]:'.',
                 (r[4]>31&&r[4]<127)?r[4]:'.', (r[5]>31&&r[5]<127)?r[5]:'.',
                 (r[6]>31&&r[6]<127)?r[6]:'.', (r[7]>31&&r[7]<127)?r[7]:'.' );
    }
}

/* ★★★★★★ MacRunner 2026-08-31 — ЧТО ЛЕЖИТ В frame->lr МЕЖДУ СОХРАНЕНИЕМ И ВОЗВРАТОМ.
 *
 * Живой стек (не цепочка кадров — она врала) назвал настоящий путь:
 *   rpcrt4!RPCRT4_ReceiveWithAuth -> RPCRT4_receive_fragment -> rpcrt4_conn_np_read
 *   -> ntdll!__wine_rpc_NtReadFile -> ntdll!NtWaitForSingleObject+0x14 (ret переходника)
 *   -> ближайший возврат kernelbase!WaitForSingleObject+0x5c
 *
 * Системный переходник ARM64 прячет адрес возврата в x9 (`mov x9, x30` перед `blr x16`),
 * диспетчер кладёт его в кадр (`stp x9, x19, [x10, #0xf0]` — это поле `lr`) и на выходе
 * возвращает (`ldp x30, x17, [sp, #0xf0]`). Значит `frame->lr` ОБЯЗАН содержать
 * `WaitForSingleObject+0x5c`. Если там адрес данных — корень найден: портится именно
 * это поле между сохранением и восстановлением.
 *
 * Читаем из C, в обработчике самого вызова: в ассемблер лезть не нужно. */
void macrunner_hb_show_frame_lr( const char *где )
{
    /* ★★★★★★ 31.08 — СЛОТ НА ВХОДЕ В ВЫЗОВ: затирают его или он негоден изначально?
     *
     * Дошли до точного места: отказ — `ret` в kernelbase!WaitForSingleObject, её слот
     * сохранённого x30 лежит по frame->sp+0x18 (пролог: `sub sp,sp,#0x20; str x30,[sp,#0x18]`).
     * Диспетчер, доставка исключения и printf уже сняты замерами. Остаются ровно две
     * возможности, и они взаимоисключающи:
     *   (а) на входе в вызов слот ЦЕЛ  -> его затирают, пока поток ждёт;
     *   (б) на входе он УЖЕ негоден    -> функцию позвали с негодным x30, затирать нечего.
     * Одно чтение отвечает окончательно. Печатаем только случай (б) и первые случаи (а)
     * с несовпадением — иначе вывод замедлит поток и отказ спрячется. */
    static unsigned int n_плохих;
    struct syscall_frame *f = get_syscall_frame();
    ULONG_PTR slot_addr, slot;
    if (!f || !f->sp) return;
    slot_addr = (ULONG_PTR)f->sp + 0x18;
    slot = *(volatile ULONG_PTR *)slot_addr;
    /* Сравнивать слот с frame->lr БЕССМЫСЛЕННО: NtWaitForSingleObject зовут отовсюду, и
     * frame->sp+0x18 — слот сохранённого x30 только когда звала WaitForSingleObject.
     * Замер это и показал: 255 «несовпадений», из них настоящих ноль (в строках с
     * frame->lr=WaitForSingleObject+0x5c слот содержал годный адрес возврата в rpcrt4).
     * Фильтруем на САМО негодное значение: указатель в область TEB 0x7ffd…, который и
     * оказывается в x30 при отказе. Если он там уже на ВХОДЕ — функцию позвали негодно;
     * если нет — слот затирают во время ожидания. */
    if (slot >= (ULONG_PTR)0x7ffd0000000 && slot < (ULONG_PTR)0x7ffe0000000 && n_плохих++ < 8)
        macrunner_sig_printf( "macrunner-hb-слот-на-входе: pid=%d %s НЕГОДНОЕ УЖЕ НА ВХОДЕ "
                              "слот[%p]=%p frame->lr=%p frame->sp=%p\n",
                              (int)getpid(), где ? где : "?",
                              (void *)slot_addr, (void *)slot, (void *)f->lr, (void *)f->sp );
}


/* ★★★★★★ MacRunner 2026-08-31 — АППАРАТНАЯ ТОЧКА ОСТАНОВА НА ЗАПИСЬ.
 *
 * Замер назвал место: негодный x30 лежит в слоте `sp-8` (после `ldp x29,x30,[sp],#16`),
 * адрес слота ОДИН И ТОТ ЖЕ во всех шести прогонах, а в слоте — указатель на счётную
 * строку `\pipe\svcctl` (rhs пола RPC-башни). Значит эпилог взял x30 честно, а испорчен
 * САМ СЛОТ. Перехватить запись в регистр нельзя, но запись в ПАМЯТЬ — можно, и не
 * догадками: ARMv8 даёт сторожевые регистры DBGWVR/DBGWCR, а macOS открывает их из
 * пространства пользователя через thread_set_state(ARM_DEBUG_STATE64). Это тот самый
 * механизм, которым пользуется отладчик; своего изобретать не нужно.
 *
 * DBGWCR: бит0 E=1 включает; PAC (биты 2:1) = 0b10 — только EL0; LSC (биты 4:3) = 0b10 —
 * только запись; BAS (биты 12:5) = 0xff — все восемь байт слова.
 *
 * Сторож снимается ПРИ ПЕРВОМ ЖЕ срабатывании: событие сторожа на ARM возвращает
 * управление на ту же самую инструкцию, и не сняв его, мы получили бы вечный повтор.
 * Поэтому он взводится заново на следующем входе в точку взвода — так за прогон
 * набирается цепочка писателей, а не один.
 */
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/thread_status.h>

static ULONG_PTR macrunner_hb_watch_addr;    /* режим «числом»: MACRUNNER_HB_WATCH=0x… */
/* ★ 02.09.2026 — РЕЖИМ «ГОСТЕВОЙ АДРЕС»: MACRUNNER_HB_WATCH_GUEST=0x7bd37334.
 *
 * Сторож писался под ХОЗЯЙСКИЙ адрес на стеке. Порча кучи ГОСТЯ (режим D у Diablo:
 * heap_allocate_block читает затёртую ссылку списка свободных блоков) лежит по
 * гостевому адресу, а хозяйский = база окна guest32 + гостевой. До закрепления
 * раскладки база прыгала каждый прогон, и навести сторож заранее было НЕ НА ЧТО —
 * поэтому его так ни разу и не пустили. Теперь база закрепляется гейтом
 * MACRUNNER_HB_GUEST32_BASE, а хозяйский адрес считается на месте взвода: к старту
 * потока окно уже создано. */
static ULONG_PTR macrunner_hb_watch_guest;
/* ★★★★★★ 31.08 — РЕЖИМ «САМ»: MACRUNNER_HB_WATCH=auto.
 *
 * Фиксированный адрес не годится: замер показал, что ЛЮБОЕ возмущение сдвигает глубину
 * стека, и слот уезжает (frame->sp был 0x1121cda30, с лишним вызовом стал 0x1121cdb10,
 * слот с sp-8 на sp-24). Сторож при этом добросовестно караулил уже пустое место.
 *
 * Поэтому адрес вычисляется НА МЕСТЕ: у kernelbase!WaitForSingleObject пролог
 * `sub sp,#0x20; str x30,[sp,#0x18]`, а frame->sp — это её sp внутри вызова, значит её
 * слот сохранённого x30 всегда лежит по frame->sp+0x18, какой бы ни была глубина.
 * Взводим сторожа ровно туда на каждом входе в ожидание — и он караулит нужный слот
 * ровно тот промежуток, когда поток спит и слот портится. */
static int macrunner_hb_watch_auto;
static __thread ULONG_PTR macrunner_hb_watch_cel;   /* действующий адрес этого потока */

/* on: взвести сторожа; step: включить пошаговый режим (MDSCR_EL1.SS).
 * Оба состояния живут в ОДНОЙ структуре, поэтому и ставятся одним вызовом. */
static void macrunner_hb_watch_set( int on, int step )
{
    arm_debug_state64_t ds;
    memset( &ds, 0, sizeof(ds) );
    if (on)
    {
        ds.__wvr[0] = macrunner_hb_watch_cel & ~(ULONG_PTR)7;
        /* LSC (биты 4:3): 0b01 — чтение, 0b10 — запись, 0b11 — оба. Ночь следили только за
         * ЗАПИСЬЮ и писателя не нашли. Ставим 0b11: смена вида доступа меняет ТОЛЬКО
         * непосредственное значение в этой инструкции, размер кода тот же — а именно
         * раскладка кода и решает, воспроизведётся ли отказ. */
        ds.__wcr[0] = 1u | (2u << 1) | (3u << 3) | (0xffu << 5);
    }
    if (step) ds.__mdscr_el1 |= 1u;          /* SS — ровно один шаг */
    {
        /* Код возврата ПРОВЕРЯЕМ: без него «сторож не сработал» неотличимо от
         * «сторож не взвёлся». Печать редкая (первые 4 раза и все ошибки), чтобы
         * не сдвинуть тайминг. */
        kern_return_t kr = thread_set_state( mach_thread_self(), ARM_DEBUG_STATE64,
                                             (thread_state_t)&ds, ARM_DEBUG_STATE64_COUNT );
        static unsigned int skazano;
        if (kr != KERN_SUCCESS || skazano++ < 4)
            macrunner_sig_printf( "macrunner-hb-сторож-взвод: on=%d цель=%p kr=%d%s\n",
                                  on, (void *)macrunner_hb_watch_cel, (int)kr,
                                  kr == KERN_SUCCESS ? "" : " ОШИБКА" );
    }
}

/* Сторож — регистр ПОТОКА, поэтому и признак взвода потоковый. Взводим только на том
 * потоке, чей стек содержит наблюдаемый адрес: на остальных сторож не сработал бы всё
 * равно, а лишний системный вызов на каждом ожидании — плата ни за что. */
static __thread int macrunner_hb_watch_armed;
static unsigned int macrunner_hb_watch_zvali, macrunner_hb_watch_vzveli, macrunner_hb_watch_sovpalo;
static unsigned int macrunner_hb_watch_after;   /* окно: не раньше N-го ожидания */
/* ★ 02.09.2026 — ПЕРЕВЗВОД РЕДКИМ ТИКОМ: MACRUNNER_HB_WATCH_EVERY=<N>.
 *
 * Сторож снимается при первом же попадании, иначе получаем вечный повтор той же
 * инструкции. Для слота на стеке этого хватало: чужие записи туда редки. Для кучи
 * ГОСТЯ — нет: первым попаданием окажется ШТАТНАЯ запись при аллокации, и цепочка
 * писателей не наберётся.
 *
 * Перевзвод на КАЖДОМ событии уже пробовали и он измеренно негоден: сотни
 * thread_set_state гасят сам отказ (замер 31.08: 0 из 4). Пошаговый возврат тоже
 * закрыт — macOS не принимает MDSCR_EL1.SS через thread_set_state.
 *
 * Отсюда середина: взводить заново РЕДКО — раз в N системных вызовов гостя. При
 * N порядка 10 тысяч это несколько десятков thread_set_state за прогон (не гасит),
 * а кольцо на 16 записей успевает набрать цепочку. Виновник — последняя запись
 * перед отказом; кольцо вываливается в macrunner_hb_print_fault_regs. */
static unsigned int macrunner_hb_watch_every;
static unsigned int macrunner_hb_watch_tikov;
static ULONG_PTR macrunner_hb_watch_lr;         /* MACRUNNER_HB_WATCH_LR: чей вызов ловим */
static int macrunner_hb_slot_gate;              /* MACRUNNER_HB_SLOT_CHECK */
static int macrunner_hb_prot_gate;              /* MACRUNNER_HB_PROT_WATCH */
static unsigned int macrunner_hb_prot_vzveli, macrunner_hb_sig_prot_fail, macrunner_hb_prot_sovpalo;
static ULONG_PTR macrunner_hb_prot_lr[6];
static unsigned int macrunner_hb_prot_zvali, macrunner_hb_prot_every = 50;

/* ★ 31.08 — АДРЕС ЧИТАЕМ В КОНСТРУКТОРЕ. Раньше он читался в signal_init_process, а тот
 * отрабатывает ПОЗЖЕ старта первых потоков: замер дал «звали=1, взвели=1» — сторож не
 * попадал на те потоки, что стартовали до него. Конструктор разделяемой библиотеки
 * выполняется при загрузке, до потоков и до обработчиков сигналов; getenv здесь
 * безопасен (в горячем пути он ронял процессы, поэтому только тут). */
int macrunner_hb_teb_slow = 0;   /* 1 — прежний путь через вызов помощника */

static void __attribute__((constructor)) macrunner_hb_watch_ctor(void)
{
    {   /* Печатаем ЗНАЧЕНИЕ гейта: молчаливо неработающий гейт даёт ровно такую же
         * картину, как «эффекта нет», и без этой строки одно от другого не отличить. */
        const char *v = getenv( "MACRUNNER_HB_TEB_SLOW" );
        if (v && *v && *v != '0') macrunner_hb_teb_slow = 1;
        if (v && *v) { char b[64]; int n = 0; const char *t = "macrunner-hb-teb-gate=X\n";
          while (t[n]) { b[n] = t[n]; n++; }
          b[n-2] = macrunner_hb_teb_slow ? '1' : '0';
          write( 2, b, n ); } }
    const char *e = getenv( "MACRUNNER_HB_WATCH" );
    if (e && *e)
    {
        if (e[0] == 'a') macrunner_hb_watch_auto = 1;      /* auto — вычислять на месте */
        else macrunner_hb_watch_addr = (ULONG_PTR)strtoull( e, NULL, 0 );
    }
    e = getenv( "MACRUNNER_HB_WATCH_EVERY" );
    if (e && *e) macrunner_hb_watch_every = (unsigned int)strtoul( e, NULL, 0 );
    e = getenv( "MACRUNNER_HB_WATCH_GUEST" );
    if (e && *e) macrunner_hb_watch_guest = (ULONG_PTR)strtoull( e, NULL, 0 );
    e = getenv( "MACRUNNER_HB_WATCH_AFTER" );
    if (e && *e) macrunner_hb_watch_after = (unsigned int)strtoul( e, NULL, 0 );
}
static __thread int macrunner_hb_watch_stepping;

/* ★★★★★★ 31.08 — ЦЕЛ ЛИ СЛОТ. Читаем frame->sp+0x18 и сравниваем с frame->lr: у
 * kernelbase!WaitForSingleObject это её же слот сохранённого x30, и он обязан содержать
 * адрес возврата в её вызывающего. Печатаем ТОЛЬКО негодное значение (указатель в
 * область 0x7ffd…) — иначе вывод замедлит поток и отказ спрячется. */
/* ★★★★★★ MacRunner 2026-08-31 — СЛЕЖЕНИЕ ЗАЩИТОЙ СТРАНИЦЫ.
 *
 * Аппаратный сторож (DBGWVR/DBGWCR) на этом отказе исчерпан: он взводится системным
 * вызовом, а отказ гаснет от любого замедления — измерено многократно (0 из 8 даже от
 * пары чтений на возврате). Отладчики в таком случае берут второй механизм: снимают со
 * страницы право записи, и любая запись сама приходит отказом, который называет pc.
 *
 * Здесь: на ожидании, пришедшем из kernelbase!WaitForSingleObject, снимаем запись со
 * страницы, где лежит её слот сохранённого x30 (frame->sp+0x18). Поток в это время СПИТ
 * и в свой стек не пишет — значит первая же запись в страницу и есть искомая. Поймав её,
 * возвращаем право записи и больше не трогаем: одна поимка за прогон, дальше прогон идёт
 * своим ходом. Цена — одна mprotect на нужном ожидании.
 */
#include <sys/mman.h>
#include <errno.h>

static ULONG_PTR macrunner_hb_prot_page;     /* защищённая страница, 0 — нет */
static ULONG_PTR macrunner_hb_prot_slot;

/* ★★★★★★ 01.09 — КОЛЬЦО «СЛОТ НА ВХОДЕ И НА ВЫХОДЕ».
 *
 * Осталась одна неразделённая развилка: слот сохранённого x30 у WaitForSingleObject
 * ЧИСТ на входе в системный вызов и НЕГОДЕН в её эпилоге. Между этими точками ровно
 * два участка: (а) само ожидание, (б) десяток инструкций после возврата — проверка
 * статуса, RtlNtStatusToDosError на ветке ошибки, запись LastError через x18.
 *
 * Все прежние попытки это разделить гасили отказ, потому что печатали или звали
 * системные вызовы. Здесь только СОХРАНЕНИЯ: три слова в потоковое кольцо, ни печати,
 * ни ветвлений по значению. Кольцо вываливается из обработчика отказа — так же, как
 * работает уже существующее кольцо доставок, которое отказу не мешает.
 *
 * kogda: 0 — вход, 1 — выход. */
#define MR_SLOT_RING 24
struct mr_slot_note { ULONG64 kadr, sp, val, lr, prev, pc; ULONG64 czval, cbylo, cstalo, cflags, u1snyal, u1posle, u1ramka, u1dosp, u1pered; unsigned int u1dov, u1posv; unsigned int kogda, n, apc, isk, emul, vhody, setctx; };
static __thread struct mr_slot_note mr_slot_ring[MR_SLOT_RING];
static __thread unsigned int mr_slot_n;

void macrunner_hb_note_slot( int kogda )
{
    struct syscall_frame *f = get_syscall_frame();
    struct mr_slot_note *e;
    ULONG_PTR slot;
    if (!macrunner_hb_slot_gate || !f || !f->sp) return;
    slot = (ULONG_PTR)f->sp + 0x18;
    e = &mr_slot_ring[mr_slot_n % MR_SLOT_RING];
    /* Адрес САМОГО кадра — иначе не отличить «другой кадр» (вложенность) от «тот же
     * кадр с затёртым полем sp». Это разные дефекты и разное лечение. */
    e->kadr  = (ULONG64)(ULONG_PTR)f;
    e->sp    = (ULONG64)(ULONG_PTR)f->sp;
    e->val   = (ULONG64)*(volatile ULONG_PTR *)slot;
    e->lr    = (ULONG64)(ULONG_PTR)f->lr;
    e->prev  = (ULONG64)(ULONG_PTR)f->prev_frame;
    e->pc    = (ULONG64)(ULONG_PTR)f->pc;
    e->apc   = mr_pisal_apc;
    e->isk   = mr_pisal_isk;
    e->emul  = mr_pisal_emul;
    e->setctx = mr_pisal_setctx;
    e->czval  = mr_ctx_zval;
    e->cbylo  = mr_ctx_bylo_sp;
    e->cstalo = mr_ctx_stalo_sp;
    e->cflags = mr_ctx_flags;
    e->u1snyal = mr_usr1_snyal_sp;
    e->u1posle = mr_usr1_posle_sp;
    e->u1ramka = mr_usr1_ramka_sp;
    e->u1dosp  = mr_usr1_do_sp;
    e->u1pered = mr_usr1_pered_sp;
    e->u1dov   = mr_usr1_do_vhod;
    e->u1posv  = mr_usr1_posle_vhod;
    e->vhody = f->align;   /* счётчик входов диспетчера в ЭТОТ кадр */
    e->kogda = (unsigned int)kogda;
    e->n     = ++mr_slot_n;
}

static void mr_slot_dump( void )
{
    /* Шапка называет число событий, хвост — число напечатанных строк. Без обоих
     * K строк кольца читаются как K событий (192 строки = 3 аномалии, 01.09). */
    static unsigned int mr_vydach;
    unsigned int k, strok = 0, nomer = ++mr_vydach;
    if (!macrunner_hb_slot_gate) return;
    macrunner_sig_printf( "macrunner-hb-слот-кольцо: pid=%d всего=%u выдача=%u\n",
                          (int)getpid(), mr_slot_n, nomer );
    for (k = 0; k < MR_SLOT_RING; k++)
    {
        const struct mr_slot_note *e = &mr_slot_ring[k];
        if (!e->n) continue;
        macrunner_sig_printf( "macrunner-hb-слот-кольцо:   n=%u %s кадр=%p sp=%p слот=%p значение=%p lr=%p pc=%p prev=%p апк=%u иск=%u эмул=%u УСТКОНТ=%u ВХОДОВ=%u | звал=%p sp %p->%p флаги=%#llx | usr1: снял=%p после=%p кадр=%p | ПЕРЕД=%p кадр_до=%p входы %u->%u\n",
                              e->n, e->kogda ? "ВЫХОД" : "вход ",
                              (void *)(ULONG_PTR)e->kadr,
                              (void *)(ULONG_PTR)e->sp,
                              (void *)(ULONG_PTR)(e->sp + 0x18),
                              (void *)(ULONG_PTR)e->val,
                              (void *)(ULONG_PTR)e->lr,
                              (void *)(ULONG_PTR)e->pc,
                              (void *)(ULONG_PTR)e->prev,
                              e->apc, e->isk, e->emul, e->setctx, e->vhody,
                              (void *)(ULONG_PTR)e->czval,
                              (void *)(ULONG_PTR)e->cbylo,
                              (void *)(ULONG_PTR)e->cstalo,
                              (unsigned long long)e->cflags,
                              (void *)(ULONG_PTR)e->u1snyal,
                              (void *)(ULONG_PTR)e->u1posle,
                              (void *)(ULONG_PTR)e->u1ramka,
                              (void *)(ULONG_PTR)e->u1pered,
                              (void *)(ULONG_PTR)e->u1dosp, e->u1dov, e->u1posv );
        strok++;
    }
    macrunner_sig_printf( "macrunner-hb-слот-кольцо: ИТОГ выдача=%u строк=%u (выдач=%u, НЕ %u)\n", nomer, strok, nomer, strok );
}

void macrunner_hb_prot_arm( void )
{
    /* ★★★★★★ 01.09 — КАНАРЕЙКА, НЕ ТРОГАЮЩАЯ КАДР.
     *
     * Прокладка в кадре kernelbase!WaitForSingleObject гасит отказ при ЛЮБОМ размере
     * (0x20, 0x40, 0xC0) — потому что отказ есть СОВПАДЕНИЕ АДРЕСОВ, и прокладка его
     * разрушает. Значит наблюдать надо, не меняя геометрию.
     *
     * Снимаем право записи со страницы, где лежит слот сохранённого x30, ровно на время
     * ожидания. Поток спит и в свой стек не пишет — первая же запись в страницу и есть
     * искомая полоса, а отказ по защите называет её pc точно. Одна mprotect за прогон,
     * кадр не меняется ни на байт, раскладка тоже.
     *
     * Взводим ОДИН раз: `macrunner_hb_prot_page` остаётся ненулевой до срабатывания.
     * Фильтр по вызывающему необязателен: если MACRUNNER_HB_WATCH_LR не задан, берём
     * первое же ожидание. */
    struct syscall_frame *f;
    ULONG_PTR slot, page;
    if (!macrunner_hb_prot_gate || macrunner_hb_prot_page) return;
    /* ★ ИЗБИРАТЕЛЬНОСТЬ. Защита 16 КБ накрывает вчетверо больше нужного, и взвод на
     * КАЖДОМ ожидании даёт десятки ловушек — они сами гасят отказ (0 из 4). Взводим
     * на каждом N-м ожидании: ловушек единицы, а покрытие остаётся по всему прогону.
     * MACRUNNER_HB_PROT_EVERY, умолчание 50. */
    if (++macrunner_hb_prot_zvali % macrunner_hb_prot_every) return;
    f = get_syscall_frame();
    if (!f || !f->sp) return;
    {   /* Запоминаем, какие вызывающие вообще приходят: фильтр по lr не совпадал ни разу,
         * а при отказе frame->lr равен WaitForSingleObject+0x5c. Одно из двух неверно, и
         * без списка значений не понять какое. Печатаем их в итоговой строке. */
        unsigned int k;
        for (k = 0; k < 6; k++)
        {
            if (macrunner_hb_prot_lr[k] == (ULONG_PTR)f->lr) break;
            if (!macrunner_hb_prot_lr[k]) { macrunner_hb_prot_lr[k] = (ULONG_PTR)f->lr; break; }
        }
    }
    if (macrunner_hb_watch_lr && (ULONG_PTR)f->lr != macrunner_hb_watch_lr) return;
    macrunner_hb_prot_sovpalo++;
    slot = (ULONG_PTR)f->sp + 0x18;
    /* ★ Apple Silicon: страница 16 КБ, не 4. Маска ~0xfff давала EINVAL (errno=22) —
     * адрес кратен 0x1000, но не 0x4000, и mprotect отвергала его молча. */
    page = slot & ~(ULONG_PTR)0x3fff;
    macrunner_hb_prot_slot = slot;
    if (mprotect( (void *)page, 0x4000, PROT_READ ))
    {
        /* Причину печатаем ОДИН раз: без неё «не смогли» неотличимо от «не пробовали». */
        if (!macrunner_hb_sig_prot_fail)
            macrunner_sig_printf( "macrunner-hb-защита-отказ: pid=%d стр=%p errno=%d\n",
                                  (int)getpid(), (void *)page, errno );
        macrunner_hb_sig_prot_fail++;
        return;
    }
    macrunner_hb_prot_page = page;
    macrunner_hb_prot_vzveli++;
}

/* Вызывается из обработчика отказа ДО всего прочего. Возвращает 1, если отказ — наш
 * сторож: тогда право записи возвращается, а прогон продолжается с того же места. */
static int macrunner_hb_prot_hit( const ucontext_t *context, ULONG_PTR addr )
{
    static unsigned int n_;
    if (!macrunner_hb_prot_page) return 0;
    if ((addr & ~(ULONG_PTR)0x3fff) != macrunner_hb_prot_page) return 0;
    mprotect( (void *)macrunner_hb_prot_page, 0x4000, PROT_READ | PROT_WRITE );
    macrunner_hb_prot_page = 0;
    if (n_++ < 4)
        macrunner_sig_printf( "macrunner-hb-СТРАНИЦА: pid=%d ПИШЕТ pc=%p lr=%p sp=%p "
                 "адрес=%p слот=%p попал_в_слот=%s\n", (int)getpid(),
                 (void *)(ULONG_PTR)PC_sig(context), (void *)(ULONG_PTR)REGn_sig(30, context),
                 (void *)(ULONG_PTR)SP_sig(context), (void *)addr,
                 (void *)macrunner_hb_prot_slot,
                 (addr == macrunner_hb_prot_slot) ? "ДА" : "нет" );
    return 1;
}

void macrunner_hb_slot_check( const char *где )
{
    static unsigned int n_;
    struct syscall_frame *f = get_syscall_frame();
    ULONG_PTR a, v;
    if (!macrunner_hb_slot_gate) return;
    if (!f || !f->sp) return;
    if ((ULONG_PTR)f->lr != macrunner_hb_watch_lr) return;   /* только вызовы WaitForSingleObject */
    a = (ULONG_PTR)f->sp + 0x18;
    v = *(volatile ULONG_PTR *)a;
    if (v >= (ULONG_PTR)0x7ffd0000000 && v < (ULONG_PTR)0x7ffe0000000 && n_++ < 8)
        macrunner_sig_printf( "macrunner-hb-слот-%s: pid=%d НЕГОДЕН слот[%p]=%p lr=%p\n",
                              где ? где : "?", (int)getpid(), (void *)a, (void *)v, (void *)f->lr );
}

void macrunner_hb_watch_arm( const char *где )
{
    /* ★★★★★★ 31.08 — ВЗВОД ПО ВЫЗЫВАЮЩЕМУ, А НЕ ПО АДРЕСУ.
     *
     * Фиксированный адрес не работает принципиально: отказ приходится каждый раз на
     * СВОЙ вызов ожидания, и frame->sp гуляет (0x1121cda30, 0x1121cdb00, 0x1121cdb10).
     * Сторож караулил пустое место. Сплошной перевзвод на каждом ожидании тоже не
     * годится — сотни thread_set_state гасят отказ (0 из 4).
     *
     * Верный признак — ВЫЗЫВАЮЩИЙ. У всех отказов `frame->lr` один и тот же:
     * kernelbase!WaitForSingleObject+0x5c. Взводим сторожа только на таких ожиданиях,
     * и целимся в её слот сохранённого x30 — frame->sp+0x18 (пролог
     * `sub sp,#0x20; str x30,[sp,#0x18]`). Адрес получается верным при любой глубине,
     * а взводов за прогон единицы.
     *
     * MACRUNNER_HB_WATCH_LR=<адрес> задаёт вызывающего; базы модулей у Wine постоянны.
     */
    if (macrunner_hb_prot_gate)
        macrunner_sig_printf( "macrunner-hb-защита-итог: pid=%d звали=%u взвели=%u не_смогли=%u совпало=%u "
                              "слот=%p вызывающие: %p %p %p %p %p %p\n",
                              (int)getpid(), macrunner_hb_prot_zvali, macrunner_hb_prot_vzveli,
                              macrunner_hb_sig_prot_fail, macrunner_hb_prot_sovpalo,
                              (void *)macrunner_hb_prot_slot,
                              (void *)macrunner_hb_prot_lr[0], (void *)macrunner_hb_prot_lr[1],
                              (void *)macrunner_hb_prot_lr[2], (void *)macrunner_hb_prot_lr[3],
                              (void *)macrunner_hb_prot_lr[4], (void *)macrunner_hb_prot_lr[5] );
    if (!macrunner_hb_watch_addr && !macrunner_hb_watch_lr && !macrunner_hb_watch_guest) return;
    macrunner_hb_watch_zvali++;

    if (macrunner_hb_watch_lr)
    {
        struct syscall_frame *f = get_syscall_frame();
        ULONG_PTR novaya;
        if (!f || !f->sp) return;
        if ((ULONG_PTR)f->lr != macrunner_hb_watch_lr) return;   /* не тот вызывающий */
        macrunner_hb_watch_sovpalo++;
        novaya = (ULONG_PTR)f->sp + 0x18;
        if (novaya != macrunner_hb_watch_cel)
        {
            macrunner_hb_watch_cel = novaya;
            macrunner_hb_watch_armed = 0;
        }
    }
    else if (macrunner_hb_watch_guest)
    {
        extern unsigned long long macrunner_hb_wow64_guest32_base(void);
        unsigned long long baza = macrunner_hb_wow64_guest32_base();
        if (!baza) return;                       /* окно ещё не создано — взведёмся позже */
        macrunner_hb_watch_cel = (ULONG_PTR)(baza + macrunner_hb_watch_guest);
        {
            static int skazano;
            if (!skazano++)
            {
                fprintf( stderr, "macrunner-hb-сторож-гость: гостевой=%#llx база=%#llx хозяйский=%#llx\n",
                         (unsigned long long)macrunner_hb_watch_guest, baza,
                         (unsigned long long)macrunner_hb_watch_cel );
                fflush( stderr );
            }
        }
    }
    else macrunner_hb_watch_cel = macrunner_hb_watch_addr;

    if (macrunner_hb_watch_armed || !macrunner_hb_watch_cel) return;
    macrunner_hb_watch_set( 1, 0 );
    macrunner_hb_watch_armed = 1;
    macrunner_hb_watch_vzveli++;
}

/* Редкий перевзвод: зовётся из входа гостевого системного вызова (xtajit).
 * Вхолостую — одна проверка и возврат. */
__attribute__((visibility("default"))) void macrunner_hb_watch_tick( void )
{
    static __thread unsigned int n;
    if (!macrunner_hb_watch_every) return;
    if (!macrunner_hb_watch_guest && !macrunner_hb_watch_addr) return;
    if (++n % macrunner_hb_watch_every) return;
    macrunner_hb_watch_armed = 0;            /* разрешить повторный взвод */
    macrunner_hb_watch_tikov++;
    macrunner_hb_watch_arm( "тик" );
}

/* Кольцо записей. Печатать В МОМЕНТ записи нельзя: вывод замедляет поток настолько,
 * что отказ перестаёт воспроизводиться (замер: 0 из 6 против 4 из 6). Пошаговый возврат
 * сторожа (MDSCR_EL1.SS) искажает ход ТАК ЖЕ сильно — тоже 0 из 6. Поэтому шага нет:
 * сторож снимается при срабатывании и взводится заново на следующем входе в ожидание.
 * Записи между этими точками мы не увидим, зато ход прогона почти не тронут и отказ
 * воспроизводится — а нужна ПОСЛЕДНЯЯ запись перед отказом, и она в кольцо попадёт. */
#define MR_KOLTSO 16
static struct { ULONG_PTR pc, lr, v; } macrunner_hb_watch_ring[MR_KOLTSO];
static unsigned int macrunner_hb_watch_ring_n;

static void macrunner_hb_watch_dump( void );

static int macrunner_hb_watch_hit( const ucontext_t *context )
{
    /* ★★★★★★ 31.08 — ПРИБОР САМ ОТЛИЧАЕТ ЧУЖУЮ ЗАПИСЬ ОТ СВОЕЙ.
     *
     * Замеры свели стену сюда: слот сохранённого x30 у kernelbase!WaitForSingleObject
     * затирается, ПОКА ПОТОК СПИТ в системном вызове. Значит пишет другой поток —
     * и сторож, взведённый только на спящем потоке, не мог этого увидеть: сторожевые
     * регистры потоковые.
     *
     * Пошаговый возврат сторожа здесь НЕ нужен и вреден: замер показал, что macOS не
     * принимает MDSCR_EL1.SS через thread_set_state (восемь одинаковых pc подряд —
     * вечный повтор), а любое замедление прячет отказ. Достаточно снять сторожа после
     * первого попадания: в ЧУЖОЙ стек посторонний поток пишет редко, поэтому первое же
     * попадание и есть искомое. Свои записи (адрес внутри собственного стека потока)
     * только считаем — печатать их нельзя, они горячие. */
    unsigned int i;
    TEB *teb;
    ULONG_PTR nizh = 0, verh = 0;
    int svoj;

    if (!macrunner_hb_watch_cel) return 0;
    macrunner_hb_watch_set( 0, 0 );          /* иначе вечный повтор той же инструкции */
    macrunner_hb_watch_armed = 0;

    teb = NtCurrentTeb();
    if (teb) { nizh = (ULONG_PTR)teb->Tib.StackLimit; verh = (ULONG_PTR)teb->Tib.StackBase; }
    svoj = (macrunner_hb_watch_cel >= nizh && macrunner_hb_watch_cel < verh);

    i = macrunner_hb_watch_ring_n++ % MR_KOLTSO;
    macrunner_hb_watch_ring[i].pc = (ULONG_PTR)PC_sig(context);
    macrunner_hb_watch_ring[i].lr = (ULONG_PTR)REGn_sig(30, context);
    macrunner_hb_watch_ring[i].v  = *(volatile ULONG_PTR *)macrunner_hb_watch_cel;

    /* В ГОСТЕВОМ режиме признак «свой/чужой стек» бессмыслен: гостевой адрес не
     * лежит в стеке ни одного хозяйского потока. Кольцо же вываливается только при
     * отказе, поэтому без отказа попадания не видны вовсе — прогон показывал
     * «0 попаданий» при шести реальных. Печатаем первые восемь. */
    if (macrunner_hb_watch_guest)
    {
        static unsigned int n_g;
        /* ★ 02.09: было 8 — 9-е и дальше терялись; плюс x0..x5: при pc в _platform_memmove это dst/src/len
         * копирования (x0 сохраняется до конца), т.е. ДИАПАЗОН, накрывший цель, а не одно слово. */
        if (n_g++ < 200)
            macrunner_sig_printf( "macrunner-hb-ПОПАДАНИЕ-ГОСТЬ: pid=%d цель=%p pc=%p lr=%p значение=%p "
                                  "тиков=%u взводов=%u x0=%p x1=%p x2=%p x3=%p x4=%p x5=%p\n",
                                  (int)getpid(), (void *)macrunner_hb_watch_cel,
                                  (void *)macrunner_hb_watch_ring[i].pc,
                                  (void *)macrunner_hb_watch_ring[i].lr,
                                  (void *)macrunner_hb_watch_ring[i].v,
                                  macrunner_hb_watch_tikov, macrunner_hb_watch_vzveli,
                                  (void *)REGn_sig(0, context), (void *)REGn_sig(1, context),
                                  (void *)REGn_sig(2, context), (void *)REGn_sig(3, context),
                                  (void *)REGn_sig(4, context), (void *)REGn_sig(5, context) );
        /* ★ 02.09 (kan-5+): ЗАПИСЬ в цель делает помощник JIT (memmove len=1 из блока lr в кеше кода). Гостевой адрес команды
         * передаётся помощнику (им ставится ctx->last_helper_guest) и в момент попадания лежит в одном из сохраняемых регистров.
         * Печатаем x6..x28 одной строкой только для ЗАПИСЕЙ (x0 == цель): значение в диапазоне кода гостя и есть eip писателя. */
        if (n_g <= 200 && (ULONG_PTR)REGn_sig(0, context) == macrunner_hb_watch_cel)
            macrunner_sig_printf( "macrunner-hb-ПОПАДАНИЕ-РЕГИСТРЫ: x6=%p x7=%p x8=%p x9=%p x10=%p x11=%p x12=%p x13=%p x14=%p x15=%p "
                                  "x16=%p x17=%p x19=%p x20=%p x21=%p x22=%p x23=%p x24=%p x25=%p x26=%p x27=%p x28=%p fp=%p\n",
                                  (void *)REGn_sig(6, context), (void *)REGn_sig(7, context), (void *)REGn_sig(8, context),
                                  (void *)REGn_sig(9, context), (void *)REGn_sig(10, context), (void *)REGn_sig(11, context),
                                  (void *)REGn_sig(12, context), (void *)REGn_sig(13, context), (void *)REGn_sig(14, context),
                                  (void *)REGn_sig(15, context), (void *)REGn_sig(16, context), (void *)REGn_sig(17, context),
                                  (void *)REGn_sig(19, context), (void *)REGn_sig(20, context), (void *)REGn_sig(21, context),
                                  (void *)REGn_sig(22, context), (void *)REGn_sig(23, context), (void *)REGn_sig(24, context),
                                  (void *)REGn_sig(25, context), (void *)REGn_sig(26, context), (void *)REGn_sig(27, context),
                                  (void *)REGn_sig(28, context), (void *)REGn_sig(29, context) );
        /* ★ и сразу — гостевой eip пишущей команды: у JIT (hyperbridge) указатель ctx лежит в одном из x19..x28; в ctx по
         * смещению 0xe20 — last_helper_guest (адрес команды у гостя, ставится на входе в помощник), по 0xe18 — last_helper_op
         * (offsetof посчитан clang по engine/hyperbridge/include/hb_context.h, sizeof=3624). Читаем только безопасно. */
        if (n_g <= 200 && (ULONG_PTR)REGn_sig(0, context) == macrunner_hb_watch_cel)
        {
            int r;
            for (r = 0; r <= 28; r++)
            {
                ULONG_PTR v = (ULONG_PTR)REGn_sig(r, context);
                unsigned long long guest = 0; int op = 0;
                /* ★ kan-6: ctx лежит ВЫШЕ 0x800000000 (0xcf7e8c000, 0xd0601cea0) — верхняя граница расширена до 64 ГБ;
                 * плюс регистры гостя из ctx (смещения из clang: eip=64 edi=52 esi=48 ecx=40). */
                if (v < 0x100000000ull || v >= 0x1000000000ull || (v & 7)) continue;
                if (!macrunner_signal_read_memory( &guest, (const void *)(v + 0xe20), sizeof(guest) )) continue;
                if (guest < 0x00400000 || guest > 0x7fffffff) continue;
                macrunner_signal_read_memory( &op, (const void *)(v + 0xe18), sizeof(op) );
                {
                    unsigned int eip = 0, edi = 0, esi = 0, ecx = 0, eax = 0, ebx = 0, edx = 0;
                    macrunner_signal_read_memory( &eip, (const void *)(v + 64), 4 );
                    macrunner_signal_read_memory( &edi, (const void *)(v + 52), 4 );
                    macrunner_signal_read_memory( &esi, (const void *)(v + 48), 4 );
                    macrunner_signal_read_memory( &ecx, (const void *)(v + 40), 4 );
                    macrunner_signal_read_memory( &eax, (const void *)(v + 32), 4 );
                    macrunner_signal_read_memory( &ebx, (const void *)(v + 36), 4 );
                    macrunner_signal_read_memory( &edx, (const void *)(v + 44), 4 );
                    macrunner_sig_printf( "macrunner-hb-ПОПАДАНИЕ-ГОСТЬ-EIP: ctx(x%d)=%p last_helper_guest=%08llx last_helper_op=%d блок_eip=%08x edi=%08x esi=%08x ecx=%08x eax=%08x ebx=%08x edx=%08x\n",
                                          r, (void *)v, guest, op, eip, edi, esi, ecx, eax, ebx, edx );
                }
            }
        }
    }
    if (!svoj && !macrunner_hb_watch_guest)
    {   /* ЧУЖОЙ СТЕК — это и есть то, что мы ищем. Печатаем сразу и подробно: такое
         * событие редкое, вывод хода не исказит, а без имени потока показание немое. */
        static unsigned int n_chuzhih;
        if (n_chuzhih++ < 8)
            macrunner_sig_printf( "macrunner-hb-ЧУЖАЯ-ЗАПИСЬ: pid=%d поток=%04x пишет в %p "
                     "(НЕ его стек [%p..%p)) pc=%p lr=%p значение=%p\n",
                     (int)getpid(),
                     teb ? (unsigned)(ULONG_PTR)teb->ClientId.UniqueThread : 0,
                     (void *)macrunner_hb_watch_cel, (void *)nizh, (void *)verh,
                     (void *)(ULONG_PTR)PC_sig(context),
                     (void *)(ULONG_PTR)REGn_sig(30, context),
                     (void *)macrunner_hb_watch_ring[i].v );
    }
    return 1;
}

static void macrunner_hb_watch_dump( void )
{
    unsigned int всего = macrunner_hb_watch_ring_n, k, i;
    if (!macrunner_hb_watch_addr && !macrunner_hb_watch_lr && !macrunner_hb_watch_guest) return;
    /* Печатаем ДАЖЕ при нуле: молчание прибора неотличимо от «прибор не встал», и на этом
     * я сегодня уже обжигался. Счётчики звали/взвели сразу говорят, дошло ли дело до
     * взвода в ЭТОМ процессе, или наблюдаемый адрес просто не на его стеке. */
    macrunner_sig_printf( "macrunner-hb-сторож-итог: pid=%d адрес=%p звали=%u взвели=%u совпало=%u "
                          "записей=%u\n", (int)getpid(), (void *)macrunner_hb_watch_cel,
                          macrunner_hb_watch_zvali, macrunner_hb_watch_vzveli, macrunner_hb_watch_sovpalo, всего );
    if (!всего) return;
    for (k = (всего > MR_KOLTSO ? MR_KOLTSO : всего); k > 0; k--)
    {
        i = (всего - k) % MR_KOLTSO;
        macrunner_sig_printf( "macrunner-hb-сторож-итог:   -%u pc=%p lr=%p значение=%p\n",
                              k - 1, (void *)macrunner_hb_watch_ring[i].pc,
                              (void *)macrunner_hb_watch_ring[i].lr,
                              (void *)macrunner_hb_watch_ring[i].v );
    }
}
#else
void macrunner_hb_watch_arm( const char *где ) { (void)где; }
__attribute__((visibility("default"))) void macrunner_hb_watch_tick( void ) { }
static void macrunner_hb_watch_dump( void ) { }
#endif

static void macrunner_hb_print_fault_regs( const ucontext_t *context, const char *site )
{
    uint64_t m0_dump = macrunner_m0_dump_begin( context, (uint64_t)(ULONG_PTR)site );
    macrunner_hb_watch_dump();
    mr_slot_dump();
    {   /* ★★★★★★ 01.09 — ГОТОВЫЙ ПРИБОР, КОТОРЫЙ Я ЧУТЬ НЕ ПОСТРОИЛ ЗАНОВО.
         *
         * Кольцо записей доставки (`macrunner_hb_delivery_ring`) с диапазонами lo..hi
         * ведётся с 03.08, и проверка «накрыла ли доставка слот SP-8» там же написана —
         * но живёт под `SIGSEGV && SEGV_ACCERR`, а наш отказ macOS метит как BUS, и
         * прибор не срабатывал ни разу. Переносим проверку в общий печатник: он работает
         * на ОБЕИХ площадках (изъян «прибор только на segv» повторялся четыре раза).
         *
         * Смысл: если слот попал внутрь записи доставки — виновата наша доставка, и
         * лечение в резервировании стека под неё. Если не попал ни в одну — доставка
         * оправдана, и полосу надо искать среди других записей. */
        ULONG64 slot = (ULONG64)(ULONG_PTR)SP_sig(context) - 8;
        unsigned int k, popal = 0, est = 0;
        for (k = 0; k < MACRUNNER_HB_DELIVERY_RING; k++)
        {
            const struct macrunner_hb_delivery_note *e = &macrunner_hb_delivery_ring[k];
            if (!e->seq) continue;
            est++;
            if (slot >= e->lo && slot < e->hi) popal++;
        }
        macrunner_sig_printf( "macrunner-hb-доставка-против-слота: pid=%d слот=%p доставок=%u "
                              "записей_в_кольце=%u ПОПАЛ=%u\n",
                              (int)getpid(), (void *)(ULONG_PTR)slot,
                              (unsigned)macrunner_hb_delivery_seq, est, popal );
        for (k = 0; k < MACRUNNER_HB_DELIVERY_RING; k++)
        {
            const struct macrunner_hb_delivery_note *e = &macrunner_hb_delivery_ring[k];
            if (!e->seq) continue;
            macrunner_sig_printf( "macrunner-hb-доставка-запись: n=%llu [%p..%p) код=%#llx "
                                  "прерван_sp=%p накрыл=%s\n",
                                  (unsigned long long)e->seq, (void *)(ULONG_PTR)e->lo,
                                  (void *)(ULONG_PTR)e->hi, (unsigned long long)e->code,
                                  (void *)(ULONG_PTR)e->interrupted_sp,
                                  (slot >= e->lo && slot < e->hi) ? "ДА" : "нет" );
        }
    }
    {   /* ★★★★★★ 31.08 — ЧТО ЭТО ЗА ЗНАЧЕНИЕ. Сторож на этом отказе уперся: он взводится
         * системным вызовом, а отказ гаснет от любого замедления. Поэтому спрашиваем без
         * возмущения — только в точке отказа.
         *
         * Все негодные x30 лежат в области TEB (0x7ffd0…), а одно из них, 0x7ffd02400d0,
         * сторож уже ловил: его записал спил диспетчера `stp x0, x1, [sp]`. Диспетчер
         * кладёт туда x0…x17, среди которых x17/x18 — УКАЗАТЕЛЬ НА TEB. Если негодный
         * x30 совпадает с TEB (или лежит внутри него), происхождение названо: это спил
         * диспетчера, попавший на слот сохранённого x30 спящего кадра.
         *
         * Печатаем сам TEB, PEB и смещение — сравнивать сможет кто угодно. */
        TEB *teb = NtCurrentTeb();
        ULONG_PTR v = (ULONG_PTR)REGn_sig(30, context);
        ULONG_PTR t = (ULONG_PTR)teb, peb = teb ? (ULONG_PTR)teb->Peb : 0;
        macrunner_sig_printf( "macrunner-hb-что-за-значение: pid=%d x30=%p TEB=%p PEB=%p "
                 "x30-TEB=%+lld внутри_TEB=%s внутри_PEB=%s\n",
                 (int)getpid(), (void *)v, (void *)t, (void *)peb,
                 (long long)(v - t),
                 (v >= t && v < t + 0x2000) ? "ДА" : "нет",
                 (peb && v >= peb && v < peb + 0x1000) ? "ДА" : "нет" );
    }
    {   /* ★★★★★★ 31.08 — КАДР ВЫЗОВА В ТОЧКЕ ОТКАЗА.
         *
         * Разбор кода назвал точное место: NtWaitForSingleObject БЕЗ КАДРА — прячет адрес
         * возврата в x9 и возвращается по x30, а x30 обязан восстановить диспетчер:
         *     ldp x16, x17, [sp, #0x100]   ; x16 = frame->pc
         *     ldp x30, x17, [sp, #0xf0]    ; x30 = frame->lr, x17 = frame->sp
         *     mov sp, x17 ; ret x16
         * При отказе x16 равен frame->pc — верно. Значит негоден именно frame->lr.
         * Прежний прибор читал `get_syscall_frame()->lr` ЧЕРЕЗ TEB и всегда находил его
         * целым; ассемблер же берёт поле ПО СЛУЖЕБНОМУ СТЕКУ. Если это разные кадры —
         * я проверял не тот. Печатаем адрес кадра и все три поля разом: одно показание
         * разделяет «поле испорчено» и «прочитан чужой кадр». */
        struct syscall_frame *f = get_syscall_frame();
        macrunner_sig_printf( "macrunner-hb-кадр-в-отказе: pid=%d кадр=%p lr=%p sp=%p pc=%p "
                              "prev=%p x30-при-отказе=%p совпало=%s\n",
                 (int)getpid(), f, f ? (void *)f->lr : NULL, f ? (void *)f->sp : NULL,
                 f ? (void *)f->pc : NULL, f ? (void *)f->prev_frame : NULL,
                 (void *)(ULONG_PTR)REGn_sig(30, context),
                 (f && (ULONG_PTR)f->lr == (ULONG_PTR)REGn_sig(30, context)) ? "ДА" : "НЕТ" );
    }
    {   /* ★★★★★★ 31.08 — СВОЙ ЛИ ЭТО СТЕК.
         *
         * Три замера сошлись: слот негодного x30 один и тот же во всех прогонах; отказ
         * исчезает от любого замедления (признак гонки); аппаратный сторож, взведённый
         * НА ПАДАЮЩЕМ ПОТОКЕ, не увидел при отказе ни одной записи. Сторожевые регистры
         * потоковые — чужую запись они не видят в принципе. Отсюда версия: в стек пишет
         * ДРУГОЙ поток. Первое, что её проверяет, — лежит ли sp внутри границ стека
         * СВОЕГО потока. Одна строка, никакого замедления, никаких догадок. */
        TEB *teb = NtCurrentTeb();
        ULONG_PTR sp = (ULONG_PTR)SP_sig(context);
        ULONG_PTR baza = teb ? (ULONG_PTR)teb->Tib.StackBase : 0;
        ULONG_PTR predel = teb ? (ULONG_PTR)teb->Tib.StackLimit : 0;
        macrunner_sig_printf( "macrunner-hb-чей-стек: pid=%d поток=%04x sp=%p стек=[%p..%p) "
                              "свой=%s слот=%p внутри=%s\n",
                 (int)getpid(), teb ? (unsigned)(ULONG_PTR)teb->ClientId.UniqueThread : 0,
                 (void *)sp, (void *)predel, (void *)baza,
                 (sp >= predel && sp < baza) ? "ДА" : "НЕТ",
                 (void *)macrunner_hb_watch_addr,
                 (macrunner_hb_watch_addr >= predel && macrunner_hb_watch_addr < baza)
                     ? "ДА" : "НЕТ" );
    }
    /* x9/x10 добавлены 31.08: системный переходник ARM64 прячет адрес возврата
     * ИМЕННО в x9 (`mov x9, x30` перед `blr x16`), а диспетчер обязан вернуть его
     * в x30. Если при отказе x9 верен, а x30 нет — виноват путь возврата, и это
     * различие нельзя увидеть без x9. */
    macrunner_sig_printf( "macrunner-vhf-saved: pid=%d site=%s x8=%p x9=%p x10=%p x16=%p x17=%p "
                          "x19=%p x20=%p x21=%p x22=%p x23=%p x24=%p x25=%p x26=%p "
                          "x27=%p x28=%p x29=%p x30=%p\n",
             (int)getpid(), site ? site : "?",
             (void *)(ULONG_PTR)REGn_sig(8, context),
             (void *)(ULONG_PTR)REGn_sig(9, context),
             (void *)(ULONG_PTR)REGn_sig(10, context),
             (void *)(ULONG_PTR)REGn_sig(16, context),
             (void *)(ULONG_PTR)REGn_sig(17, context),
             (void *)(ULONG_PTR)REGn_sig(19, context),
             (void *)(ULONG_PTR)REGn_sig(20, context),
             (void *)(ULONG_PTR)REGn_sig(21, context),
             (void *)(ULONG_PTR)REGn_sig(22, context),
             (void *)(ULONG_PTR)REGn_sig(23, context),
             (void *)(ULONG_PTR)REGn_sig(24, context),
             (void *)(ULONG_PTR)REGn_sig(25, context),
             (void *)(ULONG_PTR)REGn_sig(26, context),
             (void *)(ULONG_PTR)REGn_sig(27, context),
             (void *)(ULONG_PTR)REGn_sig(28, context),
             (void *)(ULONG_PTR)REGn_sig(29, context),
             (void *)(ULONG_PTR)REGn_sig(30, context) );

    {
        ULONG instruction;
        if (macrunner_fex_kusd_backend && REGn_sig(19, context) == 0x1258 &&
            macrunner_signal_read_u32_aligned( PC_sig(context), &instruction ) &&
            instruction == 0x79000268) /* STRH w8,[x19], native conversion Length write */
        {
            static unsigned int captures;
            unsigned int n = __atomic_add_fetch( &captures, 1, __ATOMIC_RELAXED );
            if (n <= 4)
            {
                ULONG_PTR stack[8] = {0}, caller = 0, sp = SP_sig(context);
                BOOL stack_ok = macrunner_signal_read_memory( stack, (const void *)sp, sizeof(stack) );
                unsigned int i;
                if (stack_ok) caller = stack[4]; /* Saved LR, before the internal size call. */
                macrunner_sig_printf( "mr-native-caller: pid=%d n=%u pc=%p sp=%p x18=%p teb=%p "
                                      "x0=%p x1=%p x2=%p x19=%p x20=%p x30=%p stack_ok=%u caller=%p\n",
                    (int)getpid(), n, (void *)(ULONG_PTR)PC_sig(context), (void *)sp,
                    (void *)(ULONG_PTR)REGn_sig(18, context), macrunner_teb_reliable(),
                    (void *)(ULONG_PTR)REGn_sig(0, context), (void *)(ULONG_PTR)REGn_sig(1, context),
                    (void *)(ULONG_PTR)REGn_sig(2, context), (void *)(ULONG_PTR)REGn_sig(19, context),
                    (void *)(ULONG_PTR)REGn_sig(20, context), (void *)(ULONG_PTR)REGn_sig(30, context),
                    stack_ok, (void *)caller );
                for (i = 0; stack_ok && i < 8; i += 2)
                    macrunner_sig_printf( "mr-native-caller-stack: pid=%d offset=%u a=%p b=%p\n",
                        (int)getpid(), i * 8, (void *)stack[i], (void *)stack[i+1] );
                for (i = 0; caller >= 64 && caller <= ~(ULONG_PTR)0 - 16 && i < 20; i += 4)
                {
                    ULONG words[4] = {0};
                    ULONG_PTR address = caller - 64 + i * 4;
                    BOOL ok = macrunner_signal_read_memory( words, (const void *)address, sizeof(words) );
                    macrunner_sig_printf( "mr-native-caller-code: pid=%d pc=%p ok=%u words=%08x,%08x,%08x,%08x\n",
                        (int)getpid(), (void *)address, ok, words[0], words[1], words[2], words[3] );
                }
            }
        }
    }

    {   /* ★★★★★ 31.08 — ГДЕ ЛЕЖАЛ НЕГОДНЫЙ x30. Перехватить запись в регистр нельзя,
         * но `ret` берёт его ИЗ ПАМЯТИ. Ищем значение x30 в стеке вокруг sp и печатаем
         * смещение: оно называет кадр и место в нём, а дальше функция опознаётся по
         * размеру кадра. Это дешевле любого пошагового перебора. */
        ULONG_PTR want = (ULONG_PTR)REGn_sig(30, context);
        ULONG_PTR sp   = (ULONG_PTR)SP_sig(context);
        int found = 0, i;
        if (!macrunner_hb_unsafe_fault_dump) { want = 0; found = 1;
            __atomic_add_fetch( &macrunner_hb_unsafe_dump_skipped, 1, __ATOMIC_RELAXED ); }
        if (want && sp)
        {
            for (i = -32; i < 96; i++)
            {
                ULONG_PTR value;
                if (!macrunner_hb_safe_copy( sp + i * sizeof(value), &value, sizeof(value) ))
                {
                    found = -1;
                    break;
                }
                if (value != want) continue;
                macrunner_sig_printf( "macrunner-vhf-слот-x30: pid=%d site=%s sp=%p "
                         "найден по sp%+d (адрес %p)\n",
                         (int)getpid(), site ? site : "?", (void *)sp,
                         (int)(i * 8), (void *)(sp + i * 8) );
                if (++found >= 4) break;
            }
        }
        if (!found)
            macrunner_sig_printf( "macrunner-vhf-слот-x30: pid=%d site=%s значение x30 в стеке "
                     "вокруг sp (-256..+768) НЕ НАЙДЕНО — оно не со стека\n",
                     (int)getpid(), site ? site : "?" );
    }
    {   /* ★★★★★★ MacRunner 2026-08-31 — ЖИВОЙ СТЕК, А НЕ ЦЕПОЧКА КАДРОВ.
         *
         * Цепочка кадров подвела: она называла путь через RPC, а вехи в самих функциях
         * показали, что тот путь НЕ ИСПОЛНЯЛСЯ ни разу (вех ноль при отказе в каждом
         * прогоне). Обходчик подбирал устаревшие слова стека.
         *
         * Поэтому здесь — сплошной разбор ЖИВОЙ части стека (выше sp) без всяких
         * предположений о разметке кадров: печатаем каждое слово, попадающее в
         * отображённый исполняемый диапазон. Это кандидаты в адреса возврата, и они
         * не зависят от того, правильно ли устроены кадры. */
        /* ★ 31.08 — ВЕСЬ СТЕК, А НЕ ОКОШКО. Замер показал: поток мелкий, от sp до вершины
         * всего ~9,6 КБ. Окно в 64 слова обрывало цепочку на середине и уводило в сторону.
         * Печатаем всё до вершины стека потока — полная история вызовов в одной точке. */
        TEB *teb_s = NtCurrentTeb();
        ULONG_PTR sp = (ULONG_PTR)SP_sig(context);
        ULONG_PTR verh = teb_s ? (ULONG_PTR)teb_s->Tib.StackBase : sp + 512;
        uint64_t m0_upper_src = teb_s ? 1u : 2u;   /* 1 = TEB StackBase, 2 = sp+512 */
        uint64_t m0_ovr = 0;
        int predel_slov;
        int i, shown = 0;
        uint64_t m0_scan;
        /* ТОЛЬКО отрицательный контроль (§6.2 п.4). В игровом прогоне не взведено. */
        if (macrunner_m0_control_armed && sp == macrunner_m0_control_sp)
        { verh = macrunner_m0_control_verh; m0_upper_src = 3u; m0_ovr = 1u; }
        predel_slov = verh > sp ? min( (verh - sp) / sizeof(ULONG_PTR), 4096 ) : 0;
        /* ★ Семья непроверенных чтений выключена -> в цикл НЕ входим вовсе.
         * BEGIN/END всё равно публикуем: иначе «сканирований ноль» нельзя было бы
         * отличить от «прибор молчит». */
        if (!macrunner_hb_unsafe_fault_dump)
        {
            predel_slov = 0;
            __atomic_add_fetch( &macrunner_hb_unsafe_dump_skipped, 1, __ATOMIC_RELAXED );
        }
        m0_scan = macrunner_m0_scan_begin( sp, verh, predel_slov, sp,
                                           m0_upper_src, m0_ovr );
        for (i = 0; i < predel_slov && shown < 48; i++)
        {
            ULONG_PTR v;
            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T len = 0;
            if (!macrunner_hb_safe_copy( sp + i * sizeof(v), &v, sizeof(v) ))
            {
                shown = -1;
                break;
            }
            if (v < 0x10000) continue;
            if (NtQueryVirtualMemory( NtCurrentProcess(), (void *)v, MemoryBasicInformation,
                                      &mbi, sizeof(mbi), &len )) continue;
            if (mbi.State != MEM_COMMIT) continue;
            if (!(mbi.Protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE
                                 |PAGE_EXECUTE_WRITECOPY))) continue;
            macrunner_sig_printf( "macrunner-vhf-живой-стек: pid=%d [sp+%#x]=%p "
                     "область=%p тип=%08lx %s\n",
                     (int)getpid(), (unsigned)(i * 8), (void *)v,
                     mbi.AllocationBase, (unsigned long)mbi.Type,
                     mbi.Type == 0x1000000 ? "ОБРАЗ" : "не образ" );
            shown++;
        }
        macrunner_m0_scan_end( m0_scan, i, shown, sp + i * sizeof(ULONG_PTR) );
        if (!macrunner_hb_unsafe_fault_dump)
            macrunner_sig_printf( "macrunner-vhf-живой-стек: pid=%d ПРОПУЩЕН — "
                     "MACRUNNER_HB_UNSAFE_FAULT_DUMP=0 (обход живого стека читает "
                     "непроверенную память; клин 217,8 с измерен M0 07.09)\n", (int)getpid() );
        else if (!shown)
            macrunner_sig_printf( "macrunner-vhf-живой-стек: pid=%d в [sp,sp+512) НЕТ ни одного "
                     "исполняемого адреса — возврата на стеке нет вовсе\n", (int)getpid() );
    }
    macrunner_hb_name_address( (ULONG_PTR)PC_sig(context), "pc" );
    macrunner_hb_name_address( (ULONG_PTR)REGn_sig(30, context), "x30" );

    /* ★ СНИМОК КАДРА. Если `ret` ушёл по негодному x30, вопрос один: слот
     * сохранённого x30 затёрли — или разъехалась разметка кадра. Различить их можно
     * только увидев саму память: у стандартного пролога `stp x29,x30,[sp,#-N]!`
     * сохранённые x29 и x30 лежат по [x29] и [x29+8]. Печатаем окно вокруг x29.
     *
     * Читаем ТОЛЬКО когда x29 похож на стек: он должен быть выровнен на 16 и лежать
     * в пределах 1 МБ от sp. Иначе в обработчике сигнала можно получить второй отказ
     * и потерять весь разбор — цена ошибки здесь выше пользы от лишней строки. */
    {
        ULONG_PTR fp = (ULONG_PTR)REGn_sig(29, context);
        ULONG_PTR sp = (ULONG_PTR)SP_sig(context);
        /* ★ Третий член семьи непроверенных чтений: окна по fp и по sp читаются
         * НАПРЯМУЮ. Проверка «выровнен и в пределах 1 МБ от sp» проверяет ЧИСЛО,
         * а не отображение страницы — ровно как «до 4096» в обходе живого стека. */
        if (!macrunner_hb_unsafe_fault_dump)
        {
            fp = 0;
            __atomic_add_fetch( &macrunner_hb_unsafe_dump_skipped, 1, __ATOMIC_RELAXED );
        }
        if (fp && !(fp & 15) && sp && (fp > sp ? fp - sp : sp - fp) < 0x100000)
        {
            ULONG_PTR w[6];
            /* ★ 31.08 — СНИМОК И ПО SP, НЕ ТОЛЬКО ПО FP.
             * Эпилог `ldp x29,x30,[sp,#N]; ret` берёт адрес возврата из стека ПО SP,
             * а не по x29: у функции с большим кадром это разные места. Печатая только
             * окно вокруг fp, мы видели ЧУЖОЙ (целый) слот вызывающего и делали вывод
             * «стек цел», хотя `ret` грузил из другого. Печатаем оба окна. */
            {
                ULONG_PTR q[0x98 / sizeof(ULONG_PTR)];
                /* Окно было узким (0x88..0xa0) и приходилось на кадр ЧУЖОЙ функции.
                 * Отказ же в эпилоге `macrunner_hb_pdata_scan_safe`, а она хранит x30 по
                 * [sp+0x70] (кадр 0x80). Печатаем ВЕСЬ кадр от sp — тогда слот возврата
                 * попадёт в окно при любом размере кадра до 0xa0. */
                if (macrunner_hb_safe_copy( sp, q, sizeof(q) ))
                    macrunner_sig_printf( "macrunner-vhf-стек-sp: pid=%d site=%s sp=%p "
                         "+00=%p +08=%p +10=%p +18=%p +60=%p +68=%p +70=%p +78=%p "
                         "+88=%p +90=%p\n",
                         (int)getpid(), site ? site : "?", (void *)sp,
                         (void *)q[0], (void *)q[1], (void *)q[2], (void *)q[3],
                         (void *)q[0x60/8], (void *)q[0x68/8],
                         (void *)q[0x70/8], (void *)q[0x78/8],
                         (void *)q[0x88/8], (void *)q[0x90/8] );
            }
            if (fp >= 16 && macrunner_hb_safe_copy( fp - 16, w, sizeof(w) ))
                macrunner_sig_printf( "macrunner-vhf-кадр: pid=%d site=%s fp=%p "
                                  "[fp]=%p [fp+8]=%p [fp+16]=%p [fp+24]=%p "
                                  "[fp-8]=%p [fp-16]=%p\n",
                     (int)getpid(), site ? site : "?", (void *)fp,
                     (void *)w[2], (void *)w[3], (void *)w[4], (void *)w[5],
                     (void *)w[1], (void *)w[0] );
        }
    }
    if (!macrunner_hb_unsafe_fault_dump)
        macrunner_sig_printf( "macrunner-hb-unsafe-dump-skip: pid=%d site=%s пропущено_блоков=%llu "
                 "(гейт MACRUNNER_HB_UNSAFE_FAULT_DUMP=0)\n",
                 (int)getpid(), site ? site : "?",
                 (unsigned long long)__atomic_load_n( &macrunner_hb_unsafe_dump_skipped,
                                                      __ATOMIC_RELAXED ) );
    macrunner_m0_dump_end( m0_dump );
}

/* ==========================================================================
 * ★★★ ШАГ-4, 08.09.2026 — ЗАМЕР ДВУХ СТЕН FEX.  ПЕЧАТЬ БЕЗУСЛОВНАЯ, первые 8.
 *
 * Наряд запрещает правку до замера: у каждой стены по нескольку правдоподобных
 * объяснений, и выбирать между ними «по правдоподобию» нельзя.
 *
 * СТЕНА x64 — `enter_jit` (engine/fex/Source/Windows/ARM64EC/Module.S:32-36):
 *     ldr  x17, [x18, #0x1788]   // TEB->ChpeV2CpuAreaInfo
 *     mov  w16, #1
 *     strb w16, [x17, #0x0]      <- отказ прав записи
 * Три объяснения: (а) x18 не наш TEB; (б) поле не по смещению 0x1788;
 * (в) отказавший поток не проходил через unix/thread.c (нет области).
 * Различает: x18 против NtCurrentTeb(), ЧИСЛО FIELD_OFFSET, и след записи
 * (macrunner-shag4-cpuarea-set) — всё в одной строке.
 *
 * СТЕНА i386 — `ldr x1,[x1]` при x1=0 в буфере диспетчера FEX.  По исходникам
 * FEXCore это НАМЕРЕННАЯ заглушка GuestSignal_SIGSEGV
 * (FEXCore/Source/Interface/Core/Dispatcher/Dispatcher.cpp:423-441), а причина
 * перехода лежит в `SynchronousFaultData`, которую пишет
 * FEXCore/Source/Interface/Core/JIT/MiscOps.cpp:59-90 ДО перехода.
 * STATE = x28 (FEXCore/Source/Interface/Core/ArchHelpers/Arm64Emitter.h:33).
 * Смещения ниже ВЫЧИСЛЕНЫ компиляцией CoreState.h (build/shag4/probe/fexoff.cpp),
 * а не выведены глазами; отрицательный контроль встроен: `Pointers.GuestSignal_*`
 * обязаны попасть в буфер диспетчера, а SIGSEGV — совпасть с pc.  Не совпало —
 * смещения неверны, и число НЕ читается как ответ.
 *
 * Читаем ТОЛЬКО через macrunner_hb_safe_copy: x18/x28 берутся из контекста и
 * могут быть мусором, прямое разыменование убило бы процесс внутри обработчика
 * (этот файл уже хранит такой случай — см. macrunner_hb_name_address).
 */
#define MACRUNNER_SHAG4_FEX_SFD        0x5d8u   /* CpuStateFrame.SynchronousFaultData */
#define MACRUNNER_SHAG4_FEX_RIP        0x18u    /* CpuStateFrame.State.rip            */
#define MACRUNNER_SHAG4_FEX_LOOPTOP    0xb60u   /* Pointers.DispatcherLoopTop         */
#define MACRUNNER_SHAG4_FEX_SIGILL     0xb98u   /* Pointers.GuestSignal_SIGILL        */
#define MACRUNNER_SHAG4_FEX_SIGTRAP    0xba0u
#define MACRUNNER_SHAG4_FEX_SIGSEGV    0xba8u
#define MACRUNNER_SHAG4_FEX_L2         0xbc0u   /* Pointers.L2Pointer                 */

extern void *macrunner_shag4_cpu_teb[8];
extern void *macrunner_shag4_cpu_area[8];
extern unsigned macrunner_shag4_cpu_n;

static void macrunner_shag4_words( const char *имя, ULONG_PTR at, int before, int after )
{
    unsigned int w[24];
    char строка[512];
    int i, n = before + after;
    int len;

    if (n > 24) n = 24;
    if (!macrunner_hb_safe_copy( at - (ULONG_PTR)before * 4, w, (size_t)n * 4 ))
    {
        macrunner_sig_printf( "macrunner-shag4-слова: %s at=%p НЕЧИТАЕМО\n", имя, (void *)at );
        return;
    }
    len = snprintf( строка, sizeof(строка), "macrunner-shag4-слова: %s at=%p от=%p",
                    имя, (void *)at, (void *)(at - (ULONG_PTR)before * 4) );
    for (i = 0; i < n && len > 0 && len < (int)sizeof(строка) - 12; i++)
        len += snprintf( строка + len, sizeof(строка) - len, "%s%08x",
                         i == before ? " >" : " ", w[i] );
    macrunner_sig_printf( "%s\n", строка );
}

static void macrunner_shag4_probe( const ucontext_t *context, const char *site )
{
    static unsigned shag4_n;
    unsigned n = ++shag4_n;
    ULONG_PTR pc  = (ULONG_PTR)PC_sig(context);
    ULONG_PTR x16 = (ULONG_PTR)REGn_sig(16, context);
    ULONG_PTR x17 = (ULONG_PTR)REGn_sig(17, context);
    ULONG_PTR x18 = (ULONG_PTR)REGn_sig(18, context);
    ULONG_PTR x28 = (ULONG_PTR)REGn_sig(28, context);
    unsigned chpe_off = (unsigned)FIELD_OFFSET(TEB, ChpeV2CpuAreaInfo);
    TEB *teb = NtCurrentTeb();
    unsigned i;

    if (n > 8) return;

    /* ---------- (1) СТЕНА x64: область CHPE ---------- */
    {
        ULONG_PTR from_x18 = 0, from_teb = 0;
        BOOL ok18 = macrunner_hb_safe_copy( x18 + chpe_off, &from_x18, sizeof(from_x18) );
        BOOL okteb = teb && macrunner_hb_safe_copy( (ULONG_PTR)teb + chpe_off, &from_teb, sizeof(from_teb) );
        void *m17 = macrunner_hb_pe_module_from_pc_no_lock( (void *)x17 );
        void *mpc = macrunner_hb_pe_module_from_pc_no_lock( (void *)pc );
        void *набл_area = NULL;
        int набл_i = -1;

        for (i = 0; i < 8; i++)
            if (macrunner_shag4_cpu_teb[i] && macrunner_shag4_cpu_teb[i] == (void *)teb)
            { набл_area = macrunner_shag4_cpu_area[i]; набл_i = (int)i; }

        macrunner_sig_printf(
            "macrunner-shag4-ec: n=%u pid=%d tid=%llu site=%s pc=%p pc_мод=%p pc_смещ=%#llx\n",
            n, (int)getpid(), (unsigned long long)pthread_mach_thread_np( pthread_self() ),
            site, (void *)pc, mpc,
            (unsigned long long)(mpc ? pc - (ULONG_PTR)mpc : 0) );
        macrunner_sig_printf(
            "macrunner-shag4-ec:   x18=%p teb_unix=%p совпали=%d chpe_off=%#x\n",
            (void *)x18, teb, (x18 && teb && x18 == (ULONG_PTR)teb) ? 1 : 0, chpe_off );
        macrunner_sig_printf(
            "macrunner-shag4-ec:   [x18+chpe]=%p ok=%d  teb_unix->chpe=%p ok=%d  x16=%p x17=%p\n",
            (void *)from_x18, ok18 ? 1 : 0, (void *)from_teb, okteb ? 1 : 0,
            (void *)x16, (void *)x17 );
        macrunner_sig_printf(
            "macrunner-shag4-ec:   x17_мод=%p x17_смещ=%#llx  записано_area=%p слот=%d записей=%u\n",
            m17, (unsigned long long)(m17 ? x17 - (ULONG_PTR)m17 : 0),
            набл_area, набл_i, macrunner_shag4_cpu_n );
        for (i = 0; i < 8; i++)
            if (macrunner_shag4_cpu_teb[i])
                macrunner_sig_printf( "macrunner-shag4-ec:   след[%u] teb=%p area=%p\n",
                                      i, macrunner_shag4_cpu_teb[i], macrunner_shag4_cpu_area[i] );
        macrunner_shag4_words( "pc", pc, 8, 8 );
        if (x17 && x17 != pc) macrunner_shag4_words( "x17", x17, 4, 4 );

        /* ★ ШАГ-4, вторая итерация: ОТКУДА ПРИШЛИ.  Первый замер показал, что
         * [x18+0x1788] СОДЕРЖИТ верную область (0x1111d0000), а x17 при этом равен
         * pc-4 — то есть `ldr x17,[x18,#0x1788]` (enter_jit) НЕ ИСПОЛНЯЛСЯ.  Различить
         * «вошли не в ту точку» и «x17 остался от вызывающего» можно только по памяти
         * вызывающего и по слоту, из которого он взял цель: файл читать нельзя, у
         * гибрида ARM64X код в памяти может отличаться от файла (правки value). */
        {
            ULONG_PTR sp = (ULONG_PTR)SP_sig(context);
            ULONG_PTR x8 = (ULONG_PTR)REGn_sig(8, context);
            ULONG_PTR x9 = (ULONG_PTR)REGn_sig(9, context);
            ULONG_PTR x30 = (ULONG_PTR)REGn_sig(30, context);
            ULONG_PTR s0 = 0, s1 = 0, d8 = 0, d8b = 0;
            void *m30 = macrunner_hb_pe_module_from_pc_no_lock( (void *)x30 );

            macrunner_hb_safe_copy( sp, &s0, sizeof(s0) );
            macrunner_hb_safe_copy( sp + 8, &s1, sizeof(s1) );
            macrunner_hb_safe_copy( x8, &d8, sizeof(d8) );
            macrunner_hb_safe_copy( x8 + 8, &d8b, sizeof(d8b) );
            macrunner_sig_printf(
                "macrunner-shag4-ec2:  sp=%p [sp]=%p [sp+8]=%p x8=%p [x8]=%p [x8+8]=%p x9=%p "
                "x30=%p x30_мод=%p x30_смещ=%#llx\n",
                (void *)sp, (void *)s0, (void *)s1, (void *)x8, (void *)d8, (void *)d8b,
                (void *)x9, (void *)x30, m30,
                (unsigned long long)(m30 ? x30 - (ULONG_PTR)m30 : 0) );
            if (x30) macrunner_shag4_words( "x30", x30, 8, 4 );
        }
    }

    /* ---------- (2) СТЕНА i386: STATE FEX ---------- */
    {
        unsigned char sfd[8];
        ULONG_PTR rip = 0, p_ill = 0, p_trap = 0, p_segv = 0, p_top = 0, p_l2 = 0;
        BOOL oksfd = macrunner_hb_safe_copy( x28 + MACRUNNER_SHAG4_FEX_SFD, sfd, sizeof(sfd) );
        BOOL okrip = macrunner_hb_safe_copy( x28 + MACRUNNER_SHAG4_FEX_RIP, &rip, sizeof(rip) );
        BOOL okp = macrunner_hb_safe_copy( x28 + MACRUNNER_SHAG4_FEX_SIGSEGV, &p_segv, sizeof(p_segv) );

        macrunner_hb_safe_copy( x28 + MACRUNNER_SHAG4_FEX_SIGILL, &p_ill, sizeof(p_ill) );
        macrunner_hb_safe_copy( x28 + MACRUNNER_SHAG4_FEX_SIGTRAP, &p_trap, sizeof(p_trap) );
        macrunner_hb_safe_copy( x28 + MACRUNNER_SHAG4_FEX_LOOPTOP, &p_top, sizeof(p_top) );
        macrunner_hb_safe_copy( x28 + MACRUNNER_SHAG4_FEX_L2, &p_l2, sizeof(p_l2) );

        macrunner_sig_printf(
            "macrunner-shag4-fex: n=%u pid=%d site=%s STATE(x28)=%p ok_sfd=%d ok_rip=%d ok_ptr=%d\n",
            n, (int)getpid(), site, (void *)x28, oksfd ? 1 : 0, okrip ? 1 : 0, okp ? 1 : 0 );
        if (oksfd)
            macrunner_sig_printf(
                "macrunner-shag4-fex:   отказ: сгенерирован=%u signal=%u trapno=%u si_code=%u err=%#x\n",
                (unsigned)sfd[0], (unsigned)sfd[1], (unsigned)sfd[2], (unsigned)sfd[3],
                (unsigned)(sfd[4] | (sfd[5] << 8)) );
        macrunner_sig_printf(
            "macrunner-shag4-fex:   rip=%p  SIGSEGV=%p совпало_с_pc=%d  SIGILL=%p SIGTRAP=%p "
            "looptop=%p L2=%p\n",
            (void *)rip, (void *)p_segv, (p_segv && p_segv == pc) ? 1 : 0,
            (void *)p_ill, (void *)p_trap, (void *)p_top, (void *)p_l2 );
        /* ★ Гостевые байты по rip ДВУМЯ путями (наряд: «high-arena адрес сам по себе
         * не доказывает правильный alias»): прямой VA и VA + база арены guest32. */
        if (rip)
        {
            unsigned long long база = macrunner_hb_wow64_guest32_base();
            unsigned char b1[16], b2[16];
            BOOL o1 = macrunner_hb_safe_copy( rip, b1, sizeof(b1) );
            BOOL o2 = база ? macrunner_hb_safe_copy( (ULONG_PTR)база + rip, b2, sizeof(b2) ) : FALSE;
            void *m1 = o1 ? macrunner_hb_pe_module_from_pc_no_lock( (void *)rip ) : NULL;
            void *m2 = o2 ? macrunner_hb_pe_module_from_pc_no_lock( (void *)((ULONG_PTR)база + rip) ) : NULL;
            char s1[80], s2[80];
            int l1 = 0, l2l = 0;

            for (i = 0; i < 16; i++)
            {
                if (o1) l1 += snprintf( s1 + l1, sizeof(s1) - l1, "%02x ", b1[i] );
                if (o2) l2l += snprintf( s2 + l2l, sizeof(s2) - l2l, "%02x ", b2[i] );
            }
            {   /* ★ «прямой VA нечитаем» обязано быть отделено от «нет прав»:
                 * mach_vm_region_recurse называет БЛИЖАЙШУЮ область при/выше адреса —
                 * если её база выше rip, значит по rip не отображено ничего. */
                mach_vm_address_t r_a = (mach_vm_address_t)rip;
                mach_vm_size_t r_s = 0;
                vm_region_submap_info_data_64_t r_i;
                mach_msg_type_number_t r_c = VM_REGION_SUBMAP_INFO_COUNT_64;
                natural_t r_d = 0;
                kern_return_t r_kr = mach_vm_region_recurse( mach_task_self(), &r_a, &r_s, &r_d,
                                                             (vm_region_recurse_info_t)&r_i, &r_c );
                macrunner_sig_printf(
                    "macrunner-shag4-fex:   область_прямого_rip: запрошен=%p ближайшая=%#llx+%#llx "
                    "prot=%d max=%d kr=%d накрывает=%d\n",
                    (void *)rip, (unsigned long long)r_a, (unsigned long long)r_s,
                    r_kr ? -1 : r_i.protection, r_kr ? -1 : r_i.max_protection, r_kr,
                    (!r_kr && (ULONG_PTR)r_a <= rip && rip < (ULONG_PTR)r_a + (ULONG_PTR)r_s) ? 1 : 0 );

                /* ★★★★★ ШАГ-4 08.09.2026 — БЛИЗНЕЦ ПО АРЕНЕ.
                 *
                 * Прибор в FEX ставить нельзя (`engine/fex/CLAUDE.md`: «AI must not be used
                 * to generate code for contributions to this project»), поэтому тот же
                 * вопрос задаём СВОЕЙ стороной. Смысл пары: `InvalidationTracker`
                 * заполняет свои исполняемые отрезки ОБХОДОМ `VirtualQuery` по ХОСТОВОМУ
                 * адресному пространству (конструктор, InvalidationTracker.cpp:23-30), а
                 * `Decoder::CheckRangeExecutable` спрашивает их по СЫРОМУ гостевому rip.
                 * Если по сырому rip не отображено ничего, а по `guest32_base + rip` лежит
                 * исполняемая область — значит отрезки заведены на арене, спрошены по сырому
                 * адресу, отсюда `NOEXEC_INST` -> `NoExecOp` -> заглушка GuestSignal_SIGSEGV.
                 * Две строки рядом делают это ЧИСЛОМ, а не рассуждением. */
                if (база)
                {
                    mach_vm_address_t a2 = (mach_vm_address_t)((ULONG_PTR)база + rip);
                    mach_vm_size_t s2 = 0;
                    vm_region_submap_info_data_64_t i2;
                    mach_msg_type_number_t c2 = VM_REGION_SUBMAP_INFO_COUNT_64;
                    natural_t d2 = 0;
                    kern_return_t kr2 = mach_vm_region_recurse( mach_task_self(), &a2, &s2, &d2,
                                                                (vm_region_recurse_info_t)&i2, &c2 );
                    macrunner_sig_printf(
                        "macrunner-shag4-fex:   область_арены_rip: запрошен=%#llx ближайшая=%#llx+%#llx "
                        "prot=%d max=%d kr=%d накрывает=%d исполняемая=%d\n",
                        (unsigned long long)((ULONG_PTR)база + rip),
                        (unsigned long long)a2, (unsigned long long)s2,
                        kr2 ? -1 : i2.protection, kr2 ? -1 : i2.max_protection, kr2,
                        (!kr2 && (ULONG_PTR)a2 <= (ULONG_PTR)база + rip
                              && (ULONG_PTR)база + rip < (ULONG_PTR)a2 + (ULONG_PTR)s2) ? 1 : 0,
                        (!kr2 && (i2.protection & VM_PROT_EXECUTE)) ? 1 : 0 );
                }
            }
            macrunner_sig_printf(
                "macrunner-shag4-fex:   гость прямой rip=%p ok=%d мод=%p смещ=%#llx байты=%s\n",
                (void *)rip, o1 ? 1 : 0, m1,
                (unsigned long long)(m1 ? rip - (ULONG_PTR)m1 : 0), o1 ? s1 : "(нет)" );
            macrunner_sig_printf(
                "macrunner-shag4-fex:   гость арена база=%#llx адрес=%p ok=%d мод=%p смещ=%#llx байты=%s\n",
                база, (void *)((ULONG_PTR)база + rip), o2 ? 1 : 0, m2,
                (unsigned long long)(m2 ? (ULONG_PTR)база + rip - (ULONG_PTR)m2 : 0), o2 ? s2 : "(нет)" );
        }
    }
}


/* ==========================================================================
 * M0 — ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ (§6.2/§6.3 наряда). ТОЛЬКО в отдельном ребёнке.
 *
 * Даёт НАСТОЯЩЕМУ macrunner_hb_print_fault_regs указатель стека прямо перед
 * НАМЕРЕННО ЗАКРЫТОЙ страницей и смотрит, что скажет прибор. Вход в обработчик —
 * настоящей командой чтения из закрытой страницы G, не raise() и не kill().
 *
 * ЗАПРЕЩЕНО (наряд, дословно): включать SA_NODEFER, чистить sa_mask, перескакивать
 * PC вторичного отказа, превращать PROT_NONE в RW, подставлять ESR первичного
 * отказа вместо вторичного. Всё это уничтожило бы проверяемый исход.
 *
 * Ветвь недостижима в обычном запуске: нужен и гейт MACRUNNER_M0_CONTROL_CASE,
 * и совпадение имени главного образа (MACRUNNER_M0_CONTROL_EXE) с argv процесса.
 * ========================================================================== */

enum {
    M0_CASE_NONE = 0, M0_CASE_UNSAFE_NONE = 1, M0_CASE_UNSAFE_HOLE = 2,
    M0_CASE_READABLE_REPEAT = 3, M0_CASE_SAFE_NONE = 4,
    M0_CASE_PRIMARY_SECONDARY_DISTINCT = 5, M0_CASE_READABLE_STALE_ESR = 6
};

static unsigned macrunner_m0_case_id( const char *name )
{
    if (!name || !*name) return M0_CASE_NONE;
    if (!strcmp( name, "unsafe-none" ))       return M0_CASE_UNSAFE_NONE;
    if (!strcmp( name, "unsafe-hole" ))       return M0_CASE_UNSAFE_HOLE;
    if (!strcmp( name, "readable-repeat" ))   return M0_CASE_READABLE_REPEAT;
    if (!strcmp( name, "safe-none" ))         return M0_CASE_SAFE_NONE;
    if (!strcmp( name, "primary-secondary-distinct" )) return M0_CASE_PRIMARY_SECONDARY_DISTINCT;
    if (!strcmp( name, "readable-stale-esr" )) return M0_CASE_READABLE_STALE_ESR;
    return 0xffffffffu;                       /* неизвестный случай — НЕ пропускать молча */
}

static unsigned  m0_ctl_case;
static ULONG_PTR m0_ctl_B, m0_ctl_G;
static size_t    m0_ctl_P;
static volatile int m0_ctl_stage;             /* последняя достигнутая ступень */
static volatile int m0_ctl_primary_hits;
static volatile int m0_ctl_dump_returns;
static volatile int m0_ctl_wrong_site;
static ULONG_PTR m0_ctl_primary_pc, m0_ctl_primary_far, m0_ctl_primary_esr;
static ucontext_t   m0_ctl_synth_uc;
static __typeof__(*(((ucontext_t *)0)->uc_mcontext)) m0_ctl_synth_mc;
static char m0_ctl_result[4096];
static int  m0_ctl_result_len;

static void m0_ctl_note( const char *fmt, ... )
{
    va_list ap;
    int n;
    if (m0_ctl_result_len >= (int)sizeof(m0_ctl_result) - 2) return;
    va_start( ap, fmt );
    n = vsnprintf( m0_ctl_result + m0_ctl_result_len,
                   sizeof(m0_ctl_result) - (size_t)m0_ctl_result_len, fmt, ap );
    va_end( ap );
    if (n > 0) m0_ctl_result_len += n;
    if (m0_ctl_result_len > (int)sizeof(m0_ctl_result) - 1)
        m0_ctl_result_len = (int)sizeof(m0_ctl_result) - 1;
}

static void m0_ctl_flush_result( void )
{
    const char *dir = getenv( "MACRUNNER_M0_DIR" );
    char path[1024];
    int fd;
    if (!dir || !*dir) return;
    snprintf( path, sizeof(path), "%s/control-result-%d.txt", dir, (int)getpid() );
    fd = open( path, O_CREAT | O_TRUNC | O_WRONLY, 0600 );
    if (fd < 0) return;
    { ssize_t ig = write( fd, m0_ctl_result, (size_t)m0_ctl_result_len ); (void)ig; }
    close( fd );
}

/* Публикация в общий буфер: контроль обязан оставить след даже если процесс умрёт. */
static void m0_ctl_publish( uint64_t stage, uint64_t a, uint64_t b, uint64_t c )
{
    struct m0_thread *t = macrunner_m0_slot();
    struct m0_scan_payload p;
    struct m0_rec *rec;
    uint64_t ticket = 0;
    if (!t) return;
    memset( &p, 0, sizeof(p) );
    p.outcome = stage; p.sp = a; p.verh = b; p.ea_first = c;
    rec = macrunner_m0_reserve( t, &ticket );
    macrunner_m0_publish( rec, ticket, M0_KIND_CONTROL, t, 0, 0, 0, &p, (uint32_t)sizeof(p) );
}

/* Обработчик контроля. Установка — как у боевого: оба сигнала в sa_mask,
 * SA_SIGINFO|SA_RESTART|SA_ONSTACK, БЕЗ SA_NODEFER. */
static void m0_ctl_handler( int sig, siginfo_t *si, void *ucp )
{
    ucontext_t *c = (ucontext_t *)ucp;
    ULONG_PTR addr = si ? (ULONG_PTR)si->si_addr : 0;

    m0_ctl_primary_hits++;
    m0_ctl_primary_pc  = (ULONG_PTR)PC_sig( c );
    m0_ctl_primary_far = (ULONG_PTR)c->uc_mcontext->__es.__far;
    m0_ctl_primary_esr = (ULONG_PTR)c->uc_mcontext->__es.__esr;
    m0_ctl_publish( 100 + (uint64_t)m0_ctl_primary_hits, (uint64_t)m0_ctl_primary_pc,
                    (uint64_t)m0_ctl_primary_far, (uint64_t)addr );

    /* Первичный отказ обязан прийти ИМЕННО из G. Иначе это уже вторичный отказ
     * (или чужой), и переводить его PC нельзя. */
    if (!(addr >= m0_ctl_G && addr < m0_ctl_G + m0_ctl_P))
    {
        m0_ctl_wrong_site = 1;
        m0_ctl_publish( 199, (uint64_t)addr, (uint64_t)m0_ctl_primary_pc,
                        (uint64_t)m0_ctl_primary_esr );
        /* НЕ перескакиваем PC вторичного отказа: пусть исход будет настоящим. */
        _exit( 70 );
    }

    m0_ctl_stage = 3;
    /* Синтетическая копия контекста. Настоящий контекст первичного сигнала НЕ трогаем
     * его SP: он остаётся для возврата. */
    memcpy( &m0_ctl_synth_uc, c, sizeof(m0_ctl_synth_uc) );
    memcpy( &m0_ctl_synth_mc, c->uc_mcontext, sizeof(m0_ctl_synth_mc) );
    m0_ctl_synth_uc.uc_mcontext = &m0_ctl_synth_mc;
    m0_ctl_synth_mc.__ss.__sp = (uint64_t)(m0_ctl_B + m0_ctl_P - 16);
    m0_ctl_synth_mc.__ss.__lr = 0;        /* ранний поиск x30 не нужен (§6.2 п.3) */
    m0_ctl_synth_mc.__ss.__fp = 0;

    macrunner_m0_control_sp   = m0_ctl_B + m0_ctl_P - 16;
    macrunner_m0_control_verh = m0_ctl_B + 2 * m0_ctl_P;
    macrunner_m0_control_armed = 1;

    m0_ctl_publish( 200, (uint64_t)macrunner_m0_control_sp,
                    (uint64_t)macrunner_m0_control_verh, (uint64_t)m0_ctl_case );

    if (m0_ctl_case == M0_CASE_SAFE_NONE)
    {
        /* Безопасная парная рука: в обработчике ТОЛЬКО снимок и задание диапазона.
         * Никакого прямого чтения. Разбор — после выхода из обработчика. */
        m0_ctl_stage = 4;
        m0_ctl_publish( 300, (uint64_t)macrunner_m0_control_sp,
                        (uint64_t)macrunner_m0_control_verh, 0 );
    }
    else
    {
        /* ОПАСНАЯ рука: НАСТОЯЩИЙ печатник по синтетическому контексту. */
        m0_ctl_stage = 4;
        macrunner_hb_print_fault_regs( &m0_ctl_synth_uc, "m0-control" );
        if (m0_ctl_case == M0_CASE_READABLE_REPEAT)
            macrunner_hb_print_fault_regs( &m0_ctl_synth_uc, "m0-control-2" );
        m0_ctl_dump_returns++;
        m0_ctl_stage = 5;
        m0_ctl_publish( 400, (uint64_t)m0_ctl_dump_returns, 0, 0 );
    }
    macrunner_m0_control_armed = 0;

    /* Возврат из первичного отказа: пропускаем сбойную команду чтения.
     * Разрешено ТОЛЬКО для первичного load (§6.2 п.6/§6.2 конец). */
    PC_sig( c ) = (DWORD64)(m0_ctl_primary_pc + 4);
    (void)sig;
}

/* Отложенное проверенное чтение для безопасной руки (§6.3). */
static void m0_ctl_deferred_read( void )
{
    ULONG_PTR lo = macrunner_m0_control_sp ? macrunner_m0_control_sp : (m0_ctl_B + m0_ctl_P - 16);
    ULONG_PTR hi = m0_ctl_B + 2 * m0_ctl_P;
    ULONG_PTR a;
    unsigned ok = 0, bad = 0;
    unsigned char buf[4096];

    for (a = lo; a < hi; )
    {
        mach_vm_size_t got = 0;
        mach_vm_size_t want = 4096;
        kern_return_t kr;
        if (a + want > hi) want = hi - a;
        kr = mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)a, want,
                                     (mach_vm_address_t)buf, &got );
        if (kr != KERN_SUCCESS || got != want)
        {
            bad++;
            m0_ctl_note( "safe: UNREADABLE_FRAGMENT адрес=%p want=%llu got=%llu kr=%d\n",
                         (void *)a, (unsigned long long)want, (unsigned long long)got, (int)kr );
        }
        else { ok++; m0_ctl_note( "safe: прочитано %p..%p\n", (void *)a, (void *)(a + want) ); }
        a += want;
    }
    m0_ctl_note( "safe: STACK_CAPTURE_DONE фрагментов_ок=%u недоступных=%u\n", ok, bad );
    m0_ctl_publish( 500, ok, bad, 0 );
}

/* Совпадает ли argv процесса с назначенным главным образом. Читаем через sysctl
 * СВОЕГО pid — без прав отладчика и без чужой памяти. */
static int m0_ctl_argv_matches( const char *needle )
{
    int mib[3];
    size_t sz = 0;
    char *buf;
    int found = 0;

    if (!needle || !*needle) return 0;
    mib[0] = CTL_KERN; mib[1] = KERN_PROCARGS2; mib[2] = (int)getpid();
    if (sysctl( mib, 3, NULL, &sz, NULL, 0 ) || !sz) return 0;
    if (sz > (1u << 20)) return 0;
    buf = malloc( sz + 1 );
    if (!buf) return 0;
    if (!sysctl( mib, 3, buf, &sz, NULL, 0 ))
    {
        size_t i;
        buf[sz] = 0;
        for (i = 0; i + strlen( needle ) <= sz; i++)
            if (!memcmp( buf + i, needle, strlen( needle ) )) { found = 1; break; }
    }
    free( buf );
    return found;
}

static void macrunner_m0_control_maybe_run( void )
{
    const char *cname = getenv( "MACRUNNER_M0_CONTROL_CASE" );
    const char *cexe  = getenv( "MACRUNNER_M0_CONTROL_EXE" );
    struct sigaction sa;
    size_t P;
    void *B, *G;
    volatile unsigned long *probe;
    unsigned long sink;

    if (!cname || !*cname) return;
    m0_ctl_case = macrunner_m0_case_id( cname );
    if (m0_ctl_case == M0_CASE_NONE) return;
    if (m0_ctl_case == 0xffffffffu)
    {
        fprintf( stderr, "macrunner-m0-control: НЕИЗВЕСТНЫЙ случай '%s' — отказ, "
                         "тихо не пропускаем\n", cname );
        fflush( stderr );
        _exit( 71 );
    }
    /* Сторож главного образа: wineboot/services наследуют переменную, но фикстуру
     * НЕ исполняют. */
    if (!m0_ctl_argv_matches( cexe )) return;

    P = (size_t)sysconf( _SC_PAGESIZE );
    if ((long)P <= 0 || (P & (P - 1))) { fprintf( stderr, "macrunner-m0-control: плохой P\n" ); _exit( 72 ); }
    m0_ctl_P = P;

    B = mmap( NULL, 2 * P, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0 );
    G = mmap( NULL, P, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0 );
    if (B == MAP_FAILED || G == MAP_FAILED) { fprintf( stderr, "macrunner-m0-control: mmap\n" ); _exit( 73 ); }
    memset( B, 0, 2 * P );
    memset( G, 0, P );
    m0_ctl_B = (ULONG_PTR)B;
    m0_ctl_G = (ULONG_PTR)G;

    /* Порча: вторая страница данных закрыта (или её вовсе нет). */
    if (m0_ctl_case == M0_CASE_UNSAFE_HOLE)
    {
        if (munmap( (char *)B + P, P )) { fprintf( stderr, "macrunner-m0-control: munmap\n" ); _exit( 74 ); }
    }
    else if (m0_ctl_case == M0_CASE_READABLE_REPEAT || m0_ctl_case == M0_CASE_READABLE_STALE_ESR)
    {
        /* обе страницы остаются RW — положительный контроль «одинаковый адрес
         * НЕ создаёт STUCK» */
    }
    else
    {
        if (mprotect( (char *)B + P, P, PROT_NONE )) { fprintf( stderr, "macrunner-m0-control: mprotect B\n" ); _exit( 75 ); }
    }
    if (mprotect( G, P, PROT_NONE )) { fprintf( stderr, "macrunner-m0-control: mprotect G\n" ); _exit( 76 ); }

    m0_ctl_note( "case=%s P=%zu B=%p G=%p B+P=%p SP=%p verh=%p\n", cname, P, B, G,
                 (void *)((char *)B + P), (void *)((ULONG_PTR)B + P - 16),
                 (void *)((ULONG_PTR)B + 2 * P) );

    memset( &sa, 0, sizeof(sa) );
    sigemptyset( &sa.sa_mask );
    sigaddset( &sa.sa_mask, SIGSEGV );
    sigaddset( &sa.sa_mask, SIGBUS );
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;   /* SA_NODEFER ОТСУТСТВУЕТ */
    sa.sa_sigaction = m0_ctl_handler;
    if (sigaction( SIGSEGV, &sa, NULL ) || sigaction( SIGBUS, &sa, NULL ))
    { fprintf( stderr, "macrunner-m0-control: sigaction\n" ); _exit( 77 ); }
    {   /* фактическую установку читаем ВНЕ обработчика */
        struct sigaction got;
        if (!sigaction( SIGSEGV, NULL, &got ))
            m0_ctl_note( "segv sa_flags=%#x sa_mask=%#llx SA_NODEFER=%s\n",
                         (unsigned)got.sa_flags, (unsigned long long)got.sa_mask,
                         (got.sa_flags & SA_NODEFER) ? "ЕСТЬ(ошибка)" : "нет" );
        if (!sigaction( SIGBUS, NULL, &got ))
            m0_ctl_note( "bus  sa_flags=%#x sa_mask=%#llx\n",
                         (unsigned)got.sa_flags, (unsigned long long)got.sa_mask );
    }

    m0_ctl_stage = 2;
    m0_ctl_publish( 1, (uint64_t)m0_ctl_B, (uint64_t)m0_ctl_G, (uint64_t)m0_ctl_case );
    m0_ctl_flush_result();
    fprintf( stderr, "macrunner-m0-control: pid=%d случай=%s ступень=подготовлено "
                     "B=%p G=%p SP=%p verh=%p\n",
             (int)getpid(), cname, B, G, (void *)((ULONG_PTR)B + P - 16),
             (void *)((ULONG_PTR)B + 2 * P) );
    fflush( stderr );

    /* НАСТОЯЩАЯ команда чтения из закрытой страницы — не raise(), не kill(). */
    probe = (volatile unsigned long *)G;
    sink = *probe;
    (void)sink;

    m0_ctl_stage = 6;
    if (m0_ctl_case == M0_CASE_SAFE_NONE) m0_ctl_deferred_read();
    if (m0_ctl_case == M0_CASE_READABLE_STALE_ESR)
    {
        /* доступная загрузка ПОСЛЕ первичного отказа: прежний ESR не должен стать
         * «вторичным отказом» */
        volatile unsigned long *ok = (volatile unsigned long *)B;
        unsigned long v = *ok;
        m0_ctl_note( "stale-esr: доступная загрузка после отказа дала %llu, "
                     "прежний esr=%#llx far=%#llx\n", (unsigned long long)v,
                     (unsigned long long)m0_ctl_primary_esr,
                     (unsigned long long)m0_ctl_primary_far );
        m0_ctl_publish( 600, (uint64_t)m0_ctl_primary_esr, (uint64_t)m0_ctl_primary_far, 0 );
    }
    m0_ctl_note( "ИТОГ: ступень=%d первичных_входов=%d возвратов_дампа=%d чужой_сайт=%d "
                 "primary_pc=%p primary_far=%p primary_esr=%#llx\n",
                 m0_ctl_stage, m0_ctl_primary_hits, m0_ctl_dump_returns, m0_ctl_wrong_site,
                 (void *)m0_ctl_primary_pc, (void *)m0_ctl_primary_far,
                 (unsigned long long)m0_ctl_primary_esr );
    m0_ctl_publish( 900, (uint64_t)m0_ctl_stage, (uint64_t)m0_ctl_primary_hits,
                    (uint64_t)m0_ctl_dump_returns );
    m0_ctl_flush_result();
    fprintf( stderr, "macrunner-m0-control: pid=%d ЗАВЕРШЕНО ступень=%d входов=%d "
                     "возвратов=%d\n", (int)getpid(), m0_ctl_stage,
             m0_ctl_primary_hits, m0_ctl_dump_returns );
    fflush( stderr );
    _exit( 0 );
}

HB_PROBE_DEFINE(pr_segv_census, "hb-segv-census-гейт",
                "входы в segv_handler ДО проверки гейта; hits = гейт "
                "MACRUNNER_HB_SEGV_CENSUS оказался открыт (умолчание — закрыт)",
                "MACRUNNER_HB_SEGV_CENSUS", 0);

/* ★★★★ ЗАПЛАТКА KUSER_SHARED_DATA — лейн ЗАПЛАТКА, 08.09.2026 ★★★★
 *
 * Разбор стены, узор команд, перепись 19 020 ARM64-PE и смета лечения —
 * reports/OBSHCHAYA-STRANITSA-08.09.2026.md, разделы 1-4.
 * Признаки решения и почему их четыре — engine/wine/dlls/ntdll/unix/macrunner_kusd.h.
 *
 * Коротко: MSVC-CRT читает KUSER_SHARED_DATA по ЗАШИТОМУ адресу 0x7FFE0000
 * парой команд `movz x16,#0x7ffe,lsl#16` + `ldrb w16,[x16,#0x296]`. Низ 4 ГБ нам
 * закрыт ядром, поэтому такое чтение — стена: Notepad++ ARM64 умирает на ней
 * 3 прогона из 3, эталон CrossOver проходит целиком.
 *
 * 0x00007FFE00000000 выразим ТЕМ ЖЕ movz (поле hw = 2 вместо 1), поэтому лечение —
 * переписать ЧЕТЫРЕ БАЙТА на месте. Отказ по каждому МЕСТУ случается ОДИН раз,
 * дальше гость читает верный адрес без всякого перехвата.
 *
 * ★ ГЛОБАЛЬНЫЙ АДРЕС KUSD НЕ ДВИГАЕМ. Вместо переноса константы (winternl.h +
 * preloader_mac.c + зоны резервирования + 12 потребителей макроса) заводим ЛЕНИВЫЙ
 * АЛИАС: второе имя той же памяти по 0x00007FFE00000000. Когерентность алиаса
 * доказана оракулом обеими руками (tools/zaplatka/orakul-alias.c):
 *     mach_vm_remap copy=FALSE -> запись в источник ВИДНА в алиасе (КОГЕРЕНТЕН)
 *     mach_vm_remap copy=TRUE  -> НЕ видна (контроль: копия, время бы замёрзло)
 * Когерентность здесь не косметика: по +0x320 лежит InterruptTime, и копия
 * означала бы замерзшее время — дефект, который проявился бы много позже.
 *
 * ★★★ ГЕЙТ MACRUNNER_HB_KUSD_PATCH, УМОЛЧАНИЕ 1 (включено 08.09.2026, лейн ВКЛЮЧИТЬ).
 * ВЫКЛЮЧАТЕЛЬ — MACRUNNER_HB_KUSD_PATCH=0: возвращает ровно прежнее поведение,
 * функция выходит первой же строкой. Приёмка включения — reports/VKLYUCHIT-KUSD-08.09.2026.md.
 *
 * ★★★ ЕДИНСТВЕННЫЙ НАСТОЯЩИЙ РИСК ВКЛЮЧЕНИЯ — САМОКОНТРОЛЬ КОДА.
 *
 * Заплатка переписывает ЧЕТЫРЕ БАЙТА в секции кода гостя. Программа, которая
 * считает контрольную сумму собственного образа (защита от вскрытия, anti-tamper,
 * упаковщики, DRM, проверка подписи своего .text в рантайме), эту правку ЗАМЕТИТ и
 * поведёт себя как при взломе: откажется стартовать, соврёт про повреждённый файл
 * или тихо уйдёт в другой путь. Отказ будет выглядеть НЕ как наш дефект.
 *
 * Признак: программа с защитой от вскрытия, в журнале есть `macrunner-kusd-zaplatka`,
 * и программа жалуется на целостность/подпись/повреждение. Лечение — выключатель:
 *     MACRUNNER_HB_KUSD_PATCH=0
 * Тогда вернётся прежняя стена 0x7FFE0296, но самоконтроль будет доволен.
 * На момент включения такой случай НЕ ВСТРЕЧАЛСЯ: проверено на Notepad++ ARM64 и
 * apphost .NET 8 — ни у одного самоконтроля нет. Это граница, а не наблюдение.
 *
 * ★ Наших двоичных заплатка коснуться не может по построению: перепись 08.09 нашла
 * узор в 16 файлах из 19 020, и НИ ОДНОГО среди ~5 700 наших ARM64-PE (мы собираем
 * clang'ом, узор — вставка MSVC). Правится только код ГОСТЯ и только по отказу. */

static ULONG_PTR macrunner_kusd_alias_base;   /* 0 = ещё не заводили */
static int       macrunner_kusd_alias_kr = -2;
static unsigned  macrunner_kusd_zaplat;       /* сколько мест переписано за прогон */
static unsigned  macrunner_kusd_otvergnuto;   /* сколько отказов отвергнуто по признакам */
static volatile sig_atomic_t macrunner_kusd_enabled = 1;
static volatile sig_atomic_t macrunner_fex_kusd_backend;

static void __attribute__((constructor)) macrunner_kusd_config_init(void)
{
    const char *value = getenv( "MACRUNNER_CPU_BACKEND" );
    macrunner_fex_kusd_backend = value && !strcasecmp( value, "fex" );
    value = getenv( "MACRUNNER_HB_KUSD_PATCH" );
    macrunner_kusd_enabled = !value || value[0] != '0';
}

/* Умолчание 1 с 08.09.2026. Выключает ТОЛЬКО явный ноль первым символом — это
 * ТОЧНОЕ ЗЕРКАЛО принятой в файле формы `v && v[0] && v[0] != '0'` (там «0…» = выкл,
 * здесь тоже «0…» = выкл). Переменная не задана ИЛИ пуста — заплатка работает:
 * пустая переменная у нас везде читается как «не задана», и менять это тут нельзя,
 * иначе `MACRUNNER_HB_KUSD_PATCH=` начало бы значить «выключить» только в этом гейте. */
static int macrunner_kusd_gate( void )
{
    /* No lazy getenv/snapshot allocation from a signal handler. */
    return macrunner_kusd_enabled;
}

/* Заводит алиас один раз на процесс. Возвращает 1 при удаче.
 * Код возврата ПЕЧАТАЕТСЯ всегда: «не сработало» обязано быть отличимо от
 * «не позвалось» — это у нас уже стоило прогонов. */
static int macrunner_kusd_alias_gotov( void )
{
    mach_vm_address_t alias = (mach_vm_address_t)MACRUNNER_KUSD_HIGH_BASE;
    vm_prot_t cur = 0, max = 0;
    kern_return_t kr;

    if (macrunner_kusd_alias_base) return 1;
    if (macrunner_kusd_alias_kr >= 0) return 0;      /* уже пробовали и не вышло */

    kr = mach_vm_remap( mach_task_self(), &alias, (mach_vm_size_t)page_size, 0,
                        VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                        mach_task_self(),
                        (mach_vm_address_t)WINE_USER_SHARED_DATA_ADDRESS,
                        /* copy */ FALSE, &cur, &max, VM_INHERIT_SHARE );
    macrunner_kusd_alias_kr = (int)kr;
    if (kr != KERN_SUCCESS || alias != (mach_vm_address_t)MACRUNNER_KUSD_HIGH_BASE)
    {
        macrunner_sig_printf( "macrunner-kusd-alias: kr=%d адрес=%p — АЛИАС НЕ ЗАВЁЛСЯ, "
                              "заплатке некуда целиться\n",
                              (int)kr, (void *)(ULONG_PTR)alias );
        return 0;
    }
    macrunner_kusd_alias_base = (ULONG_PTR)alias;
    macrunner_sig_printf( "macrunner-kusd-alias: kr=0 адрес=%p cur=0x%x max=0x%x "
                          "источник=%p (когерентный, copy=FALSE)\n",
                          (void *)macrunner_kusd_alias_base, (unsigned)cur, (unsigned)max,
                          (void *)(ULONG_PTR)WINE_USER_SHARED_DATA_ADDRESS );
    return 1;
}

/* Перепись четырёх байтов в ИСПОЛНЯЕМОЙ странице гостя.
 * Два пути: обычный mprotect и, если max_protection не даёт записи,
 * mach_vm_protect с VM_PROT_COPY (заставляет завести приватную копию).
 * Второй путь нужен для образов, отображённых только на чтение+исполнение. */
static int macrunner_kusd_perepisat( ULONG_PTR va, unsigned int novaya )
{
    /* ★ ВЫРАВНИВАНИЕ — ПО СТРАНИЦЕ ХОЗЯИНА, А НЕ ПО page_size ИЗ WINE.
     * `page_size` в unix_private.h:276 — КОНСТАНТА 0x1000, тогда как настоящая
     * страница macOS ARM64 равна 16384. Первая версия заплатки выравнивала по
     * 4 КБ, и оба mprotect честно отвечали EINVAL (errno=22) — прогон 08.09
     * on1 напечатал «возврат прав RX не удался ... errno=22». Права при этом
     * оставались от запасного пути, то есть страница уходила в исполнение с
     * чужими правами. Дефект был виден только потому, что код возврата
     * печатается; молчаливая версия оставила бы его на месяцы. */
    long      hps  = sysconf( _SC_PAGESIZE );
    ULONG_PTR page = va & ~(ULONG_PTR)(hps - 1);
    size_t    len  = (size_t)hps;
    int       put  = 0;

    if ((va & (ULONG_PTR)(hps - 1)) + 4 > (ULONG_PTR)hps) len = (size_t)hps * 2;

    if (mprotect( (void *)page, len, PROT_READ | PROT_WRITE | PROT_EXEC ) == 0) put = 1;
    else if (mprotect( (void *)page, len, PROT_READ | PROT_WRITE ) == 0)        put = 2;
    else
    {
        kern_return_t kr = mach_vm_protect( mach_task_self(), (mach_vm_address_t)page,
                                            (mach_vm_size_t)len, FALSE,
                                            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY );
        if (kr == KERN_SUCCESS) put = 3;
        else
        {
            macrunner_sig_printf( "macrunner-kusd-zaplatka: НЕ ОТКРЫЛАСЬ на запись "
                                  "va=%p errno=%d kr=%d — место не тронуто\n",
                                  (void *)va, errno, (int)kr );
            return 0;
        }
    }

    memcpy( (void *)va, &novaya, 4 );

    /* Возвращаем прежние права. Неудача здесь не смертельна (страница осталась
     * исполняемой), но обязана быть ВИДНА, а не проглочена. */
    if (mprotect( (void *)page, len, PROT_READ | PROT_EXEC ) != 0)
        macrunner_sig_printf( "macrunner-kusd-zaplatka: возврат прав RX не удался "
                              "va=%p errno=%d (страница осталась записываемой)\n",
                              (void *)va, errno );
    __builtin___clear_cache( (char *)va, (char *)va + 4 );
    return put;
}

/*
 * Единственная точка входа заплатки. Зовётся из segv_handler И bus_handler:
 * macOS метит отказ по неотображённому низкому адресу то как SEGV, то как BUS,
 * и покрыть надо оба — иначе лечение окажется лотереей.
 *
 * Возвращает 1, если место переписано и надо ВЕРНУТЬСЯ БЕЗ СДВИГА pc: команда
 * обращения исполнится заново, теперь по верной базе.
 * Возвращает 0 во всех прочих случаях, НИЧЕГО не изменив.
 */
static void macrunner_fex_kusd_note( uint64_t n, uint64_t pc, uint32_t insn, uint64_t fault,
                                     uint64_t source, const struct macrunner_fex_kusd_load *load )
{
    static const char *const names[] = {"n=", " pc=", " insn=", " addr=", " source=",
                                        " width=", " acquire=", " rt="};
    const uint64_t values[] = {n, pc, insn, fault, source, load->width, load->acquire, load->rt};
    const char *text = "macrunner-fex-kusd-read: ";
    char buffer[320], *p = buffer;
    unsigned int i;
    int saved_errno = errno;

    /* Fixed-size integer-only formatting: no stdio, locale, allocator or locks. */
    while (*text) *p++ = *text++;
    for (i = 0; i < ARRAY_SIZE(values); i++)
    {
        int shift = 60;
        text = names[i];
        while (*text) *p++ = *text++;
        *p++ = '0'; *p++ = 'x';
        while (shift && !(values[i] >> shift)) shift -= 4;
        for (; shift >= 0; shift -= 4) *p++ = "0123456789abcdef"[(values[i] >> shift) & 15];
    }
    *p++ = '\n';
    write( 2, buffer, p - buffer );
    errno = saved_errno;
}

static int macrunner_fex_kusd_popytka( siginfo_t *siginfo, ucontext_t *context )
{
    uint64_t regs[31], pc = PC_sig(context), fault = (ULONG_PTR)siginfo->si_addr;
    struct macrunner_fex_kusd_load load;
    vm_region_submap_short_info_data_64_t info;
    mach_vm_address_t base;
    mach_vm_size_t size;
    uint32_t insn;
    unsigned int i;
    ULONG_PTR source = WINE_USER_SHARED_DATA_ADDRESS;
    static unsigned long long handled;

    if (!macrunner_fex_kusd_backend || !macrunner_cpu_backend_disables_hb_semantics()) return 0;
    if (macrunner_fault_access_kind( get_fault_esr(context) ) != EXCEPTION_READ_FAULT) return 0;
    if (!macrunner_hb_safe_copy( pc, &insn, sizeof(insn) )) return 0;
    for (i = 0; i < 29; i++) regs[i] = REGn_sig(i, context);
    regs[29] = FP_sig(context);
    regs[30] = LR_sig(context);
    if (!macrunner_fex_kusd_decode( insn, fault, regs, SP_sig(context), &load )) return 0;

    /* Use Wine's live MAP_SHARED mapping, not a snapshot or a guest/JIT address rewrite.
     * virtual_map_user_shared_data owns this fixed mapping for the process lifetime. */
    if (!macrunner_region_lookup( source, &base, &size, &info ) || info.is_submap ||
        !(info.protection & VM_PROT_READ) || source < base ||
        size < MACRUNNER_FEX_KUSD_SIZE || source - base > size - MACRUNNER_FEX_KUSD_SIZE)
        return 0;
    if (!macrunner_fex_kusd_emulate( insn, fault, regs, SP_sig(context), &pc,
                                    macrunner_fex_kusd_read_live, (void *)source )) return 0;

    if (load.rt < 29) REGn_sig(load.rt, context) = regs[load.rt];
    else if (load.rt == 29) FP_sig(context) = regs[29];
    else if (load.rt == 30) LR_sig(context) = regs[30];
    PC_sig(context) = pc;
    {
        unsigned long long n = __atomic_add_fetch( &handled, 1, __ATOMIC_RELAXED );
        if (n <= 8 || !(n & (n - 1)))
            macrunner_fex_kusd_note( n, pc - 4, insn, fault, source + load.offset, &load );
    }
    return 1;
}

static int macrunner_kusd_popytka( siginfo_t *siginfo, ucontext_t *context )
{
    struct macrunner_kusd_reshenie r;
    unsigned long long regs[31];
    unsigned long long fault, pc;
    unsigned int insn_prev = 0;
    int prev_ok, i, put;

    if (!macrunner_kusd_gate()) return 0;
    if (!siginfo || !siginfo->si_addr) return 0;

    fault = (unsigned long long)(ULONG_PTR)siginfo->si_addr;
    /* Дешёвый отсев ПЕРЕД любой работой: подавляющее большинство отказов —
     * не наши, и они не должны платить за эту проверку ничем. */
    if (!macrunner_kusd_adres_nizkiy( fault ))
    {
        /* ★ СЛЕД ПОСЛЕ ЗАПЛАТКИ. Прогон on1 прошёл стену 0x7FFE0296 и тут же
         * упёрся в следующий отказ (`str w16,[x17,#0x290]` по 0x1400016CC), а
         * причину пришлось бы угадывать: регистров в журнале нет. Гадать здесь
         * нечего — печатаем первые 8 отказов ПОСЛЕ первой заплатки вместе с
         * регистрами, которыми этот код считает адрес. Печать узкая: только при
         * открытом гейте и только когда заплатка уже сработала, поэтому обычный
         * прогон она не удорожает ничем. */
        if (macrunner_kusd_zaplat)
        {
            static unsigned sled_n;
            if (sled_n++ < 8)
                macrunner_sig_printf( "macrunner-kusd-sled: n=%u addr=%p pc=%p "
                                      "x15=%p x16=%p x17=%p x8=%p\n",
                                      sled_n, siginfo->si_addr,
                                      (void *)(ULONG_PTR)PC_sig( context ),
                                      (void *)(ULONG_PTR)REGn_sig( 15, context ),
                                      (void *)(ULONG_PTR)REGn_sig( 16, context ),
                                      (void *)(ULONG_PTR)REGn_sig( 17, context ),
                                      (void *)(ULONG_PTR)REGn_sig( 8, context ) );
        }
        return 0;
    }

    /* FEX loads must preserve guest addresses and NZCV; never patch their MOVZ/MOVK. */
    if (macrunner_fex_kusd_backend && macrunner_cpu_backend_disables_hb_semantics())
        return macrunner_fex_kusd_popytka( siginfo, context );

    pc = (unsigned long long)(ULONG_PTR)PC_sig( context );
    if (pc < 4) return 0;

    /* Только безопасное чтение: pc-4 может оказаться неотображённым, и прямое
     * разыменование убило бы процесс внутри разбора чужого отказа. */
    prev_ok = macrunner_hb_safe_copy( (ULONG_PTR)(pc - 4), &insn_prev, sizeof(insn_prev) ) ? 1 : 0;

    /* ★ x29 и x30 берём ИМЕНОВАННЫМИ полями, а не REGn_sig.
     * На macOS `__ss.__x[]` объявлен как __uint64_t[29] — только x0..x28
     * (SDK mach/arm/_structs.h:150), а fp и lr лежат отдельными полями сразу
     * за массивом. REGn_sig(29)/REGn_sig(30) читают ЗА КОНЦОМ массива: значения
     * при этом случайно верные (поля идут подряд), поэтому дефект не проявился бы
     * ни в одном прогоне, а компилятор ловит его только на константном индексе —
     * в цикле молчит. Сам файл этим уже болеет в 10 местах (строки 10381 и др.). */
    for (i = 0; i < 29; i++) regs[i] = (unsigned long long)REGn_sig( i, context );
    regs[29] = (unsigned long long)FP_sig( context );
    regs[30] = (unsigned long long)LR_sig( context );

    macrunner_kusd_reshit( fault, pc, insn_prev, prev_ok, regs, &r );

    if (!r.patchit)
    {
        /* Печатаем первые 16 отвергнутых: без них «заплатка не сработала»
         * неотличимо от «сюда не заходили», а это разные диагнозы. */
        if (macrunner_kusd_otvergnuto++ < 16)
            macrunner_sig_printf( "macrunner-kusd-otverg: n=%u addr=%p pc=%p insn=0x%08x "
                                  "prev_ok=%d — %s\n",
                                  macrunner_kusd_otvergnuto, siginfo->si_addr, (void *)(ULONG_PTR)pc,
                                  insn_prev, prev_ok, macrunner_kusd_why_text( r.why ) );
        return 0;
    }

    if (!macrunner_kusd_alias_gotov()) return 0;

    if (!(put = macrunner_kusd_perepisat( (ULONG_PTR)r.insn_va, r.novaya ))) return 0;

    /* Регистр получает верную базу; pc НЕ двигаем.
     * Та же оговорка про границы массива, что и при чтении выше. */
    if      (r.rd < 29) REGn_sig( r.rd, context ) = (ULONG_PTR)r.novoe_rd;
    else if (r.rd == 29) FP_sig( context ) = (ULONG_PTR)r.novoe_rd;
    else                 LR_sig( context ) = (ULONG_PTR)r.novoe_rd;
    macrunner_kusd_zaplat++;

    /* Каждая заплатка — отдельная строка. Ожидание для Notepad++ = 7 мест;
     * если строк сильно больше, значит узор ловит лишнее, и это ДЕФЕКТ.
     * Потолок стоит высоко (256), чтобы не превратить счётчик в лотерею. */
    if (macrunner_kusd_zaplat <= 256)
        macrunner_sig_printf( "macrunner-kusd-zaplatka: n=%u va=%p 0x%08x->0x%08x rd=x%u "
                              "addr=%p put=%d\n",
                              macrunner_kusd_zaplat, (void *)(ULONG_PTR)r.insn_va,
                              r.staraya, r.novaya, r.rd, siginfo->si_addr, put );
    return 1;
}

static void segv_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    /* ПЕРЕПИСЬ ВХОДОВ (03.09.2026). Наша перепись в hb_memory.c считает входы в
     * НАШ обработчик — их за прогон 32. Но профиль i386 показывает поток,
     * который держит ядро внутри ЭТОГО обработчика. Объяснений два: либо сюда
     * приходят отказы с потока, где наш обработчик не установлен, либо один
     * вход не возвращается. Счётчик различает: много входов — первое, один
     * вход при живом потоке — второе. Порог удваивается, журнал растёт
     * логарифмом. */
    {
        static unsigned long long mr_vhodov, mr_porog = 16;
        unsigned long long v = __atomic_add_fetch( &mr_vhodov, 1, __ATOMIC_RELAXED );
        if (v >= __atomic_load_n( &mr_porog, __ATOMIC_RELAXED ))
        {
            __atomic_store_n( &mr_porog, v * 2, __ATOMIC_RELAXED );
            macrunner_sig_printf( "macrunner-wine-segv-входов: n=%llu sig=%d addr=%p\n",
                                  v, signal, siginfo ? siginfo->si_addr : NULL );
        }
    }
    struct macrunner_hb_callback_loop_signal_scope callback_loop_scope
        __attribute__((cleanup(macrunner_hb_callback_loop_signal_leave))) =
        macrunner_hb_callback_loop_signal_enter( "segv", signal, sigcontext );
    EXCEPTION_RECORD rec = { 0 };
    ucontext_t *context = sigcontext;
    DWORD64 esr = get_fault_esr( context );

    /* ★★★★★★ 02.09.2026 — СКЛЕЙКА «ОТКАЗ -> ДОВОДКА ЗАЩИТЫ -> ПОВТОР».
     *
     * Прямой доступ к памяти гостя (MACRUNNER_HB_NATIVE_MEM_I386) даёт впятеро больше
     * прямого выпуска, но прогон детерминированно кончается раньше: 13 283 строки против
     * 17 400, и шесть c0000005 против нуля. Первое исключение — по адресу база_окна +
     * 0x05d0161e, внутри образа vgui.dll во время правки импортов.
     *
     * Причина: помощник ходит ЧЕРЕЗ карту и попутно доводит хозяйскую защиту до прав
     * гостя; прямой путь ходит МИМО карты, по хозяйскому отображению, где право ещё
     * старое. Хозяйский MMU честно отказывает.
     *
     * Лечение — ленивая доводка по отказу, как у FEX и QEMU: если адрес отказа лежит
     * внутри окна guest32, применяем к странице права из карты гостя и ВОЗВРАЩАЕМСЯ БЕЗ
     * СДВИГА pc — команда исполнится заново. Проверки прав в выпущенном коде нет и не
     * должно быть: она стоила бы ровно того, ради чего прямой путь и заводили.
     *
     * Гейт MACRUNNER_HB_DIRECT_MEM_RESYNC, умолчание ВЫКЛ — приём не доказан замером. */
    {
        static int mr_resync_gate = -1;
        if (mr_resync_gate < 0)
        {
            const char *v = getenv( "MACRUNNER_HB_DIRECT_MEM_RESYNC" );
            mr_resync_gate = (v && *v && *v != '0') ? 1 : 0;
        }
        if (mr_resync_gate && siginfo && siginfo->si_addr)
        {
            extern int hb_memory_guest32_resync_by_host( unsigned long long host_addr );
            int mr_rc = hb_memory_guest32_resync_by_host( (unsigned long long)(ULONG_PTR)siginfo->si_addr );
            static unsigned int mr_resync_n;

            /* Код возврата печатаем ВСЕГДА (первые 8): без него «не сработало» неотличимо
             * от «не позвалось» и от «адрес не в окне». */
            /* Печатаем только отказы ПО АДРЕСАМ ОКНА: мелкие адреса (0x60, 0x3004) —
             * это чужие отказы приборной машинерии, они забивают вывод. */
            if ((ULONG_PTR)siginfo->si_addr >= 0x1000000000ull && mr_resync_n++ < 8)
                macrunner_sig_printf( "macrunner-hb-доводка: n=%u адрес=%p pc=%p rc=%d%s\n",
                                      mr_resync_n, siginfo->si_addr,
                                      (void *)(ULONG_PTR)PC_sig(context), mr_rc,
                                      mr_rc == 0 ? " — доведена, ПОВТОР" : " — не наша" );
            if (mr_rc == 0) return;           /* без сдвига pc: команда исполнится заново */
        }
    }

    /* ★ ЗАПЛАТКА KUSER_SHARED_DATA. Стоит ЗДЕСЬ — раньше всех приборов и раньше
     * превращения отказа в исключение: ниже по течению этот отказ становится
     * `Unhandled page fault on read access to 7FFE0296` и убивает гостя.
     * Гейт MACRUNNER_HB_KUSD_PATCH, УМОЛЧАНИЕ 1 (с 08.09.2026). Выключатель
     * MACRUNNER_HB_KUSD_PATCH=0: функция возвращает 0 первой же строкой и путь
     * остаётся ровно прежним — это и отрицательный контроль, и лечение для
     * программ с самоконтролем кода (разбор риска — у macrunner_kusd_gate). */
    {
        if (macrunner_kusd_popytka( siginfo, context ))
            return;                            /* место переписано, pc не двигаем */
    }


    /* ★ ПЕРЕПИСЬ ОТКАЗОВ (гейт MACRUNNER_HB_SEGV_CENSUS=1, умолчание 0).
     *
     * Установщик Diablo зависает на 100 % CPU в Wow64KiUserCallbackDispatcher, а штатный
     * `macrunner-hb-faultrate` в журнале НОЛЬ раз — то есть счётчики того пути не ведутся
     * и частота шторма НЕ ИЗМЕРЕНА ничем. Эта перепись стоит у самого входа: она считает
     * ВСЕ отказы и печатает редко (1, 64, 512, далее каждые 16384), поэтому шторм не
     * утопит журнал, а его наличие и размер станут числом.
     *
     * ★★★ ПОПРАВКА 07.09.2026, лейн ПРИБОРЫ-4 — ФРАЗА ВЫШЕ НЕВЕРНА, И ЭТО ИЗМЕРЕНО.
     *
     * Счётчики того пути ВЕДУТСЯ: `macrunner_hb_fault_entries` растёт безусловно, первой
     * же строкой обработчика. Не печаталась СВОДКА — она стоит под
     * `n == 64 || n == 512 || !(n & 0xfff)`, поэтому прогон с 63 отказами даёт ноль строк
     * при полностью исправном учёте.
     *
     * И вторая, более важная причина: `macrunner-hb-faultrate` живёт в ДРУГОМ
     * обработчике (`macrunner_hb_primary_signal_handler`), а сюда управление приходит
     * через `segv_handler`. Замер 07.09, wineboot --help, ntdll.so 03edda14f2eb43c3:
     *     hb-segv-census-гейт   NO-EVENTS     looked=1903  hits=0   <- ЭТОТ путь, 1903 раза
     *     hb-faultrate-сводка   NOT-OBSERVED  looked=0             <- ТОТ путь, ни разу
     * То есть ноль строк значил «в тот обработчик не входили», а не «не считаем».
     *
     * Перепись ниже оставлена: она даёт подробности (pc, addr, code, доля времени),
     * которых счётчики не выражают. Но ВЫВОД, из которого она выросла, снят. */
    struct mr_segv_timer mr_segv_scope
        __attribute__((cleanup(mr_segv_timer_leave))) = { 0 };
    struct mr_x18_resume_scope mr_x18_scope
        __attribute__((cleanup(mr_x18_resume_leave))) =
        { context, (ULONG_PTR)PC_sig(context), mr_x18_resume_always() };
    {
        static unsigned long long mr_segv_n;
        static int mr_segv_probe = -1;
        unsigned long long segv_n = __atomic_add_fetch( &mr_segv_n, 1, __ATOMIC_RELAXED );

        /* ★ 07.09.2026, лейн ПРИБОРЫ-4. Гейт умолчанием ВЫКЛЮЧЕН, поэтому ноль строк
         * `macrunner-hb-segv-census` значил две разные вещи: «гейт закрыт» и «сюда не
         * заходили». Учёт стоит ВЫШЕ гейта — это и есть точка, где наблюдение начинается;
         * hits считаются под гейтом. looked>0 hits=0 читается однозначно: путь исполнялся
         * looked раз, гейт был закрыт. Порядок вычисления не тронут. */
        HB_PROBE_LOOKED(&pr_segv_census);
        if (mr_segv_probe < 0)
        {
            const char *v = macrunner_hb_getenv( "MACRUNNER_HB_SEGV_CENSUS" );
            mr_segv_probe = (v && v[0] && v[0] != '0');
        }
        if (mr_segv_probe)
        {
            HB_PROBE_HIT(&pr_segv_census);
            unsigned long long now = mr_segv_now_ns(), first;

            mr_segv_scope.t0 = now;
            first = __atomic_load_n( &mr_segv_first_ns, __ATOMIC_RELAXED );
            if (!first) { __atomic_store_n( &mr_segv_first_ns, now, __ATOMIC_RELAXED ); first = now; }

            if (segv_n == 1 || segv_n == 64 || segv_n == 512 || !(segv_n & 0x3fff))
            {
                unsigned long long total = __atomic_load_n( &mr_segv_total_ns, __ATOMIC_RELAXED );
                unsigned long long done = segv_n - 1;
                unsigned long long ms = (now - first) / 1000000ull;

                macrunner_signal_writef(
                    "macrunner-hb-segv-census: n=%llu прошло_мс=%llu в_обработчике_мс=%llu"
                    " доля=%llu%% среднее_мкс=%llu pc=%p addr=%p code=%d\n",
                    (unsigned long long)segv_n, ms, total / 1000000ull,
                    ms ? (total / 1000000ull) * 100ull / ms : 0,
                    done ? (total / done) / 1000ull : 0,
                    (void *)(ULONG_PTR)PC_sig(context),
                    siginfo ? siginfo->si_addr : NULL,
                    siginfo ? (int)siginfo->si_code : 0 );
            }
        }
    }
#if defined(__APPLE__)
    /* MacRunner 2026-08-05 — САМЫЙ РАННИЙ ЗАМЕР, до единой нашей строки.
     *
     * Спор, который надо решить: доставка срывается с pc=0 sp=0, но отдельная программа
     * показала, что macOS отдаёт заполненный контекст даже на вложенном отказе.  Значит
     * либо ядро всё же даёт нули ИМЕННО нам (в потоке, исполняющем MAP_JIT-код), либо
     * нули появляются позже — от нашего же кода.  Прибор различает эти два случая: он
     * печатает состояние ДО того, как sigcontext увидит хоть одна наша функция.
     *
     * Печатаем только нулевые случаи и только первые 32 — обычный отказ не шумит. */
    if (!PC_sig(context) || !SP_sig(context))
    {
        static unsigned zero_entry_n;
        if (zero_entry_n++ < 32)
        {
            macrunner_signal_writef( "macrunner-hb-sigctx-zero-at-entry: n=%u sig=%d "
                                     "pc=%p sp=%p lr=%p fp=%p x0=%p si_addr=%p esr=%#llx "
                                     "uc=%p mc=%p\n",
                                     zero_entry_n, signal,
                                     (void *)(ULONG_PTR)PC_sig(context),
                                     (void *)(ULONG_PTR)SP_sig(context),
                                     (void *)(ULONG_PTR)LR_sig(context),
                                     (void *)(ULONG_PTR)REGn_sig(29, context),
                                     (void *)(ULONG_PTR)REGn_sig(0, context),
                                     siginfo ? siginfo->si_addr : NULL,
                                     (unsigned long long)esr,
                                     (void *)context, (void *)context->uc_mcontext );
        }
    }

    /* MacRunner 2026-08-05 — права области ПОД PC, снятые в момент отказа.
     *
     * Зачем отдельный прибор.  Игра умирает сразу после `Initialize engine version` с
     * c0000005 по адресу вроде 0x104C0FA8C.  На стороне PE он неопознаваем: и
     * LdrFindEntryForAddress (STATUS_NO_MORE_ENTRIES), и NtQueryVirtualMemory (MEM_FREE)
     * его не видят — это не PE-образ.  Карта, снятая снаружи через vmmap, показала область
     * "Memory Tag 22  10398c000-107990000  64.0M  rw-/rw-", то есть исполнять оттуда нельзя
     * и стать исполняемой она не может.  Но vmmap снимался не в момент отказа, поэтому
     * доказательством не является.
     *
     * Здесь права читаются РОВНО в момент отказа и ровно под PC.  Это отличает
     * "прыгнули в неисполняемую память" от "адрес был исполняемым, дело в другом" —
     * различить их иначе нечем.  Проверенная ранее версия (запасной путь mmap без MAP_JIT
     * в hb_jit_buffer_create) опровергнута: прибор там дал 0 срабатываний.
     *
     * Печатаем только первые 16 — обработчик обязан оставаться дешёвым. */
    /* Region discovery is diagnostic, not part of fault recovery. */
    if ((signal == SIGSEGV || signal == SIGBUS) && macrunner_pc_region_probe_enabled())
    {
        static unsigned pc_region_n;
        ULONG_PTR fault_pc = (ULONG_PTR)PC_sig(context);
        /* Печатать ТОЛЬКО неисполняемый PC.  Первая версия прибора печатала любой отказ и
         * весь бюджет уходил на штатные страничные отказы Wine (prot=0x5, exec есть) —
         * интересный случай до печати не доживал.  Условие ниже оставляет ровно его. */
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: условие расширено. После починки спуска в
         * подкарты «неисполняемый PC» перестал срабатывать на системных библиотеках — и
         * вместе с ложной тревогой пропал бы и НУЖНЫЙ случай: отказы внутри
         * _platform_memmove (кеш общих библиотек, от 0x180000000). Печатаем оба класса:
         * неисполняемый PC (исходная цель прибора) ЛИБО PC внутри кеша. Потолок прежний. */
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: диапазон ХОЗЯЙСКИХ образов.
         * Итерация 171 нашла настоящий адрес отказа (0x105eb4c64) и уперлась в то, что он
         * не принадлежит ntdll.so, а прибор сюда не срабатывал: PC исполняемый и лежит ВНЕ
         * общего кеша. Печати в exception.c для этого негодны — там одна и та же переменная
         * выводится то как AB0D87BF…, то как 0x10, тогда как два независимых прибора дают
         * 0x105eb4c64. Поэтому спрашиваем область здесь, где печать надёжна.
         * Расширение под тем же гейтом, что и зонд исключений: умолчание — прежнее. */
        static int probe_host_range = -1;
        if (probe_host_range < 0)
        {
            const char *v = macrunner_hb_getenv( "MACRUNNER_HB_PROBE_RAISE" );
            probe_host_range = (v && *v && *v != '0') ? 1 : 0;
        }
        if (fault_pc && pc_region_n < 16 &&
            (!macrunner_pc_region_is_exec( fault_pc ) ||
             (fault_pc >= 0x180000000ull && fault_pc < 0x280000000ull) ||
             (probe_host_range && fault_pc >= 0x100000000ull && fault_pc < 0x180000000ull)))
        {
            pc_region_n++;
            mach_vm_address_t r_addr = 0;
            mach_vm_size_t r_size = 0;
            vm_region_submap_short_info_data_64_t r_info;
            BOOL r_ok = macrunner_region_lookup( fault_pc, &r_addr, &r_size, &r_info );
            /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: печатаем ЕЩЁ И si_addr — адрес ДАННЫХ,
             * по которому случился отказ. Без него видно только «кто копировал», но не
             * «куда», а стену ступени 1 решает именно второе. Права на самой странице
             * отказа берём тем же спуском в подкарты. */
            ULONG_PTR f_addr = siginfo ? (ULONG_PTR)siginfo->si_addr : 0;
            mach_vm_address_t d_addr = 0;
            mach_vm_size_t d_size = 0;
            vm_region_submap_short_info_data_64_t d_info;
            BOOL d_ok = f_addr && macrunner_region_lookup( f_addr, &d_addr, &d_size, &d_info );
            macrunner_signal_writef( "macrunner-hb-pc-region: n=%u sig=%d pc=%p ok=%d "
                                     "region=%p-%p prot=%#x max=%#x tag=%u share=%u exec=%s"
                                     " | si_addr=%p dok=%d drange=%p-%p dprot=%#x dmax=%#x "
                                     "dtag=%u\n",
                                     pc_region_n, signal, (void *)fault_pc, (int)r_ok,
                                     (void *)(ULONG_PTR)r_addr,
                                     (void *)(ULONG_PTR)(r_addr + r_size),
                                     r_ok ? r_info.protection : 0,
                                     r_ok ? r_info.max_protection : 0,
                                     r_ok ? r_info.user_tag : 0,
                                     r_ok ? r_info.share_mode : 0,
                                     (r_ok && (r_info.protection & VM_PROT_EXECUTE)) ? "ДА" : "НЕТ",
                                     (void *)f_addr, (int)d_ok,
                                     (void *)(ULONG_PTR)d_addr,
                                     (void *)(ULONG_PTR)(d_addr + d_size),
                                     d_ok ? d_info.protection : 0,
                                     d_ok ? d_info.max_protection : 0,
                                     d_ok ? d_info.user_tag : 0 );
        }
    }
    BOOL low_stack_fault;
    void *virtual_stack;
    TEB *teb = NtCurrentTeb();
#endif

    rec.NumberParameters = 2;
    /* MacRunner 04.09.2026: разбор ESR вместо трёх чисел по месту — см. пояснение у
     * macrunner_fault_access_kind(). Прежняя проверка `esr & 0x40` объявляла записью любой
     * отказ, у которого случайно взведён бит 6, даже когда это не отказ доступа к данным. */
    rec.ExceptionInformation[0] = macrunner_fault_access_kind( esr );
    rec.ExceptionInformation[1] = (ULONG_PTR)siginfo->si_addr;
#if defined(__APPLE__)
    /* recover a gated direct guest-mem copy fault BEFORE any other handling/locking */
    macrunner_hb_dmem_fault_recover( (unsigned long long)(ULONG_PTR)siginfo->si_addr );
    low_stack_fault = macrunner_hb_is_low_stack_access_fault( context, &rec );
    virtual_stack = macrunner_hb_virtual_fault_stack( context, &rec );
#endif

    if (macrunner_hb_trace_callback_route_enabled())
        fprintf( stderr, "macrunner-hb-signal-entry: kind=segv pid=%d pc=%p fault=%p esr=0x%llx "
             "x4=%p x16=%p x24=%p x26=%p\n",
             getpid(), (void *)(ULONG_PTR)PC_sig(context),
             (void *)(ULONG_PTR)rec.ExceptionInformation[1], (unsigned long long)esr,
             (void *)(ULONG_PTR)REGn_sig(4, context), (void *)(ULONG_PTR)REGn_sig(16, context),
             (void *)(ULONG_PTR)REGn_sig(24, context), (void *)(ULONG_PTR)REGn_sig(26, context) );

#if defined(__APPLE__)
    /* MacRunner fault-time diagnostic (env-gated): the x64 JIT reported a clean MEMORY_FAULT
     * reading UnityPlayer .data (host ~0x87efe45xxxx) that the load-time probe showed RW-committed.
     * Dump the ACTUAL fault-time Mach region+protection for faults landing in the x64-guest high
     * window, to pin whether the page was reprotected (prot=0) / decommitted (region gap) at runtime. */
    if (macrunner_hb_diag_faultvm_enabled())
    {
        ULONG_PTR fa = rec.ExceptionInformation[1];
        if (fa >= 0x87ef0000000ULL && fa < 0x87f00000000ULL)
        {
            static int faultvm_n;
            if (faultvm_n++ < 24)
            {
                mach_vm_address_t ra = (mach_vm_address_t)fa;
                mach_vm_size_t rs = 0;
                vm_region_basic_info_data_64_t info;
                mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
                mach_port_t obj = MACH_PORT_NULL;
                kern_return_t kr = mach_vm_region( mach_task_self(), &ra, &rs, VM_REGION_BASIC_INFO_64,
                                                   (vm_region_info_t)&info, &cnt, &obj );
                if (obj != MACH_PORT_NULL) mach_port_deallocate( mach_task_self(), obj );
                macrunner_sig_printf( "macrunner-diag-faultvm: pc=%p lr=%p fault=%p access=%lu kr=%d "
                         "region=%p end=%p size=0x%llx prot=0x%x max=0x%x\n",
                         (void *)(ULONG_PTR)PC_sig(context), (void *)(ULONG_PTR)LR_sig(context),
                         (void *)fa, (unsigned long)rec.ExceptionInformation[0], kr,
                         (void *)(uintptr_t)ra, (void *)(uintptr_t)(ra + rs),
                         (unsigned long long)rs, kr == KERN_SUCCESS ? info.protection : 0,
                         kr == KERN_SUCCESS ? info.max_protection : 0 );
            }
        }
    }
    /* MacRunner HK memcpy fault: reconcile + guest stack walk for the Unity/Mono
     * CRT stream-buffer range 0x320fxxxxx. */
    {
        ULONG_PTR fa = rec.ExceptionInformation[1];
        if (fa >= 0x320f00000ULL && fa < 0x321100000ULL)
        {
            static int hk_memcpy_n;
            if (hk_memcpy_n++ < 32)
                macrunner_hb_trace_hk_memcpy_fault( "segv", PC_sig(context), fa );
        }
    }
#endif
    /* MacRunner diag: a NULL-target execute fault (guest called a NULL function
     * pointer) is handled by hb_jit_runtime_handle_signal_fault below (it raises
     * the synthetic guest c0000005, so route_x64_callback_fault never sees it).
     * Pin the guest call site + TEB state from the registered x64 ctx FIRST. */
    if (rec.ExceptionInformation[0] == EXCEPTION_EXECUTE_FAULT &&
        (rec.ExceptionInformation[1] < 0x1000 || PC_sig(context) == 0))
    {
        static int nullcall_segv_n;
        HB_PROBE_LOOKED(&pr_nullcall_segv);
        if (macrunner_hb_trace_nullcall_enabled() && nullcall_segv_n++ < 16)
        {
            HB_PROBE_HIT(&pr_nullcall_segv);
            macrunner_hb_trace_nullcall_site( "segv-exec0", PC_sig(context),
                                              rec.ExceptionInformation[1] );
        }
    }

    if (hb_jit_runtime_handle_signal_fault( PC_sig(context), rec.ExceptionInformation[1], signal, context ) ||
        hb_jit_runtime_handle_signal_fault( LR_sig(context), rec.ExceptionInformation[1], signal, context ))
        return;

    /* MacRunner Phase F: on macOS, executing x86_64 guest bytes on the
     * ARM64 CPU is not guaranteed to surface as EXCEPTION_EXECUTE_FAULT.
     * Some byte patterns decode as valid ARM64/SVE memory operations and
     * arrive as EXC_BAD_ACCESS while PC is still in the x64 PE .text.  Route
     * those guest-code traps through HyperBridge before normal ARM64 PE
     * fault handling, but keep the guard strictly scoped to known x64 guest
     * code pages. */
    if (macrunner_hb_route_x64_callback_fault( context, rec.ExceptionInformation[1], "segv-guest" )) return;

#if defined(__APPLE__)
    /* arm64 macOS xnu does not preserve x18 across thread context
     * switches AND wipes x18 on sigreturn even if we restore it in
     * sigcontext: when the scheduler preempts a Wine PE thread (or
     * delivers any signal), x18 — which Microsoft ARM64 ABI uses as
     * the TEB pointer — comes back as zero. The next TEB-relative load
     * in PE code then faults on a small immediate, e.g.
     * `ldr x*, [x18, #0x60]`. We MUST NOT dispatch this as a Windows
     * exception: doing so logs through the PE-side debug subsystem,
     * which itself derefs x18, recursively faults, and leaves
     * vectored_handlers_section orphaned — deadlocking the process.
     *
     * Self-heal patterns:
     *  - direct TEB deref: retry through __wine_pe_x18_resume_thunk so
     *    x18 is restored in user mode after sigreturn;
     *  - indirect TEB pointer: x18 was zero for an earlier non-faulting
     *    `add xN, x18, #off`, producing a small bogus pointer. Fix the
     *    current base register to TEB+off and retry this instruction.
     *    The faulting instruction may add its own immediate offset, e.g.
     *    `str xzr, [xN, #0x1480]`, so validate base+mem_offset rather
     *    than only matching the final fault address. */
    if (rec.ExceptionInformation[0] != EXCEPTION_EXECUTE_FAULT)
    {
        ULONG_PTR fault_addr = (ULONG_PTR)siginfo->si_addr;
        ULONG_PTR pc = PC_sig(context);
        DWORD insn;
        int base_reg;
        ULONG_PTR mem_offset;

        /* Only the Apple x18/TEB-loss patterns fault on low TEB-relative
         * addresses.  Avoid querying the virtual map before this cheap scope
         * check: SIGSEGV can arrive while virtual.c already owns virtual_mutex
         * (for example during delete_view()), and virtual_is_valid_code_address()
         * would deadlock inside the signal handler.  The CPU has already
         * fetched the current instruction for non-execute faults, so reading
         * the instruction word directly is the signal-safe path here. */
        /* ★ 2026-08-30: порог сторожа поднимается вместе с порогами ветвей. Иначе
         * производная база (замер: 0xaa64) отсекается ЗДЕСЬ и до ветвей не доходит —
         * на этом моя же правка 30.08 не сработала при верных условиях внутри. */
        if (!teb || fault_addr >= (macrunner_heal_any_small_base() ? 0x40000u : 0x4000u) ||
            pc < 0x10000)
        {
            /* ★ ПРИЧИНА ПРОПУСКА ЛЕЧЕНИЯ x18 (гейт MACRUNNER_HB_X18_SKIP_PROBE=1, умолчание 0).
             *
             * Пропуск здесь означает, что отказ по нулевому x18 НЕ будет исправлен, команда
             * исполнится снова — и получится вечный цикл. Ровно это наблюдается у установщика.
             * Прибор называет, какое из ТРЁХ условий сработало: без него они неразличимы. */
            static unsigned long long x18skip_n;
            static int x18skip_probe = -1;

            if (x18skip_probe < 0)
            {
                const char *v = macrunner_hb_getenv( "MACRUNNER_HB_X18_SKIP_PROBE" );
                x18skip_probe = (v && v[0] && v[0] != '0');
            }
            if (x18skip_probe && ++x18skip_n <= 16)
                macrunner_signal_writef(
                    "macrunner-hb-x18-skip: n=%llu причина=%s teb=%p fault=%p pc=%p\n",
                    (unsigned long long)x18skip_n,
                    !teb ? "нет-TEB" : (fault_addr >= 0x4000 ? "адрес>=0x4000" : "pc<0x10000"),
                    (void *)teb, (void *)(ULONG_PTR)fault_addr, (void *)(ULONG_PTR)pc );
            goto skip_apple_x18_heal;
        }
        insn = *(DWORD *)pc;
        base_reg = get_memory_access_base_reg( insn );
        mem_offset = get_memory_access_offset( insn );

        /* TEB-relative offsets used by PE-side code fall in 0..teb_size
         * (~14 KB) and 0x3000..0x3a00 (TLS/GdiTebBatch).  Decode the
         * actual faulting memory instruction so unrelated low/null faults
         * are still dispatched as real Windows exceptions. */
        if (REGn_sig(18, context) == 0 && teb && fault_addr < 0x4000 && base_reg == 18)
        {
            struct ntdll_thread_data *thread_data =
                (struct ntdll_thread_data *)&teb->GdiTebBatch;
            if (emulate_apple_x18_teb_access( context, teb, insn, fault_addr )) return;
            if (apple_x18_restart_owned_thunk( context, teb )) return;
            /* Stash the registers we are about to clobber in the
             * trampoline; the asm thunk reloads them from these slots
             * before branching to the retry PC. */
            thread_data->apple_x18_save_x10 = REGn_sig(10, context);
            thread_data->apple_x18_save_x16 = REGn_sig(16, context);
            thread_data->apple_x18_save_pc  = PC_sig(context);
            trace_apple_x18_heal( "direct", context, fault_addr, base_reg,
                                  REGn_sig(base_reg, context), mem_offset );
            REGn_sig(10, context) = (ULONG_PTR)teb;
            REGn_sig(18, context) = (ULONG_PTR)teb;
            PC_sig(context)       = (ULONG_PTR)__wine_pe_x18_resume_thunk;
            macrunner_x18_resume_note( &macrunner_x18.heal_thunk );
            return;
        }
        /* ★★★ ПАКЕТ-3, семья T3 — ГРАНИЦА МЕЖДУ ДОГОВОРОМ ПЛАТФОРМЫ И НАШЕЙ ДОГАДКОЙ.
         *
         * ВЫШЕ этой черты остаётся ветвь `direct`: базовый регистр БУКВАЛЬНО x18, и он ноль.
         * Происхождение там не угадано, а прочитано из команды; сам отказ — договор платформы
         * (xnu стирает x18 на sigreturn), и он бьёт по FEX ровно так же. ШАГ-4 доказал это
         * прямо: повтор нужен был для `ldr x17,[x18,#0x1788]` из ПРОЛОГА FEX. Гасить эту
         * ветвь — значит вернуть стену x64. Аудит требует того же: «точный PE ABI repair
         * отделить», «точный x18/redzone/Reset сохранить» (:28, :90, :123).
         *
         * НИЖЕ этой черты граница проходит НЕ по именам ветвей, а по тому, ДОКАЗАНО ЛИ
         * происхождение адреса. Это уточнение сделано ЗАМЕРОМ, а не рассуждением, и первая
         * редакция правки была неверна — пишу, потому что она стоила прогона:
         *
         *   ИЗМЕРЕНО  рука fex, образец x64smoke, гейт стоял НА ВСЕЙ группе -> exit=124.
         *             Отказ: pc=0x6ffffef9eb34 в НАШЕМ модуле 0x6ffffef30000,
         *             слово f90a411f = `str xzr,[x8,#0x520]`, x8=0x28, x18=0x0.
         *   ВЫВОД     это не гостевой низкий указатель, а ПЛАТФОРМЕННАЯ потеря x18 внутри
         *             нашего же ARM64 PE-кода: `mov x8,x18` исполнился, когда x18 уже был
         *             стёрт. FEX страдает от неё ровно так же, лечение обязано остаться.
         *
         * Отсюда рабочее правило: гасится та ветвь, чьё условие — ТОЛЬКО ЧИСЛОВОЕ ОКНО;
         * остаётся та, где происхождение прочитано из команд или доказано нулевым x18.
         *
         *   copied + memory_access_base_copied_from_x18   ОСТАЁТСЯ: выше по коду НАЙДЕН
         *                                                 `mov база,x18` — это факт, не догадка
         *   copied + послабление any_small_base           ГАСИТСЯ: «любая малая база» без поиска
         *   wow-teb-derived                               ОСТАЁТСЯ: найден `ldr база,[x18,#off]`
         *   tls-indexed                                   ОСТАЁТСЯ: x18==0 плюс узкое окно TLS
         *   derived                                       ГАСИТСЯ: условие — ЧИСТЫЙ ДИАПАЗОН
         *                                                 0x1000..0x3fff, ровно «низкий адрес
         *                                                 без доказательства» из аудита (:28)
         *
         * Тихий отказ, если не погасить оставшееся: НАСТОЯЩЕЕ нарушение доступа по низкому
         * адресу поглощается, гость его не видит, а мы вдобавок пишем по TEB. Поэтому в
         * приёмке стоит образец «низкий указатель + канарейка TEB»: канарейка обязана уцелеть.
         *
         * Проверка гейта стоит ПОСЛЕДНЕЙ в каждом условии — тогда счётчик считает ровно те
         * случаи, где ветвь СРАБОТАЛА БЫ, а не все отказы, дошедшие до этого места. */

        /* ★★★ 2026-08-30, лейн УСТАНОВЩИКИ — УСТАРЕВШАЯ КОПИЯ x18 ЛЕЧИТСЯ И ПРИ ЖИВОМ x18.
         *
         * Требование `x18 == 0` здесь было лишним и стоило нам всей оконной i386-работы.
         * Замер: `macrunner-hb-x18-noheal: x18=0x3001f0000 base_reg=8 base_val=0x0
         * offset=0x1488 fault=0x1488 pc=Wow64KiUserCallbackDispatcher+0x80`.
         * x18 к моменту отказа УЖЕ восстановлен, а в x8 лежит нулевая копия, снятая
         * раньше (`mov x8,x18` за 20 команд до). Условие не выполняется, лечение не
         * применяется, PC не сдвигается — команда отказывает снова. Отсюда 1,57 млн
         * отказов в секунду и полное ядро у ЛЮБОЙ оконной i386-программы.
         *
         * Остальные условия уже доказывают случай без всякого x18: база равна нулю,
         * `база + смещение == адрес отказа`, и в 32 командах выше стоит `mov база, x18`.
         * Подстановка та же самая — `teb + база`, при нулевой базе это ровно `teb`.
         * Гейт `MACRUNNER_HB_X18_HEAL_STALE_COPY=1`, умолчание 0: включать замером. */
        {
            static int heal_stale_copy = -1;
            if (heal_stale_copy < 0)
            {
                /* ★★★ 30.08: УМОЛЧАНИЕ ПЕРЕВЕДЕНО В 1 (координатор, пункт 4 входящего).
                 * Правка под выключенным гейтом не работает вообще: `grep` по scripts/*.sh
                 * давал ноль включений. Замеры: установщик Diablo — гостевых системных
                 * вызовов 557 -> 99 356; i386 notepad — 414 -> 438 (нейтрально), код
                 * выхода не меняется. Узор проверяемый: `mov база, x18` в 32 командах,
                 * `база + смещение == адрес отказа`, база < 0x4000.
                 * Выключить: MACRUNNER_HB_X18_HEAL_STALE_COPY=0. */
                const char *v = macrunner_hb_getenv( "MACRUNNER_HB_X18_HEAL_STALE_COPY" );
                heal_stale_copy = v && v[0] ? (v[0] != '0') : 1;
            }
            /* Пороги 0x4000 держались на «смещения внутри TEB». Производная база
             * (`add x26, x8, x9`) даёт значение ВНЕ этого окна — замер дал 0xaa64.
             * Инвариант `база + смещение == адрес отказа` случай и так пришпиливает,
             * поэтому при включённом гейте окно расширено до 0x40000. */
            if ((REGn_sig(18, context) == 0 || heal_stale_copy) && teb &&
                fault_addr < (heal_stale_copy ? 0x40000u : 0x4000u) &&
                base_reg >= 0 && base_reg < 31 &&
                REGn_sig(base_reg, context) < (heal_stale_copy ? 0x40000u : 0x4000u) &&
                REGn_sig(base_reg, context) + mem_offset == fault_addr &&
                (memory_access_base_copied_from_x18( (DWORD *)PC_sig(context), base_reg ) ||
                 /* ПАКЕТ-3, T3: послабление «любая малая база» доказательства НЕ имеет —
                  * гасим его при не-HB владельце, оставляя найденный `mov база,x18` выше. */
                 (macrunner_heal_any_small_base() &&
                  !macrunner_paket3_mute( MACRUNNER_P3_T3_TEB_HEAL ))))
        {
            ULONG_PTR base_addr = REGn_sig(base_reg, context);
            trace_apple_x18_heal( "copied", context, fault_addr, base_reg, base_addr, mem_offset );
            REGn_sig(base_reg, context) = (ULONG_PTR)teb + base_addr;
            setup_x18_resume_from_sigcontext( context );
            return;
        }
        }
        if (REGn_sig(18, context) == 0 && teb && get_wow_teb( teb ) &&
            fault_addr < 0x400 && base_reg >= 0 && base_reg < 31 &&
            !REGn_sig(base_reg, context) && mem_offset == fault_addr &&
            memory_access_base_loaded_wow_teb_from_x18( (DWORD *)PC_sig(context), base_reg ))
        {
            trace_apple_x18_heal( "wow-teb-derived", context, fault_addr,
                                  base_reg, REGn_sig(base_reg, context), mem_offset );
            REGn_sig(base_reg, context) = (ULONG_PTR)get_wow_teb( teb );
            setup_x18_resume_from_sigcontext( context );
            return;
        }
        if (teb && fault_addr < 0x4000 && base_reg >= 0 && base_reg < 31 &&
            REGn_sig(base_reg, context) >= 0x1000 && REGn_sig(base_reg, context) < 0x4000 &&
            (REGn_sig(base_reg, context) + mem_offset == fault_addr ||
             (fault_addr >= REGn_sig(base_reg, context) &&
              fault_addr - REGn_sig(base_reg, context) < 0x1000)) &&
            /* ПАКЕТ-3, T3: у этой ветви условие — ЧИСТЫЙ ДИАПАЗОН 0x1000..0x3fff, ни одна
             * команда не прочитана. Это ровно «низкий адрес превращается в TEB+база без
             * доказательства происхождения» из аудита (:28). Гасим при не-HB владельце:
             * гостю обязан достаться ИСХОДНЫЙ AV, а канарейка TEB — уцелеть. */
            !macrunner_paket3_mute( MACRUNNER_P3_T3_TEB_HEAL ))
        {
            ULONG_PTR base_addr = REGn_sig(base_reg, context);
            trace_apple_x18_heal( "derived", context, fault_addr, base_reg, base_addr, mem_offset );
            REGn_sig(base_reg, context) = (ULONG_PTR)teb + base_addr;
            setup_x18_resume_from_sigcontext( context );
            return;
        }
        if (REGn_sig(18, context) == 0 && teb && fault_addr < 0x4000 &&
            base_reg >= 0 && base_reg < 31 && REGn_sig(base_reg, context) < 0x400 &&
            mem_offset >= 0x1400 && mem_offset < 0x1800 &&
            REGn_sig(base_reg, context) + mem_offset == fault_addr)
        {
            /* TlsAlloc/TlsSetValue compile as:
             *   add xN, x18, index, uxtw #3
             *   str/ldr ..., [xN, #0x1480]
             * If x18 was already cleared before the non-faulting add,
             * xN only contains index*8.  Rebase that register to the
             * real TEB and retry the faulting access. */
            ULONG_PTR base_addr = REGn_sig(base_reg, context);
            trace_apple_x18_heal( "tls-indexed", context, fault_addr, base_reg, base_addr, mem_offset );
            REGn_sig(base_reg, context) = (ULONG_PTR)teb + base_addr;
            setup_x18_resume_from_sigcontext( context );
            return;
        }

        /* ★ ПОЧЕМУ ЛЕЧЕНИЕ x18 НЕ ПРИМЕНИЛОСЬ (гейт MACRUNNER_HB_X18_NOHEAL_PROBE=1, умолчание 0).
         *
         * Сюда доходим, когда НИ ОДНА ветка лечения не подошла: успешные возвращаются
         * из обработчика. Именно этот случай даёт вечный цикл — команда не исправлена,
         * PC не сдвинут, отказ повторяется. Замер 30.08: любая ОКОННАЯ i386-программа
         * даёт 1,57 млн отказов/с ровно на `Wow64KiUserCallbackDispatcher+0x80`
         * (`wow64.dll`): `ldr x19,[x8,#0x1488]` при x8=0, где x8 — копия x18
         * (`mov x8,x18` за 20 команд до, внутри окна поиска в 32 команды).
         * Печатаем x18, базовый регистр и его значение: без них не отличить
         * «x18 уже восстановлен» от «узор копии не распознан». */
        {
            static unsigned long long noheal_n;
            static int noheal_probe = -1;

            if (noheal_probe < 0)
            {
                const char *v = macrunner_hb_getenv( "MACRUNNER_HB_X18_NOHEAL_PROBE" );
                noheal_probe = (v && v[0] && v[0] != '0');
            }
            if (noheal_probe && ++noheal_n <= 12)
                macrunner_signal_writef(
                    "macrunner-hb-x18-noheal: n=%llu x18=%p base_reg=%d base_val=%p "
                    "offset=%p fault=%p pc=%p\n",
                    (unsigned long long)noheal_n,
                    (void *)(ULONG_PTR)REGn_sig(18, context), base_reg,
                    (void *)(ULONG_PTR)((base_reg >= 0 && base_reg < 31) ? REGn_sig(base_reg, context) : 0),
                    (void *)(ULONG_PTR)mem_offset, (void *)(ULONG_PTR)fault_addr,
                    (void *)(ULONG_PTR)PC_sig(context) );
        }
    }
skip_apple_x18_heal:
#endif
    if (rec.ExceptionInformation[0] == EXCEPTION_EXECUTE_FAULT &&
        macrunner_hb_route_x64_callback_fault( context, rec.ExceptionInformation[1], "segv-exec" ))
        return;
    if (macrunner_hb_wow64_i386_execute_fault( context, &rec ))
    {
        if (macrunner_hb_trace_callback_route_enabled())
            fprintf( stderr, "macrunner-hb-wow64-i386-exec-route: pid=%d pc=%p sp=%p fault=%p lr=%p\n",
                 getpid(), (void *)(ULONG_PTR)PC_sig(context),
                 (void *)(ULONG_PTR)SP_sig(context),
                 (void *)(ULONG_PTR)rec.ExceptionInformation[1],
                 (void *)(ULONG_PTR)LR_sig(context) );
        setup_exception( context, &rec );
        return;
    }
    {
        /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1088 — ПОДТВЕРДИТЬ ГИПОТЕЗУ ЧИСЛОМ.
         *
         * Версия 1087: сторожевая страница потребляется ЗДЕСЬ — `virtual_handle_fault` снимает
         * бит и возвращает `80000001`, а мы считаем ненулевой возврат «не обработано» и идём
         * дальше, где сторожа уже нет. Прежде чем править (пятый раз за тему), печатаем
         * ВОЗВРАТ и адрес: если версия верна, в журнале появится `ret=80000001`. Печать
         * безусловная, первые 8 раз. */
#if defined(__APPLE__) && defined(__aarch64__)
        /* Лейн КЛИН-2 08.09.2026: PC отказа — в virtual_handle_fault его взять неоткуда. */
        macrunner_fault_pc = (void *)(ULONG_PTR)PC_sig(context);
        /* Лейн СТЕНА64 08.09.2026: снимок x0..x30 и sp — база команды записи неизвестна
         * заранее, её номер лежит в битах [9:5] самой команды (см. virtual.c). */
        {
            int _mr_i;
            for (_mr_i = 0; _mr_i < 31; _mr_i++)
                macrunner_fault_x[_mr_i] = (unsigned long long)REGn_sig(_mr_i, context);
            macrunner_fault_x[31] = (unsigned long long)SP_sig(context);
            macrunner_fault_x_valid = 1;
        }
#endif
        NTSTATUS _vhf = virtual_handle_fault( &rec,
#if defined(__APPLE__)
                                              virtual_stack
#else
                                              (void *)SP_sig(context)
#endif
            );
        macrunner_m0_vhf( (unsigned)_vhf, 1 );
        {
            static unsigned _vhf_n;
            unsigned n = ++_vhf_n;
            if (n <= 8 || _vhf == STATUS_GUARD_PAGE_VIOLATION)
            {
                static unsigned _g_n;
                if (_vhf != STATUS_GUARD_PAGE_VIOLATION || ++_g_n <= 8)
                {
                    /* ★ 30.08, лейн УСТАНОВЩИКИ — БАЗА МОДУЛЯ РЯДОМ С PC.
                     * Без неё символизация отказа невозможна: базы PE меняются от прогона
                     * к прогону, а в журнале их нет. Итерация 38 потрачена на отзыв ложной
                     * символизации — предположенная база дала команду `mov w24, wzr`,
                     * которая отказать не может. Берём готовую `..._no_lock` (безопасна
                     * в обработчике, уже применяется в этом файле). */
                    {
                        void *_mod = macrunner_hb_pe_module_from_pc_no_lock( (void *)(ULONG_PTR)PC_sig(context) );

                        /* итерация 81 (лейн МЕЛКИЕ): без ПОЛНОГО списка загрузчика поле
                         * `модуль=` не с чем сверить — карта `+loaddll` неполна (замер 80).
                         * Печатаем список один раз на процесс, прямо здесь: к моменту
                         * первого отказа он заполнен, в отличие от старта процесса. */
                        macrunner_hb_dump_ldr_modules_once();

                    /* ★★★★★ ИТЕРАЦИЯ 84, лейн МЕЛКИЕ — ПРАВА И ТЕГ ОБЛАСТИ ОТКАЗА.
                     *
                     * Два готовых зонда для этого есть, и оба структурно не подходят
                     * (проверено, а не предположено):
                     *   `macrunner-diag-faultvm` — за гейтом И ограничен окном
                     *     0x87ef0000000..0x87f00000000; наш адрес 0x1121e1210 вне него;
                     *   `macrunner-hb-bus-sample` — внутри блока счётчиков, который в
                     *     ОБОИХ прогонах итерации 83 не напечатал ни строки, плюс потолок 6.
                     * Поэтому запрос области ставится рядом с `macrunner-vhf-probe` —
                     * единственным прибором, чья печать по этому отказу доказана.
                     * `tag` называет ВЛАДЕЛЬЦА области, то есть кто её отвёл; prot/max
                     * отделяют «прав не выдали» от «это вообще не наша память». */
                    {
                        static int обл_n;

                        if (обл_n++ < 12)
                        {
                            mach_vm_address_t o_a = (mach_vm_address_t)rec.ExceptionInformation[1];
                            mach_vm_size_t o_s = 0;
                            vm_region_submap_info_data_64_t o_i;
                            mach_msg_type_number_t o_c = VM_REGION_SUBMAP_INFO_COUNT_64;
                            natural_t o_d = 0;
                            kern_return_t o_kr = mach_vm_region_recurse( mach_task_self(), &o_a, &o_s,
                                                                        &o_d, (vm_region_recurse_info_t)&o_i,
                                                                        &o_c );
                            macrunner_sig_printf( "macrunner-vhf-обл: pid=%d addr=%p область=%#llx+%#llx "
                                                  "prot=%d max=%d tag=%u shared=%d kr=%d site=%s\n",
                                                  (int)getpid(), (void *)(ULONG_PTR)rec.ExceptionInformation[1],
                                                  (unsigned long long)o_a, (unsigned long long)o_s,
                                                  o_kr ? -1 : o_i.protection, o_kr ? -1 : o_i.max_protection,
                                                  o_kr ? 0u : (unsigned)o_i.user_tag,
                                                  o_kr ? -1 : (int)o_i.share_mode, o_kr, "segv" );
                        }
                    }
                        macrunner_sig_printf( "macrunner-vhf-probe: n=%u pid=%d ret=%08x addr=%p pc=%p "
                                         "host_base=%p модуль=%p смещение=%p wxrежим=%d site=segv\n",
                                 n, (int)getpid(), (unsigned)_vhf,
                                 (void *)(ULONG_PTR)rec.ExceptionInformation[1],
                                 (void *)(ULONG_PTR)PC_sig(context), macrunner_hb_host_base,
                                 _mod,
                                 _mod ? (void *)(ULONG_PTR)(PC_sig(context) - (ULONG_PTR)_mod) : NULL, hb_jit_wx_mode_get() );
                    }
                    /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1124 — СОХРАНЯЕМЫЕ РЕГИСТРЫ
                     * НА СТОРОНЕ UNIX.
                     *
                     * Отказ 1122 — `ldrb w9,[x21,x9]`: x9=0x57 виден в печати PE-стороны, а x21
                     * там не печатается, и отличить «таблица пуста изначально» от «регистр
                     * испорчен по дороге» нечем. Печать PE-стороны править не стал: развёрнутый
                     * `ntdll.dll` (6 946 304 Б) собран НЕ тем путём, что даёт здешняя сборка
                     * (4 194 304 Б), и подмена рабочего носителя ради диагностики — ровно то,
                     * что запрещено главным правилом проекта. Печатаем из сигнального
                     * обработчика: тот же отказ, тот же контекст, свой модуль. */
                    /* MacRunner 2026-08-17, лейн ЛЕСТНИЦА, итерация 1392 — ДОБАВЛЕН АДРЕС
                     * ВОЗВРАТА (x30) И КАДР (x29).
                     *
                     * Без них вызывающего приходилось угадывать по соседним регистрам, и это
                     * ДВАЖДЫ подряд дало неверный ответ: 1389 назвал испорченным канал (на деле
                     * строку формата), 1390 назвал вызывающим `RtlAddAccessDeniedAce` — а
                     * арифметика 1391 показала, что на том месте нужное число получиться не
                     * могло. Оба раза догадка строилась на `x20`, который здесь просто хранит
                     * старое значение. */
                    /* ★ MacRunner 2026-08-31 — X16/X17 ОБЯЗАТЕЛЬНЫ ДЛЯ ОТКАЗОВ ВЫБОРКИ.
                     *
                     * Прибор печатал только x19-x30 (сохраняемые вызываемым). Для отказа
                     * ВЫБОРКИ ИНСТРУКЦИИ этого мало: на ARM64 переход через переходник
                     * идёт `ldr x16,[...]; br x16` — цель лежит в X16 (или X17 у длинного
                     * переходника), и без них нельзя отличить переход по переходнику от
                     * порчи адреса возврата. Именно на этом застряла цепочка
                     * combase!start_rpcss -> NdrClientCall2 -> ndr_client_call -> страница rw:
                     * косвенных переходов внутри `ndr_client_call` НЕТ (проверено
                     * дизассемблером, 242 инструкции, ни одного blr/br), значит переход
                     * делает переходник — а назвать его может только X16/X17.
                     *
                     * X8 добавлен потому, что через него идёт косвенный вызов у clang
                     * (регистр непрямого результата и частый держатель цели). */
                    if (macrunner_hb_prot_hit( context, (ULONG_PTR)siginfo->si_addr )) return;
                    macrunner_hb_print_fault_regs( context, "segv" );
                    macrunner_shag4_probe( context, "segv" );
                    macrunner_hb_dump_vhf_site( context );
                }
            }
        }
        if (!_vhf) return;
    }
#if defined(__APPLE__)
    if (low_stack_fault)
    {
        if (macrunner_hb_trace_low_stack_fault_enabled())
            macrunner_signal_writef( "macrunner-hb-low-stack-as-overflow: pid=%d "
                                     "pc=%p sp=%p fault=%p info0=%Ix "
                                     "teb_stack=%p-%p dealloc=%p\n",
                                     getpid(), (void *)(ULONG_PTR)PC_sig(context),
                                     (void *)(ULONG_PTR)SP_sig(context),
                                     (void *)(ULONG_PTR)rec.ExceptionInformation[1],
                                     (ULONG_PTR)rec.ExceptionInformation[0],
                                     teb ? teb->Tib.StackLimit : NULL,
                                     teb ? teb->Tib.StackBase : NULL,
                                     teb ? teb->DeallocationStack : NULL );
        rec.ExceptionCode = STATUS_STACK_OVERFLOW;
        rec.NumberParameters = 0;
    }
    else
#endif
    if (handle_syscall_fault( context, &rec )) return;
    macrunner_hb_trace_native_fault( "segv", context, &rec, esr );
#if defined(__APPLE__)
    macrunner_hb_trace_signal_exception_delivery( "segv", context, &rec,
                                                  low_stack_fault, low_stack_fault,
                                                  virtual_stack );
#endif
    setup_exception( context, &rec );
}


/* MacRunner 2026-09-08, лейн ЧКСТК — адрес страницы из ADRP.
 * Смещение читается ИЗ КОМАНДЫ, знак восстанавливается по биту 20 поля imm21. */
static ULONG_PTR macrunner_chkstk_adrp( ULONG_PTR pc, ULONG w )
{
    LONG imm = (LONG)((((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3));

    if (imm & 0x100000) imm -= 0x200000;
    return (pc & ~(ULONG_PTR)0xfff) + (ULONG_PTR)((LONG_PTR)imm << 12);
}

/**********************************************************************
 *		ill_handler
 *
 * Handler for SIGILL.
 */
static void ill_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    struct mr_x18_resume_scope mr_x18_scope
        __attribute__((cleanup(mr_x18_resume_leave))) =
        { (ucontext_t *)sigcontext, (ULONG_PTR)PC_sig((ucontext_t *)sigcontext), mr_x18_resume_always() };
    struct macrunner_hb_callback_loop_signal_scope callback_loop_scope
        __attribute__((cleanup(macrunner_hb_callback_loop_signal_leave))) =
        macrunner_hb_callback_loop_signal_enter( "ill", signal, sigcontext );
    EXCEPTION_RECORD rec = { EXCEPTION_ILLEGAL_INSTRUCTION };
    ucontext_t *context = sigcontext;
    static int macrunner_hb_ill_trace_count;
    BOOL jit_sigill_ownership = macrunner_hb_jit_sigill_ownership_enabled();
    BOOL instr_valid;
    ULONG instr = 0;

    instr_valid = macrunner_signal_read_u32_aligned( PC_sig( context ), &instr );

    /* ★★★ MacRunner 2026-09-08, лейн ЧЕТЫРЕ — КТО ПЕРЕШЁЛ НА БАЗУ МОДУЛЯ.
     *
     * Измерено 5 прогонов из 5 на notepad++ x86-64: c000001d по адресу, равному БАЗЕ
     * gdi32.dll, первые четыре слова по адресу = 4d5a7800 00000001 00000004 00000000,
     * то есть заголовок DOS самого модуля. Гость исполняет «MZ» как команду ARM64.
     * Дальше переводчик SEH самого Notepad++ превращает это в бросок C++ (e06d7363,
     * магия 19930520), и программа показывает МОДАЛЬНОЕ окно «Unlisted exception»
     * (класс #32770, 330x298) — после чего не делает больше НИЧЕГО. Отсюда и
     * недостающие модули: imagehlp/rsaenh/msimg32 у эталона грузятся ПОСЛЕ этого места.
     *
     * Кто именно перешёл — не измерено ничем: `macrunner-hb-illegal-host-who`
     * (exception.c) стоит под `#if defined(__aarch64__) && !defined(__arm64ec__)`, а
     * PE-половина ntdll собирается как ARM64EC, поэтому та печать в двоичном
     * ОТСУТСТВУЕТ (проверено: строк illegal-host-who в журнале 0 при 1 отказе).
     *
     * Зонд БЕЗУСЛОВНЫЙ (без гейта), печать через `macrunner_signal_writef` — она
     * безопасна в обработчике сигнала. Потолок раздельный, чтобы редкое событие не
     * съели частые: `base_n` считает ТОЛЬКО попадания на базу модуля (rva==0), их
     * штатно не бывает вовсе; `first_n` — первые четыре любых SIGILL, чтобы прибор
     * доказывал свою работу и на прогоне, где явления нет. Стоит ДО всех обработчиков
     * ниже, иначе перехват (hexpthk/JIT) унесёт событие молча. */
    {
        static int mr_ill_base_n, mr_ill_first_n, mr_ill_vsego;
        struct macrunner_hb_signal_module_info pc_i, lr_i, x16_i, x17_i;
        ULONG_PTR mr_pc = PC_sig( context ), mr_lr = LR_sig( context );
        ULONG_PTR mr_x16 = REGn_sig( 16, context ), mr_x17 = REGn_sig( 17, context );
        BOOL f_pc = macrunner_hb_signal_find_loader_module( mr_pc, &pc_i );
        BOOL f_lr = macrunner_hb_signal_find_loader_module( mr_lr, &lr_i );
        BOOL f16 = macrunner_hb_signal_find_loader_module( mr_x16, &x16_i );
        BOOL f17 = macrunner_hb_signal_find_loader_module( mr_x17, &x17_i );
        BOOL na_baze = f_pc && pc_i.rva == 0;
        /* Команда ПЕРЕД адресом возврата — это и есть сам переход. `blr xN` = 0xd63f0000
         * с номером регистра в битах [9:5]: он назовёт, через какой регистр ушли, а
         * значит и механизм (импортный переходник, EC-диспетчер, вычисленный указатель).
         * Номер регистра ЧИТАЕТСЯ из команды, а не предполагается. */
        ULONG mr_prev = 0;
        BOOL mr_prev_ok = (mr_lr > 4) && macrunner_signal_read_u32_aligned( mr_lr - 4, &mr_prev );

        mr_ill_vsego++;
        if ((na_baze && mr_ill_base_n < 8) || mr_ill_first_n < 4)
        {
            if (na_baze) mr_ill_base_n++;
            else mr_ill_first_n++;
            macrunner_signal_writef(
                "macrunner-ill-kto: n=%d vsego=%d na_baze=%d pc=%p pc_mod=%s pc_rva=0x%llx "
                "lr=%p lr_mod=%s lr_rva=0x%llx f_lr=%d "
                "x16=%p x16_mod=%s x16_rva=0x%llx f16=%d "
                "x17=%p x17_mod=%s x17_rva=0x%llx f17=%d "
                "x0=%p x1=%p x8=%p x9=%p x11=%p sp=%p instr=%#lx instr_ok=%d "
                "pered_lr=%#lx pered_ok=%d perekhod_reg=%d\n",
                na_baze ? mr_ill_base_n : mr_ill_first_n, mr_ill_vsego, (int)na_baze,
                (void *)mr_pc, f_pc ? pc_i.name : "-", (unsigned long long)(f_pc ? pc_i.rva : 0),
                (void *)mr_lr, f_lr ? lr_i.name : "-", (unsigned long long)(f_lr ? lr_i.rva : 0),
                (int)f_lr,
                (void *)mr_x16, f16 ? x16_i.name : "-", (unsigned long long)(f16 ? x16_i.rva : 0),
                (int)f16,
                (void *)mr_x17, f17 ? x17_i.name : "-", (unsigned long long)(f17 ? x17_i.rva : 0),
                (int)f17,
                (void *)(ULONG_PTR)REGn_sig( 0, context ),
                (void *)(ULONG_PTR)REGn_sig( 1, context ),
                (void *)(ULONG_PTR)REGn_sig( 8, context ),
                (void *)(ULONG_PTR)REGn_sig( 9, context ),
                (void *)(ULONG_PTR)REGn_sig( 11, context ),
                (void *)(ULONG_PTR)SP_sig( context ), (unsigned long)instr, (int)instr_valid,
                (unsigned long)mr_prev, (int)mr_prev_ok,
                (mr_prev_ok && (mr_prev & 0xfffffc1f) == 0xd63f0000) ?
                    (int)((mr_prev >> 5) & 0x1f) : -1 );

            /* ★★★ MacRunner 2026-09-08, лейн ЧКСТК — ЧТО ЛЕЖИТ В СЛОТЕ IAT.
             *
             * Зонд ЧЕТЫРЕ назвал регистр (x11 = база модуля), но НЕ сказал, откуда
             * туда попала база. Причин ровно две, и наблюдаемое у них одинаковое:
             *   (а) слот IAT не разрешён -> x11 приходит пустым;
             *   (б) слот разрешён, но EC-диспетчер подставил ПУСТОЙ выходной
             *       переходник (x10 = база + 0), и переход ушёл на базу.
             * Лечение у (а) и (б) РАЗНОЕ, поэтому слот надо прочитать, а не вывести.
             *
             * Команда перед адресом возврата — `bl` в переходник `#имя`; сверено
             * статически на двух модулях: shell32 lr_rva=0xda948 -> 0xfaf90,
             * gdi32 lr_rva=0x6ec34 -> 0x90a84. Раскладка переходника ARM64EC у LLD
             * постоянна, семь слов:
             *     +0  adrp x16, вспомогательный_IAT
             *     +4  ldr  x16, [x16, #смещение]
             *     +8  br   x16                        <- быстрый путь
             *     +12 adrp x11, настоящий_IAT
             *     +16 ldr  x11, [x11, #смещение]
             *     +20 adrp x10, выходной_переходник
             *     +24 add  x10, x10, #смещение
             * Адреса берутся ИЗ КОМАНД, а не предполагаются; узор проверяется, и при
             * несовпадении печатается отказ узнавания — иначе прибор молча соврал бы.
             * Чтение только через macrunner_signal_read_u32_aligned (безопасно в
             * обработчике сигнала). Потолок общий с блоком выше. */
            if (mr_prev_ok && (mr_prev & 0xfc000000) == 0x94000000)
            {
                LONG mr_off26 = (LONG)(mr_prev & 0x3ffffff);
                ULONG_PTR mr_thunk, mr_baza = mr_pc - (f_pc ? (ULONG_PTR)pc_i.rva : 0);
                ULONG w[7];
                int wi, w_ok = 1;

                if (mr_off26 & 0x2000000) mr_off26 -= 0x4000000;
                mr_thunk = (mr_lr - 4) + (ULONG_PTR)((LONG_PTR)mr_off26 * 4);
                for (wi = 0; wi < 7; wi++)
                    if (!macrunner_signal_read_u32_aligned( mr_thunk + wi * 4, &w[wi] )) w_ok = 0;

                if (w_ok &&
                    (w[0] & 0x9f00001f) == 0x90000010 && (w[1] & 0xffc003ff) == 0xf9400210 &&
                    (w[3] & 0x9f00001f) == 0x9000000b && (w[4] & 0xffc003ff) == 0xf940016b)
                {
                    ULONG_PTR aux_a = macrunner_chkstk_adrp( mr_thunk, w[0] ) +
                                      (ULONG_PTR)(((w[1] >> 10) & 0xfff) * 8);
                    ULONG_PTR iat_a = macrunner_chkstk_adrp( mr_thunk + 12, w[3] ) +
                                      (ULONG_PTR)(((w[4] >> 10) & 0xfff) * 8);
                    ULONG_PTR exit_a = 0;
                    ULONG alo = 0, ahi = 0, ilo = 0, ihi = 0;
                    int a_ok, i_ok;

                    if ((w[5] & 0x9f00001f) == 0x9000000a && (w[6] & 0xffc003ff) == 0x9100014a)
                        exit_a = macrunner_chkstk_adrp( mr_thunk + 20, w[5] ) +
                                 (ULONG_PTR)((w[6] >> 10) & 0xfff);
                    a_ok = macrunner_signal_read_u32_aligned( aux_a, &alo ) &&
                           macrunner_signal_read_u32_aligned( aux_a + 4, &ahi );
                    i_ok = macrunner_signal_read_u32_aligned( iat_a, &ilo ) &&
                           macrunner_signal_read_u32_aligned( iat_a + 4, &ihi );
                    macrunner_signal_writef(
                        "macrunner-chkstk-slot: mod=%s perehodnik=%p perehodnik_rva=0x%llx "
                        "aux_addr=%p aux_rva=0x%llx aux_znach=%p aux_ok=%d "
                        "iat_addr=%p iat_rva=0x%llx iat_znach=%p iat_ok=%d "
                        "vyhod=%p vyhod_rva=0x%llx baza=%p\n",
                        f_pc ? pc_i.name : "-", (void *)mr_thunk,
                        (unsigned long long)(mr_thunk - mr_baza),
                        (void *)aux_a, (unsigned long long)(aux_a - mr_baza),
                        (void *)(ULONG_PTR)(((unsigned long long)ahi << 32) | alo), (int)a_ok,
                        (void *)iat_a, (unsigned long long)(iat_a - mr_baza),
                        (void *)(ULONG_PTR)(((unsigned long long)ihi << 32) | ilo), (int)i_ok,
                        (void *)exit_a,
                        (unsigned long long)(exit_a ? exit_a - mr_baza : 0), (void *)mr_baza );
                }
                else
                    macrunner_signal_writef(
                        "macrunner-chkstk-slot: uzor NE sovpal perehodnik=%p w_ok=%d "
                        "w0=%#lx w1=%#lx w3=%#lx w4=%#lx\n",
                        (void *)mr_thunk, (int)w_ok, (unsigned long)w[0], (unsigned long)w[1],
                        (unsigned long)w[3], (unsigned long)w[4] );
            }
        }
    }

    if (macrunner_hb_trace_callback_route_enabled() && macrunner_hb_ill_trace_count++ < 16)
        fprintf( stderr, "macrunner-hb-signal-entry: kind=ill pid=%d pc=%p sp=%p instr=%#lx "
             "si_code=%d pstate=%#llx x0=%p x1=%p x16=%p x20=%p x23=%p x26=%p\n",
             getpid(), (void *)(ULONG_PTR)PC_sig(context),
             (void *)(ULONG_PTR)SP_sig(context), (unsigned long)instr, siginfo->si_code,
             (unsigned long long)PSTATE_sig(context),
             (void *)(ULONG_PTR)REGn_sig(0, context),
             (void *)(ULONG_PTR)REGn_sig(1, context),
             (void *)(ULONG_PTR)REGn_sig(16, context),
             (void *)(ULONG_PTR)REGn_sig(20, context),
             (void *)(ULONG_PTR)REGn_sig(23, context),
             (void *)(ULONG_PTR)REGn_sig(26, context) );

    /* An active HyperBridge JIT guard owns SIGILL even if generated code jumped
     * through a stale/corrupt target outside the current slab.  Claim it before
     * the ARM64X candidate/module/Mach-VM scan and carry the already-probed word
     * across siglongjmp; a non-owned signal keeps the old ARM64X path. */
    if (jit_sigill_ownership &&
        hb_jit_runtime_handle_owned_sigill( PC_sig(context), instr,
                                            instr_valid, context )) return;
    if (macrunner_hb_redirect_arm64x_hexpthk_sigill( context )) return;
    if ((!jit_sigill_ownership &&
         hb_jit_runtime_handle_signal_fault( PC_sig(context), 0, signal, context )) ||
        hb_jit_runtime_handle_signal_fault( LR_sig(context), 0, signal, context )) return;
    if (macrunner_hb_route_x64_callback_fault( context, 0, "sigill" )) return;

    if (!(PSTATE_sig( context ) & 0x10) && /* AArch64 (not WoW) */
        !(PC_sig( context ) & 3))
    {
        /* emulate mrs xN, CurrentEL */
        if ((instr & ~0x1f) == 0xd5384240) {
            ULONG reg = instr & 0x1f;
            /* ignore writes to xzr */
            if (reg != 31) REGn_sig(reg, context) = 0;
            PC_sig(context) += 4;
            return;
        }
    }

    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *		bus_handler
 *
 * Handler for SIGBUS.
 */
static void bus_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    struct mr_x18_resume_scope mr_x18_scope
        __attribute__((cleanup(mr_x18_resume_leave))) =
        { (ucontext_t *)sigcontext, (ULONG_PTR)PC_sig((ucontext_t *)sigcontext), mr_x18_resume_always() };
    struct macrunner_hb_callback_loop_signal_scope callback_loop_scope
        __attribute__((cleanup(macrunner_hb_callback_loop_signal_leave))) =
        macrunner_hb_callback_loop_signal_enter( "bus", signal, sigcontext );
    EXCEPTION_RECORD rec = { EXCEPTION_DATATYPE_MISALIGNMENT };
    ucontext_t *context = sigcontext;
    BOOL alignment_fault = FALSE;
    BOOL low_stack_fault = FALSE;
    BOOL stack_overflow_fault = FALSE;
    BOOL fault_unhandled;
    void *virtual_stack = (void *)SP_sig(context);
    TEB *teb = NtCurrentTeb();

    /* ★ ЗАПЛАТКА KUSER_SHARED_DATA — ТОТ ЖЕ вызов, что в segv_handler.
     * macOS метит отказ по неотображённому низкому адресу то как SEGV, то как BUS
     * (у нас это уже разводило обработчики: см. разбор ESR ниже, где числа стояли
     * копией в каждом). Покрыть надо оба, иначе лечение станет лотереей. */
    if (macrunner_kusd_popytka( siginfo, context )) return;

#if defined(BUS_ADRALN)
    /* MacRunner (2026-07-02): si_code==BUS_ADRALN alone is NOT reliable on this kernel --
     * observed firing for a genuine ARM64 permission fault (ESR DFSC=0xf, write to a
     * mapped-but-read-only page) with insn=`str x0,[x20]`/`strb w11,[x9]`, neither of which
     * can fault from misalignment on ARM64. Cross-check against the ESR's own DFSC field
     * (bits [5:0] of the ISS): 0x21 is the dedicated "Alignment fault" code, distinct from
     * the permission-fault range 0x0d-0x0f and the translation-fault range 0x04-0x07. Only
     * classify as a real alignment fault when BOTH agree, so a permission fault is no longer
     * mislabeled STATUS_DATATYPE_MISALIGNMENT further down (macrunner-hb-bus-fault trace
     * confirmed this exact esr=0x9200004f / insn=0xf9000280 signature). */
    /* MacRunner 04.09.2026: то же число 0x21, но теперь именем из Wine 11.14 —
     * ESR_ELx_ISS_DFSC_ALIGN_FAULT. Смысл проверки не изменился. */
    alignment_fault = (siginfo->si_code == BUS_ADRALN) &&
                       (ESR_ELx_ISS_DFSC(get_fault_esr( context )) == ESR_ELx_ISS_DFSC_ALIGN_FAULT);
#endif

    rec.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
    rec.NumberParameters = 2;
    /* MacRunner 04.09.2026: тот же разбор ESR, что и в segv_handler — см. пояснение у
     * macrunner_fault_access_kind(). Здесь это заодно снимает расхождение между двумя
     * обработчиками: копия числами стояла в каждом, и чинить пришлось бы оба. */
    rec.ExceptionInformation[0] = macrunner_fault_access_kind( get_fault_esr( context ) );
    rec.ExceptionInformation[1] = (ULONG_PTR)siginfo->si_addr;
    if (macrunner_hb_trace_bus_fault_enabled())
    {
        static int bfc = 0;
        if (bfc < 24)
        {
            unsigned int insn = 0;
            memcpy( &insn, (void *)(ULONG_PTR)PC_sig(context), 4 );
            macrunner_sig_printf( "macrunner-hb-bus-fault: #%d pc=%p fault=%p esr=0x%llx align=%u kind=%lu insn=0x%08x\n",
                     bfc, (void *)(ULONG_PTR)PC_sig(context), (void *)(ULONG_PTR)siginfo->si_addr,
                     (unsigned long long)get_fault_esr( context ), (unsigned)alignment_fault,
                     (unsigned long)rec.ExceptionInformation[0], insn );
            bfc++;
        }
    }
#if defined(__APPLE__)
    /* recover a gated direct guest-mem copy fault BEFORE any other handling/locking */
    macrunner_hb_dmem_fault_recover( (unsigned long long)(ULONG_PTR)siginfo->si_addr );
    stack_overflow_fault = macrunner_hb_is_low_stack_access_fault( context, &rec );
    virtual_stack = macrunner_hb_virtual_fault_stack( context, &rec );
#endif
    if (teb && teb->DeallocationStack &&
        (char *)SP_sig(context) < (char *)teb->Tib.StackLimit + 0x10000)
    {
        low_stack_fault = TRUE;
        if (macrunner_hb_trace_low_stack_fault_enabled())
            fprintf( stderr, "macrunner-hb-bus-low-stack: before-virtual pid=%d si_code=%d align=%u "
                 "pc=%p lr=%p fault=%p esr=0x%llx sp=%p teb_stack=%p-%p dealloc=%p "
                 "x0=%p x1=%p x2=%p x3=%p x4=%p x16=%p x18=%p x24=%p x26=%p\n",
                 getpid(), siginfo->si_code, alignment_fault,
                 (void *)(ULONG_PTR)PC_sig(context), (void *)(ULONG_PTR)LR_sig(context),
                 (void *)(ULONG_PTR)rec.ExceptionInformation[1],
                 (unsigned long long)get_fault_esr( context ), (void *)(ULONG_PTR)SP_sig(context),
                 teb->Tib.StackLimit, teb->Tib.StackBase, teb->DeallocationStack,
                 (void *)(ULONG_PTR)REGn_sig(0, context),
                 (void *)(ULONG_PTR)REGn_sig(1, context),
                 (void *)(ULONG_PTR)REGn_sig(2, context),
                 (void *)(ULONG_PTR)REGn_sig(3, context),
                 (void *)(ULONG_PTR)REGn_sig(4, context),
                 (void *)(ULONG_PTR)REGn_sig(16, context),
                 (void *)(ULONG_PTR)REGn_sig(18, context),
                 (void *)(ULONG_PTR)REGn_sig(24, context),
                 (void *)(ULONG_PTR)REGn_sig(26, context) );
#ifdef __APPLE__
        if (macrunner_hb_trace_native_faults_enabled())
        {
            macrunner_hb_trace_low_stack_symbol( "pc", PC_sig(context) );
            macrunner_hb_trace_low_stack_symbol( "lr", LR_sig(context) );
            macrunner_hb_trace_low_stack_vm_region( "fault", rec.ExceptionInformation[1] );
        }
#endif
    }

    if (macrunner_hb_trace_callback_route_enabled())
        fprintf( stderr, "macrunner-hb-signal-entry: kind=bus pid=%d pc=%p fault=%p esr=0x%llx "
             "x4=%p x16=%p x24=%p x26=%p\n",
             getpid(), (void *)(ULONG_PTR)PC_sig(context),
             (void *)(ULONG_PTR)rec.ExceptionInformation[1],
             (unsigned long long)get_fault_esr( context ),
             (void *)(ULONG_PTR)REGn_sig(4, context), (void *)(ULONG_PTR)REGn_sig(16, context),
             (void *)(ULONG_PTR)REGn_sig(24, context), (void *)(ULONG_PTR)REGn_sig(26, context) );

#if defined(__APPLE__)
    /* MacRunner fault-time diagnostic (env-gated): the x64 JIT reported a clean MEMORY_FAULT
     * reading UnityPlayer .data (host ~0x87efe45xxxx) that the load-time probe showed RW-committed.
     * Dump the ACTUAL fault-time Mach region+protection for faults landing in the x64-guest high
     * window, to pin whether the page was reprotected (prot=0) / decommitted (region gap) at runtime. */
    if (macrunner_hb_diag_faultvm_enabled())
    {
        ULONG_PTR fa = rec.ExceptionInformation[1];
        if (fa >= 0x87ef0000000ULL && fa < 0x87f00000000ULL)
        {
            static int faultvm_n;
            if (faultvm_n++ < 24)
            {
                mach_vm_address_t ra = (mach_vm_address_t)fa;
                mach_vm_size_t rs = 0;
                vm_region_basic_info_data_64_t info;
                mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
                mach_port_t obj = MACH_PORT_NULL;
                kern_return_t kr = mach_vm_region( mach_task_self(), &ra, &rs, VM_REGION_BASIC_INFO_64,
                                                   (vm_region_info_t)&info, &cnt, &obj );
                if (obj != MACH_PORT_NULL) mach_port_deallocate( mach_task_self(), obj );
                macrunner_sig_printf( "macrunner-diag-faultvm: pc=%p lr=%p fault=%p access=%lu kr=%d "
                         "region=%p end=%p size=0x%llx prot=0x%x max=0x%x\n",
                         (void *)(ULONG_PTR)PC_sig(context), (void *)(ULONG_PTR)LR_sig(context),
                         (void *)fa, (unsigned long)rec.ExceptionInformation[0], kr,
                         (void *)(uintptr_t)ra, (void *)(uintptr_t)(ra + rs),
                         (unsigned long long)rs, kr == KERN_SUCCESS ? info.protection : 0,
                         kr == KERN_SUCCESS ? info.max_protection : 0 );
            }
        }
    }
#endif
    if (hb_jit_runtime_handle_signal_fault( PC_sig(context), rec.ExceptionInformation[1], signal, context ) ||
        hb_jit_runtime_handle_signal_fault( LR_sig(context), rec.ExceptionInformation[1], signal, context ))
        return;

    /* Same Phase F rule as segv_handler: macOS can surface execution of
     * x86_64 guest bytes as SIGBUS/EXC_BAD_ACCESS when the byte pattern
     * decodes as a faulting ARM64/SVE memory instruction. */
    if (macrunner_hb_route_x64_callback_fault( context, rec.ExceptionInformation[1], "bus-guest" )) return;

#if defined(__APPLE__) && defined(__aarch64__)
    /* Лейн КЛИН-2 08.09.2026: PC отказа — см. virtual.c, ветвь MAP_JIT. */
    macrunner_fault_pc = (void *)(ULONG_PTR)PC_sig(context);
    /* Лейн СТЕНА64 08.09.2026: тот же снимок регистров и на пути bus. */
    {
        int _mr_i;
        for (_mr_i = 0; _mr_i < 31; _mr_i++)
            macrunner_fault_x[_mr_i] = (unsigned long long)REGn_sig(_mr_i, context);
        macrunner_fault_x[31] = (unsigned long long)SP_sig(context);
        macrunner_fault_x_valid = 1;
    }
#endif
#if defined(__APPLE__) && defined(__aarch64__)
    /* Permission retries cannot fix alignment. Let FEX's existing unaligned
     * handler own confirmed data aborts, without changing HB or page rights.
     * The backend identity is constructor-cached, independent of the KUSD gate. */
    if (alignment_fault && !stack_overflow_fault && macrunner_fex_kusd_backend &&
        macrunner_cpu_backend_disables_hb_semantics())
    {
        unsigned int ec = ESR_ELx_EC( get_fault_esr( context ) );
        if (ec == ESR_ELx_EC_DABT_LOW || ec == ESR_ELx_EC_DABT_CUR)
            goto deliver_bus_exception;
    }
#endif
    fault_unhandled = virtual_handle_fault( &rec, virtual_stack );
    macrunner_m0_vhf( (unsigned)fault_unhandled, 2 );
    /* Итерация 1088: тот же зонд, что и на пути segv, — на пути bus. На macOS ARM64
     * недоступная страница обычно даёт именно SIGBUS, и первый зонд молчал поэтому. */
    {
        static unsigned _vhfb_n;
        unsigned n = ++_vhfb_n;
        if (n <= 8 || fault_unhandled == STATUS_GUARD_PAGE_VIOLATION)
        {
            static unsigned _gb_n;
            if (fault_unhandled != STATUS_GUARD_PAGE_VIOLATION || ++_gb_n <= 8)
            {
                /* Итерация 1121: ПОПРАВКА В ТОТ ЖЕ ЧАС. Первая редакция добавила `pid=%d` в
                 * формат и ЗАБЫЛА добавить сам аргумент — печать поехала на одно поле, и
                 * прогон выдал `pid=-1073741819 ret=05eceb20`, то есть в pid лёг код отказа.
                 * Сломанный прибор врёт убедительно; поймано первым же прогоном. */
                /* ★ 30.08, лейн УСТАНОВЩИКИ — БАЗА МОДУЛЯ И ЗДЕСЬ ТОЖЕ.
                 * Прогон 07:17 показал, ради чего эта поправка: отказ i386 notepad
                 * приходит НЕ через segv, а через bus (`site=bus` восемь раз из восьми),
                 * и правка одного места дала бы ноль. Правило «прибор, который не
                 * доказан печатью, считается несуществующим» — ровно этот случай. */
                {
                    void *_mod = macrunner_hb_pe_module_from_pc_no_lock( (void *)(ULONG_PTR)PC_sig(context) );

                    /* итерация 81 (лейн МЕЛКИЕ) — И ЗДЕСЬ ТОЖЕ, по той же причине, что
                     * абзацем выше. Первый заход поставил дамп списка загрузчика только
                     * на площадку segv, и процесс, падавший через bus, остался БЕЗ карты:
                     * «модулей 0» вместо шести. Та же грабля, тот же файл, соседние строки. */
                    macrunner_hb_dump_ldr_modules_once();
                    /* ★★★★★ ИТЕРАЦИЯ 84, лейн МЕЛКИЕ — ПРАВА И ТЕГ ОБЛАСТИ ОТКАЗА.
                     *
                     * Два готовых зонда для этого есть, и оба структурно не подходят
                     * (проверено, а не предположено):
                     *   `macrunner-diag-faultvm` — за гейтом И ограничен окном
                     *     0x87ef0000000..0x87f00000000; наш адрес 0x1121e1210 вне него;
                     *   `macrunner-hb-bus-sample` — внутри блока счётчиков, который в
                     *     ОБОИХ прогонах итерации 83 не напечатал ни строки, плюс потолок 6.
                     * Поэтому запрос области ставится рядом с `macrunner-vhf-probe` —
                     * единственным прибором, чья печать по этому отказу доказана.
                     * `tag` называет ВЛАДЕЛЬЦА области, то есть кто её отвёл; prot/max
                     * отделяют «прав не выдали» от «это вообще не наша память». */
                    {
                        static int обл_n;

                        if (обл_n++ < 12)
                        {
                            mach_vm_address_t o_a = (mach_vm_address_t)rec.ExceptionInformation[1];
                            mach_vm_size_t o_s = 0;
                            vm_region_submap_info_data_64_t o_i;
                            mach_msg_type_number_t o_c = VM_REGION_SUBMAP_INFO_COUNT_64;
                            natural_t o_d = 0;
                            kern_return_t o_kr = mach_vm_region_recurse( mach_task_self(), &o_a, &o_s,
                                                                        &o_d, (vm_region_recurse_info_t)&o_i,
                                                                        &o_c );
                            macrunner_sig_printf( "macrunner-vhf-обл: pid=%d addr=%p область=%#llx+%#llx "
                                                  "prot=%d max=%d tag=%u shared=%d kr=%d site=%s\n",
                                                  (int)getpid(), (void *)(ULONG_PTR)rec.ExceptionInformation[1],
                                                  (unsigned long long)o_a, (unsigned long long)o_s,
                                                  o_kr ? -1 : o_i.protection, o_kr ? -1 : o_i.max_protection,
                                                  o_kr ? 0u : (unsigned)o_i.user_tag,
                                                  o_kr ? -1 : (int)o_i.share_mode, o_kr, "bus" );
                        }
                    }
                    macrunner_hb_dump_vhf_stack( context );
                    macrunner_sig_printf( "macrunner-vhf-probe: n=%u pid=%d ret=%08x addr=%p pc=%p "
                                     "host_base=%p модуль=%p смещение=%p wxrежим=%d site=bus\n",
                             n, (int)getpid(), (unsigned)fault_unhandled,
                             (void *)(ULONG_PTR)rec.ExceptionInformation[1],
                             (void *)(ULONG_PTR)PC_sig(context), macrunner_hb_host_base,
                             _mod,
                             _mod ? (void *)(ULONG_PTR)(PC_sig(context) - (ULONG_PTR)_mod) : NULL, hb_jit_wx_mode_get() );
                    if (macrunner_hb_prot_hit( context, (ULONG_PTR)siginfo->si_addr )) return;
                    macrunner_hb_print_fault_regs( context, "bus" );
                    macrunner_shag4_probe( context, "bus" );
                }
#if defined(__APPLE__)
                /* MacRunner 2026-08-27 — ФАКТИЧЕСКИЕ права хозяйской страницы отказа.
                 *
                 * Наша карта прав говорит «запись разрешена»: PAGE_EXECUTE_WRITECOPY даёт
                 * READ|WRITE, а для guest32 EXEC переводится в PROT_READ, то есть RWX даже
                 * не запрашивается.  И всё равно запись падает.  Значит расходятся НАША
                 * карта и то, что реально стоит на странице у ядра.  Без этого числа спор
                 * неразрешим: правку в помощнике JIT я уже написал по догадке, и замер дал
                 * ноль срабатываний — условие `can_write` считало запись разрешённой. */
                {
                    mach_vm_address_t vaddr = (mach_vm_address_t)rec.ExceptionInformation[1];
                    mach_vm_size_t vsize = 0;
                    vm_region_basic_info_data_64_t vinfo;
                    mach_msg_type_number_t vcount = VM_REGION_BASIC_INFO_COUNT_64;
                    mach_port_t vobject = MACH_PORT_NULL;
                    kern_return_t vkr = mach_vm_region( mach_task_self(), &vaddr, &vsize,
                                                        VM_REGION_BASIC_INFO_64,
                                                        (vm_region_info_t)&vinfo, &vcount, &vobject );
                    macrunner_sig_printf( "macrunner-vhf-probe-vm: n=%u addr=%p vm_base=%p vm_size=%llx "
                             "kr=%d prot=%#x max=%#x shared=%d reserved=%d\n",
                             n, (void *)(ULONG_PTR)rec.ExceptionInformation[1],
                             (void *)(uintptr_t)vaddr, (unsigned long long)vsize, vkr,
                             vkr == KERN_SUCCESS ? vinfo.protection : 0,
                             vkr == KERN_SUCCESS ? vinfo.max_protection : 0,
                             vkr == KERN_SUCCESS ? (int)vinfo.shared : -1,
                             vkr == KERN_SUCCESS ? (int)vinfo.reserved : -1 );
                }
#endif
            }
        }
    }
    if (low_stack_fault && macrunner_hb_trace_low_stack_fault_enabled())
        fprintf( stderr, "macrunner-hb-bus-low-stack: after-virtual pid=%d unhandled=%u code=%#lx "
             "fault=%p sp=%p vstack=%p teb_stack=%p-%p dealloc=%p\n",
             getpid(), fault_unhandled, rec.ExceptionCode,
             (void *)(ULONG_PTR)rec.ExceptionInformation[1],
             (void *)(ULONG_PTR)SP_sig(context), virtual_stack,
             teb->Tib.StackLimit, teb->Tib.StackBase, teb->DeallocationStack );
    if (!fault_unhandled)
    {
#if defined(__APPLE__)
        if (virtual_is_valid_code_address( (void *)PC_sig(context), sizeof(DWORD) ))
            setup_x18_resume_from_sigcontext( context );
#endif
        return;
    }
#if defined(__APPLE__)
    if (stack_overflow_fault)
    {
        rec.ExceptionCode = STATUS_STACK_OVERFLOW;
        rec.NumberParameters = 0;
    }
    /* MacRunner 2026-08-27 — ЧТЕНИЕ НЕ ДОЛЖНО ВЫДЕЛЯТЬ ПАМЯТЬ.
     *
     * Замер Heroes III: шесть отказов, все на ПЕРВОЙ странице за концом образа —
     * ws2_32 (конец 0x79cd0000), WSOCK32 (0x79d20000), UxTheme (0x79dc0000),
     * MSIMG32 (0x79e08000), IMM32 (0x79e94000), dwmapi (0x79ef0000). Совпадение с
     * SizeOfImage точное во всех шести случаях, и приходят они изнутри цепочки
     * NtReadVirtualMemory (номер 0x3f): гость сканирует образы и читает на страницу
     * дальше.
     *
     * Windows на это отвечает STATUS_PARTIAL_COPY и НЕ ВЫДЕЛЯЕТ НИЧЕГО. У нас же
     * обработчик молча коммитил страницу — то есть отдавал гостю память, которую тот не
     * просил, да ещё и по одному входу в ядро на каждый образ.
     *
     * Различаем по ESR: бит 0x40 — это запись. Читающий отказ по НЕВЫДЕЛЕННОЙ памяти
     * оставляем как есть, и __TRY/__EXCEPT внутри NtReadVirtualMemory честно вернёт
     * STATUS_PARTIAL_COPY. Рост стека сюда не попадает: стек растёт записью.
     *
     * Гейт MACRUNNER_HB_READ_NO_COMMIT СНЯТ 02.09.2026: правка безусловна,
     * выключенная ветка возвращала известный дефект (scripts/гейты.py). */
    else
    {
        DWORD64 macrunner_esr = get_fault_esr( context );
        BOOL macrunner_is_write = (macrunner_esr & 0x40) != 0;
        BOOL macrunner_gate = TRUE;  /* гейт MACRUNNER_HB_READ_NO_COMMIT снят 02.09.2026 */
        static unsigned int macrunner_esr_n;
        unsigned int en = ++macrunner_esr_n;

        if (en <= 8)
            macrunner_sig_printf( "macrunner-hb-fault-kind: n=%u addr=%p esr=%#llx запись=%d гейт=%d\n",
                     en, (void *)(ULONG_PTR)rec.ExceptionInformation[1],
                     (unsigned long long)macrunner_esr, macrunner_is_write, macrunner_gate );

        if (!(!macrunner_is_write && macrunner_gate) &&
            macrunner_hb_try_commit_or_upgrade_page( (unsigned long long)rec.ExceptionInformation[1] ))
            return;
    }
#endif
#if defined(__APPLE__) && defined(__aarch64__)
deliver_bus_exception:
#endif
    if (handle_syscall_fault( context, &rec )) return;
    macrunner_hb_trace_native_fault( "bus", context, &rec, get_fault_esr( context ) );

    if (alignment_fault && !stack_overflow_fault)
    {
        memset( &rec, 0, sizeof(rec) );
        rec.ExceptionCode = EXCEPTION_DATATYPE_MISALIGNMENT;
    }

#if defined(__APPLE__)
    macrunner_hb_trace_signal_exception_delivery( "bus", context, &rec,
                                                  low_stack_fault, stack_overflow_fault,
                                                  virtual_stack );
#endif
    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *		trap_handler
 *
 * Handler for SIGTRAP.
 */
static void trap_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    struct mr_x18_resume_scope mr_x18_scope
        __attribute__((cleanup(mr_x18_resume_leave))) =
        { (ucontext_t *)sigcontext, (ULONG_PTR)PC_sig((ucontext_t *)sigcontext), mr_x18_resume_always() };
    EXCEPTION_RECORD rec = { 0 };
    ucontext_t *context = sigcontext;
    CONTEXT ctx;

#ifdef __APPLE__
    /* Проверять ЦЕЛЬ, а не только режим «числом»: в гостевом режиме
     * (MACRUNNER_HB_WATCH_GUEST) адрес считается на месте взвода, и обработчик,
     * смотревший лишь на macrunner_hb_watch_addr, не признавал срабатывание своим —
     * ловушка уходила дальше и убивала процесс (прогон 4593 строки вместо 17 тыс.). */
    if (macrunner_hb_watch_cel && macrunner_hb_watch_hit( context )) return;
#endif
    rec.ExceptionAddress = (void *)PC_sig(context);
    save_context( &ctx, sigcontext );
    if (macrunner_hb_trace_callback_route_enabled())
        fprintf( stderr, "macrunner-hb-signal-entry: kind=trap pid=%d pc=%p sp=%p si_code=%d "
             "x4=%p x16=%p x24=%p x26=%p\n",
             getpid(), (void *)(ULONG_PTR)PC_sig(context),
             (void *)(ULONG_PTR)SP_sig(context), siginfo->si_code,
             (void *)(ULONG_PTR)REGn_sig(4, context),
             (void *)(ULONG_PTR)REGn_sig(16, context),
             (void *)(ULONG_PTR)REGn_sig(24, context),
             (void *)(ULONG_PTR)REGn_sig(26, context) );

    switch (siginfo->si_code)
    {
    case TRAP_TRACE:
        rec.ExceptionCode = EXCEPTION_SINGLE_STEP;
        break;
    case TRAP_BRKPT:
        /* debug exceptions do not update ESR on Linux, so we fetch the instruction directly. */
        if (!(PSTATE_sig( context ) & 0x10) && /* AArch64 (not WoW) */
            !(PC_sig( context ) & 3))
        {
            ULONG instr;
            ULONG imm;

            if (!macrunner_signal_read_u32_aligned( PC_sig( context ), &instr )) break;
            imm = (instr >> 5) & 0xffff;
            switch (imm)
            {
            case 0xf000:
                ctx.Pc += 4;  /* skip the brk instruction */
                rec.ExceptionCode = EXCEPTION_BREAKPOINT;
                rec.NumberParameters = 1;
                break;
            case 0xf001:
                rec.ExceptionCode = STATUS_ASSERTION_FAILURE;
                break;
            case 0xf003:
                rec.ExceptionCode = STATUS_STACK_BUFFER_OVERRUN;
                rec.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
                rec.NumberParameters = 1;
                rec.ExceptionInformation[0] = ctx.X[0];
                NtRaiseException( &rec, &ctx, FALSE );
                break;
            case 0xf004:
                rec.ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
                break;
            default:
                rec.ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
                break;
            }
        }
        break;
    default:
        rec.ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
        break;
    }

    setup_raise_exception( sigcontext, &rec, &ctx );
}

/**********************************************************************
 *		fpe_handler
 *
 * Handler for SIGFPE.
 */
static void fpe_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    struct mr_x18_resume_scope mr_x18_scope
        __attribute__((cleanup(mr_x18_resume_leave))) =
        { (ucontext_t *)sigcontext, (ULONG_PTR)PC_sig((ucontext_t *)sigcontext), mr_x18_resume_always() };
    EXCEPTION_RECORD rec = { 0 };

    switch (siginfo->si_code & 0xffff )
    {
#ifdef FPE_FLTSUB
    case FPE_FLTSUB:
        rec.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
        break;
#endif
#ifdef FPE_INTDIV
    case FPE_INTDIV:
        rec.ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
        break;
#endif
#ifdef FPE_INTOVF
    case FPE_INTOVF:
        rec.ExceptionCode = EXCEPTION_INT_OVERFLOW;
        break;
#endif
#ifdef FPE_FLTDIV
    case FPE_FLTDIV:
        rec.ExceptionCode = EXCEPTION_FLT_DIVIDE_BY_ZERO;
        break;
#endif
#ifdef FPE_FLTOVF
    case FPE_FLTOVF:
        rec.ExceptionCode = EXCEPTION_FLT_OVERFLOW;
        break;
#endif
#ifdef FPE_FLTUND
    case FPE_FLTUND:
        rec.ExceptionCode = EXCEPTION_FLT_UNDERFLOW;
        break;
#endif
#ifdef FPE_FLTRES
    case FPE_FLTRES:
        rec.ExceptionCode = EXCEPTION_FLT_INEXACT_RESULT;
        break;
#endif
#ifdef FPE_FLTINV
    case FPE_FLTINV:
#endif
    default:
        rec.ExceptionCode = EXCEPTION_FLT_INVALID_OPERATION;
        break;
    }
    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *		int_handler
 *
 * Handler for SIGINT.
 */
static void int_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    HANDLE handle;

    if (!p__wine_ctrl_routine) return;
    if (!NtCreateThreadEx( &handle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(),
                           p__wine_ctrl_routine, 0 /* CTRL_C_EVENT */, 0, 0, 0, 0, NULL ))
        NtClose( handle );
}


/**********************************************************************
 *		abrt_handler
 *
 * Handler for SIGABRT.
 */
static void abrt_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { EXCEPTION_WINE_ASSERTION, EXCEPTION_NONCONTINUABLE };

    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *		quit_handler
 *
 * Handler for SIGQUIT.
 */
static void quit_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    ucontext_t *context = sigcontext;

    if (!is_inside_syscall( SP_sig(context) )) user_mode_abort_thread( 0, get_syscall_frame() );
    abort_thread(0);
}


/**********************************************************************
 *		usr1_handler
 *
 * Handler for SIGUSR1, used to signal a thread that it got suspended.
 */
static void usr1_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    ucontext_t *ucontext = sigcontext;
    CONTEXT context;
    ULONG_PTR observed_pc = PC_sig(ucontext), observed_sp = SP_sig(ucontext);
    ULONG_PTR observed_x28 = REGn_sig(28, ucontext);

#if defined(__APPLE__)
    /* A veneer has no side effects beyond restoring x18. Expose its logical
     * continuation, not private RX code absent from the ARM64EC bitmap. */
    TEB *direct_teb = macrunner_teb_reliable();
    ULONG_PTR direct_target = mr_direct_target( (ULONG_PTR)direct_teb, observed_pc );
    if (direct_target)
    {
        PC_sig(ucontext) = observed_pc = direct_target;
        REGn_sig(18, ucontext) = (ULONG_PTR)direct_teb;
    }
    CHPE_V2_CPU_AREA_INFO *chpe = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    if (macrunner_fex_kusd_backend && chpe && chpe->SuspendDoorbell &&
        (chpe->InSimulation || chpe->InSyscallCallback))
    {
        ULONG_PTR restart = apple_x18_resume_thunk_start( observed_pc );
        struct ntdll_thread_data *data = (struct ntdll_thread_data *)&macrunner_teb_reliable()->GdiTebBatch;
        ULONG_PTR pending_x10 = data->apple_x18_save_x10;
        ULONG_PTR pending_x16 = data->apple_x18_save_x16;
        ULONG_PTR pending_pc = data->apple_x18_save_pc;
        NTSTATUS status = server_select( NULL, 0, SELECT_INTERRUPTIBLE | SELECT_COOPERATIVE_SUSPEND,
                                         0, NULL, NULL );
        if (status == STATUS_THREAD_WAS_SUSPENDED)
        {
            static unsigned int deferred;
            unsigned int n = __atomic_add_fetch( &deferred, 1, __ATOMIC_RELAXED );
            *chpe->SuspendDoorbell = -1;
            macrunner_fex_suspend_pending = TRUE;
            if (n <= 32)
                macrunner_signal_writef( "mr-cooperative-suspend: n=%u tid=%lx pc=%p simulation=%u callback=%u\n",
                    n, (unsigned long)NtCurrentTeb()->ClientId.UniqueThread, (void *)observed_pc,
                    (unsigned int)chpe->InSimulation, (unsigned int)chpe->InSyscallCallback );
        }
        if (!is_inside_syscall( SP_sig(ucontext) ))
        {
            if (restart)
            {
                data->apple_x18_save_x10 = pending_x10;
                data->apple_x18_save_x16 = pending_x16;
                data->apple_x18_save_pc = pending_pc;
                REGn_sig(10, ucontext) = (ULONG_PTR)macrunner_teb_reliable();
                REGn_sig(18, ucontext) = REGn_sig(10, ucontext);
                PC_sig(ucontext) = restart;
            }
            else setup_x18_resume_from_sigcontext( ucontext );
        }
        return;
    }
#endif
    if (is_inside_syscall( SP_sig(ucontext) ))
    {
        {   /* ★ Читаем frame->sp ПРЯМО ПЕРЕД снятием, в том же вызове обработчика.
             * Иначе нельзя отличить «снимок врёт» от «я смешал два вызова в одной записи»:
             * поля __thread переживают вызов и в кольцо попадают вперемешку. */
            struct syscall_frame *fpre = get_syscall_frame();
            mr_usr1_pered_sp = fpre ? (ULONG64)fpre->sp : 0;
        }
        context.ContextFlags = CONTEXT_FULL | CONTEXT_ARM64_X18 | CONTEXT_EXCEPTION_REQUEST;
        NtGetContextThread( GetCurrentThread(), &context );
        /* ★★★★★★ 01.09 — ОТКУДА УСТАРЕВШИЙ Sp.
         * Замер довёл сюда: применяемый контекст несёт Sp от ПРОШЛОГО вызова, из-за чего
         * frame->sp откатывается и гость возвращается на мёртвый кадр. Здесь два
         * подозреваемых: снимок уже был стар, либо его переписал ответ сервера
         * (`wait_suspend` -> `contexts_from_server`). Записываем оба значения и текущий
         * frame->sp — это их разделяет. Только сохранения, без печати. */
        mr_usr1_snyal_sp = (ULONG64)context.Sp;
        {   /* ★ 01.09 — ПОЧЕМУ КАДР ДВИГАЕТСЯ. Страж, который я поставил, лечит следствие:
             * «не применять контекст, если кадр сдвинулся». Настоящий вопрос — ПОЧЕМУ он
             * сдвигается, пока поток стоит в wait_suspend. Записываем frame->sp и счётчик
             * входов диспетчера ДО ожидания; после — уже пишется. Разница по счётчику
             * скажет, вошёл ли в кадр системный вызов за это время. */
            struct syscall_frame *f0 = get_syscall_frame();
            mr_usr1_do_sp    = f0 ? (ULONG64)f0->sp : 0;
            mr_usr1_do_vhod  = f0 ? (unsigned int)f0->align : 0;
        }
        wait_suspend( &context );
        {   struct syscall_frame *f1 = get_syscall_frame();
            mr_usr1_posle_vhod = f1 ? (unsigned int)f1->align : 0; }
        mr_usr1_posle_sp = (ULONG64)context.Sp;
        { struct syscall_frame *f_ = get_syscall_frame();
          mr_usr1_ramka_sp = f_ ? (ULONG64)f_->sp : 0; }
        mr_usr1_n++;
        {   /* ★★★★★★ ЛЕЧЕНИЕ 01.09 — НЕ ПРИМЕНЯТЬ КОНТЕКСТ, КОТОРЫЙ СЕРВЕР НЕ МЕНЯЛ.
             *
             * Апстрим применяет снятый контекст безусловно, полагаясь на то, что кадр
             * системного вызова за время `wait_suspend` не двигается. У нас двигается:
             * замер (3 прогона из 3) показал `снял=0x…a30, после=0x…a30, кадр=0x…b00` —
             * сервер контекст НЕ трогал, а `frame->sp` за это время ушёл вперёд. Слепое
             * применение откатывает `frame->sp` на позицию прошлого вызова, диспетчер
             * возвращает гостя на мёртвый кадр, эпилог `kernelbase!WaitForSingleObject`
             * читает `ldr x30,[sp,#0x18]` из переиспользованной памяти и `ret` уходит в
             * данные — `esr=0x8200000f`.
             *
            /* Заплатка «пропустить no-op применение контекста» удалена 02.09.2026.
             * Её умолчание перевели в ВЫКЛ ещё 01.09, когда нашли настоящую
             * причину — потерянную половину условия в NtGetContextThread (см. выше).
             * С 01.09 она не исполнялась ни в одном прогоне: мёртвый код за
             * выключателем. Убираем причину держать выключатель. */
            NtSetContextThread( GetCurrentThread(), &context );
        }
    }
    else
    {
        ULONG_PTR native_resume = 0;
        BOOL native_prefix_resume = FALSE;
#if defined(__APPLE__)
        CONTEXT before_suspend, before_prefix_suspend;
        struct ntdll_thread_data *resume_data = NULL;
        ULONG_PTR pending_x10 = 0, pending_x16 = 0, pending_pc = 0;
#endif
        save_context( &context, ucontext );
#if defined(__APPLE__)
        native_prefix_resume = macrunner_native_dispatcher_prefix_owned( context.Pc, macrunner_fex_kusd_backend );
        if (native_prefix_resume) before_prefix_suspend = context;
        if (macrunner_fex_kusd_backend && is_arm64ec() &&
            (native_resume = apple_x18_resume_thunk_start( context.Pc )))
        {
            resume_data = (struct ntdll_thread_data *)&macrunner_teb_reliable()->GdiTebBatch;
            before_suspend = context;
            pending_x10 = resume_data->apple_x18_save_x10;
            pending_x16 = resume_data->apple_x18_save_x16;
            pending_pc = resume_data->apple_x18_save_pc;
        }
#endif
        context.ContextFlags |= CONTEXT_EXCEPTION_REPORTING;
        wait_suspend( &context );
#if defined(__APPLE__)
        if (macrunner_fex_kusd_backend && is_arm64ec())
        {
            static unsigned int observations;
            unsigned int n = __atomic_add_fetch( &observations, 1, __ATOMIC_RELAXED );
            if (n <= 64)
                macrunner_signal_writef( "mr-suspend-context: pid=%d tid=%lx n=%u "
                    "pc=%p sp=%p x28=%p returned_pc=%p returned_sp=%p returned_x28=%p "
                    "flags=%08x ec_before=%u ec_after=%u resume_thunk=%u\n",
                    (int)getpid(), (unsigned long)NtCurrentTeb()->ClientId.UniqueThread, n,
                    (void *)observed_pc, (void *)observed_sp, (void *)observed_x28,
                    (void *)(ULONG_PTR)context.Pc, (void *)(ULONG_PTR)context.Sp,
                    (void *)(ULONG_PTR)context.X28, (unsigned int)context.ContextFlags,
                    (unsigned int)is_ec_code( observed_pc ), (unsigned int)is_ec_code( context.Pc ),
                    (unsigned int)apple_x18_pc_is_resume_thunk( context.Pc ) );
        }
        /* Our Mach-O resume stubs are native but absent from the PE EC bitmap.
         * Re-entering guest simulation here abandons the suspended native stack. */
        if (native_resume && !apple_x18_resume_context_unchanged( &before_suspend, &context ))
            native_resume = 0;
        /* Only untouched pre-frame native entry state bypasses guest re-entry.
         * This owns the saved PC; unlike native_resume it must not restart a thunk. */
        if (native_prefix_resume &&
            !macrunner_native_prefix_context_unchanged( &before_prefix_suspend, &context ))
            native_prefix_resume = FALSE;
#endif
        /* MacRunner 2026-09-04 — перенос из Wine 11.16 (commit d3b41a854a8b, «ntdll: Setup
         * KiUserEmulationDispatcher in usr1_handler when needed»); у нас дерево 11.0.
         *
         * ЧТО ЧИНИТ: сюда мы попадаем, когда поток приостановили ВНЕ системного вызова —
         * то есть прямо посреди пользовательского кода. Если гость x64, этот код гостевой,
         * и `restore_context` возвращала бы процессор на АДРЕС x64 в режиме ARM64: первая
         * же выбранная команда — мусор. Это и есть «поток в эмуляции приостанавливается
         * негодно»: до сих пор всякая приостановка потока, стоящего в эмулируемом коде,
         * кончалась не продолжением, а отказом на выборке.
         *
         * Лечение апстрима: снятый контекст кладём на стек гостя как есть и возвращаемся
         * не в него, а в диспетчер эмуляции, который войдёт в симуляцию с этого контекста.
         *
         * Отличие от апстрима: у него область процессора создаётся безусловно
         * (unix/thread.c:1233), у нас — лениво, при первом входе в симуляцию
         * (dlls/ntdll/loader.c:404). Поэтому оба указателя проверяем: без области писать
         * InSimulation некуда, а без диспетчера некуда прыгать — в этом случае оставляем
         * прежнее поведение, а не падаем. */
        if (!native_resume && !native_prefix_resume && is_arm64ec() && !is_ec_code( context.Pc ) && pKiUserEmulationDispatcher &&
            NtCurrentTeb()->ChpeV2CpuAreaInfo)
        {
            CONTEXT *user_context = (CONTEXT *)((context.Sp - sizeof(CONTEXT)) & ~15);

            NtCurrentTeb()->ChpeV2CpuAreaInfo->InSimulation = 1;
            *user_context = context;
            user_context->ContextFlags = CONTEXT_FULL;
            context.Sp = (ULONG_PTR)user_context;
            context.Pc = (ULONG_PTR)pKiUserEmulationDispatcher;
        }
        restore_context( &context, ucontext );
#if defined(__APPLE__)
        if (native_resume)
        {
            TEB *teb = macrunner_teb_reliable();
            static unsigned int resumes;
            unsigned int n = __atomic_add_fetch( &resumes, 1, __ATOMIC_RELAXED );

            /* wait_suspend can run APCs, including nested x18-healing signals.
             * Restore this invocation's backing slots, then replay the SAME stub.
             * Changed server contexts deliberately retain the existing path. */
            resume_data->apple_x18_save_x10 = pending_x10;
            resume_data->apple_x18_save_x16 = pending_x16;
            resume_data->apple_x18_save_pc = pending_pc;
            REGn_sig(10, ucontext) = (ULONG_PTR)teb;
            REGn_sig(18, ucontext) = (ULONG_PTR)teb;
            PC_sig(ucontext) = native_resume;
            if (n <= 16)
                macrunner_signal_writef( "mr-suspend-native-resume: n=%u pc=%p restart=%p target=%p\n",
                    n, (void *)(ULONG_PTR)context.Pc, (void *)native_resume,
                    (void *)(ULONG_PTR)((struct ntdll_thread_data *)&teb->GdiTebBatch)->apple_x18_save_pc );
        }
        /* This native entry does not read x18: it loads TEB into x17, saves
         * that value to the syscall frame, then sets x18 after the stack
         * switch. The generic x18 thunk destroys live x17 in this interval.
         * Keep every saved register and resume at the exact native PC. */
        else if (!(native_prefix_resume &&
                   context.Pc >= (ULONG_PTR)__wine_syscall_dispatcher &&
                   context.Pc < (ULONG_PTR)__wine_syscall_dispatcher_prefix_end))
            setup_x18_resume_from_sigcontext( ucontext );
#endif
    }
}


/**********************************************************************
 *		usr2_handler
 *
 * Handler for SIGUSR2, used to set a thread context.
 */
static void usr2_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    struct syscall_frame *frame = get_syscall_frame();
    ucontext_t *context = sigcontext;
    DWORD i;

    /* ★ СТЕНА64: обработчик может ВЫЙТИ НИЧЕГО НЕ СДЕЛАВ по проверке ниже — и тогда
     * медленный путь вернётся в хвост диспетчера, где x17 берётся не из кадра.
     * Печатаем сам факт входа и исход проверки. */
    {
        static __thread unsigned int mr_st64_usr2_n;
        if (++mr_st64_usr2_n <= 16)
        {
            fprintf( stderr, "macrunner-st64-usr2: n=%u внутри_вызова=%d pc=%#llx x17_кадра=%#llx\n",
                     mr_st64_usr2_n, is_inside_syscall( SP_sig(context) ) ? 1 : 0,
                     (unsigned long long)frame->pc, (unsigned long long)frame->x[17] );
            fflush( stderr );
        }
    }

    if (!is_inside_syscall( SP_sig(context) )) return;

    /* MacRunner 2026-09-04 — перенос из Wine 11.16 (commit d3b41a854a8b, «ntdll: Setup
     * KiUserEmulationDispatcher in usr1_handler when needed»); у нас дерево 11.0.
     *
     * Тот же дефект, что в usr1_handler выше, но на пути установки контекста ЧУЖОМУ потоку:
     * кадр системного вызова помнит, куда возвращаться, и если это адрес гостя x64, возврат
     * туда напрямую невозможен. Возвращаемся в диспетчер эмуляции, положив полный контекст
     * на стек гостя. Условия те же: без области процессора и без диспетчера ведём себя
     * по-старому. */
    if (is_arm64ec() && !is_ec_code( frame->pc ) && pKiUserEmulationDispatcher &&
        NtCurrentTeb()->ChpeV2CpuAreaInfo)
    {
        CONTEXT *user_context = (CONTEXT *)((frame->sp - sizeof(CONTEXT)) & ~15);

        NtCurrentTeb()->ChpeV2CpuAreaInfo->InSimulation = 1;
        user_context->ContextFlags = CONTEXT_FULL;
        NtGetContextThread( GetCurrentThread(), user_context );
        SP_sig(context) = (ULONG_PTR)user_context;
        PC_sig(context) = (ULONG_PTR)pKiUserEmulationDispatcher;
    }
    else
    {
        SP_sig(context) = frame->sp;
        PC_sig(context) = frame->pc;
    }
    FP_sig(context)     = frame->fp;
    LR_sig(context)     = frame->lr;
    PSTATE_sig(context) = frame->cpsr;
    for (i = 0; i <= 28; i++) REGn_sig( i, context ) = frame->x[i];

#ifdef linux
    {
        struct fpsimd_context *fp = get_fpsimd_context( sigcontext );
        if (fp)
        {
            fp->fpcr = frame->fpcr;
            fp->fpsr = frame->fpsr;
            memcpy( fp->vregs, frame->v, sizeof(fp->vregs) );
        }
    }
#elif defined(__APPLE__)
    context->uc_mcontext->__ns.__fpcr = frame->fpcr;
    context->uc_mcontext->__ns.__fpsr = frame->fpsr;
    memcpy( context->uc_mcontext->__ns.__v, frame->v, sizeof(frame->v) );
    setup_x18_resume_from_sigcontext( context );
#endif
}


/**********************************************************************
 *           get_thread_ldt_entry
 */
/* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1058 — ОПИСАТЕЛИ СЕГМЕНТОВ ГОСТЯ i386.
 *
 * Заглушка `STATUS_NOT_IMPLEMENTED` давала 128 отказов из 140 в наборе Wine (91.4 %,
 * `dlls/ntdll/tests/wow64.c:1307`) — перебор 256 селекторов через
 * `NtQueryInformationThread(ThreadDescriptorTableEntry)`, и на каждый ответ `c0000002`.
 *
 * Хостовой таблицы описателей у ARM64 нет и быть не может, но она здесь и не нужна:
 * сегментная модель гостя ПЛОСКАЯ и задана нами же в этом файле (строки 6307-6312,
 * `SegCs=0x23 SegSs=SegDs=SegEs=SegGs=0x2b SegFs=0x53`). Описатель синтезируется из неё:
 *
 *   0x23  код 32 бита : база 0, предел 0xfffff страницами, тип 0x1b (код, чтение)
 *   0x2b  данные      : база 0, предел 0xfffff страницами, тип 0x13 (данные, запись)
 *   0x53  TEB гостя   : база = 32-битный TEB, предел 0xfff БАЙТАМИ, тип 0x13
 *   0x03  пустой      : нули, но успех — так отвечает Windows
 *   прочее            : STATUS_UNSUCCESSFUL, длину ответа не трогаем
 *
 * Селекторы таблицы LDT (бит 2) отвергаются: LDT у WOW64 нет, и тест это допускает. */
static void macrunner_fill_ldt_entry( LDT_ENTRY *entry, ULONG_PTR base, ULONG limit,
                                      unsigned int type, BOOL granularity )
{
    memset( entry, 0, sizeof(*entry) );
    entry->BaseLow                   = (WORD)base;
    entry->HighWord.Bits.BaseMid     = (BYTE)(base >> 16);
    entry->HighWord.Bits.BaseHi      = (BYTE)(base >> 24);
    entry->LimitLow                  = (WORD)limit;
    entry->HighWord.Bits.LimitHi     = (limit >> 16) & 0x0f;
    entry->HighWord.Bits.Type        = type;
    entry->HighWord.Bits.Dpl         = 3;
    entry->HighWord.Bits.Pres        = 1;
    entry->HighWord.Bits.Default_Big = 1;
    entry->HighWord.Bits.Granularity = granularity ? 1 : 0;
}

NTSTATUS get_thread_ldt_entry( HANDLE handle, THREAD_DESCRIPTOR_INFORMATION *info, ULONG len )
{
    TEB *teb = NtCurrentTeb();
    WOW_TEB *wow_teb;
    ULONG sel;

    if (len != sizeof(*info)) return STATUS_INFO_LENGTH_MISMATCH;
    if (info->Selector >> 16) return STATUS_UNSUCCESSFUL;

    if (handle != GetCurrentThread())
    {
        THREAD_BASIC_INFORMATION tbi;
        NTSTATUS status = NtQueryInformationThread( handle, ThreadBasicInformation,
                                                    &tbi, sizeof(tbi), NULL );
        if (status) return status;
        if (!tbi.TebBaseAddress) return STATUS_UNSUCCESSFUL;
        teb = tbi.TebBaseAddress;
    }

    sel = info->Selector | 3;
    if (sel == 3)   /* пустой селектор: нули и успех */
    {
        memset( &info->Entry, 0, sizeof(info->Entry) );
        return STATUS_SUCCESS;
    }
    if (sel & 4) return STATUS_UNSUCCESSFUL;   /* LDT: у WOW64 её нет */

    wow_teb = get_wow_teb( teb );
    if (!wow_teb) return STATUS_UNSUCCESSFUL;  /* поток не WOW64 — сегментов у него нет */

    switch (sel)
    {
    case 0x23:  /* код 32 бита */
        macrunner_fill_ldt_entry( &info->Entry, 0, 0xfffff, 0x1b, TRUE );
        return STATUS_SUCCESS;
    case 0x2b:  /* данные 32 бита: ss, ds, es, gs */
        macrunner_fill_ldt_entry( &info->Entry, 0, 0xfffff, 0x13, TRUE );
        return STATUS_SUCCESS;
    case 0x53:  /* TEB гостя: предел в БАЙТАХ, поэтому без страничной гранулярности */
        macrunner_fill_ldt_entry( &info->Entry, (ULONG_PTR)wow_teb, 0xfff, 0x13, FALSE );
        return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;
}


/**********************************************************************
 *             signal_init_threading
 */
static void segv_handler( int signal, siginfo_t *siginfo, void *sigcontext );
static void ill_handler( int signal, siginfo_t *siginfo, void *sigcontext );
static void bus_handler( int signal, siginfo_t *siginfo, void *sigcontext );

#if defined(__APPLE__) && defined(__aarch64__)
static struct sigaction macrunner_hb_prev_segv_action;
static struct sigaction macrunner_hb_prev_ill_action;
static struct sigaction macrunner_hb_prev_bus_action;
static BOOL macrunner_hb_primary_signal_trace;
static BOOL macrunner_hb_primary_signal_pre_wine_installed;
static BOOL macrunner_hb_primary_signal_post_wine_installed;
static BOOL macrunner_hb_wine_signal_handlers_ready;

static struct sigaction *macrunner_hb_prev_action_for_signal( int sig )
{
    if (sig == SIGSEGV) return &macrunner_hb_prev_segv_action;
    if (sig == SIGILL) return &macrunner_hb_prev_ill_action;
    return &macrunner_hb_prev_bus_action;
}

static const char *macrunner_hb_signal_source( int sig )
{
    if (sig == SIGSEGV) return "primary-segv";
    if (sig == SIGILL) return "primary-sigill";
    return "primary-bus";
}

static void macrunner_hb_chain_signal( int sig, siginfo_t *siginfo, void *sigcontext )
{
    struct sigaction *prev = macrunner_hb_prev_action_for_signal( sig );

    if ((prev->sa_flags & SA_SIGINFO) && prev->sa_sigaction)
    {
        prev->sa_sigaction( sig, siginfo, sigcontext );
        return;
    }
    if (prev->sa_handler == SIG_IGN) return;
    if (prev->sa_handler && prev->sa_handler != SIG_DFL)
    {
        prev->sa_handler( sig );
        return;
    }

    if (!macrunner_hb_wine_signal_handlers_ready)
    {
        if (sig == SIGBUS)
        {
            static unsigned int early_bus_count;

            if (early_bus_count++ < 4)
                macrunner_signal_writef( "macrunner-hb-early-native-bus: pid=%d pc=%p fault=%p "
                                         "routing-to-wine-bus-handler\n",
                                         getpid(), (void *)(ULONG_PTR)PC_sig((ucontext_t *)sigcontext),
                                         (void *)(ULONG_PTR)siginfo->si_addr );
            bus_handler( sig, siginfo, sigcontext );
            return;
        }
        macrunner_signal_writef( "macrunner-hb-early-nonx64-signal: pid=%d sig=%d pc=%p fault=%p "
                                 "prev_flags=%#x prev_handler=%p prev_sigaction=%p\n",
                                 getpid(), sig, (void *)(ULONG_PTR)PC_sig((ucontext_t *)sigcontext),
                                 (void *)(ULONG_PTR)(sig == SIGILL ? 0 : (ULONG_PTR)siginfo->si_addr),
                                 prev->sa_flags, prev->sa_handler, prev->sa_sigaction );
        signal( sig, SIG_DFL );
        raise( sig );
        return;
    }

    /* Once Wine owns its normal signal state, non-x64 faults still need Wine's
     * native handlers even if this primary handler was installed over a default
     * action in a bootstrap edge case. */
    if (sig == SIGSEGV)
    {
        segv_handler( sig, siginfo, sigcontext );
        return;
    }
    if (sig == SIGILL)
    {
        ill_handler( sig, siginfo, sigcontext );
        return;
    }
    if (sig == SIGBUS)
    {
        bus_handler( sig, siginfo, sigcontext );
        return;
    }

    signal( sig, SIG_DFL );
    raise( sig );
}

/* MacRunner 2026-07-29 (HK master lane, ITER-4): mark this thread as "inside the signal
 * handler" for the whole handler subtree, so HyperBridge's PE-header reads switch to the
 * non-faulting mach_vm_read_overwrite probe.  See the long note on
 * macrunner_hb_image_nt_header() in macrunner_hb.c for the live measurement that motivates it:
 * three threads pinned forever in a KERNEL fault loop on the `dos->e_magic` read reached from
 * this handler.  Scoped here rather than in macrunner_hb_route_x64_callback_fault() because
 * this is the single sa_sigaction entry point, so one scope also covers the ARM64X hexpthk
 * SIGILL redirect, which reaches the same classifier by a different route.
 *
 * Deliberately NOT folded into the existing fault-reentry guard: that guard is skipped
 * entirely when MACRUNNER_HB_FAULT_REENTRY_LIMIT_OFF is set, and this must not be. */
struct macrunner_hb_header_probe_scope { int engaged; };

static struct macrunner_hb_header_probe_scope macrunner_hb_header_probe_enter(void)
{
    struct macrunner_hb_header_probe_scope scope = { 1 };

    macrunner_hb_fault_header_probe_depth++;
    return scope;
}

static void macrunner_hb_header_probe_leave( struct macrunner_hb_header_probe_scope *scope )
{
    if (scope->engaged) macrunner_hb_fault_header_probe_depth--;
}

/* MacRunner 2026-07-30 — COST and KIND of a fault, the two things that make the rate readable.
 *
 * The rate alone was measured at a steady ~1800/s (entries=8192 in 4583 ms, 12288 in 6865 ms,
 * 16384 in 8799 ms). That number does not become a share of wall clock until it is multiplied by
 * the cost of one entry, and nothing measured that: at 20 us per fault 1800/s is 3.6 % and a
 * curiosity, at 500 us it is 90 % and the whole 16x gap to Rosetta. Guessing between those two is
 * how this project has lost days before.
 *
 * KIND matters for the same reason. vmmap on a live guest shows 178 regions mapped r--/rwx against
 * 459 rw-/rwx, and the read-only ones are where the guest's own memory sits — the classic
 * write-watch arrangement, in which every guest WRITE to a watched page traps. si_code separates
 * that case (SEGV_ACCERR, a permission fault on a mapped page) from a genuinely absent mapping
 * (SEGV_MAPERR) at no cost, so the report can say whether the storm is write-watch or something
 * else instead of leaving it to be inferred.
 *
 * The timing uses the cleanup attribute this handler already uses for its other scopes, so every
 * exit path is covered including the ones that resume the guest by rewriting the context. */
static ULONG64 macrunner_hb_fault_entries;
static ULONG64 macrunner_hb_fault_first_ns;
static ULONG64 macrunner_hb_fault_total_ns;
static ULONG64 macrunner_hb_fault_accerr;   /* write/permission fault on a mapped page */
static ULONG64 macrunner_hb_fault_maperr;   /* no mapping at that address */
static ULONG64 macrunner_hb_fault_otherkind;
/* 2026-07-30 — SPLIT of "other", which turned out to be 7395135 of 7417856 entries over a full
 * 409 s run. The first report was taken 12 s in and said 1711/s at 1 % busy; the full run says
 * 18131/s at 11 %, so the early reading was not representative and the storm is NOT a red herring.
 * accerr (write-watch) stayed at 22721, so almost none of it is the memory protection path. In an
 * x86-on-ARM translator the obvious remaining candidate is SIGILL, which is how control lands in
 * code that has not been translated yet -- but naming it without counting it is exactly the guess
 * this project keeps paying for. */
static ULONG64 macrunner_hb_fault_sigill;
static ULONG64 macrunner_hb_fault_sigbus;
static ULONG64 macrunner_hb_fault_sigtrap;
static ULONG64 macrunner_hb_fault_sigsegv_other;
/* 2026-07-30 — IDENTIFIED, now narrow it. The split said SIGBUS: bus=17429592 of 17453056 entries,
 * ill=0 trap=0 segv_other=0, at 35943/s and 16 % of wall clock in a run that reached the language
 * marker at +299.7 s. So it is neither the write-watch path (accerr, 23464) nor the untranslated-code
 * path (SIGILL, zero) — my guess of SIGILL was wrong.
 *
 * si_code is what separates the two candidates that remain, and they need opposite fixes:
 *   BUS_ADRALN — an unaligned access. x86 permits unaligned accesses including unaligned LOCK
 *                operations; ARM64 exclusives do not, so a guest atomic on an odd address traps
 *                every single execution. Mono leans on lock cmpxchg heavily.
 *   BUS_OBJERR — the W^X arrangement on Apple Silicon: a page cannot be writable and executable at
 *                once, so writing to one mapped executable raises this.
 * Six sampled PCs and addresses come with it, because after three wrong guesses today the numbers
 * are cheaper than another theory. */
static ULONG64 macrunner_hb_fault_bus_adraln;
static ULONG64 macrunner_hb_fault_bus_adrerr;
static ULONG64 macrunner_hb_fault_bus_objerr;
static ULONG64 macrunner_hb_fault_bus_othercode;

/* 2026-07-30 — THE DISCRIMINATOR between "expensive but correct" and "broken".
 *
 * Established: one PC (0x7ffd078b944, identical across processes, so a fixed-base module, and
 * 190 KB from the loader-init PC the log reports) executing `str x0,[x20]` (insn=0xf9000280) into
 * mostly page-ALIGNED addresses in SM=COW image mappings, with esr=0x9200004f — DFSC 0x0f, a write
 * permission fault, align=0. Between 9.4 and 17.4 million per run.
 *
 * Two readings fit that and only one is a defect:
 *   - first-touch copy-on-write, one fault per page. Expensive but CORRECT, and the answer would be
 *     to touch fewer pages, not to change the fault path.
 *   - the same pages faulting again and again because something re-protects them. A defect, and the
 *     fix is to stop re-arming.
 * The earlier samples support the second (…d7000, …d7048, …d70c8 all inside ONE page) and these
 * support the first (…91d000, …702000, …17a000, page-aligned, different pages). Counting distinct
 * pages settles it: faults ~= distinct pages is reading one, faults >> distinct pages is reading two.
 *
 * A 4096-entry direct-mapped table of page numbers, not a real set: a collision undercounts
 * distinct pages, which biases toward reading two, so a "faults ~= distinct" result cannot be an
 * artefact of the table. Lossy on purpose — an exact set has no place on a signal path. */
#define MACRUNNER_HB_FAULT_PAGE_SLOTS 4096
static ULONG64 macrunner_hb_fault_page_tab[MACRUNNER_HB_FAULT_PAGE_SLOTS];
static ULONG64 macrunner_hb_fault_pages_distinct;
static ULONG64 macrunner_hb_fault_same_page_repeat;

/* MacRunner 2026-08-03 — WHICH pages, not just how many.
 *
 * The counter above says 43 distinct pages carry 90 M faults and that 99.97 % of them are
 * BUS_ADRALN, which is enough to prove a storm and not enough to act on.  The storm ignites right
 * after `Restored language code` (+312 s in GPRDUMP2: 1.6 M faults at +377 s, 8.2 M by +433 s) and
 * is the signature of the stuck phase rather than a background tax — so naming the pages names the
 * thing the guest is grinding against.
 *
 * A 64-entry table with a linear scan: at the observed ~100 k faults/s worst case that is a few
 * million compares per second against a handler that already costs 6 µs per fault, i.e. noise.
 * Bounded and lossy on purpose — once full it stops learning rather than evicting, because the
 * hot pages arrive early and an eviction policy on a signal path buys nothing. */
#define MACRUNNER_HB_FAULT_TOP_SLOTS 64
static ULONG64 macrunner_hb_fault_top_page[MACRUNNER_HB_FAULT_TOP_SLOTS];
static ULONG64 macrunner_hb_fault_top_count[MACRUNNER_HB_FAULT_TOP_SLOTS];
static ULONG64 macrunner_hb_fault_top_pc[MACRUNNER_HB_FAULT_TOP_SLOTS];
/* DFSC из ESR. На ARM64 si_code=BUS_ADRALN выставляется безусловно и причину НЕ сообщает —
 * различает её только Data Fault Status Code: 0x04-0x07 трансляция, 0x08-0x0B флаг доступа,
 * 0x0C-0x0F права, 0x21 невыровненный доступ. Без него шторм в 130 млн отказов на одну
 * страницу неотличим от «кривой атомик» до «хвост секции PE за концом файла», а лечатся они
 * в разных местах. get_fault_esr() на macOS уже есть (uc_mcontext->__es.__esr). */
static ULONG64 macrunner_hb_fault_top_esr[MACRUNNER_HB_FAULT_TOP_SLOTS];
/* Адрес возврата на кадр выше. Без него диагноз упирается в тупик: pc шторма опознан через atos
 * по живому процессу как _platform_memmove из libsystem_platform.dylib+144, то есть обычное
 * копирование памяти — и оно НИКОГДА не назовёт виновника, потому что виновник тот, кто позвал
 * memmove с указателем на несуществующую страницу. 188-257 млн отказов, dfsc=0x07 (записи в
 * таблице страниц нет), 35 % времени процесса — и всё это указывает на системную библиотеку,
 * в которой чинить нечего. LR даёт НАШ кадр, а с ним место в коде, где указатель или длина
 * посчитаны неверно. */
static ULONG64 macrunner_hb_fault_top_lr[MACRUNNER_HB_FAULT_TOP_SLOTS];

/* ★★★ 07.09.2026, лейн ПРИБОРЫ-4 — ТРИ ПРИБОРА ВОКРУГ ТАБЛИЦЫ ГОРЯЧИХ СТРАНИЦ.
 *
 * На числе `macrunner-hb-fault-page` стоит запись CLAUDE.md «Шторм отказов = ОТСУТСТВУЮЩАЯ
 * СТРАНИЦА (DFSC=0x07), а не выравнивание» (faults=257 136 606, esr=92000007, dfsc=0x07).
 * Вывод верен для той страницы, что попала в таблицу; но МОЛЧАНИЕ этой строки означало
 * ЧЕТЫРЕ разные вещи, и различить их было нечем:
 *
 *   1. обработчик не входили вовсе                       (отказов не было)
 *   2. входили, но `macrunner_hb_fault_top_emit` не звали (нужно n кратное 262 144)
 *   3. звали, но ни у одной страницы не набралось 1024   (порог печати внутри emit)
 *   4. ★ страница ВЫТЕСНЕНА: все 64 слота заняли ПРЕДЫДУЩИЕ страницы, и цикл ниже
 *      просто ДОХОДИЛ ДО КОНЦА, НИЧЕГО НЕ ЗАПИСАВ И НИЧЕГО НЕ СКАЗАВ.
 *
 * Четвёртый случай — не рассуждение: таблица на 64 слота, слоты не вытесняются никогда,
 * а шторм разгорается ПОЗЖЕ (комментарий ниже: «+312 s ... a plain first-24 bound is
 * exhausted in ninety seconds»). То есть самая горячая страница прогона могла прийти уже
 * к полной таблице и не попасть в перепись НИ РАЗУ — при этом «top»-строки печатались бы
 * исправно, по холодным первым занявшим. Такое молчание неотличимо от «страница не
 * горячая», и это ровно тот класс, ради которого заведён hb_probe.h.
 *
 * Учёт стоит в обработчике сигнала, поэтому — только счётчики (одно расслабленное
 * атомарное сложение на прибор), без печати: HB_PROBE_SAY зовёт fprintf, а он в
 * обработчике не async-signal-safe. Числа выходят перепись через пульс. */
HB_PROBE_DEFINE(pr_fault_top_slot, "hb-fault-top-слот",
                "обращения к таблице 64 горячих страниц; hits = страница УЧТЕНА "
                "(нашлась в слоте или заняла свободный)",
                NULL, 0);
HB_PROBE_DEFINE(pr_fault_top_perelivanie, "hb-fault-top-перелив",
                "те же обращения; hits = страница ВЫТЕСНЕНА, все 64 слота заняты "
                "другими, отказ по ней не учитывается нигде",
                NULL, 0);
HB_PROBE_DEFINE(pr_fault_top_emit, "hb-fault-page-выпуск",
                "вызовы macrunner_hb_fault_top_emit; hits = строка hb-fault-page "
                "РЕАЛЬНО напечатана (у страницы набралось >= 1024 отказов)",
                NULL, 0);
HB_PROBE_DEFINE(pr_faultrate, "hb-faultrate-сводка",
                "входы в первичный обработчик сигнала (looked = ПОЛНОЕ число отказов, "
                "без потолка); hits = разы, когда сводка macrunner-hb-faultrate "
                "печаталась (n==64, n==512, далее каждые 4096)",
                NULL, 0);

static void macrunner_hb_fault_note_top( ULONG64 page, ULONG_PTR pc, ULONG64 esr, ULONG_PTR lr )
{
    unsigned int i;

    HB_PROBE_LOOKED(&pr_fault_top_slot);
    HB_PROBE_LOOKED(&pr_fault_top_perelivanie);
    for (i = 0; i < MACRUNNER_HB_FAULT_TOP_SLOTS; i++)
    {
        ULONG64 have = __atomic_load_n( &macrunner_hb_fault_top_page[i], __ATOMIC_RELAXED );

        if (have == page)
        {
            __atomic_add_fetch( &macrunner_hb_fault_top_count[i], 1, __ATOMIC_RELAXED );
            HB_PROBE_HIT(&pr_fault_top_slot);
            return;
        }
        if (!have)
        {
            __atomic_store_n( &macrunner_hb_fault_top_pc[i], (ULONG64)pc, __ATOMIC_RELAXED );
            __atomic_store_n( &macrunner_hb_fault_top_lr[i], (ULONG64)lr, __ATOMIC_RELAXED );
            __atomic_store_n( &macrunner_hb_fault_top_esr[i], esr, __ATOMIC_RELAXED );
            __atomic_store_n( &macrunner_hb_fault_top_page[i], page, __ATOMIC_RELAXED );
            __atomic_add_fetch( &macrunner_hb_fault_top_count[i], 1, __ATOMIC_RELAXED );
            HB_PROBE_HIT(&pr_fault_top_slot);
            return;
        }
    }
    /* Сюда попадает ВЫТЕСНЕННАЯ страница. Прежде здесь не было ничего. */
    HB_PROBE_HIT(&pr_fault_top_perelivanie);
}

static void macrunner_hb_fault_top_emit(void)
{
    unsigned int i;

    HB_PROBE_LOOKED(&pr_fault_top_emit);
    for (i = 0; i < MACRUNNER_HB_FAULT_TOP_SLOTS; i++)
    {
        ULONG64 page = __atomic_load_n( &macrunner_hb_fault_top_page[i], __ATOMIC_RELAXED );
        ULONG64 count = __atomic_load_n( &macrunner_hb_fault_top_count[i], __ATOMIC_RELAXED );

        if (!page || count < 1024) continue;
        HB_PROBE_HIT(&pr_fault_top_emit);
        {
            ULONG64 esr = __atomic_load_n( &macrunner_hb_fault_top_esr[i], __ATOMIC_RELAXED );
            macrunner_signal_writef( "macrunner-hb-fault-page: addr=%p faults=%llu pc=%p lr=%p esr=%llx ec=%llx dfsc=%llx\n",
                                     (void *)(ULONG_PTR)(page << 14),
                                     (unsigned long long)count,
                                     (void *)(ULONG_PTR)__atomic_load_n( &macrunner_hb_fault_top_pc[i],
                                                                        __ATOMIC_RELAXED ),
                                     (void *)(ULONG_PTR)__atomic_load_n( &macrunner_hb_fault_top_lr[i],
                                                                        __ATOMIC_RELAXED ),
                                     (unsigned long long)esr,
                                     (unsigned long long)((esr >> 26) & 0x3f),
                                     (unsigned long long)(esr & 0x3f) );
        }
    }
}

/* How many faults this page has already taken.  Used to spend the detail budget on the page the
 * census has already proven hot, instead of on the first arrivals: the storm ignites only after
 * `Restored language code` (+312 s), while the ordinary guest-code-entry faults start immediately,
 * so a plain "first 24" bound is exhausted in ninety seconds on exactly the traffic we do not care
 * about.  Measured that way once — 24 samples, all of them routine, none from the storm. */
static ULONG64 macrunner_hb_fault_page_count( ULONG64 page )
{
    unsigned int i;

    for (i = 0; i < MACRUNNER_HB_FAULT_TOP_SLOTS; i++)
    {
        if (__atomic_load_n( &macrunner_hb_fault_top_page[i], __ATOMIC_RELAXED ) != page) continue;
        return __atomic_load_n( &macrunner_hb_fault_top_count[i], __ATOMIC_RELAXED );
    }
    return 0;
}

static void macrunner_hb_fault_note_page( ULONG_PTR addr, ULONG_PTR pc, ULONG64 esr, ULONG_PTR lr )
{
    ULONG64 page = (ULONG64)(addr >> 14);  /* 16 KB pages on this platform */
    size_t slot = (size_t)((page * 2654435761u) & (MACRUNNER_HB_FAULT_PAGE_SLOTS - 1));
    ULONG64 prev = __atomic_load_n( &macrunner_hb_fault_page_tab[slot], __ATOMIC_RELAXED );

    macrunner_hb_fault_note_top( page, pc, esr, lr );
    if (prev == page)
    {
        __atomic_add_fetch( &macrunner_hb_fault_same_page_repeat, 1, __ATOMIC_RELAXED );
        return;
    }
    __atomic_store_n( &macrunner_hb_fault_page_tab[slot], page, __ATOMIC_RELAXED );
    __atomic_add_fetch( &macrunner_hb_fault_pages_distinct, 1, __ATOMIC_RELAXED );
}

struct macrunner_hb_faultrate_scope { ULONG64 t0; };

static void macrunner_hb_faultrate_leave( struct macrunner_hb_faultrate_scope *scope )
{
    ULONG64 now;

    if (!scope->t0) return;
    now = macrunner_hb_callback_loop_now_ns();
    if (now > scope->t0)
        __atomic_add_fetch( &macrunner_hb_fault_total_ns, now - scope->t0, __ATOMIC_RELAXED );
}

static void macrunner_hb_primary_signal_handler( int sig, siginfo_t *siginfo, void *sigcontext )
{
    struct mr_x18_resume_scope mr_x18_scope
        __attribute__((cleanup(mr_x18_resume_leave))) =
        { (ucontext_t *)sigcontext, (ULONG_PTR)PC_sig((ucontext_t *)sigcontext), mr_x18_resume_always() };
    struct macrunner_hb_faultrate_scope faultrate_scope
        __attribute__((cleanup(macrunner_hb_faultrate_leave))) =
        { macrunner_hb_callback_loop_now_ns() };

    struct macrunner_hb_header_probe_scope header_probe_scope
        __attribute__((cleanup(macrunner_hb_header_probe_leave))) =
        macrunner_hb_header_probe_enter();
    struct macrunner_hb_callback_loop_signal_scope callback_loop_scope
        __attribute__((cleanup(macrunner_hb_callback_loop_signal_leave))) =
        macrunner_hb_callback_loop_signal_enter( "primary", sig, sigcontext );
    ULONG_PTR fault_addr = (sig == SIGILL) ? 0 : (ULONG_PTR)siginfo->si_addr;
    ucontext_t *context = sigcontext;
    struct m0_sig_scope m0_scope __attribute__((cleanup(m0_sig_scope_leave))) =
        { macrunner_m0_sig_enter( sigcontext, siginfo, sig ) };
    (void)m0_scope;

    /* MacRunner 2026-07-30 — FAULT RATE. The one number this project has never measured, and the
     * only one that can explain the shape of its startup cost.
     *
     * Measured: 749.9 s to "Restored language" against under 45 s for Rosetta, and the gap is
     * DIFFUSE — the eight largest stalls in a 930 s run sum to 29 s, and the timestamped marks are
     * spread evenly across the whole run. A diffuse 16x is the signature of a constant per-operation
     * overhead, not of a hotspot, which is why every lever pulled so far (cache retention 38->96 %,
     * the fault-safe header probe, the multi-helper path) moved the wall clock by less than the
     * ±6 s our time metric can even resolve. Profiling said 100 % of samples sit inside this
     * handler, but with no count of how often it is ENTERED that is unreadable: it is equally
     * consistent with a few pinned threads and with every guest block transition costing a kernel
     * trap. Those two possibilities call for completely different work, and nothing here
     * distinguishes them.
     *
     * So count entries and report a rate. If this is thousands per second, dispatch is fault-driven
     * and that is the 16x — Rosetta chains translated blocks directly and pays no trap per
     * transition. If it is tens per second, the handler is a red herring and the cost is elsewhere.
     *
     * Deliberately not gated behind an env var: a relaxed atomic increment on a path that is
     * already doing signal delivery is unmeasurable, and a gate is how this measurement would end
     * up never taken. The REPORT is throttled to once per 4096 entries. */
    {
        ULONG64 n = __atomic_add_fetch( &macrunner_hb_fault_entries, 1, __ATOMIC_RELAXED );
        int code = siginfo ? siginfo->si_code : 0;

        /* ★★★ 07.09.2026, лейн ПРИБОРЫ-4 — ОТСУТСТВИЕ СТРОКИ `macrunner-hb-faultrate` УЖЕ
         * ОДИН РАЗ БЫЛО ПРОЧИТАНО КАК ВЫВОД, и вывод оказался неверным.
         *
         * В ЭТОМ ЖЕ ФАЙЛЕ, у переписи MACRUNNER_HB_SEGV_CENSUS, стоит фраза: «штатный
         * `macrunner-hb-faultrate` в журнале НОЛЬ раз — то есть счётчики того пути не
         * ведутся и частота шторма НЕ ИЗМЕРЕНА ничем». Счётчики ВЕДУТСЯ: `n` растёт
         * безусловно строкой выше. Не печатается СВОДКА — она стоит под
         * `n == 64 || n == 512 || !(n & 0xfff)`, поэтому прогон с 63 отказами даёт ноль
         * строк при полностью исправном учёте. На этом нуле выросла вторая перепись,
         * гейт которой (умолчание 0) сам по себе даёт третий неотличимый ноль.
         *
         * Прибор различает эти случаи по устройству:
         *     looked = 0             в обработчик не входили             (отказов нет)
         *     looked > 0, hits = 0   входили N раз, сводка не печаталась (N < 64)
         *     hits > 0               сводка печаталась hits раз
         * looked — это и есть полное число отказов, и оно теперь видно в переписи ВСЕГДА,
         * а не только когда их набралось 64. */
        HB_PROBE_LOOKED(&pr_faultrate);
        if (n == 64 || n == 512 || !(n & 0xfff)) HB_PROBE_HIT(&pr_faultrate);

        if (fault_addr) macrunner_hb_fault_note_page( fault_addr, (ULONG_PTR)PC_sig(context),
                                              (ULONG64)get_fault_esr( context ),
                                              (ULONG_PTR)LR_sig(context) );

        if (sig == SIGSEGV && code == SEGV_ACCERR)
        {
            /* 2026-07-30 — sample this path too, because the LABEL is not stable. Two runs of the
             * same binary: one reported 17429592 SIGBUS/BUS_ADRALN against 23464 accerr, the other
             * 9445176 accerr against 200 bus. This file already knew why -- the 2026-07-02 note in
             * bus_handler records BUS_ADRALN firing for a genuine ARM64 permission fault -- so the
             * two counters are ONE phenomenon the kernel labels inconsistently, and an instrument
             * that only watches bus_handler is blind whenever the coin lands the other way. */
            static int accerr_dumped;
            ULONG64 an = __atomic_add_fetch( &macrunner_hb_fault_accerr, 1, __ATOMIC_RELAXED );

            if (__atomic_fetch_add( &accerr_dumped, 1, __ATOMIC_RELAXED ) < 6 ||
                (macrunner_hb_accerr_storm_sample_enabled() && (an & 0xfffffull) == 0))
            {
                /* MacRunner 04.08 16:58 — ИМЯ МОДУЛЯ, А НЕ ГОЛЫЙ АДРЕС.
                 *
                 * Прогон 162224 дал 66.16 млн отказов, из них 66 162 622 на ОДНОЙ странице, а все
                 * шесть выборок — с адресами сбоя 0x60, 0x60, 0x3000, 0x3004, 0x17ee, 0x180c, то
                 * есть на нулевой странице, при `pc` в полосе 0x87fff9…  Дальше нужно знать, ЧЕЙ
                 * это код, и вот этого лог не даёт.  Попытка вычислить модуль арифметикой (взять
                 * базу `native_module=0x87fff950000` из соседней строки и вычесть) провалилась
                 * честно: ни один из 1819 модулей диста не имеет `EnterCriticalSection` на
                 * полученном RVA 0x735d0 — значит база принадлежит другому модулю, а полоса
                 * содержит их несколько.  Привязку должен печатать сам прибор, как это уже делают
                 * соседние: `macrunner_hb_signal_find_loader_module` здесь доступна. */
                struct macrunner_hb_signal_module_info pc_mod;
                BOOL have_mod = macrunner_hb_signal_find_loader_module( (ULONG_PTR)PC_sig(context), &pc_mod );

                macrunner_signal_writef( "macrunner-hb-accerr-sample: n=%llu pc=%p fault=%p lr=%p esr=0x%llx "
                                         "pc_module=%s pc_base=%p pc_rva=0x%llx found=%u\n",
                                         (unsigned long long)an,
                                         (void *)(ULONG_PTR)PC_sig(context), (void *)fault_addr,
                                         (void *)(ULONG_PTR)LR_sig(context),
                                         (unsigned long long)get_fault_esr( context ),
                                         pc_mod.name, pc_mod.base,
                                         (unsigned long long)pc_mod.rva, have_mod );
            }

            /* MacRunner 04.08 — попытка ИСПОЛНЕНИЯ по неотображаемому адресу, названная поимённо.
             *
             * Ниже в bus_handler такой прибор уже есть (`macrunner-hb-exec-into-stack`), но он
             * висит на ветке SIGBUS, а этот шторм приходит как SEGV_ACCERR — ровно та
             * нестабильность метки, о которой предупреждает комментарий выше.  Прогон 08:20 дал
             * 172.9 млн отказов при 394 тыс/с, у всех pc == fault == lr == 0x6001c04420000 и
             * esr EC=0x20 (отказ выборки инструкции), а загрузка встала на 43.5 с.  Адрес занимает
             * 52 бита при 47-битном пользовательском пространстве macOS, то есть это не
             * «неотображённая страница», а испорченный указатель, по которому кто-то прыгнул.
             *
             * Печатаем ПЕРВЫЕ 24 попытки — не под условием горячей страницы, потому что назвать
             * нужно самый первый прыжок, до того как цикл установится.  x16/x17 добавлены к
             * обычным x0-x2: непрямая ветвь идёт именно через них. */
            if (fault_addr && (ULONG_PTR)fault_addr == (ULONG_PTR)PC_sig(context))
            {
                static ULONG64 exec_accerr_dumped;

                if (__atomic_fetch_add( &exec_accerr_dumped, 1, __ATOMIC_RELAXED ) < 24)
                {
                    UINT64 grsp = 0;
                    int gstate = 0;
                    UINT64 grip = macrunner_hb_guest_pc_for_tid( GetCurrentThreadId(),
                                                                 &grsp, &gstate, NULL );

                    macrunner_signal_writef(
                        "macrunner-hb-exec-unmappable: n=%llu pc=%p lr=%p sp=%p x0=%p x1=%p x2=%p "
                        "x16=%p x17=%p gstate=%d guest_rip=%p guest_rsp=%p\n",
                        (unsigned long long)an,
                        (void *)(ULONG_PTR)PC_sig(context),
                        (void *)(ULONG_PTR)LR_sig(context),
                        (void *)(ULONG_PTR)SP_sig(context),
                        (void *)(ULONG_PTR)REGn_sig(0, context),
                        (void *)(ULONG_PTR)REGn_sig(1, context),
                        (void *)(ULONG_PTR)REGn_sig(2, context),
                        (void *)(ULONG_PTR)REGn_sig(16, context),
                        (void *)(ULONG_PTR)REGn_sig(17, context),
                        gstate, (void *)(ULONG_PTR)grip, (void *)(ULONG_PTR)grsp );

                    /* Кто прыгнул — ищется по хостовому кадру, а не по гостевому.
                     *
                     * Счётчики HyperBridge говорят, что у потока НЕТ взведённого кадра защиты
                     * (claim_declined_frame=41608 из 41608), то есть в момент прыжка он не
                     * исполнял транслированный код под охраной.  Значит назвать источник может
                     * только хостовая сторона: x19 — указатель контекста в коде HB, x18 — TEB,
                     * x29/x30 — кадр и адрес возврата, а восемь слов у sp содержат цепочку
                     * вызовов.  Стек читаем ТОЛЬКО если он выглядит как стек (выровнен и
                     * непустой): в обработчике сигнала любое неудачное чтение стоит прогона. */
                    {
                        ULONG_PTR hsp = (ULONG_PTR)SP_sig(context);

                        ULONG_PTR teb = (ULONG_PTR)REGn_sig(18, context);
                        ULONG64 stack_base = 0, stack_limit = 0;

                        /* Границы стека берём из TEB (NtTib.StackBase +0x08, StackLimit +0x10):
                         * если sp прижат к пределу, это переполнение хостового стека, и тогда
                         * область сохранения кадра затирается просто потому, что её некуда класть.
                         * Проверяем ту же гипотезу целиком: пролог блока HB кладёт x19-x23 и LR,
                         * поэтому печатаем ВЕСЬ набор — если мусор во всех, затёрта вся область,
                         * а не отдельный регистр. */
                        if (teb && !(teb & 7))
                        {
                            stack_base  = ((const ULONG64 *)teb)[1];
                            stack_limit = ((const ULONG64 *)teb)[2];
                        }

                        macrunner_signal_writef(
                            "macrunner-hb-exec-unmappable-frame: x18=%p x19=%p x20=%p x21=%p "
                            "x22=%p x23=%p x29=%p x30=%p stack_base=%p stack_limit=%p\n",
                            (void *)teb,
                            (void *)(ULONG_PTR)REGn_sig(19, context),
                            (void *)(ULONG_PTR)REGn_sig(20, context),
                            (void *)(ULONG_PTR)REGn_sig(21, context),
                            (void *)(ULONG_PTR)REGn_sig(22, context),
                            (void *)(ULONG_PTR)REGn_sig(23, context),
                            (void *)(ULONG_PTR)REGn_sig(29, context),
                            (void *)(ULONG_PTR)REGn_sig(30, context),
                            (void *)(ULONG_PTR)stack_base, (void *)(ULONG_PTR)stack_limit );

                        if (hsp && !(hsp & 15))
                        {
                            /* Окно шире и НИЖЕ sp тоже.
                             *
                             * В прошлом заходе на самой вершине уже лежало w0=0xa0802 — член того
                             * же семейства, что и мусор в регистрах (0402/0422/0442/0522/0802,
                             * шаг 0x20).  Значит источник узора где-то рядом с кадром, и его надо
                             * не угадывать, а увидеть: печатаем 24 слова начиная с sp-0x40, чтобы
                             * захватить и область, куда пролог блока HB кладёт x19-x23 и LR.
                             * Три строки по восемь слов — писатель асинхронно-безопасный, но
                             * форматная строка у него не резиновая. */
                            const ULONG64 *w = (const ULONG64 *)(hsp - 0x100);
                            int row;

                            for (row = 0; row < 6; row++)
                                macrunner_signal_writef(
                                    "macrunner-hb-exec-unmappable-stack: at=%p "
                                    "%p %p %p %p %p %p %p %p\n",
                                    (void *)(hsp - 0x100 + (ULONG_PTR)row * 64),
                                    (void *)(ULONG_PTR)w[row * 8 + 0], (void *)(ULONG_PTR)w[row * 8 + 1],
                                    (void *)(ULONG_PTR)w[row * 8 + 2], (void *)(ULONG_PTR)w[row * 8 + 3],
                                    (void *)(ULONG_PTR)w[row * 8 + 4], (void *)(ULONG_PTR)w[row * 8 + 5],
                                    (void *)(ULONG_PTR)w[row * 8 + 6], (void *)(ULONG_PTR)w[row * 8 + 7] );
                        }
                    }
                }
            }
        }
        else if (sig == SIGSEGV && code == SEGV_MAPERR)
            __atomic_add_fetch( &macrunner_hb_fault_maperr, 1, __ATOMIC_RELAXED );
        else
        {
            __atomic_add_fetch( &macrunner_hb_fault_otherkind, 1, __ATOMIC_RELAXED );
            if (sig == SIGILL)       __atomic_add_fetch( &macrunner_hb_fault_sigill, 1, __ATOMIC_RELAXED );
            else if (sig == SIGBUS)
            {
                static int bus_dumped;

                __atomic_add_fetch( &macrunner_hb_fault_sigbus, 1, __ATOMIC_RELAXED );
                if (code == BUS_ADRALN)      __atomic_add_fetch( &macrunner_hb_fault_bus_adraln, 1, __ATOMIC_RELAXED );
                else if (code == BUS_ADRERR) __atomic_add_fetch( &macrunner_hb_fault_bus_adrerr, 1, __ATOMIC_RELAXED );
                else if (code == BUS_OBJERR) __atomic_add_fetch( &macrunner_hb_fault_bus_objerr, 1, __ATOMIC_RELAXED );
                else                         __atomic_add_fetch( &macrunner_hb_fault_bus_othercode, 1, __ATOMIC_RELAXED );

                if (__atomic_fetch_add( &bus_dumped, 1, __ATOMIC_RELAXED ) < 6)
                {
                    /* MacRunner 2026-08-05 — печатаем ПРАВА страницы, а не только адрес.
                     *
                     * Замерено: 186 млн отказов BUS_ADRALN с ОДНОГО pc (ntdll RVA 0x3b944,
                     * `str x0,[x20]` в fixup_imports), 230 тыс/с, 39 % времени.  Обычному
                     * восьмибайтовому store выравнивание не нужно, значит дело не в нём:
                     * так macOS отвечает на запись в страницу без права записи.  Без прав
                     * в строке приходится гадать, какая из наших защит её сняла — с ними
                     * виновник называется сразу (prot=1 R, 3 RW, 5 RX, 7 RWX; tag — чей
                     * аллокатор). */
                    mach_vm_address_t r_addr = (mach_vm_address_t)fault_addr;
                    mach_vm_size_t r_size = 0;
                    vm_region_submap_info_data_64_t r_info;
                    mach_msg_type_number_t r_cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
                    natural_t r_depth = 0;
                    kern_return_t r_kr = mach_vm_region_recurse( mach_task_self(), &r_addr, &r_size,
                                                                &r_depth, (vm_region_recurse_info_t)&r_info,
                                                                &r_cnt );
                    macrunner_signal_writef( "macrunner-hb-bus-sample: code=%d pc=%p fault=%p lr=%p "
                                             "region=%#llx+%#llx prot=%d/%d tag=%u shared=%d kr=%d\n",
                                             code, (void *)(ULONG_PTR)PC_sig(context),
                                             (void *)fault_addr, (void *)(ULONG_PTR)LR_sig(context),
                                             (unsigned long long)r_addr, (unsigned long long)r_size,
                                             r_kr ? -1 : r_info.protection,
                                             r_kr ? -1 : r_info.max_protection,
                                             r_kr ? 0 : r_info.user_tag,
                                             r_kr ? -1 : (int)r_info.share_mode, r_kr );

                    /* MacRunner 2026-08-05 — ЦЕПОЧКА ВЫЗОВОВ прямо из обработчика.
                     *
                     * Замер 51086 записей показал: в падающую страницу `import_dll` не
                     * пишет НИ РАЗУ, хотя дизассемблер показывает `bl find_named_export`
                     * прямо перед падающим `str`.  Символ `fixup_imports` занимает ~5 КБ —
                     * в него заинлайнено многое, и соседство инструкций обмануло.
                     * Значит надо не гадать по инлайну, а взять настоящих вызывающих.
                     *
                     * Идём по цепочке кадров через x29 (FP): [fp] = предыдущий fp,
                     * [fp+8] = адрес возврата.  Async-signal-safe: только чтения, никаких
                     * блокировок и аллокаций.  Каждый шаг проверяем — выравнивание,
                     * монотонный рост (стек растёт вниз, значит fp должен увеличиваться)
                     * и разумный предел, иначе на битом кадре уйдём в бесконечность или
                     * вложенный отказ. */
                    {
                        ULONG_PTR fp = REGn_sig(29, context);
                        ULONG_PTR prev = 0;
                        unsigned lvl;

                        for (lvl = 0; lvl < 8; lvl++)
                        {
                            ULONG_PTR next, ret;

                            if (!fp || (fp & 7) || fp <= prev) break;
                            if (prev && fp - prev > 0x100000) break;
                            next = ((const ULONG_PTR *)fp)[0];
                            ret  = ((const ULONG_PTR *)fp)[1];
                            if (!ret) break;
                            macrunner_signal_writef( "macrunner-hb-bus-frame: lvl=%u fp=%p ret=%p\n",
                                                     lvl, (void *)fp, (void *)ret );
                            prev = fp;
                            fp = next;
                        }
                    }
                }

                /* MacRunner 2026-08-03 — the execute-attempt case, named rather than counted.
                 *
                 * The page census says one page carries 79 % of a 90 M-fault storm and that the
                 * faulting address and the pc are THE SAME (addr=0x110ac8000 pc=0x110acada8), while
                 * the surrounding traces show sp=0x110ace210 — the thread keeps branching into its
                 * own stack and faulting on the instruction fetch.  That is exactly the signature
                 * already on file for exit=5 (pc == lr == fault, info0=0x8), which makes the storm
                 * and the fatal fault one phenomenon at two magnifications: ~237 k survivable
                 * attempts, then one that is not.
                 *
                 * Six samples cannot show WHO branches there.  x30 is the link register the branch
                 * came through, x0-x2 carry the usual dispatch operands, and the guest pc says where
                 * the emulated thread believed it was.  Bounded to 24: under this storm an unbounded
                 * print would become the bottleneck it is measuring. */
                if (fault_addr && (ULONG_PTR)fault_addr == (ULONG_PTR)PC_sig(context) &&
                    macrunner_hb_fault_page_count( (ULONG64)((ULONG_PTR)fault_addr >> 14) ) > 65536)
                {
                    static ULONG64 exec_dumped;

                    if (__atomic_fetch_add( &exec_dumped, 1, __ATOMIC_RELAXED ) < 24)
                    {
                        UINT64 grsp = 0;
                        int gstate = 0;
                        UINT64 grip = macrunner_hb_guest_pc_for_tid( GetCurrentThreadId(),
                                                                     &grsp, &gstate, NULL );

                        macrunner_signal_writef(
                            "macrunner-hb-exec-into-stack: pc=%p lr=%p sp=%p x0=%p x1=%p x2=%p "
                            "gstate=%d guest_rip=%p guest_rsp=%p\n",
                            (void *)(ULONG_PTR)PC_sig(context),
                            (void *)(ULONG_PTR)LR_sig(context),
                            (void *)(ULONG_PTR)SP_sig(context),
                            (void *)(ULONG_PTR)REGn_sig(0, context),
                            (void *)(ULONG_PTR)REGn_sig(1, context),
                            (void *)(ULONG_PTR)REGn_sig(2, context),
                            gstate, (void *)(ULONG_PTR)grip, (void *)(ULONG_PTR)grsp );

                        /* MacRunner 2026-08-03 — WHO returned into the stack.
                         *
                         * pc == lr is the signature of a `ret` taken with x30 holding a stack
                         * address instead of a code address, and the address itself
                         * (0x1155ca8f8, inside a 16 MB rw- region flanked by a 32 KB --- guard,
                         * i.e. a thread stack) cannot name the culprit.  The callee-saved
                         * registers can: this translator keeps its context in the x19-x28 range,
                         * so their values say which layer was running.  x29 is the frame pointer,
                         * and the qwords around sp are the frame whose saved lr was consumed —
                         * an epilogue's `ldp x29, x30, [sp], #N` leaves its source right there.
                         *
                         * Reading the host stack here is safe: it is our own mapping, rw- and
                         * resident, and the window is small and bounded. */
                        {
                            const ULONG64 *hs = (const ULONG64 *)(ULONG_PTR)SP_sig(context);

                            macrunner_signal_writef(
                                "macrunner-hb-exec-into-stack-regs: fp=%p x19=%p x20=%p x21=%p "
                                "x22=%p x23=%p x24=%p x25=%p x26=%p x27=%p x28=%p\n",
                                (void *)(ULONG_PTR)REGn_sig(29, context),
                                (void *)(ULONG_PTR)REGn_sig(19, context),
                                (void *)(ULONG_PTR)REGn_sig(20, context),
                                (void *)(ULONG_PTR)REGn_sig(21, context),
                                (void *)(ULONG_PTR)REGn_sig(22, context),
                                (void *)(ULONG_PTR)REGn_sig(23, context),
                                (void *)(ULONG_PTR)REGn_sig(24, context),
                                (void *)(ULONG_PTR)REGn_sig(25, context),
                                (void *)(ULONG_PTR)REGn_sig(26, context),
                                (void *)(ULONG_PTR)REGn_sig(27, context),
                                (void *)(ULONG_PTR)REGn_sig(28, context) );
                            macrunner_signal_writef(
                                "macrunner-hb-exec-into-stack-frame: sp+00=%p +08=%p +10=%p "
                                "+18=%p +20=%p +28=%p +30=%p +38=%p\n",
                                (void *)(ULONG_PTR)hs[0], (void *)(ULONG_PTR)hs[1],
                                (void *)(ULONG_PTR)hs[2], (void *)(ULONG_PTR)hs[3],
                                (void *)(ULONG_PTR)hs[4], (void *)(ULONG_PTR)hs[5],
                                (void *)(ULONG_PTR)hs[6], (void *)(ULONG_PTR)hs[7] );

                            /* MacRunner 2026-08-03 — WHERE IS THE RECORD, measured instead of hunted.
                             *
                             * A translated block saves X23 and LR as a PAIR at [SP,#32] and restores
                             * that pair before RET (hb_arm64_codegen.c:756/809).  At the stall the
                             * restored values are X23 = 0x00000000c0000005 and LR = a stack address —
                             * byte-for-byte EXCEPTION_RECORD.ExceptionCode|ExceptionFlags followed by
                             * .ExceptionRecord.  So a delivery record is sitting on the block's
                             * register-save area, and the epilogue loads its fields as registers.
                             *
                             * Two attempts to find the WRITER by reading code both missed: wine's
                             * setup_raise_exception() is never reached in these runs (its own trace is
                             * 0 while the helper it calls printed 16 times from a DIFFERENT caller —
                             * the low-stack predicate), and the guest x64-domain dispatcher keeps its
                             * state on the heap, not the stack.  So stop hunting the writer and locate
                             * the record itself: scan the frame window for the 8-byte signature and
                             * print every hit with its offset from SP and the three qwords that follow.
                             *
                             * A fixed offset across hits means the writer computed the address from
                             * SP; scattered offsets mean it did not.  Either way it is an answer, and
                             * it costs a bounded read of our own resident stack on a path already
                             * capped at 24. */
                            {
                                const ULONG64 SIG = 0x00000000c0000005ull;
                                unsigned int i, hits = 0;

                                for (i = 0; i < 2048 && hits < 4; i++)
                                {
                                    if (hs[i] != SIG) continue;
                                    hits++;
                                    macrunner_signal_writef(
                                        "macrunner-hb-exec-into-stack-record: hit=%u at=%p sp_off=+0x%x "
                                        "next=%p %p %p sp=%p\n",
                                        hits, (void *)(ULONG_PTR)&hs[i], (unsigned)(i * 8),
                                        (void *)(ULONG_PTR)hs[i + 1],
                                        (void *)(ULONG_PTR)hs[i + 2],
                                        (void *)(ULONG_PTR)hs[i + 3],
                                        (void *)(ULONG_PTR)SP_sig(context) );
                                }
                                if (!hits)
                                    macrunner_signal_writef(
                                        "macrunner-hb-exec-into-stack-record: none in 16 KB above sp=%p"
                                        " — the record is NOT in this window, x23 came from elsewhere\n",
                                        (void *)(ULONG_PTR)SP_sig(context) );

                                /* MacRunner 2026-08-03 — THE SLOTS THE EPILOGUE ACTUALLY READ.
                                 *
                                 * The first cut of this scan started at SP and walked UP, which is the
                                 * wrong direction for this question: a block's 48-byte frame is built by
                                 * `STP X19,X20,[SP,#-48]!` and torn down by `LDP X19,X20,[SP],#48`, so by
                                 * the time the RET faults the frame sits BELOW the reported SP.  The pair
                                 * that fed X23 and LR was at [SP-48+32] and [SP-48+40] — i.e. SP-16 and
                                 * SP-8 — and the upward scan never covered them.  It found records at
                                 * +0x1020/+0x11d0/+0x2230 instead, one of which happens to be exactly
                                 * where the bad PC points, which is a real and useful fact but a
                                 * different one.
                                 *
                                 * Print the popped frame verbatim.  Popped stack is still mapped and
                                 * still holds its bytes; nothing else has run on this thread between the
                                 * LDP and this handler.  If SP-16 reads 0xc0000005 and SP-8 reads the bad
                                 * PC, then the pair is confirmed as the source and the question becomes
                                 * who put them there — either the block was ENTERED with them live in
                                 * X23/LR, or something wrote over the slots while the block ran. */
                                macrunner_signal_writef(
                                    "macrunner-hb-exec-into-stack-popped: sp-30=%p -28=%p -20=%p "
                                    "-18=%p -10=%p(x23 slot) -08=%p(lr slot) sp=%p\n",
                                    (void *)(ULONG_PTR)hs[-6], (void *)(ULONG_PTR)hs[-5],
                                    (void *)(ULONG_PTR)hs[-4], (void *)(ULONG_PTR)hs[-3],
                                    (void *)(ULONG_PTR)hs[-2], (void *)(ULONG_PTR)hs[-1],
                                    (void *)(ULONG_PTR)SP_sig(context) );

                                /* MacRunner 2026-08-03 — WHICH REGISTER CARRIED THE BRANCH.
                                 *
                                 * Settled so far, by measurement and not by reading: the bad PC is
                                 * always exactly SP+0x1020, and it lands at offset 0x3b0 inside the
                                 * delivery layout this same handler wrote (base and size are printed
                                 * by -record-overlap).  0x3b0 is offsetof(struct exc_stack_layout,
                                 * rec).  Only two instructions in the tree produce that address —
                                 * `add x0, sp, #0x3b0` in the plain ARM64 KiUserExceptionDispatcher
                                 * and `add x0, sp, #0x3b0+0x4d0` in the ARM64EC one — and both mean it
                                 * as an ARGUMENT.  So &rec reached a branch instead.
                                 *
                                 * Each candidate leaves a different register equal to PC: x16 for the
                                 * `br x16` in __wine_pe_x18_thunk and for the dispatcher's own
                                 * `blr x16`; x9 for the ARM64EC dispatch-call path, which does
                                 * `mov x9, x0` first; x0 if something branched on the argument
                                 * directly; x17 is the scratch an EC exit thunk would use.  Print all
                                 * of them and the answer names itself.  Three hypotheses today were
                                 * each killed by one measurement after costing a run — this is the
                                 * measurement that replaces the fourth. */
                                macrunner_signal_writef(
                                    "macrunner-hb-exec-into-stack-branch: pc=%p x0=%p x9=%p x10=%p "
                                    "x16=%p x17=%p x30=%p sp=%p\n",
                                    (void *)(ULONG_PTR)PC_sig(context),
                                    (void *)(ULONG_PTR)REGn_sig(0, context),
                                    (void *)(ULONG_PTR)REGn_sig(9, context),
                                    (void *)(ULONG_PTR)REGn_sig(10, context),
                                    (void *)(ULONG_PTR)REGn_sig(16, context),
                                    (void *)(ULONG_PTR)REGn_sig(17, context),
                                    (void *)(ULONG_PTR)LR_sig(context),
                                    (void *)(ULONG_PTR)SP_sig(context) );

                                /* MacRunner 2026-08-03 night — the SEH-handler argument registers.
                                 *
                                 * `sample` of the live hung process named the caller: the frame under
                                 * the bad PC returns to dispatch_exception+0x8fc, and the instruction
                                 * before that return address is `bl call_seh_handlers` (ntdll rva
                                 * 0x29210, native ntdll base 0x87fff950000 this run).  Handlers are
                                 * invoked one level down by call_seh_handler, which is
                                 * `blr x4` with the ABI (rec=x0, frame=x1, context=x2, dispatch=x3,
                                 * handler=x4) and which does NOT set x29, so the fp chain skips it —
                                 * exactly what sample showed.
                                 *
                                 * x4 is therefore the handler pointer actually branched to, and x3
                                 * the DISPATCHER_CONTEXT it came from.  Neither was ever printed.
                                 * If x4 == pc == &rec, the handler pointer IS the exception record
                                 * and the question becomes who put it in dispatch->LanguageHandler;
                                 * if x4 is a sane handler, the branch was not this blr and the
                                 * search moves on with one measurement instead of a guess. */
                                /* The OTHER call_seh_handler call site takes its handler from the
                                 * TEB registration list — `(PEXCEPTION_ROUTINE)teb_frame->Handler`,
                                 * a linked list that lives ON THE STACK.  Three deliveries wrote
                                 * 1 136 bytes each onto this stack this run, so a registration
                                 * record inside those ranges would now yield whatever the delivery
                                 * left there.  Print the head and the first few links: a Handler
                                 * equal to the faulting PC names this path outright. */
                                {
                                    TEB *teb = NtCurrentTeb();
                                    const ULONG64 *link = teb ? (const ULONG64 *)teb->Tib.ExceptionList : NULL;
                                    unsigned int li;

                                    for (li = 0; li < 4 && link; li++)
                                    {
                                        ULONG64 prev, handler;

                                        if (((ULONG64)(ULONG_PTR)link & 7) ||
                                            (ULONG64)(ULONG_PTR)link < 0x10000) break;
                                        prev = link[0];
                                        handler = link[1];
                                        macrunner_signal_writef(
                                            "macrunner-hb-exec-into-stack-tebseh: %u frame=%p prev=%p "
                                            "handler=%p is_pc=%u\n",
                                            li, (const void *)link, (void *)(ULONG_PTR)prev,
                                            (void *)(ULONG_PTR)handler,
                                            handler == (ULONG64)PC_sig(context) ? 1u : 0u );
                                        link = (const ULONG64 *)(ULONG_PTR)prev;
                                    }
                                }

                                macrunner_signal_writef(
                                    "macrunner-hb-exec-into-stack-args: pc=%p x1=%p x2=%p x3=%p "
                                    "x4=%p x5=%p x6=%p x7=%p x8=%p\n",
                                    (void *)(ULONG_PTR)PC_sig(context),
                                    (void *)(ULONG_PTR)REGn_sig(1, context),
                                    (void *)(ULONG_PTR)REGn_sig(2, context),
                                    (void *)(ULONG_PTR)REGn_sig(3, context),
                                    (void *)(ULONG_PTR)REGn_sig(4, context),
                                    (void *)(ULONG_PTR)REGn_sig(5, context),
                                    (void *)(ULONG_PTR)REGn_sig(6, context),
                                    (void *)(ULONG_PTR)REGn_sig(7, context),
                                    (void *)(ULONG_PTR)REGn_sig(8, context) );

                                /* MacRunner 2026-08-04 — WHO CALLED THE CODE THAT RETURNED INTO &rec.
                                 *
                                 * Settled by the NOGATES control run, and it moves the question:
                                 * the popped frame is CLEAN (x23 slot = 0x87fff9bb860, lr slot =
                                 * 0x87ef13c0000 — both guest addresses, both plausible), yet x30
                                 * equals &rec of the THIRD nested delivery.  So LR was NOT read back
                                 * from that frame; something set x30 = &rec directly, and only the
                                 * dispatcher computes that address (`add x0, sp, #0x3b0`) — as an
                                 * ARGUMENT, into x0.
                                 *
                                 * The one register the dump never printed is the frame pointer, and
                                 * it is exactly what names the caller: on ARM64 every framed callee
                                 * stores {caller FP, caller LR} at [x29].  Walk four links with
                                 * guarded reads (this runs inside a signal handler; a fault here
                                 * would replace one stall with a worse one), print raw addresses,
                                 * and resolve them offline against macrunner-hb-host-image.
                                 *
                                 * Reading only, no behaviour change, capped by the same counter as
                                 * the dumps above. */
                                {
                                    ULONG64 fp = REGn_sig(29, context);
                                    unsigned int fi;

                                    macrunner_signal_writef(
                                        "macrunner-hb-exec-into-stack-fp: head fp=%p sp=%p pc=%p\n",
                                        (void *)(ULONG_PTR)fp,
                                        (void *)(ULONG_PTR)SP_sig(context),
                                        (void *)(ULONG_PTR)PC_sig(context) );
                                    for (fi = 0; fi < 4 && fp && !(fp & 7); fi++)
                                    {
                                        ULONG64 prev = 0, ret = 0;

                                        if (!macrunner_signal_read_memory( &prev, (const void *)(ULONG_PTR)fp,
                                                                           sizeof(prev) ) ||
                                            !macrunner_signal_read_memory( &ret, (const void *)(ULONG_PTR)(fp + 8),
                                                                           sizeof(ret) ))
                                        {
                                            macrunner_signal_writef(
                                                "macrunner-hb-exec-into-stack-fp: %u fp=%p <unreadable>\n",
                                                fi, (void *)(ULONG_PTR)fp );
                                            break;
                                        }
                                        macrunner_signal_writef(
                                            "macrunner-hb-exec-into-stack-fp: %u fp=%p prev=%p ret=%p\n",
                                            fi, (void *)(ULONG_PTR)fp, (void *)(ULONG_PTR)prev,
                                            (void *)(ULONG_PTR)ret );
                                        if (prev <= fp) break;
                                        fp = prev;
                                    }
                                }

                                /* MacRunner 2026-08-03 night — the discriminator.
                                 *
                                 * The epilogue loaded LR from [SP-8] (the frame is popped by
                                 * `LDP X19,X20,[SP],#48`, so its LR slot is 8 below the reported
                                 * SP).  If that address lies inside a range THIS thread's delivery
                                 * wrote, our own exception frame flattened a live block frame and
                                 * the fix belongs in the delivery's stack reservation.  If it lies
                                 * in none of them, the delivery is exonerated for a second time and
                                 * the slot was never written by the block either — which points at
                                 * block entry, not at delivery.  Printed even when the ring is
                                 * empty: a silent instrument and one that found nothing must stay
                                 * distinguishable (this lane has lost days to that difference). */
                                {
                                    ULONG64 lr_slot = (ULONG64)(ULONG_PTR)SP_sig(context) - 8;
                                    ULONG64 x23_slot = lr_slot - 8;
                                    unsigned int k, hit = 0;

                                    for (k = 0; k < MACRUNNER_HB_DELIVERY_RING; k++)
                                    {
                                        const struct macrunner_hb_delivery_note *e =
                                            &macrunner_hb_delivery_ring[k];
                                        unsigned int covers_lr, covers_x23;

                                        if (!e->seq) continue;
                                        covers_lr = (lr_slot >= e->lo && lr_slot < e->hi);
                                        covers_x23 = (x23_slot >= e->lo && x23_slot < e->hi);
                                        if (covers_lr || covers_x23) hit++;
                                        macrunner_signal_writef(
                                            "macrunner-hb-delivery-vs-slot: seq=%llu write=%p-%p "
                                            "rec=%p code=%#llx interrupted_sp=%p lr_slot=%p "
                                            "covers_lr=%u covers_x23=%u\n",
                                            (unsigned long long)e->seq,
                                            (void *)(ULONG_PTR)e->lo, (void *)(ULONG_PTR)e->hi,
                                            (void *)(ULONG_PTR)e->rec_addr,
                                            (unsigned long long)e->code,
                                            (void *)(ULONG_PTR)e->interrupted_sp,
                                            (void *)(ULONG_PTR)lr_slot, covers_lr, covers_x23 );
                                    }
                                    macrunner_signal_writef(
                                        "macrunner-hb-delivery-vs-slot-summary: deliveries=%llu "
                                        "hits=%u lr_slot=%p pc=%p sp=%p\n",
                                        (unsigned long long)macrunner_hb_delivery_seq, hit,
                                        (void *)(ULONG_PTR)lr_slot,
                                        (void *)(ULONG_PTR)PC_sig(context),
                                        (void *)(ULONG_PTR)SP_sig(context) );
                                }

                                /* MacRunner 2026-08-03 night — WHO RETURNED TO &rec.
                                 *
                                 * Measured this run, three deliveries deep on one stack: delivery #3
                                 * set SP=0x1119cb200, and `add x0, sp, #0x3b0` in
                                 * KiUserExceptionDispatcher makes &rec = 0x1119cb5b0 — bit-for-bit
                                 * the faulting PC.  SP at the fault is 0xC70 BELOW the dispatcher's,
                                 * so dispatch_exception and its callees really ran; one of them
                                 * returned to x30 = &rec, i.e. its saved LR was replaced by the very
                                 * pointer the dispatcher passes in x0.  The popped frame is NOT the
                                 * source (its LR slot holds 0x87ef13c0000, a sane guest base), so the
                                 * useful question is which frame is on the stack right now.
                                 *
                                 * Walk the frame-pointer chain — the one structure that survives a
                                 * corrupted LR — and print each frame's saved LR.  The first entry
                                 * that is neither host nor guest code names the function whose return
                                 * address was overwritten, and the frame ABOVE it is the writer's
                                 * neighbourhood.  Reads are bounded (16 frames, ascending, aligned)
                                 * and this path is already capped at 24 dumps. */
                                {
                                    ULONG64 fp = REGn_sig(29, context);
                                    ULONG64 sp_now = (ULONG64)(ULONG_PTR)SP_sig(context);
                                    unsigned int fi;

                                    macrunner_signal_writef(
                                        "macrunner-hb-exec-into-stack-fp: head fp=%p sp=%p "
                                        "x19=%p x20=%p x21=%p x22=%p x23=%p x28=%p\n",
                                        (void *)(ULONG_PTR)fp, (void *)(ULONG_PTR)sp_now,
                                        (void *)(ULONG_PTR)REGn_sig(19, context),
                                        (void *)(ULONG_PTR)REGn_sig(20, context),
                                        (void *)(ULONG_PTR)REGn_sig(21, context),
                                        (void *)(ULONG_PTR)REGn_sig(22, context),
                                        (void *)(ULONG_PTR)REGn_sig(23, context),
                                        (void *)(ULONG_PTR)REGn_sig(28, context) );

                                    for (fi = 0; fi < 16; fi++)
                                    {
                                        const ULONG64 *frame = (const ULONG64 *)(ULONG_PTR)fp;
                                        ULONG64 prev, lr;

                                        /* Ascending and aligned, or the chain is over. Staying inside
                                         * the interrupted stack keeps every read on memory this thread
                                         * demonstrably owns. */
                                        if (!fp || (fp & 7) || fp < sp_now || fp - sp_now > 0x40000)
                                            break;
                                        prev = frame[0];
                                        lr = frame[1];
                                        macrunner_signal_writef(
                                            "macrunner-hb-exec-into-stack-fp: %u fp=%p prev=%p lr=%p\n",
                                            fi, (void *)(ULONG_PTR)fp, (void *)(ULONG_PTR)prev,
                                            (void *)(ULONG_PTR)lr );
                                        if (prev <= fp) break;
                                        fp = prev;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else if (sig == SIGTRAP) __atomic_add_fetch( &macrunner_hb_fault_sigtrap, 1, __ATOMIC_RELAXED );
            else if (sig == SIGSEGV) __atomic_add_fetch( &macrunner_hb_fault_sigsegv_other, 1, __ATOMIC_RELAXED );
        }

        if (n == 1)
            __atomic_store_n( &macrunner_hb_fault_first_ns, faultrate_scope.t0, __ATOMIC_RELAXED );
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: РАННИЕ точки печати.
         * Период «кратно 4096» писался под шторм в сотни миллионов отказов. На ступени 1
         * (Diablo) отказов за весь прогон МЕНЬШЕ 4096, поэтому строка не печаталась ни разу
         * и разбивка по видам сигналов была недоступна — молчание прибора я едва не принял
         * за отсутствие явления. Добавлены точки 64 и 512: они дают ту же строку на малых
         * числах и ничего не стоят, потому что срабатывают дважды за прогон. */
        else if (n == 64 || n == 512 || !(n & 0xfff))
        {
            ULONG64 t0 = __atomic_load_n( &macrunner_hb_fault_first_ns, __ATOMIC_RELAXED );
            ULONG64 ms = t0 && faultrate_scope.t0 > t0 ? (faultrate_scope.t0 - t0) / 1000000ull : 0;
            /* total_ns excludes the entry in progress, which is what we want: it is the sum over
             * COMPLETED handler calls, so avg_us is a cost per fault and not a partial one. */
            ULONG64 total = __atomic_load_n( &macrunner_hb_fault_total_ns, __ATOMIC_RELAXED );
            ULONG64 done = n - 1;

            macrunner_signal_writef(
                "macrunner-hb-faultrate: entries=%llu elapsed_ms=%llu rate=%llu/s"
                " avg_us=%llu busy_pct=%llu accerr=%llu maperr=%llu other=%llu"
                " ill=%llu bus=%llu trap=%llu segv_other=%llu"
                " adraln=%llu adrerr=%llu objerr=%llu buscode_other=%llu"
                " pages_distinct=%llu same_page=%llu x18_heal=%llu\n",
                (unsigned long long)n, (unsigned long long)ms,
                (unsigned long long)(ms ? (n * 1000ull) / ms : 0),
                (unsigned long long)(done ? (total / done) / 1000ull : 0),
                (unsigned long long)(ms ? (total / 1000000ull) * 100ull / ms : 0),
                (unsigned long long)__atomic_load_n( &macrunner_hb_fault_accerr, __ATOMIC_RELAXED ),
                (unsigned long long)__atomic_load_n( &macrunner_hb_fault_maperr, __ATOMIC_RELAXED ),
                (unsigned long long)__atomic_load_n( &macrunner_hb_fault_otherkind, __ATOMIC_RELAXED ),
                (unsigned long long)__atomic_load_n( &macrunner_hb_fault_sigill, __ATOMIC_RELAXED ),
                (unsigned long long)__atomic_load_n( &macrunner_hb_fault_sigbus, __ATOMIC_RELAXED ),
                (unsigned long long)__atomic_load_n( &macrunner_hb_fault_sigtrap, __ATOMIC_RELAXED ),
                (unsigned long long)__atomic_load_n( &macrunner_hb_fault_sigsegv_other, __ATOMIC_RELAXED ),
                (unsigned long long)__atomic_load_n( &macrunner_hb_fault_bus_adraln, __ATOMIC_RELAXED ),
                (unsigned long long)__atomic_load_n( &macrunner_hb_fault_bus_adrerr, __ATOMIC_RELAXED ),
                (unsigned long long)__atomic_load_n( &macrunner_hb_fault_bus_objerr, __ATOMIC_RELAXED ),
                (unsigned long long)__atomic_load_n( &macrunner_hb_fault_bus_othercode, __ATOMIC_RELAXED ),
                (unsigned long long)__atomic_load_n( &macrunner_hb_fault_pages_distinct, __ATOMIC_RELAXED ),
                (unsigned long long)__atomic_load_n( &macrunner_hb_fault_same_page_repeat, __ATOMIC_RELAXED ),
                (unsigned long long)__atomic_load_n( &macrunner_hb_fault_x18_heal, __ATOMIC_RELAXED ) );
            /* The page census is bulky, so it rides the summary at a coarser cadence: often enough
             * to catch the storm's shape, rare enough not to become the storm's own cost. */
            if (!(n & 0x3ffff)) macrunner_hb_fault_top_emit();
        }
    }

    if (macrunner_hb_present_signal_probe_enabled_for_current_thread())
    {
        static __thread unsigned int signal_count;
        unsigned int count = ++signal_count;

        if (count <= 128 || (!(count & 0x3ff) && count <= 131072))
            macrunner_signal_writef(
                "macrunner-hb-present-signal-probe: hit=%u sig=%d code=%d "
                "pc=%p fault=%p lr=%p sp=%p x0=%p x1=%p x4=%p x16=%p x18=%p\n",
                count, sig, siginfo ? siginfo->si_code : 0,
                (void *)(ULONG_PTR)PC_sig(context), (void *)fault_addr,
                (void *)(ULONG_PTR)LR_sig(context), (void *)(ULONG_PTR)SP_sig(context),
                (void *)(ULONG_PTR)REGn_sig(0, context),
                (void *)(ULONG_PTR)REGn_sig(1, context),
                (void *)(ULONG_PTR)REGn_sig(4, context),
                (void *)(ULONG_PTR)REGn_sig(16, context),
                (void *)(ULONG_PTR)REGn_sig(18, context) );
    }

    /* MacRunner diag: does ANY signal handler see the NULL-target (pc=0) fault? */
    {
        ULONG_PTR pcv = PC_sig( (ucontext_t *)sigcontext );
        if ((pcv < 0x10000 || fault_addr < 0x10000) && pcv != fault_addr)
        {
            static int prim_n;
            HB_PROBE_LOOKED(&pr_nullcall_prim);
            if (macrunner_hb_trace_nullcall_enabled() && prim_n++ < 16)
            {
                HB_PROBE_SAY( &pr_nullcall_prim, "sig=%d pc=%p fault=%p lr=%p\n",
                              sig, (void *)pcv, (void *)fault_addr,
                              (void *)(ULONG_PTR)LR_sig( (ucontext_t *)sigcontext ) );
                fflush( stderr );
            }
        }
    }

    if (macrunner_hb_route_x64_callback_fault( sigcontext, fault_addr,
                                               macrunner_hb_signal_source( sig ) ))
        return;

    if (macrunner_hb_primary_signal_trace && macrunner_hb_trace_signal_chain_enabled())
        fprintf( stderr, "macrunner-hb-signal-chain: pid=%d sig=%d pc=%p fault=%p\n",
                 getpid(), sig, (void *)(ULONG_PTR)PC_sig((ucontext_t *)sigcontext),
                 (void *)(ULONG_PTR)fault_addr );
    macrunner_hb_chain_signal( sig, siginfo, sigcontext );
}

#if defined(__APPLE__) && defined(__aarch64__)
static void macrunner_hb_start_arm64ec_spin_watchdog(void);
#endif

static void macrunner_hb_install_primary_signal_handlers( const char *stage, BOOL x64_image_trigger )
{
    struct sigaction sig_act;
    BOOL macrunner_trace;
    int segv_rc, ill_rc, bus_rc;

    if (!macrunner_hb_x64_loader_enabled()) return;
    if (!x64_image_trigger && !macrunner_hb_x64_guest_process()) return;
    if (macrunner_hb_wine_signal_handlers_ready)
    {
        if (macrunner_hb_primary_signal_post_wine_installed) return;
    }
    else if (macrunner_hb_primary_signal_pre_wine_installed) return;

    macrunner_trace = macrunner_hb_trace_callback_route_enabled() ||
                      (macrunner_hb_getenv( "MACRUNNER_HB_TRACE_HOST_EXEC" ) &&
                       macrunner_hb_getenv( "MACRUNNER_HB_TRACE_HOST_EXEC" )[0] &&
                       macrunner_hb_getenv( "MACRUNNER_HB_TRACE_HOST_EXEC" )[0] != '0');
    macrunner_hb_primary_signal_trace = macrunner_trace;
    fprintf( stderr, "macrunner-hb-signal-init: pid=%d stage=%s-start trace=%d\n",
             getpid(), stage, macrunner_trace );

    /* MacRunner Lane A (nested-exception spin fix, 2026-06-12): mask SIGSEGV/SIGBUS
     * while this handler runs (drop SA_NODEFER).  On Apple, macOS wipes x18 on
     * sigreturn so PE code takes a dense storm of healable x18/TEB faults; if a
     * GENUINE guest access-violation (e.g. Mono-JIT deref of a NULL/garbage pointer)
     * fires WHILE the handler is still dispatching a preceding fault on the SA_ONSTACK
     * signal stack, SA_NODEFER let it pre-empt re-entrantly.  Its saved SP is then in
     * the signal-stack band, so virtual_setup_exception sees is_inside_signal_stack()
     * and calls abort_thread(1) -> the main thread dies and the boot spins to timeout
     * (stochastic ~1/2).  Masking defers the second fault until after sigreturn, when
     * SP is back on the thread stack, so it dispatches as an ordinary in-guest SEH AV
     * instead of aborting.  The x18-heal paths never deliberately re-fault (they only
     * touch already-mapped TEB + patch sigcontext), so masking is safe; this matches
     * upstream Wine's segv_handler posture (no SA_NODEFER). */
    sigemptyset( &sig_act.sa_mask );
    sigaddset( &sig_act.sa_mask, SIGSEGV );
    sigaddset( &sig_act.sa_mask, SIGBUS );
    sig_act.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
    sig_act.sa_sigaction = macrunner_hb_primary_signal_handler;

    segv_rc = sigaction( SIGSEGV, &sig_act, &macrunner_hb_prev_segv_action );
    /* Leave SIGILL directly owned by Wine.  Native ARM64 PE uses SIGILL in
     * startup/exception-dispatch paths, while x64 no-exec boundary faults are
     * delivered as SIGBUS/SIGSEGV on macOS.  Wine's own ill_handler still
     * routes guest x64 PCs through HyperBridge if that ever appears. */
    ill_rc = 0;
    bus_rc = sigaction( SIGBUS, &sig_act, &macrunner_hb_prev_bus_action );
    if (macrunner_hb_wine_signal_handlers_ready)
        macrunner_hb_primary_signal_post_wine_installed = TRUE;
    else
        macrunner_hb_primary_signal_pre_wine_installed = TRUE;
    macrunner_hb_note_x64_guest_fault_handlers_ready();

    fprintf( stderr, "macrunner-hb-signal-init: pid=%d stage=%s-primary-installed rc=%d/%d/%d\n",
             getpid(), stage, segv_rc, ill_rc, bus_rc );
#if defined(__APPLE__) && defined(__aarch64__)
    macrunner_hb_start_arm64ec_spin_watchdog();
#endif
}

void macrunner_hb_prepare_x64_guest_fault_handlers( const char *stage )
{
    macrunner_hb_install_primary_signal_handlers( stage, TRUE );
}
#endif

#if defined(__APPLE__) && defined(__aarch64__)
static void macrunner_hb_trace_arm64ec_watchdog_bytes( mach_vm_address_t addr, char *buf,
                                                       size_t buf_size )
{
    uint8_t bytes[32];
    mach_vm_size_t out_size = 0;
    kern_return_t kr;
    size_t i, pos = 0;

    if (!buf_size) return;
    buf[0] = 0;
    kr = mach_vm_read_overwrite( mach_task_self(), addr, sizeof(bytes),
                                 (mach_vm_address_t)(uintptr_t)bytes, &out_size );
    if (kr != KERN_SUCCESS)
    {
        snprintf( buf, buf_size, "read=%d", kr );
        return;
    }
    for (i = 0; i < out_size && pos + 3 < buf_size; i++)
        pos += snprintf( buf + pos, buf_size - pos, "%02x", bytes[i] );
}

static void macrunner_hb_trace_arm64ec_watchdog_ascii( mach_vm_address_t addr, char *buf,
                                                       size_t buf_size )
{
    uint8_t bytes[48];
    mach_vm_size_t out_size = 0;
    kern_return_t kr;
    size_t i, pos = 0;

    if (!buf_size) return;
    buf[0] = 0;
    if (!addr)
    {
        snprintf( buf, buf_size, "null" );
        return;
    }

    kr = mach_vm_read_overwrite( mach_task_self(), addr, sizeof(bytes),
                                 (mach_vm_address_t)(uintptr_t)bytes, &out_size );
    if (kr != KERN_SUCCESS)
    {
        snprintf( buf, buf_size, "read=%d", kr );
        return;
    }

    for (i = 0; i < out_size && pos + 2 < buf_size; i++)
    {
        uint8_t c = bytes[i];

        if (!c) break;
        buf[pos++] = (c >= 0x21 && c <= 0x7e) ? (char)c : '.';
    }
    buf[pos] = 0;
}

static unsigned int macrunner_hb_arm64ec_watchdog_env_u32( const char *name, unsigned int fallback,
                                                           unsigned int min_value, unsigned int max_value )
{
    const char *env = macrunner_hb_getenv( name );
    char *end;
    unsigned long value;

    if (!env || !env[0]) return fallback;
    value = strtoul( env, &end, 0 );
    if (end == env) return fallback;
    if (value < min_value) value = min_value;
    if (value > max_value) value = max_value;
    return (unsigned int)value;
}

static void *macrunner_hb_arm64ec_spin_watchdog_thread( void *arg )
{
    unsigned int delay_ms = macrunner_hb_arm64ec_watchdog_env_u32(
        "MACRUNNER_HB_TRACE_ARM64EC_SPIN_WATCHDOG_DELAY_MS", 3000, 0, 600000 );
    unsigned int interval_ms = macrunner_hb_arm64ec_watchdog_env_u32(
        "MACRUNNER_HB_TRACE_ARM64EC_SPIN_WATCHDOG_INTERVAL_MS", 1000, 10, 60000 );
    unsigned int sample_count = macrunner_hb_arm64ec_watchdog_env_u32(
        "MACRUNNER_HB_TRACE_ARM64EC_SPIN_WATCHDOG_SAMPLES", 30, 1, 10000 );
    int sample, thread_index;

    (void)arg;
    usleep( (useconds_t)delay_ms * 1000 );
    for (sample = 0; sample < sample_count; sample++)
    {
        thread_act_array_t threads = NULL;
        mach_msg_type_number_t thread_count = 0;
        kern_return_t kr = task_threads( mach_task_self(), &threads, &thread_count );

        if (kr != KERN_SUCCESS)
        {
            fprintf( stderr, "macrunner-hb-arm64ec-watchdog: sample=%d task_threads=%d\n",
                     sample, kr );
            fflush( stderr );
            usleep( (useconds_t)interval_ms * 1000 );
            continue;
        }
        for (thread_index = 0; thread_index < thread_count; thread_index++)
        {
            arm_thread_state64_t state;
            mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
            char bytes[80];
            char x0s[80], x1s[80], x14s[80], x20s[80];
            uint64_t pc;

            if (threads[thread_index] == mach_thread_self()) continue;
            kr = thread_get_state( threads[thread_index], ARM_THREAD_STATE64,
                                   (thread_state_t)&state, &state_count );
            if (kr != KERN_SUCCESS) continue;
            pc = state.__pc;
            if (pc < 0x0000080000000000ULL) continue;
            macrunner_hb_trace_arm64ec_watchdog_bytes( (mach_vm_address_t)(pc & ~3ULL),
                                                       bytes, sizeof(bytes) );
            macrunner_hb_trace_arm64ec_watchdog_ascii( (mach_vm_address_t)state.__x[0],
                                                       x0s, sizeof(x0s) );
            macrunner_hb_trace_arm64ec_watchdog_ascii( (mach_vm_address_t)state.__x[1],
                                                       x1s, sizeof(x1s) );
            macrunner_hb_trace_arm64ec_watchdog_ascii( (mach_vm_address_t)state.__x[14],
                                                       x14s, sizeof(x14s) );
            macrunner_hb_trace_arm64ec_watchdog_ascii( (mach_vm_address_t)state.__x[20],
                                                       x20s, sizeof(x20s) );
            fprintf( stderr, "macrunner-hb-arm64ec-watchdog: pid=%d sample=%d thread=%d "
                      "pc=%p lr=%p sp=%p x0=%p x1=%p x2=%p x3=%p x4=%p "
                      "x8=%p x9=%p x10=%p x11=%p x12=%p x13=%p x14=%p "
                      "x16=%p x18=%p x20=%p x0s=%s x1s=%s x14s=%s x20s=%s bytes=%s\n",
                      getpid(), sample, thread_index, (void *)(uintptr_t)pc,
                      (void *)(uintptr_t)state.__lr, (void *)(uintptr_t)state.__sp,
                      (void *)(uintptr_t)state.__x[0], (void *)(uintptr_t)state.__x[1],
                      (void *)(uintptr_t)state.__x[2], (void *)(uintptr_t)state.__x[3],
                      (void *)(uintptr_t)state.__x[4], (void *)(uintptr_t)state.__x[8],
                      (void *)(uintptr_t)state.__x[9], (void *)(uintptr_t)state.__x[10],
                      (void *)(uintptr_t)state.__x[11], (void *)(uintptr_t)state.__x[12],
                      (void *)(uintptr_t)state.__x[13], (void *)(uintptr_t)state.__x[14],
                      (void *)(uintptr_t)state.__x[16], (void *)(uintptr_t)state.__x[18],
                      (void *)(uintptr_t)state.__x[20], x0s, x1s, x14s, x20s, bytes );
            fflush( stderr );
        }
        if (threads)
            vm_deallocate( mach_task_self(), (vm_address_t)threads,
                           thread_count * sizeof(*threads) );
        usleep( (useconds_t)interval_ms * 1000 );
    }
    return NULL;
}

static void macrunner_hb_start_arm64ec_spin_watchdog(void)
{
    static BOOL started;
    pthread_t thread;
    const char *env = macrunner_hb_getenv( "MACRUNNER_HB_TRACE_ARM64EC_SPIN_WATCHDOG" );

    if (started || !env || !env[0] || env[0] == '0') return;
    started = TRUE;
    if (!pthread_create( &thread, NULL, macrunner_hb_arm64ec_spin_watchdog_thread, NULL ))
        pthread_detach( thread );
}
#endif

void signal_init_threading(void)
{
#if defined(__APPLE__) && defined(__aarch64__)
    macrunner_enable_windows_x18_abi();
    macrunner_x18_trust_abi_init();
#endif
#if defined(__APPLE__) && defined(__aarch64__)
    macrunner_hb_install_primary_signal_handlers( "early-threading", FALSE );
#endif
}


/**********************************************************************
 *             signal_alloc_thread
 */
NTSTATUS signal_alloc_thread( TEB *teb )
{
    return STATUS_SUCCESS;
}


/**********************************************************************
 *             signal_free_thread
 */
void signal_free_thread( TEB *teb )
{
#ifdef __APPLE__
    mr_direct_release( (ULONG_PTR)teb );
#endif
}


/**********************************************************************
 *		signal_init_process
 */
void signal_init_process(void)
{
#ifdef __APPLE__
    /* Главный поток не проходит через start_thread — взводим сторожа и здесь. */
    macrunner_m0_init();
    macrunner_hb_watch_arm( "signal_init_process" );
    {   /* адрес слежения читаем ОДИН раз: getenv в горячем пути уже ронял три процесса */
        const char *e = getenv( "MACRUNNER_HB_WATCH" );
        if (e && *e) macrunner_hb_watch_addr = (ULONG_PTR)strtoull( e, NULL, 0 );
        e = getenv( "MACRUNNER_HB_WATCH_LR" );
        if (e && *e) macrunner_hb_watch_lr = (ULONG_PTR)strtoull( e, NULL, 0 );
        e = getenv( "MACRUNNER_HB_PROT_WATCH" );
        if (e && *e && *e != '0') macrunner_hb_prot_gate = 1;
        e = getenv( "MACRUNNER_HB_PROT_EVERY" );
        if (e && *e) { unsigned int v_ = (unsigned int)strtoul( e, NULL, 0 );
                       if (v_) macrunner_hb_prot_every = v_; }
        e = getenv( "MACRUNNER_HB_SLOT_CHECK" );
        if (e && *e && *e != '0') macrunner_hb_slot_gate = 1;
        e = getenv( "MACRUNNER_HB_WATCH_AFTER" );
        if (e && *e) macrunner_hb_watch_after = (unsigned int)strtoul( e, NULL, 0 );
    }
#endif
    struct sigaction sig_act;
    struct ntdll_thread_data *thread_data = ntdll_get_thread_data();
    void *kernel_stack = (char *)thread_data->kernel_stack + kernel_stack_size;
    BOOL macrunner_trace = macrunner_hb_trace_callback_route_enabled();

    if (macrunner_trace)
        fprintf( stderr, "macrunner-hb-signal-init: pid=%d stage=start\n", getpid() );

    thread_data->syscall_frame = (struct syscall_frame *)kernel_stack - 1;

    signal_alloc_thread( NtCurrentTeb() );
    if (macrunner_trace)
        fprintf( stderr, "macrunner-hb-signal-init: pid=%d stage=thread-allocated\n", getpid() );

    sig_act.sa_mask = server_block_set;
    sig_act.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;

    sig_act.sa_sigaction = int_handler;
    if (sigaction( SIGINT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = fpe_handler;
    if (sigaction( SIGFPE, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = abrt_handler;
    if (sigaction( SIGABRT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = quit_handler;
    if (sigaction( SIGQUIT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = usr1_handler;
    if (sigaction( SIGUSR1, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = usr2_handler;
    if (sigaction( SIGUSR2, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = trap_handler;
    if (sigaction( SIGTRAP, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = segv_handler;
    if (sigaction( SIGSEGV, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = ill_handler;
    if (sigaction( SIGILL, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = bus_handler;
    if (sigaction( SIGBUS, &sig_act, NULL ) == -1) goto error;
#if defined(__APPLE__) && defined(__aarch64__)
    macrunner_hb_wine_signal_handlers_ready = TRUE;
    macrunner_hb_primary_signal_pre_wine_installed = FALSE;
    macrunner_hb_install_primary_signal_handlers( "wine-process", FALSE );
    macrunner_hb_start_arm64ec_spin_watchdog();
#else
    macrunner_hb_note_x64_guest_fault_handlers_ready();
#endif
    if (macrunner_trace)
        fprintf( stderr, "macrunner-hb-signal-init: pid=%d stage=installed-segv-ill-bus\n", getpid() );
    macrunner_m0_control_maybe_run();
    return;

 error:
    perror("sigaction");
    exit(1);
}


/***********************************************************************
 *           syscall_dispatcher_return_slowpath
 */
void syscall_dispatcher_return_slowpath(void)
{
    /* ★ СТЕНА64: медленный путь — ЕДИНСТВЕННОЕ место, где x16/x17 могут получить
     * значения, отличные от pc и sp. Печатаем, зовут ли его вообще на возобновлении
     * гостя и с какими x16/x17. Молчание здесь = быстрый путь, то есть x17 обречён. */
    {
        static __thread unsigned int mr_st64_slow_n;
        struct syscall_frame *f = get_syscall_frame();
        if (++mr_st64_slow_n <= 16)
        {
            fprintf( stderr, "macrunner-st64-slowpath: n=%u pc=%#llx sp=%#llx x16=%#llx x17=%#llx\n",
                     mr_st64_slow_n, (unsigned long long)f->pc, (unsigned long long)f->sp,
                     (unsigned long long)f->x[16], (unsigned long long)f->x[17] );
            fflush( stderr );
        }
    }
    raise( SIGUSR2 );
}

/***********************************************************************
 *           init_syscall_frame
 */
void init_syscall_frame( LPTHREAD_START_ROUTINE entry, void *arg, BOOL suspend, TEB *teb )
{
    struct syscall_frame *frame = ((struct ntdll_thread_data *)&teb->GdiTebBatch)->syscall_frame;
    CONTEXT *ctx, context = { CONTEXT_ALL };
    I386_CONTEXT *i386_context;
    ARM_CONTEXT *arm_context;

#if defined(__APPLE__) && defined(__aarch64__)
    macrunner_enable_windows_x18_abi();
#endif
    context.X0  = (DWORD64)entry;
    context.X1  = (DWORD64)arg;
    context.X18 = (DWORD64)teb;
    context.Sp  = (DWORD64)teb->Tib.StackBase;
    context.Pc  = (DWORD64)pRtlUserThreadStart;

    if ((i386_context = get_cpu_area( IMAGE_FILE_MACHINE_I386 )))
    {
        XMM_SAVE_AREA32 *fpu = (XMM_SAVE_AREA32 *)i386_context->ExtendedRegisters;
        i386_context->ContextFlags = CONTEXT_I386_ALL;
        i386_context->Eax = (ULONG_PTR)entry;
        i386_context->Ebx = (arg == peb ? (ULONG_PTR)wow_peb : (ULONG_PTR)arg);
        i386_context->Esp = get_wow_teb( teb )->Tib.StackBase - 16;
        i386_context->Eip = pLdrSystemDllInitBlock->pRtlUserThreadStart;
        i386_context->SegCs = 0x23;
        i386_context->SegDs = 0x2b;
        i386_context->SegEs = 0x2b;
        i386_context->SegFs = 0x53;
        i386_context->SegGs = 0x2b;
        i386_context->SegSs = 0x2b;
        i386_context->EFlags = 0x202;
        fpu->ControlWord = 0x27f;
        fpu->MxCsr = 0x1f80;
        fpux_to_fpu( &i386_context->FloatSave, fpu );
    }
    else if ((arm_context = get_cpu_area( IMAGE_FILE_MACHINE_ARMNT )))
    {
        arm_context->ContextFlags = CONTEXT_ARM_ALL;
        arm_context->R0 = (ULONG_PTR)entry;
        arm_context->R1 = (arg == peb ? (ULONG_PTR)wow_peb : (ULONG_PTR)arg);
        arm_context->Sp = get_wow_teb( teb )->Tib.StackBase;
        arm_context->Pc = pLdrSystemDllInitBlock->pRtlUserThreadStart;
        if (arm_context->Pc & 1) arm_context->Cpsr |= 0x20; /* thumb mode */
    }

    if (suspend)
    {
        context.ContextFlags |= CONTEXT_EXCEPTION_REPORTING | CONTEXT_EXCEPTION_ACTIVE;
        wait_suspend( &context );
    }

    ctx = (CONTEXT *)((ULONG_PTR)context.Sp & ~15) - 1;
    *ctx = context;
    ctx->ContextFlags = CONTEXT_FULL | CONTEXT_ARM64_X18;
    signal_set_full_context( ctx );

    frame->sp    = (ULONG64)ctx;
    frame->pc    = (ULONG64)pLdrInitializeThunk;
    frame->x[0]  = (ULONG64)ctx;
    frame->x[18] = (ULONG64)teb;
    syscall_frame_fixup_for_fastpath( frame );

    pthread_sigmask( SIG_UNBLOCK, &server_block_set, NULL );
}


/***********************************************************************
 *           signal_start_thread
 */
__ASM_GLOBAL_FUNC( signal_start_thread,
                   "stp x29, x30, [sp,#-0xc0]!\n\t"
                   __ASM_CFI(".cfi_def_cfa_offset 0xc0\n\t")
                   __ASM_CFI(".cfi_offset 29,-0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xb8\n\t")
                   "mov x29, sp\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   "stp x19, x20, [x29, #0x10]\n\t"
                   __ASM_CFI(".cfi_rel_offset 19,0x10\n\t")
                   __ASM_CFI(".cfi_rel_offset 20,0x18\n\t")
                   "stp x21, x22, [x29, #0x20]\n\t"
                   __ASM_CFI(".cfi_rel_offset 21,0x20\n\t")
                   __ASM_CFI(".cfi_rel_offset 22,0x28\n\t")
                   "stp x23, x24, [x29, #0x30]\n\t"
                   __ASM_CFI(".cfi_rel_offset 23,0x30\n\t")
                   __ASM_CFI(".cfi_rel_offset 24,0x38\n\t")
                   "stp x25, x26, [x29, #0x40]\n\t"
                   __ASM_CFI(".cfi_rel_offset 25,0x40\n\t")
                   __ASM_CFI(".cfi_rel_offset 26,0x48\n\t")
                   "stp x27, x28, [x29, #0x50]\n\t"
                   __ASM_CFI(".cfi_rel_offset 27,0x50\n\t")
                   __ASM_CFI(".cfi_rel_offset 28,0x58\n\t")
                   "add x5, x29, #0xc0\n\t"     /* syscall_cfa */
                   /* set syscall frame */
                   "ldr x4, [x3, #0x378]\n\t"   /* thread_data->syscall_frame */
                   "cbnz x4, 1f\n\t"
                   "sub x4, sp, #0x330\n\t"     /* sizeof(struct syscall_frame) */
                   "str x4, [x3, #0x378]\n\t"   /* thread_data->syscall_frame */
                   "1:\tstr wzr, [x4, #0x10c]\n\t" /* frame->restore_flags */
                   "stp xzr, x5, [x4, #0x110]\n\t" /* frame->prev_frame,syscall_cfa */
                   /* switch to kernel stack */
                   "mov sp, x4\n\t"
                   "bl " __ASM_NAME("init_syscall_frame") "\n\t"
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") )


/***********************************************************************
 *           __wine_syscall_dispatcher
 */
__ASM_GLOBAL_FUNC( __wine_syscall_dispatcher,
                   "hint 34\n\t" /* bti c */
                   WINE_LOAD_TEB_IN_X17
                   "ldr x10, [x17, #0x378]\n\t" /* thread_data->syscall_frame */
                   "stp x17, x19, [x10, #0x90]\n\t"
                   "stp x20, x21, [x10, #0xa0]\n\t"
                   "stp x22, x23, [x10, #0xb0]\n\t"
                   "stp x24, x25, [x10, #0xc0]\n\t"
                   "stp x26, x27, [x10, #0xd0]\n\t"
                   "stp x28, x29, [x10, #0xe0]\n\t"
                   "mov x19, sp\n\t"
                   "stp x9, x19, [x10, #0xf0]\n\t"
                   /* ★★★★★★ 01.09 — СЧЁТЧИК ВХОДОВ В КАДР.
                    * Замер: поле `sp` в кадре меняется между входом и выходом ОДНОГО вызова, а все
                    * писатели этого поля из C не исполнялись — значит в ЗАНЯТЫЙ кадр вошёл второй
                    * системный вызов и переписал sp своим (`stp x9, x19` строкой выше). Считаем входы
                    * в поле `align` (0x124) — чистая набивка, нигде не используется. Три инструкции;
                    * x9 здесь уже сохранён и до `mrs x9, NZCV` мёртв. */
                   "ldr w9, [x10, #0x124]\n\t"
                   "add w9, w9, #1\n\t"
                   "str w9, [x10, #0x124]\n\t"
                   "mrs x9, NZCV\n\t"
                   "stp x30, x9, [x10, #0x100]\n\t"
                   "str w8, [x10, #0x120]\n\t"
                   "mrs x9, FPCR\n\t"
                   "str w9, [x10, #0x128]\n\t"
                   "mrs x9, FPSR\n\t"
                   "str w9, [x10, #0x12c]\n\t"
                   "stp q0,  q1,  [x10, #0x130]\n\t"
                   "stp q2,  q3,  [x10, #0x150]\n\t"
                   "stp q4,  q5,  [x10, #0x170]\n\t"
                   "stp q6,  q7,  [x10, #0x190]\n\t"
                   "stp q8,  q9,  [x10, #0x1b0]\n\t"
                   "stp q10, q11, [x10, #0x1d0]\n\t"
                   "stp q12, q13, [x10, #0x1f0]\n\t"
                   "stp q14, q15, [x10, #0x210]\n\t"
                   "stp q16, q17, [x10, #0x230]\n\t"
                   "stp q18, q19, [x10, #0x250]\n\t"
                   "stp q20, q21, [x10, #0x270]\n\t"
                   "stp q22, q23, [x10, #0x290]\n\t"
                   "stp q24, q25, [x10, #0x2b0]\n\t"
                   "stp q26, q27, [x10, #0x2d0]\n\t"
                   "stp q28, q29, [x10, #0x2f0]\n\t"
                   "stp q30, q31, [x10, #0x310]\n\t"
                   "mov x22, x10\n\t"
                   /* switch to kernel stack */
                   ".alt_entry " __ASM_NAME("__wine_syscall_dispatcher_prefix_end") "\n\t"
                   __ASM_GLOBL( __ASM_NAME("__wine_syscall_dispatcher_prefix_end") ) "\n\t"
                   "mov sp, x10\n\t"
                   /* we're now on the kernel stack, stitch unwind info with previous frame */
                   __ASM_CFI_CFA_IS_AT2(x22, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_CFI(".cfi_offset 29, -0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30, -0xb8\n\t")
                   __ASM_CFI(".cfi_offset 19, -0xb0\n\t")
                   __ASM_CFI(".cfi_offset 20, -0xa8\n\t")
                   __ASM_CFI(".cfi_offset 21, -0xa0\n\t")
                   __ASM_CFI(".cfi_offset 22, -0x98\n\t")
                   __ASM_CFI(".cfi_offset 23, -0x90\n\t")
                   __ASM_CFI(".cfi_offset 24, -0x88\n\t")
                   __ASM_CFI(".cfi_offset 25, -0x80\n\t")
                   __ASM_CFI(".cfi_offset 26, -0x78\n\t")
                   __ASM_CFI(".cfi_offset 27, -0x70\n\t")
                   __ASM_CFI(".cfi_offset 28, -0x68\n\t")
                   "and x20, x8, #0xfff\n\t"    /* syscall number */
                   "ubfx x21, x8, #12, #2\n\t"  /* syscall table number */
                   "mov x18, x17\n\t"            /* x18 is Apple-volatile; x17 holds TEB */
                   "ldr x16, [x18, #0x370]\n\t" /* thread_data->syscall_table */
                   "add x21, x16, x21, lsl #5\n\t"
                   "ldr x16, [x21, #16]\n\t"    /* table->ServiceLimit */
                   "cmp x20, x16\n\t"
                   "bcs " __ASM_LOCAL_LABEL("bad_syscall") "\n\t"
                   "ldr x16, [x21, #24]\n\t"    /* table->ArgumentTable */
                   "ldrb w9, [x16, x20]\n\t"
                   "subs x9, x9, #64\n\t"
                   "bls 2f\n\t"
                   "sub sp, sp, x9\n\t"
                   "tbz x9, #3, 1f\n\t"
                   "sub sp, sp, #8\n"
                   "1:\tsub x9, x9, #8\n\t"
                   "ldr x10, [x19, x9]\n\t"
                   "str x10, [sp, x9]\n\t"
                   "cbnz x9, 1b\n"
                   "2:\tldr x16, [x21]\n\t"     /* table->ServiceTable */
                   "ldr x23, [x16, x20, lsl 3]\n\t"
                   "mov x18, x17\n\t"            /* x18 is Apple-volatile; x17 holds TEB */
                   "ldr w11, [x18, #0x380]\n\t" /* thread_data->syscall_trace */
                   "cbnz x11, " __ASM_LOCAL_LABEL("trace_syscall") "\n\t"
                   "blr x23\n\t"
                   "mov sp, x22\n"
                   __ASM_CFI_CFA_IS_AT2(sp, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") ":\n\t"
                   "ldr w16, [sp, #0x10c]\n\t"  /* frame->restore_flags */
                   "tbz x16, #1, 2f\n\t"        /* CONTEXT_INTEGER */
                   "ldp x12, x13, [sp, #0x80]\n\t" /* frame->x[16..17] */
                   "ldp x14, x15, [sp, #0xf8]\n\t" /* frame->sp, frame->pc */
                   "cmp x12, x15\n\t"              /* frame->x16 == frame->pc? */
                   "ccmp x13, x14, #0, eq\n\t"     /* frame->x17 == frame->sp? */
                   "beq 1f\n\t"                    /* take slowpath if unequal */
                   "bl " __ASM_NAME("syscall_dispatcher_return_slowpath") "\n"
                   "1:\tldp x0, x1, [sp, #0x00]\n\t"
                   "ldp x2, x3, [sp, #0x10]\n\t"
                   "ldp x4, x5, [sp, #0x20]\n\t"
                   "ldp x6, x7, [sp, #0x30]\n\t"
                   "ldp x8, x9, [sp, #0x40]\n\t"
                   "ldp x10, x11, [sp, #0x50]\n\t"
                   "ldp x12, x13, [sp, #0x60]\n\t"
                   "ldp x14, x15, [sp, #0x70]\n"
                   "2:\tldp x18, x19, [sp, #0x90]\n\t"
                   "ldp x20, x21, [sp, #0xa0]\n\t"
                   "ldp x22, x23, [sp, #0xb0]\n\t"
                   "ldp x24, x25, [sp, #0xc0]\n\t"
                   "ldp x26, x27, [sp, #0xd0]\n\t"
                   "ldp x28, x29, [sp, #0xe0]\n\t"
                   "tbz x16, #2, 1f\n\t"        /* CONTEXT_FLOATING_POINT */
                   "ldp q0,  q1,  [sp, #0x130]\n\t"
                   "ldp q2,  q3,  [sp, #0x150]\n\t"
                   "ldp q4,  q5,  [sp, #0x170]\n\t"
                   "ldp q6,  q7,  [sp, #0x190]\n\t"
                   "ldp q8,  q9,  [sp, #0x1b0]\n\t"
                   "ldp q10, q11, [sp, #0x1d0]\n\t"
                   "ldp q12, q13, [sp, #0x1f0]\n\t"
                   "ldp q14, q15, [sp, #0x210]\n\t"
                   "ldp q16, q17, [sp, #0x230]\n\t"
                   "ldp q18, q19, [sp, #0x250]\n\t"
                   "ldp q20, q21, [sp, #0x270]\n\t"
                   "ldp q22, q23, [sp, #0x290]\n\t"
                   "ldp q24, q25, [sp, #0x2b0]\n\t"
                   "ldp q26, q27, [sp, #0x2d0]\n\t"
                   "ldp q28, q29, [sp, #0x2f0]\n\t"
                   "ldp q30, q31, [sp, #0x310]\n\t"
                   "ldr w17, [sp, #0x128]\n\t"
                   "msr FPCR, x17\n\t"
                   "ldr w17, [sp, #0x12c]\n\t"
                   "msr FPSR, x17\n"
                   "1:\tldp x16, x17, [sp, #0x100]\n\t"
                   "msr NZCV, x17\n\t"
                   "ldp x30, x17, [sp, #0xf0]\n\t"
                   /* frame->x18 was populated from x17 (the entry TEB), not
                    * from the Apple-volatile incoming x18.  Do not call a
                    * host helper here: that would overwrite the authoritative
                    * saved TEB immediately before returning to ARM64 PE code. */
                   /* switch to user stack */
                   "mov sp, x17\n\t"
                   "ret x16\n"

                   __ASM_LOCAL_LABEL("trace_syscall") ":\n\t"
                   "stp x0, x1, [sp, #-0x40]!\n\t"
                   "stp x2, x3, [sp, #0x10]\n\t"
                   "stp x4, x5, [sp, #0x20]\n\t"
                   "stp x6, x7, [sp, #0x30]\n\t"
                   "mov x0, x8\n\t"             /* id */
                   "mov x1, sp\n\t"             /* args */
                   "ldr x16, [x21, #24]\n\t"    /* table->ArgumentTable */
                   "ldrb w2, [x16, x20]\n\t"    /* len */
                   "bl " __ASM_NAME("trace_syscall") "\n\t"
                   "ldp x2, x3, [sp, #0x10]\n\t"
                   "ldp x4, x5, [sp, #0x20]\n\t"
                   "ldp x6, x7, [sp, #0x30]\n\t"
                   "ldp x0, x1, [sp], #0x40\n\t"
                   "blr x23\n"
                   "mov sp, x22\n"

                   __ASM_LOCAL_LABEL("trace_syscall_ret") ":\n\t"
                   "mov x21, x0\n\t"            /* retval */
                   "ldr w0, [sp, #0x120]\n\t"   /* frame->syscall_id */
                   "mov x1, x21\n\t"            /* retval */
                   "bl " __ASM_NAME("trace_sysret") "\n\t"
                   "mov x0, x21\n\t"            /* retval */
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") "\n"

                   __ASM_LOCAL_LABEL("bad_syscall") ":\n\t"
                   "mov x0, #0xc0000000\n\t"    /* STATUS_INVALID_SYSTEM_SERVICE */
                   "movk x0, #0x001c\n\t"
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") )

__ASM_GLOBAL_FUNC( __wine_syscall_dispatcher_return,
                   WINE_RESTORE_X18_IF_ZERO
                   "ldr w11, [x18, #0x380]\n\t" /* thread_data->syscall_trace */
                   "cbnz x11, " __ASM_LOCAL_LABEL("trace_syscall_ret") "\n\t"
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") )


/***********************************************************************
 *           __wine_unix_call_dispatcher
 */
__ASM_GLOBAL_FUNC( __wine_unix_call_dispatcher,
                   "hint 34\n\t" /* bti c */
                   WINE_RESTORE_X18_IF_ZERO
                   "ldr x10, [x18, #0x378]\n\t" /* thread_data->syscall_frame */
                   ".alt_entry " __ASM_NAME("__wine_unix_call_dispatcher_prefix_end") "\n\t"
                   __ASM_GLOBL( __ASM_NAME("__wine_unix_call_dispatcher_prefix_end") ) "\n\t"
                   "stp x18, x19, [x10, #0x90]\n\t"
                   "stp x20, x21, [x10, #0xa0]\n\t"
                   "stp x22, x23, [x10, #0xb0]\n\t"
                   "stp x24, x25, [x10, #0xc0]\n\t"
                   "stp x26, x27, [x10, #0xd0]\n\t"
                   "stp x28, x29, [x10, #0xe0]\n\t"
                   "stp q8,  q9,  [x10, #0x1b0]\n\t"
                   "stp q10, q11, [x10, #0x1d0]\n\t"
                   "stp q12, q13, [x10, #0x1f0]\n\t"
                   "stp q14, q15, [x10, #0x210]\n\t"
                   "mov x9, sp\n\t"
                   "stp x30, x9, [x10, #0xf0]\n\t"
                   "mrs x9, NZCV\n\t"
                   "stp x30, x9, [x10, #0x100]\n\t"
                   "mov x19, x10\n\t"
                   /* switch to kernel stack */
                   "mov sp, x10\n\t"
                   /* we're now on the kernel stack, stitch unwind info with previous frame */
                   __ASM_CFI_CFA_IS_AT2(x19, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_CFI(".cfi_offset 29, -0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30, -0xb8\n\t")
                   __ASM_CFI(".cfi_offset 19, -0xb0\n\t")
                   __ASM_CFI(".cfi_offset 20, -0xa8\n\t")
                   __ASM_CFI(".cfi_offset 21, -0xa0\n\t")
                   __ASM_CFI(".cfi_offset 22, -0x98\n\t")
                   __ASM_CFI(".cfi_offset 23, -0x90\n\t")
                   __ASM_CFI(".cfi_offset 24, -0x88\n\t")
                   __ASM_CFI(".cfi_offset 25, -0x80\n\t")
                   __ASM_CFI(".cfi_offset 26, -0x78\n\t")
                   __ASM_CFI(".cfi_offset 27, -0x70\n\t")
                   __ASM_CFI(".cfi_offset 28, -0x68\n\t")
                   "ldr x16, [x0, x1, lsl 3]\n\t"
                   "mov x0, x2\n\t"             /* args */
                   "blr x16\n\t"
                   "ldr w16, [sp, #0x10c]\n\t"  /* frame->restore_flags */
                   "cbnz w16, " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") "\n\t"
                   __ASM_CFI_CFA_IS_AT2(sp, 0x98, 0x02) /* frame->syscall_cfa */
                   "ldp x18, x19, [sp, #0x90]\n\t"
                   "ldp x16, x17, [sp, #0xf8]\n\t"
                   /* switch to user stack */
                   "mov sp, x16\n\t"
                   "ret x17" )

#endif  /* __aarch64__ */
