/*
 * Loader functions
 *
 * Copyright 1995, 2003 Alexandre Julliard
 * Copyright 2002 Dmitry Timoshkov for CodeWeavers
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
#include <stdarg.h>
#include <stdlib.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "winioctl.h"
#include "winternl.h"
#include "delayloadhandler.h"

#include "wine/exception.h"
#include "wine/debug.h"
#include "wine/list.h"
#include "ntdll_misc.h"
#include "ddk/ntddk.h"
#include "ddk/wdm.h"
#include "macrunner_arm64x_delay.h"

WINE_DEFAULT_DEBUG_CHANNEL(module);

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: гейт трассы записей таблицы импорта, умолчание ВЫКЛ. */
static BOOL macrunner_hb_trace_iat_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        static const WCHAR nameW[] =
            {'M','A','C','R','U','N','N','E','R','_','H','B','_','T','R','A','C','E','_','I','A','T',0};
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
WINE_DECLARE_DEBUG_CHANNEL(relay);
WINE_DECLARE_DEBUG_CHANNEL(snoop);
WINE_DECLARE_DEBUG_CHANNEL(loaddll);
WINE_DECLARE_DEBUG_CHANNEL(imports);

static BOOL macrunner_hb_trace_xtajit64(void);
static BOOL macrunner_hb_use_xtajit64_thread(void);

#ifdef _WIN64
#define DEFAULT_SECURITY_COOKIE_64  (((ULONGLONG)0x00002b99 << 32) | 0x2ddfa232)
#endif
#define DEFAULT_SECURITY_COOKIE_32  0xbb40e64e
#define DEFAULT_SECURITY_COOKIE_16  (DEFAULT_SECURITY_COOKIE_32 >> 16)

#ifdef __i386__
static const WCHAR pe_dir[] = L"\\i386-windows";
#elif defined __x86_64__
static const WCHAR pe_dir[] = L"\\x86_64-windows";
#elif defined __arm__
static const WCHAR pe_dir[] = L"\\arm-windows";
#elif defined __aarch64__
static const WCHAR pe_dir[] = L"\\aarch64-windows";
#else
static const WCHAR pe_dir[] = L"";
#endif

/* we don't want to include winuser.h */
#define RT_MANIFEST                         ((ULONG_PTR)24)
#define CREATEPROCESS_MANIFEST_RESOURCE_ID  ((ULONG_PTR)1)
#define ISOLATIONAWARE_MANIFEST_RESOURCE_ID ((ULONG_PTR)2)

typedef DWORD (CALLBACK *DLLENTRYPROC)(HMODULE,DWORD,LPVOID);
typedef void  (CALLBACK *LDRENUMPROC)(LDR_DATA_TABLE_ENTRY *, void *, BOOLEAN *);

static void __fastcall default_thread_init_func( DWORD unknown, LPTHREAD_START_ROUTINE entry, void *arg );
void (FASTCALL *pBaseThreadInitThunk)(DWORD,LPTHREAD_START_ROUTINE,void *) = default_thread_init_func;
NTSTATUS (WINAPI *__wine_unix_call_dispatcher)( unixlib_handle_t, unsigned int, void * ) = NULL;
/* MacRunner 2026-08-03 — filled by the unix side (load_ntdll_functions) with a lock-free guest-image
 * lookup.  The PE side otherwise cannot answer "which module owns this guest address": the loader
 * list does not contain guest modules above HOST_BOUNDARY_MAX, and NtQueryVirtualMemory reports
 * MEM_FREE for them because the engine maps them outside the Windows VM bookkeeping.  Stays NULL if
 * the unix side is older than this symbol, so every caller must check it. */
int (*macrunner_hb_guest_image_lookup)( UINT64 pc, UINT64 *base, UINT64 *size ) = NULL;
/* Filled by the unix side alongside the image lookup; NULL when unavailable. */
int (*macrunner_hb_guest_ctx_lookup)( DWORD tid, UINT64 *guest_pc, UINT64 *guest_sp ) = NULL;
int (*macrunner_hb_known_stack_lookup)( UINT64 sp, UINT64 *lo, UINT64 *hi, int *kind ) = NULL;

static DWORD (WINAPI *pCtrlRoutine)(void *);

SYSTEM_DLL_INIT_BLOCK LdrSystemDllInitBlock = { 0xf0 };

void *__wine_syscall_dispatcher = NULL;
unixlib_handle_t __wine_unixlib_handle = 0;

/* windows directory */
const WCHAR windows_dir[] = L"C:\\windows";
/* system directory with trailing backslash */
static const WCHAR system_dir[] = L"C:\\windows\\system32\\";
static const WCHAR syswow64_dir[] = L"C:\\windows\\syswow64\\";

/* system search path */
static const WCHAR system_path[] = L"C:\\windows\\system32;C:\\windows\\system;C:\\windows";

static BOOL is_prefix_bootstrap;  /* are we bootstrapping the prefix? */
static BOOL wow64_using_32bit_prefix;  /* are we using a 32-bit-only prefix in wow64 mode? */
static BOOL imports_fixup_done = FALSE;  /* set once the imports have been fixed up, before attaching them */
static BOOL process_detaching = FALSE;  /* set on process detach to avoid deadlocks with thread detach */
static int free_lib_count;   /* recursion depth of LdrUnloadDll calls */
static LONG path_safe_mode;  /* path mode set by RtlSetSearchPathMode */
static LONG dll_safe_mode = 1;  /* dll search mode */
static UNICODE_STRING dll_directory;  /* extra path for LdrSetDllDirectory */
static UNICODE_STRING system_dll_path; /* path to search for system dependency dlls */
static DWORD default_search_flags;  /* default flags set by LdrSetDefaultDllDirectories */
static WCHAR *default_load_path;    /* default dll search path */
static HANDLE known_dlls_ntdir;  /* NT directory containing known dlls sections */

struct dll_dir_entry
{
    struct list entry;
    WCHAR       dir[1];
};

static struct list dll_dir_list = LIST_INIT( dll_dir_list );  /* extra dirs from LdrAddDllDirectory */

struct ldr_notification
{
    struct list                    entry;
    PLDR_DLL_NOTIFICATION_FUNCTION callback;
    void                           *context;
};

static struct list ldr_notifications = LIST_INIT( ldr_notifications );

static const char * const reason_names[] =
{
    "PROCESS_DETACH",
    "PROCESS_ATTACH",
    "THREAD_ATTACH",
    "THREAD_DETACH",
};

struct file_id
{
    BYTE ObjectId[16];
};

#define HASH_MAP_SIZE 32
static LIST_ENTRY hash_table[HASH_MAP_SIZE];

/* internal representation of loaded modules */
typedef struct _wine_modref
{
    LDR_DATA_TABLE_ENTRY  ldr;
    struct file_id        id;
    ULONG                 CheckSum;
    BOOL                  system;
} WINE_MODREF;

static UINT tls_module_count = 32;     /* number of modules with TLS directory */
static IMAGE_TLS_DIRECTORY *tls_dirs;  /* array of TLS directories */
static BOOL macrunner_hb_amd64_main_on_arm64;
static WORD macrunner_hb_native_counterpart_machine;

static RTL_CRITICAL_SECTION loader_section;
static RTL_CRITICAL_SECTION_DEBUG critsect_debug =
{
    0, 0, &loader_section,
    { &critsect_debug.ProcessLocksList, &critsect_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": loader_section") }
};
static RTL_CRITICAL_SECTION loader_section = { &critsect_debug, -1, 0, 0, 0, 0 };

static CRITICAL_SECTION dlldir_section;
static CRITICAL_SECTION_DEBUG dlldir_critsect_debug =
{
    0, 0, &dlldir_section,
    { &dlldir_critsect_debug.ProcessLocksList, &dlldir_critsect_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": dlldir_section") }
};
static CRITICAL_SECTION dlldir_section = { &dlldir_critsect_debug, -1, 0, 0, 0, 0 };

static RTL_CRITICAL_SECTION peb_lock;
static RTL_CRITICAL_SECTION_DEBUG peb_critsect_debug =
{
    0, 0, &peb_lock,
    { &peb_critsect_debug.ProcessLocksList, &peb_critsect_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": peb_lock") }
};
static RTL_CRITICAL_SECTION peb_lock = { &peb_critsect_debug, -1, 0, 0, 0, 0 };

static PEB_LDR_DATA ldr =
{
    sizeof(ldr), TRUE, NULL,
    { &ldr.InLoadOrderModuleList, &ldr.InLoadOrderModuleList },
    { &ldr.InMemoryOrderModuleList, &ldr.InMemoryOrderModuleList },
    { &ldr.InInitializationOrderModuleList, &ldr.InInitializationOrderModuleList }
};

static RTL_RB_TREE base_address_index_tree;

static RTL_BITMAP tls_bitmap;
static RTL_BITMAP tls_expansion_bitmap;

static WINE_MODREF *cached_modref;
static WINE_MODREF *last_failed_modref;

static LDR_DDAG_NODE *node_ntdll, *node_kernel32;

static NTSTATUS load_dll( const WCHAR *load_path, const WCHAR *libname, DWORD flags, WINE_MODREF** pwm, BOOL system );
static NTSTATUS get_env_var( const WCHAR *name, SIZE_T extra, UNICODE_STRING *ret );
static WINE_MODREF *find_fullname_module( const UNICODE_STRING *nt_name );
static NTSTATUS process_attach( LDR_DDAG_NODE *node, LPVOID lpReserved );
static FARPROC find_ordinal_export( HMODULE module, const IMAGE_EXPORT_DIRECTORY *exports,
                                    DWORD exp_size, DWORD ordinal, LPCWSTR load_path,
                                    WINE_MODREF *importer, BOOL is_dynamic );
static FARPROC find_named_export( HMODULE module, const IMAGE_EXPORT_DIRECTORY *exports, DWORD exp_size,
                                  const char *name, int hint, LPCWSTR load_path,
                                  WINE_MODREF *importer, BOOL is_dynamic );
static BOOL macrunner_hb_trace_bootstrap(void);
static BOOL macrunner_hb_trace_thread_lifecycle(void);

#if defined(__aarch64__) && !defined(__arm64ec__)
/* Сколько раз мы завели звонок приостановки (по одному на поток, у которого впервые
 * создаётся область процессора CHPE). Нужен именно счётчик, а не «где-то печатается»:
 * без него «звонок ставится» остаётся утверждением, а не измерением. */
static unsigned int macrunner_hb_doorbell_armed;

enum macrunner_hb_xtajit64_unix_funcs
{
    macrunner_hb_xtajit64_unix_process_init,
    macrunner_hb_xtajit64_unix_thread_init,
    macrunner_hb_xtajit64_unix_thread_term,
    macrunner_hb_xtajit64_unix_process_term,
    macrunner_hb_xtajit64_unix_simulate,
    macrunner_hb_xtajit64_unix_notify_memory_alloc,
    macrunner_hb_xtajit64_unix_notify_memory_protect,
    macrunner_hb_xtajit64_unix_notify_memory_free,
    macrunner_hb_xtajit64_unix_notify_map_view,
    macrunner_hb_xtajit64_unix_notify_unmap_view,
    macrunner_hb_xtajit64_unix_flush_instruction_cache,
    macrunner_hb_xtajit64_unix_funcs_count
};

struct macrunner_hb_xtajit64_amd64_context
{
    ULONG64 rax, rbx, rcx, rdx;
    ULONG64 rsi, rdi, rsp, rbp;
    ULONG64 r8, r9, r10, r11;
    ULONG64 r12, r13, r14, r15;
    ULONG64 rip, rflags;
    ULONG64 gs_base, fs_base;
    WORD seg_cs, seg_ds, seg_es, seg_fs, seg_gs, seg_ss;
    ULONG64 xmm[16][2];
};

struct macrunner_hb_xtajit64_simulate_params
{
    struct macrunner_hb_xtajit64_amd64_context context;
    ULONG max_code_bytes;
    NTSTATUS status;
    LONG hb_result;
    ULONG faulted;
    ULONG64 steps;
    ULONG64 blocks;
};

static unixlib_handle_t macrunner_hb_xtajit64_unix_handle;

static NTSTATUS macrunner_hb_xtajit64_unix_call( enum macrunner_hb_xtajit64_unix_funcs func, void *params )
{
    if (!macrunner_hb_xtajit64_unix_handle) return STATUS_DLL_NOT_FOUND;
    return __wine_unix_call( macrunner_hb_xtajit64_unix_handle, func, params );
}

static void macrunner_hb_xtajit64_pack_context( struct macrunner_hb_xtajit64_amd64_context *dst,
                                                const AMD64_CONTEXT *src )
{
    const M128A *xmm = &src->Xmm0;
    unsigned int i;

    dst->rax = src->Rax;
    dst->rbx = src->Rbx;
    dst->rcx = src->Rcx;
    dst->rdx = src->Rdx;
    dst->rsi = src->Rsi;
    dst->rdi = src->Rdi;
    dst->rsp = src->Rsp;
    dst->rbp = src->Rbp;
    dst->r8 = src->R8;
    dst->r9 = src->R9;
    dst->r10 = src->R10;
    dst->r11 = src->R11;
    dst->r12 = src->R12;
    dst->r13 = src->R13;
    dst->r14 = src->R14;
    dst->r15 = src->R15;
    dst->rip = src->Rip;
    dst->rflags = src->EFlags;
    dst->fs_base = 0;
    dst->gs_base = (ULONG64)(ULONG_PTR)NtCurrentTeb();
    dst->seg_cs = src->SegCs;
    dst->seg_ds = src->SegDs;
    dst->seg_es = src->SegEs;
    dst->seg_fs = src->SegFs;
    dst->seg_gs = src->SegGs;
    dst->seg_ss = src->SegSs;
    for (i = 0; i < 16; i++)
    {
        dst->xmm[i][0] = xmm[i].Low;
        dst->xmm[i][1] = (ULONG64)xmm[i].High;
    }
}

static void macrunner_hb_xtajit64_unpack_context( AMD64_CONTEXT *dst,
                                                  const struct macrunner_hb_xtajit64_amd64_context *src )
{
    M128A *xmm = &dst->Xmm0;
    unsigned int i;

    dst->Rax = src->rax;
    dst->Rbx = src->rbx;
    dst->Rcx = src->rcx;
    dst->Rdx = src->rdx;
    dst->Rsi = src->rsi;
    dst->Rdi = src->rdi;
    dst->Rsp = src->rsp;
    dst->Rbp = src->rbp;
    dst->R8 = src->r8;
    dst->R9 = src->r9;
    dst->R10 = src->r10;
    dst->R11 = src->r11;
    dst->R12 = src->r12;
    dst->R13 = src->r13;
    dst->R14 = src->r14;
    dst->R15 = src->r15;
    dst->Rip = src->rip;
    dst->EFlags = (DWORD)src->rflags;
    dst->SegCs = src->seg_cs;
    dst->SegDs = src->seg_ds;
    dst->SegEs = src->seg_es;
    dst->SegFs = src->seg_fs;
    dst->SegGs = src->seg_gs;
    dst->SegSs = src->seg_ss;
    for (i = 0; i < 16; i++)
    {
        xmm[i].Low = src->xmm[i][0];
        xmm[i].High = (LONGLONG)src->xmm[i][1];
    }
}

static void macrunner_hb_xtajit64_pack_import_context( struct macrunner_hb_x64_import_context_params *dst,
                                                       const AMD64_CONTEXT *src )
{
    struct macrunner_hb_xtajit64_amd64_context tmp;

    memset( dst, 0, sizeof(*dst) );
    memset( &tmp, 0, sizeof(tmp) );
    macrunner_hb_xtajit64_pack_context( &tmp, src );
    memcpy( dst, &tmp, sizeof(tmp) );
}

static void macrunner_hb_xtajit64_unpack_import_context( AMD64_CONTEXT *dst,
                                                         const struct macrunner_hb_x64_import_context_params *src )
{
    struct macrunner_hb_xtajit64_amd64_context tmp;

    memset( &tmp, 0, sizeof(tmp) );
    memcpy( &tmp, src, sizeof(tmp) );
    macrunner_hb_xtajit64_unpack_context( dst, &tmp );
}

static NTSTATUS macrunner_hb_xtajit64_begin_thread( LPTHREAD_START_ROUTINE entry, void *arg )
{
    TEB *teb = NtCurrentTeb();
    CHPE_V2_CPU_AREA_INFO *cpu;
    AMD64_CONTEXT *ctx;
    struct macrunner_hb_xtajit64_simulate_params params;
    struct macrunner_hb_x64_import_context_params import_params;
    void *old_stack_limit;
    void *old_stack_base;
    ULONG64 rsp;
    NTSTATUS status;
    unsigned int handoffs = 0;
    unsigned int handoff_limit = 0;

    if (!teb->ChpeV2CpuAreaInfo)
    {
        const SIZE_T chpev2_stack_size = 0x40000;
        SIZE_T size = chpev2_stack_size;
        void *stack = NULL;
        NTSTATUS status;

        status = NtAllocateVirtualMemory( GetCurrentProcess(), &stack, 0, &size,
                                          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
        if (status) return status;
        RtlZeroMemory( stack, size );
        cpu = stack;
        cpu->ContextAmd64 = (ARM64EC_NT_CONTEXT *)&cpu->EmulatorDataInline;
        cpu->EmulatorStackLimit = (ULONG_PTR)stack + 0x1000;
        cpu->EmulatorStackBase = (ULONG_PTR)stack + size;
        /* MacRunner 2026-09-04 — ЗВОНОК ПРИОСТАНОВКИ: ставим указатель.
         *
         * Поле SuspendDoorbell — указатель на слово, которое ядро Windows взводит, когда просят
         * приостановить поток, стоящий в эмулируемом коде: поток не замораживают на месте (в
         * середине оттранслированного блока состояние гостя неконсистентно), а дают ему дойти до
         * своей границы. Заполняет это поле НЕ ядро и не Wine, а DLL эмулятора: во всём дереве
         * Wine (проверено по 11.14, dlls/ntdll/unix/signal_arm64.c:359 и 1386) звонок только
         * читают и пишут ПО указателю, а сам указатель не присваивают нигде. Эмулятор здесь —
         * мы, значит ставить указатель наша обязанность, и до сегодня он оставался нулевым:
         * обе половины механизма (проверка в signal_arm64ec.c:158 у нас, кооперативная ветка
         * usr1_handler у апстрима) молча выключены нулём.
         *
         * Память берём из EmulatorData[] — четыре слота в самой области, которые по назначению
         * принадлежат эмулятору (так же их использует FEX, cache/FEX/Source/Windows/ARM64EC/
         * Module.cpp) и которых мы не используем больше нигде. Это даёт адрес, посчитанный
         * компилятором, без зашитых смещений и без второго выделения, которое могло бы дать
         * новый путь отказа. Блок уже обнулён RtlZeroMemory выше, поэтому звонок начинает
         * жизнь снятым. */
        cpu->SuspendDoorbell = (ULONG *)&cpu->EmulatorData[0];
        macrunner_hb_doorbell_armed++;
        teb->ChpeV2CpuAreaInfo = cpu;
    }

    cpu = teb->ChpeV2CpuAreaInfo;
    if (macrunner_hb_trace_xtajit64())
        MESSAGE( "macrunner-xtajit64: звонок приостановки cpu=%p doorbell=%p значение=%lu взведено=%u\n",
                 cpu, cpu->SuspendDoorbell,
                 cpu->SuspendDoorbell ? (ULONG)*cpu->SuspendDoorbell : 0,
                 macrunner_hb_doorbell_armed );
    ctx = &cpu->ContextAmd64->AMD64_Context;
    rsp = (cpu->EmulatorStackBase & ~(ULONG64)15) - 8 - 32;
    if (rsp < cpu->EmulatorStackLimit) return STATUS_NO_MEMORY;

    *(ULONG64 *)(ULONG_PTR)rsp = 0xffff0000;
    RtlZeroMemory( (void *)(ULONG_PTR)(rsp + 8), 32 );
    old_stack_limit = teb->Tib.StackLimit;
    old_stack_base = teb->Tib.StackBase;
    teb->Tib.StackLimit = (void *)(ULONG_PTR)cpu->EmulatorStackLimit;
    teb->Tib.StackBase = (void *)(ULONG_PTR)cpu->EmulatorStackBase;

    RtlZeroMemory( ctx, sizeof(*ctx) );
    ctx->ContextFlags = CONTEXT_AMD64_FULL;
    ctx->MxCsr = 0x1f80;
    ctx->SegCs = 0x33;
    ctx->SegSs = 0x2b;
    ctx->EFlags = 0x202;
    ctx->Rsp = rsp;
    ctx->Rip = (ULONG64)(ULONG_PTR)entry;
    ctx->Rcx = (ULONG64)(ULONG_PTR)arg;
    cpu->InSimulation = 1;

    if (macrunner_hb_trace_xtajit64())
    {
        MESSAGE( "macrunner-xtajit64: dispatch BeginSimulation entry=%p arg=%p rsp=%p cpu=%p\n",
                 entry, arg, (void *)(ULONG_PTR)rsp, cpu );
        MESSAGE( "macrunner-xtajit64: BeginSimulation REACHED rip=%p rsp=%p rax=%p rcx=%p rdx=%p insim=%lu\n",
                 (void *)ctx->Rip, (void *)ctx->Rsp, (void *)ctx->Rax,
                 (void *)ctx->Rcx, (void *)ctx->Rdx, (ULONG)cpu->InSimulation );
    }

    for (;;)
    {
        memset( &params, 0, sizeof(params) );
        macrunner_hb_xtajit64_pack_context( &params.context, ctx );
        params.max_code_bytes = 4096;

        status = macrunner_hb_xtajit64_unix_call( macrunner_hb_xtajit64_unix_simulate, &params );
        if (!status) status = params.status;
        macrunner_hb_xtajit64_unpack_context( ctx, &params.context );

        if (macrunner_hb_trace_xtajit64())
            MESSAGE( "macrunner-xtajit64: BeginSimulation executed status=%08lx hb=%ld faulted=%lu steps=%s blocks=%s rip=%p rsp=%p\n",
                     status, params.hb_result, params.faulted, wine_dbgstr_longlong(params.steps),
                     wine_dbgstr_longlong(params.blocks), (void *)ctx->Rip, (void *)ctx->Rsp );
        if (status) break;
        if (ctx->Rip == 0xffff0000) break;
        handoffs++;
        if (handoff_limit && handoffs > handoff_limit)
        {
            status = STATUS_TIMEOUT;
            break;
        }

        macrunner_hb_xtajit64_pack_import_context( &import_params, ctx );
        status = WINE_UNIX_CALL( unix_macrunner_hb_x64_import_context, &import_params );
        if (status) break;
        if (!import_params.handled)
        {
            MESSAGE( "macrunner-xtajit64: BeginSimulation stopped at unhandled boundary rip=%p rsp=%p\n",
                     (void *)ctx->Rip, (void *)ctx->Rsp );
            status = STATUS_NOT_IMPLEMENTED;
            break;
        }
        macrunner_hb_xtajit64_unpack_import_context( ctx, &import_params );
        if (macrunner_hb_trace_xtajit64())
            MESSAGE( "macrunner-xtajit64: import handoff complete rip=%p rsp=%p rax=%p count=%u\n",
                     (void *)ctx->Rip, (void *)ctx->Rsp, (void *)ctx->Rax, handoffs );
    }

    cpu->InSimulation = 0;
    teb->Tib.StackLimit = old_stack_limit;
    teb->Tib.StackBase = old_stack_base;
    return status;
}
#endif

static void FASTCALL macrunner_hb_BaseThreadInitThunk( DWORD unknown, LPTHREAD_START_ROUTINE entry, void *arg )
{
    struct macrunner_hb_x64_thread_entry_params params;
    NTSTATUS status;

    memset( &params, 0, sizeof(params) );
    params.entry = entry;
    params.arg = arg;
    MESSAGE( "MacRunner HyperBridge thread callback entry=%p arg=%p\n", entry, arg );
    if (macrunner_hb_trace_thread_lifecycle())
        MESSAGE( "macrunner-ui-input: stage=hb_BaseThreadInitThunk_enter tid=%p entry=%p arg=%p unknown=%lu\n",
                 NtCurrentTeb()->ClientId.UniqueThread, entry, arg, unknown );
    if (macrunner_hb_trace_bootstrap())
        MESSAGE( "macrunner-hb-bootstrap-thread-thunk: entry=%p arg=%p\n", entry, arg );
#if defined(__aarch64__) && !defined(__arm64ec__)
    if (macrunner_hb_amd64_main_on_arm64 && macrunner_hb_xtajit64_unix_handle &&
        macrunner_hb_use_xtajit64_thread())
    {
        status = macrunner_hb_xtajit64_begin_thread( entry, arg );
        MESSAGE( "MacRunner xtajit64 BeginSimulation returned unexpectedly status=%lx\n", status );
        RtlExitUserThread( status );
    }
#endif
    status = WINE_UNIX_CALL( unix_macrunner_hb_x64_thread_entry, &params );
    if (macrunner_hb_trace_thread_lifecycle())
        MESSAGE( "macrunner-ui-input: stage=hb_BaseThreadInitThunk_unix_return tid=%p entry=%p arg=%p status=%lx ret=%s blocks=%s steps=%s\n",
                 NtCurrentTeb()->ClientId.UniqueThread, entry, arg, status,
                 wine_dbgstr_longlong(params.ret), wine_dbgstr_longlong(params.blocks),
                 wine_dbgstr_longlong(params.steps) );
    if (macrunner_hb_trace_bootstrap())
        MESSAGE( "macrunner-hb-bootstrap-thread-thunk-return: entry=%p arg=%p status=%lx ret=%s blocks=%s steps=%s\n",
                 entry, arg, status, wine_dbgstr_longlong(params.ret), wine_dbgstr_longlong(params.blocks),
                 wine_dbgstr_longlong(params.steps) );
    if (status)
    {
        MESSAGE( "MacRunner HyperBridge thread callback failed entry=%p arg=%p status=%lx blocks=%s steps=%s\n",
             entry, arg, status, wine_dbgstr_longlong(params.blocks), wine_dbgstr_longlong(params.steps) );
        RtlExitUserThread( status );
    }
    if (macrunner_hb_trace_thread_lifecycle())
        MESSAGE( "macrunner-ui-input: stage=hb_BaseThreadInitThunk_exit_call tid=%p entry=%p arg=%p ret=%s\n",
                 NtCurrentTeb()->ClientId.UniqueThread, entry, arg, wine_dbgstr_longlong(params.ret) );
    RtlExitUserThread( params.ret );
}

/* check whether the file name contains a path */
static inline BOOL contains_path( LPCWSTR name )
{
    return ((*name && (name[1] == ':')) || wcschr(name, '/') || wcschr(name, '\\'));
}

static BOOL get_env( const WCHAR *var, WCHAR *val, unsigned int len )
{
    UNICODE_STRING name, value;

    name.Length = wcslen( var ) * sizeof(WCHAR);
    name.MaximumLength = name.Length + sizeof(WCHAR);
    name.Buffer = (WCHAR *)var;

    value.Length = 0;
    value.MaximumLength = len;
    value.Buffer = val;

    return !RtlQueryEnvironmentVariable_U( NULL, &name, &value );
}

static BOOL macrunner_hb_trace_bootstrap(void)
{
    WCHAR value[8] = {0};

    return get_env( L"MACRUNNER_HB_TRACE_BOOTSTRAP", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

/* MacRunner lane ЛЕСТНИЦА 2026-08-16 (итерации 1160-1165).  ucrtbase.dll is the first
 * UNCOVERED case of the class this function's callers already pay for three times over:
 * MODULE_InitDLL skips DllMain for AMD64 builtins that are not on the allowlist, marks them
 * LDR_PROCESS_ATTACHED and returns SUCCESS, so any process-level side effect of that DllMain
 * is lost silently.  For ucrtbase the lost side effect is msvcrt_init_args() (msvcrt/data.c:331),
 * which is the ONLY caller-independent filler of __argc/__argv/__wargv/_acmdln/_wcmdln/
 * _pgmptr/_wpgmptr/_winver/_winmajor/_winminor/_osver/_osplatform/_fmode/_HUGE.
 *
 * MEASURED, not inferred (all in one guest process, kernelbase swapped per the lane recipe):
 *   - `macrunner-hb-bootstrap-dll-entry-skip: module=L"ucrtbase.dll" reason=PROCESS_ATTACH`
 *   - in that same process: _acmdln=NULL, _wcmdln=NULL, __argc=0
 *   - _configure_narrow_argv() is a stub returning 0 (data.c:598), so it never covers for it
 *   - a value scan of the WHOLE of ucrtbase's .data finds no pointer to the command line or to
 *     the program path, in either ARM64X data set -- the stores never happened anywhere
 *   - ucrtbase DOES have a native ARM64 entry: CHPE AlternateEntryPoint = RVA 0x10f4b4 (.text),
 *     confirmed by the .a64xrm map's first pair (0x120000 -> 0x10f4b4) and by validating the
 *     same derivation against kernelbase, whose 0xdf000 matches its measured native_entry.
 *
 * вид Б by order 145 asks for a gate that is ON by default.  This one ships OFF, and the reason
 * is a measurement, not caution: with the gate lit the guest dies with exit=5 before printing a
 * single line (lane iteration 1166, two arms of the SAME binary -- gate=0 reproduced the old
 * exit=77 exactly, gate=default-on gave exit=5 and no output).  Running ucrtbase's native ARM64
 * DllMain is therefore fatal as of today, and a fatal default would break every run in every
 * lane.  It stays OFF until that death is diagnosed; the allowlist entry and this gate are what
 * make the next diagnosis a one-variable run instead of a rebuild. */
/* ★ 05.09.2026 — `macrunner_hb_import_prefer_arm64ec_enabled()` УДАЛЁН вместе с гейтом
 * `MACRUNNER_HB_IMPORT_PREFER_ARM64EC`. Лечение доказано исполнением и сделано безусловным,
 * а признак берётся из образа, а не из окружения: см. `macrunner_hb_module_live_half_is_ec`
 * и место применения в `macrunner_hb_find_native_target_for_thunk_import`. */

/* MacRunner 2026-08-17, лейн ЛЕСТНИЦА, итерация 1349 — ТО ЖЕ, НО ТОЛЬКО ДЛЯ ГОСТЕВОГО ОБРАЗА.
 *
 * Гейт выше переставляет порядок разрешения для КАЖДОГО импорта, и замер 1348 показал, чем это
 * кончается: рука ARM64EC с ним не доходит даже до конструктора CRT (`код=5`, ноль меток), а
 * `mintest3` уходит в шторм отказов (16 650 240 записей, 140 206/с) и упирается в бюджет.
 * Рука x86_64 при этом не задета.
 *
 * Причина разделения — в том, КТО импортирует. Мест применения два, и они не пересекаются:
 *   - `macrunner_hb_fix_native_import_target` требует, чтобы импортирующий БЫЛ встроенным
 *     модулем Wine (`macrunner_hb_importer_is_native_wine_builtin`), то есть это связи
 *     встроенных модулей между собой — нативный код ARM64, зовущий нативный код ARM64;
 *   - место в разборе таблицы импорта, наоборот, встроенных импортирующих ОТСЕКАЕТ, и
 *     обслуживает только образ гостя.
 * Подмена тел на ARM64EC у первых меняет соглашение вызова между нативными модулями — вот это
 * и ломается. У второго же ровно обратная нужда: гостевой образ ARM64EC обязан звать
 * EC-половину, потому что заполнена она (замер r9-DK: нативная отдаёт NULL, EC — годную строку).
 *
 * Поэтому здесь отдельный гейт, и применяется он ТОЛЬКО к гостю. По умолчанию ВЫКЛ. */
static BOOL macrunner_hb_import_prefer_arm64ec_guest_enabled(void)
{
    WCHAR value[8] = {0};

    return get_env( L"MACRUNNER_HB_IMPORT_PREFER_ARM64EC_GUEST", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

/* ОПЫТ, а не правка (лейн ЛЕСТНИЦА, итерация 1203).  Перечисление класса замером (1202) дало
 * восемь модулей с пропущенным `DllMain` в минимальной программе x64, и как минимум пятеро из
 * них что-то теряют: `msvcrt` — тот же `msvcrt_init_args`, что лечит гейт для ucrtbase;
 * `kernel32` — фильтр необработанных исключений, `system_info`, `kernelbase_global_data`,
 * `copy_startup_info`; `imm32` — таблицу ввода; `uxtheme` — оформление; `gdi32` — свой описатель
 * модуля.  Добавлять по гейту на модуль бессмысленно: их уже четыре.
 *
 * Этот гейт проверяет САМ КРИТЕРИЙ: запускать нативный `DllMain` ЛЮБОМУ встроенному модулю
 * AMD64, у которого есть нативная точка входа.  Таких 598 из 601 (сплошной замер 1175).
 * Безопасно по построению: у кого точки входа нет, `macrunner_hb_get_native_arm64x_entry`
 * вернёт NULL и модуль уйдёт в прежний пропуск.
 *
 * По умолчанию ВЫКЛ: это замер политики, а не решение о ней. */
/* Объявление вперёд: сам разрешитель дискового экспорта определён ниже (строка ~2419), а
 * заполнитель стоит здесь, рядом с прочими гейтами. */
static void *macrunner_hb_find_disk_export_outside_section( WINE_MODREF *target_mod, const char *name,
                                                            const char *section );

/* MacRunner 2026-08-17, лейн ЛЕСТНИЦА, итерация 1357 — ЗАПОЛНИТЬ __argc/__argv БЕЗ DllMain.
 *
 * Замер 1356, обе руки одинаково: `__p___argc()` отдаёт `base+0x17d138`, и там НОЛЬ;
 * `__p___argv()` — `base+0x17d168`, тоже ноль. Заполнителя (`msvcrt_init_args` из `DllMain`
 * ucrtbase) не звали: для встроенных AMD64 `DllMain` пропускается. Гейт, который его
 * запускает, прогон убивает (`MACRUNNER_HB_UCRTBASE_NATIVE_DLLMAIN=1`, r9-EC: `код=5`, 33 с).
 *
 * Здесь заполняем сами, и адреса НЕ угадываем: спрашиваем у самого модуля его же экспорты
 * `__p___argc`/`__p___argv`. Разрешение экспорта даёт ту же половину ARM64X, которую потом
 * прочитает гость — это подтверждено замером 1356 (обе руки получили нативную).
 *
 * Разбор строки простейший: разделители — пробелы, кавычки снимаются. Этого хватает для
 * `"C:\walk.exe" minimal`; полного разбора Windows здесь не строим и говорим об этом вслух.
 *
 * ★ 2026-08-18, итерация 2315 — УМОЛЧАНИЕ ПЕРЕВЕДЕНО НА ВКЛ по приказу владельца (пункт 175).
 *
 * Разбор владельца: прежнее умолчание НЕ соответствовало Windows. Настоящая Windows всегда даёт
 * `argc >= 1` и `argv[0]` с именем образа, у нас было `argc=0, argv[0]=NULL`. То есть гейт не
 * добавляет поведения — он убирает отступление от эталона, а отступление хуже непроверенной
 * правки, которая эталон восстанавливает.
 *
 * Замерено (итерация 2299, i386): без гейта `argc=0`; с гейтом `argc=1` и имя образа; с двумя
 * аргументами `argc=3`. Семь форматов печати из семи верны.
 *
 * НЕ ПРОВЕРЕНО НА x64 — на момент правки гостевая проба под x64 не стартовала иначе как через
 * `scripts/mr-run.sh`, и замера argc там нет. Назвать вслух обязан: перепроверить, когда
 * появится стартующая x64-проба.
 *
 * ★★★ 2026-08-18, итерация 2323 — УМОЛЧАНИЕ ВЕРНУТО В ВЫКЛ (приказ владельца 177, отмена 175).
 *
 * Включение убивает Hollow Knight. Три прогона, отличавшиеся ОДНОЙ переменной:
 *
 *   ВКЛ           +28,285 с  exit=29   c000001d (недопустимая команда), swapchain НЕ достигнут
 *   ВЫКЛ          +462,630 с exit=186  swapchain 106 с, дошёл до входа в GOG
 *   ВКЛ повтор    +26,891 с  exit=29   та же смерть, та же секунда
 *
 * Зонд входа (итерация 2322) назвал место: последний модуль перед смертью — `ucrtbase.dll`,
 * то есть экспорты `__p___argc`/`__p___argv` НАЙДЕНЫ, и падение происходит уже после их
 * разрешения, не дойдя до печати успеха. Маркер успеха не напечатан ни в одной из рук.
 *
 * Отступление от Windows (там всегда `argc >= 1`) остаётся ОСОЗНАННЫМ и с названной ценой:
 * лечение есть и проверено на i386 (7 форматов из 7), но на x64 оно смертельно для мишени.
 * Включать явным `MACRUNNER_HB_FILL_CRT_ARGV=1`. */
static BOOL macrunner_hb_fill_crt_argv_enabled(void)
{
    WCHAR value[8] = {0};

    return get_env( L"MACRUNNER_HB_FILL_CRT_ARGV", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

static void macrunner_hb_fill_crt_argv( WINE_MODREF *wm )
{
    static BOOL done;
    ANSI_STRING name_argc, name_argv;
    int *(*p_argc)(void) = NULL;
    char ***(*p_argv)(void) = NULL;
    const UNICODE_STRING *cmd;
    char *narrow, **vec;
    unsigned int i, n = 0, len;
    int in_quote = 0, in_word = 0;

    if (done || !wm || !macrunner_hb_fill_crt_argv_enabled()) return;
    cmd = &NtCurrentTeb()->Peb->ProcessParameters->CommandLine;
    if (!cmd->Buffer || !cmd->Length) return;

    /* ★ 2026-08-18, итерация 2322 — БЕЗУСЛОВНЫЙ ЗОНД ВХОДА.
     *
     * Две руки HK с включённым умолчанием умерли на +28,3 и +26,9 с с `c000001d`, рука с
     * `=0` дожила до 462 с. При этом маркер УСПЕХА (`fill-crt-argv:`) не напечатан ни в одной —
     * значит до записи дело не дошло, и виновата не запись, а сам ПУТЬ: при включённом гейте
     * мы зовём `LdrGetProcedureAddress` для КАЖДОГО модуля в его `DLL_PROCESS_ATTACH`.
     *
     * Зонд печатает имя модуля ДО разрешения экспорта — то есть отвечает на вопрос «на каком
     * модуле мы падаем», а не «нашли ли мы argc». Первые 40 модулей, дальше молчит.
     * Канал — `MESSAGE`, он в этих журналах доказанно доходит (`init_locale done` виден). */
    {
        static unsigned зонд;
        if (зонд < 40)
        {
            зонд++;
            MESSAGE( "macrunner-hb-fill-crt-argv-вход: n=%u module=%s base=%p\n",
                     зонд, debugstr_w(wm->ldr.BaseDllName.Buffer), wm->ldr.DllBase );
        }
    }

    RtlInitAnsiString( &name_argc, "__p___argc" );
    RtlInitAnsiString( &name_argv, "__p___argv" );
    if (LdrGetProcedureAddress( wm->ldr.DllBase, &name_argc, 0, (void **)&p_argc )) return;
    if (LdrGetProcedureAddress( wm->ldr.DllBase, &name_argv, 0, (void **)&p_argv )) return;
    if (!p_argc || !p_argv) return;

    /* ★ 2026-08-18, итерация 2341, хвост Х1 — ПЕЧАТЬ ДО ПЕРВОГО РАЗЫМЕНОВАНИЯ.
     *
     * Замер 2340: печать, стоявшая перед вызовами `d_argc()`, не появилась ни разу, а по адресу
     * отказа лежат байты `cc cc 48 8b c4` — набивка и пролог x86-64. Значит мы исполняем
     * x64-код, но НЕ в том месте, на которое я думал: до дискового экспорта дело не доходит.
     *
     * Остаётся ровно два кандидата: сам вызов `p_argc()`/`p_argv()`, полученный через
     * `LdrGetProcedureAddress` на гибридном модуле, или чужой код между модулями. Эта печать
     * их разводит: если она появится, а смерть останется — виноват вызов ниже; если не
     * появится — мы умираем ещё раньше, вне заполнителя. */
    MESSAGE( "macrunner-hb-fill-crt-argv-разрешено: module=%s base=%p p_argc=%p p_argv=%p\n",
             debugstr_w(wm->ldr.BaseDllName.Buffer), wm->ldr.DllBase,
             (void *)p_argc, (void *)p_argv );

    len = cmd->Length / sizeof(WCHAR);
    if (!(narrow = RtlAllocateHeap( GetProcessHeap(), 0, len + 1 ))) return;
    for (i = 0; i < len; i++) narrow[i] = (char)(cmd->Buffer[i] & 0x7f);
    narrow[len] = 0;

    /* Считаем слова и режем на месте. Массив на len/2+2 указателей — с запасом. */
    if (!(vec = RtlAllocateHeap( GetProcessHeap(), 0, (len / 2 + 2) * sizeof(char *) )))
    {
        RtlFreeHeap( GetProcessHeap(), 0, narrow );
        return;
    }
    for (i = 0; i < len; i++)
    {
        if (narrow[i] == '"') { in_quote = !in_quote; narrow[i] = 0; in_word = 0; continue; }
        if (!in_quote && narrow[i] == ' ') { narrow[i] = 0; in_word = 0; continue; }
        if (!in_word) { vec[n++] = &narrow[i]; in_word = 1; }
    }
    vec[n] = NULL;

    /* Итерация 1357, ЗАМЕР ОПРОВЕРГ ДОГАДКУ 1356. Я полагал, что разрешение экспорта даст ту
     * же половину ARM64X, что читает гость. Прогон r9-EI напечатал `pargc=0x0FBE4EF448`, а это
     * `база+0x17F448` — половина ARM64EC, тогда как гость читает `+0x17D138`, нативную
     * (замер 1356). `LdrGetProcedureAddress`, вызванный из нативного кода ntdll, выбирает
     * СВОЮ половину. Поэтому пишем в ОБЕ: вторую берём дисковым экспортом — той же дорогой,
     * которой разрешаются импорты гостя. */
    *p_argc() = (int)n;
    *p_argv() = vec;
    {
        int *(*d_argc)(void) = macrunner_hb_find_disk_export_outside_section( wm, "__p___argc", ".hexpthk" );
        char ***(*d_argv)(void) = macrunner_hb_find_disk_export_outside_section( wm, "__p___argv", ".hexpthk" );

        /* ★ 2026-08-18, итерация 2340, хвост Х1 — ПЕЧАТЬ ПЕРЕНЕСЕНА ПЕРЕД ВЫЗОВАМИ.
         *
         * Три прогона HK умирали здесь с `c000001d` (недопустимая команда), и печать, стоявшая
         * ПОСЛЕ вызовов, не появилась ни разу — то есть о самих адресах мы не знали ничего.
         *
         * Версия (итерация 2338): `find_disk_export_outside_section` даёт адрес, вычисленный по
         * ДИСКОВОМУ образу в обход `.hexpthk`, а у ARM64EC-модуля (`ucrtbase.dll`, на котором нас
         * застал зонд входа) по такому адресу лежит x64-код. Вызов x64-байтов напрямую из
         * нативного ARM64-кода ntdll и есть недопустимая команда.
         *
         * Печать ДО вызова отвечает на это числом: если версия верна, мы увидим адреса и
         * смерть на том же месте; если адреса совпадут с нативными, версия неверна. */
        MESSAGE( "macrunner-hb-fill-crt-argv-адреса: p_argc=%p p_argv=%p d_argc=%p d_argv=%p base=%p\n",
                 (void *)p_argc, (void *)p_argv, (void *)d_argc, (void *)d_argv, wm->ldr.DllBase );
        if (d_argc && (void *)d_argc != (void *)p_argc) *d_argc() = (int)n;
        if (d_argv && (void *)d_argv != (void *)p_argv) *d_argv() = vec;
        MESSAGE( "macrunner-hb-fill-crt-argv: вторая половина ПРОЙДЕНА d_argc=%p d_argv=%p\n",
                 (void *)d_argc, (void *)d_argv );
    }
    done = TRUE;
    MESSAGE( "macrunner-hb-fill-crt-argv: module=%s argc=%u argv=%p argv0=%s pargc=%p pargv=%p\n",
             debugstr_w(wm->ldr.BaseDllName.Buffer), n, vec, n ? vec[0] : "(нет)",
             (void *)p_argc(), (void *)p_argv() );
}

static BOOL macrunner_hb_native_dllmain_all_enabled(void)
{
    WCHAR value[8] = {0};

    return get_env( L"MACRUNNER_HB_NATIVE_DLLMAIN_ALL", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

static BOOL macrunner_hb_ucrtbase_native_dllmain_enabled(void)
{
    WCHAR value[8] = {0};

    return get_env( L"MACRUNNER_HB_UCRTBASE_NATIVE_DLLMAIN", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

static BOOL macrunner_hb_language_observer_enabled(void)
{
    WCHAR value[8] = {0};

    if (get_env( L"MACRUNNER_HB_RETURN_ROUTE_OBSERVER", value, sizeof(value) ) &&
        value[0] && value[0] != '0')
        return TRUE;
    value[0] = 0;
    return get_env( L"MACRUNNER_HB_LANGUAGE_FLOW_OBSERVER", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

static BOOL macrunner_trace_process_exit_enabled(void)
{
    WCHAR value[8] = {0};

    return get_env( L"MACRUNNER_TRACE_PROCESS_EXIT", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

static BOOL macrunner_hb_trace_xtajit64(void)
{
    WCHAR value[8] = {0};

    return get_env( L"MACRUNNER_HB_TRACE_XTAJIT64", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

static BOOL macrunner_hb_use_xtajit64_thread(void)
{
    WCHAR value[8] = {0};

    return get_env( L"MACRUNNER_HB_USE_XTAJIT64_THREAD", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

static BOOL macrunner_hb_trace_pe32_loader(void)
{
    WCHAR value[8] = {0};

    return get_env( L"MACRUNNER_HB_TRACE_PE32_LOADER", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА, итерация 194.
 * Трасса загрузчика включалась выражением вида
 *     (current_machine == IMAGE_FILE_MACHINE_I386 && macrunner_hb_pe32_loader_trace_auto()) || macrunner_hb_trace_pe32_loader()
 * то есть для ЛЮБОГО 32-битного процесса она БЕЗУСЛОВНА, а гейт MACRUNNER_HB_TRACE_PE32_LOADER
 * стоит по ИЛИ и выключить её не может в принципе. Вся ступень 1 (Diablo, i386) шла с полной
 * трассой загрузчика, причём её вывод до нашего журнала не доходит (строк macrunner-pe32-loader
 * в журналах ноль) — то есть форматирование выполняется и выбрасывается.
 * Здесь авто-включение делается отключаемым, УМОЛЧАНИЕ ПРЕЖНЕЕ, чтобы замер менял одну вещь. */
static BOOL macrunner_hb_pe32_loader_trace_auto(void)
{
    static int cached = -1;

    if (cached < 0)
    {
        WCHAR value[8] = {0};

        if (get_env( L"MACRUNNER_HB_PE32_LOADER_TRACE_AUTO", value, sizeof(value) ) && value[0])
            cached = (value[0] != '0');
        else
            cached = 1;
    }
    return cached;
}

/* Run winemetal.dll's x64 DllMain (instead of the builtin skip) so __wine_init_unix_call publishes
 * __wine_unixlib_handle.  Proven to wire the handle (first WMTCopyAllDevices unix call returns
 * STATUS_SUCCESS), but a separate HB exception/re-execution loop on the success-then-fault path still
 * blocks end-to-end (the same unix call re-dispatches and faults c0000005).  Default OFF until that
 * loop is fixed, so default behaviour stays at the clean DXGI_ERROR_NOT_FOUND (no hang). */
static BOOL macrunner_hb_winemetal_x64_dllmain_enabled(void)
{
    WCHAR value[8] = {0};

    return get_env( L"MACRUNNER_HB_WINEMETAL_X64_DLLMAIN", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

/* MacRunner 2026-07-29 (HK DllMain lane).  winemac.drv is in exactly the class the
 * winemetal.dll comment below describes: a Wine builtin that carries its own unixlib and
 * whose x64 DllMain calls __wine_init_unix_call before anything else can work.  It reached
 * neither escape hatch, so in Hollow Knight's process (an AMD64 main on ARM64) it took the
 * dll-entry SKIP: LdrLoadDll reported success, the loader logged the module as LOADED
 * builtin, and DllMain never executed -- hence stage=dllmain_attach exists only for the
 * aarch64 explorer-class pid 005c and never for HK's pid 0020.  With DllMain skipped,
 * dllmain.c:562 MACDRV_CALL(init) is never issued, unix macdrv_init is never entered,
 * macdrv_main.c:537 init_user_driver() -> gdi.c:297 __wine_set_user_driver never runs, and
 * load_display_driver keeps its re-entrancy placeholder for the life of the process.
 *
 * winemac.drv is also the ONLY wine builtin on HK's thread with no native aarch64 twin (37
 * of them load twice), because the native-counterpart swap is driven from import resolution
 * and the display driver arrives via an explicit LdrLoadDll from User32LoadDriver instead.
 * So it has neither of the two routes every other builtin has: no native thunk to be routed
 * to, and no x64 entry allowed to run.  Running its x64 DllMain is the only remaining route.
 *
 * ---------------------------------------------------------------------------------------
 * DEFAULT FLIPPED TO **OFF**, 2026-07-29, on measured evidence -- read this before turning
 * it back on.  Running this DllMain WORKS as far as the loader is concerned and then HANGS
 * the guest, reproducibly, 2 runs out of 2, in two independent lanes:
 *
 *   run                                        last log ts   endpoint
 *   laneA-hk-dllmain-x64entry-i1  (this lane)   +50.182 s     stage=dllmain_unixcall_init
 *   laneA-HK-E2E-20-TEBFIX        (e2e lane)    +45.946 s     stage=dllmain_unixcall_init
 *
 * Both stop on the LAST line winemac.drv's process_attach prints before MACDRV_CALL(init),
 * i.e. between dllmain.c:551 and dllmain.c:563, with the process still alive and its log
 * frozen (the e2e run sat there >9 min).  Three control runs on the ntdll WITHOUT this
 * change (winemac-initdll=0) ran to +897 s, +2519 s and +4285 s instead.
 *
 * The regression is worse than "no gain": with the guest wedged inside process_attach, the
 * unix-side self-init (macdrv_main.c macdrv_process_selfinit) never gets to run either, so
 * user_driver_placeholder_replaced goes 1 -> 0.  All three control runs DID replace the
 * placeholder with the real driver via that route.  So default-ON trades a working driver
 * for a hung boot, and it wedges every sister lane sharing this dist.
 *
 * Opt IN with MACRUNNER_HB_WINEMAC_X64_DLLMAIN=1 to reproduce/diagnose the hang.  The route
 * probe above it (macrunner-hb-winemac-initdll) stays UNGATED, so a run log still reports
 * which route winemac.drv took even with this off. */
static BOOL macrunner_hb_winemac_x64_dllmain_enabled(void)
{
    WCHAR value[8] = {0};

    return get_env( L"MACRUNNER_HB_WINEMAC_X64_DLLMAIN", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

/* MacRunner 2026-07-29 (HK DllMain lane).  The OTHER route out of the same skip, and the one
 * that does not have to survive the wedge documented above.
 *
 * The x64 route (gate above) does get winemac.drv's DllMain to run in HK's process --
 * stage=dllmain_attach arch=x86_64 pid=0020 was measured -- and then wedges while the DllMain
 * calls a native PE import, on a stack that carries BOTH macrunner_hb_x64_dll_entry and
 * win32u's load_display_driver -> KeUserModeCallback.  `sample` caught the thread 3626/3626
 * inside macrunner_hb_route_x64_callback_fault -> macrunner_hb_pc_in_executable_section, and a
 * sister lane sampled a SECOND, unrelated fault ending in the same router.  That router is in
 * engine/hyperbridge and ntdll/unix/macrunner_hb.c -- FORBIDDEN territory for this lane -- so
 * the x64 route cannot be finished from here at all.
 *
 * This gate avoids it instead of surviving it: run the DllMain as NATIVE ARM64 code, the way
 * win32u.dll, user32.dll and kernelbase.dll already run theirs in this very process, so no x64
 * guest code executes, macrunner_hb_x64_dll_entry is never entered, and the fault router is
 * never reached.
 *
 * Why this is now believed possible, measured on the shipped artifacts 2026-07-29 -- the point
 * that was missing every previous time this was considered:
 *
 *   dist file                          machine  CHPEMetadataPointer  .hexpthk
 *   aarch64-windows/win32u.dll         aa64     0x18004cbf8          YES     <- native route works
 *   aarch64-windows/user32.dll         aa64     0x180154a3c          YES     <- native route works
 *   aarch64-windows/winemac.drv        aa64     0x18000b230          YES     <- SAME SHAPE
 *   x86_64-windows/winemac.drv         8664     0                    no      <- what HK loads
 *
 * i.e. the aarch64 winemac.drv is a genuine ARM64X hybrid, structurally identical to the two
 * modules whose native entry macrunner_hb_get_native_arm64x_entry already resolves.  The copy
 * HK actually loads is a pure AMD64 PE with no CHPE metadata, from which no native entry can
 * ever be derived -- which is why adding winemac.drv to needs_native_entry only does anything
 * when the ARM64X build is the one at c:\windows\system32\winemac.drv.
 *
 * So this is HALF of a two-part change and is inert on its own:
 *   1. MACRUNNER_PREFIX_WINEMAC_NATIVE=1  (scripts/sync-prefix-from-dist.sh) puts the ARM64X
 *      build at the path User32LoadDriver pins;
 *   2. this gate lets the loader derive that build's native ARM64 entry and call it.
 * Part 1 alone was tried on 2026-07-29 and correctly REFUTED -- but it was tried while DllMain
 * was still being skipped for winemac.drv entirely, so it was acting downstream of an entry
 * that was never invoked.  The pair has never been run together.
 *
 * Safe by construction when either half is missing: macrunner_hb_get_native_arm64x_entry()
 * returns NULL for the pure-AMD64 file (it requires MACHINE_ARM64 + CHPEMetadataPointer on
 * disk), and a NULL native_entry falls through to the existing needs_x64_entry check, i.e. to
 * the unchanged default skip.  Default OFF regardless, because this lane's standing rule is
 * that an offline proof is not a runtime proof.
 *
 * Opt IN with MACRUNNER_HB_WINEMAC_NATIVE_DLLMAIN=1. */
static BOOL macrunner_hb_winemac_native_dllmain_enabled(void)
{
    WCHAR value[8] = {0};

    return get_env( L"MACRUNNER_HB_WINEMAC_NATIVE_DLLMAIN", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

static BOOL macrunner_hb_trace_thread_lifecycle(void)
{
    WCHAR value[8] = {0};

    return macrunner_hb_trace_bootstrap() ||
           (get_env( L"MACRUNNER_TRACE_UI_INPUT", value, sizeof(value) ) && value[0] && value[0] != '0') ||
           (get_env( L"MACRUNNER_TRACE_UI_EVENT_PATH", value, sizeof(value) ) && value[0] && value[0] != '0') ||
           (get_env( L"MACRUNNER_TRACE_UI_WAIT", value, sizeof(value) ) && value[0] && value[0] != '0');
}

/***********************************************************************
 *  ★★★ ШАГ-2 08.09.2026 — ВЛАДЕЛЕЦ CPU, КАКИМ ЕГО ВИДИТ PE-ПОЛОВИНА (договор T8)
 *
 * Unix-половина читает MACRUNNER_CPU_BACKEND в macrunner_hb_init_flags() и там же гасит
 * свой кешированный macrunner_hb_x64_loader.  PE-половина об этом НЕ ЗНАЛА: все её ветви
 * ключены на СОБСТВЕННОЕ чтение MACRUNNER_HB_X64_LOADER (macrunner_hb_loader_env_enabled
 * ниже).  Унаследованное значение 1 поэтому оставляло включённым весь PE-марш HyperBridge
 * — пропуск DllMain, свои списки импортов/TLS, подмену BaseThreadInitThunk и захват входа
 * потока x64 — при уже выбранном FEX.  Это ровно «ТИХИЙ: stale HB_X64_LOADER=1» из
 * reports/research/20260907-ASTRA-WINE-FEX-CONTRACT-AUDIT.md:32 (T8).
 *
 * Значение читается ОДИН раз и кешируется, то есть backend НЕИЗМЕНЕН для PE с первого
 * обращения к предикату и не может быть переигран SetEnvironmentVariable из гостя.
 *
 * Буфер намеренно велик: unix-половина принимает только hb|fex|none (иначе fatal_error),
 * поэтому «не поместилось» здесь недостижимо, и молчаливый откат к hb невозможен.
 * Печать безусловная — молчание прибора обязано отличаться от «backend = hb». */
static int macrunner_cpu_backend_pe_is_hb = -1;

BOOL macrunner_cpu_backend_is_hb(void)
{
    if (macrunner_cpu_backend_pe_is_hb == -1)
    {
        WCHAR value[64] = {0};
        RTL_USER_PROCESS_PARAMETERS *params = NtCurrentTeb()->Peb->ProcessParameters;
        BOOL env_ready = params && params->Environment;
        BOOL found = env_ready && get_env( L"MACRUNNER_CPU_BACKEND", value, sizeof(value) );
        BOOL is_hb = TRUE;

        if (found && value[0])
            is_hb = ((value[0] == 'h' || value[0] == 'H') &&
                     (value[1] == 'b' || value[1] == 'B') && !value[2]);
        /* ★ Ответ кешируем ТОЛЬКО когда окружение уже есть: иначе «переменной не видно»
         * закешировалось бы как «backend = hb» — тот самый тихий откат. */
        if (env_ready) macrunner_cpu_backend_pe_is_hb = is_hb;
        else
        {
            static unsigned int mr_early;
            if (mr_early++ < 4)
                MESSAGE( "macrunner-cpu-backend-pe: окружение ещё не готово, ответ не кеширую\n" );
            return is_hb;
        }
        MESSAGE( "macrunner-cpu-backend-pe: value=%s is_hb=%u\n",
                 found ? debugstr_w(value) : "(unset)", is_hb );
        return is_hb;
    }
    return macrunner_cpu_backend_pe_is_hb;
}

static BOOL macrunner_hb_loader_env_enabled( WCHAR *value, unsigned int len, BOOL *has_env )
{
    BOOL found = get_env( L"MACRUNNER_HB_X64_LOADER", value, len );
    BOOL enabled = found && value[0] && value[0] != '0';
    /* ★ ШАГ-2 (T8): владелец CPU решает ПЕРВЫМ. Это единственная точка, через которую
     * PE-половина включает марш HyperBridge, — значит и гасить достаточно здесь.
     * Спрашиваем БЕЗУСЛОВНО, а не под `enabled &&`: иначе при X64_LOADER=0 прибор
     * backend-а молчал бы, и «FEX выбран» было бы неотличимо от «сюда не дошли». */
    BOOL cpu_is_hb = macrunner_cpu_backend_is_hb();

    if (enabled && !cpu_is_hb) enabled = FALSE;

    if (enabled && (value[0] == 'f' || value[0] == 'F') &&
        (value[1] == 'a' || value[1] == 'A') &&
        (value[2] == 'l' || value[2] == 'L') &&
        (value[3] == 's' || value[3] == 'S') &&
        (value[4] == 'e' || value[4] == 'E') && !value[5])
        enabled = FALSE;
    if (has_env) *has_env = found;
    return enabled;
}

static BOOL macrunner_hb_x64_main_requested(void)
{
    static int cached_result = -1;
    if (macrunner_hb_amd64_main_on_arm64) return TRUE;
    if (cached_result != -1) return cached_result;
    {
        WCHAR value[8] = {0};
        IMAGE_NT_HEADERS *nt;
        BOOL has_env;
        BOOL enabled;
        static unsigned int report_count;

        /* Keep the default Wine lanes completely untouched unless Phase G
         * explicitly asks to route a regular AMD64 PE through HyperBridge.
         *
         * Do not gate this on PE-side current_machine.  In the x86_64-windows
         * loader image it is correctly AMD64 even when the Unix host loader is
         * ARM64; the real safety gate is the main image machine plus the explicit
         * environment opt-in. */
        enabled = macrunner_hb_loader_env_enabled( value, sizeof(value), &has_env );
        nt = RtlImageNtHeader( NtCurrentTeb()->Peb->ImageBaseAddress );
        MESSAGE( "MacRunner HyperBridge gate current=%04x has_env=%u value=%s enabled=%u main=%04x\n",
               current_machine, has_env, has_env ? debugstr_w(value) : "(unset)", enabled,
               nt ? nt->FileHeader.Machine : 0 );
        if (macrunner_hb_trace_bootstrap() && report_count++ < 8)
            MESSAGE( "macrunner-hb-bootstrap-gate: current=%04x has_env=%u value=%s enabled=%u main=%04x image=%p\n",
                     current_machine, has_env, has_env ? debugstr_w(value) : "(unset)", enabled,
                     nt ? nt->FileHeader.Machine : 0, NtCurrentTeb()->Peb->ImageBaseAddress );
        if (!enabled)
        {
            cached_result = FALSE;
            return FALSE;
        }
        if (!nt) return FALSE;
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return FALSE;
        cached_result = (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
        return cached_result;
    }
}

static WORD macrunner_hb_requested_main_machine(void)
{
    WCHAR value[8] = {0};
    IMAGE_NT_HEADERS *nt;

    if (!macrunner_hb_loader_env_enabled( value, sizeof(value), NULL )) return 0;
    if (!(nt = RtlImageNtHeader( NtCurrentTeb()->Peb->ImageBaseAddress ))) return 0;

    switch (nt->FileHeader.Machine)
    {
    case IMAGE_FILE_MACHINE_I386:
    case IMAGE_FILE_MACHINE_AMD64:
        return nt->FileHeader.Machine;
    default:
        return 0;
    }
}

static WORD macrunner_hb_builtin_dependency_machine(void)
{
    WORD requested;
    WCHAR value[8] = {0};
    BOOL enabled;
    static unsigned int report_count;

    if (macrunner_hb_native_counterpart_machine) return macrunner_hb_native_counterpart_machine;

    /*
     * In the PE32 HyperBridge lane the running i386 ntdll may receive absolute
     * system32 paths from WOW64 bootstrap before the usual file-system
     * redirection has a chance to steer them to syswow64.  Keep this env-gated
     * so stock i386 Wine behavior is untouched, but force builtin lookup to the
     * i386 dist lane instead of ever mapping prefix system32/x86_64 images.
     */
    if (current_machine == IMAGE_FILE_MACHINE_I386)
    {
        /* ★★★★★★ MacRunner 2026-09-01 — РАЗВЕДЕНЫ ДВЕ РАЗНЫЕ СУЩНОСТИ.
         *
         * Здесь стоял `macrunner_hb_loader_env_enabled()`, то есть гейт
         * `MACRUNNER_HB_X64_LOADER` — про x64-загрузчик. Разворот встроенных библиотек
         * для i386 к x64-загрузчику отношения не имеет, а был выключен ЗАОДНО с ним.
         * Возврат 0 заставляет `macrunner_hb_open_native_builtin_dependency` немедленно
         * отдать STATUS_DLL_NOT_FOUND — и 32-битный гость может брать ТОЛЬКО то, что
         * физически лежит в префиксе, тогда как 64-битный разворачивает имена в дист.
         *
         * Чем это стоило: 32-битная Diablo не находила `winemac.drv` (c0000135), драйвер
         * вывода не грузился, отрисовки не было. Замер на ИСХОДНОМ префиксе, без единого
         * скопированного файла: гейт выкл — 2 отказа, вкл — 0, `user32-loaddriver`
         * `c0000135` -> `00000000`.
         *
         * Своя переменная `MACRUNNER_HB_I386_BUILTIN`; `=1` включает. Старый гейт
         * продолжает включать разворот, если задан, — уже настроенные лейны не ломаются.
         *
         * ★★★ УМОЛЧАНИЕ ВКЛЮЧЕНО. Ниже — история, почему оно час было выключено. Включение действительно чинит загрузку
         * (отказы загрузки на четырёх мишенях 2/6/9/1 -> 0/0/3/0, у UT99 впервые появился
         * экран), НО вносит падение: парный замер на UT99 дал `c0000005` в 2 прогонах из
         * 3 при включённом и 0 из 3 при выключенном.
         *
         * ✗ ОТОЗВАНО 01.09: «виновата КИРИЛЛИЦА в строке формата». Тот вывод сравнивал
         * "размер=%lx" (12 байт) с "size=%lx" (4 байта) — менялись СРАЗУ алфавит, длина
         * литерала и раскладка образа; отказы к тому же считались подстрокой `c0000005`,
         * которая попадается на стеке как обычное число.
         *
         * ПАРНЫЙ ЗАМЕР 01.09 (scripts/замер-формата.sh): четыре руки в ОДНОМ двоичном
         * файле, равной длины, выбор гейтом MACRUNNER_HB_FMT_PROBE; 4 круга по 60 с,
         * руки вперемежку. Настоящих докладов об исключении (не подстрок) за 4 прогона:
         *     рука 0  печати нет            7
         *     рука 1  латиница в формате    5
         *     рука 2  кириллица в формате   4
         *     рука 3  кириллица аргументом  4
         * Алфавит не различается, а рука БЕЗ печати даёт БОЛЬШЕ всех. Докладчик в
         * strspn (dlls/ntdll/string.c) не сработал ни разу за 16 прогонов: строки без
         * завершающего нуля туда не приходило. Кириллица в строках формата НЕ ОПАСНА.
         *
         * Настоящее падение UT99 иное и от рук не зависит (2 случая на 16 прогонов, в
         * руках 2 и 3): SIGILL/KERN_INVALID_ADDRESS по адресу внутри зарезервированного
         * гостевого окна 0x3xxxxxxxx; отчёт macOS называет unregister_view/delete_view,
         * но смещения +0xe11f8 ложные — ближайший символ снизу без верхней границы.
         *
         * Сам разворот для i386 исправен: `winemac.drv` грузится. Умолчание включено. */
        {
            static int i386_gate = -1;
            if (i386_gate < 0)
            {
                WCHAR own[8] = {0};
                BOOL own_found = get_env( L"MACRUNNER_HB_I386_BUILTIN", own, sizeof(own) );
                if (own_found && own[0])
                    i386_gate = (own[0] != '0');
                else
                    i386_gate = 1;   /* ★ 01.09 — умолчание ВКЛЮЧЕНО, см. ниже */
            }
            enabled = i386_gate || macrunner_hb_loader_env_enabled( value, sizeof(value), NULL );
        }
        if (report_count++ < 16)
            MESSAGE( "MacRunner HyperBridge i386 builtin gate enabled=%u value=%s\n",
                   enabled, debugstr_w(value) );
        return enabled ? IMAGE_FILE_MACHINE_I386 : 0;
    }

    requested = macrunner_hb_requested_main_machine();
    if (current_machine == IMAGE_FILE_MACHINE_I386 && requested == IMAGE_FILE_MACHINE_I386)
        return IMAGE_FILE_MACHINE_I386;
    if (current_machine != IMAGE_FILE_MACHINE_ARM64) return 0;
    if (requested == IMAGE_FILE_MACHINE_I386) return IMAGE_FILE_MACHINE_I386;
    if (requested == IMAGE_FILE_MACHINE_AMD64) return 0;

    return IMAGE_FILE_MACHINE_ARM64;
}

static BOOL macrunner_hb_prefer_native_builtin_dependency(void)
{
    return !!macrunner_hb_builtin_dependency_machine();
}

static const WCHAR *macrunner_hb_basename_from_path( const WCHAR *name )
{
    const WCHAR *base = name, *p;

    if (!name) return NULL;
    for (p = name; *p; p++)
    {
        if (*p == '\\' || *p == '/') base = p + 1;
    }
    return base;
}

static BOOL macrunner_hb_is_wow64_host_module( const WCHAR *name )
{
    const WCHAR *base = macrunner_hb_basename_from_path( name );

    if (!base) return FALSE;
    return !wcsicmp( base, L"wow64.dll" ) ||
           !wcsicmp( base, L"wow64win.dll" ) ||
           !wcsicmp( base, L"wow64cpu.dll" ) ||
           !wcsicmp( base, L"xtajit.dll" ) ||
           !wcsicmp( base, L"xtajit64.dll" ) ||
           !wcsicmp( base, L"win32u.dll" );
}

static BOOL macrunner_hb_is_wow64_bootstrap_host_module( const WCHAR *name )
{
    const WCHAR *base = macrunner_hb_basename_from_path( name );

    if (!base) return FALSE;
    return !wcsicmp( base, L"wow64.dll" ) ||
           !wcsicmp( base, L"wow64win.dll" ) ||
           !wcsicmp( base, L"wow64cpu.dll" ) ||
           !wcsicmp( base, L"xtajit.dll" ) ||
           !wcsicmp( base, L"xtajit64.dll" ) ||
           !wcsicmp( base, L"win32u.dll" );
}

static BOOL macrunner_hb_pe32_system32_redirect_enabled( const WCHAR *name )
{
    WCHAR value[8] = {0};
    IMAGE_NT_HEADERS *nt;

    if (macrunner_hb_is_wow64_host_module( name )) return FALSE;
    if (!macrunner_hb_loader_env_enabled( value, sizeof(value), NULL )) return FALSE;
    if (!(nt = RtlImageNtHeader( NtCurrentTeb()->Peb->ImageBaseAddress ))) return FALSE;
    return nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386;
}

static BOOL macrunner_hb_path_segment_is_system32( const WCHAR *path, SIZE_T len )
{
    SIZE_T system_len = wcslen( system_dir );

    while (len && (path[len - 1] == '\\' || path[len - 1] == '/')) len--;
    if (system_len && system_dir[system_len - 1] == '\\') system_len--;
    return len == system_len && !wcsnicmp( path, system_dir, len );
}

static NTSTATUS open_dll_file( UNICODE_STRING *nt_name, WINE_MODREF **pwm, HANDLE *mapping,
                               SECTION_IMAGE_INFORMATION *image_info, struct file_id *id );

#define RTL_UNLOAD_EVENT_TRACE_NUMBER 64

typedef struct _RTL_UNLOAD_EVENT_TRACE
{
    void *BaseAddress;
    SIZE_T SizeOfImage;
    ULONG Sequence;
    ULONG TimeDateStamp;
    ULONG CheckSum;
    WCHAR ImageName[32];
} RTL_UNLOAD_EVENT_TRACE, *PRTL_UNLOAD_EVENT_TRACE;

static RTL_UNLOAD_EVENT_TRACE unload_traces[RTL_UNLOAD_EVENT_TRACE_NUMBER];
static RTL_UNLOAD_EVENT_TRACE *unload_trace_ptr;
static unsigned int unload_trace_seq;

static void __fastcall default_thread_init_func( DWORD unknown, LPTHREAD_START_ROUTINE entry, void *arg )
{
    RtlExitUserThread( entry( arg ) );
}

static void module_push_unload_trace( const WINE_MODREF *wm )
{
    RTL_UNLOAD_EVENT_TRACE *ptr = &unload_traces[unload_trace_seq];
    const LDR_DATA_TABLE_ENTRY *ldr = &wm->ldr;
    unsigned int len = min(sizeof(ptr->ImageName) - sizeof(WCHAR), ldr->BaseDllName.Length);

    ptr->BaseAddress = ldr->DllBase;
    ptr->SizeOfImage = ldr->SizeOfImage;
    ptr->Sequence = unload_trace_seq;
    ptr->TimeDateStamp = ldr->TimeDateStamp;
    ptr->CheckSum = wm->CheckSum;
    memcpy(ptr->ImageName, ldr->BaseDllName.Buffer, len);
    ptr->ImageName[len / sizeof(*ptr->ImageName)] = 0;

    unload_trace_seq = (unload_trace_seq + 1) % ARRAY_SIZE(unload_traces);
    unload_trace_ptr = unload_traces;
}

static int rtl_rb_tree_put( RTL_RB_TREE *tree, const void *key, RTL_BALANCED_NODE *entry,
                            int (*compare_func)( const void *key, const RTL_BALANCED_NODE *entry ))
{
    RTL_BALANCED_NODE *parent = tree->root;
    BOOLEAN right = 0;
    int c;

    while (parent)
    {
        if (!(c = compare_func( key, parent ))) return -1;
        right = c > 0;
        if (!parent->Children[right]) break;
        parent = parent->Children[right];
    }
    RtlRbInsertNodeEx( tree, parent, right, entry );
    return 0;
}

static RTL_BALANCED_NODE *rtl_rb_tree_get( RTL_RB_TREE *tree, const void *key,
                                           int (*compare_func)( const void *key, const RTL_BALANCED_NODE *entry ))
{
    RTL_BALANCED_NODE *parent = tree->root;
    int c;

    while (parent)
    {
        if (!(c = compare_func( key, parent ))) return parent;
        parent = parent->Children[c > 0];
    }
    return NULL;
}


/*********************************************************************
 *           RtlGetUnloadEventTrace [NTDLL.@]
 */
RTL_UNLOAD_EVENT_TRACE * WINAPI RtlGetUnloadEventTrace(void)
{
    return unload_traces;
}

/*********************************************************************
 *           RtlGetUnloadEventTraceEx [NTDLL.@]
 */
void WINAPI RtlGetUnloadEventTraceEx(ULONG **size, ULONG **count, void **trace)
{
    static ULONG element_size = sizeof(*unload_traces);
    static ULONG element_count = ARRAY_SIZE(unload_traces);

    *size = &element_size;
    *count = &element_count;
    *trace = &unload_trace_ptr;
}

/*************************************************************************
 *		call_dll_entry_point
 *
 * Some brain-damaged dlls (ir32_32.dll for instance) modify ebx in
 * their entry point, so we need a small asm wrapper. Testing indicates
 * that only modifying esi leads to a crash, so use this one to backup
 * ebp while running the dll entry proc.
 */
#if defined(__i386__)
extern BOOL call_dll_entry_point( DLLENTRYPROC proc, void *module, UINT reason, void *reserved );
__ASM_GLOBAL_FUNC(call_dll_entry_point,
                  "pushl %ebp\n\t"
                  __ASM_CFI(".cfi_adjust_cfa_offset 4\n\t")
                  __ASM_CFI(".cfi_rel_offset %ebp,0\n\t")
                  "movl %esp,%ebp\n\t"
                  __ASM_CFI(".cfi_def_cfa_register %ebp\n\t")
                  "pushl %ebx\n\t"
                  __ASM_CFI(".cfi_rel_offset %ebx,-4\n\t")
                  "pushl %esi\n\t"
                  __ASM_CFI(".cfi_rel_offset %esi,-8\n\t")
                  "pushl %edi\n\t"
                  __ASM_CFI(".cfi_rel_offset %edi,-12\n\t")
                  "movl %ebp,%esi\n\t"
                  __ASM_CFI(".cfi_def_cfa_register %esi\n\t")
                  "pushl 20(%ebp)\n\t"
                  "pushl 16(%ebp)\n\t"
                  "pushl 12(%ebp)\n\t"
                  "movl 8(%ebp),%eax\n\t"
                  "call *%eax\n\t"
                  "movl %esi,%ebp\n\t"
                  __ASM_CFI(".cfi_def_cfa_register %ebp\n\t")
                  "leal -12(%ebp),%esp\n\t"
                  "popl %edi\n\t"
                  __ASM_CFI(".cfi_same_value %edi\n\t")
                  "popl %esi\n\t"
                  __ASM_CFI(".cfi_same_value %esi\n\t")
                  "popl %ebx\n\t"
                  __ASM_CFI(".cfi_same_value %ebx\n\t")
                  "popl %ebp\n\t"
                  __ASM_CFI(".cfi_def_cfa %esp,4\n\t")
                  __ASM_CFI(".cfi_same_value %ebp\n\t")
                  "ret" )
#elif defined(__x86_64__) && !defined(__arm64ec__)
extern BOOL CDECL call_dll_entry_point( DLLENTRYPROC proc, void *module, UINT reason, void *reserved );
/* Some apps modify rbx in TLS entry point. */
__ASM_GLOBAL_FUNC(call_dll_entry_point,
                  "pushq %rbx\n\t"
                  __ASM_SEH(".seh_pushreg %rbx\n\t")
                  __ASM_CFI(".cfi_adjust_cfa_offset 8\n\t")
                  __ASM_CFI(".cfi_rel_offset %rbx,0\n\t")
                  "subq $48,%rsp\n\t"
                  __ASM_SEH(".seh_stackalloc 48\n\t")
                  __ASM_SEH(".seh_endprologue\n\t")
                  __ASM_CFI(".cfi_adjust_cfa_offset 48\n\t")
                  "mov %rcx,%r10\n\t"
                  "mov %rdx,%rcx\n\t"
                  "mov %r8d,%edx\n\t"
                  "mov %r9,%r8\n\t"
                  "call *%r10\n\t"
                  "addq $48,%rsp\n\t"
                  __ASM_CFI(".cfi_adjust_cfa_offset -48\n\t")
                  "popq %rbx\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset -8\n\t")
                   __ASM_CFI(".cfi_same_value %rbx\n\t")
                  "ret" )
#else
static inline BOOL call_dll_entry_point( DLLENTRYPROC proc, void *module,
                                         UINT reason, void *reserved )
{
    return proc( module, reason, reserved );
}
#endif


#if defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)
/*************************************************************************
 *		stub_entry_point
 *
 * Entry point for stub functions.
 */
static void WINAPI stub_entry_point( const char *dll, const char *name, void *ret_addr )
{
    EXCEPTION_RECORD rec;

    rec.ExceptionCode           = EXCEPTION_WINE_STUB;
    rec.ExceptionFlags          = EXCEPTION_NONCONTINUABLE;
    rec.ExceptionRecord         = NULL;
    rec.ExceptionAddress        = ret_addr;
    rec.NumberParameters        = 2;
    rec.ExceptionInformation[0] = (ULONG_PTR)dll;
    rec.ExceptionInformation[1] = (ULONG_PTR)name;
    for (;;) RtlRaiseException( &rec );
}


#pragma pack(push,1)
#ifdef __i386__
struct stub
{
    BYTE        pushl1;     /* pushl $name */
    const char *name;
    BYTE        pushl2;     /* pushl $dll */
    const char *dll;
    BYTE        call;       /* call stub_entry_point */
    DWORD       entry;
};
#elif defined(__arm__)
struct stub
{
    DWORD ldr_r0;        /* ldr r0, $dll */
    DWORD ldr_r1;        /* ldr r1, $name */
    DWORD mov_r2_lr;     /* mov r2, lr */
    DWORD ldr_pc_pc;     /* ldr pc, [pc, #4] */
    const char *dll;
    const char *name;
    const void* entry;
};
#elif defined(__aarch64__)
struct stub
{
    DWORD ldr_x0;        /* ldr x0, $dll */
    DWORD ldr_x1;        /* ldr x1, $name */
    DWORD mov_x2_lr;     /* mov x2, lr */
    DWORD ldr_x16;       /* ldr x16, $entry */
    DWORD br_x16;        /* br x16 */
    const char *dll;
    const char *name;
    const void *entry;
};
#else
struct stub
{
    BYTE movq_rdi[2];      /* movq $dll,%rdi */
    const char *dll;
    BYTE movq_rsi[2];      /* movq $name,%rsi */
    const char *name;
    BYTE movq_rsp_rdx[4];  /* movq (%rsp),%rdx */
    BYTE movq_rax[2];      /* movq $entry, %rax */
    const void* entry;
    BYTE jmpq_rax[2];      /* jmp %rax */
};
#endif
#pragma pack(pop)

/*************************************************************************
 *		allocate_stub
 *
 * Allocate a stub entry point.
 */
static ULONG_PTR allocate_stub( const char *dll, const char *name )
{
#define MAX_SIZE 65536
    static struct stub *stubs;
    static unsigned int nb_stubs;
    struct stub *stub;

    if (nb_stubs >= MAX_SIZE / sizeof(*stub)) return 0xdeadbeef;

    if (!stubs)
    {
        SIZE_T size = MAX_SIZE;
        if (NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&stubs, 0, &size,
                                     MEM_COMMIT, PAGE_EXECUTE_READWRITE ) != STATUS_SUCCESS)
            return 0xdeadbeef;
    }
    stub = &stubs[nb_stubs++];
#ifdef __i386__
    stub->pushl1    = 0x68;  /* pushl $name */
    stub->name      = name;
    stub->pushl2    = 0x68;  /* pushl $dll */
    stub->dll       = dll;
    stub->call      = 0xe8;  /* call stub_entry_point */
    stub->entry     = (BYTE *)stub_entry_point - (BYTE *)(&stub->entry + 1);
#elif defined(__arm__)
    stub->ldr_r0    = 0xe59f0008;   /* ldr r0, [pc, #8] ($dll) */
    stub->ldr_r1    = 0xe59f1008;   /* ldr r1, [pc, #8] ($name) */
    stub->mov_r2_lr = 0xe1a0200e;   /* mov r2, lr */
    stub->ldr_pc_pc = 0xe59ff004;   /* ldr pc, [pc, #4] */
    stub->dll       = dll;
    stub->name      = name;
    stub->entry     = stub_entry_point;
#elif defined(__aarch64__)
    stub->ldr_x0    = 0x580000a0; /* ldr x0, #20 ($dll) */
    stub->ldr_x1    = 0x580000c1; /* ldr x1, #24 ($name) */
    stub->mov_x2_lr = 0xaa1e03e2; /* mov x2, lr */
    stub->ldr_x16   = 0x580000d0; /* ldr x16, #24 ($entry) */
    stub->br_x16    = 0xd61f0200; /* br x16 */
    stub->dll       = dll;
    stub->name      = name;
    stub->entry     = stub_entry_point;
#else
    stub->movq_rdi[0]     = 0x48;  /* movq $dll,%rcx */
    stub->movq_rdi[1]     = 0xb9;
    stub->dll             = dll;
    stub->movq_rsi[0]     = 0x48;  /* movq $name,%rdx */
    stub->movq_rsi[1]     = 0xba;
    stub->name            = name;
    stub->movq_rsp_rdx[0] = 0x4c;  /* movq (%rsp),%r8 */
    stub->movq_rsp_rdx[1] = 0x8b;
    stub->movq_rsp_rdx[2] = 0x04;
    stub->movq_rsp_rdx[3] = 0x24;
    stub->movq_rax[0]     = 0x48;  /* movq $entry, %rax */
    stub->movq_rax[1]     = 0xb8;
    stub->entry           = stub_entry_point;
    stub->jmpq_rax[0]     = 0xff;  /* jmp %rax */
    stub->jmpq_rax[1]     = 0xe0;
#endif
    return (ULONG_PTR)stub;
}

#else  /* __i386__ */
static inline ULONG_PTR allocate_stub( const char *dll, const char *name ) { return 0xdeadbeef; }
#endif  /* __i386__ */

/* call ldr notifications */
static void call_ldr_notifications( ULONG reason, LDR_DATA_TABLE_ENTRY *module )
{
    struct ldr_notification *notify, *notify_next;
    LDR_DLL_NOTIFICATION_DATA data;

    if (process_detaching && reason == LDR_DLL_NOTIFICATION_REASON_UNLOADED) return;

    data.Loaded.Flags       = 0;
    data.Loaded.FullDllName = &module->FullDllName;
    data.Loaded.BaseDllName = &module->BaseDllName;
    data.Loaded.DllBase     = module->DllBase;
    data.Loaded.SizeOfImage = module->SizeOfImage;

    LIST_FOR_EACH_ENTRY_SAFE( notify, notify_next, &ldr_notifications, struct ldr_notification, entry )
    {
        TRACE_(relay)("\1Call LDR notification callback (proc=%p,reason=%lu,data=%p,context=%p)\n",
                notify->callback, reason, &data, notify->context );

        notify->callback(reason, &data, notify->context);

        TRACE_(relay)("\1Ret  LDR notification callback (proc=%p,reason=%lu,data=%p,context=%p)\n",
                notify->callback, reason, &data, notify->context );
    }
}

/* compare base address */
static int base_address_compare( const void *key, const RTL_BALANCED_NODE *entry )
{
    const LDR_DATA_TABLE_ENTRY *mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode);
    const char *base = key;

    if (base < (char *)mod->DllBase) return -1;
    if (base > (char *)mod->DllBase) return 1;
    return 0;
}

/* compute basename hash */
static ULONG hash_basename( const UNICODE_STRING *basename )
{
    ULONG hash = 0;

    RtlHashUnicodeString( basename, TRUE, HASH_STRING_ALGORITHM_DEFAULT, &hash );
    return hash % HASH_MAP_SIZE;
}

/* build NT name for dll in system directory */
static NTSTATUS build_sysdir_nt_name( const WCHAR *name, UNICODE_STRING *nt_name )
{
    nt_name->Length = (4 + wcslen(system_dir) + wcslen(name)) * sizeof(WCHAR);
    nt_name->MaximumLength = nt_name->Length + sizeof(WCHAR);
    nt_name->Buffer = RtlAllocateHeap( GetProcessHeap(), 0, nt_name->MaximumLength );
    if (!nt_name->Buffer)
    {
        nt_name->Length = nt_name->MaximumLength = 0;
        return STATUS_NO_MEMORY;
    }
    wcscpy( nt_name->Buffer, L"\\??\\" );
    wcscat( nt_name->Buffer, system_dir );
    wcscat( nt_name->Buffer, name );
    return STATUS_SUCCESS;
}

/*************************************************************************
 *		get_modref
 *
 * Looks for the referenced HMODULE in the current process
 * The loader_section must be locked while calling this function.
 */
static WINE_MODREF *get_modref( HMODULE hmod )
{
    PLDR_DATA_TABLE_ENTRY mod;
    RTL_BALANCED_NODE *node;

    if (cached_modref && cached_modref->ldr.DllBase == hmod) return cached_modref;

    if (!(node = rtl_rb_tree_get( &base_address_index_tree, hmod, base_address_compare ))) return NULL;
    mod = CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode);
    return cached_modref = CONTAINING_RECORD(mod, WINE_MODREF, ldr);
}


/**********************************************************************
 *	    find_basename_module
 *
 * Find a module from its base name.
 * The loader_section must be locked while calling this function
 */
static WINE_MODREF *find_basename_module_machine( LPCWSTR name, WORD machine );

static WINE_MODREF *find_basename_module( LPCWSTR name )
{
    PLIST_ENTRY mark, entry;
    UNICODE_STRING name_str;

    if (macrunner_hb_amd64_main_on_arm64)
        return find_basename_module_machine( name, current_machine );

    RtlInitUnicodeString( &name_str, name );

    if (cached_modref && !(cached_modref->ldr.Flags & LDR_REDIRECTED)
        && RtlEqualUnicodeString( &name_str, &cached_modref->ldr.BaseDllName, TRUE ))
        return cached_modref;

    mark = &hash_table[hash_basename( &name_str )];
    for (entry = mark->Flink; entry != mark; entry = entry->Flink)
    {
        WINE_MODREF *mod = CONTAINING_RECORD(entry, WINE_MODREF, ldr.HashLinks);
        if (!mod->system && !(mod->ldr.Flags & LDR_REDIRECTED)
            && RtlEqualUnicodeString( &name_str, &mod->ldr.BaseDllName, TRUE ))
        {
            cached_modref = CONTAINING_RECORD(mod, WINE_MODREF, ldr);
            return cached_modref;
        }
    }
    return NULL;
}

static WINE_MODREF *find_basename_module_machine( LPCWSTR name, WORD machine )
{
    PLIST_ENTRY mark, entry;
    UNICODE_STRING name_str;

    RtlInitUnicodeString( &name_str, name );
    if (cached_modref && !(cached_modref->ldr.Flags & LDR_REDIRECTED)
        && RtlEqualUnicodeString( &name_str, &cached_modref->ldr.BaseDllName, TRUE ))
    {
        IMAGE_NT_HEADERS *nt = RtlImageNtHeader( cached_modref->ldr.DllBase );
        if (nt && nt->FileHeader.Machine == machine) return cached_modref;
    }

    mark = &hash_table[hash_basename( &name_str )];
    for (entry = mark->Flink; entry != mark; entry = entry->Flink)
    {
        WINE_MODREF *mod = CONTAINING_RECORD(entry, WINE_MODREF, ldr.HashLinks);
        IMAGE_NT_HEADERS *nt;

        if (mod->ldr.Flags & LDR_REDIRECTED) continue;
        if (!RtlEqualUnicodeString( &name_str, &mod->ldr.BaseDllName, TRUE )) continue;
        if (!(nt = RtlImageNtHeader( mod->ldr.DllBase ))) continue;
        if (nt->FileHeader.Machine != machine) continue;
        cached_modref = mod;
        return mod;
    }
    return NULL;
}

static void macrunner_hb_copy_import_name( char *dst, size_t dst_size, const char *src )
{
    size_t i;

    if (!dst || !dst_size) return;
    if (!src) src = "";
    for (i = 0; i + 1 < dst_size && src[i]; i++) dst[i] = src[i];
    dst[i] = 0;
}

static void macrunner_hb_format_ordinal_import_name( char *dst, size_t dst_size, ULONG ordinal )
{
    char digits[16];
    size_t i = 0, j = 0;

    if (!dst || dst_size < 2) return;
    dst[j++] = '#';
    do
    {
        digits[i++] = '0' + ordinal % 10;
        ordinal /= 10;
    } while (ordinal && i < sizeof(digits));
    while (i && j + 1 < dst_size) dst[j++] = digits[--i];
    dst[j] = 0;
}

static BOOL macrunner_hb_ascii_ieq( const char *a, const char *b )
{
    unsigned char ca, cb;

    if (!a || !b) return FALSE;
    while (*a && *b)
    {
        ca = *a++;
        cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca += 'a' - 'A';
        if (cb >= 'A' && cb <= 'Z') cb += 'a' - 'A';
        if (ca != cb) return FALSE;
    }
    return !*a && !*b;
}

static char macrunner_hb_x64_acmdln_buffer[32768];
static char *macrunner_hb_x64_acmdln_ptr = macrunner_hb_x64_acmdln_buffer;
static WCHAR macrunner_hb_x64_wcmdln_buffer[32768];
static WCHAR *macrunner_hb_x64_wcmdln_ptr = macrunner_hb_x64_wcmdln_buffer;
static BOOL macrunner_hb_x64_cmdln_initialized;

static void macrunner_hb_init_x64_cmdln_proxy(void)
{
    RTL_USER_PROCESS_PARAMETERS *params;
    const WCHAR *src;
    SIZE_T i, len, max_wchars, max_chars;

    if (macrunner_hb_x64_cmdln_initialized) return;
    macrunner_hb_x64_cmdln_initialized = TRUE;

    params = NtCurrentTeb()->Peb->ProcessParameters;
    if (!params || !params->CommandLine.Buffer)
    {
        macrunner_hb_x64_acmdln_buffer[0] = 0;
        macrunner_hb_x64_wcmdln_buffer[0] = 0;
        return;
    }

    src = params->CommandLine.Buffer;
    len = params->CommandLine.Length / sizeof(WCHAR);
    max_wchars = ARRAY_SIZE(macrunner_hb_x64_wcmdln_buffer) - 1;
    max_chars = ARRAY_SIZE(macrunner_hb_x64_acmdln_buffer) - 1;
    if (len > max_wchars) len = max_wchars;
    if (len > max_chars) len = max_chars;

    for (i = 0; i < len; i++)
    {
        WCHAR ch = src[i];
        macrunner_hb_x64_wcmdln_buffer[i] = ch;
        macrunner_hb_x64_acmdln_buffer[i] = ch < 0x80 ? (char)ch : '?';
    }
    macrunner_hb_x64_wcmdln_buffer[i] = 0;
    macrunner_hb_x64_acmdln_buffer[i] = 0;
}

static ULONG_PTR macrunner_hb_get_x64_data_import_proxy( const char *dll_name, const char *import_name,
                                                         ULONG_PTR target )
{
    if (!macrunner_hb_ascii_ieq( dll_name, "msvcrt.dll" )) return 0;

    if (macrunner_hb_ascii_ieq( import_name, "_acmdln" ))
    {
        macrunner_hb_init_x64_cmdln_proxy();
        MESSAGE( "MacRunner HyperBridge data import proxy msvcrt!_acmdln native=%p proxy=%p value=%p len=%zu\n",
               (void *)target, &macrunner_hb_x64_acmdln_ptr, macrunner_hb_x64_acmdln_ptr,
               strlen(macrunner_hb_x64_acmdln_buffer) );
        return (ULONG_PTR)&macrunner_hb_x64_acmdln_ptr;
    }
    if (macrunner_hb_ascii_ieq( import_name, "_wcmdln" ))
    {
        macrunner_hb_init_x64_cmdln_proxy();
        MESSAGE( "MacRunner HyperBridge data import proxy msvcrt!_wcmdln native=%p proxy=%p value=%p len=%zu\n",
               (void *)target, &macrunner_hb_x64_wcmdln_ptr, macrunner_hb_x64_wcmdln_ptr,
               wcslen(macrunner_hb_x64_wcmdln_buffer) );
        return (ULONG_PTR)&macrunner_hb_x64_wcmdln_ptr;
    }
    return 0;
}

static BOOL macrunner_hb_is_crt_string_semantic_import( const char *import_name )
{
    return macrunner_hb_ascii_ieq( import_name, "memset" ) ||
           macrunner_hb_ascii_ieq( import_name, "memcpy" ) ||
           macrunner_hb_ascii_ieq( import_name, "memmove" ) ||
           macrunner_hb_ascii_ieq( import_name, "memchr" ) ||
           macrunner_hb_ascii_ieq( import_name, "memcmp" ) ||
           macrunner_hb_ascii_ieq( import_name, "strcmp" ) ||
           macrunner_hb_ascii_ieq( import_name, "strncmp" ) ||
           macrunner_hb_ascii_ieq( import_name, "strlen" ) ||
           macrunner_hb_ascii_ieq( import_name, "strnlen" ) ||
           macrunner_hb_ascii_ieq( import_name, "wcslen" ) ||
           macrunner_hb_ascii_ieq( import_name, "wcsnlen" ) ||
           macrunner_hb_ascii_ieq( import_name, "isdigit" ) ||
           macrunner_hb_ascii_ieq( import_name, "isspace" ) ||
           macrunner_hb_ascii_ieq( import_name, "isxdigit" ) ||
           macrunner_hb_ascii_ieq( import_name, "tolower" ) ||
           macrunner_hb_ascii_ieq( import_name, "toupper" ) ||
           macrunner_hb_ascii_ieq( import_name, "_tolower_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_toupper_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_iswalpha_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_iswcntrl_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_iswdigit_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_iswlower_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_iswprint_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_iswpunct_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_iswspace_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_iswupper_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_iswxdigit_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_towlower_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_towupper_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_strcoll_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_strxfrm_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_wcscoll_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_wcsxfrm_l" ) ||
           macrunner_hb_ascii_ieq( import_name, "_strdup" ) ||
           macrunner_hb_ascii_ieq( import_name, "mbrlen" );
}

static BOOL macrunner_hb_is_crt_stdio_semantic_import( const char *import_name )
{
    return macrunner_hb_ascii_ieq( import_name, "__acrt_iob_func" ) ||
           macrunner_hb_ascii_ieq( import_name, "__stdio_common_vfprintf" ) ||
           macrunner_hb_ascii_ieq( import_name, "__stdio_common_vfwprintf" ) ||
           macrunner_hb_ascii_ieq( import_name, "_fileno" ) ||
           macrunner_hb_ascii_ieq( import_name, "_fseeki64" ) ||
           macrunner_hb_ascii_ieq( import_name, "_ftelli64" ) ||
           macrunner_hb_ascii_ieq( import_name, "_setmode" ) ||
           macrunner_hb_ascii_ieq( import_name, "_wfopen" ) ||
           macrunner_hb_ascii_ieq( import_name, "fclose" ) ||
           macrunner_hb_ascii_ieq( import_name, "fflush" ) ||
           macrunner_hb_ascii_ieq( import_name, "fgetwc" ) ||
           macrunner_hb_ascii_ieq( import_name, "fopen" ) ||
           macrunner_hb_ascii_ieq( import_name, "fputc" ) ||
           macrunner_hb_ascii_ieq( import_name, "fputwc" ) ||
           macrunner_hb_ascii_ieq( import_name, "fread" ) ||
           macrunner_hb_ascii_ieq( import_name, "fseek" ) ||
           macrunner_hb_ascii_ieq( import_name, "fwrite" ) ||
           macrunner_hb_ascii_ieq( import_name, "getc" ) ||
           macrunner_hb_ascii_ieq( import_name, "setbuf" ) ||
           macrunner_hb_ascii_ieq( import_name, "ungetc" ) ||
           macrunner_hb_ascii_ieq( import_name, "ungetwc" );
}

static BOOL macrunner_hb_is_crt_multibyte_semantic_import( const char *import_name )
{
    return macrunner_hb_ascii_ieq( import_name, "_mbtowc_l" );
}

static BOOL macrunner_hb_is_crt_math_semantic_import( const char *import_name )
{
    return macrunner_hb_ascii_ieq( import_name, "ceilf" );
}

static BOOL macrunner_hb_is_crt_heap_semantic_import( const char *import_name )
{
    return macrunner_hb_ascii_ieq( import_name, "malloc" ) ||
           macrunner_hb_ascii_ieq( import_name, "free" ) ||
           macrunner_hb_ascii_ieq( import_name, "calloc" ) ||
           macrunner_hb_ascii_ieq( import_name, "realloc" ) ||
           macrunner_hb_ascii_ieq( import_name, "_aligned_malloc" ) ||
           macrunner_hb_ascii_ieq( import_name, "_aligned_free" );
}

static BOOL macrunner_hb_is_address_wait_semantic_import( const char *import_name )
{
    return macrunner_hb_ascii_ieq( import_name, "WaitOnAddress" ) ||
           macrunner_hb_ascii_ieq( import_name, "WakeByAddressAll" ) ||
           macrunner_hb_ascii_ieq( import_name, "WakeByAddressSingle" ) ||
           macrunner_hb_ascii_ieq( import_name, "RtlWaitOnAddress" ) ||
           macrunner_hb_ascii_ieq( import_name, "RtlWakeAddressAll" ) ||
           macrunner_hb_ascii_ieq( import_name, "RtlWakeAddressSingle" );
}

static BOOL macrunner_hb_is_x64_stack_probe_semantic_import( const char *dll_name,
                                                              const char *import_name )
{
    return macrunner_hb_ascii_ieq( dll_name, "ntdll.dll" ) &&
           (macrunner_hb_ascii_ieq( import_name, "___chkstk_ms" ) ||
            macrunner_hb_ascii_ieq( import_name, "__chkstk_ms" ) ||
            macrunner_hb_ascii_ieq( import_name, "__chkstk" ));
}

static BOOL macrunner_hb_is_semantic_import_stub( const char *dll_name, const char *import_name )
{
    if (macrunner_hb_is_address_wait_semantic_import( import_name ))
        return TRUE;
    if (macrunner_hb_is_x64_stack_probe_semantic_import( dll_name, import_name ))
        return TRUE;

    if (macrunner_hb_ascii_ieq( dll_name, "ucrtbase.dll" ))
        return macrunner_hb_ascii_ieq( import_name, "_configure_narrow_argv" ) ||
               macrunner_hb_ascii_ieq( import_name, "_configure_wide_argv" ) ||
               macrunner_hb_ascii_ieq( import_name, "_initialize_narrow_environment" ) ||
               macrunner_hb_ascii_ieq( import_name, "_initialize_wide_environment" ) ||
               macrunner_hb_ascii_ieq( import_name, "_get_initial_narrow_environment" ) ||
               macrunner_hb_ascii_ieq( import_name, "_get_initial_wide_environment" ) ||
               macrunner_hb_ascii_ieq( import_name, "__p__environ" ) ||
               macrunner_hb_ascii_ieq( import_name, "__p__wenviron" ) ||
               macrunner_hb_ascii_ieq( import_name, "_set_app_type" ) ||
               macrunner_hb_ascii_ieq( import_name, "__p___argc" ) ||
               macrunner_hb_ascii_ieq( import_name, "__p___argv" ) ||
               macrunner_hb_ascii_ieq( import_name, "exit" ) ||
               macrunner_hb_ascii_ieq( import_name, "_create_locale" ) ||
               macrunner_hb_ascii_ieq( import_name, "_free_locale" ) ||
               macrunner_hb_ascii_ieq( import_name, "_configthreadlocale" ) ||
               macrunner_hb_ascii_ieq( import_name, "setlocale" ) ||
               macrunner_hb_ascii_ieq( import_name, "__pctype_func" ) ||
               macrunner_hb_ascii_ieq( import_name, "___mb_cur_max_func" ) ||
               macrunner_hb_ascii_ieq( import_name, "___lc_codepage_func" ) ||
               macrunner_hb_ascii_ieq( import_name, "localeconv" ) ||
               macrunner_hb_is_crt_string_semantic_import( import_name ) ||
               macrunner_hb_is_crt_stdio_semantic_import( import_name ) ||
               macrunner_hb_is_crt_multibyte_semantic_import( import_name ) ||
               macrunner_hb_is_crt_math_semantic_import( import_name ) ||
               macrunner_hb_is_crt_heap_semantic_import( import_name );

    if (macrunner_hb_ascii_ieq( dll_name, "api-ms-win-crt-locale-l1-1-0.dll" ))
        return macrunner_hb_ascii_ieq( import_name, "_create_locale" ) ||
               macrunner_hb_ascii_ieq( import_name, "_free_locale" ) ||
               macrunner_hb_ascii_ieq( import_name, "_configthreadlocale" ) ||
               macrunner_hb_ascii_ieq( import_name, "setlocale" ) ||
               macrunner_hb_ascii_ieq( import_name, "__pctype_func" ) ||
               macrunner_hb_ascii_ieq( import_name, "___mb_cur_max_func" ) ||
               macrunner_hb_ascii_ieq( import_name, "___lc_codepage_func" ) ||
               macrunner_hb_ascii_ieq( import_name, "localeconv" );

    if (macrunner_hb_ascii_ieq( dll_name, "api-ms-win-crt-string-l1-1-0.dll" ))
        return macrunner_hb_is_crt_string_semantic_import( import_name );

    if (macrunner_hb_ascii_ieq( dll_name, "api-ms-win-crt-private-l1-1-0.dll" ))
        return macrunner_hb_is_crt_string_semantic_import( import_name );

    if (macrunner_hb_ascii_ieq( dll_name, "api-ms-win-crt-stdio-l1-1-0.dll" ))
        return macrunner_hb_is_crt_stdio_semantic_import( import_name );

    if (macrunner_hb_ascii_ieq( dll_name, "api-ms-win-crt-multibyte-l1-1-0.dll" ))
        return macrunner_hb_is_crt_multibyte_semantic_import( import_name );

    if (macrunner_hb_ascii_ieq( dll_name, "api-ms-win-crt-math-l1-1-0.dll" ))
        return macrunner_hb_is_crt_math_semantic_import( import_name );

    if (macrunner_hb_ascii_ieq( dll_name, "api-ms-win-crt-heap-l1-1-0.dll" ))
        return macrunner_hb_is_crt_heap_semantic_import( import_name );

    if (macrunner_hb_ascii_ieq( dll_name, "kernelbase.dll" ) ||
        macrunner_hb_ascii_ieq( dll_name, "kernel32.dll" ))
        return macrunner_hb_ascii_ieq( import_name, "GetCommandLineA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetCommandLineW" ) ||
               macrunner_hb_ascii_ieq( import_name, "DisableThreadLibraryCalls" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleHandleA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleHandleW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleHandleExA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleHandleExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleFileNameA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleFileNameW" ) ||
               macrunner_hb_ascii_ieq( import_name, "LoadLibraryA" ) ||
               macrunner_hb_ascii_ieq( import_name, "LoadLibraryW" ) ||
               macrunner_hb_ascii_ieq( import_name, "LoadLibraryExA" ) ||
               macrunner_hb_ascii_ieq( import_name, "LoadLibraryExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "FreeLibrary" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetProcAddress" ) ||
               macrunner_hb_ascii_ieq( import_name, "EnumProcessModules" ) ||
               macrunner_hb_ascii_ieq( import_name, "EnumProcessModulesEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "K32EnumProcessModules" ) ||
               macrunner_hb_ascii_ieq( import_name, "K32EnumProcessModulesEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleBaseNameA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleBaseNameW" ) ||
               macrunner_hb_ascii_ieq( import_name, "K32GetModuleBaseNameA" ) ||
               macrunner_hb_ascii_ieq( import_name, "K32GetModuleBaseNameW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleFileNameExA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleFileNameExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "K32GetModuleFileNameExA" ) ||
               macrunner_hb_ascii_ieq( import_name, "K32GetModuleFileNameExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleInformation" ) ||
               macrunner_hb_ascii_ieq( import_name, "K32GetModuleInformation" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetProcessImageFileNameA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetProcessImageFileNameW" ) ||
               macrunner_hb_ascii_ieq( import_name, "K32GetProcessImageFileNameA" ) ||
               macrunner_hb_ascii_ieq( import_name, "K32GetProcessImageFileNameW" ) ||
               macrunner_hb_ascii_ieq( import_name, "FormatMessageA" ) ||
               macrunner_hb_ascii_ieq( import_name, "FormatMessageW" ) ||
               macrunner_hb_ascii_ieq( import_name, "QueryPerformanceFrequency" ) ||
               macrunner_hb_ascii_ieq( import_name, "QueryPerformanceCounter" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetSystemTimePreciseAsFileTime" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetSystemTimeAsFileTime" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetSystemTime" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetLocalTime" ) ||
               macrunner_hb_ascii_ieq( import_name, "SystemTimeToFileTime" ) ||
               macrunner_hb_ascii_ieq( import_name, "FileTimeToSystemTime" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetEnvironmentStringsA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetEnvironmentStringsW" ) ||
               macrunner_hb_ascii_ieq( import_name, "FreeEnvironmentStringsA" ) ||
               macrunner_hb_ascii_ieq( import_name, "FreeEnvironmentStringsW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetEnvironmentVariableA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetEnvironmentVariableW" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetEnvironmentVariableA" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetEnvironmentVariableW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetACP" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetOEMCP" ) ||
               macrunner_hb_ascii_ieq( import_name, "AreFileApisANSI" ) ||
               macrunner_hb_ascii_ieq( import_name, "IsValidCodePage" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetCPInfo" ) ||
               macrunner_hb_ascii_ieq( import_name, "MultiByteToWideChar" ) ||
               macrunner_hb_ascii_ieq( import_name, "WideCharToMultiByte" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetStringTypeW" ) ||
               macrunner_hb_ascii_ieq( import_name, "LCMapStringEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetTempPathA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetTempPathW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetTempPath2A" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetTempPath2W" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetStartupInfoA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetStartupInfoW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetStdHandle" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetFileType" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetSystemInfo" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetNativeSystemInfo" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetLogicalProcessorInformation" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetLogicalProcessorInformationEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "GlobalMemoryStatus" ) ||
               macrunner_hb_ascii_ieq( import_name, "GlobalMemoryStatusEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateFileA" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateFileW" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateDirectoryA" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateDirectoryW" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateDirectoryExA" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateDirectoryExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "MoveFileA" ) ||
               macrunner_hb_ascii_ieq( import_name, "MoveFileW" ) ||
               macrunner_hb_ascii_ieq( import_name, "MoveFileExA" ) ||
               macrunner_hb_ascii_ieq( import_name, "MoveFileExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "ReadFile" ) ||
               macrunner_hb_ascii_ieq( import_name, "WriteFile" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetFileSize" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetFileSizeEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetFilePointer" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetFilePointerEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetFileAttributesA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetFileAttributesW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetFileAttributesExA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetFileAttributesExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetFileAttributesA" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetFileAttributesW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetLastError" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetLastError" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetProcessHeap" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetCurrentProcess" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetCurrentThread" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetCurrentProcessId" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetCurrentThreadId" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetTickCount" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetTickCount64" ) ||
               macrunner_hb_ascii_ieq( import_name, "LocalAlloc" ) ||
               macrunner_hb_ascii_ieq( import_name, "LocalReAlloc" ) ||
               macrunner_hb_ascii_ieq( import_name, "LocalFree" ) ||
               macrunner_hb_ascii_ieq( import_name, "LocalSize" ) ||
               macrunner_hb_ascii_ieq( import_name, "InitializeCriticalSection" ) ||
               macrunner_hb_ascii_ieq( import_name, "InitializeCriticalSectionAndSpinCount" ) ||
               macrunner_hb_ascii_ieq( import_name, "InitializeCriticalSectionEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "DeleteCriticalSection" ) ||
               macrunner_hb_ascii_ieq( import_name, "EnterCriticalSection" ) ||
               macrunner_hb_ascii_ieq( import_name, "LeaveCriticalSection" ) ||
               macrunner_hb_ascii_ieq( import_name, "TryEnterCriticalSection" ) ||
               macrunner_hb_ascii_ieq( import_name, "InitializeSRWLock" ) ||
               macrunner_hb_ascii_ieq( import_name, "AcquireSRWLockExclusive" ) ||
               macrunner_hb_ascii_ieq( import_name, "AcquireSRWLockShared" ) ||
               macrunner_hb_ascii_ieq( import_name, "ReleaseSRWLockExclusive" ) ||
               macrunner_hb_ascii_ieq( import_name, "ReleaseSRWLockShared" ) ||
               macrunner_hb_ascii_ieq( import_name, "TryAcquireSRWLockExclusive" ) ||
               macrunner_hb_ascii_ieq( import_name, "TryAcquireSRWLockShared" ) ||
               macrunner_hb_ascii_ieq( import_name, "InitializeConditionVariable" ) ||
               macrunner_hb_ascii_ieq( import_name, "SleepConditionVariableCS" ) ||
               macrunner_hb_ascii_ieq( import_name, "SleepConditionVariableSRW" ) ||
               macrunner_hb_ascii_ieq( import_name, "WakeAllConditionVariable" ) ||
               macrunner_hb_ascii_ieq( import_name, "WakeConditionVariable" ) ||
               macrunner_hb_ascii_ieq( import_name, "InitializeSListHead" ) ||
               macrunner_hb_ascii_ieq( import_name, "InterlockedFlushSList" ) ||
               macrunner_hb_ascii_ieq( import_name, "InterlockedPopEntrySList" ) ||
               macrunner_hb_ascii_ieq( import_name, "InterlockedPushEntrySList" ) ||
               macrunner_hb_ascii_ieq( import_name, "InterlockedPushListSList" ) ||
               macrunner_hb_ascii_ieq( import_name, "InterlockedPushListSListEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "QueryDepthSList" ) ||
               macrunner_hb_ascii_ieq( import_name, "HeapAlloc" ) ||
               macrunner_hb_ascii_ieq( import_name, "HeapReAlloc" ) ||
               macrunner_hb_ascii_ieq( import_name, "HeapFree" ) ||
               macrunner_hb_ascii_ieq( import_name, "HeapSize" ) ||
               macrunner_hb_ascii_ieq( import_name, "VirtualAlloc" ) ||
               macrunner_hb_ascii_ieq( import_name, "VirtualAllocEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "VirtualFree" ) ||
               macrunner_hb_ascii_ieq( import_name, "VirtualFreeEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "VirtualProtect" ) ||
               macrunner_hb_ascii_ieq( import_name, "VirtualProtectEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "VirtualQuery" ) ||
               macrunner_hb_ascii_ieq( import_name, "VirtualQueryEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "TlsAlloc" ) ||
               macrunner_hb_ascii_ieq( import_name, "TlsSetValue" ) ||
               macrunner_hb_ascii_ieq( import_name, "TlsGetValue" ) ||
               macrunner_hb_ascii_ieq( import_name, "TlsFree" ) ||
               macrunner_hb_ascii_ieq( import_name, "FlsAlloc" ) ||
               macrunner_hb_ascii_ieq( import_name, "FlsSetValue" ) ||
               macrunner_hb_ascii_ieq( import_name, "FlsGetValue" ) ||
               macrunner_hb_ascii_ieq( import_name, "FlsFree" ) ||
               macrunner_hb_ascii_ieq( import_name, "AddVectoredExceptionHandler" ) ||
               macrunner_hb_ascii_ieq( import_name, "RemoveVectoredExceptionHandler" ) ||
               macrunner_hb_ascii_ieq( import_name, "RaiseException" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateThread" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateRemoteThread" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateRemoteThreadEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "ResumeThread" ) ||
               macrunner_hb_ascii_ieq( import_name, "SuspendThread" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetThreadDescription" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreatePipe" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateEventA" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateEventW" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateEventExA" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateEventExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "OpenEventA" ) ||
               macrunner_hb_ascii_ieq( import_name, "OpenEventW" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetEvent" ) ||
               macrunner_hb_ascii_ieq( import_name, "ResetEvent" ) ||
               macrunner_hb_ascii_ieq( import_name, "PulseEvent" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateSemaphoreA" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateSemaphoreW" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateSemaphoreExA" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateSemaphoreExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "OpenSemaphoreA" ) ||
               macrunner_hb_ascii_ieq( import_name, "OpenSemaphoreW" ) ||
               macrunner_hb_ascii_ieq( import_name, "ReleaseSemaphore" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateMutexA" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateMutexW" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateMutexExA" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateMutexExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "OpenMutexA" ) ||
               macrunner_hb_ascii_ieq( import_name, "OpenMutexW" ) ||
               macrunner_hb_ascii_ieq( import_name, "ReleaseMutex" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetErrorMode" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetErrorMode" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetThreadErrorMode" ) ||
               macrunner_hb_ascii_ieq( import_name, "OutputDebugStringA" ) ||
               macrunner_hb_ascii_ieq( import_name, "OutputDebugStringW" ) ||
               macrunner_hb_ascii_ieq( import_name, "WaitForSingleObject" ) ||
               macrunner_hb_ascii_ieq( import_name, "WaitForSingleObjectEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "WaitForMultipleObjects" ) ||
               macrunner_hb_ascii_ieq( import_name, "WaitForMultipleObjectsEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "DuplicateHandle" ) ||
               macrunner_hb_ascii_ieq( import_name, "BCryptGenRandom" ) ||
               macrunner_hb_ascii_ieq( import_name, "CloseHandle" );

    if (macrunner_hb_ascii_ieq( dll_name, "comctl32.dll" ))
        return macrunner_hb_ascii_ieq( import_name, "InitCommonControls" );

    if (macrunner_hb_ascii_ieq( dll_name, "shell32.dll" ) ||
        macrunner_hb_ascii_ieq( dll_name, "shcore.dll" ))
        return macrunner_hb_ascii_ieq( import_name, "CommandLineToArgvW" ) ||
               macrunner_hb_ascii_ieq( import_name, "SHGetKnownFolderPath" );

    if (macrunner_hb_ascii_ieq( dll_name, "api-ms-win-core-winrt-l1-1-0.dll" ) ||
        macrunner_hb_ascii_ieq( dll_name, "combase.dll" ))
        return macrunner_hb_ascii_ieq( import_name, "RoInitialize" ) ||
               macrunner_hb_ascii_ieq( import_name, "RoUninitialize" ) ||
               macrunner_hb_ascii_ieq( import_name, "RoGetActivationFactory" ) ||
               macrunner_hb_ascii_ieq( import_name, "RoActivateInstance" ) ||
               macrunner_hb_ascii_ieq( import_name, "CoTaskMemAlloc" ) ||
               macrunner_hb_ascii_ieq( import_name, "CoTaskMemRealloc" ) ||
               macrunner_hb_ascii_ieq( import_name, "CoTaskMemFree" );

    if (macrunner_hb_ascii_ieq( dll_name, "ole32.dll" ))
        return macrunner_hb_ascii_ieq( import_name, "CoInitialize" ) ||
               macrunner_hb_ascii_ieq( import_name, "CoInitializeEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "CoUninitialize" ) ||
               macrunner_hb_ascii_ieq( import_name, "CoTaskMemAlloc" ) ||
               macrunner_hb_ascii_ieq( import_name, "CoTaskMemRealloc" ) ||
               macrunner_hb_ascii_ieq( import_name, "CoTaskMemFree" );

    if (macrunner_hb_ascii_ieq( dll_name, "psapi.dll" ))
        return macrunner_hb_ascii_ieq( import_name, "EnumProcessModules" ) ||
               macrunner_hb_ascii_ieq( import_name, "EnumProcessModulesEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleBaseNameA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleBaseNameW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleFileNameExA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleFileNameExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetModuleInformation" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetProcessImageFileNameA" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetProcessImageFileNameW" );

    if (macrunner_hb_ascii_ieq( dll_name, "ntdll.dll" ))
        return macrunner_hb_ascii_ieq( import_name, "NtQueryVirtualMemory" ) ||
               macrunner_hb_ascii_ieq( import_name, "LdrGetDllHandle" ) ||
               macrunner_hb_ascii_ieq( import_name, "LdrGetDllHandleEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "RtlFindExportedRoutineByName" ) ||
               macrunner_hb_ascii_ieq( import_name, "RtlAddVectoredExceptionHandler" ) ||
               macrunner_hb_ascii_ieq( import_name, "RtlRemoveVectoredExceptionHandler" ) ||
               macrunner_hb_ascii_ieq( import_name, "RtlInitializeSRWLock" ) ||
               macrunner_hb_ascii_ieq( import_name, "RtlAcquireSRWLockExclusive" ) ||
               macrunner_hb_ascii_ieq( import_name, "RtlAcquireSRWLockShared" ) ||
               macrunner_hb_ascii_ieq( import_name, "RtlReleaseSRWLockExclusive" ) ||
               macrunner_hb_ascii_ieq( import_name, "RtlReleaseSRWLockShared" ) ||
               macrunner_hb_ascii_ieq( import_name, "RtlTryAcquireSRWLockExclusive" ) ||
               macrunner_hb_ascii_ieq( import_name, "RtlTryAcquireSRWLockShared" ) ||
               macrunner_hb_ascii_ieq( import_name, "RtlInitializeConditionVariable" ) ||
               macrunner_hb_ascii_ieq( import_name, "RtlSleepConditionVariableCS" ) ||
               macrunner_hb_ascii_ieq( import_name, "RtlSleepConditionVariableSRW" ) ||
               macrunner_hb_ascii_ieq( import_name, "RtlWakeAllConditionVariable" ) ||
               macrunner_hb_ascii_ieq( import_name, "RtlWakeConditionVariable" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwEventActivityIdControl" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwEventEnabled" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwEventProviderEnabled" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwEventRegister" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwEventSetInformation" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwEventUnregister" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwEventWrite" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwEventWriteEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwEventWriteString" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwEventWriteTransfer" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwGetTraceEnableFlags" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwGetTraceEnableLevel" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwGetTraceLoggerHandle" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwLogTraceEvent" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwRegisterTraceGuidsA" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwRegisterTraceGuidsW" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwTraceMessage" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwTraceMessageVa" ) ||
               macrunner_hb_ascii_ieq( import_name, "EtwUnregisterTraceGuids" );

    if (macrunner_hb_ascii_ieq( dll_name, "msvcrt.dll" ))
        return macrunner_hb_ascii_ieq( import_name, "time" ) ||
               macrunner_hb_ascii_ieq( import_name, "_time64" ) ||
               macrunner_hb_ascii_ieq( import_name, "_ftime64" ) ||
               macrunner_hb_ascii_ieq( import_name, "_ftime64_s" ) ||
               macrunner_hb_ascii_ieq( import_name, "__pctype_func" ) ||
               macrunner_hb_ascii_ieq( import_name, "___mb_cur_max_func" ) ||
               macrunner_hb_ascii_ieq( import_name, "___lc_codepage_func" ) ||
               macrunner_hb_ascii_ieq( import_name, "localeconv" ) ||
               macrunner_hb_is_crt_string_semantic_import( import_name ) ||
               macrunner_hb_is_crt_stdio_semantic_import( import_name ) ||
               macrunner_hb_is_crt_multibyte_semantic_import( import_name ) ||
               macrunner_hb_is_crt_math_semantic_import( import_name ) ||
               macrunner_hb_is_crt_heap_semantic_import( import_name );

    if (macrunner_hb_ascii_ieq( dll_name, "user32.dll" ))
        return macrunner_hb_ascii_ieq( import_name, "CheckMenuItem" ) ||
               macrunner_hb_ascii_ieq( import_name, "CreateWindowExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "DefWindowProcW" ) ||
               macrunner_hb_ascii_ieq( import_name, "DestroyWindow" ) ||
               macrunner_hb_ascii_ieq( import_name, "DialogBoxParamW" ) ||
               macrunner_hb_ascii_ieq( import_name, "DispatchMessageW" ) ||
               macrunner_hb_ascii_ieq( import_name, "EnableMenuItem" ) ||
               macrunner_hb_ascii_ieq( import_name, "EndDialog" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetClientRect" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetDesktopWindow" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetDlgItem" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetDlgItemInt" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetDlgItemTextW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetDpiForWindow" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetMenu" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetMessageW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetMonitorInfoW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetParent" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetSystemMetrics" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetWindowPlacement" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetWindowRect" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetWindowTextLengthW" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetWindowTextW" ) ||
               macrunner_hb_ascii_ieq( import_name, "InvalidateRect" ) ||
               macrunner_hb_ascii_ieq( import_name, "IsClipboardFormatAvailable" ) ||
               macrunner_hb_ascii_ieq( import_name, "IsDialogMessageW" ) ||
               macrunner_hb_ascii_ieq( import_name, "LoadAcceleratorsW" ) ||
               macrunner_hb_ascii_ieq( import_name, "LoadCursorA" ) ||
               macrunner_hb_ascii_ieq( import_name, "LoadCursorW" ) ||
               macrunner_hb_ascii_ieq( import_name, "LoadIconA" ) ||
               macrunner_hb_ascii_ieq( import_name, "LoadIconW" ) ||
               macrunner_hb_ascii_ieq( import_name, "LoadImageA" ) ||
               macrunner_hb_ascii_ieq( import_name, "LoadImageW" ) ||
               macrunner_hb_ascii_ieq( import_name, "LoadStringW" ) ||
               macrunner_hb_ascii_ieq( import_name, "MessageBoxW" ) ||
               macrunner_hb_ascii_ieq( import_name, "MonitorFromRect" ) ||
               macrunner_hb_ascii_ieq( import_name, "PostMessageW" ) ||
               macrunner_hb_ascii_ieq( import_name, "PostQuitMessage" ) ||
               macrunner_hb_ascii_ieq( import_name, "RegisterClassExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "RegisterWindowMessageW" ) ||
               macrunner_hb_ascii_ieq( import_name, "SendMessageW" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetActiveWindow" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetDlgItemInt" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetDlgItemTextW" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetFocus" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetWindowPos" ) ||
               macrunner_hb_ascii_ieq( import_name, "SetWindowTextW" ) ||
               macrunner_hb_ascii_ieq( import_name, "ShowWindow" ) ||
               macrunner_hb_ascii_ieq( import_name, "TranslateAcceleratorW" ) ||
               macrunner_hb_ascii_ieq( import_name, "TranslateMessage" ) ||
               macrunner_hb_ascii_ieq( import_name, "UpdateWindow" ) ||
               macrunner_hb_ascii_ieq( import_name, "WinHelpW" );

    if (macrunner_hb_ascii_ieq( dll_name, "advapi32.dll" ))
        return macrunner_hb_ascii_ieq( import_name, "RegOpenKeyW" ) ||
               macrunner_hb_ascii_ieq( import_name, "RegOpenKeyExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "RegCreateKeyExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "RegQueryValueExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "RegSetValueExW" ) ||
               macrunner_hb_ascii_ieq( import_name, "RegDeleteValueW" ) ||
               macrunner_hb_ascii_ieq( import_name, "RegCloseKey" ) ||
               macrunner_hb_ascii_ieq( import_name, "EventActivityIdControl" ) ||
               macrunner_hb_ascii_ieq( import_name, "EventEnabled" ) ||
               macrunner_hb_ascii_ieq( import_name, "EventProviderEnabled" ) ||
               macrunner_hb_ascii_ieq( import_name, "EventRegister" ) ||
               macrunner_hb_ascii_ieq( import_name, "EventSetInformation" ) ||
               macrunner_hb_ascii_ieq( import_name, "EventUnregister" ) ||
               macrunner_hb_ascii_ieq( import_name, "EventWrite" ) ||
               macrunner_hb_ascii_ieq( import_name, "EventWriteEx" ) ||
               macrunner_hb_ascii_ieq( import_name, "EventWriteString" ) ||
               macrunner_hb_ascii_ieq( import_name, "EventWriteTransfer" ) ||
               macrunner_hb_ascii_ieq( import_name, "OpenProcessToken" ) ||
               macrunner_hb_ascii_ieq( import_name, "OpenThreadToken" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetTokenInformation" ) ||
               macrunner_hb_ascii_ieq( import_name, "IsValidSid" ) ||
               macrunner_hb_ascii_ieq( import_name, "EqualSid" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetLengthSid" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetSidIdentifierAuthority" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetSidSubAuthority" ) ||
               macrunner_hb_ascii_ieq( import_name, "GetSidSubAuthorityCount" );

    return FALSE;
}

static BOOL macrunner_hb_section_contains_target( HMODULE module, const IMAGE_SECTION_HEADER *sec,
                                                  ULONG_PTR target )
{
    ULONG_PTR base = (ULONG_PTR)module;
    ULONG_PTR start, size = max( sec->Misc.VirtualSize, sec->SizeOfRawData );

    if (!size) return FALSE;
    if (sec->VirtualAddress > ~(ULONG_PTR)0 - base) return FALSE;
    start = base + sec->VirtualAddress;
    if (size > ~(ULONG_PTR)0 - start) return FALSE;
    return target >= start && target < start + size;
}

static BOOL macrunner_hb_address_in_section( HMODULE module, const char *section, ULONG_PTR target )
{
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sec;
    unsigned int i;

    if (!module || !section || !target) return FALSE;
    if (!(nt = RtlImageNtHeader( module ))) return FALSE;

    sec = IMAGE_FIRST_SECTION( nt );
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (strncmp( (const char *)sec->Name, section, IMAGE_SIZEOF_SHORT_NAME )) continue;
        if (macrunner_hb_section_contains_target( module, sec, target )) return TRUE;
    }
    return FALSE;
}

static BOOL macrunner_hb_address_in_executable_section( HMODULE module, ULONG_PTR target )
{
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sec;
    unsigned int i;

    if (!module || !target) return FALSE;
    if (!(nt = RtlImageNtHeader( module ))) return FALSE;

    sec = IMAGE_FIRST_SECTION( nt );
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (macrunner_hb_section_contains_target( module, sec, target ))
            return !!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE);
    }
    return FALSE;
}

static BOOL macrunner_hb_target_is_native_thunk( WINE_MODREF *target_mod, ULONG_PTR target )
{
    return target_mod && macrunner_hb_address_in_section( target_mod->ldr.DllBase, ".hexpthk", target );
}

static BOOL macrunner_hb_target_is_native_thunk_or_mid( WINE_MODREF *target_mod, ULONG_PTR target,
                                                       ULONG_PTR *thunk_start )
{
    if (macrunner_hb_target_is_native_thunk( target_mod, target ))
    {
        if (thunk_start) *thunk_start = target;
        return TRUE;
    }
    if ((target & 0xf) == 2 && target >= 2 &&
        macrunner_hb_target_is_native_thunk( target_mod, target - 2 ))
    {
        if (thunk_start) *thunk_start = target - 2;
        return TRUE;
    }
    return FALSE;
}

static BOOL macrunner_hb_importer_is_native_wine_builtin( WINE_MODREF *importer )
{
    if (!importer) return FALSE;
    if (!(importer->ldr.Flags & LDR_WINE_INTERNAL)) return FALSE;

    /*
     * The main x86_64 builtin EXE is intentionally routed through HyperBridge
     * import thunks.  Native Wine DLLs that it calls (user32 -> win32u, etc.)
     * must not inherit those x64-facing thunk addresses for their own imports.
     */
    return importer->ldr.DllBase != NtCurrentTeb()->Peb->ImageBaseAddress;
}

static void *macrunner_hb_find_export_outside_section( HMODULE module, const char *name, const char *section )
{
    const IMAGE_EXPORT_DIRECTORY *exports;
    const WORD *ordinals;
    const DWORD *names, *functions;
    DWORD exp_size;
    unsigned int i;

    if (!module || !name || !section) return NULL;
    exports = RtlImageDirectoryEntryToData( module, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &exp_size );
    if (!exports || exp_size < sizeof(*exports)) return NULL;

    ordinals = get_rva( module, exports->AddressOfNameOrdinals );
    names = get_rva( module, exports->AddressOfNames );
    functions = get_rva( module, exports->AddressOfFunctions );

    for (i = 0; i < exports->NumberOfNames; i++)
    {
        int ordinal;
        void *proc;

        if (strcmp( get_rva( module, names[i] ), name )) continue;
        ordinal = ordinals[i];
        if (ordinal < 0 || ordinal >= exports->NumberOfFunctions) continue;
        if (!functions[ordinal]) continue;
        proc = get_rva( module, functions[ordinal] );
        if (((const char *)proc >= (const char *)exports) &&
            ((const char *)proc < (const char *)exports + exp_size))
            continue;
        if (!macrunner_hb_address_in_section( module, section, (ULONG_PTR)proc )) return proc;
    }
    return NULL;
}

static void *macrunner_hb_file_rva_to_ptr( BYTE *data, SIZE_T size, IMAGE_SECTION_HEADER *sections,
                                           unsigned int count, DWORD rva, SIZE_T len )
{
    unsigned int i;

    for (i = 0; i < count; i++)
    {
        DWORD sec_size = max( sections[i].Misc.VirtualSize, sections[i].SizeOfRawData );
        DWORD delta;

        if (rva < sections[i].VirtualAddress) continue;
        delta = rva - sections[i].VirtualAddress;
        if (delta >= sec_size || delta > sections[i].SizeOfRawData) continue;
        if (len > sections[i].SizeOfRawData - delta) continue;
        if ((SIZE_T)sections[i].PointerToRawData > size ||
            delta > size - (SIZE_T)sections[i].PointerToRawData ||
            len > size - (SIZE_T)sections[i].PointerToRawData - delta)
            return NULL;
        return data + sections[i].PointerToRawData + delta;
    }
    return NULL;
}

static BOOL macrunner_hb_file_rva_in_section( IMAGE_SECTION_HEADER *sections, unsigned int count,
                                              const char *section, DWORD rva )
{
    unsigned int i;

    for (i = 0; i < count; i++)
    {
        DWORD sec_size = max( sections[i].Misc.VirtualSize, sections[i].SizeOfRawData );
        DWORD delta;

        if (strncmp( (const char *)sections[i].Name, section, IMAGE_SIZEOF_SHORT_NAME )) continue;
        if (rva < sections[i].VirtualAddress) return FALSE;
        delta = rva - sections[i].VirtualAddress;
        return delta < sec_size;
    }
    return FALSE;
}

static char *macrunner_hb_file_rva_to_string( BYTE *data, SIZE_T size, IMAGE_SECTION_HEADER *sections,
                                              unsigned int count, DWORD rva )
{
    unsigned int i;

    for (i = 0; i < count; i++)
    {
        DWORD sec_size = max( sections[i].Misc.VirtualSize, sections[i].SizeOfRawData );
        DWORD delta;
        SIZE_T raw, remaining;
        char *str;

        if (rva < sections[i].VirtualAddress) continue;
        delta = rva - sections[i].VirtualAddress;
        if (delta >= sec_size || delta >= sections[i].SizeOfRawData) continue;
        raw = sections[i].PointerToRawData;
        if (raw > size || delta > size - raw) return NULL;
        remaining = min( (SIZE_T)sections[i].SizeOfRawData - delta, size - raw - delta );
        str = (char *)data + raw + delta;
        return memchr( str, 0, remaining ) ? str : NULL;
    }
    return NULL;
}

static IMAGE_SECTION_HEADER *macrunner_hb_disk_sections( BYTE *data, SIZE_T size, IMAGE_NT_HEADERS *nt )
{
    SIZE_T nt_offset, optional_offset, section_offset;

    if ((BYTE *)nt < data) return NULL;
    nt_offset = (BYTE *)nt - data;
    if (nt_offset > size || offsetof( IMAGE_NT_HEADERS, OptionalHeader ) > size - nt_offset) return NULL;
    optional_offset = nt_offset + offsetof( IMAGE_NT_HEADERS, OptionalHeader );
    if (nt->FileHeader.SizeOfOptionalHeader > size - optional_offset) return NULL;
    section_offset = optional_offset + nt->FileHeader.SizeOfOptionalHeader;
    if (nt->FileHeader.NumberOfSections > (size - section_offset) / sizeof(IMAGE_SECTION_HEADER)) return NULL;
    return (IMAGE_SECTION_HEADER *)(data + section_offset);
}

static void *macrunner_hb_find_disk_export_outside_section( WINE_MODREF *target_mod, const char *name,
                                                            const char *section )
{
    FILE_STANDARD_INFORMATION info;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    UNICODE_STRING nt_name;
    LARGE_INTEGER offset;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sections;
    const IMAGE_DATA_DIRECTORY *export_dir;
    IMAGE_EXPORT_DIRECTORY *exports;
    DWORD *names, *functions, func_rva;
    WORD *ordinals;
    HANDLE file;
    BYTE *data;
    SIZE_T size;
    NTSTATUS status;
    void *ret = NULL;
    unsigned int i;

    if (!target_mod || !target_mod->ldr.FullDllName.Buffer || !name || !section) return NULL;
    if ((status = RtlDosPathNameToNtPathName_U_WithStatus( target_mod->ldr.FullDllName.Buffer,
                                                           &nt_name, NULL, NULL )))
        return NULL;

    InitializeObjectAttributes( &attr, &nt_name, OBJ_CASE_INSENSITIVE, 0, NULL );
    status = NtOpenFile( &file, GENERIC_READ | SYNCHRONIZE, &attr, &io, FILE_SHARE_READ,
                         FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE );
    RtlFreeUnicodeString( &nt_name );
    if (status) return NULL;

    if (NtQueryInformationFile( file, &io, &info, sizeof(info), FileStandardInformation )) goto done_file;
    if (info.EndOfFile.QuadPart <= 0 || info.EndOfFile.QuadPart > 64 * 1024 * 1024) goto done_file;
    size = info.EndOfFile.QuadPart;
    if (!(data = RtlAllocateHeap( GetProcessHeap(), 0, size ))) goto done_file;

    offset.QuadPart = 0;
    status = NtReadFile( file, 0, NULL, NULL, &io, data, size, &offset, NULL );
    if (status || io.Information < sizeof(*dos)) goto done_data;

    dos = (IMAGE_DOS_HEADER *)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto done_data;
    if (size < sizeof(*nt) || (SIZE_T)dos->e_lfanew > size - sizeof(*nt))
        goto done_data;
    nt = (IMAGE_NT_HEADERS *)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) goto done_data;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) goto done_data;
    export_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!export_dir->VirtualAddress) goto done_data;
    if (!(sections = macrunner_hb_disk_sections( data, size, nt ))) goto done_data;

    exports = macrunner_hb_file_rva_to_ptr( data, size, sections, nt->FileHeader.NumberOfSections,
                                            export_dir->VirtualAddress, sizeof(*exports) );
    if (!exports) goto done_data;
    if (exports->NumberOfNames > ~(SIZE_T)0 / sizeof(*names) ||
        exports->NumberOfNames > ~(SIZE_T)0 / sizeof(*ordinals) ||
        exports->NumberOfFunctions > ~(SIZE_T)0 / sizeof(*functions))
        goto done_data;
    names = macrunner_hb_file_rva_to_ptr( data, size, sections, nt->FileHeader.NumberOfSections,
                                          exports->AddressOfNames, exports->NumberOfNames * sizeof(*names) );
    ordinals = macrunner_hb_file_rva_to_ptr( data, size, sections, nt->FileHeader.NumberOfSections,
                                             exports->AddressOfNameOrdinals,
                                             exports->NumberOfNames * sizeof(*ordinals) );
    functions = macrunner_hb_file_rva_to_ptr( data, size, sections, nt->FileHeader.NumberOfSections,
                                              exports->AddressOfFunctions,
                                              exports->NumberOfFunctions * sizeof(*functions) );
    if (!names || !ordinals || !functions) goto done_data;

    for (i = 0; i < exports->NumberOfNames; i++)
    {
        char *export_name = macrunner_hb_file_rva_to_string( data, size, sections,
                                                             nt->FileHeader.NumberOfSections, names[i] );
        WORD ordinal;

        if (!export_name || strcmp( export_name, name )) continue;
        ordinal = ordinals[i];
        if (ordinal >= exports->NumberOfFunctions) break;
        func_rva = functions[ordinal];
        if (func_rva >= export_dir->VirtualAddress && func_rva - export_dir->VirtualAddress < export_dir->Size)
            break;
        if (macrunner_hb_file_rva_in_section( sections, nt->FileHeader.NumberOfSections, section, func_rva ))
            break;
        if (target_mod->ldr.SizeOfImage > ~(ULONG_PTR)0 - (ULONG_PTR)target_mod->ldr.DllBase ||
            func_rva >= target_mod->ldr.SizeOfImage ||
            (ULONG_PTR)target_mod->ldr.DllBase > ~(ULONG_PTR)0 - func_rva)
            break;
        ret = (BYTE *)target_mod->ldr.DllBase + func_rva;
        break;
    }

done_data:
    RtlFreeHeap( GetProcessHeap(), 0, data );
done_file:
    NtClose( file );
    return ret;
}

static const char *macrunner_hb_coff_symbol_name( const IMAGE_SYMBOL *symbol, const char *strings,
                                                  SIZE_T strings_size, char short_name[9] )
{
    DWORD offset;

    if (symbol->N.Name.Short)
    {
        memcpy( short_name, symbol->N.ShortName, 8 );
        short_name[8] = 0;
        return short_name;
    }

    offset = symbol->N.Name.Long;
    if (offset < sizeof(DWORD) || offset >= strings_size) return NULL;
    if (!memchr( strings + offset, 0, strings_size - offset )) return NULL;
    return strings + offset;
}

static BOOL macrunner_hb_coff_symbol_slot_rva( const IMAGE_NT_HEADERS *nt,
                                               const IMAGE_SECTION_HEADER *section,
                                               const IMAGE_SYMBOL *symbol, ULONG_PTR *rva )
{
    SIZE_T sec_size = max( section->Misc.VirtualSize, section->SizeOfRawData );

    if (symbol->Value > sec_size || sizeof(void *) > sec_size - symbol->Value) return FALSE;
    if (section->VirtualAddress > nt->OptionalHeader.SizeOfImage ||
        symbol->Value > nt->OptionalHeader.SizeOfImage - section->VirtualAddress ||
        sizeof(void *) > nt->OptionalHeader.SizeOfImage - section->VirtualAddress - symbol->Value)
        return FALSE;
    *rva = section->VirtualAddress + symbol->Value;
    return TRUE;
}

static void *macrunner_hb_find_disk_symbol_pointer_value( WINE_MODREF *target_mod, const char *name )
{
    FILE_STANDARD_INFORMATION info;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    UNICODE_STRING nt_name;
    LARGE_INTEGER offset;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sections;
    IMAGE_SYMBOL *symbols;
    const char *strings;
    DWORD strings_size;
    HANDLE file;
    BYTE *data;
    SIZE_T size, symbol_bytes;
    NTSTATUS status;
    void *ret = NULL;
    unsigned int i;

    if (!target_mod || !target_mod->ldr.FullDllName.Buffer || !name) return NULL;
    if ((status = RtlDosPathNameToNtPathName_U_WithStatus( target_mod->ldr.FullDllName.Buffer,
                                                           &nt_name, NULL, NULL )))
        return NULL;

    InitializeObjectAttributes( &attr, &nt_name, OBJ_CASE_INSENSITIVE, 0, NULL );
    status = NtOpenFile( &file, GENERIC_READ | SYNCHRONIZE, &attr, &io, FILE_SHARE_READ,
                         FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE );
    RtlFreeUnicodeString( &nt_name );
    if (status) return NULL;

    if (NtQueryInformationFile( file, &io, &info, sizeof(info), FileStandardInformation )) goto done_file;
    if (info.EndOfFile.QuadPart <= 0 || info.EndOfFile.QuadPart > 64 * 1024 * 1024) goto done_file;
    size = info.EndOfFile.QuadPart;
    if (!(data = RtlAllocateHeap( GetProcessHeap(), 0, size ))) goto done_file;

    offset.QuadPart = 0;
    status = NtReadFile( file, 0, NULL, NULL, &io, data, size, &offset, NULL );
    if (status || io.Information < sizeof(*dos)) goto done_data;

    dos = (IMAGE_DOS_HEADER *)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto done_data;
    if (size < sizeof(*nt) || (SIZE_T)dos->e_lfanew > size - sizeof(*nt))
        goto done_data;
    nt = (IMAGE_NT_HEADERS *)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) goto done_data;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) goto done_data;
    if (!nt->FileHeader.PointerToSymbolTable || !nt->FileHeader.NumberOfSymbols) goto done_data;
    if (nt->FileHeader.NumberOfSymbols > (~(SIZE_T)0 - sizeof(DWORD)) / IMAGE_SIZEOF_SYMBOL)
        goto done_data;
    symbol_bytes = (SIZE_T)nt->FileHeader.NumberOfSymbols * IMAGE_SIZEOF_SYMBOL;
    if ((SIZE_T)nt->FileHeader.PointerToSymbolTable > size ||
        symbol_bytes > size - nt->FileHeader.PointerToSymbolTable ||
        sizeof(DWORD) > size - nt->FileHeader.PointerToSymbolTable - symbol_bytes)
        goto done_data;

    if (!(sections = macrunner_hb_disk_sections( data, size, nt ))) goto done_data;
    symbols = (IMAGE_SYMBOL *)(data + nt->FileHeader.PointerToSymbolTable);
    strings = (const char *)(symbols + nt->FileHeader.NumberOfSymbols);
    strings_size = *(const DWORD *)strings;
    if (strings_size < sizeof(DWORD) || (BYTE *)strings + strings_size > data + size) goto done_data;

    for (i = 0; i < nt->FileHeader.NumberOfSymbols; i += symbols[i].NumberOfAuxSymbols + 1)
    {
        IMAGE_SYMBOL *symbol = &symbols[i];
        char short_name[9];
        const char *sym_name;
        IMAGE_SECTION_HEADER *section;
        ULONG_PTR rva;
        void **slot;

        if (symbol->SectionNumber <= 0 || symbol->SectionNumber > nt->FileHeader.NumberOfSections) continue;
        if (symbol->StorageClass != IMAGE_SYM_CLASS_EXTERNAL) continue;
        if (!(sym_name = macrunner_hb_coff_symbol_name( symbol, strings, strings_size, short_name ))) continue;
        if (strcmp( sym_name, name )) continue;

        section = &sections[symbol->SectionNumber - 1];
        if (!macrunner_hb_coff_symbol_slot_rva( nt, section, symbol, &rva )) continue;
        if ((ULONG_PTR)target_mod->ldr.DllBase > ~(ULONG_PTR)0 - rva) continue;

        slot = (void **)((BYTE *)target_mod->ldr.DllBase + rva);
        if (*slot)
        {
            ret = *slot;
            MESSAGE( "MacRunner HyperBridge found %s!%s alias slot rva=%Ix value=%p\n",
                   debugstr_w(target_mod->ldr.BaseDllName.Buffer), name, rva, ret );
            break;
        }
        MESSAGE( "MacRunner HyperBridge observed empty %s!%s alias slot rva=%Ix\n",
               debugstr_w(target_mod->ldr.BaseDllName.Buffer), name, rva );
    }

done_data:
    RtlFreeHeap( GetProcessHeap(), 0, data );
done_file:
    NtClose( file );
    return ret;
}

static unsigned int macrunner_hb_sync_disk_symbol_pointer_aliases( WINE_MODREF *target_mod, const char *name,
                                                                   void *value )
{
    FILE_STANDARD_INFORMATION info;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    UNICODE_STRING nt_name;
    LARGE_INTEGER offset;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sections;
    IMAGE_SYMBOL *symbols;
    const char *strings;
    DWORD strings_size;
    HANDLE file;
    BYTE *data;
    SIZE_T size, symbol_bytes;
    NTSTATUS status;
    unsigned int i, count = 0;

    if (!target_mod || !target_mod->ldr.FullDllName.Buffer || !name || !value) return 0;
    if ((status = RtlDosPathNameToNtPathName_U_WithStatus( target_mod->ldr.FullDllName.Buffer,
                                                           &nt_name, NULL, NULL )))
        return 0;

    InitializeObjectAttributes( &attr, &nt_name, OBJ_CASE_INSENSITIVE, 0, NULL );
    status = NtOpenFile( &file, GENERIC_READ | SYNCHRONIZE, &attr, &io, FILE_SHARE_READ,
                         FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE );
    RtlFreeUnicodeString( &nt_name );
    if (status) return 0;

    if (NtQueryInformationFile( file, &io, &info, sizeof(info), FileStandardInformation )) goto done_file;
    if (info.EndOfFile.QuadPart <= 0 || info.EndOfFile.QuadPart > 64 * 1024 * 1024) goto done_file;
    size = info.EndOfFile.QuadPart;
    if (!(data = RtlAllocateHeap( GetProcessHeap(), 0, size ))) goto done_file;

    offset.QuadPart = 0;
    status = NtReadFile( file, 0, NULL, NULL, &io, data, size, &offset, NULL );
    if (status || io.Information < sizeof(*dos)) goto done_data;

    dos = (IMAGE_DOS_HEADER *)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto done_data;
    if (size < sizeof(*nt) || (SIZE_T)dos->e_lfanew > size - sizeof(*nt))
        goto done_data;
    nt = (IMAGE_NT_HEADERS *)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) goto done_data;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) goto done_data;
    if (!nt->FileHeader.PointerToSymbolTable || !nt->FileHeader.NumberOfSymbols) goto done_data;
    if (nt->FileHeader.NumberOfSymbols > (~(SIZE_T)0 - sizeof(DWORD)) / IMAGE_SIZEOF_SYMBOL)
        goto done_data;
    symbol_bytes = (SIZE_T)nt->FileHeader.NumberOfSymbols * IMAGE_SIZEOF_SYMBOL;
    if ((SIZE_T)nt->FileHeader.PointerToSymbolTable > size ||
        symbol_bytes > size - nt->FileHeader.PointerToSymbolTable ||
        sizeof(DWORD) > size - nt->FileHeader.PointerToSymbolTable - symbol_bytes)
        goto done_data;

    if (!(sections = macrunner_hb_disk_sections( data, size, nt ))) goto done_data;
    symbols = (IMAGE_SYMBOL *)(data + nt->FileHeader.PointerToSymbolTable);
    strings = (const char *)(symbols + nt->FileHeader.NumberOfSymbols);
    strings_size = *(const DWORD *)strings;
    if (strings_size < sizeof(DWORD) || (BYTE *)strings + strings_size > data + size) goto done_data;

    for (i = 0; i < nt->FileHeader.NumberOfSymbols; i += symbols[i].NumberOfAuxSymbols + 1)
    {
        IMAGE_SYMBOL *symbol = &symbols[i];
        char short_name[9];
        const char *sym_name;
        IMAGE_SECTION_HEADER *section;
        ULONG_PTR rva;
        void **slot, *protect_base, *old_value;
        SIZE_T protect_size = sizeof(*slot);
        ULONG old_prot;

        if (symbol->SectionNumber <= 0 || symbol->SectionNumber > nt->FileHeader.NumberOfSections) continue;
        if (symbol->StorageClass != IMAGE_SYM_CLASS_EXTERNAL) continue;
        if (!(sym_name = macrunner_hb_coff_symbol_name( symbol, strings, strings_size, short_name ))) continue;
        if (strcmp( sym_name, name )) continue;

        section = &sections[symbol->SectionNumber - 1];
        if (!macrunner_hb_coff_symbol_slot_rva( nt, section, symbol, &rva )) continue;
        if ((ULONG_PTR)target_mod->ldr.DllBase > ~(ULONG_PTR)0 - rva) continue;

        slot = (void **)((BYTE *)target_mod->ldr.DllBase + rva);
        old_value = *slot;
        if (old_value == value)
        {
            count++;
            continue;
        }

        protect_base = slot;
        if (!NtProtectVirtualMemory( NtCurrentProcess(), &protect_base, &protect_size,
                                     PAGE_READWRITE, &old_prot ))
        {
            *slot = value;
            NtProtectVirtualMemory( NtCurrentProcess(), &protect_base, &protect_size,
                                    old_prot, &old_prot );
            count++;
            MESSAGE( "MacRunner HyperBridge synced %s!%s alias slot rva=%Ix %p -> %p\n",
                   debugstr_w(target_mod->ldr.BaseDllName.Buffer), name, rva, old_value, value );
        }
    }

done_data:
    RtlFreeHeap( GetProcessHeap(), 0, data );
done_file:
    NtClose( file );
    return count;
}

static void macrunner_hb_sync_syscall_dispatcher_aliases( WINE_MODREF *optional_win32u );

static void *macrunner_hb_get_pe_call12_trampoline(void)
{
    static void *pe_call12;
    WCHAR ntdllW[] = {'n','t','d','l','l','.','d','l','l',0};
    WINE_MODREF *ntdll_mod;

    if (pe_call12) return pe_call12;
    if (!(ntdll_mod = find_basename_module_machine( ntdllW, current_machine ))) return NULL;
    macrunner_hb_sync_syscall_dispatcher_aliases( NULL );
    return pe_call12 = macrunner_hb_find_disk_export_outside_section( ntdll_mod,
                                                                      "__wine_macrunner_hb_pe_call12",
                                                                      ".hexpthk" );
}

static void *macrunner_hb_get_pe_callback12_trampoline(void)
{
    static void *pe_callback12;
    WCHAR ntdllW[] = {'n','t','d','l','l','.','d','l','l',0};
    WINE_MODREF *ntdll_mod;

    if (pe_callback12) return pe_callback12;
    if (!(ntdll_mod = find_basename_module_machine( ntdllW, current_machine ))) return NULL;
    macrunner_hb_sync_syscall_dispatcher_aliases( NULL );
    return pe_callback12 = macrunner_hb_find_disk_export_outside_section( ntdll_mod,
                                                                          "__wine_macrunner_hb_pe_callback12",
                                                                          ".hexpthk" );
}

/* MacRunner 2026-07-29 (HK DllMain lane, iter 9).  WHICH of the image's TWO DllMain bodies to call.
 *
 * An ARM64X wine builtin from build-arm64ec-spike links BOTH dllmain.o's into one .text
 * (build-arm64ec-spike/Makefile:509892 passes dlls/<mod>/aarch64-windows/dllmain.o AND
 * dlls/<mod>/arm64ec-windows/dllmain.o to one winegcc -marm64x link), so there are two entries:
 *   - OptionalHeader.AddressOfEntryPoint  -> the PURE-ARM64 body (AAPCS64)
 *   - CHPE AlternateEntryPoint            -> the ARM64EC body (x64 ABI)
 * Decoded off the shipped aarch64-windows/winemac.drv: AEP 0x2d90 is `b 0x1808`, plain AArch64
 * with no ARM64EC entry-thunk marker word; AlternateEntryPoint 0x6030 is the target of the
 * image's single .hexpthk export thunk at 0x8000 (x86-64: `mov rax,rsp; mov [rax+20h],rbx;
 * push rbp; pop rbp; jmp 0x6030`), i.e. 0x6030 is what x64 code enters -- the EC body.  The one
 * .a64xrm redirection entry {src 0x8000 -> dst 0x6030} says the same thing independently.
 *
 * The EC body is the RIGHT choice for the other three natgate modules: measured in HK's own
 * process (i8 run 105607), kernelbase.dll / win32u.dll / USER32.dll all take this path at their
 * AlternateEntryPoint and their DllMains RETURN -- the loader runs on for dozens more modules.
 * It is the WRONG choice for winemac.drv: three separate routes have now wedged in the
 * HyperBridge EC-thunk fault router, while explorer executes the SAME FILE's pure-ARM64 body
 * (initdll machine=aa64 entry=base+0x2d90) through dllmain_attach -> dllmain_unixcall_init
 * status=00000000 -> macdrv_init_entry on every run.  winemac.drv is also the only one of the
 * four whose DllMain calls straight back out through imports (macdrv_pe_trace -> GetStdHandle /
 * WriteFile / MESSAGE, then __wine_init_unix_call) before doing anything else.
 *
 * Note the RVA is read from the DISK header on purpose: HK maps this image as its EC VIEW
 * (measured -- initdll reports machine=8664 and entry=base+0x8000, the .hexpthk), so the
 * in-memory AddressOfEntryPoint is the x64 thunk, not 0x2d90.  Section contents are not
 * view-swapped, so base+0x2d90 is the native body in either view.
 *
 * Scope is deliberately winemac.drv-only: the other three work on the EC body today, and "an
 * offline proof that a mechanism is wrong is not a proof that changing it is safe" has already
 * cost this project two guest regressions.  Opt out with MACRUNNER_HB_WINEMAC_NATIVE_AEP=0 to
 * A/B straight back to the EC body without a rebuild. */
static BOOL macrunner_hb_prefer_native_view_aep( WINE_MODREF *target_mod )
{
    WCHAR value[8] = {0};

    if (!target_mod || !target_mod->ldr.BaseDllName.Buffer) return FALSE;
    if (wcsicmp( target_mod->ldr.BaseDllName.Buffer, L"winemac.drv" )) return FALSE;

    /* default ON, but only ever reached from the already default-OFF winemac natgate */
    if (!get_env( L"MACRUNNER_HB_WINEMAC_NATIVE_AEP", value, sizeof(value) )) return TRUE;
    return value[0] != '0';
}

/* See the call site in MODULE_InitDLL for what this probe splits apart.  Default OFF. */
static BOOL macrunner_hb_winemac_entry_probe_enabled(void)
{
    WCHAR value[8] = {0};

    return get_env( L"MACRUNNER_HB_WINEMAC_ENTRY_PROBE", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

/* ★ 04.09.2026 — macrunner_hb_find_disk_native_entry() УДАЛЕНА.
 *
 * Она открывала файл модуля и читала его ЦЕЛИКОМ в кучу (до 64 МБ) ради ЧЕТЫРЁХ БАЙТ —
 * нативной точки входа, — и делала это на каждом уведомлении DllMain, включая
 * DLL_THREAD_ATTACH/DETACH. Обе точки входа читаются из уже отображённого образа:
 * см. macrunner_hb_arm64x_entry_from_view() ниже и там же числа замера (590 из 590).
 * Лечение доказано и сделано безусловным, лишний путь снят целиком. */

static IMAGE_ARM64EC_METADATA *macrunner_hb_get_arm64x_metadata( HMODULE module )
{
    IMAGE_LOAD_CONFIG_DIRECTORY *cfg;
    IMAGE_NT_HEADERS *nt;
    ULONG_PTR base;
    ULONG size;

    if (!(nt = RtlImageNtHeader( module ))) return NULL;
    if (!(cfg = RtlImageDirectoryEntryToData( module, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size )))
        return NULL;
    size = min( size, cfg->Size );
    if (size <= offsetof( IMAGE_LOAD_CONFIG_DIRECTORY, CHPEMetadataPointer )) return NULL;
    base = (ULONG_PTR)module;
    if (nt->OptionalHeader.SizeOfImage > ~(ULONG_PTR)0 - base) return NULL;
    if (cfg->CHPEMetadataPointer <= base ||
        cfg->CHPEMetadataPointer >= base + nt->OptionalHeader.SizeOfImage)
        return NULL;
    return (IMAGE_ARM64EC_METADATA *)cfg->CHPEMetadataPointer;
}

static DLLENTRYPROC macrunner_hb_arm64x_entry_from_view( WINE_MODREF *wm, const char *skip_section );

/* ★★★★★★★ 05.09.2026 — ПОЛОВИНА, КОТОРАЯ ЖИВЁТ В ЭТОМ ПРОЦЕССЕ.
 *
 * У образа ARM64X два ТЕЛА одной и той же функции и две копии `.data`, а связывающих их
 * исправлений нет ни одного (0 из 9118 на 590 образах — разбор 04.09). Инициализирует свою
 * копию только ТА половина, чья точка входа отработала: при AMD64-главном образе таблица
 * исправлений переключает образ в вид EC, и `DllMain` исполняет половину EC. Половина ARM64
 * при этом остаётся с нулями — измерено в госте pid=0020 05.09:
 *
 *     вид=EC     &sort=…7762F8 guid_count=75  locale_table=…B902688   ЗАПОЛНЕНА
 *     вид=native &sort=…773AF0 guid_count=0   locale_table=0          ПУСТА
 *
 * ЗАЧЕМ ЭТО ЗДЕСЬ. Разрешение импортов отдавало адреса из МЁРТВОЙ половины: шаг «дисковая
 * таблица экспорта» (`macrunner_hb_find_disk_export_outside_section`) читает таблицу
 * НЕПЕРЕКЛЮЧЁННОГО файла, а она называет тела ARM64. Цепочка отказа, снятая по адресам:
 *
 *     x64-locale-probe.exe -> kernel32!CompareStringW  rva 0x2b60c (тело ARM64)
 *       -> kernelbase!CompareStringW    rva 0x31d20 (+0xfc = 0x31e1c, кадр 3)
 *       -> kernelbase!CompareStringEx   rva 0x30e34 (+0xf4 = 0x30f28, кадр 2)
 *       -> kernelbase!get_language_sort rva 0x2da24 (+0x148 = 0x2db6c, кадр 1) -> c0000005 по 0x0
 *     в кадре отказа x5 = &locale_table нативной копии, x7 = &nls_key нативной копии.
 *
 * И ГЛАВНОЕ, ПОЧЕМУ «дать каждой половине свой адрес» НЕВОЗМОЖНО: у обычного импорта СЛОТ IAT
 * ОДИН НА ОБЕ ПОЛОВИНЫ. Разобрано в kernel32.dll: тело EC `jmp *0x4eda(%rip)` и тело ARM64
 * `adrp x16,…; ldr x16,[x16,#0xf0]; br x16` читают ОДИН И ТОТ ЖЕ слот 0x580f0, и среди 21
 * исправления ARM64X этого модуля его нет (две DELTA — у ОТЛОЖЕННОГО импорта). Значит вопрос
 * «какое тело писать в слот» имеет ровно один правильный ответ на процесс: тело ЖИВОЙ половины.
 * Так же устроено и у Microsoft: в процессе живёт РОВНО ОДИН вид, вторая половина — мёртвый груз.
 *
 * Предикат НЕ ПОВТОРЯЕТ рассуждение о том, какая половина живая, а СПРАШИВАЕТ У ЗАГРУЗЧИКА ту
 * самую точку входа, которую он и исполняет (`macrunner_hb_arm64x_entry_from_view`), и сравнивает
 * её с нативной (`CHPE.AlternateEntryPoint`). Поэтому исключение winemac.drv, у которого мы
 * намеренно зовём НАТИВНОЕ тело, учитывается само собой — переписывать его сюда не нужно. */
static BOOL macrunner_hb_module_live_half_is_ec( WINE_MODREF *wm )
{
    IMAGE_ARM64EC_METADATA *metadata;
    ULONG_PTR base, entry;

    if (!wm || !wm->ldr.DllBase) return FALSE;
    if (!(metadata = macrunner_hb_get_arm64x_metadata( wm->ldr.DllBase ))) return FALSE;
    if (!(entry = (ULONG_PTR)macrunner_hb_arm64x_entry_from_view( wm, NULL ))) return FALSE;
    base = (ULONG_PTR)wm->ldr.DllBase;
    return entry - base != metadata->AlternateEntryPoint;
}

static void *macrunner_hb_redirect_arm64x_thunk_to_native( HMODULE module, void *ptr )
{
    IMAGE_ARM64EC_METADATA *metadata = macrunner_hb_get_arm64x_metadata( module );
    IMAGE_NT_HEADERS *nt;
    const IMAGE_ARM64EC_REDIRECTION_ENTRY *map;
    ULONG_PTR base = (ULONG_PTR)module, target = (ULONG_PTR)ptr, rva;
    int min, max;

    if (!metadata || !ptr) return ptr;
    if (!(nt = RtlImageNtHeader( module ))) return ptr;
    if (nt->OptionalHeader.SizeOfImage > ~(ULONG_PTR)0 - base ||
        target < base || target - base >= nt->OptionalHeader.SizeOfImage)
        return ptr;
    rva = target - base;
    map = get_rva( module, metadata->RedirectionMetadata );
    min = 0;
    max = metadata->RedirectionMetadataCount - 1;
    while (min <= max)
    {
        int pos = (min + max) / 2;

        if (map[pos].Source == rva) return get_rva( module, map[pos].Destination );
        if (map[pos].Source < rva) min = pos + 1;
        else max = pos - 1;
    }
    return ptr;
}

static void *macrunner_hb_find_native_target_for_thunk_import( WINE_MODREF *target_mod,
                                                              const char *import_name,
                                                              ULONG_PTR thunk_target,
                                                              BOOL prefer_arm64ec,
                                                              WINE_MODREF *importer )
{
    /* ОБЯЗАТЕЛЬНО NULL: с 1177 первый шаг стоит под гейтом, и при выключенном гейте эта
     * переменная читается раньше первого присваивания.  Компилятор поймал это предупреждением
     * -Wsometimes-uninitialized; без инициализации «выключенный гейт» НЕ был бы инертным. */
    void *native_target = NULL;
    void *r_disk = NULL, *r_exp = NULL, *r_redir = NULL;
    BOOL live_ec = FALSE;
    /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1134 — ПЕЧАТЬ ПОД ГЕЙТОМ, А НЕ ПО ТРЁМ
     * ЗАШИТЫМ ИМЕНАМ.
     *
     * Серия 1111-1133 привела сюда: импорт `GetEnvironmentStringsA` уходит в тело набора A,
     * чьи глобали никто не инициализирует, и гость умирает с exit=5 на первой же свёртке в
     * ANSI. Какая из трёх ветвей этой функции даёт адрес — не измерено, а печать включена
     * только для DXGI/D3D. Гейт: `MACRUNNER_HB_TRACE_NATIVETHUNK=1` — печатать всё,
     * либо подстрока имени — печатать совпадающие. */
    int dbg = import_name && (strstr( import_name, "CreateDXGIFactory" ) ||
                             strstr( import_name, "D3D11Create" ) ||
                             strstr( import_name, "D3D11On12" ));
    if (import_name && !dbg)
    {
        WCHAR want[64] = {0};

        if (get_env( L"MACRUNNER_HB_TRACE_NATIVETHUNK", want, sizeof(want) ) && want[0])
        {
            if (want[0] == '1' && !want[1]) dbg = 1;
            else
            {
                char narrow[64];
                unsigned i;

                for (i = 0; i + 1 < sizeof(narrow) && want[i]; i++) narrow[i] = (char)want[i];
                narrow[i] = 0;
                dbg = strstr( import_name, narrow ) != NULL;
            }
        }
    }

    if (!target_mod || !import_name || !thunk_target) return NULL;

    live_ec = macrunner_hb_module_live_half_is_ec( target_mod );

    /* MacRunner lane ЛЕСТНИЦА 2026-08-16 (итерации 1168-1176): ПОРЯДОК ЭТИХ ТРЁХ ШАГОВ ВЫБИРАЕТ
     * ПОЛОВИНУ ОБРАЗА, и по умолчанию выбирает НЕРАБОЧУЮ.
     *
     * У образа ARM64X ДВЕ таблицы экспорта, и правки IMAGE_DYNAMIC_RELOCATION_ARM64X переписывают
     * при загрузке само поле DataDir[0].VirtualAddress.  Измерено на kernelbase (19 правок, 9 из
     * них в заголовке):
     *
     *     поле                       на диске        после правок
     *     Machine                    0xaa64 ARM64    0x8664 AMD64
     *     AddressOfEntryPoint        0x761c4         0xe7000
     *     DataDir[0] EXPORT .rva     0x127068        0x131cb8      <-- две РАЗНЫЕ таблицы
     *
     *     дисковая  @0x127068  1422 имени: GetCommandLineW -> 0x0565bc  .text     (диапазон ARM64)
     *     в памяти  @0x131cb8  1428 имён : GetCommandLineW -> 0x0e8340  .hexpthk  -> по .a64xrm
     *                                                                   -> 0x0bdd30 (ARM64EC)
     *
     * Диапазоны взяты из таблицы CodeMap метаданных CHPE, а не угаданы:
     * ARM64 001000..0775e4, ARM64EC 078000..0e48dc, AMD64 0e5000..0ec330.
     *
     * DllMain модуля исполняется телом ARM64EC (точка входа = CHPE AlternateEntryPoint, во всех
     * 598 гибридных модулях диста она лежит в диапазоне ARM64EC) и заполняет глобали половины
     * ARM64EC.  Глобали половины ARM64 не пишет никто: из 78 строго спаренных переменных 14 пусты
     * со стороны ARM64 при заполненном двойнике, и НИ ОДНОЙ в обратную сторону.
     *
     * Поэтому шаг 1, читающий ДИСКОВУЮ таблицу, отдаёт тела ARM64 с пустыми глобалями.  Замер
     * вызовом обоих тел по адресу в одном процессе:
     *     ARM64   0x0565bc GetCommandLineW -> NULL        ARM64   0x0565b0 GetCommandLineA -> NULL
     *     ARM64EC 0x0bdd30 GetCommandLineW -> годная      ARM64EC 0x0bdd20 GetCommandLineA -> годная
     *
     * Фильтр ".hexpthk" писался под таблицу ИЗ ПАМЯТИ, где все экспорты указывают на переходники;
     * применённый к дисковой таблице он молча выбирает половину чужого вида.
     *
     * ПОРЯДОК БОЛЬШЕ НЕ ПОД ГЕЙТОМ (05.09) — см. следующий блок. */
    /* ★★★★★★★ 05.09.2026 — ГЕЙТЫ СНЯТЫ, ПРАВИЛО СТАЛО БЕЗУСЛОВНЫМ И ЧИТАЕТ ВИД МОДУЛЯ.
     *
     * Здесь стояли два гейта, оба по умолчанию ВЫКЛ: `MACRUNNER_HB_IMPORT_PREFER_ARM64EC`
     * (сплошная перестановка) и `MACRUNNER_HB_IMPORT_PREFER_ARM64EC_NAMES` (то же по подстроке
     * имени импорта). Довод 1352 против сплошной перестановки — «делает ПРАВИЛЬНУЮ замену и при
     * этом убивает прогон» — был верен по НАБЛЮДЕНИЮ и неверен по ОБЪЯСНЕНИЮ: перестановка
     * ломала связи там, где живая половина модуля НАТИВНАЯ, а гейт не умел их различать.
     *
     * Различие теперь берётся не из окружения, а из образа: `macrunner_hb_module_live_half_is_ec`
     * спрашивает у загрузчика ТУ САМУЮ точку входа, которую он исполняет. Живёт половина EC —
     * значит и тела надо брать оттуда: только её `.data` заполнена `DllMain`.
     *
     * ДОКАЗАНО ИСПОЛНЕНИЕМ 05.09 (`scripts/проба-x64-локаль.sh`, гость tools/x64-locale-probe.exe):
     *   ДО:    GetLocaleInfoW n=0 err=87, затем c0000005 в get_language_sort, rc=5
     *   ПОСЛЕ: GetLocaleInfoW n=6 err=0, CompareStringW n=1 err=0, LCMapStringW n=3 err=0, rc=0
     * и строка «вид=native» у гостя ИСЧЕЗЛА: мёртвая половина больше не исполняется вовсе.
     *
     * Отсекается это правило само собой там, где его быть не должно: у не-гибрида метаданных
     * CHPE нет, а `macrunner_hb_find_native_target_for_thunk_import` вызывается только из двух
     * мест, оба под `macrunner_hb_x64_main_requested()` — путь i386 не задет ни в одной ветви. */
    if (prefer_arm64ec || live_ec)
    {
        void *redirected = macrunner_hb_redirect_arm64x_thunk_to_native( target_mod->ldr.DllBase,
                                                                         (void *)thunk_target );

        if (redirected != (void *)thunk_target &&
            !macrunner_hb_address_in_section( target_mod->ldr.DllBase, ".hexpthk",
                                              (ULONG_PTR)redirected ))
            native_target = r_redir = redirected;
    }
    if (!native_target)
        native_target = r_disk = macrunner_hb_find_disk_export_outside_section( target_mod, import_name, ".hexpthk" );
    if (!native_target)
        native_target = r_exp = macrunner_hb_find_export_outside_section( target_mod->ldr.DllBase, import_name, ".hexpthk" );
    if (!native_target)
    {
        void *redirected = macrunner_hb_redirect_arm64x_thunk_to_native( target_mod->ldr.DllBase,
                                                                         (void *)thunk_target );

        if (redirected != (void *)thunk_target &&
            !macrunner_hb_address_in_section( target_mod->ldr.DllBase, ".hexpthk",
                                              (ULONG_PTR)redirected ))
            native_target = r_redir = redirected;
    }

    /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1280 — НЕ ПОДМЕНЯТЬ ВЕРНЫЙ АДРЕС НЕВЕРНЫМ.
     *
     * ИЗМЕРЕНО (1279, прогоны r9-M и статика по kernelbase.dll):
     *   у ARM64X-модуля ДВЕ таблицы экспорта, и они дают РАЗНЫЕ адреса:
     *       дисковая (DataDir[0] в файле, rva 0x127068), 1422 экспорта:  CreateFileA -> rva 0x1f630
     *       вторая (куда указывают правки ARM64X, 0x131cb8), 1428:       CreateFileA -> rva 0xe77c0
     *   гость приходит сюда с `thunk_target` = 0xe77c0, то есть УЖЕ С ВЕРНЫМ адресом,
     *   а разрешение отвечает `disk=0x1f630, export=0, redir=0` и подменяет верный неверным.
     *
     * Следствие прослежено до отказа теста: вызов уходит в тело вида ARM64, файл не открывается
     * (0 совпадений на 5003 открытия), `CreateFileA` возвращает мусор `0x6f4000000000`,
     * `NtCreateSection` отвечает `c0000008`, и девять отказов класса D — производные.
     *
     * Правка узкая: если ЕДИНСТВЕННЫЙ источник ответа — дисковая таблица (в памяти не нашлось,
     * перенаправление не сработало), не подменять ничего. NULL здесь означает «оставить то, что
     * у гостя уже есть».
     *
     * Гейт `MACRUNNER_HB_IMPORT_REJECT_DISK_ONLY`, умолчание ВЫКЛ: правка задевает разрешение
     * КАЖДОГО импорта каждого встроенного модуля. База сравнения — набор `wow64_test.exe`:
     * 34 отказа в 31 месте, воспроизведено семью прогонами подряд. */
    /* ПОПРАВКА К СЕБЕ (итерация 1281). Первая редакция условия (1280) звучала «источник ответа —
     * ТОЛЬКО дисковая таблица» и оказалась НЕ узкой: она выполняется почти у всех импортов
     * (`ActivateActCtx`, `AddConsoleAliasA`, `AddDllDirectory`…), подмена отключилась массово, и
     * прогон умер ДО набора — 0 строк из `wow64.c`, `c0000005` по адресу из текстовых байтов.
     * «Ноль отказов» тогда означало «до отказов не дошло».
     *
     * Настоящее различие из 1279 иное: у гостя УЖЕ ЕСТЬ годный адрес второй таблицы. Проверяю
     * ровно это, тремя условиями сразу:
     *   1) `thunk_target` указывает в ИСПОЛНЯЕМУЮ секцию модуля — то есть это код, а не заглушка;
     *   2) модуль ARM64X (есть метаданные ARM64EC) — только у таких таблиц экспорта две;
     *   3) дисковый ответ РАСХОДИТСЯ с `thunk_target` — если совпадает, подменять нечего.
     * Все три вместе выделяют случай `CreateFileA` (thunk 0xe77c0 против диска 0x1f630) и не
     * трогают импорты, у которых `thunk_target` не код или модуль не ARM64X. */
    /* ★★★★★★ 05.09.2026 — ПРИБОР БЕЗ ГЕЙТА: «адрес отдан из МЁРТВОЙ половины».
     *
     * Правило выше говорит: у модуля, живущего в виде EC, тела берутся из половины EC. Если
     * ответом всё-таки стала ДИСКОВАЯ таблица (половина ARM64), значит перенаправление .a64xrm
     * этого экспорта не нашло — и вызывающий уйдёт в код, чьи глобали никто не заполнял. Ровно
     * это 04-05.09 убивало x64-гостя: kernelbase!get_language_sort читала нулевой locale_table
     * и падала с c0000005 по адресу 0, а наружу это выглядело как «GetLocaleInfoW вернул 87».
     *
     * Печать БЕЗ ГЕЙТА и с потолком в 8 строк: событие не должно случаться вовсе, а когда
     * случится — искать его по имени и адресу должно быть можно в ЛЮБОМ журнале, без пересборки
     * и без второго прогона. Отрицательный контроль встроен: при здоровом дисте строк ноль. */
    if (live_ec && r_disk && native_target == r_disk)
    {
        static LONG dead_half_hits;

        if (InterlockedIncrement( &dead_half_hits ) <= 8)
        {
            ULONG_PTR b = (ULONG_PTR)target_mod->ldr.DllBase;

            MESSAGE( "macrunner-arm64x-мёртвая-половина-импорт: importer=%s %s!%s "
                     "живая=EC адрес=rva 0x%llx (дисковая таблица ARM64) thunk=rva 0x%llx\n",
                     importer ? debugstr_w(importer->ldr.BaseDllName.Buffer) : "?",
                     debugstr_w(target_mod->ldr.BaseDllName.Buffer), import_name,
                     (unsigned long long)((ULONG_PTR)r_disk - b),
                     (unsigned long long)(thunk_target - b) );
        }
    }

    if (dbg)
    {
        ULONG_PTR b = (ULONG_PTR)target_mod->ldr.DllBase;
        MESSAGE( "macrunner-hb-nativethunk: importer=%s prefer_ec=%d import=%s mod=%s base=%p thunk_target=%p(rva 0x%llx) "
                 "disk=%p(rva 0x%llx) export=%p(rva 0x%llx) redir=%p(rva 0x%llx) final=%p(rva 0x%llx) exec=%d\n",
                 importer ? debugstr_w(importer->ldr.BaseDllName.Buffer) : "?", prefer_arm64ec,
                 import_name, debugstr_w(target_mod->ldr.BaseDllName.Buffer), (void *)b,
                 (void *)thunk_target, (unsigned long long)(thunk_target - b),
                 r_disk, (unsigned long long)(r_disk ? (ULONG_PTR)r_disk - b : 0),
                 r_exp, (unsigned long long)(r_exp ? (ULONG_PTR)r_exp - b : 0),
                 r_redir, (unsigned long long)(r_redir ? (ULONG_PTR)r_redir - b : 0),
                 native_target, (unsigned long long)(native_target ? (ULONG_PTR)native_target - b : 0),
                 native_target ? macrunner_hb_address_in_executable_section( target_mod->ldr.DllBase,
                                                                             (ULONG_PTR)native_target ) : -1 );
    }

    /* MacRunner лейн ЛЕСТНИЦА, итерация 1194 — СЧЁТЧИК ВМЕСТО ПЕЧАТИ НА КАЖДЫЙ ИМПОРТ.
     *
     * Печать выше (`dbg`) выдаёт строку на КАЖДОЕ разрешение — в пробе x64 это 833 строки за
     * запуск, а на Diablo поток сносит прогон: измерено дважды подряд, `MACRUNNER_HB_TRACE_
     * NATIVETHUNK=1` даёт `Killed: 9` на 17.6-17.8 с при журнале ровно 85 543 байта в обеих
     * руках, тогда как та же конфигурация без него живёт 250.9 с (итерация 1193).  То есть
     * прибор уничтожал измерение.
     *
     * Здесь тот же вопрос решается счётчиками с редкой печатью: сколько разрешений всего и
     * какой ветвью они разрешились.  Гейт отдельный, чтобы не смешивать с построчной печатью. */
    {
        static LONG n_total, n_disk, n_exp, n_redir, n_none;
        LONG n = InterlockedIncrement( &n_total );

        if (r_disk) InterlockedIncrement( &n_disk );
        else if (r_exp) InterlockedIncrement( &n_exp );
        else if (r_redir) InterlockedIncrement( &n_redir );
        else InterlockedIncrement( &n_none );

        if (n == 1 || (n & 0xFFF) == 0)
        {
            WCHAR val[8] = {0};

            if (get_env( L"MACRUNNER_HB_COUNT_NATIVETHUNK", val, sizeof(val) ) &&
                val[0] && val[0] != '0')
                MESSAGE( "macrunner-hb-thunkcount: vsego=%ld disk=%ld export=%ld redir=%ld net=%ld\n",
                         (long)n, (long)n_disk, (long)n_exp, (long)n_redir, (long)n_none );
        }
    }

    if (native_target &&
        macrunner_hb_address_in_executable_section( target_mod->ldr.DllBase,
                                                    (ULONG_PTR)native_target ))
        return native_target;
    return NULL;
}

/* ★ 2026-08-18, итерация 2385: счётчики отсева ARM64X определены БЕЗУСЛОВНО.
 * Были под `#if defined(__aarch64__) && !defined(__arm64ec__)`, а считать надо и из кода,
 * который компилируется в обе половины ARM64X, — иначе компоновка EC-половины падает с
 * `undefined symbol ... (EC symbol)`. Поймано сборкой, не прогоном. */
volatile LONG macrunner_hb_arm64x_gate_hits[6];

#if defined(__aarch64__) && !defined(__arm64ec__)
static void *macrunner_hb_resolve_arm64x_dispatch_import( void *target );

/* The caller is an EC helper even in the native ARM64 loader.  In particular,
 * x4/x5 carry the EC vararg stack pointer/size.  Do not call a plain ARM64
 * vararg export, or let a resolver C call destroy these registers. */
static void __attribute__((naked)) macrunner_hb_arm64x_dispatch_import(void)
{
    asm( ".seh_proc macrunner_hb_arm64x_dispatch_import\n\t"
         "stp x29, x30, [sp, #-288]!\n\t"
         ".seh_save_fplr_x 288\n\t"
         "mov x29, sp\n\t"
         ".seh_set_fp\n\t"
         ".seh_endprologue\n\t"
         "stp x0, x1, [sp, #16]\n\t"
         "stp x2, x3, [sp, #32]\n\t"
         "stp x4, x5, [sp, #48]\n\t"
         "stp x6, x7, [sp, #64]\n\t"
         "stp x8, x9, [sp, #80]\n\t"
         "stp x10, x11, [sp, #96]\n\t"
         "stp x12, x13, [sp, #112]\n\t"
         "stp x14, x15, [sp, #128]\n\t"
         "stp x16, x17, [sp, #144]\n\t"
         "stp q0, q1, [sp, #160]\n\t"
         "stp q2, q3, [sp, #192]\n\t"
         "stp q4, q5, [sp, #224]\n\t"
         "stp q6, q7, [sp, #256]\n\t"
         "mov x0, x11\n\t"
         "bl %0\n\t"
         "str x0, [sp, #104]\n\t"  /* only the dispatch target changes */
         "ldp q6, q7, [sp, #256]\n\t"
         "ldp q4, q5, [sp, #224]\n\t"
         "ldp q2, q3, [sp, #192]\n\t"
         "ldp q0, q1, [sp, #160]\n\t"
         "ldp x16, x17, [sp, #144]\n\t"
         "ldp x14, x15, [sp, #128]\n\t"
         "ldp x12, x13, [sp, #112]\n\t"
         "ldp x10, x11, [sp, #96]\n\t"
         "ldp x8, x9, [sp, #80]\n\t"
         "ldp x6, x7, [sp, #64]\n\t"
         "ldp x4, x5, [sp, #48]\n\t"
         "ldp x2, x3, [sp, #32]\n\t"
         "ldp x0, x1, [sp, #16]\n\t"
         ".seh_startepilogue\n\t"
         "ldp x29, x30, [sp], #288\n\t"
         ".seh_save_fplr_x 288\n\t"
         ".seh_endepilogue\n\t"
         "ret\n\t"
         ".seh_endproc" :: "S" (macrunner_hb_resolve_arm64x_dispatch_import) );
}

static void __attribute__((naked)) macrunner_hb_arm64x_native_dispatch_ret(void)
{
    asm( "ldrb w16, [x11]\n\t"
         "cmp w16, #0xff\n\t"
         "b.ne .Lmacrunner_hb_arm64x_native_dispatch_lea\n\t"
         "ldrb w16, [x11, #1]\n\t"
         "cmp w16, #0x25\n\t"               /* ff 25 jmp *disp32(%rip) */
         "b.eq %0\n\t"
         "ret\n\t"
         ".Lmacrunner_hb_arm64x_native_dispatch_lea:\n\t"
         "cmp w16, #0x48\n\t"
         "b.ne .Lmacrunner_hb_arm64x_native_dispatch_done\n\t"
         "ldrb w16, [x11, #1]\n\t"
         "cmp w16, #0x8d\n\t"               /* unresolved x64 delay import */
         "b.eq %0\n\t"
         ".Lmacrunner_hb_arm64x_native_dispatch_done:\n\t"
         "ret" :: "S" (macrunner_hb_arm64x_dispatch_import) );
}

/* ★★★ MacRunner 2026-08-18, лейн ЛЕСТНИЦА, итерация 2382 (приказы владельца 179 и 186) —
 * ШЕСТЬ СЛОТОВ РАЗВЕДЕНЫ НА ШЕСТЬ ТРАМПЛИНОВ. Тело пока ОДНО И ТО ЖЕ.
 *
 * Зачем именно так, а не сразу починка. По договору ARM64EC пять слотов из шести должны делать
 * не то, что делает наш общий обработчик (он лишь разматывает цепочку x64-переходов `ff 25` и
 * возвращается). Но какой слот у нас зовётся на самом деле — не измерено ни разу: симптом
 * «58 повторов по одному адресу» это ПОКАЗАНИЕ, а не имя слота.
 *
 * Поэтому сначала прибор: шесть отдельных входов, каждый считает свои вызовы, тело общее —
 * поведение прогона не меняется ни на бит. Прогон назовёт слот, и только тогда правка будет
 * опираться на замер, а не на догадку (правило приказа 185: догадка УСКОРЯЕТ, но не решает).
 *
 * Счётчик потоко-безопасный и без печати на горячем пути: печать по требованию, из
 * `macrunner_hb_arm64x_slot_report()`. */
static volatile LONG macrunner_hb_arm64x_slot_hits[6];

static void macrunner_hb_arm64x_slot_report(void)
{
    static const char * const имена[6] = { "dispatch_call", "call_no_redirect", "fptr",
                                           "icall", "icall_cfg", "ret" };
    unsigned i;

    static const char * const причины[6] = { "не-внутренний-модуль", "хозяин-не-ARM64",
                                             "нет-PE-заголовка", "модуль-не-AMD64",
                                             "дошло-до-ветви-ВНУТРЕННИХ", "дошло-до-обработки-DllMain" };

    for (i = 0; i < 6; i++)
        MESSAGE( "macrunner-hb-arm64x-slot: %s=%ld\n", имена[i],
                 (long)macrunner_hb_arm64x_slot_hits[i] );
    for (i = 0; i < 6; i++)
        MESSAGE( "macrunner-hb-arm64x-отсев: %s=%ld\n", причины[i],
                 (long)macrunner_hb_arm64x_gate_hits[i] );
}

#define MACRUNNER_HB_ARM64X_SLOT_THUNK(имя, индекс)                                    \
    static void __attribute__((naked)) macrunner_hb_arm64x_slot_##имя(void);           \
    static void macrunner_hb_arm64x_slot_note_##имя(ULONG_PTR цель, ULONG_PTR thunk)   \
    {                                                                                  \
        /* ★ 2026-08-18, итерация 2389 — ПЕРВОЕ СРАБАТЫВАНИЕ ПЕЧАТАЕТСЯ ЗДЕСЬ.          \
         * Счётчики выводились только из `LdrShutdownProcess`, куда главный процесс не   \
         * доходит, поэтому «ноль вызовов» значил «ноль у отчитавшихся». Печать прямо в  \
         * учётчике снимает оговорку: регистры тут уже сохранены обёрткой. */            \
        LONG было = InterlockedIncrement( (LONG *)&macrunner_hb_arm64x_slot_hits[индекс] ); \
        if (было <= 4)                                                                 \
            MESSAGE( "macrunner-hb-arm64x-вызов: слот=%s n=%ld цель_x11=%p thunk_x10=%p\n", \
                     #имя, (long)было, (void *)цель, (void *)thunk );                  \
    }                                                                                  \
    static void __attribute__((naked)) macrunner_hb_arm64x_slot_##имя(void)            \
    {                                                                                  \
        asm( "stp x29, x30, [sp, #-96]!\n\t"                                          \
             "stp x9, x10, [sp, #16]\n\t"                                             \
             "stp x11, x12, [sp, #32]\n\t"                                            \
             "stp x0, x1, [sp, #48]\n\t"                                              \
             "stp x2, x3, [sp, #64]\n\t"                                              \
             "stp x16, x17, [sp, #80]\n\t"                                            \
             "mov x0, x11\n\t"                    /* цель, как её видит проверяльщик */ \
             "mov x1, x10\n\t"                    /* exit thunk по договору ARM64EC */  \
             "bl %0\n\t"                                                              \
             "ldp x16, x17, [sp, #80]\n\t"                                            \
             "ldp x2, x3, [sp, #64]\n\t"                                              \
             "ldp x0, x1, [sp, #48]\n\t"                                              \
             "ldp x11, x12, [sp, #32]\n\t"                                            \
             "ldp x9, x10, [sp, #16]\n\t"                                             \
             "ldp x29, x30, [sp], #96\n\t"                                            \
             "b %1"                                                                    \
             :: "S" (macrunner_hb_arm64x_slot_note_##имя),                             \
                "S" (macrunner_hb_arm64x_native_dispatch_ret) );                        \
    }

MACRUNNER_HB_ARM64X_SLOT_THUNK( call,             0 )
MACRUNNER_HB_ARM64X_SLOT_THUNK( call_no_redirect, 1 )
MACRUNNER_HB_ARM64X_SLOT_THUNK( fptr,             2 )
MACRUNNER_HB_ARM64X_SLOT_THUNK( icall,            3 )
MACRUNNER_HB_ARM64X_SLOT_THUNK( icall_cfg,        4 )
MACRUNNER_HB_ARM64X_SLOT_THUNK( ret,              5 )

static BOOL macrunner_hb_section_contains_virtual_rva( const IMAGE_SECTION_HEADER *sec, DWORD rva,
                                                       SIZE_T len )
{
    DWORD delta;

    if (rva < sec->VirtualAddress) return FALSE;
    delta = rva - sec->VirtualAddress;
    return delta <= sec->Misc.VirtualSize && len <= sec->Misc.VirtualSize - delta;
}

static void macrunner_hb_update_arm64x_pointer( void *module, const IMAGE_SECTION_HEADER *sec,
                                                UINT rva, void *ptr, unsigned int *count )
{
    void *slot;

    if (!rva) return;
    if (!macrunner_hb_section_contains_virtual_rva( sec, rva, sizeof(void *) ) ||
        (ULONG_PTR)module > ~(ULONG_PTR)0 - rva)
    {
        MESSAGE( "MacRunner HyperBridge ARM64X metadata rva %x outside section %s va=%lx size=%lx\n",
               rva, sec->Name, sec->VirtualAddress, sec->Misc.VirtualSize );
        return;
    }
    slot = get_rva( module, rva );
    *(void **)slot = ptr;
    if (count) (*count)++;
}

static void macrunner_hb_update_arm64x_native_dispatch_metadata( WINE_MODREF *wm )
{
    IMAGE_ARM64EC_METADATA *metadata;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sec;
    DWORD i, protect_old;
    unsigned int count = 0;

    /* ★ 2026-08-18, лейн ЛЕСТНИЦА, итерация 2383 — ПЕРЕПИСЬ ОТСЕВА НА ВХОДЕ.
     *
     * Замер 2382: все шесть слотов дали ноль, и строк «initialized ARM64X native dispatch
     * metadata» тоже ноль — значит до раздачи указателей дело не доходит. Четыре условия ниже
     * отсекают молча и неразличимо, а это ровно тот класс, который я сегодня уже ловил на
     * `not-x64-main-process`: одно молчание на несколько причин.
     *
     * Считаем КАЖДУЮ причину отдельно и печатаем свод по выходу процесса — тогда следующий
     * прогон назовёт условие, а не оставит меня гадать. Печати на горячем пути нет: только
     * инкременты. */
    {
        extern volatile LONG macrunner_hb_arm64x_gate_hits[6];
        if (!wm || !(wm->ldr.Flags & LDR_WINE_INTERNAL))
            { InterlockedIncrement( (LONG *)&macrunner_hb_arm64x_gate_hits[0] ); return; }
        if (current_machine != IMAGE_FILE_MACHINE_ARM64)
            { InterlockedIncrement( (LONG *)&macrunner_hb_arm64x_gate_hits[1] ); return; }
        if (!(nt = RtlImageNtHeader( wm->ldr.DllBase )))
            { InterlockedIncrement( (LONG *)&macrunner_hb_arm64x_gate_hits[2] ); return; }
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
            { InterlockedIncrement( (LONG *)&macrunner_hb_arm64x_gate_hits[3] ); return; }
        if (!(metadata = macrunner_hb_get_arm64x_metadata( wm->ldr.DllBase )))
            { InterlockedIncrement( (LONG *)&macrunner_hb_arm64x_gate_hits[4] ); return; }
        InterlockedIncrement( (LONG *)&macrunner_hb_arm64x_gate_hits[5] );
    }

    /*
     * Upstream ARM64EC fills these slots from arm64ec_update_hybrid_metadata().
     * Our Phase G aarch64 host is not an ARM64EC process, but native ARM64 Wine
     * DLLs still execute ARM64X helper thunks.  Native destinations can return
     * directly to the following "br x11".  Import stubs must first be resolved;
     * an unresolved EC delay-IAT slot still contains x64 LEA/JMP code.
     */
    sec = IMAGE_FIRST_SECTION( nt );
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (macrunner_hb_section_contains_virtual_rva( sec, metadata->__os_arm64x_dispatch_icall,
                                                       sizeof(void *) ) &&
            (ULONG_PTR)wm->ldr.DllBase <= ~(ULONG_PTR)0 - sec->VirtualAddress)
        {
            void *base = get_rva( wm->ldr.DllBase, sec->VirtualAddress );
            SIZE_T size = sec->Misc.VirtualSize;

            NtProtectVirtualMemory( NtCurrentProcess(), &base, &size, PAGE_READWRITE, &protect_old );
            macrunner_hb_update_arm64x_pointer( wm->ldr.DllBase, sec, metadata->__os_arm64x_dispatch_call,
                                                macrunner_hb_arm64x_native_dispatch_ret, &count );
            macrunner_hb_update_arm64x_pointer( wm->ldr.DllBase, sec, metadata->__os_arm64x_dispatch_call_no_redirect,
                                                macrunner_hb_arm64x_native_dispatch_ret, &count );
            macrunner_hb_update_arm64x_pointer( wm->ldr.DllBase, sec, metadata->__os_arm64x_dispatch_fptr,
                                                macrunner_hb_arm64x_native_dispatch_ret, &count );
            macrunner_hb_update_arm64x_pointer( wm->ldr.DllBase, sec, metadata->__os_arm64x_dispatch_icall,
                                                macrunner_hb_arm64x_native_dispatch_ret, &count );
            macrunner_hb_update_arm64x_pointer( wm->ldr.DllBase, sec, metadata->__os_arm64x_dispatch_icall_cfg,
                                                macrunner_hb_arm64x_native_dispatch_ret, &count );
            macrunner_hb_update_arm64x_pointer( wm->ldr.DllBase, sec, metadata->__os_arm64x_dispatch_ret,
                                                macrunner_hb_arm64x_native_dispatch_ret, &count );
            NtProtectVirtualMemory( NtCurrentProcess(), &base, &size, protect_old, &protect_old );
            /* ★ 2026-08-18, итерация 2408 — печать раздачи убрана: ответ получен
             * (6 указателей на модуль, замер 2388). */
            MESSAGE( "MacRunner HyperBridge initialized ARM64X native dispatch metadata for %s count=%u helper=%p\n",
                   debugstr_w(wm->ldr.BaseDllName.Buffer), count, macrunner_hb_arm64x_native_dispatch_ret );
            return;
        }
    }
}
#else
static void macrunner_hb_update_arm64x_native_dispatch_metadata( WINE_MODREF *wm )
{
}
#endif

static WINE_MODREF *macrunner_hb_find_module_from_address( ULONG_PTR addr )
{
    PLIST_ENTRY mark, entry;

    mark = &NtCurrentTeb()->Peb->LdrData->InLoadOrderModuleList;
    for (entry = mark->Flink; entry != mark; entry = entry->Flink)
    {
        LDR_DATA_TABLE_ENTRY *mod = CONTAINING_RECORD( entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
        IMAGE_NT_HEADERS *nt = RtlImageNtHeader( mod->DllBase );
        ULONG_PTR base = (ULONG_PTR)mod->DllBase;

        if (!nt) continue;
        if (nt->OptionalHeader.SizeOfImage <= ~(ULONG_PTR)0 - base &&
            addr >= base && addr < base + nt->OptionalHeader.SizeOfImage)
            return CONTAINING_RECORD( mod, WINE_MODREF, ldr );
    }
    return NULL;
}

static BOOL macrunner_hb_modref_range_contains( WINE_MODREF *mod, ULONG_PTR addr, SIZE_T len )
{
    ULONG_PTR base, end;

    if (!mod) return FALSE;
    base = (ULONG_PTR)mod->ldr.DllBase;
    if (mod->ldr.SizeOfImage > ~(ULONG_PTR)0 - base) return FALSE;
    end = base + mod->ldr.SizeOfImage;
    return addr >= base && addr <= end && len <= end - addr;
}

/* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1258 — СЧЁТЧИК МОЛЧАЛИВОГО ПОТОЛКА.
 *
 * Зачем. Потолок цепочки разрешения (8 шагов ниже) числился открытым пунктом доски со словами
 * «молчаливый выход по потолку, счётчика достижений нет» (партия 6, итерация 1247). Пока
 * счётчика нет, вопрос «а достигается ли он вообще» не имеет ответа, и правка потолка была бы
 * починкой по догадке.
 *
 * ВАЖНО, потолков ДВА, и это разные места (поправка к собственному итогу, 1258):
 *   loader.c:3182  этот цикл на C, `limit < 8`                      — считается здесь
 *   loader.c:3046  ассемблерный трамплин dispatch_ret, `mov x12,#8` — НЕ считается, naked
 * Оба молчат, оба ходят по одной и той же цепочке `ff 25`. Счётчик закрывает только первый.
 *
 * Гейт MACRUNNER_HB_ARM64X_CHAIN_STATS, умолчание ВКЛ (значение `0` выключает, `2` включает
 * построчную печать КАЖДОГО звена). Цена при умолчании: два сложения на вызов разрешения —
 * это путь загрузки импортов, а не горячий путь исполнения.
 *
 * Печать: ПЕРВОЕ достижение потолка печатается ВСЕГДА и с адресом; далее сводка по степеням
 * двойки от числа вызовов. Событие, которое может не наступить, негодно как критерий — поэтому
 * сводка выходит и при нуле достижений, и «потолок не достигнут ни разу» становится ИЗМЕРЕНИЕМ,
 * а не молчанием.
 */
static int macrunner_hb_arm64x_chain_stats_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        WCHAR value[8] = {0};

        if (!get_env( L"MACRUNNER_HB_ARM64X_CHAIN_STATS", value, sizeof(value) ) || !value[0])
            enabled = 1;                          /* переменной нет — ВКЛ */
        else if (value[0] == '0') enabled = 0;
        else if (value[0] == '2') enabled = 2;    /* плюс печать каждого звена */
        else enabled = 1;
    }
    return enabled;
}

static unsigned long long macrunner_hb_a64x_chain_calls;
static unsigned long long macrunner_hb_a64x_chain_links;
static unsigned long long macrunner_hb_a64x_chain_ceiling;
/* Числа печатаются ШЕСТНАДЦАТЕРИЧНО: `wine_dbgstr_longlong` иначе не умеет, а `%llu` в этой
 * сборке PE недоступен. Поэтому в формате стоит явный `0x` — без него «вызовов=400» читается
 * как четыреста, а это 1024 (поймано на первом же применении, 1258). */
static unsigned int macrunner_hb_a64x_chain_max;

static void *macrunner_hb_resolve_arm64x_native_target( void *ptr )
{
    unsigned int limit;
    void *start = ptr;
    int stats = macrunner_hb_arm64x_chain_stats_enabled();

    for (limit = 0; ptr && limit < 8; limit++)
    {
        WINE_MODREF *mod = macrunner_hb_find_module_from_address( (ULONG_PTR)ptr );
        void *native;
        BYTE *code = ptr;
        ULONG_PTR slot;
        INT32 disp;
        void *next;

        if (mod)
        {
            native = macrunner_hb_redirect_arm64x_thunk_to_native( mod->ldr.DllBase, ptr );
            if (native && native != ptr)
            {
                ptr = native;
                continue;
            }
        }

        if (!macrunner_hb_modref_range_contains( mod, (ULONG_PTR)code, 6 )) break;
        if (code[0] != 0xff || code[1] != 0x25) break; /* x64 jmp *disp32(%rip) */
        memcpy( &disp, code + 2, sizeof(disp) );
        slot = (ULONG_PTR)code + 6;
        if (slot < (ULONG_PTR)code) break;
        if (disp < 0)
        {
            ULONG_PTR back = -(LONG_PTR)disp;
            if (back > slot) break;
            slot -= back;
        }
        else
        {
            if ((ULONG_PTR)disp > ~(ULONG_PTR)0 - slot) break;
            slot += disp;
        }
        if (!macrunner_hb_modref_range_contains( mod, slot, sizeof(next) )) break;
        next = *(void **)slot;
        if (!next || next == ptr) break;
        ptr = next;
    }

    if (stats)
    {
        unsigned long long n = ++macrunner_hb_a64x_chain_calls;

        macrunner_hb_a64x_chain_links += limit;
        /* `limit == 8` означает ИМЕННО потолок: выход по `break` увеличения не делает. */
        /* Печать через MESSAGE, а НЕ fprintf: это сторона PE, CRT здесь нет и сборка
         * падает на `undefined symbol: fprintf` (проверено). Соседний маркер этого же файла
         * `macrunner-hb-arm64x-native-import-prefix` (строка 4811) печатает так же и в живом
         * прогоне выходит — то есть идиома доказана, а не выбрана по вкусу. */
        if (limit >= 8 && ++macrunner_hb_a64x_chain_ceiling == 1)
            MESSAGE( "macrunner-hb-a64x-chain: ПОТОЛОК ДОСТИГНУТ впервые вызов=%s начало=%p конец=%p\n",
                     wine_dbgstr_longlong(n), start, ptr );
        if (stats > 1)
            MESSAGE( "macrunner-hb-a64x-chain: вызов=%s звеньев=%u начало=%p конец=%p\n",
                     wine_dbgstr_longlong(n), limit, start, ptr );
        /* Печать НА СОБЫТИЕ, а не только по периоду (поправка 1258, поймано применением).
         * Периодическая сводка по степеням двойки отставала от конца прогона: последняя вышла
         * на вызове 0x400, а первая непустая цепочка случилась на 0x573 — то есть прибор
         * отчитался «звеньев 0» и пропустил ВСЕ 117 интересных случаев. Максимум длины —
         * это ровно то число, ради которого прибор и ставился, поэтому он печатается при
         * каждом росте. */
        if (limit > macrunner_hb_a64x_chain_max)
        {
            macrunner_hb_a64x_chain_max = limit;
            MESSAGE( "macrunner-hb-a64x-chain: НОВЫЙ МАКСИМУМ звеньев=%u вызов=0x%s начало=%p конец=%p\n",
                     limit, wine_dbgstr_longlong(n), start, ptr );
        }
        if ((n & (n - 1)) == 0 || (n & 1023u) == 0)
            MESSAGE( "macrunner-hb-a64x-chain: вызовов=0x%s звеньев=0x%s потолков=0x%s максимум=%u\n",
                     wine_dbgstr_longlong(n),
                     wine_dbgstr_longlong(macrunner_hb_a64x_chain_links),
                     wine_dbgstr_longlong(macrunner_hb_a64x_chain_ceiling),
                     macrunner_hb_a64x_chain_max );
    }
    return ptr;
}

/*
 * MacRunner 2026-07-29 (HK DllMain lane) -- MEASURED root cause, not a guess.
 *
 * In Hollow Knight's x86_64 guest process winemac.drv is mapped with NO executable pages at
 * all.  `vmmap` on the live wedged process (pid 35734, run …i4-native-a1-try1-094345) against
 * the on-disk section table: the image is exactly DllBase 0x87ef2e40000 + SizeOfImage 0x30000,
 * and all three of its live regions are r-- / rw- / r--.  RVA 0x0-0xc000 -- which covers .text
 * (marked XR- in the PE section table) and .hexpthk -- is live-mapped r--.  So the correctly
 * resolved native entry (DllBase + AlternateEntryPoint 0x6030, inside .text) is a branch into a
 * non-executable page: SIGILL, routed into macrunner_hb_route_x64_callback_fault ->
 * macrunner_hb_redirect_arm64x_hexpthk_sigill, where the guest thread spun 4790/4790 samples.
 *
 * This is specific to this module, not a blanket "guest PEs are never executable": the same
 * process has 37 executable regions out of 294 in the guest band, including one inside
 * win32u.dll's guest copy.  winemac.drv has zero -- it is the one builtin that never enters
 * builtin-twin resolution, because User32LoadDriver pins LdrLoadDll to c:\windows\system32.
 *
 * It also explains why the x64 route (MACRUNNER_HB_WINEMAC_X64_DLLMAIN) got further before
 * wedging: guest x64 code is READ by the translator, and r-- pages read fine.  Native ARM64
 * code must be EXECUTED, so it dies on the first instruction.
 *
 * The repair below only ever ADDS execute to a range the PE's own section header already marks
 * IMAGE_SCN_MEM_EXECUTE, and only when the live protection lacks it -- so it cannot grant
 * execute to data.  Scope is deliberately asymmetric:
 *   - the PROBE runs for every needs_native_entry module (win32u/kernelbase/user32 included),
 *     because their protections are the control this lane never measured;
 *   - the REPAIR is applied to winemac.drv ONLY.  win32u/user32/kernelbase have working native
 *     entries today, and "an offline proof that a mechanism is wrong is not a proof that
 *     changing it is safe" has already cost this project two guest regressions.
 * Opt out with MACRUNNER_HB_NATIVE_ENTRY_MKEXEC=0.
 */
static BOOL macrunner_hb_native_entry_mkexec_enabled(void)
{
    WCHAR value[8] = {0};

    /* default ON: opt out with MACRUNNER_HB_NATIVE_ENTRY_MKEXEC=0 */
    if (!get_env( L"MACRUNNER_HB_NATIVE_ENTRY_MKEXEC", value, sizeof(value) )) return TRUE;
    return value[0] != '0';
}

static void macrunner_hb_make_native_entry_executable( WINE_MODREF *wm, DLLENTRYPROC entry )
{
    MEMORY_BASIC_INFORMATION info;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sec;
    SIZE_T info_len = 0, size;
    ULONG_PTR target = (ULONG_PTR)entry;
    ULONG old_prot = 0;
    void *base;
    unsigned int i;
    BOOL is_winemac, sect_exec = FALSE, repaired = FALSE;
    NTSTATUS status;

    if (!wm || !entry || !wm->ldr.DllBase) return;
    if (!(nt = RtlImageNtHeader( wm->ldr.DllBase ))) return;

    is_winemac = wm->ldr.BaseDllName.Buffer &&
                 !wcsicmp( wm->ldr.BaseDllName.Buffer, L"winemac.drv" );

    /* which section holds the entry, and does the PE itself call it executable */
    sec = IMAGE_FIRST_SECTION( nt );
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (!macrunner_hb_section_contains_target( wm->ldr.DllBase, sec, target )) continue;
        sect_exec = (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        break;
    }

    if (NtQueryVirtualMemory( NtCurrentProcess(), (void *)target, MemoryBasicInformation,
                              &info, sizeof(info), &info_len ))
        return;

    if (sect_exec && is_winemac && macrunner_hb_native_entry_mkexec_enabled() &&
        !(info.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                          PAGE_EXECUTE_WRITECOPY)))
    {
        base = info.BaseAddress;
        size = info.RegionSize;
        status = NtProtectVirtualMemory( NtCurrentProcess(), &base, &size,
                                         PAGE_EXECUTE_READ, &old_prot );
        repaired = !status;
        MESSAGE( "macrunner-hb-native-entry-mkexec: module=%s entry=%p region=%p size=%p "
                 "old_prot=%lx status=%lx repaired=%u\n",
                 debugstr_w(wm->ldr.BaseDllName.Buffer), entry, base, (void *)size,
                 (ULONG)old_prot, (ULONG)status, repaired );
    }

    /* UNGATED probe, every needs_native_entry module.  Prints AFTER any repair so the value is
     * the protection the entry is actually called with -- the number that decides whether a
     * SIGILL at the first instruction is even possible. */
    MESSAGE( "macrunner-hb-native-entry-prot: module=%s entry=%p prot=%lx state=%lx "
             "sect_exec=%u repaired=%u\n",
             debugstr_w(wm->ldr.BaseDllName.Buffer), entry,
             (ULONG)(repaired ? PAGE_EXECUTE_READ : info.Protect), (ULONG)info.State,
             sect_exec, repaired );
}

/* ★★★★★★★ 04.09.2026 — ОБЕ ТОЧКИ ВХОДА ARM64X ЧИТАЮТСЯ ИЗ ОТОБРАЖЁННОГО ОБРАЗА.
 *
 * ЧТО БЫЛО. macrunner_hb_find_disk_native_entry() открывала файл модуля и читала его
 * ЦЕЛИКОМ в кучу (до 64 МБ; у нас kernelbase.dll — 8 548 352 Б, user32.dll — 8 570 880,
 * ucrtbase.dll — 6 973 952, win32u.dll — 1 143 808), чтобы достать ЧЕТЫРЕ БАЙТА. Довод в
 * комментарии был такой: «в памяти лежит вид EC, и его AlternateEntryPoint сам перевёрнут
 * исправлениями ARM64X на точку входа EC, поэтому читать надо с диска».
 *
 * ЭТОТ ДОВОД НЕВЕРЕН, и это измерено, а не рассуждение. Разбор настоящей таблицы
 * исправлений (tools/arm64x/razbor_arm64x.py) на ВСЕХ 590 собранных образах ARM64X дерева:
 *   вид EC: CHPE.AlternateEntryPoint == дисковый OptionalHeader.AddressOfEntryPoint
 *           590 из 590, расхождений 0        (то есть в памяти лежит НАТИВНАЯ точка входа);
 *   вид EC: AddressOfEntryPoint лежит в .hexpthk
 *           590 из 590                        (то есть в памяти лежит ПЕРЕХОДНИК);
 *   перенаправление .a64xrm [Source == EC-шная AEP].Destination
 *           == дисковый CHPE.AlternateEntryPoint, 590 из 590 (то есть тело EC тоже в памяти);
 *   таблица перенаправлений отсортирована по Source: 590 из 590, 68 251 запись
 *           (двоичный поиск в macrunner_hb_redirect_arm64x_thunk_to_native применим).
 * kernelbase.dll: диск AEP 0x76694 -> вид EC 0xe7000 (.hexpthk);
 *                 диск Alternate 0xdf470 -> вид EC 0x76694 (.text, нативная).
 *
 * ЦЕНА СТАРОГО ПУТИ БЫЛА НЕ РАЗОВОЙ. Вызов стоит в MODULE_InitDLL БЕЗ проверки reason,
 * то есть срабатывает и на DLL_THREAD_ATTACH/DETACH: комментарий выше в этом же файле
 * сам считает, что за +117 с набирается 45 уведомлений, 43 из них THREAD_*, и что HK
 * создаёт больше сотни потоков. Каждое такое уведомление по разрешённому списку
 * (win32u, kernelbase, user32, ucrtbase, winemac.drv) означало NtOpenFile + чтение всего
 * файла + RtlAllocateHeap на его размер.
 *
 * Заодно снята дыра, которую прежний комментарий сам же и называл ловушкой: диск читался
 * по FullDllName, и если там лежала чисто-AMD64 сборка, путь молча отдавал NULL. Теперь
 * читается ТОТ ОБРАЗ, КОТОРЫЙ ИСПОЛНЯЕТСЯ.
 *
 * Сторож на случай, если раскладка образов однажды изменится:
 * tools/arm64x/sverka_arm64x.py (инварианты И2/И3/И4) + tests/test_arm64x_locale_mirror.py.
 * У сверки есть ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: --испортить значение|дельта|размер. */
static DLLENTRYPROC macrunner_hb_arm64x_entry_from_view( WINE_MODREF *wm, const char *skip_section )
{
    IMAGE_ARM64EC_METADATA *metadata;
    IMAGE_NT_HEADERS *nt;
    ULONG_PTR base, entry;
    ULONG native_rva, ec_rva = 0, rva;

    if (!wm || !(nt = RtlImageNtHeader( wm->ldr.DllBase ))) return NULL;
    if (!(metadata = macrunner_hb_get_arm64x_metadata( wm->ldr.DllBase ))) return NULL;

    base = (ULONG_PTR)wm->ldr.DllBase;
    if (nt->OptionalHeader.SizeOfImage > ~(ULONG_PTR)0 - base) return NULL;

    /* Нативное тело ARM64: в виде EC его RVA лежит в CHPE.AlternateEntryPoint. */
    native_rva = metadata->AlternateEntryPoint;

    /* Тело ARM64EC: точка входа вида EC — переходник .hexpthk, а таблица перенаправлений
     * образа переводит переходник в тело. Отдельного чтения файла для этого не нужно. */
    if (nt->OptionalHeader.AddressOfEntryPoint)
    {
        void *thunk = (void *)(base + nt->OptionalHeader.AddressOfEntryPoint);
        void *body = macrunner_hb_redirect_arm64x_thunk_to_native( wm->ldr.DllBase, thunk );

        if (body != thunk && (ULONG_PTR)body >= base &&
            (ULONG_PTR)body - base < nt->OptionalHeader.SizeOfImage)
            ec_rva = (ULONG)((ULONG_PTR)body - base);
    }

    /* Тот же выбор, что делал дисковый путь: winemac.drv — нативное тело, остальные — EC. */
    rva = (macrunner_hb_prefer_native_view_aep( wm ) && native_rva) ? native_rva
                                                                   : (ec_rva ? ec_rva : native_rva);

    /* UNGATED, winemac.drv only. Печатает ОБА кандидата И выбор — три исхода («нативное
     * тело», «тело EC», «сюда не дошли») этот лейн уже путал.
     *
     * ★ 05.09.2026 — ПЕЧАТЬ ОДИН РАЗ. С 05.09 эту функцию спрашивает ещё и
     * `macrunner_hb_module_live_half_is_ec`, то есть КАЖДОЕ разрешение импорта (в пробе x64 —
     * 835 раз за процесс). Выбор от вызова к вызову не меняется, а строка на каждый вызов
     * превращает прибор в шум, который уже однажды уничтожал измерение (итерация 1193). */
    if (wm->ldr.BaseDllName.Buffer && !wcsicmp( wm->ldr.BaseDllName.Buffer, L"winemac.drv" ))
    {
        static unsigned int pick_printed;

        if (!pick_printed)
        {
            pick_printed = 1;
            MESSAGE( "macrunner-hb-winemac-entrypick: prefer_aep=%u native=%x ec=%x chosen=%x\n",
                     (unsigned int)macrunner_hb_prefer_native_view_aep( wm ),
                     (unsigned int)native_rva, (unsigned int)ec_rva, (unsigned int)rva );
        }
    }

    if (!rva || rva >= nt->OptionalHeader.SizeOfImage) return NULL;
    entry = base + rva;
    if (skip_section && macrunner_hb_address_in_section( wm->ldr.DllBase, skip_section, entry ))
        return NULL;
    return (DLLENTRYPROC)entry;
}

static DLLENTRYPROC macrunner_hb_get_native_arm64x_entry( WINE_MODREF *wm )
{
    IMAGE_NT_HEADERS *nt;
    ULONG_PTR entry, base;

    if (!wm || !(wm->ldr.Flags & LDR_WINE_INTERNAL)) return NULL;
    if (current_machine != IMAGE_FILE_MACHINE_ARM64) return NULL;
    if (!(nt = RtlImageNtHeader( wm->ldr.DllBase ))) return NULL;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return NULL;
    if ((entry = (ULONG_PTR)macrunner_hb_arm64x_entry_from_view( wm, ".hexpthk" )))
        return (DLLENTRYPROC)entry;
    if (!macrunner_hb_get_arm64x_metadata( wm->ldr.DllBase )) return NULL;
    if (!nt->OptionalHeader.AddressOfEntryPoint) return NULL;

    base = (ULONG_PTR)wm->ldr.DllBase;
    if (nt->OptionalHeader.SizeOfImage > ~(ULONG_PTR)0 - base ||
        nt->OptionalHeader.AddressOfEntryPoint >= nt->OptionalHeader.SizeOfImage ||
        base > ~(ULONG_PTR)0 - nt->OptionalHeader.AddressOfEntryPoint)
        return NULL;
    entry = base + nt->OptionalHeader.AddressOfEntryPoint;
    if (macrunner_hb_address_in_section( wm->ldr.DllBase, ".hexpthk", entry )) return NULL;
    return (DLLENTRYPROC)entry;
}

static void macrunner_hb_sync_syscall_dispatcher_aliases( WINE_MODREF *optional_win32u )
{
    static const char dispatcher_name[] = "__wine_syscall_dispatcher";
    WCHAR ntdllW[] = {'n','t','d','l','l','.','d','l','l',0};
    WINE_MODREF *ntdll_mod;
    void *dispatcher;
    unsigned int ntdll_count = 0, win32u_count = 0;

    if (!(ntdll_mod = find_basename_module_machine( ntdllW, current_machine ))) return;

    dispatcher = macrunner_hb_find_disk_symbol_pointer_value( ntdll_mod, dispatcher_name );
    if (!dispatcher) dispatcher = __wine_syscall_dispatcher;
    if (!dispatcher)
    {
        MESSAGE( "MacRunner HyperBridge cannot sync win32u syscall dispatcher: ntdll dispatcher is null\n" );
        return;
    }

    /*
     * ARM64X binaries carry multiple COFF symbol views for this data slot.
     * The native win32u syscall stub reads the ARM64 view, while generic PE
     * export lookup can see the EC/x64 view.  Keep every alias consistent so
     * native user32->win32u calls reach the real Wine syscall dispatcher.
     */
    ntdll_count = macrunner_hb_sync_disk_symbol_pointer_aliases( ntdll_mod, dispatcher_name, dispatcher );
    if (optional_win32u && !wcsicmp( optional_win32u->ldr.BaseDllName.Buffer, L"win32u.dll" ))
        win32u_count = macrunner_hb_sync_disk_symbol_pointer_aliases( optional_win32u, dispatcher_name, dispatcher );
    MESSAGE( "MacRunner HyperBridge synced syscall dispatcher aliases dispatcher=%p ntdll=%u win32u=%u\n",
           dispatcher, ntdll_count, win32u_count );
}

static void macrunner_hb_sync_win32u_syscall_dispatcher_aliases( WINE_MODREF *win32u )
{
    if (!win32u || wcsicmp( win32u->ldr.BaseDllName.Buffer, L"win32u.dll" )) return;
    macrunner_hb_sync_syscall_dispatcher_aliases( win32u );
}

static const WCHAR *macrunner_hb_builtin_machine_dir( WORD machine )
{
    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:  return L"\\i386-windows";
    case IMAGE_FILE_MACHINE_AMD64: return L"\\x86_64-windows";
    case IMAGE_FILE_MACHINE_ARM64: return L"\\aarch64-windows";
    default: return NULL;
    }
}

static const WCHAR *macrunner_hb_builtin_machine_slash_dir( WORD machine )
{
    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:  return L"/i386-windows";
    case IMAGE_FILE_MACHINE_AMD64: return L"/x86_64-windows";
    case IMAGE_FILE_MACHINE_ARM64: return L"/aarch64-windows";
    default: return NULL;
    }
}

static BOOL macrunner_hb_is_dxmt_graphics_frontend( const WCHAR *name );

static WCHAR *macrunner_hb_build_builtin_path_for_machine( const WCHAR *name, WORD machine )
{
    WCHAR dllpath[32];
    UNICODE_STRING path;
    const WCHAR *machine_dir, *machine_slash_dir;
    const WCHAR *seg, *end, *p;
    WCHAR *ret, sep;
    SIZE_T seg_len, name_len, total;
    DWORD i;

    if (!name) return NULL;
    if (!(machine_dir = macrunner_hb_builtin_machine_dir( machine ))) return NULL;
    if (!(machine_slash_dir = macrunner_hb_builtin_machine_slash_dir( machine ))) return NULL;

    /* MacRunner Fix-A mirror (PE side): for the 4 DXMT/DXVK graphics frontends,
     * resolve the builtin from the MACRUNNER_DXMT_ROOT overlay FIRST (before the
     * system_dll_path scan), so a dependency load (e.g. DXMT d3d11 -> dxgi) commits
     * DXMT's ARM64X twin from the overlay instead of wine's pure-ARM64 dxgi (which
     * -> wined3d -> NULL on macOS). Strictly gated on the 4 graphics names +
     * MACRUNNER_DXMT_ROOT set; the overlay deploys all 4 for both arches, so a
     * missing-file early-return can't strand a non-graphics builtin. machine_dir
     * already carries a leading '\\' (e.g. "\\aarch64-windows"). */
    if (macrunner_hb_is_dxmt_graphics_frontend( name ))
    {
        WCHAR root[800];
        if (get_env( L"MACRUNNER_DXMT_ROOT", root, sizeof(root) ) && root[0])
        {
            SIZE_T rl = wcslen( root ), ml = wcslen( machine_dir ), nl = wcslen( name );
            WCHAR *ov = RtlAllocateHeap( GetProcessHeap(), 0, (rl + ml + nl + 8) * sizeof(WCHAR) );
            if (ov)
            {
                SIZE_T j = 0; DWORD k;
                ov[j++] = 'Z'; ov[j++] = ':';
                for (k = 0; k < rl; k++) ov[j++] = (root[k] == '/') ? '\\' : root[k];
                memcpy( ov + j, machine_dir, ml * sizeof(WCHAR) ); j += ml;
                ov[j++] = '\\';
                memcpy( ov + j, name, (nl + 1) * sizeof(WCHAR) );
                MESSAGE( "MacRunner HyperBridge DXMT overlay builtin path %s => %s\n",
                       debugstr_w(name), debugstr_w(ov) );
                return ov;
            }
        }
    }

    if (system_dll_path.Buffer)
    {
        name_len = wcslen( name );
        for (seg = system_dll_path.Buffer; *seg; seg = *end ? end + 1 : end)
        {
            end = seg;
            while (*end && *end != ';') end++;
            seg_len = end - seg;
            if (!seg_len) continue;
            if (!wcsstr( seg, machine_dir ) && !wcsstr( seg, machine_slash_dir )) continue;

            sep = '\\';
            for (p = seg; p < end; p++)
            {
                if (*p == '/')
                {
                    sep = '/';
                    break;
                }
            }
            total = seg_len + 1 + name_len;
            if (!(ret = RtlAllocateHeap( GetProcessHeap(), 0, (total + 1) * sizeof(WCHAR) )))
                return NULL;
            memcpy( ret, seg, seg_len * sizeof(WCHAR) );
            if (ret[seg_len - 1] != '\\' && ret[seg_len - 1] != '/') ret[seg_len++] = sep;
            memcpy( ret + seg_len, name, (name_len + 1) * sizeof(WCHAR) );
            return ret;
        }
    }

    for (i = 0; ; i++)
    {
        swprintf( dllpath, ARRAY_SIZE(dllpath), L"WINEDLLDIR%u", i );
        if (get_env_var( dllpath, wcslen(machine_dir) + wcslen(name) + 2, &path )) break;
        RtlAppendUnicodeToString( &path, machine_dir );
        RtlAppendUnicodeToString( &path, L"\\" );
        RtlAppendUnicodeToString( &path, name );
        return path.Buffer;
    }
    MESSAGE( "MacRunner HyperBridge could not build builtin path for %s machine=%04x\n",
           debugstr_w(name), machine );
    return NULL;
}

static WCHAR *macrunner_hb_build_native_builtin_path( const WCHAR *name )
{
    return macrunner_hb_build_builtin_path_for_machine( name, current_machine );
}

static NTSTATUS macrunner_hb_open_native_builtin_dependency( const WCHAR *libname, UNICODE_STRING *nt_name,
                                                            WINE_MODREF **pwm, HANDLE *mapping,
                                                            SECTION_IMAGE_INFORMATION *image_info,
                                                            struct file_id *id )
{
    const WCHAR *basename;
    WCHAR *native_path;
    NTSTATUS status;
    WORD target_machine, prev_native_counterpart_machine;

    if (!(basename = macrunner_hb_basename_from_path( libname )) || !*basename)
        return STATUS_DLL_NOT_FOUND;
    if (!(target_machine = macrunner_hb_builtin_dependency_machine())) return STATUS_DLL_NOT_FOUND;

    if (current_machine == IMAGE_FILE_MACHINE_ARM64 &&
        target_machine == IMAGE_FILE_MACHINE_I386 &&
        macrunner_hb_is_wow64_bootstrap_host_module( basename ))
        target_machine = IMAGE_FILE_MACHINE_ARM64;

    if (!(native_path = macrunner_hb_build_builtin_path_for_machine( basename, target_machine )))
        return STATUS_DLL_NOT_FOUND;

    status = RtlDosPathNameToNtPathName_U_WithStatus( native_path, nt_name, NULL, NULL );
    if (!status)
    {
        prev_native_counterpart_machine = macrunner_hb_native_counterpart_machine;
        macrunner_hb_native_counterpart_machine = target_machine;
        status = open_dll_file( nt_name, pwm, mapping, image_info, id );
        macrunner_hb_native_counterpart_machine = prev_native_counterpart_machine;
        if (status == STATUS_SUCCESS)
        {
            MESSAGE( "MacRunner HyperBridge builtin dependency %s => %s machine=%04x\n",
                   debugstr_w(libname), debugstr_w(native_path), target_machine );
            RtlFreeHeap( GetProcessHeap(), 0, native_path );
            return STATUS_SUCCESS;
        }
        MESSAGE( "MacRunner HyperBridge builtin dependency rejected %s => %s machine=%04x status=%lx\n",
               debugstr_w(libname), debugstr_w(native_path), target_machine, status );
        RtlFreeUnicodeString( nt_name );
        nt_name->Buffer = NULL;
    }
    RtlFreeHeap( GetProcessHeap(), 0, native_path );
    return status;
}

static BOOL macrunner_hb_is_dxmt_graphics_frontend( const WCHAR *name )
{
    return name && (!wcsicmp( name, L"d3d11.dll" ) || !wcsicmp( name, L"dxgi.dll" ) ||
                    !wcsicmp( name, L"d3d10core.dll" ) || !wcsicmp( name, L"d3d9.dll" ));
}

/* MacRunner option-2 (operator-chosen): route the x64 guest's d3d11/dxgi/d3d10core/d3d9 import to DXMT's
 * x86_64-windows frontend (JIT-executed) instead of swapping to a native ARM64 counterpart. DXMT ships only
 * plain-ARM64 aarch64 twins (no .hexpthk/.a64xrm), so the ARM64EC loader prefers wine's ARM64X dxgi as the
 * companion -> wined3d -> NULL device on macOS. Skipping the native-counterpart swap for these 4 names keeps
 * the x64 DXMT dxgi (D3D11->Metal) bound; its heavy Metal work lives in winemetal.so (native, via unixcall),
 * so only the dxgi frontend logic is JIT'd. Gated by MACRUNNER_HB_DXMT_X64_FRONTEND -> reversible. */
static BOOL macrunner_hb_dxmt_x64_frontend_enabled(void)
{
    WCHAR value[8] = {0};

    return get_env( L"MACRUNNER_HB_DXMT_X64_FRONTEND", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

static WINE_MODREF *macrunner_hb_load_native_counterpart_module( WINE_MODREF *target_mod )
{
    static const WCHAR x64_dir[] = L"\\x86_64-windows\\";
    static const WCHAR arm64_dir[] = L"\\aarch64-windows\\";
    const WCHAR *full, *match;
    UNICODE_STRING native_name;
    WINE_MODREF *native_mod = NULL;
    IMAGE_NT_HEADERS *native_nt;
    SIZE_T prefix_len, suffix_len, native_len;
    WCHAR *native_path;
    NTSTATUS status;
    WORD prev_native_counterpart_machine;

    if (!target_mod || !target_mod->ldr.FullDllName.Buffer) return NULL;
    if (current_machine != IMAGE_FILE_MACHINE_ARM64) return NULL;

    full = target_mod->ldr.FullDllName.Buffer;
    if (!(match = wcsstr( full, x64_dir )))
    {
        /* MacRunner option-2: skip the native-counterpart swap for DXMT graphics frontends so the x64
         * guest keeps DXMT's x86_64 dxgi (JIT->Metal) instead of wine's ARM64X dxgi (->wined3d->NULL). */
        if (macrunner_hb_dxmt_x64_frontend_enabled() &&
            macrunner_hb_is_dxmt_graphics_frontend( target_mod->ldr.BaseDllName.Buffer ))
            return NULL;

        /* MacRunner EDIT 2: for DXMT graphics frontends, skip the already-loaded
         * find_basename match (it is current-machine/ARM64-keyed -> misses DXMT's
         * ARM64X twin whose FileHeader.Machine is flipped to AMD64 by the EC-view
         * update_arm64x_mapping, and can wrongly match wine's pure-ARM64 dxgi).
         * Go straight to the builtin path, which now routes to the DXMT overlay. */
        if (!macrunner_hb_is_dxmt_graphics_frontend( target_mod->ldr.BaseDllName.Buffer ) &&
            (native_mod = find_basename_module_machine( target_mod->ldr.BaseDllName.Buffer, current_machine )))
            return native_mod;

        if ((native_path = macrunner_hb_build_native_builtin_path( target_mod->ldr.BaseDllName.Buffer )))
        {
            prev_native_counterpart_machine = macrunner_hb_native_counterpart_machine;
            macrunner_hb_native_counterpart_machine = current_machine;
            status = load_dll( NULL, native_path, 0, &native_mod, FALSE );
            macrunner_hb_native_counterpart_machine = prev_native_counterpart_machine;
            native_nt = native_mod ? RtlImageNtHeader( native_mod->ldr.DllBase ) : NULL;
            if (!status && native_nt && (native_nt->FileHeader.Machine == current_machine ||
                                         macrunner_hb_get_arm64x_metadata( native_mod->ldr.DllBase )))
            {
                MESSAGE( "MacRunner HyperBridge native counterpart module fallback %s => %s at %p\n",
                       debugstr_w(target_mod->ldr.BaseDllName.Buffer), debugstr_w(native_path),
                       native_mod->ldr.DllBase );
                RtlFreeHeap( GetProcessHeap(), 0, native_path );
                return native_mod;
            }
            MESSAGE( "MacRunner HyperBridge native counterpart module fallback failed %s => %s status=%lx\n",
                   debugstr_w(target_mod->ldr.BaseDllName.Buffer), debugstr_w(native_path), status );
            RtlFreeHeap( GetProcessHeap(), 0, native_path );
        }
        return NULL;
    }
    prefix_len = match - full;
    suffix_len = wcslen( match + ARRAY_SIZE(x64_dir) - 1 );
    native_len = prefix_len + ARRAY_SIZE(arm64_dir) - 1 + suffix_len;
    if (!(native_path = RtlAllocateHeap( GetProcessHeap(), 0, (native_len + 1) * sizeof(WCHAR) )))
        return NULL;

    memcpy( native_path, full, prefix_len * sizeof(WCHAR) );
    memcpy( native_path + prefix_len, arm64_dir, (ARRAY_SIZE(arm64_dir) - 1) * sizeof(WCHAR) );
    memcpy( native_path + prefix_len + ARRAY_SIZE(arm64_dir) - 1,
            match + ARRAY_SIZE(x64_dir) - 1, (suffix_len + 1) * sizeof(WCHAR) );
    RtlInitUnicodeString( &native_name, native_path );

    if (!(native_mod = find_fullname_module( &native_name )))
    {
        prev_native_counterpart_machine = macrunner_hb_native_counterpart_machine;
        macrunner_hb_native_counterpart_machine = current_machine;
        status = load_dll( NULL, native_path, 0, &native_mod, FALSE );
        macrunner_hb_native_counterpart_machine = prev_native_counterpart_machine;
        if (status)
        {
            MESSAGE( "MacRunner HyperBridge native counterpart module load failed %s => %s status=%lx\n",
                   debugstr_w(full), debugstr_w(native_path), status );
            native_mod = NULL;
            goto done;
        }
    }

    if (!(native_nt = RtlImageNtHeader( native_mod->ldr.DllBase )))
    {
        MESSAGE( "MacRunner HyperBridge native counterpart module rejected %s: missing NT header\n",
               debugstr_w(native_path) );
        native_mod = NULL;
        goto done;
    }
    if (native_nt->FileHeader.Machine != current_machine &&
        !macrunner_hb_get_arm64x_metadata( native_mod->ldr.DllBase ))
    {
        MESSAGE( "MacRunner HyperBridge native counterpart module rejected %s machine=%04x\n",
               debugstr_w(native_path), native_nt->FileHeader.Machine );
        native_mod = NULL;
        goto done;
    }

done:
    RtlFreeHeap( GetProcessHeap(), 0, native_path );
    return native_mod;
}

/* MacRunner 2026-07-29 (HK DllMain lane) -- the LOAD-step route out of the winemac.drv skip.
 *
 * Measured, in HK's own process (wine pid 0020), and it is a mechanism, not a protection quirk:
 * the native aarch64 twins are loaded as a SIDE EFFECT OF IMPORT RESOLUTION.  import_dll()
 * computes force_native_imports (loader.c, "macrunner_hb_importer_is_native_wine_builtin") and
 * calls macrunner_hb_load_native_counterpart_module() on each import of a native wine builtin.
 * That is why 37 builtins load twice in HK and winemac.drv does not: **winemac.drv is imported
 * by nobody.**  It is a display driver, reached only through an explicit LdrLoadDll issued by
 * User32LoadDriver.  Never being an import, it never enters the twin path -- so HK holds only
 * its pure-AMD64 system32 copy, whose DllMain MODULE_InitDLL then skips by design.
 *
 * Both earlier routes attacked the ENTRY of that guest-only copy and both failed for reasons
 * that follow from this same fact:
 *   - x64 entry (MACRUNNER_HB_WINEMAC_X64_DLLMAIN): DllMain runs, then wedges in the HyperBridge
 *     fault router on a native PE import -- forbidden territory, unfixable from this lane;
 *   - native entry (MACRUNNER_HB_WINEMAC_NATIVE_DLLMAIN + prefix swap): the resolved entry sits
 *     in a hand-copied, non-executable image (vmmap: winemac.drv's 3 regions are the ONLY SM=ZER
 *     regions in HK's 306-region PE band; SM=ZER implies non-executable 18/18 across two
 *     processes, and all 38 executable regions are file-backed SM=COW), so it SIGILLs on its
 *     first instruction and lands in that same router.
 *
 * This gate does neither.  It gives winemac.drv the one thing the other 37 builtins have: its
 * aarch64-windows twin, loaded through the SAME proven helper, then attached the same way
 * find_forwarded_export() attaches a dynamically loaded forwarder (load_dll + process_attach).
 * The twin's FileHeader.Machine is aa64, so MODULE_InitDLL's amd64-main-on-arm64 block is not
 * entered for it at all -- no skip, no native-entry lookup, no x64 entry, no fault router.  Its
 * DllMain runs as ordinary native code, exactly as it already does in the aarch64 explorer
 * process (pid 005c) where dllmain_attach + macdrv_init_entry are measured every run.
 *
 * The guest copy is left in place and untouched: this ADDS a module, it does not substitute one,
 * so nothing that already resolved against the system32 copy changes.
 *
 * Default OFF.  It runs inside the KeUserModeCallback that load_display_driver issues, and the
 * boot it would alter currently works -- HK gets its real driver at ~+141 s via the unix-side
 * macdrv_process_selfinit.  Trading that for an untested load in a nested callback is exactly
 * the move that has already cost this project two guest regressions.  Opt IN with
 * MACRUNNER_HB_WINEMAC_TWIN_ATTACH=1.  The probe below is UNGATED, so a run log always reports
 * whether the twin was attempted and what happened -- "the gate was off" and "the gate did
 * nothing" can never produce the same log. */
static BOOL macrunner_hb_winemac_twin_attach_enabled(void)
{
    WCHAR value[8] = {0};

    return get_env( L"MACRUNNER_HB_WINEMAC_TWIN_ATTACH", value, sizeof(value) ) &&
           value[0] && value[0] != '0';
}

static void macrunner_hb_attach_winemac_native_twin( WINE_MODREF *wm )
{
    WINE_MODREF *native_mod;
    IMAGE_NT_HEADERS *nt;
    NTSTATUS status = STATUS_DLL_NOT_FOUND;
    void *twin_base = NULL;
    BOOL enabled;

    if (!wm || !wm->ldr.BaseDllName.Buffer || !wm->ldr.DllBase) return;
    if (wcsicmp( wm->ldr.BaseDllName.Buffer, L"winemac.drv" )) return;
    if (!macrunner_hb_amd64_main_on_arm64) return;
    if (current_machine != IMAGE_FILE_MACHINE_ARM64) return;

    /* Only the guest (AMD64-view) copy needs a twin.  If this modref is already the native
     * view -- the aarch64 explorer-class process, or the twin we ourselves just loaded --
     * there is nothing to add, and recursing here would be a load loop. */
    if (!(nt = RtlImageNtHeader( wm->ldr.DllBase ))) return;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return;

    enabled = macrunner_hb_winemac_twin_attach_enabled();
    if (enabled && (native_mod = macrunner_hb_load_native_counterpart_module( wm )))
    {
        /* Same shape as find_forwarded_export()'s dynamic-forwarder attach: the twin is
         * nobody's import, so no enclosing process_attach walk will ever reach it. */
        twin_base = native_mod->ldr.DllBase;
        status = process_attach( native_mod->ldr.DdagNode, NULL );
        /* Read the base BEFORE unloading -- LdrUnloadDll can free the modref, so reporting
         * native_mod->ldr.DllBase afterwards would be a use-after-free on the error path. */
        if (status != STATUS_SUCCESS) LdrUnloadDll( twin_base );
    }

    MESSAGE( "macrunner-hb-winemac-twin-attach: gate=%u guest_base=%p twin=%p status=%08lx\n",
             enabled, wm->ldr.DllBase, twin_base, (ULONG)status );
}

static void *macrunner_hb_find_native_counterpart_export( WINE_MODREF *target_mod, const char *import_name,
                                                          WINE_MODREF **native_mod_out )
{
    static const WCHAR x64_dir[] = L"\\x86_64-windows\\";
    static const WCHAR arm64_dir[] = L"\\aarch64-windows\\";
    const WCHAR *full, *match;
    UNICODE_STRING native_name;
    WINE_MODREF *native_mod = NULL;
    IMAGE_NT_HEADERS *native_nt;
    SIZE_T prefix_len, suffix_len, native_len;
    WCHAR *native_path;
    NTSTATUS status;
    void *proc = NULL;
    WORD prev_native_counterpart_machine;

    if (native_mod_out) *native_mod_out = NULL;
    if (!target_mod || !target_mod->ldr.FullDllName.Buffer || !import_name) return NULL;
    if (current_machine != IMAGE_FILE_MACHINE_ARM64) return NULL;

    /* MacRunner option-2: for DXMT graphics frontends, don't resolve a native ARM64 export -> the import
     * binds to DXMT's x86_64 dxgi export (JIT->Metal) instead of wine's ARM64X dxgi (->wined3d->NULL). */
    if (macrunner_hb_dxmt_x64_frontend_enabled() &&
        macrunner_hb_is_dxmt_graphics_frontend( target_mod->ldr.BaseDllName.Buffer ))
    {
        static int o2n;
        if (o2n++ < 30)
            MESSAGE( "MacRunner opt2-gate find_export GFX: target=%s import=%s\n",
                 debugstr_w(target_mod->ldr.BaseDllName.Buffer), import_name );
        return NULL;
    }

    full = target_mod->ldr.FullDllName.Buffer;
    if (!(match = wcsstr( full, x64_dir )))
    {
        /* MacRunner EDIT 2 (mirror of load_native_counterpart_module): force the
         * builtin-path route for DXMT graphics frontends (skip the ARM64-keyed /
         * EC-view-blind find_basename match) so it resolves the DXMT overlay twin. */
        native_mod = macrunner_hb_is_dxmt_graphics_frontend( target_mod->ldr.BaseDllName.Buffer )
                     ? NULL : find_basename_module_machine( target_mod->ldr.BaseDllName.Buffer, current_machine );
        if (!native_mod)
        {
            if (!(native_path = macrunner_hb_build_native_builtin_path( target_mod->ldr.BaseDllName.Buffer )))
                return NULL;
            prev_native_counterpart_machine = macrunner_hb_native_counterpart_machine;
            macrunner_hb_native_counterpart_machine = current_machine;
            status = load_dll( NULL, native_path, 0, &native_mod, FALSE );
            macrunner_hb_native_counterpart_machine = prev_native_counterpart_machine;
            if (status)
            {
                MESSAGE( "MacRunner HyperBridge native counterpart fallback load failed %s => %s status=%lx\n",
                       debugstr_w(target_mod->ldr.BaseDllName.Buffer), debugstr_w(native_path), status );
                RtlFreeHeap( GetProcessHeap(), 0, native_path );
                return NULL;
            }
            RtlFreeHeap( GetProcessHeap(), 0, native_path );
        }
        if (!(native_nt = RtlImageNtHeader( native_mod->ldr.DllBase ))) return NULL;
        if (native_nt->FileHeader.Machine != current_machine &&
            !macrunner_hb_get_arm64x_metadata( native_mod->ldr.DllBase ))
            return NULL;
        proc = macrunner_hb_find_disk_export_outside_section( native_mod, import_name, ".hexpthk" );
        if (!proc)
            proc = macrunner_hb_find_export_outside_section( native_mod->ldr.DllBase, import_name, ".hexpthk" );
        if (proc)
        {
            MESSAGE( "MacRunner HyperBridge native counterpart fallback export %s!%s => %p from %s\n",
                   debugstr_w(target_mod->ldr.BaseDllName.Buffer), import_name, proc,
                   debugstr_w(native_mod->ldr.BaseDllName.Buffer) );
            if (native_mod_out) *native_mod_out = native_mod;
        }
        return proc;
    }
    prefix_len = match - full;
    suffix_len = wcslen( match + ARRAY_SIZE(x64_dir) - 1 );
    native_len = prefix_len + ARRAY_SIZE(arm64_dir) - 1 + suffix_len;
    if (!(native_path = RtlAllocateHeap( GetProcessHeap(), 0, (native_len + 1) * sizeof(WCHAR) )))
        return NULL;

    memcpy( native_path, full, prefix_len * sizeof(WCHAR) );
    memcpy( native_path + prefix_len, arm64_dir, (ARRAY_SIZE(arm64_dir) - 1) * sizeof(WCHAR) );
    memcpy( native_path + prefix_len + ARRAY_SIZE(arm64_dir) - 1,
            match + ARRAY_SIZE(x64_dir) - 1, (suffix_len + 1) * sizeof(WCHAR) );
    RtlInitUnicodeString( &native_name, native_path );

    if (!(native_mod = find_fullname_module( &native_name )))
    {
        prev_native_counterpart_machine = macrunner_hb_native_counterpart_machine;
        macrunner_hb_native_counterpart_machine = current_machine;
        status = load_dll( NULL, native_path, 0, &native_mod, FALSE );
        macrunner_hb_native_counterpart_machine = prev_native_counterpart_machine;
        if (status)
        {
            MESSAGE( "MacRunner HyperBridge native counterpart load failed %s => %s status=%lx\n",
                   debugstr_w(full), debugstr_w(native_path), status );
            goto done;
        }
    }
    if (!(native_nt = RtlImageNtHeader( native_mod->ldr.DllBase )))
    {
        MESSAGE( "MacRunner HyperBridge native counterpart rejected %s: missing NT header\n",
               debugstr_w(native_path) );
        goto done;
    }
    if (native_nt->FileHeader.Machine != current_machine &&
        !macrunner_hb_get_arm64x_metadata( native_mod->ldr.DllBase ))
    {
        MESSAGE( "MacRunner HyperBridge native counterpart rejected %s machine=%04x\n",
               debugstr_w(native_path), native_nt->FileHeader.Machine );
        goto done;
    }

    proc = macrunner_hb_find_disk_export_outside_section( native_mod, import_name, ".hexpthk" );
    if (!proc)
        proc = macrunner_hb_find_export_outside_section( native_mod->ldr.DllBase, import_name, ".hexpthk" );
    if (!proc)
    {
        void *live_proc = RtlFindExportedRoutineByName( native_mod->ldr.DllBase, import_name );

        if (live_proc)
        {
            proc = macrunner_hb_redirect_arm64x_thunk_to_native( native_mod->ldr.DllBase, live_proc );
            if (proc == live_proc &&
                macrunner_hb_address_in_section( native_mod->ldr.DllBase, ".hexpthk", (ULONG_PTR)proc ))
                proc = NULL;
        }
    }
    if (proc)
    {
        MESSAGE( "MacRunner HyperBridge native counterpart export %s!%s => %p from %s\n",
               debugstr_w(target_mod->ldr.BaseDllName.Buffer), import_name, proc, debugstr_w(native_path) );
        if (native_mod_out) *native_mod_out = native_mod;
    }

    if (import_name && native_mod &&
        (strstr( import_name, "CreateDXGIFactory" ) || strstr( import_name, "D3D11Create" ) ||
         strstr( import_name, "D3D11On12" )))
        MESSAGE( "macrunner-hb-counterpart: import=%s target_path=%s native_path=%s native_base=%p arm64x=%d proc=%p(rva 0x%llx)\n",
                 import_name, debugstr_w(target_mod->ldr.FullDllName.Buffer),
                 debugstr_w(native_mod->ldr.FullDllName.Buffer), native_mod->ldr.DllBase,
                 macrunner_hb_get_arm64x_metadata( native_mod->ldr.DllBase ) ? 1 : 0, proc,
                 (unsigned long long)(proc ? (ULONG_PTR)proc - (ULONG_PTR)native_mod->ldr.DllBase : 0) );

done:
    RtlFreeHeap( GetProcessHeap(), 0, native_path );
    return proc;
}

static ULONG_PTR macrunner_hb_maybe_register_import_thunk( WINE_MODREF *importer, WINE_MODREF *target_mod,
                                                           const char *dll_name, const char *import_name,
                                                           ULONG_PTR target )
{
    struct macrunner_hb_register_import_thunk_params params;
    IMAGE_NT_HEADERS *importer_nt, *target_nt;
    NTSTATUS status;
    BOOL native_thunk;
    BOOL native_counterpart = FALSE;
    BOOL semantic_stub = FALSE;
    ULONG_PTR thunk_target = 0;
    WCHAR trace_value[8] = {0};
    BOOL trace_iat = get_env( L"MACRUNNER_HB_TRACE_IAT", trace_value, sizeof(trace_value) ) &&
                     trace_value[0] && trace_value[0] != '0';

    if (!target || !importer || !target_mod || !dll_name || !import_name)
    {
        if (trace_iat) MESSAGE( "MacRunner HyperBridge IAT skip %s!%s: missing input\n",
                              dll_name ? dll_name : "?", import_name ? import_name : "?" );
        return target;
    }
    if (!macrunner_hb_x64_main_requested())
    {
        if (trace_iat) MESSAGE( "MacRunner HyperBridge IAT skip %s!%s: gate disabled\n", dll_name, import_name );
        return target;
    }
    semantic_stub = macrunner_hb_is_semantic_import_stub( dll_name, import_name );

    importer_nt = RtlImageNtHeader( importer->ldr.DllBase );
    target_nt = RtlImageNtHeader( target_mod->ldr.DllBase );
    if (import_name && (strstr( import_name, "CreateDXGIFactory" ) ||
                        strstr( import_name, "D3D11Create" ) || strstr( import_name, "D3D11On12" )))
        MESSAGE( "macrunner-hb-iatentry: %s!%s target=%p(rva 0x%llx) tmod=%s tbase=%p imach=%04x tmach=%04x flags=%lx\n",
                 dll_name, import_name, (void *)target,
                 (unsigned long long)(target - (ULONG_PTR)target_mod->ldr.DllBase),
                 debugstr_w(target_mod->ldr.BaseDllName.Buffer), target_mod->ldr.DllBase,
                 importer_nt ? importer_nt->FileHeader.Machine : 0,
                 target_nt ? target_nt->FileHeader.Machine : 0, target_mod->ldr.Flags );
    if (trace_iat)
        MESSAGE( "MacRunner HyperBridge IAT candidate %s!%s importer=%s imach=%04x target=%s tmach=%04x flags=%lx target=%p\n",
               dll_name, import_name, debugstr_w(importer->ldr.BaseDllName.Buffer),
               importer_nt ? importer_nt->FileHeader.Machine : 0,
               debugstr_w(target_mod->ldr.BaseDllName.Buffer),
               target_nt ? target_nt->FileHeader.Machine : 0, target_mod->ldr.Flags, (void *)target );
    if (!(target_mod->ldr.Flags & LDR_WINE_INTERNAL))
    {
        if (trace_iat) MESSAGE( "MacRunner HyperBridge IAT skip %s!%s: target is not Wine builtin\n",
                              dll_name, import_name );
        return target;
    }
    if (macrunner_hb_importer_is_native_wine_builtin( importer ))
    {
        if (trace_iat) MESSAGE( "MacRunner HyperBridge IAT skip %s!%s: importer %s is Wine builtin\n",
                              dll_name, import_name, debugstr_w(importer->ldr.BaseDllName.Buffer) );
        return target;
    }
    if (!importer_nt || !target_nt) return target;
    /* MacRunner 2026-08-17, лейн ЛЕСТНИЦА, итерация 1351 — ОБРАЗ ARM64EC СЮДА НЕ ДОХОДИЛ ВОВСЕ.
     *
     * Проверка пропускала только `AMD64`, а наш гостевой образ ARM64EC несёт в заголовке
     * `IMAGE_FILE_MACHINE_ARM64EC` (0xA641) — измерено `llvm-readobj` по самому файлу пробы.
     * Значит весь путь исправления нативных переходников для EC-гостя не выполнялся НИ РАЗУ,
     * и трасса 1350 (`redir=0`, `final=` нативная половина) — это следы связей встроенных
     * модулей между собой, а не гостя.
     *
     * Пропускаем ARM64EC ТОЛЬКО при зажжённом гейте: без него условие прежнее до буквы. */
    if (importer_nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
        !(importer_nt->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64EC &&
          macrunner_hb_import_prefer_arm64ec_guest_enabled()))
        return target;
    native_thunk = (target_nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
                    target_nt->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64X ||
                    target_nt->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64EC) &&
                   macrunner_hb_target_is_native_thunk_or_mid( target_mod, target, &thunk_target );
    if (import_name && (strstr( import_name, "D3D11Create" ) || strstr( import_name, "D3D11On12" ) ||
                        strstr( import_name, "CreateDXGIFactory" )))
        MESSAGE( "macrunner-hb-cpdecision: import=%s native_thunk=%d tmach=0x%x cur=0x%x tpath=%s\n",
                 import_name, native_thunk, target_nt->FileHeader.Machine, current_machine,
                 debugstr_w(target_mod->ldr.FullDllName.Buffer) );
    if (semantic_stub && trace_iat)
        MESSAGE( "MacRunner HyperBridge IAT semantic stub %s!%s target=%p\n",
               dll_name, import_name, (void *)target );
    if (native_thunk)
    {
        /* Избирательно (итерация 1349): EC-половину предпочитаем ТОЛЬКО когда импортирует
         * гостевой образ ARM64EC. Признак — метаданные CHPE: у настоящего x86-64 их нет,
         * у ARM64EC есть, хотя `Machine` у обоих `AMD64`. */
        BOOL prefer_ec = macrunner_hb_import_prefer_arm64ec_guest_enabled() &&
                         importer_nt->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64EC;
        void *native_target = macrunner_hb_find_native_target_for_thunk_import( target_mod, import_name,
                                                                               thunk_target, prefer_ec, importer );

        if (!native_target || native_target == (void *)target)
        {
            MESSAGE( "MacRunner HyperBridge refusing unsafe native import thunk %s!%s target=%p: "
                  "ARM64X redirection not found\n", dll_name, import_name, (void *)target );
            return target;
        }
        MESSAGE( "MacRunner HyperBridge native import thunk %s!%s redirected %p -> %p\n",
               dll_name, import_name, (void *)target, native_target );
        target = (ULONG_PTR)native_target;
    }
    else if (target_nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
             current_machine == IMAGE_FILE_MACHINE_ARM64)
    {
        WINE_MODREF *native_mod = NULL;
        void *native_target = macrunner_hb_find_native_counterpart_export( target_mod, import_name, &native_mod );

        if (import_name && (strstr( import_name, "D3D11Create" ) || strstr( import_name, "D3D11On12" ) ||
                            strstr( import_name, "CreateDXGIFactory" )))
            MESSAGE( "macrunner-hb-cpresult: import=%s native_target=%p native_mod=%s\n",
                     import_name, native_target,
                     native_mod ? debugstr_w(native_mod->ldr.FullDllName.Buffer) : "(null)" );
        if (native_target)
        {
            MESSAGE( "MacRunner HyperBridge native counterpart import %s!%s redirected %p -> %p (%s)\n",
                   dll_name, import_name, (void *)target, native_target,
                   semantic_stub ? "semantic" : "builtin" );
            target = (ULONG_PTR)native_target;
            native_counterpart = TRUE;
            if (native_mod) target_mod = native_mod;
            target_nt = RtlImageNtHeader( target_mod->ldr.DllBase );
        }
    }
    else if (target_nt->FileHeader.Machine == current_machine &&
             current_machine == IMAGE_FILE_MACHINE_ARM64)
    {
        /* Delay-loaded Wine builtins can already be resolved to the native
         * ARM64 module.  Still publish a guest-callable thunk for the AMD64
         * application so direct delay-load IAT calls do not jump into ARM64
         * code bytes as if they were x86_64. */
        native_counterpart = TRUE;
    }
    if (target_nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 && !native_thunk &&
        !native_counterpart && !semantic_stub)
    {
        if (trace_iat) MESSAGE( "MacRunner HyperBridge IAT skip %s!%s: AMD64 Wine builtin has no native counterpart\n",
                              dll_name, import_name );
        return target;
    }
    if (!native_thunk &&
        target_nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
        target_nt->FileHeader.Machine != current_machine)
        return target;

    if (!macrunner_hb_address_in_executable_section( target_mod->ldr.DllBase, target ))
    {
        WINE_MODREF *actual_mod = macrunner_hb_find_module_from_address( target );
        IMAGE_NT_HEADERS *actual_nt = actual_mod ? RtlImageNtHeader( actual_mod->ldr.DllBase ) : NULL;

        if (actual_mod && actual_mod != target_mod && (actual_mod->ldr.Flags & LDR_WINE_INTERNAL) &&
            actual_nt && actual_nt->FileHeader.Machine == current_machine &&
            macrunner_hb_address_in_executable_section( actual_mod->ldr.DllBase, target ))
        {
            MESSAGE( "MacRunner HyperBridge forwarded executable import %s!%s target=%p module %s -> %s\n",
                   dll_name, import_name, (void *)target, debugstr_w(target_mod->ldr.BaseDllName.Buffer),
                   debugstr_w(actual_mod->ldr.BaseDllName.Buffer) );
            target_mod = actual_mod;
            target_nt = actual_nt;
            native_counterpart = TRUE;
        }
        else
        {
            ULONG_PTR data_proxy = macrunner_hb_get_x64_data_import_proxy( dll_name, import_name, target );

            if (data_proxy)
                return data_proxy;
            if (semantic_stub)
            {
                MESSAGE( "MacRunner HyperBridge semantic import %s!%s target=%p registered without executable native target\n",
                       dll_name, import_name, (void *)target );
            }
            else
            {
                MESSAGE( "MacRunner HyperBridge data import %s!%s target=%p left unthunked\n",
                       dll_name, import_name, (void *)target );
                return target;
            }
        }
    }

    memset( &params, 0, sizeof(params) );
    params.target = (void *)target;
    if ((native_thunk || native_counterpart) && current_machine == IMAGE_FILE_MACHINE_ARM64)
    {
        params.pe_call12 = macrunner_hb_get_pe_call12_trampoline();
        params.pe_callback12 = macrunner_hb_get_pe_callback12_trampoline();
    }
    params.module_id = (ULONG_PTR)importer->ldr.DllBase;
    params.target_module_id = (ULONG_PTR)target_mod->ldr.DllBase;
    params.target_machine = (native_thunk || native_counterpart) ? current_machine : target_nt->FileHeader.Machine;
    params.target_module_machine = target_nt->FileHeader.Machine;
    macrunner_hb_copy_import_name( params.dll_name, sizeof(params.dll_name), dll_name );
    macrunner_hb_copy_import_name( params.import_name, sizeof(params.import_name), import_name );

    status = WINE_UNIX_CALL( unix_macrunner_hb_register_import_thunk, &params );
    if (status)
    {
        MESSAGE( "MacRunner HyperBridge failed to register import thunk %s!%s target=%p status=%lx\n",
              dll_name, import_name, (void *)target, status );
        return target;
    }

    if (import_name && (strstr( import_name, "D3D11Create" ) || strstr( import_name, "D3D11On12" ) ||
                        strstr( import_name, "CreateDXGIFactory" )))
        MESSAGE( "macrunner-hb-iatfinal: importer=%s import=%s native_cp=%d guest_target=%p target=%p tmmach=0x%x\n",
                 debugstr_w(importer->ldr.BaseDllName.Buffer), import_name, native_counterpart,
                 (void *)(ULONG_PTR)params.guest_target, (void *)target, params.target_module_machine );
    MESSAGE( "MacRunner HyperBridge rewrote import %s!%s target=%p guest=%p\n",
           dll_name, import_name, (void *)target, (void *)(ULONG_PTR)params.guest_target );
    return (ULONG_PTR)params.guest_target;
}

static ULONG_PTR macrunner_hb_fix_native_import_target( WINE_MODREF *importer, WINE_MODREF *target_mod,
                                                        const char *dll_name, const char *import_name,
                                                        ULONG_PTR target )
{
    void *native_target;
    ULONG_PTR thunk_target = 0;

    if (!target || !importer || !target_mod || !dll_name || !import_name) return target;
    if (!macrunner_hb_x64_main_requested()) return target;
    if (current_machine != IMAGE_FILE_MACHINE_ARM64) return target;
    if (!macrunner_hb_importer_is_native_wine_builtin( importer )) return target;
    if (!(target_mod->ldr.Flags & LDR_WINE_INTERNAL)) return target;
    if (macrunner_hb_target_is_native_thunk_or_mid( target_mod, target, &thunk_target ))
    {
        native_target = macrunner_hb_find_native_target_for_thunk_import( target_mod, import_name,
                                                                         thunk_target, FALSE, importer );
        if (native_target)
        {
            MESSAGE( "MacRunner HyperBridge repaired native thunk import %s -> %s!%s %p -> %p\n",
                   debugstr_w(importer->ldr.BaseDllName.Buffer), dll_name, import_name,
                   (void *)target, native_target );
            return (ULONG_PTR)native_target;
        }
        MESSAGE( "MacRunner HyperBridge native thunk import %s -> %s!%s unresolved target=%p thunk=%p\n",
              debugstr_w(importer->ldr.BaseDllName.Buffer), dll_name, import_name,
              (void *)target, (void *)thunk_target );
    }
    if (macrunner_hb_address_in_executable_section( target_mod->ldr.DllBase, target )) return target;
    else
    {
        WINE_MODREF *actual_mod = macrunner_hb_find_module_from_address( target );
        IMAGE_NT_HEADERS *actual_nt = actual_mod ? RtlImageNtHeader( actual_mod->ldr.DllBase ) : NULL;

        if (actual_mod && actual_mod != target_mod && (actual_mod->ldr.Flags & LDR_WINE_INTERNAL) &&
            actual_nt && actual_nt->FileHeader.Machine == current_machine &&
            macrunner_hb_address_in_executable_section( actual_mod->ldr.DllBase, target ))
        {
            MESSAGE( "MacRunner HyperBridge native forwarded import %s -> %s!%s target=%p module %s -> %s\n",
                   debugstr_w(importer->ldr.BaseDllName.Buffer), dll_name, import_name, (void *)target,
                   debugstr_w(target_mod->ldr.BaseDllName.Buffer),
                   debugstr_w(actual_mod->ldr.BaseDllName.Buffer) );
            return target;
        }
        if (actual_mod && actual_nt && actual_nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            const char *native_import_name = macrunner_hb_ascii_ieq( import_name, "__chkstk_arm64ec" )
                                             ? "__chkstk" : import_name;
            WINE_MODREF *native_mod = NULL;
            void *native_target = macrunner_hb_find_native_counterpart_export( actual_mod,
                                                                               native_import_name,
                                                                               &native_mod );

            if (native_target && native_mod &&
                macrunner_hb_address_in_executable_section( native_mod->ldr.DllBase,
                                                            (ULONG_PTR)native_target ))
            {
                MESSAGE( "MacRunner HyperBridge native forwarded counterpart import %s -> %s!%s "
                       "target=%p module %s -> %s native=%p\n",
                       debugstr_w(importer->ldr.BaseDllName.Buffer), dll_name, import_name,
                       (void *)target, debugstr_w(actual_mod->ldr.BaseDllName.Buffer),
                       debugstr_w(native_mod->ldr.BaseDllName.Buffer), native_target );
                return (ULONG_PTR)native_target;
            }
        }
    }

    /*
     * Some ARM64/ARM64X builtins expose a live export-table view that can point
     * at metadata/name-table bytes while the on-disk ARM64 view points at real
     * code.  Native Wine DLLs must never import a non-executable export target:
     * they will call it directly during PROCESS_ATTACH before HyperBridge can
     * trap it.  Re-read the same export from disk as the source of truth.
     */
    native_target = macrunner_hb_find_disk_export_outside_section( target_mod, import_name, ".hexpthk" );
    if (!native_target)
        native_target = macrunner_hb_find_export_outside_section( target_mod->ldr.DllBase, import_name, ".hexpthk" );
    if (!native_target)
    {
        void *live_target = RtlFindExportedRoutineByName( target_mod->ldr.DllBase, import_name );

        if (live_target)
        {
            native_target = macrunner_hb_redirect_arm64x_thunk_to_native( target_mod->ldr.DllBase,
                                                                          live_target );
            if (native_target == live_target &&
                macrunner_hb_address_in_section( target_mod->ldr.DllBase, ".hexpthk",
                                                 (ULONG_PTR)native_target ))
                native_target = NULL;
        }
    }

    if (native_target && macrunner_hb_address_in_executable_section( target_mod->ldr.DllBase,
                                                                     (ULONG_PTR)native_target ))
    {
        MESSAGE( "MacRunner HyperBridge repaired native import %s -> %s!%s %p -> %p\n",
               debugstr_w(importer->ldr.BaseDllName.Buffer), dll_name, import_name,
               (void *)target, native_target );
        return (ULONG_PTR)native_target;
    }

    MESSAGE( "MacRunner HyperBridge native import %s -> %s!%s resolved to non-executable %p\n",
          debugstr_w(importer->ldr.BaseDllName.Buffer), dll_name, import_name, (void *)target );
    return target;
}

static ULONG_PTR macrunner_hb_resolve_native_import_target( WINE_MODREF *target_mod, const char *dll_name,
                                                            const char *import_name, ULONG_PTR target )
{
    IMAGE_NT_HEADERS *target_nt;
    void *native_target;

    if (!target || !target_mod) return target;
    if (!(target_mod->ldr.Flags & LDR_WINE_INTERNAL)) return target;
    if (!(target_nt = RtlImageNtHeader( target_mod->ldr.DllBase ))) return target;
    if (target_nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
        target_nt->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64X &&
        target_nt->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64EC &&
        !macrunner_hb_get_arm64x_metadata( target_mod->ldr.DllBase ))
        return target;

    native_target = macrunner_hb_resolve_arm64x_native_target( (void *)target );
    if (native_target && native_target != (void *)target)
        MESSAGE( "MacRunner HyperBridge resolved native import %s!%s %p -> %p\n",
               dll_name ? dll_name : "?", import_name ? import_name : "?",
               (void *)target, native_target );
    return native_target ? (ULONG_PTR)native_target : target;
}

static BOOL macrunner_hb_delay_load_prefers_native_builtin( void *base, const char *dll_name )
{
    IMAGE_NT_HEADERS *nt;

    if (!dll_name || !macrunner_hb_amd64_main_on_arm64) return FALSE;
    if (current_machine != IMAGE_FILE_MACHINE_ARM64) return FALSE;
    if (!(nt = RtlImageNtHeader( base ))) return FALSE;
    return nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
}

static BOOL macrunner_hb_delay_load_is_native_builtin_importer( void *base, const char *dll_name )
{
    IMAGE_NT_HEADERS *nt;
    WINE_MODREF *importer;
    BOOL ret = FALSE;

    if (!dll_name || !macrunner_hb_amd64_main_on_arm64) return FALSE;
    if (current_machine != IMAGE_FILE_MACHINE_ARM64) return FALSE;
    if (!(nt = RtlImageNtHeader( base ))) return FALSE;
    if (nt->FileHeader.Machine != current_machine) return FALSE;

    RtlEnterCriticalSection( &loader_section );
    importer = get_modref( base );
    ret = macrunner_hb_importer_is_native_wine_builtin( importer );
    RtlLeaveCriticalSection( &loader_section );
    return ret;
}

static BOOL macrunner_hb_skip_x64_builtin_search_candidate( const WCHAR *path )
{
    if (!imports_fixup_done || !macrunner_hb_amd64_main_on_arm64) return FALSE;
    if (current_machine != IMAGE_FILE_MACHINE_ARM64) return FALSE;
    if (!path) return FALSE;
    if (!wcsstr( path, L"\\x86_64-windows\\" ) && !wcsstr( path, L"/x86_64-windows/" ))
        return FALSE;

    /* After the AMD64 application's static imports have been fixed up, a
     * runtime LoadLibrary from Wine's own x86_64 builtin directory is almost
     * always a delayed Win32 service dependency (uxtheme, comctl32 helpers,
     * shell helpers, ...).  Let the normal system32/builtin search find the
     * native ARM64 counterpart instead of mapping a second AMD64 Wine DLL
     * that native user32/comctl32 cannot execute directly. */
    MESSAGE( "MacRunner HyperBridge skipping AMD64 Wine builtin search candidate %s\n", debugstr_w(path) );
    return TRUE;
}

static FARPROC macrunner_hb_maybe_register_dynamic_import_thunk( void *base, HMODULE module,
                                                                 const char *dll_name,
                                                                 const char *import_name,
                                                                 ULONG ordinal, FARPROC proc )
{
    WINE_MODREF *importer, *target_mod;
    char ordinal_name[24];

    if (!proc || !macrunner_hb_delay_load_prefers_native_builtin( base, dll_name )) return proc;
    if (!import_name)
    {
        macrunner_hb_format_ordinal_import_name( ordinal_name, sizeof(ordinal_name), ordinal );
        import_name = ordinal_name;
    }

    RtlEnterCriticalSection( &loader_section );
    importer = get_modref( base );
    target_mod = get_modref( module );
    if (importer && target_mod)
        proc = (FARPROC)macrunner_hb_maybe_register_import_thunk( importer, target_mod, dll_name,
                                                                  import_name, (ULONG_PTR)proc );
    RtlLeaveCriticalSection( &loader_section );
    return proc;
}

/**********************************************************************
 *	    find_fullname_module
 *
 * Find a module from its full path name.
 * The loader_section must be locked while calling this function
 */
static WINE_MODREF *find_fullname_module( const UNICODE_STRING *nt_name )
{
    PLIST_ENTRY mark, entry;
    UNICODE_STRING name = *nt_name;

    if (name.Length <= 4 * sizeof(WCHAR)) return NULL;
    name.Length -= 4 * sizeof(WCHAR);  /* for \??\ prefix */
    name.Buffer += 4;

    if (cached_modref && RtlEqualUnicodeString( &name, &cached_modref->ldr.FullDllName, TRUE ))
        return cached_modref;

    mark = &NtCurrentTeb()->Peb->LdrData->InLoadOrderModuleList;
    for (entry = mark->Flink; entry != mark; entry = entry->Flink)
    {
        LDR_DATA_TABLE_ENTRY *mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (RtlEqualUnicodeString( &name, &mod->FullDllName, TRUE ))
        {
            cached_modref = CONTAINING_RECORD(mod, WINE_MODREF, ldr);
            return cached_modref;
        }
    }
    return NULL;
}


/**********************************************************************
 *	    find_fileid_module
 *
 * Find a module from its file id.
 * The loader_section must be locked while calling this function
 */
static WINE_MODREF *find_fileid_module( const struct file_id *id )
{
    LIST_ENTRY *mark, *entry;

    if (cached_modref && !memcmp( &cached_modref->id, id, sizeof(*id) )) return cached_modref;

    mark = &NtCurrentTeb()->Peb->LdrData->InLoadOrderModuleList;
    for (entry = mark->Flink; entry != mark; entry = entry->Flink)
    {
        LDR_DATA_TABLE_ENTRY *mod = CONTAINING_RECORD( entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
        WINE_MODREF *wm = CONTAINING_RECORD( mod, WINE_MODREF, ldr );

        if (!memcmp( &wm->id, id, sizeof(*id) ))
        {
            cached_modref = wm;
            return wm;
        }
    }
    return NULL;
}


/******************************************************************************
 *	get_apiset_entry
 */
static BOOL apiset_offset_ptr( const API_SET_NAMESPACE *map, ULONG offset, SIZE_T len, const void **ptr )
{
    if (!map || map->Size < sizeof(*map)) return FALSE;
    if (offset > map->Size || len > map->Size - offset) return FALSE;
    *ptr = (const char *)map + offset;
    return TRUE;
}

static NTSTATUS get_apiset_entry( const API_SET_NAMESPACE *map, const WCHAR *name, ULONG len,
                                  const API_SET_NAMESPACE_ENTRY **entry )
{
    const API_SET_HASH_ENTRY *hash_entry;
    const API_SET_NAMESPACE_ENTRY *entries;
    ULONG hash, i, hash_len;
    SIZE_T hash_size, entry_size, hashed_bytes;
    int min, max;

    if (len <= 4) return STATUS_INVALID_PARAMETER;
    if (wcsnicmp( name, L"api-", 4 ) && wcsnicmp( name, L"ext-", 4 )) return STATUS_INVALID_PARAMETER;
    if (!map) return STATUS_APISET_NOT_PRESENT;
    if (!map->Count || map->Count > 0x7fffffff ||
        map->Count > (SIZE_T)-1 / sizeof(*hash_entry) ||
        map->Count > (SIZE_T)-1 / sizeof(*entries))
        return STATUS_APISET_NOT_PRESENT;
    hash_size = (SIZE_T)map->Count * sizeof(*hash_entry);
    entry_size = (SIZE_T)map->Count * sizeof(*entries);
    if (!apiset_offset_ptr( map, map->HashOffset, hash_size, (const void **)&hash_entry ) ||
        !apiset_offset_ptr( map, map->EntryOffset, entry_size, (const void **)&entries ))
        return STATUS_APISET_NOT_PRESENT;

    for (i = hash_len = 0; i < len; i++)
    {
        if (name[i] == '.') break;
        if (name[i] == '-') hash_len = i;
    }
    if (hash_len > (SIZE_T)-1 / sizeof(WCHAR)) return STATUS_APISET_NOT_PRESENT;
    hashed_bytes = (SIZE_T)hash_len * sizeof(WCHAR);
    for (i = hash = 0; i < hash_len; i++)
        hash = hash * map->HashFactor + ((name[i] >= 'A' && name[i] <= 'Z') ? name[i] + 32 : name[i]);

    min = 0;
    max = map->Count - 1;
    while (min <= max)
    {
        int pos = (min + max) / 2;
        if (hash_entry[pos].Hash < hash) min = pos + 1;
        else if (hash_entry[pos].Hash > hash) max = pos - 1;
        else
        {
            const WCHAR *entry_name;

            if (hash_entry[pos].Index >= map->Count) break;
            *entry = entries + hash_entry[pos].Index;
            if ((*entry)->HashedLength != hashed_bytes) break;
            if (!apiset_offset_ptr( map, (*entry)->NameOffset, (*entry)->HashedLength,
                                    (const void **)&entry_name ))
                break;
            if (wcsnicmp( entry_name, name, hash_len )) break;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_APISET_NOT_PRESENT;
}


/******************************************************************************
 *	get_apiset_target
 */
static NTSTATUS get_apiset_target( const API_SET_NAMESPACE *map, const API_SET_NAMESPACE_ENTRY *entry,
                                   const WCHAR *host, UNICODE_STRING *ret )
{
    const API_SET_VALUE_ENTRY *value;
    ULONG i, len;

    if (!entry->ValueCount) return STATUS_DLL_NOT_FOUND;
    if (entry->ValueCount > (SIZE_T)-1 / sizeof(*value) ||
        !apiset_offset_ptr( map, entry->ValueOffset, (SIZE_T)entry->ValueCount * sizeof(*value),
                            (const void **)&value ))
        return STATUS_DLL_NOT_FOUND;
    if (host)
    {
        /* look for specific host in entries 1..n, entry 0 is the default */
        for (i = 1; i < entry->ValueCount; i++)
        {
            const WCHAR *value_name;

            if (value[i].NameLength % sizeof(WCHAR)) return STATUS_DLL_NOT_FOUND;
            if (!apiset_offset_ptr( map, value[i].NameOffset, value[i].NameLength,
                                    (const void **)&value_name ))
                return STATUS_DLL_NOT_FOUND;
            len = value[i].NameLength / sizeof(WCHAR);
            if (!wcsnicmp( host, value_name, len ) && !host[len])
            {
                value += i;
                break;
            }
        }
    }
    if (!value->ValueOffset) return STATUS_DLL_NOT_FOUND;
    if (!apiset_offset_ptr( map, value->ValueOffset, value->ValueLength, (const void **)&ret->Buffer ))
        return STATUS_DLL_NOT_FOUND;
    ret->Length = value->ValueLength;
    return STATUS_SUCCESS;
}


/**********************************************************************
 *	    build_import_name
 */
static BOOL macrunner_hb_is_ucrt_apiset_name( const WCHAR *name )
{
    static const WCHAR prefix[] = L"api-ms-win-crt-";

    return !wcsnicmp( name, prefix, ARRAY_SIZE(prefix) - 1 );
}

static NTSTATUS build_import_name( WINE_MODREF *importer, WCHAR buffer[256], const char *import, int len )
{
    const API_SET_NAMESPACE *map = NtCurrentTeb()->Peb->ApiSetMap;
    const API_SET_NAMESPACE_ENTRY *entry;
    const WCHAR *host = importer->ldr.BaseDllName.Buffer;
    UNICODE_STRING str;

    while (len && import[len-1] == ' ') len--;  /* remove trailing spaces */
    if (len + sizeof(".dll") > 256) return STATUS_DLL_NOT_FOUND;
    ascii_to_unicode( buffer, import, len );
    buffer[len] = 0;
    if (!wcschr( buffer, '.' )) wcscpy( buffer + len, L".dll" );

    if (get_apiset_entry( map, buffer, wcslen(buffer), &entry ))
    {
        if (macrunner_hb_is_ucrt_apiset_name( buffer )) wcscpy( buffer, L"ucrtbase.dll" );
        return STATUS_SUCCESS;
    }

    if (get_apiset_target( map, entry, host, &str )) return STATUS_DLL_NOT_FOUND;
    if (str.Length >= 256 * sizeof(WCHAR)) return STATUS_DLL_NOT_FOUND;

    TRACE( "found %s for %s\n", debugstr_us(&str), debugstr_w(buffer));
    memcpy( buffer, str.Buffer, str.Length );
    buffer[str.Length / sizeof(WCHAR)] = 0;
    return STATUS_SUCCESS;
}


/**********************************************************************
 *	    append_dll_ext
 */
static WCHAR *append_dll_ext( const WCHAR *name )
{
    const WCHAR *ext = wcsrchr( name, '.' );

    if (!ext || wcschr( ext, '/' ) || wcschr( ext, '\\'))
    {
        WCHAR *ret = RtlAllocateHeap( GetProcessHeap(), 0,
                                      wcslen(name) * sizeof(WCHAR) + sizeof(L".dll") );
        if (!ret) return NULL;
        wcscpy( ret, name );
        wcscat( ret, L".dll" );
        return ret;
    }
    return NULL;
}


static BOOL image_contains_range( HMODULE module, const void *ptr, SIZE_T size )
{
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( module );
    ULONG_PTR base = (ULONG_PTR)module, addr = (ULONG_PTR)ptr, end;

    if (!nt) return FALSE;
    if (nt->OptionalHeader.SizeOfImage > ~(ULONG_PTR)0 - base) return FALSE;
    end = base + nt->OptionalHeader.SizeOfImage;
    if (addr < base || addr > end) return FALSE;
    return size <= end - addr;
}

static BOOL image_contains_array( HMODULE module, const void *ptr, SIZE_T count, SIZE_T elem_size )
{
    if (elem_size && count > (SIZE_T)-1 / elem_size) return FALSE;
    return image_contains_range( module, ptr, count * elem_size );
}

static void *image_rva_range( HMODULE module, DWORD rva, SIZE_T size )
{
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( module );
    ULONG_PTR base = (ULONG_PTR)module;

    if (!nt) return NULL;
    if (nt->OptionalHeader.SizeOfImage > ~(ULONG_PTR)0 - base) return NULL;
    if (rva > nt->OptionalHeader.SizeOfImage || size > nt->OptionalHeader.SizeOfImage - rva)
        return NULL;
    return (void *)(base + rva);
}

static const char *image_rva_string( HMODULE module, DWORD rva )
{
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( module );
    const char *str;
    SIZE_T len;

    if (!nt || !(str = image_rva_range( module, rva, 1 ))) return NULL;
    len = nt->OptionalHeader.SizeOfImage - rva;
    return memchr( str, 0, len ) ? str : NULL;
}

static const IMAGE_IMPORT_BY_NAME *image_import_by_name( HMODULE module, DWORD rva )
{
    const IMAGE_IMPORT_BY_NAME *import;
    DWORD name_rva;

    import = image_rva_range( module, rva, FIELD_OFFSET( IMAGE_IMPORT_BY_NAME, Name ) + 1 );
    if (!import) return NULL;
    if (rva > ~(DWORD)0 - FIELD_OFFSET( IMAGE_IMPORT_BY_NAME, Name ))
        return NULL;
    name_rva = rva + FIELD_OFFSET( IMAGE_IMPORT_BY_NAME, Name );
    if (!image_rva_string( module, name_rva ))
        return NULL;
    return import;
}

static NTSTATUS get_import_descriptor_count( HMODULE module, const IMAGE_IMPORT_DESCRIPTOR *imports,
                                             DWORD size, DWORD *count )
{
    DWORD i, max = size / sizeof(*imports);

    *count = 0;
    if (!max || !image_contains_array( module, imports, max, sizeof(*imports) ))
        return STATUS_INVALID_IMAGE_FORMAT;

    for (i = 0; i < max; i++)
    {
        if (!imports[i].Name || !imports[i].FirstThunk)
        {
            *count = i;
            return STATUS_SUCCESS;
        }
    }

    WARN( "import descriptor table at %p is not terminated within directory size %lu\n",
          imports, size );
    return STATUS_INVALID_IMAGE_FORMAT;
}

static NTSTATUS get_import_thunk_count( HMODULE module, const IMAGE_THUNK_DATA *thunks, SIZE_T *count )
{
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( module );
    ULONG_PTR base = (ULONG_PTR)module, addr = (ULONG_PTR)thunks, end;
    SIZE_T i, max;

    *count = 0;
    if (!nt) return STATUS_INVALID_IMAGE_FORMAT;
    end = base + nt->OptionalHeader.SizeOfImage;
    if (end < base || addr < base || addr > end) return STATUS_INVALID_IMAGE_FORMAT;

    max = (end - addr) / sizeof(*thunks);
    for (i = 0; i < max; i++)
    {
        if (!thunks[i].u1.Ordinal)
        {
            *count = i;
            return STATUS_SUCCESS;
        }
    }

    WARN( "import thunk table at %p is not terminated within image\n", thunks );
    return STATUS_INVALID_IMAGE_FORMAT;
}

/***********************************************************************
 *           is_import_dll_system
 */
static BOOL is_import_dll_system( LDR_DATA_TABLE_ENTRY *mod, const IMAGE_IMPORT_DESCRIPTOR *import )
{
    const char *name = image_rva_string( mod->DllBase, import->Name );

    if (!name) return FALSE;
    return !_stricmp( name, "ntdll.dll" ) || !_stricmp( name, "kernel32.dll" );
}

static SIZE_T macrunner_hb_arm64x_native_import_prefix_count( WINE_MODREF *wm,
                                                              const IMAGE_THUNK_DATA *import_list,
                                                              const IMAGE_THUNK_DATA *thunk_list )
{
    HMODULE module = wm->ldr.DllBase;
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( module );
    SIZE_T count = 0;

    if (!macrunner_hb_x64_main_requested()) return 0;
    if (!(wm->ldr.Flags & LDR_WINE_INTERNAL)) return 0;
    if (!nt || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return 0;
    if (!macrunner_hb_get_arm64x_metadata( module )) return 0;

    while (count < 16)
    {
        const IMAGE_THUNK_DATA *prev_import = import_list - count - 1;
        const IMAGE_THUNK_DATA *prev_thunk = thunk_list - count - 1;

        if (!image_contains_array( module, prev_import, 1, sizeof(*prev_import) ) ||
            !image_contains_array( module, prev_thunk, 1, sizeof(*prev_thunk) ))
            break;
        if (!prev_import->u1.Ordinal) break;
        if (prev_thunk->u1.Function != prev_import->u1.Ordinal) break;
        if (!IMAGE_SNAP_BY_ORDINAL( prev_import->u1.Ordinal ) &&
            !image_import_by_name( module, (DWORD)prev_import->u1.AddressOfData ))
            break;
        count++;
    }
    return count;
}

static void macrunner_hb_resolve_arm64x_native_import_prefix( WINE_MODREF *wm, WINE_MODREF *wmImp,
                                                              const char *dll_name, LPCWSTR load_path,
                                                              const IMAGE_THUNK_DATA *import_list,
                                                              IMAGE_THUNK_DATA *thunk_list,
                                                              SIZE_T prefix_count )
{
    WINE_MODREF *native_wm = macrunner_hb_load_native_counterpart_module( wmImp );
    IMAGE_NT_HEADERS *native_nt = native_wm ? RtlImageNtHeader( native_wm->ldr.DllBase ) : NULL;
    HMODULE native_mod;
    const IMAGE_EXPORT_DIRECTORY *exports;
    DWORD exp_size;
    SIZE_T i;
    static unsigned int report_count;

    if (!prefix_count || !native_nt ||
        (native_nt->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64 &&
         !macrunner_hb_get_arm64x_metadata( native_wm->ldr.DllBase )))
        return;
    native_mod = native_wm->ldr.DllBase;
    exports = RtlImageDirectoryEntryToData( native_mod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &exp_size );
    if (!exports) return;

    for (i = prefix_count; i; i--)
    {
        const IMAGE_THUNK_DATA *src = import_list - i;
        IMAGE_THUNK_DATA *dst = thunk_list - i;
        const char *import_name;
        ULONG_PTR target;
        char ordinal_name[24];

        if (IMAGE_SNAP_BY_ORDINAL( src->u1.Ordinal ))
        {
            int ordinal = IMAGE_ORDINAL( src->u1.Ordinal );
            target = (ULONG_PTR)find_ordinal_export( native_mod, exports, exp_size,
                                                     ordinal - exports->Base, load_path, wm, FALSE );
            macrunner_hb_format_ordinal_import_name( ordinal_name, sizeof(ordinal_name), ordinal );
            import_name = ordinal_name;
        }
        else
        {
            const IMAGE_IMPORT_BY_NAME *pe_name =
                image_import_by_name( wm->ldr.DllBase, (DWORD)src->u1.AddressOfData );
            if (!pe_name) continue;
            import_name = (const char *)pe_name->Name;
            target = (ULONG_PTR)find_named_export( native_mod, exports, exp_size, import_name,
                                                   pe_name->Hint, load_path, wm, FALSE );
        }

        target = (ULONG_PTR)macrunner_hb_resolve_arm64x_native_target( (void *)target );
        if (!target) continue;
        /* MacRunner 2026-08-05 — СКОБКА ЗАЩИТЫ, без неё запись не проходит НИКОГДА.
         *
         * Слот импорта лежит на странице образа, отображённой R-X (замерено
         * `mach_vm_region_recurse` в момент отказа: `prot=5/7` — чтения и исполнение есть,
         * записи нет, при max_protection=RWX).  Прямая запись даёт SIGBUS; si_code приходит
         * BUS_ADRALN и врёт — поле DFSC в ESR равно 0xf, то есть отказ ПО ПРАВАМ, а не по
         * выравниванию (это уже разбирали 02.07 и починили тогда только классификацию).
         * Обработчик права не поднимает и PC не двигает, поэтому инструкция повторяется
         * вечно: замерено 186 млн отказов, 230 тыс/с, 39 % времени процесса — и прогон
         * встаёт намертво на очередном модуле.
         *
         * Скобка ровно та же, что уже стоит у соседней нашей функции (см. синхронизацию
         * alias-слотов COFF выше в этом же файле): снять защиту, записать, вернуть как было.
         * При отказе снятия слот пропускается — молча писать мимо защиты нельзя. */
        {
            PVOID protect_base = dst;
            SIZE_T protect_size = sizeof(dst->u1.Function);
            ULONG old_prot;

            if (NtProtectVirtualMemory( NtCurrentProcess(), &protect_base, &protect_size,
                                        PAGE_READWRITE, &old_prot ))
            {
                static unsigned protect_fail_count;
                if (protect_fail_count++ < 8)
                    MESSAGE( "macrunner-hb-arm64x-native-import-protect-failed: module=%s dll=%s "
                             "import=%s slot=%p\n",
                             debugstr_w(wm->ldr.BaseDllName.Buffer), dll_name, import_name, dst );
                continue;
            }
            dst->u1.Function = target;
            NtProtectVirtualMemory( NtCurrentProcess(), &protect_base, &protect_size,
                                    old_prot, &old_prot );
        }
        if (report_count++ < 32)
            MESSAGE( "macrunner-hb-arm64x-native-import-prefix: module=%s dll=%s import=%s "
                     "slot=%p target=%p native=%p\n",
                     debugstr_w(wm->ldr.BaseDllName.Buffer), dll_name, import_name, dst,
                     (void *)target, native_mod );
    }
}

/**********************************************************************
 *	    insert_single_list_tail
 */
static void insert_single_list_after( LDRP_CSLIST *list, SINGLE_LIST_ENTRY *prev, SINGLE_LIST_ENTRY *entry )
{
    if (!list->Tail)
    {
        assert( !prev );
        entry->Next = entry;
        list->Tail = entry;
        return;
    }
    if (!prev)
    {
        /* Insert at head. */
        entry->Next = list->Tail->Next;
        list->Tail->Next = entry;
        return;
    }
    entry->Next = prev->Next;
    prev->Next = entry;
    if (prev == list->Tail) list->Tail = entry;
}

/**********************************************************************
 *	    remove_single_list_entry
 */
static void remove_single_list_entry( LDRP_CSLIST *list, SINGLE_LIST_ENTRY *entry )
{
    SINGLE_LIST_ENTRY *prev;

    assert( list->Tail );

    if (entry->Next == entry)
    {
        assert( list->Tail == entry );
        list->Tail = NULL;
        return;
    }

    prev = list->Tail->Next;
    while (prev->Next != entry && prev != list->Tail)
        prev = prev->Next;
    assert( prev->Next == entry );
    prev->Next = entry->Next;
    if (list->Tail == entry) list->Tail = prev;
    entry->Next = NULL;
}

static LDR_DEPENDENCY *find_module_dependency( LDR_DDAG_NODE *from, LDR_DDAG_NODE *to )
{
    SINGLE_LIST_ENTRY *entry, *mark = from->Dependencies.Tail;

    if (!mark) return NULL;

    for (entry = mark->Next; entry != mark; entry = entry->Next)
    {
        LDR_DEPENDENCY *dep = CONTAINING_RECORD( entry, LDR_DEPENDENCY, dependency_to_entry );
        if (dep->dependency_to == to && dep->dependency_from == from) return dep;
    }

    return NULL;
}

/**********************************************************************
 *	    add_module_dependency_after
 */
static BOOL add_module_dependency_after( LDR_DDAG_NODE *from, LDR_DDAG_NODE *to,
                                         SINGLE_LIST_ENTRY *dep_after )
{
    LDR_DEPENDENCY *dep;

    if ((dep = find_module_dependency( from, to )))
    {
        /* Dependency already exists; consume the module reference stolen from the caller */
        WINE_MODREF *wm = CONTAINING_RECORD( to->Modules.Flink, WINE_MODREF, ldr.NodeModuleLink );
        assert( wm->ldr.LoadCount != 1 );
        if (wm->ldr.LoadCount != -1) wm->ldr.LoadCount--;
        return TRUE;
    }

    if (!(dep = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*dep) ))) return FALSE;

    dep->dependency_from = from;
    insert_single_list_after( &from->Dependencies, dep_after, &dep->dependency_to_entry );
    dep->dependency_to = to;
    insert_single_list_after( &to->IncomingDependencies, NULL, &dep->dependency_from_entry );

    return TRUE;
}

/**********************************************************************
 *	    add_module_dependency
 */
static BOOL add_module_dependency( LDR_DDAG_NODE *from, LDR_DDAG_NODE *to )
{
    return add_module_dependency_after( from, to, from->Dependencies.Tail );
}

/**********************************************************************
 *	    remove_module_dependency
 */
static void remove_module_dependency( LDR_DEPENDENCY *dep )
{
    remove_single_list_entry( &dep->dependency_to->IncomingDependencies, &dep->dependency_from_entry );
    remove_single_list_entry( &dep->dependency_from->Dependencies, &dep->dependency_to_entry );
    RtlFreeHeap( GetProcessHeap(), 0, dep );
}

/**********************************************************************
 *	    walk_node_dependencies
 */
static NTSTATUS walk_node_dependencies( LDR_DDAG_NODE *node, void *context,
                                        NTSTATUS (*callback)( LDR_DDAG_NODE *, void * ))
{
    SINGLE_LIST_ENTRY *entry;
    LDR_DEPENDENCY *dep;
    NTSTATUS status;

    if (!(entry = node->Dependencies.Tail)) return STATUS_SUCCESS;

    do
    {
        entry = entry->Next;
        dep = CONTAINING_RECORD( entry, LDR_DEPENDENCY, dependency_to_entry );
        assert( dep->dependency_from == node );
        if ((status = callback( dep->dependency_to, context ))) break;
    } while (entry != node->Dependencies.Tail);

    return status;
}

/*************************************************************************
 *		find_forwarded_export
 *
 * Find the final function pointer for a forwarded function.
 * The loader_section must be locked while calling this function.
 */
static FARPROC find_forwarded_export( HMODULE module, const char *forward, const char *forward_end,
                                      LPCWSTR load_path, WINE_MODREF *importer, BOOL is_dynamic )
{
    const IMAGE_EXPORT_DIRECTORY *exports;
    DWORD exp_size;
    WINE_MODREF *wm;
    WCHAR mod_name[256];
    const char *end, *nul;
    FARPROC proc = NULL;
    BOOL wm_loaded = FALSE;

    if (!(nul = memchr( forward, 0, forward_end - forward )))
    {
        WARN( "forwarder string at %p is not terminated in export directory\n", forward );
        return NULL;
    }

    for (end = nul; end > forward && end[-1] != '.'; --end) {}
    if (end == forward || end == nul) return NULL;
    --end;

    if (build_import_name( importer, mod_name, forward, end - forward )) return NULL;

    if (!(wm = find_basename_module_machine( mod_name, current_machine )))
    {
        WINE_MODREF *imp = get_modref( module );
        TRACE( "delay loading %s for '%s'\n", debugstr_w(mod_name), forward );
        if (load_dll( load_path, mod_name, 0, &wm, imp->system ) != STATUS_SUCCESS)
        {
            ERR( "module not found for forward '%s' used by %s\n",
                 forward, debugstr_w(imp->ldr.FullDllName.Buffer) );
            return NULL;
        }
        wm_loaded = TRUE;
    }

    if (wm->ldr.DdagNode != node_ntdll && wm->ldr.DdagNode != node_kernel32)
    {
        /* Prepare for the callee stealing the reference */
        if (!wm_loaded && wm->ldr.LoadCount != -1) wm->ldr.LoadCount++;
        add_module_dependency( importer->ldr.DdagNode, wm->ldr.DdagNode );
        if (is_dynamic && wm_loaded && process_attach( wm->ldr.DdagNode, NULL ) != STATUS_SUCCESS)
        {
            ERR( "process_attach failed for forward '%s' used by %s\n",
                 forward, debugstr_w(get_modref( module )->ldr.FullDllName.Buffer) );
            LdrUnloadDll( wm->ldr.DllBase );
            return NULL;
        }
    }

    if ((exports = RtlImageDirectoryEntryToData( wm->ldr.DllBase, TRUE,
                                                 IMAGE_DIRECTORY_ENTRY_EXPORT, &exp_size )))
    {
        const char *name = end + 1;

        if (macrunner_hb_amd64_main_on_arm64 && !strcmp( name, "__chkstk_arm64ec" ))
        {
            WINE_MODREF *guest_wm = find_basename_module_machine( mod_name, IMAGE_FILE_MACHINE_AMD64 );
            if (guest_wm)
            {
                const IMAGE_EXPORT_DIRECTORY *guest_exports;
                DWORD guest_exp_size;

                guest_exports = RtlImageDirectoryEntryToData( guest_wm->ldr.DllBase, TRUE,
                                                              IMAGE_DIRECTORY_ENTRY_EXPORT,
                                                              &guest_exp_size );
                if (guest_exports)
                {
                    wm = guest_wm;
                    exports = guest_exports;
                    exp_size = guest_exp_size;
                }
            }
        }
        else if (macrunner_hb_amd64_main_on_arm64 &&
                 (!strcmp( name, "__wine_unix_call_dispatcher_arm64ec" ) ||
                  !strcmp( name, "KiUserEmulationDispatcher" )))
        {
            WINE_MODREF *native_wm = find_basename_module_machine( mod_name, current_machine );
            if (native_wm)
            {
                const IMAGE_EXPORT_DIRECTORY *native_exports;
                DWORD native_exp_size;

                native_exports = RtlImageDirectoryEntryToData( native_wm->ldr.DllBase, TRUE,
                                                               IMAGE_DIRECTORY_ENTRY_EXPORT,
                                                               &native_exp_size );
                if (native_exports)
                {
                    wm = native_wm;
                    exports = native_exports;
                    exp_size = native_exp_size;
                }
            }
        }

        if (*name == '#') { /* ordinal */
            proc = find_ordinal_export( wm->ldr.DllBase, exports, exp_size,
                                        atoi(name+1) - exports->Base, load_path,
                                        importer, is_dynamic );
        } else
            proc = find_named_export( wm->ldr.DllBase, exports, exp_size, name, -1, load_path,
                                      importer, is_dynamic );
    }

    if (!proc)
    {
        ERR("function not found for forward '%s' used by %s."
            " If you are using builtin %s, try using the native one instead.\n",
            forward, debugstr_w(get_modref(module)->ldr.FullDllName.Buffer),
            debugstr_w(get_modref(module)->ldr.BaseDllName.Buffer) );
    }
    return proc;
}


/*************************************************************************
 *		find_ordinal_export
 *
 * Find an exported function by ordinal.
 * The exports base must have been subtracted from the ordinal already.
 * The loader_section must be locked while calling this function.
 */
static FARPROC find_ordinal_export( HMODULE module, const IMAGE_EXPORT_DIRECTORY *exports,
                                    DWORD exp_size, DWORD ordinal, LPCWSTR load_path,
                                    WINE_MODREF *importer, BOOL is_dynamic )
{
    FARPROC proc;
    const DWORD *functions = get_rva( module, exports->AddressOfFunctions );

    if (ordinal >= exports->NumberOfFunctions)
    {
        TRACE("	ordinal %ld out of range!\n", ordinal + exports->Base );
        return NULL;
    }
    if (!functions[ordinal]) return NULL;

    proc = get_rva( module, functions[ordinal] );

    /* if the address falls into the export dir, it's a forward */
    if (((const char *)proc >= (const char *)exports) && 
        ((const char *)proc < (const char *)exports + exp_size))
        return find_forwarded_export( module, (const char *)proc, (const char *)exports + exp_size,
                                      load_path, importer, is_dynamic );

    if (TRACE_ON(snoop))
    {
        const WCHAR *user = !is_dynamic ? importer->ldr.BaseDllName.Buffer : NULL;
        proc = SNOOP_GetProcAddress( module, exports, exp_size, proc, ordinal, user );
    }
    if (TRACE_ON(relay))
    {
        const WCHAR *user = !is_dynamic ? importer->ldr.BaseDllName.Buffer : NULL;
        proc = RELAY_GetProcAddress( module, exports, exp_size, proc, ordinal, user );
    }
    /*
     * Do not rewrite imports internal to native ARM64 Wine builtins here.
     * Phase G's cross-arch boundary is the AMD64 application's IAT and the
     * Phase F callback trap. Rewriting native builtin ordinal imports during
     * PROCESS_ATTACH can recurse through ARM64X helper views before the DLL is
     * initialized and has produced early comctl32 stack overflows.
     */
    return proc;
}


/*************************************************************************
 *		find_name_in_exports
 *
 * Helper for find_named_export.
 */
static int find_name_in_exports( HMODULE module, const IMAGE_EXPORT_DIRECTORY *exports, const char *name )
{
    const WORD *ordinals = get_rva( module, exports->AddressOfNameOrdinals );
    const DWORD *names = get_rva( module, exports->AddressOfNames );
    int min = 0, max = exports->NumberOfNames - 1;

    while (min <= max)
    {
        int res, pos = (min + max) / 2;
        char *ename = get_rva( module, names[pos] );
        if (!(res = strcmp( ename, name ))) return ordinals[pos];
        if (res > 0) max = pos - 1;
        else min = pos + 1;
    }
    return -1;
}


/*************************************************************************
 *		find_named_export
 *
 * Find an exported function by name.
 * The loader_section must be locked while calling this function.
 */
static FARPROC find_named_export( HMODULE module, const IMAGE_EXPORT_DIRECTORY *exports, DWORD exp_size,
                                  const char *name, int hint, LPCWSTR load_path, WINE_MODREF *importer,
                                  BOOL is_dynamic )
{
    const WORD *ordinals = get_rva( module, exports->AddressOfNameOrdinals );
    const DWORD *names = get_rva( module, exports->AddressOfNames );
    int ordinal;

    /* first check the hint */
    if (hint >= 0 && hint < exports->NumberOfNames)
    {
        char *ename = get_rva( module, names[hint] );
        if (!strcmp( ename, name ))
            return find_ordinal_export( module, exports, exp_size, ordinals[hint], load_path, importer, is_dynamic );
    }

    /* then do a binary search */
    if ((ordinal = find_name_in_exports( module, exports, name )) == -1) return NULL;
    return find_ordinal_export( module, exports, exp_size, ordinal, load_path, importer, is_dynamic );

}


/*************************************************************************
 *		RtlFindExportedRoutineByName
 */
void * WINAPI RtlFindExportedRoutineByName( HMODULE module, const char *name )
{
    const IMAGE_EXPORT_DIRECTORY *exports;
    const DWORD *functions;
    DWORD exp_size;
    int ordinal;
    void *proc;

    exports = RtlImageDirectoryEntryToData( module, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &exp_size );
    if (!exports || exp_size < sizeof(*exports)) return NULL;

    if ((ordinal = find_name_in_exports( module, exports, name )) == -1) return NULL;
    if (ordinal >= exports->NumberOfFunctions) return NULL;
    functions = get_rva( module, exports->AddressOfFunctions );
    if (!functions[ordinal]) return NULL;
    proc = get_rva( module, functions[ordinal] );
    /* if the address falls into the export dir, it's a forward */
    if (((const char *)proc >= (const char *)exports) &&
        ((const char *)proc < (const char *)exports + exp_size))
        return NULL;
    return proc;
}


/*************************************************************************
 *		import_dll
 *
 * Import the dll specified by the given import descriptor.
 * The loader_section must be locked while calling this function.
 */
static BOOL import_dll( WINE_MODREF *wm, const IMAGE_IMPORT_DESCRIPTOR *descr, LPCWSTR load_path, WINE_MODREF **pwm )
{
    HMODULE module = wm->ldr.DllBase;
    BOOL system = wm->system || (wm->ldr.Flags & LDR_WINE_INTERNAL);
    NTSTATUS status;
    WINE_MODREF *wmImp;
    HMODULE imp_mod;
    const IMAGE_EXPORT_DIRECTORY *exports;
    DWORD exp_size;
    const IMAGE_THUNK_DATA *import_list;
    IMAGE_THUNK_DATA *thunk_list;
    SIZE_T i, import_count, arm64x_native_prefix_count = 0;
    WCHAR buffer[256];
    const char *name = image_rva_string( module, descr->Name );
    DWORD len;
    PVOID protect_base;
    SIZE_T protect_size = 0;
    DWORD protect_old;
    BOOL force_native_imports = FALSE;
    BOOL trace_pe32_loader = (current_machine == IMAGE_FILE_MACHINE_I386 && macrunner_hb_pe32_loader_trace_auto()) || macrunner_hb_trace_pe32_loader();

    if (!name)
    {
        WARN( "invalid import dll name rva %08lx in %s\n",
              (ULONG)descr->Name, debugstr_w(wm->ldr.FullDllName.Buffer) );
        if (trace_pe32_loader)
            MESSAGE( "macrunner-pe32-loader-fail: import_dll module=%s base=%p reason=invalid-name-rva name_rva=%08lx\n",
                     debugstr_w(wm->ldr.BaseDllName.Buffer), module, (ULONG)descr->Name );
        return FALSE;
    }
    len = strlen(name);

    thunk_list = get_rva( module, (DWORD)descr->FirstThunk );
    if (descr->OriginalFirstThunk)
        import_list = get_rva( module, (DWORD)descr->OriginalFirstThunk );
    else
        import_list = thunk_list;

    if (get_import_thunk_count( module, import_list, &import_count ) ||
        !image_contains_array( module, thunk_list, import_count + 1, sizeof(*thunk_list) ))
    {
        WARN( "invalid import thunk table for %s imported from %s\n",
              name, debugstr_w(wm->ldr.FullDllName.Buffer) );
        if (trace_pe32_loader)
            MESSAGE( "macrunner-pe32-loader-fail: import_dll module=%s base=%p dll=%s reason=invalid-thunk-table oft=%08lx ft=%08lx\n",
                     debugstr_w(wm->ldr.BaseDllName.Buffer), module, name,
                     (ULONG)descr->OriginalFirstThunk, (ULONG)descr->FirstThunk );
        return FALSE;
    }

    if (trace_pe32_loader)
        MESSAGE( "macrunner-pe32-loader: import_dll module=%s base=%p dll=%s oft=%08lx ft=%08lx first=%08Ix flags=%lx\n",
                 debugstr_w(wm->ldr.BaseDllName.Buffer), module, name, (ULONG)descr->OriginalFirstThunk,
                 (ULONG)descr->FirstThunk, (ULONG_PTR)import_list->u1.Ordinal, wm->ldr.Flags );

    if (!import_list->u1.Ordinal)
    {
        WARN( "Skipping unused import %s\n", name );
        *pwm = NULL;
        return TRUE;
    }

    for (i = 0; i < import_count; i++)
    {
        if (!IMAGE_SNAP_BY_ORDINAL(import_list[i].u1.Ordinal) &&
            !image_import_by_name( module, (DWORD)import_list[i].u1.AddressOfData ))
        {
            WARN( "invalid import-by-name rva %Ix for %s imported from %s\n",
                  (ULONG_PTR)import_list[i].u1.AddressOfData, name,
                  debugstr_w(wm->ldr.FullDllName.Buffer) );
            if (trace_pe32_loader)
                MESSAGE( "macrunner-pe32-loader-fail: import_dll module=%s base=%p dll=%s reason=invalid-import-by-name index=%Iu rva=%Ix\n",
                         debugstr_w(wm->ldr.BaseDllName.Buffer), module, name, i,
                         (ULONG_PTR)import_list[i].u1.AddressOfData );
            return FALSE;
        }
    }
    arm64x_native_prefix_count = macrunner_hb_arm64x_native_import_prefix_count( wm, import_list, thunk_list );

    status = build_import_name( wm, buffer, name, len );
    force_native_imports = macrunner_hb_x64_main_requested() &&
                           macrunner_hb_importer_is_native_wine_builtin( wm ) &&
                           current_machine == IMAGE_FILE_MACHINE_ARM64;
    if (!status) status = load_dll( load_path, buffer, 0, &wmImp, system );

    if (status)
    {
        if (status == STATUS_DLL_NOT_FOUND)
            ERR("Library %s (which is needed by %s) not found\n",
                name, debugstr_w(wm->ldr.FullDllName.Buffer));
        else
            ERR("Loading library %s (which is needed by %s) failed (error %lx).\n",
                name, debugstr_w(wm->ldr.FullDllName.Buffer), status);
        if (trace_pe32_loader)
            MESSAGE( "macrunner-pe32-loader-fail: import_dll module=%s base=%p dll=%s resolved=%s status=%08lx system=%u load_path=%s\n",
                     debugstr_w(wm->ldr.BaseDllName.Buffer), module, name,
                     debugstr_w(buffer), status, system, debugstr_w(load_path) );
        return FALSE;
    }

    if (force_native_imports)
    {
        IMAGE_NT_HEADERS *import_nt = RtlImageNtHeader( wmImp->ldr.DllBase );

        if (import_nt && import_nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            WINE_MODREF *native_wm;
            IMAGE_NT_HEADERS *native_nt;

            /*
             * Native ARM64 Wine builtins can be loaded in the same process as
             * AMD64 guest builtins.  Only fix the bad reuse case: if normal
             * Wine lookup handed a native importer an already-loaded AMD64 PE
             * module, load the exact aarch64-windows counterpart by full path.
             * A basename-only retry can still return the same AMD64 MODREF
             * from the process module list, so validate the replacement before
             * wiring it into a native dependency graph.
             */
            native_wm = macrunner_hb_load_native_counterpart_module( wmImp );
            native_nt = native_wm ? RtlImageNtHeader( native_wm->ldr.DllBase ) : NULL;
            if (native_nt && (native_nt->FileHeader.Machine == current_machine ||
                              macrunner_hb_get_arm64x_metadata( native_wm->ldr.DllBase )))
            {
                MESSAGE( "MacRunner HyperBridge native importer %s switched import %s from AMD64 %p to ARM64 %p\n",
                       debugstr_w(wm->ldr.BaseDllName.Buffer), name, wmImp->ldr.DllBase, native_wm->ldr.DllBase );
                wmImp = native_wm;
            }
            else
                MESSAGE( "MacRunner HyperBridge native importer %s could not switch import %s from AMD64 %p\n",
                       debugstr_w(wm->ldr.BaseDllName.Buffer), name, wmImp->ldr.DllBase );
        }
    }

    /* unprotect the import address table since it can be located in
     * readonly section */
    protect_base = thunk_list - arm64x_native_prefix_count;
    protect_size = (import_count + arm64x_native_prefix_count) * sizeof(*thunk_list);
    status = NtProtectVirtualMemory( NtCurrentProcess(), &protect_base,
                                     &protect_size, PAGE_READWRITE, &protect_old );
    if (status)
    {
        ERR( "Failed to make import address table writable for %s imported from %s, status %lx\n",
             name, debugstr_w(wm->ldr.FullDllName.Buffer), status );
        return FALSE;
    }

    /* MacRunner 2026-08-05 — след скобки защиты IAT, обе стороны.
     *
     * Проверяемая версия: скобка сама по себе верна (диапазон покрывает записываемые
     * слоты, статус проверяется), но NtProtectVirtualMemory работает СТРАНИЦАМИ.  Если
     * импорты двух модулей попали на одну страницу и правятся по очереди, то возврат
     * защиты вторым модулем делает страницу R-X ЦЕЛИКОМ — вместе со слотами первого,
     * который ещё пишет.  Это укладывается в наблюдаемое: 186 млн отказов записи по
     * одному адресу при формально корректной скобке.
     *
     * Печатаем округлённые ядром base/size (NtProtectVirtualMemory возвращает их
     * выровненными по странице) и tid — по ним видно перекрытие диапазонов. */
    {
        static unsigned iat_trace_count;
        if (iat_trace_count++ < 256)
            MESSAGE( "macrunner-hb-iat-protect: phase=open tid=%04x dll=%s importer=%s "
                     "base=%p size=%Ix pages=%p-%p old_prot=%lx\n",
                     (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread,
                     name, debugstr_w(wm->ldr.BaseDllName.Buffer),
                     protect_base, protect_size,
                     (void *)((ULONG_PTR)protect_base & ~(ULONG_PTR)0xfff),
                     (void *)(((ULONG_PTR)protect_base + protect_size + 0xfff) & ~(ULONG_PTR)0xfff),
                     protect_old );
    }

    if (macrunner_hb_x64_main_requested() && !strcmp( name, "ntdll.dll" ) &&
        !macrunner_hb_importer_is_native_wine_builtin( wm ))
    {
        IMAGE_NT_HEADERS *importer_nt = RtlImageNtHeader( wm->ldr.DllBase );
        WCHAR ntdllW[] = {'n','t','d','l','l','.','d','l','l',0};
        WINE_MODREF *guest_wm;

        if (importer_nt && importer_nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
            (guest_wm = find_basename_module_machine( ntdllW, IMAGE_FILE_MACHINE_AMD64 )))
            wmImp = guest_wm;
    }
    imp_mod = wmImp->ldr.DllBase;
    exports = RtlImageDirectoryEntryToData( imp_mod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &exp_size );

    if (!exports)
    {
        /* set all imported function to deadbeef */
        while (import_count--)
        {
            if (IMAGE_SNAP_BY_ORDINAL(import_list->u1.Ordinal))
            {
                int ordinal = IMAGE_ORDINAL(import_list->u1.Ordinal);
                WARN("No implementation for %s.%d", name, ordinal );
                thunk_list->u1.Function = allocate_stub( name, IntToPtr(ordinal) );
            }
            else
            {
                const IMAGE_IMPORT_BY_NAME *pe_name = image_import_by_name( module, (DWORD)import_list->u1.AddressOfData );
                WARN("No implementation for %s.%s", name, pe_name->Name );
                thunk_list->u1.Function = allocate_stub( name, (const char*)pe_name->Name );
            }
            WARN(" imported from %s, allocating stub %p\n",
                 debugstr_w(wm->ldr.FullDllName.Buffer),
                 (void *)thunk_list->u1.Function );
            import_list++;
            thunk_list++;
        }
        goto done;
    }

    macrunner_hb_resolve_arm64x_native_import_prefix( wm, wmImp, name, load_path,
                                                      import_list, thunk_list,
                                                      arm64x_native_prefix_count );

    while (import_count--)
    {
        if (IMAGE_SNAP_BY_ORDINAL(import_list->u1.Ordinal))
        {
            int ordinal = IMAGE_ORDINAL(import_list->u1.Ordinal);
            char ordinal_name[24];

            /* MacRunner 2026-08-05 — та же трассировка, что у ветки «по имени»: без неё
             * множество записей неполно.  Замер по одной только именной ветке дал 50918
             * записей и НИ ОДНОЙ в падающую страницу 0x87EFB727000, хотя скобку на неё
             * import_dll открывает пять раз (mpr.dll импортирует из user32/advapi32/
             * ucrtbase/kernel32/ntdll — все слоты на одной странице).  Значит запись идёт
             * либо здесь, либо вообще вне loader.c, и различить это можно только полным
             * множеством. */
            {
                /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: за гейтом. Потолок 4096 стоит НА
                 * ПРОЦЕСС, а процессов в прогоне много (wineboot, services, explorer, игра),
                 * отсюда 30 547 строк = 25.7% журнала. Лейн перешёл к замерам времени.
                 * MACRUNNER_HB_TRACE_IAT=1 возвращает трассу. */
                static unsigned slot_trace_ord;
                if (macrunner_hb_trace_iat_enabled() && slot_trace_ord++ < 4096)
                    MESSAGE( "macrunner-hb-iat-write: slot=%p dll=%s importer=%s ordinal=%d\n",
                             thunk_list, name, debugstr_w(wm->ldr.BaseDllName.Buffer), ordinal );
            }
            thunk_list->u1.Function = (ULONG_PTR)find_ordinal_export( imp_mod, exports, exp_size,
                                                                       ordinal - exports->Base, load_path, wm, FALSE );
            macrunner_hb_format_ordinal_import_name( ordinal_name, sizeof(ordinal_name), ordinal );
            if (force_native_imports)
                thunk_list->u1.Function = macrunner_hb_resolve_native_import_target( wmImp, name, ordinal_name,
                                                                                    thunk_list->u1.Function );
            if (!thunk_list->u1.Function)
            {
                thunk_list->u1.Function = allocate_stub( name, IntToPtr(ordinal) );
                WARN("No implementation for %s.%d imported from %s, setting to %p\n",
                     name, ordinal, debugstr_w(wm->ldr.FullDllName.Buffer),
                     (void *)thunk_list->u1.Function );
            }
            thunk_list->u1.Function = macrunner_hb_maybe_register_import_thunk( wm, wmImp, name,
                                                                                ordinal_name,
                                                                                thunk_list->u1.Function );
            TRACE_(imports)("--- Ordinal %s.%d = %p\n", name, ordinal, (void *)thunk_list->u1.Function );
        }
        else  /* import by name */
        {
            const IMAGE_IMPORT_BY_NAME *pe_name;
            pe_name = image_import_by_name( module, (DWORD)import_list->u1.AddressOfData );
            /* MacRunner 2026-08-05 — РЕШАЮЩИЙ ЗАМЕР: адрес КАЖДОЙ записи в слот.
             *
             * Отказ (SIGBUS, DFSC=0xf, права) приходит с PC ровно этой строки, а страница
             * при этом формально накрыта скобкой `import_dll`.  Учёт скобок сошёлся:
             * 1546 пар, 0 незакрытых, 0 случаев «внутренняя вернула READONLY под открытой
             * внешней».  Значит либо запись идёт не отсюда, либо защиту снимает кто-то
             * третий уже ПОСЛЕ открытия скобки.
             *
             * Сверка множеств решает спор: если адрес отказа есть в этом логе — писали мы
             * внутри скобки, и защиту отобрали снаружи; если адреса нет — пишет другой код.
             * Печать до записи, чтобы след остался даже если она упадёт. */
            {
                static unsigned slot_trace;
                if (macrunner_hb_trace_iat_enabled() && slot_trace++ < 4096)
                    MESSAGE( "macrunner-hb-iat-write: slot=%p dll=%s importer=%s import=%s\n",
                             thunk_list, name, debugstr_w(wm->ldr.BaseDllName.Buffer),
                             (const char *)pe_name->Name );
            }
            thunk_list->u1.Function = (ULONG_PTR)find_named_export( imp_mod, exports, exp_size,
                                                                     (const char*)pe_name->Name,
                                                                    pe_name->Hint, load_path, wm, FALSE );
            thunk_list->u1.Function = macrunner_hb_fix_native_import_target( wm, wmImp, name,
                                                                             (const char *)pe_name->Name,
                                                                             thunk_list->u1.Function );
            if (force_native_imports)
                thunk_list->u1.Function = macrunner_hb_resolve_native_import_target( wmImp, name,
                                                                                    (const char *)pe_name->Name,
                                                                                    thunk_list->u1.Function );
            if (!thunk_list->u1.Function)
            {
                thunk_list->u1.Function = allocate_stub( name, (const char*)pe_name->Name );
                WARN("No implementation for %s.%s imported from %s, setting to %p\n",
                     name, pe_name->Name, debugstr_w(wm->ldr.FullDllName.Buffer),
                     (void *)thunk_list->u1.Function );
            }
            thunk_list->u1.Function = macrunner_hb_maybe_register_import_thunk( wm, wmImp, name,
                                                                                (const char *)pe_name->Name,
                                                                                thunk_list->u1.Function );
            TRACE_(imports)("--- %s %s.%d = %p\n",
                            pe_name->Name, name, pe_name->Hint, (void *)thunk_list->u1.Function);
        }
        import_list++;
        thunk_list++;
    }

done:
    /* MacRunner 2026-08-05 — вторая половина следа: КОГДА и ЧЕМ защиту вернули.
     * Совпадение страниц этой строки с ещё не закрытым phase=open другого потока/модуля
     * и есть доказательство перекрытия. */
    {
        static unsigned iat_close_count;
        if (iat_close_count++ < 256)
            MESSAGE( "macrunner-hb-iat-protect: phase=close tid=%04x dll=%s importer=%s "
                     "base=%p size=%Ix pages=%p-%p restore_prot=%lx\n",
                     (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread,
                     name, debugstr_w(wm->ldr.BaseDllName.Buffer),
                     protect_base, protect_size,
                     (void *)((ULONG_PTR)protect_base & ~(ULONG_PTR)0xfff),
                     (void *)(((ULONG_PTR)protect_base + protect_size + 0xfff) & ~(ULONG_PTR)0xfff),
                     protect_old );
    }
    /* restore old protection of the import address table */
    status = NtProtectVirtualMemory( NtCurrentProcess(), &protect_base, &protect_size, protect_old, &protect_old );
    if (status)
    {
        ERR( "Failed to restore import address table protection for %s imported from %s, status %lx\n",
             name, debugstr_w(wm->ldr.FullDllName.Buffer), status );
        return FALSE;
    }
    *pwm = wmImp;
    return TRUE;
}


/***********************************************************************
 *           create_module_activation_context
 */
static NTSTATUS create_module_activation_context( LDR_DATA_TABLE_ENTRY *module )
{
    NTSTATUS status;
    LDR_RESOURCE_INFO info;
    const IMAGE_RESOURCE_DATA_ENTRY *entry;
    ULONG_PTR manifest_id = (module->Flags & LDR_IMAGE_IS_DLL) ?
        ISOLATIONAWARE_MANIFEST_RESOURCE_ID : CREATEPROCESS_MANIFEST_RESOURCE_ID;

    info.Type = RT_MANIFEST;
    info.Name = manifest_id;
    info.Language = 0;
    if (!(status = LdrFindResource_U( module->DllBase, &info, 3, &entry )))
    {
        ACTCTXW ctx;
        ctx.cbSize   = sizeof(ctx);
        ctx.lpSource = NULL;
        ctx.dwFlags  = ACTCTX_FLAG_RESOURCE_NAME_VALID | ACTCTX_FLAG_HMODULE_VALID;
        ctx.hModule  = module->DllBase;
        ctx.lpResourceName = (LPCWSTR)manifest_id;
        status = RtlCreateActivationContext( &module->ActivationContext, &ctx );
    }
    return status;
}


/*************************************************************************
 *		is_dll_native_subsystem
 *
 * Check if dll is a proper native driver.
 * Some dlls (corpol.dll from IE6 for instance) are incorrectly marked as native
 * while being perfectly normal DLLs.  This heuristic should catch such breakages.
 */
static BOOL is_dll_native_subsystem( LDR_DATA_TABLE_ENTRY *mod, const IMAGE_NT_HEADERS *nt, LPCWSTR filename )
{
    const IMAGE_IMPORT_DESCRIPTOR *imports;
    DWORD i, size;

    if (nt->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_NATIVE) return FALSE;
    if (nt->OptionalHeader.SectionAlignment < page_size) return TRUE;
    if (mod->Flags & LDR_WINE_INTERNAL) return TRUE;

    if ((imports = RtlImageDirectoryEntryToData( mod->DllBase, TRUE,
                                                 IMAGE_DIRECTORY_ENTRY_IMPORT, &size )))
    {
        DWORD nb_imports;

        if (get_import_descriptor_count( mod->DllBase, imports, size, &nb_imports ))
        {
            WARN( "%s has invalid import descriptors, assuming native subsystem\n", debugstr_w(filename) );
            return TRUE;
        }
        for (i = 0; i < nb_imports; i++)
            if (is_import_dll_system( mod, &imports[i] ))
            {
                TRACE( "%s imports system dll, assuming not native\n", debugstr_w(filename) );
                return FALSE;
            }
    }
    return TRUE;
}

/*************************************************************************
 *		alloc_tls_slot
 *
 * Allocate a TLS slot for a newly-loaded module.
 * The loader_section must be locked while calling this function.
 */
static BOOL get_tls_data_size( const IMAGE_TLS_DIRECTORY *dir, SIZE_T *size )
{
    ULONG_PTR start = dir->StartAddressOfRawData;
    ULONG_PTR end = dir->EndAddressOfRawData;

    if (end < start) return FALSE;
    *size = end - start;
    return *size <= (SIZE_T)-1 - dir->SizeOfZeroFill;
}

static BOOL validate_tls_directory( HMODULE module, const IMAGE_TLS_DIRECTORY *dir, SIZE_T *size )
{
    if (!get_tls_data_size( dir, size ))
    {
        WARN( "invalid TLS raw data range %p-%p in module %p\n",
              (void *)dir->StartAddressOfRawData, (void *)dir->EndAddressOfRawData, module );
        return FALSE;
    }
    if (!*size && !dir->SizeOfZeroFill && !dir->AddressOfCallBacks) return TRUE;

    if (!dir->AddressOfIndex ||
        !image_contains_range( module, (const void *)dir->AddressOfIndex, sizeof(DWORD) ))
    {
        WARN( "invalid TLS index pointer %p in module %p\n", (void *)dir->AddressOfIndex, module );
        return FALSE;
    }
    if (*size && !image_contains_range( module, (const void *)dir->StartAddressOfRawData, *size ))
    {
        WARN( "invalid TLS raw data range %p-%p in module %p\n",
              (void *)dir->StartAddressOfRawData, (void *)dir->EndAddressOfRawData, module );
        return FALSE;
    }
    if (dir->AddressOfCallBacks &&
        !image_contains_range( module, (const void *)dir->AddressOfCallBacks, sizeof(PIMAGE_TLS_CALLBACK) ))
    {
        WARN( "invalid TLS callback array %p in module %p\n", (void *)dir->AddressOfCallBacks, module );
        return FALSE;
    }
    return TRUE;
}

static BOOL alloc_tls_slot( LDR_DATA_TABLE_ENTRY *mod )
{
    unsigned int mr_tls_potokov = 0, mr_tls_vydano = 0, mr_tls_propushcheno = 0;
    const IMAGE_TLS_DIRECTORY *dir;
    ULONG i, dirsize;
    SIZE_T size;
    void *new_ptr;
    UINT old_module_count = tls_module_count;
    HANDLE thread = NULL, next;

    if (!(dir = RtlImageDirectoryEntryToData( mod->DllBase, TRUE, IMAGE_DIRECTORY_ENTRY_TLS, &dirsize )))
        return FALSE;

    if (!validate_tls_directory( mod->DllBase, dir, &size )) return FALSE;
    if (!size && !dir->SizeOfZeroFill && !dir->AddressOfCallBacks) return FALSE;

    for (i = 0; i < tls_module_count; i++)
    {
        if (!tls_dirs[i].StartAddressOfRawData && !tls_dirs[i].EndAddressOfRawData &&
            !tls_dirs[i].SizeOfZeroFill && !tls_dirs[i].AddressOfCallBacks)
            break;
    }

    TRACE( "module %p data %p-%p zerofill %lu index %p callback %p flags %lx -> slot %lu\n", mod->DllBase,
           (void *)dir->StartAddressOfRawData, (void *)dir->EndAddressOfRawData, dir->SizeOfZeroFill,
           (void *)dir->AddressOfIndex, (void *)dir->AddressOfCallBacks, dir->Characteristics, i );

    if (i == tls_module_count)
    {
        UINT new_count = tls_module_count * 2;

        new_ptr = RtlReAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY, tls_dirs,
                                     new_count * sizeof(*tls_dirs) );
        if (!new_ptr) return FALSE;
        tls_dirs = new_ptr;
        tls_module_count = new_count;
    }

    /* allocate the data block in all running threads */
    while (!NtGetNextThread( GetCurrentProcess(), thread, THREAD_QUERY_LIMITED_INFORMATION, 0, 0, &next ))
    {
        THREAD_BASIC_INFORMATION tbi;
        TEB *teb;

        if (thread) NtClose( thread );
        thread = next;
        if (NtQueryInformationThread( thread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL ) || !tbi.TebBaseAddress)
        {
            ERR( "NtQueryInformationThread failed.\n" );
            continue;
        }
        teb = tbi.TebBaseAddress;
        /* ★ 01.09.2026: здесь читается ХОЗЯЙСКИЙ TEB32 (координаты слоя WoW64), и он
         * долго был рассинхронизирован с гостевой копией: указатель на массив TLS жил
         * только в гостевой, а тут был ноль — поток объявлялся незаведённым, блок не
         * выдавался никому, и статический TLS падал (Half-Life,
         * FileSystem_Stdio.dll+0x8330, чтение [0+4]). Причина устранена ОБРАТНОЙ
         * синхронизацией в sync_teb32_to_guest (dlls/xtajit/unixlib.c, гейт
         * MACRUNNER_HB_TEB32_TLS_WRITEBACK). Заплатка «для себя брать свой TEB» была
         * снята: замер показал, что обратной синхронизации достаточно. */
        mr_tls_potokov++;
        if (!teb->ThreadLocalStoragePointer)
        {
            /* Thread is not initialized by loader yet or already teared down. */
            mr_tls_propushcheno++;
            MESSAGE( "macrunner-tls-пропуск: поток=%04lx без массива TLS (модуль=%p)\n",
                     HandleToULong(tbi.ClientId.UniqueThread), mod->DllBase );
            /* Опознание ИЗ ТОГО TEB, что вернул запрос: если поток там не наш (или ноль) —
             * адрес просто чужой; если наш — значит у потока ДВА разных TEB. */
            continue;
        }

        if (old_module_count < tls_module_count)
        {
            void **old = teb->ThreadLocalStoragePointer;
            void **new = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY, tls_module_count * sizeof(*new));

            if (!new)
            {
                NtClose( thread );
                return FALSE;
            }
            if (old) memcpy( new, old, old_module_count * sizeof(*new) );
            teb->ThreadLocalStoragePointer = new;
#ifdef __x86_64__  /* macOS-specific hack */
            if (teb->Instrumentation[0]) ((TEB *)teb->Instrumentation[0])->ThreadLocalStoragePointer = new;
#endif
            TRACE( "thread %04lx tls block %p -> %p\n", HandleToULong(teb->ClientId.UniqueThread), old, new );
            /* FIXME: can't free old block here, should be freed at thread exit */
        }

        if (!(new_ptr = RtlAllocateHeap( GetProcessHeap(), 0, size + dir->SizeOfZeroFill )))
        {
            NtClose( thread );
            return FALSE;
        }
        memcpy( new_ptr, (void *)dir->StartAddressOfRawData, size );
        memset( (char *)new_ptr + size, 0, dir->SizeOfZeroFill );

        TRACE( "thread %04lx slot %lu: %Iu/%lu bytes at %p\n",
               HandleToULong(teb->ClientId.UniqueThread), i, size, dir->SizeOfZeroFill, new_ptr );

        mr_tls_vydano++;
        RtlFreeHeap( GetProcessHeap(), 0,
                     InterlockedExchangePointer( (void **)teb->ThreadLocalStoragePointer + i, new_ptr ));
    }
    if (thread) NtClose( thread );

    *(DWORD *)dir->AddressOfIndex = i;
    tls_dirs[i] = *dir;
    /* ★ 01.09.2026 — TLS ПОД ПРИБОРОМ. Half-Life падает в FileSystem_Stdio.dll+0x8330
     * на `cmp 0x4(%edx),%eax`, где edx = tls_array[tls_index] и он НУЛЕВОЙ: чтение
     * [0+4] даёт c0000005 с info1=4. Нужно видеть, кому слот выдан, а кого пропустили. */
    MESSAGE( "macrunner-tls-слот: модуль=%p слот=%lu всего_модулей=%u потоков_видано=%u "
             "выдано=%u пропущено_без_массива=%u размер=%Iu+%lu\n",
             mod->DllBase, (unsigned long)i, tls_module_count, mr_tls_potokov,
             mr_tls_vydano, mr_tls_propushcheno, size, dir->SizeOfZeroFill );
    return TRUE;
}


/*************************************************************************
 *		free_tls_slot
 *
 * Free the module TLS slot on unload.
 * The loader_section must be locked while calling this function.
 */
static void free_tls_slot( LDR_DATA_TABLE_ENTRY *mod )
{
    const IMAGE_TLS_DIRECTORY *dir;
    ULONG i, dirsize;
    SIZE_T size;

    if (mod->TlsIndex != -1)
        return;
    if (!(dir = RtlImageDirectoryEntryToData( mod->DllBase, TRUE, IMAGE_DIRECTORY_ENTRY_TLS, &dirsize )))
        return;
    if (!validate_tls_directory( mod->DllBase, dir, &size ) || !dir->AddressOfIndex)
        return;

    i = *(ULONG*)dir->AddressOfIndex;
    assert( i < tls_module_count );
    memset( &tls_dirs[i], 0, sizeof(tls_dirs[i]) );
}


/****************************************************************
 *       fixup_imports_ilonly
 *
 * Fixup imports for an IL-only module. All we do is import mscoree.
 * The loader_section must be locked while calling this function.
 */
static NTSTATUS fixup_imports_ilonly( WINE_MODREF *wm, LPCWSTR load_path, void **entry )
{
    NTSTATUS status;
    void *proc;
    const char *name;
    WINE_MODREF *imp;

    if (!(wm->ldr.Flags & LDR_DONT_RESOLVE_REFS)) return STATUS_SUCCESS;  /* already done */
    wm->ldr.Flags &= ~LDR_DONT_RESOLVE_REFS;

    assert( !wm->ldr.DdagNode->Dependencies.Tail );
    if (!(status = load_dll( load_path, L"mscoree.dll", 0, &imp, FALSE ))
          && !add_module_dependency_after( wm->ldr.DdagNode, imp->ldr.DdagNode, NULL ))
        status = STATUS_NO_MEMORY;
    if (status)
    {
        ERR( "mscoree.dll not found, IL-only binary %s cannot be loaded\n",
             debugstr_w(wm->ldr.BaseDllName.Buffer) );
        return status;
    }

    TRACE( "loaded mscoree for %s\n", debugstr_w(wm->ldr.FullDllName.Buffer) );

    name = (wm->ldr.Flags & LDR_IMAGE_IS_DLL) ? "_CorDllMain" : "_CorExeMain";
    if (!(proc = RtlFindExportedRoutineByName( imp->ldr.DllBase, name ))) return STATUS_PROCEDURE_NOT_FOUND;
    *entry = proc;
    return STATUS_SUCCESS;
}


/****************************************************************
 *       fixup_imports
 *
 * Fixup all imports of a given module.
 * The loader_section must be locked while calling this function.
 */
static NTSTATUS fixup_imports( WINE_MODREF *wm, LPCWSTR load_path )
{
    const IMAGE_IMPORT_DESCRIPTOR *imports;
    SINGLE_LIST_ENTRY *dep_after;
    WINE_MODREF *imp;
    DWORD i, nb_imports;
    DWORD size;
    NTSTATUS status;
    ULONG_PTR cookie;
    BOOL trace_pe32_loader = (current_machine == IMAGE_FILE_MACHINE_I386 && macrunner_hb_pe32_loader_trace_auto()) || macrunner_hb_trace_pe32_loader();

    if (trace_pe32_loader)
    {   /* ★★★★★★ MacRunner 2026-09-01 — БАЗА СВОЕЙ ntdll.
         *
         * Здесь же стоит парный замер «кириллица в формате против раскладки»
         * (гейт MACRUNNER_HB_FMT_PROBE, руки ниже). Итог: алфавит строки формата
         * на отказы НЕ влияет — разбор в шапке гейта i386 выше. Прежний запрет
         * «строки формата только латиницей» СНЯТ как недоказанный. */
        static int mr_base_shown;
        if (!mr_base_shown)
        {
            MEMORY_BASIC_INFORMATION mbi;
            IMAGE_NT_HEADERS *nth;
            mr_base_shown = 1;
            if (!NtQueryVirtualMemory( GetCurrentProcess(), LdrInitializeThunk,
                                       MemoryBasicInformation, &mbi, sizeof(mbi), NULL ))
            {
                nth = RtlImageNtHeader( mbi.AllocationBase );
                /* ★ ПАРНЫЙ ЗАМЕР 01.09 — ОДИН ДВОИЧНЫЙ ФАЙЛ, ЧЕТЫРЕ РУКИ.
                 *
                 * Прошлый вывод «кириллица в формате роняет прогон» сравнивал "размер=%lx"
                 * (12 байт) с "size=%lx" (4 байта): менялись СРАЗУ алфавит, длина литерала
                 * и раскладка образа. У стены уже был случай, когда отказ зависел от
                 * РАСКЛАДКИ, а не от исполнения, — значит вывод был не доказан.
                 *
                 * Здесь все строки лежат в образе ОДНОВРЕМЕННО и равны по длине (12 байт
                 * до '='), а рука выбирается гейтом в прогоне:
                 *   MACRUNNER_HB_FMT_PROBE=0  печати нет (раскладка та же, исполнение другое)
                 *   MACRUNNER_HB_FMT_PROBE=1  латиница В ФОРМАТЕ
                 *   MACRUNNER_HB_FMT_PROBE=2  кириллица В ФОРМАТЕ
                 *   MACRUNNER_HB_FMT_PROBE=3  кириллица АРГУМЕНТОМ (умолчание)
                 * Раскладка тождественна во всех руках, поэтому различие в числе отказов
                 * может исходить только от исполняемых байтов. */
                WCHAR fmt_env[8] = {0};
                int fmt_ruka = 3;
                if (get_env( L"MACRUNNER_HB_FMT_PROBE", fmt_env, sizeof(fmt_env) ) && fmt_env[0])
                    fmt_ruka = fmt_env[0] - '0';
                
                if (fmt_ruka == 1)
                    MESSAGE( "macrunner-pe32-loader: self-ntdll base=%p razmerAAAAAA=%lx machine=%04x\n",
                             mbi.AllocationBase,
                             nth ? nth->OptionalHeader.SizeOfImage : 0,
                             nth ? nth->FileHeader.Machine : 0 );
                else if (fmt_ruka == 2)
                    MESSAGE( "macrunner-pe32-loader: self-ntdll base=%p размер=%lx machine=%04x\n",
                             mbi.AllocationBase,
                             nth ? nth->OptionalHeader.SizeOfImage : 0,
                             nth ? nth->FileHeader.Machine : 0 );
                else if (fmt_ruka == 3)
                    MESSAGE( "macrunner-pe32-loader: self-ntdll base=%p %s=%lx machine=%04x\n",
                             mbi.AllocationBase, "размер",
                             nth ? nth->OptionalHeader.SizeOfImage : 0,
                             nth ? nth->FileHeader.Machine : 0 );
            }
        }
    }
    if (trace_pe32_loader)
        MESSAGE( "macrunner-pe32-loader: fixup_imports enter module=%s base=%p flags=%lx machine=%04x\n",
                 debugstr_w(wm->ldr.BaseDllName.Buffer), wm->ldr.DllBase, wm->ldr.Flags,
                 RtlImageNtHeader( wm->ldr.DllBase ) ? RtlImageNtHeader( wm->ldr.DllBase )->FileHeader.Machine : 0 );

    if (!(wm->ldr.Flags & LDR_DONT_RESOLVE_REFS))
    {
        if (trace_pe32_loader)
            MESSAGE( "macrunner-pe32-loader: fixup_imports skip module=%s flags=%lx\n",
                     debugstr_w(wm->ldr.BaseDllName.Buffer), wm->ldr.Flags );
        return STATUS_SUCCESS;  /* already done */
    }
    wm->ldr.Flags &= ~LDR_DONT_RESOLVE_REFS;

    if (alloc_tls_slot( &wm->ldr )) wm->ldr.TlsIndex = -1;

    if (!(imports = RtlImageDirectoryEntryToData( wm->ldr.DllBase, TRUE,
                                                  IMAGE_DIRECTORY_ENTRY_IMPORT, &size )))
    {
        if (trace_pe32_loader)
            MESSAGE( "macrunner-pe32-loader: fixup_imports no-import-dir module=%s\n",
                     debugstr_w(wm->ldr.BaseDllName.Buffer) );
        return STATUS_SUCCESS;
    }

    if ((status = get_import_descriptor_count( wm->ldr.DllBase, imports, size, &nb_imports )))
    {
        WARN( "invalid import descriptor table in %s\n", debugstr_w(wm->ldr.FullDllName.Buffer) );
        return status;
    }

    if (trace_pe32_loader)
        MESSAGE( "macrunner-pe32-loader: fixup_imports descriptors module=%s count=%lu size=%lu\n",
                 debugstr_w(wm->ldr.BaseDllName.Buffer), nb_imports, size );

    if (!nb_imports) return STATUS_SUCCESS;  /* no imports */

    if (!create_module_activation_context( &wm->ldr ))
        RtlActivateActivationContext( 0, wm->ldr.ActivationContext, &cookie );

    /* load the imported modules. They are automatically
     * added to the modref list of the process.
     */
    status = STATUS_SUCCESS;
    for (i = 0; i < nb_imports; i++)
    {
        dep_after = wm->ldr.DdagNode->Dependencies.Tail;
        if (!import_dll( wm, &imports[i], load_path, &imp ))
        {
            const char *name = image_rva_string( wm->ldr.DllBase, imports[i].Name );

            if (trace_pe32_loader)
                MESSAGE( "macrunner-pe32-loader-fail: fixup_imports module=%s base=%p import_index=%lu dll=%s status=%08lx\n",
                         debugstr_w(wm->ldr.BaseDllName.Buffer), wm->ldr.DllBase, i,
                         name ? name : "<invalid>", STATUS_DLL_NOT_FOUND );
            status = STATUS_DLL_NOT_FOUND;
        }
        else if (imp && imp->ldr.DdagNode != node_ntdll && imp->ldr.DdagNode != node_kernel32)
            add_module_dependency_after( wm->ldr.DdagNode, imp->ldr.DdagNode, dep_after );
    }
    if (wm->ldr.ActivationContext) RtlDeactivateActivationContext( 0, cookie );
    return status;
}


/*************************************************************************
 *		alloc_module
 *
 * Allocate a WINE_MODREF structure and add it to the process list
 * The loader_section must be locked while calling this function.
 */
static WINE_MODREF *alloc_module( HMODULE hModule, const UNICODE_STRING *nt_name, BOOL builtin )
{
    WCHAR *buffer;
    WINE_MODREF *wm;
    const WCHAR *p;
    const IMAGE_NT_HEADERS *nt = RtlImageNtHeader(hModule);

    if (!(wm = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*wm) ))) return NULL;

    wm->ldr.DllBase       = hModule;
    wm->ldr.SizeOfImage   = nt->OptionalHeader.SizeOfImage;
    wm->ldr.Flags         = LDR_DONT_RESOLVE_REFS | (builtin ? LDR_WINE_INTERNAL : 0);
    wm->ldr.TlsIndex      = 0;
    wm->ldr.LoadCount     = 1;
    wm->CheckSum          = nt->OptionalHeader.CheckSum;
    wm->ldr.TimeDateStamp = nt->FileHeader.TimeDateStamp;

    if (!(buffer = RtlAllocateHeap( GetProcessHeap(), 0, nt_name->Length - 3 * sizeof(WCHAR) )))
    {
        RtlFreeHeap( GetProcessHeap(), 0, wm );
        return NULL;
    }

    if (!(wm->ldr.DdagNode = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*wm->ldr.DdagNode) )))
    {
        RtlFreeHeap( GetProcessHeap(), 0, buffer );
        RtlFreeHeap( GetProcessHeap(), 0, wm );
        return NULL;
    }
    InitializeListHead(&wm->ldr.DdagNode->Modules);
    InsertTailList(&wm->ldr.DdagNode->Modules, &wm->ldr.NodeModuleLink);

    if (nt_name->Length >= 8 * sizeof(WCHAR) && !wcsncmp(nt_name->Buffer + 4, L"UNC\\", 4))
    {
        buffer[0] = '\\';
        memcpy( buffer + 1, nt_name->Buffer + 7 /* \??\UNC prefix */, nt_name->Length - 7 * sizeof(WCHAR) );
        buffer[nt_name->Length/sizeof(WCHAR) - 6] = 0;
    }
    else
    {
        memcpy( buffer, nt_name->Buffer + 4 /* \??\ prefix */, nt_name->Length - 4 * sizeof(WCHAR) );
        buffer[nt_name->Length/sizeof(WCHAR) - 4] = 0;
    }
    if ((p = wcsrchr( buffer, '\\' ))) p++;
    else p = buffer;
    RtlInitUnicodeString( &wm->ldr.FullDllName, buffer );
    RtlInitUnicodeString( &wm->ldr.BaseDllName, p );

    if (!is_dll_native_subsystem( &wm->ldr, nt, p ))
    {
        if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL)
            wm->ldr.Flags |= LDR_IMAGE_IS_DLL;
        if (nt->OptionalHeader.AddressOfEntryPoint)
            wm->ldr.EntryPoint = image_rva_range( hModule, nt->OptionalHeader.AddressOfEntryPoint, 1 );
    }

    InsertTailList(&NtCurrentTeb()->Peb->LdrData->InLoadOrderModuleList,
                   &wm->ldr.InLoadOrderLinks);
    InsertTailList(&NtCurrentTeb()->Peb->LdrData->InMemoryOrderModuleList,
                   &wm->ldr.InMemoryOrderLinks);
    InsertTailList(&hash_table[hash_basename( &wm->ldr.BaseDllName )], &wm->ldr.HashLinks);
    if (rtl_rb_tree_put( &base_address_index_tree, wm->ldr.DllBase, &wm->ldr.BaseAddressIndexNode, base_address_compare ))
        ERR( "rtl_rb_tree_put failed.\n" );
    /* wait until init is called for inserting into InInitializationOrderModuleList */

    if (!(nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT))
    {
        ULONG flags = MEM_EXECUTE_OPTION_ENABLE;
        WARN( "disabling no-exec because of %s\n", debugstr_w(wm->ldr.BaseDllName.Buffer) );
        NtSetInformationProcess( GetCurrentProcess(), ProcessExecuteFlags, &flags, sizeof(flags) );
    }
    return wm;
}


/*************************************************************************
 *              alloc_thread_tls
 *
 * Allocate the per-thread structure for module TLS storage.
 */
static NTSTATUS alloc_thread_tls(void)
{
    void **pointers;
    UINT i;
    SIZE_T size;

    if (!(pointers = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY,
                                      tls_module_count * sizeof(*pointers) )))
        return STATUS_NO_MEMORY;

    for (i = 0; i < tls_module_count; i++)
    {
        const IMAGE_TLS_DIRECTORY *dir = &tls_dirs[i];

        if (!get_tls_data_size( dir, &size )) continue;
        if (!size && !dir->SizeOfZeroFill) continue;

        if (!(pointers[i] = RtlAllocateHeap( GetProcessHeap(), 0, size + dir->SizeOfZeroFill )))
        {
            while (i) RtlFreeHeap( GetProcessHeap(), 0, pointers[--i] );
            RtlFreeHeap( GetProcessHeap(), 0, pointers );
            return STATUS_NO_MEMORY;
        }
        memcpy( pointers[i], (void *)dir->StartAddressOfRawData, size );
        memset( (char *)pointers[i] + size, 0, dir->SizeOfZeroFill );

        TRACE( "slot %u: %Iu/%lu bytes at %p\n", i, size, dir->SizeOfZeroFill, pointers[i] );
    }
    NtCurrentTeb()->ThreadLocalStoragePointer = pointers;
#ifdef __x86_64__  /* macOS-specific hack */
    if (NtCurrentTeb()->Instrumentation[0])
        ((TEB *)NtCurrentTeb()->Instrumentation[0])->ThreadLocalStoragePointer = pointers;
#endif
    return STATUS_SUCCESS;
}


/*************************************************************************
 *              call_tls_callbacks
 */
static BOOL macrunner_hb_call_x64_tls_callback( HMODULE module, PIMAGE_TLS_CALLBACK callback,
                                                UINT reason, NTSTATUS *status )
{
    IMAGE_NT_HEADERS *nt;
    struct macrunner_hb_x64_dll_entry_params params;

    if (!macrunner_hb_amd64_main_on_arm64) return FALSE;
    if (!(nt = RtlImageNtHeader( module )) || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return FALSE;
    /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 1003 — ARM64EC НЕ ЕСТЬ x64.
     * У ARM64EC-образа поле Machine и ДОЛЖНО читаться как AMD64 — в этом весь смысл EC:
     * загрузчик x64 обязан его принять. Но код по его точкам входа НАТИВНЫЙ ARM64, и гнать
     * его через транслятор x86 нельзя. Замерено на `artifacts/ntdll_test_ec.exe`: обратный
     * вызов TLS `__dyn_tls_init` (0x140016c9c, при разборе — `stp x19,x20,[sp,#-0x30]!`)
     * уходил в x64-дорогу, отказывал и возвращался тем же адресом через обработчик сигнала:
     * 58 повторов, до `main` дело не доходило ни разу.
     * Признак различения — метаданные ARM64X/CHPE: у настоящего x64-образа их нет. */
    if (macrunner_hb_get_arm64x_metadata( module )) return FALSE;

    memset( &params, 0, sizeof(params) );
    params.entry = callback;
    params.module = module;
    params.reason = reason;

    if (macrunner_hb_trace_bootstrap())
        MESSAGE( "macrunner-hb-bootstrap-tls-callback: module=%p callback=%p reason=%s\n",
                 module, callback, reason_names[reason] );
    *status = WINE_UNIX_CALL( unix_macrunner_hb_x64_dll_entry, &params );
    if (macrunner_hb_trace_bootstrap())
        MESSAGE( "macrunner-hb-bootstrap-tls-callback-return: module=%p callback=%p "
                 "status=%lx ret=%u blocks=%s steps=%s\n",
                 module, callback, *status, (unsigned int)params.ret,
                 wine_dbgstr_longlong(params.blocks), wine_dbgstr_longlong(params.steps) );
    return TRUE;
}

static BOOL macrunner_hb_call_x64_cdecl_one_arg( HMODULE module, void *entry, void *arg,
                                                  NTSTATUS *status, ULONG *ret )
{
    IMAGE_NT_HEADERS *nt;
    struct macrunner_hb_x64_dll_entry_params params;

    if (!macrunner_hb_amd64_main_on_arm64) return FALSE;
    if (!(nt = RtlImageNtHeader( module )) || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return FALSE;

    memset( &params, 0, sizeof(params) );
    params.entry = entry;
    params.module = module;
    params.arg0 = arg;
    *status = WINE_UNIX_CALL( unix_macrunner_hb_x64_dll_entry, &params );
    if (ret) *ret = params.ret;
    return TRUE;
}

#define MACRUNNER_HB_LANGUAGE_OBSERVER_BOOTSTRAP_VERSION 0x484b4c32u

struct macrunner_hb_language_observer_bootstrap
{
    ULONG version;
    ULONG introspection_enabled;
    HMODULE mono_module;
    const char *description;
};

typedef void (CDECL *macrunner_hb_language_observer_init_fn)(
    const struct macrunner_hb_language_observer_bootstrap *bootstrap );

struct macrunner_hb_language_observer_context
{
    HMODULE volatile mono_module;
    HMODULE profiler_module;
    macrunner_hb_language_observer_init_fn profiler_init;
    LONG armed;
    LONG cancelled;
};

static struct macrunner_hb_language_observer_context macrunner_hb_language_observer_context;
static LONG macrunner_hb_language_observer_started;

static BOOL macrunner_hb_prepare_language_observer(
    HMODULE *profiler_module, macrunner_hb_language_observer_init_fn *profiler_init )
{
    static const UNICODE_STRING profiler_name =
        RTL_CONSTANT_STRING( L"mono-profiler-hk_language.dll" );
    static const char export_name[] = "macrunner_hb_profiler_init_hk_language";
    ANSI_STRING name = { sizeof(export_name) - 1, sizeof(export_name), (char *)export_name };
    NTSTATUS status;

    status = LdrLoadDll( NULL, 0, &profiler_name, profiler_module );
    if (status)
    {
        MESSAGE( "macrunner-hb-language-flow: event=bootstrap-failed status=%08lx "
             "stage=observer-dll-load\n", status );
        return FALSE;
    }
    status = LdrGetProcedureAddress( *profiler_module, &name, 0, (void **)profiler_init );
    if (status)
    {
        MESSAGE( "macrunner-hb-language-flow: event=bootstrap-failed status=%08lx "
             "stage=observer-init-export\n", status );
        return FALSE;
    }
    return TRUE;
}

static void macrunner_hb_initialize_language_observer(
    const struct macrunner_hb_language_observer_context *context )
{
    static const char description[] = "hk_language";
    struct macrunner_hb_language_observer_bootstrap bootstrap;
    NTSTATUS status;

    bootstrap.version = MACRUNNER_HB_LANGUAGE_OBSERVER_BOOTSTRAP_VERSION;
    bootstrap.introspection_enabled = 1;
    bootstrap.mono_module = context->mono_module;
    bootstrap.description = description;

    if (macrunner_hb_call_x64_cdecl_one_arg( context->profiler_module,
                                              context->profiler_init, &bootstrap, &status, NULL ))
    {
        if (status)
            MESSAGE( "macrunner-hb-language-flow: event=bootstrap-failed status=%08lx "
                 "stage=observer-init-call\n", status );
        return;
    }
    context->profiler_init( &bootstrap );
}

static void *macrunner_hb_mono_rel32_target( HMODULE module, const BYTE *next,
                                              const BYTE *disp_ptr, SIZE_T size )
{
    ULONG_PTR address = (ULONG_PTR)next;
    LONGLONG delta;
    LONG disp;

    memcpy( &disp, disp_ptr, sizeof(disp) );
    delta = disp;
    if (delta < 0)
    {
        delta = -delta;
        if (address < (ULONG_PTR)delta) return NULL;
        address -= delta;
    }
    else
    {
        if (address > ~(ULONG_PTR)0 - (ULONG_PTR)delta) return NULL;
        address += delta;
    }
    if (!image_contains_range( module, (const void *)address, size )) return NULL;
    return (void *)address;
}

static void WINAPI macrunner_hb_language_observer_worker( void *arg )
{
    static const char export_name[] = "mono_profiler_enable_call_context_introspection";
    void *enable_introspection;
    void *hook;
    void *volatile *introspection_hook;
    volatile LONG *call_contexts;
    volatile LONG *startup_done;
    const BYTE *code;
    struct macrunner_hb_language_observer_context *context = arg;
    HMODULE mono_module = NULL;
    LARGE_INTEGER counter, delay, frequency, spin_until;
    ULONG i;
    NTSTATUS status;

    if (InterlockedCompareExchange( &context->cancelled, 0, 0 ))
    {
        InterlockedExchange( &context->armed, -1 );
        return;
    }

    InterlockedExchange( &context->armed, 1 );
    delay.QuadPart = -10000;
    for (i = 0; i < 5000; i++)
    {
        if (InterlockedCompareExchange( &context->cancelled, 0, 0 ))
        {
            InterlockedExchange( &context->armed, -1 );
            return;
        }
        mono_module = InterlockedCompareExchangePointer( (void *volatile *)&context->mono_module,
                                                          NULL, NULL );
        if (mono_module) break;
        NtDelayExecution( FALSE, &delay );
    }
    if (!mono_module)
    {
        MESSAGE( "macrunner-hb-language-flow: event=bootstrap-failed status=%08lx "
             "stage=mono-module-publish-timeout\n", STATUS_TIMEOUT );
        InterlockedExchange( &context->armed, -1 );
        return;
    }

    enable_introspection = RtlFindExportedRoutineByName( mono_module, export_name );
    if (!enable_introspection)
    {
        MESSAGE( "macrunner-hb-language-flow: event=bootstrap-failed status=%08lx "
             "stage=mono-introspection-export\n", STATUS_PROCEDURE_NOT_FOUND );
        InterlockedExchange( &context->armed, -1 );
        return;
    }

    code = (const BYTE *)enable_introspection;
    if (!image_contains_range( mono_module, code, 46 ) ||
        code[0] != 0x48 || code[1] != 0x83 || code[2] != 0xec || code[3] != 0x28 ||
        code[4] != 0x83 || code[5] != 0x3d || code[10] != 0x00 ||
        code[11] != 0x74 || code[12] != 0x07 || code[20] != 0xff || code[21] != 0x15 ||
        code[26] != 0xb8 || code[27] != 0x01 || code[28] != 0x00 ||
        code[29] != 0x00 || code[30] != 0x00 || code[31] != 0xc7 || code[32] != 0x05 ||
        code[37] != 0x01 || code[38] != 0x00 || code[39] != 0x00 || code[40] != 0x00 ||
        code[41] != 0x48 || code[42] != 0x83 || code[43] != 0xc4 ||
        code[44] != 0x28 || code[45] != 0xc3 ||
        !(startup_done = macrunner_hb_mono_rel32_target( mono_module, code + 11,
                                                         code + 6, sizeof(*startup_done) )) ||
        !(introspection_hook = macrunner_hb_mono_rel32_target( mono_module, code + 26,
                                                               code + 22, sizeof(*introspection_hook) )) ||
        !(call_contexts = macrunner_hb_mono_rel32_target( mono_module, code + 41,
                                                          code + 33, sizeof(*call_contexts) )))
    {
        MESSAGE( "macrunner-hb-language-flow: event=bootstrap-failed status=%08lx "
             "stage=mono-introspection-export-shape\n", STATUS_INVALID_IMAGE_FORMAT );
        InterlockedExchange( &context->armed, -1 );
        return;
    }

    NtQueryPerformanceCounter( &counter, &frequency );
    spin_until.QuadPart = counter.QuadPart + 2 * frequency.QuadPart;
    InterlockedExchange( &context->armed, 2 );
    i = 0;
    for (;;)
    {
        if (InterlockedCompareExchange( &context->cancelled, 0, 0 )) return;
        hook = InterlockedCompareExchangePointer( introspection_hook, NULL, NULL );
        if (hook)
        {
            if (!image_contains_range( mono_module, hook, 1 ))
            {
                MESSAGE( "macrunner-hb-language-flow: event=bootstrap-failed status=%08lx "
                     "stage=mono-introspection-hook-target\n", STATUS_INVALID_IMAGE_FORMAT );
                return;
            }
            if (macrunner_hb_call_x64_cdecl_one_arg( mono_module, hook, NULL,
                                                      &status, NULL ))
            {
                if (status)
                {
                    MESSAGE( "macrunner-hb-language-flow: event=bootstrap-failed status=%08lx "
                         "stage=mono-introspection-hook-call\n", status );
                    return;
                }
            }
            else ((void (CDECL *)(void))hook)();
            InterlockedExchange( call_contexts, 1 );
            macrunner_hb_initialize_language_observer( context );
            return;
        }
        if (InterlockedCompareExchange( startup_done, 0, 0 ))
        {
            MESSAGE( "macrunner-hb-language-flow: event=bootstrap-failed status=%08lx "
                 "stage=mono-introspection-startup-done\n", STATUS_INVALID_DEVICE_STATE );
            return;
        }
        NtQueryPerformanceCounter( &counter, NULL );
        if (counter.QuadPart < spin_until.QuadPart)
        {
            YieldProcessor();
            continue;
        }
        if (i++ == 120000) break;
        NtDelayExecution( FALSE, &delay );
    }

    MESSAGE( "macrunner-hb-language-flow: event=bootstrap-failed status=%08lx "
         "stage=mono-introspection-ready-timeout\n", STATUS_TIMEOUT );
}

static BOOL macrunner_hb_start_language_observer(
    HMODULE profiler_module, macrunner_hb_language_observer_init_fn profiler_init )
{
    struct macrunner_hb_language_observer_context *context =
        &macrunner_hb_language_observer_context;
    HANDLE thread;
    NTSTATUS status;

    if (InterlockedCompareExchange( &macrunner_hb_language_observer_started, 1, 0 )) return FALSE;
    InterlockedExchangePointer( (void *volatile *)&context->mono_module, NULL );
    context->profiler_module = profiler_module;
    context->profiler_init = profiler_init;
    InterlockedExchange( &context->armed, 0 );
    InterlockedExchange( &context->cancelled, 0 );
    status = RtlCreateUserThread( GetCurrentProcess(), NULL, FALSE, 0, 0, 0,
                                  macrunner_hb_language_observer_worker, context,
                                  &thread, NULL );
    if (status)
    {
        InterlockedExchange( &context->armed, -1 );
        InterlockedExchange( &macrunner_hb_language_observer_started, 0 );
        MESSAGE( "macrunner-hb-language-flow: event=bootstrap-failed status=%08lx "
             "stage=observer-worker-create\n", status );
        return FALSE;
    }
    NtClose( thread );
    return TRUE;
}

static BOOL macrunner_hb_wait_language_observer_state( LONG expected, const char *timeout_stage )
{
    struct macrunner_hb_language_observer_context *context =
        &macrunner_hb_language_observer_context;
    LARGE_INTEGER delay;
    LONG state;
    ULONG i;

    delay.QuadPart = -10000;
    for (i = 0; i < 5000; i++)
    {
        state = InterlockedCompareExchange( &context->armed, 0, 0 );
        if (state >= expected) return TRUE;
        if (state < 0) return FALSE;
        NtDelayExecution( FALSE, &delay );
    }
    InterlockedExchange( &context->cancelled, 1 );
    MESSAGE( "macrunner-hb-language-flow: event=bootstrap-failed status=%08lx "
         "stage=%s\n", STATUS_TIMEOUT, timeout_stage );
    return FALSE;
}

static BOOL macrunner_hb_publish_language_observer_mono( HMODULE mono_module )
{
    InterlockedExchangePointer(
        (void *volatile *)&macrunner_hb_language_observer_context.mono_module, mono_module );
    return macrunner_hb_wait_language_observer_state( 2, "observer-worker-arm-timeout" );
}

static void macrunner_hb_cancel_language_observer(void)
{
    if (!InterlockedCompareExchange( &macrunner_hb_language_observer_started, 0, 0 )) return;
    InterlockedExchange( &macrunner_hb_language_observer_context.cancelled, 1 );
}

static BOOL macrunner_hb_is_exact_mono_name( const UNICODE_STRING *name )
{
    static const UNICODE_STRING mono_name = RTL_CONSTANT_STRING( L"mono-2.0-bdwgc.dll" );
    UNICODE_STRING basename;
    USHORT chars, i, start = 0;

    if (!name || !name->Buffer || name->Length % sizeof(WCHAR)) return FALSE;
    chars = name->Length / sizeof(WCHAR);
    for (i = 0; i < chars; i++)
        if (name->Buffer[i] == '/' || name->Buffer[i] == '\\') start = i + 1;
    basename.Buffer = name->Buffer + start;
    basename.Length = (chars - start) * sizeof(WCHAR);
    basename.MaximumLength = basename.Length;
    return RtlEqualUnicodeString( &basename, &mono_name, TRUE );
}

static void call_tls_callbacks( HMODULE module, UINT reason )
{
    const IMAGE_TLS_DIRECTORY *dir;
    const PIMAGE_TLS_CALLBACK *callback;
    ULONG dirsize;
    NTSTATUS status;

    dir = RtlImageDirectoryEntryToData( module, TRUE, IMAGE_DIRECTORY_ENTRY_TLS, &dirsize );
    if (!dir || !dir->AddressOfCallBacks) return;
    if (!image_contains_range( module, (const void *)dir->AddressOfCallBacks, sizeof(*callback) ))
    {
        TRACE_(relay)("\1invalid TLS callback array (callbacks=%p,module=%p,reason=%s)\n",
                      (void *)dir->AddressOfCallBacks, module, reason_names[reason] );
        return;
    }

    for (callback = (const PIMAGE_TLS_CALLBACK *)dir->AddressOfCallBacks;; callback++)
    {
        PIMAGE_TLS_CALLBACK proc;

        if (!image_contains_range( module, callback, sizeof(*callback) ))
        {
            TRACE_(relay)("\1invalid TLS callback slot (callback=%p,module=%p,reason=%s)\n",
                          callback, module, reason_names[reason] );
            return;
        }
        __TRY
        {
            proc = *callback;
        }
        __EXCEPT_ALL
        {
            TRACE_(relay)("\1exception %08lx reading TLS callback array (callbacks=%p,module=%p,reason=%s)\n",
                          GetExceptionCode(), callback, module, reason_names[reason] );
            return;
        }
        __ENDTRY

        if (!proc) break;

        TRACE_(relay)("\1Call TLS callback (proc=%p,module=%p,reason=%s,reserved=0)\n",
                      proc, module, reason_names[reason] );
        __TRY
        {
            if (macrunner_hb_call_x64_tls_callback( module, proc, reason, &status ))
            {
                if (status)
                {
                    TRACE_(relay)("\1exception %08lx in TLS callback (proc=%p,module=%p,reason=%s,reserved=0)\n",
                                  status, proc, module, reason_names[reason] );
                    return;
                }
            }
            else call_dll_entry_point( (DLLENTRYPROC)proc, module, reason, NULL );
        }
        __EXCEPT_ALL
        {
            TRACE_(relay)("\1exception %08lx in TLS callback (proc=%p,module=%p,reason=%s,reserved=0)\n",
                          GetExceptionCode(), proc, module, reason_names[reason] );
            return;
        }
        __ENDTRY
        TRACE_(relay)("\1Ret  TLS callback (proc=%p,module=%p,reason=%s,reserved=0)\n",
                      *callback, module, reason_names[reason] );
    }
}

/*************************************************************************
 *              MODULE_InitDLL
 */
static NTSTATUS MODULE_InitDLL( WINE_MODREF *wm, UINT reason, LPVOID lpReserved )
{
    WCHAR mod_name[64];
    NTSTATUS status = STATUS_SUCCESS;
    DLLENTRYPROC entry = wm->ldr.EntryPoint;
    void *module = wm->ldr.DllBase;
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( module );
    BOOL retv = FALSE;

    /* MacRunner 2026-07-29 (HK DllMain lane) -- UNGATED, and placed before EVERY early return
     * in this function on purpose.  This lane's standing trap is that a probe sitting inside
     * one branch cannot distinguish "took the other branch" from "never got here", so its
     * silence proves nothing.  This one fires for winemac.drv whatever happens next: it
     * reports the two inputs that decide the route (image machine + LDR_WINE_INTERNAL) and
     * the flags that can short-circuit the call, so a run log always says which route was
     * taken.  MESSAGE() survives WINEDEBUG=-all.
     *
     * PROCESS_* ONLY, restricted 2026-07-29 after measuring the cost of not restricting it.
     * The first version printed for every reason, and a verify run logged 45 of these by
     * +117 s -- 43 of them THREAD_ATTACH.  The reason is structural, not incidental: DllMain
     * is what calls DisableThreadLibraryCalls(), so whenever winemac.drv's entry does NOT run
     * (the default), thread notifications are never suppressed and this probe fires once per
     * thread for the life of the process.  HK creates >100.  The routing question this probe
     * exists to answer is a PROCESS_ATTACH question, so the thread reasons were pure noise on
     * an already throughput-starved boot. */
    if (wm->ldr.BaseDllName.Buffer && !wcsicmp( wm->ldr.BaseDllName.Buffer, L"winemac.drv" ) &&
        (reason == DLL_PROCESS_ATTACH || reason == DLL_PROCESS_DETACH))
        MESSAGE( "macrunner-hb-winemac-initdll: reason=%s machine=%04x flags=%08lx entry=%p "
                 "x64main=%u gate=%u natgate=%u\n",
                 reason < ARRAY_SIZE(reason_names) ? reason_names[reason] : "?",
                 nt ? nt->FileHeader.Machine : 0, wm->ldr.Flags, entry,
                 macrunner_hb_amd64_main_on_arm64, macrunner_hb_winemac_x64_dllmain_enabled(),
                 macrunner_hb_winemac_native_dllmain_enabled() );

    /* Skip calls for modules loaded with special load flags */

    if (wm->ldr.Flags & LDR_DONT_RESOLVE_REFS) return STATUS_SUCCESS;
    if (wm->ldr.TlsIndex == -1) call_tls_callbacks( wm->ldr.DllBase, reason );
    if (!entry) return STATUS_SUCCESS;

    if (TRACE_ON(relay))
    {
        size_t len = min( wm->ldr.BaseDllName.Length, sizeof(mod_name)-sizeof(WCHAR) );
        memcpy( mod_name, wm->ldr.BaseDllName.Buffer, len );
        mod_name[len / sizeof(WCHAR)] = 0;
        TRACE_(relay)("\1Call PE DLL (proc=%p,module=%p %s,reason=%s,res=%p)\n",
                      entry, module, debugstr_w(mod_name), reason_names[reason], lpReserved );
    }
    else TRACE("(%p %s,%s,%p) - CALL\n", module, debugstr_w(wm->ldr.BaseDllName.Buffer),
               reason_names[reason], lpReserved );

    __TRY
    {
        if (macrunner_hb_amd64_main_on_arm64 && nt && nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            struct macrunner_hb_x64_dll_entry_params params;
            DLLENTRYPROC header_entry = nt->OptionalHeader.AddressOfEntryPoint ?
                image_rva_range( module, nt->OptionalHeader.AddressOfEntryPoint, 1 ) : NULL;

            if (header_entry && entry != header_entry)
            {
                if (macrunner_hb_trace_bootstrap())
                    MESSAGE( "macrunner-hb-bootstrap-dll-entry-fixup: module=%s old=%p header=%p aep=%lx\n",
                             debugstr_w(wm->ldr.BaseDllName.Buffer), entry, header_entry,
                             (ULONG)nt->OptionalHeader.AddressOfEntryPoint );
                entry = header_entry;
            }

            /* ★ 2026-08-18, итерация 2408 — зонд входа убран: он ответил (участок
             * исполняется, модули внутренние — замер 2387) и печатал на каждом модуле. */

            if (wm->ldr.Flags & LDR_WINE_INTERNAL)
            {
                /* user32: its process_attach publishes Peb->KernelCallbackTable;
                 * with the entry skipped the table stays NULL and every win32u
                 * kernel callback (window-proc dispatch) faults at [NULL+id*8],
                 * so the window can never be driven.  Native user32 callbacks
                 * reach the guest WNDPROC through the x64 callback route. */
                BOOL needs_native_entry = !wcsicmp( wm->ldr.BaseDllName.Buffer, L"win32u.dll" ) ||
                                          !wcsicmp( wm->ldr.BaseDllName.Buffer, L"kernelbase.dll" ) ||
                                          !wcsicmp( wm->ldr.BaseDllName.Buffer, L"user32.dll" ) ||
                /* ucrtbase.dll: skipping its DllMain loses msvcrt_init_args(), so the guest CRT
                 * starts with __argc=0, __argv=NULL, _acmdln=NULL, _pgmptr=NULL.  Same class as
                 * win32u's KernelCallbackTable and winemetal's unixlib handle.  See
                 * macrunner_hb_ucrtbase_native_dllmain_enabled() for the measured chain. */
                                          macrunner_hb_native_dllmain_all_enabled() ||
                                          (macrunner_hb_ucrtbase_native_dllmain_enabled() &&
                                           !wcsicmp( wm->ldr.BaseDllName.Buffer, L"ucrtbase.dll" )) ||
                /* winemac.drv: run its DllMain as native ARM64 instead of as x64 guest code,
                 * so the HyperBridge fault router the x64 route wedges in is never reached.
                 * Inert unless the ARM64X build is the one at the pinned system32 path -- see
                 * macrunner_hb_winemac_native_dllmain_enabled() for the measured two-part
                 * chain and why a missing half degrades to the unchanged skip. */
                                          (macrunner_hb_winemac_native_dllmain_enabled() &&
                                           !wcsicmp( wm->ldr.BaseDllName.Buffer, L"winemac.drv" ));
                /* winemetal.dll is a builtin that carries a Wine unixlib (DXMT's Metal bridge):
                 * unlike the other graphics frontends its x64 DllMain MUST run, because it calls
                 * __wine_init_unix_call to publish __wine_unixlib_handle.  If skipped, the handle
                 * stays 0 and every WINE_UNIX_CALL dispatches through a null funcs table
                 * (WMTCopyAllDevices()==0 -> no Metal adapter -> D3D11CreateDevice==0x887A0002).
                 * It has no native ARM64 entry (pure x86_64 PE), so route it through the x64 entry
                 * path below instead of the skip. */
                BOOL needs_x64_entry = (macrunner_hb_winemetal_x64_dllmain_enabled() &&
                                        !wcsicmp( wm->ldr.BaseDllName.Buffer, L"winemetal.dll" )) ||
                /* winemac.drv: same class as winemetal.dll (builtin + own unixlib), and
                 * additionally the only builtin here with no native aarch64 twin, so the
                 * skip left it with no route at all.  See
                 * macrunner_hb_winemac_x64_dllmain_enabled() for the measured chain. */
                                       (macrunner_hb_winemac_x64_dllmain_enabled() &&
                                        !wcsicmp( wm->ldr.BaseDllName.Buffer, L"winemac.drv" ));
                DLLENTRYPROC native_entry = NULL;

                /* Fill the ARM64X dispatch slots for EVERY hybrid builtin at
                 * attach: __icall_helper_arm64ec loads __os_arm64x_dispatch_icall
                 * and branches through it, so a NULL slot is a branch-to-zero
                 * (ws2_32 died this way during Mono/Unity init, lr=...3fa4).
                 * The update only inspects this module's own headers/metadata —
                 * no LDR recursion; the recursion warning below applies to the
                 * native-entry lookup, which stays allowlisted. */
                if (reason == DLL_PROCESS_ATTACH)
                    macrunner_hb_update_arm64x_native_dispatch_metadata( wm );

                /*
                 * Most AMD64 Wine builtins are intentionally not executed in
                 * HyperBridge; their public imports are routed to native ARM64
                 * thunks instead.  Only the small set below needs a native
                 * entry call for dispatcher/runtime setup.  kernelbase ARM64X
                 * entries currently resolve to native ARM64 code; handing those
                 * addresses to the x64 runner decodes ARM64 bytes as x64.
                 * Looking up ARM64X metadata for every skipped builtin can
                 * recurse through complex helper DLLs (notably comctl32) before
                 * they are initialized, so keep that lookup behind the narrow
                 * allowlist.
                 */
                if (macrunner_hb_trace_bootstrap())
                    MESSAGE( "macrunner-hb-bootstrap-native-entry-path: module=%s needs=%u before-lookup\n",
                             debugstr_w(wm->ldr.BaseDllName.Buffer), needs_native_entry );
                if (needs_native_entry) native_entry = macrunner_hb_get_native_arm64x_entry( wm );
                if (macrunner_hb_trace_bootstrap())
                    MESSAGE( "macrunner-hb-bootstrap-native-entry-path: module=%s native_entry=%p after-lookup\n",
                             debugstr_w(wm->ldr.BaseDllName.Buffer), native_entry );

                /* UNGATED, winemac.drv only.  The native route has exactly one way to fail
                 * silently -- macrunner_hb_get_native_arm64x_entry() returns NULL when the file
                 * at the pinned system32 path is the pure-AMD64 build instead of the ARM64X one
                 * -- and that failure is INVISIBLE downstream, because it degrades into the same
                 * skip the default already takes.  Without this line, "the native gate did
                 * nothing" and "the native gate was never on" produce identical logs, which is
                 * this lane's oldest trap.  natentry=0000000000000000 means part 1 of the pair
                 * (MACRUNNER_PREFIX_WINEMAC_NATIVE) did not land, not that the gate is wrong. */
                if (wm->ldr.BaseDllName.Buffer && !wcsicmp( wm->ldr.BaseDllName.Buffer, L"winemac.drv" ) &&
                    (reason == DLL_PROCESS_ATTACH || reason == DLL_PROCESS_DETACH))
                    MESSAGE( "macrunner-hb-winemac-natentry: reason=%s natgate=%u needs_native=%u "
                             "natentry=%p\n",
                             reason < ARRAY_SIZE(reason_names) ? reason_names[reason] : "?",
                             macrunner_hb_winemac_native_dllmain_enabled(), needs_native_entry,
                             native_entry );

                if (needs_native_entry && reason == DLL_PROCESS_ATTACH)
                {
                    if (macrunner_hb_trace_bootstrap())
                        MESSAGE( "macrunner-hb-bootstrap-native-entry-path: module=%s before-metadata-update\n",
                                 debugstr_w(wm->ldr.BaseDllName.Buffer) );
                    macrunner_hb_update_arm64x_native_dispatch_metadata( wm );
                    if (macrunner_hb_trace_bootstrap())
                        MESSAGE( "macrunner-hb-bootstrap-native-entry-path: module=%s after-metadata-update\n",
                                 debugstr_w(wm->ldr.BaseDllName.Buffer) );
                }

                if (native_entry)
                {
                    /* MacRunner 2026-07-29 (HK DllMain lane): the resolved native entry can sit
                     * in a live-mapped NON-executable page -- measured for winemac.drv in HK's
                     * guest process, where it SIGILLs on the first instruction.  Probe the
                     * protection for every module taking this branch and repair winemac.drv's.
                     * See macrunner_hb_make_native_entry_executable() for the measurement. */
                    macrunner_hb_make_native_entry_executable( wm, native_entry );

                    /* MacRunner 2026-07-29 (HK DllMain lane, iter 10).  SPLIT the remaining
                     * failure space in two with one call.
                     *
                     * Measured across FOUR structurally different routes (x64 entry; native entry
                     * on a prefix-swapped copy; ARM64EC body of a properly loaded twin; and iter 9,
                     * the pure-ARM64 body of that twin): the loader reaches the line right before
                     * call_dll_entry_point and the thread then spins 6353/6353 in
                     * macrunner_hb_redirect_arm64x_hexpthk_sigill.  `stage=dllmain_attach` -- the
                     * FIRST statement of DllMain -- never prints.  But that statement is
                     * macdrv_pe_trace(), which itself calls out through imports (GetStdHandle /
                     * WriteFile / MESSAGE), so its absence does NOT distinguish:
                     *   (a) the CALL MECHANISM faults (entry prologue / ABI / unwind), from
                     *   (b) the call lands fine and the first IMPORT out of DllMain faults.
                     * Those have opposite fixes, and everything downstream of them is in
                     * ntdll/unix/macrunner_hb.c, which this lane may not touch -- so handing the
                     * owner of that file the wrong half would cost another day.
                     *
                     * winemac.drv's DllMain is `if (reason != DLL_PROCESS_ATTACH) return TRUE;`
                     * (dllmain.c), i.e. for DLL_THREAD_ATTACH the body is a pure no-op that issues
                     * NO imports.  So calling THIS SAME ENTRY with DLL_THREAD_ATTACH exercises the
                     * call mechanism alone:
                     *   returns  -> mechanism is fine, the fault is (b), the first import call;
                     *   wedges   -> the fault is (a), before any of winemac.drv's own code runs.
                     * Both probes print, so silence is interpretable either way.
                     *
                     * Default OFF; winemac.drv only; opt in with
                     * MACRUNNER_HB_WINEMAC_ENTRY_PROBE=1.  Harmless when it returns: a spurious
                     * THREAD_ATTACH to a DllMain that ignores every reason but PROCESS_ATTACH. */
                    if (reason == DLL_PROCESS_ATTACH && macrunner_hb_winemac_entry_probe_enabled() &&
                        wm->ldr.BaseDllName.Buffer &&
                        !wcsicmp( wm->ldr.BaseDllName.Buffer, L"winemac.drv" ))
                    {
                        BOOL probe_ret;
                        MESSAGE( "macrunner-hb-winemac-entryprobe: phase=before entry=%p reason=THREAD_ATTACH\n",
                                 native_entry );
                        probe_ret = call_dll_entry_point( native_entry, module, DLL_THREAD_ATTACH, NULL );
                        MESSAGE( "macrunner-hb-winemac-entryprobe: phase=after ret=%u -- CALL MECHANISM OK, "
                                 "so the wedge is in DllMain's own first import\n", (unsigned int)probe_ret );
                    }

                    if (macrunner_hb_trace_bootstrap())
                        MESSAGE( "macrunner-hb-bootstrap-native-entry-path: module=%s call-native-entry=%p\n",
                                 debugstr_w(wm->ldr.BaseDllName.Buffer), native_entry );
                    MESSAGE( "MacRunner HyperBridge calling native ARM64 builtin DLL entry %s: %p -> %p\n",
                           debugstr_w(wm->ldr.BaseDllName.Buffer), entry, native_entry );
                    retv = call_dll_entry_point( native_entry, module, reason, lpReserved );
                    if (macrunner_hb_trace_bootstrap())
                        MESSAGE( "macrunner-hb-bootstrap-native-entry-path: module=%s native-entry-return ret=%u\n",
                                 debugstr_w(wm->ldr.BaseDllName.Buffer), retv );
                    if (retv && reason == DLL_PROCESS_ATTACH)
                        macrunner_hb_sync_win32u_syscall_dispatcher_aliases( wm );
                    status = STATUS_SUCCESS;
                    goto done_call;
                }

                if (!needs_x64_entry)
                {
                    if (macrunner_hb_trace_bootstrap())
                        MESSAGE( "macrunner-hb-bootstrap-dll-entry-skip: module=%s reason=%s\n",
                                 debugstr_w(wm->ldr.BaseDllName.Buffer), reason_names[reason] );
                    /* Итерация 1357: ровно здесь теряется `msvcrt_init_args`. Заполняем сами,
                     * под гейтом; без гейта вызов инертен (первая же проверка выходит). */
                    if (reason == DLL_PROCESS_ATTACH) macrunner_hb_fill_crt_argv( wm );
                    retv = TRUE;
                    status = STATUS_SUCCESS;
                    goto done_call;
                }
                if (macrunner_hb_trace_bootstrap())
                    MESSAGE( "macrunner-hb-bootstrap-dll-entry-x64-unixlib: module=%s reason=%s entry=%p\n",
                             debugstr_w(wm->ldr.BaseDllName.Buffer), reason_names[reason], entry );
                /* fall through to the x64 entry path so winemetal's DllMain runs */
            }

            memset( &params, 0, sizeof(params) );
            params.entry = entry;
            params.module = module;
            params.reason = reason;
            params.reserved = lpReserved;

            if (macrunner_hb_trace_bootstrap())
                MESSAGE( "macrunner-hb-bootstrap-dll-entry: module=%s entry=%p reason=%s module_base=%p\n",
                         debugstr_w(wm->ldr.BaseDllName.Buffer), entry, reason_names[reason], module );
            status = WINE_UNIX_CALL( unix_macrunner_hb_x64_dll_entry, &params );
            retv = params.ret;
            if (macrunner_hb_trace_bootstrap())
                MESSAGE( "macrunner-hb-bootstrap-dll-entry-return: module=%s status=%lx ret=%u blocks=%s steps=%s\n",
                         debugstr_w(wm->ldr.BaseDllName.Buffer), status, (unsigned int)params.ret,
                         wine_dbgstr_longlong(params.blocks), wine_dbgstr_longlong(params.steps) );
            MESSAGE( "MacRunner HyperBridge x64 entry %s returned status=%lx ret=%u blocks=%s steps=%s\n",
                   debugstr_w(wm->ldr.BaseDllName.Buffer), status, (unsigned int)params.ret,
                   wine_dbgstr_longlong(params.blocks), wine_dbgstr_longlong(params.steps) );
        }
        else retv = call_dll_entry_point( entry, module, reason, lpReserved );
done_call:
        if (status == STATUS_SUCCESS && !retv)
            status = STATUS_DLL_INIT_FAILED;
    }
    __EXCEPT_ALL
    {
        status = GetExceptionCode();
        TRACE_(relay)("\1exception %08lx in PE entry point (proc=%p,module=%p,reason=%s,res=%p)\n",
                      status, entry, module, reason_names[reason], lpReserved );
    }
    __ENDTRY

    /* The state of the module list may have changed due to the call
       to the dll. We cannot assume that this module has not been
       deleted.  */
    if (TRACE_ON(relay))
        TRACE_(relay)("\1Ret  PE DLL (proc=%p,module=%p %s,reason=%s,res=%p) retval=%x\n",
                      entry, module, debugstr_w(mod_name), reason_names[reason], lpReserved, retv );
    else
        TRACE("(%p,%s,%p) - RETURN %d\n", module, reason_names[reason], lpReserved, retv );

    return status;
}


/*************************************************************************
 *		process_attach
 *
 * Send the process attach notification to all DLLs the given module
 * depends on (recursively). This is somewhat complicated due to the fact that
 *
 * - we have to respect the module dependencies, i.e. modules implicitly
 *   referenced by another module have to be initialized before the module
 *   itself can be initialized
 *
 * - the initialization routine of a DLL can itself call LoadLibrary,
 *   thereby introducing a whole new set of dependencies (even involving
 *   the 'old' modules) at any time during the whole process
 *
 * (Note that this routine can be recursively entered not only directly
 *  from itself, but also via LoadLibrary from one of the called initialization
 *  routines.)
 *
 * Furthermore, we need to rearrange the main WINE_MODREF list to allow
 * the process *detach* notifications to be sent in the correct order.
 * This must not only take into account module dependencies, but also
 * 'hidden' dependencies created by modules calling LoadLibrary in their
 * attach notification routine.
 *
 * The strategy is rather simple: we move a WINE_MODREF to the head of the
 * list after the attach notification has returned.  This implies that the
 * detach notifications are called in the reverse of the sequence the attach
 * notifications *returned*.
 *
 * The loader_section must be locked while calling this function.
 */
static NTSTATUS process_attach( LDR_DDAG_NODE *node, LPVOID lpReserved )
{
    NTSTATUS status = STATUS_SUCCESS;
    LDR_DATA_TABLE_ENTRY *mod;
    ULONG_PTR cookie;
    WINE_MODREF *wm;

    if (process_detaching) return status;

    mod = CONTAINING_RECORD( node->Modules.Flink, LDR_DATA_TABLE_ENTRY, NodeModuleLink );
    wm = CONTAINING_RECORD( mod, WINE_MODREF, ldr );

    /* Skip initialization entirely if requested */
    if (wm->ldr.Flags & LDR_DONT_RESOLVE_REFS)
        return status;

    /* prevent infinite recursion in case of cyclical dependencies */
    if (    ( wm->ldr.Flags & LDR_LOAD_IN_PROGRESS )
         || ( wm->ldr.Flags & LDR_PROCESS_ATTACHED ) )
        return status;

    TRACE("(%s,%p) - START\n", debugstr_w(wm->ldr.BaseDllName.Buffer), lpReserved );
    if (macrunner_hb_trace_bootstrap())
    {
        IMAGE_NT_HEADERS *nt = RtlImageNtHeader( wm->ldr.DllBase );
        MESSAGE( "macrunner-hb-bootstrap-process-attach-start: module=%s machine=%04x flags=%lx entry=%p\n",
                 debugstr_w(wm->ldr.BaseDllName.Buffer), nt ? nt->FileHeader.Machine : 0,
                 wm->ldr.Flags, wm->ldr.EntryPoint );
    }

    /* Tag current MODREF to prevent recursive loop */
    wm->ldr.Flags |= LDR_LOAD_IN_PROGRESS;
    if (lpReserved) wm->ldr.LoadCount = -1;  /* pin it if imported by the main exe */
    if (wm->ldr.ActivationContext) RtlActivateActivationContext( 0, wm->ldr.ActivationContext, &cookie );

    /* Recursively attach all DLLs this one depends on */
    status = walk_node_dependencies( node, lpReserved, process_attach );
    if (macrunner_hb_trace_bootstrap())
        MESSAGE( "macrunner-hb-bootstrap-process-attach-after-deps: module=%s status=%lx\n",
                 debugstr_w(wm->ldr.BaseDllName.Buffer), status );

    if (!wm->ldr.InInitializationOrderLinks.Flink)
        InsertTailList(&NtCurrentTeb()->Peb->LdrData->InInitializationOrderModuleList,
                &wm->ldr.InInitializationOrderLinks);

    /* Call DLL entry point */
    if (status == STATUS_SUCCESS)
    {
        call_ldr_notifications( LDR_DLL_NOTIFICATION_REASON_LOADED, &wm->ldr );
        if (macrunner_hb_trace_bootstrap())
            MESSAGE( "macrunner-hb-bootstrap-process-attach-before-initdll: module=%s entry=%p\n",
                     debugstr_w(wm->ldr.BaseDllName.Buffer), wm->ldr.EntryPoint );
        status = MODULE_InitDLL( wm, DLL_PROCESS_ATTACH, lpReserved );
        if (macrunner_hb_trace_bootstrap())
            MESSAGE( "macrunner-hb-bootstrap-process-attach-after-initdll: module=%s status=%lx\n",
                     debugstr_w(wm->ldr.BaseDllName.Buffer), status );
        if (status == STATUS_SUCCESS)
        {
            wm->ldr.Flags |= LDR_PROCESS_ATTACHED;
        }
        else
        {
            MODULE_InitDLL( wm, DLL_PROCESS_DETACH, lpReserved );
            call_ldr_notifications( LDR_DLL_NOTIFICATION_REASON_UNLOADED, &wm->ldr );

            /* point to the name so LdrInitializeThunk can print it */
            last_failed_modref = wm;
            WARN("Initialization of %s failed\n", debugstr_w(wm->ldr.BaseDllName.Buffer));
        }
    }

    if (wm->ldr.ActivationContext) RtlDeactivateActivationContext( 0, cookie );
    /* Remove recursion flag */
    wm->ldr.Flags &= ~LDR_LOAD_IN_PROGRESS;

    TRACE("(%s,%p) - END\n", debugstr_w(wm->ldr.BaseDllName.Buffer), lpReserved );
    return status;
}


/*************************************************************************
 *		process_detach
 *
 * Send DLL process detach notifications.  See the comment about calling
 * sequence at process_attach.
 */
static void process_detach(void)
{
    PLIST_ENTRY mark, entry;
    PLDR_DATA_TABLE_ENTRY mod;

    mark = &NtCurrentTeb()->Peb->LdrData->InInitializationOrderModuleList;
    do
    {
        for (entry = mark->Blink; entry != mark; entry = entry->Blink)
        {
            mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY,
                                    InInitializationOrderLinks);
            /* Check whether to detach this DLL */
            if ( !(mod->Flags & LDR_PROCESS_ATTACHED) )
                continue;
            if ( mod->LoadCount && !process_detaching )
                continue;

            /* Call detach notification */
            mod->Flags &= ~LDR_PROCESS_ATTACHED;
            MODULE_InitDLL( CONTAINING_RECORD(mod, WINE_MODREF, ldr), 
                            DLL_PROCESS_DETACH, ULongToPtr(process_detaching) );
            call_ldr_notifications( LDR_DLL_NOTIFICATION_REASON_UNLOADED, mod );

            /* Restart at head of WINE_MODREF list, as entries might have
               been added and/or removed while performing the call ... */
            break;
        }
    } while (entry != mark);
}

/*************************************************************************
 *		thread_attach
 *
 * Send DLL thread attach notifications. These are sent in the
 * reverse sequence of process detach notification.
 * The loader_section must be locked while calling this function.
 */
static void thread_attach(void)
{
    PLIST_ENTRY mark, entry;
    PLDR_DATA_TABLE_ENTRY mod;

    mark = &NtCurrentTeb()->Peb->LdrData->InInitializationOrderModuleList;
    for (entry = mark->Flink; entry != mark; entry = entry->Flink)
    {
        mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY,
                                InInitializationOrderLinks);
        if ( !(mod->Flags & LDR_PROCESS_ATTACHED) )
            continue;
        if ( mod->Flags & LDR_NO_DLL_CALLS )
            continue;

        MODULE_InitDLL( CONTAINING_RECORD(mod, WINE_MODREF, ldr), DLL_THREAD_ATTACH, NULL );
    }
}

/******************************************************************
 *		LdrDisableThreadCalloutsForDll (NTDLL.@)
 *
 */
NTSTATUS WINAPI LdrDisableThreadCalloutsForDll(HMODULE hModule)
{
    WINE_MODREF *wm;
    NTSTATUS    ret = STATUS_SUCCESS;

    RtlEnterCriticalSection( &loader_section );

    wm = get_modref( hModule );
    if (!wm || wm->ldr.TlsIndex == -1)
        ret = STATUS_DLL_NOT_FOUND;
    else
        wm->ldr.Flags |= LDR_NO_DLL_CALLS;

    RtlLeaveCriticalSection( &loader_section );

    return ret;
}

/* compare base address */
static int module_address_search_compare( const void *key, const RTL_BALANCED_NODE *entry )
{
    const LDR_DATA_TABLE_ENTRY *mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode);
    ULONG_PTR addr = (ULONG_PTR)key, base = (ULONG_PTR)mod->DllBase;

    if (addr < base) return -1;
    if (mod->SizeOfImage > ~(ULONG_PTR)0 - base || addr >= base + mod->SizeOfImage) return 1;
    return 0;
}

/******************************************************************
 *              LdrFindEntryForAddress (NTDLL.@)
 *
 * The loader_section must be locked while calling this function
 */
NTSTATUS WINAPI LdrFindEntryForAddress( const void *addr, PLDR_DATA_TABLE_ENTRY *pmod )
{
    RTL_BALANCED_NODE *node;

    if (!(node = rtl_rb_tree_get( &base_address_index_tree, addr, module_address_search_compare )))
        return STATUS_NO_MORE_ENTRIES;
    *pmod = CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode);
    return STATUS_SUCCESS;
}

/******************************************************************
 *              LdrEnumerateLoadedModules (NTDLL.@)
 */
NTSTATUS WINAPI LdrEnumerateLoadedModules( void *unknown, LDRENUMPROC callback, void *context )
{
    LIST_ENTRY *mark, *entry;
    LDR_DATA_TABLE_ENTRY *mod;
    BOOLEAN stop = FALSE;

    TRACE( "(%p, %p, %p)\n", unknown, callback, context );

    if (unknown || !callback)
        return STATUS_INVALID_PARAMETER;

    RtlEnterCriticalSection( &loader_section );

    mark = &NtCurrentTeb()->Peb->LdrData->InMemoryOrderModuleList;
    for (entry = mark->Flink; entry != mark; entry = entry->Flink)
    {
        mod = CONTAINING_RECORD( entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
        callback( mod, context, &stop );
        if (stop) break;
    }

    RtlLeaveCriticalSection( &loader_section );
    return STATUS_SUCCESS;
}

/******************************************************************
 *              LdrRegisterDllNotification (NTDLL.@)
 */
NTSTATUS WINAPI LdrRegisterDllNotification(ULONG flags, PLDR_DLL_NOTIFICATION_FUNCTION callback,
                                           void *context, void **cookie)
{
    struct ldr_notification *notify;

    TRACE( "(%lx, %p, %p, %p)\n", flags, callback, context, cookie );

    if (!callback || !cookie)
        return STATUS_INVALID_PARAMETER;

    if (flags)
        FIXME( "ignoring flags %lx\n", flags );

    notify = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*notify) );
    if (!notify) return STATUS_NO_MEMORY;
    notify->callback = callback;
    notify->context = context;

    RtlEnterCriticalSection( &loader_section );
    list_add_tail( &ldr_notifications, &notify->entry );
    RtlLeaveCriticalSection( &loader_section );

    *cookie = notify;
    return STATUS_SUCCESS;
}

/******************************************************************
 *              LdrUnregisterDllNotification (NTDLL.@)
 */
NTSTATUS WINAPI LdrUnregisterDllNotification( void *cookie )
{
    struct ldr_notification *notify = cookie;

    TRACE( "(%p)\n", cookie );

    if (!notify) return STATUS_INVALID_PARAMETER;

    RtlEnterCriticalSection( &loader_section );
    list_remove( &notify->entry );
    RtlLeaveCriticalSection( &loader_section );

    RtlFreeHeap( GetProcessHeap(), 0, notify );
    return STATUS_SUCCESS;
}

/******************************************************************
 *		LdrLockLoaderLock  (NTDLL.@)
 *
 * Note: some flags are not implemented.
 * Flag 0x01 is used to raise exceptions on errors.
 */
NTSTATUS WINAPI LdrLockLoaderLock( ULONG flags, ULONG *result, ULONG_PTR *magic )
{
    if (flags & ~0x2) FIXME( "flags %lx not supported\n", flags );

    if (result) *result = 0;
    if (magic) *magic = 0;
    if (flags & ~0x3) return STATUS_INVALID_PARAMETER_1;
    if (!result && (flags & 0x2)) return STATUS_INVALID_PARAMETER_2;
    if (!magic) return STATUS_INVALID_PARAMETER_3;

    if (flags & 0x2)
    {
        if (!RtlTryEnterCriticalSection( &loader_section ))
        {
            *result = 2;
            return STATUS_SUCCESS;
        }
        *result = 1;
    }
    else
    {
        RtlEnterCriticalSection( &loader_section );
        if (result) *result = 1;
    }
    *magic = GetCurrentThreadId();
    return STATUS_SUCCESS;
}


/******************************************************************
 *		LdrUnlockLoaderUnlock  (NTDLL.@)
 */
NTSTATUS WINAPI LdrUnlockLoaderLock( ULONG flags, ULONG_PTR magic )
{
    if (magic)
    {
        if (magic != GetCurrentThreadId()) return STATUS_INVALID_PARAMETER_2;
        RtlLeaveCriticalSection( &loader_section );
    }
    return STATUS_SUCCESS;
}


/******************************************************************
 *		LdrGetProcedureAddress  (NTDLL.@)
 */
NTSTATUS WINAPI LdrGetProcedureAddress(HMODULE module, const ANSI_STRING *name,
                                       ULONG ord, PVOID *address)
{
    IMAGE_EXPORT_DIRECTORY *exports;
    WINE_MODREF *wm;
    DWORD exp_size;
    NTSTATUS ret = STATUS_PROCEDURE_NOT_FOUND;

    RtlEnterCriticalSection( &loader_section );

    /* check if the module itself is invalid to return the proper error */
    if (!(wm = get_modref( module ))) ret = STATUS_DLL_NOT_FOUND;
    else if ((exports = RtlImageDirectoryEntryToData( module, TRUE,
                                                      IMAGE_DIRECTORY_ENTRY_EXPORT, &exp_size )))
    {
        void *proc = name ? find_named_export( module, exports, exp_size, name->Buffer, -1, NULL, wm, TRUE )
                          : find_ordinal_export( module, exports, exp_size, ord - exports->Base, NULL, wm, TRUE );
        if (proc)
        {
            *address = proc;
            ret = STATUS_SUCCESS;
        }
        else
        {
            /* MacRunner 2026-08-27 — НАЗЫВАТЬ НЕНАЙДЕННУЮ ФУНКЦИЮ.
             *
             * Heroes III умирает так: xdd.dll (DDrawCompat) получает нулевой адрес функции,
             * идёт по нему раскручивать цепочку батутов (`movb (%edi),%al` / `cmpb $0xe9` —
             * JMP rel32 / rel8 / FF 25), читает по нулю и вызывает __fastfail.
             *
             * Кто именно не нашёлся — видно только здесь, и стояло это под WARN, то есть в
             * обычном прогоне молчало. Печатаем безусловно: имя функции и модуль. */
            static unsigned int miss_n;
            unsigned int mn = ++miss_n;

            if (mn <= 64 || !(mn % 256))
                MESSAGE( "macrunner-ldr-proc-miss: n=%u функция=%s порядковый=%lu модуль=%s\n",
                     mn, debugstr_a(name ? name->Buffer : NULL), ord,
                     debugstr_us(&wm->ldr.FullDllName) );
            WARN( "%s (ordinal %lu) not found in %s\n", debugstr_a(name ? name->Buffer : NULL),
                  ord, debugstr_us(&wm->ldr.FullDllName) );
        }
    }

    RtlLeaveCriticalSection( &loader_section );
    return ret;
}


/***********************************************************************
 *           set_security_cookie
 *
 * Create a random security cookie for buffer overflow protection. Make
 * sure it does not accidentally match the default cookie value.
 */
static void set_security_cookie( ULONG_PTR *cookie )
{
    static ULONG seed;

    TRACE( "initializing security cookie %p\n", cookie );

    if (!seed) seed = NtGetTickCount() ^ GetCurrentProcessId();
    for (;;)
    {
        if (*cookie == DEFAULT_SECURITY_COOKIE_16)
            *cookie = RtlRandom( &seed ) >> 16; /* leave the high word clear */
        else if (*cookie == DEFAULT_SECURITY_COOKIE_32)
            *cookie = RtlRandom( &seed );
#ifdef DEFAULT_SECURITY_COOKIE_64
        else if (*cookie == DEFAULT_SECURITY_COOKIE_64)
        {
            *cookie = RtlRandom( &seed );
            /* fill up, but keep the highest word clear */
            *cookie ^= (ULONG_PTR)RtlRandom( &seed ) << 16;
        }
#endif
        else
            break;
    }
}


/***********************************************************************
 *           update_load_config
 */
static void update_load_config( void *module )
{
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( module );
    IMAGE_LOAD_CONFIG_DIRECTORY *cfg;
    ULONG_PTR base = (ULONG_PTR)module, end;
    ULONG size;

    if (!nt || nt->OptionalHeader.SizeOfImage > ~(ULONG_PTR)0 - base) return;
    end = base + nt->OptionalHeader.SizeOfImage;
    cfg = RtlImageDirectoryEntryToData( module, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size );
    if (!cfg) return;
    size = min( size, cfg->Size );
    if (size > offsetof( IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie ) &&
        cfg->SecurityCookie > base && cfg->SecurityCookie < end)
    {
        set_security_cookie( (ULONG_PTR *)cfg->SecurityCookie );
    }
#ifdef __arm64ec__
    if (size > offsetof( IMAGE_LOAD_CONFIG_DIRECTORY, CHPEMetadataPointer ) &&
        cfg->CHPEMetadataPointer > base && cfg->CHPEMetadataPointer < end)
    {
        arm64ec_update_hybrid_metadata( module, nt, (void *)cfg->CHPEMetadataPointer );
    }
#endif
}


static BOOL image_section_raw_range_fits( const IMAGE_SECTION_HEADER *sec, SIZE_T image_size,
                                          SIZE_T *size )
{
    SIZE_T rva = sec->VirtualAddress;

    *size = sec->SizeOfRawData;
    if (!*size) return TRUE;
    return rva < image_size && *size <= image_size - rva;
}

static BOOL image_relocation_block_targets_fit( const IMAGE_BASE_RELOCATION *rel, SIZE_T image_size )
{
    const USHORT *fixup = (const USHORT *)(rel + 1);
    ULONG count = (rel->SizeOfBlock - sizeof(*rel)) / sizeof(*fixup);

    while (count--)
    {
        USHORT entry = *fixup++;
        SIZE_T offset = entry & 0xfff;
        SIZE_T size = 0, rva;

        switch (entry >> 12)
        {
        case IMAGE_REL_BASED_ABSOLUTE:
            continue;
        case IMAGE_REL_BASED_HIGH:
        case IMAGE_REL_BASED_LOW:
        case IMAGE_REL_BASED_HIGHADJ:
            size = sizeof(short);
            if ((entry >> 12) == IMAGE_REL_BASED_HIGHADJ)
            {
                if (!count) return FALSE;
                fixup++;
                count--;
            }
            break;
        case IMAGE_REL_BASED_HIGHLOW:
            size = sizeof(int);
            break;
#ifdef _WIN64
        case IMAGE_REL_BASED_DIR64:
            size = sizeof(INT_PTR);
            break;
#elif defined(__arm__)
        case IMAGE_REL_BASED_THUMB_MOV32:
            size = 2 * sizeof(UINT);
            break;
#endif
        default:
            return FALSE;
        }
        if (rel->VirtualAddress > image_size || offset > image_size - rel->VirtualAddress) return FALSE;
        rva = rel->VirtualAddress + offset;
        if (size > image_size - rva) return FALSE;
    }
    return TRUE;
}


static NTSTATUS perform_relocations( void *module, IMAGE_NT_HEADERS *nt, SIZE_T len )
{
    char *base;
    IMAGE_BASE_RELOCATION *rel, *end;
    const IMAGE_DATA_DIRECTORY *relocs;
    const IMAGE_SECTION_HEADER *sec;
    INT_PTR delta;
    ULONG *protect_old, i;
    NTSTATUS status = STATUS_SUCCESS;

    base = (char *)nt->OptionalHeader.ImageBase;
    if (module == base) return STATUS_SUCCESS;  /* nothing to do */

    /* no relocations are performed on non page-aligned binaries */
    if (nt->OptionalHeader.SectionAlignment < page_size)
        return STATUS_SUCCESS;

    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL) &&
        module != NtCurrentTeb()->Peb->ImageBaseAddress)
        return STATUS_SUCCESS;

    relocs = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
    {
        WARN( "Need to relocate module from %p to %p, but there are no relocation records\n",
              base, module );
        return STATUS_CONFLICTING_ADDRESSES;
    }

    if (!relocs->Size) return STATUS_SUCCESS;
    if (!relocs->VirtualAddress) return STATUS_CONFLICTING_ADDRESSES;
    if (relocs->VirtualAddress > len || relocs->Size > len - relocs->VirtualAddress)
    {
        WARN( "invalid relocation directory va %lx size %lx image size %Iu\n",
              relocs->VirtualAddress, relocs->Size, len );
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (!(protect_old = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY,
                                         nt->FileHeader.NumberOfSections * sizeof(*protect_old ))))
        return STATUS_NO_MEMORY;

    sec = IMAGE_FIRST_SECTION( nt );
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        void *addr;
        SIZE_T size;

        if (!image_section_raw_range_fits( &sec[i], len, &size ))
        {
            WARN( "invalid relocation section %lu va %lx raw size %lx image size %Iu\n",
                  i, sec[i].VirtualAddress, sec[i].SizeOfRawData, len );
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto done;
        }
        if (!size) continue;
        addr = get_rva( module, sec[i].VirtualAddress );
        status = NtProtectVirtualMemory( NtCurrentProcess(), &addr,
                                         &size, PAGE_READWRITE, &protect_old[i] );
        if (status == STATUS_DISK_FULL)
            status = NtProtectVirtualMemory( NtCurrentProcess(), &addr,
                                             &size, PAGE_WRITECOPY, &protect_old[i] );
        if (status)
        {
            WARN( "failed to make relocation section %lu writable, status %lx\n", i, status );
            goto done;
        }
    }

    TRACE( "relocating from %p-%p to %p-%p\n",
           base, base + len, module, (char *)module + len );

    rel = get_rva( module, relocs->VirtualAddress );
    end = get_rva( module, relocs->VirtualAddress + relocs->Size );
    delta = (char *)module - base;

    if ((ULONG_PTR)delta == 0x800000000ull || (ULONG_PTR)module >= 0x80000000000ull)
        MESSAGE( "macrunner-hb-pe-relocate: module=%p image_base=%p delta=%p machine=%#x\n",
                 module, base, (void *)delta, nt->FileHeader.Machine );

    while (rel < end - 1 && rel->SizeOfBlock)
    {
        SIZE_T remaining = (char *)end - (char *)rel;

        if (rel->SizeOfBlock < sizeof(*rel) || rel->SizeOfBlock > remaining ||
            (rel->SizeOfBlock - sizeof(*rel)) % sizeof(USHORT))
        {
            WARN( "invalid relocation block %p size %lx remaining %Iu\n",
                  rel, rel->SizeOfBlock, remaining );
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto done;
        }
        if (rel->VirtualAddress >= len)
        {
            WARN( "invalid address %p in relocation %p\n", get_rva( module, rel->VirtualAddress ), rel );
            status = STATUS_ACCESS_VIOLATION;
            goto done;
        }
        if (!image_relocation_block_targets_fit( rel, len ))
        {
            WARN( "invalid relocation targets in block %p va %lx size %lx image size %Iu\n",
                  rel, rel->VirtualAddress, rel->SizeOfBlock, len );
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto done;
        }
        rel = LdrProcessRelocationBlock( get_rva( module, rel->VirtualAddress ),
                                         (rel->SizeOfBlock - sizeof(*rel)) / sizeof(USHORT),
                                         (USHORT *)(rel + 1), delta );
        if (!rel)
        {
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto done;
        }
    }

done:
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        NTSTATUS restore_status;
        void *addr;
        SIZE_T size;

        if (!protect_old[i]) continue;
        if (!image_section_raw_range_fits( &sec[i], len, &size ))
        {
            if (!status) status = STATUS_INVALID_IMAGE_FORMAT;
            continue;
        }
        addr = get_rva( module, sec[i].VirtualAddress );
        restore_status = NtProtectVirtualMemory( NtCurrentProcess(), &addr,
                                                 &size, protect_old[i], &protect_old[i] );
        if (restore_status)
        {
            WARN( "failed to restore relocation section %lu protection, status %lx\n", i, restore_status );
            if (!status) status = restore_status;
        }
    }
    RtlFreeHeap( GetProcessHeap(), 0, protect_old );
    return status;
}

#if defined(__i386__) || defined(__x86_64__)
static void apply_binary_patches( WINE_MODREF* wm );
#endif
#ifdef __x86_64__
static void apply_fuzzy_binary_patches( WINE_MODREF* wm );
#endif

/*************************************************************************
 *		build_module
 *
 * Build the module data for a mapped dll.
 */
static NTSTATUS build_module( LPCWSTR load_path, const UNICODE_STRING *nt_name, void **module,
                              const SECTION_IMAGE_INFORMATION *image_info, const struct file_id *id,
                              DWORD flags, BOOL system, BOOL redirected, WINE_MODREF **pwm )
{
    static const char builtin_signature[] = "Wine builtin DLL";
    char *signature = (char *)((IMAGE_DOS_HEADER *)*module + 1);
    BOOL is_builtin;
    IMAGE_NT_HEADERS *nt;
    WINE_MODREF *wm;
    NTSTATUS status;
    SIZE_T map_size;

    if (!(nt = RtlImageNtHeader( *module ))) return STATUS_INVALID_IMAGE_FORMAT;

    if (nt->OptionalHeader.SizeOfImage > ~(SIZE_T)0 - (page_size - 1))
        return STATUS_INVALID_IMAGE_FORMAT;
    map_size = (nt->OptionalHeader.SizeOfImage + page_size - 1) & ~(page_size - 1);
    if (map_size < nt->OptionalHeader.SizeOfImage || (ULONG_PTR)*module > ~(ULONG_PTR)0 - map_size)
        return STATUS_INVALID_IMAGE_FORMAT;
    if ((status = perform_relocations( *module, nt, map_size ))) return status;

    is_builtin = ((char *)nt - signature >= sizeof(builtin_signature) &&
                  !memcmp( signature, builtin_signature, sizeof(builtin_signature) ));

    /* create the MODREF */

    if (!(wm = alloc_module( *module, nt_name, is_builtin ))) return STATUS_NO_MEMORY;

    if (id) wm->id = *id;
    if (image_info->LoaderFlags) wm->ldr.Flags |= LDR_COR_IMAGE;
    if (image_info->ComPlusILOnly) wm->ldr.Flags |= LDR_COR_ILONLY;
    if (redirected) wm->ldr.Flags |= LDR_REDIRECTED;
    wm->system = system;

    update_load_config( *module );

    /* fixup imports */

    if (!(flags & DONT_RESOLVE_DLL_REFERENCES) &&
        ((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) ||
         nt->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE))
    {
        if (wm->ldr.Flags & LDR_COR_ILONLY)
            status = fixup_imports_ilonly( wm, load_path, &wm->ldr.EntryPoint );
        else
            status = fixup_imports( wm, load_path );
        if (status != STATUS_SUCCESS)
        {
            /* the module has only be inserted in the load & memory order lists */
            RemoveEntryList(&wm->ldr.InLoadOrderLinks);
            RemoveEntryList(&wm->ldr.InMemoryOrderLinks);
            RemoveEntryList(&wm->ldr.HashLinks);
            RtlRbRemoveNode( &base_address_index_tree, &wm->ldr.BaseAddressIndexNode );

            /* FIXME: there are several more dangling references
             * left. Including dlls loaded by this dll before the
             * failed one. Unrolling is rather difficult with the
             * current structure and we can leave them lying
             * around with no problems, so we don't care.
             * As these might reference our wm, we don't free it.
             */
            *module = NULL;
            return status;
        }
    }

    TRACE( "loaded %s %p %p\n", debugstr_us(nt_name), wm, *module );

    if (is_builtin)
    {
        if (TRACE_ON(relay)) RELAY_SetupDLL( *module );
    }
    else
    {
        if ((wm->ldr.Flags & LDR_IMAGE_IS_DLL) && TRACE_ON(snoop)) SNOOP_SetupDLL( *module );
    }

    TRACE_(loaddll)( "Loaded %s at %p: %s\n", debugstr_w(wm->ldr.FullDllName.Buffer), *module,
                     is_builtin ? "builtin" : "native" );

#if defined(__x86_64__)
    /* CW HACK 22434 */
    if (is_builtin == FALSE)
    {
	struct pe_module_loaded_params params = { *module, (void*)((BYTE*)*module + map_size) };
	WINE_UNIX_CALL( unix_pe_module_loaded, &params );
    }
#endif

#if defined(__i386__) || defined(__x86_64__)
    if (!wcscmp( wm->ldr.BaseDllName.Buffer, L"libcef.dll" ) ||
        !wcscmp( wm->ldr.BaseDllName.Buffer, L"Qt5WebEngineCore.dll" ))
    {
        apply_binary_patches( wm );
    }
#endif

#if defined(__x86_64__)
    if (!wcscmp( wm->ldr.BaseDllName.Buffer, L"cohtml_Unity3DPlugin.dll" ))
        apply_fuzzy_binary_patches( wm );
#endif

    wm->ldr.LoadCount = 1;
    *pwm = wm;
    *module = NULL;
    return STATUS_SUCCESS;
}


/*************************************************************************
 *		build_ntdll_module
 *
 * Build the module data for the initially-loaded ntdll.
 */
static void build_ntdll_module(void)
{
    UNICODE_STRING nt_name = RTL_CONSTANT_STRING( L"\\??\\C:\\windows\\system32\\ntdll.dll" );
    UNICODE_STRING base_name = RTL_CONSTANT_STRING( L"ntdll.dll" );
    MEMORY_BASIC_INFORMATION meminfo;
    WINE_MODREF *wm;
    void *module;

    NtQueryVirtualMemory( GetCurrentProcess(), LdrInitializeThunk, MemoryBasicInformation,
                          &meminfo, sizeof(meminfo), NULL );
    module = meminfo.AllocationBase;
    wm = alloc_module( module, &nt_name, TRUE );
    assert( wm );
    wm->ldr.Flags &= ~LDR_DONT_RESOLVE_REFS;
    node_ntdll = wm->ldr.DdagNode;
    if (TRACE_ON(relay)) RELAY_SetupDLL( module );
    TRACE_(loaddll)( "Loaded %s at %p: builtin\n", debugstr_w(wm->ldr.FullDllName.Buffer), module);

    if (macrunner_hb_x64_main_requested() && LdrSystemDllInitBlock.ntdll_handle &&
        !find_basename_module_machine( base_name.Buffer, IMAGE_FILE_MACHINE_AMD64 ))
    {
        void *guest_module = (void *)(ULONG_PTR)LdrSystemDllInitBlock.ntdll_handle;
        IMAGE_NT_HEADERS *guest_nt = RtlImageNtHeader( guest_module );
        WINE_MODREF *guest_wm;

        if (guest_nt && guest_nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
            (guest_wm = alloc_module( guest_module, &nt_name, TRUE )))
        {
            /* This is a guest export provider for AMD64 IAT resolution. The
             * host ARM64 ntdll remains the process-initialized system DLL. */
            guest_wm->ldr.LoadCount = -1;
            TRACE_(loaddll)( "Loaded guest %s at %p: builtin\n",
                             debugstr_w(guest_wm->ldr.FullDllName.Buffer), guest_module );
        }
    }
}


#ifdef _WIN64
/* convert PE header to 64-bit when loading a 32-bit IL-only module into a 64-bit process */
static BOOL convert_to_pe64( HMODULE module, const SECTION_IMAGE_INFORMATION *info )
{
    static const ULONG copy_dirs[] = { IMAGE_DIRECTORY_ENTRY_RESOURCE,
                                       IMAGE_DIRECTORY_ENTRY_SECURITY,
                                       IMAGE_DIRECTORY_ENTRY_BASERELOC,
                                       IMAGE_DIRECTORY_ENTRY_DEBUG,
                                       IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR };
    IMAGE_OPTIONAL_HEADER32 hdr32 = { IMAGE_NT_OPTIONAL_HDR32_MAGIC };
    IMAGE_OPTIONAL_HEADER64 hdr64 = { IMAGE_NT_OPTIONAL_HDR64_MAGIC };
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( module );
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION( nt );
    SIZE_T hdr_size = min( sizeof(hdr32), nt->FileHeader.SizeOfOptionalHeader );
    SIZE_T size = min( nt->OptionalHeader.SizeOfHeaders, nt->OptionalHeader.SizeOfImage );
    void *addr = module;
    ULONG_PTR image_base = (ULONG_PTR)module, image_end, sections_start = (ULONG_PTR)(nt + 1);
    ULONG i, old_prot;

    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return TRUE;  /* already 64-bit */
    if (NtCurrentTeb()->WowTebOffset) return TRUE;  /* no need to convert */
    if (!info->ImageContainsCode) return TRUE;  /* no need to convert */

    TRACE( "%p\n", module );

    if (size > ~(ULONG_PTR)0 - image_base) return FALSE;
    image_end = image_base + size;
    if (sections_start > image_end ||
        nt->FileHeader.NumberOfSections > (image_end - sections_start) / sizeof(*sec))
        return FALSE;

    if (NtProtectVirtualMemory( NtCurrentProcess(), &addr, &size, PAGE_READWRITE, &old_prot ))
        return FALSE;

    memcpy( &hdr32, &nt->OptionalHeader, hdr_size );
    memcpy( &hdr64, &hdr32, offsetof( IMAGE_OPTIONAL_HEADER64, SizeOfStackReserve ));
    hdr64.Magic               = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    hdr64.AddressOfEntryPoint = 0;
    hdr64.ImageBase           = hdr32.ImageBase;
    hdr64.SizeOfStackReserve  = hdr32.SizeOfStackReserve;
    hdr64.SizeOfStackCommit   = hdr32.SizeOfStackCommit;
    hdr64.SizeOfHeapReserve   = hdr32.SizeOfHeapReserve;
    hdr64.SizeOfHeapCommit    = hdr32.SizeOfHeapCommit;
    hdr64.LoaderFlags         = hdr32.LoaderFlags;
    hdr64.NumberOfRvaAndSizes = hdr32.NumberOfRvaAndSizes;
    for (i = 0; i < ARRAY_SIZE( copy_dirs ); i++)
        hdr64.DataDirectory[copy_dirs[i]] = hdr32.DataDirectory[copy_dirs[i]];

    memmove( nt + 1, sec, nt->FileHeader.NumberOfSections * sizeof(*sec) );
    nt->FileHeader.SizeOfOptionalHeader = sizeof(hdr64);
    nt->OptionalHeader = hdr64;
    NtProtectVirtualMemory( NtCurrentProcess(), &addr, &size, old_prot, &old_prot );
    return TRUE;
}

/* read data out of a PE image directory */
static ULONG read_image_directory( HANDLE file, const SECTION_IMAGE_INFORMATION *info,
                                   ULONG dir, void *buffer, ULONG maxlen, USHORT *magic )
{
    IMAGE_DOS_HEADER mz;
    IO_STATUS_BLOCK io;
    LARGE_INTEGER offset;
    IMAGE_SECTION_HEADER *sec;
    unsigned int i, count;
    DWORD va, size;
    SIZE_T section_bytes, read_size;
    union
    {
        IMAGE_NT_HEADERS32 nt32;
        IMAGE_NT_HEADERS64 nt64;
    } nt;

    offset.QuadPart = 0;
    if (NtReadFile( file, 0, NULL, NULL, &io, &mz, sizeof(mz), &offset, NULL )) return 0;
    if (io.Information != sizeof(mz)) return 0;
    if (mz.e_magic != IMAGE_DOS_SIGNATURE) return 0;
    offset.QuadPart = mz.e_lfanew;
    if (NtReadFile( file, 0, NULL, NULL, &io, &nt, sizeof(nt), &offset, NULL )) return 0;
    if (io.Information != sizeof(nt)) return 0;
    if (nt.nt32.Signature != IMAGE_NT_SIGNATURE) return 0;
    if (dir >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return 0;
    *magic = nt.nt32.OptionalHeader.Magic;
    switch (nt.nt32.OptionalHeader.Magic)
    {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        if (dir >= nt.nt32.OptionalHeader.NumberOfRvaAndSizes) return 0;
        if (nt.nt32.FileHeader.SizeOfOptionalHeader <
            offsetof( IMAGE_OPTIONAL_HEADER32, DataDirectory ) + (dir + 1) * sizeof(IMAGE_DATA_DIRECTORY))
            return 0;
        va = nt.nt32.OptionalHeader.DataDirectory[dir].VirtualAddress;
        size = nt.nt32.OptionalHeader.DataDirectory[dir].Size;
        break;
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        if (dir >= nt.nt64.OptionalHeader.NumberOfRvaAndSizes) return 0;
        if (nt.nt64.FileHeader.SizeOfOptionalHeader <
            offsetof( IMAGE_OPTIONAL_HEADER64, DataDirectory ) + (dir + 1) * sizeof(IMAGE_DATA_DIRECTORY))
            return 0;
        va = nt.nt64.OptionalHeader.DataDirectory[dir].VirtualAddress;
        size = nt.nt64.OptionalHeader.DataDirectory[dir].Size;
        break;
    default:
        return 0;
    }
    if (!va) return 0;
    offset.QuadPart += offsetof( IMAGE_NT_HEADERS32, OptionalHeader ) + nt.nt32.FileHeader.SizeOfOptionalHeader;
    count = nt.nt32.FileHeader.NumberOfSections;
    if (!count || count > (SIZE_T)-1 / sizeof(*sec)) return 0;
    section_bytes = (SIZE_T)count * sizeof(*sec);
    if (!(sec = RtlAllocateHeap( GetProcessHeap(), 0, section_bytes ))) return 0;
    if (NtReadFile( file, 0, NULL, NULL, &io, sec, section_bytes, &offset, NULL )) goto done;
    if (io.Information != section_bytes) goto done;
    read_size = min( maxlen, size );
    for (i = 0; i < count; i++)
    {
        DWORD delta;

        if (va < sec[i].VirtualAddress) continue;
        delta = va - sec[i].VirtualAddress;
        if (sec[i].Misc.VirtualSize && delta >= sec[i].Misc.VirtualSize) continue;
        if (delta >= sec[i].SizeOfRawData || read_size > sec[i].SizeOfRawData - delta) continue;
        offset.QuadPart = (ULONGLONG)sec[i].PointerToRawData + delta;
        if (NtReadFile( file, 0, NULL, NULL, &io, buffer, read_size, &offset, NULL )) goto done;
        RtlFreeHeap( GetProcessHeap(), 0, sec );
        return io.Information;
    }
done:
    RtlFreeHeap( GetProcessHeap(), 0, sec );
    return 0;
}

/* check COM header for ILONLY flag, ignoring runtime version */
static BOOL is_com_ilonly( HANDLE file, const SECTION_IMAGE_INFORMATION *info )
{
    USHORT magic;
    IMAGE_COR20_HEADER cor_header;
    ULONG len = read_image_directory( file, info, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
                                      &cor_header, sizeof(cor_header), &magic );

    if (len != sizeof(cor_header)) return FALSE;
    if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return FALSE;
    return !!(cor_header.Flags & COMIMAGE_FLAGS_ILONLY);
}

/* check LOAD_CONFIG header for CHPE metadata */
static BOOL has_chpe_metadata( HANDLE file, const SECTION_IMAGE_INFORMATION *info )
{
    USHORT magic;
    IMAGE_LOAD_CONFIG_DIRECTORY64 loadcfg;
    ULONG len = read_image_directory( file, info, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
                                      &loadcfg, sizeof(loadcfg), &magic );

    if (!len) return FALSE;
    if (magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return FALSE;
    len = min( len, loadcfg.Size );
    if (len <= offsetof( IMAGE_LOAD_CONFIG_DIRECTORY64, CHPEMetadataPointer )) return FALSE;
    return !!loadcfg.CHPEMetadataPointer;
}

/* On WoW64 setups, an image mapping can also be created for the other 32/64 CPU */
/* but it cannot necessarily be loaded as a dll, so we need some additional checks */
static BOOL is_valid_binary( HANDLE file, const SECTION_IMAGE_INFORMATION *info )
{
    if (macrunner_hb_native_counterpart_machine)
    {
        if (info->Machine == macrunner_hb_native_counterpart_machine) return TRUE;
        if (macrunner_hb_native_counterpart_machine == IMAGE_FILE_MACHINE_ARM64 &&
            has_chpe_metadata( file, info )) return TRUE;
        return FALSE;
    }
    if (info->Machine == current_machine) return TRUE;
    if (macrunner_hb_x64_main_requested() && info->Machine == IMAGE_FILE_MACHINE_AMD64) return TRUE;
    if (NtCurrentTeb()->WowTebOffset) return TRUE;
    /* support ARM64EC binaries on x86-64 */
    if (current_machine == IMAGE_FILE_MACHINE_AMD64 && has_chpe_metadata( file, info )) return TRUE;
    /* support ARM64X/CHPE builtins on native ARM64 */
    if (current_machine == IMAGE_FILE_MACHINE_ARM64 && has_chpe_metadata( file, info )) return TRUE;
    /* support 32-bit IL-only images on 64-bit */
    if (!info->ImageContainsCode) return TRUE;
    if (info->ComPlusNativeReady) return TRUE;
    return is_com_ilonly( file, info );
}

#else  /* _WIN64 */

static BOOL is_valid_binary( HANDLE file, const SECTION_IMAGE_INFORMATION *info )
{
    return (info->Machine == current_machine);
}

#endif  /* _WIN64 */


/******************************************************************
 *		get_module_path_end
 *
 * Returns the end of the directory component of the module path.
 */
static inline const WCHAR *get_module_path_end( const WCHAR *module )
{
    const WCHAR *p;
    const WCHAR *mod_end = module;

    if ((p = wcsrchr( mod_end, '\\' ))) mod_end = p;
    if ((p = wcsrchr( mod_end, '/' ))) mod_end = p;
    if (mod_end == module + 2 && module[1] == ':') mod_end++;
    if (mod_end == module && module[0] && module[1] == ':') mod_end += 2;
    return mod_end;
}


/******************************************************************
 *		append_path
 *
 * Append a counted string to the load path. Helper for get_dll_load_path.
 */
static inline WCHAR *append_path( WCHAR *p, const WCHAR *str, int len )
{
    if (len == -1) len = wcslen(str);
    if (!len) return p;
    memcpy( p, str, len * sizeof(WCHAR) );
    p[len] = ';';
    return p + len + 1;
}


/******************************************************************
 *           get_dll_load_path
 */
static NTSTATUS get_dll_load_path( LPCWSTR module, LPCWSTR dll_dir, ULONG safe_mode, WCHAR **path )
{
    const WCHAR *mod_end = module;
    UNICODE_STRING name = RTL_CONSTANT_STRING( L"PATH" ), value;
    WCHAR *p, *ret;
    int len = ARRAY_SIZE(system_path) + 1, path_len = 0;

    if (module)
    {
        mod_end = get_module_path_end( module );
        len += (mod_end - module) + 1;
    }

    value.Length = 0;
    value.MaximumLength = 0;
    value.Buffer = NULL;
    if (RtlQueryEnvironmentVariable_U( NULL, &name, &value ) == STATUS_BUFFER_TOO_SMALL)
        path_len = value.Length;

    if (dll_dir) len += wcslen( dll_dir ) + 1;
    else len += 2;  /* current directory */
    if (!(p = ret = RtlAllocateHeap( GetProcessHeap(), 0, path_len + len * sizeof(WCHAR) )))
        return STATUS_NO_MEMORY;

    p = append_path( p, module, mod_end - module );
    if (dll_dir) p = append_path( p, dll_dir, -1 );
    else if (!safe_mode) p = append_path( p, L".", -1 );
    p = append_path( p, system_path, -1 );
    if (!dll_dir && safe_mode) p = append_path( p, L".", -1 );

    value.Buffer = p;
    value.MaximumLength = path_len;

    while (RtlQueryEnvironmentVariable_U( NULL, &name, &value ) == STATUS_BUFFER_TOO_SMALL)
    {
        WCHAR *new_ptr;

        /* grow the buffer and retry */
        path_len = value.Length;
        if (!(new_ptr = RtlReAllocateHeap( GetProcessHeap(), 0, ret, path_len + len * sizeof(WCHAR) )))
        {
            RtlFreeHeap( GetProcessHeap(), 0, ret );
            return STATUS_NO_MEMORY;
        }
        value.Buffer = new_ptr + (value.Buffer - ret);
        value.MaximumLength = path_len;
        ret = new_ptr;
    }
    value.Buffer[value.Length / sizeof(WCHAR)] = 0;
    *path = ret;
    return STATUS_SUCCESS;
}


/******************************************************************
 *		get_dll_load_path_search_flags
 */
static NTSTATUS get_dll_load_path_search_flags( LPCWSTR module, DWORD flags, WCHAR **path )
{
    const WCHAR *image = NULL, *mod_end, *image_end;
    struct dll_dir_entry *dir;
    WCHAR *p, *ret;
    int len = 1;

    if (flags & LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)
        flags |= (LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
                  LOAD_LIBRARY_SEARCH_USER_DIRS |
                  LOAD_LIBRARY_SEARCH_SYSTEM32);

    if (flags & LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR)
    {
        DWORD type = RtlDetermineDosPathNameType_U( module );
        if (type != RtlPathTypeDriveAbsolute && type != RtlPathTypeRooted && type != RtlPathTypeLocalDevice && type != RtlPathTypeUncAbsolute)
            return STATUS_INVALID_PARAMETER;
        mod_end = get_module_path_end( module );
        len += (mod_end - module) + 1;
    }
    else module = NULL;

    if (flags & LOAD_LIBRARY_SEARCH_APPLICATION_DIR)
    {
        image = NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer;
        image_end = get_module_path_end( image );
        len += (image_end - image) + 1;
    }

    if (flags & LOAD_LIBRARY_SEARCH_USER_DIRS)
    {
        LIST_FOR_EACH_ENTRY( dir, &dll_dir_list, struct dll_dir_entry, entry )
            len += wcslen( dir->dir + 4 /* \??\ */ ) + 1;
        if (dll_directory.Length) len += dll_directory.Length / sizeof(WCHAR) + 1;
    }

    if (flags & LOAD_LIBRARY_SEARCH_SYSTEM32) len += wcslen( system_dir );

    if ((p = ret = RtlAllocateHeap( GetProcessHeap(), 0, len * sizeof(WCHAR) )))
    {
        if (module) p = append_path( p, module, mod_end - module );
        if (image) p = append_path( p, image, image_end - image );
        if (flags & LOAD_LIBRARY_SEARCH_USER_DIRS)
        {
            LIST_FOR_EACH_ENTRY( dir, &dll_dir_list, struct dll_dir_entry, entry )
                p = append_path( p, dir->dir + 4 /* \??\ */, -1 );
            p = append_path( p, dll_directory.Buffer, dll_directory.Length / sizeof(WCHAR) );
        }
        if (flags & LOAD_LIBRARY_SEARCH_SYSTEM32) wcscpy( p, system_dir );
        else
        {
            if (p > ret) p--;
            *p = 0;
        }
    }
    *path = ret;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *	open_dll_file
 *
 * Open a file for a new dll. Helper for find_dll_file.
 */
static NTSTATUS open_dll_file( UNICODE_STRING *nt_name, WINE_MODREF **pwm, HANDLE *mapping,
                               SECTION_IMAGE_INFORMATION *image_info, struct file_id *id )
{
    FILE_BASIC_INFORMATION info;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    LARGE_INTEGER size;
    FILE_OBJECTID_BUFFER fid;
    NTSTATUS status;
    HANDLE handle;

    if ((*pwm = find_fullname_module( nt_name ))) return STATUS_SUCCESS;

    InitializeObjectAttributes( &attr, nt_name, OBJ_CASE_INSENSITIVE, 0, NULL );
    if ((status = NtOpenFile( &handle, GENERIC_READ | SYNCHRONIZE, &attr, &io,
                              FILE_SHARE_READ | FILE_SHARE_DELETE,
                              FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE )))
    {
        if (status != STATUS_OBJECT_PATH_NOT_FOUND &&
            status != STATUS_OBJECT_NAME_NOT_FOUND &&
            !NtQueryAttributesFile( &attr, &info ))
        {
            /* if the file exists but failed to open, report the error */
            return status;
        }
        /* otherwise continue searching */
        return STATUS_DLL_NOT_FOUND;
    }

    if (!NtFsControlFile( handle, 0, NULL, NULL, &io, FSCTL_GET_OBJECT_ID, NULL, 0, &fid, sizeof(fid) ))
    {
        memcpy( id, fid.ObjectId, sizeof(*id) );
        if ((*pwm = find_fileid_module( id )))
        {
            TRACE( "%s is the same file as existing module %p %s\n", debugstr_w( nt_name->Buffer ),
                   (*pwm)->ldr.DllBase, debugstr_w( (*pwm)->ldr.FullDllName.Buffer ));
            NtClose( handle );
            return STATUS_SUCCESS;
        }
    }

    size.QuadPart = 0;
    status = NtCreateSection( mapping, STANDARD_RIGHTS_REQUIRED | SECTION_QUERY |
                              SECTION_MAP_READ | SECTION_MAP_EXECUTE,
                              NULL, &size, PAGE_EXECUTE_READ, SEC_IMAGE, handle );
    if (!status)
    {
        NtQuerySection( *mapping, SectionImageInformation, image_info, sizeof(*image_info), NULL );
        if (!is_valid_binary( handle, image_info ))
        {
            TRACE( "%s is for arch %x, continuing search\n", debugstr_us(nt_name), image_info->Machine );
            status = STATUS_NOT_SUPPORTED;
            NtClose( *mapping );
            *mapping = NULL;
        }
    }
    NtClose( handle );
    return status;
}


/***********************************************************************
 *	open_known_dll
 *
 * Open a dll from the KnownDlls NT directory.
 */
static NTSTATUS open_known_dll( const WCHAR *libname, UNICODE_STRING *nt_name, WINE_MODREF **pwm,
                                HANDLE *mapping, SECTION_IMAGE_INFORMATION *image_info, struct file_id *id )
{
    NTSTATUS status;
    UNICODE_STRING str;
    OBJECT_ATTRIBUTES attr;

    if (!known_dlls_ntdir) return STATUS_DLL_NOT_FOUND;
    /* CW HACK 20810: In Wow64/32-bit-bottle mode, don't load from KnownDlls */
    if (wow64_using_32bit_prefix) return STATUS_DLL_NOT_FOUND;
    RtlInitUnicodeString( &str, libname );
    InitializeObjectAttributes( &attr, &str, OBJ_CASE_INSENSITIVE, known_dlls_ntdir, NULL );
    if ((status = NtOpenSection( mapping, MAXIMUM_ALLOWED, &attr ))) return status;
    if ((status = build_sysdir_nt_name( libname, nt_name )))
    {
        NtClose( *mapping );
        *mapping = NULL;
        return status;
    }
    if ((*pwm = find_fullname_module( nt_name )))
    {
        NtClose( *mapping );
        return STATUS_SUCCESS;
    }
    NtQuerySection( *mapping, SectionImageInformation, image_info, sizeof(*image_info), NULL );
    if (current_machine == IMAGE_FILE_MACHINE_I386 && image_info->Machine != IMAGE_FILE_MACHINE_I386)
    {
        TRACE( "%s known dll is for arch %x, continuing search\n", debugstr_us(nt_name), image_info->Machine );
        NtClose( *mapping );
        *mapping = NULL;
        RtlFreeUnicodeString( nt_name );
        nt_name->Buffer = NULL;
        return STATUS_DLL_NOT_FOUND;
    }
    memset( id, 0, sizeof(*id) );
    TRACE( "loaded %s from known dlls\n", debugstr_us(nt_name) );
    return STATUS_SUCCESS;
}


/******************************************************************************
 *	find_existing_module
 *
 * Find an existing module that is the same mapping as the new module.
 */
static WINE_MODREF *find_existing_module( HMODULE module )
{
    WINE_MODREF *wm;
    LIST_ENTRY *mark, *entry;
    LDR_DATA_TABLE_ENTRY *mod;
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( module );

    if ((wm = get_modref( module ))) return wm;

    mark = &NtCurrentTeb()->Peb->LdrData->InMemoryOrderModuleList;
    for (entry = mark->Flink; entry != mark; entry = entry->Flink)
    {
        mod = CONTAINING_RECORD( entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
        if (mod->TimeDateStamp != nt->FileHeader.TimeDateStamp) continue;
        wm = CONTAINING_RECORD( mod, WINE_MODREF, ldr );
        if (wm->CheckSum != nt->OptionalHeader.CheckSum) continue;
        if (NtAreMappedFilesTheSame( mod->DllBase, module ) != STATUS_SUCCESS) continue;
        return CONTAINING_RECORD( mod, WINE_MODREF, ldr );
    }
    return NULL;
}

#ifdef __x86_64__

static BOOL byte_pattern_matches( const char *addr, char wildcard_byte,
                                  const char *pattern, size_t pattern_size )
{
    size_t i;
    for (i = 0; i < pattern_size; i++)
    {
        if (pattern[i] != wildcard_byte && addr[i] != pattern[i])
            return FALSE;
    }

    return TRUE;
}

static void *find_byte_pattern( void *dllbase, size_t size_of_image,
                                char wildcard_byte, const char *pattern, size_t pattern_size )
{
    size_t offset;
    for (offset = 0; offset <= size_of_image - pattern_size; offset++)
    {
        char *addr = (char *)dllbase + offset;
        if (byte_pattern_matches( addr, wildcard_byte, pattern, pattern_size ))
            return addr;
    }

    return NULL;
}

static void apply_byte_pattern_patch( void *addr, char wildcard_byte, const char *after, size_t after_size )
{
    size_t i;
    for (i = 0; i < after_size; i++)
    {
        if (after[i] != wildcard_byte)
            ((char *)addr)[i] = after[i];
    }
}

static void apply_fuzzy_binary_patches( WINE_MODREF *wm )
{
    static const char before_cohtml_v1[] =
    {
        0xcc,                                /* int3 */
        0x40, 0xff,                          /* push <wildcard> */
        0x48, 0xff, 0xff, 0xff,              /* sub <wildcard>, <wildcard> */
        0x80, 0xff, 0xff, 0xff,              /* cmp <wildcard>, <wildcard> */
        0x48, 0xff, 0xff,                    /* mov <wildcard>, <wildcard> */
        0x0f, 0x84                           /* jz ... */
    };
    static const char after_cohtml_v1[] = {
        0xff,                                /* (unchanged) */
        0xff, 0xff,                          /* (unchanged) */
        0xff, 0xff, 0xff, 0xff,              /* (unchanged) */
        0xff, 0xff, 0xff, 0xff,              /* (unchanged) */
        0xff, 0xff, 0xff,                    /* (unchanged) */
        0xff, 0x85                           /* jnz ... */
    };
    C_ASSERT( sizeof(before_cohtml_v1) == sizeof(after_cohtml_v1) );


    struct {
        const WCHAR *libname;
        const char *name;
        char wildcard_byte;
        const char *before, *after;
        size_t size;
        BOOL stop_patching_after_success;
        /* If should_apply is non-null, the patch is only applied if it returns
         * true (in addition to meeting the other criteria). */
        BOOL (*should_apply)(void);
    } static const patches[] =
    {
        /* CW HACK 22901: cohtml_Unity3DPlugin.dll for Cities Skylines 2. */
        {
            L"cohtml_Unity3DPlugin.dll",
            "cohtml_v1",
            0xff,
            before_cohtml_v1, after_cohtml_v1,
            sizeof(before_cohtml_v1),
            TRUE,
            NULL
        }
    };

    unsigned int i;
    SIZE_T pagesize = page_size;
    WCHAR *libname = wm->ldr.BaseDllName.Buffer;

    for (i = 0; i < ARRAY_SIZE(patches); i++)
    {
        DWORD old_prot;
        void *dllbase = wm->ldr.DllBase;
        void *target, *target_page;

        if (wcscmp( libname, patches[i].libname ))
            continue;

        if (patches[i].should_apply && !patches[i].should_apply())
        {
            TRACE( "predicate function said we should not apply %s to %s\n", patches[i].name, debugstr_w(libname) );
            continue;
        }

        target = find_byte_pattern( dllbase, wm->ldr.SizeOfImage,
                                    patches[i].wildcard_byte, patches[i].before, patches[i].size );

        if (!target)
        {
            TRACE( "%s doesn't match %s\n", debugstr_w(libname), patches[i].name );
            continue;
        }

        TRACE( "Found %s %s byte pattern at %p; applying patch\n", debugstr_w(libname), patches[i].name, target );
        target_page = (void *)((ULONG_PTR)target & ~(page_size-1));
        NtProtectVirtualMemory( NtCurrentProcess(), &target_page, &pagesize, PAGE_EXECUTE_READWRITE, &old_prot );
        apply_byte_pattern_patch( target, patches[i].wildcard_byte, patches[i].after, patches[i].size );
        NtProtectVirtualMemory( NtCurrentProcess(), &target_page, &pagesize, old_prot, &old_prot );

        if (patches[i].stop_patching_after_success)
            break;
    }
}
#endif

#if defined(__i386__) || defined(__x86_64__)
static void apply_binary_patches( WINE_MODREF* wm )
{
#ifdef __x86_64__
    static const char before_85_3_9_0[] =
    {
        0x65, 0x48, 0x8b, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00, /* mov rax, qword [gs:0x8] */
        0xc3,                                                 /* ret */
        0xcc,                                                 /* int3 */
        0xcc,                                                 /* int3 */
        0xcc,                                                 /* int3 */
        0xcc,                                                 /* int3 */
        0xcc,                                                 /* int3 */
        0xcc,                                                 /* int3 */
        0x48, 0x83, 0xec, 0x28,                               /* sub rsp, 0x28 */
        0x65, 0x48, 0x8b, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00, /* mov rax, qword [gs:0x8] */
        0x48, 0x83, 0xc0, 0xf8                                /* add rax, 0xfffffffffffffff8 */
    };
    static const char after_85_3_9_0[] =
    {
        0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, /* mov rax, qword [gs:0x30] */
        0x48, 0x8b, 0x40, 0x08,                               /* mov rax, qword [rax+8] */
        0xc3,                                                 /* ret */
        0xcc,                                                 /* int3 */
        0xcc,                                                 /* int3 */
        0x48, 0x83, 0xec, 0x28,                               /* sub rsp, 0x28 */
        0xe8, 0xe7, 0xff, 0xff, 0xff,                         /* call 0xfffffffffffffffe */
        0x90,                                                 /* nop */
        0x90,                                                 /* nop */
        0x90,                                                 /* nop */
        0x90,                                                 /* nop */
        0x48, 0x83, 0xc0, 0xf8                                /* add rax,0xfffffffffffffff8 */
    };
    C_ASSERT( sizeof(before_85_3_9_0) == sizeof(after_85_3_9_0) );


    /* The first patch needed for 85.3.11 is the same as 85_3_9_0, just at a different offset. */

    static const char before_85_3_11_1[] =
    {
        0x48, 0x8b, 0x44, 0x24, 0x28,  /* mov rax, qword ptr [rsp + 0x28] */
        0x65, 0x48, 0x8b, 0x34, 0x25, 0x08, 0x00, 0x00, 0x00,  /* mov rsi, qword ptr gs:[0x8] */
        0x48, 0x85, 0xf6,              /* test rsi, rsi */
        0x74, 0x2e                     /* jz 0x028c525b */

    };
    static const char after_85_3_11_1[] =
    {
        /* Taking a cue from after_72_0_3626_121_2 - overwriting the test and jump to make room. */
        0x48, 0x8b, 0x44, 0x24, 0x28,  /* mov rax, qword ptr [rsp + 0x28] */
        0x65, 0x48, 0x8b, 0x34, 0x25, 0x30, 0x00, 0x00, 0x00,  /* mov rsi, qword ptr gs:[0x30] */
        0x48, 0x8b, 0x76, 0x08,        /* mov rsi, qword ptr [rsi+8] */
        0x90,                          /* nop */
    };
    C_ASSERT( sizeof(before_85_3_11_1) == sizeof(after_85_3_11_1) );


    static const char before_72_0_3626_121_1[] =
    {
        0x65, 0x48, 0x8b, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00, /* mov rax, qword [gs:0x8] */
        0xc3,                                                 /* ret */
        0x48, 0x83, 0xec, 0x28,                               /* sub rsp, 0x28 */
        0x65, 0x48, 0x8b, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00, /* mov rax, qword [gs:0x8] */
        0x48, 0x83, 0xc0, 0xf8,                               /* add rax, 0xfffffffffffffff8 */
    };
    static const char after_72_0_3626_121_1[] =
    {
        0xe8, 0xb7, 0x00, 0x00, 0x00, /* call 0xbc */
        0x90,                         /* nop */
        0x90,                         /* nop */
        0x90,                         /* nop */
        0x90,                         /* nop */
        0xc3,                         /* ret */
        0x48, 0x83, 0xec, 0x28,       /* sub rsp, 0x28 */
        0xe8, 0xa9, 0x00, 0x00, 0x00, /* call 0xae */
        0x90,                         /* nop */
        0x90,                         /* nop */
        0x90,                         /* nop */
        0x90,                         /* nop */
        0x48, 0x83, 0xc0, 0xf8,       /* add rax, 0xfffffffffffffff8 */
    };
    C_ASSERT( sizeof(before_72_0_3626_121_1) == sizeof(after_72_0_3626_121_1) );

    static const char before_72_0_3626_121_2[] =
    {
        0x48, 0x8b, 0x46, 0x08,                                 /* mov rax, qword [rsi+8] */
        0x65, 0x48, 0x8b, 0x34, 0x25, 0x08, 0x00, 0x00, 0x00,   /* mov rsi, qword [gs:0x8] */
        0x48, 0x85, 0xf6,                                       /* test rsi, rsi */
        0x74, 0x2e,                                             /* je 0x30 */
    };
    static const char after_72_0_3626_121_2[] =
    {
        0x48, 0x8b, 0x46, 0x08,                                 /* mov rax, qword [rsi+8] */
        0x65, 0x48, 0x8b, 0x34, 0x25, 0x30, 0x00, 0x00, 0x00,   /* mov rsi, qword [gs:0x30] */
        0x48, 0x8b, 0x76, 0x08,                                 /* mov rsi, qword [rsi+8] */
        0x90,                                                   /* nop */
    };
    C_ASSERT( sizeof(before_72_0_3626_121_2) == sizeof(after_72_0_3626_121_2) );

    static const char before_72_0_3626_121_3[] =
    {
        0xcc,       /* int3 */
        0x0f, 0x0b, /* ud2 */
        0x6a, 0x1c, /* push 0x1c */
        0x0f, 0x0b, /* ud2 */
        0xcc,       /* int3 */
        0x0f, 0x0b, /* ud2 */
        0x6a, 0x1d, /* push 0x1d */
        0x0f, 0x0b  /* ud2 */
    };
    static const char after_72_0_3626_121_3[] =
    {
        0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, /* mov rax, qword [gs:0x30] */
        0x48, 0x8b, 0x40, 0x08,                               /* mov rax, qword [rax+8] */
        0xc3,                                                 /* ret */
    };
    C_ASSERT( sizeof(before_72_0_3626_121_3) == sizeof(after_72_0_3626_121_3) );

    static const char before_qt_5_15_2_0_1[] =
    {
        0x65, 0x48, 0x8b, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00, /* mov rax, qword [gs:0x8] */
        0xc3,                                                 /* ret */
        0xcc,                                                 /* int3 */
        0xcc,                                                 /* int3 */
        0xcc,                                                 /* int3 */
        0xcc,                                                 /* int3 */
        0xcc,                                                 /* int3 */
        0xcc,                                                 /* int3 */
        0x48, 0x83, 0xec, 0x28,                               /* sub rsp, 0x28 */
        0x65, 0x48, 0x8b, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00, /* mov rax, qword [gs:0x8] */
        0x48, 0x83, 0xe8, 0x08                                /* sub rax, 0x8 */
    };
    static const char after_qt_5_15_2_0_1[] =
    {
        0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, /* mov rax, qword [gs:0x30] */
        0x48, 0x8b, 0x40, 0x08,                               /* mov rax, qword [rax+8] */
        0xc3,                                                 /* ret */
        0xcc,                                                 /* int3 */
        0xcc,                                                 /* int3 */
        0x48, 0x83, 0xec, 0x28,                               /* sub rsp, 0x28 */
        0xe8, 0xe7, 0xff, 0xff, 0xff,                         /* call 0xfffffffffffffffe */
        0x90,                                                 /* nop */
        0x90,                                                 /* nop */
        0x90,                                                 /* nop */
        0x90,                                                 /* nop */
        0x48, 0x83, 0xe8, 0x08                                /* sub rax,0x8 */
    };
    C_ASSERT( sizeof(before_qt_5_15_2_0_1) == sizeof(after_qt_5_15_2_0_1) );

    static const char before_qt_5_15_2_0_2[] = {
        0xff, 0x15, 0xd5, 0xb4, 0x6e, 0x02,                   /* call [KERNEL32.DLL::VirtualQuery] */
        0x65, 0x48, 0x8b, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00, /* mov rax, qword [gs:0x8] */
        0x48, 0x8b, 0x4c, 0x24, 0x28                          /* mov rcx, qword [rsp+0x28] */
    };
    static const char after_qt_5_15_2_0_2[] = {
        0xff, 0x15, 0xd5, 0xb4, 0x6e, 0x02, /* call [KERNEL32.DLL::VirtualQuery] */
        0xe8, 0x78, 0xff, 0xff, 0xff,       /* call 0xfffffffffffffffe */
        0x90,                               /* nop */
        0x90,                               /* nop */
        0x90,                               /* nop */
        0x90,                               /* nop */
        0x48, 0x8b, 0x4c, 0x24, 0x28        /* mov rcx, qword [rsp+0x28] */
    };
    C_ASSERT( sizeof(before_qt_5_15_2_0_2) == sizeof(after_qt_5_15_2_0_2) );


    static const char before_epic_cmd_line_args_90_6_7[] = {
        0x8b, 0x47, 0x64,
        0x89, 0x43, 0x64,
        0x8b, 0x47, 0x68,              /* mov eax, dword ptr [rdi+0x68] */
        0x89, 0x43, 0x68,              /* mov dword ptr [rbx + 0x68], eax */
    };
    static const char after_epic_cmd_line_args_90_6_7[] = {
        0x8b, 0x47, 0x64,
        0x89, 0x43, 0x64,
        0x31, 0xc0,                     /* xor eax, eax */
        0x90,                           /* nop */
        0x89, 0x43, 0x68                /* mov dword ptr [rsi+0x68], eax */
    };
    C_ASSERT( sizeof(before_epic_cmd_line_args_90_6_7) == sizeof(after_epic_cmd_line_args_90_6_7) );
#endif  /* __x86_64__ */

#ifdef __i386__
    static const char before_cmd_line_args_111_2_7[] = {
        0x8b, 0x47, 0x38,
        0x89, 0x46, 0x38,
        0x8b, 0x47, 0x3c,               /* mov eax, dword ptr [edi+0x3c] */
        0x89, 0x46, 0x3c                /* mov dword ptr [esi+0x3c], eax */
    };
    static const char after_cmd_line_args_111_2_7[] = {
        0x8b, 0x47, 0x38,
        0x89, 0x46, 0x38,
        0x31, 0xc0,                     /* xor eax, eax */
        0x90,                           /* nop */
        0x89, 0x46, 0x3c                /* mov dword ptr [esi+0x3c], eax */
    };
    C_ASSERT( sizeof(before_cmd_line_args_111_2_7) == sizeof(after_cmd_line_args_111_2_7) );

    static const char before_cmd_line_args_135_0_20[] = {
        0x8b, 0x47, 0x34,
        0x89, 0x46, 0x34,
        0x8b, 0x47, 0x38,               /* mov eax, dword ptr [edi+0x38] */
        0x89, 0x46, 0x38                /* mov dword ptr [esi+0x38], eax */
    };
    static const char after_cmd_line_args_135_0_20[] = {
        0x8b, 0x47, 0x34,
        0x89, 0x46, 0x34,
        0x31, 0xc0,                     /* xor eax, eax */
        0x90,                           /* nop */
        0x89, 0x46, 0x38                /* mov dword ptr [esi+0x38], eax */
    };
    C_ASSERT( sizeof(before_cmd_line_args_135_0_20) == sizeof(after_cmd_line_args_135_0_20) );
#endif  /* __i386__ */


    struct
    {
        const WCHAR *libname;
        const char *name;
        const void *before, *after;
        size_t size;
        ULONG_PTR offset;
        BOOL stop_patching_after_success;
    } static const patches[] =
    {
#ifdef __x86_64__
        /* CW HACK 22584L
         * libcef.dll 85.3.11, for an updated Rockstar Games Social Club/Launcher.
         */
        {
            L"libcef.dll",
            "CEF %gs 85.3.11-0",
            /* This patch is identical to the one for 85.3.9, just at a different offset. */
            before_85_3_9_0, after_85_3_9_0,
            sizeof(before_85_3_9_0),
            0x28c5190,
            FALSE
        },
        {
            L"libcef.dll",
            "CEF %gs 85.3.11-1",
            before_85_3_11_1, after_85_3_11_1,
            sizeof(before_85_3_11_1),
            0x28c521a,
            TRUE
        },

        /* CW HACK 18582:
         * libcef.dll 85.3.9.0 used by the Rockstar Games Social Club/Launcher
         * (and downloadable from
         * https://cef-builds.spotifycdn.com/index.html#windows64).
         */
        {
            L"libcef.dll",
            "CEF %gs 85.3.9.0",
            before_85_3_9_0, after_85_3_9_0,
            sizeof(before_85_3_9_0),
            0x28c4b30,
            TRUE
        },

        /* CW HACK 19114:
         * libcef.dll 72.0.3626.121 used by the game beamNG.drive.
         * Patch also works for version downloadable from CEF builds.
         */
        {
            L"libcef.dll",
            "CEF %gs 72.0.3626.121-0",
            before_72_0_3626_121_1, after_72_0_3626_121_1,
            sizeof(before_72_0_3626_121_1),
            0x23bb2ad,
            FALSE
        },
        {
            L"libcef.dll",
            "CEF %gs 72.0.3626.121-1",
            before_72_0_3626_121_2, after_72_0_3626_121_2,
            sizeof(before_72_0_3626_121_2),
            0x23bb329,
            FALSE
        },
        {
            L"libcef.dll",
            "CEF %gs 72.0.3626.121-2",
            before_72_0_3626_121_3, after_72_0_3626_121_3,
            sizeof(before_72_0_3626_121_3),
            0x23bb369,
            TRUE
        },

        /* CW HACK 16900:
         * libcef.dll 72.0.3626.96 used by the game Wizard101.
         * Patch also works for version 3.3626.1886.g162fdec downloadable from CEF builds.
         */
        {
            L"libcef.dll",
            "CEF %gs 72.0.3626.96-0",
            /* This patch is identical to the one for 72.0.3626.121, just at a different offset. */
            before_72_0_3626_121_1, after_72_0_3626_121_1,
            sizeof(before_72_0_3626_121_1),
            0x23bb82d,
            FALSE
        },
        {
            L"libcef.dll",
            "CEF %gs 72.0.3626.96-1",
            before_72_0_3626_121_2, after_72_0_3626_121_2,
            sizeof(before_72_0_3626_121_2),
            0x23bb8a9,
            FALSE
        },
        {
            L"libcef.dll",
            "CEF %gs 72.0.3626.96-2",
            before_72_0_3626_121_3, after_72_0_3626_121_3,
            sizeof(before_72_0_3626_121_3),
            0x23bb8e9,
            TRUE
        },

        /* CW HACK 21548:
         * Qt5WebEngineCore.dll 5.15.2.0 used by the EA Launcher.
         * Based on CEF 83.0.4103.122, but has different offsets.
         */
        {
            L"Qt5WebEngineCore.dll",
            "CEF/Qt5WebEngineCore %gs 5.15.2.0-0",
            before_qt_5_15_2_0_1, after_qt_5_15_2_0_1,
            sizeof(before_qt_5_15_2_0_1),
            0x2810f10,
            FALSE
        },
        {
            L"Qt5WebEngineCore.dll",
            "CEF/Qt5WebEngineCore %gs 5.15.2.0-1",
            before_qt_5_15_2_0_2, after_qt_5_15_2_0_2,
            sizeof(before_qt_5_15_2_0_2),
            0x2810f8d,
            TRUE
        },

        /* CW HACK 23854:
         * Ignore the command_line_args_disabled flag in the cef_settings_t
         * passed to cef_inititalize. Always set it to 0.
         */
        {
            L"libcef.dll",
            "CEF cmd_line_args_disabled 90.6.7",
            before_epic_cmd_line_args_90_6_7,
            after_epic_cmd_line_args_90_6_7,
            sizeof(before_epic_cmd_line_args_90_6_7),
            0x3807,
            TRUE
        },
#endif  /* __x86_64__ */

#ifdef __i386__
        /* CW HACK 19252:
         * 32-bit libcef 111.2.7+gebf5d6a+chromium-111.0.5563.148.
         * (For Ubisoft Connect, has same offsets as CEF builds).
         * Ignore the command_line_args_disabled flag in the cef_settings_t
         * passed to cef_inititalize. Always set it to 0.
         */
        {
            L"libcef.dll",
            "CEF cmd_line_args_disabled x86 111.2.7",
            before_cmd_line_args_111_2_7,
            after_cmd_line_args_111_2_7,
            sizeof(before_cmd_line_args_111_2_7),
            0x114a43,
            TRUE
        },

        /* CW HACK 25737:
           32-bit libcef 135.0.20+ge7de5c3+chromium-135.0.7049.85.
           For command_line_args_disabled in an updated Ubisoft Connect. */
        {
            L"libcef.dll",
            "CEF cmd_line_args_disabled x86 135.0.20",
            before_cmd_line_args_135_0_20,
            after_cmd_line_args_135_0_20,
            sizeof(before_cmd_line_args_135_0_20),
            0x11e92d,
            TRUE
        },
#endif  /* __i386__ */
    };

    unsigned int i;
    SIZE_T pagesize = page_size;
    WCHAR *libname = wm->ldr.BaseDllName.Buffer;

    for (i = 0; i < ARRAY_SIZE(patches); i++)
    {
        DWORD old_prot;
        void *dllbase = wm->ldr.DllBase;
        void *target = (void *)((ULONG_PTR)dllbase + patches[i].offset);
        void *target_page = (void *)((ULONG_PTR)target & ~(page_size-1));

        if (wcscmp( libname, patches[i].libname ))
            continue;

        if (wm->ldr.SizeOfImage < patches[i].offset)
        {
            TRACE( "%s too small to match patch '%s'\n", debugstr_w(libname), patches[i].name );
            continue;
        }
        if (memcmp( target, patches[i].before, patches[i].size ))
        {
            TRACE( "%s doesn't match patch '%s'\n", debugstr_w(libname), patches[i].name );
            continue;
        }

        TRACE( "Found matching %s, applying patch '%s'\n", debugstr_w(libname), patches[i].name );
        NtProtectVirtualMemory( NtCurrentProcess(), &target_page, &pagesize, PAGE_EXECUTE_READWRITE, &old_prot );
        memcpy( target, patches[i].after, patches[i].size );
        NtProtectVirtualMemory( NtCurrentProcess(), &target_page, &pagesize, old_prot, &old_prot );

        if (patches[i].stop_patching_after_success)
            break;
    }
}
#endif

/******************************************************************************
 *	load_native_dll  (internal)
 */
static NTSTATUS load_native_dll( LPCWSTR load_path, const UNICODE_STRING *nt_name, HANDLE mapping,
                                 const SECTION_IMAGE_INFORMATION *image_info, const struct file_id *id,
                                 DWORD flags, BOOL system, BOOL redirected, WINE_MODREF** pwm )
{
    void *module = NULL;
    SIZE_T len = 0;
    NTSTATUS status = WINE_NT_MAP_VIEW( mapping, NtCurrentProcess(), &module, 0, 0, NULL, &len,
                                          ViewShare, 0, PAGE_EXECUTE_READ );

    if (!NT_SUCCESS(status)) return status;

    if ((*pwm = find_existing_module( module )))  /* already loaded */
    {
        if ((*pwm)->ldr.LoadCount != -1) (*pwm)->ldr.LoadCount++;
        TRACE( "found %s for %s at %p, count=%d\n",
               debugstr_us(&(*pwm)->ldr.FullDllName), debugstr_us(nt_name),
               (*pwm)->ldr.DllBase, (*pwm)->ldr.LoadCount);
        if (module != (*pwm)->ldr.DllBase) NtUnmapViewOfSection( NtCurrentProcess(), module );
        return STATUS_SUCCESS;
    }
#ifdef _WIN64
    if (status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH && !convert_to_pe64( module, image_info ))
        status = STATUS_INVALID_IMAGE_FORMAT;
#endif
    if (NT_SUCCESS(status)) status = build_module( load_path, nt_name, &module, image_info, id,
                                                   flags, system, redirected, pwm );
    if (status && module) NtUnmapViewOfSection( NtCurrentProcess(), module );
    return status;
}


/***********************************************************************
 *           load_so_dll
 */
static NTSTATUS load_so_dll( LPCWSTR load_path, const UNICODE_STRING *nt_name,
                             DWORD flags, WINE_MODREF **pwm )
{
    void *module;
    NTSTATUS status;
    WINE_MODREF *wm;
    struct load_so_dll_params params = { *nt_name, &module };

    TRACE( "trying %s as so lib\n", debugstr_us(nt_name) );
    if ((status = WINE_UNIX_CALL( unix_load_so_dll, &params )))
    {
        WARN( "failed to load .so lib %s\n", debugstr_us(nt_name) );
        if (status == STATUS_INVALID_IMAGE_FORMAT) status = STATUS_INVALID_IMAGE_NOT_MZ;
        return status;
    }

    if ((wm = get_modref( module )))  /* already loaded */
    {
        TRACE( "Found %s at %p for builtin %s\n",
               debugstr_w(wm->ldr.FullDllName.Buffer), wm->ldr.DllBase, debugstr_us(nt_name) );
        if (wm->ldr.LoadCount != -1) wm->ldr.LoadCount++;
    }
    else
    {
        SECTION_IMAGE_INFORMATION image_info = { 0 };

        if ((status = build_module( load_path, &params.nt_name, &module, &image_info, NULL, flags,
                                    FALSE, FALSE, &wm )))
        {
            if (module) NtUnmapViewOfSection( NtCurrentProcess(), module );
            return status;
        }
    }
    *pwm = wm;
    return STATUS_SUCCESS;
}


/*************************************************************************
 *		build_main_module
 *
 * Build the module data for the main image.
 */
static WINE_MODREF *build_main_module(void)
{
    SECTION_IMAGE_INFORMATION info;
    UNICODE_STRING nt_name;
    WINE_MODREF *wm;
    NTSTATUS status;
    RTL_USER_PROCESS_PARAMETERS *params = NtCurrentTeb()->Peb->ProcessParameters;
    void *module = NtCurrentTeb()->Peb->ImageBaseAddress;
    IMAGE_NT_HEADERS *nt;
    WORD image_machine;

    NtQueryInformationProcess( GetCurrentProcess(), ProcessImageInformation, &info, sizeof(info), NULL );
    nt = RtlImageNtHeader( module );
    image_machine = nt ? nt->FileHeader.Machine : info.Machine;
    macrunner_hb_amd64_main_on_arm64 = macrunner_hb_x64_main_requested();
    if (info.ImageCharacteristics & IMAGE_FILE_DLL)
    {
        MESSAGE( "wine: %s is a dll, not an executable\n", debugstr_us(&params->ImagePathName) );
        NtTerminateProcess( GetCurrentProcess(), STATUS_INVALID_IMAGE_FORMAT );
    }
#ifdef _WIN64
    if (!convert_to_pe64( module, &info ))
    {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto failed;
    }
#endif
    status = RtlDosPathNameToNtPathName_U_WithStatus( params->ImagePathName.Buffer, &nt_name, NULL, NULL );
    if (status) goto failed;
    status = build_module( NULL, &nt_name, &module, &info, NULL, DONT_RESOLVE_DLL_REFERENCES, FALSE,
                           FALSE, &wm );
    if (status) goto failed;
    RtlFreeUnicodeString( &nt_name );
    wm->ldr.LoadCount = -1;
    nt = RtlImageNtHeader( wm->ldr.DllBase );
    {
        WCHAR hb_loader_value[8] = {0};
        if (current_machine == IMAGE_FILE_MACHINE_ARM64 &&
            macrunner_hb_loader_env_enabled( hb_loader_value, sizeof(hb_loader_value), NULL ) &&
            nt && nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            macrunner_hb_amd64_main_on_arm64 = TRUE;
            if (macrunner_hb_trace_bootstrap())
                MESSAGE( "macrunner-hb-bootstrap-main-amd64-detected: image=%p entry=%p\n",
                         wm->ldr.DllBase, wm->ldr.EntryPoint );
        }
    }
    if ((current_machine == IMAGE_FILE_MACHINE_I386 && macrunner_hb_pe32_loader_trace_auto()) || macrunner_hb_trace_pe32_loader())
        MESSAGE( "macrunner-pe32-loader: build_main_module base=%p flags=%lx entry=%p machine=%04x info_machine=%04x\n",
                 wm->ldr.DllBase, wm->ldr.Flags, wm->ldr.EntryPoint, image_machine, info.Machine );
    return wm;
failed:
    MESSAGE( "wine: failed to create main module for %s, status %lx\n",
             debugstr_us(&params->ImagePathName), status );
    NtTerminateProcess( GetCurrentProcess(), status );
    return NULL;  /* unreached */
}


/***********************************************************************
 *	build_dlldata_path
 *
 * Helper for find_actctx_dll.
 */
static NTSTATUS build_dlldata_path( LPCWSTR libname, ACTCTX_SECTION_KEYED_DATA *data, LPWSTR *fullname )
{
    ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION *dlldata = data->lpData;
    ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT *path;
    char *base = data->lpSectionBase;
    SIZE_T total = dlldata->TotalPathLength + (wcslen(libname) + 1) * sizeof(WCHAR);
    WCHAR *p, *buffer;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;

    if (!(p = buffer = RtlAllocateHeap( GetProcessHeap(), 0, total ))) return STATUS_NO_MEMORY;
    path = (ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT *)(dlldata + 1);
    for (i = 0; i < dlldata->PathSegmentCount; i++)
    {
        memcpy( p, base + path[i].Offset, path[i].Length );
        p += path[i].Length / sizeof(WCHAR);
    }
    if (p == buffer || p[-1] == '\\') wcscpy( p, libname );
    else *p = 0;

    if (dlldata->Flags & ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_EXPAND)
    {
        RtlExpandEnvironmentStrings( NULL, buffer, wcslen(buffer), NULL, 0, &total );
        if ((*fullname = RtlAllocateHeap( GetProcessHeap(), 0, total * sizeof(WCHAR) )))
            RtlExpandEnvironmentStrings( NULL, buffer, wcslen(buffer), *fullname, total, NULL );
        else
            status = STATUS_NO_MEMORY;

        RtlFreeHeap( GetProcessHeap(), 0, buffer );
    }
    else *fullname = buffer;

    return status;
}


/***********************************************************************
 *	find_actctx_dll
 *
 * Find the full path (if any) of the dll from the activation context.
 */
static NTSTATUS find_actctx_dll( LPCWSTR libname, LPWSTR *fullname )
{
    static const WCHAR winsxsW[] = {'\\','w','i','n','s','x','s','\\'};

    ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION *info = NULL;
    ACTCTX_SECTION_KEYED_DATA data;
    ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION *dlldata;
    UNICODE_STRING nameW;
    NTSTATUS status;
    SIZE_T needed, size = 1024;
    WCHAR *p;

    RtlInitUnicodeString( &nameW, libname );
    data.cbSize = sizeof(data);
    status = RtlFindActivationContextSectionString( FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX, NULL,
                                                    ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION,
                                                    &nameW, &data );
    if (status != STATUS_SUCCESS) return status;

    if (data.ulLength < sizeof(*dlldata))
    {
        status = STATUS_SXS_KEY_NOT_FOUND;
        goto done;
    }
    dlldata = data.lpData;
    if (!(dlldata->Flags & ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT))
    {
        status = build_dlldata_path( libname, &data, fullname );
        goto done;
    }

    for (;;)
    {
        if (!(info = RtlAllocateHeap( GetProcessHeap(), 0, size )))
        {
            status = STATUS_NO_MEMORY;
            goto done;
        }
        status = RtlQueryInformationActivationContext( 0, data.hActCtx, &data.ulAssemblyRosterIndex,
                                                       AssemblyDetailedInformationInActivationContext,
                                                       info, size, &needed );
        if (status == STATUS_SUCCESS) break;
        if (status != STATUS_BUFFER_TOO_SMALL) goto done;
        RtlFreeHeap( GetProcessHeap(), 0, info );
        size = needed;
        /* restart with larger buffer */
    }

    if (!info->lpAssemblyManifestPath)
    {
        status = STATUS_SXS_KEY_NOT_FOUND;
        goto done;
    }

    if ((p = wcsrchr( info->lpAssemblyManifestPath, '\\' )))
    {
        DWORD len, dirlen = info->ulAssemblyDirectoryNameLength / sizeof(WCHAR);
        p++;
        len = wcslen( p );
        if (!dirlen || len <= dirlen ||
            RtlCompareUnicodeStrings( p, dirlen, info->lpAssemblyDirectoryName, dirlen, TRUE ) ||
            wcsicmp( p + dirlen, L".manifest" ))
        {
            /* manifest name does not match directory name, so it's not a global
             * windows/winsxs manifest; use the manifest directory name instead */
            dirlen = p - info->lpAssemblyManifestPath;
            needed = (dirlen + 1) * sizeof(WCHAR) + nameW.Length;
            if (!(*fullname = p = RtlAllocateHeap( GetProcessHeap(), 0, needed )))
            {
                status = STATUS_NO_MEMORY;
                goto done;
            }
            memcpy( p, info->lpAssemblyManifestPath, dirlen * sizeof(WCHAR) );
            p += dirlen;
            wcscpy( p, libname );
            goto done;
        }
    }

    if (!info->lpAssemblyDirectoryName)
    {
        status = STATUS_SXS_KEY_NOT_FOUND;
        goto done;
    }

    needed = (wcslen(windows_dir) * sizeof(WCHAR) +
              sizeof(winsxsW) + info->ulAssemblyDirectoryNameLength + nameW.Length + 2*sizeof(WCHAR));

    if (!(*fullname = p = RtlAllocateHeap( GetProcessHeap(), 0, needed )))
    {
        status = STATUS_NO_MEMORY;
        goto done;
    }
    wcscpy( p, windows_dir );
    p += wcslen(p);
    memcpy( p, winsxsW, sizeof(winsxsW) );
    p += ARRAY_SIZE( winsxsW );
    memcpy( p, info->lpAssemblyDirectoryName, info->ulAssemblyDirectoryNameLength );
    p += info->ulAssemblyDirectoryNameLength / sizeof(WCHAR);
    *p++ = '\\';
    wcscpy( p, libname );
done:
    RtlFreeHeap( GetProcessHeap(), 0, info );
    RtlReleaseActivationContext( data.hActCtx );
    return status;
}



/******************************************************************************
 *	find_apiset_dll
 */
static NTSTATUS find_apiset_dll( const WCHAR *name, WCHAR **fullname )
{
    const API_SET_NAMESPACE *map = NtCurrentTeb()->Peb->ApiSetMap;
    const API_SET_NAMESPACE_ENTRY *entry;
    UNICODE_STRING str;
    ULONG len;

    if (get_apiset_entry( map, name, wcslen(name), &entry ))
    {
        static const WCHAR ucrtbaseW[] = L"ucrtbase.dll";
        ULONG system_len = wcslen( system_dir );

        if (!macrunner_hb_is_ucrt_apiset_name( name )) return STATUS_APISET_NOT_PRESENT;
        len = system_len + ARRAY_SIZE(ucrtbaseW) - 1;
        if (!(*fullname = RtlAllocateHeap( GetProcessHeap(), 0, (len + 1) * sizeof(WCHAR) )))
            return STATUS_NO_MEMORY;
        wcscpy( *fullname, system_dir );
        memcpy( *fullname + system_len, ucrtbaseW, sizeof(ucrtbaseW) );
        return STATUS_SUCCESS;
    }
    if (get_apiset_target( map, entry, NULL, &str )) return STATUS_DLL_NOT_FOUND;

    len = wcslen( system_dir ) + str.Length / sizeof(WCHAR);
    if (!(*fullname = RtlAllocateHeap( GetProcessHeap(), 0, (len + 1) * sizeof(WCHAR) )))
        return STATUS_NO_MEMORY;
    wcscpy( *fullname, system_dir );
    memcpy( *fullname + wcslen( system_dir ), str.Buffer, str.Length );
    (*fullname)[len] = 0;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *	get_env_var
 */
static NTSTATUS get_env_var( const WCHAR *name, SIZE_T extra, UNICODE_STRING *ret )
{
    NTSTATUS status;
    SIZE_T len, size = 1024 + extra;

    for (;;)
    {
        ret->Buffer = RtlAllocateHeap( GetProcessHeap(), 0, size * sizeof(WCHAR) );
        if (!ret->Buffer)
        {
            ret->Length = ret->MaximumLength = 0;
            return STATUS_NO_MEMORY;
        }
        status = RtlQueryEnvironmentVariable( NULL, name, wcslen(name),
                                              ret->Buffer, size - extra - 1, &len );
        if (!status)
        {
            ret->Buffer[len] = 0;
            ret->Length = len * sizeof(WCHAR);
            ret->MaximumLength = size * sizeof(WCHAR);
            return status;
        }
        RtlFreeHeap( GetProcessHeap(), 0, ret->Buffer );
        if (status != STATUS_BUFFER_TOO_SMALL)
        {
            ret->Buffer = NULL;
            return status;
        }
        size = len + 1 + extra;
    }
}


/***********************************************************************
 *	find_builtin_without_file
 *
 * Find a builtin dll when the corresponding file cannot be found in the prefix.
 * This is used during prefix bootstrap.
 */
static NTSTATUS find_builtin_without_file( const WCHAR *name, UNICODE_STRING *new_name,
                                           WINE_MODREF **pwm, HANDLE *mapping,
                                           SECTION_IMAGE_INFORMATION *image_info, struct file_id *id )
{
    const WCHAR *ext;
    WCHAR dllpath[32];
    DWORD i, len;
    NTSTATUS status = STATUS_DLL_NOT_FOUND;
    BOOL found_image = FALSE;

    if (contains_path( name )) return status;

    /* CW HACK 20810: In Wow64/32-bit-bottle mode, 64-bit DLLs (like wow64*) won't be present in the prefix. */
    if (!is_prefix_bootstrap && !wow64_using_32bit_prefix)
    {
        /* 16-bit files can't be loaded from the prefix */
        if (!name[1] || wcscmp( name + wcslen(name) - 2, L"16" )) return status;
    }

    if (!get_env_var( L"WINEBUILDDIR", 20 + 2 * wcslen(name) + wcslen(pe_dir), new_name ))
    {
        len = new_name->Length;
        RtlAppendUnicodeToString( new_name, L"\\dlls\\" );
        RtlAppendUnicodeToString( new_name, name );
        if ((ext = wcsrchr( name, '.' )) && !wcscmp( ext, L".dll" )) new_name->Length -= 4 * sizeof(WCHAR);
        RtlAppendUnicodeToString( new_name, pe_dir );
        RtlAppendUnicodeToString( new_name, L"\\" );
        RtlAppendUnicodeToString( new_name, name );
        status = open_dll_file( new_name, pwm, mapping, image_info, id );
        if (status != STATUS_DLL_NOT_FOUND) goto done;

        new_name->Length = len;
        RtlAppendUnicodeToString( new_name, L"\\programs\\" );
        RtlAppendUnicodeToString( new_name, name );
        RtlAppendUnicodeToString( new_name, pe_dir );
        RtlAppendUnicodeToString( new_name, L"\\" );
        RtlAppendUnicodeToString( new_name, name );
        status = open_dll_file( new_name, pwm, mapping, image_info, id );
        if (status != STATUS_DLL_NOT_FOUND) goto done;
        RtlFreeUnicodeString( new_name );
    }

    for (i = 0; ; i++)
    {
        swprintf( dllpath, ARRAY_SIZE(dllpath), L"WINEDLLDIR%u", i );
        if (get_env_var( dllpath, wcslen(pe_dir) + wcslen(name) + 1, new_name )) break;
        len = new_name->Length;
        RtlAppendUnicodeToString( new_name, pe_dir );
        RtlAppendUnicodeToString( new_name, L"\\" );
        RtlAppendUnicodeToString( new_name, name );
        status = open_dll_file( new_name, pwm, mapping, image_info, id );
        if (status != STATUS_DLL_NOT_FOUND) goto done;
        new_name->Length = len;
        RtlAppendUnicodeToString( new_name, L"\\" );
        RtlAppendUnicodeToString( new_name, name );
        status = open_dll_file( new_name, pwm, mapping, image_info, id );
        if (status == STATUS_NOT_SUPPORTED) found_image = TRUE;
        else if (status != STATUS_DLL_NOT_FOUND) goto done;
        RtlFreeUnicodeString( new_name );
    }
    if (found_image) status = STATUS_NOT_SUPPORTED;

done:
    RtlFreeUnicodeString( new_name );
    if (!status && (status = build_sysdir_nt_name( name, new_name )))
    {
        if (*mapping)
        {
            NtClose( *mapping );
            *mapping = NULL;
        }
        *pwm = NULL;
    }
    return status;
}


/***********************************************************************
 *	search_dll_file
 *
 * Search for dll in the specified paths.
 */
static NTSTATUS search_dll_file( LPCWSTR paths, LPCWSTR search, UNICODE_STRING *nt_name,
                                 WINE_MODREF **pwm, HANDLE *mapping, SECTION_IMAGE_INFORMATION *image_info,
                                 struct file_id *id )
{
    WCHAR *name;
    BOOL found_image = FALSE;
    NTSTATUS status = STATUS_DLL_NOT_FOUND;
    ULONG len;
    BOOL pe32_system32_redirect = macrunner_hb_pe32_system32_redirect_enabled( search );

    /* CW HACK 20810:
     * 32-bit bottles from CrossOver 20 and earlier contain a stub wow64cpu.dll.
     * In Wow64/32-bit-bottle mode, this causes problems and isn't usable.
     * Return DLL_NOT_FOUND so the builtin gets used instead.
     */
    if (wow64_using_32bit_prefix && !wcscmp(search, L"wow64cpu.dll"))
        return STATUS_DLL_NOT_FOUND;

    /* CW HACK 20810:
     * 32-bit bottles from CrossOver 22 and earlier contain a fake win32u.dll.
     * In Wow64/32-bit-bottle mode, this causes problems and isn't usable.
     * Return DLL_NOT_FOUND so the builtin gets used instead.
     */
    if (wow64_using_32bit_prefix && !wcscmp(search, L"win32u.dll"))
        return STATUS_DLL_NOT_FOUND;

    if (!paths) paths = default_load_path;
    len = wcslen( paths );

    if (len < wcslen( system_dir )) len = wcslen( system_dir );
    len += wcslen( search ) + 2;

    if (!(name = RtlAllocateHeap( GetProcessHeap(), 0, len * sizeof(WCHAR) )))
        return STATUS_NO_MEMORY;

    while (*paths)
    {
        LPCWSTR ptr = paths;

        while (*ptr && *ptr != ';') ptr++;
        len = ptr - paths;
        if (*ptr == ';') ptr++;
        if (pe32_system32_redirect && macrunner_hb_path_segment_is_system32( paths, len ))
        {
            len = wcslen( syswow64_dir );
            memcpy( name, syswow64_dir, len * sizeof(WCHAR) );
            MESSAGE( "MacRunner HyperBridge PE32 system32 redirect %s via %s\n",
                   debugstr_w(search), debugstr_wn(name, len) );
        }
        else memcpy( name, paths, len * sizeof(WCHAR) );
        if (len && name[len - 1] != '\\') name[len++] = '\\';
        wcscpy( name + len, search );

        if (macrunner_hb_skip_x64_builtin_search_candidate( name ))
        {
            paths = ptr;
            continue;
        }

        nt_name->Buffer = NULL;
        if ((status = RtlDosPathNameToNtPathName_U_WithStatus( name, nt_name, NULL, NULL ))) goto done;

        status = open_dll_file( nt_name, pwm, mapping, image_info, id );
        if (status == STATUS_NOT_SUPPORTED) found_image = TRUE;
        else if (status != STATUS_DLL_NOT_FOUND) goto done;
        RtlFreeUnicodeString( nt_name );
        paths = ptr;
    }

    if (found_image) status = STATUS_NOT_SUPPORTED;

done:
    RtlFreeHeap( GetProcessHeap(), 0, name );
    return status;
}

/***********************************************************************
 *	find_dll_file
 *
 * Find the file (or already loaded module) for a given dll name.
 */
/* ★ 2026-08-30, лейн МЕЛКИЕ — SxS: разрешённый путь НЕ подменять однофамильцем из дистa.
 *
 * Замер (aarch64 winver, канал +module): перенаправление контекста активации РАБОТАЕТ —
 *   find_dll_file found L"C:\\windows\\winsxs\\arm64_...common-controls..._6.0.2600.2982_...\\comctl32.dll"
 * но следом наш macrunner_hb_open_native_builtin_dependency берёт от него ОДНО БАЗОВОЕ ИМЯ
 * и собирает путь заново в машинном каталоге дистa, теряя каталог сборки:
 *   => L"\\??\\Z:\\...\\lib\\wine\\aarch64-windows\\comctl32.dll"
 * За прогон 5 таких подмен, отображений из winsxs — ноль.
 *
 * Цена: comctl32 без версии 6 не имеет в таблице классов Button/Static/Edit/ListBox/
 * ComboBox/ComboLBox (commctrl.c:100, #if __WINE_COMCTL32_VERSION == 6), поэтому
 * RegisterClassNameW("Button") возвращает FALSE, класс "6.0.2600.2982!Button" не
 * регистрируется, и ЛЮБОЙ диалог теряет ВСЕ свои управляющие элементы. */
static BOOL macrunner_hb_sxs_keep_redirect_enabled(void)
{
    WCHAR value[8] = {0};

    if (!get_env( L"MACRUNNER_HB_SXS_KEEP_REDIRECT", value, sizeof(value) )) return TRUE;
    return value[0] && value[0] != '0';
}

/* ★ 2026-08-30, лейн МЕЛКИЕ, поправка к правке того же дня.
 *
 * Первая редакция держала ЛЮБОЙ перенаправленный путь — и это сломало i386.
 * Замер (i386 winver, пара на одном двоичном): окон 68 против 82, код выхода 53
 * против 0. Причина видна в зонде: каталог сборки в префиксе ОДИН, `arm64_`, и
 * 32-разрядному гостю доставался ARM64 comctl32. Подмена
 * macrunner_hb_open_native_builtin_dependency ровно за тем и стоит — вернуть модуль
 * НУЖНОЙ разрядности.
 *
 * Поэтому перенаправление держим только когда разрядность сборки отвечает гостю.
 * Не путь winsxs — прежнее поведение (там же ходит запасной путь v5
 * C:\windows\system32\comctl32.dll из get_class_version, и его трогать не нужно). */
static BOOL macrunner_hb_sxs_dir_matches_machine( const WCHAR *path )
{
    static const WCHAR marker[] = { 'w','i','n','s','x','s' };
    const WCHAR *p, *seg = NULL, *want;
    SIZE_T i, want_len;

    if (!path) return FALSE;

    for (p = path; *p; p++)
    {
        if (p != path && p[-1] != '\\' && p[-1] != '/') continue;
        for (i = 0; i < ARRAY_SIZE(marker); i++)
        {
            WCHAR c = p[i];
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            if (c != marker[i]) break;
        }
        if (i == ARRAY_SIZE(marker) && (p[i] == '\\' || p[i] == '/')) { seg = p + i + 1; break; }
    }
    if (!seg) return FALSE;

    switch (current_machine)
    {
    case IMAGE_FILE_MACHINE_ARM64: want = L"arm64_"; want_len = 6; break;
    case IMAGE_FILE_MACHINE_I386:  want = L"x86_";   want_len = 4; break;
    case IMAGE_FILE_MACHINE_AMD64: want = L"amd64_"; want_len = 6; break;
    default: return FALSE;
    }
    return !wcsnicmp( seg, want, want_len );
}

static NTSTATUS find_dll_file( const WCHAR *load_path, const WCHAR *libname, UNICODE_STRING *nt_name,
                               WINE_MODREF **pwm, HANDLE *mapping, SECTION_IMAGE_INFORMATION *image_info,
                               struct file_id *id, BOOL *redirected, BOOL find_loaded )
{
    WCHAR *fullname = NULL;
    NTSTATUS status;
    ULONG wow64_old_value = 0;

    *pwm = NULL;
    *redirected = FALSE;
    nt_name->Buffer = NULL;

    if (!contains_path( libname ))
    {
        status = find_apiset_dll( libname, &fullname );
        if (status == STATUS_DLL_NOT_FOUND) return status;

        if (status)
        {
            status = find_actctx_dll( libname, &fullname );
            if (status == STATUS_SUCCESS) *redirected = TRUE;
        }

        if (status == STATUS_SUCCESS)
        {
            TRACE ("found %s for %s\n", debugstr_w(fullname), debugstr_w(libname) );
            libname = fullname;
        }
        else
        {
            if (status != STATUS_SXS_KEY_NOT_FOUND) return status;
            if (macrunner_hb_native_counterpart_machine)
            {
                if ((*pwm = find_basename_module_machine( libname, macrunner_hb_native_counterpart_machine )))
                    return STATUS_SUCCESS;
            }
            else if (macrunner_hb_amd64_main_on_arm64)
            {
                if ((*pwm = find_basename_module_machine( libname, IMAGE_FILE_MACHINE_ARM64 )))
                    return STATUS_SUCCESS;
            }
            else if ((*pwm = find_basename_module( libname ))) return STATUS_SUCCESS;
            if (find_loaded)
            {
                TRACE( "Skipping file search for %s.\n", debugstr_w(libname) );
                return STATUS_DLL_NOT_FOUND;
            }
            if (!open_known_dll( libname, nt_name, pwm, mapping, image_info, id )) return STATUS_SUCCESS;
        }
    }

    /* Win 7/2008R2 and up seem to re-enable WoW64 FS redirection when loading libraries */
    RtlWow64EnableFsRedirectionEx( 0, &wow64_old_value );

    if (RtlDetermineDosPathNameType_U( libname ) == RtlPathTypeRelative)
    {
        status = macrunner_hb_open_native_builtin_dependency( libname, nt_name, pwm, mapping, image_info, id );
        if (status == STATUS_SUCCESS ||
            (status != STATUS_DLL_NOT_FOUND && status != STATUS_NOT_SUPPORTED))
            goto done;
        status = search_dll_file( load_path, libname, nt_name, pwm, mapping, image_info, id );
        if (status == STATUS_DLL_NOT_FOUND)
            status = find_builtin_without_file( libname, nt_name, pwm, mapping, image_info, id );
    }
    else
    {
        if (*redirected && macrunner_hb_sxs_keep_redirect_enabled() &&
            macrunner_hb_sxs_dir_matches_machine( libname ))
        {
            static unsigned mr_sxs_n;

            status = STATUS_DLL_NOT_FOUND;
            if (mr_sxs_n < 16)
            {
                mr_sxs_n++;
                MESSAGE( "macrunner-hb-sxs-keep: n=%u путь=%s\n",
                         mr_sxs_n, debugstr_w(libname) );
            }
        }
        else
            status = macrunner_hb_open_native_builtin_dependency( libname, nt_name, pwm, mapping, image_info, id );
        if (status == STATUS_SUCCESS ||
            (status != STATUS_DLL_NOT_FOUND && status != STATUS_NOT_SUPPORTED))
            goto done;
        if (!(status = RtlDosPathNameToNtPathName_U_WithStatus( libname, nt_name, NULL, NULL )))
            status = open_dll_file( nt_name, pwm, mapping, image_info, id );
    }

done:
    if (status == STATUS_NOT_SUPPORTED) status = STATUS_INVALID_IMAGE_FORMAT;

    RtlFreeHeap( GetProcessHeap(), 0, fullname );
    if (wow64_old_value) RtlWow64EnableFsRedirectionEx( 1, &wow64_old_value );
    return status;
}


/***********************************************************************
 *	load_dll  (internal)
 *
 * Load a PE style module according to the load order.
 * The loader_section must be locked while calling this function.
 */
static NTSTATUS load_dll( const WCHAR *load_path, const WCHAR *libname, DWORD flags, WINE_MODREF** pwm, BOOL system )
{
    UNICODE_STRING nt_name;
    struct file_id id;
    HANDLE mapping = 0;
    SECTION_IMAGE_INFORMATION image_info;
    NTSTATUS nts = STATUS_DLL_NOT_FOUND;
    BOOL redirected;
    void *prev;

    TRACE( "looking for %s in %s\n", debugstr_w(libname), debugstr_w(load_path) );

    if (system && system_dll_path.Buffer && !macrunner_hb_prefer_native_builtin_dependency())
        nts = search_dll_file( system_dll_path.Buffer, libname, &nt_name, pwm, &mapping, &image_info, &id );

    if (nts)
    {
        nts = find_dll_file( load_path, libname, &nt_name, pwm, &mapping, &image_info, &id,
                             &redirected, FALSE );
        system = FALSE;
    }

    if (*pwm)  /* found already loaded module */
    {
        if ((*pwm)->ldr.LoadCount != -1) (*pwm)->ldr.LoadCount++;

        TRACE("Found %s for %s at %p, count=%d\n",
              debugstr_w((*pwm)->ldr.FullDllName.Buffer), debugstr_w(libname),
              (*pwm)->ldr.DllBase, (*pwm)->ldr.LoadCount);
        RtlFreeUnicodeString( &nt_name );
        return STATUS_SUCCESS;
    }

    if (nts && nts != STATUS_INVALID_IMAGE_NOT_MZ) goto done;

    prev = NtCurrentTeb()->Tib.ArbitraryUserPointer;
    NtCurrentTeb()->Tib.ArbitraryUserPointer = nt_name.Buffer + 4;

    switch (nts)
    {
    case STATUS_INVALID_IMAGE_NOT_MZ:  /* not in PE format, maybe it's a .so file */
        if (__wine_unixlib_handle) nts = load_so_dll( load_path, &nt_name, flags, pwm );
        break;

    case STATUS_SUCCESS:  /* valid PE file */
        nts = load_native_dll( load_path, &nt_name, mapping, &image_info, &id, flags, system,
                               redirected, pwm );
        break;
    }

    NtCurrentTeb()->Tib.ArbitraryUserPointer = prev;

done:
    if (nts == STATUS_SUCCESS)
        TRACE("Loaded module %s at %p\n", debugstr_us(&nt_name), (*pwm)->ldr.DllBase);
    else
    {
        static unsigned int macrunner_ldr_fail_trace_count;

        if (macrunner_ldr_fail_trace_count++ < 128)
            MESSAGE( "macrunner-ldr-load-dll-fail: status=%08lx lib=%s load_path=%s "
                 "flags=%08lx system=%u nt=%s\n",
                 nts, debugstr_w(libname), debugstr_w(load_path), flags, system,
                 debugstr_us(&nt_name) );
        WARN("Failed to load module %s; status=%lx\n", debugstr_w(libname), nts);
    }

    if (mapping) NtClose( mapping );
    RtlFreeUnicodeString( &nt_name );
    return nts;
}


/***********************************************************************
 *              __wine_ctrl_routine
 */
NTSTATUS WINAPI __wine_ctrl_routine( void *arg )
{
    DWORD ret = pCtrlRoutine ? pCtrlRoutine( arg ) : 0;
    RtlExitUserThread( ret );
}


/***********************************************************************
 *              __wine_unix_call
 *
 * CW HACK 22435: Needed by D3DMetal PE DLLs
 */
NTSTATUS WINAPI __wine_unix_call_exported( unixlib_handle_t handle, unsigned int code, void *args )
{
    return __wine_unix_call( handle, code, args );
}


/***********************************************************************
 *           __wine_unix_spawnvp
 */
NTSTATUS WINAPI __wine_unix_spawnvp( char * const argv[], int wait )
{
    struct wine_spawnvp_params params = { (char **)argv, wait };

    return WINE_UNIX_CALL( unix_wine_spawnvp, &params );
}


/***********************************************************************
 *           wine_server_call
 */
unsigned int CDECL wine_server_call( void *req_ptr )
{
    return WINE_UNIX_CALL( unix_wine_server_call, req_ptr );
}


/***********************************************************************
 *           wine_server_fd_to_handle
 */
NTSTATUS CDECL wine_server_fd_to_handle( int fd, unsigned int access, unsigned int attributes,
                                         HANDLE *handle )
{
    struct wine_server_fd_to_handle_params params = { fd, access, attributes, handle };

    return WINE_UNIX_CALL( unix_wine_server_fd_to_handle, &params );
}


/***********************************************************************
 *           wine_server_handle_to_fd (NTDLL.@)
 */
NTSTATUS CDECL wine_server_handle_to_fd( HANDLE handle, unsigned int access, int *unix_fd,
                                         unsigned int *options )
{
    struct wine_server_handle_to_fd_params params = { handle, access, unix_fd, options };

    return WINE_UNIX_CALL( unix_wine_server_handle_to_fd, &params );
}

/******************************************************************
 *		LdrLoadDll (NTDLL.@)
 */
NTSTATUS WINAPI DECLSPEC_HOTPATCH LdrLoadDll(LPCWSTR path_name, DWORD flags,
                                             const UNICODE_STRING *libname, HMODULE* hModule)
{
    macrunner_hb_language_observer_init_fn language_observer_init = NULL;
    HMODULE language_observer_module = NULL;
    WINE_MODREF *wm;
    BOOL language_observer_candidate = macrunner_hb_language_observer_enabled() &&
                                       macrunner_hb_is_exact_mono_name( libname );
    BOOL load_language_observer = FALSE;
    NTSTATUS nts;
    WCHAR *dllname = append_dll_ext( libname->Buffer );

    if (language_observer_candidate &&
        macrunner_hb_prepare_language_observer( &language_observer_module,
                                                 &language_observer_init ) &&
        macrunner_hb_start_language_observer( language_observer_module,
                                               language_observer_init ) &&
        macrunner_hb_wait_language_observer_state( 1, "observer-worker-start-timeout" ))
        load_language_observer = TRUE;

    RtlEnterCriticalSection( &loader_section );

    nts = load_dll( path_name, dllname ? dllname : libname->Buffer, flags, &wm, FALSE );

    if (load_language_observer)
    {
        if (!nts && wm && macrunner_hb_is_exact_mono_name( &wm->ldr.BaseDllName ))
            load_language_observer = macrunner_hb_publish_language_observer_mono(
                wm->ldr.DllBase );
        else
        {
            macrunner_hb_cancel_language_observer();
            load_language_observer = FALSE;
        }
    }

    if (nts == STATUS_SUCCESS)
    {
        nts = process_attach( wm->ldr.DdagNode, NULL );
        if (nts != STATUS_SUCCESS)
        {
            if (load_language_observer) macrunner_hb_cancel_language_observer();
            LdrUnloadDll(wm->ldr.DllBase);
            wm = NULL;
        }
        /* MacRunner (HK DllMain lane): winemac.drv is the one wine builtin nobody imports, so
         * import_dll()'s native-counterpart swap never gives it an aarch64 twin.  Give it one
         * here, at the explicit LdrLoadDll that User32LoadDriver issues.  Gated, and a no-op
         * for every other module -- see macrunner_hb_attach_winemac_native_twin(). */
        if (nts == STATUS_SUCCESS) macrunner_hb_attach_winemac_native_twin( wm );
    }
    *hModule = (wm) ? wm->ldr.DllBase : NULL;

    if (nts)
    {
        static unsigned int macrunner_ldr_load_dll_trace_count;

        if (macrunner_ldr_load_dll_trace_count++ < 128)
            MESSAGE( "macrunner-ldr-LdrLoadDll-fail: status=%08lx name=%s path=%s "
                 "flags=%08lx module=%p\n",
                 nts, debugstr_w(dllname ? dllname : libname->Buffer),
                 debugstr_w(path_name), flags, *hModule );
    }

    RtlLeaveCriticalSection( &loader_section );
    RtlFreeHeap( GetProcessHeap(), 0, dllname );
    return nts;
}


/******************************************************************
 *		LdrGetDllFullName (NTDLL.@)
 */
NTSTATUS WINAPI LdrGetDllFullName( HMODULE module, UNICODE_STRING *name )
{
    WINE_MODREF *wm;
    NTSTATUS status;

    TRACE( "module %p, name %p.\n", module, name );

    if (!module) module = NtCurrentTeb()->Peb->ImageBaseAddress;

    RtlEnterCriticalSection( &loader_section );
    wm = get_modref( module );
    if (wm)
    {
        RtlCopyUnicodeString( name, &wm->ldr.FullDllName );
        if (name->MaximumLength < wm->ldr.FullDllName.Length + sizeof(WCHAR)) status = STATUS_BUFFER_TOO_SMALL;
        else status = STATUS_SUCCESS;
    } else status = STATUS_DLL_NOT_FOUND;
    RtlLeaveCriticalSection( &loader_section );

    return status;
}


/******************************************************************
 *		LdrGetDllHandleEx (NTDLL.@)
 */
NTSTATUS WINAPI LdrGetDllHandleEx( ULONG flags, LPCWSTR load_path, ULONG *dll_characteristics,
                                           const UNICODE_STRING *name, HMODULE *base )
{
    static const ULONG supported_flags = LDR_GET_DLL_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT
                                         | LDR_GET_DLL_HANDLE_EX_FLAG_PIN;
    static const ULONG valid_flags = LDR_GET_DLL_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT
                                     | LDR_GET_DLL_HANDLE_EX_FLAG_PIN | 4;
    SECTION_IMAGE_INFORMATION image_info;
    UNICODE_STRING nt_name;
    struct file_id id;
    BOOL redirected;
    NTSTATUS status;
    WINE_MODREF *wm;
    WCHAR *dllname;
    HANDLE mapping;

    TRACE( "flags %#lx, load_path %p, dll_characteristics %p, name %p, base %p.\n",
            flags, load_path, dll_characteristics, name, base );

    if (flags & ~valid_flags) return STATUS_INVALID_PARAMETER;

    if ((flags & (LDR_GET_DLL_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | LDR_GET_DLL_HANDLE_EX_FLAG_PIN))
                 == (LDR_GET_DLL_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | LDR_GET_DLL_HANDLE_EX_FLAG_PIN))
        return STATUS_INVALID_PARAMETER;

    if (flags & ~supported_flags) FIXME( "Unsupported flags %#lx.\n", flags );
    if (dll_characteristics) FIXME( "dll_characteristics unsupported.\n" );

    dllname = append_dll_ext( name->Buffer );

    RtlEnterCriticalSection( &loader_section );

    status = find_dll_file( load_path, dllname ? dllname : name->Buffer,
                            &nt_name, &wm, &mapping, &image_info, &id, &redirected, TRUE );

    if (wm) *base = wm->ldr.DllBase;
    else
    {
        if (status == STATUS_SUCCESS) NtClose( mapping );
        status = STATUS_DLL_NOT_FOUND;
    }
    RtlFreeUnicodeString( &nt_name );

    if (!status)
    {
        if (flags & LDR_GET_DLL_HANDLE_EX_FLAG_PIN)
            LdrAddRefDll( LDR_ADDREF_DLL_PIN, *base );
        else if (!(flags & LDR_GET_DLL_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT))
            LdrAddRefDll( 0, *base );
    }

    RtlLeaveCriticalSection( &loader_section );
    RtlFreeHeap( GetProcessHeap(), 0, dllname );
    TRACE( "%s -> %p (load path %s)\n", debugstr_us(name), status ? NULL : *base, debugstr_w(load_path) );
    return status;
}


/******************************************************************
 *		LdrGetDllHandle (NTDLL.@)
 */
NTSTATUS WINAPI LdrGetDllHandle( LPCWSTR load_path, ULONG flags, const UNICODE_STRING *name, HMODULE *base )
{
    return LdrGetDllHandleEx( LDR_GET_DLL_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, load_path, NULL, name, base );
}


/******************************************************************
 *		LdrAddRefDll (NTDLL.@)
 */
NTSTATUS WINAPI LdrAddRefDll( ULONG flags, HMODULE module )
{
    NTSTATUS ret = STATUS_SUCCESS;
    WINE_MODREF *wm;

    if (flags & ~LDR_ADDREF_DLL_PIN) FIXME( "%p flags %lx not implemented\n", module, flags );

    RtlEnterCriticalSection( &loader_section );

    if ((wm = get_modref( module )))
    {
        if (flags & LDR_ADDREF_DLL_PIN)
            wm->ldr.LoadCount = -1;
        else
            if (wm->ldr.LoadCount != -1) wm->ldr.LoadCount++;
        TRACE( "(%s) ldr.LoadCount: %d\n", debugstr_w(wm->ldr.BaseDllName.Buffer), wm->ldr.LoadCount );
    }
    else ret = STATUS_INVALID_PARAMETER;

    RtlLeaveCriticalSection( &loader_section );
    return ret;
}


/***********************************************************************
 *           LdrProcessRelocationBlock  (NTDLL.@)
 *
 * Apply relocations to a given page of a mapped PE image.
 */
IMAGE_BASE_RELOCATION * WINAPI LdrProcessRelocationBlock( void *page, UINT count,
                                                          USHORT *relocs, INT_PTR delta )
{
    while (count--)
    {
        USHORT offset = *relocs & 0xfff;
        int type = *relocs >> 12;
        switch(type)
        {
        case IMAGE_REL_BASED_ABSOLUTE:
            break;
        case IMAGE_REL_BASED_HIGH:
            *(short *)((char *)page + offset) += HIWORD(delta);
            break;
        case IMAGE_REL_BASED_LOW:
            *(short *)((char *)page + offset) += LOWORD(delta);
            break;
        case IMAGE_REL_BASED_HIGHLOW:
            *(int *)((char *)page + offset) += delta;
            break;
        case IMAGE_REL_BASED_HIGHADJ:
            if (!count) return NULL;
            *(short *)((char *)page + offset) += HIWORD( delta + (short)relocs[1] );
            relocs++;
            count--;
            break;
#ifdef _WIN64
        case IMAGE_REL_BASED_DIR64:
            *(INT_PTR *)((char *)page + offset) += delta;
            break;
#elif defined(__arm__)
        case IMAGE_REL_BASED_THUMB_MOV32:
        {
            UINT *inst = (UINT *)((char *)page + offset);
            WORD lo = ((inst[0] << 1) & 0x0800) + ((inst[0] << 12) & 0xf000) +
                      ((inst[0] >> 20) & 0x0700) + ((inst[0] >> 16) & 0x00ff);
            WORD hi = ((inst[1] << 1) & 0x0800) + ((inst[1] << 12) & 0xf000) +
                      ((inst[1] >> 20) & 0x0700) + ((inst[1] >> 16) & 0x00ff);
            DWORD imm = MAKELONG( lo, hi ) + delta;

            lo = LOWORD( imm );
            hi = HIWORD( imm );

            if ((inst[0] & 0x8000fbf0) != 0x0000f240 || (inst[1] & 0x8000fbf0) != 0x0000f2c0)
                ERR("wrong Thumb2 instruction @%p %08x:%08x, expected MOVW/MOVT\n",
                    inst, inst[0], inst[1] );

            inst[0] = (inst[0] & 0x8f00fbf0) + ((lo >> 1) & 0x0400) + ((lo >> 12) & 0x000f) +
                                               ((lo << 20) & 0x70000000) + ((lo << 16) & 0xff0000);
            inst[1] = (inst[1] & 0x8f00fbf0) + ((hi >> 1) & 0x0400) + ((hi >> 12) & 0x000f) +
                                               ((hi << 20) & 0x70000000) + ((hi << 16) & 0xff0000);
            break;
        }
#endif
        default:
            FIXME("Unknown/unsupported fixup type %x.\n", type);
            return NULL;
        }
        relocs++;
    }
    return (IMAGE_BASE_RELOCATION *)relocs;  /* return address of next block */
}


/******************************************************************
 *		LdrQueryProcessModuleInformation
 *
 */
NTSTATUS WINAPI LdrQueryProcessModuleInformation(RTL_PROCESS_MODULES *smi,
                                                 ULONG buf_size, ULONG* req_size)
{
    RTL_PROCESS_MODULE_INFORMATION *sm = &smi->Modules[0];
    ULONG               size = sizeof(ULONG);
    NTSTATUS            nts = STATUS_SUCCESS;
    ANSI_STRING         str;
    char*               ptr;
    PLIST_ENTRY         mark, entry;
    LDR_DATA_TABLE_ENTRY *mod;
    WORD id = 0;

    smi->ModulesCount = 0;

    RtlEnterCriticalSection( &loader_section );
    mark = &NtCurrentTeb()->Peb->LdrData->InLoadOrderModuleList;
    for (entry = mark->Flink; entry != mark; entry = entry->Flink)
    {
        mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        size += sizeof(*sm);
        if (size <= buf_size)
        {
            sm->Section = 0; /* FIXME */
            sm->MappedBaseAddress = mod->DllBase;
            sm->ImageBaseAddress = mod->DllBase;
            sm->ImageSize = mod->SizeOfImage;
            sm->Flags = mod->Flags;
            sm->LoadOrderIndex = id++;
            sm->InitOrderIndex = 0; /* FIXME */
            sm->LoadCount = mod->LoadCount;
            str.Length = 0;
            str.MaximumLength = MAXIMUM_FILENAME_LENGTH;
            str.Buffer = (char*)sm->Name;
            RtlUnicodeStringToAnsiString(&str, &mod->FullDllName, FALSE);
            ptr = strrchr(str.Buffer, '\\');
            sm->NameOffset = (ptr != NULL) ? (ptr - str.Buffer + 1) : 0;

            smi->ModulesCount++;
            sm++;
        }
        else nts = STATUS_INFO_LENGTH_MISMATCH;
    }
    RtlLeaveCriticalSection( &loader_section );

    if (req_size) *req_size = size;

    return nts;
}


static NTSTATUS query_dword_option( HANDLE hkey, LPCWSTR name, LONG *value )
{
    NTSTATUS status;
    UNICODE_STRING str;
    ULONG size;
    WCHAR buffer[64];
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)buffer;

    RtlInitUnicodeString( &str, name );

    size = sizeof(buffer) - sizeof(WCHAR);
    if ((status = NtQueryValueKey( hkey, &str, KeyValuePartialInformation, buffer, size, &size )))
        return status;

    if (info->Type != REG_DWORD)
    {
        buffer[size / sizeof(WCHAR)] = 0;
        *value = wcstoul( (WCHAR *)info->Data, 0, 16 );
    }
    else memcpy( value, info->Data, sizeof(*value) );
    return status;
}

static NTSTATUS query_string_option( HANDLE hkey, LPCWSTR name, ULONG type,
                                     void *data, ULONG in_size, ULONG *out_size )
{
    NTSTATUS status;
    UNICODE_STRING str;
    ULONG size;
    char *buffer;
    KEY_VALUE_PARTIAL_INFORMATION *info;
    static const int info_size = FIELD_OFFSET( KEY_VALUE_PARTIAL_INFORMATION, Data );

    RtlInitUnicodeString( &str, name );

    size = info_size + in_size;
    if (!(buffer = RtlAllocateHeap( GetProcessHeap(), 0, size ))) return STATUS_NO_MEMORY;
    info = (KEY_VALUE_PARTIAL_INFORMATION *)buffer;
    status = NtQueryValueKey( hkey, &str, KeyValuePartialInformation, buffer, size, &size );
    if (!status || status == STATUS_BUFFER_OVERFLOW)
    {
        if (out_size) *out_size = info->DataLength;
        if (data && !status) memcpy( data, info->Data, info->DataLength );
    }
    RtlFreeHeap( GetProcessHeap(), 0, buffer );
    return status;
}


/******************************************************************
 *		LdrQueryImageFileExecutionOptions  (NTDLL.@)
 */
NTSTATUS WINAPI LdrQueryImageFileExecutionOptions( const UNICODE_STRING *key, LPCWSTR value, ULONG type,
                                                   void *data, ULONG in_size, ULONG *out_size )
{
    static const WCHAR optionsW[] = L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
    WCHAR path[MAX_PATH + ARRAY_SIZE( optionsW )];
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name_str;
    HANDLE hkey;
    NTSTATUS status;
    ULONG len;
    WCHAR *p;

    InitializeObjectAttributes( &attr, &name_str, OBJ_CASE_INSENSITIVE, 0, NULL );
    p = key->Buffer + key->Length / sizeof(WCHAR);
    while (p > key->Buffer && p[-1] != '\\') p--;
    len = key->Length - (p - key->Buffer) * sizeof(WCHAR);
    name_str.Buffer = path;
    name_str.Length = sizeof(optionsW) - sizeof(WCHAR) + len;
    name_str.MaximumLength = name_str.Length;
    memcpy( path, optionsW, sizeof(optionsW) );
    memcpy( path + ARRAY_SIZE( optionsW ) - 1, p, len );
    if ((status = NtOpenKey( &hkey, KEY_QUERY_VALUE, &attr ))) return status;

    if (type == REG_DWORD)
    {
        if (out_size) *out_size = sizeof(ULONG);
        if (in_size >= sizeof(ULONG)) status = query_dword_option( hkey, value, data );
        else status = STATUS_BUFFER_OVERFLOW;
    }
    else status = query_string_option( hkey, value, type, data, in_size, out_size );

    NtClose( hkey );
    return status;
}


/******************************************************************
 *		RtlDllShutdownInProgress  (NTDLL.@)
 */
BOOLEAN WINAPI RtlDllShutdownInProgress(void)
{
    return process_detaching;
}

/* ARM64X carries native and hybrid delay-import IAT/INT tables back-to-back.
 * The dynamic-relocation view selected for an AMD64 main image rewrites the
 * shared descriptor to the hybrid tables, while a native ARM64 thunk still
 * passes its slot from the immediately adjacent native tables.  Select the
 * sibling view only when CHPE metadata advertises the dual delay-IAT family
 * and both complete, terminated tables fit inside the image. */
static BOOL macrunner_hb_select_arm64x_delay_import_view( void *base,
                                                          IMAGE_THUNK_DATA **iat,
                                                          IMAGE_THUNK_DATA **int_table,
                                                          SIZE_T import_count,
                                                          IMAGE_THUNK_DATA *addr )
{
    IMAGE_ARM64EC_METADATA *metadata = macrunner_hb_get_arm64x_metadata( base );
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( base );
    ULONG_PTR image_base = (ULONG_PTR)base, image_end;
    ULONG_PTR iat_addr = (ULONG_PTR)*iat, int_addr = (ULONG_PTR)*int_table;
    ULONG_PTR thunk_addr = (ULONG_PTR)addr, candidate_iat_addr, candidate_int_addr;
    SIZE_T candidate_count, span;
    int direction;

    if (!metadata || !nt || !import_count) return FALSE;
    if (!image_contains_array( base, metadata, 1, sizeof(*metadata) )) return FALSE;
    if (metadata->Version < 2) return FALSE;
    if (!metadata->AuxiliaryDelayloadIAT || !metadata->AuxiliaryDelayloadIATCopy)
        return FALSE;
    if (!image_contains_array( base, get_rva( base, metadata->AuxiliaryDelayloadIAT ),
                               1, sizeof(IMAGE_THUNK_DATA) ) ||
        !image_contains_array( base, get_rva( base, metadata->AuxiliaryDelayloadIATCopy ),
                               1, sizeof(IMAGE_THUNK_DATA) ))
        return FALSE;
    if (import_count == ~(SIZE_T)0 || import_count + 1 > ~(SIZE_T)0 / sizeof(**iat))
        return FALSE;
    span = (import_count + 1) * sizeof(**iat);
    if (span > nt->OptionalHeader.SizeOfImage) return FALSE;
    if (nt->OptionalHeader.SizeOfImage > ~(ULONG_PTR)0 - image_base) return FALSE;
    image_end = image_base + nt->OptionalHeader.SizeOfImage;

    for (direction = -1; direction <= 1; direction += 2)
    {
        if (direction < 0)
        {
            if (iat_addr < image_base + span || int_addr < image_base + span) continue;
            candidate_iat_addr = iat_addr - span;
            candidate_int_addr = int_addr - span;
        }
        else
        {
            if (iat_addr > image_end - span || int_addr > image_end - span) continue;
            candidate_iat_addr = iat_addr + span;
            candidate_int_addr = int_addr + span;
        }

        if (candidate_iat_addr < image_base || candidate_iat_addr > image_end - span ||
            candidate_int_addr < image_base || candidate_int_addr > image_end - span)
            continue;
        if (!image_contains_array( base, (void *)candidate_iat_addr, import_count + 1,
                                   sizeof(**iat) ) ||
            !image_contains_array( base, (void *)candidate_int_addr, import_count + 1,
                                   sizeof(**int_table) ))
            continue;
        if ((*iat)[import_count].u1.Function ||
            ((IMAGE_THUNK_DATA *)candidate_iat_addr)[import_count].u1.Function)
            continue;
        if (get_import_thunk_count( base, (IMAGE_THUNK_DATA *)candidate_int_addr,
                                    &candidate_count ) || candidate_count != import_count)
            continue;
        if (thunk_addr < candidate_iat_addr ||
            thunk_addr - candidate_iat_addr >= import_count * sizeof(**iat) ||
            (thunk_addr - candidate_iat_addr) % sizeof(**iat))
            continue;

        *iat = (IMAGE_THUNK_DATA *)candidate_iat_addr;
        *int_table = (IMAGE_THUNK_DATA *)candidate_int_addr;
        return TRUE;
    }
    return FALSE;
}

static int macrunner_hb_arm64x_code_type( HMODULE base, const void *ptr )
{
    IMAGE_ARM64EC_METADATA *metadata = macrunner_hb_get_arm64x_metadata( base );
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( base );

    if (!nt || !metadata || (ULONG_PTR)ptr < (ULONG_PTR)base ||
        !image_contains_range( base, metadata, offsetof( IMAGE_ARM64EC_METADATA, CodeRangesToEntryPoints ) ))
        return -1;
    return mr_arm64x_code_kind( base, nt->OptionalHeader.SizeOfImage, metadata->CodeMap,
                               metadata->CodeMapCount, (ULONG_PTR)ptr - (ULONG_PTR)base );
}

/* Resolve the export in the selected EC view, not the plain ARM64 sibling.
 * A varargs call cannot cross those ABIs by just changing its function pointer. */
static FARPROC macrunner_hb_delay_ec_export( FARPROC proc )
{
    WINE_MODREF *wm;
    IMAGE_ARM64EC_METADATA *metadata;
    const IMAGE_ARM64EC_REDIRECTION_ENTRY *map;
    ULONG_PTR rva;
    ULONG i;
    FARPROC ret = NULL;

    RtlEnterCriticalSection( &loader_section );
    if (!(wm = macrunner_hb_find_module_from_address( (ULONG_PTR)proc )) ||
        !(metadata = macrunner_hb_get_arm64x_metadata( wm->ldr.DllBase )) ||
        !image_contains_range( wm->ldr.DllBase, metadata,
                              offsetof( IMAGE_ARM64EC_METADATA, GetX64InformationFunctionPointer ) ))
        goto done;
    rva = (ULONG_PTR)proc - (ULONG_PTR)wm->ldr.DllBase;
    map = get_rva( wm->ldr.DllBase, metadata->RedirectionMetadata );
    if (!image_contains_array( wm->ldr.DllBase, map, metadata->RedirectionMetadataCount, sizeof(*map) ))
        goto done;
    for (i = 0; i < metadata->RedirectionMetadataCount; i++)
        if (map[i].Source == rva)
        {
            proc = image_rva_range( wm->ldr.DllBase, map[i].Destination, 4 );
            break;
        }
    if (proc && !((ULONG_PTR)proc & 3) &&
        macrunner_hb_arm64x_code_type( wm->ldr.DllBase, proc ) == 1 &&
        macrunner_hb_address_in_executable_section( wm->ldr.DllBase, (ULONG_PTR)proc ))
        ret = proc;
done:
    RtlLeaveCriticalSection( &loader_section );
    return ret;
}

/* ARM64X in its live EC view also reports AMD64. Machine alone cannot
 * distinguish it from an already-loaded, pure-x64 KnownDll. */
static BOOL macrunner_hb_delay_module_is_ec( WINE_MODREF *wm )
{
    IMAGE_ARM64EC_METADATA *metadata;
    IMAGE_NT_HEADERS *nt;
    const IMAGE_ARM64EC_REDIRECTION_ENTRY *map;
    void *entry;

    if (!wm || !(wm->ldr.Flags & LDR_WINE_INTERNAL) ||
        (wm->ldr.Flags & (LDR_REDIRECTED | LDR_DONT_RESOLVE_REFS))) return FALSE;
    if (!(nt = RtlImageNtHeader( wm->ldr.DllBase )) ||
        (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
         nt->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64EC)) return FALSE;
    if (!(metadata = macrunner_hb_get_arm64x_metadata( wm->ldr.DllBase )) ||
        !image_contains_range( wm->ldr.DllBase, metadata,
                              offsetof( IMAGE_ARM64EC_METADATA, GetX64InformationFunctionPointer ) ))
        return FALSE;
    map = get_rva( wm->ldr.DllBase, metadata->RedirectionMetadata );
    if (!image_contains_array( wm->ldr.DllBase, map, metadata->RedirectionMetadataCount, sizeof(*map) ) ||
        !macrunner_hb_module_live_half_is_ec( wm )) return FALSE;
    entry = (void *)macrunner_hb_arm64x_entry_from_view( wm, NULL );
    return entry && !((ULONG_PTR)entry & 3) &&
           macrunner_hb_arm64x_code_type( wm->ldr.DllBase, entry ) == 1 &&
           macrunner_hb_address_in_executable_section( wm->ldr.DllBase, (ULONG_PTR)entry );
}

static WINE_MODREF *macrunner_hb_find_delay_ec_module( const UNICODE_STRING *name )
{
    PLIST_ENTRY mark = &hash_table[hash_basename( name )], entry;

    for (entry = mark->Flink; entry != mark; entry = entry->Flink)
    {
        WINE_MODREF *wm = CONTAINING_RECORD(entry, WINE_MODREF, ldr.HashLinks);

        if (RtlEqualUnicodeString( name, &wm->ldr.BaseDllName, TRUE ) &&
            macrunner_hb_delay_module_is_ec( wm )) return wm;
    }
    return NULL;
}

/* Called with loader_section held by the native dispatch resolver. Keep
 * reference/attach semantics, but never let basename/KnownDll reuse select
 * the x64 copy, or use plain ARM64 as a fallback for an EC varargs call. */
static NTSTATUS macrunner_hb_load_delay_ec_module( const UNICODE_STRING *name, HMODULE *module )
{
    WINE_MODREF *wm = *module ? get_modref( *module ) : NULL;
    UNICODE_STRING basename;
    WCHAR *redirected = NULL, *path = NULL;
    HMODULE acquired = NULL;
    NTSTATUS status;

    /* A populated cache owns the module used by previously resolved slots.
     * Do not replace/unload it without also rebinding those slots. */
    if (*module)
    {
        if (!wm) return STATUS_INVALID_PARAMETER;
        return macrunner_hb_delay_module_is_ec( wm ) ? STATUS_SUCCESS : STATUS_INVALID_IMAGE_FORMAT;
    }

    status = find_apiset_dll( name->Buffer, &redirected );
    if (status && status != STATUS_APISET_NOT_PRESENT) goto done;
    RtlInitUnicodeString( &basename, macrunner_hb_basename_from_path( redirected ? redirected : name->Buffer ) );
    if ((wm = macrunner_hb_find_delay_ec_module( &basename )))
    {
        if ((status = LdrAddRefDll( 0, wm->ldr.DllBase ))) goto done;
    }
    else
    {
        if (!(path = macrunner_hb_build_native_builtin_path( basename.Buffer )))
        {
            status = STATUS_DLL_NOT_FOUND;
            goto done;
        }
        /* Explicit builtin path bypasses KnownDll basename reuse. Mapping
         * still chooses the process's EC view; no AA64 machine override. */
        if ((status = load_dll( NULL, path, 0, &wm, FALSE ))) goto done;
    }
    acquired = wm->ldr.DllBase;
    if (!macrunner_hb_delay_module_is_ec( wm ))
        status = STATUS_INVALID_IMAGE_FORMAT;
    else
        status = process_attach( wm->ldr.DdagNode, NULL );
    if (!status)
    {
        *module = acquired;
        acquired = NULL;
    }
done:
    if (acquired) LdrUnloadDll( acquired );
    RtlFreeHeap( GetProcessHeap(), 0, path );
    RtlFreeHeap( GetProcessHeap(), 0, redirected );
    return status;
}

static void *resolve_delay_loaded_api( void *base, const IMAGE_DELAYLOAD_DESCRIPTOR *desc,
                                      PDELAYLOAD_FAILURE_DLL_CALLBACK dllhook,
                                      PDELAYLOAD_FAILURE_SYSTEM_ROUTINE syshook,
                                      IMAGE_THUNK_DATA *addr, ULONG flags, BOOL native_ec );

#if defined(__aarch64__) && !defined(__arm64ec__)
/* Match a decoded LEA's slot to a real, terminated delay-import descriptor.
 * The sibling-table selection is shared with the normal resolver. */
static const IMAGE_DELAYLOAD_DESCRIPTOR *macrunner_hb_delay_descriptor_for_slot(
    HMODULE base, IMAGE_THUNK_DATA *slot )
{
    const IMAGE_DELAYLOAD_DESCRIPTOR *table, *match = NULL;
    IMAGE_ARM64EC_METADATA *metadata = macrunner_hb_get_arm64x_metadata( base );
    ULONG size = 0, i, count;

    if (!metadata || !image_contains_range( base, metadata,
                                           offsetof( IMAGE_ARM64EC_METADATA, HybridImageInfoBitfield ) ) ||
        metadata->Version < 2 || !metadata->AuxiliaryDelayloadIAT || !metadata->AuxiliaryDelayloadIATCopy)
        return NULL;
    table = RtlImageDirectoryEntryToData( base, TRUE, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, &size );
    count = size / sizeof(*table);
    if (!table || !count || size % sizeof(*table) ||
        !image_contains_array( base, table, count, sizeof(*table) )) return NULL;
    for (i = 0; i < count; i++)
    {
        IMAGE_THUNK_DATA *iat, *names;
        SIZE_T imports, offset;

        if (!table[i].DllNameRVA)
        {
            static const IMAGE_DELAYLOAD_DESCRIPTOR terminator;
            return memcmp( &table[i], &terminator, sizeof(terminator) ) ? NULL : match;
        }
        if (table[i].Attributes.AllAttributes != 1 || !table[i].ImportNameTableRVA ||
            !image_rva_string( base, table[i].DllNameRVA ) ||
            !image_rva_range( base, table[i].ModuleHandleRVA, sizeof(HMODULE) )) return NULL;
        iat = get_rva( base, table[i].ImportAddressTableRVA );
        names = get_rva( base, table[i].ImportNameTableRVA );
        if (get_import_thunk_count( base, names, &imports ) ||
            !image_contains_array( base, iat, imports + 1, sizeof(*iat) ) || iat[imports].u1.Function)
            return NULL;
        offset = (ULONG_PTR)slot - (ULONG_PTR)iat;
        if ((ULONG_PTR)slot >= (ULONG_PTR)iat && !(offset % sizeof(*iat)) &&
            offset / sizeof(*iat) < imports)
        {
            if (match) return NULL;
            match = &table[i];
        }
        else if (macrunner_hb_select_arm64x_delay_import_view( base, &iat, &names, imports, slot ))
        {
            if (match) return NULL;
            match = &table[i];
        }
    }
    return NULL;  /* no descriptor terminator */
}

static void *macrunner_hb_resolve_arm64x_dispatch_import_locked( void *target )
{
    unsigned int depth;

    for (depth = 0; depth < 8; depth++)
    {
        WINE_MODREF *wm = macrunner_hb_find_module_from_address( (ULONG_PTR)target );
        IMAGE_NT_HEADERS *nt;
        struct mr_arm64x_import import;
        enum mr_arm64x_import_kind kind;
        const IMAGE_DELAYLOAD_DESCRIPTOR *desc;
        IMAGE_THUNK_DATA *slot;
        void *next;
        int code_type;

        if (!wm || !(nt = RtlImageNtHeader( wm->ldr.DllBase )) ||
            !image_contains_range( wm->ldr.DllBase, target, 4 ) ||
            !macrunner_hb_address_in_executable_section( wm->ldr.DllBase, (ULONG_PTR)target )) break;
        code_type = macrunner_hb_arm64x_code_type( wm->ldr.DllBase, target );
        if (code_type == 0 || code_type == 1 ||
            (code_type < 0 && nt->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64 &&
             !macrunner_hb_get_arm64x_metadata( wm->ldr.DllBase )))
        {
            if (!((ULONG_PTR)target & 3)) return target;
            break;
        }
        if (code_type != 2 || !(wm->ldr.Flags & LDR_WINE_INTERNAL)) break;
        kind = mr_arm64x_decode_import( wm->ldr.DllBase, nt->OptionalHeader.SizeOfImage,
                                       (ULONG_PTR)target - (ULONG_PTR)wm->ldr.DllBase, &import );
        if (kind != MR_ARM64X_IMPORT_JUMP && kind != MR_ARM64X_IMPORT_DELAY) break;
        slot = get_rva( wm->ldr.DllBase, import.slot );
        if (kind == MR_ARM64X_IMPORT_DELAY)
        {
            if (macrunner_hb_arm64x_code_type( wm->ldr.DllBase,
                                               get_rva( wm->ldr.DllBase, import.branch ) ) != 2 ||
                !macrunner_hb_address_in_executable_section( wm->ldr.DllBase,
                                               (ULONG_PTR)get_rva( wm->ldr.DllBase, import.branch ) ) ||
                !(desc = macrunner_hb_delay_descriptor_for_slot( wm->ldr.DllBase, slot ))) break;
            /* Another thread may already have resolved the shared slot. */
            if ((void *)slot->u1.Function == target)
                next = resolve_delay_loaded_api( wm->ldr.DllBase, desc, NULL, NULL, slot, 0, TRUE );
            else
                next = (void *)macrunner_hb_delay_ec_export( (FARPROC)slot->u1.Function );
            if (next) return next;  /* both paths checked the EC ABI */
            break;
        }
        memcpy( &next, slot, sizeof(next) );
        if (!next || next == target) break;
        target = next;
    }
    RtlRaiseStatus( STATUS_INVALID_IMAGE_FORMAT );
    return NULL;
}

static void CALLBACK macrunner_hb_dispatch_import_unlock( BOOL normal )
{
    (void)normal;
    RtlLeaveCriticalSection( &loader_section );
}

static void *macrunner_hb_resolve_arm64x_dispatch_import( void *target )
{
    RtlEnterCriticalSection( &loader_section );
    __TRY
    {
        target = macrunner_hb_resolve_arm64x_dispatch_import_locked( target );
    }
    __FINALLY( macrunner_hb_dispatch_import_unlock )
    __ENDTRY
    return target;
}
#endif

static void *resolve_delay_loaded_api( void *base, const IMAGE_DELAYLOAD_DESCRIPTOR *desc,
                                      PDELAYLOAD_FAILURE_DLL_CALLBACK dllhook,
                                      PDELAYLOAD_FAILURE_SYSTEM_ROUTINE syshook,
                                      IMAGE_THUNK_DATA *addr, ULONG flags, BOOL native_ec )
{
    IMAGE_THUNK_DATA *pIAT, *pINT;
    const IMAGE_IMPORT_BY_NAME *iibn = NULL;
    DELAYLOAD_INFO delayinfo;
    UNICODE_STRING mod;
    const CHAR* name;
    HMODULE *phmod;
    SIZE_T import_count;
    ULONG_PTR iat_addr, thunk_addr, offset;
    BOOL import_by_ordinal;
    BOOL trace_macrunner_delay;
    NTSTATUS nts;
    FARPROC fp = NULL;
    INT_PTR id;
    WCHAR macrunner_delay_probe_value[8] = {0};
    static unsigned int macrunner_delay_trace_count;

    TRACE( "(%p, %p, %p, %p, %p, 0x%08lx)\n", base, desc, dllhook, syshook, addr, flags );
    trace_macrunner_delay = get_env( L"MACRUNNER_HB_DELAY_RESOLVE_PROBE",
                                     macrunner_delay_probe_value,
                                     sizeof(macrunner_delay_probe_value) ) &&
                            macrunner_delay_probe_value[0] &&
                            macrunner_delay_probe_value[0] != '0' &&
                            macrunner_delay_trace_count++ < 4096;

    phmod = get_rva(base, desc->ModuleHandleRVA);
    pIAT = get_rva(base, desc->ImportAddressTableRVA);
    pINT = desc->ImportNameTableRVA ? get_rva(base, desc->ImportNameTableRVA) : pIAT;
    name = image_rva_string(base, desc->DllNameRVA);

    if (!name || !image_contains_array( base, phmod, 1, sizeof(*phmod) ) ||
        get_import_thunk_count( base, pINT, &import_count ) ||
        !image_contains_array( base, pIAT, import_count + 1, sizeof(*pIAT) ))
    {
        if (trace_macrunner_delay)
            MESSAGE( "macrunner-hb-delay-resolve: stage=invalid-descriptor base=%p desc=%p "
                     "dll=%s phmod=%p iat=%p int=%p\n",
                     base, desc, name ? name : "(invalid)", phmod, pIAT, pINT );
        WARN( "invalid delay-load descriptor %p for base %p\n", desc, base );
        return NULL;
    }

    iat_addr = (ULONG_PTR)pIAT;
    thunk_addr = (ULONG_PTR)addr;
    if (thunk_addr < iat_addr || (offset = thunk_addr - iat_addr) % sizeof(*pIAT) ||
        offset / sizeof(*pIAT) >= import_count)
    {
        IMAGE_THUNK_DATA *descriptor_iat = pIAT;

        if (!macrunner_hb_select_arm64x_delay_import_view( base, &pIAT, &pINT,
                                                            import_count, addr ))
        {
            if (trace_macrunner_delay)
                MESSAGE( "macrunner-hb-delay-resolve: stage=invalid-thunk base=%p dll=%s "
                         "iat=%p addr=%p count=%Iu\n", base, name, pIAT, addr, import_count );
            WARN( "delay-load thunk %p is outside IAT %p count %Iu for %s\n",
                  addr, pIAT, import_count, name );
            return NULL;
        }
        iat_addr = (ULONG_PTR)pIAT;
        if (trace_macrunner_delay)
            MESSAGE( "macrunner-hb-delay-resolve: stage=arm64x-sibling-view base=%p dll=%s "
                     "descriptor_iat=%p selected_iat=%p selected_int=%p addr=%p count=%Iu\n",
                     base, name, descriptor_iat, pIAT, pINT, addr, import_count );
    }

    offset = thunk_addr - iat_addr;
    id = offset / sizeof(*pIAT);
    import_by_ordinal = IMAGE_SNAP_BY_ORDINAL(pINT[id].u1.Ordinal);
    if (!import_by_ordinal &&
        !(iibn = image_import_by_name( base, (DWORD)pINT[id].u1.AddressOfData )))
    {
        if (trace_macrunner_delay)
            MESSAGE( "macrunner-hb-delay-resolve: stage=invalid-import base=%p dll=%s "
                     "id=%Id int=%p value=%Ix\n", base, name, id, pINT,
                     (ULONG_PTR)pINT[id].u1.AddressOfData );
        WARN( "invalid delay-load import-by-name rva %Ix for %s\n",
              (ULONG_PTR)pINT[id].u1.AddressOfData, name );
        return NULL;
    }
    if (trace_macrunner_delay)
    {
        IMAGE_NT_HEADERS *importer_nt = RtlImageNtHeader( base );

        MESSAGE( "macrunner-hb-delay-resolve: stage=start base=%p machine=%04x "
                 "dll=%s id=%Id import=%s iat=%p addr=%p phmod=%p value=%p\n",
                 base, importer_nt ? importer_nt->FileHeader.Machine : 0, name, id,
                 import_by_ordinal ? "(ordinal)" : (const char *)iibn->Name,
                 pIAT, addr, phmod, *phmod );
    }

    if (native_ec)
    {
        if (!RtlCreateUnicodeStringFromAsciiz( &mod, name ))
        {
            nts = STATUS_NO_MEMORY;
            goto fail;
        }
        nts = macrunner_hb_load_delay_ec_module( &mod, phmod );
        RtlFreeUnicodeString( &mod );
        if (trace_macrunner_delay)
            MESSAGE( "macrunner-hb-delay-resolve: stage=load dll=%s force_native=%u "
                     "status=%08lx module=%p\n", name, TRUE, nts, *phmod );
        if (nts) goto fail;
    }
    else if (!*phmod)
    {
        BOOL force_native_module = macrunner_hb_delay_load_is_native_builtin_importer( base, name );
        WORD prev_native_counterpart_machine = macrunner_hb_native_counterpart_machine;

        if (!RtlCreateUnicodeStringFromAsciiz(&mod, name))
        {
            nts = STATUS_NO_MEMORY;
            goto fail;
        }
        if (force_native_module)
        {
            MESSAGE( "MacRunner HyperBridge native delay-load %s from ARM64 builtin base=%p forcing machine=%04x\n",
                   name, base, current_machine );
            macrunner_hb_native_counterpart_machine = current_machine;
        }
        nts = LdrLoadDll(NULL, 0, &mod, phmod);
        if (trace_macrunner_delay)
            MESSAGE( "macrunner-hb-delay-resolve: stage=load dll=%s force_native=%u "
                     "status=%08lx module=%p\n", name, force_native_module, nts, *phmod );
        if (force_native_module)
            macrunner_hb_native_counterpart_machine = prev_native_counterpart_machine;
        RtlFreeUnicodeString(&mod);
        if (nts) goto fail;
    }

    if (import_by_ordinal)
        nts = LdrGetProcedureAddress(*phmod, NULL, LOWORD(pINT[id].u1.Ordinal), (void**)&fp);
    else
    {
        ANSI_STRING fnc;

        RtlInitAnsiString(&fnc, (char*)iibn->Name);
        nts = LdrGetProcedureAddress(*phmod, &fnc, 0, (void**)&fp);
    }
    if (trace_macrunner_delay)
    {
        IMAGE_NT_HEADERS *target_nt = *phmod ? RtlImageNtHeader( *phmod ) : NULL;

        MESSAGE( "macrunner-hb-delay-resolve: stage=lookup dll=%s module=%p "
                 "machine=%04x import=%s status=%08lx target=%p\n",
                 name, *phmod, target_nt ? target_nt->FileHeader.Machine : 0,
                 import_by_ordinal ? "(ordinal)" : (const char *)iibn->Name, nts, fp );
    }
    if (!nts)
    {
        const char *import_name = NULL;

        if (!import_by_ordinal) import_name = (char*)iibn->Name;
        if (native_ec)
        {
            fp = macrunner_hb_delay_ec_export( fp );
            if (!fp)
            {
                nts = STATUS_INVALID_IMAGE_FORMAT;
                goto fail;
            }
        }
        else
            fp = macrunner_hb_maybe_register_dynamic_import_thunk( base, *phmod, name, import_name,
                                                                   LOWORD(pINT[id].u1.Ordinal), fp );
        /* MacRunner 2026-08-05 — СКОБКА ЗАЩИТЫ, иначе отложенный импорт не патчится НИКОГДА.
         *
         * Слот отложенного импорта лежит в секции образа, отображённой без права записи
         * (замерено `mach_vm_region_recurse` в момент отказа: `prot=5/7`).  Без скобки
         * запись даёт SIGBUS — причём `si_code` на ARM64 приходит `BUS_ADRALN` и врёт:
         * XNU ставит его любому SIGBUS безусловно, а настоящую причину показывает DFSC
         * в ESR, и он равен 0xf, то есть отказ ПО ПРАВАМ.
         *
         * Отличие от обычного импорта, из-за которого это дороже всего остального:
         * отложенный импорт разрешается ПРИ КАЖДОМ ВЫЗОВЕ, пока слот не пропатчен.
         * Запись не проходит -> слот пуст -> следующий вызов снова идёт сюда.  Замерено
         * 186 млн отказов, 230 тыс/с, 39 % времени процесса — и прогон встаёт намертво.
         *
         * `import_dll` для обычных импортов такую скобку уже держит (см. выше по файлу);
         * здесь её просто не было. */
        {
            PVOID protect_base = &pIAT[id];
            SIZE_T protect_size = sizeof(pIAT[id].u1.Function);
            ULONG old_prot;
            NTSTATUS prot_status = NtProtectVirtualMemory( NtCurrentProcess(), &protect_base,
                                                           &protect_size, PAGE_READWRITE, &old_prot );
            if (prot_status)
            {
                if (native_ec)
                {
                    nts = prot_status;
                    goto fail;
                }
                static unsigned delay_protect_fail;
                if (delay_protect_fail++ < 8)
                    MESSAGE( "macrunner-hb-delay-resolve: stage=protect-failed dll=%s import=%s "
                             "iat_slot=%p status=%lx\n", name,
                             import_name ? import_name : "(ordinal)", &pIAT[id], prot_status );
            }
            pIAT[id].u1.Function = (ULONG_PTR)fp;
            if (!prot_status)
                NtProtectVirtualMemory( NtCurrentProcess(), &protect_base, &protect_size,
                                        old_prot, &old_prot );
        }
        if (trace_macrunner_delay)
            MESSAGE( "macrunner-hb-delay-resolve: stage=success dll=%s import=%s "
                     "iat_slot=%p target=%p\n", name,
                     import_name ? import_name : "(ordinal)", &pIAT[id], fp );
        return fp;
    }

fail:
    if (native_ec) RtlRaiseStatus( nts );
    if (trace_macrunner_delay)
        MESSAGE( "macrunner-hb-delay-resolve: stage=fail dll=%s import=%s "
                 "status=%08lx module=%p\n", name,
                 import_by_ordinal ? "(ordinal)" : (const char *)iibn->Name, nts, *phmod );
    delayinfo.Size = sizeof(delayinfo);
    delayinfo.DelayloadDescriptor = desc;
    delayinfo.ThunkAddress = addr;
    delayinfo.TargetDllName = name;
    if (import_by_ordinal)
    {
        delayinfo.TargetApiDescriptor.ImportDescribedByName = FALSE;
        delayinfo.TargetApiDescriptor.Description.Ordinal = LOWORD(pINT[id].u1.Ordinal);
    }
    else
    {
        delayinfo.TargetApiDescriptor.ImportDescribedByName = TRUE;
        delayinfo.TargetApiDescriptor.Description.Name = (const char *)iibn->Name;
    }
    delayinfo.TargetModuleBase = *phmod;
    delayinfo.Unused = NULL;
    delayinfo.LastError = nts;

    if (dllhook)
        return dllhook(4, &delayinfo);

    if (import_by_ordinal)
    {
        DWORD_PTR ord = LOWORD(pINT[id].u1.Ordinal);
        return syshook(name, (const char *)ord);
    }
    else
    {
        return syshook(name, (const char *)iibn->Name);
    }
}

/****************************************************************************
 *              LdrResolveDelayLoadedAPI   (NTDLL.@)
 */
void *WINAPI LdrResolveDelayLoadedAPI( void *base, const IMAGE_DELAYLOAD_DESCRIPTOR *desc,
                                     PDELAYLOAD_FAILURE_DLL_CALLBACK dllhook,
                                     PDELAYLOAD_FAILURE_SYSTEM_ROUTINE syshook,
                                     IMAGE_THUNK_DATA *addr, ULONG flags )
{
    return resolve_delay_loaded_api( base, desc, dllhook, syshook, addr, flags, FALSE );
}

/******************************************************************
 *		LdrShutdownProcess (NTDLL.@)
 *
 */
void WINAPI LdrShutdownProcess(void)
{
    /* ★ 2026-08-18, итерация 2382 — ОТЧЁТ СЛОТОВ ARM64X ПО ВЫХОДУ ПРОЦЕССА.
     *
     * Счётчики шести трамплинов бесполезны, пока их никто не печатает: у нас записано отдельным
     * правилом, что маркер, печать которого не доказана, считается несуществующим. Печатаем
     * здесь — один раз на процесс, без влияния на горячий путь. */
#if defined(__aarch64__) && !defined(__arm64ec__)
    macrunner_hb_arm64x_slot_report();
#endif
    BOOL detaching = process_detaching;

    TRACE("()\n");

    process_detaching = TRUE;
    if (!detaching)
        RtlProcessFlsData( NtCurrentTeb()->FlsSlots, 1 );

    process_detach();
}


/******************************************************************
 *		RtlExitUserProcess (NTDLL.@)
 */
void WINAPI RtlExitUserProcess( DWORD status )
{
    if (macrunner_trace_process_exit_enabled())
    {
        RTL_USER_PROCESS_PARAMETERS *params = NtCurrentTeb()->Peb->ProcessParameters;

        MESSAGE( "macrunner-rtl-exit: pid=%lu tid=%lu status=0x%lx image=%s cmd=%s\n",
                 GetCurrentProcessId(), GetCurrentThreadId(), status,
                 params ? debugstr_us( &params->ImagePathName ) : "(null)",
                 params ? debugstr_us( &params->CommandLine ) : "(null)" );
    }
    RtlEnterCriticalSection( &loader_section );
    RtlAcquirePebLock();
    NtTerminateProcess( 0, status );
    LdrShutdownProcess();
    for (;;) NtTerminateProcess( GetCurrentProcess(), status );
}

/******************************************************************
 *		LdrShutdownThread (NTDLL.@)
 *
 */
void WINAPI LdrShutdownThread(void)
{
    PLIST_ENTRY mark, entry;
    LDR_DATA_TABLE_ENTRY *mod;
    WINE_MODREF *wm;
    UINT i;
    void **pointers;

    TRACE("()\n");

    /* don't do any detach calls if process is exiting */
    if (process_detaching) return;

    RtlProcessFlsData( NtCurrentTeb()->FlsSlots, 1 );

    RtlEnterCriticalSection( &loader_section );

    if (!NtCurrentTeb()->SkipThreadAttach)
    {
        wm = get_modref( NtCurrentTeb()->Peb->ImageBaseAddress );
        mark = &NtCurrentTeb()->Peb->LdrData->InInitializationOrderModuleList;
        for (entry = mark->Blink; entry != mark; entry = entry->Blink)
        {
            mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY,
                                    InInitializationOrderLinks);
            if ( !(mod->Flags & LDR_PROCESS_ATTACHED) )
                continue;
            if ( mod->Flags & LDR_NO_DLL_CALLS )
                continue;

            MODULE_InitDLL( CONTAINING_RECORD(mod, WINE_MODREF, ldr),
                            DLL_THREAD_DETACH, NULL );
        }

        if (wm->ldr.TlsIndex == -1) call_tls_callbacks( wm->ldr.DllBase, DLL_THREAD_DETACH );
    }

    RtlAcquirePebLock();
    if ((pointers = NtCurrentTeb()->ThreadLocalStoragePointer))
    {
        NtCurrentTeb()->ThreadLocalStoragePointer = NULL;
#ifdef __x86_64__  /* macOS-specific hack */
        if (NtCurrentTeb()->Instrumentation[0])
            ((TEB *)NtCurrentTeb()->Instrumentation[0])->ThreadLocalStoragePointer = NULL;
#endif
        for (i = 0; i < tls_module_count; i++) RtlFreeHeap( GetProcessHeap(), 0, pointers[i] );
        RtlFreeHeap( GetProcessHeap(), 0, pointers );
    }
    RtlProcessFlsData( NtCurrentTeb()->FlsSlots, 2 );
    NtCurrentTeb()->FlsSlots = NULL;
    RtlFreeHeap( GetProcessHeap(), 0, NtCurrentTeb()->TlsExpansionSlots );
    NtCurrentTeb()->TlsExpansionSlots = NULL;
    RtlReleasePebLock();

    RtlLeaveCriticalSection( &loader_section );
    /* don't call DbgUiGetThreadDebugObject as some apps hook it and terminate if called */
    if (NtCurrentTeb()->DbgSsReserved[1]) NtClose( NtCurrentTeb()->DbgSsReserved[1] );
    RtlFreeThreadActivationContextStack();

    heap_thread_detach();
}


/***********************************************************************
 *           free_modref
 *
 */
static void free_modref( WINE_MODREF *wm )
{
    SINGLE_LIST_ENTRY *entry;
    LDR_DEPENDENCY *dep;

    RemoveEntryList(&wm->ldr.InLoadOrderLinks);
    RemoveEntryList(&wm->ldr.InMemoryOrderLinks);
    RemoveEntryList(&wm->ldr.HashLinks);
    RtlRbRemoveNode( &base_address_index_tree, &wm->ldr.BaseAddressIndexNode );
    if (wm->ldr.InInitializationOrderLinks.Flink)
        RemoveEntryList(&wm->ldr.InInitializationOrderLinks);

    while ((entry = wm->ldr.DdagNode->Dependencies.Tail))
    {
        dep = CONTAINING_RECORD( entry, LDR_DEPENDENCY, dependency_to_entry );
        assert( dep->dependency_from == wm->ldr.DdagNode );
        remove_module_dependency( dep );
    }

    while ((entry = wm->ldr.DdagNode->IncomingDependencies.Tail))
    {
        dep = CONTAINING_RECORD( entry, LDR_DEPENDENCY, dependency_from_entry );
        assert( dep->dependency_to == wm->ldr.DdagNode );
        remove_module_dependency( dep );
    }

    RemoveEntryList(&wm->ldr.NodeModuleLink);
    if (IsListEmpty(&wm->ldr.DdagNode->Modules))
        RtlFreeHeap( GetProcessHeap(), 0, wm->ldr.DdagNode );

    TRACE(" unloading %s\n", debugstr_w(wm->ldr.FullDllName.Buffer));
    if (!TRACE_ON(module))
        TRACE_(loaddll)("Unloaded module %s : %s\n",
                        debugstr_w(wm->ldr.FullDllName.Buffer),
                        (wm->ldr.Flags & LDR_WINE_INTERNAL) ? "builtin" : "native" );

    free_tls_slot( &wm->ldr );
    RtlReleaseActivationContext( wm->ldr.ActivationContext );
    NtUnmapViewOfSection( NtCurrentProcess(), wm->ldr.DllBase );
    if (cached_modref == wm) cached_modref = NULL;
    RtlFreeUnicodeString( &wm->ldr.FullDllName );
    RtlFreeHeap( GetProcessHeap(), 0, wm );
}

/***********************************************************************
 *           MODULE_FlushModrefs
 *
 * Remove all unused modrefs and call the internal unloading routines
 * for the library type.
 *
 * The loader_section must be locked while calling this function.
 */
static void MODULE_FlushModrefs(void)
{
    PLIST_ENTRY mark, entry, prev;
    LDR_DATA_TABLE_ENTRY *mod;
    WINE_MODREF*wm;

    mark = &NtCurrentTeb()->Peb->LdrData->InInitializationOrderModuleList;
    for (entry = mark->Blink; entry != mark; entry = prev)
    {
        mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
        wm = CONTAINING_RECORD(mod, WINE_MODREF, ldr);
        prev = entry->Blink;
        if (!mod->LoadCount) free_modref( wm );
    }

    /* check load order list too for modules that haven't been initialized yet */
    mark = &NtCurrentTeb()->Peb->LdrData->InLoadOrderModuleList;
    for (entry = mark->Blink; entry != mark; entry = prev)
    {
        mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        wm = CONTAINING_RECORD(mod, WINE_MODREF, ldr);
        prev = entry->Blink;
        if (!mod->LoadCount) free_modref( wm );
    }
}

/***********************************************************************
 *           MODULE_DecRefCount
 *
 * The loader_section must be locked while calling this function.
 */
static NTSTATUS MODULE_DecRefCount( LDR_DDAG_NODE *node, void *context )
{
    LDR_DATA_TABLE_ENTRY *mod;
    WINE_MODREF *wm;

    mod = CONTAINING_RECORD( node->Modules.Flink, LDR_DATA_TABLE_ENTRY, NodeModuleLink );
    wm = CONTAINING_RECORD( mod, WINE_MODREF, ldr );

    if ( wm->ldr.Flags & LDR_UNLOAD_IN_PROGRESS )
        return STATUS_SUCCESS;

    if ( wm->ldr.LoadCount <= 0 )
        return STATUS_SUCCESS;

    --wm->ldr.LoadCount;
    TRACE("(%s) ldr.LoadCount: %d\n", debugstr_w(wm->ldr.BaseDllName.Buffer), wm->ldr.LoadCount );

    if ( wm->ldr.LoadCount == 0 )
    {
        wm->ldr.Flags |= LDR_UNLOAD_IN_PROGRESS;
        walk_node_dependencies( node, context, MODULE_DecRefCount );
        wm->ldr.Flags &= ~LDR_UNLOAD_IN_PROGRESS;
        module_push_unload_trace( wm );
    }
    return STATUS_SUCCESS;
}

/******************************************************************
 *		LdrUnloadDll (NTDLL.@)
 *
 *
 */
NTSTATUS WINAPI LdrUnloadDll( HMODULE hModule )
{
    WINE_MODREF *wm;
    NTSTATUS retv = STATUS_SUCCESS;

    if (process_detaching) return retv;

    TRACE("(%p)\n", hModule);

    RtlEnterCriticalSection( &loader_section );

    free_lib_count++;
    if ((wm = get_modref( hModule )) != NULL)
    {
        TRACE("(%s) - START\n", debugstr_w(wm->ldr.BaseDllName.Buffer));

        /* Recursively decrement reference counts */
        MODULE_DecRefCount( wm->ldr.DdagNode, NULL );

        /* Call process detach notifications */
        if ( free_lib_count <= 1 )
        {
            process_detach();
            MODULE_FlushModrefs();
        }

        TRACE("END\n");
    }
    else
        retv = STATUS_DLL_NOT_FOUND;

    free_lib_count--;

    RtlLeaveCriticalSection( &loader_section );

    return retv;
}

/***********************************************************************
 *           RtlImageNtHeader   (NTDLL.@)
 */
PIMAGE_NT_HEADERS WINAPI RtlImageNtHeader(HMODULE hModule)
{
    IMAGE_NT_HEADERS *ret;

    __TRY
    {
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hModule;

        ret = NULL;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE)
        {
            ret = (IMAGE_NT_HEADERS *)((char *)dos + dos->e_lfanew);
            if (ret->Signature != IMAGE_NT_SIGNATURE) ret = NULL;
        }
    }
    __EXCEPT_PAGE_FAULT
    {
        return NULL;
    }
    __ENDTRY
    return ret;
}

/***********************************************************************
 *           load_global_options
 */
static void load_global_options(void)
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING bootstrap_mode_str = RTL_CONSTANT_STRING( L"WINEBOOTSTRAPMODE" );
    UNICODE_STRING wow6432bit_prefix_mode_str = RTL_CONSTANT_STRING( L"WINEWOW6432BPREFIXMODE" );
    UNICODE_STRING session_manager_str =
        RTL_CONSTANT_STRING( L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" );
    UNICODE_STRING val_str;
    HANDLE hkey;

    val_str.MaximumLength = 0;
    is_prefix_bootstrap =
        RtlQueryEnvironmentVariable_U( NULL, &bootstrap_mode_str, &val_str ) != STATUS_VARIABLE_NOT_FOUND;

    val_str.MaximumLength = 0;
    wow64_using_32bit_prefix =
        RtlQueryEnvironmentVariable_U( NULL, &wow6432bit_prefix_mode_str, &val_str ) != STATUS_VARIABLE_NOT_FOUND;

    InitializeObjectAttributes( &attr, &session_manager_str, OBJ_CASE_INSENSITIVE, 0, NULL );
    if (!NtOpenKey( &hkey, KEY_QUERY_VALUE, &attr ))
    {
        query_dword_option( hkey, L"SafeProcessSearchMode", &path_safe_mode );
        query_dword_option( hkey, L"SafeDllSearchMode", &dll_safe_mode );
        NtClose( hkey );
    }
}

static BOOL needs_elevation(void)
{
    ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION run_level;

    if (!RtlQueryInformationActivationContext( 0, NULL, NULL, RunlevelInformationInActivationContext,
                                               &run_level, sizeof(run_level), NULL ))
    {
        TRACE( "image requested run level %#x\n", run_level.RunLevel );
        if (run_level.RunLevel == ACTCTX_RUN_LEVEL_HIGHEST_AVAILABLE
                || run_level.RunLevel == ACTCTX_RUN_LEVEL_REQUIRE_ADMIN)
            return TRUE;
    }
    return FALSE;
}

static void elevate_token(void)
{
    PROCESS_ACCESS_TOKEN token;
    TOKEN_ELEVATION_TYPE type;
    TOKEN_LINKED_TOKEN linked;

    NtQueryInformationToken( GetCurrentThreadEffectiveToken(),
                             TokenElevationType, &type, sizeof(type), NULL );

    if (type == TokenElevationTypeFull) return;

    NtQueryInformationToken( GetCurrentThreadEffectiveToken(),
                             TokenLinkedToken, &linked, sizeof(linked), NULL );
    NtDuplicateToken( linked.LinkedToken, 0, NULL, FALSE, TokenPrimary, &token.Token );

    token.Thread = NULL;
    NtSetInformationProcess( GetCurrentProcess(), ProcessAccessToken, &token, sizeof(token) );
    NtClose( token.Token );
    NtClose( linked.LinkedToken );
}

static void open_known_dll_ntdir(void)
{
    UNICODE_STRING dir = RTL_CONSTANT_STRING( L"\\KnownDlls" );
    OBJECT_ATTRIBUTES attr;

    switch (current_machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        if (NtCurrentTeb()->WowTebOffset) RtlInitUnicodeString( &dir, L"\\KnownDlls32" );
        break;
    case IMAGE_FILE_MACHINE_ARMNT:
        if (NtCurrentTeb()->WowTebOffset) RtlInitUnicodeString( &dir, L"\\KnownDllsArm32" );
        break;
    default:
        break;
    }
    InitializeObjectAttributes( &attr, &dir, OBJ_CASE_INSENSITIVE, 0, NULL );
    NtOpenDirectoryObject( &known_dlls_ntdir, DIRECTORY_ALL_ACCESS, &attr );
}

#if defined(__arm64ec__) || defined(__aarch64__)

#if defined(__aarch64__) && !defined(__arm64ec__)
static NTSTATUS macrunner_hb_xtajit64_process_init( WINE_MODREF *wm )
{
    NTSTATUS status;

    if (!wm || !wm->ldr.DllBase) return STATUS_DLL_NOT_FOUND;

    status = NtQueryVirtualMemory( GetCurrentProcess(), wm->ldr.DllBase, MemoryWineUnixFuncs,
                                   &macrunner_hb_xtajit64_unix_handle,
                                   sizeof(macrunner_hb_xtajit64_unix_handle), NULL );
    if (status)
    {
        ERR( "could not resolve xtajit64 unixlib funcs from %s status=%08lx\n",
             debugstr_w(wm->ldr.FullDllName.Buffer), status );
        macrunner_hb_xtajit64_unix_handle = 0;
        return status;
    }

    status = macrunner_hb_xtajit64_unix_call( macrunner_hb_xtajit64_unix_process_init, NULL );
    MESSAGE( "macrunner-xtajit64: ProcessInit status=%08lx\n", status );
    if (status) return status;

    status = macrunner_hb_xtajit64_unix_call( macrunner_hb_xtajit64_unix_thread_init, NULL );
    MESSAGE( "macrunner-xtajit64: ThreadInit status=%08lx\n", status );
    return status;
}
#endif

static void load_arm64ec_module(void)
{
    ULONG buffer[16];
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)buffer;
    UNICODE_STRING nameW = RTL_CONSTANT_STRING( L"\\Registry\\Machine\\Software\\Microsoft\\Wow64\\amd64" );
    WCHAR module[64] = L"C:\\windows\\system32\\xtajit64.dll";
    OBJECT_ATTRIBUTES attr;
    WINE_MODREF *wm;
    NTSTATUS status;
    HANDLE key;

    InitializeObjectAttributes( &attr, &nameW, OBJ_CASE_INSENSITIVE, 0, NULL );
    if (!NtOpenKey( &key, KEY_READ | KEY_WOW64_64KEY, &attr ))
    {
        UNICODE_STRING valueW = RTL_CONSTANT_STRING( L"" );
        ULONG dirlen = wcslen( L"C:\\windows\\system32\\" );
        ULONG size = sizeof(buffer);

        if (!NtQueryValueKey( key, &valueW, KeyValuePartialInformation, buffer, size, &size ) && info->Type == REG_SZ)
        {
            size = sizeof(module) - (dirlen + 1) * sizeof(WCHAR);
            memcpy( module + dirlen, info->Data, min( info->DataLength, size ));
        }
        NtClose( key );
    }

    if ((status = load_dll( NULL, module, 0, &wm, FALSE ))
#ifdef __arm64ec__
        || (status = arm64ec_process_init( wm->ldr.DllBase ))
#else
        || (status = macrunner_hb_xtajit64_process_init( wm ))
#endif
       )
    {
        ERR( "could not load %s, status %lx\n", debugstr_w(module), status );
        NtTerminateProcess( GetCurrentProcess(), status );
    }
    MESSAGE( "macrunner-xtajit64: loader ProcessInit/ThreadInit completed module=%p\n",
             wm->ldr.DllBase );
}

#endif

#ifdef _WIN64

static void build_wow64_main_module(void)
{
    UNICODE_STRING nt_name;
    WINE_MODREF *wm;
    RTL_USER_PROCESS_PARAMETERS *params = NtCurrentTeb()->Peb->ProcessParameters;
    void *module = NtCurrentTeb()->Peb->ImageBaseAddress;

    RtlDosPathNameToNtPathName_U_WithStatus( params->ImagePathName.Buffer, &nt_name, NULL, NULL );
    wm = alloc_module( module, &nt_name, FALSE );
    assert( wm );
    wm->ldr.LoadCount = -1;
    RtlFreeUnicodeString( &nt_name );
}

static void (WINAPI *pWow64LdrpInitialize)( CONTEXT *ctx );

void (WINAPI *pWow64PrepareForException)( EXCEPTION_RECORD *rec, CONTEXT *context ) = NULL;

static void init_wow64( CONTEXT *context )
{
    if (!imports_fixup_done)
    {
        HMODULE wow64;
        WINE_MODREF *wm;
        NTSTATUS status;
        static const WCHAR wow64_path[] = L"C:\\windows\\system32\\wow64.dll";

        build_wow64_main_module();
        build_ntdll_module();

        /* CW HACK 20810: In Wow64/32-bit-bottle mode, load by name rather than full path */
        if (wow64_using_32bit_prefix)
        {
            RTL_USER_PROCESS_PARAMETERS *params = NtCurrentTeb()->Peb->ProcessParameters;
            static const WCHAR wow64_dll[] = L"wow64.dll";

            default_load_path = params->DllPath.Buffer;
            if (!default_load_path)
                get_dll_load_path( params->ImagePathName.Buffer, NULL, dll_safe_mode, &default_load_path );
            status = load_dll( NULL, wow64_dll, 0, &wm, FALSE );
        }
        else
            status = load_dll( NULL, wow64_path, 0, &wm, FALSE );
        MESSAGE( "macrunner-wow64-init: load wow64 status=%lx wm=%p prefix32=%u\n",
                 status, wm, wow64_using_32bit_prefix );

        if (status)
        {
            ERR( "could not load %s, status %lx\n", debugstr_w(wow64_path), status );
            NtTerminateProcess( GetCurrentProcess(), status );
        }
        wow64 = wm->ldr.DllBase;
#define GET_PTR(name) \
        if (!(p ## name = RtlFindExportedRoutineByName( wow64, #name ))) ERR( "failed to load %s\n", #name )

        GET_PTR( Wow64LdrpInitialize );
        GET_PTR( Wow64PrepareForException );
#undef GET_PTR
        MESSAGE( "macrunner-wow64-init: wow64=%p init=%p prepare=%p\n",
                 wow64, pWow64LdrpInitialize, pWow64PrepareForException );
        imports_fixup_done = TRUE;
    }

    RtlLeaveCriticalSection( &loader_section );
    MESSAGE( "macrunner-wow64-init: calling Wow64LdrpInitialize context=%p\n", context );
    pWow64LdrpInitialize( context );
    MESSAGE( "macrunner-wow64-init: Wow64LdrpInitialize returned unexpectedly\n" );
}


#else

void *Wow64Transition = NULL;

static void map_wow64cpu(void)
{
    SIZE_T size = 0;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING string = RTL_CONSTANT_STRING( L"\\??\\C:\\windows\\sysnative\\wow64cpu.dll" );
    HANDLE file, section;
    IO_STATUS_BLOCK io;
    NTSTATUS status;

    InitializeObjectAttributes( &attr, &string, 0, NULL, NULL );
    if ((status = NtOpenFile( &file, GENERIC_READ | SYNCHRONIZE, &attr, &io, FILE_SHARE_READ,
                              FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE )))
    {
        WARN("failed to open wow64cpu, status %#lx\n", status);
        return;
    }
    if (!NtCreateSection( &section, STANDARD_RIGHTS_REQUIRED | SECTION_QUERY |
                          SECTION_MAP_READ | SECTION_MAP_EXECUTE,
                          NULL, NULL, PAGE_EXECUTE_READ, SEC_COMMIT, file ))
    {
        WINE_NT_MAP_VIEW( section, NtCurrentProcess(), &Wow64Transition, 0,
                            0, NULL, &size, ViewShare, 0, PAGE_EXECUTE_READ );
        NtClose( section );
    }
    NtClose( file );
}

static void init_wow64( CONTEXT *context )
{
    PEB *peb = NtCurrentTeb()->Peb;
    PEB64 *peb64 = UlongToPtr( NtCurrentTeb64()->Peb );

    if (Wow64Transition) return;  /* already initialized */

    peb64->OSMajorVersion   = peb->OSMajorVersion;
    peb64->OSMinorVersion   = peb->OSMinorVersion;
    peb64->OSBuildNumber    = peb->OSBuildNumber;
    peb64->OSPlatformId     = peb->OSPlatformId;

#define SET_INIT_BLOCK(func) LdrSystemDllInitBlock.p ## func = PtrToUlong( &func )
    SET_INIT_BLOCK( KiUserApcDispatcher );
    SET_INIT_BLOCK( KiUserExceptionDispatcher );
    SET_INIT_BLOCK( LdrInitializeThunk );
    SET_INIT_BLOCK( LdrSystemDllInitBlock );
    SET_INIT_BLOCK( RtlUserThreadStart );
    SET_INIT_BLOCK( KiUserCallbackDispatcher );
    /* SET_INIT_BLOCK( RtlpQueryProcessDebugInformationRemote ); */
    /* SET_INIT_BLOCK( RtlpFreezeTimeBias ); */
    /* LdrSystemDllInitBlock.ntdll_handle */
#undef SET_INIT_BLOCK

    map_wow64cpu();
}
#endif


/* release some address space once dlls are loaded*/
static void release_address_space(void)
{
#ifndef _WIN64
    void *addr = (void *)1;
    SIZE_T size = 0;

    NtFreeVirtualMemory( GetCurrentProcess(), &addr, &size, MEM_RELEASE );
#endif
}

#if defined(__x86_64__) && !defined(__arm64ec__)
extern void CDECL wine_get_host_version( const char **sysname, const char **release );

static BOOL is_macos(void)
{
    const char *sysname;

    wine_get_host_version( &sysname, NULL );
    return !strcmp( sysname, "Darwin" );
}
#endif

/******************************************************************
 *		loader_init
 *
 * Attach to all the loaded dlls.
 * If this is the first time, perform the full process initialization.
 */
void loader_init( CONTEXT *context, void **entry )
{
    static int attach_done;
    NTSTATUS status;
    ULONG_PTR cookie, port = 0;
    WINE_MODREF *wm;

    if (process_detaching) NtTerminateThread( GetCurrentThread(), 0 );

    if (NtCurrentTeb()->SkipLoaderInit) return;

    /* ★★★★★ ИТЕРАЦИЯ 136, лейн УСТАНОВЩИКИ — ЕСТЬ ЛИ У ПРОЦЕССА КОМАНДНАЯ СТРОКА.
     *
     * Ступень 4 (JournalStudio-Setup.exe, x86_64, WiX) падает в `msvcrt!build_argv+0x14`
     * на `ldr x2,[x0]` при `x0=0` — разборщик получает нулевой указатель. Три прогона
     * дословно одинаковы; с аргументом `/help` — то же самое (итерация 135), значит
     * дело не в пустых аргументах.
     *
     * Проксирование `msvcrt!_acmdln/_wcmdln` (loader.c:1737) тут не участвует: падает
     * сам msvcrt, а не гость, читающий импорт. Значит смотреть надо на параметры
     * процесса. Печать разовая, на процесс. */
    {
        static int mr_cl_said;
        if (!mr_cl_said++)
        {
            PEB *mr_peb = NtCurrentTeb()->Peb;
            RTL_USER_PROCESS_PARAMETERS *mr_pp = mr_peb ? mr_peb->ProcessParameters : NULL;
            MESSAGE( "macrunner-cmdline: peb=%p params=%p cmd.buf=%p cmd.len=%u img.buf=%p img.len=%u\n",
                     mr_peb, mr_pp,
                     mr_pp ? mr_pp->CommandLine.Buffer : NULL,
                     mr_pp ? (unsigned)mr_pp->CommandLine.Length : 0,
                     mr_pp ? mr_pp->ImagePathName.Buffer : NULL,
                     mr_pp ? (unsigned)mr_pp->ImagePathName.Length : 0 );
            if (mr_pp && mr_pp->CommandLine.Buffer && mr_pp->CommandLine.Length)
                MESSAGE( "macrunner-cmdline-текст: %s\n", debugstr_w(mr_pp->CommandLine.Buffer) );
        }
    }

    RtlEnterCriticalSection( &loader_section );

    if (!imports_fixup_done)
    {
        ANSI_STRING ctrl_routine = RTL_CONSTANT_STRING( "CtrlRoutine" );
        WINE_MODREF *kernel32;
        PEB *peb = NtCurrentTeb()->Peb;
        unsigned int i;
        WCHAR env_str[16];
        ULONG heap_flags = HEAP_GROWABLE;

        peb->LdrData            = &ldr;
        peb->FastPebLock        = &peb_lock;
        peb->TlsBitmap          = &tls_bitmap;
        peb->TlsExpansionBitmap = &tls_expansion_bitmap;
        peb->LoaderLock         = &loader_section;

        /* CW Hack 23394, 23427 */
        if (get_env( L"WINE_HEAP_ZERO_MEMORY", env_str, sizeof(env_str)) && env_str[0] == L'1')
        {
            ERR( "Enabling heap zero hack.\n" );
            heap_flags |= HEAP_ZERO_MEMORY;
        }

        peb->ProcessHeap        = RtlCreateHeap( heap_flags, NULL, 0, 0, NULL, NULL );

        RtlInitializeBitMap( &tls_bitmap, peb->TlsBitmapBits, sizeof(peb->TlsBitmapBits) * 8 );
        RtlInitializeBitMap( &tls_expansion_bitmap, peb->TlsExpansionBitmapBits,
                             sizeof(peb->TlsExpansionBitmapBits) * 8 );
        /* TLS index 0 is always reserved, and wow64 reserves extra TLS entries */
        RtlSetBits( peb->TlsBitmap, 0, NtCurrentTeb()->WowTebOffset ? WOW64_TLS_MAX_NUMBER : 1 );
        RtlSetBits( peb->TlsBitmap, NTDLL_TLS_ERRNO, 1 );

        if (!(tls_dirs = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY, tls_module_count * sizeof(*tls_dirs) )))
            NtTerminateProcess( GetCurrentProcess(), STATUS_NO_MEMORY );

        for (i = 0; i < HASH_MAP_SIZE; i++)
            InitializeListHead( &hash_table[i] );

        init_user_process_params();
        load_global_options();
        version_init();
        open_known_dll_ntdir();

        default_load_path = peb->ProcessParameters->DllPath.Buffer;
        if (!default_load_path)
            get_dll_load_path( peb->ProcessParameters->ImagePathName.Buffer, NULL, dll_safe_mode, &default_load_path );

        if (NtCurrentTeb()->WowTebOffset) init_wow64( context );

        wm = build_main_module();
        if (macrunner_hb_amd64_main_on_arm64 && wm && wm->ldr.EntryPoint && entry)
        {
            if (macrunner_hb_trace_bootstrap())
                MESSAGE( "macrunner-hb-bootstrap-main-entry-override: old=%p new=%p image=%p\n",
                         *entry, wm->ldr.EntryPoint, wm->ldr.DllBase );
            *entry = wm->ldr.EntryPoint;
#if defined(__aarch64__) && !defined(__arm64ec__)
            if (macrunner_hb_trace_bootstrap())
                MESSAGE( "macrunner-hb-bootstrap-main-context-after-entry: pc=%p x0=%p x1=%p entry_slot=%p\n",
                         (void *)context->Pc, (void *)context->X0, (void *)context->X1, *entry );
#endif
        }
        build_ntdll_module();
#ifdef __arm64ec__
        load_arm64ec_module();
        update_load_config( wm->ldr.DllBase );
#elif defined(__aarch64__)
        if (macrunner_hb_amd64_main_on_arm64) load_arm64ec_module();
#endif

        if ((status = load_dll( NULL, L"kernel32.dll", 0, &kernel32, FALSE )) != STATUS_SUCCESS)
        {
            MESSAGE( "wine: could not load kernel32.dll, status %lx\n", status );
            NtTerminateProcess( GetCurrentProcess(), status );
        }
        node_kernel32 = kernel32->ldr.DdagNode;
        pBaseThreadInitThunk = RtlFindExportedRoutineByName( kernel32->ldr.DllBase, "BaseThreadInitThunk" );
        LdrGetProcedureAddress( kernel32->ldr.DllBase, &ctrl_routine, 0, (void **)&pCtrlRoutine );
        if (current_machine == IMAGE_FILE_MACHINE_ARM64)
        {
            void *native_proc;

            if (macrunner_hb_amd64_main_on_arm64)
            {
                MESSAGE( "MacRunner HyperBridge loader callback BaseThreadInitThunk: %p -> bridge wrapper %p\n",
                       pBaseThreadInitThunk, macrunner_hb_BaseThreadInitThunk );
                if (macrunner_hb_trace_bootstrap())
                    MESSAGE( "macrunner-hb-bootstrap-base-thread-thunk-install: old=%p bridge=%p\n",
                             pBaseThreadInitThunk, macrunner_hb_BaseThreadInitThunk );
                pBaseThreadInitThunk = macrunner_hb_BaseThreadInitThunk;
            }
            else
            {
            if (macrunner_hb_address_in_section( kernel32->ldr.DllBase, ".hexpthk",
                                                 (ULONG_PTR)pBaseThreadInitThunk ) &&
                (((native_proc = macrunner_hb_redirect_arm64x_thunk_to_native( kernel32->ldr.DllBase,
                                                                               pBaseThreadInitThunk )) &&
                  native_proc != pBaseThreadInitThunk) ||
                 (native_proc = macrunner_hb_find_export_outside_section( kernel32->ldr.DllBase,
                                                                          "BaseThreadInitThunk",
                                                                          ".hexpthk" ))))
            {
                MESSAGE( "MacRunner HyperBridge loader callback BaseThreadInitThunk: %p -> native %p\n",
                       pBaseThreadInitThunk, native_proc );
                pBaseThreadInitThunk = native_proc;
            }
            else if (macrunner_hb_amd64_main_on_arm64)
                MESSAGE( "MacRunner HyperBridge loader callback BaseThreadInitThunk kept at %p\n",
                       pBaseThreadInitThunk );
            }
            if (pCtrlRoutine)
            {
                WINE_MODREF *ctrl_mod = macrunner_hb_find_module_from_address( (ULONG_PTR)pCtrlRoutine );

                if (ctrl_mod && macrunner_hb_address_in_section( ctrl_mod->ldr.DllBase, ".hexpthk",
                                                                 (ULONG_PTR)pCtrlRoutine ) &&
                    (((native_proc = macrunner_hb_redirect_arm64x_thunk_to_native( ctrl_mod->ldr.DllBase,
                                                                                   pCtrlRoutine )) &&
                      native_proc != pCtrlRoutine) ||
                     (native_proc = macrunner_hb_find_export_outside_section( ctrl_mod->ldr.DllBase,
                                                                              ctrl_routine.Buffer,
                                                                              ".hexpthk" ))))
                {
                    MESSAGE( "MacRunner HyperBridge loader callback %s: %p -> native %p\n",
                           ctrl_routine.Buffer, pCtrlRoutine, native_proc );
                    pCtrlRoutine = native_proc;
                }
                else if (macrunner_hb_amd64_main_on_arm64)
                    MESSAGE( "MacRunner HyperBridge loader callback %s kept at %p\n",
                           ctrl_routine.Buffer, pCtrlRoutine );
            }
        }

        actctx_init();
        locale_init();
        if (needs_elevation())
            elevate_token();
        get_env_var( L"WINESYSTEMDLLPATH", 0, &system_dll_path );

        /*
         * ProcessParameters (including the selected native/WOW64 environment)
         * are final here, while the main image imports and entry point have not
         * run.  The observer is default-off and its result cannot affect loader
         * status or control flow.
         */
        macrunner_observe_initial_guest_peb();
        if (wm->ldr.Flags & LDR_COR_ILONLY)
            status = fixup_imports_ilonly( wm, NULL, entry );
        else
            status = fixup_imports( wm, NULL );

        if (status)
        {
            if ((current_machine == IMAGE_FILE_MACHINE_I386 && macrunner_hb_pe32_loader_trace_auto()) || macrunner_hb_trace_pe32_loader())
                MESSAGE( "macrunner-pe32-loader-fail: loader_init main_imports image=%s module=%s base=%p status=%08lx flags=%lx\n",
                         debugstr_w(NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer),
                         debugstr_w(wm->ldr.BaseDllName.Buffer), wm->ldr.DllBase, status, wm->ldr.Flags );
            ERR( "Importing dlls for %s failed, status %lx\n",
                 debugstr_w(NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer), status );
            NtTerminateProcess( GetCurrentProcess(), status );
        }
        imports_fixup_done = TRUE;
    }
    else
    {
#ifdef _WIN64
        if (NtCurrentTeb()->WowTebOffset) init_wow64( context );
#endif
#ifdef __arm64ec__
        arm64ec_thread_init();
#elif defined(__aarch64__)
        if (macrunner_hb_amd64_main_on_arm64 && macrunner_hb_xtajit64_unix_handle)
        {
            NTSTATUS xtajit64_status = macrunner_hb_xtajit64_unix_call( macrunner_hb_xtajit64_unix_thread_init,
                                                                        NULL );
            MESSAGE( "macrunner-xtajit64: ThreadInit status=%08lx\n", xtajit64_status );
            if (xtajit64_status) NtTerminateProcess( GetCurrentProcess(), xtajit64_status );
        }
#endif

        if (NtCurrentTeb()->SkipThreadAttach)
        {
            RtlLeaveCriticalSection( &loader_section );
            return;
        }

        wm = get_modref( NtCurrentTeb()->Peb->ImageBaseAddress );
    }

#if defined(__x86_64__) && !defined(__arm64ec__)
        if (is_macos() && !NtCurrentTeb()->WowTebOffset)
        {
            /* CW HACK 18756 */
            /* Preallocate TlsExpansionSlots.  Otherwise, kernelbase will
               allocate it on demand, but won't be able to do the Mac-specific poking to the
               %gs-relative address. */
            if (!NtCurrentTeb()->TlsExpansionSlots)
                NtCurrentTeb()->TlsExpansionSlots = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY, 8 * sizeof(NtCurrentTeb()->Peb->TlsExpansionBitmapBits) * sizeof(void*) );
            __asm__ volatile ("movq %0,%%gs:%c1"
                              :
                              : "r" (NtCurrentTeb()->TlsExpansionSlots), "n" (FIELD_OFFSET(TEB, TlsExpansionSlots)));

            if (!attach_done) /* only the first time */
                while (RtlFindClearBitsAndSet(NtCurrentTeb()->Peb->TlsBitmap, 1, 1) != ~0U);
        }
#endif

    NtCurrentTeb()->FlsSlots = fls_alloc_data();

    if (!attach_done)  /* first time around */
    {
        attach_done = 1;
        if ((status = alloc_thread_tls()) != STATUS_SUCCESS)
        {
            ERR( "TLS init  failed when loading %s, status %lx\n",
                 debugstr_w(NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer), status );
            NtTerminateProcess( GetCurrentProcess(), status );
        }
        wm->ldr.Flags |= LDR_PROCESS_ATTACHED;  /* don't try to attach again */
        if (wm->ldr.ActivationContext)
            RtlActivateActivationContext( 0, wm->ldr.ActivationContext, &cookie );

        if (macrunner_hb_trace_bootstrap())
            MESSAGE( "macrunner-hb-bootstrap-loader-stage: before-system-attach\n" );
        if (macrunner_hb_trace_bootstrap())
            MESSAGE( "macrunner-hb-bootstrap-loader-stage: before-ntdll-attach\n" );
        if ((status = process_attach( node_ntdll, context )))
        {
            ERR( "Initializing system dll for %s failed, status %lx\n",
                 debugstr_w(NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer), status );
            NtTerminateProcess( GetCurrentProcess(), status );
        }
        if (macrunner_hb_trace_bootstrap())
            MESSAGE( "macrunner-hb-bootstrap-loader-stage: after-ntdll-attach\n" );
        if (macrunner_hb_trace_bootstrap())
            MESSAGE( "macrunner-hb-bootstrap-loader-stage: before-kernel32-attach\n" );
        if ((status = process_attach( node_kernel32, context )))
        {
            ERR( "Initializing system dll for %s failed, status %lx\n",
                 debugstr_w(NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer), status );
            NtTerminateProcess( GetCurrentProcess(), status );
        }
        if (macrunner_hb_trace_bootstrap())
            MESSAGE( "macrunner-hb-bootstrap-loader-stage: after-kernel32-attach\n" );
        if (macrunner_hb_trace_bootstrap())
            MESSAGE( "macrunner-hb-bootstrap-loader-stage: after-system-attach\n" );

        if (macrunner_hb_trace_bootstrap())
            MESSAGE( "macrunner-hb-bootstrap-loader-stage: before-main-dependencies\n" );
        if ((status = walk_node_dependencies( wm->ldr.DdagNode, context, process_attach )))
        {
            if (last_failed_modref)
                ERR( "%s failed to initialize, aborting\n",
                     debugstr_w(last_failed_modref->ldr.BaseDllName.Buffer) + 1 );
            ERR( "Initializing dlls for %s failed, status %lx\n",
                 debugstr_w(NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer), status );
            NtTerminateProcess( GetCurrentProcess(), status );
        }
        if (macrunner_hb_trace_bootstrap())
            MESSAGE( "macrunner-hb-bootstrap-loader-stage: after-main-dependencies\n" );
        release_address_space();
        if (macrunner_hb_trace_bootstrap())
            MESSAGE( "macrunner-hb-bootstrap-loader-stage: after-release-address-space\n" );
        if (wm->ldr.TlsIndex == -1) call_tls_callbacks( wm->ldr.DllBase, DLL_PROCESS_ATTACH );
        if (macrunner_hb_trace_bootstrap())
            MESSAGE( "macrunner-hb-bootstrap-loader-stage: after-main-tls-callbacks\n" );
        if (wm->ldr.ActivationContext) RtlDeactivateActivationContext( 0, cookie );

        NtQueryInformationProcess( GetCurrentProcess(), ProcessDebugPort, &port, sizeof(port), NULL );
        if (port) process_breakpoint();
    }
    else
    {
        if ((status = alloc_thread_tls()) != STATUS_SUCCESS)
            NtTerminateThread( GetCurrentThread(), status );
        thread_attach();
        if (wm->ldr.TlsIndex == -1) call_tls_callbacks( wm->ldr.DllBase, DLL_THREAD_ATTACH );
    }

    RtlLeaveCriticalSection( &loader_section );
}


/***********************************************************************
 *           RtlImageDirectoryEntryToData   (NTDLL.@)
 */
PVOID WINAPI RtlImageDirectoryEntryToData( HMODULE module, BOOL image, WORD dir, ULONG *size )
{
    const IMAGE_DATA_DIRECTORY *data;
    const IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *section = NULL;
    DWORD addr, headers_size, image_size;
    void *ret;

    if ((ULONG_PTR)module & 1) image = FALSE;  /* mapped as data file */
    module = (HMODULE)((ULONG_PTR)module & ~3);
    if (!(nt = RtlImageNtHeader( module ))) return NULL;
    if (dir >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        const IMAGE_NT_HEADERS64 *nt64 = (const IMAGE_NT_HEADERS64 *)nt;

        if (dir >= nt64->OptionalHeader.NumberOfRvaAndSizes) return NULL;
        if (nt64->FileHeader.SizeOfOptionalHeader <
            offsetof( IMAGE_OPTIONAL_HEADER64, DataDirectory ) + (dir + 1) * sizeof(IMAGE_DATA_DIRECTORY))
            return NULL;
        data = &nt64->OptionalHeader.DataDirectory[dir];
        headers_size = nt64->OptionalHeader.SizeOfHeaders;
        image_size = nt64->OptionalHeader.SizeOfImage;
    }
    else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        const IMAGE_NT_HEADERS32 *nt32 = (const IMAGE_NT_HEADERS32 *)nt;

        if (dir >= nt32->OptionalHeader.NumberOfRvaAndSizes) return NULL;
        if (nt32->FileHeader.SizeOfOptionalHeader <
            offsetof( IMAGE_OPTIONAL_HEADER32, DataDirectory ) + (dir + 1) * sizeof(IMAGE_DATA_DIRECTORY))
            return NULL;
        data = &nt32->OptionalHeader.DataDirectory[dir];
        headers_size = nt32->OptionalHeader.SizeOfHeaders;
        image_size = nt32->OptionalHeader.SizeOfImage;
    }
    else return NULL;

    if (!(addr = data->VirtualAddress)) return NULL;
    *size = data->Size;
    if ((ULONG_PTR)module > ~(ULONG_PTR)0 - addr) return NULL;
    if (image)
    {
        if (addr > image_size || *size > image_size - addr) return NULL;
        return (char *)module + addr;
    }
    if (addr < headers_size)
    {
        if (*size > headers_size - addr) return NULL;
        return (char *)module + addr;
    }

    /* not mapped as image, need to find the section containing the virtual address */
    if (!(ret = RtlImageRvaToVa( nt, module, addr, &section ))) return NULL;
    if (*size > section->SizeOfRawData - (addr - section->VirtualAddress)) return NULL;
    return ret;
}


/***********************************************************************
 *           RtlImageRvaToSection   (NTDLL.@)
 */
static BOOL image_section_contains_raw_rva( const IMAGE_SECTION_HEADER *sec, DWORD rva )
{
    return sec->SizeOfRawData && rva >= sec->VirtualAddress &&
           rva - sec->VirtualAddress < sec->SizeOfRawData;
}

static BOOL image_section_table_fits( const IMAGE_NT_HEADERS *nt, HMODULE module )
{
    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION( nt );
    ULONG_PTR base = (ULONG_PTR)module, table = (ULONG_PTR)sec, limit;
    DWORD image_size, headers_size;

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        const IMAGE_NT_HEADERS64 *nt64 = (const IMAGE_NT_HEADERS64 *)nt;
        image_size = nt64->OptionalHeader.SizeOfImage;
        headers_size = nt64->OptionalHeader.SizeOfHeaders;
    }
    else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        const IMAGE_NT_HEADERS32 *nt32 = (const IMAGE_NT_HEADERS32 *)nt;
        image_size = nt32->OptionalHeader.SizeOfImage;
        headers_size = nt32->OptionalHeader.SizeOfHeaders;
    }
    else return FALSE;

    if (image_size > ~(ULONG_PTR)0 - base || headers_size > image_size) return FALSE;
    limit = base + (headers_size ? headers_size : image_size);
    if (table < base || table > limit) return FALSE;
    return nt->FileHeader.NumberOfSections <= (limit - table) / sizeof(*sec);
}

static BOOL image_section_pointer_in_table( const IMAGE_NT_HEADERS *nt, HMODULE module,
                                            const IMAGE_SECTION_HEADER *sec )
{
    ULONG_PTR first = (ULONG_PTR)IMAGE_FIRST_SECTION( nt );
    ULONG_PTR ptr = (ULONG_PTR)sec;

    if (!image_section_table_fits( nt, module )) return FALSE;
    if (ptr < first) return FALSE;
    if ((ptr - first) % sizeof(*sec)) return FALSE;
    return (ptr - first) / sizeof(*sec) < nt->FileHeader.NumberOfSections;
}

PIMAGE_SECTION_HEADER WINAPI RtlImageRvaToSection( const IMAGE_NT_HEADERS *nt,
                                                   HMODULE module, DWORD rva )
{
    int i;
    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION( nt );

    if (!image_section_table_fits( nt, module )) return NULL;
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (image_section_contains_raw_rva( sec, rva )) return (PIMAGE_SECTION_HEADER)sec;
    }
    return NULL;
}


/***********************************************************************
 *           RtlImageRvaToVa   (NTDLL.@)
 */
PVOID WINAPI RtlImageRvaToVa( const IMAGE_NT_HEADERS *nt, HMODULE module,
                              DWORD rva, IMAGE_SECTION_HEADER **section )
{
    IMAGE_SECTION_HEADER *sec;

    if (section && *section)  /* try this section first */
    {
        sec = *section;
        if (image_section_pointer_in_table( nt, module, sec ) &&
            image_section_contains_raw_rva( sec, rva ))
            goto found;
    }
    if (!(sec = RtlImageRvaToSection( nt, module, rva ))) return NULL;
 found:
    if (sec->PointerToRawData > ~(ULONG_PTR)0 - (rva - sec->VirtualAddress) ||
        (ULONG_PTR)module > ~(ULONG_PTR)0 - sec->PointerToRawData - (rva - sec->VirtualAddress))
        return NULL;
    if (section) *section = sec;
    return (char *)module + sec->PointerToRawData + (rva - sec->VirtualAddress);
}


/***********************************************************************
 *           RtlAddressInSectionTable   (NTDLL.@)
 */
PVOID WINAPI RtlAddressInSectionTable( const IMAGE_NT_HEADERS *nt, HMODULE module,
                                       DWORD rva )
{
    return RtlImageRvaToVa( nt, module, rva, NULL );
}

/***********************************************************************
 *           RtlPcToFileHeader   (NTDLL.@)
 */
PVOID WINAPI RtlPcToFileHeader( PVOID pc, PVOID *address )
{
    LDR_DATA_TABLE_ENTRY *module;
    PVOID ret = NULL;

    RtlEnterCriticalSection( &loader_section );
    if (!LdrFindEntryForAddress( pc, &module )) ret = module->DllBase;
    RtlLeaveCriticalSection( &loader_section );
    *address = ret;
    return ret;
}


/****************************************************************************
 *		LdrGetDllDirectory  (NTDLL.@)
 */
NTSTATUS WINAPI LdrGetDllDirectory( UNICODE_STRING *dir )
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlEnterCriticalSection( &dlldir_section );
    dir->Length = dll_directory.Length + sizeof(WCHAR);
    if (dir->MaximumLength >= dir->Length) RtlCopyUnicodeString( dir, &dll_directory );
    else
    {
        status = STATUS_BUFFER_TOO_SMALL;
        if (dir->MaximumLength) dir->Buffer[0] = 0;
    }
    RtlLeaveCriticalSection( &dlldir_section );
    return status;
}


/****************************************************************************
 *		LdrSetDllDirectory  (NTDLL.@)
 */
NTSTATUS WINAPI LdrSetDllDirectory( const UNICODE_STRING *dir )
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING new;

    if (!dir->Buffer) RtlInitUnicodeString( &new, NULL );
    else if ((status = RtlDuplicateUnicodeString( 1, dir, &new ))) return status;

    RtlEnterCriticalSection( &dlldir_section );
    RtlFreeUnicodeString( &dll_directory );
    dll_directory = new;
    RtlLeaveCriticalSection( &dlldir_section );
    return status;
}


/****************************************************************************
 *		LdrAddDllDirectory  (NTDLL.@)
 */
NTSTATUS WINAPI LdrAddDllDirectory( const UNICODE_STRING *dir, void **cookie )
{
    FILE_BASIC_INFORMATION info;
    UNICODE_STRING nt_name;
    NTSTATUS status;
    OBJECT_ATTRIBUTES attr;
    DWORD len;
    struct dll_dir_entry *ptr;
    RTL_PATH_TYPE type = RtlDetermineDosPathNameType_U( dir->Buffer );

    if (type != RtlPathTypeRooted && type != RtlPathTypeDriveAbsolute && type != RtlPathTypeUncAbsolute)
        return STATUS_INVALID_PARAMETER;

    status = RtlDosPathNameToNtPathName_U_WithStatus( dir->Buffer, &nt_name, NULL, NULL );
    if (status) return status;
    len = nt_name.Length / sizeof(WCHAR);
    if (!(ptr = RtlAllocateHeap( GetProcessHeap(), 0, offsetof(struct dll_dir_entry, dir[++len] ))))
        return STATUS_NO_MEMORY;
    memcpy( ptr->dir, nt_name.Buffer, len * sizeof(WCHAR) );

    InitializeObjectAttributes( &attr, &nt_name, OBJ_CASE_INSENSITIVE, 0, NULL );
    status = NtQueryAttributesFile( &attr, &info );
    RtlFreeUnicodeString( &nt_name );

    if (!status)
    {
        TRACE( "%s\n", debugstr_w( ptr->dir ));
        RtlEnterCriticalSection( &dlldir_section );
        list_add_head( &dll_dir_list, &ptr->entry );
        RtlLeaveCriticalSection( &dlldir_section );
        *cookie = ptr;
    }
    else RtlFreeHeap( GetProcessHeap(), 0, ptr );
    return status;
}


/****************************************************************************
 *		LdrRemoveDllDirectory  (NTDLL.@)
 */
NTSTATUS WINAPI LdrRemoveDllDirectory( void *cookie )
{
    struct dll_dir_entry *ptr = cookie;

    TRACE( "%s\n", debugstr_w( ptr->dir ));

    RtlEnterCriticalSection( &dlldir_section );
    list_remove( &ptr->entry );
    RtlFreeHeap( GetProcessHeap(), 0, ptr );
    RtlLeaveCriticalSection( &dlldir_section );
    return STATUS_SUCCESS;
}


/*************************************************************************
 *		LdrSetDefaultDllDirectories  (NTDLL.@)
 */
NTSTATUS WINAPI LdrSetDefaultDllDirectories( ULONG flags )
{
    /* LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR doesn't make sense in default dirs */
    const ULONG load_library_search_flags = (LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
                                             LOAD_LIBRARY_SEARCH_USER_DIRS |
                                             LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                             LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);

    if (!flags || (flags & ~load_library_search_flags)) return STATUS_INVALID_PARAMETER;
    default_search_flags = flags;
    return STATUS_SUCCESS;
}


/******************************************************************
 *		LdrGetDllPath  (NTDLL.@)
 */
NTSTATUS WINAPI LdrGetDllPath( PCWSTR module, ULONG flags, PWSTR *path, PWSTR *unknown )
{
    NTSTATUS status;
    const ULONG load_library_search_flags = (LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                                             LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
                                             LOAD_LIBRARY_SEARCH_USER_DIRS |
                                             LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                             LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);

    if (flags & LOAD_WITH_ALTERED_SEARCH_PATH)
    {
        if (flags & load_library_search_flags) return STATUS_INVALID_PARAMETER;
        if (default_search_flags) flags |= default_search_flags | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR;
    }
    else if (!(flags & load_library_search_flags)) flags |= default_search_flags;

    RtlEnterCriticalSection( &dlldir_section );

    if (flags & load_library_search_flags)
    {
        status = get_dll_load_path_search_flags( module, flags, path );
    }
    else
    {
        const WCHAR *dlldir = dll_directory.Length ? dll_directory.Buffer : NULL;
        if (!(flags & LOAD_WITH_ALTERED_SEARCH_PATH) || !wcschr( module, L'\\' ))
            module = NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer;
        status = get_dll_load_path( module, dlldir, dll_safe_mode, path );
    }

    RtlLeaveCriticalSection( &dlldir_section );
    *unknown = NULL;
    return status;
}


/*************************************************************************
 *		RtlSetSearchPathMode (NTDLL.@)
 */
NTSTATUS WINAPI RtlSetSearchPathMode( ULONG flags )
{
    int val;

    switch (flags)
    {
    case BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE:
        val = 1;
        break;
    case BASE_SEARCH_PATH_DISABLE_SAFE_SEARCHMODE:
        val = 0;
        break;
    case BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE | BASE_SEARCH_PATH_PERMANENT:
        InterlockedExchange( &path_safe_mode, 2 );
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    for (;;)
    {
        LONG prev = path_safe_mode;
        if (prev == 2) break;  /* permanently set */
        if (InterlockedCompareExchange( &path_safe_mode, val, prev ) == prev) return STATUS_SUCCESS;
    }
    return STATUS_ACCESS_DENIED;
}


/******************************************************************
 *           RtlGetExePath   (NTDLL.@)
 */
NTSTATUS WINAPI RtlGetExePath( PCWSTR name, PWSTR *path )
{
    const WCHAR *dlldir = L".";
    const WCHAR *module = NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer;

    /* same check as NeedCurrentDirectoryForExePathW */
    if (!wcschr( name, '\\' ))
    {
        UNICODE_STRING name = RTL_CONSTANT_STRING( L"NoDefaultCurrentDirectoryInExePath" ), value = { 0 };

        if (RtlQueryEnvironmentVariable_U( NULL, &name, &value ) != STATUS_VARIABLE_NOT_FOUND)
            dlldir = L"";
    }
    return get_dll_load_path( module, dlldir, FALSE, path );
}


/******************************************************************
 *           RtlGetSearchPath   (NTDLL.@)
 */
NTSTATUS WINAPI RtlGetSearchPath( PWSTR *path )
{
    const WCHAR *module = NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer;
    return get_dll_load_path( module, NULL, path_safe_mode, path );
}


/******************************************************************
 *           RtlReleasePath   (NTDLL.@)
 */
void WINAPI RtlReleasePath( PWSTR path )
{
    RtlFreeHeap( GetProcessHeap(), 0, path );
}


/*********************************************************************
 *           ApiSetQueryApiSetPresence   (NTDLL.@)
 */
NTSTATUS WINAPI ApiSetQueryApiSetPresence( const UNICODE_STRING *name, BOOLEAN *present )
{
    const API_SET_NAMESPACE *map = NtCurrentTeb()->Peb->ApiSetMap;
    const API_SET_NAMESPACE_ENTRY *entry;
    UNICODE_STRING str;

    *present = (!get_apiset_entry( map, name->Buffer, name->Length / sizeof(WCHAR), &entry ) &&
                !get_apiset_target( map, entry, NULL, &str ));
    return STATUS_SUCCESS;
}


/*********************************************************************
 *           ApiSetQueryApiSetPresenceEx   (NTDLL.@)
 */
NTSTATUS WINAPI ApiSetQueryApiSetPresenceEx( const UNICODE_STRING *name, BOOLEAN *in_schema, BOOLEAN *present )
{
    const API_SET_NAMESPACE *map = NtCurrentTeb()->Peb->ApiSetMap;
    const API_SET_NAMESPACE_ENTRY *entry;
    NTSTATUS status;
    UNICODE_STRING str;
    ULONG i, len = name->Length / sizeof(WCHAR);

    /* extension not allowed */
    for (i = 0; i < len; i++) if (name->Buffer[i] == '.') return STATUS_INVALID_PARAMETER;

    status = get_apiset_entry( map, name->Buffer, len, &entry );
    if (status == STATUS_APISET_NOT_PRESENT)
    {
        *in_schema = *present = FALSE;
        return STATUS_SUCCESS;
    }
    if (status) return status;

    /* the name must match exactly */
    *in_schema = (entry->NameLength == name->Length &&
                  !wcsnicmp( (WCHAR *)((char *)map + entry->NameOffset), name->Buffer, len ));
    *present = *in_schema && !get_apiset_target( map, entry, NULL, &str );
    return STATUS_SUCCESS;
}


/******************************************************************
 *		DllMain   (NTDLL.@)
 */
BOOL WINAPI DllMain( HINSTANCE inst, DWORD reason, LPVOID reserved )
{
    if (reason == DLL_PROCESS_ATTACH) LdrDisableThreadCalloutsForDll( inst );
    return TRUE;
}
