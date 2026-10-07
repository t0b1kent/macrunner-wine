/*
 * Win32 virtual memory functions
 *
 * Copyright 1997, 2002, 2020 Alexandre Julliard
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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SYSINFO_H
# include <sys/sysinfo.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
# include <sys/sysctl.h>
#endif
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYS_QUEUE_H
# include <sys/queue.h>
#endif
#ifdef HAVE_SYS_USER_H
# include <sys/user.h>
#endif
#ifdef HAVE_LIBPROCSTAT_H
# include <libprocstat.h>
#endif
#include <unistd.h>
#include <dlfcn.h>
#ifdef HAVE_VALGRIND_VALGRIND_H
# include <valgrind/valgrind.h>
#endif
#if defined(__APPLE__)
#define host_page_size mac_host_page_size
# include <mach/mach_init.h>
# include <mach/mach_vm.h>
# include <mach/task.h>
# include <mach/thread_state.h>
# include <mach/vm_map.h>
#undef host_page_size
#endif

#if defined(HAVE_LINUX_USERFAULTFD_H) && defined(HAVE_LINUX_FS_H)
# include <linux/userfaultfd.h>
# include <linux/fs.h>
#if defined(UFFD_FEATURE_WP_ASYNC) && defined(PM_SCAN_WP_MATCHING)
#define USE_UFFD_WRITEWATCH
#endif
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wine/list.h"
#include "wine/rbtree.h"
#include "unix_private.h"
#include "wine/debug.h"
#include "hb_probe.h"

/* ── Прибор ветви guest32/wine-prot ───────────────────────────────────────────
 * Потолок «первые 8» здесь уже снят (см. разбор у самой печати ниже), но ноль
 * оставался двусмысленным ПО ДРУГОЙ причине: гейт MACRUNNER_HB_GUEST32_WINE_PROT
 * по умолчанию ВЫКЛЮЧЕН, и молчание значило либо «представлений guest32 не было»,
 * либо «были, но гейт закрыт». Различает LOOKED, поставленный ВЫШЕ гейта:
 *     looked=0            представлений guest32 не встречалось
 *     looked>0, hits=0    представления были, а гейт закрыт  <- вот это и путали
 *     hits>0              правка применялась столько-то раз
 * Имя гейта печатается переписью само, догадываться не нужно. */
HB_PROBE_DEFINE(pr_guest32_wineprot, "guest32-wineprot",
                "представления guest32, у которых хозяйские права приводились к полной "
                "правде Wine одним mprotect_range. LOOKED — каждое представление guest32, "
                "дошедшее до этой ветви; HIT — каждое, где гейт был открыт и mprotect "
                "действительно звался. Печать подробностей идёт отдельной строкой "
                "macrunner-guest32-wineprot и выбирает первые 8, каждое 64-е и все "
                "расхождения — счёт же ведётся по ВСЕМ",
                "MACRUNNER_HB_GUEST32_WINE_PROT", 0);

HB_PROBE_DEFINE(pr_reserve_top, "hb-reserve-top",
                "ПРОХОДЫ через место резервирования полосы адресов при инициализации "
                "процесса: looked — сколько раз это место исполнялось (обязано быть 1 на "
                "процесс), hits — сколько раз резерв ПРИМЕНЁН. looked=0 означает, что путь "
                "не исполнялся вовсе — не тот ntdll.so, другая ветка #ifdef или раскладка "
                "не в то дерево; looked=1 при hits=0 означает ЛИБО "
                "MACRUNNER_HB_RESERVE_HOLES=0, ЛИБО непустой preload_info — что именно, "
                "говорит соседний прибор hb-reserve-preload",
                "MACRUNNER_HB_RESERVE_HOLES", 0);

HB_PROBE_DEFINE(pr_reserve_preload, "hb-reserve-preload",
                "те же проходы через место резервирования (looked общий с hb-reserve-top); "
                "hits — случаи, когда резервирование пропущено из-за НЕПУСТОГО preload_info. "
                "Комментарий в коде утверждает, что на macOS предзагрузчик невозможен и это "
                "поле всегда пусто; прибор поставлен затем, чтобы утверждение стало замером",
                NULL, 0);

/* ── 07.09.2026, лейн ПРИБОРЫ-4: УПРАВЛЕНИЕ ПРАВАМИ ОБЛАСТЕЙ ───────────────────────
 * reports/00-ПЕРЕД-ЛЮБЫМ-ДЕЛОМ.md перечисляет пробелы карты, и первым стоит: «управление
 * правами областей — hb_memory_protect, guest32_sync_host_protection — шага нет, а именно
 * там расхождение perm против prot». Оба гейта этого пути умолчанием ЗАКРЫТЫ, обе печати
 * под потолком, и потому вопрос «а срабатывало ли оно вообще» до сих пор не имел числа.
 * Приборы объявлены здесь, рядом с остальными приборами файла; работают ниже по тексту. */
HB_PROBE_DEFINE(pr_g32_commit_truth, "guest32-коммит-правда-учёт",
                "заходы в ветвь понижения прав при отображении guest32 (looked — все, "
                "выше гейта); hits = права ДЕЙСТВИТЕЛЬНО понижены до PAGE_NOACCESS, то "
                "есть гейт был открыт И страница ещё не была committed",
                "MACRUNNER_HB_GUEST32_COMMIT_TRUTH", 0);

HB_PROBE_DEFINE(pr_g32_commit_stroka, "guest32-коммит-правда",
                "те же понижения прав; hits = строка о понижении ВЫПУЩЕНА. Печать берёт "
                "первые 8 и далее каждое 64-е, поэтому число строк в журнале НЕ равно "
                "числу событий — разница видна как looked против hits",
                "MACRUNNER_HB_GUEST32_COMMIT_TRUTH", 0);

HB_PROBE_DEFINE(pr_g32_sync_gate, "guest32-синхр-гейт",
                "проходы через синхронизацию прав в NtProtectVirtualMemory (looked — все); "
                "hits = гейт MACRUNNER_HB_GUEST32_SYNC_PROT открыт",
                "MACRUNNER_HB_GUEST32_SYNC_PROT", 0);

HB_PROBE_DEFINE(pr_g32_sync_okno, "guest32-синхр-окно",
                "те же проходы; hits = адрес ПРИЗНАН принадлежащим гостевому окну 4 ГБ и "
                "права перенесены. Разница с guest32-синхр-гейт и есть отсев по старшим "
                "битам — та самая поправка итерации 126, которую журнал не показывал",
                NULL, 0);

HB_PROBE_DEFINE(pr_g32_sync_stroka, "guest32-синхр-прав",
                "переносы прав в гостевое окно; hits = строка ВЫПУЩЕНА (потолок 8). "
                "looked против hits показывает, какую долю переносов журнал не видел",
                NULL, 0);

WINE_DEFAULT_DEBUG_CHANNEL(virtual);
WINE_DECLARE_DEBUG_CHANNEL(module);
WINE_DECLARE_DEBUG_CHANNEL(virtual_ranges);

/* Real Win32 guests use 0x01000000; keep accepting Wine's local header value too. */
#define MEM_RESET_UNDO_WIN32 0x01000000
#define MEM_RESET_UNDO_FLAGS (MEM_RESET_UNDO | MEM_RESET_UNDO_WIN32)

struct preload_info
{
    void  *addr;
    size_t size;
};

struct reserved_area
{
    struct list entry;
    void       *base;
    size_t      size;
};

static struct list reserved_areas = LIST_INIT(reserved_areas);

struct builtin_module
{
    struct list  entry;
    unsigned int refcount;
    void        *handle;
    void        *module;
    char        *unix_path;
    void        *unix_handle;
};

static struct list builtin_modules = LIST_INIT( builtin_modules );

static inline BOOL is_mem_reset_undo_type( ULONG type )
{
    return type == MEM_RESET_UNDO || type == MEM_RESET_UNDO_WIN32;
}

struct file_view
{
    struct wine_rb_entry entry;  /* entry in global view tree */
    void         *base;          /* base address */
    size_t        size;          /* size in bytes */
    unsigned int  protect;       /* protection for all pages at allocation time and SEC_* flags */
};

/* per-page protection flags */
#define VPROT_READ       0x01
#define VPROT_WRITE      0x02
#define VPROT_EXEC       0x04
#define VPROT_WRITECOPY  0x08
#define VPROT_GUARD      0x10
#define VPROT_COMMITTED  0x20
#define VPROT_WRITEWATCH 0x40
#define VPROT_COPIED     0x80
/* per-mapping protection flags */
#define VPROT_ARM64EC          0x0100  /* view may contain ARM64EC code */
#define VPROT_SYSTEM           0x0200  /* system view (underlying mmap not under our control) */
#define VPROT_PLACEHOLDER      0x0400
#define VPROT_FREE_PLACEHOLDER 0x0800
#define VPROT_MACRUNNER_X64_GUEST 0x1000  /* AMD64 guest image: executable by HyperBridge, not by host CPU */
#define VPROT_MACRUNNER_I386_GUEST 0x2000 /* i386 guest image: executable by HyperBridge, not by host CPU */
#define VPROT_MACRUNNER_JIT        0x4000 /* область MAP_JIT: права ставятся ОДИН раз, дальше pthread_jit_write_protect_np */

#if defined(__APPLE__) && defined(__aarch64__)
/* ★ Лейн MAPJIT 08.09.2026. Объявляем сами: <pthread.h> сюда не включён, а тянуть его в
 * unix-половину ntdll ради одного вызова — лишняя связность. Символ есть в libSystem
 * (проверено на этой машине: pthread_jit_write_protect_supported_np() = 1). */
extern void pthread_jit_write_protect_np( int enabled );

/* Предел подряд идущих переключений по ОДНОМУ адресу. Смысл — не «оптимизация», а отказ
 * менять один вид зависания на другой: исчерпан предел -> уходим прежним путём. Значение
 * с запасом: настоящий JIT чередует запись и исполнение пачками, а не по команде. */
#define MACRUNNER_JIT_WX_MAX_RUNS  1000000ull
static unsigned long long macrunner_jit_wx_toggles;

/* ★★★ ЛЕЙН КЛИН-2 08.09.2026 — PC ОТКАЗА. Прибора, отвечающего «кто пишет», в дереве не
 * было: `rec->ExceptionAddress` в `virtual_handle_fault` пуст (замер лейна MAPJIT, 8 печатей
 * из 8), а `virtual_handle_fault` не получает контекста сигнала. Обработчик сигнала PC знает
 * (`PC_sig(context)`), поэтому кладём его сюда перед вызовом.
 *
 * Различает ровно то, ради чего заведён:
 *   pc ВНУТРИ области MAP_JIT  -> выпущенный код пишет в САМ СЕБЯ (структурный клин)
 *   pc в модуле FEX/хозяина    -> пишет эмиттер, лечится скобкой W^X вокруг выпуска
 * Без него обе гипотезы дают ОДИНАКОВЫЙ адрес отказа и неразличимы. */
__thread void *macrunner_fault_pc;

/* ★ Лейн СТЕНА64 08.09.2026 — СНИМОК X-РЕГИСТРОВ В МОМЕНТ ОТКАЗА.
 *
 * Зачем, а не «печать x17 внутри FEX» (патч КЛИН-2 01-fex-probe-x17-callret.patch):
 * искомое число — значение базового регистра команды записи — лежит В КОНТЕКСТЕ СИГНАЛА,
 * который получает НАШ обработчик. FEX его видит позже и только если отказ до него дошёл.
 * Здесь снимок берётся БЕЗУСЛОВНО и до всякой развилки, поэтому годится и тогда, когда
 * отказ до эмулятора не доходит вовсе — а это ровно тот случай, что мерил КЛИН-2
 * (ResetToConsistentStateImpl 4 вызова против миллионов отказов).
 *
 * Снимаем ВСЕ x0..x30 и sp, а не один x17: база команды записи берётся из битов [9:5]
 * самой команды, и заранее неизвестно, какой это регистр. На p4smc это был x17
 * (REG_CALLRET_SP в конфигурации ARM64EC), на notepad++ разница pc-addr другая (0x1b0
 * против 0x10) — значит команда другая, и предполагать x17 нельзя. Снимок 32 слов
 * стоит одного цикла копирования на отказ и снимает догадку целиком. */
__thread unsigned long long macrunner_fault_x[32];
__thread int macrunner_fault_x_valid;


/* Предел переключений — ПЕРЕМЕННОЙ, а не только константой. Причина: с константой
 * 1 000 000 «первый клин снят» верно лишь до исчерпания предела, а за ним прогон
 * возвращается в прежний клин (замер КЛИН-2: pass 7,9–8,6 млн за 25 с, 3 из 3).
 * Чтобы отличить «сходится» от «крутится вечно», предел надо уметь двигать без сборки. */
static unsigned long long macrunner_jit_wx_max_runs( void )
{
    static unsigned long long v;
    if (!v)
    {
        const char *s = getenv( "MACRUNNER_HB_JIT_WX_MAX" );
        v = (s && *s) ? strtoull( s, NULL, 0 ) : MACRUNNER_JIT_WX_MAX_RUNS;
        if (!v) v = ~0ull;   /* 0 = без предела */
    }
    return v;
}
#endif

/* Conversion from VPROT_* to Win32 flags */
static const BYTE VIRTUAL_Win32Flags[16] =
{
    PAGE_NOACCESS,              /* 0 */
    PAGE_READONLY,              /* READ */
    PAGE_READWRITE,             /* WRITE */
    PAGE_READWRITE,             /* READ | WRITE */
    PAGE_EXECUTE,               /* EXEC */
    PAGE_EXECUTE_READ,          /* READ | EXEC */
    PAGE_EXECUTE_READWRITE,     /* WRITE | EXEC */
    PAGE_EXECUTE_READWRITE,     /* READ | WRITE | EXEC */
    PAGE_WRITECOPY,             /* WRITECOPY */
    PAGE_WRITECOPY,             /* READ | WRITECOPY */
    PAGE_WRITECOPY,             /* WRITE | WRITECOPY */
    PAGE_WRITECOPY,             /* READ | WRITE | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY,     /* EXEC | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY,     /* READ | EXEC | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY,     /* WRITE | EXEC | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY      /* READ | WRITE | EXEC | WRITECOPY */
};

static struct wine_rb_tree views_tree;
static pthread_mutex_t virtual_mutex;

static const UINT page_shift = 12;
static const UINT_PTR page_mask = 0xfff;
static const UINT_PTR granularity_mask = 0xffff;

#ifdef __aarch64__
static UINT_PTR host_page_size;
static UINT_PTR host_page_mask;
#else
static const UINT_PTR host_page_size = 0x1000;
static const UINT_PTR host_page_mask = 0xfff;
#endif

static void init_virtual_mutex(void)
{
    pthread_mutexattr_t attr;

    pthread_mutexattr_init( &attr );
    pthread_mutexattr_settype( &attr, PTHREAD_MUTEX_RECURSIVE );
    pthread_mutex_init( &virtual_mutex, &attr );
    pthread_mutexattr_destroy( &attr );
}

static void ntdll_atfork_child(void)
{
    init_virtual_mutex();
    pthread_mutex_init( &fd_cache_mutex, NULL );
}

/* Note: these are Windows limits, you cannot change them. */
#if defined(__i386__) || defined(__x86_64__)
static void *address_space_start = (void *)0x110000; /* keep DOS area clear */
#else
static void *address_space_start = (void *)0x10000;
#endif
#ifdef _WIN64
static void *address_space_limit = (void *)0x7fffffff0000;  /* top of the total available address space */
static void *user_space_limit    = (void *)0x7fffffff0000;  /* top of the user address space */
static void *working_set_limit   = (void *)0x7fffffff0000;  /* top of the current working set */
#else
static void *address_space_limit = (void *)0xc0000000;
static void *user_space_limit    = (void *)0x7fff0000;
static void *working_set_limit   = (void *)0x7fff0000;
#endif

static void *host_addr_space_limit;  /* top of the host virtual address space */

static struct file_view *arm64ec_view;

ULONG_PTR user_space_wow_limit = 0;
struct _KUSER_SHARED_DATA *user_shared_data = (void *)WINE_USER_SHARED_DATA_ADDRESS;

/* TEB allocation blocks */
static void *teb_block;
static void **next_free_teb;
static int teb_block_pos;
static struct list teb_list = LIST_INIT( teb_list );

#define ROUND_ADDR(addr,mask) ((void *)((UINT_PTR)(addr) & ~(UINT_PTR)(mask)))
#define ROUND_SIZE(addr,size,mask) (((SIZE_T)(size) + ((UINT_PTR)(addr) & (mask)) + (mask)) & ~(UINT_PTR)(mask))

static BOOL round_size_checked( UINT_PTR addr, SIZE_T size, UINT_PTR mask, SIZE_T *rounded )
{
    SIZE_T offset = addr & mask;

    if (size > ~(SIZE_T)0 - offset) return FALSE;
    size += offset;
    if (size > ~(SIZE_T)0 - mask) return FALSE;
    *rounded = ROUND_SIZE( addr, size - offset, mask );
    return TRUE;
}

#define VIRTUAL_DEBUG_DUMP_VIEW(view) do { if (TRACE_ON(virtual)) dump_view(view); } while (0)
#define VIRTUAL_DEBUG_DUMP_RANGES() do { if (TRACE_ON(virtual_ranges)) dump_free_ranges(); } while (0)

#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

#ifdef _WIN64  /* on 64-bit the page protection bytes use a 2-level table */
static const size_t pages_vprot_shift = 20;
static const size_t pages_vprot_mask = (1 << 20) - 1;
static size_t pages_vprot_size;
static BYTE **pages_vprot;
#else  /* on 32-bit we use a simple array with one byte per page */
static BYTE *pages_vprot;
#endif

static int use_kernel_writewatch;
#ifdef USE_UFFD_WRITEWATCH
static int uffd_fd, pagemap_fd;
#endif

static struct file_view *view_block_start, *view_block_end, *next_free_view;
static const size_t view_block_size = 0x100000;
static void *preload_reserve_start;
static void *preload_reserve_end;
static BOOL force_exec_prot;  /* whether to force PROT_EXEC on all PROT_READ mmaps */
static BOOL enable_write_exceptions;  /* raise exception on writes to executable memory */
#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
static __thread BOOL macrunner_hb_wow64_guest32_map_active;
#endif
/* ★ ПАКЕТ-2: двусторонний прибор владения, определён в unix/macrunner_hb.c.
 * Спрашивает ЕДИНСТВЕННЫЙ селектор пакета 1, своего выбора не имеет. */
extern BOOL macrunner_paket2_mute( const char *family );

struct range_entry
{
    void *base;
    void *end;
};

static struct range_entry *free_ranges;
static struct range_entry *free_ranges_end;
static SIZE_T free_ranges_capacity = 0x100000;

#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
#include "macrunner_vm_arena.h"
#else
#define MR_VM_INC(n) ((void)0)
#define MR_VM_CALL(context,expression) (expression)
#define mr_vm_ensure_free_range_slot() ((void)0)
#define mr_vm_ranges_high() ((void)0)
#endif


static inline BOOL is_beyond_limit( const void *addr, size_t size, const void *limit )
{
    UINT_PTR start = (UINT_PTR)addr, end = start + size;
    UINT_PTR max = (UINT_PTR)limit;

    return start >= max || end < start || end > max;
}

static inline BOOL is_vprot_exec_write( BYTE vprot )
{
    return (vprot & VPROT_EXEC) && (vprot & (VPROT_WRITE | VPROT_WRITECOPY));
}

/* mmap() anonymous memory at a fixed address */
void *anon_mmap_fixed( void *start, size_t size, int prot, int flags )
{
    assert( !((UINT_PTR)start & host_page_mask) );
    assert( !(size & host_page_mask) );

    return mmap( start, size, prot, MAP_PRIVATE | MAP_ANON | MAP_FIXED | flags, -1, 0 );
}

/* allocate anonymous mmap() memory at any address */
void *anon_mmap_alloc( size_t size, int prot )
{
    assert( !(size & host_page_mask) );

    return mmap( NULL, size, prot, MAP_PRIVATE | MAP_ANON, -1, 0 );
}

#ifdef USE_UFFD_WRITEWATCH
static void kernel_writewatch_init(void)
{
    struct uffdio_api uffdio_api;

    uffd_fd = syscall( __NR_userfaultfd, O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY );
    if (uffd_fd == -1) return;

    uffdio_api.api = UFFD_API;
    uffdio_api.features = UFFD_FEATURE_WP_ASYNC | UFFD_FEATURE_WP_UNPOPULATED;
    if (ioctl( uffd_fd, UFFDIO_API, &uffdio_api ) || uffdio_api.api != UFFD_API)
    {
        close( uffd_fd );
        return;
    }
    pagemap_fd = open( "/proc/self/pagemap", O_CLOEXEC | O_RDONLY );
    if (pagemap_fd == -1)
    {
        ERR( "Error opening /proc/self/pagemap.\n" );
        close( uffd_fd );
        return;
    }
    use_kernel_writewatch = 1;
    TRACE( "Using kernel write watches.\n" );
}

static void kernel_writewatch_reset( void *start, SIZE_T len )
{
    struct pm_scan_arg arg = { 0 };

    len = ROUND_SIZE( start, len, host_page_mask );
    start = (char *)ROUND_ADDR( start, host_page_mask );

    arg.size = sizeof(arg);
    arg.start = (UINT_PTR)start;
    arg.end = arg.start + len;
    arg.flags = PM_SCAN_WP_MATCHING;
    arg.category_mask = PAGE_IS_WRITTEN;
    arg.return_mask = PAGE_IS_WRITTEN;
    if (ioctl( pagemap_fd, PAGEMAP_SCAN, &arg ) < 0)
        ERR( "ioctl(PAGEMAP_SCAN) failed, err %s.\n", strerror(errno) );
}

static void kernel_writewatch_register_range( struct file_view *view, void *base, size_t size )
{
    struct uffdio_register uffdio_register;
    struct uffdio_writeprotect wp;

    if (!(view->protect & VPROT_WRITEWATCH) || !use_kernel_writewatch) return;

    size = ROUND_SIZE( base, size, host_page_mask );
    base = (char *)ROUND_ADDR( base, host_page_mask );

    /* Transparent huge pages will result in larger areas reported as dirty. */
    madvise( base, size, MADV_NOHUGEPAGE );

    uffdio_register.range.start = (UINT_PTR)base;
    uffdio_register.range.len = size;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_WP;
    if (ioctl( uffd_fd, UFFDIO_REGISTER, &uffdio_register ) == -1)
    {
        ERR( "ioctl( UFFDIO_REGISTER ) failed, %s.\n", strerror(errno) );
        return;
    }

    if (!(uffdio_register.ioctls & UFFDIO_WRITEPROTECT))
    {
        ERR( "uffdio_register.ioctls %s.\n", wine_dbgstr_longlong(uffdio_register.ioctls) );
        return;
    }
    wp.range.start = (UINT_PTR)base;
    wp.range.len = size;
    wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;

    if (ioctl( uffd_fd, UFFDIO_WRITEPROTECT, &wp ) == -1)
        ERR( "ioctl( UFFDIO_WRITEPROTECT ) failed, %s.\n", strerror(errno) );
}

static void kernel_get_write_watches( void *base, SIZE_T size, void **buffer, ULONG_PTR *count, BOOL reset )
{
    struct pm_scan_arg arg = { 0 };
    struct page_region rgns[256];
    SIZE_T buffer_len = *count;
    char *addr, *next_addr;
    int rgn_count, i;
    size_t end, granularity = host_page_size / page_size;

    assert( !(size & page_mask) );

    end = (size_t)((char *)base + size);
    size = ROUND_SIZE( base, size, host_page_mask );
    addr = (char *)ROUND_ADDR( base, host_page_mask );

    arg.size = sizeof(arg);
    arg.vec = (ULONG_PTR)rgns;
    arg.vec_len = ARRAY_SIZE(rgns);
    if (reset) arg.flags |= PM_SCAN_WP_MATCHING;
    arg.category_mask = PAGE_IS_WRITTEN;
    arg.return_mask = PAGE_IS_WRITTEN;

    *count = 0;
    while (1)
    {
        arg.start = (UINT_PTR)addr;
        arg.end = arg.start + size;
        arg.max_pages = (buffer_len + granularity - 1) / granularity;

        if ((rgn_count = ioctl( pagemap_fd, PAGEMAP_SCAN, &arg )) < 0)
        {
            ERR( "ioctl( PAGEMAP_SCAN ) failed, error %s.\n", strerror(errno) );
            return;
        }
        if (!rgn_count) break;

        assert( rgn_count <= ARRAY_SIZE(rgns) );
        for (i = 0; i < rgn_count; ++i)
        {
            size_t c_addr = max( rgns[i].start, (size_t)base );

            rgns[i].end = min( rgns[i].end, end );
            assert( rgns[i].categories == PAGE_IS_WRITTEN );
            while (buffer_len && c_addr < rgns[i].end)
            {
                buffer[(*count)++] = (void *)c_addr;
                --buffer_len;
                c_addr += page_size;
            }
            if (!buffer_len) break;
        }
        if (!buffer_len || rgn_count < arg.vec_len) break;
        next_addr = (char *)(ULONG_PTR)arg.walk_end;
        assert( size >= next_addr - addr );
        if (!(size -= next_addr - addr)) break;
        addr = next_addr;
    }
}
#else
static void kernel_writewatch_init(void)
{
}

static void kernel_writewatch_reset( void *start, SIZE_T len )
{
}

static void kernel_writewatch_register_range( struct file_view *view, void *base, size_t size )
{
}

static void kernel_get_write_watches( void *base, SIZE_T size, void **buffer, ULONG_PTR *count, BOOL reset )
{
    assert( 0 );
}
#endif

static void *reserved_area_end( void *addr, SIZE_T *size )
{
    UINT_PTR start = (UINT_PTR)addr;
    SIZE_T max_size = ~(UINT_PTR)0 - start;

    if (*size > max_size) *size = max_size;
    return (void *)(start + *size);
}

static void *reserved_area_limit( const struct reserved_area *area )
{
    SIZE_T size = area->size;

    return reserved_area_end( area->base, &size );
}


static void mmap_add_reserved_area( void *addr, SIZE_T size )
{
    struct reserved_area *area;
    struct list *ptr, *next;
    void *end, *area_end;

    assert( !((UINT_PTR)addr & host_page_mask) );
    assert( !(size & host_page_mask) );

    end = reserved_area_end( addr, &size );
    if (!size) return;

    LIST_FOR_EACH( ptr, &reserved_areas )
    {
        area = LIST_ENTRY( ptr, struct reserved_area, entry );
        area_end = reserved_area_limit( area );

        if (area->base > end) break;
        if (area_end < addr) continue;
        if (area->base > addr)
        {
            area->size += (char *)area->base - (char *)addr;
            area->base = addr;
        }
        if (area_end >= end) return;

        /* try to merge with the following ones */
        while ((next = list_next( &reserved_areas, ptr )))
        {
            struct reserved_area *area_next = LIST_ENTRY( next, struct reserved_area, entry );
            void *next_end = reserved_area_limit( area_next );

            if (area_next->base > end) break;
            list_remove( next );
            free( area_next );
            if (next_end >= end)
            {
                end = next_end;
                break;
            }
        }
        area->size = (char *)end - (char *)area->base;
        return;
    }

    if ((area = malloc( sizeof(*area) )))
    {
        area->base = addr;
        area->size = size;
        list_add_before( ptr, &area->entry );
    }
}

static BOOL mmap_remove_reserved_area( void *addr, SIZE_T size )
{
    struct reserved_area *area;
    struct list *ptr;
    void *end, *area_end;

    assert( !((UINT_PTR)addr & host_page_mask) );
    assert( !(size & host_page_mask) );

    end = reserved_area_end( addr, &size );
    if (!size) return TRUE;

    ptr = list_head( &reserved_areas );
    /* find the first area covering address */
    while (ptr)
    {
        area = LIST_ENTRY( ptr, struct reserved_area, entry );
        area_end = reserved_area_limit( area );
        if (area->base >= end) break;  /* outside the range */
        if (area_end > addr)  /* overlaps range */
        {
            if (area->base >= addr)
            {
                if (area_end > end)
                {
                    /* range overlaps beginning of area only -> shrink area */
                    area->size -= (char *)end - (char *)area->base;
                    area->base = end;
                    break;
                }
                else
                {
                    /* range contains the whole area -> remove area completely */
                    ptr = list_next( &reserved_areas, ptr );
                    list_remove( &area->entry );
                    free( area );
                    continue;
                }
            }
            else
            {
                if (area_end > end)
                {
                    /* range is in the middle of area -> split area in two */
                    struct reserved_area *new_area = malloc( sizeof(*new_area) );
                    if (!new_area) return FALSE;
                    new_area->base = end;
                    new_area->size = (char *)area_end - (char *)new_area->base;
                    list_add_after( ptr, &new_area->entry );
                    area->size = (char *)addr - (char *)area->base;
                    break;
                }
                else
                {
                    /* range overlaps end of area only -> shrink area */
                    area->size = (char *)addr - (char *)area->base;
                }
            }
        }
        ptr = list_next( &reserved_areas, ptr );
    }
    return TRUE;
}

static int mmap_is_in_reserved_area( void *addr, SIZE_T size )
{
    struct reserved_area *area;
    void *end, *area_end;

    end = reserved_area_end( addr, &size );

    LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
    {
        if (area->base > addr) break;
        area_end = reserved_area_limit( area );
        if (area_end <= addr) continue;
        /* area must contain block completely */
        if (area_end < end) return -1;
        return 1;
    }
    return 0;
}


/***********************************************************************
 *           unmap_area_above_user_limit
 *
 * Unmap memory that's above the user space limit, by replacing it with an empty mapping,
 * and return the remaining size below the limit. virtual_mutex must be held by caller.
 */
static size_t unmap_area_above_user_limit( void *addr, size_t size )
{
    size_t ret = 0;

    if (addr < user_space_limit)
    {
        ret = (char *)user_space_limit - (char *)addr;
        if (ret >= size) return size;  /* nothing is above limit */
        size -= ret;
        addr = user_space_limit;
    }
    anon_mmap_fixed( addr, size, PROT_NONE, MAP_NORESERVE );
    mmap_add_reserved_area( addr, size );
    return ret;
}


static void *anon_mmap_tryfixed( void *start, size_t size, int prot, int flags )
{
    void *ptr;

#ifdef MAP_FIXED_NOREPLACE
    ptr = mmap( start, size, prot, MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
#elif defined(MAP_TRYFIXED)
    ptr = mmap( start, size, prot, MAP_TRYFIXED | MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
    ptr = mmap( start, size, prot, MAP_FIXED | MAP_EXCL | MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
    if (ptr == MAP_FAILED && errno == EINVAL) errno = EEXIST;
#elif defined(__APPLE__)
    mach_vm_address_t result = (mach_vm_address_t)start;
    kern_return_t ret = mach_vm_map( mach_task_self(), &result, size, 0, VM_FLAGS_FIXED,
                                     MEMORY_OBJECT_NULL, 0, 0, prot, VM_PROT_ALL, VM_INHERIT_COPY );

    if (!ret)
    {
        if ((ptr = anon_mmap_fixed( start, size, prot, flags )) == MAP_FAILED)
            mach_vm_deallocate( mach_task_self(), result, size );
    }
    else
    {
        errno = (ret == KERN_NO_SPACE ? EEXIST : ENOMEM);
        ptr = MAP_FAILED;
    }
#else
    ptr = mmap( start, size, prot, MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
#endif
    if (ptr != MAP_FAILED && ptr != start)
    {
        size = unmap_area_above_user_limit( ptr, size );
        if (size) munmap( ptr, size );
        ptr = MAP_FAILED;
        errno = EEXIST;
    }
    return ptr;
}

/* ★★★ 07.09.2026, лейн ПРИБОРЫ-4 — НА ЧИСЛАХ ЭТОГО СЕМЕЙСТВА СТОИТ ЗАПИСЬ CLAUDE.md
 * «Резервирование ВЫКЛЮЧАТЬ ЦЕЛИКОМ НЕЛЬЗЯ — это давало шторм 17,5 млн; надо опускать
 * ВЕРХ». Соседний прибор того же файла (hb-reserve-top) лейн ПРИБОРЫ-3 уже перевёл и
 * замером показал, что блок RESERVE_TOP до исполнения НЕ ДОХОДИТ — то есть читать
 * молчание этой семьи как «явление не случилось» здесь уже однажды было ошибкой.
 *
 * Автор печати сам написал рядом: «молчащее резервирование неотличимо от
 * несостоявшегося, а разница между ними и есть ответ». Печать это не решает: она под
 * потолком 64 и внутри двух условий, поэтому ноль строк по-прежнему значит четыре
 * разные вещи — reserve_area не звали; звали, но дыр не нашлось; дыры нашлись, но их
 * больше 64 и печатались первые; сборка не для __APPLE__.
 *
 * Учёт стоит выше потолка и выше исхода. looked = найденные дыры, hits = РЕАЛЬНО
 * зарезервированные; разность даёт число отказов без чтения журнала. */
HB_PROBE_DEFINE(pr_reserve_area, "hb-reserve-area",
                "вызовы reserve_area (looked) против тех, что дошли до обхода областей "
                "(hits): различает 'не звали' и 'звали, но диапазон пуст'",
                NULL, 0);
HB_PROBE_DEFINE(pr_reserve_hole, "hb-reserve-hole-исход",
                "найденные дыры адресного пространства (все, без потолка печати 64); "
                "hits = дыра РЕАЛЬНО зарезервирована, mach_vm_map вернул 0",
                NULL, 0);
HB_PROBE_DEFINE(pr_reserve_hole_stroka, "hb-reserve-hole",
                "та же совокупность дыр; hits = строка о дыре ВЫПУЩЕНА (первые 64 плюс "
                "все дыры от 1 ГБ). Отдельным прибором, потому что условие печати шире "
                "потолка и в потолке hb_probe не выражается",
                NULL, 0);

static void reserve_area( void *addr, void *end )
{
    HB_PROBE_LOOKED(&pr_reserve_area);
#ifdef __APPLE__

#ifdef __i386__
    static const mach_vm_address_t max_address = VM_MAX_ADDRESS;
#else
    static const mach_vm_address_t max_address = MACH_VM_MAX_ADDRESS;
#endif
    mach_vm_address_t address = (mach_vm_address_t)addr;
    mach_vm_address_t end_address = (mach_vm_address_t)end;

    if (!end_address || max_address < end_address)
        end_address = max_address;

    HB_PROBE_HIT(&pr_reserve_area);
    while (address < end_address)
    {
        mach_vm_address_t hole_address = address;
        kern_return_t ret;
        mach_vm_size_t size;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t dummy_object_name = MACH_PORT_NULL;

        /* find the mapped region at or above the current address. */
        ret = mach_vm_region(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64,
                             (vm_region_info_t)&info, &count, &dummy_object_name);
        if (ret != KERN_SUCCESS)
        {
            address = max_address;
            size = 0;
        }

        if (end_address < address)
            address = end_address;
        if (hole_address < address)
        {
            /* found a hole, attempt to reserve it. */
            size_t hole_size = address - hole_address;
            mach_vm_address_t alloc_address = hole_address;

            ret = mach_vm_map( mach_task_self(), &alloc_address, hole_size, 0, VM_FLAGS_FIXED,
                               MEMORY_OBJECT_NULL, 0, 0, PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY );
            /* MacRunner 2026-08-06 — какие дыры реально удалось зарезервировать.
             *
             * Зачем. Mono просит у гостя блоки под исполняемый код по КОНКРЕТНЫМ адресам
             * (VirtualAlloc size=0x10000 type=0x3000 protect=0x40) и получает c0000018
             * (конфликт адресов) 12 раз подряд, после чего поток умирает с c000007b.
             * Занимают эти адреса области с меткой malloc (tag=1..3), то есть куча ХОСТА
             * расползлась туда, где гость собирался разместить код: 4.2, 4.7, 15.7, 18.3 ГБ.
             * В эталонном прогоне конфликтов было НОЛЬ — значит это регрессия расположения.
             *
             * Резервирование идёт один раз при старте и должно закрывать эти адреса заранее.
             * Печатаем каждую дыру и исход попытки: молчащее резервирование неотличимо от
             * несостоявшегося, а разница между ними и есть ответ. */
            {
                static unsigned reserve_n;
                HB_PROBE_LOOKED(&pr_reserve_hole);
                HB_PROBE_LOOKED(&pr_reserve_hole_stroka);
                if (!ret) HB_PROBE_HIT(&pr_reserve_hole);
                if (reserve_n++ < 64 || hole_size >= 0x40000000)
                    HB_PROBE_SAY( &pr_reserve_hole_stroka,
                             "n=%u addr=%p size=%llx (%.1f ГБ) ret=%d %s\n",
                             reserve_n, (void *)(ULONG_PTR)hole_address,
                             (unsigned long long)hole_size, (double)hole_size / (1024.0*1024.0*1024.0),
                             (int)ret, ret ? "НЕ ЗАРЕЗЕРВИРОВАНА" : "зарезервирована" );
            }
            if (!ret) mmap_add_reserved_area( (void*)hole_address, hole_size );
            else if (ret == KERN_NO_SPACE)
            {
                /* something filled (part of) the hole before we could.
                   go back and look again. */
                address = hole_address;
                continue;
            }
        }
        address += size;
    }
#else
    size_t size = (char *)end - (char *)addr;

    if (!size) return;

    if (anon_mmap_tryfixed( addr, size, PROT_NONE, MAP_NORESERVE ) != MAP_FAILED)
    {
        mmap_add_reserved_area( addr, size );
        return;
    }
    size = (size / 2) & ~granularity_mask;
    if (size)
    {
        reserve_area( addr, (char *)addr + size );
        reserve_area( (char *)addr + size, end );
    }
#endif /* __APPLE__ */
}


static void mmap_init( const struct preload_info *preload_info )
{
#ifndef _WIN64
#ifndef __APPLE__
    char stack;
    char * const stack_ptr = &stack;
#endif
    char *user_space_limit = (char *)0x7ffe0000;
    int i;

    if (preload_info)
    {
        /* check for a reserved area starting at the user space limit */
        /* to avoid wasting time trying to allocate it again */
        for (i = 0; preload_info[i].size; i++)
        {
            SIZE_T size = preload_info[i].size;
            char *preload_end;

            if ((char *)preload_info[i].addr > user_space_limit) break;
            preload_end = reserved_area_end( preload_info[i].addr, &size );
            if (preload_end > user_space_limit)
            {
                user_space_limit = preload_end;
                break;
            }
        }
    }
    else reserve_area( (void *)0x00010000, (void *)0x40000000 );


#ifndef __APPLE__
    if (stack_ptr >= user_space_limit)
    {
        char *end = 0;
        char *base = stack_ptr - ((unsigned int)stack_ptr & granularity_mask) - (granularity_mask + 1);
        if (base > user_space_limit) reserve_area( user_space_limit, base );
        base = stack_ptr - ((unsigned int)stack_ptr & granularity_mask) + (granularity_mask + 1);
#if defined(linux) || defined(__FreeBSD__) || defined (__FreeBSD_kernel__) || defined(__DragonFly__)
        /* Heuristic: assume the stack is near the end of the address */
        /* space, this avoids a lot of futile allocation attempts */
        end = (char *)(((unsigned long)base + 0x0fffffff) & 0xf0000000);
#endif
        reserve_area( base, end );
    }
    else
#endif
        reserve_area( user_space_limit, 0 );

#else

    /* ★★★ 06.09.2026, лейн ПРИБОРЫ-3 — УЧЁТ СТОИТ ВЫШЕ РАННЕГО ВОЗВРАТА.
     * Первая моя редакция ставила его НИЖЕ `if (preload_info) return;`, и прибор честно
     * ответил looked=0 на обеих руках. Ноль был правдой («не смотрел»), но причину не
     * называл — ровно та ошибка постановки, о которой предупреждает шапка hb_probe.h:
     * учёт в точке РЕШЕНИЯ вместо точки, где наблюдение НАЧИНАЕТСЯ. Поймал её сам прибор:
     * НЕ отсутствие строки, а состояние NOT-OBSERVED при заведомо исполняемом пути. */
    HB_PROBE_LOOKED( &pr_reserve_top );
    HB_PROBE_LOOKED( &pr_reserve_preload );
    if (preload_info)
    {
        /* Комментарий ниже утверждает, что на macOS предзагрузчик невозможен и
         * preload_info здесь ВСЕГДА пуст. Утверждение никем не измерено — теперь измеряется:
         * ненулевой hits у этого прибора означает, что резервирование пропускается ИМЕННО
         * поэтому, а не из-за выключенного гейта. */
        HB_PROBE_SAY( &pr_reserve_preload, "резервирование ПРОПУЩЕНО: preload_info непуст\n" );
        return;
    }
    /* if we don't have a preloader, try to reserve the space now */
#if defined(__APPLE__) && defined(__aarch64__)
    /* MacRunner 2026-08-06 — на macOS эти три диапазона не работают, и вот почему.
     *
     * ЗАМЕР (прибор macrunner-hb-reserve-hole + отдельная проверка mach_vm_map):
     *   0x00010000    ret=1  KERN_INVALID_ADDRESS
     *   0x7f000000    ret=1  KERN_INVALID_ADDRESS
     *   0x100000000   ret=1  KERN_INVALID_ADDRESS   (ровно 4 ГБ — тоже нельзя)
     *   0x110000000   ret=0  ЗАРЕЗЕРВИРОВАНО
     *   0x400000000   ret=0  ЗАРЕЗЕРВИРОВАНО
     *
     * ret=1 это НЕ «занято» (занято дало бы KERN_NO_SPACE=3), а «такого адреса в карте
     * процесса нет»: у 64-битных программ macOS первые четыре гигабайта отрезаны насовсем
     * (__PAGEZERO по умолчанию 4 ГБ). Значит два нижних диапазона — мёртвый код, перенесённый
     * с Linux, где preloader занимает их ДО старта; на macOS preloader невозможен (это трюк
     * с ELF-интерпретатором), поэтому preload_info здесь всегда пуст.
     *
     * ЧЕМ ЭТО ОБОРАЧИВАЛОСЬ. Середина адресного пространства не запрашивалась вовсе, и её
     * забирала куча ХОСТА: распределитель malloc берёт крупные куски без фиксированного
     * адреса, а ядро выдаёт первую свободную дыру над границей. Дальше Mono просил у гостя
     * блоки под исполняемый код по конкретным адресам (VirtualAlloc size=0x10000 type=0x3000
     * protect=0x40) и получал c0000018 (STATUS_CONFLICTING_ADDRESSES) — 12 раз подряд, после
     * чего поток умирал. Занятые адреса: 4.2, 4.7, 15.7, 18.3, 18.4 ГБ, метки malloc (tag 1..3).
     *
     * ПРАВКА. Низкие диапазоны убраны как заведомо невозможные, вместо них обход дыр в той
     * области, которая гостю и нужна. Обход (reserve_area) сам пропускает занятое и берёт
     * свободное, поэтому одним куском брать не требуется — это проверено: запрос 4 ГБ одним
     * блоком от 16 ГБ даёт KERN_NO_SPACE, а обход дыр проходит.
     *
     * Верхний диапазон 0x7ffffe000000 оставлен без изменений — он рабочий. */
    /* Гейт добавлен 06.08 после того, как отказ выборки команды (ESR ec=0x20, dfsc=0x06,
     * pc=0) пришёлся на адрес 0xeb11b4000 — ВНУТРИ пятого зарезервированного куска
     * (0xc14000000 + 0x3ac000000, 14.7 ГБ), с правами prot=0 при max=7. То есть модуль
     * гостя лёг в область, которую мы сами закрыли PROT_NONE. Резервирование дало
     * конфликтов Mono 22 → 9, поэтому просто убирать его нельзя — нужна честная пара.
     * MACRUNNER_HB_RESERVE_HOLES=0 отключает обход дыр целиком. */
    /* MacRunner 2026-08-09 — ВЕРХНЯЯ ГРАНИЦА резервирования отдельным гейтом.
     *
     * Измерено в этот день на ОДНОМ бинаре, прогоны по 240 с (окно явления +195…+198 с
     * покрыто; предыдущий A/B на 120 с промахнулся мимо него и дал ложное «не влияет»):
     *
     *   RESERVE_HOLES=0                     отказов 95 млн (шторм с +195 с), exit=124
     *   RESERVE_HOLES=1, верх 0x1000000000  отказов 20 480, но exit=5 на +198 с
     *   RESERVE_HOLES=1, верх 0xc14000000   отказов 20 480 И exit=124   ← обе беды сняты
     *
     * Механизм у обеих бед один. Гостевой модуль (dynamic-builtin.dll по 0xeb11b0000)
     * попадает в ПЯТЫЙ кусок 0xc14000000+0x3ac000000 и остаётся prot=0 при max=7 →
     * `dxmt-com-lazy-signature reason=not-readable` → `badtarget` → c000007b → exit=5.
     * Тот же адрес 0xeb11b4000 назван в комментарии ниже — это не история, а живой отказ.
     * Если же резерв убрать целиком, полосу занимает куча хоста и начинается шторм.
     * Верх ниже 0xc14000000 оставляет полосу гостевых образов свободной и сохраняет резерв
     * там, где он и нужен. Вторая полоса образов (0x87ef…, ~8.5 ТБ) и так вне диапазона.
     *
     * Умолчание = прежние 64 ГБ, поэтому без переменной поведение НЕ меняется.
     * Печать одна на процесс: иначе об активности гейта пришлось бы гадать. */
    /* ★★ 06.09.2026, лейн ПРИБОРЫ-3 — «печать одна на процесс, иначе об активности гейта
     * пришлось бы гадать» верно ровно наполовину: строка ЕСТЬ, когда резерв включён, но её
     * ОТСУТСТВИЕ значило две разные вещи и различить их было нечем —
     *   а) MACRUNNER_HB_RESERVE_HOLES=0, резерв выключен сознательно;
     *   б) до этого места вообще не дошли: не тот ntdll.so в прогоне, другая ветка #ifdef,
     *      разложено не в то дерево (правило «дистов два» стоило нам полдня 06.08).
     * Учёт стоит ВЫШЕ гейта, поэтому теперь это два разных ответа:
     *   looked=0           путь резервирования не исполнялся ВООБЩЕ
     *   looked=1, hits=0   исполнялся, резерв выключен переменной
     *   hits=1             резерв применён, верх назван в строке */
    HB_PROBE_LOOKED( &pr_reserve_top );
    if (!getenv( "MACRUNNER_HB_RESERVE_HOLES" ) || strcmp( getenv( "MACRUNNER_HB_RESERVE_HOLES" ), "0" ))
    {
        const char *top_env = getenv( "MACRUNNER_HB_RESERVE_TOP" );
        unsigned long long top = 0x001000000000ull;

        if (top_env && *top_env)
        {
            char *end = NULL;
            unsigned long long v = strtoull( top_env, &end, 0 );
            if (end && !*end && v > 0x000110000000ull) top = v;
        }
        HB_PROBE_SAY( &pr_reserve_top, "top=%#llx (умолчание 0x1000000000)\n", top );
        fflush( stderr );
        reserve_area( (void *)0x000110000000, (void *)(uintptr_t)top );  /* 4.3 ГБ … top */
    }
    reserve_area( (void *)0x7ffffe000000, (void *)0x7fffffff0000 );
#else
    reserve_area( (void *)0x000000010000, (void *)0x000068000000 );
    reserve_area( (void *)0x00007f000000, (void *)0x00007fff0000 );
    reserve_area( (void *)0x7ffffe000000, (void *)0x7fffffff0000 );
#endif

#endif
}


/***********************************************************************
 *           get_wow_user_space_limit
 */
static ULONG_PTR get_wow_user_space_limit(void)
{
#ifdef _WIN64
    return user_space_wow_limit & ~granularity_mask;
#endif
    return (ULONG_PTR)user_space_limit;
}


/***********************************************************************
 *           add_builtin_module
 */
static void add_builtin_module( void *module, void *handle )
{
    struct builtin_module *builtin;

    if (!(builtin = malloc( sizeof(*builtin) ))) return;
    builtin->handle      = handle;
    builtin->module      = module;
    builtin->refcount    = 1;
    builtin->unix_path   = NULL;
    builtin->unix_handle = NULL;
    list_add_tail( &builtin_modules, &builtin->entry );
}


/***********************************************************************
 *           release_builtin_module
 */
static void release_builtin_module( void *module )
{
    struct builtin_module *builtin;

    LIST_FOR_EACH_ENTRY( builtin, &builtin_modules, struct builtin_module, entry )
    {
        if (builtin->module != module) continue;
        if (!--builtin->refcount)
        {
            list_remove( &builtin->entry );
            if (builtin->handle) dlclose( builtin->handle );
            if (builtin->unix_handle) dlclose( builtin->unix_handle );
            free( builtin->unix_path );
            free( builtin );
        }
        break;
    }
}


/***********************************************************************
 *           get_builtin_so_handle
 */
void *get_builtin_so_handle( void *module )
{
    sigset_t sigset;
    void *ret = NULL;
    struct builtin_module *builtin;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    LIST_FOR_EACH_ENTRY( builtin, &builtin_modules, struct builtin_module, entry )
    {
        if (builtin->module != module) continue;
        ret = builtin->handle;
        if (ret) builtin->refcount++;
        break;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}


#if defined(__APPLE__) && defined(__aarch64__)
extern BOOL macrunner_cpu_backend_disables_hb_semantics(void);

/* ★★★★ Лейн FEX-N2d 07.09.2026 — ПОДМЕНА СПУТНИКА ЗАКРЫТА ЗНАКОМ, А НЕ ДОВЕРИЕМ.
 *
 * ИЗМЕРЕНО, две руки, различие ровно одно — лежит ли на пути загрузки unix-половина
 * HyperBridge (dist/lib/wine/aarch64-unix/xtajit.so):
 *
 *     прибор                                убран      на месте
 *     macrunner-fex-glue (конструктор клея)     1            0
 *     macrunner-fex-jitexec (крюк 7)            4            0
 *     macrunner-fex-call7 «вернулся УСПЕХ»      2            2    <-- ЛОЖНЫЙ УСПЕХ
 *     macrunner-fex-init: шаг=13 InitCore       1            0
 *     наибольшее n у jit-mprotect-skip          4      196 608    <-- клин
 *     строк в журнале                      54 942        9 837
 *
 * ПРИЧИНА. Символ `__wine_unix_call_funcs` есть у ОБОИХ спутников, а `unix_path`
 * пишется модулю ОДИН раз (load_builtin_unixlib выше). Победивший первым спутник
 * отдаёт СВОЮ таблицу, и dlsym об этом ничего не сообщает: у HyperBridge под индексом 7
 * лежит совсем другой обработчик, он возвращает успех, и FEX идёт дальше вслепую.
 *
 * ЛЕЧЕНИЕ. Клей FEX экспортирует `__fex_darwin_unixlib_abi`. Спутник HyperBridge его не
 * несёт и нести не может. Если транслятор процесса — FEX, а спутник модуля процессора
 * знака не имеет, таблица НЕ ОТДАЁТСЯ: возвращается STATUS_ENTRYPOINT_NOT_FOUND, и FEX
 * печатает «НЕТ-КЛЕЯ» и завершает процесс. Громкий отказ вместо тихой чужой работы.
 *
 * ГРАНИЦЫ. Проверка касается ТОЛЬКО модуля процессора (xtajit.so / xtajit64.so) и
 * ТОЛЬКО при backend != hb, поэтому рука HyperBridge и все прочие спутники
 * (win32u.so, winemac.so, …) не задеты вовсе. Обход: MACRUNNER_FEX_ABI_MARK=0. */
static BOOL macrunner_fex_unixlib_marker_needed( const char *path )
{
    static int gate = -1;
    const char *name;

    if (!path) return FALSE;
    if (gate < 0)
    {
        const char *value = getenv( "MACRUNNER_FEX_ABI_MARK" );
        gate = value ? atoi( value ) : 1;
    }
    if (!gate) return FALSE;
    if (!macrunner_cpu_backend_disables_hb_semantics()) return FALSE;

    name = strrchr( path, '/' );
    name = name ? name + 1 : path;
    /* ★ ШАГ-2: спутники FEX переименованы (см. macrunner_fex_unix_name в unix/loader.c),
     * иначе dyld отдавал одноимённый образ HyperBridge.  Старые имена оставлены, чтобы
     * прежние раскладки не потеряли проверку знака молча. */
    return !strcmp( name, "libwow64fex.so" ) || !strcmp( name, "libarm64ecfex.so" ) ||
           !strcmp( name, "xtajit.so" ) || !strcmp( name, "xtajit64.so" );
}
#endif

/***********************************************************************
 *           get_builtin_unix_funcs
 */
static NTSTATUS get_builtin_unix_funcs( void *module, BOOL wow, const void **funcs )
{
    const char *ptr_name = wow ? "__wine_unix_call_wow64_funcs" : "__wine_unix_call_funcs";
    sigset_t sigset;
    NTSTATUS status = STATUS_DLL_NOT_FOUND;
    struct builtin_module *builtin;
    char *unix_path = NULL;
    void *unix_handle = NULL;
    BOOL tried_load = FALSE;
    BOOL need_load = FALSE;

retry:
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    LIST_FOR_EACH_ENTRY( builtin, &builtin_modules, struct builtin_module, entry )
    {
        if (builtin->module != module) continue;
        if (unix_handle)
        {
            if (!builtin->unix_handle)
            {
                builtin->unix_handle = unix_handle;
                unix_handle = NULL;
            }
        }
        if (builtin->unix_path && !builtin->unix_handle && !tried_load)
        {
            unix_path = strdup( builtin->unix_path );
            need_load = TRUE;
            break;
        }
        if (builtin->unix_handle)
        {
            *funcs = dlsym( builtin->unix_handle, ptr_name );
            status = *funcs ? STATUS_SUCCESS : STATUS_ENTRYPOINT_NOT_FOUND;
#if defined(__APPLE__) && defined(__aarch64__)
            /* Лейн FEX-N2d: см. macrunner_fex_unixlib_marker_needed выше. Печать
             * БЕЗУСЛОВНАЯ (потолок 8): без неё «отдали чужую таблицу» и «отдали свою»
             * выглядят в журнале одинаково — ровно это и стоило захода N2b. */
            if (macrunner_fex_unixlib_marker_needed( builtin->unix_path ))
            {
                const void *mark = dlsym( builtin->unix_handle, "__fex_darwin_unixlib_abi" );
                static unsigned int mr_abi_n;
                unsigned int n = __atomic_add_fetch( &mr_abi_n, 1, __ATOMIC_RELAXED );
                /* ★ ШАГ-2 08.09.2026 — ЧЕЙ ОБРАЗ НА САМОМ ДЕЛЕ ОТДАЛ ТАБЛИЦУ.
                 *
                 * N2d оставил это незакрытым (его §6 п.2): путь в журнале был НАШ, а знака
                 * в полученном образе не было, и «кто подменил» осталось гипотезой про
                 * install_name.  Просимый путь — не доказательство: dlopen может вернуть
                 * УЖЕ ЗАГРУЖЕННЫЙ образ.  dladdr по адресу самой таблицы называет файл,
                 * из которого она взята, без всяких предположений. */
                Dl_info mr_dli;
                const void *mr_tab = *funcs;
                const char *mr_real = "(dladdr не ответил)";

                if (mr_tab && dladdr( (void *)mr_tab, &mr_dli ) && mr_dli.dli_fname)
                    mr_real = mr_dli.dli_fname;

                if (!mark && status == STATUS_SUCCESS)
                {
                    *funcs = NULL;
                    status = STATUS_ENTRYPOINT_NOT_FOUND;
                }
                if (n <= 8)
                {
                    fprintf( stderr, "macrunner-fex-unixlib-abi: n=%u pid=%d путь=%s знак=%s"
                             " таблица=%s итог=%08x образ=%s\n", n, (int)getpid(), builtin->unix_path,
                             mark ? "ЕСТЬ" : "НЕТ", *funcs ? "отдана" : "НЕ отдана",
                             (unsigned)status, mr_real );
                    fflush( stderr );
                }
            }
#endif
        }
        break;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    if (need_load)
    {
        tried_load = TRUE;
        need_load = FALSE;
        if (!unix_path) return STATUS_NO_MEMORY;
        unix_handle = dlopen( unix_path, RTLD_NOW );
        if (!unix_handle)
            WARN_(module)( "failed to load %s: %s\n", debugstr_a(unix_path), dlerror() );
        free( unix_path );
        unix_path = NULL;
        goto retry;
    }
    if (unix_handle) dlclose( unix_handle );
    return status;
}


/***********************************************************************
 *           load_builtin_unixlib
 */
NTSTATUS load_builtin_unixlib( void *module, const char *name )
{
    sigset_t sigset;
    NTSTATUS status = STATUS_SUCCESS;
    struct builtin_module *builtin;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    LIST_FOR_EACH_ENTRY( builtin, &builtin_modules, struct builtin_module, entry )
    {
        if (builtin->module != module) continue;
        if (!builtin->unix_path) builtin->unix_path = strdup( name );
        else status = STATUS_IMAGE_ALREADY_LOADED;
        break;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *           free_ranges_lower_bound
 *
 * Returns the first range whose end is not less than addr, or end if there's none.
 */
static struct range_entry *free_ranges_lower_bound( void *addr )
{
    struct range_entry *begin = free_ranges;
    struct range_entry *end = free_ranges_end;
    struct range_entry *mid;

    while (begin < end)
    {
        mid = begin + (end - begin) / 2;
        if (mid->end < addr)
            begin = mid + 1;
        else
            end = mid;
    }

    return begin;
}

static void dump_free_ranges(void)
{
    struct range_entry *r;
    for (r = free_ranges; r != free_ranges_end; ++r)
        TRACE_(virtual_ranges)("%p - %p.\n", r->base, r->end);
}

static BOOL get_view_granularity_range( const struct file_view *view, void **base, void **end, void **limit )
{
    UINT_PTR addr = (UINT_PTR)view->base;
    UINT_PTR rounded_base = addr & ~(UINT_PTR)granularity_mask;
    SIZE_T rounded_size;

    if ((UINT_PTR)view->size > ~(UINT_PTR)0 - addr) return FALSE;
    if (!round_size_checked( addr, view->size, granularity_mask, &rounded_size )) return FALSE;
    if (rounded_size > ~(UINT_PTR)0 - rounded_base) return FALSE;

    *base = (void *)rounded_base;
    *end = (void *)(rounded_base + rounded_size);
    if (limit) *limit = (void *)(addr + view->size);
    return TRUE;
}

/***********************************************************************
 *           free_ranges_insert_view
 *
 * Updates the free_ranges after a new view has been created.
 */
static void free_ranges_insert_view( struct file_view *view )
{
    void *view_base, *view_end, *view_limit;
    struct range_entry *range, *next;

    if (!get_view_granularity_range( view, &view_base, &view_end, &view_limit ))
    {
        ERR( "view range overflow base %p size %zx\n", view->base, view->size );
        VIRTUAL_DEBUG_DUMP_RANGES();
        return;
    }

    range = free_ranges_lower_bound( view_base );
    next = range + 1;

    /* free_ranges initial value is such that the view is either inside range or before another one. */
    assert( range != free_ranges_end );
    assert( range->end > view_base || next != free_ranges_end );

    /* Free ranges addresses are aligned at granularity_mask while the views may be not. */

    if (range->base > view_base)
        view_base = range->base;
    if (range->end < view_end)
        view_end = range->end;
    if (range->end == view_base && next->base >= view_end)
        view_end = view_base;

    TRACE_(virtual_ranges)( "%p - %p, aligned %p - %p.\n",
                            view->base, view_limit, view_base, view_end );

    if (view_end <= view_base)
    {
        VIRTUAL_DEBUG_DUMP_RANGES();
        return;
    }

    /* this should never happen */
    if (range->base > view_base || range->end < view_end)
        ERR( "range %p - %p is already partially mapped\n", view_base, view_end );
    assert( range->base <= view_base && range->end >= view_end );

    /* need to split the range in two */
    if (range->base < view_base && range->end > view_end)
    {
        SIZE_T range_index = range - free_ranges, next_index = next - free_ranges;
        mr_vm_ensure_free_range_slot();
        range = free_ranges + range_index;
        next = free_ranges + next_index;
        memmove( next + 1, next, (free_ranges_end - next) * sizeof(struct range_entry) );
        free_ranges_end += 1;
        mr_vm_ranges_high();
        if ((char *)free_ranges_end - (char *)free_ranges > free_ranges_capacity)
            ERR( "Free range sequence is full, trouble ahead!\n" );
        assert( (char *)free_ranges_end - (char *)free_ranges <= free_ranges_capacity );

        next->base = view_end;
        next->end = range->end;
        range->end = view_base;
    }
    else
    {
        /* otherwise we just have to shrink it */
        if (range->base < view_base)
            range->end = view_base;
        else
            range->base = view_end;

        if (range->base < range->end)
        {
            VIRTUAL_DEBUG_DUMP_RANGES();
            return;
        }
        /* and possibly remove it if it's now empty */
        memmove( range, next, (free_ranges_end - next) * sizeof(struct range_entry) );
        free_ranges_end -= 1;
        assert( free_ranges_end - free_ranges > 0 );
    }
    VIRTUAL_DEBUG_DUMP_RANGES();
}

/***********************************************************************
 *           free_ranges_remove_view
 *
 * Updates the free_ranges after a view has been destroyed.
 */
static void free_ranges_remove_view( struct file_view *view )
{
    struct file_view *prev_view = RB_ENTRY_VALUE( rb_prev( &view->entry ), struct file_view, entry );
    struct file_view *next_view = RB_ENTRY_VALUE( rb_next( &view->entry ), struct file_view, entry );
    void *view_base, *view_end, *view_limit;
    void *prev_view_base = NULL, *prev_view_end = NULL;
    void *next_view_base = NULL, *next_view_end = NULL;
    struct range_entry *range, *next;

    if (!get_view_granularity_range( view, &view_base, &view_end, &view_limit ) ||
        (prev_view && !get_view_granularity_range( prev_view, &prev_view_base, &prev_view_end, NULL )) ||
        (next_view && !get_view_granularity_range( next_view, &next_view_base, &next_view_end, NULL )))
    {
        ERR( "view range overflow base %p size %zx\n", view->base, view->size );
        VIRTUAL_DEBUG_DUMP_RANGES();
        return;
    }

    range = free_ranges_lower_bound( view_base );
    next = range + 1;

    /* Free ranges addresses are aligned at granularity_mask while the views may be not. */

    if (prev_view_end && prev_view_end > view_base && prev_view_base < view_end)
        view_base = prev_view_end;
    if (next_view_base && next_view_base < view_end && next_view_end > view_base)
        view_end = next_view_base;

    TRACE_(virtual_ranges)( "%p - %p, aligned %p - %p.\n",
                            view->base, view_limit, view_base, view_end );

    if (view_end <= view_base)
    {
        VIRTUAL_DEBUG_DUMP_RANGES();
        return;
    }
    /* free_ranges initial value is such that the view is either inside range or before another one. */
    assert( range != free_ranges_end );
    assert( range->end > view_base || next != free_ranges_end );

    /* this should never happen, but we can safely ignore it */
    if (range->base <= view_base && range->end >= view_end)
    {
        WARN( "range %p - %p is already unmapped\n", view_base, view_end );
        return;
    }

    /* this should never happen */
    if (range->base < view_end && range->end > view_base)
        ERR( "range %p - %p is already partially unmapped\n", view_base, view_end );
    assert( range->end <= view_base || range->base >= view_end );

    /* merge with next if possible */
    if (range->end == view_base && next->base == view_end)
    {
        range->end = next->end;
        memmove( next, next + 1, (free_ranges_end - next - 1) * sizeof(struct range_entry) );
        free_ranges_end -= 1;
        assert( free_ranges_end - free_ranges > 0 );
    }
    /* or try growing the range */
    else if (range->end == view_base)
        range->end = view_end;
    else if (range->base == view_end)
        range->base = view_base;
    /* otherwise create a new one */
    else
    {
        SIZE_T range_index = range - free_ranges;
        mr_vm_ensure_free_range_slot();
        range = free_ranges + range_index;
        memmove( range + 1, range, (free_ranges_end - range) * sizeof(struct range_entry) );
        free_ranges_end += 1;
        mr_vm_ranges_high();
        if ((char *)free_ranges_end - (char *)free_ranges > free_ranges_capacity)
            ERR( "Free range sequence is full, trouble ahead!\n" );
        assert( (char *)free_ranges_end - (char *)free_ranges <= free_ranges_capacity );

        range->base = view_base;
        range->end = view_end;
    }
    VIRTUAL_DEBUG_DUMP_RANGES();
}


static inline int is_view_valloc( const struct file_view *view )
{
    return !(view->protect & (SEC_FILE | SEC_RESERVE | SEC_COMMIT));
}

/***********************************************************************
 *           get_page_vprot
 *
 * Return the page protection byte.
 */
static BYTE get_page_vprot( const void *addr )
{
    size_t idx = (size_t)addr >> page_shift;

#ifdef _WIN64
    if ((idx >> pages_vprot_shift) >= pages_vprot_size) return 0;
    if (!pages_vprot[idx >> pages_vprot_shift]) return 0;
    return pages_vprot[idx >> pages_vprot_shift][idx & pages_vprot_mask];
#else
    return pages_vprot[idx];
#endif
}


static BOOL get_page_range( const void *addr, size_t size, size_t *idx, size_t *end )
{
    UINT_PTR start = (UINT_PTR)addr;

    *idx = start >> page_shift;
    if (!size)
    {
        *end = *idx;
        return TRUE;
    }

    if (size - 1 > ~(UINT_PTR)0 - start) return FALSE;
    *end = ((start + size - 1) >> page_shift) + 1;
#ifdef _WIN64
    if (*end > pages_vprot_size << pages_vprot_shift) return FALSE;
#endif
    return TRUE;
}


/***********************************************************************
 *           get_host_page_vprot
 *
 * Return the union of the page protection bytes of all the pages making up the host page.
 */
static BYTE get_host_page_vprot( const void *addr )
{
    char *page = ROUND_ADDR( addr, host_page_mask );
    size_t i;
    BYTE vprot = 0;

    /* A host page may span the end of a lazily allocated vprot bucket.  Use
     * the per-page accessor so signal handling for unmapped addresses cannot
     * fault while trying to classify the original fault. */
    for (i = 0; i < host_page_size; i += page_size) vprot |= get_page_vprot( page + i );
    return vprot;
}


/***********************************************************************
 *           get_vprot_range_size
 *
 * Return the size of the region with equal masked vprot byte.
 * Also return the protections for the first page.
 * The function assumes that base and size are page aligned,
 * base + size does not wrap around and the range is within view so
 * vprot bytes are allocated for the range. */
static SIZE_T get_vprot_range_size( char *base, SIZE_T size, BYTE mask, BYTE *vprot )
{
    static const UINT_PTR word_from_byte = (UINT_PTR)0x101010101010101;
    static const UINT_PTR index_align_mask = sizeof(UINT_PTR) - 1;
    SIZE_T curr_idx, start_idx, end_idx, aligned_start_idx;
    UINT_PTR vprot_word, mask_word;
    const BYTE *vprot_ptr;

    TRACE("base %p, size %p, mask %#x.\n", base, (void *)size, mask);

    curr_idx = start_idx = (size_t)base >> page_shift;
    end_idx = start_idx + (size >> page_shift);

    aligned_start_idx = ROUND_SIZE( 0, start_idx, index_align_mask );
    if (aligned_start_idx > end_idx) aligned_start_idx = end_idx;

#ifdef _WIN64
    vprot_ptr = pages_vprot[curr_idx >> pages_vprot_shift] + (curr_idx & pages_vprot_mask);
#else
    vprot_ptr = pages_vprot + curr_idx;
#endif
    *vprot = *vprot_ptr;

    /* Page count page table is at least the multiples of sizeof(UINT_PTR)
     * so we don't have to worry about crossing the boundary on unaligned idx values. */

    for (; curr_idx < aligned_start_idx; ++curr_idx, ++vprot_ptr)
        if ((*vprot ^ *vprot_ptr) & mask) return (curr_idx - start_idx) << page_shift;

    vprot_word = word_from_byte * *vprot;
    mask_word = word_from_byte * mask;
    for (; curr_idx < end_idx; curr_idx += sizeof(UINT_PTR), vprot_ptr += sizeof(UINT_PTR))
    {
#ifdef _WIN64
        if (!(curr_idx & pages_vprot_mask)) vprot_ptr = pages_vprot[curr_idx >> pages_vprot_shift];
#endif
        if ((vprot_word ^ *(UINT_PTR *)vprot_ptr) & mask_word)
        {
            for (; curr_idx < end_idx; ++curr_idx, ++vprot_ptr)
                if ((*vprot ^ *vprot_ptr) & mask) break;
            return (curr_idx - start_idx) << page_shift;
        }
    }
    return size;
}

/***********************************************************************
 *           set_page_vprot
 *
 * Set a range of page protection bytes.
 */
static void set_page_vprot( const void *addr, size_t size, BYTE vprot )
{
    size_t idx, end;

    if (!get_page_range( addr, size, &idx, &end )) return;
    if (idx == end) return;

#ifdef _WIN64
    while (idx >> pages_vprot_shift != end >> pages_vprot_shift)
    {
        size_t dir_size = pages_vprot_mask + 1 - (idx & pages_vprot_mask);
        memset( pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask), vprot, dir_size );
        idx += dir_size;
    }
    memset( pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask), vprot, end - idx );
#else
    memset( pages_vprot + idx, vprot, end - idx );
#endif
}


/***********************************************************************
 *           set_page_vprot_bits
 *
 * Set or clear bits in a range of page protection bytes.
 */
static void set_page_vprot_bits( const void *addr, size_t size, BYTE set, BYTE clear )
{
    size_t idx, end;

    if (!get_page_range( addr, size, &idx, &end )) return;

#ifdef _WIN64
    for ( ; idx < end; idx++)
    {
        BYTE *ptr = pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask);
        *ptr = (*ptr & ~clear) | set;
    }
#else
    for ( ; idx < end; idx++) pages_vprot[idx] = (pages_vprot[idx] & ~clear) | set;
#endif
}


/***********************************************************************
 *           set_page_vprot_exec_write_protect
 *
 * Write protect pages that are executable.
 */
static BOOL set_page_vprot_exec_write_protect( const void *addr, size_t size )
{
    BOOL ret = FALSE;
#ifdef _WIN64 /* only supported on 64-bit so assume 2-level table */
    size_t idx, end;

    if (!get_page_range( addr, size, &idx, &end )) return FALSE;

    for ( ; idx < end; idx++)
    {
        BYTE *ptr = pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask);
        if (!is_vprot_exec_write( *ptr )) continue;
        *ptr |= VPROT_WRITEWATCH;
        ret = TRUE;
    }
#endif
    return ret;
}


/***********************************************************************
 *           alloc_pages_vprot
 *
 * Allocate the page protection bytes for a given range.
 */
static BOOL alloc_pages_vprot( const void *addr, size_t size )
{
#ifdef _WIN64
    size_t idx, end;
    size_t i;
    void *ptr;

    if (!get_page_range( addr, size, &idx, &end )) return FALSE;
    if (idx == end) return TRUE;
    assert( end <= pages_vprot_size << pages_vprot_shift );
    for (i = idx >> pages_vprot_shift; i < (end + pages_vprot_mask) >> pages_vprot_shift; i++)
    {
        if (pages_vprot[i]) continue;
        if ((ptr = MR_VM_CALL( MR_VM_METADATA,
                              anon_mmap_alloc( pages_vprot_mask + 1, PROT_READ | PROT_WRITE ) )) == MAP_FAILED)
        {
            ERR( "anon mmap error %s for vprot table, size %08lx\n", strerror(errno), pages_vprot_mask + 1 );
            return FALSE;
        }
        pages_vprot[i] = ptr;
    }
#endif
    return TRUE;
}


static inline UINT64 maskbits( size_t idx )
{
    return ~(UINT64)0 << (idx & 63);
}

/***********************************************************************
 *           set_arm64ec_range
 */
static void set_arm64ec_range( const void *addr, size_t size )
{
    UINT64 *map = arm64ec_view->base;
    size_t idx, end, pos, end_pos;

    if (!get_page_range( addr, size, &idx, &end ) || idx == end) return;
    pos = idx / 64;
    end_pos = end / 64;

    if (end_pos > pos)
    {
        map[pos++] |= maskbits( idx );
        while (pos < end_pos) map[pos++] = ~(UINT64)0;
        if (end & 63) map[pos] |= ~maskbits( end );
    }
    else map[pos] |= maskbits( idx ) & ~maskbits( end );
}


/***********************************************************************
 *           clear_arm64ec_range
 */
static void clear_arm64ec_range( const void *addr, size_t size )
{
    UINT64 *map = arm64ec_view->base;
    size_t idx, end, pos, end_pos;

    if (!get_page_range( addr, size, &idx, &end ) || idx == end) return;
    pos = idx / 64;
    end_pos = end / 64;

    if (end_pos > pos)
    {
        map[pos++] &= ~maskbits( idx );
        while (pos < end_pos) map[pos++] = 0;
        if (end & 63) map[pos] &= maskbits( end );
    }
    else map[pos] &= ~maskbits( idx ) | maskbits( end );
}


/***********************************************************************
 *           compare_view
 *
 * View comparison function used for the rb tree.
 */
static int compare_view( const void *addr, const struct wine_rb_entry *entry )
{
    struct file_view *view = WINE_RB_ENTRY_VALUE( entry, struct file_view, entry );

    if (addr < view->base) return -1;
    if (addr > view->base) return 1;
    return 0;
}


/***********************************************************************
 *           get_prot_str
 */
static const char *get_prot_str( BYTE prot )
{
    static char buffer[6];
    buffer[0] = (prot & VPROT_COMMITTED) ? 'c' : '-';
    buffer[1] = (prot & VPROT_GUARD) ? 'g' : ((prot & VPROT_WRITEWATCH) ? 'H' : '-');
    buffer[2] = (prot & VPROT_READ) ? 'r' : '-';
    buffer[3] = (prot & VPROT_WRITECOPY) ? (prot & VPROT_COPIED ? 'w' : 'W')
        : ((prot & VPROT_WRITE) ? 'w' : '-');
    buffer[4] = (prot & VPROT_EXEC) ? 'x' : '-';
    buffer[5] = 0;
    return buffer;
}


/***********************************************************************
 *           get_unix_prot
 *
 * Convert page protections to protection for mmap/mprotect.
 */
static int get_unix_prot( BYTE vprot )
{
    int prot = 0;
    if ((vprot & VPROT_COMMITTED) && !(vprot & VPROT_GUARD))
    {
        if (vprot & VPROT_READ) prot |= PROT_READ;
        if (vprot & VPROT_WRITE) prot |= PROT_WRITE | PROT_READ;
        if (vprot & VPROT_WRITECOPY) prot |= PROT_WRITE | PROT_READ;
        if (vprot & VPROT_EXEC) prot |= PROT_EXEC | PROT_READ;
        if (vprot & VPROT_WRITEWATCH) prot &= ~PROT_WRITE;
    }
    if (!prot) prot = PROT_NONE;
    return prot;
}


/***********************************************************************
 *           dump_view
 */
static void dump_view( struct file_view *view )
{
    UINT i, count;
    char *addr = view->base;
    BYTE prot = get_page_vprot( addr );

    TRACE( "View: %p - %p %s", addr, addr + view->size - 1, get_prot_str(view->protect) );
    if (view->protect & VPROT_SYSTEM)
        TRACE( " (builtin image)\n" );
    else if (view->protect & VPROT_FREE_PLACEHOLDER)
        TRACE( " (placeholder)\n" );
    else if (view->protect & SEC_IMAGE)
        TRACE( " (image)\n" );
    else if (view->protect & SEC_FILE)
        TRACE( " (file)\n" );
    else if (view->protect & (SEC_RESERVE | SEC_COMMIT))
        TRACE( " (anonymous)\n" );
    else
        TRACE( " (valloc)\n");

    for (count = i = 1; i < view->size >> page_shift; i++, count++)
    {
        BYTE next = get_page_vprot( addr + (count << page_shift) );
        if (next == prot) continue;
        TRACE( "      %p - %p %s\n",
                 addr, addr + (count << page_shift) - 1, get_prot_str(prot) );
        addr += (count << page_shift);
        prot = next;
        count = 0;
    }
    if (count)
        TRACE( "      %p - %p %s\n",
                 addr, addr + (count << page_shift) - 1, get_prot_str(prot) );
}


/***********************************************************************
 *           VIRTUAL_Dump
 */
#ifdef WINE_VM_DEBUG
static void VIRTUAL_Dump(void)
{
    sigset_t sigset;
    struct file_view *view;

    TRACE( "Dump of all virtual memory views:\n" );
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
    {
        dump_view( view );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}
#endif


/***********************************************************************
 *           find_view
 *
 * Find the view containing a given address. virtual_mutex must be held by caller.
 *
 * PARAMS
 *      addr  [I] Address
 *
 * RETURNS
 *	View: Success
 *	NULL: Failure
 */
static BOOL get_view_limit( const struct file_view *view, char **limit )
{
    UINT_PTR base = (UINT_PTR)view->base;

    if ((UINT_PTR)view->size > ~(UINT_PTR)0 - base) return FALSE;
    *limit = (char *)(base + view->size);
    return TRUE;
}

static struct file_view *find_view( const void *addr, size_t size )
{
    struct wine_rb_entry *ptr = views_tree.root;
    const char *addr_end;

    if ((UINT_PTR)size > ~(UINT_PTR)0 - (UINT_PTR)addr) return NULL; /* overflow */
    addr_end = (const char *)addr + size;

    while (ptr)
    {
        struct file_view *view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );
        char *view_end;

        if (!get_view_limit( view, &view_end )) return NULL;

        if ((const char *)view->base > (const char *)addr) ptr = ptr->left;
        else if (view_end <= (const char *)addr) ptr = ptr->right;
        else if (view_end < addr_end) break;  /* size too large */
        else return view;
    }
    return NULL;
}


/***********************************************************************
 *           is_write_watch_range
 */
/* MacRunner 2026-07-30 — is the fault storm Mono's GC write barrier?
 *
 * Established by measurement: 9.4-17.4 million write-PERMISSION faults per startup (esr=0x9200004f,
 * DFSC 0x0f, align=0), all from one PC executing `str x0,[x20]`, with the same page faulting
 * repeatedly at advancing offsets, and the storm starting exactly when Mono comes up -- 88/s before,
 * 12000-36000/s after. Our own commit-upgrade path never fires (zero traces), so the faults are
 * handled upstream, and set_vprot at virtual.c:1516 is why they happen at all: a VPROT_WRITEWATCH
 * page has PROT_WRITE stripped on purpose, so every write traps once per page.
 *
 * Once per page would be fine. What makes it a storm is re-arming, and the only thing that re-arms
 * is a caller resetting the watch -- which is exactly what a generational GC does every collection
 * to find its dirty pages. Mono is a generational GC. use_kernel_writewatch, the path where the
 * kernel tracks dirty pages with no faults at all, is set only by the Linux pagemap_scan ioctl, so
 * on macOS we are always on the mprotect-and-signal fallback.
 *
 * That chain is coherent but it is still inference at the last link, and four inferences today were
 * wrong. These three counters close it: if a guest asks for MEM_WRITE_WATCH and then resets the
 * watch thousands of times, the storm is the GC barrier and the fix is to make this feature
 * unavailable so Mono falls back to its software card table -- a few instructions per write instead
 * of a kernel round trip. If they stay at zero, write-watch is not involved and the read-only
 * mapping comes from somewhere else entirely. */
static unsigned int macrunner_ww_alloc, macrunner_ww_get, macrunner_ww_reset;

static void macrunner_ww_note( const char *what, unsigned int *ctr )
{
    unsigned int n = __atomic_add_fetch( ctr, 1, __ATOMIC_RELAXED );

    if (n <= 4 || !(n & 0x3ff))
    {
        fprintf( stderr, "macrunner-ww: %s n=%u alloc=%u get=%u reset=%u\n", what, n,
                 __atomic_load_n( &macrunner_ww_alloc, __ATOMIC_RELAXED ),
                 __atomic_load_n( &macrunner_ww_get, __ATOMIC_RELAXED ),
                 __atomic_load_n( &macrunner_ww_reset, __ATOMIC_RELAXED ) );
        fflush( stderr );
    }
}

static inline BOOL is_write_watch_range( const void *addr, size_t size )
{
    struct file_view *view = find_view( addr, size );
    return view && (view->protect & VPROT_WRITEWATCH);
}


/***********************************************************************
 *           find_view_range
 *
 * Find the first view overlapping at least part of the specified range.
 * virtual_mutex must be held by caller.
 */
/* ★ СТЕНА64: лежит ли адрес в области MAP_JIT, то есть в КОДОВОМ БУФЕРЕ FEX.
 *
 * Нужно трамплину возврата из сигнала (signal_arm64.c): внутри выпущенного FEX кода
 * распределение регистров задано САМИМ FEX (Arm64Emitter.h:68-80) — x17 там
 * REG_CALLRET_SP и ЖИВОЙ, а x16 не несёт никакой роли вовсе. Снаружи буфера это
 * неверно, поэтому решение принимается по принадлежности адреса, а не глобально.
 *
 * Замка НЕ берём: зовут из обработчика сигнала, где брать его нельзя, а дерево
 * представлений в момент возобновления не меняется — мы ничего не выделяем. Обход
 * дерева только на чтение; так же его зовёт ветвь самозаписи ниже. */
BOOL macrunner_addr_in_jit_view( const void *addr )
{
    struct file_view *v;

    if (!addr) return FALSE;
    v = find_view( ROUND_ADDR( addr, host_page_mask ), host_page_size );
    return (v && (v->protect & VPROT_MACRUNNER_JIT)) ? TRUE : FALSE;
}


static struct file_view *find_view_range( const void *addr, size_t size )
{
    struct wine_rb_entry *ptr = views_tree.root;
    const char *addr_end;

    if ((UINT_PTR)size > ~(UINT_PTR)0 - (UINT_PTR)addr) return NULL; /* overflow */
    addr_end = (const char *)addr + size;

    while (ptr)
    {
        struct file_view *view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );
        char *view_end;

        if (!get_view_limit( view, &view_end )) return NULL;

        if ((const char *)view->base >= addr_end) ptr = ptr->left;
        else if (view_end <= (const char *)addr) ptr = ptr->right;
        else return view;
    }
    return NULL;
}


/***********************************************************************
 *           find_view_inside_range
 *
 * Find first (resp. last, if top_down) view inside a range.
 * virtual_mutex must be held by caller.
 */
static struct wine_rb_entry *find_view_inside_range( void **base_ptr, void **end_ptr, int top_down )
{
    struct wine_rb_entry *first = NULL, *ptr = views_tree.root;
    void *base = *base_ptr, *end = *end_ptr;

    /* find the first (resp. last) view inside the range */
    while (ptr)
    {
        struct file_view *view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );
        char *view_end;

        if (!get_view_limit( view, &view_end ))
        {
            ERR( "view range overflow base %p size %zx\n", view->base, view->size );
            *base_ptr = *end_ptr;
            return NULL;
        }

        if (view_end >= (char *)end)
        {
            end = min( end, view->base );
            ptr = ptr->left;
        }
        else if (view->base <= base)
        {
            base = max( (char *)base, view_end );
            ptr = ptr->right;
        }
        else
        {
            first = ptr;
            ptr = top_down ? ptr->right : ptr->left;
        }
    }

    *base_ptr = base;
    *end_ptr = end;
    return first;
}


/***********************************************************************
 *           try_map_free_area
 *
 * Try mmaping some expected free memory region, eventually stepping and
 * retrying inside it, and return where it actually succeeded, or NULL.
 */
/* MacRunner ЛЕСТНИЦА 2026-08-09 — перепись перебора свободного адреса.
 *
 * Профиль (два среза по 30 с) показал, что 42.2% и 33.4% ВСЕГО активного времени процесса
 * сидит в `_kernelrpc_mach_vm_map_trap` под одним путём: NtCreateThreadEx -> init_thread_stack
 * -> virtual_alloc_thread_stack -> map_view -> map_free_area -> try_map_free_area. Отсюда
 * гипотеза: цикл ниже делает МНОГО проваливающихся системных вызовов, потому что идёт по
 * диапазонам, которые дерево видов Wine считает свободными, а macOS уже занял нашими же
 * отображениями (арены MAP_JIT, резерв RESERVE_HOLES/RESERVE_TOP).
 *
 * Прежде чем что-то чинить — СЧИТАЕМ. Перепись отвечает ровно на один вопрос: время уходит на
 * МНОЖЕСТВО неудачных проб или на ОДИН дорогой успешный вызов. Это разные болезни.
 * Что убьёт гипотезу: малое `steps` при большом времени — значит перебора нет.
 *
 * Печать через fprintf(stderr): здесь не сигнальный путь, а канал ошибок wine до наших
 * журналов не доходит (проверено 02.08 — строк `err:` нет ни в одном прогоне за всю историю).
 * virtual_mutex держится вызывающим (см. комментарий к map_free_area), поэтому обычные
 * инкременты, без атомарных операций. */
static ULONG64 macrunner_mapscan_calls;
static ULONG64 macrunner_mapscan_steps;
static ULONG64 macrunner_mapscan_eexist;
static ULONG64 macrunner_mapscan_max_steps;
static ULONG64 macrunner_mapscan_fail;
static ULONG64 macrunner_mapscan_big_reports;

static ULONG64 macrunner_mapscan_skips;
static ULONG64 macrunner_mapscan_skipped_bytes;

static void* try_map_free_area_impl( void *base, void *end, ptrdiff_t step,
                                     void *start, size_t size, int unix_prot );

#ifdef __APPLE__
/* MacRunner ЛЕСТНИЦА 2026-08-09 — ПЕРЕШАГНУТЬ занятую область вместо перебора по шагу.
 *
 * Замер (перепись выше): 783 млн проваленных `mach_vm_map` за 300 с, EEXIST ровно 100.0%,
 * худший ОДИН вызов — 6 740 352 шага, диапазон 0xfbf810000…0x769a000000, то есть 411 ГБ,
 * просмотренных кусочками по 64 КБ. Занимают эту полосу НАШИ отображения (арены JIT), в дереве
 * видов Wine не заведённые, поэтому Wine идёт туда как в пустоту.
 *
 * Ядро знает границы занятого и отдаёт их ОДНИМ вызовом. Спрашиваем `mach_vm_region` и прыгаем
 * за конец занятой области вместо шага в 64 КБ: миллионы системных вызовов превращаются в
 * единицы. Корректность не страдает — адрес по-прежнему проверяется настоящим `mach_vm_map`,
 * меняется ТОЛЬКО величина шага при отказе, и только вперёд (для перебора сверху вниз
 * поведение прежнее).
 *
 * За гейтом MACRUNNER_HB_MAPSCAN_SKIP (умолчание 0): включается замером, как требует правило. */
static int macrunner_mapscan_skip_enabled(void)
{
    static int cached = -1;

    if (cached < 0)
    {
        const char *v = getenv( "MACRUNNER_HB_MAPSCAN_SKIP" );
        cached = (v && *v && *v != '0') ? 1 : 0;
        fprintf( stderr, "macrunner-hb-mapscan-skip: gate=%d\n", cached );
        fflush( stderr );
    }
    return cached;
}

/* Конец занятой области, содержащей start, выровненный вверх по шагу; NULL если start свободен
 * (тогда решает обычный шаг — расходиться с наблюдаемым EEXIST мы не имеем права). */
static char *macrunner_mapscan_next_free( char *start, size_t step )
{
    mach_vm_address_t addr = (mach_vm_address_t)(uintptr_t)start;
    mach_vm_size_t rsize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    mach_vm_address_t occupied_end;
    uintptr_t aligned;

    if (mach_vm_region( mach_task_self(), &addr, &rsize, VM_REGION_BASIC_INFO_64,
                        (vm_region_info_t)&info, &count, &obj ) != KERN_SUCCESS)
        return NULL;
    if (addr > (mach_vm_address_t)(uintptr_t)start) return NULL;   /* start уже свободен */
    occupied_end = addr + rsize;
    if (occupied_end <= (mach_vm_address_t)(uintptr_t)start) return NULL;

    aligned = ((uintptr_t)occupied_end + step - 1) & ~(uintptr_t)(step - 1);
    if (aligned <= (uintptr_t)start) return NULL;                  /* без движения вперёд */
    return (char *)aligned;
}
#endif

static void* try_map_free_area( void *base, void *end, ptrdiff_t step,
                                void *start, size_t size, int unix_prot )
{
    ULONG64 before = macrunner_mapscan_steps;
    void *scan_start = start;
    void *ret = MR_VM_CALL( MR_VM_NOADDR, try_map_free_area_impl( base, end, step, start, size, unix_prot ) );
    ULONG64 n = macrunner_mapscan_steps - before;
    ULONG64 calls = ++macrunner_mapscan_calls;
    BOOL big = n >= 1024 && macrunner_mapscan_big_reports < 32;

    MR_VM_INC(try_map_free);
    MR_VM_INC(gap_steps);

    if (n > macrunner_mapscan_max_steps) macrunner_mapscan_max_steps = n;
    if (!ret) macrunner_mapscan_fail++;
    if (big) macrunner_mapscan_big_reports++;

    /* Печать ТОЛЬКО через write(2) с ручным форматированием.
     *
     * Первая версия звала fprintf — и прогон 22:09 умер, не дойдя даже до
     * 'Initialize engine version' (exit=3, ни одной строки переписи). Причина в том, что
     * вызывающий ДЕРЖИТ virtual_mutex, а stdio при первом обращении инициализируется и
     * выделяет память: malloc -> mmap -> обратно в этот же путь -> захват уже занятого
     * мьютекса. Печать стояла на `calls <= 16`, поэтому подрывалась первая же проба.
     * Ни stdio, ни malloc, ни блокировок — только буфер на стеке. */
    if (calls <= 16 || !(calls & 0xff) || big)
    {
        char buf[512];
        unsigned int pos = 0;
        const ULONG64 dvals[6] = { calls, macrunner_mapscan_steps, macrunner_mapscan_eexist,
                                   n, macrunner_mapscan_max_steps, macrunner_mapscan_fail };
        static const char *const dnames[6] = { " calls=", " steps=", " eexist=",
                                               " this_steps=", " max_steps=", " fail=" };
        /* Адреса — чтобы назвать ВЛАДЕЛЬЦА занятой области, а не гадать о нём. Резерв стоит на
         * MACRUNNER_HB_RESERVE_TOP=0xc14000000, и попадание диапазона в него это и решает. */
        const ULONG64 hvals[5] = { (ULONG64)(ULONG_PTR)scan_start, (ULONG64)(ULONG_PTR)base,
                                   (ULONG64)(ULONG_PTR)end, (ULONG64)(ULONG_PTR)size,
                                   (ULONG64)(ULONG_PTR)(step < 0 ? -step : step) };
        static const char *const hnames[5] = { " start=0x", " base=0x", " end=0x",
                                               " size=0x", " step=0x" };
        const char tag[] = "macrunner-hb-mapscan:";
        unsigned int i, k;

        for (i = 0; i < sizeof(tag) - 1; i++) buf[pos++] = tag[i];
        for (k = 0; k < 6; k++)
        {
            char dec[24];
            unsigned int nd = 0;
            ULONG64 v = dvals[k];

            for (i = 0; dnames[k][i]; i++) buf[pos++] = dnames[k][i];
            do { dec[nd++] = (char)('0' + (v % 10)); v /= 10; } while (v);
            while (nd) buf[pos++] = dec[--nd];
        }
        for (k = 0; k < 5; k++)
        {
            char hex[20];
            unsigned int nh = 0;
            ULONG64 v = hvals[k];

            for (i = 0; hnames[k][i]; i++) buf[pos++] = hnames[k][i];
            do { hex[nh++] = "0123456789abcdef"[v & 0xf]; v >>= 4; } while (v);
            while (nh) buf[pos++] = hex[--nh];
        }
        if (step < 0) { buf[pos++] = ' '; buf[pos++] = 'd'; buf[pos++] = 'n'; }
        buf[pos++] = '\n';
        { ssize_t ignored = write( 2, buf, pos ); (void)ignored; }
    }
    return ret;
}

static void* try_map_free_area_impl( void *base, void *end, ptrdiff_t step,
                                     void *start, size_t size, int unix_prot )
{
    while (start && base <= start)
    {
        char *map_end;

        if (start >= end || (SIZE_T)((char *)end - (char *)start) < size) break;
        map_end = (char *)start + size;
        macrunner_mapscan_steps++;
        if (anon_mmap_tryfixed( start, size, unix_prot, 0 ) != MAP_FAILED) return start;
        if (errno == EEXIST) macrunner_mapscan_eexist++;
        TRACE( "Found free area is already mapped, start %p.\n", start );
        if (errno != EEXIST)
        {
#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
            if (errno == ENOMEM && (ULONG_PTR)start >= limit_4g &&
                (ULONG_PTR)map_end <= limit_4g + 128 * 1024 * 1024)
            {
                TRACE( "treating unmappable 4GB aperture as occupied, range %p-%p.\n", start, map_end );
                errno = EEXIST;
            }
            else
#endif
            {
                ERR( "mmap() error %s, range %p-%p, unix_prot %#x.\n",
                     strerror(errno), start, map_end, unix_prot );
                return NULL;
            }
        }
        if ((step > 0 && (char *)end - (char *)start < step) ||
            (step < 0 && (char *)start - (char *)base < -step) ||
            step == 0)
            break;
#ifdef __APPLE__
        if (step > 0 && macrunner_mapscan_skip_enabled())
        {
            char *skip_to = macrunner_mapscan_next_free( start, (size_t)step );

            if (skip_to > (char *)start + step)
            {
                macrunner_mapscan_skips++;
                macrunner_mapscan_skipped_bytes += (ULONG64)(skip_to - (char *)start);
                start = skip_to;
                continue;
            }
        }
#endif
        start = (char *)start + step;
    }

    return NULL;
}


/***********************************************************************
 *           map_free_area
 *
 * Find a free area between views inside the specified range and map it.
 * virtual_mutex must be held by caller.
 */
static void *map_free_area( void *base, void *end, size_t size, int top_down, int unix_prot, size_t align_mask )
{
    MR_VM_INC(map_free);
    struct wine_rb_entry *first = find_view_inside_range( &base, &end, top_down );
    ptrdiff_t step = top_down ? -(align_mask + 1) : (align_mask + 1);
    void *start;

    if (end <= base || (SIZE_T)((char *)end - (char *)base) < size) return NULL;

    if (top_down)
    {
        start = ROUND_ADDR( (char *)end - size, align_mask );
        if (start >= end || start < base) return NULL;

        while (first)
        {
            struct file_view *view = WINE_RB_ENTRY_VALUE( first, struct file_view, entry );
            char *view_end, *start_end;

            if (!get_view_limit( view, &view_end )) return NULL;
            if ((UINT_PTR)size > ~(UINT_PTR)0 - (UINT_PTR)start) return NULL;
            start_end = (char *)start + size;
            if ((start = try_map_free_area( view_end, start_end, step, start, size, unix_prot ))) break;
            if ((SIZE_T)((char *)view->base - (char *)base) < size) return NULL;
            start = ROUND_ADDR( (char *)view->base - size, align_mask );
            /* stop if remaining space is not large enough */
            if (!start || start >= end || start < base) return NULL;
            first = rb_prev( first );
        }
    }
    else
    {
        if (align_mask > ~(UINT_PTR)0 - (UINT_PTR)base) return NULL;
        start = ROUND_ADDR( (char *)base + align_mask, align_mask );
        if (!start || start >= end || (char *)end - (char *)start < size) return NULL;

        while (first)
        {
            struct file_view *view = WINE_RB_ENTRY_VALUE( first, struct file_view, entry );
            char *view_end;

            if (!get_view_limit( view, &view_end )) return NULL;
            if ((start = try_map_free_area( start, view->base, step,
                                            start, size, unix_prot ))) break;
            if (align_mask > ~(UINT_PTR)0 - (UINT_PTR)view_end) return NULL;
            start = ROUND_ADDR( view_end + align_mask, align_mask );
            /* stop if remaining space is not large enough */
            if (!start || start >= end || (char *)end - (char *)start < size) return NULL;
            first = rb_next( first );
        }
    }

    if (!first)
        start = try_map_free_area( base, end, step, start, size, unix_prot );

    if (!start)
        ERR( "couldn't map free area in range %p-%p, size %p\n", base, end, (void *)size );

    return start;
}


/***********************************************************************
 *           find_reserved_free_area
 *
 * Find a free area between views inside the specified range.
 * virtual_mutex must be held by caller.
 * The range must be inside a reserved area.
 */
static void *find_reserved_free_area( void *base, void *end, size_t size, int top_down, size_t align_mask )
{
    struct range_entry *range;
    void *start;

    if (end <= base || (SIZE_T)((char *)end - (char *)base) < size) return NULL;
    if (align_mask > ~(UINT_PTR)0 - (UINT_PTR)base) return NULL;
    base = ROUND_ADDR( (char *)base + align_mask, align_mask );
    end = (char *)ROUND_ADDR( (char *)end - size, align_mask ) + size;

    if (top_down)
    {
        start = (char *)end - size;
        range = free_ranges_lower_bound( start );
        assert(range != free_ranges_end && range->end >= start);

        if ((char *)range->end - (char *)start < size)
            start = (range->end > base && (SIZE_T)((char *)range->end - (char *)base) >= size)
                ? ROUND_ADDR( (char *)range->end - size, align_mask ) : NULL;
        do
        {
            if (!start || start >= end || start < base || (char *)end - (char *)start < size) return NULL;
            if (start < range->end && start >= range->base && (char *)range->end - (char *)start >= size) break;
            if (--range < free_ranges) return NULL;
            start = (range->end > base && (SIZE_T)((char *)range->end - (char *)base) >= size)
                ? ROUND_ADDR( (char *)range->end - size, align_mask ) : NULL;
        }
        while (1);
    }
    else
    {
        start = base;
        range = free_ranges_lower_bound( start );
        assert(range != free_ranges_end && range->end >= start);

        if (start < range->base)
            start = (align_mask <= ~(UINT_PTR)0 - (UINT_PTR)range->base)
                ? ROUND_ADDR( (char *)range->base + align_mask, align_mask ) : NULL;
        do
        {
            if (!start || start >= end || start < base || (char *)end - (char *)start < size) return NULL;
            if (start < range->end && start >= range->base && (char *)range->end - (char *)start >= size) break;
            if (++range == free_ranges_end) return NULL;
            start = (align_mask <= ~(UINT_PTR)0 - (UINT_PTR)range->base)
                ? ROUND_ADDR( (char *)range->base + align_mask, align_mask ) : NULL;
        }
        while (1);
    }
    return start;
}


/***********************************************************************
 *           remove_reserved_area
 *
 * Remove a reserved area from the list maintained by libwine.
 * virtual_mutex must be held by caller.
 */
static BOOL remove_reserved_area( void *addr, size_t size )
{
    struct file_view *view;
    size_t view_size;
    char *end;

    if (size > ~(SIZE_T)0 - (UINT_PTR)addr) return FALSE;
    end = (char *)addr + size;

    TRACE( "removing %p-%p\n", addr, end );
    if (!mmap_remove_reserved_area( addr, size )) return FALSE;

    /* unmap areas not covered by an existing view */
    WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
    {
        char *view_end, *view_host_end;

        if (!get_view_limit( view, &view_end )) return FALSE;
        if ((char *)view->base >= end) break;
        if (view_end <= (char *)addr) continue;
        if (view->base > addr) munmap( addr, (char *)view->base - (char *)addr );
        if (view_end > end) return TRUE;
        if (!round_size_checked( (UINT_PTR)view->base, view->size, host_page_mask, &view_size ) ||
            view_size > ~(SIZE_T)0 - (SIZE_T)view->base)
            return FALSE;
        view_host_end = (char *)view->base + view_size;
        size = end - view_host_end;
        addr = view_host_end;
    }
    munmap( addr, size );
    return TRUE;
}


/***********************************************************************
 *           unmap_area
 *
 * Unmap an area, or simply replace it by an empty mapping if it is
 * in a reserved area. virtual_mutex must be held by caller.
 */
static void unmap_area( void *start, size_t size )
{
    struct reserved_area *area;
    void *end;

    assert( !((UINT_PTR)start & host_page_mask) );
    if (!round_size_checked( 0, size, host_page_mask, &size ) ||
        size > ~(SIZE_T)0 - (SIZE_T)start)
    {
        ERR( "unmap range overflow base %p size %zx\n", start, size );
        return;
    }

    if (!(size = unmap_area_above_user_limit( start, size ))) return;

    end = (char *)start + size;

    LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
    {
        void *area_start = area->base;
        void *area_end = reserved_area_limit( area );

        if (area_start >= end) break;
        if (area_end <= start) continue;
        if (area_start > start)
        {
            munmap( start, (char *)area_start - (char *)start );
            start = area_start;
        }
        if (area_end >= end)
        {
#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
            mr_vm_restore_none( start, (char *)end - (char *)start );
#else
            anon_mmap_fixed( start, (char *)end - (char *)start, PROT_NONE, MAP_NORESERVE );
#endif
            return;
        }
#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
        mr_vm_restore_none( start, (char *)area_end - (char *)start );
#else
        anon_mmap_fixed( start, (char *)area_end - (char *)start, PROT_NONE, MAP_NORESERVE );
#endif
        start = area_end;
    }
    munmap( start, (char *)end - (char *)start );
}


/***********************************************************************
 *           alloc_view
 *
 * Allocate a new view. virtual_mutex must be held by caller.
 */
static struct file_view *alloc_view(void)
{
    if (next_free_view)
    {
        struct file_view *ret = next_free_view;
        next_free_view = *(struct file_view **)ret;
        return ret;
    }
    if (view_block_start == view_block_end)
    {
#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
        if (mr_vm_metadata_ready) { MR_VM_INC(metadata_view_exhausted); return NULL; }
#endif
        void *ptr = MR_VM_CALL( MR_VM_METADATA, anon_mmap_alloc( view_block_size, PROT_READ | PROT_WRITE ) );
        if (ptr == MAP_FAILED) return NULL;
        view_block_start = ptr;
        view_block_end = view_block_start + view_block_size / sizeof(*view_block_start);
    }
    return view_block_start++;
}


/***********************************************************************
 *           free_view
 *
 * Free memory for view structure. virtual_mutex must be held by caller.
 */
static void free_view( struct file_view *view )
{
    *(struct file_view **)view = next_free_view;
    next_free_view = view;
}


/***********************************************************************
 *           unregister_view
 *
 * Remove view from the tree and update free ranges. virtual_mutex must be held by caller.
 */
static void unregister_view( struct file_view *view )
{
    /* ★★★★★ MacRunner 2026-08-29 — ПРОВЕРКА ЦЕЛОСТНОСТИ ПЕРЕД УДАЛЕНИЕМ.
     *
     * Отчёт macOS о падении UnrealTournament (14:07:07):
     *   EXC_BAD_ACCESS / SIGILL  KERN_INVALID_ADDRESS at 0x30BDEE900
     *     ntdll.so+0xdd960  unregister_view
     *     ntdll.so+0xd2290  delete_view
     * SIGILL вместе с невалидным адресом означает, что выполнение ушло по битому
     * указателю: либо сам `view` не структура, либо узел `entry` уже не в дереве,
     * и `wine_rb_remove` идёт по мусорным связям.
     *
     * Отказ молчаливый: процесс просто исчезает, а игра до того ЧТО-ТО просила и
     * не получила. Печатаем состояние ДО удаления — тогда видно, что именно
     * пришло и от кого, вместо разбора по стеку постфактум.
     *
     * Проверка дешёвая (три сравнения) и не меняет поведения: при непройденном
     * инварианте мы всё равно продолжаем, чтобы не подменять отказ своим. */
    if ((ULONG_PTR)view < 0x10000 || ((ULONG_PTR)view & 7) ||
        !view->size || ((ULONG_PTR)view->base & page_mask))
    {
        static int said;
        if (said++ < 8)
            fprintf( stderr, "macrunner-view-повреждён: view=%p base=%p size=%zx protect=%x "
                 "вызывающий=%p\n",
                 view, view ? view->base : NULL, view ? view->size : 0,
                 view ? view->protect : 0, __builtin_return_address(0) );
    }

    if (mmap_is_in_reserved_area( view->base, view->size ))
        free_ranges_remove_view( view );
    wine_rb_remove( &views_tree, &view->entry );
}


/***********************************************************************
 *           delete_view
 *
 * Deletes a view. virtual_mutex must be held by caller.
 */
static void delete_view( struct file_view *view ) /* [in] View */
{
    /* ★★★★★ MacRunner 2026-09-01 — СНИМАЕМ ЛИ МЫ СОБСТВЕННЫЙ СТЕК.
     *
     * Падение UT99, которое видно на экране («quit unexpectedly»): отчёт macOS даёт
     * pc = unregister_view+4, то есть `stp x28, x27, [sp, #0x30]` — ПЕРВУЮ запись
     * пролога, и адрес отказа в точности равен sp+0x30. Прошлая теория «битый
     * указатель view» этим снимается: функция не дошла до своей первой настоящей
     * инструкции.
     *
     * Отчёт говорит прямо: `0x30bdee810 is not in any region` — стек не просто
     * переполнен, он ОТСУТСТВУЕТ. А порядок здесь такой: сперва unmap_area, потом
     * unregister_view. Если снимаемая область содержит текущий стек, то стек
     * исчезает ровно между этими двумя строками.
     *
     * Прибор молчит всегда и говорит ровно в этом случае. MESSAGE, а не ERR:
     * ERR гасится частью каналов при WINEDEBUG=-all, с которым идут все прогоны. */
    {
        ULONG_PTR sp = (ULONG_PTR)__builtin_frame_address( 0 );
        ULONG_PTR b = (ULONG_PTR)view->base;

        /* Отказ привязан к полноэкранному пути, а он занимает весь экран — гонять
         * его помногу нельзя. Поэтому докладываем и про КРУПНЫЕ области (>= 32 МБ):
         * они удаляются и в окне, и по ним видно, какие места вообще снимают такие
         * куски. Искомая область была 0x4010000 = 64 МБ + 64 КБ. */
        if (view->size >= 0x2000000 && !(sp >= b && sp < b + view->size))
            MESSAGE( "macrunner-hb-крупная-область: база=%p размер=%lx protect=%x звал=%p "
                     "sp=%lx pid=%d\n", view->base, (unsigned long)view->size,
                     view->protect, __builtin_return_address( 0 ),
                     (unsigned long)sp, (int)getpid() );

        if (sp >= b && sp < b + view->size)
        {
            TEB *teb = NtCurrentTeb();
            MESSAGE( "macrunner-hb-снимаем-свой-стек: view=%p база=%p размер=%lx sp=%lx "
                     "до_конца=%lx protect=%x звал=%p pid=%d tid=%04x\n",
                     view, view->base, (unsigned long)view->size, (unsigned long)sp,
                     (unsigned long)(b + view->size - sp), view->protect,
                     __builtin_return_address( 0 ), (int)getpid(),
                     teb ? (unsigned int)(ULONG_PTR)teb->ClientId.UniqueThread : 0 );
            MESSAGE( "macrunner-hb-снимаем-свой-стек: стек_потока base=%p limit=%p dealloc=%p\n",
                     teb ? teb->Tib.StackBase : NULL, teb ? teb->Tib.StackLimit : NULL,
                     teb ? teb->DeallocationStack : NULL );
        }
    }
    /* ★★★★★★ MacRunner 04.09.2026 — ОБЛАСТЬ С НАШИМ СТЕКОМ НЕ СНИМАЕТСЯ.
     *
     * Замер: ВОСЕМЬ отчётов macOS о падении Diablo из восьми дают один и тот же
     * кадр — pc = unregister_view+4, команда `stp x28,x27,[sp,#0x30]`, адрес
     * отказа = sp+0x30, ESR «byte write Translation fault», а vmRegionInfo
     * говорит «is not in any region, GAP OF 0x4010000 BYTES». Адреса сверены с
     * бинарём побайтно: delete_view и unregister_view лежат ровно там.
     *
     * То есть между unmap_area (строка ниже) и unregister_view СТЕК ИСЧЕЗАЕТ, и
     * пролог следующей функции пишет в снятую память. Сама область при этом
     * законна (protect=0x23) — беда в том, ЧТО в ней лежит.
     *
     * ПЕРЕСТАНОВКА СТРОК НЕ ПОМОЖЕТ: даже сняв область последней, delete_view не
     * сможет ВЕРНУТЬСЯ — возвращаться будет некуда. Поэтому область остаётся
     * отображённой (утечка адресного пространства) и мы громко докладываем:
     * процесс живёт, а причина видна по имени вызывающего.
     *
     * Гейта нет намеренно: ветка исполняется только там, где сейчас
     * гарантированно гибнет процесс. */
    {
        ULONG_PTR mr_sp = (ULONG_PTR)__builtin_frame_address( 0 );
        ULONG_PTR mr_b  = (ULONG_PTR)view->base;

        if (mr_sp >= mr_b && mr_sp < mr_b + view->size)
        {
            MESSAGE( "macrunner-отказ-снять-свой-стек: view=%p база=%p размер=%lx sp=%lx "
                     "звал=%p teb_base=%p teb_limit=%p dealloc=%p\n",
                     view, view->base, (unsigned long)view->size, (unsigned long)mr_sp,
                     __builtin_return_address( 0 ), NtCurrentTeb()->Tib.StackBase,
                     NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->DeallocationStack );
            return;                     /* ни unmap, ни правки дерева видов */
        }
    }
    if (!(view->protect & VPROT_SYSTEM)) unmap_area( view->base, view->size );
    set_page_vprot( view->base, view->size, 0 );
    if (view->protect & VPROT_ARM64EC) clear_arm64ec_range( view->base, view->size );
    unregister_view( view );
    free_view( view );
}


/***********************************************************************
 *           register_view
 *
 * Add view to the tree and update free ranges. virtual_mutex must be held by caller.
 */
static void register_view( struct file_view *view )
{
    wine_rb_put( &views_tree, view->base, &view->entry );
    if (mmap_is_in_reserved_area( view->base, view->size ))
        free_ranges_insert_view( view );
}


/***********************************************************************
 *           create_view
 *
 * Create a view. virtual_mutex must be held by caller.
 */
static NTSTATUS create_view( struct file_view **view_ret, void *base, size_t size, unsigned int vprot )
{
    struct file_view *view;
    char *end;

    assert( !((UINT_PTR)base & host_page_mask) );
    assert( !(size & page_mask) );

    if (size > ~(SIZE_T)0 - (UINT_PTR)base) return STATUS_CONFLICTING_ADDRESSES;
    end = (char *)base + size;

    /* Check for overlapping views. This can happen if the previous view
     * was a system view that got unmapped behind our back. In that case
     * we recover by simply deleting it. */

    while ((view = find_view_range( base, size )))
    {
        char *view_end;

        if (!get_view_limit( view, &view_end )) return STATUS_CONFLICTING_ADDRESSES;
        TRACE( "overlapping view %p-%p for %p-%p\n",
               view->base, view_end, base, end );
        /* MacRunner 2026-08-11 — безусловный зонд: утверждение ниже валит ступень 1 Diablo
         * (abort, 0x80000101), а TRACE выше до наших журналов не доходит. Печатаем ОБА
         * представления и права старого: это и есть ответ на вопрос, кто кладёт область
         * поверх уже учтённой. Первые 8 раз, чтобы не залить журнал. */
        {
            static int probe_n;
            if (probe_n < 8)
            {
                probe_n++;
                fprintf( stderr, "macrunner-createview-overlap: старое=%p-%p prot=%08x система=%d "
                                 "новое=%p-%p size=%08lx\n",
                         view->base, view_end, (unsigned)view->protect,
                         (view->protect & VPROT_SYSTEM) ? 1 : 0,
                         base, end, (unsigned long)size );
            }
        }
        assert( view->protect & VPROT_SYSTEM );
        delete_view( view );
    }

    if (!alloc_pages_vprot( base, size )) return STATUS_NO_MEMORY;

    /* Create the view structure */

    if (!(view = alloc_view()))
    {
        FIXME( "out of memory for %p-%p\n", base, end );
        return STATUS_NO_MEMORY;
    }

    view->base    = base;
    view->size    = size;
    view->protect = vprot;
    if (use_kernel_writewatch) vprot &= ~VPROT_WRITEWATCH;
    set_page_vprot( base, size, vprot );

    register_view( view );
    kernel_writewatch_register_range( view, view->base, view->size );

    *view_ret = view;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           get_win32_prot
 *
 * Convert page protections to Win32 flags.
 */
static DWORD get_win32_prot( BYTE vprot, unsigned int map_prot )
{
    DWORD ret;

    if ((vprot & (VPROT_COPIED | VPROT_WRITECOPY)) == (VPROT_COPIED | VPROT_WRITECOPY))
        vprot = (vprot & ~VPROT_WRITECOPY) | VPROT_WRITE;
    ret = VIRTUAL_Win32Flags[vprot & 0x0f];
    if (vprot & VPROT_GUARD) ret |= PAGE_GUARD;
    if (map_prot & SEC_NOCACHE) ret |= PAGE_NOCACHE;
    return ret;
}


/***********************************************************************
 *           get_vprot_flags
 *
 * Build page protections from Win32 flags.
 */
static NTSTATUS get_vprot_flags( DWORD protect, unsigned int *vprot, BOOL image )
{
    switch(protect & 0xff)
    {
    case PAGE_READONLY:
        *vprot = VPROT_READ;
        break;
    case PAGE_READWRITE:
        if (image)
            *vprot = VPROT_READ | VPROT_WRITECOPY;
        else
            *vprot = VPROT_READ | VPROT_WRITE;
        break;
    case PAGE_WRITECOPY:
        *vprot = VPROT_READ | VPROT_WRITECOPY;
        break;
    case PAGE_EXECUTE:
        *vprot = VPROT_EXEC;
        break;
    case PAGE_EXECUTE_READ:
        *vprot = VPROT_EXEC | VPROT_READ;
        break;
    case PAGE_EXECUTE_READWRITE:
        if (image)
            *vprot = VPROT_EXEC | VPROT_READ | VPROT_WRITECOPY;
        else
            *vprot = VPROT_EXEC | VPROT_READ | VPROT_WRITE;
        break;
    case PAGE_EXECUTE_WRITECOPY:
        *vprot = VPROT_EXEC | VPROT_READ | VPROT_WRITECOPY;
        break;
    case PAGE_NOACCESS:
        *vprot = 0;
        break;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }
    if (protect & PAGE_GUARD) *vprot |= VPROT_GUARD;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           mprotect_exec
 *
 * Wrapper for mprotect, adds PROT_EXEC if forced by force_exec_prot
 */
static BOOL macrunner_hb_trace_host_exec(void);
static BOOL macrunner_hb_range_overlaps_x64_guest( const void *base, size_t size );
static BOOL macrunner_hb_x64_guest_fault_handlers_are_ready;
/* MacRunner 2026-06-21: invalidate the HB special_read/write region cache on guest VM changes. */
extern void macrunner_hb_vm_changed( void );

/* MacRunner 2026-08-05 — RWX на Apple Silicon недостижим, а объединение его требует.
 *
 * Хостовая страница здесь 16 КБ, страница Windows 4 КБ, и `mprotect_range` применяет
 * ОБЪЕДИНЕНИЕ прав всех четырёх подстраниц.  Когда таблица импорта делит хостовую
 * страницу с кодом, запрос «дай записать» превращается в READ|WRITE|EXEC.  Замерено:
 *
 *     vprot4k =0x29  unix4k =0x3   (просили чтение+запись)
 *     vprot16k=0x2d  unix16k=0x7   (ушло в mprotect: чтение+запись+исполнение)
 *     actual  =0x5                 (ядро оставило чтение+исполнение)
 *
 * Apple Silicon RWX без MAP_JIT не выдаёт, поэтому запись не появляется, а
 * NtProtectVirtualMemory при этом рапортует успех.  Дальше первая же запись падает
 * SIGBUS, обработчик права не поднимает, и инструкция повторяется вечно:
 * 254 635 651 отказ за прогон, 241 тыс/с, 40 % времени процесса.
 *
 * Лечение: не отдавать RWX как единственную попытку.  Пробуем как просили, а при
 * отказе снимаем EXEC — запись важнее, потому что исполнение с этой хостовой страницы
 * возобновится при следующей смене прав, а несостоявшаяся запись вешает процесс
 * Гейт MACRUNNER_HB_RWX_FALLBACK СНЯТ 02.09.2026: правка безусловна,
 * выключенная ветка возвращала известный дефект (scripts/гейты.py). */
static unsigned int macrunner_hb_rwx_fallback_hits;

/* ★★★ MacRunner 07.09.2026, лейн FEX-N2 — ОБЛАСТЬ MAP_JIT ПРИНИМАЕТ mprotect ОДИН РАЗ.
 *
 * Замерено пробой reports/FEX-N2-lab/jit_mprotect2.c на этой машине:
 *
 *     mmap(MAP_JIT, RW)          -> prot=3 max=7
 *     mprotect RWX  #1           -> rc=0        права стали 7
 *     mprotect RX                -> rc=-1 EACCES
 *     mprotect RWX  #2           -> rc=-1 EACCES
 *     2000 подряд mprotect RWX   -> 2000 отказов из 2000
 *     при этом вызов кода        -> 42, то есть область ЖИВА и исполняется
 *
 * То есть модель Wine «поменял права -> вернул protect_old» к области MAP_JIT
 * неприменима В ПРИНЦИПЕ: после первого применения EXEC ядро отказывает любому
 * следующему mprotect. Запись и исполнение там разделяет НЕ mprotect, а потоковый
 * pthread_jit_write_protect_np.
 *
 * Поэтому для таких представлений mprotect не зовём вовсе и рапортуем успех: права
 * уже RWX от рождения (см. map_view), менять их нечем и не нужно.
 *
 * ГРАНИЦА: это верно только для представлений, которые МЫ отобразили с MAP_JIT
 * (VPROT_MACRUNNER_JIT). Обычные представления Wine идут прежним путём. */
static unsigned int macrunner_jit_mprotect_skips;

static inline int mprotect_exec( void *base, size_t size, int unix_prot )
{
    struct file_view *view = find_view( base, size );

    BOOL macrunner_x64_guest = (view && (view->protect & VPROT_MACRUNNER_X64_GUEST)) ||
                               macrunner_hb_range_overlaps_x64_guest( base, size );
    int requested_prot = unix_prot;
    int rc;

#if defined(__APPLE__) && defined(__aarch64__)
    if (view && (view->protect & VPROT_MACRUNNER_JIT))
    {
        unsigned int n = __atomic_add_fetch( &macrunner_jit_mprotect_skips, 1, __ATOMIC_RELAXED );

        if (n <= 8 || !(n & 0xffff))
        {
            fprintf( stderr, "macrunner-fex-jit-mprotect-skip: base=%p size=%zx unix_prot=%#x n=%u\n",
                     base, size, unix_prot, n );
            fflush( stderr );
        }
        return 0;
    }
#endif

    if (macrunner_x64_guest) unix_prot &= ~PROT_EXEC;
    else if (view && (view->protect & VPROT_MACRUNNER_I386_GUEST)) unix_prot &= ~PROT_EXEC;

#if defined(__APPLE__) && defined(__aarch64__)
    /* Здесь и живёт лечение, описанное выше: запись важнее исполнения.
     *
     * Откат «попробовать RWX, при отказе снять EXEC» тут НЕ годится — замерено, что
     * `mprotect` в этом случае возвращает 0 и просто не применяет запись, так что
     * ошибки, на которую можно было бы откатиться, не бывает.  Значит EXEC снимаем
     * сразу, как только видим сочетание записи с исполнением на хостовой странице,
     * которая крупнее страницы Windows.
     *
     * Право исполнения не теряется: вызывающий закрывает скобку обратным
     * `NtProtectVirtualMemory( ..., protect_old )`, и EXEC возвращается вместе с
     * прежними правами.  А вот несостоявшаяся запись вешает процесс навсегда. */
    if (host_page_size > page_size &&
        (unix_prot & PROT_WRITE) && (unix_prot & PROT_EXEC))
    {
        unsigned int n = __atomic_add_fetch( &macrunner_hb_rwx_fallback_hits, 1, __ATOMIC_RELAXED );

        unix_prot &= ~PROT_EXEC;
        if (n <= 8 || !(n & 0x3ff))
        {
            fprintf( stderr, "macrunner-hb-rwx-fallback: base=%p size=%zx requested=%#x final=%#x n=%u\n",
                     base, size, requested_prot, unix_prot, n );
            fflush( stderr );
        }
    }
#endif

    if (macrunner_hb_trace_host_exec() && (macrunner_x64_guest || (requested_prot & PROT_EXEC)))
        fprintf( stderr, "macrunner-host-exec-mprotect: pid=%d base=%p size=%zx requested=%#x final=%#x "
                 "view=%p protect=%#x x64_guest=%d signal_ready=%d\n",
                 getpid(), base, size, requested_prot, unix_prot, view, view ? view->protect : 0,
                 macrunner_x64_guest, macrunner_hb_x64_guest_fault_handlers_are_ready );

    if (!macrunner_x64_guest && force_exec_prot && (unix_prot & PROT_READ) && !(unix_prot & PROT_EXEC))
    {
        TRACE( "forcing exec permission on %p-%p\n", base, (char *)base + size - 1 );
        if (!mprotect( base, size, unix_prot | PROT_EXEC )) return 0;
        /* exec + write may legitimately fail, in that case fall back to write only */
        if (!(unix_prot & PROT_WRITE)) return -1;
    }

    rc = mprotect( base, size, unix_prot );

    if (macrunner_hb_trace_host_exec() && (macrunner_x64_guest || (requested_prot & PROT_EXEC)))
        fprintf( stderr, "macrunner-host-exec-mprotect-result: pid=%d base=%p size=%zx requested=%#x "
                 "final=%#x rc=%d errno=%d (%s) x64_guest=%d\n",
                 getpid(), base, size, requested_prot, unix_prot, rc, rc ? errno : 0,
                 rc ? strerror(errno) : "ok", macrunner_x64_guest );

#if defined(__APPLE__) && defined(__aarch64__)
    if (!rc && macrunner_x64_guest && macrunner_hb_trace_host_exec())
    {
        mach_vm_address_t addr = (mach_vm_address_t)(uintptr_t)base;
        mach_vm_size_t vm_size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        kern_return_t kr;

        kr = mach_vm_region( mach_task_self(), &addr, &vm_size, VM_REGION_BASIC_INFO_64,
                             (vm_region_info_t)&info, &count, &object );
        fprintf( stderr, "macrunner-host-exec-mprotect-vm: pid=%d base=%p size=%zx vm_base=%p "
                 "vm_size=%llx kr=%d prot=%#x max=%#x requested=%#x final=%#x\n",
                 getpid(), base, size, (void *)(uintptr_t)addr, (unsigned long long)vm_size,
                 kr, kr == KERN_SUCCESS ? info.protection : 0,
                 kr == KERN_SUCCESS ? info.max_protection : 0, requested_prot, unix_prot );
        if (kr == KERN_SUCCESS && (info.protection & VM_PROT_EXECUTE))
            fprintf( stderr, "macrunner-host-exec-still-exec: range %p-%p requested %#x final %#x vm_base %p "
                 "vm_size %#llx prot %#x max %#x\n",
                 base, (char *)base + size, requested_prot, unix_prot, (void *)(uintptr_t)addr,
                 (unsigned long long)vm_size, info.protection, info.max_protection );
    }
#endif

    if (rc)
    {
#if defined(__APPLE__) && defined(__aarch64__)
        int err = errno;

        if ((unix_prot & PROT_EXEC) && (unix_prot & PROT_WRITE) &&
            !mprotect( base, size, unix_prot & ~PROT_WRITE ))
            return 0;
        if ((unix_prot & PROT_EXEC) || macrunner_x64_guest)
            ERR( "mprotect_exec failed %s, range %p-%p, requested %#x final %#x x64_guest=%d\n",
                 strerror(err), base, (char *)base + size, requested_prot, unix_prot,
                 macrunner_x64_guest );
#endif
        return -1;
    }
    return 0;
}


/***********************************************************************
 *           ЛОВУШКА ЗАПИСИ ПО КОДУ  (MacRunner 08.09.2026, лейн ЛОВУШКА)
 *
 * ИЗМЕРЕНО (tools/paket4/bin/p4smc.x64.exe, рука fex, 5 прогонов из 5):
 *     гость объявляет 4 КБ как PAGE_EXECUTE_READ, соседние 12 КБ остаются
 *     PAGE_READWRITE — всё внутри ОДНОЙ хозяйской страницы 16 КБ.
 *         CODE_WRITE=0x0  BYTES_LANDED=1  GOT=0x00111111  OUTCOME=3 (STALE)
 *     То есть запись в страницу кода проходит БЕЗ отказа, байты ложатся, а вызов
 *     возвращает прежний перевод. Отказ ТИХИЙ: ни ошибки, ни кода возврата.
 *     Эталон CrossOver и наш HB на i386 в том же образце дают 0xc0000005.
 *
 * ПРИЧИНА (по исходникам, virtual.c: get_host_page_vprot): права четырёх
 * подстраниц складываются ПО ИЛИ, поэтому записываемый сосед делает записываемой
 * ВСЮ хозяйскую страницу — и ловушки записи по коду не существует вовсе.
 *
 * ПОЧЕМУ НЕ «ПРОСТО ПОСТАВИТЬ ПРАВА НА 4 КБ». Измерено прямой пробой на этой
 * машине (mmap 16 КБ + mprotect на первые 4 КБ, три вида выделения):
 *         mprotect(4K, r-x) -> rc=0, а mach_vm_region показывает
 *         base=<та же> size=0x4000 prot=0x5 — права легли на ВСЕ 16 КБ.
 * Ядро округляет диапазон ВВЕРХ до своей страницы; подстраничной разметки у
 * процесса без права подписи НЕТ (у области MAP_JIT mprotect вовсе даёт EACCES).
 * Значит единственный доступный способ завести ловушку — сделать хозяйскую
 * страницу НЕзаписываемой и разбирать отказ по правам ИМЕННО 4-КБ страницы.
 *
 * ГРАНИЦА, сознательно узкая: снимаем запись ТОЛЬКО с тех хозяйских страниц, где
 * есть подстраница КОДА без права записи рядом с записываемой подстраницей. Общий
 * случай «смешанная запись» не трогаем — это меняло бы поведение всего Wine и
 * возвращало бы риск зависания, ради которого написана ветвь rwx-fallback выше.
 * Когда права внутри хозяйской страницы ОДНОРОДНЫ, эта правка не делает ничего.
 *
 * ЗАЩИТА ОТ ЗАВИСАНИЯ (та самая, ради которой писан rwx-fallback): обе дороги
 * отказа завершаются продвижением, ни одна не повторяет команду вечно —
 *   4-КБ страница БЕЗ права записи -> STATUS_ACCESS_VIOLATION гостю;
 *   4-КБ страница С правом записи   -> «CW Hack 24945» снимает EXEC и отдаёт
 *                                      странице запись, команда проходит.
 *
 * ★★★ ГЕЙТ MACRUNNER_HB_CODE_WRITE_TRAP ПО УМОЛЧАНИЮ **ВЫКЛЮЧЕН**, И ВОТ ЧИСЛО.
 *
 * Правило проекта — «выключенный гейт есть главная статья потерь» — здесь уступает
 * правилу «не менять тихий отказ на висящий процесс». Ловушка РАБОТАЕТ (доказано
 * ниже), но выданный ею c0000005 уводит FEX в бесконечную качку W^X на ЕГО ЖЕ
 * странице JIT, и прогон встаёт:
 *
 *     гейт=1: arm=3 av=1 pass=35 304 448 отказов на ОДНОМ адресе 0x10f1d4c4c
 *             (страница 0x10f1d4000, gvprot=0x27 = RWX), alarm 90 с, вывода ноль
 *     гейт=0: arm=0 av=0 pass=0, OUTCOME=3, RC=107 — прогон доходит до конца
 *     Тот же двоичный, разделение полное, различает ТОЛЬКО этот гейт.
 *
 * Качка НЕ наша и НЕ на нашей странице: страница RWX, хозяин RWX не даёт, поэтому
 * ветвь rwx-fallback снимает EXEC на записи, а «CW Hack 25719» возвращает его на
 * исполнении — и так по кругу. Наш c0000005 лишь ВВОДИТ FEX в этот путь.
 *
 * ЧТО СНИМЕТ СТЕНУ (замер, а не рассуждение): страница JIT у FEX должна жить как
 * MAP_JIT (VPROT_MACRUNNER_JIT) с pthread_jit_write_protect_np — тогда mprotect по
 * ней не зовётся вовсе (см. ветвь VPROT_MACRUNNER_JIT в mprotect_exec выше), качки
 * нет, и c0000005 доходит до ResetToConsistentState. Признак снятия: прогон с
 * гейтом=1, где pass остаётся малым, а p4smc даёт OUTCOME=2 / GOT=0x00222222.
 * Крюки для этого уже есть — места 6 и 7 клея FEX (markjit / jitexec).
 */
static unsigned long long macrunner_code_write_trap_armed;
static unsigned long long macrunner_code_write_trap_av;
static unsigned long long macrunner_code_write_trap_pass;

/* 0 — выключено (умолчание); 1 — ловушка взводится; 2 — ТОЛЬКО СЧЁТ.
 *
 * Режим 2 заведён ради долга №46: «сколько раз статья встречается в настоящей
 * нагрузке» нельзя было назвать, потому что печать имела потолок «первые 8».
 * Здесь счётчик БЕЗ потолка, а прав он не меняет вовсе — значит режим 2 безопасен
 * для любого прогона, включая игровой, и даёт число без риска зависания. */
static int macrunner_code_write_trap_mode(void)
{
#if defined(__APPLE__) && defined(__aarch64__)
    static int mode = -1;
    const char *env;

    if (mode != -1) return mode;
    env = getenv( "MACRUNNER_HB_CODE_WRITE_TRAP" );
    if (!env || !env[0]) mode = 0;          /* умолчание 0 — обоснование числом выше */
    else if (env[0] == '2') mode = 2;
    else mode = (env[0] != '0');
    return mode;
#else
    return 0;
#endif
}

#if defined(__APPLE__) && defined(__aarch64__)
/* БЕЗЛИМИТНЫЙ счётчик (долг №46: печать с потолком «первые 8» — это потолок, а не
 * число событий). Итог печатается один раз при выгрузке, счётчики без потолка. */
static void __attribute__((destructor)) macrunner_code_write_trap_dump(void)
{
    unsigned long long a = __atomic_load_n( &macrunner_code_write_trap_armed, __ATOMIC_RELAXED );
    unsigned long long v = __atomic_load_n( &macrunner_code_write_trap_av, __ATOMIC_RELAXED );
    unsigned long long p = __atomic_load_n( &macrunner_code_write_trap_pass, __ATOMIC_RELAXED );

    if (a || v || p)
    {
        fprintf( stderr, "macrunner-code-write-trap-total: pid=%d armed=%llu av=%llu pass=%llu\n",
                 getpid(), a, v, p );
        fflush( stderr );
    }
}
#endif

/* Какие представления имеют право на ловушку.
 *
 * ИЗМЕРЕНО 08.09: без этого отбора ловушка взводилась 115 раз за процесс, в том
 * числе на образах Wine (страницы 0x6fffff……, uni=0x2d), и гость вставал намертво.
 * С отбором остаётся ровно частная память гостя — тот случай, ради которого правка.
 *
 * SEC_IMAGE исключены сознательно: у образов смена прав идёт через загрузчик, то
 * есть «по уведомлению», и этот путь исправен и без нас (b5.x64 = 107).
 * VPROT_SYSTEM — чужие отображения, не наши. */
static BOOL macrunner_code_write_trap_view_ok( const struct file_view *view )
{
#if defined(__APPLE__) && defined(__aarch64__)
    return view && !(view->protect & (SEC_IMAGE | VPROT_SYSTEM));
#else
    return FALSE;
#endif
}


/***********************************************************************
 *           get_host_page_unix_prot
 *
 * Права хозяйской страницы: объединение подстраниц (как get_host_page_vprot) и
 * решение о ловушке записи — ОДНИМ проходом. Отдельная функция удвоила бы цену:
 * get_host_page_vprot делает ровно такой же обход подстраниц.
 */
static int get_host_page_unix_prot( const void *addr, BYTE set, BYTE clear, BOOL may_trap )
{
    char *page = ROUND_ADDR( addr, host_page_mask );
    size_t i;
    BYTE uni = 0;
    int prot;
#if defined(__APPLE__) && defined(__aarch64__)
    BOOL ro_exec = FALSE, writable = FALSE;
#endif

    for (i = 0; i < host_page_size; i += page_size)
    {
        BYTE v = (get_page_vprot( page + i ) & ~clear) | set;

        uni |= v;
#if defined(__APPLE__) && defined(__aarch64__)
        if (get_unix_prot( v ) & PROT_WRITE) writable = TRUE;
        else if ((v & VPROT_COMMITTED) && (v & VPROT_EXEC) && !(v & VPROT_GUARD)) ro_exec = TRUE;
#endif
    }
    prot = get_unix_prot( uni );

#if defined(__APPLE__) && defined(__aarch64__)
    if (may_trap && host_page_size > page_size && ro_exec && writable && (prot & PROT_WRITE) &&
        macrunner_code_write_trap_mode())
    {
        unsigned long long n = __atomic_add_fetch( &macrunner_code_write_trap_armed, 1,
                                                   __ATOMIC_RELAXED );

        if (macrunner_code_write_trap_mode() == 1) prot &= ~PROT_WRITE;   /* 2 = только счёт */
        if (n <= 8 || !(n & 0x3ff))
        {
            fprintf( stderr, "macrunner-code-write-trap-arm: page=%p uni=%#x prot=%#x mode=%d n=%llu\n",
                     page, uni, prot, macrunner_code_write_trap_mode(), n );
            fflush( stderr );
        }
    }
#endif
    return prot;
}


/***********************************************************************
 *           mprotect_range
 *
 * Call mprotect on a page range, applying the protections from the per-page byte.
 */
static int mprotect_range( void *base, size_t size, BYTE set, BYTE clear )
{
    size_t i, count;
    char *addr = ROUND_ADDR( base, host_page_mask );
    int prot, next;
    /* Ловушку заводим ТОЛЬКО на частной памяти гостя (VirtualAlloc), НЕ на образах.
     * Замерено 08.09: без этого условия ловушка взводилась на 32 хозяйских страницах
     * образов самого Wine (uni=0x2d, код рядом с WRITECOPY), процесс-гость вставал
     * намертво — alarm 90 с, вывода ноль. У образов права меняет загрузчик, и там
     * действует путь «по уведомлению», который и без нас исправен (b5.x64 = 107). */
    BOOL may_trap = macrunner_code_write_trap_view_ok( find_view( base, size ) );

    if (!round_size_checked( (UINT_PTR)base, size, host_page_mask, &size )) return -1;

    prot = get_host_page_unix_prot( addr, set, clear, may_trap );
    for (count = i = 1; i < size / host_page_size; i++, count++)
    {
        next = get_host_page_unix_prot( addr + count * host_page_size, set, clear, may_trap );
        if (next == prot) continue;
        if (mprotect_exec( addr, count * host_page_size, prot )) return -1;
        addr += count * host_page_size;
        prot = next;
        count = 0;
    }
    return mprotect_exec( addr, count * host_page_size, prot );
}


/***********************************************************************
 *           set_vprot
 *
 * Change the protection of a range of pages.
 */
static BOOL set_vprot( struct file_view *view, void *base, size_t size, BYTE vprot )
{
    if (!use_kernel_writewatch && view->protect & VPROT_WRITEWATCH)
    {
        /* each page may need different protections depending on write watch flag */
        set_page_vprot_bits( base, size, vprot & ~VPROT_WRITEWATCH, ~vprot & ~VPROT_WRITEWATCH );
    }
    else
    {
        if (enable_write_exceptions && is_vprot_exec_write( vprot )) vprot |= VPROT_WRITEWATCH;
        else if (use_kernel_writewatch && view->protect & VPROT_WRITEWATCH) vprot &= ~VPROT_WRITEWATCH;
        set_page_vprot( base, size, vprot );
    }
    {
        BOOL ok = !mprotect_range( base, size, 0, 0 );
        /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1087 — ЗОНД СТОРОЖЕВОЙ СТРАНИЦЫ.
         *
         * Три итерации подряд я чинил дорогу отказа по догадкам и трижды мимо (1084-1086).
         * Вопрос, который надо было задать первым, отвечается ОДНИМ числом: какие права у
         * хостовой страницы ПОСЛЕ того, как сторож взведён. `PROT_NONE` -> виноват путь
         * отказа; что-то другое -> сторож не взводится вовсе, и искать надо здесь.
         * Печать безусловная, только для страниц со сторожем, первые 8 раз. */
#if defined(__APPLE__) && defined(__aarch64__)
        if (vprot & VPROT_GUARD)
        {
            static unsigned guard_probe_n;
            unsigned n = ++guard_probe_n;
            if (n <= 8)
            {
                mach_vm_address_t ga = (mach_vm_address_t)(uintptr_t)base;
                mach_vm_size_t gsz = 0;
                vm_region_basic_info_data_64_t gi;
                mach_msg_type_number_t gc = VM_REGION_BASIC_INFO_COUNT_64;
                mach_port_t go = MACH_PORT_NULL;
                kern_return_t gkr = mach_vm_region( mach_task_self(), &ga, &gsz,
                                                    VM_REGION_BASIC_INFO_64,
                                                    (vm_region_info_t)&gi, &gc, &go );
                if (go != MACH_PORT_NULL) mach_port_deallocate( mach_task_self(), go );
                fprintf( stderr, "macrunner-guard-probe: pid=%d n=%u base=%p size=%zx vprot=%#x "
                         "unix_prot=%#x mprotect_ok=%d kr=%d actual=%#x max=%#x\n",
                         getpid(), n, base, size, vprot, get_unix_prot( vprot ), ok, (int)gkr,
                         gkr == KERN_SUCCESS ? (unsigned)gi.protection : 0,
                         gkr == KERN_SUCCESS ? (unsigned)gi.max_protection : 0 );
                fflush( stderr );
            }
        }
#endif
        /* MacRunner 2026-08-05 — ЗАПРОСИЛИ ЗАПИСЬ, А ПОЛУЧИЛИ ЛИ?
         *
         * Замерено: `NtProtectVirtualMemory(PAGE_READWRITE)` возвращает успех, а
         * следующая же запись падает, и `mach_vm_region` в тот момент показывает
         * prot=5 (R-X) при max=7.  Ровно один отказ на каждое открытие скобки —
         * 254 млн за прогон, 40 % времени процесса.
         *
         * Причин может быть две, и различить их можно только здесь, на слое, где
         * права реально применяются: либо `PROT_WRITE` вырезан у нас
         * (`get_unix_prot` снимает его для страниц с VPROT_WRITEWATCH, строка выше
         * в этом же файле), либо `mprotect` соврал.  Печатаем ЗАПРОШЕННОЕ и
         * ФАКТИЧЕСКОЕ рядом — тогда виновата будет названа сторона, а не версия.
         *
         * Печатаем только расхождения и только первые 32: совпадения не шумят. */
#if defined(__APPLE__) && defined(__aarch64__)
        if (ok && (get_unix_prot( get_page_vprot( base ) ) & PROT_WRITE))
        {
            mach_vm_address_t a = (mach_vm_address_t)(uintptr_t)base;
            mach_vm_size_t sz = 0;
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj = MACH_PORT_NULL;

            if (!mach_vm_region( mach_task_self(), &a, &sz, VM_REGION_BASIC_INFO_64,
                                 (vm_region_info_t)&info, &cnt, &obj ) &&
                !(info.protection & VM_PROT_WRITE))
            {
                static unsigned mismatch_n;
                if (mismatch_n++ < 32)
                {
                    /* MacRunner 2026-08-05 — печатаем ЧЕТЫРЕ величины, а не две.
                     *
                     * Раньше печатались права 4 КБ-страницы, а `mprotect_range` работает
                     * ХОСТОВЫМИ страницами (на Apple Silicon 16 КБ) и берёт ОБЪЕДИНЕНИЕ
                     * прав всех четырёх подстраниц.  Если рядом с таблицей импорта лежит
                     * код, объединение получает EXEC, и запрос превращается в RWX, которого
                     * Apple Silicon без MAP_JIT не даёт.  Без печати обоих значений отличить
                     * «мы просили не то» от «ядро не дало» невозможно. */
                    void *hpage = ROUND_ADDR( base, host_page_mask );
                    fprintf( stderr, "macrunner-hb-prot-mismatch: base=%p size=%zx "
                             "vprot4k=%#x unix4k=%#x  hpage=%p vprot16k=%#x unix16k=%#x  "
                             "actual=%#x max=%#x n=%u\n",
                             base, size, get_page_vprot( base ),
                             get_unix_prot( get_page_vprot( base ) ),
                             hpage, get_host_page_vprot( hpage ),
                             get_unix_prot( get_host_page_vprot( hpage ) ),
                             info.protection, info.max_protection, mismatch_n );
                    fflush( stderr );
                }
            }
            if (obj != MACH_PORT_NULL) mach_port_deallocate( mach_task_self(), obj );
        }
#endif
        return ok;
    }
}


/***********************************************************************
 *           set_protection
 *
 * Set page protections on a range of pages
 */
static NTSTATUS set_protection( struct file_view *view, void *base, SIZE_T size, ULONG protect )
{
    unsigned int vprot;
    NTSTATUS status;

    if ((status = get_vprot_flags( protect, &vprot, view->protect & SEC_IMAGE ))) return status;
    if (is_view_valloc( view ))
    {
        if (vprot & VPROT_WRITECOPY) return STATUS_INVALID_PAGE_PROTECTION;
    }
    else
    {
        BYTE access = vprot & (VPROT_READ | VPROT_WRITE | VPROT_EXEC);
        if ((view->protect & access) != access) return STATUS_INVALID_PAGE_PROTECTION;
    }

    if (!set_vprot( view, base, size, vprot | VPROT_COMMITTED )) return STATUS_ACCESS_DENIED;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           commit_arm64ec_map
 *
 * Make sure that the pages corresponding to the address range of the view
 * are committed in the ARM64EC code map.
 */
static void commit_arm64ec_map( struct file_view *view )
{
    size_t start = ((size_t)view->base >> page_shift) / 8;
    size_t end, size;
    char *view_end, *bitmap_addr;
    void *base;

    if (!get_view_limit( view, &view_end ))
    {
        ERR( "ARM64EC map view range overflow base %p size %zx\n", view->base, view->size );
        return;
    }
    end = ((size_t)view_end >> page_shift) / 8;
    if (end < start || end == ~(size_t)0 || !round_size_checked( start, end + 1 - start, page_mask, &size ))
    {
        ERR( "ARM64EC bitmap span overflow for view %p-%p\n", view->base, view_end );
        return;
    }
    if (start > ~(size_t)0 - (size_t)arm64ec_view->base)
    {
        ERR( "ARM64EC bitmap base overflow for view %p-%p\n", view->base, view_end );
        return;
    }
    bitmap_addr = (char *)arm64ec_view->base + start;
    base = ROUND_ADDR( bitmap_addr, page_mask );

    view->protect |= VPROT_ARM64EC;
    set_vprot( arm64ec_view, base, size, VPROT_READ | VPROT_WRITE | VPROT_COMMITTED );
}


/***********************************************************************
 *           update_write_watches
 */
static void update_write_watches( void *base, size_t size, size_t accessed_size )
{
    char *accessed_end, *end;

    if (accessed_size > size) accessed_size = size;
    if (size > ~(SIZE_T)0 - (UINT_PTR)base) return;
    accessed_end = (char *)base + accessed_size;
    end = (char *)base + size;

    TRACE( "updating watch %p-%p-%p\n", base, accessed_end, end );
    /* clear write watch flag on accessed pages */
    set_page_vprot_bits( base, accessed_size, 0, VPROT_WRITEWATCH );
    /* restore page protections on the entire range */
    mprotect_range( base, size, 0, 0 );
}


/***********************************************************************
 *           reset_write_watches
 *
 * Reset write watches in a memory range.
 */
static void reset_write_watches( void *base, SIZE_T size )
{
    if (use_kernel_writewatch)
    {
        kernel_writewatch_reset( base, size );
        if (!enable_write_exceptions) return;
        if (!set_page_vprot_exec_write_protect( base, size )) return;
    }
    else set_page_vprot_bits( base, size, VPROT_WRITEWATCH, 0 );

    mprotect_range( base, size, 0, 0 );
}


/***********************************************************************
 *           unmap_extra_space
 *
 * Release the extra memory while keeping the range starting on the alignment boundary.
 */
static inline void *unmap_extra_space( void *ptr, size_t total_size, size_t wanted_size, size_t align_mask )
{
    if ((ULONG_PTR)ptr & align_mask)
    {
        size_t extra = align_mask + 1 - ((ULONG_PTR)ptr & align_mask);
        munmap( ptr, extra );
        ptr = (char *)ptr + extra;
        total_size -= extra;
    }
    if (total_size > wanted_size)
        munmap( (char *)ptr + wanted_size, total_size - wanted_size );
    return ptr;
}


/***********************************************************************
 *           find_reserved_free_area_outside_preloader
 *
 * Find a free area inside a reserved area, skipping the preloader reserved range.
 * virtual_mutex must be held by caller.
 */
static void *find_reserved_free_area_outside_preloader( void *start, void *end, size_t size,
                                                        int top_down, size_t align_mask )
{
    void *ret;

    if (preload_reserve_end >= end)
    {
        if (preload_reserve_start <= start) return NULL;  /* no space in that area */
        if (preload_reserve_start < end) end = preload_reserve_start;
    }
    else if (preload_reserve_start <= start)
    {
        if (preload_reserve_end > start) start = preload_reserve_end;
    }
    else /* range is split in two by the preloader reservation, try both parts */
    {
        if (top_down)
        {
            ret = find_reserved_free_area( preload_reserve_end, end, size, top_down, align_mask );
            if (ret) return ret;
            end = preload_reserve_start;
        }
        else
        {
            ret = find_reserved_free_area( start, preload_reserve_start, size, top_down, align_mask );
            if (ret) return ret;
            start = preload_reserve_end;
        }
    }
    return find_reserved_free_area( start, end, size, top_down, align_mask );
}

/***********************************************************************
 *           map_reserved_area
 *
 * Try to map some space inside a reserved area.
 * virtual_mutex must be held by caller.
 */
static void *map_reserved_area( void *limit_low, void *limit_high, size_t size, int top_down,
                                int unix_prot, size_t align_mask )
{
    void *ptr = NULL;
    struct reserved_area *area;

    if (top_down)
    {
        LIST_FOR_EACH_ENTRY_REV( area, &reserved_areas, struct reserved_area, entry )
        {
            void *start = area->base;
            void *end;

            if (area->size > ~(SIZE_T)0 - (UINT_PTR)start) return NULL;
            end = (char *)start + area->size;
            if (start >= limit_high) continue;
            if (end <= limit_low) return NULL;
            if (start < limit_low)
            {
                SIZE_T rounded_start;

                if (!round_size_checked( 0, (SIZE_T)limit_low, host_page_mask, &rounded_start ))
                    return NULL;
                start = (void *)rounded_start;
            }
            if (end > limit_high) end = ROUND_ADDR( limit_high, host_page_mask );
            ptr = find_reserved_free_area_outside_preloader( start, end, size, top_down, align_mask );
            if (ptr) break;
        }
    }
    else
    {
        LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
        {
            void *start = area->base;
            void *end;

            if (area->size > ~(SIZE_T)0 - (UINT_PTR)start) return NULL;
            end = (char *)start + area->size;
            if (start >= limit_high) return NULL;
            if (end <= limit_low) continue;
            if (start < limit_low)
            {
                SIZE_T rounded_start;

                if (!round_size_checked( 0, (SIZE_T)limit_low, host_page_mask, &rounded_start ))
                    return NULL;
                start = (void *)rounded_start;
            }
            if (end > limit_high) end = ROUND_ADDR( limit_high, host_page_mask );
            ptr = find_reserved_free_area_outside_preloader( start, end, size, top_down, align_mask );
            if (ptr) break;
        }
    }
    if (ptr)
    {
#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
        if (unix_prot == PROT_NONE && !mr_vm_dirty && mr_vm_contains( ptr, size ))
        {
            /* Fresh reserve and successful unmap_area replacements are anonymous zero PROT_NONE. */
            MR_VM_INC(arena_none);
            if (mr_vm_context == MR_VM_ARENA) MR_VM_INC(arena_none_noaddr);
            return ptr;
        }
#endif
        if (anon_mmap_fixed( ptr, size, unix_prot, 0 ) != ptr) ptr = NULL;
    }
    return ptr;
}

/***********************************************************************
 *           map_fixed_area
 *
 * Map a memory area at a fixed address.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS map_fixed_area( void *base, size_t size, int unix_prot )
{
    struct reserved_area *area;
    NTSTATUS status;
    size_t host_size;
    char *start = base, *end;

    if ((UINT_PTR)base & host_page_mask) return STATUS_CONFLICTING_ADDRESSES;
    if (find_view_range( base, size )) return STATUS_CONFLICTING_ADDRESSES;
    if (!round_size_checked( 0, size, host_page_mask, &host_size ) ||
        host_size > ~(UINT_PTR)0 - (UINT_PTR)base)
        return STATUS_INVALID_PARAMETER;
    end = (char *)base + host_size;

    LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
    {
        char *area_start = area->base;
        char *area_end = reserved_area_limit( area );

        if (area_start >= end) break;
        if (area_end <= start) continue;
        if (area_start > start)
        {
            if (anon_mmap_tryfixed( start, area_start - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
            start = area_start;
        }
        if (area_end >= end)
        {
#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
            if (unix_prot == PROT_NONE && !mr_vm_dirty && mr_vm_contains( start, end - start ))
            {
                MR_VM_INC(arena_none);
                MR_VM_INC(arena_none_fixed);
                return STATUS_SUCCESS;
            }
#endif
            if (anon_mmap_fixed( start, end - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
            return STATUS_SUCCESS;
        }
        if (anon_mmap_fixed( start, area_end - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
        start = area_end;
    }

    if (anon_mmap_tryfixed( start, end - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
    return STATUS_SUCCESS;

failed:
    if (errno == ENOMEM)
    {
        ERR( "out of memory for %p-%p\n", base, end );
        status = STATUS_NO_MEMORY;
    }
    else if (errno == EEXIST) status = STATUS_CONFLICTING_ADDRESSES;
    else
    {
        ERR( "mmap error %s for %p-%p, unix_prot %#x\n",
             strerror(errno), base, end, unix_prot );
        status = STATUS_INVALID_PARAMETER;
    }
    unmap_area( base, start - (char *)base );
    return status;
}

/***********************************************************************
 *           map_view
 *
 * Create a view and mmap the corresponding memory area.
 * virtual_mutex must be held by caller.
 */
#if defined(__APPLE__) && defined(__aarch64__)
extern BOOL macrunner_cpu_backend_disables_hb_semantics(void);

/* Лейн FEX-N2, 07.09.2026. Просят ли у нас область под СВОЙ хозяйский исполняемый код.
 *
 * Признак: транслятор процесса не HyperBridge, адрес не задан (ветвь вызова), запрошены
 * одновременно запись и исполнение, с коммитом. Ровно так просит FEX
 * (AllocatorHooks.h:49-63, VirtualAlloc(nullptr, ..., PAGE_EXECUTE_READWRITE)).
 *
 * Представления-заготовки, сторожа записи и подмену заготовки исключаем: у них своя
 * механика, и единственный mprotect области MAP_JIT с ней несовместим.
 *
 * Выключатель MACRUNNER_FEX_JIT_MAP=0 возвращает прежнее поведение целиком. */
static BOOL macrunner_fex_jit_view_wanted( unsigned int vprot, unsigned int alloc_type )
{
    static int gate = -1;

    if (gate < 0)
    {
        const char *value = getenv( "MACRUNNER_FEX_JIT_MAP" );
        gate = value ? atoi( value ) : 1;
    }
    if (!gate) return FALSE;
    if (!macrunner_cpu_backend_disables_hb_semantics()) return FALSE;
    if (!(vprot & VPROT_EXEC)) return FALSE;

    /* ★ Лейн FEX-N2c — БЕЗУСЛОВНЫЙ ЗОНД ДОСТИЖИМОСТИ.
     *
     * Прошлый заход не мог отличить «предикат сказал НЕТ» от «предикат не звали вовсе»:
     * молчащий гейт печати не имеет, и оба случая выглядят одинаково — ноль строк
     * macrunner-fex-jit-map. Стоило дня разбора. Печатаем ПОСЛЕ отсева не-исполняемых
     * (иначе тысячи строк) и до всех остальных условий, чтобы вердикт был виден вместе
     * с причиной. Потолок 16 — этого хватает: исполняемых выделений за прогон единицы. */
    {
        static unsigned int mr_seen;
        unsigned int n = __atomic_add_fetch( &mr_seen, 1, __ATOMIC_RELAXED );
        BOOL ok = (vprot & (VPROT_WRITE | VPROT_WRITECOPY)) && (vprot & VPROT_COMMITTED) &&
                  !(vprot & (VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER | VPROT_WRITEWATCH)) &&
                  !(alloc_type & (MEM_REPLACE_PLACEHOLDER | MEM_RESERVE_PLACEHOLDER));
        if (n <= 16)
        {
            fprintf( stderr, "macrunner-fex-jit-gate: n=%u vprot=%#x alloc=%#x "
                     "write=%d commit=%d place=%d вердикт=%d\n",
                     n, vprot, alloc_type,
                     !!(vprot & (VPROT_WRITE | VPROT_WRITECOPY)),
                     !!(vprot & VPROT_COMMITTED),
                     !!((vprot & (VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER)) ||
                        (alloc_type & (MEM_REPLACE_PLACEHOLDER | MEM_RESERVE_PLACEHOLDER))),
                     (int)ok );
            fflush( stderr );
        }
    }

    if (!(vprot & (VPROT_WRITE | VPROT_WRITECOPY))) return FALSE;
    if (!(vprot & VPROT_COMMITTED)) return FALSE;
    if (vprot & (VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER | VPROT_WRITEWATCH)) return FALSE;
    if (alloc_type & (MEM_REPLACE_PLACEHOLDER | MEM_RESERVE_PLACEHOLDER)) return FALSE;
    return TRUE;
}

/* ★★★ Лейн FEX-N2c — ХОЗЯЙСКАЯ исполняемая память транслятора, и ТОЛЬКО она.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫЙ, БОЛЕЕ УЗКИЙ ПРЕДИКАТ. Первая редакция правки снимала с арены
 * guest32 всё, что хочет ветвь MAP_JIT, — и это ИЗМЕРЕННО СЛОМАЛО прогон (exit=1,
 * клей FEX не грузился вовсе). Причина видна зондом: ветвь MAP_JIT срабатывает и на
 * ОБРАЗАХ PE (`vprot=0x180002d` = SEC_IMAGE|SEC_FILE|WRITECOPY|EXEC|COMMITTED,
 * 39 из 41 срабатывания за прогон). Гостевой образ i386 обязан лежать В ОКНЕ 4 ГБ —
 * иначе 32-битный гость его не адресует. Снимать образы с арены НЕЛЬЗЯ.
 *
 * ОТЛИЧИЕ ОТ ветви MAP_JIT: здесь дополнительно требуется, чтобы память была
 * АНОНИМНОЙ (не образ и не файл) и просилась под запись НАПРЯМУЮ (VPROT_WRITE, а не
 * VPROT_WRITECOPY). Ровно так просит FEXCore: AllocatorHooks.h VirtualAlloc(nullptr,
 * Size, PAGE_EXECUTE_READWRITE) -> vprot = READ|WRITE|EXEC|COMMITTED, без SEC_*.
 * Через это одно узкое место идут ВСЕ ЧЕТЫРЕ исполняемых выделения FEXCore
 * (SharedCodeBufferManager, Dispatcher, CodeCache x2), поэтому предикат покрывает
 * их разом и покроет всякое будущее пятое.
 *
 * ГРАНИЦА: только backend != hb (через macrunner_fex_jit_view_wanted), поэтому рука
 * HyperBridge не задета. Выключатель тот же MACRUNNER_FEX_JIT_MAP=0. */
static BOOL macrunner_fex_host_jit_alloc_wanted( const void *base, unsigned int vprot, unsigned int alloc_type )
{
    /* ★ АДРЕС ОБЯЗАН БЫТЬ НЕ ЗАДАН, и это НЕ формальность — это второй измеренный отказ.
     * Ветвь MAP_JIT проверяет base НЕЯВНО: она стоит внутри `else` от `if (base)`.
     * Здесь же предикат зовётся ВЫШЕ, где base может быть любым, и без этой строки он
     * снял с арены `vprot=0x27 alloc=0x1000` — фиксацию УЖЕ ЗАРЕЗЕРВИРОВАННОЙ гостем
     * области по заданному адресу. Гостевая память уехала мимо окна 4 ГБ, и прогон встал
     * на load_64bit_module, не дойдя до BTCpuProcessInit. */
    if (base) return FALSE;

    /* ★ И ОБЯЗАТЕЛЬНО MEM_RESERVE — это ТРЕТИЙ измеренный отказ, контроль был полным.
     * Без этой строки предикат снял с арены `base=0 vprot=0x27 alloc=0x1000` — ФИКСАЦИЮ
     * без резервирования, то есть коммит внутри чужой области. Разделение:
     *     ntdll.so 4e120fb9 (исходный) -> glue=1 init=14 markjit=2 after-BTCpu=2
     *     ntdll.so df2d4c91 (без этой строки) -> все четыре НОЛЬ, стоп на load_64bit_module
     * FEXCore просит ровно MEM_COMMIT|MEM_RESERVE|MEM_TOP_DOWN = 0x103000
     * (AllocatorHooks.h: Flags = MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN). */
    if (!(alloc_type & MEM_RESERVE)) return FALSE;

    if (!macrunner_fex_jit_view_wanted( vprot, alloc_type )) return FALSE;
    /* ★ Порядок: ПОСЛЕ гейта транслятора. Замер 07.09: при обратном порядке прибор
     * notopdown печатался 12 раз на КОНТРОЛЬНОЙ руке hb (поведение то же — оба пути
     * дают FALSE, — но прибор на контроле сбивает с толку следующего). */
    /* ★★★★ Лейн FEX-N2d — MEM_TOP_DOWN ОБЯЗАТЕЛЕН. ЧЕТВЁРТЫЙ измеренный отказ, и он
     * стоил захода N2c регресса «after BTCpuProcessInit: 2 -> 0».
     *
     * ЧТО БЫЛО ИЗМЕРЕНО (журнал N2c, reports/FEX-N2d-lab/ulikiN2c/fex/run.log, pid 69218):
     *     9424  macrunner-fex-init: шаг=13 InitCore          <- InitCore УЖЕ ВЕРНУЛСЯ
     *     9427  macrunner-fex-jit-gate:  n=3 vprot=0x27 alloc=0x3000     <- БЕЗ MEM_TOP_DOWN
     *     9430  macrunner-fex-jit-map:   base=0x100370000 size=4000
     *     9437  macrunner-vhf-обл: addr=0x100370000 prot=7 max=7 site=bus  <- SIGBUS, вечный повтор
     *     байты у pc: 09 01 00 b9 = str w9,[x8]; x8=0x100370000, x9=0x2ecd2ecd
     *
     * ЧЬЯ ЭТО ПАМЯТЬ. Не FEXCore. Это трамплин syscall/unixcall, который выделяет САМ
     * модуль WOW64 сразу ПОСЛЕ InitCore:
     *     engine/fex/Source/Windows/WOW64/Module.cpp:626-630
     *         NtAllocateVirtualMemory( ..., (1U<<31)-1, &Size, MEM_RESERVE|MEM_COMMIT,
     *                                  PAGE_EXECUTE_READWRITE );
     *         *reinterpret_cast<uint32_t*>(Addr) = 0x2ecd2ecd;
     * Запись — ОБЫЧНАЯ запись C++ вне всякой скобки W^X. Область MAP_JIT при
     * pthread_jit_write_protect_np(1) на запись закрыта, отсюда SIGBUS. То есть прежний
     * предикат снимал с арены ЧУЖОЕ выделение и делал его незаписываемым.
     *
     * ПОЧЕМУ ИМЕННО MEM_TOP_DOWN — признак СТРУКТУРНЫЙ, а не подобранный. Все четыре
     * исполняемых выделения FEXCore идут через одно узкое место, и оно ставит флаг
     * БЕЗУСЛОВНО (FEXCore/include/FEXCore/Utils/AllocatorHooks.h:102):
     *     DWORD Flags = (Commit ? MEM_COMMIT : 0) | MEM_RESERVE | MEM_TOP_DOWN;
     * Трамплин Module.cpp его не ставит НИКОГДА. Разделение полное и по построению.
     *
     * ВТОРОЙ, НЕЗАВИСИМЫЙ ДОВОД. Тот же вызов просит zero_bits=(1U<<31)-1, то есть адрес
     * в НИЖНИХ 2 ГБ (гость обязан дотянуться до трамплина). Ветвь MAP_JIT предел соблюсти
     * НЕ МОЖЕТ — MAP_FIXED с MAP_JIT закрыт ядром, адрес выбирает ядро; она и выдала
     * 0x100370000, то есть 4 ГБ. Даже без W^X это было бы нарушением договора. */
    if (!(alloc_type & MEM_TOP_DOWN))
    {
        static unsigned int mr_skip_td;
        unsigned int n = __atomic_add_fetch( &mr_skip_td, 1, __ATOMIC_RELAXED );
        if (n <= 8)
        {
            fprintf( stderr, "macrunner-fex-host-jit-notopdown: n=%u vprot=%#x alloc=%#x"
                     " — не FEXCore, оставлено арене guest32\n", n, vprot, alloc_type );
            fflush( stderr );
        }
        return FALSE;
    }

    if (!(vprot & VPROT_WRITE)) return FALSE;            /* WRITECOPY = образ, не наша память */
    if (vprot & (SEC_IMAGE | SEC_FILE)) return FALSE;    /* отображение файла/образа — в окно гостя */

    {
        static unsigned int mr_taken;
        unsigned int n = __atomic_add_fetch( &mr_taken, 1, __ATOMIC_RELAXED );
        if (n <= 16)
        {
            fprintf( stderr, "macrunner-fex-host-jit: снято с арены guest32 n=%u base=%p vprot=%#x alloc=%#x\n",
                     n, base, vprot, alloc_type );  /* размер печатает сама ветвь jit-map */
            fflush( stderr );
        }
    }
    return TRUE;
}
#endif

static NTSTATUS map_view( struct file_view **view_ret, void *base, size_t size,
                          unsigned int alloc_type, unsigned int vprot,
                          ULONG_PTR limit_low, ULONG_PTR limit_high, size_t align_mask )
{
    int top_down = alloc_type & MEM_TOP_DOWN;
    void *ptr;
    int unix_prot = get_unix_prot( vprot );
    NTSTATUS status;
    int mr_guest32_view = 0;   /* ★ 06.09 лейн ТЕНЕВАЯ-КАРТА-2: пришли ли на `done:` путём guest32 */

    if (base) MR_VM_INC(view_fixed);
    else MR_VM_INC(view_noaddr);
    if (unix_prot == PROT_NONE)
    {
        if (base) MR_VM_INC(fixed_none);
        else MR_VM_INC(noaddr_none);
    }
    if (vprot & SEC_IMAGE) MR_VM_INC(view_image);
    else if (vprot & SEC_FILE) MR_VM_INC(view_file);
    if (top_down) MR_VM_INC(view_topdown);
    if (limit_low || limit_high) MR_VM_INC(view_limited);

    if (!align_mask) align_mask = granularity_mask;
    assert( align_mask >= host_page_mask );

    if (alloc_type & MEM_REPLACE_PLACEHOLDER)
    {
        struct file_view *view;

        if (!(view = find_view( base, 0 ))) return STATUS_INVALID_PARAMETER;
        if (view->base != base || view->size != size) return STATUS_CONFLICTING_ADDRESSES;
        if (!(view->protect & VPROT_FREE_PLACEHOLDER)) return STATUS_INVALID_PARAMETER;

        TRACE( "found view %p, size %p, protect %#x.\n", view->base, (void *)view->size, view->protect );

        view->protect = vprot | VPROT_PLACEHOLDER;
        set_vprot( view, base, size, vprot );
        if (vprot & VPROT_WRITEWATCH)
        {
            kernel_writewatch_register_range( view, base, size );
            reset_write_watches( base, size );
        }
        *view_ret = view;
        return STATUS_SUCCESS;
    }

    if (limit_high && limit_low >= limit_high) return STATUS_INVALID_PARAMETER;

    if (use_kernel_writewatch && vprot & VPROT_WRITEWATCH)
        unix_prot = get_unix_prot( vprot & ~VPROT_WRITEWATCH );

    unix_prot &= ~PROT_EXEC;

#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
    /* ★★★ MacRunner 07.09.2026, лейн FEX-N2c — АРЕНА guest32 ПЕРЕХВАТЫВАЛА ХОЗЯЙСКИЙ
     * ИСПОЛНЯЕМЫЙ КОД, И ИМЕННО ЭТО, А НЕ «РАЗМЕТКА У ОДНОГО ИЗ ЧЕТЫРЁХ», БЫЛО СТЕНОЙ.
     *
     * ИЗМЕРЕНО (прогон reports/FEX-N2b-lab/runs/fex, pid 61239):
     *     macrunner-hb-guest32-окно: база=0xc00000000 размер=100000000   <- окно 4 ГБ
     *     диспетчер FEX      0xcdfff0000   внутри окна
     *     кодовый буфер FEX  0xcb57f0000   внутри окна
     *     строк macrunner-fex-jit-map в ЭТОМ процессе — НОЛЬ из 39 за прогон
     *     macrunner-hb-rwx-fallback: base=0xcdfff0000 requested=0x7 final=0x3 n=2 844 672
     *
     * ПОЧЕМУ. Блок ниже стоит ВЫШЕ ветви MAP_JIT и уходит по `goto done`, поэтому для
     * образа-гостя i386 гейт `macrunner_fex_jit_view_wanted` был НЕДОСТИЖИМ в принципе.
     * Все четыре исполняемых выделения FEXCore идут через одно узкое место
     * (AllocatorHooks.h VirtualAlloc), и все четыре попадали сюда.
     *
     * ПОЧЕМУ ЛЕЧИТЬ ЗДЕСЬ, А НЕ В FEX. Память диспетчера и кодового буфера —
     * ХОЗЯЙСКАЯ (выпущенный ARM64-код транслятора), гостю она не адресуется. В окне
     * гостя 4 ГБ ей не место ни по смыслу, ни по правам: арена отдаёт обычную область,
     * с которой mprotect_exec обязан снять EXEC (Apple Silicon RWX без MAP_JIT не даёт).
     *
     * ГРАНИЦА. Условие снятия — РОВНО тот же предикат, что включает ветвь MAP_JIT,
     * поэтому поведение guest32 для всего остального побайтово прежнее, а рука
     * HyperBridge не задета вовсе (предикат требует backend != hb). */
    /* ★★★★ ПАКЕТ-2 (договор T5) — ЛОВУШКА, НАЗВАННАЯ АУДИТОМ ДОСЛОВНО:
     * «Machine==I386 сам включает HB map, даже при unset env; presence-test считает и
     * строку `0` включённой». Оба изъяна видны прямо в условии: первый дизъюнкт включает
     * нашу частную арену по одной только разрядности гостя, третий проверяет переменную
     * НА НАЛИЧИЕ, поэтому `MACRUNNER_HB_WOW64_GUEST32=0` читалось как «включено».
     *
     * Лечение — спросить ВЛАДЕЛЬЦА, а не разрядность. Проверка стоит ПОСЛЕДНЕЙ намеренно
     * (урок пакета 3): тогда счётчик считает ровно те случаи, где ветвь СРАБОТАЛА БЫ, а не
     * все отображения, дошедшие до этого места.
     *
     * Гасить надо здесь ОТДЕЛЬНО от гейта самой арены: без этого ветвь всё равно вошла бы,
     * шестнадцать раз получила бы отказ от `..._alloc_range`, напечатала бы шестнадцать
     * `macrunner-guest32-конфликт` и только потом провалилась бы дальше. Громко, медленно
     * и с ложным следом в журнале. */
    if (is_win64 && (main_image_info.Machine == IMAGE_FILE_MACHINE_I386 ||
                     macrunner_hb_wow64_guest32_map_active ||
                     getenv( "MACRUNNER_HB_WOW64_GUEST32" )) &&
        !macrunner_fex_host_jit_alloc_wanted( base, vprot, alloc_type ) &&
        !macrunner_paket2_mute( "T5-mapview" ))
    {
        ULONG protect = PAGE_NOACCESS;
        if (vprot & VPROT_EXEC)
            protect = (vprot & (VPROT_WRITE | VPROT_WRITECOPY)) ? PAGE_EXECUTE_READWRITE :
                      (vprot & VPROT_READ) ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
        else if (vprot & (VPROT_WRITE | VPROT_WRITECOPY))
            protect = PAGE_READWRITE;
        else if (vprot & VPROT_READ)
            protect = PAGE_READONLY;

        /* ★★★★★ MacRunner 06.09.2026, лейн ТЕНЕВАЯ-КАРТА-4 — ПРАВДА О КОММИТЕ В ИСТОЧНИКЕ,
         * А НЕ ПОВЕРХ НЕГО. Приём взят из box64 и QEMU, разбор в
         * reports/ТЕНЕВАЯ-КАРТА-i386-ПО-ОБРАЗЦУ-box64-06.09.2026.md §1.
         *
         * ЧТО НЕ ТАК СЕЙЧАС. Эти шесть строк выше пересчитывают `vprot` в `protect`, СПРОСИВ
         * только READ/WRITE/EXEC. `VPROT_COMMITTED` не спрашивается вовсе, поэтому
         * `VirtualAlloc(MEM_RESERVE, PAGE_READWRITE)` даёт нам `PAGE_READWRITE`, а из него
         * `r->perm = R|W`. Дальше эта ложь расходится ПО ТРЁМ потребителям сразу:
         *     помощник        -- `region->perm` (полная проверка) говорит «писать можно»;
         *     теневая карта   -- `hb_memory_perm_map_*` строится из того же `r->perm`;
         *     MMU хозяина     -- `guest32_apply_host_prot` ставит страницу из того же `r->perm`.
         * Правка `MACRUNNER_HB_GUEST32_WINE_PROT` чинит ТОЛЬКО третьего, и измерено (руки
         * A/B, 06.09), что `guest32_apply_host_prot` тут же ставит права обратно: он тоже
         * читает `r->perm`. Две правки набора «правдивые-права» работают друг против друга
         * ровно на том классе, ради которого набор написан.
         *
         * ПОЧЕМУ ИМЕННО ЗДЕСЬ. У box64 (`research/box64/src/wrapped/wrappedlibc.c:3892`) и у
         * QEMU (`research/qemu/linux-user/mmap.c:269`) программная таблица прав заполняется
         * ИЗ СОБСТВЕННОЙ обёртки `mmap`, то есть источник прав ОДИН и он точен по построению.
         * У нас источников два (Wine `vprot` и наш `r->perm`), и беднейший побеждает. Ставим
         * правду в точке, где `r->perm` РОЖДАЕТСЯ, а не латаем её следствия.
         *
         * ГРАНИЦА, НАЗВАННАЯ ЧЕСТНО: `VPROT_GUARD` здесь НЕ учитывается намеренно. Сторожевая
         * страница снимается срабатыванием внутри `virtual_handle_fault`, а не через
         * `NtProtectVirtualMemory`, и нашей таблице об этом сообщить некому — понизив её
         * здесь, мы сломали бы законный ВТОРОЙ доступ (проба `guard2` зонда). Точка
         * уведомления о снятии сторожа не существует; это записано сметой в отчёте.
         *
         * ★ ГЕЙТ РАБОТАЕТ ТОЛЬКО НАБОРОМ с `MACRUNNER_HB_GUEST32_SYNC_PROT=1`: понижение прав
         * на резерве обязано иметь ПАРНОЕ повышение на коммите, иначе законная запись после
         * `MEM_COMMIT` упрётся в нашу же таблицу. В одиночку гейт ЛОМАЕТ гостя. */
        {
            static int mr_commit_truth = -1;
            /* ★ 07.09.2026, лейн ПРИБОРЫ-4. Гейт с умолчанием 0 и печать под потолком
             * «первые 8, дальше каждая 64-я» — ноль строк значил ТРИ вещи: гейт закрыт,
             * сюда не заходили, страница уже была committed. Разводим: looked считает
             * заходы (безусловно), hits — случаи, когда права ДЕЙСТВИТЕЛЬНО понижены.
             * Управление прав — тот самый пробел, который reports/ДОРОЖКА.md называет
             * отсутствующим шагом карты. */
            HB_PROBE_LOOKED(&pr_g32_commit_truth);
            if (mr_commit_truth < 0)
            {
                const char *v = getenv( "MACRUNNER_HB_GUEST32_COMMIT_TRUTH" );
                mr_commit_truth = (v && *v && *v != '0') ? 1 : 0;
            }
            if (mr_commit_truth && !(vprot & VPROT_COMMITTED))
            {
                static unsigned mr_ct_n;
                unsigned n = ++mr_ct_n;
                protect = PAGE_NOACCESS;
                HB_PROBE_HIT(&pr_g32_commit_truth);
                HB_PROBE_LOOKED(&pr_g32_commit_stroka);
                if (n <= 8 || (n % 64) == 0)
                    HB_PROBE_SAY( &pr_g32_commit_stroka, "n=%u база=%p размер=%llx "
                             "vprot=%02x -> PAGE_NOACCESS\n",
                             n, base, (unsigned long long)size, (unsigned)(vprot & 0xff) );
            }
        }

        if (base && (ULONG_PTR)base < limit_4g && (uint64_t)(ULONG_PTR)base + size <= limit_4g)
        {
            status = macrunner_hb_wow64_guest32_map_fixed( (ULONG_PTR)base, size, protect, &ptr );
            if (!status)
            {
                /* MacRunner 2026-08-14, лейн ЛЕСТНИЦА, итерация 860: этот путь идёт в
                 * `create_view` МИМО общей проверки ниже (`if (base)`), потому что стоит
                 * до неё и уходит по `goto done`. Именно он и валил ступень 1 ассертом
                 * `view->protect & VPROT_SYSTEM` через пять строк после первого удачного
                 * полноэкранного блита: наш распределитель guest32 отдавал 64 КБ по
                 * адресу, который в списке представлений wine всё ещё занят чужой
                 * 16-мегабайтной резервацией (учёт распределителя и учёт представлений
                 * разошлись после MEM_DECOMMIT). Проверяем ДО отображения. */
                struct file_view *clash = find_view_range( ptr, size );
                if (clash && !(clash->protect & VPROT_SYSTEM))
                {
                    static int said;
                    if (said++ < 8)
                        fprintf( stderr, "macrunner-guest32-конфликт: путь=fixed занято=%p-%p "
                                 "prot=%08x запрошено=%p-%p size=%08lx\n",
                                 clash->base, (char *)clash->base + clash->size,
                                 (unsigned)clash->protect, ptr, (char *)ptr + size,
                                 (unsigned long)size );
                    return STATUS_CONFLICTING_ADDRESSES;
                }
                TRACE( "got fixed WOW64 guest32 mem %p-%p for guest %p-%p\n",
                       ptr, (char *)ptr + size, base, (char *)base + size );
                mr_guest32_view = 1;
                MR_VM_INC(guest32);
                goto done;
            }
            return status;
        }
        else if (!base)
        {
            ULONG_PTR guest_low = max( limit_low, (ULONG_PTR)address_space_start );
            ULONG_PTR guest_high = limit_high ? min( limit_high, limit_4g ) : min( (ULONG_PTR)user_space_limit, limit_4g );
            /* MacRunner 2026-08-14, лейн ЛЕСТНИЦА, итерация 861.
             *
             * Учёт арены guest32 и список представлений wine РАСХОДЯТСЯ: 16-мегабайтная
             * резервация гостя `0x…7e60000-0x…8e30000` заведена другим путём и арене
             * неизвестна, поэтому арена спокойно отдаёт 64 КБ внутри неё. Дальше
             * `create_view` видит наложение и валит процесс (стена итераций 859-860).
             *
             * Отказ здесь НЕ годится, и это измерено: в 860 возврат
             * STATUS_CONFLICTING_ADDRESSES получала КУЧА, и гость замолкал через 34
             * строки после блита — abort сменился зависанием. Правильный ответ —
             * попросить у арены ДРУГОЙ адрес: занятый она уже пометила у себя, значит
             * следующий вызов выдаст иной. Пробуем ограниченное число раз, а если не
             * вышло — уходим в общий путь ниже, который ищет по спискам самого wine. */
            unsigned int guest32_try;
            for (guest32_try = 0; guest32_try < 16; guest32_try++)
            {
                struct file_view *clash;

                if (guest_low >= guest_high || size > guest_high - guest_low) break;
                if (macrunner_hb_wow64_guest32_alloc_range( size, protect, guest_low, guest_high,
                                                            top_down, &ptr ))
                    break;
                if (!(clash = find_view_range( ptr, size )) || (clash->protect & VPROT_SYSTEM))
                {
                    TRACE( "got WOW64 guest32 mem %p-%p for guest range %#lx-%#lx\n",
                           ptr, (char *)ptr + size, guest_low, guest_high );
                    mr_guest32_view = 1;
                    MR_VM_INC(guest32);
                    goto done;
                }
                {
                    static int said;
                    if (said++ < 8)
                        fprintf( stderr, "macrunner-guest32-конфликт: путь=range попытка=%u "
                                 "занято=%p-%p prot=%08x выдано=%p-%p size=%08lx — берём другой\n",
                                 guest32_try, clash->base, (char *)clash->base + clash->size,
                                 (unsigned)clash->protect, ptr, (char *)ptr + size,
                                 (unsigned long)size );
                }
                /* ★ ИТЕРАЦИЯ 113 — ОСВОБОДИТЬ ТО, ЧТО АРЕНА ВЫДАЛА И МЫ ОТВЕРГЛИ.
                 * Без этого область остаётся у арены брошенной и позже отвергает
                 * законные записи гостя (доказано совпадением баз, итерация 112).
                 * Гейт MACRUNNER_HB_GUEST32_FREE_ON_CLASH, умолчание 0 — правка
                 * трогает раскладку памяти, включать только замером. */
                {
                    static int mr_free_gate = -1;
                    if (mr_free_gate < 0)
                    {
                        const char *v = getenv( "MACRUNNER_HB_GUEST32_FREE_ON_CLASH" );
                        mr_free_gate = (v && *v && *v != '0') ? 1 : 0;
                    }
                    if (mr_free_gate)
                    {
                        NTSTATUS fs = macrunner_hb_wow64_guest32_free( ptr );
                        static int mr_free_n;
                        /* ★ ИТЕРАЦИЯ 114 — И СДВИНУТЬ ПОИСК ВЫШЕ ОСВОБОЖДЁННОГО.
                         *
                         * Замер 113: одно освобождение без сдвига загнало цикл в круг —
                         * все 8 попыток выдавали ОДИН адрес 0x305d40000, потому что
                         * освобождённое немедленно предлагается снова. Исходный отказ
                         * по 0x5D4BFFC при этом исчез (правка верна), но гость стал
                         * падать на записи по нулю после исчерпания 16 попыток.
                         * Поднимаем нижнюю границу за конец отвергнутой области —
                         * тогда нет ни утечки, ни топтания. */
                        ULONG_PTR mr_next = ((ULONG_PTR)ptr & 0xffffffffu) + size;
                        mr_next = (mr_next + 0xffff) & ~(ULONG_PTR)0xffff;
                        if (mr_next > guest_low) guest_low = mr_next;
                        if (mr_free_n++ < 8)
                            /* ★ БЫЛО `%Ix` — спецификатор MSVC. Здесь юниксовая половина,
                             * формататор libc macOS, и она его НЕ ЗНАЕТ: компилятор говорит
                             * «undefined behavior or no effect». Строка при этом печаталась,
                             * то есть прибор не молчал и не усекал — он отвечал НЕВЕРНЫМ
                             * ЧИСЛОМ, и это выглядело как исправный замер. */
                            fprintf( stderr, "macrunner-guest32-освобождено: попытка=%u "
                                     "адрес=%p статус=%08lx новый_низ=%lx\n",
                                     guest32_try, ptr, (unsigned long)fs,
                                     (unsigned long)guest_low );
                    }
                }
            }
        }
    }
#endif

    if (base)
    {
        if (is_beyond_limit( base, size, address_space_limit )) return STATUS_WORKING_SET_LIMIT_RANGE;
        if (limit_low && base < (void *)limit_low) return STATUS_CONFLICTING_ADDRESSES;
        if (limit_high && is_beyond_limit( base, size, (void *)limit_high )) return STATUS_CONFLICTING_ADDRESSES;
        if (is_beyond_limit( base, size, host_addr_space_limit )) return STATUS_CONFLICTING_ADDRESSES;
        /* MacRunner 2026-08-14, лейн ЛЕСТНИЦА, итерация 860: ступень 1 (Diablo) умирала
         * ЧЕРЕЗ ПЯТЬ СТРОК после первого удачного полноэкранного блита —
         * `assert( view->protect & VPROT_SYSTEM )` в `create_view` (virtual.c:2388).
         *
         * Путь: сюда приходит запрос с ФИКСИРОВАННОЙ базой на область, уже занятую
         * НЕ системным представлением (замер: старое 0x307e60000-0x308e30000 prot=0x03,
         * новое 0x308320000-0x308330000, 64 КБ — тот самый блок, который куча ucrtbase
         * перед этим раскоммитила). `map_fixed_area` отображает поверх, и только потом
         * `create_view` обнаруживает наложение и валит процесс.
         *
         * Два изъяна, и оба лечатся здесь, ДО отображения:
         * 1. Отказ должен быть отказом, а не abort: на Windows резервирование поверх уже
         *    зарезервированного возвращает STATUS_CONFLICTING_ADDRESSES. Ровно этот код
         *    функция уже возвращает тремя строками выше — идиома своя, не привнесённая.
         * 2. Проверять НАДО РАНЬШЕ `map_fixed_area`: иначе мы успеваем отобразить память
         *    поверх живого чужого представления и повреждаем его. Прежний порядок делал
         *    это всегда, а замечал только на ассерте.
         * Системные представления не трогаем — их `create_view` умеет удалять сам. */
        {
            struct file_view *clash = find_view_range( base, size );
            if (clash && !(clash->protect & VPROT_SYSTEM))
            {
                static int said;
                if (said++ < 8)
                    fprintf( stderr, "macrunner-mapview-конфликт: занято=%p-%p prot=%08x "
                             "запрошено=%p-%p size=%08lx — STATUS_CONFLICTING_ADDRESSES\n",
                             clash->base, (char *)clash->base + clash->size,
                             (unsigned)clash->protect, base, (char *)base + size,
                             (unsigned long)size );
                return STATUS_CONFLICTING_ADDRESSES;
            }
        }
        if ((status = MR_VM_CALL( MR_VM_FIXED, map_fixed_area( base, size, unix_prot ) ))) return status;
        if (is_beyond_limit( base, size, working_set_limit )) working_set_limit = address_space_limit;
        ptr = base;
    }
    else
    {
        void *start = address_space_start;
        void *end = min( user_space_limit, host_addr_space_limit );
        size_t unmap_size, host_size, view_size;

        if (!round_size_checked( 0, size, host_page_mask, &host_size ) ||
            align_mask == ~(SIZE_T)0 ||
            host_size > ~(SIZE_T)0 - align_mask - 1)
            return STATUS_INVALID_PARAMETER;
        view_size = host_size + align_mask + 1;

#if defined(__APPLE__) && defined(__aarch64__)
        /* ★★★ MacRunner 07.09.2026, лейн FEX-N2 — ИСПОЛНЯЕМАЯ ПАМЯТЬ ТОЛЬКО ЧЕРЕЗ MAP_JIT.
         *
         * ЗАЧЕМ. Транслятор, которому нужна собственная исполняемая память (FEX просит её
         * как VirtualAlloc(nullptr, ..., PAGE_EXECUTE_READWRITE), AllocatorHooks.h:49-63),
         * получал от нас обычное отображение, с которого mprotect_exec снимал EXEC. Замер
         * прогона reports/FEX-N3-lab/runs/fex: 3 415 040 срабатываний отката на ОДНОМ
         * адресе 0x3dfff0000. В контрольной руке hb того же адреса нет вовсе — там откат
         * даёт ~121 срабатывание на загрузке модулей PE, и они несущие для обеих рук.
         *
         * ПОЧЕМУ ИМЕННО ТАК, А НЕ КАК У CrossOver. Их спутник размечает УЖЕ ВЫДЕЛЕННУЮ
         * область на месте: mmap(addr, size, 7, 0x1812) — то есть MAP_JIT|MAP_FIXED.
         * Нам это НЕДОСТУПНО, и причина внешняя. XNU bsd/kern/kern_mman.c:403-423
         * разрешает MAP_JIT вместе с MAP_FIXED только когда страница карты процесса
         * 4 КБ и карта не exotic; иначе EINVAL. У нас страница 16 КБ, и проба
         * reports/FEX-N2-lab/rwx_probe.c это подтвердила фактом:
         *
         *     MAP_JIT без MAP_FIXED            -> ok, prot=7 max=7, код вернул 42 и 43
         *     MAP_JIT|MAP_FIXED поверх RW      -> EINVAL
         *     MAP_JIT|MAP_FIXED поверх PROT_NONE -> EINVAL
         *     RWX без MAP_JIT (контроль)       -> EACCES
         *
         * CrossOver уходит в 4 КБ отдельным перезапуском (_posix_spawnattr_set_4k_page_size_np).
         * Нам эта дорога закрыта: проба reports/FEX-N2-lab/spawn4k_probe.c дала
         * posix_spawn rc=88 на ТРЁХ разных двоичных, включая системный /bin/echo, тогда
         * как тот же spawn без атрибута работает. Право на 4 КБ у нас нет, а
         * fourk_fatal_mode на этой машине включён (XNU mach_loader.c:985-1025).
         *
         * ОТСЮДА КОНСТРУКЦИЯ. Адрес выбирает ЯДРО (MAP_FIXED нельзя), права ставим
         * RWX СРАЗУ (второго mprotect не будет — см. mprotect_exec), представление
         * помечаем VPROT_MACRUNNER_JIT. Дальше всё обычное хозяйство Wine работает:
         * ниже по коду тот же `create_view`, тот же учёт, тот же NtQueryVirtualMemory.
         *
         * ГРАНИЦЫ. Ветвь берётся только при backend != hb, поэтому рука HyperBridge
         * побайтово прежняя. Отказ mmap здесь НЕ фатален — падаем на обычный путь,
         * то есть в прежнее поведение. */
        /* ★★★ ШАГ-2 08.09.2026 — ЗДЕСЬ СТОЯЛ ШИРОКИЙ ПРЕДИКАТ, И НА x64 ОН ЗАБИРАЛ ОБРАЗЫ PE.
         *
         * ИЗМЕРЕНО (reports/SHAG2-lab/runs/arhiv, рука fex-x64 до правки, pid 59808):
         *     macrunner-mapview-конфликт: запрошено=0x6ffffa600000 size=0x3b9000 — CONFLICTING
         *     macrunner-fex-jit-gate:  n=1 vprot=0x180002d alloc=0x100000 вердикт=1
         *     macrunner-fex-jit-map:   base=0x1131d0000 size=0x3bc000 vprot=0x180402d n=1
         *     macrunner-cpu-backend-load: overlay try pe=…/aarch64-windows/xtajit64.dll
         *                                 status=0xc0000005            <- ОТКАЗ ДОСТУПА
         *     macrunner-ldr-load-dll-fail: status=c0000005 lib=…xtajit64.dll  -> exit=5
         * vprot=0x180002d = SEC_IMAGE|SEC_FILE|WRITECOPY|EXEC|COMMITTED, то есть ОБРАЗ PE.
         *
         * ПОЧЕМУ ЭТО НЕ ВЫЛЕЗАЛО НА i386. Там блок арены guest32 стоит ВЫШЕ и уходит по
         * `goto done` для всего, что не прошло УЗКИЙ предикат, поэтому сюда попадало ровно
         * узкое множество.  У гостя x64 арены нет, условие блока ложно, и широкий предикат
         * впервые получил управление на образах — все они уходили в область MAP_JIT, где
         * запись секций/релокаций невозможна.
         *
         * ЛЕЧЕНИЕ: тот же УЗКИЙ предикат, что уже стоит у арены — анонимная память,
         * MEM_RESERVE|MEM_TOP_DOWN, VPROT_WRITE (не WRITECOPY), без SEC_IMAGE/SEC_FILE.
         * На i386 это ТОЖДЕСТВЕННАЯ замена (см. рассуждение выше — множества совпадают),
         * на x64 она убирает захват образов. */
        if (macrunner_fex_host_jit_alloc_wanted( base, vprot, alloc_type ))
        {
            void *jit = MR_VM_CALL( MR_VM_JIT,
                        mmap( NULL, view_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0 ) );
            if (jit == MAP_FAILED)
            {
                fprintf( stderr, "macrunner-fex-jit-map: ОТКАЗ size=%zx errno=%d (%s) — обычный путь\n",
                         view_size, errno, strerror(errno) );
                fflush( stderr );
            }
            /* ★★★ Лейн FEX-N2d — ПРЕДЕЛ ВЫЗЫВАЮЩЕГО ЭТА ВЕТВЬ СОБЛЮСТИ НЕ МОЖЕТ.
             *
             * Довод ВНЕШНИЙ, не наш: MAP_JIT вместе с MAP_FIXED закрыт ядром (XNU
             * bsd/kern/kern_mman.c:403-423 при странице 16 КБ), значит адрес выбирает
             * ЯДРО и указания limit_low/limit_high выполнить нечем. Клампинг предела
             * стоит НИЖЕ по коду, и эта ветвь уходит по `goto done` мимо него — то есть
             * без этой проверки предел молча игнорируется.
             *
             * Измерено на живом примере (N2c): вызов с zero_bits=(1U<<31)-1, то есть
             * «нижние 2 ГБ», получил 0x100370000 — вчетверо выше запрошенного потолка.
             * ★ ГРАНИЦА: на прогоне i386 эта проверка ИНЕРТНА — трамплин туда больше не
             * доходит (снят выше по MEM_TOP_DOWN). Она сторожит ветви x64/ARM64EC, где
             * арены guest32 нет; там не измерена. */
            else if ((limit_low && (ULONG_PTR)jit < limit_low) ||
                     (limit_high && (ULONG_PTR)jit + view_size - 1 > limit_high))
            {
                munmap( jit, view_size );
                fprintf( stderr, "macrunner-fex-jit-map: предел вызывающего low=%#llx high=%#llx"
                         " ядром не соблюдён (дало %p+%zx) — обычный путь\n",
                         (unsigned long long)limit_low, (unsigned long long)limit_high,
                         jit, view_size );
                fflush( stderr );
            }
            else if (is_beyond_limit( jit, view_size, user_space_limit ))
            {
                /* Ядро выдало выше предела пользовательского пространства: вернуть и не брать. */
                munmap( jit, view_size );
                fprintf( stderr, "macrunner-fex-jit-map: адрес выше предела, отдан обратно\n" );
                fflush( stderr );
            }
            else
            {
                static unsigned int mr_jit_maps;
                unsigned int n = __atomic_add_fetch( &mr_jit_maps, 1, __ATOMIC_RELAXED );
                ptr = unmap_extra_space( jit, view_size, host_size, align_mask );
                vprot |= VPROT_MACRUNNER_JIT;
                MR_VM_INC(jit);
                fprintf( stderr, "macrunner-fex-jit-map: base=%p size=%zx vprot=%#x n=%u\n",
                         ptr, host_size, vprot, n );
                fflush( stderr );
                goto done;
            }
        }
#endif

        if (limit_low && (void *)limit_low > start) start = (void *)limit_low;
        if (limit_high && (void *)limit_high < end) end = (char *)limit_high + 1;

#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
        if (mr_vm_owned)
        {
            void *arena_low = max( start, mr_vm_base );
            void *arena_high = min( end, mr_vm_end );
            if (arena_low < arena_high)
            {
                ULONG64 errors_before = mr_vm_get( &mr_vm_kernel[MR_VM_ARENA].eexist ) +
                                        mr_vm_get( &mr_vm_kernel[MR_VM_ARENA].enomem ) +
                                        mr_vm_get( &mr_vm_kernel[MR_VM_ARENA].einval ) +
                                        mr_vm_get( &mr_vm_kernel[MR_VM_ARENA].other_errno );
                ptr = MR_VM_CALL( MR_VM_ARENA,
                      map_reserved_area( arena_low, arena_high, host_size, top_down, unix_prot, align_mask ) );
                if (ptr) { MR_VM_INC(arena_maps); goto done; }
                if (errors_before != mr_vm_get( &mr_vm_kernel[MR_VM_ARENA].eexist ) +
                                     mr_vm_get( &mr_vm_kernel[MR_VM_ARENA].enomem ) +
                                     mr_vm_get( &mr_vm_kernel[MR_VM_ARENA].einval ) +
                                     mr_vm_get( &mr_vm_kernel[MR_VM_ARENA].other_errno ))
                    MR_VM_INC(arena_mapping_failed);
                else MR_VM_INC(arena_exhausted);
                /* No silent scan fallback once this request selected our owned arena. */
                return STATUS_NO_MEMORY;
            }
            MR_VM_INC(outside_limits);
        }
        else if (!mr_vm_gate) MR_VM_INC(gate_off);
#endif

        if ((ptr = MR_VM_CALL( MR_VM_NOADDR,
                    map_reserved_area( start, end, host_size, top_down, unix_prot, align_mask ) )))
        {
            MR_VM_INC(legacy_reserved);
            TRACE( "got mem in reserved area %p-%p\n", ptr, (char *)ptr + size );
            goto done;
        }

        if (start > address_space_start || end < host_addr_space_limit || top_down)
        {
            MR_VM_INC(legacy_scan);
            if (!(ptr = MR_VM_CALL( MR_VM_NOADDR,
                       map_free_area( start, end, host_size, top_down, unix_prot, align_mask ) )))
                return STATUS_NO_MEMORY;
            TRACE( "got mem with map_free_area %p-%p\n", ptr, (char *)ptr + size );
            goto done;
        }

        for (;;)
        {
            MR_VM_INC(legacy_anon);
            if ((ptr = MR_VM_CALL( MR_VM_NOADDR, anon_mmap_alloc( view_size, unix_prot ) )) == MAP_FAILED)
            {
                status = (errno == ENOMEM) ? STATUS_NO_MEMORY : STATUS_INVALID_PARAMETER;
                ERR( "anon mmap error %s, size %p, unix_prot %#x\n",
                     strerror(errno), (void *)view_size, unix_prot );
                return status;
            }
            TRACE( "got mem with anon mmap %p-%p\n", ptr, (char *)ptr + size );
            /* if we got something beyond the user limit, unmap it and retry */
            if (!is_beyond_limit( ptr, view_size, user_space_limit )) break;
            unmap_size = unmap_area_above_user_limit( ptr, view_size );
            if (unmap_size) munmap( ptr, unmap_size );
        }
        ptr = unmap_extra_space( ptr, view_size, host_size, align_mask );
    }
done:
    { /* Итерация 311: назвать ВЫЗЫВАЮЩЕГО. Приём из 307 — печать с номером места,
       безусловная, первые 4 раза на место. Утверждение VPROT_SYSTEM воспроизводится 3/3,
       и место вызова — единственное, чего не хватает для разбора. */
      static int said_3164;
      if (said_3164++ < 4)
        fprintf(stderr, "macrunner-createview-site: место=3164\n"); }
    status = create_view( view_ret, ptr, size, vprot );
    if (status != STATUS_SUCCESS) unmap_area( ptr, size );
#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
    /* ★★★ MacRunner 06.09.2026, лейн ТЕНЕВАЯ-КАРТА-2 — ПРАВДА О ПРАВАХ ЖИВЁТ ТОЛЬКО ЗДЕСЬ.
     *
     * Ветвь guest32 выше уходит `goto done` МИМО отображения с защитой: у прочих ветвей
     * права ставит сам `anon_mmap_alloc`/`map_free_area` (аргумент `unix_prot`), а у guest32
     * хозяйская память уже есть — это окно, и `mprotect` там делает только
     * `hb_memory_guest32_map`. Но он знает лишь `perm` (R/W/X), пересчитанный из `vprot`
     * тремя строками выше, а `get_unix_prot` смотрит ЕЩЁ ТРИ вещи, которых в `perm` нет
     * в принципе:
     *     VPROT_COMMITTED  нет коммита -> PROT_NONE   (иначе резерв записываем)
     *     VPROT_GUARD      сторож      -> PROT_NONE   (иначе сторожевая страница записываема)
     *     VPROT_WRITEWATCH             -> снять PROT_WRITE
     * Отсюда правка: после `create_view` (он и заполняет побайтовый `vprot` страниц)
     * привести хозяйские права к ПОЛНОЙ правде Wine одним `mprotect_range`. Он же несёт
     * правило 16 КБ — `get_host_page_vprot` объединяет подстраницы через ИЛИ.
     *
     * Гейт MACRUNNER_HB_GUEST32_WINE_PROT, умолчание 0. Часть набора «правдивые-права-i386»
     * (reports/ГЕЙТЫ-НАБОРЫ.txt): в одиночку он ЗАКРОЕТ страницы, которые наша таблица
     * областей всё ещё считает записываемыми, и починка `guest32_sync_host_protection`
     * откроет их обратно — то есть без MACRUNNER_HB_GUEST32_HOST_PERM=1 и
     * MACRUNNER_HB_GUEST32_NO_REPAIR=1 правка даёт ноль, выглядящий выводом. */
    else if (mr_guest32_view)
    {
        static int mr_wine_prot_gate = -1;
        /* ★ ВЫШЕ ГЕЙТА, безусловно: иначе «не смотрел» и «гейт закрыт» дали бы
         * один и тот же ноль, а это и есть та путаница, ради которой прибор взят. */
        HB_PROBE_LOOKED(&pr_guest32_wineprot);
        if (mr_wine_prot_gate < 0)
        {
            const char *v = getenv( "MACRUNNER_HB_GUEST32_WINE_PROT" );
            mr_wine_prot_gate = (v && *v && *v != '0') ? 1 : 0;
        }
        if (mr_wine_prot_gate)
        {
            HB_PROBE_HIT(&pr_guest32_wineprot);
            /* ★ ПОТОЛКА «ПЕРВЫЕ 8» ЗДЕСЬ БЫТЬ НЕ ДОЛЖНО. Первая редакция печатала только
             * первые восемь представлений — и резерв самого гостя (он заводится позже
             * загрузчика) в печать не попал ВООБЩЕ. Выглядело как «правка не сработала».
             * Это ровно тот класс врущего прибора, что записан в reports/00-ПЕРЕД-ЛЮБЫМ-ДЕЛОМ.md
             * («печать ограничена n<=8 — считал строки, не отказы»). Теперь: счётчики без
             * потолка, печать первых 8 и каждого 64-го, и ОТДЕЛЬНО — каждое представление,
             * где Wine строже нашего `perm` (это и есть предмет правки). */
            int rc = mprotect_range( ptr, size, 0, 0 );
            int unix_wine = get_unix_prot( vprot );
            int unix_perm = 0;   /* что поставил бы hb_memory_guest32_map из одного `protect` */
            static unsigned mr_wp_n, mr_wp_fail, mr_wp_tighter;
            unsigned n;

            /* Те же три строки, что и в ветви guest32 выше (`protect` там локален):
             * WRITE|WRITECOPY -> R+W, иначе READ -> R, плюс EXEC. Ни коммита, ни сторожа,
             * ни writewatch здесь нет — в этом вся разница с `get_unix_prot`. */
            if (vprot & (VPROT_WRITE | VPROT_WRITECOPY)) unix_perm = PROT_READ | PROT_WRITE;
            else if (vprot & VPROT_READ)                 unix_perm = PROT_READ;
            if (vprot & VPROT_EXEC)                      unix_perm |= PROT_EXEC;

            n = ++mr_wp_n;
            if (rc) mr_wp_fail++;
            if ((unix_perm & ~unix_wine) != 0) mr_wp_tighter++;
            if (n <= 8 || (n % 64) == 0 || rc || (unix_perm & ~unix_wine) != 0)
            {
                /* ★ СПРОСИТЬ У ЯДРА, А НЕ ПОВЕРИТЬ `mprotect`. Тот же приём, что в
                 * `guest32_sync_host_protection` (замер 02.09: `mprotect` возвращал 0, а
                 * права не применялись). `rc=0` доказывает вызов, не результат. */
                mach_vm_address_t qa = (mach_vm_address_t)(uintptr_t)ptr;
                mach_vm_size_t qs = 0;
                vm_region_basic_info_data_64_t qi;
                mach_msg_type_number_t qc = VM_REGION_BASIC_INFO_COUNT_64;
                mach_port_t qo = MACH_PORT_NULL;
                unsigned qprot = 0xffff;
                if (mach_vm_region( mach_task_self(), &qa, &qs, VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&qi, &qc, &qo ) == KERN_SUCCESS)
                    qprot = (unsigned)qi.protection;
                fprintf( stderr, "macrunner-guest32-wineprot: n=%u %p-%p vprot=%02x wine=%d "
                                 "perm=%d rc=%d ядро=%x строже=%u отказов=%u\n",
                         n, ptr, (char *)ptr + size, (unsigned)(vprot & 0xff),
                         unix_wine, unix_perm, rc, qprot, mr_wp_tighter, mr_wp_fail );
            }
        }
    }
#else
    (void)mr_guest32_view;
#endif
    return status;
}


/***********************************************************************
 *           map_file_into_view
 *
 * Wrapper for mmap() to map a file into a view, falling back to read if mmap fails.
 * virtual_mutex must be held by caller.
 */
static BOOL macrunner_hb_is_x64_guest_image( const struct pe_image_info *image_info )
{
#if defined(__APPLE__) && defined(__aarch64__)
    const char *enabled = getenv( "MACRUNNER_HB_X64_LOADER" );

    /* ★ ШАГ-2 08.09.2026, договор T13 (20260907-ASTRA-WINE-FEX-CONTRACT-AUDIT.md:37).
     *
     * Ниже стоит ПОВТОРНОЕ чтение сырого MACRUNNER_HB_X64_LOADER через `||`, поэтому
     * УНАСЛЕДОВАННОЕ значение 1 возвращало классификацию образов HyperBridge даже после
     * того, как macrunner_cpu_backend_init() погасил кешированный флаг.  То есть выбранный
     * FEX получал регистрацию гостевых диапазонов, подмену базы релокаций и чужую
     * маршрутизацию отказов — ровно «ТИХИЙ неверный владелец» из аудита.
     *
     * Владелец CPU решает первым и безусловно. */
    if (macrunner_cpu_backend_disables_hb_semantics()) return FALSE;

    return (macrunner_hb_x64_loader || (enabled && enabled[0] && enabled[0] != '0')) &&
           current_machine == IMAGE_FILE_MACHINE_ARM64 &&
           image_info && image_info->machine == IMAGE_FILE_MACHINE_AMD64;
#else
    return FALSE;
#endif
}

/* MacRunner 2026-08-27 — НАСТОЯЩИЙ copy-on-write для секций гостевого образа.
 *
 * Windows отдаёт секциям образа PAGE_EXECUTE_WRITECOPY: гость пишет в свою .text
 * НЕ вызывая VirtualProtect, а ядро молча делает приватную копию страницы.  Именно
 * так ведёт себя SMACKW32.DLL из Diablo — держит данные в секции кода и правит их
 * атомарной операцией LOCK.  У нас страница выходила R-X, запись падала SIGBUS, и мы
 * лечили это в помощнике JIT — то есть чинили следствие.
 *
 * Право исполнения на хозяине этим страницам не нужно вовсе: гостевой i386-код
 * исполняет HyperBridge, а хозяйский процессор их только ЧИТАЕТ при трансляции.
 * Для x64-гостя это уже сделано (VPROT_MACRUNNER_X64_GUEST), для i386 — нет, хотя
 * путь исполнения тот же самый.  Сняв EXEC, мы получаем на WRITECOPY-странице
 * обычные R+W, стена W^X Apple Silicon в них не упирается, и COW делает ядро — без
 * единой нашей строки в горячем пути.
 *
 * Гейт MACRUNNER_HB_I386_GUEST_NOEXEC, умолчание ВЫКЛ до замера на двух мишенях. */
static BOOL macrunner_hb_i386_guest_noexec_enabled(void)
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = getenv( "MACRUNNER_HB_I386_GUEST_NOEXEC" );
        cached = (v && *v && *v != '0') ? 1 : 0;
    }
    return cached;
}

static BOOL macrunner_hb_is_i386_guest_image( const struct pe_image_info *image_info )
{
#if defined(__APPLE__) && defined(__aarch64__)
    return macrunner_hb_i386_guest_noexec_enabled() &&
           current_machine == IMAGE_FILE_MACHINE_ARM64 &&
           image_info && image_info->machine == IMAGE_FILE_MACHINE_I386;
#else
    return FALSE;
#endif
}

static BOOL macrunner_hb_strip_host_exec_for_image( const struct pe_image_info *image_info )
{
#if defined(__APPLE__) && defined(__aarch64__)
    return macrunner_hb_is_x64_guest_image( image_info ) ||
           macrunner_hb_is_i386_guest_image( image_info );
#else
    return FALSE;
#endif
}

static void macrunner_hb_protect_wow64_guest32_image_range( const struct pe_image_info *image_info,
                                                            void *base, SIZE_T size, BYTE vprot,
                                                            unsigned int map_prot )
{
#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
    ULONG_PTR guest_base = (ULONG_PTR)base;

    if (!is_win64 || !image_info || image_info->machine != IMAGE_FILE_MACHINE_I386) return;
    if (!guest_base || !size) return;
    (void)macrunner_hb_wow64_guest32_protect( guest_base, size, get_win32_prot( vprot, map_prot ) );
#endif
}

static BOOL macrunner_hb_trace_host_exec(void)
{
#if defined(__APPLE__) && defined(__aarch64__)
    static int enabled = -1;
    const char *env;

    if (enabled != -1) return enabled;
    env = getenv( "MACRUNNER_HB_TRACE_HOST_EXEC" );
    enabled = env && env[0] && env[0] != '0';
    return enabled;
#else
    return FALSE;
#endif
}

#if defined(__APPLE__) && defined(__aarch64__)
#define MACRUNNER_HB_X64_GUEST_RANGE_MAX 128
struct macrunner_hb_x64_guest_range
{
    char *base;
    SIZE_T size;
};

static struct macrunner_hb_x64_guest_range macrunner_hb_x64_guest_ranges[MACRUNNER_HB_X64_GUEST_RANGE_MAX];
static unsigned int macrunner_hb_x64_guest_range_count;

static BOOL macrunner_hb_range_overlaps( const void *base, size_t size, const void *range_base, size_t range_size )
{
    const char *start = base;
    const char *range_start = range_base;
    const char *end, *range_end;

    if (!size || !range_size) return FALSE;
    if (size > ~(SIZE_T)0 - (UINT_PTR)start ||
        range_size > ~(SIZE_T)0 - (UINT_PTR)range_start)
        return FALSE;
    end = start + size;
    range_end = range_start + range_size;
    return start < range_end && end > range_start;
}

static BOOL macrunner_hb_range_overlaps_x64_guest( const void *base, size_t size )
{
    unsigned int i;

    for (i = 0; i < macrunner_hb_x64_guest_range_count; i++)
    {
        if (macrunner_hb_range_overlaps( base, size, macrunner_hb_x64_guest_ranges[i].base,
                                         macrunner_hb_x64_guest_ranges[i].size ))
            return TRUE;
    }
    return FALSE;
}

BOOL macrunner_hb_is_registered_x64_guest_address( const void *addr )
{
    return addr && macrunner_hb_range_overlaps_x64_guest( addr, 1 );
}

BOOL macrunner_hb_is_current_x64_guest_view_address( const void *addr )
{
    struct file_view *view;
    BOOL ret = FALSE;

    if (!addr) return FALSE;
    mutex_lock( &virtual_mutex );
    view = find_view( addr, 1 );
    ret = view && (view->protect & VPROT_MACRUNNER_X64_GUEST);
    mutex_unlock( &virtual_mutex );
    return ret;
}

BOOL macrunner_hb_is_current_x64_guest_exec_address( const void *addr )
{
    struct file_view *view;
    BOOL ret = FALSE;

    if (!addr) return FALSE;
    mutex_lock( &virtual_mutex );
    view = find_view( addr, 1 );
    ret = view && (view->protect & VPROT_MACRUNNER_X64_GUEST) &&
          (get_page_vprot( addr ) & VPROT_EXEC);
    mutex_unlock( &virtual_mutex );
    return ret;
}

static void macrunner_hb_register_x64_guest_range( void *base, SIZE_T size )
{
    unsigned int i;

    if (!base || !size) return;
    for (i = 0; i < macrunner_hb_x64_guest_range_count; i++)
    {
        if (macrunner_hb_x64_guest_ranges[i].base == base &&
            macrunner_hb_x64_guest_ranges[i].size == size)
            return;
    }
    if (macrunner_hb_x64_guest_range_count >= MACRUNNER_HB_X64_GUEST_RANGE_MAX)
    {
        fprintf( stderr, "MacRunner x64 guest range table full, cannot register %p-%p\n",
             base, (char *)base + size );
        return;
    }
    macrunner_hb_x64_guest_ranges[macrunner_hb_x64_guest_range_count].base = base;
    macrunner_hb_x64_guest_ranges[macrunner_hb_x64_guest_range_count].size = size;
    macrunner_hb_x64_guest_range_count++;
    if (macrunner_hb_trace_host_exec())
        fprintf( stderr, "macrunner-host-exec-register-range: pid=%d base=%p size=%zx count=%u\n",
                 getpid(), base, (size_t)size, macrunner_hb_x64_guest_range_count );
}

extern int (*hb_guest_region_query_cb)( UINT64 addr, UINT64 *out_base,
                                       UINT64 *out_size, unsigned int *out_perm );

void macrunner_hb_note_x64_guest_fault_handlers_ready(void)
{
    unsigned int i;
    sigset_t sigset;

    macrunner_hb_x64_guest_fault_handlers_are_ready = TRUE;
    if (macrunner_hb_trace_host_exec())
        fprintf( stderr, "macrunner-host-exec-signal-ready: pid=%d ranges=%u\n",
                 getpid(), macrunner_hb_x64_guest_range_count );
    if (!macrunner_hb_x64_guest_range_count) return;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    for (i = 0; i < macrunner_hb_x64_guest_range_count; i++)
    {
        if (macrunner_hb_trace_host_exec())
            fprintf( stderr, "macrunner-host-exec-reprotect-range: pid=%d base=%p size=%zx\n",
                     getpid(), macrunner_hb_x64_guest_ranges[i].base,
                     (size_t)macrunner_hb_x64_guest_ranges[i].size );
        mprotect_range( macrunner_hb_x64_guest_ranges[i].base,
                        macrunner_hb_x64_guest_ranges[i].size, 0, 0 );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}
#else
static BOOL macrunner_hb_range_overlaps_x64_guest( const void *base, size_t size )
{
    return FALSE;
}
static void macrunner_hb_register_x64_guest_range( void *base, SIZE_T size )
{
}
void macrunner_hb_note_x64_guest_fault_handlers_ready(void)
{
}
#endif

/* MacRunner (Indiana Jones GOG v11, 29.09.2026): an image section that is both SHARED and WRITE is
 * mapped MAP_SHARED from the server's shared file.  With 16K host pages that only works when the section's
 * address, its offset in the shared file and its size are all host-page multiples; otherwise
 * map_file_into_view() refuses ("unaligned shared mapping ... not supported") and the whole image fails
 * with STATUS_INVALID_IMAGE_FORMAT (c000007b, "Bad EXE format").  Windows (4K pages) maps such images.
 * Fall back to a private copy of that one section: cross-process sharing of the section is lost, the
 * image loads.  TheGreatCircle.exe has one such section: .mydata, 12 bytes at RVA 0x72e2000. */
static BOOL macrunner_shared_section_needs_private( const struct file_view *view, const IMAGE_SECTION_HEADER *sec,
                                                   SIZE_T map_size, off_t *pos )
{
    UINT_PTR addr = (UINT_PTR)view->base + sec->VirtualAddress;
    BOOL at_view_end = sec->VirtualAddress + map_size >= view->size;

    if (!(addr & host_page_mask) && !(*pos & host_page_mask) && (at_view_end || !(map_size & host_page_mask)))
        return FALSE;
    fprintf( stderr, "macrunner-shared-section-private: section %.8s rva=%#x size=%#lx shared_pos=%#llx: "
             "not host-page aligned, mapped as a private copy\n", (const char *)sec->Name,
             (unsigned int)sec->VirtualAddress, (unsigned long)map_size, (unsigned long long)*pos );
    *pos += map_size;   /* keep the offsets of later shared sections in the shared file */
    return TRUE;
}

static NTSTATUS map_file_into_view( struct file_view *view, int fd, size_t start, size_t size,
                                    off_t offset, unsigned int vprot, BOOL removable, BOOL executable,
                                    BOOL host_executable )
{
    char *data_addr, *map_addr, *host_addr;
    char *view_end, *map_end, *data_end;
    size_t map_size, host_size;
    int prot = PROT_READ | PROT_WRITE;
    unsigned int flags = MAP_FIXED;

    if (start >= view->size || size > view->size - start) return STATUS_INVALID_PARAMETER;
    if (!round_size_checked( start, size, page_mask, &map_size )) return STATUS_INVALID_PARAMETER;

    if (vprot & VPROT_WRITE) flags |= MAP_SHARED;
    else if (vprot & VPROT_WRITECOPY) flags |= MAP_PRIVATE;
    else
    {
        /* code sections need a private mapping on macOS so they can be made executable. Non-executable read-only sections may be shared
         * session/data mappings (private = stale zero-filled snapshot), and so is the RX half of an anonymous-section W^X double mapping:
         * it aliases the writer's view (MacRunner 2026-09-29, alias_probe vp / alias_coherence). Only images and file-backed views stay private. */
#if defined(__linux__) || defined(__APPLE__)
        if (executable || ((vprot & VPROT_EXEC) && (vprot & SEC_FILE))) flags |= MAP_PRIVATE;
        else
        {
            flags |= MAP_SHARED;
            prot &= ~PROT_WRITE;
        }
#else
        flags |= MAP_SHARED;
        prot &= ~PROT_WRITE;
#endif
    }

    if (!get_view_limit( view, &view_end )) return STATUS_INVALID_PARAMETER;
    data_addr = (char *)view->base + start;
    map_addr = ROUND_ADDR( data_addr, page_mask );
    if (map_size > ~(UINT_PTR)0 - (UINT_PTR)map_addr) return STATUS_INVALID_PARAMETER;
    map_end = map_addr + map_size;
    data_end = map_addr + size;
    if (macrunner_hb_trace_host_exec() && executable)
        fprintf( stderr, "macrunner-host-exec-map-file: pid=%d view=%p base=%p start=%zx size=%zx vprot=%#x exec=%d host_exec=%d protect=%#x\n",
                 getpid(), view, map_addr, start, size, vprot, executable, host_executable, view->protect );
    host_addr = ROUND_ADDR( data_addr, host_page_mask );
    /* last page doesn't need to be a full page */
    if (map_end >= view_end) host_size = map_size;
    else if (!round_size_checked( 0, map_size, host_page_mask, &host_size )) return STATUS_INVALID_PARAMETER;

#if defined(__APPLE__) && defined(__aarch64__)
    if (host_executable)
        goto read_fallback;
#endif

    /* only try mmap if media is not removable (or if we require write access),
       and if alignment is correct */
    if ((!removable || (flags & MAP_SHARED)) && host_addr == map_addr && host_size == map_size)
    {
        if (mmap( host_addr, host_size, prot, flags, fd, offset ) != MAP_FAILED)
            return STATUS_SUCCESS;

        switch (errno)
        {
        case EINVAL:  /* file offset is not page-aligned, fall back to read() */
            break;
        case ENOEXEC:
        case ENODEV:  /* filesystem doesn't support mmap(), fall back to read() */
            if (vprot & VPROT_WRITE)
            {
                ERR( "shared writable mmap not supported, broken filesystem?\n" );
                return STATUS_NOT_SUPPORTED;
            }
            break;
        case EACCES:
        case EPERM:  /* access error, fall back to read() */
            if (vprot & VPROT_WRITE) return STATUS_ACCESS_DENIED;
            break;
        default:
            ERR( "mmap error %s, range %p-%p, unix_prot %#x\n",
                 strerror(errno), map_addr, map_end, prot );
            return STATUS_NO_MEMORY;
        }
    }

read_fallback:
    if (vprot & VPROT_WRITE)
    {
        ERR( "unaligned shared mapping %p-%p not supported\n", map_addr, map_end );
        return STATUS_INVALID_PARAMETER;
    }

#if defined(__APPLE__) && defined(__aarch64__)
    /* Apple Silicon enforces W^X for executable mappings.  The read fallback
     * only needs write access while copying bytes into the image view; the
     * final PE section protections below re-apply host execute permission for
     * native ARM64 code and keep x64 guest code non-executable on the host. */
    if (mprotect( host_addr, host_size, PROT_READ | PROT_WRITE ))
        return STATUS_ACCESS_DENIED;
#else
    if (mprotect( map_addr, map_size, PROT_READ | PROT_WRITE ))
        return STATUS_ACCESS_DENIED;
#endif
    if (size)
    {
        char *read_buf;
        size_t read_pos = 0;

        if (!(read_buf = malloc( size ))) return STATUS_NO_MEMORY;
        while (read_pos < size)
        {
            ssize_t ret = pread( fd, read_buf + read_pos, size - read_pos, offset + read_pos );

            if (ret < 0)
            {
                if (errno == EINTR) continue;
                ERR( "pread error %s, range %p-%p, offset %#llx\n",
                     strerror(errno), map_addr, data_end, (unsigned long long)(offset + read_pos) );
                free( read_buf );
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            if (!ret)
            {
                ERR( "short pread, range %p-%p, offset %#llx, read %zu of %zu\n",
                     map_addr, data_end, (unsigned long long)offset, read_pos, size );
                free( read_buf );
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            read_pos += ret;
        }
        memcpy( map_addr, read_buf, size );
        free( read_buf );
    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           get_committed_size
 *
 * Get the size of the committed range with equal masked vprot bytes starting at base.
 * Also return the protections for the first page.
 */
static SIZE_T get_committed_size( struct file_view *view, void *base, size_t max_size, BYTE *vprot, BYTE vprot_mask )
{
    SIZE_T offset, size;

    base = ROUND_ADDR( base, page_mask );
    offset = (char *)base - (char *)view->base;

    if (view->protect & SEC_RESERVE)
    {
        size = 0;

        *vprot = get_page_vprot( base );

        SERVER_START_REQ( get_mapping_committed_range )
        {
            req->base   = wine_server_client_ptr( view->base );
            req->offset = offset;
            if (!wine_server_call( req ))
            {
                size = min( reply->size, max_size );
                if (reply->committed)
                {
                    *vprot |= VPROT_COMMITTED;
                    set_page_vprot_bits( base, size, VPROT_COMMITTED, 0 );
                }
            }
        }
        SERVER_END_REQ;

        if (!size || !(vprot_mask & ~VPROT_COMMITTED)) return size;
    }
    else size = min( view->size - offset, max_size );

    return get_vprot_range_size( base, size, vprot_mask, vprot );
}


/***********************************************************************
 *           decommit_pages
 *
 * Decommit some pages of a given view.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS decommit_pages( struct file_view *view, char *base, size_t size )
{
    SIZE_T host_start_size;
    char *end, *host_end, *host_start;

    if (!round_size_checked( 0, (SIZE_T)base, host_page_mask, &host_start_size ))
        return STATUS_INVALID_PARAMETER;
    host_start = (char *)host_start_size;

    if (!size)
    {
        size = view->size;
        if (view->size > ~(SIZE_T)0 - (SIZE_T)host_start) return STATUS_INVALID_PARAMETER;
        host_end = host_start + view->size;
    }
    else
    {
        if (size > ~(SIZE_T)0 - (SIZE_T)base) return STATUS_INVALID_PARAMETER;
        end = base + size;
        host_end = ROUND_ADDR( end, host_page_mask );
    }

    if (host_start < host_end) anon_mmap_fixed( host_start, host_end - host_start, PROT_NONE, 0 );
    set_page_vprot_bits( base, size, 0, VPROT_COMMITTED );
    if (host_start < host_end) kernel_writewatch_register_range( view, host_start, host_end - host_start );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           remove_pages_from_view
 *
 * Remove some pages of a given view.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS remove_pages_from_view( struct file_view *view, char *base, size_t size )
{
    char *base_end, *view_end;

    assert( size < view->size );

    if (size > ~(SIZE_T)0 - (SIZE_T)base || !get_view_limit( view, &view_end ))
        return STATUS_INVALID_PARAMETER;
    base_end = base + size;

    if (view->base != base && base_end != view_end)
    {
        struct file_view *new_view = alloc_view();

        if (!new_view)
        {
            ERR( "out of memory for %p-%p\n", base, base_end );
            return STATUS_NO_MEMORY;
        }
        new_view->base    = base_end;
        new_view->size    = view_end - (char *)new_view->base;
        new_view->protect = view->protect;

        unregister_view( view );
        view->size = base - (char *)view->base;
        register_view( view );
        register_view( new_view );

        VIRTUAL_DEBUG_DUMP_VIEW( view );
        VIRTUAL_DEBUG_DUMP_VIEW( new_view );
    }
    else
    {
        unregister_view( view );
        if (view->base == base)
        {
            view->base = base_end;
            view->size -= size;
        }
        else view->size = base - (char *)view->base;

        register_view( view );
        VIRTUAL_DEBUG_DUMP_VIEW( view );
    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           free_pages_preserve_placeholder
 *
 * Turn pages of a given view into a placeholder.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS free_pages_preserve_placeholder( struct file_view *view, char *base, size_t size )
{
    SIZE_T host_size;
    char *base_end, *view_end;
    NTSTATUS status;

    if (!size) return STATUS_INVALID_PARAMETER_3;
    if (!(view->protect & VPROT_PLACEHOLDER)) return STATUS_CONFLICTING_ADDRESSES;
    if (view->protect & VPROT_FREE_PLACEHOLDER && size == view->size) return STATUS_CONFLICTING_ADDRESSES;
    if (size > ~(SIZE_T)0 - (SIZE_T)base || !get_view_limit( view, &view_end ))
        return STATUS_INVALID_PARAMETER;
    base_end = base + size;

    if (size < view->size)
    {
        if ((UINT_PTR)base & host_page_mask ||
            ((size & host_page_mask) && base_end != view_end))
        {
            ERR( "unaligned partial free %p-%p\n", base, base_end );
            return STATUS_CONFLICTING_ADDRESSES;
        }

        status = remove_pages_from_view( view, base, size );
        if (status) return status;

        { /* Итерация 311: назвать ВЫЗЫВАЮЩЕГО. Приём из 307 — печать с номером места,
           безусловная, первые 4 раза на место. Утверждение VPROT_SYSTEM воспроизводится 3/3,
           и место вызова — единственное, чего не хватает для разбора. */
          static int said_3658;
          if (said_3658++ < 4)
            fprintf(stderr, "macrunner-createview-site: место=3658\n"); }
        status = create_view( &view, base, size, VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER );
        if (status) return status;
    }

    view->protect = VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER;
    set_page_vprot( view->base, view->size, 0 );
    if (!round_size_checked( 0, view->size, host_page_mask, &host_size ))
        return STATUS_INVALID_PARAMETER;
    anon_mmap_fixed( view->base, host_size, PROT_NONE, 0 );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           free_pages
 *
 * Free some pages of a given view.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS free_pages( struct file_view *view, char *base, size_t size )
{
    SIZE_T host_base_size;
    char *base_end, *host_base, *host_end, *view_end;
    NTSTATUS status;

    if (!round_size_checked( 0, (SIZE_T)base, host_page_mask, &host_base_size ) ||
        size > ~(SIZE_T)0 - (SIZE_T)base || !get_view_limit( view, &view_end ))
        return STATUS_INVALID_PARAMETER;
    base_end = base + size;
    host_base = (char *)host_base_size;
    host_end = base_end;

    if (size == view->size)
    {
        assert( base == view->base );
        delete_view( view );
        return STATUS_SUCCESS;
    }

    /* new view needs to start on page boundary */

    if (view->base == base)  /* shrink from the start */
    {
        if (size & host_page_mask)
        {
            ERR( "unaligned partial free %p-%p\n", base, base_end );
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }
    else if (base_end < view_end)  /* create a hole */
    {
        if ((UINT_PTR)base_end & host_page_mask)
        {
            ERR( "unaligned partial free %p-%p\n", base, base_end );
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }

    status = remove_pages_from_view( view, base, size );
    if (!status)
    {
        set_page_vprot( base, size, 0 );
        if (view->protect & VPROT_ARM64EC) clear_arm64ec_range( base, size );
        if (host_base < host_end) unmap_area( host_base, host_end - host_base );
    }
    return status;
}


/***********************************************************************
 *           coalesce_placeholders
 *
 * Coalesce placeholder views.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS coalesce_placeholders( struct file_view *view, char *base, size_t size )
{
    struct rb_entry *next;
    struct file_view *curr_view, *next_view;
    unsigned int i, view_count = 0;
    size_t views_size = 0;

    if (!size) return STATUS_INVALID_PARAMETER_3;
    if (base != view->base) return STATUS_CONFLICTING_ADDRESSES;

    curr_view = view;
    while (curr_view->protect & VPROT_FREE_PLACEHOLDER)
    {
        char *curr_end;

        if (!get_view_limit( curr_view, &curr_end ) || curr_view->size > ~(size_t)0 - views_size)
            return STATUS_CONFLICTING_ADDRESSES;
        ++view_count;
        views_size += curr_view->size;
        if (views_size >= size) break;
        if (!(next = rb_next( &curr_view->entry ))) break;
        next_view = RB_ENTRY_VALUE( next, struct file_view, entry );
        if (curr_end != next_view->base) break;
        curr_view = next_view;
    }

    if (view_count < 2 || size != views_size) return STATUS_CONFLICTING_ADDRESSES;

    for (i = 1; i < view_count; ++i)
    {
        curr_view = RB_ENTRY_VALUE( rb_next( &view->entry ), struct file_view, entry );
        unregister_view( curr_view );
        free_view( curr_view );
    }

    unregister_view( view );
    view->size = views_size;
    register_view( view );

    VIRTUAL_DEBUG_DUMP_VIEW( view );

    return STATUS_SUCCESS;
}


/***********************************************************************
 *           allocate_dos_memory
 *
 * Allocate the DOS memory range.
 */
static NTSTATUS allocate_dos_memory( struct file_view **view, unsigned int vprot )
{
    size_t size;
    void *addr = NULL;
    void * const low_64k = (void *)0x10000;
    const size_t dosmem_size = 0x110000;
    int unix_prot = get_unix_prot( vprot ) & ~PROT_EXEC;

    /* check for existing view */

    if (find_view_range( 0, dosmem_size )) return STATUS_CONFLICTING_ADDRESSES;

    /* check without the first 64K */

    if (mmap_is_in_reserved_area( low_64k, dosmem_size - 0x10000 ) != 1)
    {
        addr = anon_mmap_tryfixed( low_64k, dosmem_size - 0x10000, unix_prot, 0 );
        if (addr == MAP_FAILED) return map_view( view, NULL, dosmem_size, 0, vprot, 0, 0, 0 );
    }

    /* now try to allocate the low 64K too */

    if (mmap_is_in_reserved_area( NULL, 0x10000 ) != 1)
    {
        addr = anon_mmap_tryfixed( (void *)host_page_size, 0x10000 - host_page_size, unix_prot, 0 );
        if (addr != MAP_FAILED)
        {
            if (!anon_mmap_fixed( NULL, host_page_size, unix_prot, 0 ))
            {
                addr = NULL;
                TRACE( "successfully mapped low 64K range\n" );
            }
            else TRACE( "failed to map page 0\n" );
        }
        else
        {
            addr = low_64k;
            TRACE( "failed to map low 64K range\n" );
        }
    }

    /* now reserve the whole range */

    size = (char *)dosmem_size - (char *)addr;
    anon_mmap_fixed( addr, size, unix_prot, 0 );
    { /* Итерация 311: назвать ВЫЗЫВАЮЩЕГО. Приём из 307 — печать с номером места,
       безусловная, первые 4 раза на место. Утверждение VPROT_SYSTEM воспроизводится 3/3,
       и место вызова — единственное, чего не хватает для разбора. */
      static int said_3828;
      if (said_3828++ < 4)
        fprintf(stderr, "macrunner-createview-site: место=3828\n"); }
    return create_view( view, addr, size, vprot );
}


/***********************************************************************
 *           map_pe_header
 *
 * Map the header of a PE file into memory.
 */
static NTSTATUS map_pe_header( void *ptr, size_t size, size_t map_size, int fd, BOOL *removable )
{
    ssize_t ret;

    if (!size) return STATUS_INVALID_IMAGE_FORMAT;

    map_size &= ~host_page_mask;

    if (!*removable && map_size)
    {
        if (mmap( ptr, map_size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, fd, 0 ) != MAP_FAILED)
        {
            if (size > map_size)
            {
                ret = pread( fd, (char *)ptr + map_size, size - map_size, map_size );
                if (ret != size - map_size)
                    return ret < 0 ? errno_to_status( errno ) : STATUS_INVALID_IMAGE_FORMAT;
            }
            return STATUS_SUCCESS;
        }
        switch (errno)
        {
        case EPERM:
        case EACCES:
            WARN( "noexec file system, falling back to read\n" );
            break;
        case ENOEXEC:
        case ENODEV:
            WARN( "file system doesn't support mmap, falling back to read\n" );
            break;
        default:
            ERR( "mmap error %s, range %p-%p\n", strerror(errno), ptr, (char *)ptr + size );
            return STATUS_NO_MEMORY;
        }
        *removable = TRUE;
    }
    ret = pread( fd, ptr, size, 0 );
    if (ret != size) return ret < 0 ? errno_to_status( errno ) : STATUS_INVALID_IMAGE_FORMAT;
    return STATUS_SUCCESS;  /* page protections will be updated later */
}

#ifdef _WIN64

/***********************************************************************
 *           get_host_addr_space_limit
 */
static void *get_host_addr_space_limit(void)
{
#if defined(__APPLE__) && defined(__aarch64__)
    const char *arena = getenv( "MACRUNNER_VM_ARENA" );
    if (arena && !strcmp( arena, "1" )) return (void *)(UINT_PTR)MACH_VM_MAX_ADDRESS;
#endif
    unsigned int flags = MAP_PRIVATE | MAP_ANON;
    UINT_PTR addr = (UINT_PTR)1 << 63;

#ifdef MAP_FIXED_NOREPLACE
    flags |= MAP_FIXED_NOREPLACE;
#endif

    while (addr >> 32)
    {
        void *ret = mmap( (void *)addr, host_page_size, PROT_NONE, flags, -1, 0 );
        if (ret != MAP_FAILED)
        {
            munmap( ret, host_page_size );
            if (ret >= (void *)addr) break;
        }
        else if (errno == EEXIST) break;
        addr >>= 1;
    }
    return (void *)((addr << 1) - (granularity_mask + 1));
}

#endif /* _WIN64 */

#ifdef __aarch64__

/***********************************************************************
 *           alloc_arm64ec_map
 */
static void alloc_arm64ec_map(void)
{
    unsigned int status;
    SIZE_T size = ((ULONG_PTR)address_space_limit + page_size) >> (page_shift + 3);  /* one bit per page */

    if (!round_size_checked( 0, size, host_page_mask, &size ))
    {
        ERR( "failed to round ARM64EC map size\n" );
        exit(1);
    }
    status = map_view( &arm64ec_view, NULL, size, MEM_TOP_DOWN, VPROT_READ | VPROT_COMMITTED, 0, 0, 0 );
    if (status)
    {
        ERR( "failed to allocate ARM64EC map: %08x\n", status );
        exit(1);
    }
    peb->EcCodeBitMap = arm64ec_view->base;
}

static BOOL arm64ec_rva_array_fits_view( const struct file_view *view, ULONG rva, ULONG count,
                                          size_t elem_size )
{
    if (!count) return TRUE;
    if (!rva || view->size < elem_size || rva > view->size - elem_size) return FALSE;
    return count <= (view->size - rva) / elem_size;
}


/***********************************************************************
 *           update_arm64ec_ranges
 */
static void update_arm64ec_ranges( struct file_view *view, IMAGE_NT_HEADERS *nt,
                                   const IMAGE_DATA_DIRECTORY *dir, UINT *entry_point )
{
    const IMAGE_ARM64EC_METADATA *metadata;
    const IMAGE_CHPE_RANGE_ENTRY *map;
    char *base = view->base;
    const IMAGE_LOAD_CONFIG_DIRECTORY *cfg = (void *)(base + dir->VirtualAddress);
    ULONGLONG metadata_va, metadata_rva;
    ULONG_PTR redirected_entry;
    ULONG i, size;

    if (dir->Size < sizeof(cfg->Size)) return;
    size = min( dir->Size, cfg->Size );
    if (size < offsetof( IMAGE_LOAD_CONFIG_DIRECTORY, CHPEMetadataPointer ) +
               sizeof(cfg->CHPEMetadataPointer)) return;
    metadata_va = cfg->CHPEMetadataPointer;
    if (!metadata_va || metadata_va < nt->OptionalHeader.ImageBase) return;
    metadata_rva = metadata_va - nt->OptionalHeader.ImageBase;
    if (view->size < sizeof(*metadata) || metadata_rva > view->size - sizeof(*metadata)) return;
    metadata = (void *)(base + metadata_rva);
    if (metadata->RedirectionMetadataCount > INT_MAX) return;
    if (!arm64ec_rva_array_fits_view( view, metadata->RedirectionMetadata,
                                      metadata->RedirectionMetadataCount,
                                      sizeof(IMAGE_ARM64EC_REDIRECTION_ENTRY) ))
        return;
    if (!arm64ec_view) alloc_arm64ec_map();
    commit_arm64ec_map( view );
    redirected_entry = metadata->RedirectionMetadataCount
                       ? redirect_arm64ec_rva( base, nt->OptionalHeader.AddressOfEntryPoint, metadata )
                       : nt->OptionalHeader.AddressOfEntryPoint;
    if (redirected_entry > UINT_MAX || redirected_entry >= view->size) return;
    *entry_point = redirected_entry;
    if (!metadata->CodeMap || !metadata->CodeMapCount) return;
    if (!arm64ec_rva_array_fits_view( view, metadata->CodeMap, metadata->CodeMapCount,
                                      sizeof(*map) ))
        return;
    map = (void *)(base + metadata->CodeMap);

    for (i = 0; i < metadata->CodeMapCount; i++)
    {
        ULONG rva = map[i].StartOffset & ~3;

        if ((map[i].StartOffset & 0x3) != 1 /* arm64ec */) continue;
        if (rva > view->size || map[i].Length > view->size - rva ||
            (ULONG_PTR)base > ~(ULONG_PTR)0 - rva)
            continue;
        set_arm64ec_range( base + rva, map[i].Length );
    }
}


/***********************************************************************
 *           apply_arm64x_relocations
 */
static BOOL arm64x_fixup_fits_view( size_t total_size, ULONG page_rva, USHORT offset, size_t size )
{
    if (page_rva >= total_size || offset >= total_size - page_rva) return FALSE;
    return size <= total_size - page_rva - offset;
}

/* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1123 — ПРИБОР НА ПРЕВРАЩЕНИЕ ОБРАЗА ARM64X.
 *
 * Здесь образ ARM64X переводится в вид ARM64EC: правки типов ZEROFILL/VALUE/DELTA переписывают
 * и код, и УКАЗАТЕЛИ В ДАННЫХ. Любая неудача возвращает FALSE, а вызывающий просто выходит —
 * МОЛЧА, оставляя образ переведённым НАПОЛОВИНУ. Ровно такое состояние мы и наблюдаем в
 * kernelbase: `GetACP()` отдаёт 1252 (поле CodePage заполнено), а указатель таблицы в той же
 * структуре пуст, и свёртка падает на `ldrb w9,[x21,x9]` с x21=0 (итерация 1122).
 *
 * Пока прибора нет, «наполовину» и «полностью» неразличимы. Считаем применённые правки по типам
 * и печатаем итог — с указанием, дошли ли до конца потока. */
static unsigned long long g_a64x_zero, g_a64x_value, g_a64x_delta;

static BOOL apply_arm64x_relocations( char *base, const IMAGE_BASE_RELOCATION *reloc, size_t size,
                                      size_t total_size )
{
    const char *end = (const char *)reloc + size;

    while ((const char *)reloc + sizeof(*reloc) <= end && reloc->SizeOfBlock)
    {
        size_t remaining = end - (const char *)reloc;
        const USHORT *rel = (const USHORT *)(reloc + 1);
        const USHORT *rel_end;
        char *page;

        if (reloc->SizeOfBlock < sizeof(*reloc) || reloc->SizeOfBlock > remaining ||
            (reloc->SizeOfBlock - sizeof(*reloc)) % sizeof(USHORT) ||
            reloc->VirtualAddress >= total_size)
            return FALSE;
        rel_end = (const USHORT *)((const char *)reloc + reloc->SizeOfBlock);
        page = base + reloc->VirtualAddress;

        while (rel < rel_end && *rel)
        {
            USHORT offset = *rel & 0xfff;
            USHORT type = (*rel >> 12) & 3;
            USHORT arg = *rel >> 14;
            size_t fixup_size = type == IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA
                                ? sizeof(int) : 1u << arg;
            int val;
            rel++;
            if (!arm64x_fixup_fits_view( total_size, reloc->VirtualAddress, offset, fixup_size )) return FALSE;
            switch (type)
            {
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL:
                memset( page + offset, 0, fixup_size );
                g_a64x_zero++;
                break;
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE:
            {
                size_t value_words = (fixup_size + sizeof(USHORT) - 1) / sizeof(USHORT);
                if ((size_t)(rel_end - rel) < value_words) return FALSE;
                memcpy( page + offset, rel, fixup_size );
                rel += value_words;
                g_a64x_value++;
                break;
            }
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA:
                if (rel >= rel_end) return FALSE;
                val = (unsigned int)*rel++ * ((arg & 2) ? 8 : 4);
                if (arg & 1) val = -val;
                *(int *)(page + offset) += val;
                g_a64x_delta++;
                break;
            default:
                return FALSE;
            }
        }
        reloc = (const IMAGE_BASE_RELOCATION *)rel_end;
    }
    return TRUE;
}


/***********************************************************************
 *           update_arm64x_mapping
 */
/* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1143 — НАБЛЮДАТЕЛЬ ЗА ЯЧЕЙКОЙ ОБРАЗА.
 *
 * Серия 1122-1142 свела отказ гостя x64 к одному: в `kernelbase+0x152910` (глобаль
 * `ansi_cpinfo` набора ARM64) вместо нуля лежит мусор, из-за чего ленивая инициализация
 * пропускается и таблица кодовой страницы остаётся пустой. Доказано, что мусор НЕ из файла
 * (1142) и что при отображении хвост секции обнуляется (1141). Значит его пишет код между
 * отображением и входом в гостя — и найти писателя можно только печатью по вехам.
 *
 * Гейт: MACRUNNER_HB_WATCH_RVA=<hex>. Печатается для КАЖДОГО образа, где такое смещение
 * существует; различать образы по базе. */
char *macrunner_hb_watch_bases[16];
unsigned macrunner_hb_watch_n;
ULONG_PTR macrunner_hb_watch_rva_value;

static void macrunner_hb_watch_rva( const char *stage, char *base, SIZE_T image_size )
{
    static int cached = -2;
    static ULONG_PTR rva;
    const unsigned char *p;

    if (cached == -2)
    {
        const char *e = getenv( "MACRUNNER_HB_WATCH_RVA" );
        rva = (e && *e) ? (ULONG_PTR)strtoull( e, NULL, 0 ) : 0;
        cached = rva ? 1 : 0;
    }
    if (cached <= 0 || !base || rva + 16 > image_size) return;
    p = (const unsigned char *)base + rva;
    /* Итерация 1144: запоминаем базы, чтобы ТУ ЖЕ ячейку можно было перечитать позже, перед
     * передачей управления гостю, В ТОМ ЖЕ ПРОЦЕССЕ. Сопоставление по базе между процессами
     * (как в 1143) — неполное доказательство, и я это уже трижды оплатил. */
    if (macrunner_hb_watch_n < 16)
    {
        unsigned wi;
        for (wi = 0; wi < macrunner_hb_watch_n; wi++)
            if (macrunner_hb_watch_bases[wi] == base) break;
        if (wi == macrunner_hb_watch_n) macrunner_hb_watch_bases[macrunner_hb_watch_n++] = base;
    }
    macrunner_hb_watch_rva_value = rva;
    fprintf( stderr, "macrunner-hb-watch: pid=%d этап=%s база=%p rva=0x%llx: "
                     "%02x %02x %02x %02x %02x %02x %02x %02x\n",
             (int)getpid(), stage, (void *)base, (unsigned long long)rva,
             p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7] );
    fflush( stderr );
}

static void update_arm64x_mapping( struct file_view *view, IMAGE_NT_HEADERS *nt,
                                   const IMAGE_DATA_DIRECTORY *dir, IMAGE_SECTION_HEADER *sections )
{
    const IMAGE_DYNAMIC_RELOCATION_TABLE *table;
    const char *ptr, *end;
    char *base = view->base;
    const IMAGE_LOAD_CONFIG_DIRECTORY *cfg = (void *)(base + dir->VirtualAddress);
    ULONG sec, offset, size, section_rva, section_size;

    if (dir->Size < sizeof(cfg->Size)) return;
    size = min( dir->Size, cfg->Size );
    if (size < offsetof( IMAGE_LOAD_CONFIG_DIRECTORY, DynamicValueRelocTableSection ) +
               sizeof(cfg->DynamicValueRelocTableSection)) return;
    offset = cfg->DynamicValueRelocTableOffset;
    sec = cfg->DynamicValueRelocTableSection;
    if (!sec || sec > nt->FileHeader.NumberOfSections) return;
    section_rva = sections[sec - 1].VirtualAddress;
    section_size = sections[sec - 1].Misc.VirtualSize;
    if (section_rva >= view->size || section_size > view->size - section_rva) return;
    if (section_size < sizeof(*table) || offset > section_size - sizeof(*table)) return;
    table = (const IMAGE_DYNAMIC_RELOCATION_TABLE *)(base + section_rva + offset);
    ptr = (const char *)(table + 1);
    if (table->Size > section_size - offset - sizeof(*table)) return;
    end = ptr + table->Size;
    switch (table->Version)
    {
    case 1:
        while (ptr < end)
        {
            const IMAGE_DYNAMIC_RELOCATION64 *dyn = (const IMAGE_DYNAMIC_RELOCATION64 *)ptr;
            size_t remaining = end - ptr;
            if (remaining < sizeof(*dyn) || dyn->BaseRelocSize > remaining - sizeof(*dyn)) return;
            if (dyn->Symbol == IMAGE_DYNAMIC_RELOCATION_ARM64X)
            {
                BOOL ok = apply_arm64x_relocations( base, (const IMAGE_BASE_RELOCATION *)(dyn + 1),
                                                    dyn->BaseRelocSize, view->size );
                fprintf( stderr, "macrunner-hb-arm64x: pid=%d base=%p версия=1 успех=%d "
                                 "zero=%llu value=%llu delta=%llu\n",
                         (int)getpid(), base, ok, g_a64x_zero, g_a64x_value, g_a64x_delta );
                fflush( stderr );
                if (!ok) return;
                break;
            }
            ptr += sizeof(*dyn) + dyn->BaseRelocSize;
        }
        break;
    case 2:
        while (ptr < end)
        {
            const IMAGE_DYNAMIC_RELOCATION64_V2 *dyn = (const IMAGE_DYNAMIC_RELOCATION64_V2 *)ptr;
            size_t remaining = end - ptr;
            if (remaining < sizeof(*dyn) || dyn->HeaderSize < sizeof(*dyn) ||
                dyn->HeaderSize > remaining || dyn->FixupInfoSize > remaining - dyn->HeaderSize)
                return;
            if (dyn->Symbol == IMAGE_DYNAMIC_RELOCATION_ARM64X)
            {
                if (!apply_arm64x_relocations( base, (const IMAGE_BASE_RELOCATION *)(ptr + dyn->HeaderSize),
                                               dyn->FixupInfoSize, view->size ))
                    return;
                break;
            }
            ptr += dyn->HeaderSize + dyn->FixupInfoSize;
        }
        break;
    default:
        FIXME( "unsupported version %u\n", table->Version );
        break;
    }
}

#endif  /* __aarch64__ */

/***********************************************************************
 *           get_data_dir
 */
static IMAGE_DATA_DIRECTORY *get_data_dir( IMAGE_NT_HEADERS *nt, SIZE_T total_size, ULONG dir )
{
    IMAGE_DATA_DIRECTORY *data;

    if (dir >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;
    switch (nt->OptionalHeader.Magic)
    {
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        if (dir >= ((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.NumberOfRvaAndSizes) return NULL;
        if (((IMAGE_NT_HEADERS64 *)nt)->FileHeader.SizeOfOptionalHeader <
            offsetof( IMAGE_OPTIONAL_HEADER64, DataDirectory ) + (dir + 1) * sizeof(IMAGE_DATA_DIRECTORY))
            return NULL;
        data = &((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.DataDirectory[dir];
        break;
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        if (dir >= ((IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.NumberOfRvaAndSizes) return NULL;
        if (((IMAGE_NT_HEADERS32 *)nt)->FileHeader.SizeOfOptionalHeader <
            offsetof( IMAGE_OPTIONAL_HEADER32, DataDirectory ) + (dir + 1) * sizeof(IMAGE_DATA_DIRECTORY))
            return NULL;
        data = &((IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.DataDirectory[dir];
        break;
    default:
        return NULL;
    }
    if (!data->Size) return NULL;
    if (!data->VirtualAddress) return NULL;
    if (data->VirtualAddress >= total_size) return NULL;
    if (data->Size > total_size - data->VirtualAddress) return NULL;
    return data;
}


/***********************************************************************
 *           process_relocation_block
 *
 * Reimplementation of LdrProcessRelocationBlock.
 */
static BOOL relocation_block_targets_fit_image( const IMAGE_BASE_RELOCATION *rel, ULONG total_size )
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
        case IMAGE_REL_BASED_DIR64:
            size = sizeof(INT64);
            break;
        case IMAGE_REL_BASED_THUMB_MOV32:
            size = 2 * sizeof(UINT);
            break;
        default:
            return FALSE;
        }
        if (rel->VirtualAddress > total_size || offset > total_size - rel->VirtualAddress) return FALSE;
        rva = rel->VirtualAddress + offset;
        if (size > total_size - rva) return FALSE;
    }
    return TRUE;
}

static BOOL is_valid_relocation_block( const IMAGE_BASE_RELOCATION *rel, const IMAGE_BASE_RELOCATION *end,
                                       ULONG total_size )
{
    SIZE_T remaining = (const char *)end - (const char *)rel;

    if (rel->SizeOfBlock < sizeof(*rel) || rel->SizeOfBlock > remaining ||
        (rel->SizeOfBlock - sizeof(*rel)) % sizeof(USHORT))
        return FALSE;
    return rel->VirtualAddress < total_size && relocation_block_targets_fit_image( rel, total_size );
}

static IMAGE_BASE_RELOCATION *process_relocation_block( char *page, IMAGE_BASE_RELOCATION *rel,
                                                        INT_PTR delta )
{
    USHORT *reloc = (USHORT *)(rel + 1);
    unsigned int count;

    for (count = (rel->SizeOfBlock - sizeof(*rel)) / sizeof(USHORT); count; count--, reloc++)
    {
        USHORT offset = *reloc & 0xfff;
        switch (*reloc >> 12)
        {
        case IMAGE_REL_BASED_ABSOLUTE:
            break;
        case IMAGE_REL_BASED_HIGH:
            *(short *)(page + offset) += HIWORD(delta);
            break;
        case IMAGE_REL_BASED_LOW:
            *(short *)(page + offset) += LOWORD(delta);
            break;
        case IMAGE_REL_BASED_HIGHLOW:
            *(int *)(page + offset) += delta;
            break;
        case IMAGE_REL_BASED_HIGHADJ:
            if (count < 2) return NULL;
            *(short *)(page + offset) += HIWORD( delta + (short)reloc[1] );
            reloc++;
            count--;
            break;
        case IMAGE_REL_BASED_DIR64:
            *(INT64 *)(page + offset) += delta;
            break;
        case IMAGE_REL_BASED_THUMB_MOV32:
        {
            DWORD *inst = (DWORD *)(page + offset);
            WORD lo = ((inst[0] << 1) & 0x0800) + ((inst[0] << 12) & 0xf000) +
                      ((inst[0] >> 20) & 0x0700) + ((inst[0] >> 16) & 0x00ff);
            WORD hi = ((inst[1] << 1) & 0x0800) + ((inst[1] << 12) & 0xf000) +
                      ((inst[1] >> 20) & 0x0700) + ((inst[1] >> 16) & 0x00ff);
            DWORD imm = MAKELONG( lo, hi ) + delta;

            lo = LOWORD( imm );
            hi = HIWORD( imm );
            inst[0] = (inst[0] & 0x8f00fbf0) + ((lo >> 1) & 0x0400) + ((lo >> 12) & 0x000f) +
                                               ((lo << 20) & 0x70000000) + ((lo << 16) & 0xff0000);
            inst[1] = (inst[1] & 0x8f00fbf0) + ((hi >> 1) & 0x0400) + ((hi >> 12) & 0x000f) +
                                               ((hi << 20) & 0x70000000) + ((hi << 16) & 0xff0000);
            break;
        }
        default:
            FIXME( "Unknown/unsupported relocation %x\n", *reloc );
            return NULL;
        }
    }
    return (IMAGE_BASE_RELOCATION *)reloc;  /* return address of next block */
}


/***********************************************************************
 *           map_image_into_view
 *
 * Map an executable (PE format) image into an existing view.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS map_image_into_view( struct file_view *view, const UNICODE_STRING *nt_name, int fd,
                                     struct pe_image_info *image_info, USHORT machine,
                                     int shared_fd, BOOL removable )
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sections = NULL, *sec;
    IMAGE_DATA_DIRECTORY *imports, *dir;
    NTSTATUS status = STATUS_CONFLICTING_ADDRESSES;
    int i;
    off_t pos;
    struct stat st;
    char *header_end;
    char *ptr = view->base;
    SIZE_T file_host_size, file_page_size, file_sector_size, header_size, header_map_size, header_span;
    SIZE_T rounded_size, total_size = view->size;
    SIZE_T align_mask;
    INT_PTR delta;

    if (!image_info->alignment) return STATUS_INVALID_IMAGE_FORMAT;
    align_mask = max( image_info->alignment - 1, page_mask );

    TRACE_(module)( "mapping PE file %s at %p-%p\n", debugstr_us(nt_name), ptr, ptr + total_size );

    /* map the header */

    if (fstat( fd, &st )) return errno_to_status( errno );
    if (st.st_size < 0) return STATUS_INVALID_IMAGE_FORMAT;
    if (!round_size_checked( 0, st.st_size, host_page_mask, &file_host_size ) ||
        !round_size_checked( 0, st.st_size, page_mask, &file_page_size ) ||
        !round_size_checked( 0, st.st_size, 0x1ff, &file_sector_size ))
        return STATUS_INVALID_IMAGE_FORMAT;
    header_size = min( image_info->header_size, st.st_size );
    header_map_size = min( image_info->header_map_size, file_host_size );
    if ((status = map_pe_header( view->base, header_size, header_map_size, fd, &removable )))
        return status;

    status = STATUS_INVALID_IMAGE_FORMAT;  /* generic error */
    dos = (IMAGE_DOS_HEADER *)ptr;
    if (!round_size_checked( 0, header_size, align_mask, &header_span ) || header_span > total_size)
        return status;
    header_end = ptr + header_span;
    memset( ptr + header_size, 0, header_end - (ptr + header_size) );
    if (header_end - ptr < sizeof(*nt) ||
        (SIZE_T)dos->e_lfanew > header_end - ptr - sizeof(*nt))
        return status;
    nt = (IMAGE_NT_HEADERS *)(ptr + dos->e_lfanew);
    if ((char *)(nt + 1) > header_end) return status;
    sec = IMAGE_FIRST_SECTION( nt );
    if ((char *)(sec + nt->FileHeader.NumberOfSections) > header_end) return status;
    if ((char *)(sec + nt->FileHeader.NumberOfSections) > ptr + header_map_size)
    {
        /* copy section data since it will get overwritten by a section mapping */
        if (!(sections = malloc( sizeof(*sections) * nt->FileHeader.NumberOfSections )))
            return STATUS_NO_MEMORY;
        memcpy( sections, sec, sizeof(*sections) * nt->FileHeader.NumberOfSections );
        sec = sections;
    }
    imports = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_IMPORT );

    /* check for non page-aligned binary */

    if (image_info->image_flags & IMAGE_FLAGS_ImageMappedFlat)
    {
        /* unaligned sections, this happens for native subsystem binaries */
        /* in that case Windows simply maps in the whole file */

        total_size = min( total_size, file_page_size );
        if (map_file_into_view( view, fd, 0, total_size, 0, VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY,
                                removable, TRUE,
                                !macrunner_hb_strip_host_exec_for_image( image_info ) ) != STATUS_SUCCESS)
            goto done;

        /* check that all sections are loaded at the right offset */
        if (nt->OptionalHeader.FileAlignment != nt->OptionalHeader.SectionAlignment) goto done;
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            if (sec[i].VirtualAddress != sec[i].PointerToRawData)
                goto done;  /* Windows refuses to load in that case too */
        }

        /* set the image protections */
        set_vprot( view, ptr, total_size, VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY | VPROT_EXEC );
        macrunner_hb_protect_wow64_guest32_image_range( image_info, ptr, total_size,
                                                        VPROT_COMMITTED | VPROT_READ |
                                                        VPROT_WRITECOPY | VPROT_EXEC,
                                                        view->protect );

        /* no relocations are performed on non page-aligned binaries */
        status = STATUS_SUCCESS;
        goto done;
    }


    /* map all the sections */

    for (i = pos = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        static const SIZE_T sector_align = 0x1ff;
        SIZE_T map_size, file_start, file_size, end;

        if (!sec[i].Misc.VirtualSize)
        {
            if (!round_size_checked( 0, sec[i].SizeOfRawData, align_mask, &map_size ))
                goto done;
        }
        else
        {
            if (!round_size_checked( 0, sec[i].Misc.VirtualSize, align_mask, &map_size ))
                goto done;
        }

        /* file positions are rounded to sector boundaries regardless of OptionalHeader.FileAlignment */
        file_start = sec[i].PointerToRawData & ~sector_align;
        if (!round_size_checked( sec[i].PointerToRawData, sec[i].SizeOfRawData, sector_align, &file_size ))
            goto done;
        if (file_size > map_size) file_size = map_size;

        /* a few sanity checks */
        if (!round_size_checked( sec[i].VirtualAddress, map_size, align_mask, &rounded_size ))
            goto done;
        if (sec[i].VirtualAddress > total_size || rounded_size > total_size - sec[i].VirtualAddress)
        {
            WARN_(module)( "%s section %.8s too large (%x+%lx/%lx)\n",
                           debugstr_us(nt_name), sec[i].Name, sec[i].VirtualAddress, map_size, total_size );
            goto done;
        }
        end = sec[i].VirtualAddress + rounded_size;

        if ((sec[i].Characteristics & IMAGE_SCN_MEM_SHARED) &&
            (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
            !macrunner_shared_section_needs_private( view, &sec[i], map_size, &pos ))
        {
            BOOL executable = !!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE);
            BOOL host_executable = executable && !macrunner_hb_strip_host_exec_for_image( image_info );
            SIZE_T section_end = end;

            TRACE_(module)( "%s mapping shared section %.8s at %p off %x (%x) size %lx (%lx) flags %x\n",
                            debugstr_us(nt_name), sec[i].Name, ptr + sec[i].VirtualAddress,
                            sec[i].PointerToRawData, (int)pos, file_size, map_size,
                            sec[i].Characteristics );
            if (map_file_into_view( view, shared_fd, sec[i].VirtualAddress, map_size, pos,
                                    VPROT_COMMITTED | VPROT_READ | VPROT_WRITE, FALSE,
                                    executable, host_executable ) != STATUS_SUCCESS)
            {
                ERR_(module)( "Could not map %s shared section %.8s\n", debugstr_us(nt_name), sec[i].Name );
                goto done;
            }

            /* check if the import directory falls inside this section */
            if (imports && imports->VirtualAddress >= sec[i].VirtualAddress &&
                imports->VirtualAddress - sec[i].VirtualAddress < map_size)
            {
                UINT_PTR base = imports->VirtualAddress & ~host_page_mask;
                SIZE_T size;
                UINT_PTR end;

                if (!round_size_checked( imports->VirtualAddress, imports->Size, host_page_mask, &size ))
                    goto done;
                if (base < sec[i].VirtualAddress) base = sec[i].VirtualAddress;
                end = (size > ~(UINT_PTR)0 - base) ? section_end : base + size;
                if (end > section_end) end = section_end;
                if (end > base)
                    map_file_into_view( view, shared_fd, base, end - base,
                                        pos + (base - sec[i].VirtualAddress),
                                        VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY, FALSE, FALSE, FALSE );
            }
            pos += map_size;
            continue;
        }

        TRACE_(module)( "mapping %s section %.8s at %p off %x size %x virt %x flags %x\n",
                        debugstr_us(nt_name), sec[i].Name, ptr + sec[i].VirtualAddress,
                        sec[i].PointerToRawData, sec[i].SizeOfRawData,
                        sec[i].Misc.VirtualSize, sec[i].Characteristics );

        if (!sec[i].PointerToRawData || !file_size) continue;

        /* Note: if the section is not aligned properly map_file_into_view will magically
         *       fall back to read(), so we don't need to check anything here.
         */
        end = file_start + file_size;
        {
            BOOL executable = !!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE);
            BOOL host_executable = executable && !macrunner_hb_strip_host_exec_for_image( image_info );

        if (sec[i].PointerToRawData >= st.st_size ||
            end > file_sector_size ||
            end < file_start ||
            map_file_into_view( view, fd, sec[i].VirtualAddress, file_size, file_start,
                                VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY,
                                removable, executable, host_executable ) != STATUS_SUCCESS)
        {
            ERR_(module)( "Could not map %s section %.8s, file probably truncated\n",
                          debugstr_us(nt_name), sec[i].Name );
            goto done;
        }
        }

        if (file_size & align_mask)
        {
            if (!round_size_checked( 0, file_size, align_mask, &end )) goto done;
            if (end > map_size) end = map_size;
            TRACE_(module)("clearing %p - %p\n",
                           ptr + sec[i].VirtualAddress + file_size,
                           ptr + sec[i].VirtualAddress + end );
            memset( ptr + sec[i].VirtualAddress + file_size, 0, end - file_size );
        }
    }

    macrunner_hb_watch_rva( "после-секций", ptr, total_size );

#ifdef __aarch64__
    if ((dir = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG )))
    {
        if (image_info->machine == IMAGE_FILE_MACHINE_ARM64 &&
            (machine == IMAGE_FILE_MACHINE_AMD64 ||
             (!machine && main_image_info.Machine == IMAGE_FILE_MACHINE_AMD64)))
        {
            update_arm64x_mapping( view, nt, dir, sec );
            macrunner_hb_watch_rva( "после-правок-ARM64X", ptr, total_size );
            /* reload changed machine from NT header */
            image_info->machine = nt->FileHeader.Machine;
        }
        if (image_info->machine == IMAGE_FILE_MACHINE_AMD64)
            update_arm64ec_ranges( view, nt, dir, &image_info->entry_point );
    }
#endif
    if (machine && machine != nt->FileHeader.Machine && !wow64_using_32bit_prefix)
    {
#if defined(__APPLE__) && defined(__aarch64__)
        if (machine == IMAGE_FILE_MACHINE_ARM64 &&
            nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
            macrunner_hb_x64_guest_process() &&
            macrunner_hb_is_x64_guest_image( image_info ))
        {
            if (macrunner_hb_trace_host_exec())
                fprintf( stderr, "macrunner-host-exec-allow-x64-machine-mismatch: pid=%d requested=%#x image=%#x base=%#lx\n",
                         getpid(), machine, nt->FileHeader.Machine, (ULONG_PTR)image_info->base );
        }
        else
#endif
        {
        status = STATUS_NOT_SUPPORTED;
        goto done;
        }
    }

    /* relocate to dynamic base */

    if (image_info->map_addr)
    {
        ULONG_PTR reloc_base = image_info->map_addr;

#if defined(__APPLE__) && defined(__aarch64__)
        if (macrunner_hb_is_x64_guest_image( image_info ) && reloc_base != (ULONG_PTR)ptr)
        {
            if (macrunner_hb_trace_host_exec())
                fprintf( stderr, "macrunner-host-exec-x64-relocate-host-base: pid=%d %s server_base=%#lx host_base=%p preferred=%#lx\n",
                         getpid(), debugstr_us(nt_name), (ULONG_PTR)image_info->map_addr,
                         ptr, (ULONG_PTR)image_info->base );
            reloc_base = (ULONG_PTR)ptr;
        }
#endif

        if (!(delta = reloc_base - image_info->base)) goto no_dynamic_reloc;

        TRACE_(module)( "relocating %s dynamic base %lx -> %lx mapped at %p\n", debugstr_us(nt_name),
                        (ULONG_PTR)image_info->base, reloc_base, ptr );

        if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            ((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.ImageBase = reloc_base;
        else
            ((IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.ImageBase = reloc_base;

        if ((dir = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_BASERELOC )))
        {
            IMAGE_BASE_RELOCATION *rel = (IMAGE_BASE_RELOCATION *)(ptr + dir->VirtualAddress);
            IMAGE_BASE_RELOCATION *end = (IMAGE_BASE_RELOCATION *)((char *)rel + dir->Size);

            while (rel && rel < end - 1 && rel->SizeOfBlock)
            {
                if (!is_valid_relocation_block( rel, end, total_size ) ||
                    !(rel = process_relocation_block( ptr + rel->VirtualAddress, rel, delta )))
                {
                    status = STATUS_INVALID_IMAGE_FORMAT;
                    goto done;
                }
            }
        }
    }
no_dynamic_reloc:

    /* set the image protections */

    set_vprot( view, ptr, header_span, VPROT_COMMITTED | VPROT_READ );
    macrunner_hb_protect_wow64_guest32_image_range( image_info, ptr, header_span,
                                                    VPROT_COMMITTED | VPROT_READ,
                                                    view->protect );

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        SIZE_T size;
        BYTE vprot = VPROT_COMMITTED;

        if (sec[i].Misc.VirtualSize)
        {
            if (!round_size_checked( sec[i].VirtualAddress, sec[i].Misc.VirtualSize, align_mask, &size ))
            {
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto done;
            }
        }
        else
        {
            if (!round_size_checked( sec[i].VirtualAddress, sec[i].SizeOfRawData, align_mask, &size ))
            {
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto done;
            }
        }
        if (sec[i].VirtualAddress > total_size || size > total_size - sec[i].VirtualAddress)
        {
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto done;
        }

        if (sec[i].Characteristics & IMAGE_SCN_MEM_READ)    vprot |= VPROT_READ;
        if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)   vprot |= VPROT_WRITECOPY;
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) vprot |= VPROT_EXEC;

        if (!set_vprot( view, ptr + sec[i].VirtualAddress, size, vprot ) && (vprot & VPROT_EXEC))
            ERR( "failed to set %08x protection on %s section %.8s, noexec filesystem?\n",
                 sec[i].Characteristics, debugstr_us(nt_name), sec[i].Name );
        macrunner_hb_protect_wow64_guest32_image_range( image_info, ptr + sec[i].VirtualAddress,
                                                        size, vprot, view->protect );
    }

#ifdef VALGRIND_LOAD_PDB_DEBUGINFO
    VALGRIND_LOAD_PDB_DEBUGINFO(fd, ptr, total_size, ptr - (char *)wine_server_get_ptr( image_info->base ));
#endif

#if defined(__APPLE__) && defined(__aarch64__)
    /* MacRunner BSS-tail diagnostic (env-gated, read-only): the x64 JIT faulted reading a .data
     * BSS-tail address (UnityPlayer +0x1F40460, VirtualSize >> SizeOfRawData). Static reading shows
     * map_view commits the whole image host-RW and set_vprot covers the full VirtualSize, so dump the
     * REAL host protection (mach_vm_region) + wine guest vprot at each x64-guest section's start /
     * BSS-tail / deep page to pin whether the tail is actually committed at load. */
    if (macrunner_hb_is_x64_guest_image( image_info ) && getenv( "MACRUNNER_DIAG_BSS" ))
    {
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            SIZE_T vsz = sec[i].Misc.VirtualSize;
            SIZE_T raw = sec[i].SizeOfRawData;
            SIZE_T eff_raw, tail_off;
            struct { const char *what; SIZE_T off; } pts[3];
            int p;

            if (!vsz) continue;
            eff_raw = min( raw, vsz );
            if (!round_size_checked( 0, eff_raw, host_page_mask, &tail_off )) tail_off = 0;
            pts[0].what = "start";    pts[0].off = 0;
            pts[1].what = "bss-tail"; pts[1].off = (tail_off < vsz) ? tail_off : vsz - 1;
            pts[2].what = "deep";     pts[2].off = (vsz > host_page_size) ? (vsz - host_page_size) : 0;
            for (p = 0; p < 3; p++)
            {
                char *a = ptr + sec[i].VirtualAddress + pts[p].off;
                mach_vm_address_t ra = (mach_vm_address_t)(uintptr_t)a;
                mach_vm_size_t rs = 0;
                vm_region_basic_info_data_64_t info;
                mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
                mach_port_t obj = MACH_PORT_NULL;
                kern_return_t kr = mach_vm_region( mach_task_self(), &ra, &rs, VM_REGION_BASIC_INFO_64,
                                                   (vm_region_info_t)&info, &cnt, &obj );

                fprintf( stderr, "macrunner-diag-bss: %s sec=%.8s va=%#x vsz=%#lx raw=%#lx pt=%s off=%#lx "
                         "host=%p vm_base=%p vm_size=%#llx kr=%d hostprot=%#x guestvprot=%#x\n",
                         debugstr_us(nt_name), sec[i].Name, sec[i].VirtualAddress,
                         (unsigned long)vsz, (unsigned long)raw, pts[p].what, (unsigned long)pts[p].off, a,
                         (kr == KERN_SUCCESS) ? (void *)(uintptr_t)ra : NULL,
                         (kr == KERN_SUCCESS) ? (unsigned long long)rs : 0ull, kr,
                         (kr == KERN_SUCCESS) ? info.protection : 0, get_page_vprot( a ) );
            }
        }
    }
#endif

    status = STATUS_SUCCESS;

done:
    free( sections );
    return status;
}


/***********************************************************************
 *             get_mapping_info
 */
static unsigned int get_mapping_info( HANDLE handle, ACCESS_MASK access, unsigned int *sec_flags,
                                      mem_size_t *full_size, HANDLE *shared_file,
                                      struct pe_image_info **info, UNICODE_STRING *nt_name,
                                      ANSI_STRING *exp_name )
{
    struct pe_image_info *image_info;
    SIZE_T namelen, total, size = 1024;
    unsigned int status;

    for (;;)
    {
        if (!(image_info = malloc( size ))) return STATUS_NO_MEMORY;

        SERVER_START_REQ( get_mapping_info )
        {
            req->handle = wine_server_obj_handle( handle );
            req->access = access;
            wine_server_set_reply( req, image_info, size );
            status = wine_server_call( req );
            *sec_flags   = reply->flags;
            *full_size   = reply->size;
            namelen      = reply->name_len;
            total        = reply->total;
            *shared_file = wine_server_ptr_handle( reply->shared_file );
        }
        SERVER_END_REQ;
        if (!status && total <= size) break;
        free( image_info );
        if (status) return status;
        if (*shared_file) NtClose( *shared_file );
        size = total;
    }

    if (total)
    {
        assert( total >= sizeof(*image_info) );
        total -= sizeof(*image_info);
        nt_name->Buffer = (WCHAR *)(image_info + 1);
        nt_name->Length = nt_name->MaximumLength = namelen;
        exp_name->Buffer = (char *)nt_name->Buffer + namelen;
        exp_name->Length = exp_name->MaximumLength = total - namelen;
        *info = image_info;
    }
    else free( image_info );

    return STATUS_SUCCESS;
}


/***********************************************************************
 *             map_image_view
 *
 * Map a view for a PE image at an appropriate address.
 */
static NTSTATUS map_image_view( struct file_view **view_ret, struct pe_image_info *image_info, SIZE_T size,
                                ULONG_PTR limit_low, ULONG_PTR limit_high, ULONG alloc_type )
{
    unsigned int vprot = SEC_IMAGE | SEC_FILE | VPROT_COMMITTED | VPROT_READ | VPROT_EXEC | VPROT_WRITECOPY;
    BOOL macrunner_x64_guest = macrunner_hb_is_x64_guest_image( image_info );
    void *base;
    NTSTATUS status;
    ULONG_PTR start, end;
    BOOL top_down = (image_info->image_charact & IMAGE_FILE_DLL) &&
                    (image_info->image_flags & IMAGE_FLAGS_ImageDynamicallyRelocated);
#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
    BOOL old_guest32_map_active = macrunner_hb_wow64_guest32_map_active;
    if (is_win64 && image_info->machine == IMAGE_FILE_MACHINE_I386)
        macrunner_hb_wow64_guest32_map_active = TRUE;
#endif

    if (macrunner_x64_guest)
    {
        vprot |= VPROT_MACRUNNER_X64_GUEST;
        macrunner_hb_prepare_x64_guest_fault_handlers( "x64-image-map" );
    }
    else if (macrunner_hb_is_i386_guest_image( image_info ))
    {
        vprot |= VPROT_MACRUNNER_I386_GUEST;
    }

    if (macrunner_hb_trace_host_exec())
        fprintf( stderr, "macrunner-host-exec-map-image: pid=%d image_base=%#lx size=%zx machine=%#x current_machine=%#x flags=%#x vprot=%#x x64_guest=%d signal_ready=%d loader=%d env=%s\n",
                 getpid(), (ULONG_PTR)image_info->base, (size_t)size, image_info->machine, current_machine,
                 image_info->image_flags, vprot, macrunner_x64_guest,
                 macrunner_hb_x64_guest_fault_handlers_are_ready, macrunner_hb_x64_loader,
                 getenv( "MACRUNNER_HB_X64_LOADER" ) ? getenv( "MACRUNNER_HB_X64_LOADER" ) : "" );

    limit_low = max( limit_low, (ULONG_PTR)address_space_start );  /* make sure the DOS area remains free */
    if (!limit_high) limit_high = (ULONG_PTR)user_space_limit;

    /* first try the specified base */

    if (image_info->map_addr)
    {
        base = wine_server_get_ptr( image_info->map_addr );
        if ((ULONG_PTR)base != image_info->map_addr) base = NULL;
    }
    else
    {
        base = wine_server_get_ptr( image_info->base );
        if ((ULONG_PTR)base != image_info->base) base = NULL;
    }
    if (base)
    {
        status = map_view( view_ret, base, size, alloc_type, vprot, limit_low, limit_high, 0 );
        if (!status)
        {
            if (macrunner_x64_guest) macrunner_hb_register_x64_guest_range( (*view_ret)->base, (*view_ret)->size );
#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
            macrunner_hb_wow64_guest32_map_active = old_guest32_map_active;
#endif
            return status;
        }
    }

    /* then some appropriate address range */

    if (image_info->base >= limit_4g)
    {
        start = max( limit_low, limit_4g );
        end = limit_high;
    }
    else
    {
        start = limit_low;
        end = min( limit_high, get_wow_user_space_limit() );
    }
    if (start < end && (start != limit_low || end != limit_high))
    {
        status = map_view( view_ret, NULL, size, top_down ? MEM_TOP_DOWN : 0, vprot, start, end, 0 );
        if (!status)
        {
            if (macrunner_x64_guest) macrunner_hb_register_x64_guest_range( (*view_ret)->base, (*view_ret)->size );
#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
            macrunner_hb_wow64_guest32_map_active = old_guest32_map_active;
#endif
            return status;
        }
    }

    /* then any suitable address */

    status = map_view( view_ret, NULL, size, top_down ? MEM_TOP_DOWN : 0, vprot, limit_low, limit_high, 0 );
    if (!status && macrunner_x64_guest) macrunner_hb_register_x64_guest_range( (*view_ret)->base, (*view_ret)->size );
#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
    macrunner_hb_wow64_guest32_map_active = old_guest32_map_active;
#endif
    return status;
}


/***********************************************************************
 *             virtual_map_image
 *
 * Map a PE image section into memory.
 */
static NTSTATUS virtual_map_image( HANDLE mapping, void **addr_ptr, SIZE_T *size_ptr, HANDLE shared_file,
                                   ULONG_PTR limit_low, ULONG_PTR limit_high, ULONG alloc_type,
                                   USHORT machine, struct pe_image_info *image_info,
                                   UNICODE_STRING *nt_name, BOOL is_builtin, off_t offset)
{
    int unix_fd = -1, needs_close;
    int shared_fd = -1, shared_needs_close = 0;
    SIZE_T size = image_info->map_size;
    struct file_view *view;
    unsigned int status;
    sigset_t sigset;

    if (offset >= size)
        return STATUS_INVALID_PARAMETER;

    if ((status = server_get_unix_fd( mapping, 0, &unix_fd, &needs_close, NULL, NULL )))
        return status;

    if (shared_file && ((status = server_get_unix_fd( shared_file, FILE_READ_DATA|FILE_WRITE_DATA,
                                                      &shared_fd, &shared_needs_close, NULL, NULL ))))
    {
        if (needs_close) close( unix_fd );
        return status;
    }

    if (peb->OSMajorVersion > 5 && /* CW HACK 22939: ASLR is supported only on Windows Vista and later */
        !image_info->map_addr &&
        (image_info->image_charact & IMAGE_FILE_DLL) &&
        (image_info->image_flags & IMAGE_FLAGS_ImageDynamicallyRelocated))
    {
        SERVER_START_REQ( get_image_map_address )
        {
            req->handle = wine_server_obj_handle( mapping );
            if (!wine_server_call( req )) image_info->map_addr = reply->addr;
        }
        SERVER_END_REQ;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    status = map_image_view( &view, image_info, size, limit_low, limit_high, alloc_type );
    if (status) goto done;

    status = map_image_into_view( view, nt_name, unix_fd, image_info, machine, shared_fd, needs_close );
    if (status == STATUS_SUCCESS)
    {
#if defined(__APPLE__) && defined(__aarch64__)
        /* Keep the cross-arch execution boundary independent of Wine's mapping
         * timing: AMD64 guest image pages may be executable to HyperBridge, but
         * must never be left executable by the host ARM64 CPU. */
        if (macrunner_hb_is_x64_guest_image( image_info ))
            mprotect_range( view->base, view->size, 0, 0 );
#endif
        if (offset)
        {
            free_pages( view, view->base, offset );
            size -= offset;
        }

        image_info->base = wine_server_client_ptr( view->base );
        SERVER_START_REQ( map_image_view )
        {
            req->mapping = wine_server_obj_handle( mapping );
            req->base    = image_info->base;
            req->size    = size;
            req->entry   = image_info->entry_point;
            req->machine = image_info->machine;
            req->offset  = offset;
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
    }
    if (NT_SUCCESS(status))
    {
        if (is_builtin && !offset) add_builtin_module( view->base, NULL );
        *addr_ptr = view->base;
        *size_ptr = size;
        VIRTUAL_DEBUG_DUMP_VIEW( view );
    }
    else delete_view( view );

done:
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    if (needs_close) close( unix_fd );
    if (shared_needs_close) close( shared_fd );
    return status;
}


/***********************************************************************
 *             virtual_map_section
 *
 * Map a file section into memory.
 */
static unsigned int virtual_map_section( HANDLE handle, PVOID *addr_ptr, ULONG_PTR limit_low,
                                         ULONG_PTR limit_high, SIZE_T commit_size,
                                         const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                         ULONG alloc_type, ULONG protect, USHORT machine )
{
    unsigned int res;
    mem_size_t full_size;
    ACCESS_MASK access;
    SIZE_T size;
    struct pe_image_info *image_info = NULL;
    UNICODE_STRING nt_name;
    ANSI_STRING exp_name;
    void *base;
    int unix_handle = -1, needs_close;
    unsigned int vprot, sec_flags;
    struct file_view *view;
    HANDLE shared_file;
    LARGE_INTEGER offset;
    sigset_t sigset;

    switch(protect)
    {
    case PAGE_NOACCESS:
    case PAGE_READONLY:
    case PAGE_WRITECOPY:
        access = SECTION_MAP_READ;
        break;
    case PAGE_READWRITE:
        access = SECTION_MAP_WRITE;
        break;
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_WRITECOPY:
        access = SECTION_MAP_READ | SECTION_MAP_EXECUTE;
        break;
    case PAGE_EXECUTE_READWRITE:
        access = SECTION_MAP_WRITE | SECTION_MAP_EXECUTE;
        break;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    res = get_mapping_info( handle, access, &sec_flags, &full_size, &shared_file,
                            &image_info, &nt_name, &exp_name );
    if (res) return res;

    offset.QuadPart = offset_ptr ? offset_ptr->QuadPart : 0;

    if (image_info)
    {
        SECTION_IMAGE_INFORMATION info;
        ULONG64 prev = 0;

        if (NtCurrentTeb64())
        {
            prev = NtCurrentTeb64()->Tib.ArbitraryUserPointer;
            NtCurrentTeb64()->Tib.ArbitraryUserPointer = PtrToUlong(NtCurrentTeb()->Tib.ArbitraryUserPointer);
        }
        /* check if we can replace that mapping with the builtin */
        res = load_builtin( image_info, &nt_name, &exp_name, machine, &info,
                            addr_ptr, size_ptr, limit_low, limit_high, offset.QuadPart );
        if (res == STATUS_IMAGE_ALREADY_LOADED)
            res = virtual_map_image( handle, addr_ptr, size_ptr, shared_file, limit_low, limit_high,
                                     alloc_type, machine, image_info, &nt_name, FALSE, offset.QuadPart );
        if (shared_file) NtClose( shared_file );
        free( image_info );
        if (NtCurrentTeb64()) NtCurrentTeb64()->Tib.ArbitraryUserPointer = prev;
        return res;
    }

    base = *addr_ptr;
    if (offset.QuadPart >= full_size) return STATUS_INVALID_PARAMETER;
    if (*size_ptr)
    {
        size = *size_ptr;
        if (size > full_size - offset.QuadPart) return STATUS_INVALID_VIEW_SIZE;
    }
    else
    {
        size = full_size - offset.QuadPart;
        if (size != full_size - offset.QuadPart)  /* truncated */
        {
            WARN( "Files larger than 4Gb (%s) not supported on this platform\n",
                  wine_dbgstr_longlong(full_size) );
            return STATUS_INVALID_PARAMETER;
        }
    }
    if (!round_size_checked( 0, size, page_mask, &size ) || !size) return STATUS_INVALID_PARAMETER;

    get_vprot_flags( protect, &vprot, FALSE );
    vprot |= sec_flags;
    if (!(sec_flags & SEC_RESERVE)) vprot |= VPROT_COMMITTED;

    if ((res = server_get_unix_fd( handle, 0, &unix_handle, &needs_close, NULL, NULL ))) return res;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    res = map_view( &view, base, size, alloc_type, vprot, limit_low, limit_high, 0 );
    if (res) goto done;

    TRACE( "handle=%p size=%lx offset=%s\n", handle, size, wine_dbgstr_longlong(offset.QuadPart) );
    res = map_file_into_view( view, unix_handle, 0, size, offset.QuadPart, vprot, needs_close, FALSE, FALSE );
    if (res == STATUS_SUCCESS)
    {
        /* file mappings must always be accessible */
        mprotect_range( view->base, view->size, VPROT_COMMITTED, 0 );

        SERVER_START_REQ( map_view )
        {
            req->mapping = wine_server_obj_handle( handle );
            req->access  = access;
            req->base    = wine_server_client_ptr( view->base );
            req->size    = size;
            req->start   = offset.QuadPart;
            res = wine_server_call( req );
        }
        SERVER_END_REQ;
    }
    else ERR( "mapping %p %lx %s failed\n", view->base, size, wine_dbgstr_longlong(offset.QuadPart) );

    if (NT_SUCCESS(res))
    {
        *addr_ptr = view->base;
        *size_ptr = size;
        VIRTUAL_DEBUG_DUMP_VIEW( view );
    }
    else delete_view( view );

done:
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    if (needs_close) close( unix_handle );
    return res;
}


/* allocate some space for the virtual heap, if possible from a reserved area */
static void *alloc_virtual_heap( SIZE_T size )
{
    struct reserved_area *area;
    void *ret;

    if (!round_size_checked( 0, size, host_page_mask, &size )) return MAP_FAILED;

    LIST_FOR_EACH_ENTRY_REV( area, &reserved_areas, struct reserved_area, entry )
    {
        void *base = area->base;
        void *end = (char *)base + area->size;

        if (is_beyond_limit( base, area->size, address_space_limit ))
            address_space_limit = host_addr_space_limit = end;
        if (is_win64 && base < (void *)0x80000000) break;
        if (preload_reserve_end >= end)
        {
            if (preload_reserve_start <= base) continue;  /* no space in that area */
            if (preload_reserve_start < end) end = preload_reserve_start;
        }
        else if (preload_reserve_end > base)
        {
            if (preload_reserve_start <= base) base = preload_reserve_end;
            else if ((char *)end - (char *)preload_reserve_end >= size) base = preload_reserve_end;
            else end = preload_reserve_start;
        }
        if ((char *)end - (char *)base < size) continue;
        ret = anon_mmap_fixed( (char *)end - size, size, PROT_READ | PROT_WRITE, 0 );
        if (ret == MAP_FAILED) continue;
        if (!mmap_remove_reserved_area( ret, size ))
        {
            anon_mmap_fixed( ret, size, PROT_NONE, MAP_NORESERVE );
            continue;
        }
        return ret;
    }
    return anon_mmap_alloc( size, PROT_READ | PROT_WRITE );
}

/***********************************************************************
 *           virtual_init
 */
void virtual_init(void)
{
    const struct preload_info **preload_info = dlsym( RTLD_DEFAULT, "wine_main_preload_info" );
    const char *preload;
    size_t size;
    int i;
    init_virtual_mutex();
    pthread_atfork( NULL, NULL, ntdll_atfork_child );

#ifdef __aarch64__
    host_page_size = sysconf( _SC_PAGESIZE );
    host_page_mask = host_page_size - 1;
    TRACE( "host page size: %uk\n", (UINT)host_page_size / 1024 );
#endif

#ifdef _WIN64
    host_addr_space_limit = get_host_addr_space_limit();
#ifdef __aarch64__
    if (getenv("MACRUNNER_HB_X64_LOADER") &&
        getenv("MACRUNNER_HB_X64_LOADER")[0] &&
        getenv("MACRUNNER_HB_X64_LOADER")[0] != '0' &&
        host_addr_space_limit > (void *)0x0000088000000000)
    {
        fprintf( stderr, "MacRunner HyperBridge clamping host addr space limit from %p to %p\n",
               host_addr_space_limit, (void *)0x0000088000000000 );
        host_addr_space_limit = (void *)0x0000088000000000;
    }
#endif
    TRACE( "host addr space limit: %p\n", host_addr_space_limit );
#else
    host_addr_space_limit = address_space_limit;
#endif

    kernel_writewatch_init();

    if (preload_info && *preload_info)
        for (i = 0; (*preload_info)[i].size; i++)
            mmap_add_reserved_area( (*preload_info)[i].addr, (*preload_info)[i].size );

#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
    mr_vm_arena_init();
#endif

    mmap_init( preload_info ? *preload_info : NULL );

    if ((preload = getenv("WINEPRELOADRESERVE")))
    {
        unsigned long start, end;
        if (sscanf( preload, "%lx-%lx", &start, &end ) == 2)
        {
            SIZE_T rounded_end;

            if (end <= start || !round_size_checked( 0, end, host_page_mask, &rounded_end ))
                WARN( "ignoring invalid WINEPRELOADRESERVE range %s\n", preload );
            else
            {
                preload_reserve_start = ROUND_ADDR( start, host_page_mask );
                preload_reserve_end = (void *)rounded_end;
                /* some apps start inside the DOS area */
                if (preload_reserve_start)
                    address_space_start = min( address_space_start, preload_reserve_start );
            }
        }
        unsetenv( "WINEPRELOADRESERVE" );
    }

    /* try to find space in a reserved area for the views and pages protection table */
#ifdef _WIN64
    pages_vprot_size = ((size_t)host_addr_space_limit >> page_shift >> pages_vprot_shift) + 1;
    if (pages_vprot_size > (~(SIZE_T)0 - 2 * view_block_size) / sizeof(*pages_vprot))
        size = ~(SIZE_T)0;
    else
        size = 2 * view_block_size + pages_vprot_size * sizeof(*pages_vprot);
#else
    size = 2 * view_block_size + (1U << (32 - page_shift));
#endif
#if defined(__APPLE__) && defined(__aarch64__) && defined(_WIN64)
    if (!mr_vm_metadata_init())
#endif
    {
        view_block_start = alloc_virtual_heap( size );
        assert( view_block_start != MAP_FAILED );
        view_block_end = view_block_start + view_block_size / sizeof(*view_block_start);
        free_ranges = (void *)((char *)view_block_start + view_block_size);
        pages_vprot = (void *)((char *)view_block_start + 2 * view_block_size);
    }
    wine_rb_init( &views_tree, compare_view );

    free_ranges[0].base = (void *)0;
    free_ranges[0].end = (void *)~0;
    free_ranges_end = free_ranges + 1;

    /* make the DOS area accessible (except the low 64K) to hide bugs in broken apps like Excel 2003 */
    size = (char *)address_space_start - (char *)0x10000;
    if (size && mmap_is_in_reserved_area( (void*)0x10000, size ) == 1)
        anon_mmap_fixed( (void *)0x10000, size, PROT_READ | PROT_WRITE, 0 );
}


/***********************************************************************
 *           get_system_affinity_mask
 */
ULONG_PTR get_system_affinity_mask(void)
{
    ULONG num_cpus = peb->NumberOfProcessors;
    if (num_cpus >= sizeof(ULONG_PTR) * 8) return ~(ULONG_PTR)0;
    return ((ULONG_PTR)1 << num_cpus) - 1;
}

/***********************************************************************
 *           virtual_get_system_info
 */
void virtual_get_system_info( SYSTEM_BASIC_INFORMATION *info, BOOL wow64 )
{
#if defined(HAVE_SYSINFO) \
    && defined(HAVE_STRUCT_SYSINFO_TOTALRAM) && defined(HAVE_STRUCT_SYSINFO_MEM_UNIT)
    struct sysinfo sinfo;

    if (!sysinfo(&sinfo))
    {
        ULONG64 total = (ULONG64)sinfo.totalram * sinfo.mem_unit;
        info->MmHighestPhysicalPage = max(1, total / page_size);
    }
#elif defined(__APPLE__)
    /* sysconf(_SC_PHYS_PAGES) is buggy on macOS: in a 32-bit process, it
     * returns an error on Macs with >4GB of RAM.
     */
    INT64 memsize;
    size_t len = sizeof(memsize);

    if (!sysctlbyname( "hw.memsize", &memsize, &len, NULL, 0 ))
        info->MmHighestPhysicalPage = max(1, memsize / page_size);
#elif defined(_SC_PHYS_PAGES)
    LONG64 phys_pages = sysconf( _SC_PHYS_PAGES );

    info->MmHighestPhysicalPage = max(1, phys_pages);
#else
    info->MmHighestPhysicalPage = 0x7fffffff / page_size;
#endif

    info->unknown                 = 0;
    info->KeMaximumIncrement      = 0;  /* FIXME */
    info->PageSize                = page_size;
    info->MmLowestPhysicalPage    = 1;
    info->MmNumberOfPhysicalPages = info->MmHighestPhysicalPage - info->MmLowestPhysicalPage;
    info->AllocationGranularity   = granularity_mask + 1;
    info->LowestUserAddress       = (void *)0x10000;
    info->ActiveProcessorsAffinityMask = get_system_affinity_mask();
    info->NumberOfProcessors      = peb->NumberOfProcessors;
    if (wow64) info->HighestUserAddress = (char *)get_wow_user_space_limit() - 1;
    else info->HighestUserAddress = (char *)user_space_limit - 1;
}


/***********************************************************************
 *           virtual_map_builtin_module
 */
NTSTATUS virtual_map_builtin_module( HANDLE mapping, void **module, SIZE_T *size,
                                     SECTION_IMAGE_INFORMATION *info, ULONG_PTR limit_low,
                                     ULONG_PTR limit_high, WORD machine, BOOL prefer_native, off_t offset )
{
    mem_size_t full_size;
    unsigned int sec_flags;
    HANDLE shared_file;
    struct pe_image_info *image_info = NULL;
    NTSTATUS status;
    UNICODE_STRING nt_name;
    ANSI_STRING exp_name;

    if ((status = get_mapping_info( mapping, SECTION_MAP_READ, &sec_flags, &full_size, &shared_file,
                                    &image_info, &nt_name, &exp_name )))
        return status;

    if (!image_info) return STATUS_INVALID_PARAMETER;

    *module = NULL;
    *size = 0;

    if (!image_info->wine_builtin) /* ignore non-builtins */
    {
        if (!image_info->wine_fakedll)
            WARN_(module)( "%s found in WINEDLLPATH but not a builtin, ignoring\n", debugstr_us(&nt_name) );
        status = STATUS_DLL_NOT_FOUND;
    }
    else if (prefer_native && (image_info->dll_charact & IMAGE_DLLCHARACTERISTICS_PREFER_NATIVE))
    {
        TRACE_(module)( "%s has prefer-native flag, ignoring builtin\n", debugstr_us(&nt_name) );
        status = STATUS_IMAGE_ALREADY_LOADED;
    }
    else
    {
        status = virtual_map_image( mapping, module, size, shared_file, limit_low, limit_high, 0,
                                    machine, image_info, &nt_name, TRUE, offset );
        virtual_fill_image_information( image_info, info );
    }

    if (shared_file) NtClose( shared_file );
    free( image_info );
    return status;
}


/***********************************************************************
 *           virtual_map_module
 */
NTSTATUS virtual_map_module( HANDLE mapping, void **module, SIZE_T *size, SECTION_IMAGE_INFORMATION *info,
                             ULONG_PTR limit_low, ULONG_PTR limit_high, USHORT machine )
{
    unsigned int status;
    mem_size_t full_size;
    unsigned int sec_flags;
    HANDLE shared_file;
    struct pe_image_info *image_info = NULL;
    UNICODE_STRING nt_name;
    ANSI_STRING exp_name;

    if ((status = get_mapping_info( mapping, SECTION_MAP_READ, &sec_flags, &full_size, &shared_file,
                                    &image_info, &nt_name, &exp_name )))
        return status;

    if (!image_info) return STATUS_INVALID_PARAMETER;

    *module = NULL;
    *size = 0;

    /* check if we can replace that mapping with the builtin */
    status = load_builtin( image_info, &nt_name, &exp_name, machine, info,
                           module, size, limit_low, limit_high, 0 );
    if (status == STATUS_IMAGE_ALREADY_LOADED)
    {
        status = virtual_map_image( mapping, module, size, shared_file, limit_low, limit_high, 0,
                                    machine, image_info, &nt_name, FALSE, 0 );
        virtual_fill_image_information( image_info, info );
    }
    if (shared_file) NtClose( shared_file );
    free( image_info );
    return status;
}


/***********************************************************************
 *           virtual_create_builtin_view
 */
NTSTATUS virtual_create_builtin_view( void *module, const UNICODE_STRING *nt_name,
                                      struct pe_image_info *info, void *so_handle )
{
    NTSTATUS status;
    sigset_t sigset;
    IMAGE_DOS_HEADER *dos = module;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((char *)dos + dos->e_lfanew);
    SIZE_T size = info->map_size;
    IMAGE_SECTION_HEADER *sec;
    struct file_view *view;
    void *base = wine_server_get_ptr( info->base );
    int i;

    if (size > ~(ULONG_PTR)0 - (ULONG_PTR)base) return STATUS_INVALID_IMAGE_FORMAT;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    { /* Итерация 311: назвать ВЫЗЫВАЮЩЕГО. Приём из 307 — печать с номером места,
       безусловная, первые 4 раза на место. Утверждение VPROT_SYSTEM воспроизводится 3/3,
       и место вызова — единственное, чего не хватает для разбора. */
      static int said_5360;
      if (said_5360++ < 4)
        fprintf(stderr, "macrunner-createview-site: место=5360\n"); }
    status = create_view( &view, base, size, SEC_IMAGE | SEC_FILE | VPROT_SYSTEM |
                          VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY | VPROT_EXEC );
    if (!status)
    {
        TRACE( "created %p-%p for %s\n", base, (char *)base + size, debugstr_us(nt_name) );

        /* The PE header is always read-only, no write, no execute. */
        set_page_vprot( base, page_size, VPROT_COMMITTED | VPROT_READ );

        sec = IMAGE_FIRST_SECTION( nt );
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            BYTE flags = VPROT_COMMITTED;

            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) flags |= VPROT_EXEC;
            if (sec[i].Characteristics & IMAGE_SCN_MEM_READ) flags |= VPROT_READ;
            if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) flags |= VPROT_WRITE;
            if (sec[i].VirtualAddress > size || sec[i].Misc.VirtualSize > size - sec[i].VirtualAddress)
            {
                status = STATUS_INVALID_IMAGE_FORMAT;
                break;
            }
            set_page_vprot( (char *)base + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, flags );
        }

        if (!status)
        {
            SERVER_START_REQ( map_builtin_view )
            {
                wine_server_add_data( req, info, sizeof(*info) );
                wine_server_add_data( req, nt_name->Buffer, nt_name->Length );
                status = wine_server_call( req );
            }
            SERVER_END_REQ;
        }

        if (!status)
        {
            add_builtin_module( view->base, so_handle );
            VIRTUAL_DEBUG_DUMP_VIEW( view );
            if (is_beyond_limit( base, size, working_set_limit )) working_set_limit = address_space_limit;
        }
        else delete_view( view );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    return status;
}


/***********************************************************************
 *           virtual_relocate_module
 */
static BOOL virtual_section_raw_range_fits( const IMAGE_SECTION_HEADER *sec, ULONG image_size,
                                            SIZE_T *size )
{
    ULONG rva = sec->VirtualAddress;

    *size = sec->SizeOfRawData;
    if (!*size) return TRUE;
    return rva < image_size && *size <= image_size - rva;
}

NTSTATUS virtual_relocate_module( void *module )
{
    char *ptr = module;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(ptr + ((IMAGE_DOS_HEADER *)module)->e_lfanew);
    IMAGE_DATA_DIRECTORY *relocs;
    IMAGE_BASE_RELOCATION *rel, *end;
    IMAGE_SECTION_HEADER *sec;
    SIZE_T rounded_size;
    ULONG total_size;
    ULONG *protect_old, i;
    ULONG_PTR image_base;
    INT_PTR delta;
    NTSTATUS status = STATUS_SUCCESS;

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        image_base = ((const IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.ImageBase;
    else
        image_base = ((const IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.ImageBase;

    if (!round_size_checked( 0, nt->OptionalHeader.SizeOfImage, page_mask, &rounded_size ) ||
        rounded_size > MAXDWORD)
        return STATUS_INVALID_IMAGE_FORMAT;
    total_size = rounded_size;


    if (!(delta = (ULONG_PTR)module - image_base)) return STATUS_SUCCESS;

#if defined(__APPLE__) && defined(__aarch64__)
    if (macrunner_hb_trace_host_exec())
        fprintf( stderr, "macrunner-host-exec-virtual-relocate: pid=%d module=%p image_base=%#lx delta=%#lx machine=%#x\n",
                 getpid(), module, image_base, (ULONG_PTR)delta, nt->FileHeader.Machine );
#endif

    if (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
    {
        ERR( "Need to relocate module from %p to %p, but relocation records are stripped\n",
             (void *)image_base, module );
        return STATUS_CONFLICTING_ADDRESSES;
    }

    TRACE( "%p -> %p\n", (void *)image_base, module );

    if (!(relocs = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_BASERELOC ))) return STATUS_SUCCESS;

    if (!(protect_old = calloc( nt->FileHeader.NumberOfSections, sizeof(*protect_old) )))
        return STATUS_NO_MEMORY;

    sec = IMAGE_FIRST_SECTION( nt );
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        void *addr;
        SIZE_T size;

        if (!virtual_section_raw_range_fits( &sec[i], total_size, &size ))
        {
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto done;
        }
        if (!size) continue;
        addr = (char *)module + sec[i].VirtualAddress;
        if ((status = NtProtectVirtualMemory( NtCurrentProcess(), &addr, &size,
                                              PAGE_READWRITE, &protect_old[i] )))
            goto done;
    }


    rel = (IMAGE_BASE_RELOCATION *)((char *)module + relocs->VirtualAddress);
    end = (IMAGE_BASE_RELOCATION *)((char *)rel + relocs->Size);

    while (rel && rel < end - 1 && rel->SizeOfBlock)
    {
        if (!is_valid_relocation_block( rel, end, total_size ) ||
            !(rel = process_relocation_block( (char *)module + rel->VirtualAddress, rel, delta )))
        {
            status = STATUS_INVALID_IMAGE_FORMAT;
            break;
        }
    }

done:
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        void *addr;
        SIZE_T size;

        if (!protect_old[i]) continue;
        if (!virtual_section_raw_range_fits( &sec[i], total_size, &size ))
            continue;
        if (!size) continue;
        addr = (char *)module + sec[i].VirtualAddress;
        NtProtectVirtualMemory( NtCurrentProcess(), &addr, &size, protect_old[i], &protect_old[i] );
    }
    free( protect_old );
    return status;
}


/* Итерация 1299: адрес PEB32 после переноса в зеркало guest32; NULL, если переноса не было.
 * Ставится из env.c, читается ниже в init_teb. Смысл и три места — в unix_private.h. */
void *macrunner_hb_wow_peb32_mirror = NULL;

/* set some initial values in a new TEB */
static TEB *init_teb( void *ptr, BOOL is_wow )
{
    struct ntdll_thread_data *thread_data;
    TEB *teb;
    TEB64 *teb64 = ptr;
    TEB32 *teb32 = (TEB32 *)((char *)ptr + teb_offset);

#ifdef _WIN64
    teb = (TEB *)teb64;
    /* Итерация 1299: усечение `peb + page_size` даёт несуществующий адрес (у нас блок TEB/PEB
     * выше 4 ГБ). Если PEB32 перенесён в зеркало — берём оттуда. */
    teb32->Peb = macrunner_hb_wow_peb32_mirror
                 ? PtrToUlong( macrunner_hb_wow_peb32_mirror )
                 : PtrToUlong( (char *)peb + page_size );
    teb32->Tib.Self = PtrToUlong( teb32 );
    teb32->Tib.ExceptionList = ~0u;
    teb32->ActivationContextStackPointer = PtrToUlong( &teb32->ActivationContextStack );
    teb32->ActivationContextStack.FrameListCache.Flink =
        teb32->ActivationContextStack.FrameListCache.Blink =
            PtrToUlong( &teb32->ActivationContextStack.FrameListCache );
    teb32->StaticUnicodeString.Buffer = PtrToUlong( teb32->StaticUnicodeBuffer );
    teb32->StaticUnicodeString.MaximumLength = sizeof( teb32->StaticUnicodeBuffer );
    teb32->GdiBatchCount = PtrToUlong( teb64 );
    teb32->WowTebOffset  = -teb_offset;
    {
        static unsigned mr_n;
        if (mr_n++ < 8)
            fprintf( stderr, "macrunner-wowoff-писатель: место=init_teb teb64=%p было=%08lx "
                     "пишем=%08lx is_wow=%d\n", teb64,
                     (unsigned long)(ULONG)teb64->WowTebOffset,
                     (unsigned long)(ULONG)teb_offset, (int)is_wow );
    }
    if (is_wow) teb64->WowTebOffset = teb_offset;
#else
    teb = (TEB *)teb32;
    teb32->Tib.ExceptionList = ~0u;
    teb64->Peb = PtrToUlong( (char *)peb - page_size );
    teb64->Tib.Self = PtrToUlong( teb64 );
    teb64->Tib.ExceptionList = PtrToUlong( teb32 );
    teb64->ActivationContextStackPointer = PtrToUlong( &teb64->ActivationContextStack );
    teb64->ActivationContextStack.FrameListCache.Flink =
        teb64->ActivationContextStack.FrameListCache.Blink =
            PtrToUlong( &teb64->ActivationContextStack.FrameListCache );
    teb64->StaticUnicodeString.Buffer = PtrToUlong( teb64->StaticUnicodeBuffer );
    teb64->StaticUnicodeString.MaximumLength = sizeof( teb64->StaticUnicodeBuffer );
    teb64->WowTebOffset = teb_offset;
    if (is_wow)
    {
        teb32->GdiBatchCount = PtrToUlong( teb64 );
        teb32->WowTebOffset  = -teb_offset;
    }
#endif
    teb->Peb = peb;
    teb->Tib.Self = &teb->Tib;
    teb->Tib.StackBase = (void *)~0ul;
    teb->ActivationContextStackPointer = &teb->ActivationContextStack;
    InitializeListHead( &teb->ActivationContextStack.FrameListCache );
    teb->StaticUnicodeString.Buffer = teb->StaticUnicodeBuffer;
    teb->StaticUnicodeString.MaximumLength = sizeof(teb->StaticUnicodeBuffer);
    thread_data = (struct ntdll_thread_data *)&teb->GdiTebBatch;
    thread_data->request_fd = -1;
    thread_data->reply_fd   = -1;
    thread_data->wait_fd[0] = -1;
    thread_data->wait_fd[1] = -1;
    thread_data->alert_fd   = -1;
    list_add_head( &teb_list, &thread_data->entry );
    return teb;
}


/***********************************************************************
 *           virtual_alloc_first_teb
 */
TEB *virtual_alloc_first_teb(void)
{
    void *ptr;
    TEB *teb;
    unsigned int status;
    SIZE_T data_size = page_size;
    SIZE_T block_size = signal_stack_mask + 1;
    SIZE_T total = 32 * block_size;

    /* reserve space for shared user data */
    status = NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&user_shared_data, 0, &data_size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READONLY );
    if (status)
    {
        ERR( "wine: failed to map the shared user data: %08x\n", status );
        _exit(1);
    }

    /* On macOS arm64, the low 2GB range is not generally mappable because of
     * PAGEZERO constraints, so don't force first-TEB allocation below 2GB.
     */
#if defined(__aarch64__)
    /* The main image is not known until init_startup_info(), after this block
     * is allocated.  init_teb() embeds TEB32/PEB32 and writes their addresses
     * with PtrToUlong().  Keep that block representable by the 32-bit ABI even
     * when unconstrained allocations prefer the high owned arena.  The old
     * low reserved-area path and the gate-off behavior remain unchanged. */
    NtAllocateVirtualMemory( NtCurrentProcess(), &teb_block,
#if defined(__APPLE__) && defined(_WIN64)
                             mr_vm_owned ? limit_4g - 1 : 0,
#else
                             0,
#endif
                             &total,
                             MEM_RESERVE, PAGE_READWRITE );
#else
    NtAllocateVirtualMemory( NtCurrentProcess(), &teb_block, is_win64 ? limit_2g - 1 : 0, &total,
                             MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );
#endif
    teb_block_pos = 30;
    ptr = (char *)teb_block + 30 * block_size;
    data_size = 2 * block_size;
    NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&ptr, 0, &data_size, MEM_COMMIT, PAGE_READWRITE );
    peb = (PEB *)((char *)teb_block + 31 * block_size + (is_win64 ? 0 : page_size));
    teb = init_teb( ptr, FALSE );
    pthread_key_create( &teb_key, NULL );
    pthread_setspecific( teb_key, teb );
    return teb;
}


/***********************************************************************
 *           virtual_alloc_teb
 */
NTSTATUS virtual_alloc_teb( TEB **ret_teb )
{
    sigset_t sigset;
    TEB *teb;
    void *ptr = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T block_size = signal_stack_mask + 1;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (next_free_teb)
    {
        ptr = next_free_teb;
        next_free_teb = *(void **)ptr;
        memset( ptr, 0, teb_size );
    }
    else
    {
        if (!teb_block_pos)
        {
            SIZE_T total = 32 * block_size;

            if ((status = NtAllocateVirtualMemory( NtCurrentProcess(), &ptr, user_space_wow_limit,
                                                   &total, MEM_RESERVE, PAGE_READWRITE )))
            {
                server_leave_uninterrupted_section( &virtual_mutex, &sigset );
                return status;
            }
            teb_block = ptr;
            teb_block_pos = 32;
        }
        ptr = ((char *)teb_block + --teb_block_pos * block_size);
        {
            /* MacRunner 2026-08-27, Diablo — СКОЛЬКО РЕАЛЬНО ЗАКОММИЧЕНО.
             *
             * Два отказа из пяти: DFSC=0x07 (страница ОТСУТСТВУЕТ) при записи по
             * TEB+0xF238 и TEB-0xDC8. Блок TEB — 64 КБ (signal_stack_mask+1), внутри
             * TEB (0x3800) и стек сигналов; при странице macOS 16 КБ это ровно четыре
             * страницы, и 0xF238 лежит в ПОСЛЕДНЕЙ. Если коммит покрывает меньше блока,
             * последняя страница остаётся невыделенной — что и даёт DFSC=0x07.
             * Печатаем запрошенное и полученное. */
            void *было = ptr;
            SIZE_T запрошено = block_size, дано = block_size;
            NTSTATUS st = NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&ptr, 0, &дано,
                                                   MEM_COMMIT, PAGE_READWRITE );
            {
                static int n;
                if (++n <= 6)
                {
                    fprintf( stderr, "macrunner-teb-block: n=%d ptr=%p->%p запрошено=%#lx дано=%#lx st=%08x\n",
                             n, было, ptr, (unsigned long)запрошено, (unsigned long)дано, (unsigned)st );
                    fflush( stderr );
                }
            }
        }
    }
    *ret_teb = teb = init_teb( ptr, is_wow64() );

    if ((status = signal_alloc_thread( teb )))
    {
        *(void **)ptr = next_free_teb;
        next_free_teb = ptr;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *           virtual_free_teb
 */
void virtual_free_teb( TEB *teb )
{
    struct ntdll_thread_data *thread_data = (struct ntdll_thread_data *)&teb->GdiTebBatch;
    void *ptr;
    SIZE_T size;
    sigset_t sigset;
    WOW_TEB *wow_teb = get_wow_teb( teb );

    if (teb->DeallocationStack)
    {
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), &teb->DeallocationStack, &size, MEM_RELEASE );
    }
#ifdef __aarch64__
    if (teb->ChpeV2CpuAreaInfo)
    {
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), (void **)&teb->ChpeV2CpuAreaInfo, &size, MEM_RELEASE );
    }
#endif
    if (thread_data->kernel_stack)
    {
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), &thread_data->kernel_stack, &size, MEM_RELEASE );
    }
    if (wow_teb && (ptr = ULongToPtr( wow_teb->DeallocationStack )))
    {
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), &ptr, &size, MEM_RELEASE );
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    signal_free_thread( teb );
    list_remove( &thread_data->entry );
    ptr = teb;
    if (!is_win64) ptr = (char *)ptr - teb_offset;
    *(void **)ptr = next_free_teb;
    next_free_teb = ptr;
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}


/* LDT support */

#if defined(__i386__) || defined(__x86_64__)

struct ldt_copy
{
    unsigned int    base[LDT_SIZE];
    struct ldt_bits bits[LDT_SIZE];
};
C_ASSERT( sizeof(struct ldt_copy) == 8 * LDT_SIZE );

static struct ldt_copy *ldt_copy;

UINT ldt_bitmap[LDT_SIZE / 32] = { ~0u };

/***********************************************************************
 *           ldt_update_entry
 */
WORD ldt_update_entry( WORD sel, LDT_ENTRY entry )
{
    unsigned int index = sel >> 3;

    if (!ldt_copy)
    {
        struct file_view *view;

        if (map_view( &view, NULL, sizeof(*ldt_copy), MEM_TOP_DOWN,
                      VPROT_COMMITTED | VPROT_READ | VPROT_WRITE,
                      is_win64 ? limit_2g : 0, limit_4g, 0 )) return 0;
        ldt_copy = view->base;
        if (is_win64) wow_peb->SpareUlongs[0] = PtrToUlong( ldt_copy );
        else peb->SpareUlongs[0] = PtrToUlong( ldt_copy );
    }

    ldt_set_entry( sel, entry );
    ldt_copy->base[index]             = ldt_get_base( entry );
    ldt_copy->bits[index].limit       = entry.LimitLow | (entry.HighWord.Bits.LimitHi << 16);
    ldt_copy->bits[index].type        = entry.HighWord.Bits.Type;
    ldt_copy->bits[index].granularity = entry.HighWord.Bits.Granularity;
    ldt_copy->bits[index].default_big = entry.HighWord.Bits.Default_Big;
    ldt_bitmap[index / 32] |= 1u << (index & 31);
    return sel;
}

/***********************************************************************
 *           ldt_get_entry
 */
NTSTATUS ldt_get_entry( WORD sel, CLIENT_ID client_id, LDT_ENTRY *entry )
{
    NTSTATUS status = STATUS_SUCCESS;
    unsigned int base = 0;
    struct ldt_bits bits = { 0 };
    unsigned int idx = sel >> 3;

    if (client_id.UniqueProcess == NtCurrentTeb()->ClientId.UniqueProcess)
    {
        if (ldt_copy)
        {
            base = ldt_copy->base[idx];
            bits = ldt_copy->bits[idx];
        }
    }
    else
    {
        HANDLE process;
        ULONG ptr = 0;
        PEB32 *peb32 = NULL;

        if ((status = NtOpenProcess( &process, PROCESS_ALL_ACCESS, NULL, &client_id ))) return status;

        if (!is_win64)
        {
            PROCESS_BASIC_INFORMATION pbi;

            NtQueryInformationProcess( process, ProcessBasicInformation, &pbi, sizeof(pbi), NULL );
            peb32 = (PEB32 *)pbi.PebBaseAddress;
        }
        else NtQueryInformationProcess( process, ProcessWow64Information, &peb32, sizeof(peb32), NULL );

        if (!NtReadVirtualMemory( process, &peb32->SpareUlongs[0], &ptr, sizeof(ptr), NULL ) && ptr)
        {
            struct ldt_copy *ldt = ULongToPtr( ptr );
            NtReadVirtualMemory( process, &ldt->base[idx], &base, sizeof(base), NULL );
            NtReadVirtualMemory( process, &ldt->bits[idx], &bits, sizeof(bits), NULL );
        }
        NtClose( process );
    }

    if (base || bits.limit || bits.type) *entry = ldt_make_entry( base, bits );
    else status = STATUS_UNSUCCESSFUL;

    return status;
}

/******************************************************************************
 *           NtSetLdtEntries   (NTDLL.@)
 *           ZwSetLdtEntries   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetLdtEntries( ULONG sel1, LDT_ENTRY entry1, ULONG sel2, LDT_ENTRY entry2 )
{
    sigset_t sigset;

    if (is_win64 && !is_wow64()) return STATUS_NOT_IMPLEMENTED;
    if (sel1 >> 16 || sel2 >> 16) return STATUS_INVALID_LDT_DESCRIPTOR;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (sel1) ldt_update_entry( sel1, entry1 );
    if (sel2) ldt_update_entry( sel2, entry2 );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return STATUS_SUCCESS;
}

#else /* defined(__i386__) || defined(__x86_64__) */

/******************************************************************************
 *           NtSetLdtEntries   (NTDLL.@)
 *           ZwSetLdtEntries   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetLdtEntries( ULONG sel1, LDT_ENTRY entry1, ULONG sel2, LDT_ENTRY entry2 )
{
    return STATUS_NOT_IMPLEMENTED;
}

#endif /* defined(__i386__) || defined(__x86_64__) */


/***********************************************************************
 *           virtual_clear_tls_index
 */
NTSTATUS virtual_clear_tls_index( ULONG index )
{
    struct ntdll_thread_data *thread_data;
    sigset_t sigset;

    if (index < TLS_MINIMUM_AVAILABLE)
    {
        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        LIST_FOR_EACH_ENTRY( thread_data, &teb_list, struct ntdll_thread_data, entry )
        {
            TEB *teb = CONTAINING_RECORD( thread_data, TEB, GdiTebBatch );
#ifdef _WIN64
            WOW_TEB *wow_teb = get_wow_teb( teb );
            if (wow_teb) wow_teb->TlsSlots[index] = 0;
            else
#endif
            teb->TlsSlots[index] = 0;
        }
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    }
    else
    {
        index -= TLS_MINIMUM_AVAILABLE;
        if (index >= 8 * sizeof(peb->TlsExpansionBitmapBits)) return STATUS_INVALID_PARAMETER;

        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        LIST_FOR_EACH_ENTRY( thread_data, &teb_list, struct ntdll_thread_data, entry )
        {
            TEB *teb = CONTAINING_RECORD( thread_data, TEB, GdiTebBatch );
#ifdef _WIN64
            WOW_TEB *wow_teb = get_wow_teb( teb );
            if (wow_teb)
            {
                if (wow_teb->TlsExpansionSlots)
                    ((ULONG *)ULongToPtr( wow_teb->TlsExpansionSlots ))[index] = 0;
            }
            else
#endif
            if (teb->TlsExpansionSlots) teb->TlsExpansionSlots[index] = 0;
        }
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           virtual_alloc_thread_stack
 */
NTSTATUS virtual_alloc_thread_stack( INITIAL_TEB *stack, ULONG_PTR limit_low, ULONG_PTR limit_high,
                                     SIZE_T reserve_size, SIZE_T commit_size, BOOL guard_page )
{
    struct file_view *view;
    NTSTATUS status;
    sigset_t sigset;
    SIZE_T size;
    char *stack_limit, *view_end;

    if (!reserve_size) reserve_size = main_image_info.MaximumStackSize;
    if (!commit_size) commit_size = main_image_info.CommittedStackSize;

    size = max( reserve_size, commit_size );
    if (size < 1024 * 1024) size = 1024 * 1024;  /* Xlib needs a large stack */
#if defined(__APPLE__) && defined(__aarch64__)
    /* Pure-arm64 WOW64/HyperBridge executes PE32 init through native ARM64 PE
     * syscalls, unixlib callbacks, and translated guest frames.  The previous
     * 8 MB minimum still reaches the guard page during nested win32u/user32
     * callbacks; keep normal native-stack exception delivery room on
     * macOS/arm64. */
    if (size < 16 * 1024 * 1024) size = 16 * 1024 * 1024;
#elif defined(__aarch64__)
    /* arm64 uses larger signal/exception frames than x86. */
    if (size < 2 * 1024 * 1024) size = 2 * 1024 * 1024;
#endif
    if (!round_size_checked( 0, size, granularity_mask, &size )) return STATUS_NO_MEMORY;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    status = map_view( &view, NULL, size, 0, VPROT_READ | VPROT_WRITE | VPROT_COMMITTED,
                       limit_low, limit_high, 0 );
    if (status != STATUS_SUCCESS) goto done;
    if (!get_view_limit( view, &view_end ))
    {
        delete_view( view );
        status = STATUS_NO_MEMORY;
        goto done;
    }
    stack_limit = view->base;

#ifdef VALGRIND_STACK_REGISTER
    VALGRIND_STACK_REGISTER( view->base, view_end );
#endif

    /* setup no access guard page */
    if (guard_page)
    {
        char *guard_base;

        if (host_page_size > ~(UINT_PTR)0 - (UINT_PTR)view->base)
        {
            delete_view( view );
            status = STATUS_NO_MEMORY;
            goto done;
        }
        guard_base = (char *)view->base + host_page_size;
        if (host_page_size > ~(UINT_PTR)0 - (UINT_PTR)guard_base)
        {
            delete_view( view );
            status = STATUS_NO_MEMORY;
            goto done;
        }
        stack_limit = guard_base + host_page_size;
        set_page_vprot( view->base, host_page_size, 0 );
        set_page_vprot( guard_base, host_page_size, VPROT_READ | VPROT_WRITE | VPROT_COMMITTED | VPROT_GUARD );
        mprotect_range( view->base, stack_limit - (char *)view->base, 0, 0 );
    }
    VIRTUAL_DEBUG_DUMP_VIEW( view );

    /* note: limit is lower than base since the stack grows down */
    stack->OldStackBase = 0;
    stack->OldStackLimit = 0;
    stack->DeallocationStack = view->base;
    stack->StackBase = view_end;
    stack->StackLimit = stack_limit;
done:
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


static const WCHAR shared_data_nameW[] = {'\\','K','e','r','n','e','l','O','b','j','e','c','t','s',
                                          '\\','_','_','w','i','n','e','_','u','s','e','r','_','s','h','a','r','e','d','_','d','a','t','a',0};

/***********************************************************************
 *           virtual_map_user_shared_data
 */
void virtual_map_user_shared_data(void)
{
    UNICODE_STRING name_str = RTL_CONSTANT_STRING( shared_data_nameW );
    OBJECT_ATTRIBUTES attr = { sizeof(attr), 0, &name_str };
    unsigned int status;
    HANDLE section;
    int res, fd, needs_close;
    void *mapped;

    if ((status = NtOpenSection( &section, SECTION_ALL_ACCESS, &attr )))
    {
        ERR( "failed to open the USD section: %08x\n", status );
        exit(1);
    }
    if ((res = server_get_unix_fd( section, 0, &fd, &needs_close, NULL, NULL )))
    {
        ERR( "failed to remap the process USD: %d\n", res );
        exit(1);
    }
#if defined(__aarch64__)
    {
        mach_vm_address_t addr = (mach_vm_address_t)(uintptr_t)user_shared_data;
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        kern_return_t kr;

        kr = mach_vm_region( mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                             (vm_region_info_t)&info, &count, &object );
        if (kr != KERN_SUCCESS || addr != (mach_vm_address_t)(uintptr_t)user_shared_data || size < page_size)
        {
            ERR( "USD slot %p is not reserved by the preloader: kr=%x addr=%llx size=%llx\n",
                 user_shared_data, kr, (unsigned long long)addr, (unsigned long long)size );
            exit(1);
        }
        kr = mach_vm_protect( mach_task_self(), addr, page_size, FALSE, VM_PROT_READ | VM_PROT_WRITE );
        if (kr != KERN_SUCCESS)
        {
            ERR( "failed to protect the reserved USD slot %p: %x\n", user_shared_data, kr );
            exit(1);
        }
    }
#endif
    mapped = mmap( user_shared_data, page_size, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0 );
    if (mapped != user_shared_data)
    {
        ERR( "failed to remap the process USD at %p: errno=%d\n", user_shared_data, errno );
        exit(1);
    }
    if (needs_close) close( fd );
    NtClose( section );
}


/******************************************************************
 *		virtual_init_user_shared_data
 *
 * Initialize user shared data before running wineboot.
 */
void virtual_init_user_shared_data(void)
{
    UNICODE_STRING name_str = RTL_CONSTANT_STRING( shared_data_nameW );
    OBJECT_ATTRIBUTES attr = { sizeof(attr), 0, &name_str };
    SYSTEM_BASIC_INFORMATION info;
    KUSER_SHARED_DATA *data;
    unsigned int status;
    HANDLE section;
    int res, fd, needs_close;

    if ((status = NtOpenSection( &section, SECTION_ALL_ACCESS, &attr )))
    {
        ERR( "failed to open the USD section: %08x\n", status );
        exit(1);
    }
    if ((res = server_get_unix_fd( section, 0, &fd, &needs_close, NULL, NULL )) ||
        (data = mmap( NULL, sizeof(*data), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 )) == MAP_FAILED)
    {
        ERR( "failed to remap the process USD: %d\n", res );
        exit(1);
    }
    if (needs_close) close( fd );
    NtClose( section );

    virtual_get_system_info( &info, FALSE );

    data->TickCountMultiplier   = 1 << 24;
    data->LargePageMinimum      = 2 * 1024 * 1024;
    data->SystemCall            = 1;
    data->NumberOfPhysicalPages = info.MmNumberOfPhysicalPages;
    data->NXSupportPolicy       = NX_SUPPORT_POLICY_OPTIN;
    data->ActiveProcessorCount  = peb->NumberOfProcessors;
    data->ActiveGroupCount      = 1;

    switch (native_machine)
    {
    case IMAGE_FILE_MACHINE_I386:  data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL; break;
    case IMAGE_FILE_MACHINE_AMD64: data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64; break;
    case IMAGE_FILE_MACHINE_ARMNT: data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM; break;
    case IMAGE_FILE_MACHINE_ARM64: data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM64; break;
    }

    init_shared_data_cpuinfo( data );
    munmap( data, sizeof(*data) );
}


struct thread_stack_info
{
    char  *start;
    char  *limit;
    char  *end;
    SIZE_T guaranteed;
    BOOL   is_wow;
};

/***********************************************************************
 *           is_inside_thread_stack
 */
static BOOL is_inside_thread_stack( void *ptr, struct thread_stack_info *stack )
{
    TEB *teb = NtCurrentTeb();
    WOW_TEB *wow_teb = get_wow_teb( teb );
    size_t min_guaranteed = max( page_size * (is_win64 ? 2 : 1), host_page_size );

#if defined(__APPLE__) && defined(__aarch64__)
    /* ARM64 PE exception dispatch uses larger native frames than the generic
     * host-page guarantee leaves available after a guard-page stack overflow. */
    min_guaranteed = max( min_guaranteed, (size_t)0x100000 );
#endif

    stack->start = teb->DeallocationStack;
    stack->limit = teb->Tib.StackLimit;
    stack->end   = teb->Tib.StackBase;
    stack->guaranteed = max( teb->GuaranteedStackBytes, min_guaranteed );
    stack->is_wow = FALSE;
    if ((char *)ptr > stack->start && (char *)ptr <= stack->end) return TRUE;

    if (!wow_teb) return FALSE;
    stack->start = ULongToPtr( wow_teb->DeallocationStack );
    stack->limit = ULongToPtr( wow_teb->Tib.StackLimit );
    stack->end   = ULongToPtr( wow_teb->Tib.StackBase );
    stack->guaranteed = max( wow_teb->GuaranteedStackBytes, min_guaranteed );
    stack->is_wow = TRUE;
    return ((char *)ptr > stack->start && (char *)ptr <= stack->end);
}


/***********************************************************************
 *           grow_thread_stack
 */
static NTSTATUS grow_thread_stack( char *page, struct thread_stack_info *stack_info )
{
    NTSTATUS ret = 0;

    set_page_vprot_bits( page, host_page_size, VPROT_COMMITTED, VPROT_GUARD );
    mprotect_range( page, host_page_size, 0, 0 );
    if (page >= stack_info->start + host_page_size + stack_info->guaranteed)
    {
        set_page_vprot_bits( page - host_page_size, host_page_size, VPROT_COMMITTED | VPROT_GUARD, 0 );
        mprotect_range( page - host_page_size, host_page_size, 0, 0 );
    }
    else  /* inside guaranteed space -> overflow exception */
    {
        page = stack_info->start + host_page_size;
        set_page_vprot_bits( page, stack_info->guaranteed, VPROT_COMMITTED, VPROT_GUARD );
        mprotect_range( page, stack_info->guaranteed, 0, 0 );
        ret = STATUS_STACK_OVERFLOW;
    }
    if (stack_info->is_wow)
    {
        WOW_TEB *wow_teb = get_wow_teb( NtCurrentTeb() );
        wow_teb->Tib.StackLimit = PtrToUlong( page );
    }
    else NtCurrentTeb()->Tib.StackLimit = page;
    return ret;
}


/***********************************************************************
 *           virtual_handle_fault
 */
NTSTATUS virtual_handle_fault( EXCEPTION_RECORD *rec, void *stack )
{
    NTSTATUS ret = STATUS_ACCESS_VIOLATION;
    ULONG_PTR err = rec->ExceptionInformation[0];
    void *addr = (void *)rec->ExceptionInformation[1];
    char *page = ROUND_ADDR( addr, host_page_mask );
    BYTE vprot;

    mutex_lock( &virtual_mutex );  /* no need for signal masking inside signal handler */
    vprot = get_host_page_vprot( page );

#ifdef __APPLE__
    /* Rosetta on Apple Silicon misreports certain write faults as read faults. */
    if (err == EXCEPTION_READ_FAULT && (get_unix_prot( vprot ) & PROT_READ))
    {
        err = EXCEPTION_WRITE_FAULT;
    }

#if defined(__APPLE__) && defined(__aarch64__)
    /* ★ ЛОВУШКА ЗАПИСИ ПО КОДУ — разбор отказа по правам ИМЕННО 4-КБ страницы.
     *
     * СТОЯТЬ ОБЯЗАНА ВЫШЕ «CW Hack 24945»: тот при объединении W|X снимает EXEC и
     * отдаёт хозяйской странице запись, то есть погасил бы ловушку ДО того, как её
     * успели разобрать, и тихий отказ вернулся бы в прежнем виде.
     *
     * Условие сужено до того случая, который создали мы сами:
     *   объединение подстраниц ДАЁТ запись, а применённые права её НЕ дают
     *   -> значит запись сняли мы (get_host_page_unix_prot), и отвечать за отказ нам.
     * При однородных правах внутри хозяйской страницы обе части равны и ветвь молчит. */
    if (err == EXCEPTION_WRITE_FAULT && host_page_size > page_size &&
        macrunner_code_write_trap_mode() == 1)
    {
        BYTE gvprot = get_page_vprot( addr );

        if ((gvprot & VPROT_COMMITTED) && !(gvprot & VPROT_GUARD) &&
            !(gvprot & (VPROT_WRITE | VPROT_WRITECOPY)) &&
            (get_unix_prot( vprot ) & PROT_WRITE) &&
            !(get_host_page_unix_prot( page, 0, 0,
                  macrunner_code_write_trap_view_ok( find_view( page, host_page_size ) ) ) & PROT_WRITE))
        {
            unsigned long long n = __atomic_add_fetch( &macrunner_code_write_trap_av, 1,
                                                       __ATOMIC_RELAXED );

            if (n <= 8 || !(n & 0x3ff))
            {
                fprintf( stderr, "macrunner-code-write-trap-av: addr=%p page=%p gvprot=%#x n=%llu\n",
                         addr, page, gvprot, n );
                fflush( stderr );
            }
            ret = STATUS_ACCESS_VIOLATION;
            goto done;
        }
    }
#endif

#if defined(__APPLE__) && defined(__aarch64__)
    /* ★★★★ ЛЕЙН MAPJIT 08.09.2026 — ОТКАЗ НА ОБЛАСТИ MAP_JIT ЛЕЧИТСЯ ПОТОКОВЫМ W^X,
     * А mprotect-ом НЕ ЛЕЧИТСЯ ВООБЩЕ. Здесь и была бесконечная качка.
     *
     * ИЗМЕРЕНО (прибор scratchpad/wx_probe.c, эта машина, страница 16 КБ):
     *     pthread_jit_write_protect_supported_np() = 1
     *     запись в MAP_JIT БЕЗ toggle          -> ОТКАЗ      (состояние по умолчанию — «исполнять»)
     *     запись после wp(0)                   -> прошла
     *     запись после wp(1)                   -> ОТКАЗ      (W^X действует по-настоящему)
     *     запись ВНУТРИ обработчика сигнала    -> прошла     (вход в обработчик состояние НЕ сбрасывает)
     *
     * ПОЧЕМУ ПРЕЖНИЙ ПУТЬ ЗАЦИКЛИВАЛСЯ. Отказ записи по области MAP_JIT попадал ниже,
     * в «CW Hack 24945»; тот зовёт mprotect_range -> mprotect_exec, а mprotect_exec для
     * представления с VPROT_MACRUNNER_JIT возвращает 0, НЕ ТРОГАЯ прав (см. ветвь выше по
     * файлу — для MAP_JIT это единственно верно, ядро второй mprotect и не примет).
     * Дальше обработчик рапортовал STATUS_SUCCESS, команда повторялась, отказ повторялся —
     * и так без конца. Замер до правки: 15 901 696 отказов на ОДНОМ адресе 0x10f1d4c4c
     * за 40 с, прогон не завершается, 4 из 4.
     *
     * ЧЬЯ ЭТО ПАМЯТЬ. Главная арена JIT самого FEX: SharedCodeBufferManager.cpp:21
     * VirtualAlloc(Size, true), INITIAL_CODE_SIZE = 16 МиБ — ровно наблюдаемое
     * «macrunner-fex-jit-map: base=0x10f1d0000 size=1000000». Пишет туда ОДНО место —
     * memcpy в JIT.cpp:1114 под CodeBufferWriteMutex. Скобки W^X у FEX нет и быть не
     * может: во ВСЁМ дереве engine/fex ноль упоминаний MAP_JIT и
     * pthread_jit_write_protect_np, его модель — постоянный RWX (SharedCodeBufferManager.cpp:48-52).
     * Значит переключать состояние обязаны МЫ, и единственное место, где это можно
     * сделать не трогая FEX, — здесь, по факту отказа.
     *
     * ПОЧЕМУ ЭТО НЕ НОВАЯ КАЧКА. Переключение МЕНЯЕТ состояние потока, то есть каждый
     * отказ продвигает: запись -> разрешили запись; исполнение -> разрешили исполнение.
     * Ровно так работает всякий JIT под W^X.
     *
     * ★★★★ И ВОТ ЧЕМ ЭТО КОНЧИЛОСЬ — ЛЕЧЕНИЕ ИЗМЕРЕНО И НЕ РАБОТАЕТ. ГЕЙТ СВОЙ, УМОЛЧАНИЕ 0.
     *
     * Переключение действительно снимает ПЕРВЫЙ клин (тот, что был у «CW Hack 24945»):
     *     до правки  pass = 15 901 696 на одном адресе, 4 прогона из 4
     *     с правкой  pass = 1
     * Но под ним обнаружился ВТОРОЙ, независимый: отказы идут строго через один —
     * запись 0x10f1d4c4c / исполнение 0x10f1d4c5c, — и продвижения нет вовсе:
     *     268 435 562 переключения за 40 с, ТРИ прогона из трёх, число совпадает до единицы
     *     av = 1 (гость отказал ОДИН раз), содержимое по адресу не меняется НИ РАЗУ
     * То есть FEX после нашего c0000005 бесконечно выпускает ОДИН И ТОТ ЖЕ блок
     * (гостевой RIP 0x140001727 собирается в x6 на глазах у прибора), а цена W^X —
     * следствие, а не причина. Лечить надо не здесь.
     *
     * ПОЭТОМУ ВЕТВЬ ПОД СВОИМ ГЕЙТОМ MACRUNNER_HB_JIT_WX_TOGGLE, УМОЛЧАНИЕ 0: при
     * умолчании дерево ведёт себя в ТОЧНОСТИ как до захода (проверено: 5 прогонов из 5
     * RC=107, OUTCOME=3, переключений 0, pass 0). Включать — только вместе с замером. */
    {
        struct file_view *jv = find_view( page, host_page_size );
        static __thread unsigned long long jit_view_runs;
        static int wx_mode = -1;

        if (wx_mode < 0)
        {
            const char *v = getenv( "MACRUNNER_HB_JIT_WX_TOGGLE" );
            wx_mode = (v && *v && *v != '0') ? 1 : 0;
        }

        if (wx_mode && jv && (jv->protect & VPROT_MACRUNNER_JIT) &&
            (err == EXCEPTION_WRITE_FAULT || err == EXCEPTION_EXECUTE_FAULT))
        {
            /* ★★★ СЧЁТ ПО ПРЕДСТАВЛЕНИЮ, А НЕ ПО АДРЕСУ — И ЭТО ИСПРАВЛЕНИЕ ПО ЗАМЕРУ.
             *
             * Сначала предел стоял по ОДНОМУ адресу (`addr == last_addr`). Замер показал,
             * что так он не сработает НИКОГДА: отказы идут строго через один — запись по
             * 0x10f1d4c4c, исполнение по 0x10f1d4c5c, — поэтому «подряд» всегда 1, а
             * счётчик обнуляется каждым вторым отказом. 53 280 768 переключений при
             * пределе 64: сторож был, но не сторожил.
             *
             * ★ И ОТДЕЛЬНО — ПРИБОР ВРАЛ. Печать шла при `n <= 8 || !(n & 0xffff)`; шаг
             * 65536 ЧЁТНЫЙ, а чередование строгое, поэтому выборка попадала ВСЕГДА в одну
             * и ту же фазу: 817 печатей «исполнение» против 3 «запись». Соотношение
             * прочиталось бы как «отказы исполнения преобладают в 270 раз», тогда как на
             * деле их поровну. Шаг печати, кратный периоду события, показывает одну фазу.
             *
             * Поэтому считаем ЛЮБЫЕ переключения по этому представлению подряд, а сбрасываем
             * счётчик только тогда, когда отказ пришёл НЕ по области MAP_JIT (то есть работа
             * действительно продвинулась куда-то ещё). */
            unsigned long long n;

            /* ★ Счётчик МОНОТОННЫЙ, сброса нет. Прежний вариант сбрасывался на отказе
             * вне области MAP_JIT — а такие отказы порождает сам же уход прежним путём,
             * поэтому предел не срабатывал никогда: замер дал 268 435 562 переключения
             * при пределе 1 000 000. Без сброса худшее, что может случиться, —
             * ровно прежнее поведение. */
            /* ★★★ САМОЗАПИСЬ ВНУТРИ ОБЛАСТИ MAP_JIT — ПЕРЕКЛЮЧЕНИЕМ НЕ ЛЕЧИТСЯ ВООБЩЕ.
             *
             * Замер лейна КЛИН-2 (прибор `pc=`/`pc_в_jit=` ниже, 23 печати из 23 и 8 498
             * из 8 499): PC отказа = 0x10f1d4c5c, ВНУТРИ той же области MAP_JIT, что и
             * адрес записи 0x10f1d4c4c = PC-0x10. Команда по PC — `a9bf2a26`
             * (`stp x6, x10, [x17, #-0x10]!`), то есть x17 == PC: пуш стека возвратов FEX
             * уехал в кодовую арену.
             *
             * Такую команду ИСПОЛНИТЬ И ЗАПИСАТЬ ОДНОВРЕМЕННО НЕЛЬЗЯ: выборка требует
             * wp(1), запись требует wp(0). Переключение из обработчика лишь меняет, какая
             * из двух половин откажет, — отсюда строгое чередование write/exec и миллионы
             * отказов при нулевом продвижении.
             *
             * И ГЛАВНОЕ: у FEX для этого отказа ЕСТЬ СВОЙ обработчик —
             * `CallRetStack::HandleAccessViolation` (Source/Windows/Common/CallRetStack.h)
             * сбрасывает x17 на DefaultLocation, стек возвратов заведён с охранными
             * страницами PAGE_NOACCESS с ОБЕИХ сторон именно под этот случай. Он
             * вызывается из `ResetToConsistentStateImpl`, то есть требует, чтобы отказ
             * ДОШЁЛ до эмулятора. Наш обработчик его съедал: замер КЛИН-2 —
             * `ResetToConsistentStateImpl` вызван 4 раза за прогон, а
             * `HandleRWXAccessViolation` вернул «обработано» 0 раз, при миллионах отказов.
             *
             * Поэтому: отказ ЗАПИСИ, у которого И адрес, И PC лежат в областях MAP_JIT,
             * отдаём дальше как STATUS_ACCESS_VIOLATION — мимо «CW Hack 24945», которая
             * иначе вернёт STATUS_SUCCESS, ничего не изменив.
             *
             * Гейт свой, умолчание 0. */
            {
                static int selfwrite_mode = -1;
                if (selfwrite_mode < 0)
                {
                    const char *v = getenv( "MACRUNNER_HB_JIT_SELFWRITE_AV" );
                    selfwrite_mode = (v && *v && *v != '0') ? 1 : 0;
                }
                if (selfwrite_mode && err == EXCEPTION_WRITE_FAULT && macrunner_fault_pc)
                {
                    struct file_view *pcv = find_view( ROUND_ADDR( macrunner_fault_pc, host_page_mask ),
                                                       host_page_size );
                    if (pcv && (pcv->protect & VPROT_MACRUNNER_JIT))
                    {
                        static unsigned long long sw_n;
                        unsigned long long k = __atomic_add_fetch( &sw_n, 1, __ATOMIC_RELAXED );
                        if (k <= 8 || !(k & 0x3ff))
                        {
                            /* ★ СТЕНА64: НАЗВАТЬ БАЗОВЫЙ РЕГИСТР, А НЕ ПРЕДПОЛАГАТЬ ЕГО.
                             *
                             * КЛИН-2 на p4smc прочитал команду `a9bf2a26` = `stp x6,x10,[x17,#-0x10]!`
                             * и заключил «x17 уехал в кодовую арену». На notepad++ разница
                             * pc-addr = 0x1b0, а не 0x10 — то есть команда ДРУГАЯ, и перенос
                             * вывода про x17 был бы догадкой. Печатаем саму команду, номер её
                             * базового регистра (биты [9:5] — общее место у всей группы
                             * загрузки/сохранения) и ЗНАЧЕНИЕ этого регистра из снимка.
                             *
                             * Решающая проверка ставится прямо здесь: `дельта` = x[база] - addr.
                             * Совпадение с непосредственным смещением команды доказывает, что
                             * запись идёт ИМЕННО через этот регистр, а не через случайное
                             * совпадение адресов. */
                            unsigned int insn = 0;
                            int rn = -1;
                            unsigned long long rv = 0;
                            int rn_v_jit = 0;
                            if (macrunner_fault_x_valid)
                            {
                                insn = *(const unsigned int *)((ULONG_PTR)macrunner_fault_pc & ~3ull);
                                rn = (int)((insn >> 5) & 0x1f);
                                rv = (rn == 31) ? macrunner_fault_x[31] : macrunner_fault_x[rn];
                                {
                                    struct file_view *rv_v = find_view( ROUND_ADDR( (void *)(ULONG_PTR)rv,
                                                                                    host_page_mask ),
                                                                        host_page_size );
                                    rn_v_jit = (rv_v && (rv_v->protect & VPROT_MACRUNNER_JIT)) ? 1 : 0;
                                }
                            }
                            fprintf( stderr, "macrunner-jit-selfwrite-av: addr=%p pc=%p n=%llu"
                                     " insn=%08x base=x%d base_val=%#llx base_в_jit=%d дельта=%lld"
                                     " x16=%#llx x17=%#llx x30=%#llx sp=%#llx — отдаём отказ эмулятору\n",
                                     addr, macrunner_fault_pc, k,
                                     insn, rn, rv, rn_v_jit,
                                     (long long)(rv - (unsigned long long)(ULONG_PTR)addr),
                                     macrunner_fault_x[16], macrunner_fault_x[17],
                                     macrunner_fault_x[30], macrunner_fault_x[31] );
                            fflush( stderr );
                        }
                        ret = STATUS_ACCESS_VIOLATION;
                        goto done;
                    }
                }
            }

            jit_view_runs++;

            if (jit_view_runs <= macrunner_jit_wx_max_runs())
            {
                /* Запись -> снять потоковую защиту записи; исполнение -> вернуть её. */
                pthread_jit_write_protect_np( err == EXCEPTION_WRITE_FAULT ? 0 : 1 );
                n = __atomic_add_fetch( &macrunner_jit_wx_toggles, 1, __ATOMIC_RELAXED );
                if (n <= 8 || !(n & 0xffff))
                {
                    /* ★ rec->ExceptionAddress ЗДЕСЬ ПУСТ (замер: pc=0x0 во всех 8 печатях) —
                     * его заполняет обработчик сигнала ПОЗЖЕ. Прибор по нему негоден, и я им
                     * не пользуюсь.
                     *
                     * Зато у отказа ИСПОЛНЕНИЯ сам `addr` И ЕСТЬ PC. Печатаем слова по adr —
                     * область читаема в обоих состояниях W^X, так что чтение безопасно. Этого
                     * довольно, чтобы отличить «пишет чужой модуль» (лечится) от «выпущенный
                     * код пишет в самого себя» (структурный клин: исполнить команду можно лишь
                     * при wp(1), а её запись пройдёт лишь при wp(0) — одновременно нельзя). */
                    /* ★★★ ФОРМАТ БЫЛ СЛОМАН — И ЭТО ОТМЕНИЛО ГЛАВНЫЙ ВЫВОД ПРОШЛОГО ЗАХОДА.
                     *
                     * Было: одиннадцать спецификаторов (`%p %s %llu %llu %llu %llu` + пять
                     * `%08x`) против ДЕВЯТИ аргументов. Лишние два `%llu` съедали `w[-2]` и
                     * `w[-1]`, а два последних `%08x` читали за концом списка. Напечатанное
                     * «n=268435562 переключений» было словом `0x1000006A` — командой `adr`,
                     * а «совпадает до единицы в трёх прогонах» объяснялось тем, что это
                     * КОНСТАНТА в выпущенном коде, а не замер. Настоящий счёт в тех же
                     * прогонах доходил до 1 000 000 (предел), после чего клин возвращался.
                     *
                     * Правило отсюда: число, НЕ меняющееся между прогонами, подозрительно
                     * само по себе — у живого счётчика есть разброс. */
                    const unsigned int *w = (const unsigned int *)((ULONG_PTR)addr & ~3ull);
                    void *fpc = macrunner_fault_pc;
                    struct file_view *pv = fpc ? find_view( ROUND_ADDR( fpc, host_page_mask ), host_page_size ) : NULL;

                    fprintf( stderr, "macrunner-jit-wx-toggle: addr=%p %s подряд=%llu n=%llu"
                             " pc=%p pc_в_jit=%d слова[-2..+2]=%08x %08x %08x %08x %08x\n",
                             addr, err == EXCEPTION_WRITE_FAULT ? "write->wp(0)" : "exec->wp(1)",
                             jit_view_runs, n, fpc,
                             (pv && (pv->protect & VPROT_MACRUNNER_JIT)) ? 1 : 0,
                             w[-2], w[-1], w[0], w[1], w[2] );
                    fflush( stderr );
                }
                ret = STATUS_SUCCESS;
                goto done;
            }
            else
            {
                static unsigned int mr_wx_giveup;
                if (__atomic_add_fetch( &mr_wx_giveup, 1, __ATOMIC_RELAXED ) <= 8)
                {
                    fprintf( stderr, "macrunner-jit-wx-предел: addr=%p подряд=%llu — прежним путём\n",
                             addr, jit_view_runs );
                    fflush( stderr );
                }
            }
        }
    }
#endif

    /* CW Hack 24945 */
    if (err == EXCEPTION_WRITE_FAULT &&
        ((get_unix_prot( vprot ) & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)))
    {
        unsigned long long np = __atomic_add_fetch( &macrunner_code_write_trap_pass, 1,
                                                    __ATOMIC_RELAXED );

        if (np <= 8 || !(np & 0x3ff))
        {
            fprintf( stderr, "macrunner-code-write-trap-pass: addr=%p page=%p gvprot=%#x n=%llu pc=%p\n",
                     addr, page, get_page_vprot( addr ), np,
#if defined(__APPLE__) && defined(__aarch64__)
                     macrunner_fault_pc
#else
                     (void *)0
#endif
                     );
            fflush( stderr );
        }
        mprotect_range( page, host_page_size, 0, VPROT_EXEC | VPROT_WRITEWATCH );
        ret = STATUS_SUCCESS;
        goto done;
    }

    /* CW Hack 25719 */
    if (err == EXCEPTION_EXECUTE_FAULT && (get_unix_prot( vprot ) & PROT_EXEC))
    {
        mprotect_range( page, host_page_size, 0, VPROT_EXEC );
        mprotect_range( page, host_page_size, VPROT_EXEC, 0 );
        ret = STATUS_SUCCESS;
        goto done;
    }
#endif

#if defined(__APPLE__) && defined(__aarch64__)
    if (!is_inside_signal_stack( stack ) && err != EXCEPTION_EXECUTE_FAULT)
    {
        struct thread_stack_info stack_info;

        if (is_inside_thread_stack( addr, &stack_info ) &&
            page < stack_info.start + host_page_size &&
            (char *)stack >= stack_info.start &&
            (char *)stack < stack_info.start + host_page_size)
        {
            set_page_vprot_bits( stack_info.start, host_page_size, VPROT_COMMITTED, VPROT_GUARD );
            mprotect_range( stack_info.start, host_page_size, 0, 0 );
            ret = STATUS_SUCCESS;
            goto done;
        }
    }
#endif

    if (!is_inside_signal_stack( stack ) && (vprot & VPROT_GUARD))
    {
        struct thread_stack_info stack_info;
        if (!is_inside_thread_stack( page, &stack_info ))
        {
            set_page_vprot_bits( page, host_page_size, 0, VPROT_GUARD );
            mprotect_range( page, host_page_size, 0, 0 );
            ret = STATUS_GUARD_PAGE_VIOLATION;
        }
        else ret = grow_thread_stack( page, &stack_info );
    }
#if defined(__APPLE__) && defined(__aarch64__)
    else if (!is_inside_signal_stack( stack ) && err != EXCEPTION_EXECUTE_FAULT)
    {
        struct thread_stack_info stack_info;

        if (is_inside_thread_stack( addr, &stack_info ) &&
            page < stack_info.limit && page + host_page_size >= stack_info.limit &&
            (char *)stack >= stack_info.limit && (char *)stack <= stack_info.end)
            ret = grow_thread_stack( page, &stack_info );
    }
#endif
    else if (err == EXCEPTION_WRITE_FAULT)
    {
        if (vprot & VPROT_WRITEWATCH)
        {
            if (enable_write_exceptions && is_vprot_exec_write( vprot ) && !ntdll_get_thread_data()->allow_writes)
            {
                rec->NumberParameters = 3;
                rec->ExceptionInformation[2] = STATUS_EXECUTABLE_MEMORY_WRITE;
                ret = STATUS_IN_PAGE_ERROR;
            }
            else
            {
                set_page_vprot_bits( page, host_page_size, 0, VPROT_WRITEWATCH );
                mprotect_range( page, host_page_size, 0, 0 );
            }
        }
        /* ignore fault if page is writable now */
        if (get_unix_prot( get_host_page_vprot( page )) & PROT_WRITE)
        {
            if ((vprot & VPROT_WRITEWATCH) || is_write_watch_range( page, 1 ))
                ret = STATUS_SUCCESS;
        }
    }

#ifdef __APPLE__
done:
#endif
    mutex_unlock( &virtual_mutex );
    rec->ExceptionCode = ret;
    return ret;
}


/***********************************************************************
 *           virtual_setup_exception
 */
void *virtual_setup_exception( void *stack_ptr, size_t size, EXCEPTION_RECORD *rec )
{
    char *stack = stack_ptr;
    struct thread_stack_info stack_info;

    if (!is_inside_thread_stack( stack, &stack_info ))
    {
        if (is_inside_signal_stack( stack ))
        {
            ERR( "nested exception on signal stack addr %p stack %p\n", rec->ExceptionAddress, stack );
            abort_thread(1);
        }
        WARN( "exception outside of stack limits addr %p stack %p (%p-%p-%p)\n",
              rec->ExceptionAddress, stack, NtCurrentTeb()->DeallocationStack,
              NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
        return stack - size;
    }

#if defined(__APPLE__) && defined(__aarch64__)
    if (rec->ExceptionCode == STATUS_STACK_OVERFLOW &&
        stack_info.guaranteed >= host_page_size &&
        stack_info.limit <= stack_info.start + host_page_size)
    {
        char *guarantee = stack_info.start + host_page_size;
        char *guarantee_top = guarantee + stack_info.guaranteed;

        if (guarantee_top > stack_info.end) guarantee_top = stack_info.end;
        stack = (char *)((ULONG_PTR)guarantee_top & ~(ULONG_PTR)15) - size;
        if (stack >= stack_info.start + host_page_size)
        {
            mutex_lock( &virtual_mutex );
            set_page_vprot_bits( guarantee, guarantee_top - guarantee,
                                 VPROT_COMMITTED, VPROT_GUARD );
            mprotect_range( guarantee, guarantee_top - guarantee, 0, 0 );
            mutex_unlock( &virtual_mutex );
            rec->NumberParameters = 0;
            return stack;
        }
    }
#endif

    stack -= size;

    if (stack < stack_info.start + host_page_size)
    {
        UINT diff;
#if defined(__APPLE__) && defined(__aarch64__)
        if (stack_info.guaranteed >= host_page_size &&
            stack_info.limit <= stack_info.start + host_page_size &&
            (rec->ExceptionCode == STATUS_STACK_OVERFLOW ||
             (char *)stack_ptr <= stack_info.start + host_page_size))
        {
            char *guarantee = stack_info.start + host_page_size;
            char *guarantee_top = guarantee + stack_info.guaranteed;

            if (guarantee_top > stack_info.end) guarantee_top = stack_info.end;
            stack = (char *)((ULONG_PTR)guarantee_top & ~(ULONG_PTR)15) - size;
            if (stack >= stack_info.start + host_page_size)
            {
                mutex_lock( &virtual_mutex );
                set_page_vprot_bits( guarantee, guarantee_top - guarantee,
                                     VPROT_COMMITTED, VPROT_GUARD );
                mprotect_range( guarantee, guarantee_top - guarantee, 0, 0 );
                mutex_unlock( &virtual_mutex );
                rec->ExceptionCode = STATUS_STACK_OVERFLOW;
                rec->NumberParameters = 0;
                return stack;
            }
        }
#endif
        /* stack overflow on last page, unrecoverable */
        diff = stack_info.start + host_page_size - stack;
        ERR( "stack overflow %u bytes addr %p stack %p (%p-%p-%p)\n",
             diff, rec->ExceptionAddress, stack, stack_info.start, stack_info.limit, stack_info.end );
        abort_thread(1);
    }
    else if (stack < stack_info.limit)
    {
        char *page = ROUND_ADDR( stack, host_page_mask );
        mutex_lock( &virtual_mutex );  /* no need for signal masking inside signal handler */
        if ((get_host_page_vprot( page ) & VPROT_GUARD) && grow_thread_stack( page, &stack_info ))
        {
            rec->ExceptionCode = STATUS_STACK_OVERFLOW;
            rec->NumberParameters = 0;
        }
        mutex_unlock( &virtual_mutex );
    }
#if defined(VALGRIND_MAKE_MEM_UNDEFINED)
    VALGRIND_MAKE_MEM_UNDEFINED( stack, size );
#elif defined(VALGRIND_MAKE_WRITABLE)
    VALGRIND_MAKE_WRITABLE( stack, size );
#endif
    return stack;
}


/***********************************************************************
 *           check_write_access
 *
 * Check if the memory range is writable, temporarily disabling write watches if necessary.
 */
static NTSTATUS check_write_access( void *base, size_t size, BOOL *has_write_watch )
{
    size_t i;
    char *addr = ROUND_ADDR( base, host_page_mask );

    if (!round_size_checked( (UINT_PTR)base, size, host_page_mask, &size ))
        return STATUS_INVALID_USER_BUFFER;
    for (i = 0; i < size; i += host_page_size)
    {
        BYTE vprot = get_host_page_vprot( addr + i );
        if (vprot & VPROT_WRITEWATCH) *has_write_watch = TRUE;
        if (!(get_unix_prot( vprot & ~VPROT_WRITEWATCH ) & PROT_WRITE))
            return STATUS_INVALID_USER_BUFFER;
    }
    if (*has_write_watch)
        mprotect_range( addr, size, 0, VPROT_WRITEWATCH );  /* temporarily enable write access */
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           virtual_locked_server_call
 */
unsigned int virtual_locked_server_call( void *req_ptr )
{
    struct __server_request_info * const req = req_ptr;
    sigset_t sigset;
    void *addr = req->reply_data;
    data_size_t size = req->u.req.request_header.reply_size;
    BOOL has_write_watch = FALSE;
    unsigned int ret;

    if (!size) return wine_server_call( req_ptr );

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!(ret = check_write_access( addr, size, &has_write_watch )))
    {
        ret = server_call_unlocked( req );
        if (has_write_watch) update_write_watches( addr, size, wine_server_reply_size( req ));
    }
    else memset( &req->u.reply, 0, sizeof(req->u.reply) );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}


/***********************************************************************
 *           virtual_locked_read
 */
ssize_t virtual_locked_read( int fd, void *addr, size_t size )
{
    sigset_t sigset;
    BOOL has_write_watch = FALSE;
    int err = EFAULT;

    ssize_t ret = read( fd, addr, size );
    if (ret != -1 || use_kernel_writewatch || errno != EFAULT) return ret;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!check_write_access( addr, size, &has_write_watch ))
    {
        ret = read( fd, addr, size );
        err = errno;
        if (has_write_watch) update_write_watches( addr, size, max( 0, ret ));
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    errno = err;
    return ret;
}


/***********************************************************************
 *           virtual_locked_pread
 */
ssize_t virtual_locked_pread( int fd, void *addr, size_t size, off_t offset )
{
    sigset_t sigset;
    BOOL has_write_watch = FALSE;
    int err = EFAULT;

    ssize_t ret = pread( fd, addr, size, offset );
    if (ret != -1 || use_kernel_writewatch || errno != EFAULT) return ret;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!check_write_access( addr, size, &has_write_watch ))
    {
        ret = pread( fd, addr, size, offset );
        err = errno;
        if (has_write_watch) update_write_watches( addr, size, max( 0, ret ));
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    errno = err;
    return ret;
}


/***********************************************************************
 *           virtual_locked_recvmsg
 */
ssize_t virtual_locked_recvmsg( int fd, struct msghdr *hdr, int flags )
{
    sigset_t sigset;
    size_t i;
    BOOL has_write_watch = FALSE;
    int err = EFAULT;

    ssize_t ret = recvmsg( fd, hdr, flags );
    if (ret != -1 || use_kernel_writewatch || errno != EFAULT) return ret;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    for (i = 0; i < hdr->msg_iovlen; i++)
        if (check_write_access( hdr->msg_iov[i].iov_base, hdr->msg_iov[i].iov_len, &has_write_watch ))
            break;
    if (i == hdr->msg_iovlen)
    {
        ret = recvmsg( fd, hdr, flags );
        err = errno;
    }
    if (has_write_watch)
        while (i--) update_write_watches( hdr->msg_iov[i].iov_base, hdr->msg_iov[i].iov_len, 0 );

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    errno = err;
    return ret;
}


/***********************************************************************
 *           virtual_is_valid_code_address
 */
BOOL virtual_is_valid_code_address( const void *addr, SIZE_T size )
{
    struct file_view *view;
    BOOL ret = FALSE;
    sigset_t sigset;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((view = find_view( addr, size )))
        ret = !(view->protect & VPROT_SYSTEM);  /* system views are not visible to the app */
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}


/***********************************************************************
 *           virtual_check_buffer_for_read
 *
 * Check if a memory buffer can be read, triggering page faults if needed for DIB section access.
 */
/* ★★★★★ ЛЕЙН ПРИБОРЫ, 25.08 — место №2 карты времени: проверка буфера гостя.
 *
 * Зачем. Проекту приписано, что `virtual_check_buffer_for_write` держит 24-35 % пути
 * загрузки Diablo. Числа этого не подтверждают и не опровергают: гейта у места нет, в
 * вычитание оно не попадало, а мои замеры уже нашли диспетчер на 29,5 % — значит на
 * проверку буфера столько же места в тех же часах просто нет. Ставлю счёт, чтобы спор
 * решался числом.
 *
 * Что считаем. Обе функции трогают ОДИН БАЙТ НА СТРАНИЦУ, поэтому работа пропорциональна
 * не размеру буфера, а числу страниц — считаем и то и другое.
 *
 * Дисциплина та же, что у прибора сервера: счёт всегда, часы по гейту
 * `MACRUNNER_HB_TRACE_VCHECK`, печать ТОЛЬКО по выходу. Печать из горячего пути в этой
 * же сессии повесила прогон на 8,5 минуты (server.c) — второй раз не наступаю. */
/* ★★★★★ ЛЕЙН ЗАГРУЗКА, 07.09.2026 — ПОЧИНКА СЕКУНДОМЕРА. Дефект доказан КОДОМ.
 *
 * ЧТО БЫЛО НЕ ТАК. `mr_vc_note`, внутри которого копилось `ns`, стоял ДО `__TRY` и до
 * обхода страниц. Значит `ns` мерил ПРОЛОГ И УЧЁТ — `clock_gettime`, два ветвления и три
 * атомарных прибавления, — а НЕ обход и его отказы страниц. То есть прибор, заведённый
 * ради вопроса «сколько стоит проверка буфера», отвечал про стоимость собственного учёта.
 * Ранние возвраты (`!size`, `!ptr`) не считались ВОВСЕ: у них `mr_vc_note` не звался.
 *
 * ЧТО СДЕЛАНО. Прежний `ns` ОСТАВЛЕН БЕЗ ИЗМЕНЕНИЙ — он нужен в ТОМ ЖЕ прогоне, чтобы
 * отрицательный контроль показал обе руки одним журналом, а не двумя сборками.
 *   walk_ns   НОВЫЙ: от входа до выхода, включая `__TRY`, обход И путь ошибки.
 *   touch     фактические касания страниц (итерации цикла + два краевых байта),
 *             считаются АРИФМЕТИЧЕСКИ — в цикле не прибавлено ни одной команды,
 *             потому что печать/счёт в горячем пути уже однажды подавили ступень.
 *   done/flt  обходы завершённые и упавшие в `__EXCEPT` — раздельно.
 *   early     возвраты до обхода, которые прежний прибор терял целиком.
 *
 * ★ ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ (обязателен, иначе починка недоказуема):
 *   MACRUNNER_HB_VCHECK_TEST_DELAY_NS=<Δ>  вставляет ЗАНЯТОЕ ожидание Δ нс ВНУТРИ обхода,
 *   после прежней точки замера. Прежний `ns` обязан остаться СЛЕПЫМ, новый `walk_ns`
 *   обязан вырасти на Δ×(число впрысков). Число впрысков ограничено
 *   MACRUNNER_HB_VCHECK_TEST_DELAY_MAX (умолчание 2000) — без потолка контроль съел бы
 *   прогон. Впрыски печатаются числом, поэтому предсказание проверяется арифметикой,
 *   а не на глаз. */
static unsigned long long mr_vc_r_calls, mr_vc_w_calls;
static unsigned long long mr_vc_r_bytes, mr_vc_w_bytes;
static unsigned long long mr_vc_r_pages, mr_vc_w_pages;
static unsigned long long mr_vc_ns;              /* ПРЕЖНИЙ, дефектный: пролог+учёт */
static unsigned long long mr_vc_r_walk_ns, mr_vc_w_walk_ns;   /* НОВЫЙ: весь обход */
static unsigned long long mr_vc_r_touch, mr_vc_w_touch;
static unsigned long long mr_vc_r_done, mr_vc_w_done;
static unsigned long long mr_vc_r_flt, mr_vc_w_flt;
static unsigned long long mr_vc_early_nosize, mr_vc_early_noptr;
static unsigned long long mr_vc_delay_seen, mr_vc_delay_done, mr_vc_delay_spun_ns;
static int mr_vc_on = -1;
static long long mr_vc_delay_ns = -1;
static unsigned long long mr_vc_delay_max;

static inline int mr_vc_timing(void)
{
    if (mr_vc_on < 0)
    {
        const char *v = getenv( "MACRUNNER_HB_TRACE_VCHECK" );
        mr_vc_on = (v && *v && *v != '0') ? 1 : 0;
    }
    return mr_vc_on;
}

/* часы БЕЗ гейта: нужны отрицательному контролю, который обязан работать и тогда,
 * когда учёт времени выключен */
static inline unsigned long long mr_vc_raw_now(void)
{
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}

static inline unsigned long long mr_vc_now(void)
{
    if (!mr_vc_timing()) return 0;
    return mr_vc_raw_now();
}

/* ★ намеренная порча: занятое ожидание ВНУТРИ обхода, после прежней точки замера */
static inline void mr_vc_test_delay(void)
{
    unsigned long long n, t0;

    if (mr_vc_delay_ns < 0)
    {
        const char *v = getenv( "MACRUNNER_HB_VCHECK_TEST_DELAY_NS" );
        const char *m = getenv( "MACRUNNER_HB_VCHECK_TEST_DELAY_MAX" );
        mr_vc_delay_max = (m && *m) ? strtoull( m, NULL, 0 ) : 2000ull;
        mr_vc_delay_ns = (v && *v) ? strtoll( v, NULL, 0 ) : 0;
    }
    if (mr_vc_delay_ns <= 0) return;
    n = __atomic_add_fetch( &mr_vc_delay_seen, 1, __ATOMIC_RELAXED );
    if (n > mr_vc_delay_max) return;
    t0 = mr_vc_raw_now();
    while (mr_vc_raw_now() - t0 < (unsigned long long)mr_vc_delay_ns) { /* занято */ }
    __atomic_add_fetch( &mr_vc_delay_spun_ns, mr_vc_raw_now() - t0, __ATOMIC_RELAXED );
    __atomic_add_fetch( &mr_vc_delay_done, 1, __ATOMIC_RELAXED );
}

/* Закрытие ПОЛНОГО пролёта. Зовётся на ВСЕХ выходах после __TRY, включая __EXCEPT:
 * ошибочный буфер стоит времени ровно так же, как удачный, и терять его нельзя. */
static inline void mr_vc_walk_end( int is_write, SIZE_T size, unsigned long long t0, int ok )
{
    unsigned long long dt = t0 ? (mr_vc_raw_now() - t0) : 0;
    /* касания = итерации цикла + p[0] + p[count-1]; арифметика, а не счёт в цикле */
    unsigned long long touch = (unsigned long long)((size + host_page_size - 1) / host_page_size) + 1;

    if (is_write)
    {
        if (dt) __atomic_add_fetch( &mr_vc_w_walk_ns, dt, __ATOMIC_RELAXED );
        if (ok) { __atomic_add_fetch( &mr_vc_w_done, 1, __ATOMIC_RELAXED );
                  __atomic_add_fetch( &mr_vc_w_touch, touch, __ATOMIC_RELAXED ); }
        else    __atomic_add_fetch( &mr_vc_w_flt, 1, __ATOMIC_RELAXED );
    }
    else
    {
        if (dt) __atomic_add_fetch( &mr_vc_r_walk_ns, dt, __ATOMIC_RELAXED );
        if (ok) { __atomic_add_fetch( &mr_vc_r_done, 1, __ATOMIC_RELAXED );
                  __atomic_add_fetch( &mr_vc_r_touch, touch, __ATOMIC_RELAXED ); }
        else    __atomic_add_fetch( &mr_vc_r_flt, 1, __ATOMIC_RELAXED );
    }
}

/* Перепись. Зовётся по выходу (atexit) И с фазовых часов — иначе убитый по времени
 * прогон не оставил бы ни строки, а это ровно наш случай: бюджет всегда обрывает игру. */
void macrunner_vcheck_census_print( const char *povod )
{
    fprintf( stderr,
             "macrunner-vcheck-census: pid=%d povod=%s read_calls=%llu read_bytes=%llu read_pages=%llu "
             "write_calls=%llu write_bytes=%llu write_pages=%llu ns=%llu | "
             "walk_ns_r=%llu walk_ns_w=%llu touch_r=%llu touch_w=%llu "
             "done_r=%llu done_w=%llu flt_r=%llu flt_w=%llu early_nosize=%llu early_noptr=%llu | "
             "delay_ns=%lld delay_seen=%llu delay_done=%llu delay_spun_ns=%llu chasy=%d\n",
             (int)getpid(), povod ? povod : "?",
             mr_vc_r_calls, mr_vc_r_bytes, mr_vc_r_pages,
             mr_vc_w_calls, mr_vc_w_bytes, mr_vc_w_pages, mr_vc_ns,
             mr_vc_r_walk_ns, mr_vc_w_walk_ns, mr_vc_r_touch, mr_vc_w_touch,
             mr_vc_r_done, mr_vc_w_done, mr_vc_r_flt, mr_vc_w_flt,
             mr_vc_early_nosize, mr_vc_early_noptr,
             mr_vc_delay_ns, mr_vc_delay_seen, mr_vc_delay_done, mr_vc_delay_spun_ns,
             mr_vc_timing() );
    fflush( stderr );
}

static void mr_vc_report(void)
{
    macrunner_vcheck_census_print( "vyhod" );
}

static inline void mr_vc_early( int is_write, int noptr, unsigned long long t0 )
{
    (void)is_write;
    if (noptr) __atomic_add_fetch( &mr_vc_early_noptr, 1, __ATOMIC_RELAXED );
    else       __atomic_add_fetch( &mr_vc_early_nosize, 1, __ATOMIC_RELAXED );
    if (t0) __atomic_add_fetch( &mr_vc_ns, mr_vc_raw_now() - t0, __ATOMIC_RELAXED );
}

static inline void mr_vc_note( int is_write, SIZE_T size, unsigned long long t0 )
{
    static int atexit_done;
    unsigned long long pages = (unsigned long long)(size / host_page_size) + 1;

    if (!atexit_done) { atexit_done = 1; atexit( mr_vc_report ); }
    if (is_write)
    {
        __atomic_add_fetch( &mr_vc_w_calls, 1, __ATOMIC_RELAXED );
        __atomic_add_fetch( &mr_vc_w_bytes, (unsigned long long)size, __ATOMIC_RELAXED );
        __atomic_add_fetch( &mr_vc_w_pages, pages, __ATOMIC_RELAXED );
    }
    else
    {
        __atomic_add_fetch( &mr_vc_r_calls, 1, __ATOMIC_RELAXED );
        __atomic_add_fetch( &mr_vc_r_bytes, (unsigned long long)size, __ATOMIC_RELAXED );
        __atomic_add_fetch( &mr_vc_r_pages, pages, __ATOMIC_RELAXED );
    }
    if (t0) __atomic_add_fetch( &mr_vc_ns, mr_vc_now() - t0, __ATOMIC_RELAXED );
}

BOOL virtual_check_buffer_for_read( const void *ptr, SIZE_T size )
{
    unsigned long long mr_t0 = mr_vc_now();
    if (!size) { mr_vc_early( 0, 0, mr_t0 ); return TRUE; }
    if (!ptr) { mr_vc_early( 0, 1, mr_t0 ); return FALSE; }
    mr_vc_note( 0, size, mr_t0 );   /* ПРЕЖНИЙ дефектный замер — оставлен как есть */

    __TRY
    {
        volatile const char *p = ptr;
        char dummy __attribute__((unused));
        SIZE_T count = size;

        mr_vc_test_delay();   /* ★ отрицательный контроль: ВНУТРИ обхода, ниже старой точки */
        while (count > host_page_size)
        {
            dummy = *p;
            p += host_page_size;
            count -= host_page_size;
        }
        dummy = p[0];
        dummy = p[count - 1];
    }
    __EXCEPT
    {
        mr_vc_walk_end( 0, size, mr_t0, 0 );
        return FALSE;
    }
    __ENDTRY
    mr_vc_walk_end( 0, size, mr_t0, 1 );
    return TRUE;
}


/***********************************************************************
 *           virtual_check_buffer_for_write
 *
 * Check if a memory buffer can be written to, triggering page faults if needed for write watches.
 */
BOOL virtual_check_buffer_for_write( void *ptr, SIZE_T size )
{
    unsigned long long mr_t0 = mr_vc_now();
    if (!size) { mr_vc_early( 1, 0, mr_t0 ); return TRUE; }
    if (!ptr) { mr_vc_early( 1, 1, mr_t0 ); return FALSE; }
    mr_vc_note( 1, size, mr_t0 );   /* ПРЕЖНИЙ дефектный замер — оставлен как есть */

    __TRY
    {
        volatile char *p = ptr;
        SIZE_T count = size;

        mr_vc_test_delay();   /* ★ отрицательный контроль: ВНУТРИ обхода, ниже старой точки */
        while (count > host_page_size)
        {
            *p |= 0;
            p += host_page_size;
            count -= host_page_size;
        }
        p[0] |= 0;
        p[count - 1] |= 0;
    }
    __EXCEPT
    {
        mr_vc_walk_end( 1, size, mr_t0, 0 );
        return FALSE;
    }
    __ENDTRY
    mr_vc_walk_end( 1, size, mr_t0, 1 );
    return TRUE;
}


/* ★★★★★ ЛЕЙН ЗАГРУЗКА, 07.09.2026 — ФАЗОВЫЕ ЧАСЫ: CPU ОТДЕЛЬНО, ОЖИДАНИЕ ОТДЕЛЬНО.
 *
 * ЗАЧЕМ. Числа 9,121 с и 0,246 с — ВНУТРЕННИЙ секундомер Unity, напечатанный самой игрой.
 * Он говорит «сколько прошло» и молчит о том, СЧИТАЛИ мы это время или ЖДАЛИ. У нас
 * измерено, что ожидание потока = обращение к wineserver 44-48 %, а ожидание запуска =
 * explorer 5,25 с. Если фаза — ожидание, чинить надо производителя события, а не
 * трансляцию, и наоборот. Без разделения выбор правки — угадывание.
 *
 * ГДЕ СТОИТ. Строки Unity доходят до нашего журнала через `NtWriteFile` (там же, кстати,
 * стоит и `virtual_check_buffer_for_read` — то есть путь заведомо исполняется). Скан
 * ловит МАРКЕР В ПОТОКЕ ВЫВОДА ГОСТЯ и снимает на этом самом месте три часа сразу:
 *     wall        CLOCK_MONOTONIC          — сколько прошло
 *     cpu_proc    CLOCK_PROCESS_CPUTIME_ID — сколько СЧИТАЛ весь процесс
 *     cpu_thread  CLOCK_THREAD_CPUTIME_ID  — сколько считал ЭТОТ поток (критический:
 *                                            печатает именно главный поток Unity)
 * Отсюда `ozhidanie = d_wall - d_cpu_thread` — время, когда критический поток НЕ считал.
 * ★ ГРАНИЦА, которую нельзя замалчивать: `d_cpu_proc` складывает потоки и потому МОЖЕТ
 * БЫТЬ БОЛЬШЕ `d_wall`; это не ошибка, а параллелизм. Вычитать ожидание надо из
 * потокового, а не из процессного — процессное печатается рядом как свидетель загрузки.
 *
 * ЦЕНА В ГОРЯЧЕМ ПУТИ. Печать в горячем пути уже подавила ступень лестницы, поэтому:
 * гейт умолчанием ЗАКРЫТ; скан идёт ОДНИМ проходом с фильтром по первому байту (шесть
 * образцов начинаются на B/L/F/U/G/G, остальные байты уходят в `default:`); буферы
 * длиннее 8 КиБ не сканируются вовсе; число событий ограничено потолком. Свою цену
 * прибор объявляет сам — считает вызовы и просканированные байты и печатает их.
 *
 * ПЕРЕПИСЬ ПРИ УБИЙСТВЕ. На каждом маркере печатается и перепись vcheck. Прогон игры
 * ВСЕГДА обрывается по бюджету, `atexit` при этом может не отработать — значит перепись,
 * живущая только в `atexit`, есть перепись, которой нет. */
HB_PROBE_DEFINE(pr_faza, "faza-otmetka",
                "ЗАПИСИ ГОСТЯ, дошедшие до NtWriteFile и просмотренные на фазовые "
                "маркеры Unity: looked — каждая такая запись (ставится ВЫШЕ гейта, "
                "поэтому looked=0 означает, что путь вывода гостя не исполнялся вовсе, "
                "а looked>0 при hits=0 — что гейт MACRUNNER_HB_TRACE_FAZA закрыт ЛИБО "
                "маркеров в выводе не было); hits — найденный маркер. Потолок печати "
                "объявляет НИЖНЮЮ границу: упёршись в него, прибор считает дальше, но "
                "молчит",
                "MACRUNNER_HB_TRACE_FAZA", 64);

static const char * const mr_faza_pat[] = {
    "Begin MonoManager ReloadAssembly",
    "Loaded All Assemblies, in",
    "Finished resetting the current domain, in",
    "UnloadTime:",
    "GOG signing in",
    "Galaxy Init",
};
static const char * const mr_faza_imya[] = {
    "reload-nachalo", "assemblies-konec", "domain-reset-konec",
    "unloadtime", "gog-signin", "galaxy-init",
};
#define MR_FAZA_N ((int)(sizeof(mr_faza_pat)/sizeof(mr_faza_pat[0])))

static unsigned long long mr_faza_calls, mr_faza_bytes, mr_faza_skipped;
static unsigned long long mr_faza_prev_wall, mr_faza_prev_cpup, mr_faza_prev_cput;
static unsigned long long mr_faza_first_wall;
static int mr_faza_on = -1;

static inline int mr_faza_gate(void)
{
    if (mr_faza_on < 0)
    {
        const char *v = getenv( "MACRUNNER_HB_TRACE_FAZA" );
        mr_faza_on = (v && *v && *v != '0') ? 1 : 0;
    }
    return mr_faza_on;
}

static inline unsigned long long mr_faza_clock( clockid_t id )
{
    struct timespec ts;
    if (clock_gettime( id, &ts )) return 0;
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}

static void mr_faza_event( const char *imya )
{
    unsigned long long wall = mr_faza_clock( CLOCK_MONOTONIC );
    unsigned long long cpup = mr_faza_clock( CLOCK_PROCESS_CPUTIME_ID );
    unsigned long long cput = mr_faza_clock( CLOCK_THREAD_CPUTIME_ID );
    unsigned long long dw = mr_faza_prev_wall ? wall - mr_faza_prev_wall : 0;
    unsigned long long dp = mr_faza_prev_cpup ? cpup - mr_faza_prev_cpup : 0;
    unsigned long long dt = mr_faza_prev_cput ? cput - mr_faza_prev_cput : 0;
    double d_wait = (dw > dt) ? (double)(dw - dt) / 1e9 : 0.0;

    if (!mr_faza_first_wall) mr_faza_first_wall = wall;
    HB_PROBE_SAY( &pr_faza,
        "sobytie=%s pid=%d tid=%llx ot_nachala=%.6f "
        "d_wall=%.6f d_cpu_potok=%.6f d_cpu_process=%.6f d_ozhidanie_potoka=%.6f "
        "dolya_cpu=%.2f%% skan_vyzovov=%llu skan_bajt=%llu skan_propushcheno=%llu\n",
        imya, (int)getpid(), (unsigned long long)(uintptr_t)pthread_self(),
        (double)(wall - mr_faza_first_wall) / 1e9,
        (double)dw / 1e9, (double)dt / 1e9, (double)dp / 1e9, d_wait,
        dw ? 100.0 * (double)dt / (double)dw : 0.0,
        mr_faza_calls, mr_faza_bytes, mr_faza_skipped );
    macrunner_vcheck_census_print( imya );
    mr_faza_prev_wall = wall; mr_faza_prev_cpup = cpup; mr_faza_prev_cput = cput;
}

/* Зовётся из NtWriteFile ПОСЛЕ успешной проверки буфера: к этому моменту байты заведомо
 * читаемы, и скан не может сам вызвать отказ страницы. */
void macrunner_faza_write_scan( const void *buffer, ULONG length )
{
    const unsigned char *b = buffer;
    ULONG i;
    int m;

    HB_PROBE_LOOKED( &pr_faza );
    if (!mr_faza_gate() || !b || !length) return;
    if (length > 8192) { __atomic_add_fetch( &mr_faza_skipped, 1, __ATOMIC_RELAXED ); return; }
    __atomic_add_fetch( &mr_faza_calls, 1, __ATOMIC_RELAXED );
    __atomic_add_fetch( &mr_faza_bytes, (unsigned long long)length, __ATOMIC_RELAXED );

    for (i = 0; i < length; i++)
    {
        switch (b[i])
        {
        case 'B': case 'L': case 'F': case 'U': case 'G':
            for (m = 0; m < MR_FAZA_N; m++)
            {
                size_t n = strlen( mr_faza_pat[m] );
                if (b[i] != (unsigned char)mr_faza_pat[m][0]) continue;
                if (i + n > length) continue;
                if (!memcmp( b + i, mr_faza_pat[m], n )) mr_faza_event( mr_faza_imya[m] );
            }
            break;
        default: break;
        }
    }
}


/***********************************************************************
 *           virtual_uninterrupted_read_memory
 *
 * Similar to NtReadVirtualMemory, but without wineserver calls. Moreover
 * permissions are checked before accessing each page, to ensure that no
 * exceptions can happen.
 */
SIZE_T virtual_uninterrupted_read_memory( const void *addr, void *buffer, SIZE_T size )
{
    struct file_view *view;
    sigset_t sigset;
    SIZE_T bytes_read = 0;

    if (!size) return 0;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((view = find_view( addr, size )))
    {
        if (!(view->protect & VPROT_SYSTEM))
        {
            while (bytes_read < size && (get_unix_prot( get_host_page_vprot( addr )) & PROT_READ))
            {
                SIZE_T block_size = min( size - bytes_read, host_page_size - ((UINT_PTR)addr & host_page_mask) );
                memcpy( buffer, addr, block_size );

                addr   = (const void *)((const char *)addr + block_size);
                buffer = (void *)((char *)buffer + block_size);
                bytes_read += block_size;
            }
        }
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return bytes_read;
}


/***********************************************************************
 *           virtual_uninterrupted_write_memory
 *
 * Similar to NtWriteVirtualMemory, but without wineserver calls. Moreover
 * permissions are checked before accessing each page, to ensure that no
 * exceptions can happen.
 */
NTSTATUS virtual_uninterrupted_write_memory( void *addr, const void *buffer, SIZE_T size )
{
    BOOL has_write_watch = FALSE;
    sigset_t sigset;
    NTSTATUS ret;

    if (!size) return STATUS_SUCCESS;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!(ret = check_write_access( addr, size, &has_write_watch )))
    {
        memcpy( addr, buffer, size );
        if (has_write_watch) update_write_watches( addr, size, size );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}


/***********************************************************************
 *           virtual_set_force_exec
 *
 * Whether to force exec prot on all views.
 */
void virtual_set_force_exec( BOOL enable )
{
    struct file_view *view;
    sigset_t sigset;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!force_exec_prot != !enable)  /* change all existing views */
    {
        force_exec_prot = enable;

        WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
        {
            /* file mappings are always accessible */
            BYTE commit = is_view_valloc( view ) ? 0 : VPROT_COMMITTED;

            mprotect_range( view->base, view->size, commit, 0 );
        }
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}


/***********************************************************************
 *           virtual_manage_exec_writes
 */
void virtual_enable_write_exceptions( BOOL enable )
{
    struct file_view *view;
    sigset_t sigset;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!enable_write_exceptions && enable)  /* change all existing views */
    {
        WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
            if (set_page_vprot_exec_write_protect( view->base, view->size ))
                mprotect_range( view->base, view->size, 0, 0 );
    }
    enable_write_exceptions = enable;
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}


/* free reserved areas within a given range */
static void free_reserved_memory( char *base, char *limit )
{
    struct reserved_area *area;

    for (;;)
    {
        int removed = 0;

        LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
        {
            char *area_base = area->base;
            char *area_end = reserved_area_limit( area );

            if (area_end <= base) continue;
            if (area_base >= limit) return;
            if (area_base < base) area_base = base;
            if (area_end > limit) area_end = limit;
            if (!remove_reserved_area( area_base, area_end - area_base )) return;
            removed = 1;
            break;
        }
        if (!removed) return;
    }
}

#ifndef _WIN64

/***********************************************************************
 *           virtual_release_address_space
 *
 * Release some address space once we have loaded and initialized the app.
 */
static void virtual_release_address_space(void)
{
#ifndef __APPLE__  /* On macOS, we still want to free some of low memory, for OpenGL resources */
    if (user_space_limit > (void *)limit_2g) return;
#endif
    free_reserved_memory( (char *)0x20000000, (char *)0x7f000000 );
}

#endif  /* _WIN64 */


/* CROSSOVER HACK: bug 17634 */
static BOOL force_laa(void)
{
    static const WCHAR LargeAddressAwareW[] = {'L','a','r','g','e','A','d','d','r','e','s','s','A','w','a','r','e',0};
    const char *e = getenv("WINE_LARGE_ADDRESS_AWARE");
    UNICODE_STRING nameW, valuenameW;
    HANDLE root, app_key = 0;
    OBJECT_ATTRIBUTES attr;
    char tmp[64];
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)tmp;
    DWORD count;
    BOOL result=FALSE;
    WCHAR *app_name;

    if ((app_name = ntdll_wcsrchr( main_wargv[0], '\\' ))) app_name++;
    else app_name = main_wargv[0];

    if ((e != NULL) && (*e != '\0' && *e != '0'))
        return TRUE;

    if (!open_hkcu_key( "Software\\Wine\\AppDefaults", &root ))
    {
        ULONG len = wcslen( app_name ) + 1;
        nameW.Length = (len - 1) * sizeof(WCHAR);
        nameW.MaximumLength = len * sizeof(WCHAR);
        if ((nameW.Buffer = malloc( nameW.MaximumLength )))
        {
            wcscpy( nameW.Buffer, app_name );
            InitializeObjectAttributes( &attr, &nameW, 0, root, NULL );

            /* @@ Wine registry key: HKCU\Software\Wine\AppDefaults\app.exe */
            NtOpenKey( &app_key, KEY_ALL_ACCESS, &attr );
            free( nameW.Buffer );
        }
        NtClose( root );
    }

    if (app_key)
    {
        valuenameW.Length = sizeof(LargeAddressAwareW) - sizeof(WCHAR);
        valuenameW.Buffer = (WCHAR*)LargeAddressAwareW;
        if (!NtQueryValueKey( app_key, &valuenameW, KeyValuePartialInformation, tmp, sizeof(tmp)-1, &count))
        {
            if (info->DataLength >= sizeof(DWORD))
            {
                if ((*(DWORD *)info->Data) != 0)
                    result = TRUE;
            }
        }
        NtClose( app_key );
    }

    return result;
}

/***********************************************************************
 *           virtual_set_large_address_space
 *
 * Enable use of a large address space when allowed by the application.
 */
void virtual_set_large_address_space(void)
{
    BOOL large_address_space_active = ((main_image_info.ImageCharacteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) || force_laa());
    if (is_win64)
    {
        if (!is_wow64())
        {
            address_space_start = (void *)0x10000;
#ifndef __APPLE__  /* don't free the zerofill section on macOS */
            if ((main_image_info.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) &&
                (main_image_info.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
                free_reserved_memory( 0, (char *)0x7ffe0000 );
#endif
        }
        else user_space_wow_limit = (large_address_space_active ? limit_4g : limit_2g) - 1;
    }
    else
    {
        if (!large_address_space_active) return;
        free_reserved_memory( (char *)0x80000000, address_space_limit );
    }
    user_space_limit = working_set_limit = address_space_limit;
}


/***********************************************************************
 *             allocate_virtual_memory
 *
 * NtAllocateVirtualMemory[Ex] implementation.
 */
static NTSTATUS allocate_virtual_memory( void **ret, SIZE_T *size_ptr, ULONG type, ULONG protect,
                                         ULONG_PTR limit_low, ULONG_PTR limit_high,
                                         ULONG_PTR align, ULONG attributes )
{
    void *base;
    unsigned int vprot;
    BOOL is_dos_memory = FALSE;
    struct file_view *view;
    sigset_t sigset;
    SIZE_T size = *size_ptr;
    NTSTATUS status = STATUS_SUCCESS;

    if (type & MEM_LARGE_PAGES)
    {
        static const ULONG large_page_type_mask = MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN | MEM_LARGE_PAGES;
        static const SIZE_T large_page_mask = 2 * 1024 * 1024 - 1;

        if ((type & ~large_page_type_mask) ||
            (type & (MEM_COMMIT | MEM_RESERVE)) != (MEM_COMMIT | MEM_RESERVE) ||
            (*ret && ((UINT_PTR)*ret & large_page_mask)) ||
            (*size_ptr & large_page_mask))
            return STATUS_INVALID_PARAMETER;
        return STATUS_PRIVILEGE_NOT_HELD;
    }

    /* Round parameters to a page boundary */

    if (is_beyond_limit( 0, size, working_set_limit )) return STATUS_WORKING_SET_LIMIT_RANGE;

    if (*ret)
    {
        void *page_base;
        SIZE_T page_size, prefix_size;

        if (type & MEM_RESERVE && !(type & MEM_REPLACE_PLACEHOLDER)) /* Round down to 64k boundary */
            base = ROUND_ADDR( *ret, granularity_mask );
        else
            base = ROUND_ADDR( *ret, page_mask );
        page_base = ROUND_ADDR( *ret, page_mask );
        if (!round_size_checked( (UINT_PTR)*ret, size, page_mask, &page_size ))
            return STATUS_INVALID_PARAMETER;
        if ((UINT_PTR)page_base < (UINT_PTR)base) return STATUS_INVALID_PARAMETER;
        prefix_size = (UINT_PTR)page_base - (UINT_PTR)base;
        if (page_size > ~(SIZE_T)0 - prefix_size) return STATUS_INVALID_PARAMETER;
        size = prefix_size + page_size;

        /* disallow low 64k, wrap-around and kernel space */
        if (((char *)base < (char *)0x10000) ||
            is_beyond_limit( base, size, address_space_limit ))
        {
            /* address 1 is magic to mean DOS area */
            if (!base && *ret == (void *)1 && size == 0x110000) is_dos_memory = TRUE;
            else return STATUS_INVALID_PARAMETER;
        }
    }
    else
    {
        base = NULL;
        if (!round_size_checked( 0, size, page_mask, &size )) return STATUS_INVALID_PARAMETER;
    }

    /* Compute the alloc type flags */

    if ((type & MEM_RESET_UNDO_FLAGS) && !is_mem_reset_undo_type( type ))
    {
        WARN("called with wrong alloc type flags (%08x) !\n", type);
        return STATUS_INVALID_PARAMETER;
    }

    if (!(type & (MEM_COMMIT | MEM_RESERVE | MEM_RESET | MEM_RESET_UNDO_FLAGS))
        || (type & MEM_REPLACE_PLACEHOLDER && !(type & MEM_RESERVE)))
    {
        WARN("called with wrong alloc type flags (%08x) !\n", type);
        return STATUS_INVALID_PARAMETER;
    }

    if ((type & MEM_RESERVE_PLACEHOLDER) &&
        (!(type & MEM_RESERVE) || (type & (MEM_COMMIT | MEM_RESET | MEM_RESET_UNDO_FLAGS | MEM_REPLACE_PLACEHOLDER))))
        return STATUS_INVALID_PARAMETER;
    if ((type & MEM_WRITE_WATCH) && !(type & MEM_RESERVE)) return STATUS_INVALID_PARAMETER;
    if (type & MEM_RESERVE_PLACEHOLDER && (protect != PAGE_NOACCESS)) return STATUS_INVALID_PARAMETER;
    if (!arm64ec_view && (attributes & MEM_EXTENDED_PARAMETER_EC_CODE)) return STATUS_INVALID_PARAMETER;

    /* Reserve the memory */

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    if ((type & MEM_RESERVE) || (!base && !(type & (MEM_RESET | MEM_RESET_UNDO_FLAGS))))
    {
        if (!(status = get_vprot_flags( protect, &vprot, FALSE )))
        {
            if (type & MEM_COMMIT) vprot |= VPROT_COMMITTED;
            if (type & MEM_WRITE_WATCH)
            {
                vprot |= VPROT_WRITEWATCH;
                macrunner_ww_note( "alloc", &macrunner_ww_alloc );
            }
            if (type & MEM_RESERVE_PLACEHOLDER) vprot |= VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER;
            if (protect & PAGE_NOCACHE) vprot |= SEC_NOCACHE;

            if (vprot & VPROT_WRITECOPY) status = STATUS_INVALID_PAGE_PROTECTION;
            else if (is_dos_memory) status = allocate_dos_memory( &view, vprot );
            else status = map_view( &view, base, size, type, vprot, limit_low, limit_high,
                                    align ? align - 1 : granularity_mask );

            if (status == STATUS_SUCCESS)
            {
                base = view->base;
                if (vprot & VPROT_EXEC || force_exec_prot) mprotect_range( base, size, 0, 0 );
            }
        }
    }
    else if (type & MEM_RESET)
    {
        if (!(view = find_view( base, size ))) status = STATUS_NOT_MAPPED_VIEW;
#if defined(__APPLE__) && defined(MADV_FREE_REUSABLE)
        else if (view->protect & SEC_FILE) status = STATUS_INVALID_PARAMETER;
        else if (madvise( base, size, MADV_FREE_REUSABLE ))
        {
            int err = errno;

            /* Darwin's reusable advice requires writable pages. MEM_RESET must
             * preserve protection. Ordinary file views were excluded above. */
            if (err == EPERM || err == EACCES)
            {
                if (madvise( base, size, MADV_DONTNEED )) status = errno_to_status( errno );
            }
            else status = errno_to_status( err );
        }
#else
        else if (madvise( base, size, MADV_DONTNEED )) status = errno_to_status( errno );
#endif
    }
    else if (type & MEM_RESET_UNDO_FLAGS)
    {
        if (!(view = find_view( base, size ))) status = STATUS_NOT_MAPPED_VIEW;
#if defined(__APPLE__) && defined(MADV_FREE_REUSE)
        else if (madvise( base, size, MADV_FREE_REUSE )) status = errno_to_status( errno );
#else
        else status = STATUS_UNSUCCESSFUL;
#endif
    }
    else  /* commit the pages */
    {
        if (!(view = find_view( base, size ))) status = STATUS_NOT_MAPPED_VIEW;
        else if (view->protect & SEC_FILE) status = STATUS_ALREADY_COMMITTED;
        else if (view->protect & VPROT_FREE_PLACEHOLDER) status = STATUS_CONFLICTING_ADDRESSES;
        else if (!(status = set_protection( view, base, size, protect )) && (view->protect & SEC_RESERVE))
        {
            SERVER_START_REQ( add_mapping_committed_range )
            {
                req->base   = wine_server_client_ptr( view->base );
                req->offset = (char *)base - (char *)view->base;
                req->size   = size;
                wine_server_call( req );
            }
            SERVER_END_REQ;
        }
    }

    if (!status && (attributes & MEM_EXTENDED_PARAMETER_EC_CODE))
    {
        commit_arm64ec_map( view );
        set_arm64ec_range( base, size );
    }

    if (!status) VIRTUAL_DEBUG_DUMP_VIEW( view );

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    if (status == STATUS_SUCCESS)
    {
        *ret = base;
        *size_ptr = size;
    }
    else if (status == STATUS_NO_MEMORY)
        ERR( "out of memory for allocation, base %p size %08lx\n", base, size );

    return status;
}


/***********************************************************************
 *             NtAllocateVirtualMemory   (NTDLL.@)
 *             ZwAllocateVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtAllocateVirtualMemory( HANDLE process, PVOID *ret, ULONG_PTR zero_bits,
                                         SIZE_T *size_ptr, ULONG type, ULONG protect )
{
    {   /* ★★★★★ MacRunner 2026-08-31 — КТО ВЛАДЕЕТ ОБЛАСТЬЮ, В КОТОРУЮ УХОДИТ RET.
         *
         * Стена: `ret` по x30, равному указателю в частные 68 КБ (0x11000), отведённые
         * PAGE_READWRITE, где лежит имя канала RPC `\pipe\svcctl`. Область исключена
         * из всех известных структур поимённо (стек, TEB, PEB, блок параметров, образы).
         * Остался вопрос владельца. Печатаем ВЫДЕЛЕНИЕ такого размера вместе с адресом
         * возврата вызывающего — он и назовёт компонент. */
        static unsigned int alloc_rep;
        if (size_ptr && *size_ptr >= 0x10000 && *size_ptr <= 0x12000 && alloc_rep < 24)
        {
            alloc_rep++;
            fprintf( stderr, "macrunner-hb-выделение68к: n=%u размер=%p тип=%08lx защита=%08lx адрес=%p\n",
                     alloc_rep, (void *)*size_ptr, (unsigned long)type,
                     (unsigned long)protect, ret ? *ret : NULL );
            fflush( stderr );
        }
    }

    static const ULONG type_mask = MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN | MEM_WRITE_WATCH
                                   | MEM_RESET | MEM_RESET_UNDO_FLAGS | MEM_LARGE_PAGES;
    ULONG_PTR limit;

    if (!ret || !size_ptr) return STATUS_ACCESS_VIOLATION;

    TRACE("%p %p %08lx %x %08x\n", process, *ret, *size_ptr, type, protect );

    if (!*size_ptr) return STATUS_INVALID_PARAMETER;
    if (zero_bits > 21 && zero_bits < 32) return STATUS_INVALID_PARAMETER_3;
    if (zero_bits > 32 && zero_bits < granularity_mask) return STATUS_INVALID_PARAMETER_3;
#ifndef _WIN64
    if (!is_old_wow64() && zero_bits >= 32) return STATUS_INVALID_PARAMETER_3;
#endif
    if (type & ~type_mask) return STATUS_INVALID_PARAMETER;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;
        unsigned int status;

        memset( &call, 0, sizeof(call) );

        call.virtual_alloc.type         = APC_VIRTUAL_ALLOC;
        call.virtual_alloc.addr         = wine_server_client_ptr( *ret );
        call.virtual_alloc.size         = *size_ptr;
        call.virtual_alloc.zero_bits    = zero_bits;
        call.virtual_alloc.op_type      = type;
        call.virtual_alloc.prot         = protect;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_alloc.status == STATUS_SUCCESS)
        {
            *ret      = wine_server_get_ptr( result.virtual_alloc.addr );
            *size_ptr = result.virtual_alloc.size;
        }
        else
        {
            WARN( "cross-process allocation failed, process=%p base=%p size=%08lx status=%08x",
                  process, *ret, *size_ptr, result.virtual_alloc.status );
        }
        return result.virtual_alloc.status;
    }

    if (!*ret)
        limit = get_zero_bits_limit( zero_bits );
    else
        limit = 0;

    {
        NTSTATUS macrunner_st = allocate_virtual_memory( ret, size_ptr, type, protect, 0, limit, 0, 0 );
        if (!macrunner_st)
        {
            macrunner_hb_vm_changed();
            macrunner_hb_register_x64_exec_alloc( *ret, *size_ptr, type, protect, *ret, *size_ptr );
            /* ★★★★★ ИТЕРАЦИЯ 128 — ДОНЕСТИ ФИКСАЦИЮ ДО ТАБЛИЦЫ HyperBridge.
             *
             * Измерено (итерация 127): гость резервирует мегабайт по 0x05D10000 (у нас
             * регион заводится с PAGE_NOACCESS -> perm=0), затем фиксирует 528 КБ по
             * 0x05D44000 с `MEM_COMMIT`; 0x05D44000+0x84000 = 0x05DC8000 — ровно верхняя
             * граница области, на которой прогон падает с `write-deny perm=0`.
             * Наша таблица прав о фиксации не узнаёт: единственный вызов
             * `guest32_protect` во всём дереве стоит в пути PE-образов.
             *
             * Синхронизацию в `NtProtectVirtualMemory` (итерации 125-126) сюда же не
             * годилась: замер 111 показал, что смен прав на этой области НЕТ ни одной.
             *
             * Только гостевое окно (сравнение старших битов), только MEM_COMMIT.
             * Гейт тот же `MACRUNNER_HB_GUEST32_SYNC_PROT`, умолчание 0. */
            if ((type & MEM_COMMIT) && *ret && *size_ptr)
            {
                static int mr_ca_gate = -1;
                if (mr_ca_gate < 0)
                {
                    const char *v = getenv( "MACRUNNER_HB_GUEST32_SYNC_PROT" );
                    mr_ca_gate = (v && *v && *v != '0') ? 1 : 0;
                }
                if (mr_ca_gate)
                {
                    unsigned long long mr_win = macrunner_hb_wow64_guest32_base();
                    ULONG_PTR mr_hi = (ULONG_PTR)*ret & ~(ULONG_PTR)0xffffffffu;
                    if (mr_win && mr_hi == (ULONG_PTR)(mr_win & ~0xffffffffull))
                    {
                        /* ★★★★★ ИТЕРАЦИЯ 130 — ПРИ ОТКАЗЕ ОТОБРАЖАТЬ, А НЕ ТОЛЬКО МЕНЯТЬ ПРАВА.
                         *
                         * Замер 129: из 126 синхронизаций 8 вернули 0xC0000018, и среди
                         * них ровно нужная (гость=5d44000 размер=84000). Причина в коде:
                         * `hb_memory_guest32_protect` выходит до цикла установки прав,
                         * если `guest32_range_fully_mapped` находит дыру — то есть
                         * ставить права НЕКУДА, диапазон у нас не отображён.
                         *
                         * Значит на фиксации надо отображать: `guest32_map_fixed` для
                         * того же диапазона. Пробуем сперва права (дёшево, обычный
                         * случай), при отказе — отображение. */
                        ULONG_PTR mr_g = (ULONG_PTR)*ret & 0xffffffffu;
                        NTSTATUS mr_s = macrunner_hb_wow64_guest32_protect( mr_g, *size_ptr, protect );
                        NTSTATUS mr_m = 0;
                        if (mr_s)
                        {
                            /* ★★★★★ ИТЕРАЦИЯ 132 — ДОФИКСАЦИЯ КУСКАМИ.
                             *
                             * Замер 131: из восьми отказов прав семь чинятся простым
                             * отображением всего диапазона, а восьмой (0x84000) не
                             * ложится — он ПЕРЕКРЫВАЕТСЯ с уже отображённым, и
                             * `map_fixed` отвергает его целиком. Недостающей операции
                             * «дофиксировать» в модели памяти нет, но её можно собрать
                             * из имеющихся: идём кусками по 64 КБ, уже отображённые
                             * отвергнутся безвредно, дыры заполнятся. После этого
                             * повторяем смену прав на весь диапазон. */
                            void *mr_hp = NULL;
                            mr_m = macrunner_hb_wow64_guest32_map_fixed( mr_g, *size_ptr, protect, &mr_hp );
                            if (mr_m)
                            {
                                SIZE_T mr_off, mr_step = 0x10000;
                                unsigned mr_ok = 0, mr_bad = 0;
                                for (mr_off = 0; mr_off < *size_ptr; mr_off += mr_step)
                                {
                                    SIZE_T mr_chunk = *size_ptr - mr_off;
                                    void *mr_h2 = NULL;
                                    if (mr_chunk > mr_step) mr_chunk = mr_step;
                                    if (macrunner_hb_wow64_guest32_map_fixed( mr_g + mr_off, mr_chunk,
                                                                              protect, &mr_h2 ))
                                        mr_bad++;
                                    else mr_ok++;
                                }
                                mr_m = macrunner_hb_wow64_guest32_protect( mr_g, *size_ptr, protect );
                                {
                                    static unsigned mr_pc_n;
                                    if (mr_pc_n++ < 8)
                                        fprintf( stderr, "macrunner-guest32-dofiks: guest=%llx size=%llx "
                                                 "kuskov_ok=%u kuskov_otkaz=%u itog_prav=%08llx\n",
                                                 (unsigned long long)mr_g,
                                                 (unsigned long long)*size_ptr,
                                                 mr_ok, mr_bad, (unsigned long long)mr_m );
                                }
                            }
                        }
                        static unsigned mr_ca_n;
                        if (mr_ca_n++ < 200)
                            fprintf( stderr, "macrunner-guest32-синхр-фикс: гость=%llx размер=%llx "
                                     "права=%08x статус=%08llx отобр=%08llx\n",
                                     (unsigned long long)mr_g, (unsigned long long)*size_ptr,
                                     (unsigned)protect, (unsigned long long)mr_s,
                                     (unsigned long long)mr_m );
                    }
                }
            }
        }
        return macrunner_st;
    }
}


static NTSTATUS get_extended_params( const MEM_EXTENDED_PARAMETER *parameters, ULONG count,
                                     ULONG_PTR *limit_low, ULONG_PTR *limit_high, ULONG_PTR *align,
                                     ULONG *attributes, USHORT *machine )
{
    ULONG i, present = 0;

    if (count && !parameters) return STATUS_INVALID_PARAMETER;

    for (i = 0; i < count; ++i)
    {
        if (parameters[i].Type >= 32) return STATUS_INVALID_PARAMETER;
        if (present & (1u << parameters[i].Type)) return STATUS_INVALID_PARAMETER;
        present |= 1u << parameters[i].Type;

        switch (parameters[i].Type)
        {
        case MemExtendedParameterAddressRequirements:
        {
            MEM_ADDRESS_REQUIREMENTS *r = parameters[i].Pointer;
            ULONG_PTR limit;

            if (!r) return STATUS_INVALID_PARAMETER;

            if (is_wow64()) limit = get_wow_user_space_limit();
            else limit = (ULONG_PTR)user_space_limit;

            if (r->Alignment)
            {
                if ((r->Alignment & (r->Alignment - 1)) || r->Alignment - 1 < granularity_mask)
                {
                    WARN( "Invalid alignment %lu.\n", r->Alignment );
                    return STATUS_INVALID_PARAMETER;
                }
                *align = r->Alignment;
            }
            if (r->LowestStartingAddress)
            {
                *limit_low = (ULONG_PTR)r->LowestStartingAddress;
                if (*limit_low >= limit || (*limit_low & granularity_mask))
                {
                    WARN( "Invalid limit %p.\n", r->LowestStartingAddress );
                    return STATUS_INVALID_PARAMETER;
                }
            }
            if (r->HighestEndingAddress)
            {
                *limit_high = (ULONG_PTR)r->HighestEndingAddress;
                if (*limit_high > limit ||
                    *limit_high <= *limit_low ||
                    ((*limit_high + 1) & page_mask))
                {
                    WARN( "Invalid limit %p.\n", r->HighestEndingAddress );
                    return STATUS_INVALID_PARAMETER;
                }
            }
            break;
        }

        case MemExtendedParameterAttributeFlags:
            *attributes = parameters[i].ULong;
            break;

        case MemExtendedParameterImageMachine:
            *machine = parameters[i].ULong;
            break;

        case MemExtendedParameterNumaNode:
        case MemExtendedParameterPartitionHandle:
        case MemExtendedParameterUserPhysicalHandle:
            FIXME( "Parameter type %d is not supported.\n", parameters[i].Type );
            break;

        default:
            WARN( "Invalid parameter type %u\n", parameters[i].Type );
            return STATUS_INVALID_PARAMETER;
        }
    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *             NtAllocateVirtualMemoryEx   (NTDLL.@)
 *             ZwAllocateVirtualMemoryEx   (NTDLL.@)
 */
NTSTATUS WINAPI NtAllocateVirtualMemoryEx( HANDLE process, PVOID *ret, SIZE_T *size_ptr, ULONG type,
                                           ULONG protect, MEM_EXTENDED_PARAMETER *parameters,
                                           ULONG count )
{
    static const ULONG type_mask = MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN | MEM_WRITE_WATCH
                                   | MEM_RESET | MEM_RESET_UNDO_FLAGS | MEM_RESERVE_PLACEHOLDER
                                   | MEM_REPLACE_PLACEHOLDER | MEM_LARGE_PAGES;
    ULONG_PTR limit_low = 0;
    ULONG_PTR limit_high = 0;
    ULONG_PTR align = 0;
    ULONG attributes = 0;
    USHORT machine = 0;
    unsigned int status;

    if (!ret || !size_ptr) return STATUS_ACCESS_VIOLATION;

    TRACE( "%p %p %08lx %x %08x %p %u\n",
           process, *ret, *size_ptr, type, protect, parameters, count );

    status = get_extended_params( parameters, count, &limit_low, &limit_high,
                                  &align, &attributes, &machine );
    if (status) return status;

    if (type & ~type_mask) return STATUS_INVALID_PARAMETER;
    if (*ret && (align || limit_low || limit_high)) return STATUS_INVALID_PARAMETER;
    if (!*size_ptr) return STATUS_INVALID_PARAMETER;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_alloc_ex.type         = APC_VIRTUAL_ALLOC_EX;
        call.virtual_alloc_ex.addr         = wine_server_client_ptr( *ret );
        call.virtual_alloc_ex.size         = *size_ptr;
        call.virtual_alloc_ex.limit_low    = limit_low;
        call.virtual_alloc_ex.limit_high   = limit_high;
        call.virtual_alloc_ex.align        = align;
        call.virtual_alloc_ex.op_type      = type;
        call.virtual_alloc_ex.prot         = protect;
        call.virtual_alloc_ex.attributes   = attributes;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_alloc_ex.status == STATUS_SUCCESS)
        {
            *ret      = wine_server_get_ptr( result.virtual_alloc_ex.addr );
            *size_ptr = result.virtual_alloc_ex.size;
        }
        return result.virtual_alloc_ex.status;
    }

    {
        NTSTATUS macrunner_st = allocate_virtual_memory( ret, size_ptr, type, protect,
                                                         limit_low, limit_high, align, attributes );
        if (!macrunner_st)
        {
            macrunner_hb_vm_changed();
            macrunner_hb_register_x64_exec_alloc( *ret, *size_ptr, type, protect, *ret, *size_ptr );
        }
        return macrunner_st;
    }
}


/***********************************************************************
 *             NtFreeVirtualMemory   (NTDLL.@)
 *             ZwFreeVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtFreeVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr, ULONG type )
{
    struct file_view *view;
    char *base;
    sigset_t sigset;
    unsigned int status = STATUS_SUCCESS;
    LPVOID addr;
    SIZE_T size;
    char *view_end = NULL;

    if (!addr_ptr || !size_ptr) return STATUS_ACCESS_VIOLATION;

    addr = *addr_ptr;
    size = *size_ptr;

    TRACE("%p %p %08lx %x\n", process, addr, size, type );

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_free.type      = APC_VIRTUAL_FREE;
        call.virtual_free.addr      = wine_server_client_ptr( addr );
        call.virtual_free.size      = size;
        call.virtual_free.op_type   = type;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_free.status == STATUS_SUCCESS)
        {
            *addr_ptr = wine_server_get_ptr( result.virtual_free.addr );
            *size_ptr = result.virtual_free.size;
        }
        return result.virtual_free.status;
    }

    /* Fix the parameters */

    if (size && !round_size_checked( (UINT_PTR)addr, size, page_mask, &size ))
        return STATUS_INVALID_PARAMETER;
    base = ROUND_ADDR( addr, page_mask );

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    /* avoid freeing the DOS area when a broken app passes a NULL pointer */
    if (!base)
    {
#ifndef _WIN64
        /* address 1 is magic to mean release reserved space */
        if (addr == (void *)1 && !size && type == MEM_RELEASE) virtual_release_address_space();
        else
#endif
        status = STATUS_INVALID_PARAMETER;
    }
    else if (!(view = find_view( base, 0 ))) status = STATUS_MEMORY_NOT_ALLOCATED;
    else if (!get_view_limit( view, &view_end )) status = STATUS_INVALID_PARAMETER;
    else if (!is_view_valloc( view )) status = STATUS_INVALID_PARAMETER;
    else if (!size && base != view->base) status = STATUS_FREE_VM_NOT_AT_BASE;
    else if ((SIZE_T)(view_end - base) < size && !(type & MEM_COALESCE_PLACEHOLDERS))
             status = STATUS_UNABLE_TO_FREE_VM;
    else switch (type)
    {
    case MEM_DECOMMIT:
        status = decommit_pages( view, base, size );
        break;
    case MEM_RELEASE:
        if (!size) size = view->size;
        status = free_pages( view, base, size );
        break;
    case MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER:
        status = free_pages_preserve_placeholder( view, base, size );
        break;
    case MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS:
        status = coalesce_placeholders( view, base, size );
        break;
    case MEM_COALESCE_PLACEHOLDERS:
        status = STATUS_INVALID_PARAMETER_4;
        break;
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    if (status == STATUS_SUCCESS)
    {
        *addr_ptr = base;
        *size_ptr = size;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    if (!status) macrunner_hb_vm_changed();   /* MacRunner: invalidate HB region cache on free */
    return status;
}


/***********************************************************************
 *             NtProtectVirtualMemory   (NTDLL.@)
 *             ZwProtectVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtProtectVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr,
                                        ULONG new_prot, ULONG *old_prot )
{
    struct file_view *view;
    sigset_t sigset;
    unsigned int status = STATUS_SUCCESS;
    char *base;
    BYTE vprot;
    SIZE_T size;
    SIZE_T allocation_size = 0;
    LPVOID addr;
    void *allocation_base = NULL;
    DWORD old;

    if (!addr_ptr || !size_ptr || !old_prot)
        return STATUS_ACCESS_VIOLATION;

    size = *size_ptr;
    addr = *addr_ptr;

    TRACE("%p %p %08lx %08x\n", process, addr, size, new_prot );

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_protect.type = APC_VIRTUAL_PROTECT;
        call.virtual_protect.addr = wine_server_client_ptr( addr );
        call.virtual_protect.size = size;
        call.virtual_protect.prot = new_prot;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_protect.status == STATUS_SUCCESS)
        {
            *addr_ptr = wine_server_get_ptr( result.virtual_protect.addr );
            *size_ptr = result.virtual_protect.size;
            *old_prot = result.virtual_protect.prot;
        }
        else *old_prot = PAGE_NOACCESS;
        return result.virtual_protect.status;
    }

    /* Fix the parameters */

    if (!round_size_checked( (UINT_PTR)addr, size, page_mask, &size ))
        return STATUS_INVALID_PARAMETER;
    base = ROUND_ADDR( addr, page_mask );

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    if ((view = find_view( base, size )))
    {
        char *view_end;

        if (is_view_valloc( view ) && get_view_limit( view, &view_end ))
        {
            allocation_base = view->base;
            allocation_size = view_end - (char *)view->base;
        }

        /* Make sure all the pages are committed */
        if (get_committed_size( view, base, size, &vprot, VPROT_COMMITTED ) >= size && (vprot & VPROT_COMMITTED))
        {
            old = get_win32_prot( vprot, view->protect );
            status = set_protection( view, base, size, new_prot );

            if (simulate_writecopy && status == STATUS_SUCCESS
                && ((old == PAGE_WRITECOPY || old == PAGE_EXECUTE_WRITECOPY)))
            {
                TRACE("Setting VPROT_COPIED.\n");

                set_page_vprot_bits(base, size, VPROT_COPIED, 0);
                vprot |= VPROT_COPIED;
                old = get_win32_prot( vprot, view->protect );
            }
        }
        else status = STATUS_NOT_COMMITTED;
    }
    else status = STATUS_INVALID_PARAMETER;

    if (!status) VIRTUAL_DEBUG_DUMP_VIEW( view );

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    if (status == STATUS_SUCCESS)
    {
        *addr_ptr = base;
        *size_ptr = size;
        *old_prot = old;
        if (allocation_base)
            macrunner_hb_register_x64_exec_protect( base, size, new_prot,
                                                    allocation_base, allocation_size );
    }
    else *old_prot = PAGE_NOACCESS;
    if (!status) macrunner_hb_vm_changed();   /* MacRunner: invalidate HB region cache on protect */
    /* ★★★★★ ИТЕРАЦИЯ 125 — ДОНОСИТЬ СМЕНУ ПРАВ ДО ТАБЛИЦЫ HyperBridge.
     *
     * Измерено (итерации 109-124): у HyperBridge своя таблица прав (`r->perm`), и она
     * ставится ОДИН раз при отображении. Единственный вызов
     * `macrunner_hb_wow64_guest32_protect` во всём дереве стоит в
     * `macrunner_hb_protect_wow64_guest32_image_range`, то есть только для PE-образов.
     * Для обычной памяти гостя (резерв -> фиксация, VirtualProtect) права у нас
     * остаются прежними: резерв даёт `PAGE_NOACCESS -> HB_PERM_NONE`, и последующая
     * запись гостя отвергается, хотя wine считает страницу закоммиченной и записываемой.
     *
     * Замер отказа: регион [05db8000..05dc8000] perm=0 при MEM_COMMIT у wine; гость
     * пишет `MOVS` с конца области (обратное копирование) и получает c0000005.
     *
     * Гейт `MACRUNNER_HB_GUEST32_SYNC_PROT`, умолчание 0 — правка трогает права
     * гостевой памяти, включать замером. */
    if (!status)
    {
        static int mr_sync_gate = -1;
        /* ★ 07.09.2026, лейн ПРИБОРЫ-4. Тот же разбор, что у КОММИТ-ПРАВДА: гейт
         * умолчанием закрыт, печать под потолком 8, а само условие тройное (гейт, окно
         * гостя, совпадение старших битов). Ноль строк не отличал «гейт закрыт» от
         * «адрес не из гостевого окна» — а второе и есть находка итерации 126, ради
         * которой правка писалась. Три прибора вместо одного молчания. */
        HB_PROBE_LOOKED(&pr_g32_sync_gate);
        HB_PROBE_LOOKED(&pr_g32_sync_okno);
        if (mr_sync_gate < 0)
        {
            const char *v = getenv( "MACRUNNER_HB_GUEST32_SYNC_PROT" );
            mr_sync_gate = (v && *v && *v != '0') ? 1 : 0;
        }
        if (mr_sync_gate) HB_PROBE_HIT(&pr_g32_sync_gate);
        /* ★ ИТЕРАЦИЯ 126 — ДВЕ ПОПРАВКИ К СОБСТВЕННОЙ ПРАВКЕ.
         *
         * 1. Синхронизировать ТОЛЬКО память гостевого окна. В `NtProtectVirtualMemory`
         *    `base` — ХОЗЯЙСКИЙ адрес; маска `& 0xffffffff` для библиотек wine
         *    (0x7ffd…) даёт мусорный «гостевой» адрес, и права ставились по случайным
         *    местам. Замер 125: отказов стало больше (1 -> 3). Сравниваем старшие
         *    биты с базой окна.
         * 2. Печать через `%llx`: `%Ix` — формат wine, на unix-стороне он выводится
         *    буквально, и значения в строке съезжают по аргументам (замер 125). */
        if (mr_sync_gate && base && size)
        {
            unsigned long long mr_win = macrunner_hb_wow64_guest32_base();
            ULONG_PTR mr_hi = (ULONG_PTR)base & ~(ULONG_PTR)0xffffffffu;
            if (mr_win && mr_hi == (ULONG_PTR)(mr_win & ~0xffffffffull))
            {
                ULONG_PTR mr_g = (ULONG_PTR)base & 0xffffffffu;
                NTSTATUS mr_s = macrunner_hb_wow64_guest32_protect( mr_g, size, new_prot );
                static unsigned mr_sync_n;
                HB_PROBE_HIT(&pr_g32_sync_okno);
                HB_PROBE_LOOKED(&pr_g32_sync_stroka);
                if (mr_sync_n++ < 8)
                    HB_PROBE_SAY( &pr_g32_sync_stroka, "гость=%llx размер=%llx "
                             "права=%08x статус=%08llx\n",
                             (unsigned long long)mr_g, (unsigned long long)size,
                             (unsigned)new_prot, (unsigned long long)mr_s );
            }
        }
    }
    /* ★★★★★ ИТЕРАЦИЯ 92 — ДОХОДЯТ ЛИ ПРАВА ДО НАСТОЯЩЕГО ОТОБРАЖЕНИЯ.
     *
     * Итерации 90-91: `NtProtectVirtualMemory` вернул успех, `NtQueryVirtualMemory`
     * подтвердил `PAGE_READONLY`, а запись по этому адресу всё равно прошла без отказа.
     * Учёт wine и настоящее отображение расходятся; различить можно только спросив
     * систему напрямую. Здесь unix-сторона, значит mach доступен.
     *
     * Печать ограничена восемью вызовами и только для запросов, снимающих запись
     * (`PAGE_READONLY`/`PAGE_NOACCESS`) — иначе утонем: смен прав за прогон тысячи. */
#if defined(__APPLE__)
    if (!status && (new_prot == PAGE_READONLY || new_prot == PAGE_NOACCESS))
    {
        /* 92-бис: потолок в 8 съедали ранние защиты PE-модулей (адреса 0x7ffd0…),
         * а нужна страница TEB. Фильтруем по младшим 32 битам: TEB-блок лежит по
         * гостевому 0x1F0000, значит страница поля — 0x…1F1000 при любой базе окна. */
        /* 94: сравнение ЯБЛОК С ЯБЛОКАМИ. Прежний широкий аудит смешивал случаи:
         * у части записей `было_wine = 0x08` (PAGE_WRITECOPY), а у нашей страницы TEB —
         * `0x04` (PAGE_READWRITE). Для WRITECOPY отображение и должно оставаться
         * записываемым: копирование при записи реализовано через свой обработчик.
         * Поэтому берём ТОЛЬКО переход RW -> READONLY, как у TEB, и печатаем адрес,
         * чтобы отличить арендованную память от обычной. */
        /* ★★★★★ ИТЕРАЦИЯ 94 — САМОПРОВЕРКА: РАБОТАЕТ ЛИ mprotect В ЭТОМ ПРОЦЕССЕ ВООБЩЕ.
         *
         * Замер 94а показал: за весь прогон переходов RW->READONLY ровно два, и оба
         * мои (страница TEB). Сравнивать не с чем: в i386-процессе вся память идёт
         * через арену (итерация 93), обычной просто нет.
         *
         * Поэтому проверяю ступень ниже: берём страницу НАПРЯМУЮ через mmap (мимо wine
         * и мимо арены), ставим PROT_READ напрямую через mprotect и спрашиваем mach.
         * Если и там останется rw- — сломан mprotect на уровне процесса, и это гораздо
         * крупнее арены. Если станет r-- — механизм ОС исправен, значит теряется путь
         * wine. Один раз за процесс. */
        {
            static int mr_self_done;
            if (!mr_self_done)
            {
                void *sp = mmap( NULL, 0x4000, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANON, -1, 0 );
                mr_self_done = 1;
                if (sp != MAP_FAILED)
                {
                    int rc = mprotect( sp, 0x4000, PROT_READ );
                    mach_vm_address_t sa = (mach_vm_address_t)(ULONG_PTR)sp;
                    mach_vm_size_t ss = 0;
                    vm_region_basic_info_data_64_t si;
                    mach_msg_type_number_t sc = VM_REGION_BASIC_INFO_COUNT_64;
                    mach_port_t so = MACH_PORT_NULL;
                    kern_return_t sk = mach_vm_region( mach_task_self(), &sa, &ss,
                                                       VM_REGION_BASIC_INFO_64,
                                                       (vm_region_info_t)&si, &sc, &so );
                    fprintf( stderr, "macrunner-страницы: хозяйская=%lx гостевая=%lx кратность=%lu\n",
                             (unsigned long)host_page_size, (unsigned long)page_size,
                             (unsigned long)(host_page_size / page_size) );
                    fprintf( stderr, "macrunner-mprotect-самопроверка: стр=%p mprotect=%d errno=%d "
                             "mach_kr=%d mach_база=%llx mach_права=%d(%s%s%s)\n",
                             sp, rc, rc ? errno : 0, (int)sk,
                             (unsigned long long)sa, (int)si.protection,
                             (si.protection & VM_PROT_READ) ? "r" : "-",
                             (si.protection & VM_PROT_WRITE) ? "w" : "-",
                             (si.protection & VM_PROT_EXECUTE) ? "x" : "-" );
                    fflush( stderr );
                    munmap( sp, 0x4000 );
                }
                else fprintf( stderr, "macrunner-mprotect-самопроверка: mmap ОТКАЗ errno=%d\n", errno );
            }
        }
        static unsigned mr_pa_n;
        if (old == PAGE_READWRITE && mr_pa_n++ < 12)
        {
            mach_vm_address_t a2 = (mach_vm_address_t)(ULONG_PTR)base;
            mach_vm_size_t sz2 = 0;
            vm_region_basic_info_data_64_t inf;
            mach_msg_type_number_t cnt2 = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj = MACH_PORT_NULL;
            kern_return_t kr = mach_vm_region( mach_task_self(), &a2, &sz2, VM_REGION_BASIC_INFO_64,
                                               (vm_region_info_t)&inf, &cnt2, &obj );
            fprintf( stderr, "macrunner-prot-аудит: n=%u адрес=%p размер=%lx просили=%08x "
                     "было_wine=%08x mach_kr=%d mach_база=%llx mach_размер=%llx "
                     "mach_права=%d(%s%s%s) макс=%d\n",
                     mr_pa_n, base, (unsigned long)size, (unsigned)new_prot, (unsigned)old,
                     (int)kr, (unsigned long long)a2, (unsigned long long)sz2,
                     (int)inf.protection,
                     (inf.protection & VM_PROT_READ) ? "r" : "-",
                     (inf.protection & VM_PROT_WRITE) ? "w" : "-",
                     (inf.protection & VM_PROT_EXECUTE) ? "x" : "-",
                     (int)inf.max_protection );
            fflush( stderr );
        }
    }
#endif
    return status;
}


static struct file_view *get_memory_region_size( char *base, char **region_start, char **region_end,
                                                 BOOL *fake_reserved )
{
    struct wine_rb_entry *ptr;
    struct file_view *view;

    *fake_reserved = FALSE;
    *region_start = NULL;
    *region_end = working_set_limit;

    ptr = views_tree.root;
    while (ptr)
    {
        char *view_end;

        view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );
        if (!get_view_limit( view, &view_end )) return NULL;
        if ((char *)view->base > base)
        {
            *region_end = view->base;
            ptr = ptr->left;
        }
        else if (view_end <= base)
        {
            *region_start = view_end;
            ptr = ptr->right;
        }
        else
        {
            *region_start = view->base;
            *region_end = view_end;
            return view;
        }
    }
#ifdef __i386__
    {
        struct reserved_area *area;

        /* on i386, pretend that space outside of a reserved area is allocated,
         * so that the app doesn't believe it's fully available */
        LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
        {
            char *area_start = area->base;
            char *area_end = reserved_area_limit( area );

            if (area_end <= base)
            {
                if (*region_start < area_end) *region_start = area_end;
                continue;
            }
            if (area_start <= base || area_start <= (char *)address_space_start)
            {
                if (area_end < *region_end) *region_end = area_end;
                return NULL;
            }
            /* report the remaining part of the 64K after the view as free */
            if ((UINT_PTR)*region_start & granularity_mask)
            {
                char *next = (char *)ROUND_ADDR( *region_start, granularity_mask ) + granularity_mask + 1;

                if (base < next)
                {
                    *region_end = min( next, *region_end );
                    return NULL;
                }
                else *region_start = base;
            }
            /* pretend it's allocated */
            if (area_start < *region_end) *region_end = area_start;
            break;
        }
        *fake_reserved = TRUE;
    }
#endif
    return NULL;
}


static unsigned int fill_basic_memory_info( const void *addr, MEMORY_BASIC_INFORMATION *info )
{
    char *base, *alloc_base, *alloc_end;
    struct file_view *view;
    BOOL fake_reserved;
    sigset_t sigset;

    base = ROUND_ADDR( addr, page_mask );

    if (is_beyond_limit( base, 1, working_set_limit )) return STATUS_INVALID_PARAMETER;

    /* Find the view containing the address */

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    view = get_memory_region_size( base, &alloc_base, &alloc_end, &fake_reserved );

    /* Fill the info structure */

    info->BaseAddress = base;
    info->RegionSize  = alloc_end - base;

    if (!view)
    {
        if (fake_reserved)
        {
            info->State             = MEM_RESERVE;
            info->Protect           = PAGE_NOACCESS;
            info->AllocationBase    = alloc_base;
            info->AllocationProtect = PAGE_NOACCESS;
            info->Type              = MEM_PRIVATE;
        }
        else
        {
            /* MacRunner 2026-08-07 — спросить таблицу гостевых регионов ПЕРЕД тем как сказать
             * MEM_FREE.
             *
             * У нас два адресных пространства: гостевое (0x87ef...) и хостовое, которое выдаёт
             * mmap. hb_memory_map_private хранит пару base/host_base у себя, а дерево видов
             * адресует хостовое — поэтому по адресу внутри ЖИВОГО UnityPlayer сюда приходил
             * MEM_FREE с alloc_base=0 при работающей игре, грузящей объекты.
             *
             * Цена, которую мы за это платили, измерена: диагностика macrunner-hb-nullcall-vtable
             * стоит под «модуль найден» и не срабатывала ни разу, а опознание модуля вынуждено
             * СКАНИРОВАТЬ память вниз в поисках заголовка PE (~47 % главного потока при загрузке
             * до мемоизации). У Prism тот же запрос отвечает MEM_COMMIT + MEM_IMAGE.
             *
             * Завести здесь вид нельзя: гостевой адрес не принадлежит хостовому пространству, и
             * create_view его не адресует. Зато таблица регионов уже знает базу, размер и права —
             * отвечаем по существующему знанию, ничего не дублируя.
             *
             * MEM_IMAGE не заявляется: таблица регионов не различает образ и приватную память, а
             * врать про тип хуже, чем ответить честное MEM_PRIVATE. Главное здесь — что адрес
             * перестал быть «свободным», и опознание модуля наконец получает опору. */
            uint64_t g_base = 0, g_size = 0;
            uint32_t g_perm = 0;

            /* ★★★★ ПАКЕТ-2 (договор T7) — ОТВЕТ КАРТЫ ПАМЯТИ ПРИНАДЛЕЖИТ ВЛАДЕЛЬЦУ CPU.
             *
             * Ниже ответ восполняется из ЧАСТНОЙ карты HyperBridge, и восполняется ОДНИМ
             * И ТЕМ ЖЕ: `MEM_COMMIT` + `PAGE_EXECUTE_READWRITE` + `MEM_PRIVATE`. Права
             * `g_perm` при этом ЗАПРАШИВАЮТСЯ И ВЫБРАСЫВАЮТСЯ — переменная не читается
             * ни разу. Для HyperBridge это осознанная огрублённая подпорка (её история
             * в комментарии выше), и она остаётся.
             *
             * Для FEX она ЯДОВИТА, и вот чем именно. `Common/InvalidationTracker.cpp:23-29,
             * 46-63,171-183` строит интервалы самопишущегося кода и освобождения ИЗ ОТВЕТА
             * VirtualQuery. Ответ «всё исполняемо, всё зафиксировано, ничего не свободно»
             * даёт ему ложную карту исполнения и защиты, и отказ будет ТИХИМ: NT API
             * вернул успех, а трактовка памяти неверна.
             *
             * ГРАНИЦА: гасится ТОЛЬКО восполнение из карты HB. Ветвь `else` ниже
             * (честный `MEM_FREE`) и вся ветвь `view` остаются общими для обеих рук —
             * это обычный Wine, а не наш договор.
             *
             * Точность самого `g_perm` — отдельный долг, к владению не относится. */
            /* ★ БЕЗУСЛОВНЫЙ ЗОНД ДОСТИЖИМОСТИ (ПАКЕТ-2, T7). Гейт ниже стоит ПОСЛЕ
             * проверки `hb_guest_region_query_cb`, и это верно для счёта — но тогда его
             * ноль означает СРАЗУ ДВА разных положения: «сюда не дошли» и «обратный вызов
             * не назначен». Ровно эта двусмысленность у нас уже стоила дня. Зонд отвечает
             * прямо: печатает сам указатель. Потолок 8 — ветвь редкая. */
            {
                /* ★ ДВА СЧЁТЧИКА, А НЕ ОДИН. Первая редакция считала все заходы с потолком
                 * 8 — и потолок выбрали ранние заходы, когда обратный вызов ещё не
                 * назначен (он ставится позже, при инициализации unix-половины модуля
                 * процессора). Поздний заход с НЕПУСТЫМ указателем в печать бы не попал,
                 * и «cb=0x0 восемь раз» читалось бы как «его нет никогда». Это наш
                 * записанный класс отказа: потолок «первые N» голодом морит редкое
                 * позднее событие. Теперь у случая «указатель ЕСТЬ» свой счётчик и свой
                 * потолок, отнять его нечем. */
                static unsigned int mr_reach, mr_cb_set;
                if (hb_guest_region_query_cb)
                {
                    unsigned int mm = __atomic_add_fetch( &mr_cb_set, 1, __ATOMIC_RELAXED );
                    if (mm <= 8 || !(mm % 512))
                        fprintf( stderr, "macrunner-paket2-t7-dostup: cb=ЕСТЬ n=%u addr=%p\n",
                                 mm, base ), fflush( stderr );
                }
                else
                {
                    unsigned int nn = __atomic_add_fetch( &mr_reach, 1, __ATOMIC_RELAXED );
                    if (nn <= 4 || !(nn % 4096))
                        fprintf( stderr, "macrunner-paket2-t7-dostup: cb=0x0 n=%u addr=%p "
                                 "(vosplneniya iz karty HB net)\n", nn, base ), fflush( stderr );
                }
            }
            if (hb_guest_region_query_cb && !macrunner_paket2_mute( "T7-qvm" ) &&
                hb_guest_region_query_cb( (uint64_t)(ULONG_PTR)base, &g_base, &g_size, &g_perm ))
            {
                info->State             = MEM_COMMIT;
                info->Protect           = PAGE_EXECUTE_READWRITE;
                info->AllocationBase    = (void *)(ULONG_PTR)g_base;
                info->AllocationProtect = PAGE_EXECUTE_READWRITE;
                info->Type              = MEM_PRIVATE;
                if (g_size && (ULONG_PTR)base >= g_base &&
                    (ULONG_PTR)base - g_base < g_size)
                    info->RegionSize = (SIZE_T)(g_size - ((ULONG_PTR)base - g_base));
            }
            else
            {
                info->State             = MEM_FREE;
                info->Protect           = PAGE_NOACCESS;
                info->AllocationBase    = 0;
                info->AllocationProtect = 0;
                info->Type              = 0;
            }
        }
    }
    else
    {
        BYTE vprot;

        info->AllocationBase = alloc_base;
        info->RegionSize = get_committed_size( view, base, ~(size_t)0, &vprot, ~VPROT_WRITEWATCH );
        info->State = (vprot & VPROT_COMMITTED) ? MEM_COMMIT : MEM_RESERVE;
        info->Protect = (vprot & VPROT_COMMITTED) ? get_win32_prot( vprot, view->protect ) : 0;
        info->AllocationProtect = get_win32_prot( view->protect, view->protect );
        if (view->protect & SEC_IMAGE) info->Type = MEM_IMAGE;
        else if (view->protect & (SEC_FILE | SEC_RESERVE | SEC_COMMIT)) info->Type = MEM_MAPPED;
        else info->Type = MEM_PRIVATE;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    return STATUS_SUCCESS;
}

/* get basic information about a memory block */
static unsigned int get_basic_memory_info( HANDLE process, LPCVOID addr,
                                           MEMORY_BASIC_INFORMATION *info,
                                           SIZE_T len, SIZE_T *res_len )
{
    unsigned int status;

    if (len < sizeof(*info))
        return STATUS_INFO_LENGTH_MISMATCH;
    if (!info) return STATUS_ACCESS_VIOLATION;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_query.type = APC_VIRTUAL_QUERY;
        call.virtual_query.addr = wine_server_client_ptr( addr );
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_query.status == STATUS_SUCCESS)
        {
            info->BaseAddress       = wine_server_get_ptr( result.virtual_query.base );
            info->AllocationBase    = wine_server_get_ptr( result.virtual_query.alloc_base );
            info->RegionSize        = result.virtual_query.size;
            info->Protect           = result.virtual_query.prot;
            info->AllocationProtect = result.virtual_query.alloc_prot;
            info->State             = (DWORD)result.virtual_query.state << 12;
            info->Type              = (DWORD)result.virtual_query.alloc_type << 16;
            if (info->RegionSize != result.virtual_query.size)  /* truncated */
                return STATUS_INVALID_PARAMETER;  /* FIXME */
            if (res_len) *res_len = sizeof(*info);
        }
        return result.virtual_query.status;
    }

    if ((status = fill_basic_memory_info( addr, info ))) return status;

    if (res_len) *res_len = sizeof(*info);
    return STATUS_SUCCESS;
}

static unsigned int get_remote_memory_region_info( HANDLE process, LPCVOID addr, MEMORY_REGION_INFORMATION *info,
                                                   SIZE_T len, SIZE_T *res_len )
{
    MEMORY_BASIC_INFORMATION basic_info, entry_info;
    char *base, *region_start, *region_end, *next;
    SIZE_T commit_size = 0;
    unsigned int status;

    status = get_basic_memory_info( process, addr, &basic_info, sizeof(basic_info), NULL );
    if (status) return status;
    if (basic_info.State == MEM_FREE || !basic_info.AllocationBase) return STATUS_INVALID_ADDRESS;

    region_start = basic_info.AllocationBase;
    region_end = region_start;
    base = region_start;

    for (;;)
    {
        status = get_basic_memory_info( process, base, &entry_info, sizeof(entry_info), NULL );
        if (status || entry_info.State == MEM_FREE || entry_info.AllocationBase != basic_info.AllocationBase)
            break;

        if (entry_info.RegionSize > ~(UINT_PTR)0 - (UINT_PTR)entry_info.BaseAddress)
            return STATUS_INVALID_PARAMETER;
        next = (char *)entry_info.BaseAddress + entry_info.RegionSize;
        if (next <= base) break;

        if (entry_info.State == MEM_COMMIT)
        {
            if (commit_size > ~(SIZE_T)0 - entry_info.RegionSize) return STATUS_INVALID_PARAMETER;
            commit_size += entry_info.RegionSize;
        }
        region_end = next;
        base = next;
    }

    info->AllocationBase = basic_info.AllocationBase;
    info->AllocationProtect = basic_info.AllocationProtect;
    info->RegionType = 0; /* FIXME */
    if (len >= FIELD_OFFSET(MEMORY_REGION_INFORMATION, CommitSize))
        info->RegionSize = region_end - region_start;
    if (len >= FIELD_OFFSET(MEMORY_REGION_INFORMATION, PartitionId))
        info->CommitSize = commit_size;

    if (res_len) *res_len = sizeof(*info);
    return STATUS_SUCCESS;
}

static unsigned int get_memory_region_info( HANDLE process, LPCVOID addr, MEMORY_REGION_INFORMATION *info,
                                            SIZE_T len, SIZE_T *res_len )
{
    char *base, *region_start, *region_end;
    struct file_view *view;
    BYTE vprot, vprot_mask;
    BOOL fake_reserved;
    sigset_t sigset;
    SIZE_T size;

    if (len < FIELD_OFFSET(MEMORY_REGION_INFORMATION, CommitSize))
        return STATUS_INFO_LENGTH_MISMATCH;
    if (!info) return STATUS_ACCESS_VIOLATION;

    if (process != NtCurrentProcess())
        return get_remote_memory_region_info( process, addr, info, len, res_len );

    base = ROUND_ADDR( addr, page_mask );

    if (is_beyond_limit( base, 1, working_set_limit )) return STATUS_INVALID_PARAMETER;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    if ((view = get_memory_region_size( base, &region_start, &region_end, &fake_reserved )))
    {
        info->AllocationBase = view->base;
        info->AllocationProtect = get_win32_prot( view->protect, view->protect );
        info->RegionType = 0; /* FIXME */
        if (len >= FIELD_OFFSET(MEMORY_REGION_INFORMATION, CommitSize))
            info->RegionSize = view->size;
        if (len >= FIELD_OFFSET(MEMORY_REGION_INFORMATION, PartitionId))
        {
            base = region_start;
            info->CommitSize = 0;
            vprot_mask = VPROT_COMMITTED;
            if (!is_view_valloc( view )) vprot_mask |= PAGE_WRITECOPY;
            while (base != region_end &&
                   (size = get_committed_size( view, base, ~(size_t)0, &vprot, vprot_mask )))
            {
                if ((vprot & vprot_mask) == vprot_mask) info->CommitSize += size;
                base += size;
            }
        }
    }
    else
    {
        if (!fake_reserved)
        {
            server_leave_uninterrupted_section( &virtual_mutex, &sigset );
            return STATUS_INVALID_ADDRESS;
        }
        info->AllocationBase = region_start;
        info->AllocationProtect = PAGE_NOACCESS;
        info->RegionType = 0; /* FIXME */
        info->RegionSize = region_end - region_start;
        info->CommitSize = 0;
    }

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    if (res_len) *res_len = sizeof(*info);
    return STATUS_SUCCESS;
}

struct working_set_info_ref
{
    char *addr;
    SIZE_T orig_index;
};

#if defined(HAVE_LIBPROCSTAT)
struct fill_working_set_info_data
{
    struct procstat *pstat;
    struct kinfo_proc *kip;
    unsigned int vmentry_count;
    struct kinfo_vmentry *vmentries;
};

static void init_fill_working_set_info_data( struct fill_working_set_info_data *d, char *end )
{
    unsigned int proc_count;

    d->kip = NULL;
    d->vmentry_count = 0;
    d->vmentries = NULL;

    if ((d->pstat = procstat_open_sysctl()))
        d->kip = procstat_getprocs( d->pstat, KERN_PROC_PID, getpid(), &proc_count );
    if (d->kip)
        d->vmentries = procstat_getvmmap( d->pstat, d->kip, &d->vmentry_count );
    if (!d->vmentries)
        WARN( "couldn't get process vmmap, errno %d\n", errno );
}

static void free_fill_working_set_info_data( struct fill_working_set_info_data *d )
{
    if (d->vmentries)
        procstat_freevmmap( d->pstat, d->vmentries );
    if (d->kip)
        procstat_freeprocs( d->pstat, d->kip );
    if (d->pstat)
        procstat_close( d->pstat );
}

static void fill_working_set_info( struct fill_working_set_info_data *d, struct file_view *view, BYTE vprot,
                                   struct working_set_info_ref *ref, SIZE_T count,
                                   MEMORY_WORKING_SET_EX_INFORMATION *info )
{
    SIZE_T i;
    int j;

    for (i = 0; i < count; ++i)
    {
        MEMORY_WORKING_SET_EX_INFORMATION *p = &info[ref[i].orig_index];
        struct kinfo_vmentry *entry = NULL;

        for (j = 0; j < d->vmentry_count; j++)
        {
            if (d->vmentries[j].kve_start <= (ULONG_PTR)p->VirtualAddress && (ULONG_PTR)p->VirtualAddress <= d->vmentries[j].kve_end)
            {
                entry = &d->vmentries[j];
                break;
            }
        }

        p->VirtualAttributes.Valid = !(vprot & VPROT_GUARD) && (vprot & 0x0f) && entry && entry->kve_type != KVME_TYPE_SWAP;
        p->VirtualAttributes.Shared = !is_view_valloc( view );
        if (p->VirtualAttributes.Shared && p->VirtualAttributes.Valid)
            p->VirtualAttributes.ShareCount = 1; /* FIXME */
        if (p->VirtualAttributes.Valid)
            p->VirtualAttributes.Win32Protection = get_win32_prot( vprot, view->protect );
    }
}
#else
static int pagemap_fd = -2;

struct fill_working_set_info_data
{
    UINT64 pm_buffer[256];
    SIZE_T buffer_start;
    ssize_t buffer_len;
    SIZE_T end_page;
};

static void init_fill_working_set_info_data( struct fill_working_set_info_data *d, char *end )
{
    d->buffer_start = 0;
    d->buffer_len = 0;
    d->end_page = (UINT_PTR)end / host_page_size;
    memset( d->pm_buffer, 0, sizeof(d->pm_buffer) );

    if (pagemap_fd != -2) return;

#ifdef O_CLOEXEC
    if ((pagemap_fd = open( "/proc/self/pagemap", O_RDONLY | O_CLOEXEC, 0 )) == -1 && errno == EINVAL)
#endif
        pagemap_fd = open( "/proc/self/pagemap", O_RDONLY, 0 );

    if (pagemap_fd == -1) WARN( "unable to open /proc/self/pagemap\n" );
    else fcntl(pagemap_fd, F_SETFD, FD_CLOEXEC);  /* in case O_CLOEXEC isn't supported */
}

static void free_fill_working_set_info_data( struct fill_working_set_info_data *d )
{
}

static void fill_working_set_info( struct fill_working_set_info_data *d, struct file_view *view, BYTE vprot,
                                   struct working_set_info_ref *ref, SIZE_T count,
                                   MEMORY_WORKING_SET_EX_INFORMATION *info )
{
    MEMORY_WORKING_SET_EX_INFORMATION *p;
    UINT64 pagemap;
    SIZE_T i, page;
    ssize_t len;

    for (i = 0; i < count; ++i)
    {
        page = (UINT_PTR)ref[i].addr / host_page_size;
        p = &info[ref[i].orig_index];

        assert(page >= d->buffer_start);
        if (page >= d->buffer_start + d->buffer_len)
        {
            d->buffer_start = page;
            len = min( sizeof(d->pm_buffer), (d->end_page - page) * sizeof(pagemap) );
            if (pagemap_fd != -1)
            {
                d->buffer_len = pread( pagemap_fd, d->pm_buffer, len, page * sizeof(pagemap) );
                if (d->buffer_len != len)
                {
                    d->buffer_len = max( d->buffer_len, 0 );
                    memset( d->pm_buffer + d->buffer_len / sizeof(pagemap), 0, len - d->buffer_len );
                }
            }
            d->buffer_len = len / sizeof(pagemap);
        }
        pagemap = d->pm_buffer[page - d->buffer_start];

        p->VirtualAttributes.Valid = !(vprot & VPROT_GUARD) && (vprot & 0x0f) && (pagemap >> 63);
        p->VirtualAttributes.Shared = !is_view_valloc( view ) && ((pagemap >> 61) & 1);
        if (p->VirtualAttributes.Shared && p->VirtualAttributes.Valid)
            p->VirtualAttributes.ShareCount = 1; /* FIXME */
        if (p->VirtualAttributes.Valid)
            p->VirtualAttributes.Win32Protection = get_win32_prot( vprot, view->protect );
    }
}
#endif

static int compare_working_set_info_ref( const void *a, const void *b )
{
    const struct working_set_info_ref *r1 = a, *r2 = b;

    if (r1->addr < r2->addr) return -1;
    return r1->addr > r2->addr;
}

static NTSTATUS get_remote_working_set_ex( HANDLE process, MEMORY_WORKING_SET_EX_INFORMATION *info,
                                           SIZE_T len, SIZE_T *res_len )
{
    SIZE_T i, count = len / sizeof(*info);

    for (i = 0; i < count; ++i)
    {
        MEMORY_BASIC_INFORMATION basic_info;
        unsigned int status;

        status = get_basic_memory_info( process, info[i].VirtualAddress, &basic_info, sizeof(basic_info), NULL );
        info[i].VirtualAttributes.Flags = 0;
        if (status == STATUS_INVALID_PARAMETER || status == STATUS_WORKING_SET_LIMIT_RANGE) continue;
        if (status) return status;
        if (basic_info.State != MEM_COMMIT || !basic_info.Protect ||
            (basic_info.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            continue;

        info[i].VirtualAttributes.Valid = 1;
        info[i].VirtualAttributes.Win32Protection = basic_info.Protect;
        if (basic_info.Type != MEM_PRIVATE)
        {
            info[i].VirtualAttributes.Shared = 1;
            info[i].VirtualAttributes.ShareCount = 1; /* FIXME */
        }
    }

    if (res_len) *res_len = len;
    return STATUS_SUCCESS;
}

static NTSTATUS get_working_set_ex( HANDLE process, LPCVOID addr,
                                    MEMORY_WORKING_SET_EX_INFORMATION *info,
                                    SIZE_T len, SIZE_T *res_len )
{
    struct working_set_info_ref ref_buffer[256], *ref = ref_buffer, *r;
    struct fill_working_set_info_data data;
    char *start, *end;
    UINT_PTR last, limit;
    SIZE_T i, count;
    struct file_view *view, *prev_view;
    sigset_t sigset;
    BYTE vprot;

    if (len < sizeof(*info)) return STATUS_INFO_LENGTH_MISMATCH;
    if (!info) return STATUS_ACCESS_VIOLATION;
    if (process != NtCurrentProcess()) return get_remote_working_set_ex( process, info, len, res_len );

    count = len / sizeof(*info);

    if (count > ARRAY_SIZE(ref_buffer) && !(ref = malloc( count * sizeof(*ref) )))
        return STATUS_NO_MEMORY;
    for (i = 0; i < count; ++i)
    {
        ref[i].orig_index = i;
        ref[i].addr = ROUND_ADDR( info[i].VirtualAddress, page_mask );
        info[i].VirtualAttributes.Flags = 0;
    }
    qsort( ref, count, sizeof(*ref), compare_working_set_info_ref );
    start = ref[0].addr;
    last = (UINT_PTR)ref[count - 1].addr;
    limit = (UINT_PTR)working_set_limit;
    if (last >= limit || page_size > limit - last) end = working_set_limit;
    else end = (char *)(last + page_size);

    if ((UINT_PTR)start >= (UINT_PTR)end)
    {
        if (ref != ref_buffer) free( ref );
        if (res_len) *res_len = len;
        return STATUS_SUCCESS;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    init_fill_working_set_info_data( &data, end );

    view = find_view_range( start, end - start );
    while (view && (char *)view->base > start)
    {
        char *prev_end;

        prev_view = RB_ENTRY_VALUE( rb_prev( &view->entry ), struct file_view, entry );
        if (!prev_view || !get_view_limit( prev_view, &prev_end ) || prev_end <= start) break;
        view = prev_view;
    }

    r = ref;
    while (view && (char *)view->base < end)
    {
        char *view_end;

        if (!get_view_limit( view, &view_end )) break;
        if (start < (char *)view->base) start = view->base;
        while (r != ref + count && r->addr < start) ++r;
        while (start != view_end && r != ref + count && r->addr < view_end)
        {
            start += get_committed_size( view, start, end - start, &vprot, ~VPROT_WRITEWATCH );
            i = 0;
            while (r + i != ref + count && r[i].addr < start) ++i;
            if (vprot & VPROT_COMMITTED) fill_working_set_info( &data, view, vprot, r, i, info );
            r += i;
        }
        if (r == ref + count) break;
        view = RB_ENTRY_VALUE( rb_next( &view->entry ), struct file_view, entry );
    }

    free_fill_working_set_info_data( &data );
    if (ref != ref_buffer) free( ref );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    if (res_len)
        *res_len = len;
    return STATUS_SUCCESS;
}

static unsigned int get_memory_section_name( HANDLE process, LPCVOID addr,
                                             MEMORY_SECTION_NAME *info, SIZE_T len, SIZE_T *ret_len )
{
    unsigned int status;

    if (!info) return STATUS_ACCESS_VIOLATION;

    SERVER_START_REQ( get_mapping_filename )
    {
        req->process = wine_server_obj_handle( process );
        req->addr = wine_server_client_ptr( addr );
        if (len > sizeof(*info) + sizeof(WCHAR))
            wine_server_set_reply( req, info + 1, len - sizeof(*info) - sizeof(WCHAR) );
        status = wine_server_call( req );
        if (!status || status == STATUS_BUFFER_OVERFLOW)
        {
            if (ret_len) *ret_len = sizeof(*info) + reply->len + sizeof(WCHAR);
            if (len < sizeof(*info)) status = STATUS_INFO_LENGTH_MISMATCH;
            if (!status)
            {
                info->SectionFileName.Buffer = (WCHAR *)(info + 1);
                info->SectionFileName.Length = reply->len;
                info->SectionFileName.MaximumLength = reply->len + sizeof(WCHAR);
                info->SectionFileName.Buffer[reply->len / sizeof(WCHAR)] = 0;
            }
        }
    }
    SERVER_END_REQ;
    return status;
}

static unsigned int get_memory_image_info( HANDLE process, LPCVOID addr, MEMORY_IMAGE_INFORMATION *info,
                                           SIZE_T len, SIZE_T *res_len )
{
    unsigned int status;

    if (len < sizeof(*info)) return STATUS_INFO_LENGTH_MISMATCH;
    if (!info) return STATUS_ACCESS_VIOLATION;
    memset( info, 0, sizeof(*info) );

    SERVER_START_REQ( get_image_view_info )
    {
        req->process = wine_server_obj_handle( process );
        req->addr = wine_server_client_ptr( addr );
        status = wine_server_call( req );
        if (!status && reply->base)
        {
            info->ImageBase = wine_server_get_ptr( reply->base );
            info->SizeOfImage = reply->size;
            info->ImageSigningLevel = 12;
        }
    }
    SERVER_END_REQ;

    if (status == STATUS_NOT_MAPPED_VIEW)
    {
        MEMORY_BASIC_INFORMATION basic_info;

        status = get_basic_memory_info( process, addr, &basic_info, sizeof(basic_info), NULL );
        if (status || basic_info.State == MEM_FREE) status = STATUS_INVALID_ADDRESS;
    }

    if (!status && res_len) *res_len = sizeof(*info);
    return status;
}


/***********************************************************************
 *             NtQueryVirtualMemory   (NTDLL.@)
 *             ZwQueryVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryVirtualMemory( HANDLE process, LPCVOID addr,
                                      MEMORY_INFORMATION_CLASS info_class,
                                      PVOID buffer, SIZE_T len, SIZE_T *res_len )
{
    NTSTATUS status;

    TRACE("(%p, %p, info_class=%d, %p, %ld, %p)\n",
          process, addr, info_class, buffer, len, res_len);

    switch(info_class)
    {
        case MemoryBasicInformation:
            return get_basic_memory_info( process, addr, buffer, len, res_len );

        case MemoryWorkingSetExInformation:
            return get_working_set_ex( process, addr, buffer, len, res_len );

        case MemoryMappedFilenameInformation:
            return get_memory_section_name( process, addr, buffer, len, res_len );

        case MemoryRegionInformation:
            return get_memory_region_info( process, addr, buffer, len, res_len );

        case MemoryImageInformation:
            return get_memory_image_info( process, addr, buffer, len, res_len );

        case MemoryWineUnixFuncs:
        case MemoryWineUnixWow64Funcs:
            if (len != sizeof(unixlib_handle_t)) return STATUS_INFO_LENGTH_MISMATCH;
            if (!buffer) return STATUS_ACCESS_VIOLATION;
            if (process == GetCurrentProcess())
            {
                void *module = (void *)addr;
                const void *funcs = NULL;

                status = get_builtin_unix_funcs( module, info_class == MemoryWineUnixWow64Funcs, &funcs );
                if (!status) *(unixlib_handle_t *)buffer = (UINT_PTR)funcs;
                return status;
            }
            return STATUS_INVALID_HANDLE;

        default:
            FIXME("(%p,%p,info_class=%d,%p,%ld,%p) Unknown information class\n",
                  process, addr, info_class, buffer, len, res_len);
            return STATUS_INVALID_INFO_CLASS;
    }
}


/***********************************************************************
 *             NtLockVirtualMemory   (NTDLL.@)
 *             ZwLockVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtLockVirtualMemory( HANDLE process, PVOID *addr, SIZE_T *size, ULONG unknown )
{
    unsigned int status = STATUS_SUCCESS;
    SIZE_T host_size, rounded_size;
    void *rounded_addr;

    if (!addr || !size) return STATUS_ACCESS_VIOLATION;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_lock.type = APC_VIRTUAL_LOCK;
        call.virtual_lock.addr = wine_server_client_ptr( *addr );
        call.virtual_lock.size = *size;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_lock.status == STATUS_SUCCESS)
        {
            *addr = wine_server_get_ptr( result.virtual_lock.addr );
            *size = result.virtual_lock.size;
        }
        return result.virtual_lock.status;
    }

    if (!round_size_checked( (UINT_PTR)*addr, *size, page_mask, &rounded_size ))
        return STATUS_INVALID_PARAMETER;
    rounded_addr = ROUND_ADDR( *addr, page_mask );
    if (!round_size_checked( (UINT_PTR)rounded_addr, rounded_size, host_page_mask, &host_size ))
        return STATUS_INVALID_PARAMETER;
    *size = rounded_size;
    *addr = rounded_addr;

    if (mlock( ROUND_ADDR( *addr, host_page_mask ), host_size ))
        status = STATUS_ACCESS_DENIED;
    return status;
}


/***********************************************************************
 *             NtUnlockVirtualMemory   (NTDLL.@)
 *             ZwUnlockVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtUnlockVirtualMemory( HANDLE process, PVOID *addr, SIZE_T *size, ULONG unknown )
{
    unsigned int status = STATUS_SUCCESS;
    SIZE_T host_size, rounded_size;
    void *rounded_addr;

    if (!addr || !size) return STATUS_ACCESS_VIOLATION;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_unlock.type = APC_VIRTUAL_UNLOCK;
        call.virtual_unlock.addr = wine_server_client_ptr( *addr );
        call.virtual_unlock.size = *size;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_unlock.status == STATUS_SUCCESS)
        {
            *addr = wine_server_get_ptr( result.virtual_unlock.addr );
            *size = result.virtual_unlock.size;
        }
        return result.virtual_unlock.status;
    }

    if (!round_size_checked( (UINT_PTR)*addr, *size, page_mask, &rounded_size ))
        return STATUS_INVALID_PARAMETER;
    rounded_addr = ROUND_ADDR( *addr, page_mask );
    if (!round_size_checked( (UINT_PTR)rounded_addr, rounded_size, host_page_mask, &host_size ))
        return STATUS_INVALID_PARAMETER;
    *size = rounded_size;
    *addr = rounded_addr;

    if (munlock( ROUND_ADDR( *addr, host_page_mask ), host_size ))
        status = STATUS_ACCESS_DENIED;
    return status;
}


/***********************************************************************
 *             NtMapViewOfSection   (NTDLL.@)
 *             ZwMapViewOfSection   (NTDLL.@)
 */
#if defined(__aarch64__)
NTSTATUS WINAPI NtMapViewOfSection( HANDLE handle, HANDLE process, PVOID *addr_ptr, ULONG_PTR zero_bits,
                                    SIZE_T commit_size, const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                    const struct __wine_nt_section_extra *extra )
#else
NTSTATUS WINAPI NtMapViewOfSection( HANDLE handle, HANDLE process, PVOID *addr_ptr, ULONG_PTR zero_bits,
                                    SIZE_T commit_size, const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                    SECTION_INHERIT inherit,
                                    ULONG alloc_type_arg, ULONG protect_arg )
#endif
{
    unsigned int res;
    SIZE_T mask = granularity_mask;
    LARGE_INTEGER offset;
#if defined(__aarch64__)
    SECTION_INHERIT inherit = extra ? extra->inherit : ViewShare;
    ULONG alloc_type = extra ? extra->alloc_type : 0;
    ULONG protect = extra ? extra->protect : 0;
#else
    ULONG alloc_type = alloc_type_arg;
    ULONG protect = protect_arg;
#endif

    offset.QuadPart = offset_ptr ? offset_ptr->QuadPart : 0;

    if (!addr_ptr || !size_ptr) return STATUS_ACCESS_VIOLATION;

    TRACE("handle=%p process=%p addr=%p off=%s size=0x%lx alloc_type=0x%x access=0x%x\n",
          handle, process, *addr_ptr, wine_dbgstr_longlong(offset.QuadPart), *size_ptr, alloc_type, protect );

    /* Check parameters */
    if (zero_bits > 21 && zero_bits < 32)
        return STATUS_INVALID_PARAMETER_4;

    /* If both addr_ptr and zero_bits are passed, they have match */
    if (zero_bits && zero_bits < 32 && ((UINT_PTR)*addr_ptr >> (32 - zero_bits)))
        return STATUS_INVALID_PARAMETER_4;
    if (zero_bits >= 32 && ((UINT_PTR)*addr_ptr & ~zero_bits))
        return STATUS_INVALID_PARAMETER_4;

    if (!is_win64 && !is_wow64())
    {
        if (zero_bits >= 32) return STATUS_INVALID_PARAMETER_4;
        if (alloc_type & AT_ROUND_TO_PAGE)
        {
            *addr_ptr = ROUND_ADDR( *addr_ptr, page_mask );
            mask = page_mask;
        }
    }
    else if (alloc_type & AT_ROUND_TO_PAGE) return STATUS_INVALID_PARAMETER_9;

    if (alloc_type & MEM_REPLACE_PLACEHOLDER) mask = page_mask;
    if (offset.u.LowPart & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & host_page_mask)
    {
        ERR( "unaligned placeholder at %p\n", *addr_ptr );
        return STATUS_MAPPED_ALIGNMENT;
    }

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.map_view.type         = APC_MAP_VIEW;
        call.map_view.handle       = wine_server_obj_handle( handle );
        call.map_view.addr         = wine_server_client_ptr( *addr_ptr );
        call.map_view.size         = *size_ptr;
        call.map_view.offset       = offset.QuadPart;
        call.map_view.zero_bits    = zero_bits;
        call.map_view.alloc_type   = alloc_type;
        call.map_view.prot         = protect;
        res = server_queue_process_apc( process, &call, &result );
        if (res != STATUS_SUCCESS) return res;

        if (NT_SUCCESS(result.map_view.status))
        {
            *addr_ptr = wine_server_get_ptr( result.map_view.addr );
            *size_ptr = result.map_view.size;
        }
        return result.map_view.status;
    }

    return virtual_map_section( handle, addr_ptr, 0, get_zero_bits_limit( zero_bits ), commit_size,
                                offset_ptr, size_ptr, alloc_type, protect, 0 );
}

/***********************************************************************
 *             NtMapViewOfSectionEx   (NTDLL.@)
 *             ZwMapViewOfSectionEx   (NTDLL.@)
 */
NTSTATUS WINAPI NtMapViewOfSectionEx( HANDLE handle, HANDLE process, PVOID *addr_ptr,
                                      const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                      ULONG alloc_type, ULONG protect,
                                      MEM_EXTENDED_PARAMETER *parameters, ULONG count )
{
    ULONG_PTR limit_low = 0, limit_high = 0, align = 0;
    ULONG attributes = 0;
    USHORT machine = 0;
    unsigned int status;
    SIZE_T mask = granularity_mask;
    LARGE_INTEGER offset;

    offset.QuadPart = offset_ptr ? offset_ptr->QuadPart : 0;

    if (!addr_ptr || !size_ptr) return STATUS_ACCESS_VIOLATION;

    TRACE( "handle=%p process=%p addr=%p off=%s size=0x%lx alloc_type=0x%x access=0x%x\n",
           handle, process, *addr_ptr, wine_dbgstr_longlong(offset.QuadPart), *size_ptr, alloc_type, protect );

    status = get_extended_params( parameters, count, &limit_low, &limit_high,
                                  &align, &attributes, &machine );
    if (status) return status;

    if (align) return STATUS_INVALID_PARAMETER;
    if (*addr_ptr && (limit_low || limit_high)) return STATUS_INVALID_PARAMETER;

    if (alloc_type & AT_ROUND_TO_PAGE)
    {
        if (is_win64 || is_wow64()) return STATUS_INVALID_PARAMETER;
        *addr_ptr = ROUND_ADDR( *addr_ptr, page_mask );
        mask = page_mask;
    }

    if (alloc_type & MEM_REPLACE_PLACEHOLDER) mask = page_mask;
    if (offset.u.LowPart & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & host_page_mask)
    {
        ERR( "unaligned placeholder at %p\n", *addr_ptr );
        return STATUS_MAPPED_ALIGNMENT;
    }

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.map_view_ex.type         = APC_MAP_VIEW_EX;
        call.map_view_ex.handle       = wine_server_obj_handle( handle );
        call.map_view_ex.addr         = wine_server_client_ptr( *addr_ptr );
        call.map_view_ex.size         = *size_ptr;
        call.map_view_ex.offset       = offset.QuadPart;
        call.map_view_ex.limit_low    = limit_low;
        call.map_view_ex.limit_high   = limit_high;
        call.map_view_ex.alloc_type   = alloc_type;
        call.map_view_ex.prot         = protect;
        call.map_view_ex.machine      = machine;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (NT_SUCCESS(result.map_view_ex.status))
        {
            *addr_ptr = wine_server_get_ptr( result.map_view_ex.addr );
            *size_ptr = result.map_view_ex.size;
        }
        return result.map_view_ex.status;
    }

    return virtual_map_section( handle, addr_ptr, limit_low, limit_high, 0,
                                offset_ptr, size_ptr, alloc_type, protect, machine );
}


/***********************************************************************
 *             unmap_view_of_section
 *
 * NtUnmapViewOfSection[Ex] implementation.
 */
static NTSTATUS unmap_view_of_section( HANDLE process, PVOID addr, ULONG flags )
{
    struct file_view *view;
    unsigned int status = STATUS_NOT_MAPPED_VIEW;
    sigset_t sigset;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.unmap_view.type = APC_UNMAP_VIEW;
        call.unmap_view.addr = wine_server_client_ptr( addr );
        call.unmap_view.flags = flags;
        status = server_queue_process_apc( process, &call, &result );
        if (status == STATUS_SUCCESS) status = result.unmap_view.status;
        return status;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!(view = find_view( addr, 0 )) || is_view_valloc( view )) goto done;

    if (flags & MEM_PRESERVE_PLACEHOLDER && !(view->protect & VPROT_PLACEHOLDER))
    {
        status = STATUS_CONFLICTING_ADDRESSES;
        goto done;
    }
    if (view->protect & VPROT_SYSTEM)
    {
        struct builtin_module *builtin;

        LIST_FOR_EACH_ENTRY( builtin, &builtin_modules, struct builtin_module, entry )
        {
            if (builtin->module != view->base) continue;
            if (builtin->refcount > 1)
            {
                TRACE( "not freeing in-use builtin %p\n", view->base );
                builtin->refcount--;
                server_leave_uninterrupted_section( &virtual_mutex, &sigset );
                return STATUS_SUCCESS;
            }
        }
    }

    SERVER_START_REQ( unmap_view )
    {
        req->base = wine_server_client_ptr( view->base );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    if (!status)
    {
        if (view->protect & SEC_IMAGE) release_builtin_module( view->base );
        if (flags & MEM_PRESERVE_PLACEHOLDER) free_pages_preserve_placeholder( view, view->base, view->size );
        else delete_view( view );
    }
    else FIXME( "failed to unmap %p %x\n", view->base, status );
done:
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *             NtUnmapViewOfSection   (NTDLL.@)
 *             ZwUnmapViewOfSection   (NTDLL.@)
 */
NTSTATUS WINAPI NtUnmapViewOfSection( HANDLE process, PVOID addr )
{
    return unmap_view_of_section( process, addr, 0 );
}

/***********************************************************************
 *             NtUnmapViewOfSectionEx   (NTDLL.@)
 *             ZwUnmapViewOfSectionEx   (NTDLL.@)
 */
NTSTATUS WINAPI NtUnmapViewOfSectionEx( HANDLE process, PVOID addr, ULONG flags )
{
    static const ULONG type_mask = MEM_UNMAP_WITH_TRANSIENT_BOOST | MEM_PRESERVE_PLACEHOLDER;

    if (flags & ~type_mask)
    {
        WARN( "Unsupported flags %#x.\n", flags );
        return STATUS_INVALID_PARAMETER;
    }
    if (flags & MEM_UNMAP_WITH_TRANSIENT_BOOST) FIXME( "Ignoring MEM_UNMAP_WITH_TRANSIENT_BOOST.\n" );
    return unmap_view_of_section( process, addr, flags );
}

/******************************************************************************
 *             virtual_fill_image_information
 *
 * Helper for NtQuerySection.
 */
void virtual_fill_image_information( const struct pe_image_info *pe_info, SECTION_IMAGE_INFORMATION *info )
{
    info->TransferAddress             = wine_server_get_ptr( pe_info->base + pe_info->entry_point );
    info->ZeroBits                    = pe_info->zerobits;
    info->MaximumStackSize            = pe_info->stack_size;
    info->CommittedStackSize          = pe_info->stack_commit;
    info->SubSystemType               = pe_info->subsystem;
    info->MinorSubsystemVersion       = pe_info->subsystem_minor;
    info->MajorSubsystemVersion       = pe_info->subsystem_major;
    info->MajorOperatingSystemVersion = pe_info->osversion_major;
    info->MinorOperatingSystemVersion = pe_info->osversion_minor;
    info->ImageCharacteristics        = pe_info->image_charact;
    info->DllCharacteristics          = pe_info->dll_charact;
    info->Machine                     = pe_info->machine;
    info->ImageContainsCode           = pe_info->contains_code;
    info->ImageFlags                  = pe_info->image_flags;
    info->LoaderFlags                 = pe_info->loader_flags;
    info->ImageFileSize               = pe_info->file_size;
    info->CheckSum                    = pe_info->checksum;
#ifndef _WIN64 /* don't return 64-bit values to 32-bit processes */
    if (is_machine_64bit( pe_info->machine ))
    {
        info->TransferAddress = (void *)0x81231234;  /* sic */
        info->MaximumStackSize = 0x100000;
        info->CommittedStackSize = 0x10000;
    }
#endif
}

/******************************************************************************
 *             NtQuerySection   (NTDLL.@)
 *             ZwQuerySection   (NTDLL.@)
 */
NTSTATUS WINAPI NtQuerySection( HANDLE handle, SECTION_INFORMATION_CLASS class, void *ptr,
                                SIZE_T size, SIZE_T *ret_size )
{
    unsigned int status;
    struct pe_image_info image_info;

    switch (class)
    {
    case SectionBasicInformation:
        if (size < sizeof(SECTION_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;
        break;
    case SectionImageInformation:
        if (size < sizeof(SECTION_IMAGE_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;
        break;
    default:
	FIXME( "class %u not implemented\n", class );
	return STATUS_NOT_IMPLEMENTED;
    }
    if (!ptr) return STATUS_ACCESS_VIOLATION;

    SERVER_START_REQ( get_mapping_info )
    {
        req->handle = wine_server_obj_handle( handle );
        req->access = SECTION_QUERY;
        wine_server_set_reply( req, &image_info, sizeof(image_info) );
        if (!(status = wine_server_call( req )))
        {
            if (class == SectionBasicInformation)
            {
                SECTION_BASIC_INFORMATION *info = ptr;
                info->Attributes    = reply->flags;
                info->BaseAddress   = NULL;
                info->Size.QuadPart = reply->size;
                if (ret_size) *ret_size = sizeof(*info);
            }
            else if (reply->flags & SEC_IMAGE)
            {
                SECTION_IMAGE_INFORMATION *info = ptr;
                virtual_fill_image_information( &image_info, info );
                if (ret_size) *ret_size = sizeof(*info);
            }
            else status = STATUS_SECTION_NOT_IMAGE;
        }
    }
    SERVER_END_REQ;

    return status;
}


/***********************************************************************
 *             NtFlushVirtualMemory   (NTDLL.@)
 *             ZwFlushVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushVirtualMemory( HANDLE process, LPCVOID *addr_ptr,
                                      SIZE_T *size_ptr, ULONG unknown )
{
    struct file_view *view;
    unsigned int status = STATUS_SUCCESS;
    sigset_t sigset;
    void *addr;

    if (!addr_ptr || !size_ptr) return STATUS_ACCESS_VIOLATION;

    addr = ROUND_ADDR( *addr_ptr, page_mask );

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_flush.type = APC_VIRTUAL_FLUSH;
        call.virtual_flush.addr = wine_server_client_ptr( addr );
        call.virtual_flush.size = *size_ptr;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_flush.status == STATUS_SUCCESS)
        {
            *addr_ptr = wine_server_get_ptr( result.virtual_flush.addr );
            *size_ptr = result.virtual_flush.size;
        }
        return result.virtual_flush.status;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!(view = find_view( addr, *size_ptr ))) status = STATUS_INVALID_PARAMETER;
    else
    {
        char *view_end;
        SIZE_T host_size;

        if (!get_view_limit( view, &view_end ))
        {
            status = STATUS_INVALID_PARAMETER;
            goto done;
        }
        if (!*size_ptr) *size_ptr = view_end - (char *)addr;
        if (!round_size_checked( (UINT_PTR)addr, *size_ptr, host_page_mask, &host_size ))
        {
            status = STATUS_INVALID_PARAMETER;
            goto done;
        }
        *addr_ptr = addr;
#ifdef MS_ASYNC
        if (msync( ROUND_ADDR( addr, host_page_mask ), host_size, MS_ASYNC ))
            status = STATUS_NOT_MAPPED_DATA;
#endif
    }
done:
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *             NtGetWriteWatch   (NTDLL.@)
 *             ZwGetWriteWatch   (NTDLL.@)
 */
NTSTATUS WINAPI NtGetWriteWatch( HANDLE process, ULONG flags, PVOID base, SIZE_T size, PVOID *addresses,
                                 ULONG_PTR *count, ULONG *granularity )
{
    NTSTATUS status = STATUS_SUCCESS;

    macrunner_ww_note( "get", &macrunner_ww_get );
    sigset_t sigset;
    char *end;

    if (!count || !granularity) return STATUS_ACCESS_VIOLATION;
    if (!round_size_checked( (UINT_PTR)base, size, page_mask, &size ))
        return STATUS_INVALID_PARAMETER;
    base = ROUND_ADDR( base, page_mask );
    if (!*count || !size) return STATUS_INVALID_PARAMETER;
    if (size > ~(SIZE_T)0 - (UINT_PTR)base) return STATUS_INVALID_PARAMETER;
    end = (char *)base + size;
    if (flags & ~WRITE_WATCH_FLAG_RESET) return STATUS_INVALID_PARAMETER;

    if (!addresses) return STATUS_ACCESS_VIOLATION;

    TRACE( "%p %x %p-%p %p %lu\n", process, flags, base, end, addresses, *count );

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    if (is_write_watch_range( base, size ))
    {
        ULONG_PTR pos = 0;
        char *addr = base;

        if (use_kernel_writewatch)
            kernel_get_write_watches( base, size, addresses, count, flags & WRITE_WATCH_FLAG_RESET );
        else
        {
            while (pos < *count && addr < end)
            {
                if (!(get_page_vprot( addr ) & VPROT_WRITEWATCH)) addresses[pos++] = addr;
                addr += page_size;
            }
            size = addr - (char *)base;
            *count = pos;
        }
        if (flags & WRITE_WATCH_FLAG_RESET && (enable_write_exceptions || !use_kernel_writewatch))
        {
            if (use_kernel_writewatch)
                set_page_vprot_exec_write_protect( base, size );
            else
                set_page_vprot_bits( base, size, VPROT_WRITEWATCH, 0 );
            mprotect_range( base, size, 0, 0 );
        }
        *granularity = page_size;
    }
    else status = STATUS_INVALID_PARAMETER;

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *             NtResetWriteWatch   (NTDLL.@)
 *             ZwResetWriteWatch   (NTDLL.@)
 */
NTSTATUS WINAPI NtResetWriteWatch( HANDLE process, PVOID base, SIZE_T size )
{
    macrunner_ww_note( "reset", &macrunner_ww_reset );
    NTSTATUS status = STATUS_SUCCESS;
    sigset_t sigset;
    char *end;

    if (!round_size_checked( (UINT_PTR)base, size, page_mask, &size ))
        return STATUS_INVALID_PARAMETER;
    base = ROUND_ADDR( base, page_mask );
    if (size > ~(SIZE_T)0 - (UINT_PTR)base) return STATUS_INVALID_PARAMETER;
    end = (char *)base + size;

    TRACE( "%p %p-%p\n", process, base, end );

    if (!size) return STATUS_INVALID_PARAMETER;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    if (is_write_watch_range( base, size ))
        reset_write_watches( base, size );
    else
        status = STATUS_INVALID_PARAMETER;

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *             NtReadVirtualMemory   (NTDLL.@)
 *             ZwReadVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtReadVirtualMemory( HANDLE process, const void *addr, void *buffer,
                                     SIZE_T size, SIZE_T *bytes_read )
{
    unsigned int status;

    if (!virtual_check_buffer_for_write( buffer, size ))
    {
        status = STATUS_ACCESS_VIOLATION;
        size = 0;
    }
    else if (process == GetCurrentProcess())
    {
#if defined(__APPLE__) && defined(__aarch64__)
        /* MacRunner 2026-08-27 — СПРОСИТЬ ПРАВА, А НЕ УЗНАВАТЬ ЧЕРЕЗ ОТКАЗ.
         *
         * Замер Heroes III: восемь отказов SIGBUS, все читающие (esr=0x92000007, DFSC=0x07 —
         * страницы нет), адреса идут вниз ровно по странице — гость сканирует память и
         * заходит за конец образа. Каждый такой отказ стоит входа в ядро, обработчика и
         * разбора, а ответ известен заранее: читать оттуда нечего.
         *
         * __TRY/__EXCEPT ниже возвращает верный STATUS_PARTIAL_COPY, но узнаёт об этом
         * дорогим путём. Спрашиваем у ядра права до чтения: одна проверка вместо отказа.
         * При любой неясности идём прежней дорогой — поведение не меняется, меняется цена.
         *
         * Гейт MACRUNNER_HB_READ_PROBE_FIRST СНЯТ 02.09.2026: правка безусловна,
         * выключенная ветка возвращала известный дефект (scripts/гейты.py). */
        static int probe_gate = -1;

        if (probe_gate < 0)
        if (size)
        {
            mach_vm_address_t r = (mach_vm_address_t)(uintptr_t)addr;
            mach_vm_size_t rsz = 0;
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj = MACH_PORT_NULL;
            kern_return_t kr = mach_vm_region( mach_task_self(), &r, &rsz, VM_REGION_BASIC_INFO_64,
                                               (vm_region_info_t)&info, &cnt, &obj );

            if (obj != MACH_PORT_NULL) mach_port_deallocate( mach_task_self(), obj );
            if (kr == KERN_SUCCESS &&
                (r > (mach_vm_address_t)(uintptr_t)addr ||          /* область начинается позже */
                 !(info.protection & VM_PROT_READ)))                 /* или читать нельзя */
            {
                static unsigned int refused;
                unsigned int n = ++refused;

                if (n <= 8 || !(n % 256))
                    fprintf( stderr, "macrunner-hb-read-probe: n=%u addr=%p size=%zu — читать нечего,"
                             " отдаём PARTIAL_COPY без отказа\n", n, addr, (size_t)size ), fflush( stderr );
                if (bytes_read) *bytes_read = 0;
                return STATUS_PARTIAL_COPY;
            }
        }
#endif
        __TRY
        {
            memmove( buffer, addr, size );
            status = STATUS_SUCCESS;
        }
        __EXCEPT
        {
            status = STATUS_PARTIAL_COPY;
            size = 0;
        }
        __ENDTRY
    }
    else
    {
        /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1305 — ВХОД И ВЫХОД ЧТЕНИЯ ЧУЖОЙ ПАМЯТИ.
         *
         * Замер 1304: с перенесённым PEB32 набор `wow64_test` встаёт СРАЗУ ПОСЛЕ успешного
         * `NtDebugActiveProcess` (зонд напечатал `ВХОД` и `ВЫХОД ret=0x0`, и больше в журнале
         * не появилось ничего). Следующий оператор теста — `ReadProcessMemory` по PEB только что
         * присоединённого ребёнка, то есть ЭТА ветвь: чтение идёт через сервер, а тому для
         * чтения надо остановить цель.
         *
         * Печатей две по той же причине, что и в `NtDebugActiveProcess`: при зависании печать
         * результата не появляется никогда, и «нет строки» неотличимо от «вызова не было».
         * Ограничение — первые 200 вызовов, только МЕЖПРОЦЕССНАЯ ветвь (своя память читается
         * `memmove` выше и в счёт не идёт).
         *
         * ПОЧЕМУ 200, А НЕ 8 (итерация 1305, поймано на себе): с пределом 8 зонд напечатал ровно
         * 8 входов и 8 выходов и замолчал ЗАДОЛГО до интересного места. Отсутствие строки после
         * присоединения отладчика тогда означало не «чтения не было», а «квота кончилась» —
         * и по нему я чуть не объявил, что чтение не начинается. Предел, съеденный до окна
         * наблюдения, превращает зонд в источник ложных выводов. */
        { static int said_in; if (said_in++ < 200)
            fprintf( stderr, "macrunner-hb-xread: ВХОД process=%p addr=%p size=%llu\n",
                     process, addr, (unsigned long long)size ), fflush( stderr ); }

        SERVER_START_REQ( read_process_memory )
        {
            req->handle = wine_server_obj_handle( process );
            req->addr   = wine_server_client_ptr( addr );
            wine_server_set_reply( req, buffer, size );
            status = wine_server_call( req );
            size = status ? 0 : wine_server_reply_size( reply );
        }
        SERVER_END_REQ;

        { static int said_out; if (said_out++ < 200)
            fprintf( stderr, "macrunner-hb-xread: ВЫХОД status=0x%x прочитано=%llu\n",
                     status, (unsigned long long)size ), fflush( stderr ); }
    }
    if (bytes_read) *bytes_read = size;
    return status;
}

#ifdef __APPLE__
static int is_apple_silicon(void)
{
    static int apple_silicon_status, did_check = 0;
    if (!did_check)
    {
        /* returns 0 for native process or on error, 1 for translated */
        int ret = 0;
        size_t size = sizeof(ret);
        if (sysctlbyname( "sysctl.proc_translated", &ret, &size, NULL, 0 ) == -1)
            apple_silicon_status = 0;
        else
            apple_silicon_status = ret;

        did_check = 1;
    }

    return apple_silicon_status;
}

/* CW HACK 18947
 * If mach_vm_write() is used to modify code cross-process (which is how we implement
 * NtWriteVirtualMemory), Rosetta won't notice the change and will execute the "old" code.
 *
 * To work around this, after the write completes,
 * toggle the executable bit (from inside the target process) on/off for any executable
 * pages that were modified, to force Rosetta to re-translate it.
 */
static void toggle_executable_pages_for_rosetta( HANDLE process, void *addr, SIZE_T size )
{
    MEMORY_BASIC_INFORMATION info;
    NTSTATUS status;
    SIZE_T ret;

    if (!is_apple_silicon())
        return;

    status = NtQueryVirtualMemory( process, addr, MemoryBasicInformation, &info, sizeof(info), &ret );

    if (!status && (info.AllocationProtect & 0xf0))
    {
        DWORD origprot, noexec;
        noexec = info.AllocationProtect & ~0xf0;
        if (!noexec) noexec = PAGE_NOACCESS;

        NtProtectVirtualMemory( process, &addr, &size, noexec, &origprot );
        NtProtectVirtualMemory( process, &addr, &size, origprot, &noexec );
    }
}
#endif

/***********************************************************************
 *             NtWriteVirtualMemory   (NTDLL.@)
 *             ZwWriteVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtWriteVirtualMemory( HANDLE process, void *addr, const void *buffer,
                                      SIZE_T size, SIZE_T *bytes_written )
{
    unsigned int status;

    if (virtual_check_buffer_for_read( buffer, size ))
    {
        SERVER_START_REQ( write_process_memory )
        {
            req->handle     = wine_server_obj_handle( process );
            req->addr       = wine_server_client_ptr( addr );
            wine_server_add_data( req, buffer, size );
            status = wine_server_call( req );
            size = status ? 0 : reply->written;
        }
        SERVER_END_REQ;

#ifdef __APPLE__
        toggle_executable_pages_for_rosetta( process, addr, size );
#endif
    }
    else
    {
        status = STATUS_PARTIAL_COPY;
        size = 0;
    }
    if (bytes_written) *bytes_written = size;
    return status;
}


/***********************************************************************
 *             NtAreMappedFilesTheSame   (NTDLL.@)
 *             ZwAreMappedFilesTheSame   (NTDLL.@)
 */
NTSTATUS WINAPI NtAreMappedFilesTheSame(PVOID addr1, PVOID addr2)
{
    struct file_view *view1, *view2;
    unsigned int status;
    sigset_t sigset;

    TRACE("%p %p\n", addr1, addr2);

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    view1 = find_view( addr1, 0 );
    view2 = find_view( addr2, 0 );

    if (!view1 || !view2)
        status = STATUS_INVALID_ADDRESS;
    else if (is_view_valloc( view1 ) || is_view_valloc( view2 ))
        status = STATUS_CONFLICTING_ADDRESSES;
    else if (view1 == view2)
        status = STATUS_SUCCESS;
    else if ((view1->protect & VPROT_SYSTEM) || (view2->protect & VPROT_SYSTEM))
        status = STATUS_NOT_SAME_DEVICE;
    else
    {
        SERVER_START_REQ( is_same_mapping )
        {
            req->base1 = wine_server_client_ptr( view1->base );
            req->base2 = wine_server_client_ptr( view2->base );
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
    }

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


static NTSTATUS prefetch_memory( HANDLE process, ULONG_PTR count,
                                 PMEMORY_RANGE_ENTRY addresses, ULONG flags )
{
    ULONG_PTR i;
    PVOID base;
    SIZE_T size;
    static unsigned int once;

    if (!once++)
    {
        FIXME( "(process=%p,flags=%u) NtSetInformationVirtualMemory(VmPrefetchInformation) partial stub\n",
                process, flags );
    }

    for (i = 0; i < count; i++)
    {
        SIZE_T size;

        if (!addresses[i].NumberOfBytes ||
            !round_size_checked( (UINT_PTR)addresses[i].VirtualAddress,
                                 addresses[i].NumberOfBytes, host_page_mask, &size ))
            return STATUS_INVALID_PARAMETER_4;
    }

    if (process != NtCurrentProcess()) return STATUS_SUCCESS;

    for (i = 0; i < count; i++)
    {
        base = ROUND_ADDR( addresses[i].VirtualAddress, host_page_mask );
        if (!round_size_checked( (UINT_PTR)addresses[i].VirtualAddress,
                                 addresses[i].NumberOfBytes, host_page_mask, &size ))
            return STATUS_INVALID_PARAMETER_4;
        madvise( base, size, MADV_WILLNEED );
    }

    return STATUS_SUCCESS;
}

static NTSTATUS set_dirty_state_information( ULONG_PTR count, MEMORY_RANGE_ENTRY *addresses )
{
    ULONG_PTR i;
    sigset_t sigset;
    NTSTATUS ret = STATUS_SUCCESS;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    for (i = 0; i < count; i++)
    {
        void *base = ROUND_ADDR( addresses[i].VirtualAddress, page_mask );
        SIZE_T size;
        struct file_view *view;

        if (!round_size_checked( (UINT_PTR)addresses[i].VirtualAddress,
                                 addresses[i].NumberOfBytes, page_mask, &size ))
        {
            ret = STATUS_INVALID_PARAMETER_4;
            break;
        }
        view = find_view( base, size );

        if (!view)
        {
            ret = STATUS_MEMORY_NOT_ALLOCATED;
            break;
        }
        if (use_kernel_writewatch) reset_write_watches( base, size );
        else if (set_page_vprot_exec_write_protect( base, size ))
            mprotect_range( base, size, 0, 0 );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}

/***********************************************************************
 *           NtSetInformationVirtualMemory   (NTDLL.@)
 *           ZwSetInformationVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetInformationVirtualMemory( HANDLE process,
                                               VIRTUAL_MEMORY_INFORMATION_CLASS info_class,
                                               ULONG_PTR count, PMEMORY_RANGE_ENTRY addresses,
                                               PVOID ptr, ULONG size )
{
    TRACE("(%p, info_class=%d, %lu, %p, %p, %u)\n",
          process, info_class, count, addresses, ptr, size);

    switch (info_class)
    {
    case VmPrefetchInformation:
        if (!ptr) return STATUS_INVALID_PARAMETER_5;
        if (size != sizeof(ULONG)) return STATUS_INVALID_PARAMETER_6;
        if (!count) return STATUS_INVALID_PARAMETER_3;
        if (!addresses) return STATUS_ACCESS_VIOLATION;
        return prefetch_memory( process, count, addresses, *(ULONG *)ptr );

    case VmPageDirtyStateInformation:
        if (process != GetCurrentProcess()) return STATUS_NOT_SUPPORTED;
        if (!enable_write_exceptions) return STATUS_NOT_SUPPORTED;
        if (!ptr) return STATUS_INVALID_PARAMETER_5;
        if (size != sizeof(ULONG)) return STATUS_INVALID_PARAMETER_6;
        if (*(ULONG *)ptr) return STATUS_INVALID_PARAMETER_5;
        if (!count) return STATUS_INVALID_PARAMETER_3;
        if (!addresses) return STATUS_ACCESS_VIOLATION;
        return set_dirty_state_information( count, addresses );

    default:
        FIXME("(%p,info_class=%d,%lu,%p,%p,%u) Unknown information class\n",
              process, info_class, count, addresses, ptr, size);
        return STATUS_INVALID_PARAMETER_2;
    }
}


/**********************************************************************
 *           NtFlushInstructionCache  (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushInstructionCache( HANDLE handle, const void *addr, SIZE_T size )
{
#if defined(__x86_64__) || defined(__i386__)
    /* no-op */
#elif defined(HAVE___CLEAR_CACHE)
    if (handle == GetCurrentProcess())
    {
        if (size > ~(SIZE_T)0 - (UINT_PTR)addr) return STATUS_INVALID_PARAMETER;
        __clear_cache( (char *)addr, (char *)addr + size );
    }
    else
    {
        static int once;
        if (!once++) FIXME( "%p %p %ld other process not supported\n", handle, addr, size );
    }
#else
    static int once;
    if (!once++) FIXME( "%p %p %ld\n", handle, addr, size );
#endif
    return STATUS_SUCCESS;
}


#ifdef __APPLE__

static kern_return_t (*p_thread_get_register_pointer_values)( thread_t, uintptr_t*, size_t*, uintptr_t* );
static pthread_once_t tgrpvs_init_once = PTHREAD_ONCE_INIT;

static void tgrpvs_init(void)
{
    p_thread_get_register_pointer_values = dlsym( RTLD_DEFAULT, "thread_get_register_pointer_values" );
    if (!p_thread_get_register_pointer_values)
        FIXME( "thread_get_register_pointer_values not supported for NtFlushProcessWriteBuffers\n" );
}

/**********************************************************************
 *           NtFlushProcessWriteBuffers  (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushProcessWriteBuffers(void)
{
    /* Taken from https://github.com/dotnet/runtime/blob/7be37908e5a1cbb83b1062768c1649827eeaceaa/src/coreclr/pal/src/thread/process.cpp#L2799 */
    mach_msg_type_number_t count, i;
    thread_act_array_t threads;

    pthread_once( &tgrpvs_init_once, tgrpvs_init );
    if (!p_thread_get_register_pointer_values) return STATUS_SUCCESS;

    /* Get references to all threads of this process */
    if (task_threads( mach_task_self(), &threads, &count )) return STATUS_SUCCESS;

    for (i = 0; i < count; i++)
    {
        uintptr_t reg_values[128];
        size_t reg_count = ARRAY_SIZE( reg_values );
        uintptr_t sp;

        /* Request the thread's register pointer values to force the thread to go through a memory barrier */
        p_thread_get_register_pointer_values( threads[i], &sp, &reg_count, reg_values );
        mach_port_deallocate( mach_task_self(), threads[i] );
    }
    vm_deallocate( mach_task_self(), (vm_address_t)threads, count * sizeof(threads[0]) );
    return STATUS_SUCCESS;
}

#elif defined(__linux__) && defined(__NR_membarrier)

#define MEMBARRIER_CMD_PRIVATE_EXPEDITED            0x08
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED   0x10

static pthread_once_t membarrier_init_once = PTHREAD_ONCE_INIT;

static int membarrier( int cmd, unsigned int flags, int cpu_id )
{
    return syscall( __NR_membarrier, cmd, flags, cpu_id );
}

static void membarrier_init(void)
{
    if (membarrier( MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0 ))
        FIXME( "membarrier not supported for NtFlushProcessWriteBuffers\n" );
}

/**********************************************************************
 *           NtFlushProcessWriteBuffers  (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushProcessWriteBuffers(void)
{
    pthread_once( &membarrier_init_once, membarrier_init );
    membarrier( MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0 );
    return STATUS_SUCCESS;
}

#else /* __linux__ */

/**********************************************************************
 *           NtFlushProcessWriteBuffers  (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushProcessWriteBuffers(void)
{
    static int once = 0;
    if (!once++) FIXME( "stub\n" );
    return STATUS_SUCCESS;
}

#endif

/**********************************************************************
 *           NtCreatePagingFile  (NTDLL.@)
 */
NTSTATUS WINAPI NtCreatePagingFile( UNICODE_STRING *name, LARGE_INTEGER *min_size,
                                    LARGE_INTEGER *max_size, LARGE_INTEGER *actual_size )
{
    FIXME( "(%s %p %p %p) stub\n", debugstr_us(name), min_size, max_size, actual_size );
    return STATUS_SUCCESS;
}

#ifndef _WIN64

/***********************************************************************
 *             NtWow64AllocateVirtualMemory64   (NTDLL.@)
 *             ZwWow64AllocateVirtualMemory64   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64AllocateVirtualMemory64( HANDLE process, ULONG64 *ret, ULONG64 zero_bits,
                                                ULONG64 *size_ptr, ULONG type, ULONG protect )
{
    void *base;
    SIZE_T size;
    unsigned int status;

    if (!ret || !size_ptr) return STATUS_ACCESS_VIOLATION;

    TRACE("%p %s %s %x %08x\n", process,
          wine_dbgstr_longlong(*ret), wine_dbgstr_longlong(*size_ptr), type, protect );

    if (!*size_ptr) return STATUS_INVALID_PARAMETER_4;
    if (zero_bits > 21 && zero_bits < 32) return STATUS_INVALID_PARAMETER_3;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_alloc.type         = APC_VIRTUAL_ALLOC;
        call.virtual_alloc.addr         = *ret;
        call.virtual_alloc.size         = *size_ptr;
        call.virtual_alloc.zero_bits    = zero_bits;
        call.virtual_alloc.op_type      = type;
        call.virtual_alloc.prot         = protect;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_alloc.status == STATUS_SUCCESS)
        {
            *ret      = result.virtual_alloc.addr;
            *size_ptr = result.virtual_alloc.size;
        }
        return result.virtual_alloc.status;
    }

    base = (void *)(ULONG_PTR)*ret;
    size = *size_ptr;
    if ((ULONG_PTR)base != *ret) return STATUS_CONFLICTING_ADDRESSES;
    if (size != *size_ptr) return STATUS_WORKING_SET_LIMIT_RANGE;

    status = NtAllocateVirtualMemory( process, &base, zero_bits, &size, type, protect );
    if (!status)
    {
        *ret = (ULONG_PTR)base;
        *size_ptr = size;
    }
    return status;
}


/***********************************************************************
 *             NtWow64ReadVirtualMemory64   (NTDLL.@)
 *             ZwWow64ReadVirtualMemory64   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64ReadVirtualMemory64( HANDLE process, ULONG64 addr, void *buffer,
                                            ULONG64 size, ULONG64 *bytes_read )
{
    unsigned int status;

    if (size > MAXLONG) size = MAXLONG;

    if (virtual_check_buffer_for_write( buffer, size ))
    {
        SERVER_START_REQ( read_process_memory )
        {
            req->handle = wine_server_obj_handle( process );
            req->addr   = addr;
            wine_server_set_reply( req, buffer, size );
            status = wine_server_call( req );
            size = status ? 0 : wine_server_reply_size( reply );
        }
        SERVER_END_REQ;
    }
    else
    {
        status = STATUS_ACCESS_VIOLATION;
        size = 0;
    }
    if (bytes_read) *bytes_read = size;
    return status;
}


/***********************************************************************
 *             NtWow64WriteVirtualMemory64   (NTDLL.@)
 *             ZwWow64WriteVirtualMemory64   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64WriteVirtualMemory64( HANDLE process, ULONG64 addr, const void *buffer,
                                             ULONG64 size, ULONG64 *bytes_written )
{
    unsigned int status;

    if (size > MAXLONG) size = MAXLONG;

    if (virtual_check_buffer_for_read( buffer, size ))
    {
        SERVER_START_REQ( write_process_memory )
        {
            req->handle     = wine_server_obj_handle( process );
            req->addr       = addr;
            wine_server_add_data( req, buffer, size );
            status = wine_server_call( req );
            size = status ? 0 : reply->written;
        }
        SERVER_END_REQ;
    }
    else
    {
        status = STATUS_PARTIAL_COPY;
        size = 0;
    }
    if (bytes_written) *bytes_written = size;
    return status;
}


/***********************************************************************
 *             NtWow64GetNativeSystemInformation   (NTDLL.@)
 *             ZwWow64GetNativeSystemInformation   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64GetNativeSystemInformation( SYSTEM_INFORMATION_CLASS class, void *info,
                                                   ULONG len, ULONG *retlen )
{
    NTSTATUS status;

    switch (class)
    {
    case SystemCpuInformation:
        status = NtQuerySystemInformation( class, info, len, retlen );
        if (!status && is_old_wow64())
        {
            SYSTEM_CPU_INFORMATION *cpu = info;

            if (cpu->ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
                cpu->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
        }
        return status;
    case SystemBasicInformation:
    case SystemEmulationBasicInformation:
    case SystemEmulationProcessorInformation:
        return NtQuerySystemInformation( class, info, len, retlen );
    case SystemNativeBasicInformation:
        return NtQuerySystemInformation( SystemBasicInformation, info, len, retlen );
    default:
        if (is_old_wow64()) return STATUS_INVALID_INFO_CLASS;
        return NtQuerySystemInformation( class, info, len, retlen );
    }
}

/***********************************************************************
 *             NtWow64IsProcessorFeaturePresent   (NTDLL.@)
 *             ZwWow64IsProcessorFeaturePresent   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64IsProcessorFeaturePresent( UINT feature )
{
    return feature < PROCESSOR_FEATURE_MAX && user_shared_data->ProcessorFeatures[feature];
}

#endif  /* _WIN64 */
