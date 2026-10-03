/*
 * Unix interface for loader functions
 *
 * Copyright (C) 2020 Alexandre Julliard
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
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <spawn.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dlfcn.h>
#ifdef HAVE_PWD_H
# include <pwd.h>
#endif
#ifdef HAVE_ELF_H
# include <elf.h>
#endif
#ifdef HAVE_LINK_H
# include <link.h>
#endif
#ifdef HAVE_SYS_AUXV_H
# include <sys/auxv.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif
#include <limits.h>
#ifdef HAVE_SYS_SYSCTL_H
# include <sys/sysctl.h>
#endif
#ifdef __APPLE__
# include <CoreFoundation/CoreFoundation.h>
# define LoadResource MacLoadResource
# define GetCurrentThread MacGetCurrentThread
# include <CoreServices/CoreServices.h>
# undef LoadResource
# undef GetCurrentThread
# include <pthread.h>
# include <mach/mach.h>
# include <mach/mach_error.h>
# include <mach-o/getsect.h>
# include <crt_externs.h>
# ifndef _POSIX_SPAWN_DISABLE_ASLR
#  define _POSIX_SPAWN_DISABLE_ASLR 0x0100
# endif
# define environ (*_NSGetEnviron())
#else
  extern char **environ;
#endif
#ifdef __ANDROID__
# include <jni.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "winbase.h"
#include "winnls.h"
#include "winioctl.h"
#include "winternl.h"
#include "unix_private.h"
#include "msync.h"
#include "wine/list.h"
#include "ntsyscalls.h"
#include "wine/debug.h"
#include "../../../../hyperbridge/include/hb_memory.h"
#include "../../../../hyperbridge/include/hb_runtime.h"

WINE_DEFAULT_DEBUG_CHANNEL(module);
WINE_DECLARE_DEBUG_CHANNEL(syscall);

#if defined __i386__ || defined __x86_64__
#define SO_DLLS_SUPPORTED
#endif

void *pDbgUiRemoteBreakin = NULL;
void *pKiRaiseUserExceptionDispatcher = NULL;
void *pKiUserExceptionDispatcher = NULL;
void *pKiUserApcDispatcher = NULL;
void *pKiUserCallbackDispatcher = NULL;
void *pKiUserEmulationDispatcher = NULL;
void *pLdrInitializeThunk = NULL;
void *pRtlUserThreadStart = NULL;
void *p__wine_ctrl_routine = NULL;
SYSTEM_DLL_INIT_BLOCK *pLdrSystemDllInitBlock = NULL;

extern typeof(NtReadFile) __wine_rpc_NtReadFile;
extern void macrunner_hb_register_x64_original_exec_sections( void *module, const IMAGE_NT_HEADERS *nt );
extern void macrunner_hb_init_environment( void );

static void stub_syscall( const char *name )
{
    CONTEXT context = { .ContextFlags = CONTEXT_FULL };
    EXCEPTION_RECORD rec =
    {
        .ExceptionCode = EXCEPTION_WINE_STUB,
        .ExceptionFlags = EXCEPTION_NONCONTINUABLE,
        .NumberParameters = 2,
        .ExceptionInformation[0] = (ULONG_PTR)"ntdll",
        .ExceptionInformation[1] = (ULONG_PTR)name,
    };
    NtGetContextThread( GetCurrentThread(), &context );
#ifdef __i386__
    rec.ExceptionAddress = (void *)context.Eip;
#elif defined __x86_64__
    rec.ExceptionAddress = (void *)context.Rip;
#elif defined __arm__ || defined __aarch64__
    rec.ExceptionAddress = (void *)context.Pc;
#endif
    NtRaiseException( &rec, &context, TRUE );
}


#define SYSCALL_STUB(name) static void name(void) { stub_syscall( #name ); }
ALL_SYSCALL_STUBS

#if defined(__APPLE__) && defined(__aarch64__)
/* The syscall dispatcher supplies eight-byte Windows stack slots. Darwin C
 * packs narrow stack arguments; adapt only the syscall-table boundary. */
static NTSTATUS macrunner_notify_key_slots( HANDLE key, HANDLE event, PIO_APC_ROUTINE apc,
                                            void *context, IO_STATUS_BLOCK *io, ULONG filter,
                                            BOOLEAN subtree, void *buffer,
                                            ULONG_PTR length, ULONG_PTR async )
{
    return NtNotifyChangeKey( key, event, apc, context, io, filter, subtree,
                              buffer, (ULONG)length, (BOOLEAN)async );
}

static NTSTATUS macrunner_notify_keys_slots( HANDLE key, ULONG count, OBJECT_ATTRIBUTES *attr,
                                             HANDLE event, PIO_APC_ROUTINE apc, void *context,
                                             IO_STATUS_BLOCK *io, ULONG filter,
                                             ULONG_PTR subtree, void *buffer,
                                             ULONG_PTR length, ULONG_PTR async )
{
    return NtNotifyChangeMultipleKeys( key, count, attr, event, apc, context, io, filter,
                                       (BOOLEAN)subtree, buffer, (ULONG)length, (BOOLEAN)async );
}
#define NtNotifyChangeKey macrunner_notify_key_slots
#define NtNotifyChangeMultipleKeys macrunner_notify_keys_slots
#endif

static void * const syscalls[] =
{
#define SYSCALL_ENTRY(id,name,args) name,
    ALL_SYSCALLS
#undef SYSCALL_ENTRY
};

#if defined(__APPLE__) && defined(__aarch64__)
#undef NtNotifyChangeKey
#undef NtNotifyChangeMultipleKeys
#endif

static BYTE syscall_args[ARRAY_SIZE(syscalls)] =
{
#define SYSCALL_ENTRY(id,name,args) args,
    ALL_SYSCALLS
#undef SYSCALL_ENTRY
};

__attribute__((visibility("default")))  /* CW Hack 24067 */
SYSTEM_SERVICE_TABLE KeServiceDescriptorTable[4] =
{
    { (ULONG_PTR *)syscalls, NULL, ARRAY_SIZE(syscalls), syscall_args }
};

static const char *ntsyscall_names[] =
{
#define SYSCALL_ENTRY(id,name,args) #name,
    ALL_SYSCALLS
#undef SYSCALL_ENTRY
};

static const char **syscall_names[4] = { ntsyscall_names };
static const char **usercall_names;

void ntdll_add_syscall_debug_info( UINT idx, const char **names, const char **user_names )
{
    syscall_names[idx] = names;
    usercall_names = user_names;
}

#ifdef __GNUC__
static void fatal_error( const char *err, ... ) __attribute__((noreturn, format(printf,1,2)));
#endif

static const char *bin_dir;
static const char *dll_dir;
static const char *ntdll_dir;
static const char *alt_build_dir;
static SIZE_T dll_path_maxlen;

const char *home_dir = NULL;
const char *data_dir = NULL;
const char *build_dir = NULL;
const char *config_dir = NULL;
const char *wineloader = NULL;
const char **dll_paths = NULL;
const char **system_dll_paths = NULL;
const char *user_name = NULL;
SECTION_IMAGE_INFORMATION main_image_info = { NULL };
BOOL macrunner_hb_x64_loader = FALSE;

/* die on a fatal error; use only during initialization */
static void fatal_error( const char *err, ... )
{
    va_list args;

    va_start( args, err );
    fprintf( stderr, "wine: " );
    vfprintf( stderr, err, args );
    va_end( args );
    exit(1);
}

static void set_max_limit( int limit )
{
    struct rlimit rlimit;

    if (!getrlimit( limit, &rlimit ))
    {
        rlimit.rlim_cur = rlimit.rlim_max;
        if (!setrlimit( limit, &rlimit )) return;
#ifdef __APPLE__
        if (limit == RLIMIT_NOFILE)
        {
            /* macOS before Big Sur fails if rlim_max is larger than maxfilesperproc */
            unsigned int nlimit = 0;
            size_t size = sizeof(nlimit);
            sysctlbyname("kern.maxfilesperproc", &nlimit, &size, NULL, 0);
            rlimit.rlim_cur = max( nlimit, OPEN_MAX );
            if (!setrlimit( RLIMIT_NOFILE, &rlimit )) return;
        }
#endif
        WARN("Failed to raise limit %d\n", limit);
    }
}

/* canonicalize path and return its directory name */
static char *realpath_dirname( const char *name )
{
    char *p, *fullpath = realpath( name, NULL );

    if (fullpath)
    {
        p = strrchr( fullpath, '/' );
        if (p == fullpath) p++;
        if (p) *p = 0;
    }
    return fullpath;
}

/* if string ends with tail, remove it */
static char *remove_tail( const char *str, const char *tail )
{
    size_t len = strlen( str );
    size_t tail_len = strlen( tail );
    char *ret;

    if (len < tail_len) return NULL;
    if (strcmp( str + len - tail_len, tail )) return NULL;
    if (!(ret = malloc( len - tail_len + 1 ))) fatal_error( "out of memory building loader path\n" );
    memcpy( ret, str, len - tail_len );
    ret[len - tail_len] = 0;
    return ret;
}

/* build a path from the specified dir and name */
static char *build_path( const char *dir, const char *name )
{
    size_t len = strlen( dir );
    size_t name_len = strlen( name );
    char *ret;

    if (len)
    {
        if (name[0] == '/') name++;
        name_len = strlen( name );
    }
    if (name_len > ~(size_t)0 - 2 || len > ~(size_t)0 - name_len - 2)
        fatal_error( "loader path too long\n" );
    if (!(ret = malloc( len + name_len + 2 ))) fatal_error( "out of memory building loader path\n" );

    if (len)
    {
        memcpy( ret, dir, len );
        if (ret[len - 1] != '/') ret[len++] = '/';
    }
    strcpy( ret + len, name );
    return ret;
}

/* build a path with the relative dir from 'from' to 'dest' appended to base */
static char *build_relative_path( const char *base, const char *from, const char *dest )
{
    const char *start;
    char *ret;
    size_t base_len, start_len, alloc_size;
    unsigned int dotdots = 0;

    for (;;)
    {
        while (*from == '/') from++;
        while (*dest == '/') dest++;
        start = dest;  /* save start of next path element */
        if (!*from) break;

        while (*from && *from != '/' && *from == *dest) { from++; dest++; }
        if ((!*from || *from == '/') && (!*dest || *dest == '/')) continue;

        do  /* count remaining elements in 'from' */
        {
            dotdots++;
            while (*from && *from != '/') from++;
            while (*from == '/') from++;
        }
        while (*from);
        break;
    }

    base_len = strlen( base );
    start_len = strlen( start );
    if (start_len > ~(size_t)0 - 2 || base_len > ~(size_t)0 - start_len - 2 ||
        dotdots > (~(size_t)0 - base_len - start_len - 2) / 3)
        fatal_error( "loader path too long\n" );
    alloc_size = base_len + 3 * dotdots + start_len + 2;
    if (!(ret = malloc( alloc_size )))
        fatal_error( "out of memory building loader path\n" );
    strcpy( ret, base );
    while (dotdots--) strcat( ret, "/.." );

    if (!start[0]) return ret;
    strcat( ret, "/" );
    strcat( ret, start );
    return ret;
}

/* build a path to a binary and exec it */
static int build_path_and_exec( pid_t *pid, const char *dir, const char *name, char **argv )
{
    int ret;

    argv[0] = build_path( dir, name );
    ret = posix_spawn( pid, argv[0], NULL, NULL, argv, environ );
    free( argv[0] );
    return ret;
}


static const char *get_so_dir( WORD machine )
{
    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:  return "/i386-unix";
    case IMAGE_FILE_MACHINE_AMD64: return "/x86_64-unix";
    case IMAGE_FILE_MACHINE_ARMNT: return "/arm-unix";
    case IMAGE_FILE_MACHINE_ARM64: return "/aarch64-unix";
    default: return "";
    }
}

static const char *get_pe_dir( WORD machine )
{
    switch(machine)
    {
    case IMAGE_FILE_MACHINE_I386:  return "/i386-windows";
    case IMAGE_FILE_MACHINE_AMD64: return "/x86_64-windows";
    case IMAGE_FILE_MACHINE_ARMNT: return "/arm-windows";
    case IMAGE_FILE_MACHINE_ARM64: return "/aarch64-windows";
    default: return "";
    }
}

static BOOL macrunner_hb_x64_loader_enabled(void)
{
    const char *enabled = getenv( "MACRUNNER_HB_X64_LOADER" );

    return enabled && enabled[0] && enabled[0] != '0' && strcasecmp( enabled, "false" );
}

static BOOL macrunner_hb_unicode_basename_matches_ascii( const UNICODE_STRING *path, const char *name )
{
    unsigned int i, base = 0, len;
    size_t name_len = strlen( name );

    if (!path || !path->Buffer) return FALSE;
    len = path->Length / sizeof(WCHAR);
    for (i = 0; i < len; i++)
        if (path->Buffer[i] == '/' || path->Buffer[i] == '\\') base = i + 1;
    if (len - base != name_len) return FALSE;

    for (i = 0; i < name_len; i++)
    {
        WCHAR a = path->Buffer[base + i];
        char b = name[i];

        if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
        if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
        if (a > 127 || (char)a != b) return FALSE;
    }
    return TRUE;
}

static BOOL macrunner_hb_ansi_name_matches_ascii( const ANSI_STRING *string, const char *name )
{
    size_t len = strlen( name );

    return string && string->Buffer && string->Length == len && !strncasecmp( string->Buffer, name, len );
}

static BOOL macrunner_hb_builtin_name_matches( const UNICODE_STRING *nt_name, const ANSI_STRING *exp_name,
                                               const char *name )
{
    return macrunner_hb_ansi_name_matches_ascii( exp_name, name ) ||
           macrunner_hb_unicode_basename_matches_ascii( nt_name, name );
}

static BOOL macrunner_hb_is_wow64_host_builtin( const UNICODE_STRING *nt_name, const ANSI_STRING *exp_name )
{
    return macrunner_hb_builtin_name_matches( nt_name, exp_name, "wow64.dll" ) ||
           macrunner_hb_builtin_name_matches( nt_name, exp_name, "wow64win.dll" ) ||
           macrunner_hb_builtin_name_matches( nt_name, exp_name, "wow64cpu.dll" ) ||
           macrunner_hb_builtin_name_matches( nt_name, exp_name, "xtajit.dll" ) ||
           macrunner_hb_builtin_name_matches( nt_name, exp_name, "xtajit64.dll" ) ||
           macrunner_hb_builtin_name_matches( nt_name, exp_name, "win32u.dll" );
}

/***********************************************************************
 *  MACRUNNER_CPU_BACKEND — процессный выбор транслятора (лейн FEX-N3, 07.09.2026)
 *
 * Значения:
 *   hb   (или переменная не задана) — прежнее поведение: CPU-модули xtajit/xtajit64
 *        несут HyperBridge, перехваты загрузчика HB работают как раньше;
 *   fex  — CPU-модули берутся из overlay (PE + нативный спутник одной парой),
 *        перехваты HyperBridge в ЗАГРУЗЧИКЕ выключаются принудительно, даже если
 *        MACRUNNER_HB_X64_LOADER=1 в окружении;
 *   none — ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: загрузка любого CPU-модуля отвергается
 *        (STATUS_DLL_NOT_FOUND). Нужен, чтобы доказать, что smoke зависит от
 *        backend-а, а не проходит сам по себе на HB.
 *
 * Любое другое значение — fatal_error: тихий откат на HB это ровно тот класс
 * ошибки («гейт выключен, а мерили как включённый»), ради которого правило писано.
 *
 * Читается ОДИН раз из macrunner_hb_init_flags(), то есть до инициализации CPU:
 * оба вызова (loader.c ~3193 в unix-старте и ~3482 в __wine_main) стоят раньше,
 * чем грузится ntdll.dll и тем более чем wow64 берёт CPU-модуль.
 */
enum macrunner_cpu_backend
{
    MACRUNNER_CPU_BACKEND_HB = 0,
    MACRUNNER_CPU_BACKEND_FEX,
    MACRUNNER_CPU_BACKEND_NONE,
};

static enum macrunner_cpu_backend macrunner_cpu_backend = MACRUNNER_CPU_BACKEND_HB;
static BOOL macrunner_cpu_backend_seen;

/* Читается из signal_arm64.c: у него СВОЯ копия macrunner_hb_x64_loader_enabled()
 * (signal_arm64.c:2081), поэтому гашение флага в этом файле до него НЕ доходит.
 * Единая точка правды — эта функция. */
BOOL macrunner_cpu_backend_disables_hb_semantics(void)
{
    return macrunner_cpu_backend != MACRUNNER_CPU_BACKEND_HB;
}

static const char *macrunner_cpu_backend_name( enum macrunner_cpu_backend backend )
{
    switch (backend)
    {
    case MACRUNNER_CPU_BACKEND_FEX:  return "fex";
    case MACRUNNER_CPU_BACKEND_NONE: return "none";
    default:                         return "hb";
    }
}

/* имена CPU-модулей задаются реестром HKLM\Software\Microsoft\Wow64\<арх>
 * (loader/wine.inf.in:396,398) и разбираются в dlls/wow64/syscall.c:1430 */
static BOOL macrunner_is_cpu_backend_module( const UNICODE_STRING *nt_name, const ANSI_STRING *exp_name )
{
    return macrunner_hb_builtin_name_matches( nt_name, exp_name, "xtajit.dll" ) ||
           macrunner_hb_builtin_name_matches( nt_name, exp_name, "xtajit64.dll" );
}

/* ★★★ ШАГ-2 08.09.2026 — СПУТНИК FEX ОБЯЗАН НАЗЫВАТЬСЯ ИНАЧЕ, ЧЕМ СПУТНИК HyperBridge.
 *
 * ИЗМЕРЕНО (рука fex-i386 до правки, reports/SHAG2-lab/runs/arhiv, pid 59678):
 *     macrunner-fex-unixlib-abi: путь=<overlay>/aarch64-unix/xtajit.so знак=НЕТ
 *     macrunner-fex-init: шаг=7 UnixLib::Init НЕТ   -> exit=187 (0xBB)
 * То есть dlopen звали с НАШИМ путём, а знака в полученном образе не было.  Причина —
 * у обоих спутников ОДИН install_name:
 *     dist/lib/wine/aarch64-unix/xtajit.so   @rpath/xtajit.so  UUID 67AE71B2…  знака нет
 *     overlay/aarch64-unix/xtajit.so         @rpath/xtajit.so  UUID 2FF87898…  знак есть
 * dyld отдаёт уже загруженный образ с совпавшим install_name, и путь в журнале об этом
 * молчит.  N2d закрыл ТИХУЮ работу с чужой таблицей знаком; здесь закрыта сама коллизия.
 *
 * Имена взяты из таблицы раскладки Астры (20260908-ASTRA-WINE-FEX-BUILD-PLAN.md): это
 * ВНУТРЕННИЕ имена модулей FEX у upstream, поэтому совпасть с чем-то в дисте они не могут.
 * `.def` при этом НЕ переименовывается — имя PE-файла и внутреннее имя остаются прежними,
 * меняется ТОЛЬКО имя нативного спутника.
 *
 * Возврат NULL = имя не наше, спутник ищется прежним способом. */
static const char *macrunner_fex_unix_name( const char *dll_name )
{
    if (!dll_name) return NULL;
    if (!strcmp( dll_name, "xtajit.dll" ))   return "libwow64fex.so";
    if (!strcmp( dll_name, "xtajit64.dll" )) return "libarm64ecfex.so";
    return NULL;
}

static void macrunner_cpu_backend_init(void)
{
    const char *value = getenv( "MACRUNNER_CPU_BACKEND" );

    if (!value || !value[0] || !strcasecmp( value, "hb" ))
        macrunner_cpu_backend = MACRUNNER_CPU_BACKEND_HB;
    else if (!strcasecmp( value, "fex" ))
        macrunner_cpu_backend = MACRUNNER_CPU_BACKEND_FEX;
    else if (!strcasecmp( value, "none" ))
        macrunner_cpu_backend = MACRUNNER_CPU_BACKEND_NONE;
    else
        fatal_error( "macrunner-cpu-backend: неизвестное значение MACRUNNER_CPU_BACKEND=%s "
                     "(допустимы hb, fex, none)\n", value );

    macrunner_cpu_backend_seen = TRUE;

    if (macrunner_cpu_backend != MACRUNNER_CPU_BACKEND_HB)
    {
        /* перехваты HyperBridge в загрузчике: гасим до того, как их кто-то прочтёт */
        macrunner_hb_x64_loader = FALSE;
    }

    /* Безусловная печать: прибор обязан давать ненулевое на ОБЕИХ руках, иначе
     * его молчание нельзя отличить от «не дошло». */
    fprintf( stderr, "macrunner-cpu-backend: selected=%s env=%s hb_x64_loader=%d\n",
             macrunner_cpu_backend_name( macrunner_cpu_backend ),
             value ? value : "(unset)", macrunner_hb_x64_loader ? 1 : 0 );
}

static void macrunner_hb_init_flags(void)
{
    macrunner_hb_init_environment();
    hb_memory_init_environment();
    hb_runtime_init_environment();
    macrunner_hb_x64_loader = macrunner_hb_x64_loader_enabled();
    macrunner_cpu_backend_init();
}

static WORD get_alt_machine( WORD machine )
{
    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:  return IMAGE_FILE_MACHINE_AMD64;
    case IMAGE_FILE_MACHINE_AMD64: return IMAGE_FILE_MACHINE_I386;
    case IMAGE_FILE_MACHINE_ARMNT: return IMAGE_FILE_MACHINE_ARM64;
    case IMAGE_FILE_MACHINE_ARM64: return IMAGE_FILE_MACHINE_ARMNT;
    default: return machine;
    }
}

/* CW Hack 24067 */
__attribute__((visibility("default")))
void prepend_dll_path(const char *path)
{
    size_t i, count;
    const char **new_dll_paths;
    size_t path_len = strlen(path);

    for (count = 0; dll_paths[count]; count++)
        ;

    if (count > ~(size_t)0 / sizeof(*new_dll_paths) - 2)
        fatal_error( "too many DLL search paths\n" );
    if (!(new_dll_paths = calloc(count + 2, sizeof(*new_dll_paths))))
        fatal_error( "out of memory setting DLL search path\n" );
    new_dll_paths[0] = path;
    for (i = 0; dll_paths[i]; i++)
        new_dll_paths[i + 1] = dll_paths[i];

    free(dll_paths);
    dll_paths = new_dll_paths;
    if (path_len > dll_path_maxlen)
        dll_path_maxlen = path_len;
}

static void set_dll_path(void)
{
    char *p, *path = getenv( "WINEDLLPATH" );
    size_t i, count = 0;

    if (path) for (p = path, count = 1; *p; p++) if (*p == ':') count++;

    if (count > ~(size_t)0 / sizeof(*dll_paths) - 2)
        fatal_error( "too many DLL search paths\n" );
    if (!(dll_paths = malloc( (count + 2) * sizeof(*dll_paths) )))
        fatal_error( "out of memory setting DLL search path\n" );
    count = 0;

    if (!build_dir) dll_paths[count++] = dll_dir;

    if (path)
    {
        if (!(path = strdup(path))) fatal_error( "out of memory setting DLL search path\n" );
        for (p = strtok( path, ":" ); p; p = strtok( NULL, ":" ))
        {
            if (!(dll_paths[count] = strdup( p )))
                fatal_error( "out of memory setting DLL search path\n" );
            count++;
        }
        free( path );
    }

    for (i = 0; i < count; i++) dll_path_maxlen = max( dll_path_maxlen, strlen(dll_paths[i]) );
    dll_paths[count] = NULL;
}


static void set_system_dll_path(void)
{
    const char *p, *path = SYSTEMDLLPATH;
    size_t count = 0;

    if (path && *path) for (p = path, count = 1; *p; p++) if (*p == ':') count++;

    if (count > ~(size_t)0 / sizeof(*system_dll_paths) - 1)
        fatal_error( "too many system DLL search paths\n" );
    if (!(system_dll_paths = malloc( (count + 1) * sizeof(*system_dll_paths) )))
        fatal_error( "out of memory setting system DLL search path\n" );
    count = 0;

    if (path && *path)
    {
        char *path_copy;

        if (!(path_copy = strdup(path))) fatal_error( "out of memory setting system DLL search path\n" );
        for (p = strtok( path_copy, ":" ); p; p = strtok( NULL, ":" ))
        {
            if (!(system_dll_paths[count] = strdup( p )))
                fatal_error( "out of memory setting system DLL search path\n" );
            count++;
        }
        free( path_copy );
    }
    system_dll_paths[count] = NULL;
}


static void set_home_dir(void)
{
    const char *home = getenv( "HOME" );
    const char *name = getenv( "USER" );
    const char *p;

    if (!home || !name)
    {
        struct passwd *pwd = getpwuid( getuid() );
        if (pwd)
        {
            if (!home) home = pwd->pw_dir;
            if (!name) name = pwd->pw_name;
        }
        if (!name) name = "wine";
    }
    if ((p = strrchr( name, '/' ))) name = p + 1;
    if ((p = strrchr( name, '\\' ))) name = p + 1;
    if (home && !(home_dir = strdup( home ))) fatal_error( "out of memory setting home directory\n" );
    if (!(user_name = strdup( name ))) fatal_error( "out of memory setting user name\n" );
}


static void set_config_dir(void)
{
    char *p, *dir;
    const char *prefix = getenv( "WINEPREFIX" );

    if (prefix)
    {
        if (prefix[0] != '/')
            fatal_error( "invalid directory %s in WINEPREFIX: not an absolute path\n", prefix );
        if (!(config_dir = dir = strdup( prefix ))) fatal_error( "out of memory setting WINEPREFIX\n" );
        for (p = dir + strlen(dir) - 1; p > dir && *p == '/'; p--) *p = 0;
    }
    else
    {
        if (!home_dir) fatal_error( "could not determine your home directory\n" );
        if (home_dir[0] != '/') fatal_error( "the home directory %s is not an absolute path\n", home_dir );
        config_dir = build_path( home_dir, ".wine" );
    }
}

static void init_paths(void)
{
    char *wow64_path;
    Dl_info info;

    if (!dladdr( init_paths, &info ) || !(ntdll_dir = realpath_dirname( info.dli_fname )))
        fatal_error( "cannot get path to ntdll.so\n" );

    if ((build_dir = remove_tail( ntdll_dir, "/dlls/ntdll" )))
    {
        wineloader = build_path( build_dir, "loader/wine" );
        wow64_path = build_path( build_dir, "loader-wow64" );
        alt_build_dir = realpath_dirname( wow64_path );
        free( wow64_path );
    }
    else
    {
        if (!(dll_dir = remove_tail( ntdll_dir, get_so_dir(current_machine) ))) dll_dir = ntdll_dir;
        bin_dir = build_relative_path( dll_dir, LIBDIR "/wine", BINDIR );
        data_dir = build_relative_path( dll_dir, LIBDIR "/wine", DATADIR "/wine" );
        wineloader = build_path( ntdll_dir, "wine" );
    }

    set_dll_path();
    set_system_dll_path();
    set_home_dir();
    set_config_dir();
}


/***********************************************************************
 *           get_alternate_wineloader
 */
char *get_alternate_wineloader( WORD machine )
{
    const char *arch;
    BOOL force_wow64 = (arch = getenv( "WINEARCH" )) && !strcmp( arch, "wow64" );
    char *ret = NULL;

    if (is_win64)
    {
        if (force_wow64) return NULL;
        if (machine != get_alt_machine( current_machine )) return NULL;
    }
    else
    {
        if (!force_wow64 && machine == current_machine) return NULL;
        machine = get_alt_machine( current_machine );
    }

    if (!build_dir)
    {
        if (asprintf( &ret, "%s%s/wine", dll_dir, get_so_dir( machine )) < 0) return NULL;
    }
    else if (alt_build_dir && asprintf( &ret, "%s/loader/wine", alt_build_dir ) < 0) return NULL;

    return ret;
}

/* CW HACK 22144 */
#ifdef __APPLE__
/* This is the same "exe path to display name" algorithm used in
 * loader/main.c to determine the name used for the application menu (CW hack 13438).
 *
 * TODO: this could do something more complicated, like getting strings out of the
 * version resource.
 */
static char *extract_exe_name(const char *exe_path)
{
    char *exe_name, *exe_path_copy, *p, *ret;
    size_t exe_name_len;

    if (!(exe_path_copy = strdup(exe_path))) return NULL;
    exe_name = exe_path_copy;

    if ((p = strrchr(exe_name, '\\'))) exe_name = p + 1;
    if ((p = strrchr(exe_name, '/'))) exe_name = p + 1;
    if (strspn(exe_name, "0123456789abcdefABCDEF") == 32 &&
        exe_name[32] == '.')
        exe_name += 33;
    if ((p = strrchr(exe_name, '.')) && p != exe_name)
        exe_name_len = p - exe_name;
    else
        exe_name_len = strlen(exe_name);

    if (exe_name_len)
        ret = strdup(exe_name);
    else
        ret = NULL;

    free(exe_path_copy);
    return ret;
}

/* Returns a path to $TMPDIR/winetemp-<wineloader_inode>-<wineloader_size_in_bytes>-<wineloader_mtime_sec>-<-wineloader_mtime_nsec>
 * The intention is that all links to the same wineloader will go in the same directory, and a different directory
 * will be used if wineloader is updated or modified.
 */
static char *create_tempdir(const char *wineloader_path)
{
    char *str = NULL, *ntdll = NULL, *p, *tempdir = malloc(MAX_PATH);
    struct stat st;
    size_t n, wineloader_len;

    if (!tempdir) return NULL;

    if (!confstr(_CS_DARWIN_USER_TEMP_DIR, tempdir, MAX_PATH))
        goto fail;

    if (stat(wineloader_path, &st))
        goto fail;

    if (asprintf(&str, "/winetemp-%llu-%llu-%lu-%lu/", st.st_ino, st.st_size, st.st_mtimespec.tv_sec, st.st_mtimespec.tv_nsec) < 0)
        goto fail;

    n = strlcat(tempdir, str, MAX_PATH);
    free(str);
    str = NULL;
    if (n >= MAX_PATH)
        goto fail;

    /* mkdir may fail if the directory already exists but that's ok */
    mkdir(tempdir, 0700);

    wineloader_len = strlen( wineloader_path );
    if (wineloader_len > ~(size_t)0 - sizeof("/ntdll.so"))
        goto fail;
    if (!(ntdll = malloc( wineloader_len + sizeof("/ntdll.so") )))
        goto fail;
    strcpy( ntdll, wineloader_path );
    if ((p = strrchr( ntdll, '/' ))) *p = 0;
    strcat( ntdll, "/ntdll.so" );
    if (asprintf( &str, "%s/ntdll.so", tempdir ) < 0)
        goto fail;
    symlink( ntdll, str );
    free( str );
    free( ntdll);
    return tempdir;

fail:
    free(str);
    free(ntdll);
    free(tempdir);
    return NULL;
}


static char *create_preloader_link(const char *wineloader_path, const char *exe_name)
{
    struct stat st;
    char *linkpath = create_tempdir(wineloader_path);

    if (!linkpath)
        return NULL;

    if (strlcat(linkpath, exe_name, MAX_PATH) >= MAX_PATH)
        goto fail;

    /* If the link already exists, use it (if it's in this dir, it points to the right place). */
    if (!stat(linkpath, &st))
        return linkpath;

    /* Try a hard link first, to avoid the little "alias" arrow that the Dock puts on the icon.
     * But if that fails, fall back to a symlink.
     */
    if (!link(wineloader_path, linkpath) || !symlink(wineloader_path, linkpath))
        return linkpath;

fail:
    free(linkpath);
    return NULL;
}

static void replace_wineloader_path_with_link(char **wineloader_path, const char *image_path)
{
    char *app_name = extract_exe_name(image_path);
    if (app_name)
    {
        char *preloader_path = create_preloader_link(*wineloader_path, app_name);
        if (preloader_path)
        {
            free(*wineloader_path);
            *wineloader_path = preloader_path;
        }

        /* Pass the app name to the preloader through an env var. */
        setenv("WINEPRELOADERAPPNAME", app_name, 1);
        free(app_name);
    }
}
#endif


static void preloader_exec( char **argv, const char *image_path )
{
#ifdef HAVE_WINE_PRELOADER
    if (asprintf( &argv[0], "%s-preloader", argv[1] ) < 0)
        fatal_error( "out of memory executing wine preloader\n" );
#ifdef __APPLE__
    {
        posix_spawnattr_t attr;

        /* CW HACK 22144: Create and exec a more descriptively-named link to the preloader,
         * which will show up as the icon name in the Dock. */
        replace_wineloader_path_with_link( &(argv[0]), image_path );

        posix_spawnattr_init( &attr );
        posix_spawnattr_setflags( &attr, POSIX_SPAWN_SETEXEC | _POSIX_SPAWN_DISABLE_ASLR );
        posix_spawn( NULL, argv[0], NULL, &attr, argv, *_NSGetEnviron() );
        posix_spawnattr_destroy( &attr );
    }
#endif
    execv( argv[0], argv );
    free( argv[0] );
#endif

#if defined(__APPLE__) && !defined(HAVE_WINE_PRELOADER)
    /* CW HACK 22144: Create and exec a more descriptively-named link to the loader,
     * which will show up as the icon name in the Dock.
     * When the preloader is not being used, WINEDLLPATH needs to be set correctly for
     * the loader to find ntdll.so, so don't even attempt this unless WINEDLLPATH is set.
     */
    if (getenv("WINEDLLPATH"))
        replace_wineloader_path_with_link( &(argv[1]), image_path );
#endif

    execv( argv[1], argv + 1 );
}

/* exec the appropriate wine loader for the specified machine */
static NTSTATUS loader_exec( char **argv, WORD machine, const char *image_path )
{
    static char noexec[] = "WINELOADERNOEXEC=1";

    putenv( noexec );

    if (((argv[1] = get_alternate_wineloader( machine )))) preloader_exec( argv, image_path );

    if (!(argv[1] = strdup( wineloader ))) return STATUS_NO_MEMORY;
    preloader_exec( argv, image_path );
    return STATUS_INVALID_IMAGE_FORMAT;
}


/***********************************************************************
 *           exec_wineloader
 *
 * argv[0] and argv[1] must be reserved for the preloader and loader respectively.
 */
NTSTATUS exec_wineloader( char **argv, int socketfd, const struct pe_image_info *pe_info, const char *image_path )
{
    WORD machine = pe_info->machine;
    ULONGLONG res_start = pe_info->base;
    ULONGLONG res_end = pe_info->base + pe_info->map_size;
    char preloader_reserve[64], socket_env[64];

    if (pe_info->wine_fakedll) res_start = res_end = 0;
    if (pe_info->image_flags & IMAGE_FLAGS_ComPlusNativeReady) machine = native_machine;

    signal( SIGPIPE, SIG_DFL );

    snprintf( socket_env, sizeof(socket_env), "WINESERVERSOCKET=%u", socketfd );
    snprintf( preloader_reserve, sizeof(preloader_reserve), "WINEPRELOADRESERVE=%x%08x-%x%08x",
             (UINT)(res_start >> 32), (UINT)res_start, (UINT)(res_end >> 32), (UINT)res_end );

    putenv( preloader_reserve );
    putenv( socket_env );

    return loader_exec( argv, machine, image_path );
}


/***********************************************************************
 *           exec_wineserver
 *
 * Exec a new wine server.
 */
static int exec_wineserver( pid_t *pid, char **argv )
{
    char *path;

    if (!is_win64 && alt_build_dir)  /* look for 64-bit server */
        return build_path_and_exec( pid, alt_build_dir, "server/wineserver", argv );

    if (build_dir)
        return build_path_and_exec( pid, build_dir, "server/wineserver", argv );

    if (!build_path_and_exec( pid, bin_dir, "wineserver", argv )) return 0;
    if ((path = getenv( "WINESERVER" )) && !build_path_and_exec( pid, "", path, argv )) return 0;

    if ((path = getenv( "PATH" )))
    {
        char *path_copy;

        if ((path_copy = strdup( path )))
        {
            for (path = strtok( path_copy, ":" ); path; path = strtok( NULL, ":" ))
            {
                if (!build_path_and_exec( pid, path, "wineserver", argv ))
                {
                    free( path_copy );
                    return 0;
                }
            }
            free( path_copy );
        }
    }
    return build_path_and_exec( pid, BINDIR, "wineserver", argv );
}


/***********************************************************************
 *           start_server
 *
 * Start a new wine server.
 */
void start_server( BOOL debug )
{
    static BOOL started;  /* we only try once */
    char *argv[3];
    static char debug_flag[] = "-d";

    if (!started)
    {
        int status;
        pid_t pid;

        argv[1] = debug ? debug_flag : NULL;
        argv[2] = NULL;
        if (exec_wineserver( &pid, argv )) fatal_error( "could not exec wineserver\n" );
        waitpid( pid, &status, 0 );
        status = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
        if (status == 2) return;  /* server lock held by someone else, will retry later */
        if (status) exit(status);  /* server failed */
        started = TRUE;
    }
}


/***********************************************************************
 *           KeAddSystemServiceTable
 */
BOOLEAN KeAddSystemServiceTable( ULONG_PTR *funcs, ULONG_PTR *counters, ULONG limit,
                                 BYTE *arguments, ULONG index )
{
    if (index >= ARRAY_SIZE(KeServiceDescriptorTable)) return FALSE;
    KeServiceDescriptorTable[index].ServiceTable  = funcs;
    KeServiceDescriptorTable[index].CounterTable  = counters;
    KeServiceDescriptorTable[index].ServiceLimit  = limit;
    KeServiceDescriptorTable[index].ArgumentTable = arguments;
    return TRUE;
}

void trace_syscall( UINT id, ULONG_PTR *args, ULONG len )
{
    UINT idx = (id >> 12) & 3, num = id & 0xfff;
    const char **names = syscall_names[idx];

    if (names && names[num])
        TRACE_(syscall)( "\1SysCall  %s(", names[num] );
    else
        TRACE_(syscall)( "\1SysCall  %04x(", id );

    len /= sizeof(ULONG_PTR);
    for (ULONG i = 0; i < len; i++)
    {
        TRACE_(syscall)( "%08lx", args[i] );
        if (i < len - 1) TRACE_(syscall)( "," );
    }
    TRACE_(syscall)( ")\n" );
}

void trace_sysret( UINT id, ULONG_PTR retval )
{
    UINT idx = (id >> 12) & 3, num = id & 0xfff;
    const char **names = syscall_names[idx];

    if (names && names[num])
        TRACE_(syscall)( "\1SysRet   %s() retval=%08lx\n", names[num], retval );
    else
        TRACE_(syscall)( "\1SysRet   %04x() retval=%08lx\n", id, retval );
}

void trace_usercall( UINT id, ULONG_PTR *args, ULONG len )
{
    if (usercall_names)
        TRACE_(syscall)("\1UserCall %s(%p,%u)\n", usercall_names[id], args, len );
    else
        TRACE_(syscall)("\1UserCall %04x(%p,%u)\n", id, args, len );
}

void trace_userret( void *ret_ptr, ULONG len, NTSTATUS status, UINT id )
{
    if (usercall_names)
        TRACE_(syscall)("\1UserRet  %s(%p,%u) retval=%08x\n", usercall_names[id], ret_ptr, len, status );
    else
        TRACE_(syscall)("\1UserRet  %04x(%p,%u) retval=%08x\n", id, ret_ptr, len, status );
}

#ifdef SO_DLLS_SUPPORTED

/* adjust an array of pointers to make them into RVAs */
static inline void fixup_rva_ptrs( void *array, BYTE *base, unsigned int count )
{
    BYTE **src = array;
    DWORD *dst = array;

    for ( ; count; count--, src++, dst++) *dst = *src ? *src - base : 0;
}

static BOOL builtin_ptr_array_fits_image( BYTE *base, DWORD image_size, void *array, unsigned int count )
{
    BYTE **ptr = array;
    ULONG_PTR image_base = (ULONG_PTR)base;

    for ( ; count; count--, ptr++ )
    {
        ULONG_PTR addr = (ULONG_PTR)*ptr;

        if (!addr) continue;
        if (addr < image_base || addr - image_base >= image_size) return FALSE;
    }
    return TRUE;
}

/* fixup an array of RVAs by adding the specified delta */
static inline BOOL fixup_rva_dwords( DWORD *ptr, int delta, unsigned int count )
{
    for ( ; count; count--, ptr++)
    {
        UINT_PTR value = *ptr;

        if (!value) continue;
        if (delta >= 0)
        {
            if (value > UINT_MAX - (UINT_PTR)delta) return FALSE;
            value += (UINT_PTR)delta;
        }
        else
        {
            UINT_PTR abs_delta = (UINT_PTR)(-(delta + 1)) + 1;

            if (value < abs_delta) return FALSE;
            value -= abs_delta;
        }
        *ptr = (DWORD)value;
    }
    return TRUE;
}


static BOOL resource_ptr_fits( const BYTE *root, size_t size, const void *ptr, size_t len )
{
    ULONG_PTR base = (ULONG_PTR)root, addr = (ULONG_PTR)ptr;

    if (addr < base || addr - base > size) return FALSE;
    return len <= size - (addr - base);
}

static BOOL resource_offset_ptr( BYTE *root, size_t size, DWORD offset, size_t len, void **ptr )
{
    if (offset > size || len > size - offset) return FALSE;
    *ptr = root + offset;
    return TRUE;
}

static BOOL resource_name_fits( IMAGE_RESOURCE_DIRECTORY_ENTRY *entry, BYTE *root, size_t size )
{
    IMAGE_RESOURCE_DIR_STRING_U *str;

    if (!entry->NameIsString) return TRUE;
    if (!resource_offset_ptr( root, size, entry->NameOffset,
                              FIELD_OFFSET( IMAGE_RESOURCE_DIR_STRING_U, NameString ), (void **)&str ))
        return FALSE;
    return resource_ptr_fits( root, size, str->NameString, (size_t)str->Length * sizeof(WCHAR) );
}

static BOOL fixup_resource_data_entry( IMAGE_RESOURCE_DATA_ENTRY *data, DWORD image_size, int delta )
{
    UINT_PTR value = data->OffsetToData;

    if (value)
    {
        if (delta >= 0)
        {
            if (value > ~(UINT_PTR)0 - (UINT_PTR)delta) return FALSE;
            value += delta;
        }
        else
        {
            UINT_PTR neg_delta = 0 - (UINT_PTR)delta;
            if (value < neg_delta) return FALSE;
            value -= neg_delta;
        }
        if (value > ~(DWORD)0) return FALSE;
        data->OffsetToData = value;
    }
    return data->OffsetToData < image_size && data->Size <= image_size - data->OffsetToData;
}

/* fixup RVAs in the resource directory */
static BOOL fixup_so_resources( IMAGE_RESOURCE_DIRECTORY *dir, BYTE *root, size_t size, DWORD image_size,
                                int delta, unsigned int level )
{
    IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
    unsigned int i;
    DWORD count;

    if (level > 16 || !resource_ptr_fits( root, size, dir, sizeof(*dir) )) return FALSE;
    count = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
    entry = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
    if (!resource_ptr_fits( root, size, entry, count * sizeof(*entry) )) return FALSE;
    for (i = 0; i < count; i++, entry++)
    {
        DWORD offset = entry->OffsetToDirectory;
        void *ptr;

        if (!resource_name_fits( entry, root, size )) return FALSE;
        if (offset >= size) return FALSE;
        ptr = root + offset;
        if (entry->DataIsDirectory)
        {
            if (!fixup_so_resources( ptr, root, size, image_size, delta, level + 1 )) return FALSE;
        }
        else
        {
            if (!resource_ptr_fits( root, size, ptr, sizeof(IMAGE_RESOURCE_DATA_ENTRY) )) return FALSE;
            if (!fixup_resource_data_entry( ptr, image_size, delta )) return FALSE;
        }
    }
    return TRUE;
}

static BOOL builtin_rva_array_fits_image( DWORD image_size, DWORD rva, DWORD count, size_t elem_size )
{
    if (!count) return TRUE;
    if (!rva || image_size < elem_size || rva > image_size - elem_size) return FALSE;
    return count <= (image_size - rva) / elem_size;
}

static BOOL builtin_rva_string_fits_image( BYTE *base, DWORD image_size, DWORD rva )
{
    if (!rva || rva >= image_size) return FALSE;
    return memchr( base + rva, 0, image_size - rva ) != NULL;
}

static BOOL fixup_rva_strings( BYTE *base, DWORD image_size, DWORD *ptr, int delta, DWORD count )
{
    UINT_PTR value;

    for ( ; count; count--, ptr++ )
    {
        if (!*ptr) return FALSE;
        value = *ptr;
        if (delta >= 0)
        {
            if (value > ~(UINT_PTR)0 - (UINT_PTR)delta) return FALSE;
            value += delta;
        }
        else
        {
            UINT_PTR neg_delta = 0 - (UINT_PTR)delta;
            if (value < neg_delta) return FALSE;
            value -= neg_delta;
        }
        if (value > ~(DWORD)0 || !builtin_rva_string_fits_image( base, image_size, value ))
            return FALSE;
        *ptr = value;
    }
    return TRUE;
}

static BOOL builtin_import_by_name_fits_image( BYTE *base, DWORD image_size, DWORD rva )
{
    DWORD name_rva;

    if (!builtin_rva_array_fits_image( image_size, rva, 1,
                                       FIELD_OFFSET( IMAGE_IMPORT_BY_NAME, Name ) + 1 ))
        return FALSE;
    if (rva > ~(DWORD)0 - FIELD_OFFSET( IMAGE_IMPORT_BY_NAME, Name )) return FALSE;
    name_rva = rva + FIELD_OFFSET( IMAGE_IMPORT_BY_NAME, Name );
    return builtin_rva_string_fits_image( base, image_size, name_rva );
}

/* fixup an array of name/ordinal RVAs by adding the specified delta */
static BOOL fixup_rva_names( BYTE *base, DWORD image_size, UINT_PTR *ptr, int delta )
{
    UINT_PTR value;

    for ( ; *ptr; ptr++)
    {
        if (*ptr & IMAGE_ORDINAL_FLAG) continue;

        value = *ptr;
        if (delta >= 0)
        {
            if (value > ~(UINT_PTR)0 - (UINT_PTR)delta) return FALSE;
            value += delta;
        }
        else
        {
            UINT_PTR neg_delta = 0 - (UINT_PTR)delta;
            if (value < neg_delta) return FALSE;
            value -= neg_delta;
        }
        if (value > ~(DWORD)0 || !builtin_import_by_name_fits_image( base, image_size, value ))
            return FALSE;
        *ptr = value;
    }
    return TRUE;
}

static BOOL builtin_thunk_array_fits_image( BYTE *base, DWORD image_size, DWORD rva )
{
    UINT_PTR *ptr;
    DWORD count, i;

    if (!builtin_rva_array_fits_image( image_size, rva, 1, sizeof(*ptr) )) return FALSE;
    ptr = (UINT_PTR *)(base + rva);
    count = (image_size - rva) / sizeof(*ptr);
    for (i = 0; i < count; i++) if (!ptr[i]) return TRUE;
    return FALSE;
}

static IMAGE_DATA_DIRECTORY *builtin_get_data_dir( IMAGE_NT_HEADERS *nt, DWORD dir )
{
    if (dir >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;
    if (dir >= nt->OptionalHeader.NumberOfRvaAndSizes) return NULL;
    return &nt->OptionalHeader.DataDirectory[dir];
}

/***********************************************************************
 *           fill_builtin_image_info
 */
static void fill_builtin_image_info( void *module, struct pe_image_info *info )
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)module;
    const IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((const BYTE *)dos + dos->e_lfanew);

    memset( info, 0, sizeof(*info) );
    info->base            = nt->OptionalHeader.ImageBase;
    info->entry_point     = nt->OptionalHeader.AddressOfEntryPoint;
    info->map_size        = nt->OptionalHeader.SizeOfImage;
    info->stack_size      = nt->OptionalHeader.SizeOfStackReserve;
    info->stack_commit    = nt->OptionalHeader.SizeOfStackCommit;
    info->subsystem       = nt->OptionalHeader.Subsystem;
    info->subsystem_minor = nt->OptionalHeader.MinorSubsystemVersion;
    info->subsystem_major = nt->OptionalHeader.MajorSubsystemVersion;
    info->osversion_major = nt->OptionalHeader.MajorOperatingSystemVersion;
    info->osversion_minor = nt->OptionalHeader.MinorOperatingSystemVersion;
    info->image_charact   = nt->FileHeader.Characteristics;
    info->dll_charact     = nt->OptionalHeader.DllCharacteristics;
    info->machine         = nt->FileHeader.Machine;
    info->contains_code   = TRUE;
    info->wine_builtin    = TRUE;
    info->header_size     = nt->OptionalHeader.SizeOfHeaders;
    info->file_size       = nt->OptionalHeader.SizeOfImage;
    info->checksum        = nt->OptionalHeader.CheckSum;
}

/*************************************************************************
 *		map_so_dll
 *
 * Map a builtin dll in memory and fixup RVAs.
 */
static NTSTATUS map_so_dll( const IMAGE_NT_HEADERS *nt_descr, HMODULE module )
{
    static const char builtin_signature[32] = "Wine builtin DLL";
    IMAGE_DATA_DIRECTORY *dir;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sec;
    BYTE *addr = (BYTE *)module;
    DWORD code_start, code_end, data_start, data_end;
    DWORD alignment = nt_descr->OptionalHeader.SectionAlignment;
    DWORD align_mask;
    ULONGLONG header_end;
    INT_PTR delta_ptr;
    ULONGLONG end;
    int delta, nb_sections = 2;  /* code + data */
    unsigned int i;

    if (!alignment || (alignment & (alignment - 1))) return STATUS_INVALID_IMAGE_FORMAT;
    align_mask = alignment - 1;
    header_end = sizeof(IMAGE_DOS_HEADER)
                 + sizeof(builtin_signature)
                 + sizeof(IMAGE_NT_HEADERS)
                 + nb_sections * sizeof(IMAGE_SECTION_HEADER);
    if (header_end > UINT_MAX - align_mask) return STATUS_INVALID_IMAGE_FORMAT;
    code_start = (header_end + align_mask) & ~align_mask;

    if (anon_mmap_fixed( addr, code_start, PROT_READ | PROT_WRITE, 0 ) != addr) return STATUS_NO_MEMORY;

    dos = (IMAGE_DOS_HEADER *)addr;
    nt  = (IMAGE_NT_HEADERS *)((BYTE *)(dos + 1) + sizeof(builtin_signature));
    sec = (IMAGE_SECTION_HEADER *)(nt + 1);

    /* build the DOS and NT headers */

    dos->e_magic    = IMAGE_DOS_SIGNATURE;
    dos->e_cblp     = 0x90;
    dos->e_cp       = 3;
    dos->e_cparhdr  = (sizeof(*dos) + 0xf) / 0x10;
    dos->e_minalloc = 0;
    dos->e_maxalloc = 0xffff;
    dos->e_ss       = 0x0000;
    dos->e_sp       = 0x00b8;
    dos->e_lfanew   = sizeof(*dos) + sizeof(builtin_signature);
    memcpy( dos + 1, builtin_signature, sizeof(builtin_signature) );

    *nt = *nt_descr;
    macrunner_hb_register_x64_original_exec_sections( addr, nt_descr );

    delta_ptr = (INT_PTR)nt_descr - (INT_PTR)addr;
    if (delta_ptr < 0 || delta_ptr > INT_MAX) return STATUS_INVALID_IMAGE_FORMAT;
    delta      = delta_ptr;
    data_start = delta & ~align_mask;
#ifdef __APPLE__
    {
        Dl_info dli;
        BYTE *data_segment;
        unsigned long data_size;
        /* need the mach_header, not the PE header, to give to getsegmentdata(3) */
        if (!dladdr(addr, &dli)) return STATUS_INVALID_IMAGE_FORMAT;
        data_segment = getsegmentdata(dli.dli_fbase, "__DATA", &data_size);
        if (!data_segment || (ULONG_PTR)data_segment < (ULONG_PTR)addr) return STATUS_INVALID_IMAGE_FORMAT;
        end = (ULONGLONG)((ULONG_PTR)data_segment - (ULONG_PTR)addr) + data_size + align_mask;
        if (end > UINT_MAX) return STATUS_INVALID_IMAGE_FORMAT;
        code_end   = (ULONG_PTR)data_segment - (ULONG_PTR)addr;
        data_end   = end & ~align_mask;
    }
#else
    code_end   = data_start;
    end = (ULONGLONG)nt->OptionalHeader.SizeOfImage + delta + align_mask;
    if (end > UINT_MAX) return STATUS_INVALID_IMAGE_FORMAT;
    data_end   = end & ~align_mask;
#endif
    if (code_end < code_start || data_end < data_start) return STATUS_INVALID_IMAGE_FORMAT;

    if (!builtin_ptr_array_fits_image( addr, data_end, &nt->OptionalHeader.AddressOfEntryPoint, 1 ))
        return STATUS_INVALID_IMAGE_FORMAT;
    fixup_rva_ptrs( &nt->OptionalHeader.AddressOfEntryPoint, addr, 1 );

    nt->FileHeader.NumberOfSections                = nb_sections;
    nt->OptionalHeader.BaseOfCode                  = code_start;
#ifndef _WIN64
    nt->OptionalHeader.BaseOfData                  = data_start;
#endif
    nt->OptionalHeader.SizeOfCode                  = code_end - code_start;
    nt->OptionalHeader.SizeOfInitializedData       = data_end - data_start;
    nt->OptionalHeader.SizeOfUninitializedData     = 0;
    nt->OptionalHeader.SizeOfImage                 = data_end;
    nt->OptionalHeader.ImageBase                   = (ULONG_PTR)addr;
    nt->OptionalHeader.NumberOfRvaAndSizes         = min( nt->OptionalHeader.NumberOfRvaAndSizes,
                                                          IMAGE_NUMBEROF_DIRECTORY_ENTRIES );

    /* build the code section */

    memcpy( sec->Name, ".text", sizeof(".text") );
    sec->SizeOfRawData = code_end - code_start;
    sec->Misc.VirtualSize = sec->SizeOfRawData;
    sec->VirtualAddress   = code_start;
    sec->PointerToRawData = code_start;
    sec->Characteristics  = (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
    sec++;

    /* build the data section */

    memcpy( sec->Name, ".data", sizeof(".data") );
    sec->SizeOfRawData = data_end - data_start;
    sec->Misc.VirtualSize = sec->SizeOfRawData;
    sec->VirtualAddress   = data_start;
    sec->PointerToRawData = data_start;
    sec->Characteristics  = (IMAGE_SCN_CNT_INITIALIZED_DATA |
                             IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ);
    sec++;

    for (i = 0; i < nt->OptionalHeader.NumberOfRvaAndSizes; i++)
        if (!fixup_rva_dwords( &nt->OptionalHeader.DataDirectory[i].VirtualAddress, delta, 1 ))
            return STATUS_INVALID_IMAGE_FORMAT;

    /* build the import directory */

    dir = builtin_get_data_dir( nt, IMAGE_FILE_IMPORT_DIRECTORY );
    if (dir && dir->Size)
    {
        IMAGE_IMPORT_DESCRIPTOR *imports;
        DWORD count;

        if (dir->VirtualAddress >= nt->OptionalHeader.SizeOfImage ||
            dir->Size > nt->OptionalHeader.SizeOfImage - dir->VirtualAddress ||
            dir->Size < sizeof(*imports))
            return STATUS_INVALID_IMAGE_FORMAT;
        imports = (IMAGE_IMPORT_DESCRIPTOR *)(addr + dir->VirtualAddress);
        count = dir->Size / sizeof(*imports);

        for (i = 0; i < count && imports[i].Name; i++)
        {
            if (!fixup_rva_dwords( &imports[i].OriginalFirstThunk, delta, 1 ) ||
                !fixup_rva_dwords( &imports[i].Name, delta, 1 ) ||
                !fixup_rva_dwords( &imports[i].FirstThunk, delta, 1 ))
                return STATUS_INVALID_IMAGE_FORMAT;
            if (!builtin_rva_string_fits_image( addr, nt->OptionalHeader.SizeOfImage, imports[i].Name ))
                return STATUS_INVALID_IMAGE_FORMAT;
            if (imports[i].OriginalFirstThunk &&
                !builtin_thunk_array_fits_image( addr, nt->OptionalHeader.SizeOfImage,
                                                 imports[i].OriginalFirstThunk ))
                return STATUS_INVALID_IMAGE_FORMAT;
            if (imports[i].FirstThunk &&
                !builtin_thunk_array_fits_image( addr, nt->OptionalHeader.SizeOfImage,
                                                 imports[i].FirstThunk ))
                return STATUS_INVALID_IMAGE_FORMAT;
            if (imports[i].OriginalFirstThunk)
            {
                if (!fixup_rva_names( addr, nt->OptionalHeader.SizeOfImage,
                                      (UINT_PTR *)(addr + imports[i].OriginalFirstThunk), delta ))
                    return STATUS_INVALID_IMAGE_FORMAT;
            }
            if (imports[i].FirstThunk)
            {
                if (!fixup_rva_names( addr, nt->OptionalHeader.SizeOfImage,
                                      (UINT_PTR *)(addr + imports[i].FirstThunk), delta ))
                    return STATUS_INVALID_IMAGE_FORMAT;
            }
        }
        if (i == count) return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* build the resource directory */

    dir = builtin_get_data_dir( nt, IMAGE_FILE_RESOURCE_DIRECTORY );
    if (dir && dir->Size)
    {
        void *ptr;

        if (dir->VirtualAddress >= nt->OptionalHeader.SizeOfImage ||
            dir->Size > nt->OptionalHeader.SizeOfImage - dir->VirtualAddress)
            return STATUS_INVALID_IMAGE_FORMAT;
        ptr = addr + dir->VirtualAddress;
        if (!fixup_so_resources( ptr, ptr, dir->Size, nt->OptionalHeader.SizeOfImage, delta, 0 ))
            return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* build the export directory */

    dir = builtin_get_data_dir( nt, IMAGE_FILE_EXPORT_DIRECTORY );
    if (dir && dir->Size)
    {
        IMAGE_EXPORT_DIRECTORY *exports;

        if (dir->Size < sizeof(*exports) || dir->VirtualAddress >= nt->OptionalHeader.SizeOfImage ||
            dir->Size > nt->OptionalHeader.SizeOfImage - dir->VirtualAddress ||
            !builtin_rva_array_fits_image( nt->OptionalHeader.SizeOfImage, dir->VirtualAddress,
                                           1, sizeof(*exports) ))
            return STATUS_INVALID_IMAGE_FORMAT;
        exports = (IMAGE_EXPORT_DIRECTORY *)(addr + dir->VirtualAddress);
        if (!fixup_rva_strings( addr, nt->OptionalHeader.SizeOfImage, &exports->Name, delta, 1 ))
            return STATUS_INVALID_IMAGE_FORMAT;
        if (!fixup_rva_dwords( &exports->AddressOfFunctions, delta, 1 ) ||
            !fixup_rva_dwords( &exports->AddressOfNames, delta, 1 ) ||
            !fixup_rva_dwords( &exports->AddressOfNameOrdinals, delta, 1 ))
            return STATUS_INVALID_IMAGE_FORMAT;
        if (!builtin_rva_array_fits_image( nt->OptionalHeader.SizeOfImage, exports->AddressOfNames,
                                           exports->NumberOfNames, sizeof(DWORD) ) ||
            !builtin_rva_array_fits_image( nt->OptionalHeader.SizeOfImage, exports->AddressOfNameOrdinals,
                                           exports->NumberOfNames, sizeof(WORD) ) ||
            !builtin_rva_array_fits_image( nt->OptionalHeader.SizeOfImage, exports->AddressOfFunctions,
                                           exports->NumberOfFunctions, sizeof(UINT_PTR) ))
            return STATUS_INVALID_IMAGE_FORMAT;
        if (!fixup_rva_strings( addr, nt->OptionalHeader.SizeOfImage,
                                (DWORD *)(addr + exports->AddressOfNames), delta, exports->NumberOfNames ))
            return STATUS_INVALID_IMAGE_FORMAT;
        if (!builtin_ptr_array_fits_image( addr, nt->OptionalHeader.SizeOfImage,
                                           addr + exports->AddressOfFunctions, exports->NumberOfFunctions ))
            return STATUS_INVALID_IMAGE_FORMAT;
        fixup_rva_ptrs( addr + exports->AddressOfFunctions, addr, exports->NumberOfFunctions );
    }

    /* build the delay import directory */

    dir = builtin_get_data_dir( nt, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT );
    if (dir && dir->Size)
    {
        IMAGE_DELAYLOAD_DESCRIPTOR *imports;
        DWORD count;

        if (dir->VirtualAddress >= nt->OptionalHeader.SizeOfImage ||
            dir->Size > nt->OptionalHeader.SizeOfImage - dir->VirtualAddress ||
            dir->Size < sizeof(*imports))
            return STATUS_INVALID_IMAGE_FORMAT;
        imports = (IMAGE_DELAYLOAD_DESCRIPTOR *)(addr + dir->VirtualAddress);
        count = dir->Size / sizeof(*imports);

        for (i = 0; i < count && imports[i].DllNameRVA; i++)
        {
            if (!fixup_rva_dwords( &imports[i].DllNameRVA, delta, 1 ) ||
                !fixup_rva_dwords( &imports[i].ModuleHandleRVA, delta, 1 ) ||
                !fixup_rva_dwords( &imports[i].ImportAddressTableRVA, delta, 1 ) ||
                !fixup_rva_dwords( &imports[i].ImportNameTableRVA, delta, 1 ) ||
                !fixup_rva_dwords( &imports[i].BoundImportAddressTableRVA, delta, 1 ) ||
                !fixup_rva_dwords( &imports[i].UnloadInformationTableRVA, delta, 1 ))
                return STATUS_INVALID_IMAGE_FORMAT;
            if (!builtin_rva_string_fits_image( addr, nt->OptionalHeader.SizeOfImage,
                                                imports[i].DllNameRVA ))
                return STATUS_INVALID_IMAGE_FORMAT;
            if (!builtin_rva_array_fits_image( nt->OptionalHeader.SizeOfImage,
                                               imports[i].ModuleHandleRVA, 1, sizeof(UINT_PTR) ) ||
                !builtin_thunk_array_fits_image( addr, nt->OptionalHeader.SizeOfImage,
                                                 imports[i].ImportAddressTableRVA ))
                return STATUS_INVALID_IMAGE_FORMAT;
            if (imports[i].ImportNameTableRVA &&
                !builtin_thunk_array_fits_image( addr, nt->OptionalHeader.SizeOfImage,
                                                 imports[i].ImportNameTableRVA ))
                return STATUS_INVALID_IMAGE_FORMAT;
            if (imports[i].BoundImportAddressTableRVA &&
                !builtin_thunk_array_fits_image( addr, nt->OptionalHeader.SizeOfImage,
                                                 imports[i].BoundImportAddressTableRVA ))
                return STATUS_INVALID_IMAGE_FORMAT;
            if (imports[i].UnloadInformationTableRVA &&
                !builtin_thunk_array_fits_image( addr, nt->OptionalHeader.SizeOfImage,
                                                 imports[i].UnloadInformationTableRVA ))
                return STATUS_INVALID_IMAGE_FORMAT;
            if (imports[i].ImportNameTableRVA)
            {
                if (!fixup_rva_names( addr, nt->OptionalHeader.SizeOfImage,
                                      (UINT_PTR *)(addr + imports[i].ImportNameTableRVA), delta ))
                    return STATUS_INVALID_IMAGE_FORMAT;
            }
        }
        if (i == count) return STATUS_INVALID_IMAGE_FORMAT;
    }

    return STATUS_SUCCESS;
}

/***********************************************************************
 *           dlopen_dll
 */
static NTSTATUS dlopen_dll( const char *so_name, UNICODE_STRING *nt_name, void **ret_module,
                            struct pe_image_info *image_info, BOOL prefer_native )
{
    void *module, *handle;
    const IMAGE_NT_HEADERS *nt;
    ULONGLONG image_base;
    NTSTATUS status;

    handle = dlopen( so_name, RTLD_NOW );
    if (!handle)
    {
        WARN( "failed to load .so lib %s: %s\n", debugstr_a(so_name), dlerror() );
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (!(nt = dlsym( handle, "__wine_spec_nt_header" )))
    {
        ERR( "invalid .so library %s, too old?\n", debugstr_a(so_name));
        dlclose( handle );
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    image_base = nt->OptionalHeader.ImageBase;
    if (image_base > (ULONGLONG)(ULONG_PTR)~0 - 0xffff)
    {
        dlclose( handle );
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    module = (HMODULE)((ULONG_PTR)(image_base + 0xffff) & ~(ULONG_PTR)0xffff);
    if (get_builtin_so_handle( module ))  /* already loaded */
    {
        fill_builtin_image_info( module, image_info );
        *ret_module = module;
        dlclose( handle );
        return STATUS_SUCCESS;
    }

    if ((status = map_so_dll( nt, module )))
    {
        dlclose( handle );
        return status;
    }

    fill_builtin_image_info( module, image_info );
    if (prefer_native && (image_info->dll_charact & IMAGE_DLLCHARACTERISTICS_PREFER_NATIVE))
    {
        TRACE( "%s has prefer-native flag, ignoring builtin\n", debugstr_a(so_name) );
        dlclose( handle );
        return STATUS_IMAGE_ALREADY_LOADED;
    }

    if (virtual_create_builtin_view( module, nt_name, image_info, handle ))
    {
        dlclose( handle );
        return STATUS_NO_MEMORY;
    }
    *ret_module = module;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           load_so_dll
 */
static NTSTATUS load_so_dll( void *args )
{
    static const WCHAR soW[] = {'.','s','o',0};
    struct load_so_dll_params *params = args;
    UNICODE_STRING *nt_name = &params->nt_name;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING true_nt_name;
    struct pe_image_info info;
    char *unix_name;
    NTSTATUS status;
    DWORD len;

    if (get_load_order( nt_name ) == LO_DISABLED) return STATUS_DLL_NOT_FOUND;
    InitializeObjectAttributes( &attr, nt_name, OBJ_CASE_INSENSITIVE, 0, 0 );
    if (!get_nt_and_unix_names( &attr, &true_nt_name, &unix_name, FILE_OPEN, FALSE ))
    {
        /* remove .so extension from Windows name */
        len = nt_name->Length / sizeof(WCHAR);
        if (len > 3 && !wcsicmp( nt_name->Buffer + len - 3, soW )) nt_name->Length -= 3 * sizeof(WCHAR);

        status = dlopen_dll( unix_name, nt_name, params->module, &info, FALSE );
    }
    else status = STATUS_DLL_NOT_FOUND;

    free( unix_name );
    free( true_nt_name.Buffer );
    return status;
}


/* check if the library is the correct architecture */
/* only returns false for a valid library of the wrong arch */
static int check_library_arch( int fd )
{
#ifdef __APPLE__
    struct  /* Mach-O header */
    {
        unsigned int magic;
        unsigned int cputype;
    } header;

    if (read( fd, &header, sizeof(header) ) != sizeof(header)) return 1;
    if (header.magic != 0xfeedface) return 1;
    if (sizeof(void *) == sizeof(int)) return !(header.cputype >> 24);
    else return (header.cputype >> 24) == 1; /* CPU_ARCH_ABI64 */
#else
    struct  /* ELF header */
    {
        unsigned char magic[4];
        unsigned char class;
        unsigned char data;
        unsigned char version;
    } header;

    if (read( fd, &header, sizeof(header) ) != sizeof(header)) return 1;
    if (memcmp( header.magic, "\177ELF", 4 )) return 1;
    if (header.version != 1 /* EV_CURRENT */) return 1;
#ifdef WORDS_BIGENDIAN
    if (header.data != 2 /* ELFDATA2MSB */) return 1;
#else
    if (header.data != 1 /* ELFDATA2LSB */) return 1;
#endif
    if (sizeof(void *) == sizeof(int)) return header.class == 1; /* ELFCLASS32 */
    else return header.class == 2; /* ELFCLASS64 */
#endif
}

/***********************************************************************
 *           open_builtin_so_file
 */
static NTSTATUS open_builtin_so_file( char *name, OBJECT_ATTRIBUTES *attr, void **module,
                                      SECTION_IMAGE_INFORMATION *image_info, USHORT search_machine,
                                      USHORT load_machine, BOOL prefer_native )
{
    NTSTATUS status = STATUS_DLL_NOT_FOUND;
    int fd;
    char *end = name + strlen( name );

    if (search_machine != current_machine) return status;
    if (load_machine && load_machine != current_machine) return status;

    *module = NULL;
    strcpy( end, ".so" );
    if ((fd = open( name, O_RDONLY )) == -1) goto done;

    if (check_library_arch( fd ))
    {
        struct pe_image_info info;

        status = dlopen_dll( name, attr->ObjectName, module, &info, prefer_native );
        if (!status) virtual_fill_image_information( &info, image_info );
        else if (status != STATUS_IMAGE_ALREADY_LOADED)
        {
            ERR( "failed to load .so lib %s\n", debugstr_a(name) );
            status = STATUS_PROCEDURE_NOT_FOUND;
        }
    }
    else status = STATUS_NOT_SUPPORTED;

    close( fd );
 done:
    *end = 0;
    return status;
}

/***********************************************************************
 *           open_main_image_so_file
 */
static NTSTATUS open_main_image_so_file( const char *name, UNICODE_STRING *nt_name, void **module,
                                         SECTION_IMAGE_INFORMATION *image_info )
{
    struct pe_image_info pe_info;
    NTSTATUS status;

    /* remove .so extension from Windows name */
    if (nt_name->Length > 3 * sizeof(WCHAR))
    {
        static const WCHAR soW[] = {'.','s','o',0};
        WCHAR *p = nt_name->Buffer + nt_name->Length / sizeof(WCHAR);
        if (!wcsicmp( p - 3, soW ))
        {
            p[-3] = 0;
            nt_name->Length -= 3 * sizeof(WCHAR);
        }
    }
    status = dlopen_dll( name, nt_name, module, &pe_info, FALSE );
    if (!status) virtual_fill_image_information( &pe_info, image_info );
    return status;
}

extern NTSTATUS unwind_builtin_dll( void *args );

#else /* SO_DLLS_SUPPORTED */

static NTSTATUS open_builtin_so_file( char *name, OBJECT_ATTRIBUTES *attr, void **module,
                                      SECTION_IMAGE_INFORMATION *image_info, USHORT search_machine,
                                      USHORT load_machine, BOOL prefer_native )
{
    return STATUS_DLL_NOT_FOUND;
}

static NTSTATUS open_main_image_so_file( const char *name, UNICODE_STRING *nt_name, void **module,
                                         SECTION_IMAGE_INFORMATION *image_info )
{
    return STATUS_INVALID_IMAGE_FORMAT;
}

static NTSTATUS load_so_dll( void *args )
{
    return STATUS_INVALID_IMAGE_FORMAT;
}

static NTSTATUS unwind_builtin_dll( void *args )
{
    return STATUS_UNSUCCESSFUL;
}

#endif /* SO_DLLS_SUPPORTED */


/* CW HACK 22434 */
#if defined(__APPLE__) && defined(__x86_64__)
#include <sys/utsname.h>
static pthread_once_t non_native_init_once = PTHREAD_ONCE_INIT;
static void *non_native_support_lib;
void *libd3dshared_load_addr = NULL, *libd3dshared_code_end = NULL;
static void (*register_non_native_code_region)( void*, void* );
static bool (*supports_non_native_code_regions)(void);

/* Non-native code region support requires Sonoma or later, don't bother loading on earlier OSes */
static BOOL sonoma_or_later(void)
{
    int result;
    struct utsname name;
    unsigned major, minor;

    result = (uname( &name ) == 0 &&
              sscanf( name.release, "%u.%u", &major, &minor ) == 2 &&
              major >= 23 /* macOS 14 Sonoma */);

    return (result == 1) ? TRUE : FALSE;
}

static void init_non_native_support(void)
{
    char *libd3dshared_path = getenv( "CX_APPLEGPTK_LIBD3DSHARED_PATH" );

    register_non_native_code_region = NULL;
    supports_non_native_code_regions = NULL;

    if (!libd3dshared_path || !sonoma_or_later())
        return;

    non_native_support_lib = dlopen( libd3dshared_path, RTLD_LOCAL );
    if (non_native_support_lib)
    {
        Dl_info dli;

        register_non_native_code_region = dlsym( non_native_support_lib, "register_non_native_code_region" );
        supports_non_native_code_regions = dlsym( non_native_support_lib, "supports_non_native_code_regions" );

        if (dladdr( supports_non_native_code_regions, &dli ))
        {
            unsigned long code_size;

            libd3dshared_load_addr = dli.dli_fbase;
            getsegmentdata(dli.dli_fbase, "__TEXT", &code_size);
            libd3dshared_code_end = (char *)libd3dshared_load_addr + code_size;
        }

        TRACE( "Loaded libd3dshared.dylib, does%s support non-native code regions\n",
                supports_non_native_code_regions ? (supports_non_native_code_regions() ? "" : " not") : " not" );
    }
    else
        TRACE( "Loading libd3dshared.dylib failed: %s\n", dlerror() );
}

static NTSTATUS pe_module_loaded( void *args )
{
    struct pe_module_loaded_params *params = args;

    pthread_once( &non_native_init_once, &init_non_native_support );
    if ((supports_non_native_code_regions && supports_non_native_code_regions()))
    {
        TRACE( "Marking non_native_code_region: %p-%p\n", params->start, params->end );
        register_non_native_code_region( params->start, params->end );
    }
    return STATUS_SUCCESS;
}
#else
static NTSTATUS pe_module_loaded( void *args ) { return STATUS_NOT_IMPLEMENTED; }
#endif

extern NTSTATUS macrunner_hb_register_import_thunk( void *args );
extern NTSTATUS macrunner_hb_x64_dll_entry( void *args );
extern NTSTATUS macrunner_hb_x64_thread_entry( void *args );
extern NTSTATUS macrunner_hb_x64_import_context( void *args );
extern NTSTATUS macrunner_guest_peb_observe( void *args );

/* The native process owner is fixed before PE initialization. Guest child
 * environments may omit or replace runner configuration; they are not authority. */
static NTSTATUS macrunner_cpu_backend_query( void *args )
{
    if (!macrunner_cpu_backend_seen) return STATUS_UNSUCCESSFUL;
    *(UINT *)args = macrunner_cpu_backend == MACRUNNER_CPU_BACKEND_HB;
    return STATUS_SUCCESS;
}

static const unixlib_entry_t unix_call_funcs[] =
{
    load_so_dll,
    unwind_builtin_dll,
    unixcall_wine_dbg_write,
    unixcall_wine_server_call,
    unixcall_wine_server_fd_to_handle,
    unixcall_wine_server_handle_to_fd,
    unixcall_wine_spawnvp,
    system_time_precise,
    macrunner_hb_register_import_thunk,
    macrunner_hb_x64_dll_entry,
    macrunner_hb_x64_thread_entry,
    macrunner_hb_x64_import_context,
    pe_module_loaded,
    macrunner_guest_peb_observe,
    macrunner_cpu_backend_query,
};


BOOL simulate_writecopy;  /* CW Hack 22996 */

static void hacks_init(void)
{
    const char *env_str;

    env_str = getenv("WINE_SIMULATE_WRITECOPY");
    if (env_str) simulate_writecopy = atoi(env_str);
}


#ifdef _WIN64

static NTSTATUS wow64_load_so_dll( void *args ) { return STATUS_INVALID_IMAGE_FORMAT; }
static NTSTATUS wow64_unwind_builtin_dll( void *args ) { return STATUS_UNSUCCESSFUL; }
static NTSTATUS wow64_macrunner_hb_register_import_thunk( void *args ) { return STATUS_NOT_IMPLEMENTED; }
static NTSTATUS wow64_macrunner_hb_x64_dll_entry( void *args ) { return STATUS_NOT_IMPLEMENTED; }
static NTSTATUS wow64_macrunner_hb_x64_thread_entry( void *args ) { return STATUS_NOT_IMPLEMENTED; }
static NTSTATUS wow64_macrunner_hb_x64_import_context( void *args ) { return STATUS_NOT_IMPLEMENTED; }
static NTSTATUS wow64_pe_module_loaded( void *args ) { return STATUS_NOT_IMPLEMENTED; }

const unixlib_entry_t unix_call_wow64_funcs[] =
{
    wow64_load_so_dll,
    wow64_unwind_builtin_dll,
    wow64_wine_dbg_write,
    wow64_wine_server_call,
    wow64_wine_server_fd_to_handle,
    wow64_wine_server_handle_to_fd,
    wow64_wine_spawnvp,
    system_time_precise,
    wow64_macrunner_hb_register_import_thunk,
    wow64_macrunner_hb_x64_dll_entry,
    wow64_macrunner_hb_x64_thread_entry,
    wow64_macrunner_hb_x64_import_context,
    wow64_pe_module_loaded,
    macrunner_guest_peb_observe,
    macrunner_cpu_backend_query,
};

#endif  /* _WIN64 */


static inline char *prepend( char *buffer, const char *str, size_t len )
{
    return memcpy( buffer - len, str, len );
}

static inline char *prepend_build_dir_path( char *ptr, const char *ext, const char *arch_dir,
                                            const char *top_dir, const char *build_dir )
{
    char *name = ptr;
    unsigned int namelen = strlen(name), extlen = strlen(ext);

    if (namelen > extlen && !strcmp( name + namelen - extlen, ext )) namelen -= extlen;
    ptr = prepend( ptr, arch_dir, strlen(arch_dir) );
    ptr = prepend( ptr, name, namelen );
    ptr = prepend( ptr, top_dir, strlen(top_dir) );
    ptr = prepend( ptr, build_dir, strlen(build_dir) );
    return ptr;
}


/***********************************************************************
 *	open_dll_file
 *
 * Open a file for a new dll. Helper for open_builtin_pe_file.
 */
static NTSTATUS open_dll_file( const char *name, OBJECT_ATTRIBUTES *attr, HANDLE *mapping )
{
    LARGE_INTEGER size;
    NTSTATUS status;
    HANDLE handle;

    if ((status = open_unix_file( &handle, name, GENERIC_READ | SYNCHRONIZE, attr, 0,
                                  FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_OPEN,
                                  FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0 )))
    {
        if (status != STATUS_OBJECT_PATH_NOT_FOUND && status != STATUS_OBJECT_NAME_NOT_FOUND)
        {
            /* if the file exists but failed to open, report the error */
            struct stat st;
            if (!stat( name, &st )) return status;
        }
        /* otherwise continue searching */
        return STATUS_DLL_NOT_FOUND;
    }

    size.QuadPart = 0;
    status = NtCreateSection( mapping, STANDARD_RIGHTS_REQUIRED | SECTION_QUERY |
                              SECTION_MAP_READ | SECTION_MAP_EXECUTE,
                              NULL, &size, PAGE_EXECUTE_READ, SEC_IMAGE, handle );
    NtClose( handle );
    return status;
}


/***********************************************************************
 *           open_builtin_pe_file
 */
static NTSTATUS open_builtin_pe_file( const char *name, OBJECT_ATTRIBUTES *attr, void **module,
                                      SIZE_T *size, SECTION_IMAGE_INFORMATION *image_info,
                                      ULONG_PTR limit_low, ULONG_PTR limit_high,
                                      WORD machine, BOOL prefer_native, off_t offset )
{
    NTSTATUS status;
    HANDLE mapping;

    *module = NULL;
    status = open_dll_file( name, attr, &mapping );
    if (!status)
    {
        status = virtual_map_builtin_module( mapping, module, size, image_info,
                                             limit_low, limit_high, machine, prefer_native, offset );
        NtClose( mapping );
    }
    return status;
}


/***********************************************************************
 *           find_builtin_dll
 */
static NTSTATUS find_builtin_dll( UNICODE_STRING *nt_name, ANSI_STRING *exp_name, void **module,
                                  SIZE_T *size_ptr, SECTION_IMAGE_INFORMATION *image_info,
                                  ULONG_PTR limit_low, ULONG_PTR limit_high, USHORT search_machine,
                                  USHORT load_machine, BOOL prefer_native, off_t offset )
{
    unsigned int i, pos, len, namepos = 0, maxlen = 0;
    char *ptr = NULL, *file, *ext = NULL;
    const char *pe_dir = get_pe_dir( search_machine );
    const char *so_dir = get_so_dir( current_machine );
    const char *pe_build_dir = build_dir;
    OBJECT_ATTRIBUTES attr;
    NTSTATUS status = STATUS_DLL_NOT_FOUND;
    BOOL found_image = FALSE;
    /* лейн FEX-N3: CPU-модуль опознаём ОДИН раз, чтобы не платить за это на каждом builtin */
    BOOL macrunner_is_cpu = macrunner_is_cpu_backend_module( nt_name, exp_name );
    char *macrunner_cpu_pe_path = NULL;
    char *macrunner_cpu_unix_path = NULL;   /* ШАГ-2: спутник FEX под СВОИМ именем */

    InitializeObjectAttributes( &attr, nt_name, 0, 0, NULL );

    /* ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ MACRUNNER_CPU_BACKEND=none: CPU-модуль не выдаём ВООБЩЕ.
     * Нужен, чтобы smoke не мог «пройти сам» на прежнем backend-е. */
    if (macrunner_is_cpu && macrunner_cpu_backend == MACRUNNER_CPU_BACKEND_NONE)
    {
        fprintf( stderr, "macrunner-cpu-backend-load: backend=none REFUSED name=%s\n",
                 debugstr_us(nt_name) );
        return STATUS_DLL_NOT_FOUND;
    }

    if (!exp_name || !exp_name->Length)
    {
        len = nt_name->Length / sizeof(WCHAR);

        /* CX HACK 20810: in wow64/32-bit-bottle mode, use 32-bit builtin EXEs */
        if (wow64_using_32bit_prefix &&
            len > 4 &&
            (nt_name->Buffer[len-3] == 'e' &&
             nt_name->Buffer[len-2] == 'x' &&
             nt_name->Buffer[len-1] == 'e'))
            pe_dir = get_pe_dir( IMAGE_FILE_MACHINE_I386 );

        for (i = 0; i < len; i++)
            if (nt_name->Buffer[i] == '/' || nt_name->Buffer[i] == '\\') namepos = i + 1;
        len -= namepos;
        if (!len) return STATUS_DLL_NOT_FOUND;
    }
    else len = exp_name->Length;

    if (build_dir)
    {
        if (alt_build_dir && search_machine == get_alt_machine( current_machine ))
            pe_build_dir = alt_build_dir;
        maxlen = max( strlen(build_dir), strlen(pe_build_dir) ) + sizeof("/programs/") + len;
    }
    maxlen = max( maxlen, dll_path_maxlen + 1 ) + len + sizeof("/aarch64-windows") + sizeof(".so");

    if (!(file = malloc( maxlen ))) return STATUS_NO_MEMORY;

    pos = maxlen - len - sizeof(".so");
    if (!exp_name || !exp_name->Length)
    {
        /* we don't want to depend on the current codepage here */
        for (i = 0; i < len; i++)
        {
            if (nt_name->Buffer[namepos + i] > 127) goto done;
            file[pos + i] = (char)nt_name->Buffer[namepos + i];
        }
    }
    else memcpy( file + pos, exp_name->Buffer, len );

    for (i = 0; i < len; i++)
    {
        if (file[pos + i] >= 'A' && file[pos + i] <= 'Z') file[pos + i] += 'a' - 'A';
        else if (file[pos + i] == '.') ext = file + pos + i;
    }
    file[pos + len] = 0;
    file[--pos] = '/';

    TRACE( "looking for %s for file %s\n", debugstr_a(file + pos + 1), debugstr_us(nt_name) );

#if defined(__APPLE__)
    /* MacRunner DXMT-routing diagnostic (env-gated): the x64-guest's DXGI/D3D11 calls dispatch to the
     * native ARM64 twin, which loaded as WINE's (not DXMT's) -> wined3d -> no Metal device. Log every
     * find_builtin_dll resolution of a graphics frontend to see the machine/pe_dir/Fix-A outcome. */
    if (getenv( "MACRUNNER_DIAG_DXMT" ))
    {
        const char *gname = file + pos + 1;
        if (!strcmp(gname,"d3d11.dll") || !strcmp(gname,"dxgi.dll") ||
            !strcmp(gname,"d3d10core.dll") || !strcmp(gname,"d3d9.dll"))
            fprintf( stderr, "macrunner-diag-dxmt-entry: name=%s search_machine=0x%x load_machine=0x%x "
                     "pe_dir=%s prefer_native=%d dxmt_root=%s\n",
                     gname, search_machine, load_machine, pe_dir, prefer_native,
                     getenv("MACRUNNER_DXMT_ROOT") ? getenv("MACRUNNER_DXMT_ROOT") : "(null)" );
    }
#endif

    if (build_dir)
    {
        /* try as a dll */
        ptr = prepend_build_dir_path( file + pos, ".dll", pe_dir, "/dlls", pe_build_dir );
        status = open_builtin_pe_file( ptr, &attr, module, size_ptr, image_info,
                                       limit_low, limit_high, load_machine, prefer_native, offset );
        ptr = prepend_build_dir_path( file + pos, ".dll", "", "/dlls", build_dir );
        if (status != STATUS_DLL_NOT_FOUND) goto done;
        status = open_builtin_so_file( ptr, &attr, module, image_info,
                                       search_machine, load_machine, prefer_native );
        if (status != STATUS_DLL_NOT_FOUND) goto done;

        /* now as a program */
        ptr = prepend_build_dir_path( file + pos, ".exe", pe_dir, "/programs", pe_build_dir );
        status = open_builtin_pe_file( ptr, &attr, module, size_ptr, image_info,
                                       limit_low, limit_high, load_machine, prefer_native, offset );
        ptr = prepend_build_dir_path( file + pos, ".exe", "", "/programs", build_dir );
        if (status != STATUS_DLL_NOT_FOUND) goto done;
        status = open_builtin_so_file( ptr, &attr, module, image_info,
                                       search_machine, load_machine, prefer_native );
        if (status != STATUS_DLL_NOT_FOUND) goto done;
    }

    /* MacRunner HyperBridge: DXMT graphics frontends (d3d11/dxgi/d3d10core/d3d9) carry
     * the "Wine builtin DLL" marker, so load_builtin() resolves them as builtins and
     * find_builtin_dll otherwise picks wine's OWN d3d11/dxgi twins from dll_dir (searched
     * before WINEDLLPATH) -> wined3d -> wined3d_create()==NULL on macOS ->
     * DXGI_ERROR_UNSUPPORTED (0x887a0004). When MACRUNNER_DXMT_ROOT points at a dual-arch
     * overlay (<arch>-windows/<dll>), search it FIRST but ONLY for these exact graphics
     * names, so core DLLs (kernel32 etc.) and native-builtin dependency resolution are
     * untouched. The overlay is also in WINEDLLPATH, so dll_path_maxlen already covers its
     * length; the strlen guard keeps the file buffer safe if it ever is not. winemetal is
     * deliberately excluded: wine has no winemetal twin (no shadowing) and its unixlib lives
     * in <root>/aarch64-unix, which only the normal so_dir search resolves. */
    {
        const char *dxmt_root = getenv( "MACRUNNER_DXMT_ROOT" );
        const char *name = file + pos + 1; /* lowercased basename, NUL-terminated */
        if (dxmt_root && dxmt_root[0] && strlen( dxmt_root ) <= dll_path_maxlen &&
            (!strcmp( name, "d3d11.dll" ) || !strcmp( name, "dxgi.dll" ) ||
             !strcmp( name, "d3d10core.dll" ) || !strcmp( name, "d3d9.dll" )))
        {
            /* <root>/<arch>-windows/<name> */
            ptr = prepend( prepend( file + pos, pe_dir, strlen(pe_dir) ), dxmt_root, strlen(dxmt_root) );
            status = open_builtin_pe_file( ptr, &attr, module, size_ptr, image_info, limit_low,
                                           limit_high, load_machine, prefer_native, offset );
#if defined(__APPLE__)
            if (getenv( "MACRUNNER_DIAG_DXMT" ))
                fprintf( stderr, "macrunner-diag-dxmt: name=%s pe_dir=%s try1=%s status1=0x%x\n",
                         name, pe_dir, ptr, (unsigned int)status );
#endif
            if (NT_SUCCESS(status)) goto done;
            /* <root>/<name> (overlay set directly to a machine dir) */
            ptr = prepend( file + pos, dxmt_root, strlen(dxmt_root) );
            status = open_builtin_pe_file( ptr, &attr, module, size_ptr, image_info, limit_low,
                                           limit_high, load_machine, prefer_native, offset );
#if defined(__APPLE__)
            if (getenv( "MACRUNNER_DIAG_DXMT" ))
                fprintf( stderr, "macrunner-diag-dxmt: name=%s try2=%s status2=0x%x\n",
                         name, ptr, (unsigned int)status );
#endif
            if (NT_SUCCESS(status)) goto done;
            status = STATUS_DLL_NOT_FOUND; /* not in overlay -> fall through to normal search */
        }
    }

    /* ★ лейн FEX-N3 2026-09-07 — CPU-модуль берётся из overlay ОДНОЙ СОГЛАСОВАННОЙ ПАРОЙ.
     *
     * Почему одного WINEDLLPATH НЕДОСТАТОЧНО: set_dll_path (loader.c:573) кладёт dll_dir
     * ПЕРВЫМ и только потом элементы WINEDLLPATH, а цикл ниже берёт первое совпадение.
     * Значит xtajit.dll из самого диста победил бы overlay и прогон молча ушёл бы на
     * HyperBridge — ровно тот тихий откат, ради которого заведён MACRUNNER_CPU_BACKEND.
     * (Тем же способом решена задача для DXMT — блок MACRUNNER_DXMT_ROOT выше.)
     *
     * Затрагиваются РОВНО два имени CPU-модуля; всё остальное ищется по-прежнему.
     * PE берётся из <root>/<arch>-windows, спутник — из <root>/<arch>-unix, то есть пара
     * приходит из ОДНОГО корня, а несовпадение basename даёт отказ загрузки (см. done:).
     * Корень обязан быть и в WINEDLLPATH — тогда dll_path_maxlen покрывает его длину;
     * если нет, отказываем громко, а не портим буфер. */
    if (macrunner_is_cpu)
    {
        const char *fex_root = getenv( "MACRUNNER_FEX_OVERLAY" );

        if (fex_root && fex_root[0])
        {
            if (strlen( fex_root ) > dll_path_maxlen)
            {
                fprintf( stderr, "macrunner-cpu-backend-load: overlay=%s ОТВЕРГНУТ — длина %zu > "
                         "dll_path_maxlen %zu; добавь корень в WINEDLLPATH\n",
                         fex_root, strlen( fex_root ), dll_path_maxlen );
                return STATUS_DLL_NOT_FOUND;
            }
            /* ★ ШАГ-2: каталог PE берём как обычно из search_machine, но обе половины FEX —
             * ARM64/ARM64EC и лежат в каталоге ТЕКУЩЕЙ машины.  Вспомогательные процессы
             * (native ARM64) спрашивают xtajit64 с pe_dir=x86_64-windows, и прежде это
             * лечили КОПИЕЙ провайдера в overlay/x86_64-windows — раскладка Астры такую
             * копию прямо запрещает.  Вместо копии — вторая попытка по current_machine. */
            {
                const char *fex_pe_dir[2];
                unsigned int try_i;

                fex_pe_dir[0] = pe_dir;
                fex_pe_dir[1] = get_pe_dir( current_machine );
                status = STATUS_DLL_NOT_FOUND;
                for (try_i = 0; try_i < 2; try_i++)
                {
                    if (try_i && !strcmp( fex_pe_dir[0], fex_pe_dir[1] )) break;
                    ptr = prepend( prepend( file + pos, fex_pe_dir[try_i], strlen(fex_pe_dir[try_i]) ),
                                   fex_root, strlen(fex_root) );
                    status = open_builtin_pe_file( ptr, &attr, module, size_ptr, image_info, limit_low,
                                                   limit_high, load_machine, prefer_native, offset );
                    fprintf( stderr, "macrunner-cpu-backend-load: overlay try%u pe=%s status=0x%08x\n",
                             try_i, ptr, (unsigned int)status );
                    if (NT_SUCCESS(status)) break;
                }
            }
            if (NT_SUCCESS(status))
            {
                const char *soname = macrunner_fex_unix_name( file + pos + 1 );

                macrunner_cpu_pe_path = strdup( ptr );
                /* спутник ищем в so_dir ТОГО ЖЕ корня, не рядом с PE */
                if (soname)
                {
                    size_t need = strlen(fex_root) + strlen(so_dir) + 1 + strlen(soname) + 1;
                    if ((macrunner_cpu_unix_path = malloc( need )))
                        snprintf( macrunner_cpu_unix_path, need, "%s%s/%s", fex_root, so_dir, soname );
                }
                ptr = prepend( prepend( file + pos, so_dir, strlen(so_dir) ), fex_root, strlen(fex_root) );
                goto done;
            }
            /* overlay задан, но пары в нём нет — это ошибка раскладки, а не повод
             * тихо взять CPU-модуль из диста */
            status = STATUS_DLL_NOT_FOUND;
            goto done;
        }
    }

    for (i = 0; dll_paths[i]; i++)
    {
        ptr = file + pos;
        ptr = prepend( ptr, pe_dir, strlen(pe_dir) );
        ptr = prepend( ptr, dll_paths[i], strlen(dll_paths[i]) );
        status = open_builtin_pe_file( ptr, &attr, module, size_ptr, image_info, limit_low, limit_high,
                                       load_machine, prefer_native, offset );
        if (macrunner_is_cpu && NT_SUCCESS(status))
        {
            free( macrunner_cpu_pe_path );
            macrunner_cpu_pe_path = strdup( ptr );
        }
        /* use so dir for unix lib */
        ptr = file + pos;
        ptr = prepend( ptr, so_dir, strlen(so_dir) );
        ptr = prepend( ptr, dll_paths[i], strlen(dll_paths[i]) );
        if (status != STATUS_DLL_NOT_FOUND) goto done;
        status = open_builtin_so_file( ptr, &attr, module, image_info,
                                       search_machine, load_machine, prefer_native );
        if (status != STATUS_DLL_NOT_FOUND) goto done;
        ptr = prepend( file + pos, dll_paths[i], strlen(dll_paths[i]) );
        status = open_builtin_pe_file( ptr, &attr, module, size_ptr, image_info, limit_low, limit_high,
                                       load_machine, prefer_native, offset );
        if (status == STATUS_NOT_SUPPORTED)
        {
            found_image = TRUE;
            continue;
        }
        if (status != STATUS_DLL_NOT_FOUND) goto done;
        status = open_builtin_so_file( ptr, &attr, module, image_info,
                                       search_machine, load_machine, prefer_native );
        if (status == STATUS_NOT_SUPPORTED) found_image = TRUE;
        else if (status != STATUS_DLL_NOT_FOUND) goto done;
    }

    if (found_image) status = STATUS_NOT_SUPPORTED;
    WARN( "cannot find builtin library for %s\n", debugstr_us(nt_name) );
 done:
    if (NT_SUCCESS(status) && ext)
    {
        strcpy( ext, ".so" );
        /* ШАГ-2: у модуля процессора на пути FEX спутник назван по-своему (см.
         * macrunner_fex_unix_name) — иначе dyld отдаёт одноимённый спутник HyperBridge. */
        load_builtin_unixlib( *module, macrunner_cpu_unix_path ? macrunner_cpu_unix_path : ptr );
    }
    /* ★ лейн FEX-N3: БЕЗУСЛОВНЫЙ прибор личности CPU-модуля. Печатает на ЛЮБОМ backend-е,
     * иначе его молчание неотличимо от «сюда не дошли». Плюс жёсткая проверка ПАРЫ:
     * upstream FEX ИГНОРИРУЕТ результат FEX::Windows::UnixLib::Init (Module.cpp:538) —
     * без спутника он молча живёт с нулевым диспетчером и каждый Call даёт
     * STATUS_NOT_SUPPORTED. Такое расхождение обязано быть ОТКАЗОМ ЗАГРУЗКИ. */
    if (macrunner_is_cpu)
    {
        struct stat st;
        const char *unix_path = (NT_SUCCESS(status) && ext)
                                ? (macrunner_cpu_unix_path ? macrunner_cpu_unix_path : ptr) : NULL;
        int unix_present = (unix_path && !stat( unix_path, &st ));

        fprintf( stderr, "macrunner-cpu-backend-load: backend=%s name=%s status=0x%08x "
                 "pe=%s unix=%s unix_present=%d\n",
                 macrunner_cpu_backend_name( macrunner_cpu_backend ), debugstr_us(nt_name),
                 (unsigned int)status, macrunner_cpu_pe_path ? macrunner_cpu_pe_path : "(none)",
                 unix_path ? unix_path : "(none)", unix_present );

        if (NT_SUCCESS(status) && macrunner_cpu_pe_path && !unix_present)
        {
            fprintf( stderr, "macrunner-cpu-backend-load: PAIR MISMATCH — спутник %s отсутствует "
                     "рядом с %s, загрузка CPU-модуля ОТВЕРГНУТА\n",
                     unix_path ? unix_path : "(none)", macrunner_cpu_pe_path );
            NtUnmapViewOfSection( NtCurrentProcess(), *module );
            *module = NULL;
            status = STATUS_DLL_NOT_FOUND;
        }
        free( macrunner_cpu_pe_path );
    }
    free( macrunner_cpu_unix_path );
    free( file );
    return status;
}


/***********************************************************************
 *           load_builtin
 *
 * Load the builtin dll if specified by load order configuration.
 * Return STATUS_IMAGE_ALREADY_LOADED if we should keep the native one that we have found.
 */
NTSTATUS load_builtin( const struct pe_image_info *image_info, UNICODE_STRING *nt_name,
                       ANSI_STRING *exp_name, USHORT machine, SECTION_IMAGE_INFORMATION *info,
                       void **module, SIZE_T *size, ULONG_PTR limit_low, ULONG_PTR limit_high,
                       off_t offset )
{
    NTSTATUS status;
    USHORT search_machine = image_info->machine;
    enum loadorder loadorder = get_load_order( nt_name );
    BOOL force_current_machine_builtin = FALSE;

    if (loadorder == LO_DISABLED) return STATUS_DLL_NOT_FOUND;

    if (image_info->wine_builtin)
    {
        if (loadorder == LO_NATIVE) return STATUS_DLL_NOT_FOUND;
        loadorder = LO_BUILTIN_NATIVE;  /* load builtin, then fallback to the file we found */
    }
    else if (image_info->wine_fakedll)
    {
        TRACE( "%s is a fake Wine dll\n", debugstr_us(nt_name) );
        if (loadorder == LO_NATIVE) return STATUS_DLL_NOT_FOUND;
        loadorder = LO_BUILTIN;  /* builtin with no fallback since mapping a fake dll is not useful */
    }

    if (is_arm64ec() && image_info->is_hybrid && search_machine == IMAGE_FILE_MACHINE_AMD64)
        search_machine = current_machine;

#if defined(__APPLE__)
    {
        static int lb_diag_n;
        if (getenv( "MACRUNNER_DIAG_DXMT" ) && image_info->is_hybrid && lb_diag_n++ < 60)
            fprintf( stderr, "macrunner-diag-loadbuiltin: nt=%s image_mach=0x%x search_mach=0x%x req_mach=0x%x "
                     "is_hybrid=%d is_arm64ec=%d wine_builtin=%d loadorder=%d main_mach=0x%x\n",
                     debugstr_us(nt_name),
                     image_info->machine, search_machine, machine, image_info->is_hybrid, is_arm64ec(),
                     image_info->wine_builtin, loadorder, main_image_info.Machine );
    }
#endif

#if defined(__APPLE__) && defined(__aarch64__)
    if (macrunner_hb_x64_loader &&
        current_machine == IMAGE_FILE_MACHINE_ARM64 &&
        image_info->machine == IMAGE_FILE_MACHINE_AMD64 &&
        macrunner_hb_builtin_name_matches( nt_name, exp_name, "xtajit64.dll" ))
    {
        fprintf( stderr, "MacRunner x64-on-ARM64 using current-machine xtajit64 builtin for %s\n",
               debugstr_us(nt_name) );
        search_machine = current_machine;
        machine = current_machine;
        force_current_machine_builtin = TRUE;
    }
    else if (macrunner_hb_x64_loader &&
        current_machine == IMAGE_FILE_MACHINE_ARM64 &&
        main_image_info.Machine == IMAGE_FILE_MACHINE_ARM64 &&
        image_info->machine == IMAGE_FILE_MACHINE_AMD64 &&
        (!machine || machine == current_machine))
    {
        fprintf( stderr, "MacRunner native ARM64 helper using current-machine builtin for wrong-arch prefix image %s\n",
               debugstr_us(nt_name) );
        search_machine = current_machine;
        machine = current_machine;
        force_current_machine_builtin = TRUE;
    }

    if (macrunner_hb_x64_loader &&
        current_machine == IMAGE_FILE_MACHINE_ARM64 &&
        main_image_info.Machine == IMAGE_FILE_MACHINE_I386 &&
        image_info->machine == IMAGE_FILE_MACHINE_AMD64 &&
        !macrunner_hb_is_wow64_host_builtin( nt_name, exp_name ))
    {
        fprintf( stderr, "MacRunner HyperBridge PE32 builtin using i386 lane for wrong-arch prefix image %s\n",
               debugstr_us(nt_name) );
        search_machine = IMAGE_FILE_MACHINE_I386;
        machine = IMAGE_FILE_MACHINE_I386;
        force_current_machine_builtin = TRUE;
    }
#endif

    switch (loadorder)
    {
    case LO_NATIVE:
    case LO_NATIVE_BUILTIN:
        return STATUS_IMAGE_ALREADY_LOADED;
    case LO_BUILTIN:
        return find_builtin_dll( nt_name, exp_name, module, size, info, limit_low, limit_high,
                                 search_machine, machine, FALSE, offset );
    default:
        status = find_builtin_dll( nt_name, exp_name, module, size, info, limit_low, limit_high,
                                   search_machine, machine, (loadorder == LO_DEFAULT), offset );
        if (status == STATUS_DLL_NOT_FOUND || status == STATUS_NOT_SUPPORTED)
        {
            if (force_current_machine_builtin) return status;
            /* ★★★ ШАГ-2 08.09.2026 — ОТКАТ НА ОБРАЗ ИЗ ПРЕФИКСА ДЛЯ МОДУЛЯ ПРОЦЕССОРА ЗАПРЕЩЁН.
             *
             * STATUS_IMAGE_ALREADY_LOADED означает «оставь тот файл, что уже открыт», а
             * открыт при этом файл ПРЕФИКСА — `drive_c/windows/system32/xtajit*.dll`, куда
             * sync-prefix-from-dist.sh кладёт копию HyperBridge.  То есть отказ загрузки
             * НАШЕГО провайдера тихо превращался в загрузку ЧУЖОГО, минуя find_builtin_dll
             * вместе со всеми его проверками пары и знака.  N3 (§3) видел это как
             * `BTCpuProcessInit(HB)=1` на всех трёх отрицательных контролях и назвал дырой.
             *
             * При выбранном не-HB трансляторе отказ обязан быть ГРОМКИМ. */
            if (macrunner_is_cpu_backend_module( nt_name, exp_name ) &&
                macrunner_cpu_backend != MACRUNNER_CPU_BACKEND_HB)
            {
                fprintf( stderr, "macrunner-cpu-backend-load: ОТКАТ НА ПРЕФИКС ЗАПРЕЩЁН "
                         "backend=%s name=%s status=0x%08x\n",
                         macrunner_cpu_backend_name( macrunner_cpu_backend ),
                         debugstr_us(nt_name), (unsigned int)status );
                return status;
            }
            return STATUS_IMAGE_ALREADY_LOADED;
        }
        return status;
    }
}


/***************************************************************************
 *	get_machine_wow64_dir
 *
 * cf. GetSystemWow64Directory2.
 */
static const WCHAR *get_machine_wow64_dir( WORD machine )
{
    static const WCHAR system32[] = {'\\','?','?','\\','C',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m','3','2','\\',0};
    static const WCHAR syswow64[] = {'\\','?','?','\\','C',':','\\','w','i','n','d','o','w','s','\\','s','y','s','w','o','w','6','4','\\',0};
    static const WCHAR sysarm32[] = {'\\','?','?','\\','C',':','\\','w','i','n','d','o','w','s','\\','s','y','s','a','r','m','3','2','\\',0};

    if (machine == native_machine || wow64_using_32bit_prefix) machine = IMAGE_FILE_MACHINE_TARGET_HOST;

    switch (machine)
    {
    case IMAGE_FILE_MACHINE_TARGET_HOST: return system32;
    case IMAGE_FILE_MACHINE_AMD64:
        if (macrunner_hb_x64_guest_process())
            return system32;
        return NULL;
    case IMAGE_FILE_MACHINE_I386:        return syswow64;
    case IMAGE_FILE_MACHINE_ARMNT:       return sysarm32;
    default: return NULL;
    }
}

static BOOL macrunner_hb_same_basename( const UNICODE_STRING *path, const WCHAR *name )
{
    unsigned int i, base = 0, len = path->Length / sizeof(WCHAR);
    unsigned int name_len = wcslen( name );

    for (i = 0; i < len; i++)
        if (path->Buffer[i] == '/' || path->Buffer[i] == '\\') base = i + 1;

    return len - base == name_len && !wcsnicmp( path->Buffer + base, name, name_len );
}

static BOOL macrunner_hb_is_system_helper_path( const UNICODE_STRING *path, BOOL allow_windows_dir )
{
    static const WCHAR windows[] = {'\\','?','?','\\','C',':','\\','w','i','n','d','o','w','s','\\',0};
    const WCHAR *system32 = get_machine_wow64_dir( IMAGE_FILE_MACHINE_TARGET_HOST );
    unsigned int i, base = 0, len = path->Length / sizeof(WCHAR);
    unsigned int system32_len = wcslen( system32 );
    unsigned int windows_len = wcslen( windows );

    for (i = 0; i < len; i++)
        if (path->Buffer[i] == '/' || path->Buffer[i] == '\\') base = i + 1;

    if (base == system32_len && !wcsnicmp( path->Buffer, system32, system32_len )) return TRUE;
    return allow_windows_dir && base == windows_len && !wcsnicmp( path->Buffer, windows, windows_len );
}

BOOL macrunner_hb_prefer_native_helper_exe( const UNICODE_STRING *path )
{
    static const WCHAR wineboot[] = {'w','i','n','e','b','o','o','t','.','e','x','e',0};
    static const WCHAR services[] = {'s','e','r','v','i','c','e','s','.','e','x','e',0};
    static const WCHAR explorer[] = {'e','x','p','l','o','r','e','r','.','e','x','e',0};
    static const WCHAR rpcss[] = {'r','p','c','s','s','.','e','x','e',0};
    static const WCHAR plugplay[] = {'p','l','u','g','p','l','a','y','.','e','x','e',0};
    static const WCHAR winedevice[] = {'w','i','n','e','d','e','v','i','c','e','.','e','x','e',0};
    static const WCHAR svchost[] = {'s','v','c','h','o','s','t','.','e','x','e',0};
    BOOL explorer_path;

    if (!path || !path->Buffer || !path->Length) return FALSE;
    if (current_machine != IMAGE_FILE_MACHINE_ARM64) return FALSE;
    if (!macrunner_hb_x64_loader_enabled()) return FALSE;

    explorer_path = macrunner_hb_same_basename( path, explorer );
    if (!explorer_path &&
        !macrunner_hb_same_basename( path, wineboot ) &&
        !macrunner_hb_same_basename( path, services ) &&
        !macrunner_hb_same_basename( path, plugplay ) &&
        !macrunner_hb_same_basename( path, winedevice ) &&
        !macrunner_hb_same_basename( path, svchost ) &&
        !macrunner_hb_same_basename( path, rpcss ))
        return FALSE;

    return macrunner_hb_is_system_helper_path( path, explorer_path );
}


/***************************************************************************
 *	is_builtin_path
 *
 * Check if path is inside a system directory, to support loading builtins
 * when the corresponding file doesn't exist yet.
 */
BOOL is_builtin_path( const UNICODE_STRING *path, WORD *machine )
{
    unsigned int i, len = path->Length / sizeof(WCHAR), dirlen;
    const WCHAR *sysdir, *p = path->Buffer;

    /* only fake builtin existence during prefix bootstrap */
    if (!is_prefix_bootstrap) return FALSE;

    for (i = 0; i < supported_machines_count; i++)
    {
        sysdir = get_machine_wow64_dir( supported_machines[i] );
        if (!sysdir) continue;
        dirlen = wcslen( sysdir );
        if (len <= dirlen) continue;
        if (wcsnicmp( p, sysdir, dirlen )) continue;
        /* check for remaining path components */
        for (p += dirlen, len -= dirlen; len; p++, len--) if (*p == '\\') return FALSE;
        *machine = supported_machines[i];
        return TRUE;
    }
    return FALSE;
}


/***********************************************************************
 *           open_main_image
 */
static NTSTATUS open_main_image( UNICODE_STRING *nt_name, void **module, SECTION_IMAGE_INFORMATION *info,
                                 enum loadorder loadorder, USHORT machine )
{
    OBJECT_ATTRIBUTES attr;
    SIZE_T size = 0;
    char *unix_name;
    NTSTATUS status;
    HANDLE mapping;
    UNICODE_STRING true_nt_name;

    if (loadorder == LO_DISABLED) NtTerminateProcess( GetCurrentProcess(), STATUS_DLL_NOT_FOUND );

    InitializeObjectAttributes( &attr, nt_name, OBJ_CASE_INSENSITIVE, 0, NULL );
    if (get_nt_and_unix_names( &attr, &true_nt_name, &unix_name, FILE_OPEN, FALSE )) return STATUS_DLL_NOT_FOUND;

    status = open_dll_file( unix_name, &attr, &mapping );
    if (!status)
    {
        status = virtual_map_module( mapping, module, &size, info, 0, 0, machine );
        if (status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH && info->ComPlusNativeReady)
        {
            info->Machine = native_machine;
            status = STATUS_SUCCESS;
        }
        NtClose( mapping );
    }
    else if (status == STATUS_INVALID_IMAGE_NOT_MZ && loadorder != LO_NATIVE)
    {
        status = open_main_image_so_file( unix_name, attr.ObjectName, module, info );
    }
    free( unix_name );
    free( true_nt_name.Buffer );
    return status;
}


/***********************************************************************
 *           load_main_exe
 */
NTSTATUS load_main_exe( UNICODE_STRING *nt_name, USHORT load_machine, void **module )
{
    enum loadorder loadorder = get_load_order( nt_name );
    unsigned int status;
    SIZE_T size;
    USHORT search_machine;

    if (macrunner_hb_prefer_native_helper_exe( nt_name ))
    {
        fprintf( stderr, "MacRunner loading native helper builtin for %s\n", debugstr_us(nt_name) );
        status = find_builtin_dll( nt_name, NULL, module, &size, &main_image_info, 0, 0,
                                   current_machine, current_machine, FALSE, 0 );
        if (status == STATUS_IMAGE_NOT_AT_BASE) status = virtual_relocate_module( *module );
        if (status != STATUS_DLL_NOT_FOUND && status != STATUS_NOT_SUPPORTED) return status;
    }

    status = open_main_image( nt_name, module, &main_image_info, loadorder, load_machine );
    if (status != STATUS_DLL_NOT_FOUND) return status;

    /* if path is in system dir, we can load the builtin even if the file itself doesn't exist */
    if (loadorder != LO_NATIVE && is_builtin_path( nt_name, &search_machine ))
        status = find_builtin_dll( nt_name, NULL, module, &size, &main_image_info, 0, 0,
                                   search_machine, load_machine, FALSE, 0 );
    return status;
}


/***********************************************************************
 *           load_start_exe
 *
 * Load start.exe as main image.
 */
NTSTATUS load_start_exe( UNICODE_STRING *nt_name, void **module )
{
    static const WCHAR startW[] = {'s','t','a','r','t','.','e','x','e',0};
    unsigned int status;
    SIZE_T size;
    WCHAR *image = malloc( sizeof("\\??\\C:\\windows\\system32\\start.exe") * sizeof(WCHAR) );

    if (!image) return STATUS_NO_MEMORY;
    wcscpy( image, get_machine_wow64_dir( current_machine ));
    wcscat( image, startW );
    init_unicode_string( nt_name, image );
    status = find_builtin_dll( nt_name, NULL, module, &size, &main_image_info, 0, 0, current_machine, 0, FALSE, 0 );
    if (!NT_SUCCESS(status))
    {
        MESSAGE( "wine: failed to load start.exe: %x\n", status );
        NtTerminateProcess( GetCurrentProcess(), status );
    }
    return status;
}

static BOOL module_rva_array_fits_image( ULONG image_size, ULONG rva, ULONG count, size_t elem_size )
{
    if (!count) return TRUE;
    if (!rva || image_size < elem_size || rva > image_size - elem_size) return FALSE;
    return count <= (image_size - rva) / elem_size;
}

static void *module_rva_ptr( HMODULE module, ULONG image_size, ULONG rva, SIZE_T size )
{
    ULONG_PTR base = (ULONG_PTR)module;

    if (image_size > ~(ULONG_PTR)0 - base) return NULL;
    if (rva > image_size || size > image_size - rva) return NULL;
    return (void *)(base + rva);
}

static BOOL module_string_fits_image( HMODULE module, ULONG image_size, ULONG rva )
{
    char *str = module_rva_ptr( module, image_size, rva, 1 );

    if (!str) return FALSE;
    return memchr( str, 0, image_size - rva ) != NULL;
}

static ULONG_PTR find_ordinal_export( HMODULE module, ULONG image_size,
                                      const IMAGE_EXPORT_DIRECTORY *exports, DWORD ordinal )
{
    const DWORD *functions;

    if (!module_rva_array_fits_image( image_size, exports->AddressOfFunctions,
                                      exports->NumberOfFunctions, sizeof(*functions) ))
        return 0;
    if (ordinal >= exports->NumberOfFunctions) return 0;
    functions = module_rva_ptr( module, image_size, exports->AddressOfFunctions,
                                exports->NumberOfFunctions * sizeof(*functions) );
    if (!functions) return 0;
    if (!functions[ordinal] || functions[ordinal] >= image_size) return 0;
    return (ULONG_PTR)module_rva_ptr( module, image_size, functions[ordinal], 1 );
}

static ULONG_PTR find_named_export( HMODULE module, ULONG image_size,
                                    const IMAGE_EXPORT_DIRECTORY *exports, const char *name )
{
    const WORD *ordinals;
    const DWORD *names;
    int min = 0, max;

    if (!exports->NumberOfNames || exports->NumberOfNames > INT_MAX) return 0;
    if (!module_rva_array_fits_image( image_size, exports->AddressOfNameOrdinals,
                                      exports->NumberOfNames, sizeof(*ordinals) ))
        return 0;
    if (!module_rva_array_fits_image( image_size, exports->AddressOfNames,
                                      exports->NumberOfNames, sizeof(*names) ))
        return 0;
    ordinals = module_rva_ptr( module, image_size, exports->AddressOfNameOrdinals,
                               exports->NumberOfNames * sizeof(*ordinals) );
    names = module_rva_ptr( module, image_size, exports->AddressOfNames,
                            exports->NumberOfNames * sizeof(*names) );
    if (!ordinals || !names) return 0;
    max = exports->NumberOfNames - 1;
    while (min <= max)
    {
        int res, pos = (min + max) / 2;
        char *ename;
        if (!module_string_fits_image( module, image_size, names[pos] )) return 0;
        ename = module_rva_ptr( module, image_size, names[pos], 1 );
        if (!ename) return 0;
        if (!(res = strcmp( ename, name )))
            return find_ordinal_export( module, image_size, exports, ordinals[pos] );
        if (res > 0) max = pos - 1;
        else min = pos + 1;
    }
    return 0;
}

static inline void *get_rva( void *module, ULONG_PTR addr )
{
    return (BYTE *)module + addr;
}

static ULONG get_module_image_size( HMODULE module )
{
    const IMAGE_NT_HEADERS *nt = get_rva( module, ((IMAGE_DOS_HEADER *)module)->e_lfanew );

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return ((const IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.SizeOfImage;
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return ((const IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.SizeOfImage;
    return 0;
}

static const void *get_module_data_dir( HMODULE module, ULONG dir, ULONG *size )
{
    const IMAGE_NT_HEADERS *nt = get_rva( module, ((IMAGE_DOS_HEADER *)module)->e_lfanew );
    const IMAGE_DATA_DIRECTORY *data;
    ULONG image_size;

    if (dir >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        const IMAGE_OPTIONAL_HEADER64 *opt = &((const IMAGE_NT_HEADERS64 *)nt)->OptionalHeader;
        if (dir >= opt->NumberOfRvaAndSizes) return NULL;
        if (nt->FileHeader.SizeOfOptionalHeader <
            offsetof( IMAGE_OPTIONAL_HEADER64, DataDirectory ) + (dir + 1) * sizeof(IMAGE_DATA_DIRECTORY))
            return NULL;
        image_size = opt->SizeOfImage;
        data = &((const IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.DataDirectory[dir];
    }
    else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        const IMAGE_OPTIONAL_HEADER32 *opt = &((const IMAGE_NT_HEADERS32 *)nt)->OptionalHeader;
        if (dir >= opt->NumberOfRvaAndSizes) return NULL;
        if (nt->FileHeader.SizeOfOptionalHeader <
            offsetof( IMAGE_OPTIONAL_HEADER32, DataDirectory ) + (dir + 1) * sizeof(IMAGE_DATA_DIRECTORY))
            return NULL;
        image_size = opt->SizeOfImage;
        data = &((const IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.DataDirectory[dir];
    }
    else
        return NULL;
    if (!data->VirtualAddress || !data->Size) return NULL;
    if (data->VirtualAddress >= image_size || data->Size > image_size - data->VirtualAddress) return NULL;
    if (size) *size = data->Size;
    return module_rva_ptr( module, image_size, data->VirtualAddress, data->Size );
}

/***********************************************************************
 *           load_ntdll_functions
 */
static void load_ntdll_functions( HMODULE module )
{
    void **p__wine_syscall_dispatcher;
    void **p__wine_unix_call_dispatcher;
    void **p__wine_unix_call_dispatcher_arm64ec = NULL;
    unixlib_handle_t *p__wine_unixlib_handle;
    const IMAGE_EXPORT_DIRECTORY *exports;
    ULONG image_size, exports_size;

    image_size = get_module_image_size( module );
    exports = get_module_data_dir( module, IMAGE_DIRECTORY_ENTRY_EXPORT, &exports_size );
    assert( image_size && exports && exports_size >= sizeof(*exports) );
    if (!image_size || !exports || exports_size < sizeof(*exports))
        fatal_error( "invalid ntdll export directory\n" );

#define GET_FUNC(name) \
    do { \
        if (!(p##name = (void *)find_named_export( module, image_size, exports, #name ))) \
            fatal_error( "ntdll export %s not found\n", #name ); \
    } while (0)

    GET_FUNC( DbgUiRemoteBreakin );
    GET_FUNC( KiRaiseUserExceptionDispatcher );
    GET_FUNC( KiUserExceptionDispatcher );
    GET_FUNC( KiUserApcDispatcher );
    GET_FUNC( KiUserCallbackDispatcher );
    GET_FUNC( LdrInitializeThunk );
    GET_FUNC( LdrSystemDllInitBlock );
    GET_FUNC( RtlUserThreadStart );
    GET_FUNC( __wine_ctrl_routine );
    GET_FUNC( __wine_syscall_dispatcher );
    GET_FUNC( __wine_unix_call_dispatcher );
    GET_FUNC( __wine_unixlib_handle );
    if (is_arm64ec())
    {
        GET_FUNC( __wine_unix_call_dispatcher_arm64ec );
        GET_FUNC( KiUserEmulationDispatcher );
    }
    *p__wine_syscall_dispatcher = __wine_syscall_dispatcher;
    *p__wine_unixlib_handle = (UINT_PTR)unix_call_funcs;
    if (p__wine_unix_call_dispatcher_arm64ec)
    {
        /* redirect __wine_unix_call_dispatcher to __wine_unix_call_dispatcher_arm64ec */
        *p__wine_unix_call_dispatcher = *p__wine_unix_call_dispatcher_arm64ec;
        *p__wine_unix_call_dispatcher_arm64ec = __wine_unix_call_dispatcher;
    }
    else *p__wine_unix_call_dispatcher = __wine_unix_call_dispatcher;
#undef GET_FUNC

    /* MacRunner 2026-08-03 — hand the PE side a lock-free guest-image lookup.  Resolved WITHOUT
     * GET_FUNC on purpose: GET_FUNC calls fatal_error, and a diagnostic aid must never be able to
     * kill the process at startup just because a stale PE ntdll lacks the export. */
    {
        void **p = (void *)find_named_export( module, image_size, exports,
                                              "macrunner_hb_guest_image_lookup" );
        if (p) *p = macrunner_hb_guest_image_for_pc;
    }
    {
        void **p = (void *)find_named_export( module, image_size, exports,
                                              "macrunner_hb_guest_ctx_lookup" );
        if (p) *p = macrunner_hb_guest_ctx_for_tid;
    }
    /* итерация 143 (лейн УСТАНОВЩИКИ): перечень известных стеков потока — мостовой и
     * отложенный исходный. Тем же необязательным способом: старый PE-ntdll без экспорта
     * просто не получит его и будет вести себя как раньше. */
    {
        void **p = (void *)find_named_export( module, image_size, exports,
                                              "macrunner_hb_known_stack_lookup" );
        if (p) *p = macrunner_hb_known_stack_for_sp;
    }
}


/***********************************************************************
 *           load_ntdll_wow64_functions
 */
static void load_ntdll_wow64_functions( HMODULE module )
{
    const IMAGE_EXPORT_DIRECTORY *exports;
    ULONG image_size, exports_size;

    image_size = get_module_image_size( module );
    exports = get_module_data_dir( module, IMAGE_FILE_EXPORT_DIRECTORY, &exports_size );
    assert( image_size && exports && exports_size >= sizeof(*exports) );
    if (!image_size || !exports || exports_size < sizeof(*exports))
        fatal_error( "invalid wow64 ntdll export directory\n" );

    pLdrSystemDllInitBlock->ntdll_handle = (ULONG_PTR)module;

#define GET_FUNC(name) \
    do { \
        if (!(pLdrSystemDllInitBlock->p##name = find_named_export( module, image_size, exports, #name ))) \
            fatal_error( "wow64 ntdll export %s not found\n", #name ); \
    } while (0)
#define GET_OPTIONAL_FUNC(name) \
    pLdrSystemDllInitBlock->p##name = find_named_export( module, image_size, exports, #name )
    GET_FUNC( KiUserApcDispatcher );
    GET_FUNC( KiUserCallbackDispatcher );
    GET_FUNC( KiUserExceptionDispatcher );
    GET_FUNC( LdrInitializeThunk );
    GET_FUNC( LdrSystemDllInitBlock );
    GET_FUNC( RtlUserThreadStart );
    GET_OPTIONAL_FUNC( RtlpFreezeTimeBias );
    GET_OPTIONAL_FUNC( RtlpQueryProcessDebugInformationRemote );
#undef GET_OPTIONAL_FUNC
#undef GET_FUNC

    if (!(p__wine_ctrl_routine = (void *)find_named_export( module, image_size, exports,
                                                            "__wine_ctrl_routine" )))
        fatal_error( "wow64 ntdll export __wine_ctrl_routine not found\n" );

#ifdef _WIN64
    {
        unixlib_handle_t *p__wine_unixlib_handle = (void *)find_named_export( module, image_size, exports,
                                                                              "__wine_unixlib_handle" );
        if (!p__wine_unixlib_handle)
            fatal_error( "wow64 ntdll export __wine_unixlib_handle not found\n" );
        *p__wine_unixlib_handle = (UINT_PTR)unix_call_wow64_funcs;
    }
#endif

    /* also set the 32-bit LdrSystemDllInitBlock */
    memcpy( (void *)(ULONG_PTR)pLdrSystemDllInitBlock->pLdrSystemDllInitBlock,
            pLdrSystemDllInitBlock, sizeof(*pLdrSystemDllInitBlock) );
}


/***********************************************************************
 *           redirect_arm64ec_rva
 *
 * Redirect an address through the arm64ec redirection table.
 */
ULONG_PTR redirect_arm64ec_rva( void *base, ULONG_PTR rva, const IMAGE_ARM64EC_METADATA *metadata )
{
    const IMAGE_ARM64EC_REDIRECTION_ENTRY *map = get_rva( base, metadata->RedirectionMetadata );
    int min = 0, max = metadata->RedirectionMetadataCount - 1;

    while (min <= max)
    {
        int pos = (min + max) / 2;
        if (map[pos].Source == rva) return map[pos].Destination;
        if (map[pos].Source < rva) min = pos + 1;
        else max = pos - 1;
    }
    return rva;
}


static BOOL module_ptr_fits_image( HMODULE module, ULONG image_size, const void *ptr, size_t size )
{
    ULONG_PTR base = (ULONG_PTR)module, addr = (ULONG_PTR)ptr;

    if (addr < base || image_size < size) return FALSE;
    return addr - base <= image_size - size;
}

static void *redirect_arm64ec_proc( HMODULE module, ULONG image_size, void *proc,
                                    const IMAGE_ARM64EC_METADATA *metadata )
{
    ULONG_PTR base = (ULONG_PTR)module, addr = (ULONG_PTR)proc;
    ULONG_PTR target;

    if (addr < base || addr - base >= image_size) return NULL;
    target = redirect_arm64ec_rva( module, addr - base, metadata );
    if (target >= image_size) return NULL;
    return module_rva_ptr( module, image_size, target, 1 );
}

/***********************************************************************
 *           redirect_ntdll_functions
 *
 * Redirect ntdll functions on arm64ec.
 */
static void redirect_ntdll_functions( HMODULE module )
{
    const IMAGE_LOAD_CONFIG_DIRECTORY *loadcfg;
    const IMAGE_ARM64EC_METADATA *metadata;
    ULONG image_size, loadcfg_size;

    if (!(image_size = get_module_image_size( module ))) return;
    if (!(loadcfg = get_module_data_dir( module, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &loadcfg_size ))) return;
    if (loadcfg_size < offsetof( IMAGE_LOAD_CONFIG_DIRECTORY, CHPEMetadataPointer ) +
                       sizeof(loadcfg->CHPEMetadataPointer)) return;
    if (!(metadata = (void *)(ULONG_PTR)loadcfg->CHPEMetadataPointer)) return;
    if (!module_ptr_fits_image( module, image_size, metadata, sizeof(*metadata) )) return;
    if (metadata->RedirectionMetadataCount > INT_MAX) return;
    if (!module_rva_array_fits_image( image_size, metadata->RedirectionMetadata,
                                      metadata->RedirectionMetadataCount,
                                      sizeof(IMAGE_ARM64EC_REDIRECTION_ENTRY) ))
        return;
#define REDIRECT(name) do { \
    void *redirected = redirect_arm64ec_proc( module, image_size, p##name, metadata ); \
    if (!redirected) return; \
    p##name = redirected; \
} while (0)
    REDIRECT( DbgUiRemoteBreakin );
    REDIRECT( KiRaiseUserExceptionDispatcher );
    REDIRECT( KiUserExceptionDispatcher );
    REDIRECT( KiUserApcDispatcher );
    REDIRECT( KiUserCallbackDispatcher );
    REDIRECT( KiUserEmulationDispatcher );
    REDIRECT( LdrInitializeThunk );
    REDIRECT( RtlUserThreadStart );
#undef REDIRECT
}


/***********************************************************************
 *           load_ntdll
 */
static void load_ntdll(void)
{
    static WCHAR path[] = {'\\','?','?','\\','C',':','\\','w','i','n','d','o','w','s','\\',
                           's','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0};
    USHORT machine = current_machine;
    const char *pe_dir;
    unsigned int status;
    SECTION_IMAGE_INFORMATION info;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING str;
    void *module;
    SIZE_T size = 0;
    char *name = NULL;

    init_unicode_string( &str, path );
    InitializeObjectAttributes( &attr, &str, 0, 0, NULL );

    /* MacRunner, лейн ШАГ-1, 08.09.2026 — ОТКУДА БЕРЁТСЯ ntdll В РЕЖИМЕ ARM64EC.
     *
     * Было: `machine = main_image_info.Machine` (AMD64), и тот же `machine` шёл в
     * get_pe_dir() -> каталог "/x86_64-windows". Там лежит ЧИСТЫЙ x86-64 ntdll.dll
     * (build/Makefile:361834, `-b x86_64-w64-mingw32`), в котором экспорта
     * `__wine_unix_call_dispatcher_arm64ec` нет и быть не может: ntdll.spec:1757
     * объявляет его `-arch=arm64ec`. Отсюда отказ GET_FUNC (loader.c:2786).
     *
     * Гибрид ARM64X, несущий вид EC вместе с этим экспортом, собирается ОДИН и лежит в
     * "/aarch64-windows" (build/Makefile:361743, `-b arm64ec-w64-mingw32 -marm64x`).
     * Ровно так же поступает и обычная загрузка встроенных модулей: load_builtin()
     * при is_arm64ec() переводит поиск AMD64-гибрида на current_machine (см. выше в
     * этом файле). load_ntdll() строит путь сам и этого перевода не делал.
     *
     * Разделяем два разных смысла:
     *   pe_dir  — ГДЕ лежит файл: гибрид, то есть каталог current_machine;
     *   machine — ЧЕМ его считать при отображении: AMD64, и это обязательно, потому что
     *             перевод ARM64X -> вид EC в map_image_into_view (virtual.c:5542-5545)
     *             включается ИМЕННО по machine == AMD64. С ARM64 файл отобразился бы
     *             в родном виде, и экспорта EC в нём снова не оказалось бы.
     */
    if (is_arm64ec())
    {
        machine = main_image_info.Machine;
        pe_dir = get_pe_dir( current_machine );
    }
    else pe_dir = get_pe_dir( machine );

    if (build_dir)
    {
        if (asprintf( &name, "%s%s/ntdll.dll", ntdll_dir, pe_dir ) < 0)
            fatal_error( "out of memory building ntdll path\n" );
    }
    else if (asprintf( &name, "%s%s/ntdll.dll", dll_dir, pe_dir ) < 0)
        fatal_error( "out of memory building ntdll path\n" );

    /* БЕЗУСЛОВНЫЙ зонд: печатается ВСЕГДА, до попытки открытия. Нужен потому, что отказ
     * "ntdll export ... not found" не называет ФАЙЛ, и три захода подряд разбирали не тот.
     * Имя маркера латиницей — `strings -a` не находит кириллические (проверено 07.09). */
    fprintf( stderr, "macrunner-load-ntdll: arm64ec=%d cur_machine=%#x main_machine=%#x "
                     "map_machine=%#x file=%s\n",
             is_arm64ec(), current_machine, main_image_info.Machine, machine, name );
    fflush( stderr );

    status = open_builtin_pe_file( name, &attr, &module, &size, &info, 0, 0, machine, FALSE, 0 );
    if (status == STATUS_DLL_NOT_FOUND)
    {
        free( name );
        if (asprintf( &name, "%s/ntdll.dll%c.so", ntdll_dir, 0 ) < 0)
            fatal_error( "out of memory building ntdll path\n" );
        status = open_builtin_so_file( name, &attr, &module, &info, machine, 0, FALSE );
    }
    if (status == STATUS_IMAGE_NOT_AT_BASE) status = virtual_relocate_module( module );
    if (status) fatal_error( "failed to load %s error %x\n", name, status );
    free( name );
    load_ntdll_functions( module );
    if (is_arm64ec()) redirect_ntdll_functions( module );
}


/***********************************************************************
 *           load_apiset_dll
 */
static void load_apiset_dll(void)
{
    static WCHAR path[] = {'\\','?','?','\\','C',':','\\','w','i','n','d','o','w','s','\\',
                           's','y','s','t','e','m','3','2','\\',
                           'a','p','i','s','e','t','s','c','h','e','m','a','.','d','l','l',0};
    const char *pe_dir = get_pe_dir( current_machine );
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS *nt;
    const IMAGE_SECTION_HEADER *sec;
    API_SET_NAMESPACE *map;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING str;
    unsigned int status;
    HANDLE handle, mapping;
    SIZE_T size;
    char *name = NULL;
    void *ptr;
    UINT i;

    init_unicode_string( &str, path );
    InitializeObjectAttributes( &attr, &str, 0, 0, NULL );

    if (build_dir)
    {
        if (asprintf( &name, "%s/dlls/apisetschema%s/apisetschema.dll", build_dir, pe_dir ) < 0)
            fatal_error( "out of memory building apisetschema path\n" );
    }
    else if (asprintf( &name, "%s%s/apisetschema.dll", dll_dir, pe_dir ) < 0)
        fatal_error( "out of memory building apisetschema path\n" );
    status = open_unix_file( &handle, name, GENERIC_READ | SYNCHRONIZE, &attr, 0,
                             FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_OPEN,
                             FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0 );
    free( name );

    if (!status)
    {
        status = NtCreateSection( &mapping, STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ,
                                  NULL, NULL, PAGE_READONLY, SEC_COMMIT, handle );
        NtClose( handle );
    }
    if (!status)
    {
        status = map_section( mapping, &ptr, &size, PAGE_READONLY );
        NtClose( mapping );
    }
    if (!status)
    {
        SIZE_T nt_offset, optional_offset, section_offset;

        dos = ptr;
        if (size < sizeof(*dos) || dos->e_magic != IMAGE_DOS_SIGNATURE ||
            (nt_offset = dos->e_lfanew) > size - offsetof( IMAGE_NT_HEADERS, OptionalHeader ))
        {
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto done;
        }
        nt = get_rva( ptr, nt_offset );
        optional_offset = nt_offset + offsetof( IMAGE_NT_HEADERS, OptionalHeader );
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->FileHeader.SizeOfOptionalHeader > size - optional_offset)
        {
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto done;
        }
        section_offset = optional_offset + nt->FileHeader.SizeOfOptionalHeader;
        sec = (const IMAGE_SECTION_HEADER *)((const char *)ptr + section_offset);
        if (section_offset > size ||
            nt->FileHeader.NumberOfSections > (size - section_offset) / sizeof(*sec))
        {
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto done;
        }
        status = STATUS_APISET_NOT_PRESENT;

        for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        {
            SIZE_T raw, raw_size, section_size;

            if (memcmp( (char *)sec->Name, ".apiset", 8 )) continue;
            raw = sec->PointerToRawData;
            raw_size = sec->SizeOfRawData;
            section_size = sec->Misc.VirtualSize;
            if (!section_size || raw_size < section_size) section_size = raw_size;
            if (raw >= size || raw_size > size - raw || section_size < sizeof(*map))
            {
                status = STATUS_INVALID_IMAGE_FORMAT;
                break;
            }
            map = (API_SET_NAMESPACE *)((char *)ptr + raw);
            if (map->Version == 6 && map->Size >= sizeof(*map) && map->Size <= section_size)
            {
                peb->ApiSetMap = map;
                if (wow_peb) wow_peb->ApiSetMap = PtrToUlong(map);
                TRACE( "loaded %s apiset at %p\n", debugstr_w(path), map );
                return;
            }
            break;
        }
done:
        NtUnmapViewOfSection( NtCurrentProcess(), ptr );
    }
    ERR( "failed to load apiset: %x\n", status );
}


/***********************************************************************
 *           load_wow64_ntdll
 */
static void load_wow64_ntdll( USHORT machine )
{
    static const WCHAR ntdllW[] = {'n','t','d','l','l','.','d','l','l',0};
    SECTION_IMAGE_INFORMATION info;
    UNICODE_STRING nt_name;
    void *module;
    unsigned int status;
    SIZE_T size;
    const WCHAR *wow64_dir;
    WCHAR *path;

    if (machine == current_machine) return;
    if (!(wow64_dir = get_machine_wow64_dir( machine ))) return;

    if (!(path = malloc( sizeof("\\??\\C:\\windows\\system32\\ntdll.dll") * sizeof(WCHAR) )))
        fatal_error( "out of memory loading wow64 ntdll.dll\n" );
    wcscpy( path, wow64_dir );
    wcscat( path, ntdllW );
    init_unicode_string( &nt_name, path );
    status = find_builtin_dll( &nt_name, NULL, &module, &size, &info, 0, 0, machine, 0, FALSE, 0 );
    if (status == STATUS_IMAGE_NOT_AT_BASE) status = virtual_relocate_module( module );
    if (status) fatal_error( "failed to load %s error %x\n", debugstr_w(path), status );
    load_ntdll_wow64_functions( module );
    TRACE("loaded %s at %p\n", debugstr_w(path), module );
    free( path );
}


/***********************************************************************
 *           get_image_address
 */
static ULONG_PTR get_image_address(void)
{
#ifdef HAVE_GETAUXVAL
    ULONG_PTR size, num, phdr_addr = getauxval( AT_PHDR );
    ElfW(Phdr) *phdr;

    if (!phdr_addr) return 0;
    phdr = (ElfW(Phdr) *)phdr_addr;
    size = getauxval( AT_PHENT );
    num = getauxval( AT_PHNUM );
    while (num--)
    {
        if (phdr->p_type == PT_PHDR) return phdr_addr - phdr->p_offset;
        phdr = (ElfW(Phdr) *)((char *)phdr + size);
    }
#elif defined(__APPLE__) && defined(TASK_DYLD_INFO)
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t size = TASK_DYLD_INFO_COUNT;

    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyld_info, &size) == KERN_SUCCESS)
        return dyld_info.all_image_info_addr;
#endif
    return 0;
}

#if defined(__APPLE__) && defined(__x86_64__)
static __thread struct tm localtime_tls;
struct tm *my_localtime(const time_t *timep)
{
    return localtime_r(timep, &localtime_tls);
}

static void hook(void *to_hook, const void *replace)
{
    size_t offset;

    struct hooked_function
    {
        char jmp[8];
        const void *dst;
    } *hooked_function = to_hook;
    ULONG_PTR intval = (UINT_PTR)to_hook;

    intval -= (intval % 4096);
    if (mprotect( (void *)intval, 0x2000, PROT_EXEC | PROT_READ | PROT_WRITE ))
        fatal_error( "failed to make hook target %p writable: %s\n", to_hook, strerror(errno) );

    /* The offset is from the end of the jmp instruction (6 bytes) to the start of the destination. */
    offset = offsetof(struct hooked_function, dst) - offsetof(struct hooked_function, jmp) - 0x6;

    /* jmp *(rip + offset) */
    hooked_function->jmp[0] = 0xff;
    hooked_function->jmp[1] = 0x25;
    hooked_function->jmp[2] = offset;
    hooked_function->jmp[3] = 0x00;
    hooked_function->jmp[4] = 0x00;
    hooked_function->jmp[5] = 0x00;
    /* Filler */
    hooked_function->jmp[6] = 0xcc;
    hooked_function->jmp[7] = 0xcc;
    /* Dest address absolute */
    hooked_function->dst = replace;

    //size = sizeof(*hooked_function);
    //NtProtectVirtualMemory(proc, (void **)hooked_function, &size, old_protect, &old_protect);
}
#endif

/***********************************************************************
 *           start_main_thread
 */
static void start_main_thread(void)
{
    TEB *teb = virtual_alloc_first_teb();

    signal_init_threading();
    dbg_init();
    startup_info_size = server_init_process();
    hacks_init();
    msync_init();
    virtual_map_user_shared_data();
    init_cpu_info();
    init_files();
    init_startup_info();
    *(ULONG_PTR *)&peb->CloudFileFlags = get_image_address();
    set_load_order_app_name( main_wargv[0] );
    init_thread_stack( teb, 0, 0, 0 );
    NtCreateKeyedEvent( &keyed_event, GENERIC_READ | GENERIC_WRITE, NULL, 0 );
    load_ntdll();
    load_wow64_ntdll( main_image_info.Machine );
    load_apiset_dll();

#if defined(__APPLE__) && defined(__x86_64__)
    /* This is necessary because we poke PEB into pthread TLS at offset 0x60. It is normally in use by
     * localtime(), which is called a lot by system libraries. Make localtime() go away. */
    hook(localtime, my_localtime);
#endif

    /* CW Hack 24067 */
    {
        void *cxcompatdb = NULL;
        char *name = NULL;

        if (asprintf( &name, "%s/cxcompatdb.so", ntdll_dir ) < 0)
            fatal_error( "out of memory loading cxcompatdb.so\n" );
        if (name)
        {
            if (!access( name, R_OK ))
            {
                cxcompatdb = dlopen( name, RTLD_LOCAL | RTLD_LAZY );
                if (!cxcompatdb)
                    WARN( "error loading cxcompatdb.so: %s\n", dlerror() );
            }
            free(name);
        }
    }

    server_init_process_done();
}

#ifdef __ANDROID__

#ifndef WINE_JAVA_CLASS
#define WINE_JAVA_CLASS "org/winehq/wine/WineActivity"
#endif

JavaVM *java_vm = NULL;
jobject java_object = 0;
unsigned short java_gdt_sel = 0;

/* main Wine initialisation */
static jstring wine_init_jni( JNIEnv *env, jobject obj, jobjectArray cmdline, jobjectArray environment )
{
    char **argv;
    char *str;
    char error[1024];
    int i, argc, length;

    /* get the command line array */

    argc = (*env)->GetArrayLength( env, cmdline );
    for (i = length = 0; i < argc; i++)
    {
        jobject str_obj = (*env)->GetObjectArrayElement( env, cmdline, i );
        length += (*env)->GetStringUTFLength( env, str_obj ) + 1;
    }

    argv = malloc( (argc + 1) * sizeof(*argv) + length );
    if (!argv) return (*env)->NewStringUTF( env, "out of memory" );
    str = (char *)(argv + argc + 1);
    for (i = 0; i < argc; i++)
    {
        jobject str_obj = (*env)->GetObjectArrayElement( env, cmdline, i );
        length = (*env)->GetStringUTFLength( env, str_obj );
        (*env)->GetStringUTFRegion( env, str_obj, 0,
                                    (*env)->GetStringLength( env, str_obj ), str );
        argv[i] = str;
        str[length] = 0;
        str += length + 1;
    }
    argv[argc] = NULL;

    /* set the environment variables */

    if (environment)
    {
        int count = (*env)->GetArrayLength( env, environment );
        for (i = 0; i < count - 1; i += 2)
        {
            jobject var_obj = (*env)->GetObjectArrayElement( env, environment, i );
            jobject val_obj = (*env)->GetObjectArrayElement( env, environment, i + 1 );
            const char *var = (*env)->GetStringUTFChars( env, var_obj, NULL );

            if (val_obj)
            {
                const char *val = (*env)->GetStringUTFChars( env, val_obj, NULL );
                setenv( var, val, 1 );
                if (!strcmp( var, "LD_LIBRARY_PATH" ))
                {
                    void (*update_func)( const char * ) = dlsym( RTLD_DEFAULT,
                                                                 "android_update_LD_LIBRARY_PATH" );
                    if (update_func) update_func( val );
                }
                else if (!strcmp( var, "WINEDEBUGLOG" ))
                {
                    int fd = open( val, O_WRONLY | O_CREAT | O_APPEND, 0666 );
                    if (fd != -1)
                    {
                        dup2( fd, 2 );
                        close( fd );
                    }
                }
                (*env)->ReleaseStringUTFChars( env, val_obj, val );
            }
            else unsetenv( var );

            (*env)->ReleaseStringUTFChars( env, var_obj, var );
        }
    }

    java_object = (*env)->NewGlobalRef( env, obj );

    main_argc = argc;
    main_argv = argv;

    macrunner_hb_init_flags();
    init_paths();
    virtual_init();
    init_environment();

#ifdef __i386__
    {
        unsigned short java_fs;
        __asm__( "mov %%fs,%0" : "=r" (java_fs) );
        if (!(java_fs & 4)) java_gdt_sel = java_fs;
        __asm__( "mov %0,%%fs" :: "r" (0) );
        start_main_thread();
        __asm__( "mov %0,%%fs" :: "r" (java_fs) );
    }
#else
    start_main_thread();
#endif
    return (*env)->NewStringUTF( env, error );
}

jint JNI_OnLoad( JavaVM *vm, void *reserved )
{
    static const JNINativeMethod method =
    {
        "wine_init", "([Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/String;", wine_init_jni
    };

    JNIEnv *env;
    jclass class;

    java_vm = vm;
    if ((*vm)->AttachCurrentThread( vm, &env, NULL ) != JNI_OK) return JNI_ERR;
    if (!(class = (*env)->FindClass( env, WINE_JAVA_CLASS ))) return JNI_ERR;
    (*env)->RegisterNatives( env, class, &method, 1 );
    return JNI_VERSION_1_6;
}

#endif  /* __ANDROID__ */

#ifdef __APPLE__
static void *apple_wine_thread( void *arg )
{
    start_main_thread();
    return NULL;
}

/***********************************************************************
 *           apple_create_wine_thread
 *
 * Spin off a secondary thread to complete Wine initialization, leaving
 * the original thread for the Mac frameworks.
 *
 * Invoked as a CFRunLoopSource perform callback.
 */
static void apple_create_wine_thread( void *arg )
{
    pthread_t thread;
    pthread_attr_t attr;

    pthread_attr_init( &attr );
    pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_JOINABLE );
    if (pthread_create( &thread, &attr, apple_wine_thread, NULL )) exit(1);
    pthread_attr_destroy( &attr );
}


/***********************************************************************
 *           apple_main_thread
 *
 * Park the process's original thread in a Core Foundation run loop for
 * use by the Mac frameworks, especially receiving and handling
 * distributed notifications.  Spin off a new thread for the rest of the
 * Wine initialization.
 */
static void apple_main_thread(void)
{
    CFRunLoopSourceContext source_context = { 0 };
    CFRunLoopSourceRef source;

    if (!pthread_main_np()) return;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    /* Multi-processing Services can get confused about the main thread if the
     * first time it's used is on a secondary thread.  Use it here to make sure
     * that doesn't happen. */
    MPTaskIsPreemptive(MPCurrentTaskID());
#pragma clang diagnostic pop

    /* Give ourselves the best chance of having the distributed notification
     * center scheduled on this thread's run loop.  In theory, it's scheduled
     * in the first thread to ask for it. */
    CFNotificationCenterGetDistributedCenter();

    /* We use this run loop source for two purposes.  First, a run loop exits
     * if it has no more sources scheduled.  So, we need at least one source
     * to keep the run loop running.  Second, although it's not critical, it's
     * preferable for the Wine initialization to not proceed until we know
     * the run loop is running.  So, we signal our source immediately after
     * adding it and have its callback spin off the Wine thread. */
    source_context.perform = apple_create_wine_thread;
    source = CFRunLoopSourceCreate( NULL, 0, &source_context );
    CFRunLoopAddSource( CFRunLoopGetCurrent(), source, kCFRunLoopCommonModes );
    CFRunLoopSourceSignal( source );
    CFRelease( source );
    CFRunLoopRun(); /* Should never return, except on error. */
}
#endif  /* __APPLE__ */


#if defined(__linux__) && !defined(__ANDROID__) && (defined(__i386__) || defined(__arm__))

static void check_vmsplit( void *stack )
{
    if (stack < (void *)0x80000000)
    {
        /* if the stack is below 0x80000000, assume we can safely try a munmap there */
        if (munmap( (void *)0x80000000, 1 ) == -1 && errno == EINVAL)
            ERR( "Warning: memory above 0x80000000 doesn't seem to be accessible.\n"
                 "Wine requires a 3G/1G user/kernel memory split to work properly.\n" );
    }
}

static int pre_exec(void)
{
    int temp;

    check_vmsplit( &temp );
    return 1;  /* we have a preloader on x86/arm */
}

#elif (defined(__FreeBSD__) || defined (__FreeBSD_kernel__) || defined(__DragonFly__))

static int pre_exec(void)
{
    struct rlimit rl;

    rl.rlim_cur = 0x02000000;
    rl.rlim_max = 0x02000000;
    setrlimit( RLIMIT_DATA, &rl );
    return 1;
}

#elif defined(__APPLE__)

static int pre_exec(void)
{
    if (build_dir)
    {
        char *path;
        const char *old_path = getenv( "DYLD_LIBRARY_PATH" );

        if (old_path)
        {
            if (asprintf( &path, "%s/dlls/ntdll:%s/dlls/win32u:%s", build_dir, build_dir, old_path ) < 0)
                fatal_error( "out of memory setting DYLD_LIBRARY_PATH\n" );
        }
        else if (asprintf( &path, "%s/dlls/ntdll:%s/dlls/win32u", build_dir, build_dir ) < 0)
            fatal_error( "out of memory setting DYLD_LIBRARY_PATH\n" );
        setenv( "DYLD_LIBRARY_PATH", path, 1 );
        free( path );
        return 1;
    }
#ifdef HAVE_WINE_PRELOADER
    return 1;
#else
    return 0;
#endif
}

#else

static int pre_exec(void)
{
#ifdef HAVE_WINE_PRELOADER
    return 1;  /* we have a preloader */
#else
    return 0;  /* no exec needed */
#endif
}

#endif


static void reexec_loader( int argc, char *argv[], char *extra_arg )
{
    WORD machine = current_machine;
    char **new_argv;
    size_t extra_count = extra_arg ? 3 : 2;

    /* have to exec if we have a preloader, or an argument, or if we are the initial wrapper */
    if (!pre_exec() && !extra_arg && dlsym( RTLD_DEFAULT, "wine_main_preload_info" )) return;

    if (argc < 0 || (size_t)argc > ~(size_t)0 / sizeof(*new_argv) - extra_count)
        fatal_error( "too many arguments re-executing wine loader\n" );

    if (extra_arg)
    {
        if (!(new_argv = malloc( ((size_t)argc + extra_count) * sizeof(*new_argv) )))
            fatal_error( "out of memory re-executing wine loader\n" );
        memcpy( new_argv + 3, argv + 1, (size_t)argc * sizeof(*argv) );
        new_argv[2] = extra_arg;
    }
    else
    {
        if (!(new_argv = malloc( ((size_t)argc + extra_count) * sizeof(*new_argv) )))
            fatal_error( "out of memory re-executing wine loader\n" );
        memcpy( new_argv + 2, argv + 1, (size_t)argc * sizeof(*argv) );
    }

    /* default to 32-bit loader to support 32-bit prefixes */
    if (current_machine != IMAGE_FILE_MACHINE_ARM64 &&
        machine == IMAGE_FILE_MACHINE_AMD64)
        machine = IMAGE_FILE_MACHINE_I386;

    loader_exec( new_argv, machine, argv[0] );
    fatal_error( "could not exec the wine loader\n" );
}

/***********************************************************************
 *           check_command_line
 *
 * Check if command line is one that needs to be handled specially.
 */
static void check_command_line( int argc, char *argv[] )
{
    char *basename;
    static const char usage[] =
        "Usage: wine PROGRAM [ARGUMENTS...]   Run the specified program\n"
        "       wine --help                   Display this help and exit\n"
        "       wine --version                Output version information and exit";

    if ((basename = strrchr( argv[0], '/' ))) basename++;
    else basename = argv[0];

    if (strcmp( basename, "wine" )) /* check if there's a builtin exe corresponding to the base name */
    {
        const char *pe_dir = get_pe_dir( current_machine );
        char *exe;

        if (build_dir)
        {
            if (asprintf( &exe, "%s/programs/%s%s/%s.exe", build_dir, basename, pe_dir, basename ) < 0)
                fatal_error( "out of memory checking builtin executable\n" );
            if (!access( exe, R_OK )) reexec_loader( argc, argv, basename );
            free( exe );
        }
        else
        {
            for (size_t i = 0; dll_paths[i]; i++)
            {
                if (asprintf( &exe, "%s%s/%s.exe", dll_paths[i], pe_dir, basename ) < 0)
                    fatal_error( "out of memory checking builtin executable\n" );
                if (!access( exe, R_OK )) reexec_loader( argc, argv, basename );
                free( exe );
            }
        }
    }

    if (argc <= 1)
    {
        fprintf( stderr, "%s\n", usage );
        exit(1);
    }
    if (!strcmp( argv[1], "--help" ))
    {
        printf( "%s\n", usage );
        exit(0);
    }
    if (!strcmp( argv[1], "--version" ))
    {
        printf( "%s\n", wine_build );
        exit(0);
    }

    reexec_loader( argc, argv, NULL );
}


/***********************************************************************
 *           __wine_main
 *
 * Main entry point called by the wine loader.
 */
DECLSPEC_EXPORT void __wine_main( int argc, char *argv[] )
{
    main_argc = argc;
    main_argv = argv;

    macrunner_hb_init_flags();
    init_paths();
    if (!getenv( "WINELOADERNOEXEC" ) || argc <= 1) check_command_line( argc, argv );
    unsetenv( "WINELOADERNOEXEC" );

#ifdef RLIMIT_NOFILE
    set_max_limit( RLIMIT_NOFILE );
#endif
#ifdef RLIMIT_AS
    set_max_limit( RLIMIT_AS );
#endif
#ifdef RLIMIT_NICE
    set_max_limit( RLIMIT_NICE );
#endif

    virtual_init();
    init_environment();

#ifdef __APPLE__
    apple_main_thread();
#endif
    start_main_thread();
}
