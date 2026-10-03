/*
 * Emulator initialisation code
 *
 * Copyright 2000 Alexandre Julliard
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

#include "config.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>
#include <limits.h>
#ifdef __APPLE__
# include <mach/mach.h>
# include <mach/mach_vm.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
# include <sys/sysctl.h>
#endif
#ifdef __APPLE__
# include <mach-o/dyld.h>
#endif

#ifdef __APPLE__ /* CrossOver Hack 13438 */
#include <crt_externs.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>
#endif

#include "main.h"

#if defined(__APPLE__) && (defined(__x86_64__) || defined(__aarch64__)) && !defined(HAVE_WINE_PRELOADER)

/* MacRunner: extended to __aarch64__. The x86_64 zerofill+image_base technique
 * (binary loaded at 0x200000000, WINE_RESERVE zerofill at 0x1000-0x200000000,
 * WINE_TOP_DOWN at 0x7ff000000000) works on Apple Silicon too — provided the
 * loader is linked with matching -image_base / -segaddr ldflags (see Makefile).
 */
__asm__(".zerofill WINE_RESERVE,WINE_RESERVE");
static char __wine_reserve[0x1fffff000] __attribute__((section("WINE_RESERVE, WINE_RESERVE")));

__asm__(".zerofill WINE_TOP_DOWN,WINE_TOP_DOWN");
static char __wine_top_down[0x001ff0000] __attribute__((section("WINE_TOP_DOWN, WINE_TOP_DOWN")));

static const struct wine_preload_info preload_info[] =
{
    { __wine_reserve,  sizeof(__wine_reserve)  }, /*         0x1000 -    0x200000000: low 8GB */
    { __wine_top_down, sizeof(__wine_top_down) }, /* 0x7ff000000000 - 0x7ff001ff0000: top-down allocations + virtual heap */
    { 0, 0 }                                      /* end of list */
};

const __attribute((visibility("default"))) struct wine_preload_info *wine_main_preload_info = preload_info;

static void init_reserved_areas(void)
{
    int i;

    for (i = 0; wine_main_preload_info[i].size != 0; i++)
    {
        /* Match how the preloader maps reserved areas: */
        mmap(wine_main_preload_info[i].addr, wine_main_preload_info[i].size, PROT_NONE,
             MAP_FIXED | MAP_NORESERVE | MAP_PRIVATE | MAP_ANON, -1, 0);
    }
}

#elif defined(__APPLE__) && defined(__aarch64__)

/* A provisioned ARM64 loader may replace its otherwise inaccessible PAGEZERO.
 * Reserve only PAGEZERO, before dlopen or any guest initialisation, and expose
 * successful ownership through Wine's existing preload interface.  Never mark
 * an unsuccessful reservation as usable memory.  Keep the Windows null 64K.
 */
static const struct wine_preload_info signed32_preload_info[] =
{
    { (void *)0x00010000, 0xffff0000 },
    { 0, 0 }
};

const __attribute__((visibility("default"))) struct wine_preload_info *wine_main_preload_info = NULL;

static void init_reserved_areas(void)
{
    void *addr = signed32_preload_info[0].addr;
    size_t size = signed32_preload_info[0].size;
    void *mapped = mmap( addr, size, PROT_NONE,
                         MAP_FIXED | MAP_NORESERVE | MAP_PRIVATE | MAP_ANON, -1, 0 );
    if (mapped == MAP_FAILED)
    {
        perror( "macrunner-signed32: reserve PAGEZERO" );
        exit(1);
    }
    if (mapped != addr)
    {
        fprintf( stderr, "macrunner-signed32: unexpected reservation address %p\n", mapped );
        exit(1);
    }
    wine_main_preload_info = signed32_preload_info;
    fprintf( stderr, "macrunner-signed32: reserved=%p size=%#zx preload=ready pid=%d\n",
             mapped, size, (int)getpid() );
}

#else

/* the preloader will set this variable */
const __attribute((visibility("default"))) struct wine_preload_info *wine_main_preload_info = NULL;

static void init_reserved_areas(void)
{
}

#endif

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
    ret = malloc( len - tail_len + 1 );
    memcpy( ret, str, len - tail_len );
    ret[len - tail_len] = 0;
    return ret;
}

/* build a path from the specified dir and name */
static char *build_path( const char *dir, const char *name )
{
    size_t len = strlen( dir );
    char *ret = malloc( len + strlen( name ) + 2 );

    memcpy( ret, dir, len );
    if (len && ret[len - 1] != '/') ret[len++] = '/';
    strcpy( ret + len, name );
    return ret;
}

static const char *get_self_exe(void)
{
#if defined(__linux__) || defined(__FreeBSD_kernel__) || defined(__NetBSD__)
    return "/proc/self/exe";
#elif defined (__FreeBSD__) || defined(__DragonFly__)
    static int pathname[] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
    size_t path_size = PATH_MAX;
    char *path = malloc( path_size );
    if (path && !sysctl( pathname, sizeof(pathname)/sizeof(pathname[0]), path, &path_size, NULL, 0 ))
        return path;
    free( path );
#elif defined(__APPLE__)
    uint32_t path_size = PATH_MAX;
    char *path = malloc( path_size );
    if (path && !_NSGetExecutablePath( path, &path_size ))
        return path;
    free( path );
#endif
    return NULL;
}

#ifdef __APPLE__
/***********************************************************************
 *  macrunner_zakrepit_ntdll
 *
 * Закрепление базы ntdll.so — последний незакреплённый кусок раскладки.
 *
 * ЗАМЕР назвал причину: ниже ntdll.so лежит область с меткой ядра user_tag=1
 * (VM_MEMORY_MALLOC), её размер гуляет от прогона к прогону (0x188000 /
 * 0x1ac000 / 0x1f0000), и dyld, кладя dlopen-образ в первую свободную дыру,
 * поднимает ntdll.so на разную высоту: 5 разных баз из 6 прогонов даже с
 * выключенным ASLR. `-image_base` не помогает — современный компоновщик его
 * игнорирует («prefered load addresses are disabled with chained fixups»),
 * а DYLD_INSERT_LIBRARIES проверка библиотек в подписанный процесс не пускает
 * (Killed: 9). Поэтому занимаем дыры сами, прямо перед dlopen.
 *
 * Приём: занять ВСЕ свободные дыры ниже выбранного адреса — тогда первая
 * свободная дыра ровно он, и dyld кладёт образ туда. Занимаем ТОЛЬКО
 * свободное: границы спрашиваем у ядра через mach_vm_region и mmap MAP_FIXED
 * ставим лишь в промежутки между занятыми областями, поверх чужого — никогда.
 *
 * Гейт MACRUNNER_NTDLL_BASE=<адрес>; без него не делает и не печатает ничего.
 */
static void macrunner_zakrepit_ntdll( void )
{
    const char *env = getenv( "MACRUNNER_NTDLL_BASE" );
    unsigned long long cel;
    mach_vm_address_t adres = 0x100000000ULL;
    unsigned zanyato = 0, promahov = 0;
    unsigned long long zapolneno = 0;

    if (!env || !*env) return;
    cel = strtoull( env, NULL, 0 );
    if (cel <= 0x100000000ULL) return;

    for (;;)
    {
        mach_vm_address_t a = adres;
        mach_vm_size_t razmer = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        mach_vm_address_t konec;

        if (mach_vm_region( mach_task_self(), &a, &razmer, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &cnt, &obj ) != KERN_SUCCESS)
            a = (mach_vm_address_t)cel;              /* выше нет ничего — дыра до цели */

        konec = a < (mach_vm_address_t)cel ? a : (mach_vm_address_t)cel;
        if (konec > adres)
        {
            size_t dlina = (size_t)(konec - adres);
            void *dal = mmap( (void *)(uintptr_t)adres, dlina, PROT_NONE,
                              MAP_PRIVATE | MAP_ANON | MAP_NORESERVE | MAP_FIXED, -1, 0 );
            if (dal == (void *)(uintptr_t)adres) { zanyato++; zapolneno += dlina; }
            else promahov++;
        }
        if (a >= (mach_vm_address_t)cel) break;
        adres = a + razmer;
        if (adres >= cel) break;
    }
    fprintf( stderr, "macrunner-ntdll-закрепление: цель=%#llx дыр_занято=%u байт=%#llx промахов=%u (pid=%d)\n",
             cel, zanyato, zapolneno, promahov, (int)getpid() );
    fflush( stderr );
}
#endif

static void *try_dlopen( const char *argv0 )
{
    char *dir, *path, *p;
    void *handle;

    if (!argv0) return NULL;
    if (!(dir = realpath_dirname( argv0 ))) return NULL;

    if ((p = remove_tail( dir, "/loader" )))
        path = build_path( p, "dlls/ntdll/ntdll.so" );
    else
        path = build_path( dir, "ntdll.so" );

#ifdef __APPLE__
    macrunner_zakrepit_ntdll();
#endif
    handle = dlopen( path, RTLD_NOW );
    free( p );
    free( dir );
    free( path );
    return handle;
}

#ifdef __APPLE__
#define min(a,b)   (((a) < (b)) ? (a) : (b))
/***********************************************************************
 *           apple_override_bundle_name
 *
 * Rewrite the bundle name in the Info.plist embedded in the loader.
 * This is the only way to control the title of the application menu
 * when using the Mac driver.  The GUI frameworks call down into Core
 * Foundation to get the bundle name for that.
 *
 * CrossOver Hack 13438
 */
static void apple_override_bundle_name( int argc, char *argv[] )
{
    char* info_plist;
    unsigned long remaining;
    static const char prefix[] = "<key>CFBundleName</key>\n    <string>";
    const size_t prefix_len = strlen(prefix);
    static const char suffix[] = "</string>";
    const size_t suffix_len = strlen(suffix);
    static const char padding[] = "<!-- bundle name padding -->";
    const size_t padding_len = strlen(padding);
    char* bundle_name;
    const char* p;
    size_t bundle_name_len, max_bundle_name_len;
    vm_address_t start, end;
    const char* new_bundle_name = getenv("WINEPRELOADERAPPNAME");
    size_t new_bundle_name_len;

    unsetenv("WINEPRELOADERAPPNAME");

    if (!new_bundle_name && argc < 2)
        return;

    info_plist = (char *)getsectiondata(_NSGetMachExecuteHeader(), "__TEXT", "__info_plist", &remaining);
    if (!info_plist || !remaining)
        return;

    bundle_name = strnstr(info_plist, prefix, remaining);
    if (!bundle_name)
        return;

    bundle_name += prefix_len;
    remaining -= bundle_name - info_plist;
    p = strnstr(bundle_name, suffix, remaining);
    if (!p)
        return;

    bundle_name_len = p - bundle_name;
    remaining -= bundle_name_len + suffix_len;

    max_bundle_name_len = bundle_name_len;
    if (padding_len <= remaining &&
        !memcmp(bundle_name + bundle_name_len + suffix_len, padding, padding_len))
        max_bundle_name_len += padding_len;

    if (!new_bundle_name)
    {
        new_bundle_name = argv[1];
        if ((p = strrchr(new_bundle_name, '\\'))) new_bundle_name = p + 1;
        if ((p = strrchr(new_bundle_name, '/'))) new_bundle_name = p + 1;
        if (strspn(new_bundle_name, "0123456789abcdefABCDEF") == 32 &&
            new_bundle_name[32] == '.')
            new_bundle_name += 33;
        if ((p = strrchr(new_bundle_name, '.')) && p != new_bundle_name)
            new_bundle_name_len = p - new_bundle_name;
        else
            new_bundle_name_len = strlen(new_bundle_name);
    }
    else
        new_bundle_name_len = strlen(new_bundle_name);

    if (!new_bundle_name_len)
        return;

    start = (vm_address_t)bundle_name;
    end = (vm_address_t)(bundle_name + max_bundle_name_len + suffix_len);
    start &= ~(getpagesize() - 1);
    end = (end + getpagesize() - 1) & ~(getpagesize() - 1);
    if (vm_protect(mach_task_self(), start, end - start, 0,
                   VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE|VM_PROT_COPY) == KERN_SUCCESS)
    {
        size_t copy_len = min(new_bundle_name_len, max_bundle_name_len);
        memcpy(bundle_name, new_bundle_name, copy_len);
        memcpy(bundle_name + copy_len, suffix, suffix_len);
        if (copy_len < max_bundle_name_len)
            memset(bundle_name + copy_len + suffix_len, ' ', max_bundle_name_len - copy_len);
        vm_protect(mach_task_self(), start, end - start, 0, VM_PROT_READ|VM_PROT_EXECUTE);
    }
}
#endif

/**********************************************************************
 *           main
 */
int main( int argc, char *argv[] )
{
    void *handle;

    init_reserved_areas();

#ifdef __APPLE__ /* CrossOver Hack 13438 */
    apple_override_bundle_name(argc, argv);
#endif

    if ((handle = try_dlopen( get_self_exe() )) ||
        (handle = try_dlopen( argv[0] )))
    {
        void (*init_func)(int, char **) = dlsym( handle, "__wine_main" );
        if (init_func) init_func( argc, argv );
        fprintf( stderr, "wine: __wine_main function not found in ntdll.so\n" );
        exit(1);
    }

    fprintf( stderr, "wine: could not load ntdll.so: %s\n", dlerror() );
    pthread_detach( pthread_self() );  /* force importing libpthread for OpenGL */
    exit(1);
}
