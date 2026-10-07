/*
 * Debugging functions
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

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "unix_private.h"
#include "wine/debug.h"

WINE_DECLARE_DEBUG_CHANNEL(pid);
WINE_DECLARE_DEBUG_CHANNEL(timestamp);
WINE_DEFAULT_DEBUG_CHANNEL(ntdll);

struct debug_info
{
    unsigned int str_pos;       /* current position in strings buffer */
    unsigned int out_pos;       /* current position in output buffer */
    char         strings[1020]; /* buffer for temporary strings */
    char         output[1020];  /* current output line */
};

C_ASSERT( sizeof(struct debug_info) == 0x800 );

static BOOL init_done;
static struct debug_info initial_info;  /* debug info for initial thread */
static unsigned char default_flags = (1 << __WINE_DBCL_ERR) | (1 << __WINE_DBCL_FIXME);
static int nb_debug_options = -1;
static int options_size;
static struct __wine_debug_channel *debug_options;

static const char * const debug_classes[] = { "fixme", "err", "warn", "trace" };

/* get the debug info pointer for the current thread */
static inline struct debug_info *get_info(void)
{
    if (!init_done) return &initial_info;
#ifdef _WIN64
    return (struct debug_info *)((TEB32 *)((char *)NtCurrentTeb() + teb_offset) + 1);
#else
    return (struct debug_info *)(NtCurrentTeb() + 1);
#endif
}

/* A unixcall must not report success after a short write or EINTR.  On a
 * permanent sink error return the delivered prefix, so the caller can retain
 * the remaining bytes.  Do not log here: this is the logging transport. */
static int write_output( const char *str, size_t len )
{
    size_t done = 0;
    ssize_t ret;

    while (done < len)
    {
        ret = write( 2, str + done, len - done );
        if (ret > 0) done += ret;
        else if (ret < 0 && errno == EINTR) continue;
        else return done ? done : -1;
    }
    return done;
}

static int flush_output( struct debug_info *info, size_t len )
{
    int ret = write_output( info->output, len );

    if (ret > 0)
    {
        info->out_pos -= ret;
        memmove( info->output, info->output + ret, info->out_pos );
    }
    return ret == len ? 0 : -1;
}

/* Keep the last byte of an unfinished line buffered when streaming a full
 * buffer.  out_pos then continues to suppress a second header, without
 * changing the shared 0x800-byte TEB layout or adding a continuation flag. */
static int append_output( struct debug_info *info, const char *str, size_t len )
{
    size_t total = len, count;

    while (len)
    {
        count = min( len, sizeof(info->output) - info->out_pos );
        memcpy( info->output + info->out_pos, str, count );
        info->out_pos += count;
        str += count;
        len -= count;
        if (info->out_pos == sizeof(info->output) &&
            flush_output( info, sizeof(info->output) - 1 ) < 0) return -1;
    }
    return total;
}

void * __cdecl __wine_dbg_alloc( unsigned int size )
{
    return malloc( size );
}

void __cdecl __wine_dbg_free( void *ptr )
{
    free( ptr );
}

/* add a new debug option at the end of the option list */
static void add_option( const char *name, unsigned char set, unsigned char clear )
{
    int min = 0, max = nb_debug_options - 1, pos, res;

    if (!name[0])  /* "all" option */
    {
        default_flags = (default_flags & ~clear) | set;
        return;
    }
    if (strlen(name) >= sizeof(debug_options[0].name)) return;

    while (min <= max)
    {
        pos = (min + max) / 2;
        res = strcmp( name, debug_options[pos].name );
        if (!res)
        {
            debug_options[pos].flags = (debug_options[pos].flags & ~clear) | set;
            return;
        }
        if (res < 0) max = pos - 1;
        else min = pos + 1;
    }
    if (nb_debug_options >= options_size)
    {
        options_size = max( options_size * 2, 16 );
        debug_options = realloc( debug_options, options_size * sizeof(debug_options[0]) );
    }

    pos = min;
    if (pos < nb_debug_options) memmove( &debug_options[pos + 1], &debug_options[pos],
                                         (nb_debug_options - pos) * sizeof(debug_options[0]) );
    strcpy( debug_options[pos].name, name );
    debug_options[pos].flags = (default_flags & ~clear) | set;
    nb_debug_options++;
}

/* parse a set of debugging option specifications and add them to the option list */
static void parse_options( const char *str, const char *app_name )
{
    char *opt, *next, *options;
    unsigned int i;

    if (!(options = strdup(str))) return;
    for (opt = options; opt; opt = next)
    {
        char *p;
        unsigned char set = 0, clear = 0;

        if ((next = strchr( opt, ',' ))) *next++ = 0;

        if ((p = strchr( opt, ':' )))
        {
            *p = 0;
            if (strcasecmp( opt, app_name )) continue;
            opt = p + 1;
        }

        p = opt + strcspn( opt, "+-" );
        if (!p[0]) p = opt;  /* assume it's a debug channel name */

        if (p > opt)
        {
            for (i = 0; i < ARRAY_SIZE(debug_classes); i++)
            {
                int len = strlen(debug_classes[i]);
                if (len != (p - opt)) continue;
                if (!memcmp( opt, debug_classes[i], len ))  /* found it */
                {
                    if (*p == '+') set |= 1 << i;
                    else clear |= 1 << i;
                    break;
                }
            }
            if (i == ARRAY_SIZE(debug_classes)) /* bad class name, skip it */
                continue;
        }
        else
        {
            if (*p == '-') clear = ~0;
            else set = ~0;
        }
        if (*p == '+' || *p == '-') p++;
        if (!p[0]) continue;

        if (!strcmp( p, "all" ))
            default_flags = (default_flags & ~clear) | set;
        else
            add_option( p, set, clear );
    }
    free( options );
}

/* print the usage message */
static void debug_usage(void)
{
    static const char usage[] =
        "Syntax of the WINEDEBUG variable:\n"
        "  WINEDEBUG=[[process:]class]+xxx,[[process:]class]-yyy,...\n\n"
        "Example: WINEDEBUG=+relay,warn-heap\n"
        "    turns on relay traces, disable heap warnings\n"
        "Available message classes: err, warn, fixme, trace\n";
    write( 2, usage, sizeof(usage) - 1 );
    exit(1);
}

/* initialize all options at startup */
static void init_options(void)
{
    char *wine_debug = getenv("WINEDEBUG");
    const char *app_name, *p;
    struct stat st1, st2;

    nb_debug_options = 0;

    /* check for stderr pointing to /dev/null */
    if (!fstat( 2, &st1 ) && S_ISCHR(st1.st_mode) &&
        !stat( "/dev/null", &st2 ) && S_ISCHR(st2.st_mode) &&
        st1.st_rdev == st2.st_rdev)
    {
        default_flags = 0;
        return;
    }
    if (!wine_debug) return;
    if (!strcmp( wine_debug, "help" )) debug_usage();

    app_name = main_argv[1];
    while ((p = strpbrk( app_name, "/\\" ))) app_name = p + 1;

    parse_options( wine_debug, app_name );
}

/***********************************************************************
 *		__wine_dbg_get_channel_flags  (NTDLL.@)
 *
 * Get the flags to use for a given channel, possibly setting them too in case of lazy init
 */
unsigned char __cdecl __wine_dbg_get_channel_flags( struct __wine_debug_channel *channel )
{
    int min, max, pos, res;
    unsigned char flags;

    if (!(channel->flags & (1 << __WINE_DBCL_INIT))) return channel->flags;

    if (nb_debug_options == -1) init_options();

    flags = default_flags;
    min = 0;
    max = nb_debug_options - 1;
    while (min <= max)
    {
        pos = (min + max) / 2;
        res = strcmp( channel->name, debug_options[pos].name );
        if (!res)
        {
            flags = debug_options[pos].flags;
            break;
        }
        if (res < 0) max = pos - 1;
        else min = pos + 1;
    }

    if (!(flags & (1 << __WINE_DBCL_INIT))) channel->flags = flags; /* not dynamically changeable */
    return flags;
}

/***********************************************************************
 *		__wine_dbg_strdup  (NTDLL.@)
 */
const char * __cdecl __wine_dbg_strdup( const char *str )
{
    struct debug_info *info = get_info();
    unsigned int pos = info->str_pos;
    size_t n = strlen( str ) + 1;

    assert( n <= sizeof(info->strings) );
    if (pos + n > sizeof(info->strings)) pos = 0;
    info->str_pos = pos + n;
    return memcpy( info->strings + pos, str, n );
}

/***********************************************************************
 *		unixcall_wine_dbg_write
 */
NTSTATUS unixcall_wine_dbg_write( void *args )
{
    struct wine_dbg_write_params *params = args;

    /* ★★★★★ ИТЕРАЦИЯ 80, лейн МЕЛКИЕ — СВЯЗКА wine-pid <-> ospid, ОДИН РАЗ НА ПОТОК.
     *
     * Карта загрузчика (`+loaddll`) помечена pid-ом WINE (`%04x`), а все наши приборы
     * печатают `getpid()`. Соединить их было нечем, и в журнале taskmgr это стоило
     * достоверности: 16 процессов, ОДИННАДЦАТЬ разных `.exe` на базе 0x140000000,
     * 14 загрузок `rpcrt4.dll` на 9 базах (замер итерации 79). Из-за этого и
     * `koren-otkaza.py`, и я привязывали адрес не к тому модулю.
     *
     * Две неудачные точки, обе проверены замером, а не рассуждением:
     *   1) `macrunner-dbgchan-init` — напечатал `winepid=0000` 16 раз из 16:
     *      `ClientId` там ещё не заполнен;
     *   2) построитель префикса в этом же файле — не сработал ни разу: строки
     *      `loaddll` формирует PE-сторона, до unix-построителя они не доходят.
     * Здесь же проходит КАЖДАЯ строка трассы PE-стороны, и TEB заведомо годен —
     * это обычный вызов, не обработчик сигнала. */
    {
        static __thread int pidmap_said;

        if (!pidmap_said)
        {
            unsigned wpid = (unsigned)GetCurrentProcessId();

            if (wpid)
            {
                char buf[96];
                int n = snprintf( buf, sizeof(buf), "macrunner-pidmap: winepid=%04x ospid=%d\n",
                                  wpid, (int)getpid() );
                pidmap_said = 1;
                if (n > 0) write( 2, buf, n );
            }
        }
    }
    return write_output( params->str, params->len );
}

#ifdef _WIN64
/***********************************************************************
 *		wow64_wine_dbg_write
 */
NTSTATUS wow64_wine_dbg_write( void *args )
{
    struct
    {
        ULONG        str;
        unsigned int len;
    } const *params32 = args;

    /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 256 — НЕНУЛЕВАЯ БАЗА 32-БИТНОГО ГОСТЯ.
     * `ULongToPtr` здесь давал адрес в нижних 4 ГБ, где у нас ничего не отображено: macOS не
     * даёт `__PAGEZERO` меньше 4 ГБ, поэтому гостевое пространство живёт по базе. Итог —
     * `write()` отказывал КАЖДЫЙ раз (замер: 41 697 вызовов, все result=0xffffffff), и вся
     * отладочная печать wine из 32-битных модулей пропадала. Тот же класс, что уже ловили в
     * `wow64win` (95 переводов) и `wow64/process.c`. Запасной путь оставлен на случай сборки
     * без гостевой памяти по базе. */
    void *host = macrunner_hb_wow64_guest32_host_ptr( params32->str );

    return write_output( host ? host : ULongToPtr(params32->str), params32->len );
}
#endif

/***********************************************************************
 *		__wine_dbg_output  (NTDLL.@)
 */
int __cdecl __wine_dbg_output( const char *str )
{
    struct debug_info *info = get_info();
    const char *end = strrchr( str, '\n' );
    int ret = 0;

    if (end)
    {
        if ((ret = append_output( info, str, end + 1 - str )) < 0) return -1;
        if (flush_output( info, info->out_pos ) < 0) return -1;
        str = end + 1;
    }
    if (*str)
    {
        int tail = append_output( info, str, strlen( str ));
        if (tail < 0) return -1;
        ret += tail;
    }
    return ret;
}

/***********************************************************************
 *		__wine_dbg_header  (NTDLL.@)
 */
int __cdecl __wine_dbg_header( enum __wine_debug_class cls, struct __wine_debug_channel *channel,
                               const char *function )
{
    static const char * const classes[] = { "fixme", "err", "warn", "trace" };
    struct debug_info *info = get_info();
    char prefix[80];
    int ret = 0, len;

    if (!(__wine_dbg_get_channel_flags( channel ) & (1 << cls))) return -1;

    /* only print header if we are at the beginning of the line */
    if (info->out_pos) return 0;

    if (init_done)
    {
        if (TRACE_ON(timestamp))
        {
            UINT ticks = NtGetTickCount();
            len = snprintf( prefix, sizeof(prefix), "%3u.%03u:", ticks / 1000, ticks % 1000 );
            if (append_output( info, prefix, len ) < 0) return -1;
            ret += len;
        }
        if (TRACE_ON(pid))
        {
            len = snprintf( prefix, sizeof(prefix), "%04x:", GetCurrentProcessId() );
            if (append_output( info, prefix, len ) < 0) return -1;
            ret += len;
        }
        len = snprintf( prefix, sizeof(prefix), "%04x:", GetCurrentThreadId() );
        if (append_output( info, prefix, len ) < 0) return -1;
        ret += len;
    }
    if (function && cls < ARRAY_SIZE( classes ))
    {
        len = snprintf( prefix, sizeof(prefix), "%s:%.15s:", classes[cls], channel->name );
        if (append_output( info, prefix, len ) < 0 ||
            append_output( info, function, strlen(function) ) < 0 ||
            append_output( info, " ", 1 ) < 0) return -1;
        ret += len + strlen(function) + 1;
    }
    return ret;
}

/***********************************************************************
 *		dbg_init
 */
void dbg_init(void)
{
    struct __wine_debug_channel *options, default_option = { default_flags };

    setbuf( stdout, NULL );
    setbuf( stderr, NULL );

    if (nb_debug_options == -1) init_options();

    options = (struct __wine_debug_channel *)((char *)peb + (is_win64 ? 2 : 1) * page_size);
    memcpy( options, debug_options, nb_debug_options * sizeof(*options) );
    free( debug_options );
    debug_options = options;
    options[nb_debug_options] = default_option;
    init_done = TRUE;
    /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 255 — СВЕРКА С ГОСТЕВЫМ ВИДОМ.
     * Каналы wine из i386-модулей не печатаются вовсе. PE-сторона берёт таблицу по
     * `PEB32 + page_size` и считает её длину циклом `while (name[0])`; зонд в xtajit показал,
     * что гость видит по этому адресу запись С ПУСТЫМ ИМЕНЕМ первой, то есть насчитывает ноль
     * каналов. Печатаем адрес и первые записи ТУТ, чтобы сверить с тем, что видит гость. */
    /* MacRunner 2026-08-27: pid обязателен. Под Diablo живут несколько процессов, их
     * адресные пространства независимы, и один и тот же числовой адрес таблицы в разных
     * процессах — разные страницы. Без pid сверка хозяйского зонда с гостевым
     * (macrunner-xtajit-dbgchan) сравнивает несравнимое. */
    /* ★★★★★ ИТЕРАЦИЯ 79-80, лейн МЕЛКИЕ — ОБЩИЙ КЛЮЧ МЕЖДУ КАРТОЙ И ОТКАЗОМ.
     *
     * Карта загрузчика (`+loaddll`) помечается pid-ом WINE (шестнадцатеричный `0028`,
     * см. строку 352: `GetCurrentProcessId()`), а все наши приборы печатают `getpid()`
     * (десятичный `52536`). Это разные пространства имён, и соединить их было нечем.
     * Цена измерена в итерации 79: в одном журнале taskmgr — 16 процессов, ОДИННАДЦАТЬ
     * разных `.exe` на базе 0x140000000 и 14 загрузок `rpcrt4.dll` на 9 базах; любая
     * привязка адреса к модулю в таком журнале недостоверна, и `koren-otkaza.py` выдал
     * `wineboot.exe RVA=0x46d27394` при размере образа 0x34000.
     *
     * Печать стоит здесь, а не в обработчике сигнала: это путь инициализации, замков
     * не берёт, и её достаточно ОДНОЙ на процесс — дальше пары сопоставляются разбором. */
    fprintf( stderr, "macrunner-dbgchan-init: pid=%d winepid=%04x таблица=%p peb=%p is_win64=%d nb=%d "
             "записи: [%02x '%.15s'] [%02x '%.15s'] [%02x '%.15s'] [%02x '%.15s']\n",
             (int)getpid(), (unsigned)GetCurrentProcessId(), options, peb, is_win64, nb_debug_options,
             options[0].flags, options[0].name, options[1].flags, options[1].name,
             options[2].flags, options[2].name, options[3].flags, options[3].name );
}


/***********************************************************************
 *  macrunner_dbg_mirror_options
 *
 * MacRunner 2026-08-27 — ТАБЛИЦА КАНАЛОВ ДЛЯ i386-СТОРОНЫ.
 *
 * Замер (прогон og-raw, сверка по ОДНОМУ процессу и ОДНОМУ адресу, с pid в обоих
 * зондах): хозяин пишет по 0x300202000 записи [ff 'd3d'] [03 ''], а гость через
 * 21 мс читает по тому же числовому адресу сырьё
 *   03 00 00 ... | 03 00 00 ...
 * — имени 'd3d' там нет вовсе. То есть числовое совпадение адресов обманчиво:
 * гостевой путь guest32_host_ptr ведёт не в ту страницу, куда писал dbg_init.
 *
 * Следствие: TRACE ни из одного i386-модуля (wined3d, ddraw, gdi32, opengl32) не
 * печатается — видны только fixme и err, включённые по умолчанию. Весь разбор
 * i386-стороны идёт вслепую.
 *
 * Копируем готовую таблицу ещё и по гостевому пути. Зовётся из env.c, когда PEB32
 * уже установлен и зеркало готово, — в самом dbg_init делать это рано.
 */
void macrunner_dbg_mirror_options( ULONG peb32 )
{
    void *dst;

    if (!init_done || !peb32) return;
    if (!(dst = macrunner_hb_wow64_guest32_host_ptr( (ULONG_PTR)peb32 + page_size ))) return;
    if (dst == debug_options) return;   /* уже одна и та же память — копировать нечего */

    memcpy( dst, debug_options, (nb_debug_options + 1) * sizeof(*debug_options) );
    fprintf( stderr, "macrunner-dbgchan-зеркало: pid=%d peb32=%08x откуда=%p куда=%p nb=%d\n",
             (int)getpid(), (unsigned)peb32, debug_options, dst, nb_debug_options );
    fflush( stderr );
}


/***********************************************************************
 *              NtTraceControl  (NTDLL.@)
 */
NTSTATUS WINAPI NtTraceControl( ULONG code, void *inbuf, ULONG inbuf_len,
                                void *outbuf, ULONG outbuf_len, ULONG *size )
{
    FIXME( "code %u, inbuf %p, inbuf_len %u, outbuf %p, outbuf_len %u, size %p\n",
           code, inbuf, inbuf_len, outbuf, outbuf_len, size );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              NtSetDebugFilterState  (NTDLL.@)
 */
NTSTATUS WINAPI NtSetDebugFilterState( ULONG component_id, ULONG level, BOOLEAN state )
{
    FIXME( "component_id %#x, level %u, state %#x stub.\n", component_id, level, state );

    return STATUS_SUCCESS;
}
