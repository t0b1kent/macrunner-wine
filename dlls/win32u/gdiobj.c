/*
 * GDI functions
 *
 * Copyright 1993 Alexandre Julliard
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

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>   /* итерация 813: getpid() для сопоставления писателя и читателя */

#include "windef.h"
#include "winbase.h"
#include "wingdi.h"
#include "winreg.h"
#include "winnls.h"
#include "winerror.h"
#include "winternl.h"

#include "ntgdi_private.h"
#include "wine/debug.h"
#include "wine/unixlib.h"

WINE_DEFAULT_DEBUG_CHANNEL(gdi);

/* ★ 06.09.2026 — реализация прибора в dib.c, здесь только заголовок. */
#include "hb_probe.h"

/* Имя второго прибора НАЧИНАЕТСЯ с `stockobj`, чтобы прежний потребитель
 * (`scripts/инварианты.sh`, поиск подстроки `macrunner-stockobj`) продолжал
 * находить обе выборки, а не потерял половину при разведении. */
HB_PROBE_DEFINE(pr_stockobj, "stockobj",
                "вызовы NtGdiGetStockObject с ГОДНЫМ номером объекта "
                "(0 <= obj <= STOCK_LAST+1, кроме 9). Недопустимые номера — те, что валят "
                "assert строкой ниже, — считает ОТДЕЛЬНЫЙ прибор stockobj-негодный: "
                "у них своя выборка и свой потолок, складывать эти два числа нельзя",
                NULL, 8);
HB_PROBE_DEFINE(pr_stockobj_bad, "stockobj-негодный",
                "вызовы NtGdiGetStockObject с номером, который валит assert "
                "(obj < 0, obj > STOCK_LAST+1 либо obj == 9) — стена ступени 1. "
                "Годные вызовы сюда НЕ попадают",
                NULL, 32);

#define FIRST_GDI_HANDLE 32

static GDI_SHARED_MEMORY *gdi_shared;
/* Итерация 814: свидетели завода. Строка `gdiinit` печатается в самой ранней фазе процесса,
 * когда stderr может быть ещё не сведён в журнал, поэтому её ОТСУТСТВИЕ ничего не доказывает
 * (замер 813). Эти два значения печатаются ПОЗДНО — в строке промаха, где stderr заведомо
 * работает: счётчик отвечает «завод был или нет», а сохранённый указатель — «подменили или
 * нет». */
static unsigned gdi_init_done;
static GDI_SHARED_MEMORY *gdi_shared_at_init;
/* Итерация 815: чей поток ведёт завод. Нужен ИМЕННО он, а не просто флаг: место вызова
 * (`class.c:264`) прямо предупреждает — «bootstrap can load cursors before shared session init
 * returns», то есть в `GetStockObject` можно войти ПОВТОРНО из того же потока, что выполняет
 * `gdi_init`. Если такой поток заставить ждать готовности, он будет ждать сам себя. */
static ULONG gdi_init_tid;
static GDI_HANDLE_ENTRY *next_free;
static GDI_HANDLE_ENTRY *next_unused;
static LONG debug_count;

static inline HGDIOBJ entry_to_handle( GDI_HANDLE_ENTRY *entry )
{
    unsigned int idx = entry - gdi_shared->Handles;
    return ULongToHandle( idx | (entry->Unique << NTGDI_HANDLE_TYPE_SHIFT) );
}

static inline GDI_HANDLE_ENTRY *handle_entry( HGDIOBJ handle )
{
    unsigned int idx = LOWORD(handle);

    if (idx < GDI_MAX_HANDLE_COUNT && gdi_shared->Handles[idx].Type)
    {
        if (!HIWORD( handle ) || HIWORD( handle ) == gdi_shared->Handles[idx].Unique)
            return &gdi_shared->Handles[idx];
    }
    if (handle) WARN( "invalid handle %p\n", handle );
    return NULL;
}

static inline struct gdi_obj_header *entry_obj( GDI_HANDLE_ENTRY *entry )
{
    return (struct gdi_obj_header *)(ULONG_PTR)entry->Object;
}

/***********************************************************************
 *          GDI stock objects
 */

static const LOGBRUSH WhiteBrush = { BS_SOLID, RGB(255,255,255), 0 };
static const LOGBRUSH BlackBrush = { BS_SOLID, RGB(0,0,0), 0 };
static const LOGBRUSH NullBrush  = { BS_NULL, 0, 0 };

static const LOGBRUSH LtGrayBrush = { BS_SOLID, RGB(192,192,192), 0 };
static const LOGBRUSH GrayBrush   = { BS_SOLID, RGB(128,128,128), 0 };
static const LOGBRUSH DkGrayBrush = { BS_SOLID, RGB(64,64,64), 0 };

static const LOGBRUSH DCBrush = { BS_SOLID, RGB(255,255,255), 0 };

static pthread_mutex_t gdi_lock;


/****************************************************************************
 *
 *	language-independent stock fonts
 *
 */

static const LOGFONTW OEMFixedFont =
{ 12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, OEM_CHARSET,
  0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN };

static const LOGFONTW AnsiFixedFont =
{ 12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET,
  0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
  {'C','o','u','r','i','e','r'} };

static const LOGFONTW AnsiVarFont =
{ 12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET,
  0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
  {'M','S',' ','S','a','n','s',' ','S','e','r','i','f'} };

/******************************************************************************
 *
 *      language-dependent stock fonts
 *
 *      'ANSI' charset and 'DEFAULT' charset is not same.
 *      The chars in CP_ACP should be drawn with 'DEFAULT' charset.
 *      'ANSI' charset seems to be identical with ISO-8859-1.
 *      'DEFAULT' charset is a language-dependent charset.
 *
 *      'System' font seems to be an alias for language-dependent font.
 */

/*
 * language-dependent stock fonts for all known charsets
 * please see TranslateCharsetInfo (dlls/gdi/font.c) and
 * CharsetBindingInfo (dlls/x11drv/xfont.c),
 * and modify entries for your language if needed.
 */
struct DefaultFontInfo
{
        UINT            charset;
        LOGFONTW        SystemFont;
        LOGFONTW        DeviceDefaultFont;
        LOGFONTW        SystemFixedFont;
        LOGFONTW        DefaultGuiFont;
};

static const struct DefaultFontInfo default_fonts[] =
{
    {   ANSI_CHARSET,
        { /* System */
          16, 7, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* Device Default */
          16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* System Fixed */
          16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET,
           0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
           {'C','o','u','r','i','e','r'}
        },
        { /* DefaultGuiFont */
          -11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'M','S',' ','S','h','e','l','l',' ','D','l','g'}
        },
    },
    {   EASTEUROPE_CHARSET,
        { /* System */
          16, 7, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, EASTEUROPE_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* Device Default */
          16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, EASTEUROPE_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* System Fixed */
          16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, EASTEUROPE_CHARSET,
           0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
           {'C','o','u','r','i','e','r'}
        },
        { /* DefaultGuiFont */
          -11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, EASTEUROPE_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'M','S',' ','S','h','e','l','l',' ','D','l','g'}
        },
    },
    {   RUSSIAN_CHARSET,
        { /* System */
          16, 7, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, RUSSIAN_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* Device Default */
          16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, RUSSIAN_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* System Fixed */
          16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, RUSSIAN_CHARSET,
           0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
           {'C','o','u','r','i','e','r'}
        },
        { /* DefaultGuiFont */
          -11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, RUSSIAN_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'M','S',' ','S','h','e','l','l',' ','D','l','g'}
        },
    },
    {   GREEK_CHARSET,
        { /* System */
          16, 7, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, GREEK_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* Device Default */
          16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, GREEK_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* System Fixed */
          16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, GREEK_CHARSET,
           0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
           {'C','o','u','r','i','e','r'}
        },
        { /* DefaultGuiFont */
          -11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, GREEK_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'M','S',' ','S','h','e','l','l',' ','D','l','g'}
        },
    },
    {   TURKISH_CHARSET,
        { /* System */
          16, 7, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, TURKISH_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* Device Default */
          16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, TURKISH_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* System Fixed */
          16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, TURKISH_CHARSET,
           0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
           {'C','o','u','r','i','e','r'}
        },
        { /* DefaultGuiFont */
          -11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, TURKISH_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'M','S',' ','S','h','e','l','l',' ','D','l','g'}
        },
    },
    {   HEBREW_CHARSET,
        { /* System */
          16, 7, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, HEBREW_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* Device Default */
          16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, HEBREW_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* System Fixed */
          16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, HEBREW_CHARSET,
           0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
           {'C','o','u','r','i','e','r'}
        },
        { /* DefaultGuiFont */
          -11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, HEBREW_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'M','S',' ','S','h','e','l','l',' ','D','l','g'}
        },
    },
    {   ARABIC_CHARSET,
        { /* System */
          16, 7, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ARABIC_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* Device Default */
          16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ARABIC_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* System Fixed */
          16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ARABIC_CHARSET,
           0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
           {'C','o','u','r','i','e','r'}
        },
        { /* DefaultGuiFont */
          -11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ARABIC_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'M','S',' ','S','h','e','l','l',' ','D','l','g'}
        },
    },
    {   BALTIC_CHARSET,
        { /* System */
          16, 7, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, BALTIC_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* Device Default */
          16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, BALTIC_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* System Fixed */
          16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, BALTIC_CHARSET,
           0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
           {'C','o','u','r','i','e','r'}
        },
        { /* DefaultGuiFont */
          -11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, BALTIC_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'M','S',' ','S','h','e','l','l',' ','D','l','g'}
        },
    },
    {   THAI_CHARSET,
        { /* System */
          16, 7, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, THAI_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* Device Default */
          16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, THAI_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* System Fixed */
          16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, THAI_CHARSET,
           0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
           {'C','o','u','r','i','e','r'}
        },
        { /* DefaultGuiFont */
          -11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, THAI_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'M','S',' ','S','h','e','l','l',' ','D','l','g'}
        },
    },
    {   SHIFTJIS_CHARSET,
        { /* System */
          18, 8, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, SHIFTJIS_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* Device Default */
          18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, SHIFTJIS_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* System Fixed */
          16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, SHIFTJIS_CHARSET,
           0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
           {'C','o','u','r','i','e','r'}
        },
        { /* DefaultGuiFont */
          -12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, SHIFTJIS_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'M','S',' ','S','h','e','l','l',' ','D','l','g'}
        },
    },
    {   GB2312_CHARSET,
        { /* System */
          16, 7, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, GB2312_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* Device Default */
          16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, GB2312_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* System Fixed */
          16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, GB2312_CHARSET,
           0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
           {'C','o','u','r','i','e','r'}
        },
        { /* DefaultGuiFont */
          -12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, GB2312_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'M','S',' ','S','h','e','l','l',' ','D','l','g'}
        },
    },
    {   HANGEUL_CHARSET,
        { /* System */
          16, 8, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, HANGEUL_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* Device Default */
          16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, HANGEUL_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* System Fixed */
          16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, HANGEUL_CHARSET,
           0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
           {'C','o','u','r','i','e','r'}
        },
        { /* DefaultGuiFont */
          -12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, HANGEUL_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'M','S',' ','S','h','e','l','l',' ','D','l','g'}
        },
    },
    {   CHINESEBIG5_CHARSET,
        { /* System */
          16, 7, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, CHINESEBIG5_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* Device Default */
          16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, CHINESEBIG5_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* System Fixed */
          16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, CHINESEBIG5_CHARSET,
           0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
           {'C','o','u','r','i','e','r'}
        },
        { /* DefaultGuiFont */
          -12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, CHINESEBIG5_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'M','S',' ','S','h','e','l','l',' ','D','l','g'}
        },
    },
    {   JOHAB_CHARSET,
        { /* System */
          16, 7, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, JOHAB_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* Device Default */
          16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, JOHAB_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'S','y','s','t','e','m'}
        },
        { /* System Fixed */
          16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, JOHAB_CHARSET,
           0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
           {'C','o','u','r','i','e','r'}
        },
        { /* DefaultGuiFont */
          -12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, JOHAB_CHARSET,
           0, 0, DEFAULT_QUALITY, VARIABLE_PITCH | FF_SWISS,
           {'M','S',' ','S','h','e','l','l',' ','D','l','g'}
        },
    },
};

void make_gdi_object_system( HGDIOBJ handle, BOOL set)
{
    GDI_HANDLE_ENTRY *entry;

    pthread_mutex_lock( &gdi_lock );
    if ((entry = handle_entry( handle ))) entry_obj( entry )->system = !!set;
    pthread_mutex_unlock( &gdi_lock );
}

/******************************************************************************
 *      get_default_fonts
 */
static const struct DefaultFontInfo* get_default_fonts(void)
{
    unsigned int n;
    CHARSETINFO csi;

    if (ansi_cp.CodePage == CP_UTF8) return &default_fonts[0];

    csi.ciCharset = ANSI_CHARSET;
    translate_charset_info( ULongToPtr(ansi_cp.CodePage), &csi, TCI_SRCCODEPAGE );

    for(n = 0; n < ARRAY_SIZE( default_fonts ); n++)
        if ( default_fonts[n].charset == csi.ciCharset )
            return &default_fonts[n];

    FIXME( "unhandled charset 0x%08x - use ANSI_CHARSET for default stock objects\n", csi.ciCharset );
    return &default_fonts[0];
}


/***********************************************************************
 *           GDI_get_ref_count
 *
 * Retrieve the reference count of a GDI object.
 * Note: the object must be locked otherwise the count is meaningless.
 */
UINT GDI_get_ref_count( HGDIOBJ handle )
{
    GDI_HANDLE_ENTRY *entry;
    UINT ret = 0;

    pthread_mutex_lock( &gdi_lock );
    if ((entry = handle_entry( handle ))) ret = entry_obj( entry )->selcount;
    pthread_mutex_unlock( &gdi_lock );
    return ret;
}


/***********************************************************************
 *           GDI_inc_ref_count
 *
 * Increment the reference count of a GDI object.
 */
HGDIOBJ GDI_inc_ref_count( HGDIOBJ handle )
{
    GDI_HANDLE_ENTRY *entry;

    pthread_mutex_lock( &gdi_lock );
    if ((entry = handle_entry( handle ))) entry_obj( entry )->selcount++;
    else handle = 0;
    pthread_mutex_unlock( &gdi_lock );
    return handle;
}


/***********************************************************************
 *           GDI_dec_ref_count
 *
 * Decrement the reference count of a GDI object.
 */
BOOL GDI_dec_ref_count( HGDIOBJ handle )
{
    GDI_HANDLE_ENTRY *entry;

    pthread_mutex_lock( &gdi_lock );
    if ((entry = handle_entry( handle )))
    {
        assert( entry_obj( entry )->selcount );
        if (!--entry_obj( entry )->selcount && entry_obj( entry )->deleted)
        {
            /* handle delayed DeleteObject*/
            entry_obj( entry )->deleted = 0;
            pthread_mutex_unlock( &gdi_lock );
            TRACE( "executing delayed DeleteObject for %p\n", handle );
            NtGdiDeleteObjectApp( handle );
            return TRUE;
        }
    }
    pthread_mutex_unlock( &gdi_lock );
    return entry != NULL;
}


static HFONT create_font( const LOGFONTW *deffont )
{
    ENUMLOGFONTEXDVW lf;

    memset( &lf, 0, sizeof(lf) );
    lf.elfEnumLogfontEx.elfLogFont = *deffont;
    return NtGdiHfontCreate( &lf, sizeof(lf), 0, 0, NULL );
}

static HFONT create_scaled_font( const LOGFONTW *deffont, unsigned int dpi )
{
    LOGFONTW lf;

    lf = *deffont;
    lf.lfHeight = muldiv( lf.lfHeight, dpi, 96 );
    return create_font( &lf );
}

static void init_gdi_shared(void)
{
    SIZE_T size = sizeof(*gdi_shared);

    if (NtAllocateVirtualMemory( GetCurrentProcess(), (void **)&gdi_shared, zero_bits,
                                 &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE ))
        return;
    next_unused = gdi_shared->Handles + FIRST_GDI_HANDLE;

#ifndef _WIN64
    if (win32u_current_teb64())
    {
        TEB64 *teb64 = win32u_current_teb64();
        PEB64 *peb64 = (PEB64 *)(UINT_PTR)teb64->Peb;
        if (teb64->Peb && !((UINT_PTR)peb64 & (sizeof(ULONG64) - 1)))
        {
            peb64->GdiSharedHandleTable = (UINT_PTR)gdi_shared;
            return;
        }
        WARN( "invalid wow64 PEB64 mirror target teb64=%p peb64=%p\n", teb64, peb64 );
    }
#else
    if (NtCurrentTeb()->WowTebOffset)
    {
        /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — ПЕРЕВОД ГОСТЕВОГО АДРЕСА.
         *
         * Здесь корень ранней смерти ступени 1, доказанный итерацией 174 тремя
         * сходимостями: машинный код (`ldr w8,[x8,#0x30]` затем `str w19,[x8,#0x94]`),
         * заголовок (`PEB32.GdiSharedHandleTable` = 0x94) и арифметика отказа
         * (`si_addr = 0x201094` при `teb32->Peb = 0x201000`).
         *
         * `teb32->Peb` — адрес В ГОСТЕВОМ пространстве. В апстриме 32-битный гость лежит в
         * нижних 4 ГБ тождественно, поэтому приведение к указателю там ВЕРНО. У нас гость
         * живёт по ненулевой базе (наблюдал 0x3/0x5/0xb/0xd × 4 ГБ), и запись уходит по
         * непереведённому адресу — процесс гибнет на третьей секунде.
         *
         * Прерывистость отсюда же: сторож `if (teb32->Peb)` пропускает запись, пока поле
         * ещё ноль, поэтому часть прогонов выживала — та самая «половина» из итераций 163-165.
         *
         * Гейт снят 02.09.2026, правка безусловна.
         * чтобы мерить чередованием. */
        TEB32 *teb32 = (TEB32 *)((char *)NtCurrentTeb() + NtCurrentTeb()->WowTebOffset);
        PEB32 *peb32 = (PEB32 *)(UINT_PTR)teb32->Peb;
        if (teb32->Peb)
        {
            /* Гейт MACRUNNER_HB_GDI_PEB32_XLAT снят 02.09.2026: выключенная ветка оставляла
             * teb32->Peb гостевым адресом в хозяйском пространстве, отчего gdi32 читал по
             * NULL (0x30e у Heroes, 0x33e у UT99). Перевод адреса безусловен. */
            {
                extern unsigned long long macrunner_hb_wow64_guest32_base(void);
                unsigned long long base = macrunner_hb_wow64_guest32_base();
                if (base)
                {
                    peb32 = (PEB32 *)(UINT_PTR)(base + (unsigned long long)teb32->Peb);
                    /* Печать через stderr, а НЕ через ERR(): канал err в этом проекте до
                     * журналов не доходит ни в одном прогоне за всю историю. */
                    fprintf( stderr, "macrunner-hb-gdi-peb32-xlat: guest=%08x base=%llx host=%p\n",
                             (unsigned int)teb32->Peb, base, peb32 );
                    fflush( stderr );
                }
            }
            peb32->GdiSharedHandleTable = PtrToUlong( gdi_shared );
        }
    }
#endif
    /* NOTE: Windows uses 32-bit for 32-bit kernel */
    NtCurrentTeb()->Peb->GdiSharedHandleTable = gdi_shared;
}

/***********************************************************************
 *           GetStockObject    (win32u.so)
 */
HGDIOBJ WINAPI GetStockObject( INT obj )
{
    /* MacRunner 2026-08-13, лейн ЛЕСТНИЦА, итерация 810 — ЧТО ИМЕННО СЮДА ПЕРЕДАЮТ.
     *
     * Итерация 809 разрешила адрес ловушки ступени 1: `win32u.so + 0x129b78`, символ
     * `_GetStockObject.cold.1 + 40` — то есть провалившийся `assert` строкой ниже. Осталось
     * узнать значение и вызывающего.
     *
     * Печатаются ДВА набора: первые 8 вызовов БЕЗУСЛОВНО и все недопустимые (потолок 32).
     * Только недопустимых было бы мало: их отсутствие не отличалось бы от молчащего зонда, а
     * это ровно та ловушка, на которой лейн уже терял прогоны. */
    /* ★★ 06.09.2026, лейн ПРИБОРЫ-3 — ОДНА СТРОКА, ДВЕ ПОПУЛЯЦИИ, ТРИ ДЕФЕКТА.
     *
     *     if (bad ? (probe_bad < 32 && ++probe_bad) : (probe_all < 8 && ++probe_all))
     *
     * 1. ДВЕ РАЗНЫЕ ВЫБОРКИ печатались под ОДНИМ именем и с РАЗНЫМИ потолками (32 и 8).
     *    Сложить их числа нельзя, а из журнала это не видно — ровно так у нас уже вышло
     *    с write-deny, где тяжёлый диапазон печатался без потолка;
     * 2. `++probe_N` стоит СПРАВА от `&&` и потому НЕ выполняется, когда потолок уже
     *    выбран: счётчик считает НАПЕЧАТАННОЕ, а не случившееся;
     * 3. молчание после потолка неотличимо от «недопустимых вызовов не было» — а именно
     *    этим прибором scripts/инварианты.sh проверяет стену ступени 1.
     *
     * Разведено на два прибора со своими популяциями и потолками; учёт всегда, печать
     * ограничена, число объявляет себя нижней границей само. */
    {
        int bad = (obj < 0 || obj > STOCK_LAST + 1 || obj == 9);

        HB_PROBE_LOOKED( &pr_stockobj );
        HB_PROBE_LOOKED( &pr_stockobj_bad );
        if (bad)
            HB_PROBE_SAY( &pr_stockobj_bad, "obj=%d годен=0 STOCK_LAST=%d вызвал=%p\n",
                          (int)obj, (int)STOCK_LAST, __builtin_return_address(0) );
        else
            HB_PROBE_SAY( &pr_stockobj, "obj=%d годен=1 STOCK_LAST=%d вызвал=%p\n",
                          (int)obj, (int)STOCK_LAST, __builtin_return_address(0) );
        fflush( stderr );
    }
    assert( obj >= 0 && obj <= STOCK_LAST + 1 && obj != 9 );

    switch (obj)
    {
    case OEM_FIXED_FONT:
        if (get_system_dpi() != 96) obj = 9;
        break;
    case SYSTEM_FONT:
        if (get_system_dpi() != 96) obj = STOCK_LAST + 2;
        break;
    case SYSTEM_FIXED_FONT:
        if (get_system_dpi() != 96) obj = STOCK_LAST + 3;
        break;
    case DEFAULT_GUI_FONT:
        if (get_system_dpi() != 96) obj = STOCK_LAST + 4;
        break;
    }

    /* MacRunner 2026-08-13, лейн ЛЕСТНИЦА, итерация 811 — ПОЧЕМУ ЗАПИСЬ НЕ НАХОДИТСЯ.
     *
     * Итерация 810 доказала дизассемблером: ловушка `brk #1` стоит сразу за `WARN("invalid
     * handle")` из встроенной `handle_entry`, а номер объекта ДОПУСТИМ в 65 случаях из 65.
     * Значит запись дескриптора пуста либо чужая. Здесь печатаются те пять чисел, которые
     * различают эти два случая, и ничего больше.
     *
     * Отдельно и НЕЗАВИСИМО — защита от ловушки: `entry_to_handle` разыменовывает ноль без
     * проверки, и это неопределённое поведение. Windows на недопустимый номер отдаёт NULL, а
     * не падает. Гейт `MACRUNNER_WIN32U_STOCKOBJ_NULL_OK` по умолчанию ВКЛЮЧЁН (отключение
     * значением `0`): выключенное по умолчанию лекарство — главная статья потерь проекта.
     * Два вопроса разделены гейтом, поэтому одна сборка отвечает на оба. */
    {
        HGDIOBJ handle = ULongToHandle( obj + FIRST_GDI_HANDLE );
        GDI_HANDLE_ENTRY *entry = handle_entry( handle );

        if (!entry)
        {
            static unsigned probe_n;
            unsigned int idx = LOWORD( handle );
            const char *off = getenv( "MACRUNNER_WIN32U_STOCKOBJ_NULL_OK" );
            int null_ok = !(off && off[0] == '0');

            if (probe_n < 32)
            {
                probe_n++;
                fprintf( stderr, "macrunner-stockobj-miss: n=%u obj=%d idx=%u shared=%p "
                         "тип=%08x hiword=%04x unique=%04x предел=%u гейт=%d pid=%p unix=%d "
                         "завод=%u указатель_при_заводе=%p поток_завода=%08x поток_сейчас=%08x\n",
                         probe_n, (int)obj, idx, gdi_shared,
                         (gdi_shared && idx < GDI_MAX_HANDLE_COUNT)
                             ? (unsigned)gdi_shared->Handles[idx].Type : 0xffffffffu,
                         (unsigned)HIWORD( handle ),
                         (gdi_shared && idx < GDI_MAX_HANDLE_COUNT)
                             ? (unsigned)gdi_shared->Handles[idx].Unique : 0xffffu,
                         (unsigned)GDI_MAX_HANDLE_COUNT, null_ok,
                         NtCurrentTeb()->ClientId.UniqueProcess, (int)getpid(),
                         gdi_init_done, gdi_shared_at_init, (unsigned)gdi_init_tid,
                         (unsigned)HandleToULong( NtCurrentTeb()->ClientId.UniqueThread ) );
                fflush( stderr );
            }
            /* Итерация 817: блок ОЖИДАНИЯ готовности СНЯТ. Он был построен в 815 под
             * гипотезу «гонка двух потоков» и не сработал ни разу за четыре руки при 12
             * промахах в каждой. Причина выяснена в 816 и делает ожидание невозможным по
             * построению: `поток_завода == поток_сейчас` во всех промахах, то есть в
             * `GetStockObject` заходит ТОТ ЖЕ поток, что ведёт `gdi_init`. Ждать — значит
             * ждать самого себя. Мёртвый код убран, чтобы он не выглядел работающим
             * лекарством; свидетели потоков в печати ОСТАВЛЕНЫ, они и есть доказательство. */
            if (null_ok) return 0;
        }
        return entry_to_handle( entry );
    }
}

static void init_stock_objects( unsigned int dpi )
{
    const struct DefaultFontInfo *deffonts;
    unsigned int i;
    HGDIOBJ obj;

    /* Create stock objects in order matching stock object macros,
     * so that they use predictable handle slots. Our GetStockObject
     * depends on it. */
    create_brush( &WhiteBrush );
    create_brush( &LtGrayBrush );
    create_brush( &GrayBrush );
    create_brush( &DkGrayBrush );
    create_brush( &BlackBrush );
    create_brush( &NullBrush );

    create_pen( PS_SOLID, 0, RGB(255,255,255) );
    create_pen( PS_SOLID, 0, RGB(0,0,0) );
    create_pen( PS_NULL,  0, RGB(0,0,0) );

    /* slot 9 is not used for non-scaled stock objects */
    create_scaled_font( &OEMFixedFont, dpi );

    /* language-independent stock fonts */
    create_font( &OEMFixedFont );
    create_font( &AnsiFixedFont );
    create_font( &AnsiVarFont );

    /* language-dependent stock fonts */
    deffonts = get_default_fonts();
    create_font( &deffonts->SystemFont );
    create_font( &deffonts->DeviceDefaultFont );

    PALETTE_Init();

    create_font( &deffonts->SystemFixedFont );
    create_font( &deffonts->DefaultGuiFont );

    create_brush( &DCBrush );
    NtGdiCreatePen( PS_SOLID, 0, RGB(0,0,0), NULL );

    obj = NtGdiCreateBitmap( 1, 1, 1, 1, NULL );

    assert( (HandleToULong( obj ) & 0xffff) == FIRST_GDI_HANDLE + DEFAULT_BITMAP );

    create_scaled_font( &deffonts->SystemFont, dpi );
    create_scaled_font( &deffonts->SystemFixedFont, dpi );
    create_scaled_font( &deffonts->DefaultGuiFont, dpi );

    /* clear the NOSYSTEM bit on all stock objects*/
    for (i = 0; i < STOCK_LAST + 5; i++)
    {
        GDI_HANDLE_ENTRY *entry = &gdi_shared->Handles[FIRST_GDI_HANDLE + i];
        entry_obj( entry )->system = TRUE;
        entry->StockFlag = 1;
    }
}


static const char *gdi_obj_type( unsigned type )
{
    switch ( type )
    {
        case NTGDI_OBJ_PEN: return "NTGDI_OBJ_PEN";
        case NTGDI_OBJ_BRUSH: return "NTGDI_OBJ_BRUSH";
        case NTGDI_OBJ_DC: return "NTGDI_OBJ_DC";
        case NTGDI_OBJ_METADC: return "NTGDI_OBJ_METADC";
        case NTGDI_OBJ_PAL: return "NTGDI_OBJ_PAL";
        case NTGDI_OBJ_FONT: return "NTGDI_OBJ_FONT";
        case NTGDI_OBJ_BITMAP: return "NTGDI_OBJ_BITMAP";
        case NTGDI_OBJ_REGION: return "NTGDI_OBJ_REGION";
        case NTGDI_OBJ_METAFILE: return "NTGDI_OBJ_METAFILE";
        case NTGDI_OBJ_MEMDC: return "NTGDI_OBJ_MEMDC";
        case NTGDI_OBJ_EXTPEN: return "NTGDI_OBJ_EXTPEN";
        case NTGDI_OBJ_ENHMETADC: return "NTGDI_OBJ_ENHMETADC";
        case NTGDI_OBJ_ENHMETAFILE: return "NTGDI_OBJ_ENHMETAFILE";
        default: return "UNKNOWN";
    }
}

static void dump_gdi_objects( void )
{
    GDI_HANDLE_ENTRY *entry;

    TRACE( "%u objects:\n", GDI_MAX_HANDLE_COUNT );

    pthread_mutex_lock( &gdi_lock );
    for (entry = gdi_shared->Handles; entry < next_unused; entry++)
    {
        if (!entry->Type)
            TRACE( "handle %p FREE\n", entry_to_handle( entry ));
        else
            TRACE( "handle %p obj %s type %s selcount %u deleted %u\n",
                   entry_to_handle( entry ), wine_dbgstr_longlong( entry->Object ),
                   gdi_obj_type( entry->ExtType << NTGDI_HANDLE_TYPE_SHIFT ),
                   entry_obj( entry )->selcount, entry_obj( entry )->deleted );
    }
    pthread_mutex_unlock( &gdi_lock );
}

/***********************************************************************
 *           alloc_gdi_handle
 *
 * Allocate a GDI handle for an object, which must have been allocated on the process heap.
 */
HGDIOBJ alloc_gdi_handle( struct gdi_obj_header *obj, DWORD type, const struct gdi_obj_funcs *funcs )
{
    GDI_HANDLE_ENTRY *entry;
    HGDIOBJ ret;

    assert( type );  /* type 0 is reserved to mark free entries */

    pthread_mutex_lock( &gdi_lock );

    entry = next_free;
    if (entry)
        next_free = (GDI_HANDLE_ENTRY *)(UINT_PTR)entry->Object;
    else if (next_unused < gdi_shared->Handles + GDI_MAX_HANDLE_COUNT)
        entry = next_unused++;
    else
    {
        pthread_mutex_unlock( &gdi_lock );
        ERR( "out of GDI object handles, expect a crash\n" );
        if (TRACE_ON(gdi)) dump_gdi_objects();
        return 0;
    }
    obj->funcs    = funcs;
    obj->selcount = 0;
    obj->system   = 0;
    obj->deleted  = 0;
    entry->Object  = (UINT_PTR)obj;
    entry->ExtType = type >> NTGDI_HANDLE_TYPE_SHIFT;
    entry->Type    = entry->ExtType & 0x1f;
    if (++entry->Generation == 0x80) entry->Generation = 1;
    ret = entry_to_handle( entry );
    pthread_mutex_unlock( &gdi_lock );
    TRACE( "allocated %s %p %u/%u\n", gdi_obj_type(type), ret,
           InterlockedIncrement( &debug_count ), GDI_MAX_HANDLE_COUNT );
    return ret;
}


/***********************************************************************
 *           free_gdi_handle
 *
 * Free a GDI handle and return a pointer to the object.
 */
void *free_gdi_handle( HGDIOBJ handle )
{
    void *object = NULL;
    GDI_HANDLE_ENTRY *entry;

    pthread_mutex_lock( &gdi_lock );
    if ((entry = handle_entry( handle )))
    {
        TRACE( "freed %s %p %u/%u\n", gdi_obj_type( entry->ExtType << NTGDI_HANDLE_TYPE_SHIFT ),
               handle, InterlockedDecrement( &debug_count ) + 1, GDI_MAX_HANDLE_COUNT );
        object = entry_obj( entry );
        entry->Type = 0;
        entry->Object = (UINT_PTR)next_free;
        next_free = entry;
    }
    pthread_mutex_unlock( &gdi_lock );
    return object;
}

DWORD get_gdi_object_type( HGDIOBJ obj )
{
    GDI_HANDLE_ENTRY *entry = handle_entry( obj );
    return entry ? entry->ExtType << NTGDI_HANDLE_TYPE_SHIFT : 0;
}

void set_gdi_client_ptr( HGDIOBJ obj, void *ptr )
{
    GDI_HANDLE_ENTRY *entry = handle_entry( obj );
    if (entry) entry->UserPointer = (UINT_PTR)ptr;
}

/***********************************************************************
 *           get_any_obj_ptr
 *
 * Return a pointer to, and the type of, the GDI object
 * associated with the handle.
 * The object must be released with GDI_ReleaseObj.
 */
void *get_any_obj_ptr( HGDIOBJ handle, DWORD *type )
{
    void *ptr = NULL;
    GDI_HANDLE_ENTRY *entry;

    pthread_mutex_lock( &gdi_lock );

    if ((entry = handle_entry( handle )))
    {
        ptr = entry_obj( entry );
        *type = entry->ExtType << NTGDI_HANDLE_TYPE_SHIFT;
    }

    if (!ptr) pthread_mutex_unlock( &gdi_lock );
    return ptr;
}

/***********************************************************************
 *           GDI_GetObjPtr
 *
 * Return a pointer to the GDI object associated with the handle.
 * Return NULL if the object has the wrong type.
 * The object must be released with GDI_ReleaseObj.
 */
void *GDI_GetObjPtr( HGDIOBJ handle, DWORD type )
{
    DWORD ret_type;
    void *ptr = get_any_obj_ptr( handle, &ret_type );
    if (ptr && ret_type != type)
    {
        GDI_ReleaseObj( handle );
        ptr = NULL;
    }
    return ptr;
}

/***********************************************************************
 *           GDI_ReleaseObj
 *
 */
void GDI_ReleaseObj( HGDIOBJ handle )
{
    pthread_mutex_unlock( &gdi_lock );
}


/***********************************************************************
 *           NtGdiDeleteObjectApp    (win32u.@)
 *
 * Delete a Gdi object.
 *
 * PARAMS
 *  obj [I] Gdi object to delete
 *
 * RETURNS
 *  Success: TRUE. If obj was not returned from GetStockObject(), any resources
 *           it consumed are released.
 *  Failure: FALSE, if obj is not a valid Gdi object, or is currently selected
 *           into a DC.
 */
BOOL WINAPI NtGdiDeleteObjectApp( HGDIOBJ obj )
{
    GDI_HANDLE_ENTRY *entry;
    const struct gdi_obj_funcs *funcs = NULL;
    struct gdi_obj_header *header;

    pthread_mutex_lock( &gdi_lock );
    if (!(entry = handle_entry( obj )))
    {
        pthread_mutex_unlock( &gdi_lock );
        return FALSE;
    }

    header = entry_obj( entry );
    if (header->system)
    {
	TRACE("Preserving system object %p\n", obj);
        pthread_mutex_unlock( &gdi_lock );
	return TRUE;
    }

    obj = entry_to_handle( entry );  /* make it a full handle */

    if (header->selcount)
    {
        TRACE("delayed for %p because object in use, count %u\n", obj, header->selcount );
        header->deleted = 1;  /* mark for delete */
    }
    else funcs = header->funcs;

    pthread_mutex_unlock( &gdi_lock );

    TRACE("%p\n", obj );

    if (funcs && funcs->pDeleteObject) return funcs->pDeleteObject( obj );
    return TRUE;
}

/***********************************************************************
 *           NtGdiCreateClientObj    (win32u.@)
 */
HANDLE WINAPI NtGdiCreateClientObj( ULONG type )
{
    struct gdi_obj_header *obj;
    HGDIOBJ handle;

    if (!(obj = malloc( sizeof(*obj) )))
        return 0;

    handle = alloc_gdi_handle( obj, type, NULL );
    if (!handle) free( obj );
    return handle;
}

/***********************************************************************
 *           NtGdiDeleteClientObj    (win32u.@)
 */
BOOL WINAPI NtGdiDeleteClientObj( HGDIOBJ handle )
{
    void *obj;
    if (!(obj = free_gdi_handle( handle ))) return FALSE;
    free( obj );
    return TRUE;
}


/***********************************************************************
 *           NtGdiExtGetObjectW    (win32u.@)
 */
INT WINAPI NtGdiExtGetObjectW( HGDIOBJ handle, INT count, void *buffer )
{
    GDI_HANDLE_ENTRY *entry;
    const struct gdi_obj_funcs *funcs = NULL;
    INT result = 0;

    TRACE("%p %d %p\n", handle, count, buffer );

    pthread_mutex_lock( &gdi_lock );
    if ((entry = handle_entry( handle )))
    {
        funcs = entry_obj( entry )->funcs;
        handle = entry_to_handle( entry );  /* make it a full handle */
    }
    pthread_mutex_unlock( &gdi_lock );

    if (funcs && funcs->pGetObjectW)
    {
        if (buffer && ((ULONG_PTR)buffer >> 16) == 0) /* catch apps getting argument order wrong */
            RtlSetLastWin32Error( ERROR_NOACCESS );
        else
            result = funcs->pGetObjectW( handle, count, buffer );
    }
    return result;
}

/***********************************************************************
 *           NtGdiGetDCObject    (win32u.@)
 *
 * Get the currently selected object of a given type in a device context.
 */
HANDLE WINAPI NtGdiGetDCObject( HDC hdc, UINT type )
{
    HGDIOBJ ret = 0;
    DC *dc;

    if (!(dc = get_dc_ptr( hdc ))) return 0;

    switch (type)
    {
    case NTGDI_OBJ_EXTPEN: /* fall through */
    case NTGDI_OBJ_PEN:    ret = dc->hPen; break;
    case NTGDI_OBJ_BRUSH:  ret = dc->hBrush; break;
    case NTGDI_OBJ_PAL:    ret = dc->hPalette; break;
    case NTGDI_OBJ_FONT:   ret = dc->hFont; break;
    case NTGDI_OBJ_SURF:
        /* Update bitmap for display device contexts */
        if (dc->is_display) dc->hBitmap = get_display_bitmap();
        ret = dc->hBitmap; break;
    default:
        FIXME( "(%p, %d): unknown type.\n", hdc, type );
        break;
    }
    release_dc_ptr( dc );
    return ret;
}


/***********************************************************************
 *           NtGdiUnrealizeObject    (win32u.@)
 */
BOOL WINAPI NtGdiUnrealizeObject( HGDIOBJ obj )
{
    const struct gdi_obj_funcs *funcs = NULL;
    GDI_HANDLE_ENTRY *entry;

    pthread_mutex_lock( &gdi_lock );
    if ((entry = handle_entry( obj )))
    {
        funcs = entry_obj( entry )->funcs;
        obj = entry_to_handle( entry );  /* make it a full handle */
    }
    pthread_mutex_unlock( &gdi_lock );

    if (funcs && funcs->pUnrealizeObject) return funcs->pUnrealizeObject( obj );
    return funcs != NULL;
}


/***********************************************************************
 *           NtGdiFlush    (win32u.@)
 */
BOOL WINAPI NtGdiFlush(void)
{
    return TRUE;  /* FIXME */
}


/*******************************************************************
 *           NtGdiGetColorAdjustment    (win32u.@)
 */
BOOL WINAPI NtGdiGetColorAdjustment( HDC hdc, COLORADJUSTMENT *ca )
{
    FIXME( "stub\n" );
    return FALSE;
}

/*******************************************************************
 *           NtGdiSetColorAdjustment    (win32u.@)
 */
BOOL WINAPI NtGdiSetColorAdjustment( HDC hdc, const COLORADJUSTMENT *ca )
{
    FIXME( "stub\n" );
    return FALSE;
}

void gdi_init(void)
{
    pthread_mutexattr_t attr;
    unsigned int dpi;

    pthread_mutexattr_init( &attr );
    pthread_mutexattr_settype( &attr, PTHREAD_MUTEX_RECURSIVE );
    pthread_mutex_init( &gdi_lock, &attr );
    pthread_mutexattr_destroy( &attr );

    gdi_init_tid = HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );
    init_gdi_shared();
    /* MacRunner 2026-08-13, лейн ЛЕСТНИЦА, итерация 812 — ШЁЛ ЛИ ЗАВОД ОБЪЕКТОВ В ЭТОМ ПРОЦЕССЕ.
     *
     * Итерация 811 замерила: таблица ОТОБРАЖЕНА (`shared=0x305cd0000`), а слоты стандартных
     * объектов пусты (`Type=0` у 39/45/47). Два объяснения не различаются по тем числам:
     * `gdi_init` в этом процессе не выполнялся вовсе, либо выполнился и не заполнил. Печатаем
     * вход, значение таблицы и состояние ПЕРВОГО слота ДО и ПОСЛЕ `init_stock_objects` —
     * этого достаточно, чтобы развести случаи. Печать безусловная, одна на процесс. */
    {
        unsigned int t_before = (gdi_shared && FIRST_GDI_HANDLE < GDI_MAX_HANDLE_COUNT)
                              ? (unsigned)gdi_shared->Handles[FIRST_GDI_HANDLE].Type : 0xffffffffu;
        /* Итерация 813: pid ОБЯЗАТЕЛЕН — без него писателя и читателя не сопоставить по
         * процессу, и вывод «завода не было» повисает в воздухе (замер 812). */
        fprintf( stderr, "macrunner-gdiinit: вход shared=%p слот%u_тип_до=%08x pid=%p unix=%d\n",
                 gdi_shared, (unsigned)FIRST_GDI_HANDLE, t_before,
                 NtCurrentTeb()->ClientId.UniqueProcess, (int)getpid() );
        fflush( stderr );
    }
    if (!gdi_shared)
    {
        fprintf( stderr, "macrunner-gdiinit: выход БЕЗ_ТАБЛИЦЫ — объекты не заводятся\n" );
        fflush( stderr );
        return;
    }

    dpi = font_init();
    init_stock_objects( dpi );
    gdi_shared_at_init = gdi_shared;
    gdi_init_done++;
    gdi_init_tid = 0;
    fprintf( stderr, "macrunner-gdiinit: готово dpi=%u слот%u_тип_после=%08x слот39=%08x "
             "pid=%p unix=%d shared=%p\n",
             dpi, (unsigned)FIRST_GDI_HANDLE,
             (unsigned)gdi_shared->Handles[FIRST_GDI_HANDLE].Type,
             (unsigned)gdi_shared->Handles[39].Type,
             NtCurrentTeb()->ClientId.UniqueProcess, (int)getpid(), gdi_shared );
    fflush( stderr );
}
