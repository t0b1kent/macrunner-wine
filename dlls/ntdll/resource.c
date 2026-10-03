/*
 * PE file resources
 *
 * Copyright 1995 Thomas Sandford
 * Copyright 1996 Martin von Loewis
 * Copyright 2003 Alexandre Julliard
 *
 * Based on the Win16 resource handling code in loader/resource.c
 * Copyright 1993 Robert J. Amstadt
 * Copyright 1995 Alexandre Julliard
 * Copyright 1997 Marcus Meissner
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

#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "ntdll_misc.h"
#include "wine/asm.h"
#include "wine/exception.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(resource);

#define IS_INTRESOURCE(x)       (((ULONG_PTR)(x) >> 16) == 0)

static BOOL resource_contains( const void *root, ULONG size, const void *ptr, SIZE_T len )
{
    const char *start = root, *addr = ptr, *end = start + size;

    if (end < start || addr < start || addr > end) return FALSE;
    return len <= end - addr;
}

static BOOL resource_offset_ptr( const void *root, ULONG size, ULONG offset, SIZE_T len, const void **ptr )
{
    if (offset > size || len > size - offset) return FALSE;
    *ptr = (const char *)root + offset;
    return TRUE;
}

static BOOL get_resource_entries( const IMAGE_RESOURCE_DIRECTORY *dir, const void *root, ULONG size,
                                  const IMAGE_RESOURCE_DIRECTORY_ENTRY **entry, ULONG *count )
{
    ULONG named, ids;

    if (!resource_contains( root, size, dir, sizeof(*dir) )) return FALSE;
    named = dir->NumberOfNamedEntries;
    ids = dir->NumberOfIdEntries;
    if (named > ~(ULONG)0 - ids) return FALSE;
    *count = named + ids;
    *entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
    return resource_contains( root, size, *entry, *count * sizeof(**entry) );
}

static const IMAGE_RESOURCE_DIR_STRING_U *get_resource_name_string( const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry,
                                                                    const void *root, ULONG size )
{
    const IMAGE_RESOURCE_DIR_STRING_U *str;

    if (!entry->NameIsString) return NULL;
    if (!resource_offset_ptr( root, size, entry->NameOffset,
                              FIELD_OFFSET( IMAGE_RESOURCE_DIR_STRING_U, NameString ),
                              (const void **)&str ))
        return NULL;
    if (!resource_contains( root, size, str->NameString, str->Length * sizeof(WCHAR) ))
        return NULL;
    return str;
}

static const void *get_resource_entry_data( const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry,
                                            const void *root, ULONG size, int want_dir )
{
    const void *ret;
    SIZE_T min_size = want_dir ? sizeof(IMAGE_RESOURCE_DIRECTORY) : sizeof(IMAGE_RESOURCE_DATA_ENTRY);

    if (!!entry->DataIsDirectory != !!want_dir) return NULL;
    if (!resource_offset_ptr( root, size, entry->OffsetToDirectory, min_size, &ret )) return NULL;
    return ret;
}

/**********************************************************************
 *  is_data_file_module
 *
 * Check if a module handle is for a LOAD_LIBRARY_AS_DATAFILE module.
 */
static inline BOOL is_data_file_module( HMODULE hmod )
{
    return (ULONG_PTR)hmod & 1;
}


/**********************************************************************
 *  push_language
 *
 * push a language in the list of languages to try
 */
static inline int push_language( WORD *list, int pos, WORD lang )
{
    int i;
    for (i = 0; i < pos; i++) if (list[i] == lang) return pos;
    list[pos++] = lang;
    return pos;
}


/**********************************************************************
 *  find_first_entry
 *
 * Find the first suitable entry in a resource directory
 */
static const IMAGE_RESOURCE_DIRECTORY *find_first_entry( const IMAGE_RESOURCE_DIRECTORY *dir,
                                                         const void *root, ULONG size, int want_dir )
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
    ULONG count, pos;

    if (!get_resource_entries( dir, root, size, &entry, &count )) return NULL;
    for (pos = 0; pos < count; pos++)
    {
        const void *ret = get_resource_entry_data( &entry[pos], root, size, want_dir );
        if (ret) return ret;
    }
    return NULL;
}


/**********************************************************************
 *  find_entry_by_id
 *
 * Find an entry by id in a resource directory
 */
static const IMAGE_RESOURCE_DIRECTORY *find_entry_by_id( const IMAGE_RESOURCE_DIRECTORY *dir,
                                                         WORD id, const void *root, ULONG size, int want_dir )
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
    ULONG count, min, max, pos;

    if (!get_resource_entries( dir, root, size, &entry, &count )) return NULL;
    if (!dir->NumberOfIdEntries || dir->NumberOfNamedEntries >= count) return NULL;
    min = dir->NumberOfNamedEntries;
    max = min + dir->NumberOfIdEntries;       /* граница ИСКЛЮЧИТЕЛЬНАЯ */
    if (max > count) max = count;             /* заголовок мог соврать: не выходить
                                               * за уже проверенный массив */
    while (min < max)
    {
        pos = min + (max - min) / 2;
        if (entry[pos].Id == id)
        {
            const void *ret = get_resource_entry_data( &entry[pos], root, size, want_dir );
            if (ret)
            {
                TRACE("root %p dir %p id %04x ret %p\n",
                      root, dir, id, ret);
                return ret;
            }
            break;
        }
        if (entry[pos].Id > id) max = pos;     /* без -1; подпорка `if (!pos) break;`
                                               * от 12.06 стала не нужна и снята */
        else min = pos + 1;
    }
    TRACE("root %p dir %p id %04x not found\n", root, dir, id );
    return NULL;
}


/**********************************************************************
 *  find_entry_by_name
 *
 * Find an entry by name in a resource directory
 */
static const IMAGE_RESOURCE_DIRECTORY *find_entry_by_name( const IMAGE_RESOURCE_DIRECTORY *dir,
                                                           LPCWSTR name, const void *root,
                                                           ULONG size, int want_dir )
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
    const IMAGE_RESOURCE_DIR_STRING_U *str;
    int res, namelen;
    ULONG count, min, max, pos;

    if (IS_INTRESOURCE(name)) return find_entry_by_id( dir, LOWORD(name), root, size, want_dir );
    if (!get_resource_entries( dir, root, size, &entry, &count )) return NULL;
    if (!dir->NumberOfNamedEntries || dir->NumberOfNamedEntries > count) return NULL;
    namelen = wcslen(name);
/* MacRunner 2026-08-31 — ПОЛУОТКРЫТЫЙ интервал в обоих двоичных поисках.
 *
 * КОРЕНЬ. Здесь `min/max/pos` объявлены ULONG (у upstream Wine они `int`).
 * При беззнаковом типе `max = pos - 1` на pos 0 даёт 0xFFFFFFFF, условие
 * `min <= max` остаётся истинным, следующий шаг берёт pos = 0x7FFFFFFF и читает
 * entry[pos] на 16 ГиБ дальше массива -> c0000005. Замерено: winver, отказ в
 * ntdll+0x5d8f8, `ldr w8,[x25,x8]` при x8 = 0x7FFFFFFF<<3; диалог About умирал
 * на 6-м из 8 окон, WM_INITDIALOG не выполнялся, оттого в заголовке оставалось
 * буквальное "About %s", а статики были пусты.
 *
 * ПОЧЕМУ НЕ КАК РАНЬШЕ И НЕ КАК У UPSTREAM.
 *   * Наша правка 12.06 (`if (!pos) break;`) закрывала ОДНУ функцию из двух и
 *     лечила следствие: подпорка на конкретном значении индекса.
 *   * Возврат к `int`, как у upstream, убирает переполнение вниз, но сохраняет
 *     классическое переполнение середины `(min + max) / 2` (Bloch, «Nearly All
 *     Binary Searches and Mergesorts Are Broken», 2006).
 *
 * ЧТО СДЕЛАНО. Верхняя граница ИСКЛЮЧИТЕЛЬНАЯ, `max` никогда не уменьшается на
 * единицу, а середина считается как `min + (max - min) / 2`. Тогда:
 *   * вычесть единицу из нуля НЕГДЕ — переполнения вниз нет ПО ПОСТРОЕНИЮ;
 *   * середина не переполняется даже при границах у предела типа;
 *   * особый случай `if (!pos) break;` больше не нужен и снят;
 *   * типы остаются беззнаковыми — сравнения со знаковыми не появляются.
 * Множество перебираемых индексов то же самое: [min, min+N) вместо [min, min+N-1].
 */
    min = 0;
    max = dir->NumberOfNamedEntries;          /* граница ИСКЛЮЧИТЕЛЬНАЯ */
    while (min < max)
    {
        pos = min + (max - min) / 2;
        if (!(str = get_resource_name_string( &entry[pos], root, size ))) return NULL;
        res = wcsncmp( name, str->NameString, str->Length );
        if (!res && namelen == str->Length)
        {
            const void *ret = get_resource_entry_data( &entry[pos], root, size, want_dir );
            if (ret)
            {
                TRACE("root %p dir %p name %s ret %p\n",
                      root, dir, debugstr_w(name), ret);
                return ret;
            }
            break;
        }
        if (res < 0) max = pos;               /* без -1: вниз не переполнить */
        else min = pos + 1;
    }
    TRACE("root %p dir %p name %s not found\n", root, dir, debugstr_w(name) );
    return NULL;
}


/**********************************************************************
 *  find_entry
 *
 * Find a resource entry
 */
static NTSTATUS find_entry( HMODULE hmod, const LDR_RESOURCE_INFO *info,
                            ULONG level, const void **ret, int want_dir )
{
    ULONG size;
    const void *root;
    const IMAGE_RESOURCE_DIRECTORY *resdirptr;
    WORD list[9];  /* list of languages to try */
    WORD lang;
    BOOL neutral_lang;
    int i, pos = 0;

    root = RtlImageDirectoryEntryToData( hmod, TRUE, IMAGE_DIRECTORY_ENTRY_RESOURCE, &size );
    if (!root) return STATUS_RESOURCE_DATA_NOT_FOUND;
    if (size < sizeof(*resdirptr)) return STATUS_RESOURCE_DATA_NOT_FOUND;
    resdirptr = root;

    if (!level--) goto done;
    if (!(*ret = find_entry_by_name( resdirptr, (LPCWSTR)info->Type, root, size, want_dir || level )))
        return STATUS_RESOURCE_TYPE_NOT_FOUND;
    if (!level--) return STATUS_SUCCESS;

    resdirptr = *ret;
    if (!(*ret = find_entry_by_name( resdirptr, (LPCWSTR)info->Name, root, size, want_dir || level )))
        return STATUS_RESOURCE_NAME_NOT_FOUND;
    if (!level--) return STATUS_SUCCESS;
    if (level) return STATUS_INVALID_PARAMETER;  /* level > 3 */

    lang = info->Language;
    neutral_lang = PRIMARYLANGID( lang ) == LANG_NEUTRAL;

    /* 1. specified language */
    pos = push_language( list, pos, lang );

    /* 2. specified language with neutral sublanguage */
    pos = push_language( list, pos, MAKELANGID( PRIMARYLANGID(lang), SUBLANG_NEUTRAL ) );

    /* 3. neutral language with neutral sublanguage */
    pos = push_language( list, pos, MAKELANGID( LANG_NEUTRAL, SUBLANG_NEUTRAL ) );

    /* if no explicitly specified language, try some defaults */
    if (neutral_lang)
    {
        LANGID user_lang, user_neutral_lang, system_lang;

        get_resource_lcids( &user_lang, &user_neutral_lang, &system_lang );

        /* user defaults, unless SYS_DEFAULT sublanguage specified  */
        if (SUBLANGID(lang) != SUBLANG_SYS_DEFAULT)
        {
            /* 4. current thread locale language */
            pos = push_language( list, pos, LANGIDFROMLCID(NtCurrentTeb()->CurrentLocale) );

            /* 5. user locale language */
            pos = push_language( list, pos, user_lang );

            /* 6. user locale language with neutral sublanguage  */
            pos = push_language( list, pos, user_neutral_lang );
        }

        /* 7. system locale language */
        pos = push_language( list, pos, system_lang );

        /* 8. system locale language with neutral sublanguage */
        pos = push_language( list, pos, MAKELANGID( PRIMARYLANGID( system_lang ), SUBLANG_NEUTRAL ) );

        /* 9. English */
        pos = push_language( list, pos, MAKELANGID( LANG_ENGLISH, SUBLANG_DEFAULT ) );
    }
    if (neutral_lang)
        pos = push_language( list, pos, MAKELANGID( LANG_ENGLISH, SUBLANG_DEFAULT ) );

    resdirptr = *ret;
    if (!lang)
    {
        LANGID user_lang, user_neutral_lang, system_lang;
        WORD defaults[6];

        get_resource_lcids( &user_lang, &user_neutral_lang, &system_lang );
        defaults[0] = LANGIDFROMLCID(NtCurrentTeb()->CurrentLocale);
        defaults[1] = user_lang;
        defaults[2] = user_neutral_lang;
        defaults[3] = system_lang;
        defaults[4] = MAKELANGID( PRIMARYLANGID( system_lang ), SUBLANG_NEUTRAL );
        defaults[5] = MAKELANGID( LANG_ENGLISH, SUBLANG_DEFAULT );

        for (i = 0; i < ARRAY_SIZE(defaults); i++)
            if ((*ret = find_entry_by_id( resdirptr, defaults[i], root, size, want_dir ))) return STATUS_SUCCESS;
        if ((*ret = find_first_entry( resdirptr, root, size, want_dir ))) return STATUS_SUCCESS;
    }
    for (i = 0; i < pos; i++)
        if ((*ret = find_entry_by_id( resdirptr, list[i], root, size, want_dir ))) return STATUS_SUCCESS;

    /* if no explicitly specified language, return the first entry */
    if (neutral_lang)
    {
        if ((*ret = find_first_entry( resdirptr, root, size, want_dir ))) return STATUS_SUCCESS;
    }
    return STATUS_RESOURCE_LANG_NOT_FOUND;

done:
    *ret = resdirptr;
    return STATUS_SUCCESS;
}


/**********************************************************************
 *	LdrFindResourceDirectory_U  (NTDLL.@)
 */
NTSTATUS WINAPI DECLSPEC_HOTPATCH LdrFindResourceDirectory_U( HMODULE hmod, const LDR_RESOURCE_INFO *info,
                                            ULONG level, const IMAGE_RESOURCE_DIRECTORY **dir )
{
    const void *res;
    NTSTATUS status;

    __TRY
    {
	if (info) TRACE( "module %p type %s name %s lang %04lx level %ld\n",
                     hmod, debugstr_w((LPCWSTR)info->Type),
                     level > 1 ? debugstr_w((LPCWSTR)info->Name) : "",
                     level > 2 ? info->Language : 0, level );

        status = find_entry( hmod, info, level, &res, TRUE );
        if (status == STATUS_SUCCESS) *dir = res;
    }
    __EXCEPT_PAGE_FAULT
    {
        return GetExceptionCode();
    }
    __ENDTRY;
    return status;
}


/**********************************************************************
 *	LdrFindResource_U  (NTDLL.@)
 */
NTSTATUS WINAPI DECLSPEC_HOTPATCH LdrFindResource_U( HMODULE hmod, const LDR_RESOURCE_INFO *info,
                                   ULONG level, const IMAGE_RESOURCE_DATA_ENTRY **entry )
{
    const void *res;
    NTSTATUS status;

    __TRY
    {
	if (info) TRACE( "module %p type %s name %s lang %04lx level %ld\n",
                     hmod, debugstr_w((LPCWSTR)info->Type),
                     level > 1 ? debugstr_w((LPCWSTR)info->Name) : "",
                     level > 2 ? info->Language : 0, level );

        status = find_entry( hmod, info, level, &res, FALSE );
        if (status == STATUS_SUCCESS) *entry = res;
    }
    __EXCEPT_PAGE_FAULT
    {
        return GetExceptionCode();
    }
    __ENDTRY;
    return status;
}


/* don't penalize other platforms with stuff needed on i386 for compatibility */
#ifdef __i386__
NTSTATUS WINAPI access_resource( HMODULE hmod, const IMAGE_RESOURCE_DATA_ENTRY *entry,
                                 void **ptr, ULONG *size )
#else
static inline NTSTATUS access_resource( HMODULE hmod, const IMAGE_RESOURCE_DATA_ENTRY *entry,
                                        void **ptr, ULONG *size )
#endif
{
    NTSTATUS status;

    __TRY
    {
        ULONG dirsize;
        void *root;

        if (!(root = RtlImageDirectoryEntryToData( hmod, TRUE, IMAGE_DIRECTORY_ENTRY_RESOURCE, &dirsize )))
            status = STATUS_RESOURCE_DATA_NOT_FOUND;
        else if (!resource_contains( root, dirsize, entry, sizeof(*entry) ))
            status = STATUS_RESOURCE_DATA_NOT_FOUND;
        else
        {
            BOOL is_data_file = is_data_file_module(hmod);
            hmod = (HMODULE)((ULONG_PTR)hmod & ~3);
            if (is_data_file)
            {
                void *data = RtlImageRvaToVa( RtlImageNtHeader(hmod), hmod, entry->OffsetToData, NULL );
                if (!data) return STATUS_RESOURCE_DATA_NOT_FOUND;
                if (ptr) *ptr = data;
            }
            else
            {
                const IMAGE_NT_HEADERS *nt = RtlImageNtHeader(hmod);
                if (!nt || entry->OffsetToData >= nt->OptionalHeader.SizeOfImage ||
                    entry->Size > nt->OptionalHeader.SizeOfImage - entry->OffsetToData)
                    return STATUS_RESOURCE_DATA_NOT_FOUND;
                if (ptr) *ptr = (char *)hmod + entry->OffsetToData;
            }
            if (size) *size = entry->Size;
            status = STATUS_SUCCESS;
        }
    }
    __EXCEPT_PAGE_FAULT
    {
        return GetExceptionCode();
    }
    __ENDTRY;
    return status;
}

/**********************************************************************
 *	LdrAccessResource  (NTDLL.@)
 *
 * NOTE
 * On x86, Shrinker, an executable compressor, depends on the
 * "call access_resource" instruction being there.
 */
#ifdef __i386__
__ASM_STDCALL_FUNC( LdrAccessResource, 16,
    "pushl %ebp\n\t"
    "movl %esp, %ebp\n\t"
    "subl $4,%esp\n\t"
    "pushl 24(%ebp)\n\t"
    "pushl 20(%ebp)\n\t"
    "pushl 16(%ebp)\n\t"
    "pushl 12(%ebp)\n\t"
    "pushl 8(%ebp)\n\t"
    "call " __ASM_STDCALL("access_resource",16) "\n\t"
    "leave\n\t"
    "ret $16"
)
#else
NTSTATUS WINAPI LdrAccessResource( HMODULE hmod, const IMAGE_RESOURCE_DATA_ENTRY *entry,
                                   void **ptr, ULONG *size )
{
    return access_resource( hmod, entry, ptr, size );
}
#endif

/**********************************************************************
 *	RtlFindMessage  (NTDLL.@)
 */
NTSTATUS WINAPI RtlFindMessage( HMODULE hmod, ULONG type, ULONG lang,
                                ULONG msg_id, const MESSAGE_RESOURCE_ENTRY **ret )
{
    const MESSAGE_RESOURCE_DATA *data;
    const MESSAGE_RESOURCE_BLOCK *block;
    const IMAGE_RESOURCE_DATA_ENTRY *rsrc;
    LDR_RESOURCE_INFO info;
    NTSTATUS status;
    ULONG size;
    void *ptr;
    unsigned int i;

    info.Type     = type;
    info.Name     = 1;
    info.Language = lang;

    if ((status = LdrFindResource_U( hmod, &info, 3, &rsrc )) != STATUS_SUCCESS)
        return status;
    if ((status = LdrAccessResource( hmod, rsrc, &ptr, &size )) != STATUS_SUCCESS)
        return status;

    data = ptr;
    if (size < offsetof( MESSAGE_RESOURCE_DATA, Blocks )) return STATUS_RESOURCE_DATA_NOT_FOUND;
    if (data->NumberOfBlocks > (size - offsetof( MESSAGE_RESOURCE_DATA, Blocks )) / sizeof(*block))
        return STATUS_RESOURCE_DATA_NOT_FOUND;
    block = data->Blocks;
    for (i = 0; i < data->NumberOfBlocks; i++, block++)
    {
        if (msg_id >= block->LowId && msg_id <= block->HighId)
        {
            const MESSAGE_RESOURCE_ENTRY *entry;
            ULONG entry_index;

            if (!resource_offset_ptr( data, size, block->OffsetToEntries, sizeof(*entry),
                                      (const void **)&entry ))
                return STATUS_RESOURCE_DATA_NOT_FOUND;
            for (entry_index = msg_id - block->LowId; entry_index > 0; entry_index--)
            {
                if (!resource_contains( data, size, entry, sizeof(*entry) ) ||
                    entry->Length < sizeof(*entry) ||
                    !resource_contains( data, size, entry, entry->Length ))
                    return STATUS_RESOURCE_DATA_NOT_FOUND;
                entry = (const MESSAGE_RESOURCE_ENTRY *)((const char *)entry + entry->Length);
            }
            if (!resource_contains( data, size, entry, sizeof(*entry) ) ||
                entry->Length < sizeof(*entry) ||
                !resource_contains( data, size, entry, entry->Length ))
                return STATUS_RESOURCE_DATA_NOT_FOUND;
            *ret = entry;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_MESSAGE_NOT_FOUND;
}
