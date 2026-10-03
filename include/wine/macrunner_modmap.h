/*
 * MacRunner: атрибуция адреса по КАРТЕ МОДУЛЕЙ, а не по совпавшему смещению.
 *
 * Дважды за проект адрес приписывался не тому модулю: смещение «находилось»
 * в игре, а лежало в нашем winemac.drv; после перебазирования ImageBase из
 * заголовка не значит ничего.  Спрашиваем загрузчик.
 *
 * Возвращает строку вида "wined3d.dll+0x28c440" в буфер вызывающего.
 * Никогда не отказывает: при неудаче пишет "?+0xАДРЕС".
 */
#ifndef __WINE_MACRUNNER_MODMAP_H
#define __WINE_MACRUNNER_MODMAP_H

#include <stdio.h>
#include <windef.h>
#include <winbase.h>

static inline const char *macrunner_addr_module( const void *addr, char *buf, unsigned len )
{
    struct macrunner_ldr_entry   /* начало LDR_DATA_TABLE_ENTRY, поля до BaseDllName */
    {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        void      *DllBase;
        void      *EntryPoint;
        ULONG      SizeOfImage;
        struct { USHORT Length, MaximumLength; WCHAR *Buffer; } FullDllName;
        struct { USHORT Length, MaximumLength; WCHAR *Buffer; } BaseDllName;
    };
    typedef LONG (WINAPI *macrunner_find_entry_t)( const void *, struct macrunner_ldr_entry ** );
    static macrunner_find_entry_t find_entry;
    struct macrunner_ldr_entry *e = NULL;
    unsigned i;

    if (!find_entry)
    {
        HMODULE ntdll = GetModuleHandleW( L"ntdll.dll" );
        if (ntdll) find_entry = (macrunner_find_entry_t)GetProcAddress( ntdll, "LdrFindEntryForAddress" );
    }
    if (find_entry && !find_entry( addr, &e ) && e && e->DllBase)
    {
        char name[64];
        unsigned n = e->BaseDllName.Length / sizeof(WCHAR);
        if (n >= sizeof(name)) n = sizeof(name) - 1;
        for (i = 0; i < n; i++) name[i] = (char)e->BaseDllName.Buffer[i];
        name[n] = 0;
        snprintf( buf, len, "%s+0x%lx [база=%p размер=0x%lx]", name,
                  (unsigned long)((const char *)addr - (const char *)e->DllBase),
                  e->DllBase, (unsigned long)e->SizeOfImage );
    }
    else snprintf( buf, len, "?+0x%p", addr );
    return buf;
}

#endif /* __WINE_MACRUNNER_MODMAP_H */
