/*
 * WoW64 private definitions
 *
 * Copyright 2021 Alexandre Julliard
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

#ifndef __WOW64WIN_PRIVATE_H
#define __WOW64WIN_PRIVATE_H

#include "../win32u/win32syscalls.h"
#include "ntuser.h"

#define SYSCALL_ENTRY(id,name,_args) extern NTSTATUS WINAPI wow64_ ## name( UINT *args );
ALL_SYSCALLS32
#undef SYSCALL_ENTRY

extern ntuser_callback user_callbacks[];

#define MACRUNNER_WOW64_TLS_GUEST32_BASE (WOW64_TLS_MAX_NUMBER - 1)

/* Set once at process attach by ntdll's existing CPU-owner export. FEX
 * owns guest VA directly; the legacy HyperBridge alias TLS is not its data. */
extern BOOL macrunner_wow64win_cpu_hb;

struct object_attr64
{
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      str;
    SECURITY_DESCRIPTOR sd;
};

typedef struct
{
    ULONG Length;
    ULONG RootDirectory;
    ULONG ObjectName;
    ULONG Attributes;
    ULONG SecurityDescriptor;
    ULONG SecurityQualityOfService;
} OBJECT_ATTRIBUTES32;

static inline void *guest32_host_ptr( ULONG_PTR ptr )
{
    ULONG_PTR base;

    if (!ptr) return NULL;
    if (ptr > 0xffffffff) return (void *)ptr;

    /* ★ 2026-08-30, лейн МЕЛКИЕ — АТОМ НЕ АДРЕС.
     *
     * У Wine `get_ptr` в переходниках wow64win это `ULongToPtr`, поэтому маленькое целое
     * переживает переход и `IS_INTRESOURCE` у получателя срабатывает. Наш безусловный
     * перевод превращал атом в `база|атом` — ненулевой указатель, для которого
     * `IS_INTRESOURCE` уже ЛОЖЬ. Дальше `win32u/window.c NtUserGetProp` идёт в ветвь
     * строки и зовёт `lstrlenW(str)` по этому адресу.
     *
     * Замер (i386 winver, comctl32 версии 6): `GetWindowTheme` возвращал гостю
     * `0xc0000005` — код отказа системного вызова вместо дескриптора темы, и он доезжал
     * до `uxtheme MSSTYLES_FindProperty+0x8a`, где `movl 0x104(%edx),%eax` падал.
     *
     * Нижние 64 КБ гостевого пространства не отображаются никогда (сторожевая область
     * NULL), поэтому значение `< 0x10000` адресом быть не может — переводить его нечего. */
    if (ptr < 0x10000) return ULongToPtr( ptr );

    if (!macrunner_wow64win_cpu_hb) return ULongToPtr( ptr );

    base = (ULONG_PTR)NtCurrentTeb()->TlsSlots[MACRUNNER_WOW64_TLS_GUEST32_BASE];
    if (base) return (void *)((base & ~(ULONG_PTR)0xffffffff) | (ULONG)ptr);

    return ULongToPtr( ptr );
}

/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ЗНАЧЕНИЕ, КОТОРОЕ ХОСТ НЕ РАЗЫМЕНОВЫВАЕТ.
 *
 * Три вида значений в этих переходниках выглядят как указатели, но указателями хоста не
 * являются и склеивать их с базой гостя НЕЛЬЗЯ: описатели (HIMC, HWND) и адреса
 * гостевого КОДА (оконная процедура, обратные вызовы). Они проходят насквозь и парно
 * возвращаются гостю через `PtrToUlong`; перевод изменил бы значение, которое видит гость.
 *
 * Проверено поимённо 10.08: `lpfnWndProc` — ровно две точки (вход 3109, выход 2402),
 * `hwndTarget` — пара (вход 4090, выход 3173), `himc` — одна точка без обратной.
 * Замкнутые пары, третьего пути нет, поэтому непереведённое состояние согласовано.
 *
 * Отдельное имя нужно, чтобы отличать «сознательно не переводим» от «забыли перевести»:
 * ниже `UlongToPtr` в этом модуле отравлен и даёт ошибку сборки. */
static inline void *guest32_opaque_value( ULONG value ) { return ULongToPtr( value ); }

static inline ULONG get_ulong( UINT **args ) { return *(*args)++; }
static inline HANDLE get_handle( UINT **args ) { return LongToHandle( *(*args)++ ); }
static inline void *get_ptr( UINT **args ) { return guest32_host_ptr( *(*args)++ ); }

static inline void **addr_32to64( void **addr, ULONG *addr32 )
{
    if (!addr32) return NULL;
    *addr = guest32_host_ptr( *addr32 );
    return addr;
}

static inline SIZE_T *size_32to64( SIZE_T *size, ULONG *size32 )
{
    if (!size32) return NULL;
    *size = *size32;
    return size;
}

static inline void put_addr( ULONG *addr32, void *addr )
{
    if (addr32) *addr32 = PtrToUlong( addr );
}

static inline void put_size( ULONG *size32, SIZE_T size )
{
    if (size32) *size32 = min( size, MAXDWORD );
}

static inline UNICODE_STRING *unicode_str_32to64( UNICODE_STRING *str, const UNICODE_STRING32 *str32 )
{
    if (!str32) return NULL;
    str->Length = str32->Length;
    str->MaximumLength = str32->MaximumLength;
    str->Buffer = guest32_host_ptr( str32->Buffer );
    return str;
}

static inline SECURITY_DESCRIPTOR *secdesc_32to64( SECURITY_DESCRIPTOR *out, const SECURITY_DESCRIPTOR *in )
{
    /* relative descr has the same layout for 32 and 64 */
    const SECURITY_DESCRIPTOR_RELATIVE *sd = (const SECURITY_DESCRIPTOR_RELATIVE *)in;

    if (!in) return NULL;
    out->Revision = sd->Revision;
    out->Sbz1     = sd->Sbz1;
    out->Control  = sd->Control & ~SE_SELF_RELATIVE;
    if (sd->Control & SE_SELF_RELATIVE)
    {
        if (sd->Owner) out->Owner = (PSID)((BYTE *)sd + sd->Owner);
        if (sd->Group) out->Group = (PSID)((BYTE *)sd + sd->Group);
        if ((sd->Control & SE_SACL_PRESENT) && sd->Sacl) out->Sacl = (PSID)((BYTE *)sd + sd->Sacl);
        if ((sd->Control & SE_DACL_PRESENT) && sd->Dacl) out->Dacl = (PSID)((BYTE *)sd + sd->Dacl);
    }
    else
    {
        out->Owner = guest32_host_ptr( sd->Owner );
        out->Group = guest32_host_ptr( sd->Group );
        if (sd->Control & SE_SACL_PRESENT) out->Sacl = guest32_host_ptr( sd->Sacl );
        if (sd->Control & SE_DACL_PRESENT) out->Dacl = guest32_host_ptr( sd->Dacl );
    }
    return out;
}

static inline OBJECT_ATTRIBUTES *objattr_32to64( struct object_attr64 *out, const OBJECT_ATTRIBUTES32 *in )
{
    memset( out, 0, sizeof(*out) );
    if (!in) return NULL;
    if (in->Length != sizeof(*in)) return &out->attr;

    out->attr.Length = sizeof(out->attr);
    out->attr.RootDirectory = LongToHandle( in->RootDirectory );
    out->attr.Attributes = in->Attributes;
    out->attr.ObjectName = unicode_str_32to64( &out->str, guest32_host_ptr( in->ObjectName ));
    out->attr.SecurityQualityOfService = guest32_host_ptr( in->SecurityQualityOfService );
    out->attr.SecurityDescriptor = secdesc_32to64( &out->sd, guest32_host_ptr( in->SecurityDescriptor ));
    return &out->attr;
}

static inline void set_last_error32( DWORD err )
{
    TEB *teb = NtCurrentTeb();
    TEB32 *teb32 = (TEB32 *)((char *)teb + teb->WowTebOffset);
    teb32->LastErrorValue = err;
}


/* MacRunner 2026-08-10, лейн ЛЕСТНИЦА: ОТРАВЛЕНИЕ. Прямой `UlongToPtr` в этом модуле
 * означает пропущенный перевод гостевого указателя — самый дорогой класс дефектов
 * этого дерева (ошибка 1411 на классе окна стоила дня). Пусть он будет ошибкой
 * СБОРКИ, а не находкой через месяц. Разыменовываемое -> guest32_host_ptr(),
 * описатели и адреса гостевого кода -> guest32_opaque_value(). */
#undef UlongToPtr
#define UlongToPtr(x) MACRUNNER_ZAPRESHCHENO_ispolzuy_guest32_host_ptr_ili_guest32_opaque_value(x)

#endif /* __WOW64WIN_PRIVATE_H */
