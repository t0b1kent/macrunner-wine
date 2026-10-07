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

#ifndef __WOW64_PRIVATE_H
#define __WOW64_PRIVATE_H

#include "../ntdll/ntsyscalls.h"
#include "struct32.h"

#define SYSCALL_ENTRY(id,name,_args) extern NTSTATUS WINAPI wow64_ ## name( UINT *args );
ALL_SYSCALLS32
#undef SYSCALL_ENTRY

extern void init_image_mapping( HMODULE module );
extern void init_file_redirects(void);
extern BOOL get_file_redirect( OBJECT_ATTRIBUTES *attr );
extern NTSTATUS write_guest32_output( void *dst, const void *src, SIZE_T size );

extern USHORT native_machine;
extern USHORT current_machine;
extern ULONG_PTR args_alignment;
extern ULONG_PTR highest_user_address;
extern ULONG_PTR default_zero_bits;
extern ULONG_PTR macrunner_wow64_guest32_base;
extern SYSTEM_DLL_INIT_BLOCK *pLdrSystemDllInitBlock;

#define MACRUNNER_WOW64_TLS_GUEST32_BASE (WOW64_TLS_MAX_NUMBER - 1)

extern void     (WINAPI *pBTCpuFlushInstructionCache2)( const void *, SIZE_T );
extern void     (WINAPI *pBTCpuFlushInstructionCacheHeavy)( const void *, SIZE_T );
extern NTSTATUS (WINAPI *pBTCpuNotifyMapViewOfSection)( void *, void *, void *, SIZE_T, ULONG, ULONG );
extern void     (WINAPI *pBTCpuNotifyMemoryAlloc)( void *, SIZE_T, ULONG, ULONG, BOOL, NTSTATUS );
extern void     (WINAPI *pBTCpuNotifyProcessExecuteFlagsChange)( ULONG );
extern void     (WINAPI *pBTCpuNotifyMemoryDirty)( void *, SIZE_T );
extern void     (WINAPI *pBTCpuNotifyMemoryFree)( void *, SIZE_T, ULONG, BOOL, NTSTATUS );
extern void     (WINAPI *pBTCpuNotifyMemoryProtect)( void *, SIZE_T, ULONG, BOOL, NTSTATUS );
extern void     (WINAPI *pBTCpuNotifyReadFile)( HANDLE, void *, SIZE_T, BOOL, NTSTATUS );
extern void     (WINAPI *pBTCpuNotifyUnmapViewOfSection)( void *, BOOL, NTSTATUS );
extern void     (WINAPI *pBTCpuUpdateProcessorInformation)( SYSTEM_CPU_INFORMATION * );
extern void     (WINAPI *pBTCpuProcessTerm)( HANDLE, BOOL, NTSTATUS );
extern void     (WINAPI *pBTCpuThreadTerm)( HANDLE, LONG );
extern NTSTATUS (WINAPI *pBTCpuSuspendLocalThread)( HANDLE, ULONG * );
extern NTSTATUS WINAPI Wow64SuspendLocalThread( HANDLE, ULONG * );

struct object_attr64
{
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      str;
    SECURITY_DESCRIPTOR sd;
};

/* cf. GetSystemWow64Directory2 */
static inline const WCHAR *get_machine_wow64_dir( USHORT machine )
{
    switch (machine)
    {
    case IMAGE_FILE_MACHINE_TARGET_HOST: return L"\\??\\C:\\windows\\system32";
    case IMAGE_FILE_MACHINE_I386:        return L"\\??\\C:\\windows\\syswow64";
    case IMAGE_FILE_MACHINE_ARMNT:       return L"\\??\\C:\\windows\\sysarm32";
    default: return NULL;
    }
}

static inline TEB32 *NtCurrentTeb32(void)
{
    TEB *teb = NtCurrentTeb();

    if (native_machine == IMAGE_FILE_MACHINE_ARM64 &&
        current_machine == IMAGE_FILE_MACHINE_ARM64 &&
        ((ULONG_PTR)teb & ~(ULONG_PTR)0xffffffff))
        return (TEB32 *)teb;

    return (TEB32 *)((char *)teb + teb->WowTebOffset);
}

/***********************************************************************
 *  ★★★★ ПАКЕТ-2 08.09.2026 — ВЛАДЕЛЕЦ CPU ДЛЯ wow64.dll (договор T5)
 *
 * Кеш и разбор — в syscall.c, и они спрашивают ЕДИНСТВЕННЫЙ селектор пакета 1 через
 * экспорт ntdll. Здесь только быстрый путь: `guest32_host_ptr` зовётся на КАЖДЫЙ
 * 32-битный указатель каждого системного вызова, вызов функции там был бы заметен. */
extern int macrunner_wow64_cpu_hb;          /* -1 не спрошено, 1 hb, 0 не hb */
extern BOOL macrunner_wow64_cpu_is_hb_slow(void);
extern BOOL macrunner_wow64_paket2_mute( const char *family );

static inline BOOL macrunner_wow64_is_hb(void)
{
    if (macrunner_wow64_cpu_hb < 0) return macrunner_wow64_cpu_is_hb_slow();
    return macrunner_wow64_cpu_hb != 0;
}

static inline void *guest32_host_ptr( ULONG_PTR ptr )
{
    ULONG_PTR base;
    ULONG_PTR macrunner_base;
    TEB *teb;
    LONG wow_offset;

    if (!ptr) return NULL;
    if (ptr > 0xffffffff) return (void *)ptr;
    if (native_machine == IMAGE_FILE_MACHINE_ARM64 &&
        current_machine == IMAGE_FILE_MACHINE_I386)
    {
        /* ★★★★ ПАКЕТ-2 (договор T5) — ПРИ ВЛАДЕЛЬЦЕ FEX АДРЕС ГОСТЯ ТОЖДЕСТВЕНЕН.
         *
         * Ниже — вся адресная модель HyperBridge: гость лежит смещением в ВЫСОКОЙ
         * хозяйской арене, и каждый 32-битный указатель склеивается со старшими битами
         * частной базы. FEX-WOW64 построен на обратном тождестве «гостевой VA ==
         * хозяйский VA» (F:WOW64/Module.cpp:160-163 ходит через TEB+WowTebOffset
         * напрямую, F:Common/WinAPI/Alloc.cpp:25-44 отдаёт гостю низкие адреса), и
         * частной базы ему никто не публикует.
         *
         * ВЫХОД ЗДЕСЬ, А НЕ «БАЗА СЛУЧАЙНО ОКАЖЕТСЯ НУЛЕВОЙ». Разница не косметическая:
         * три нижних ветви выводят базу из `teb`/`teb+WowTebOffset`, то есть из
         * ХОЗЯЙСКОГО TEB. Он на 64-битном хозяине лежит высоко, и при непустом
         * `WowTebOffset` последняя ветвь вернула бы `база | ptr` — молча и мимо всякого
         * гейта. Совместимость «по случайному нулю» тут недоказуема, поэтому владение
         * объявлено явно.
         *
         * ГРАНИЦА: правка касается ТОЛЬКО пары ARM64-хозяин / I386-гость. Ветви
         * ARM64/ARM64 и все прочие разрядности не тронуты.
         *
         * ОПРОВЕРГНЕТ: прогон на руке fex, где `macrunner-paket2-pe family=T5-base`
         * печатает ненулевые старшие биты TEB32 — тогда тождество неверно и FEX
         * сломан на своём же договоре, а не нашей правкой. */
        if (!macrunner_wow64_is_hb()) return ULongToPtr( ptr );

        macrunner_base = macrunner_wow64_guest32_base;
        if (!macrunner_base)
            macrunner_base = (ULONG_PTR)NtCurrentTeb()->TlsSlots[MACRUNNER_WOW64_TLS_GUEST32_BASE];
        if (macrunner_base)
            return (void *)((macrunner_base & ~(ULONG_PTR)0xffffffff) | (ULONG)ptr);
    }

    teb = NtCurrentTeb();
    wow_offset = teb->WowTebOffset;

    if (native_machine == IMAGE_FILE_MACHINE_ARM64 &&
        current_machine == IMAGE_FILE_MACHINE_ARM64)
    {
        base = (ULONG_PTR)teb & ~(ULONG_PTR)0xffffffff;
        if (!base && wow_offset) base = ((ULONG_PTR)teb + wow_offset) & ~(ULONG_PTR)0xffffffff;
        if (base) return (void *)(base | (ULONG)ptr);
    }

    if (current_machine != IMAGE_FILE_MACHINE_I386 || !wow_offset)
        return ULongToPtr( ptr );

    base = ((ULONG_PTR)teb + wow_offset) & ~(ULONG_PTR)0xffffffff;
    if (base)
        return (void *)(base | (ULONG)ptr);

    return ULongToPtr( ptr );
}

static inline ULONG get_ulong( UINT **args )
{
    volatile UINT *ptr = *args;
    ULONG ret = ptr[0];

    *args = (UINT *)(ptr + 1);
    return ret;
}

static inline HANDLE get_handle( UINT **args ) { return LongToHandle( get_ulong( args ) ); }
static inline void *get_ptr( UINT **args ) { return guest32_host_ptr( get_ulong( args ) ); }

static inline ULONG64 get_ulong64( UINT **args )
{
    volatile UINT *ptr;
    ULONG64 ret;

    *args = (UINT *)(((ULONG_PTR)*args + args_alignment - 1) & ~(args_alignment - 1));
    ptr = *args;
    ret = ptr[0] | ((ULONG64)ptr[1] << 32);
    *args = (UINT *)(ptr + 2);
    return ret;
}

static inline ULONG_PTR get_zero_bits( ULONG_PTR zero_bits )
{
    return zero_bits ? zero_bits : default_zero_bits;
}

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

static inline void *apc_32to64( ULONG func )
{
    return func ? Wow64ApcRoutine : NULL;
}

static inline void *apc_param_32to64( ULONG func, ULONG context )
{
    if (!func) return ULongToPtr( context );
    return (void *)(ULONG_PTR)(((ULONG64)func << 32) | context);
}

static inline IO_STATUS_BLOCK *iosb_32to64( IO_STATUS_BLOCK *io, IO_STATUS_BLOCK32 *io32 )
{
    if (!io32) return NULL;
    io->Pointer = io32;
    return io;
}

static inline UNICODE_STRING *unicode_str_32to64( UNICODE_STRING *str, const UNICODE_STRING32 *str32 )
{
    if (!str32) return NULL;
    str->Length = str32->Length;
    str->MaximumLength = str32->MaximumLength;
    str->Buffer = guest32_host_ptr( str32->Buffer );
    return str;
}

static inline CLIENT_ID *client_id_32to64( CLIENT_ID *id, const CLIENT_ID32 *id32 )
{
    if (!id32) return NULL;
    id->UniqueProcess = LongToHandle( id32->UniqueProcess );
    id->UniqueThread = LongToHandle( id32->UniqueThread );
    return id;
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
        out->Owner = sd->Owner ? (PSID)((BYTE *)sd + sd->Owner) : NULL;
        out->Group = sd->Group ? (PSID)((BYTE *)sd + sd->Group) : NULL;
        out->Sacl = ((sd->Control & SE_SACL_PRESENT) && sd->Sacl) ? (PSID)((BYTE *)sd + sd->Sacl) : NULL;
        out->Dacl = ((sd->Control & SE_DACL_PRESENT) && sd->Dacl) ? (PSID)((BYTE *)sd + sd->Dacl) : NULL;
    }
    else
    {
        out->Owner = guest32_host_ptr( sd->Owner );
        out->Group = guest32_host_ptr( sd->Group );
        out->Sacl = (sd->Control & SE_SACL_PRESENT) ? guest32_host_ptr( sd->Sacl ) : NULL;
        out->Dacl = (sd->Control & SE_DACL_PRESENT) ? guest32_host_ptr( sd->Dacl ) : NULL;
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

static inline OBJECT_ATTRIBUTES *objattr_32to64_redirect( struct object_attr64 *out,
                                                          const OBJECT_ATTRIBUTES32 *in )
{
    OBJECT_ATTRIBUTES *attr = objattr_32to64( out, in );

    if (attr) get_file_redirect( attr );
    return attr;
}

static inline TOKEN_USER *token_user_32to64( TOKEN_USER *out, const TOKEN_USER32 *in )
{
    out->User.Sid = ULongToPtr( in->User.Sid );
    out->User.Attributes = in->User.Attributes;
    return out;
}

static inline TOKEN_OWNER *token_owner_32to64( TOKEN_OWNER *out, const TOKEN_OWNER32 *in )
{
    out->Owner = ULongToPtr( in->Owner );
    return out;
}

static inline TOKEN_PRIMARY_GROUP *token_primary_group_32to64( TOKEN_PRIMARY_GROUP *out, const TOKEN_PRIMARY_GROUP32 *in )
{
    out->PrimaryGroup = ULongToPtr( in->PrimaryGroup );
    return out;
}

static inline TOKEN_DEFAULT_DACL *token_default_dacl_32to64( TOKEN_DEFAULT_DACL *out, const TOKEN_DEFAULT_DACL32 *in )
{
    out->DefaultDacl = ULongToPtr( in->DefaultDacl );
    return out;
}

static inline void put_handle( ULONG *handle32, HANDLE handle )
{
    *handle32 = HandleToULong( handle );
}

/* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 318 — СТОРОЖ ОБРАТНОГО НАПРАВЛЕНИЯ.
 *
 * По образцу QEMU (`h2g`/`h2g_valid`, пункт 85 входящего): весь класс держится не на типах,
 * а на ОДНОЙ проверке. У нас обратного преобразования не было вовсе — везде голое усечение,
 * и потому шестой случай класса (хостовый указатель с базой, попавший в 32-битную цепочку SEH)
 * нашёлся только разбором адреса вручную.
 *
 * Базы у нас выровнены на 4 ГБ (`0x300000000`, `0x500000000`, `0xB00000000`, `0xC00000000`),
 * поэтому проверка сводится к сравнению старшей половины. Печатаем, а НЕ прерываем: прогон
 * должен доходить до конца, иначе прибор сам станет причиной отказа. */
/* Печать вынесена в wow64/virtual.c: в этом заголовке ни MESSAGE, ни ERR не объявлены
 * (он включается раньше wine/debug.h), а сборка на этом падает. */
extern void macrunner_h2g_report( const void *p );

static inline int macrunner_host_ptr_is_guest32( const void *p )
{
    ULONG_PTR x = (ULONG_PTR)p, base;

    if (!x) return 1;
    if (x <= 0xffffffff) return 1;        /* уже 32-битное — вопроса нет */
    base = macrunner_wow64_guest32_base;
    if (!base) base = (ULONG_PTR)NtCurrentTeb()->TlsSlots[MACRUNNER_WOW64_TLS_GUEST32_BASE];
    if (!base) return 1;                  /* базы не знаем — судить не о чем */
    return (x & ~(ULONG_PTR)0xffffffff) == (base & ~(ULONG_PTR)0xffffffff);
}

static inline void put_addr( ULONG *addr32, void *addr )
{
    if (addr32)
    {
        if (!macrunner_host_ptr_is_guest32( addr ))
        {
            macrunner_h2g_report( addr );
        }
        *addr32 = PtrToUlong( addr );
    }
}

static inline void put_size( ULONG *size32, SIZE_T size )
{
    if (size32) *size32 = min( size, MAXDWORD );
}

static inline void put_client_id( CLIENT_ID32 *id32, const CLIENT_ID *id )
{
    if (!id32) return;
    id32->UniqueProcess = HandleToLong( id->UniqueProcess );
    id32->UniqueThread = HandleToLong( id->UniqueThread );
}

static inline void put_iosb( IO_STATUS_BLOCK32 *io32, const IO_STATUS_BLOCK *io )
{
    /* sync I/O modifies the 64-bit iosb right away, so in that case we update the 32-bit one */
    /* async I/O leaves the 64-bit one untouched and updates the 32-bit one directly later on */
    if (io32 && io->Pointer != io32)
    {
        io32->Status = io->Status;
        io32->Information = io->Information;
    }
}

extern void put_section_image_info( SECTION_IMAGE_INFORMATION32 *info32,
                                    const SECTION_IMAGE_INFORMATION *info );
extern void put_vm_counters( VM_COUNTERS_EX32 *info32, const VM_COUNTERS_EX *info,
                             ULONG size );

#endif /* __WOW64_PRIVATE_H */
