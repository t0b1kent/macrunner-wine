/*
 * Ntdll Unix interface
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

#ifndef __NTDLL_UNIXLIB_H
#define __NTDLL_UNIXLIB_H

#include <stdint.h>

#include "wine/unixlib.h"

struct _DISPATCHER_CONTEXT;

struct wine_dbg_write_params
{
    const char  *str;
    unsigned int len;
};

struct wine_server_fd_to_handle_params
{
    int          fd;
    unsigned int access;
    unsigned int attributes;
    HANDLE      *handle;
};

struct wine_server_handle_to_fd_params
{
    HANDLE        handle;
    unsigned int  access;
    int          *unix_fd;
    unsigned int *options;
};

struct wine_spawnvp_params
{
    char       **argv;
    int          wait;
};

struct load_so_dll_params
{
    UNICODE_STRING              nt_name;
    void                      **module;
};

struct unwind_builtin_dll_params
{
    ULONG                       type;
    struct _DISPATCHER_CONTEXT *dispatch;
    CONTEXT                    *context;
};

struct pe_module_loaded_params
{
    void *start;
    void *end;
};

struct macrunner_hb_x64_dll_entry_params
{
    void   *entry;
    void   *module;
    void   *arg0;
    ULONG   reason;
    void   *reserved;
    ULONG   ret;
    ULONG64 blocks;
    ULONG64 steps;
};

struct macrunner_hb_x64_thread_entry_params
{
    void   *entry;
    void   *arg;
    ULONG64 rdx;
    ULONG64 r8;
    ULONG64 r9;
    ULONG64 ret;
    ULONG64 blocks;
    ULONG64 steps;
};

struct macrunner_hb_x64_import_context_params
{
    ULONG64 rax, rbx, rcx, rdx;
    ULONG64 rsi, rdi, rsp, rbp;
    ULONG64 r8, r9, r10, r11;
    ULONG64 r12, r13, r14, r15;
    ULONG64 rip, rflags;
    ULONG64 gs_base, fs_base;
    WORD seg_cs, seg_ds, seg_es, seg_fs, seg_gs, seg_ss;
    ULONG64 xmm[16][2];
    ULONG handled;
    NTSTATUS status;
};

struct macrunner_hb_register_import_thunk_params
{
    void    *target;
    void    *pe_call12;
    void    *pe_callback12;
    ULONG64  module_id;
    ULONG64  target_module_id;
    ULONG64  guest_target;
    USHORT   target_machine;
    USHORT   target_module_machine;
    char     dll_name[96];
    char     import_name[96];
};

#define MACRUNNER_GUEST_PEB_OBSERVER_ABI_VERSION 1
#define MACRUNNER_GUEST_PEB_OBSERVER_MAX_BYTES (1024u * 1024u)
#define MACRUNNER_GUEST_PEB_OBSERVER_MAX_RECORDS 8192u
#define MACRUNNER_GUEST_PEB_OBSERVER_FLAG_PROBE 0x00000001u
#define MACRUNNER_GUEST_PEB_OBSERVER_FLAG_ACTIVE 0x00000002u
#define MACRUNNER_GUEST_PEB_OBSERVER_FLAG_COMPLETE 0x00000004u

enum macrunner_guest_peb_view
{
    MACRUNNER_GUEST_PEB_VIEW_NATIVE = 1,
    MACRUNNER_GUEST_PEB_VIEW_WOW64 = 2,
};

/* Fixed-width PE/Unix boundary.  No raw environment bytes cross it. */
struct macrunner_guest_peb_record
{
    uint32_t ordinal;
    uint32_t utf16_code_units;
    uint8_t sha256[32];
};

struct macrunner_guest_peb_observer_params
{
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t view;
    uint32_t pointer_bits;
    uint64_t process_id;
    uint64_t environment_size;
    uint32_t record_count;
    uint32_t flags;
    uint8_t environment_sha256[32];
    uint8_t image_path_sha256[32];
    uint8_t ntdll_identity_sha256[32];
    uint64_t records;
};

enum ntdll_unix_funcs
{
    unix_load_so_dll,
    unix_unwind_builtin_dll,
    unix_wine_dbg_write,
    unix_wine_server_call,
    unix_wine_server_fd_to_handle,
    unix_wine_server_handle_to_fd,
    unix_wine_spawnvp,
    unix_system_time_precise,
    unix_macrunner_hb_register_import_thunk,
    unix_macrunner_hb_x64_dll_entry,
    unix_macrunner_hb_x64_thread_entry,
    unix_macrunner_hb_x64_import_context,
    /* Unconditional: arm64ec-clang defines __x86_64__, plain aarch64 does not.
     * A conditional entry desyncs the PE enum from the unix funcs table and
     * sends EC callers past the end of unix_call_funcs (blr to garbage). */
    unix_pe_module_loaded,
    unix_macrunner_guest_peb_observe,
    unix_macrunner_cpu_backend_query,
};

extern unixlib_handle_t __wine_unixlib_handle;

#endif /* __NTDLL_UNIXLIB_H */
