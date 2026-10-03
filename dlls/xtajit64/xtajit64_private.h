#ifndef __XTAJIT64_PRIVATE_H
#define __XTAJIT64_PRIVATE_H

#include <stdint.h>
#include "windef.h"
#include "winnt.h"
#include "wine/unixlib.h"

enum xtajit64_unix_funcs
{
    unix_process_init,
    unix_thread_init,
    unix_thread_term,
    unix_process_term,
    unix_simulate,
    unix_notify_memory_alloc,
    unix_notify_memory_protect,
    unix_notify_memory_free,
    unix_notify_map_view,
    unix_notify_unmap_view,
    unix_flush_instruction_cache,
    unix_funcs_count
};

struct xtajit64_amd64_context
{
    ULONG64 rax, rbx, rcx, rdx;
    ULONG64 rsi, rdi, rsp, rbp;
    ULONG64 r8, r9, r10, r11;
    ULONG64 r12, r13, r14, r15;
    ULONG64 rip, rflags;
    ULONG64 gs_base, fs_base;
    WORD seg_cs, seg_ds, seg_es, seg_fs, seg_gs, seg_ss;
    ULONG64 xmm[16][2];
};

struct xtajit64_simulate_params
{
    struct xtajit64_amd64_context context;
    ULONG max_code_bytes;
    NTSTATUS status;
    LONG hb_result;
    ULONG faulted;
    ULONG64 steps;
    ULONG64 blocks;
};

struct xtajit64_memory_params
{
    void *addr;
    SIZE_T size;
    ULONG type;
    ULONG protect;
    BOOL is_post;
    NTSTATUS status;
};

#endif
