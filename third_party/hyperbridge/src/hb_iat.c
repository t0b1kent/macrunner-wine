#include "hb_iat.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#if defined(__APPLE__) && defined(__MACH__)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif

static uint64_t bridge_calls;

static bool host_addr_has_prot(uintptr_t p, int required) {
    if (!p) return false;
#if defined(__APPLE__) && defined(__MACH__)
    mach_vm_address_t addr = (mach_vm_address_t)p;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &addr, &size,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info,
                                      &count, &object_name);
    if (object_name != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), object_name);
    }
    if (kr != KERN_SUCCESS) return false;
    if (p < (uintptr_t)addr || p >= (uintptr_t)(addr + size)) return false;
    return (info.protection & required) == required;
#else
    FILE* fp = fopen("/proc/self/maps", "r");
    char line[512];
    bool allowed = false;

    if (!fp) return false;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start = 0, end = 0;
        char perms[5] = {0};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        if (p >= (uintptr_t)start && p < (uintptr_t)end) {
            allowed = true;
            if ((required & 1) && perms[0] != 'r') allowed = false;
            if ((required & 2) && perms[1] != 'w') allowed = false;
            if ((required & 4) && perms[2] != 'x') allowed = false;
            break;
        }
    }
    fclose(fp);
    return allowed;
#endif
}

static bool host_range_has_prot(const void* ptr, size_t size, int required) {
    uintptr_t start = (uintptr_t)ptr;
    if (!start || size == 0) return false;
    uintptr_t end = start + size - 1;
    if (end < start) return false;
    return host_addr_has_prot(start, required) && host_addr_has_prot(end, required);
}

static bool iat_slot_readable(const void* slot) {
#if defined(__APPLE__) && defined(__MACH__)
    return host_range_has_prot(slot, sizeof(void*), VM_PROT_READ);
#else
    return host_range_has_prot(slot, sizeof(void*), 1);
#endif
}

static bool iat_slot_writable(const void* slot) {
#if defined(__APPLE__) && defined(__MACH__)
    return host_range_has_prot(slot, sizeof(void*), VM_PROT_WRITE);
#else
    return host_range_has_prot(slot, sizeof(void*), 2);
#endif
}

hb_result_t hb_iat_plan_init(hb_iat_rewrite_plan_t* plan, size_t capacity) {
    if (!plan || capacity == 0) return HB_ERR_INVALID_ARG;
    memset(plan, 0, sizeof(*plan));
    plan->entries = calloc(capacity, sizeof(hb_iat_rewrite_entry_t));
    if (!plan->entries) return HB_ERR_OUT_OF_MEMORY;
    plan->capacity = capacity;
    return HB_OK;
}

void hb_iat_plan_destroy(hb_iat_rewrite_plan_t* plan) {
    if (!plan) return;
    free(plan->entries);
    memset(plan, 0, sizeof(*plan));
}

hb_result_t hb_iat_plan_add(hb_iat_rewrite_plan_t* plan, const hb_iat_rewrite_entry_t* entry) {
    if (!plan || !entry || !entry->slot) return HB_ERR_INVALID_ARG;
    if (plan->count >= plan->capacity) return HB_ERR_OUT_OF_MEMORY;
    plan->entries[plan->count++] = *entry;
    return HB_OK;
}

hb_result_t hb_iat_plan_trace_jsonl(const hb_iat_rewrite_plan_t* plan, const char* path) {
    if (!plan || !path) return HB_ERR_INVALID_ARG;
    FILE* fp = fopen(path, "a");
    if (!fp) return HB_ERR_NOT_FOUND;
    for (size_t i = 0; i < plan->count; i++) {
        const hb_iat_rewrite_entry_t* e = &plan->entries[i];
        fprintf(fp, "{\"event\":\"plan\",\"module_id\":%llu,\"iat_rva\":%llu,\"dll\":\"%s\",\"import\":\"%s\",\"flags\":%u}\n",
                (unsigned long long)e->module_id, (unsigned long long)e->iat_rva, e->dll_name, e->import_name, e->flags);
    }
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    return HB_OK;
}

hb_result_t hb_iat_plan_apply(hb_iat_rewrite_plan_t* plan, bool dry_run, hb_iat_stats_t* stats) {
    if (!plan) return HB_ERR_INVALID_ARG;
    for (size_t i = 0; i < plan->count; i++) {
        hb_iat_rewrite_entry_t* e = &plan->entries[i];
        if ((e->flags & HB_IAT_FLAG_ALLOWLISTED) == 0 || !e->bridge_target) {
            if (stats) stats->denied_count++;
            continue;
        }
        if (!iat_slot_readable(e->slot)) {
            return HB_ERR_MEMORY_FAULT;
        }
        e->original_target = *e->slot;
        if (!dry_run) {
            if (!iat_slot_writable(e->slot)) {
                return HB_ERR_MEMORY_FAULT;
            }
            *e->slot = e->bridge_target;
            __builtin___clear_cache((char*)e->slot, (char*)e->slot + sizeof(void*));
            e->flags |= HB_IAT_FLAG_APPLIED;
        }
        if (stats) stats->rewritten_count++;
    }
    plan->applied = !dry_run;
    return HB_OK;
}

hb_result_t hb_iat_plan_rollback(hb_iat_rewrite_plan_t* plan, hb_iat_stats_t* stats) {
    if (!plan) return HB_ERR_INVALID_ARG;
    for (size_t i = 0; i < plan->count; i++) {
        hb_iat_rewrite_entry_t* e = &plan->entries[i];
        if ((e->flags & HB_IAT_FLAG_APPLIED) != 0) {
            if (!iat_slot_writable(e->slot)) {
                return HB_ERR_MEMORY_FAULT;
            }
            *e->slot = e->original_target;
            __builtin___clear_cache((char*)e->slot, (char*)e->slot + sizeof(void*));
            e->flags &= ~HB_IAT_FLAG_APPLIED;
            if (stats) stats->rollback_count++;
        }
    }
    plan->applied = false;
    return HB_OK;
}

uint64_t hb_call_import(uint64_t module_id, uint64_t import_id, void* guest_context) {
    (void)module_id;
    (void)import_id;
    (void)guest_context;
    bridge_calls++;
    return bridge_calls;
}
