#ifndef MR_DIRECT_RESUME_H
#define MR_DIRECT_RESUME_H
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libkern/OSCacheControl.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>

/* Private immutable RX veneers. No Wine view locks, malloc, file I/O or RWX
 * mapping on the signal path. Two pages retain the previous continuation. */
struct mr_direct_slot { uintptr_t page, target; };
struct mr_direct_owner {
    uintptr_t owner;
    struct mr_direct_slot slots[2];
    unsigned next;
};
static struct mr_direct_owner mr_direct_owners[1024];

static struct mr_direct_owner *mr_direct_find(uintptr_t owner, int create)
{
    struct mr_direct_owner *empty = NULL;
    if (!owner) return NULL;
    for (unsigned i = 0; i < 1024; ++i) {
        uintptr_t value = __atomic_load_n(&mr_direct_owners[i].owner, __ATOMIC_ACQUIRE);
        if (value == owner) return &mr_direct_owners[i];
        if (!value && !empty) empty = &mr_direct_owners[i];
    }
    if (create && empty) {
        uintptr_t zero = 0;
        if (__atomic_compare_exchange_n(&empty->owner, &zero, owner, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return empty;
        return mr_direct_find(owner, create);
    }
    return NULL;
}

static uintptr_t mr_direct_target(uintptr_t owner, uintptr_t pc)
{
    struct mr_direct_owner *record = mr_direct_find(owner, 0);
    if (record) for (unsigned i = 0; i < 2; ++i)
        if (record->slots[i].page &&
            (pc == record->slots[i].page || pc == record->slots[i].page + 4))
            return record->slots[i].target;
    return 0;
}

static uintptr_t mr_direct_prepare(uintptr_t owner, uintptr_t target)
{
    const uintptr_t page_size = vm_page_size;
    struct mr_direct_owner *record;
    mach_vm_address_t address = 0;
    if (!target || (target & 3) || !page_size || (page_size & (page_size - 1))) return 0;
    record = mr_direct_find(owner, 1);
    if (!record) return 0;
    for (unsigned i = 0; i < 2; ++i)
        if (record->slots[i].page && record->slots[i].target == target)
            return record->slots[i].page;
    /* Fixed allocation without VM_FLAGS_OVERWRITE never replaces a mapping.
     * Leave margin for the branch instruction's own +4 PC. */
    for (uintptr_t distance = page_size; distance < 0x07000000; distance += page_size) {
        uintptr_t base = target & ~(page_size - 1);
        for (unsigned side = 0; side < 2; ++side) {
            if ((!side && base > UINTPTR_MAX - distance) || (side && base <= distance)) continue;
            address = side ? base - distance : base + distance;
            if (mach_vm_allocate(mach_task_self(), &address, page_size, VM_FLAGS_FIXED) == KERN_SUCCESS)
                goto allocated;
        }
    }
    return 0;
allocated:;
    int64_t delta = (int64_t)target - (int64_t)(address + 4);
    if ((delta & 3) || delta < -0x08000000LL || delta >= 0x08000000LL) goto failed;
    uint32_t *code = (uint32_t *)(uintptr_t)address;
    code[0] = 0x58000052; /* ldr x18, [pc, #8] */
    code[1] = 0x14000000 | ((uint32_t)(delta / 4) & 0x03ffffff);
    *(uint64_t *)(code + 2) = owner;
    sys_icache_invalidate((void *)(uintptr_t)address, 16);
    if (mach_vm_protect(mach_task_self(), address, page_size, FALSE,
                        VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS) goto failed;
    unsigned index = record->next++ & 1;
    uintptr_t old = record->slots[index].page;
    record->slots[index].target = target;
    record->slots[index].page = address;
    if (old) mach_vm_deallocate(mach_task_self(), old, page_size);
    return address;
failed:
    mach_vm_deallocate(mach_task_self(), address, page_size);
    return 0;
}

/* Wine calls this after the corresponding thread no longer executes. */
static void mr_direct_release(uintptr_t owner)
{
    struct mr_direct_owner *record = mr_direct_find(owner, 0);
    if (!record) return;
    for (unsigned i = 0; i < 2; ++i) {
        if (record->slots[i].page)
            mach_vm_deallocate(mach_task_self(), record->slots[i].page, vm_page_size);
        record->slots[i].page = record->slots[i].target = 0;
    }
    record->next = 0;
    __atomic_store_n(&record->owner, 0, __ATOMIC_RELEASE);
}
#endif
