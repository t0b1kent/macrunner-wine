/* MacRunner Wine VM arena. LGPL-2.1-or-later. Default off until acceptance. */
#ifndef MACRUNNER_VM_ARENA_H
#define MACRUNNER_VM_ARENA_H

enum mr_vm_context_id { MR_VM_OTHER, MR_VM_INIT, MR_VM_NOADDR, MR_VM_FIXED,
                        MR_VM_METADATA, MR_VM_RELEASE, MR_VM_ARENA, MR_VM_JIT,
                        MR_VM_CONTEXT_COUNT };
static __thread unsigned int mr_vm_context;
struct mr_vm_kernel_counts
{
    ULONG64 mmap_calls, mach_map_calls, munmap_calls, mprotect_calls, mach_deallocate_calls;
    ULONG64 eexist, enomem, einval, other_errno;
    ULONG64 mach_no_space, mach_invalid_address, mach_protection, mach_resource, mach_other;
};
static struct mr_vm_kernel_counts mr_vm_kernel[MR_VM_CONTEXT_COUNT];
#define MR_VM_FIELDS(X) \
    X(view_noaddr) X(view_fixed) X(noaddr_none) X(fixed_none) \
    X(view_image) X(view_file) X(view_topdown) X(view_limited) \
    X(arena_maps) X(arena_none) X(arena_none_noaddr) X(arena_none_fixed) X(arena_exhausted) \
    X(arena_mapping_failed) X(outside_limits) X(gate_off) X(reservation_failed) \
    X(reservation_bookkeeping_failed) X(legacy_reserved) X(legacy_scan) X(legacy_anon) \
    X(guest32) X(jit) X(map_free) X(try_map_free) X(gap_steps) X(free_ranges_high) \
    X(free_ranges_grow) X(free_ranges_grow_failed) X(release_failed) \
    X(metadata_ready) X(metadata_init_failed) X(metadata_bytes) X(metadata_view_slots) \
    X(metadata_range_slots) X(metadata_view_exhausted)
struct mr_vm_path_counts
{
#define MR_VM_DECLARE(n) ULONG64 n;
    MR_VM_FIELDS(MR_VM_DECLARE)
#undef MR_VM_DECLARE
};
static struct mr_vm_path_counts mr_vm_paths;
static int mr_vm_gate, mr_vm_owned, mr_vm_dirty, mr_vm_summary_done;
static pid_t mr_vm_init_pid;
static void *mr_vm_base, *mr_vm_end;
static kern_return_t mr_vm_reserve_kr;
static void mmap_add_reserved_area( void *addr, SIZE_T size );
static int mmap_is_in_reserved_area( void *addr, SIZE_T size );
static BOOL mmap_remove_reserved_area( void *addr, SIZE_T size );
void virtual_vm_arena_summary(void);
static ULONG64 mr_vm_get( const ULONG64 *ptr ) { return __atomic_load_n( ptr, __ATOMIC_RELAXED ); }
#define MR_VM_INC(n) __atomic_add_fetch( &mr_vm_paths.n, 1, __ATOMIC_RELAXED )
#define MR_VM_KINC(n) __atomic_add_fetch( &mr_vm_kernel[mr_vm_context].n, 1, __ATOMIC_RELAXED )
#define MR_VM_CALL(context,expression) \
    ({ unsigned int mr_old_context = mr_vm_context; __typeof__(expression) mr_result; \
       mr_vm_context = (context); mr_result = (expression); \
       mr_vm_context = mr_old_context; mr_result; })

static void mr_vm_errno( int error )
{
    if (error == EEXIST) MR_VM_KINC(eexist);
    else if (error == ENOMEM) MR_VM_KINC(enomem);
    else if (error == EINVAL) MR_VM_KINC(einval);
    else MR_VM_KINC(other_errno);
}

static void *mr_vm_mmap( void *addr, size_t size, int prot, int flags, int fd, off_t offset )
{
    void *ret = mmap( addr, size, prot, flags, fd, offset );
    int error = errno;
    MR_VM_KINC(mmap_calls);
    if (ret == MAP_FAILED) mr_vm_errno( error );
    errno = error;
    return ret;
}

static int mr_vm_munmap( void *addr, size_t size )
{
    int ret = munmap( addr, size ), error = errno;
    MR_VM_KINC(munmap_calls);
    if (ret) mr_vm_errno( error );
    errno = error;
    return ret;
}

static int mr_vm_mprotect( void *addr, size_t size, int prot )
{
    int ret = mprotect( addr, size, prot ), error = errno;
    MR_VM_KINC(mprotect_calls);
    if (ret) mr_vm_errno( error );
    errno = error;
    return ret;
}

static kern_return_t mr_vm_mach_map( vm_map_t task, mach_vm_address_t *addr,
                                    mach_vm_size_t size, mach_vm_offset_t mask, int flags,
                                    mem_entry_name_port_t object, memory_object_offset_t offset,
                                    boolean_t copy, vm_prot_t prot, vm_prot_t max_prot,
                                    vm_inherit_t inherit )
{
    kern_return_t ret = mach_vm_map( task, addr, size, mask, flags, object, offset, copy,
                                     prot, max_prot, inherit );
    MR_VM_KINC(mach_map_calls);
    if (ret == KERN_NO_SPACE) MR_VM_KINC(mach_no_space);
    else if (ret == KERN_INVALID_ADDRESS) MR_VM_KINC(mach_invalid_address);
    else if (ret == KERN_PROTECTION_FAILURE) MR_VM_KINC(mach_protection);
    else if (ret == KERN_RESOURCE_SHORTAGE) MR_VM_KINC(mach_resource);
    else if (ret != KERN_SUCCESS) MR_VM_KINC(mach_other);
    return ret;
}

static kern_return_t mr_vm_mach_deallocate( vm_map_t task, mach_vm_address_t addr, mach_vm_size_t size )
{
    kern_return_t ret = mach_vm_deallocate( task, addr, size );
    MR_VM_KINC(mach_deallocate_calls);
    if (ret == KERN_INVALID_ADDRESS) MR_VM_KINC(mach_invalid_address);
    else if (ret != KERN_SUCCESS) MR_VM_KINC(mach_other);
    return ret;
}

/* Intercept only this Wine translation unit, including file mappings and init probes. */
#define mmap mr_vm_mmap
#define munmap mr_vm_munmap
#define mprotect mr_vm_mprotect
#define mach_vm_map mr_vm_mach_map
#define mach_vm_deallocate mr_vm_mach_deallocate

static BOOL mr_vm_contains( const void *addr, SIZE_T size )
{
    return mr_vm_owned && (UINT_PTR)addr >= (UINT_PTR)mr_vm_base &&
           (UINT_PTR)addr < (UINT_PTR)mr_vm_end && size <= (UINT_PTR)mr_vm_end - (UINT_PTR)addr;
}

static void mr_vm_restore_none( void *addr, SIZE_T size )
{
    if (MR_VM_CALL( MR_VM_RELEASE, anon_mmap_fixed( addr, size, PROT_NONE, MAP_NORESERVE ) ) == MAP_FAILED &&
        mr_vm_contains( addr, size ))
    {
        MR_VM_INC(release_failed);
        /* A failed reset must never be treated as clean zero reserve by the fast path. */
        if (!__atomic_exchange_n( &mr_vm_dirty, 1, __ATOMIC_RELAXED ))
            fprintf( stderr, "macrunner-vm-arena: RELEASE_FAILED errno=%d clean-reserve-skip-disabled\n", errno );
    }
}

static BOOL mr_vm_ranges_dynamic;
static BOOL mr_vm_metadata_ready;
static void mr_vm_ensure_free_range_slot(void)
{
    SIZE_T used = (char *)free_ranges_end - (char *)free_ranges;
    struct range_entry *old = free_ranges, *replacement;
    SIZE_T old_capacity = free_ranges_capacity, capacity;
    if (!mr_vm_gate || used + sizeof(*free_ranges) <= free_ranges_capacity) return;
    if (mr_vm_metadata_ready || free_ranges_capacity > ~(SIZE_T)0 / 2) goto failed;
    capacity = free_ranges_capacity * 2;
    replacement = MR_VM_CALL( MR_VM_METADATA, anon_mmap_alloc( capacity, PROT_READ | PROT_WRITE ) );
    if (replacement == MAP_FAILED) goto failed;
    memcpy( replacement, free_ranges, used );
    free_ranges = replacement;
    free_ranges_end = (void *)((char *)replacement + used);
    free_ranges_capacity = capacity;
    if (mr_vm_ranges_dynamic) MR_VM_CALL( MR_VM_METADATA, munmap( old, old_capacity ) );
    mr_vm_ranges_dynamic = TRUE;
    MR_VM_INC(free_ranges_grow);
    return;
failed:
    MR_VM_INC(free_ranges_grow_failed);
    fprintf( stderr, "macrunner-vm-arena: FREE_RANGES_GROW_FAILED used=%zu capacity=%zu errno=%d\n",
             used, free_ranges_capacity, errno );
    virtual_vm_arena_summary();
    abort(); /* Preserve old bytes; never memmove beyond capacity. */
}

static void mr_vm_ranges_high(void)
{
    ULONG64 count = free_ranges_end - free_ranges;
    /* These mutations are serialized by Wine's virtual_mutex. */
    if (count > mr_vm_get( &mr_vm_paths.free_ranges_high ))
        __atomic_store_n( &mr_vm_paths.free_ranges_high, count, __ATOMIC_RELAXED );
}

/* Nonempty Wine views occupy at least one Windows page and do not overlap.
 * Bound both arrays by the entire host address space, not by an expected
 * workload. Demand-zero backing leaves unused metadata physically untouched.
 * One init mapping replaces part of our owned arena; keep its builtin-DLL end
 * available. No ordinary request needs a metadata mmap or a capacity guess. */
static BOOL mr_vm_metadata_init(void)
{
    SIZE_T slots, view_bytes, range_bytes, table_bytes, prot_bytes, total, i;
    BYTE *pool;
    if (!mr_vm_owned) return FALSE;
    slots = ((SIZE_T)host_addr_space_limit >> page_shift) + 1;
    if (slots > ~(SIZE_T)0 / sizeof(*view_block_start) ||
        slots + 1 > ~(SIZE_T)0 / sizeof(*free_ranges)) goto failed;
    if (!round_size_checked( 0, slots * sizeof(*view_block_start), host_page_mask, &view_bytes ) ||
        !round_size_checked( 0, (slots + 1) * sizeof(*free_ranges), host_page_mask, &range_bytes ) ||
        !round_size_checked( 0, pages_vprot_size * sizeof(*pages_vprot), host_page_mask, &table_bytes ) ||
        pages_vprot_size > ~(SIZE_T)0 / (pages_vprot_mask + 1)) goto failed;
    prot_bytes = pages_vprot_size * (pages_vprot_mask + 1);
    if (view_bytes > ~(SIZE_T)0 - range_bytes ||
        view_bytes + range_bytes > ~(SIZE_T)0 - table_bytes ||
        view_bytes + range_bytes + table_bytes > ~(SIZE_T)0 - prot_bytes) goto failed;
    total = view_bytes + range_bytes + table_bytes + prot_bytes;
    if (!mr_vm_contains( mr_vm_base, total )) goto failed;
    pool = MR_VM_CALL( MR_VM_INIT,
           anon_mmap_fixed( mr_vm_base, total, PROT_READ | PROT_WRITE, MAP_NORESERVE ) );
    if (pool == MAP_FAILED) goto failed;
    if (!mmap_remove_reserved_area( pool, total ))
    {
        mr_vm_restore_none( pool, total );
        goto failed;
    }
    view_block_start = (void *)pool;
    view_block_end = view_block_start + slots;
    free_ranges = (void *)(pool + view_bytes);
    free_ranges_capacity = range_bytes;
    pages_vprot = (void *)(pool + view_bytes + range_bytes);
    pool += view_bytes + range_bytes + table_bytes;
    for (i = 0; i < pages_vprot_size; ++i) pages_vprot[i] = pool + i * (pages_vprot_mask + 1);
    mr_vm_metadata_ready = TRUE;
    __atomic_store_n( &mr_vm_paths.metadata_ready, 1, __ATOMIC_RELAXED );
    __atomic_store_n( &mr_vm_paths.metadata_bytes, total, __ATOMIC_RELAXED );
    __atomic_store_n( &mr_vm_paths.metadata_view_slots, slots, __ATOMIC_RELAXED );
    __atomic_store_n( &mr_vm_paths.metadata_range_slots, range_bytes / sizeof(*free_ranges), __ATOMIC_RELAXED );
    return TRUE;
failed:
    MR_VM_INC(metadata_init_failed);
    fprintf( stderr, "macrunner-vm-arena: METADATA_INIT_FAILED errno=%d legacy-metadata\n", errno );
    return FALSE;
}

/* No libc formatting/initialization on the terminating path. */
static char *mr_vm_text( char *ptr, const char *value )
{
    while (*value) *ptr++ = *value++;
    return ptr;
}
static char *mr_vm_decimal( char *ptr, ULONG64 value )
{
    char digits[24]; unsigned int count = 0;
    do { digits[count++] = '0' + value % 10; value /= 10; } while (value);
    while (count) *ptr++ = digits[--count];
    return ptr;
}
static char *mr_vm_field( char *ptr, const char *name, ULONG64 value )
{
    *ptr++ = ' '; ptr = mr_vm_text( ptr, name ); *ptr++ = '=';
    return mr_vm_decimal( ptr, value );
}

void virtual_vm_arena_summary(void)
{
    static const char *const names[] = { "other", "init", "noaddr", "fixed", "metadata", "release", "arena", "jit" };
    char buf[8192], *ptr = buf;
    ULONG64 failures = 0;
    unsigned int i;
    if (__atomic_exchange_n( &mr_vm_summary_done, 1, __ATOMIC_RELAXED )) return;
    ptr = mr_vm_text( ptr, "macrunner-vm-arena-summary:" );
    ptr = mr_vm_field( ptr, "pid", getpid() );
    ptr = mr_vm_field( ptr, "init_pid", mr_vm_init_pid );
    ptr = mr_vm_field( ptr, "gate", mr_vm_gate );
    ptr = mr_vm_field( ptr, "owned", mr_vm_owned );
    ptr = mr_vm_field( ptr, "dirty", mr_vm_dirty );
#define MR_VM_PRINT(n) ptr = mr_vm_field( ptr, #n, mr_vm_get( &mr_vm_paths.n ) );
    MR_VM_FIELDS(MR_VM_PRINT)
#undef MR_VM_PRINT
    for (i = 0; i < MR_VM_CONTEXT_COUNT; ++i)
    {
        struct mr_vm_kernel_counts *c = &mr_vm_kernel[i];
#define MR_VM_KPRINT(n) *ptr++ = ' '; ptr = mr_vm_text( ptr, names[i] ); *ptr++ = '_'; \
                        ptr = mr_vm_text( ptr, #n ); *ptr++ = '='; \
                        ptr = mr_vm_decimal( ptr, mr_vm_get( &c->n ) );
        MR_VM_KPRINT(mmap_calls) MR_VM_KPRINT(mach_map_calls)
        MR_VM_KPRINT(munmap_calls) MR_VM_KPRINT(mprotect_calls) MR_VM_KPRINT(mach_deallocate_calls)
        MR_VM_KPRINT(eexist) MR_VM_KPRINT(enomem) MR_VM_KPRINT(einval) MR_VM_KPRINT(other_errno)
        MR_VM_KPRINT(mach_no_space) MR_VM_KPRINT(mach_invalid_address)
        MR_VM_KPRINT(mach_protection) MR_VM_KPRINT(mach_resource) MR_VM_KPRINT(mach_other)
#undef MR_VM_KPRINT
        if (i == MR_VM_NOADDR || i == MR_VM_ARENA || i == MR_VM_JIT)
            failures += mr_vm_get(&c->eexist) + mr_vm_get(&c->enomem) + mr_vm_get(&c->einval) +
                       mr_vm_get(&c->other_errno) + mr_vm_get(&c->mach_no_space) +
                       mr_vm_get(&c->mach_invalid_address) + mr_vm_get(&c->mach_protection) +
                       mr_vm_get(&c->mach_resource) + mr_vm_get(&c->mach_other);
    }
    ptr = mr_vm_field( ptr, "kernel_fail", failures );
    ptr = mr_vm_text( ptr, " coverage=Wine-virtual.c snapshot=exit-not-global-trace\n" );
    { ssize_t ignored = write( 2, buf, ptr - buf ); (void)ignored; }
}

static void mr_vm_arena_init(void)
{
    const char *gate = getenv( "MACRUNNER_VM_ARENA" );
    const char *state = "OFF";
    mr_vm_init_pid = getpid();
    mr_vm_gate = gate && !strcmp( gate, "1" );
    atexit( virtual_vm_arena_summary );
    if (mr_vm_gate)
    {
        mach_vm_address_t addr = 0x600000000000ULL;
        const mach_vm_size_t size = 0x100000000000ULL;
        mr_vm_reserve_kr = MR_VM_CALL( MR_VM_INIT, mach_vm_map( mach_task_self(), &addr, size, 0,
                                      VM_FLAGS_FIXED, MEMORY_OBJECT_NULL, 0, FALSE,
                                      VM_PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY ) );
        if (mr_vm_reserve_kr == KERN_SUCCESS)
        {
            mmap_add_reserved_area( (void *)(UINT_PTR)addr, size );
            if (mmap_is_in_reserved_area( (void *)(UINT_PTR)addr, size ) == 1)
            {
                mr_vm_base = (void *)(UINT_PTR)addr;
                mr_vm_end = (char *)mr_vm_base + size;
                mr_vm_owned = TRUE;
                state = "OWNED";
            }
            else
            {
                MR_VM_INC(reservation_bookkeeping_failed);
                MR_VM_CALL( MR_VM_INIT, mach_vm_deallocate( mach_task_self(), addr, size ) );
                state = "BOOKKEEPING_FAILED_LEGACY";
            }
        }
        else { MR_VM_INC(reservation_failed); state = "RESERVE_FAILED_LEGACY"; }
    }
    fprintf( stderr, "macrunner-vm-arena: rev=vm-arena-r2 pid=%d gate=%d state=%s base=%p end=%p"
                     " reserve_kr=%d host_limit=%p host_page=%zu\n", getpid(), mr_vm_gate,
                     state, mr_vm_base, mr_vm_end, mr_vm_reserve_kr, host_addr_space_limit, host_page_size );
    fflush( stderr );
}
#endif
