/*
 * MacRunner wcstombs owner/view diagnostic probe core.
 *
 * This header intentionally contains only bounded, allocation-free predicates
 * shared by kernelbase's probe and its focused host fixture.
 */

#ifndef __MACRUNNER_WCSTOMBS_PROBE_H
#define __MACRUNNER_WCSTOMBS_PROBE_H

#include <stddef.h>
#include <stdint.h>

enum macrunner_hb_wcstombs_owner_class
{
    MACRUNNER_HB_WCSTOMBS_OWNER_ANSI,
    MACRUNNER_HB_WCSTOMBS_OWNER_OEM,
    MACRUNNER_HB_WCSTOMBS_OWNER_CODEPAGES,
    MACRUNNER_HB_WCSTOMBS_OWNER_OTHER
};

struct macrunner_hb_wcstombs_owner
{
    enum macrunner_hb_wcstombs_owner_class class;
    int index;
};

static inline int macrunner_hb_wcstombs_probe_env_enabled( const uint16_t *value,
                                                           size_t value_length )
{
    return value && value_length == sizeof(*value) && value[0] == '1';
}

static inline int macrunner_hb_wcstombs_probe_should_arm( int enabled, unsigned int dstlen,
                                                          uintptr_t dbcs_offsets,
                                                          uintptr_t wide_char_table )
{
    return enabled && !dstlen && dbcs_offsets && wide_char_table < 0x10000;
}

static inline int macrunner_hb_wcstombs_probe_try_begin( volatile int32_t *once, int enabled,
                                                         unsigned int dstlen,
                                                         uintptr_t dbcs_offsets,
                                                         uintptr_t wide_char_table )
{
    int32_t expected = 0;

    if (!macrunner_hb_wcstombs_probe_should_arm( enabled, dstlen, dbcs_offsets,
                                                  wide_char_table ))
        return 0;
    return __atomic_compare_exchange_n( once, &expected, 1, 0, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE );
}

static inline struct macrunner_hb_wcstombs_owner
macrunner_hb_wcstombs_probe_classify_owner( uintptr_t info, uintptr_t ansi, uintptr_t oem,
                                            uintptr_t codepages, size_t codepage_capacity,
                                            size_t codepage_stride )
{
    struct macrunner_hb_wcstombs_owner ret = { MACRUNNER_HB_WCSTOMBS_OWNER_OTHER, -1 };
    uintptr_t offset;

    if (info == ansi)
    {
        ret.class = MACRUNNER_HB_WCSTOMBS_OWNER_ANSI;
        return ret;
    }
    if (info == oem)
    {
        ret.class = MACRUNNER_HB_WCSTOMBS_OWNER_OEM;
        return ret;
    }
    if (!codepage_stride || codepage_capacity > UINTPTR_MAX / codepage_stride)
        return ret;
    if (info < codepages) return ret;

    offset = info - codepages;
    if (offset >= codepage_capacity * codepage_stride || offset % codepage_stride)
        return ret;

    ret.class = MACRUNNER_HB_WCSTOMBS_OWNER_CODEPAGES;
    ret.index = offset / codepage_stride;
    return ret;
}

static inline unsigned int
macrunner_hb_wcstombs_probe_readable_source_count( uintptr_t src, unsigned int srclen,
                                                   uintptr_t region_base, size_t region_size,
                                                   int committed, int readable )
{
    unsigned int count = srclen < 2 ? srclen : 2;
    size_t bytes = count * sizeof(uint16_t);
    uintptr_t region_end, src_end;

    if (!src || !count || !committed || !readable) return 0;
    if (region_size > UINTPTR_MAX - region_base) return 0;
    if (bytes > UINTPTR_MAX - src) return 0;

    region_end = region_base + region_size;
    src_end = src + bytes;
    if (src < region_base || src_end > region_end) return 0;
    return count;
}

#endif /* __MACRUNNER_WCSTOMBS_PROBE_H */
