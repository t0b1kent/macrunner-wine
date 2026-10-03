/* Bounded decoding of the import thunks emitted in Wine ARM64X images.
 * This describes code; it never executes an x64 instruction. */
#ifndef MACRUNNER_ARM64X_DELAY_H
#define MACRUNNER_ARM64X_DELAY_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

enum mr_arm64x_import_kind
{
    MR_ARM64X_IMPORT_INVALID = -1,
    MR_ARM64X_IMPORT_NONE,
    MR_ARM64X_IMPORT_JUMP,
    MR_ARM64X_IMPORT_DELAY
};

struct mr_arm64x_import
{
    size_t slot;
    size_t branch;
};

static inline int mr_arm64x_span( size_t size, size_t start, size_t length )
{
    return start <= size && length <= size - start;
}

static inline int mr_arm64x_rel32( size_t size, size_t next, int32_t disp,
                           size_t length, size_t *result )
{
    if (next > size) return 0;
    if (disp < 0)
    {
        uint32_t back = -(int64_t)disp;
        if (back > next) return 0;
        *result = next - back;
    }
    else
    {
        if ((uint32_t)disp > size - next) return 0;
        *result = next + (uint32_t)disp;
    }
    return mr_arm64x_span( size, *result, length );
}

static inline enum mr_arm64x_import_kind mr_arm64x_decode_import( const void *image, size_t size,
                                                          size_t pc, struct mr_arm64x_import *out )
{
    const unsigned char *bytes = image;
    int32_t disp;

    if (!mr_arm64x_span( size, pc, 2 )) return MR_ARM64X_IMPORT_INVALID;
    if (bytes[pc] == 0xff && bytes[pc + 1] == 0x25)
    {
        if (!mr_arm64x_span( size, pc, 6 )) return MR_ARM64X_IMPORT_INVALID;
        memcpy( &disp, bytes + pc + 2, sizeof(disp) );
        if (!mr_arm64x_rel32( size, pc + 6, disp, 8, &out->slot ) || out->slot % 8)
            return MR_ARM64X_IMPORT_INVALID;
        out->branch = 0;
        return MR_ARM64X_IMPORT_JUMP;
    }
    if (bytes[pc] != 0x48 || bytes[pc + 1] != 0x8d) return MR_ARM64X_IMPORT_NONE;
    if (!mr_arm64x_span( size, pc, 12 ) || bytes[pc + 2] != 0x05 || bytes[pc + 7] != 0xe9)
        return MR_ARM64X_IMPORT_INVALID;
    memcpy( &disp, bytes + pc + 3, sizeof(disp) );
    if (!mr_arm64x_rel32( size, pc + 7, disp, 8, &out->slot ) || out->slot % 8)
        return MR_ARM64X_IMPORT_INVALID;
    memcpy( &disp, bytes + pc + 8, sizeof(disp) );
    if (!mr_arm64x_rel32( size, pc + 12, disp, 1, &out->branch ) || out->branch == pc)
        return MR_ARM64X_IMPORT_INVALID;
    return MR_ARM64X_IMPORT_DELAY;
}

/* ARM64X CodeMap tags are two bits: ARM64=0, ARM64EC=1, AMD64=2. */
static inline int mr_arm64x_code_kind( const void *image, size_t size, size_t map,
                               size_t count, size_t pc )
{
    const unsigned char *bytes = image;
    size_t i;

    if (!count || count > size / 8 || !mr_arm64x_span( size, map, count * 8 ) || pc >= size)
        return -1;
    for (i = 0; i < count; i++)
    {
        uint32_t tagged, length;
        size_t start;
        memcpy( &tagged, bytes + map + i * 8, 4 );
        memcpy( &length, bytes + map + i * 8 + 4, 4 );
        start = tagged & ~3u;
        if ((tagged & 3) == 3 || !mr_arm64x_span( size, start, length )) return -1;
        if (pc >= start && pc - start < length) return tagged & 3;
    }
    return -1;
}

#endif
