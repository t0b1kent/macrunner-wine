/* ARM64 memory copying for Wine PE modules.
 * This file is part of Wine, distributed under the GNU LGPL, version 2.1 or later.
 */
#ifndef __WINE_ARM64_MEMMOVE_H
#define __WINE_ARM64_MEMMOVE_H

#include <stddef.h>
#include <stdint.h>

#if defined(__aarch64__) || defined(__arm64ec__)
/* Under Apple hardware TSO, a multi-register SIMD load has a large per-register
 * cost. Keep every load a single instruction/register, including short copies.
 * The asm is intentional: the compiler otherwise combines adjacent LDR Qs into
 * LDP Q. Both source vectors are loaded before either destination is written,
 * so the same loop also preserves overlapping memmove in either direction.
 * No access extends outside [src,src+n) or [dst,dst+n).
 */
static __inline__ __attribute__((always_inline)) void *wine_arm64_memmove( void *dst, const void *src, size_t n )
{
    unsigned char *d = dst;
    const unsigned char *s = src;

    if (!n || dst == src) return dst;
    if ((uintptr_t)dst - (uintptr_t)src >= n)
    {
        __asm__ volatile (
            "lsr x10, %x[count], #5\n\t"
            "cbz x10, 2f\n\t"
            "1: ldr q0, [%x[source]]\n\t"
            "ldr q1, [%x[source], #16]\n\t"
            "add %x[source], %x[source], #32\n\t"
            "stp q0, q1, [%x[dest]], #32\n\t"
            "subs x10, x10, #1\n\t"
            "b.ne 1b\n\t"
            "2: tbz %x[count], #4, 3f\n\t"
            "ldr q0, [%x[source]], #16\n\t"
            "str q0, [%x[dest]], #16\n\t"
            "3: tbz %x[count], #3, 4f\n\t"
            "ldr x9, [%x[source]], #8\n\t"
            "str x9, [%x[dest]], #8\n\t"
            "4: tbz %x[count], #2, 5f\n\t"
            "ldr w9, [%x[source]], #4\n\t"
            "str w9, [%x[dest]], #4\n\t"
            "5: tbz %x[count], #1, 6f\n\t"
            "ldrh w9, [%x[source]], #2\n\t"
            "strh w9, [%x[dest]], #2\n\t"
            "6: tbz %x[count], #0, 7f\n\t"
            "ldrb w9, [%x[source]]\n\t"
            "strb w9, [%x[dest]]\n\t"
            "7:\n\t"
            : [dest] "+&r" (d), [source] "+&r" (s), [count] "+&r" (n)
            : : "x9", "x10", "v0", "v1", "cc", "memory" );
    }
    else
    {
        d += n;
        s += n;
        __asm__ volatile (
            "lsr x10, %x[count], #5\n\t"
            "cbz x10, 2f\n\t"
            "1: sub %x[source], %x[source], #32\n\t"
            "sub %x[dest], %x[dest], #32\n\t"
            "ldr q0, [%x[source]]\n\t"
            "ldr q1, [%x[source], #16]\n\t"
            "stp q0, q1, [%x[dest]]\n\t"
            "subs x10, x10, #1\n\t"
            "b.ne 1b\n\t"
            "2: tbz %x[count], #4, 3f\n\t"
            "ldr q0, [%x[source], #-16]!\n\t"
            "str q0, [%x[dest], #-16]!\n\t"
            "3: tbz %x[count], #3, 4f\n\t"
            "ldr x9, [%x[source], #-8]!\n\t"
            "str x9, [%x[dest], #-8]!\n\t"
            "4: tbz %x[count], #2, 5f\n\t"
            "ldr w9, [%x[source], #-4]!\n\t"
            "str w9, [%x[dest], #-4]!\n\t"
            "5: tbz %x[count], #1, 6f\n\t"
            "ldrh w9, [%x[source], #-2]!\n\t"
            "strh w9, [%x[dest], #-2]!\n\t"
            "6: tbz %x[count], #0, 7f\n\t"
            "ldrb w9, [%x[source], #-1]!\n\t"
            "strb w9, [%x[dest], #-1]!\n\t"
            "7:\n\t"
            : [dest] "+&r" (d), [source] "+&r" (s), [count] "+&r" (n)
            : : "x9", "x10", "v0", "v1", "cc", "memory" );
    }
    return dst;
}
#endif
#endif
