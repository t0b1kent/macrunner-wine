/* Scalar, read-only KUSD fault emulation shared with the native host tests. */
#ifndef MACRUNNER_FEX_KUSD_H
#define MACRUNNER_FEX_KUSD_H

#include <stdint.h>
#include <string.h>

#define MACRUNNER_FEX_KUSD_BASE UINT64_C(0x7ffe0000)
#define MACRUNNER_FEX_KUSD_SIZE 4096u

struct macrunner_fex_kusd_load
{
    uint64_t offset;
    unsigned int rt, width, sign_extend, dst32, acquire;
};

typedef int (*macrunner_fex_kusd_reader)( void *, uint64_t, unsigned int,
                                         unsigned int, uint64_t * );

static inline int macrunner_fex_kusd_decode( uint32_t insn, uint64_t fault,
                                            const uint64_t regs[31], uint64_t sp,
                                            struct macrunner_fex_kusd_load *load )
{
    unsigned int size = insn >> 30, opc = (insn >> 22) & 3, rn = (insn >> 5) & 31;
    int64_t displacement = 0;
    uint64_t address = rn == 31 ? sp : regs[rn];
    struct macrunner_fex_kusd_load result = {0};

    result.rt = insn & 31;
    result.width = 1u << size;
    if ((insn & 0x3ffffc00u) == 0x08dffc00u || /* LDAR B/H/W/X */
        (insn & 0x3ffffc00u) == 0x38bfc000u)   /* LDAPR B/H/W/X */
    {
        result.acquire = 1;
        opc = 1;
    }
    else if ((insn & 0x3f000000u) == 0x39000000u) /* LDR, unsigned immediate */
        displacement = ((insn >> 10) & 4095u) * result.width;
    else if ((insn & 0x3f200c00u) == 0x38000000u || /* LDUR, no writeback */
             (insn & 0x3f200c00u) == 0x19000000u)   /* LDAPUR, no writeback */
    {
        displacement = (insn >> 12) & 511u;
        if (displacement & 256) displacement -= 512;
        result.acquire = (insn & 0x3f000000u) == 0x19000000u;
    }
    else return 0; /* No stores, RMW/exclusives, SIMD, pairs or writeback. */

    if (!opc || (opc == 2 && size == 3) || (opc == 3 && size >= 2)) return 0;
    result.sign_extend = opc >= 2;
    result.dst32 = opc == 3 || (opc == 1 && size < 3);
    if (displacement >= 0)
    {
        if (address > UINT64_MAX - (uint64_t)displacement) return 0;
        address += displacement;
    }
    else
    {
        if (address < (uint64_t)-displacement) return 0;
        address -= (uint64_t)-displacement;
    }
    if (address != fault || address < MACRUNNER_FEX_KUSD_BASE) return 0;
    result.offset = address - MACRUNNER_FEX_KUSD_BASE;
    if (result.offset > MACRUNNER_FEX_KUSD_SIZE - result.width) return 0;
    /* Do not turn an alignment fault on an acquire load into a successful read. */
    if (result.acquire && (address & (result.width - 1))) return 0;
    *load = result;
    return 1;
}

/* The caller supplies a verified, stable, live read-only shared-data mapping. */
static inline int macrunner_fex_kusd_read_live( void *page, uint64_t offset,
                                               unsigned int width, unsigned int acquire,
                                               uint64_t *value )
{
    const unsigned char *p;
    int order = acquire ? __ATOMIC_ACQUIRE : __ATOMIC_RELAXED;

    if (width != 1 && width != 2 && width != 4 && width != 8) return 0;
    if (!page || offset > MACRUNNER_FEX_KUSD_SIZE - width) return 0;
    p = (const unsigned char *)page + offset;
    if ((uintptr_t)p & (width - 1))
    {
        if (acquire) return 0;
        *value = 0;
        memcpy( value, p, width );
        return 1;
    }
    switch (width)
    {
    case 1: *value = __atomic_load_n( (const uint8_t *)p, order ); break;
    case 2: *value = __atomic_load_n( (const uint16_t *)p, order ); break;
    case 4: *value = __atomic_load_n( (const uint32_t *)p, order ); break;
    case 8: *value = __atomic_load_n( (const uint64_t *)p, order ); break;
    }
    return 1;
}

static inline int macrunner_fex_kusd_emulate( uint32_t insn, uint64_t fault,
                                             uint64_t regs[31], uint64_t sp, uint64_t *pc,
                                             macrunner_fex_kusd_reader read, void *page )
{
    struct macrunner_fex_kusd_load load;
    uint64_t value;

    if ((*pc & 3) || *pc > UINT64_MAX - 4) return 0;
    if (!macrunner_fex_kusd_decode( insn, fault, regs, sp, &load )) return 0;
    if (!read( page, load.offset, load.width, load.acquire, &value )) return 0;
    if (load.sign_extend)
    {
        uint64_t sign = UINT64_C(1) << (load.width * 8 - 1);
        value = (value ^ sign) - sign;
    }
    if (load.dst32) value = (uint32_t)value;
    /* Rt==Rn overwrites the address just as the original load does; XZR discards. */
    if (load.rt != 31) regs[load.rt] = value;
    *pc += 4;
    return 1;
}

#endif
