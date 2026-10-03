#ifndef HB_IR_H
#define HB_IR_H

#include "hb_result.h"
#include "hb_context.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IR operand types */
typedef enum {
    HB_OP_REG,
    HB_OP_IMM,
    HB_OP_MEM,
    HB_OP_LABEL,
    HB_OP_NONE
} hb_op_type_t;

/* IR value size */
typedef enum {
    HB_SIZE_8 = 1,
    HB_SIZE_16 = 2,
    HB_SIZE_32 = 4,
    HB_SIZE_64 = 8,
    HB_SIZE_80 = 10,
    HB_SIZE_128 = 16,
    HB_SIZE_256 = 32,
    HB_SIZE_512 = 64
} hb_size_t;

typedef enum {
    HB_VEC_PHADDW = 1,
    HB_VEC_PHADDD,
    HB_VEC_PHADDSW,
    HB_VEC_PHSUBW,
    HB_VEC_PHSUBD,
    HB_VEC_PHSUBSW,
    HB_VEC_PMADDUBSW,
    HB_VEC_PSIGNB,
    HB_VEC_PSIGNW,
    HB_VEC_PSIGND,
    HB_VEC_PMULHRSW,
    HB_VEC_PABSB,
    HB_VEC_PABSW,
    HB_VEC_PABSD,
    HB_VEC_PTEST,
    HB_VEC_PMOVSXBW,
    HB_VEC_PMOVSXBD,
    HB_VEC_PMOVSXBQ,
    HB_VEC_PMOVSXWD,
    HB_VEC_PMOVSXWQ,
    HB_VEC_PMOVSXDQ,
    HB_VEC_PMULDQ,
    HB_VEC_PCMPEQQ,
    HB_VEC_PACKUSDW,
    HB_VEC_PMOVZXBW,
    HB_VEC_PMOVZXBD,
    HB_VEC_PMOVZXBQ,
    HB_VEC_PMOVZXWD,
    HB_VEC_PMOVZXWQ,
    HB_VEC_PMOVZXDQ,
    HB_VEC_PCMPGTQ,
    HB_VEC_PMINSB,
    HB_VEC_PMINSD,
    HB_VEC_PMINUW,
    HB_VEC_PMINUD,
    HB_VEC_PMAXSB,
    HB_VEC_PMAXSD,
    HB_VEC_PMAXUW,
    HB_VEC_PMAXUD,
    HB_VEC_PMULLD,
    HB_VEC_PHMINPOSUW,
    HB_VEC_PALIGNR,
    HB_VEC_PBLENDW,
    HB_VEC_BLENDPS,
    HB_VEC_BLENDPD,
    HB_VEC_PBLENDVB,
    HB_VEC_BLENDVPS,
    HB_VEC_BLENDVPD,
    HB_VEC_PSUBUSB,
    HB_VEC_PSUBUSW,
    HB_VEC_PSUBSB,
    HB_VEC_PSUBSW,
    HB_VEC_PMINUB,
    HB_VEC_PMINSW,
    HB_VEC_PMAXUB,
    HB_VEC_PMAXSW,
    HB_VEC_PMULUDQ,
    HB_VEC_PSADBW,
    HB_VEC_MPSADBW,
    HB_VEC_VPBROADCASTB,
    HB_VEC_VPBROADCASTW,
    HB_VEC_VPBROADCASTD,
    HB_VEC_VPBROADCASTQ,
    HB_VEC_VBROADCASTSS,
    HB_VEC_VBROADCASTSD,
    HB_VEC_VBROADCASTF32X2,
    HB_VEC_VBROADCASTF64X2,
    HB_VEC_VBROADCASTF32X4,
    HB_VEC_VBROADCASTF64X4,
    HB_VEC_VBROADCASTF32X8,
    HB_VEC_VBROADCASTI32X2,
    HB_VEC_VBROADCASTI128,
    HB_VEC_VPBLENDD,
    HB_VEC_VPERMQ,
    HB_VEC_VPERMPD,
    HB_VEC_VPERMILPS,
    HB_VEC_VPERMILPD,
    HB_VEC_VBLENDVPS,
    HB_VEC_VBLENDVPD,
    HB_VEC_VPBLENDVB,
    HB_VEC_VINSERTF128,
    HB_VEC_VINSERTI128,
    HB_VEC_VEXTRACTF128,
    HB_VEC_VEXTRACTI128,
    HB_VEC_VPERM2F128,
    HB_VEC_VPERM2I128,
    HB_VEC_VPSRLVD,
    HB_VEC_VPSRLVQ,
    HB_VEC_VPSRAVD,
    HB_VEC_VPSLLVD,
    HB_VEC_VPSLLVQ,
    HB_VEC_PCLMULQDQ,
    HB_VEC_AESKEYGENASSIST,
    HB_VEC_AESIMC,
    HB_VEC_AESENC,
    HB_VEC_AESENCLAST,
    HB_VEC_AESDEC,
    HB_VEC_AESDECLAST,
    HB_VEC_GF2P8MULB,
    HB_VEC_GF2P8AFFINEQB,
    HB_VEC_GF2P8AFFINEINVQB,
    HB_VEC_VPERMD,
    HB_VEC_VPERMPS,
    HB_VEC_VMASKMOVPS,
    HB_VEC_VMASKMOVPD,
    HB_VEC_VMASKMOVDQU,
    HB_VEC_VPMASKMOVD,
    HB_VEC_VPMASKMOVQ,
    HB_VEC_VTESTPS,
    HB_VEC_VTESTPD,
    HB_VEC_VGATHERDPS,
    HB_VEC_VGATHERDPD,
    HB_VEC_VGATHERQPS,
    HB_VEC_VGATHERQPD,
    HB_VEC_VPGATHERDD,
    HB_VEC_VPGATHERDQ,
    HB_VEC_VPGATHERQD,
    HB_VEC_VPGATHERQQ,
    HB_VEC_PCMPESTRM,
    HB_VEC_PCMPESTRI,
    HB_VEC_PCMPISTRM,
    HB_VEC_PCMPISTRI,
    HB_VEC_VFMADD132,
    HB_VEC_VFMADD213,
    HB_VEC_VFMADD231,
    HB_VEC_VFMSUB132,
    HB_VEC_VFMSUB213,
    HB_VEC_VFMSUB231,
    HB_VEC_VFMADDSUB132,
    HB_VEC_VFMSUBADD132,
    HB_VEC_VFMADDSUB213,
    HB_VEC_VFMSUBADD213,
    HB_VEC_VFMADDSUB231,
    HB_VEC_VFMSUBADD231,
    HB_VEC_VFNMADD132,
    HB_VEC_VFNMSUB132,
    HB_VEC_VFNMADD213,
    HB_VEC_VFNMSUB213,
    HB_VEC_VFNMADD231,
    HB_VEC_VFNMSUB231,
    HB_VEC_VCVTPH2PS,
    HB_VEC_VCVTPS2PH,
    HB_VEC_VCMPPS,
    HB_VEC_VCMPPD,
    HB_VEC_VCMPSS,
    HB_VEC_VCMPSD,
    HB_VEC_VHADDPS,
    HB_VEC_VHADDPD,
    HB_VEC_VHSUBPS,
    HB_VEC_VHSUBPD,
    HB_VEC_VADDSUBPS,
    HB_VEC_VADDSUBPD,
    HB_VEC_VMOVSLDUP,
    HB_VEC_VMOVSHDUP,
    HB_VEC_VMOVDDUP,
    HB_VEC_SHA1NEXTE,
    HB_VEC_SHA1MSG1,
    HB_VEC_SHA1MSG2,
    HB_VEC_SHA256RNDS2,
    HB_VEC_SHA256MSG1,
    HB_VEC_SHA256MSG2,
    HB_VEC_SHA1RNDS4,
    /* ★★★★★★ MacRunner 2026-08-29 — CRC32 (SSE4.2) НУЖЕН СВОЙ КОД.
     * Раньше CRC32 лифтился как VEC_PACKED с vec_op=0 — тем же нулём, что у ADCX и ADOX,
     * поэтому в интерпретаторе его нельзя было отличить, и он не исполнялся ВООБЩЕ:
     * декодер знал, лифтер принимал, интерпретатор и кодогенератор — ноль упоминаний.
     * Проба исполнения (tests/hb_x86_exec_probe, f20f38f1cb) давала ок=0 и неизменный
     * регистр. Из-за этого лаунчер Diablo падал c0000001 на `f2 0f 38 f1 4b fc`, а
     * установщик InnoSetup получал строки с испорченными байтами: он считает CRC32 при
     * распаковке, и неверный результат портит данные, а не роняет. Один корень, два лица. */
    HB_VEC_CRC32
} hb_ir_vec_op_t;

/* x64 registers */
typedef enum {
    HB_REG_RAX = 0, HB_REG_RCX, HB_REG_RDX, HB_REG_RBX,
    HB_REG_RSP, HB_REG_RBP, HB_REG_RSI, HB_REG_RDI,
    HB_REG_R8, HB_REG_R9, HB_REG_R10, HB_REG_R11,
    HB_REG_R12, HB_REG_R13, HB_REG_R14, HB_REG_R15,
    HB_REG_RIP,
    HB_REG_XMM0, HB_REG_XMM1, HB_REG_XMM2, HB_REG_XMM3,
    HB_REG_XMM4, HB_REG_XMM5, HB_REG_XMM6, HB_REG_XMM7,
    HB_REG_XMM8, HB_REG_XMM9, HB_REG_XMM10, HB_REG_XMM11,
    HB_REG_XMM12, HB_REG_XMM13, HB_REG_XMM14, HB_REG_XMM15,
    HB_REG_XMM16, HB_REG_XMM17, HB_REG_XMM18, HB_REG_XMM19,
    HB_REG_XMM20, HB_REG_XMM21, HB_REG_XMM22, HB_REG_XMM23,
    HB_REG_XMM24, HB_REG_XMM25, HB_REG_XMM26, HB_REG_XMM27,
    HB_REG_XMM28, HB_REG_XMM29, HB_REG_XMM30, HB_REG_XMM31,
    /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 303 — регистры MMX.
     * Добавлены В КОНЕЦ, перед счётчиком: существующие номера не сдвигаются. */
    HB_REG_MM0, HB_REG_MM1, HB_REG_MM2, HB_REG_MM3,
    HB_REG_MM4, HB_REG_MM5, HB_REG_MM6, HB_REG_MM7,
    /* MacRunner 04.09.2026 — РЕГИСТРЫ-МАСКИ AVX-512 (k0..k7).
     *
     * Место под них в состоянии было давно (`uint64_t k[8]` в hb_context_t),
     * но КЛАССА регистров не было, и приёмник-маска у семьи VCMP под EVEX
     * оказывался то непосредственным, то вектором. Проверено: декодер такие
     * формы отвергал, то есть молчаливой порчи не было, — но и исполнить их
     * было нельзя.
     *
     * Добавлены В КОНЕЦ, перед счётчиком: существующие номера не сдвигаются,
     * и зашитые в выпущенный код смещения остаются верны. */
    HB_REG_K0, HB_REG_K1, HB_REG_K2, HB_REG_K3,
    HB_REG_K4, HB_REG_K5, HB_REG_K6, HB_REG_K7,
    HB_REG_COUNT
} hb_reg_t;

/* x86 registers */
typedef enum {
    HB_REG_X86_EAX = 0, HB_REG_X86_ECX, HB_REG_X86_EDX, HB_REG_X86_EBX,
    HB_REG_X86_ESP, HB_REG_X86_EBP, HB_REG_X86_ESI, HB_REG_X86_EDI,
    HB_REG_X86_EIP,
    HB_REG_X86_XMM0, HB_REG_X86_XMM1, HB_REG_X86_XMM2, HB_REG_X86_XMM3,
    HB_REG_X86_XMM4, HB_REG_X86_XMM5, HB_REG_X86_XMM6, HB_REG_X86_XMM7,
    HB_REG_X86_COUNT
} hb_reg_x86_t;

/* IR operand */
typedef struct {
    hb_op_type_t type;
    hb_size_t size;
    uint8_t reg_offset; /* x86-64 legacy high-8 regs: AH/CH/DH/BH live at byte offset 1. */
    union {
        hb_reg_t reg;
        int64_t imm;
        struct {
            hb_reg_t base;
            hb_reg_t index;
            uint8_t scale;
            int64_t disp;
            uint8_t segment; /* 0 none, 0x64 FS, 0x65 GS */
            bool addr32;     /* x86-64 0x67 address-size override: low-32 effective address */
            bool addr16;     /* i386 0x67: 16-битная адресация, адрес усекается до 0xFFFF */
            bool vsib;       /* AVX gather VSIB: index names an XMM/YMM vector register */
            uint8_t vsib_index_size;
            uint8_t vsib_elem_size;
            uint8_t vsib_count;
        } mem;
        uint64_t label;
    };
} hb_ir_operand_t;

/* IR operation codes */
typedef enum {
    HB_IR_NOP,
    HB_IR_MOV,
    HB_IR_MOV_SEG,
    HB_IR_LEA,
    HB_IR_ADD,
    HB_IR_ADC,
    HB_IR_SUB,
    HB_IR_SBB,
    HB_IR_MUL,
    HB_IR_IMUL,
    HB_IR_DIV,
    HB_IR_IDIV,
    HB_IR_BT,
    HB_IR_BTS,
    HB_IR_BTR,
    HB_IR_BTC,
    HB_IR_AND,
    HB_IR_OR,
    HB_IR_XOR,
    HB_IR_NOT,
    HB_IR_NEG,
    HB_IR_SHL,
    HB_IR_SHR,
    HB_IR_SAR,
    HB_IR_ROL,
    HB_IR_ROR,
    HB_IR_RCL,
    HB_IR_RCR,
    HB_IR_SHLD,
    HB_IR_SHRD,
    HB_IR_CMP,
    HB_IR_TEST,
    HB_IR_CMPXCHG,
    HB_IR_CMPXCHG8B,
    HB_IR_XCHG,
    HB_IR_XADD,
    HB_IR_FENCE,
    HB_IR_LAHF,
    HB_IR_SAHF,
    HB_IR_CPUID,
    /* Итерация 303: перенос MMX (MOVQ/MOVD). Отдельная операция, чтобы не трогать общие пути
     * чтения регистров: кодогенератор уводит её в помощник-интерпретатор веткой default. */
    HB_IR_MMX_MOV,
    /* Итерация 304, партия 2 MMX: побитовая логика. Операции ПП отдельные, как и MMX_MOV,
     * чтобы не трогать общие пути чтения регистров. */
    HB_IR_MMX_AND, HB_IR_MMX_ANDN, HB_IR_MMX_OR, HB_IR_MMX_XOR,
    /* Итерация 305, партия 3 MMX: сдвиги. Разрядность элемента — в поле target (2/4/8). */
    HB_IR_MMX_SRL, HB_IR_MMX_SRA, HB_IR_MMX_SLL,
    HB_IR_XGETBV,
    HB_IR_RDTSC,
    HB_IR_RDTSCP,
    HB_IR_VERR,
    HB_IR_VERW,
    HB_IR_RDRAND,
    HB_IR_RDSEED,
    HB_IR_SETcc,
    HB_IR_CMOVcc,
    HB_IR_LOAD,
    HB_IR_STORE,
    HB_IR_PUSH,
    HB_IR_POP,
    HB_IR_PUSHF,
    HB_IR_POPF,
    HB_IR_CALL,
    HB_IR_CALLF,       /* 0x9A far CALL ptr16:32 (32-bit only) */
    HB_IR_JMPF,        /* 0xEA far JMP ptr16:32 (32-bit only) */
    HB_IR_RETF,        /* 0xCA/0xCB RETF / RETF imm16 (32-bit) */
    HB_IR_IRET,        /* 0xCF IRET/IRETD */
    HB_IR_INT3,        /* 0xCC INT3 — debug breakpoint (3-byte form) */
    HB_IR_INT,         /* 0xCD imm8 INT n — vectored software interrupt */
    HB_IR_INT1,        /* 0xF1 INT1 / ICEBP — debug breakpoint (1-byte form) */
    HB_IR_INTO,        /* 0xCE INTO — overflow-trap if OF=1 */
    HB_IR_HLT,         /* 0xF4 HLT — privileged, but acknowledged */
    HB_IR_IN,          /* 0xE4/0xE5/0xEC/0xED IN — port I/O (privileged) */
    HB_IR_OUT,         /* 0xE6/0xE7/0xEE/0xEF OUT — port I/O (privileged) */
    HB_IR_XLAT,        /* 0xD7 XLATB — AL = [EBX+AL] */
    HB_IR_PUSH_SEG,    /* 0x06/0x0E/0x16/0x1E PUSH ES/CS/SS/DS */
    HB_IR_POP_SEG,     /* 0x07/0x17/0x1F POP ES/SS/DS (CS/FS/GS are privileged) */
    HB_IR_CLC,         /* 0xF8 */
    HB_IR_STC,         /* 0xF9 */
    HB_IR_CMC,         /* 0xF5 */
    HB_IR_CLD,         /* 0xFC */
    HB_IR_STD,         /* 0xFD */
    HB_IR_CLI,         /* 0xFA */
    HB_IR_STI,         /* 0xFB */
    HB_IR_ENTER,       /* 0xC8 ENTER imm16, imm8 */
    HB_IR_RET,
    HB_IR_JMP,
    HB_IR_Jcc,
    HB_IR_LOOP,
    HB_IR_JRCXZ,
    HB_IR_SIGN_EXTEND,
    HB_IR_CWD,
    HB_IR_MOVS,
    HB_IR_CMPS,
    HB_IR_LODS,
    HB_IR_SCAS,
    HB_IR_STOS,
    HB_IR_ZERO_EXTEND,
    HB_IR_TRUNC,
    HB_IR_BSF,
    HB_IR_TZCNT,
    HB_IR_LZCNT,
    HB_IR_BSR,
    HB_IR_POPCNT,
    HB_IR_BSWAP,
    HB_IR_MOVBE,
    HB_IR_MOVDIR64B,
    HB_IR_CRC32,
    HB_IR_ANDN,
    HB_IR_BEXTR,
    HB_IR_BLSI,
    HB_IR_BLSMSK,
    HB_IR_BLSR,
    HB_IR_BZHI,
    HB_IR_MULX,
    HB_IR_PDEP,
    HB_IR_PEXT,
    HB_IR_RORX,
    HB_IR_SARX,
    HB_IR_SHLX,
    HB_IR_SHRX,
    HB_IR_ADCX,
    HB_IR_ADOX,
    HB_IR_XMM_AND,
    HB_IR_XMM_SCALAR_MOV,
    HB_IR_XMM_QWORD_LANE_MOV,
    HB_IR_XMM_ANDN,
    HB_IR_XMM_OR,
    HB_IR_XORPS,
    HB_IR_PCMPEQB,
    HB_IR_PCMPEQW,
    HB_IR_PCMPEQD,
    HB_IR_PCMPGTB,
    HB_IR_PCMPGTW,
    HB_IR_PCMPGTD,
    HB_IR_PMOVMSKB,
    HB_IR_MOVMSK,
    HB_IR_PUNPCK,
    HB_IR_PACKSSWB,
    HB_IR_PACKUSWB,
    HB_IR_PACKSSDW,
    HB_IR_PMULLW,
    HB_IR_PMULHW,
    HB_IR_PMULHUW,
    HB_IR_PMADDWD,
    HB_IR_PADDSB,
    HB_IR_PADDSW,
    HB_IR_PADDUSB,
    HB_IR_PADDUSW,
    HB_IR_PAVGB,
    HB_IR_PAVGW,
    /* MacRunner 2026-08-10, лейн ЛЕСТНИЦА — партия 4: насыщающее ВЫЧИТАНИЕ и PSADBW.
     * Замер 188: эти коды рвались в ДЕКОДЕРЕ x86-32 (decode=-5), эталон x64 их знает. */
    HB_IR_PSUBSB,
    HB_IR_PSUBSW,
    HB_IR_PSUBUSB,
    HB_IR_PSUBUSW,
    HB_IR_PSADBW,
    HB_IR_PSHUFB,
    HB_IR_PINSRW,
    HB_IR_PEXTRW,
    HB_IR_PINSR,
    HB_IR_PEXTR,
    HB_IR_INSERTPS,
    HB_IR_EXTRACTPS,
    HB_IR_PSHUF,
    HB_IR_FSHUF,
    HB_IR_PSRL,
    HB_IR_PSRA,
    HB_IR_PSLL,
    HB_IR_PSRLQ,
    HB_IR_PSLLQ,
    HB_IR_PSRLDQ,
    HB_IR_PSLLDQ,
    HB_IR_MOVD,
    HB_IR_CVTDQ2PD,
    HB_IR_CVTDQ2PS,
    HB_IR_CVTPS2DQ,
    HB_IR_CVTTPS2DQ,
    HB_IR_CVTPS2PD,
    HB_IR_CVTPD2PS,
    HB_IR_CVTPD2DQ,
    HB_IR_CVTTPD2DQ,
    HB_IR_CVTSS2SD,
    HB_IR_CVTSD2SS,
    HB_IR_CVTSI2SD,
    HB_IR_CVTSI2SS,
    HB_IR_FSQRT,
    HB_IR_FRSQRT,
    HB_IR_FRCP,
    HB_IR_FROUND,
    HB_IR_FDP,
    HB_IR_FADD,
    HB_IR_FSUB,
    HB_IR_FMUL,
    HB_IR_FDIV,
    HB_IR_ADDSD,
    HB_IR_SUBSD,
    HB_IR_DIVSD,
    HB_IR_MULSD,
    HB_IR_DIVSS,
    HB_IR_MULSS,
    HB_IR_FAR_BRANCH,
    HB_IR_HADDSUB,
    HB_IR_MOVDUP,
    HB_IR_MOVQ2DQ,
    HB_IR_MOVDQ2Q,
    HB_IR_MASKMOV,
    HB_IR_CVT_MMX_FP,
    HB_IR_FCMP_MASK,
    HB_IR_FMIN,
    HB_IR_FMAX,
    HB_IR_COMISS,
    HB_IR_COMISD,
    HB_IR_CVTSD2SI,
    HB_IR_CVTSS2SI,
    HB_IR_CVTTSD2SI,
    HB_IR_CVTTSS2SI,
    HB_IR_VCVTTSS2USI,
    HB_IR_VCVTTSD2USI,
    HB_IR_PADD,
    HB_IR_PSUB,
    HB_IR_VEC_PACKED,
    HB_IR_EVEX_CMP_MASK,
    HB_IR_VZEROUPPER,
    HB_IR_VZEROALL,      /* обнуляет регистры ЦЕЛИКОМ, а не только старшие половины */
    /* Чтение и запись базы FS/GS. `target`: бит0 — GS вместо FS, бит1 — запись. */
    HB_IR_FSGSBASE,
    HB_IR_X87_FLD,
    HB_IR_X87_FST,
    HB_IR_X87_FSTP,
    HB_IR_X87_FILD,
    HB_IR_X87_FISTP,
    HB_IR_X87_FIST,
    HB_IR_X87_FLDCW,
    HB_IR_X87_FNSTCW,
    HB_IR_X87_FNSTSW,
    HB_IR_X87_FLDENV,
    HB_IR_X87_FNSTENV,
    HB_IR_X87_FRSTOR,
    HB_IR_X87_FNSAVE,
    HB_IR_X87_FXSAVE,
    HB_IR_X87_FXRSTOR,
    HB_IR_X87_FADD,
    HB_IR_X87_FMUL,
    HB_IR_X87_FCOM,
    HB_IR_X87_FCOMP,
    HB_IR_X87_FSUB,
    HB_IR_X87_FSUBR,
    HB_IR_X87_FDIV,
    HB_IR_X87_FDIVR,
    HB_IR_X87_FADDP,
    HB_IR_X87_FMULP,
    HB_IR_X87_FCOMPP,
    HB_IR_X87_FSUBP,
    HB_IR_X87_FSUBRP,
    HB_IR_X87_FDIVP,
    HB_IR_X87_FDIVRP,
    HB_IR_X87_FXCH,
    HB_IR_X87_FRNDINT,
    HB_IR_X87_FINCSTP,
    HB_IR_X87_FDECSTP,
    /* ★ 30.08, лейн УСТАНОВЩИКИ: FFREE ST(i) — пометить слот свободным.
     * Раньше поднимался в NOP, отчего идиома Delphi `FFREE ST(0); FINCSTP`
     * (конец FillChar) оставляла слот занятым и за 8 вызовов набивала стек. */
    HB_IR_X87_FFREE,
    HB_IR_X87_FXAM,
    HB_IR_X87_FSQRT,
    /* D9 F0-FF transcendentals. */
    HB_IR_X87_F2XM1,
    HB_IR_X87_FYL2X,
    HB_IR_X87_FPTAN,
    HB_IR_X87_FPATAN,
    HB_IR_X87_FXTRACT,
    HB_IR_X87_FPREM1,
    HB_IR_X87_FPREM,
    HB_IR_X87_FYL2XP1,
    HB_IR_X87_FSINCOS,
    HB_IR_X87_FSCALE,
    HB_IR_X87_FSIN,
    HB_IR_X87_FCOS,
    HB_IR_X87_FNCLEX,
    HB_IR_X87_FNINIT,
    /* Unordered FPU compares (gap matrix #8). FUCOM/FUCOMP set FPU SW C0/C2/C3
     * to 111 on NaN; FCOM/FCOMP do not. FCOMI/FCOMIP/FUCOMI/FUCOMIP additionally
     * write EFLAGS (ZF/PF/CF) from the comparison. The pop variants pop ST(0). */
    HB_IR_X87_FUCOM,
    HB_IR_X87_FUCOMP,
    HB_IR_X87_FCOMI,
    HB_IR_X87_FUCOMI,
    HB_IR_X87_FCOMIP,
    HB_IR_X87_FUCOMIP,
    /* D9 D0/E0/E1/E4 stack-top sign / abs / test (gap matrix #9). */
    HB_IR_X87_FNOP,   /* FNOP — FPU no-op (D9 D0). */
    HB_IR_X87_FCHS,   /* FCHS — complement sign of ST(0) (D9 E0). */
    HB_IR_X87_FABS,   /* FABS — clear sign of ST(0) (D9 E1). */
    HB_IR_X87_FTST,   /* FTST — compare ST(0) to +0.0, set C0/C2/C3 (D9 E4). */
    /* Legacy i386-only ops (removed in x64). */
    HB_IR_PUSHA,
    HB_IR_POPA,
    HB_IR_AAA,
    HB_IR_AAS,
    HB_IR_AAM,
    HB_IR_AAD,
    HB_IR_DAA,
    HB_IR_DAS,
    HB_IR_BOUND,
    HB_IR_ARPL,
    HB_IR_LDS, HB_IR_LES, HB_IR_LFS, HB_IR_LGS,
    HB_IR_HOST_CALL,
    HB_IR_FAULT,
    /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 350 — FISTTP.
     * В конец перечисления, а не в группу x87: так не сдвигаются значения соседей.
     * Отличие от FISTP одно и существенное: усечение К НУЛЮ независимо от режима
     * округления в управляющем слове (после FNINIT там 0x037F, то есть к ближайшему). */
    HB_IR_X87_FISTTP,
    HB_IR_X87_FBLD,     /* итерация 1047: загрузка упакованного BCD 80 бит */
    HB_IR_X87_FBSTP,    /* итерация 1047: запись упакованного BCD 80 бит со снятием */
    /* Итерация 520: EMMS — помечает все регистры x87 пустыми. Объявлено ПОСЛЕ `FISTTP`
     * намеренно: прослеживание FIP охватывает диапазон `FLD..FISTTP`, а замер эталона
     * показал, что на `emms` указатель последней команды НЕ обновляется. */
    HB_IR_X87_EMMS,
    /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 906 — семья `FI` (x87 с ЦЕЛЫМ операндом):
     * FIADD/FIMUL/FICOM/FICOMP/FISUB/FISUBR/FIDIV/FIDIVR. Вид действия едет вторым операндом
     * (`reg_op` 0..7), поэтому здесь одно значение, а не восемь. Объявлено В КОНЦЕ, чтобы не
     * сдвигать значения соседей, — но в отличие от `EMMS` эти команды указатель последней
     * команды x87 ОБНОВЛЯЮТ, поэтому внесены в `x87_updates_fip` поимённо. */
    HB_IR_X87_FI,
    /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1076 — регистр режима SSE, пара
     * «загрузить/выгрузить». Объявлено В КОНЦЕ по правилу этого файла (строка 216 и соседи):
     * значения операций попадают в СОХРАНЁННЫЕ записи кеша переводов, и вставка в середину
     * сдвинула бы всё, что ниже. Сначала я вставил рядом с `X87_FNSTCW` — ту же ошибку
     * поймал часом раньше в `hb_context.h`, значит правило надо читать ДО правки, а не после. */
    HB_IR_LDMXCSR,
    HB_IR_STMXCSR,
    /* Итерация 1080: образ таблицы дескрипторов (предел + база). В конце перечня — правило
     * этого файла: значения попадают в сохранённые записи кеша переводов. */
    HB_IR_SGDT,
    HB_IR_SIDT,
    /* 05.09.2026: XTEST — «внутри ли транзакции». Транзакции у нас ВСЕГДА отменяются на
     * XBEGIN (как у Intel с RTM_ALWAYS_ABORT), поэтому ответ один: ZF <- 1, а CF, OF, SF,
     * PF, AF <- 0 (SDM, XTEST). Отдельная операция, а не `TEST`/`CMP`: у любого нулевого
     * результата АЛУ PF=1, а XTEST обязан дать PF=0. XBEGIN отдельной операции не
     * получил — он поднимается как `MOV EAX, 0` + `JMP запасной_путь`, и оба
     * исполнителя берут его штатно. В конец перечисления — номера соседей не двигаем. */
    HB_IR_XTEST,
    HB_IR_UNSUPPORTED
} hb_ir_op_t;

typedef enum {
    HB_FENCE_ACQUIRE = 1,
    HB_FENCE_RELEASE = 2,
    HB_FENCE_FULL = 3
} hb_fence_kind_t;

/* Condition codes for SETcc, CMOVcc, Jcc */
typedef enum {
    HB_CC_E,   /* equal / zero */
    HB_CC_NE,  /* not equal */
    HB_CC_S,   /* sign */
    HB_CC_NS,  /* not sign */
    HB_CC_G,   /* greater (signed) */
    HB_CC_GE,  /* greater or equal (signed) */
    HB_CC_L,   /* less (signed) */
    HB_CC_LE,  /* less or equal (signed) */
    HB_CC_A,   /* above (unsigned) */
    HB_CC_AE,  /* above or equal (unsigned) */
    HB_CC_B,   /* below (unsigned) */
    HB_CC_BE,  /* below or equal (unsigned) */
    HB_CC_O,   /* overflow */
    HB_CC_NO,  /* not overflow */
    HB_CC_P,   /* parity */
    HB_CC_NP   /* not parity */
} hb_cc_t;

/* IR instruction */
/* Разметка поля `target` для EVEX. Жила в hb_interpreter.c, но с выпуском узких
 * чтений в XMM понадобилась и кодогенератору: он обязан пропустить команду с
 * маской приёмника в интерпретатор, а не записать регистр целиком. Дублировать
 * значения в двух файлах нельзя — разойдутся молча. */
#define HB_EVEX_TARGET_ARG_MASK   0x00ffffffu
#define HB_EVEX_TARGET_MASK_SHIFT 24
#define HB_EVEX_TARGET_ZERO_BIT   27
#define HB_EVEX_TARGET_PRESENT    (1u << 28)
#define HB_EVEX_ARG_BROADCAST     0x200u
#define HB_EVEX_ARG_ROUND_SHIFT   10
#define HB_EVEX_ARG_ROUND_MASK    0x1c00u

typedef struct hb_ir_instr {
    hb_ir_op_t op;
    hb_cc_t cc;           /* for SETcc, CMOVcc, Jcc */
    hb_ir_operand_t dst;
    hb_ir_operand_t src1;
    hb_ir_operand_t src2;
    uint64_t guest_addr;  /* original guest address */
    uint8_t guest_len;    /* original instruction length */
    uint8_t rep_prefix;   /* MacRunner 2026-08-12, итерация 490 — ПРЕФИКС ПОВТОРА У СТРОКОВЫХ.
                           * Сейчас `REP`/`REPNE` едет вторым ОПЕРАНДОМ (`hb_decode_x64.c:3057`,
                           * `set_imm(out, 2, 0xf2/0xf3, 1)`), и из-за этого описание операндов
                           * расходится с архитектурным: стенд ждёт память по [rsi]/[rdi], а
                           * получает регистр — 0 из 70 случаев семейства (замер 487).
                           * Поле заводится ОТДЕЛЬНО и заполняется ПАРАЛЛЕЛЬНО старому способу:
                           * пока его никто не читает, поведение не меняется. Переключение
                           * потребителей — следующим шагом, по одному, с проверкой стендом.
                           * 0 = нет префикса, 0xf2 = REPNE, 0xf3 = REP. */
    bool preserve_cf;     /* MacRunner 2026-08-12, итерация 389 — INC/DEC.
                           * Обе подняты обычными ADD/SUB (`hb_lift_x86.c:793`, то же в x64), а те
                           * пишут CF. Архитектура же требует у INC/DEC менять OF/SF/ZF/AF/PF и
                           * CF НЕ ТРОГАТЬ. Стенд ловил это как `dec … flag.cf expected=0 actual=1`,
                           * 3 случая из 9176. Флаг переводит запись отложенных флагов в вид,
                           * который CF не заявляет, и тогда бит остаётся прежним — тем же
                           * механизмом, которым чинили PUSHF. */
    bool zero_upper;      /* XMM partial load zeroes bytes above the loaded scalar */
    bool zero_ymm_upper;  /* 128-bit VEX destination zeroes upper YMM half */
    bool is_locked;       /* x86 LOCK prefix (0xF0) on a memory-RMW: full barrier semantics.
                           * Mono hazard-pointer loops use `lock or [rsp],r` purely as a fence;
                           * codegen must bracket the op with DMB ISH or it livelocks on ARM64. */
    uint64_t target;      /* branch target guest address */
    const char* comment;
} hb_ir_instr_t;

/* Basic block */
typedef struct hb_ir_block {
    uint64_t id;
    uint64_t guest_addr;  /* start guest address */
    hb_ir_instr_t* instrs;
    size_t instr_count;
    size_t instr_cap;
    struct hb_ir_block** succ;
    size_t succ_count;
    struct hb_ir_block** pred;
    size_t pred_count;
    /* MacRunner 2026-08-01 — memoised index of the first control-transfer instruction.
     *
     * hb_jit_runtime_run re-derived this with a linear scan on EVERY dispatched block, and the
     * profile put that scan at the top of the critical thread's self time. The answer is a pure
     * function of `instrs`, which never changes after translation, so it is computed once.
     *
     * -2 = not yet computed, -1 = no control-transfer instruction in this block, >=0 = index.
     * Blocks are created by hb_ir_block_create and only appended to during translation, so the
     * one place that must invalidate this is the append path. */
    int32_t first_transfer_idx;
} hb_ir_block_t;

/* Sentinels for hb_ir_block_t.first_transfer_idx. */
#define HB_IR_TRANSFER_UNCOMPUTED (-2)
#define HB_IR_TRANSFER_NONE       (-1)

/* Control-flow graph.
 * ★ ЭТО КОНТЕЙНЕР ВЫПУСКА (legacy), а не решатель: его `succ`/`pred` пусты всегда,
 * читать их для анализа флагов ЗАПРЕЩЕНО. Настоящий граф — `hb_cfg_analysis_t`. */
typedef struct {
    hb_ir_block_t** blocks;
    size_t block_count;
    size_t block_cap;
    hb_ir_block_t* entry;
    /* НЕВЛАДЕЮЩИЙ указатель на граф анализа той же единицы: владеет им `hb_ir_func_t`.
     * Нужен потому, что кодогенератор получает `cfg`, а не `func`; заводить второй
     * владелец времени жизни нельзя — освобождение шло бы дважды. */
    struct hb_cfg_analysis* acfg;
} hb_ir_cfg_t;

/* ═══════════════════════════════════════════════════════════════════════════════════
 * НАСТОЯЩИЙ ГРАФ АНАЛИЗА — лейн CFG, 07.09.2026
 *
 * ЗАЧЕМ ОТДЕЛЬНАЯ СТРУКТУРА, А НЕ `hb_ir_cfg_t`. Производственных вызовов
 * `hb_ir_cfg_add_edge` НЕТ ни одного (поиск по исходникам движка даёт
 * определение и комментарий, вызовы — только в пробах). То есть `succ`/`pred` у
 * `hb_ir_block_t` ПУСТЫ ВСЕГДА, и любой анализ, поставленный на них, был бы прибором
 * на пустой структуре. Это у нас УЖЕ БЫЛО — `hb_runtime.c:4223-4231` описывает ровно
 * такой ложный прибор: «сходящаяся сумма корзин не доказывала достижимость».
 *
 * ★ И переназначить смысл `hb_ir_cfg_t` нельзя без аудита потребителей: на нём держатся
 * выпуск (`hb_arm64_codegen_block_with_cfg`), поиск блока по адресу входа
 * (`hb_runtime.c` find_block), помощники и время жизни указателей. Поэтому старый
 * контейнер остаётся ЕДИНИЦЕЙ ВЫПУСКА, а здесь заводится ГРАФ АНАЛИЗА: его узлы —
 * НЕИЗМЕНЯЕМЫЕ диапазоны индексов того же массива команд, а дуги типизованы и несут
 * причину. Читать `succ`/`pred` для анализа флагов ЗАПРЕЩЕНО.
 *
 * ★★ ВИД ДУГИ И СОСТОЯНИЕ ЦЕЛИ — РАЗНЫЕ ВЕЩИ, и между ними нельзя ставить знак
 * равенства. «Известная цель», «известный summary» и «разрешение не публиковать flags»
 * — три независимых условия. Поэтому у дуги ДВА поля, а не одно.
 * ═══════════════════════════════════════════════════════════════════════════════════ */

/* ФОРМА выхода: что за команда его порождает. */
typedef enum {
    HB_CFG_E_FALL     = 0,  /* последовательное продолжение (провал условного перехода) */
    HB_CFG_E_TAKEN    = 1,  /* взятая ветвь условного перехода */
    HB_CFG_E_JUMP     = 2,  /* прямой безусловный переход */
    HB_CFG_E_TRANSFER = 3,  /* CALL/RET/косвенный/дальний/системный — консервативный выход */
    HB_CFG_E_END      = 4   /* конец разбора без terminator: окно/предел кончились */
} hb_cfg_edge_kind_t;

/* СОСТОЯНИЕ ЦЕЛИ: что мы про неё знаем. Никогда не путать с формой выхода. */
typedef enum {
    HB_CFG_T_KNOWN_LOCAL        = 0, /* начало ДЕЙСТВИТЕЛЬНО поднятой гостевой команды здесь */
    HB_CFG_T_UNKNOWN_NOT_LIFTED = 1, /* адрес попал в окно разбора, но команда не поднята */
    HB_CFG_T_UNKNOWN_OUTSIDE    = 2, /* адрес вне окна разбора */
    HB_CFG_T_UNKNOWN_TRANSFER   = 3, /* цель не выражена адресом (косвенный, RET, far, syscall) */
    HB_CFG_T_UNKNOWN_INCOMPLETE = 4  /* обрыв разбора, бюджет, ошибка построения */
} hb_cfg_target_state_t;

/* Причина наблюдения (observer): почему в этой точке состояние может быть прочитано
 * посторонним до того, как команда завершится. */
typedef enum {
    HB_CFG_OBS_MEM    = 0,  /* операнд в памяти гостя: отказ до commit */
    HB_CFG_OBS_HELPER = 1,  /* уход к помощнику по неописанному контракту */
    HB_CFG_OBS_TRAP   = 2   /* INT/INT3/системный выход */
} hb_cfg_obs_reason_t;

/* Гостевая команда: перепись «что ДЕЙСТВИТЕЛЬНО декодировано» и во что она развернулась.
 * Восстанавливать это по повторяющимся `guest_addr` НЕЛЬЗЯ: одна гостевая команда даёт
 * несколько IR-операций, а команда с ПУСТЫМ выхлопом иначе потерялась бы вовсе. */
typedef struct {
    uint64_t addr;
    uint64_t target;    /* цель прямого перехода, 0 если её нет */
    uint32_t ir_first;  /* индекс первой IR-команды; ir_count==0 -> позиция вставки */
    uint32_t ir_count;  /* 0 = гостевая команда не породила ни одной IR-операции */
    uint8_t  len;
    uint8_t  is_branch;
    uint8_t  is_cond;
    uint8_t  is_call;
    uint8_t  is_ret;
    uint8_t  has_target; /* прямая цель разрешена декодером */
} hb_cfg_guest_t;

/* Узел: НЕИЗМЕНЯЕМЫЙ диапазон индексов массива команд единицы. Резать только между
 * гостевыми командами, не внутри их развёртки. */
typedef struct {
    uint32_t ir_first;    /* включительно */
    uint32_t ir_end;      /* исключая */
    uint32_t g_first;     /* индекс в переписи гостевых команд, включительно */
    uint32_t g_end;       /* исключая */
    uint64_t guest_first; /* адрес первой гостевой команды узла */
    uint64_t guest_end;   /* адрес ЗА последней гостевой командой узла */
} hb_cfg_node_t;

typedef struct {
    uint32_t from;          /* индекс узла-источника */
    int32_t  to;            /* индекс узла-приёмника либо -1 (цель вне единицы/неизвестна) */
    uint32_t site_ir;       /* индекс IR-команды, породившей выход */
    uint64_t site_guest;    /* гостевой адрес этой команды */
    uint64_t target_guest;  /* гостевой адрес цели; 0 = адресом не выражена */
    uint8_t  kind;          /* hb_cfg_edge_kind_t */
    uint8_t  state;         /* hb_cfg_target_state_t */
} hb_cfg_edge_t;

typedef struct {
    uint32_t node;
    uint32_t ir;
    uint64_t guest;
    uint8_t  reason;        /* hb_cfg_obs_reason_t */
} hb_cfg_obs_t;

typedef struct hb_cfg_analysis {
    hb_cfg_guest_t* guest;  size_t guest_n, guest_cap;
    hb_cfg_node_t*  nodes;  size_t node_n,  node_cap;
    hb_cfg_edge_t*  edges;  size_t edge_n,  edge_cap;
    hb_cfg_obs_t*   obs;    size_t obs_n,   obs_cap;
    /* Обратный индекс: для узла j — сколько дуг в него входит. Полный список получается
     * обходом `edges`; здесь только счёт, потому что pred нужен решателю как ПРИЗНАК
     * («есть ли вход извне»), а не как список. */
    uint32_t*       pred_count; size_t pred_n;
    /* 0 = граф НЕПОЛОН, анализ пользоваться им НЕ ВПРАВЕ. Ошибка построения означает
     * «анализ недоступен», а не «граф с потерянной дугой». */
    int complete;
    const char* incomplete_reason;
    /* Число выходов по видам — для отчёта, считается ПО ПЕРЕПИСИ terminator'ов,
     * а не по уже построенному списку дуг. */
    uint32_t n_known_local, n_unknown_not_lifted, n_unknown_outside;
    uint32_t n_unknown_transfer, n_unknown_incomplete;
} hb_cfg_analysis_t;

/* IR function / translation unit */
typedef struct {
    uint64_t guest_addr;
    size_t guest_len;
    hb_ir_cfg_t* cfg;
    hb_ir_instr_t** flat_instrs; /* optional flat view */
    size_t flat_count;
    bool has_unsupported;
    const char* unsupported_reason;
    bool truncated;
    const char* truncation_reason;
    /* ★ Граф анализа. NULL, пока гейт MACRUNNER_HB_ANALYSIS_CFG не открыт. */
    hb_cfg_analysis_t* acfg;
} hb_ir_func_t;

/* IR builder */
typedef struct {
    hb_ir_func_t* func;
    hb_ir_block_t* current_block;
} hb_ir_builder_t;

/* IR API */
hb_ir_func_t* hb_ir_func_create(uint64_t guest_addr, size_t guest_len);
void hb_ir_func_destroy(hb_ir_func_t* func);

hb_ir_block_t* hb_ir_block_create(uint64_t id, uint64_t guest_addr);
void hb_ir_block_destroy(hb_ir_block_t* block);

hb_ir_cfg_t* hb_ir_cfg_create(void);
void hb_ir_cfg_destroy(hb_ir_cfg_t* cfg);
void hb_ir_cfg_add_block(hb_ir_cfg_t* cfg, hb_ir_block_t* block);
void hb_ir_cfg_add_edge(hb_ir_cfg_t* cfg, hb_ir_block_t* from, hb_ir_block_t* to);

/* ═══ ГРАФ АНАЛИЗА: перепись, построение, проверка ═══ (лейн CFG, 07.09.2026)
 *
 * Порядок обязателен: перепись ведётся ПО ХОДУ разбора (у обоих лифтеров, в уже
 * существующей точке `pre_instr`), построение зовётся ОДИН раз после окончания
 * разбора и ДО публикации IR. */
int  hb_cfg_analysis_enabled(void);
/* Перепись одной гостевой команды. `ir_count == 0` — команда без IR, её тоже заносим. */
void hb_cfg_ledger_note(hb_ir_func_t* func, uint64_t addr, unsigned len,
                        size_t ir_first, size_t ir_count,
                        int is_branch, int is_cond, int is_call, int is_ret,
                        int has_target, uint64_t target);
/* Построение. Возвращает 1, если граф ПОЛОН и им можно пользоваться. */
int  hb_cfg_build(hb_ir_func_t* func, const hb_ir_block_t* block);
void hb_cfg_analysis_destroy(hb_cfg_analysis_t* a);
/* Независимая проверка: разбиение покрывает массив ровно один раз, число альтернатив
 * у каждого terminator'а совпадает с ожидаемым ПО ПЕРЕПИСИ, дуги не дублируются,
 * счёт входов согласован. Возвращает 0 при первом же расхождении и пишет причину. */
int  hb_cfg_validate(const hb_cfg_analysis_t* a, const hb_ir_block_t* block,
                     const char** why);
/* Единая точка ответа «команда трогает память гостя», то есть может ОТКАЗАТЬ до commit.
 * Заведена здесь, чтобы у кодогенератора и у построителя графа не расползлись две копии
 * одного правила: такая пара уже находилась в этом дереве и расхождение не ловил ни один
 * счётчик. */
int  hb_ir_instr_touches_guest_memory(const hb_ir_instr_t* in);

hb_ir_builder_t* hb_ir_builder_create(hb_ir_func_t* func);
void hb_ir_builder_destroy(hb_ir_builder_t* b);
void hb_ir_builder_set_block(hb_ir_builder_t* b, hb_ir_block_t* block);

hb_ir_instr_t* hb_ir_emit(hb_ir_builder_t* b, hb_ir_op_t op);
hb_ir_instr_t* hb_ir_emit_mov(hb_ir_builder_t* b, hb_ir_operand_t dst, hb_ir_operand_t src);
hb_ir_instr_t* hb_ir_emit_lea(hb_ir_builder_t* b, hb_ir_operand_t dst, hb_ir_operand_t src);
hb_ir_instr_t* hb_ir_emit_binop(hb_ir_builder_t* b, hb_ir_op_t op, hb_ir_operand_t dst, hb_ir_operand_t a, hb_ir_operand_t b_op);
hb_ir_instr_t* hb_ir_emit_unop(hb_ir_builder_t* b, hb_ir_op_t op, hb_ir_operand_t dst, hb_ir_operand_t src);
hb_ir_instr_t* hb_ir_emit_load(hb_ir_builder_t* b, hb_ir_operand_t dst, hb_ir_operand_t addr);
hb_ir_instr_t* hb_ir_emit_store(hb_ir_builder_t* b, hb_ir_operand_t addr, hb_ir_operand_t src);
hb_ir_instr_t* hb_ir_emit_fence(hb_ir_builder_t* b, hb_fence_kind_t kind);
hb_ir_instr_t* hb_ir_emit_call(hb_ir_builder_t* b, uint64_t target);
hb_ir_instr_t* hb_ir_emit_ret(hb_ir_builder_t* b);
hb_ir_instr_t* hb_ir_emit_jmp(hb_ir_builder_t* b, uint64_t target);
hb_ir_instr_t* hb_ir_emit_jcc(hb_ir_builder_t* b, hb_cc_t cc, uint64_t target);
hb_ir_instr_t* hb_ir_emit_push(hb_ir_builder_t* b, hb_ir_operand_t src);
hb_ir_instr_t* hb_ir_emit_pop(hb_ir_builder_t* b, hb_ir_operand_t dst);
hb_ir_instr_t* hb_ir_emit_cmp(hb_ir_builder_t* b, hb_ir_operand_t a, hb_ir_operand_t b_op);
hb_ir_instr_t* hb_ir_emit_test(hb_ir_builder_t* b, hb_ir_operand_t a, hb_ir_operand_t b_op);
hb_ir_instr_t* hb_ir_emit_setcc(hb_ir_builder_t* b, hb_cc_t cc, hb_ir_operand_t dst);
hb_ir_instr_t* hb_ir_emit_cmovcc(hb_ir_builder_t* b, hb_cc_t cc, hb_ir_operand_t dst, hb_ir_operand_t src);
hb_ir_instr_t* hb_ir_emit_host_call(hb_ir_builder_t* b, uint32_t thunk_id);
hb_ir_instr_t* hb_ir_emit_fault(hb_ir_builder_t* b, hb_result_t reason, const char* msg);
/* Итерация 939: отказ ПО ПРИВИЛЕГИЯМ. Отдельный вход, потому что `hb_ir_emit_fault`
 * свой аргумент `reason` выбрасывал (`(void)reason;`) и все отказы были неразличимы. */
hb_ir_instr_t* hb_ir_emit_fault_priv(hb_ir_builder_t* b, const char* msg);
/* Итерация 1081: отказ по НЕДОПУСТИМОЙ команде (#UD). Отдельный вход по той же причине,
 * что и привилегированный: сторона wine выбирает доставку по виду отказа. */
hb_ir_instr_t* hb_ir_emit_fault_illegal(hb_ir_builder_t* b, const char* msg);
hb_ir_instr_t* hb_ir_emit_unsupported(hb_ir_builder_t* b, const char* feature, uint64_t guest_addr, uint8_t* bytes, size_t len);

/* Operand helpers */
hb_ir_operand_t hb_ir_reg(hb_reg_t reg, hb_size_t size);
hb_ir_operand_t hb_ir_imm(int64_t val, hb_size_t size);
hb_ir_operand_t hb_ir_mem(hb_reg_t base, hb_reg_t index, uint8_t scale, int64_t disp, hb_size_t size);
hb_ir_operand_t hb_ir_mem_segment(hb_reg_t base, hb_reg_t index, uint8_t scale,
                                  int64_t disp, hb_size_t size, uint8_t segment);
hb_ir_operand_t hb_ir_label(uint64_t id);
hb_ir_operand_t hb_ir_none(void);

/* Serialization */
char* hb_ir_func_to_json(const hb_ir_func_t* func);
char* hb_ir_func_to_string(const hb_ir_func_t* func);
hb_result_t hb_ir_func_validate(const hb_ir_func_t* func);

/* Register name helpers */
const char* hb_reg_name(hb_reg_t reg);
const char* hb_reg_x86_name(hb_reg_x86_t reg);

#ifdef __cplusplus
}
#endif

/* ★★★ ЕДИНИЦА 2026-08-24 — РЕЕСТР НАБЛЮДАВШИХСЯ ВХОДОВ.
 *
 * Слияние удлиняет единицу; если снаружи кто-то переходит на адрес ВНУТРИ неё, кеш
 * блоков (ключ — строго адрес входа) этого адреса не найдёт и переведёт хвост ВТОРОЙ раз.
 * Замер по кешу на диске: при глубине 4 внутрь единицы попадает от 31 до 62 % начал блоков.
 *
 * Лечение выбрано БЕЗ разбора переносимого состояния: лифтер не сливает ЧЕРЕЗ адрес,
 * который уже наблюдался как вход. Тогда единица никогда не накрывает чужой вход, и
 * вопрос «безопасен ли вход в середину» не возникает вовсе. Это приём FEX
 * (`AddBranchTarget` расщепляет блок по границе команды), перенесённый на кеш.
 *
 * Сходимость: первый переход на новый адрес всё равно даёт один дубль — узнать вход
 * заранее нельзя. Дальше адрес в реестре, и последующие трансляции режутся по нему;
 * с кешем на диске это сходится между прогонами. */
void hb_known_entry_note(uint64_t guest_addr);
int  hb_known_entry_is(uint64_t guest_addr);
void hb_known_entry_report(void);

/* ★ ЕДИНИЦА 04.09.2026 — ОДИН текст правила «внутренний ли переход слитой единицы»
 * на выпуск и на рантайм. Разбор и замер отказа — у определения в hb_ir.c.
 * Предел: таблица смещений выпуска рассчитана на столько команд. */
#define HB_EDINICA_MAX_INSTR 256u
int hb_edinica_target_index(const hb_ir_block_t* block, uint64_t tgt, size_t* out_i);
int hb_edinica_perehod_vnutrennij(const hb_ir_block_t* block, size_t i);

#endif
