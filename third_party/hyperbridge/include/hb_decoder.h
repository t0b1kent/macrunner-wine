#ifndef HB_DECODER_H
#define HB_DECODER_H

#include "hb_result.h"
#include "hb_context.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Decoded instruction */
typedef struct {
    uint64_t addr;        /* guest address */
    uint8_t len;          /* instruction length in bytes */
    uint8_t bytes[15];    /* raw instruction bytes */

    /* Mnemonic / op */
    enum {
        HB_INS_MOV, HB_INS_MOV_SEG, HB_INS_LEA, HB_INS_ADD, HB_INS_ADC, HB_INS_SUB, HB_INS_SBB,
        HB_INS_AND, HB_INS_OR, HB_INS_XOR, HB_INS_NOT, HB_INS_NEG,
        HB_INS_INC, HB_INS_DEC, HB_INS_MUL, HB_INS_IMUL, HB_INS_DIV, HB_INS_IDIV,
        HB_INS_BT, HB_INS_BTS, HB_INS_BTR, HB_INS_BTC,
        HB_INS_SHL, HB_INS_SHR, HB_INS_SAR, HB_INS_ROL, HB_INS_ROR, HB_INS_RCL, HB_INS_RCR,
        HB_INS_SHLD, HB_INS_SHRD,
        HB_INS_CMP, HB_INS_TEST, HB_INS_CMPXCHG, HB_INS_CMPXCHG8B, HB_INS_XCHG, HB_INS_XADD,
        HB_INS_PUSH, HB_INS_POP, HB_INS_PUSHF, HB_INS_POPF, HB_INS_PUSH_SEG, HB_INS_POP_SEG,
        HB_INS_CALL, HB_INS_RET, HB_INS_RETF, HB_INS_ENTER, HB_INS_INT, HB_INS_INT1,
        HB_INS_INT3, HB_INS_INTO, HB_INS_IRET, HB_INS_JMP, HB_INS_Jcc, HB_INS_LOOP, HB_INS_JRCXZ,
        HB_INS_SETcc, HB_INS_CMOVcc,
        HB_INS_MOVZX, HB_INS_MOVSX, HB_INS_MOVSXD,
        HB_INS_CDQE, HB_INS_CWDE, HB_INS_CWD, HB_INS_LEAVE, HB_INS_LAHF, HB_INS_SAHF, HB_INS_CPUID, HB_INS_MMX_MOV, HB_INS_MMX_AND, HB_INS_MMX_ANDN, HB_INS_MMX_OR, HB_INS_MMX_XOR, HB_INS_MMX_SRL, HB_INS_MMX_SRA, HB_INS_MMX_SLL, HB_INS_XGETBV, HB_INS_RDTSC, HB_INS_RDTSCP, HB_INS_PRIV, HB_INS_VERR, HB_INS_VERW, HB_INS_NOP, HB_INS_FENCE,
        HB_INS_RDRAND, HB_INS_RDSEED,
        HB_INS_MOVS, HB_INS_CMPS, HB_INS_LODS, HB_INS_SCAS, HB_INS_STOS,
        HB_INS_INS, HB_INS_OUTS, HB_INS_IN, HB_INS_OUT, HB_INS_XLAT, HB_INS_SALC,
        HB_INS_CLC, HB_INS_STC, HB_INS_CMC, HB_INS_CLD, HB_INS_STD, HB_INS_CLI, HB_INS_STI,
        HB_INS_HLT,
        /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1063 — ДАЛЬНИЕ ПЕРЕХОДЫ ЧЕРЕЗ ПАМЯТЬ.
         * `FF /3` (call m16:32) и `FF /5` (jmp m16:32) — 9 из 18 пробелов доски x86-32.
         * Своё имя, а не общий `HB_INS_SYS`: доска мерит, УЗНАЁМ ли мы команду, и общий
         * ярлык «семантика отказана» на этот вопрос отвечает «нет». Смена сегмента кода
         * нами не моделируется, поэтому исполнение — честный отказ (случая в лифтере нет). */
        HB_INS_CALL_FAR_MEM, HB_INS_JMP_FAR_MEM,
        HB_INS_CALL_FAR_IMM, HB_INS_JMP_FAR_IMM,
        HB_INS_SYS_PRIV,
        HB_INS_UNAVAILABLE_EXT,
        /* Итерация 1075: `0F AE /2` и `/3` — загрузка и выгрузка регистра режима SSE. */
        HB_INS_LDMXCSR, HB_INS_STMXCSR,
        /* Итерация 1080: `0F 01 /0` и `/1` — выгрузка образа таблицы дескрипторов.
         * Законны в ПОЛЬЗОВАТЕЛЬСКОМ режиме, поэтому отказ на них убивает гостя. */
        HB_INS_SGDT, HB_INS_SIDT,
        /* MacRunner 2026-08-16, лейн ЛЕСТНИЦА, итерация 1095 — ПРИВИЛЕГИРОВАННЫЕ ПОИМЁННО.
         * `LLDT`, `LTR`, `LGDT`, `LIDT`, `LMSW`, `INVLPG` разбирались общим ярлыком
         * `HB_INS_PRIV`. Отказ при этом ВЕРЕН (все требуют CPL 0), но доска мерит, УЗНАЁМ ли
         * мы команду, и общий ярлык отвечает «нет» — та же причина, по которой в 1063 не стал
         * приравнивать `HB_INS_SYS` к `jmp`. Семантика не меняется: все шесть поднимают тот же
         * привилегированный отказ. */
        HB_INS_LLDT, HB_INS_LTR, HB_INS_LGDT, HB_INS_LIDT, HB_INS_LMSW, HB_INS_INVLPG,
        HB_INS_MOV_CR, HB_INS_MOV_DR,
        HB_INS_BSF, HB_INS_TZCNT, HB_INS_LZCNT, HB_INS_POPCNT,
        HB_INS_BSR, HB_INS_BSWAP, HB_INS_MOVBE, HB_INS_MOVDIRI, HB_INS_MOVDIR64B, HB_INS_CRC32,
        HB_INS_ANDN, HB_INS_BEXTR, HB_INS_BLSI, HB_INS_BLSMSK, HB_INS_BLSR,
        HB_INS_BZHI, HB_INS_MULX, HB_INS_PDEP, HB_INS_PEXT,
        HB_INS_RORX, HB_INS_SARX, HB_INS_SHLX, HB_INS_SHRX,
        HB_INS_ADCX, HB_INS_ADOX, HB_INS_SSE_MOV, HB_INS_MOVNTDQA,
        HB_INS_MOVHLPS, HB_INS_MOVLHPS, HB_INS_VMOVHLPS, HB_INS_VMOVLHPS,
        HB_INS_VMOVLPS, HB_INS_VMOVHPS, HB_INS_VMOVLPD, HB_INS_VMOVHPD,
        HB_INS_MOVHPS, HB_INS_MOVHPD,
        HB_INS_XMM_AND, HB_INS_XMM_ANDN, HB_INS_XMM_OR, HB_INS_XORPS, HB_INS_PXOR,
        HB_INS_PCMPEQB, HB_INS_PCMPEQW, HB_INS_PCMPEQD,
        HB_INS_PCMPGTB, HB_INS_PCMPGTW, HB_INS_PCMPGTD,
        HB_INS_PMOVMSKB, HB_INS_MOVMSKPS, HB_INS_MOVMSKPD,
        HB_INS_VTESTPS, HB_INS_VTESTPD,
        HB_INS_UNPCKLPS, HB_INS_UNPCKLPD, HB_INS_UNPCKHPS, HB_INS_UNPCKHPD,
        HB_INS_PUNPCKLBW, HB_INS_PUNPCKLWD, HB_INS_PUNPCKLDQ, HB_INS_PUNPCKLQDQ,
        HB_INS_PUNPCKHBW, HB_INS_PUNPCKHWD, HB_INS_PUNPCKHDQ, HB_INS_PUNPCKHQDQ,
        HB_INS_PACKSSWB, HB_INS_PACKUSWB, HB_INS_PACKSSDW,
        HB_INS_PMULLW, HB_INS_PMULHW, HB_INS_PMULHUW, HB_INS_PMADDWD,
        HB_INS_PADDSB, HB_INS_PADDSW, HB_INS_PADDUSB, HB_INS_PADDUSW,
        HB_INS_PAVGB, HB_INS_PAVGW, HB_INS_PSHUFB, HB_INS_PINSRW, HB_INS_PEXTRW,
        HB_INS_PINSRB, HB_INS_PINSRD, HB_INS_PINSRQ,
        HB_INS_PEXTRB, HB_INS_PEXTRD, HB_INS_PEXTRQ,
        HB_INS_EXTRACTPS, HB_INS_INSERTPS,
        HB_INS_PSHUFD, HB_INS_PSHUFLW, HB_INS_PSHUFHW,
        /* Итерация 883: MMX-перестановка слов `PSHUFW mm, mm/m64, imm8` — отдельный опкод.
         * `PSHUFD` не подходит: там 128 бит и ДВОЙНЫЕ слова, здесь 64 бита и слова. */
        HB_INS_PSHUFW,
        HB_INS_SHUFPS, HB_INS_SHUFPD,
        HB_INS_PSRLW, HB_INS_PSRAW, HB_INS_PSLLW,
        HB_INS_PSRLD, HB_INS_PSRAD, HB_INS_PSLLD,
        HB_INS_PSRLQ, HB_INS_PSLLQ, HB_INS_PSRLDQ, HB_INS_PSLLDQ,
        HB_INS_PSUBUSB, HB_INS_PSUBUSW, HB_INS_PSUBSB, HB_INS_PSUBSW,
        HB_INS_PMINUB, HB_INS_PMINSW, HB_INS_PMAXUB, HB_INS_PMAXSW,
        HB_INS_PMULUDQ, HB_INS_PSADBW, HB_INS_MPSADBW, HB_INS_VMPSADBW,
        HB_INS_PHADDW, HB_INS_PHADDD, HB_INS_PHADDSW,
        HB_INS_PHSUBW, HB_INS_PHSUBD, HB_INS_PHSUBSW,
        HB_INS_PMADDUBSW, HB_INS_PSIGNB, HB_INS_PSIGNW, HB_INS_PSIGND,
        HB_INS_PMULHRSW, HB_INS_PABSB, HB_INS_PABSW, HB_INS_PABSD,
        HB_INS_PTEST,
        HB_INS_PMOVSXBW, HB_INS_PMOVSXBD, HB_INS_PMOVSXBQ,
        HB_INS_PMOVSXWD, HB_INS_PMOVSXWQ, HB_INS_PMOVSXDQ,
        HB_INS_PMULDQ, HB_INS_PCMPEQQ, HB_INS_PACKUSDW,
        HB_INS_PMOVZXBW, HB_INS_PMOVZXBD, HB_INS_PMOVZXBQ,
        HB_INS_PMOVZXWD, HB_INS_PMOVZXWQ, HB_INS_PMOVZXDQ,
        HB_INS_PCMPGTQ, HB_INS_PMINSB, HB_INS_PMINSD, HB_INS_PMINUW,
        HB_INS_PMINUD, HB_INS_PMAXSB, HB_INS_PMAXSD, HB_INS_PMAXUW,
        HB_INS_PMAXUD, HB_INS_PMULLD, HB_INS_PHMINPOSUW,
        HB_INS_PALIGNR, HB_INS_PBLENDW, HB_INS_BLENDPS, HB_INS_BLENDPD,
        HB_INS_PBLENDVB, HB_INS_BLENDVPS, HB_INS_BLENDVPD, HB_INS_VZEROUPPER,
        /* VZEROALL — ОТДЕЛЬНАЯ команда, а не VZEROUPPER с другим L.
         * `C5 FC 77` (L=1) обнуляет регистры ЦЕЛИКОМ, `C5 F8 77` (L=0) — только
         * старшие половины. Обе сводились к VZEROUPPER, и xmm0…xmm15 оставались
         * нетронутыми (замерено оракулом: 16 разошедшихся регистров на форму). */
        HB_INS_VZEROALL,
        /* RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE (F3 0F AE /0../3, только длинный
         * режим). Разбирались в общую корзину HB_INS_SYS, которую лифтер не
         * берёт, — восемь форм отказывали подъёмом. База сегмента у нас есть
         * настоящая (`ctx->fs_base`/`gs_base`), и через неё гость читает TEB. */
        HB_INS_RDFSBASE, HB_INS_RDGSBASE, HB_INS_WRFSBASE, HB_INS_WRGSBASE,
        HB_INS_VPBROADCASTB, HB_INS_VPBROADCASTW, HB_INS_VPBROADCASTD,
        HB_INS_VPBROADCASTQ,
        HB_INS_VBROADCASTSS, HB_INS_VBROADCASTSD,
        HB_INS_VBROADCASTF32X2, HB_INS_VBROADCASTF64X2,
        HB_INS_VBROADCASTF32X4, HB_INS_VBROADCASTF64X4,
        HB_INS_VBROADCASTF32X8, HB_INS_VBROADCASTI32X2,
        HB_INS_VBROADCASTI128,
        HB_INS_VPBLENDD, HB_INS_VPERMQ, HB_INS_VPERMPD,
        HB_INS_VPERMILPS, HB_INS_VPERMILPD,
        HB_INS_VBLENDVPS, HB_INS_VBLENDVPD, HB_INS_VPBLENDVB,
        HB_INS_VINSERTF128, HB_INS_VINSERTI128,
        HB_INS_VEXTRACTF128, HB_INS_VEXTRACTI128,
        HB_INS_VPERM2F128, HB_INS_VPERM2I128,
        HB_INS_VPSRLVD, HB_INS_VPSRLVQ, HB_INS_VPSRAVD,
        HB_INS_VPSLLVD, HB_INS_VPSLLVQ,
        HB_INS_PCLMULQDQ, HB_INS_AESKEYGENASSIST, HB_INS_VPCLMULQDQ,
        HB_INS_AESIMC, HB_INS_AESENC, HB_INS_AESENCLAST, HB_INS_AESDEC, HB_INS_AESDECLAST,
        HB_INS_VAESENC, HB_INS_VAESENCLAST, HB_INS_VAESDEC, HB_INS_VAESDECLAST,
        HB_INS_GF2P8MULB, HB_INS_VGF2P8MULB,
        HB_INS_GF2P8AFFINEQB, HB_INS_GF2P8AFFINEINVQB,
        HB_INS_VGF2P8AFFINEQB, HB_INS_VGF2P8AFFINEINVQB,
        HB_INS_VPERMD, HB_INS_VPERMPS,
        HB_INS_VMASKMOVPS, HB_INS_VMASKMOVPD, HB_INS_VMASKMOVDQU,
        HB_INS_VPMASKMOVD, HB_INS_VPMASKMOVQ,
        HB_INS_VGATHERDPS, HB_INS_VGATHERDPD, HB_INS_VGATHERQPS, HB_INS_VGATHERQPD,
        HB_INS_VPGATHERDD, HB_INS_VPGATHERDQ, HB_INS_VPGATHERQD, HB_INS_VPGATHERQQ,
        HB_INS_PCMPESTRM, HB_INS_PCMPESTRI, HB_INS_PCMPISTRM, HB_INS_PCMPISTRI,
        /* SHA extensions (Intel SHA-NI: 0F 38 C8..CF, 0F 38 D0..D6, 0F 3A CC). */
        HB_INS_SHA1NEXTE, HB_INS_SHA1MSG1, HB_INS_SHA1MSG2,
        HB_INS_SHA256RNDS2, HB_INS_SHA256MSG1, HB_INS_SHA256MSG2,
        HB_INS_SHA1RNDS4,
        HB_INS_MOVD, HB_INS_CVTDQ2PD, HB_INS_CVTDQ2PS, HB_INS_CVTPS2DQ, HB_INS_CVTTPS2DQ,
        HB_INS_CVTPS2PD, HB_INS_CVTPD2PS, HB_INS_CVTPD2DQ, HB_INS_CVTTPD2DQ,
        HB_INS_CVTSS2SD, HB_INS_CVTSD2SS,
        HB_INS_CVTSI2SD, HB_INS_CVTSI2SS,
        HB_INS_SQRTPS, HB_INS_SQRTPD, HB_INS_SQRTSS, HB_INS_SQRTSD,
        HB_INS_RSQRTPS, HB_INS_RSQRTSS, HB_INS_RCPPS, HB_INS_RCPSS,
        HB_INS_ROUNDPS, HB_INS_ROUNDPD, HB_INS_ROUNDSS, HB_INS_ROUNDSD,
        HB_INS_DPPS, HB_INS_DPPD,
        HB_INS_ADDPS, HB_INS_ADDPD, HB_INS_ADDSS, HB_INS_ADDSD,
        HB_INS_SUBPS, HB_INS_SUBPD, HB_INS_SUBSS, HB_INS_SUBSD,
        HB_INS_MULPS, HB_INS_MULPD, HB_INS_DIVPS, HB_INS_DIVPD,
        HB_INS_DIVSD, HB_INS_MULSD,
        HB_INS_DIVSS, HB_INS_MULSS,
        HB_INS_MINPS, HB_INS_MAXPS, HB_INS_MINPD, HB_INS_MAXPD,
        HB_INS_MINSS, HB_INS_MAXSS, HB_INS_MINSD, HB_INS_MAXSD,
        HB_INS_CMPPS, HB_INS_CMPPD, HB_INS_CMPSS, HB_INS_CMPSD,
        HB_INS_CVTPI2PS, HB_INS_CVTPI2PD, HB_INS_CVTPS2PI, HB_INS_CVTPD2PI,
        HB_INS_CVTTPS2PI, HB_INS_CVTTPD2PI,
        HB_INS_HADDPS, HB_INS_HADDPD, HB_INS_HSUBPS, HB_INS_HSUBPD,
        HB_INS_ADDSUBPS, HB_INS_ADDSUBPD,
        HB_INS_MOVDDUP, HB_INS_MOVSLDUP, HB_INS_MOVSHDUP,
        HB_INS_MOVQ2DQ, HB_INS_MOVDQ2Q,
        HB_INS_MASKMOVQ, HB_INS_MASKMOVDQU,
        HB_INS_VFMADD132PS, HB_INS_VFMADD132PD, HB_INS_VFMADD132SS, HB_INS_VFMADD132SD,
        HB_INS_VFMADD213PS, HB_INS_VFMADD213PD, HB_INS_VFMADD213SS, HB_INS_VFMADD213SD,
        HB_INS_VFMADD231PS, HB_INS_VFMADD231PD, HB_INS_VFMADD231SS, HB_INS_VFMADD231SD,
        HB_INS_VFMSUB132PS, HB_INS_VFMSUB132PD, HB_INS_VFMSUB132SS, HB_INS_VFMSUB132SD,
        HB_INS_VFMSUB213PS, HB_INS_VFMSUB213PD, HB_INS_VFMSUB213SS, HB_INS_VFMSUB213SD,
        HB_INS_VFMSUB231PS, HB_INS_VFMSUB231PD, HB_INS_VFMSUB231SS, HB_INS_VFMSUB231SD,
        HB_INS_VFMADDSUB132PS, HB_INS_VFMADDSUB132PD, HB_INS_VFMSUBADD132PS, HB_INS_VFMSUBADD132PD,
        HB_INS_VFMADDSUB213PS, HB_INS_VFMADDSUB213PD, HB_INS_VFMSUBADD213PS, HB_INS_VFMSUBADD213PD,
        HB_INS_VFMADDSUB231PS, HB_INS_VFMADDSUB231PD, HB_INS_VFMSUBADD231PS, HB_INS_VFMSUBADD231PD,
        HB_INS_VFNMADD132PS, HB_INS_VFNMADD132PD, HB_INS_VFNMADD132SS, HB_INS_VFNMADD132SD,
        HB_INS_VFNMSUB132PS, HB_INS_VFNMSUB132PD, HB_INS_VFNMSUB132SS, HB_INS_VFNMSUB132SD,
        HB_INS_VFNMADD213PS, HB_INS_VFNMADD213PD, HB_INS_VFNMADD213SS, HB_INS_VFNMADD213SD,
        HB_INS_VFNMSUB213PS, HB_INS_VFNMSUB213PD, HB_INS_VFNMSUB213SS, HB_INS_VFNMSUB213SD,
        HB_INS_VFNMADD231PS, HB_INS_VFNMADD231PD, HB_INS_VFNMADD231SS, HB_INS_VFNMADD231SD,
        HB_INS_VFNMSUB231PS, HB_INS_VFNMSUB231PD, HB_INS_VFNMSUB231SS, HB_INS_VFNMSUB231SD,
        HB_INS_VCVTPH2PS, HB_INS_VCVTPS2PH,
        HB_INS_VCMPPS, HB_INS_VCMPPD, HB_INS_VCMPSS, HB_INS_VCMPSD,
        HB_INS_VHADDPS, HB_INS_VHADDPD, HB_INS_VHSUBPS, HB_INS_VHSUBPD,
        HB_INS_VADDSUBPS, HB_INS_VADDSUBPD,
        HB_INS_VMOVSLDUP, HB_INS_VMOVSHDUP, HB_INS_VMOVDDUP,
        HB_INS_COMISS, HB_INS_COMISD,
        HB_INS_CVTSD2SI, HB_INS_CVTSS2SI, HB_INS_CVTTSD2SI, HB_INS_CVTTSS2SI,
        /* AVX-512: преобразование скаляра в БЕЗЗНАКОВОЕ целое с усечением.
         * Отдельные команды, а не разновидность знаковых: у них другой
         * диапазон и другое «неопределённое» значение при выходе за него. */
        HB_INS_VCVTTSS2USI, HB_INS_VCVTTSD2USI,
        HB_INS_PADDB, HB_INS_PADDW, HB_INS_PADDD, HB_INS_PADDQ,
        HB_INS_PSUBB, HB_INS_PSUBW, HB_INS_PSUBD, HB_INS_PSUBQ,
        HB_INS_X87_FLD, HB_INS_X87_FST, HB_INS_X87_FSTP, HB_INS_X87_FILD, HB_INS_X87_FISTP,
        HB_INS_X87_FIST, HB_INS_X87_FISTTP,
        /* итерация 1047: упакованный BCD 80 бит, DF /4 и DF /6 */
        HB_INS_X87_FBLD, HB_INS_X87_FBSTP, HB_INS_X87_FI, HB_INS_X87_EMMS,   /* итерация 520 */
        HB_INS_X87_FLDCW, HB_INS_X87_FNSTCW, HB_INS_X87_FNSTSW,
        HB_INS_X87_FLDENV, HB_INS_X87_FNSTENV, HB_INS_X87_FRSTOR, HB_INS_X87_FNSAVE,
        HB_INS_X87_FXSAVE, HB_INS_X87_FXRSTOR,
        HB_INS_X87_FADD, HB_INS_X87_FMUL, HB_INS_X87_FCOM, HB_INS_X87_FCOMP,
        HB_INS_X87_FSUB, HB_INS_X87_FSUBR, HB_INS_X87_FDIV, HB_INS_X87_FDIVR,
        HB_INS_X87_FADDP, HB_INS_X87_FMULP, HB_INS_X87_FCOMPP,
        HB_INS_X87_FSUBP, HB_INS_X87_FSUBRP, HB_INS_X87_FDIVP, HB_INS_X87_FDIVRP,
        HB_INS_X87_FXCH, HB_INS_X87_FRNDINT, HB_INS_X87_FNCLEX, HB_INS_X87_FNINIT,
        HB_INS_X87_FINCSTP, HB_INS_X87_FDECSTP, HB_INS_X87_FXAM, HB_INS_X87_FSQRT,
        /* D9 F0-FF transcendentals (gap matrix #6, libm-backed). */
        HB_INS_X87_F2XM1, HB_INS_X87_FYL2X, HB_INS_X87_FPTAN, HB_INS_X87_FPATAN,
        HB_INS_X87_FXTRACT, HB_INS_X87_FPREM1, HB_INS_X87_FPREM, HB_INS_X87_FYL2XP1,
        HB_INS_X87_FSINCOS, HB_INS_X87_FSCALE, HB_INS_X87_FSIN, HB_INS_X87_FCOS,
        HB_INS_X87_FFREE, HB_INS_X87_FFREEP,
        HB_INS_X87_FCMOV, HB_INS_X87_FCOMI, HB_INS_X87_FUCOMI, HB_INS_X87_FCOMPI,
        HB_INS_X87_FUCOMPI, HB_INS_X87_FUCOM, HB_INS_X87_FUCOMP,
        /* D9 D0/E0/E1/E4 — stack-top sign / abs / test. Split out from MISC
         * so the lifter can dispatch each to its proper IR op. */
        HB_INS_X87_FNOP, HB_INS_X87_FCHS, HB_INS_X87_FABS, HB_INS_X87_FTST,
        HB_INS_X87_MISC,
        /* Legacy i386-only opcodes (removed in x64). */
        HB_INS_PUSHA, HB_INS_POPA,
        HB_INS_AAA, HB_INS_AAS, HB_INS_AAM, HB_INS_AAD, HB_INS_DAA, HB_INS_DAS,
        HB_INS_BOUND, HB_INS_ARPL, HB_INS_LDS, HB_INS_LES, HB_INS_LFS, HB_INS_LGS,
        /* 04.09.2026: вскрыты ПОЧИНЕННЫМ прибором. Пока он подавал один байт
         * modrm на все случаи, список пробелов печатался ПУСТЫМ. */
        HB_INS_LSS, HB_INS_MOVNTI, HB_INS_MOVNTQ, HB_INS_XABORT, HB_INS_XBEGIN,
        HB_INS_LDDQU, HB_INS_PTWRITE, HB_INS_MOVNTSS, HB_INS_MOVNTSD,
        HB_INS_TDNOW,   /* 3DNow!: семья задаётся непосредственным байтом */
        HB_INS_SYS, HB_INS_UD, HB_INS_MMX, HB_INS_VEC,
        /* 05.09.2026: XEND (0F 01 D5) и XTEST (0F 01 D6) — транзакционная память.
         * До этого оба проваливались в разбор группы 7 «по членам» (reg=2 -> LGDT на
         * x64, PRIV на i386) и давали гостю отказ по ПРИВИЛЕГИИ на командах кольца 3.
         * В КОНЕЦ перечисления намеренно: номера соседей (SYS=628 и прочие) стоят в
         * журналах и отчётах, сдвигать их незачем. */
        HB_INS_XEND, HB_INS_XTEST,
        HB_INS_UNKNOWN,
        HB_INS_UNSUPPORTED
    } opcode;

    /* Condition for SETcc/CMOVcc/Jcc */
    enum {
        HB_COND_NONE = 0,
        HB_COND_E, HB_COND_NE, HB_COND_S, HB_COND_NS,
        HB_COND_G, HB_COND_GE, HB_COND_L, HB_COND_LE,
        HB_COND_A, HB_COND_AE, HB_COND_B, HB_COND_BE,
        HB_COND_O, HB_COND_NO, HB_COND_P, HB_COND_NP,
        HB_COND_C, HB_COND_NC
    } cond;

    /* Operands */
    struct {
        bool present;
        bool is_reg;
        bool is_mem;
        bool is_imm;
        int reg;      /* register index or -1 */
        uint8_t reg_offset; /* byte offset for legacy AH/CH/DH/BH register aliases */
        int64_t imm;
        struct {
            int base;   /* -1 if none */
            int index;  /* -1 if none */
            uint8_t scale;
            int64_t disp;
            bool rip_relative;
            uint64_t rip_target; /* resolved RIP-relative */
            uint8_t segment;     /* legacy segment prefix: 0 none, 0x64 FS, 0x65 GS */
            bool addr32;          /* x86-64 address-size override (0x67): 32-bit effective address */
            bool addr16;          /* i386 0x67: 16-битная адресация, адрес усечь до 0xFFFF */
            bool vsib;            /* AVX gather VSIB: index names an XMM/YMM vector register */
            uint8_t vsib_index_size;
            uint8_t vsib_elem_size;
            uint8_t vsib_count;
        } mem;
        uint8_t size; /* operand size in bytes */
    } op1, op2, op3;

    /* REX prefix info */
    bool has_rex;
    uint8_t rex_w;
    uint8_t rex_r;
    uint8_t rex_x;
    uint8_t rex_b;
    uint8_t segment_prefix; /* 0 нет; 0x26 ES, 0x2e CS, 0x36 SS, 0x3e DS, 0x64 FS, 0x65 GS */
    bool address32_prefix;  /* 0x67 address-size override */
    uint8_t rep_prefix;     /* Итерация 490: префикс повтора у строковых, отдельно от операндов.
                             * 0 нет, 0xf2 REPNE, 0xf3 REP. Заполняется ПАРАЛЛЕЛЬНО прежнему
                             * способу (префикс вторым операндом), потребителей пока нет. */
    bool lock_prefix;       /* 0xF0 LOCK: memory-RMW is a full barrier (Mono hazard-ptr fence) */

    /* ModRM/SIB info */
    bool has_modrm;
    uint8_t mod;
    uint8_t reg_op;
    uint8_t rm;
    bool has_sib;
    uint8_t sib_scale;
    uint8_t sib_index;
    uint8_t sib_base;

    /* Flags affected */
    bool writes_flags;
    bool reads_flags;

    /* Branch info */
    bool is_branch;
    bool is_call;
    bool is_ret;
    bool is_conditional;
    uint64_t branch_target; /* relative target resolved */
    uint16_t ret_imm;       /* ret N */

    /* Stack info */
    int stack_delta; /* bytes pushed (+) or popped (-) */

    /* Extra immediate for VEX/EVEX forms whose three decoded operands are all used. */
    bool has_imm8;
    uint8_t imm8;

    /* EVEX write-mask metadata for interpreter AVX-512 semantics. */
    bool evex;
    uint8_t evex_mask;
    bool evex_zero;
    bool evex_broadcast;
    uint8_t evex_rounding;
    uint8_t evex_mask_lane;

} hb_decoded_t;

/* Decoder state */
typedef struct {
    hb_arch_t arch;
    const uint8_t* code;
    size_t code_len;
    uint64_t base_addr;
    size_t pos;
} hb_decoder_t;

hb_decoder_t* hb_decoder_create(hb_arch_t arch, const uint8_t* code, size_t code_len, uint64_t base_addr);
void hb_decoder_destroy(hb_decoder_t* d);

hb_result_t hb_decode_next(hb_decoder_t* d, hb_decoded_t* out);
hb_result_t hb_decode_at(hb_decoder_t* d, size_t offset, hb_decoded_t* out);

/* x64 specific */
hb_result_t hb_decode_x64(const uint8_t* code, size_t len, uint64_t addr, hb_decoded_t* out);

/* x86 specific */
hb_result_t hb_decode_x86(const uint8_t* code, size_t len, uint64_t addr, hb_decoded_t* out);

/* Utility */
int hb_reg_index_from_modrm(uint8_t modrm, bool rex_r, bool is_64bit);
int hb_rm_index_from_modrm(uint8_t modrm, bool rex_b, bool is_64bit);
const char* hb_opcode_name(int opcode);
const char* hb_cond_name(int cond);

#ifdef __cplusplus
}
#endif

#endif
