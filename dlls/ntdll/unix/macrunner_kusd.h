/*
 * MacRunner 08.09.2026 — ЗАПЛАТКА KUSER_SHARED_DATA (лейн ЗАПЛАТКА).
 *
 * ЧТО ЛЕЧИТ. macOS требует жёсткий __PAGEZERO 4 ГБ для CPU_TYPE_ARM64
 * (bsd/kern/mach_loader.c:897-901), поэтому канонический адрес Windows
 * 0x7FFE0000 нам не отобразить, и KUSER_SHARED_DATA живёт выше.
 * Всё, что идёт через наш код, мы переносим. Не переносится ровно одно —
 * ЗАШИТОЕ чтение низкого адреса в стартовом коде MSVC-CRT:
 *
 *     D2AFFFD0  movz x16, #0x7ffe, lsl #16     ; KUSER_SHARED_DATA
 *     394A5A10  ldrb w16, [x16, #0x296]        ; ProcessorFeatures[0x22]
 *
 * Узор найден у 16 ARM64-PE из 19 020 просмотренных: все 7 модулей
 * Notepad++ 8.9.5, штатный apphost .NET 8 win-arm64, собственные двоичные
 * Microsoft Prism. Наших — 0 из 14 214 (мы собираем clang'ом, узор от MSVC).
 *
 * ЧЕМ ЛЕЧИМ. 0x00007FFE00000000 выразим ТЕМ ЖЕ movz — поле hw = 2 вместо 1.
 * Значит при отказе достаточно переписать ЧЕТЫРЕ БАЙТА на месте, и дальше
 * гость читает верный адрес без всякого перехвата. Отказ по каждому МЕСТУ
 * случается один раз.
 *
 * ЧЕМ ЭТО ОПАСНО И ЧТО ЗАЩИЩАЕТ. Тот же байтовый узор бывает у ПЕРЕМЕЩАЕМОГО
 * обращения: movz грузит 0x7FFE0000 как СМЕЩЕНИЕ, которое потом складывается
 * с базой (`add x1,x26,x8` — шесть таких мест в ARM64EC ntoskrnl.exe). Правка
 * такого места сломала бы работающий код, и сломала бы МОЛЧА.
 *
 * Поэтому решение принимается по ЧЕТЫРЁМ признакам сразу, и все четыре
 * проверяются здесь, в одном месте, которое включают и движок, и стенд:
 *
 *   1. адрес отказа лежит в низком каноническом окне KUSD;
 *   2. команда по pc-4 — ровно `movz Xd,#0x7ffe,lsl#16` по битовому узору;
 *   3. регистр Xd В КОНТЕКСТЕ ОТКАЗА равен 0x7FFE0000 — то есть значение
 *      movz дожило до обращения и не было ни к чему прибавлено;
 *   4. адрес отказа отстоит от Xd меньше чем на окно — то есть обращение
 *      шло ИМЕННО от этого регистра.
 *
 * Признак 3 и есть защита от перемещаемой формы: там база в другом регистре,
 * а сам отказ пришёл бы по base+0x7FFE0xxx, то есть мимо признака 1.
 *
 * Не совпал хоть один признак — НЕ ТРОГАЕМ НИЧЕГО и отдаём отказ дальше,
 * ровно как прежде. Заплатка, которая правит не то, страшнее стены.
 */

#ifndef __MACRUNNER_KUSD_H
#define __MACRUNNER_KUSD_H

/* Канонический адрес Windows. Ниже 4 ГБ, поэтому у нас не отображается. */
#define MACRUNNER_KUSD_LOW_BASE    0x000000007ffe0000ull
/* Окно, в котором ловим отказ. Сама KUSD — одна страница, но Windows
 * резервирует под неё 64 КБ, и обращения по +0x2d8/+0x320 обязаны попасть. */
#define MACRUNNER_KUSD_LOW_SIZE    0x10000ull

/* Куда переписываем. Выразим ОДНИМ movz: 0x7ffe << 32, то есть hw = 2.
 * Пригодность адреса измерена оракулом (mach_vm_allocate FIXED, kr=0,
 * с настоящей записью и чтением) — reports/OBSHCHAYA-STRANITSA-08.09.2026.md §4. */
#define MACRUNNER_KUSD_HIGH_BASE   0x00007ffe00000000ull

/* movz Xd, #0x7ffe, lsl #16 — sf=1 opc=10 100101 hw=01 imm16=0x7ffe Rd
 * Байты в файле: [C0-DF] FF AF D2. */
#define MACRUNNER_KUSD_MOVZ_MASK   0xffffffe0u
#define MACRUNNER_KUSD_MOVZ_LOW    0xd2afffc0u   /* hw = 1 -> lsl #16 */
#define MACRUNNER_KUSD_MOVZ_HIGH   0xd2cfffc0u   /* hw = 2 -> lsl #32 */
/* 32-битная форма (movz Wd) — ПЕРЕМЕЩАЕМАЯ, её не трогаем никогда.
 * Оставлено здесь, чтобы стенд мог проверить, что мы её отвергаем. */
#define MACRUNNER_KUSD_MOVZ_W32    0x52afffc0u

/* Почему решение отвергнуто. Печатается в журнал: «не сработало» обязано быть
 * отличимо от «не позвалось» — у нас это уже стоило прогонов. */
enum macrunner_kusd_why
{
    MACRUNNER_KUSD_OK = 0,
    MACRUNNER_KUSD_NE_OKNO,        /* адрес отказа вне низкого окна KUSD */
    MACRUNNER_KUSD_NET_KOMANDY,    /* команда по pc-4 не прочитана */
    MACRUNNER_KUSD_NE_UZOR,        /* по pc-4 не movz Xd,#0x7ffe,lsl#16 */
    MACRUNNER_KUSD_NE_BAZA,        /* регистр Xd не несёт 0x7FFE0000 */
    MACRUNNER_KUSD_NE_OT_NEGO      /* отказ не от этого регистра */
};

struct macrunner_kusd_reshenie
{
    int                   patchit;   /* 1 = переписать четыре байта */
    enum macrunner_kusd_why why;
    unsigned long long    insn_va;   /* адрес команды movz (pc-4) */
    unsigned int          staraya;   /* что там сейчас */
    unsigned int          novaya;    /* что записать */
    unsigned int          rd;        /* регистр назначения movz */
    unsigned long long    novoe_rd;  /* какое значение положить в Xd */
};

static inline int macrunner_kusd_adres_nizkiy( unsigned long long a )
{
    return a >= MACRUNNER_KUSD_LOW_BASE && a < MACRUNNER_KUSD_LOW_BASE + MACRUNNER_KUSD_LOW_SIZE;
}

static inline int macrunner_kusd_uzor_sovpal( unsigned int insn )
{
    return (insn & MACRUNNER_KUSD_MOVZ_MASK) == MACRUNNER_KUSD_MOVZ_LOW;
}

static inline unsigned int macrunner_kusd_novaya_komanda( unsigned int insn )
{
    /* поле hw — биты 22:21. Было 01, ставим 10. Всё остальное, включая
     * регистр назначения, СОХРАНЯЕТСЯ байт в байт. */
    return (insn & ~(3u << 21)) | (2u << 21);
}

/*
 * Единственное место, где принимается решение. Ничего не пишет и не читает
 * память — все входные данные уже добыты вызывающим (в движке — через
 * безопасное копирование). Поэтому её проверяет стенд без всякого Wine.
 *
 *   fault_addr   адрес, по которому случился отказ (si_addr)
 *   pc           где стоял гость в момент отказа
 *   insn_prev    четыре байта по pc-4 (значение важно только при prev_ok)
 *   prev_ok      удалось ли их прочитать
 *   regs         x0..x30 из контекста отказа
 */
static inline void macrunner_kusd_reshit( unsigned long long fault_addr,
                                          unsigned long long pc,
                                          unsigned int insn_prev,
                                          int prev_ok,
                                          const unsigned long long *regs,
                                          struct macrunner_kusd_reshenie *out )
{
    unsigned int rd;

    out->patchit  = 0;
    out->insn_va  = pc - 4;
    out->staraya  = insn_prev;
    out->novaya   = 0;
    out->rd       = 32;
    out->novoe_rd = 0;

    if (!macrunner_kusd_adres_nizkiy( fault_addr )) { out->why = MACRUNNER_KUSD_NE_OKNO;     return; }
    if (!prev_ok)                                   { out->why = MACRUNNER_KUSD_NET_KOMANDY; return; }
    if (!macrunner_kusd_uzor_sovpal( insn_prev ))   { out->why = MACRUNNER_KUSD_NE_UZOR;     return; }

    rd = insn_prev & 0x1fu;
    out->rd = rd;
    /* x31 в поле Rd у movz означает регистр zr — писать в него бессмысленно,
     * и такой movz не мог дать базу обращения. Заодно защищает regs[31]. */
    if (rd >= 31)                                   { out->why = MACRUNNER_KUSD_NE_UZOR;     return; }

    /* ★ Признак, который отсекает перемещаемую форму: значение movz обязано
     * дожить до обращения НЕТРОНУТЫМ. Если его к чему-то прибавили, здесь
     * будет не 0x7FFE0000. */
    if (regs[rd] != MACRUNNER_KUSD_LOW_BASE)        { out->why = MACRUNNER_KUSD_NE_BAZA;     return; }

    /* ★ И обращение обязано идти от НЕГО. */
    if (fault_addr < regs[rd] ||
        fault_addr - regs[rd] >= MACRUNNER_KUSD_LOW_SIZE) { out->why = MACRUNNER_KUSD_NE_OT_NEGO; return; }

    out->patchit  = 1;
    out->why      = MACRUNNER_KUSD_OK;
    out->novaya   = macrunner_kusd_novaya_komanda( insn_prev );
    out->novoe_rd = MACRUNNER_KUSD_HIGH_BASE;
}

static inline const char *macrunner_kusd_why_text( enum macrunner_kusd_why w )
{
    switch (w)
    {
    case MACRUNNER_KUSD_OK:          return "патчим";
    case MACRUNNER_KUSD_NE_OKNO:     return "адрес вне низкого окна KUSD";
    case MACRUNNER_KUSD_NET_KOMANDY: return "команда по pc-4 не прочитана";
    case MACRUNNER_KUSD_NE_UZOR:     return "по pc-4 не movz Xd,#0x7ffe,lsl#16";
    case MACRUNNER_KUSD_NE_BAZA:     return "регистр Xd не несёт 0x7FFE0000";
    case MACRUNNER_KUSD_NE_OT_NEGO:  return "отказ не от этого регистра";
    }
    return "?";
}

#endif /* __MACRUNNER_KUSD_H */
