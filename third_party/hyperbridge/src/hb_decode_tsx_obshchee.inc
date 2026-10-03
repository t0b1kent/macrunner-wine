/* ТРАНЗАКЦИОННАЯ ПАМЯТЬ (TSX/RTM) — РАЗБОР, один текст на обе ветви.
 *
 * ЗАЧЕМ ОБЩИЙ ТЕКСТ. 04.09.2026 разбор `C6 F8` / `C7 F8` появился ДВУМЯ копиями —
 * в hb_decode_x64.c и hb_decode_x86.c. Копия x64 забыла префикс 66: длина
 * `66 C7 F8 iw` выходила 7 вместо 5. Это регресс правки 15.08 (итерация 943),
 * которая ровно эту ширину и чинила, — и которую копия 04.09 сделала мёртвой
 * (управление до старой ветки `modrm == 0xf8` больше не доходило). Замер пробой
 * 05.09: x64 `66 C7 F8 34 12` -> len=7, i386 те же байты -> len=5.
 *
 * Вторая дыра той же семьи: `0F 01 D5` (XEND) и `0F 01 D6` (XTEST) уходили в
 * разбор группы 7 «по членам»: reg=2 -> LGDT (x64) и PRIV (i386), то есть гость
 * получал отказ по ПРИВИЛЕГИИ (c0000096) на командах пользовательского кольца.
 *
 * Единица, включающая файл, обязана определить: hb_dec_t с полями code/pos/addr,
 * can_read, read_u8, read_s16, read_s32, set_imm.
 */
#ifndef HB_DECODE_TSX_OBSHCHEE_VKLYUCHENO
#define HB_DECODE_TSX_OBSHCHEE_VKLYUCHENO

/* XABORT imm8 (C6 F8 ib) и XBEGIN rel16/32 (C7 F8 iw/id).
 *
 * Байт F8 стоит НА МЕСТЕ modrm, но modrm-ом не является: у групп 11 (C6/C7)
 * поле reg служит расширением кода операции, и значение 0xF8 (mod=11, reg=7,
 * rm=0) выделено под эти две команды. `rel16` — ширина смещения: на x64 это
 * `operand16 && !rex_w` (REX.W бьёт 66), на i386 — `operand16`.
 *
 * XBEGIN помечается БЕЗУСЛОВНЫМ ПЕРЕХОДОМ: транзакции у нас всегда отменяются
 * (см. hb_lift_sist_obshchee.inc), значит управление всегда уходит на запасной
 * путь. Цель = адрес следующей команды + смещение (SDM: fallbackRIP := RIP + rel).
 *
 * Возвращает false, если это не та кодировка (после C6/C7 стоит не F8) —
 * тогда вызывающий разбирает группу 11 как обычно (MOV r/m, imm). */
static bool hb_tsx_gruppa11(hb_dec_t* d, uint8_t opcode, bool rel16,
                            hb_decoded_t* out, hb_result_t* itog) {
    if (!(opcode == 0xC6 || opcode == 0xC7)) return false;
    if (!can_read(d, 1) || d->code[d->pos] != 0xF8) return false;
    (void)read_u8(d);                       /* съесть F8 */
    out->writes_flags = false;
    if (opcode == 0xC6) {
        if (!can_read(d, 1)) { *itog = HB_ERR_DECODE_FAILED; return true; }
        out->opcode = HB_INS_XABORT;
        set_imm(out, 1, read_u8(d), 1);
        *itog = HB_OK; return true;
    }
    {
        uint8_t razm = rel16 ? 2 : 4;
        int64_t rel;
        uint64_t tsel;
        if (!can_read(d, razm)) { *itog = HB_ERR_DECODE_FAILED; return true; }
        rel = rel16 ? (int64_t)read_s16(d) : (int64_t)read_s32(d);
        tsel = d->addr + d->pos + (uint64_t)rel;   /* pos уже за смещением */
        out->opcode = HB_INS_XBEGIN;
        out->is_branch = true;
        out->is_conditional = false;
        out->branch_target = tsel;
        set_imm(out, 1, (int64_t)tsel, razm);
        *itog = HB_OK; return true;
    }
}

/* XEND (0F 01 D5) и XTEST (0F 01 D6). Звать ДО разбора группы 7 по членам.
 * XTEST пишет флаги (ZF и пятёрку остальных), XEND — нет. */
static bool hb_tsx_0f01(uint8_t modrm, hb_decoded_t* out) {
    if (modrm == 0xD5) {
        out->opcode = HB_INS_XEND;
        out->writes_flags = false;
        return true;
    }
    if (modrm == 0xD6) {
        out->opcode = HB_INS_XTEST;
        out->writes_flags = true;
        return true;
    }
    return false;
}

#endif /* HB_DECODE_TSX_OBSHCHEE_VKLYUCHENO */
