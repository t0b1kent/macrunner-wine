/* СИСТЕМНЫЕ И ДАЛЬНИЕ ПЕРЕДАЧИ УПРАВЛЕНИЯ — один текст на обе ветви.
 *
 * ЗАМЕР. Доска x64 показывала 13 отказов подъёма на семи именах: retf, int3,
 * int, int1, xlatb, iretd, дальний call. Прямая проба обеими ветвями:
 *   подняли оба: 0    только x64: 0    ТОЛЬКО i386: 7
 * То есть теперь отставала ветвь x64 — зеркально утреннему случаю с
 * вектором, где отставал i386.
 *
 * Тела нейтральны: только hb_ir_emit, operand_from_dec и emit. Поэтому текст
 * один, а связывание два — как и у hb_lift_vec_obshchee.inc.
 *
 * ОГОВОРКА ЧЕСТНАЯ. Часть этих команд (retf, iretd, дальний call) в
 * пользовательском кольце неисполнима. Подъём здесь не делает их
 * исполнимыми: он переносит отказ с РАЗБОРА на ИСПОЛНЕНИЕ, где отказ можно
 * назвать точно. Это лучше, чем не поднять вовсе: «не умею поднять» и «эту
 * команду нельзя выполнять в кольце 3» — разные вещи, и путать их значит
 * терять место отказа.
 *
 * Единица, включающая файл, обязана определить operand_from_dec и emit. */
#ifndef HB_LIFT_SIST_OBSHCHEE_VKLYUCHENO
#define HB_LIFT_SIST_OBSHCHEE_VKLYUCHENO

static bool hb_sist_obshchee(const hb_decoded_t* dec, hb_ir_builder_t* b,
                             hb_result_t* itog) {
    switch (dec->opcode) {
        case HB_INS_IRET: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_IRET);
            if (i) i->src1 = operand_from_dec(dec, 1); /* size (16 vs 32) */
            emit(b, i, dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_INT3:
            emit(b, hb_ir_emit(b, HB_IR_INT3), dec);
            *itog = HB_OK; return true;
        case HB_INS_INT1:
            emit(b, hb_ir_emit(b, HB_IR_INT1), dec);
            *itog = HB_OK; return true;
        case HB_INS_INT: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_INT);
            if (i) i->src1 = operand_from_dec(dec, 1);
            emit(b, i, dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_INTO:
            emit(b, hb_ir_emit(b, HB_IR_INTO), dec);
            *itog = HB_OK; return true;
        case HB_INS_CALL_FAR_MEM:
        case HB_INS_JMP_FAR_MEM: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_FAR_BRANCH);
            if (i) {
                i->src1 = operand_from_dec(dec, 1);
                i->src2 = hb_ir_none();
                i->target = 2u | ((dec->opcode == HB_INS_CALL_FAR_MEM) ? 1u : 0u);
            }
            emit(b, i, dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_RETF: {
            hb_ir_instr_t *i = hb_ir_emit(b, HB_IR_RETF);
            if (i) i->src1 = hb_ir_imm(dec->ret_imm, HB_SIZE_16);
            emit(b, i, dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_XLAT:
            emit(b, hb_ir_emit(b, HB_IR_XLAT), dec);
            *itog = HB_OK; return true;

        /* ★ ТРАНЗАКЦИОННАЯ ПАМЯТЬ (RTM: XBEGIN / XABORT / XEND / XTEST) — 05.09.2026.
         *
         * ЧТО БЫЛО. Декодер узнавал XBEGIN и XABORT (с 04.09), но ни один лифтер их не
         * поднимал — блок отказывал «неподдержанным опкодом», и гость, вошедший в
         * транзакцию, умирал. XEND и XTEST разбирались как LGDT/PRIV — отказ по привилегии.
         *
         * КАК У ЭТАЛОНОВ (research/, прочитано 05.09):
         *   QEMU (TCG)  — не разбирает вовсе: #UD, RTM в cpuid не объявлен;
         *   box64       — упоминаний XBEGIN/XEND/XTEST в src нет: неизвестный опкод;
         *   FEX         — в таблицах есть (PrimaryGroupTables.cpp:198/201,
         *                 SecondaryModRMTables.cpp:34/35), длина верна, обработчика нет ->
         *                 «не реализовано», SIGILL.
         *
         * КАК У ЖЕЛЕЗА. Intel после TAA выпустил режим RTM_ALWAYS_ABORT
         * (CPUID.07H.EDX[11], MSR TSX_FORCE_ABORT): XBEGIN всегда отменяет транзакцию с
         * EAX = 0 и уходит на запасной путь; XTEST отвечает «не в транзакции» (ZF=1);
         * XABORT вне транзакции — NOP (SDM); XEND вне транзакции — #GP(0). Это
         * архитектурное поведение НАСТОЯЩИХ процессоров, а не наша выдумка, и ровно оно
         * здесь воспроизводится — лучше трёх эталонов (у них гость гибнет на первом же
         * XBEGIN, даже если у него есть запасной путь).
         *
         * EAX = 0: ни один разряд состояния не выставлен, в том числе бит 1 (RETRY), —
         * поэтому glibc/TBB/прочие обёртки не крутят повтор, а сразу берут замок.
         * Тот же код, что у железа с TSX_FORCE_ABORT.
         *
         * XEND: у нас нет доставляемого вида #GP (виды у стороны wine: PRIVILEGED и
         * ILLEGAL; всё прочее = смерть процесса «runtime»). Отдаём ILLEGAL (#UD,
         * c000001d): именно так ведёт себя процессор БЕЗ RTM, каковым мы себя объявляем
         * (лист 7 CPUID у нас пуст). Достижимо только ошибочным кодом: при всегда-отмене
         * штатный путь до XEND не доходит.
         *
         * XBEGIN без своей IR-операции: `MOV EAX, 0` (32-битная запись гасит старшую
         * половину RAX, как и у mov eax, imm32) + `JMP запасной_путь` — обе операции
         * выпускаются кодогенератором штатно, без помощника. Цель перехода декодер
         * кладёт в branch_target и помечает команду безусловным переходом, поэтому
         * единица трансляции кончается здесь, как на любом jmp. */
        case HB_INS_XBEGIN: {
            hb_ir_instr_t* m = hb_ir_emit_mov(b, hb_ir_reg(HB_REG_RAX, HB_SIZE_32),
                                              hb_ir_imm(0, HB_SIZE_32));
            emit(b, m, dec);
            emit(b, hb_ir_emit_jmp(b, dec->branch_target), dec);
            *itog = HB_OK; return true;
        }
        case HB_INS_XABORT:
            emit(b, hb_ir_emit(b, HB_IR_NOP), dec);
            *itog = HB_OK; return true;
        case HB_INS_XEND:
            emit(b, hb_ir_emit_fault_illegal(b, "XEND вне транзакции (транзакции всегда отменяются)"), dec);
            *itog = HB_OK; return true;
        case HB_INS_XTEST:
            emit(b, hb_ir_emit(b, HB_IR_XTEST), dec);
            *itog = HB_OK; return true;
        default:
            return false;
    }
}

#endif /* HB_LIFT_SIST_OBSHCHEE_VKLYUCHENO */
