/* КОМАНДЫ, У КОТОРЫХ ЗАКОНЕН ПРЕФИКС LOCK.
 *
 * ПОРОЖДЁННЫЙ ФАЙЛ — не править руками.
 * Прибор: tools/оракул/замки-через-bochs.py
 * Оракул: bochscpu (Bochs), длинный режим.
 *
 * Список снят ИСПОЛНЕНИЕМ: каждой паре (команда, приёмник в памяти)
 * задавались два вопроса — исполняется ли форма БЕЗ префикса и С ним.
 * В список попали только те, у кого обе формы исполнились.
 *
 * Замер того же дня: при приёмнике-РЕГИСТРЕ процессор не принял LOCK
 * НИ У ОДНОЙ команды (0 из 513) — поэтому проверка приёмника входит
 * в правило наравне со списком имён.
 */
#ifndef HB_ZAMKI_H
#define HB_ZAMKI_H

#define HB_ZAMKI(X) \
    X(HB_INS_ADC) \
    X(HB_INS_ADD) \
    X(HB_INS_AND) \
    X(HB_INS_BTC) \
    X(HB_INS_BTR) \
    X(HB_INS_BTS) \
    X(HB_INS_CMPXCHG) \
    X(HB_INS_CMPXCHG8B) \
    X(HB_INS_DEC) \
    X(HB_INS_INC) \
    X(HB_INS_NEG) \
    X(HB_INS_NOT) \
    X(HB_INS_OR) \
    X(HB_INS_SBB) \
    X(HB_INS_SUB) \
    X(HB_INS_XADD) \
    X(HB_INS_XCHG) \
    X(HB_INS_XOR) \

#endif /* HB_ZAMKI_H */
