/* УНАРНЫЕ ФОРМЫ VEX — поле vvvv у них ЗАРЕЗЕРВИРОВАНО (обязано быть 1111)
 * и операндом не является.
 *
 * ПОРОЖДЁННЫЙ ФАЙЛ. Список снят ИСПОЛНЕНИЕМ, а не рукой: настоящий
 * процессор отвергает такие кодировки при vvvv != 1111 (#UD, вектор 6).
 * Прибор: tools/оракул/сверка-ролей-оракулом.py
 * Источник: tools/оракул/роли-поправки.txt
 */
#ifndef HB_UNARNYE_VEX_H
#define HB_UNARNYE_VEX_H

#define HB_UNARNYE_VEX(X) \
    X(HB_INS_AESIMC) \
    X(HB_INS_PABSB) \
    X(HB_INS_PABSD) \
    X(HB_INS_PABSW) \
    X(HB_INS_PHMINPOSUW) \
    X(HB_INS_PMOVSXBD) \
    X(HB_INS_PMOVSXBQ) \
    X(HB_INS_PMOVSXBW) \
    X(HB_INS_PMOVSXDQ) \
    X(HB_INS_PMOVSXWD) \
    X(HB_INS_PMOVSXWQ) \
    X(HB_INS_PMOVZXBD) \
    X(HB_INS_PMOVZXBQ) \
    X(HB_INS_PMOVZXBW) \
    X(HB_INS_PMOVZXDQ) \
    X(HB_INS_PMOVZXWD) \
    X(HB_INS_PMOVZXWQ) \
    X(HB_INS_PTEST) \

#endif /* HB_UNARNYE_VEX_H */
