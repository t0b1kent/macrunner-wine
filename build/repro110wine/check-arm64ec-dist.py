#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сторож ARM64EC: дист без переходников EC выглядит целым и не запускает игру.

Заведён 07.09.2026 лейном РЕГРЕСС. Повод — реальная потеря:
    engine/wine/dist, 06.09 11:39 — 639 модулей из 758 потеряли ARM64EC
    (нет CHPEMetadataPointer, нет секций .hexpthk и .a64xrm).
    Hollow Knight на этой половине: ступень 1 и 6, три прогона из трёх.
    Возврат PE-половины опоры: ступень 11 за 47 и 48 с, два из двух.

Почему сторож нужен: у битого диста ВСЕ файлы на месте, размеры правдоподобны,
`ls` и сверка комплектности проходят. Отличие видно только в заголовке PE.

Причина потери (найдена 07.09): в дереве исходников `engine/wine/Makefile`
(порождён 26.06) `arm64ec_CC` ПУСТ, а `-marm64x` встречается 0 раз (в
`build/` и `build-arm64ec-spike/` — 883 раза). Его `prefix` =
    <historical-foreign-prefix> (пример чужой сборки; путь текущего checkout задаётся аргументом).
ССЫЛКА в живое дерево. Поэтому `make && make install` из корня исходников молча
кладёт ARM64-модули БЕЗ EC прямо в рабочий дист.

Использование:
    python3 scripts/check-arm64ec-dist.py <дист> [<дист> ...]
    python3 scripts/check-arm64ec-dist.py --min 600 <дист>
    python3 scripts/check-arm64ec-dist.py --zagotovki <корень-дерева>   # мина в исходниках

Код возврата: 0 — целый, 1 — битый (меньше порога), 2 — дист не найден.
"""
import os
import struct
import sys

POROG_UMOLCHANIE = 600
RASSHIRENIYA = ('.dll', '.exe', '.drv', '.sys', '.acm', '.cpl', '.ocx')


def pe_priznaki(put):
    """Вернуть (est_chpe, est_hexpthk, est_a64xrm) или None, если это не PE."""
    try:
        with open(put, 'rb') as f:
            data = f.read()
    except OSError:
        return None
    if data[:2] != b'MZ':
        return None
    try:
        e = struct.unpack_from('<I', data, 0x3c)[0]
        if data[e:e + 4] != b'PE\0\0':
            return None
        nsec = struct.unpack_from('<H', data, e + 6)[0]
        osz = struct.unpack_from('<H', data, e + 20)[0]
        opt = e + 24
        nrva = struct.unpack_from('<I', data, opt + 108)[0]
        dd = opt + 112
        dirs = [struct.unpack_from('<II', data, dd + 8 * i) for i in range(nrva)]
        so = opt + osz
        secs = []
        for i in range(nsec):
            b = data[so + 40 * i:so + 40 * i + 40]
            name = b[:8].rstrip(b'\0').decode('latin1')
            vs, va, rs, pr = struct.unpack_from('<IIII', b, 8)
            secs.append((name, va, vs, pr, rs))
        imena = set(s[0] for s in secs)
        chpe = 0
        if len(dirs) > 10 and dirs[10][0]:
            rva = dirs[10][0]
            off = None
            for _, va, vs, pr, rs in secs:
                if va <= rva < va + max(vs, rs):
                    off = pr + (rva - va)
                    break
            if off is not None and off + 4 <= len(data):
                size = struct.unpack_from('<I', data, off)[0]
                if size > 0xd0 and off + 0xd0 <= len(data):
                    chpe = struct.unpack_from('<Q', data, off + 0xC8)[0]
        return (chpe != 0, '.hexpthk' in imena, '.a64xrm' in imena)
    except (struct.error, IndexError, UnicodeDecodeError):
        return None


def perepis(dist):
    katalog = os.path.join(dist, 'lib', 'wine', 'aarch64-windows')
    if not os.path.isdir(katalog):
        return None
    vsego = chpe = hexpthk = a64xrm = 0
    for imya in sorted(os.listdir(katalog)):
        if not imya.endswith(RASSHIRENIYA):
            continue
        put = os.path.join(katalog, imya)
        if not os.path.isfile(put) or os.path.islink(put):
            continue
        pr = pe_priznaki(put)
        if pr is None:
            continue
        vsego += 1
        chpe += pr[0]
        hexpthk += pr[1]
        a64xrm += pr[2]
    return vsego, chpe, hexpthk, a64xrm


def perepis_zagotovok(koren):
    """Перепись ЗАГОТОВОК в дереве исходников: engine/wine/dlls/*/aarch64-windows/*.

    Заведено 07.09.2026 после находки лейна ПЕРЕМЕР: сторож смотрел на ДИСТ, а
    заготовка без EC оставалась в дереве и отравляла дист при следующем
    `make install` из корня. Отпечаток мины:
        engine/wine/dlls/ntdll/aarch64-windows/ntdll.dll  3 751 936 Б  без EC
        здоровый эталон того же модуля                    7 064 576 Б
    """
    baza = os.path.join(koren, 'engine', 'wine', 'dlls')
    if not os.path.isdir(baza):
        return None
    vsego = chpe = 0
    bez_ec = []
    for dll in sorted(os.listdir(baza)):
        katalog = os.path.join(baza, dll, 'aarch64-windows')
        if not os.path.isdir(katalog):
            continue
        for imya in sorted(os.listdir(katalog)):
            if not imya.endswith(RASSHIRENIYA):
                continue
            put = os.path.join(katalog, imya)
            if not os.path.isfile(put) or os.path.islink(put):
                continue
            pr = pe_priznaki(put)
            if pr is None:
                continue
            vsego += 1
            if pr[0]:
                chpe += 1
            else:
                bez_ec.append(put)
    return vsego, chpe, bez_ec


def main(argv):
    porog = POROG_UMOLCHANIE
    rezhim_zagotovok = False
    puti = []
    i = 1
    while i < len(argv):
        if argv[i] == '--min':
            porog = int(argv[i + 1])
            i += 2
            continue
        if argv[i] == '--zagotovki':
            rezhim_zagotovok = True
            i += 1
            continue
        puti.append(argv[i])
        i += 1
    if not puti:
        print(__doc__)
        return 2
    kod = 0
    if rezhim_zagotovok:
        for koren in puti:
            z = perepis_zagotovok(koren)
            if z is None:
                print('НЕТ ДЕРЕВА (нет engine/wine/dlls): %s' % koren)
                kod = max(kod, 2)
                continue
            vsego, chpe, bez_ec = z
            if bez_ec:
                print('МИНА  заготовок без EC: %d из %d  %s' % (len(bez_ec), vsego, koren))
                for put in bez_ec[:20]:
                    print('       %s  %d Б' % (put, os.path.getsize(put)))
                if len(bez_ec) > 20:
                    print('       ... и ещё %d' % (len(bez_ec) - 20))
                print('       Следующий `make install` из КОРНЯ engine/wine положит их')
                print('       в рабочий дист. Собирать только в engine/wine/build.')
                kod = max(kod, 1)
            else:
                print('ЧИСТО  заготовок с EC: %d из %d  %s' % (chpe, vsego, koren))
        return kod
    for dist in puti:
        p = perepis(dist)
        if p is None:
            print('НЕТ ДИСТА (нет lib/wine/aarch64-windows): %s' % dist)
            kod = max(kod, 2)
            continue
        vsego, chpe, hexpthk, a64xrm = p
        bit = chpe < porog
        print('%s EC=%d/%d  .hexpthk=%d  .a64xrm=%d  %s'
              % ('БИТЫЙ' if bit else 'ЦЕЛЫЙ', chpe, vsego, hexpthk, a64xrm, dist))
        if bit:
            print('       Дист собран БЕЗ ARM64EC. Гонять на нём бессмысленно:')
            print('       HK встаёт на ступени 1-6. Лечение — вернуть PE-половину')
            print('       из целого диста, либо собирать в engine/wine/build,')
            print('       а НЕ в корне engine/wine (там arm64ec_CC пуст).')
            kod = max(kod, 1)
    return kod


if __name__ == '__main__':
    sys.exit(main(sys.argv))
