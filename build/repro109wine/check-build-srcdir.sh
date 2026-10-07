#!/bin/sh
# Сторож: собирает ли build/Makefile ИСХОДНИКИ СВОЕГО дерева.
#
# Заведён 07.09.2026 после находки лейна ПОВТОР-7. В копии лейна (git worktree)
# каталог engine/wine/build сконфигурирован ./configure ОДИН раз, в главном
# дереве, и несёт АБСОЛЮТНЫЙ путь:
#     srcdir = /.../Main/MacRunner/engine/wine        <- ГЛАВНОЕ дерево
# Поэтому `make` в копии компилирует ЧУЖИЕ исходники и линкует ЧУЖУЮ
# libhyperbridge.a. Правка копии в сборку НЕ ПОПАДАЕТ, а сборка проходит
# УСПЕШНО — то есть замер идёт по чужому коду под видом своего.
#
# Тот же класс уже кусал дважды: лейн ПРИБОРЫ-5 «проверил компиляцией» чужой,
# непочатый файл; лейн СВОД обошёл это подменой пути исходника вручную.
#
# Использование:
#     sh scripts/check-build-srcdir.sh [<корень-дерева>]
# Код возврата: 0 — свой, 1 — ЧУЖОЙ, 2 — нечего проверять.
set -u
koren=${1:-.}
koren=$(cd "$koren" 2>/dev/null && pwd) || { echo "нет каталога: ${1:-.}" >&2; exit 2; }
kod=0
nashel=0
for mk in "$koren"/engine/wine/build/Makefile "$koren"/engine/wine/build-arm64ec-spike/Makefile; do
    [ -f "$mk" ] || continue
    nashel=1
    sd=$(grep -m1 '^srcdir[[:space:]]*=' "$mk" | sed 's/^srcdir[[:space:]]*=[[:space:]]*//')
    case "$sd" in
        /*) abs="$sd" ;;
        *)  abs=$(cd "$(dirname "$mk")/$sd" 2>/dev/null && pwd) ;;
    esac
    case "$abs" in
        "$koren"/*|"$koren")
            echo "СВОЙ   $mk"
            echo "       srcdir = $abs"
            ;;
        *)
            echo "ЧУЖОЙ  $mk"
            echo "       srcdir = $abs"
            echo "       а дерево = $koren"
            echo "       make здесь соберёт ЧУЖИЕ исходники, и сборка ПРОЙДЁТ УСПЕШНО."
            echo "       Лечение: переконфигурировать build в этом дереве, либо собирать"
            echo "       с явной подменой пути и ПОСТПРОВЕРКОЙ строки прибора в готовом .so."
            kod=1
            ;;
    esac
done
[ "$nashel" = 1 ] || { echo "нет ни одного build/Makefile под $koren" >&2; exit 2; }
exit $kod
