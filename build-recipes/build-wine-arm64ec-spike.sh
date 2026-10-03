#!/bin/bash
# Portable four-PE-architecture adaptation of the published 1.0.7 recipe.
set -euo pipefail
recipe_root="$(cd "$(dirname "$0")" && pwd -P)"
source_root="$(cd "$recipe_root/.." && pwd -P)"
build_dir="${WINE_BUILD:-$source_root/_build}"
install_dir="${WINE_INSTALL:-$source_root/_install}"
build_jobs="${BUILD_JOBS:-2}"
case "$build_jobs" in ''|*[!0-9]*|0) echo 'BUILD_JOBS must be a positive integer' >&2; exit 2;; esac
bash "$recipe_root/configure.sh"
build_dir="$(cd "$build_dir" && pwd -P)"
make -f "$source_root/third_party/hyperbridge/Makefile" \
    SRC_ROOT="$source_root/third_party/hyperbridge" BUILD_ROOT="$build_dir/hyperbridge" \
    -j"$build_jobs" 2>&1 | tee "$build_dir/hyperbridge.log"
make -C "$build_dir" -j"$build_jobs" 2>&1 | tee "$build_dir/build.log"
make -C "$build_dir" install 2>&1 | tee "$build_dir/install.log"
"$(brew --prefix)/bin/python3" "$recipe_root/compare-release.py" "$install_dir" "$build_dir/reports"
echo 'Wine installation and release comparison report complete'
