#!/bin/bash
set -euo pipefail
recipe_root="$(cd "$(dirname "$0")" && pwd -P)"
source_root="$(cd "$recipe_root/.." && pwd -P)"
if [ "$(uname -m)" != arm64 ]; then
    echo "This recipe requires native macOS ARM64; the assigned runner is not arm64." >&2
    exit 1
fi
brew_root="$(brew --prefix)"
toolchain_root="${LLVM_MINGW_ROOT:-$source_root/_toolchain/llvm-mingw-20260505-ucrt-macos-universal}"
build_dir="${WINE_BUILD:-$source_root/_build}"
install_dir="${WINE_INSTALL:-$source_root/_install}"
mkdir -p "$build_dir" "$install_dir"
build_dir="$(cd "$build_dir" && pwd -P)"
install_dir="$(cd "$install_dir" && pwd -P)"
"$brew_root/bin/python3" "$recipe_root/stage-source.py" "$build_dir"
export PATH="$(brew --prefix bison)/bin:$(brew --prefix flex)/bin:$toolchain_root/bin:$PATH"
export PKG_CONFIG_PATH="$brew_root/lib/pkgconfig:$brew_root/share/pkgconfig:$(brew --prefix gettext)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export CC="ccache /usr/bin/clang"
export CXX="ccache /usr/bin/clang++"
export CFLAGS="-O2 -arch arm64 -mmacosx-version-min=14.0 -I$brew_root/include"
export CPPFLAGS="-I$brew_root/include"
export LDFLAGS="-arch arm64 -mmacosx-version-min=14.0 -L$brew_root/lib"
export aarch64_CC="ccache $toolchain_root/bin/aarch64-w64-mingw32-gcc"
export aarch64_CXX="ccache $toolchain_root/bin/aarch64-w64-mingw32-g++"
export arm64ec_CC="ccache $toolchain_root/bin/arm64ec-w64-mingw32-gcc"
export arm64ec_CXX="ccache $toolchain_root/bin/arm64ec-w64-mingw32-g++"
export x86_64_CC="ccache $toolchain_root/bin/x86_64-w64-mingw32-gcc"
export x86_64_CXX="ccache $toolchain_root/bin/x86_64-w64-mingw32-g++"
export i386_CC="ccache $toolchain_root/bin/i686-w64-mingw32-gcc"
export i386_CXX="ccache $toolchain_root/bin/i686-w64-mingw32-g++"
for target_arch in aarch64 arm64ec x86_64 i686; do
    test -x "$toolchain_root/bin/$target_arch-w64-mingw32-gcc"
done
cd "$build_dir"
"$build_dir/source-wine/configure" --prefix="$install_dir" \
    --enable-archs=aarch64,arm64ec,x86_64,i386 --disable-tests \
    --without-x --without-alsa --without-capi --without-oss --without-pulse --with-coreaudio \
    2>&1 | tee configure.log
