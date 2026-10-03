#!/bin/bash
set -euo pipefail
recipe_root="$(cd "$(dirname "$0")" && pwd -P)"
brew install python bison flex pkg-config freetype fontconfig libpng gstreamer glib gettext gnutls libusb sdl2 ffmpeg ccache molten-vk vulkan-headers
export PATH="$(brew --prefix)/bin:$PATH"
python3 "$recipe_root/download-toolchain.py"
