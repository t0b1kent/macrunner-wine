# MacRunner Wine

Public Wine source for [MacRunner releases](https://github.com/t0b1kent/macrunner-app/releases),
based on CodeWeavers CrossOver 26.1.0 / Wine 11.0. MacRunner integrates native
macOS Wine with [HyperBridge](https://github.com/t0b1kent/hyperbridge).

Wine is **LGPL-2.1-or-later**: see [COPYING.LIB](COPYING.LIB) and [LICENSE](LICENSE).
All upstream copyright, author and third-party notices are retained, including
the original Wine README below and [its unchanged copy](docs/UPSTREAM-README.md).
The retained source-only HyperBridge dependency is MIT-licensed; its license
is in [third_party/hyperbridge/LICENSE](third_party/hyperbridge/LICENSE).

History:

- `crossover-26.1.0`: exact unmodified `sources/wine` import from the
  [public CrossOver tarball](https://media.codeweavers.com/pub/crossover/source/crossover-sources-26.1.0.tar.gz),
  SHA256 `e4ec87d5821a009dd1f1d2e36ffe2e24b8fcbae9516375ea42f95a16928ab8fa`.
- `macrunner-1.0.7`: published 1.0.7 source patch plus selected release inputs,
  portable recipes and cloud build. See [PROVENANCE](docs/PROVENANCE.md) and
  [the precise archived source map](docs/release-source-map.json).

## Build on native macOS ARM64

Install Homebrew and Xcode or Command Line Tools first. The recipes use Python
3.12 or later; bootstrap installs Homebrew Python. From a fresh checkout:

```sh
bash build-recipes/bootstrap.sh
BUILD_JOBS=2 nice -n 20 bash build-recipes/build-wine-arm64ec-spike.sh
```

The recipe downloads **llvm-mingw 20260505**, verifies SHA256
`050379de888f0c843787819dadf183df3693330a5724643919e9121f16355295`,
and configures native arm64 with deployment target macOS 14.0, four PE
architectures (`aarch64,arm64ec,x86_64,i386`), CoreAudio, no X11 and no tests.
Homebrew provides Python, bison, flex, pkg-config, freetype, fontconfig, libpng, MoltenVK, Vulkan headers,
gstreamer, glib, gettext, gnutls, libusb, SDL2, ffmpeg and ccache.
The recipe stages the unchanged Wine tree as `_build/source-wine` beside
`_build/hyperbridge`, preserving the original relative include layout.
It builds the archived HyperBridge source, then runs Wine `make` and `make install`.
Everything remains inside `_toolchain`, `_build` and `_install` by default.

To check configure without a full build:

```sh
bash build-recipes/configure.sh
```

`LLVM_MINGW_ROOT` can select an already extracted, SHA-verified 20260505
toolchain. `WINE_BUILD` and `WINE_INSTALL` can select isolated output directories.
The executable recipe is the portable equivalent of the published configure
command and `build-wine-arm64ec-spike.sh`; no maintainer machine paths are needed.

## Release source and overlays

The published September tree differs from the selected release sources.
This tree installs the five historical floor sources, the accepted Unix ntdll
source/header map (including short `signal_arm64`, native-prefix/direct-resume
headers, system fixes and ALIAS-L0 `virtual.c`), the selected WoW64/WoW64Win
compiled inputs, loader `main.c/main.h`, and the cooperative wineserver sources.
Those replacements are recorded with old/new SHA256 and archive paths in
[release-source-map.json](docs/release-source-map.json). C/H/Makefile inputs remain
byte-exact; build staging preserves dependency paths and applies the selected
Wine-side probe header in the isolated sibling include tree.

The original release combined builds from different dates and architectures;
this is a clean compilation of their selected combined source state.
Compiler/SDK and dependency drift, retained historical objects, PE stripping,
configured paths and code signing prevent a promise of identical release bytes.
See [RECOMPILE-CHECK](docs/RECOMPILE-CHECK.md). A completed full cloud build is
required before claiming that this recipe builds all release modules.

## GitHub Actions

[build.yml](.github/workflows/build.yml) runs manually or on `macrunner-*` tags,
with `contents: read`, no repository secrets and a 330-minute job limit.
The coordinator measured `macos-15` as an ARM64 Apple M2 Pro virtual runner;
the first step prints `uname -m` and CPU brand and rejects a non-ARM64 assignment.
Homebrew dependency versions and the runner compiler/SDK are logged because
they are not pinned to the historical release machine.

Artifacts contain SHA256 of ntdll, win32u, wow64*, kernelbase, loaders and other
selected outputs, raw build logs, toolchain versions and a comparison with
[32 signed 1.0.7 reference hashes](docs/release-1.0.7-sha256.tsv).
The comparison reports `MATCH`, `DIFFERENT` or `MISSING`; byte differences do
not fail the build. Compile/configure/install failures still fail the job.
Cloud verification is pending the curator's repository creation and push.

## Original Wine README

## INTRODUCTION

Wine is a program which allows running Microsoft Windows programs
(including DOS, Windows 3.x, Win32, and Win64 executables) on Unix.
It consists of a program loader which loads and executes a Microsoft
Windows binary, and a library (called Winelib) that implements Windows
API calls using their Unix, X11 or Mac equivalents.  The library may also
be used for porting Windows code into native Unix executables.

Wine is free software, released under the GNU LGPL; see the file
LICENSE for the details.


## QUICK START

From the top-level directory of the Wine source (which contains this file),
run:

```
./configure
make
```

Then either install Wine:

```
make install
```

Or run Wine directly from the build directory:

```
./wine notepad
```

Run programs as `wine program`. For more information and problem
resolution, read the rest of this file, the Wine man page, and
especially the wealth of information found at https://www.winehq.org.


## REQUIREMENTS

To compile and run Wine, you must have one of the following:

- Linux version 2.6.22 or later
- FreeBSD 12.4 or later
- Solaris x86 9 or later
- NetBSD-current
- macOS 10.12 or later

As Wine requires kernel-level thread support to run, only the operating
systems mentioned above are supported.  Other operating systems which
support kernel threads may be supported in the future.

**FreeBSD info**:
  See https://wiki.freebsd.org/Wine for more information.

**Solaris info**:
  You will most likely need to build Wine with the GNU toolchain
  (gcc, gas, etc.). Warning : installing gas does *not* ensure that it
  will be used by gcc. Recompiling gcc after installing gas or
  symlinking cc, as and ld to the gnu tools is said to be necessary.

**NetBSD info**:
  Make sure you have the USER_LDT, SYSVSHM, SYSVSEM, and SYSVMSG options
  turned on in your kernel.

**macOS info**:
  You need Xcode/Xcode Command Line Tools or Apple cctools.  The
  minimum requirements for compiling Wine are clang 3.8 with the
  MacOSX10.13.sdk and mingw-w64 v12 for 32-bit wine.  The
  MacOSX10.14.sdk and later can build 64-bit wine.

**Supported file systems**:
  Wine should run on most file systems. A few compatibility problems
  have also been reported using files accessed through Samba. Also,
  NTFS does not provide all the file system features needed by some
  applications.  Using a native Unix file system is recommended.

**Basic requirements**:
  You need to have the X11 development include files installed
  (called xorg-dev in Debian and libX11-devel in Red Hat).
  Of course you also need make (most likely GNU make).
  You also need flex version 2.5.33 or later and bison.

**Optional support libraries**:
  Configure will display notices when optional libraries are not found
  on your system. See https://gitlab.winehq.org/wine/wine/-/wikis/Building-Wine
  for hints about the packages you should install. On 64-bit
  platforms, you have to make sure to install the 32-bit versions of
  these libraries.


## COMPILATION

To build Wine, do:

```
./configure
make
```

This will build the program "wine" and numerous support libraries/binaries.
The program "wine" will load and run Windows executables.
The library "libwine" ("Winelib") can be used to compile and link
Windows source code under Unix.

To see compile configuration options, do `./configure --help`.

For more information, see https://gitlab.winehq.org/wine/wine/-/wikis/Building-Wine


## SETUP

Once Wine has been built correctly, you can do `make install`; this
will install the wine executable and libraries, the Wine man page, and
other needed files.

Don't forget to uninstall any conflicting previous Wine installation
first.  Try either `dpkg -r wine` or `rpm -e wine` or `make uninstall`
before installing.

Once installed, you can run the `winecfg` configuration tool. See the
Support area at https://www.winehq.org/ for configuration hints.


## RUNNING PROGRAMS

When invoking Wine, you may specify the entire path to the executable,
or a filename only.

For example, to run Notepad:

```
wine notepad            (using the search Path as specified in
wine notepad.exe         the registry to locate the file)

wine c:\\windows\\notepad.exe      (using DOS filename syntax)

wine ~/.wine/drive_c/windows/notepad.exe  (using Unix filename syntax)

wine notepad.exe readme.txt          (calling program with parameters)
```

Wine is not perfect, so some programs may crash. If that happens you
will get a crash log that you should attach to your report when filing
a bug.


## GETTING MORE INFORMATION

- **WWW**: A great deal of information about Wine is available from WineHQ at
	https://www.winehq.org/ : various Wine Guides, application database,
	bug tracking. This is probably the best starting point.

- **FAQ**: The Wine FAQ is located at https://gitlab.winehq.org/wine/wine/-/wikis/FAQ

- **Wiki**: The Wine Wiki is located at https://gitlab.winehq.org/wine/wine/-/wikis/

- **Gitlab**: Wine development is hosted at https://gitlab.winehq.org

- **Mailing lists**:
	There are several mailing lists for Wine users and developers; see
	https://gitlab.winehq.org/wine/wine/-/wikis/Forums for more
	information.

- **Bugs**: Report bugs to Wine Bugzilla at https://bugs.winehq.org
	Please search the bugzilla database to check whether your
	problem is already known or fixed before posting a bug report.

- **IRC**: Online help is available at channel `#WineHQ` on irc.libera.chat.
