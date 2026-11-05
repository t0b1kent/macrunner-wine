# Building the MacRunner Wine runtime on GitHub

The `repro110wine` recipe builds the c32r runtime from the pinned Wine revision,
the ordered c12 overlays and the sealed cumulative release patch. Published
runtime modules, local installations and Homebrew libraries are not build inputs.
The recipe checks every required base file and overlay before applying changes.

Use `.github/workflows/repro110-wine-c12-xcode27-arm64.yml` in a clean checkout of
`t0b1kent/macrunner-wine`. Start with `phase=inputs`, review its complete input
receipt, then select `phase=full`. Optional `deps_run`/`deps_sha` and
`source_run`/`source_sha` pairs reuse an explicitly selected public artifact;
the driver rechecks its contents against the current locks. Read the current
workflow inputs before dispatching a run.

The pinned cloud profile uses the `xcode-27` ARM64 runner, Python 3.13.7,
Xcode 27.0/27A266a and SDK 27.0. SDK preflight checks both x18 ABI exports before
downloads. There is no SDK fallback. The full driver uses a fresh work directory,
two build jobs and a 330-minute deadline, bounded by the 360-minute workflow job.

## ARM64EC compiler requirement

The build tool is the official llvm-mingw **20260908**, containing LLVM 23.1.1.
Its archive is pinned in both Wine locks to SHA256
`d1dc5d1ecf3a3ced5ed5544c72f1acd0c8e84eb3024d520ecc6b143eec62a149`
and 124244100 bytes. This upstream compiler archive is a build dependency;
the recipe does not claim to build the cross compiler from source.

LLVM 22.1.5 emitted ARM64EC variadic exit thunks that placed the x4/x5 descriptor
on the x64 stack instead of copying its payload. An SCM call could consequently
deliver `0x10` as an output pointer and fault inside RPC context unmarshalling.
[LLVM PR 190933](https://github.com/llvm/llvm-project/pull/190933) fixes this ABI
boundary. The compiler update applies to all four Wine targets and all generated
variadic call sites. Do not restore the 20260505 compiler pin.

The compile driver verifies the archive hash and link graph before extraction,
requires all ten compiler/linker entry points to stay inside its root and records
the selected binary hashes. Inert transport tests cover redirects, missing tools
and escaping links, including the extraction path used by Apple Python.

## Outputs and acceptance

The workflow builds source dependencies, pinned MoltenVK and Wine targets
`aarch64`, `arm64ec`, `x86_64` and `i386`. It retains build logs, producer receipts,
source manifests, archive hashes and the first failure. `check-build-srcdir.sh`
and `check-arm64ec-dist.py` validate the selected build and install trees.
An `install skipped` result cannot be accepted as a complete runtime.

Source-built FEX and graphics components are produced by their separate pinned
workflows. Release composition must select actual successful artifact IDs,
commit hashes and digests. A successful Wine build is not release acceptance:
the complete signed package still needs the native and graphics gates, isolated
functional game checks, updater verification and curator-run notarization.
