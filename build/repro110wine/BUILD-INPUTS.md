# Verify every source input before compiling Wine

Use the pinned Python 3.13.7 and Xcode 27.0/27A266a cloud profile. These steps do not sign or notarize outputs.

From the repository root, run `python3 -I -B build/repro109wine/build_full.py --check-inputs`.

Then run `python3 -I -B build/repro109deps/preflight_sources.py --work "$RUNNER_TEMP/wine-source-inputs" --workers 8 --minutes 10`.

Review `wine-source-inputs/reports/RESULT.json`: every one of the 47 components must be PRESENT, with zero failures. There are 46 downloaded archives and one pinned Git source, x264; it also produces a sealed source archive. The collector checks independent inputs even when another component fails. It runs no configure, compiler, installer or upstream source code.

Only after that review, run `python3 -I -B build/repro109wine/build_full.py --profile github-xcode27-arm64 --build --work "$RUNNER_TEMP/wine-full" --jobs 3 --source-inputs "$RUNNER_TEMP/wine-source-inputs"`.

The consumer rehashes every input before any SDK compilation. It copies these verified files instead of downloading dependencies during their builds. Transfer the source set between jobs as tar, preserving x264 executable modes and Git history; the workflow performs bounded safe extraction and another complete rehash.

Each archive has a primary URL and at least one sealed fallback. A wrong SHA/size body is preserved before trying the next URL. A selected source must match the locked SHA; changing the pin to accept an HTML response is prohibited. Untried backups remain NOT_ENABLED in that run.

The new dav1d, fontconfig and zstd pins refer to published release archives and checksum metadata. Five projects currently use official generated snapshots: Ninja, Vulkan-Headers, libvpx, libvmaf and SVT-AV1. The inspected release asset lists expose no separately uploaded source archive for those versions. This exception remains open against a strict static-download requirement. x264 uses its officially documented Git URL. Exact archive sizes for FFmpeg and gst-libav remain unmeasured; their complete SHA256 and 256 MiB transfer caps are enforced.

Successful source acquisition does not prove a successful build, ARM64EC counts, function/section equivalence, application behavior or stand results. Preserve the entire failure receipt and bounded raw evidence.
