# Recompilation limits

This repository supplies the source selected for MacRunner 1.0.7 S2. It does
not promise byte-identical reproduction of that signed release.

The published source archive contains the original reports at
`wine/ntdll-overlays/RECOMPILE-CHECK.md` and
`wine/ntdll-1.0.7/RECOMPILE-CHECK.md`; their original SHA256 values are recorded
in [published-inputs.json](published-inputs.json). This document is a public,
path-independent summary. The original archive remains the raw evidence.

The historical SDK 26.5 check reproduced 15 of 24 linked objects having a
recorded compile command. Nine others, and the unlinked control, differed in
1–17 functions. SDK 27.0 reproduced none of those objects. Compiler drift is
an inference from the evidence, not a proven attribution.

The selected 1.0.7 short rebuild recompiled only `signal_arm64.o`, retaining
25 other inputs, including `libhyperbridge.a`. Two supplier builds and the
relocated public recipe reproduced the same unsigned output SHA256
`a67f798ee7db945984830861d28cd61ef802c0a931c515a4f557684c789c07e2`.
The signal object reproduced SHA256
`23d02a23a65491c04150e76ebe40e6a0468d07a73774f017e2173a537e9f9a30`.
This is limited relink evidence, not a clean rebuild of all Wine sources.
The rejected full current-toolchain experiment changed 37 functions among
2,900. Source identity alone did not reproduce the inherited objects.

Original per-object compilation receipts, compiler patch level and a full
historical HyperBridge member-to-source build receipt are incomplete. PE source
pairings partly rely on timestamps; no full PE recompilation was performed in
the original audit. The reconstructed native-prefix-policy header is accepted
for the newly compiled signal object, not claimed as a recovered historical header.

A single full build compiles a combined source state, while the original
release combined PE architectures and native modules built at different times.
The shared ntdll header overlays apply to a clean build of every architecture;
the original PE `ntdll.dll` predates some Unix-side overlays. Current Homebrew
dependencies and GitHub's compiler/SDK can also differ from release inputs.

The public build creates every object from source and includes no retained
object/library. Its SHA comparison reports MATCH, DIFFERENT or MISSING; it
does not fail on hash differences. Raw installed files are compared with signed,
stripped, packaged release files. Native ad hoc or Apple signing, PE debug
stripping, configured paths and layout also affect whole-file SHA256.

Cloud execution remains to be verified after repository publication by the
curator. Local preparation verifies clean configure; it is not a successful
cloud run or full-product runtime acceptance.
