# Candidate c33r Wine source delta

This stage adds the pinned `release111-c33r.patch` after the existing c12 overlay, keyboard patch and c32r cumulative delta. All 75 changed files have exact preimage/result identities in `release111-source.lock.json`. Source preparation is separate from compilation, release acceptance and publication.

The exported DLL source targets agree between the native and PE source snapshots. The generated `configure` comes from the actual PE build: both snapshots share the same `configure.ac`, while the native-only generated script predates the accepted ARM64EC `-fasync-exceptions` detection. The delta uses the newer generated script and does not change product defaults.

The export was reconstructed from pinned revision `b812a090e2ca58c3902008929facd71f15fc3fc4` using the existing guarded source pipeline. The cumulative patch was checked/applied and the result compared with the candidate source snapshots. The prior compiler/build recipe repairs are retained.

This covers Wine DLL sources. The two loader source/packaging files are excluded and require their separate acceptance. HyperBridge, FEX, graphics component exports, final helper deployment-target alignment and cloud binary reproduction remain separate release checks. No Developer ID signing, notarization or publication is enabled by this stage.

The five legacy private Xcode Cloud dispatcher tests explicitly require their two dispatcher fixture scripts. Public-only checkouts do not contain those scripts and report these tests as skipped, not passed. The public source/build-driver checks remain enabled.
