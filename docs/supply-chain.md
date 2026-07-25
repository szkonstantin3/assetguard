# Supply-chain metadata

AssetGuard can generate deterministic local dependency and build metadata after validating a current Windows release. The generator uses the locked dependency graph and does not import application runtime code.

Run it from the project root with exact uv 0.11.28:

```powershell
uv run --locked --no-sync python tools/generate_supply_chain.py --release-dir dist/release --output-dir build/supply-chain/local --source-commit <40-lowercase-commit-sha>
```

The selected output directory contains exactly:

- `AssetGuard-0.1.0-runtime.cdx.json`;
- `AssetGuard-0.1.0-all-extras.cdx.json`;
- `AssetGuard-0.1.0-windows-x86_64.provenance.json`;
- `AssetGuard-0.1.0-supply-chain.sha256`.

The runtime SBOM represents base application dependencies. The all-extras SBOM also includes the declared development and Windows build dependencies. Both are CycloneDX 1.5 documents exported by uv 0.11.28 from `uv.lock`.

The generator removes uv's nondeterministic CycloneDX serial number and metadata timestamp, adds the scope, uv version, and current lock digest, and deterministically orders components, dependency edges, properties, hashes, and JSON keys. Unknown CycloneDX fields remain intact. Output uses UTF-8, LF line endings, two-space JSON indentation, and one final newline.

## AssetGuard Windows release build type v1

<a id="assetguard-windows-release-build-type-v1"></a>

The build type URI identifies the following local process:

- input is the public AssetGuard repository at one explicit 40-character commit;
- dependency input is the exact graph in `uv.lock`;
- the release profile is Windows x86_64 with CPython 3.13.9, PyInstaller 6.21.0, and pyinstaller-hooks-contrib 2026.6;
- the source epoch is fixed at `1767225600`;
- `uv run --locked --no-sync python tools/build_windows_release.py --verify-reproducible` builds two independent copies and requires byte equality;
- the resulting release set is the versioned executable, ZIP, manifest, and checksum file;
- the two SBOMs are exported only after that four-file release passes PE, checksum, manifest, ZIP, payload, and current-source-digest validation.

The builder ID is the public `tools/build_windows_release.py` path in the repository. The provenance subjects are the four validated release files and both normalized SBOMs. Resolved dependency descriptors bind the source commit, the SHA-256 of `uv.lock`, and the deterministic release source-input digest.

The provenance is an in-toto Statement v1 whose predicate type is SLSA provenance v1. It contains no timestamps, run identifiers, host identity, local paths, or invocation environment. Provenance is unsigned local metadata; no SLSA level or signature is claimed.

The generator does not sign, upload, release, or publish any file. `build/supply-chain/` is ignored local proof output. Files are generated and validated in a temporary sibling directory, then individually replaced atomically. The four replacements are not transactionally atomic as one filesystem operation; a process or machine interruption can still require regeneration, although handled publication failures attempt to restore the previous set.

Validate a generated directory by rerunning the exact command and comparing all four output files byte-for-byte. The checksum file covers the two SBOMs and provenance; provenance subjects separately cover the validated release artifacts.

Current limitations: uv's CycloneDX export is a preview feature; the metadata is local and unsigned, makes no SLSA-level claim, is not an attestation service result, and is not uploaded automatically. It describes only the current Linux/Windows CPython 3.12/3.13 dependency-lock contract and the Windows x86_64 release profile. Dependency updates follow [the dependency update policy](dependency-update-policy.md).
