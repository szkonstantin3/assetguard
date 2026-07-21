# Windows Sandbox clean-room verification

Phase 08 verifies the existing Phase 07 Windows bundle inside a disposable Windows Sandbox. The objective is to prove that the packaged executables work without the AssetGuard source tree, a virtual environment, a usable Python runtime, dependency installation, or network access.

## Prerequisites

- Windows AMD64 with Windows Sandbox already installed and available.
- The unchanged four-file Phase 07 release under `dist/release`.
- Python on the host only, for the standard-library verifier.

The verifier detects `WindowsSandbox.exe` in the trusted Windows System32 directory. It does not enable Windows Sandbox, change optional features, configure Hyper-V, install software, or alter Windows security settings.

Run from the project root:

```powershell
python tools/verify_windows_sandbox.py
```

Before launch, the host verifies every Phase 07 artifact hash, the checksum file, manifest, source digest, and exact ZIP payload. The generated `.wsb` configuration disables networking, vGPU, clipboard, printer, audio-input, and video-input redirection. It maps only:

- `dist/release` to `C:\AssetGuardRelease` as read-only;
- the scoped ignored exchange directory to `C:\AssetGuardExchange` as writable.

No project root, `src`, `.git`, virtual environment, user profile, package cache, or other host drive is mapped. The generated `.wsb` file contains the necessary absolute host paths only at runtime under `build/windows-clean-room/session`; no absolute host path is committed.

## Runtime proof

The built-in Windows PowerShell verifier checks that no usable `python`, `python3`, `py`, or `pip` command is available. It validates the release and ZIP payload independently, extracts only into Sandbox-local storage, and runs both the versioned executable and extracted `AssetGuard.exe` by absolute path.

The proof exercises help, scan help, valid and warning-only exit `0`, validation exit `1`, malformed-asset exit `2`, no traceback or failed-report publication, workers `4`, SQLite cache hits, JSON, HTML, output/cache self-exclusion, Unicode paths, PNG, TGA, OBJ, duplicate, naming, triangulation, and non-destructive asset behavior. Standalone and extracted JSON and HTML outputs must be byte-identical.

The Sandbox writes `sandbox-result.json` and its SHA-256 sidecar to the exchange mapping. The host verifies the checksum before parsing the result, validates every required passing check, re-hashes the host release directory, and writes the canonical ignored proof to:

```text
build/windows-clean-room/proof/
  AssetGuard-0.1.0-windows-x86_64.clean-room-proof.json
  AssetGuard-0.1.0-windows-x86_64.clean-room-proof.sha256
```

These proof files are local verification evidence, not release artifacts, and are never copied into `dist/release`.

## Proof boundaries

- The Phase 07 development-machine proof established same-toolchain byte-repeatability and packaged behavior on the build host.
- A successful Phase 08 Windows Sandbox run establishes an isolated local clean-room proof with no source mapping, usable Python runtime, or network.
- An independent external clean Windows-machine proof remains preferable before broad public distribution.

If Windows Sandbox is missing, disabled, cannot launch, times out, or returns invalid evidence, the command fails without enabling or repairing the feature. Static verifier tests may still pass, but they do not constitute a clean-room runtime proof.

The verifier never rebuilds or modifies the Phase 07 release, accesses the network, signs code, uploads artifacts, or publishes a release.
