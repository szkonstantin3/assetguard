# AssetGuard

AssetGuard is a small, deterministic command-line validator for game-asset directories. Phase 07 checks file names, PNG/TGA texture dimensions, and OBJ mesh structure, detects duplicate file content with SHA-256, can reuse parsed metrics through an optional SQLite cache, and can run hashing and parser work on a bounded thread pool. It writes an authoritative JSON report, can also publish a self-contained HTML report, includes a locally prepared cross-platform CI workflow, and provides a pinned Windows x86_64 executable build. It is an MVP and is not production-ready.

## Current capabilities

- Recursive regular-file scanning with configurable excluded directory names
- Case-sensitive allowed-prefix validation for file names
- PNG and TGA power-of-two and maximum-dimension checks
- OBJ triangulation, UV coverage, triangle-count, and material-slot checks
- Chunked SHA-256 duplicate detection for every scanned file
- Optional content-addressed SQLite caching for successful texture and OBJ metrics
- Optional deterministic bounded thread parallelism for hashing and metric parsing
- Deterministic, typed JSON reports without machine-specific metadata
- Optional deterministic, escaped, self-contained HTML reports
- CI-compatible exit codes and automated tests
- A locally prepared, read-only GitHub Actions validation workflow
- A deterministic local Windows x86_64 one-file executable release profile

AssetGuard never modifies scanned assets.

## Installation

Python 3.12 or newer is required. From the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Configuration

An example is available at `examples/rules.yaml`:

```yaml
version: 1
scan:
  exclude_directories: [.git, .venv, __pycache__]
naming:
  enabled: true
  severity: error
  allowed_prefixes: [T_, M_, MI_, SM_, SK_, BP_]
textures:
  enabled: true
  severity: error
  extensions: [.png, .tga]
  require_power_of_two: true
  max_width: 4096
  max_height: 4096
meshes:
  enabled: true
  severity: error
  extensions: [.obj]
  require_triangulated: true
  require_uv: true
  max_triangles: 100000
  max_material_slots: 8
duplicates:
  enabled: true
  severity: warning
```

Unknown configuration fields and invalid values are rejected.

## OBJ validation

Phase 02 supports only OBJ meshes. The internal parser reads files incrementally as UTF-8 (including an optional BOM) and accepts face corners in the forms `v`, `v/vt`, `v//vn`, and `v/vt/vn`. Negative indexes are allowed. It checks:

- whether every face is triangulated;
- calculated triangle count (`n - 2` triangles for an `n`-corner face);
- whether every face corner contains a UV index;
- the number of unique material slots used by faces.

Faces without `usemtl` use one implicit default material slot. Empty OBJ files are valid checked meshes and emit no mesh issue. Index-range validation is not implemented in Phase 02.

## Usage

```powershell
assetguard scan ./sample_assets --config ./examples/rules.yaml --output ./assetguard-report.json
```

Add the optional HTML report while retaining the required JSON report:

```powershell
assetguard scan ./sample_assets --config ./examples/rules.yaml --output ./assetguard-report.json --html-output ./assetguard-report.html
```

Use four worker threads with `--workers` or `-j`:

```powershell
assetguard scan ./sample_assets --config ./examples/rules.yaml --output ./assetguard-report.json --workers 4
assetguard scan ./sample_assets --config ./examples/rules.yaml --output ./assetguard-report.json -j 4
```

Combine JSON, HTML, the metric cache, and parallel work:

```powershell
assetguard scan ./sample_assets --config ./examples/rules.yaml --output ./assetguard-report.json --html-output ./assetguard-report.html --cache ./.assetguard/cache.sqlite3 --workers 4
```

The module entry point is equivalent:

```powershell
python -m assetguard scan ./sample_assets --config ./examples/rules.yaml --output ./assetguard-report.json --html-output ./assetguard-report.html --cache ./.assetguard/cache.sqlite3 --workers 4
```

## HTML report

JSON remains AssetGuard's authoritative machine-readable report. The optional HTML document is rendered directly from the same completed typed report in memory; AssetGuard does not rescan assets or read the JSON file back from disk.

The single offline HTML page contains visible PASSED or FAILED status text, tool and schema information, the exact scan-summary counters, and every validation issue in the existing deterministic issue order. Structured details use canonical sorted-key JSON. All dynamic text is HTML-escaped, and the document uses embedded static CSS, a restrictive Content Security Policy, no JavaScript, no external fonts or stylesheets, no remote images, and no asset links.

Equivalent worker counts and cache miss/hit states produce byte-identical HTML, just as they do for JSON. Worker count, cache paths and statistics, timestamps, machine data, and absolute scan roots are intentionally absent from both formats.

The explicitly selected HTML path is excluded from scanning, even inside the asset root; other `.html` files are not broadly excluded. HTML output must not collide with the JSON output, configuration, cache database, or recognized SQLite sidecars. Path and write failures return exit code `2` without silently omitting the requested report.

JSON and HTML are each written atomically, but publication is not transactional across both files. AssetGuard renders HTML first, publishes the authoritative JSON, then publishes HTML. If the later HTML write fails, exit code `2` is returned and the already-published JSON may remain; the successful scan summary is not printed.

## Parallel execution

`--workers` defaults to `1` and accepts values from `1` through `32`. A value of `1` uses the synchronous Phase 03-compatible path without creating a thread pool. AssetGuard does not select a worker count from the current machine.

With more than one worker, AssetGuard first collects and sorts regular asset paths, then performs chunked SHA-256 work in parallel. Cache lookups remain ordered and coordinator-owned. Only uncached texture and OBJ metric extraction is submitted to parser workers. Validation rules, issue construction, duplicate grouping, cache writes, and report generation remain on the coordinator thread.

Results are consumed in input order even when workers finish out of order. Submission is bounded to at most twice the worker count, so the complete asset list is not submitted eagerly. Worker count, thread identities, task counts, and timing data never enter the JSON report; identical assets and rules produce the same report bytes for `--workers 1` and `--workers 4`.

## Metric cache

The optional cache is an AssetGuard-owned SQLite database keyed by the current file-content SHA-256, validator kind, and validator metric version. It stores only successful parser metrics:

- texture width and height;
- OBJ face, calculated triangle, non-triangulated-face, face-corner, UV-corner, and material-slot counts.

AssetGuard recalculates SHA-256 from the candidate file bytes before every cache lookup. It therefore still reads each configured texture and OBJ file on every scan; the cache avoids repeated Pillow or OBJ parsing, not file I/O. File size, modification time, and path are never trusted as content identity.

Phase 04 preserves that rule: candidate bytes are still read for SHA-256 before coordinator-thread cache lookup. Cache misses may be parsed concurrently, but SQLite ownership checks, reads, writes, rollback, commit, and close operations remain on the coordinator thread using SQLite's default same-thread protection.

Current configuration rules are reapplied to typed metrics after every hit, so changing thresholds, toggles, severity, or a filename takes effect without invalidating the metric entry. Naming results, duplicate groups, rule settings, final issues, and paths are not cached.

When enabled, the CLI prints `Cache hits` and `Cache misses`. These count configured content validators, not all files. Statistics and the cache path never enter the JSON report. A cache stored under the scanned root, including its `-journal`, `-wal`, and `-shm` sidecar names, is excluded from scanning.

Existing cache files must contain the AssetGuard ownership marker and supported schema. Incompatible, unrelated, locked, corrupted, or invalid-payload databases fail with exit code `2`; AssetGuard does not delete, rebuild, migrate, or repair them.

Exit codes are:

- `0`: the scan completed with no error-severity issues (warnings are allowed)
- `1`: the scan completed with one or more error-severity issues, including mesh validation errors
- `2`: configuration, input, file-read, texture/mesh parse, cache, JSON/HTML rendering, or report-write failure; malformed assets and unusable output paths use this code

Invalid worker counts and operational failures inside hash or parser workers also return `2` without a normal traceback.

## Authoritative JSON report

Reports use relative forward-slash paths and contain no timestamps or absolute paths:

```json
{
  "schema_version": 1,
  "tool": {
    "name": "AssetGuard",
    "version": "0.1.0"
  },
  "scan": {
    "root": ".",
    "files_scanned": 0,
    "textures_checked": 0,
    "meshes_checked": 0,
    "duplicate_groups": 0
  },
  "summary": {
    "errors": 0,
    "warnings": 0,
    "passed": true
  },
  "issues": []
}
```

## Tests

```powershell
python -m pytest -q
python -m pytest --cov=assetguard --cov-report=term-missing
```

## Dependency lock

The committed `uv.lock` is the authoritative exact dependency resolution for Linux CPython 3.12 and 3.13 and Windows CPython 3.12 and 3.13. Install and validate it with exactly uv 0.11.28:

```powershell
python -m pip install uv==0.11.28
uv lock --check
uv sync --locked --extra dev
uv pip check
uv sync --locked --extra dev --extra build
```

Application dependency ranges remain declared in `pyproject.toml`; exact resolved runtime, development, and Windows-build versions and distribution hashes live in `uv.lock`. Lock updates must be deliberate and reviewed. Hosted CI installs exact uv 0.11.28, checks the lock, synchronizes with `uv sync --locked`, validates the environment with `uv pip check`, and runs commands with `uv run --locked --no-sync`. The test matrix synchronizes the locked `dev` extra; Windows packaging synchronizes both the locked `dev` and `build` extras.

## Windows executable

Phase 07 defines a Windows x86_64/AMD64 one-file console build using exactly CPython 3.13.9, PyInstaller 6.21.0, and pyinstaller-hooks-contrib 2026.6. The build profile rejects a different operating system, architecture, Python patch version, or PyInstaller toolchain before generating artifacts. Install the dedicated development and build extras without adding PyInstaller to AssetGuard's runtime dependencies:

```powershell
python -m pip install uv==0.11.28
uv lock --check
uv sync --locked --extra dev --extra build --python 3.13.9
uv pip check
```

Create one locally validated artifact set:

```powershell
uv run --locked --no-sync python tools/build_windows_release.py
```

Build two independent clean copies with the controlled toolchain and require byte-identical executable, ZIP, manifest, and checksum outputs before publication into `dist/release`:

```powershell
uv run --locked --no-sync python tools/build_windows_release.py --verify-reproducible
uv run --locked --no-sync python -m pytest -q tests/test_windows_packaging.py
```

The release directory contains exactly these versioned files for version `0.1.0`:

- `AssetGuard-0.1.0-windows-x86_64.exe`;
- `AssetGuard-0.1.0-windows-x86_64.zip`;
- `AssetGuard-0.1.0-windows-x86_64.manifest.json`;
- `AssetGuard-0.1.0-windows-x86_64.sha256`.

The executable exposes the existing command hierarchy directly, for example:

```powershell
dist\release\AssetGuard-0.1.0-windows-x86_64.exe --help
dist\release\AssetGuard-0.1.0-windows-x86_64.exe scan ./sample_assets --config ./examples/rules.yaml --output ./assetguard-report.json
```

The ZIP has one root directory and includes exactly `AssetGuard.exe`, `README.md`, and `examples/rules.yaml`. The canonical manifest records the pinned toolchain, source-input digest, and payload hashes. The checksum file verifies the published executable, ZIP, and manifest.

The reproducibility claim is deliberately limited to a **same-toolchain byte-repeatable build**: two clean builds on the same Windows machine with the same CPython 3.13.9 interpreter, pinned PyInstaller versions, controlled environment, and identical sources. It is not a cross-machine, cross-Windows-version, cross-Python-patch, or post-signing reproducibility claim. Packaged runtime proof compares JSON and HTML reports byte-for-byte with `python -m assetguard`, exercises cache and worker-4 behavior, demonstrates exits `0`, `1`, and `2`, and checks Unicode paths without modifying proof assets.

There is no installer, code signature, remote upload, or artifact publication in this phase. A separate clean Windows-machine compatibility test is still required before public distribution. Final files are individually published through temporary siblings and atomic replacement where practical, but the four-file publication is not transactionally atomic as a group.

## Supply-chain metadata

After validating a current four-file Windows release, generate deterministic local metadata with exact uv 0.11.28:

```powershell
uv run --locked --no-sync python tools/generate_supply_chain.py --release-dir dist/release --output-dir build/supply-chain/local --source-commit <40-lowercase-commit-sha>
```

The output directory contains `AssetGuard-0.1.0-runtime.cdx.json`, `AssetGuard-0.1.0-all-extras.cdx.json`, `AssetGuard-0.1.0-windows-x86_64.provenance.json`, and `AssetGuard-0.1.0-supply-chain.sha256`. The runtime CycloneDX 1.5 SBOM contains application dependencies; the all-extras SBOM also contains declared development and Windows-build dependencies. Provenance is unsigned local metadata; no SLSA level or signature is claimed. Generation does not upload or publish artifacts.

See [Supply-chain metadata](docs/supply-chain.md) for the deterministic format and build-type contract, and [Dependency update policy](docs/dependency-update-policy.md) for deliberate lock maintenance.

## Continuous integration

The locally prepared workflow is stored at `.github/workflows/ci.yml`. It is configured for unrestricted `push` and `pull_request` events plus manual `workflow_dispatch` runs, without assuming a future default branch name. Superseded runs for the same workflow and Git reference are cancelled.

One test job expands to a four-leg matrix:

- Ubuntu (`ubuntu-latest`) with Python 3.12;
- Ubuntu (`ubuntu-latest`) with Python 3.13;
- Windows (`windows-latest`) with Python 3.12;
- Windows (`windows-latest`) with Python 3.13.

Every leg installs exact uv 0.11.28, validates `uv.lock`, synchronizes the locked `dev` extra for its matrix Python, checks dependency consistency with `uv pip check`, runs the full test suite with a 90% coverage gate, and smoke-tests both the module and installed `assetguard` entry points through `uv run --locked --no-sync`. The workflow disables Git's automatic CRLF conversion through scoped process configuration so the lock bytes remain identical on Windows and Linux. Repository permission is limited to `contents: read`, checkout credentials are not persisted, and the only external actions are official GitHub actions pinned to immutable commits:

- `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` (`v7.0.1`);
- `actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97` (`v7.0.0`).

The local equivalent commands are:

```powershell
python -m pip install uv==0.11.28
uv --version
uv lock --check
uv sync --locked --extra dev --python 3.13.9
uv pip check
uv run --locked --no-sync python -m pytest -q --cov=assetguard --cov-report=term-missing --cov-fail-under=90
uv run --locked --no-sync python -m assetguard --help
uv run --locked --no-sync python -m assetguard scan --help
uv run --locked --no-sync assetguard --help
uv run --locked --no-sync assetguard scan --help
```

The locked workflow configuration is contract-tested locally. Its cross-platform status is established only by a completed GitHub-hosted run for the exact commit being evaluated; no CI badge is maintained in this phase.

A dependent `package-windows` job uses Windows and Python 3.13.9 to synchronize the locked `dev` and `build` extras, verify dependencies, run the two-build reproducibility proof, and inspect the generated artifacts through `uv run --locked --no-sync`. It does not upload, sign, release, or publish them.

## Current limitations

Phase 07 supports only OBJ meshes and does not validate referenced index ranges. It has no multiprocessing, automatic worker selection, parallel SQLite access, or metadata-only cache shortcut. Candidate file bytes are still read for SHA-256 on every applicable scan. Concurrent modification of assets during a scan is unsupported, and performance depends on the filesystem and asset types.

The HTML report is static and has no interactive filtering, charts, PDF export, historical analytics, or live asset links. The cache has no pruning, migration, parallel-access guarantee, or repair command. AssetGuard has no GUI, asset repair or conversion, other mesh formats, full filesystem incremental skipping, Blender integration, or engine integration. The executable has no installer or code signature. Hosted results remain commit-specific, and local validation alone does not prove every supported runner and Python combination.

## Roadmap

- Clean Windows-machine executable verification
- Code signing
- Explicitly authorized artifact publication
- Broader mesh-format support
- Unreal Engine integration
