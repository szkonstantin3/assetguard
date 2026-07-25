# Dependency update policy

AssetGuard dependency changes are deliberate lock updates, not incidental results of unrelated work. The project requires exactly uv 0.11.28 and reviews dependency changes separately from feature changes.

## Baseline verification

Before an update, run:

```powershell
git status --short
uv --version
uv lock --check
```

The tracked tree must be clean, uv must report version 0.11.28, the current lock must validate, and hosted CI for the current commit must already be green.

## Targeted update

Prefer the narrowest update:

```powershell
uv lock --upgrade-package <package>
```

To request a particular version:

```powershell
uv lock --upgrade-package <package>==<version>
```

Inspect every transitive change. Unrelated package drift must not be accepted silently.

## Full update

A full resolution update is exceptional:

```powershell
uv lock --upgrade
```

It requires an explicit scope and a complete review of the resulting lockfile.

## Required review

Review the complete `uv.lock` diff, including:

- package additions and removals;
- every version change;
- distribution hashes;
- resolution and environment-marker changes;
- source and index changes;
- credentials, usernames, absolute paths, and other local-data leakage.

## Required validation

Run the locked dependency and application gates:

```powershell
uv lock --check
uv sync --locked --extra dev --extra build
uv pip check
uv run --locked --no-sync python -m pytest -q
uv run --locked --no-sync python -m pytest --cov=assetguard --cov-report=term-missing --cov-fail-under=90
uv run --locked --no-sync python tools/build_windows_release.py --verify-reproducible
```

After an accepted dependency change, regenerate the runtime and all-extras SBOMs and provenance, then compare and review their exact component, relationship, toolchain, source-digest, and checksum changes.

## Publication policy

A lock update uses a dedicated commit with no mixed feature work. It must not be force-pushed, and hosted CI must pass for the exact commit. Accepting or committing a lock update does not authorize a release or artifact publication. Signing and publication each require separate explicit authorization.
