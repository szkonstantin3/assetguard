"""Generate deterministic local SBOM and provenance metadata for AssetGuard."""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import getpass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit
import zipfile

if __package__:
    from tools import build_windows_release as build
else:
    import build_windows_release as build


PROJECT_ROOT = Path(__file__).resolve().parents[1]
UV_VERSION = "0.11.28"
CYCLONEDX_FORMAT = "cyclonedx1.5"
PROJECT_NAME = "AssetGuard"
PROJECT_VERSION = "0.1.0"
SOURCE_DATE_EPOCH = 1767225600
REPOSITORY_URL = "https://github.com/szkonstantin3/assetguard"
BUILD_TYPE = (
    REPOSITORY_URL
    + "/blob/main/docs/supply-chain.md#assetguard-windows-release-build-type-v1"
)
BUILDER_ID = REPOSITORY_URL + "/blob/main/tools/build_windows_release.py"
UNSIGNED_WARNING = (
    "Provenance is unsigned local metadata; no SLSA level or signature is claimed."
)
RUNTIME_SBOM_NAME = f"AssetGuard-{PROJECT_VERSION}-runtime.cdx.json"
ALL_EXTRAS_SBOM_NAME = f"AssetGuard-{PROJECT_VERSION}-all-extras.cdx.json"
PROVENANCE_NAME = (
    f"AssetGuard-{PROJECT_VERSION}-windows-x86_64.provenance.json"
)
SUPPLY_CHAIN_CHECKSUM_NAME = f"AssetGuard-{PROJECT_VERSION}-supply-chain.sha256"
OUTPUT_NAMES = (
    ALL_EXTRAS_SBOM_NAME,
    PROVENANCE_NAME,
    RUNTIME_SBOM_NAME,
    SUPPLY_CHAIN_CHECKSUM_NAME,
)
RELEASE_STEM = f"AssetGuard-{PROJECT_VERSION}-windows-x86_64"
RELEASE_NAMES = (
    f"{RELEASE_STEM}.exe",
    f"{RELEASE_STEM}.manifest.json",
    f"{RELEASE_STEM}.sha256",
    f"{RELEASE_STEM}.zip",
)
PAYLOAD_PATHS = ("AssetGuard.exe", "README.md", "examples/rules.yaml")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SOURCE_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
CHECKSUM_LINE_RE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$")
FORBIDDEN_SCOPE_PACKAGES = {
    "pytest",
    "pytest-cov",
    "pyinstaller",
    "pyinstaller-hooks-contrib",
}


class SupplyChainError(Exception):
    """Raised for an expected supply-chain generation failure."""


@dataclass(frozen=True)
class ValidatedRelease:
    """Validated release paths and content-derived metadata."""

    artifacts: build.ReleaseArtifactSet
    hashes: Mapping[str, str]
    source_digest: str


@dataclass(frozen=True)
class GenerationResult:
    """Published supply-chain paths and deterministic summary metadata."""

    paths: tuple[Path, ...]
    hashes: Mapping[str, str]
    runtime_components: int
    all_extras_components: int
    source_digest: str


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""

    return hashlib.sha256(data).hexdigest()


def canonical_json(document: Mapping[str, Any]) -> bytes:
    """Serialize canonical project JSON with a single LF newline."""

    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def parse_uv_version(output: str) -> str:
    """Extract a semantic uv version from the official version output."""

    match = re.fullmatch(r"uv ([0-9]+\.[0-9]+\.[0-9]+)(?:\s+.*)?\r?\n?", output)
    if match is None:
        raise SupplyChainError("cannot parse uv version output")
    return match.group(1)


def validate_source_commit(source_commit: str) -> None:
    """Require a full lowercase hexadecimal Git commit identifier."""

    if SOURCE_COMMIT_RE.fullmatch(source_commit) is None:
        raise SupplyChainError("source commit must be exactly 40 lowercase hexadecimal characters")


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_directory_relationship(release_dir: Path, output_dir: Path) -> None:
    """Reject equal or nested release/output directories."""

    release = release_dir.resolve()
    output = output_dir.resolve()
    if release == output or _is_within(release, output) or _is_within(output, release):
        raise SupplyChainError("release and output directories must be separate and non-nested")


def controlled_uv_environment() -> dict[str, str]:
    """Build a small environment sufficient for a local locked uv export."""

    allowed = {
        "APPDATA",
        "COMSPEC",
        "HOME",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    environment["PYTHONUTF8"] = "1"
    environment["UV_NO_PROGRESS"] = "1"
    return environment


def uv_export_command(uv_executable: str, output_file: Path, *, all_extras: bool) -> list[str]:
    """Return the exact locked CycloneDX export command."""

    command = [
        uv_executable,
        "export",
        "--locked",
        "--format",
        CYCLONEDX_FORMAT,
    ]
    if all_extras:
        command.append("--all-extras")
    command.extend(["--output-file", str(output_file)])
    return command


def _run_uv(command: Sequence[str], *, project_root: Path) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command),
            cwd=project_root,
            env=controlled_uv_environment(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            check=False,
        )
    except (OSError, UnicodeError) as exc:
        raise SupplyChainError(f"cannot execute uv: {exc}") from exc
    if result.returncode != 0:
        diagnostic = (result.stderr or result.stdout).strip().splitlines()
        detail = " | ".join(diagnostic[-8:]) or f"exit code {result.returncode}"
        raise SupplyChainError(f"uv command failed: {detail}")
    return result


def verify_uv(project_root: Path) -> tuple[str, str]:
    """Require exact uv, validate the lock, and return executable and lock hash."""

    executable = shutil.which("uv")
    if executable is None:
        raise SupplyChainError(f"uv {UV_VERSION} is required")
    version_result = _run_uv([executable, "--version"], project_root=project_root)
    actual_version = parse_uv_version(version_result.stdout)
    if actual_version != UV_VERSION:
        raise SupplyChainError(f"uv {UV_VERSION} is required; found {actual_version}")
    lock_path = project_root / "uv.lock"
    if not lock_path.is_file():
        raise SupplyChainError("required project file is missing: uv.lock")
    before = build.sha256_file(lock_path)
    _run_uv([executable, "lock", "--check"], project_root=project_root)
    after = build.sha256_file(lock_path)
    if before != after:
        raise SupplyChainError("uv.lock changed during validation")
    return executable, before


def _require_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise SupplyChainError(f"{label} must be a JSON object")
    return value


def _require_list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SupplyChainError(f"{label} must be a JSON array")
    return value


def load_raw_sbom(path: Path) -> dict[str, Any]:
    """Load and structurally validate a uv CycloneDX 1.5 document."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SupplyChainError(f"invalid CycloneDX export '{path.name}': {exc}") from exc
    root = _require_object(document, "CycloneDX document")
    if root.get("bomFormat") != "CycloneDX" or root.get("specVersion") != "1.5":
        raise SupplyChainError("uv export is not CycloneDX 1.5")
    if not isinstance(root.get("version"), int):
        raise SupplyChainError("CycloneDX version must be an integer")
    metadata = _require_object(root.get("metadata"), "CycloneDX metadata")
    project = _require_object(metadata.get("component"), "CycloneDX project component")
    if str(project.get("name", "")).casefold() != PROJECT_NAME.casefold():
        raise SupplyChainError("CycloneDX project component is not AssetGuard")
    _require_list(root.get("components"), "CycloneDX components")
    if "dependencies" in root:
        _require_list(root["dependencies"], "CycloneDX dependencies")
    return root


def _sort_name_value(items: object, label: str) -> list[dict[str, Any]]:
    values = _require_list(items, label)
    typed = [_require_object(value, f"{label} entry") for value in values]
    return sorted(typed, key=lambda value: (str(value.get("name", "")), str(value.get("value", ""))))


def _normalize_component(component: dict[str, Any]) -> None:
    if "properties" in component:
        component["properties"] = _sort_name_value(component["properties"], "component properties")
    if "hashes" in component:
        hashes = _require_list(component["hashes"], "component hashes")
        component["hashes"] = sorted(
            [_require_object(value, "component hash") for value in hashes],
            key=lambda value: (str(value.get("alg", "")), str(value.get("content", ""))),
        )


def _component_names(document: Mapping[str, Any]) -> set[str]:
    components = _require_list(document.get("components"), "CycloneDX components")
    return {
        str(_require_object(component, "CycloneDX component").get("name", "")).casefold()
        for component in components
    }


def normalize_sbom(raw: Mapping[str, Any], *, scope: str, lock_sha256: str) -> dict[str, Any]:
    """Remove unstable fields and deterministically order a uv CycloneDX export."""

    if scope not in {"runtime", "all-extras"}:
        raise SupplyChainError(f"unsupported SBOM scope: {scope}")
    if SHA256_RE.fullmatch(lock_sha256) is None:
        raise SupplyChainError("uv.lock digest is invalid")
    document = copy.deepcopy(_require_object(dict(raw), "CycloneDX document"))
    document.pop("serialNumber", None)
    metadata = _require_object(document.get("metadata"), "CycloneDX metadata")
    metadata.pop("timestamp", None)
    project_component = _require_object(metadata.get("component"), "CycloneDX project component")
    _normalize_component(project_component)
    existing = metadata.get("properties", [])
    properties = _sort_name_value(existing, "metadata properties")
    reserved = {
        "assetguard:scope",
        "assetguard:uv-version",
        "assetguard:uv-lock-sha256",
    }
    properties = [item for item in properties if item.get("name") not in reserved]
    properties.extend(
        [
            {"name": "assetguard:scope", "value": scope},
            {"name": "assetguard:uv-lock-sha256", "value": lock_sha256},
            {"name": "assetguard:uv-version", "value": UV_VERSION},
        ]
    )
    metadata["properties"] = sorted(
        properties,
        key=lambda value: (str(value.get("name", "")), str(value.get("value", ""))),
    )
    components = _require_list(document.get("components"), "CycloneDX components")
    typed_components = [_require_object(component, "CycloneDX component") for component in components]
    for component in typed_components:
        _normalize_component(component)
    document["components"] = sorted(
        typed_components,
        key=lambda value: (
            str(value.get("bom-ref", "")),
            str(value.get("purl", "")),
            str(value.get("name", "")),
            str(value.get("version", "")),
        ),
    )
    if "dependencies" in document:
        dependencies = [
            _require_object(value, "CycloneDX dependency")
            for value in _require_list(document["dependencies"], "CycloneDX dependencies")
        ]
        for dependency in dependencies:
            if "dependsOn" in dependency:
                depends_on = _require_list(dependency["dependsOn"], "dependency dependsOn")
                if not all(isinstance(value, str) for value in depends_on):
                    raise SupplyChainError("dependency dependsOn values must be strings")
                dependency["dependsOn"] = sorted(depends_on)
        document["dependencies"] = sorted(
            dependencies, key=lambda value: str(value.get("ref", ""))
        )
    names = _component_names(document)
    if scope == "runtime" and names & FORBIDDEN_SCOPE_PACKAGES:
        unexpected = ", ".join(sorted(names & FORBIDDEN_SCOPE_PACKAGES))
        raise SupplyChainError(f"runtime SBOM contains development/build packages: {unexpected}")
    if scope == "all-extras" and not FORBIDDEN_SCOPE_PACKAGES <= names:
        missing = ", ".join(sorted(FORBIDDEN_SCOPE_PACKAGES - names))
        raise SupplyChainError(f"all-extras SBOM is missing required packages: {missing}")
    return document


def _release_artifacts(release_dir: Path) -> build.ReleaseArtifactSet:
    expected = set(RELEASE_NAMES)
    try:
        actual = {path.name for path in release_dir.iterdir()}
    except OSError as exc:
        raise SupplyChainError(f"cannot inspect release directory: {exc}") from exc
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unexpected " + ", ".join(extra))
        raise SupplyChainError("release directory must contain exactly four expected files: " + "; ".join(detail))
    paths = {name: release_dir / name for name in expected}
    if not all(path.is_file() for path in paths.values()):
        raise SupplyChainError("release artifact paths must be regular files")
    return build.ReleaseArtifactSet(
        executable=paths[f"{RELEASE_STEM}.exe"],
        archive=paths[f"{RELEASE_STEM}.zip"],
        manifest=paths[f"{RELEASE_STEM}.manifest.json"],
        checksums=paths[f"{RELEASE_STEM}.sha256"],
    )


def _parse_release_checksums(path: Path) -> dict[str, str]:
    try:
        data = path.read_bytes()
        text = data.decode("ascii")
    except (OSError, UnicodeError) as exc:
        raise SupplyChainError(f"invalid release checksum file: {exc}") from exc
    if b"\r" in data or not data.endswith(b"\n") or data.endswith(b"\n\n"):
        raise SupplyChainError("release checksum file must use LF and one final newline")
    result: dict[str, str] = {}
    filenames: list[str] = []
    for line in text[:-1].split("\n"):
        match = CHECKSUM_LINE_RE.fullmatch(line)
        if match is None:
            raise SupplyChainError("release checksum file has invalid syntax")
        digest, filename = match.groups()
        if filename in result or Path(filename).name != filename or "/" in filename or "\\" in filename:
            raise SupplyChainError("release checksum file contains an unsafe or duplicate filename")
        result[filename] = digest
        filenames.append(filename)
    if filenames != sorted(filenames):
        raise SupplyChainError("release checksum lines must be sorted by filename")
    expected = {f"{RELEASE_STEM}.exe", f"{RELEASE_STEM}.zip", f"{RELEASE_STEM}.manifest.json"}
    if set(result) != expected:
        raise SupplyChainError("release checksum file must cover the executable, ZIP, and manifest exactly")
    return result


def _load_release_manifest(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SupplyChainError(f"invalid release manifest: {exc}") from exc
    return _require_object(document, "release manifest")


def validate_release(release_dir: Path, *, project_root: Path = PROJECT_ROOT) -> ValidatedRelease:
    """Validate a complete current Windows release without modifying it."""

    if not release_dir.is_dir():
        raise SupplyChainError("release directory does not exist")
    artifacts = _release_artifacts(release_dir)
    try:
        build.validate_amd64_pe(artifacts.executable)
    except build.BuildError as exc:
        raise SupplyChainError(str(exc)) from exc
    declared = _parse_release_checksums(artifacts.checksums)
    actual = {
        artifacts.executable.name: build.sha256_file(artifacts.executable),
        artifacts.archive.name: build.sha256_file(artifacts.archive),
        artifacts.manifest.name: build.sha256_file(artifacts.manifest),
    }
    if declared != actual:
        raise SupplyChainError("release checksum verification failed")
    manifest = _load_release_manifest(artifacts.manifest)
    expected_product = {
        "name": PROJECT_NAME,
        "version": PROJECT_VERSION,
        "platform": "windows",
        "architecture": "x86_64",
        "format": "pyinstaller-onefile",
    }
    expected_toolchain = {
        "python": build.REQUIRED_PYTHON,
        "pyinstaller": build.REQUIRED_PYINSTALLER,
        "pyinstaller_hooks_contrib": build.REQUIRED_HOOKS,
        "source_date_epoch": SOURCE_DATE_EPOCH,
    }
    if set(manifest) != {"schema_version", "product", "toolchain", "source", "payload"}:
        raise SupplyChainError("release manifest has unexpected or missing fields")
    if manifest.get("schema_version") != 1 or manifest.get("product") != expected_product:
        raise SupplyChainError("release manifest product contract is invalid")
    if manifest.get("toolchain") != expected_toolchain:
        raise SupplyChainError("release manifest toolchain contract is invalid")
    try:
        current_source_digest = build.calculate_source_digest(project_root)
    except build.BuildError as exc:
        raise SupplyChainError(str(exc)) from exc
    if manifest.get("source") != {"sha256": current_source_digest}:
        raise SupplyChainError("release manifest source digest does not match current source inputs")
    payload = _require_list(manifest.get("payload"), "release manifest payload")
    entries = [_require_object(value, "release manifest payload entry") for value in payload]
    if [entry.get("path") for entry in entries] != list(PAYLOAD_PATHS):
        raise SupplyChainError("release manifest payload paths are invalid")
    for entry in entries:
        if set(entry) != {"path", "size", "sha256"}:
            raise SupplyChainError("release manifest payload entry has invalid fields")
        if not isinstance(entry["size"], int) or entry["size"] < 0:
            raise SupplyChainError("release manifest payload size is invalid")
        if not isinstance(entry["sha256"], str) or SHA256_RE.fullmatch(entry["sha256"]) is None:
            raise SupplyChainError("release manifest payload digest is invalid")
    entry_map = {str(entry["path"]): entry for entry in entries}
    expected_members = [f"{RELEASE_STEM}/{path}" for path in PAYLOAD_PATHS]
    try:
        with zipfile.ZipFile(artifacts.archive) as archive:
            names = archive.namelist()
            if names != expected_members:
                raise SupplyChainError("release ZIP members or ordering are invalid")
            payload_bytes: dict[str, bytes] = {}
            for member, payload_path in zip(names, PAYLOAD_PATHS, strict=True):
                build.validate_archive_path(member)
                data = archive.read(member)
                payload_bytes[payload_path] = data
                entry = entry_map[payload_path]
                if len(data) != entry["size"] or sha256_bytes(data) != entry["sha256"]:
                    raise SupplyChainError(f"release ZIP payload is invalid: {payload_path}")
    except (OSError, zipfile.BadZipFile, KeyError, build.BuildError) as exc:
        if isinstance(exc, SupplyChainError):
            raise
        raise SupplyChainError(f"invalid release ZIP: {exc}") from exc
    try:
        executable_bytes = artifacts.executable.read_bytes()
    except OSError as exc:
        raise SupplyChainError(f"cannot read release executable: {exc}") from exc
    if executable_bytes != payload_bytes["AssetGuard.exe"]:
        raise SupplyChainError("standalone executable does not match the ZIP payload")
    hashes = {path.name: build.sha256_file(path) for path in artifacts.ordered_paths()}
    return ValidatedRelease(artifacts=artifacts, hashes=hashes, source_digest=current_source_digest)


def build_provenance(
    release: ValidatedRelease,
    *,
    runtime_sbom: Path,
    all_extras_sbom: Path,
    source_commit: str,
    lock_sha256: str,
) -> dict[str, Any]:
    """Build a deterministic unsigned in-toto/SLSA provenance statement."""

    validate_source_commit(source_commit)
    subject_paths = list(release.artifacts.ordered_paths()) + [runtime_sbom, all_extras_sbom]
    subjects = [
        {"name": path.name, "digest": {"sha256": build.sha256_file(path)}}
        for path in sorted(subject_paths, key=lambda value: value.name)
    ]
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "repository": REPOSITORY_URL,
                    "sourceCommit": source_commit,
                    "buildCommand": [
                        "uv",
                        "run",
                        "--locked",
                        "--no-sync",
                        "python",
                        "tools/build_windows_release.py",
                        "--verify-reproducible",
                    ],
                    "platform": "windows",
                    "architecture": "x86_64",
                },
                "internalParameters": {
                    "python": build.REQUIRED_PYTHON,
                    "uv": UV_VERSION,
                    "pyinstaller": build.REQUIRED_PYINSTALLER,
                    "pyinstallerHooksContrib": build.REQUIRED_HOOKS,
                    "sourceDateEpoch": SOURCE_DATE_EPOCH,
                    "repeatabilityMode": "same-toolchain-two-build",
                },
                "resolvedDependencies": sorted(
                    [
                    {
                        "uri": "file:uv.lock",
                        "name": "uv.lock",
                        "digest": {"sha256": lock_sha256},
                    },
                    {
                        "uri": "urn:assetguard:windows-release-source-inputs:v1",
                        "name": "AssetGuard Windows release source inputs",
                        "digest": {"sha256": release.source_digest},
                    },
                    {
                        "uri": f"git+{REPOSITORY_URL}@{source_commit}",
                        "digest": {"gitCommit": source_commit},
                    },
                    ],
                    key=lambda value: str(value["uri"]),
                ),
            },
            "runDetails": {
                "builder": {
                    "id": BUILDER_ID,
                    "version": {
                        "assetguardBuildProfile": "1",
                        "python": build.REQUIRED_PYTHON,
                        "uv": UV_VERSION,
                        "pyinstaller": build.REQUIRED_PYINSTALLER,
                        "pyinstallerHooksContrib": build.REQUIRED_HOOKS,
                    },
                }
            },
        },
    }


def serialize_supply_chain_checksums(files: Mapping[str, bytes]) -> bytes:
    """Serialize hashes for the two SBOMs and provenance in lexical order."""

    expected = {RUNTIME_SBOM_NAME, ALL_EXTRAS_SBOM_NAME, PROVENANCE_NAME}
    if set(files) != expected:
        raise SupplyChainError("supply-chain checksum inputs are incomplete")
    return "".join(
        f"{sha256_bytes(files[name])}  {name}\n" for name in sorted(files)
    ).encode("ascii")


def verify_supply_chain_checksums(directory: Path) -> None:
    """Verify the canonical supply-chain checksum file."""

    checksum_path = directory / SUPPLY_CHAIN_CHECKSUM_NAME
    declared = _parse_generic_checksums(checksum_path)
    expected_names = {RUNTIME_SBOM_NAME, ALL_EXTRAS_SBOM_NAME, PROVENANCE_NAME}
    if set(declared) != expected_names:
        raise SupplyChainError("supply-chain checksum file has the wrong targets")
    actual = {name: build.sha256_file(directory / name) for name in expected_names}
    if declared != actual:
        raise SupplyChainError("supply-chain checksum verification failed")


def _parse_generic_checksums(path: Path) -> dict[str, str]:
    try:
        data = path.read_bytes()
        text = data.decode("ascii")
    except (OSError, UnicodeError) as exc:
        raise SupplyChainError(f"invalid supply-chain checksum file: {exc}") from exc
    if b"\r" in data or not data.endswith(b"\n") or data.endswith(b"\n\n"):
        raise SupplyChainError("supply-chain checksum file must use LF and one final newline")
    result: dict[str, str] = {}
    filenames: list[str] = []
    for line in text[:-1].split("\n"):
        match = CHECKSUM_LINE_RE.fullmatch(line)
        if match is None:
            raise SupplyChainError("supply-chain checksum file has invalid syntax")
        digest, filename = match.groups()
        if filename in result or Path(filename).name != filename:
            raise SupplyChainError("supply-chain checksum file has an unsafe or duplicate filename")
        result[filename] = digest
        filenames.append(filename)
    if filenames != sorted(filenames):
        raise SupplyChainError("supply-chain checksum lines must be sorted by filename")
    return result


def _iter_strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_strings(item)


def audit_generated_files(paths: Iterable[Path], *, project_root: Path, temporary_root: Path) -> None:
    """Reject local paths, identities, credentials, and secrets in generated bytes."""

    labels = {
        str(project_root.resolve()),
        project_root.resolve().as_posix(),
        str(temporary_root.resolve()),
        temporary_root.resolve().as_posix(),
        getpass.getuser(),
    }
    secret_values = {
        value
        for key, value in os.environ.items()
        if value
        and len(value) >= 8
        and re.search(r"(?i)(token|secret|password|credential|api[_-]?key)", key)
    }
    labels.update(secret_values)
    token_pattern = re.compile(
        rb"(?i)(-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----|github_pat_|gh[pousr]_|bearer\s+)"
    )
    path_pattern = re.compile(r"(?i)^(?:[a-z]:[\\/]|/(?:home|users|tmp|workspace)/|file:///)")
    public_hosts = {
        "files.pythonhosted.org",
        "github.com",
        "in-toto.io",
        "pypi.org",
        "slsa.dev",
    }
    for path in paths:
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise SupplyChainError(f"cannot audit '{path.name}': {exc}") from exc
        if token_pattern.search(data):
            raise SupplyChainError(f"generated file '{path.name}' contains credential-like data")
        for label in labels:
            if not label:
                continue
            for encoded in (label.encode("utf-8"), label.encode("utf-16le")):
                if encoded and encoded in data:
                    raise SupplyChainError(f"generated file '{path.name}' contains local identity data")
        if path.suffix == ".json":
            try:
                document = json.loads(data.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise SupplyChainError(f"generated JSON '{path.name}' is invalid: {exc}") from exc
            for value in _iter_strings(document):
                if value in labels:
                    raise SupplyChainError(f"generated file '{path.name}' contains local identity data")
                if path_pattern.search(value):
                    raise SupplyChainError(f"generated file '{path.name}' contains an absolute local path")
                if value.startswith(("http://", "https://", "git+https://")):
                    parsed = urlsplit(value.removeprefix("git+"))
                    if parsed.username is not None or parsed.password is not None:
                        raise SupplyChainError(f"generated file '{path.name}' contains a credential URL")
                    if parsed.scheme != "https" or parsed.hostname not in public_hosts:
                        raise SupplyChainError(f"generated file '{path.name}' contains a private or insecure URL")


def _write_file(path: Path, data: bytes) -> None:
    try:
        path.write_bytes(data)
    except OSError as exc:
        raise SupplyChainError(f"cannot write '{path.name}': {exc}") from exc


def _atomic_publish_set(staging: Path, output_dir: Path) -> tuple[Path, ...]:
    expected = set(OUTPUT_NAMES)
    if output_dir.exists():
        if not output_dir.is_dir():
            raise SupplyChainError("output path is not a directory")
        try:
            actual = {path.name for path in output_dir.iterdir()}
        except OSError as exc:
            raise SupplyChainError(f"cannot inspect output directory: {exc}") from exc
        if not actual <= expected:
            unexpected = ", ".join(sorted(actual - expected))
            raise SupplyChainError(f"output directory contains unexpected files: {unexpected}")
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SupplyChainError(f"cannot create output directory: {exc}") from exc
    previous: dict[str, bytes | None] = {}
    temporary: dict[str, Path] = {}
    try:
        for name in OUTPUT_NAMES:
            destination = output_dir / name
            previous[name] = destination.read_bytes() if destination.exists() else None
            sibling = output_dir / f".{name}.tmp"
            sibling.write_bytes((staging / name).read_bytes())
            temporary[name] = sibling
        for name in OUTPUT_NAMES:
            os.replace(temporary[name], output_dir / name)
    except OSError as exc:
        for sibling in temporary.values():
            try:
                sibling.unlink(missing_ok=True)
            except OSError:
                pass
        rollback_errors: list[str] = []
        for name, original in previous.items():
            destination = output_dir / name
            try:
                if original is None:
                    destination.unlink(missing_ok=True)
                else:
                    rollback = output_dir / f".{name}.rollback"
                    rollback.write_bytes(original)
                    os.replace(rollback, destination)
            except OSError as rollback_exc:
                rollback_errors.append(f"{name}: {rollback_exc}")
        detail = f"cannot publish supply-chain set: {exc}"
        if rollback_errors:
            detail += "; rollback failed: " + "; ".join(rollback_errors)
        raise SupplyChainError(detail) from exc
    published = tuple(output_dir / name for name in OUTPUT_NAMES)
    verify_supply_chain_checksums(output_dir)
    if {path.name for path in output_dir.iterdir()} != expected:
        raise SupplyChainError("published supply-chain directory does not contain exactly four files")
    return published


def generate_supply_chain(
    *,
    release_dir: Path,
    output_dir: Path,
    source_commit: str,
    project_root: Path = PROJECT_ROOT,
) -> GenerationResult:
    """Generate, validate, and atomically publish the four metadata files."""

    validate_source_commit(source_commit)
    validate_directory_relationship(release_dir, output_dir)
    for relative in ("pyproject.toml", "uv.lock", "README.md"):
        if not (project_root / relative).is_file():
            raise SupplyChainError(f"required project file is missing: {relative}")
    release = validate_release(release_dir, project_root=project_root)
    uv_executable, lock_sha256 = verify_uv(project_root)
    output_parent = output_dir.resolve().parent
    try:
        output_parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SupplyChainError(f"cannot create output parent: {exc}") from exc
    with tempfile.TemporaryDirectory(prefix=".assetguard-supply-chain-", dir=output_parent) as temporary:
        staging = Path(temporary)
        runtime_raw = staging / "runtime.raw.json"
        all_extras_raw = staging / "all-extras.raw.json"
        _run_uv(
            uv_export_command(uv_executable, runtime_raw, all_extras=False),
            project_root=project_root,
        )
        _run_uv(
            uv_export_command(uv_executable, all_extras_raw, all_extras=True),
            project_root=project_root,
        )
        if build.sha256_file(project_root / "uv.lock") != lock_sha256:
            raise SupplyChainError("uv.lock changed during SBOM export")
        audit_generated_files(
            (runtime_raw, all_extras_raw),
            project_root=project_root,
            temporary_root=staging,
        )
        runtime_document = normalize_sbom(
            load_raw_sbom(runtime_raw), scope="runtime", lock_sha256=lock_sha256
        )
        all_extras_document = normalize_sbom(
            load_raw_sbom(all_extras_raw), scope="all-extras", lock_sha256=lock_sha256
        )
        runtime_path = staging / RUNTIME_SBOM_NAME
        all_extras_path = staging / ALL_EXTRAS_SBOM_NAME
        _write_file(runtime_path, canonical_json(runtime_document))
        _write_file(all_extras_path, canonical_json(all_extras_document))
        provenance = build_provenance(
            release,
            runtime_sbom=runtime_path,
            all_extras_sbom=all_extras_path,
            source_commit=source_commit,
            lock_sha256=lock_sha256,
        )
        provenance_path = staging / PROVENANCE_NAME
        _write_file(provenance_path, canonical_json(provenance))
        checksum_inputs = {
            runtime_path.name: runtime_path.read_bytes(),
            all_extras_path.name: all_extras_path.read_bytes(),
            provenance_path.name: provenance_path.read_bytes(),
        }
        checksum_path = staging / SUPPLY_CHAIN_CHECKSUM_NAME
        _write_file(checksum_path, serialize_supply_chain_checksums(checksum_inputs))
        verify_supply_chain_checksums(staging)
        generated = (runtime_path, all_extras_path, provenance_path, checksum_path)
        audit_generated_files(generated, project_root=project_root, temporary_root=staging)
        published = _atomic_publish_set(staging, output_dir)
    hashes = {path.name: build.sha256_file(path) for path in published}
    return GenerationResult(
        paths=published,
        hashes=hashes,
        runtime_components=len(runtime_document["components"]) + 1,
        all_extras_components=len(all_extras_document["components"]) + 1,
        source_digest=release.source_digest,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate deterministic local AssetGuard SBOM and provenance metadata."
    )
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = generate_supply_chain(
            release_dir=args.release_dir,
            output_dir=args.output_dir,
            source_commit=args.source_commit,
        )
    except (
        SupplyChainError,
        build.BuildError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"Supply-chain generation failed: {exc}", file=sys.stderr)
        return 1
    print("Generated deterministic supply-chain metadata:")
    for path in sorted(result.paths, key=lambda value: value.name):
        print(f"  {path.name}: {result.hashes[path.name]}")
    print(f"Runtime components: {result.runtime_components}")
    print(f"All-extras components: {result.all_extras_components}")
    print(f"Source commit: {args.source_commit}")
    print(f"Release source digest: {result.source_digest}")
    print(UNSIGNED_WARNING)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
