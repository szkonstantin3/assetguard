"""Verify the Phase 07 Windows release in an isolated Windows Sandbox."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import tomllib
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.1.0"
EXPECTED_SOURCE_DIGEST = "9093ed7948b76f3315c442655c95fbe8b2bd77c178c0c23a1506835c4e64c9b9"
EXPECTED_HASHES = {
    "AssetGuard-0.1.0-windows-x86_64.exe": (
        "96aad7aac3f952fd636925d63ba15ffbcccdfe6ce3d532ad5d3eb3ae4a362dd3"
    ),
    "AssetGuard-0.1.0-windows-x86_64.zip": (
        "2a6ceea4c9f4463abfec27105638fdcacd0d25b02e8f49f7048a50e62179c24d"
    ),
    "AssetGuard-0.1.0-windows-x86_64.manifest.json": (
        "94be9e4f767bb2a2ac3333cb82a6a02094d2a5b2445ef293846177f6b2cfa245"
    ),
    "AssetGuard-0.1.0-windows-x86_64.sha256": (
        "d3f223ebe486016195bd5919f8eab5978077f9786997a0078b01ccfaa1f53f6a"
    ),
}
EXPECTED_ZIP_MEMBERS = [
    "AssetGuard-0.1.0-windows-x86_64/AssetGuard.exe",
    "AssetGuard-0.1.0-windows-x86_64/README.md",
    "AssetGuard-0.1.0-windows-x86_64/examples/rules.yaml",
]
RESULT_NAME = "sandbox-result.json"
RESULT_CHECKSUM_NAME = "sandbox-result.sha256"
SANDBOX_TIMEOUT_SECONDS = 600


class VerificationError(Exception):
    """Raised for an expected integrity, availability, or proof failure."""


@dataclass(frozen=True)
class ReleaseArtifacts:
    """The exact four Phase 07 release paths."""

    executable: Path
    archive: Path
    manifest: Path
    checksums: Path

    def ordered_paths(self) -> tuple[Path, ...]:
        return tuple(sorted(self.__dict__.values(), key=lambda path: path.name))


@dataclass(frozen=True)
class PreparedSession:
    """Host paths used for one disposable Sandbox run."""

    session_dir: Path
    exchange_dir: Path
    configuration: Path
    result: Path
    result_checksum: Path


def sha256_file(path: Path) -> str:
    """Hash a file in chunks."""

    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise VerificationError(f"cannot read '{path}': {exc}") from exc
    return digest.hexdigest()


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Serialize deterministic UTF-8 JSON with one LF newline."""

    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def read_project_version(project_root: Path) -> str:
    """Read the project version without importing AssetGuard."""

    try:
        with (project_root / "pyproject.toml").open("rb") as source:
            version = tomllib.load(source)["project"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        raise VerificationError(f"cannot read project version: {exc}") from exc
    if not isinstance(version, str) or not version:
        raise VerificationError("project version is invalid")
    return version


def release_artifacts(project_root: Path, version: str) -> ReleaseArtifacts:
    """Resolve the exact versioned Phase 07 release paths."""

    stem = f"AssetGuard-{version}-windows-x86_64"
    release = project_root / "dist" / "release"
    return ReleaseArtifacts(
        executable=release / f"{stem}.exe",
        archive=release / f"{stem}.zip",
        manifest=release / f"{stem}.manifest.json",
        checksums=release / f"{stem}.sha256",
    )


def release_hashes(artifacts: ReleaseArtifacts) -> dict[str, str]:
    """Return release hashes keyed by basename."""

    return {path.name: sha256_file(path) for path in artifacts.ordered_paths()}


def parse_checksum_text(text: str) -> dict[str, str]:
    """Parse strict lowercase SHA-256 lines with safe basename targets."""

    if not text.endswith("\n") or text.endswith("\n\n") or "\r" in text:
        raise VerificationError("checksum file must use LF and one final newline")
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\]+)", line)
        if match is None:
            raise VerificationError(f"malformed checksum line: {line!r}")
        digest, filename = match.groups()
        if Path(filename).is_absolute() or ":" in filename or filename in {".", ".."}:
            raise VerificationError(f"unsafe checksum filename: {filename}")
        if filename in parsed:
            raise VerificationError(f"duplicate checksum filename: {filename}")
        parsed[filename] = digest
    return parsed


def validate_manifest(manifest: Any, version: str) -> list[dict[str, Any]]:
    """Validate the deterministic Phase 07 manifest contract."""

    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise VerificationError("manifest schema_version must be 1")
    expected_product = {
        "name": "AssetGuard",
        "version": version,
        "platform": "windows",
        "architecture": "x86_64",
        "format": "pyinstaller-onefile",
    }
    if manifest.get("product") != expected_product:
        raise VerificationError("manifest product contract is invalid")
    expected_toolchain = {
        "python": "3.13.9",
        "pyinstaller": "6.21.0",
        "pyinstaller_hooks_contrib": "2026.6",
        "source_date_epoch": 1767225600,
    }
    if manifest.get("toolchain") != expected_toolchain:
        raise VerificationError("manifest toolchain contract is invalid")
    if manifest.get("source") != {"sha256": EXPECTED_SOURCE_DIGEST}:
        raise VerificationError("manifest source digest is invalid")
    payload = manifest.get("payload")
    if not isinstance(payload, list) or len(payload) != 3:
        raise VerificationError("manifest payload must contain exactly three entries")
    paths = [entry.get("path") for entry in payload if isinstance(entry, dict)]
    if paths != ["AssetGuard.exe", "README.md", "examples/rules.yaml"]:
        raise VerificationError("manifest payload paths are invalid")
    for entry in payload:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "size", "sha256"}
            or not isinstance(entry["size"], int)
            or entry["size"] < 0
            or not isinstance(entry["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
        ):
            raise VerificationError("manifest payload entry is invalid")
    return payload


def _validate_zip_name(name: str) -> None:
    pure = PurePosixPath(name)
    if (
        pure.is_absolute()
        or ".." in pure.parts
        or "\\" in name
        or not pure.parts
        or ":" in pure.parts[0]
    ):
        raise VerificationError(f"unsafe ZIP entry path: {name}")


def validate_zip(archive_path: Path, payload_entries: Sequence[Mapping[str, Any]]) -> None:
    """Validate exact ZIP names, safety, sizes, and payload hashes."""

    expected_payload = {str(entry["path"]): entry for entry in payload_entries}
    try:
        with zipfile.ZipFile(archive_path) as archive:
            names = archive.namelist()
            if names != EXPECTED_ZIP_MEMBERS:
                raise VerificationError("release ZIP members are not exact")
            for name in names:
                _validate_zip_name(name)
                relative = name.split("/", 1)[1]
                data = archive.read(name)
                expected = expected_payload[relative]
                if len(data) != expected["size"]:
                    raise VerificationError(f"ZIP size mismatch for {relative}")
                if hashlib.sha256(data).hexdigest() != expected["sha256"]:
                    raise VerificationError(f"ZIP hash mismatch for {relative}")
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        if isinstance(exc, VerificationError):
            raise
        raise VerificationError(f"cannot validate release ZIP: {exc}") from exc


def validate_release_integrity(project_root: Path) -> tuple[ReleaseArtifacts, dict[str, str]]:
    """Validate all host release artifacts before any Sandbox work."""

    version = read_project_version(project_root)
    if version != EXPECTED_VERSION:
        raise VerificationError(
            f"project version {version} does not match expected {EXPECTED_VERSION}"
        )
    artifacts = release_artifacts(project_root, version)
    release_dir = artifacts.executable.parent
    try:
        actual_names = sorted(path.name for path in release_dir.iterdir() if path.is_file())
    except OSError as exc:
        raise VerificationError(f"cannot inspect release directory: {exc}") from exc
    expected_names = sorted(EXPECTED_HASHES)
    if actual_names != expected_names:
        raise VerificationError("release directory does not contain exactly four expected files")
    hashes = release_hashes(artifacts)
    if hashes != dict(sorted(EXPECTED_HASHES.items())):
        raise VerificationError("Phase 07 release artifact hash mismatch")
    try:
        checksum_text = artifacts.checksums.read_text(encoding="utf-8")
        checksums = parse_checksum_text(checksum_text)
    except (OSError, UnicodeError) as exc:
        raise VerificationError(f"cannot read checksum file: {exc}") from exc
    expected_checksum_names = {
        artifacts.executable.name,
        artifacts.archive.name,
        artifacts.manifest.name,
    }
    if set(checksums) != expected_checksum_names:
        raise VerificationError("checksum file targets are invalid")
    for name, digest in checksums.items():
        if hashes[name] != digest:
            raise VerificationError(f"checksum verification failed for {name}")
    try:
        manifest = json.loads(artifacts.manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot parse manifest: {exc}") from exc
    payload = validate_manifest(manifest, version)
    validate_zip(artifacts.archive, payload)
    return artifacts, hashes


def verify_host_platform(
    *, system: str | None = None, machine: str | None = None
) -> None:
    """Require a Windows AMD64 host without changing optional features."""

    actual_system = platform.system() if system is None else system
    actual_machine = platform.machine() if machine is None else machine
    if actual_system != "Windows":
        raise VerificationError(f"Windows Sandbox requires Windows; found {actual_system}")
    if actual_machine.upper() not in {"AMD64", "X86_64"}:
        raise VerificationError(f"Windows Sandbox proof requires AMD64; found {actual_machine}")


def locate_windows_sandbox(
    *, system_root: Path | None = None, require_exists: bool = True
) -> Path:
    """Locate WindowsSandbox.exe only through the trusted System32 path."""

    root = system_root if system_root is not None else Path(os.environ.get("SystemRoot", r"C:\Windows"))
    executable = root / "System32" / "WindowsSandbox.exe"
    if require_exists and not executable.is_file():
        raise VerificationError(
            f"Windows Sandbox is unavailable at trusted path '{executable}'"
        )
    return executable


def generate_wsb_xml(release_dir: Path, exchange_dir: Path) -> str:
    """Generate the isolated two-mapping Sandbox configuration."""

    configuration = ET.Element("Configuration")
    ET.SubElement(configuration, "VGpu").text = "Disable"
    ET.SubElement(configuration, "Networking").text = "Disable"
    ET.SubElement(configuration, "ClipboardRedirection").text = "Disable"
    ET.SubElement(configuration, "PrinterRedirection").text = "Disable"
    ET.SubElement(configuration, "AudioInput").text = "Disable"
    ET.SubElement(configuration, "VideoInput").text = "Disable"
    mapped_folders = ET.SubElement(configuration, "MappedFolders")
    for host, guest, read_only in (
        (release_dir.resolve(), r"C:\AssetGuardRelease", "true"),
        (exchange_dir.resolve(), r"C:\AssetGuardExchange", "false"),
    ):
        mapped = ET.SubElement(mapped_folders, "MappedFolder")
        ET.SubElement(mapped, "HostFolder").text = str(host)
        ET.SubElement(mapped, "SandboxFolder").text = guest
        ET.SubElement(mapped, "ReadOnly").text = read_only
    logon = ET.SubElement(configuration, "LogonCommand")
    ET.SubElement(logon, "Command").text = (
        r"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
        r"-File C:\AssetGuardExchange\verify_release.ps1"
    )
    return ET.tostring(configuration, encoding="unicode", short_empty_elements=False) + "\n"


def _safe_recreate(path: Path, allowed_parent: Path) -> None:
    resolved = path.resolve()
    parent = allowed_parent.resolve()
    if resolved.parent != parent:
        raise VerificationError(f"refusing to recreate unexpected path: {path}")
    if resolved.exists():
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True)


def prepare_session(project_root: Path, artifacts: ReleaseArtifacts) -> PreparedSession:
    """Create only the scoped ignored session and exchange files."""

    clean_root = project_root / "build" / "windows-clean-room"
    clean_root.mkdir(parents=True, exist_ok=True)
    session = clean_root / "session"
    _safe_recreate(session, clean_root)
    exchange = session / "exchange"
    exchange.mkdir()
    verifier_source = (
        project_root
        / "packaging"
        / "windows"
        / "clean_room"
        / "verify_release.ps1"
    )
    verifier_target = exchange / "verify_release.ps1"
    try:
        shutil.copyfile(verifier_source, verifier_target)
    except OSError as exc:
        raise VerificationError(f"cannot prepare Sandbox verifier: {exc}") from exc
    control = {
        "schema_version": 1,
        "networking_disabled": True,
        "source_tree_mapped": False,
        "release_mapping_read_only": True,
        "expected_version": EXPECTED_VERSION,
        "expected_source_digest": EXPECTED_SOURCE_DIGEST,
        "expected_hashes": dict(sorted(EXPECTED_HASHES.items())),
    }
    (exchange / "sandbox-control.json").write_bytes(canonical_json(control))
    configuration = session / "assetguard-clean-room.wsb"
    configuration.write_text(
        generate_wsb_xml(artifacts.executable.parent, exchange),
        encoding="utf-8",
        newline="\n",
    )
    return PreparedSession(
        session_dir=session,
        exchange_dir=exchange,
        configuration=configuration,
        result=exchange / RESULT_NAME,
        result_checksum=exchange / RESULT_CHECKSUM_NAME,
    )


def validate_result_sidecar(result: Path, checksum_path: Path) -> str:
    """Verify the Sandbox JSON checksum before parsing it."""

    try:
        parsed = parse_checksum_text(checksum_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise VerificationError(f"cannot read Sandbox result checksum: {exc}") from exc
    if parsed.keys() != {result.name}:
        raise VerificationError("Sandbox result checksum target is invalid")
    actual = sha256_file(result)
    if parsed[result.name] != actual:
        raise VerificationError("Sandbox result checksum mismatch")
    return actual


def validate_sandbox_result(
    result: Any,
    expected_hashes: Mapping[str, str],
) -> dict[str, Any]:
    """Validate every required clean-room result field and passing check."""

    if not isinstance(result, dict) or result.get("schema_version") != 1:
        raise VerificationError("Sandbox result schema_version must be 1")
    environment = result.get("environment")
    required_environment = {
        "architecture",
        "python_available",
        "source_tree_mapped",
        "release_mapping_read_only",
        "networking_disabled",
        "windows_product_name",
        "windows_version",
        "windows_build",
        "powershell_version",
    }
    if not isinstance(environment, dict) or set(environment) != required_environment:
        raise VerificationError("Sandbox environment fields are invalid")
    if environment["architecture"].upper() != "AMD64":
        raise VerificationError("Sandbox architecture is not AMD64")
    if environment["python_available"] is not False:
        raise VerificationError("a usable Python runtime was detected in Sandbox")
    if environment["source_tree_mapped"] is not False:
        raise VerificationError("project source tree was mapped into Sandbox")
    if environment["release_mapping_read_only"] is not True:
        raise VerificationError("release mapping was not proven read-only")
    if environment["networking_disabled"] is not True:
        raise VerificationError("Sandbox networking was not disabled")
    for key in (
        "windows_product_name",
        "windows_version",
        "windows_build",
        "powershell_version",
    ):
        if not isinstance(environment[key], str) or not environment[key]:
            raise VerificationError(f"Sandbox environment field '{key}' is invalid")
    release = result.get("release")
    if not isinstance(release, dict) or release != {
        "version": EXPECTED_VERSION,
        "executable_sha256": expected_hashes[
            "AssetGuard-0.1.0-windows-x86_64.exe"
        ],
        "zip_sha256": expected_hashes["AssetGuard-0.1.0-windows-x86_64.zip"],
        "manifest_sha256": expected_hashes[
            "AssetGuard-0.1.0-windows-x86_64.manifest.json"
        ],
        "checksum_sha256": expected_hashes[
            "AssetGuard-0.1.0-windows-x86_64.sha256"
        ],
    }:
        raise VerificationError("Sandbox release evidence is invalid")
    checks = result.get("checks")
    if not isinstance(checks, list) or not checks:
        raise VerificationError("Sandbox checks are missing")
    names: list[str] = []
    for check in checks:
        if (
            not isinstance(check, dict)
            or set(check) != {"name", "passed", "details"}
            or not isinstance(check["name"], str)
            or check["passed"] is not True
            or not isinstance(check["details"], dict)
        ):
            raise VerificationError("Sandbox check failed or is malformed")
        names.append(check["name"])
    if names != sorted(names) or len(names) != len(set(names)):
        raise VerificationError("Sandbox checks are not uniquely sorted")
    summary = result.get("summary")
    if summary != {
        "passed": True,
        "checks_passed": len(checks),
        "checks_failed": 0,
    }:
        raise VerificationError("Sandbox result summary is not passing")
    return result


def read_validated_result(session: PreparedSession) -> tuple[dict[str, Any], str]:
    """Checksum, parse, and validate the Sandbox result."""

    result_hash = validate_result_sidecar(session.result, session.result_checksum)
    try:
        raw_result = json.loads(session.result.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot parse Sandbox result: {exc}") from exc
    return validate_sandbox_result(raw_result, EXPECTED_HASHES), result_hash


def wait_for_result(
    process: subprocess.Popen[bytes],
    session: PreparedSession,
    *,
    timeout_seconds: int = SANDBOX_TIMEOUT_SECONDS,
) -> tuple[dict[str, Any], str]:
    """Wait only as a hang guard and return a checksum-validated result."""

    deadline = time.monotonic() + timeout_seconds
    last_error: VerificationError | None = None
    while time.monotonic() < deadline:
        if session.result.is_file() and session.result_checksum.is_file():
            try:
                return read_validated_result(session)
            except VerificationError as exc:
                last_error = exc
        return_code = process.poll()
        if return_code not in (None, 0):
            if last_error is not None:
                raise last_error
            raise VerificationError(
                f"Windows Sandbox exited with code {return_code} without a valid result"
            )
        time.sleep(1)
    if last_error is not None:
        raise VerificationError(f"Sandbox result remained invalid: {last_error}")
    raise VerificationError("Windows Sandbox verification timed out without a result")


def launch_and_validate(
    sandbox_executable: Path,
    session: PreparedSession,
) -> tuple[dict[str, Any], str]:
    """Launch one Sandbox process and terminate only that process if needed."""

    try:
        process = subprocess.Popen(
            [str(sandbox_executable), str(session.configuration)],
            cwd=session.session_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise VerificationError(f"cannot launch Windows Sandbox: {exc}") from exc
    try:
        return wait_for_result(process, session)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def write_host_proof(
    project_root: Path,
    sandbox_result: Mapping[str, Any],
    sandbox_result_hash: str,
) -> tuple[Path, Path, str]:
    """Write the validated canonical host proof outside dist/release."""

    proof_dir = project_root / "build" / "windows-clean-room" / "proof"
    proof_dir.mkdir(parents=True, exist_ok=True)
    stem = "AssetGuard-0.1.0-windows-x86_64.clean-room-proof"
    proof_path = proof_dir / f"{stem}.json"
    checksum_path = proof_dir / f"{stem}.sha256"
    proof = {
        "schema_version": 1,
        "product": {
            "name": "AssetGuard",
            "version": EXPECTED_VERSION,
            "platform": "windows",
            "architecture": "x86_64",
        },
        "sandbox_result_sha256": sandbox_result_hash,
        "environment": sandbox_result["environment"],
        "release": sandbox_result["release"],
        "checks": sandbox_result["checks"],
        "summary": sandbox_result["summary"],
    }
    proof_bytes = canonical_json(proof)
    proof_hash = hashlib.sha256(proof_bytes).hexdigest()
    proof_path.write_bytes(proof_bytes)
    checksum_path.write_text(
        f"{proof_hash}  {proof_path.name}\n", encoding="utf-8", newline="\n"
    )
    return proof_path, checksum_path, proof_hash


def cleanup_successful_session(session_dir: Path) -> None:
    """Best-effort cleanup after Sandbox has published a passing result."""

    discard_dir = session_dir.with_name(f"{session_dir.name}.cleanup")
    if discard_dir.exists():
        return
    for _attempt in range(10):
        if not session_dir.exists():
            return
        try:
            session_dir.rename(discard_dir)
            break
        except OSError:
            time.sleep(1)
    else:
        return
    try:
        shutil.rmtree(discard_dir)
    except OSError:
        pass


def run_verification(project_root: Path = PROJECT_ROOT) -> tuple[Path, str, int]:
    """Perform host integrity, actual Sandbox execution, and host validation."""

    artifacts, before_hashes = validate_release_integrity(project_root)
    verify_host_platform()
    sandbox_executable = locate_windows_sandbox()
    session = prepare_session(project_root, artifacts)
    succeeded = False
    try:
        sandbox_result, result_hash = launch_and_validate(sandbox_executable, session)
        after_hashes = release_hashes(artifacts)
        if after_hashes != before_hashes:
            raise VerificationError("host release artifacts changed during Sandbox execution")
        actual_names = sorted(
            path.name for path in artifacts.executable.parent.iterdir() if path.is_file()
        )
        if actual_names != sorted(EXPECTED_HASHES):
            raise VerificationError("dist/release contents changed during Sandbox execution")
        proof_path, _checksum_path, proof_hash = write_host_proof(
            project_root, sandbox_result, result_hash
        )
        checks_passed = int(sandbox_result["summary"]["checks_passed"])
        succeeded = True
    finally:
        if succeeded:
            cleanup_successful_session(session.session_dir)
    return proof_path, proof_hash, checks_passed


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        print("Error: no command-line options are supported", file=sys.stderr)
        return 2
    try:
        proof_path, proof_hash, checks_passed = run_verification()
    except (VerificationError, OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print("Windows Sandbox clean-room verification: PASSED")
    print(f"Checks passed: {checks_passed}")
    print(f"Proof: {proof_path}")
    print(f"Proof SHA-256: {proof_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
