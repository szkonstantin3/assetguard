import base64
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import sys
import xml.etree.ElementTree as ET
import zipfile

import pytest
from PIL import Image

from tools import verify_windows_sandbox as verifier


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HOST_VERIFIER = PROJECT_ROOT / "tools" / "verify_windows_sandbox.py"
POWERSHELL_VERIFIER = (
    PROJECT_ROOT
    / "packaging"
    / "windows"
    / "clean_room"
    / "verify_release.ps1"
)
PHASE07_SOURCE_HASHES = {
    "__init__.py": "6aedc32f97378e0f1e7736ae04ae511d0aaf2e033b2e2e4ff52114700bb87964",
    "__main__.py": "987f943932d8a1430f6760f7c3459de9ff7817abb9b939a97c491e421e717c53",
    "cache.py": "0538b115599e2102e94477b407f0253493da6f453021bd30412847d2285580a8",
    "cli.py": "3add8685ee97bf63a2bd3afcd5efc1a3da0daeb60339c9f174658d2b14ab70af",
    "config.py": "a1704670363b1587f1adf86ffad1dd8ad40acf2c768963422395427ac6b07c29",
    "html_reporting.py": "f63a1feb2e345508c2f900cab9dbebf982348e2e410c34e1cd99e50f960883d2",
    "models.py": "21ea12cd4bd7ae382643a943100db46059ec1b4664742a2f461bd0dc231e6d45",
    "obj_mesh.py": "ede483473a709708284897db9d8338da5f26cfa93ec1f4ee03c856d3f090bdf4",
    "parallel.py": "ca192009c57b66ae5ef856aecef971f7b420f6f36e2b5ecc1c6259efdb0f3937",
    "reporting.py": "d7375fbefa1ce10b89fb27f72abf3456851cdd87fb64c9a06c9e6167bb11156e",
    "scanner.py": "0f578c7f9814ed9bd82ec543f5aef417753c8c1c95fa3ec204dc1d8ee1b12f4e",
}
PHASE07_SOURCE_MANIFEST_SHA256 = (
    "98b05b4de3ff913c4f2ee51bfaacf2099c4e6ab8ab5fb35b64a67d33404f66e0"
)
PHASE12C_R1_SOURCE_HASHES = {
    "__init__.py": "6aedc32f97378e0f1e7736ae04ae511d0aaf2e033b2e2e4ff52114700bb87964",
    "__main__.py": "987f943932d8a1430f6760f7c3459de9ff7817abb9b939a97c491e421e717c53",
    "cache.py": "a1af3167b1d1d7a4b323fcf0483610afaf297c89a475a49f69197fcc28c028b3",
    "cli.py": "d04ab38023836fbfcfe8b806bf5b6ae5efde958143c917ecb1b0428aad8e8772",
    "config.py": "8a38f07e0204a6bcea4cf1cdceb5fa71be6ebf0fd8774380f605a6b725f9f112",
    "html_reporting.py": "2f38c476581af9a2002bd42345b0b0626e0ad1d278277ccae6953f651028e2db",
    "models.py": "21ea12cd4bd7ae382643a943100db46059ec1b4664742a2f461bd0dc231e6d45",
    "obj_mesh.py": "ede483473a709708284897db9d8338da5f26cfa93ec1f4ee03c856d3f090bdf4",
    "parallel.py": "ca192009c57b66ae5ef856aecef971f7b420f6f36e2b5ecc1c6259efdb0f3937",
    "path_security.py": "b50b5a4d156336463e0c694a01ad05baeae15a45dd6aa3acefebd141ba165af6",
    "reporting.py": "f39faddfe933864d064dde955381375a9dd7a7c19b7d45cb7498278ec979fba4",
    "scanner.py": "93a329b0133b1840fc617d741f2e4cad117ad19c735c73b903ae2af056a9c83f",
}
RELEASE_ARTIFACTS = verifier.release_artifacts(PROJECT_ROOT, verifier.EXPECTED_VERSION)
RELEASE_ARTIFACTS_AVAILABLE = all(
    path.is_file() for path in RELEASE_ARTIFACTS.ordered_paths()
)
PHASE07_RELEASE_INTEGRITY_REQUESTED = (
    os.environ.get("ASSETGUARD_PHASE07_RELEASE_INTEGRITY") == "1"
)
SANDBOX_AVAILABLE = (
    sys.platform == "win32"
    and (Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsSandbox.exe").is_file()
)
INTEGRATION_ENABLED = (
    os.environ.get("ASSETGUARD_WINDOWS_SANDBOX_INTEGRATION") == "1"
    and SANDBOX_AVAILABLE
    and RELEASE_ARTIFACTS_AVAILABLE
)

SYNTHETIC_PAYLOADS = {
    "AssetGuard.exe": b"synthetic AssetGuard executable\n",
    "README.md": b"# Synthetic AssetGuard release\n",
    "examples/rules.yaml": b"version: 1\n",
}


def _synthetic_manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "product": {
            "name": "AssetGuard",
            "version": "0.1.0",
            "platform": "windows",
            "architecture": "x86_64",
            "format": "pyinstaller-onefile",
        },
        "toolchain": {
            "python": "3.13.9",
            "pyinstaller": "6.21.0",
            "pyinstaller_hooks_contrib": "2026.6",
            "source_date_epoch": 1767225600,
        },
        "source": {"sha256": verifier.EXPECTED_SOURCE_DIGEST},
        "payload": [
            {
                "path": path,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for path, data in SYNTHETIC_PAYLOADS.items()
        ],
    }


def _write_synthetic_release_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for member, data in zip(
            verifier.EXPECTED_ZIP_MEMBERS,
            SYNTHETIC_PAYLOADS.values(),
            strict=True,
        ):
            entry = zipfile.ZipInfo(member, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_STORED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
    return path


def _valid_result() -> dict[str, object]:
    return {
        "schema_version": 1,
        "environment": {
            "architecture": "AMD64",
            "python_available": False,
            "source_tree_mapped": False,
            "release_mapping_read_only": True,
            "networking_disabled": True,
            "windows_product_name": "Windows Sandbox",
            "windows_version": "test-version",
            "windows_build": "test-build",
            "powershell_version": "5.1",
        },
        "release": {
            "version": "0.1.0",
            "executable_sha256": verifier.EXPECTED_HASHES[
                "AssetGuard-0.1.0-windows-x86_64.exe"
            ],
            "zip_sha256": verifier.EXPECTED_HASHES[
                "AssetGuard-0.1.0-windows-x86_64.zip"
            ],
            "manifest_sha256": verifier.EXPECTED_HASHES[
                "AssetGuard-0.1.0-windows-x86_64.manifest.json"
            ],
            "checksum_sha256": verifier.EXPECTED_HASHES[
                "AssetGuard-0.1.0-windows-x86_64.sha256"
            ],
        },
        "checks": [{"name": "release_checksums", "passed": True, "details": {}}],
        "summary": {"passed": True, "checks_passed": 1, "checks_failed": 0},
    }


def _write_result_with_sidecar(directory: Path, result: dict[str, object]) -> tuple[Path, Path]:
    result_path = directory / verifier.RESULT_NAME
    checksum_path = directory / verifier.RESULT_CHECKSUM_NAME
    result_path.write_bytes(verifier.canonical_json(result))
    checksum_path.write_text(
        f"{verifier.sha256_file(result_path)}  {result_path.name}\n",
        encoding="utf-8",
        newline="\n",
    )
    return result_path, checksum_path


def test_verifier_files_exist_and_are_portable_text() -> None:
    assert HOST_VERIFIER.is_file()
    assert POWERSHELL_VERIFIER.is_file()
    for path in (HOST_VERIFIER, POWERSHELL_VERIFIER):
        data = path.read_bytes()
        assert data.endswith(b"\n")
        assert b"\r" not in data
        assert b"\t" not in data


def test_phase07_source_hash_manifest_remains_exact() -> None:
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", digest)
        for digest in PHASE07_SOURCE_HASHES.values()
    )
    canonical_manifest = "".join(
        f"{filename}\0{digest}\n"
        for filename, digest in sorted(PHASE07_SOURCE_HASHES.items())
    ).encode("ascii")

    assert hashlib.sha256(canonical_manifest).hexdigest() == PHASE07_SOURCE_MANIFEST_SHA256


def test_application_source_hashes_match_phase12c_r1_exact() -> None:
    source_root = PROJECT_ROOT / "src" / "assetguard"
    source_paths = sorted(source_root.glob("*.py"), key=lambda path: path.name)
    actual = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source_paths
    }
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", digest)
        for digest in PHASE12C_R1_SOURCE_HASHES.values()
    )
    assert actual == PHASE12C_R1_SOURCE_HASHES


@pytest.mark.skipif(
    not PHASE07_RELEASE_INTEGRITY_REQUESTED,
    reason=(
        "trusted Phase 07 release integrity verification requires "
        "ASSETGUARD_PHASE07_RELEASE_INTEGRITY=1"
    ),
)
def test_expected_release_names_and_phase07_hashes_validate() -> None:
    if not RELEASE_ARTIFACTS_AVAILABLE:
        pytest.fail("trusted Phase 07 release artifacts are missing")

    artifacts, hashes = verifier.validate_release_integrity(PROJECT_ROOT)

    assert {path.name for path in artifacts.ordered_paths()} == set(verifier.EXPECTED_HASHES)
    assert hashes == verifier.EXPECTED_HASHES


@pytest.mark.parametrize(
    "text",
    [
        "not-a-checksum\n",
        f"{'a' * 64} AssetGuard.exe\n",
        f"{'A' * 64}  AssetGuard.exe\n",
        f"{'a' * 64}  nested/file.exe\n",
    ],
)
def test_checksum_parser_rejects_malformed_and_path_lines(text: str) -> None:
    with pytest.raises(verifier.VerificationError):
        verifier.parse_checksum_text(text)


def test_checksum_parser_rejects_absolute_and_duplicate_names() -> None:
    with pytest.raises(verifier.VerificationError, match="unsafe"):
        verifier.parse_checksum_text(f"{'a' * 64}  C:artifact.exe\n")
    with pytest.raises(verifier.VerificationError, match="duplicate"):
        verifier.parse_checksum_text(
            f"{'a' * 64}  artifact.exe\n{'b' * 64}  artifact.exe\n"
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (("product", "version", "9.9.9"), "product"),
        (("product", "platform", "linux"), "product"),
        (("product", "architecture", "arm64"), "product"),
        (("toolchain", "python", "3.12.0"), "toolchain"),
        (("source", "sha256", "0" * 64), "source digest"),
    ],
)
def test_manifest_validation_rejects_wrong_contract(
    mutation: tuple[str, str, object], message: str
) -> None:
    manifest = _synthetic_manifest()
    section, key, value = mutation
    manifest[section][key] = value  # type: ignore[index]

    with pytest.raises(verifier.VerificationError, match=message):
        verifier.validate_manifest(manifest, "0.1.0")


def test_manifest_and_zip_validate_exact_synthetic_payload(tmp_path: Path) -> None:
    payload = verifier.validate_manifest(_synthetic_manifest(), "0.1.0")
    verifier.validate_zip(_write_synthetic_release_zip(tmp_path / "release.zip"), payload)


@pytest.mark.parametrize("unsafe_name", ["../escape", "/absolute", "C:/drive"])
def test_zip_validation_rejects_non_exact_or_unsafe_names(
    tmp_path: Path, unsafe_name: str
) -> None:
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(unsafe_name, b"bad")

    with pytest.raises(verifier.VerificationError):
        verifier.validate_zip(
            archive,
            verifier.validate_manifest(_synthetic_manifest(), "0.1.0"),
        )


def test_generated_wsb_is_valid_isolated_two_mapping_xml(tmp_path: Path) -> None:
    release = tmp_path / "release & artifacts"
    exchange = tmp_path / "exchange & results"
    release.mkdir()
    exchange.mkdir()
    xml_text = verifier.generate_wsb_xml(release, exchange)
    root = ET.fromstring(xml_text)
    mappings = root.findall("./MappedFolders/MappedFolder")
    host_folders = {mapping.findtext("HostFolder") for mapping in mappings}

    assert root.findtext("Networking") == "Disable"
    assert root.findtext("VGpu") == "Disable"
    assert root.findtext("ClipboardRedirection") == "Disable"
    assert root.findtext("PrinterRedirection") == "Disable"
    assert root.findtext("AudioInput") == "Disable"
    assert root.findtext("VideoInput") == "Disable"
    assert len(mappings) == 2
    assert mappings[0].findtext("SandboxFolder") == r"C:\AssetGuardRelease"
    assert mappings[0].findtext("ReadOnly") == "true"
    assert mappings[1].findtext("SandboxFolder") == r"C:\AssetGuardExchange"
    assert mappings[1].findtext("ReadOnly") == "false"
    assert host_folders == {
        str(release.resolve()),
        str(exchange.resolve()),
    }
    assert str(PROJECT_ROOT.resolve()) not in host_folders
    assert "&amp;" in xml_text
    command = root.findtext("./LogonCommand/Command")
    assert command == (
        r"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
        r"-File C:\AssetGuardExchange\verify_release.ps1"
    )


def test_missing_sandbox_nonwindows_and_nonamd64_are_clean_errors(tmp_path: Path) -> None:
    with pytest.raises(verifier.VerificationError, match="unavailable"):
        verifier.locate_windows_sandbox(system_root=tmp_path)
    with pytest.raises(verifier.VerificationError, match="requires Windows"):
        verifier.verify_host_platform(system="Linux", machine="x86_64")
    with pytest.raises(verifier.VerificationError, match="requires AMD64"):
        verifier.verify_host_platform(system="Windows", machine="ARM64")


def test_invalid_result_checksum_is_rejected(tmp_path: Path) -> None:
    result, checksum = _write_result_with_sidecar(tmp_path, _valid_result())
    checksum.write_text(f"{'0' * 64}  {result.name}\n", encoding="utf-8")

    with pytest.raises(verifier.VerificationError, match="mismatch"):
        verifier.validate_result_sidecar(result, checksum)


def test_failed_or_missing_sandbox_result_fields_are_rejected() -> None:
    failed = _valid_result()
    failed["checks"][0]["passed"] = False  # type: ignore[index]
    failed["summary"] = {"passed": False, "checks_passed": 0, "checks_failed": 1}
    with pytest.raises(verifier.VerificationError, match="failed or is malformed"):
        verifier.validate_sandbox_result(failed, verifier.EXPECTED_HASHES)

    missing = _valid_result()
    del missing["environment"]["python_available"]  # type: ignore[index]
    with pytest.raises(verifier.VerificationError, match="environment fields"):
        verifier.validate_sandbox_result(missing, verifier.EXPECTED_HASHES)


def test_valid_result_and_canonical_host_proof_are_deterministic(tmp_path: Path) -> None:
    result = verifier.validate_sandbox_result(_valid_result(), verifier.EXPECTED_HASHES)
    first = verifier.canonical_json(result)
    second = verifier.canonical_json(deepcopy(result))
    proof_path, checksum_path, proof_hash = verifier.write_host_proof(
        tmp_path, result, hashlib.sha256(first).hexdigest()
    )

    assert first == second
    assert first.endswith(b"\n") and not first.endswith(b"\n\n")
    assert proof_path.parent == tmp_path / "build" / "windows-clean-room" / "proof"
    assert tmp_path / "dist" / "release" not in proof_path.parents
    assert hashlib.sha256(proof_path.read_bytes()).hexdigest() == proof_hash
    assert verifier.parse_checksum_text(checksum_path.read_text(encoding="utf-8")) == {
        proof_path.name: proof_hash
    }


def test_wait_accepts_successful_launcher_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exchange = tmp_path / "exchange"
    exchange.mkdir()
    result_path = exchange / verifier.RESULT_NAME
    checksum_path = exchange / verifier.RESULT_CHECKSUM_NAME
    session = verifier.PreparedSession(
        session_dir=tmp_path,
        exchange_dir=exchange,
        configuration=tmp_path / "session.wsb",
        result=result_path,
        result_checksum=checksum_path,
    )

    class HandedOffProcess:
        returncode = 0

        @staticmethod
        def poll() -> int:
            return 0

    def publish_result(_seconds: float) -> None:
        _write_result_with_sidecar(exchange, _valid_result())

    monkeypatch.setattr(verifier.time, "sleep", publish_result)

    result, result_hash = verifier.wait_for_result(  # type: ignore[arg-type]
        HandedOffProcess(), session, timeout_seconds=2
    )

    assert result["summary"]["passed"] is True  # type: ignore[index]
    assert result_hash == verifier.sha256_file(result_path)


def test_successful_session_cleanup_renames_before_removal(tmp_path: Path) -> None:
    session = tmp_path / "session"
    session.mkdir()
    (session / "runtime.txt").write_text("temporary", encoding="utf-8")

    verifier.cleanup_successful_session(session)

    assert not session.exists()
    assert not (tmp_path / "session.cleanup").exists()


def test_locked_successful_session_cleanup_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = tmp_path / "session"
    session.mkdir()
    sleeps: list[float] = []

    def locked_rename(_self: Path, _target: Path) -> Path:
        raise PermissionError("mapped")

    monkeypatch.setattr(Path, "rename", locked_rename)
    monkeypatch.setattr(verifier.time, "sleep", sleeps.append)

    verifier.cleanup_successful_session(session)

    assert session.is_dir()
    assert sleeps == [1] * 10


def test_powershell_verifier_has_no_network_download_or_tool_dependency() -> None:
    source = POWERSHELL_VERIFIER.read_text(encoding="utf-8").lower()

    for forbidden in (
        "invoke-webrequest",
        "invoke-restmethod",
        "curl ",
        "wget ",
        "pip install",
        "python -m",
        "git ",
    ):
        assert forbidden not in source
    assert "enable-windowsoptionalfeature" not in source
    assert "disable-windowsoptionalfeature" not in source
    assert "dism" not in source


def test_powershell_verifier_covers_runtime_and_non_destructive_contracts() -> None:
    source = POWERSHELL_VERIFIER.read_text(encoding="utf-8")

    required_markers = [
        '@("--help")',
        '@("scan", "--help")',
        '"valid_exit"',
        '"warning_exit"',
        '"error_exit"',
        '"malformed_exit"',
        '"cache_hits"',
        '"worker_4"',
        '"html_output"',
        '"unicode_paths"',
        '"asset_non_destructive"',
        "last_write_utc_ticks",
        '"json_equivalence"',
        '"html_equivalence"',
    ]
    assert all(marker in source for marker in required_markers)


def test_embedded_png_fixture_is_fully_decodable() -> None:
    source = POWERSHELL_VERIFIER.read_text(encoding="utf-8")
    match = re.search(r'FromBase64String\(\s*"([A-Za-z0-9+/=]+)"', source)
    assert match is not None

    with Image.open(io.BytesIO(base64.b64decode(match.group(1)))) as image:
        assert image.size == (2, 2)
        image.load()


def test_host_verifier_rechecks_release_and_keeps_proof_outside_release() -> None:
    source = HOST_VERIFIER.read_text(encoding="utf-8")

    assert "before_hashes" in source and "after_hashes" in source
    assert "host release artifacts changed" in source
    assert '"windows-clean-room" / "proof"' in source
    assert "dist" not in str(
        PROJECT_ROOT / "build" / "windows-clean-room" / "proof"
    ).split(os.sep)[-3:]
    assert "from assetguard" not in source and "import assetguard" not in source


@pytest.mark.skipif(
    not INTEGRATION_ENABLED,
    reason="Windows Sandbox integration not explicitly enabled and available",
)
def test_actual_windows_sandbox_clean_room_integration() -> None:
    before = verifier.release_hashes(
        verifier.release_artifacts(PROJECT_ROOT, verifier.EXPECTED_VERSION)
    )
    proof_path, proof_hash, checks_passed = verifier.run_verification(PROJECT_ROOT)
    after = verifier.release_hashes(
        verifier.release_artifacts(PROJECT_ROOT, verifier.EXPECTED_VERSION)
    )

    assert checks_passed > 0
    assert proof_path.is_file()
    assert hashlib.sha256(proof_path.read_bytes()).hexdigest() == proof_hash
    assert before == after == verifier.EXPECTED_HASHES
