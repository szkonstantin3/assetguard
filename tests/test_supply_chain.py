from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tomllib
from typing import Any, Iterator
import zipfile

import pytest

from tools import build_windows_release as build
from tools import generate_supply_chain as supply


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GENERATOR = PROJECT_ROOT / "tools" / "generate_supply_chain.py"
SUPPLY_DOC = PROJECT_ROOT / "docs" / "supply-chain.md"
UPDATE_POLICY = PROJECT_ROOT / "docs" / "dependency-update-policy.md"
README = PROJECT_ROOT / "README.md"
COMMIT = "a" * 40
LOCK_SHA = "b" * 64


def _raw_sbom(*, all_extras: bool = False) -> dict[str, Any]:
    names = ["Pillow", "pydantic", "PyYAML", "typer"]
    if all_extras:
        names += ["pytest", "pytest-cov", "pyinstaller", "pyinstaller-hooks-contrib"]
    components = [
        {
            "type": "library",
            "bom-ref": f"pkg-{name}",
            "name": name,
            "version": "1.0",
            "purl": f"pkg:pypi/{name.casefold()}@1.0",
            "properties": [
                {"name": "z", "value": "2"},
                {"name": "a", "value": "1"},
            ],
            "hashes": [
                {"alg": "SHA-512", "content": "2"},
                {"alg": "SHA-256", "content": "1"},
            ],
        }
        for name in reversed(names)
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": "urn:uuid:random",
        "metadata": {
            "timestamp": "2026-01-01T00:00:00Z",
            "component": {
                "type": "application",
                "bom-ref": "assetguard-1@0.1.0",
                "name": "AssetGuard",
                "version": "0.1.0",
                "properties": [{"name": "uv:package:is_project_root", "value": "true"}],
            },
        },
        "components": components,
        "dependencies": [
            {"ref": "z", "dependsOn": ["b", "a"]},
            {"ref": "a", "dependsOn": []},
        ],
        "unknown": {"preserved": True},
    }


def _minimal_pe() -> bytes:
    data = bytearray(128)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<H", data, 68, build.PE_MACHINE_AMD64)
    return bytes(data)


def _synthetic_release(directory: Path, source_digest: str = "c" * 64) -> build.ReleaseArtifactSet:
    directory.mkdir(parents=True)
    stem = supply.RELEASE_STEM
    executable_name = f"{stem}.exe"
    archive_name = f"{stem}.zip"
    manifest_name = f"{stem}.manifest.json"
    checksum_name = f"{stem}.sha256"
    payload = {
        "AssetGuard.exe": _minimal_pe(),
        "README.md": b"AssetGuard\n",
        "examples/rules.yaml": b"naming:\n  enabled: true\n",
    }
    executable = directory / executable_name
    executable.write_bytes(payload["AssetGuard.exe"])
    archive = directory / archive_name
    build.create_deterministic_zip(archive, stem, payload)
    manifest = directory / manifest_name
    manifest.write_bytes(build.serialize_manifest("0.1.0", source_digest, payload))
    checksums = directory / checksum_name
    checksums.write_bytes(
        build.serialize_checksums(
            {
                executable_name: executable.read_bytes(),
                archive_name: archive.read_bytes(),
                manifest_name: manifest.read_bytes(),
            }
        )
    )
    return build.ReleaseArtifactSet(executable, archive, manifest, checksums)


def _refresh_release_checksums(artifacts: build.ReleaseArtifactSet) -> None:
    artifacts.checksums.write_bytes(
        build.serialize_checksums(
            {
                artifacts.executable.name: artifacts.executable.read_bytes(),
                artifacts.archive.name: artifacts.archive.read_bytes(),
                artifacts.manifest.name: artifacts.manifest.read_bytes(),
            }
        )
    )


def _validate_synthetic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, supply.ValidatedRelease]:
    release_dir = tmp_path / "release"
    digest = "c" * 64
    _synthetic_release(release_dir, digest)
    monkeypatch.setattr(build, "calculate_source_digest", lambda root: digest)
    return release_dir, supply.validate_release(release_dir, project_root=tmp_path)


def _supply_chain_staging(directory: Path) -> None:
    files = {
        supply.RUNTIME_SBOM_NAME: b"runtime\n",
        supply.ALL_EXTRAS_SBOM_NAME: b"all\n",
        supply.PROVENANCE_NAME: b"provenance\n",
    }
    for name, data in files.items():
        (directory / name).write_bytes(data)
    (directory / supply.SUPPLY_CHAIN_CHECKSUM_NAME).write_bytes(
        supply.serialize_supply_chain_checksums(files)
    )


def _strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def test_generator_and_documentation_files_exist() -> None:
    assert GENERATOR.is_file()
    assert SUPPLY_DOC.is_file()
    assert UPDATE_POLICY.is_file()


def test_generator_does_not_import_application_runtime() -> None:
    source = GENERATOR.read_text(encoding="utf-8")
    assert "import assetguard" not in source
    assert "from assetguard" not in source


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("uv 0.11.28 (123abc 2026-01-01)\n", "0.11.28"),
        ("uv 0.11.28\r\n", "0.11.28"),
    ],
)
def test_uv_version_parser(output: str, expected: str) -> None:
    assert supply.parse_uv_version(output) == expected


@pytest.mark.parametrize("output", ["", "0.11.28", "uv latest", "uv 0.11"])
def test_uv_version_parser_rejects_invalid_output(output: str) -> None:
    with pytest.raises(supply.SupplyChainError, match="parse uv version"):
        supply.parse_uv_version(output)


@pytest.mark.parametrize("commit", ["A" * 40, "a" * 39, "g" * 40, "", "a" * 41])
def test_source_commit_must_be_full_lowercase_hex(commit: str) -> None:
    with pytest.raises(supply.SupplyChainError, match="40 lowercase"):
        supply.validate_source_commit(commit)


def test_source_commit_accepts_full_lowercase_hex() -> None:
    supply.validate_source_commit(COMMIT)


@pytest.mark.parametrize("relationship", ["equal", "output-in-release", "release-in-output"])
def test_release_and_output_directories_cannot_overlap(tmp_path: Path, relationship: str) -> None:
    release = tmp_path / "release"
    output = tmp_path / "output"
    if relationship == "equal":
        output = release
    elif relationship == "output-in-release":
        output = release / "metadata"
    else:
        release = output / "release"
    with pytest.raises(supply.SupplyChainError, match="non-nested"):
        supply.validate_directory_relationship(release, output)


def test_uv_export_commands_are_locked_cyclonedx_and_scope_specific(tmp_path: Path) -> None:
    runtime = supply.uv_export_command("uv", tmp_path / "runtime.json", all_extras=False)
    all_extras = supply.uv_export_command("uv", tmp_path / "all.json", all_extras=True)
    assert runtime[:5] == ["uv", "export", "--locked", "--format", "cyclonedx1.5"]
    assert "--all-extras" not in runtime
    assert all_extras.count("--all-extras") == 1
    assert runtime[-2] == "--output-file"
    assert all_extras[-2] == "--output-file"


def test_controlled_uv_environment_has_no_secret_bearing_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")
    monkeypatch.setenv("PASSWORD", "secret-password")
    environment = supply.controlled_uv_environment()
    assert "GITHUB_TOKEN" not in environment and "PASSWORD" not in environment
    assert environment["PYTHONUTF8"] == "1"
    assert environment["UV_NO_PROGRESS"] == "1"


def test_raw_sbom_loader_requires_cyclonedx_15_and_assetguard(tmp_path: Path) -> None:
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(_raw_sbom()), encoding="utf-8")
    assert supply.load_raw_sbom(path)["specVersion"] == "1.5"
    invalid = _raw_sbom()
    invalid["specVersion"] = "1.6"
    path.write_text(json.dumps(invalid), encoding="utf-8")
    with pytest.raises(supply.SupplyChainError, match="CycloneDX 1.5"):
        supply.load_raw_sbom(path)


def test_normalization_removes_only_unstable_fields_and_preserves_unknowns() -> None:
    raw = _raw_sbom()
    raw["components"][0]["properties"].append(
        {"name": "uv:package:marker", "value": "python_version == '3.13'"}
    )
    normalized = supply.normalize_sbom(raw, scope="runtime", lock_sha256=LOCK_SHA)
    assert "serialNumber" not in normalized
    assert "timestamp" not in normalized["metadata"]
    assert normalized["unknown"] == {"preserved": True}
    assert normalized["bomFormat"] == "CycloneDX"
    assert any(
        property_["name"] == "uv:package:marker"
        for component in normalized["components"]
        for property_ in component["properties"]
    )


def test_normalization_adds_sorted_assetguard_metadata_properties() -> None:
    raw = _raw_sbom()
    raw["metadata"]["properties"] = [{"name": "z", "value": "last"}]
    normalized = supply.normalize_sbom(raw, scope="runtime", lock_sha256=LOCK_SHA)
    properties = normalized["metadata"]["properties"]
    assert properties == sorted(properties, key=lambda item: (item["name"], item["value"]))
    values = {item["name"]: item["value"] for item in properties}
    assert {
        "assetguard:scope": "runtime",
        "assetguard:uv-version": "0.11.28",
        "assetguard:uv-lock-sha256": LOCK_SHA,
    }.items() <= values.items()


def test_normalization_sorts_components_dependencies_properties_and_hashes() -> None:
    normalized = supply.normalize_sbom(_raw_sbom(), scope="runtime", lock_sha256=LOCK_SHA)
    assert [item["bom-ref"] for item in normalized["components"]] == sorted(
        item["bom-ref"] for item in normalized["components"]
    )
    assert [item["ref"] for item in normalized["dependencies"]] == ["a", "z"]
    assert normalized["dependencies"][1]["dependsOn"] == ["a", "b"]
    component = normalized["components"][0]
    assert [item["name"] for item in component["properties"]] == ["a", "z"]
    assert [item["alg"] for item in component["hashes"]] == ["SHA-256", "SHA-512"]


def test_runtime_scope_rejects_development_and_build_packages() -> None:
    with pytest.raises(supply.SupplyChainError, match="runtime SBOM contains"):
        supply.normalize_sbom(_raw_sbom(all_extras=True), scope="runtime", lock_sha256=LOCK_SHA)


def test_all_extras_scope_requires_development_and_build_packages() -> None:
    with pytest.raises(supply.SupplyChainError, match="all-extras SBOM is missing"):
        supply.normalize_sbom(_raw_sbom(), scope="all-extras", lock_sha256=LOCK_SHA)


def test_all_extras_scope_accepts_all_declared_groups() -> None:
    normalized = supply.normalize_sbom(
        _raw_sbom(all_extras=True), scope="all-extras", lock_sha256=LOCK_SHA
    )
    assert len(normalized["components"]) == 8


def test_canonical_json_is_utf8_sorted_lf_and_stable() -> None:
    first = supply.canonical_json({"z": "ž", "a": 1})
    second = supply.canonical_json({"a": 1, "z": "ž"})
    assert first == second
    assert first.startswith(b'{\n  "a"')
    assert b"\r" not in first and first.endswith(b"\n") and not first.endswith(b"\n\n")
    assert "ž" in first.decode("utf-8")


def test_synthetic_release_validates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    release_dir, validated = _validate_synthetic(tmp_path, monkeypatch)
    assert validated.source_digest == "c" * 64
    assert len(validated.hashes) == 4
    assert {path.name for path in release_dir.iterdir()} == set(supply.RELEASE_NAMES)


def test_release_requires_exactly_four_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    release_dir = tmp_path / "release"
    _synthetic_release(release_dir)
    (release_dir / "extra.txt").write_text("unexpected", encoding="utf-8")
    monkeypatch.setattr(build, "calculate_source_digest", lambda root: "c" * 64)
    with pytest.raises(supply.SupplyChainError, match="exactly four"):
        supply.validate_release(release_dir, project_root=tmp_path)


@pytest.mark.parametrize("name", supply.RELEASE_NAMES)
def test_release_rejects_each_missing_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    release_dir = tmp_path / "release"
    _synthetic_release(release_dir)
    (release_dir / name).unlink()
    monkeypatch.setattr(build, "calculate_source_digest", lambda root: "c" * 64)
    with pytest.raises(supply.SupplyChainError, match="exactly four"):
        supply.validate_release(release_dir, project_root=tmp_path)


def test_release_rejects_non_amd64_executable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    release_dir = tmp_path / "release"
    artifacts = _synthetic_release(release_dir)
    artifacts.executable.write_bytes(b"not a PE")
    monkeypatch.setattr(build, "calculate_source_digest", lambda root: "c" * 64)
    with pytest.raises(supply.SupplyChainError, match="not a Windows PE"):
        supply.validate_release(release_dir, project_root=tmp_path)


@pytest.mark.parametrize(
    "checksum_bytes",
    [
        b"bad\n",
        (b"a" * 64) + b"  ../unsafe.exe\n",
        (b"a" * 64) + b"  duplicate.exe\n" + (b"b" * 64) + b"  duplicate.exe\n",
        (b"A" * 64) + b"  file.exe\n",
        (b"a" * 64) + b"  file.exe\r\n",
    ],
)
def test_release_rejects_invalid_checksum_syntax(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, checksum_bytes: bytes
) -> None:
    release_dir = tmp_path / "release"
    artifacts = _synthetic_release(release_dir)
    artifacts.checksums.write_bytes(checksum_bytes)
    monkeypatch.setattr(build, "calculate_source_digest", lambda root: "c" * 64)
    with pytest.raises(supply.SupplyChainError, match="checksum"):
        supply.validate_release(release_dir, project_root=tmp_path)


def test_release_rejects_checksum_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    release_dir = tmp_path / "release"
    artifacts = _synthetic_release(release_dir)
    data = artifacts.checksums.read_text(encoding="ascii")
    artifacts.checksums.write_text("0" * 64 + data[64:], encoding="ascii", newline="\n")
    monkeypatch.setattr(build, "calculate_source_digest", lambda root: "c" * 64)
    with pytest.raises(supply.SupplyChainError, match="verification failed"):
        supply.validate_release(release_dir, project_root=tmp_path)


def test_release_rejects_wrong_manifest_product(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    release_dir = tmp_path / "release"
    artifacts = _synthetic_release(release_dir)
    manifest = json.loads(artifacts.manifest.read_text(encoding="utf-8"))
    manifest["product"]["architecture"] = "arm64"
    artifacts.manifest.write_bytes(supply.canonical_json(manifest))
    _refresh_release_checksums(artifacts)
    monkeypatch.setattr(build, "calculate_source_digest", lambda root: "c" * 64)
    with pytest.raises(supply.SupplyChainError, match="product contract"):
        supply.validate_release(release_dir, project_root=tmp_path)


def test_release_rejects_wrong_toolchain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    release_dir = tmp_path / "release"
    artifacts = _synthetic_release(release_dir)
    manifest = json.loads(artifacts.manifest.read_text(encoding="utf-8"))
    manifest["toolchain"]["python"] = "3.13.8"
    artifacts.manifest.write_bytes(supply.canonical_json(manifest))
    _refresh_release_checksums(artifacts)
    monkeypatch.setattr(build, "calculate_source_digest", lambda root: "c" * 64)
    with pytest.raises(supply.SupplyChainError, match="toolchain"):
        supply.validate_release(release_dir, project_root=tmp_path)


def test_release_rejects_stale_source_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    release_dir = tmp_path / "release"
    _synthetic_release(release_dir, "c" * 64)
    monkeypatch.setattr(build, "calculate_source_digest", lambda root: "d" * 64)
    with pytest.raises(supply.SupplyChainError, match="source digest"):
        supply.validate_release(release_dir, project_root=tmp_path)


def test_release_rejects_wrong_payload_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    release_dir = tmp_path / "release"
    artifacts = _synthetic_release(release_dir)
    manifest = json.loads(artifacts.manifest.read_text(encoding="utf-8"))
    manifest["payload"][0]["path"] = "Other.exe"
    artifacts.manifest.write_bytes(supply.canonical_json(manifest))
    _refresh_release_checksums(artifacts)
    monkeypatch.setattr(build, "calculate_source_digest", lambda root: "c" * 64)
    with pytest.raises(supply.SupplyChainError, match="payload paths"):
        supply.validate_release(release_dir, project_root=tmp_path)


def test_release_rejects_unsafe_or_wrong_zip_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release_dir = tmp_path / "release"
    artifacts = _synthetic_release(release_dir)
    with zipfile.ZipFile(artifacts.archive, "w") as archive:
        archive.writestr("../unsafe", b"bad")
    _refresh_release_checksums(artifacts)
    monkeypatch.setattr(build, "calculate_source_digest", lambda root: "c" * 64)
    with pytest.raises(supply.SupplyChainError, match="ZIP members"):
        supply.validate_release(release_dir, project_root=tmp_path)


def test_release_rejects_zip_payload_hash_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release_dir = tmp_path / "release"
    artifacts = _synthetic_release(release_dir)
    payload = {
        "AssetGuard.exe": artifacts.executable.read_bytes(),
        "README.md": b"changed\n",
        "examples/rules.yaml": b"naming:\n  enabled: true\n",
    }
    build.create_deterministic_zip(artifacts.archive, supply.RELEASE_STEM, payload)
    _refresh_release_checksums(artifacts)
    monkeypatch.setattr(build, "calculate_source_digest", lambda root: "c" * 64)
    with pytest.raises(supply.SupplyChainError, match="ZIP payload"):
        supply.validate_release(release_dir, project_root=tmp_path)


def test_provenance_has_six_sorted_subjects_and_exact_types(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, release = _validate_synthetic(tmp_path, monkeypatch)
    runtime = tmp_path / supply.RUNTIME_SBOM_NAME
    all_extras = tmp_path / supply.ALL_EXTRAS_SBOM_NAME
    runtime.write_bytes(b"runtime\n")
    all_extras.write_bytes(b"all\n")
    document = supply.build_provenance(
        release,
        runtime_sbom=runtime,
        all_extras_sbom=all_extras,
        source_commit=COMMIT,
        lock_sha256=LOCK_SHA,
    )
    assert document["_type"] == "https://in-toto.io/Statement/v1"
    assert document["predicateType"] == "https://slsa.dev/provenance/v1"
    names = [subject["name"] for subject in document["subject"]]
    assert len(names) == 6 and names == sorted(names)
    assert supply.PROVENANCE_NAME not in names
    assert supply.SUPPLY_CHAIN_CHECKSUM_NAME not in names


def test_provenance_records_commit_lock_source_and_exact_builder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, release = _validate_synthetic(tmp_path, monkeypatch)
    runtime = tmp_path / supply.RUNTIME_SBOM_NAME
    all_extras = tmp_path / supply.ALL_EXTRAS_SBOM_NAME
    runtime.write_bytes(b"runtime\n")
    all_extras.write_bytes(b"all\n")
    document = supply.build_provenance(
        release,
        runtime_sbom=runtime,
        all_extras_sbom=all_extras,
        source_commit=COMMIT,
        lock_sha256=LOCK_SHA,
    )
    definition = document["predicate"]["buildDefinition"]
    assert definition["buildType"] == supply.BUILD_TYPE
    assert definition["externalParameters"]["sourceCommit"] == COMMIT
    assert definition["externalParameters"]["buildCommand"][-2:] == [
        "tools/build_windows_release.py",
        "--verify-reproducible",
    ]
    assert [item["uri"] for item in definition["resolvedDependencies"]] == [
        "file:uv.lock",
        f"git+{supply.REPOSITORY_URL}@{COMMIT}",
        "urn:assetguard:windows-release-source-inputs:v1",
    ]
    assert document["predicate"]["runDetails"]["builder"]["id"] == supply.BUILDER_ID
    assert definition["internalParameters"] == {
        "python": "3.13.9",
        "uv": "0.11.28",
        "pyinstaller": "6.21.0",
        "pyinstallerHooksContrib": "2026.6",
        "sourceDateEpoch": 1767225600,
        "repeatabilityMode": "same-toolchain-two-build",
    }
    assert document["predicate"]["runDetails"]["builder"]["version"] == {
        "assetguardBuildProfile": "1",
        "python": "3.13.9",
        "uv": "0.11.28",
        "pyinstaller": "6.21.0",
        "pyinstallerHooksContrib": "2026.6",
    }


def test_provenance_contains_no_time_host_or_invocation_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, release = _validate_synthetic(tmp_path, monkeypatch)
    runtime = tmp_path / supply.RUNTIME_SBOM_NAME
    all_extras = tmp_path / supply.ALL_EXTRAS_SBOM_NAME
    runtime.write_bytes(b"runtime\n")
    all_extras.write_bytes(b"all\n")
    document = supply.build_provenance(
        release,
        runtime_sbom=runtime,
        all_extras_sbom=all_extras,
        source_commit=COMMIT,
        lock_sha256=LOCK_SHA,
    )
    lowered = canonical = supply.canonical_json(document).decode("utf-8").casefold()
    assert "invocation" not in lowered
    assert "startedon" not in lowered and "finishedon" not in lowered
    assert str(tmp_path).casefold() not in canonical


def test_supply_chain_checksum_serialization_is_exact_and_sorted() -> None:
    files = {
        supply.PROVENANCE_NAME: b"p",
        supply.RUNTIME_SBOM_NAME: b"r",
        supply.ALL_EXTRAS_SBOM_NAME: b"a",
    }
    lines = supply.serialize_supply_chain_checksums(files).decode("ascii").splitlines()
    assert [line.split("  ", 1)[1] for line in lines] == sorted(files)
    assert all(re.fullmatch(r"[0-9a-f]{64}  [A-Za-z0-9._-]+", line) for line in lines)


def test_supply_chain_checksum_verification_detects_corruption(tmp_path: Path) -> None:
    _supply_chain_staging(tmp_path)
    supply.verify_supply_chain_checksums(tmp_path)
    (tmp_path / supply.RUNTIME_SBOM_NAME).write_bytes(b"changed")
    with pytest.raises(supply.SupplyChainError, match="verification failed"):
        supply.verify_supply_chain_checksums(tmp_path)


def test_supply_chain_checksum_verification_rejects_unsorted_lines(tmp_path: Path) -> None:
    _supply_chain_staging(tmp_path)
    path = tmp_path / supply.SUPPLY_CHAIN_CHECKSUM_NAME
    lines = path.read_text(encoding="ascii").splitlines(keepends=True)
    path.write_text("".join(reversed(lines)), encoding="ascii", newline="\n")
    with pytest.raises(supply.SupplyChainError, match="sorted by filename"):
        supply.verify_supply_chain_checksums(tmp_path)


def test_atomic_publish_creates_exactly_four_files(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    output = tmp_path / "output"
    staging.mkdir()
    _supply_chain_staging(staging)
    published = supply._atomic_publish_set(staging, output)
    assert len(published) == 4
    assert {path.name for path in output.iterdir()} == set(supply.OUTPUT_NAMES)
    supply.verify_supply_chain_checksums(output)


def test_atomic_publish_restores_prior_set_on_replace_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging = tmp_path / "staging"
    output = tmp_path / "output"
    staging.mkdir()
    output.mkdir()
    _supply_chain_staging(staging)
    _supply_chain_staging(output)
    (staging / supply.RUNTIME_SBOM_NAME).write_bytes(b"new runtime\n")
    staged_files = {
        supply.RUNTIME_SBOM_NAME: (staging / supply.RUNTIME_SBOM_NAME).read_bytes(),
        supply.ALL_EXTRAS_SBOM_NAME: (staging / supply.ALL_EXTRAS_SBOM_NAME).read_bytes(),
        supply.PROVENANCE_NAME: (staging / supply.PROVENANCE_NAME).read_bytes(),
    }
    (staging / supply.SUPPLY_CHAIN_CHECKSUM_NAME).write_bytes(
        supply.serialize_supply_chain_checksums(staged_files)
    )
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    real_replace = supply.os.replace
    calls = 0

    def fail_second(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("controlled failure")
        real_replace(source, destination)

    monkeypatch.setattr(supply.os, "replace", fail_second)
    with pytest.raises(supply.SupplyChainError, match="cannot publish"):
        supply._atomic_publish_set(staging, output)
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before


def test_output_directory_rejects_unexpected_existing_files(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    output = tmp_path / "output"
    staging.mkdir()
    output.mkdir()
    _supply_chain_staging(staging)
    (output / "unrelated.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(supply.SupplyChainError, match="unexpected files"):
        supply._atomic_publish_set(staging, output)


def test_privacy_audit_rejects_project_root_username_and_credentials(tmp_path: Path) -> None:
    target = tmp_path / "metadata.json"
    target.write_bytes(supply.canonical_json({"path": str(PROJECT_ROOT.resolve())}))
    with pytest.raises(supply.SupplyChainError, match="local identity"):
        supply.audit_generated_files([target], project_root=PROJECT_ROOT, temporary_root=tmp_path)
    target.write_bytes(b"github_pat_secret-value")
    with pytest.raises(supply.SupplyChainError, match="credential-like"):
        supply.audit_generated_files([target], project_root=PROJECT_ROOT, temporary_root=tmp_path)


def test_privacy_audit_allows_public_urls_and_relative_lock(tmp_path: Path) -> None:
    target = tmp_path / "metadata.json"
    target.write_bytes(
        supply.canonical_json(
            {
                "repository": supply.REPOSITORY_URL,
                "lock": "file:uv.lock",
                "project": ".",
            }
        )
    )
    supply.audit_generated_files([target], project_root=PROJECT_ROOT, temporary_root=tmp_path / "other")


@pytest.mark.parametrize("url", ["https://private.example/simple", "http://pypi.org/simple"])
def test_privacy_audit_rejects_private_or_insecure_indexes(tmp_path: Path, url: str) -> None:
    target = tmp_path / "metadata.json"
    target.write_bytes(supply.canonical_json({"index": url}))
    with pytest.raises(supply.SupplyChainError, match="private or insecure"):
        supply.audit_generated_files(
            [target], project_root=PROJECT_ROOT, temporary_root=tmp_path / "other"
        )


def test_cli_invalid_commit_is_concise_without_traceback(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(GENERATOR),
            "--release-dir",
            str(tmp_path / "release"),
            "--output-dir",
            str(tmp_path / "output"),
            "--source-commit",
            "BAD",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert result.returncode != 0
    assert "40 lowercase" in result.stderr
    assert "Traceback" not in result.stderr
    assert not (tmp_path / "output").exists()


def test_documentation_describes_unsigned_local_contract_and_commands() -> None:
    supply_doc = SUPPLY_DOC.read_text(encoding="utf-8")
    policy = UPDATE_POLICY.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    assert "assetguard-windows-release-build-type-v1" in supply_doc
    assert "uv run --locked --no-sync python tools/generate_supply_chain.py" in supply_doc
    assert supply.UNSIGNED_WARNING in supply_doc and supply.UNSIGNED_WARNING in readme
    assert "no SLSA level" in supply_doc
    assert all(
        heading in policy
        for heading in (
            "Baseline verification",
            "Targeted update",
            "Full update",
            "Required review",
            "Required validation",
            "Publication policy",
        )
    )
    assert "uv lock --check" in policy and "uv lock --upgrade-package" in policy


def test_documentation_does_not_claim_signing_or_publication() -> None:
    text = (SUPPLY_DOC.read_text(encoding="utf-8") + README.read_text(encoding="utf-8")).casefold()
    assert "unsigned local metadata" in text
    assert "does not upload" in text or "not uploaded" in text
    assert "signed provenance" not in text
    assert "slsa level 1" not in text and "slsa level 2" not in text


def test_supply_chain_integration() -> None:
    if os.environ.get("ASSETGUARD_SUPPLY_CHAIN_INTEGRATION") != "1":
        pytest.skip("supply-chain integration requires ASSETGUARD_SUPPLY_CHAIN_INTEGRATION=1")
    if sys.platform != "win32":
        pytest.skip("supply-chain integration requires Windows")
    release_dir = PROJECT_ROOT / "dist" / "release"
    if not release_dir.is_dir() or {path.name for path in release_dir.iterdir()} != set(supply.RELEASE_NAMES):
        pytest.skip("current four-file Windows release is unavailable")
    executable = shutil.which("uv")
    if executable is None:
        pytest.skip("uv 0.11.28 is required for supply-chain integration")
    version = subprocess.run(
        [executable, "--version"], capture_output=True, text=True, encoding="utf-8", check=False
    )
    if version.returncode != 0 or supply.parse_uv_version(version.stdout) != supply.UV_VERSION:
        pytest.skip("uv 0.11.28 is required for supply-chain integration")
    try:
        supply.validate_release(release_dir)
    except supply.SupplyChainError:
        pytest.skip("current release does not match current locked source inputs")
    output_root = PROJECT_ROOT / "build" / "supply-chain" / "integration"
    first = output_root / "first"
    second = output_root / "second"
    before = {path.name: (build.sha256_file(path), path.stat().st_size, path.stat().st_mtime_ns) for path in release_dir.iterdir()}
    first_result = supply.generate_supply_chain(
        release_dir=release_dir, output_dir=first, source_commit=COMMIT
    )
    second_result = supply.generate_supply_chain(
        release_dir=release_dir, output_dir=second, source_commit=COMMIT
    )
    assert first_result.hashes == second_result.hashes
    assert all((first / name).read_bytes() == (second / name).read_bytes() for name in supply.OUTPUT_NAMES)
    assert {path.name for path in first.iterdir()} == set(supply.OUTPUT_NAMES)
    runtime = json.loads((first / supply.RUNTIME_SBOM_NAME).read_text(encoding="utf-8"))
    all_extras = json.loads((first / supply.ALL_EXTRAS_SBOM_NAME).read_text(encoding="utf-8"))
    assert {item["name"]: item["value"] for item in runtime["metadata"]["properties"]}[
        "assetguard:scope"
    ] == "runtime"
    assert {item["name"]: item["value"] for item in all_extras["metadata"]["properties"]}[
        "assetguard:scope"
    ] == "all-extras"
    provenance = json.loads((first / supply.PROVENANCE_NAME).read_text(encoding="utf-8"))
    assert provenance["predicate"]["buildDefinition"]["externalParameters"]["sourceCommit"] == COMMIT
    supply.verify_supply_chain_checksums(first)
    supply.audit_generated_files(first.iterdir(), project_root=PROJECT_ROOT, temporary_root=output_root)
    after = {path.name: (build.sha256_file(path), path.stat().st_size, path.stat().st_mtime_ns) for path in release_dir.iterdir()}
    assert after == before
