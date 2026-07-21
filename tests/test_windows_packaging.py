import ast
import getpass
import io
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tomllib
import zipfile

import pytest
import yaml

from tools import build_windows_release as build


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
ENTRY_POINT = PROJECT_ROOT / "packaging" / "windows" / "assetguard_entry.py"
SPEC = PROJECT_ROOT / "packaging" / "windows" / "assetguard.spec"
WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
INTEGRATION_ENABLED = (
    sys.platform == "win32"
    and os.environ.get("ASSETGUARD_PACKAGING_INTEGRATION") == "1"
)


def _project_metadata() -> dict[str, object]:
    with PYPROJECT.open("rb") as source:
        return tomllib.load(source)


def _synthetic_pe(path: Path, machine: int = build.PE_MACHINE_AMD64) -> Path:
    data = bytearray(256)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (128).to_bytes(4, "little")
    data[128:132] = b"PE\0\0"
    data[132:134] = machine.to_bytes(2, "little")
    path.write_bytes(data)
    return path


def _fake_artifact_set(directory: Path, marker: bytes) -> build.ReleaseArtifactSet:
    directory.mkdir(parents=True, exist_ok=True)
    paths = {
        "executable": directory / "AssetGuard-0.1.0-windows-x86_64.exe",
        "archive": directory / "AssetGuard-0.1.0-windows-x86_64.zip",
        "manifest": directory / "AssetGuard-0.1.0-windows-x86_64.manifest.json",
        "checksums": directory / "AssetGuard-0.1.0-windows-x86_64.sha256",
    }
    for name, path in paths.items():
        path.write_bytes(marker if name == "executable" else name.encode("ascii"))
    return build.ReleaseArtifactSet(**paths)


def _published_artifacts() -> build.ReleaseArtifactSet:
    version = build.read_project_version(PROJECT_ROOT)
    release = PROJECT_ROOT / "dist" / "release"
    stem = f"AssetGuard-{version}-windows-x86_64"
    return build.ReleaseArtifactSet(
        executable=release / f"{stem}.exe",
        archive=release / f"{stem}.zip",
        manifest=release / f"{stem}.manifest.json",
        checksums=release / f"{stem}.sha256",
    )


def test_build_extra_is_exact_and_runtime_dependencies_stay_clean() -> None:
    metadata = _project_metadata()["project"]
    assert isinstance(metadata, dict)
    extras = metadata["optional-dependencies"]
    assert isinstance(extras, dict)

    assert extras["build"] == [
        "pyinstaller==6.21.0",
        "pyinstaller-hooks-contrib==2026.6",
    ]
    assert extras["dev"] == ["pytest>=8.3", "pytest-cov>=6.0"]
    assert all("pyinstaller" not in dependency.lower() for dependency in metadata["dependencies"])


def test_entry_point_is_a_thin_existing_cli_launcher() -> None:
    source = ENTRY_POINT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = [node for node in tree.body if isinstance(node, ast.ImportFrom)]
    main = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    main_calls = [
        ast.unparse(statement.value)
        for statement in main.body
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
    ]

    assert [(node.module, [alias.name for alias in node.names]) for node in imports] == [
        ("assetguard.cli", ["app"])
    ]
    assert "argparse" not in source and "typer" not in source
    assert "__version__" not in source
    assert source.count("app()") == 1
    assert main_calls == [
        "_configure_utf8_stream(sys.stdout)",
        "_configure_utf8_stream(sys.stderr)",
        "app()",
    ]


def test_entry_point_reconfigures_legacy_stream_for_utf8_output() -> None:
    namespace = runpy.run_path(str(ENTRY_POINT), run_name="assetguard_packaging_test")
    configure = namespace["_configure_utf8_stream"]
    sample = "звіт: C:\\дані\\результат.json"

    legacy_bytes = io.BytesIO()
    legacy_stream = io.TextIOWrapper(legacy_bytes, encoding="cp1252", errors="strict")
    with pytest.raises(UnicodeEncodeError):
        legacy_stream.write(sample)
    legacy_stream.close()

    utf8_bytes = io.BytesIO()
    utf8_stream = io.TextIOWrapper(utf8_bytes, encoding="cp1252", errors="strict")
    configure(utf8_stream)
    assert utf8_stream.encoding == "utf-8"
    assert utf8_stream.errors == "backslashreplace"
    utf8_stream.write(sample)
    utf8_stream.flush()
    assert utf8_bytes.getvalue() == sample.encode("utf-8")
    utf8_stream.detach().close()

    configure(object())
    configure(None)


def test_spec_is_narrow_console_onefile_profile() -> None:
    source = SPEC.read_text(encoding="utf-8")

    assert "exe = EXE(" in source
    assert "COLLECT(" not in source
    assert 'name="AssetGuard"' in source
    assert "console=True" in source
    assert "upx=False" in source
    assert "strip=False" in source
    assert "debug=False" in source
    assert "runtime_tmpdir=None" in source
    assert "uac_admin=False" in source and "uac_uiaccess=False" in source
    assert "PIL.PngImagePlugin" in source
    assert "PIL.TgaImagePlugin" in source
    assert "D:\\AssetGuard" not in source
    assert "collect_all" not in source
    assert "tests" in source


def test_line_endings_and_generated_output_contracts_are_checked_in() -> None:
    attributes = (PROJECT_ROOT / ".gitattributes").read_text(encoding="utf-8")
    ignored = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")

    for extension in ("py", "toml", "yml", "yaml", "md", "json", "spec", "txt"):
        assert f"*.{extension} text eol=lf" in attributes
    for binary in ("exe", "dll", "pyd", "zip", "png", "tga", "sqlite", "sqlite3"):
        assert f"*.{binary} binary" in attributes
    assert "/build/" in ignored and "/dist/" in ignored
    assert "assetguard.spec" not in ignored


def test_fixed_build_epoch_and_no_current_time_release_metadata() -> None:
    source = (PROJECT_ROOT / "tools" / "build_windows_release.py").read_text(
        encoding="utf-8"
    )

    assert build.SOURCE_DATE_EPOCH == 1767225600
    assert '"SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH)' in source
    assert '"PYTHONHASHSEED": "0"' in source
    assert '"PYTHONDONTWRITEBYTECODE": "1"' in source
    assert '"PYINSTALLER_CONFIG_DIR"' in source
    assert "datetime.now" not in source
    assert "datetime.utcnow" not in source
    assert "time.time(" not in source


def test_project_and_runtime_versions_match_and_resource_is_stable(tmp_path: Path) -> None:
    project_version = build.read_project_version(PROJECT_ROOT)
    assert project_version == build.read_runtime_version(PROJECT_ROOT) == "0.1.0"
    assert build.windows_version_tuple(project_version) == (0, 1, 0, 0)

    resource = tmp_path / "version.txt"
    build.generate_version_resource(resource, project_version)
    text = resource.read_text(encoding="utf-8")
    assert "AssetGuard Project" in text
    assert "AssetGuard Game Asset Validator" in text
    assert "AssetGuard.exe" in text
    assert "date=(0, 0)" in text
    assert str(PROJECT_ROOT) not in text


def test_manifest_serialization_is_canonical_sorted_and_path_free() -> None:
    payload = {"README.md": b"readme\n", "AssetGuard.exe": b"exe"}
    first = build.serialize_manifest("0.1.0", "a" * 64, payload)
    second = build.serialize_manifest("0.1.0", "a" * 64, dict(reversed(list(payload.items()))))
    parsed = json.loads(first)

    assert first == second
    assert first.endswith(b"\n") and not first.endswith(b"\n\n")
    assert [entry["path"] for entry in parsed["payload"]] == [
        "AssetGuard.exe",
        "README.md",
    ]
    assert parsed["toolchain"] == {
        "python": "3.13.9",
        "pyinstaller": "6.21.0",
        "pyinstaller_hooks_contrib": "2026.6",
        "source_date_epoch": 1767225600,
    }
    assert str(PROJECT_ROOT).encode() not in first
    assert getpass.getuser().encode() not in first


def test_checksum_serialization_is_stable_lowercase_and_sorted() -> None:
    files = {"z.zip": b"z", "a.exe": b"a", "m.json": b"m"}
    first = build.serialize_checksums(files)
    second = build.serialize_checksums(dict(reversed(list(files.items()))))
    lines = first.decode("utf-8").splitlines()

    assert first == second
    assert [line.split("  ", 1)[1] for line in lines] == ["a.exe", "m.json", "z.zip"]
    assert all(re.fullmatch(r"[0-9a-f]{64}  [^\\/]+", line) for line in lines)
    assert first.endswith(b"\n") and not first.endswith(b"\n\n")


def test_zip_is_stored_ordered_fixed_and_lf_normalized(tmp_path: Path) -> None:
    destination = tmp_path / "release.zip"
    payload = {
        "examples/rules.yaml": b"version: 1\n",
        "README.md": b"readme\n",
        "AssetGuard.exe": b"MZ",
    }
    build.create_deterministic_zip(destination, "AssetGuard-0.1.0-windows-x86_64", payload)

    with zipfile.ZipFile(destination) as archive:
        infos = archive.infolist()
        assert [info.filename for info in infos] == [
            "AssetGuard-0.1.0-windows-x86_64/AssetGuard.exe",
            "AssetGuard-0.1.0-windows-x86_64/README.md",
            "AssetGuard-0.1.0-windows-x86_64/examples/rules.yaml",
        ]
        assert all(info.compress_type == zipfile.ZIP_STORED for info in infos)
        assert all(info.date_time == build.fixed_zip_datetime() for info in infos)
        assert archive.read(infos[1]) == b"readme\n"
        assert archive.read(infos[2]) == b"version: 1\n"


@pytest.mark.parametrize(
    "path",
    ["/absolute", "../escape", "safe/../../escape", "C:/drive", r"back\slash"],
)
def test_zip_paths_reject_absolute_drive_and_traversal(path: str) -> None:
    with pytest.raises(build.BuildError, match="unsafe ZIP path"):
        build.validate_archive_path(path)


def test_text_normalization_does_not_modify_source(tmp_path: Path) -> None:
    source = tmp_path / "text.md"
    original = b"one\r\ntwo\rthree\n"
    source.write_bytes(original)

    assert build.normalized_text_bytes(source) == b"one\ntwo\nthree\n"
    assert source.read_bytes() == original


def test_source_digest_is_deterministic_and_content_sensitive(tmp_path: Path) -> None:
    first = tmp_path / "a.txt"
    second = tmp_path / "nested" / "b.txt"
    second.parent.mkdir()
    first.write_bytes(b"alpha")
    second.write_bytes(b"beta")
    paths = [Path("nested/b.txt"), Path("a.txt")]

    digest = build.calculate_source_digest(tmp_path, paths)
    assert digest == build.calculate_source_digest(tmp_path, list(reversed(paths)))
    second.write_bytes(b"BETa")
    assert build.calculate_source_digest(tmp_path, paths) != digest


def test_source_digest_changes_when_lock_bytes_change(tmp_path: Path) -> None:
    lock = tmp_path / "uv.lock"
    lock.write_bytes(b"version = 1\n")
    paths = [Path("uv.lock")]
    digest = build.calculate_source_digest(tmp_path, paths)

    lock.write_bytes(b"version = 2\n")

    assert build.calculate_source_digest(tmp_path, paths) != digest


def test_source_digest_input_set_contains_all_required_classes() -> None:
    relative = [path.as_posix() for path in build.source_input_paths(PROJECT_ROOT)]

    assert relative[:3] == ["README.md", "examples/rules.yaml", "packaging/windows/assetguard.spec"]
    assert "packaging/windows/assetguard_entry.py" in relative
    assert "pyproject.toml" in relative
    assert "tools/build_windows_release.py" in relative
    assert relative.count("uv.lock") == 1
    assert "src/assetguard/cli.py" in relative
    assert all(not Path(path).is_absolute() for path in relative)


def test_valid_amd64_pe_passes_and_invalid_pe_fails(tmp_path: Path) -> None:
    build.validate_amd64_pe(_synthetic_pe(tmp_path / "valid.exe"))
    with pytest.raises(build.BuildError, match="not AMD64"):
        build.validate_amd64_pe(_synthetic_pe(tmp_path / "x86.exe", machine=0x014C))
    invalid = tmp_path / "invalid.exe"
    invalid.write_bytes(b"not PE")
    with pytest.raises(build.BuildError, match="not a Windows PE"):
        build.validate_amd64_pe(invalid)


def test_wrong_platform_python_or_architecture_is_rejected() -> None:
    with pytest.raises(build.BuildError, match="Windows is required"):
        build.verify_platform(system="Linux")
    with pytest.raises(build.BuildError, match="CPython 3.13.9 is required"):
        build.verify_platform(
            system="Windows",
            implementation="CPython",
            python_version=(3, 13, 8),
            machine="AMD64",
            is_64_bit=True,
        )
    with pytest.raises(build.BuildError, match="x86_64/AMD64"):
        build.verify_platform(
            system="Windows",
            implementation="CPython",
            python_version=(3, 13, 9),
            machine="ARM64",
            is_64_bit=True,
        )


def test_wrong_pyinstaller_and_hooks_versions_are_rejected() -> None:
    versions = {
        "pyinstaller": "6.20.0",
        "pyinstaller-hooks-contrib": "2026.6",
    }
    with pytest.raises(build.BuildError, match="pyinstaller 6.21.0 is required"):
        build.verify_tool_versions(versions.__getitem__)
    versions["pyinstaller"] = "6.21.0"
    versions["pyinstaller-hooks-contrib"] = "2026.5"
    with pytest.raises(build.BuildError, match="hooks-contrib 2026.6 is required"):
        build.verify_tool_versions(versions.__getitem__)


def test_sanitized_runtime_environment_removes_python_and_venv_paths(tmp_path: Path) -> None:
    environment = build.sanitized_runtime_environment(tmp_path)

    assert "PYTHONHOME" not in environment
    assert "PYTHONPATH" not in environment
    assert "VIRTUAL_ENV" not in environment
    assert environment["PYTHONUTF8"] == "1"
    assert str(Path(sys.executable).parent).lower() not in environment["PATH"].lower()


def test_failed_build_does_not_publish(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(build, "verify_build_environment", lambda _root: "0.1.0")

    def fail_build(_root: Path, _build_root: Path, _version: str) -> Path:
        raise build.BuildError("simulated build failure")

    monkeypatch.setattr(build, "invoke_pyinstaller", fail_build)
    with pytest.raises(build.BuildError, match="simulated build failure"):
        build.build_release(tmp_path)
    assert not (tmp_path / "dist" / "release").exists()


def test_reproducibility_mismatch_does_not_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(build, "verify_build_environment", lambda _root: "0.1.0")
    counter = iter([b"first", b"second"])

    def fake_executable(_root: Path, current: Path, _version: str) -> Path:
        return _synthetic_pe(current / "AssetGuard.exe")

    proof = build.PackagedProof(0, 0, 1, 2, 2, True, True, True)
    monkeypatch.setattr(build, "invoke_pyinstaller", fake_executable)
    monkeypatch.setattr(build, "run_packaged_proofs", lambda *_args: proof)
    monkeypatch.setattr(
        build,
        "create_release_artifact_set",
        lambda _root, _exe, destination, _version: _fake_artifact_set(
            destination, next(counter)
        ),
    )
    monkeypatch.setattr(build, "assert_no_artifact_leakage", lambda *_args: None)

    with pytest.raises(build.BuildError, match="reproducibility mismatch"):
        build.build_release(tmp_path, verify_reproducible=True)
    assert not (tmp_path / "dist" / "release").exists()


def test_ci_contains_locked_read_only_dependent_windows_packaging_job() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    package_job = workflow["jobs"]["package-windows"]
    commands = [
        line.strip()
        for step in package_job["steps"]
        if isinstance(step, dict)
        for line in step.get("run", "").splitlines()
        if line.strip()
    ]
    expected = [
        "python -m pip install uv==0.11.28",
        "uv --version",
        "uv lock --check",
        "uv sync --locked --extra dev --extra build --python 3.13.9",
        "uv pip check",
        (
            "uv run --locked --no-sync python tools/build_windows_release.py "
            "--verify-reproducible"
        ),
        (
            "uv run --locked --no-sync python -m pytest -q "
            "tests/test_windows_packaging.py"
        ),
    ]

    assert workflow["permissions"] == {"contents": "read"}
    assert package_job["needs"] == "test"
    assert package_job["runs-on"] == "windows-latest"
    assert commands == expected
    integration_step = next(
        step for step in package_job["steps"] if step.get("run") == expected[-1]
    )
    assert integration_step["env"] == {"ASSETGUARD_PACKAGING_INTEGRATION": "1"}
    assert 'python -m pip install -e ".[dev,build]"' not in WORKFLOW.read_text(
        encoding="utf-8"
    )
    assert "python -m pip check" not in commands
    assert "upload-artifact" not in WORKFLOW.read_text(encoding="utf-8")
    assert "${{ secrets" not in WORKFLOW.read_text(encoding="utf-8")


@pytest.mark.skipif(not INTEGRATION_ENABLED, reason="packaging integration not enabled")
def test_built_release_has_exact_four_files_and_amd64_executable() -> None:
    artifacts = _published_artifacts()
    expected = {path.name for path in artifacts.ordered_paths()}

    assert artifacts.executable.parent.is_dir()
    assert {path.name for path in artifacts.executable.parent.iterdir()} == expected
    assert all(path.is_file() for path in artifacts.ordered_paths())
    build.validate_amd64_pe(artifacts.executable)


@pytest.mark.skipif(not INTEGRATION_ENABLED, reason="packaging integration not enabled")
def test_built_executable_help_and_full_packaged_proof(tmp_path: Path) -> None:
    artifacts = _published_artifacts()
    help_result = subprocess.run(
        [str(artifacts.executable.resolve()), "--help"],
        cwd=tmp_path,
        env=build.sanitized_runtime_environment(tmp_path / "temp"),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    scan_help_result = subprocess.run(
        [str(artifacts.executable.resolve()), "scan", "--help"],
        cwd=tmp_path,
        env=build.sanitized_runtime_environment(tmp_path / "temp-2"),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    proof = build.run_packaged_proofs(artifacts.executable, tmp_path / "proof")

    assert help_result.returncode == scan_help_result.returncode == 0
    assert (proof.valid_exit, proof.warning_exit, proof.error_exit, proof.operational_exit) == (
        0,
        0,
        1,
        2,
    )
    assert proof.cache_hits == 2
    assert proof.json_equal and proof.html_equal and proof.assets_unchanged


@pytest.mark.skipif(not INTEGRATION_ENABLED, reason="packaging integration not enabled")
def test_built_executable_redirects_cyrillic_output_as_utf8_under_legacy_codepage(
    tmp_path: Path,
) -> None:
    executable = _published_artifacts().executable.resolve()
    assets = tmp_path / "активи"
    assets.mkdir()
    texture = assets / "T_текстура.png"
    texture.write_bytes(build.deterministic_png())
    config = tmp_path / "правила.yaml"
    config.write_text(
        """version: 1
scan:
  exclude_directories:
    - .git
naming:
  enabled: true
  severity: error
  allowed_prefixes:
    - T_
textures:
  enabled: true
  severity: error
  extensions:
    - .png
  require_power_of_two: true
  max_width: 4096
  max_height: 4096
duplicates:
  enabled: false
  severity: warning
""",
        encoding="utf-8",
        newline="\n",
    )
    report = tmp_path / "звіти" / "результат.json"
    html_report = tmp_path / "звіти" / "результат.html"
    cache = tmp_path / "кеш" / "метрики.sqlite3"
    command = [
        str(executable),
        "scan",
        str(assets.resolve()),
        "--config",
        str(config.resolve()),
        "--output",
        str(report.resolve()),
        "--html-output",
        str(html_report.resolve()),
        "--cache",
        str(cache.resolve()),
        "--workers",
        "4",
    ]
    environment = build.sanitized_runtime_environment(tmp_path / "runtime-temp")
    environment["PYTHONUTF8"] = "0"
    environment["PYTHONIOENCODING"] = "cp1252:strict"
    initial_stat = texture.stat()
    initial_asset = (
        build.sha256_file(texture),
        initial_stat.st_size,
        initial_stat.st_mtime_ns,
    )

    first = subprocess.run(
        command,
        cwd=tmp_path,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    first_stdout = first.stdout.decode("utf-8", errors="strict")
    first_stderr = first.stderr.decode("utf-8", errors="strict")

    assert first.returncode == 0
    assert str(report.resolve()) in first_stdout
    assert str(html_report.resolve()) in first_stdout
    assert report.is_file() and html_report.is_file() and cache.is_file()
    assert "Traceback" not in first_stderr
    assert "UnicodeEncodeError" not in first_stderr
    first_json = report.read_bytes()
    first_html = html_report.read_bytes()

    second = subprocess.run(
        command,
        cwd=tmp_path,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    second_stdout = second.stdout.decode("utf-8", errors="strict")
    second_stderr = second.stderr.decode("utf-8", errors="strict")
    final_stat = texture.stat()
    final_asset = (
        build.sha256_file(texture),
        final_stat.st_size,
        final_stat.st_mtime_ns,
    )

    assert second.returncode == 0
    assert "Cache hits: 1" in second_stdout
    assert str(report.resolve()) in second_stdout
    assert str(html_report.resolve()) in second_stdout
    assert "Traceback" not in second_stderr
    assert "UnicodeEncodeError" not in second_stderr
    assert report.read_bytes() == first_json
    assert html_report.read_bytes() == first_html
    assert final_asset == initial_asset


@pytest.mark.skipif(not INTEGRATION_ENABLED, reason="packaging integration not enabled")
def test_release_zip_manifest_and_checksums_are_consistent() -> None:
    artifacts = _published_artifacts()
    version = build.read_project_version(PROJECT_ROOT)
    stem = f"AssetGuard-{version}-windows-x86_64"
    manifest = json.loads(artifacts.manifest.read_text(encoding="utf-8"))

    with zipfile.ZipFile(artifacts.archive) as archive:
        names = archive.namelist()
        assert names == [
            f"{stem}/AssetGuard.exe",
            f"{stem}/README.md",
            f"{stem}/examples/rules.yaml",
        ]
        payload = {
            name.removeprefix(f"{stem}/"): archive.read(name) for name in names
        }
    assert manifest["source"]["sha256"] == build.calculate_source_digest(PROJECT_ROOT)
    assert manifest["payload"] == [
        {
            "path": path,
            "size": len(payload[path]),
            "sha256": build.sha256_bytes(payload[path]),
        }
        for path in sorted(payload)
    ]
    build.verify_checksum_file(artifacts)


@pytest.mark.skipif(not INTEGRATION_ENABLED, reason="packaging integration not enabled")
def test_two_clean_staged_artifact_sets_are_byte_identical_and_path_free() -> None:
    version = build.read_project_version(PROJECT_ROOT)
    stem = f"AssetGuard-{version}-windows-x86_64"

    def staged(number: int) -> build.ReleaseArtifactSet:
        root = PROJECT_ROOT / "build" / "windows-release" / f"build-{number}" / "release-set"
        return build.ReleaseArtifactSet(
            executable=root / f"{stem}.exe",
            archive=root / f"{stem}.zip",
            manifest=root / f"{stem}.manifest.json",
            checksums=root / f"{stem}.sha256",
        )

    first = staged(1)
    second = staged(2)
    assert all(path.is_file() for path in first.ordered_paths() + second.ordered_paths())
    assert build.compare_artifact_sets(first, second) == build.artifact_hashes(first)
    build.assert_no_artifact_leakage(_published_artifacts(), PROJECT_ROOT)
