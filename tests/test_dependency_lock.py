import getpass
import hashlib
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tomllib
from typing import Iterator
from urllib.parse import urlsplit

import pytest

from tools import build_windows_release as build


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
LOCK = PROJECT_ROOT / "uv.lock"
WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
UV_VERSION = "0.11.28"
EXPECTED_LOCK_SHA256 = "f2db95d6ae701c605dab99d1649e95fd9fdff1e33498c80a6e0c11c117ed35e2"
EXPECTED_ENVIRONMENTS = [
    "sys_platform == 'linux' and implementation_name == 'cpython' and python_version == '3.12'",
    "sys_platform == 'linux' and implementation_name == 'cpython' and python_version == '3.13'",
    "sys_platform == 'win32' and implementation_name == 'cpython' and python_version == '3.12'",
    "sys_platform == 'win32' and implementation_name == 'cpython' and python_version == '3.13'",
]
EXPECTED_RESOLUTION_MARKERS = [
    "python_full_version < '3.13' and implementation_name == 'cpython' and sys_platform == 'linux'",
    "python_full_version == '3.13.*' and implementation_name == 'cpython' and sys_platform == 'linux'",
    "python_full_version < '3.13' and implementation_name == 'cpython' and sys_platform == 'win32'",
    "python_full_version == '3.13.*' and implementation_name == 'cpython' and sys_platform == 'win32'",
]
EXPECTED_RUNTIME = ["Pillow>=11.0", "pydantic>=2.10", "PyYAML>=6.0", "typer>=0.15"]
EXPECTED_DEV = ["pytest>=8.3", "pytest-cov>=6.0"]
EXPECTED_BUILD = [
    "pyinstaller==6.21.0",
    "pyinstaller-hooks-contrib==2026.6",
]


def _load_toml(path: Path) -> dict[str, object]:
    with path.open("rb") as source:
        return tomllib.load(source)


def _normalized_requirement_name(requirement: str) -> str:
    name = re.split(r"[<>=!~;\[\s]", requirement, maxsplit=1)[0]
    return re.sub(r"[-_.]+", "-", name).lower()


def _strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _package_map(lock: dict[str, object]) -> dict[str, dict[str, object]]:
    packages = lock["package"]
    assert isinstance(packages, list)
    typed = [package for package in packages if isinstance(package, dict)]
    assert len(typed) == len(packages)
    return {str(package["name"]): package for package in typed}


def test_lock_exists_parses_and_uses_supported_schema() -> None:
    assert LOCK.is_file()
    lock = _load_toml(LOCK)

    assert lock["version"] == 1
    assert lock["revision"] == 3
    assert lock["requires-python"] == ">=3.12"
    assert lock["resolution-markers"] == EXPECTED_RESOLUTION_MARKERS
    assert lock["supported-markers"] == EXPECTED_RESOLUTION_MARKERS


def test_pyproject_requires_exact_uv_and_four_supported_environments() -> None:
    project = _load_toml(PYPROJECT)
    uv = project["tool"]["uv"]

    assert uv == {
        "required-version": "==0.11.28",
        "environments": EXPECTED_ENVIRONMENTS,
    }


def test_project_dependency_ranges_extras_and_entry_point_are_preserved() -> None:
    document = _load_toml(PYPROJECT)
    project = document["project"]

    assert project["requires-python"] == ">=3.12"
    assert project["dependencies"] == EXPECTED_RUNTIME
    assert project["optional-dependencies"]["dev"] == EXPECTED_DEV
    assert project["optional-dependencies"]["build"] == EXPECTED_BUILD
    assert project["scripts"] == {"assetguard": "assetguard.cli:app"}
    assert document["build-system"] == {
        "requires": ["setuptools>=75"],
        "build-backend": "setuptools.build_meta",
    }


def test_lock_contains_project_direct_dependencies_and_extras() -> None:
    lock = _load_toml(LOCK)
    packages = _package_map(lock)
    project = packages["assetguard"]

    assert project["version"] == "0.1.0"
    assert project["source"] == {"editable": "."}
    assert {dependency["name"] for dependency in project["dependencies"]} == {
        _normalized_requirement_name(requirement) for requirement in EXPECTED_RUNTIME
    }
    assert {
        dependency["name"]
        for dependency in project["optional-dependencies"]["dev"]
    } == {"pytest", "pytest-cov"}
    assert {
        dependency["name"]
        for dependency in project["optional-dependencies"]["build"]
    } == {"pyinstaller", "pyinstaller-hooks-contrib"}
    assert {
        _normalized_requirement_name(requirement) for requirement in EXPECTED_RUNTIME
    } <= packages.keys()


def test_lock_contains_expected_test_and_exact_build_tools() -> None:
    packages = _package_map(_load_toml(LOCK))

    assert "pytest" in packages and "pytest-cov" in packages
    assert packages["pyinstaller"]["version"] == "6.21.0"
    assert packages["pyinstaller-hooks-contrib"]["version"] == "2026.6"


def test_registry_packages_have_exact_versions_and_distribution_hashes() -> None:
    packages = _package_map(_load_toml(LOCK))
    sha256 = re.compile(r"^sha256:[0-9a-f]{64}$")

    for name, package in packages.items():
        assert re.fullmatch(r"[0-9][0-9A-Za-z.+!-]*", str(package["version"]))
        if name == "assetguard":
            continue
        assert package["source"] == {"registry": "https://pypi.org/simple"}
        artifacts = list(package.get("wheels", []))
        if "sdist" in package:
            artifacts.append(package["sdist"])
        assert artifacts
        assert all(sha256.fullmatch(str(artifact["hash"])) for artifact in artifacts)


def test_lock_has_no_private_git_credential_or_absolute_path_source() -> None:
    lock = _load_toml(LOCK)
    raw = LOCK.read_text(encoding="utf-8")
    project_variants = {
        str(PROJECT_ROOT),
        str(PROJECT_ROOT.resolve()),
        PROJECT_ROOT.as_posix(),
        PROJECT_ROOT.resolve().as_posix(),
    }

    assert all(variant not in raw for variant in project_variants)
    assert getpass.getuser().casefold() not in raw.casefold()
    assert ".venv" not in raw and "site-packages" not in raw
    assert "git+" not in raw.casefold() and "github.com" not in raw.casefold()
    assert not re.search(r"(?i)(github_pat_|gh[pousr]_|bearer\s+|password\s*=)", raw)
    assert not re.search(r"(?i)(?:^|[=\"' ])(?:[a-z]:[\\/]|/(?:home|users|tmp|workspace)/)", raw)

    packages = _package_map(lock)
    assert packages["assetguard"]["source"] == {"editable": "."}
    for package in packages.values():
        source = package["source"]
        assert "git" not in source and "path" not in source
        if "editable" in source:
            assert source["editable"] == "."
        if "registry" in source:
            assert source["registry"] == "https://pypi.org/simple"
    for value in _strings(lock):
        if value.startswith(("http://", "https://")):
            parsed = urlsplit(value)
            assert parsed.scheme == "https"
            assert parsed.username is None and parsed.password is None
            assert parsed.hostname in {"pypi.org", "files.pythonhosted.org"}


def test_local_project_lock_record_has_no_timestamp_metadata() -> None:
    project = _package_map(_load_toml(LOCK))["assetguard"]
    keys = {str(key).casefold() for key in project}

    assert not {"timestamp", "created-at", "updated-at", "upload-time"} & keys


def test_lock_uses_lf_and_exactly_one_final_newline() -> None:
    data = LOCK.read_bytes()

    assert b"\r" not in data
    assert data.endswith(b"\n")
    assert not data.endswith(b"\n\n")


def test_lock_sha256_preserves_the_validated_phase10a_resolution() -> None:
    assert hashlib.sha256(LOCK.read_bytes()).hexdigest() == EXPECTED_LOCK_SHA256


def test_exact_uv_accepts_lock_without_mutating_bytes() -> None:
    executable = shutil.which("uv")
    if executable is None:
        pytest.skip("uv 0.11.28 is not installed")
    version = subprocess.run(
        [executable, "--version"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if not version.stdout.startswith(f"uv {UV_VERSION} "):
        pytest.skip(f"uv {UV_VERSION} is required for the focused lock check")
    before = LOCK.read_bytes()

    result = subprocess.run(
        [executable, "lock", "--check"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert LOCK.read_bytes() == before


def test_build_source_inputs_include_one_safe_lock_path() -> None:
    inputs = build.source_input_paths(PROJECT_ROOT)

    assert inputs.count(Path("uv.lock")) == 1
    assert inputs == sorted(set(inputs), key=lambda path: path.as_posix())
    assert all(not path.is_absolute() for path in inputs)
    assert all(".." not in PurePosixPath(path.as_posix()).parts for path in inputs)


def test_source_digest_changes_with_synthetic_lock_bytes(tmp_path: Path) -> None:
    lock = tmp_path / "uv.lock"
    lock.write_bytes(b"version = 1\n")
    digest = build.calculate_source_digest(tmp_path, [Path("uv.lock")])

    lock.write_bytes(b"version = 1\nrevision = 3\n")

    assert build.calculate_source_digest(tmp_path, [Path("uv.lock")]) != digest


def test_ci_enforces_the_exact_locked_uv_resolution() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    required_uv = _load_toml(PYPROJECT)["tool"]["uv"]["required-version"]
    commands = [line.strip() for line in workflow.splitlines() if line.strip()]

    assert required_uv == f"=={UV_VERSION}"
    assert workflow.count(f"python -m pip install uv{required_uv}") == 2
    assert workflow.count("uv lock --check") == 2
    assert workflow.count("uv sync --locked") == 2
    assert "uv sync --locked --extra dev --python ${{ matrix.python-version }}" in workflow
    assert "uv sync --locked --extra dev --extra build --python 3.13.9" in workflow
    uv_runs = [command.removeprefix("run: ") for command in commands if "uv run " in command]
    assert uv_runs
    assert all("uv run --locked --no-sync" in command for command in uv_runs)
    assert 'python -m pip install -e ".[dev]' not in workflow
