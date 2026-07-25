from itertools import product
from pathlib import Path
import re
from typing import Any, Iterator

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
CHECKOUT_ACTION = (
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
)
SETUP_PYTHON_ACTION = (
    "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
)
TEST_RUN_COMMANDS = [
    "python -m pip install uv==0.11.28",
    "uv --version",
    "uv lock --check",
    "uv sync --locked --extra dev --python ${{ matrix.python-version }}",
    "uv pip check",
    (
        "uv run --locked --no-sync python -m pytest -q --cov=assetguard "
        "--cov-report=term-missing --cov-fail-under=90"
    ),
    "uv run --locked --no-sync python -m assetguard --help",
    "uv run --locked --no-sync python -m assetguard scan --help",
    "uv run --locked --no-sync assetguard --help",
    "uv run --locked --no-sync assetguard scan --help",
]
PACKAGE_RUN_COMMANDS = [
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
SUPPLY_CHAIN_STEP_NAME = "Generate and verify deterministic supply-chain metadata"
SUPPLY_CHAIN_FILENAMES = {
    "AssetGuard-0.1.0-all-extras.cdx.json",
    "AssetGuard-0.1.0-runtime.cdx.json",
    "AssetGuard-0.1.0-supply-chain.sha256",
    "AssetGuard-0.1.0-windows-x86_64.provenance.json",
}


def _workflow_text() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def _workflow() -> dict[str, Any]:
    parsed = yaml.load(_workflow_text(), Loader=yaml.BaseLoader)
    assert isinstance(parsed, dict)
    return parsed


def _job(name: str = "test") -> dict[str, Any]:
    jobs = _workflow()["jobs"]
    assert isinstance(jobs, dict)
    job = jobs[name]
    assert isinstance(job, dict)
    return job


def _steps(job_name: str = "test") -> list[dict[str, Any]]:
    steps = _job(job_name)["steps"]
    assert isinstance(steps, list)
    assert all(isinstance(step, dict) for step in steps)
    return steps


def _all_steps() -> list[dict[str, Any]]:
    return [step for job_name in _workflow()["jobs"] for step in _steps(job_name)]


def _step_named(name: str, job_name: str = "package-windows") -> dict[str, Any]:
    matching = [step for step in _steps(job_name) if step.get("name") == name]
    assert len(matching) == 1
    return matching[0]


def _run_commands(job_name: str = "test") -> list[str]:
    return [
        line.strip()
        for step in _steps(job_name)
        for line in str(step.get("run", "")).splitlines()
        if line.strip()
    ]


def _all_run_commands() -> list[str]:
    return [
        line.strip()
        for step in _all_steps()
        for line in str(step.get("run", "")).splitlines()
        if line.strip()
    ]


def _scalar_values(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from _scalar_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _scalar_values(child)
    elif value is not None:
        yield str(value)


def _node_mapping(node: Node) -> dict[str, Node]:
    assert isinstance(node, MappingNode)
    return {
        key.value: value
        for key, value in node.value
        if isinstance(key, ScalarNode)
    }


def test_workflow_exists_parses_and_has_expected_name() -> None:
    assert WORKFLOW_PATH.is_file()
    workflow = _workflow()

    assert workflow["name"] == "AssetGuard CI"


def test_workflow_file_is_portable_yaml_text() -> None:
    raw = WORKFLOW_PATH.read_bytes()

    assert raw.endswith(b"\n")
    assert b"\r" not in raw
    assert b"\t" not in raw


def test_only_safe_required_triggers_are_enabled() -> None:
    triggers = _workflow()["on"]
    assert isinstance(triggers, dict)

    assert set(triggers) == {"push", "pull_request", "workflow_dispatch"}
    assert all(configuration in {None, ""} for configuration in triggers.values())
    assert "pull_request_target" not in triggers
    assert "workflow_run" not in triggers
    assert "schedule" not in triggers


def test_permissions_are_exactly_read_only() -> None:
    workflow = _workflow()
    scalar_values = {value.lower() for value in _scalar_values(workflow)}

    assert workflow["permissions"] == {"contents": "read"}
    assert {"write", "write-all"}.isdisjoint(scalar_values)
    assert workflow["env"] == {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.autocrlf",
        "GIT_CONFIG_VALUE_0": "false",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PYTHONUTF8": "1",
    }


def test_concurrency_cancels_superseded_runs_per_workflow_and_ref() -> None:
    concurrency = _workflow()["concurrency"]
    assert isinstance(concurrency, dict)

    assert "${{ github.workflow }}" in concurrency["group"]
    assert "${{ github.ref }}" in concurrency["group"]
    assert concurrency["cancel-in-progress"] == "true"


def test_exact_four_leg_matrix_and_bounded_job_are_declared() -> None:
    workflow = _workflow()
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    assert set(jobs) == {"test", "package-windows"}

    job = _job()
    strategy = job["strategy"]
    assert isinstance(strategy, dict)
    matrix = strategy["matrix"]
    assert isinstance(matrix, dict)
    assert matrix["os"] == ["ubuntu-latest", "windows-latest"]
    assert matrix["python-version"] == ["3.12", "3.13"]
    assert list(product(matrix["os"], matrix["python-version"])) == [
        ("ubuntu-latest", "3.12"),
        ("ubuntu-latest", "3.13"),
        ("windows-latest", "3.12"),
        ("windows-latest", "3.13"),
    ]
    assert strategy["fail-fast"] == "false"
    assert job["name"] == "Test (${{ matrix.os }}, Python ${{ matrix.python-version }})"
    assert job["runs-on"] == "${{ matrix.os }}"
    assert 1 <= int(job["timeout-minutes"]) <= 60


def test_python_matrix_versions_are_explicitly_quoted_strings() -> None:
    document = yaml.compose(_workflow_text(), Loader=yaml.BaseLoader)
    assert document is not None
    root = _node_mapping(document)
    jobs = _node_mapping(root["jobs"])
    test_job = _node_mapping(jobs["test"])
    strategy = _node_mapping(test_job["strategy"])
    matrix = _node_mapping(strategy["matrix"])
    versions = matrix["python-version"]
    assert isinstance(versions, SequenceNode)

    assert [node.value for node in versions.value] == ["3.12", "3.13"]
    assert all(
        isinstance(node, ScalarNode) and node.style in {"'", '"'}
        for node in versions.value
    )


def test_only_required_full_sha_action_references_are_used() -> None:
    action_references = [step["uses"] for step in _all_steps() if "uses" in step]

    assert action_references == [
        CHECKOUT_ACTION,
        SETUP_PYTHON_ACTION,
        CHECKOUT_ACTION,
        SETUP_PYTHON_ACTION,
    ]
    assert all(
        re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", reference)
        for reference in action_references
    )
    raw = _workflow_text()
    assert f"{CHECKOUT_ACTION} # v7.0.1" in raw
    assert f"{SETUP_PYTHON_ACTION} # v7.0.0" in raw


def test_checkout_does_not_persist_credentials() -> None:
    checkouts = [step for step in _all_steps() if step.get("uses") == CHECKOUT_ACTION]

    assert len(checkouts) == 2
    assert all(
        checkout["with"] == {"persist-credentials": "false"}
        for checkout in checkouts
    )


def test_setup_python_uses_matrix_version_and_pip_cache() -> None:
    setup = next(step for step in _steps() if step.get("uses") == SETUP_PYTHON_ACTION)

    assert setup["with"] == {
        "python-version": "${{ matrix.python-version }}",
        "cache": "pip",
        "cache-dependency-path": "pyproject.toml",
    }


def test_locked_sync_dependency_check_coverage_gate_and_cli_smokes_are_exact() -> None:
    commands = _run_commands()

    assert commands == TEST_RUN_COMMANDS
    test_command = commands[5]
    assert test_command.startswith("uv run --locked --no-sync python -m pytest ")
    assert "--cov=assetguard" in test_command.split()
    assert "--cov-report=term-missing" in test_command.split()
    assert re.findall(r"--cov-fail-under(?:=|\s+)(\d+)", test_command) == ["90"]
    assert commands[-4:] == TEST_RUN_COMMANDS[-4:]


def test_every_project_command_enforces_the_exact_locked_uv_environment() -> None:
    test_commands = _run_commands("test")
    package_commands = _run_commands("package-windows")
    all_commands = test_commands + package_commands

    assert test_commands == TEST_RUN_COMMANDS
    assert package_commands[: len(PACKAGE_RUN_COMMANDS)] == PACKAGE_RUN_COMMANDS
    assert [command for command in all_commands if command.startswith("python -m pip install")] == [
        "python -m pip install uv==0.11.28",
        "python -m pip install uv==0.11.28",
    ]
    assert "python -m pip check" not in all_commands
    assert [command for command in all_commands if command.startswith("uv lock")] == [
        "uv lock --check",
        "uv lock --check",
    ]
    sync_commands = [command for command in all_commands if command.startswith("uv sync")]
    assert sync_commands == [TEST_RUN_COMMANDS[3], PACKAGE_RUN_COMMANDS[3]]
    assert all("--locked" in command.split() for command in sync_commands)
    assert "--extra build" not in test_commands[3]
    assert "--extra build" in package_commands[3]
    uv_runs = [command for command in all_commands if command.startswith("uv run")]
    assert uv_runs
    assert all(
        {"--locked", "--no-sync"} <= set(command.split()) for command in uv_runs
    )


def test_workflow_has_no_continue_on_error_secrets_or_extra_execution() -> None:
    workflow = _workflow()
    scalar_values = [value.lower() for value in _scalar_values(workflow)]
    raw_lower = _workflow_text().lower()

    assert "continue-on-error" not in scalar_values
    assert "secrets." not in raw_lower
    assert "${{ secrets" not in raw_lower
    assert _run_commands() == TEST_RUN_COMMANDS


def test_run_steps_contain_no_write_or_publication_commands() -> None:
    run_text = "\n".join(_all_run_commands()).lower()
    forbidden_patterns = [
        r"\bgit\s+(?:add|commit|push|tag|checkout|reset|clean)\b",
        r"\b(?:publish|deploy)\b|\bgh\s+release\b|\btwine\s+upload\b",
        r"\b(?:curl|wget|invoke-webrequest)\b",
    ]

    assert all(re.search(pattern, run_text) is None for pattern in forbidden_patterns)


def test_no_artifact_or_unapproved_third_party_action_is_referenced() -> None:
    action_references = [step["uses"] for step in _all_steps() if "uses" in step]

    assert set(action_references) == {CHECKOUT_ACTION, SETUP_PYTHON_ACTION}
    assert all("artifact" not in reference.lower() for reference in action_references)


def test_windows_packaging_job_preserves_security_and_exact_contract() -> None:
    job = _job("package-windows")
    steps = _steps("package-windows")
    setup = next(step for step in steps if step.get("uses") == SETUP_PYTHON_ACTION)

    assert job["needs"] == "test"
    assert job["runs-on"] == "windows-latest"
    assert job["timeout-minutes"] == "30"
    assert setup["with"] == {
        "python-version": "3.13.9",
        "cache": "pip",
        "cache-dependency-path": "pyproject.toml",
    }
    assert 'python-version: "3.13.9"' in _workflow_text()
    assert _run_commands("package-windows")[: len(PACKAGE_RUN_COMMANDS)] == PACKAGE_RUN_COMMANDS
    packaging_test = next(
        step
        for step in steps
        if step.get("run") == PACKAGE_RUN_COMMANDS[-1]
    )
    assert packaging_test["env"] == {"ASSETGUARD_PACKAGING_INTEGRATION": "1"}


def test_supply_chain_gate_is_mandatory_and_follows_validated_packaging() -> None:
    steps = _steps("package-windows")
    names = [step.get("name") for step in steps]
    supply_chain = _step_named(SUPPLY_CHAIN_STEP_NAME)

    assert names.index(SUPPLY_CHAIN_STEP_NAME) > names.index(
        "Build and prove repeatable release"
    )
    assert names.index(SUPPLY_CHAIN_STEP_NAME) > names.index(
        "Validate packaged artifacts"
    )
    assert supply_chain["shell"] == "pwsh"
    assert supply_chain["env"] == {"ASSETGUARD_SOURCE_COMMIT": "${{ github.sha }}"}
    assert "if" not in supply_chain
    assert "continue-on-error" not in supply_chain


def test_supply_chain_gate_generates_two_independent_locked_output_sets() -> None:
    run = str(_step_named(SUPPLY_CHAIN_STEP_NAME)["run"])
    generator_prefix = (
        "uv run --locked --no-sync python tools/generate_supply_chain.py"
    )
    invocations = [
        line.strip()
        for line in run.splitlines()
        if "tools/generate_supply_chain.py" in line
    ]

    assert len(invocations) == 2
    assert all(line.startswith(generator_prefix) for line in invocations)
    assert all("--release-dir $releaseDir" in line for line in invocations)
    assert {re.search(r"--output-dir\s+(\$\w+)", line).group(1) for line in invocations} == {
        "$firstOutput",
        "$secondOutput",
    }
    assert all(
        "--source-commit $env:ASSETGUARD_SOURCE_COMMIT" in line
        for line in invocations
    )
    assert '$releaseDir = "dist/release"' in run
    assert '$firstOutput = "build/supply-chain/ci-first"' in run
    assert '$secondOutput = "build/supply-chain/ci-second"' in run
    assert "$firstOutput" != "$secondOutput"


def test_supply_chain_gate_validates_source_commit_and_exact_output_contract() -> None:
    run = str(_step_named(SUPPLY_CHAIN_STEP_NAME)["run"])

    assert "-cnotmatch '^[0-9a-f]{40}$'" in run
    assert "exactly 40 lowercase hexadecimal characters" in run
    assert {
        name for name in SUPPLY_CHAIN_FILENAMES if f'"{name}"' in run
    } == SUPPLY_CHAIN_FILENAMES
    assert all(run.count(f'"{name}"') == 1 for name in SUPPLY_CHAIN_FILENAMES)
    assert "Get-ChildItem -LiteralPath $directory -Force" in run
    assert "Compare-Object -ReferenceObject $expectedNames" in run
    assert "$actualNames.Count -ne $expectedNames.Count" in run
    assert "Assert-ExactSupplyChainOutputSet $firstOutput" in run
    assert "Assert-ExactSupplyChainOutputSet $secondOutput" in run
    assert "verify_supply_chain_checksums" in run
    assert "build/supply-chain/ci-first" in run
    assert "build/supply-chain/ci-second" in run


def test_supply_chain_gate_requires_filename_size_hash_and_byte_equality() -> None:
    run = str(_step_named(SUPPLY_CHAIN_STEP_NAME)["run"])

    assert "Compare-Object -ReferenceObject $firstNames" in run
    assert "relative filename sets differ" in run
    assert "(Get-Item -LiteralPath $firstPath).Length" in run
    assert "(Get-Item -LiteralPath $secondPath).Length" in run
    assert "Get-FileHash -LiteralPath $firstPath -Algorithm SHA256" in run
    assert "Get-FileHash -LiteralPath $secondPath -Algorithm SHA256" in run
    assert "[System.IO.File]::ReadAllBytes" in run
    assert run.count("[Convert]::ToBase64String") == 2
    assert all(
        message in run
        for message in (
            "Supply-chain size mismatch for '$name'",
            "Supply-chain SHA-256 mismatch for '$name'",
            "Supply-chain byte mismatch for '$name'",
        )
    )


def test_supply_chain_gate_fails_closed_without_upload_or_publication() -> None:
    step = _step_named(SUPPLY_CHAIN_STEP_NAME)
    run = str(step["run"])

    assert run.count("if ($LASTEXITCODE -ne 0)") == 3
    assert "throw" in run
    assert "||" not in run
    assert "continue-on-error" not in step
    assert "uses" not in step
    assert "build/supply-chain/" in run
    assert "dist/release" in run
    assert not re.search(r"\b(?:upload|publish|gh\s+release|git\s+add)\b", run, re.I)


def test_packaging_job_has_no_upload_release_signing_or_secrets() -> None:
    raw = _workflow_text().lower()
    packaging_commands = "\n".join(_run_commands("package-windows")).lower()

    assert "upload-artifact" not in raw
    assert "download-artifact" not in raw
    assert "${{ secrets" not in raw
    assert all(
        token not in packaging_commands
        for token in ("git push", "git commit", "git tag", "twine", "signtool")
    )
