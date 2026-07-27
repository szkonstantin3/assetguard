from pathlib import Path
import re
from typing import Any, Iterator

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = PROJECT_ROOT / ".github" / "workflows"
CI_WORKFLOW = WORKFLOWS / "ci.yml"
CODEQL_WORKFLOW = WORKFLOWS / "codeql.yml"
DEPENDABOT_CONFIG = PROJECT_ROOT / ".github" / "dependabot.yml"
DEPENDENCY_POLICY = PROJECT_ROOT / "docs" / "dependency-update-policy.md"
CHECKOUT_ACTION = (
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
)
CODEQL_INIT_ACTION = (
    "github/codeql-action/init@e4fba868fa4b1b91e1fdab776edc8cfbe6e9fb81"
)
CODEQL_ANALYZE_ACTION = (
    "github/codeql-action/analyze@e4fba868fa4b1b91e1fdab776edc8cfbe6e9fb81"
)


def _yaml(path: Path) -> dict[str, Any]:
    parsed = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(parsed, dict)
    return parsed


def _strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)


def _uses_values(value: object) -> Iterator[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "uses":
                assert isinstance(child, str)
                yield child
            yield from _uses_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _uses_values(child)


def _workflow_paths() -> list[Path]:
    return sorted(
        [*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")],
        key=lambda path: path.name,
    )


def test_codeql_workflow_has_exact_triggers_matrix_and_permissions() -> None:
    workflow = _yaml(CODEQL_WORKFLOW)

    assert workflow["name"] == "CodeQL"
    assert workflow["on"] == {
        "push": {"branches": ["main"]},
        "pull_request": {"branches": ["main"]},
        "schedule": [{"cron": "23 3 * * 1"}],
    }
    assert workflow["permissions"] == {}
    assert set(workflow["jobs"]) == {"analyze"}

    job = workflow["jobs"]["analyze"]
    assert job["name"] == "CodeQL (${{ matrix.language }})"
    assert job["runs-on"] == "ubuntu-latest"
    assert job["timeout-minutes"] == "20"
    assert job["strategy"] == {
        "fail-fast": "false",
        "matrix": {
            "include": [
                {"language": "python", "build-mode": "none"},
                {"language": "actions", "build-mode": "none"},
            ]
        },
    }
    assert job["permissions"] == {
        "contents": "read",
        "security-events": "write",
    }


def test_codeql_workflow_uses_only_the_exact_pinned_analysis_steps() -> None:
    job = _yaml(CODEQL_WORKFLOW)["jobs"]["analyze"]
    steps = job["steps"]

    assert [step["name"] for step in steps] == [
        "Check out repository",
        "Initialize CodeQL",
        "Analyze with CodeQL",
    ]
    assert [step["uses"] for step in steps] == [
        CHECKOUT_ACTION,
        CODEQL_INIT_ACTION,
        CODEQL_ANALYZE_ACTION,
    ]
    assert steps[0]["with"] == {"persist-credentials": "false"}
    assert steps[1]["with"] == {
        "languages": "${{ matrix.language }}",
        "build-mode": "${{ matrix.build-mode }}",
        "queries": "security-extended",
    }
    assert steps[2]["with"] == {
        "category": "/language:${{ matrix.language }}"
    }
    assert all("run" not in step for step in steps)


def test_codeql_workflow_has_no_unsafe_or_unnecessary_capability() -> None:
    workflow = _yaml(CODEQL_WORKFLOW)
    raw = CODEQL_WORKFLOW.read_text(encoding="utf-8").lower()
    scalar_values = {value.lower() for value in _strings(workflow)}

    assert {
        "workflow_dispatch",
        "pull_request_target",
        "workflow_run",
        "issue_comment",
        "paths",
        "paths-ignore",
        "secrets",
        "continue-on-error",
    }.isdisjoint(scalar_values)
    assert "${{ secrets" not in raw
    assert "upload-artifact" not in raw
    assert "download-artifact" not in raw
    assert "write-all" not in scalar_values
    assert not re.search(r"\b(?:curl|wget|pip install|uv sync|pytest)\b", raw)


def test_every_remote_workflow_action_is_github_owned_sha_pinned_and_commented() -> None:
    remote_reference = re.compile(
        r"^(?P<owner>[a-z0-9_.-]+)/[a-z0-9_.-]+(?:/[a-z0-9_.-]+)?@[0-9a-f]{40}$"
    )
    version_comment = re.compile(r"#\s+v\d+\.\d+\.\d+\s*$")
    references: list[str] = []

    for path in _workflow_paths():
        document = _yaml(path)
        raw_lines = path.read_text(encoding="utf-8").splitlines()
        path_references = [
            reference
            for reference in _uses_values(document)
            if not reference.startswith(("./", "docker://"))
        ]
        references.extend(path_references)
        for reference in sorted(set(path_references)):
            matched = remote_reference.fullmatch(reference)
            assert matched is not None, f"mutable remote action reference: {reference}"
            assert matched.group("owner") in {"actions", "github"}
            matching_lines = [
                line
                for line in raw_lines
                if re.search(rf"\buses:\s*{re.escape(reference)}(?:\s|$)", line)
            ]
            assert len(matching_lines) == path_references.count(reference)
            assert all(version_comment.search(line) for line in matching_lines)

    assert set(references) == {
        CHECKOUT_ACTION,
        "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
        CODEQL_INIT_ACTION,
        CODEQL_ANALYZE_ACTION,
    }


def test_dependabot_has_exactly_two_independent_update_entries() -> None:
    config = _yaml(DEPENDABOT_CONFIG)

    assert config["version"] == "2"
    assert config["updates"] == [
        {
            "package-ecosystem": "uv",
            "directory": "/",
            "schedule": {
                "interval": "weekly",
                "day": "monday",
                "time": "04:00",
                "timezone": "Etc/UTC",
            },
            "open-pull-requests-limit": "5",
            "versioning-strategy": "increase-if-necessary",
            "cooldown": {"default-days": "7"},
        },
        {
            "package-ecosystem": "github-actions",
            "directory": "/",
            "schedule": {
                "interval": "weekly",
                "day": "tuesday",
                "time": "04:00",
                "timezone": "Etc/UTC",
            },
            "open-pull-requests-limit": "5",
            "cooldown": {"default-days": "7"},
        },
    ]


def test_dependabot_has_no_grouping_credentials_or_unsafe_configuration() -> None:
    config = _yaml(DEPENDABOT_CONFIG)
    forbidden = {
        "groups",
        "multi-ecosystem-groups",
        "registries",
        "credentials",
        "ignore",
        "target-branch",
        "insecure-external-code-execution",
        "auto-merge",
    }

    assert forbidden.isdisjoint({value for value in _strings(config)})
    assert "registries" not in config


def test_existing_assetguard_ci_job_identity_and_matrix_are_unchanged() -> None:
    workflow = _yaml(CI_WORKFLOW)
    jobs = workflow["jobs"]

    assert set(jobs) == {"test", "package-windows"}
    assert jobs["test"]["name"] == (
        "Test (${{ matrix.os }}, Python ${{ matrix.python-version }})"
    )
    assert jobs["test"]["strategy"]["matrix"] == {
        "os": ["ubuntu-latest", "windows-latest"],
        "python-version": ["3.12", "3.13"],
    }
    assert jobs["package-windows"]["name"] == (
        "Package (windows-latest, Python 3.13.9)"
    )
    assert jobs["package-windows"]["needs"] == "test"


def test_dependency_policy_records_independent_review_and_toolchain_boundaries() -> None:
    policy = DEPENDENCY_POLICY.read_text(encoding="utf-8")

    assert "Each dependency and Action update remains independently reviewable" in policy
    assert "cooldown does not delay security updates" in policy
    assert "does not maintain AssetGuard's explicit `uv==0.11.28` toolchain pins" in policy
    assert "separate validated phase" in policy
    assert "lowercase 40-character commit SHA" in policy
    assert "same-line version comment" in policy
