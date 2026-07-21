import copy
import json
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

from click.testing import Result
from PIL import Image
import pytest
from typer.testing import CliRunner

import assetguard.cli as cli_module
import assetguard.html_reporting as html_module
import assetguard.scanner as scanner_module
from assetguard.cache import cache_related_paths
from assetguard.cli import app
from assetguard.html_reporting import (
    HtmlReportError,
    render_html_report,
    validate_html_output_path,
    write_html_report,
)
from assetguard.models import Issue, Report, ScanInfo, Summary, ToolInfo

runner = CliRunner()

VALID_OBJ = """\
v 0 0 0
v 1 0 0
v 0 1 0
vt 0 0
vt 1 0
vt 0 1
f 1/1 2/2 3/3
"""


def make_report(
    *,
    passed: bool = True,
    issues: list[Issue] | None = None,
) -> Report:
    return Report(
        tool=ToolInfo(version="0.1.0"),
        scan=ScanInfo(
            files_scanned=7,
            textures_checked=2,
            meshes_checked=3,
            duplicate_groups=1,
        ),
        summary=Summary(
            errors=0 if passed else 2,
            warnings=3,
            passed=passed,
        ),
        issues=[] if issues is None else issues,
    )


def write_rules(
    path: Path,
    *,
    naming: bool = False,
    naming_severity: str = "error",
    textures: bool = True,
    texture_severity: str = "error",
    meshes: bool = True,
    mesh_severity: str = "error",
    duplicates: bool = False,
) -> Path:
    path.write_text(
        f"""\
version: 1
scan:
  exclude_directories: []
naming:
  enabled: {str(naming).lower()}
  severity: {naming_severity}
  allowed_prefixes: [T_, SM_]
textures:
  enabled: {str(textures).lower()}
  severity: {texture_severity}
  extensions: [.png, .tga]
  require_power_of_two: true
  max_width: 4096
  max_height: 4096
meshes:
  enabled: {str(meshes).lower()}
  severity: {mesh_severity}
  extensions: [.obj]
  require_triangulated: true
  require_uv: true
  max_triangles: 100000
  max_material_slots: 8
duplicates:
  enabled: {str(duplicates).lower()}
  severity: warning
""",
        encoding="utf-8",
    )
    return path


def invoke_scan(
    assets: Path,
    config: Path,
    output: Path,
    *,
    html_output: Path | None = None,
    cache: Path | None = None,
    workers: int = 1,
) -> Result:
    arguments = [
        "scan",
        str(assets),
        "--config",
        str(config),
        "--output",
        str(output),
        "--workers",
        str(workers),
    ]
    if html_output is not None:
        arguments.extend(["--html-output", str(html_output)])
    if cache is not None:
        arguments.extend(["--cache", str(cache)])
    return runner.invoke(app, arguments)


def create_png(path: Path, size: tuple[int, int] = (64, 64), color: int = 20) -> Path:
    Image.new("RGBA", size, (color, color, color, 255)).save(path)
    return path


def test_renderer_creates_complete_html5_document_and_status() -> None:
    passing = render_html_report(make_report(passed=True))
    failing = render_html_report(make_report(passed=False))

    assert passing.startswith("<!doctype html>\n<html lang=\"en\">\n")
    assert passing.endswith("</body>\n</html>\n")
    assert "<head>" in passing and "<main>" in passing and "<footer>" in passing
    assert "Status: <span class=\"status status--passed\">PASSED</span>" in passing
    assert "Status: <span class=\"status status--failed\">FAILED</span>" in failing
    assert '<meta charset="utf-8">' in passing
    assert '<meta name="viewport"' in passing
    assert "Content-Security-Policy" in passing
    assert "<style>" in passing


def test_summary_uses_exact_typed_values_and_no_issue_message() -> None:
    rendered = render_html_report(make_report())

    expected = {
        "Files scanned": 7,
        "Textures checked": 2,
        "Meshes checked": 3,
        "Duplicate groups": 1,
        "Errors": 0,
        "Warnings": 3,
    }
    for label, value in expected.items():
        assert f"<dt>{label}</dt><dd>{value}</dd>" in rendered
    assert "No validation issues were found." in rendered
    assert "<tbody>" not in rendered


def test_issue_rows_preserve_order_and_render_canonical_details() -> None:
    issues = [
        Issue(
            code="Z_SECOND",
            severity="warning",
            path="雪/模型.obj",
            message="Unicode π warning",
            details={"zeta": 2, "alpha": 1},
        ),
        Issue(
            code="A_FIRST",
            severity="error",
            path="T_asset.png",
            message="Error message",
            details=None,
        ),
    ]

    rendered = render_html_report(make_report(passed=False, issues=issues))

    assert rendered.index("Z_SECOND") < rendered.index("A_FIRST")
    assert "WARNING" in rendered and "ERROR" in rendered
    assert "雪/模型.obj" in rendered and "Unicode π warning" in rendered
    assert rendered.index("&quot;alpha&quot;") < rendered.index("&quot;zeta&quot;")
    assert "<pre><code>{" in rendered
    assert 'aria-label="No details">&mdash;' in rendered


@pytest.mark.parametrize("details", [None, {}])
def test_absent_or_empty_details_use_deterministic_em_dash(
    details: dict[str, object] | None,
) -> None:
    issue = Issue(
        code="DETAILS",
        severity="warning",
        path="asset.bin",
        message="message",
        details=details,
    )

    rendered = render_html_report(make_report(issues=[issue]))

    assert rendered.count('aria-label="No details">&mdash;') == 1


def test_all_dynamic_issue_content_is_escaped() -> None:
    attack = '</script><img src=x onerror=alert(1)><a href="https://example.invalid">& " \' < >'
    issue = Issue(
        code=attack,
        severity="error",
        path=attack,
        message=attack,
        details={"payload": attack},
    )

    rendered = render_html_report(make_report(passed=False, issues=[issue]))

    assert "&lt;/script&gt;" in rendered
    assert "&lt;img src=x onerror=alert(1)&gt;" in rendered
    assert "&lt;a href=&quot;" in rendered
    assert "&amp; &quot;" in rendered and "&#x27;" in rendered
    assert "<script" not in rendered.lower()
    assert "<img" not in rendered.lower()
    assert "<a " not in rendered.lower()
    assert "onerror=" not in rendered.replace("&lt;img src=x onerror=", "")


def test_static_document_has_no_runtime_or_external_dependencies() -> None:
    rendered = render_html_report(make_report())
    lowered = rendered.lower()

    assert "<script" not in lowered
    assert "<link" not in lowered
    assert "http://" not in lowered
    assert "https://" not in lowered
    assert "file://" not in lowered
    assert "src=" not in lowered
    assert "url(" not in lowered
    assert "script-src 'none'" in lowered
    assert "base-uri 'none'" in lowered


def test_rendering_is_byte_deterministic_and_does_not_mutate_report() -> None:
    report = make_report(
        passed=False,
        issues=[
            Issue(
                code="CODE",
                severity="error",
                path="asset.bin",
                message="message",
                details={"b": 2, "a": 1},
            )
        ],
    )
    before = copy.deepcopy(report.model_dump())

    first = render_html_report(report)
    second = render_html_report(report)

    assert first.encode("utf-8") == second.encode("utf-8")
    assert report.model_dump() == before
    assert "\r" not in first
    assert first.endswith("\n") and not first.endswith("\n\n")


def test_writer_creates_parents_and_uses_utf8_lf_and_one_newline(tmp_path: Path) -> None:
    issue = Issue(
        code="UNICODE",
        severity="warning",
        path="雪/模型.obj",
        message="π message",
    )
    output = tmp_path / "deep" / "reports" / "report.html"

    write_html_report(make_report(issues=[issue]), output)
    content = output.read_bytes()

    assert content.startswith(b"<!doctype html>")
    assert not content.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in content
    assert content.endswith(b"\n") and not content.endswith(b"\n\n")
    assert "雪/模型.obj" in content.decode("utf-8")


def test_invalid_details_are_a_typed_rendering_failure() -> None:
    issue = Issue(
        code="BAD_DETAILS",
        severity="error",
        path="asset.bin",
        message="message",
        details={"not_json": object()},
    )

    with pytest.raises(HtmlReportError, match="cannot render HTML report"):
        render_html_report(make_report(passed=False, issues=[issue]))


def test_atomic_writer_failure_cleans_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "report.html"

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("replacement failed")

    monkeypatch.setattr(html_module.os, "replace", fail_replace)

    with pytest.raises(HtmlReportError, match="cannot write HTML report"):
        write_html_report(make_report(), output)
    assert not output.exists()
    assert list(tmp_path.glob(".report.html.*.tmp")) == []


def test_temporary_file_creation_failure_is_typed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_temporary_file(**_kwargs: object) -> object:
        raise OSError("temporary file unavailable")

    monkeypatch.setattr(html_module.tempfile, "NamedTemporaryFile", fail_temporary_file)

    with pytest.raises(HtmlReportError, match="cannot write HTML report"):
        write_html_report(make_report(), tmp_path / "report.html")


def test_path_resolution_failure_is_typed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_resolve = Path.resolve

    def fail_html_resolve(path: Path, strict: bool = False) -> Path:
        if path.name == "report.html":
            raise OSError("resolution failed")
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", fail_html_resolve)

    with pytest.raises(HtmlReportError, match="cannot resolve HTML output"):
        validate_html_output_path(
            tmp_path / "report.html",
            tmp_path / "report.json",
            tmp_path / "rules.yaml",
        )


def test_omitting_html_preserves_cli_output_and_creates_no_html(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "T_valid.bin").write_bytes(b"valid")
    config = write_rules(tmp_path / "rules.yaml", textures=False, meshes=False, naming=True)
    output = tmp_path / "report.json"

    result = invoke_scan(assets, config, output)

    assert result.exit_code == 0
    assert result.stdout == (
        "Files scanned: 1\n"
        "Textures checked: 0\n"
        "Meshes checked: 0\n"
        "Errors: 0\n"
        "Warnings: 0\n"
        "Duplicate groups: 0\n"
        f"Report: {output}\n"
    )
    assert list(tmp_path.rglob("*.html")) == []


def test_cli_creates_html_and_prints_report_path(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "T_valid.bin").write_bytes(b"valid")
    output = tmp_path / "report.json"
    html_output = tmp_path / "nested" / "report.html"

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml", textures=False, meshes=False),
        output,
        html_output=html_output,
    )

    assert result.exit_code == 0
    assert output.is_file() and html_output.is_file()
    assert f"HTML report: {html_output}" in result.stdout


def test_python_module_entrypoint_supports_html_output(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "T_valid.bin").write_bytes(b"valid")
    config = write_rules(tmp_path / "rules.yaml", textures=False, meshes=False)
    output = tmp_path / "report.json"
    html_output = tmp_path / "report.html"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "assetguard",
            "scan",
            str(assets),
            "--config",
            str(config),
            "--output",
            str(output),
            "--html-output",
            str(html_output),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert output.is_file() and html_output.is_file()
    assert f"HTML report: {html_output}" in result.stdout


def test_worker_counts_produce_identical_json_and_html(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_first.png", (63, 64), 10)
    create_png(assets / "T_second.png", (64, 64), 20)
    (assets / "SM_valid.obj").write_text(VALID_OBJ, encoding="utf-8")
    config = write_rules(tmp_path / "rules.yaml", texture_severity="warning")

    one_json = tmp_path / "one.json"
    one_html = tmp_path / "one.html"
    four_json = tmp_path / "four.json"
    four_html = tmp_path / "four.html"
    one = invoke_scan(assets, config, one_json, html_output=one_html, workers=1)
    four = invoke_scan(assets, config, four_json, html_output=four_html, workers=4)

    assert one.exit_code == four.exit_code == 0
    assert one_json.read_bytes() == four_json.read_bytes()
    assert one_html.read_bytes() == four_html.read_bytes()


def test_cache_miss_hit_and_no_cache_html_are_identical(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_valid.png")
    (assets / "SM_valid.obj").write_text(VALID_OBJ, encoding="utf-8")
    config = write_rules(tmp_path / "rules.yaml")
    cache = tmp_path / "metrics.sqlite3"

    no_cache_json = tmp_path / "no-cache.json"
    no_cache_html = tmp_path / "no-cache.html"
    miss_json = tmp_path / "miss.json"
    miss_html = tmp_path / "miss.html"
    hit_json = tmp_path / "hit.json"
    hit_html = tmp_path / "hit.html"
    no_cache = invoke_scan(
        assets,
        config,
        no_cache_json,
        html_output=no_cache_html,
        workers=4,
    )
    miss = invoke_scan(
        assets,
        config,
        miss_json,
        html_output=miss_html,
        cache=cache,
        workers=4,
    )
    hit = invoke_scan(
        assets,
        config,
        hit_json,
        html_output=hit_html,
        cache=cache,
        workers=4,
    )

    assert no_cache.exit_code == miss.exit_code == hit.exit_code == 0
    assert "Cache misses: 2" in miss.stdout
    assert "Cache hits: 2" in hit.stdout
    assert no_cache_json.read_bytes() == miss_json.read_bytes() == hit_json.read_bytes()
    assert no_cache_html.read_bytes() == miss_html.read_bytes() == hit_html.read_bytes()
    html_text = hit_html.read_text(encoding="utf-8")
    assert "Cache hits" not in html_text and "Cache misses" not in html_text
    assert "worker" not in html_text.lower()
    assert str(cache) not in html_text
    assert str(tmp_path) not in html_text


def test_enabling_html_does_not_change_json_bytes_or_schema(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "T_valid.bin").write_bytes(b"valid")
    config = write_rules(tmp_path / "rules.yaml", textures=False, meshes=False)
    plain_json = tmp_path / "plain.json"
    html_json = tmp_path / "html.json"

    plain = invoke_scan(assets, config, plain_json)
    with_html = invoke_scan(
        assets,
        config,
        html_json,
        html_output=tmp_path / "report.html",
    )

    assert plain.exit_code == with_html.exit_code == 0
    assert plain_json.read_bytes() == html_json.read_bytes()
    payload = json.loads(html_json.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert list(payload) == ["schema_version", "tool", "scan", "summary", "issues"]


def test_html_json_and_cache_outputs_inside_root_are_all_excluded(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    asset = create_png(assets / "T_asset.png")
    output = assets / "bad-report.json"
    html_output = assets / "bad-report.png"
    cache = assets / "metrics.sqlite3"
    output.write_bytes(asset.read_bytes())
    html_output.write_bytes(asset.read_bytes())
    config = write_rules(
        tmp_path / "rules.yaml",
        naming=True,
        textures=True,
        meshes=False,
        duplicates=True,
    )

    first = invoke_scan(
        assets,
        config,
        output,
        html_output=html_output,
        cache=cache,
        workers=4,
    )
    first_json = json.loads(output.read_text(encoding="utf-8"))
    second = invoke_scan(
        assets,
        config,
        output,
        html_output=html_output,
        cache=cache,
        workers=4,
    )
    second_json = json.loads(output.read_text(encoding="utf-8"))

    assert first.exit_code == second.exit_code == 0
    assert first_json["scan"] == second_json["scan"] == {
        "root": ".",
        "files_scanned": 1,
        "textures_checked": 1,
        "meshes_checked": 0,
        "duplicate_groups": 0,
    }
    assert first_json["issues"] == second_json["issues"] == []
    assert "Cache misses: 1" in first.stdout
    assert "Cache hits: 1" in second.stdout


@pytest.mark.parametrize(
    ("collision_kind", "error_text"),
    [
        ("json", "JSON report"),
        ("config", "configuration"),
        ("cache", "cache database"),
        ("journal", "cache sidecar"),
        ("wal", "cache sidecar"),
        ("shm", "cache sidecar"),
    ],
)
def test_html_path_collisions_return_two_before_scanning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    collision_kind: str,
    error_text: str,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    config = write_rules(tmp_path / "rules.yaml", textures=False, meshes=False)
    output = tmp_path / "report.json"
    cache = tmp_path / "cache.sqlite3"
    collision_paths = {
        "json": output,
        "config": config,
        "cache": cache,
        "journal": cache_related_paths(cache)[1],
        "wal": cache_related_paths(cache)[2],
        "shm": cache_related_paths(cache)[3],
    }
    monkeypatch.setattr(
        cli_module,
        "scan_directory",
        lambda *_args, **_kwargs: pytest.fail("scan executed after path collision"),
    )

    result = invoke_scan(
        assets,
        config,
        output,
        html_output=collision_paths[collision_kind],
        cache=cache if collision_kind not in {"json", "config"} else None,
    )

    assert result.exit_code == 2
    assert error_text in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists()
    assert not cache.exists()


def test_html_directory_path_returns_two_without_scanning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    html_directory = tmp_path / "html-directory"
    html_directory.mkdir()
    monkeypatch.setattr(
        cli_module,
        "scan_directory",
        lambda *_args, **_kwargs: pytest.fail("scan executed after path validation failure"),
    )

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml", textures=False, meshes=False),
        tmp_path / "report.json",
        html_output=html_directory,
    )

    assert result.exit_code == 2
    assert "HTML output path is a directory" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("kind", ["texture", "obj"])
def test_malformed_asset_publishes_neither_report(tmp_path: Path, kind: str) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    if kind == "texture":
        (assets / "T_bad.png").write_bytes(b"not an image")
    else:
        (assets / "SM_bad.obj").write_text("f 1/1/1/1 2 3\n", encoding="utf-8")
    output = tmp_path / "report.json"
    html_output = tmp_path / "report.html"

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml"),
        output,
        html_output=html_output,
        workers=4,
    )

    assert result.exit_code == 2
    assert "Traceback" not in result.stderr
    assert not output.exists() and not html_output.exists()


def test_worker_failure_publishes_neither_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "T_asset.bin").write_bytes(b"content")
    output = tmp_path / "report.json"
    html_output = tmp_path / "report.html"

    def fail_hash(_path: Path) -> str:
        raise RuntimeError("worker failed")

    monkeypatch.setattr(scanner_module, "_sha256", fail_hash)
    result = invoke_scan(
        assets,
        write_rules(
            tmp_path / "rules.yaml",
            textures=False,
            meshes=False,
            duplicates=True,
        ),
        output,
        html_output=html_output,
        workers=4,
    )

    assert result.exit_code == 2
    assert "Traceback" not in result.stderr
    assert not output.exists() and not html_output.exists()


def test_cache_failure_publishes_neither_report(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    cache = tmp_path / "invalid-cache.bin"
    cache.write_bytes(b"not SQLite")
    output = tmp_path / "report.json"
    html_output = tmp_path / "report.html"

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml"),
        output,
        html_output=html_output,
        cache=cache,
    )

    assert result.exit_code == 2
    assert "Traceback" not in result.stderr
    assert not output.exists() and not html_output.exists()


def test_json_write_failure_prevents_html_publication(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "T_valid.bin").write_bytes(b"valid")
    output_directory = tmp_path / "json-directory"
    output_directory.mkdir()
    html_output = tmp_path / "report.html"

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml", textures=False, meshes=False),
        output_directory,
        html_output=html_output,
    )

    assert result.exit_code == 2
    assert "cannot write report" in result.stderr
    assert "Traceback" not in result.stderr
    assert not html_output.exists()


def test_html_render_failure_publishes_neither_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "T_valid.bin").write_bytes(b"valid")
    output = tmp_path / "report.json"
    html_output = tmp_path / "report.html"

    def fail_render(_report: Report) -> str:
        raise HtmlReportError("simulated HTML render failure")

    monkeypatch.setattr(cli_module, "render_html_report", fail_render)
    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml", textures=False, meshes=False),
        output,
        html_output=html_output,
    )

    assert result.exit_code == 2
    assert "simulated HTML render failure" in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists() and not html_output.exists()


def test_later_html_write_failure_leaves_authoritative_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "T_valid.bin").write_bytes(b"valid")
    output = tmp_path / "report.json"
    html_output = tmp_path / "report.html"

    def fail_write(*_args: object, **_kwargs: object) -> None:
        raise HtmlReportError("simulated HTML write failure")

    monkeypatch.setattr(cli_module, "write_html_report", fail_write)
    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml", textures=False, meshes=False),
        output,
        html_output=html_output,
    )

    assert result.exit_code == 2
    assert output.is_file() and not html_output.exists()
    assert "simulated HTML write failure" in result.stderr
    assert "Traceback" not in result.stderr
    assert "Files scanned:" not in result.stdout


def test_warning_and_error_verdicts_publish_both_reports(tmp_path: Path) -> None:
    warning_assets = tmp_path / "warning-assets"
    warning_assets.mkdir()
    (warning_assets / "T_first.bin").write_bytes(b"same")
    (warning_assets / "T_second.bin").write_bytes(b"same")
    warning_json = tmp_path / "warning.json"
    warning_html = tmp_path / "warning.html"
    warning = invoke_scan(
        warning_assets,
        write_rules(
            tmp_path / "warning.yaml",
            textures=False,
            meshes=False,
            duplicates=True,
        ),
        warning_json,
        html_output=warning_html,
    )

    error_assets = tmp_path / "error-assets"
    error_assets.mkdir()
    (error_assets / "bad.bin").write_bytes(b"bad")
    error_json = tmp_path / "error.json"
    error_html = tmp_path / "error.html"
    error = invoke_scan(
        error_assets,
        write_rules(
            tmp_path / "error.yaml",
            naming=True,
            textures=False,
            meshes=False,
        ),
        error_json,
        html_output=error_html,
    )

    assert warning.exit_code == 0
    assert error.exit_code == 1
    assert warning_json.is_file() and warning_html.is_file()
    assert error_json.is_file() and error_html.is_file()
    assert "PASSED" in warning_html.read_text(encoding="utf-8")
    assert "FAILED" in error_html.read_text(encoding="utf-8")


def test_html_semantics_match_json_report(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_odd.png", (63, 64))
    output = tmp_path / "report.json"
    html_output = tmp_path / "report.html"

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml", meshes=False),
        output,
        html_output=html_output,
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    rendered = html_output.read_text(encoding="utf-8")

    assert result.exit_code == 1
    assert ("PASSED" in rendered) is payload["summary"]["passed"]
    assert "FAILED" in rendered
    for label, key in [
        ("Files scanned", "files_scanned"),
        ("Textures checked", "textures_checked"),
        ("Meshes checked", "meshes_checked"),
        ("Duplicate groups", "duplicate_groups"),
    ]:
        assert f"<dt>{label}</dt><dd>{payload['scan'][key]}</dd>" in rendered
    for issue in payload["issues"]:
        assert issue["code"] in rendered
        assert issue["path"] in rendered
        assert issue["message"] in rendered


def test_rendering_has_no_scanner_cache_parser_hash_or_worker_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        pytest.fail("renderer invoked a scanning or parsing boundary")

    monkeypatch.setattr(scanner_module, "scan_directory", forbidden)
    monkeypatch.setattr(scanner_module, "scan_directory_with_cache", forbidden)
    monkeypatch.setattr(scanner_module, "_sha256", forbidden)
    monkeypatch.setattr(scanner_module, "_read_texture_metrics", forbidden)
    monkeypatch.setattr(scanner_module, "_read_mesh_metrics", forbidden)
    monkeypatch.setattr(scanner_module, "ordered_bounded_map", forbidden)

    rendered = render_html_report(make_report())

    assert "AssetGuard Validation Report" in rendered


def test_direct_path_validator_accepts_distinct_file(tmp_path: Path) -> None:
    result = validate_html_output_path(
        tmp_path / "report.html",
        tmp_path / "report.json",
        tmp_path / "rules.yaml",
        cache_related_paths(tmp_path / "cache.sqlite3"),
    )

    assert result == (tmp_path / "report.html").resolve()


def test_writer_propagates_typed_renderer_failure(tmp_path: Path) -> None:
    issue = Issue(
        code="BAD",
        severity="error",
        path="asset.bin",
        message="message",
        details={"bad": object()},
    )

    with pytest.raises(HtmlReportError, match="cannot render HTML report"):
        write_html_report(
            make_report(passed=False, issues=[issue]),
            tmp_path / "report.html",
        )
