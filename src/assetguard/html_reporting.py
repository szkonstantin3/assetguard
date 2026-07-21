"""Deterministic self-contained HTML rendering and publication."""

import json
import os
import tempfile
from html import escape
from pathlib import Path
from typing import Iterable

from assetguard.models import Issue, Report


class HtmlReportError(Exception):
    """Raised when an HTML report path, rendering, or write operation fails."""


def _escaped_text(value: object) -> str:
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    return escape(text, quote=True)


def _render_details(issue: Issue) -> str:
    if not issue.details:
        return '<span class="no-details" aria-label="No details">&mdash;</span>'
    details = json.dumps(
        issue.details,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )
    return f"<pre><code>{_escaped_text(details)}</code></pre>"


def _render_issue_row(issue: Issue) -> str:
    severity = issue.severity.upper()
    severity_class = "error" if issue.severity == "error" else "warning"
    return "\n".join(
        [
            "          <tr>",
            (
                '            <td><span class="severity severity--'
                f'{severity_class}">{_escaped_text(severity)}</span></td>'
            ),
            f"            <td><code>{_escaped_text(issue.code)}</code></td>",
            f"            <td>{_escaped_text(issue.path)}</td>",
            f"            <td>{_escaped_text(issue.message)}</td>",
            f"            <td>{_render_details(issue)}</td>",
            "          </tr>",
        ]
    )


def render_html_report(report: Report) -> str:
    """Render a completed typed report as deterministic, escaped HTML5."""

    try:
        status = "PASSED" if report.summary.passed else "FAILED"
        status_class = "passed" if report.summary.passed else "failed"
        lines = [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '  <meta charset="utf-8">',
            '  <meta name="viewport" content="width=device-width, initial-scale=1">',
            (
                '  <meta http-equiv="Content-Security-Policy" content="default-src '
                "'none'; style-src 'unsafe-inline'; script-src 'none'; img-src 'none'; "
                "font-src 'none'; connect-src 'none'; media-src 'none'; object-src 'none'; "
                "frame-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'\">"
            ),
            "  <title>AssetGuard Validation Report</title>",
            "  <style>",
            "    :root { color-scheme: light; font-family: system-ui, sans-serif; }",
            "    * { box-sizing: border-box; }",
            "    body { margin: 0; background: #f4f6f8; color: #1d2733; line-height: 1.5; }",
            "    main { width: min(1120px, calc(100% - 2rem)); margin: 2rem auto; }",
            "    header, section, footer { background: #fff; border: 1px solid #ccd4dc; border-radius: .5rem; margin-block: 1rem; padding: 1.25rem; }",
            "    h1, h2 { line-height: 1.2; margin-top: 0; }",
            "    .status { display: inline-block; border: 2px solid currentColor; border-radius: .25rem; font-weight: 700; letter-spacing: .04em; padding: .25rem .55rem; }",
            "    .status--passed { color: #176b3a; }",
            "    .status--failed { color: #a32323; }",
            "    .metadata { display: flex; flex-wrap: wrap; gap: .5rem 1.25rem; margin: 1rem 0 0; }",
            "    .metadata span { white-space: nowrap; }",
            "    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); gap: .75rem; margin: 0; }",
            "    .summary div { border-inline-start: .3rem solid #526b82; background: #f7f9fb; padding: .75rem; }",
            "    .summary dt { color: #52606d; font-size: .875rem; }",
            "    .summary dd { font-size: 1.5rem; font-weight: 700; margin: .15rem 0 0; }",
            "    .table-wrap { overflow-x: auto; }",
            "    .table-wrap:focus-visible { outline: 3px solid #245b91; outline-offset: 2px; }",
            "    table { border-collapse: collapse; width: 100%; }",
            "    caption { font-weight: 600; padding: 0 0 .75rem; text-align: left; }",
            "    th, td { border: 1px solid #ccd4dc; padding: .65rem; text-align: left; vertical-align: top; }",
            "    th { background: #edf1f5; }",
            "    .severity { font-weight: 700; }",
            "    .severity--error { color: #a32323; }",
            "    .severity--warning { color: #775500; }",
            "    code, pre { font-family: ui-monospace, monospace; }",
            "    pre { background: #f4f6f8; margin: 0; max-width: 32rem; overflow-wrap: anywhere; padding: .5rem; white-space: pre-wrap; }",
            "    .no-details { color: #52606d; }",
            "    footer { color: #52606d; font-size: .875rem; text-align: center; }",
            "    @media (max-width: 640px) { main { width: min(100% - 1rem, 1120px); margin-block: .5rem; } header, section, footer { padding: .85rem; } }",
            "    @media print { body { background: #fff; } main { margin: 0; width: 100%; } header, section, footer { break-inside: avoid; box-shadow: none; } .table-wrap { overflow: visible; } }",
            "  </style>",
            "</head>",
            "<body>",
            "  <main>",
            "    <header>",
            "      <h1>AssetGuard Validation Report</h1>",
            (
                f'      <p>Status: <span class="status status--{status_class}">'
                f"{_escaped_text(status)}</span></p>"
            ),
            '      <p class="metadata">',
            (
                f"        <span>Tool: {_escaped_text(report.tool.name)} "
                f"{_escaped_text(report.tool.version)}</span>"
            ),
            f"        <span>Schema version: {_escaped_text(report.schema_version)}</span>",
            f"        <span>Scan root: {_escaped_text(report.scan.root)}</span>",
            "      </p>",
            "    </header>",
            '    <section aria-labelledby="summary-heading">',
            '      <h2 id="summary-heading">Summary</h2>',
            '      <dl class="summary">',
            f"        <div><dt>Files scanned</dt><dd>{_escaped_text(report.scan.files_scanned)}</dd></div>",
            f"        <div><dt>Textures checked</dt><dd>{_escaped_text(report.scan.textures_checked)}</dd></div>",
            f"        <div><dt>Meshes checked</dt><dd>{_escaped_text(report.scan.meshes_checked)}</dd></div>",
            f"        <div><dt>Duplicate groups</dt><dd>{_escaped_text(report.scan.duplicate_groups)}</dd></div>",
            f"        <div><dt>Errors</dt><dd>{_escaped_text(report.summary.errors)}</dd></div>",
            f"        <div><dt>Warnings</dt><dd>{_escaped_text(report.summary.warnings)}</dd></div>",
            "      </dl>",
            "    </section>",
            '    <section aria-labelledby="issues-heading">',
            '      <h2 id="issues-heading">Validation issues</h2>',
        ]

        if report.issues:
            lines.extend(
                [
                    '      <div class="table-wrap" role="region" aria-label="Validation issues" tabindex="0">',
                    "        <table>",
                    "          <caption>Validation issues in deterministic report order</caption>",
                    "          <thead>",
                    "            <tr>",
                    '              <th scope="col">Severity</th>',
                    '              <th scope="col">Code</th>',
                    '              <th scope="col">Asset</th>',
                    '              <th scope="col">Message</th>',
                    '              <th scope="col">Details</th>',
                    "            </tr>",
                    "          </thead>",
                    "          <tbody>",
                ]
            )
            lines.extend(_render_issue_row(issue) for issue in report.issues)
            lines.extend(
                [
                    "          </tbody>",
                    "        </table>",
                    "      </div>",
                ]
            )
        else:
            lines.append("      <p>No validation issues were found.</p>")

        lines.extend(
            [
                "    </section>",
                "    <footer>AssetGuard deterministic validation report.</footer>",
                "  </main>",
                "</body>",
                "</html>",
            ]
        )
        return "\n".join(lines) + "\n"
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HtmlReportError("cannot render HTML report") from exc


def write_html_report(report: Report, destination: Path) -> None:
    """Atomically write a deterministic HTML report."""

    temporary_path: Path | None = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        rendered = render_html_report(report)
        normalized = rendered.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(normalized)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, destination)
    except HtmlReportError:
        raise
    except (OSError, TypeError, ValueError, UnicodeError) as exc:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise HtmlReportError(f"cannot write HTML report '{destination}': {exc}") from exc


def validate_html_output_path(
    html_output: Path,
    json_output: Path,
    config_path: Path,
    cache_paths: Iterable[Path] = (),
) -> Path:
    """Resolve and validate an HTML output path before scanning."""

    try:
        resolved_html = html_output.resolve(strict=False)
        resolved_json = json_output.resolve(strict=False)
        resolved_config = config_path.resolve(strict=False)
        resolved_cache_paths = tuple(path.resolve(strict=False) for path in cache_paths)
    except OSError as exc:
        raise HtmlReportError("cannot resolve HTML output or related paths") from exc

    if resolved_html == resolved_json:
        raise HtmlReportError("HTML output path must not be the same as the JSON report path")
    if resolved_html == resolved_config:
        raise HtmlReportError("HTML output path must not be the same as the configuration path")
    if resolved_cache_paths and resolved_html == resolved_cache_paths[0]:
        raise HtmlReportError("HTML output path must not be the same as the cache database path")
    if resolved_html in resolved_cache_paths[1:]:
        raise HtmlReportError("HTML output path must not be a recognized cache sidecar path")
    if resolved_html.exists() and resolved_html.is_dir():
        raise HtmlReportError("HTML output path is a directory")
    return resolved_html
