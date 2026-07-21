"""Typer command-line interface for AssetGuard."""

from pathlib import Path
from typing import Annotated

import typer

from assetguard.cache import (
    AssetMetricsCache,
    CacheError,
    cache_related_paths,
    validate_cache_path,
)
from assetguard.config import ConfigurationError, load_config
from assetguard.html_reporting import (
    HtmlReportError,
    render_html_report,
    validate_html_output_path,
    write_html_report,
)
from assetguard.reporting import ReportWriteError, write_report
from assetguard.scanner import ScanError, scan_directory, scan_directory_with_cache

app = typer.Typer(
    name="assetguard",
    help="Deterministically validate a game-assets directory.",
    add_completion=False,
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """AssetGuard command group."""


@app.command()
def scan(
    assets_directory: Annotated[
        Path,
        typer.Argument(help="Directory containing assets to scan."),
    ],
    config: Annotated[
        Path,
        typer.Option("--config", help="YAML rules file."),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", help="Destination JSON report."),
    ],
    html_output: Annotated[
        Path | None,
        typer.Option("--html-output", help="Optional self-contained HTML report."),
    ] = None,
    cache: Annotated[
        Path | None,
        typer.Option("--cache", help="Optional SQLite metric cache."),
    ] = None,
    workers: Annotated[
        int,
        typer.Option(
            "--workers",
            "-j",
            min=1,
            max=32,
            help=(
                "Worker threads for hashing and metric parsing; SQLite operations "
                "remain on the coordinator thread."
            ),
        ),
    ] = 1,
) -> None:
    """Scan assets and write deterministic JSON and optional HTML reports."""

    try:
        rules = load_config(config)
        cache_hits: int | None = None
        cache_misses: int | None = None
        resolved_cache: Path | None = None
        cache_paths: tuple[Path, ...] = ()
        if cache is not None:
            resolved_cache = validate_cache_path(cache, config, output)
            cache_paths = cache_related_paths(resolved_cache)

        resolved_html: Path | None = None
        if html_output is not None:
            resolved_html = validate_html_output_path(
                html_output,
                output,
                config,
                cache_paths,
            )

        excluded_files = [output]
        if resolved_html is not None:
            excluded_files.append(resolved_html)
        excluded_files.extend(cache_paths)

        if resolved_cache is None:
            report = scan_directory(
                assets_directory,
                rules,
                excluded_files=excluded_files,
                workers=workers,
            )
        else:
            with AssetMetricsCache(resolved_cache) as metrics_cache:
                cached_result = scan_directory_with_cache(
                    assets_directory,
                    rules,
                    metrics_cache,
                    excluded_files=excluded_files,
                    workers=workers,
                )
                metrics_cache.commit()
            report = cached_result.report
            cache_hits = cached_result.cache_hits
            cache_misses = cached_result.cache_misses

        if resolved_html is not None:
            render_html_report(report)
        write_report(report, output)
        if resolved_html is not None:
            write_html_report(report, resolved_html)
    except (
        CacheError,
        ConfigurationError,
        HtmlReportError,
        ScanError,
        ReportWriteError,
    ) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    typer.echo(f"Files scanned: {report.scan.files_scanned}")
    typer.echo(f"Textures checked: {report.scan.textures_checked}")
    typer.echo(f"Meshes checked: {report.scan.meshes_checked}")
    typer.echo(f"Errors: {report.summary.errors}")
    typer.echo(f"Warnings: {report.summary.warnings}")
    typer.echo(f"Duplicate groups: {report.scan.duplicate_groups}")
    if cache_hits is not None and cache_misses is not None:
        typer.echo(f"Cache hits: {cache_hits}")
        typer.echo(f"Cache misses: {cache_misses}")
    typer.echo(f"Report: {output}")
    if html_output is not None:
        typer.echo(f"HTML report: {html_output}")

    if not report.summary.passed:
        raise typer.Exit(code=1)
