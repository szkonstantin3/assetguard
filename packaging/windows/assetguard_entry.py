"""Frozen AssetGuard console entry point."""

import sys

from assetguard.cli import app


def _configure_utf8_stream(stream: object | None) -> None:
    reconfigure = getattr(stream, "reconfigure", None)
    if callable(reconfigure):
        reconfigure(encoding="utf-8", errors="backslashreplace")


def main() -> None:
    _configure_utf8_stream(sys.stdout)
    _configure_utf8_stream(sys.stderr)
    app()


if __name__ == "__main__":
    main()
