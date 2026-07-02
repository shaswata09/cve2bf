"""Command-line entry point for batch CVE -> BF analysis.

Useful for building a labelled dataset or regression-testing the pipeline over
many CVEs without the HTTP layer.

Examples
--------
Analyse a few CVEs and write JSONL::

    python -m app.cli --cve CVE-2014-0160 --out results.jsonl

Analyse every CVE listed (one per line) in a file::

    python -m app.cli --file cves.txt --out results.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys

from app.logging_config import configure_logging
from app.services.orchestrator import build_orchestrator


def _read_ids(args: argparse.Namespace) -> list[str]:
    ids: list[str] = list(args.cve or [])
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            ids.extend(line.strip() for line in fh if line.strip())
    return ids


def main(argv: list[str] | None = None) -> int:
    """Run the batch CLI. Returns a process exit code."""
    parser = argparse.ArgumentParser(description="Batch CVE -> BF chain generator.")
    parser.add_argument("--cve", action="append", help="A CVE id (repeatable).")
    parser.add_argument("--file", help="File with one CVE id per line.")
    parser.add_argument("--out", help="Write JSONL results here (default: stdout).")
    args = parser.parse_args(argv)

    configure_logging()
    ids = _read_ids(args)
    if not ids:
        parser.error("Provide at least one CVE via --cve or --file.")

    orchestrator = build_orchestrator()
    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    valid_count = 0
    try:
        for cve_id in ids:
            response = orchestrator.analyze(cve_id)
            valid_count += int(response.valid)
            out.write(response.model_dump_json() + "\n")
    finally:
        if args.out:
            out.close()

    print(f"Analysed {len(ids)} CVE(s); {valid_count} produced a valid chain.", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
