"""Command line interface.

  supa-launch-check scan [PATH]
  supa-launch-check live --url URL --anon-key KEY --i-own-this-project
  supa-launch-check rules
"""

from __future__ import annotations

import argparse
import os
import sys
import textwrap

from . import __version__
from .findings import RULES, SEVERITIES, SEVERITY_RANK, Finding
from .live import MAX_TABLES_DEFAULT, LiveCheckError, run_live_check
from .report import render_json, render_text, use_color
from .static_scan import MAX_BYTES_DEFAULT, scan_path

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

CONSENT_TEXT = """\
LIVE CHECK - OWNER-AUTHORISED USE ONLY

You are about to send read-only requests to:
    {url}

  * Only run this against a Supabase project that you own or are explicitly
    authorised in writing to test. Testing other people's projects without
    permission may be illegal.
  * Requests: 1 schema fetch + up to {max_tables} `select * limit 1` requests,
    one every {delay}s, using the anon/publishable key you supplied.
  * Nothing is written, updated, deleted or called (no RPC). Row contents are
    never printed or stored, only whether rows were returned.
"""


def _fail_on(args) -> int | None:
    return None if args.fail_on == "never" else SEVERITY_RANK[args.fail_on]


def _exit_code(findings: list[Finding], threshold: int | None) -> int:
    if threshold is None:
        return EXIT_OK
    return EXIT_FINDINGS if any(SEVERITY_RANK[f.severity] <= threshold for f in findings) else EXIT_OK


def _filter_min(findings: list[Finding], min_sev: str) -> list[Finding]:
    lim = SEVERITY_RANK[min_sev]
    return [f for f in findings if SEVERITY_RANK[f.severity] <= lim]


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--json", action="store_true", help="print a JSON report instead of text")
    p.add_argument(
        "--fail-on",
        choices=[*SEVERITIES, "never"],
        default="high",
        help="exit 1 if any finding is at or above this severity (default: high)",
    )
    p.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="low",
        help="hide findings below this severity (default: low = show all)",
    )
    p.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    p.add_argument("--brief", action="store_true", help="omit the why/fix text")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="supa-launch-check",
        description="Pre-launch security checks for Supabase-backed apps (Lovable, Bolt, Cursor, hand-written).",
        epilog="Only use on projects you own. This is not a penetration test and finds only the issues it knows about.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="static scan of a local repo or build folder (no network)")
    s.add_argument("path", nargs="?", default=".", help="repo or build folder to scan (default: .)")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="glob of paths to skip (repeatable), e.g. --exclude 'docs/*'")
    s.add_argument("--include-tests", action="store_true", help="also scan test/fixture files")
    s.add_argument("--max-file-mb", type=float, default=MAX_BYTES_DEFAULT / 1024 / 1024,
                   help="skip files larger than this (default: 10)")
    _add_common(s)

    lv = sub.add_parser("live", help="owner-only read-only check of what the anon key can read")
    lv.add_argument("--url", default=os.environ.get("SUPABASE_URL"),
                    help="project URL, e.g. https://abcd.supabase.co (or env SUPABASE_URL)")
    lv.add_argument("--anon-key", default=os.environ.get("SUPABASE_ANON_KEY"),
                    help="anon / publishable key (or env SUPABASE_ANON_KEY). Never a service key.")
    lv.add_argument("--i-own-this-project", dest="owner", action="store_true",
                    help="required: confirms you own or are authorised to test this project")
    lv.add_argument("--yes", action="store_true",
                    help="skip the interactive consent prompt (for CI; still requires --i-own-this-project)")
    lv.add_argument("--delay", type=float, default=0.5, help="seconds between requests (min 0.2, default 0.5)")
    lv.add_argument("--max-tables", type=int, default=MAX_TABLES_DEFAULT,
                    help=f"check at most this many tables (default {MAX_TABLES_DEFAULT})")
    _add_common(lv)

    sub.add_parser("rules", help="list every rule with why it matters and how to fix it")
    return parser


def cmd_scan(args) -> int:
    if not os.path.isdir(args.path):
        print(f"error: {args.path} is not a directory", file=sys.stderr)
        return EXIT_ERROR
    result, _ = scan_path(
        args.path,
        excludes=args.exclude,
        max_bytes=int(args.max_file_mb * 1024 * 1024),
        include_tests=args.include_tests,
    )
    exit_code = _exit_code(result.findings, _fail_on(args))
    shown = _filter_min(result.findings, args.min_severity)
    if args.json:
        sys.stdout.write(render_json(shown, meta={
            "mode": "scan", "target": result.root, "files_scanned": result.files_scanned,
            "sql_files": result.sql_files, "exit_code": exit_code,
        }))
    else:
        header = [f"Scanned {args.path}",
                  f"{result.files_scanned} files, {len(result.sql_files)} SQL migration file(s)"]
        if not result.sql_files:
            header.append("No supabase/migrations found: RLS could not be verified statically. "
                          "Run `supabase db pull` to bring your schema into the repo.")
        sys.stdout.write(render_text(shown, header=header, color=use_color(force=False if args.no_color else None),
                                     verbose_fix=not args.brief, footer=[f"Exit code: {exit_code}"]))
    return exit_code


def cmd_live(args) -> int:
    if not args.owner:
        print("error: live checks require --i-own-this-project.\n"
              "Only test Supabase projects you own or are authorised in writing to test.", file=sys.stderr)
        return EXIT_ERROR
    if not args.url or not args.anon_key:
        print("error: --url and --anon-key (or SUPABASE_URL / SUPABASE_ANON_KEY) are required", file=sys.stderr)
        return EXIT_ERROR
    delay = max(0.2, args.delay)
    max_tables = max(1, min(args.max_tables, 1000))
    if not args.yes:
        if not sys.stdin.isatty():
            print("error: no terminal for the consent prompt; pass --yes together with --i-own-this-project",
                  file=sys.stderr)
            return EXIT_ERROR
        print(CONSENT_TEXT.format(url=args.url, max_tables=max_tables, delay=delay), file=sys.stderr)
        answer = input("Type 'I own this project' to continue: ").strip().lower()
        if answer != "i own this project":
            print("Aborted.", file=sys.stderr)
            return EXIT_ERROR
    try:
        res = run_live_check(args.url, args.anon_key, delay=delay, max_tables=max_tables)
    except LiveCheckError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    exit_code = _exit_code(res.findings, _fail_on(args))
    shown = _filter_min(res.findings, args.min_severity)
    if args.json:
        sys.stdout.write(render_json(shown, meta={
            "mode": "live", "target": res.url, "requests_made": res.requests_made,
            "tables": [t.__dict__ for t in res.tables], "rpc_functions": res.rpc_functions,
            "truncated": res.truncated, "exit_code": exit_code,
        }))
    else:
        header = [f"Live check of {res.url} as the anon role ({res.requests_made} read-only requests)"]
        width = max((len(t.table) for t in res.tables), default=5)
        header.append("")
        for t in res.tables:
            header.append(f"  {t.table:<{width}}  {t.note}")
        if res.truncated:
            header.append(f"  ... stopped after {max_tables} tables (--max-tables)")
        sys.stdout.write(render_text(shown, header=header, color=use_color(force=False if args.no_color else None),
                                     verbose_fix=not args.brief, footer=[f"Exit code: {exit_code}"]))
    return exit_code


def cmd_rules(_args) -> int:
    for r in RULES.values():
        print(f"{r.id}  {r.title}")
        print(textwrap.fill(r.why, 92, initial_indent="    ", subsequent_indent="    "))
        print("    Fix:")
        print(textwrap.indent(Finding(r.id, "low", "").fix, "      "))
        print()
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass
    args = build_parser().parse_args(argv)
    return {"scan": cmd_scan, "live": cmd_live, "rules": cmd_rules}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
