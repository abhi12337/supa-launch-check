"""Human-readable and JSON reports."""

from __future__ import annotations

import json
import os
import sys
import textwrap

from . import __version__
from .findings import SEVERITIES, Finding, sort_findings

COLORS = {
    "critical": "\033[1;97;41m",
    "high": "\033[1;31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def use_color(stream=sys.stdout, force: bool | None = None) -> bool:
    if force is not None:
        return force
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    return counts


def _indent(text: str, prefix: str = "      ") -> str:
    return textwrap.indent(text, prefix)


def render_text(
    findings: list[Finding],
    *,
    header: list[str],
    footer: list[str] | None = None,
    color: bool = False,
    verbose_fix: bool = True,
) -> str:
    def c(name: str, s: str) -> str:
        return f"{COLORS[name]}{s}{COLORS['reset']}" if color else s

    out: list[str] = [c("bold", f"supa-launch-check {__version__}")]
    out += header
    out.append("")
    findings = sort_findings(findings)
    if not findings:
        out.append("No findings. (This is not a guarantee: see 'What it does not check' in the README.)")
    shown_fix: set[str] = set()
    for f in findings:
        sev = f"{f.severity.upper():<8}"
        tag = c("dim", " [heuristic]") if f.heuristic else ""
        out.append(f"{c(f.severity, sev)} {f.rule_id}  {c('bold', f.rule.title)}{tag}")
        if f.location:
            out.append(f"      at: {f.location}")
        out.append(_indent(textwrap.fill(f.message, 92)))
        if f.evidence:
            out.append(f"      found: {f.evidence}")
        if verbose_fix:
            if f.rule_id not in shown_fix:
                shown_fix.add(f.rule_id)
                out.append(c("dim", textwrap.fill(f.rule.why, 92, initial_indent="      why: ",
                                                  subsequent_indent="           ")))
            out.append(c("dim", "      fix:"))
            out.append(_indent(f.fix, "        "))
        out.append("")
    counts = summarize(findings)
    parts = [f"{counts[s]} {s}" for s in SEVERITIES]
    out.append(c("bold", "Summary: ") + ", ".join(parts))
    if footer:
        out += footer
    return "\n".join(out) + "\n"


def render_json(findings: list[Finding], *, meta: dict) -> str:
    findings = sort_findings(findings)
    doc = {
        "tool": "supa-launch-check",
        "version": __version__,
        **meta,
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(doc, indent=2) + "\n"
