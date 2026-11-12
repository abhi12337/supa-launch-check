"""Static scan of a local repo or build folder: secrets, .env files, client-side table access."""

from __future__ import annotations

import base64
import bisect
import fnmatch
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .findings import Finding, mask_secret
from .sql_scan import SqlResult, scan_sql_files

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".turbo", ".cache", ".parcel-cache",
    "coverage", ".idea", ".vscode", ".expo", ".gradle", "Pods",
}
SKIP_PATH_SUFFIXES = (".next/cache",)
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".avif", ".svgz", ".pdf",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".webm", ".wav",
    ".zip", ".gz", ".tgz", ".br", ".7z", ".rar", ".jar", ".exe", ".dll", ".so", ".dylib",
    ".wasm", ".pyc", ".class", ".lockb", ".db", ".sqlite",
}
CODE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"}
BUILD_DIRS = {"dist", "build", "out", ".next", ".output", ".vercel", ".netlify", "public", "www"}
SERVER_HINTS = ("supabase/functions/", "/api/", "/server/", "/backend/", "/functions/", "/lambda/")
ENV_SAFE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")
IGNORE_MARK = re.compile(r"supa-launch-check:\s*ignore", re.I)
MAX_BYTES_DEFAULT = 10 * 1024 * 1024

# --- secret patterns -------------------------------------------------------------
RE_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
RE_SB_SECRET = re.compile(r"\bsb_secret_[A-Za-z0-9_-]{16,}")


@dataclass(frozen=True)
class SecretPattern:
    rule_id: str
    name: str
    regex: re.Pattern
    severity: str  # severity when hard-coded in client/build code
    server_severity: str  # severity when in server-only code


SECRET_PATTERNS = [
    SecretPattern("SLC003", "Stripe live secret key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}"), "critical", "critical"),
    SecretPattern("SLC003", "Stripe test secret key", re.compile(r"\bsk_test_[A-Za-z0-9]{20,}"), "low", "low"),
    SecretPattern("SLC004", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), "critical", "high"),
    SecretPattern("SLC004", "OpenAI API key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}"), "critical", "high"),
    SecretPattern("SLC004", "AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high", "high"),
    SecretPattern("SLC004", "GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})"), "high", "high"),
    SecretPattern("SLC004", "Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "high", "high"),
]

RE_PUBLIC_SERVICE_VAR = re.compile(
    r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|PUBLIC)_"
    r"[A-Z0-9_]*(?:SERVICE_ROLE|SERVICE_KEY|SUPABASE_SECRET|SECRET_KEY)[A-Z0-9_]*\b"
)
RE_FROM_CALL = re.compile(r"\.from\(\s*(['\"`])([A-Za-z_][A-Za-z0-9_.]*)\1\s*\)")
RE_FROM_EXCLUDE_BEFORE = re.compile(r"(?:storage\s*|Array|Buffer|Object|Uint8Array|stream|Readable)\s*$")


def decode_jwt_payload(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    seg = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(seg.encode()).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    sql_files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


class _Lines:
    def __init__(self, text: str):
        self.text = text
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line_of(self, pos: int) -> int:
        return bisect.bisect_right(self.starts, pos)

    def line_text(self, lineno: int) -> str:
        s = self.starts[lineno - 1]
        e = self.starts[lineno] - 1 if lineno < len(self.starts) else len(self.text)
        return self.text[s:e]


def _is_env_file(name: str) -> bool:
    return (name == ".env" or name.startswith(".env.") or name.endswith(".env")) and not name.lower().endswith(
        ENV_SAFE_SUFFIXES
    )


def _is_server_path(rel: str) -> bool:
    p = "/" + rel.lower()
    name = p.rsplit("/", 1)[-1]
    return (
        any(h in p for h in SERVER_HINTS)
        or ".server." in name
        or name in {"middleware.ts", "middleware.js"}
        or p.startswith(("/supabase/", "/scripts/", "/migrations/"))
    )


def _is_build_path(rel: str) -> bool:
    return rel.split("/", 1)[0] in BUILD_DIRS or "/.next/static/" in "/" + rel


def _is_test_path(rel: str) -> bool:
    p = "/" + rel.lower()
    return any(s in p for s in ("/test/", "/tests/", "/__tests__/", "/e2e/", ".test.", ".spec.", "/fixtures/"))


def iter_files(root: Path, excludes: list[str]) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        keep = []
        for d in dirnames:
            rel = f"{rel_dir}/{d}" if rel_dir else d
            if d in SKIP_DIRS or rel.endswith(SKIP_PATH_SUFFIXES) or any(fnmatch.fnmatch(rel, g) for g in excludes):
                continue
            keep.append(d)
        dirnames[:] = sorted(keep)
        for f in sorted(filenames):
            rel = f"{rel_dir}/{f}" if rel_dir else f
            if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(f, g) for g in excludes):
                continue
            out.append(Path(dirpath) / f)
    return out


def _read_text(path: Path, max_bytes: int) -> str | None:
    if path.suffix.lower() in BINARY_EXT:
        return None
    try:
        if path.stat().st_size > max_bytes:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


# --- git helpers ----------------------------------------------------------------
def _git(root: Path, *args: str) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _git_info(root: Path, env_rels: list[str]) -> tuple[bool, set[str], set[str]]:
    """Return (is_git_repo, tracked env files, ignored env files)."""
    cp = _git(root, "rev-parse", "--is-inside-work-tree")
    if cp is None or cp.returncode != 0 or cp.stdout.strip() != "true":
        return False, set(), set()
    tracked: set[str] = set()
    ignored: set[str] = set()
    if env_rels:
        cp = _git(root, "ls-files", "--", *env_rels)
        if cp and cp.returncode == 0:
            tracked = {line.strip() for line in cp.stdout.splitlines() if line.strip()}
        cp = _git(root, "check-ignore", "--", *env_rels)
        if cp and cp.returncode in (0, 1):
            ignored = {line.strip() for line in cp.stdout.splitlines() if line.strip()}
    return True, tracked, ignored


def _gitignore_covers(root: Path, rel: str) -> bool:
    """Minimal .gitignore check for non-git folders (root .gitignore only)."""
    gi = root / ".gitignore"
    if not gi.is_file():
        return False
    name = rel.rsplit("/", 1)[-1]
    covered = False
    for raw in gi.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        neg = line.startswith("!")
        pat = line[1:] if neg else line
        pat = pat.lstrip("/")
        if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, f"**/{pat}"):
            covered = not neg
    return covered


# --- main scan ------------------------------------------------------------------
def find_sql_files(root: Path, files: list[Path]) -> list[Path]:
    mig = root / "supabase" / "migrations"
    if mig.is_dir():
        sql = sorted(p for p in mig.glob("*.sql") if p.is_file())
        schemas = root / "supabase" / "schemas"
        if schemas.is_dir():
            sql = sorted(schemas.glob("*.sql")) + sql
        return sql
    return sorted(
        (p for p in files if p.suffix.lower() == ".sql" and not _is_test_path(p.relative_to(root).as_posix())),
        key=lambda p: p.relative_to(root).as_posix(),
    )


def scan_path(
    root: str | Path,
    *,
    excludes: list[str] | None = None,
    max_bytes: int = MAX_BYTES_DEFAULT,
    include_tests: bool = False,
) -> tuple[ScanResult, SqlResult]:
    root = Path(root).resolve()
    excludes = list(excludes or [])
    result = ScanResult(root=str(root))
    files = iter_files(root, excludes)

    # SQL first, so client-side table access can be cross-checked.
    sql_paths = find_sql_files(root, files)
    sql = scan_sql_files(sql_paths, root)
    result.sql_files = sql.files
    result.findings.extend(sql.findings)

    rels = {p: p.relative_to(root).as_posix() for p in files}
    env_rels = [rels[p] for p in files if _is_env_file(p.name)]
    is_git, tracked, ignored = _git_info(root, env_rels)
    skip_secret_scan: set[str] = set()
    for rel in env_rels:
        if is_git:
            if rel in tracked:
                result.findings.append(Finding("SLC005", "high", f"{rel} is tracked by git (committed).", rel))
            elif rel in ignored:
                skip_secret_scan.add(rel)
            else:
                result.findings.append(
                    Finding("SLC005", "medium", f"{rel} is not git-ignored; one `git add .` away from being committed.", rel)
                )
        elif _gitignore_covers(root, rel):
            skip_secret_scan.add(rel)
        else:
            result.findings.append(
                Finding("SLC005", "medium", f"{rel} exists and is not covered by .gitignore.", rel)
            )

    client_tables: dict[str, tuple[str, int, int]] = {}  # table -> (file, line, count)
    seen_secrets: set[tuple[str, str, str]] = set()

    for path in files:
        rel = rels[path]
        if rel in skip_secret_scan:
            continue
        if not include_tests and _is_test_path(rel):
            continue
        text = _read_text(path, max_bytes)
        if text is None:
            continue
        result.files_scanned += 1
        lines = _Lines(text)
        server = _is_server_path(rel)
        build = _is_build_path(rel)
        where = "a built bundle served to browsers" if build else ("server-side code" if server else "source code")

        def ignored_at(pos: int) -> tuple[bool, int]:
            ln = lines.line_of(pos)
            return bool(IGNORE_MARK.search(lines.line_text(ln))), ln

        def add_secret(rule: str, sev: str, value: str, pos: int, label: str) -> None:
            ign, ln = ignored_at(pos)
            key = (rule, rel, value)
            if ign or key in seen_secrets:
                return
            seen_secrets.add(key)
            result.findings.append(
                Finding(rule, sev, f"{label} hard-coded in {where}.", rel, ln, evidence=mask_secret(value))
            )

        # Supabase JWTs: only service_role (or other non-anon roles) are secrets.
        for m in RE_JWT.finditer(text):
            payload = decode_jwt_payload(m.group(0))
            if not payload:
                continue
            role = str(payload.get("role", ""))
            if role == "service_role":
                add_secret("SLC001", "high" if server and not build else "critical", m.group(0), m.start(),
                           "Supabase service_role JWT")
            elif role == "supabase_admin":
                add_secret("SLC001", "critical", m.group(0), m.start(), "Supabase admin JWT")

        for m in RE_SB_SECRET.finditer(text):
            add_secret("SLC002", "high" if server and not build else "critical", m.group(0), m.start(),
                       "Supabase secret key (sb_secret_)")

        for sp in SECRET_PATTERNS:
            for m in sp.regex.finditer(text):
                sev = sp.server_severity if server and not build else sp.severity
                add_secret(sp.rule_id, sev, m.group(0), m.start(), sp.name)

        if not server:
            for m in RE_PUBLIC_SERVICE_VAR.finditer(text):
                ign, ln = ignored_at(m.start())
                key = ("SLC007", rel, m.group(0))
                if ign or key in seen_secrets:
                    continue
                seen_secrets.add(key)
                result.findings.append(
                    Finding("SLC007", "high", f"{m.group(0)} puts a secret key into the client bundle.", rel, ln,
                            evidence=m.group(0))
                )

        if path.suffix.lower() in CODE_EXT and not server:
            for m in RE_FROM_CALL.finditer(text):
                before = text[max(0, m.start() - 20) : m.start()]
                if RE_FROM_EXCLUDE_BEFORE.search(before):
                    continue
                ign, ln = ignored_at(m.start())
                if ign:
                    continue
                table = m.group(2)
                if table in client_tables:
                    f, l, c = client_tables[table]
                    client_tables[table] = (f, l, c + 1)
                else:
                    client_tables[table] = (rel, ln, 1)

    have_sql = bool(sql.files)
    for table, (rel, ln, count) in sorted(client_tables.items()):
        state = sql.rls_enabled(table)
        if state is True:
            continue
        uses = f" ({count} call sites)" if count > 1 else ""
        if state is False:
            msg = (f"Client code queries '{table}'{uses} directly, and the migrations never enable RLS on it "
                   "(see SLC101).")
            sev = "high"
        elif have_sql:
            msg = (f"Client code queries '{table}'{uses} directly, but no migration defines it or enables RLS "
                   "on it, so its protection cannot be verified from the repo.")
            sev = "medium"
        else:
            msg = (f"Client code queries '{table}'{uses} directly and no SQL migrations were found to confirm "
                   "RLS is enabled.")
            sev = "low"
        result.findings.append(
            Finding("SLC006", sev, msg, rel, ln, heuristic=True, extra={"table": table, "call_sites": count})
        )

    return result, sql
