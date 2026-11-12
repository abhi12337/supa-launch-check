"""Scan Supabase SQL migrations for RLS and privilege mistakes.

This is a pragmatic, regex-assisted reader, not a full Postgres parser. It understands
comments, string literals, quoted identifiers and dollar-quoted bodies well enough to
split statements correctly and to avoid matching text inside function bodies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .findings import Finding

EXPOSED_SCHEMAS = {"public"}

_IDENT = r'(?:"[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)'
_QNAME = rf"({_IDENT}(?:\s*\.\s*{_IDENT})?)"


@dataclass
class Statement:
    text: str  # comments removed, original casing, strings/bodies intact
    masked: str  # same, but dollar-quoted bodies blanked out
    file: str
    line: int


def split_statements(sql: str, file: str = "<sql>") -> list[Statement]:
    """Split SQL into statements, dropping comments and tracking start lines."""
    out: list[Statement] = []
    buf: list[str] = []
    masked: list[str] = []
    i, n = 0, len(sql)
    line = 1
    start_line: int | None = None

    def emit() -> None:
        nonlocal start_line
        text = "".join(buf).strip()
        if text:
            out.append(Statement(text, "".join(masked).strip(), file, start_line or line))
        buf.clear()
        masked.clear()
        start_line = None

    while i < n:
        c = sql[i]
        if c == "-" and sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j == -1 else j  # keep the newline itself
            continue
        if c == "/" and sql.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if sql.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif sql.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            line += sql.count("\n", i, j)
            buf.append(" ")
            masked.append(" ")
            i = j
            continue
        if start_line is None and not c.isspace() and c != ";":
            start_line = line
        if c == "'" or c == '"':
            j = i + 1
            while j < n:
                if sql[j] == c:
                    if j + 1 < n and sql[j + 1] == c:  # escaped quote
                        j += 2
                        continue
                    break
                j += 1
            chunk = sql[i : j + 1]
            buf.append(chunk)
            masked.append(chunk)
            line += chunk.count("\n")
            i = j + 1
            continue
        if c == "$":
            m = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$", sql[i:])
            if m:
                tag = m.group(0)
                end = sql.find(tag, i + len(tag))
                end = n if end == -1 else end + len(tag)
                chunk = sql[i:end]
                buf.append(chunk)
                masked.append(f"{tag}{tag}")
                line += chunk.count("\n")
                i = end
                continue
        if c == ";":
            emit()
            i += 1
            continue
        if c == "\n":
            line += 1
        buf.append(c)
        masked.append(c)
        i += 1
    emit()
    return out


def norm_ident(raw: str) -> str:
    parts = [p.strip() for p in re.split(r'\.(?=(?:[^"]*"[^"]*")*[^"]*$)', raw)]
    cleaned = [p[1:-1] if p.startswith('"') and p.endswith('"') else p.lower() for p in parts]
    if len(cleaned) == 1:
        cleaned.insert(0, "public")
    return ".".join(cleaned)


def _schema(qname: str) -> str:
    return qname.split(".", 1)[0]


def _short(qname: str) -> str:
    return qname.split(".", 1)[1] if qname.startswith("public.") else qname


def _balanced_after(text: str, pos: int) -> str | None:
    """Return the contents of the parenthesised group starting at/after pos."""
    start = text.find("(", pos)
    if start == -1:
        return None
    depth, j = 0, start
    in_str: str | None = None
    while j < len(text):
        ch = text[j]
        if in_str:
            if ch == in_str:
                in_str = None
        elif ch in "'\"":
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1 : j]
        j += 1
    return None


def _is_true(expr: str | None) -> bool:
    if expr is None:
        return False
    e = re.sub(r"\s+", "", expr).lower()
    while e.startswith("(") and e.endswith(")"):
        e = e[1:-1]
    return e in {"true", "1=1", "'t'", "true::boolean"}


def _split_top(text: str, sep: str = ",") -> list[str]:
    parts, depth, cur, in_str = [], 0, [], None
    for ch in text:
        if in_str:
            cur.append(ch)
            if ch == in_str:
                in_str = None
            continue
        if ch in "'\"":
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


@dataclass
class TableState:
    name: str
    file: str
    line: int
    rls: bool = False


@dataclass
class SqlResult:
    findings: list[Finding] = field(default_factory=list)
    tables: dict[str, TableState] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)

    def rls_enabled(self, table: str) -> bool | None:
        """True/False if the table is defined in the scanned SQL, else None."""
        key = table if "." in table else f"public.{table.lower()}"
        st = self.tables.get(key)
        return None if st is None else st.rls


RE_CREATE_TABLE = re.compile(
    rf"^create\s+(?:(?:global\s+|local\s+)?(temp|temporary)\s+|unlogged\s+)?table\s+"
    rf"(?:if\s+not\s+exists\s+)?{_QNAME}",
    re.I,
)
RE_ALTER_TABLE = re.compile(
    rf"^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?{_QNAME}(.*)$", re.I | re.S
)
RE_DROP_TABLE = re.compile(r"^drop\s+table\s+(?:if\s+exists\s+)?(.+?)(?:\s+(?:cascade|restrict))?$", re.I | re.S)
RE_POLICY = re.compile(rf"^create\s+policy\s+({_IDENT})\s+on\s+{_QNAME}(.*)$", re.I | re.S)
RE_FUNCTION = re.compile(
    rf"^create\s+(?:or\s+replace\s+)?function\s+{_QNAME}\s*\(", re.I
)
RE_ALTER_FUNC_PATH = re.compile(
    rf"^alter\s+function\s+{_QNAME}\s*(?:\([^)]*\))?\s+set\s+\"?search_path\b", re.I | re.S
)
RE_VIEW = re.compile(
    rf"^create\s+(?:or\s+replace\s+)?(?:temp\s+|temporary\s+)?(?:recursive\s+)?view\s+"
    rf"(?:if\s+not\s+exists\s+)?{_QNAME}(.*)$",
    re.I | re.S,
)
RE_ALTER_VIEW_INVOKER = re.compile(
    rf"^alter\s+view\s+(?:if\s+exists\s+)?{_QNAME}\s+set\s*\(\s*security_invoker\s*=\s*(?:true|on|1)",
    re.I,
)
RE_BUCKET_INSERT = re.compile(
    r"^insert\s+into\s+storage\s*\.\s*buckets\s*\(([^)]*)\)\s*values\s*(.*)$", re.I | re.S
)
RE_BUCKET_UPDATE = re.compile(
    r"^update\s+storage\s*\.\s*buckets\s+set\s+(.*?)\s+where\s+(.*)$", re.I | re.S
)

PUBLIC_ROLES = {"public", "anon"}
# Roles that bypass RLS or are never used by API clients: a `using (true)` policy for
# them grants nothing that the role does not already have.
PRIVILEGED_ROLES = {
    "service_role", "postgres", "supabase_admin", "supabase_auth_admin",
    "supabase_storage_admin", "supabase_realtime_admin", "dashboard_user",
}
RE_DROP_POLICY = re.compile(rf"^drop\s+policy\s+(?:if\s+exists\s+)?({_IDENT})\s+on\s+{_QNAME}", re.I)
RE_DROP_FUNCTION = re.compile(rf"^drop\s+function\s+(?:if\s+exists\s+)?{_QNAME}", re.I)
RE_DROP_VIEW = re.compile(rf"^drop\s+view\s+(?:if\s+exists\s+)?(.+?)(?:\s+(?:cascade|restrict))?$", re.I | re.S)


def _policy_parts(rest: str) -> tuple[str, set[str], str | None, str | None, bool]:
    low = rest.lower()
    restrictive = bool(re.search(r"\bas\s+restrictive\b", low))
    m = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", low)
    cmd = m.group(1) if m else "all"
    m = re.search(r"\bto\s+(.+?)(?=\busing\b|\bwith\s+check\b|$)", rest, re.I | re.S)
    roles = {r.strip().strip('"').lower() for r in m.group(1).split(",")} if m else {"public"}
    using = check = None
    m = re.search(r"\busing\s*\(", rest, re.I)
    if m:
        using = _balanced_after(rest, m.end() - 1)
    m = re.search(r"\bwith\s+check\s*\(", rest, re.I)
    if m:
        check = _balanced_after(rest, m.end() - 1)
    return cmd, roles, using, check, restrictive


def _signature(arglist: str) -> str:
    """'a int default 1, b text = 'x'' -> 'a int, b text' (valid in ALTER FUNCTION)."""
    out = []
    for arg in _split_top(arglist):
        arg = re.split(r"\s+default\s+|\s*=\s*", arg, maxsplit=1, flags=re.I)[0]
        out.append(" ".join(arg.split()))
    return ", ".join(a for a in out if a)


def _strip_quotes(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] == "'":
        return v[1:-1]
    return v


RE_DO_BLOCK = re.compile(r"^do\b", re.I)
RE_LITERAL_ENABLE_RLS = re.compile(
    rf"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?{_QNAME}\s+enable\s+row\s+level\s+security\b", re.I
)
RE_DYNAMIC_ENABLE_RLS = re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:\w+\.)?%[ILs]\s+enable\s+row\s+level\s+security", re.I
)
RE_ARRAY_LITERAL = re.compile(r"\barray\s*\[([^\]]*)\]", re.I)


def _apply_do_block_rls(text: str, res: SqlResult) -> None:
    """Follow RLS enabled inside `DO $$ ... $$` blocks.

    Handles literal `alter table x enable row level security` statements and the common
    loop `foreach t in array array['a','b'] loop execute format('alter table public.%I
    enable row level security', t)`. Loops over catalog queries cannot be resolved
    statically and are left alone.
    """
    names = [m.group(1) for m in RE_LITERAL_ENABLE_RLS.finditer(text)]
    if RE_DYNAMIC_ENABLE_RLS.search(text):
        for arr in RE_ARRAY_LITERAL.finditer(text):
            names.extend(re.findall(r"'([A-Za-z_][A-Za-z0-9_$.]*)'", arr.group(1)))
    for raw in names:
        t = res.tables.get(norm_ident(raw))
        if t is not None:
            t.rls = True


def scan_sql_files(paths: list[Path], root: Path) -> SqlResult:
    res = SqlResult()
    pending_defs: dict[str, Finding] = {}  # security definer funcs waiting for an ALTER fix
    pending_views: dict[str, Finding] = {}
    pending_policies: dict[tuple[str, str], Finding] = {}  # (table, policy) -> open policy

    def rel(p: Path) -> str:
        try:
            return p.relative_to(root).as_posix()
        except ValueError:
            return p.as_posix()

    for path in paths:
        try:
            sql = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rp = rel(path)
        res.files.append(rp)
        for st in split_statements(sql, rp):
            text = st.text
            low_masked = st.masked.lower()

            if m := RE_CREATE_TABLE.match(text):
                if m.group(1):  # temp table
                    continue
                name = norm_ident(m.group(2))
                res.tables[name] = TableState(name, st.file, st.line)
                continue

            if RE_DO_BLOCK.match(text):
                _apply_do_block_rls(text, res)
                continue

            if m := RE_ALTER_TABLE.match(text):
                name = norm_ident(m.group(1))
                rest = m.group(2).lower()
                t = res.tables.get(name)
                if re.search(r"\b(enable|force)\s+row\s+level\s+security\b", rest):
                    if t is None:  # table defined elsewhere (e.g. dashboard); remember RLS
                        t = res.tables[name] = TableState(name, st.file, st.line, rls=True)
                    t.rls = True
                elif re.search(r"\bdisable\s+row\s+level\s+security\b", rest):
                    if t is None:
                        t = res.tables[name] = TableState(name, st.file, st.line)
                    t.rls = False
                    t.file, t.line = st.file, st.line
                elif (rm := re.search(rf"\brename\s+to\s+({_IDENT})", m.group(2), re.I)) and t:
                    new = f"{_schema(name)}.{norm_ident(rm.group(1)).split('.', 1)[1]}"
                    res.tables[new] = res.tables.pop(name)
                    res.tables[new].name = new
                    for key in [k for k in pending_policies if k[0] == name]:  # policies follow
                        f = pending_policies.pop(key)
                        f.extra["table"] = new
                        pending_policies[(new, key[1])] = f
                continue

            if m := RE_DROP_TABLE.match(text):
                for raw in _split_top(m.group(1)):
                    dropped = norm_ident(raw)
                    res.tables.pop(dropped, None)
                    for key in [k for k in pending_policies if k[0] == dropped]:
                        del pending_policies[key]
                continue

            if m := RE_DROP_POLICY.match(text):
                pending_policies.pop((norm_ident(m.group(2)), m.group(1).strip('"')), None)
                continue

            if m := RE_DROP_FUNCTION.match(text):
                pending_defs.pop(norm_ident(m.group(1)), None)
                continue

            if m := RE_DROP_VIEW.match(text):
                for raw in _split_top(m.group(1)):
                    pending_views.pop(norm_ident(raw), None)
                continue

            if m := RE_POLICY.match(text):
                pname = m.group(1).strip('"')
                table = norm_ident(m.group(2))
                cmd, roles, using, check, restrictive = _policy_parts(m.group(3))
                pending_policies.pop((table, pname), None)
                if restrictive or (roles and roles <= PRIVILEGED_ROLES):
                    continue
                open_using = _is_true(using) and cmd in {"all", "select", "update", "delete"}
                open_check = _is_true(check) and cmd in {"all", "insert", "update"}
                if not (open_using or open_check):
                    continue
                is_public = bool(roles & PUBLIC_ROLES)
                if cmd in {"update", "delete", "all"}:  # modify/delete any row
                    sev = "critical" if is_public else "high"
                elif cmd == "insert":  # write any row (spam, forged ownership)
                    sev = "high" if is_public else "medium"
                else:  # read-only exposure; may be intentional for public data
                    sev = "medium" if is_public else "low"
                clause = []
                if open_using:
                    clause.append("using (true)")
                if open_check:
                    clause.append("with check (true)")
                who = "anyone (anon)" if is_public else "any signed-in user"
                pending_policies[(table, pname)] = (
                    Finding(
                        "SLC102",
                        sev,
                        f'Policy "{pname}" on {_short(table)} is FOR {cmd.upper()} TO '
                        f"{', '.join(sorted(roles))} with {' and '.join(clause)}: "
                        f"{who} can {'read' if cmd == 'select' else 'access/modify'} every row.",
                        st.file,
                        st.line,
                        extra={"table": table, "policy": pname, "command": cmd, "roles": sorted(roles)},
                    )
                )
                continue

            if m := RE_FUNCTION.match(text):
                fname = norm_ident(m.group(1))
                args = _signature(_balanced_after(text, m.end() - 1) or "")
                if re.search(r"\bsecurity\s+definer\b", low_masked) and not re.search(
                    r"\bset\s+\"?search_path\b", low_masked
                ):
                    f = Finding(
                        "SLC104",
                        "medium",
                        f"Function {_short(fname)}() is SECURITY DEFINER but does not set search_path.",
                        st.file,
                        st.line,
                        extra={"function": fname, "args": args},
                    )
                    if re.search(r"\breturns\s+\"?(?:trigger|event_trigger)\b", low_masked):
                        # Trigger functions cannot be invoked through /rpc; this is hardening only.
                        f.severity = "low"
                        f.message += " It is a trigger function, so it is not callable via /rpc (hardening only)."
                    elif _schema(fname) in EXPOSED_SCHEMAS:
                        f.severity = "high"
                        f.message += " It is in an API-exposed schema, so it is callable via /rpc."
                    pending_defs[fname] = f
                else:
                    pending_defs.pop(fname, None)
                continue

            if m := RE_ALTER_FUNC_PATH.match(text):
                pending_defs.pop(norm_ident(m.group(1)), None)
                continue

            if m := RE_VIEW.match(text):
                vname = norm_ident(m.group(1))
                head = re.split(r"\bas\b", m.group(2).lower(), maxsplit=1)[0]
                invoker = re.search(r"security_invoker\s*=\s*(true|on|1)", head)
                if _schema(vname) in EXPOSED_SCHEMAS and not invoker:
                    pending_views[vname] = Finding(
                        "SLC105",
                        "medium",
                        f"View {_short(vname)} runs with its owner's rights, so it ignores RLS "
                        "on the tables it reads.",
                        st.file,
                        st.line,
                        extra={"view": vname},
                    )
                else:
                    pending_views.pop(vname, None)
                continue

            if m := RE_ALTER_VIEW_INVOKER.match(text):
                pending_views.pop(norm_ident(m.group(1)), None)
                continue

            if m := RE_BUCKET_INSERT.match(text):
                cols = [c.strip().strip('"').lower() for c in m.group(1).split(",")]
                if "public" not in cols:
                    continue
                values_part = re.split(r"\bon\s+conflict\b|\breturning\b", m.group(2), flags=re.I)[0]
                for tup in _split_top(values_part):
                    tup = tup.strip()
                    if not (tup.startswith("(") and tup.endswith(")")):
                        continue
                    vals = _split_top(tup[1:-1])
                    if len(vals) != len(cols):
                        continue
                    row = dict(zip(cols, vals))
                    if row["public"].strip().lower() in {"true", "'true'", "'t'", "true::boolean"}:
                        bucket = _strip_quotes(row.get("id") or row.get("name") or "?")
                        res.findings.append(
                            Finding(
                                "SLC103",
                                "medium",
                                f"Storage bucket '{bucket}' is created public: anyone with a file "
                                "URL can download it without any policy check.",
                                st.file,
                                st.line,
                                extra={"bucket": bucket},
                            )
                        )
                continue

            if m := RE_BUCKET_UPDATE.match(text):
                if re.search(r"\bpublic\s*=\s*true\b", m.group(1), re.I):
                    bm = re.search(r"\b(?:id|name)\s*=\s*'([^']*)'", m.group(2), re.I)
                    bucket = bm.group(1) if bm else "?"
                    res.findings.append(
                        Finding(
                            "SLC103",
                            "medium",
                            f"Storage bucket '{bucket}' is switched to public.",
                            st.file,
                            st.line,
                            extra={"bucket": bucket},
                        )
                    )
                continue

    for t in res.tables.values():
        if not t.rls and _schema(t.name) in EXPOSED_SCHEMAS:
            res.findings.append(
                Finding(
                    "SLC101",
                    "critical",
                    f"Table {_short(t.name)} has no `enable row level security` in any migration: "
                    "anyone with your anon key can query it via the REST API.",
                    t.file,
                    t.line,
                    extra={"table": t.name},
                )
            )
    res.findings.extend(pending_policies.values())
    res.findings.extend(pending_defs.values())
    res.findings.extend(pending_views.values())
    return res
