"""Finding model and the rule catalogue (ids, severities, why it matters, how to fix)."""

from __future__ import annotations

import re
import textwrap
from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}  # lower = worse


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    why: str
    fix: str


RULES: dict[str, Rule] = {}


def _rule(id: str, title: str, why: str, fix: str) -> None:
    RULES[id] = Rule(id, title, " ".join(why.split()), textwrap.dedent(fix).strip(chr(10)))


# ---------------------------------------------------------------- static scan
_rule(
    "SLC001",
    "Supabase service_role key in code",
    """
The service_role key bypasses Row Level Security completely. Anyone who has it can
read, change and delete every row in every table and every file in storage. If it is
in client code or a built bundle, every visitor to your site already has it.
""",
    """
1. Rotate it now: Supabase dashboard -> Project Settings -> API Keys (roll the JWT secret
   for legacy keys, or create a new secret key and delete the old one).
2. Remove it from the code and from git history (git filter-repo / BFG).
3. Use only the anon / publishable key in the browser. Keep the service key in server-side
   environment variables (Edge Functions, your API) and never prefix it with
   NEXT_PUBLIC_ / VITE_ / REACT_APP_ / EXPO_PUBLIC_.
""",
)
_rule(
    "SLC002",
    "Supabase secret key (sb_secret_...) in code",
    """
sb_secret_ keys are the new-style equivalent of the service_role key: they bypass Row
Level Security. Supabase blocks them in browsers, but anyone who reads the repo or the
bundle can use them from a server or script.
""",
    """
1. Delete the key in Supabase dashboard -> Project Settings -> API Keys and create a new one.
2. Remove it from the code and git history.
3. Load it from a server-side environment variable only.
""",
)
_rule(
    "SLC003",
    "Payment provider secret key in code",
    """
A Stripe live secret / restricted key lets the holder create charges, issue refunds and
read customer data on your account.
""",
    """
1. Roll the key in Stripe Dashboard -> Developers -> API keys.
2. Remove it from code and git history; load it from a server-side environment variable.
3. In the browser use only the publishable key (pk_live_...).
""",
)
_rule(
    "SLC004",
    "API secret key in code",
    """
Hard-coded API secrets (OpenAI, Anthropic, AWS, GitHub, private keys) get scraped from
public repos and bundles within minutes and used to run up bills or access your accounts.
""",
    """
1. Revoke / rotate the key in the provider's dashboard.
2. Remove it from code and git history.
3. Call the provider from a server (e.g. a Supabase Edge Function) that reads the key from
   an environment variable; never ship it to the browser.
""",
)
_rule(
    "SLC005",
    ".env file committed or not ignored",
    """
.env files usually hold secrets (service keys, database URLs, API keys). Once committed
they stay in git history even after deletion.
""",
    """
1. Add to .gitignore:   .env  and  .env*.local  (keep .env.example with dummy values).
2. If it was committed:  git rm --cached .env  then rotate every secret it contained,
   because the old values remain in history.
""",
)
_rule(
    "SLC006",
    "Client queries a table with no RLS evidence",
    """
Browser code talks to this table directly with the public anon key. That is only safe if
Row Level Security is enabled and the policies restrict rows to the right user. This rule
is a heuristic: it matches supabase.from('table') calls and cross-checks your migrations.
""",
    """
Make sure the table has RLS on and a policy scoped to the user, e.g.:

  alter table <table> enable row level security;
  create policy "owner can read" on <table>
    for select to authenticated using ((select auth.uid()) = user_id);

If the table is defined outside supabase/migrations (dashboard-created), run
`supabase db pull` so the schema is in the repo and can be checked.
""",
)
_rule(
    "SLC007",
    "Service key exposed through a public env-var prefix",
    """
Variables prefixed NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_, PUBLIC_ etc. are inlined
into the browser bundle at build time. A service-role / secret key there is public.
""",
    """
Rename the variable without the public prefix (e.g. SUPABASE_SERVICE_ROLE_KEY), read it
only in server code, and rotate the key because past builds already contain it.
""",
)

# ---------------------------------------------------------------- SQL scan
_rule(
    "SLC101",
    "Table in public schema without Row Level Security",
    """
Every table in the public schema is reachable through the auto-generated REST API with
the anon key that ships in your frontend. Without RLS, anyone can read (and, depending on
grants, insert/update/delete) all rows.
""",
    """
  alter table <table> enable row level security;

Then add policies for what each role may do, e.g.:

  create policy "users read own rows" on <table>
    for select to authenticated using ((select auth.uid()) = user_id);
""",
)
_rule(
    "SLC102",
    "Policy allows everything (using (true) / with check (true))",
    """
A policy with `using (true)` or `with check (true)` lets the listed roles touch every row.
For anon/public that means anyone on the internet; for authenticated it means any user who
can sign up. Write access with (true) is how apps get their data wiped or spammed.
""",
    """
Scope the policy to the row owner, e.g.:

  drop policy "<policy>" on <table>;
  create policy "<policy>" on <table>
    for <command> to authenticated
    using ((select auth.uid()) = user_id)        -- adjust to your owner column
    with check ((select auth.uid()) = user_id);

Keep `using (true)` only for SELECT on data that is meant to be fully public.
""",
)
_rule(
    "SLC103",
    "Storage bucket created as public",
    """
Files in a public bucket can be downloaded by anyone who has (or guesses) the URL, with no
RLS check. Fine for logos and avatars, dangerous for invoices, IDs, exports or uploads.
""",
    """
If the files are not meant to be public:

  update storage.buckets set public = false where id = '<bucket>';

and serve them with signed URLs (supabase.storage.from('<bucket>').createSignedUrl(...))
plus policies on storage.objects scoped to the owner.
""",
)
_rule(
    "SLC104",
    "SECURITY DEFINER function without a fixed search_path",
    """
SECURITY DEFINER functions run with the privileges of their owner (often postgres) and,
in the public schema, can be called by anyone via /rest/v1/rpc. Without a fixed
search_path, a caller who can create objects may hijack names the function resolves.
""",
    """
  alter function <function>(<args>) set search_path = '';

and schema-qualify every object inside the body (public.table, auth.uid()). Also consider
whether it needs SECURITY DEFINER at all, and revoke execute from anon if not public:

  revoke execute on function <function>(<args>) from anon, public;
""",
)
_rule(
    "SLC105",
    "View in public schema bypasses RLS (no security_invoker)",
    """
Postgres views run with the permissions of the view owner by default, so a view over an
RLS-protected table returns every row to anon/authenticated callers through the API.
""",
    """
On Postgres 15+:

  alter view <view> set (security_invoker = true);

or create it with:  create view <view> with (security_invoker = true) as ...
""",
)

# ---------------------------------------------------------------- live check
_rule(
    "SLC201",
    "Table rows readable with the anon key (live)",
    """
A real `select ... limit 1` request made with only your public anon key returned data.
Anyone visiting your site can run the same request and page through the whole table.
""",
    """
If this table should not be public:

  alter table <table> enable row level security;
  -- remove broad policies such as: using (true)
  create policy "owner can read" on <table>
    for select to authenticated using ((select auth.uid()) = user_id);

If it is intentionally public (e.g. blog posts), make sure no private columns are
exposed; move them to a separate table or use a view with security_invoker.
""",
)
_rule(
    "SLC202",
    "RPC functions exposed to the anon key (live)",
    """
Every function in an exposed schema is callable via POST /rest/v1/rpc/<name>. SECURITY
DEFINER functions in that list bypass RLS. This check only lists them; it never calls them.
""",
    """
For functions that should not be public:

  revoke execute on function <function>(<args>) from anon, public;

or move them to a schema that is not exposed through the API.
""",
)


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str | None = None
    line: int | None = None
    evidence: str | None = None
    heuristic: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    @property
    def location(self) -> str:
        if self.file is None:
            return ""
        return f"{self.file}:{self.line}" if self.line else self.file

    @property
    def fix(self) -> str:
        """The rule's fix text with this finding's table/policy/bucket/... filled in."""
        text = self.rule.fix
        e = self.extra
        subs = {
            "<table>": qualified(e["table"]) if e.get("table") else None,
            "<view>": qualified(e["view"]) if e.get("view") else None,
            "<function>": qualified(e["function"]) if e.get("function") else None,
            "<args>": e.get("args"),
            "<policy>": e.get("policy", "").replace('"', '""') or None,
            "<bucket>": e.get("bucket"),
            "<command>": e.get("command"),
        }
        for k, v in subs.items():
            if v is not None:
                text = text.replace(k, v)
            elif k in ("<table>", "<view>", "<function>"):
                text = text.replace(k, "public." + k)
        return text

    def to_dict(self) -> dict:
        d = asdict(self)
        d["title"] = self.rule.title
        d["why"] = self.rule.why
        d["fix"] = self.fix
        if not d["extra"]:
            d.pop("extra")
        return d


_PLAIN = re.compile(r"^[a-z_][a-z0-9_$]*$")


def _qi(part: str) -> str:
    return part if _PLAIN.match(part) else '"' + part.replace('"', '""') + '"'


def qualified(name: str) -> str:
    """'todos' -> 'public.todos', 'public.Orders' -> 'public."Orders"'."""
    schema, _, obj = name.rpartition(".")
    return f"{_qi(schema or 'public')}.{_qi(obj)}"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_RANK[f.severity], f.rule_id, f.file or "", f.line or 0),
    )


def mask_secret(value: str, keep_start: int = 8, keep_end: int = 4) -> str:
    """Show just enough of a secret to find it, never enough to use it."""
    if len(value) <= keep_start + keep_end + 4:
        return value[: min(4, len(value) // 3)] + "****"
    return f"{value[:keep_start]}...{value[-keep_end:]} ({len(value)} chars)"
