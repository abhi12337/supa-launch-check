# supa-launch-check

A pre-launch security check for Supabase-backed apps, including apps built with Lovable,
Bolt, Cursor or v0. Run it before you go live. It looks for the mistakes that most often
leak data from Supabase apps:

- a `service_role` / `sb_secret_` key shipped in frontend code or a built bundle
- tables with no Row Level Security
- policies that let anyone do anything (`using (true)`)
- public storage buckets
- `SECURITY DEFINER` functions you can call over the API

Zero dependencies (Python 3.10+ standard library only). Works offline. CI-friendly exit codes.

> **Owner-only rule.** Use this tool only on projects you own, or that you have written
> permission to test. The static scan reads local files only. The optional live check
> sends requests to a Supabase project, so it will not run unless you pass
> `--i-own-this-project` and confirm a consent prompt. Testing other people's systems
> without permission may be illegal where you live.

---

## Quick start

```bash
pipx install git+https://github.com/abhi12337/supa-launch-check   # straight from GitHub
pipx install .                      # from a clone of this repo (or: pip install .)

supa-launch-check scan path/to/your-app          # source repo
supa-launch-check scan path/to/your-app/dist     # built output: where leaked keys really end up
supa-launch-check scan . --json > report.json    # machine-readable output
supa-launch-check rules                          # every rule, why it matters, how to fix it
```

Try it on a deliberately broken demo app:

```bash
python examples/make_demo_app.py /tmp/demo-app
supa-launch-check scan /tmp/demo-app
```

Exit codes: `0` = nothing at or above `--fail-on` (default `high`), `1` = findings at or above
it, `2` = usage error. Use `--fail-on critical|high|medium|low|never` to tune CI.

## Example output

`supa-launch-check scan demo-app --brief` (the full report adds "why" and "fix" to every
finding):

```text
supa-launch-check 0.1.0
Scanned demo-app
5 files, 1 SQL migration file(s)

CRITICAL SLC001  Supabase service_role key in code
      at: src/integrations/supabase/client.ts:5
      Supabase service_role JWT hard-coded in source code.
      found: eyJhbGci...ZXJl (220 chars)

CRITICAL SLC004  API secret key in code
      at: src/lib/ai.ts:1
      OpenAI API key hard-coded in source code.
      found: sk-proj-...fXYZ (43 chars)

CRITICAL SLC101  Table in public schema without Row Level Security
      at: supabase/migrations/20250101000000_init.sql:9
      Table todos has no `enable row level security` in any migration: anyone with your anon key
      can query it via the REST API.

CRITICAL SLC102  Policy allows everything (using (true) / with check (true))
      at: supabase/migrations/20250101000000_init.sql:17
      Policy "Allow all" on invoices is FOR ALL TO anon with using (true) and with check (true):
      anyone (anon) can access/modify every row.

HIGH     SLC006  Client queries a table with no RLS evidence [heuristic]
      at: src/pages/Dashboard.tsx:4
      Client code queries 'todos' directly, and the migrations never enable RLS on it (see
      SLC101).

HIGH     SLC104  SECURITY DEFINER function without a fixed search_path
      at: supabase/migrations/20250101000000_init.sql:21
      Function is_admin() is SECURITY DEFINER but does not set search_path. It is in an API-
      exposed schema, so it is callable via /rpc.

MEDIUM   SLC005  .env file committed or not ignored
      at: .env
      .env exists and is not covered by .gitignore.

MEDIUM   SLC102  Policy allows everything (using (true) / with check (true))
      at: supabase/migrations/20250101000000_init.sql:6
      Policy "Enable read access for all users" on profiles is FOR SELECT TO public with using
      (true): anyone (anon) can read every row.

MEDIUM   SLC103  Storage bucket created as public
      at: supabase/migrations/20250101000000_init.sql:19
      Storage bucket 'receipts' is created public: anyone with a file URL can download it without
      any policy check.

Summary: 4 critical, 2 high, 3 medium, 0 low
Exit code: 1
```

A full finding, with the fix filled in for your table and policy names:

```text
CRITICAL SLC102  Policy allows everything (using (true) / with check (true))
      at: supabase/migrations/20250101000000_init.sql:17
      Policy "Allow all" on invoices is FOR ALL TO anon with using (true) and with check (true):
      anyone (anon) can access/modify every row.
      why: A policy with `using (true)` or `with check (true)` lets the listed roles touch
           every row. For anon/public that means anyone on the internet; for authenticated
           it means any user who can sign up. Write access with (true) is how apps get their
           data wiped or spammed.
      fix:
        Scope the policy to the row owner, e.g.:

          drop policy "Allow all" on public.invoices;
          create policy "Allow all" on public.invoices
            for all to authenticated
            using ((select auth.uid()) = user_id)        -- adjust to your owner column
            with check ((select auth.uid()) = user_id);

        Keep `using (true)` only for SELECT on data that is meant to be fully public.
```

Secrets are always masked in the output (text and JSON). Row data from the live check is
never printed or stored.

## What it checks

### 1. Static scan of a repo or build folder (`scan`, no network)

| Rule | Severity | What it finds |
|---|---|---|
| SLC001 | Critical (High in server-only code) | JWTs whose decoded payload has `"role": "service_role"`. The anon key is ignored, because it is meant to be public. |
| SLC002 | Critical (High in server-only code) | New-style `sb_secret_...` Supabase keys. |
| SLC003 | Critical / Low | Stripe live secret/restricted keys (`sk_live_`, `rk_live_`); test keys are Low. |
| SLC004 | Critical / High | OpenAI, Anthropic, AWS access key ids, GitHub tokens, private key blocks. |
| SLC005 | High / Medium | `.env` files tracked by git (High) or present and not git-ignored (Medium). `.env.example` etc. are skipped. Git-ignored `.env` files are not scanned for secrets, because a local server key there is normal. |
| SLC006 | High / Medium / Low, **heuristic** | Client code calling `supabase.from('table')` on a table whose migrations never enable RLS (High), that no migration defines (Medium), or when there are no migrations at all (Low). `storage.from(...)` and server paths are ignored. |
| SLC007 | High | Service keys behind public env prefixes: `VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`, `EXPO_PUBLIC_`, `PUBLIC_`, ... |

Built bundles (`dist/`, `build/`, `.next/static/`, `out/`, ...) are scanned too, including
minified files. `node_modules`, `.git`, binaries and test folders are skipped (use
`--include-tests` to scan tests, `--exclude GLOB` to skip more).

### 2. Migration / SQL scan (part of `scan`)

Reads `supabase/migrations/*.sql` in order, then `supabase/schemas/*.sql` if you use
declarative schemas (they describe the final state). In a monorepo without a root
`supabase/` folder it scans every nested `**/supabase/migrations` folder as its own project,
and falls back to every `.sql` file only if there is none. It follows
`alter table ... enable/disable row level security` (including the common `DO $$ ... foreach
... execute format('alter table %I enable row level security')` loop), renames, and dropped
tables, policies, functions and views across files. It ignores comments and does not
otherwise look inside function bodies.

| Rule | Severity | What it finds |
|---|---|---|
| SLC101 | Critical | A table in `public` that never gets `enable row level security` (or has it disabled later). |
| SLC102 | Critical to Low | Permissive policies with `using (true)` / `with check (true)`. UPDATE/DELETE/ALL for anon/public is Critical; INSERT for anon is High; SELECT for anon is Medium (it may be intentional); SELECT for authenticated is Low. Restrictive policies are ignored. |
| SLC103 | Medium | `insert into storage.buckets (..., public) values (..., true)` or `update storage.buckets set public = true`. |
| SLC104 | High in `public`, else Medium | `security definer` functions without `set search_path` (an `alter function ... set search_path` later counts as fixed). |
| SLC105 | Medium | Views in `public` without `security_invoker = true`; they bypass RLS on the tables they read. |

### 3. Live check (`live`, owner-only, opt-in)

```bash
supa-launch-check live \
  --url https://YOUR-PROJECT.supabase.co \
  --anon-key "$SUPABASE_ANON_KEY" \
  --i-own-this-project
```

Exactly what it does:

1. `GET /rest/v1/` (the PostgREST OpenAPI document) to list exposed tables and RPC functions.
2. For each table, `GET /rest/v1/<table>?select=*&limit=1` with your anon/publishable key.
3. Reports **SLC201 (High)** for each table that returns a row to an anonymous request, and
   **SLC202 (Low)** listing RPC functions the anon key can see. Functions are never called.

Safety rails:

- Will not run without `--i-own-this-project`, and asks you to type `I own this project`
  (in CI, add `--yes` together with `--i-own-this-project`).
- Refuses `service_role` and `sb_secret_` keys. It must see what an anonymous visitor sees.
- Read-only: GET requests only. No insert, update, delete, upsert or RPC calls.
- Rate-limited: one request every 0.5 s by default (`--delay`, minimum 0.2 s), at most 200
  tables (`--max-tables`).
- Never prints or stores row contents, only whether rows came back.
- `https` only, except for `localhost` (local Supabase via `supabase start`).

Some projects disable the OpenAPI endpoint for anon; the check then stops with a clear
message instead of guessing table names.

## What it does not check

Be clear about the limits before you rely on it:

- **It is not a penetration test** and gives **no guarantee** that your app is secure. A
  clean report means "none of these known mistakes were found", nothing more.
- It does not evaluate whether policy logic is correct (for example `auth.uid() = user_id`
  on the wrong column, or a role check that can be spoofed through `user_metadata`).
- It cannot see tables, policies or buckets created only in the dashboard. Run
  `supabase db pull` so your schema lives in `supabase/migrations`.
- It does not test Edge Functions, auth settings (email confirmation, OTP expiry, leaked
  password protection), rate limits, CORS, storage object policies, or your own API.
- Secret detection is pattern-based. Unusual or custom secrets will be missed.
- SLC006 is a heuristic: it can miss dynamic table names and can flag tables that are
  protected by rules it cannot see.

Supabase's own Security Advisor (Dashboard -> Advisors) checks your live database and is a
good companion to this tool.

## How to fix each finding

`supa-launch-check rules` prints all of this, and every finding in the report includes its
fix with your real table, policy, bucket and function names filled in.

**SLC001 / SLC002 - service_role or secret key in code.** Rotate it first (Project Settings
-> API Keys); removing it from code is not enough because it is in your git history and in
deployed bundles. Use only the anon/publishable key in the browser. Keep secret keys in
server-side env vars (Edge Functions, your API).

**SLC003 / SLC004 - other secrets.** Rotate in the provider dashboard, remove from code and
history (`git filter-repo` or BFG), call the provider from a server that reads the key from
an env var.

**SLC005 - .env committed.**
```bash
echo ".env" >> .gitignore && echo ".env*.local" >> .gitignore
git rm --cached .env      # then rotate every secret it held
```

**SLC006 / SLC101 - table without RLS.**
```sql
alter table public.todos enable row level security;
create policy "owner can read" on public.todos
  for select to authenticated using ((select auth.uid()) = user_id);
```

**SLC102 - `using (true)` policy.**
```sql
drop policy "Allow all" on public.invoices;
create policy "owner can manage" on public.invoices
  for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);
```

**SLC103 - public bucket.**
```sql
update storage.buckets set public = false where id = 'receipts';
```
Then serve files with `createSignedUrl(...)` and add owner-scoped policies on `storage.objects`.

**SLC104 - SECURITY DEFINER without search_path.**
```sql
alter function public.is_admin() set search_path = '';
revoke execute on function public.is_admin() from anon, public;  -- if anon should not call it
```
Schema-qualify everything inside the body (`public.profiles`, `auth.uid()`).

**SLC105 - view bypasses RLS.**
```sql
alter view public.profile_summary set (security_invoker = true);
```

**SLC201 - table readable by anon (live).** Enable RLS and replace broad policies as in
SLC101/SLC102. If the table is meant to be public, make sure it has no private columns.

**SLC202 - RPC functions visible to anon (live).**
```sql
revoke execute on function public.some_function(args) from anon, public;
```

## Suppressing a finding

Add `supa-launch-check: ignore` as a comment on the same line:

```ts
const demoKey = "sk_test_..."; // supa-launch-check: ignore
```

## Use in CI

See [`examples/github-actions/supa-launch-check.yml`](examples/github-actions/supa-launch-check.yml).
It runs the static scan on every pull request and fails the build on Critical/High findings.
For the best coverage, build the app first and scan the build output as well.

## JSON output

`--json` prints:

```json
{
  "tool": "supa-launch-check",
  "version": "0.1.0",
  "mode": "scan",
  "target": "/abs/path/demo-app",
  "files_scanned": 5,
  "sql_files": ["supabase/migrations/20250101000000_init.sql"],
  "exit_code": 1,
  "summary": {"critical": 4, "high": 2, "medium": 3, "low": 0},
  "findings": [
    {
      "rule_id": "SLC101",
      "severity": "critical",
      "message": "Table todos has no `enable row level security` ...",
      "file": "supabase/migrations/20250101000000_init.sql",
      "line": 9,
      "evidence": null,
      "heuristic": false,
      "extra": {"table": "public.todos"},
      "title": "Table in public schema without Row Level Security",
      "why": "...",
      "fix": "alter table public.todos enable row level security; ..."
    }
  ]
}
```

## Development

```bash
pip install -e ".[test]"
pytest
```

Test fixtures never contain real or real-looking secrets in the repository: fake keys are
assembled at runtime in `tests/conftest.py`.

## License

MIT, Copyright (c) 2026 Abheesht Tripathi. See [LICENSE](LICENSE).

---

**More open-source checks from the same author:** [mcp-audit](https://github.com/abhi12337/mcp-audit) · [rules-file-audit](https://github.com/abhi12337/rules-file-audit) · [inject-test](https://github.com/abhi12337/inject-test) · [firebase-launch-check](https://github.com/abhi12337/firebase-launch-check) · [key-leak-check](https://github.com/abhi12337/key-leak-check) · [route-auth-check](https://github.com/abhi12337/route-auth-check) · [webhook-check](https://github.com/abhi12337/webhook-check) · [llm-cost-lint](https://github.com/abhi12337/llm-cost-lint) · [pg-launch-check](https://github.com/abhi12337/pg-launch-check). Overview and research: [github.com/abhi12337](https://github.com/abhi12337)

Need help fixing these before launch? abheeshttripathi890@gmail.com
