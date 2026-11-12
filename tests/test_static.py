import shutil
from pathlib import Path

import pytest

from supa_launch_check.static_scan import decode_jwt_payload, scan_path

FIX = Path(__file__).parent / "fixtures"


def scan(root, **kw):
    res, _ = scan_path(root, **kw)
    return res.findings


def only(findings, rule):
    return [f for f in findings if f.rule_id == rule]


# ---------------------------------------------------------------- SLC001 service_role JWT
def test_decode_jwt_payload(fake):
    assert decode_jwt_payload(fake["service_jwt"])["role"] == "service_role"
    assert decode_jwt_payload("eyJ.not.jwt") is None


def test_service_role_jwt_in_client_code_is_critical_and_masked(make_repo, fake):
    root = make_repo({"src/lib/supabase.ts": f'import x from "y";\nconst key = "{fake["service_jwt"]}";\n'})
    [f] = only(scan(root), "SLC001")
    assert f.severity == "critical"
    assert (f.file, f.line) == ("src/lib/supabase.ts", 2)
    assert fake["service_jwt"] not in f.evidence
    assert "..." in f.evidence


def test_anon_jwt_is_not_a_finding(make_repo, fake):
    root = make_repo({"src/client.ts": f'const anon = "{fake["anon_jwt"]}";'})
    assert only(scan(root), "SLC001") == []


def test_service_role_in_server_code_is_high(make_repo, fake):
    root = make_repo({"supabase/functions/admin/index.ts": f'const k = "{fake["service_jwt"]}";'})
    [f] = only(scan(root), "SLC001")
    assert f.severity == "high"


def test_service_role_in_minified_build_bundle(make_repo, fake):
    bundle = "!function(){var a=1;" * 200 + f'createClient("https://x.supabase.co","{fake["service_jwt"]}")' + "}();"
    root = make_repo({"dist/assets/index-abc123.js": bundle})
    [f] = only(scan(root), "SLC001")
    assert f.severity == "critical"
    assert "built bundle" in f.message
    assert f.line == 1


def test_same_secret_reported_once_per_file(make_repo, fake):
    k = fake["service_jwt"]
    root = make_repo({"src/a.ts": f'"{k}"\n"{k}"\n'})
    assert len(only(scan(root), "SLC001")) == 1


# ---------------------------------------------------------------- SLC002 sb_secret_
def test_sb_secret_key(make_repo, fake):
    root = make_repo({"src/env.js": f"export const k = '{fake['sb_secret']}';",
                      "src/ok.js": f"export const p = '{fake['sb_publishable']}';"})
    [f] = only(scan(root), "SLC002")
    assert f.severity == "critical" and f.file == "src/env.js"


# ---------------------------------------------------------------- SLC003 / SLC004 other secrets
def test_stripe_keys(make_repo, fake):
    root = make_repo({"src/pay.ts": f"const live = '{fake['stripe_live']}';\nconst test = '{fake['stripe_test']}';"})
    sev = sorted(f.severity for f in only(scan(root), "SLC003"))
    assert sev == ["critical", "low"]


@pytest.mark.parametrize("name,label", [
    ("openai", "OpenAI API key"),
    ("anthropic", "Anthropic API key"),
    ("aws", "AWS access key id"),
    ("github", "GitHub token"),
    ("private_key", "Private key"),
])
def test_api_secrets(make_repo, fake, name, label):
    root = make_repo({"src/ai.ts": f"const k = `{fake[name]}`;"})
    found = only(scan(root), "SLC004")
    assert len(found) == 1, found
    assert label in found[0].message
    if name != "private_key":
        assert fake[name] not in found[0].evidence


def test_inline_ignore_comment(make_repo, fake):
    root = make_repo({"src/a.ts": f"const k = '{fake['stripe_live']}'; // supa-launch-check: ignore"})
    assert only(scan(root), "SLC003") == []


def test_skips_node_modules_binaries_and_tests(make_repo, fake):
    root = make_repo({
        "node_modules/pkg/index.js": f"'{fake['stripe_live']}'",
        "assets/logo.png": b"\x89PNG\0\0" + fake["stripe_live"].encode(),
        "src/blob.dat": b"\0\0\0" + fake["stripe_live"].encode(),
        "src/__tests__/a.test.ts": f"'{fake['stripe_live']}'",
    })
    assert scan(root) == []
    assert len(only(scan(root, include_tests=True), "SLC003")) == 1


def test_exclude_glob(make_repo, fake):
    root = make_repo({"docs/leak.md": fake["stripe_live"]})
    assert only(scan(root), "SLC003")
    assert only(scan(root, excludes=["docs/*"]), "SLC003") == []


# ---------------------------------------------------------------- SLC005 .env files
def test_env_file_not_ignored_without_git(make_repo):
    root = make_repo({".env": "X=1", ".env.example": "X=", "src/a.ts": ""})
    [f] = only(scan(root), "SLC005")
    assert f.file == ".env" and f.severity == "medium"


def test_env_file_ignored_by_gitignore_without_git(make_repo, fake):
    root = make_repo({".env.local": f"SUPABASE_SERVICE_ROLE_KEY={fake['service_jwt']}", ".gitignore": ".env*\n"})
    findings = scan(root)
    assert only(findings, "SLC005") == []
    assert only(findings, "SLC001") == []  # local, ignored .env holding a server key is normal


def test_env_file_committed_in_git(make_repo, fake):
    root = make_repo(
        {".env": f"STRIPE={fake['stripe_live']}", ".env.production": "A=1", ".gitignore": ".env.production\n"},
        git=True, add=[".env"],
    )
    findings = scan(root)
    env = {f.file: f.severity for f in only(findings, "SLC005")}
    assert env == {".env": "high"}
    assert only(findings, "SLC003")  # committed .env is scanned for secrets


def test_env_file_untracked_not_ignored_in_git(make_repo):
    root = make_repo({".env": "A=1"}, git=True)
    [f] = only(scan(root), "SLC005")
    assert f.severity == "medium"


# ---------------------------------------------------------------- SLC006 client table access
def _with_migrations(make_repo, files):
    root = make_repo(files)
    shutil.copytree(FIX / "sql_vulnerable" / "supabase", root / "supabase")
    return root


def test_client_from_cross_checks_migrations(make_repo):
    root = _with_migrations(make_repo, {
        "src/App.tsx": (
            "const a = await supabase.from('profiles').select('*')\n"   # RLS on -> no finding
            "const b = await supabase.from('todos').select('*')\n"      # RLS off -> high
            "const c = await supabase.from(\"payments\").select()\n"    # unknown -> medium
            "const d = await supabase.from('todos').insert({})\n"
            "const e = await supabase.storage.from('avatars').upload(p, f)\n"  # storage, ignored
            "const g = Array.from('abc')\n"                             # not supabase
        ),
        "src/server/admin.ts": "await supabase.from('secrets').select()",  # server path, ignored
    })
    found = {f.extra["table"]: f for f in only(scan(root), "SLC006")}
    assert set(found) == {"todos", "payments"}
    assert found["todos"].severity == "high"
    assert found["todos"].extra["call_sites"] == 2
    assert found["payments"].severity == "medium"
    assert all(f.heuristic for f in found.values())


def test_client_from_without_migrations_is_low(make_repo):
    root = make_repo({"src/App.jsx": "supabase.from(`orders`).select()"})
    [f] = only(scan(root), "SLC006")
    assert f.severity == "low" and f.extra["table"] == "orders"


# ---------------------------------------------------------------- SLC007 public env var
def test_service_key_behind_public_prefix(make_repo):
    root = make_repo({
        "src/lib/sb.ts": "createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY)",
        "app/page.tsx": "process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY",
    })
    [f] = only(scan(root), "SLC007")
    assert f.evidence == "VITE_SUPABASE_SERVICE_ROLE_KEY" and f.severity == "high"


# ---------------------------------------------------------------- whole repo
def test_clean_repo_is_clean(make_repo, fake):
    root = make_repo({
        "src/lib/supabase.ts": f"export const sb = createClient(url, '{fake['anon_jwt']}')",
        "src/App.tsx": "supabase.from('profiles').select('*')",
        ".gitignore": ".env\n",
        ".env": "SUPABASE_SERVICE_ROLE_KEY=whatever",
    })
    shutil.copytree(FIX / "sql_clean" / "supabase", root / "supabase")
    assert scan(root) == []


# ---------------------------------------------------------------- monorepos and demo keys
def test_nested_supabase_migrations_are_scanned_per_project(make_repo):
    root = make_repo({
        "apps/a/supabase/migrations/001.sql": "create table todos (id int);",
        "apps/b/supabase/migrations/001.sql": "create table todos (id int); alter table todos enable row level security;",
        "apps/a/supabase/seed.sql": "create table seed_only (id int);",
        "packages/other/schema.sql": "create table unrelated (id int);",
    })
    res, sql = scan_path(root)
    assert sorted(res.sql_files) == ["apps/a/supabase/migrations/001.sql", "apps/b/supabase/migrations/001.sql"]
    [f] = only(res.findings, "SLC101")
    assert f.file == "apps/a/supabase/migrations/001.sql"
    assert sql.rls_enabled("todos") is False  # unprotected in at least one project


def test_local_demo_service_role_key_is_low(make_repo):
    import base64, json as _json
    def b64(o):
        raw = o if isinstance(o, bytes) else _json.dumps(o).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    demo = ".".join([b64({"alg": "HS256", "typ": "JWT"}),
                     b64({"iss": "supabase-demo", "role": "service_role", "exp": 1983812996}),
                     b64(b"fake-signature-bytes-for-test")])
    root = make_repo({"src/lib/local.ts": f'const k = "{demo}";'})
    [f] = only(scan(root), "SLC001")
    assert f.severity == "low"
    assert "demo" in f.message


# ---------------------------------------------------------------- false-positive guards
def test_placeholder_api_key_is_low(make_repo):
    placeholder = "sk-" + "or-v1-" + "0" * 40
    root = make_repo({"src/settings.tsx": f'const placeholder = "{placeholder}";'})
    [f] = only(scan(root), "SLC004")
    assert f.severity == "low" and "placeholder" in f.message


def test_real_looking_api_key_is_not_a_placeholder(make_repo, fake):
    root = make_repo({"src/ai.ts": f'const k = "{fake["openai"]}";'})
    [f] = only(scan(root), "SLC004")
    assert f.severity == "critical"


def test_pem_header_mentioned_in_docs_is_ignored(make_repo, fake):
    root = make_repo({"README.md": f"If your key starts with `{fake['private_key']}`, convert it."})
    assert only(scan(root), "SLC004") == []


def test_pem_key_with_body_in_docs_is_reported(make_repo, fake):
    body = "MIIEow" + "Ab9Zx3Kq" * 10
    root = make_repo({"docs/setup.md": f"{fake['private_key']}\n{body}\n"})
    assert len(only(scan(root), "SLC004")) == 1


def test_xcode_env_is_not_a_dotenv_file(make_repo):
    root = make_repo({"ios/.xcode.env": "export NODE_BINARY=$(command -v node)\n"}, git=True, add=["ios/.xcode.env"])
    assert only(scan(root), "SLC005") == []


def test_from_call_in_file_without_supabase_is_ignored(make_repo):
    root = make_repo({
        "supabase/migrations/001.sql": "create table todos (id int);",
        "src/color.ts": "import tinycolor from 'tinycolor';\nconst c = colord.from('transparent');",
    })
    assert only(scan(root), "SLC006") == []


def test_from_call_in_background_jobs_is_server_side(make_repo):
    root = make_repo({
        "supabase/migrations/001.sql": "create table todos (id int);",
        "packages/jobs/src/sync.ts": "import { supabase } from './supabase';\nawait supabase.from('todos').select();",
    })
    assert only(scan(root), "SLC006") == []


def test_from_call_in_server_action_is_ignored(make_repo):
    root = make_repo({
        "supabase/migrations/001.sql": "create table todos (id int);",
        "app/actions/todos.ts": "'use server';\nimport { createClient } from '@/utils/supabase/server';\n"
                                "export async function f(s) { return s.from('todos').select(); }",
        "lib/admin.ts": "import 'server-only';\nconst supabase = admin();\nsupabase.from('todos').delete();",
    })
    assert only(scan(root), "SLC006") == []


def test_declarative_schemas_are_read_after_migrations(make_repo):
    root = make_repo({
        "supabase/migrations/001.sql": "create table todos (id int);",
        "supabase/schemas/01_todos.sql": "create table todos (id int); alter table todos enable row level security;",
    })
    res, _ = scan_path(root)
    assert res.sql_files == ["supabase/migrations/001.sql", "supabase/schemas/01_todos.sql"]
    assert only(res.findings, "SLC101") == []


def test_multiline_storage_from_with_crlf_is_not_a_table(make_repo):
    code = "const supabase = createClient();\r\nconst { error } = await supabase.storage\r\n            .from('audio')\r\n            .remove(paths);\r\n"
    root = make_repo({"supabase/migrations/001.sql": "create table todos (id int);", "src/player.tsx": code})
    assert only(scan(root), "SLC006") == []
