from pathlib import Path

from supa_launch_check.sql_scan import norm_ident, scan_sql_files, split_statements

FIX = Path(__file__).parent / "fixtures"


def _scan(name):
    root = FIX / name
    files = sorted((root / "supabase" / "migrations").glob("*.sql"))
    return scan_sql_files(files, root)


def _by(res, rule):
    return [f for f in res.findings if f.rule_id == rule]


# ---------------------------------------------------------------- parser
def test_split_handles_comments_strings_and_dollar_quotes():
    sql = """-- a comment; with semicolon
create table a (x text default 'a;b');
/* block ; comment */
create function f() returns int as $body$ select 1; select 2; $body$ language sql;
select 3"""
    stmts = split_statements(sql)
    assert len(stmts) == 3
    assert stmts[0].text.startswith("create table a")
    assert stmts[0].line == 2
    assert "select 2;" in stmts[1].text  # body kept in text
    assert "select 2" not in stmts[1].masked  # but blanked in masked
    assert stmts[1].line == 4
    assert stmts[2].text == "select 3"


def test_norm_ident():
    assert norm_ident("todos") == "public.todos"
    assert norm_ident("Public.Todos") == "public.todos"
    assert norm_ident('"public"."Orders"') == "public.Orders"
    assert norm_ident("private.audit") == "private.audit"


# ---------------------------------------------------------------- SLC101
def test_tables_without_rls():
    res = _scan("sql_vulnerable")
    tables = {f.extra["table"]: f for f in _by(res, "SLC101")}
    assert set(tables) == {"public.todos", "public.Orders", "public.notes"}
    assert all(f.severity == "critical" for f in tables.values())
    # line of the create statement, and the disabling migration for notes
    assert tables["public.todos"].line == 11
    assert tables["public.notes"].file.endswith("20240202000000_oops.sql")
    assert res.rls_enabled("profiles") is True
    assert res.rls_enabled("todos") is False
    assert res.rls_enabled("unknown_table") is None


def test_comments_temp_dropped_and_private_tables_ignored():
    res = _scan("sql_vulnerable")
    names = set(res.tables)
    assert "public.ghost_in_comment" not in names
    assert "public.ghost_in_block_comment" not in names
    assert "public.scratch" not in names
    assert "public.dropped_later" not in names
    assert not any(f.extra.get("table") == "private.audit_log" for f in res.findings)


# ---------------------------------------------------------------- SLC102
def test_open_policies_and_severities():
    res = _scan("sql_vulnerable")
    pol = {f.extra["policy"]: f.severity for f in _by(res, "SLC102")}
    assert pol == {
        "anyone can read profiles": "medium",
        "anyone can do anything": "critical",
        "anyone can insert": "high",
        "users read all": "low",
        "users update anything": "high",
    }


# ---------------------------------------------------------------- SLC103
def test_public_buckets():
    res = _scan("sql_vulnerable")
    buckets = sorted(f.extra["bucket"] for f in _by(res, "SLC103"))
    assert buckets == ["avatars", "invoices"]  # avatars on insert, invoices via update


# ---------------------------------------------------------------- SLC104
def test_security_definer_without_search_path():
    res = _scan("sql_vulnerable")
    funcs = {f.extra["function"]: f for f in _by(res, "SLC104")}
    assert set(funcs) == {"public.get_all_emails"}
    assert funcs["public.get_all_emails"].severity == "high"


# ---------------------------------------------------------------- SLC105
def test_views_without_security_invoker():
    res = _scan("sql_vulnerable")
    assert [f.extra["view"] for f in _by(res, "SLC105")] == ["public.profile_summary"]


def test_clean_migrations_have_no_findings():
    res = _scan("sql_clean")
    assert res.findings == []
    assert res.rls_enabled("posts") is True


def test_alter_table_rls_for_table_defined_elsewhere(tmp_path):
    p = tmp_path / "m.sql"
    p.write_text("alter table public.dash_table enable row level security;", encoding="utf-8")
    res = scan_sql_files([p], tmp_path)
    assert res.findings == []
    assert res.rls_enabled("dash_table") is True


def test_rename_keeps_rls_state(tmp_path):
    p = tmp_path / "m.sql"
    p.write_text(
        "create table public.a (id int);\nalter table public.a rename to b;\n"
        "alter table public.b enable row level security;",
        encoding="utf-8",
    )
    res = scan_sql_files([p], tmp_path)
    assert res.findings == []


def test_fix_text_is_filled_in_with_real_names():
    res = _scan("sql_vulnerable")
    fixes = {f.rule_id + ":" + str(f.extra.get("table") or f.extra.get("function") or f.extra.get("bucket")): f.fix
             for f in res.findings}
    assert "alter table public.todos enable row level security;" in fixes["SLC101:public.todos"]
    assert 'alter table public."Orders" enable row level security;' in fixes["SLC101:public.Orders"]
    assert "alter function public.get_all_emails() set search_path = '';" in fixes["SLC104:public.get_all_emails"]
    assert "where id = 'avatars'" in fixes["SLC103:avatars"]
    assert "<" not in fixes["SLC101:public.todos"]


def test_function_signature_drops_defaults(tmp_path):
    p = tmp_path / "m.sql"
    p.write_text(
        "create function public.f(a int default 1, b text = 'x', out c int)\n"
        "returns int language sql security definer as $$ select 1 $$;",
        encoding="utf-8",
    )
    [f] = scan_sql_files([p], tmp_path).findings
    assert f.extra["args"] == "a int, b text, out c int"
    assert "public.f(a int, b text, out c int)" in f.fix


# ---------------------------------------------------------------- later migrations fix things
def _scan_text(tmp_path, *sqls):
    paths = []
    for i, sql in enumerate(sqls):
        p = tmp_path / f"{i:03d}.sql"
        p.write_text(sql, encoding="utf-8")
        paths.append(p)
    return scan_sql_files(paths, tmp_path)


def test_dropped_open_policy_is_not_reported(tmp_path):
    res = _scan_text(
        tmp_path,
        'create table t (id int); alter table t enable row level security;\n'
        'create policy "open" on t for all using (true);',
        'drop policy if exists "open" on public.t;\n'
        'create policy "owner" on t for all using (auth.uid() = id);',
    )
    assert _by(res, "SLC102") == []


def test_recreated_open_policy_is_reported_once(tmp_path):
    res = _scan_text(
        tmp_path,
        'create policy "p" on t for update using (true);',
        'drop policy "p" on t; create policy "p" on t for update using (true);',
    )
    assert len(_by(res, "SLC102")) == 1


def test_dropping_table_drops_its_policy_findings(tmp_path):
    res = _scan_text(tmp_path, 'create policy "p" on t for delete using (true);', "drop table if exists t;")
    assert _by(res, "SLC102") == []


def test_service_role_only_policy_is_not_reported(tmp_path):
    res = _scan_text(
        tmp_path,
        'create policy "svc" on t for all to service_role using (true) with check (true);\n'
        'create policy "mixed" on t for all to authenticated, service_role using (true);',
    )
    [f] = _by(res, "SLC102")
    assert f.extra["policy"] == "mixed"


def test_dropped_security_definer_function_and_view(tmp_path):
    res = _scan_text(
        tmp_path,
        "create function public.f() returns int language sql security definer as $$ select 1 $$;\n"
        "create view public.v as select 1;",
        "drop function if exists public.f(); drop view if exists public.v;",
    )
    assert _by(res, "SLC104") == [] and _by(res, "SLC105") == []


def test_security_definer_trigger_function_is_low(tmp_path):
    res = _scan_text(
        tmp_path,
        "create function public.handle_new_user() returns trigger language plpgsql security definer "
        "as $$ begin insert into public.profiles(id) values (new.id); return new; end $$;",
    )
    [f] = _by(res, "SLC104")
    assert f.severity == "low" and "trigger" in f.message


def test_rls_enabled_in_do_block_loop(tmp_path):
    res = _scan_text(
        tmp_path,
        "create table public.a (id int); create table public.b (id int); create table public.c (id int);\n"
        "do $$ declare t text; begin\n"
        "  foreach t in array array['a', 'b'] loop\n"
        "    execute format('alter table public.%I enable row level security', t);\n"
        "  end loop;\n"
        "end $$;",
        "do $x$ begin if true then alter table public.c enable row level security; end if; end $x$;",
    )
    assert _by(res, "SLC101") == []


def test_do_block_without_rls_changes_nothing(tmp_path):
    res = _scan_text(
        tmp_path,
        "create table public.a (id int);\n"
        "do $$ begin perform 1 from unnest(array['a']); end $$;",
    )
    assert len(_by(res, "SLC101")) == 1


def test_quoted_trigger_return_type_is_low(tmp_path):
    res = _scan_text(
        tmp_path,
        'CREATE OR REPLACE FUNCTION "public"."handle_new_user"() RETURNS "trigger" LANGUAGE "plpgsql" '
        "SECURITY DEFINER AS $$ begin return new; end $$;",
    )
    [f] = _by(res, "SLC104")
    assert f.severity == "low"


def test_renamed_table_keeps_policy_and_replacement_supersedes_it(tmp_path):
    res = _scan_text(
        tmp_path,
        'create table "contactNotes" (id int); alter table "contactNotes" enable row level security;\n'
        'create policy "upd" on "contactNotes" for update to authenticated using (true);',
        'alter table "contactNotes" rename to contact_notes;',
        'create policy "upd" on contact_notes for update to authenticated using (true);',
    )
    [f] = _by(res, "SLC102")
    assert f.extra["table"] == "public.contact_notes"


def test_quoted_search_path_counts_as_set(tmp_path):
    res = _scan_text(
        tmp_path,
        'CREATE OR REPLACE FUNCTION "public"."is_admin"() RETURNS boolean LANGUAGE "plpgsql" SECURITY DEFINER '
        "SET \"search_path\" TO '' AS $$ begin return true; end $$;\n"
        'CREATE FUNCTION public.g() RETURNS int LANGUAGE sql SECURITY DEFINER AS $$ select 1 $$;\n'
        'ALTER FUNCTION "public"."g"() SET "search_path" TO \'\';',
    )
    assert _by(res, "SLC104") == []
