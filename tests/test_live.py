import io
import json
import urllib.error

import pytest

from supa_launch_check.live import LiveCheckError, run_live_check, validate_key, validate_url

URL = "https://abcdefghijklmnopqrst.supabase.co"


class FakeResp:
    def __init__(self, status, body):
        self.status = status
        self._body = body if isinstance(body, bytes) else json.dumps(body).encode()

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def make_opener(spec, tables):
    calls = []

    def opener(req, timeout):
        calls.append(req)
        path = req.full_url[len(URL):]
        if path == "/rest/v1/":
            return FakeResp(200, spec)
        name = path.split("/rest/v1/", 1)[1].split("?", 1)[0]
        status, body = tables[name]
        if status >= 400:
            raise urllib.error.HTTPError(req.full_url, status, "err", {}, io.BytesIO(b"{}"))
        return FakeResp(status, body)

    return opener, calls


SPEC = {"paths": {"/": {}, "/todos": {}, "/profiles": {}, "/secrets": {}, "/rpc/get_all_emails": {}}}
TABLES = {
    "todos": (200, [{"id": 1, "title": "private stuff"}]),
    "profiles": (200, []),
    "secrets": (401, None),
}


def test_reports_anon_readable_tables_and_rpc(fake):
    opener, calls = make_opener(SPEC, TABLES)
    sleeps = []
    res = run_live_check(URL, fake["anon_jwt"], opener=opener, sleep=sleeps.append, delay=0.5)
    by = {t.table: t for t in res.tables}
    assert by["todos"].rows_visible and not by["profiles"].rows_visible
    assert "permission denied" in by["secrets"].note
    rules = sorted((f.rule_id, f.severity) for f in res.findings)
    assert rules == [("SLC201", "high"), ("SLC202", "low")]
    assert res.findings[0].extra["table"] == "todos"
    # never leaks row contents
    assert "private stuff" not in json.dumps([f.to_dict() for f in res.findings])
    # read-only, rate-limited, never calls RPC
    assert all(r.get_method() == "GET" for r in calls)
    assert not any("/rpc/" in r.full_url for r in calls)
    assert all("limit=1" in r.full_url for r in calls[1:])
    assert len(calls) == 4 and res.requests_made == 4
    assert sleeps == [0.5, 0.5, 0.5]
    assert calls[0].get_header("Authorization") == f"Bearer {fake['anon_jwt']}"


def test_publishable_key_sends_no_bearer(fake):
    opener, calls = make_opener({"paths": {}}, {})
    run_live_check(URL, fake["sb_publishable"], opener=opener, sleep=lambda s: None)
    assert calls[0].get_header("Authorization") is None
    assert calls[0].get_header("Apikey") == fake["sb_publishable"]


def test_max_tables_truncates(fake):
    spec = {"paths": {f"/t{i}": {} for i in range(10)}}
    opener, calls = make_opener(spec, {f"t{i}": (200, []) for i in range(10)})
    res = run_live_check(URL, fake["anon_jwt"], opener=opener, sleep=lambda s: None, max_tables=3)
    assert res.truncated and len(res.tables) == 3 and len(calls) == 4


@pytest.mark.parametrize("key", ["service_jwt", "sb_secret"])
def test_refuses_secret_keys(fake, key):
    with pytest.raises(LiveCheckError):
        validate_key(fake[key])


def test_refuses_garbage_key():
    with pytest.raises(LiveCheckError):
        validate_key("hello")


@pytest.mark.parametrize("url,ok", [
    ("https://x.supabase.co", True),
    ("https://x.supabase.co/", True),
    ("http://localhost:54321", True),
    ("http://x.supabase.co", False),
    ("ftp://x", False),
    ("https://x.supabase.co/rest/v1", False),
])
def test_validate_url(url, ok):
    if ok:
        assert validate_url(url)
    else:
        with pytest.raises(LiveCheckError):
            validate_url(url)


def test_schema_unreadable_raises(fake):
    def opener(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 401, "no", {}, io.BytesIO(b""))

    with pytest.raises(LiveCheckError, match="HTTP 401"):
        run_live_check(URL, fake["anon_jwt"], opener=opener, sleep=lambda s: None)
