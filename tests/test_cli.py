import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from supa_launch_check.cli import main
from supa_launch_check.findings import RULES

FIX = Path(__file__).parent / "fixtures"


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


# ---------------------------------------------------------------- scan
def test_scan_vulnerable_exits_1_with_text_report(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "sql_vulnerable"), "--no-color")
    assert code == 1
    assert "CRITICAL" in out and "SLC101" in out and "enable row level security" in out
    assert "20240101000000_init.sql:11" in out
    assert "Exit code: 1" in out


def test_scan_clean_exits_0(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "sql_clean"))
    assert code == 0
    assert "No findings" in out


def test_scan_json(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "sql_vulnerable"), "--json")
    doc = json.loads(out)
    assert code == 1 and doc["exit_code"] == 1 and doc["mode"] == "scan"
    assert doc["summary"]["critical"] >= 3
    first = doc["findings"][0]
    assert first["severity"] == "critical"
    assert {"rule_id", "file", "line", "why", "fix", "title"} <= set(first)


def test_fail_on_and_min_severity(capsys):
    code, _, _ = run(capsys, "scan", str(FIX / "sql_vulnerable"), "--fail-on", "never")
    assert code == 0
    code, out, _ = run(capsys, "scan", str(FIX / "sql_vulnerable"), "--json", "--min-severity", "critical")
    assert {f["severity"] for f in json.loads(out)["findings"]} == {"critical"}


def test_scan_output_never_contains_full_secret(capsys, make_repo, fake):
    root = make_repo({"src/a.ts": f"const k = '{fake['service_jwt']}'"})
    code, out, _ = run(capsys, "scan", str(root), "--json")
    assert code == 1
    assert fake["service_jwt"] not in out


def test_scan_missing_dir(capsys, tmp_path):
    code, _, err = run(capsys, "scan", str(tmp_path / "nope"))
    assert code == 2 and "not a directory" in err


def test_rules_lists_every_rule(capsys):
    code, out, _ = run(capsys, "rules")
    assert code == 0
    for rid in RULES:
        assert rid in out


# ---------------------------------------------------------------- live (owner gate)
def test_live_requires_owner_flag(capsys, fake):
    code, _, err = run(capsys, "live", "--url", "https://x.supabase.co", "--anon-key", fake["anon_jwt"], "--yes")
    assert code == 2 and "--i-own-this-project" in err


def test_live_requires_tty_or_yes(capsys, fake, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    code, _, err = run(capsys, "live", "--url", "https://x.supabase.co", "--anon-key", fake["anon_jwt"],
                       "--i-own-this-project")
    assert code == 2 and "--yes" in err


def test_live_refuses_service_key(capsys, fake):
    code, _, err = run(capsys, "live", "--url", "https://x.supabase.co", "--anon-key", fake["service_jwt"],
                       "--i-own-this-project", "--yes")
    assert code == 2 and "anon key" in err


@pytest.fixture
def fake_postgrest():
    """A tiny local PostgREST lookalike that records every request it receives."""
    seen = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, status, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            seen.append(("GET", self.path, self.headers.get("apikey")))
            if self.path == "/rest/v1/":
                return self._send(200, {"paths": {"/": {}, "/orders": {}, "/profiles": {}, "/rpc/do_thing": {}}})
            if self.path.startswith("/rest/v1/orders"):
                return self._send(200, [{"id": 1, "card_last4": "4242"}])
            if self.path.startswith("/rest/v1/profiles"):
                return self._send(200, [])
            self._send(404, {})

        def do_POST(self):  # pragma: no cover - must never be hit
            seen.append(("POST", self.path, None))
            self._send(405, {})

        do_PATCH = do_DELETE = do_PUT = do_POST

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", seen
    srv.shutdown()


def test_live_end_to_end_against_local_server(capsys, fake, fake_postgrest):
    url, seen = fake_postgrest
    code, out, _ = run(capsys, "live", "--url", url, "--anon-key", fake["anon_jwt"],
                       "--i-own-this-project", "--yes", "--delay", "0", "--json")
    doc = json.loads(out)
    assert code == 1
    assert [f["rule_id"] for f in doc["findings"]] == ["SLC201", "SLC202"]
    assert doc["findings"][0]["extra"]["table"] == "orders"
    assert "4242" not in out
    assert {m for m, _, _ in seen} == {"GET"}
    assert len(seen) == 3 and doc["requests_made"] == 3
