"""Shared helpers. Fake secrets are assembled at runtime so that no secret-shaped
string is ever committed to this repository (keeps secret scanners quiet)."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def _b64(obj) -> str:
    raw = obj if isinstance(obj, bytes) else json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def fake_jwt(role: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"iss": "supabase", "ref": "abcdefghijklmnopqrst", "role": role, "iat": 1700000000, "exp": 2000000000}
    return f"{_b64(header)}.{_b64(payload)}.{_b64(b'not-a-real-signature-just-test-bytes')}"


FAKE = {
    "service_jwt": fake_jwt("service_role"),
    "anon_jwt": fake_jwt("anon"),
    "sb_secret": "sb_" + "secret_" + "Fak3K3yF0rT3st1ngOnly_abcdef",
    "sb_publishable": "sb_" + "publishable_" + "Fak3PublishableKey_abcdef",
    "stripe_live": "sk_" + "live_" + "FAKEFAKEFAKE0123456789abcd",
    "stripe_test": "sk_" + "test_" + "FAKEFAKEFAKE0123456789abcd",
    "openai": "sk-" + "proj-" + "FAKEfakeFAKEfake0123456789abcdefABCDEF",
    "anthropic": "sk-" + "ant-" + "api03-FAKEfakeFAKEfake0123456789abcdef",
    "aws": "AKIA" + "FAKE0123456789AB",
    "github": "ghp" + "_" + "FAKEfakeFAKEfake0123456789abcdefABCD",
    "private_key": "-----BEGIN " + "RSA PRIVATE KEY-----",
}


@pytest.fixture
def fake():
    return FAKE


@pytest.fixture
def make_repo(tmp_path):
    """make_repo({"rel/path": "content", ...}, git=False) -> Path"""

    def _make(files: dict[str, str | bytes], *, git: bool = False, add: list[str] | None = None) -> Path:
        root = tmp_path / "repo"
        root.mkdir(exist_ok=True)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                p.write_bytes(content)
            else:
                p.write_text(content, encoding="utf-8")
        if git:
            if shutil.which("git") is None:
                pytest.skip("git not installed")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            if add:
                subprocess.run(["git", "-C", str(root), "add", "-f", *add], check=True)
        return root

    return _make


@pytest.fixture
def copy_fixture(tmp_path):
    def _copy(name: str) -> Path:
        dst = tmp_path / name
        shutil.copytree(FIXTURES / name, dst)
        return dst

    return _copy
