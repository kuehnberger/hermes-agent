"""Credential-file permissions and scope policy for the Google Workspace skill.

Two invariants are pinned here:

**Permissions.** Every credential file the skill writes (OAuth token, client
secret, pending OAuth session, last auth URL) must end up mode 0600.  The
ambient umask is not enough: under ``umask 022`` a plain ``write_text()`` leaves
the refresh token world-readable, and under this host's ``umask 002`` it leaves
it group- and world-readable.

**Scope policy.** A reduced-scope token must never be refreshed with the global
eight-scope request set, and the "missing scopes" report must be measured
against the deployment's policy rather than the global default — otherwise a
deliberately calendar-only grant reports "missing 7 scopes" forever in every
profile that shares the token.
"""

from __future__ import annotations

import importlib.util
import json
import os
import stat
from pathlib import Path

import pytest


SCRIPTS_DIR = (
    Path(__file__).resolve().parents[2]
    / "skills/productivity/google-workspace/scripts"
)
SETUP_PATH = SCRIPTS_DIR / "setup.py"
GOOGLE_API_PATH = SCRIPTS_DIR / "google_api.py"
GWS_BRIDGE_PATH = SCRIPTS_DIR / "gws_bridge.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# --------------------------------------------------------------------------- #
# Permissions
# --------------------------------------------------------------------------- #


def test_client_secret_is_written_private(monkeypatch, tmp_path):
    setup = _load(SETUP_PATH, "gws_setup_client_secret")
    target = tmp_path / "google_client_secret.json"
    monkeypatch.setattr(setup, "CLIENT_SECRET_PATH", target)

    source = tmp_path / "client_secret.json"
    source.write_text(json.dumps({"installed": {"client_id": "x", "client_secret": "y"}}))

    setup.store_client_secret(str(source))

    assert target.exists()
    assert _mode(target) == 0o600


def test_pending_oauth_session_is_written_private(monkeypatch, tmp_path):
    """The PKCE code_verifier is a secret; the pending file must be private."""
    setup = _load(SETUP_PATH, "gws_setup_pending")
    target = tmp_path / "google_oauth_pending.json"
    monkeypatch.setattr(setup, "PENDING_AUTH_PATH", target)

    setup._save_pending_auth(state="st", code_verifier="cv", scopes=[])

    assert _mode(target) == 0o600
    assert json.loads(target.read_text())["code_verifier"] == "cv"


def test_token_exchange_writes_token_private(monkeypatch, tmp_path):
    """The exchange path must persist the token 0600, not rely on the umask."""
    setup = _load(SETUP_PATH, "gws_setup_exchange")
    token = tmp_path / "google_token.json"
    policy = tmp_path / "google_oauth_policy.json"
    client_secret = tmp_path / "google_client_secret.json"
    client_secret.write_text(json.dumps({"installed": {"client_id": "c", "client_secret": "s"}}))
    monkeypatch.setattr(setup, "TOKEN_PATH", token)
    monkeypatch.setattr(setup, "PENDING_AUTH_PATH", tmp_path / "google_oauth_pending.json")
    monkeypatch.setattr(setup, "CLIENT_SECRET_PATH", client_secret)
    monkeypatch.setattr(setup, "_policy_candidates", lambda: [policy])
    monkeypatch.setattr(setup, "_policy_sidecar_path", lambda: policy)

    class _Creds:
        granted_scopes = ["https://www.googleapis.com/auth/calendar"]
        expired = False
        valid = True

        def to_json(self):
            return json.dumps(
                {
                    "type": "authorized_user",
                    "token": "t",
                    "refresh_token": "r",
                    "client_id": "c",
                    "client_secret": "s",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            )

    class _Flow:
        credentials = _Creds()

        def fetch_token(self, code):
            return None

        @classmethod
        def from_client_secrets_file(cls, *a, **k):
            return cls()

    monkeypatch.setattr(setup, "_ensure_deps", lambda: None)
    monkeypatch.setattr(setup, "_load_pending_auth", lambda: {
        "state": "st", "code_verifier": "cv", "scopes": ["https://www.googleapis.com/auth/calendar"]
    })
    monkeypatch.setattr("google_auth_oauthlib.flow.Flow", _Flow)

    setup.exchange_auth_code("code")

    assert token.exists()
    assert _mode(token) == 0o600


def test_google_api_refresh_keeps_token_private(monkeypatch, tmp_path):
    """A token rewritten by the refresh path must not become world-readable."""
    google_api = _load(GOOGLE_API_PATH, "gws_google_api_perm")
    token = tmp_path / "google_token.json"
    monkeypatch.setattr(google_api, "TOKEN_PATH", token)

    # A token with no "scopes" key: the refresh path must not invent the global set.
    token.write_text(
        json.dumps(
            {
                "type": "authorized_user",
                "token": "old",
                "expiry": "2000-01-01T00:00:00+00:00",
                "refresh_token": "r",
                "client_id": "c",
                "client_secret": "s",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        )
    )

    class _Creds:
        expired = True
        valid = True
        refresh_token = "r"

        def refresh(self, request):
            return None

        def to_json(self):
            return json.dumps({"type": "authorized_user", "token": "new", "refresh_token": "r"})

    import google.oauth2.credentials as creds_mod

    monkeypatch.setattr(
        creds_mod.Credentials, "from_authorized_user_file", staticmethod(lambda *a, **k: _Creds())
    )

    google_api.get_credentials()

    assert _mode(token) == 0o600


def test_gws_bridge_refresh_keeps_token_private(monkeypatch, tmp_path):
    """The gws bridge writes the token too — it must be private as well."""
    bridge = _load(GWS_BRIDGE_PATH, "gws_bridge_perm")
    token = tmp_path / "google_token.json"
    monkeypatch.setattr(bridge, "get_token_path", lambda: token)

    token_data = {
        "type": "authorized_user",
        "client_id": "c",
        "client_secret": "s",
        "refresh_token": "r",
        "token_uri": "https://oauth2.googleapis.com/token",
    }

    class _Resp:
        def read(self):
            return json.dumps({"access_token": "at", "expires_in": 3600}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Resp())

    bridge.refresh_token(dict(token_data))

    assert _mode(token) == 0o600


def test_write_secret_forces_mode_even_under_permissive_umask(monkeypatch, tmp_path):
    """The 0600 guarantee must not depend on the process umask."""
    policy = _load(SCRIPTS_DIR / "_gws_policy.py", "gws_policy_umask")
    target = tmp_path / "secret.json"

    old = os.umask(0o000)
    try:
        policy.write_secret(target, "payload")
    finally:
        os.umask(old)

    assert _mode(target) == 0o600


# --------------------------------------------------------------------------- #
# Scope policy
# --------------------------------------------------------------------------- #


def test_policy_defaults_to_full_scope_set(tmp_path):
    policy = _load(SCRIPTS_DIR / "_gws_policy.py", "gws_policy_default")
    monkey = os.environ.pop(policy.SCOPES_ENV_VAR, None)
    try:
        assert policy.policy_scopes([tmp_path / "absent.json"]) == policy.DEFAULT_SCOPES
    finally:
        if monkey is not None:
            os.environ[policy.SCOPES_ENV_VAR] = monkey


def test_policy_sidecar_overrides_default(tmp_path):
    policy = _load(SCRIPTS_DIR / "_gws_policy.py", "gws_policy_sidecar")
    sidecar = tmp_path / policy.POLICY_FILENAME
    sidecar.write_text(json.dumps({"services": ["calendar"]}))

    monkey = os.environ.pop(policy.SCOPES_ENV_VAR, None)
    try:
        resolved = policy.policy_scopes([sidecar])
    finally:
        if monkey is not None:
            os.environ[policy.SCOPES_ENV_VAR] = monkey

    assert resolved == ["https://www.googleapis.com/auth/calendar"]


def test_policy_env_overrides_sidecar(tmp_path, monkeypatch):
    policy = _load(SCRIPTS_DIR / "_gws_policy.py", "gws_policy_env")
    sidecar = tmp_path / policy.POLICY_FILENAME
    sidecar.write_text(json.dumps({"services": ["calendar"]}))
    monkeypatch.setenv(policy.SCOPES_ENV_VAR, "docs,sheets")

    resolved = policy.policy_scopes([sidecar])

    assert "https://www.googleapis.com/auth/documents" in resolved
    assert "https://www.googleapis.com/auth/spreadsheets" in resolved
    assert "https://www.googleapis.com/auth/calendar" not in resolved


def test_effective_scopes_honours_services_override(tmp_path):
    policy = _load(SCRIPTS_DIR / "_gws_policy.py", "gws_policy_effective")
    sidecar = tmp_path / policy.POLICY_FILENAME
    sidecar.write_text(json.dumps({"services": ["calendar"]}))

    resolved = policy.effective_scopes([sidecar], "email,calendar")

    assert "https://www.googleapis.com/auth/gmail.send" in resolved
    assert "https://www.googleapis.com/auth/calendar" in resolved
    assert "https://www.googleapis.com/auth/drive" not in resolved


def test_effective_scopes_all_returns_default_set(tmp_path):
    policy = _load(SCRIPTS_DIR / "_gws_policy.py", "gws_policy_all")
    resolved = policy.effective_scopes([tmp_path / "absent.json"], "all")
    assert resolved == policy.DEFAULT_SCOPES


def test_reduced_scope_token_is_not_reported_as_missing_scopes(monkeypatch, tmp_path):
    """A calendar-only token under a calendar-only policy is complete.

    This is the fleet case: research consented with calendar only, and every
    other profile sharing that token used to report
    "AUTHENTICATED (partial): missing 7 scopes" forever.
    """
    setup = _load(SETUP_PATH, "gws_setup_partial")
    policy_file = tmp_path / "google_oauth_policy.json"
    policy_file.write_text(json.dumps({"scopes": ["https://www.googleapis.com/auth/calendar"]}))
    monkeypatch.setattr(setup, "_policy_candidates", lambda: [policy_file])

    payload = {"scopes": ["https://www.googleapis.com/auth/calendar"]}

    assert setup._missing_scopes_from_payload(payload) == []


def test_missing_scopes_still_reported_against_policy(monkeypatch, tmp_path):
    """A token that lacks what the policy demands must still be flagged."""
    setup = _load(SETUP_PATH, "gws_setup_missing")
    policy_file = tmp_path / "google_oauth_policy.json"
    policy_file.write_text(
        json.dumps({"scopes": ["https://www.googleapis.com/auth/calendar",
                               "https://www.googleapis.com/auth/drive"]})
    )
    monkeypatch.setattr(setup, "_policy_candidates", lambda: [policy_file])

    payload = {"scopes": ["https://www.googleapis.com/auth/calendar"]}

    assert setup._missing_scopes_from_payload(payload) == [
        "https://www.googleapis.com/auth/drive"
    ]


def test_stored_token_scopes_are_not_widened_to_global_default(monkeypatch, tmp_path):
    """google_api must refresh with the token's own scopes, never the global set.

    Widening makes google-auth request scopes the grant never had; Google then
    answers ``invalid_scope`` and every API call breaks.
    """
    google_api = _load(GOOGLE_API_PATH, "gws_google_api_scopes")
    token = tmp_path / "google_token.json"

    token.write_text(json.dumps({"scopes": ["https://www.googleapis.com/auth/calendar"]}))
    monkeypatch.setattr(google_api, "TOKEN_PATH", token)
    assert google_api._stored_token_scopes() == ["https://www.googleapis.com/auth/calendar"]

    # A token that records nothing must not cause the global set to be sent.
    token.write_text(json.dumps({"refresh_token": "r"}))
    assert google_api._stored_token_scopes() is None


def test_revoke_uses_stored_scopes_not_global_default(monkeypatch, tmp_path):
    """revoke() must not request the global scope set for a narrowed token."""
    setup = _load(SETUP_PATH, "gws_setup_revoke")
    token = tmp_path / "google_token.json"
    token.write_text(json.dumps({"scopes": ["https://www.googleapis.com/auth/calendar"]}))
    monkeypatch.setattr(setup, "TOKEN_PATH", token)
    monkeypatch.setattr(setup, "_ensure_deps", lambda: None)

    seen: dict = {}

    class _Creds:
        expired = False
        refresh_token = "r"
        token = "at"

    def _from_file(path, scopes=None):
        seen["scopes"] = scopes
        return _Creds()

    import google.oauth2.credentials as creds_mod

    monkeypatch.setattr(
        creds_mod.Credentials, "from_authorized_user_file", staticmethod(_from_file)
    )

    import urllib.request

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Resp())

    setup.revoke()

    assert seen["scopes"] == ["https://www.googleapis.com/auth/calendar"]


def test_policy_resolution_follows_fleet_root_symlink(tmp_path):
    """A profile whose token symlinks at the fleet root finds the shared policy.

    Layout: <root>/google_token.json, <root>/profiles/<name>/google_token.json
    -> <root>/google_token.json.
    """
    policy = _load(SCRIPTS_DIR / "_gws_policy.py", "gws_policy_fleet")

    root = tmp_path / "hermes"
    profile = root / "profiles" / "research"
    profile.mkdir(parents=True)
    (root / "google_token.json").write_text("{}")
    (profile / "google_token.json").symlink_to(root / "google_token.json")

    candidates = policy.policy_candidates(profile / "google_token.json", profile)

    assert candidates[0] == root / policy.POLICY_FILENAME


def test_policy_resolution_refuses_symlink_escaping_fleet_root(tmp_path):
    """A token symlink pointing anywhere else must not widen policy lookup.

    This is the symlink-proof requirement: the policy may only be read from
    the profile home, or from a directory shaped like the fleet credential
    root.  Anything else (e.g. /etc, a temp dir) is refused.
    """
    policy = _load(SCRIPTS_DIR / "_gws_policy.py", "gws_policy_escape")

    profile = tmp_path / "hermes" / "profiles" / "research"
    profile.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (profile / "google_token.json").symlink_to(outside / "google_token.json")

    candidates = policy.policy_candidates(profile / "google_token.json", profile)

    assert candidates == [profile / policy.POLICY_FILENAME]


def test_policy_resolution_accepts_token_inside_profile_home(tmp_path):
    """A standalone profile (token in its own home) resolves locally."""
    policy = _load(SCRIPTS_DIR / "_gws_policy.py", "gws_policy_standalone")

    profile = tmp_path / "hermes"
    profile.mkdir()
    (profile / "google_token.json").write_text("{}")

    candidates = policy.policy_candidates(profile / "google_token.json", profile)

    assert candidates[0] == profile / policy.POLICY_FILENAME


def test_setup_exposes_documented_services_and_format_flags():
    """The bundled SKILL.md documents --services and --format; they must parse."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, str(SETUP_PATH), "--auth-url", "--services", "email,calendar",
         "--format", "json"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={**os.environ, "HERMES_HOME": str(SCRIPTS_DIR.parent)},
    )
    # Either it parses (and then fails later for a missing client secret) or it
    # does not — but it must never fail with an argparse "unrecognized arguments".
    assert "unrecognized arguments" not in result.stderr
