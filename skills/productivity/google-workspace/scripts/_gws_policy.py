#!/usr/bin/env python3
"""Shared Google Workspace OAuth policy: scope selection and secret-file permissions.

Two concerns live here because they must behave identically in every script of this
skill (``setup.py``, ``google_api.py``, ``gws_bridge.py``):

**Scope selection.** The set of Google scopes a deployment wants is *policy*, not a
hardcoded constant baked into one script.  Resolution order (first hit wins):

1. ``HERMES_GOOGLE_SCOPES`` environment variable (comma separated; entries may be
   service names such as ``calendar`` or full scope URLs).
2. A policy sidecar ``google_oauth_policy.json`` looked up next to the credential
   file, then next to ``HERMES_HOME``.  A sidecar (rather than a key inside
   ``google_token.json``) because ``google-auth`` rewrites the token file on every
   refresh and drops unknown keys — a policy stored inside the token would silently
   disappear.
3. :data:`DEFAULT_SCOPES` — the upstream default (all Workspace services), so a
   stock install behaves exactly as before.

The *same* resolved set is used for the OAuth consent request and for the
"missing scopes" report in ``--check``.  That symmetry is what keeps a deliberately
narrow grant (e.g. calendar only) from producing a permanent
``AUTHENTICATED (partial): missing 7 scopes`` warning in every other profile, and
what keeps a shared token from being refreshed with scopes it was never granted.

**Secret file permissions.** ``Path.write_text()`` creates files with
``0666 & ~umask``.  Under the common ``umask 022`` that is ``0644``
(world-readable); under this host's ``umask 002`` it is ``0664`` — also
world-readable.  A Google refresh token and the OAuth client secret are bearer
credentials, so every write goes through :func:`write_secret`, which forces
``0600``.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Sequence
from pathlib import Path

# The upstream default: every Google Workspace service this skill can drive.
DEFAULT_SCOPES: list[str] = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/contacts.readonly",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/documents",
]

# Named service groups accepted by ``--services`` and by the policy sidecar.
SERVICE_SCOPES: dict[str, list[str]] = {
    "email": [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/gmail.modify",
    ],
    "gmail": [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/gmail.modify",
    ],
    "calendar": ["https://www.googleapis.com/auth/calendar"],
    "drive": ["https://www.googleapis.com/auth/drive"],
    "contacts": ["https://www.googleapis.com/auth/contacts.readonly"],
    "sheets": ["https://www.googleapis.com/auth/spreadsheets"],
    "docs": ["https://www.googleapis.com/auth/documents"],
    "all": list(DEFAULT_SCOPES),
}

#: Name of the policy sidecar, stored next to the credential files.
POLICY_FILENAME = "google_oauth_policy.json"

#: Environment variable that overrides the sidecar.
SCOPES_ENV_VAR = "HERMES_GOOGLE_SCOPES"

#: Mode enforced on every credential file this skill writes.
SECRET_FILE_MODE = 0o600


def write_secret(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` and force ``0600`` permissions.

    ``write_text()`` alone leaves the file readable by every local user
    (``0644`` under ``umask 022``, ``0664`` under ``umask 002``), which exposes a
    live refresh token.  The chmod is best-effort: on a filesystem that refuses it
    the write still succeeds, but the caller should surface that rather than
    pretend the file is private.
    """
    path.write_text(text, encoding="utf-8")
    ensure_secret_mode(path)


def ensure_secret_mode(path: Path) -> bool:
    """Tighten an existing credential file to ``0600``.

    Returns ``True`` when the file ends up private, ``False`` when the
    filesystem refused the chmod.  Used both after writes and when an existing
    deployment is repaired in place.
    """
    try:
        os.chmod(path, SECRET_FILE_MODE)
    except OSError:
        return False
    return True


def _expand_scope_entry(entry: str) -> list[str]:
    """Map one policy entry to scope URLs.  Unknown names expand to nothing."""
    entry = entry.strip()
    if not entry:
        return []
    if entry.startswith("http://") or entry.startswith("https://"):
        return [entry]
    return list(SERVICE_SCOPES.get(entry.lower(), []))


def resolve_scopes_from_entries(entries: Iterable[str]) -> list[str]:
    """Expand policy entries (service names or scope URLs) to a scope list."""
    scopes: list[str] = []
    for entry in entries:
        for scope in _expand_scope_entry(entry):
            if scope not in scopes:
                scopes.append(scope)
    return scopes


def read_policy_sidecar(path: Path) -> list[str]:
    """Read the scope policy sidecar; return ``[]`` when absent or unusable."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    entries: list[str] = []
    raw_services = data.get("services")
    if isinstance(raw_services, list):
        entries.extend(str(s) for s in raw_services)
    raw_scopes = data.get("scopes")
    if isinstance(raw_scopes, list):
        entries.extend(str(s) for s in raw_scopes)
    return resolve_scopes_from_entries(entries)


def _is_fleet_root(resolved_dir: Path, hermes_home: Path) -> bool:
    """True when *resolved_dir* is the fleet-wide credential root.

    The shared-credential layout is ``<root>/google_token.json`` with one
    profile home per ``<root>/profiles/<name>``.  A profile's token symlink
    therefore resolves to a directory that *contains* its home.  That is the
    one legitimate escape, and it is recognised by shape rather than by trust.
    """
    try:
        parts = hermes_home.resolve().relative_to(resolved_dir).parts
    except (ValueError, OSError):
        return False
    return len(parts) >= 2 and parts[0] == "profiles"


def policy_candidates(token_path: Path, hermes_home: Path) -> list[Path]:
    """Policy sidecar locations to consult, most specific first.

    The policy lives beside the credential file, so a fleet that shares one
    token also shares one scope policy.  Resolution is *symlink-proof*: the
    resolved token directory is only accepted when it is inside ``hermes_home``
    or is a recognisable fleet root.  A symlink pointing anywhere else is
    refused, and the policy is then read from ``hermes_home`` alone — the same
    containment rule ``tools/credential_files.py`` applies to credentials.
    """
    candidates: list[Path] = []
    try:
        resolved_dir = token_path.resolve().parent
    except OSError:
        resolved_dir = None

    if resolved_dir is not None:
        inside_home = False
        try:
            resolved_dir.relative_to(hermes_home.resolve())
            inside_home = True
        except (ValueError, OSError):
            inside_home = False
        if inside_home or _is_fleet_root(resolved_dir, hermes_home):
            candidates.append(resolved_dir / POLICY_FILENAME)

    candidates.append(hermes_home / POLICY_FILENAME)

    unique: list[Path] = []
    for path in candidates:
        if path not in unique:
            unique.append(path)
    return unique


def policy_scopes(sidecar_paths: Sequence[Path]) -> list[str]:
    """Resolve the deployment's scope policy.

    Precedence: ``HERMES_GOOGLE_SCOPES`` > first readable sidecar > the upstream
    default.  ``sidecar_paths`` is ordered by priority (next to the credential
    file first, then ``HERMES_HOME``).
    """
    raw_env = os.environ.get(SCOPES_ENV_VAR, "").strip()
    if raw_env:
        scopes = resolve_scopes_from_entries(raw_env.replace(",", " ").split())
        if scopes:
            return scopes
    for path in sidecar_paths:
        scopes = read_policy_sidecar(path)
        if scopes:
            return scopes
    return list(DEFAULT_SCOPES)


def effective_scopes(sidecar_paths: Sequence[Path], services: str | None = None) -> list[str]:
    """Scopes to request in the OAuth consent screen.

    An explicit ``--services`` selection is a one-off override of the deployment
    policy; without it the policy sidecar decides.
    """
    if services and services.strip():
        requested = services.strip().lower()
        if requested == "all":
            return list(DEFAULT_SCOPES)
        scopes = resolve_scopes_from_entries(requested.replace(",", " ").split())
        if scopes:
            return scopes
    return policy_scopes(sidecar_paths)


def write_policy(path: Path, scopes: Sequence[str], services: str | None = None) -> None:
    """Persist the scope policy sidecar next to the credential files."""
    payload: dict[str, object] = {"scopes": list(scopes)}
    if services:
        payload["services"] = services
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def missing_scopes(granted: Iterable[str], required: Sequence[str]) -> list[str]:
    """Scopes in ``required`` that ``granted`` does not cover."""
    granted_set = {s for s in granted if s}
    return sorted(scope for scope in required if scope not in granted_set)


def granted_scopes_from_payload(payload: dict) -> list[str]:
    """Scopes a stored token actually carries, per the token file's own record."""
    raw = payload.get("scopes") or payload.get("scope")
    if not raw:
        return []
    if isinstance(raw, str):
        raw = raw.split()
    return [s.strip() for s in raw if str(s).strip()]
