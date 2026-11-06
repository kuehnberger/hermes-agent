#!/usr/bin/env python3
"""Google Workspace OAuth2 setup for Hermes Agent.

Fully non-interactive — designed to be driven by the agent via terminal commands.
The agent mediates between this script and the user (works on CLI, Telegram, Discord, etc.)

Commands:
  setup.py --check                          # Is auth valid? Exit 0 = yes, 1 = no
  setup.py --client-secret /path/to.json    # Store OAuth client credentials
  setup.py --auth-url [--services S]        # Print the OAuth URL for user to visit
  setup.py --auth-code CODE                 # Exchange auth code for token
  setup.py --revoke                         # Revoke and delete stored token
  setup.py --install-deps                   # Install Python dependencies only

Agent workflow:
  1. Run --check. If exit 0, auth is good — skip setup.
  2. Ask user for client_secret.json path. Run --client-secret PATH.
  3. Run --auth-url. Send the printed URL to the user.
  4. User opens URL, authorizes, gets redirected to a page with a code.
  5. User pastes the code. Agent runs --auth-code CODE.
  6. Run --check to verify. Done.

Scope policy
-------------
The Google scopes this deployment expects are *policy*, not a hardcoded constant.
They are resolved (first hit wins) from:

1. ``--services`` on the command line (one-off override of the consent request).
2. ``HERMES_GOOGLE_SCOPES`` in the environment.
3. The policy sidecar ``google_oauth_policy.json``, looked up next to the token
   file and then next to HERMES_HOME.  It lives beside the credential rather
   than inside it because ``google-auth`` rewrites ``google_token.json`` on every
   refresh and drops any key it does not know.
4. The default full Workspace scope set.

The same resolved set drives the consent request *and* the "missing scopes"
report, so a deliberately narrowed grant (calendar only) does not produce a
permanent "AUTHENTICATED (partial): missing 7 scopes" warning in every other
profile that shares the token.

Credential files (token, client secret, pending OAuth session, last auth URL)
are always written with mode 0600 — the ambient umask alone would leave a live
refresh token world-readable.
"""

from __future__ import annotations  # allow PEP 604 `X | None` on Python 3.9+

import argparse
import json
import os
import sys
from pathlib import Path

try:
    import pm
except ImportError:
    # A copied skill must not install into an unrelated Python environment.
    pm = None

# Ensure sibling modules (_hermes_home, _gws_policy) are importable when run standalone.
_SCRIPTS_DIR = str(Path(__file__).resolve().parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from _gws_policy import (
    DEFAULT_SCOPES,
    POLICY_FILENAME,
    granted_scopes_from_payload,
    missing_scopes,
    policy_candidates,
    policy_scopes,
    write_policy,
    write_secret,
)
from _hermes_home import display_hermes_home, get_hermes_home

HERMES_HOME = get_hermes_home()
TOKEN_PATH = HERMES_HOME / "google_token.json"
CLIENT_SECRET_PATH = HERMES_HOME / "google_client_secret.json"
PENDING_AUTH_PATH = HERMES_HOME / "google_oauth_pending.json"
LAST_AUTH_URL_PATH = HERMES_HOME / "google_oauth_last_url.txt"

# The default (unconstrained) Workspace scope set.  Kept under the historical
# name because other scripts in this skill import it.
SCOPES = list(DEFAULT_SCOPES)

# OAuth redirect for "out of band" manual code copy flow.
# Google deprecated OOB, so we use a localhost redirect and tell the user to
# copy the code from the browser's URL bar (or the page body).
REDIRECT_URI = "http://localhost:1"


# --------------------------------------------------------------------------- #
# Scope policy
# --------------------------------------------------------------------------- #


def _policy_candidates() -> list[Path]:
    """Policy sidecar locations, most specific first.

    The sidecar is looked up next to the *resolved* token file so that every
    profile sharing one token also shares one scope policy — the fleet layout
    symlinks each profile's ``google_token.json`` at a common file, and the
    policy has to travel with it.  Resolution is symlink-proof: a token
    symlink pointing outside the recognised fleet root is not followed.
    """
    return policy_candidates(TOKEN_PATH, HERMES_HOME)


def _policy_sidecar_path() -> Path:
    """Where a policy sidecar is written (next to the resolved token file)."""
    candidates = _policy_candidates()
    return candidates[0] if candidates else HERMES_HOME / POLICY_FILENAME


def _required_scopes() -> list[str]:
    """Scopes this deployment expects the token to carry."""
    return policy_scopes(_policy_candidates())


def _normalize_authorized_user_payload(payload: dict) -> dict:
    normalized = dict(payload)
    if not normalized.get("type"):
        normalized["type"] = "authorized_user"
    return normalized


def _load_token_payload(path: Path = TOKEN_PATH) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _missing_scopes_from_payload(payload: dict, required: list[str] | None = None) -> list[str]:
    """Required scopes the stored token does not actually carry."""
    required = _required_scopes() if required is None else required
    granted = granted_scopes_from_payload(payload)
    if not granted:
        # Nothing recorded — do not accuse the token of missing anything.
        return []
    return missing_scopes(granted, required)


def _format_missing_scopes(missing: list[str]) -> str:
    bullets = "\n".join(f"  - {scope}" for scope in missing)
    return (
        "Token is valid but missing required Google Workspace scopes:\n"
        f"{bullets}\n"
        "Run the Google Workspace setup again from this same Hermes profile to refresh consent."
    )


def _emit(payload: dict, fmt: str) -> None:
    """Print a result either as JSON or as a human-readable block."""
    if fmt == "json":
        print(json.dumps(payload, indent=2))
        return
    for key, value in payload.items():
        if value is None:
            continue
        if isinstance(value, list):
            for item in value:
                print(f"{key}: {item}")
        else:
            print(f"{key}: {value}")


# --------------------------------------------------------------------------- #
# Dependencies
# --------------------------------------------------------------------------- #


def install_deps():
    """Sync Hermes' declared Google extra, ready for the next process."""
    if pm is None:
        print("ERROR: Run this script in the Hermes environment; use hermes setup first.")
        return False
    try:
        pm.sync_venv(["google"], explicit=True)
    except Exception as exc:
        print(f"ERROR: Failed to install Google dependencies: {exc}")
        return False
    print("Google dependencies synced. Restart Hermes, then rerun setup to continue OAuth.")
    return True


def _ensure_deps():
    """Let PM check imports and stop if activation needs a new process."""
    if pm is None:
        print("ERROR: Run this script in the Hermes environment; use hermes setup first.")
        sys.exit(1)
    try:
        pm.ensure_import("google")
    except Exception as exc:
        print(f"ERROR: Google dependencies unavailable: {exc}")
        sys.exit(1)


# --------------------------------------------------------------------------- #
# Status
# --------------------------------------------------------------------------- #


def check_auth_live():
    """Check auth with a real API call to detect disabled_client/account issues."""
    # quiet=True suppresses the "AUTHENTICATED" print from check_auth so the
    # final status line reflects the live-call outcome (OK or FAILED).
    if not check_auth(quiet=True):
        return False
    try:
        from googleapiclient.discovery import build
        from google.oauth2.credentials import Credentials
        creds = Credentials.from_authorized_user_file(str(TOKEN_PATH))
        service = build("calendar", "v3", credentials=creds)
        service.calendarList().list(maxResults=1).execute()
        print("LIVE_CHECK_OK: Real API call succeeded.")
        return True
    except Exception as e:
        err_str = str(e).lower()
        if "disabled_client" in err_str or "invalid_client" in err_str:
            print(f"LIVE_CHECK_FAILED: OAuth client or account disabled: {e}")
            print("  1. Check Google Cloud Console for disabled OAuth client")
            print("  2. Check myaccount.google.com for account status")
            print("  3. Do NOT retry with a disabled account")
        else:
            print(f"LIVE_CHECK_FAILED: {e}")
        return False


def check_auth(quiet: bool = False):
    """Check if stored credentials are valid. Prints status, exits 0 or 1."""
    if not TOKEN_PATH.exists():
        print(f"NOT_AUTHENTICATED: No token at {TOKEN_PATH}")
        return False

    _ensure_deps()
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request

    try:
        # Don't pass scopes — user may have authorized only a subset.
        # Passing scopes forces google-auth to validate them on refresh,
        # which fails with invalid_scope if the token has fewer scopes
        # than requested.
        creds = Credentials.from_authorized_user_file(str(TOKEN_PATH))
    except Exception as e:
        print(f"TOKEN_CORRUPT: {e}")
        return False

    payload = _load_token_payload(TOKEN_PATH)
    if creds.valid:
        missing = _missing_scopes_from_payload(payload)
        if missing:
            print(f"AUTHENTICATED (partial): Token valid but missing {len(missing)} scopes:")
            for s in missing:
                print(f"  - {s}")
        if not quiet:
            print(f"AUTHENTICATED: Token valid at {TOKEN_PATH}")
        return True

    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            write_secret(
                TOKEN_PATH,
                json.dumps(
                    _normalize_authorized_user_payload(json.loads(creds.to_json())),
                    indent=2,
                ),
            )
            missing = _missing_scopes_from_payload(_load_token_payload(TOKEN_PATH))
            if missing:
                print(f"AUTHENTICATED (partial): Token refreshed but missing {len(missing)} scopes:")
                for s in missing:
                    print(f"  - {s}")
            if not quiet:
                print(f"AUTHENTICATED: Token refreshed at {TOKEN_PATH}")
            return True
        except Exception as e:
            err_str = str(e).lower()
            if "disabled_client" in err_str or "invalid_client" in err_str:
                print(f"OAUTH_CLIENT_DISABLED: {e}")
                print("  The OAuth client or Google account has been disabled.")
                print("  Steps to resolve:")
                print("    1. Check your Google Cloud Console — verify the OAuth client is not disabled")
                print("    2. Check if your Google account itself is disabled at myaccount.google.com")
                print("    3. If the account is disabled, you can appeal at accounts.google.com/signin/recovery")
                print("    4. Do NOT retry API calls with a disabled account — this may worsen the situation")
                print("    5. If the OAuth client is disabled, create a new one in Google Cloud Console")
            elif "token_revoked" in err_str or "invalid_grant" in err_str:
                print(f"TOKEN_REVOKED: {e}")
                print("  Re-run setup to re-authenticate.")
            else:
                print(f"REFRESH_FAILED: {e}")
            return False

    print("TOKEN_INVALID: Re-run setup.")
    return False


# --------------------------------------------------------------------------- #
# Client secret
# --------------------------------------------------------------------------- #


def store_client_secret(path: str):
    """Copy and validate client_secret.json to Hermes home."""
    src = Path(path).expanduser().resolve()
    if not src.exists():
        print(f"ERROR: File not found: {src}")
        sys.exit(1)

    try:
        data = json.loads(src.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print("ERROR: File is not valid JSON.")
        sys.exit(1)

    if "installed" not in data and "web" not in data:
        print("ERROR: Not a Google OAuth client secret file (missing 'installed' key).")
        print("Download the correct file from: https://console.cloud.google.com/apis/credentials")
        sys.exit(1)

    # The client secret is a bearer credential: keep it private.
    write_secret(CLIENT_SECRET_PATH, json.dumps(data, indent=2))
    print(f"OK: Client secret saved to {CLIENT_SECRET_PATH}")


# --------------------------------------------------------------------------- #
# OAuth session
# --------------------------------------------------------------------------- #


def _save_pending_auth(*, state: str, code_verifier: str, scopes: list[str]):
    """Persist the OAuth session bits needed for a later token exchange.

    The PKCE code_verifier is a secret — it is the second half of the
    authorization code proof — so the file is written 0600.
    """
    write_secret(
        PENDING_AUTH_PATH,
        json.dumps(
            {
                "state": state,
                "code_verifier": code_verifier,
                "redirect_uri": REDIRECT_URI,
                "scopes": list(scopes),
            },
            indent=2,
        ),
    )


def _load_pending_auth() -> dict:
    """Load the pending OAuth session created by get_auth_url()."""
    if not PENDING_AUTH_PATH.exists():
        print("ERROR: No pending OAuth session found. Run --auth-url first.")
        sys.exit(1)

    try:
        data = json.loads(PENDING_AUTH_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"ERROR: Could not read pending OAuth session: {e}")
        print("Run --auth-url again to start a fresh OAuth session.")
        sys.exit(1)

    if not data.get("state") or not data.get("code_verifier"):
        print("ERROR: Pending OAuth session is missing PKCE data.")
        print("Run --auth-url again to start a fresh OAuth session.")
        sys.exit(1)

    return data


def _extract_code_and_state(code_or_url: str) -> tuple[str, str | None]:
    """Accept either a raw auth code or the full redirect URL pasted by the user."""
    if not code_or_url.startswith("http"):
        return code_or_url, None

    from urllib.parse import parse_qs, urlparse

    parsed = urlparse(code_or_url)
    params = parse_qs(parsed.query)
    if "code" not in params:
        print("ERROR: No 'code' parameter found in URL.")
        sys.exit(1)

    state = params.get("state", [None])[0]
    return params["code"][0], state


def _build_auth_url(scopes: list[str]) -> str:
    """Create a consent URL for ``scopes`` and stash the pending session."""
    from google_auth_oauthlib.flow import Flow

    flow = Flow.from_client_secrets_file(
        str(CLIENT_SECRET_PATH),
        scopes=scopes,
        redirect_uri=REDIRECT_URI,
        autogenerate_code_verifier=True,
    )
    auth_url, state = flow.authorization_url(
        access_type="offline",
        prompt="consent",
    )
    if not flow.code_verifier:
        raise RuntimeError("PKCE code_verifier was not generated")
    _save_pending_auth(state=state, code_verifier=flow.code_verifier, scopes=scopes)
    # The URL embeds the client id and the PKCE challenge: keep it private.
    write_secret(LAST_AUTH_URL_PATH, auth_url)
    return auth_url


def get_auth_url(services: str | None = None, fmt: str = "text"):
    """Print the OAuth authorization URL. User visits this in a browser."""
    if not CLIENT_SECRET_PATH.exists():
        print("ERROR: No client secret stored. Run --client-secret first.")
        sys.exit(1)

    _ensure_deps()

    scopes = _consent_scopes(services)
    auth_url = _build_auth_url(scopes)

    if fmt == "json":
        _emit(
            {
                "auth_url": auth_url,
                "scopes": scopes,
                "last_url_file": str(LAST_AUTH_URL_PATH),
            },
            fmt,
        )
        return

    # Print just the URL so the agent can extract it cleanly
    print(auth_url)


def _consent_scopes(services: str | None) -> list[str]:
    """Scopes to ask for on the consent screen."""
    from _gws_policy import effective_scopes

    return effective_scopes(_policy_candidates(), services)


def exchange_auth_code(code: str, fmt: str = "text"):
    """Exchange the authorization code for a token and save it."""
    if not CLIENT_SECRET_PATH.exists():
        print("ERROR: No client secret stored. Run --client-secret first.")
        sys.exit(1)

    pending_auth = _load_pending_auth()
    raw_callback = code
    code, returned_state = _extract_code_and_state(code)
    if returned_state and returned_state != pending_auth["state"]:
        print("ERROR: OAuth state mismatch. Run --auth-url again to start a fresh session.")
        sys.exit(1)

    _ensure_deps()
    from google_auth_oauthlib.flow import Flow
    from urllib.parse import parse_qs, urlparse

    # Extract granted scopes from the callback URL if the user pasted the full redirect URL.
    # Fall back to the scopes this pending session actually asked for — never to the
    # global default, or a narrowed consent would be widened on exchange.
    requested_scopes = list(pending_auth.get("scopes") or _required_scopes())
    granted_scopes = list(requested_scopes)
    if isinstance(raw_callback, str) and raw_callback.startswith("http"):
        params = parse_qs(urlparse(raw_callback).query)
        scope_val = (params.get("scope") or [""])[0].strip()
        if scope_val:
            granted_scopes = scope_val.split()

    flow = Flow.from_client_secrets_file(
        str(CLIENT_SECRET_PATH),
        scopes=granted_scopes,
        redirect_uri=pending_auth.get("redirect_uri", REDIRECT_URI),
        state=pending_auth["state"],
        code_verifier=pending_auth["code_verifier"],
    )

    try:
        # Accept partial scopes — user may deselect some permissions in the consent screen
        os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"
        flow.fetch_token(code=code)
    except Exception as e:
        fresh = _fresh_auth_url()
        if fmt == "json":
            _emit(
                {
                    "status": "error",
                    "error": f"Token exchange failed: {e}",
                    "fresh_auth_url": fresh,
                },
                fmt,
            )
        else:
            print(f"ERROR: Token exchange failed: {e}")
            if fresh:
                print("The code may have expired. Use this fresh URL instead:")
                print(fresh)
            else:
                print("The code may have expired. Run --auth-url to get a fresh URL.")
        sys.exit(1)

    creds = flow.credentials
    token_payload = _normalize_authorized_user_payload(json.loads(creds.to_json()))

    # Store only the scopes actually granted by the user, not what was requested.
    # creds.to_json() writes the requested scopes, which causes refresh to fail
    # with invalid_scope if the user only authorized a subset.
    actually_granted = list(creds.granted_scopes or []) if hasattr(creds, "granted_scopes") and creds.granted_scopes else []
    if actually_granted:
        token_payload["scopes"] = actually_granted
    elif granted_scopes != requested_scopes:
        # granted_scopes was extracted from the callback URL
        token_payload["scopes"] = granted_scopes

    # The token is a bearer credential: it must not be world-readable.
    write_secret(TOKEN_PATH, json.dumps(token_payload, indent=2))

    # Record the scope policy beside the token so every profile sharing this
    # token compares against the same expectation.
    try:
        write_policy(
            _policy_sidecar_path(),
            requested_scopes,
            services=None,
        )
    except OSError:
        pass

    PENDING_AUTH_PATH.unlink(missing_ok=True)

    missing = _missing_scopes_from_payload(token_payload, requested_scopes)
    if fmt == "json":
        _emit(
            {
                "status": "ok",
                "token_path": str(TOKEN_PATH),
                "granted_scopes": granted_scopes_from_payload(token_payload),
                "missing_scopes": missing,
            },
            fmt,
        )
        return

    if missing:
        print(f"WARNING: Token missing some Google Workspace scopes: {', '.join(missing)}")
        print("Some services may not be available.")
    print(f"OK: Authenticated. Token saved to {TOKEN_PATH}")
    print(f"Profile-scoped token location: {display_hermes_home()}/google_token.json")


def _fresh_auth_url() -> str | None:
    """Best-effort fresh consent URL after a failed code exchange."""
    try:
        if not CLIENT_SECRET_PATH.exists():
            return None
        return _build_auth_url(_consent_scopes(None))
    except Exception:
        return None


def revoke():
    """Revoke stored token and delete it."""
    if not TOKEN_PATH.exists():
        print("No token to revoke.")
        return

    _ensure_deps()
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request

    try:
        # Refresh with the scopes this token actually holds.  Passing the global
        # default set makes google-auth request scopes the grant never had, and
        # Google answers invalid_scope — which would abort the revocation.
        stored = granted_scopes_from_payload(_load_token_payload(TOKEN_PATH))
        creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), stored or None)
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())

        import urllib.request
        urllib.request.urlopen(
            urllib.request.Request(
                f"https://oauth2.googleapis.com/revoke?token={creds.token}",
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
            timeout=15,
        )
        print("Token revoked with Google.")
    except Exception as e:
        print(f"Remote revocation failed (token may already be invalid): {e}")

    TOKEN_PATH.unlink(missing_ok=True)
    PENDING_AUTH_PATH.unlink(missing_ok=True)
    print(f"Deleted {TOKEN_PATH}")


def main():
    parser = argparse.ArgumentParser(description="Google Workspace OAuth setup for Hermes")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="Check if auth is valid (exit 0=yes, 1=no)")
    group.add_argument("--check-live", action="store_true", help="Check auth with a real API call (detects disabled_client)")
    group.add_argument("--client-secret", metavar="PATH", help="Store OAuth client_secret.json")
    group.add_argument("--auth-url", action="store_true", help="Print OAuth URL for user to visit")
    group.add_argument("--auth-code", metavar="CODE", help="Exchange auth code for token")
    group.add_argument("--revoke", action="store_true", help="Revoke and delete stored token")
    group.add_argument("--install-deps", action="store_true", help="Install Python dependencies")
    parser.add_argument(
        "--services",
        metavar="LIST",
        help="Comma-separated services to request (email,calendar,drive,contacts,sheets,docs) or 'all'",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format for --auth-url / --auth-code (default: text)",
    )
    args = parser.parse_args()

    if args.check:
        sys.exit(0 if check_auth() else 1)
    if getattr(args, "check_live", False):
        sys.exit(0 if check_auth_live() else 1)
    elif args.client_secret:
        store_client_secret(args.client_secret)
    elif args.auth_url:
        get_auth_url(args.services, args.format)
    elif args.auth_code:
        exchange_auth_code(args.auth_code, args.format)
    elif args.revoke:
        revoke()
    elif args.install_deps:
        sys.exit(0 if install_deps() else 1)


if __name__ == "__main__":
    main()
