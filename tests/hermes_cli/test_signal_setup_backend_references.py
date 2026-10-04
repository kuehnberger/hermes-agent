"""Signal setup surfaces must point at signal-cli's own HTTP daemon.

``gateway/platforms/signal.py`` speaks exactly one protocol: signal-cli's
``daemon --http`` endpoints — ``GET /api/v1/check``, ``GET /api/v1/events``
(SSE) and ``POST /api/v1/rpc`` (JSON-RPC 2.0) — as documented in signal-cli's
``man/signal-cli-jsonrpc.5.adoc``. bbernhard/signal-cli-rest-api, the project
the Messaging panel used to link, serves a different surface (``/v1/*`` and
``/v2/*``) and never exposes ``/api/v1/*`` in any of its modes, so a setup
copied from that link 404s on every request (#132554).

These tests pin the two things a user follows — the panel's "Open setup
guide" target and the ``SIGNAL_HTTP_URL`` field hint — plus a sweep of the
surfaces that render setup copy so the stale link cannot come back.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SIGNAL_GUIDE = "https://hermes-agent.nousresearch.com/docs/user-guide/messaging/signal"
WRONG_BACKEND = "bbernhard/signal-cli-rest-api"
WRONG_BACKEND_CLAIM = "signal-cli REST"

# Directories whose text a user reads while setting Signal up.
SETUP_SURFACES = (
    REPO_ROOT / "hermes_cli",
    REPO_ROOT / "apps" / "desktop" / "src",
    REPO_ROOT / "website",
)


def _stale_files() -> list[str]:
    offenders: list[str] = []
    for surface in SETUP_SURFACES:
        for path in surface.rglob("*"):
            if not path.is_file() or "node_modules" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if WRONG_BACKEND in text or WRONG_BACKEND_CLAIM in text:
                offenders.append(str(path.relative_to(REPO_ROOT)))
    return sorted(offenders)


def test_signal_catalog_entry_links_the_hermes_signal_guide():
    """The panel's "Open setup guide" button must open the Signal setup guide."""
    from hermes_cli.web_server_messaging import _PLATFORM_OVERRIDES

    entry = _PLATFORM_OVERRIDES["signal"]
    assert entry["docs_url"] == SIGNAL_GUIDE
    assert "HTTP mode" in entry["description"]
    assert "REST bridge" not in entry["description"]


def test_signal_http_url_hint_describes_the_http_daemon():
    """The URL field hint is what users type into; it must name a daemon."""
    from hermes_cli.web_routers.messaging import _MESSAGING_ENV_FALLBACKS

    field = _MESSAGING_ENV_FALLBACKS["SIGNAL_HTTP_URL"]
    assert "HTTP daemon" in field["description"]
    assert field["url"] == SIGNAL_GUIDE

    account = _MESSAGING_ENV_FALLBACKS["SIGNAL_ACCOUNT"]
    assert "bridge" not in account["description"]


def test_no_setup_surface_links_the_wrong_signal_backend():
    """Setup copy must never steer users at a backend the adapter can't talk to."""
    assert _stale_files() == []
