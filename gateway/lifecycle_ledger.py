"""Gateway lifecycle ledger — durable termination-reason evidence.

Graceful shutdowns leave forensics (``gateway-exit-diag.log``); an unclean
death (SIGKILL, kernel OOM, VM death) runs no handler.  A sentinel at
``<HERMES_HOME>/state/gateway.lifecycle.json`` closes the gap:
:func:`record_startup` finds ``phase == "running"`` from the previous life →
unclean death, appended to the exit-diag log as ``gateway.previous_unclean_exit``
and logged at WARNING; :func:`mark_exited` rewrites ``phase=exited`` on every
clean exit path.  Best-effort: forensics must never affect the lifecycle.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sqlite3
import subprocess
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


def _process_hermes_home() -> Path:
    """HERMES_HOME for process-level identity files (ignore task overrides)."""
    from hermes_constants import get_hermes_home, get_process_hermes_home

    # get_process_hermes_home expands ``~``/``$VAR`` (python -m gateway.run skips the CLI normalizer).
    return get_process_hermes_home() if os.environ.get("HERMES_HOME", "").strip() else get_hermes_home()


def _home_path(home: Optional[Path], *relative: str) -> Path:
    return (_process_hermes_home() if home is None else home).joinpath(*relative)


def get_lifecycle_sentinel_path(home: Optional[Path] = None) -> Path:
    """Return ``<HERMES_HOME>/state/gateway.lifecycle.json``."""
    return _home_path(home, "state", "gateway.lifecycle.json")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _proc_fields(path: str, wanted: Dict[str, str]) -> Dict[str, int]:
    """``{dst: int}`` for each ``src: dst`` key found in a ``Key: value`` /proc file."""
    found: Dict[str, int] = {}
    try:
        with open(path, encoding="utf-8-sig") as fh:
            for line in fh:
                key = line.split(":", 1)[0]
                if key in wanted:
                    found[wanted[key]] = int(line.split()[1])
                    if len(found) == len(wanted):
                        break
    except (OSError, ValueError, IndexError):
        return {}
    return found


def sample_memory() -> Dict[str, Any]:
    """Cheap /proc snapshot (KiB): own RSS + MemTotal/MemAvailable + swap used.  Linux-only
    (``{}`` elsewhere), never raises; the 30s heartbeat embeds it so OOM cycles are classifiable."""
    sample = _proc_fields("/proc/self/status", {"VmRSS": "rss_kib"})
    mem = _proc_fields("/proc/meminfo", {"MemTotal": "mem_total_kib", "MemAvailable": "mem_available_kib",
                                         "SwapTotal": "SwapTotal", "SwapFree": "SwapFree"})
    swap_total, swap_free = mem.pop("SwapTotal", None), mem.pop("SwapFree", None)
    sample.update(mem)
    if swap_total is not None and swap_free is not None:
        sample["swap_used_kib"] = swap_total - swap_free
    return sample


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _write_sentinel(payload: Dict[str, Any], home: Optional[Path]) -> None:
    try:
        from utils import atomic_json_write

        path = get_lifecycle_sentinel_path(home)
        from hermes_constants import mkdir_under_hermes_home

        mkdir_under_hermes_home(path.parent)
        atomic_json_write(path, payload, indent=None)
    except Exception:
        logger.debug("Failed to write lifecycle sentinel", exc_info=True)


def _append_exit_diag(record: Dict[str, Any], home: Optional[Path]) -> None:
    """Append a JSON line to gateway-exit-diag.log (same format as the CLI's ``_exit_diag``)."""
    try:
        path = _home_path(home, "logs", "gateway-exit-diag.log")
        from hermes_constants import mkdir_under_hermes_home

        mkdir_under_hermes_home(path.parent)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except OSError:
        logger.debug("Failed to append unclean-exit record", exc_info=True)


def _pid_is_sentinel_owner(pid: Any, start_time: Any, create_time: Any) -> bool:
    """True when ``pid`` is a live process that is the sentinel's incarnation — guards the
    ``--replace`` race: a live matching owner mid-teardown is a handover, not a death.

    Identity is the psutil ``create_time`` the sentinel stamps at claim (epoch seconds, same
    producer on both sides). The sentinel's ``start_time`` is the ledger claim time and is NOT
    comparable with ``gateway.status.get_process_start_time`` (proc ticks on Linux, centiseconds
    elsewhere) — the old comparison never matched, so every ``--replace`` handover read as an
    unclean death. A pre-stamp sentinel (no ``create_time``) still has ``start_time`` in epoch
    seconds: the owner was born BEFORE it claimed, a PID reuser AFTER the owner died, so a birth
    later than the claim is a reuser."""
    try:
        pid_int = int(pid)
        # NOT os.kill(pid, 0): on Windows that sends CTRL_C_EVENT to the target's console group.
        from gateway.status import _pid_exists

        if pid_int <= 0 or not _pid_exists(pid_int):
            return False
    except Exception:
        return False
    from hermes_cli.process_identity import _process_create_time

    actual = _process_create_time(pid_int)
    if actual is None:
        return True  # can't disambiguate PID reuse
    if type(create_time) in (int, float):
        return abs(actual - float(create_time)) <= 2.0
    if type(start_time) in (int, float):
        return actual <= float(start_time) + 2.0
    return True


def _suspected_oom(mem: Dict[str, Any]) -> bool:
    """Heuristic only (classification stays with the reader); thresholds are
    memory_status' "critical" tier so a live warning and a post-mortem verdict agree."""
    from gateway.memory_status import _CRITICAL_AVAILABLE_FRACTION, _CRITICAL_AVAILABLE_KIB

    total, avail = mem.get("mem_total_kib"), mem.get("mem_available_kib")
    if not isinstance(avail, int):
        return False
    return avail < _CRITICAL_AVAILABLE_KIB or (
        isinstance(total, int) and total > 0 and avail / total < _CRITICAL_AVAILABLE_FRACTION
    )


def detect_unclean_exit(home: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Evidence dict when the previous life died uncleanly, else ``None``. Read-only."""
    sentinel = _read_json(get_lifecycle_sentinel_path(home))
    if not sentinel or sentinel.get("phase") != "running":
        return None
    if _pid_is_sentinel_owner(sentinel.get("pid"), sentinel.get("start_time"), sentinel.get("create_time")):
        return None  # live owner — planned takeover in flight, not a death
    evidence: Dict[str, Any] = {
        "prior_pid": sentinel.get("pid"), "prior_started_at": sentinel.get("started_at"),
        "prior_start_time": sentinel.get("start_time"),
    }
    # Enrich with the last heartbeat: last proven liveness and memory at that moment.
    try:
        from gateway.shutdown_watchdog import get_loop_heartbeat_path

        hb = _read_json(get_loop_heartbeat_path(home)) or {}
    except Exception:
        hb = {}
    if hb:
        evidence["last_heartbeat_at"] = hb.get("updated_at")
    mem = hb.get("mem")
    if isinstance(mem, dict):
        evidence["last_heartbeat_mem"] = mem
        if _suspected_oom(mem):
            evidence["suspected_oom"] = True
    return evidence


# Startup-watchdog lease held while the unclean-exit integrity check runs (#115542):
# ``PRAGMA quick_check(1)`` is one monolithic SQLite operation and per-call leases
# clamp at 900s, so a single entry lease cannot cover a multi-thousand-second healthy
# check on a huge store — without renewal the watchdog kills the attempt with exit 75
# and the restart loop never reaches the cron ticker. The progress handler below renews
# a phase-owned lease for as long as SQLite is making progress, and always returns 0
# so it never aborts the check; the ok/absent/first-complaint verdicts stay fail-closed.
_INTEGRITY_CHECK_LEASE_PHASE = "state_db_unclean_integrity_check"
_INTEGRITY_CHECK_LEASE_S = 900.0
# VM instructions between progress-handler invocations; each invocation is a
# monotonic-clock compare, renewing at most every _INTEGRITY_CHECK_LEASE_RENEW_S.
_INTEGRITY_CHECK_PROGRESS_OPS = 100_000
_INTEGRITY_CHECK_LEASE_RENEW_S = 60.0


def _install_integrity_check_lease(conn: sqlite3.Connection) -> None:
    """Claim the integrity-check lease and renew it from a SQLite progress handler.

    ``report_startup_progress`` is a no-op when no watchdog is armed and never raises.
    The handler always returns 0 -- it must never abort the verdict PRAGMA.  Synchronous
    by design: no checker worker thread can outlive the check.
    """
    from hermes_startup_watchdog import report_startup_progress

    report_startup_progress(_INTEGRITY_CHECK_LEASE_S, phase=_INTEGRITY_CHECK_LEASE_PHASE)
    last_renew = time.monotonic()

    def _on_progress() -> int:
        nonlocal last_renew
        now = time.monotonic()
        if now - last_renew >= _INTEGRITY_CHECK_LEASE_RENEW_S:
            last_renew = now
            report_startup_progress(_INTEGRITY_CHECK_LEASE_S, phase=_INTEGRITY_CHECK_LEASE_PHASE)
        return 0

    conn.set_progress_handler(_on_progress, _INTEGRITY_CHECK_PROGRESS_OPS)


def check_state_db_integrity(home: Optional[Path] = None) -> str:
    """``"ok"``, ``"absent"``, or the first ``quick_check`` complaint.  Never raises.

    Only after an unclean death — SIGKILL mid-WAL-checkpoint can leave half-written
    b-tree pages.  ``quick_check(1)`` stops at the first problem (~2s on a healthy
    500MB store): cheap once per unclean boot, too costly every boot.  Opened
    normally: a WAL store needs its -shm sidecar for read-only, and the PRAGMA writes nothing.

    Holds a phase-owned startup-watchdog lease for the check duration
    (renewed from a SQLite progress handler, #115542) so a long healthy check
    on a huge store is not mistaken for a parked deadlock.
    """
    path = _home_path(home, "state.db")
    if not path.exists():
        return "absent"
    try:
        with closing(sqlite3.connect(str(path))) as conn:
            _install_integrity_check_lease(conn)
            row = conn.execute("PRAGMA quick_check(1)").fetchone()
    except Exception as exc:
        return f"check-failed: {exc}"
    return "check-failed: no result" if not row or row[0] is None else str(row[0])


# ---------------------------------------------------------------------------
# Discriminating evidence for an unclean death: did the whole GUEST go, or only us?
#
# Four byte-identical warnings in one evening cost a two-hour forensics session
# because the line listed five possible causes and no discriminator, so OOM, an
# idle-timeout hypothesis and a user restart all stayed live at once.  The facts
# below separate them in one clause each.  Evidence TEXT only: nothing here gates,
# blocks or changes how recovery runs, and anything unreadable is omitted rather
# than guessed (the ``real-disk.py`` UNKNOWN rule).
# ---------------------------------------------------------------------------

# One bounded PowerShell call per unclean boot (measured ~0.6s on this host).  The
# event-log query is read-only; the timeout is what keeps forensics off the
# startup path when interop is wedged.
_HOST_PROBE_TIMEOUT_S = 6.0
# ``psutil.boot_time()`` is whole seconds, so an orderer inside the boot second
# itself would otherwise fall outside the window.
_HOST_PROBE_SLACK_S = 2
# Event messages are localized and can be long; bound the clause either way.
_HOST_EVENT_MESSAGE_LIMIT = 400

_EXIT_CAUSES_GENERIC = (
    "no exit path ran — SIGKILL / OOM / VM death, or a process kill issued by the agent or one of its "
    "descendants, e.g. a pkill/taskkill of the host interpreter image; see #113667"
)
# Reordered on purpose when a reboot is proven: lead with the cause that actually
# took every process down, and with the one query that names who ordered it.
_EXIT_CAUSES_REBOOT = (
    "no exit path ran — EXTERNAL SHUTDOWN FIRST: an external `wsl --shutdown` or a host restart tore the whole "
    "guest down, so check Windows Event 1074 first (SIGKILL / OOM / a pkill of the host interpreter image stay "
    "the fallback suspects); see #113667"
)


def _guest_boot_time() -> Optional[float]:
    """Epoch seconds the CURRENT guest boot began — ``psutil.boot_time()``, the same
    ``/proc/stat`` ``btime`` that ``uptime -s`` prints (the WSL VM's start under WSL).
    ``None`` when unreadable: UNKNOWN, never guessed."""
    try:
        import psutil  # type: ignore

        return float(psutil.boot_time())
    except Exception:
        logger.debug("Guest boot time unreadable — no reboot claim will be made", exc_info=True)
        return None


def _epoch(value: Any) -> Optional[float]:
    """Epoch seconds for a number or an ISO-8601 string (``Z``-tolerant); ``None`` = unknown."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value.strip():
        try:
            stamp = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return stamp.timestamp()
    return None


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _detect_vm_reboot(evidence: Dict[str, Any]) -> Optional[Tuple[float, float]]:
    """``(boot, prior_last_seen)`` when the guest rebooted between lives, else ``None``.

    The previous life's death lies at or after every timestamp held for it — it
    started then, and it was alive at its last heartbeat — and a reboot can only
    happen after that death.  So ``boot > max(start, heartbeat)`` proves the
    previous life ran on an EARLIER boot and took the guest with it; otherwise
    both lives share a boot and the death was a kill inside a live guest
    (SIGKILL / OOM / pkill).  Anything unknown on either side → ``None``: no claim
    without evidence, and never a claim the timestamps cannot carry.
    """
    boot = _guest_boot_time()
    if boot is None:
        return None
    known = [stamped for stamped in (
        _epoch(evidence.get("prior_start_time")),
        _epoch(evidence.get("prior_started_at")),
        _epoch(evidence.get("last_heartbeat_at")),
    ) if stamped is not None]
    if not known:
        return None
    prior_last_seen = max(known)
    return (boot, prior_last_seen) if boot > prior_last_seen else None


def _host_probe_script(since_epoch: float, boot_epoch: float) -> str:
    """PowerShell (5.1 and ``pwsh``) printing one line per fact for the death window.

    The window is ``[since, boot + slack]``: from the previous life's last sighting
    up to THIS boot (plus ``_HOST_PROBE_SLACK_S`` because the boot time is whole
    seconds), so an orderer belonging to an earlier life can never be attributed
    to this death and a restart ordered after our boot can never be claimed for it.

    ``EVENT|HIT|<utc>|<sid>|<base64 utf-8 message>`` / ``EVENT|NONE`` / ``EVENT|ERR``
    is the newest Windows Event 1074 (a user/OS-ordered restart or shutdown) in that
    window; ``IDLE|set|<path>|<raw line>`` / ``IDLE|absent|<path>`` / ``IDLE|nofile``
    is ``vmIdleTimeout`` from the host's ``%USERPROFILE%\\.wslconfig``, read host-side
    because the guest cannot tell which Windows profile is the right one on its own.

    Two details are load-bearing: the message is base64 because Windows writes it in
    the console codepage and in the host's language, and the "no events" branch tests
    ``FullyQualifiedErrorId`` instead of the error text because that text is localized.
    """
    return (
        f"$sw=[DateTimeOffset]::FromUnixTimeSeconds({int(since_epoch)}).LocalDateTime; "
        f"$ew=[DateTimeOffset]::FromUnixTimeSeconds({int(boot_epoch + _HOST_PROBE_SLACK_S)}).LocalDateTime; "
        "$e=Get-WinEvent -FilterHashtable @{LogName='System';Id=1074;StartTime=$sw;EndTime=$ew} -MaxEvents 1 "
        "-ErrorAction SilentlyContinue -ErrorVariable err; "
        f"if ($null -ne $e) {{ $m=[string]$e.Message; if ($m.Length -gt {_HOST_EVENT_MESSAGE_LIMIT}) "
        f"{{ $m=$m.Substring(0,{_HOST_EVENT_MESSAGE_LIMIT}) }}; "
        "'EVENT|HIT|' + $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssK') + '|' + $e.UserId + '|' + "
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($m)) } "
        "elseif (@($err).Count -and @($err)[0].FullyQualifiedErrorId -match '^NoMatchingEventsFound') "
        "{ 'EVENT|NONE' } else { 'EVENT|ERR' }; "
        "$p=Join-Path $env:USERPROFILE '.wslconfig'; "
        "if (Test-Path -LiteralPath $p) { $l=Select-String -LiteralPath $p -Pattern 'vmIdleTimeout' | "
        "Select-Object -First 1; if ($l) { 'IDLE|set|' + $p + '|' + ($l.Line.Trim() -replace '\\|','/') } "
        "else { 'IDLE|absent|' + $p } } else { 'IDLE|nofile' }"
    )


def _parse_host_probe(stdout: Optional[str]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """``(event, idle)`` decoded from the probe's stdout; ``None`` for a part it did not print.

    Only ``EVENT|HIT`` names an orderer and only ``EVENT|NONE`` licenses the "the host
    did not order this" claim — anything else comes back ``unknown``, never inferred.
    """
    event: Optional[Dict[str, Any]] = None
    idle: Optional[Dict[str, Any]] = None
    for line in (stdout or "").splitlines():
        parts = line.strip().split("|")
        if parts[0] == "EVENT" and event is None:
            if len(parts) >= 5 and parts[1] == "HIT":
                try:
                    message = base64.b64decode(parts[4]).decode("utf-8", "replace")
                except Exception:
                    logger.debug("Could not decode the Event 1074 message from the host probe", exc_info=True)
                    message = ""
                # Event messages are multi-line; one warning line must stay one line.
                event = {"status": "hit", "at": parts[2], "sid": parts[3], "message": " ".join(message.split())}
            elif len(parts) >= 2 and parts[1] == "NONE":
                event = {"status": "none"}
            else:
                event = {"status": "unknown"}
        elif parts[0] == "IDLE" and idle is None:
            if len(parts) >= 4 and parts[1] == "set":
                idle = {"status": "set", "path": parts[2], "line": parts[3]}
            elif len(parts) >= 3 and parts[1] == "absent":
                idle = {"status": "absent", "path": parts[2]}
            elif len(parts) >= 2 and parts[1] == "nofile":
                idle = {"status": "no_file"}
            else:
                idle = {"status": "unknown"}
    return event, idle


def _host_restart_evidence(boot_epoch: float, since_epoch: float) -> Optional[Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]]:
    """One bounded, read-only PowerShell call for ``[since, boot]``; ``None`` = nothing to add.

    ``None`` when we are not on Windows/WSL, when no PowerShell is on PATH, or when the
    call fails or times out — the clauses are then dropped silently rather than guessed,
    so the warning degrades to exactly what it says today.
    """
    try:
        if os.name != "nt":
            from hermes_constants import is_wsl

            if not is_wsl():
                return None  # Event 1074 and .wslconfig are Windows facts; nothing to ask here
        import shutil

        powershell = (shutil.which("powershell.exe") or shutil.which("powershell")
                      or shutil.which("pwsh.exe") or shutil.which("pwsh"))
        if powershell is None:
            return None
        argv = [powershell, "-NoProfile", "-Command", _host_probe_script(since_epoch, boot_epoch)]
        if os.name == "nt":
            # Windows: the shared helper also contains the probe in a Job Object, so a wedged
            # child holding the pipes cannot outlive the timeout (#87134).
            from hermes_cli._subprocess_compat import bounded_probe_run

            result = bounded_probe_run(argv, timeout=_HOST_PROBE_TIMEOUT_S, errors="replace")
        else:
            # POSIX/WSL: that helper imports ``ctypes.wintypes`` and returns None here, and the
            # hang it guards against is Windows handle inheritance — a plain run suffices.
            result = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL,
                                    encoding="utf-8", errors="replace", timeout=_HOST_PROBE_TIMEOUT_S)
        if result is None or result.returncode != 0:
            return None
        return _parse_host_probe(result.stdout)
    except Exception:
        logger.debug("Host restart evidence probe failed — its clauses will be omitted", exc_info=True)
        return None


def _enrich_reboot_evidence(evidence: Dict[str, Any]) -> None:
    """Append the facts that discriminate WHY the guest died.  Text only, never raises.

    Every step is optional: a missing piece leaves its clause out of the warning, so
    forensics can never block or delay the boot it is describing.
    """
    try:
        reboot = _detect_vm_reboot(evidence)
    except Exception:
        logger.debug("VM reboot detection failed — no reboot claim will be made", exc_info=True)
        reboot = None
    if reboot is None:
        return
    boot, prior_last_seen = reboot
    evidence["vm_rebooted"] = True
    evidence["wsl_boot_at"] = _iso(boot)
    evidence["prior_last_seen_at"] = _iso(prior_last_seen)
    try:
        probe = _host_restart_evidence(boot, prior_last_seen)
    except Exception:
        logger.debug("Host restart evidence unavailable", exc_info=True)
        probe = None
    if probe is None:
        return
    event, idle = probe
    if event is not None:
        evidence["host_restart_1074"] = event
    if idle is not None:
        evidence["vm_idle_timeout"] = idle


def _exit_causes(evidence: Dict[str, Any]) -> str:
    """What the warning says could have killed the life — reordered once a reboot is proven."""
    return _EXIT_CAUSES_REBOOT if evidence.get("vm_rebooted") else _EXIT_CAUSES_GENERIC


def _evidence_suffix(evidence: Dict[str, Any]) -> str:
    """The discriminating clauses appended to the warning (empty when none are known)."""
    if not evidence.get("vm_rebooted"):
        return ""
    clauses = [
        "VM REBOOTED between lives (new WSL boot %s > prior last seen %s)"
        % (evidence.get("wsl_boot_at"), evidence.get("prior_last_seen_at"))
    ]
    event = evidence.get("host_restart_1074")
    if isinstance(event, dict):
        status = event.get("status")
        if status == "hit":
            clauses.append("Windows Event 1074 ordered at %s by %s" % (event.get("at"), event.get("message")))
        elif status == "none":
            clauses.append("no Windows Event 1074 in that window — NOT a user/OS-ordered restart "
                           "(suspect an external `wsl --shutdown` / WSL service stop, not OOM)")
        else:
            clauses.append("Windows Event 1074: UNKNOWN (query failed)")
    idle = evidence.get("vm_idle_timeout")
    if isinstance(idle, dict):
        status = idle.get("status")
        if status == "set":
            clauses.append("%s (%s)" % (idle.get("line"), idle.get("path")))
        elif status == "absent":
            clauses.append("vmIdleTimeout not set in %s" % idle.get("path"))
        elif status == "no_file":
            clauses.append("no host .wslconfig to read vmIdleTimeout from")
        else:
            clauses.append("vmIdleTimeout: UNKNOWN")
    return " | evidence: " + "; ".join(clauses)


def _report_unclean_exit(evidence: Dict[str, Any], home: Optional[Path]) -> None:
    """Integrity-check the store, append the discriminating reboot/host evidence, persist the
    exit-diag record, log at WARNING.  Never raises."""
    # The death may have torn the store; this is the only moment we know to look.
    verdict = evidence["state_db_integrity"] = check_state_db_integrity(home=home)
    if verdict not in ("ok", "absent"):
        logger.error(
            "state.db FAILED integrity check after an unclean gateway exit: %s — sessions may read as "
            "missing until it is repaired. Run `hermes doctor`.",
            verdict,
        )
    _enrich_reboot_evidence(evidence)
    _append_exit_diag({"ts": _now_iso(), "tag": "gateway.previous_unclean_exit", "pid": os.getpid(), **evidence}, home)
    logger.warning(
        "Previous gateway life (pid=%s, started_at=%s) exited UNCLEANLY (%s). last_heartbeat_at=%s last_mem=%s "
        "suspected_oom=%s%s",
        evidence.get("prior_pid"), evidence.get("prior_started_at"), _exit_causes(evidence),
        evidence.get("last_heartbeat_at"), evidence.get("last_heartbeat_mem"),
        evidence.get("suspected_oom", False), _evidence_suffix(evidence),
    )


def record_startup(home: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Boot entry point: report any unclean previous exit (evidence dict, also persisted
    to ``gateway-exit-diag.log`` and logged at WARNING) then claim the sentinel.  Never raises."""
    evidence: Optional[Dict[str, Any]] = None
    try:
        evidence = detect_unclean_exit(home)
        if evidence is not None:
            _report_unclean_exit(evidence, home)
    except Exception:
        logger.debug("Unclean-exit detection failed", exc_info=True)
    try:
        claim: Dict[str, Any] = {"phase": "running", "pid": os.getpid(), "start_time": time.time(), "started_at": _now_iso()}
        # Process birth (psutil), distinct from ``start_time`` (the ledger claim, seconds later once
        # imports finish): the Windows start attestation binds PIDs to birth time (#110020 review).
        from hermes_cli.process_identity import _process_create_time

        create_time = _process_create_time(os.getpid())
        if create_time is not None:
            claim["create_time"] = create_time
        # Carry the verdict on the PREVIOUS life on the new sentinel: it is the only
        # machine-readable copy (/api/status reads it to report an OOM restart).
        # Scoped to this life — the next clean exit or boot rewrites the sentinel.
        if evidence is not None:
            claim["prior_unclean_exit"] = True
            if evidence.get("suspected_oom"):
                claim["prior_suspected_oom"] = True
        _write_sentinel(claim, home)
    except Exception:
        logger.debug("Failed to claim lifecycle sentinel", exc_info=True)
    return evidence


def mark_exited(exit_code: Optional[int] = None, reason: str = "graceful_shutdown", home: Optional[Path] = None) -> None:
    """Mark the current life as cleanly exited.  Idempotent, never raises.

    Only rewrites a sentinel provably owned by this process: during ``--replace``
    the replacement claims it before the old process finishes teardown and must not
    be clobbered.  ``pid=None`` / malformed sentinels have unknown ownership → left alone.
    """
    try:
        sentinel = _read_json(get_lifecycle_sentinel_path(home))
        if sentinel is not None and sentinel.get("pid") != os.getpid():
            return
        exited: Dict[str, Any] = {"phase": "exited", "pid": os.getpid(), "exit_code": exit_code, "exit_reason": reason,
                                  "exited_at": _now_iso()}
        # Carry the incarnation identity: the Windows start attestation matches a clean exit by
        # PID *and* start time so a reused PID's exit cannot vouch for a different life (#110020).
        for key in ("start_time", "create_time"):
            if sentinel is not None and sentinel.get(key) is not None:
                exited[key] = sentinel[key]
        _write_sentinel(exited, home)
    except Exception:
        logger.debug("Failed to mark lifecycle sentinel exited", exc_info=True)


def read_prior_exit_label(profile_home: Path) -> str:
    """``clean``/``unclean``/``unknown`` for the profile's last gateway life; annotates
    ``container-boot.log``.  ``running`` is unclean: the old PID namespace is gone at container boot."""
    try:
        phase = (_read_json(get_lifecycle_sentinel_path(profile_home)) or {}).get("phase")
        return {"exited": "clean", "running": "unclean"}.get(phase, "unknown")
    except Exception:
        return "unknown"
