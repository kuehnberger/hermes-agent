"""Tests for gateway.lifecycle_ledger — unclean-shutdown detection (NS-608).

The ledger is a tiny sentinel state machine:
``record_startup`` claims ``state/gateway.lifecycle.json`` as
``phase=running``; every exit path calls ``mark_exited``; the next boot's
``record_startup``/``detect_unclean_exit`` reports a still-``running``
sentinel from a dead process as an unclean death (SIGKILL / OOM / VM loss)
and enriches the report with the last heartbeat's memory sample.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from gateway.lifecycle_ledger import (
    detect_unclean_exit,
    get_lifecycle_sentinel_path,
    mark_exited,
    read_prior_exit_label,
    record_startup,
    sample_memory,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEAD_PID = 2 ** 22 + 12345  # beyond default pid_max on Linux; never alive


def _write_sentinel(home: Path, payload: dict) -> Path:
    path = get_lifecycle_sentinel_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _read_sentinel(home: Path) -> dict:
    return json.loads(get_lifecycle_sentinel_path(home).read_text(encoding="utf-8"))


def _write_heartbeat(home: Path, payload: dict) -> Path:
    path = home / "state" / "gateway.heartbeat"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _exit_diag_records(home: Path) -> list[dict]:
    path = home / "logs" / "gateway-exit-diag.log"
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# sample_memory
# ---------------------------------------------------------------------------


@pytest.mark.platforms("linux")  # /proc is Linux-only
def test_sample_memory_has_expected_keys_on_linux() -> None:
    sample = sample_memory()
    assert sample.get("rss_kib", 0) > 0
    assert sample.get("mem_total_kib", 0) > 0
    assert "mem_available_kib" in sample


# ---------------------------------------------------------------------------
# First boot / clean lifecycle
# ---------------------------------------------------------------------------


def test_first_boot_reports_nothing_and_claims_sentinel(tmp_path: Path) -> None:
    assert record_startup(home=tmp_path) is None
    sentinel = _read_sentinel(tmp_path)
    assert sentinel["phase"] == "running"
    assert sentinel["pid"] == os.getpid()
    assert "start_time" in sentinel


def test_clean_exit_then_boot_reports_nothing(tmp_path: Path) -> None:
    record_startup(home=tmp_path)
    mark_exited(0, reason="graceful_shutdown", home=tmp_path)

    sentinel = _read_sentinel(tmp_path)
    assert sentinel["phase"] == "exited"
    assert sentinel["exit_code"] == 0
    assert sentinel["exit_reason"] == "graceful_shutdown"

    assert record_startup(home=tmp_path) is None
    assert _exit_diag_records(tmp_path) == []


# ---------------------------------------------------------------------------
# Unclean-death detection
# ---------------------------------------------------------------------------


def test_running_sentinel_from_dead_pid_is_unclean(tmp_path: Path) -> None:
    _write_sentinel(tmp_path, {
        "phase": "running",
        "pid": _DEAD_PID,
        "start_time": 1000.0,
        "started_at": "2026-07-11T04:30:00+00:00",
    })

    evidence = detect_unclean_exit(home=tmp_path)
    assert evidence is not None
    assert evidence["prior_pid"] == _DEAD_PID
    assert evidence["prior_started_at"] == "2026-07-11T04:30:00+00:00"


def test_record_startup_persists_unclean_report_and_reclaims(tmp_path: Path) -> None:
    _write_sentinel(tmp_path, {
        "phase": "running",
        "pid": _DEAD_PID,
        "start_time": 1000.0,
        "started_at": "2026-07-11T04:30:00+00:00",
    })

    evidence = record_startup(home=tmp_path)
    assert evidence is not None

    records = _exit_diag_records(tmp_path)
    assert len(records) == 1
    assert records[0]["tag"] == "gateway.previous_unclean_exit"
    assert records[0]["prior_pid"] == _DEAD_PID
    assert records[0]["pid"] == os.getpid()

    # Sentinel reclaimed for the new life.
    sentinel = _read_sentinel(tmp_path)
    assert sentinel["phase"] == "running"
    assert sentinel["pid"] == os.getpid()




def test_record_startup_carries_unclean_flags_onto_new_sentinel(
    tmp_path: Path,
) -> None:
    """The unclean-death verdict must survive on the reclaimed sentinel so
    /api/status can surface "restarted after (suspected) OOM" (NS-656)."""
    _write_sentinel(tmp_path, {
        "phase": "running",
        "pid": _DEAD_PID,
        "start_time": 1000.0,
        "started_at": "2026-07-11T04:30:00+00:00",
    })
    # Last heartbeat shows near-exhausted memory → suspected OOM.
    from gateway.shutdown_watchdog import get_loop_heartbeat_path

    hb_path = get_loop_heartbeat_path(tmp_path)
    hb_path.parent.mkdir(parents=True, exist_ok=True)
    hb_path.write_text(json.dumps({
        "pid": _DEAD_PID,
        "updated_at": "2026-07-11T05:00:00+00:00",
        "mem": {"mem_total_kib": 1024 * 1024, "mem_available_kib": 20 * 1024},
    }), encoding="utf-8")

    evidence = record_startup(home=tmp_path)
    assert evidence is not None
    assert evidence.get("suspected_oom") is True

    sentinel = _read_sentinel(tmp_path)
    assert sentinel["phase"] == "running"
    assert sentinel["prior_unclean_exit"] is True
    assert sentinel["prior_suspected_oom"] is True


def test_record_startup_clean_boot_has_no_prior_flags(tmp_path: Path) -> None:
    _write_sentinel(tmp_path, {
        "phase": "exited",
        "pid": _DEAD_PID,
        "exit_code": 0,
        "exit_reason": "graceful_shutdown",
    })
    assert record_startup(home=tmp_path) is None
    sentinel = _read_sentinel(tmp_path)
    assert sentinel["phase"] == "running"
    assert "prior_unclean_exit" not in sentinel
    assert "prior_suspected_oom" not in sentinel


# ---------------------------------------------------------------------------
# Takeover ownership guard on mark_exited
# ---------------------------------------------------------------------------


def test_mark_exited_leaves_pid_none_sentinel_alone(tmp_path: Path) -> None:
    """A sentinel with pid=None has unknown ownership — mark_exited must not
    clobber it with a clean-exit claim it cannot prove is its own."""
    _write_sentinel(tmp_path, {"phase": "running", "pid": None, "start_time": 2000.0})
    mark_exited(0, reason="graceful_shutdown", home=tmp_path)
    sentinel = _read_sentinel(tmp_path)
    assert sentinel["phase"] == "running"
    assert sentinel["pid"] is None


# ---------------------------------------------------------------------------
# read_prior_exit_label (container-boot annotation)
# ---------------------------------------------------------------------------


def test_prior_exit_label_survives_corrupt_sentinel(tmp_path: Path) -> None:
    path = get_lifecycle_sentinel_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("garbage", encoding="utf-8")
    assert read_prior_exit_label(tmp_path) == "unknown"


def test_sentinel_carries_process_birth_through_exit(tmp_path: Path, monkeypatch) -> None:
    """The running sentinel stamps the process ``create_time`` (psutil birth, not the later ledger
    claim) and the exited sentinel keeps it, so the Windows start attestation can match a clean
    exit by incarnation, not by reusable PID (#110020)."""
    monkeypatch.setattr("hermes_cli.process_identity._process_create_time", lambda pid=None: 1234.5)
    record_startup(home=tmp_path)
    running = json.loads(get_lifecycle_sentinel_path(tmp_path).read_text(encoding="utf-8"))
    assert running["create_time"] == 1234.5
    mark_exited(0, reason="graceful_shutdown", home=tmp_path)
    exited = json.loads(get_lifecycle_sentinel_path(tmp_path).read_text(encoding="utf-8"))
    assert exited["phase"] == "exited"
    assert (exited["start_time"], exited["create_time"]) == (running["start_time"], 1234.5)


def test_replace_handover_is_not_a_death_and_pid_reuse_is(tmp_path: Path, monkeypatch) -> None:
    """The live-owner guard compares the sentinel's psutil ``create_time`` with the live PID's
    (same producer, epoch seconds). The ledger's ``start_time`` (claim time) is never compared
    with ``get_process_start_time`` (proc ticks / centiseconds): that comparison could not match,
    so a ``--replace`` handover was reported as an unclean death."""
    monkeypatch.setattr("gateway.status._pid_exists", lambda pid: True)
    monkeypatch.setattr("hermes_cli.process_identity._process_create_time", lambda pid=None: 5000.0)
    live = {"phase": "running", "pid": 4242, "start_time": 5003.7, "started_at": "x"}

    _write_sentinel(tmp_path, {**live, "create_time": 5000.0})
    assert detect_unclean_exit(home=tmp_path) is None  # same incarnation still alive: handover

    _write_sentinel(tmp_path, {**live, "create_time": 4000.0})
    assert detect_unclean_exit(home=tmp_path) is not None  # PID reused by another process: death

    # Pre-stamp sentinel (no create_time): the owner was born before it claimed; a reuser after.
    _write_sentinel(tmp_path, live)  # birth 5000.0 <= claim 5003.7 → owner
    assert detect_unclean_exit(home=tmp_path) is None
    _write_sentinel(tmp_path, {**live, "start_time": 4000.0})  # born after the claim → reuser → death
    assert detect_unclean_exit(home=tmp_path) is not None


# ---------------------------------------------------------------------------
# Discriminating reboot evidence — VM reboot vs SIGKILL/OOM
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_real_host_probe(monkeypatch) -> None:
    """Keep the suite off the real Windows event log.

    Every test below either wants no host evidence or installs its own canned
    result; PowerShell's own output is covered by the ``_parse_host_probe`` tests,
    which feed in the exact lines the probe prints.
    """
    monkeypatch.setattr("gateway.lifecycle_ledger._host_restart_evidence",
                        lambda boot_epoch, since_epoch: None)


def _unclean_life(home: Path, started: float, heartbeat: float | None = None) -> None:
    """A dead ``phase=running`` life that began at ``started`` and was last seen beating at ``heartbeat``."""
    _write_sentinel(home, {
        "phase": "running",
        "pid": _DEAD_PID,
        "start_time": started,
        "started_at": datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
    })
    if heartbeat is not None:
        _write_heartbeat(home, {
            "updated_at": datetime.fromtimestamp(heartbeat, tz=timezone.utc).isoformat(),
            "mem": {"mem_total_kib": 1024 * 1024, "mem_available_kib": 512 * 1024},
        })


def _warned(caplog, home: Path) -> str:
    """Run the boot report and return everything logged at WARNING for this module."""
    with caplog.at_level(logging.WARNING, logger="gateway.lifecycle_ledger"):
        assert record_startup(home=home) is not None
    return caplog.text


def test_rebooted_guest_is_named_and_reordered_in_the_warning(tmp_path: Path, caplog, monkeypatch) -> None:
    """The gate: an unclean life plus a NEWER boot must say ``VM REBOOTED``, and the hint list must
    lead with the external-shutdown explanation instead of the generic SIGKILL/OOM list."""
    now = time.time()
    _unclean_life(tmp_path, started=now - 3600, heartbeat=now - 1800)
    monkeypatch.setattr("gateway.lifecycle_ledger._guest_boot_time", lambda: now - 60)

    text = _warned(caplog, tmp_path)

    assert "exited UNCLEANLY (no exit path ran — EXTERNAL SHUTDOWN FIRST" in text
    assert "check Windows Event 1074 first" in text
    assert "exited UNCLEANLY (no exit path ran — SIGKILL" not in text
    assert "VM REBOOTED between lives (new WSL boot " in text
    assert " > prior last seen " in text
    # The evidence is persisted with the exit-diag record, not just printed.
    record = _exit_diag_records(tmp_path)[-1]
    assert record["vm_rebooted"] is True
    assert record["wsl_boot_at"] > record["prior_last_seen_at"]


def test_same_boot_death_keeps_the_existing_warning_verbatim(tmp_path: Path, caplog, monkeypatch) -> None:
    """A death inside a live guest (boot older than both marks) must not claim a reboot, and its
    warning must stay exactly what it says today."""
    now = time.time()
    _unclean_life(tmp_path, started=now - 3600, heartbeat=now - 1800)
    monkeypatch.setattr("gateway.lifecycle_ledger._guest_boot_time", lambda: now - 7200)

    text = _warned(caplog, tmp_path)

    assert "exited UNCLEANLY (no exit path ran — SIGKILL / OOM / VM death, or a process kill issued by " in text
    assert "VM REBOOTED" not in text
    assert " | evidence: " not in text
    assert "vm_rebooted" not in _exit_diag_records(tmp_path)[-1]


def test_unknown_prior_timestamps_make_no_reboot_claim(tmp_path: Path, caplog, monkeypatch) -> None:
    """No start and no heartbeat ⇒ the comparison cannot be made, so nothing is asserted."""
    _write_sentinel(tmp_path, {"phase": "running", "pid": _DEAD_PID})
    monkeypatch.setattr("gateway.lifecycle_ledger._guest_boot_time", lambda: time.time() - 60)

    text = _warned(caplog, tmp_path)

    assert "VM REBOOTED" not in text
    assert "exited UNCLEANLY (no exit path ran — SIGKILL" in text


def test_host_restart_event_names_the_orderer(tmp_path: Path, caplog, monkeypatch) -> None:
    """A 1074 in the death window is the orderer: the warning must carry its time, who ordered it,
    and the host's vmIdleTimeout, and all of it must reach the exit-diag record."""
    now = time.time()
    _unclean_life(tmp_path, started=now - 3600, heartbeat=now - 1800)
    monkeypatch.setattr("gateway.lifecycle_ledger._guest_boot_time", lambda: now - 60)
    monkeypatch.setattr(
        "gateway.lifecycle_ledger._host_restart_evidence",
        lambda boot_epoch, since_epoch: (
            {"status": "hit", "at": "2026-10-05T16:29:33Z", "sid": "S-1-5-21-427566232-1001",
             "message": 'Prozess "C:\\\\WINDOWS\\\\Explorer.EXE (YODA)" im Auftrag von "YODA\\\\gk"'},
            {"status": "set", "path": "C:\\Users\\gk\\.wslconfig", "line": "vmIdleTimeout=-1"},
        ),
    )

    text = _warned(caplog, tmp_path)

    assert "Windows Event 1074 ordered at 2026-10-05T16:29:33Z by Prozess" in text
    assert "Explorer.EXE (YODA)" in text
    assert "vmIdleTimeout=-1 (C:\\Users\\gk\\.wslconfig)" in text
    record = _exit_diag_records(tmp_path)[-1]
    assert record["host_restart_1074"]["status"] == "hit"
    assert record["host_restart_1074"]["at"] == "2026-10-05T16:29:33Z"
    assert record["vm_idle_timeout"]["line"] == "vmIdleTimeout=-1"


def test_no_host_restart_event_points_at_external_shutdown(tmp_path: Path, caplog, monkeypatch) -> None:
    """Probed, and the host ordered NOTHING in the window — the claim that matters most, because it
    is what separates an external ``wsl --shutdown`` from a user restart."""
    now = time.time()
    _unclean_life(tmp_path, started=now - 3600, heartbeat=now - 1800)
    monkeypatch.setattr("gateway.lifecycle_ledger._guest_boot_time", lambda: now - 60)
    monkeypatch.setattr(
        "gateway.lifecycle_ledger._host_restart_evidence",
        lambda boot_epoch, since_epoch: (
            {"status": "none"},
            {"status": "absent", "path": "C:\\Users\\gk\\.wslconfig"},
        ),
    )

    text = _warned(caplog, tmp_path)

    assert "no Windows Event 1074 in that window — NOT a user/OS-ordered restart" in text
    assert "external `wsl --shutdown` / WSL service stop, not OOM" in text
    assert "vmIdleTimeout not set in C:\\Users\\gk\\.wslconfig" in text


def test_unavailable_host_probe_omits_its_clauses_only(tmp_path: Path, caplog, monkeypatch) -> None:
    """PowerShell absent/failed ⇒ no host clauses at all, but the reboot itself is still reported
    and the warning still fires (forensics never block boot)."""
    now = time.time()
    _unclean_life(tmp_path, started=now - 3600, heartbeat=now - 1800)
    monkeypatch.setattr("gateway.lifecycle_ledger._guest_boot_time", lambda: now - 60)

    text = _warned(caplog, tmp_path)

    assert "VM REBOOTED between lives" in text
    assert "Windows Event 1074 ordered at" not in text
    assert "no Windows Event 1074 in that window" not in text
    assert "vmIdleTimeout" not in text
    assert _exit_diag_records(tmp_path)[-1]["vm_rebooted"] is True


def test_probe_script_bounds_the_death_window() -> None:
    """The window must run from the previous life's last sighting to THIS boot, so an orderer from
    an earlier life can never be attributed to this death."""
    from gateway.lifecycle_ledger import _host_probe_script

    script = _host_probe_script(1791223627.0, 1791224314.0)
    assert "FromUnixTimeSeconds(1791223627)" in script
    assert "FromUnixTimeSeconds(1791224316)" in script  # boot + _HOST_PROBE_SLACK_S
    assert "EndTime=$ew" in script and "Id=1074" in script
    assert "FullyQualifiedErrorId" in script  # the "no events" text is localized, the id is not


def test_probe_script_delimiters_balance() -> None:
    """A stray ``}}`` is a PowerShell parse error, and nothing else in this suite executes the
    generated script — so an unbalanced brace would silently drop every clause the probe exists
    to supply (it was caught this way on 2026-10-05)."""
    from gateway.lifecycle_ledger import _host_probe_script

    script = _host_probe_script(1791223627.0, 1791224314.0)
    for opening, closing in (("{", "}"), ("(", ")")):
        assert script.count(opening) == script.count(closing), f"unbalanced {opening}{closing}: {script}"


@pytest.mark.platforms("windows")
def test_probe_script_parses_in_a_real_powershell() -> None:
    """The generated PowerShell itself: it is the one part no other test runs, and a script that
    does not parse returns nothing, which reads as "no evidence" rather than as an error."""
    import shutil

    from gateway.lifecycle_ledger import _host_probe_script

    hosts = [found for name in ("powershell.exe", "powershell", "pwsh") if (found := shutil.which(name))]
    if not hosts:
        pytest.skip("no PowerShell host")
    result = subprocess.run(
        [hosts[0], "-NoProfile", "-Command", _host_probe_script(time.time() - 3600, time.time())],
        capture_output=True, encoding="utf-8", errors="replace", timeout=30,
    )
    stdout = result.stdout or ""
    assert "EVENT|" in stdout, (result.returncode, stdout, result.stderr)
    assert "IDLE|" in stdout, (result.returncode, stdout, result.stderr)


def test_parse_host_probe_reads_the_exact_lines_the_probe_prints() -> None:
    from gateway.lifecycle_ledger import _parse_host_probe

    message = 'Vom Prozess "C:\\WINDOWS\\Explorer.EXE (YODA)" auf Anforderung von "YODA\\gk"'
    stdout = (
        "EVENT|HIT|2026-10-05T16:29:33Z|S-1-5-21-427566232-1001|"
        + base64.b64encode(message.encode("utf-8")).decode("ascii")
        + "\nIDLE|set|C:\\Users\\gk\\.wslconfig|vmIdleTimeout=-1\n"
    )
    assert _parse_host_probe(stdout) == (
        {"status": "hit", "at": "2026-10-05T16:29:33Z", "sid": "S-1-5-21-427566232-1001", "message": message},
        {"status": "set", "path": "C:\\Users\\gk\\.wslconfig", "line": "vmIdleTimeout=-1"},
    )

    assert _parse_host_probe("EVENT|NONE\nIDLE|absent|C:\\Users\\gk\\.wslconfig\n") == (
        {"status": "none"},
        {"status": "absent", "path": "C:\\Users\\gk\\.wslconfig"},
    )
    # Real event messages are multi-line: one warning line must stay one line.
    multi = base64.b64encode("Ursachencode: 0x80000000\r\nHerunterfahrtyp: neu starten".encode()).decode()
    assert _parse_host_probe(f"EVENT|HIT|2026-10-05T16:29:33Z|S-1-5-21-1001|{multi}\n")[0] == {
        "status": "hit", "at": "2026-10-05T16:29:33Z", "sid": "S-1-5-21-1001",
        "message": "Ursachencode: 0x80000000 Herunterfahrtyp: neu starten",
    }
    # A failed query is UNKNOWN — never read as "the host ordered nothing".
    assert _parse_host_probe("EVENT|ERR\nIDLE|nofile\n") == ({"status": "unknown"}, {"status": "no_file"})
    assert _parse_host_probe("") == (None, None)
    assert _parse_host_probe(None) == (None, None)
