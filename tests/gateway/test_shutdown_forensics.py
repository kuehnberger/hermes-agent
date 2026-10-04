"""Tests for gateway.shutdown_forensics — fast snapshot + async diag spawn."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

import pytest

from gateway import shutdown_forensics as sf

# ---------------------------------------------------------------------------
# _signal_name
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# snapshot_shutdown_context
# ---------------------------------------------------------------------------

class TestSnapshotShutdownContext:

    def test_detects_takeover_marker_for_self(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        marker = tmp_path / ".gateway-takeover.json"
        marker.write_text(
            f'{{"target_pid": {os.getpid()}, "replacer_pid": 99999}}',
            encoding="utf-8",
        )
        ctx = sf.snapshot_shutdown_context(signal.SIGTERM)
        assert "takeover_marker" in ctx
        assert ctx["takeover_marker_for_self"] is True

# ---------------------------------------------------------------------------
# format_context_for_log / context_as_json
# ---------------------------------------------------------------------------

class TestFormatters:

    def test_context_as_json_handles_unserialisable_values(self):
        ctx = {"signal": "SIGTERM", "weird": object()}
        payload = sf.context_as_json(ctx)
        # default=str means objects get repr'd, JSON stays valid
        decoded = json.loads(payload)
        assert decoded["signal"] == "SIGTERM"
        assert "weird" in decoded

# ---------------------------------------------------------------------------
# persisted snapshots must never include process argv (#112459)
# ---------------------------------------------------------------------------

_ARGV_CANARY = "lin_api_CANARY_SHUTDOWN_FORENSICS_9f3a2c"

@pytest.fixture
def child_with_secret_argv():
    """A live child whose argv carries a token-shaped value, like ``docker exec -e KEY=...``."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)", f"--token={_ARGV_CANARY}"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        yield proc
    finally:
        proc.kill()
        proc.wait()

class TestArgvFreePersistence:

    @pytest.mark.platforms("linux")
    def test_snapshot_and_log_line_identify_process_without_argv(self, child_with_secret_argv):
        """/proc-backed summaries keep pid/name/ppid/state but never the command line, so neither
        the JSON snapshot nor the warning line can carry a credential from a parent's argv."""
        summary = sf._proc_summary(child_with_secret_argv.pid)
        assert summary["pid"] == child_with_secret_argv.pid
        assert summary["name"]  # identity survives
        assert "cmdline" not in summary

        ctx = sf.snapshot_shutdown_context(signal.SIGTERM)
        ctx["parent"] = summary
        line = sf.format_context_for_log(ctx)
        assert _ARGV_CANARY not in line and _ARGV_CANARY not in sf.context_as_json(ctx)
        assert f"parent_pid={child_with_secret_argv.pid}" in line

# ---------------------------------------------------------------------------
# spawn_async_diagnostic
# ---------------------------------------------------------------------------

class TestSpawnAsyncDiagnostic:
    @pytest.mark.platforms("linux")
    def test_spawns_subprocess_and_writes_output(self, tmp_path):
        self._assert_diagnostic_written(tmp_path)

    @pytest.mark.platforms("macos")
    def test_spawns_without_gnu_timeout_on_macos(self, tmp_path):
        """Stock macOS has no ``timeout`` binary and BSD ``ps``; the diagnostic still lands."""
        self._assert_diagnostic_written(tmp_path)

    @staticmethod
    def _assert_diagnostic_written(tmp_path):
        log_path = tmp_path / "diag.log"
        pid = sf.spawn_async_diagnostic(log_path, "SIGTERM", timeout_seconds=3.0)
        assert pid is not None and pid > 0

        # Wait briefly for the subprocess to write — bounded by its own timeout.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if log_path.exists() and log_path.stat().st_size > 0:
                # Wait a touch longer for the script to finish writing
                time.sleep(0.2)
                break
            time.sleep(0.1)

        # Reap the subprocess so it doesn't show up as a zombie.
        try:
            os.waitpid(pid, 0)
        except (ChildProcessError, OSError):
            pass

        assert log_path.exists()
        contents = log_path.read_text(encoding="utf-8", errors="replace")
        assert "shutdown diagnostic" in contents
        assert "SIGTERM" in contents
        lines = contents.splitlines()
        ps_section = lines[lines.index("--- ps (top 60 by cpu, comm only) ---") + 1:]
        assert ps_section and ps_section[0].split()[:2] == ["PID", "PPID"], \
            "ps column header must lead the listing, not sort as a 0.0-cpu row"

    @pytest.mark.platforms("linux")
    def test_diagnostic_log_omits_child_argv_and_is_owner_only(self, tmp_path, child_with_secret_argv):
        """The detached ps/pstree walk must not write any process's argv to disk, and the log
        (even one created 0644 by an earlier release) ends up owner-only."""
        log_path = tmp_path / "diag.log"
        log_path.write_text("prior\n", encoding="utf-8")
        os.chmod(log_path, 0o644)

        pid = sf.spawn_async_diagnostic(log_path, "SIGTERM", timeout_seconds=5.0)
        assert pid is not None
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            try:
                if os.waitpid(pid, os.WNOHANG)[0] == pid:
                    break
            except ChildProcessError:
                break
            time.sleep(0.1)

        contents = log_path.read_text(encoding="utf-8", errors="replace")
        assert "shutdown diagnostic" in contents
        assert _ARGV_CANARY not in contents
        assert (log_path.stat().st_mode & 0o777) == 0o600

# ---------------------------------------------------------------------------
# parse_systemd_duration_to_us
# ---------------------------------------------------------------------------

class TestParseSystemdDuration:
    def test_seconds(self):
        assert sf.parse_systemd_duration_to_us("90s") == 90 * 1_000_000

    def test_minutes(self):
        assert sf.parse_systemd_duration_to_us("3min") == 180 * 1_000_000

# ---------------------------------------------------------------------------
# _systemd_timeout_stop_us (#132565)
# ---------------------------------------------------------------------------

class _FakeCompleted:
    def __init__(self, returncode: int, stdout: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


def _systemctl_stub(monkeypatch, per_flag: dict):
    """Run argv -> _FakeCompleted from `per_flag` ("--user" / ""), recording the calls."""
    calls: list[list[str]] = []

    def _fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        assert "--user" in cmd or cmd.index("systemctl") == 0
        for key, value in per_flag.items():
            if key == "user" and "--user" in cmd:
                return _FakeCompleted(0, value)
            if key == "system" and "--user" not in cmd:
                return _FakeCompleted(0, value)
        return _FakeCompleted(1, "")

    monkeypatch.setattr(sf.subprocess, "run", _fake_run)
    return calls


class TestSystemdTimeoutStopUs:
    def test_system_unit_not_found_in_user_manager_falls_through(self, monkeypatch):
        """A system-only unit: `systemctl --user show` answers rc=0 with the DEFAULT 1min 30s.
        That default must not win — the system manager's value (#132565) does."""
        calls = _systemctl_stub(monkeypatch, {
            "user": "LoadState=not-found\nTimeoutStopUSec=1min 30s\n",
            "system": "LoadState=loaded\nTimeoutStopUSec=3min 30s\n",
        })
        assert sf._systemd_timeout_stop_us("hermes-gateway.service") == 210 * 1_000_000
        assert len(calls) == 2, "the system query must still be issued"
        assert "--user" in calls[0] and "--user" not in calls[1]

    def test_user_unit_still_wins(self, monkeypatch):
        calls = _systemctl_stub(monkeypatch, {
            "user": "LoadState=loaded\nTimeoutStopUSec=1min 30s\n",
            "system": "LoadState=loaded\nTimeoutStopUSec=10min\n",
        })
        assert sf._systemd_timeout_stop_us("hermes-gateway.service") == 90 * 1_000_000
        assert len(calls) == 1, "a user unit must not trigger a system query"

    def test_numeric_microseconds(self, monkeypatch):
        _systemctl_stub(monkeypatch, {
            "user": "LoadState=loaded\nTimeoutStopUSec=210000000\n",
            "system": "",
        })
        assert sf._systemd_timeout_stop_us("hermes-gateway.service") == 210_000_000

    def test_unit_in_no_manager_returns_none(self, monkeypatch):
        """Both managers not-found -> undeterminable, not the 90s default."""
        _systemctl_stub(monkeypatch, {
            "user": "LoadState=not-found\nTimeoutStopUSec=1min 30s\n",
            "system": "LoadState=not-found\nTimeoutStopUSec=1min 30s\n",
        })
        assert sf._systemd_timeout_stop_us("nope.service") is None

    def test_missing_loadstate_defaults_to_loaded(self, monkeypatch):
        """Older systemd without LoadState in the answer: keep the pre-existing behaviour."""
        _systemctl_stub(monkeypatch, {"user": "TimeoutStopUSec=2min\n", "system": ""})
        assert sf._systemd_timeout_stop_us("hermes-gateway.service") == 120 * 1_000_000

    def test_masked_unit_with_unit_file_still_counted(self, monkeypatch):
        _systemctl_stub(monkeypatch, {
            "user": "LoadState=masked\nTimeoutStopUSec=4min\n", "system": ""})
        assert sf._systemd_timeout_stop_us("hermes-gateway.service") == 240 * 1_000_000

    def test_nonzero_returncode_skipped(self, monkeypatch):
        _systemctl_stub(monkeypatch, {
            "user": "LoadState=loaded\nTimeoutStopUSec=1min 30s\n", "system": ""})
        monkeypatch.setattr(sf.subprocess, "run",
                            lambda cmd, **kw: _FakeCompleted(1, "TimeoutStopUSec=1min 30s\n"))
        assert sf._systemd_timeout_stop_us("hermes-gateway.service") is None

    def test_systemd_alignment_no_false_mismatch_for_system_unit(self, monkeypatch):
        """End-to-end: a system unit sized for the stop budget must not warn 'stale unit'."""
        monkeypatch.setenv("INVOCATION_ID", "deadbeef")
        cgroup = "0::/system.slice/hermes-gateway.service\n"

        class _FakeFile:
            def __enter__(self_inner): return self_inner
            def __exit__(self_inner, *exc): return False
            def __iter__(self_inner): return iter(cgroup.splitlines(True))

        monkeypatch.setattr(sf, "open", lambda *a, **kw: _FakeFile(), raising=False)
        _systemctl_stub(monkeypatch, {
            "user": "LoadState=not-found\nTimeoutStopUSec=1min 30s\n",
            "system": "LoadState=loaded\nTimeoutStopUSec=210s\n",
        })
        result = sf.check_systemd_timing_alignment(drain_timeout=30.0, cron_drain_timeout=30.0)
        assert result is not None
        assert result["unit"] == "hermes-gateway.service"
        assert result["timeout_stop_sec"] == 210.0
        assert result["mismatch"] is False, result

    def test_systemd_alignment_still_flags_genuinely_stale_system_unit(self, monkeypatch):
        monkeypatch.setenv("INVOCATION_ID", "deadbeef")
        cgroup = "0::/system.slice/hermes-gateway.service\n"

        class _FakeFile2:
            def __enter__(self_inner): return self_inner
            def __exit__(self_inner, *exc): return False
            def __iter__(self_inner): return iter(cgroup.splitlines(True))

        monkeypatch.setattr(sf, "open", lambda *a, **kw: _FakeFile2(), raising=False)
        _systemctl_stub(monkeypatch, {
            "user": "LoadState=not-found\nTimeoutStopUSec=1min 30s\n",
            "system": "LoadState=loaded\nTimeoutStopUSec=60s\n",
        })
        result = sf.check_systemd_timing_alignment(drain_timeout=30.0, cron_drain_timeout=30.0)
        assert result is not None
        assert result["timeout_stop_sec"] == 60.0
        assert result["mismatch"] is True, result

# ---------------------------------------------------------------------------
# check_systemd_timing_alignment
# ---------------------------------------------------------------------------
