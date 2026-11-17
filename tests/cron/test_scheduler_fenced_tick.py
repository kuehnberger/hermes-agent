"""Behavior contract: the IN-PROCESS cron ticker holds its agent jobs while an update owns
the install (the fence), so a fenced tick DEFERS the fire instead of skipping it.

Why this exists
---------------
``cron/scheduler_gateway_gate.py`` already holds a HEADLESS tick's agent jobs when no ready
gateway serves the home ("Down" includes draining). Its own docstring says the rest:

    "The in-process ticker never reaches this gate: it runs inside the gateway by definition."

That leaves the in-process ticker - the one the gateway itself runs every 60 s - dispatching
agent jobs while the install is fenced. The gateway then refuses the agent's connect
("draining: update_paused"), but by then ``cron/monitor.py::check_monitor`` has ALREADY
persisted ``monitor_state.last_output_hash``. The next tick reads the same hash, sees
``changed=False`` and suppresses the agent run: the change is never delivered and never
re-alerted. The blind window is silent.

The contract
------------
* fenced  -> the agent jobs are held (skipped, NOT failed), the no_agent jobs still run, the
  dispatch marks are dropped so the due instant does not move, and the monitor state is never
  touched (the monitor gate never runs at all).
* not fenced -> every due job is dispatched, exactly as before.
* the fence cannot be read -> fail OPEN (dispatch as usual): a broken import must never stop
  the tick.
"""

import pathlib

import pytest

from cron import scheduler_gateway_gate as gate


def _job(job_id, *, no_agent=False):
    return {"id": job_id, "no_agent": no_agent}


@pytest.fixture()
def noted(monkeypatch):
    """Capture the fire-refusal notes instead of touching the jobs store."""
    calls = []
    monkeypatch.setattr(gate, "_note_fire_refused", lambda ids, detail: calls.append((list(ids), detail)))
    return calls


@pytest.fixture()
def fenced(monkeypatch):
    """Control the fence verdict through the helper the gate imports."""
    state = {"value": False}

    def _fake_update_fenced(homes):
        state["homes"] = homes
        return state["value"]

    import hermes_cli.gateway_runtime as runtime

    monkeypatch.setattr(runtime, "_update_fenced", _fake_update_fenced)
    return state


class TestFencedTick:
    def test_fenced_holds_agent_jobs_and_keeps_script_jobs(self, fenced, noted):
        fenced["value"] = True
        due = [_job("a1"), _job("s1", no_agent=True), _job("a2")]

        kept = gate.refuse_agent_jobs_while_fenced(due)

        assert [j["id"] for j in kept] == ["s1"]
        assert len(noted) == 1
        assert sorted(noted[0][0]) == ["a1", "a2"]
        assert "fenced" in noted[0][1]

    def test_not_fenced_dispatches_everything(self, fenced, noted):
        fenced["value"] = False
        due = [_job("a1"), _job("s1", no_agent=True)]

        kept = gate.refuse_agent_jobs_while_fenced(due)

        assert [j["id"] for j in kept] == ["a1", "s1"]
        assert noted == []

    def test_script_only_tick_is_untouched(self, fenced, noted):
        fenced["value"] = True
        due = [_job("s1", no_agent=True)]

        kept = gate.refuse_agent_jobs_while_fenced(due)

        assert [j["id"] for j in kept] == ["s1"]
        assert noted == []

    def test_empty_tick_is_untouched(self, fenced, noted):
        fenced["value"] = True

        assert gate.refuse_agent_jobs_while_fenced([]) == []
        assert noted == []

    def test_the_fence_is_read_over_the_hermes_homes(self, fenced, noted):
        """The install-root marker also covers profiles, so the check must span the
        process home, the active home and the default root (they collapse to one path in
        a test environment, so assert the SET and its content, not its size)."""
        fenced["value"] = True

        gate.refuse_agent_jobs_while_fenced([_job("a1")])

        homes = fenced["homes"]
        assert homes, "the fence must be read over at least one Hermes home"
        assert all(isinstance(h, pathlib.PurePath) for h in homes)
        assert any(str(h) for h in homes)

    def test_a_broken_fence_check_fails_open(self, monkeypatch, noted):
        """A gate that cannot read the fence must not stop the tick."""
        import hermes_cli.gateway_runtime as runtime

        def _boom(homes):
            raise RuntimeError("no marker for you")

        monkeypatch.setattr(runtime, "_update_fenced", _boom)
        due = [_job("a1")]

        kept = gate.refuse_agent_jobs_while_fenced(due)

        assert [j["id"] for j in kept] == ["a1"]
        assert noted == []
