"""``kanban.max_spawn`` is a live concurrency cap, not a per-tick spawn rate.

``_tick_spawn_budget`` reads ``max_spawn`` against ``running_count`` — the
number of tasks *already* ``running`` on the board — so the cap holds
concurrency flat instead of admitting one worker per tick until the board
happens to fill. That is the opposite of what the CLI help text used to
promise ("Cap number of spawns this pass" / "per tick"), and the key had no
row in the config reference at all, which is how an operator ends up
debugging a "stuck dispatcher" warning that is really an idle-by-design tick.

These tests pin the two public statements of that semantics -- the ``--max``
help strings and the docs row -- against the real dispatch behaviour, so the
wording cannot drift back to promising a per-pass rate.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import kanban_db_dispatch as kbd
from hermes_cli import kanban_parser

_REPO_ROOT = Path(__file__).resolve().parents[2]
_KANBAN_DOC = _REPO_ROOT / "website" / "docs" / "user-guide" / "features" / "kanban.md"


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    """Isolated HERMES_HOME with an empty kanban DB."""
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


def _fake_spawn_factory(spawns):
    def fake_spawn(task, workspace, board=None):
        spawns.append(task.id)
        return 42

    return fake_spawn


def test_max_spawn_holds_concurrency_not_a_per_tick_rate(
    kanban_home, all_assignees_spawnable, monkeypatch,
):
    """The behaviour the docs and help text claim: N running + max_spawn N = idle.

    Under a per-tick reading this test's second tick would spawn another
    worker every tick until the board filled; under the real (concurrency)
    semantics it stays at exactly ``max_spawn`` running indefinitely.
    """
    monkeypatch.setattr(kbd, "_memory_pressure_level", lambda *a, **k: "unknown")
    spawns: list = []
    with kbc.connect() as conn:
        running = kb.create_task(conn, title="running", assignee="alice")
        assert kb.claim_task(conn, running) is not None
        for i in range(3):
            kb.create_task(conn, title=f"ready-{i}", assignee="alice")

        # Three consecutive ticks at max_spawn=1.
        results = [
            kbd.dispatch_once(conn, spawn_fn=_fake_spawn_factory(spawns), max_spawn=1)
            for _ in range(3)
        ]

    assert not spawns, (
        "max_spawn=1 with 1 already running must spawn nothing on any tick "
        f"(concurrency cap), got {spawns!r}"
    )
    assert all(not res.spawned for res in results)


def test_max_spawn_allows_a_slot_once_one_finishes(
    kanban_home, all_assignees_spawnable, monkeypatch,
):
    """The cap defers, it does not drop: a freed slot admits the next card."""
    monkeypatch.setattr(kbd, "_memory_pressure_level", lambda *a, **k: "unknown")
    spawns: list = []
    with kbc.connect() as conn:
        running = kb.create_task(conn, title="running", assignee="alice")
        assert kb.claim_task(conn, running) is not None
        ready_id = kb.create_task(conn, title="waiting", assignee="alice")

        first = kbd.dispatch_once(conn, spawn_fn=_fake_spawn_factory(spawns), max_spawn=1)
        assert not first.spawned

        conn.execute("UPDATE tasks SET status = 'done' WHERE id = ?", (running,))
        conn.execute(
            "UPDATE tasks SET claim_lock = NULL, claim_expires = NULL, "
            "worker_pid = NULL, current_run_id = NULL WHERE id = ?",
            (running,),
        )
        second = kbd.dispatch_once(conn, spawn_fn=_fake_spawn_factory(spawns), max_spawn=1)

    assert [task_id for task_id, *_ in second.spawned] == [ready_id]


def _max_help_texts() -> dict[str, str]:
    """Map each kanban subcommand exposing ``--max`` to that flag's help string.

    Built through the public ``build_parser`` seam rather than by reaching
    into argparse internals, so the test keeps working if the parser's
    internal layout changes.
    """
    root = argparse.ArgumentParser(prog="hermes")
    sub = root.add_subparsers(dest="_cmd")
    kanban = kanban_parser.build_parser(sub)

    helps: dict[str, str] = {}
    for action in kanban._subparsers._group_actions:  # noqa: SLF001
        for name, subparser in getattr(action, "choices", {}).items():
            for opt in subparser._actions:  # noqa: SLF001
                if opt.dest == "max":
                    helps[name] = opt.help or ""
    return helps


def test_dispatch_max_help_text_does_not_promise_a_per_pass_rate():
    """``hermes kanban dispatch --max`` must not say "spawns this pass".

    That wording described a per-pass rate; the flag is a per-board
    concurrency cap. An operator who reads "one spawn per pass" and sets
    ``--max 1`` on a live board gets a silent no-op instead.
    """
    helps = _max_help_texts()
    assert helps, "could not locate the --max arguments in the kanban parser"
    for command, help_text in helps.items():
        lowered = help_text.lower()
        assert "spawns this pass" not in lowered, (
            f"`{command} --max` help still promises a per-pass spawn rate: {help_text!r}"
        )
        assert "concurrency" in lowered, (
            f"`{command} --max` help must name the concurrency semantics, "
            f"got {help_text!r}"
        )


def test_max_spawn_has_a_config_reference_row():
    """The key is documented in the concurrency table with its real meaning."""
    assert _KANBAN_DOC.is_file(), f"kanban doc not found at {_KANBAN_DOC}"
    text = _KANBAN_DOC.read_text(encoding="utf-8")

    row = next(
        (
            line
            for line in text.splitlines()
            if line.startswith("| `kanban.max_spawn`")
        ),
        None,
    )
    assert row is not None, (
        "kanban.max_spawn has no row in the concurrency config table — an "
        "undocumented cap is indistinguishable from a silent dispatcher hang"
    )
    lowered = row.lower()
    assert "concurrency" in lowered, (
        f"the max_spawn row must state the concurrency semantics: {row!r}"
    )
    # The trap the card was filed against: the key reads like a rate, not a
    # ceiling, so the row must actively DISPEL that reading rather than merely
    # fail to mention it. (Checked as an explicit negated phrase, not a regex
    # over the prose -- markdown emphasis like "*not* a per-tick spawn rate"
    # defeats word-level lookbehinds.)
    flat = lowered.replace("*", "").replace("**", "")
    assert re.search(r"not\s+a\s+per[- ]tick\s+(spawn\s+)?(rate|budget)", flat), (
        f"the max_spawn row must explicitly deny the per-tick-rate reading: {row!r}"
    )


def test_max_spawn_row_points_at_the_other_concurrency_axes():
    """Cross-reference so an operator can find the right knob per axis."""
    row = next(
        line
        for line in _KANBAN_DOC.read_text(encoding="utf-8").splitlines()
        if line.startswith("| `kanban.max_spawn`")
    )
    assert "max_in_progress" in row and "max_in_progress_per_profile" in row, (
        f"the max_spawn row should name the host-wide and per-profile caps: {row!r}"
    )
