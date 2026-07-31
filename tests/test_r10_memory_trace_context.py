from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

ASB_ROOT = Path(__file__).resolve().parents[1] / "experiments" / "benchmarks" / "ASB"
if str(ASB_ROOT) not in sys.path:
    sys.path.insert(0, str(ASB_ROOT))

from pyopenagi.agents.react_agent_attack import (  # noqa: E402
    _append_memory_trace,
    clear_memory_trace_context,
    set_memory_trace_context,
)


def test_memory_trace_context_is_thread_local(tmp_path: Path, monkeypatch):
    path = tmp_path / "events.jsonl"
    monkeypatch.setenv("ASB_MEMORY_TRACE_FILE", str(path))

    def worker(sample_id: str):
        set_memory_trace_context(sample_id=sample_id, ablation_mode="full")
        _append_memory_trace({"memory_search": sample_id, "pair_hit": True})
        clear_memory_trace_context()

    threads = [threading.Thread(target=worker, args=(f"s{i}",)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert {row["sample_id"] for row in rows} == {"s0", "s1", "s2", "s3"}
    assert all(row["ablation_mode"] == "full" for row in rows)
    assert all(row["pair_hit"] is True for row in rows)
