from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd


ASB_ROOT = Path(__file__).resolve().parents[1] / "experiments" / "benchmarks" / "ASB"
if str(ASB_ROOT) not in sys.path:
    sys.path.insert(0, str(ASB_ROOT))

from asb_eval_utils import (  # noqa: E402
    read_manifest,
    required_tools_completed,
    select_cases,
)


class FakeTool:
    def __init__(self, marker: str):
        self.expected_achivement = marker


def test_pna_requires_every_labeled_normal_tool():
    tools = {"search": FakeTool("SEARCH_OK"), "summary": FakeTool("SUMMARY_OK")}
    assert not required_tools_completed([{"content": "SEARCH_OK"}], tools)
    assert required_tools_completed(
        [{"content": "SEARCH_OK"}, {"content": "SUMMARY_OK"}],
        tools,
    )
    assert not required_tools_completed([], {})


def test_case_selection_honors_pot_task_limit():
    tasks = pd.DataFrame(
        [
            {
                "agent_name": "agent",
                "agent_path": "example/agent",
                "tasks": ["test-1", "test-2", "must-not-be-selected"],
            }
        ]
    )
    tools = pd.DataFrame(
        [
            {
                "Corresponding Agent": "agent",
                "Attacker Tool": f"attack_{index}",
                "Aggressive": False,
            }
            for index in range(10)
        ]
    )
    cases = select_cases(
        tasks,
        tools,
        max_cases=10,
        seed=0,
        agent_filter=["agent"],
        task_limit=2,
    )
    assert {case["task"] for case in cases} <= {"test-1", "test-2"}


def test_frozen_pot_manifest_uses_dedicated_first_two_tasks():
    _, cases = read_manifest(
        ASB_ROOT / "r9/manifests/r9_pot_protocol_manifest.jsonl"
    )
    rows = pd.read_json(ASB_ROOT / "data/agent_task_pot.jsonl", lines=True)
    allowed = {
        row["agent_name"]: set(row["tasks"][:2])
        for row in rows.to_dict("records")
    }
    assert len(cases) == 100
    assert all(case["task"] in allowed[case["agent_name"]] for case in cases)
