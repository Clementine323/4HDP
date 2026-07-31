"""Shared utilities for reproducible ASB experiments used by 4HDP.

The helpers keep sample selection identical across defended runs, baseline runs,
ablations, and timing experiments.  They do not expose attack labels or attack
success oracles to the 4HDP auditor; they are used only by experiment drivers.
"""
from __future__ import annotations

import json
import os
import random
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

import pandas as pd

HIGH_RISK_AGENT_FILTER = [
    "financial_analyst_agent",
    "legal_consultant_agent",
    "medical_advisor_agent",
]


def parse_agent_filter(value: Optional[str] = None) -> Optional[List[str]]:
    """Parse FOURHDP_AGENT_FILTER.

    Defaults to the three high-consequence vertical scenarios discussed in the
    paper.  Set FOURHDP_AGENT_FILTER=all to evaluate every ASB role.
    """
    raw = value if value is not None else os.environ.get("FOURHDP_AGENT_FILTER")
    if raw is None or raw.strip() == "":
        return list(HIGH_RISK_AGENT_FILTER)
    raw = raw.strip()
    if raw.lower() in {"all", "*", "none"}:
        return None
    return [x.strip() for x in raw.split(",") if x.strip()]


def _safe_bool(value) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _tool_name(tool_row) -> str:
    try:
        return str(tool_row["Attacker Tool"])
    except Exception:
        return "UnknownTool"


def required_tools_completed(messages: Sequence[dict], normal_tools: dict) -> bool:
    """Return true only when every ASB-labeled normal tool was invoked."""
    if not normal_tools:
        return False
    found_tools = set()
    for message in messages or []:
        content = str(message.get("content") or "")
        for name, instance in normal_tools.items():
            expected = str(getattr(instance, "expected_achivement", "") or "")
            if expected and expected in content:
                found_tools.add(name)
    return all(name in found_tools for name in normal_tools)


def select_cases(
    tasks_df: pd.DataFrame,
    tools_df: pd.DataFrame,
    *,
    max_cases: int,
    seed: int,
    agent_filter: Optional[Sequence[str]] = None,
    task_limit: Optional[int] = None,
) -> List[dict]:
    """Select a balanced, deterministic set of ASB cases.

    Selection is round-robin over the chosen agents, so the default 100-case
    paper setting covers financial, legal, and medical agents rather than being
    an accidental prefix of the ASB task file.
    """
    if max_cases <= 0:
        return []

    rng = random.Random(seed)
    tasks_records = tasks_df.to_dict("records")
    if agent_filter is not None:
        allowed = set(agent_filter)
        tasks_records = [r for r in tasks_records if r.get("agent_name") in allowed]

    if not tasks_records:
        raise ValueError(
            "No ASB agents matched the configured filter. "
            f"FOURHDP_AGENT_FILTER={agent_filter!r}"
        )

    # Shuffle each agent's tools deterministically, but keep the agent order from
    # agent_task.jsonl so manifests are easy to inspect.
    per_agent_tools = {}
    for agent in tasks_records:
        name = agent["agent_name"]
        subset = tools_df[tools_df["Corresponding Agent"] == name]
        per_agent_tools[name] = subset.sample(frac=1, random_state=seed).reset_index(drop=True).to_dict("records")

    cases: List[dict] = []
    cursor = {agent["agent_name"]: 0 for agent in tasks_records}
    while len(cases) < max_cases:
        progressed = False
        for agent in tasks_records:
            if len(cases) >= max_cases:
                break
            name = agent["agent_name"]
            idx = cursor[name]
            tools = per_agent_tools.get(name, [])
            if idx >= len(tools):
                continue
            task_candidates = list(agent.get("tasks") or [])
            if task_limit is not None:
                if task_limit <= 0:
                    raise ValueError("task_limit must be positive when supplied")
                task_candidates = task_candidates[:task_limit]
            if not task_candidates:
                continue
            tool_record = tools[idx]
            if str(tool_record.get("Record Type", "")).strip() == "benign_sampling_index":
                # RQ11 must cover every task template, not merely sample task
                # texts with replacement.  Cycling deterministically preserves
                # balanced role coverage and guarantees all templates appear.
                task_idx = (idx + seed) % len(task_candidates)
            else:
                task_idx = rng.randrange(len(task_candidates))
            case_id = f"seed{seed:03d}_{len(cases):04d}_{name}_{_tool_name(tool_record)}"
            cases.append({
                "case_id": case_id,
                "agent_name": name,
                "agent_path": agent["agent_path"],
                "task": task_candidates[task_idx],
                "task_index": task_idx,
                "attacker_tool": _tool_name(tool_record),
                "aggressive": _safe_bool(tool_record.get("Aggressive", False)),
                "tool_record": tool_record,
            })
            cursor[name] += 1
            progressed = True
        if not progressed:
            break

    return cases


def write_manifest(cases: Sequence[dict], path: str | Path, *, metadata: Optional[dict] = None) -> None:
    """Write a JSONL manifest without embedding large message traces."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        if metadata:
            f.write(json.dumps({"record_type": "metadata", **metadata}, ensure_ascii=False) + "\n")
        for c in cases:
            row = {k: v for k, v in c.items() if k != "tool_record"}
            f.write(json.dumps({"record_type": "case", **row}, ensure_ascii=False) + "\n")


def load_cases_from_data(
    attacker_tools_path: str,
    tasks_path: str,
    *,
    max_cases: int,
    seed: int,
    agent_filter: Optional[Sequence[str]] = None,
    task_limit: Optional[int] = None,
) -> tuple[pd.DataFrame, pd.DataFrame, List[dict]]:
    tools_df = pd.read_json(attacker_tools_path, lines=True)
    tasks_df = pd.read_json(tasks_path, lines=True)
    cases = select_cases(
        tasks_df,
        tools_df,
        max_cases=max_cases,
        seed=seed,
        agent_filter=agent_filter,
        task_limit=task_limit,
    )
    return tools_df, tasks_df, cases



def read_manifest(path: str | Path) -> tuple[dict, List[dict]]:
    """Read a JSONL manifest written by :func:`write_manifest`.

    The first metadata record is optional.  Case order is preserved because it
    is useful for human inspection, although all statistical pairing should be
    performed by ``case_id`` rather than row position.
    """
    manifest_path = Path(path)
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest does not exist: {manifest_path}")

    metadata: dict = {}
    cases: List[dict] = []
    with manifest_path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in manifest {manifest_path} at line {line_no}: {exc}"
                ) from exc
            record_type = row.get("record_type", "case")
            if record_type == "metadata":
                metadata = {k: v for k, v in row.items() if k != "record_type"}
            elif record_type == "case":
                case = {k: v for k, v in row.items() if k != "record_type"}
                if "case_id" not in case:
                    raise ValueError(
                        f"Manifest case at line {line_no} has no case_id: {manifest_path}"
                    )
                cases.append(case)
            else:
                raise ValueError(
                    f"Unknown record_type={record_type!r} at line {line_no}: {manifest_path}"
                )

    ids = [str(c["case_id"]) for c in cases]
    duplicates = sorted({x for x in ids if ids.count(x) > 1})
    if duplicates:
        raise ValueError(
            f"Manifest contains duplicate case_id values: {duplicates[:10]}"
        )
    return metadata, cases


def materialize_manifest_cases(
    manifest_cases: Sequence[dict],
    tools_df: pd.DataFrame,
) -> List[dict]:
    """Attach the exact tool row needed by ASB's agent factory.

    ``write_manifest`` intentionally omits the large ``tool_record`` object.
    This helper restores it by the stable pair ``(agent_name, attacker_tool)``
    and rejects missing or ambiguous matches rather than silently selecting a
    different sample.
    """
    required = {"Corresponding Agent", "Attacker Tool"}
    missing = required.difference(tools_df.columns)
    if missing:
        raise ValueError(f"Tool data is missing required columns: {sorted(missing)}")

    out: List[dict] = []
    for case in manifest_cases:
        agent_name = str(case.get("agent_name", ""))
        tool_name = str(case.get("attacker_tool", ""))
        matches = tools_df[
            (tools_df["Corresponding Agent"].astype(str) == agent_name)
            & (tools_df["Attacker Tool"].astype(str) == tool_name)
        ]
        if len(matches) != 1:
            raise ValueError(
                "Expected exactly one tool row for manifest case "
                f"{case.get('case_id')!r}, agent={agent_name!r}, tool={tool_name!r}; "
                f"found {len(matches)}"
            )
        row = dict(case)
        row["tool_record"] = matches.iloc[0].to_dict()
        row["aggressive"] = _safe_bool(row["tool_record"].get("Aggressive", False))
        out.append(row)
    return out
