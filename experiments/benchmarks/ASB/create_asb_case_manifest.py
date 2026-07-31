#!/usr/bin/env python3
"""Create an explicit deterministic ASB case manifest for paired runs."""
from __future__ import annotations

import argparse
from pathlib import Path

from asb_eval_utils import load_cases_from_data, parse_agent_filter, write_manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attacker-tools", default="data/all_attack_tools.jsonl")
    parser.add_argument("--tasks", default="data/agent_task.jsonl")
    parser.add_argument("--cases", type=int, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--agent-filter", default=None)
    parser.add_argument(
        "--task-limit",
        type=int,
        default=None,
        help="Restrict each agent to the first N task templates (PoT uses 2).",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output).resolve()
    if output.exists():
        raise SystemExit(f"Refusing to overwrite case manifest: {output}")
    agent_filter = parse_agent_filter(args.agent_filter)
    _, _, cases = load_cases_from_data(
        args.attacker_tools,
        args.tasks,
        max_cases=args.cases,
        seed=args.seed,
        agent_filter=agent_filter,
        task_limit=args.task_limit,
    )
    if len(cases) != args.cases:
        raise SystemExit(f"Selected {len(cases)} cases, expected {args.cases}")
    write_manifest(
        cases,
        output,
        metadata={
            "script": "create_asb_case_manifest.py",
            "seed": args.seed,
            "max_cases": args.cases,
            "agent_filter": agent_filter if agent_filter is not None else "all",
            "task_limit": args.task_limit,
            "tasks_path": str(Path(args.tasks).resolve()),
            "purpose": "paired ASB/4HDP ablation",
        },
    )
    print(f"ASB case manifest written: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
