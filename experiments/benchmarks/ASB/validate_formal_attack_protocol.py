#!/usr/bin/env python3
"""Offline go/no-go validation for formal ASB attack/defense runs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from asb_eval_utils import materialize_manifest_cases, read_manifest


ATTACK_MANIFESTS = {
    "DPI": "r9_dpi_manifest.jsonl",
    "IPI": "r9_ipi_manifest.jsonl",
    "MP": "r9_mp_manifest.jsonl",
    "POT": "r9_pot_protocol_manifest.jsonl",
    "MIXED": "r9_mixed_manifest.jsonl",
}
PAPER_AGENTS = {
    "financial_analyst_agent",
    "legal_consultant_agent",
    "medical_advisor_agent",
}


def require_text(path: Path, required: list[str], errors: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    for needle in required:
        if needle not in text:
            errors.append(f"{path.name}: missing required protocol token {needle!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-dir", default="r9/manifests")
    parser.add_argument("--expected-cases", type=int, default=100)
    parser.add_argument(
        "--agents",
        default="financial_analyst_agent,legal_consultant_agent,medical_advisor_agent",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    manifest_dir = (root / args.manifest_dir).resolve()
    expected_agents = {value.strip() for value in args.agents.split(",") if value.strip()}
    errors: list[str] = []
    checks: dict[str, dict] = {}

    if expected_agents != PAPER_AGENTS:
        errors.append(
            "Formal paper-subset protocol must use financial, legal, and medical agents"
        )

    attack_tools = pd.read_json(root / "data/all_attack_tools.jsonl", lines=True)
    pot_rows = pd.read_json(root / "data/agent_task_pot.jsonl", lines=True)
    pot_tasks = {
        row["agent_name"]: set((row.get("tasks") or [])[:2])
        for row in pot_rows.to_dict("records")
    }

    for attack, filename in ATTACK_MANIFESTS.items():
        path = manifest_dir / filename
        if not path.is_file():
            errors.append(f"{attack}: missing manifest {path}")
            continue
        metadata, cases = read_manifest(path)
        if len(cases) < args.expected_cases:
            errors.append(
                f"{attack}: needs at least {args.expected_cases} cases, found {len(cases)}"
            )
        try:
            materialize_manifest_cases(cases, attack_tools)
        except Exception as exc:
            errors.append(f"{attack}: cannot materialize manifest: {exc}")
        agents = {str(case.get("agent_name")) for case in cases}
        if agents != expected_agents:
            errors.append(
                f"{attack}: agents {sorted(agents)} do not match {sorted(expected_agents)}"
            )
        if attack == "POT":
            bad = [
                str(case.get("case_id"))
                for case in cases
                if case.get("task") not in pot_tasks.get(case.get("agent_name"), set())
            ]
            if bad:
                errors.append(
                    f"POT: {len(bad)} cases are not from the first two dedicated PoT tasks"
                )
        checks[attack] = {
            "manifest": str(path),
            "cases": len(cases),
            "agents": sorted(agents),
            "metadata": metadata,
        }

    require_text(
        root / "run_rq1_experiments.sh",
        [
            "--direct_prompt_injection --attack_type combined_attack",
            "--observation_prompt_injection --attack_type combined_attack",
            "--memory_attack --read_db",
            "--tasks_path data/agent_task_pot.jsonl",
            "--task_num 2 --attack_type combined_attack",
            "--direct_prompt_injection --observation_prompt_injection --read_db",
        ],
        errors,
    )
    require_text(
        root / "run_baseline_timing.sh",
        [
            "--memory_attack --read_db",
            "--tasks_path data/agent_task_pot.jsonl",
            "--direct_prompt_injection --observation_prompt_injection",
            "--read_db --database",
        ],
        errors,
    )
    require_text(
        root / "run_r10_mp_mixed_defense_smoke.sh",
        [
            '--expected-cases "$FOURHDP_MAX_CASES"',
            '--audit-model "$FOURHDP_AUDIT_MODEL"',
        ],
        errors,
    )

    report = {
        "ok": not errors,
        "protocol": {
            "scope": "paper three-domain subset",
            "prompt_injection_type": "combined_attack",
            "pot_task_file": "data/agent_task_pot.jsonl",
            "pot_task_limit": 2,
            "audit_model": "gpt-4o",
            "tool_surface_shortcut": False,
        },
        "checks": checks,
        "errors": errors,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
