"""Static preflight checks for the matched R9 experiment."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from asb_eval_utils import read_manifest, materialize_manifest_cases

REQUIRED_DEFENSE_SYMBOLS = {
    "delimiters_defense",
    "instructional_prevention",
    "direct_paraphrase_defense",
    "dynamic_prompt_rewriting",
    "ob_sandwich_defense",
    "pot_paraphrase_defense",
    "pot_shuffling_defense",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-dir", default="r9/manifests")
    parser.add_argument("--expected-cases", type=int, default=100)
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    manifest_dir = Path(args.manifest_dir).resolve()
    react = (root / "pyopenagi/agents/react_agent_attack.py").read_text(encoding="utf-8")
    missing_symbols = sorted(x for x in REQUIRED_DEFENSE_SYMBOLS if x not in react)
    if missing_symbols:
        raise SystemExit(f"Missing ASB defense implementations: {missing_symbols}")

    checks = {}
    manifest_names = {
        "dpi": "r9_dpi_manifest.jsonl",
        "ipi": "r9_ipi_manifest.jsonl",
        "mp": "r9_mp_manifest.jsonl",
        "pot": "r9_pot_protocol_manifest.jsonl",
        "mixed": "r9_mixed_manifest.jsonl",
        "benign": "r9_benign_manifest.jsonl",
    }
    pot_tasks = {
        row["agent_name"]: set((row.get("tasks") or [])[:2])
        for row in pd.read_json(root / "data/agent_task_pot.jsonl", lines=True).to_dict("records")
    }
    for stage, filename in manifest_names.items():
        path = manifest_dir / filename
        metadata, cases = read_manifest(path)
        if len(cases) != args.expected_cases:
            raise SystemExit(f"{stage}: expected {args.expected_cases}, found {len(cases)}")
        uses_benign_index = any(
            str(case.get("attacker_tool", "")).startswith("benign_index_")
            for case in cases
        )
        tools_path = root / (
            "data/benign_case_index_v2.jsonl" if uses_benign_index
            else "data/all_attack_tools.jsonl"
        )
        tools = pd.read_json(tools_path, lines=True)
        materialized = materialize_manifest_cases(cases, tools)
        if stage == "pot":
            bad_tasks = [
                case["case_id"]
                for case in materialized
                if case.get("task") not in pot_tasks.get(case.get("agent_name"), set())
            ]
            if bad_tasks:
                raise SystemExit(
                    f"pot: {len(bad_tasks)} cases are not from the first two "
                    "ASB PoT test tasks"
                )
        checks[stage] = {
            "case_count": len(materialized),
            "unique_ids": len({x["case_id"] for x in materialized}),
            "agents": sorted({x["agent_name"] for x in materialized}),
            "manifest_metadata": metadata,
        }

    print("R9 static preflight: PASS")
    print(json.dumps(checks, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
