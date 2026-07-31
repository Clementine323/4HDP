#!/usr/bin/env python3
"""Pre-flight validation for long 4HDP/ASB runs.

Run this before launching multi-hour experiments.  It checks dataset files,
scenario filtering, deterministic case selection, environment variables, and
basic package imports without calling the victim LLM or audit LLM.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd

from asb_eval_utils import parse_agent_filter, load_cases_from_data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attacker-tools", default="data/all_attack_tools.jsonl")
    parser.add_argument("--tasks", default="data/agent_task.jsonl")
    parser.add_argument("--max-cases", type=int, default=int(os.environ.get("FOURHDP_MAX_CASES", "100")))
    parser.add_argument("--seed", type=int, default=int(os.environ.get("FOURHDP_RANDOM_SEED", "0")))
    parser.add_argument("--model", default=os.environ.get("MODEL_NAME") or os.environ.get("FOURHDP_AUDIT_MODEL") or "gpt-4o-mini")
    args = parser.parse_args()

    errors = []
    warnings = []
    for path in [args.attacker_tools, args.tasks, "data/all_normal_tools.jsonl"]:
        if not Path(path).exists():
            errors.append(f"Missing required file: {path}")

    agent_filter = parse_agent_filter()
    try:
        tools_df, tasks_df, cases = load_cases_from_data(
            args.attacker_tools,
            args.tasks,
            max_cases=args.max_cases,
            seed=args.seed,
            agent_filter=agent_filter,
        )
    except Exception as exc:
        errors.append(f"Case selection failed: {exc}")
        tools_df = pd.DataFrame()
        tasks_df = pd.DataFrame()
        cases = []

    selected_agents = sorted({c["agent_name"] for c in cases})
    selected_counts = {a: sum(1 for c in cases if c["agent_name"] == a) for a in selected_agents}

    # Import checks that often fail only after a long launch if not verified.
    import_checks = {}
    required_imports = ["fourhdp", "dotenv", "jsonlines", "langchain_chroma", "langchain_openai"]
    for mod in required_imports:
        try:
            __import__(mod)
            import_checks[mod] = "ok"
        except Exception as exc:
            import_checks[mod] = f"failed: {exc}"
            errors.append(
                f"Cannot import {mod}: {exc}. Install root and ASB requirements before long runs."
            )

    if not os.environ.get("OPENAI_API_KEY"):
        warnings.append("OPENAI_API_KEY is not configured; real 4HDP audit runs will fail closed.")

    env = {
        "OPENAI_API_KEY_configured": bool(os.environ.get("OPENAI_API_KEY")),
        "OPENAI_BASE_URL": os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        "MODEL_NAME": os.environ.get("MODEL_NAME"),
        "FOURHDP_AUDIT_MODEL": os.environ.get("FOURHDP_AUDIT_MODEL"),
        "FOURHDP_ABLATION": os.environ.get("FOURHDP_ABLATION", "full"),
        "FOURHDP_AGENT_FILTER": os.environ.get("FOURHDP_AGENT_FILTER", "financial_analyst_agent,legal_consultant_agent,medical_advisor_agent"),
        "FOURHDP_MAX_CASES": args.max_cases,
        "FOURHDP_RANDOM_SEED": args.seed,
        "FOURHDP_MAX_WORKERS": os.environ.get("FOURHDP_MAX_WORKERS", "10"),
    }

    summary = {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "data": {
            "tasks_rows": len(tasks_df),
            "attack_tools_rows": len(tools_df),
            "selected_cases": len(cases),
            "selected_agents": selected_agents,
            "selected_counts": selected_counts,
            "first_cases": [{k: v for k, v in c.items() if k != "tool_record"} for c in cases[:5]],
        },
        "imports": import_checks,
        "environment": env,
        "audit_model_effective": args.model,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
