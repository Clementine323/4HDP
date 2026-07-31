#!/usr/bin/env python3
"""Aggregate 4HDP ASB CSV/RQ3 outputs into paper-ready metrics."""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
from pathlib import Path

ATTACKS = ["DPI", "IPI", "MP", "POT", "MIXED", "BENIGN"]


def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def truthy(value) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def attack_from_name(name: str) -> str:
    upper = name.upper()
    for attack in ATTACKS:
        if f"_{attack}" in upper or upper.endswith(f"{attack}.CSV"):
            return attack
    return "UNKNOWN"


def summarize_csv(path: Path) -> dict:
    rows = read_csv(path)
    valid = [r for r in rows if r.get("Sample Status", "valid") == "valid"]
    framework_errors = sum(1 for r in rows if r.get("Sample Status") == "framework_error")
    blocked = [r for r in valid if truthy(r.get("4HDP Blocked") or r.get("FourHDP Blocked"))]
    security_blocks = [r for r in blocked if r.get("Block Type", "security") == "security"]
    audit_fail_blocks = [r for r in blocked if r.get("Block Type") == "audit_failure"]
    attack_success = [r for r in valid if truthy(r.get("Attack Successful Under 4HDP") or r.get("Attack Successful (Without Shield)") or r.get("attack_successful_under_4hdp"))]
    original_success = [
        r for r in valid if truthy(r.get("Original Task Successful"))
    ]
    benign = attack_from_name(path.name) == "BENIGN"

    if benign:
        metric = {
            "FPR_total": len(blocked) / len(valid) if valid else 0.0,
            "FPR_security": len(security_blocks) / len(valid) if valid else 0.0,
            "audit_failure_rate": len(audit_fail_blocks) / len(valid) if valid else 0.0,
            "PNA_submitted": len(original_success) / len(rows) if rows else 0.0,
            "PNA_valid": len(original_success) / len(valid) if valid else 0.0,
        }
    else:
        metric = {
            "ASR_valid": len(attack_success) / len(valid) if valid else 0.0,
            "ASR_submitted": len(attack_success) / len(rows) if rows else 0.0,
            "DSR_valid": len(blocked) / len(valid) if valid else 0.0,
            "security_block_rate": len(security_blocks) / len(valid) if valid else 0.0,
            "audit_failure_rate": len(audit_fail_blocks) / len(valid) if valid else 0.0,
        }
    return {
        "file": str(path),
        "attack": attack_from_name(path.name),
        "total_rows": len(rows),
        "valid_cases": len(valid),
        "framework_errors": framework_errors,
        "blocked": len(blocked),
        "security_blocks": len(security_blocks),
        "audit_failure_blocks": len(audit_fail_blocks),
        "attack_success_under_4hdp": len(attack_success),
        "original_task_success": len(original_success),
        **metric,
    }


def attach_rq3(summary: dict, csv_path: Path):
    rq3 = csv_path.with_name(csv_path.name.replace(".csv", "_rq3.json"))
    if not rq3.exists():
        return summary
    try:
        data = json.loads(rq3.read_text(encoding="utf-8"))
    except Exception:
        return summary
    latency = data.get("latency", {})
    token = data.get("token_usage", {})
    summary.update({
        "latency_count": latency.get("count", 0),
        "latency_mean_s": latency.get("mean_s", 0),
        "latency_median_s": latency.get("median_s", 0),
        "latency_p95_s": latency.get("p95_s", 0),
        "latency_max_s": latency.get("max_s", 0),
        "latency_total_s": latency.get("total_s", 0),
        "token_total": token.get("total_tokens", 0),
        "token_calls": token.get("total_calls", 0),
        "wall_time_s": data.get("wall_time_s", 0),
        "ablation_mode": data.get("ablation_mode", "full"),
        "system_stability_rate": data.get("system_stability_rate", None),
    })
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", default="results_4hdp")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    root = Path(args.results_dir)
    csv_files = [Path(p) for p in glob.glob(str(root / "**" / "fourhdp_eval_*.csv"), recursive=True)]
    if not csv_files:
        csv_files = [Path(p) for p in glob.glob(str(root / "**" / "*.csv"), recursive=True)]
    summaries = [attach_rq3(summarize_csv(p), p) for p in sorted(csv_files)]

    out = Path(args.output) if args.output else root / "summary_4hdp_metrics.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    if summaries:
        keys = sorted(set().union(*(s.keys() for s in summaries)))
        with out.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(summaries)
    print(json.dumps({"files": len(summaries), "output": str(out), "summaries": summaries}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
