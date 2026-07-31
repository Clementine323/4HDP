#!/usr/bin/env python3
"""Create paired, paper-ready summaries for 4HDP component ablations.

Expected layout:
  results_root/<mode>/seed_<n>/fourhdp_eval_*.csv

Outputs:
  ablation_metrics_by_seed.csv
  ablation_comparison.csv          (paired deltas versus full)
  ablation_metrics_aggregate.csv   (mean/std across seeds)
  ablation_pairing_report.json
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
from statistics import mean, pstdev
from typing import Iterable

ATTACKS = ["DPI", "IPI", "MP", "POT", "MIXED"]


def truthy(value) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def valid_rows(path: Path) -> tuple[list[dict], int]:
    rows = read_csv(path)
    valid = [r for r in rows if r.get("Sample Status", "valid") == "valid"]
    errors = sum(1 for r in rows if r.get("Sample Status") == "framework_error")
    return valid, errors


def manifest_ids(path: Path) -> list[str]:
    ids: list[str] = []
    if not path.exists():
        return ids
    with path.open(encoding="utf-8") as f:
        for line in f:
            try:
                row = json.loads(line)
            except Exception:
                continue
            if row.get("record_type") == "case" and row.get("case_id"):
                ids.append(str(row["case_id"]))
    return ids


def digest_ids(ids: Iterable[str]) -> str:
    payload = "\n".join(sorted(ids)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def read_audit_latencies(run_dir: Path) -> list[float]:
    values: list[float] = []
    for path in sorted(run_dir.glob("fourhdp_eval_*_audit_events.jsonl")):
        with path.open(encoding="utf-8") as f:
            for line in f:
                try:
                    row = json.loads(line)
                    values.append(float(row.get("audit_latency_s", 0.0)))
                except Exception:
                    continue
    return values


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return ordered[lo]
    return ordered[lo] * (hi - pos) + ordered[hi] * (pos - lo)


def token_and_wall_totals(run_dir: Path) -> tuple[int, int, float]:
    tokens = 0
    calls = 0
    wall = 0.0
    for path in sorted(run_dir.glob("fourhdp_eval_*_rq3.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        usage = data.get("token_usage", {})
        tokens += int(usage.get("total_tokens", 0) or 0)
        calls += int(usage.get("total_calls", 0) or 0)
        wall += float(data.get("wall_time_s", 0.0) or 0.0)
    return tokens, calls, wall


def summarize_run(run_dir: Path, mode: str, seed: str) -> dict:
    attack_submitted = attack_valid = attack_success = attack_blocked = 0
    attack_security_blocks = attack_audit_failures = attack_framework_errors = 0
    per_attack = {}

    for attack in ATTACKS:
        path = run_dir / f"fourhdp_eval_{attack}.csv"
        all_rows = read_csv(path)
        valid, framework_errors = valid_rows(path)
        success = sum(1 for r in valid if truthy(r.get("Attack Successful Under 4HDP")))
        blocked = sum(1 for r in valid if truthy(r.get("FourHDP Blocked") or r.get("4HDP Blocked")))
        security = sum(1 for r in valid if (r.get("Block Type") or "").lower() == "security")
        audit_fail = sum(1 for r in valid if (r.get("Block Type") or "").lower() == "audit_failure")
        attack_submitted += len(all_rows)
        attack_valid += len(valid)
        attack_success += success
        attack_blocked += blocked
        attack_security_blocks += security
        attack_audit_failures += audit_fail
        attack_framework_errors += framework_errors
        per_attack[f"ASR_{attack}"] = success / len(valid) if valid else 0.0
        per_attack[f"DSR_{attack}"] = blocked / len(valid) if valid else 0.0
        per_attack[f"N_{attack}"] = len(valid)

    benign_path = run_dir / "fourhdp_eval_BENIGN.csv"
    benign_rows = read_csv(benign_path)
    benign_valid_rows, benign_framework_errors = valid_rows(benign_path)
    benign_blocked = sum(1 for r in benign_valid_rows if truthy(r.get("FourHDP Blocked") or r.get("4HDP Blocked")))
    benign_security = sum(1 for r in benign_valid_rows if (r.get("Block Type") or "").lower() == "security")
    benign_audit_fail = sum(1 for r in benign_valid_rows if (r.get("Block Type") or "").lower() == "audit_failure")
    benign_completed = sum(
        1 for r in benign_valid_rows if truthy(r.get("Original Task Successful"))
    )

    latencies = read_audit_latencies(run_dir)
    tokens, token_calls, wall = token_and_wall_totals(run_dir)

    return {
        "mode": mode,
        "seed": seed,
        "run_dir": str(run_dir),
        "attack_valid": attack_valid,
        "attack_submitted": attack_submitted,
        "attack_success": attack_success,
        "attack_blocked": attack_blocked,
        "ASR_overall": attack_success / attack_valid if attack_valid else 0.0,
        "ASR_overall_submitted": (
            attack_success / attack_submitted if attack_submitted else 0.0
        ),
        "DSR_overall": attack_blocked / attack_valid if attack_valid else 0.0,
        "security_block_rate": attack_security_blocks / attack_valid if attack_valid else 0.0,
        "attack_audit_failure_rate": attack_audit_failures / attack_valid if attack_valid else 0.0,
        "attack_framework_errors": attack_framework_errors,
        "benign_valid": len(benign_valid_rows),
        "benign_submitted": len(benign_rows),
        "benign_completed": benign_completed,
        "PNA_submitted": (
            benign_completed / len(benign_rows) if benign_rows else 0.0
        ),
        "PNA_valid": (
            benign_completed / len(benign_valid_rows) if benign_valid_rows else 0.0
        ),
        "benign_blocked": benign_blocked,
        "FPR_total": benign_blocked / len(benign_valid_rows) if benign_valid_rows else 0.0,
        "FPR_security": benign_security / len(benign_valid_rows) if benign_valid_rows else 0.0,
        "benign_audit_failure_rate": benign_audit_fail / len(benign_valid_rows) if benign_valid_rows else 0.0,
        "benign_framework_errors": benign_framework_errors,
        "audit_calls": len(latencies),
        "latency_mean_s": mean(latencies) if latencies else 0.0,
        "latency_median_s": percentile(latencies, 0.5),
        "latency_p95_s": percentile(latencies, 0.95),
        "latency_max_s": max(latencies) if latencies else 0.0,
        "token_total": tokens,
        "token_calls": token_calls,
        "wall_time_s": wall,
        **per_attack,
    }


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    keys = sorted(set().union(*(r.keys() for r in rows))) if rows else []
    with path.open("w", newline="", encoding="utf-8") as f:
        if not keys:
            return
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-root", required=True)
    parser.add_argument("--output-dir", default=None)
    args = parser.parse_args()

    root = Path(args.results_root).resolve()
    out = Path(args.output_dir).resolve() if args.output_dir else root
    rows: list[dict] = []
    pairing_records: list[dict] = []

    run_dirs: dict[tuple[str, str], Path] = {}
    for mode_dir in sorted(root.glob("*")):
        if not mode_dir.is_dir():
            continue
        for seed_dir in sorted(mode_dir.glob("seed_*")):
            if seed_dir.is_dir():
                seed = seed_dir.name.removeprefix("seed_")
                run_dirs[(mode_dir.name, seed)] = seed_dir
                rows.append(summarize_run(seed_dir, mode_dir.name, seed))

    # Pairing check: every mode must use exactly the same sample IDs as full for
    # the same seed and attack/benign condition.
    seeds = sorted({seed for _, seed in run_dirs})
    modes = sorted({mode for mode, _ in run_dirs})
    for seed in seeds:
        full_dir = run_dirs.get(("full", seed))
        for label in ATTACKS + ["BENIGN"]:
            full_manifest = full_dir / f"fourhdp_eval_{label}_manifest.jsonl" if full_dir else None
            full_ids = manifest_ids(full_manifest) if full_manifest else []
            full_digest = digest_ids(full_ids)
            for mode in modes:
                run_dir = run_dirs.get((mode, seed))
                manifest = run_dir / f"fourhdp_eval_{label}_manifest.jsonl" if run_dir else None
                ids = manifest_ids(manifest) if manifest else []
                pairing_records.append({
                    "seed": seed,
                    "mode": mode,
                    "condition": label,
                    "full_count": len(full_ids),
                    "mode_count": len(ids),
                    "full_digest": full_digest,
                    "mode_digest": digest_ids(ids),
                    "paired": bool(full_ids) and full_ids == ids,
                    "missing_from_mode": sorted(set(full_ids) - set(ids))[:10],
                    "extra_in_mode": sorted(set(ids) - set(full_ids))[:10],
                })

    by_key = {(r["mode"], r["seed"]): r for r in rows}
    comparison: list[dict] = []
    delta_fields = [
        "ASR_overall", "DSR_overall", "FPR_total", "FPR_security",
        "latency_mean_s", "latency_p95_s", "token_total", "wall_time_s",
    ]
    for row in rows:
        full = by_key.get(("full", row["seed"]))
        comp = dict(row)
        for field in delta_fields:
            comp[f"delta_{field}_vs_full"] = (
                float(row.get(field, 0.0)) - float(full.get(field, 0.0)) if full else ""
            )
        relevant_pairing = [
            p for p in pairing_records if p["seed"] == row["seed"] and p["mode"] == row["mode"]
        ]
        comp["all_samples_paired_with_full"] = bool(relevant_pairing) and all(p["paired"] for p in relevant_pairing)
        comparison.append(comp)

    # Mean/std across seeds.  Keep only numeric metrics useful in the paper.
    aggregate_fields = [
        "ASR_overall", "DSR_overall", "security_block_rate",
        "attack_audit_failure_rate", "FPR_total", "FPR_security",
        "benign_audit_failure_rate", "latency_mean_s", "latency_p95_s",
        "token_total", "wall_time_s",
    ]
    aggregate: list[dict] = []
    for mode in modes:
        mode_rows = [r for r in rows if r["mode"] == mode]
        if not mode_rows:
            continue
        record = {"mode": mode, "seeds": len(mode_rows)}
        for field in aggregate_fields:
            vals = [float(r.get(field, 0.0)) for r in mode_rows]
            record[f"{field}_mean"] = mean(vals)
            record[f"{field}_std"] = pstdev(vals) if len(vals) > 1 else 0.0
        aggregate.append(record)

    write_csv(out / "ablation_metrics_by_seed.csv", rows)
    write_csv(out / "ablation_comparison.csv", comparison)
    write_csv(out / "ablation_metrics_aggregate.csv", aggregate)
    report = {
        "results_root": str(root),
        "runs": len(rows),
        "pairing_checks": pairing_records,
        "all_pairings_ok": bool(pairing_records) and all(p["paired"] for p in pairing_records),
    }
    (out / "ablation_pairing_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps({
        "runs": len(rows),
        "modes": modes,
        "seeds": seeds,
        "all_pairings_ok": report["all_pairings_ok"],
        "output_dir": str(out),
    }, ensure_ascii=False, indent=2))
    return 0 if rows else 2


if __name__ == "__main__":
    raise SystemExit(main())
