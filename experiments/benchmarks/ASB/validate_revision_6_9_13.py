#!/usr/bin/env python3
"""Strict validator and paper-table aggregator for revision items 6, 9, and 13.

The campaign compares, on exactly the same frozen manifests:
  * no defense,
  * the principal ASB prompt-layer defenses, and
  * full 4HDP with the paper's gpt-4o auditor.

It also produces paired end-to-end overhead metrics.  BENIGN is the primary
performance row because attack blocking can terminate a defended execution
early; attack rows are retained as supplemental path-specific measurements.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from asb_eval_utils import read_manifest


ATTACK_SPECS: dict[str, dict[str, Any]] = {
    "DPI": {
        "manifest": "r9_dpi_manifest.jsonl",
        "methods": ("delimiter", "paraphrase", "instructional", "dpr"),
    },
    "IPI": {
        "manifest": "r9_ipi_manifest.jsonl",
        "methods": ("delimiter", "instructional", "sandwich"),
    },
    "POT": {
        "manifest": "r9_pot_protocol_manifest.jsonl",
        "methods": ("shuffle", "paraphrase"),
    },
    "BENIGN": {
        "manifest": "r9_benign_revision_manifest.jsonl",
        "methods": (),
    },
}


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def int_field(row: dict[str, str], key: str) -> int:
    value = str(row.get(key, "")).strip().lower()
    if value in {"true", "yes"}:
        return 1
    if value in {"false", "no", ""}:
        return 0
    return int(float(value))


def token_total(data: dict[str, Any] | None) -> int:
    if not isinstance(data, dict):
        return 0
    return int(data.get("total_tokens", 0) or 0)


def latency_value(data: dict[str, Any], key: str, metric: str) -> float:
    block = data.get(key) or {}
    return float(block.get(metric, 0.0) or 0.0)


def write_csv(path: Path, fieldnames: list[str], records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-dir", required=True)
    parser.add_argument("--prompt-dir", required=True)
    parser.add_argument("--defended-dir", required=True)
    parser.add_argument("--manifest-dir", default="r9/manifests")
    parser.add_argument("--expected-cases", required=True, type=int)
    parser.add_argument("--victim-model", required=True)
    parser.add_argument("--audit-model", default="gpt-4o")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()

    baseline_dir = Path(args.baseline_dir).resolve()
    prompt_dir = Path(args.prompt_dir).resolve()
    defended_dir = Path(args.defended_dir).resolve()
    manifest_dir = Path(args.manifest_dir).resolve()
    report_path = Path(args.report).resolve()

    errors: list[str] = []
    warnings: list[str] = []
    cells: list[dict[str, Any]] = []
    asr_rows: list[dict[str, Any]] = []
    overhead_rows: list[dict[str, Any]] = []

    canonical_ids: dict[str, set[str]] = {}
    for attack, spec in ATTACK_SPECS.items():
        manifest_path = manifest_dir / spec["manifest"]
        if not manifest_path.is_file():
            errors.append(f"{attack}: missing source manifest {manifest_path}")
            canonical_ids[attack] = set()
            continue
        _, cases = read_manifest(str(manifest_path))
        expected = [str(case["case_id"]) for case in cases[: args.expected_cases]]
        if len(expected) != args.expected_cases:
            errors.append(
                f"{attack}: manifest cases={len(expected)} expected={args.expected_cases}"
            )
        if len(expected) != len(set(expected)):
            errors.append(f"{attack}: duplicate IDs in source manifest")
        canonical_ids[attack] = set(expected)

    for attack, spec in ATTACK_SPECS.items():
        baseline_csv = baseline_dir / f"baseline_{attack}.csv"
        baseline_json = baseline_dir / f"baseline_{attack}_timing.json"
        defended_csv = defended_dir / f"fourhdp_eval_{attack}.csv"
        defended_json = defended_dir / f"fourhdp_eval_{attack}_rq3.json"

        baseline_rows: list[dict[str, str]] = []
        defended_rows: list[dict[str, str]] = []
        baseline_metrics: dict[str, Any] = {}
        defended_metrics: dict[str, Any] = {}

        if not baseline_csv.is_file():
            errors.append(f"baseline/{attack}: missing {baseline_csv}")
        else:
            baseline_rows = load_csv(baseline_csv)
            ids = {str(row.get("Sample ID") or "") for row in baseline_rows}
            cell_errors = []
            if len(baseline_rows) != args.expected_cases:
                cell_errors.append(f"rows={len(baseline_rows)}")
            if len(ids) != len(baseline_rows):
                cell_errors.append("duplicate sample IDs")
            if ids != canonical_ids.get(attack, set()):
                cell_errors.append("source-manifest sample mismatch")
            if any(row.get("Sample Status") != "valid" for row in baseline_rows):
                cell_errors.append("non-valid sample")
            if any(row.get("Victim Model") != args.victim_model for row in baseline_rows):
                cell_errors.append("victim-model mismatch")
            if cell_errors:
                errors.extend(f"baseline/{attack}: {item}" for item in cell_errors)
            cells.append(
                {
                    "kind": "baseline",
                    "attack": attack,
                    "path": str(baseline_csv),
                    "rows": len(baseline_rows),
                    "ok": not cell_errors,
                }
            )
        if not baseline_json.is_file():
            errors.append(f"baseline/{attack}: missing {baseline_json}")
        else:
            baseline_metrics = load_json(baseline_json)
            if baseline_metrics.get("victim_model") != args.victim_model:
                errors.append(f"baseline/{attack}: timing victim-model mismatch")
            if int(baseline_metrics.get("framework_errors", -1)) != 0:
                errors.append(f"baseline/{attack}: framework errors present")
            if int(baseline_metrics.get("valid_cases", -1)) != args.expected_cases:
                errors.append(f"baseline/{attack}: timing valid count mismatch")
            if latency_value(baseline_metrics, "end_to_end_latency_valid", "count") != args.expected_cases:
                errors.append(f"baseline/{attack}: missing end-to-end latency samples")

        if not defended_csv.is_file():
            errors.append(f"4hdp/{attack}: missing {defended_csv}")
        else:
            defended_rows = load_csv(defended_csv)
            ids = {str(row.get("Sample ID") or "") for row in defended_rows}
            cell_errors = []
            if len(defended_rows) != args.expected_cases:
                cell_errors.append(f"rows={len(defended_rows)}")
            if len(ids) != len(defended_rows):
                cell_errors.append("duplicate sample IDs")
            if ids != canonical_ids.get(attack, set()):
                cell_errors.append("source-manifest sample mismatch")
            if any(row.get("Sample Status") != "valid" for row in defended_rows):
                cell_errors.append("non-valid sample")
            if any(row.get("Victim Model") != args.victim_model for row in defended_rows):
                cell_errors.append("victim-model mismatch")
            if any(row.get("Audit Model") != args.audit_model for row in defended_rows):
                cell_errors.append("audit-model mismatch")
            if any(row.get("Block Type") == "audit_failure" for row in defended_rows):
                cell_errors.append("audit-failure block present")
            if cell_errors:
                errors.extend(f"4hdp/{attack}: {item}" for item in cell_errors)
            cells.append(
                {
                    "kind": "4hdp",
                    "attack": attack,
                    "path": str(defended_csv),
                    "rows": len(defended_rows),
                    "ok": not cell_errors,
                }
            )
        if not defended_json.is_file():
            errors.append(f"4hdp/{attack}: missing {defended_json}")
        else:
            defended_metrics = load_json(defended_json)
            checks = {
                "victim model": defended_metrics.get("victim_model") == args.victim_model,
                "audit model": defended_metrics.get("audit_model") == args.audit_model,
                "full ablation": defended_metrics.get("ablation_mode") == "full",
                "framework errors": int(defended_metrics.get("framework_errors", -1)) == 0,
                "audit engine errors": int(defended_metrics.get("audit_engine_errors", -1)) == 0,
                "audit-failure blocks": int(defended_metrics.get("audit_failure_blocks", -1)) == 0,
                "valid count": int(defended_metrics.get("valid_cases", -1)) == args.expected_cases,
                "tool-surface original protocol": defended_metrics.get("tool_surface_enforced") is False,
                "end-to-end latency": latency_value(defended_metrics, "end_to_end_latency_valid", "count") == args.expected_cases,
            }
            for name, ok in checks.items():
                if not ok:
                    errors.append(f"4hdp/{attack}: failed check: {name}")

        if baseline_rows and defended_rows:
            base_ids = {row["Sample ID"] for row in baseline_rows}
            def_ids = {row["Sample ID"] for row in defended_rows}
            if base_ids != def_ids:
                errors.append(f"{attack}: baseline/4HDP samples are not paired")

        if attack != "BENIGN" and baseline_rows:
            asr_rows.append(
                {
                    "victim_model": args.victim_model,
                    "attack": attack,
                    "method": "no_defense",
                    "attack_successes": sum(int_field(row, "Attack Successful") for row in baseline_rows),
                    "valid_cases": len(baseline_rows),
                    "asr": sum(int_field(row, "Attack Successful") for row in baseline_rows) / len(baseline_rows),
                }
            )
        if attack != "BENIGN" and defended_rows:
            successes = sum(int_field(row, "Attack Successful Under 4HDP") for row in defended_rows)
            asr_rows.append(
                {
                    "victim_model": args.victim_model,
                    "attack": attack,
                    "method": "4hdp_full",
                    "attack_successes": successes,
                    "valid_cases": len(defended_rows),
                    "asr": successes / len(defended_rows),
                }
            )

        for method in spec["methods"]:
            prompt_csv = prompt_dir / attack / method / f"{attack}_{method}.csv"
            prompt_json = prompt_csv.with_name(prompt_csv.stem + "_summary.json")
            if not prompt_csv.is_file():
                errors.append(f"prompt/{attack}/{method}: missing {prompt_csv}")
                continue
            prompt_rows = load_csv(prompt_csv)
            ids = {str(row.get("Sample ID") or "") for row in prompt_rows}
            cell_errors = []
            if len(prompt_rows) != args.expected_cases:
                cell_errors.append(f"rows={len(prompt_rows)}")
            if len(ids) != len(prompt_rows):
                cell_errors.append("duplicate sample IDs")
            if ids != canonical_ids.get(attack, set()):
                cell_errors.append("source-manifest sample mismatch")
            if any(row.get("Sample Status") != "valid" for row in prompt_rows):
                cell_errors.append("non-valid sample")
            if any(row.get("Victim Model") != args.victim_model for row in prompt_rows):
                cell_errors.append("victim-model mismatch")
            if any(int_field(row, "Rewrite Failure") for row in prompt_rows):
                cell_errors.append("rewrite failure present")
            if cell_errors:
                errors.extend(f"prompt/{attack}/{method}: {item}" for item in cell_errors)
            if not prompt_json.is_file():
                errors.append(f"prompt/{attack}/{method}: missing summary")
            else:
                prompt_metrics = load_json(prompt_json)
                if prompt_metrics.get("victim_model") != args.victim_model:
                    errors.append(f"prompt/{attack}/{method}: summary victim mismatch")
                if int(prompt_metrics.get("submitted", -1)) != args.expected_cases:
                    errors.append(f"prompt/{attack}/{method}: submitted mismatch")
                if int(prompt_metrics.get("valid", -1)) != args.expected_cases:
                    errors.append(f"prompt/{attack}/{method}: valid mismatch")
                if int(prompt_metrics.get("framework_error", -1)) != 0:
                    errors.append(f"prompt/{attack}/{method}: framework error")
                if int(prompt_metrics.get("rewrite_failure", -1)) != 0:
                    errors.append(f"prompt/{attack}/{method}: rewrite failure")
            cells.append(
                {
                    "kind": "prompt",
                    "attack": attack,
                    "method": method,
                    "path": str(prompt_csv),
                    "rows": len(prompt_rows),
                    "ok": not cell_errors and prompt_json.is_file(),
                }
            )
            successes = sum(int_field(row, "Attack Successful") for row in prompt_rows)
            asr_rows.append(
                {
                    "victim_model": args.victim_model,
                    "attack": attack,
                    "method": method,
                    "attack_successes": successes,
                    "valid_cases": len(prompt_rows),
                    "asr": successes / len(prompt_rows) if prompt_rows else None,
                }
            )

        if baseline_metrics and defended_metrics:
            base_mean = latency_value(baseline_metrics, "end_to_end_latency_valid", "mean_s")
            base_p95 = latency_value(baseline_metrics, "end_to_end_latency_valid", "p95_s")
            full_mean = latency_value(defended_metrics, "end_to_end_latency_valid", "mean_s")
            full_p95 = latency_value(defended_metrics, "end_to_end_latency_valid", "p95_s")
            base_total_tokens = token_total(baseline_metrics.get("total_token_usage"))
            full_total_tokens = token_total(defended_metrics.get("total_token_usage"))
            audit_tokens = token_total(defended_metrics.get("audit_token_usage") or defended_metrics.get("token_usage"))
            overhead_rows.append(
                {
                    "victim_model": args.victim_model,
                    "workload": attack,
                    "primary_overhead_row": attack == "BENIGN",
                    "baseline_mean_e2e_s": base_mean,
                    "full_mean_e2e_s": full_mean,
                    "delta_mean_e2e_s": full_mean - base_mean,
                    "delta_mean_e2e_pct": ((full_mean - base_mean) / base_mean * 100.0) if base_mean else None,
                    "baseline_p95_e2e_s": base_p95,
                    "full_p95_e2e_s": full_p95,
                    "delta_p95_e2e_s": full_p95 - base_p95,
                    "audit_mean_s": latency_value(defended_metrics, "latency", "mean_s"),
                    "audit_p95_s": latency_value(defended_metrics, "latency", "p95_s"),
                    "audit_calls": int(defended_metrics.get("total_tool_calls_audited", 0) or 0),
                    "baseline_total_tokens": base_total_tokens,
                    "full_total_tokens": full_total_tokens,
                    "delta_total_tokens": full_total_tokens - base_total_tokens,
                    "incremental_audit_tokens": audit_tokens,
                    "note": (
                        "Primary matched overhead estimate on benign tasks."
                        if attack == "BENIGN"
                        else "Supplemental attack-path timing; blocking may terminate 4HDP runs early."
                    ),
                }
            )

    asr_path = report_path.with_name("opinion9_matched_asr.csv")
    overhead_path = report_path.with_name("opinion6_13_overhead.csv")
    write_csv(
        asr_path,
        ["victim_model", "attack", "method", "attack_successes", "valid_cases", "asr"],
        asr_rows,
    )
    write_csv(
        overhead_path,
        [
            "victim_model", "workload", "primary_overhead_row",
            "baseline_mean_e2e_s", "full_mean_e2e_s", "delta_mean_e2e_s", "delta_mean_e2e_pct",
            "baseline_p95_e2e_s", "full_p95_e2e_s", "delta_p95_e2e_s",
            "audit_mean_s", "audit_p95_s", "audit_calls",
            "baseline_total_tokens", "full_total_tokens", "delta_total_tokens",
            "incremental_audit_tokens", "note",
        ],
        overhead_rows,
    )

    report = {
        "ok": not errors,
        "victim_model": args.victim_model,
        "audit_model": args.audit_model,
        "expected_cases_per_cell": args.expected_cases,
        "baseline_dir": str(baseline_dir),
        "prompt_dir": str(prompt_dir),
        "defended_dir": str(defended_dir),
        "cells": cells,
        "warnings": warnings,
        "errors": errors,
        "opinion9_table": str(asr_path),
        "opinion6_13_table": str(overhead_path),
        "overhead_interpretation": (
            "Use BENIGN as the primary end-to-end overhead estimate. Attack-path rows are "
            "supplemental because security blocking may shorten defended executions."
        ),
        "token_interpretation": (
            "incremental_audit_tokens matches the paper's audit-token definition; "
            "delta_total_tokens additionally includes victim-model usage when the provider returns usage metadata."
        ),
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("REVISION 6/9/13 STRICT VALIDATION:", "PASS" if report["ok"] else "FAILED")
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
