#!/usr/bin/env python3
"""Validate one completed paper-subset baseline/4HDP run."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


ATTACKS = ("DPI", "IPI", "MP", "POT", "MIXED", "BENIGN")


def rows(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-dir", required=True)
    parser.add_argument("--defended-dir", required=True)
    parser.add_argument("--expected-cases", type=int, required=True)
    parser.add_argument("--victim-model", required=True)
    parser.add_argument("--audit-model", default="gpt-4o")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()

    baseline_dir = Path(args.baseline_dir).resolve()
    defended_dir = Path(args.defended_dir).resolve()
    errors: list[str] = []
    cells: list[dict] = []

    for attack in ATTACKS:
        baseline = baseline_dir / f"baseline_{attack}.csv"
        defended = defended_dir / f"fourhdp_eval_{attack}.csv"
        for kind, path in (("baseline", baseline), ("4hdp", defended)):
            cell = {"kind": kind, "attack": attack, "path": str(path), "ok": False}
            cells.append(cell)
            if not path.is_file():
                errors.append(f"{kind}/{attack}: missing {path}")
                continue
            data = rows(path)
            if len(data) != args.expected_cases:
                errors.append(
                    f"{kind}/{attack}: rows={len(data)} expected={args.expected_cases}"
                )
            invalid = [row for row in data if row.get("Sample Status") != "valid"]
            if invalid:
                errors.append(f"{kind}/{attack}: {len(invalid)} non-valid rows")
            ids = [str(row.get("Sample ID") or "") for row in data]
            if len(ids) != len(set(ids)):
                errors.append(f"{kind}/{attack}: duplicate sample IDs")
            if "Original Task Successful" not in (data[0] if data else {}):
                errors.append(f"{kind}/{attack}: task-completion field is absent")
            if kind == "4hdp":
                if any(row.get("Victim Model") != args.victim_model for row in data):
                    errors.append(f"4hdp/{attack}: victim-model mismatch")
                if any(row.get("Audit Model") != args.audit_model for row in data):
                    errors.append(f"4hdp/{attack}: audit-model mismatch")
                if any(row.get("Block Type") == "audit_failure" for row in data):
                    errors.append(f"4hdp/{attack}: audit failure was present")
                rq3_path = defended.with_name(defended.stem + "_rq3.json")
                if not rq3_path.is_file():
                    errors.append(f"4hdp/{attack}: missing RQ3 metadata")
                else:
                    rq3 = json.loads(rq3_path.read_text(encoding="utf-8"))
                    if rq3.get("tool_surface_enforced") is not False:
                        errors.append(f"4hdp/{attack}: tool-surface shortcut enabled")
                    if int(rq3.get("framework_errors", -1)) != 0:
                        errors.append(f"4hdp/{attack}: framework errors present")
                    if int(rq3.get("audit_engine_errors", -1)) != 0:
                        errors.append(f"4hdp/{attack}: audit-engine errors present")
            cell.update(
                {
                    "ok": not invalid and len(data) == args.expected_cases,
                    "rows": len(data),
                    "valid": len(data) - len(invalid),
                }
            )

        if baseline.is_file() and defended.is_file():
            baseline_ids = {row["Sample ID"] for row in rows(baseline)}
            defended_ids = {row["Sample ID"] for row in rows(defended)}
            if baseline_ids != defended_ids:
                errors.append(f"{attack}: baseline/4HDP samples are not paired")

    report = {
        "ok": not errors,
        "victim_model": args.victim_model,
        "audit_model": args.audit_model,
        "expected_cases_per_cell": args.expected_cases,
        "cells": cells,
        "errors": errors,
    }
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
