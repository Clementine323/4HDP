#!/usr/bin/env python3
"""Verify ASB result integrity before using outputs in the paper.

This script checks that baseline and 4HDP runs are comparable:
- expected CSV, manifest, trace, and timing/RQ3 files exist;
- row counts and valid-case counts are non-zero;
- sample IDs in baseline and 4HDP match for each attack and model;
- manifest sample IDs match CSV sample IDs;
- framework/audit failures are surfaced explicitly.

It never changes result files.  Use it after smoke tests and after long runs.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

ATTACKS = ["DPI", "IPI", "MP", "POT", "MIXED", "BENIGN"]


def read_csv(path: Path) -> List[dict]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def read_manifest_ids(path: Path) -> List[str]:
    if not path.exists():
        return []
    ids: List[str] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("record_type") == "case" and row.get("case_id"):
                ids.append(str(row["case_id"]))
    return ids


def sample_ids(rows: Iterable[dict]) -> List[str]:
    ids = []
    for r in rows:
        sid = r.get("Sample ID") or r.get("sample_id") or r.get("case_id")
        if sid:
            ids.append(str(sid))
    return ids


def status_counts(rows: Iterable[dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for r in rows:
        status = str(r.get("Sample Status") or r.get("sample_status") or "valid")
        counts[status] = counts.get(status, 0) + 1
    return counts


def check_one_csv(path: Path, source: str, attack: str, require_files: bool) -> dict:
    rows = read_csv(path)
    ids = sample_ids(rows)
    manifest = path.with_name(path.name.replace(".csv", "_manifest.jsonl"))
    trace = path.with_name(path.name.replace(".csv", "_traces.jsonl"))
    audit_events = path.with_name(path.name.replace(".csv", "_audit_events.jsonl"))
    is_4hdp = source.startswith("4hdp")
    aux = path.with_name(path.name.replace(".csv", "_rq3.json" if is_4hdp else "_timing.json"))
    manifest_ids = read_manifest_ids(manifest)

    errors: List[str] = []
    warnings: List[str] = []
    if not path.exists():
        errors.append("missing_csv")
    if require_files:
        if not manifest.exists():
            errors.append("missing_manifest")
        if not trace.exists():
            errors.append("missing_trace")
        if not aux.exists():
            errors.append("missing_aux_metrics")
        if is_4hdp and not audit_events.exists():
            errors.append("missing_audit_events")
    if path.exists() and not rows:
        errors.append("empty_csv")
    if rows and not ids:
        errors.append("missing_sample_ids")
    if manifest.exists() and set(ids) != set(manifest_ids):
        missing_in_csv = sorted(set(manifest_ids) - set(ids))[:5]
        missing_in_manifest = sorted(set(ids) - set(manifest_ids))[:5]
        errors.append("csv_manifest_sample_id_mismatch")
        warnings.append(
            f"manifest_not_in_csv={missing_in_csv}; csv_not_in_manifest={missing_in_manifest}"
        )

    counts = status_counts(rows)
    if counts.get("framework_error", 0) > 0:
        warnings.append(f"framework_errors={counts.get('framework_error', 0)}")
    if source == "4hdp" and rows:
        audit_fail = sum(1 for r in rows if str(r.get("Block Type", "")).lower() == "audit_failure")
        if audit_fail:
            warnings.append(f"audit_failure_blocks={audit_fail}")

    return {
        "source": source,
        "attack": attack,
        "csv": str(path),
        "exists": path.exists(),
        "rows": len(rows),
        "sample_ids": ids,
        "manifest_ids": manifest_ids,
        "valid_cases": counts.get("valid", 0),
        "framework_errors": counts.get("framework_error", 0),
        "errors": errors,
        "warnings": warnings,
    }


def compare_samples(base: dict, defended: dict) -> Tuple[List[str], List[str]]:
    b = set(base.get("sample_ids", []))
    d = set(defended.get("sample_ids", []))
    return sorted(b - d), sorted(d - b)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--asb-root", default=".", help="ASB benchmark directory")
    parser.add_argument("--model", default=None, help="Model subdirectory to check, e.g. gpt-4o-mini")
    parser.add_argument("--attacks", default=",".join(ATTACKS), help="Comma-separated attack names")
    parser.add_argument("--output-json", default="result_integrity_report.json")
    parser.add_argument("--output-csv", default="result_integrity_report.csv")
    parser.add_argument("--allow-missing", action="store_true", help="Report missing files as warnings instead of failing")
    parser.add_argument("--check-ablation", action="store_true", help="Also check results_4hdp/<model>/<ablation>/ outputs")
    args = parser.parse_args()

    root = Path(args.asb_root).resolve()
    attacks = [a.strip().upper() for a in args.attacks.split(",") if a.strip()]
    model_dirs: List[str]
    if args.model:
        model_dirs = [args.model]
    else:
        candidates = {p.parent.name for p in (root / "results_4hdp").glob("*/fourhdp_eval_*.csv")}
        candidates |= {p.parent.name for p in (root / "results_baseline").glob("*/baseline_*.csv")}
        model_dirs = sorted(candidates)

    require_files = not args.allow_missing
    checks: List[dict] = []
    comparisons: List[dict] = []

    for model in model_dirs:
        for attack in attacks:
            base_path = root / "results_baseline" / model / f"baseline_{attack}.csv"
            four_path = root / "results_4hdp" / model / f"fourhdp_eval_{attack}.csv"
            base = check_one_csv(base_path, "baseline", attack, require_files)
            defended = check_one_csv(four_path, "4hdp", attack, require_files)
            base["model"] = model
            defended["model"] = model
            checks.extend([base, defended])
            missing_in_4hdp, missing_in_baseline = compare_samples(base, defended)
            cmp_errors = []
            if missing_in_4hdp or missing_in_baseline:
                cmp_errors.append("baseline_4hdp_sample_id_mismatch")
            comparisons.append({
                "model": model,
                "attack": attack,
                "baseline_rows": base["rows"],
                "fourhdp_rows": defended["rows"],
                "missing_in_4hdp_count": len(missing_in_4hdp),
                "missing_in_baseline_count": len(missing_in_baseline),
                "missing_in_4hdp_preview": missing_in_4hdp[:5],
                "missing_in_baseline_preview": missing_in_baseline[:5],
                "errors": cmp_errors,
            })

        if args.check_ablation:
            ablation_root = root / "results_4hdp" / model / "ablation"
            if ablation_root.exists():
                for seed_dir in sorted(ablation_root.glob("*/seed_*")):
                    if not seed_dir.is_dir():
                        continue
                    mode = seed_dir.parent.name
                    seed = seed_dir.name.removeprefix("seed_")
                    for attack in attacks:
                        p = seed_dir / f"fourhdp_eval_{attack}.csv"
                        check = check_one_csv(p, "4hdp_ablation", attack, require_files)
                        check["model"] = model
                        check["ablation"] = mode
                        check["seed"] = seed
                        checks.append(check)
            else:
                # Backward compatibility with the older <model>/<ablation>/ layout.
                for abl_dir in sorted((root / "results_4hdp" / model).glob("*")):
                    if not abl_dir.is_dir():
                        continue
                    for attack in attacks:
                        p = abl_dir / f"fourhdp_eval_{attack}.csv"
                        check = check_one_csv(p, "4hdp_ablation", attack, require_files)
                        check["model"] = model
                        check["ablation"] = abl_dir.name
                        checks.append(check)

    flat_rows = []
    for c in checks:
        flat_rows.append({
            "type": "file",
            "model": c.get("model", ""),
            "attack": c.get("attack", ""),
            "source": c.get("source", ""),
            "ablation": c.get("ablation", ""),
            "seed": c.get("seed", ""),
            "rows": c.get("rows", 0),
            "valid_cases": c.get("valid_cases", 0),
            "framework_errors": c.get("framework_errors", 0),
            "errors": ";".join(c.get("errors", [])),
            "warnings": ";".join(c.get("warnings", [])),
            "file": c.get("csv", ""),
        })
    for cmp in comparisons:
        flat_rows.append({
            "type": "comparison",
            "model": cmp["model"],
            "attack": cmp["attack"],
            "source": "baseline_vs_4hdp",
            "ablation": "",
            "seed": "",
            "rows": "",
            "valid_cases": "",
            "framework_errors": "",
            "errors": ";".join(cmp.get("errors", [])),
            "warnings": (
                f"missing_in_4hdp={cmp['missing_in_4hdp_count']};"
                f"missing_in_baseline={cmp['missing_in_baseline_count']}"
            ),
            "file": "",
        })

    out_json = root / args.output_json if not Path(args.output_json).is_absolute() else Path(args.output_json)
    out_csv = root / args.output_csv if not Path(args.output_csv).is_absolute() else Path(args.output_csv)
    out_json.write_text(json.dumps({"checks": checks, "comparisons": comparisons}, ensure_ascii=False, indent=2), encoding="utf-8")
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        fieldnames = ["type", "model", "attack", "source", "ablation", "seed", "rows", "valid_cases", "framework_errors", "errors", "warnings", "file"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flat_rows)

    hard_errors = []
    for c in checks:
        if c.get("errors"):
            hard_errors.extend([f"{c.get('model','')}/{c.get('source')}/{c.get('attack')}: {e}" for e in c["errors"]])
    for cmp in comparisons:
        if cmp.get("errors"):
            hard_errors.extend([f"{cmp['model']}/compare/{cmp['attack']}: {e}" for e in cmp["errors"]])

    summary = {
        "ok": not hard_errors,
        "models_checked": model_dirs,
        "files_checked": len(checks),
        "comparisons_checked": len(comparisons),
        "hard_errors": hard_errors[:20],
        "output_json": str(out_json),
        "output_csv": str(out_csv),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if not hard_errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
