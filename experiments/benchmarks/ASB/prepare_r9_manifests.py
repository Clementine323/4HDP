"""Freeze revision-item-9 manifests from the completed 4HDP full run."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

from asb_eval_utils import read_manifest

STAGES = ("DPI", "IPI", "MP", "POT", "MIXED", "BENIGN")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def find_stage_manifest(source: Path, stage: str) -> Path:
    candidates = sorted(
        p for p in source.glob(f"*_{stage}_manifest.jsonl")
        if not p.name.startswith("._")
    )
    if len(candidates) != 1:
        raise SystemExit(
            f"Expected exactly one {stage} manifest in {source}; found: "
            + ", ".join(p.name for p in candidates)
        )
    return candidates[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--output-dir", default="r9/manifests")
    parser.add_argument("--expected-cases", type=int, default=100)
    args = parser.parse_args()

    source = Path(args.source_dir).resolve()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)

    index = {"source_dir": str(source), "manifests": {}}
    for stage in STAGES:
        src = find_stage_manifest(source, stage)
        metadata, cases = read_manifest(src)
        if len(cases) != args.expected_cases:
            raise SystemExit(
                f"{stage}: expected {args.expected_cases} cases, found {len(cases)} in {src}"
            )
        dst = output / f"r9_{stage.lower()}_manifest.jsonl"
        shutil.copy2(src, dst)
        index["manifests"][stage] = {
            "path": str(dst),
            "case_count": len(cases),
            "unique_case_ids": len({c["case_id"] for c in cases}),
            "agents": sorted({c["agent_name"] for c in cases}),
            "sha256": sha256(dst),
            "source_metadata": metadata,
        }

    index_path = output / "r9_manifest_index.json"
    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(index, ensure_ascii=False, indent=2))
    print(f"Manifest index written to: {index_path}")


if __name__ == "__main__":
    main()
