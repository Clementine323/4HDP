"""Verify that an ASB poisoned-memory Chroma database is complete and paired."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from langchain_chroma import Chroma

from asb_eval_utils import read_manifest
from asb_memory_retrieval import chroma_content_sha256, sha256_file


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--expected-count", type=int, default=100)
    parser.add_argument("--report", default="")
    parser.add_argument("--embedding-model", default="text-embedding-ada-002")
    parser.add_argument("--injection-model", default="gpt-4o-mini")
    parser.add_argument("--attack-type", default="combined_attack")
    parser.add_argument("--asb-upstream-ref", default="agiresearch/asb@eac7bcf")
    parser.add_argument(
        "--write-metadata",
        action="store_true",
        help="Write build provenance after verifying a newly created database.",
    )
    parser.add_argument(
        "--require-metadata",
        action="store_true",
        help="Reject a database without matching, previously written build provenance.",
    )
    args = parser.parse_args()

    db_path = Path(args.database)
    if not db_path.exists():
        raise SystemExit(f"Database does not exist: {db_path}")

    _, cases = read_manifest(args.manifest)
    db = Chroma(persist_directory=str(db_path))
    count = int(db._collection.count())
    payload = db._collection.get(include=["documents", "metadatas"])
    documents = [str(x or "") for x in (payload.get("documents") or [])]
    database_content_hash = chroma_content_sha256(db)

    missing_pairs = []
    missing_workflow_tools = []
    malformed_docs = []
    workflow_tool_hits = 0
    for idx, doc in enumerate(documents):
        if not all(marker in doc for marker in ("Agent:", "Task:", "Workflow:", "Tools:")):
            malformed_docs.append(idx)

    for case in cases:
        task = str(case["task"])
        tool = str(case["attacker_tool"])
        matched = [doc for doc in documents if task in doc and tool in doc]
        if not matched:
            missing_pairs.append(case["case_id"])
            continue
        if any(
            tool in doc.split("Workflow:", 1)[1].split("; Tools:", 1)[0]
            for doc in matched
            if "Workflow:" in doc and "; Tools:" in doc
        ):
            workflow_tool_hits += 1
        else:
            missing_workflow_tools.append(case["case_id"])

    report = {
        "database": str(db_path.resolve()),
        "manifest": str(Path(args.manifest).resolve()),
        "expected_count": args.expected_count,
        "manifest_cases": len(cases),
        "database_count": count,
        "embedding_model": args.embedding_model,
        "injection_model": args.injection_model,
        "attack_type": args.attack_type,
        "asb_upstream_ref": args.asb_upstream_ref,
        "database_content_sha256": database_content_hash,
        "source_manifest_sha256": sha256_file(args.manifest),
        "malformed_document_count": len(malformed_docs),
        "missing_pair_count": len(missing_pairs),
        "missing_pair_ids": missing_pairs[:20],
        "workflow_contains_attacker_tool_count": workflow_tool_hits,
        "workflow_contains_attacker_tool_rate": (workflow_tool_hits / len(cases) if cases else None),
        "missing_workflow_tool_count": len(missing_workflow_tools),
        "missing_workflow_tool_ids": missing_workflow_tools[:20],
        "ok": (
            count == args.expected_count
            and len(cases) == args.expected_count
            and not malformed_docs
            and not missing_pairs
            and not missing_workflow_tools
        ),
    }

    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.report:
        out = Path(args.report)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    if not report["ok"]:
        raise SystemExit("R9 poisoned-memory verification: FAILED")

    metadata_path = db_path / "asb_memory_db_metadata.json"
    if args.write_metadata and args.require_metadata:
        raise SystemExit("Use only one of --write-metadata and --require-metadata")
    if args.write_metadata:
        metadata = {
            "schema_version": "asb-memory-db-v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "database": str(db_path.resolve()),
            "database_count": count,
            "database_content_sha256": database_content_hash,
            "source_manifest": str(Path(args.manifest).resolve()),
            "source_manifest_sha256": sha256_file(args.manifest),
            "embedding_model": args.embedding_model,
            "injection_model": args.injection_model,
            "attack_type": args.attack_type,
            "asb_upstream_ref": args.asb_upstream_ref,
        }
        metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
        report["metadata_file"] = str(metadata_path.resolve())
        report["metadata_status"] = "written"
    elif args.require_metadata:
        if not metadata_path.is_file():
            raise SystemExit(f"Required database metadata is missing: {metadata_path}")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        expected = {
            "schema_version": "asb-memory-db-v1",
            "database": str(db_path.resolve()),
            "database_count": count,
            "database_content_sha256": database_content_hash,
            "source_manifest_sha256": sha256_file(args.manifest),
            "embedding_model": args.embedding_model,
            "injection_model": args.injection_model,
            "attack_type": args.attack_type,
            "asb_upstream_ref": args.asb_upstream_ref,
        }
        mismatches = {
            key: {"expected": value, "observed": metadata.get(key)}
            for key, value in expected.items()
            if metadata.get(key) != value
        }
        if mismatches:
            raise SystemExit(f"Database provenance metadata mismatch: {json.dumps(mismatches)}")
        report["metadata_file"] = str(metadata_path.resolve())
        report["metadata_status"] = "verified"

    # Re-write the report after optional metadata validation so it captures the
    # provenance status as well as document completeness.
    if args.report:
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print("R9 poisoned-memory verification: PASS")


if __name__ == "__main__":
    main()
