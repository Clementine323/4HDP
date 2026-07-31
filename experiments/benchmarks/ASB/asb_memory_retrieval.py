"""Reproducible helpers for ASB memory-poisoning retrieval.

The live retrieval path deliberately preserves ASB's original semantics: the
query is the task followed by the JSON tool list and Chroma returns top-1 by
embedding similarity.  A frozen manifest records that result once so paired
4HDP ablations can consume identical attack inputs without turning retrieval
success into an oracle or silently replacing misses with the intended poison.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = "asb-memory-retrieval-v1"


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_memory_query(task: str, tools: Sequence[Mapping[str, Any]]) -> str:
    """Build the query exactly as ASB's ``ReactAgentAttack`` does."""
    return str(task) + "; " + json.dumps(list(tools))


def parse_memory_document(document: str | None) -> tuple[bool, str]:
    """Parse ASB's ``Agent; Task; Workflow; Tools`` memory document.

    Splitting on the stable field delimiters is more robust than a non-greedy
    regex for workflows containing nested JSON or semicolons.
    """
    text = str(document or "")
    if "Task:" not in text or "Workflow:" not in text or "; Tools:" not in text:
        return False, ""
    workflow = text.split("Workflow:", 1)[1].rsplit("; Tools:", 1)[0].strip()
    return bool(workflow), workflow


def retrieval_flags(document: str | None, task: str, attacker_tool: str) -> dict[str, bool]:
    parse_ok, workflow = parse_memory_document(document)
    text = str(document or "")
    return {
        "pair_hit": bool(task and attacker_tool and task in text and attacker_tool in text),
        "parse_ok": parse_ok,
        "workflow_tool_hit": bool(parse_ok and attacker_tool and attacker_tool in workflow),
    }


def chroma_content_sha256(vector_db: Any) -> str:
    """Hash logical Chroma content rather than mutable SQLite/WAL files."""
    payload = vector_db._collection.get(include=["documents", "metadatas"])
    ids = payload.get("ids") or []
    documents = payload.get("documents") or []
    metadatas = payload.get("metadatas") or []
    rows = []
    for index, item_id in enumerate(ids):
        rows.append({
            "id": str(item_id),
            "document": str(documents[index] or "") if index < len(documents) else "",
            "metadata": metadatas[index] if index < len(metadatas) else None,
        })
    rows.sort(key=lambda row: (row["id"], row["document"]))
    return sha256_text(canonical_json(rows))


def load_jsonl(path: str | Path) -> list[dict]:
    rows: list[dict] = []
    source = Path(path)
    with source.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{source}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{source}:{line_number}: JSONL record must be an object")
            rows.append(row)
    return rows


def load_retrieval_manifest(path: str | Path) -> tuple[dict, dict[str, dict]]:
    metadata: dict = {}
    entries: dict[str, dict] = {}
    for row in load_jsonl(path):
        record_type = row.get("record_type")
        if record_type == "metadata":
            if metadata:
                raise ValueError(f"Retrieval manifest has multiple metadata rows: {path}")
            metadata = {key: value for key, value in row.items() if key != "record_type"}
            continue
        if record_type != "retrieval":
            raise ValueError(f"Unknown retrieval-manifest record_type={record_type!r}: {path}")
        case_id = str(row.get("case_id") or "")
        if not case_id:
            raise ValueError(f"Retrieval manifest row has no case_id: {path}")
        if case_id in entries:
            raise ValueError(f"Duplicate retrieval case_id={case_id!r}: {path}")
        entries[case_id] = row
    if metadata.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported retrieval manifest schema {metadata.get('schema_version')!r}; "
            f"expected {SCHEMA_VERSION!r}"
        )
    return metadata, entries


def validate_retrieval_manifest(
    path: str | Path,
    *,
    expected_case_ids: Iterable[str],
    database: str | Path,
    database_content_sha256: str,
    embedding_model: str,
    attack_kind: str,
) -> tuple[dict, dict[str, dict]]:
    metadata, entries = load_retrieval_manifest(path)
    expected_ids = [str(value) for value in expected_case_ids]
    actual_ids = list(entries)
    if actual_ids != expected_ids:
        missing = sorted(set(expected_ids) - set(actual_ids))
        extra = sorted(set(actual_ids) - set(expected_ids))
        raise ValueError(
            "Frozen retrieval manifest is not exactly paired with selected cases: "
            f"missing={missing[:10]}, extra={extra[:10]}, order_match={actual_ids == expected_ids}"
        )
    expected_db = str(Path(database).resolve())
    if metadata.get("database") != expected_db:
        raise ValueError(
            f"Frozen retrieval database mismatch: {metadata.get('database')!r} != {expected_db!r}"
        )
    if metadata.get("database_content_sha256") != database_content_sha256:
        raise ValueError("Frozen retrieval database content hash does not match the opened Chroma database")
    if metadata.get("embedding_model") != embedding_model:
        raise ValueError(
            f"Frozen retrieval embedding model mismatch: {metadata.get('embedding_model')!r} "
            f"!= {embedding_model!r}"
        )
    if str(metadata.get("attack_kind")) != str(attack_kind):
        raise ValueError(
            f"Frozen retrieval attack kind mismatch: {metadata.get('attack_kind')!r} != {attack_kind!r}"
        )
    for case_id, row in entries.items():
        query = str(row.get("memory_search") or "")
        document = row.get("memory_found")
        if row.get("memory_search_sha256") != sha256_text(query):
            raise ValueError(f"Frozen retrieval query hash mismatch for {case_id}")
        if document is not None and row.get("memory_found_sha256") != sha256_text(str(document)):
            raise ValueError(f"Frozen retrieval document hash mismatch for {case_id}")
        flags = retrieval_flags(document, str(row.get("task") or ""), str(row.get("attacker_tool") or ""))
        if any(bool(row.get(key)) != value for key, value in flags.items()):
            raise ValueError(f"Frozen retrieval flags are inconsistent with document for {case_id}")
    return metadata, entries
