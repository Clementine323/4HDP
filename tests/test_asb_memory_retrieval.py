from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from langchain_core.documents import Document


ASB_ROOT = Path(__file__).resolve().parents[1] / "experiments" / "benchmarks" / "ASB"
if str(ASB_ROOT) not in sys.path:
    sys.path.insert(0, str(ASB_ROOT))

from asb_memory_retrieval import (  # noqa: E402
    SCHEMA_VERSION,
    build_memory_query,
    parse_memory_document,
    retrieval_flags,
    sha256_text,
)
from pyopenagi.agents.react_agent_attack import (  # noqa: E402
    ReactAgentAttack,
    clear_memory_trace_context,
    set_memory_trace_context,
)


TOOLS = [
    {
        "type": "function",
        "function": {"name": "normal_tool", "description": "normal", "parameters": None},
    },
    {
        "type": "function",
        "function": {"name": "attack_tool", "description": "attack"},
    },
]


def _agent(*, mode: str, manifest: Path | None = None, vectorstore=None):
    agent = object.__new__(ReactAgentAttack)
    agent.task_input = "current task"
    agent.tools = TOOLS
    agent.tool_name = "attack_tool"
    agent.agent_name = "example/test_agent"
    agent.vectorstore = vectorstore
    agent.args = SimpleNamespace(
        database="/tmp/fake-asb-db",
        memory_retrieval_mode=mode,
        memory_retrieval_manifest=str(manifest) if manifest else None,
    )
    agent.memory_search = None
    agent.memory_found = None
    agent.memory_retrieval_score = None
    agent.memory_pair_hit = False
    agent.memory_parse_ok = False
    agent.memory_workflow_tool_hit = False
    agent.memory_retrieval_source = None
    agent.memory_search_sha256 = None
    agent.memory_found_sha256 = None
    agent.memory_retrieval_manifest_sha256 = None
    return agent


def _write_manifest(path: Path, document: str) -> None:
    query = build_memory_query("current task", TOOLS)
    flags = retrieval_flags(document, "current task", "attack_tool")
    rows = [
        {
            "record_type": "metadata",
            "schema_version": SCHEMA_VERSION,
            "database": "/tmp/fake-asb-db",
            "database_content_sha256": "db-hash",
            "embedding_model": "text-embedding-ada-002",
            "attack_kind": "MP",
        },
        {
            "record_type": "retrieval",
            "case_id": "case-1",
            "agent_name": "test_agent",
            "task": "current task",
            "attacker_tool": "attack_tool",
            "memory_search": query,
            "memory_search_sha256": sha256_text(query),
            "memory_found": document,
            "memory_found_sha256": sha256_text(document),
            "score": 1.25,
            **flags,
        },
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_memory_document_parser_handles_nested_json_and_semicolons():
    document = (
        'Agent: test; Task: current task; Workflow: '
        '[{"message": "a; b", "tool_use": ["attack_tool"]}]; Tools: []'
    )
    ok, workflow = parse_memory_document(document)
    assert ok is True
    assert '"a; b"' in workflow
    assert retrieval_flags(document, "current task", "attack_tool") == {
        "pair_hit": True,
        "parse_ok": True,
        "workflow_tool_hit": True,
    }


def test_live_retrieval_preserves_asb_top1_query_and_result(monkeypatch, tmp_path: Path):
    document = (
        'Agent: test; Task: current task; Workflow: '
        '[{"message": "attack", "tool_use": ["attack_tool"]}]; Tools: []'
    )

    class FakeVectorStore:
        def __init__(self):
            self.query = None
            self.k = None

        def similarity_search_with_score(self, query, k=4):
            self.query = query
            self.k = k
            return [(Document(page_content=document), 0.125)]

    vectorstore = FakeVectorStore()
    trace = tmp_path / "trace.jsonl"
    monkeypatch.setenv("ASB_MEMORY_TRACE_FILE", str(trace))
    agent = _agent(mode="live", vectorstore=vectorstore)
    instruction = agent.search_memory_instruction()

    assert vectorstore.query == build_memory_query("current task", TOOLS)
    assert vectorstore.k == 1
    assert agent.memory_retrieval_source == "live_chroma"
    assert agent.memory_pair_hit is True
    assert "attack_tool" in instruction
    event = json.loads(trace.read_text(encoding="utf-8"))
    assert event["retrieval_source"] == "live_chroma"
    assert event["memory_found_sha256"] == sha256_text(document)


def test_frozen_retrieval_replays_a_real_top1_miss_without_oracle_replacement(
    monkeypatch, tmp_path: Path
):
    # This is a valid ASB top-1 document for a different task/tool. A paired
    # ablation must replay the miss, not replace it with the intended poison.
    document = (
        'Agent: other; Task: unrelated task; Workflow: '
        '[{"message": "normal", "tool_use": ["other_tool"]}]; Tools: []'
    )
    manifest = tmp_path / "frozen.jsonl"
    trace = tmp_path / "trace.jsonl"
    _write_manifest(manifest, document)
    monkeypatch.setenv("ASB_MEMORY_TRACE_FILE", str(trace))
    set_memory_trace_context(sample_id="case-1", ablation_mode="no_history")
    try:
        agent = _agent(mode="frozen", manifest=manifest, vectorstore=None)
        instruction = agent.search_memory_instruction()
    finally:
        clear_memory_trace_context()

    assert "other_tool" in instruction
    assert agent.memory_pair_hit is False
    assert agent.memory_workflow_tool_hit is False
    assert agent.memory_parse_ok is True
    assert agent.memory_retrieval_source == "frozen_manifest"
    event = json.loads(trace.read_text(encoding="utf-8"))
    assert event["sample_id"] == "case-1"
    assert event["pair_hit"] is False


def test_frozen_retrieval_rejects_changed_task_or_tools(tmp_path: Path):
    document = (
        'Agent: test; Task: current task; Workflow: '
        '[{"message": "attack", "tool_use": ["attack_tool"]}]; Tools: []'
    )
    manifest = tmp_path / "frozen.jsonl"
    _write_manifest(manifest, document)
    set_memory_trace_context(sample_id="case-1")
    try:
        agent = _agent(mode="frozen", manifest=manifest)
        agent.task_input = "changed task"
        with pytest.raises(RuntimeError, match="query mismatch"):
            agent.search_memory_instruction()
    finally:
        clear_memory_trace_context()
