"""
Oracle-free ASB adapter for 4HDP.

The adapter converts an ASB/PyOpenAGI tool call into a deployment-visible
pseudo Python payload for pre-execution auditing.  It deliberately avoids using
benchmark-only oracle fields such as the attack label, AttackerTool class, or
attack goal.  Only the information that a runtime defense could observe before
execution is serialized: tool name, tool parameters, tool description, user task,
recent conversation, and step metadata.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Optional, Sequence

logger = logging.getLogger("FourHDP.ASB")


_STEP_PROMPT_RE = re.compile(
    r"^\s*At step\s+\d+[,]?\s+you need to\s+",
    flags=re.IGNORECASE,
)


def extract_current_step(messages: Optional[list], char_limit: int = 1000) -> str:
    """Return the latest deployment-visible ASB step instruction.

    The current tool call is generated in response to a user message of the form
    ``At step N, you need to ...``.  At interception time the model's current
    assistant tool-call message has not yet been appended to ``self.messages``;
    therefore using the latest assistant message would incorrectly select the
    previous step's action/observation.
    """
    for msg in reversed(messages or []):
        if not isinstance(msg, dict) or msg.get("role") != "user":
            continue
        content = str(msg.get("content", "")).strip()
        if _STEP_PROMPT_RE.match(content):
            return content[:char_limit]
    return ""


def tool_call_to_code(
    tool_name: str,
    tool_params: Optional[Dict[str, Any]] = None,
    description: str = "",
    *,
    user_intent: str = "",
    current_thought: str = "",
    current_step: str = "",
    recent_messages: Optional[list] = None,
    allowed_tool_names: Optional[Sequence[str]] = None,
    enforce_tool_surface: bool = True,
    final_stage: bool = False,
    # Backward-compatible but intentionally ignored oracle fields:
    attack_goal: Optional[str] = None,
    expected_achievement: Optional[str] = None,
    is_attacker_tool: bool = False,
) -> str:
    """
    Convert a structured ASB tool call into a pseudo-code payload for auditing.

    Parameters marked as oracle fields are accepted to keep older scripts from
    breaking, but they are not serialized into the audit input.  This prevents
    the defense from seeing information unavailable at deployment time.
    """
    func_name = _to_snake_case(tool_name or "unknown_tool")
    visible_payload = {
        "tool_name": tool_name,
        "normalized_call": func_name,
        "parameters": tool_params if tool_params is not None else {},
        "description": description or "",
        "user_intent": user_intent or "",
        "current_thought": current_thought or "",
        "current_step": current_step or "",
        "recent_messages": _trim_messages(recent_messages or []),
        "allowed_tool_names": (
            None
            if allowed_tool_names is None
            else sorted({str(name) for name in allowed_tool_names if str(name).strip()})
        ),
        "enforce_tool_surface": bool(enforce_tool_surface),
        "final_stage": bool(final_stage),
    }

    serialized = json.dumps(visible_payload, ensure_ascii=False, sort_keys=True)
    return "\n".join([
        "# ASB tool call intercepted by 4HDP before execution.",
        "# Oracle-free setting: no benchmark labels, attack goals, or attacker-tool flags are used.",
        f"tool_call = {serialized!r}",
        "result = call_asb_tool(tool_call)",
        "print(result)",
    ])


def _trim_messages(messages: list, limit: int = 4, char_limit: int = 500) -> list:
    """Keep the recent ASB conversation compact and deterministic."""
    compact = []
    for msg in messages[-limit:]:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role", ""))[:32]
        content = str(msg.get("content", ""))[:char_limit]
        compact.append({"role": role, "content": content})
    return compact


def _to_snake_case(name: str) -> str:
    name = str(name or "unknown_tool")
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()
