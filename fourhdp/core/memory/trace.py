"""
Multi-Agent Execution Memory.

Tracks execution history per agent for contextual auditing and cumulative risk calculation.
"""
import os
from typing import Dict, List, Any
from pydantic import BaseModel, Field
from datetime import datetime

from fourhdp.core.datatypes import InterceptionContext, AuditResult


class TraceEvent(BaseModel):
    """Represents a single historical event in an agent's execution trace."""
    timestamp: float = Field(default_factory=lambda: datetime.now().timestamp())
    agent_id: str = "System"
    function: str
    payload: str = ""
    risk_score: float
    allowed: bool = True
    fs_changes: List[str] = Field(default_factory=list)


class ExecutionMemory:
    """
    Per-Agent Execution Memory for Multi-Agent Systems.
    Maintains separate history for each agent ID and tracks cumulative risk.
    """
    
    def __init__(self):
        self.agent_traces: Dict[str, List[TraceEvent]] = {}
        self._cumulative_risk: Dict[str, float] = {}

    def add_event(
        self, 
        agent_id: str, 
        ctx: InterceptionContext, 
        result: AuditResult
    ) -> TraceEvent:
        event = TraceEvent(
            timestamp=ctx.timestamp,
            agent_id=agent_id,
            function=ctx.function_name,
            payload=ctx.cleaned_payload[:200],  # Truncate for memory
            risk_score=result.risk_score,
            allowed=result.allowed
        )
        
        if agent_id not in self.agent_traces:
            self.agent_traces[agent_id] = []
            self._cumulative_risk[agent_id] = 0.0
            
        self.agent_traces[agent_id].append(event)
        
        # Calculate cumulative risk over the last 5 steps (sliding window)
        recent_events = self.agent_traces[agent_id][-5:]

        risk_floor = max(
            0.0,
            min(
                1.0,
                float(
                    os.environ.get(
                        "FOURHDP_CUMULATIVE_RISK_FLOOR",
                        "0.0",
                    )
                ),
            ),
        )

        self._cumulative_risk[agent_id] = sum(
            max(0.0, float(event.risk_score) - risk_floor)
            for event in recent_events
        )
        
        # Limit history per agent to prevent memory bloat
        if len(self.agent_traces[agent_id]) > 50:
            self.agent_traces[agent_id] = self.agent_traces[agent_id][-50:]
            
        return event

    def get_cumulative_risk(self, agent_id: str) -> float:
        """Returns the cumulative risk score for the agent's recent steps."""
        return self._cumulative_risk.get(agent_id, 0.0)

    def update_last_event(self, agent_id: str, fs_changes: List[str]):
        if agent_id in self.agent_traces and self.agent_traces[agent_id]:
            self.agent_traces[agent_id][-1].fs_changes = fs_changes

    def get_recent_history(self, agent_id: str, limit: int = 5) -> str:
        if agent_id not in self.agent_traces or not self.agent_traces[agent_id]:
            return f"No previous actions for agent {agent_id}."
            
        recent = self.agent_traces[agent_id][-limit:]
        lines = []
        for idx, event in enumerate(recent):
            status = "ALLOWED" if event.allowed else "BLOCKED"
            line = f"{idx+1}. [{status}] {event.function}: {event.payload[:50]}... (Risk: {event.risk_score:.2f})"
            if event.fs_changes:
                line += f" | FS: {event.fs_changes[:2]}"
            lines.append(line)
        
        return "\n".join(lines)

    def get_all_agents(self) -> List[str]:
        return list(self.agent_traces.keys())

    def clear_agent(self, agent_id: str):
        """Remove traces and risk for a single agent."""
        self.agent_traces.pop(agent_id, None)
        self._cumulative_risk.pop(agent_id, None)

    def clear(self):
        self.agent_traces.clear()
        self._cumulative_risk.clear()