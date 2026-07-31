import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class SecurityException(BaseException):
    """
    Exception raised when a security policy is violated.
    Inherits from BaseException to bypass standard try-except Exception blocks.
    """
    pass

class InterceptionContext(BaseModel):
    """
    Captures the context of a function interception in a Multi-Agent System.
    
    Attributes:
        timestamp: Unix timestamp of interception.
        function_name: Name of the intercepted function.
        module: Name of the module containing the function.
        agent_id: Identifier of the calling agent (e.g., "CoderAgent:0x123").
        args: Positional arguments passed to the function.
        kwargs: Keyword arguments passed to the function.
        stack_trace: The call stack at the time of interception.
        cleaned_payload: The extracted code/command string for auditing.
    """
    timestamp: float = Field(default_factory=time.time)
    function_name: str
    module: str
    agent_id: str = "System"
    args: List[Any] = Field(default_factory=list)
    kwargs: Dict[str, Any] = Field(default_factory=dict)
    stack_trace: str = ""
    cleaned_payload: str = ""
    flow_screening_enabled: Optional[bool] = None

class AuditResult(BaseModel):
    """
    Result of a security audit.
    
    Attributes:
        allowed: Whether the action is allowed.
        risk_score: A score between 0.0 (safe) and 1.0 (critical risk).
        reason: Explanation for the decision.
        violation_type: Type of violation (DPI, IPI, Backdoor, SafetyHazard, None).
        suggestions: Optional suggestion for safer alternative.
    """
    allowed: bool
    risk_score: float
    reason: str
    violation_type: str = "None"
    suggestions: Optional[str] = None

    # Paper/reproducibility metadata.  These fields make ablation decisions
    # inspectable without parsing free-form reason strings.
    ablation_mode: str = "full"
    decision_source: str = "unknown"
    static_enabled: bool = True
    taint_enabled: bool = True
    semantic_enabled: bool = True
    history_enabled: bool = True
    static_findings_count: int = 0
    static_risk_score: Optional[float] = None
    semantic_risk_score: Optional[float] = None
    taint_boost: float = 0.0
    cumulative_risk_before: float = 0.0
    cumulative_risk_after: float = 0.0
