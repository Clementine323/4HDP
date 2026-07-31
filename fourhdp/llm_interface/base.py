from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple, Optional

class LLMProvider(ABC):
    """
    Abstract base class for LLM providers used in security auditing.
    """
    
    @abstractmethod
    def analyze_intent(self, command: str, user_intent: str, context: Dict[str, Any], history_str: str = "") -> Tuple[float, str, Optional[str]]:
        """
        Analyzes the risk of a given command based on user intent and context.
        
        Args:
            command: The specific command or function call being executed.
            user_intent: The high-level intent description provided by the agent.
            context: Additional context context (e.g., args, kwargs, AST findings).

        Returns:
            Tuple[float, str, Optional[str]]: Risk score, reasoning, and optional suggestion for mitigation.
        """
        pass
