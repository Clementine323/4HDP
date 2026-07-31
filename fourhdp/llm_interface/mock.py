from typing import Dict, Any, Tuple, Optional
from fourhdp.llm_interface.base import LLMProvider

class MockLLM(LLMProvider):
    """
    Mock LLM for testing purposes without API keys.
    """
    
    def analyze_intent(self, command: str, user_intent: str, context: Dict[str, Any], history_str: str = "") -> Tuple[float, str, Optional[str]]:
        """
        Returns high risk for keywords like 'rm', 'delete', 'format'.
        Otherwise returns 0.0.
        """
        # Simple keyword matching for testing
        dangerous_keywords = ["rm", "delete", "format", "dangerous"]
        
        # Check command
        for keyword in dangerous_keywords:
            if keyword in command.lower():
                return 1.0, f"Dangerous keyword '{keyword}' found in command.", "Consider using a safe alternative."
                
        # Check user intent just in case
        for keyword in dangerous_keywords:
            if keyword in user_intent.lower():
                return 1.0, f"Dangerous keyword '{keyword}' found in intent.", None
                
        return 0.0, "Deemed safe by MockLLM.", None
