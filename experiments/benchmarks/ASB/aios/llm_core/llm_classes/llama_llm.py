import re
import json
import time
from typing import List, Dict, Any
from .gpt_llm import GPTLLM
from pyopenagi.utils.chat_template import Response

class LlamaLLM(GPTLLM):
    """
    LlamaLLM class for interacting with Llama models via OpenAI-compatible proxy.
    
    This class inherits from GPTLLM as Llama 3 models on the current proxy 
    (OpenAI-compatible provider) use the OpenAI-compatible chat completions API.
    """

    def __init__(self, llm_name: str,
                 max_gpu_memory: Dict[int, str] = None,
                 eval_device: str = None,
                 max_new_tokens: int = 1024,
                 log_mode: str = "console"):
        super().__init__(llm_name,
                         max_gpu_memory=max_gpu_memory,
                         eval_device=eval_device,
                         max_new_tokens=max_new_tokens,
                         log_mode=log_mode)

    def process(self, agent_process: Any, temperature: float = 0.0) -> None:
        """
        Process a query using the Llama model.
        """
        # Ensure the model name is correct for this class if needed, 
        # though we allow various Llama variants.
        # assert re.search(r'llama', self.model_name, re.IGNORECASE), "Model name must contain 'llama'"
        
        # Use the underlying GPTLLM process logic as it handles the OpenAI proxy correctly
        super().process(agent_process, temperature)
