# registering all proprietary llm models in a constant

from .gpt_llm import GPTLLM
from .gemini_llm import GeminiLLM
from .bed_rock import BedrockLLM
from .llama_llm import LlamaLLM

#used for closed LLM model registry
MODEL_REGISTRY = {
    # Gemini-1.5
    "gemini-1.5-flash": GeminiLLM,
    "gemini-1.5-pro": GeminiLLM,

    # GPT3.5
    'gpt-3.5-turbo': GPTLLM,
    'gpt-4-turbo': GPTLLM,

    # GPT4o
    'gpt-4o': GPTLLM,
    'gpt-4o-2024-08-06': GPTLLM,
    'gpt-4o-mini': GPTLLM,

    # Llama 3.1 (via OpenAI-compatible provider)
    'llama-3.1-70b-instruct': LlamaLLM
}
