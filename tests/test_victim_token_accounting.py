from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys

# The CI image used for offline protocol tests may not install the OpenAI SDK.
# Stub only the import surface required to load GPTLLM; no API call is made.
if "openai" not in sys.modules:
    openai_stub = ModuleType("openai")
    openai_stub.OpenAI = object
    openai_stub.APIConnectionError = RuntimeError
    openai_stub.RateLimitError = RuntimeError
    openai_stub.APIStatusError = RuntimeError
    sys.modules["openai"] = openai_stub

ASB_ROOT = Path(__file__).resolve().parents[1] / "experiments" / "benchmarks" / "ASB"
if str(ASB_ROOT) not in sys.path:
    sys.path.insert(0, str(ASB_ROOT))

from aios.llm_core.llm_classes.gpt_llm import GPTLLM


def test_openai_compatible_victim_token_accounting_is_shared_and_resettable():
    GPTLLM.reset_token_stats()
    response = SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=11, completion_tokens=7)
    )
    GPTLLM._record_usage(response)
    GPTLLM._record_usage(response)

    assert GPTLLM.get_token_stats() == {
        "total_calls": 2,
        "total_prompt_tokens": 22,
        "total_completion_tokens": 14,
        "total_tokens": 36,
    }

    GPTLLM.reset_token_stats()
    assert GPTLLM.get_token_stats()["total_tokens"] == 0
