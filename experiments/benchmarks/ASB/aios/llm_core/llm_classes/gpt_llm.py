import re
from .base_llm import BaseLLM
import time
import threading

# could be dynamically imported similar to other models
from openai import OpenAI

import openai

from pyopenagi.utils.chat_template import Response
import json

class GPTLLM(BaseLLM):
    """OpenAI-compatible victim-model wrapper with process-local usage metrics.

    The counters are intentionally maintained at class level so one experiment
    process can aggregate usage across the scheduler's worker threads.  LlamaLLM
    inherits this implementation, so OpenAI-compatible Llama calls use the same
    accounting path.
    """

    _usage_lock = threading.Lock()
    _total_prompt_tokens = 0
    _total_completion_tokens = 0
    _total_calls = 0

    @classmethod
    def reset_token_stats(cls):
        with GPTLLM._usage_lock:
            GPTLLM._total_prompt_tokens = 0
            GPTLLM._total_completion_tokens = 0
            GPTLLM._total_calls = 0

    @classmethod
    def get_token_stats(cls):
        with GPTLLM._usage_lock:
            prompt = int(GPTLLM._total_prompt_tokens)
            completion = int(GPTLLM._total_completion_tokens)
            calls = int(GPTLLM._total_calls)
        return {
            "total_calls": calls,
            "total_prompt_tokens": prompt,
            "total_completion_tokens": completion,
            "total_tokens": prompt + completion,
        }

    @classmethod
    def _record_usage(cls, response):
        usage = getattr(response, "usage", None)
        if usage is None:
            return
        prompt = int(getattr(usage, "prompt_tokens", 0) or 0)
        completion = int(getattr(usage, "completion_tokens", 0) or 0)
        with GPTLLM._usage_lock:
            GPTLLM._total_prompt_tokens += prompt
            GPTLLM._total_completion_tokens += completion
            GPTLLM._total_calls += 1

    def __init__(self, llm_name: str,
                 max_gpu_memory: dict = None,
                 eval_device: str = None,
                 max_new_tokens: int = 1024,
                 log_mode: str = "console"):
        super().__init__(llm_name,
                         max_gpu_memory,
                         eval_device,
                         max_new_tokens,
                         log_mode)

    def load_llm_and_tokenizer(self) -> None:
        import os
        api_key = os.environ.get("OPENAI_API_KEY")
        base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.model = OpenAI(api_key=api_key, base_url=base_url)
        self.tokenizer = None

    def parse_tool_calls(self, tool_calls):
        if tool_calls:
            parsed_tool_calls = []
            for tool_call in tool_calls:
                function_name = tool_call.function.name
                function_args = json.loads(tool_call.function.arguments)
                parsed_tool_calls.append(
                    {
                        "name": function_name,
                        "parameters": function_args
                    }
                )
            return parsed_tool_calls
        return None

    def process(self,
            agent_process,
            temperature=0.0
        ):
        # ensures the model is the current one
        # assert re.search(r'gpt', self.model_name, re.IGNORECASE)

        """ wrapper around openai api """
        agent_process.set_status("executing")
        agent_process.set_start_time(time.time())
        messages = agent_process.query.messages
        # print(messages)
        self.logger.log(
            f"{agent_process.agent_name} is switched to executing.\n",
            level = "executing"
        )
        
        # Simple retry logic for stability
        max_retries = 3
        retry_count = 0
        last_error = "Unknown error"
        
        while retry_count < max_retries:
            try:
                time.sleep(2) # rate limit mitigation
                response = self.model.chat.completions.create(
                    model=self.model_name,
                    messages = messages,
                    tools = agent_process.query.tools,
                    # tool_choice = "required" if agent_process.query.tools else None,
                    max_tokens = self.max_new_tokens,
                    seed = 0,
                    temperature = temperature,
                )
                
                if response is None:
                    last_error = "API returned None"
                    retry_count += 1
                    continue

                # Handle case where proxy returns error inside a successful response object
                if hasattr(response, 'error') and response.error:
                    error_msg = response.error.get('message', 'Unknown proxy error')
                    print(f"DEBUG: Proxy reported error (attempt {retry_count+1}/{max_retries}): {error_msg}")
                    last_error = f"Proxy Error: {error_msg}"
                    # If it's a server error or rate limit, we retry
                    if "server_error" in error_msg or "饱和" in error_msg:
                        retry_count += 1
                        time.sleep(5)
                        continue
                    else:
                        # For other types of errors (e.g. invalid request), no point in retrying
                        agent_process.set_response(Response(response_message=last_error))
                        agent_process.set_status("done")
                        return

                if not hasattr(response, 'choices') or response.choices is None or len(response.choices) == 0:
                    print(f"DEBUG ERROR: response structure is invalid. Response: {response}")
                    last_error = "Error: API returned invalid response structure or empty choices"
                    retry_count += 1
                    continue

                GPTLLM._record_usage(response)
                response_message = response.choices[0].message.content or ""
                tool_calls = self.parse_tool_calls(
                    response.choices[0].message.tool_calls
                )
                
                agent_process.set_response(
                    Response(
                        response_message = response_message,
                        tool_calls = tool_calls
                    )
                )
                # Success - break retry loop
                break
                
            except (openai.APIConnectionError, openai.RateLimitError, openai.APIStatusError) as e:
                print(f"DEBUG: API error (attempt {retry_count+1}/{max_retries}): {str(e)}")
                last_error = f"API Error: {str(e)}"
                retry_count += 1
                time.sleep(5)
            except Exception as e:
                print(f"DEBUG: Unexpected error (attempt {retry_count+1}/{max_retries}): {str(e)}")
                last_error = f"An unexpected error occurred: {e}"
                retry_count += 1
                time.sleep(2)

        if retry_count == max_retries:
            self.logger.log(f"Failed after {max_retries} attempts. Last error: {last_error}", level="warning")
            agent_process.set_response(Response(response_message=last_error))

        agent_process.set_status("done")
        agent_process.set_end_time(time.time())
