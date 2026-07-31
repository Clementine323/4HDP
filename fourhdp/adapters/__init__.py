"""
FourHDP Adapters — Framework-specific hooks for code execution interception.

Each adapter patches a specific agent framework's code execution entry point,
routing LLM-generated code through FourHDP's 4-layer enforcement pipeline.

Supported frameworks:
  - Open Interpreter (OI): hooks computer.run(lang, code)
  - AutoGen:               hooks executor.run_code(code)
  - ASB (Tool-based):      hooks agent.call_tools(tool)
"""

from fourhdp.adapters.oi_adapter import hook_open_interpreter, unhook_open_interpreter
from fourhdp.adapters.autogen_adapter import hook_autogen, unhook_autogen

def get_adapter_hooks(agent_instance):
    """
    Dynamically determine if the agent_instance requires a special framework hook.

    Returns:
        (hook_func, unhook_func, bypass_low_level)
        - hook_func: function to patch the framework's execution entry point.
        - unhook_func: function to restore the original method.
        - bypass_low_level: bool indicating if low-level hooks (exec/eval) should be
          bypassed when this framework hook intercepts the execution, to avoid duplicate audits.
    """
    if not agent_instance:
        return None, None, False

    instance_type_name = type(agent_instance).__name__
    module_name = type(agent_instance).__module__

    # Open Interpreter heuristics
    if "interpreter" in module_name.lower() or instance_type_name == "OpenInterpreter":
        return hook_open_interpreter, unhook_open_interpreter, True

    # AutoGen heuristics
    if "autogen" in module_name.lower() and instance_type_name == "UserProxyAgent":
        return hook_autogen, unhook_autogen, False

    # Default: No special adapter needed (relies on standard interceptor targets)
    return None, None, False

__all__ = [
    "hook_open_interpreter",
    "unhook_open_interpreter",
    "hook_autogen",
    "unhook_autogen",
    "get_adapter_hooks",
]
