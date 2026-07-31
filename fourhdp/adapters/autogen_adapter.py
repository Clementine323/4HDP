"""
AutoGen Adapter for FourHDP.

Hooks AutoGen's `UserProxyAgent.run_code(code)` — the framework-level entry
point where LLM-generated code blocks are dispatched to subprocess execution.

AutoGen internally calls: run_code → execute_code → write tmpfile → subprocess.run.
We intercept at run_code (before code enters the subprocess boundary).
"""
import logging

from fourhdp.core.datatypes import InterceptionContext

logger = logging.getLogger("FourHDP")


def hook_autogen(shield, executor, agent_id: str, user_intent: str):
    """
    Patch an AutoGen UserProxyAgent (executor) so every `run_code(code)`
    goes through FourHDP's 4-layer enforcement pipeline.

    Why hook run_code instead of subprocess.run?
      1. run_code has the raw code string; subprocess.run only sees a file path
      2. subprocess.run happens in a child process — parent hooks can't reach it
      3. run_code is called once per code block — subprocess.run has framework noise

    Args:
        shield: FourHDP instance
        executor: AutoGen UserProxyAgent instance
        agent_id: Unique agent identifier (e.g. "AutoGen_Deployer")
        user_intent: The user's original task description

    Returns:
        The original `run_code` method (for restore).
    """
    original_run_code = executor.run_code

    # Register with shield
    shield._agent_intents[agent_id] = user_intent



    def _shielded_run_code(code, **kwargs):
        """Intercept AutoGen code execution and audit through FourHDP."""
        lang = kwargs.get("lang", "python")
        logger.info(f"[AutoGen Adapter] Intercepted run_code | Agent: {agent_id} | Lang: {lang}")

        ctx = InterceptionContext(
            function_name=f"autogen.run_code({lang})",
            module="autogen.UserProxyAgent",
            agent_id=agent_id,
            args=[code],
            kwargs=kwargs,
            stack_trace="",
            cleaned_payload=code[:2000],
        )

        # 4-layer pipeline: AST → LLM Audit → Risk Decision
        # Blocked → SecurityException (code never runs)
        # Allowed → original_run_code(code, **kwargs)
        return shield._enforcement_wrapper(ctx, original_run_code, code, **kwargs)

    executor.run_code = _shielded_run_code
    logger.info(f"[AutoGen Adapter] Hooked run_code for {agent_id}")
    return original_run_code


def unhook_autogen(executor, original_run_code):
    """Restore the original run_code method."""
    executor.run_code = original_run_code
    logger.info("[AutoGen Adapter] Restored original run_code")
