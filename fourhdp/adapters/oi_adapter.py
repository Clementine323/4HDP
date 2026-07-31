"""
Open Interpreter Adapter for FourHDP.

Hooks OI's `computer.run(language, code)` — the framework-level entry point
where LLM-generated code is dispatched to the Jupyter kernel.
"""
import functools
import logging

from fourhdp.core.datatypes import InterceptionContext

logger = logging.getLogger("FourHDP")


def hook_open_interpreter(shield, agent_instance, agent_id: str, user_intent: str):
    """
    Patch an Open Interpreter instance so every `computer.run(lang, code)`
    goes through FourHDP's 4-layer enforcement pipeline.

    Args:
        shield: FourHDP instance
        agent_instance: The Open Interpreter `interpreter` object
        agent_id: Unique agent identifier
        user_intent: The user's original task description

    Returns:
        The original `computer.run` function (for restore).
        None if the instance has no `computer.run`.
    """
    if not hasattr(agent_instance, "computer"):
        return None
    if not hasattr(agent_instance.computer, "run"):
        return None

    original_run = agent_instance.computer.run
    shield._agent_intents[agent_id] = user_intent

    @functools.wraps(original_run)
    def _hooked_computer_run(language: str, code: str, *args, **kwargs):
        ctx = InterceptionContext(
            function_name=f"computer.run({language})",
            module="interpreter.computer",
            agent_id=agent_id,
            args=[language, code],
            kwargs=kwargs,
            stack_trace="",
            cleaned_payload=code[:2000],
        )
        return shield._enforcement_wrapper(
            ctx, original_run, language, code, *args, **kwargs
        )

    agent_instance.computer.run = _hooked_computer_run
    logger.info(f"[OI Adapter] Hooked computer.run for {agent_id}")
    return original_run


def unhook_open_interpreter(agent_instance, original_run):
    """Restore the original computer.run method."""
    if original_run and hasattr(agent_instance, "computer"):
        agent_instance.computer.run = original_run
        logger.info("[OI Adapter] Restored original computer.run")
