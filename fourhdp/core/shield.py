"""
FourHDP: Multi-Agent Security Controller.
Supports MAS by binding intents to specific agent instances.
"""
import functools
import logging
import sys
from typing import Callable, Optional, Dict, Any

from fourhdp.core.datatypes import SecurityException, InterceptionContext
from fourhdp.core.instrumentation.interceptor import SystemInterceptor
from fourhdp.core.auditor.engine import HybridAuditor
from fourhdp.core.memory.trace import ExecutionMemory

logger = logging.getLogger("FourHDP")


def _print_section(title, content_lines, width=70):
    """Print a structured log section for verbose mode."""
    print(f"\n[{title}]")
    for line in content_lines:
        print(f"  {line}")


class FourHDP:
    _instance: Optional["FourHDP"] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self.interceptor = SystemInterceptor()
        self.auditor = HybridAuditor()
        self.memory = ExecutionMemory()
        self._agent_intents: Dict[str, str] = {}
        # New: Store current thoughts dynamically passed from Agent framework
        self._agent_thoughts: Dict[str, str] = {}
        self.mode: str = "BLOCK"
        self._verbose: bool = False
        self._interception_count: int = 0
        self._active_unhookers = []
        self._bypass_low_level: bool = False
        self._initialized = True
        
    def enable(self, agent_instance: Any, user_intent: str, verbose: bool = False):
        agent_id = f"{type(agent_instance).__name__}:{hex(id(agent_instance))}"
        self._agent_intents[agent_id] = user_intent
        self._verbose = verbose
        self._interception_count = 0
        self._bypass_low_level = False
        
        _ = self.auditor.llm

        # 原生函数目标
        targets = [
            ('builtins', 'exec'),
            ('builtins', 'eval'),
            ('os', 'system'),
            ('subprocess', 'run'),
            ('subprocess', 'call'),
            ('subprocess', 'Popen'),
        ]
        
        # self._hook_safe 函数内部 调用了 interceptor.py 里的 hook_function
        for module_name, func_name in targets:
            self._hook_safe(module_name, func_name)

        # Dynamically load and apply framework adapters if needed
        from fourhdp.adapters import get_adapter_hooks
        hook_func, unhook_func, bypass_ll = get_adapter_hooks(agent_instance)
        if hook_func:
            original_func = hook_func(self, agent_instance, agent_id, user_intent)
            if original_func and unhook_func:
                self._bypass_low_level = bypass_ll
                self._active_unhookers.append(lambda: unhook_func(agent_instance, original_func))
        
        logger.info(f"FourHDP enabled for {agent_id}.")

    def update_agent_thought(self, agent_instance: Any, current_thought: str):
        """Allows dynamic injection of the agent's current thought process."""
        agent_id = f"{type(agent_instance).__name__}:{hex(id(agent_instance))}"
        self._agent_thoughts[agent_id] = current_thought

    def _hook_safe(self, module_name: str, func_name: str):
        try:
            self.interceptor.hook_function(
                module_name=module_name,
                func_name=func_name,
                execution_wrapper=self._enforcement_wrapper
            )
        except Exception:
            pass
    
    def _enforcement_wrapper(self, ctx: InterceptionContext, original_func: Callable, *args, **kwargs):
        agent_id = ctx.agent_id
        intent = self._agent_intents.get(agent_id, "Unknown or background task.")
        thought = self._agent_thoughts.get(agent_id, "Not provided at OS level.")
        ablation_mode, ablation_spec = self.auditor.get_ablation_spec()

        # When a high-level framework hook is active, bypass low-level exec/eval audit
        # for the same agent. The real defense is at the framework level
        # where we see actual agent-generated code, not compiled library bytecode.
        if self._bypass_low_level and ctx.function_name in (
            'builtins.exec', 'builtins.eval'
        ):
            return original_func(*args, **kwargs)
        
        logger.info(f"Auditing: {ctx.function_name} from {agent_id}")
        
        if ablation_spec.history_enabled:
            history_str = self.memory.get_recent_history(agent_id, limit=5)
            cumulative_risk = self.memory.get_cumulative_risk(agent_id)
        else:
            history_str = ""
            cumulative_risk = 0.0

        # --- Verbose: LAYER 1 - INTERCEPTOR ---
        if self._verbose:
            self._interception_count += 1
            print("\n" + "=" * 70)
            print(f"  INTERCEPTION EVENT #{self._interception_count}")
            print("=" * 70)
            _print_section("LAYER 1 - INTERCEPTOR", [
                f"Function:  {ctx.function_name}",
                f"Caller:    {agent_id}",
                f"Module:    {ctx.module}",
                f"Ablation:  {ablation_mode}",
                f"Payload:   {(ctx.cleaned_payload or '(empty)')[:200]}",
            ])

        # --- AST Analysis for verbose output only ---
        ast_findings = []
        if ablation_spec.static_enabled and ctx.cleaned_payload:
            ast_findings = self.auditor.ast_analyzer.analyze(ctx.cleaned_payload)
        if not ablation_spec.taint_enabled:
            ast_findings = self.auditor._strip_taint(ast_findings)

        # --- Verbose: LAYER 2 - AST ---
        if self._verbose:
            if not ablation_spec.static_enabled:
                finding_lines = [
                    "Static analysis disabled by ablation.",
                    "Taint Boost: 0.00",
                ]
            elif ast_findings:
                finding_lines = [f"Findings:  {len(ast_findings)} issue(s) detected"]
                for i, f in enumerate(ast_findings, 1):
                    finding_lines.append(
                        f"{i}. {self.auditor._format_single_finding(f)}"
                    )
                taint_boost = self.auditor._compute_taint_boost(ast_findings) if ablation_spec.taint_enabled else 0.0
                finding_lines.append(f"Taint Boost: {taint_boost:.2f}")
            else:
                finding_lines = [
                    "Findings:  0 issues (clean)",
                    "Taint Boost: 0.00",
                ]
            _print_section("LAYER 2 - AST STATIC ANALYSIS", finding_lines)

        # --- Run full audit according to the selected ablation mode ---
        result = self.auditor.audit(
            ctx=ctx,
            user_intent=intent,
            history_str=history_str,
            current_cumulative_risk=cumulative_risk,
            current_thought=thought
        )

        # --- Verbose: LAYER 3 - LLM AUDIT ---
        if self._verbose:
            # Extract the core LLM reasoning (strip the appended decision tags)
            reasoning_text = result.reason
            # Remove the "[Action Blocked..." suffix for cleaner display
            if "[Action Blocked" in reasoning_text:
                core_reasoning = reasoning_text[:reasoning_text.index("[Action Blocked")].strip()
            elif "Static Analysis Evidence" in reasoning_text:
                core_reasoning = reasoning_text
            else:
                core_reasoning = reasoning_text

            if result.semantic_enabled:
                semantic_line = f"Semantic Risk: {result.semantic_risk_score if result.semantic_risk_score is not None else 'N/A'}"
            else:
                semantic_line = "Semantic audit disabled by ablation."
            _print_section("LAYER 3 - LLM AUDIT ENGINE", [
                f"User Intent:   \"{intent[:80]}\"",
                f"Risk Score:    {result.risk_score:.2f}",
                f"Violation:     {result.violation_type}",
                f"Decision:      {result.decision_source}",
                semantic_line,
                f"Reasoning:     {core_reasoning[:300]}",
            ])

        # --- Record to memory only when the history/risk-state module is enabled ---
        if result.history_enabled:
            self.memory.add_event(agent_id, ctx, result)
            new_cumulative = self.memory.get_cumulative_risk(agent_id)
            new_history = self.memory.get_recent_history(agent_id, limit=5)
        else:
            new_cumulative = 0.0
            new_history = "[history disabled by ablation]"

        # --- Verbose: LAYER 4 - MEMORY ---
        if self._verbose:
            _print_section("LAYER 4 - EXECUTION MEMORY", [
                f"Enabled: {result.history_enabled}",
                f"Cumulative Risk: {new_cumulative:.2f} (threshold: 0.90)",
                "Recent History:",
            ])
            for hist_line in new_history.split("\n"):
                print(f"    {hist_line}")

            decision = "BLOCKED" if not result.allowed else "ALLOWED"
            print(f"\n  [DECISION] >>> {decision} <<<")
            print("=" * 70)
            sys.stdout.flush()

        # # 判断大模型/静态分析得出的结果是否被设定为不允许放行 (allowed = False)
        if not result.allowed:
            reason = f"Policy Violation: {ctx.function_name} | Agent: {agent_id} | " \
                     f"Reason: {result.reason} | Risk: {result.risk_score:.2f}"
            logger.error(f"BLOCKING: {reason}")
            
            if self.mode == "BLOCK":
                # 当模式为 BLOCK 时，直接通过抛出异常打断当前的程序流
                raise SecurityException(reason)
            elif self.mode == "WARN":
                logger.warning(f"[WARN] Potential threat: {reason}")
        
        # 若 allowed 为 True 或未匹配 BLOCK 模式导致没有抛出异常中断，
        # 则代码最终运行到这里，系统以原参数透传给原始 API。
        return original_func(*args, **kwargs)

    def disable(self):
        self.interceptor.unhook_all()
        # Restore any high-level framework hooks
        for unhooker in self._active_unhookers:
            try:
                unhooker()
            except Exception as e:
                logger.error(f"Error during unhook: {e}")
        self._active_unhookers.clear()
        self._bypass_low_level = False
        self._verbose = False
        self._interception_count = 0
        self._agent_intents.clear()
        self._agent_thoughts.clear()
        logger.info("FourHDP deactivated.")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disable()
