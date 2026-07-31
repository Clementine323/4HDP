# ASB tool-call adapter

The executable adapter is `fourhdp/adapters/asb_adapter.py`. It converts a
structured ASB/PyOpenAGI tool call into a deterministic pseudo-Python payload
before the underlying tool is executed.

## Runtime-visible fields

The payload serialises the tool name, normalised call name, parameters, tool
description, original user intent, current agent thought, current step,
recent messages, request-local allowed tool names, the tool-surface flag, and
the final-stage flag.

## Oracle-free boundary

Benchmark-only attack labels, attack goals, expected achievements, and
attacker-tool class flags are accepted only for backward compatibility and are
not serialised into the audit payload. The defence therefore receives only
information available at interception time.

## Representation

```python
# ASB tool call intercepted by 4HDP before execution.
tool_call = "<deterministically serialised runtime-visible JSON>"
result = call_asb_tool(tool_call)
print(result)
```

The adapter does not execute this pseudo-code. Static, semantic, and
history-aware components inspect it as a pre-execution representation. The
actual call is executed only after an allow decision.

`extract_current_step` selects the latest user message matching
`At step N, you need to ...`; it does not use the previous assistant action as
the current step.

Relevant source files:

- `fourhdp/adapters/asb_adapter.py`
- `experiments/benchmarks/ASB/main_attacker_with_shield.py`
- `experiments/benchmarks/ASB/asb_eval_utils.py`
