# Semantic audit prompt

The complete public template is stored in
`prompts/semantic_audit_prompt_template.txt`. The executable source of truth is
the `system_prompt` f-string in `fourhdp/llm_interface/openai_client.py`.

At runtime the template receives:

- original user intent;
- agent identifier and current thought;
- intercepted code or command;
- up to five recent history events and current cumulative risk;
- static-analysis evidence and taint boost.

The audit request uses temperature `0.0`. The MP/MIXED revision campaign fixes
the semantic auditor to `gpt-4o`. Timeout and retry controls are exposed through
`FOURHDP_AUDIT_TIMEOUT` and `FOURHDP_AUDIT_RETRIES`.

Missing credentials, malformed JSON, exhausted retries, and unexpected audit
exceptions are handled fail-closed and are recorded separately from ordinary
security detections by the benchmark harness.
