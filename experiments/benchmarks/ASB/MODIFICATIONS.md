# 4HDP modifications to the ASB/AIOS evaluation harness

Upstream reference recorded by the frozen retrieval manifests:
`agiresearch/asb@eac7bcf`.

The public evaluation layer adds or modifies the following behaviour:

- `main_attacker_with_shield.py`: pre-execution 4HDP interception, oracle-free
  adapter integration, security/audit/framework outcome separation, and audit
  metadata accounting.
- `main_attacker_baseline_timing.py`: matched no-defence timing and the corrected
  Chroma object/hash interface used by the final MP/MIXED campaign.
- `main_attacker_matched.py`: frozen-manifest matched prompt-defence runner.
- `asb_eval_utils.py`: balanced deterministic case selection, frozen manifest
  I/O, and strict all-required-normal-tools completion.
- `asb_memory_retrieval.py`: frozen retrieval schema, validation, and hashes.
- `pyopenagi/agents/react_agent_attack.py`: memory-retrieval trace context and
  integration with the frozen retrieval protocol.
- `pyopenagi/agents/base_agent.py`: robust workflow parsing for plain JSON,
  fenced JSON, and JSON embedded in prose, with schema validation.
- `aios/llm_core/llm_classes/gpt_llm.py`: shared victim-model token accounting.
- revision runners and validators under this directory: fixed seeds, frozen
  inputs, model-role separation, and result-integrity checks.

Benchmark labels and attack goals are not exposed to the 4HDP audit decision.
