# Output and accounting schema

The runners write local outputs that are deliberately excluded from this
release. The defended harness separates the following categories:

- submitted and valid samples;
- attack success under 4HDP;
- original-task completion under the strict all-required-tools criterion;
- security blocks;
- audit-failure blocks and audit-engine errors;
- framework errors;
- per-call audit latency and token accounting;
- victim model, audit model, attack condition, thresholds, and ablation mode.

The per-call audit event schema additionally records the tool name, current
step, request-local allowed tool names, payload hash/preview, static and semantic
risk scores, cumulative risk before/after, decision source, violation type, and
latency. Full event files are generated locally and are not distributed.

Relevant source files:

- `experiments/benchmarks/ASB/main_attacker_with_shield.py`
- `experiments/benchmarks/ASB/main_attacker_baseline_timing.py`
- `experiments/benchmarks/ASB/validate_formal_run_outputs.py`
