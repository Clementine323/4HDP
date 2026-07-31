# Reviewer #12 Adaptive / Knowledgeable Attack Suite

This suite evaluates 4HDP against intercepted pre-execution payloads designed to address reviewer comment #12. The payloads are not executed. They are passed to the same `HybridAuditor` path used by the ASB adapter.

Current checked-in files:

- `adaptive_samples.jsonl`: 152 pre-execution stress-test samples, including 118 malicious payloads and 34 benign controls.
- `knowledgeable_pairs.jsonl`: 24 malicious samples organized as 12 base-vs-adapted knowledgeable attack pairs. Use this file for the core reviewer-#12 paired experiment.

## Scope

Covered:

- interceptable Python and tool-call payloads;
- audit-LLM prompt-injection / JSON-coercion attempts;
- multi-language scripts such as Bash, PowerShell, Node.js, Perl, Ruby and cmd;
- native-binary invocation and executable staging patterns;
- container / host-boundary abuse attempts, including Docker socket and Kubernetes privileged manifest patterns;
- attempts to tamper with the 4HDP defense runtime after interception;
- hard-benign controls for FPR measurement.

Not claimed:

- actions that bypass the 4HDP interception layer entirely;
- a defense runtime already compromised before interception;
- actual execution-level containment against real container escapes or native malware.

## Smoke run without an API key

```bash
export FOURHDP_ADAPTIVE_MOCK=1
export FOURHDP_ADAPTIVE_ABLATIONS="full"
bash experiments/run_adaptive_experiments.sh
```

## Paper-style run

Core knowledgeable-pair experiment:

```bash
export OPENAI_API_KEY=YOUR_KEY
export OPENAI_BASE_URL=https://api.openai.com/v1
export FOURHDP_AUDIT_MODEL=gpt-4o-mini
export FOURHDP_ADAPTIVE_SAMPLES=experiments/adaptive_attacks/knowledgeable_pairs.jsonl
export FOURHDP_FAIL_ON_MISSING_KEY=1
export FOURHDP_ADAPTIVE_ABLATIONS="full"
export FOURHDP_RANDOM_SEED=2026
export FOURHDP_ADAPTIVE_REPEAT=3
export FOURHDP_BOOTSTRAP_CI=1000
export FOURHDP_RUN_ID=auto
bash experiments/run_adaptive_experiments.sh
```

Full stress-test suite:

```bash
unset FOURHDP_ADAPTIVE_SAMPLES
export FOURHDP_FAIL_ON_MISSING_KEY=1
export FOURHDP_ADAPTIVE_ABLATIONS="full no_semantic no_taint no_history ast_only llm_only"
export FOURHDP_RANDOM_SEED=2026
export FOURHDP_ADAPTIVE_REPEAT=1
export FOURHDP_BOOTSTRAP_CI=1000
export FOURHDP_RUN_ID=auto
bash experiments/run_adaptive_experiments.sh
```

## Outputs

- `adaptive_results.csv`: per-sample decision records.
- `adaptive_summary.csv`: ASR, security detection rate, fail-closed rate, FPR, audit failure rate, latency, grouped by overall / threat dimension / attack type / language / scenario / knowledge level / adaptation strategy / variant.
- `adaptive_pair_results.csv`: per-pair base-vs-adapted outcomes and `adaptation_success` indicators.
- `adaptive_metadata.json`: model/config snapshot, sample SHA-256, run id, seed, ablations and scope statement.
- `adaptive_sample_manifest.json`: selected sample counts by dimension, attack type, scenario and language.

The key reporting fields are:

- `ASR`: malicious samples allowed by the defense.
- `security_detection_rate`: malicious samples blocked by security evidence or semantic audit.
- `fail_closed_rate`: malicious samples blocked because the audit backend failed.
- `FPR_security`: benign samples blocked by security misjudgment, excluding backend failures.
- `audit_failure_rate`: all samples that fail closed because the audit backend failed.
- `adaptation_success`: in `adaptive_pair_results.csv`, true when the base attack is blocked but the adapted variant bypasses the defense.
