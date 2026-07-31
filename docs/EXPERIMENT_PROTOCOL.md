# Experiment protocol

This repository distributes implementation and fixed inputs, not experimental
outputs.

## Environment

- Python: `3.11` (see `.python-version`).
- Install with `pip install -r requirements-repro.txt`.
- API credentials are supplied locally through `.env` and are never committed.
- Remote model execution may incur cost and may remain nondeterministic even
  when temperature is set to zero.

## MP/MIXED paired campaign

- Victim models: `gpt-4o-mini`, `gpt-4o`, and `llama-3.1-70b-instruct`.
- Semantic auditor: `gpt-4o`.
- Attack conditions: MP and MIXED.
- Defence conditions: no defence and full 4HDP.
- Frozen cases per model–attack–defence cell: 100.
- Random seed: 0.
- Formal repetitions: one formal campaign per cell.
- Entry point: `experiments/benchmarks/ASB/run_missing_mp_mixed_campaign.sh`.

The poisoned-memory database is intentionally not distributed. Rebuild it with
`build_r9_poisoned_memory.sh` before the MP/MIXED runner. The runner then uses
the public frozen retrieval manifests to hold retrieval evidence constant.

## DPI/IPI/PoT/benign matched campaign

`run_revision_6_9_13.sh` uses frozen manifests for no-defence, full 4HDP, and
matched prompt-layer baselines. Formal mode is selected by setting
`REVISION_MAX_CASES=100`; the auditor is fixed to `gpt-4o`.

## Expanded benign and ablation evaluation

- `run_rq11_benign_expanded.sh` is the expanded benign entry point.
- `run_ablation_experiments.sh` runs the component ablations.
- `experiments/run_adaptive_audit.py` evaluates the fixed adaptive/knowledgeable
  payload suite without executing the payloads.

## Recommended sequence

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-repro.txt
cp .env.example .env
python scripts/verify_public_package.py
cd experiments/benchmarks/ASB
bash build_r9_poisoned_memory.sh
bash run_missing_mp_mixed_campaign.sh smoke
bash run_missing_mp_mixed_campaign.sh formal
```

Result CSV/JSON files, full logs, raw audit traces, and local databases are
generated locally and are excluded from this release.
