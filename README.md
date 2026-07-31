# 4HDP reproducibility release

This repository contains the 4HDP implementation and fixed-input materials for
an intent-aware, state-tracking runtime defence for code-execution agents.

## Public scope

Included: 4HDP source code, the ASB/AIOS evaluation harness, the oracle-free ASB
adapter, the complete semantic-audit prompt template, threshold profiles,
frozen case and retrieval manifests, experiment entry points, validators,
tests, and synthetic format examples.

Excluded: experimental results, full execution/audit logs, raw traces, local
Chroma databases, API credentials, manuscript drafts, reviewer correspondence,
failed runs, and recovery archives.

## Documentation

- `docs/ASB_ADAPTER.md`
- `docs/AUDIT_PROMPT.md`
- `docs/THRESHOLDS_AND_DECISIONS.md`
- `docs/SAMPLE_COMPOSITION.md`
- `docs/EXPERIMENT_PROTOCOL.md`
- `docs/FAILURE_AND_BOUNDARY_CASES.md`
- `docs/OUTPUT_SCHEMA.md`
- `docs/KNOWN_LIMITATIONS.md`

## Install and validate

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements-repro.txt
cp .env.example .env
python scripts/verify_public_package.py
bash scripts/check_release_safety.sh
```

Provide credentials only in the local `.env` file.

## Main MP/MIXED entry point

```bash
cd experiments/benchmarks/ASB
bash build_r9_poisoned_memory.sh
bash run_missing_mp_mixed_campaign.sh smoke
bash run_missing_mp_mixed_campaign.sh formal
```

Formal execution uses paid remote APIs. Read `docs/EXPERIMENT_PROTOCOL.md`
before running.

## Third-party code

The ASB/AIOS snapshot is under `experiments/benchmarks/ASB/`. Its upstream MIT
licence and attribution are preserved. See `THIRD_PARTY_NOTICES.md`.

## Claim boundary

This package supports inspection and reproduction of a stated finite-sample
protocol. It does not claim a proof of universal or absolute security.

## Licence status

The upstream ASB/AIOS material retains its MIT licence. The original 4HDP
implementation is publicly available for research review and reproducibility.
No top-level open-source licence is currently granted for the original 4HDP
implementation; see `USAGE_NOTICE.md`.

## Data and privacy notice

The provenance and privacy scope of the retained benchmark fixtures are
documented in `DATA_NOTICE.md`.
