# Reproducibility index

1. Core implementation: `fourhdp/`
2. ASB evaluation harness: `experiments/benchmarks/ASB/`
3. Exact semantic prompt: `prompts/semantic_audit_prompt_template.txt`
4. Threshold profiles: `configs/*.env` and `docs/THRESHOLDS_AND_DECISIONS.md`
5. Adapter specification: `docs/ASB_ADAPTER.md`
6. Frozen input composition: `docs/SAMPLE_COMPOSITION.md`
7. Experiment commands: `docs/EXPERIMENT_PROTOCOL.md`
8. Failure and metric boundaries: `docs/FAILURE_AND_BOUNDARY_CASES.md`
9. File integrity: `SOURCE_CHECKSUMS.sha256`
10. Selected revision results: `reproducibility/revision_evidence/`
11. Result verification: `python scripts/verify_revision_evidence.py`

Full raw logs and unselected runs remain excluded. The revision evidence
contains only de-identified minimal outcomes and summaries needed to verify
the manuscript's selected results without rerunning remote models.
