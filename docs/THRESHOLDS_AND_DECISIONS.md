# Thresholds and decision rules

The implementation is in `fourhdp/core/auditor/engine.py`; recent-step state is
maintained by `fourhdp/core/memory/trace.py`.

## Core rules

- Single-step threshold: `0.7`.
- Cumulative threshold: `0.9`.
- Capability-provenance floor: `0.85` when a request-local tool-surface violation is detected.
- A single step is blocked when adjusted risk is **greater than** `0.7`.
- A history-aware sequence is blocked when cumulative risk is **greater than or equal to** `0.9`.
- Cumulative risk uses the five most recent events. Per-agent history is capped at 50 events.
- Audit-backend errors return risk `1.0` and fail closed.

The adjusted score combines semantic risk, static findings, a taint boost, and,
when applicable, the capability-provenance floor.

## Formal protocol overrides

The engine has general defaults, but the formal runners explicitly freeze the
following settings.

### MP/MIXED campaign

- safe fast path: disabled;
- static hard block: disabled;
- cumulative risk floor: `0.0`;
- request-local tool surface: enforced;
- memory capability-integrity guard: enabled;
- single/cumulative thresholds: `0.7` / `0.9`.

See `configs/formal_mp_mixed.env` and
`experiments/benchmarks/ASB/run_missing_mp_mixed_campaign.sh`.

### DPI/IPI/PoT/benign matched campaign

- safe fast path: disabled;
- static hard block: disabled;
- cumulative risk floor: `0.3`;
- request-local tool surface: not enforced;
- memory capability-integrity guard: disabled;
- single/cumulative thresholds: `0.7` / `0.9`.

See `configs/formal_dpi_ipi_pot_benign.env` and
`experiments/benchmarks/ASB/run_revision_6_9_13.sh`.

### Expanded benign campaign

The RQ11 runner enables the safe fast path and static hard block, evaluates all
ASB roles, and retains thresholds `0.7` / `0.9`. See
`configs/rq11_benign.env`.

## Ablations

Supported modes are `full`, `no_static`, `no_semantic`, `no_history`,
`no_taint`, `static_only`, and `semantic_only`. Legacy aliases are accepted for
compatibility.
