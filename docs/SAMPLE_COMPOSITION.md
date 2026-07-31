# Sample composition

This document is generated from frozen input manifests. It contains no model outputs or experimental outcomes.

## Frozen case manifests

| Condition | Cases | Unique task texts | Unique tool/index IDs | Aggressive | Non-aggressive |
|---|---:|---:|---:|---:|---:|
| DPI | 100 | 15 | 100 | 48 | 52 |
| IPI | 100 | 15 | 100 | 48 | 52 |
| MP | 100 | 15 | 100 | 48 | 52 |
| MIXED | 100 | 15 | 100 | 48 | 52 |
| PoT | 100 | 6 | 100 | 48 | 52 |
| Benign | 100 | 15 | 100 | 0 | 100 |

All six frozen case sets are balanced across the three evaluated high-consequence roles:

- `financial_analyst_agent`: 34 cases
- `legal_consultant_agent`: 33 cases
- `medical_advisor_agent`: 33 cases

DPI, IPI, MP, and MIXED use the same ordered 100 case IDs. The attack condition is changed by the runner configuration, which preserves case pairing across conditions.

The PoT manifest uses the first two dedicated PoT task templates for each role. The benign revision manifest contains 100 non-aggressive index records.

## Frozen memory-retrieval inputs

### MP

- Retrieval records: 100
- Schema: `asb-memory-retrieval-v1`
- Retrieval semantics: `ASB live top-1, frozen once without pair-hit filtering`
- Embedding model: `text-embedding-ada-002`
- Database content SHA-256: `e97977a03a6e2990aa58e744582c5d24025e88662c3f77335ad4ea1fbc43d935`
- Case-manifest SHA-256: `bc4e803c5f10c86a331519f3599bf82d4c784ca97cb4e54e72f38b2167107370`

### MIXED

- Retrieval records: 100
- Schema: `asb-memory-retrieval-v1`
- Retrieval semantics: `ASB live top-1, frozen once without pair-hit filtering`
- Embedding model: `text-embedding-ada-002`
- Database content SHA-256: `e97977a03a6e2990aa58e744582c5d24025e88662c3f77335ad4ea1fbc43d935`
- Case-manifest SHA-256: `bc4e803c5f10c86a331519f3599bf82d4c784ca97cb4e54e72f38b2167107370`

## Provenance note

Some manifest metadata records the model used when an input asset was generated. Runtime victim and auditor assignments are controlled by the campaign scripts; generation metadata must not be interpreted as the runtime model assignment.
