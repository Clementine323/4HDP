# Known limitations

- The formal protocol uses finite frozen samples and recorded seeds; it is not a
  theoretical security proof.
- The selected no-defence MP/MIXED comparison cells have one formal 100-case
  run each. The defended Table 2 stability analysis reports three full
  same-protocol rounds, but these do not provide a multi-seed confidence
  interval or a verified remote-model weight snapshot. The state-tracking
  paired comparison has only one round.
- Remote model APIs can change over time and may be nondeterministic.
- The original-task metric is marker-based and can undercount partial or
  text-only recovery.
- The poisoned-memory database is regenerated locally rather than distributed;
  its expected content and metadata hashes are recorded by the public protocol.
- Thresholds and prompts were evaluated in the stated ASB/AIOS setting and may
  require recalibration for other agent frameworks or tool surfaces.
