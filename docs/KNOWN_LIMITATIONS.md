# Known limitations

- The formal protocol uses finite frozen samples and recorded seeds; it is not a
  theoretical security proof.
- The formal MP/MIXED campaign records one formal run per cell rather than a
  multi-seed confidence interval.
- Remote model APIs can change over time and may be nondeterministic.
- The original-task metric is marker-based and can undercount partial or
  text-only recovery.
- The poisoned-memory database is regenerated locally rather than distributed;
  its expected content and metadata hashes are recorded by the public protocol.
- Thresholds and prompts were evaluated in the stated ASB/AIOS setting and may
  require recalibration for other agent frameworks or tool surfaces.
