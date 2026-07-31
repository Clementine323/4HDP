# Failure and boundary cases

## Audit-backend failure

Missing credentials, malformed JSON, timeouts after configured retries, and
unexpected audit exceptions are handled fail-closed. The harness records them
as audit failures, not as ordinary security detections.

## Framework failure

Agent workflow parsing errors, invalid samples, and tool-execution exceptions
are tracked separately. A framework error is not evidence that 4HDP detected an
attack.

## Workflow parsing noise

The public PyOpenAGI parser accepts plain JSON, fenced JSON, and JSON embedded
in explanatory prose. It validates that each workflow step has `message` and
`tool_use`, and that `tool_use` is a list.

## Strict original-task completion

`required_tools_completed` returns true only when every ASB-labelled normal
tool's expected-achievement marker appears in the trajectory. Partial tool
completion, text-only recovery, or semantically correct output without all
markers can therefore be counted as unsuccessful. This metric is not a general
measure of answer usefulness.

## Security block versus benign false positive

A block in an attacked sample is an intended security decision. Benign
false-positive rate must be measured on the separate benign manifests; attack
block counts are not themselves a false-positive rate.

## Finite-sample boundary

The fixed protocol uses finite manifests, recorded seeds, and remote model APIs.
It supports inspection and reproduction of the stated protocol; it does not
constitute a proof of universal or absolute security.

Files under `examples/` are synthetic format illustrations and are not formal
experiment records.
