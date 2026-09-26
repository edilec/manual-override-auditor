# Manual Override Auditor

Offline, read-only validation of exported policy decisions and override events. The original decision is a separate record: an override refers to it and carries an `originalResult` copy, which must agree with that record. The audit assesses a supplied time, so its output is reproducible.

## Run

```sh
node bin/manual-override-auditor.mjs --root examples --input passing.json --as-of 2026-01-02T00:00:00Z
node bin/manual-override-auditor.mjs --root examples --input failing.json --as-of 2026-01-02T00:00:00Z --human
npm run check
```

`--root` names the evidence directory. `--input` is relative to it. `--as-of` is a required exact UTC timestamp. Optional `--out report.json` writes the same JSON report inside the root after destination checks. JSON always goes to stdout; `--human` adds a brief summary to stderr. `--help` lists options. A bad CLI option/configuration gives exit 2 with empty stdout. An unreadable, non-UTF-8, malformed or unsupported input gives an `incomplete` JSON report and exit 2.

## Input version 1

The top level has `schemaVersion: "1"`, `decisions`, and `overrides` arrays. A decision has a unique `id`, `result` (`allow` or `deny`), and `recordedAt`. An override has a unique `id`, `decisionId`, `originalResult`, `overrideResult`, `actor`, `reason`, `scope`, `occurredAt`, `expiresAt`, and `followUpEvidence`. Dates are exact UTC timestamps, for example `2026-01-02T00:00:00Z`. Actor, reason, scope, and evidence are nonempty references or descriptions in the source document; the report does not print them. An override result must differ from the original, occur after the decision, and have an expiry later than its event time. An expiry at or before `--as-of` fails. A future event or a missing/ambiguous original decision makes the report incomplete.

## Report and rules

The version 1 report has `schemaVersion`, `tool`, `status`, `summary`, and `findings`. Findings use the fixed logical role `@input`, not a filesystem path, and a JSON Pointer into the exact file named at invocation. This source ordinal provenance lets an operator locate evidence without publishing identifiers. Findings sort by `(file, pointer, ruleId)` in code-unit order.

| Rule | Severity | Meaning |
| --- | --- | --- |
| `input-unreadable`, `input-invalid` | error, incomplete | Export could not be read, decoded, parsed, or lacks version 1 shape |
| `byte-limit`, `record-limit`, `depth-limit`, `time-limit` | error, incomplete | Processing bound was exceeded |
| `decision-invalid`, `decision-duplicate`, `decision-unknown` | error, incomplete | Recorded decision is unusable, ambiguous, or absent |
| `override-in-future` | error, incomplete | Event had not happened at assessment time |
| `no-overrides`, `override-invalid`, `override-duplicate` | error, incomplete | No events, unusable event, or ambiguous event ID |
| `actor-missing`, `reason-missing`, `scope-missing`, `follow-up-missing` | error, fail | Required accountability field is empty |
| `original-result-mismatch`, `override-no-change`, `override-before-decision` | error, fail | Override contradicts the recorded decision or order |
| `expiry-invalid`, `override-expired` | error, fail | Invalid or expired time window |

Exit `0` means evaluated and passed; `1` means evaluated with policy errors; `2` means incomplete evidence, invalid CLI configuration, or output failure. Unknowns never pass.

Limits are 1,048,576 input bytes, 1,000 decisions and 1,000 overrides, JSON nesting depth 16, and 5,000 ms for read/processing. The limit itself is allowed; the next byte, record, level, or millisecond is not. Reports omit raw identifiers, reasons, actors, scope, evidence, and malformed JSON excerpts. Input realpaths and optional output destinations must remain inside the declared root; a report destination cannot alias the input through a hard or symbolic link.

## Scope

This validates evidence in a supplied export. It cannot confirm actor identity, verify a ticket exists, authorize the exception, or fetch a live policy decision. No telemetry or provider calls. MIT license; see [LICENSE](./LICENSE).
