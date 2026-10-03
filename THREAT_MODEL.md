# Threat model

macuahuitl guards the last mile: text a model or process emits before
it reaches a user, file, or wire. It assumes the generator can produce
harmful or secret-bearing content and the filter cannot ask it to be
nice first.

## What it defends against

- **Boundary-split leaks.** A secret emitted across chunks
  (`sk-abc` + `def…`) is caught — the scan always covers
  `accumulated + chunk`.
- **Formatting evasion.** Separator tricks (`B-E-G-I-N`, spaced-out
  keys, mixed case) are flattened by the structural form and still
  blocked.
- **Case evasion.** Matching is case-insensitive throughout.
- **PII egress.** Emails, SSNs, phones, keys, bearer tokens are
  redacted in place even when the response itself is allowed.
- **Post-block dribble.** Once a stream is killed it stays killed —
  subsequent chunks emit `Blocked`, not more text.

## What it does not defend against

- **Encoding evasion.** Base64/hex/rot13-encoded secrets don't match
  literal patterns — decode before filtering if the channel permits
  arbitrary encodings.
- **Semantic secrets.** Paraphrased or partially reordered sensitive
  content isn't a string pattern.
- **Pattern-list compromise.** Whoever edits the blocklist sets what's
  blocked — treat it as a protected surface (`akicita`-style bounds).
- **Denial of service by pattern count?** No — matching time is
  independent of pattern count; but construction cost grows with the
  list. Compile once, scan many.

## Design posture

Kill mid-flow, latch the kill, and never let formatting be the
difference between a secret and a string.
