# Security policy

## Reporting

Open a private security advisory on the GitHub repository, or email the
maintainer (see `Cargo.toml` authors). Do not file public issues for
filter-bypass findings — e.g. a boundary/encoding trick that gets a
blocked pattern through the stream.

## Scope

In scope:

- Patterns that escape the automaton (matching bugs, wrong ranges).
- Boundary evasion — a match spanning `accumulated`/`chunk` slipping
  through `push`.
- Structural-form misses for ≥8-char patterns.
- `Blocked` streams that resume emitting.
- PII redaction that misses a covered pattern class.

Out of scope:

- Encoding channels (base64/hex) — literal matchers can't see encoded
  secrets; pre-decode upstream.
- Blocklist file integrity — the list is a trust boundary, protect it
  at the filesystem layer.
- Regex DoS in the PII layer — patterns are fixed and linear-time;
  pathological input is the caller's input-hygiene problem.

## Guidance

- Compile the firewall once per pattern-set change, not per request —
  the automaton is built for reuse.
- Treat the blocked marker as terminal: don't concatenate additional
  model output after `Blocked`.
- Keep secrets out of the blocklist itself where possible — patterns
  are stored plaintext.
