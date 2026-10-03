# macuahuitl specification

Streaming output firewall with pattern kill, structural-form evasion
check, and in-place PII redaction.

## Components

- **`Automaton`** — Aho-Corasick over bytes: trie + BFS failure links,
  case-insensitive, leftmost non-overlapping matches in one linear
  scan. Time is O(text + matches), independent of pattern count.
- **`Firewall`** — pattern set + compiled automaton + structural forms.
  `check` is whole-text; `stream` is mid-generation.
- **`Stream`** — accumulates emitted text; every `push` scans
  `accumulated + chunk`.

## Matching semantics

- Case-insensitive; matches are reported on the original text's byte
  ranges (UTF-8-boundary safe).
- Matches are leftmost and non-overlapping — a match starting inside a
  prior match's range is skipped.
- **Structural form:** `lowercase(alnum-only)` of both pattern and
  text. Any pattern whose structural form is ≥8 chars blocks when its
  form appears anywhere in the structural text — formatting tricks
  (dashes, spaces, punctuation between characters) can't evade.
- **Structural hit = whole-text block**, matching upstream semantics;
  automaton hits = marker substitution (`check`) or stream kill.

## Streaming semantics

`push(chunk)` scans `accumulated + chunk` — a pattern straddling the
emission boundary is caught. `Blocked` latches: once killed, the stream
returns `Blocked` for every subsequent push and `accumulated` stops
growing.

## PII patterns

Email, SSN (`NNN-NN-NNNN`), US phone, `sk-…`/`AIza…` API keys,
`Bearer …` — replaced in place with `[REDACTED_*]`. Redaction never
blocks the text.

## Non-goals

- It filters *output*, not intent — pair with `tokala` (deliberation)
  upstream.
- The automaton matches literal strings, not regex, not semantics —
  paraphrased secrets aren't a blocklist's job.
