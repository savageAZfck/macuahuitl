# macuahuitl

A streaming output firewall. Named for the Aztec war club edged with obsidian — the strike that lands **mid-flow**.

Ported from Bad Apple's `StreamingFirewall`, generalized for any text stream: local model output, agent tool results, log pipelines.

## The problem it solves

Post-hoc filters check the response *after* it exists. A blocked pattern that spans two emitted chunks — `forbidden ` + `fruit` — is already halfway out the door. macuahuitl scans `accumulated + chunk` on every push, so a pattern is killed **as it forms**, not after it lands. Once blocked, the stream stays dead.

## Three layers

- **Aho-Corasick automaton** — trie + BFS failure links, case-insensitive, leftmost non-overlapping matches in a single linear scan. O(text), not O(text × patterns).
- **Structural-form check** — every pattern ≥8 alnum chars is also matched against the alphanumeric-only form of the text. `BEGIN---PRIVATE---KEY` and `B-E-G-I-N` can't slip past as "different strings."
- **PII redaction** — emails, SSNs, phones, API keys, bearer tokens replaced in place (`[REDACTED_*]`) rather than blocking the response.

## Usage

```rust
use macuahuitl::{Firewall, Verdict};

let fw = Firewall::with_blocklist(&std::fs::read_to_string("blocklist.txt")?);
let mut stream = fw.stream();

for chunk in model_output_chunks {
    match stream.push(&chunk) {
        Verdict::Emit(text) => print!("{text}"),
        Verdict::Blocked => { eprintln!("\n[Output firewall: blocked]"); break; }
    }
}
```

One-shot: `fw.check(text)` replaces matches with the marker; `fw.check_and_redact` adds PII redaction. Built-in defaults always block key material (`sk-`, `ssh-rsa`, `-----BEGIN`).

## License

MIT
