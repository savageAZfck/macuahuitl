//! macuahuitl — a streaming output firewall.
//!
//! Named for the Aztec war club edged with obsidian — the strike that
//! lands mid-flow. This crate kills a pattern *as it forms* in a token
//! stream, not after the response is complete: an Aho-Corasick
//! automaton scans `accumulated + chunk` on every push so a blocked
//! pattern can never straddle the emission boundary and slip out half
//! at a time.
//!
//! Ported from Bad Apple's `StreamingFirewall`: blocklist + structural-
//! form evasion check + in-place PII redaction.

use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

// ──────────────────────── aho-corasick automaton ────────────────────

/// Aho-Corasick automaton over bytes, case-insensitive.
/// Trie + BFS failure links; reports leftmost non-overlapping matches
/// in a single linear scan.
struct Automaton {
    next: Vec<HashMap<u8, usize>>,
    fail: Vec<usize>,
    output: Vec<Vec<usize>>,
    pattern_lens: Vec<usize>,
}

impl Automaton {
    fn build(patterns: &[String]) -> Self {
        let mut a = Self {
            next: vec![HashMap::new()],
            fail: vec![0],
            output: vec![Vec::new()],
            pattern_lens: patterns.iter().map(|p| p.len()).collect(),
        };
        for (i, p) in patterns.iter().enumerate() {
            let mut cur = 0;
            for &b in p.as_bytes() {
                let nxt = match a.next[cur].get(&b) {
                    Some(&n) => n,
                    None => {
                        let n = a.next.len();
                        a.next.push(HashMap::new());
                        a.fail.push(0);
                        a.output.push(Vec::new());
                        a.next[cur].insert(b, n);
                        n
                    }
                };
                cur = nxt;
            }
            a.output[cur].push(i);
        }
        // BFS failure links.
        let mut queue: Vec<usize> = a.next[0].values().copied().collect();
        for &c in &queue {
            a.fail[c] = 0;
        }
        let mut qi = 0;
        while qi < queue.len() {
            let cur = queue[qi];
            qi += 1;
            let children: Vec<(u8, usize)> =
                a.next[cur].iter().map(|(&c, &n)| (c, n)).collect();
            for (ch, child) in children {
                let mut f = a.fail[cur];
                while f != 0 && !a.next[f].contains_key(&ch) {
                    f = a.fail[f];
                }
                a.fail[child] = match a.next[f].get(&ch) {
                    Some(&n) if n != child => n,
                    _ => 0,
                };
                let inherited = a.output[a.fail[child]].clone();
                a.output[child].extend(inherited);
                queue.push(child);
            }
        }
        a
    }

    /// Byte ranges of all leftmost non-overlapping matches.
    fn search(&self, text_lower: &[u8]) -> Vec<(usize, usize)> {
        let mut matches = Vec::new();
        let mut last_end: Option<usize> = None;
        let mut cur = 0;
        for (i, &b) in text_lower.iter().enumerate() {
            while cur != 0 && !self.next[cur].contains_key(&b) {
                cur = self.fail[cur];
            }
            if let Some(&n) = self.next[cur].get(&b) {
                cur = n;
            }
            for &pi in &self.output[cur] {
                let len = self.pattern_lens[pi];
                let end = i + 1;
                let Some(start) = end.checked_sub(len) else { continue };
                if let Some(last) = last_end {
                    if start < last {
                        continue;
                    }
                }
                matches.push((start, end));
                last_end = Some(end);
            }
        }
        matches
    }
}

// ─────────────────────────── firewall ───────────────────────────────

/// What the stream produced for one chunk.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Emit this text.
    Emit(String),
    /// The strike landed — emit the blocked marker, kill the stream.
    Blocked,
}

/// Built-in defaults — key-material sentinels that are always blocked,
/// merged with the operator's blocklist.
pub const DEFAULT_PATTERNS: &[&str] = &[
    "sk-",
    "ssh-rsa",
    "-----BEGIN",
    "-----END",
    "BEGIN PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
];

/// The marker emitted when the strike lands.
pub const BLOCKED_MARKER: &str = "[Output firewall: blocked]";

/// The war club. Holds the pattern set; `check` for whole text,
/// `stream()` for mid-generation kills.
pub struct Firewall {
    patterns: Vec<String>,
    automaton: Automaton,
    /// Structural forms of patterns ≥8 alnum chars — catches keys
    /// reformatted with separators.
    structural: Vec<String>,
    pub marker: String,
}

impl Firewall {
    /// A firewall over `patterns` — caller merges any defaults wanted.
    /// Patterns are matched case-insensitively.
    pub fn new(patterns: Vec<String>) -> Self {
        let lowered: Vec<String> = patterns.iter().map(|p| p.to_lowercase()).collect();
        let automaton = Automaton::build(&lowered);
        let structural = lowered
            .iter()
            .map(|p| structural_form(p))
            .filter(|s| s.len() >= 8)
            .collect();
        Self {
            patterns: lowered,
            automaton,
            structural,
            marker: BLOCKED_MARKER.to_string(),
        }
    }

    /// Defaults merged with a blocklist file (one pattern per line,
    /// `#` comments and blank lines ignored).
    pub fn with_blocklist(blocklist_text: &str) -> Self {
        let mut patterns: Vec<String> =
            DEFAULT_PATTERNS.iter().map(|s| s.to_string()).collect();
        patterns.extend(parse_blocklist(blocklist_text));
        Self::new(patterns)
    }

    /// Active patterns (lowercased).
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    /// One-shot scan: replace every blocked occurrence with the marker.
    pub fn check(&self, text: &str) -> String {
        // Structural-form check for long patterns — a match anywhere
        // blocks the whole text, matching the upstream semantics.
        let st = structural_form(text);
        if self.structural.iter().any(|p| st.contains(p)) {
            return self.marker.clone();
        }
        let lower = text.to_lowercase();
        let matches = self.automaton.search(lower.as_bytes());
        let mut out = String::with_capacity(text.len());
        let mut pos = 0;
        for (s, e) in matches {
            if s < pos {
                continue;
            }
            // Only splice on UTF-8 boundaries.
            if !text.is_char_boundary(s) || !text.is_char_boundary(e) {
                continue;
            }
            out.push_str(&text[pos..s]);
            out.push_str(&self.marker);
            pos = e;
        }
        out.push_str(&text[pos..]);
        out
    }

    /// One-shot with PII redaction on top.
    pub fn check_and_redact(&self, text: &str) -> String {
        redact_pii(&self.check(text))
    }

    /// Start a stream — chunks are pushed through [`Stream::push`].
    pub fn stream(&self) -> Stream<'_> {
        Stream {
            fw: self,
            accumulated: String::new(),
            blocked: false,
        }
    }
}

/// A guarded token stream. Push each emitted chunk; the firewall scans
/// `accumulated + chunk` so a pattern spanning the boundary is caught
/// as it forms. Once blocked, the stream stays dead.
pub struct Stream<'f> {
    fw: &'f Firewall,
    accumulated: String,
    blocked: bool,
}

impl Stream<'_> {
    pub fn push(&mut self, chunk: &str) -> Verdict {
        if self.blocked {
            return Verdict::Blocked;
        }
        let combined = format!("{}{chunk}", self.accumulated);

        // Structural-form evasion check.
        let st = structural_form(&combined);
        if self.fw.structural.iter().any(|p| st.contains(p)) {
            self.blocked = true;
            return Verdict::Blocked;
        }
        let lower = combined.to_lowercase();
        if !self.fw.automaton.search(lower.as_bytes()).is_empty() {
            self.blocked = true;
            return Verdict::Blocked;
        }
        self.accumulated = combined;
        Verdict::Emit(chunk.to_string())
    }

    /// Whether the stream has been killed.
    pub fn is_blocked(&self) -> bool {
        self.blocked
    }

    /// Everything emitted so far.
    pub fn accumulated(&self) -> &str {
        &self.accumulated
    }
}

/// Parse a blocklist: one pattern per line, `#` comments and blank
/// lines ignored.
pub fn parse_blocklist(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

/// Alphanumeric-only lowercase form — the shape a key takes with all
/// formatting separators stripped.
fn structural_form(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

// ─────────────────────────── PII redaction ──────────────────────────

fn pii_patterns() -> &'static [(Regex, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            (
                Regex::new(r"(?i)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(),
                "[REDACTED_EMAIL]",
            ),
            (
                Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
                "[REDACTED_SSN]",
            ),
            (
                Regex::new(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap(),
                "[REDACTED_PHONE]",
            ),
            (
                Regex::new(r"\b(sk-[a-zA-Z0-9_\-]{20,}|AIza[0-9A-Za-z_\-]{35,})").unwrap(),
                "[REDACTED_KEY]",
            ),
            (
                Regex::new(r"(?i)bearer\s+[A-Za-z0-9_\-\.=]+").unwrap(),
                "[REDACTED_BEARER]",
            ),
        ]
    })
}

/// In-place PII redaction — emails, SSNs, phones, API keys, bearer
/// tokens — replaced rather than blocking the whole response.
pub fn redact_pii(text: &str) -> String {
    let mut out = text.to_string();
    for (re, rep) in pii_patterns() {
        out = re.replace_all(&out, *rep).into_owned();
    }
    out
}
