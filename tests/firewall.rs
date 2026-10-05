use macuahuitl::{parse_blocklist, redact_pii, Firewall, Verdict, BLOCKED_MARKER};

fn fw() -> Firewall {
    Firewall::new(vec![
        "forbidden fruit".to_string(),
        "secret token".to_string(),
    ])
}

#[test]
fn one_shot_replaces_matches() {
    let out = fw().check("eat the forbidden fruit today");
    assert!(out.contains(BLOCKED_MARKER));
    assert!(!out.contains("forbidden fruit"));
}

#[test]
fn case_insensitive_matching() {
    assert!(fw().check("FORBIDDEN FRUIT").contains(BLOCKED_MARKER));
}

#[test]
fn stream_kills_pattern_spanning_chunk_boundary() {
    // The pattern forms across two chunks — caught as it forms.
    let f = fw();
    let mut s = f.stream();
    assert!(matches!(
        s.push("here comes the forbidden "),
        Verdict::Emit(_)
    ));
    assert_eq!(s.push("fruit salad"), Verdict::Blocked);
    assert!(s.is_blocked());
    // Once dead, stays dead.
    assert_eq!(s.push("more text"), Verdict::Blocked);
}

#[test]
fn clean_stream_passes_through() {
    let f = fw();
    let mut s = f.stream();
    assert_eq!(s.push("hello "), Verdict::Emit("hello ".to_string()));
    assert_eq!(s.push("world"), Verdict::Emit("world".to_string()));
    assert!(!s.is_blocked());
    assert_eq!(s.accumulated(), "hello world");
}

#[test]
fn structural_form_catches_reformatted_keys() {
    // "BEGIN PRIVATE KEY" written with dashes — structural form matches.
    let f = Firewall::with_blocklist("");
    assert!(
        f.check("here: B-E-G-I-N-P-R-I-V-A-T-E-K-E-Y")
            .contains(BLOCKED_MARKER)
            || f.check("BEGIN---PRIVATE---KEY").contains(BLOCKED_MARKER)
    );
    assert!(f.check("BEGIN PRIVATE KEY").contains(BLOCKED_MARKER));
}

#[test]
fn defaults_block_key_material() {
    let f = Firewall::with_blocklist("");
    assert!(f.check("ssh-rsa AAAAB3...").contains(BLOCKED_MARKER));
    assert!(f
        .check("-----BEGIN RSA PRIVATE KEY-----")
        .contains(BLOCKED_MARKER));
}

#[test]
fn blocklist_parsing() {
    let list = parse_blocklist("# comment\n\nalpha\n  beta  \n# another\ngamma\n");
    assert_eq!(list, vec!["alpha", "beta", "gamma"]);
}

#[test]
fn pii_redaction() {
    let out = redact_pii("mail me at alice@example.com or 555-123-4567");
    assert!(out.contains("[REDACTED_EMAIL]"));
    assert!(out.contains("[REDACTED_PHONE]"));
    let out = redact_pii("use key sk-abcdefghijklmnopqrstuvwxyz123456");
    assert!(out.contains("[REDACTED_KEY]"));
}

#[test]
fn redact_after_check() {
    let f = Firewall::with_blocklist("");
    let out = f.check_and_redact("contact bob@test.com please");
    assert!(out.contains("[REDACTED_EMAIL]"));
}
