use macuahuitl::{Firewall, Verdict};

fn main() {
    let fw = Firewall::with_blocklist("forbidden fruit\nnuclear codes\n");

    // A model streaming tokens — the secret forms across the boundary.
    let chunks = [
        "The user asks for ",
        "the forbidden ",
        "fruit recipe: first ",
        "take the sec",
        "ret ingredient…",
    ];

    let mut stream = fw.stream();
    for chunk in chunks {
        match stream.push(chunk) {
            Verdict::Emit(text) => print!("{text}"),
            Verdict::Blocked => {
                println!("\n>>> strike landed mid-flow — stream killed");
                break;
            }
        }
    }
    println!("blocked: {}", stream.is_blocked());
    println!("escaped before the strike: {:?}", stream.accumulated());

    // One-shot redaction for PII.
    println!("{}", fw.check_and_redact("email me at alice@example.com"));
}
