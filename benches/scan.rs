use macuahuitl::Firewall;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    // 500-pattern blocklist over a 1 MiB stream.
    let patterns: Vec<String> = (0..500)
        .map(|i| format!("forbidden-pattern-{i:04}"))
        .collect();
    let fw = Firewall::new(patterns);
    let text = "lorem ipsum dolor sit amet consectetur adipiscing elit ".repeat(20_000);
    let t = Instant::now();
    black_box(fw.check(black_box(&text)));
    println!(
        "check {:.1} MiB vs 500 patterns: {:?}",
        text.len() as f64 / 1_048_576.0,
        t.elapsed()
    );

    // Streaming throughput.
    let mut s = fw.stream();
    let t = Instant::now();
    for chunk in text.as_bytes().chunks(64) {
        s.push(std::str::from_utf8(chunk).unwrap());
    }
    println!("streamed {:.1} MiB in 64B chunks: {:?}", text.len() as f64 / 1_048_576.0, t.elapsed());
}
