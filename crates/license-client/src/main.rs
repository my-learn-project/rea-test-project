#![forbid(unsafe_code)]

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 1 || args[0] != "--stdio" {
        eprintln!("Usage: license-client --stdio");
        std::process::exit(2);
    }
    if let Err(e) = license_client::run_stdio() {
        eprintln!("license-client I/O error: {e}");
        std::process::exit(1);
    }
}
