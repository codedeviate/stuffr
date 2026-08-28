//! The `stf` command. Phase 0 ships only `formats` and `--version`; Phase 1
//! adds the real verbs.

use std::process::ExitCode;

fn main() -> ExitCode {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        None | Some("--version" | "-V") => {
            println!("stf {}", stuffr::VERSION);
            ExitCode::SUCCESS
        }
        Some("formats") => {
            print_formats();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("stf: unknown command `{other}`");
            eprintln!("Phase 0 supports: formats, --version");
            ExitCode::from(2)
        }
    }
}

fn print_formats() {
    let rows = stuffr::registry().matrix();
    if rows.is_empty() {
        println!("This build contains 0 formats.");
        println!("(Phase 0 validates the core against mock formats; Phase 1 adds real ones.)");
        return;
    }
    println!(
        "{:<16} {:<10} {:<5} {:<5} {:<8} EXTENSIONS",
        "FORMAT", "KIND", "READ", "WRITE", "PARALLEL"
    );
    for r in rows {
        println!(
            "{:<16} {:<10} {:<5} {:<5} {:<8} {}",
            r.id.as_str(),
            match r.kind {
                stuffr::FormatKind::Codec => "codec",
                stuffr::FormatKind::Container => "container",
            },
            if r.read { "yes" } else { "-" },
            if r.write { "yes" } else { "-" },
            if r.parallel { "yes" } else { "-" },
            r.extensions.join(", "),
        );
    }
}
