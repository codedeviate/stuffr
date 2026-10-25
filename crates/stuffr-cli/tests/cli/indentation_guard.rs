use crate::common::*;

// ---------------------------------------------------------------------------
// The collapsed-indentation guard, enumerated structurally.
// ---------------------------------------------------------------------------

/// Phase 2's final review found three multi-line literals in `main.rs`
/// collapsed with their continuation indentation left in, so users saw runs of
/// 22-30 spaces mid-sentence:
///
/// ```text
/// stuffr: usage error: packing 2 paths needs an output naming a container
/// (`-o bundle.tar`,                      or --format tar); a codec …
/// ```
///
/// The guard written then enumerated three hardcoded invocations, and in Phase
/// 2c it failed to catch the identical defect recurring, because the new
/// message was not one of its three. This is the same guard enumerated from
/// something a future task cannot escape: every string literal in every
/// source file of every crate, discovered by walking the tree, whether or not
/// any test ever reaches the code that prints it.
///
/// The mechanism is the one that produced the defect twice: a heredoc (or any
/// other editor) eating the `\` that ends a continued line leaves the next
/// line's indentation INSIDE the literal, and `cargo fmt` then folds the whole
/// thing onto one line. Neither the compiler nor the gate sees anything wrong;
/// only running the binary does.
#[test]
fn no_message_literal_in_the_workspace_carries_a_run_of_collapsed_indentation() {
    // The scanner is tested before it is trusted. Without this, a scanner that
    // silently found no literals at all would report the whole workspace
    // clean — the exact shape of defect this test exists to catch.
    let defective = "fn f() { err(\"packing paths needs a container (`-o bundle.tar`,                      or --format tar)\"); }";
    let found = rust_string_literals(defective);
    assert_eq!(
        found.len(),
        1,
        "the scanner must find the literal: {found:?}"
    );
    assert!(
        first_space_run(&found[0].1).is_some_and(|at| !is_column_label(&found[0].1[..at])),
        "the scanner must flag the historical defect: {:?}",
        found[0].1
    );

    let continued = "fn f() { err(\"packing paths needs a container \\\n                     (`-o bundle.tar`, or --format tar)\"); }";
    let found = rust_string_literals(continued);
    assert_eq!(found.len(), 1);
    assert_eq!(
        found[0].1, "packing paths needs a container (`-o bundle.tar`, or --format tar)",
        "a `\\`-continued literal carries no indentation, and the scanner must apply that \
         rule rather than report the source text"
    );
    assert!(first_space_run(&found[0].1).is_none());

    let aligned = "fn f() { println!(\"format:   {}\", x); }";
    let found = rust_string_literals(aligned);
    let at = first_space_run(&found[0].1).expect("the column really is three spaces");
    assert!(
        is_column_label(&found[0].1[..at]),
        "a deliberate column label must not be reported as a collapse"
    );

    // The exemption must not widen back into prose. A whole clause ending in a
    // colon is the historical defect verbatim — messages here routinely end a
    // clause with a colon before a list — and an exemption that allowed spaces
    // in the label let exactly this through.
    let colon_prose = "fn f() { err(\"stuffr cannot do this:                    try force\"); }";
    let found = rust_string_literals(colon_prose);
    assert_eq!(found.len(), 1);
    let at = first_space_run(&found[0].1).expect("the run is there");
    assert!(
        !is_column_label(&found[0].1[..at]),
        "a prose clause ending in a colon is not a column label: {:?}",
        found[0].1
    );

    // The two shapes either side of the one-word rule, so its boundary is
    // pinned rather than incidental.
    assert!(is_column_label("MemAvailable:"));
    assert!(!is_column_label("two words:"));

    let quoted_char = "fn f() { let q = '\"'; err(\"a   collapse\"); }";
    let found = rust_string_literals(quoted_char);
    assert_eq!(
        found.iter().map(|(_, t)| t.as_str()).collect::<Vec<_>>(),
        vec!["a   collapse"],
        "a `\"` inside a char literal must not desynchronise the scan"
    );

    // The verbatim-reference exemption is exactly one shape of path.
    use std::path::Path;
    assert!(is_verbatim_reference_messages(Path::new(
        "crates/stuffr-cli/src/compat/bzip2/messages.rs"
    )));
    assert!(!is_verbatim_reference_messages(Path::new(
        "crates/stuffr-cli/src/compat/bzip2/run.rs"
    )));
    assert!(!is_verbatim_reference_messages(Path::new(
        "crates/stuffr-cli/src/messages.rs"
    )));
    assert!(!is_verbatim_reference_messages(Path::new(
        "crates/stuffr-cli/src/compat/messages.rs"
    )));
    assert!(!is_verbatim_reference_messages(Path::new(
        "crates/stuffr-cli/src/compat/bzip2/xmessages.rs"
    )));
    assert!(is_verbatim_reference_messages(Path::new(
        "crates/stuffr-cli/src/compat/gzip/gnu/messages.rs"
    )));
    assert!(is_verbatim_reference_messages(Path::new(
        "crates/stuffr-cli/src/compat/gzip/bsd/messages.rs"
    )));
    assert!(!is_verbatim_reference_messages(Path::new(
        "crates/stuffr-cli/src/compat/gzip/bsd/run.rs"
    )));
    assert!(!is_verbatim_reference_messages(Path::new(
        "crates/stuffr-cli/src/compat/gzip/gnu/run.rs"
    )));
    assert!(!is_verbatim_reference_messages(Path::new(
        "crates/stuffr-cli/src/compat/gzip/gnu/x/messages.rs"
    )));
    // The compress family's personalities (0.18.0), as gzip's.
    assert!(is_verbatim_reference_messages(Path::new(
        "crates/stuffr-cli/src/compat/compress/apple/messages.rs"
    )));
    assert!(!is_verbatim_reference_messages(Path::new(
        "crates/stuffr-cli/src/compat/compress/apple/run.rs"
    )));
    assert!(is_verbatim_reference_messages(Path::new(
        "crates/stuffr-cli/src/compat/compress/ncompress/messages.rs"
    )));
    assert!(!is_verbatim_reference_messages(Path::new(
        "crates/stuffr-cli/src/compat/compress/ncompress/run.rs"
    )));

    // And now the workspace itself.
    let files = workspace_source_files();
    assert!(
        files.len() > 20,
        "the walk found only {} source files, which is not this workspace: {files:?}",
        files.len()
    );
    assert!(
        files.iter().any(|p| p.ends_with("stuffr-cli/src/main.rs")),
        "the walk must reach the crate every user-facing message is printed from"
    );

    let mut scanned = 0usize;
    let mut offenders = Vec::new();
    let mut exempted = 0usize;
    for file in &files {
        if is_verbatim_reference_messages(file) {
            exempted += 1;
            continue;
        }
        let src = std::fs::read_to_string(file).unwrap();
        for (line, text) in rust_string_literals(&src) {
            scanned += 1;
            let Some(at) = first_space_run(&text) else {
                continue;
            };
            if is_column_label(&text[..at]) {
                continue;
            }
            offenders.push(format!("{}:{line}: {text:?}", file.display()));
        }
    }
    assert!(
        scanned > 1000,
        "only {scanned} literals scanned, which is not this workspace"
    );
    assert!(
        exempted >= 1,
        "the bzip2 message table was not found, so the exemption matched nothing"
    );
    assert!(
        offenders.is_empty(),
        "a string literal carries a run of three or more spaces, which reaches the user as \
         collapsed continuation indentation mid-sentence. Re-join the sentence and end each \
         continued line with `\\` (which strips the newline AND the next line's indentation); \
         a deliberate column is written `label:   value`. Offenders:\n{}",
        offenders.join("\n")
    );
}
