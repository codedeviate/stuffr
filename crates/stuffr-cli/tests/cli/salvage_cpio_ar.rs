use crate::common::*;
use std::path::PathBuf;
use std::process::Command;

// ---------------------------------------------------------------------
// Salvage Stage 3 Task 3: cpio, the first format whose every entry is
// `Unattested`.
// ---------------------------------------------------------------------

/// A cpio whose first header has one non-hex digit: `stuffr list` refuses
/// the whole archive at exit 5, and salvage — format DETECTED from the
/// untouched magic — recovers every entry behind it as `Unattested`, says
/// why on each row and in the default summary, writes each byte for byte,
/// and exits 4: nothing in `newc` can prove a recovered record is real.
#[test]
fn salvage_recovers_a_damaged_cpio_as_unattested() {
    let dir = tmp_dir();
    let mut bytes = newc_archive(&[
        ("first.txt", b"lost with its header"),
        ("second.txt", b"recovered"),
        ("third.txt", b"also recovered"),
    ]);
    bytes[6] = b'x';
    let archive = dir.join("damaged.cpio");
    std::fs::write(&archive, &bytes).unwrap();

    let listed = run_output(&["list", archive.to_str().unwrap()]);
    assert_eq!(
        listed.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );

    let out = run_output(&["salvage", archive.to_str().unwrap(), "--list"]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        out.status.code(),
        Some(4),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: Vec<&str> = stdout.lines().collect();
    assert_eq!(rows.len(), 2, "{stdout}");
    for (row, name) in rows.iter().zip(["second.txt", "third.txt"]) {
        assert!(row.contains("Unattested") && row.contains(name), "{row}");
        assert!(
            row.contains("[no checksum and no header self-check in this format]"),
            "{row}"
        );
    }
    assert!(
        !stdout.contains("Complete") && !stdout.contains("Intact"),
        "{stdout}"
    );

    let out_dir = dir.join("recovered");
    let written = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&written.stderr);
    assert_eq!(written.status.code(), Some(4), "{stderr}");
    assert!(stderr.contains("2 entries are unattested"), "{stderr}");
    assert_eq!(
        std::fs::read(out_dir.join("second.txt")).unwrap(),
        b"recovered"
    );
    assert_eq!(
        std::fs::read(out_dir.join("third.txt")).unwrap(),
        b"also recovered"
    );
    assert!(!out_dir.join("first.txt").exists());
}

/// R1, routed from Task 1: `salvage --index N -o FILE` over an `Unattested`
/// entry wrote the file and exited 4 with `salvage -> wrote FILE` as its
/// only line — a non-zero status and no reason. It now prints the same
/// sentence `-C` prints.
#[test]
fn salvage_says_why_an_unattested_entry_written_with_dash_o_exits_4() {
    let dir = tmp_dir();
    let archive = dir.join("healthy.cpio");
    std::fs::write(
        &archive,
        newc_archive(&[("a.txt", b"one"), ("b.txt", b"two")]),
    )
    .unwrap();
    let target = dir.join("picked.txt");
    let out = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "--index",
        "1",
        "-o",
        target.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{stderr}");
    assert!(stderr.contains("salvage -> wrote"), "{stderr}");
    assert!(
        stderr.contains("1 entry is unattested: this format carries no checksum"),
        "exit 4 must say why: {stderr}"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"two");
}

/// A healthy cpio of a variant this build does not read is a claim about
/// the BUILD: `list` refuses it at exit 3, and so does `salvage`, naming the
/// variant — never "the scan found nothing recoverable" at exit 5.
#[test]
fn salvage_says_exit_3_for_a_cpio_variant_it_cannot_read() {
    let dir = tmp_dir();
    let mut crc: Vec<u8> = newc_entry(b"070702", "a.txt", b"alpha");
    crc.extend_from_slice(&newc_entry(b"070702", "TRAILER!!!", b""));
    let archive = dir.join("crc.cpio");
    std::fs::write(&archive, &crc).unwrap();

    assert_eq!(
        run_output(&["list", archive.to_str().unwrap()])
            .status
            .code(),
        Some(3)
    );
    let out = run_output(&[
        "salvage",
        "--format",
        "cpio",
        archive.to_str().unwrap(),
        "--list",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{stderr}");
    assert!(
        stderr.contains("070702") && stderr.contains("newc-crc"),
        "{stderr}"
    );
    assert!(!stderr.contains("nothing recoverable"), "{stderr}");
    assert!(out.stdout.is_empty());
}

// ---------------------------------------------------------------------
// Salvage Stage 3 Task 4: `ar`, and the limitation it states.
// ---------------------------------------------------------------------

/// **The limitation, where a user meets it.** An `ar` whose third member's
/// header is destroyed: `list` refuses the archive at exit 5; `salvage`
/// recovers the two members before the hole — and NOT the two intact ones
/// after it — and every mode (`--list`, `-C`, `-o`) says on stderr where the
/// walk stopped and that what follows is unreachable by construction, not
/// absent. Exit 4, the ordinary code for `Unattested` members (Ruling S-X).
#[test]
fn salvage_of_an_ar_with_a_hole_says_what_lies_past_it_is_unreachable() {
    let dir = tmp_dir();
    let (mut bytes, offsets) = ar_archive(&[
        ("one.txt", b"first"),
        ("two.txt", b"second"),
        ("three.txt", b"third"),
        ("four.txt", b"fourth"),
        ("five.txt", b"fifth"),
    ]);
    let hole = offsets[2];
    bytes[hole + 16..hole + 28].copy_from_slice(b"XXXXXXXXXXXX");
    let archive = dir.join("holed.a");
    std::fs::write(&archive, &bytes).unwrap();

    assert_eq!(
        run_output(&["list", archive.to_str().unwrap()])
            .status
            .code(),
        Some(5)
    );

    let says_why = |stderr: &str, mode: &str| {
        for needle in [
            format!("stopped at offset {hole}"),
            format!("{} bytes still to go", bytes.len() - hole),
            "unreachable by construction — not absent".to_string(),
            "timestamp".to_string(),
        ] {
            assert!(
                stderr.contains(&needle),
                "{mode}: missing {needle:?}: {stderr}"
            );
        }
    };

    let out = run_output(&["salvage", archive.to_str().unwrap(), "--list"]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{stdout}{stderr}");
    let rows: Vec<&str> = stdout.lines().collect();
    assert_eq!(rows.len(), 2, "{stdout}");
    for (row, name) in rows.iter().zip(["one.txt", "two.txt"]) {
        assert!(row.contains(name) && row.contains("Unattested"), "{row}");
    }
    for later in ["three.txt", "four.txt", "five.txt"] {
        assert!(!stdout.contains(later), "{stdout}");
    }
    says_why(&stderr, "--list");

    let out_dir = dir.join("recovered");
    let written = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&written.stderr);
    assert_eq!(written.status.code(), Some(4), "{stderr}");
    says_why(&stderr, "-C");
    assert!(stderr.contains("2 entries are unattested"), "{stderr}");
    assert_eq!(std::fs::read(out_dir.join("one.txt")).unwrap(), b"first");
    assert_eq!(std::fs::read(out_dir.join("two.txt")).unwrap(), b"second");
    assert!(!out_dir.join("four.txt").exists());

    let target = dir.join("picked.txt");
    let one = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "--index",
        "1",
        "-o",
        target.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&one.stderr);
    assert_eq!(one.status.code(), Some(4), "{stderr}");
    says_why(&stderr, "-o");
    assert_eq!(std::fs::read(&target).unwrap(), b"second");
}

/// The common damage: an `ar` cut inside its last member's payload. Every
/// member before it is whole, the cut one lands as `NAME.partial` holding
/// exactly the surviving bytes, and nothing claims anything is unreachable.
/// Cut inside the last member's HEADER instead, the note says the archive is
/// cut short there — never "unreachable".
#[test]
fn salvage_of_a_truncated_ar_recovers_the_tail_and_says_no_more_than_that() {
    let dir = tmp_dir();
    let (bytes, offsets) = ar_archive(&[("a.txt", b"alpha"), ("b.txt", b"bravo and more")]);
    let payload_cut = &bytes[..offsets[1] + 60 + 5];
    let archive = dir.join("cut.a");
    std::fs::write(&archive, payload_cut).unwrap();
    let out_dir = dir.join("cut-out");
    let run = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(4), "{stderr}");
    assert!(!stderr.contains("unreachable"), "{stderr}");
    assert!(!stderr.contains("walks the archive"), "{stderr}");
    assert_eq!(std::fs::read(out_dir.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(
        std::fs::read(out_dir.join("b.txt.partial")).unwrap(),
        b"bravo"
    );

    let header_cut = &bytes[..offsets[1] + 30];
    std::fs::write(&archive, header_cut).unwrap();
    let run = run_output(&["salvage", archive.to_str().unwrap(), "--list"]);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(4), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "the file ends 30 bytes into the record at offset {}",
            offsets[1]
        )),
        "{stderr}"
    );
    assert!(stderr.contains("cut short"), "{stderr}");
    assert!(!stderr.contains("unreachable"), "{stderr}");
}

/// 0.10.4: `list` of an `ar` cut inside a member's payload reads no payload,
/// and used to take the crate's drain of the cut one for a clean end: exit 0.
/// It is corrupt, exit 5, from a file and from stdin alike.
#[test]
fn list_of_an_ar_cut_inside_a_member_exits_5_from_a_file_and_from_stdin() {
    let dir = tmp_dir();
    let (bytes, offsets) = ar_archive(&[("a.txt", b"alpha"), ("b.txt", b"bravo and more")]);
    let cut = &bytes[..offsets[1] + 60 + 5];
    let archive = dir.join("cut.a");
    std::fs::write(&archive, cut).unwrap();

    let out = run_output(&["list", archive.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "{stderr}");
    assert!(stderr.contains("truncated"), "{stderr}");

    let out = run_with_stdin_output(&["list", "-"], cut);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "{stderr}");
    assert!(stderr.contains("truncated"), "{stderr}");
}

/// Nothing recovered at all — the FIRST header destroyed — is exit 5, and
/// the note still says why, before the "nothing recoverable" line.
#[test]
fn salvage_of_an_ar_whose_first_header_is_destroyed_exits_5_and_says_why() {
    let dir = tmp_dir();
    let (mut bytes, _) = ar_archive(&[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
    bytes[8 + 48..8 + 58].copy_from_slice(b"??????????");
    let archive = dir.join("first.a");
    std::fs::write(&archive, &bytes).unwrap();
    let run = run_output(&["salvage", archive.to_str().unwrap(), "--list"]);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(5), "{stderr}");
    let note = stderr
        .find("stopped at offset 8")
        .unwrap_or_else(|| panic!("{stderr}"));
    let nothing = stderr.find("found nothing recoverable").unwrap();
    assert!(note < nothing, "{stderr}");
}

/// 0.8.1: GNU binutils' `ar rcs` over Mach-O objects writes its inline
/// `__.SYMDEF` with an all-space mode field, which `list` used to refuse at
/// exit 5. Now `list` exits 0 and shows the table as Apple `ar t` does,
/// `unpack` extracts every member with the objects byte-exact, and
/// `salvage --list` recovers every member with no walk-stop note. macOS
/// only — an ELF host's GNU `ar` writes `/`, which was always read — and
/// GNU `ar` (keg-only, `brew install binutils`) plus `cc` are required
/// there, failing loudly when absent.
#[test]
fn gnu_ar_on_mach_o_with_a_blank_mode_symbol_table_lists_unpacks_and_salvages() {
    if !cfg!(target_os = "macos") {
        return;
    }
    let gnu = PathBuf::from("/opt/homebrew/opt/binutils/bin/ar");
    assert!(
        gnu.is_file(),
        "GNU ar not at {} (`brew install binutils`)",
        gnu.display()
    );
    let cc = which("cc").expect("no `cc` on PATH — this test needs Mach-O objects");
    let dir = tmp_dir();
    for (name, body) in [
        ("f", "int f(void){return 1;}\n"),
        ("g", "int g(void){return 2;}\n"),
    ] {
        std::fs::write(dir.join(format!("{name}.c")), body).unwrap();
        let ok = Command::new(&cc)
            .args(["-c", "-o", &format!("{name}.o"), &format!("{name}.c")])
            .current_dir(&dir)
            .status()
            .unwrap();
        assert!(ok.success(), "cc -c {name}.c");
    }
    let made = Command::new(&gnu)
        .args(["rcs", "lib.a", "f.o", "g.o"])
        .current_dir(&dir)
        .status()
        .unwrap();
    assert!(made.success(), "GNU ar rcs");
    let archive = dir.join("lib.a");
    let bytes = std::fs::read(&archive).unwrap();
    // The first member header (after the 8-byte `!<arch>\n`): its mode field
    // is `[40..48]` (`ar-0.9.0/src/lib.rs:292`).
    assert_eq!(&bytes[8..8 + 16], format!("{:<16}", "__.SYMDEF").as_bytes());
    assert_eq!(
        bytes[8 + 40..8 + 48],
        [b' '; 8],
        "GNU no longer writes a blank mode"
    );

    let out = run_output(&["list", archive.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    let names: Vec<&str> = stdout
        .lines()
        .map(|l| l.split_whitespace().last().unwrap())
        .collect();
    assert_eq!(names, ["__.SYMDEF", "f.o", "g.o"], "{stdout}");

    let out_dir = dir.join("unpacked");
    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    for obj in ["f.o", "g.o"] {
        assert_eq!(
            std::fs::read(out_dir.join(obj)).unwrap(),
            std::fs::read(dir.join(obj)).unwrap(),
            "{obj}"
        );
    }
    assert!(out_dir.join("__.SYMDEF").is_file());

    let out = run_output(&["salvage", archive.to_str().unwrap(), "--list"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{stdout}{stderr}");
    let rows: Vec<&str> = stdout.lines().collect();
    assert_eq!(rows.len(), 3, "{stdout}");
    for (row, name) in rows.iter().zip(["__.SYMDEF", "f.o", "g.o"]) {
        assert!(row.contains(name) && row.contains("Unattested"), "{row}");
    }
    assert!(!stderr.contains("stopped at offset"), "{stderr}");
    assert!(!stderr.contains("symbol table"), "{stderr}");
}

/// `stuffr pack` over a tree (every name `/`-bearing, so BSD `#1/N` form),
/// then salvage: every file back, byte for byte, exit 4 for `Unattested`.
#[test]
fn salvage_recovers_what_stuffr_pack_wrote_as_ar() {
    let dir = tmp_dir();
    let tree = dir.join("tree");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("a.txt"), b"alpha\n").unwrap();
    std::fs::write(tree.join("sub").join("b.bin"), vec![7u8; 3001]).unwrap();
    let archive = dir.join("packed.a");
    let packed = run_output(&[
        "pack",
        tree.to_str().unwrap(),
        "-o",
        archive.to_str().unwrap(),
    ]);
    assert!(
        packed.status.success(),
        "{}",
        String::from_utf8_lossy(&packed.stderr)
    );
    let out_dir = dir.join("packed-out");
    let run = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(4), "{stderr}");
    assert!(!stderr.contains("walks the archive"), "{stderr}");
    assert_eq!(
        std::fs::read(out_dir.join("tree").join("a.txt")).unwrap(),
        b"alpha\n"
    );
    assert_eq!(
        std::fs::read(out_dir.join("tree").join("sub").join("b.bin")).unwrap(),
        vec![7u8; 3001]
    );
}

/// Task 4 fix round 1 (I2, I3): two healthy archives this build cannot
/// read are exit 3 naming the shape — never exit 4 with fabricated content,
/// never exit 5 "nothing recoverable". A GNU thin archive, found by its `.a`
/// extension alone with no `--format`; and a `__.SYMDEF` whose mode field
/// is neither blank nor octal. (GNU `ar rcs`'s BLANK mode on Mach-O was this
/// test's original shape; it is read since 0.8.1 — see
/// `gnu_ar_on_mach_o_with_a_blank_mode_symbol_table_lists_unpacks_and_salvages`.)
#[test]
fn salvage_refuses_a_thin_archive_and_an_unreadable_symbol_table_at_exit_3() {
    let dir = tmp_dir();
    let mut thin = b"!<thin>\n".to_vec();
    thin.extend_from_slice(&ar_member("a.txt/", b"")[..60]);
    thin[8 + 48..8 + 58].copy_from_slice(format!("{:<10}", 18).as_bytes());
    thin.extend_from_slice(&ar_member("bb.bin/", b"")[..60]);
    let archive = dir.join("thin.a");
    std::fs::write(&archive, &thin).unwrap();
    let out_dir = dir.join("thin-out");
    let run = run_output(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        out_dir.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("thin archive"), "{stderr}");
    assert!(!out_dir.join("a.txt").exists());

    let mut symdef = b"!<arch>\n".to_vec();
    let mut table = ar_member("__.SYMDEF", b"\0\0\0\0");
    table[40..48].copy_from_slice(b"zzzzzzzz");
    symdef.extend(table);
    symdef.extend(ar_member("f.o", b"fff"));
    let archive = dir.join("symdef.a");
    std::fs::write(&archive, &symdef).unwrap();
    let run = run_output(&["salvage", archive.to_str().unwrap(), "--list"]);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("symbol table (`__.SYMDEF`)"), "{stderr}");
    assert!(!stderr.contains("nothing recoverable"), "{stderr}");
}
