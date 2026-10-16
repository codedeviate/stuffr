//! The lz4 compatibility family against lz4 1.10.0: stuffr invoked as `lz4`,
//! `unlz4`, `lz4cat` and `lz4c`, compared with the reference (stdout,
//! stderr, exit code, the file tree) through `compat_harness`, every case
//! under `LC_ALL=C`.
//!
//! **Task 2 wrote the probe tables** (every row below, probed 2026-10-16 by
//! running the reference binary only; the tables are also in
//! `.claude/rules/compat.md`, "lz4 1.10.0 probes"). A [`Row`] is one probed
//! command: its fixtures, the reference's exit code and the text of the
//! message it prints. Two uses:
//! - `the_recorded_table_holds_on_the_reference` (always on) runs every row
//!   on the reference and checks the recorded code and message, so the table
//!   cannot rot;
//! - `taskN_rows_match_the_reference` runs the rows a later task implements
//!   against stuffr and compares everything (`assert_same`). They are
//!   `#[ignore = "Task N"]`: un-ignoring the one for your task is the whole
//!   enablement. Ruling P1: Task 3 owns the pure parsing/usage rows, Task 4
//!   compress/decompress/test/file/interrupt, Task 5 `--list`, Task 6
//!   `-v`.
//!
//! The normalisations: a failed decode's partial output, which is the
//! reference's own race (`tolerate_lz4_partial_output`); the banner (`-V`, `-v`'s welcome line), which names
//! stuffr (spec deviation 1; masked exactly), and deviation 2's refreshes,
//! timing fields and thread count (`normalise_lz4_progress`).
//!
//! Not reproducible by the harness, recorded in `compat.md` only: standard
//! output or input closed (`>&-`, Rust reopens them on `/dev/null`);
//! `/dev/full` (Linux only); a reference that dies of SIGPIPE (the Rust
//! runtime ignores SIGPIPE: stuffr answers `Error 70`/`Error 38` where the
//! reference with a default disposition dies by the signal, sometimes after
//! printing the message; with SIGPIPE ignored the reference answers exactly
//! as stuffr does, which `closed_pipe_with_sigpipe_ignored` compares).

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;
    use std::fs;
    use std::path::Path;

    /// The C tier promises lz4's frames byte for byte; the pure tier's are
    /// judged by the reference decoding them (spec deviation 6).
    const EXACT: bool = cfg!(feature = "lz4-c");

    const REFERENCE_BANNER: &str = "*** lz4 v1.10.0 64-bit multithread, by Yann Collet ***\n";

    /// Spec deviation 1: stuffr's banner.
    fn our_banner() -> String {
        format!(
            "*** lz4 v1.10.0 64-bit multithread (stuffr {}), by Yann Collet ***\n",
            env!("CARGO_PKG_VERSION")
        )
    }

    fn ref_lz4() -> &'static str {
        static P: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        P.get_or_init(|| format!("{}/lz4", lz4_dir().unwrap_or("/nonexistent")))
    }

    // ---- fixtures ----

    fn text() -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog\n".repeat(200)
    }

    /// xxHash32 (seed 0 for lz4's checksums), from the public frame format:
    /// the header checksum is its second byte, the content and block
    /// checksums the whole word.
    fn xxh32(data: &[u8]) -> u32 {
        const P1: u32 = 2_654_435_761;
        const P2: u32 = 2_246_822_519;
        const P3: u32 = 3_266_489_917;
        const P4: u32 = 668_265_263;
        const P5: u32 = 374_761_393;
        let word = |at: usize| u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
        let mut i = 0;
        let mut h;
        if data.len() >= 16 {
            let mut v = [P1.wrapping_add(P2), P2, 0, 0u32.wrapping_sub(P1)];
            while i + 16 <= data.len() {
                for (k, lane) in v.iter_mut().enumerate() {
                    *lane = lane
                        .wrapping_add(word(i + 4 * k).wrapping_mul(P2))
                        .rotate_left(13)
                        .wrapping_mul(P1);
                }
                i += 16;
            }
            h = v[0]
                .rotate_left(1)
                .wrapping_add(v[1].rotate_left(7))
                .wrapping_add(v[2].rotate_left(12))
                .wrapping_add(v[3].rotate_left(18));
        } else {
            h = P5;
        }
        h = h.wrapping_add(data.len() as u32);
        while i + 4 <= data.len() {
            h = h.wrapping_add(word(i).wrapping_mul(P3));
            h = h.rotate_left(17).wrapping_mul(P4);
            i += 4;
        }
        while i < data.len() {
            h = h.wrapping_add(u32::from(data[i]).wrapping_mul(P5));
            h = h.rotate_left(11).wrapping_mul(P1);
            i += 1;
        }
        h ^= h >> 15;
        h = h.wrapping_mul(P2);
        h ^= h >> 13;
        h = h.wrapping_mul(P3);
        h ^ (h >> 16)
    }

    /// A frame header: magic, FLG, BD, the optional fields, the checksum.
    fn header(flg: u8, bd: u8, extra: &[u8]) -> Vec<u8> {
        let mut d = vec![flg, bd];
        d.extend_from_slice(extra);
        let hc = (xxh32(&d) >> 8) as u8;
        let mut v = vec![0x04, 0x22, 0x4d, 0x18];
        v.extend_from_slice(&d);
        v.push(hc);
        v
    }

    fn le32(n: u32) -> Vec<u8> {
        n.to_le_bytes().to_vec()
    }

    /// The reference's own output for `args` over `input` (the fixtures that
    /// need a real encoder).
    fn made(args: &[&str], input: &[u8]) -> Vec<u8> {
        filter_through(ref_lz4(), args, input)
            .unwrap_or_else(|| panic!("the reference could not run lz4 {args:?}"))
    }

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    fn flipped(mut v: Vec<u8>, at: isize) -> Vec<u8> {
        let i = if at < 0 { v.len() as isize + at } else { at } as usize;
        v[i] ^= 0xff;
        v
    }

    /// Legacy frames: magic `02 21 4c 18`, then blocks of a 4-byte size and
    /// that many bytes.
    const LEGACY: [u8; 4] = [0x02, 0x21, 0x4c, 0x18];

    /// A fixture by name. Built from the reference's own encoder or by hand;
    /// every name a [`Row`] lists must be here.
    fn fx(name: &str) -> Vec<u8> {
        let good = || made(&["-c", "-q"], &text());
        let blocks = || made(&["-c", "-q", "-BD", "-BX"], &text());
        let legacy = || made(&["-c", "-q", "-l"], &text());
        let end = le32(0);
        match name {
            "a" => text(),
            "b.lz4" => good(),
            "bc.lz4" => blocks(),
            "leg.lz4" => legacy(),
            "dict" => text()[..880].to_vec(),
            ".lz4" => text(),
            "dict2" => b"completely different dictionary content 0123456789\n".repeat(20),
            "dict_b.lz4" => {
                // The reference reads a dictionary only from a file.
                let path =
                    std::env::temp_dir().join(format!("stuffr-lz4-dict-{}", std::process::id()));
                fs::write(&path, fx("dict")).unwrap();
                let frame = made(&["-c", "-q", "-D", path.to_str().unwrap()], &text());
                let _ = fs::remove_file(&path);
                frame
            }
            "bad_bcrc2.lz4" => flipped(blocks(), 30),
            "empty.lz4" => made(&["-c", "-q"], b""),
            "e.lz4" | "a.lz4x" | "o" | "empty" => Vec::new(),
            "a2" => b"old\n".to_vec(),
            "notlz4" | "x.lz4" => b"hello world, not lz4\n".to_vec(),
            "unk_hdr.lz4" => b"\x99\x99\x99\x99rest".to_vec(),
            "t_magic.lz4" => good()[..2].to_vec(),
            "t_hdr.lz4" => good()[..5].to_vec(),
            "t_hdr2.lz4" => good()[..7].to_vec(),
            "t_bsz.lz4" => good()[..9].to_vec(),
            "t_blk.lz4" => good()[..good().len() - 6].to_vec(),
            "t_crc.lz4" => good()[..good().len() - 2].to_vec(),
            "t_bblk.lz4" => blocks()[..blocks().len() - 10].to_vec(),
            "bad_hc.lz4" => flipped(good(), 6),
            "bad_bcrc.lz4" => flipped(blocks(), -12),
            "bad_endmark.lz4" => flipped(blocks(), -8),
            "bad_ccrc.lz4" => flipped(good(), -1),
            "bad_data.lz4" => flipped(good(), 12),
            "g1.lz4" => cat(&[&good(), b"A"]),
            "g3.lz4" => cat(&[&good(), b"AAA"]),
            "g4.lz4" => cat(&[&good(), b"AAAA"]),
            "g100.lz4" => cat(&[&good(), &[b'A'; 100]]),
            "z.lz4" => cat(&[&good(), &[0u8; 8]]),
            // The Task 1 review's probe: a legacy frame whose first block
            // word is zero.
            "legzero.lz4" => cat(&[&LEGACY, &end]),
            // Header-field refusals (the checksum is not reached).
            "v0.lz4" => cat(&[&header(0x24, 0x40, &[]), &end]),
            "v2.lz4" => cat(&[&header(0xa4, 0x40, &[]), &end]),
            "rsvd_flg.lz4" => cat(&[&header(0x66, 0x40, &[]), &end]),
            "rsvd_bd.lz4" => cat(&[&header(0x64, 0xc0, &[]), &end]),
            "bd_size3.lz4" => cat(&[&header(0x64, 0x30, &[]), &end]),
            "bd_size0.lz4" => cat(&[&header(0x64, 0x00, &[]), &end]),
            // 128 KiB claimed in a 64 KiB frame, 16 MiB in a 4 MiB one.
            "blk_too_big.lz4" => cat(&[&header(0x64, 0x40, &[]), &le32(0x2_0000), &[b'x'; 16]]),
            "blk_16m.lz4" => cat(&[&header(0x64, 0x70, &[]), &le32(0x100_0000), &[b'x'; 16]]),
            "blk_uncompressed.lz4" => cat(&[
                &header(0x64, 0x40, &[]),
                &le32(0x8000_0005),
                b"hello",
                &end,
                &le32(xxh32(b"hello")),
            ]),
            "cs_2p63.lz4" => cat(&[&header(0x6c, 0x40, &(1u64 << 63).to_le_bytes()), &end]),
            "cs_trunc.lz4" => header(0x6c, 0x40, &5u64.to_le_bytes())[..9].to_vec(),
            "cs_mismatch.lz4" => cat(&[&header(0x6c, 0x40, &5u64.to_le_bytes()), &end]),
            "dictid.lz4" => cat(&[&header(0x65, 0x40, &le32(0x1234_5678)), &end]),
            "skip_trunc.lz4" => cat(&[&[0x50, 0x2a, 0x4d, 0x18], &le32(10), b"abc"]),
            "skip_hdr_trunc.lz4" => cat(&[&[0x50, 0x2a, 0x4d, 0x18], &[1]]),
            "skip_ok.lz4" => cat(&[&[0x50, 0x2a, 0x4d, 0x18], &le32(3), b"abc"]),
            "skip_then_good.lz4" => cat(&[&[0x50, 0x2a, 0x4d, 0x18], &le32(3), b"abc", &good()]),
            "two_frames.lz4" => cat(&[&good(), &good()]),
            "leg_then_good.lz4" => cat(&[&legacy(), &good()]),
            "good_then_leg.lz4" => cat(&[&good(), &legacy()]),
            "leg_bsz_trunc.lz4" => cat(&[&LEGACY, &[1, 0]]),
            "leg_blk_trunc.lz4" => cat(&[&LEGACY, &le32(50), b"abc"]),
            "leg_huge.lz4" => cat(&[&LEGACY, &le32(0xffff_fff0), b"abc"]),
            "leg_8m.lz4" => cat(&[&LEGACY, &le32(0x80_0100), b"abc"]),
            "leg_bad.lz4" => cat(&[&LEGACY, &le32(8), &[0xff; 8]]),
            "leg_garbage.lz4" => cat(&[&legacy(), b"AAA"]),
            "leg_garbage100.lz4" => cat(&[&legacy(), &[b'A'; 100]]),
            "leg_zeros.lz4" => cat(&[&legacy(), &[0u8; 8]]),
            other => panic!("no fixture named {other}"),
        }
    }

    // ---- setups ----

    fn mkdir_d(w: &Path) {
        fs::create_dir(w.join("d")).unwrap();
    }
    fn dir_with_file(w: &Path) {
        mkdir_d(w);
        fs::write(w.join("d/x"), b"hi\n").unwrap();
    }
    fn mkdir_dlz4(w: &Path) {
        fs::create_dir(w.join("d.lz4")).unwrap();
    }
    fn unreadable_a(w: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(w.join("a"), fs::Permissions::from_mode(0o000)).unwrap();
    }
    fn unreadable_b(w: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(w.join("b.lz4"), fs::Permissions::from_mode(0o000)).unwrap();
    }
    fn read_only_dir(w: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir(w.join("ro")).unwrap();
        fs::set_permissions(w.join("ro"), fs::Permissions::from_mode(0o555)).unwrap();
    }
    fn read_only_o(w: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(w.join("o"), fs::Permissions::from_mode(0o444)).unwrap();
    }
    /// A previous compression's output next to the input (`a.lz4`).
    fn existing_default_output(w: &Path) {
        fs::write(w.join("a.lz4"), b"").unwrap();
    }

    // ---- the table ----

    /// One probed command: what the reference did, as recorded 2026-10-16.
    struct Row {
        label: &'static str,
        /// The task that enables the differential row (ruling P1).
        task: &'static str,
        name: &'static str,
        args: Vec<&'static str>,
        files: Vec<&'static str>,
        stdin: Option<Vec<u8>>,
        tty_stdin: bool,
        tty_stdout: bool,
        setup: Option<fn(&Path)>,
        /// The reference's exit code.
        code: i32,
        /// Text its standard error holds (`""`: nothing is checked).
        msg: &'static str,
    }

    /// The start of every short usage: `Incorrect parameters`, then the
    /// usage block (`lz4 [arg] [input] [output]`, or the invoked name).
    const USAGE: &str = "Incorrect parameters\nUsage : \n";

    fn row(
        task: &'static str,
        label: &'static str,
        name: &'static str,
        args: &[&'static str],
        files: &[&'static str],
        code: i32,
        msg: &'static str,
    ) -> Row {
        Row {
            label,
            task,
            name,
            args: args.to_vec(),
            files: files.to_vec(),
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            setup: None,
            code,
            msg,
        }
    }

    impl Row {
        fn stdin(mut self, bytes: &[u8]) -> Row {
            self.stdin = Some(bytes.to_vec());
            self
        }
        fn stdin_fx(mut self, name: &str) -> Row {
            self.stdin = Some(fx(name));
            self
        }
        fn tty(mut self, stdin: bool, stdout: bool) -> Row {
            self.tty_stdin = stdin;
            self.tty_stdout = stdout;
            self
        }
        fn setup(mut self, f: fn(&Path)) -> Row {
            self.setup = Some(f);
            self
        }
    }

    /// Every probed row. Each `task` names who enables it; the codes and
    /// messages are the reference's, 2026-10-16, `LC_ALL=C`.
    fn rows() -> Vec<Row> {
        const T3: &str = "Task 3";
        const T4: &str = "Task 4";
        const T5: &str = "Task 5";
        const T6: &str = "Task 6";
        let usage = USAGE;
        let mut v = vec![
            // ---- Task 3: parsing and usage (no file is touched) ----
            row(
                T3,
                "unknown long option",
                "lz4",
                &["--bogus", "a"],
                &["a"],
                1,
                usage,
            ),
            row(
                T3,
                "unknown short option",
                "lz4",
                &["-y", "a"],
                &["a"],
                1,
                usage,
            ),
            row(
                T3,
                "-D without its argument",
                "lz4",
                &["a", "-D"],
                &["a"],
                1,
                usage,
            ),
            row(T3, "-D alone", "lz4", &["-D"], &[], 1, usage),
            row(T3, "-B3", "lz4", &["-B3", "a"], &["a"], 1, usage),
            row(T3, "-B8", "lz4", &["-B8", "a"], &["a"], 1, usage),
            row(T3, "-B31", "lz4", &["-B31", "a"], &["a"], 1, usage),
            row(T3, "-B0", "lz4", &["-B0", "a"], &["a"], 1, usage),
            row(T3, "--fast=0", "lz4", &["--fast=0", "a"], &["a"], 1, usage),
            row(
                T3,
                "--fast=-1",
                "lz4",
                &["--fast=-1", "a"],
                &["a"],
                1,
                usage,
            ),
            row(T3, "--fast=x", "lz4", &["--fast=x", "a"], &["a"], 1, usage),
            row(T3, "-Tx", "lz4", &["-Tx", "a"], &["a"], 1, usage),
            row(T3, "-T-1", "lz4", &["-T-1", "a"], &["a"], 1, usage),
            row(
                T3,
                "-T 2 takes no operand: a is a second name",
                "lz4",
                &["-T", "2", "-c", "a"],
                &["a"],
                1,
                "Error : a won't be used ! Do you want multiple input files (-m) ? \n",
            ),
            row(
                T3,
                "a third name without -m",
                "lz4",
                &["a", "x.lz4", "y"],
                &["a"],
                1,
                "Error : y won't be used ! Do you want multiple input files (-m) ? \n",
            ),
            row(
                T3,
                "-c with two names",
                "lz4",
                &["-c", "a", "b", "c"],
                &["a"],
                1,
                "Error : b won't be used ! Do you want multiple input files (-m) ? \n",
            ),
            row(
                T3,
                "lz4 -d of a name without .lz4",
                "lz4",
                &["-d", "a"],
                &["a"],
                1,
                "Cannot determine an output filename \nIncorrect parameters\nUsage : \n",
            ),
            row(
                T3,
                "unlz4 of a name without .lz4",
                "unlz4",
                &["a"],
                &["a"],
                1,
                "Cannot determine an output filename \nIncorrect parameters\nUsage : \n",
            ),
            // ---- Task 3 (2026-10-16): the grammar, probed for cli.rs ----
            row(
                T3,
                "-B1x: B1 is no size",
                "lz4",
                &["-B1x", "a"],
                &["a"],
                1,
                usage,
            ),
            row(
                T3,
                "a dash inside -B4-",
                "lz4",
                &["-B4-", "a"],
                &["a"],
                1,
                "using blocks of size 64 KB \nIncorrect parameters\n",
            ),
            row(
                T3,
                "-BK: B needs a digit",
                "lz4",
                &["-BK", "a"],
                &["a"],
                1,
                usage,
            ),
            row(
                T3,
                "-B wraps to 31",
                "lz4",
                &["-B4294967327", "a"],
                &["a"],
                1,
                usage,
            ),
            row(
                T3,
                "-B wraps to 0",
                "lz4",
                &["-B42949672960", "a"],
                &["a"],
                1,
                usage,
            ),
            row(
                T3,
                "-B4096M wraps to 0",
                "lz4",
                &["-B4096M", "a"],
                &["a"],
                1,
                usage,
            ),
            row(
                T3,
                "-B4 then -V",
                "lz4",
                &["-B4", "-V"],
                &[],
                0,
                "using blocks of size 64 KB \n",
            ),
            row(
                T3,
                "-B7BD then -V",
                "lz4",
                &["-B7BD", "-V"],
                &[],
                0,
                "using blocks of size 4096 KB \n",
            ),
            row(
                T3,
                "-B4B5 prints both",
                "lz4",
                &["-B4B5", "-V"],
                &[],
                0,
                "using blocks of size 64 KB \nusing blocks of size 256 KB \n",
            ),
            row(
                T3,
                "-B33 is bytes",
                "lz4",
                &["-B33", "-V"],
                &[],
                0,
                "using blocks of size 33 bytes \n",
            ),
            row(
                T3,
                "-B1023 is bytes",
                "lz4",
                &["-B1023", "-V"],
                &[],
                0,
                "using blocks of size 1023 bytes \n",
            ),
            row(
                T3,
                "-B1024 is 1 KB",
                "lz4",
                &["-B1024", "-V"],
                &[],
                0,
                "using blocks of size 1 KB \n",
            ),
            row(
                T3,
                "-B65537 is 64 KB",
                "lz4",
                &["-B65537", "-V"],
                &[],
                0,
                "using blocks of size 64 KB \n",
            ),
            row(
                T3,
                "-B is capped at 4 MiB",
                "lz4",
                &["-B99999999999", "-V"],
                &[],
                0,
                "using blocks of size 4096 KB \n",
            ),
            row(
                T3,
                "-B4194305K wraps to 1 KB",
                "lz4",
                &["-B4194305K", "-V"],
                &[],
                0,
                "using blocks of size 1 KB \n",
            ),
            row(
                T3,
                "-B64KiB",
                "lz4",
                &["-B64KiB", "-V"],
                &[],
                0,
                "using blocks of size 64 KB \n",
            ),
            row(
                T3,
                "-B64k is bytes",
                "lz4",
                &["-B64k", "-V"],
                &[],
                0,
                "using blocks of size 64 bytes \n",
            ),
            row(
                T3,
                "-q before -B silences it",
                "lz4",
                &["-q", "-B4", "-V"],
                &[],
                0,
                "",
            ),
            row(
                T3,
                "-q after -B does not",
                "lz4",
                &["-B4", "-q", "-V"],
                &[],
                0,
                "using blocks of size 64 KB \n",
            ),
            row(
                T3,
                "-B4v",
                "lz4",
                &["-B4v", "-V"],
                &[],
                0,
                "using blocks of size 64 KB \n",
            ),
            row(T3, "-T4x", "lz4", &["-T4x", "a"], &["a"], 1, usage),
            row(T3, "-TK then -V", "lz4", &["-TK", "-V"], &[], 0, ""),
            row(
                T3,
                "--threads=x",
                "lz4",
                &["--threads=x", "a"],
                &["a"],
                1,
                "error: only numeric values with optional suffixes K, KB, KiB, M, MB, MiB are allowed \n",
            ),
            row(
                T3,
                "--threads=4x",
                "lz4",
                &["--threads=4x", "a"],
                &["a"],
                1,
                "error: only numeric values with optional suffixes K, KB, KiB, M, MB, MiB are allowed \n",
            ),
            row(
                T3,
                "--threads4 reads the next argument",
                "lz4",
                &["--threads4", "a"],
                &["a"],
                1,
                "error: only numeric values with optional suffixes K, KB, KiB, M, MB, MiB are allowed \n",
            ),
            row(
                T3,
                "--threads last",
                "lz4",
                &["a", "--threads"],
                &["a"],
                1,
                "error: missing command argument \n",
            ),
            row(
                T3,
                "--threads then an option",
                "lz4",
                &["--threads", "-c", "a"],
                &["a"],
                1,
                "error: command cannot be separated from its argument by another command \n",
            ),
            row(
                T3,
                "--threads then -",
                "lz4",
                &["--threads", "-", "a"],
                &["a"],
                1,
                "error: command cannot be separated from its argument by another command \n",
            ),
            row(
                T3,
                "--threads 4 then -V",
                "lz4",
                &["--threads", "4", "-V"],
                &[],
                0,
                "",
            ),
            row(
                T3,
                "--threadsx 4 then -V",
                "lz4",
                &["--threadsx", "4", "-V"],
                &[],
                0,
                "",
            ),
            row(
                T3,
                "--threads= then -V",
                "lz4",
                &["--threads=", "-V"],
                &[],
                0,
                "",
            ),
            row(
                T3,
                "-qq --threads=x is silent",
                "lz4",
                &["-qq", "--threads=x"],
                &[],
                1,
                "",
            ),
            row(T3, "--fast=", "lz4", &["--fast=", "a"], &["a"], 1, usage),
            row(
                T3,
                "--fast=+1",
                "lz4",
                &["--fast=+1", "a"],
                &["a"],
                1,
                usage,
            ),
            row(T3, "--fast3", "lz4", &["--fast3", "a"], &["a"], 1, usage),
            row(T3, "--fastx", "lz4", &["--fastx", "a"], &["a"], 1, usage),
            row(
                T3,
                "--fast wraps to 0",
                "lz4",
                &["--fast=4294967296", "a"],
                &["a"],
                1,
                usage,
            ),
            row(
                T3,
                "--fast=0K",
                "lz4",
                &["--fast=0K", "a"],
                &["a"],
                1,
                usage,
            ),
            row(
                T3,
                "--fast=1x then -V",
                "lz4",
                &["--fast=1x", "-V"],
                &[],
                0,
                "",
            ),
            row(T3, "--best=1", "lz4", &["--best=1", "a"], &["a"], 1, usage),
            row(
                T3,
                "--decomp is no prefix",
                "lz4",
                &["--decomp", "a"],
                &["a"],
                1,
                usage,
            ),
            row(
                T3,
                "--favor-decspeed",
                "lz4",
                &["--favor-decspeed", "a"],
                &["a"],
                1,
                usage,
            ),
            row(
                T3,
                "--no-keep",
                "lz4",
                &["--no-keep", "a"],
                &["a"],
                1,
                usage,
            ),
            row(T3, "--legacy", "lz4", &["--legacy", "a"], &["a"], 1, usage),
            row(
                T3,
                "--recursive",
                "lz4",
                &["--recursive", "a"],
                &["a"],
                1,
                usage,
            ),
            row(T3, "--long-help", "lz4", &["--long-help"], &[], 1, usage),
            row(T3, "-d-c", "lz4", &["-d-c", "a"], &["a"], 1, usage),
            row(
                T3,
                "a space inside an aggregate",
                "lz4",
                &["-d -c", "a"],
                &["a"],
                1,
                usage,
            ),
            row(
                T3,
                "-qq silences a usage error",
                "lz4",
                &["-qq", "--bogus"],
                &[],
                1,
                "",
            ),
            row(
                T3,
                "-qq after the error does not",
                "lz4",
                &["--bogus", "-qq"],
                &[],
                1,
                usage,
            ),
            row(T3, "-qq -B3", "lz4", &["-qq", "-B3"], &[], 1, ""),
            row(T3, "-y is lz4c's", "lz4", &["-y", "a"], &["a"], 1, usage),
            row(T3, "-cy is lz4c's", "lz4", &["-cy", "a"], &["a"], 1, usage),
            row(T3, "-bK", "lz4", &["-bK", "a"], &["a"], 1, usage),
            row(T3, "-bx", "lz4", &["-bx", "a"], &["a"], 1, usage),
            row(T3, "-e3x", "lz4", &["-e3x", "a"], &["a"], 1, usage),
            row(T3, "-i3x", "lz4", &["-i3x", "a"], &["a"], 1, usage),
            row(T3, "-e1Kx", "lz4", &["-e1Kx", "a"], &["a"], 1, usage),
            row(
                T3,
                "-dD with nothing after",
                "lz4",
                &["a", "-dD"],
                &["a"],
                1,
                usage,
            ),
            row(T3, "-S then -V", "lz4", &["-S", "-V"], &[], 0, ""),
            // Help and version: printed as soon as read, whatever the level.
            row(
                T3,
                "-h",
                "lz4",
                &["-h"],
                &[],
                0,
                "Usage : \n      lz4 [arg] [input] [output] \n",
            ),
            row(
                T3,
                "-H",
                "lz4",
                &["-H"],
                &[],
                0,
                "***** Advanced comment *****",
            ),
            row(
                T3,
                "--help is -h",
                "lz4",
                &["--help"],
                &[],
                0,
                "--best  : same as -12\n",
            ),
            row(T3, "--version", "lz4", &["--version"], &[], 0, ""),
            row(
                T3,
                "-h before an unknown option",
                "lz4",
                &["-h", "--bogus"],
                &[],
                0,
                "Usage : \n",
            ),
            row(
                T3,
                "an unknown option before -h",
                "lz4",
                &["--bogus", "-h"],
                &[],
                1,
                usage,
            ),
            row(T3, "-hV", "lz4", &["-hV"], &[], 0, "Usage : \n"),
            row(T3, "-Vh", "lz4", &["-Vh"], &[], 0, ""),
            row(
                T3,
                "-V before an unknown option",
                "lz4",
                &["-V", "--bogus"],
                &[],
                0,
                "",
            ),
            row(T3, "-B3 before -V", "lz4", &["-B3", "-V"], &[], 1, usage),
            row(
                T3,
                "-qq -h still prints",
                "lz4",
                &["-qq", "-h"],
                &[],
                0,
                "Usage : \n",
            ),
            row(T3, "-qq -V still prints", "lz4", &["-qq", "-V"], &[], 0, ""),
            row(T3, "-dh", "lz4", &["-dh"], &[], 0, "Usage : \n"),
            row(
                T3,
                "-b before -h",
                "lz4",
                &["-b", "-h"],
                &[],
                0,
                "Usage : \n",
            ),
            row(T3, "-e before -V", "lz4", &["-e", "-V"], &[], 0, ""),
            row(
                T3,
                "unlz4 -h",
                "unlz4",
                &["-h"],
                &[],
                0,
                "      unlz4 [arg] [input] [output] \n",
            ),
            row(
                T3,
                "unlz4 -H",
                "unlz4",
                &["-H"],
                &[],
                0,
                "unlz4 will refuse to read from console",
            ),
            row(
                T3,
                "lz4cat -h",
                "lz4cat",
                &["-h"],
                &[],
                0,
                "      lz4cat [arg] [input] [output] \n",
            ),
            row(
                T3,
                "lz4cat -H",
                "lz4cat",
                &["-H"],
                &[],
                0,
                "generator | lz4cat | consumer",
            ),
            row(T3, "lz4cat -V", "lz4cat", &["-V"], &[], 0, ""),
            row(
                T3,
                "unlz4 usage error",
                "unlz4",
                &["--bogus"],
                &[],
                1,
                "      unlz4 [arg] [input] [output] \n",
            ),
            row(
                T3,
                "lz4c -h lists the legacy arguments",
                "lz4c",
                &["-h"],
                &[],
                0,
                "Legacy arguments : \n -c0    : fast compression \n",
            ),
            row(
                T3,
                "lz4c -H warns",
                "lz4c",
                &["-H"],
                &[],
                0,
                "***** Warning  ***** \n",
            ),
            row(
                T3,
                "lz4c usage error has no legacy block",
                "lz4c",
                &["--bogus"],
                &[],
                1,
                "      lz4c [arg] [input] [output] \n",
            ),
            row(
                T3,
                "lz4c -hc9 is -h",
                "lz4c",
                &["-hc9", "a"],
                &["a"],
                0,
                "Legacy arguments : \n",
            ),
            row(
                T3,
                "lz4c -hcd is -h",
                "lz4c",
                &["-hcd", "a"],
                &["a"],
                0,
                "Legacy arguments : \n",
            ),
            row(T3, "lz4c -yf", "lz4c", &["-yf", "a"], &["a"], 1, usage),
            row(
                T3,
                "lz4c -yd",
                "lz4c",
                &["-yd", "b.lz4"],
                &["b.lz4"],
                1,
                usage,
            ),
            row(T3, "lz4c -c0 then -V", "lz4c", &["-c0", "-V"], &[], 0, ""),
            // Operands.
            row(
                T3,
                "a fourth operand",
                "lz4",
                &["a", "b", "c", "d"],
                &["a"],
                1,
                "Error : c won't be used ! Do you want multiple input files (-m) ? \n",
            ),
            row(
                T3,
                "a third operand before -m",
                "lz4",
                &["a", "b", "c", "-m"],
                &["a"],
                1,
                "Error : c won't be used ! Do you want multiple input files (-m) ? \n",
            ),
            row(
                T3,
                "a third operand before -h",
                "lz4",
                &["a", "b", "c", "-h"],
                &["a"],
                1,
                "Error : c won't be used ! Do you want multiple input files (-m) ? \n",
            ),
            row(
                T3,
                "a third operand before --bogus",
                "lz4",
                &["a", "b", "c", "--bogus"],
                &["a"],
                1,
                "Error : c won't be used ! Do you want multiple input files (-m) ? \n",
            ),
            row(
                T3,
                "-B4 before a third operand",
                "lz4",
                &["-B4", "a", "b", "c"],
                &["a"],
                1,
                "using blocks of size 64 KB \nError : c won't be used ! Do you want multiple input files (-m) ? \n",
            ),
            row(
                T3,
                "stdout after -c",
                "lz4",
                &["-c", "a", "stdout"],
                &["a"],
                1,
                "Error : stdout won't be used ! Do you want multiple input files (-m) ? \n",
            ),
            row(
                T3,
                "a name after -",
                "lz4",
                &["a", "-", "b"],
                &["a"],
                1,
                "Error : b won't be used ! Do you want multiple input files (-m) ? \n",
            ),
            row(
                T3,
                "--stdout then two names",
                "lz4",
                &["--stdout", "a", "b"],
                &["a"],
                1,
                "Error : b won't be used ! Do you want multiple input files (-m) ? \n",
            ),
            row(
                T3,
                "-qq silences a surplus operand",
                "lz4",
                &["-qq", "-c", "a", "b", "c"],
                &["a"],
                1,
                "",
            ),
            row(
                T3,
                "-q does not",
                "lz4",
                &["-q", "-c", "a", "b", "c"],
                &["a"],
                1,
                "Error : b won't be used ! Do you want multiple input files (-m) ? \n",
            ),
            row(
                T3,
                "lz4 .lz4",
                "lz4",
                &[".lz4"],
                &[".lz4"],
                1,
                "Cannot determine an output filename \nIncorrect parameters\n",
            ),
            row(
                T3,
                "-qq -d a is silent",
                "lz4",
                &["-qq", "-d", "a"],
                &["a"],
                1,
                "",
            ),
            row(
                T3,
                "-p -V pauses",
                "lz4",
                &["-p", "-V"],
                &[],
                0,
                "Press enter to continue...\n",
            ),
            row(
                T3,
                "-p -h pauses",
                "lz4",
                &["-p", "-h"],
                &[],
                0,
                "(default : 3s) \nPress enter to continue...\n",
            ),
            row(
                T3,
                "-p --bogus does not",
                "lz4",
                &["-p", "--bogus"],
                &[],
                1,
                usage,
            ),
            row(
                T3,
                "-p and a surplus operand",
                "lz4",
                &["-p", "a", "b", "c"],
                &["a"],
                1,
                "Error : c won't be used ! Do you want multiple input files (-m) ? \n",
            ),
            row(
                T3,
                "-p -d a does not pause",
                "lz4",
                &["-p", "-d", "a"],
                &["a"],
                1,
                "Cannot determine an output filename \n",
            ),
            row(
                T3,
                "stdin a terminal",
                "lz4",
                &[],
                &[],
                1,
                "refusing to read from a console\n",
            )
            .tty(true, false),
            row(
                T3,
                "stdin a terminal, -c",
                "lz4",
                &["-c"],
                &[],
                1,
                "refusing to read from a console\n",
            )
            .tty(true, false),
            row(
                T3,
                "stdin a terminal, --list",
                "lz4",
                &["--list"],
                &[],
                1,
                "refusing to read from a console\n",
            )
            .tty(true, false),
            row(
                T3,
                "stdin a terminal, -m",
                "lz4",
                &["-m"],
                &[],
                1,
                "refusing to read from a console\n",
            )
            .tty(true, false),
            row(
                T3,
                "stdin a terminal, -m stdin",
                "lz4",
                &["-m", "stdin"],
                &[],
                1,
                "refusing to read from a console\n",
            )
            .tty(true, false),
            row(
                T3,
                "stdin a terminal, lz4cat",
                "lz4cat",
                &[],
                &[],
                1,
                "refusing to read from a console\n",
            )
            .tty(true, false),
            row(
                T3,
                "stdin a terminal, -p",
                "lz4",
                &["-p"],
                &[],
                1,
                "refusing to read from a console\n",
            )
            .tty(true, false),
            row(
                T3,
                "stdout a terminal, a -",
                "lz4",
                &["a", "-"],
                &["a"],
                1,
                "refusing to write to console without -c \n",
            )
            .tty(false, true),
            row(
                T3,
                "stdout a terminal, a stdout",
                "lz4",
                &["a", "stdout"],
                &["a"],
                1,
                "refusing to write to console without -c \n",
            )
            .tty(false, true),
            row(
                T3,
                "stdout a terminal, -m",
                "lz4",
                &["-m"],
                &[],
                1,
                "refusing to write to console without -c \n",
            )
            .tty(false, true)
            .stdin(b"x"),
            row(
                T3,
                "stdout a terminal, unlz4",
                "unlz4",
                &[],
                &[],
                1,
                "refusing to write to console without -c \n",
            )
            .tty(false, true)
            .stdin(b"x"),
            // ---- Task 4: Task 3's parse and decision table reaching I/O ----
            row(T4, "lz4 on stdin", "lz4", &[], &[], 0, "").stdin_fx("a"),
            row(T4, "unlz4 on stdin", "unlz4", &[], &[], 0, "").stdin_fx("b.lz4"),
            row(T4, "lz4cat on stdin", "lz4cat", &[], &[], 0, "").stdin_fx("b.lz4"),
            row(T4, "lz4c on stdin", "lz4c", &[], &[], 0, "").stdin_fx("a"),
            row(
                T4,
                "lz4c -c0 names a.lz4",
                "lz4c",
                &["-c0", "a"],
                &["a"],
                0,
                "Compressed filename will be : a.lz4 \n",
            ),
            row(
                T4,
                "lz4c -hc a out",
                "lz4c",
                &["-hc", "a", "out"],
                &["a"],
                0,
                "",
            ),
            row(
                T4,
                "lz4c -fc2 a",
                "lz4c",
                &["-fc2", "a"],
                &["a"],
                0,
                "Compressed filename will be : a.lz4 \n",
            ),
            row(
                T4,
                "lz4c -cy writes stdout",
                "lz4c",
                &["-cy", "a"],
                &["a"],
                0,
                "",
            ),
            row(
                T4,
                "a b -m compresses stdin into b",
                "lz4",
                &["a", "b", "-m"],
                &["a"],
                0,
                "",
            )
            .stdin_fx("a"),
            row(
                T4,
                "a -m compresses stdin to stdout",
                "lz4",
                &["a", "-m"],
                &["a"],
                0,
                "",
            )
            .stdin_fx("a"),
            row(
                T4,
                "a -m b reads only b",
                "lz4",
                &["a", "-m", "b"],
                &["a"],
                1,
                "b: No such file or directory \n",
            ),
            row(
                T4,
                "-m -t writes stdout",
                "lz4",
                &["-m", "-t", "b.lz4"],
                &["b.lz4"],
                0,
                "",
            ),
            row(
                T4,
                "null then -m -d writes stdout",
                "lz4",
                &["a", "null", "-m", "-d", "b.lz4"],
                &["a", "b.lz4"],
                0,
                "",
            ),
            row(
                T4,
                "null then -m compresses to notlz4.lz4",
                "lz4",
                &["a", "null", "-m", "notlz4"],
                &["a", "notlz4"],
                0,
                "",
            ),
            row(
                T4,
                "-m -d of a name without .lz4",
                "lz4",
                &["-m", "-d", "a"],
                &["a"],
                1,
                "File extension doesn't match expected LZ4_EXTENSION (.lz4); will not process file: a\n",
            ),
            row(
                T4,
                "-m -d .lz4",
                "lz4",
                &["-m", "-d", ".lz4"],
                &[".lz4"],
                1,
                "will not process file: .lz4\n",
            ),
            row(
                T4,
                "-m a stdin names stdin.lz4",
                "lz4",
                &["-m", "a", "stdin"],
                &["a"],
                0,
                "",
            )
            .stdin_fx("a"),
            row(
                T4,
                "-m stdin writes stdout",
                "lz4",
                &["-m", "stdin"],
                &[],
                0,
                "",
            )
            .stdin_fx("a"),
            row(T4, "- out", "lz4", &["-", "out"], &[], 0, "").stdin_fx("a"),
            row(
                T4,
                "a stdin names a file",
                "lz4",
                &["a", "stdin"],
                &["a"],
                0,
                "",
            ),
            row(T4, "stdin x", "lz4", &["stdin", "x"], &[], 0, "").stdin_fx("a"),
            row(
                T4,
                "-t b.lz4 out writes nothing",
                "lz4",
                &["-t", "b.lz4", "out"],
                &["b.lz4"],
                0,
                "",
            ),
            row(
                T4,
                "-t -dc writes stdout",
                "lz4",
                &["-t", "-dc", "b.lz4"],
                &["b.lz4"],
                0,
                "",
            ),
            row(
                T4,
                "lz4cat -t writes stdout",
                "lz4cat",
                &["-t", "b.lz4"],
                &["b.lz4"],
                0,
                "",
            ),
            row(
                T4,
                "unlz4 b.lz4 -",
                "unlz4",
                &["b.lz4", "-"],
                &["b.lz4"],
                0,
                "",
            ),
            row(
                T4,
                "a b - writes stdout",
                "lz4",
                &["a", "b", "-"],
                &["a"],
                0,
                "",
            ),
            row(
                T4,
                "a null -c writes stdout",
                "lz4",
                &["a", "null", "-c"],
                &["a"],
                0,
                "",
            ),
            row(
                T4,
                "-- - names a file",
                "lz4",
                &["--", "-"],
                &[],
                1,
                "Compressed filename will be : -.lz4 \n-: No such file or directory \n",
            ),
            row(
                T4,
                "an empty operand",
                "lz4",
                &["", "a"],
                &["a"],
                1,
                ": No such file or directory \n",
            ),
            row(
                T4,
                "x.LZ4 compresses",
                "lz4",
                &["x.LZ4"],
                &[],
                1,
                "Compressed filename will be : x.LZ4.lz4 \n",
            ),
            row(
                T4,
                "-p -c a pauses",
                "lz4",
                &["-p", "-c", "a"],
                &["a"],
                0,
                "Press enter to continue...\n",
            ),
            row(
                T4,
                "--rm -k keeps",
                "lz4",
                &["--rm", "-k", "a"],
                &["a"],
                0,
                "",
            ),
            row(
                T4,
                "-k --rm removes",
                "lz4",
                &["-k", "--rm", "a"],
                &["a"],
                0,
                "",
            ),
            row(
                T4,
                "--rm of standard input",
                "lz4",
                &["-c", "--rm"],
                &[],
                50,
                "Error 50 : Remove error : stdin: No such file or directory \n",
            )
            .stdin_fx("a"),
            row(
                T4,
                "stdout a terminal, a file named",
                "lz4",
                &["a"],
                &["a"],
                0,
                "Compressed filename will be : a.lz4 \n",
            )
            .tty(false, true),
            row(
                T4,
                "stdout a terminal, -m -t",
                "lz4",
                &["-m", "-t", "b.lz4"],
                &["b.lz4"],
                0,
                "",
            )
            .tty(false, true),
            // ---- Task 4: missing, unreadable and unwritable files ----
            row(
                T4,
                "missing input",
                "lz4",
                &["nosuch"],
                &[],
                1,
                "nosuch: No such file or directory \n",
            ),
            row(
                T4,
                "missing input -c",
                "lz4",
                &["-c", "nosuch"],
                &[],
                1,
                "nosuch: No such file or directory \n",
            ),
            row(
                T4,
                "missing .lz4 -d",
                "lz4",
                &["-d", "nosuch.lz4"],
                &[],
                1,
                "nosuch.lz4: No such file or directory \n",
            ),
            row(
                T4,
                "missing .lz4 -dc",
                "lz4",
                &["-dc", "nosuch.lz4"],
                &[],
                1,
                "nosuch.lz4: No such file or directory \n",
            ),
            row(
                T4,
                "missing input -m",
                "lz4",
                &["-m", "nosuch"],
                &[],
                1,
                "nosuch: No such file or directory \n",
            ),
            row(
                T4,
                "unreadable input",
                "lz4",
                &["a"],
                &["a"],
                1,
                "a: Permission denied \n",
            )
            .setup(unreadable_a),
            row(
                T4,
                "unreadable .lz4",
                "lz4",
                &["-d", "b.lz4"],
                &["b.lz4"],
                1,
                "b.lz4: Permission denied \n",
            )
            .setup(unreadable_b),
            row(
                T4,
                "directory input",
                "lz4",
                &["d"],
                &[],
                1,
                "lz4: d is a directory -- ignored \n",
            )
            .setup(mkdir_d),
            row(
                T4,
                "directory input -m",
                "lz4",
                &["-m", "d"],
                &[],
                1,
                "lz4: d is a directory -- ignored \n",
            )
            .setup(mkdir_d),
            row(
                T4,
                "directory input -c",
                "lz4",
                &["-c", "d"],
                &[],
                1,
                "lz4: d is a directory -- ignored \n",
            )
            .setup(mkdir_d),
            row(
                T4,
                "directory named .lz4 -d",
                "lz4",
                &["-d", "d.lz4"],
                &[],
                1,
                "lz4: d.lz4 is a directory -- ignored \n",
            )
            .setup(mkdir_dlz4),
            row(T4, "directory input -r", "lz4", &["-r", "d"], &[], 0, "").setup(dir_with_file),
            row(
                T4,
                "output in a missing directory",
                "lz4",
                &["a", "nodir/out.lz4"],
                &["a"],
                1,
                "nodir/out.lz4: No such file or directory\n",
            ),
            row(
                T4,
                "decode into a missing directory",
                "lz4",
                &["-d", "b.lz4", "nodir/out"],
                &["b.lz4"],
                1,
                "nodir/out: No such file or directory\n",
            ),
            row(
                T4,
                "output in an unwritable directory",
                "lz4",
                &["a", "ro/out.lz4"],
                &["a"],
                1,
                "ro/out.lz4: Permission denied\n",
            )
            .setup(read_only_dir),
            row(
                T4,
                "unwritable output with -f",
                "lz4",
                &["-f", "a", "o"],
                &["a", "o"],
                1,
                "o: Permission denied\n",
            )
            .setup(read_only_o),
            row(
                T4,
                "output is a directory",
                "lz4",
                &["a", "d"],
                &["a"],
                1,
                "d already exists; do you want to overwrite (y/N) ? ",
            )
            .setup(mkdir_d),
            row(
                T4,
                "output is a directory, -f",
                "lz4",
                &["-f", "a", "d"],
                &["a"],
                1,
                "d: Is a directory\n",
            )
            .setup(mkdir_d),
            // ---- Task 4: an existing output and the prompt (R11) ----
            row(
                T4,
                "existing output, -q",
                "lz4",
                &["-q", "a", "a.lz4x"],
                &["a", "a.lz4x"],
                1,
                "a.lz4x already exists; not overwritten  \n",
            ),
            row(
                T4,
                "existing output, stdin /dev/null",
                "lz4",
                &["a", "a.lz4x"],
                &["a", "a.lz4x"],
                1,
                "a.lz4x already exists; do you want to overwrite (y/N) ? ",
            ),
            row(
                T4,
                "existing output, answer n",
                "lz4",
                &["a", "a.lz4x"],
                &["a", "a.lz4x"],
                1,
                "do you want to overwrite (y/N) ? ",
            )
            .stdin(b"n\n"),
            row(
                T4,
                "existing output, answer y",
                "lz4",
                &["a", "a.lz4x"],
                &["a", "a.lz4x"],
                0,
                "do you want to overwrite (y/N) ? ",
            )
            .stdin(b"y\n"),
            row(
                T4,
                "existing output, answer Y",
                "lz4",
                &["a", "a.lz4x"],
                &["a", "a.lz4x"],
                0,
                "do you want to overwrite (y/N) ? ",
            )
            .stdin(b"Y\n"),
            row(
                T4,
                "existing output, EOF",
                "lz4",
                &["a", "a.lz4x"],
                &["a", "a.lz4x"],
                1,
                "not overwritten  \n",
            )
            .stdin(b""),
            row(
                T4,
                "existing output, -f",
                "lz4",
                &["-f", "a", "a.lz4x"],
                &["a", "a.lz4x"],
                0,
                "Compressed 8800 bytes into 110 bytes ==> 1.25%",
            ),
            row(
                T4,
                "decode over an existing output",
                "lz4",
                &["-d", "b.lz4", "a2"],
                &["b.lz4", "a2"],
                1,
                "a2 already exists; do you want to overwrite (y/N) ? ",
            ),
            row(
                T4,
                "decode over, answer y",
                "lz4",
                &["-d", "b.lz4", "a2"],
                &["b.lz4", "a2"],
                0,
                "decoded 8800 bytes",
            )
            .stdin(b"y\n"),
            row(
                T4,
                "decode over, answer n",
                "lz4",
                &["-d", "b.lz4", "a2"],
                &["b.lz4", "a2"],
                1,
                "not overwritten  \n",
            )
            .stdin(b"n\n"),
            row(
                T4,
                "default output exists",
                "lz4",
                &["a"],
                &["a"],
                1,
                "a.lz4 already exists; do you want to overwrite (y/N) ? ",
            )
            .setup(existing_default_output),
            row(
                T4,
                "default output exists, answer y",
                "lz4",
                &["a"],
                &["a"],
                0,
                "do you want to overwrite (y/N) ? ",
            )
            .setup(existing_default_output)
            .stdin(b"y\n"),
            // ---- Task 4: headers and stream shapes, -d / -t / -dc ----
            row(
                T4,
                "unknown header -d",
                "lz4",
                &["-d", "unk_hdr.lz4"],
                &["unk_hdr.lz4"],
                44,
                "Error 44 : Unrecognized header : file cannot be decoded \n",
            ),
            row(
                T4,
                "unknown header -t",
                "lz4",
                &["-t", "unk_hdr.lz4"],
                &["unk_hdr.lz4"],
                44,
                "Error 44 : Unrecognized header : file cannot be decoded \n",
            ),
            row(
                T4,
                "unknown header -dc",
                "lz4",
                &["-dc", "unk_hdr.lz4"],
                &["unk_hdr.lz4"],
                44,
                "Error 44 : Unrecognized header : file cannot be decoded \n",
            ),
            row(
                T4,
                "unknown header lz4cat copies",
                "lz4cat",
                &["unk_hdr.lz4"],
                &["unk_hdr.lz4"],
                0,
                "",
            ),
            row(
                T4,
                "unknown header -dcf copies",
                "lz4",
                &["-dcf", "unk_hdr.lz4"],
                &["unk_hdr.lz4"],
                0,
                "",
            ),
            row(
                T4,
                "not lz4 -dc",
                "lz4",
                &["-dc", "notlz4"],
                &["notlz4"],
                44,
                "Error 44 : Unrecognized header : file cannot be decoded \n",
            ),
            row(
                T4,
                "not lz4 -t",
                "lz4",
                &["-t", "notlz4"],
                &["notlz4"],
                44,
                "Error 44 : Unrecognized header : file cannot be decoded \n",
            ),
            row(
                T4,
                "not lz4 -dfc copies",
                "lz4",
                &["-dfc", "notlz4"],
                &["notlz4"],
                0,
                "",
            ),
            row(
                T4,
                "not lz4 named .lz4 -d",
                "lz4",
                &["-d", "x.lz4"],
                &["x.lz4"],
                44,
                "Error 44 : Unrecognized header : file cannot be decoded \n",
            ),
            row(
                T4,
                "stdin not lz4 -dc",
                "lz4",
                &["-dc"],
                &[],
                44,
                "Error 44 : Unrecognized header : file cannot be decoded \n",
            )
            .stdin(b"junk\n"),
            row(
                T4,
                "stdin not lz4 -t",
                "lz4",
                &["-t"],
                &[],
                44,
                "Error 44 : Unrecognized header : file cannot be decoded \n",
            )
            .stdin(b"junk\n"),
            row(
                T4,
                "stdin empty -t",
                "lz4",
                &["-t"],
                &[],
                0,
                "decoded 0 bytes",
            )
            .stdin(b""),
            row(T4, "stdin empty -dc", "lz4", &["-dc"], &[], 0, "").stdin(b""),
            row(T4, "stdin empty -z", "lz4", &["-z"], &[], 0, "").stdin(b""),
            row(
                T4,
                "empty input file",
                "lz4",
                &["-d", "e.lz4"],
                &["e.lz4"],
                0,
                "decoded 0 bytes",
            ),
            row(
                T4,
                "empty input file -t",
                "lz4",
                &["-t", "e.lz4"],
                &["e.lz4"],
                0,
                "decoded 0 bytes",
            ),
            row(
                T4,
                "frame of nothing -t",
                "lz4",
                &["-t", "empty.lz4"],
                &["empty.lz4"],
                0,
                "decoded 0 bytes",
            ),
            row(
                T4,
                "magic cut short -d",
                "lz4",
                &["-d", "t_magic.lz4"],
                &["t_magic.lz4"],
                40,
                "Error 40 : Unrecognized header : Magic Number unreadable \n",
            ),
            row(
                T4,
                "magic cut short -t",
                "lz4",
                &["-t", "t_magic.lz4"],
                &["t_magic.lz4"],
                40,
                "Error 40 : Unrecognized header : Magic Number unreadable \n",
            ),
            row(
                T4,
                "magic cut short -dc",
                "lz4",
                &["-dc", "t_magic.lz4"],
                &["t_magic.lz4"],
                40,
                "Error 40 : Unrecognized header : Magic Number unreadable \n",
            ),
        ];
        // Truncations: 26 "LZ4F frame decoding could not complete: invalid frame".
        for (name, what) in [
            ("t_hdr.lz4", "header cut at 5"),
            ("t_hdr2.lz4", "header cut at 7"),
            ("t_bsz.lz4", "block size cut"),
            ("t_blk.lz4", "block cut"),
            ("t_crc.lz4", "checksum cut"),
            ("t_bblk.lz4", "block with a checksum cut"),
            ("bad_endmark.lz4", "end mark flipped"),
            ("cs_trunc.lz4", "content size cut"),
            ("dictid.lz4", "dictionary ID without its dictionary"),
            ("g1.lz4", "1 byte of garbage after"),
            ("g3.lz4", "3 bytes of garbage after"),
            ("g4.lz4", "4 bytes of garbage after"),
        ] {
            for (mode, args) in [("-d", ["-d", name]), ("-t", ["-t", name])] {
                let label: &'static str = Box::leak(format!("{what} {mode}").into_boxed_str());
                let names: &'static [&'static str] = Box::leak(vec![name].into_boxed_slice());
                let args: Vec<&'static str> = args.to_vec();
                v.push(row(
                    T4,
                    label,
                    "lz4",
                    &args,
                    names,
                    26,
                    "Error 26 : LZ4F frame decoding could not complete: invalid frame ",
                ));
            }
        }
        // Decompression errors: 34 "Decompression error : ERROR_...".
        for (name, kind) in [
            ("bad_hc.lz4", "ERROR_headerChecksum_invalid"),
            ("bad_bcrc.lz4", "ERROR_blockChecksum_invalid"),
            ("bad_ccrc.lz4", "ERROR_contentChecksum_invalid"),
            ("bad_data.lz4", "ERROR_decompressionFailed"),
            ("g100.lz4", "ERROR_frameType_unknown"),
            ("z.lz4", "ERROR_frameType_unknown"),
            ("good_then_leg.lz4", "ERROR_frameType_unknown"),
            ("v0.lz4", "ERROR_headerVersion_wrong"),
            ("v2.lz4", "ERROR_headerVersion_wrong"),
            ("rsvd_flg.lz4", "ERROR_reservedFlag_set"),
            ("rsvd_bd.lz4", "ERROR_reservedFlag_set"),
            ("bd_size3.lz4", "ERROR_maxBlockSize_invalid"),
            ("bd_size0.lz4", "ERROR_maxBlockSize_invalid"),
            ("blk_too_big.lz4", "ERROR_maxBlockSize_invalid"),
            ("blk_16m.lz4", "ERROR_maxBlockSize_invalid"),
            ("cs_2p63.lz4", "ERROR_frameSize_wrong"),
            ("cs_mismatch.lz4", "ERROR_frameSize_wrong"),
        ] {
            for (mode, args) in [("-d", ["-d", name]), ("-t", ["-t", name])] {
                let label: &'static str =
                    Box::leak(format!("{name} {kind} {mode}").into_boxed_str());
                let names: &'static [&'static str] = Box::leak(vec![name].into_boxed_slice());
                let msg: &'static str =
                    Box::leak(format!("Error 34 : Decompression error : {kind} ").into_boxed_str());
                let args: Vec<&'static str> = args.to_vec();
                v.push(row(T4, label, "lz4", &args, names, 34, msg));
            }
        }
        // The block checksum has its own error name; the fuzz found it.
        v.push(row(
            T4,
            "block checksum word flipped (bc.lz4) -t",
            "lz4",
            &["-t", "bad_bcrc2.lz4"],
            &["bad_bcrc2.lz4"],
            34,
            "ERROR_blockChecksum_invalid",
        ));
        v.extend([
            // Garbage after a stream, partial output kept, concatenation.
            row(T4, "valid frame then 100 bytes -dc", "lz4", &["-dc", "g100.lz4"], &["g100.lz4"], 34, "ERROR_frameType_unknown"),
            row(T4, "lz4cat then 100 bytes", "lz4cat", &["g100.lz4"], &["g100.lz4"], 34, "ERROR_frameType_unknown"),
            row(T4, "block cut -dc keeps what decoded", "lz4", &["-dc", "t_blk.lz4"], &["t_blk.lz4"], 26, "invalid frame"),
            row(T4, "two frames -d", "lz4", &["-d", "two_frames.lz4"], &["two_frames.lz4"], 0, "decoded 17600 bytes"),
            row(T4, "skippable then frame -d", "lz4", &["-d", "skip_then_good.lz4"], &["skip_then_good.lz4"], 0, "decoded 8800 bytes"),
            row(T4, "skippable only -d", "lz4", &["-d", "skip_ok.lz4"], &["skip_ok.lz4"], 0, "decoded 0 bytes"),
            row(T4, "skippable cut inside -t", "lz4", &["-t", "skip_trunc.lz4"], &["skip_trunc.lz4"], 0, "decoded 0 bytes"),
            row(T4, "skippable size cut -t", "lz4", &["-t", "skip_hdr_trunc.lz4"], &["skip_hdr_trunc.lz4"], 42, "Error 42 : Stream error : skippable size unreadable \n"),
            row(T4, "stored block -t", "lz4", &["-t", "blk_uncompressed.lz4"], &["blk_uncompressed.lz4"], 0, "decoded 5 bytes"),
            // ---- Task 4: legacy frames (and the Task 1 review's zero word) ----
            row(T4, "legacy -d", "lz4", &["-d", "leg.lz4"], &["leg.lz4"], 0, "decoded 8800 bytes"),
            row(T4, "legacy then frame -t", "lz4", &["-t", "leg_then_good.lz4"], &["leg_then_good.lz4"], 0, "decoded 17600 bytes"),
            row(T4, "legacy magic only -d", "lz4", &["-d", "legzero.lz4"], &["legzero.lz4"], 64, "Error 64 : Decoding Failed ! Corrupted input detected ! \n"),
            row(T4, "legacy zero word -t", "lz4", &["-t", "legzero.lz4"], &["legzero.lz4"], 64, "Error 64 : Decoding Failed ! Corrupted input detected ! \n"),
            row(T4, "legacy zero word lz4cat", "lz4cat", &["legzero.lz4"], &["legzero.lz4"], 64, "Error 64 : Decoding Failed ! Corrupted input detected ! \n"),
            row(T4, "legacy zero word -dc", "lz4", &["-dc", "legzero.lz4"], &["legzero.lz4"], 64, "Error 64 : Decoding Failed ! Corrupted input detected ! \n"),
            row(T4, "legacy size word cut", "lz4", &["-t", "leg_bsz_trunc.lz4"], &["leg_bsz_trunc.lz4"], 61, "Error 61 : Error: cannot read block size in Legacy format \n"),
            row(T4, "legacy block cut", "lz4", &["-t", "leg_blk_trunc.lz4"], &["leg_blk_trunc.lz4"], 63, "Error 63 : Read error : cannot access compressed block ! \n"),
            row(T4, "legacy block claims 8 MiB+", "lz4", &["-t", "leg_8m.lz4"], &["leg_8m.lz4"], 63, "Error 63 : Read error : cannot access compressed block ! \n"),
            row(T4, "legacy block claims 4 GiB", "lz4", &["-t", "leg_huge.lz4"], &["leg_huge.lz4"], 1, "Stream followed by undecodable data at position 8 \n"),
            row(T4, "legacy block not lz4", "lz4", &["-t", "leg_bad.lz4"], &["leg_bad.lz4"], 64, "Error 64 : Decoding Failed ! Corrupted input detected ! \n"),
            row(T4, "legacy then 3 bytes", "lz4", &["-t", "leg_garbage.lz4"], &["leg_garbage.lz4"], 61, "Error 61 : Error: cannot read block size in Legacy format \n"),
            row(T4, "legacy then 100 bytes", "lz4", &["-t", "leg_garbage100.lz4"], &["leg_garbage100.lz4"], 1, "Stream followed by undecodable data at position 103 \n"),
            row(T4, "legacy then zeros", "lz4", &["-t", "leg_zeros.lz4"], &["leg_zeros.lz4"], 64, "Error 64 : Decoding Failed ! Corrupted input detected ! \n"),
            // ---- Task 4: dictionaries ----
            row(T4, "-D missing file", "lz4", &["-D", "nosuchdict", "a", "x.lz4"], &["a"], 27, "nosuchdict: No such file or directory \nError 27 : Dictionary error : could not open dictionary file \n"),
            row(T4, "-D missing file -d", "lz4", &["-D", "nosuchdict", "-d", "b.lz4"], &["b.lz4"], 27, "Error 27 : Dictionary error : could not open dictionary file \n"),
            row(T4, "-D is a directory", "lz4", &["-D", "d", "a", "x.lz4"], &["a"], 27, "lz4: d is a directory -- ignored \nError 27 : Dictionary error : could not open dictionary file \n")
                .setup(mkdir_d),
            row(T4, "-D empty file", "lz4", &["-D", "empty", "a", "x.lz4"], &["a", "empty"], 0, "Compressed 8800 bytes into 108 bytes ==> 1.23%"),
            row(T4, "-D right dictionary -d", "lz4", &["-d", "-D", "dict", "dict_b.lz4", "o"], &["dict", "dict_b.lz4"], 0, "decoded 8800 bytes"),
            row(T4, "-D glued -D<file>", "lz4", &["-Ddict", "a", "x.lz4"], &["dict", "a"], 0, "Compressed 8800 bytes into 63 bytes ==> 0.72%"),
            row(T4, "-D wrong dictionary -d", "lz4", &["-d", "-D", "dict2", "dict_b.lz4", "o"], &["dict2", "dict_b.lz4"], 34, "Error 34 : Decompression error : ERROR_contentChecksum_invalid \n"),
            row(T4, "-D wrong dictionary -t", "lz4", &["-t", "-D", "dict2", "dict_b.lz4"], &["dict2", "dict_b.lz4"], 34, "ERROR_contentChecksum_invalid"),
            row(T4, "no dictionary where one was used", "lz4", &["-d", "dict_b.lz4", "o"], &["dict_b.lz4"], 34, "Error 34 : Decompression error : ERROR_decompressionFailed \n"),
            // ---- Task 4: several files, --rm, -m ----
            row(T4, "-m with a missing name", "lz4", &["-m", "a", "nosuch", "notlz4"], &["a", "notlz4"], 1, "nosuch: No such file or directory \n"),
            row(T4, "-dm with a corrupt middle file", "lz4", &["-d", "-m", "b.lz4", "bad_data.lz4", "g1.lz4"], &["b.lz4", "bad_data.lz4", "g1.lz4"], 34, "Error 34 : Decompression error : ERROR_decompressionFailed "),
            row(T4, "-tm continues past a good file", "lz4", &["-tm", "b.lz4", "bad_data.lz4", "leg.lz4"], &["b.lz4", "bad_data.lz4", "leg.lz4"], 34, "ERROR_decompressionFailed"),
            row(T4, "-tm corrupt first", "lz4", &["-tm", "bad_hc.lz4", "b.lz4"], &["bad_hc.lz4", "b.lz4"], 34, "ERROR_headerChecksum_invalid"),
            row(T4, "--rm after a failed decode keeps the source", "lz4", &["-d", "--rm", "bad_data.lz4"], &["bad_data.lz4"], 34, "ERROR_decompressionFailed"),
            row(T4, "--rm with -t removes the source", "lz4", &["-t", "--rm", "b.lz4"], &["b.lz4"], 0, "decoded 8800 bytes"),
            row(T4, "--rm after a good decode", "lz4", &["-d", "--rm", "b.lz4"], &["b.lz4"], 0, "decoded 8800 bytes"),
            row(T4, "--rm -c keeps nothing to remove", "lz4", &["-c", "--rm", "a"], &["a"], 0, ""),
            row(T4, "lz4 of a .lz4 name decodes", "lz4", &["b.lz4"], &["b.lz4"], 0, "decoded 8800 bytes"),
            row(T4, "lz4 -z of a .lz4 name compresses", "lz4", &["-z", "b.lz4"], &["b.lz4"], 0, "Compressed 110 bytes into 100 bytes ==> 90.91%"),
            row(T4, "unlz4 of a .lz4 name", "unlz4", &["b.lz4"], &["b.lz4"], 0, "decoded 8800 bytes"),
            row(T4, "-B with no number takes none", "lz4", &["-B", "a"], &["a"], 0, "Compressed 8800 bytes into 110 bytes ==> 1.25%"),
            row(T4, "-B 7: 7 is a file name", "lz4", &["-B", "7", "a"], &["a"], 1, "7: No such file or directory \n"),
            row(T4, "level 13 is 12", "lz4", &["-13", "a"], &["a"], 0, "Compressed 8800 bytes into 107 bytes ==> 1.22%"),
            row(T4, "level 99 is 12", "lz4", &["-99", "a"], &["a"], 0, "Compressed 8800 bytes into 107 bytes ==> 1.22%"),
            row(T4, "--fast=99999999999 saturates", "lz4", &["--fast=99999999999", "a"], &["a"], 0, "Compressed 8800 bytes into 8819 bytes ==> 100.22%"),
            row(T4, "-m with no names compresses stdin", "lz4", &["-m", "-c"], &[], 0, "").stdin(&text()),
            // ---- Task 4: standard streams and a terminal ----
            row(T4, "stdin a console", "lz4", &[], &[], 1, "refusing to read from a console\n").tty(true, true),
            row(T4, "stdin a console, -d", "lz4", &["-d"], &[], 1, "refusing to read from a console\n").tty(true, true),
            row(T4, "stdin a console, lz4cat", "lz4cat", &[], &[], 1, "refusing to read from a console\n").tty(true, true),
            row(T4, "stdin a console, name -", "lz4", &["-dc", "-"], &[], 1, "refusing to read from a console\n").tty(true, true),
            row(T4, "stdout a console, name -", "lz4", &["a", "-"], &["a"], 1, "refusing to write to console without -c \n").tty(false, true),
            row(T4, "stdout a console, stdin data", "lz4", &[], &[], 1, "refusing to write to console without -c \n")
                .stdin(&text())
                .tty(false, true),
            row(T4, "stdout a console, decode stdin", "lz4", &["-d"], &[], 1, "refusing to write to console without -c \n")
                .stdin_fx("b.lz4")
                .tty(false, true),
            row(T4, "stdout a console, file in: writes FILE.lz4", "lz4", &["a"], &["a"], 0, "Compressed filename will be : a.lz4 ")
                .tty(false, true),
            row(T4, "stdout a pipe, file in: writes FILE.lz4", "lz4", &["a"], &["a"], 0, "Compressed filename will be : a.lz4 "),
            // ---- Task 5: --list ----
            row(T5, "--list on stdin", "lz4", &["--list"], &[], 0, "").stdin_fx("b.lz4"),
            row(T5, "--list on empty stdin", "lz4", &["--list"], &[], 0, "").stdin(b""),
            row(T5, "--list a frame", "lz4", &["--list", "b.lz4"], &["b.lz4"], 0, ""),
            row(T5, "--list a legacy frame", "lz4", &["--list", "leg.lz4"], &["leg.lz4"], 0, ""),
            row(T5, "--list a legacy magic only", "lz4", &["--list", "legzero.lz4"], &["legzero.lz4"], 0, ""),
            row(T5, "--list a frame of nothing", "lz4", &["--list", "empty.lz4"], &["empty.lz4"], 0, ""),
            row(T5, "--list a cut block", "lz4", &["--list", "t_blk.lz4"], &["t_blk.lz4"], 0, ""),
            row(T5, "--list not lz4", "lz4", &["--list", "notlz4"], &["notlz4"], 1, "lz4: notlz4: File format not recognized \n"),
            row(T5, "--list a cut header", "lz4", &["--list", "t_hdr.lz4"], &["t_hdr.lz4"], 1, "lz4: t_hdr.lz4: File format not recognized \n"),
            row(T5, "--list a bad header checksum", "lz4", &["--list", "bad_hc.lz4"], &["bad_hc.lz4"], 1, "lz4: bad_hc.lz4: File format not recognized \n"),
            row(T5, "--list an empty file", "lz4", &["--list", "e.lz4"], &["e.lz4"], 1, "lz4: e.lz4: File format not recognized \n"),
            row(T5, "--list frame + 3 bytes", "lz4", &["--list", "g3.lz4"], &["g3.lz4"], 40, "Error 40 : Unrecognized header : Magic Number unreadable \n"),
            row(T5, "--list frame + 100 bytes", "lz4", &["--list", "g100.lz4"], &["g100.lz4"], 1, "lz4: g100.lz4: File format not recognized \n"),
            row(T5, "--list a missing file", "lz4", &["--list", "nosuch.lz4"], &[], 1, "lz4: nosuch.lz4 is not a regular file \n"),
            row(T5, "--list a directory", "lz4", &["--list", "d"], &[], 1, "lz4: d is not a regular file \n")
                .setup(mkdir_d),
            row(T5, "--list -v two frames", "lz4", &["--list", "-v", "two_frames.lz4"], &["two_frames.lz4"], 0, ""),
            row(T5, "--list -v skippable then frame", "lz4", &["--list", "-v", "skip_then_good.lz4"], &["skip_then_good.lz4"], 0, ""),
            row(T5, "--list -v legacy then frame", "lz4", &["--list", "-v", "leg_then_good.lz4"], &["leg_then_good.lz4"], 0, ""),
            // ---- Task 6: -v and the progress display ----
            row(T6, "-v compress", "lz4", &["-v", "-T3", "a", "x.lz4"], &["a"], 0, "Using 3 threads for compression \n"),
            row(T6, "-v decode", "lz4", &["-v", "-d", "b.lz4", "bo"], &["b.lz4"], 0, "decoded 8800 bytes"),
            row(T6, "-v test", "lz4", &["-v", "-t", "b.lz4"], &["b.lz4"], 0, "decoded 8800 bytes"),
            row(T6, "-vv compress", "lz4", &["-vv", "-T1", "a", "y.lz4"], &["a"], 0, "_POSIX_VERSION defined: "),
            row(T6, "-vvv compress", "lz4", &["-vvv", "-T1", "a", "w.lz4"], &["a"], 0, "Done in "),
            row(T6, "-v -m compress", "lz4", &["-v", "-m", "-T1", "a"], &["a"], 0, "Done in "),
            row(T6, "-vv of a missing file prints Done in", "lz4", &["-vv", "-d", "z.lz4", "zo"], &[], 1, "z.lz4: No such file or directory \n"),
            row(T6, "-V", "lz4", &["-V"], &[], 0, ""),
        ]);
        v
    }

    // ---- running ----

    /// Case for `r`. The input files and, when `r` has none of its own,
    /// the reference's own encoder keep the tree small and deterministic.
    fn case(r: &Row) -> Case<'static> {
        let files: Vec<(&'static str, Vec<u8>)> = r.files.iter().map(|n| (*n, fx(n))).collect();
        Case {
            name: r.name,
            args: r.args.clone(),
            files,
            stdin: r.stdin.clone(),
            tty_stdin: r.tty_stdin,
            tty_stdout: r.tty_stdout,
            env: vec![("LC_ALL", "C")],
            compare_output_bytes: EXACT,
            expect_stdout_plain: None,
            setup: r.setup,
            roundtrip: Roundtrip::Lz4 { ref_lz4: ref_lz4() },
        }
    }

    /// Each side's banner, exactly, becomes `<banner>`: a banner where the
    /// other side has none, or one that is not exactly the expected one,
    /// still differs.
    fn mask_banners(r: &mut Run, s: &mut Run) {
        let ours = our_banner();
        let mask = |t: &str, banner: &str| t.replace(banner, "<banner>\n");
        r.stderr = mask(&r.stderr, REFERENCE_BANNER);
        s.stderr = mask(&s.stderr, &ours);
        if let Ok(t) = std::str::from_utf8(&r.stdout) {
            r.stdout = mask(t, REFERENCE_BANNER).into_bytes();
        }
        if let Ok(t) = std::str::from_utf8(&s.stdout) {
            s.stdout = mask(t, &ours).into_bytes();
        }
    }

    /// One case against the reference and stuffr, with this suite's
    /// normalisations; false when the reference is absent.
    fn compare(c: &Case) -> bool {
        let Some(dir) = lz4_dir() else { return false };
        let Some(mut r) = reference(dir, c) else {
            return false;
        };
        let mut s = stuffr_as(c);
        mask_banners(&mut r, &mut s);
        // Spec deviation 2: refreshes, timing fields, thread count.
        r.stderr = normalise_lz4_progress(&r.stderr);
        s.stderr = normalise_lz4_progress(&s.stderr);
        // The reference's own race over how much a failed decode wrote.
        tolerate_lz4_partial_output(c, &mut r, &mut s);
        assert_same(c, &r, &s);
        true
    }

    /// Every row of `task` against the reference and stuffr.
    fn check_task(task: &str) {
        let rows: Vec<Row> = rows().into_iter().filter(|r| r.task == task).collect();
        assert!(!rows.is_empty(), "no rows for {task}");
        let cases: Vec<Case> = rows.iter().map(case).collect();
        run_group(task, &cases, Skipped::none(), &compare);
    }

    #[test]
    fn task3_rows_match_the_reference() {
        check_task("Task 3");
    }

    /// `LZ4_CLEVEL` and `LZ4_NBWORKERS` (lz4.1, "Environment Variables"),
    /// probed 2026-10-16: a value not starting with a digit is warned about
    /// before the arguments are read (so `-qq` cannot silence it), under
    /// every name, `LZ4_CLEVEL`'s first; anything after the digits is
    /// ignored. Each case ends at `-V`, `-h` or a usage error, before any
    /// file is touched.
    #[test]
    fn environment_variables_match_the_reference() {
        let mut cases = Vec::new();
        for var in ["LZ4_CLEVEL", "LZ4_NBWORKERS"] {
            for val in ["x", "-1", "", " 4", "3x", "1K", "4294967297", "201"] {
                for args in [&["-V"][..], &["-qq", "-V"], &["--bogus"]] {
                    let mut c = case(&row("Task 3", "env", "lz4", args, &[], 0, ""));
                    c.env.push((var, val));
                    cases.push(c);
                }
            }
        }
        for name in ["unlz4", "lz4cat", "lz4c"] {
            let mut c = case(&row("Task 3", "env", name, &["-h"], &[], 0, ""));
            c.env.push(("LZ4_CLEVEL", "x"));
            cases.push(c);
        }
        let mut both = case(&row("Task 3", "env", "lz4", &["-V"], &[], 0, ""));
        both.env
            .extend([("LZ4_NBWORKERS", "y"), ("LZ4_CLEVEL", "x")]);
        cases.push(both);
        run_group("environment", &cases, Skipped::none(), &compare);
    }

    /// Spec deviation 5: `-b#`, `-e#` and `-i#` are refused once the
    /// command line has parsed (the reference runs its benchmark, or
    /// ignores `-e`/`-i` alone). A usage error, `-h` and `-V` answer first,
    /// as the reference's do (the Task 3 rows compare those).
    #[test]
    fn benchmark_options_are_refused() {
        let dir = ScratchDir::at(
            std::env::temp_dir().join(format!("stuffr-lz4-bench-{}", std::process::id())),
        );
        fs::create_dir_all(&*dir).unwrap();
        fs::write(dir.join("a"), text()).unwrap();
        let link = dir.join("lz4");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
        for args in [
            &["-b"][..],
            &["-b3", "a"],
            &["-c", "-e3", "a"],
            &["-i1", "-c", "a"],
            &["-b", "-d", "a"],
            &["-T1i"],
        ] {
            let o = std::process::Command::new(&link)
                .args(args)
                .current_dir(&*dir)
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
            assert_eq!(
                (o.status.code(), o.stdout.as_slice(), o.stderr.as_slice()),
                (
                    Some(1),
                    &b""[..],
                    &b"Benchmark mode is not available in this build (stuffr)\n"[..]
                ),
                "{args:?}"
            );
        }
        // `-qq` silences it, as it silences every error.
        let o = std::process::Command::new(&link)
            .args(["-qq", "-b"])
            .current_dir(&*dir)
            .output()
            .unwrap();
        assert_eq!((o.status.code(), o.stderr.len()), (Some(1), 0));
    }

    #[test]
    #[ignore = "Task 4"]
    fn task4_rows_match_the_reference() {
        check_task("Task 4");
    }

    #[test]
    #[ignore = "Task 5"]
    fn task5_rows_match_the_reference() {
        check_task("Task 5");
    }

    #[test]
    #[ignore = "Task 6"]
    fn task6_rows_match_the_reference() {
        check_task("Task 6");
    }

    /// The table, run on the reference alone (always on): every row's exit
    /// code and message are what Task 2 recorded, so a changed reference or
    /// a wrong transcription fails here, not in the task that enables the
    /// row.
    #[test]
    fn the_recorded_table_holds_on_the_reference() {
        let Some(dir) = lz4_dir() else { return };
        let rows = rows();
        let mut bad = Vec::new();
        for r in &rows {
            let c = case(r);
            let Some(run) = reference(dir, &c) else {
                return;
            };
            // The refresh of a failing decode lands anywhere in the message
            // (the reference's own race): judge the normalised text.
            let raw = run.stderr.replace(REFERENCE_BANNER, "");
            let stderr = normalise_lz4_progress(&raw);
            if run.code != r.code || !(raw.contains(r.msg) || stderr.contains(r.msg)) {
                bad.push(format!(
                    "{} ({} {:?}): recorded exit {} with {:?}; the reference gave exit {} and {:?}",
                    r.label, r.name, r.args, r.code, r.msg, run.code, run.stderr
                ));
            }
        }
        println!("{} rows on the reference", rows.len());
        assert!(
            bad.is_empty(),
            "{} rows differ:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }

    /// The exit codes the reference produced over every row and the fuzz
    /// below: the set Task 8's fuzz oracle accepts under the lz4 names.
    /// Probed 2026-10-16 over the rows and over ~3000 corruptions and cuts
    /// of ten frames (`-t`, `-dc`, `--list`).
    ///
    /// Task 3 added 50: `lz4 -c --rm` on standard input is `Error 50 :
    /// Remove error : stdin: No such file or directory` (probed 2026-10-16).
    const EXIT_CODES: [i32; 15] = [0, 1, 26, 27, 34, 38, 40, 42, 43, 44, 50, 61, 63, 64, 70];

    #[test]
    fn every_recorded_code_is_in_the_exit_set() {
        for r in rows() {
            assert!(
                EXIT_CODES.contains(&r.code),
                "{}: {} is not in the recorded exit set",
                r.label,
                r.code
            );
        }
    }

    #[test]
    fn the_xxhash_helper_matches_a_real_header() {
        // `lz4 -c` writes FLG 0x64, BD 0x40, HC 0xa7 for a default frame.
        assert_eq!(
            header(0x64, 0x40, &[]),
            [0x04, 0x22, 0x4d, 0x18, 0x64, 0x40, 0xa7]
        );
        // Fixtures built by hand are accepted by the reference where they
        // should be: a stored block with a correct content checksum.
        let Some(dir) = lz4_dir() else { return };
        let c = Case {
            name: "lz4",
            args: vec!["-dc", "s.lz4"],
            files: vec![("s.lz4", fx("blk_uncompressed.lz4"))],
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![],
            compare_output_bytes: true,
            expect_stdout_plain: None,
            setup: None,
            roundtrip: Roundtrip::Lz4 { ref_lz4: ref_lz4() },
        };
        let r = reference(dir, &c).unwrap();
        assert_eq!(
            (r.code, r.stdout.as_slice()),
            (0, &b"hello"[..]),
            "{}",
            r.stderr
        );
    }

    // ---- interrupts (R3) ----
    //
    // Probed 2026-10-16 with the harness's `interrupt()` driver (default
    // dispositions): lz4 installs no handler. SIGINT, SIGTERM and SIGHUP
    // each kill it by the signal itself (status = the signal, no exit
    // code), stderr holds only the progress refresh already drawn
    // (`\rRead : 0 MiB   ==> inf%   `), and the partial output stays under
    // its name (`out.lz4` 4 MiB..200 MiB, `out` for a decode), never
    // removed. R3 therefore maps onto NO `host.rs` answer: the default
    // disposition, no cleanup, no temporary file (lz4 writes the named
    // output directly).

    /// SIGINT, SIGTERM and SIGHUP during `lz4 -12 -T1 big out.lz4` and
    /// `unlz4 big.lz4 out`: both die by the signal and leave the partial
    /// output.
    #[test]
    #[ignore = "Task 4"]
    fn an_interrupt_leaves_the_partial_output_and_dies_by_the_signal() {
        use interrupt::*;
        let _serial = interrupt_lock();
        let Some(dir) = lz4_dir() else { return };
        let tag = std::process::id();
        let ref_dir =
            ScratchDir::at(std::env::temp_dir().join(format!("stuffr-lz4-int-ref-{tag}")));
        let our_dir = ScratchDir::at(std::env::temp_dir().join(format!("stuffr-lz4-int-{tag}")));
        let stuffr = Path::new(env!("CARGO_BIN_EXE_stuffr"));
        let plain = |mib: usize| big_input(mib).to_vec();
        let packed = |mib: usize| made(&["-1", "-q", "-c"], big_input(fast_size(mib)));
        type Job<'a> = (
            &'a str,
            &'a [&'a str],
            &'a str,
            &'a str,
            &'a dyn Fn(usize) -> Vec<u8>,
        );
        let jobs: [Job; 2] = [
            (
                "lz4",
                &["-12", "-T1", "big", "out.lz4"],
                "big",
                "out.lz4",
                &plain,
            ),
            ("unlz4", &["big.lz4", "out"], "big.lz4", "out", &packed),
        ];
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            for (name, args, input, out, make) in &jobs {
                let ours = interrupt_with_input(
                    stuffr,
                    name,
                    args,
                    &our_dir,
                    input,
                    make,
                    Inherit::Default,
                    sig,
                    &has_data(&our_dir, &|n| n == *out),
                )
                .expect("stuffr cannot hang: it panics");
                let Some(theirs) = interrupt_with_input(
                    &Path::new(dir).join("lz4"),
                    name,
                    args,
                    &ref_dir,
                    input,
                    make,
                    Inherit::Default,
                    sig,
                    &has_data(&ref_dir, &|n| n == *out),
                ) else {
                    continue;
                };
                assert!(
                    killed_by(&theirs, sig),
                    "reference {name}: {:?}",
                    theirs.status
                );
                assert!(
                    theirs.left.contains(&(*out).to_string()),
                    "reference {name} left {:?}",
                    theirs.left
                );
                assert!(killed_by(&ours, sig), "stuffr {name}: {:?}", ours.status);
                assert_eq!(ours.left, theirs.left, "{name} signal {sig}: what was left");
                // Whether the first refresh was drawn before the signal
                // depends on timing (two runs of the reference differ), so
                // each side's stderr is either nothing or one refresh.
                for (who, run) in [("stuffr", &ours), ("reference", &theirs)] {
                    let e = normalise_lz4_progress(&String::from_utf8_lossy(&run.stderr));
                    assert!(
                        e.is_empty() || e == "\r<progress>",
                        "{who} {name} signal {sig}: stderr {e:?}"
                    );
                }
            }
        }
    }

    // ---- a closed pipe ----

    /// `lz4cat big.lz4` and `lz4 -c big` into a pipe closed after one byte,
    /// SIGPIPE ignored in both children (what stuffr's runtime does to
    /// itself): the same message and exit code, 70 for a decode and 38 for
    /// a compress. With a default SIGPIPE the reference dies by the signal
    /// (rc -13), sometimes after printing the message; not compared.
    #[test]
    #[ignore = "Task 4"]
    fn closed_pipe_with_sigpipe_ignored() {
        use interrupt::big_input;
        use std::io::Read;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        let Some(dir) = lz4_dir() else { return };
        let work = ScratchDir::at(
            std::env::temp_dir().join(format!("stuffr-lz4-pipe-{}", std::process::id())),
        );
        fs::create_dir_all(&*work).unwrap();
        let big = big_input(48).to_vec();
        fs::write(work.join("big"), &big).unwrap();
        fs::write(work.join("big.lz4"), made(&["-1", "-q", "-c"], &big)).unwrap();
        let run = |exe: &Path, name: &str, args: &[&str]| -> (Option<i32>, String) {
            let mut cmd = Command::new(exe);
            cmd.arg0(name)
                .args(args)
                .current_dir(&*work)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            // SAFETY: only async-signal-safe `signal` between fork and exec.
            unsafe {
                cmd.pre_exec(|| {
                    libc::signal(libc::SIGPIPE, libc::SIG_IGN);
                    Ok(())
                });
            }
            let mut child = spawn(&mut cmd).expect("spawn");
            let mut one = [0u8; 1];
            child.stdout.take().unwrap().read_exact(&mut one).unwrap();
            let out = child.wait_with_output().unwrap();
            (
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            )
        };
        let stuffr = Path::new(env!("CARGO_BIN_EXE_stuffr"));
        let reference = Path::new(dir).join("lz4");
        for (name, args, code, msg) in [
            (
                "lz4cat",
                &["big.lz4"][..],
                70,
                "Error 70 : Write error : cannot write decoded block \n",
            ),
            (
                "lz4",
                &["-T1", "-c", "big"][..],
                38,
                "Error 38 : Write error : cannot write compressed block \n",
            ),
        ] {
            let theirs = run(&reference, name, args);
            assert_eq!(theirs.0, Some(code), "reference {name}: {:?}", theirs.1);
            assert_eq!(theirs.1, msg);
            let ours = run(stuffr, name, args);
            assert_eq!(ours, theirs, "{name}");
        }
    }
}
