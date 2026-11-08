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
//! reference's own race (`tolerate_lz4_partial_output`); the banner (`-V`,
//! `-v`'s welcome line), which names stuffr (spec deviation 1; masked
//! exactly), and deviation 2's refreshes, timing fields and thread count
//! (`normalise_lz4_progress`).
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

    const REFERENCE_BANNER: &str = "*** lz4 v1.11.0 64-bit multithread, by Yann Collet ***\n";

    /// Spec deviation 1: stuffr's banner.
    fn our_banner() -> String {
        format!(
            "*** lz4 v1.11.0 64-bit multithread (stuffr {}), by Yann Collet ***\n",
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
                // Removed on drop, a panic inside `made` included.
                let dir = ScratchDir::unique("lz4-dict");
                fs::create_dir_all(&*dir).unwrap();
                let path = dir.join("dict");
                fs::write(&path, fx("dict")).unwrap();
                made(&["-c", "-q", "-D", path.to_str().unwrap()], &text())
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
            // A file named `stdin` (`--list stdin` lists it).
            "stdin" => good(),
            // `--list` (Task 5): the reference's own encoder with a content
            // size, block checksums, linked blocks, 64 KiB blocks, no
            // checksums; and hand-made shapes (header-only, a magic number
            // alone, hostile sizes).
            "cs.lz4" => made(&["-c", "-q", "--content-size"], &text()),
            "bx.lz4" => made(&["-c", "-q", "-BX"], &text()),
            "bd.lz4" => made(&["-c", "-q", "-BD"], &text()),
            "b4.lz4" => made(&["-c", "-q", "-B4"], &text()),
            "nocrc.lz4" => made(&["-c", "-q", "--no-crc"], &text()),
            "big_blocks.lz4" => made(&["-c", "-q", "-B7", "--content-size"], &text()),
            "dict_cs.lz4" => {
                // Removed on drop, a panic inside `made` included.
                let dir = ScratchDir::unique("lz4-dictcs");
                fs::create_dir_all(&*dir).unwrap();
                let path = dir.join("dict");
                fs::write(&path, fx("dict")).unwrap();
                made(
                    &["-c", "-q", "--content-size", "-D", path.to_str().unwrap()],
                    &text(),
                )
            }
            "cs_twice.lz4" => cat(&[&fx("cs.lz4"), &fx("cs.lz4")]),
            "cs_then_plain.lz4" => cat(&[&fx("cs.lz4"), &good()]),
            "bd_then_b4.lz4" => cat(&[&fx("bd.lz4"), &fx("b4.lz4")]),
            "cs_then_skip.lz4" => cat(&[&fx("cs.lz4"), &fx("skip_ok.lz4")]),
            "leg_twice.lz4" => cat(&[&legacy(), &legacy()]),
            "skip_then_leg.lz4" => cat(&[&fx("skip_ok.lz4"), &legacy()]),
            "magic_only.lz4" => vec![0x04, 0x22, 0x4d, 0x18],
            "hdr_only.lz4" => header(0x64, 0x70, &[]),
            "hdr_plus1.lz4" => cat(&[&header(0x64, 0x70, &[]), b"z"]),
            "hdr_cs_only.lz4" => header(0x6c, 0x40, &5u64.to_le_bytes()),
            "hdr_cs_cut.lz4" => header(0x6c, 0x40, &5u64.to_le_bytes())[..6].to_vec(),
            "hdr_cut6.lz4" => header(0x64, 0x70, &[])[..6].to_vec(),
            "dictid_cs.lz4" => cat(&[
                &header(0x6d, 0x40, &cat(&[&7u64.to_le_bytes(), &le32(0x1234_5678)])),
                &le32(0x8000_0003),
                b"abc",
                &end,
                &le32(0),
            ]),
            "skip_4g.lz4" => cat(&[&[0x50, 0x2a, 0x4d, 0x18], &le32(0xffff_ffff), b"ab"]),
            "skip_size_cut.lz4" => cat(&[&[0x50, 0x2a, 0x4d, 0x18], &[1, 0]]),
            "blk_2g.lz4" => cat(&[&header(0x64, 0x40, &[]), &le32(0x7fff_ffff), b"ab"]),
            "frame_tail1.lz4" => cat(&[&good(), b"A"]),
            "frame_zero4.lz4" => cat(&[&good(), &[0u8; 4]]),
            "leg_magic_only.lz4" => LEGACY.to_vec(),
            "leg_magics.lz4" => cat(&[&LEGACY, &LEGACY]),
            "leg_zero_blocks.lz4" => cat(&[&LEGACY, &le32(0), &le32(0), &le32(0)]),
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

    fn link_to_b(w: &Path) {
        std::os::unix::fs::symlink("b.lz4", w.join("ln.lz4")).unwrap();
    }
    /// A directory `d` holding two `.lz4` files and a subdirectory with one.
    fn dir_with_lz4(w: &Path) {
        mkdir_d(w);
        fs::write(w.join("d/x.lz4"), fx("b.lz4")).unwrap();
        fs::write(w.join("d/y.lz4"), fx("cs.lz4")).unwrap();
        fs::create_dir(w.join("d/sub")).unwrap();
        fs::write(w.join("d/sub/z.lz4"), fx("leg.lz4")).unwrap();
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
            // probe: `-e#` and `-i#` change nothing outside `-b` (0.15.1).
            row(
                T3,
                "-e3 alone is ignored",
                "lz4",
                &["-e3", "-f", "a", "a.lz4"],
                &["a"],
                0,
                "",
            ),
            row(
                T3,
                "-i3 alone is ignored",
                "lz4",
                &["-i3", "-f", "a", "a.lz4"],
                &["a"],
                0,
                "",
            ),
            row(
                T3,
                "-e3 -i2 alone are ignored",
                "lz4",
                &["-e3", "-i2", "-f", "a", "a.lz4"],
                &["a"],
                0,
                "",
            ),
            row(
                T3,
                "-e without a number",
                "lz4",
                &["-e", "-f", "a", "a.lz4"],
                &["a"],
                0,
                "",
            ),
            row(
                T3,
                "-i without a number",
                "lz4",
                &["-i", "-f", "a", "a.lz4"],
                &["a"],
                0,
                "",
            ),
            row(
                T3,
                "-e99 is ignored",
                "lz4",
                &["-e99", "-f", "a", "a.lz4"],
                &["a"],
                0,
                "",
            ),
            row(
                T3,
                "-i0 is ignored",
                "lz4",
                &["-i0", "-f", "a", "a.lz4"],
                &["a"],
                0,
                "",
            ),
            row(
                T3,
                "-9e3 keeps -9",
                "lz4",
                &["-9e3", "-f", "a", "a.lz4"],
                &["a"],
                0,
                "",
            ),
            row(
                T3,
                "-e3d decompresses",
                "lz4",
                &["-e3d", "-f", "b.lz4", "bo"],
                &["b.lz4"],
                0,
                "",
            ),
            row(
                T3,
                "-e3 -d decompresses",
                "lz4",
                &["-e3", "-d", "-f", "b.lz4", "bo"],
                &["b.lz4"],
                0,
                "",
            ),
            row(
                T3,
                "-i3 -t tests",
                "lz4",
                &["-i3", "-t", "b.lz4"],
                &["b.lz4"],
                0,
                "",
            ),
            row(
                T3,
                "-e3 --list lists",
                "lz4",
                &["-e3", "--list", "b.lz4"],
                &["b.lz4"],
                0,
                "",
            ),
            row(
                T3,
                "-e3 -c writes stdout",
                "lz4",
                &["-e3", "-c", "a"],
                &["a"],
                0,
                "",
            ),
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
            // ---- Task 5, part 2: every shape the walker meets, at every
            // verbosity (the compact table, `-v`, `-vv`) ----
            row(T5, "--list a content size", "lz4", &["--list", "cs.lz4"], &["cs.lz4"], 0, ""),
            row(T5, "--list -v a content size", "lz4", &["--list", "-v", "cs.lz4"], &["cs.lz4"], 0, ""),
            row(T5, "--list -BX", "lz4", &["--list", "bx.lz4"], &["bx.lz4"], 0, ""),
            row(T5, "--list -v -BX", "lz4", &["--list", "-v", "bx.lz4"], &["bx.lz4"], 0, ""),
            row(T5, "--list -BD", "lz4", &["--list", "bd.lz4"], &["bd.lz4"], 0, ""),
            row(T5, "--list -v -BD", "lz4", &["--list", "-v", "bd.lz4"], &["bd.lz4"], 0, ""),
            row(T5, "--list -v -B4", "lz4", &["--list", "-v", "b4.lz4"], &["b4.lz4"], 0, ""),
            row(T5, "--list -v --no-crc", "lz4", &["--list", "-v", "nocrc.lz4"], &["nocrc.lz4"], 0, ""),
            row(T5, "--list -B7 and a content size", "lz4", &["--list", "big_blocks.lz4"], &["big_blocks.lz4"], 0, ""),
            row(T5, "--list -D and a content size", "lz4", &["--list", "dict_cs.lz4"], &["dict_cs.lz4"], 0, ""),
            row(T5, "--list -v -D and a content size", "lz4", &["--list", "-v", "dict_cs.lz4"], &["dict_cs.lz4"], 0, ""),
            row(T5, "--list -D (the CLI writes no dictionary ID)", "lz4", &["--list", "dict_b.lz4"], &["dict_b.lz4"], 0, ""),
            row(T5, "--list a dictionary ID with a content size", "lz4", &["--list", "-v", "dictid_cs.lz4"], &["dictid_cs.lz4"], 0, ""),
            row(T5, "--list a dictionary ID, no content size", "lz4", &["--list", "dictid.lz4"], &["dictid.lz4"], 1, "File format not recognized"),
            row(T5, "--list two frames with sizes", "lz4", &["--list", "cs_twice.lz4"], &["cs_twice.lz4"], 0, ""),
            row(T5, "--list -v two frames with sizes", "lz4", &["--list", "-v", "cs_twice.lz4"], &["cs_twice.lz4"], 0, ""),
            row(T5, "--list a size, then none", "lz4", &["--list", "cs_then_plain.lz4"], &["cs_then_plain.lz4"], 0, ""),
            row(T5, "--list blocks that differ", "lz4", &["--list", "bd_then_b4.lz4"], &["bd_then_b4.lz4"], 0, ""),
            row(T5, "--list -v blocks that differ", "lz4", &["--list", "-v", "bd_then_b4.lz4"], &["bd_then_b4.lz4"], 0, ""),
            row(T5, "--list a frame then a skippable", "lz4", &["--list", "-v", "cs_then_skip.lz4"], &["cs_then_skip.lz4"], 0, ""),
            row(T5, "--list two legacy frames", "lz4", &["--list", "leg_twice.lz4"], &["leg_twice.lz4"], 0, ""),
            row(T5, "--list -v a skippable then a legacy", "lz4", &["--list", "-v", "skip_then_leg.lz4"], &["skip_then_leg.lz4"], 0, ""),
            row(T5, "--list a skippable frame", "lz4", &["--list", "skip_ok.lz4"], &["skip_ok.lz4"], 0, ""),
            row(T5, "--list -v a skippable frame", "lz4", &["--list", "-v", "skip_ok.lz4"], &["skip_ok.lz4"], 0, ""),
            row(T5, "--list a skippable frame cut short", "lz4", &["--list", "-v", "skip_trunc.lz4"], &["skip_trunc.lz4"], 0, ""),
            row(T5, "--list a skippable size cut", "lz4", &["--list", "skip_hdr_trunc.lz4"], &["skip_hdr_trunc.lz4"], 42, "skippable size unreadable"),
            row(T5, "--list a skippable size cut to two bytes", "lz4", &["--list", "-v", "skip_size_cut.lz4"], &["skip_size_cut.lz4"], 42, "skippable size unreadable"),
            row(T5, "--list a skippable frame of 4 GiB", "lz4", &["--list", "-v", "skip_4g.lz4"], &["skip_4g.lz4"], 0, ""),
            row(T5, "--list a block of 2 GiB", "lz4", &["--list", "-v", "blk_2g.lz4"], &["blk_2g.lz4"], 0, ""),
            row(T5, "--list a block of 2 GiB, compact", "lz4", &["--list", "blk_2g.lz4"], &["blk_2g.lz4"], 0, ""),
            row(T5, "--list a header and nothing", "lz4", &["--list", "hdr_only.lz4"], &["hdr_only.lz4"], 1, "File format not recognized"),
            row(T5, "--list a header and one byte", "lz4", &["--list", "-v", "hdr_plus1.lz4"], &["hdr_plus1.lz4"], 0, ""),
            row(T5, "--list a header with a content size and nothing", "lz4", &["--list", "hdr_cs_only.lz4"], &["hdr_cs_only.lz4"], 1, "File format not recognized"),
            row(T5, "--list a magic number alone", "lz4", &["--list", "magic_only.lz4"], &["magic_only.lz4"], 71, "Error 71 : Error reading magic_only.lz4"),
            row(T5, "--list a content-size header cut at 9 bytes", "lz4", &["--list", "cs_trunc.lz4"], &["cs_trunc.lz4"], 1, "lz4: cs_trunc.lz4: File format not recognized"),
            row(T5, "--list a content-size header cut at 6 bytes", "lz4", &["--list", "hdr_cs_cut.lz4"], &["hdr_cs_cut.lz4"], 72, "Error 72 : Error reading hdr_cs_cut.lz4"),
            row(T5, "--list a header cut at 6 bytes, no content size", "lz4", &["--list", "hdr_cut6.lz4"], &["hdr_cut6.lz4"], 1, "lz4: hdr_cut6.lz4: File format not recognized"),
            row(T5, "--list a cut frame, -v", "lz4", &["--list", "-v", "t_blk.lz4"], &["t_blk.lz4"], 0, ""),
            row(T5, "--list a cut checksum, -v", "lz4", &["--list", "-v", "t_crc.lz4"], &["t_crc.lz4"], 0, ""),
            row(T5, "--list a cut block size, -v", "lz4", &["--list", "-v", "t_bsz.lz4"], &["t_bsz.lz4"], 0, ""),
            row(T5, "--list a cut header, -v", "lz4", &["--list", "-v", "t_hdr.lz4"], &["t_hdr.lz4"], 1, "File format not recognized"),
            row(T5, "--list a cut block of block checksums, -v", "lz4", &["--list", "-v", "t_bblk.lz4"], &["t_bblk.lz4"], 0, ""),
            row(T5, "--list a cut magic number", "lz4", &["--list", "t_magic.lz4"], &["t_magic.lz4"], 40, "Magic Number unreadable"),
            row(T5, "--list a legacy magic number alone", "lz4", &["--list", "leg_magic_only.lz4"], &["leg_magic_only.lz4"], 1, "File format not recognized"),
            row(T5, "--list two legacy magic numbers", "lz4", &["--list", "leg_magics.lz4"], &["leg_magics.lz4"], 1, "File format not recognized"),
            row(T5, "--list zero-size legacy blocks", "lz4", &["--list", "-v", "leg_zero_blocks.lz4"], &["leg_zero_blocks.lz4"], 0, ""),
            row(T5, "--list a legacy size above 4 GiB - 16", "lz4", &["--list", "leg_huge.lz4"], &["leg_huge.lz4"], 1, "Corrupted legacy frame \nlz4: leg_huge.lz4: File format not recognized"),
            row(T5, "--list a legacy size just above 8 MiB", "lz4", &["--list", "leg_8m.lz4"], &["leg_8m.lz4"], 1, "Corrupted legacy frame \nlz4: leg_8m.lz4: File format not recognized"),
            row(T5, "--list a legacy size cut short", "lz4", &["--list", "leg_bsz_trunc.lz4"], &["leg_bsz_trunc.lz4"], 1, "Corrupted legacy frame"),
            row(T5, "--list a legacy block cut short, -v", "lz4", &["--list", "-v", "leg_blk_trunc.lz4"], &["leg_blk_trunc.lz4"], 0, ""),
            row(T5, "--list a legacy frame then 3 bytes", "lz4", &["--list", "leg_garbage.lz4"], &["leg_garbage.lz4"], 1, "Corrupted legacy frame"),
            row(T5, "--list a legacy frame then 8 zeros", "lz4", &["--list", "-v", "leg_zeros.lz4"], &["leg_zeros.lz4"], 0, ""),
            row(T5, "--list a frame then 1 byte", "lz4", &["--list", "-v", "frame_tail1.lz4"], &["frame_tail1.lz4"], 40, "Magic Number unreadable"),
            row(T5, "--list a frame then 4 zeros, -v", "lz4", &["--list", "-v", "frame_zero4.lz4"], &["frame_zero4.lz4"], 1, "Stream followed by undecodable data at position 114"),
            row(T5, "--list a frame then 8 zeros", "lz4", &["--list", "z.lz4"], &["z.lz4"], 1, "File format not recognized"),
            row(T5, "--list frame + 100 bytes, -v", "lz4", &["--list", "-v", "g100.lz4"], &["g100.lz4"], 1, "Stream followed by undecodable data at position 114"),
            row(T5, "--list not lz4, -v", "lz4", &["--list", "-v", "notlz4"], &["notlz4"], 1, "Stream followed by undecodable data at position 4"),
            row(T5, "--list a bad header checksum, -v", "lz4", &["--list", "-v", "bad_hc.lz4"], &["bad_hc.lz4"], 1, "File format not recognized"),
            row(T5, "--list a reserved flag", "lz4", &["--list", "rsvd_flg.lz4"], &["rsvd_flg.lz4"], 1, "File format not recognized"),
            row(T5, "--list a reserved BD bit", "lz4", &["--list", "rsvd_bd.lz4"], &["rsvd_bd.lz4"], 1, "File format not recognized"),
            row(T5, "--list a bad version", "lz4", &["--list", "v0.lz4"], &["v0.lz4"], 1, "File format not recognized"),
            row(T5, "--list a block size ID of 3", "lz4", &["--list", "bd_size3.lz4"], &["bd_size3.lz4"], 1, "File format not recognized"),
            row(T5, "--list an empty frame, -v", "lz4", &["--list", "-v", "empty.lz4"], &["empty.lz4"], 0, ""),
            row(T5, "--list a content size of 2^63, -v", "lz4", &["--list", "-v", "cs_2p63.lz4"], &["cs_2p63.lz4"], 0, ""),
            row(T5, "--list a content size of 2^63, compact", "lz4", &["--list", "cs_2p63.lz4"], &["cs_2p63.lz4"], 0, ""),
            row(T5, "--list a content size that disagrees", "lz4", &["--list", "cs_mismatch.lz4"], &["cs_mismatch.lz4"], 0, ""),
            row(T5, "--list a content size cut", "lz4", &["--list", "hdr_cs_cut.lz4", "b.lz4"], &["hdr_cs_cut.lz4", "b.lz4"], 72, "Error 72"),
            // Several files, and the first failure ends the run.
            row(T5, "--list several files", "lz4", &["--list", "b.lz4", "cs.lz4", "leg.lz4"], &["b.lz4", "cs.lz4", "leg.lz4"], 0, ""),
            row(T5, "--list -v several files", "lz4", &["--list", "-v", "b.lz4", "cs.lz4", "leg.lz4"], &["b.lz4", "cs.lz4", "leg.lz4"], 0, ""),
            row(T5, "--list a failure ends the run", "lz4", &["--list", "b.lz4", "notlz4", "cs.lz4"], &["b.lz4", "notlz4", "cs.lz4"], 1, "lz4: notlz4: File format not recognized"),
            row(T5, "--list -v a failure ends the run", "lz4", &["--list", "-v", "b.lz4", "notlz4", "cs.lz4"], &["b.lz4", "notlz4", "cs.lz4"], 1, "lz4: notlz4: File format not recognized"),
            row(T5, "--list a missing file between two", "lz4", &["--list", "b.lz4", "nosuch", "cs.lz4"], &["b.lz4", "cs.lz4"], 1, "lz4: nosuch is not a regular file"),
            row(T5, "--list an Error N ends the run", "lz4", &["--list", "t_magic.lz4", "b.lz4"], &["t_magic.lz4", "b.lz4"], 40, "Magic Number unreadable"),
            row(T5, "--list - between files", "lz4", &["--list", "b.lz4", "-", "cs.lz4"], &["b.lz4", "cs.lz4"], 0, ""),
            row(T5, "--list - alone", "lz4", &["--list", "-"], &[], 0, "").stdin_fx("b.lz4"),
            row(T5, "--list -v on stdin", "lz4", &["--list", "-v"], &[], 0, "").stdin_fx("b.lz4"),
            row(T5, "--list the operand stdin, a pipe (a file of that name is not read)", "lz4", &["--list", "stdin"], &["stdin"], 1, "lz4: stdin is not a regular file"),
            row(T5, "--list after the operand", "lz4", &["b.lz4", "--list"], &["b.lz4"], 0, ""),
            row(T5, "--list -d: the last mode wins", "lz4", &["--list", "-d", "b.lz4"], &["b.lz4"], 0, ""),
            row(T5, "-d --list: the last mode wins", "lz4", &["-d", "--list", "b.lz4"], &["b.lz4"], 0, ""),
            row(T5, "--list -t: the last mode wins", "lz4", &["--list", "-t", "b.lz4"], &["b.lz4"], 0, ""),
            row(T5, "--list through a symbolic link", "lz4", &["--list", "ln.lz4"], &["b.lz4"], 0, "").setup(link_to_b),
            row(T5, "--list a directory path", "lz4", &["--list", "d/"], &[], 1, "lz4: d/ is not a regular file").setup(mkdir_d),
            row(T5, "--list -r over a directory", "lz4", &["--list", "-r", "d"], &[], 0, "").setup(dir_with_lz4),
            row(T5, "--list -v -r over a directory", "lz4", &["--list", "-v", "-r", "d"], &[], 0, "").setup(dir_with_lz4),
            row(T5, "--list -r over an empty directory", "lz4", &["--list", "-r", "d"], &[], 1, "lz4: d is not a regular file").setup(mkdir_d),
            row(T5, "--list -r with an empty directory and a file", "lz4", &["--list", "-r", "d", "b.lz4"], &["b.lz4"], 0, "").setup(mkdir_d),
            row(T5, "--list a file in a directory (base name)", "lz4", &["--list", "-v", "d/x.lz4"], &[], 0, "").setup(dir_with_lz4),
            // Display levels: the tables are standard output at every level;
            // the errors follow -q and -qq; -v adds the banner and the
            // per-frame table, -vv the version lines.
            row(T5, "--list -q", "lz4", &["--list", "-q", "b.lz4"], &["b.lz4"], 0, ""),
            row(T5, "--list -q failing", "lz4", &["--list", "-q", "notlz4"], &["notlz4"], 1, ""),
            row(T5, "--list -qq failing", "lz4", &["--list", "-qq", "notlz4"], &["notlz4"], 1, ""),
            row(T5, "--list -qq missing", "lz4", &["--list", "-qq", "nosuch"], &[], 1, ""),
            row(T5, "--list -q Error 40", "lz4", &["--list", "-q", "t_magic.lz4"], &["t_magic.lz4"], 40, ""),
            row(T5, "--list -qq Error 40", "lz4", &["--list", "-qq", "t_magic.lz4"], &["t_magic.lz4"], 40, ""),
            row(T5, "--list -vv", "lz4", &["--list", "-vv", "b.lz4"], &["b.lz4"], 0, "_POSIX_VERSION defined: "),
            row(T5, "--list -vvv", "lz4", &["--list", "-vvv", "cs.lz4"], &["cs.lz4"], 0, ""),
            row(T5, "--list -vv failing", "lz4", &["--list", "-vv", "notlz4"], &["notlz4"], 1, "_POSIX_VERSION defined: "),
            row(T5, "--list -vq", "lz4", &["--list", "-vq", "b.lz4"], &["b.lz4"], 0, ""),
            row(T5, "--list -qv", "lz4", &["--list", "-qv", "b.lz4"], &["b.lz4"], 0, ""),
            row(T5, "--list a legacy frame, -v", "lz4", &["--list", "-v", "leg.lz4"], &["leg.lz4"], 0, ""),
            row(T5, "--list a legacy frame then a frame, -q", "lz4", &["--list", "-q", "leg_then_good.lz4"], &["leg_then_good.lz4"], 0, ""),
            row(T5, "--list under unlz4", "unlz4", &["--list", "b.lz4"], &["b.lz4"], 0, ""),
            row(T5, "--list under lz4cat", "lz4cat", &["--list", "b.lz4"], &["b.lz4"], 0, ""),
            row(T5, "--list -v under lz4cat", "lz4cat", &["--list", "-v", "b.lz4"], &["b.lz4"], 0, ""),
            row(T5, "--list under lz4c", "lz4c", &["--list", "cs.lz4"], &["cs.lz4"], 0, ""),
            row(T5, "--list failing under lz4cat", "lz4cat", &["--list", "notlz4"], &["notlz4"], 1, "lz4: notlz4: File format not recognized"),
            row(T5, "-p --list", "lz4", &["-p", "--list", "b.lz4"], &["b.lz4"], 0, "Press enter to continue"),
            row(T5, "-p --list failing", "lz4", &["-p", "--list", "notlz4"], &["notlz4"], 1, "Press enter to continue"),
            row(T5, "-p --list Error 40", "lz4", &["-p", "--list", "t_magic.lz4"], &["t_magic.lz4"], 40, ""),
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
            tz: None,
            unzip_flavour: None,
            zip_flavour: None,
            zip_tree: None,
            tty_ctl: false,
            tty_signal: None,
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

    /// Whether the case's refresh count depends on 200 ms passing between
    /// two units of work: more than one input (`-m`/`-r` or `lz4cat` over
    /// two or more operands, `-c` over two), or an input of two frames
    /// (`two.lz4`). Without `-m` a second operand is the output, not an
    /// input (`-d b.lz4 b.lz4`). A `-D` value is a dictionary, not an input.
    /// `-r` is always exposed: a directory operand expands to many inputs.
    fn timing_exposed(c: &Case) -> bool {
        let mut opts: Vec<&str> = Vec::new();
        let mut operands = 0;
        let mut ended = false;
        let mut it = c.args.iter().copied();
        while let Some(a) = it.next() {
            if ended {
                operands += 1;
            } else if a == "--" {
                ended = true;
            } else if a == "-D" {
                it.next();
            } else if a.starts_with('-') && a != "-" {
                opts.push(a);
            } else {
                operands += 1;
            }
        }
        let short = |ch: char| {
            opts.iter()
                .any(|a| !a.starts_with("--") && a[1..].contains(ch))
        };
        let multi = short('m') || short('r') || c.name == "lz4cat";
        let inputs = if multi || short('c') {
            operands
        } else {
            operands.min(1)
        };
        short('r') || inputs >= 2 || c.args.contains(&"two.lz4")
    }

    /// Whether `timing_exposed` tells one input from several: a second
    /// operand is an input only under `-m`, `-r`, `-c` or `lz4cat`.
    #[test]
    fn single_inputs_are_not_timing_exposed() {
        let one = |args: &[&'static str]| lz4_case("lz4", args, vec![("b.lz4", fx("b.lz4"))]);
        assert!(!timing_exposed(&one(&["-m", "-t", "b.lz4"])));
        assert!(!timing_exposed(&one(&["-d", "b.lz4", "b.lz4"])));
        assert!(timing_exposed(&one(&["-m", "-t", "b.lz4", "b.lz4"])));
        assert!(timing_exposed(&lz4_case(
            "lz4cat",
            &["b.lz4", "b.lz4"],
            vec![]
        )));
        assert!(timing_exposed(&one(&["-d", "two.lz4", "o"])));
        // A dictionary is read, not decoded; a digit in a cluster is not `m`.
        assert!(!timing_exposed(&one(&["-m", "-D", "dict", "b.lz4"])));
        assert!(!timing_exposed(&one(&["-B4", "b.lz4"])));
        assert!(timing_exposed(&one(&["-B4m", "b.lz4", "b.lz4"])));
        assert!(timing_exposed(&one(&["-r", "d"])));
        assert!(timing_exposed(&one(&["-v", "-r", "d"])));
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
        // Deviation 2 covers which refreshes are drawn, not their figures
        // (read from the raw stderr; the pure tier's bytes, and so its
        // figures, are its own: deviation 6).
        if EXACT && !figures_are_timing(c) {
            assert_lz4_read_figures(c, &r, &s);
        }
        // Spec deviation 8: off macOS the reference completes a block-size
        // word cut short from uninitialised memory even in the first frame
        // (probe: the tarball build on Linux, CI run 39166896170).
        if !cfg!(target_os = "macos") && lists_a_cut_word(c) {
            r.stdout = mask_frame_sizes(&r.stdout);
            s.stdout = mask_frame_sizes(&s.stdout);
        }
        // Spec deviation 2: refreshes, timing fields, thread count.
        // A run with a second file or frame to draw for is timing-exposed:
        // its refreshes are dropped, not collapsed (single-file rows still
        // catch a missing or extra refresh).
        let norm = if timing_exposed(c) {
            normalise_lz4_progress_without_refreshes
        } else {
            normalise_lz4_progress
        };
        r.stderr = norm(&r.stderr);
        s.stderr = norm(&s.stderr);
        // The reference's own race over how much a failed decode wrote.
        tolerate_lz4_partial_output(c, &mut r, &mut s);
        // Spec deviation 6: the pure tier's summary counts its own bytes,
        // and its compressed bytes on a terminal (which rewrites newlines)
        // cannot be decoded back; whether anything was written still is
        // compared.
        if !EXACT {
            r.stderr = mask_compressed_size(&r.stderr);
            s.stderr = mask_compressed_size(&s.stderr);
            if c.tty_stdout && r.stdout.is_empty() == s.stdout.is_empty() {
                r.stdout.clear();
                s.stdout.clear();
            }
        }
        assert_same(c, &r, &s);
        true
    }

    /// Whether `c`'s refresh figures are timing (deviation 2): a frame
    /// compressed by liblz4's workers (lz4 1.11.0: not `-l`, not a custom
    /// `-B#`, not `--single-thread` after the last `-T#`) over more than
    /// one job (1 MiB, or a block when larger), or with linked blocks over
    /// a block or more (a worker takes even one job then). There a refresh
    /// shows what the workers had handed back when it was drawn, and the
    /// reference varies run to run (probe, 2026-11-08: 2.5 MB `-T3 -B4`
    /// drew `0.00%` and `27.71%`, 9 MiB `-B6` `18.93%` and `28.39%` at 8
    /// MiB, 1 MiB of random bytes `-B4 -BD` `0.00%` and `100.01%`; `-T1`
    /// over 1 MiB + 1 byte `0.00%` idle and `8.67%` under the suite's
    /// load). A file of one job with independent blocks is compressed by
    /// the calling thread, and a one-shot frame is drawn once complete:
    /// those are compared.
    fn figures_are_timing(c: &Case) -> bool {
        const MIB: usize = 1 << 20;
        let mut single = false;
        let mut block = 4 * MIB;
        let mut linked = false;
        for a in &c.args {
            if *a == "--" {
                break;
            }
            if *a == "--single-thread" {
                single = true;
            } else if a.starts_with("--threads") {
                single = false;
            } else if let Some(short) = a.strip_prefix('-').filter(|s| !s.starts_with('-')) {
                if short.contains('T') {
                    single = false;
                }
                if short.contains('l') {
                    return false;
                }
                if let Some(at) = short.find('B') {
                    let flags = &short[at + 1..];
                    if let Some(i) = flags.rfind(['D', 'I']) {
                        linked = flags.as_bytes()[i] == b'D';
                    }
                    let digits: String = flags
                        .chars()
                        .skip_while(|c| !c.is_ascii_digit())
                        .take_while(char::is_ascii_digit)
                        .collect();
                    let n: usize = digits.parse().unwrap_or(0);
                    match n {
                        4..=7 => block = (64 << 10) << (2 * (n - 4)),
                        65_536 | 262_144 | 1_048_576 => block = n,
                        32.. if n < 4 * MIB => return false,
                        32.. => block = 4 * MIB,
                        _ => {}
                    }
                }
            }
        }
        if single {
            return false;
        }
        let size = c
            .files
            .iter()
            .filter(|(name, _)| *name != "dict")
            .map(|(_, d)| d.len())
            .chain(c.stdin.as_ref().map(Vec::len))
            .max()
            .unwrap_or(0);
        (linked && size >= block) || size > MIB.max(block)
    }

    /// Whether `c` is a `--list -v` of a fixture whose first frame ends
    /// inside a block-size word (deviation 8).
    fn lists_a_cut_word(c: &Case) -> bool {
        c.args.contains(&"--list")
            && c.args.iter().any(|a| a.starts_with("-v"))
            && c.files
                .iter()
                .any(|(name, _)| matches!(*name, "hdr_plus1.lz4" | "t_bsz.lz4"))
    }

    /// A `--list -v` table with the frame-size cell of every `LZ4Frame`
    /// row masked (and each row's blanks collapsed, as the cell's width
    /// moves them).
    fn mask_frame_sizes(stdout: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(stdout);
        let mut out = String::with_capacity(text.len());
        for line in text.split_inclusive('\n') {
            let cells: Vec<&str> = line.split_whitespace().collect();
            if cells.get(1) == Some(&"LZ4Frame") && cells.len() >= 5 {
                let mut cells = cells;
                cells[4] = "<size>";
                out.push_str(&cells.join(" "));
                out.push('\n');
            } else {
                out.push_str(line);
            }
        }
        out.into_bytes()
    }

    /// `Compressed A bytes into B bytes ==> R%` with B and R masked: the
    /// pure tier's frames are compatible, not identical (spec deviation 6),
    /// so only the bytes read are compared.
    fn mask_compressed_size(stderr: &str) -> String {
        let mut out = String::with_capacity(stderr.len());
        let mut rest = stderr;
        while let Some(at) = rest.find(" bytes into ") {
            let (head, tail) = rest.split_at(at + " bytes into ".len());
            out.push_str(head);
            let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
            let after = &tail[digits..];
            if digits > 0
                && let Some(r) = after.strip_prefix(" bytes ==> ")
                && let Some(pct) = r.find('%')
            {
                out.push_str("<n> bytes ==> <r>");
                rest = &r[pct..];
            } else {
                rest = tail;
            }
        }
        out.push_str(rest);
        out
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
        for var in ["LZ4_CLEVEL", "LZ4_NBWORKERS", "LZ4_MEMORY"] {
            for val in [
                "x",
                "-1",
                "",
                " 4",
                "3x",
                "1K",
                "4294967297",
                "201",
                // lz4 1.11.0: whole values only, 32 bits (64 for
                // LZ4_MEMORY), and a level up to INT_MAX.
                "2147483647",
                "2147483648",
                "4294967295",
                "4294967296",
                "99999999999",
                "1KiB",
                "1Kx",
                "1G",
                "1GiB",
                "1g",
                "0",
                "00",
                "01",
                "50M",
                "18446744073709551615",
                "18446744073709551616",
            ] {
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
        let mut all = case(&row("Task 3", "env", "lz4", &["-qq", "-V"], &[], 0, ""));
        all.env.extend([
            ("LZ4_MEMORY", "z"),
            ("LZ4_NBWORKERS", "y"),
            ("LZ4_CLEVEL", "x"),
        ]);
        cases.push(all);
        // What a valid value does to a compression's thread lines.
        let a = super::compat_harness::text(4000, 46);
        for (var, val) in [
            ("LZ4_MEMORY", "50M"),
            ("LZ4_MEMORY", "1"),
            ("LZ4_MEMORY", "1K"),
            ("LZ4_MEMORY", "1G"),
            ("LZ4_MEMORY", "18446744073709551615"),
            ("LZ4_NBWORKERS", "3"),
            ("LZ4_NBWORKERS", "1K"),
            ("LZ4_NBWORKERS", "2000"),
            ("LZ4_NBWORKERS", "2147483648"),
            ("LZ4_NBWORKERS", "4294967295"),
            ("LZ4_NBWORKERS", "0"),
            ("LZ4_CLEVEL", "9"),
            ("LZ4_CLEVEL", "2147483647"),
        ] {
            for args in [&["-v", "a", "o.lz4"][..], &["a", "o.lz4"]] {
                let mut c = lz4_case("lz4", args, vec![("a", a.clone())]);
                c.env.push((var, val));
                cases.push(c);
            }
        }
        let mut c = lz4_case(
            "lz4",
            &["-v", "--memory=1G", "a", "o.lz4"],
            vec![("a", a.clone())],
        );
        c.env.push(("LZ4_MEMORY", "50M"));
        cases.push(c);
        let mut c = lz4_case("lz4", &["-v", "--memory=50M", "a", "o.lz4"], vec![("a", a)]);
        c.env.push(("LZ4_MEMORY", "1G"));
        cases.push(c);
        run_group("environment", &cases, Skipped::none(), &compare);
    }

    /// Spec deviation 5: `-b#` is refused once the command line has parsed
    /// (the reference runs its benchmark; `-e`/`-i` alone are ignored, as
    /// the Task 3 rows compare). A usage error, `-h` and `-V` answer first,
    /// as the reference's do (the Task 3 rows compare those).
    #[test]
    fn benchmark_options_are_refused() {
        // Safe as `at`: only this test builds the name, and it has the pid.
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
            &["-b1", "-e3", "a"],
            &["-b", "-d", "a"],
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

    /// `--list stdin` (the operand, not `-`) lists standard input when it is
    /// redirected from a regular file, named `stdin`, and refuses a pipe or
    /// `/dev/null` (probed 2026-10-16; the differential harness feeds a
    /// pipe, so this runs the two binaries by hand). `-` and no operand
    /// never read it.
    #[test]
    fn list_of_standard_input_redirected_from_a_file() {
        if lz4_dir().is_none() {
            return;
        }
        // Safe as `at`: only this test builds the name, and it has the pid.
        let dir = ScratchDir::at(
            std::env::temp_dir().join(format!("stuffr-lz4-liststdin-{}", std::process::id())),
        );
        fs::create_dir_all(&*dir).unwrap();
        for name in [
            "b.lz4",
            "cs.lz4",
            "leg.lz4",
            "skip_ok.lz4",
            "notlz4",
            "t_magic.lz4",
        ] {
            fs::write(dir.join(name), fx(name)).unwrap();
        }
        let link = dir.join("lz4");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
        let run = |exe: &Path, args: &[&str], input: &str| {
            let stdin = if input.is_empty() {
                std::process::Stdio::null()
            } else {
                std::process::Stdio::from(fs::File::open(dir.join(input)).unwrap())
            };
            let o = std::process::Command::new(exe)
                .args(args)
                .current_dir(&*dir)
                .stdin(stdin)
                .env("LC_ALL", "C")
                .output()
                .unwrap();
            let err = String::from_utf8_lossy(&o.stderr).into_owned();
            // Deviation 1: the banner names stuffr.
            let err = err.replacen(
                &format!("multithread (stuffr {})", env!("CARGO_PKG_VERSION")),
                "multithread",
                1,
            );
            (o.status.code(), o.stdout, err)
        };
        let reference = Path::new(ref_lz4());
        for args in [
            &["--list", "stdin"][..],
            &["--list", "-v", "stdin"],
            &["--list", "b.lz4", "stdin", "cs.lz4"],
            &["--list", "-"],
            &["--list"],
        ] {
            for input in [
                "b.lz4",
                "cs.lz4",
                "leg.lz4",
                "skip_ok.lz4",
                "notlz4",
                "t_magic.lz4",
                "",
            ] {
                assert_eq!(
                    run(&link, args, input),
                    run(reference, args, input),
                    "{args:?} < {input:?}"
                );
            }
        }
    }

    /// The dictionary fixtures write the dictionary to a scratch file the
    /// reference then reads. Two tests building them at once (as the test
    /// runner does) must not share the directory: under a fixed per-pid path
    /// one guard's drop removed the tree under the other's `lz4` spawn
    /// ("Dictionary error : could not open dictionary file"). Hammer both
    /// fixtures from two threads and compare with a quiet run.
    #[test]
    fn dictionary_fixtures_do_not_share_a_scratch_dir() {
        if lz4_dir().is_none() {
            return;
        }
        let (b, cs) = (fx("dict_b.lz4"), fx("dict_cs.lz4"));
        std::thread::scope(|s| {
            for _ in 0..2 {
                s.spawn(|| {
                    for _ in 0..150 {
                        assert_eq!(fx("dict_b.lz4"), b);
                        assert_eq!(fx("dict_cs.lz4"), cs);
                    }
                });
            }
        });
    }

    #[test]
    fn task4_rows_match_the_reference() {
        check_task("Task 4");
    }

    #[test]
    fn task5_rows_match_the_reference() {
        check_task("Task 5");
    }

    #[test]
    fn task6_rows_match_the_reference() {
        check_task("Task 6");
    }

    /// Display levels 0 to 5 on a non-terminal standard error (Task 6; the
    /// refresh gate and the terminal forms are `display.rs`'s unit tests):
    /// compress, decode, test, `-c`, `-m`, `-r`, standard input and
    /// output, a missing file, `--content-size` of a pipe, `-l`, and the
    /// overwrite question's two answers at `-v` (R11, moved here from
    /// Task 4). Timing, refreshes and the thread count are deviation 2's,
    /// normalised; every other byte of stderr, stdout and the files is
    /// the reference's, including `Done in`'s presence and place.
    #[test]
    fn display_levels_match_the_reference() {
        let mut cases = Vec::new();
        let levels: [&[&'static str]; 8] = [
            &[],
            &["-v"],
            &["-vv"],
            &["-vvv"],
            &["-q"],
            &["-qq"],
            &["-qqq"],
            &["-v", "-q"],
        ];
        // Only the fixtures a case names: the pure tier judges what it
        // wrote by decoding it, and finds the original from the files.
        let files = |tail: &[&str]| {
            let all = [
                ("a", fx("a")),
                ("a2", fx("a2")),
                ("b.lz4", fx("b.lz4")),
                ("bc.lz4", fx("bc.lz4")),
                ("leg.lz4", fx("leg.lz4")),
                ("empty.lz4", fx("empty.lz4")),
                // A skippable frame then a frame; two legacy frames.
                (
                    "sk.lz4",
                    [&b"\x50\x2a\x4d\x18\x04\x00\x00\x00abcd"[..], &fx("b.lz4")].concat(),
                ),
                ("two.lz4", [fx("leg.lz4"), fx("leg.lz4")].concat()),
            ];
            all.into_iter()
                .filter(|(n, _)| tail.contains(n))
                .collect::<Vec<_>>()
        };
        for lv in levels {
            let with = |tail: &[&'static str]| -> Vec<&'static str> {
                lv.iter().chain(tail.iter()).copied().collect()
            };
            for tail in [
                &["-T3", "a", "x.lz4"][..],
                &["-T1", "a", "x.lz4"],
                &["-T300", "a", "x.lz4"],
                &["a"],
                &["-c", "a"],
                &["a", "-"],
                &["-l", "a", "x.lz4"],
                &["-c", "-l", "a"],
                &["-m", "a", "a2"],
                &["-c", "-m", "a", "a2"],
                &["-m", "a", "nosuch"],
                &["nosuch"],
                &["-d", "b.lz4", "bo"],
                &["-d", "b.lz4"],
                &["-d", "empty.lz4", "eo"],
                &["-t", "b.lz4"],
                &["-t", "leg.lz4"],
                &["-t", "sk.lz4"],
                &["-t", "two.lz4"],
                &["-dc", "b.lz4"],
                &["-dc", "--sparse", "b.lz4"],
                &["-dc", "--no-sparse", "b.lz4"],
                &["-d", "-m", "b.lz4", "bc.lz4"],
                &["-t", "-m", "b.lz4", "leg.lz4"],
                &["-dc", "-m", "b.lz4", "bc.lz4"],
                &["-d", "nosuch.lz4", "o"],
                &["-d", "-m", "b.lz4", "nosuch.lz4", "bc.lz4"],
                &["-d", "b.lz4", "a2"],
                &["a", "a2"],
                &["-f", "-m", "a", "a2"],
            ] {
                cases.push(lz4_case("lz4", &with(tail), files(tail)));
            }
            for name in ["unlz4", "lz4cat"] {
                for tail in [&["b.lz4"][..], &["b.lz4", "bc.lz4"], &["nosuch.lz4"]] {
                    cases.push(lz4_case(name, &with(tail), files(tail)));
                }
            }
            // Standard input and output.
            cases.push(piped("lz4", &with(&["-T2"]), vec![], fx("a")));
            cases.push(piped("lz4", &with(&["-c"]), vec![], fx("a")));
            cases.push(piped(
                "lz4",
                &with(&["--content-size", "-c"]),
                vec![],
                fx("a"),
            ));
            cases.push(piped(
                "lz4",
                &with(&["--content-size", "-"]),
                vec![("o", fx("a2"))],
                fx("a"),
            ));
            cases.push(piped("lz4", &with(&["-d"]), vec![], fx("b.lz4")));
            cases.push(piped("lz4", &with(&["-dc"]), vec![], fx("b.lz4")));
            cases.push(piped("lz4", &with(&["-t", "-m"]), vec![], fx("b.lz4")));
            cases.push(piped(
                "lz4",
                &with(&["-d", "-", "o"]),
                vec![("o", fx("a2"))],
                b"n\n".to_vec(),
            ));
            // The overwrite question, refused (R11; the answered-`y` form
            // is Task 4's rows: the pure tier's round trip cannot tell
            // the answer from the data in standard input).
            cases.push(piped(
                "lz4",
                &with(&["-", "a2"]),
                vec![("a2", fx("a2"))],
                [&b"n\n"[..], &fx("a")[..]].concat(),
            ));
            // R11, moved from Task 4: two inputs, two answers, the data
            // after them unused, needs `-v` to show the order of lines.
            cases.push(piped(
                "lz4",
                &with(&["-m", "a", "a2"]),
                vec![
                    ("a", fx("a")),
                    ("a2", fx("a2")),
                    ("a.lz4", fx("a2")),
                    ("a2.lz4", fx("a2")),
                ],
                b"yxz\ny".to_vec(),
            ));
            // -r: the list at level 4.
            let mut r = lz4_case("lz4", &with(&["-r", "d"]), vec![]);
            r.setup = Some(tree);
            cases.push(r);
        }
        // The compression figures (deviation 2 keeps only which refreshes
        // are drawn): `-T1 -vvvv` draws every chance on both sides, over
        // generated text one-shot, one job, a job and a byte, several jobs
        // (legacy and linked too), two files and nothing.
        let big = |n: usize| super::compat_harness::text(n, 51);
        for (args, files) in [
            (
                &["-T1", "-vvvv", "-f", "in", "o.lz4"][..],
                vec![("in", big(2 << 20))],
            ),
            (
                &["-T1", "-vvvv", "-f", "in", "o.lz4"],
                vec![("in", big(4 << 20))],
            ),
            (
                &["-T1", "-vvvv", "-f", "in", "o.lz4"],
                vec![("in", big((4 << 20) + 1))],
            ),
            (
                &["-T1", "-vvvv", "-f", "in", "o.lz4"],
                vec![("in", big(9 << 20))],
            ),
            (
                &["-T1", "-vvvv", "-f", "-l", "in", "o.lz4"],
                vec![("in", big(9 << 20))],
            ),
            (
                &["-T1", "-vvvv", "-f", "-BD", "in", "o.lz4"],
                vec![("in", big(9 << 20))],
            ),
            (
                &["-T1", "-vvvv", "-f", "-m", "in", "in2"],
                vec![("in", big(2 << 20)), ("in2", big((4 << 20) + 1))],
            ),
            (
                &["-T1", "-vvvv", "-f", "in", "o.lz4"],
                vec![("in", Vec::new())],
            ),
        ] {
            cases.push(lz4_case("lz4", args, files));
        }
        check("display_levels_match_the_reference", &cases);
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

    use stuffr_cli::compat::lz4::EXIT_CODES;

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
            tz: None,
            unzip_flavour: None,
            zip_flavour: None,
            zip_tree: None,
            tty_ctl: false,
            tty_signal: None,
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

    // ---- part 2 (Task 4): compression, decompression, test, files ----
    //
    // Every case below runs the reference and stuffr side by side and
    // compares standard output, standard error (deviation 2 normalised),
    // the exit code and the file tree (bytes, mode, mtime); on the C tier
    // compressed bytes are compared exactly, on the pure tier the
    // reference decodes them (deviation 6). Probed 2026-10-16.

    /// A case of `name ARGS` over `files`.
    fn lz4_case(
        name: &'static str,
        args: &[&'static str],
        files: Vec<(&'static str, Vec<u8>)>,
    ) -> Case<'static> {
        Case {
            name,
            args: args.to_vec(),
            files,
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![("LC_ALL", "C")],
            compare_output_bytes: EXACT,
            tz: None,
            unzip_flavour: None,
            zip_flavour: None,
            zip_tree: None,
            tty_ctl: false,
            tty_signal: None,
            expect_stdout_plain: None,
            setup: None,
            roundtrip: Roundtrip::Lz4 { ref_lz4: ref_lz4() },
        }
    }

    /// [`lz4_case`] fed `stdin`.
    fn piped(
        name: &'static str,
        args: &[&'static str],
        files: Vec<(&'static str, Vec<u8>)>,
        stdin: Vec<u8>,
    ) -> Case<'static> {
        Case {
            stdin: Some(stdin),
            ..lz4_case(name, args, files)
        }
    }

    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    /// Run `cases` against the reference; skipped when it is absent.
    fn check(group: &str, cases: &[Case]) {
        if lz4_dir().is_none() {
            return;
        }
        run_group(group, cases, Skipped::none(), &compare);
    }

    /// The brief's six inputs: empty, one byte, 1 KiB of text, 1 MiB mixed,
    /// 1 MiB random, and 9 MiB repetitive (past a legacy block's 8 MiB and
    /// two frame jobs of 4 MiB).
    fn inputs() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("one", b"x".to_vec()),
            ("kib", super::compat_harness::text(1024, 41)),
            ("mixed", mixed(1 << 20, 42)),
            ("random", random(1 << 20, 43)),
            ("rep", repetitive(9 << 20)),
        ]
    }

    /// `--fast=5`, `-0` to `-12`, `--best`, `--favor-decSpeed` (alone and
    /// where liblz4 uses it, levels 10 and up).
    const LEVELS: [&[&str]; 18] = [
        &["--fast=5"],
        &["-0"],
        &["-1"],
        &["-2"],
        &["-3"],
        &["-4"],
        &["-5"],
        &["-6"],
        &["-7"],
        &["-8"],
        &["-9"],
        &["-10"],
        &["-11"],
        &["-12"],
        &["--best"],
        &["--favor-decSpeed"],
        &["--favor-decSpeed", "-10"],
        &["--favor-decSpeed", "--best"],
    ];

    /// Every level over every input, file to file (the summary at level 2
    /// included); the 9 MiB input at the levels that exercise each
    /// compressor (the high levels take long in a debug build).
    #[test]
    fn every_level_of_every_input() {
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for level in LEVELS {
                if name == "rep" && !matches!(level[0], "--fast=5" | "-1" | "-3" | "-9") {
                    continue;
                }
                let mut args = level.to_vec();
                args.extend([name, "o.lz4"]);
                cases.push(lz4_case("lz4", &args, vec![(name, data.clone())]));
            }
        }
        check("every_level_of_every_input", &cases);
    }

    /// The frame options over the inputs: block sizes, linked blocks, block
    /// checksums, no content checksum, the content size (from a file, from
    /// standard input redirected from a pipe), legacy, a dictionary, and
    /// the thread counts (which do not change the bytes).
    #[test]
    fn frame_options_match_the_reference() {
        const OPTIONS: [&[&str]; 18] = [
            &["-B4"],
            &["-B5"],
            &["-B6"],
            &["-B7"],
            &["-B4", "-BD"],
            &["-BD"],
            &["-BX"],
            &["-B4", "-BD", "-BX"],
            &["--no-frame-crc"],
            &["--content-size"],
            &["--content-size", "-B4", "-BD"],
            &["-l"],
            &["-l", "-9"],
            &["-D", "dict"],
            &["-D", "dict", "-BD", "-B4"],
            &["-T1"],
            &["-T4"],
            &["-T0"],
        ];
        let dict = mixed(70 << 10, 44);
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for opt in OPTIONS {
                if name == "rep" && opt.contains(&"-T4") {
                    continue;
                }
                let mut args = opt.to_vec();
                args.extend([name, "o.lz4"]);
                let mut files = vec![(name, data.clone())];
                if opt.contains(&"-D") {
                    files.push(("dict", dict.clone()));
                }
                cases.push(lz4_case("lz4", &args, files));
            }
            // Standard input: a pipe has no size (probe: `cat big | lz4
            // --content-size -c` records none).
            for opt in [&["--content-size"][..], &["-l"], &["-BD", "-B5"]] {
                let mut args = opt.to_vec();
                args.push("-c");
                cases.push(piped("lz4", &args, vec![], data.clone()));
            }
        }
        check("frame_options_match_the_reference", &cases);
    }

    /// Ruling T3-d: levels at the edge of `i32` (probe 2026-10-16: frames at
    /// `i32::MIN` and `i32::MIN + 1` are level 1's bytes, everything at or
    /// below −65535 is −65536's; legacy at `i32::MIN` is level 1's).
    #[test]
    fn extreme_levels_match_the_reference() {
        let data = mixed(300 << 10, 45);
        let mut cases = Vec::new();
        for legacy in [false, true] {
            for level in [
                "--fast=2147483646",
                "--fast=2147483647",
                "--fast=2147483648",
                "-2147483648",
                "-2147483647",
            ] {
                let mut args = vec![level, "-c", "in"];
                if legacy {
                    args.insert(0, "-l");
                }
                cases.push(lz4_case("lz4", &args, vec![("in", data.clone())]));
            }
            let mut c = lz4_case(
                "lz4",
                if legacy {
                    &["-l", "-c", "in"]
                } else {
                    &["-c", "in"]
                },
                vec![("in", data.clone())],
            );
            c.env.push(("LZ4_CLEVEL", "2147483648"));
            cases.push(c);
        }
        check("extreme_levels_match_the_reference", &cases);
    }

    // ---- files ----

    fn link_a_to_la(w: &Path) {
        std::os::unix::fs::symlink("a", w.join("la")).unwrap();
    }
    fn dangling(w: &Path) {
        std::os::unix::fs::symlink("nowhere", w.join("dangle")).unwrap();
    }
    fn tree(w: &Path) {
        fs::create_dir_all(w.join("d/sub")).unwrap();
        fs::create_dir_all(w.join("d/emp")).unwrap();
        for (n, b) in [
            ("d/zz", "1\n"),
            ("d/aa", "2\n"),
            ("d/Mm", "3\n"),
            ("d/sub/x", "4\n"),
            ("d/.h", "5\n"),
        ] {
            fs::write(w.join(n), b).unwrap();
        }
        std::os::unix::fs::symlink("../a", w.join("d/lnk")).unwrap();
    }
    fn tree_of_frames(w: &Path) {
        tree(w);
        fs::write(w.join("d/sub/y.lz4"), fx("b.lz4")).unwrap();
        fs::write(w.join("d/k.lz4"), fx("b.lz4")).unwrap();
    }
    fn link_to_dev_null(w: &Path) {
        std::os::unix::fs::symlink("/dev/null", w.join("nl")).unwrap();
    }
    fn set_up(c: Case<'static>, f: fn(&Path)) -> Case<'static> {
        Case {
            setup: Some(f),
            ..c
        }
    }
    fn mode_640_a(w: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(w.join("a"), fs::Permissions::from_mode(0o640)).unwrap();
    }
    fn mode_604_b(w: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(w.join("b.lz4"), fs::Permissions::from_mode(0o604)).unwrap();
    }
    fn stdin_file(w: &Path) {
        fs::write(w.join("stdin"), b"a file named stdin\n").unwrap();
    }

    /// Where outputs go and what happens to the files around them: `-k`
    /// and `--rm`, `-f`, the overwrite question (R11: answered `y`, `n`, at
    /// end of file, and twice from one input), symbolic links, `-m` and
    /// `-r` trees, metadata, standard input and output.
    #[test]
    fn files_match_the_reference() {
        let a = || ("a", text());
        let e = || ("e", Vec::new());
        let b = || ("b.lz4", fx("b.lz4"));
        let old = || ("a.lz4", b"old\n".to_vec());
        let mut cases = vec![
            // Standard input to standard output, and to a file.
            piped("lz4", &[], vec![], text()),
            piped("lz4", &["-", "o.lz4"], vec![], text()),
            piped("unlz4", &[], vec![], fx("b.lz4")),
            piped("unlz4", &["-", "o"], vec![], fx("b.lz4")),
            piped("lz4", &["-d", "stdin", "o"], vec![], fx("b.lz4")),
            // Several files to standard output, and as a list.
            lz4_case("lz4", &["-m", "-c", "a", "e"], vec![a(), e()]),
            lz4_case("lz4", &["-m", "a", "e"], vec![a(), e()]),
            lz4_case("lz4", &["-m", "-d", "b.lz4"], vec![b()]),
            lz4_case("lz4cat", &["b.lz4", "b.lz4"], vec![b()]),
            lz4_case("lz4", &["-dc", "-m", "b.lz4", "b.lz4"], vec![b()]),
            piped("lz4", &["-m", "stdin", "e"], vec![e()], text()),
            piped("lz4", &["-m", "e", "stdin"], vec![e()], text()),
            // Keep, remove, force.
            lz4_case("lz4", &["a"], vec![a()]),
            lz4_case("lz4", &["-k", "a"], vec![a()]),
            lz4_case("lz4", &["--rm", "a"], vec![a()]),
            lz4_case("lz4", &["--rm", "-m", "a", "e"], vec![a(), e()]),
            lz4_case("lz4", &["--rm", "a", "o.lz4"], vec![a()]),
            lz4_case("unlz4", &["--rm", "b.lz4"], vec![b()]),
            lz4_case("lz4", &["--rm", "-dc", "b.lz4"], vec![b()]),
            lz4_case("lz4", &["-f", "a"], vec![a(), old()]),
            lz4_case("lz4", &["-f", "-m", "a", "e"], vec![a(), e(), old()]),
            lz4_case(
                "unlz4",
                &["-f", "b.lz4"],
                vec![b(), ("b", b"old\n".to_vec())],
            ),
            // The overwrite question.
            piped("lz4", &["a"], vec![a(), old()], b"y\n".to_vec()),
            piped("lz4", &["a"], vec![a(), old()], b"n\n".to_vec()),
            piped("lz4", &["a"], vec![a(), old()], b"".to_vec()),
            piped("lz4", &["a"], vec![a(), old()], b"yes please\n".to_vec()),
            piped("lz4", &["a"], vec![a(), old()], b" y\n".to_vec()),
            piped("lz4", &["-q", "a"], vec![a(), old()], b"y\n".to_vec()),
            piped("lz4", &["-m", "a"], vec![a(), old()], b"y\n".to_vec()),
            piped("lz4", &["-", "e"], vec![e()], b"y\nhello".to_vec()),
            piped(
                "unlz4",
                &["b.lz4"],
                vec![b(), ("b", b"x".to_vec())],
                b"Y".to_vec(),
            ),
            // Symbolic links: followed.
            set_up(lz4_case("lz4", &["la"], vec![a()]), link_a_to_la),
            set_up(lz4_case("lz4", &["dangle"], vec![]), dangling),
            set_up(lz4_case("lz4", &["-m", "la"], vec![a()]), link_a_to_la),
            // Metadata: mode and mtime are the input's.
            set_up(lz4_case("lz4", &["a"], vec![a()]), mode_640_a),
            set_up(
                lz4_case("lz4", &["-d", "b.lz4", "o"], vec![b()]),
                mode_604_b,
            ),
            set_up(
                lz4_case("lz4", &["-f", "a", "o"], vec![a(), ("o", vec![])]),
                mode_640_a,
            ),
            // `--rm` of standard input removes a file named `stdin`.
            set_up(piped("lz4", &["-c", "--rm"], vec![], text()), stdin_file),
            // Trees.
            set_up(lz4_case("lz4", &["-r", "d"], vec![a()]), tree),
            set_up(lz4_case("lz4", &["-r", "-c", "d"], vec![a()]), tree),
            set_up(
                lz4_case("lz4", &["-r", "-d", "d"], vec![a()]),
                tree_of_frames,
            ),
            set_up(lz4_case("lz4", &["-r", "d", "a"], vec![a()]), tree),
            set_up(lz4_case("lz4", &["-dr", "d"], vec![a()]), tree_of_frames),
            set_up(lz4_case("lz4", &["-m", "d", "a"], vec![a()]), tree),
            // Directories and unreadable inputs.
            set_up(lz4_case("lz4", &["d"], vec![]), mkdir_d),
            set_up(lz4_case("lz4", &["-d", "d.lz4", "o"], vec![]), mkdir_dlz4),
            set_up(lz4_case("unlz4", &["b.lz4"], vec![b()]), unreadable_b),
            lz4_case("lz4", &["-d", "-f", "nosuch.lz4", "a"], vec![a()]),
        ];
        // `-r -c d` writes the tree's files in the directory's own order,
        // which only byte identity (the C tier) can judge.
        if !EXACT {
            cases.retain(|c| c.args != ["-r", "-c", "d"]);
        }
        check("files_match_the_reference", &cases);
    }

    /// A terminal as standard output: refused without `-c`, written with
    /// it; a file named is written whatever standard output is.
    #[test]
    fn a_terminal_output_matches_the_reference() {
        let mut cases = Vec::new();
        for args in [
            &["-c", "a"][..],
            &["a"],
            &["-d", "-c", "b.lz4"],
            &["a", "-"],
            &["-m", "-t", "b.lz4"],
        ] {
            let mut c = lz4_case("lz4", args, vec![("a", text()), ("b.lz4", fx("b.lz4"))]);
            c.tty_stdout = true;
            cases.push(c);
        }
        let mut c = piped("lz4", &["-c"], vec![], text());
        c.tty_stdout = true;
        cases.push(c);
        check("a_terminal_output_matches_the_reference", &cases);
    }

    // ---- decompression and test ----

    /// The frames every decoder name reads: the reference's own, over the
    /// inputs, with the frame options.
    fn frames() -> Vec<(&'static str, Vec<u8>)> {
        let mut v = Vec::new();
        for (name, data) in inputs() {
            if name == "rep" {
                continue;
            }
            for (tag, opts) in [
                ("", &[][..]),
                ("bdx", &["-B4", "-BD", "-BX"]),
                ("cs", &["--content-size", "--no-frame-crc"]),
                ("l", &["-l"]),
                ("hc", &["-9"]),
            ] {
                let mut args = vec!["-c", "-q"];
                args.extend_from_slice(opts);
                v.push((leak(format!("{name}{tag}.lz4")), made(&args, &data)));
            }
        }
        v.push(("rep.lz4", made(&["-c", "-q"], &repetitive(9 << 20))));
        v.push(("repl.lz4", made(&["-c", "-q", "-l"], &repetitive(9 << 20))));
        v
    }

    /// Every frame through `unlz4` (the derived name), `lz4cat`, `lz4 -d`
    /// into a named file, and `lz4 -t`.
    #[test]
    fn every_frame_decodes_as_the_reference_decodes_it() {
        let mut cases = Vec::new();
        for (name, frame) in frames() {
            let files = || vec![(name, frame.clone())];
            cases.push(lz4_case("unlz4", &[name], files()));
            cases.push(lz4_case("lz4cat", &[name], files()));
            cases.push(lz4_case("lz4", &["-d", name, "o"], files()));
            cases.push(lz4_case("lz4", &["-t", name], files()));
            cases.push(piped("lz4", &["-t"], vec![], frame.clone()));
        }
        check("every_frame_decodes_as_the_reference_decodes_it", &cases);
    }

    /// The offsets of a frame's structure: the header's fields, each block's
    /// size word, data and checksum, the end mark and the content checksum.
    fn boundaries(frame: &[u8]) -> Vec<usize> {
        let flg = frame[4];
        let header = 7 + if flg & 8 != 0 { 8 } else { 0 } + if flg & 1 != 0 { 4 } else { 0 };
        let bcrc = if flg & 0x10 != 0 { 4 } else { 0 };
        let mut v = vec![1, 2, 3, 4, 5, 6, header - 1, header];
        let mut at = header;
        loop {
            let word = u32::from_le_bytes(frame[at..at + 4].try_into().unwrap());
            v.extend([at + 1, at + 3, at + 4]);
            at += 4;
            if word == 0 {
                break;
            }
            let len = (word & 0x7fff_ffff) as usize;
            v.extend([at + 1, at + len / 2, at + len]);
            at += len;
            if bcrc > 0 {
                v.extend([at + 2, at + bcrc]);
                at += bcrc;
            }
        }
        if flg & 4 != 0 {
            v.extend([at + 1, at + 3]);
        }
        v.retain(|&n| n < frame.len());
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Review Focus 3/4's neighbours: frames cut at every structural
    /// boundary, legacy frames cut inside their words and blocks, and one
    /// byte flipped in the header, a block, a block size word and each
    /// checksum, under `-t` and `-dc`.
    #[test]
    fn damaged_frames_fail_as_the_reference_fails() {
        let plain = mixed(150 << 10, 46);
        let frame = made(&["-c", "-q", "-B4", "-BD", "-BX", "--content-size"], &plain);
        let legacy = made(&["-c", "-q", "-l"], &plain);
        let mut damaged: Vec<Vec<u8>> = Vec::new();
        for cut in boundaries(&frame) {
            damaged.push(frame[..cut].to_vec());
        }
        for cut in [1, 3, 4, 5, 7, 8, 9, 20, legacy.len() - 1] {
            damaged.push(legacy[..cut].to_vec());
        }
        // FLG, BD, the content size, the header checksum, the first block's
        // size word and data, its checksum, the end mark, the content
        // checksum.
        let first_block = 15 + 4;
        for at in [4, 5, 8, 14, 15, 17, first_block + 10, first_block + 300] {
            damaged.push(flipped(frame.clone(), at as isize));
        }
        for at in [-1, -5, -9] {
            damaged.push(flipped(frame.clone(), at));
        }
        damaged.push(flipped(legacy.clone(), 6));
        damaged.push(flipped(legacy.clone(), 20));
        let mut cases = Vec::new();
        for (i, d) in damaged.into_iter().enumerate() {
            let name = leak(format!("x{i}.lz4"));
            cases.push(lz4_case("lz4", &["-t", name], vec![(name, d.clone())]));
            cases.push(lz4_case("lz4", &["-dc", name], vec![(name, d.clone())]));
            cases.push(lz4_case("lz4", &["-d", name, "o"], vec![(name, d)]));
        }
        check("damaged_frames_fail_as_the_reference_fails", &cases);
    }

    // ---- Review Focus 1-5 ----

    /// Review Focus 1: a 64 MiB stream decodes in bounded memory (peak RSS
    /// under 32 MiB) on both tiers, as a frame of 4 MiB blocks and as a
    /// legacy frame of 8 MiB blocks.
    #[test]
    fn lz4cat_streams_a_large_input() {
        const N: usize = 64 << 20;
        if lz4_dir().is_none() {
            return;
        }
        let plain = mixed(N, 47);
        for opts in [&["-1"][..], &["-l"], &["-B4", "-BD"]] {
            let mut args = vec!["-c", "-q"];
            args.extend_from_slice(opts);
            let frame = made(&args, &plain);
            let peak = decoder_peak_rss("lz4cat", "big.lz4", &frame, &plain, &[("LC_ALL", "C")]);
            assert!(
                peak < 32 << 20,
                "{opts:?}: peak memory {peak} bytes is not under 32 MiB"
            );
        }
    }

    /// The status of `exe big.lz4` (argv[0] `name`) whose standard output is
    /// closed after the first read, under the default SIGPIPE disposition:
    /// the status and standard error.
    fn closed_pipe(
        exe: &Path,
        name: &str,
        args: &[&str],
        dir: &Path,
    ) -> (std::process::ExitStatus, String) {
        use std::io::Read;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        let mut child = spawn(
            Command::new(exe)
                .arg0(name)
                .args(args)
                .current_dir(dir)
                .env_clear()
                .env("LC_ALL", "C")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )
        .unwrap();
        let mut out = child.stdout.take().unwrap();
        let mut buf = [0u8; 4096];
        let _ = out.read(&mut buf).unwrap();
        drop(out);
        let st = child.wait().unwrap();
        let mut err = String::new();
        let _ = child.stderr.take().unwrap().read_to_string(&mut err);
        (st, err)
    }

    /// Review Focus 1: `lz4cat big.lz4 | head` and `lz4 -c big | head` end
    /// stuffr by SIGPIPE with nothing said. The reference races here (its
    /// writing thread and the signal; probed 2026-10-16): it dies by
    /// SIGPIPE, sometimes after printing its write error or a start of it,
    /// and under load it sometimes exits with that error instead (`Error
    /// 38` / `Error 70`).
    /// Each of those is accepted from the reference; stuffr's answer is the
    /// first, always.
    #[test]
    fn lz4cat_into_a_closed_pipe() {
        use interrupt::big_input;
        use std::os::unix::process::ExitStatusExt;
        let Some(dir) = lz4_dir() else { return };
        // Safe as `at`: only this test builds the name, and it has the pid.
        let work = ScratchDir::at(
            std::env::temp_dir().join(format!("stuffr-lz4cat-pipe-{}", std::process::id())),
        );
        fs::create_dir_all(&*work).unwrap();
        let big = big_input(48);
        fs::write(work.join("big"), &big).unwrap();
        fs::write(work.join("big.lz4"), made(&["-1", "-q", "-c"], &big)).unwrap();
        let stuffr = Path::new(env!("CARGO_BIN_EXE_stuffr"));
        let reference = Path::new(dir).join("lz4");
        for (name, args, msg) in [
            (
                "lz4cat",
                &["big.lz4"][..],
                "Error 70 : Write error : cannot write decoded block \n",
            ),
            (
                "lz4",
                &["-T1", "-c", "big"][..],
                "Error 38 : Write error : cannot write compressed block \n",
            ),
        ] {
            let (theirs, their_err) = closed_pipe(&reference, name, args, &work);
            let code = msg[6..8].parse::<i32>().unwrap();
            // Killed by SIGPIPE, the reference may have printed nothing,
            // the whole message or any start of it (it can die mid-write:
            // `msg` without its trailing " \n").
            let raced = theirs.signal() == Some(libc::SIGPIPE) && msg.starts_with(&*their_err);
            let answered = theirs.code() == Some(code) && their_err == msg;
            assert!(
                raced || answered,
                "reference {name}: {theirs:?} {their_err:?}"
            );
            let (ours, our_err) = closed_pipe(stuffr, name, args, &work);
            assert_eq!(
                ours.signal(),
                Some(libc::SIGPIPE),
                "stuffr as {name}: {ours:?}"
            );
            assert_eq!(our_err, "", "stuffr as {name}");
        }
    }

    /// Review Focus 2: several inputs where one fails: the same messages,
    /// the same exit code (lz4 counts the inputs that failed; an `Error N`
    /// ends the run with N), the good outputs written, and `--rm` removing
    /// only what was processed.
    #[test]
    fn several_files_one_failing() {
        let a = || ("a", text());
        let c = || ("c", b"cee\n".to_vec());
        let b = || ("b.lz4", fx("b.lz4"));
        let bad = || ("bad.lz4", fx("bad_data.lz4"));
        let c4 = || ("c.lz4", made(&["-c", "-q"], b"cee\n"));
        let lg = || ("lg.lz4", fx("leg_garbage100.lz4"));
        let cases = vec![
            lz4_case("lz4", &["-m", "a", "missing", "c"], vec![a(), c()]),
            lz4_case("lz4", &["-m", "a", "n1", "n2", "n3", "c"], vec![a(), c()]),
            lz4_case(
                "unlz4",
                &["-m", "b.lz4", "bad.lz4", "c.lz4"],
                vec![b(), bad(), c4()],
            ),
            lz4_case("lz4", &["-m", "--rm", "a", "missing"], vec![a()]),
            lz4_case(
                "lz4",
                &["-m", "--rm", "-d", "b.lz4", "bad.lz4", "c.lz4"],
                vec![b(), bad(), c4()],
            ),
            lz4_case("lz4", &["-m", "-d", "lg.lz4", "b.lz4"], vec![lg(), b()]),
            // 0.17.0 fuzz smoke: one name twice, decoded by its suffix.
            lz4_case("lz4", &["-m", "-1", "lg.lz4", "lg.lz4"], vec![lg()]),
            lz4_case("lz4", &["-m", "lg.lz4", "lg.lz4"], vec![lg()]),
            lz4_case(
                "lz4",
                &["-m", "-d", "--rm", "lg.lz4", "b.lz4"],
                vec![lg(), b()],
            ),
            lz4_case(
                "lz4",
                &["-m", "-d", "n1.lz4", "x", "y", "b.lz4"],
                vec![b(), ("x", vec![]), ("y", vec![])],
            ),
            lz4_case(
                "lz4cat",
                &["b.lz4", "missing.lz4", "c.lz4"],
                vec![b(), c4()],
            ),
            lz4_case(
                "lz4",
                &["-tm", "b.lz4", "bad.lz4", "c.lz4"],
                vec![b(), bad(), c4()],
            ),
            lz4_case("lz4", &["-p", "-m", "a", "missing"], vec![a()]),
            lz4_case("lz4", &["-p", "-t", "bad.lz4"], vec![bad()]),
        ];
        check("several_files_one_failing", &cases);
    }

    /// Review Focus 3: two frames, a skippable frame between them, a legacy
    /// frame then a modern one (and the other way), a frame followed by 1,
    /// 3, 4 and 100 bytes of garbage and by zeros, and the skippable
    /// frame's edges, from a file and from a pipe.
    #[test]
    fn concatenation_and_trailing_data() {
        let good = made(&["-c", "-q"], &text());
        let legacy = made(&["-c", "-q", "-l"], &text());
        let skip = cat(&[&[0x50, 0x2a, 0x4d, 0x18], &le32(3), b"abc"]);
        let streams: Vec<Vec<u8>> = vec![
            cat(&[&good, &good]),
            cat(&[&good, &skip, &good]),
            cat(&[&skip, &skip, &good]),
            cat(&[&legacy, &good]),
            cat(&[&good, &legacy]),
            cat(&[&legacy, &skip, &good]),
            cat(&[&legacy, &legacy]),
            cat(&[&skip, &legacy]),
            cat(&[&good, b"A"]),
            cat(&[&good, b"AAA"]),
            cat(&[&good, b"AAAA"]),
            cat(&[&good, &[b'A'; 100]]),
            cat(&[&good, &[0; 8]]),
            cat(&[&legacy, b"A"]),
            cat(&[&legacy, b"AAA"]),
            cat(&[&legacy, &[b'A'; 100]]),
            cat(&[&legacy, &[0; 4]]),
            cat(&[&skip, b"AB"]),
            cat(&[&skip, b"garbage!"]),
            cat(&[&legacy, &skip, b"garbage!"]),
            cat(&[&[0x50, 0x2a, 0x4d, 0x18], &le32(10), b"abc"]),
            cat(&[&[0x50, 0x2a, 0x4d, 0x18], &le32(0xffff_ffff), b"abc"]),
            cat(&[&[0x5f, 0x2a, 0x4d, 0x18], &le32(0)]),
            cat(&[&legacy, &[0x50, 0x2a, 0x4d, 0x18, 1]]),
            LEGACY.to_vec(),
            LEGACY[..2].to_vec(),
            Vec::new(),
        ];
        let mut cases = Vec::new();
        for (i, s) in streams.into_iter().enumerate() {
            let name = leak(format!("s{i}.lz4"));
            cases.push(lz4_case("lz4", &["-d", name, "o"], vec![(name, s.clone())]));
            cases.push(lz4_case("lz4", &["-dc", name], vec![(name, s.clone())]));
            cases.push(lz4_case("lz4cat", &[name], vec![(name, s.clone())]));
            cases.push(piped("lz4", &["-d", "-", "o"], vec![], s.clone()));
            cases.push(piped("lz4", &["-dcf"], vec![], s));
        }
        check("concatenation_and_trailing_data", &cases);
    }

    /// A block word of `0x8000_0000` (stored, length 0) is an empty block,
    /// not the end mark: liblz4 ends a frame at a word of exactly 0. With
    /// and without block and content checksums, followed by more blocks, by
    /// garbage and by nothing (found by review of the zstd family's lz4
    /// decode, which first spun on it on the pure tier).
    #[test]
    fn a_stored_block_of_length_zero() {
        let empty_crc = le32(0x02CC_5D05);
        let stored0 = le32(0x8000_0000);
        let stored2 = le32(0x8000_0002);
        let end = le32(0);
        let streams: Vec<Vec<u8>> = vec![
            cat(&[&header(0x60, 0x40, &[]), &stored0, &end, b"xxxx"]),
            cat(&[&header(0x64, 0x40, &[]), &stored0, &end, &empty_crc]),
            cat(&[&header(0x64, 0x40, &[]), &stored0, &end]),
            cat(&[
                &header(0x60, 0x40, &[]),
                &stored0,
                &stored2,
                b"ab",
                &stored0,
                &end,
            ]),
            cat(&[&header(0x70, 0x40, &[]), &stored0, &empty_crc, &end]),
            cat(&[&header(0x70, 0x40, &[]), &stored0, &end]),
            cat(&[&header(0x60, 0x40, &[]), &stored0]),
            cat(&[&header(0x60, 0x70, &[]), &stored0, &end]),
        ];
        let mut cases = Vec::new();
        for (i, s) in streams.into_iter().enumerate() {
            let name = leak(format!("z{i}.lz4"));
            cases.push(lz4_case("lz4", &["-d", name, "o"], vec![(name, s.clone())]));
            cases.push(lz4_case("lz4", &["-t", name], vec![(name, s.clone())]));
            cases.push(lz4_case("lz4cat", &[name], vec![(name, s.clone())]));
            cases.push(piped("lz4", &["-d", "-", "o"], vec![], s.clone()));
        }
        check("a_stored_block_of_length_zero", &cases);
    }

    /// Review Focus 4: a 4 MiB frame whose block word claims 16 MiB, a
    /// 64 KiB frame claiming 128 KiB, a legacy block claiming more than
    /// `LZ4_compressBound(8 MiB)` and one just under it, a content size of
    /// 2^63: the reference's exit and message, before anything is
    /// allocated (peak RSS under 32 MiB on both tiers).
    #[test]
    fn hostile_block_sizes() {
        let hostile: Vec<(&str, Vec<u8>)> = vec![
            ("blk_16m.lz4", fx("blk_16m.lz4")),
            ("blk_too_big.lz4", fx("blk_too_big.lz4")),
            (
                "blk_2g.lz4",
                cat(&[&header(0x64, 0x70, &[]), &le32(0x7fff_ffff), &[b'x'; 16]]),
            ),
            ("leg_huge.lz4", fx("leg_huge.lz4")),
            ("leg_8m.lz4", fx("leg_8m.lz4")),
            ("leg_bound.lz4", cat(&[&LEGACY, &le32(8_421_520), b"abc"])),
            ("leg_bound1.lz4", cat(&[&LEGACY, &le32(8_421_521), b"abc"])),
            ("cs_2p63.lz4", fx("cs_2p63.lz4")),
        ];
        let mut cases = Vec::new();
        for (name, data) in &hostile {
            cases.push(lz4_case("lz4", &["-t", name], vec![(name, data.clone())]));
            cases.push(lz4_case("lz4", &["-dc", name], vec![(name, data.clone())]));
        }
        check("hostile_block_sizes", &cases);
        if lz4_dir().is_none() {
            return;
        }
        for (name, data) in &hostile {
            // Linux: these runs end too soon for `RssAnon` sampling (CI run
            // 39166896170 never saw one), so the bound is checked as a cap:
            // under a 32 MiB data segment stuffr answers exactly as without
            // one (`data_limited_run`).
            #[cfg(target_os = "linux")]
            {
                let env = [("LC_ALL", "C")];
                let free = data_limited_run("lz4", &["-t", name], name, data, &env, None);
                let capped =
                    data_limited_run("lz4", &["-t", name], name, data, &env, Some(32 << 20));
                assert_eq!(
                    capped, free,
                    "{name}: under a 32 MiB data limit stuffr answers differently"
                );
            }
            #[cfg(not(target_os = "linux"))]
            {
                let (_, _, _, peak) =
                    peak_rss_run("lz4", &["-t", name], name, data, &[("LC_ALL", "C")]);
                assert!(
                    peak < 32 << 20,
                    "{name}: peak memory {peak} bytes is not under 32 MiB"
                );
            }
        }
    }

    /// Review Focus 5: where the output goes, with standard output a pipe
    /// and (for the refusals) a terminal.
    #[test]
    fn where_the_output_goes() {
        let files = || {
            vec![
                ("f", text()),
                ("g", b"gee\n".to_vec()),
                ("f.lz4", fx("b.lz4")),
            ]
        };
        let to_stdout = |args: &[&'static str]| Case {
            expect_stdout_plain: Some(text()),
            ..lz4_case("lz4", args, files())
        };
        let mut cases = vec![
            lz4_case("lz4", &["-z", "f"], files()),
            to_stdout(&["f", "-"]),
            to_stdout(&["f", "stdout"]),
            lz4_case("lz4", &["f", "null"], files()),
            to_stdout(&["-c", "f"]),
            lz4_case("lz4", &["-z", "-m", "f", "g"], files()),
            lz4_case("unlz4", &["f"], files()),
            lz4_case("unlz4", &["f.lz4", "out"], files()),
            lz4_case("lz4", &["-d", "f.lz4", "null"], files()),
            lz4_case("lz4", &["-t", "f.lz4", "-"], files()),
            piped("lz4", &[], vec![], text()),
            piped("lz4", &["-", "o.lz4"], vec![], text()),
            // `/dev/null`, spelled exactly so, is the `null` output (probe
            // 2026-10-16): no question, the summary, nothing written.
            lz4_case("lz4", &["f", "/dev/null"], files()),
            lz4_case("lz4", &["-d", "f.lz4", "/dev/null"], files()),
            lz4_case("lz4", &["-t", "f.lz4", "/dev/null"], files()),
            lz4_case("lz4", &["--rm", "f", "/dev/null"], files()),
            lz4_case("lz4", &["g", "/dev/null", "-m", "-d", "f.lz4"], files()),
            // Other spellings and a link to it are files that exist: asked
            // about, and refused at end of input.
            lz4_case("lz4", &["f", "//dev/null"], files()),
            lz4_case("lz4", &["-d", "f.lz4", "/dev//null"], files()),
            set_up(lz4_case("lz4", &["f", "nl"], files()), link_to_dev_null),
            lz4_case("lz4", &["f", "/dev/zero"], files()),
        ];
        for args in [&["-z", "f"][..], &["f", "-"], &["-c", "f"], &["f", "null"]] {
            let mut c = lz4_case("lz4", args, files());
            c.tty_stdout = true;
            cases.push(c);
        }
        let mut c = piped("lz4", &[], vec![], text());
        c.tty_stdout = true;
        cases.push(c);
        check("where_the_output_goes", &cases);
    }

    /// Sparse output (decompression only): a file gets the same bytes and
    /// size with or without it; standard output is not sparse unless
    /// `--sparse` asks, and a pipe then refuses the first seek (lz4 seeks
    /// before every piece of data, an empty skip included: `Error 72` for
    /// data in whole words, `Error 74` after the last whole word, `Error
    /// 69` for the final skip of an all-zero output).
    #[test]
    fn sparse_output_matches_the_reference() {
        let mut zeros = vec![0u8; 300_000];
        zeros[100] = b'A';
        zeros[200_000] = b'B';
        let streams: Vec<(&str, Vec<u8>)> = vec![
            ("holes.lz4", made(&["-c", "-q"], &zeros)),
            ("zeros.lz4", made(&["-c", "-q"], &[0u8; 100_000])),
            ("z10.lz4", made(&["-c", "-q"], &[0u8; 10])),
            ("a8.lz4", made(&["-c", "-q"], b"AAAAAAAA")),
            ("z8a.lz4", made(&["-c", "-q"], b"\0\0\0\0\0\0\0\0A")),
            ("zl.lz4", made(&["-c", "-q", "-l"], &[0u8; 70_000])),
            ("empty.lz4", fx("empty.lz4")),
        ];
        let mut cases = Vec::new();
        for (name, s) in &streams {
            let f = || vec![(*name, s.clone())];
            cases.push(lz4_case("lz4", &["-d", name, "o"], f()));
            cases.push(lz4_case("lz4", &["-d", "--no-sparse", name, "o"], f()));
            cases.push(lz4_case("lz4", &["-d", "--sparse", name, "o"], f()));
            cases.push(lz4_case("lz4", &["--sparse", "-dc", name], f()));
            cases.push(lz4_case("lz4", &["-dc", name], f()));
        }
        check("sparse_output_matches_the_reference", &cases);
    }

    /// The input's mode and time go only onto a regular output (probe
    /// 2026-10-16: `lz4 -f b fifo`, `b` mode 600, leaves the FIFO 644).
    #[test]
    fn metadata_goes_only_onto_a_regular_output() {
        use std::os::unix::fs::PermissionsExt;
        let Some(dir) = lz4_dir() else { return };
        let mode_after = |exe: &Path, tag: &str| -> u32 {
            // Safe as `at`: only this test builds it, with the pid; its two calls
            // pass "ref" and "ours".
            let w = ScratchDir::at(
                std::env::temp_dir().join(format!("stuffr-lz4-fifo-{tag}-{}", std::process::id())),
            );
            fs::create_dir_all(&*w).unwrap();
            fs::write(w.join("b"), text()).unwrap();
            fs::set_permissions(w.join("b"), fs::Permissions::from_mode(0o600)).unwrap();
            let fifo = w.join("fifo");
            let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: `c` is a NUL-terminated path that outlives the call.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
            fs::set_permissions(&fifo, fs::Permissions::from_mode(0o644)).unwrap();
            let reader = {
                let fifo = fifo.clone();
                std::thread::spawn(move || {
                    let mut v = Vec::new();
                    std::io::Read::read_to_end(&mut fs::File::open(fifo).unwrap(), &mut v).unwrap();
                    v
                })
            };
            let o = output(
                std::process::Command::new(exe)
                    .args(["-q", "-f", "b", "fifo"])
                    .current_dir(&*w)
                    .stdin(std::process::Stdio::null()),
            )
            .unwrap();
            assert!(
                o.status.success(),
                "{exe:?}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            let got = reader.join().unwrap();
            assert!(
                got.starts_with(&[0x04, 0x22, 0x4d, 0x18]),
                "{exe:?} wrote no frame"
            );
            fs::symlink_metadata(&fifo).unwrap().permissions().mode() & 0o7777
        };
        // Safe as `at`: only this test builds the name, and it has the pid.
        let link_dir = ScratchDir::at(
            std::env::temp_dir().join(format!("stuffr-lz4-fifo-bin-{}", std::process::id())),
        );
        fs::create_dir_all(&*link_dir).unwrap();
        let link = link_dir.join("lz4");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
        let theirs = mode_after(&Path::new(dir).join("lz4"), "ref");
        assert_eq!(theirs, 0o644, "the reference changed the FIFO's mode");
        assert_eq!(mode_after(&link, "ours"), theirs);
    }

    /// An output that is the input itself (probe, lz4 1.11.0, §1.10): lz4
    /// refuses it, `NAME: input and output are the same file; not
    /// overwritten ` (the output's name; display level 1), exit 1, the input
    /// kept, `-f` or not, through a hard link or a symbolic link too, and in
    /// `-m` mode; stuffr does the same. Spec deviation 3 is left only for
    /// standard input redirected from the output file, which lz4 truncates
    /// before reading it (the data is lost: pinned on the reference) and
    /// stuffr refuses with lz4's own words.
    #[test]
    fn an_input_that_is_its_output_is_never_lost() {
        // Safe as `at`: only this test builds the name, and it has the pid.
        let dir = ScratchDir::at(
            std::env::temp_dir().join(format!("stuffr-lz4-same-{}", std::process::id())),
        );
        fs::create_dir_all(&*dir).unwrap();
        let link = dir.join("lz4");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
        let run = |exe: &Path, args: &[&str], stdin: Option<&str>| {
            fs::write(dir.join("a"), text()).unwrap();
            fs::write(dir.join("s.lz4"), fx("b.lz4")).unwrap();
            fs::write(dir.join("y.lz4"), fx("b.lz4")).unwrap();
            for (name, to) in [
                ("h", None),
                ("sa", Some("a")),
                ("sl", Some("s.lz4")),
                ("y", Some("y.lz4")),
            ] {
                let _ = fs::remove_file(dir.join(name));
                match to {
                    None => fs::hard_link(dir.join("a"), dir.join(name)).unwrap(),
                    Some(t) => std::os::unix::fs::symlink(t, dir.join(name)).unwrap(),
                }
            }
            let mut cmd = std::process::Command::new(exe);
            cmd.args(args).current_dir(&*dir).env("LC_ALL", "C");
            cmd.stdin(match stdin {
                Some(f) => std::process::Stdio::from(fs::File::open(dir.join(f)).unwrap()),
                None => std::process::Stdio::null(),
            });
            let o = output(&mut cmd).unwrap();
            (
                o.status.code(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
                fs::read(dir.join("a")).unwrap(),
                fs::read(dir.join("s.lz4")).unwrap(),
                fs::read(dir.join("y.lz4")).unwrap(),
            )
        };
        let refused =
            |out: &str| format!("{out}: input and output are the same file; not overwritten \n");
        let kept = (text(), fx("b.lz4"), fx("b.lz4"));
        let cases: [(&[&str], &str); 9] = [
            (&["-f", "a", "a"], "a"),
            (&["a", "a"], "a"),
            (&["-q", "a", "a"], "a"),
            (&["-df", "s.lz4", "s.lz4"], "s.lz4"),
            (&["-d", "s.lz4", "s.lz4"], "s.lz4"),
            (&["-f", "h", "a"], "a"),
            (&["-f", "a", "sa"], "sa"),
            (&["-df", "s.lz4", "sl"], "sl"),
            (&["-d", "-m", "y.lz4"], "y"),
        ];
        let reference = lz4_dir().map(|d| Path::new(d).join("lz4"));
        for (args, out) in cases {
            let (code, err, a, s, y) = run(&link, args, None);
            assert_eq!(
                (code, err.as_str()),
                (Some(1), refused(out).as_str()),
                "{args:?}"
            );
            assert_eq!((a, s, y), kept, "{args:?}: the input changed");
            if let Some(r) = &reference {
                let (code, err, a, s, y) = run(r, args, None);
                assert_eq!(
                    (code, err.as_str()),
                    (Some(1), refused(out).as_str()),
                    "reference {args:?}"
                );
                assert_eq!((a, s, y), kept, "reference {args:?}: the input changed");
            }
        }
        // `-qq` hides the line; the refusal stands.
        let (code, err, a, _, _) = run(&link, &["-qq", "-f", "a", "a"], None);
        assert_eq!((code, err.as_str(), a), (Some(1), "", text()));
        // Deviation 3: standard input redirected from the output.
        let (code, err, a, _, _) = run(&link, &["-f", "-", "a"], Some("a"));
        assert_eq!((code, err.as_str()), (Some(1), refused("a").as_str()));
        assert_eq!(a, text(), "the input changed");
        if let Some(r) = &reference {
            let (code, _, a, _, _) = run(r, &["-f", "-", "a"], Some("a"));
            assert_eq!(code, Some(0));
            assert_ne!(
                a,
                text(),
                "lz4 -f - a < a kept its input: deviation 3 is moot"
            );
        }
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

    /// SIGINT, SIGTERM and SIGHUP during `lz4 -12 -T1 big out.lz4`, `lz4
    /// -12 -T4 big out.lz4` and `unlz4 big.lz4 out`: all die by the signal
    /// and leave the partial output.
    #[test]
    fn an_interrupt_leaves_the_partial_output_and_dies_by_the_signal() {
        use interrupt::*;
        let _serial = interrupt_lock();
        let Some(dir) = lz4_dir() else { return };
        let tag = std::process::id();
        // Safe as `at`: `tag` is the pid, only this test builds the names, and it holds
        // `interrupt_lock`.
        let ref_dir =
            ScratchDir::at(std::env::temp_dir().join(format!("stuffr-lz4-int-ref-{tag}")));
        let our_dir = ScratchDir::at(std::env::temp_dir().join(format!("stuffr-lz4-int-{tag}")));
        let stuffr = Path::new(env!("CARGO_BIN_EXE_stuffr"));
        let plain = big_input;
        let packed = |mib: usize| {
            big_input_through(ref_lz4(), &["-1", "-q", "-c"], fast_size(mib))
                .expect("the reference could not run lz4 -1")
        };
        type Job<'a> = (
            &'a str,
            &'a [&'a str],
            &'a str,
            &'a str,
            &'a dyn Fn(usize) -> Vec<u8>,
        );
        let jobs: [Job; 3] = [
            (
                "lz4",
                &["-12", "-T1", "big", "out.lz4"],
                "big",
                "out.lz4",
                &plain,
            ),
            // Review Focus (0.26.0 Task 4): liblz4 1.11.0's own workers on
            // a multi-job input (C tier; the pure tier has none). No
            // handler is installed, so whichever thread the signal lands
            // on, the process dies of it and the partial output stays,
            // as the reference's does.
            (
                "lz4",
                &["-12", "-T4", "big", "out.lz4"],
                "big",
                "out.lz4",
                &plain,
            ),
            ("unlz4", &["big.lz4", "out"], "big.lz4", "out", &packed),
        ];
        // A reference that hung after the signal is skipped, by name; on CI
        // every comparison must have run, so the test cannot pass vacuously.
        let mut compared = 0;
        let mut skipped = Vec::new();
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
                    assert!(take_reference_hung(), "no reference result for {name}");
                    skipped.push(format!("{name} signal {sig}"));
                    continue;
                };
                compared += 1;
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
        println!("interrupts: {compared} compared, skipped (reference hung): {skipped:?}");
        if std::env::var_os("CI").is_some() {
            assert!(skipped.is_empty(), "CI: the reference hung on {skipped:?}");
        }
    }

    // ---- a closed pipe, with SIGPIPE ignored by the parent ----

    /// Spec deviation 4, an expected difference: with SIGPIPE ignored by the
    /// parent, lz4 inherits the ignore and answers `Error 70` (decoding) or
    /// `Error 46` (compressing; 1.10.0's `Error 38`) into a closed pipe; stuffr restores the
    /// default action in `run`, as the earlier families do (ruling T3-c),
    /// and dies of the signal with nothing said. Review Focus 1's
    /// default-disposition case is `lz4cat_into_a_closed_pipe`.
    #[test]
    fn closed_pipe_with_sigpipe_ignored() {
        use interrupt::big_input;
        use std::io::Read;
        use std::os::unix::process::{CommandExt, ExitStatusExt};
        use std::process::{Command, Stdio};
        let Some(dir) = lz4_dir() else { return };
        // Safe as `at`: only this test builds the name, and it has the pid.
        let work = ScratchDir::at(
            std::env::temp_dir().join(format!("stuffr-lz4-pipe-{}", std::process::id())),
        );
        fs::create_dir_all(&*work).unwrap();
        let big = big_input(48);
        fs::write(work.join("big"), &big).unwrap();
        fs::write(work.join("big.lz4"), made(&["-1", "-q", "-c"], &big)).unwrap();
        let run = |exe: &Path, name: &str, args: &[&str]| -> (std::process::ExitStatus, String) {
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
                out.status,
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
                46,
                // lz4 1.11.0 (1.10.0: `Error 38`).
                "Error 46 : Write error : cannot write compressed block \n",
            ),
        ] {
            let theirs = run(&reference, name, args);
            assert_eq!(
                theirs.0.code(),
                Some(code),
                "reference {name}: {:?}",
                theirs.1
            );
            assert_eq!(theirs.1, msg);
            let ours = run(stuffr, name, args);
            assert_eq!(
                ours.0.signal(),
                Some(libc::SIGPIPE),
                "stuffr as {name}: {:?}",
                ours.0
            );
            assert_eq!(ours.1, "", "stuffr as {name}");
        }
    }

    // ---- deviation 10: a symlink at an output name (stuffr only) ----

    fn out_links_to_target(w: &Path) {
        fs::write(w.join("target"), b"old target").unwrap();
        std::os::unix::fs::symlink("target", w.join("o")).unwrap();
    }
    fn out_dangles(w: &Path) {
        std::os::unix::fs::symlink("nowhere", w.join("o")).unwrap();
    }

    /// Deviation 10: a symlink at the output name, live or dangling, is an
    /// existing file: refused without `-f` (the question, answered by end
    /// of input), nothing written through it; with `-f` the link is
    /// replaced by a regular file and its target is untouched. The
    /// reference writes through the link, so this is stuffr alone.
    #[test]
    fn a_symlink_at_the_output_name_is_never_written_through() {
        let a = || ("a", text());
        let b = || ("b.lz4", fx("b.lz4"));
        for (setup, live) in [
            (out_links_to_target as fn(&Path), true),
            (out_dangles, false),
        ] {
            for (name, args, input) in [
                ("lz4", &["a", "o"][..], a()),
                ("lz4", &["-d", "b.lz4", "o"], b()),
            ] {
                let what = format!("{name} {args:?}, live {live}");
                let s = stuffr_as(&set_up(lz4_case(name, args, vec![input.clone()]), setup));
                assert_ne!(s.code, 0, "{what}: {}", s.stderr);
                let link = if live { &b"target"[..] } else { b"nowhere" };
                assert_eq!(s.tree["o"].0, link, "{what}: the link was replaced");
                if live {
                    assert_eq!(s.tree["target"].0, b"old target", "{what}");
                } else {
                    assert!(!s.tree.contains_key("nowhere"), "{what}: created");
                }

                let mut forced = vec!["-f"];
                forced.extend_from_slice(args);
                let forced: &'static [&'static str] = Box::leak(forced.into_boxed_slice());
                let s = stuffr_as(&set_up(lz4_case(name, forced, vec![input]), setup));
                assert_eq!(s.code, 0, "-f {what}: {}", s.stderr);
                let o = &s.tree["o"].0;
                assert_ne!(o.as_slice(), link, "-f {what}: still the link");
                if args[0] == "-d" {
                    assert_eq!(o, &text(), "-f {what}");
                } else {
                    assert!(o.starts_with(&[0x04, 0x22, 0x4d, 0x18]), "-f {what}");
                }
                if live {
                    assert_eq!(s.tree["target"].0, b"old target", "-f {what}");
                } else {
                    assert!(!s.tree.contains_key("nowhere"), "-f {what}: created");
                }
            }
        }
    }

    /// An output whose input is a named regular file is created 0600 and
    /// given the input's mode through its descriptor once its input
    /// succeeded; a failed decode leaves it 0600 (lz4 1.11.0, probe §1.11:
    /// 1.10.0 left 0644). From standard input it is created with 0666 less
    /// the umask and keeps that. The differential rows compare all of this
    /// with the reference; this pins stuffr's side without one.
    #[test]
    fn an_output_is_private_until_its_input_succeeded() {
        let frame = fx("b.lz4");
        let cut = frame[..frame.len() - 6].to_vec();
        let s = stuffr_as(&lz4_case(
            "lz4",
            &["-d", "c.lz4", "o"],
            vec![("c.lz4", cut.clone())],
        ));
        assert_ne!(s.code, 0, "{}", s.stderr);
        assert_eq!(s.tree["o"].1, 0o600, "a failed run widened its output");
        // A successful one gets the input's mode.
        let s = stuffr_as(&set_up(
            lz4_case("lz4", &["-d", "b.lz4", "o"], vec![("b.lz4", frame)]),
            mode_604_b,
        ));
        assert_eq!(s.code, 0, "{}", s.stderr);
        assert_eq!(s.tree["o"].1, 0o604);
        // From standard input: never 0600.
        let s = stuffr_as(&piped("lz4", &["-d", "-", "o"], vec![], cut));
        assert_ne!(s.code, 0, "{}", s.stderr);
        assert_ne!(s.tree["o"].1, 0o600, "{}", s.stderr);
    }

    // ---- lz4 1.11.0: options, levels, threads, messages (0.26.0 Task 4) ----
    //
    // Probed 2026-11-08 against /opt/homebrew/Cellar/lz4/1.11.0/bin/lz4
    // (the probe's §1.1-1.8, §1.13-1.14, and Task 4's own probes).

    /// Numbers past 32 bits, levels past `INT_MAX`, `--fast`'s and
    /// `--threads`' new strictness, `--memory` and its errors, the new
    /// long options; each case ends while parsing or compresses `a`.
    #[test]
    fn the_1_11_command_line_matches_the_reference() {
        let a = super::compat_harness::text(4000, 47);
        let parse_only: &[&[&str]] = &[
            &["-2147483648", "a"],
            &["-4294967295", "a"],
            &["-4294967296", "a"],
            &["-99999999999", "a"],
            &["-2097152K", "a"],
            &["-2048M", "a"],
            &["-4194304K", "a"],
            &["-4294967296x", "a"],
            &["--fast=2147483648", "a"],
            &["--fast=4294967295", "a"],
            &["--fast=4294967296", "a"],
            &["--fast=4294967296x", "a"],
            &["--fast=2147483648x", "a"],
            &["--fast=1x", "a"],
            &["--fast=1Kx", "a"],
            &["--fast=1G", "a"],
            &["-T4294967296", "a"],
            &["-T4194304K", "a"],
            &["-T4294967296x", "a"],
            &["-T1G", "a"],
            &["--threads=4294967296", "a"],
            &["--threads=4194304K", "a"],
            &["--threads=1G", "a"],
            &["--threads=1x", "a"],
            &["--threads4", "a"],
            &["--threadsx", "4", "-V"],
            &["-B4294967296", "a"],
            &["-B4194304K", "a"],
            &["-B4096M", "a"],
            &["-B99999999999", "a"],
            &["-B4194305K", "a"],
            &["-B4G", "a"],
            &["-B1G", "a"],
            &["-B4", "-T4294967296", "a"],
            &["-b4294967296"],
            &["-e4294967296", "a"],
            &["-i4294967296", "a"],
            &["-qq", "-2147483648", "a"],
            &["-q", "-2147483648", "a"],
            &["-2147483648", "-qq", "a"],
            &["-p", "-T4294967296"],
            &["--memory=0", "a"],
            &["--memory=00", "a"],
            &["--memory=0K", "a"],
            &["--memory=", "a"],
            &["--memory=x", "a"],
            &["--memory=-1", "a"],
            &["--memory=1g", "a"],
            &["--memory=4T", "a"],
            &["--memory=1Q", "a"],
            &["--memory=1Mx", "a"],
            &["--memory=1KiBx", "a"],
            &["--memory==1M", "a"],
            &["--memory=16777216T", "a"],
            &["--memory=18446744073709551616", "a"],
            &["--memory=17179869184G", "a"],
            &["--memory=18446744073709551616x", "a"],
            &["--memory", "a"],
            &["--memory"],
            &["--memory", "-c", "a"],
            &["--memoryx=1M", "a"],
            &["-qq", "--memory=0", "a"],
            &["-q", "--memory=0", "a"],
            &["-p", "--memory=0"],
            &["--mmap=1", "a"],
            &["--single-thread=1", "a"],
            &["--single-threadx", "a"],
            &["--threads", "-v"],
            &["--threads"],
            &["--threads", "-", "a"],
        ];
        // Compressions: the thread lines (level 2 to a file, 3 with -v).
        let compress: &[&[&str]] = &[
            &["-T1"],
            &["-T0"],
            &["-T300"],
            &["-T1024"],
            &["-T1025"],
            &["-T5000"],
            &["-T4294967295"],
            &["-T1K"],
            &["-T1M"],
            &["--threads=", "-T3"],
            &["--threads=1KiB"],
            &["--memory=40M"],
            &["--memory=40M", "-T8"],
            &["--memory=1"],
            &["--memory=1", "-T1"],
            &["--memory=1", "-T8"],
            &["--memory=1K"],
            &["--memory=1KB"],
            &["--memory=1M"],
            &["--memory=1048575"],
            &["--memory=30017171"],
            &["--memory=30017172", "-T8"],
            &["--memory=42928859", "-T8"],
            &["--memory=42928860", "-T8"],
            &["--memory=40M", "-B4"],
            &["--memory=40M", "-B5"],
            &["--memory=40M", "-B4", "-BD", "-9"],
            &["--memory=17761127", "-B6", "-T5"],
            &["--memory=17761128", "-B6", "-T5"],
            &["--memory=14287391", "-B6"],
            &["--memory=14287392", "-B6"],
            &["--memory", "50M"],
            &["--memory=1G"],
            &["--memory=1GB"],
            &["--memory=1GiB"],
            &["--memory=1Gi"],
            &["--memory=01"],
            &["--memory=99999999999"],
            &["--memory=18446744073709551615"],
            &["--memory=17179869183G"],
            &["-l"],
            &["-l", "-T5000"],
            &["--memory=40M", "-l", "-T8"],
            &["--single-thread"],
            &["-T5000", "--single-thread"],
            &["--single-thread", "-T4"],
            &["--memory=40M", "--single-thread", "-T8"],
            &["--memory=40M", "-T8", "--single-thread"],
            &["-B1024"],
            &["-B32"],
            &["-B100000", "-BD"],
            &["-T5000", "-B1024"],
            &["--memory=40M", "-B1024", "-T8"],
            &["-B65536"],
            &["-B262144"],
            &["-B1048576"],
            &["-B4194304"],
            &["-B4194305"],
            &["-B4294967295"],
            &["-B4194303K"],
            &["-B4095M"],
            &["-B1Ki"],
            &["-B1KiB"],
            &["-B1KB"],
            &["-B1MB"],
            &["--mmap"],
            &["--no-mmap"],
            &["--fast=2147483647"],
            &["--fast=1K"],
            &["--fast=1KB"],
            &["--fast=1Ki"],
            &["--fast=1KiB"],
            &["-2147483647"],
            &["-2097151K"],
            &["-1KiB"],
            &["-13"],
            &["-0"],
            &["-2"],
            &["-eK"],
        ];
        let mut cases = Vec::new();
        for args in parse_only {
            cases.push(lz4_case("lz4", args, vec![("a", a.clone())]));
        }
        for opts in compress {
            for (pre, post) in [
                (&["-v"][..], &["a", "o.lz4"][..]),
                (&[][..], &["a", "o.lz4"][..]),
                (&["-v"][..], &["-c", "a"][..]),
                (&[][..], &["-c", "a"][..]),
            ] {
                // A legacy file's time is 0.26.0 Task 5's (1.11.0 copies
                // it now): standard output only here.
                if opts.contains(&"-l") && post[0] == "a" {
                    continue;
                }
                let mut args = pre.to_vec();
                args.extend_from_slice(opts);
                args.extend_from_slice(post);
                cases.push(lz4_case("lz4", &args, vec![("a", a.clone())]));
            }
        }
        // Several files: the lines once, before the first (level 3), none at
        // `-m`'s level 1.
        for args in [
            &["-v", "-T5000", "--memory=40M", "-m", "a", "b"][..],
            &["-T5000", "-m", "a", "b"],
        ] {
            cases.push(lz4_case(
                "lz4",
                args,
                vec![("a", a.clone()), ("b", a.clone())],
            ));
        }
        for args in [
            &["-vv", "-T3", "-c", "a"][..],
            &["-vv", "--memory=40M", "-c", "a"],
            &["-vv", "-T1", "a", "o.lz4"],
        ] {
            cases.push(lz4_case("lz4", args, vec![("a", a.clone())]));
        }
        // Decoding and listing print none of them.
        let frame = made(&["-1", "-q", "-c"], &a);
        for args in [
            // (`-v` would add `Done in` after a clean decode: Task 5's.)
            &["-T5000", "-d", "a.lz4", "o"][..],
            &["--memory=1", "-d", "a.lz4", "o"],
            &["-T5000", "-t", "a.lz4"],
            &["-T5000", "--list", "a.lz4"],
            &["-v", "-T5000", "--list", "a.lz4"],
        ] {
            cases.push(lz4_case("lz4", args, vec![("a.lz4", frame.clone())]));
        }
        check("the_1_11_command_line_matches_the_reference", &cases);
    }

    /// lz4 1.11.0's help: `-h`, `-H`, under each name, and the short help
    /// after a usage error (Appendix A of the probe, verbatim).
    #[test]
    fn the_1_11_help_matches_the_reference() {
        let mut cases = Vec::new();
        for name in ["lz4", "unlz4", "lz4cat", "lz4c"] {
            for args in [&["-h"][..], &["-H"], &["--help"], &["--bogus"], &["-V"]] {
                cases.push(lz4_case(name, args, vec![]));
            }
        }
        check("the_1_11_help_matches_the_reference", &cases);
    }

    /// Refresh figures around the one-job rule (fix round 1 of 0.26.0 Task
    /// 4; the reviewer ran each 10 times): a file of one job with
    /// independent blocks is compressed by the calling thread (100,000
    /// bytes and 1 MiB, at `-T1` and `-T3`, `-B4` to `-B6`), so its figure
    /// is `--single-thread`'s, and compared; the cases of more than one job
    /// or linked blocks run too, their figures being timing
    /// ([`figures_are_timing`]). Every refresh is drawn (`-vvvv`).
    #[test]
    fn deterministic_refresh_figures_match_the_reference() {
        let mut cases = Vec::new();
        for (name, len) in [
            ("k100", 100_000),
            ("m1", 1 << 20),
            ("m1p", (1 << 20) + 1),
            ("m25", 2_500_000),
        ] {
            let data = mixed(len, 51);
            for opts in [
                &["-T3", "-B4"][..],
                &["-T1", "-B4"],
                &["-T3", "-B5"],
                &["-T3", "-B6"],
                &["-T3", "-B4", "-BD"],
                &["-T3", "-B5", "-BD"],
                &["-T1", "-B4", "--no-mmap"],
                &["-T1", "-B5"],
                &["-B4"],
            ] {
                let mut args = vec!["-vvvv"];
                args.extend_from_slice(opts);
                args.extend([name, "o.lz4"]);
                cases.push(lz4_case("lz4", &args, vec![(name, data.clone())]));
            }
        }
        check("deterministic_refresh_figures_match_the_reference", &cases);
    }

    /// Standard input redirected from a regular file (review I1 of 0.26.0
    /// Task 4): its size is known (the one-job rule, `--content-size`), it
    /// is never checked for changes (probe, 1.11.0: no warning, whatever a
    /// file named `stdin` beside it), and its figures are the reference's.
    #[test]
    fn standard_input_redirected_from_a_file_matches_the_reference() {
        use std::process::{Command, Stdio};
        let Some(_) = lz4_dir() else { return };
        // Safe as `at`: only this test builds the name, and it has the pid.
        let dir = ScratchDir::at(
            std::env::temp_dir().join(format!("stuffr-lz4-redir-{}", std::process::id())),
        );
        let data = mixed(1 << 20, 52);
        let run = |exe: &Path, args: &[&str], stdin_file: bool| {
            let _ = fs::remove_dir_all(&*dir);
            fs::create_dir_all(&*dir).unwrap();
            fs::write(dir.join("a"), &data).unwrap();
            if stdin_file {
                fs::write(dir.join("stdin"), b"a file named stdin\n").unwrap();
            }
            let o = Command::new(exe)
                .args(args)
                .current_dir(&*dir)
                .stdin(Stdio::from(fs::File::open(dir.join("a")).unwrap()))
                .env_clear()
                .env("LC_ALL", "C")
                .output()
                .unwrap();
            let raw = String::from_utf8_lossy(&o.stderr).replacen(
                &format!("multithread (stuffr {})", env!("CARGO_PKG_VERSION")),
                "multithread",
                1,
            );
            let figures = lz4_read_refreshes(&raw);
            let packed = fs::read(dir.join("o.lz4")).unwrap_or_default();
            (
                o.status.code(),
                normalise_lz4_progress(&raw),
                figures,
                packed,
                o.stdout,
            )
        };
        let link_dir = ScratchDir::at(
            std::env::temp_dir().join(format!("stuffr-lz4-redir-bin-{}", std::process::id())),
        );
        fs::create_dir_all(&*link_dir).unwrap();
        let link = link_dir.join("lz4");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
        let reference = Path::new(ref_lz4());
        let mut n = 0;
        for args in [
            &["-", "o.lz4"][..],
            &["-v", "-", "o.lz4"],
            &["-v", "-12", "-T4", "-", "o.lz4"],
            &["-v", "--content-size", "-", "o.lz4"],
            &["-vvvv", "-B4", "-", "o.lz4"],
            &["-vvvv", "-T1", "-B6", "-", "o.lz4"],
        ] {
            for stdin_file in [false, true] {
                let theirs = run(reference, args, stdin_file);
                let mut ours = run(&link, args, stdin_file);
                if !EXACT {
                    // Deviation 6: the pure tier's own bytes and figures;
                    // the reference decodes them.
                    assert_eq!(
                        decode_with_reference(&ours.3),
                        data,
                        "{args:?}: the reference decodes ours"
                    );
                    ours.1 = theirs.1.clone();
                    ours.2 = theirs.2.clone();
                    ours.3 = theirs.3.clone();
                }
                assert_eq!(
                    ours, theirs,
                    "{args:?} < a (a file `stdin` beside it: {stdin_file})"
                );
                n += 1;
            }
        }
        // `--rm` of standard input is 0.26.0 Task 5's (1.11.0 removes
        // nothing); here only: no change warning on either side.
        for stdin_file in [false, true] {
            for exe in [reference, link.as_path()] {
                let (_, err, ..) = run(exe, &["-v", "--rm", "-", "o.lz4"], stdin_file);
                assert!(!err.contains("Warning"), "{exe:?} --rm: {err:?}");
            }
        }
        println!("{n} cases compared");
    }

    /// The reference's decode of an lz4 stream.
    fn decode_with_reference(packed: &[u8]) -> Vec<u8> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new(ref_lz4())
            .args(["-dc", "-q"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let packed = packed.to_vec();
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(&packed);
        });
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap();
        out.stdout
    }

    /// `--content-size` with standard input first (probe, 1.11.0: a
    /// warning at display level 2 as parsed, for every operation).
    #[test]
    fn content_size_from_standard_input_matches_the_reference() {
        let a = super::compat_harness::text(3000, 48);
        let frame = made(&["-1", "-q", "-c"], &a);
        let mut cases = Vec::new();
        for args in [
            &["--content-size", "-", "o.lz4"][..],
            &["--content-size", "-c"],
            &["--content-size"],
            &["-v", "--content-size", "-c"],
            &["-vv", "--content-size", "-", "o.lz4"],
            &["-q", "--content-size", "-c"],
            // (`-m stdin a` writes both to standard output, which the pure
            // tier's round trip cannot tell apart: one input here.)
            &["--content-size", "-m", "stdin"],
            &["--content-size", "-m", "a", "stdin"],
            &["--content-size", "a", "-", "-m"],
            &["--content-size", "stdin", "o.lz4"],
            &["--content-size", "-c", "a"],
            &["-v", "--content-size", "-l", "-", "o.lz4"],
            &["-v", "--content-size", "-f", "-", "stdin"],
        ] {
            cases.push(piped("lz4", args, vec![("a", a.clone())], a.clone()));
        }
        for args in [
            &["--content-size", "-d"][..],
            // (`-v -t` would add `Done in`, 0.26.0 Task 5's.)
            &["--content-size", "-t", "-"],
            &["-v", "--content-size", "--list", "-"],
            &["--content-size", "-dc"],
        ] {
            cases.push(piped("lz4", args, vec![], frame.clone()));
        }
        // The legacy summary (1.11.0: no blank before its newline).
        for args in [&["-v", "-l", "-c", "a"][..], &["-v", "-l", "-c", "e"]] {
            cases.push(lz4_case(
                "lz4",
                args,
                vec![("a", a.clone()), ("e", Vec::new())],
            ));
        }
        check(
            "content_size_from_standard_input_matches_the_reference",
            &cases,
        );
    }

    /// The probe's §1.13 table (errors 53 and 54 are new in 1.11.0): a
    /// source changed while it is compressed. Each case starts `lz4 -12 -T1
    /// [opts] f` over 64 MiB, changes `f` once the output holds data, and
    /// compares the exit, the message (refreshes dropped), whether the
    /// output and the source are left, and how much the output decodes to.
    ///
    /// Then standard input redirected from `f` (`lz4 -12 -T1 [opts] - f.lz4
    /// < f`, or `-c` into `f.lz4`; Task 5 review I1): checked through its
    /// descriptor only, a warning at display level 2 and never `Error 54`
    /// (also under `--no-frame-crc`), nothing for `f` renamed and replaced,
    /// ` ; source kept` under `--rm`, nothing at level 1 (`-q`, `-c`). A
    /// truncated standard input holds what was read before the truncation,
    /// which is timing on both sides: only that it decodes is compared.
    ///
    /// C tier only: the pure tier compresses so fast that the change can
    /// come after it has finished (its rule is `io.rs`' unit tests').
    #[test]
    fn a_source_changed_while_compressed_matches_the_reference() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        if !EXACT {
            return;
        }
        let Some(dir) = lz4_dir() else { return };
        let _serial = interrupt::interrupt_lock();
        let tag = std::process::id();
        let data = super::compat_harness::text(64 << 20, 49);
        #[derive(Clone, Copy, Debug)]
        enum Change {
            Append,
            Truncate,
            Rewrite,
            Old,
            Replace,
        }
        let change = |w: &Path, c: Change| {
            let f = w.join("f");
            match c {
                Change::Append => {
                    use std::io::Write;
                    fs::OpenOptions::new()
                        .append(true)
                        .open(&f)
                        .unwrap()
                        .write_all(&[b'x'; 1000])
                        .unwrap();
                }
                Change::Truncate => fs::OpenOptions::new()
                    .write(true)
                    .open(&f)
                    .unwrap()
                    .set_len(1000)
                    .unwrap(),
                Change::Rewrite => {
                    use std::io::{Seek, SeekFrom, Write};
                    let mut h = fs::OpenOptions::new().write(true).open(&f).unwrap();
                    h.seek(SeekFrom::Start(100)).unwrap();
                    h.write_all(b"ZZZZ").unwrap();
                    // Another second, so that the times say so.
                    let old = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
                    h.set_times(fs::FileTimes::new().set_modified(old)).unwrap();
                }
                Change::Old => {
                    let old = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
                    fs::File::options()
                        .write(true)
                        .open(&f)
                        .unwrap()
                        .set_times(fs::FileTimes::new().set_modified(old))
                        .unwrap();
                }
                Change::Replace => {
                    // From another second than `f`'s own status change, so
                    // that the rename moves it on both sides (the reference
                    // then counts `f` as modified too: `--no-frame-crc` is
                    // `Error 54`; within the second it is a warning).
                    use std::os::unix::fs::MetadataExt;
                    let born = fs::metadata(&f).unwrap().ctime();
                    while std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64
                        <= born
                    {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    fs::rename(&f, w.join("f.old")).unwrap();
                    fs::write(&f, b"new").unwrap();
                }
            }
        };
        // (status, stderr, output decoded size, source kept)
        let run = |exe: &Path, w: &Path, opts: &[&str], c: Change, stdin: bool| {
            let _ = fs::remove_dir_all(w);
            fs::create_dir_all(w).unwrap();
            fs::write(w.join("f"), &data).unwrap();
            let mut cmd = Command::new(exe);
            cmd.arg0_lz4()
                .args(["-12", "-T1"])
                .args(opts)
                .current_dir(w)
                .env_clear()
                .env("LC_ALL", "C")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped());
            if !stdin {
                cmd.arg("f");
            } else {
                cmd.stdin(fs::File::open(w.join("f")).unwrap());
                if opts.contains(&"-c") {
                    cmd.stdout(fs::File::create(w.join("f.lz4")).unwrap());
                } else {
                    cmd.args(["-", "f.lz4"]);
                }
            }
            let child = spawn(&mut cmd).unwrap();
            let start = Instant::now();
            while fs::metadata(w.join("f.lz4")).map_or(0, |m| m.len()) == 0 {
                assert!(
                    start.elapsed() < Duration::from_secs(60),
                    "{opts:?}: no output"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            change(w, c);
            let out = child.wait_with_output().unwrap();
            let decoded = w.join("f.lz4").exists().then(|| {
                Command::new(ref_lz4())
                    .args(["-dc", "-q", "f.lz4"])
                    .current_dir(w)
                    .stdin(Stdio::null())
                    .output()
                    .map(|o| o.stdout.len())
                    .unwrap()
            });
            let decoded = match c {
                Change::Truncate if stdin => decoded.map(|n| usize::from(n > 0)),
                _ => decoded,
            };
            // Every refresh goes, the one the error follows on its line too
            // (where lz4 draws its last is timing: deviation 2).
            let mut err = String::from_utf8_lossy(&out.stderr).into_owned();
            while let Some(at) = err.find("\rRead : ") {
                let end = err[at..].find("%   ").map_or(err.len(), |e| at + e + 4);
                err.replace_range(at..end, "");
            }
            (out.status.code(), err, decoded, w.join("f").exists())
        };
        let ref_dir =
            ScratchDir::at(std::env::temp_dir().join(format!("stuffr-lz4-mod-ref-{tag}")));
        let our_dir = ScratchDir::at(std::env::temp_dir().join(format!("stuffr-lz4-mod-{tag}")));
        let stuffr = Path::new(env!("CARGO_BIN_EXE_stuffr"));
        let reference = Path::new(dir).join("lz4");
        let mut differ = Vec::new();
        let mut n = 0;
        for c in [
            Change::Append,
            Change::Truncate,
            Change::Rewrite,
            Change::Old,
            Change::Replace,
        ] {
            for opts in [
                &[][..],
                &["--no-mmap"],
                &["--no-frame-crc"],
                &["--rm"],
                &["-l"],
            ] {
                let theirs = run(&reference, &ref_dir, opts, c, false);
                let ours = run(stuffr, &our_dir, opts, c, false);
                n += 1;
                if theirs != ours {
                    differ.push(format!(
                        "{c:?} {opts:?}:\n  reference {theirs:?}\n  stuffr    {ours:?}"
                    ));
                }
            }
        }
        // Standard input: 11 cases, the warning where it shows and where
        // it does not, kept to what tells the rules apart.
        let stdin_cases: [(Change, &[&str]); 11] = [
            (Change::Append, &[]),
            (Change::Append, &["--rm"]),
            (Change::Append, &["-l"]),
            (Change::Append, &["--no-frame-crc"]),
            (Change::Append, &["-q"]),
            (Change::Append, &["-c"]),
            (Change::Old, &[]),
            (Change::Old, &["-q"]),
            (Change::Truncate, &[]),
            (Change::Truncate, &["-l"]),
            (Change::Replace, &[]),
        ];
        for (c, opts) in stdin_cases {
            let theirs = run(&reference, &ref_dir, opts, c, true);
            let ours = run(stuffr, &our_dir, opts, c, true);
            n += 1;
            if theirs != ours {
                differ.push(format!(
                    "stdin {c:?} {opts:?}:\n  reference {theirs:?}\n  stuffr    {ours:?}"
                ));
            }
        }
        println!("{n} cases compared");
        assert!(
            differ.is_empty(),
            "{} of {n} differ:\n{}",
            differ.len(),
            differ.join("\n")
        );
    }

    // ---- lz4 1.11.0: decoding, outputs, file handling (0.26.0 Task 5) ----
    //
    // Probed 2026-11-08 against /opt/homebrew/Cellar/lz4/1.11.0/bin/lz4
    // (the probe's §1.8-1.12 and §1.15, and Task 5's own probes).

    /// The mozlz4 layout: magic, a declared size, a block.
    fn moz(size: u32, body: &[u8]) -> Vec<u8> {
        cat(&[b"mozLz40\0", &le32(size), body])
    }

    /// mozlz4 streams: good, and every hostile shape of its header (cut at
    /// every length, a size past `0x7E000000`, a wrong second half of the
    /// magic), its block (too small a size, cut, followed by more, empty),
    /// and after legacy, skippable and modern frames; from files and from a
    /// pipe, decoded, tested, copied (`-dcf`) and named `.lz4`.
    #[test]
    fn mozlz4_decodes_as_the_reference_decodes_it() {
        if lz4_dir().is_none() {
            return;
        }
        let legacy = made(&["-c", "-q", "-l"], &text());
        // One block (8800 bytes of text): the legacy frame's after its
        // magic and size word.
        let block = legacy[8..].to_vec();
        let n = text().len() as u32;
        let good = moz(n, &block);
        let frame = made(&["-c", "-q"], &text());
        let skip = cat(&[&[0x50, 0x2a, 0x4d, 0x18], &le32(3), b"abc"]);
        let mut streams: Vec<(String, Vec<u8>)> = vec![
            ("good.jsonlz4".into(), good.clone()),
            ("large.mozlz4".into(), moz(n + 1000, &block)),
            ("huge.mozlz4".into(), moz(1 << 30, &block)),
            ("max.mozlz4".into(), moz(0x7E00_0000, &block)),
            ("max1.mozlz4".into(), moz(0x7E00_0001, &block)),
            ("2g.mozlz4".into(), moz(0x8000_0000, &block)),
            ("ffff.mozlz4".into(), moz(u32::MAX, &block)),
            ("small.mozlz4".into(), moz(n - 1, &block)),
            ("cut100.mozlz4".into(), good[..100].to_vec()),
            ("two.mozlz4".into(), cat(&[&good, &good])),
            ("junk.mozlz4".into(), cat(&[&good, b"AAAA"])),
            ("zero.mozlz4".into(), moz(0, &block)),
            ("zero_empty.mozlz4".into(), moz(0, &[])),
            ("zero_token.mozlz4".into(), moz(0, &[0])),
            ("five_token.mozlz4".into(), moz(5, &[0])),
            ("two_zeros.mozlz4".into(), moz(0, &[0, 0])),
            ("empty_body.mozlz4".into(), moz(n, &[])),
            (
                "bomb.mozlz4".into(),
                moz(0x7E00_0000, &[0x1f, b'a', 1, 0, 0xff, 0xff, 0x10]),
            ),
            (
                "badmagic.mozlz4".into(),
                cat(&[b"mozLz41\0", &le32(n), &block]),
            ),
            ("mozl.mozlz4".into(), cat(&[b"mozLxxxx", &le32(n), &block])),
            ("leg_moz.lz4".into(), cat(&[&legacy, &good])),
            ("skip_moz.lz4".into(), cat(&[&skip, &good])),
            ("frame_moz.lz4".into(), cat(&[&frame, &good])),
            ("moz_frame.lz4".into(), cat(&[&good, &frame])),
            (
                "leg_mozl.lz4".into(),
                cat(&[&legacy, b"mozLxxxx", &le32(n)]),
            ),
        ];
        for k in 1..=12 {
            streams.push((format!("hdr{k}.mozlz4"), good[..k].to_vec()));
            streams.push((format!("leg_hdr{k}.lz4"), cat(&[&legacy, &good[..k]])));
        }
        let mut cases = Vec::new();
        for (name, s) in streams {
            let name = leak(name);
            cases.push(lz4_case("lz4", &["-t", name], vec![(name, s.clone())]));
            cases.push(lz4_case("lz4", &["-d", name, "o"], vec![(name, s.clone())]));
            cases.push(lz4_case("lz4", &["-dcf", name], vec![(name, s.clone())]));
            cases.push(lz4_case("lz4cat", &[name], vec![(name, s.clone())]));
            cases.push(piped("lz4", &["-dc"], vec![], s.clone()));
            cases.push(piped("lz4", &["-dcf"], vec![], s));
        }
        // The block cut at every length: decoded where liblz4 accepts the
        // cut as a block's end, `Error 64` elsewhere. The C tier only: the
        // pure tier's `lz4_flex` also accepts some cuts liblz4 1.11.0
        // refuses (one of these 79: `cut60`, where liblz4's end-of-block
        // rules refuse the last sequence; spec deviation 6).
        if EXACT {
            for k in 13..good.len() {
                let name = leak(format!("cut{k}.mozlz4"));
                cases.push(lz4_case(
                    "lz4",
                    &["-dc", name],
                    vec![(name, good[..k].to_vec())],
                ));
            }
        }
        let g = || ("good.jsonlz4", good.clone());
        let named = || ("smoz.lz4", good.clone());
        cases.extend([
            lz4_case("lz4", &["-vv", "-t", "good.jsonlz4"], vec![g()]),
            lz4_case("lz4", &["-vv", "-d", "good.jsonlz4", "o"], vec![g()]),
            lz4_case("lz4", &["-d", "good.jsonlz4"], vec![g()]),
            lz4_case("lz4", &["-d", "smoz.lz4"], vec![named()]),
            lz4_case("lz4", &["-d", "--rm", "smoz.lz4"], vec![named()]),
            lz4_case("unlz4", &["smoz.lz4"], vec![named()]),
            lz4_case("lz4", &["smoz.lz4"], vec![named()]),
            lz4_case(
                "lz4",
                &["-m", "-d", "smoz.lz4", "nosuch.lz4"],
                vec![named()],
            ),
        ]);
        check("mozlz4_decodes_as_the_reference_decodes_it", &cases);
        // Review Focus 4: a declaration of up to 2 GiB over a few bytes
        // reserves nothing near it.
        for (name, data) in [
            ("max.mozlz4", moz(0x7E00_0000, &block)),
            (
                "bomb.mozlz4",
                moz(0x7E00_0000, &[0x1f, b'a', 1, 0, 0xff, 0xff, 0x10]),
            ),
            ("ffff.mozlz4", moz(u32::MAX, &block)),
        ] {
            #[cfg(target_os = "linux")]
            {
                let env = [("LC_ALL", "C")];
                let free = data_limited_run("lz4", &["-t", name], name, &data, &env, None);
                let capped =
                    data_limited_run("lz4", &["-t", name], name, &data, &env, Some(32 << 20));
                assert_eq!(
                    capped, free,
                    "{name}: under a 32 MiB data limit stuffr answers differently"
                );
            }
            #[cfg(not(target_os = "linux"))]
            {
                let (_, _, _, peak) =
                    peak_rss_run("lz4", &["-t", name], name, &data, &[("LC_ALL", "C")]);
                assert!(
                    peak < 32 << 20,
                    "{name}: peak memory {peak} bytes is not under 32 MiB"
                );
            }
        }
    }

    /// A legacy frame ended by a zero word (the Linux kernel's end mark),
    /// then nothing, another frame, garbage or a cut magic (probe, 1.11.0:
    /// `legzero` decodes to nothing, `leg_zeros` is undecodable data at the
    /// zero word's end + 4; 1.10.0 said `Error 64` for all).
    #[test]
    fn a_zero_word_ends_a_legacy_frame() {
        let legacy = made(&["-c", "-q", "-l"], &text());
        let good = made(&["-c", "-q"], &text());
        let z = le32(0);
        let streams: Vec<Vec<u8>> = vec![
            cat(&[&LEGACY, &z]),
            cat(&[&legacy, &z]),
            cat(&[&legacy, &z, &good]),
            cat(&[&legacy, &z, &legacy]),
            cat(&[&legacy, &z, &legacy, &z]),
            cat(&[&legacy, &z, b"AAAA"]),
            cat(&[&legacy, &z, &z]),
            cat(&[&legacy, &z, b"AB"]),
            cat(&[&LEGACY, &z, &z, &z]),
        ];
        let mut cases = Vec::new();
        for (i, s) in streams.into_iter().enumerate() {
            let name = leak(format!("lz{i}.lz4"));
            cases.push(lz4_case("lz4", &["-d", name, "o"], vec![(name, s.clone())]));
            cases.push(lz4_case(
                "lz4",
                &["-v", "-t", name],
                vec![(name, s.clone())],
            ));
            cases.push(lz4_case("lz4cat", &[name], vec![(name, s.clone())]));
            cases.push(piped("lz4", &["-d", "-", "o"], vec![], s));
        }
        check("a_zero_word_ends_a_legacy_frame", &cases);
    }

    fn tree_with_dir_links(w: &Path) {
        for d in ["d/sub", "t", "e"] {
            fs::create_dir_all(w.join(d)).unwrap();
        }
        fs::write(w.join("t/x"), b"behind a link\n").unwrap();
        fs::write(w.join("d/f"), b"f\n").unwrap();
        fs::write(w.join("d/sub/g"), b"g\n").unwrap();
        for (target, at) in [
            ("../t", "d/lnk"),
            ("../../t", "d/sub/l2"),
            ("f", "d/fl"),
            ("../t", "e/only"),
        ] {
            std::os::unix::fs::symlink(target, w.join(at)).unwrap();
        }
    }

    /// `-r` follows no symbolic link to a directory inside the walk and
    /// warns about it at every display level, a link to a file is still
    /// compressed, a link named as an operand is still walked, and a
    /// directory whose only content was behind such a link is then a
    /// directory operand (probe, 1.11.0, §1.15).
    #[test]
    fn recursion_follows_no_link_to_a_directory() {
        let mut cases = Vec::new();
        for args in [
            &["-r", "d"][..],
            &["-qqq", "-r", "d"],
            &["-v", "-r", "d"],
            &["-vvvv", "-r", "d"],
            &["-q", "-r", "e"],
            &["-r", "e"],
            &["-r", "d/lnk"],
            &["-r", "-m", "d", "e"],
            &["-d", "-r", "-f", "d"],
            &["-c", "-r", "d"],
        ] {
            cases.push(set_up(lz4_case("lz4", args, vec![]), tree_with_dir_links));
        }
        check("recursion_follows_no_link_to_a_directory", &cases);
    }

    /// `Command::arg0` as `lz4`, for a binary run under another name.
    trait Arg0Lz4 {
        fn arg0_lz4(&mut self) -> &mut Self;
    }
    impl Arg0Lz4 for std::process::Command {
        fn arg0_lz4(&mut self) -> &mut Self {
            use std::os::unix::process::CommandExt;
            self.arg0("lz4")
        }
    }
}
