//! Foreign formats: a file that begins like one of ours and is not.
//!
//! An Apple disk image (UDIF) is the case in point: its first chunk is a
//! zlib (or bzip2, lzfse…) stream, and its last 512 bytes are the `koly`
//! trailer. Every verb given one by name refuses it (exit 3) and names it;
//! `--format` overrides the check, `salvage` never refuses, and a piped image
//! (no tail to read) is a corrupt stream of its first chunk, never exit 1.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::common::*;

/// The UDIF trailer: `koly`, version 4, header size 512, all big-endian,
/// then zeros to 512 bytes.
fn koly_block() -> Vec<u8> {
    let mut koly = vec![0u8; 512];
    koly[..4].copy_from_slice(b"koly");
    koly[4..8].copy_from_slice(&4u32.to_be_bytes());
    koly[8..12].copy_from_slice(&512u32.to_be_bytes());
    koly
}

/// 2 KiB that zlib cannot shrink much (a linear congruential sequence), so
/// the stream is about 2 KiB.
fn first_chunk_text() -> Vec<u8> {
    let mut x: u32 = 0x1234_5678;
    (0..2048)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (x >> 24) as u8
        })
        .collect()
}

/// A synthetic disk image that any platform can build: a real zlib stream
/// (`78 9c`), then `payload`, then 4 KiB of zeros, then the `koly` block.
pub(crate) fn synthetic_dmg_with(payload: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&first_chunk_text()).unwrap();
    let mut out = enc.finish().unwrap();
    assert_eq!(out[..2], [0x78, 0x9c]);
    out.extend_from_slice(payload);
    out.resize(out.len() + 4096, 0);
    out.extend_from_slice(&koly_block());
    out
}

pub(crate) fn synthetic_dmg() -> Vec<u8> {
    synthetic_dmg_with(&[])
}

/// Real disk images made by `hdiutil` from a one-file folder, one per
/// format, copied into `dir`. Empty (with a printed note) where `hdiutil`
/// is missing or refuses — CI's macOS runner may not be allowed to make
/// disk images, and hdiutil's own failure is not stuffr's.
///
/// `hdiutil create` costs about five seconds an image, so the five are made
/// once per test binary ([`hdiutil_images`]) and every caller gets copies.
#[cfg(target_os = "macos")]
pub(crate) fn real_disk_images(dir: &Path) -> Vec<PathBuf> {
    hdiutil_images()
        .iter()
        .map(|(name, bytes)| {
            let out = dir.join(name);
            std::fs::write(&out, bytes).unwrap();
            out
        })
        .collect()
}

/// The images `hdiutil` made, as (file name, bytes), built on first use.
///
/// Held in memory rather than in a scratch folder kept for the process: a
/// static never drops, so such a folder would outlive the run with a dead
/// pid in its name and `scripts/tmp-leaks.sh check` would flag it. The
/// folders `hdiutil` works in are ordinary per-call scratch guards, removed
/// before this returns.
#[cfg(target_os = "macos")]
fn hdiutil_images() -> &'static [(String, Vec<u8>)] {
    static IMAGES: std::sync::OnceLock<Vec<(String, Vec<u8>)>> = std::sync::OnceLock::new();
    IMAGES.get_or_init(|| {
        let Some(hdiutil) = which("hdiutil") else {
            eprintln!("note: hdiutil is missing; real disk images skipped");
            return Vec::new();
        };
        let src = tmp_dir();
        std::fs::write(src.join("hello.txt"), b"hello from a disk image\n").unwrap();
        let dir = tmp_dir();
        let mut made = Vec::new();
        for format in ["UDZO", "UDBZ", "ULMO", "UDRO", "ULFO"] {
            let name = format!("image-{format}.dmg");
            let out = dir.join(&name);
            let run = std::process::Command::new(&hdiutil)
                .args([
                    "create", "-quiet", "-ov", "-volname", "stuffr", "-format", format,
                ])
                .arg("-srcfolder")
                .arg(&*src)
                .arg("-o")
                .arg(&out)
                .output();
            match run {
                Ok(o) if o.status.success() && out.is_file() => {
                    let bytes = std::fs::read(&out).unwrap();
                    assert_eq!(
                        bytes[bytes.len() - 512..][..4],
                        *b"koly",
                        "hdiutil's {format} image has no koly trailer"
                    );
                    made.push((name, bytes));
                }
                Ok(o) => {
                    eprintln!(
                        "note: hdiutil create -format {format} failed ({}): {}; skipped",
                        o.status,
                        String::from_utf8_lossy(&o.stderr).trim()
                    );
                }
                Err(e) => {
                    eprintln!("note: hdiutil could not run ({e}); real disk images skipped");
                    return made;
                }
            }
        }
        made
    })
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn real_disk_images(_dir: &Path) -> Vec<PathBuf> {
    Vec::new()
}

/// Every disk image this machine can offer: the synthetic one always, and
/// hdiutil's where it works.
fn every_disk_image(dir: &Path) -> Vec<PathBuf> {
    let synthetic = dir.join("synthetic.dmg");
    std::fs::write(&synthetic, synthetic_dmg()).unwrap();
    let mut all = vec![synthetic];
    all.extend(real_disk_images(dir));
    all
}

fn outcome(o: &std::process::Output) -> (Option<i32>, String) {
    (
        o.status.code(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// The names in `dir`, sorted.
fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn every_verb_refuses_a_disk_image() {
    let dir = tmp_dir();
    for image in every_disk_image(&dir) {
        let work = tmp_dir();
        let x = work.join("x.dmg");
        std::fs::copy(&image, &x).unwrap();
        let xs = x.to_str().unwrap();
        let unpack_dir = work.join("out");
        let ud = unpack_dir.to_str().unwrap();
        let y = work.join("y.tar");
        let ys = y.to_str().unwrap();
        let single = work.join("single");
        let ss = single.to_str().unwrap();
        let want =
            format!("stuffr: {xs}: this is an Apple disk image (UDIF), which stuffr cannot open\n");
        for args in [
            vec!["info", xs],
            vec!["info", "--json", xs],
            vec!["cat", xs],
            vec!["cat", xs, "hello.txt"],
            vec!["list", xs],
            vec!["ls", xs],
            vec!["test", xs],
            vec!["unpack", xs, "-C", ud],
            vec!["unpack", xs, "-o", ss],
            vec!["convert", xs, "-o", ys],
            vec!["convert", xs, ys],
        ] {
            let o = run_output(&args);
            let (code, err) = outcome(&o);
            assert_eq!(code, Some(3), "{image:?} {args:?}: {err}");
            assert_eq!(err, want, "{image:?} {args:?}");
            assert!(o.stdout.is_empty(), "{image:?} {args:?} wrote to stdout");
            assert_eq!(names_in(&work), ["x.dmg"], "{image:?} {args:?} left output");
        }
    }
}

/// The path in the message is shown as `ls` and `list` show names: escaped.
#[cfg(unix)]
#[test]
fn the_refusal_escapes_the_path() {
    let dir = tmp_dir();
    let x = dir.join("a\nb.dmg");
    std::fs::write(&x, synthetic_dmg()).unwrap();
    let (code, err) = outcome(&run_output(&["info", x.to_str().unwrap()]));
    assert_eq!(code, Some(3));
    let shown = format!("{}/a\\nb.dmg", dir.display());
    assert_eq!(
        err,
        format!("stuffr: {shown}: this is an Apple disk image (UDIF), which stuffr cannot open\n")
    );
}

#[test]
fn salvage_tries_a_disk_image() {
    let dir = tmp_dir();
    let x = dir.join("x.dmg");
    std::fs::write(&x, synthetic_dmg()).unwrap();
    let out = dir.join("out");
    let (code, err) = outcome(&run_output(&[
        "salvage",
        x.to_str().unwrap(),
        "-C",
        out.to_str().unwrap(),
    ]));
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("not an archive"), "{err}");
    assert!(!err.contains("Apple disk image"), "{err}");

    // With the container named, the image is scanned like any other file
    // and the zip stored inside it is recovered.
    let zdir = tmp_dir();
    let zip = std::fs::read(write_zip_via_pack(
        &zdir,
        &[("inside.txt", b"recovered from a disk image\n")],
    ))
    .unwrap();
    let x = dir.join("with-zip.dmg");
    std::fs::write(&x, synthetic_dmg_with(&zip)).unwrap();
    let out = dir.join("zip-out");
    let o = run_output(&[
        "salvage",
        "--format",
        "zip",
        x.to_str().unwrap(),
        "-C",
        out.to_str().unwrap(),
    ]);
    let (code, err) = outcome(&o);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(
        std::fs::read(out.join("inside.txt")).unwrap(),
        b"recovered from a disk image\n"
    );
}

#[test]
fn format_flag_overrides_the_foreign_check() {
    let dir = tmp_dir();
    let x = dir.join("x.dmg");
    std::fs::write(&x, synthetic_dmg()).unwrap();
    let o = run_output(&["cat", "--format", "zlib", x.to_str().unwrap()]);
    let (code, err) = outcome(&o);
    assert!(matches!(code, Some(0 | 5)), "{code:?} {err}");
    assert!(!err.contains("Apple disk image"), "{err}");
    // What came out is the first chunk, as far as it went.
    let text = first_chunk_text();
    assert!(
        text.starts_with(&o.stdout) && !o.stdout.is_empty(),
        "{} bytes",
        o.stdout.len()
    );

    let y = dir.join("y");
    let o = run_output(&[
        "unpack",
        "--format",
        "zlib",
        x.to_str().unwrap(),
        "-o",
        y.to_str().unwrap(),
    ]);
    let (code, err) = outcome(&o);
    assert!(matches!(code, Some(0 | 5)), "{code:?} {err}");
    assert!(!err.contains("Apple disk image"), "{err}");
}

/// A pipe has no end to read, so the trailer cannot be seen: the image is
/// its first chunk's codec, and whatever that yields is never exit 1. The
/// brief's set was {2, 3, 5}; zlib stops at its own stream's end and does
/// not look at what follows, so `cat -` decodes the first chunk and exits 0
/// — the same as for any zlib stream with bytes after it.
#[test]
fn a_piped_disk_image_never_exits_1() {
    let o = run_with_stdin_output(&["cat", "-"], &synthetic_dmg());
    let (code, err) = outcome(&o);
    assert!(matches!(code, Some(0 | 2 | 3 | 5)), "{code:?} {err}");
    assert!(first_chunk_text().starts_with(&o.stdout));
    for verb in ["info", "list", "test"] {
        let o = run_with_stdin_output(&[verb, "-"], &synthetic_dmg());
        let (code, err) = outcome(&o);
        assert!(
            matches!(code, Some(0 | 2 | 3 | 5)),
            "{verb}: {code:?} {err}"
        );
    }
}

/// recon's `.scube`: pixel-like data starting `1A 01`, arc's magic, with no
/// arc header behind it (the shape `arc_rejects_pixel_like_data` pins).
pub(crate) fn arc_pixel_like() -> Vec<u8> {
    let start: [u8; 32] = [
        0x1a, 0x01, 0x00, 0xff, 0x1b, 0x01, 0x00, 0xff, 0x1d, 0x01, 0x00, 0xff, 0x1f, 0x01, 0x00,
        0xff, 0x21, 0x01, 0x00, 0xff, 0x24, 0x01, 0x00, 0xff, 0x28, 0x01, 0x00, 0xff, 0x2d, 0x01,
        0x00, 0xff,
    ];
    start.iter().copied().cycle().take(4096).collect()
}

#[test]
fn info_says_when_the_header_did_not_check_out() {
    let dir = tmp_dir();
    let x = dir.join("pixels.scube");
    std::fs::write(&x, arc_pixel_like()).unwrap();
    let o = run_output(&["info", x.to_str().unwrap()]);
    let (code, err) = outcome(&o);
    assert_eq!(code, Some(0), "{err}");
    let text = String::from_utf8(o.stdout).unwrap();
    assert!(text.contains("format:   arc\n"), "{text}");
    assert!(text.contains("detected: magic-unconfirmed\n"), "{text}");

    let o = run_output(&["info", "--json", x.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["format"], "arc");
    assert_eq!(v["detected_by"], "magic-unconfirmed");

    // Text with no magic, named `.gz`: the name decided, and gzip's check
    // refused the bytes.
    let t = dir.join("notes.gz");
    std::fs::write(&t, b"just plain text, no gzip magic here").unwrap();
    let o = run_output(&["info", "--json", t.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["detected_by"], "extension-unconfirmed");

    // A real gzip still says `magic`, in both forms.
    let g = dir.join("real.gz");
    std::fs::write(&g, gzip_wrap(b"hello")).unwrap();
    let o = run_output(&["info", g.to_str().unwrap()]);
    let text = String::from_utf8(o.stdout).unwrap();
    assert!(text.contains("detected: magic\n"), "{text}");
}

/// A tar inside a gzip whose first header fails its checksum: gzip checks
/// out, tar does not, and `info` names the layer that did not. A chain where
/// every layer checks out keeps `info`'s output exactly as it was.
#[test]
fn info_names_the_inner_layer_that_did_not_check_out() {
    let dir = tmp_dir();
    let good = write_fixture_tar_gz(&dir, "good.tar.gz", &[("a.txt", b"hello\n")]);
    let mut tar = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar);
        append_tar_entry(&mut b, "a.txt", b"hello\n");
        b.finish().unwrap();
    }
    // One byte of the name changes; the recorded checksum no longer adds up.
    tar[0] ^= 0x01;
    let bad = dir.join("bad.tar.gz");
    std::fs::write(&bad, gzip_wrap(&tar)).unwrap();
    let bs = bad.to_str().unwrap();

    let o = run_output(&["info", bs]);
    let (code, err) = outcome(&o);
    assert_eq!(code, Some(0), "{err}");
    let text = String::from_utf8(o.stdout).unwrap();
    assert!(text.contains("chain:    tar over gzip\n"), "{text}");
    assert!(text.contains("detected: magic\n"), "{text}");
    assert!(text.contains("checks:   tar did not check out\n"), "{text}");

    let o = run_output(&["info", "--json", bs]);
    assert_eq!(o.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["detected_by"], "magic");
    assert_eq!(v["unconfirmed_layer"], "tar");

    // The verbs still reach the reader and call it corrupt.
    let (code, err) = outcome(&run_output(&["list", bs]));
    assert_eq!(code, Some(5), "{err}");

    // Every layer checks out: no new line, no new field.
    let gs = good.to_str().unwrap();
    let text = String::from_utf8(run_output(&["info", gs]).stdout).unwrap();
    assert!(!text.contains("checks:"), "{text}");
    let v: serde_json::Value =
        serde_json::from_slice(&run_output(&["info", "--json", gs]).stdout).unwrap();
    assert!(v.get("unconfirmed_layer").is_none(), "{v}");

    // An outer layer that did not check out is named the same way.
    let x = dir.join("pixels.scube");
    std::fs::write(&x, arc_pixel_like()).unwrap();
    let text = String::from_utf8(run_output(&["info", x.to_str().unwrap()]).stdout).unwrap();
    assert!(text.contains("checks:   arc did not check out\n"), "{text}");
}

/// `info` agrees with `ls` on a magicless inner layer: a v7 tar under gzip
/// and the empty archive tar writes (ten zero blocks, bare and gzipped)
/// all check out — no `checks:` line — while text named `.tar.gz` is named
/// as the layer that did not.
#[test]
fn info_passes_v7_and_empty_tars() {
    let dir = tmp_dir();
    let v7 = dir.join("v7.tar.gz");
    std::fs::write(&v7, gzip_wrap(&crate::ls::v7_tar())).unwrap();
    let empty = dir.join("empty.tar");
    std::fs::write(&empty, vec![0u8; 10240]).unwrap();
    let empty_gz = dir.join("empty.tar.gz");
    std::fs::write(&empty_gz, gzip_wrap(&[0u8; 10240])).unwrap();
    for (path, chain) in [
        (&v7, "tar over gzip"),
        (&empty, "tar"),
        (&empty_gz, "tar over gzip"),
    ] {
        let o = run_output(&["info", path.to_str().unwrap()]);
        let (code, err) = outcome(&o);
        assert_eq!(code, Some(0), "{err}");
        let text = String::from_utf8(o.stdout).unwrap();
        assert!(text.contains(&format!("chain:    {chain}\n")), "{text}");
        assert!(!text.contains("checks:"), "{}: {text}", path.display());
    }
    let y = dir.join("y.tar.gz");
    std::fs::write(&y, gzip_wrap(&b"not a tar, just words\n".repeat(30))).unwrap();
    let text = String::from_utf8(run_output(&["info", y.to_str().unwrap()]).stdout).unwrap();
    assert!(text.contains("checks:   tar did not check out\n"), "{text}");
}

/// `info --memory-limit` bounds the prefix decode that judges inner layers.
/// A small `.tar.lzma` whose header asks for a 32 MiB dictionary (the
/// review's file asked for 240 MiB and peaked at 263 MB under `4M`), over a
/// tar whose checksum is broken: under a roomy limit the inner tar is
/// decoded and named; under `--memory-limit 4M` the lzma decoder is
/// refused, the tar is not judged, and nothing else changes.
#[test]
fn info_decodes_inner_layers_under_the_memory_limit() {
    let dir = tmp_dir();
    let mut tar = crate::common::small_tar();
    tar[0] ^= 0x01;
    let raw = dir.join("inner.bin");
    std::fs::write(&raw, &tar).unwrap();
    let packed = dir.join("inner.lzma");
    let o = run_output(&[
        "pack",
        raw.to_str().unwrap(),
        "-o",
        packed.to_str().unwrap(),
    ]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let mut lzma = std::fs::read(&packed).unwrap();
    lzma[1..5].copy_from_slice(&(32u32 << 20).to_le_bytes());
    let big = dir.join("b.tar.lzma");
    std::fs::write(&big, &lzma).unwrap();
    let bs = big.to_str().unwrap();

    let o = run_output(&["info", "--memory-limit", "1G", bs]);
    let (code, err) = outcome(&o);
    assert_eq!(code, Some(0), "{err}");
    let roomy = String::from_utf8(o.stdout).unwrap();
    assert!(
        roomy.contains("checks:   tar did not check out\n"),
        "{roomy}"
    );

    // The C tier's lzma decoder (liblzma's alone decoder, `lzma_c.rs`) is
    // built with no memory limit at all, for every verb: `info` hands it the
    // limit and it does not look. Only the pure tier refuses here.
    if cfg!(feature = "lzma-c") {
        return;
    }

    let o = run_output(&["info", "--memory-limit", "4M", bs]);
    let (code, err) = outcome(&o);
    assert_eq!(code, Some(0), "{err}");
    let tight = String::from_utf8(o.stdout).unwrap();
    assert!(!tight.contains("checks:"), "{tight}");
    assert!(tight.contains("chain:    tar over lzma\n"), "{tight}");
    // Everything but the `checks:` and `memory:` lines is the same report.
    let keep = |t: &str| {
        t.lines()
            .filter(|l| !l.starts_with("checks:") && !l.starts_with("memory:"))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(keep(&roomy), keep(&tight));
}
