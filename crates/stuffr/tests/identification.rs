//! Identification across the whole registry: every format with a magic
//! confirms its hits, every checked-in codec and container fixture still
//! identifies, confirmed, and the skippable frames zstd and lz4 share lead
//! to the frame behind them.

use std::path::{Path, PathBuf};

use stuffr::{
    Chain, Evidence, FormatId, FormatKind, Registry, resolve_chain, resolve_chain_checked,
};

const ZSTD: FormatId = FormatId::new("zstd");
const LZ4: FormatId = FormatId::new("lz4");

/// The kinds whose magic formats must register a confirm function: every
/// kind there is. A derivative registered on another format's magic (a
/// `jar` on zip's `PK`) must register that format's function; without one it
/// would count as confirmed and win wherever the base format's check fails.
const CONFIRMED_KINDS: &[FormatKind] = &[FormatKind::Codec, FormatKind::Container];

#[test]
fn every_magic_format_registers_a_confirm_function() {
    let reg = stuffr::registry();
    let missing: Vec<&str> = reg
        .matrix()
        .iter()
        .filter(|row| CONFIRMED_KINDS.contains(&row.kind) && reg.has_magic(row.id))
        .filter(|row| reg.confirm(row.id, &[], false).is_none())
        .map(|row| row.id.as_str())
        .collect();
    assert!(
        missing.is_empty(),
        "formats with a magic but no confirm function: {missing:?}"
    );
}

/// `plain` through the registered `codec`'s encoder.
fn encode(reg: &Registry, codec: FormatId, plain: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let buf = stuffr::testing::SharedBuf::new();
    let mut sink = reg
        .require_codec(codec)
        .unwrap()
        .encoder(Box::new(buf.clone()), &stuffr::EncodeOpts::default())
        .unwrap();
    sink.write_all(plain).unwrap();
    sink.finish().unwrap();
    buf.contents()
}

/// A skippable frame: magic nibble `nibble`, `payload` filler bytes.
fn skippable(nibble: u8, payload: usize) -> Vec<u8> {
    let mut out = vec![0x50 | nibble, 0x2a, 0x4d, 0x18];
    out.extend_from_slice(&(payload as u32).to_le_bytes());
    out.resize(8 + payload, 0xa5);
    out
}

fn outer(chain: &Chain) -> Option<FormatId> {
    match chain {
        Chain::Codec { codec, .. } => Some(*codec),
        Chain::Container { container } => Some(*container),
        _ => None,
    }
}

#[test]
fn a_skippable_frame_first_identifies_the_following_frame() {
    let reg = stuffr::registry();
    for codec in [ZSTD, LZ4] {
        let mut stream = skippable(0, 16);
        stream.extend(encode(reg, codec, b"behind a skippable frame"));
        let (chain, evidence) = resolve_chain_checked(reg, None, &stream).unwrap();
        assert_eq!(outer(&chain), Some(codec));
        assert_eq!(evidence, Evidence::Confirmed, "{codec}");
    }
}

#[test]
fn only_skippable_frames_in_the_window_confirm_nothing() {
    let reg = stuffr::registry();
    let mut window = skippable(7, 5000);
    window.truncate(stuffr::PROBE_LEN);
    for id in [ZSTD, LZ4] {
        assert_eq!(reg.confirm(id, &window, false), Some(false), "{id}");
    }
    // Nameless: two unconfirmed hits of equal rank, exit 2 as unknown was.
    let err = resolve_chain(reg, None, &window).unwrap_err();
    assert_eq!(err.exit_code(), 2, "{err}");
    // Named: the lenient path still reaches the codec the name says.
    for (name, id) in [("x.lz4", LZ4), ("x.zst", ZSTD)] {
        let (chain, evidence) = resolve_chain_checked(reg, Some(Path::new(name)), &window).unwrap();
        assert_eq!(outer(&chain), Some(id), "{name}");
        assert_eq!(evidence, Evidence::Unconfirmed, "{name}");
        assert_eq!(
            outer(&resolve_chain(reg, Some(Path::new(name)), &window).unwrap()),
            Some(id)
        );
    }
}

/// Every file under `dir`, recursively.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// No true positive is lost: every checked-in fixture a codec's magic
/// matches still resolves, and confirmed.
#[test]
fn every_codec_fixture_confirms() {
    let reg = stuffr::registry();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for dir in [
        "stuffr-formats/fixtures",
        "stuffr-formats/tests/data",
        "stuffr-cli/tests/fixtures",
    ] {
        walk(&root.join(dir), &mut files);
    }
    let mut checked = 0;
    for path in files {
        let bytes = std::fs::read(&path).unwrap();
        let prefix = &bytes[..bytes.len().min(stuffr::PROBE_LEN)];
        let codec_hit = reg
            .match_magic(prefix)
            .iter()
            .any(|id| reg.codec(*id).is_some());
        if !codec_hit {
            continue;
        }
        let resolved = resolve_chain_checked(reg, Some(&path), prefix);
        let Ok((chain @ Chain::Codec { .. }, evidence)) = resolved else {
            continue;
        };
        assert_eq!(
            evidence,
            Evidence::Confirmed,
            "{} resolved to {:?} unconfirmed",
            path.display(),
            outer(&chain)
        );
        // And the layers its name puts beneath the codec check out too, so
        // `stuffr info` names none of them.
        assert_eq!(
            stuffr::probe::first_unconfirmed_layer(
                reg,
                &chain,
                prefix,
                &stuffr::DecodeOpts::default()
            ),
            None,
            "{} ({})",
            path.display(),
            chain.describe()
        );
        checked += 1;
    }
    assert!(checked >= 10, "only {checked} codec fixtures found");
}

/// No true positive is lost on the container side either: every checked-in
/// file a container's magic matches resolves, named and nameless, to one of
/// the containers that matched, confirmed — and to what the lenient
/// resolution (unchanged by confirmation) answers.
#[test]
fn every_container_fixture_confirms() {
    let reg = stuffr::registry();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for dir in [
        "stuffr-formats/fixtures",
        "stuffr-formats/tests",
        "stuffr-cli/tests/fixtures",
        "stuffr/tests",
    ] {
        walk(&root.join(dir), &mut files);
    }
    let mut checked = 0;
    for path in files {
        let bytes = std::fs::read(&path).unwrap();
        let prefix = &bytes[..bytes.len().min(stuffr::PROBE_LEN)];
        let containers: Vec<FormatId> = reg
            .match_magic(prefix)
            .into_iter()
            .filter(|id| reg.container(*id).is_some())
            .collect();
        if containers.is_empty() {
            continue;
        }
        for name in [Some(path.as_path()), None] {
            let (chain, evidence) = resolve_chain_checked(reg, name, prefix)
                .unwrap_or_else(|e| panic!("{} ({name:?}): {e}", path.display()));
            let got = outer(&chain);
            assert!(
                got.is_some_and(|id| containers.contains(&id)),
                "{} ({name:?}) resolved to {got:?}, its magic says {containers:?}",
                path.display()
            );
            assert_eq!(
                evidence,
                Evidence::Confirmed,
                "{} ({name:?}) resolved to {got:?} unconfirmed",
                path.display()
            );
            assert_eq!(
                outer(&resolve_chain(reg, name, prefix).unwrap()),
                got,
                "{}",
                path.display()
            );
        }
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} container fixtures found");
}

/// A one-entry ustar archive, header checksum computed — or, with `break_it`,
/// one byte of the name changed after it was.
fn tiny_tar(break_it: bool) -> Vec<u8> {
    let mut h = [0u8; 512];
    h[..5].copy_from_slice(b"a.txt");
    h[100..107].copy_from_slice(b"0000644");
    h[108..115].copy_from_slice(b"0000000");
    h[116..123].copy_from_slice(b"0000000");
    h[124..135].copy_from_slice(b"00000000006");
    h[136..147].copy_from_slice(b"00000000000");
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    if break_it {
        h[0] ^= 0x01;
    }
    let mut out = h.to_vec();
    let mut data = b"hello\n".to_vec();
    data.resize(512, 0);
    out.extend_from_slice(&data);
    out.resize(out.len() + 1024, 0);
    out
}

/// `stuffr info`'s inner-layer verdict: a tar under each codec this build
/// writes, named `x.tar.<ext>`, checks out whole and names `tar` when its
/// header checksum is broken — the codec itself still confirmed.
#[test]
fn the_first_unconfirmed_layer_is_the_tar_under_a_good_codec() {
    let reg = stuffr::registry();
    const TAR: FormatId = FormatId::new("tar");
    let mut checked = 0;
    for (name, ext) in [
        ("gzip", "gz"),
        ("bzip2", "bz2"),
        ("xz", "xz"),
        ("lz4", "lz4"),
        ("lzip", "lz"),
        ("zstd", "zst"),
        ("compress", "Z"),
        ("snappy", "sz"),
    ] {
        let codec = FormatId::new(name);
        if reg.codec(codec).is_none() {
            continue;
        }
        let path = PathBuf::from(format!("x.tar.{ext}"));
        for (broken, want) in [(false, None), (true, Some(TAR))] {
            let bytes = encode(reg, codec, &tiny_tar(broken));
            let prefix = &bytes[..bytes.len().min(stuffr::PROBE_LEN)];
            let (chain, evidence) = resolve_chain_checked(reg, Some(&path), prefix).unwrap();
            assert_eq!(evidence, Evidence::Confirmed, "{name}");
            assert_eq!(chain.describe(), format!("tar over {name}"));
            let got = stuffr::probe::first_unconfirmed_layer(
                reg,
                &chain,
                prefix,
                &stuffr::DecodeOpts::default(),
            );
            assert_eq!(got, want, "{name}, broken {broken}");
        }
        checked += 1;
    }
    assert!(checked >= 6, "only {checked} codecs checked");
}

/// `tiny_tar` as a v7 archive: no `ustar` magic at 257, the checksum
/// recomputed — a real tar that only its checksum (and a name) identifies.
fn v7_tar() -> Vec<u8> {
    let mut t = tiny_tar(false);
    t[257..265].fill(0);
    t[148..156].copy_from_slice(b"        ");
    let sum: u32 = t[..512].iter().map(|&b| u32::from(b)).sum();
    t[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    t
}

fn strict(reg: &Registry, name: &str, bytes: &[u8]) -> Option<String> {
    let prefix = &bytes[..bytes.len().min(stuffr::PROBE_LEN)];
    stuffr::probe::identify_strict(
        reg,
        Some(Path::new(name)),
        prefix,
        None,
        &stuffr::DecodeOpts::default(),
    )
    .map(|c| c.describe())
}

/// The lenient chain `stuffr info` prints, and the layer it names as not
/// checking out.
fn info(reg: &Registry, name: &str, bytes: &[u8]) -> (String, Option<FormatId>) {
    let prefix = &bytes[..bytes.len().min(stuffr::PROBE_LEN)];
    let (chain, _) = resolve_chain_checked(reg, Some(Path::new(name)), prefix).unwrap();
    let layer =
        stuffr::probe::first_unconfirmed_layer(reg, &chain, prefix, &stuffr::DecodeOpts::default());
    (chain.describe(), layer)
}

/// Whole files shorter than the header their magic begins (the final
/// review's measurements): each a magic hit that `stuffr list` calls corrupt,
/// and none of them is identified — while the same bytes as the start of a
/// longer file (a full window) still are, as a damaged archive must be.
#[test]
fn a_whole_file_cut_inside_its_first_header_is_not_identified() {
    let reg = stuffr::registry();
    let mut tar300 = tiny_tar(false);
    tar300.truncate(300);
    let shapes: [(&str, Vec<u8>); 7] = [
        ("x.arc", vec![0x1a, 0x08, 0x58, 0x60]),
        ("x.cpio", b"070701".to_vec()),
        ("x.arj", vec![0x60, 0xea, 0x00]),
        ("x.zip", b"PK\x03\x04\x14".to_vec()),
        ("x.a", b"!<arch>\n!".to_vec()),
        ("headers.js", tar300),
        ("x.gz", vec![0x1f, 0x8b]),
    ];
    for (name, bytes) in shapes {
        assert_eq!(strict(reg, name, &bytes), None, "{name}");
        let (chain, evidence) = resolve_chain_checked(reg, Some(Path::new(name)), &bytes).unwrap();
        assert_eq!(evidence, Evidence::Unconfirmed, "{name}");
        // As a window onto something longer, the same start still counts.
        let id = outer(&chain).unwrap();
        assert_eq!(
            reg.confirm(id, &bytes, false),
            Some(true),
            "{name} as a window"
        );
    }
    // Complete and validly empty: still an ar archive.
    assert_eq!(strict(reg, "e.a", b"!<arch>\n").as_deref(), Some("ar"));
}

/// A codec layer's decoded bytes with no magic take the container the name
/// gives when its check accepts them: `ls` (strict) and `info` (lenient
/// chain plus its check) agree on every one of these.
#[test]
fn a_magicless_inner_layer_is_named_by_the_path_when_it_checks_out() {
    let reg = stuffr::registry();
    const GZIP: FormatId = FormatId::new("gzip");
    const TAR: FormatId = FormatId::new("tar");

    let v7 = encode(reg, GZIP, &v7_tar());
    assert_eq!(
        strict(reg, "v7.tar.gz", &v7).as_deref(),
        Some("tar over gzip")
    );
    assert_eq!(info(reg, "v7.tar.gz", &v7), ("tar over gzip".into(), None));

    // Text named `.tar.gz`: tar's checksum refuses it, so a gzip.
    let text = encode(
        reg,
        GZIP,
        &b"not a tar at all, just some words\n".repeat(30),
    );
    assert_eq!(strict(reg, "y.tar.gz", &text).as_deref(), Some("gzip"));
    assert_eq!(
        info(reg, "y.tar.gz", &text),
        ("tar over gzip".into(), Some(TAR))
    );

    // The empty archive tar writes (`tar -cf x.tar -T /dev/null`): ten
    // blocks of zeros, bare and under gzip.
    let empty = vec![0u8; 10240];
    assert_eq!(strict(reg, "e.tar", &empty).as_deref(), Some("tar"));
    assert_eq!(info(reg, "e.tar", &empty), ("tar".into(), None));
    let empty_gz = encode(reg, GZIP, &empty);
    assert_eq!(
        strict(reg, "e.tar.gz", &empty_gz).as_deref(),
        Some("tar over gzip")
    );
    assert_eq!(
        info(reg, "e.tar.gz", &empty_gz),
        ("tar over gzip".into(), None)
    );

    // A magicless codec inside (brotli in xz): listed, as 0.21.0 listed
    // it — the xz layer over bytes nothing confirms, which is also the
    // chain `info` prints.
    let brotli = FormatId::new("brotli");
    let xz = FormatId::new("xz");
    if reg.codec(brotli).is_some() && reg.codec(xz).is_some() {
        let br = encode(reg, brotli, b"hello hello hello brotli");
        let brxz = encode(reg, xz, &br);
        assert_eq!(strict(reg, "x.br.xz", &brxz).as_deref(), Some("xz"));
        assert_eq!(info(reg, "x.br.xz", &brxz), ("xz".into(), None));
    }
}
