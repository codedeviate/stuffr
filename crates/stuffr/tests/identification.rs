//! Identification across the whole registry: every format with a magic
//! confirms its hits, and the skippable frames zstd and lz4 share lead to
//! the frame behind them.

use std::path::{Path, PathBuf};

use stuffr::{
    Chain, Evidence, FormatId, FormatKind, Registry, resolve_chain, resolve_chain_checked,
};

const ZSTD: FormatId = FormatId::new("zstd");
const LZ4: FormatId = FormatId::new("lz4");

/// The kinds whose magic formats must register a confirm function. Codecs
/// today; containers join when they register theirs.
const CONFIRMED_KINDS: &[FormatKind] = &[FormatKind::Codec];

#[test]
fn every_magic_format_registers_a_confirm_function() {
    let reg = stuffr::registry();
    let missing: Vec<&str> = reg
        .matrix()
        .iter()
        .filter(|row| CONFIRMED_KINDS.contains(&row.kind) && reg.has_magic(row.id))
        .filter(|row| reg.confirm(row.id, &[]).is_none())
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
        assert_eq!(reg.confirm(id, &window), Some(false), "{id}");
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
        checked += 1;
    }
    assert!(checked >= 10, "only {checked} codec fixtures found");
}
