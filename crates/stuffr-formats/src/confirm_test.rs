//! Test helpers for the codecs' and containers' confirm functions
//! ([`stuffr_core::ConfirmFn`]): what every codec's own
//! `confirm_accepts_own_output` and `confirm_never_panics_on_short_input`
//! share.
// Each codec's tests use whichever helpers they need, and a build enabling
// only some codecs leaves the others unused.
#![allow(dead_code)]

use std::io::Write;

use stuffr_core::probe::PROBE_LEN;
use stuffr_core::testing::SharedBuf;
use stuffr_core::{
    Codec, ConfirmFn, Container, CreateOpts, EncodeOpts, EntryKind, EntryMeta, FormatMeta,
    PlainSink,
};

/// A few inputs of different shapes: empty, one byte, compressible text,
/// and 256 KiB of incompressible bytes (several blocks for every codec).
pub(crate) fn inputs() -> Vec<Vec<u8>> {
    let mut noise = Vec::with_capacity(256 << 10);
    let mut x: u32 = 0x9e37_79b9;
    while noise.len() < 256 << 10 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        noise.extend_from_slice(&x.to_le_bytes());
    }
    vec![
        Vec::new(),
        b"a".to_vec(),
        b"the quick brown fox jumps over the lazy dog\n".repeat(200),
        noise,
    ]
}

/// `plain` through `codec`'s encoder at `level`.
pub(crate) fn encode(codec: &dyn Codec, plain: &[u8], level: Option<i32>) -> Vec<u8> {
    let buf = SharedBuf::new();
    let opts = EncodeOpts {
        level,
        ..Default::default()
    };
    let mut sink = codec.encoder(Box::new(buf.clone()), &opts).unwrap();
    sink.write_all(plain).unwrap();
    sink.finish().unwrap();
    buf.contents()
}

/// Every cut of `stream` from `from` bytes up to the probe window (or the
/// whole stream) confirms as a window (`whole` false): a stream cut short
/// inside the prefix is still the format's, so a confirm function may only
/// refuse what it can see is wrong. And `stream` itself, all of it,
/// confirms as the whole stream it is.
pub(crate) fn assert_every_cut_confirms(
    what: &str,
    confirm: ConfirmFn,
    stream: &[u8],
    from: usize,
) {
    let end = stream.len().min(PROBE_LEN);
    for cut in from.min(end)..=end {
        assert!(
            confirm(&stream[..cut], false),
            "{what}: the first {cut} of {} bytes were refused: {:02x?}",
            stream.len(),
            &stream[..cut.min(24)]
        );
    }
    assert!(
        confirm(stream, true),
        "{what}: the whole {}-byte stream was refused: {:02x?}",
        stream.len(),
        &stream[..stream.len().min(24)]
    );
}

/// `stream` cut at every length from `from` short of its end is refused
/// when presented as the whole stream: a file that stops inside the header
/// the check reads is not the format's. Pass the length of that header (or
/// the shortest valid stream), not a whole archive.
pub(crate) fn assert_whole_cuts_refused(
    what: &str,
    confirm: ConfirmFn,
    stream: &[u8],
    from: usize,
) {
    for cut in from.min(stream.len())..stream.len() {
        assert!(
            !confirm(&stream[..cut], true),
            "{what}: a whole stream of the first {cut} bytes was confirmed: {:02x?}",
            &stream[..cut.min(24)]
        );
    }
}

/// Every prefix length 0..=64 of `stream` returns a verdict without
/// panicking, and so does each with its last byte replaced by every value,
/// both as a window and as the whole stream.
pub(crate) fn assert_never_panics(confirm: ConfirmFn, stream: &[u8]) {
    assert_never_panics_upto(confirm, stream, 64);
}

/// [`assert_never_panics`] for a header longer than 64 bytes: every prefix
/// length 0..=`upto`, each also with its last byte bent through every value.
pub(crate) fn assert_never_panics_upto(confirm: ConfirmFn, stream: &[u8], upto: usize) {
    for cut in 0..=stream.len().min(upto) {
        for whole in [false, true] {
            let _ = confirm(&stream[..cut], whole);
            if cut > 0 {
                let mut bent = stream[..cut].to_vec();
                for b in 0..=255u8 {
                    bent[cut - 1] = b;
                    let _ = confirm(&bent, whole);
                }
            }
        }
    }
}

/// The containers' counterpart of [`inputs`]: entry lists of different
/// shapes, so a writer's every header kind reaches the confirm function —
/// no entry at all, one empty file, a name past ustar's 100 bytes (GNU `L`
/// or pax `x` ahead of the real header), a directory, a symlink and a
/// payload of several blocks.
pub(crate) fn archive_entry_sets() -> Vec<Vec<(EntryMeta, Vec<u8>)>> {
    let long = format!("{}/{}.txt", "d".repeat(80), "n".repeat(80));
    let dir = EntryMeta {
        kind: EntryKind::Dir,
        ..EntryMeta::file("adir/")
    };
    let link = EntryMeta {
        kind: EntryKind::Symlink {
            target: "a.txt".into(),
        },
        ..EntryMeta::file("alink")
    };
    let noise = inputs().pop().expect("the noise input");
    vec![
        Vec::new(),
        vec![(EntryMeta::file("e"), Vec::new())],
        vec![(EntryMeta::file("a.txt"), b"alpha\n".to_vec())],
        vec![(EntryMeta::file(long), b"long name\n".to_vec())],
        vec![
            (dir, Vec::new()),
            (EntryMeta::file("adir/a.txt"), b"alpha\n".to_vec()),
        ],
        vec![
            (EntryMeta::file("a.txt"), b"alpha\n".to_vec()),
            (link, Vec::new()),
        ],
        vec![(EntryMeta::file("noise.bin"), noise)],
    ]
}

/// `entries` through `container`'s own writer, the path `stuffr pack`
/// takes. `None` when the writer refuses one of them (a kind or a name the
/// format cannot hold), so a caller skips that set rather than asserting on
/// a half-written archive.
pub(crate) fn write_archive(
    container: &dyn Container,
    opts: &CreateOpts,
    entries: &[(EntryMeta, Vec<u8>)],
) -> Option<Vec<u8>> {
    let buf = SharedBuf::new();
    let mut w = container
        .create(PlainSink::new(Box::new(buf.clone())), opts)
        .ok()?;
    for (meta, data) in entries {
        w.add(meta, &mut std::io::Cursor::new(data)).ok()?;
    }
    w.finish().ok()?.finish().ok()?;
    Some(buf.contents())
}

/// Every set of [`archive_entry_sets`] that `container` writes under
/// `opts` and whose bytes `meta`'s magic matches, cut at every length from
/// `from` through the probe window, confirms. (A tar of no entries is 1024
/// zero bytes: no magic, so nothing for a confirm function to see.) Returns
/// how many archives were checked, for the caller to assert a floor on: a
/// writer that refused everything would otherwise pass vacuously.
pub(crate) fn assert_own_archives_confirm(
    what: &str,
    container: &dyn Container,
    opts: &CreateOpts,
    meta: &FormatMeta,
    from: usize,
) -> usize {
    let confirm = meta
        .confirm
        .unwrap_or_else(|| panic!("{what}: no confirm function registered"));
    let mut checked = 0;
    for (i, entries) in archive_entry_sets().iter().enumerate() {
        let Some(bytes) = write_archive(container, opts, entries) else {
            continue;
        };
        if !matches_magic(meta, &bytes) {
            continue;
        }
        assert_every_cut_confirms(&format!("{what}, entry set {i}"), confirm, &bytes, from);
        checked += 1;
    }
    checked
}

/// Whether one of `meta`'s magic rules matches `bytes`.
pub(crate) fn matches_magic(meta: &FormatMeta, bytes: &[u8]) -> bool {
    meta.magics.iter().any(|rule| {
        bytes
            .get(rule.offset..rule.offset + rule.bytes.len())
            .is_some_and(|at| at == rule.bytes)
    })
}
