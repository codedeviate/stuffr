#![no_main]
//! The WRITE-side fuzz target (Phase 3c Task 8).
//!
//! The other three targets (`codec`, `container`, `chain`) all point hostile
//! bytes at a DECODER: the input IS the archive, and the invariant is that a
//! malformed one is refused rather than believed. An encoder's failure modes
//! are the mirror image and none of those targets can reach them — a codec's
//! `encoder()` and a container's `create()`/`add()`/`finish()` are not
//! executed by any of the three, at all.
//!
//! So here the arbitrary bytes are the archive's **content**, not its bytes:
//! a selector picks one writable format, the fuzzer's input is written
//! through it as a single entry (container) or as the whole stream (codec),
//! and the result is read straight back. Three things are asserted, and the
//! third is the one nothing else in this harness can check:
//!
//! 1. No panic. An encoder must survive odd input — empty, incompressible,
//!    pathologically repetitive, a length that lands exactly on an internal
//!    block boundary — without aborting the process.
//! 2. Every `Err` passes `check_error_is_classified`. An encoder is allowed
//!    to refuse (a `ResourceLimit` on something absurd is a correct answer);
//!    it is never allowed to refuse as exit 1, which means *stuffr* failed.
//! 3. **What it wrote decodes back byte-for-byte.** A decode-only harness
//!    cannot distinguish "this encoder is correct" from "this encoder and
//!    this decoder share a mistake" — but it cannot even ask, because it
//!    never runs the encoder. This is the only place in the harness where a
//!    write path is exercised at all.
//!
//! **Why the entry name is fixed rather than fuzzed.** Every container here
//! normalises names to some degree — `ar` stores a `/`-bearing name in the
//! BSD extended form, `zip` and `cpio` each have their own rules, and LHA's
//! read side reports names verbatim as of Phase 3c — so a fuzzed name would
//! produce a stream of "round trip changed the name" reports that are all
//! correct behaviour. The name is `payload.bin`, one path component, no
//! separator, ASCII: a name every one of the six writable containers stores
//! inline and unaltered. It is still COMPARED on the way back, so a
//! regression that mangled even that name is a finding.
//!
//! **What a classified `Err` after a successful write does NOT prove.** If
//! the write side completes and the read side then refuses with a properly
//! classified error, this target returns rather than aborting. That is
//! deliberate and it is a real gap, stated rather than papered over: a
//! genuine "wrote something it cannot read" bug wearing a correct exit code
//! would slip through. The alternative — treating any read-back error as a
//! crash — makes the target abort on the first legitimate bound (LHA
//! buffers ~8.4x its input on the write side; a large enough entry is a
//! correct `ResourceLimit`), which is the shape that gets a scheduled job
//! muted. The exactness assertion is what carries the weight here, and it
//! runs on every input the pair actually completes.

use libfuzzer_sys::fuzz_target;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use stuffr_core::testing::{CODEC_SLOTS, CONTAINER_SLOTS, check_error_is_classified};
use stuffr_core::{
    Codec, Container, CreateOpts, DecodeOpts, EncodeOpts, EntryMeta, Error, FormatId, OpenOpts,
    PlainSink, ReaderSource, Source, StreamPolicy,
};

/// The one entry name every writable container stores unaltered. See the
/// module doc for why this is not fuzzed.
const ENTRY_NAME: &str = "payload.bin";

/// A cap on how much of the fuzzer's input is written.
///
/// Not a correctness bound — a bound on false positives, the same role
/// `codec.rs`'s `memory_limit` plays one target over. `lha`'s encoder
/// buffers roughly 8.4x its input before emitting anything, so an
/// unbounded entry reaches `handle_alloc_error` (a SIGABRT with no stuffr
/// message) and libFuzzer reports it as a crash that is not a finding about
/// this project. libFuzzer's own default `-max_len` is 4096, so this bound
/// is only reached by a corpus seed or an explicitly widened run.
const MAX_CONTENT: usize = 256 * 1024;

/// Bounds a read-back so a hypothetical bomb cannot OOM the process before
/// the equality assertion gets to report it. One byte of headroom, so
/// "produced more than was written" still reaches the comparison and fails
/// there with a real message instead of being silently truncated into
/// agreement.
fn read_bounded(r: &mut dyn Read, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    r.take(limit as u64 + 1).read_to_end(&mut out)?;
    Ok(out)
}

/// An in-memory `Write + Send` destination. `stuffr-core`'s own
/// `CaptureWriter` is private to `container_conformance.rs`, so this is the
/// same three lines again rather than a shared helper.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn into_bytes(self) -> Vec<u8> {
        Arc::try_unwrap(self.0)
            .map(|m| m.into_inner().expect("capture mutex"))
            .unwrap_or_else(|arc| arc.lock().expect("capture mutex").clone())
    }
}

impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("capture mutex").extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Encode `content`, decode it straight back, and require the two to agree.
fn codec_round_trip(codec: &dyn Codec, content: &[u8]) {
    let id = codec.id();
    let cap = Capture::default();

    let mut sink = match codec.encoder(Box::new(cap.clone()), &EncodeOpts::default()) {
        Ok(s) => s,
        Err(e) => {
            check_error_is_classified(&e).expect("codec encoder error classification");
            return;
        }
    };
    if let Err(e) = sink.write_all(content) {
        // `from_decode_io` is for the DECODE boundary; a write-side
        // `io::Error` is a genuine i/o failure against an in-memory
        // destination that cannot fail, so anything here is a real defect
        // and `Error::from` (exit 1) reporting it as "stuffr failed" is the
        // correct classification — which is exactly what the oracle refuses.
        let e = Error::from(e);
        check_error_is_classified(&e).expect("codec encode write classification");
        return;
    }
    if let Err(e) = sink.finish() {
        check_error_is_classified(&e).expect("codec encoder finish classification");
        return;
    }

    let encoded = cap.into_bytes();
    let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(encoded)));
    let opts = DecodeOpts {
        // Same bound and the same reason as `codec.rs`'s: a pure codec's
        // declared-dictionary pre-flight must not turn every later run into
        // an OOM instead of a finding.
        memory_limit: Some(64 * 1024 * 1024),
        ..Default::default()
    };
    let mut decoded = match codec.decoder(src, &opts) {
        Ok(d) => d,
        Err(e) => {
            check_error_is_classified(&e).expect("codec decoder error classification");
            return;
        }
    };
    let got = match read_bounded(&mut decoded, content.len()) {
        Ok(v) => v,
        Err(e) => {
            let e = Error::from_decode_io(e);
            check_error_is_classified(&e).expect("codec decode read classification");
            return;
        }
    };

    assert!(
        got == content,
        "round trip through codec `{id}` did not reproduce its input: wrote {} byte(s), \
         read back {} byte(s){}",
        content.len(),
        got.len(),
        if got.len() == content.len() {
            " of the same length but different contents"
        } else {
            ""
        }
    );
}

/// Write `content` as the single entry of a fresh archive, read it back, and
/// require the name and the payload to survive.
fn container_round_trip(container: &dyn Container, content: &[u8]) {
    let id = container.id();
    let cap = Capture::default();

    let mut w = match container.create(
        PlainSink::new(Box::new(cap.clone())),
        &CreateOpts::default(),
    ) {
        Ok(w) => w,
        Err(e) => {
            check_error_is_classified(&e).expect("container create error classification");
            return;
        }
    };
    // `EntryMeta::file` leaves `size` as `None`, which is what
    // `container_conformance.rs`'s own `build` does — a container that needs
    // the length up front derives it rather than being handed a claim it
    // would then have to police.
    let meta = EntryMeta::file(ENTRY_NAME);
    if let Err(e) = w.add(&meta, &mut std::io::Cursor::new(content)) {
        check_error_is_classified(&e).expect("container add error classification");
        return;
    }
    let sink = match w.finish() {
        Ok(s) => s,
        Err(e) => {
            check_error_is_classified(&e).expect("container finish error classification");
            return;
        }
    };
    // `ArchiveWrite::finish` hands the destination back rather than
    // finishing it — the contract that makes container-over-codec possible.
    // Finishing it here is the caller's job, once, and skipping it would
    // truncate the archive this target is about to read back.
    if let Err(e) = sink.finish() {
        check_error_is_classified(&e).expect("container sink finish classification");
        return;
    }

    let bytes = cap.into_bytes();
    let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
    // `StreamPolicy::default()`, not `ForwardOnly`: `arj` declares
    // `needs_seek`, so a forward-only policy could not open what it just
    // wrote at all. The default lets the ladder spool, which is the rung a
    // real caller reading this archive from a pipe would get.
    let resolved = match stuffr_core::resolve(
        src,
        container.id(),
        container.caps(),
        &StreamPolicy::default(),
    ) {
        Ok(r) => r,
        Err(e) => {
            check_error_is_classified(&e).expect("container resolve error classification");
            return;
        }
    };
    let mut ar = match container.open(resolved, &OpenOpts::default()) {
        Ok(a) => a,
        Err(e) => {
            check_error_is_classified(&e).expect("container open error classification");
            return;
        }
    };

    let mut seen: Vec<(String, Vec<u8>)> = Vec::new();
    loop {
        let mut entry = match ar.next_entry() {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => {
                check_error_is_classified(&e).expect("container next_entry classification");
                return;
            }
        };
        let name = entry.meta().name.clone();
        let data = match read_bounded(entry.reader(), content.len()) {
            Ok(v) => v,
            Err(e) => {
                let e = Error::from_decode_io(e);
                check_error_is_classified(&e).expect("container entry read classification");
                return;
            }
        };
        seen.push((name, data));
    }

    assert_eq!(
        seen.len(),
        1,
        "round trip through container `{id}` wrote one entry and read back {} — the write \
         and read sides disagree about what the archive contains",
        seen.len()
    );
    let (name, data) = &seen[0];
    assert_eq!(
        name, ENTRY_NAME,
        "round trip through container `{id}` changed the entry name, which is one ASCII \
         path component with no separator in it"
    );
    assert!(
        data == content,
        "round trip through container `{id}` did not reproduce its entry payload: wrote {} \
         byte(s), read back {} byte(s){}",
        content.len(),
        data.len(),
        if data.len() == content.len() {
            " of the same length but different contents"
        } else {
            ""
        }
    );
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, content)) = data.split_first() else {
        return;
    };
    // Bounded for the false-positive reason `MAX_CONTENT` documents, never
    // for correctness: a shorter slice is still a perfectly good input.
    let content = &content[..content.len().min(MAX_CONTENT)];

    // The high bit picks the TABLE, not the ladder rung — unlike
    // `container.rs`, where it picks seekable versus forward-only. There is
    // no rung to choose on the write side (a `Sink` is a `Write`, not a
    // `Source`), and a target that could only ever reach containers would
    // leave every encoder in `CODEC_SLOTS` — `compress`'s included, the
    // headline of the phase this target ships in — untouched.
    let codec_side = selector & 0x80 != 0;
    let idx = (selector & 0x7f) as usize;

    let registry = stuffr::registry();
    if codec_side {
        let name = CODEC_SLOTS[idx % CODEC_SLOTS.len()];
        // A slot this build did not register is skipped rather than
        // erroring, the same as `codec.rs`: the two tiers register
        // different implementations behind the same names, and a target
        // that panicked on the difference would be unusable on one of them.
        let Some(codec) = registry.codec(FormatId::new(name)) else {
            return;
        };
        // Read-only by construction on some slots (`compress` was, until
        // Phase 3c Task 5). Asking a decode-only codec to encode is a
        // capability question the registry already answers; there is no
        // round trip to make here.
        if !codec.caps().encode {
            return;
        }
        codec_round_trip(codec.as_ref(), content);
    } else {
        let name = CONTAINER_SLOTS[idx % CONTAINER_SLOTS.len()];
        let Some(container) = registry.container(FormatId::new(name)) else {
            return;
        };
        // `arc` and `zoo` land here on every run and return immediately —
        // neither has a writer, and neither is expected to grow one.
        if !container.caps().write {
            return;
        }
        container_round_trip(container.as_ref(), content);
    }
});
