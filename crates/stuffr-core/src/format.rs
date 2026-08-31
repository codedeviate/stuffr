use std::fmt;

/// A stable, human-readable format identifier. `&'static str` rather than an
/// enum so `stuffr-formats` can add formats without editing this crate.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FormatId(&'static str);

impl FormatId {
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for FormatId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FormatKind {
    /// A byte-stream transform. Knows nothing about files or entries.
    Codec,
    /// A structure of entries. May invoke codecs internally.
    Container,
}

/// Whether decoding a stream *this codec itself wrote* will notice corruption
/// rather than silently returning wrong bytes, and — where it does — what
/// kind of guarantee that is. A single `bool` used to carry this and meant two
/// different things depending on the codec: a format-wide guarantee for gzip,
/// but only "this build's encoder turns on an optional checksum" for zstd. A
/// caller reading one undifferentiated bool had no way to tell which promise
/// it was getting, so the two review findings that added careful wording to
/// the old field's doc comment are migrated here, one paragraph per variant.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum CorruptionDetection {
    /// The format mandates a check in every valid stream: gzip's trailer
    /// CRC32, zlib's Adler-32, bzip2's per-block and whole-stream CRCs,
    /// snappy's per-chunk CRC32C. This is a format-wide guarantee — it holds
    /// for any conforming stream, not just one this codec produced itself.
    Always,
    /// The format permits a check but leaves it to the writer, so what a
    /// caller can trust depends on which writer actually produced the stream
    /// in front of them — not on which writer this codec happens to be. In
    /// principle that cuts both ways: a codec's own encoder could turn the
    /// check on while some foreign writer leaves it off, or the reverse.
    /// Every codec in this tree currently sits on the first side —
    /// **this build's encoder turns the check on; a foreign writer might
    /// not.** zstd's content checksum, xz's check-type field, and lz4's
    /// frame content checksum are all per-writer choices the format permits
    /// omitting, and this project's own encoders choose to enable all
    /// three: zstd's crate-level encoder omits it *by default* (its CLI
    /// does not, but `zstd_c.rs` and `zstd_pure.rs` both turn it on
    /// regardless), every xz encoder measured here — liblzma's and
    /// lzma-rust2's — selects CRC64 without being asked, and `lz4.rs`'s
    /// encoder calls `content_checksum(true)`, matching what the reference
    /// `lz4` CLI writes by default. lz4 did not always sit here: earlier in
    /// this project's history its own encoder left the checksum off, making
    /// it the mirror case — detection *better* on a typical foreign stream
    /// than on this codec's own output — until that was measured to leave
    /// most corrupted positions in a self-written stream silently wrong
    /// (see `lz4.rs`'s `caps()` and `decoder` docs for the before/after
    /// figures). For all three formats, detection is *weaker* on a foreign
    /// stream than on this codec's own output only when that foreign writer
    /// skipped the checksum — see `zstd_c.rs`'s `decoder` doc for a measured
    /// figure.
    ///
    /// Either way, a codec built over one of these optional-check formats
    /// must document, at the point a caller would meet it, which direction
    /// it sits and what that is worth on a stream this build did not write;
    /// the doc comment on the codec's own `caps()` is not enough by itself —
    /// the decoder needs one too.
    WhenPresent,
    /// No checksum exists, yet malformed input is still detected because the
    /// format's own decoding constraints make corruption produce an invalid
    /// decoder state. LZMA1 is the example: it has no checksum, so it looked
    /// like `Never` — but it was never measured. Measured: sweeping four
    /// payload shapes — compressible text, incompressible random, a source
    /// corpus and all zeros — every corrupted stream either errored or
    /// decoded identically, with **zero** silent-wrong decodes in any of
    /// them. LZMA1's range coder plus its end marker are constrained enough
    /// that a flipped bit almost always drives the decoder into an invalid
    /// state. This is **detection by structural invalidity, not
    /// verification**, and the difference from `Always` matters: a CRC gives
    /// a guarantee against arbitrary corruption, whereas structure gives a
    /// high empirical rate against *random* corruption and no promise at all
    /// against a deliberately crafted edit.
    Structural,
    /// The format carries no check at all — not optional, structurally
    /// absent: a bare deflate or brotli stream fed corrupt bytes produces
    /// different output rather than an error, for any writer, always. Such a
    /// format can never produce [`crate::Error::Corrupt`], and a caller is
    /// entitled to know that rather than assume a guarantee that is not
    /// there. The conservative default: a codec must opt in to claiming any
    /// detection, matching `CodecCaps`'s "every field defaults to false"
    /// contract.
    #[default]
    Never,
}

/// What a codec can do. Every field defaults to `false` (or, for
/// `detects_corruption`, its equivalent conservative variant): a backend must
/// opt in.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CodecCaps {
    pub encode: bool,
    pub decode: bool,
    pub parallel_encode: bool,
    pub parallel_decode: bool,
    /// Stream carries a frame/block index enabling random access.
    pub frame_index: bool,
    /// See [`CorruptionDetection`] for what each state promises.
    pub detects_corruption: CorruptionDetection,

    /// Rough working-set cost of one encode worker, in bytes, when the codec
    /// knows it. `None` means unknown — assume modest.
    ///
    /// Unused until Phase 1f wires parallel encode; it exists now because the
    /// governor already reasons about figures like "xz -9 at ~700 MiB per
    /// worker" with no way for a codec to supply one, and adding the field
    /// after eleven codecs exist means revisiting all eleven.
    pub memory_per_worker: Option<u64>,

    /// This build's encoder for the format is markedly worse than the format's
    /// usual one — a fallback that produces valid output nobody would choose.
    ///
    /// `ops` refuses to use it unless the caller opts in, because the output is
    /// indistinguishable afterwards: a user who asked for `.xz` expects xz
    /// ratios, and two builds of stf would otherwise produce very different
    /// files from an identical command with no way to tell which they got.
    pub weak_encoder: bool,
}

/// What a container can do, and what it needs from its input.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ContainerCaps {
    pub read: bool,
    pub write: bool,
    /// Entries can be enumerated from a forward-only source at full data
    /// fidelity (metadata may be approximate). True for zip, tar, cpio.
    pub forward_parse: bool,
    /// Only a best-effort salvage scan is possible forward-only. Distinct from
    /// `forward_parse`: this rung yields partial results by construction.
    pub degraded_parse: bool,
    /// The authoritative index lives at the end of the stream (zip, 7z, rar).
    pub trailing_index: bool,
    /// Entries share codec state, so reaching entry N decodes 1..N (7z, rar).
    pub solid: bool,
    /// Each entry carries its own codec (zip, 7z).
    pub per_entry_codec: bool,
    /// Random access is required even to enumerate (squashfs, iso).
    pub needs_seek: bool,
}

/// A magic-byte rule. Detection matches these against a bounded prefix.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MagicRule {
    pub offset: usize,
    pub bytes: &'static [u8],
    pub format: FormatId,
}

/// Registration metadata for one format.
#[derive(Clone, Copy, Debug)]
pub struct FormatMeta {
    pub id: FormatId,
    pub kind: FormatKind,
    /// Extensions without the leading dot, lowercase. e.g. `["gz", "tgz"]`.
    pub extensions: &'static [&'static str],
    pub magics: &'static [MagicRule],
    /// Breaks ties when several formats share a magic. Higher wins.
    ///
    /// The ZIP family is why this exists: jar, apk, docx, epub, odt and zip all
    /// begin `PK\x03\x04`, so longest-magic-wins cannot separate them. Rank the
    /// base format above its derivatives, and a bare stream resolves to the
    /// base while a derivative is reached by extension.
    pub priority: i16,
}

impl CodecCaps {
    /// A codec that both compresses and decompresses, with no parallelism and
    /// no frame index. The common shape.
    pub const fn round_trip() -> Self {
        Self {
            encode: true,
            decode: true,
            parallel_encode: false,
            parallel_decode: false,
            frame_index: false,
            detects_corruption: CorruptionDetection::Never,
            memory_per_worker: None,
            weak_encoder: false,
        }
    }

    /// A decode-only codec — the pure-Rust fallbacks that let a build with no C
    /// toolchain still *open* a `.zst` or `.xz`.
    pub const fn decode_only() -> Self {
        Self {
            encode: false,
            decode: true,
            parallel_encode: false,
            parallel_decode: false,
            frame_index: false,
            detects_corruption: CorruptionDetection::Never,
            memory_per_worker: None,
            weak_encoder: false,
        }
    }
}

impl ContainerCaps {
    /// A container that can be read but not written — RAR, whose compressor is
    /// proprietary.
    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            forward_parse: false,
            degraded_parse: false,
            trailing_index: false,
            solid: false,
            per_entry_codec: false,
            needs_seek: false,
        }
    }

    /// A container supporting both directions. Every other capability stays
    /// false — a constructor must not claim what a format has not.
    pub const fn read_write() -> Self {
        let mut c = Self::read_only();
        c.write = true;
        c
    }
}

impl FormatMeta {
    pub const fn codec(
        id: FormatId,
        extensions: &'static [&'static str],
        magics: &'static [MagicRule],
    ) -> Self {
        Self {
            id,
            kind: FormatKind::Codec,
            extensions,
            magics,
            priority: 0,
        }
    }

    pub const fn container(
        id: FormatId,
        extensions: &'static [&'static str],
        magics: &'static [MagicRule],
    ) -> Self {
        Self {
            id,
            kind: FormatKind::Container,
            extensions,
            magics,
            priority: 0,
        }
    }

    pub const fn with_priority(mut self, priority: i16) -> Self {
        self.priority = priority;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_id_round_trips_and_displays() {
        let id = FormatId::new("gzip");
        assert_eq!(id.as_str(), "gzip");
        assert_eq!(id.to_string(), "gzip");
    }

    #[test]
    fn caps_default_to_no_capability() {
        // A format must opt in to every capability. Defaulting to `true`
        // anywhere would let an unimplemented backend silently claim support.
        let c = CodecCaps::default();
        assert!(!c.encode && !c.decode && !c.parallel_encode);
        assert_eq!(c.detects_corruption, CorruptionDetection::Never);
        let k = ContainerCaps::default();
        assert!(!k.read && !k.write && !k.forward_parse && !k.needs_seek);
    }

    #[test]
    fn codec_caps_constructors_express_the_two_common_shapes() {
        let rt = CodecCaps::round_trip();
        assert!(rt.encode && rt.decode);
        assert!(!rt.parallel_encode && !rt.parallel_decode && !rt.frame_index);

        // The pure ruzstd / lzma-rs fallbacks: openable, not writable.
        let d = CodecCaps::decode_only();
        assert!(d.decode && !d.encode);
    }

    #[test]
    fn container_caps_constructors_express_the_two_common_shapes() {
        let ro = ContainerCaps::read_only();
        assert!(ro.read && !ro.write);
        let rw = ContainerCaps::read_write();
        assert!(rw.read && rw.write);
        // Everything else stays opt-in — a constructor must not smuggle in
        // capabilities a format has not claimed.
        assert!(!rw.forward_parse && !rw.trailing_index && !rw.needs_seek);
    }

    #[test]
    fn format_meta_constructors_set_the_kind_for_you() {
        const M: &[MagicRule] = &[];
        let c = FormatMeta::codec(FormatId::new("gzip"), &["gz"], M);
        assert_eq!(c.kind, FormatKind::Codec);
        let k = FormatMeta::container(FormatId::new("tar"), &["tar"], M);
        assert_eq!(k.kind, FormatKind::Container);
    }
}
