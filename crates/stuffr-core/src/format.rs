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
    /// A static, conservative HIGH figure for callers who introspect
    /// `CodecCaps` without encoding anything (property 12's own governor
    /// sizing, and each codec's clamp test) — it is not what the governor
    /// actually divides by during a real encode. The four codecs Phase 1f
    /// gave a multi-threaded encoder (`zstd-c`, `xz-c`, `xz-pure`, `lzip`)
    /// each call their own level-aware `per_worker_bytes(level)` for that,
    /// because the true cost varies by preset (roughly 128 MiB below preset
    /// 7, ~896 MiB at 7 and above, for xz and lzip) and this field's
    /// contract is to round up to a single figure that covers every level a
    /// caller might ask for.
    pub memory_per_worker: Option<u64>,

    /// This build's encoder for the format is markedly worse than the format's
    /// usual one — a fallback that produces valid output nobody would choose.
    ///
    /// `ops` refuses to use it unless the caller opts in, because the output is
    /// indistinguishable afterwards: a user who asked for `.xz` expects xz
    /// ratios, and two builds of stuffr would otherwise produce very different
    /// files from an identical command with no way to tell which they got.
    pub weak_encoder: bool,

    /// True only when the format itself carries no signal whatsoever — no
    /// checksum, no length, no structural decode constraint, no end-of-stream
    /// marker — that could ever distinguish a truncated stream from a complete
    /// one. This does NOT exempt a codec from conformance property 10
    /// (truncation, `conformance.rs`) — property 10 has no bare skip for any
    /// declaration, deliberately: `conformance.rs`'s own `mod broken_codecs`
    /// keeps `testing::MockCodec`, a bare unframed XOR pass-through,
    /// specifically UNABLE to clear property 10
    /// (`mock_codec_clears_every_property_up_to_truncation`), and a codec
    /// that answered nothing at all about truncation would be
    /// indistinguishable from one that never checked.
    ///
    /// What this field switches property 10 to instead is a WEAKER, but
    /// still falsifiable, property: on truncated input, the decoder must
    /// either error, or produce a byte sequence that is a genuine prefix of
    /// what the same decoder produces from the untruncated input — one that
    /// never shrinks as a less severe truncation is tried (monotonicity
    /// across the several cut lengths property 10 already sweeps), and that
    /// is not trivially empty when the untruncated decode is not (closing
    /// the residual gap a bare prefix check alone leaves: the empty string
    /// is a prefix of everything). That still catches real defect classes —
    /// a decoder that mishandles a partial final unit and emits wrong
    /// trailing bytes, reordered bytes, or fabricated padding fails this
    /// exactly as it would fail the strict "must always error" property, and
    /// one that always answers empty on truncation fails it too — while not
    /// demanding a guarantee the format cannot give. `conformance.rs`'s
    /// `a_decoder_that_returns_a_non_prefix_on_truncation_is_caught` and
    /// `a_decoder_that_always_answers_empty_on_truncation_is_caught` prove
    /// the weaker check still fires, by mutation, the same way
    /// `mock_codec_clears_every_property_up_to_truncation` proves the strict
    /// one does.
    ///
    /// Every real codec so far closes the gap the strict property demands: a
    /// mandatory checksum (gzip, zlib, bzip2, snappy), a per-writer optional
    /// one this build's own encoder always turns on (zstd, xz, lz4),
    /// structural invalidity from a range coder (LZMA1), or, for a codec with
    /// neither, an explicit end-of-stream signal (raw deflate's `BFINAL` bit
    /// — see `deflate.rs`).
    ///
    /// `legacy::compress_z` (Phase 3b) is the first exception, and this field
    /// exists because of it, not in anticipation of it: Unix compress's LZW
    /// code stream has none of the above. A prefix of a valid stream decodes
    /// via the identical state machine as the full stream and simply runs out
    /// of bits, producing a shorter but otherwise byte-correct PREFIX of the
    /// real output with no error — measured directly, at the bit level, on
    /// this project's own `hello.Z` fixture: cutting 1, 25 or 50 of its 51
    /// bytes left between 5 and 7 leftover, unconsumed bits in every case,
    /// including the GENUINE, untruncated end (6 leftover bits) — no leftover
    /// count or value distinguishes a real ending from a truncated one, because
    /// both stop for the identical reason (too few bits left for the next
    /// code). Confirmed independently against two production reference
    /// tools, not just this crate: `/usr/bin/uncompress` and `/usr/bin/gzip
    /// -dc` on macOS both exit 0 with silently-partial output on the same cut
    /// files, and in every case what they emit is a strict prefix of the
    /// untruncated decode — never garbage, never a differently-ordered or
    /// padded result. This is a real, external, cross-validated fact about
    /// the format, not a gap in `compress_z`'s own decoder — see that
    /// module's doc for the full measurement.
    ///
    /// Defaults to `false` (the strict property applies) via
    /// [`Self::round_trip`] and [`Self::decode_only`], so every existing
    /// codec's behavior — including `testing::MockCodec`'s own deliberate
    /// failure above — is unchanged; only `compress_z::CompressZ` sets this
    /// explicitly.
    pub truncation_undetectable: bool,
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
    /// A directory can be recorded AS a directory, rather than as an empty
    /// regular file that happens to share its name.
    ///
    /// `ar` is the counter-example and the reason this field exists: its
    /// format has no directory concept at all, so writing one produces a
    /// zero-byte *file* named `proj/sub` — after which an entry named
    /// `proj/sub/a.txt` cannot be extracted, because its parent is a file.
    /// A writer that cannot store the kind is expected to be told so by its
    /// caller and warn, rather than emit the lie.
    pub stores_dirs: bool,
    /// A symlink can be recorded as a link, target and all, rather than as a
    /// regular file carrying the target text as its contents.
    pub stores_symlinks: bool,
    /// Whether reading an archive of this format will NOTICE a corrupted
    /// byte rather than silently returning wrong data — and, where it does,
    /// what kind of guarantee that is. The container-side twin of
    /// [`CodecCaps::detects_corruption`], reusing the same enum and the same
    /// three meanings.
    ///
    /// Read by the read-only conformance harness's corruption property, and
    /// it is the reason that property is honest rather than merely strict:
    /// the harness flips the fixture's middle byte and demands the read-back
    /// differ from the expectation, which a container with no integrity
    /// check at all cannot promise. A fixture whose midpoint lands in a
    /// reserved, comment or padding field no reader consults would fail a
    /// CORRECT container, and the module's own rule is that properties skip
    /// on evidence, never on trust — `ContainerCaps` being one of the two
    /// admissible kinds of evidence.
    ///
    /// Defaults to [`CorruptionDetection::Never`] via [`Self::read_only`],
    /// [`Self::read_write`] and `Default`, so a container claims this the
    /// same way it claims every other capability here: explicitly. `lha`
    /// (CRC-16 per entry) and `arj` (CRC-32 per entry) are the first two to
    /// declare it.
    pub detects_corruption: CorruptionDetection,
    /// `stuffr salvage` has a scanner for this container: it can scan a
    /// damaged archive for entries, report what it proved about each, and
    /// write what it recovered.
    ///
    /// The one answer to "is salvage supported", read by `stuffr formats`'
    /// SALVAGE column and by `stuffr::entries::salvage`, which refuses a
    /// container saying `false` at exit 3 before scanning a byte. It is NOT
    /// the dispatch: the facade still maps a format to its scanner by name,
    /// and a test there pins the two to each other for every container a
    /// build registers, in both directions.
    ///
    /// It says nothing about how much a recovered entry can be trusted —
    /// that is a per-format class of evidence
    /// ([`crate::salvage::Attestation`]), owned beside the scanner dispatch.
    ///
    /// Defaults to `false` via [`Self::read_only`], [`Self::read_write`] and
    /// `Default`, like every other capability here: a container claims it
    /// explicitly, in the same commit that wires its scanner.
    pub salvage: bool,
    /// The writer refuses a second entry under a name it has already
    /// written, so an archive of this format holds one entry per name.
    ///
    /// `zip` is the case: `zip` 8.6.0's `ZipWriter` answers `Duplicate
    /// filename`, while tar, cpio and ar append a repeat like any other
    /// entry. Read by `stuffr convert`, whose source can legitimately repeat
    /// a name (`pack`'s walk never does), to keep the first entry of each
    /// name and warn about the rest rather than fail on the writer's refusal.
    ///
    /// `false` via [`Self::read_only`], [`Self::read_write`] and `Default`;
    /// every registered container states it explicitly.
    pub unique_names: bool,
    /// An entry name containing a NUL byte is stored whole by the writer.
    ///
    /// `false` for a format whose name field is NUL-terminated or
    /// NUL-padded — tar's ustar field and GNU `L` payload, cpio newc's
    /// `c_namesize` name, ar's BSD `#1/N` name (its trailing NULs are
    /// stripped on read), ARJ's header string, ARC's and ZOO's fixed fields
    /// — where the name would otherwise come back shorter than it went in.
    /// Every such writer refuses the name itself (a backstop); `stuffr
    /// convert`, whose source can legitimately carry one (an ar or zip
    /// member name), reads this to skip the entry with a warning instead
    /// (`plan_entry_write`). `pack` never meets one: an OS path cannot hold
    /// a NUL. `true` for zip and LHA, whose names are length-prefixed, so
    /// the writer stores a NUL exactly as given. zip reads it back whole;
    /// stuffr's LHA reader renders it `%00`, as it does every byte outside
    /// printable ASCII (`lha_name_from_parts`): the byte is in the archive,
    /// and only stuffr's rendering of it differs.
    ///
    /// `false` via [`Self::read_only`], [`Self::read_write`] and `Default`,
    /// the safe answer for a container that has not been audited; every
    /// registered container states it explicitly.
    pub nul_in_names: bool,
    /// A symlink TARGET containing a NUL byte is stored, and read back,
    /// whole. The sibling of [`Self::nul_in_names`], and deliberately a
    /// separate flag: tar and cpio differ on exactly this.
    ///
    /// `false` for tar, whose link target lives in the NUL-terminated
    /// linkname field (or a GNU `K` payload, also NUL-terminated) — its
    /// writer refuses one as a backstop, and `stuffr convert` skips such a
    /// symlink with a warning instead (`plan_entry_write`). `true` for cpio
    /// newc and zip, which store the target as the entry's BODY, by length
    /// (measured round trip). A container with no symlink entries
    /// (`!stores_symlinks`) states what its format would imply: `false` for
    /// ar, arj, arc and zoo, which have no link representation at all;
    /// `true` for LHA, whose `name|target` convention lives in its
    /// length-prefixed name field.
    ///
    /// `false` via [`Self::read_only`], [`Self::read_write`] and `Default`;
    /// every registered container states it explicitly.
    pub nul_in_link_targets: bool,
    /// The writer records an entry's owner — its uid and gid — so a missing
    /// one is a real loss: tar, cpio and ar write `meta.uid.unwrap_or(0)`,
    /// so an entry with no ids would assert `root:root`.
    ///
    /// `false` for a format with no owner field the writer fills: zip (the
    /// Info-ZIP `ux` extra field is not written), LHA (no UNIX extension
    /// header is written), ARJ, ARC and ZOO. Read by `plan_entry_write`, the
    /// one owner of the ownership warning: an entry with no ids costs nothing
    /// in a target that would not have stored them anyway, so `stuffr convert`
    /// from lha to zip reports no `uid_gid` loss.
    ///
    /// `false` via [`Self::read_only`], [`Self::read_write`] and `Default`;
    /// every registered container states it explicitly.
    pub stores_ownership: bool,
    /// The container's WRITER can store an [`crate::EntryKind::Hardlink`] as
    /// a link, rather than only as a second copy of the bytes.
    ///
    /// `true` for tar alone (typeflag `1`). `false` for cpio, whose writer
    /// writes `ino=0, nlink=1` for every entry, so a real cpio link would
    /// first need a unique inode per file; and for zip, ar, LHA, ARJ, ARC and
    /// ZOO, which have no link concept at all. Read by `plan_entry_write`,
    /// the one owner of what a target cannot hold.
    ///
    /// `false` via [`Self::read_only`], [`Self::read_write`] and `Default`;
    /// every registered container states it explicitly.
    pub stores_hardlinks: bool,
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
            truncation_undetectable: false,
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
            truncation_undetectable: false,
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
            stores_dirs: false,
            stores_symlinks: false,
            detects_corruption: CorruptionDetection::Never,
            salvage: false,
            unique_names: false,
            nul_in_names: false,
            nul_in_link_targets: false,
            stores_ownership: false,
            stores_hardlinks: false,
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
