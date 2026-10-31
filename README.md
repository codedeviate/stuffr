# stuffr

**stuffr** (pronounced *"stuff"*) is a universal compression and archive toolkit in
Rust — one library and one command for the whole format space, from `zstd` back
to `.arc`.

The name comes from *stuffing* things into a container. That metaphor has real
lineage here: **StuffIt** (`.sit`) was the dominant compressor on classic Mac OS
for the better part of fifteen years, and it is itself one of the formats on the
read list.

> **Status: `stuffr salvage` covers all eight containers — `zip`, `arc`,
> `zoo`, `lha` and `arj` since Salvage Stage 2 (`0.6.0`), and `tar`, `cpio`
> and `ar` since Salvage Stage 3 (scanners first shipped to testers in
> `0.7.1`; the stage completed in `0.8.0`).** `stuffr formats` says which
> containers a build can salvage, and how far each can be trusted, in its
> SALVAGE column: `yes` for the five that checksum an entry's content,
> `weak` for `tar`, `cpio` and `ar`. Every one but `ar` finds its own
> records by scanning for them, so an archive whose index, main header or
> one damaged entry costs the ordinary reader everything behind it still
> gives up what it holds. LHA and ARJ are the sharpest cases:
> LHA carries no index, no entry count and no trailer, so one bad header ends
> `list` for every entry behind it, and an ARJ archive opens with a main
> header the reader must parse before it hands back a single entry — two
> damaged bytes there and `stuffr list` exits 5 over a file whose every entry
> is intact. `salvage` finds each header on its own in both. **`tar`**, the
> Stage 3 addition, is the one format that reaches `SalvageStatus::Complete`
> ("every declared byte was present and the header self-verified, but the
> format offers nothing to check the content against"): tar checksums each
> header and never its payload, so a tar entry is never `Intact`. A
> checksum-valid tar header the scan cannot gate (a junk magic field, a v7
> checksum spelled unlike any known writer's) is never a row: the run names
> it on stderr with its offset and exits 4 rather than 0, because `stuffr
> list` may read the entry this run did not recover. **`cpio`**
> records no checksum of any kind, so a plausible-looking header found
> mid-payload cannot be told from a real one by any evidence the format
> carries: every cpio entry is `SalvageStatus::Unattested` — written under its
> real name, tagged on its row, exit 4 — and never `Complete`. **`ar`** is
> `Unattested` for the same reason, and has a harder limit, stated rather
> than hidden: a member header's only fixed marker is two bytes (`` `\n ``),
> far too weak to search for without reporting noise as entries, so `ar`
> salvage WALKS the archive from its start as `stuffr list` does and stops at
> the first member it cannot read. That recovers a truncated tail fully; it
> cannot cross a hole in the middle, and when it stops there it says so on
> stderr — the offset, and that the members after it are unreachable by
> construction, not absent. A run that recovers three members of ten lists
> three rows; that stderr note is the only sign of the other seven.
>
> `0.8.0` completes Salvage Stage 3; it is tagged, on Homebrew, and
> published to crates.io (all four crates). `0.7.1` is tagged and on
> Homebrew for testers, never on crates.io (`v0.7.0` is tagged but was never built from:
> its deep fuzz found a missing zip entry-count warning, fixed in `0.7.1`).
> `0.8.0` is a breaking bump over both: `ContainerCaps` gained a public
> `salvage` field. A crates.io user coming from `0.6.1` meets the rest of
> Stage 3's breaks too: `SalvageStatus::Unattested` (a new variant on a
> closed enum); `testing::check_salvage_claim(&status, checked,
> Attestation)`, which took `(status, checked)`;
> `SalvageDisposition::SkippedUnattested`; the facade
> `entries::SalvageOutcome`'s new public `sightings` and `walk_stop`
> fields; and one change that **still compiles**: `SalvageScan::verify`'s
> default answers `Unattested` (exit 4) where it answered `Complete` (exit
> 0), so an out-of-tree scanner that never overrode it now reports less.
> One CLI change over `0.7.1`: a `salvage` run (not `--index`-narrowed)
> that saw a header it could not gate exits 4 where it exited 0.
> **1541** tests under `--all-features`, **1476** on the
> default tier — measured from `0.8.0`'s own `make check`, `GATE_EXIT=0`,
> never carried forward.
>
> `0.8.1` is a patch on `0.8.0`. `stuffr list` now reads the static
> libraries GNU `ar rc`/`ar rcs` write on macOS, whose `__.SYMDEF` symbol
> table has a blank mode field — they exited 5; the table lists with its
> mode unknown rather than an invented one. A GNU sparse tar header that
> would overflow the `tar` crate's offset arithmetic (a panic in debug and
> fuzz builds) is refused as corrupt, and a pax extended header over
> 16 MiB is refused as a resource limit (exit 6) before it is buffered;
> `tar` is now pinned to the exact version that guard mirrors. `make fuzz`
> sizes `-runs` to each target's corpus, so it mutates again on a grown
> local corpus. **1562** tests under `--all-features`, **1497** on the
> default tier — measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.9.0` is Phase 5a: **`stuffr convert`**. Codec mode re-encodes the
> compression around a container and leaves the container alone
> (`.tar.gz` → `.tar.zst`); entry mode moves entries from one container into
> another under `pack`'s fidelity rules (`.zip` → `.tar.xz`), with anything
> the target cannot hold skipped and named on stderr (`--strict-fidelity` →
> exit 4). Library surface: `ops::recompress*`, `entries::convert_archive*`,
> `ConvertSource`, `RecompressOpts`, `ConvertOpts`.
> **Breaking:** four new public fields on `ContainerCaps`, which is not
> `#[non_exhaustive]` — `unique_names`, `nul_in_names`,
> `nul_in_link_targets` and `stores_ownership` — so a struct literal that
> lists every field no longer compiles. Nothing was removed.
> **Behaviour changes on existing verbs:** `test`, `list`, `cat` and
> `unpack` now read a compressed container's codec to its end and check its
> trailer, so a `.tar.gz` whose gzip CRC is wrong exits 5 where 0.8.1 said
> "verified" (GNU tar's record padding hid the corruption from the tar
> walk). `unpack` and `cat` may already have written bytes when that exit 5
> arrives, as with any mid-stream corruption. **Known limitation:**
> `--index` reads stop at the last selected entry and so do not reach the
> trailer. The tar, cpio and ar writers refuse an entry name with a NUL byte
> (exit 3) instead of truncating it; `pack`'s fidelity summary wording
> changed. **1656** tests under `--all-features`, **1592** on
> the default tier — measured from this bump's own `make check`,
> `GATE_EXIT=0`.
>
> `0.10.0` reads **hard links**. A tar typeflag-`1` entry and a cpio
> inode group (GNU cpio's data-on-the-last-link layout included) arrive as
> `EntryKind::Hardlink { target }`: `unpack` recreates them as real links
> (a copy where the filesystem refuses one; a link to a symlink as a
> symlink), `convert` keeps them as links into tar and writes full copies
> into containers without links, and `cat` of a link writes its target's
> bytes (the target must be selected too). A link whose target is not
> available is skipped and named (`--strict-fidelity` → exit 4); a link
> target that escapes the destination is exit 7; a tar link naming itself
> (`gtar -cf x a a`) is dropped as the same file declared twice.
> **Breaking:** `ContainerCaps::stores_hardlinks`, a new public field on an
> exhaustive struct. Additive: `EntryKind::Hardlink`,
> `Entry::announce_links`/`announces_links`, `fmt_name`, `SpillWriter`,
> `SpillPolicy::memory_cap`, `ops::refuse_directory_for`,
> `testing::check_display_has_no_raw_controls`. Nothing removed.
> **Behaviour changes:** `list`, `test`, `cat`, `unpack`, `info` and
> `salvage` exit 2 on a directory input (was 1). Every error and fidelity
> message, and `list`/`salvage` text, escapes control and bidi characters
> in names (`a\x1b[31mb`); JSON stays raw. The special-entry skip reason
> no longer mentions hard links. A tar link's `size` is `None`; held-back
> cpio link names come after their data member in entry order; `test`
> does not verify links separately. `cat` of a link without its target is
> a usage error (exit 2) naming both. Writers without link support refuse
> a `Hardlink` handed to them directly (exit 3). BSD `ar` members with an
> odd `#1/N` name length now read correctly (they were misframed), and a
> missing final pad is accepted. A malformed LZMA or XZ zip entry (and,
> on the `c-backed` tier, a malformed zstd one) is corrupt, exit 5 — every
> release since 0.2.0 exited 1 on it (found by this tag's deep fuzz).
> Converting a tar into a container without
> links keeps up to 64 MiB of recent payloads in memory, on top of the
> usual buffers.
> **Known issue (fixed in 0.10.1):** an archive that places an entry where
> it earlier created a directory, or beneath a file it created, makes
> `unpack` fail with exit 1. `--index` reads still stop at the last
> selected entry and skip the codec-trailer check (as in 0.9.0).
> **1771** tests under `--all-features`, **1707** on the
> default tier — measured from this bump's own `make check`,
> `GATE_EXIT=0`.
>
> `0.10.1` is a patch. **`unpack` no longer exits 1 on an archive that
> contradicts itself on disk:** an entry placed onto a directory the
> archive made, or beneath a file it made, is skipped and named (exit 0;
> 4 under `--strict-fidelity`), and the rest is extracted; a conflict with
> what the destination already held stays exit 2. A name too long for the
> filesystem, or one it refuses outright (macOS APFS rejects some
> unassigned code points, `EILSEQ`), is skipped the same way, and salvage
> shares the rule.
> **Symlinks:** a target with `..` after a name (`x/s2/..`, as GNU tar's
> `--transform` writes) or an empty target is skipped and named — it could
> climb out through another link (`x/s2 -> ..` then `s1 -> x/s2/..` left
> `s1` pointing outside the destination in 0.10.0); a target that escapes
> the destination outright is still exit 7, and that refusal now names the
> entry rather than the target text. Additive library API:
> `SymlinkVerdict`, `classify_symlink_target`,
> `testing::check_extraction_contained`; `check_symlink_target` keeps its
> signature, refuses those shapes too, and words a depth escape
> differently. The `container` fuzz target now extracts every seekable
> input to disk and checks containment, classification and that every
> entry is accounted for. Release hygiene: `make check` builds
> `stuffr-formats` alone under `-D warnings`, `make lint-latest` runs clippy
> on the newest stable, and `deps-guard` warns at 500,000 entries.
> **1821** tests under `--all-features`, **1757** on the
> default tier — measured from this bump's own `make check`,
> `GATE_EXIT=0`.
>
> `0.10.2` is a patch. **`salvage` keeps both of two names a case- or
> normalisation-insensitive volume (APFS, HFS+) treats as one** (`README`
> and `readme`, or two Unicode normalisation forms of one name): before,
> the second removed the first and the run still reported both written.
> The second is now written as `NAME.salvaged-N` and reported
> disambiguated (exit 4), and a disambiguated name never lands on an entry
> the archive itself named that way. `unpack` recognises what this run
> made by file identity, not only by spelling, so a case-folded clash of
> KIND with the archive's own entry (a file onto a directory it made, or
> beneath a file it made) is skipped and named rather than blamed on the
> destination; a same-kind folded duplicate
> (`README`, then `readme`) without `--force` is still exit 2, as an exact
> duplicate is, and so is a directory entry onto a file the run made
> (`a`, then `A/`), as it is for an exact name (replaced under `--force`).
> **A hard link whose path is already its target's file removes nothing:**
> under `--force` on such a volume, 0.10.1 could delete a file's only name
> (`A`, `a`, `l -> a`, `A -> a` left only `l`). That entry is now skipped and
> named ("its path already holds its hard-link target", or "names itself"
> when it is one name), and a repeated link stays exit 2 without `--force`.
> Salvage's "not a directory" reason no longer prints the destination
> path. The `container` fuzz target extracts every seekable input a second
> time with `--force`, and its containment oracle tolerates names the
> filesystem refuses.
> **1846** tests under `--all-features`, **1782** on the
> default tier — measured from this bump's own `make check`,
> `GATE_EXIT=0`.
>
> `0.10.3` is a patch. **Hostile input now costs `salvage` work linear in
> its size** in every format. Before, a crafted file could cost seconds per
> MiB, for example cpio headers landing in shared zero runs, or tar
> extension chains converging on one header, up to tens of thousands of
> times the input in reads. Each scanner now searches ahead in growing
> chunks, remembers what it has already read, and charges the bytes a
> verdict needs (a long name, an extension chain, a checksummed header)
> against a budget of `2 × file size + 32 KiB`. Whatever a budget skips is
> reported as a sighting, never exit 6, and real archives never reach it.
> The `salvage` fuzz target holds every scan to 8 × its input + 64 KiB.
> **`list`/`unpack` refuse a GNU tar long name or link over 16 MiB** (exit
> 6, as a pax header over 16 MiB already was). **GNU ar `/SYM64/` symbol
> tables are skipped like `/`**, so 64-bit `ar` libraries list, unpack and
> salvage. `make check` now builds the docs under `-D warnings`. Additive
> library API: `ForwardSearch`, `ScanBudget`, `Sighting`'s work- and
> verdict-bounded kinds, `testing::{CountingSource,
> check_scan_is_linear}`, `tar::MAX_GNU_LONG_NAME`. **Source break, kept
> as a patch under the pre-1.0 policy:** `ZipSalvage`, `ArcSalvage`,
> `ZooSalvage` and `ArjSalvage` hold scan state, so they are no longer
> unit structs. Build one per scan with `new()`.
> **1921** tests under `--all-features`, **1857** on the
> default tier — measured from this bump's own `make check`,
> `GATE_EXIT=0`.
>
> `0.10.4` is a patch. **A truncated `ar` archive is exit 5 in every verb.**
> Before, `list` (and `test` for a symbol table) reported a clean end at
> exit 0 when the file ended inside a member, a `/` or `/SYM64/` symbol
> table or the `//` name table, silently losing every later member. The
> message now names the table or member and its offset; salvage reports a
> cut table as cut short. **A zip symlink target over 64 KiB is exit 6**
> (seekable input), like cpio's identical limit, where it was exit 5.
> **A salvage refusal (exit 3) keeps its work- and verdict-bounded notes**
> instead of dropping them. **Stored salvage sightings are capped at 64 per
> shape** (the count stays exact and the printed note is unchanged), so a
> hostile file no longer costs ~4 MB of memory per MiB. Additive library
> API: `Sighting.more`, `SightingLog`, `RefusalSays`,
> `refusal_with_bounded_notes`, `testing::check_sightings_bounded`.
> **1951** tests under `--all-features`, **1887** on the
> default tier — measured from this bump's own `make check`,
> `GATE_EXIT=0`.
>
> `0.11.0` is a MINOR, the first part of Phase 5: **compatibility links,
> bzip2 family.** Invoked as `bzip2`, `bunzip2`, `bzcat` or `bzip2recover`
> (through a symlink the new `stuffr install-links --dir DIR` makes, never
> automatically), the binary behaves as bzip2 1.0.8: the same flags, files,
> exit codes (0–3) and stderr, byte for byte, and compressed output
> byte-identical on both build tiers. `--version`/`-L` name stuffr on their
> first line; the known deviations are listed under
> [Compatibility links](#compatibility-links). Links point at Homebrew's
> stable `opt` path, so they survive `brew upgrade`. Invoking `stuffr`
> itself is unchanged. **Licence:** `stuffr-cli` now carries code ported
> from bzip2 1.0.8, so its licence metadata is `MIT AND bzip2-1.0.6`
> (`crates/stuffr-cli/LICENSE-bzip2`). Additive library API, all
> `#[doc(hidden)]` or behind `testing`: `stuffr::bzip2_stream` (a
> per-stream bzip2 reader that keeps libbzip2's error kinds),
> `testing::{COMPAT_NAMES, COMPAT_TOKENS, COMPAT_FILES, CompatCase,
> encode_compat_case, decode_compat_case}`; a sixth fuzz target, `compat`.
> **2046** tests under `--all-features`, **1982** on the default tier —
> measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.12.0` is a MINOR, Phase 5's second family: **compatibility links,
> gzip family.** Invoked as `gzip`, `gunzip`, `zcat` or `gzcat`, the binary
> behaves as the platform's own gzip — GNU gzip on Linux and elsewhere,
> Apple's gzip on macOS and the BSDs (`STUFFR_GZIP_FLAVOR=gnu|bsd`
> overrides it): the same flags, files, exit codes and stderr, byte for
> byte, including the foreign formats each one reads (GNU: zip's first
> entry, `.Z`, pack; Apple: `.bz2`, `.xz`, lzip, pack, `.Z`). Apple's
> compressed output is byte-identical on the C tier (`c-backed`, which
> builds zlib); everywhere else it is compatible. GNU `-V`/`-L` print
> stuffr's own MIT notice. The known differences are listed under
> [Compatibility links](#compatibility-links); an input that turns out to
> be its own output is never lost, even where the reference loses it.
> **Licence:** the Apple personality is ported from Apple's BSD-licensed
> gzip sources, so `stuffr-cli` is now `MIT AND bzip2-1.0.6 AND
> BSD-2-Clause AND BSD-3-Clause` (`LICENSE-gzip-bsd`) and `stuffr-formats`
> is `MIT AND BSD-2-Clause` (`LICENSE-unpack-bsd`, the pack decoder).
> Additive library API, all `#[doc(hidden)]`: `stuffr::pack_stream`,
> `stuffr::zlib_c`, `stuffr::xz_stream`, `bzip2_stream::RawStream`; the
> `compat` fuzz target now covers both gzip flavours.
> **2222** tests under `--all-features`, **2150** on the default tier —
> measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.13.0` is a MINOR, Phase 5's third family: **compatibility links, xz
> family.** Invoked as `xz`, `unxz`, `xzcat`, `lzma`, `unlzma` or `lzcat`
> (`stuffr install-links` now makes fourteen names), the binary behaves as XZ
> Utils 5.8.4's `xz`: the same flags, files, exit codes (0, 1, 2) and stderr.
> Output is byte-identical on the C tier (`xz-c`) and compatible on the pure
> tier. The known differences are listed under
> [Compatibility links](#compatibility-links). **Licence:** the port follows
> XZ Utils' `src/xz`, which is 0BSD, so `stuffr-cli` is now `MIT AND
> bzip2-1.0.6 AND BSD-2-Clause AND BSD-3-Clause AND 0BSD` (`LICENSE-xz`).
> Additive library API, all `#[doc(hidden)]`: `stuffr::xz_opts`; the `compat`
> fuzz target now covers xz.
> **2373** tests under `--all-features`, **2278** on the default tier —
> measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.13.1` is a PATCH: three compatibility-link follow-ups. On the C tier
> (`xz-c`) the xz family's header probe is now xz's own call, so corrupt
> input is reported exactly where xz reports it (the difference stays on the
> pure tier only). The bzip2 and gzip families remove their partial output
> on interrupt, as their references do: GNU gzip on the six signals it
> handles, Apple gzip on SIGINT, bzip2 with its own "Control-C or similar
> caught" message and exit 1. The `compat` fuzz target now reaches xz's
> `--files=FILE` and `--files0=FILE`. Additive library API, `#[doc(hidden)]`:
> `xz_opts::Decoder::probe` (C tier).
> **2398** tests under `--all-features`, **2297** on the default tier —
> measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.13.2` is a PATCH that closes twelve old follow-ups. An unsafe-path
> refusal (exit 7) now quotes the offending link target, escaped, and a skip
> reason names an earlier entry the way the archive spelled it (`A`, not
> `a`). `install-links` shows an existing link's own text. The bzip2, gzip and
> xz links close their last interrupt windows: no empty temporary between
> creating and arming it, and bzip2 answers a signal that lands after its last
> check. tar salvage caps the terminal headers it tracks at once at 4096 (a
> sighting past that, never exit 6). The test suites build on Windows, and
> test scratch directories are removed when a test fails. **Source breaks,
> released as a PATCH because no crate outside this workspace depends on
> these crates:** `stuffr_core::Error::UnsafePath.reason` and
> `stuffr::entries::SalvageDisposition::SkippedUnsafePath.reason` are
> `String` (were `&'static str`); `stuffr_cli::compat::links::LinkAction::
> AlreadyPresent` is a struct variant `{ path, text }`.
> **2422** tests under `--all-features`, **2321** on the default tier —
> measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.14.0` is a MINOR that adds the zstd compatibility family: `zstd`,
> `unzstd`, `zstdcat` and `zstdmt`, ported from zstd 1.5.7, with every `-H`
> option except the benchmark (`-b`/`-e`/`-i`), including dictionaries and
> `--train*`, `--patch-from`, `--adapt`, `--list` and
> `--format=zstd|gzip|xz|lzma|lz4`. On the C tier (`zstd-c`) the output is
> byte-identical to zstd's, except cover dictionaries and `--format=lz4`; the
> pure tier is compatible and refuses dictionary compression and training.
> `install-links` now makes eighteen names. Additive library API,
> `#[doc(hidden)]`: `stuffr::zstd_opts`, `stuffr::lz4_frame`,
> `zlib_c::Inflate`, `RawDeflate::with_options`; `stuffr-cli` gains a
> `zstd-c` feature. Also fixed (found by deep fuzz, present since 0.10.0):
> `convert` to tar no longer writes a hard link whose target is the empty
> name, which stuffr's own reader then refused; it skips the link with a
> warning naming it.
> **2598** tests under `--all-features`, **2487** on the default tier —
> measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.15.0` is a MINOR that adds the lz4 compatibility family: `lz4`,
> `unlz4`, `lz4cat` and `lz4c`, behaving as lz4 1.10.0, with every `-H`
> option except the benchmark (`-b`/`-e`/`-i`), including `-l`, `-D`,
> `--list`, `-m`/`-r` and lz4c's legacy arguments. It is a clean-room front
> end: lz4's command line tool is GPL-2.0-or-later and was not read. On the
> C tier (`lz4-c`, liblz4 1.10.0) the `.lz4` output is byte-identical to
> lz4's, and `zstd --format=lz4` now is too; the pure tier (`lz4_flex`) is
> compatible. `install-links` now makes twenty-two names. Library API, all
> `#[doc(hidden)]`: `stuffr::lz4_opts` is added, `stuffr::lz4_frame` (and
> `stuffr_formats::lz4::raw` behind it) is removed; `stuffr-cli` gains an
> `lz4-c` feature.
> **2736** tests under `--all-features`, **2620** on the default tier —
> measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.15.1` is a PATCH that closes 0.15.0's follow-ups. The lz4 link accepts
> `-e#` and `-i#` without `-b` and ignores them, as lz4 does (only `-b#` is
> still refused), and its compression progress line now shows lz4's own
> figures: each job's refresh is over the input read before it (`inf` for the
> first), a one-shot frame's over all of it. The pure lz4 encoder compresses
> from the caller's buffer instead of copying all of its input first. On the
> zstd side, `-l` reads through a buffer (it was 12-15x slower unbuffered), the
> C tier's `-V` banner reports the libzstd actually linked, and
> `WINDOWLOG_MAX` is 30 on 32-bit targets, as libzstd's. The C-tier install
> lines now say `cargo install --locked`. The test suite is stricter: a pty
> capture race that once lost a terminal's last bytes on macOS is closed, the
> fuzz oracle ties a several-input lz4 exit to its failure lines, and two
> large lz4 reference fixtures pin the pure reader.
> **2745** tests under `--all-features`, **2631** on the default tier —
> measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.16.0` is a MINOR that adds the unzip compatibility family: `unzip`
> (and `unzip -Z`), `zipinfo` and `funzip`, ported from Info-ZIP UnZip 6.0
> in two flavours — Apple's `/usr/bin/unzip` on macOS and the BSDs,
> Ubuntu's `6.0-28ubuntu4.1` elsewhere, or as `STUFFR_UNZIP_FLAVOR` says.
> stdout, stderr, exit codes and extracted trees (bytes, modes, times,
> symlinks, quarantine) are identical wherever the reference's behaviour is
> defined, on both tiers; the ten stated deviations are listed under "The
> unzip family". Every extraction write stays beneath its root, in both
> flavours. New decoders ported from Info-ZIP (inflate and deflate64,
> explode, unshrink, traditional PKWARE decryption) also let `stuffr unpack`
> read shrink and implode entries. `install-links` now makes twenty-five
> names. Library API, all `#[doc(hidden)]`: `stuffr::infozip` is added, and
> `bzip2_stream::RawStream` gains `decompress_counted`. A seventh fuzz
> target, `infozip`, covers the new decoders. `LICENSE-infozip` (the
> Info-ZIP licence) joins both crates' licence expressions.
> **2951** tests under `--all-features`, **2837** on the default tier —
> measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.16.1` is a PATCH. One fix: `zstd -l` could read a byte of its input
> twice when a short frame sat at the end of the file (since `0.15.1`;
> output was never affected). The rest makes `make check` easier on a
> shared machine, with no library change. The gate runs 4 test threads by default;
> `make check FULL=1` lifts that, `make fuzz`'s 1 GiB memory cap and the
> Docker thread limit. The heaviest tests use far less memory (the largest
> fell from about 1.7 GB). No test leaves a `stuffr-*` folder in the temp
> directory any more, even after a panic or a read-only tree; the gate fails
> on a new leak and sweeps folders older than a day (`make sweep-tmp`).
> **2957** tests under `--all-features`, **2843** on the default tier —
> measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.17.0` is a MINOR that adds `stuffr bench`: compress your own files
> with every codec this build can write and compare compressed size, ratio,
> compression time and decompression time, then read the winners —
> smallest, fastest to compress, fastest to decompress, and the best
> balance of all three. Only codec work is timed (one stated exception: an
> output too large for memory is written to disk), every format runs under
> the same conditions (one thread unless `--threads`), and the input line
> states them. `--levels` sweeps each codec's levels, `--per-file`
> compresses each file on its own, `--repeat N` reports medians, and
> `--json`, `--csv` and `--table-only` feed other programs. No library
> change. **3027** tests under `--all-features`, **2913** on the default
> tier — measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.17.1` is a PATCH of `stuffr bench` follow-ups. A progress bar now moves
> within each row (blocks with a spinner, drawn only between timed 64 KiB
> pieces and cut to the terminal's width). An input bench cannot read — an
> unreadable file, a dangling symlink, an unreadable directory on a
> pattern's way — is a usage error naming the path (exit 2, was 1). Each
> codec keeps its compressed output in memory when its own worst case fits
> the budget; a row whose output had to go to a temp file while timed is
> marked `*` with a footnote, and JSON/CSV carry `output: memory|disk`. A
> new `lzma-c` feature labels lzma's backend truthfully. The lz4 fuzz
> oracle now holds quiet decodes to the loud re-run's failure count.
> **3051** tests under `--all-features`, **2937** on the default tier —
> measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.18.0` is a MINOR that adds the compress compatibility family:
> `compress` and `uncompress`, in two personalities — a port of Apple's
> `compress` (file_cmds 487.0.1) on macOS and the BSDs, and a port of
> ncompress 5.0 as Ubuntu's `5.0-1` builds it elsewhere, or as
> `STUFFR_COMPRESS_FLAVOR=apple|ncompress` says. stdout, stderr, exit codes
> and compressed bytes are identical to the reference wherever its output is
> a valid stream, on both tiers; the deviations are listed under "The
> compress family". `zcat` stays in the gzip family. `install-links` now
> makes twenty-seven names. `LICENSE-compress-bsd` (Apple's BSD-3-Clause
> notice) and `LICENSE-ncompress` (the Unlicense) join `stuffr-cli`, whose
> licence expression gains `Unlicense`.
> **3133** tests under `--all-features`, **3019** on the default tier —
> measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.18.1` is a PATCH: `stuffr bench` now shows how much RAM each format
> needs. Two columns, `c-mem` and `d-mem`, give each row's peak compress
> and decompress memory (resident set, macOS and Linux), measured in a
> separate untimed run so the timings are unchanged, and a `least memory:`
> winner line joins the others; best balance is unchanged. Memory is on by
> default and `--no-memory` skips it (a run takes up to about twice as long
> with it). JSON gains `compress_mem`/`decompress_mem`/`mem_error`; CSV
> appends three columns. Ctrl-C (and TERM, HUP, QUIT) now clears the
> progress bar and stops a running measurement before bench exits, leaving
> no temporary file. **3159** tests under `--all-features`, **3046** on the
> default tier — measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.18.2` is a PATCH of follow-ups from 0.16.0, 0.18.0 and 0.18.1. One
> user-visible change: a shrink- or implode-method zip DIRECTORY entry that
> declares no content but carries compressed bytes is now refused on read
> (exit 5), as the same entry stored is; it used to read as empty. The
> compat families' signal re-raise resets with `sigaction`; nothing else a
> user can see changes. New tests cover compress's read-error rule (A4) end
> to end, bench with no input, and an unzip short filename read; the unzip
> ruling pins now run on Linux too; the compress interrupt tests skip when
> the reference hangs; `tests/cli.rs` is now `tests/cli/`.
> **3165** tests under `--all-features`, **3052** on the default tier —
> measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.19.0` adds the zip family: `zip`, `zipcloak`, `zipnote` and `zipsplit`
> answer as Info-ZIP Zip 3.0 does, in two flavours — Apple's `/usr/bin/zip`
> (the default on macOS and the BSDs) and Ubuntu's `zip 3.0-13ubuntu0.2`
> (elsewhere), or `STUFFR_ZIP_FLAVOR=apple|ubuntu`. stdout, stderr, exit
> codes and every archive byte are the reference's; encrypted entries are
> compatible, identical outside their 12-byte headers and encrypted data.
> Thirty deviations are listed in "The zip family" below; the ones that
> matter most keep your data where zip can lose it (an archive that is its
> own input, `-m` before the archive is written, an interrupt while the new
> archive replaces the old). `install-links` makes thirty-one names.
> **3364** tests under `--all-features`, **3251** on the default tier —
> measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.20.0` adds the brotli family: `brotli`, `unbrotli` and `brcat` answer
> as Google's brotli 1.2.1 does. stdout, stderr and exit codes are the
> reference's on both tiers; the `.br` bytes are identical on the C tier
> (`brotli-c`, in `c-backed`, which builds the vendored libbrotli 1.2.1)
> and compatible on the pure tier, which also refuses `-D`. Ten deviations
> are listed in "The brotli family" below; the ones that matter most keep
> your data where brotli can lose it (an input that is its own output, a
> later input an earlier output would overwrite, `-j` after a failed
> close). `install-links` makes thirty-four names.
> **3423** tests under `--all-features`, **3308** on the default tier —
> measured from this bump's own `make check`, `GATE_EXIT=0`.
>
> `0.21.0` teaches `stuffr ls` (also `stuffr files`) to list a folder: every
> file in it that stuffr can open, newest first, as format, size, date and
> name, judged by the file's own first bytes, so a download with no
> extension is found and a misnamed one is not. `-r` goes into subfolders,
> `-a` shows hidden names, `-n` sorts by name, `--json` is for scripts.
> `stuffr ls archive.zip` still lists the archive's entries, exactly as
> `stuffr list` does. Nothing is ever downloaded or changed to look.
> **3472** tests under `--all-features`, **3357** on the default tier —
> measured from this bump's own `make check FULL=1`, `GATE_EXIT=0`.
>
> `0.22.0` makes identification truthful. Every format now checks its own
> header behind its magic bytes, so `stuffr ls` lists only files that really
> are what it says: an Apple disk image is no longer shown as `zlib`, `bzip2`
> or `xz`, and a colour cube or a JavaScript file no longer passes as `arc`
> or `tar`. Every verb but `salvage` refuses a disk image with exit 3 and
> says what it is; `salvage` always tries. `info` names the layer whose
> header did not check out. Blender's `.blend` files (zstd with skippable
> frames) now decode on the pure tier too.
> **3630** tests under `--all-features`, **3509** on the default tier —
> measured from this bump's own `make check FULL=1`, `GATE_EXIT=0`.
>
> `0.23.0` is for library callers and for zips that lie. Every codec now
> decodes from a borrowed reader (`stuffr_core::decode_reader`), so a
> compressed member inside a tar or zip, a `.Z` included, decodes without
> copying it out first; `Source` and `SeekRead` no longer require `Send`.
> A zip whose local headers and central directory disagree (name, method,
> CRC, sizes, flags; on a pipe also count and order) is reported, and
> `--strict-fidelity` makes that exit 4. A piped zip now reads its central
> directory too, so a well-formed one passes `--strict-fidelity`. zip moves
> to 9.1.3 and zstd to 0.14.3 (libzstd is still 1.5.7), clearing their
> advisories; four exit codes on malformed zips moved (see CONTRIBUTING).
> **3679** tests under `--all-features`, **3556** on the default tier —
> measured from this bump's own `make check FULL=1`, `GATE_EXIT=0`.
>
> Two user-visible changes on archives that already exist. First, `salvage
> --list` no longer calls an intact-length archive truncated: `Partial
> (truncated)` now means the archive FILE is shorter than the entry's own
> header declares, and a new `Partial (decode failed)` means every declared
> byte is present and did not yield the declared content. Each names
> something different to do about it — find a longer copy, or accept that the
> bytes you have are damaged. Measured before the fix, with one flipped byte
> mid-payload and every declared byte present on disk: ZOO's `lzd` and LHA's
> `-lh5-` said `truncated` while ARC's Squeezed and ZOO's `-lh5-` said
> `checksum mismatch`, for identical damage — the difference being only
> whether that codec's decoder survives to the end of the stream, which is
> not a fact about the archive. Second, one entry can no longer end a
> run: an entry over the size ceiling, an entry the filesystem refuses to
> write, and an entry whose name stuffr's own containment refuses are all
> per-entry outcomes on their own row now, where any of the three used
> to abort the archive and take every recovered entry with it — in the one
> verb whose whole purpose is not losing things. The containment case is the
> last of the three to fall, closed in the final fix wave: a 228-byte zip
> whose middle record simply has an empty name recovered the first entry,
> stopped at exit 7, lost the third and printed no summary at all, while
> `--index 0 --index 2` recovered both. **Nothing about the refusal itself
> changed** — an escaping name is never written, and a run that meets one
> still exits 7, which now outranks every other salvage exit code.
>
> Third, and not a salvage change at all: **an entry name (or symlink
> target) containing a NUL byte is now refused at exit 7** rather than
> reaching `std::fs`, which rejects an interior NUL and left `stuffr unpack`
> ending at **exit 1** — the code reserved for stuffr itself having failed,
> on a name the archive chose. It is not an attack shape: a zeroed run
> inside an ordinary name produces it, and it was the only exit 1 in a
> 31,460-invocation corruption sweep over 2,860 mutated archives in all five
> formats salvageable at the time (Stage 2). `list` and `test` still exit 0 on such an archive —
> neither turns a name into a path — and `salvage` skips that one entry and
> recovers the rest, at 7 where it used to report 4.
>
> **How much to trust a recovered entry is not the same answer for all five
> checksummed formats, and the difference is worth knowing before you rely on one.** An
> `Intact` row means this build decoded the entry's payload and it agreed
> with the checksum the archive carries. What differs is how much
> independent evidence stands behind the code that read it:
>
> * **ARC and ZOO — strongest.** Their fixtures are a borrowed corpus, and
>   the CRC in each archive's own header was computed by a DOS-era archiver
>   decades ago with no knowledge of this project. Agreeing with that number
>   is genuinely independent evidence.
> * **LHA — strong.** Checked against `lhasa`, a live external decoder that
>   shares no code with the `delharc` reader used here.
> * **ARJ — this project alone.** No `arj` or `unarj` binary is obtainable
>   on any platform in reach, so the fixture, the reader, the encoder, the
>   salvage scanner and the CRC-32 comparison are all stuffr's reading of an
>   unofficial specification plus one Rust crate's parser. A misreading
>   shared between those two leaves every test in this repository green. It
>   has never been checked against an implementation that was not ours.
>   Treat an `Intact` ARJ row as this build's best reading, not as a second
>   opinion; where the bytes matter, keep the damaged original.
> * **zip — strong, and differently evidenced from the other four.** Its
>   scanner is checked against Info-ZIP's own `unzip`/`zip -FF`, and the
>   comparison found `zip -FF` fabricating bytes on a truncated archive —
>   copying a central-directory record from elsewhere in the same file into
>   a payload that no longer exists, reporting success. stuffr writes the
>   genuine surviving prefix as `NAME.partial` instead and never invents.
>   So zip's evidence is a live external tool, like LHA's, rather than a
>   decades-old checksum like ARC's and ZOO's.
>
> A ZOO note worth carrying, because a future reader meeting `unarc-rs` will
> meet the wrong number: **ZOO's fixed directory-entry record is 56 bytes,
> not the 59 that crate models.** `zoo.h`'s `SIZ_DIRL` is 56; 59 is reached
> by three separate modelling errors that happen to cancel (`var_dir_len` as
> a `u8`, `dir_crc` as a `u32`, and `namlen`/`dirlen` pulled into the fixed
> part). A reader built on 59 computes every payload position three bytes
> late and tolerates three bytes of genuine truncation on *every* archive.
> Verified three ways, including by reading a real fixture with no stuffr in
> the loop: the record's own `offset` field says 116, the 56-byte model
> computes 116 and the 59-byte model 119. See
> `crates/stuffr-formats/src/legacy/zoo.rs`'s module doc for all five
> measurements. **1408** tests under `--all-features`, **1343** on the
> default tier — measured from `0.6.1`'s own `make check`, `GATE_EXIT=0`,
> never carried forward.
>
> **`0.6.1` closes four exit-code defects that `0.6.0` shipped**, all four
> found by the scheduled deep fuzz run and none of them reachable by the
> gate or by the 2,000-iteration smoke fuzz. Each was invisible until the
> one before it was fixed, because the run aborts on its first crash:
>
> * A `.Z` stream at `maxbits = 9` could name a dictionary slot that can
>   never be filled, and **panicked** — exit 101 from `list`, `test` and
>   `cat` on a 602-byte file. Now `Corrupt`. Nine is the one width where
>   this is reachable; 10 through 16 cannot represent the code at all.
> * A zip64 extended-information field declaring a local-header offset
>   above `i64::MAX` reached `lseek(2)` as a negative `off_t`, and the
>   kernel's `EINVAL` surfaced as **exit 1**. Now `Corrupt`, refused before
>   the syscall, for every seekable source rather than per container.
> * A decoder's own error below a container reached **exit 1** on `list`
>   and `test` while `cat` answered `5` on the same bytes — four sites,
>   reached through five of the eight registered containers and four
>   verbs, plus a `--max-ratio` refusal that reported 1 instead of 6.
>   The conversion is now structural: an
>   `io::Error` from a decoder cannot reach the exit-code wildcard, and a
>   genuine disk or permission failure passing *through* a decoder still
>   reports 1, so neither lie is available.
>
> None of these is a salvage defect; all four are read-path classification,
> and the oldest predates Stage 2 entirely. They are listed because an exit
> code is a promise this project keeps in writing.
>
> **Status: Salvage Stage 1 is complete at `0.5.0` — `stuffr salvage`
> recovers what a damaged zip's raw local-header scan can prove, even where
> its central directory alone would show less.** `list`, `cat`, `unpack` and
> `test` all stay exactly as uncompromising as they already were; `salvage`
> is the one recovery-biased verb, and it is that willingness to accept
> less-than-proven content that buys the other four the freedom to stay
> strict. Its own `--strict` asks for that same discipline on request. A
> scan position is a different numbering from `list`'s own index — on an
> archive where a name is duplicated, `salvage --index 6` and `list --index
> 6` can name different entries, or `list`'s may not exist at all — and
> every message says "scan position", never "index", so the two cannot be
> confused. A damaged archive can hold two records under one name; where
> their content differs, both are recovered and the second lands as
> `NAME.salvaged-N` rather than over the first — the same reasoning that
> gives an unproven payload `.partial`: recover by default, and let the
> filesystem carry the distinction. `salvage` has no `--force` and never
> removes or overwrites a file it did not write in the same run: a name
> the destination already holds (a file of yours, a previous run's
> output, a symlink, or the archive being read) gets the recovered copy
> as `NAME.salvaged-N` beside it, named on stderr, exit 4. `unpack
> --force` likewise never replaces the archive it is reading: an entry
> carrying the archive's own path is skipped with a warning. Cross-checked against Info-Zip's `zip
> -FF`: on a truncated archive, `-FF` copies a central-directory record from
> elsewhere in the same file into the payload gap and reports success, where
> `stuffr salvage` invents nothing — it reports the entry `Partial
> (truncated)`, writes the genuine surviving prefix as `NAME.partial`, and
> exits 4. A real disagreement, recorded rather than tuned away, since the
> fabrication is Info-Zip's own bug, not a shape to chase.
> This reverses a Phase 2 ruling ("declared, not recovered"): the
> central-directory parse that ruling declined to build now serves recovery
> as well as `list`'s own duplicate-name warning. See
> [CONTRIBUTING.md](CONTRIBUTING.md#fuzzing) for the fuzz harness's new
> fifth target, and `crates/stuffr-cli/src/examples.txt`'s "RECOVERING A
> DAMAGED ARCHIVE" section for the worked examples. **1153** tests under
> `--all-features`, **1088** on the default tier.
>
> **Status: Phase 3c is complete at `0.4.2` — twelve round-trip codecs
> (`compress` joined them in Task 5) and six round-trip containers
> (`lha` joined them in Task 6 and `arj` in Task 7), plus
> two read-only legacy containers, all in the
> default build, which needs no C toolchain to read *or write* xz, LZMA1 or
> LZIP.** `stuffr pack`,
> `unpack`, `cat`, `info`, `list`, `test` and `formats` all work, on files
> and through pipes, and `curl … | stuffr cat - | grep pattern` runs.
> `stuffr formats` lists codecs `brotli`, `bzip2`, `compress`, `deflate`,
> `gzip`, `lz4`, `lzip`, `lzma`, `snappy`, `xz`, `zlib`, `zstd` and containers
> `ar`, `arc` (`.pak` included), `arj`, `cpio`, `lha` (`.lzh` included),
> `tar`, `zip` (`zip64` included), `zoo` on every build — each round-trip codec and container proven
> against the conformance harness Phase 1c introduced and later cycles grew
> to twelve properties (`compress` graduated into that full set in Task 5,
> having run only the fixture-driven decode-only variant before; `lha` in Task 6
> and `arj` in Task 7 did the same), and each remaining
> read-only legacy container — `arc` and `zoo` — proven against a
> fixture-driven variant of the same harnesses, built for exactly this shape
> (see the Phase 3b paragraphs below), all of it then proven to coexist. The
> `legacy` feature (bundled into `full`/`--all-features`) still exists and
> still works — it is what `--no-default-features --features pure` would
> otherwise lack, not something a default build needs to opt into. **1055**
> tests under `--all-features`, **990** on the default tier — a different
> set, not a subset, because the two tiers select different backends.
> (Every figure printed here has been stale at least once — 963/898 and
> then 1018/953, each carried forward from a task that added tests after
> writing the sentence. Both counts are measured from `make check`'s two
> `cargo test` runs at the moment of the bump, never carried forward.)
> Clean across build, clippy and fmt.
>
> **The fuzz harness gained a fourth target in Task 8, and it is the
> first that runs an ENCODER.** `codec`, `container` and `chain` all
> point hostile bytes at a decoder, so a phase whose headline was three
> new encoders had added no fuzz coverage of its own work at all.
> `roundtrip` inverts the input — the fuzzer's bytes become the
> archive's *content* rather than its bytes — writes them through one
> writable format picked by a selector byte, reads them straight back,
> and requires the payload to survive byte-for-byte. See
> [CONTRIBUTING.md](CONTRIBUTING.md#fuzzing).
>
> **Phase 3a added a fuzzing harness and fixed what it found — the
> behaviour is the headline, not the fuzzer.** Five exit codes changed or
> tightened, each a bug fix rather than a new feature:
> `Error::NotSeekable` — the mandated reply to `by_index` on a forward-only
> source, e.g. an archive read from a pipe — moved from exit 1 to its
> correct **exit 3**, so a valid archive on a pipe no longer reports "stuffr
> failed" for a by-design refusal. A malformed codec stream with no
> container above it (a truncated `.zz`, an empty `.lz`) moved from exit 1
> to the correct **exit 5**: `stuffr list`/`cat` used to disagree on the
> same bytes. A stored zip entry is now held to the size its header
> declares (**exit 5** on a mismatch) — a crafted entry declaring a size
> with no matching data used to satisfy its own CRC and report "exact
> fidelity" at exit 0 (`stuffr list` still reports the declared size on such
> an entry, since `list` reads no payload in any container that streams —
> Phase 3c's `arc` and `zoo` decode an entry whole, so `list` can fail on
> those two, at exit 3 or 5). `cpio` and
> `ar` now refuse an absurd size field **before** it reaches an allocator
> (**exit 6**) rather than after; a 68-byte `.a` that used to panic (exit
> 101) is now a clean **exit 5**. None of this changed a public API
> signature — see [CONTRIBUTING.md](CONTRIBUTING.md#versioning) for why
> `0.3.1` rather than `0.4.0` is the right version for it. Also: `ar` is now
> pinned exactly at `=0.9.0`, because `ar.rs` mirrors several private facts
> about its header state machine.
>
> **`0.3.0` carries more than the write-side composition it was bumped for.**
> Entries can be reached by **index**: `stuffr list`'s first column is the
> entry's 0-based position in archive order, and `cat --index N` and `unpack
> --index N -C DIR` select by it (repeatable, mutually exclusive with
> PATTERNS). `list` now reports fidelity the way `test` and `unpack -C`
> already did — it used to drop the report and print rows in silence — and
> takes `--strict-fidelity`, gating at exit 4. That matters most on a zip
> whose central directory holds records **shadowed by a duplicate name**: the
> `zip` crate collapses them, so an 8-record file enumerates 6 entries, and
> stuffr now parses the EOCD's declared count itself and raises a fidelity
> warning naming both figures rather than announcing exact fidelity. And a
> `pack` whose plan would replace a good archive with an empty shell is
> **refused** (exit 2) one line before the destination is created, so the
> existing archive stays byte-identical.
>
> **Containers bring sharp edges worth knowing before they read as bugs.**
> The zip crate (9.1.3, as 8.6.0 before it) cannot forward-read entries
> written with data descriptors —
> exactly what many tools emit when streaming a zip *to* a pipe — so stuffr
> reports that as `Unsupported` (exit 3, with a hint), never as corruption:
> stuffr forward-reads an ordinary zip but not one another tool streamed to
> a pipe, which bears directly on this milestone's own name. The pure tier
> cannot read a zstd-compressed zip entry (`--features c-backed` closes it,
> because zip's `zstd` entry codec is the one that pulls in a C-compiling
> crate). `cpio` is `newc` only — not odc, not crc. `--strict-fidelity`
> fails on essentially any tarball containing a symlink, because a
> symlink's mtime cannot be restored without following the link. `pack`
> now walks a directory tree, and `pack -o bundle.tar.gz` (and
> `bundle.tgz`) writes the container inside the codec in one pass, so
> `stuffr pack proj -o backup.tar.gz` is a single command. What the walk
> cannot store it names in a fidelity warning rather than dropping
> silently — a socket, an undecodable name, a directory it may not list,
> a file it may not open, or a directory or symlink handed to `ar`, which
> has neither. **A permission error inside a walked tree is a warning, not
> a failure:** one unreadable file or subdirectory is skipped, named in the
> report, and the pack still exits 0, because losing a whole backup over
> one file in a home directory is worse than losing that file. **A file
> that changes size under the walk is the same bargain:** the entry header
> was written from an earlier `stat`, so a file that shrank is padded with
> zeros to the length it promised and one that grew stops there, with the
> discrepancy named — GNU tar's `file changed as we read it`, where before
> it aborted the pack and produced nothing. Pass
> `--strict-fidelity` to make any such loss exit 4 instead — the archive is
> still written and kept, exactly as `unpack -C --strict-fidelity` keeps
> what it extracted; the exit code is the verdict, not the file's absence.
> Excluding the output from its own walk is reported but is deliberately
> NOT one of those losses, so a nightly
> `pack . -o backup.tar --force --strict-fidelity` stays green.
>
> **The build tiers, and what actually differs between them:**
>
> | format | default (`pure`) build | `--features c-backed` |
> |---|---|---|
> | `xz`, `lzma` | read **and write** | read and write — ~1.4x faster encode |
> | `zstd` | read; write only under `--allow-weak-encoder` | read and write |
> | `lzip` | read and write | identical — no second backend exists |
> | the other seven | read and write | identical |
>
> **The only capability difference is zstd's encoder.** For xz and LZMA1,
> `c-backed` is a speed choice: measured in release on a 6.5 MB payload, encode
> 252 ms against 346 ms and decode 9.4 ms against 16.7 ms, at output sizes
> 2,098,920 against 2,098,968 bytes — parity. The pure xz and LZMA1 backends
> come from `lzma-rust2`, a port of Tukaani's "XZ for Java"; the system `xz`
> tool validates and byte-for-byte decodes what they write, and they read its
> output the same way. LZIP is a third format built on that same dependency,
> but unlike xz and LZMA1 it has no second, C-backed implementation to speed up
> — `c-backed` simply does not touch its row, in either direction.
>
> A default build writes `.zst` only behind `--allow-weak-encoder`, because
> `ruzstd`'s encoder produces files about 76% larger (3.53x against C zstd's
> 6.21x on an 11.7 MB corpus) at roughly 8x the time. `stuffr formats` shows
> `weak` rather than `yes` in that row, so a build's honesty is visible without
> running anything.
>
> **Parallel encode, opt-in and off by default.** Three of the eleven
> formats parallelise when asked — `xz` and `lzip` on every build, and
> `zstd` behind `--features c-backed` (the default `ruzstd` encoder has no
> multi-threaded path) — across four codec *implementations* (`zstd-c`,
> `xz-c`, `xz-pure`, `lzip`): `xz-c` and `xz-pure` are the same format and
> registration picks exactly one, so no single build ever has more than
> three parallel rows. `--threads N`, `--threads 0` (auto), `--turbo` and
> `STUFFR_THREADS` all enable it; omitting every one of them encodes
> single-threaded, so the same input always produces the same bytes.
> Reproducibility is scoped precisely — **same input + same flags + same
> environment** — because `--threads 0`'s auto-detection resolves against
> cgroup CPU quotas and so is not machine-independent by itself. `stuffr
> formats`' PARALLEL column reports this truthfully per build: `yes` for `xz`
> and `lzip` on the default (`pure`) tier and `-` for `zstd`; add
> `--features c-backed` and `zstd` becomes `yes` too.
>
> **`--memory-limit` does two jobs.** On encode it bounds the worker count —
> the governor divides the limit by each codec's measured per-worker demand,
> handing out fewer, slower threads rather than risking the OOM killer. On
> decode it bounds allocation instead, defaulting to 25% of available RAM
> (cgroup-aware); `stuffr info` reports the resolved figure, rendered for humans
> (`256 MiB`, never a raw byte count).
>
> **The per-worker figures, measured directly in release, have a consequence
> worth stating plainly.** Below preset 7, `xz` and `lzip` cost roughly
> **128 MiB per worker**; at preset 7 and above that jumps to roughly
> **896 MiB** — the match finder dominates, at about 10.5x the dictionary
> size, not the block buffer. So at the default budget:
>
> | `--memory-limit` budget | preset ≤ 6 | preset ≥ 7 |
> |---|---|---|
> | 256 MiB (the floor — what macOS gets, with no `/proc/meminfo`) | 2 workers | **1 worker** |
> | 4 GiB (Linux, 16 GB available) | 32, then CPU-capped | 4 workers |
>
> **Someone on macOS running `--threads 8 --level 9` silently gets one
> worker** unless `--memory-limit` is raised — that is the governor working
> as designed, not a bug, and it reads as one if left undocumented.
>
> **Two defects carried out of Phase 1e are now closed.** The decode
> denial-of-service is fixed for all three pure codecs it touched, with the
> allocation prevented rather than merely reported: `lzma-pure` 538.8 MB →
> 1.66 MB, `xz-pure` 68.45 MB → 1.18 MB, `lzip` 538.4 MB → 1.18 MB peak RSS,
> each now refusing at exit 6 with a message naming the declared size, the
> limit and the flag — never exit 5, so a corrupt file and an oversized one
> stay distinguishable. A legitimate large-dictionary file still decodes.
> Brotli's trailing-data divergence is fixed too: it now rejects concatenated
> streams and NUL-padded input, matching reference `brotli` 1.2.0 exactly, at
> no throughput cost.
>
> **A fifth instance of a defect class this project keeps finding: a
> concatenated stream silently truncated to less than all of it.** Bare
> `lzma-rust2::LzipReader` treats a damaged LATER member's header exactly like
> a clean end of stream — it returns `Ok` with only the earlier members'
> bytes, no error, the same shape gzip's, bzip2's, xz's and LZMA1's naive
> bindings were each caught doing earlier in this project. `lzip.rs` closes it
> with two checks of its own (a magic check ahead of the first member, and an
> unconsumed-bytes check after the reader reports done), each with a
> regression test, and validates the fix and the format's ordinary
> multi-member case against the reference `lzip` 1.26 tool directly, in both
> directions.
>
> **Phase 3b adds three READ-ONLY legacy formats — Unix `compress` (`.Z`),
> LHA/LZH and ARJ — behind their own `--features compress`/`lha`/`arj`
> (bundled into `--features legacy`, itself in `default` alongside `pure`,
> and also in `full`/`--all-features`).** All three
> were decode-only by construction when the phase landed, not by a missing
> feature: there never was a `compress` encoder here, and `lha`/`arj` read
> archives the real, decades-old `lha`/`lhasa` and `arj`/`unarj` tools
> wrote. `stuffr pack --format lha` (or `arj`, or `compress`) refused at
> **exit 3**, naming the format read-only in this build, rather than failing
> obscurely. **Phase 3c has since given all three real encoders** —
> `compress` (Task 5), `lha` (Task 6) and `arj` (Task 7); see the
> paragraphs at the end of this block. `arc` and `zoo` are now the only
> formats that answer that refusal.
>
> **LHA and ARJ differ in shape, and the difference is visible at the
> command line, not just in the source.** LHA (`delharc`) parses forward off
> a pipe with no `Seek` anywhere in its decode path, so `cat old.lzh | stuffr
> list -` is a genuine forward parse, the same footing `tar`, `ar` and `cpio`
> already stand on. ARJ (`unarj-rs`) needs `Seek` to read an archive at all,
> so a piped ARJ is spooled to a temp file first — the same ladder rung `zip`
> takes when forced onto its indexed path — and reports `Rung::Spilled`
> rather than `ForwardOnly`; that rung is authoritative, so it works, but it
> spends disk a plain LHA read never has to. ARJ also has no per-entry
> streaming reader at all: an entry decodes whole, so `--max-ratio` is a
> coarser bound there than on the five streaming containers (`tar`, `ar`,
> `cpio`, `zip`, `lha`) — Phase 3c's `arc` and `zoo` decode whole for the
> same reason, so they are coarse too — and a fixed 256 MiB
> per-entry ceiling — checked **before** allocating, at exit 6, never exit
> 5 — is the real backstop against a hostile header, since there is no
> `--memory-limit`-style knob for a container to read in the first place.
>
> **The three fixtures carry different evidentiary weight, and that is
> written down rather than left for a reader to assume parity.** `.Z`'s
> fixture is produced by the real `/usr/bin/compress`; LHA's expected output
> is independently confirmed by `lhasa` (`lha v`/`t`/`x`), a decoder sharing
> no code with the `delharc` crate this container wraps; **ARJ's fixture is
> hand-built from stuffr's own reading of the (unofficial) ARJ specification
> and of `unarj-rs`'s own parser, with no independent tool anywhere on the
> build machine to check it against.** A review during this phase caught one
> real deviation from the published spec (the main header's `file_type`
> field) that no test in this repository could have caught unassisted,
> precisely because the fixture and the parser under test were derived from
> the same source. See `crates/stuffr-formats/fixtures/legacy/MANIFEST.md`
> for the full, per-fixture provenance. **Task 7 giving ARJ an encoder did
> not close that gap and could not**: the encoder is a second transcription
> of the same tables by the same project, so a round trip through it is
> stuffr agreeing with stuffr. None of the five fixtures was regenerated
> with the encoder its format has since gained, for exactly that reason.
>
> Unix `compress` (`.Z`) is the plainest of the three, and the one with the
> most interesting implementation history: the crate first chosen for it
> turned out to decode its *entire* input on the first `Read::read` call
> regardless of buffer size, which defeats `--max-ratio`'s incremental
> accounting outright — so `compress_z.rs` now carries a from-scratch
> incremental LZW decoder, and the original crate (`newtua-lzw-z`) is kept
> only as a dev-dependency cross-validation oracle. Unix `compress` also
> carries no checksum and no end-of-stream marker at all, so truncation is
> undetectable **by construction** — measured true of the real `compress`
> and `gzip -dc` too, not just this decoder. stuffr's guarantee is narrower
> here than everywhere else as a result: a truncated `.Z` must still decode
> to a genuine prefix of the full output, never to fabricated bytes, but an
> outright error is not owed.
>
> `delharc` is pinned exactly at `=0.6.2`: its `0.8` line needs rustc 1.95,
> six minors past this project's 1.88 MSRV. Revisit the pin when MSRV moves,
> not on a schedule.
>
> **Phase 3c adds two more read-only legacy formats, ARC/PAK and ZOO — the
> first containers in this workspace that wrap no crate at all.** The one
> reference implementation in reach (`unarc-rs` 0.6.3) is disqualified as a
> dependency for three measured reasons — an unconditional MSRV of rustc
> 1.95, vendored C++ via `unrar`, and a second zip/tar stack duplicating what
> `stuffr-formats` already carries — so its MIT/Apache test corpus is
> borrowed as **bytes only** and every decoder is written from scratch here.
> `.arc` and `.pak` both read through it; like LHA and unlike ARJ it parses
> forward off a pipe, because every entry's size sits in its own header.
>
> Five of ARC's compression methods are decoded — Stored (1 and 2),
> RLE90 (3), Squeezed (4), Crunched (8) and PAK's Squashed (9), the last of
> which fell out of the Crunched LZW engine for free. Crushed (10),
> Distilled (11) and the pre-8 Crunched variants (5, 6, 7) are
> `Error::Unsupported` at **exit 3**, naming the method: no archive using
> them exists in the borrowed corpus, so a decoder for them could not be
> proven against anything, and claiming otherwise would turn a capability
> gap into a false "your archive is damaged".
>
> **This is the phase where the CRC witness starts doing real work.** Every
> ARC entry carries a CRC-16 the original archiving tool wrote decades ago,
> and the fixture-driven conformance harness checks stuffr's decode against
> that value — a witness owned neither by this project nor by the crate whose
> corpus was borrowed, which is exactly what the hand-built ARJ fixture could
> never be. `wrongcrc16.arc` is the negative twin: it declares the correct
> content's CRC over a payload that computes a different one, and stuffr
> refuses it at exit 5 rather than handing back wrong bytes.
>
> **ZOO is the same shape with one advantage ARC did not have: the original
> implementation could be read.** zoo 2.10's own C source settles every
> structural constant, and it contradicts `unarc-rs` on the most important
> one — the fixed directory-entry record is **56 bytes** (`zoo.h`'s
> `SIZ_DIRL`), not 59, which is why all four borrowed fixtures were thought
> to end in a *short* terminal marker and do not. Three packing methods
> decode: Stored, zoo's own 13-bit LZW written from scratch, and LH5 through
> the `delharc` this build already carries for LHA.
>
> ZOO's directory is a linked list of absolute file offsets rather than a
> run of headers, so unlike LHA and ARC it needs `Seek` — a piped `.zoo`
> spools to a temp file first, the rung ARJ and an indexed zip already take.
> A chain that does not advance is refused at exit 5, which is zoo's own
> verdict on the same shape, so a cyclic archive terminates rather than
> spinning.
>
> **Phase 3c Task 5 gave Unix `compress` a real encoder — the first of the
> phase's three write tasks (`compress`/`lha`/`arj`) to land.** `pack
> --format compress` now writes a `.Z` file the real `compress`(1)/
> `uncompress`(1) tools read back byte-exactly; `lha` writes as of Task 6
> and `arj` as of Task 7 (both below). `--level` maps onto `compress`'s own
> `-b` flag (`maxbits`, `9..=16`, not the 0-9 shape every other codec here
> uses), defaulting to 16. The encoder is a from-scratch, block-mode LZW
> implementation promoted out of the test suite that proved it byte-for-byte
> against the real tool before it was ever wired to a `Sink` — it never
> emits a block-mode CLEAR (the real encoder's ratio heuristic for that is
> itself not portable between BSD and GNU `compress`, see the paragraph
> above), and its dictionary simply freezes once full, which every reference
> decoder accepts. One level is deliberately not the default despite being
> real: GNU `ncompress` 5.0 cannot decode its own `-b 9` output once the
> 512-entry dictionary fills, so this build writes the BSD-shaped bytes at
> that level instead — correct, and decodable by every reference tool this
> project tested, but the format's own reference *encoder* disagreeing with
> its own reference *decoder* is why `-b 9` is opt-in rather than default.
>
> **Phase 3c Task 6 gave LHA/LZH a `-lh5-` encoder**, so `pack --format lha`
> now writes a real `.lzh` that `lhasa` reads back, CRCs and all — verified
> against that tool directly, which is the only witness that matters here
> (`delharc` reads and `oxiarc-lzhuf` writes, so any test using only those
> two proves they agree with each other, not that the file is LHA).
> **It reads seven compression methods and writes one**, and that asymmetry
> is deliberate rather than an oversight: the reader accepts `-lh0-` through
> `-lh7-` (plus the older LArc `-lz*-` family), the writer emits `-lh5-`
> alone — 8 KB window, static Huffman, the method every LHA tool in
> existence supports. Re-packing an `-lh7-` archive therefore yields a valid
> `.lzh` whose entries are `-lh5-`: a larger file, no data loss.
> Directories are stored as `-lhd-` entries **with a trailing separator**,
> and that detail is load-bearing rather than cosmetic — measured against
> lhasa 0.6.0, an `-lhd-` entry whose name lacks one makes lhasa end the
> archive there, silently, at exit 0, losing every entry behind it.
> Symlinks are not stored: `pack` warns and skips one rather than writing
> something a reader would restore as an ordinary file.
>
> **Phase 3c Task 7 gave ARJ a store-only encoder**, so `pack --format arj`
> writes a real `.arj` — and it carries two warnings the WRITE column in
> `stuffr formats` cannot express. **It does not compress.** The reader
> accepts ARJ's five methods; the writer emits method 0 (`Stored`) alone,
> so an archive stuffr writes is larger than its input, and re-packing a
> compressed `.arj` loses the compression while losing no data and no
> names. Putting a codec under it (`-o backup.arj.gz`) composes normally.
> Writing a compressed method would have meant an ARJ-flavoured LZH encoder
> with no reference implementation to check it against, which is the second
> warning in a different form: **nothing outside this project has ever read
> an ARJ archive stuffr wrote.** `.Z` has `compress`(1) and `.lzh` has
> `lhasa`; no `arj`/`unarj` binary is obtainable, so the round trip is this
> encoder against this decoder — and that decoder was built against a
> fixture the same project hand-derived, where a review already caught two
> spec deviations that every test here accepted. What answers it is a
> byte-level test asserting the published specification's own constraints —
> the main header's `file type` must equal 2, `PATHSYM_FLAG` set exactly
> when a stored name uses `/`, the basic-header-size identity, the
> 2600-byte maximum — against the bytes the encoder emits, cited to the
> spec rather than to `unarj-rs`, which parses those fields and reads none
> of them. Real, and not a second implementation. **If you have `arj` or
> `unarj` anywhere, a report either way is worth more than anything in this
> repository.** Directories are stored as themselves; a symlink is refused
> at exit 3, because ARJ's own entry-type table has no value for a link.
>
> **Task 6 also changed how LHA entry NAMES are reported, and it can break a
> working pipeline — read this before upgrading if you script `.lzh`.**
> `delharc`, the crate behind the reader, strips `..`, `.` and empty
> components from every name it hands back. stuffr now reports the name the
> archive actually stores. Three consequences:
>
> * A traversal or absolute entry that previously **extracted silently at
>   exit 0** — `../../etc/passwd` landed at `<dest>/etc/passwd` and `stuffr
>   unpack` reported `(exact fidelity)` — is now **refused at exit 7** with
>   nothing written. That is the fix, and it is why the change was made.
> * A non-printable byte is escaped `%XX` with **upper-case** hex where
>   `delharc` used lower (`%c3` → `%C3`), and a literal `%` in a stored name
>   is now escaped too (`%1f` → `%251f`, so a stored literal is no longer
>   indistinguishable from an escaped byte). Entry names are matched
>   **exactly**, so `stuffr cat old.lzh 'na%c3me.txt'` and any `--pattern`
>   written against the old spelling now answer `EntryNotFound` at exit 2.
>   Run `stuffr list` and copy the name from there.
> * `\` is still split as a path separator, exactly as before — a DOS-era
>   `dos\sub\file.txt` still reports as `dos/sub/file.txt`.
>
> Separately, and found while testing this: a **file** entry named `.`
> resolves to the destination directory itself, and `unpack` used to
> `File::create` over it — `i/o error: Is a directory`, **exit 1**, which is
> the code reserved for stuffr failing. It is now refused at exit 7 for every
> container (the hole was in the shared extraction loop, and a raw `tar` with
> such an entry reached it too). A **directory** entry named `.` — what `tar
> cf x.tar .` emits — is unaffected.
>
> **Not yet: `7z`, squashfs, ISO 9660, MS CAB and RAR.** Those five
> containers are deferred past Phase 2, each needing its own cycle — see
> [OUT-OF-SCOPE.md](OUT-OF-SCOPE.md).
>
> Already true and enforced for every codec: decoding is incremental rather
> than read-to-end, corruption is distinguishable from a full disk, truncation
> and concatenated streams are detected rather than silently truncating, output
> is fsynced before it is published and never destroys an existing file on
> failure, and `stuffr-core` carries zero format dependencies.

## Installation

The binary is `stuffr`; the package that builds it is **`stuffr-cli`**:

```sh
cargo install stuffr-cli        # installs the `stuffr` binary
```

**`cargo install stuffr` does not work** — it fails with "no binaries".
`stuffr` is the *library* crate and has no binary target; the command lives in
`stuffr-cli`. This is the same split as ripgrep's `ripgrep` package and `rg`
command, and it is the one thing about this project most likely to waste
somebody's first five minutes.

The default build is pure Rust and needs no C toolchain. To link the two
vendored, statically built C backends instead — a faster xz/LZMA1 encoder and a
strong zstd encoder:

```sh
cargo install --locked stuffr-cli --features c-backed    # needs a C compiler, nothing else
```

`--locked` keeps the vendored C libraries at the versions the compatibility
links promise (libzstd 1.5.7, liblz4 1.10.0); without it, cargo may resolve
newer `-sys` crates.

The five legacy formats (Unix `compress` `.Z`, LHA/LZH and ARJ — all three
read AND write, as of Phase 3c Tasks 5, 6 and 7 — plus the read-only ARC/PAK and ZOO) are in the default
build too, pure Rust like the rest of it — no extra flag needed.
`--features legacy` still exists and still works; it only matters paired with
`--no-default-features` (e.g. `--no-default-features --features pure`, the
build the `purity` CI job checks, is the one combination that excludes them).

Using it as a library instead:

```sh
cargo add stuffr                # the facade; re-exports stuffr-core + stuffr-formats
```

| Crate | What it is |
|---|---|
| [`stuffr-cli`](https://crates.io/crates/stuffr-cli) | the `stuffr` command — **this is the `cargo install` target** |
| [`stuffr`](https://crates.io/crates/stuffr) | the library facade — the `cargo add` target |
| [`stuffr-formats`](https://crates.io/crates/stuffr-formats) | codec and container implementations |
| [`stuffr-core`](https://crates.io/crates/stuffr-core) | traits, stream ladder, fidelity, governor, registry — zero format dependencies |

### Decoding a borrowed reader

`Source` and `SeekRead` no longer require `Send`, and `Codec::decoder` takes a
`Box<dyn Source + 'a>`, so a codec decodes a reader that borrows something: an
archive member's reader (a `.Z` inside a tar or a zip), a `&mut &[u8]`, a
`&mut File`. `stuffr::decode_reader(codec, reader, &DecodeOpts::default())` is the
one-call route (`stuffr::BorrowedSource` is the source under it); it needs no
registry and refuses a codec that cannot decode with exit 3. A caller that does
need `Send` asks for `Box<dyn Source + Send>` itself. The `stuffr` crate docs
carry a compiled example.

## Compatibility links

Invoked as `bzip2`, `bunzip2`, `bzcat` or `bzip2recover`, the `stuffr` binary
behaves as **bzip2 1.0.8**; invoked as `gzip`, `gunzip`, `zcat` or `gzcat`
(from `0.12.0`), as **gzip**; invoked as `xz`, `unxz`, `xzcat`, `lzma`,
`unlzma` or `lzcat` (from `0.13.0`), as **xz** (XZ Utils 5.8.4); invoked as
`zstd`, `unzstd`, `zstdcat` or `zstdmt` (from `0.14.0`), as **zstd** (zstd
1.5.7); invoked as `lz4`, `unlz4`, `lz4cat` or `lz4c` (from `0.15.0`), as
**lz4** (lz4 1.10.0); invoked as `unzip`, `zipinfo` or `funzip` (from
`0.16.0`), as **Info-ZIP UnZip 6.00**; invoked as `compress` or `uncompress`
(from `0.18.0`), as **compress**, Apple's 487.0.1 or ncompress 5.0; invoked as
`zip`, `zipcloak`, `zipnote` or `zipsplit` (from `0.19.0`), as **Info-ZIP Zip
3.0**; invoked as `brotli`, `unbrotli` or `brcat` (from `0.20.0`), as
**brotli** 1.2.1. In every
case that tool's flags, files, exit codes and messages, not stuffr's. The binary reads the name from
`argv[0]`, the file name only, before parsing anything. Any other name,
`stuffr` included, runs the stuffr CLI unchanged. So does a link you make by
hand under a name stuffr does not handle: `zcat2 -> stuffr` runs `stuffr`.

### Opting in

**Links are never created automatically**, not by `cargo install` and not by
Homebrew. One verb makes them:

```sh
stuffr install-links --dir ~/.local/bin                  # all thirty-four names
stuffr install-links --dir ~/.local/bin --names bzcat,zcat   # comma-separated subset
stuffr install-links --dir ~/.local/bin --dry-run        # "would create ...", changes nothing
stuffr install-links --dir ~/.local/bin --force          # replace what is already there
stuffr install-links --dir ~/.local/bin --remove         # remove stuffr's links, nothing else
```

- **Each link points at this stuffr.** Under Homebrew the target is the
  stable `<prefix>/opt/stuffr/bin/stuffr`, not the versioned
  `Cellar/stuffr/<ver>/` path that `brew upgrade` deletes, so the links
  survive an upgrade. A link left dangling into a stuffr that was deleted
  (one made by an older install) still counts as stuffr's: a re-run replaces
  it without `--force`, and `--remove` removes it.
- **A second run** reports `already present` and changes nothing.
- **Anything else at a link's name** (a regular file, or a link to another
  tool) is refused at exit 2, naming the path, and left untouched; `--force`
  replaces it. A directory is never replaced. Every name is checked before
  anything is changed, so a refusal leaves DIR as it was.
- **`--remove` touches only stuffr's links**: a link whose text is the
  target, one that resolves to this stuffr, or a dangling one into a file
  named `stuffr`. Every other entry of the same name stays, with a
  `left PATH: not a stuffr link` (or `not a link`) line.
- **Errors:** a missing DIR is exit 2; one that cannot be written to is
  exit 1, naming the link and the operating system's reason. On Windows the
  verb is refused at exit 3.

### The promise

- **Flags, files, exit codes and stderr are those of bzip2 1.0.8,
  byte for byte.** That covers every documented flag, short and long, in
  clusters (`-dkv`), with `--`, and the `BZIP2` then `BZIP` environment
  words. Output names, kept or removed inputs, copied mtime and permissions
  all match. The exit codes are bzip2's, not stuffr's 0–7: 0 success,
  1 environment problem, 2 corrupt input, 3 internal error; `bzip2recover`
  exits 0 or 1. Every message matches, including the `-v` statistics line
  and `--help`. Where `bzip2.c` surprises, stuffr follows it: `-V` and `-L`
  print and carry on, a terminal is refused even under `-f`, and `-s` caps
  the compression block size at 200k.
- **Compressed output is byte-identical** to bzip2 1.0.8 at every level, on
  both build tiers. The default level is 9, not stuffr's own 6.
  `bzip2recover`'s `rec*` files are byte-identical too.
- **The one intended difference:** `--version`, `-V`, `--license` and `-L`
  name stuffr and its version on the first line. The rest of that text is
  verbatim.

A differential suite runs each case through the system's bzip2 and through
a stuffr link, and compares exit code, stdout, stderr, files, bytes, modes
and mtimes.

### Known deviations

- **`-vv` behaves as `-v`.** libbzip2's internal trace (block CRCs, sorting
  statistics) is not reachable through stuffr's codec API.
- **With `-f` reading a FIFO or terminal, an interrupt waits for the read.**
  In file-to-file mode SIGINT, SIGTERM and SIGHUP are answered as bzip2
  answers them (its message, partial output deleted, exit 1), but stuffr's
  handlers only set a flag that the read loops poll, so a blocked read
  delays the answer until it returns.
- **When the parent ignores `SIGPIPE`**, bzip2 reports a Broken pipe I/O
  error and exits 1; stuffr dies of `SIGPIPE`. The Rust runtime ignores the
  signal before `main`, so the inherited setting cannot be read. Under the
  default setting both die of `SIGPIPE`.
- **The `perror` line after a cut-short stream** reproduces the `errno`
  bzip2 leaves behind on macOS. Elsewhere stuffr prints `strerror(0)`.
- **bzip2recover at exactly 50000 blocks.** At 50000 magics with at least 40
  bits after the last, bzip2recover 1.0.8 writes past its arrays and, on
  macOS, silently drops block 1. stuffr writes it. Upstream's undefined
  behaviour is never reproduced.
- **bzip2recover and existing files (hardening).** Upstream 1.0.8 writes
  its `rec*` files through a symlink already at that name (dangling or not)
  and truncates a file already there, mode 0666 less the umask. stuffr
  opens them as Debian's patched build does (`O_EXCL`, mode 0600): an
  existing name is refused with "can't write", exit 1, and left untouched,
  so a planted symlink cannot redirect the write, and recovered blocks of
  a private file stay private.

### The gzip family

`gzip`, `gunzip`, `zcat` and `gzcat`. Unlike bzip2, gzip has two common
implementations that differ in flags, messages and exit codes, so stuffr
carries both and picks one:

- **GNU gzip** (written against 1.15) on Linux, Windows and everywhere that
  is not listed next. `gunzip` and `zcat` behave as GNU's scripts do
  (`gzip -d`, `gzip -dc`, every message saying `gzip:`); `gzcat`, which GNU
  does not install, behaves as `zcat`.
- **Apple/BSD gzip** (Apple's 487.0.1, a port of FreeBSD's and NetBSD's) on
  macOS and the BSDs.
- **`STUFFR_GZIP_FLAVOR=gnu|bsd`** overrides the choice, whatever the
  platform; unset or empty means the platform's own. Any other value is
  refused, exit 1, naming the variable. Neither reference tool has the
  variable, so that message is stuffr's own.

**The promise, per personality:**

- **Stdout, stderr and exit codes are byte-identical to the reference tool**,
  in both personalities: every documented flag, the `GZIP` environment
  word (GNU), the suffix rules, which failures end the whole run and which
  do not, the `-l` and `-v` output, and what each tool does with `.Z`, pack
  and (Apple) bzip2, xz and lzip input. A differential suite runs each case
  through the real tool and a stuffr link and compares those streams, the
  file tree, modes and mtimes.
- **Compressed output.** The Apple personality's output is **byte-identical
  to `/usr/bin/gzip`** on the `c-backed` tier (`--features c-backed`, which
  builds zlib; Apple's gzip uses zlib too). On the default pure tier, and for
  the GNU personality on every tier, the output is **compatible**: it decodes
  everywhere, and the header matches the reference through the stored name
  (FNAME). **GNU's compressed bytes are never identical**, because GNU gzip
  has its own deflate.

**Known differences:**

- **GNU `-V` and `-L` print stuffr's own notice,** not GNU's copyright and
  GPL text: stuffr is MIT and contains no GNU code. The first line names
  stuffr, the layout is GNU's, and the exit code and stream match. The Apple
  personality prints Apple's BSD notice, with only the first line naming
  stuffr.
- **GNU `-v` prints a different percentage,** because the compressed size
  differs; the rest of the line is GNU's.
- **GNU `--rsyncable` and `--synchronous` are accepted and change nothing.**
  The output is not chunked for rsync. (Apple's gzip has neither option.)
- **LZH (`compress -H`, magic `1f a0`) is not decoded** by the GNU
  personality: GNU reads it, stuffr says "not in gzip format" (a later member:
  trailing garbage). Apple's gzip has no LZH reader either.
- **GNU, an output name longer than the file system allows** (`NAME_MAX`,
  255 bytes on most): GNU 1.15 shortens it and goes on. Compressing a file
  whose name is 253 bytes or longer, it says "NAME compressed to SHORTER.gz"
  and exits 0; under `-dN`, a stored name past the limit is written cut
  short with "warning, name truncated", exit 2. stuffr does not shorten
  names: it says "File name too long", exits 1 and keeps the input.
- **A `.Z` whose header claims fewer than 9 bits** is "corrupt input." with
  no output; GNU writes about 22 bytes of garbage first.
- **An input that is also the output is never lost.** `gzip -dNf` on a file
  whose stored name is its own name (on a case-insensitive volume, such as
  macOS's default APFS, also in another case: `X.GZ` for `x.gz`), or a
  symbolic link whose compressed name leads back to itself, makes both
  tools unlink the input before
  decoding, so a failure loses it (GNU loses both files). stuffr prints and
  exits the same, keeps the input on failure and replaces it only with a
  finished output.
- **A mid-input read error keeps the input** and removes the partial output.
  Apple's gzip keeps the cut-short output and removes the input. Streams and
  exit code match.
- **A closed standard input or output** (`gzip <&-`): the Rust runtime
  reopens it on `/dev/null` before `main`, so stuffr compresses an empty input
  or writes nowhere and exits 0, where Apple's gzip says "Can't stat stdin"
  or "write: Bad file descriptor".
- **Pure-tier xz, Apple personality.** Apple's gzip reads `.xz`; off the C tier
  stuffr decodes it with its own decoder, which judges the stream header as
  liblzma does but can differ in how a failing stream reads ("Unexpected end
  of input" against "File is corrupt") and in what it outputs first.
- **Two edge cases of GNU's own state are not reproduced:** a zip refused
  with its data-descriptor flag set no longer makes the next input's gzip
  trailer fail its check, and undefined behaviour in either tool is never
  copied.
- **Apple's `SIGINFO` (^T) progress is not printed.** (An interrupted run
  removes its hidden `.stuffr-gzip-*.tmp` output as the references do: GNU's
  on INT, TERM, HUP, PIPE, XCPU and XFSZ, Apple's on INT only; a `SIGINT`
  ignored at start stays ignored.)
- **When the parent ignores `SIGPIPE`,** the references report a broken pipe
  (GNU 1.13 and later exit 2 with a warning); stuffr dies of `SIGPIPE`, for
  the same reason as the bzip2 family. Under the default setting both die of
  it.
- **The reference version matters.** GNU 1.12 and 1.15 differ in places
  (`-l` on several members, `-S` with a `/`, which `GZIP` words count,
  quoted names). stuffr follows 1.15; Linux CI's 1.12 cases are adjusted
  where the older tool differs.

### The xz family

`xz`, `unxz`, `xzcat`, `lzma`, `unlzma` and `lzcat`, from `0.13.0`. They
behave as **XZ Utils 5.8.4's `xz`**, and only that version: there is one
personality and one reference, no flavours. The mode comes from the name as
xz derives it: `unxz` decompresses, `xzcat` and `lzcat` decompress to
standard output, and the `lzma` names use the `.lzma` format. `XZ_DEFAULTS`
and `XZ_OPT` are read before the command line, as xz reads them.

**The promise:**

- **Stdout, stderr and exit codes are byte-identical to xz 5.8.4** (under
  `LC_ALL=C`), on both build tiers: every documented option, the
  `--list` and `-vv` tables, `--robot`, `--files` and `--files0`, `--filters`
  and the filter options, `--block-list`, the suffix rules, `--info-memory`
  and the memory-limit refusals. The exit codes are xz's, 0, 1 and 2 (2 is a
  warning); stuffr's 3 to 7 never appear under these names. A run killed by
  `SIGINT`, `SIGTERM` or `SIGHUP` removes its partial output and dies of the
  signal, as xz does. A differential suite runs each case through a real
  xz 5.8.4 and a stuffr link and compares those streams, the file tree,
  modes and mtimes.
- **Compressed output.** On the `c-backed` tier (`--features c-backed`,
  which builds liblzma 5.8.4) the bytes are **identical to xz 5.8.4** for
  every preset, `-e`, `--check`, `-T`, `--block-size`, `--block-list`,
  `--format` and filter chain, including xz's default multi-threaded mode.
  On the default pure tier every option is accepted and the output is
  **compatible**: xz 5.8.4 decodes it to the input, and the container fields
  stuffr controls (the check type, the stream flags, `--format`) match.
- **The intended differences:** `--version`'s first line reads `xz (stuffr
  X.Y.Z; XZ Utils 5.8.4 compatible)` and the rest is xz's;
  `--robot --version` is xz's own and reports 5.8.4 on both tiers, because
  scripts parse it; and the `-v` progress line's speed and elapsed fields
  vary from run to run, as they do between two runs of xz.

**Known differences:**

- **Pure tier, a damaged stream can read differently.** Corruption in the
  last few bytes of a raw, `.lzma` or `.lz` stream may be reported as a
  truncated stream ("Unexpected end of input") where xz says "Compressed
  data is corrupt". The exit code is the same. Output written before a
  decode error may be a strict prefix of what xz writes (a raw, `.lzma` or
  `.lz` stream cut short, or corruption in the middle of a `.xz` Block);
  stderr, the exit code and the file tree match, and `-v`'s figures at that
  point follow it.
- **Pure tier, memory.** A stream that declares a dictionary larger than its
  data needs commits that memory, where xz only reserves it; bound it with
  `-M`. Where the size is declared (`.lzma` with a known size, a `.xz`
  Block's uncompressed size) the window is capped at that size.
- **Pure tier, `-v` sizes.** The compressed size and ratio `-v` reports are
  those of stuffr's own output, which is compatible with xz's, not equal.
- **Pure tier, two refusals and a layout.** A `.lzma` stream that declares
  its size *and* ends with an end marker is refused (liblzma accepts it; no
  xz encoder writes one). With threads and a `--block-size` smaller than the
  dictionary (a lone LZMA2 filter, no `--block-list`), the Block
  boundaries differ from xz's.
- **The memory figures** xz prints (`-vv`, `--list`, the memory-limit
  messages) come from liblzma's formulas modelled on a configure-built
  xz 5.8.4 for the host, on both tiers.
- **No sandbox.** xz may confine itself (Landlock on Linux, Capsicum on
  FreeBSD, `pledge` on OpenBSD; nothing on macOS); stuffr does not. Nothing
  that confinement changes is observable.
- **An input that is also the output is never lost,** as with the other
  families: output is written beside the target and put in place when
  complete, so a failure keeps the input even where xz would lose it.
- **Some corruption is found before the output is opened (pure tier
  only).** On the C tier the header probe is xz's own call (`lzma_code`
  with no output room), so the output is opened, refused or kept exactly as
  xz does. On the pure tier the first chunk is fed a byte at a time until
  the first byte of output, so corruption in the first LZMA chunk's
  properties byte or its range-coder start (`.xz`), or in the range-coder
  start (`.lzma`), is said before the output is opened, where xz finds it
  after opening it. Without `-f` the corruption is reported where xz
  reports that the output exists. With `-f` an existing output survives
  where xz removes it.
- **A closed standard input or output** (`xz <&-`, `xz -c a >&-`): xz says
  "(stdin): Read error: Bad file descriptor" or "(stdout): Write error: Bad
  file descriptor" and exits 1. The Rust runtime reopens a closed standard
  descriptor on `/dev/null` before `main`, so stuffr reads an empty input
  (compressing it and exiting 0, or, decompressing, saying "File format
  not recognized"), or writes nowhere and exits 0.
- **The progress timer is polled,** not set with `alarm(2)`. The lines and
  when they appear are xz's, and `SIGALRM`, `SIGINFO` (where the system
  has it) and `SIGUSR1` each still ask for a line; no visible difference
  is expected.
- **When the parent ignores `SIGPIPE`,** xz says nothing and exits 0 on a
  closed pipe; stuffr dies of `SIGPIPE`, for the same reason as the other
  families. Under the default setting both die of it.

### The zstd family

`zstd`, `unzstd`, `zstdcat` and `zstdmt`, from `0.14.0`. They behave as
**zstd 1.5.7's command line tool**, and only that version: one personality,
one reference. The preset comes from the name as zstd derives it: `unzstd`
decompresses, `zstdcat` decompresses to standard output (passing unrecognised
input through, at display level 1) and `zstdmt` compresses with `-T0`.
`ZSTD_CLEVEL` and `ZSTD_NBTHREADS` are read as zstd reads them.

**The promise:**

- **Stdout, stderr and exit codes are byte-identical to zstd 1.5.7** (under
  `LC_ALL=C`), on both build tiers: every documented option, `--list`,
  `-v`/`-vv`/`-vvv` and the parameter printers, dictionaries (`-D`,
  `--patch-from`), `--train`, `--filelist`, `-r`, the suffix rules and the
  overwrite prompt. The exit codes are zstd's (0, 1, 2 for an interrupt, and
  the `EXM_THROW` set zstd uses); stuffr's own meanings for 3 to 7 never
  apply under these names, and 3, 4 and 5 occur only as zstd's `--train` save
  errors. A differential suite runs each case through a real zstd 1.5.7 and a
  stuffr link and compares those streams, the file tree, modes and mtimes.
- **Compressed output.** On the `c-backed` tier (`--features c-backed`, which
  builds libzstd 1.5.7) zstd frames and dictionaries are **byte-identical to
  zstd 1.5.7** for every level, `--ultra`, `--long`, `-T`, `--rsyncable`,
  `--format=gzip|xz|lzma|lz4` (liblz4 1.10.0 through `lz4-c`, in
  `c-backed`), dictionaries and `--patch-from`. The exceptions:
  `--train-cover` (see below) and `--adapt` (its level moves by timing, so its
  frames are compatible, not identical). On the default pure tier every option is
  accepted and the output is **compatible**: zstd 1.5.7 decodes it to the
  input. The pure tier's refusals of dictionary compression and `--train` are
  listed below.
- **The intended differences:** the banner. `-V`, `-vV`, `-vvV`, the first
  line of `-H` and `-v`'s welcome line name stuffr: `*** Zstandard CLI
  (stuffr X.Y.Z; zstd 1.5.7 compatible) (64-bit) v1.5.7, by Yann Collet ***`.
  `-qV` prints exactly `1.5.7`.

**Known differences, both tiers:**

- **`-vvV`'s library lines.** It prints zstd's POSIX lines for the platform,
  but not the three library-version lines (zlib, lz4, lzma) that describe
  zstd's own build. `-vV`'s "supports:" line is zstd's.
- **Timing fields vary** in the `-v` summary, as they do between two runs of
  zstd.
- **An input that is also the output is never lost,** as with the other
  families.
- **Closed standard streams, and a parent that ignores `SIGPIPE`.** The Rust
  runtime reopens a closed standard descriptor on `/dev/null` and resets
  `SIGPIPE` before `main`, so neither is seen.
- **Benchmark and trace are out of scope.** `-b`, `-e#`, `-i#` and `--trace`
  are refused as a zstd built with `ZSTD_NOBENCH` and `ZSTD_NOTRACE` refuses
  them ("Incorrect parameter: -b", exit 1), and `-H` omits their lines (so a
  Homebrew zstd's `-H` differs by exactly those lines). `-B#`, `-S` and `-p#`
  keep the reference's meaning. `--[no-]asyncio` is accepted and has no
  visible effect; `--trace-file-stat` is accepted and prints no trace.
- **`-l` on two malformed skippable frames.** A size field of `0xFFFFFFF8`
  makes zstd loop forever, and stuffr answers exit 1 with `could not find end
  of skippable frame`; a skippable frame cut after 5 to 7 bytes makes zstd
  read uninitialised stack, and stuffr reads a deterministic header. Neither
  upstream defect is reproduced.
- **No `Error defined at` line.** At display level 5 and above, zstd's
  `Error defined at <file>, line <n>` line is not printed: it names the C
  implementation's source lines.
- **`--train-cover` is valid, not identical.** libzstd 1.5.7's cover sort
  breaks ties by comparing addresses, so a cover dictionary depends on heap
  layout, in zstd itself too. It is promised valid and usable by zstd, not
  byte for byte. `--train`, `--train-fastcover` and `--train-legacy` write
  zstd's bytes.
- **A symlink at an output name is never written through** (hardening).
  zstd checks for an existing output with `stat`, so a dangling symlink
  looks absent and the write creates the file it names, and `--train`
  writes its dictionary through whatever is at the name. stuffr treats any
  symlink there as an existing file (`already exists; not overwritten`, or
  the question); `-f` (or `y`) replaces the link with a fresh file and
  leaves its target alone. Outputs written in place are opened
  `O_NOFOLLOW` and their times set without following a link. `--train`
  still overwrites a regular file without `-f`, as zstd does, but refuses
  a symlink there (`cannot open`, exit 3) unless `-f`.

**Known differences, pure tier only** (`zstd-pure` without `zstd-c`):

- **`--format=lz4` is compatible, not identical** (the C tier, `lz4-c`, is
  liblz4's bytes): the pure tier's frame writer follows the frame format
  with `lz4_flex`'s block compressor at every level, in liblz4's frame
  descriptor (64 KiB linked blocks, content size, content checksum, as zstd
  sets them); lz4 reads it back to the input.

- **Compression is `ruzstd`'s `Fastest` at every level,** so the sizes and
  ratios in the summaries and in `-vvvvvv`'s trace are the tier's own. The
  compression parameters are range-checked as libzstd checks them, then
  ignored: `-T`, `--auto-threads` and `zstdmt` run single-threaded, and the
  LDM, `--rsyncable`, block-size and overlap options have no effect.
- **Content size and window.** Our frames never record a content size, so
  `--content-size` has no effect and `-l` on our own output says the
  decompressed size is unknown. The window is 128 KiB whatever `--long` asks.
- **Each input is compressed as one frame built in memory:** memory use grows
  with the input's size (a piped standard input is unbounded), and a run that
  exhausts memory ends outside zstd's exit codes.
- **Dictionary compression is refused.** Compressing with `-D` or
  `--patch-from` ends, after everything zstd prints first, with `zstd: error
  1 : dictionary compression is not available in this build (stuffr pure
  tier)`. Decompressing with either works.
- **`--train*` answers as a zstd built with `ZSTD_NODICT`.** `--train` prints
  `training mode not available`, exit 1; `--train-cover`,
  `--train-fastcover` and `--train-legacy` are no options there ("Incorrect
  parameter"). `-H` still lists the dictionary builder.
- **`--adapt` is accepted and the level never moves.**
- **A legacy frame** (v0.5 to v0.7) is `unsupported format`, as a zstd built
  without legacy support says.
- **A corrupt frame whose blocks overflow** the output libzstd sized from its
  header can be named `Data corruption detected` where libzstd says
  `Destination buffer is too small`.
- **`--format=gzip|xz|lzma` write compatible bytes,** from flate2's and the
  pure xz encoders, which the reference decodes; the summaries' sizes are the
  tier's own (with `zlib-c` gzip is zlib's bytes, with `xz-c` xz's).
- **A gzip member's deflate data goes through flate2** (miniz_oxide), which
  accepts some streams zlib refuses (a distance reaching before the output, a
  code with no end of block): where the reference says `inflate error -3` and
  writes nothing, the pure tier may write bytes and then fail (`premature gz
  end`), or, when the trailer's CRC and size match what miniz_oxide decoded,
  succeed with exit 0 and that output. With `zlib-c` it is zlib's own
  `inflate`.
- **An xz or lzma frame that fails to decode** may leave a strict prefix of
  what liblzma writes, and corruption in the last bytes of a `.lzma` reads as
  the input ending there (`premature lzma end`, the jobs before it written)
  where liblzma says `lzma_code decoding error 9`.

**Interrupts and the sandbox.** With a file destination SIGINT is answered as
zstd answers it: the partial output is removed, a newline is written to
standard error, and the process exits 2. With standard output as the
destination nothing is armed and SIGINT keeps its default action, as in zstd.
The fuzz target's sandboxed entry point caps the decoder's window log at 24,
`--train*` samples at 256 KiB (4 optimiser steps) and workers at 2; those
bounds never apply to a real run.

### The lz4 family

`lz4`, `unlz4`, `lz4cat` and `lz4c`, from `0.15.0`. They behave as the
**lz4 command line tool, version 1.10.0**, and only that version: one
personality, one reference. The preset comes from the invoked name as lz4
derives it, probed on the binary: the name itself or the name followed by `.`
and anything (`unlz4.exe`), case-sensitively; `unlz4-1`, `xunlz4` and `UNLZ4`
are plain `lz4`. `unlz4` decompresses, `lz4cat` is `-dcfm` at display level 1
and `lz4c` reads the legacy arguments (`-c0`, `-c1`, `-c2`, `-hc`, `-y`) and
lists them in its help. `LZ4_CLEVEL` and `LZ4_NBWORKERS` are read as lz4 reads
them. `-h` and `-H` print the reference's text verbatim, benchmark lines
included.

**The promise:**

- **Stdout, stderr and exit codes are those of lz4 1.10.0** (under
  `LC_ALL=C`), on both build tiers: every documented option, `--list` (compact
  and `-v`), `-v`/`-vv`/`-vvv`, `-m`, `-r`, `--rm`, `-D` dictionaries,
  legacy frames (`-l`), concatenated and skippable frames, sparse output, the
  overwrite question and the display level rules. The exit codes are lz4's:
  0, 1 (usage and file errors) and `Error N` exiting N; stuffr's own 3 to 7
  never apply under these names. A differential suite runs each case through
  a real lz4 1.10.0 and a stuffr link and compares those streams, the file
  tree, modes and mtimes.
- **Compressed output.** With `--features lz4-c` (also in `c-backed`), which
  builds liblz4 1.10.0, `.lz4` bytes are **byte-identical to lz4 1.10.0** for
  every option. On the default pure tier (`lz4_flex`) every option is accepted
  and the output is **compatible**: lz4 1.10.0 decodes it to the input.
- **The intended difference:** the banner. `-V`, the first lines of `-h`/`-H`
  and `-v` print `*** lz4 v1.10.0 64-bit multithread (stuffr X.Y.Z), by Yann
  Collet ***`; the prefix `*** lz4 v1.10.0 ` is unchanged.

**Known differences, both tiers:**

- **Timing and host fields vary,** as between two runs of lz4: the `Done in`
  line's seconds, speed and cpu load, the progress refreshes, and the `Using
  N threads` count where two programs count the host's cores differently.
  Refreshes are drawn at most every 200 ms. While compressing, a refresh that
  both draw shows the same figures (each job's refresh is over the input read
  before that job, `inf` for the first, and a one-shot frame's over all of
  it; the pure tier's ratio is of its own bytes). While decoding, stuffr
  offers one refresh per MiB decoded, while lz4's count and figures vary from
  run to run with its writer thread (probed: the same legacy file drew `14,
  14` or `8, 14` MiB, a `-B4` frame `4, 7, 8`), so those are timing too.
- **An input that is also the output is never lost.** Where the output named
  is the input file itself (same device and inode: `lz4 -f a a`, `lz4 -df
  s.lz4 s.lz4`, a hard link, standard input redirected from it), lz4 truncates
  it before reading it and the data is gone. stuffr opens nothing, prints
  `NAME is the input file; not overwritten (stuffr)`, counts that input as
  failed (exit 1, or one more in `-m`'s count), whatever `-f` says.
- **Closed standard streams, and a parent that ignores `SIGPIPE`,** as in the
  other families. A closed pipe kills stuffr by SIGPIPE, as it kills lz4
  under the default disposition; where the parent ignores SIGPIPE lz4 answers
  `Error 70` (decoding) or `Error 38` (compressing) and stuffr still dies of
  the signal. A closed standard input or output is reopened on `/dev/null`
  by the Rust runtime, so `lz4 -c <&-` (lz4: `Error 40`) compresses an empty
  input.
- **Benchmark mode is out of scope.** `-b#` prints
  `Benchmark mode is not available in this build (stuffr)` and exits 1, once
  the whole command line has parsed (a usage error, `-h` or `-V` still
  answers first). `-e#` and `-i#`, the benchmark's own settings, are accepted
  and have no effect without it, as in lz4. `-h` and `-H` still list all
  three. The hidden `-S` is accepted and has no effect, as in lz4.
- **A decode that fails keeps everything decoded before the fault** in its
  output (a file or standard output). lz4 writes on another thread and exits
  from the failing one, so it leaves nothing or all of that, run to run.
- **`--list` of a file that ends inside a block-size word** completes the
  word from an uninitialised buffer in lz4; only the `-v` size of that last
  frame shows it. On macOS that is garbage once a frame or skippable frame
  came before (the same run to run, about 4.4 million) and zero before; on
  Linux it is garbage even in the first frame, different on every run.
  stuffr completes it from the frame's previous block-size word (zero for
  the first).
- **`--list` of a regular file that cannot be opened** (mode 000) aborts lz4
  on an assertion (exit 134); stuffr prints `NAME: Permission denied` and
  exits 1.
- **A symlink at an output name is never written through** (hardening).
  lz4 checks for an existing output with `stat` and opens it with
  `fopen`, so a dangling symlink looks absent, a live one is truncated, and
  the data lands where the link points. stuffr treats any symlink there as
  an existing file (`already exists`, or the overwrite question); `-f` (or
  `y`) replaces the link with a fresh file and leaves its target alone. An
  output that takes the input's mode is created 0600 and given the mode,
  owner and time through its descriptor at the end (a failed run's output
  gets lz4's 0666 less the umask then), so a private input is never
  readable through its output while it is written.

**Known differences, pure tier only** (without `lz4-c`):

- **Levels 3 to 12, `--best` and `--favor-decSpeed` compress with the one
  level `lz4_flex` has,** so the sizes and ratios in the summaries are the
  tier's own; the frame descriptor follows lz4's.
- **A corrupt frame's `Error N` text may differ,** and the output written
  before it may be a strict prefix of lz4's.

**Behaviour kept from lz4, on purpose.** `--rm` with standard input as the
input deletes a file named `stdin` (and fails with `Error 50` when there is
none), as lz4 does. `lz4 -t --rm f.lz4` deletes the source after a
successful test, as lz4 does, so it can delete a user's only copy. An
interrupt (SIGINT, SIGTERM, SIGHUP) leaves the partial output under its name and kills the process by the signal: lz4
installs no handler and writes the output file directly, and so does stuffr.
`lz4 -d` of a file without the `.lz4` suffix is `Cannot determine an output
filename`; with `lz4 -f` and standard output as the target an unrecognised
input is copied through, as lz4 does.

### The unzip family

`unzip`, `zipinfo` and `funzip`, from `0.16.0`. `unzip -Z` is `zipinfo`, as in
Info-ZIP: the `-Z` must be the first argument, and the rest is zipinfo's
command line. They behave as **Info-ZIP UnZip 6.00**, in two flavours, chosen
as the gzip family chooses its own: Apple's build on macOS and the BSDs (the
reference is `/usr/bin/unzip`, from Apple's `zip-33` tree), Ubuntu's build
everywhere else, Windows included (Ubuntu 24.04's `6.0-28ubuntu4.1`, Debian's
patch series and build options). `STUFFR_UNZIP_FLAVOR=apple` or `ubuntu`
overrides that; any other value is refused at exit 1 with
`unzip: STUFFR_UNZIP_FLAVOR must be apple or ubuntu, not 'VALUE'` (the invoked
name leads the line). `unzip` reads `UNZIP` and `UNZIPOPT`, and `zipinfo` reads `ZIPINFO` and
`ZIPINFOOPT`, before the command line, as the reference does.

**The promise:**

- **Stdout, stderr and exit codes are those of the flavour's reference**
  (under `LC_ALL=C`), for every option of `unzip`, `zipinfo` and `funzip`:
  the listings (`-l`, `-v`, `-z`, `-T`, zipinfo's formats and totals), testing,
  extraction with its overwrite questions and passwords, the usage screens,
  `-v`, and the exit codes Info-ZIP defines (0 to 3, 4 to 8, 9 to 11, 50, 51,
  80 to 82, and 12 under Ubuntu).
- **Extracted trees are identical wherever the reference's behaviour is
  defined** (deviation 10): names, modes, times, symlinks, and on macOS the
  archive's quarantine attribute. A differential suite runs each
  case through the real unzip and a stuffr link and compares those streams
  and the file tree, modes and mtimes.
- **The intended difference:** the first banner line (below).

**Known deviations:**

1. **SIGPIPE.** The family restores SIGPIPE's default action, as the other
   families do. Under a parent that ignores SIGPIPE, unzip sees `EPIPE` and
   stuffr still dies of the signal: the Rust runtime ignores it before
   `main`, so the inherited disposition cannot be told apart.
2. **The first banner line** of each program's usage and `-v` names stuffr
   and says it is altered (Info-ZIP licence, clause 3): `UnZip 6.00 of 20
   April 2009, by stuffr X.Y.Z (altered; original by Info-ZIP, with
   modifications by Apple Inc.).` (Ubuntu: `(altered; Debian's build,
   original by Info-ZIP).`), and likewise for zipinfo and funzip. That line is
   wider than the pager's 80 columns, so under `-M` it counts as two screen
   lines and `-Mh` pauses one text line earlier than the reference. `-v`'s
   `Compiled with` line is the recorded reference build's (Apple: this
   release's macOS build), so other macOS builds print a different one.
3. **Pre-existing symlinks.** The Ubuntu flavour also stays beneath the
   extraction root, as Apple's does. On unix only: off unix (Windows) the
   walk (`unix/beneath.rs`'s `imp_std`) follows symlinks, so neither flavour
   is contained there.
4. **The archive being read is never overwritten.**
5. **`-O` and `-I` (Ubuntu)** convert names through `iconv(3)`. They are
   unavailable on Windows, where they are parsed as Ubuntu parses them and
   convert nothing, as a conversion Ubuntu's `iconv_open()` refuses (silently:
   the names stay as stored).
6. **Locale-dependent output** is identical under `C`, `C.UTF-8` and
   `en_US.UTF-8` only.
7. **Quarantine on macOS.** The Ubuntu flavour also propagates the archive's
   quarantine attribute there, as Apple's does.
8. **The terminal.** After a prompt, a pager key or an interrupt, the
   terminal's mode is put back exactly as it was, where unzip only sets echo
   again (after an interrupt in the `-M` pager it leaves canonical mode off).
   A SIGABRT stuffr raises itself (a crash) kills it by the signal; one sent
   by another process exits 80, as unzip does for both. funzip installs no
   handler, so a signal at its password prompt kills it, echo off; stuffr puts
   the mode back first, then dies of the same signal.
9. **funzip never loses a write failure.** A failed write to standard output
   is answered `out of space on stdout`, exit 9, on a real host too. funzip
   writes through buffered stdio and does not check its final `fflush()`, so
   it loses the data and exits 0.
10. **Undefined behaviour and endless loops are not reproduced.** Where a
    reference's behaviour is undefined, or never ends, stuffr gives a defined
    answer instead. Ubuntu's bzip2 decoding loops for ever on a truncated
    entry; stuffr answers as for bad bzip2 data, exit 2 (T13-2). Apple's `-:`
    on a `../` directory entry changes the directory above the extraction
    root; stuffr refuses (T10-10). After a failed create Apple writes through
    the previous entry's closed stream; stuffr says "cannot create" and goes
    on (T10-11). At the end of input the C asks for a new name for ever at the
    rename prompt, and waits for ever at the `-M` pager's; stuffr takes
    `[N]one` and stops pausing (T10-9, T11-4). Buffer overflows are answered
    in both flavours with the forms of Ubuntu's CVE fixes: a method above 999
    is `Unk` and four hex digits (`Unk03E8`), and a password prompt whose
    names are too long is "Enter password: " (T11-5). The full set is in the
    code's `// ruling:` comments.

### The compress family

`compress` and `uncompress`, from `0.18.0`. Like gzip, compress has two common
implementations that differ in flags, messages and exit codes, so stuffr
carries both and picks one:

- **Apple compress** (a port of `file_cmds-487.0.1`'s `compress.c` and
  `zopen.c`) on macOS and the BSDs.
- **ncompress** (a port of ncompress 5.0, built as Ubuntu's `5.0-1` builds it)
  everywhere else, Windows included.
- **`STUFFR_COMPRESS_FLAVOR=apple|ncompress`** overrides the choice, whatever
  the platform; unset or empty means the platform's own. Any other value is
  refused, exit 1, as `NAME: STUFFR_COMPRESS_FLAVOR must be apple or
  ncompress, not 'VALUE'` (the invoked name leads the line). Neither
  reference has the variable.

`uncompress` decompresses, and so does `compress -d`; on Linux it behaves as
ncompress's own `uncompress` (Ubuntu installs that as `uncompress.real`), never
as gzip's script. `zcat` stays in the gzip family.

**The promise:** stdout, stderr and exit codes are the chosen reference's, and
so are the compressed bytes wherever the reference's output is a valid stream
(Apple at every `-b` from 1 to 16; ncompress from 10 to 16, and at 9 until its
table fills, N1), on both build tiers. Both personalities decode every valid
stream at maxbits 9 to 16. A differential suite runs each case through the
real tool and a stuffr link. An input is never lost, including when it is also
the output.

**Apple deviations:**

- **A1.** A stream whose header asks for fewer than 12 bits is decoded (any
  maxbits up to 16), Apple's own `-b 1` to `-b 11` output included; Apple's
  `uncompress` refuses all of them with `Inappropriate file type or format`,
  exit 1. Off macOS, where Apple's compress does not exist, that is still the
  text of a refused header.
- **A2.** When the output exists and is the input itself (a link to it), Apple
  opens the output for writing over its own input and the data is lost.
  stuffr writes the output under a temporary name and renames it over the link
  when complete, then removes the input as usual: the data survives, exit 0.
  INT, TERM and HUP remove the temporary (`.stuffr-compress-*.tmp`); QUIT
  leaves it behind, as Apple leaves its partial output on QUIT, and nothing
  is lost. After a `y` at the prompt without `-f`, a compressed output not smaller than
  its input is still "no saving", exit 2, and stuffr leaves both files as
  they were.
- **A3.** A header and nothing else (`1f 9d 90`, what ncompress writes for an
  empty input) is a valid stream of no bytes: stuffr writes the empty output,
  exit 0. Apple refuses it with whatever `errno` was left, exit 1.
- **A4.** A read error part-way through a `.Z` input: Apple takes it for the
  end of the stream, publishes the cut-short output and removes the input,
  exit 0, and the data is lost. stuffr warns (`uncompress: NAME: <strerror>`),
  exit 1, removes the output and keeps the input.
- **A5 (hardening).** A symlink at an output name is never written through.
  Apple checks for an existing output with `stat`, so a dangling symlink
  looks absent and the write creates the file it names, and a live one is
  truncated through. stuffr treats any symlink there as an existing file
  (`already exists`, or the question); `-f` (or `y`) replaces the link with
  a fresh file and leaves its target alone. A new output is created 0600
  and given the input's mode, owner, times and flags through its
  descriptor at the end (Apple sets them by name), so a private input is
  never readable through its output while it is written.
- **Smaller points.** The overwrite question's answer is judged by the C
  locale (`y` or `Y`); undefined behaviour (a table chain longer than 65536
  entries, an encoder writing past its buffer after a failed write) is not
  reproduced; a write that fails part-way is reported where stuffr's 64 KiB
  buffer meets it; off macOS file flags are not copied.

**ncompress deviations:**

- **N1.** At maxbits 9 (`-b 9`, and every value clamped to 9: 0, negative
  values, 1 to 8, non-numbers, the empty string) ncompress's encoder never
  widens its codes, so once the table fills its stream is undecodable, by its
  own `uncompress` too. stuffr writes the valid compress 4.0 stream there: one
  more 9-bit code, then 10-bit codes. A short input is unchanged; after the
  table fills, the ratio checks see the 10-bit sizes, so the CLEAR codes fall
  where ncompress's would not.
- **N2.** `uncompress` decompresses under that name on every platform.
  Ubuntu's binary does so only as `uncompress.real`; where its usage says
  `uncompress.real`, stuffr's says `uncompress`.
- **N4.** `uncompress -f` on a file refused at its header (not in compressed
  format, or more than 16 bits): ncompress prints the refusal and its exit
  code, then takes the empty output for a success and removes the input.
  stuffr prints and exits the same, removes its empty output and keeps the
  input. Under `-v` ncompress also prints `g.Z: g.Z: not in compressed
  format` and then ` -- replaced with g` on the next line, which is false;
  stuffr leaves that line out. An empty `.Z` with `-f` still becomes an empty
  output, as ncompress makes it.
- **Ubuntu's build everywhere.** On macOS this personality is still Ubuntu's
  build, not Homebrew's: symbolic-link operands are followed, `-V` lists
  `FAST, ` and `IBUFSIZ=8192, OBUFSIZ=8192`, and the corrupt-input debug line
  follows 8192-byte buffers.
- **Smaller points.** Undefined behaviour is not reproduced (a debug line's
  byte read before the buffer is `00`; an over-long table chain is `corrupt
  input`); the signal handler calls `_exit`, so a pending `-r` line is not
  flushed; the answer `perror` prints after a question that meets the end of
  the input is the platform's `strerror(0)`; off unix there is no mode, owner
  or time to copy.

**Both personalities:** a reference's behaviour that no correct decoder can
read back is replaced by a valid stream, and is listed above (N1). A closed
standard input or output reads or writes `/dev/null`, because the Rust runtime
reopens it before `main`. The full set is in the code's module docs
(`crates/stuffr-cli/src/compat/compress/`).

### The zip family

`zip`, `zipcloak`, `zipnote` and `zipsplit`, from `0.19.0`. They behave as
**Info-ZIP Zip 3.0** (July 5th 2008), in two flavours, chosen as the unzip
family chooses its own: Apple's build on macOS and the BSDs (the reference is
`/usr/bin/zip`, from Apple's `zip-33` tree), Ubuntu's build everywhere else,
Windows included (Ubuntu 24.04's `3.0-13ubuntu0.2`, Debian's patch series and
build options, Unicode and bzip2 support among them).
`STUFFR_ZIP_FLAVOR=apple` or `ubuntu` overrides that; any other value is
refused at exit 1 with `zip: STUFFR_ZIP_FLAVOR must be apple or ubuntu, not
'VALUE'` (the invoked name leads the line). `zip` reads `ZIPOPT` and `ZIP`
before the command line, as the reference does.

**The promise:**

- **Stdout, stderr and exit codes are those of the flavour's reference**
  (under `LC_ALL=C`), for every option of the four programs: adding, updating,
  freshening, deleting, copying (`-U`, `--out`), fixing (`-F`, `-FF`), testing
  (`-T`, `-TT`), split archives written and read (`-s`, `-sp`, `-sb`, `-sv`),
  comments (`-c`, `-z`, `zipnote`), `zipsplit`'s splits and index, the usage
  screens, `-v`, and the exit codes Info-ZIP defines.
- **Every archive byte is identical** to the reference's, wherever its
  behaviour is defined: headers, extra fields, Zip64 records, the deflate
  stream (a port of Zip's own deflater), data descriptors, split parts. The
  one exception is encryption (deviation 4): compatible, not identical.
- A differential suite runs each case through the real zip and a stuffr link
  and compares those streams and the archives byte for byte.
- **The intended difference:** the banner and help header lines (deviation 2).

**Known deviations:**

1. **SIGPIPE** is restored to its default action, as in the other families;
   under a parent that ignores it, zip sees `EPIPE` and stuffr still dies of
   the signal (the Rust runtime ignores it before `main`).
2. **The banner.** The `-v` banner line and each program's help header name
   stuffr and say it is altered (Info-ZIP licence, clause 3): `This is Zip 3.0
   (July 5th 2008), by stuffr X.Y.Z (altered; original by Info-ZIP, with
   modifications by Apple Inc.).` (Ubuntu: `(altered; Debian's build,
   original by Info-ZIP)`), likewise `Zip 3.0 (July 5th 2008), by stuffr ...
   Usage:` and the helpers' `ZipCloak 3.0 ...`. `-v`'s `Compiled with` line is
   the recorded reference build's, so another macOS build prints a different
   one.
3. **Undefined behaviour and endless loops are not reproduced**; the code's
   `// ruling:` comments record each decision. 5 and 6 are the ones the
   command line meets.
4. **Encryption is compatible, not identical.** The ten random bytes of each
   12-byte encryption header come from the system's generator (`getentropy`,
   `getrandom` or `/dev/urandom`; a system with none ends the run, `Internal
   logic error`, exit 5), where zip's come from `rand()` seeded with the time.
   An encrypted entry's header and data therefore differ run to run, as the
   reference's do; every other byte is the same and it decrypts the same.
5. **Long option-error text.** `get_option` builds its error in a 50-byte
   buffer; an error about an option whose `'name' (description)` needs 50
   bytes or more (`-lf`, `--output-file`, `--junk-paths=x`,
   `--recurse-patterns-`: 59 forms in all, listed by `cli/tests.rs`) aborts
   both references (Apple: SIGTRAP from `__sprintf_chk`; Ubuntu: glibc's
   "buffer overflow detected" and zip's SIGABRT handler, exit 9). stuffr
   prints the whole message, exit 16, as the C would with room.
6. **`-O` with no archive name** dereferences NULL in the C (SIGSEGV, answered
   by zip's handler with a blank line and `zip error: Interrupted
   (aborting)`, exit 9). stuffr gives that answer without the dereference.
7. **No "Scanning files" progress.** The message `newname` prints when a scan
   of 100 or more names takes over five seconds, with a dot every two seconds
   after, is not made (it depends on the clock, not on the names).
8. **`//host` and `//host/share`** alone as a name (or an `-i`/`-x`/`-R`
   pattern) make `ex2in` dereference NULL in both references; stuffr gives
   the same SIGSEGV answer as 6 without the crash. The order of two equal
   names in the found list follows each libc's `qsort`: Ubuntu's stable merge
   sort, Apple's own `qsort_r` on macOS, and off macOS a BSD quicksort ported
   in `scan.rs`, which orders 6 of 4000 random arrays with many equal keys
   differently from macOS (which of two equal names is dropped, when one
   operand is given twice among many).
9. **`-c` or `-z` after `-@`** (or with zip as a filter) read standard error;
   when it is not open for reading the C's `fgets(NULL)` dies of SIGSEGV in
   both references. stuffr gives the SIGSEGV answer of 6, the temporary
   removed, at the first question; a sandbox's standard error is never
   readable.
10. **A `-c`/`-z` line is cut at its first NUL**, as the C's `strlen` and
    `strcpy` cut it; a line that begins with a NUL makes the C read the byte
    before its buffer. stuffr takes it for an empty line.
11. **A symbolic link removed between `stat` and `readlink`** under `-y`: the
    C passes `readlink`'s -1 on as a length. stuffr stores the link with no
    text (0 bytes, CRC 0), exit 0.
12. **A failing write to the archive** is answered where and as zip's stdio
    stream answers it (measured under `ulimit -f` on both references), except
    two Ubuntu answers: when only `fclose` meets the failure, Ubuntu's
    `ziperr` closes the stream twice and glibc aborts (exit 5, the temporary
    left); stuffr answers as Apple does (`Temporary file failure`, exit 10,
    the temporary removed). And the `zip I/O error:` line shows the write's
    own error, as Apple does, not whatever `errno` glibc's later calls left.
13. **Reading an archive**, undefined behaviour not reproduced: an end record
    or Zip64 record cut short is read as zeros (an archive that is only
    `PK\5\6` is empty to stuffr; Apple says "cannot update a split archive");
    a Zip64 extra field shorter than its sizes is read as zeros past its end;
    `-X-` stops copying old extra blocks at one that runs past its field.
    `-g` writes a copy up to the central directory, appends, adds what the old
    file had past the new end (zip writes in place and never truncates, so a
    shorter `-z` comment leaves the old tail), and renames the copy into
    place; the bytes of a successful run are zip's. Except under `--out`
    (ruling Z33): zip truncates the `--out` file to nothing, grows the input
    archive in place and never replaces, so `zip -g in.zip --out out.zip f`
    leaves `out.zip` empty and `in.zip` grown; stuffr leaves `in.zip`
    untouched and publishes the grown copy as `out.zip`. A failure leaves the
    archive as it was: zip prints `attempting to restore <zip> to its previous
    state` (so does stuffr, on every failure and interrupt under `-g`) and
    rewrites the old central directory in place, leaving what it appended
    after it (a write failure there can even leave no readable archive). A
    failed `-T -g` is undefined behaviour in the C (`fseeko` on the closed
    stream: Apple exits 5 after a blank line); stuffr answers with the
    restore line, exit 8. `-T -g` tests the copy, so a `-TT` command is given
    the temporary's name, not the archive's.
14. **The output is not truncated up front.** zip opens it with `fopen "wb"`
    to check it can write it when it is `--out`'s or the archive has no
    entries, then removes an entry-less archive; stuffr opens without
    truncating and removes nothing it did not create. A run that fails or is
    interrupted leaves an `--out` target or an entry-less archive as it was
    (zip leaves the first empty and the second gone). On success, an
    entry-less archive that is a symbolic or hard link: zip, having removed
    the link, renames a new file into its place (the link's target left
    empty); stuffr writes through the link, as `replace` does for any linked
    archive.
15. **A failing `-T` in Ubuntu's build** closes the temporary's stream twice
    and glibc aborts (ruling Z3); stuffr answers as Apple does in both
    flavours: `test of t.zip FAILED`, `zip error: Zip file invalid, could not
    spawn unzip, or wrong unzip (original files unmodified)`, exit 8, the
    temporary removed.
16. **A sandboxed run** spawns no `unzip` and no `-TT` command (`-T` fails as
    without an `unzip` on `PATH`), and the interrupt handler writes
    `Interrupted (aborting)` to the message stream only, not to a `-lf` log.
17. **`-sf -m`** (ruling Z16) lists and ends without writing an archive; zip's
    `finish()` then deletes the marked files. stuffr deletes nothing.
18. **Split-part questions at the end of input** (ruling Z5). zip reads the
    answers with `fgets` and ignores the result, so at end of input `-FF`
    (also `-F`, and a copy of a split archive with a missing part, and
    Ubuntu's `-sp`) asks for ever. stuffr never loops: a question about a part
    to read answers `q` (as an explicit `q`, measured: `could not find split`
    and exit 0, or `Interrupted (Could not find split)`, exit 9, when an entry
    was being copied), and `-sp`'s question about where to write the next
    split answers ENTER (as Apple's build does).
19. **`-FF`, undefined behaviour not reproduced.** The central extra field of
    an entry found by its local header is copied with `strcpy`, which stops at
    the first NUL and leaves the rest of a `malloc`ed field as it was (zeros on
    Apple, heap garbage that changes from run to run on Ubuntu); stuffr
    copies up to and with the first NUL and writes zeros after (Apple's
    bytes). The entry's `lflg`, never set, is read as 0 (it only sizes
    `tempzn`); a data descriptor signature split across two 16 KiB reads (the
    C then writes `kk - 3`, wrapped, bytes) is not taken for one; a Zip64
    extra field shorter than its sizes is read as zeros past its end.
20. **`-F`/`-FF` with `--out` the damaged archive under another name**
    (`./a.zip`, a link; ruling Z21) is refused as the same name is (`--out
    path must be different than in path`, exit 16), before anything is
    written; zip compares names only and renames its lossy salvage over the
    archive.
21. **`-sp` when the next split cannot be written** (ruling Z23, "Not enough
    room on disk") lets the user choose another disk, for ever on a full disk;
    stuffr warns as `-sp` does and ends with `-s`'s answer, `zip error:
    Output file write failure (Not enough room on disk)`, exit 14.
22. **`-sp` with an archive name that has no directory** (ruling Z24): zip
    takes the name part as empty and indexes before its buffer; stuffr takes
    such a name as one in the current directory.
23. **`-z` whose first comment line is empty** (ruling Z25) copies `\r\n` into
    a one-byte block: Ubuntu's build dies in glibc's overflow check (exit 9);
    Apple's writes the comment. stuffr writes it in both flavours.
24. **`zipcloak` ignores `readlocal()`'s failure** and goes on with an
    uninitialised local header; stuffr ends the run with that failure's code
    (`zipcloak error: ... (was encrypting an entry)` or `(was decrypting an
    entry)`), the temporary removed and the archive untouched. A split
    archive under `-O` meets it at the first entry: the UTIL build's
    `readlocal()` looks in the last part only and warns `Did not find entry
    for <name>`; Ubuntu then dies of SIGSEGV (`Interrupted (aborting)`, exit
    9, or killed by the signal from its handler; measured with a terminal in
    Docker); stuffr warns the same and ends `Zip file structure invalid`, exit
    3. (Without `-O` both refuse a split archive: `cannot update a split
    archive`, exit 16.) A central name longer than the local one makes the C
    write past the local name's buffer; stuffr keeps the local name as it is
    (a shorter central name cuts it with a NUL, as the C does).
25. **`zipnote` and `zipsplit` never set `out_path`**, so `strcmp(in_path,
    out_path)` over a NULL ends in SIGSEGV for an archive that does not exist
    (or is named ``) and for a split archive: both references print
    `Interrupted (aborting)` and exit 9. stuffr answers the same; the signal
    is not raised.
26. **`zipnote -w` on Apple** (ruling Z4) closes the input stream twice and
    always fails, exit 10, `Bad file descriptor`, the archive untouched
    (undefined behaviour). stuffr takes Ubuntu's patched answer (patch 07) in
    both flavours: `-w` works. A comment's length wraps at 65536 as the C's
    `ush` does.
27. **`zipsplit`.** A `%` in the archive's name is a conversion in the C's name
    template (undefined); stuffr takes it as a character. After an error
    writing the index under `-p` and a yes to "redo entire disk?", the C goes
    back to the wrong disk; stuffr redoes disk 1. An interrupt removes the
    parts only when `-b`'s directory is shorter than half of `PATH_MAX` (the
    handler's static holds that much).
28. **Ubuntu's `UNICODE_SUPPORT`.** Where a conversion fails and the C reads
    through the NULL it got (a bit-11 name zip's UTF-8 decoder refuses; a
    Unicode Path field whose name it refuses; `-UN escape` over a name the
    locale cannot convert) or copies a not-yet-set name, the reference dies
    of SIGSEGV and answers `Interrupted (aborting)`, exit 9; stuffr gives that
    answer without the crash. A Unicode Path field shorter than its header
    says is read as zeros past its end; an old field of another length than
    the new one is taken out and the new one appended. Patches 12 (`mbstowcs`
    told the buffer holds `strlen + 1` wide characters, which glibc aborts on
    for every non-ASCII name) and 13 (`-TT`'s command buffer one byte short)
    are Ubuntu's own fixes: both flavours take the defined behaviour.
29. **`-Z bzip2` (Ubuntu).** zipup.c tests whether an entry is text over the
    whole 16 KiB input buffer, past the bytes read, and the buffer is never
    cleared, so the test sees what an earlier entry left there (reproduced: a
    short text file after a longer text file is text). The buffer's first
    contents are uninitialised in the C; stuffr takes them as zeros (a short
    first text file is binary, `iattr` 0, as measured).
30. **An interrupt while the new archive replaces the old one** (ruling Z32).
    zip unlinks the archive and renames the temporary, or, for a linked
    archive or a temporary on another device (`-b`), truncates the archive
    and copies the temporary into it; a SIGINT or SIGTERM in that window makes
    zip's handler remove the temporary, leaving the archive gone or cut short
    and no whole copy anywhere. stuffr holds both signals back for the length
    of the replace (`zip`, its split parts and `-F`/`-FF`, `zipcloak`,
    `zipnote -w`; `-g`'s restore state is cleared in the same window) and
    answers them as zip does once the archive is whole: `Interrupted
    (aborting)`, exit 9, the new archive in place. A long cross-device copy
    answers Ctrl-C when it ends. When the replace fails after the archive
    was unlinked or cut (ruling Z34), the temporary is the only whole copy:
    it is kept under its own name, where zip's handler would remove it.

The full set is in the code's module docs
(`crates/stuffr-cli/src/compat/zip/mod.rs`), which is the source of truth.

### The brotli family

`brotli`, `unbrotli` and `brcat`, from `0.20.0`. They behave as the **brotli
command line tool, version 1.2.1**, and only that version: one personality,
one reference. The reference reads no environment variable. `unbrotli` and
`brcat` decompress (`brcat` to standard output, as `-dc`); `-V` prints
`brotli 1.2.1` and `-h` writes the help to standard error (exit 0), a usage
error its message to standard error and the help to standard output (exit 1).
The exit codes are 0 and 1 only, and the first failing file ends the run.

**The promise:**

- **Stdout, stderr and exit codes are those of brotli 1.2.1**, on both build
  tiers: every option (`-#`, `-q`, `-w`, `--large_window`, `-C`, `-D`, `-K`,
  `-t`, `-s`, `-o`, `-S`, `-f`, `-k`, `-j`, `-n`), every usage error, the
  decoder's `reason:` lines, concatenated and truncated streams. A
  differential suite runs each case through a real brotli 1.2.1 and a stuffr
  link and compares those streams, the file tree, modes and mtimes.
- **Compressed output.** With `--features brotli-c` (also in `c-backed`),
  which builds libbrotli 1.2.1 (vendored, `LICENSE-brotli`), `.br` bytes are
  **byte-identical to brotli 1.2.1** for every option. On the default pure
  tier the output is **compatible**: brotli 1.2.1 decodes it to the input.

**Known deviations:**

1. **Pure tier: the `.br` bytes are compatible, not identical.** brotli
   1.2.1 decodes them to the input; the C tier's are the reference's.
2. **Pure tier: `-D` is refused in both directions** (`-D is not supported
   by this build (pure tier); build with --features brotli-c`, exit 1, once
   the dictionary file has been read), **and so is a one-byte `-C` comment**
   when compressing (`failed to emit metadata [NAME]`, exit 1; the pure
   encoder writes a corrupt stream for it). Every other `-C` length, and
   `--large_window`, work.
3. **Pure tier: a corrupt stream's `reason:` line can differ.** The decoder
   cannot tell `-10` (`BLOCK_LENGTH_2`) from `-9` (`BLOCK_LENGTH_1`) and
   reports `-9`, and it accepts some streams libbrotli rejects with `-9`.
   `-15` is reported as `-14` where the decoder is at a metablock header.
4. **An input that is also the output is refused,** where the reference
   truncates it, and with `-d` deletes it: `brotli -f -o a a`, a hard link
   or a symlink to the input as the output. stuffr prints `input file [NAME]
   is the same as the output file` and exits 1 before opening the output.
5. **A later input operand that an earlier output would overwrite is
   refused** before the output is opened (`brotli -f a a.br`, `-df a.br a`;
   `input file [NAME] would be overwritten by the output of [NAME]`, exit
   1), where the reference overwrites that input before reading it.
6. **`-j` removes the source only after the output closed without error;**
   the reference removes it even when `fclose` failed (ENOSPC, EIO), leaving
   a truncated output and no input. stuffr buffers its output in 64 KiB, the
   reference in stdio's buffer, so on a full disk the failure may be
   reported as `fclose failed [x]` where the reference says `failed to write
   output [x]`. The output is removed either way.
7. **`brotli - -` (standard input named twice) writes both streams;** the
   reference closes standard output after the first file and crashes on the
   second.
8. **`could not read dictionary: out of memory` is never printed.** The
   dictionary buffer (at most `MAX_DICTIONARY_SIZE`, 50331660 bytes, about
   48 MiB, the reference's own limit) is a plain allocation; when the allocator cannot
   give it, Rust aborts the process (SIGABRT, status 134) where the
   reference prints that line and exits 1.
9. **No signal handler, as the reference:** an interrupt leaves the partial
   output where it was written (outputs are created directly under their
   names, never through a temporary).
10. **A closed pipe kills stuffr by SIGPIPE,** as it kills brotli under the
    default disposition. Where the parent ignores SIGPIPE brotli answers
    `failed to write output [NAME]: Broken pipe` and exits 1; stuffr still
    dies of the signal, because the Rust runtime ignores SIGPIPE before
    `main` and the inherited setting cannot be told apart. A permanent
    deviation, as in every family.
11. **`-f` never writes through a symlink at the output name** (hardening).
    The reference opens a forced output without `O_EXCL`, so a symlink
    there, dangling or not, is followed and the file it names created or
    truncated. stuffr replaces the link with a fresh file and leaves its
    target alone; without `-f` both refuse it. The input's attributes are
    copied by name after the close, as the reference copies them, but only
    onto the file this run opened.

### Roadmap

One family per release, each with its own spec stating its byte-identity
promise: **bzip2 (`0.11.0`), gzip (`0.12.0`), xz/lzma (`0.13.0`), zstd
(`0.14.0`), lz4 (`0.15.0`), `unzip`/`zipinfo`/`funzip` (`0.16.0`),
`compress`/`uncompress` (`0.18.0`), `zip`/`zipcloak`/`zipnote`/`zipsplit`
(`0.19.0`) and `brotli`/`unbrotli`/`brcat` (`0.20.0`) are done.**
`tar` is excluded (see [OUT-OF-SCOPE.md](OUT-OF-SCOPE.md)). The planned
tiers:

- **Byte-identical:** bzip2, on both tiers; gzip against Apple's gzip on
  the `c-backed` tier, via zlib (done); xz/lzma on the `c-backed` tier, via
  liblzma, against XZ Utils 5.8.4 (done); zstd on the `c-backed` tier,
  via libzstd, against zstd 1.5.7 (done; `--train-cover` and `--adapt`
  excepted, as stated above); lz4 on the `lz4-c` tier (in `c-backed`), via
  liblz4, against lz4 1.10.0 (done), which also makes zstd's `--format=lz4`
  byte-identical there; brotli on the `brotli-c` tier (in `c-backed`), via
  the vendored libbrotli 1.2.1, against brotli 1.2.1 (done).
- **Compatible behaviour only** (the same flags, files, exit codes and
  messages, and output the real tool reads): GNU gzip's exact bytes;
  every family except bzip2 on the pure tier.

### Attribution

The bzip2 family is ported from bzip2 1.0.8's `bzip2.c` and
`bzip2recover.c`, copyright (C) 1996-2019 Julian Seward, under the bzip2
licence reproduced in
[`crates/stuffr-cli/LICENSE-bzip2`](crates/stuffr-cli/LICENSE-bzip2).
The gzip family's Apple personality is ported from Apple's `gzip.c`
(`file_cmds`, itself FreeBSD's and NetBSD's, copyright (c) 1997-2017
Matthew R. Green) and from the decoders it carries (`unpack.c`, `unbzip2.c`,
`unxz.c`, `unlz.c`, `zuncompress.c`), under BSD licences whose notices are in
[`crates/stuffr-cli/LICENSE-gzip-bsd`](crates/stuffr-cli/LICENSE-gzip-bsd).
The xz family is ported from XZ Utils 5.8.4's `src/xz/`, plus the parts of
liblzma that `--list` and the memory figures need, by Lasse Collin and
contributors, under 0BSD; the licence is in
[`crates/stuffr-cli/LICENSE-xz`](crates/stuffr-cli/LICENSE-xz).
The zstd family is ported from zstd 1.5.7's `programs/` by Yann Collet and
the zstd contributors (Meta Platforms, Inc.), under zstd's BSD licence; the
licence is in
[`crates/stuffr-cli/LICENSE-zstd`](crates/stuffr-cli/LICENSE-zstd). One test
fixture carries verbatim zstd source: `crates/stuffr-cli/tests/fixtures/zstd_progress/gen.c`
copies `UTIL_makeHumanReadableSize` from `programs/util.c` (BSD, covered by
`LICENSE-zstd`).
The lz4 family ports nothing: lz4's command line tool is GPL-2.0-or-later and
its source was never read, so the front end is a clean-room implementation
from lz4's documentation (man pages, `NEWS`, `-h`/`-H`) and the behaviour of
the 1.10.0 binary. On the `lz4-c` tier liblz4 1.10.0 (Yann Collet,
BSD-2-Clause) is linked; its notice is in
[`crates/stuffr-cli/LICENSE-lz4`](crates/stuffr-cli/LICENSE-lz4).
The unzip family is ported from Info-ZIP UnZip 6.0 (Apple's `zip-33` tree
and Debian's patches) under the Info-ZIP licence, in
[`crates/stuffr-cli/LICENSE-infozip`](crates/stuffr-cli/LICENSE-infozip).
The zip family is ported from Info-ZIP Zip 3.0 (Apple's `zip-33` tree and
Debian's patches) under the same Info-ZIP licence.
The brotli family is ported from brotli 1.2.1's `c/tools/brotli.c` (MIT), and
on the `brotli-c` tier libbrotli 1.2.1 (Google, MIT) is vendored and built;
its notice is in
[`crates/stuffr-cli/LICENSE-brotli`](crates/stuffr-cli/LICENSE-brotli), under
the `MIT` already in the expression below.
The compress family's Apple personality is ported from Apple's `compress.c` and
`zopen.c` (`file_cmds`, 4.4BSD's, copyright the Regents of the University of
California), BSD-3-Clause, in
[`crates/stuffr-cli/LICENSE-compress-bsd`](crates/stuffr-cli/LICENSE-compress-bsd);
its ncompress personality is ported from ncompress 5.0's `compress.c`, released
into the public domain under the Unlicense, in
[`crates/stuffr-cli/LICENSE-ncompress`](crates/stuffr-cli/LICENSE-ncompress).
`stuffr-cli`'s licence metadata is therefore
`MIT AND bzip2-1.0.6 AND BSD-2-Clause AND BSD-3-Clause AND 0BSD AND Info-ZIP AND Unlicense`. The GNU
personality contains no GNU code: GNU gzip is GPLv3 and its source was never
read, so that behaviour comes from the manual, `--help`, the NEWS file and
running the binary.

## Why another one

Three specific gaps, rather than a general wish for tidiness.

**No single tool spans the format space.** Modern formats (zstd, brotli, lz4),
established ones (gzip, bzip2, xz, zip, 7z) and historical ones (LHA, ARJ, ARC,
ZOO, Unix `compress`) each need their own binary with its own flag conventions —
and the historical set is getting genuinely hard to run on a current machine.

**Several formats refuse to stream.** ZIP, RAR and 7z keep their authoritative
index at the *end* of the file. 7z and RAR use solid blocks that interleave
entries, so you cannot get file *N* without decoding *1..N*. squashfs and ISO are
filesystem images that need real random access. And in practice many libraries
simply demand `Read + Seek`, which stdin is not — so
`curl … | tool | grep` fails for exactly the ad-hoc inspection where it would be
most useful.

**Parallelism is ungoverned.** Tools that thread at all tend to take every core,
ignore container CPU quotas, and ignore memory demand. That is actively harmful
on a shared or loaded server.

## The three ideas

### 1. Codec and container are separate things

Every format in scope combines two independent concepts — and they stack in
**opposite orders** depending on the format:

| Format | Structure | Decode order |
|---|---|---|
| `archive.tar.gz` | container (tar) inside a codec (gzip) | codec → container |
| `archive.zip` | container whose entries each carry their own codec | container → codec, per entry |
| `archive.7z` | solid blocks: one codec chain spanning several entries | boundaries don't align |
| `image.squashfs` | a container that is a filesystem | random access is intrinsic |

Tools that conflate the two end up with a special case per format. Keeping them
orthogonal is what lets the streaming ladder and the thread governor each be
written **once** instead of per format.

### 2. Make unstreamable formats stream — and say what it cost

A container never opens a file. It asks a source for capabilities, and an
adaptive ladder answers with the highest rung it can reach:

1. **Exact** — input already seekable. Authoritative index, full metadata.
2. **ForwardOnly** — not seekable, but the format can be parsed forward (ZIP local
   headers, tar, cpio, gzip members). Real data, approximate metadata.
3. **Spilled** — the format genuinely needs seek (squashfs, ISO, 7z index). Spool
   to memory up to a cap, then a temp file, then treat as Exact.
4. **Degraded** — last resort. Parse forward anyway and record what was lost.

The point is the last clause. **Fidelity loss is a structured return value, not a
log line** — the caller can find out afterwards that entry names came from local
headers rather than the central directory, that a size was only known after its
data, or that a solid block cost 40 MB of wasted decode to reach one file.
`--strict-fidelity` turns any such warning into a non-zero exit;
`--fidelity=json` emits them machine-readably.

So `curl … | stuffr cat - | grep pattern` works on a ZIP, on real data, and tells
you honestly what it approximated.

What it approximated shrinks when the stream allows. A zip on a pipe is walked by
its local headers, then its central directory, which follows the last entry, is
read and compared with them: entry count and order, and per entry the name, method,
CRC-32, sizes and flag bits 0, 3 and 11. When that comparison completes the old
pipe warnings (`central/trailing index was never read`, `total entry count is
unknown`) are not raised, so a well-formed piped zip passes `--strict-fidelity`
(exit 0; it was exit 4 up to 0.22.0). They stay when the directory is cut off,
absent, past 32 MiB of recorded headers, or holds a unix symlink (a pipe delivers
the link as a regular file). The same comparison runs on a seekable zip: a local
header and central directory that disagree raise `Fidelity::HeadersDisagree` (``zip``
local header and central directory disagree on FIELD for entry `NAME`), exit 4 under
`--strict-fidelity`. On hostile zips four exits moved with the `zip` crate's 9.1.3
upgrade: an end record whose two counts disagree is exit 5 (was a warning), a
multi-disk end record is exit 5 (was 3), AES method 99 without its extra field is
exit 3 (was 5), and a Unicode Path extra field with a bad CRC is ignored (was exit 5).

A gzip or bzip2 file is a concatenation of members, and what follows the last one
that verified is now judged rather than dropped: NUL or `'X'` padding is silent,
as before; a damaged member header (gzip `1f 8b` with a method other than 8 or a
reserved flag bit, bzip2 `BZh` with a bad level or block magic, or the file ending
inside the magic) is corrupt, exit 5; any other tail raises
`Fidelity::TrailingDataIgnored` (`` `gzip` stream is followed by N byte(s) that are
neither another member nor padding; they were ignored ``), printed by `unpack`,
`cat` and `convert`, exit 4 under `--strict-fidelity`. Before, one flipped byte at
a member boundary silently dropped every later member at exit 0. A codec under a
container (`.tar.gz`, `.tar.bz2`) reports it the same way once the walk reaches
the end of the archive: `list`, `test`, `unpack -C`, `cat FILE ENTRY` and
entry-mode `convert` print it, and the verbs that take `--strict-fidelity` exit 4.
`cat FILE ENTRY` now prints every fidelity warning of its read on stderr (it
used to drop its report): stdout still carries the entry's bytes alone, and the
exit stays 0, since `cat` has no `--strict-fidelity`.
Each member costs a fresh decoder, so the number a file may start is bounded
member by member: 4096 are free, and each further one must be paid for by 64
bytes read or decoded, each member counting for at most 64 of its own bytes (so
one large member cannot pay for a run of empty ones), or the file is refused as
a resource limit (exit 6).
A file of a million empty 20-byte gzip members used to cost tens of GB of
zeroing with no output for `--max-ratio` to see.

### 3. One governed thread budget, conservative by default

One pool for the whole process; nothing spawns a thread outside it.

The auto budget takes the **minimum** of CPU affinity, cgroup v2 `cpu.max`, and
cgroup v1 quota — so a container limited to 2 CPUs on a 64-core host gets 2, not
64 — then defaults to **half of that, capped at 8**. `--turbo` lifts both limits;
`--threads 1` spawns no pool at all.

Work units acquire **leases** rather than being handed a thread count, so
"8 entries in parallel, each using multi-threaded zstd" cannot exceed the budget.
Nested parallelism is safe by construction instead of by every call site
remembering to divide.

Memory is a second, equally real budget: multi-threaded xz at `-9` wants roughly
700 MB *per worker*, and sixteen workers will OOM a modest server long before CPU
becomes the constraint. Codecs declare their per-worker demand and the governor
reduces the thread count to fit `--memory-limit`. Fewer, slower threads beat the
OOM killer.

## Planned CLI

*Phase 2 and later. `pack`, `unpack`, `cat`, `info`, `formats`, `list`,
`test` and `salvage` all work today, across the twelve round-trip codecs and
six round-trip containers
(`ar`, `arj`, `cpio`, `lha`, `tar`, `zip`/`zip64`) `stuffr formats` lists — `pack`/`unpack`/
`cat` are entry-aware for every container, with extraction-time path
containment and bomb limits on by default. `convert` and `install-links`
work too (the bzip2 and gzip families so far). `pack` walks a directory tree, and
`pack -o bundle.tar.gz` composes a container on top of a codec in one pass.
`salvage` is the one recovery-biased verb, and everything else here stays
as uncompromising as it was before it existed. It recovered zip archives
only in Stage 1; Stage 2 added a scanner per legacy container (`arc`,
`zoo`, `lha`, `arj`) and Stage 3 the checksum-less three (`tar`, `cpio`,
`ar`), so every container `stuffr formats` lists has one — its SALVAGE
column says how far each can be trusted. Naming a format this build has no
scanner for with `--format` is exit 3 — a statement about this build, never
about the archive.*

```
stuffr pack     [-o out.tar.zst] [--format F] [--level N] PATHS...
stuffr unpack   [-C dir [-p]] ARCHIVE [PATTERNS... | --index N...]
stuffr list     ARCHIVE                    # first column is the index
stuffr ls       [-r] [-a] [-n] [FOLDER]    # alias: files; what a folder holds that stuffr opens
stuffr cat      ARCHIVE [PATTERNS... | --index N...]  # entry data; works on a pipe
stuffr info     ARCHIVE                    # resolved chain, ladder rung, fidelity
stuffr formats                             # capability matrix for THIS build
stuffr test     ARCHIVE                    # integrity check, no extraction
stuffr salvage  ARCHIVE [-C dir | -o FILE | --list] [--index N...]  # zip/arc/zoo/lha/arj/tar/cpio/ar; scan position, not list's index
stuffr convert  IN -o OUT                  # change codec or container (.tgz -> .zip)
stuffr install-links --dir ~/.local/bin    # opt-in compat symlinks, never automatic
stuffr bench    FILES... [--formats F,G] [--levels]  # compare codecs on your own data
```

`convert` changes a format without unpacking to disk. When the container is
kept (`.tar.gz -> .tar.zst`) only the codec is re-encoded and the container's
bytes are copied untouched. When the container changes (`.tgz -> .zip`,
`.zip -> .tar.xz`) every entry is read from one and written into the other
under `pack`'s fidelity rules: what the target cannot hold is skipped with a
warning, and `--strict-fidelity` turns any loss into exit 4 with the output
still written. A zip records no owner, so converting one into a container
that stores uid/gid warns about the missing `uid_gid` for every entry. A
codec with no magic bytes nested inside another (gzip over brotli) is not
peeled and stays in the output, as with `unpack`.

`ARCHIVE` accepts `-` for stdin everywhere. Optional compat symlinks
argv[0]-dispatch into the same binary, so the tools they are named for drop
into existing scripts unchanged: `bzip2`, `bunzip2`, `bzcat` and
`bzip2recover`, `gzip`, `xz`, `zstd`, `lz4`, `unzip` with its siblings,
`compress`/`uncompress` and `zip` with its siblings today, one family per release — see [Compatibility links](#compatibility-links).

`info`'s `detected:` line says how the outer format was decided: `magic`
(its signature, with a header that checks out), `extension` (no signature
matched; the file name decided), or `magic-unconfirmed` /
`extension-unconfirmed` when the format's header check refused the bytes —
a damaged file, or one that is not that format at all. The verbs still read
such a file (a damaged archive you name is reported corrupt, exit 5, and
`salvage` can scan it). When a layer did not check out, `info` adds
`checks:   tar did not check out` naming it — an inner one too, such as the
tar of a `.tar.gz` whose first header fails its checksum — and `--json`
adds `unconfirmed_layer`; a file whose every layer checks out prints neither.

### Finding archives: `stuffr ls`

`stuffr ls` on a folder (or with no argument, the current one) lists the
files stuffr can open, newest first, `ls -l` style with the name last:

```
$ stuffr ls ~/Downloads
tar+gzip  4.2M  Oct 27 14:03  backup-2026.tar.gz
gzip      812K  Oct 25 22:10  export
zip        18M  Oct 21 09:41  photos.zip
[FOLDER]        Oct 20 11:02  old/
3 of 5 files shown, 2 not openable
```

A file is listed only when its header checks out behind its signature: its
first 4096 bytes carry the magic of a format this build reads, and the
format's own header check accepts what follows (a format with no magic,
brotli, is listed by its extension). So an extensionless gzip is found, while
a `.zip` that is really an HTML page, or text that happens to begin with a
format's magic bytes, is not. A compressed file's inner layer is decoded from
those 4096 bytes alone to name it (`tar+gzip`; a magicless inner layer such as
a v7 tar is named by the file's name, and only when its own check accepts the
decoded bytes); `ls` reads nothing more than that and the last 512 bytes.
Apple disk images (`.dmg`, recognised by their `koly` trailer) are not listed,
and every verb but `salvage` refuses one with exit 3 (`--format` overrides
that); a disk image piped in on stdin cannot be recognised, and stuffr may
decode its first chunk. On macOS, a file kept only in iCloud or another cloud
provider (not downloaded) is never opened, since reading it would download it,
so it is not identified and counts as not openable. Sizes are `ls -lh`'s,
dates `ls -l`'s in local time, and the footer (left out when it would say 0)
counts the files that are not openable. `-r` adds one block per subfolder
holding something openable, `-a` includes hidden names, `-n` sorts by name,
and `--json` prints `{entries, shown, skipped, warnings}`. `stuffr files` is
the same folder listing. Given a file or `-`, `stuffr ls` is `stuffr list`,
unchanged. A file or subfolder that cannot be read is named on stderr and the
exit is 4; the listing itself never exits 1.

### `stuffr bench`

`bench` compares codecs on your own files instead of a published corpus:

```
stuffr bench access.log*                         # every benchable codec, default levels
stuffr bench --levels --formats xz,brotli a.log  # every level of two formats
stuffr bench --per-file a.log b.log              # each file its own stream
stuffr bench --json access.log | jq .winners     # or --csv; --table-only (-q) for the table alone
stuffr bench --no-memory access.log              # skip the memory runs
```

Each row gives the compressed size, the ratio, the compress and
decompress times, and the peak memory to compress (`c-mem`) and to
decompress (`d-mem`); below the table come the smallest, the fastest each
way, the best balance of those three, and `least memory:` (the row whose
larger memory figure is smallest, shown as `c-mem / d-mem`; ties to the
smaller output). Every format runs under the same conditions: the same
input (in memory, or streamed from disk when it is over half of
`--memory-limit`), the same
`--threads` setting for compression (bench ignores `STUFFR_THREADS`;
decompression is always single-threaded), and one untimed warm-up read
first. Each codec gets the compressed-output destination its own worst case
allows: memory unless that worst case is over the limit's room for it (half of
`--memory-limit` beside in-memory input, all of it for streamed input), then
one temp file, whose writes count in that row's compress time. `compress` can
write twice its input, so it reaches the temp file first. A row that went to
disk is marked: a `*` after its compress time with a footnote under the table,
and `output` (`memory` or `disk`) in JSON and CSV. Each file's size is taken
once at the start, so a log still being written is benched as it was then.
Only codec work is timed (except the temp file's writes, in a marked row), and
`--repeat N`
reports the median of N runs. The input line names the codecs that ran
through a C library (`C: zstd, xz`), or says `pure`. Benchable means a codec
this build writes with its real encoder: zstd can be benchmarked only in a
build with the `zstd-c` feature (part of `c-backed`, and in the Homebrew
build), because the pure tier's zstd encoder is a weak fallback. Inputs must
be regular files (or links to them): a pipe or device is refused with exit 2,
so to bench a pipe, write it to a file first. No match, a directory, a
dangling symlink, a directory that cannot be read (named, or on a pattern's
way) and a file that cannot be read are exit 2 as well, naming the path. A format that fails is a row
marked failed, not an exit code. On a terminal, stderr shows a bar for the
row being measured, drawn only between timed pieces and cleared before the
table; Ctrl-C, SIGTERM, SIGHUP and SIGQUIT clear it too (and stop a running
memory run and remove bench's temp file) before bench dies of the signal
(SIGQUIT still dumps core where core dumps are on). Timings
need a release build; a debug build refuses with exit 2.

**Memory.** On macOS and Linux, after a row's timed runs, bench runs it once
more, untimed, in a separate child process: once to compress, once to
decompress (the bar reads `memory`). The figure is that process's peak
resident memory, what it actually touched, not what it reserved, above its
size just before the codec started (macOS: `getrusage`'s `ru_maxrss`; Linux:
`VmHWM` and `VmRSS` from `/proc/self/status`), under the same level,
`--threads` and `--memory-limit` as the timed runs, and measured once per row
whatever `--repeat` says. It includes a small floor of code paged in and fixed
buffers, about 0.1–0.35 MiB, so even a tiny format shows a small non-zero
value, and a light format such as lz4 shows a few hundred KiB (the floor plus
its own state). xz on a small input touches less than it reserves, so its
figure can be well under its nominal dictionary size. A format that holds its
whole input (the pure tier's zstd encoder) grows with the input. With
`--per-file` each file gets its own pair of runs and the row shows the
largest. The compress run writes the row's compressed output to a temp file in
`$TMPDIR` (`stuffr-bench-<pid>-<n>`, removed as soon as the decompress run has
read it, and on Ctrl-C), which the decompress run reads back; on Linux
`$TMPDIR` may be a tmpfs, which holds it in RAM. A memory run that fails (a
full disk, for example) shows `-`, a footnote under the table names the first
reason, and JSON and CSV carry it in `mem_error`; the row's other figures
stand, it takes no part in `least memory`, and the exit code is unchanged. A
row whose timed run failed, a refusal by `--memory-limit` included, has no
memory run. On the C tier the decoders take no memory limit, so `d-mem` can
exceed `--memory-limit`. The memory runs add one compression and one
decompression per row, so a run takes up to about twice as long (1.8x for
every level of xz and lz4 on 19 MiB of text), most for slow compressors such
as xz. `--no-memory` skips them: no memory columns and no `least memory` line.
Elsewhere (Windows, and the BSDs until their figures are verified) memory is
not measured: the cells show `-` and the input line says `memory not measured
on this platform`.

`--json` prints one object. `conditions` holds `files`, `bytes_in`, `mode`
(`one-stream` or `per-file`), `threads` (`--threads` as given, `null` when
omitted), `workers` (the compression threads that resolved to), `repeat`,
`streamed` and `memory` (`true` when the memory runs were made). Each of
`rows` holds `format`, `level` (`null` for lz4 and snappy), `backend` (`c`
or `pure`), `ok`, `bytes_out`, `ratio` (input bytes
÷ `bytes_out`), `compress_ns`, `decompress_ns` (medians, nanoseconds),
`balance` (the mean of the three `best / value` scores, relative to this
run), `error` and `output` (`memory`, or `disk` when the compressed output
went to the temp file while timed; `null` for a failed row), `compress_mem`
and `decompress_mem` (peak resident bytes, `null` when not measured or when
that side's run failed) and `mem_error` (why a memory run failed, else
`null`); a failed row has `ok: false`, its reason in `error` and
`null` in every measurement, and a ratio that cannot be computed (0 bytes)
is `null`. `winners` names `smallest`, `fastest_compress`,
`fastest_decompress`, `balance` and `least_memory` as `{format, level}`, or
`null` when no row qualifies (`least_memory` is `null` under `--no-memory`).
`--csv` has 21 columns: `format, level, ok, bytes_in,
bytes_out, ratio, compress_ns, decompress_ns, balance, error, files, mode,
threads, workers, repeat, streamed, backend, output, compress_mem,
decompress_mem, mem_error`, in that order, with the same units; an empty
field stands for `null`. The last three were appended in 0.18.1 (18
columns before), so a reader that takes columns by position is unaffected.

### Two safety defaults that are not negotiable

"Extract this untrusted archive" is the most exploited operation in this whole
domain, so:

- **Path containment.** Absolute paths, `..` traversal, and symlinks escaping the
  destination are **refused, not silently sanitised**. So is an entry whose path
  runs *through* a symlink: `a/b/up -> ..` followed by `a/b/up/link -> ../..` is
  contained when each name is resolved component-wise and still lands outside the
  destination once the OS resolves it, so the extractor also refuses any entry
  with a symlinked path component (libarchive's `SECURE_SYMLINKS` shape, refused
  rather than quietly unlinked). For the same reason a symlink target may use
  `..` only as a leading run (`../../a/b`), never after a name (`x/s2/..`): the
  OS resolves `x/s2` first, and if that is another link the `..` climbs from
  wherever it points. Such a link (and one with an empty target) is **skipped,
  not created** — named in a warning, the rest extracted, exit 0 (4 under
  `--strict-fidelity`) — since GNU tar's `--transform` rewrites targets into
  exactly that shape; a target that actually climbs out is still exit 7.
- **Bomb limits.** Default caps on total output and expansion ratio, so a 42 KB
  zip that expands to 4.5 PB fails fast instead of filling the disk. The error
  names the entry that tripped it.

Permissions follow `tar`'s non-root defaults: a restored mode is masked by the
umask (`unpack -C -p` / `--same-permissions` restores the archived bits),
setuid, setgid and the sticky bit are never restored, and a directory that
existed before the run keeps its own mode and mtime. A directory's metadata is
applied at the end of the run, through a descriptor opened `O_NOFOLLOW` and
checked against the inode the run created, so a directory swapped for a
symlink in the meantime is skipped with a warning rather than followed.
A single-stream output (`pack a.txt -o a.txt.gz`, `unpack a.gz -o a`,
`convert a.gz -o a.xz`) takes its input file's mode, as gzip does, so a 0600
file stays 0600. On macOS the input's quarantine attribute
(`com.apple.quarantine`) is carried onto every file and directory `unpack` and
`salvage` create and onto a single-stream output, as Apple's tar and unzip do,
so Gatekeeper still checks what came out of a downloaded archive, and onto an
archive `convert` writes from a quarantined one. Symlinks are not stamped by
these verbs (the unzip compatibility link does stamp them, as Apple's unzip
does).

**One window is deliberately still open, and it is worth stating plainly.** The
symlinked-component check is the only containment check that consults the
filesystem, and it is check-then-use: it `lstat`s an entry's ancestors and then
writes through `File::create` (`O_WRONLY|O_CREAT|O_TRUNC`), `create_dir_all` and
`symlink`, each of which follows a symlink it meets. Against a hostile *archive*
the window is closed — extraction is single-threaded and sequential, and every
symlink the archive creates has already been checked. Against a hostile archive
**plus a concurrent local process with write access into the destination
directory**, a component that turns into a symlink between the check and the
write is followed. Closing it means resolving nothing by name — walking the
destination with `openat(O_NOFOLLOW)` per component — which needs a `rustix` or
`libc` dependency and a design cycle of its own. Extract untrusted archives into
a directory nothing else can write to.

**A second thing worth stating plainly: entry-aware extraction is not atomic.**
A single-stream decode (`stuffr unpack a.gz -o out`) publishes through
temp-file-plus-rename, so a refused decode leaves no partial file — asserted
by name in its tests. `stuffr unpack a.tar -C out/` writes each entry straight
to its final path, so a refusal partway through leaves the entries that already
completed plus one partially-written file. The refusal itself is correct and
the exit code is right; the destination is simply not rolled back. Making it
atomic means staging the tree and moving it into place, which needs a temp
directory on the destination's filesystem and an answer for a tree larger than
the free space — its own cycle. Until then: extract into a fresh directory you
can delete, and check the exit code before trusting the contents.

## Planned format coverage

Read and write symmetry wherever it is technically possible.

- **Modern codecs:** zstd, xz/LZMA2, LZMA1, LZIP, brotli, lz4, snappy, gzip/zlib/deflate, bzip2 *(all implemented, Phase 1)*
- **Containers:** tar, cpio *(`newc` only)*, ar, zip/zip64 *(all implemented, Phase 2)*; 7z, squashfs, ISO 9660, MS CAB, RAR *(read only)* remain — each deferred to its own cycle, see [OUT-OF-SCOPE.md](OUT-OF-SCOPE.md)
- **Plain storage:** collecting and compressing are separate axes — tar, cpio, ar, zip-stored and 7z-copy all give you a container with no compression
- **Legacy:** LHA/LZH, Unix `compress` `.Z` and ARJ *(Phase 3b, part of the default build — `--features legacy` still exists for a `--no-default-features` build)*, joined by **ARC/PAK** and **ZOO** *(read-only, Phase 3c, their framing and decoders written from scratch)*. **Phase 3c** adds two things and it is worth saying which, since they landed across separate tasks: WRITE support for `compress` (Task 5 — `pack --format compress` now works), for `lha` (Task 6 — writes `-lh5-`) and for `arj` (Task 7 — writes method 0, `Stored`, so the archive is valid but larger), and READ support for **ARC and ZOO**. All of it has now landed; `arc` and `zoo` are the only legacy formats that still refuse to write, at exit 3. StuffIt `.sit` *(older methods only)* and Amiga/MS LZX are **3c candidates too**, gated on evidence rather than effort: neither has a second implementation or a tool to check a fixture against, so a fixture and its expectation would both come from the crate under test. StuffIt `.sitx` and its later methods stay permanently out — see [OUT-OF-SCOPE.md](OUT-OF-SCOPE.md)

A few formats are read-only by **external constraint rather than effort** — RAR's
compressor is proprietary and the free `unrar` source is licensed for
decompression only; StuffIt's encoders are undocumented. Those are recorded in
[OUT-OF-SCOPE.md](OUT-OF-SCOPE.md) so the gap is documented rather than looking
like an oversight.

## Build tiers

Pure Rust is the default, so `cargo install` needs no C toolchain — and as of
Phase 1e that is no longer a reduced experience for xz. The pure tier reads and
writes xz and LZMA1 at parity with `liblzma`'s output size, within about 1.4x of
its speed, and LZIP — a third format built on the same `lzma-rust2` dependency
— has no C-backed alternative to be at parity with in the first place; it is
simply the only implementation, at full ratio, in every build. Only **zstd's
encoder** is genuinely better for linking C; the pure one works but is gated
behind `--allow-weak-encoder` because its output is markedly larger. RAR
remains decode-only for licence reasons, not effort.

| Feature | Contents |
|---|---|
| `pure` *(in `default`)* | everything modern with a pure-Rust implementation — all eleven pure-tier codecs, including read+write xz, LZMA1 and LZIP, plus all four pure-tier containers |
| `c-backed` | `zstd-sys` and `liblzma`, both vendored and built statically; also the one entry codec inside `zip` that needs a C-compiling crate (see below); later `unrar` (decode) |
| `legacy` *(default)* | the historical format set — `compress` (read AND write, Phase 3c Task 5), `lha` (read AND write, Task 6 — reads seven methods, writes `-lh5-`), `arj` (read AND write, Task 7 — reads five methods, writes `Stored`, so it does not compress), `arc`, `zoo` (read-only) |
| `full` | all of the above |

`c-backed` needs a C compiler and **nothing else** — no `libclang`, no system
liblzma. Both dependencies vendor their own C source: `zstd` does by default, and
`liblzma` is pinned with `default-features = false, features = ["static"]`
specifically so it never falls back to linking a system library via pkg-config,
which would succeed on a developer machine and fail on a clean one. A CI job
checks that the `pure` graph contains neither `zstd-sys` nor `liblzma-sys`.

**The `pure`/`c-backed` split now reaches one container, not only codecs:**
reading *or* writing a `zip` entry compressed with zstd needs `--features
c-backed`; the pure tier refuses both directions as `Unsupported` (exit 3),
because the `zip` crate's own `zstd` feature is the one path into a
C-compiling dependency (`zstd-sys`). Every other entry codec `zip`
supports — store, deflate, bzip2, LZMA, xz — reads and writes on the pure
tier. This is a real orthogonality gap: `zip`'s own per-entry codec set is
not routed through stuffr's own codec registry, so it does not inherit
stuffr's pure/c-backed split codec-by-codec the way the top-level formats
do (see [OUT-OF-SCOPE.md](OUT-OF-SCOPE.md) for the wishlist item to fix
this).

There is also one granular feature per format, so a dependent can take
`stuffr = { default-features = false, features = ["zip", "zstd"] }` and compile
almost nothing. `stuffr formats` always reports what *this* build actually has.

## Layout

Library-first: the crate is the product, the binary is a consumer of it.

```
crates/
├── stuffr-core/      # traits, stream ladder, fidelity, governor, registry.
│                     #   Zero format dependencies — the tricky logic is
│                     #   testable against mocks, with no C toolchain.
├── stuffr-formats/   # every codec and container impl, one per module,
│                     #   each behind its own feature
├── stuffr/           # facade: re-exports core + formats, owns the feature
│                     #   taxonomy. The `cargo add` target.
└── stuffr-cli/       # the `stuffr` binary
```

The binary is `stuffr`, built from the `stuffr-cli` crate. Command and crates
agree, which they did not before this project was renamed: the `stuffr-*` crate
names originally existed only because `stf`, `stf-core` and `stf-cli` were
already taken on crates.io, and the command was `stf` to match them.

## Documentation

- **Design specification** — maintained outside this repository, alongside the
  implementation plans and session reports, and not currently published
- [CONTRIBUTING.md](CONTRIBUTING.md) — the development gate, commit convention,
  and the versioning policy with its milestone table
- [OUT-OF-SCOPE.md](OUT-OF-SCOPE.md) — deliberate exclusions, and the wishlist

## License

[MIT](LICENSE).

That covers this project's own code, with one exception inside it: the
compatibility links' bzip2 family (`crates/stuffr-cli/src/compat/bzip2/` and
`compat/bzip2recover/`) is ported from bzip2 1.0.8 and stays under Julian
Seward's bzip2 licence, reproduced in
[`crates/stuffr-cli/LICENSE-bzip2`](crates/stuffr-cli/LICENSE-bzip2). That
is why `stuffr-cli`'s licence metadata starts `MIT AND bzip2-1.0.6`. The bzip2
licence is a permissive BSD-style one: it asks that the notice be kept, the
origin not be misrepresented, and altered source be plainly marked as such.

Since `0.12.0` the gzip family's Apple personality is ported too, from Apple's
`gzip.c` and the decoders it carries (`unpack.c`, `unbzip2.c`, `unxz.c`,
`unlz.c`, `zuncompress.c`), and their notices are in
[`crates/stuffr-cli/LICENSE-gzip-bsd`](crates/stuffr-cli/LICENSE-gzip-bsd).
Since `0.13.0` the xz family is ported as well, from XZ Utils 5.8.4's
`src/xz/` and the liblzma sources behind `--list` and the memory figures, and
that code is **0BSD** (`crates/stuffr-cli/LICENSE-xz`; 0BSD asks for nothing
but is named so the origin is not lost).
Since `0.14.0` the zstd family is ported from zstd 1.5.7's `programs/`
(Meta Platforms, Inc.) under zstd's BSD licence, which is BSD-3-Clause
(`crates/stuffr-cli/LICENSE-zstd`), so the expression does not change. The
test fixture `crates/stuffr-cli/tests/fixtures/zstd_progress/gen.c` contains
verbatim zstd source (`UTIL_makeHumanReadableSize` from `programs/util.c`),
also BSD and covered by `LICENSE-zstd`.
The lz4 family (`0.15.0`) is not a port: lz4's CLI is GPL-2.0-or-later and was
**not read**, so `crates/stuffr-cli/src/compat/lz4/` is a clean-room
implementation from lz4's documentation and the behaviour of the 1.10.0
binary, and is MIT. On the `lz4-c` tier liblz4 1.10.0 is linked, under its
BSD-2-Clause licence (`crates/stuffr-cli/LICENSE-lz4`), already in the
expression below.
Since `0.16.0` the unzip family is ported from Info-ZIP UnZip 6.0 (Apple's
`zip-33` tree, and Debian's patch series for the Ubuntu flavour, both under
the same licence) and stays under the **Info-ZIP licence**, version
2009-Jan-02 ([`crates/stuffr-cli/LICENSE-infozip`](crates/stuffr-cli/LICENSE-infozip)).
Its clause 3 asks that an altered version be plainly marked and never
presented as an Info-ZIP release, which is why the family's banner lines
name stuffr and say "altered".
Since `0.19.0` the zip family is ported from Info-ZIP Zip 3.0 (Apple's
`zip-33` tree, and Debian's patch series for the Ubuntu flavour) and is under
the same **Info-ZIP licence**; the banner lines name stuffr and say "altered"
as for unzip.
Since `0.20.0` the brotli family is ported from brotli 1.2.1's
`c/tools/brotli.c` (MIT), with libbrotli 1.2.1 vendored under `brotli-c`; the
notice is `crates/stuffr-cli/LICENSE-brotli`, and the expression is unchanged.
Since `0.18.0` the compress family is ported too: Apple's `compress.c` and
`zopen.c` (the Regents of the University of California's BSD-3-Clause, already
in the expression; notice in
[`crates/stuffr-cli/LICENSE-compress-bsd`](crates/stuffr-cli/LICENSE-compress-bsd)),
and ncompress 5.0's `compress.c`, which is in the public domain under the
**Unlicense**
([`crates/stuffr-cli/LICENSE-ncompress`](crates/stuffr-cli/LICENSE-ncompress)).
`stuffr-cli`'s full expression is therefore
**`MIT AND bzip2-1.0.6 AND BSD-2-Clause AND BSD-3-Clause AND 0BSD AND Info-ZIP AND Unlicense`**:
the BSD-2-Clause covers `gzip.c` and the decoders, the BSD-3-Clause covers
`zuncompress.c`, the University of California's `.Z` reader, and the zstd
family; the 0BSD covers the xz family; Info-ZIP covers the unzip and zip families; the
Unlicense covers the ncompress personality. One notice is
BSD-style but not word for word the SPDX `BSD-2-Clause` text: the Lzd one in
`unlz.c`. The full notice ships in `LICENSE-gzip-bsd`, and that file, not the
SPDX name, is what to read. `stuffr-formats` is
**`MIT AND BSD-2-Clause AND 0BSD AND BSD-3-Clause AND Info-ZIP`**,
because its pack decoder (`pack.rs`) is a port of FreeBSD's `unpack.c` (Xin LI), whose notice is
[`crates/stuffr-formats/LICENSE-unpack-bsd`](crates/stuffr-formats/LICENSE-unpack-bsd),
and since `0.13.0` its liblzma memory-usage formulas and container coders
(the pure xz tier) are ported from XZ Utils 5.8.4 under 0BSD, notice in
`crates/stuffr-formats/LICENSE-xz-memusage`, and since `0.14.0` zstd
1.5.7's default compression-parameter table (`clevels.h`, Meta Platforms,
Inc.) is ported under zstd's BSD licence, notice in
`crates/stuffr-formats/LICENSE-zstd-clevels`, and since `0.16.0` Info-ZIP
UnZip 6.0's decoders (`crypt.c`, `inflate.c`, `explode.c`, `unshrink.c`,
in `src/infozip/`) are ported under the Info-ZIP licence, notice in
[`crates/stuffr-formats/LICENSE-infozip`](crates/stuffr-formats/LICENSE-infozip).
`stuffr` and `stuffr-core` are MIT. On the `c-backed` tier zlib is built too,
under the `Zlib` licence (also permissive); the default pure tier does not
contain it.

Neither licence extends to dependencies, and two are worth naming.

`lzma-rust2`, which provides the pure-Rust xz, LZMA1 and LZIP backends, is
**Apache-2.0**. It is the first non-MIT dependency in a *default* build — until
Phase 1e, only the opt-in `c-backed` tier carried a licence caveat. Apache-2.0 is
permissive and compatible, but a downstream consumer auditing licences should
know it is there without having to read the lockfile. Since Phase 2, two
versions of it build side by side — this project's own 0.20.1, and 0.16.5
pulled in transitively by the `zip` dependency (pinned `^0.16.1`) for its own
LZMA entry support. No new crate and no new licence, just a real duplicate in
the tree (`cargo tree -p stuffr --all-features -i lzma-rust2` shows both).

The `unrar` feature, if enabled, links a library whose upstream license permits
decompression only and forbids using the source to build a RAR compressor. A
build with `--features c-backed` is therefore not wholly MIT, which is one reason
that feature is opt-in rather than default.
