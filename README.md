# stuffr

**stuffr** (pronounced *"stuff"*) is a universal compression and archive toolkit in
Rust — one library and one command for the whole format space, from `zstd` back
to `.arc`.

The name comes from *stuffing* things into a container. That metaphor has real
lineage here: **StuffIt** (`.sit`) was the dominant compressor on classic Mac OS
for the better part of fifteen years, and it is itself one of the formats on the
read list.

> **Status: Phase 3c in progress at `0.4.1` — eleven round-trip codecs and
> four round-trip containers, plus five read-only legacy formats, all in the
> default build, which needs no C toolchain to read *or write* xz, LZMA1 or
> LZIP.** `stuffr pack`,
> `unpack`, `cat`, `info`, `list`, `test` and `formats` all work, on files
> and through pipes, and `curl … | stuffr cat - | grep pattern` runs.
> `stuffr formats` lists codecs `brotli`, `bzip2`, `compress`, `deflate`,
> `gzip`, `lz4`, `lzip`, `lzma`, `snappy`, `xz`, `zlib`, `zstd` and containers
> `ar`, `arc` (`.pak` included), `arj`, `cpio`, `lha` (`.lzh` included),
> `tar`, `zip` (`zip64` included), `zoo` on every build — each round-trip codec and container proven
> against the conformance harness Phase 1c introduced and later cycles grew
> to twelve properties, and each read-only legacy format proven against a
> fixture-driven variant of the same harnesses, built for exactly this shape
> (see the Phase 3b paragraphs below), all of it then proven to coexist. The
> `legacy` feature (bundled into `full`/`--all-features`) still exists and
> still works — it is what `--no-default-features --features pure` would
> otherwise lack, not something a default build needs to opt into. **1007**
> tests under `--all-features`, **942** on the default tier — a different
> set, not a subset, because the two tiers select different backends.
> (The previous figures here, 963/898, were stale by two: the gate's own
> output read 965/900 before ZOO landed. Both counts are measured from
> `make check`'s two `cargo test` runs, not carried forward.) Clean
> across build, clippy and fmt.
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
> an entry, since `list` reads no payload in any container). `cpio` and
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
> zip 8.6.0 cannot forward-read entries written with data descriptors —
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
> are decode-only by construction, not by a missing feature: there never was
> a `compress` encoder here, and `lha`/`arj` read archives the real,
> decades-old `lha`/`lhasa` and `arj`/`unarj` tools wrote. `stuffr pack
> --format lha` (or `arj`, or `compress`) refuses at **exit 3**, naming the
> format read-only in this build, rather than failing obscurely.
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
> coarser bound there than on the other five containers, and a fixed 256 MiB
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
> for the full, per-fixture provenance.
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
cargo install stuffr-cli --features c-backed    # needs a C compiler, nothing else
```

The five read-only legacy formats (Unix `compress` `.Z`, LHA/LZH, ARJ,
ARC/PAK, ZOO) are in the default build too, pure Rust like the rest of it — no
extra flag needed.
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

*Phase 2 and later. `pack`, `unpack`, `cat`, `info`, `formats`, `list` and
`test` all work today, across the eleven round-trip codecs and four
round-trip containers
(`ar`, `cpio`, `tar`, `zip`/`zip64`) `stuffr formats` lists — `pack`/`unpack`/
`cat` are entry-aware for every container, with extraction-time path
containment and bomb limits on by default. `convert` and `install-links`
are not implemented yet. `pack` walks a directory tree, and
`pack -o bundle.tar.gz` composes a container on top of a codec in one pass.*

```
stuffr pack     [-o out.tar.zst] [--format F] [--level N] PATHS...
stuffr unpack   [-C dir] ARCHIVE [PATTERNS... | --index N...]
stuffr list     ARCHIVE                    # alias: ls; first column is the index
stuffr cat      ARCHIVE [PATTERNS... | --index N...]  # entry data; works on a pipe
stuffr info     ARCHIVE                    # resolved chain, ladder rung, fidelity
stuffr formats                             # capability matrix for THIS build
stuffr test     ARCHIVE                    # integrity check, no extraction
stuffr convert  IN -o OUT                  # recompress without staging to disk
stuffr install-links --dir ~/.local/bin    # opt-in compat symlinks, never automatic
```

`ARCHIVE` accepts `-` for stdin everywhere. Optional compat symlinks
argv[0]-dispatch into the same code, so `gzip`, `gunzip`, `zcat`, `bzip2`, `xz`,
`zstd`, `unzip` and friends drop into existing scripts unchanged.

### Two safety defaults that are not negotiable

"Extract this untrusted archive" is the most exploited operation in this whole
domain, so:

- **Path containment.** Absolute paths, `..` traversal, and symlinks escaping the
  destination are **refused, not silently sanitised**. So is an entry whose path
  runs *through* a symlink: `a/b/up -> ..` followed by `a/b/up/link -> ../..` is
  contained when each name is resolved component-wise and still lands outside the
  destination once the OS resolves it, so the extractor also refuses any entry
  with a symlinked path component (libarchive's `SECURE_SYMLINKS` shape, refused
  rather than quietly unlinked).
- **Bomb limits.** Default caps on total output and expansion ratio, so a 42 KB
  zip that expands to 4.5 PB fails fast instead of filling the disk. The error
  names the entry that tripped it.

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
- **Legacy:** LHA/LZH, Unix `compress` `.Z` and ARJ *(read-only, Phase 3b, part of the default build — `--features legacy` still exists for a `--no-default-features` build)*, joined by **ARC/PAK** and **ZOO** *(read-only, Phase 3c, their framing and decoders written from scratch)*. **Phase 3c** adds two things and it is worth saying which: WRITE support for exactly the first three (`pack --format lha`/`arj`/`compress`, which today refuse at exit 3), and READ support for **ARC and ZOO** — both have now landed. StuffIt `.sit` *(older methods only)* and Amiga/MS LZX are **3c candidates too**, gated on evidence rather than effort: neither has a second implementation or a tool to check a fixture against, so a fixture and its expectation would both come from the crate under test. StuffIt `.sitx` and its later methods stay permanently out — see [OUT-OF-SCOPE.md](OUT-OF-SCOPE.md)

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
| `pure` *(default)* | everything with a pure-Rust implementation — all eleven codecs, including read+write xz, LZMA1 and LZIP, plus all four containers |
| `c-backed` | `zstd-sys` and `liblzma`, both vendored and built statically; also the one entry codec inside `zip` that needs a C-compiling crate (see below); later `unrar` (decode) |
| `legacy` *(default)* | the historical format set — `compress`, `lha`, `arj`, `arc`, `zoo`; READ-ONLY |
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

That covers this project's own code. It does **not** extend to dependencies, and
two are worth naming.

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
