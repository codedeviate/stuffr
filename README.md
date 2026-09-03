# stuffr

**stuffr** (pronounced *"stuff"*) is a universal compression and archive toolkit in
Rust — one library and one command for the whole format space, from `zstd` back
to `.arc`.

The name comes from *stuffing* things into a container. That metaphor has real
lineage here: **StuffIt** (`.sit`) was the dominant compressor on classic Mac OS
for the better part of fifteen years, and it is itself one of the formats on the
read list.

> **Status: Phase 1 complete at `0.1.0` — eleven codecs, three of them
> parallel on request, and a default build that needs no C toolchain to read
> *or write* xz, LZMA1 or LZIP.** `stuffr pack`, `unpack`, `cat`, `info` and
> `formats` all work, on files and through pipes, and
> `curl … | stuffr cat - | grep pattern` runs. `stuffr formats` lists `brotli`,
> `bzip2`, `deflate`, `gzip`, `lz4`, `lzip`, `lzma`, `snappy`, `xz`, `zlib` and
> `zstd`, each proven against the conformance harness Phase 1c introduced and
> later cycles grew to twelve properties, and then proven to coexist. 487
> tests under `--all-features`, 421 on the default tier — a different set, not
> a subset, because the two tiers select different backends. Clean across
> build, clippy and fmt.
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
> **Not yet: containers.** `tar`, `zip` and the rest are Phase 2. Nothing in
> the matrix below beyond the eleven codecs above is implemented.
>
> Already true and enforced for every codec: decoding is incremental rather
> than read-to-end, corruption is distinguishable from a full disk, truncation
> and concatenated streams are detected rather than silently truncating, output
> is fsynced before it is published and never destroys an existing file on
> failure, and `stuffr-core` carries zero format dependencies.

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

*Phase 1 and later. `pack`, `unpack`, `cat`, `info` and `formats` work today,
for the eleven codecs `stuffr formats` lists; `list`, `test`, `convert` and
`install-links`, and every container, are not implemented yet.*

```
stuffr pack     [-o out.tar.zst] [--format F] [--level N] PATHS...
stuffr unpack   [-C dir] ARCHIVE [PATTERNS...]
stuffr list     ARCHIVE                    # alias: ls
stuffr cat      ARCHIVE [PATTERNS...]      # streams entry data; works on a pipe
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
  destination are **refused, not silently sanitised**.
- **Bomb limits.** Default caps on total output and expansion ratio, so a 42 KB
  zip that expands to 4.5 PB fails fast instead of filling the disk. The error
  names the entry that tripped it.

## Planned format coverage

Read and write symmetry wherever it is technically possible.

- **Modern codecs:** zstd, xz/LZMA2, LZMA1, LZIP, brotli, lz4, snappy, gzip/zlib/deflate, bzip2
- **Containers:** tar, cpio, ar, zip/zip64, 7z, squashfs, ISO 9660, MS CAB, RAR *(read only)*
- **Plain storage:** collecting and compressing are separate axes — tar, cpio, ar, zip-stored and 7z-copy all give you a container with no compression
- **Legacy:** LHA/LZH, Unix `compress` `.Z`, `pack` `.z`, ARC, ARJ, ZOO, StuffIt `.sit` *(older methods)*, LZX

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
| `pure` *(default)* | everything with a pure-Rust implementation — all eleven codecs, including read+write xz, LZMA1 and LZIP |
| `c-backed` | `zstd-sys` and `liblzma`, both vendored and built statically; later `unrar` (decode) |
| `legacy` | the historical format set |
| `full` | all of the above |

`c-backed` needs a C compiler and **nothing else** — no `libclang`, no system
liblzma. Both dependencies vendor their own C source: `zstd` does by default, and
`liblzma` is pinned with `default-features = false, features = ["static"]`
specifically so it never falls back to linking a system library via pkg-config,
which would succeed on a developer machine and fail on a clean one. A CI job
checks that the `pure` graph contains neither `zstd-sys` nor `liblzma-sys`.

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
know it is there without having to read the lockfile.

The `unrar` feature, if enabled, links a library whose upstream license permits
decompression only and forbids using the source to build a RAR compressor. A
build with `--features c-backed` is therefore not wholly MIT, which is one reason
that feature is opt-in rather than default.
