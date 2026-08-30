# stf

**stf** (pronounced *"stuff"*) is a universal compression and archive toolkit in
Rust — one library and one command for the whole format space, from `zstd` back
to `.arc`.

The name comes from *stuffing* things into a container. That metaphor has real
lineage here: **StuffIt** (`.sit`) was the dominant compressor on classic Mac OS
for the better part of fifteen years, and it is itself one of the formats on the
read list.

> **Status: Phase 1d complete — seven codecs, proven to coexist.** `stf pack`,
> `unpack`, `cat`, `info` and `formats` all work today, on files and through
> pipes, and `curl … | stf cat - | grep pattern` runs. `stf formats` lists
> `brotli`, `bzip2`, `deflate`, `gzip`, `lz4`, `snappy` and `zlib`, each proven
> individually against the ten-property conformance harness Phase 1c added, and
> then proven together: magic detection picks the right one out of seven
> (`gzip`, `zlib`, `bzip2`, `lz4`, `snappy` all carry magic bytes; `zlib` alone
> needs four rules, one per compression-level band), and `deflate` — which has
> neither magic nor an extension convention — is reachable only via
> `--format` and fails detection cleanly rather than being guessed at. 271
> tests, clean across build, clippy and fmt.
>
> **Not yet: the codecs that need a C toolchain, or a container.** `zstd`,
> `xz` and `LZMA1` arrive in Phase 1e; parallel encode and the version bump to
> `0.1.0` follow in Phase 1f; `tar`, `zip` and the rest of the container set
> are Phase 2. Nothing in the matrix below beyond the seven listed above is
> implemented yet.
>
> Already true and enforced for every codec: decoding is incremental rather
> than read-to-end, corruption is distinguishable from a full disk, output is
> fsynced before it is published and never destroys an existing file on
> failure, and `stuffr-core` carries zero format dependencies. The property
> that actually matters is **no C toolchain is required** — `cargo install`
> needs no `cc`, no `cmake`, nothing beyond `rustc` — not that the tree
> contains no `-sys` crate: it contains three (`libbz2-rs-sys`,
> `linux-raw-sys`, `windows-sys`), and all three are pure-Rust FFI
> declarations that link nothing.

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

So `curl … | stf cat - | grep pattern` works on a ZIP, on real data, and tells
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
for the seven codecs `stf formats` lists; `list`, `test`, `convert` and
`install-links`, and every container, are not implemented yet.*

```
stf pack     [-o out.tar.zst] [--format F] [--level N] PATHS...
stf unpack   [-C dir] ARCHIVE [PATTERNS...]
stf list     ARCHIVE                    # alias: ls
stf cat      ARCHIVE [PATTERNS...]      # streams entry data; works on a pipe
stf info     ARCHIVE                    # resolved chain, ladder rung, fidelity
stf formats                             # capability matrix for THIS build
stf test     ARCHIVE                    # integrity check, no extraction
stf convert  IN -o OUT                  # recompress without staging to disk
stf install-links --dir ~/.local/bin    # opt-in compat symlinks, never automatic
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

- **Modern codecs:** zstd, xz/LZMA2, LZMA1, brotli, lz4, snappy, gzip/zlib/deflate, bzip2
- **Containers:** tar, cpio, ar, zip/zip64, 7z, squashfs, ISO 9660, MS CAB, RAR *(read only)*
- **Plain storage:** collecting and compressing are separate axes — tar, cpio, ar, zip-stored and 7z-copy all give you a container with no compression
- **Legacy:** LHA/LZH, Unix `compress` `.Z`, `pack` `.z`, ARC, ARJ, ZOO, StuffIt `.sit` *(older methods)*, LZX

A few formats are read-only by **external constraint rather than effort** — RAR's
compressor is proprietary and the free `unrar` source is licensed for
decompression only; StuffIt's encoders are undocumented. Those are recorded in
[OUT-OF-SCOPE.md](OUT-OF-SCOPE.md) so the gap is documented rather than looking
like an oversight.

## Build tiers

Pure Rust is the default, so `cargo install` needs no C toolchain. Formats that
realistically require linking C — zstd and xz *encoders*, RAR — sit behind opt-in
features, and pure-Rust *decode-only* fallbacks cover the common case of merely
wanting to open the file.

| Feature | Contents |
|---|---|
| `pure` *(default)* | everything with a pure-Rust implementation |
| `c-backed` | `zstd-sys`, `liblzma`, `unrar` (decode) |
| `legacy` | the historical format set |
| `full` | all of the above |

There is also one granular feature per format, so a dependent can take
`stuffr = { default-features = false, features = ["zip", "zstd"] }` and compile
almost nothing. `stf formats` always reports what *this* build actually has.

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
└── stuffr-cli/       # the `stf` binary
```

Crates are published as `stuffr-*` because `stf`, `stf-core` and `stf-cli` are
already taken on crates.io. The command you type stays `stf`.

## Documentation

- **Design specification** — `~/Development/Thomas/superpowers/stf/specs/2026-08-25-stf-compression-tool-design.md`
  (kept outside this repository, alongside the plans and session reports)
- [CONTRIBUTING.md](CONTRIBUTING.md) — the development gate, commit convention,
  and the versioning policy with its milestone table
- [OUT-OF-SCOPE.md](OUT-OF-SCOPE.md) — deliberate exclusions, and the wishlist

## License

[MIT](LICENSE).

That covers this project's own code. It does **not** extend to optional
dependencies: the `unrar` feature, if enabled, links a library whose upstream
license permits decompression only and forbids using the source to build a RAR
compressor. A build with `--features c-backed` is therefore not wholly MIT,
which is one reason that feature is opt-in rather than default.
