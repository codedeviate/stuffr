# stuffr-cli

The `stuffr` command — a universal compression and archive toolkit in Rust, one
command for the whole format space.

## Install

The binary is called `stuffr`, but it is built from the **`stuffr-cli`**
package, so that is the name `cargo install` needs:

```sh
cargo install stuffr-cli        # installs the `stuffr` binary
```

`cargo install stuffr` does **not** work — `stuffr` is the library crate and has
no binary target. (Same arrangement as ripgrep's `ripgrep` / `rg`.)

The default build is pure Rust and needs no C toolchain. To link the two
vendored C backends instead — a faster xz/LZMA encoder and a strong zstd
encoder:

```sh
cargo install --locked stuffr-cli --features c-backed    # needs a C compiler, nothing else
```

`--locked` keeps the vendored C libraries at the versions the compatibility
links promise (libzstd 1.5.7, liblz4 1.10.0); without it, cargo may resolve
newer `-sys` crates.

The five legacy formats (Unix `compress` `.Z`, LHA/LZH, ARJ, ARC/PAK, ZOO)
are in the default build too, pure Rust like the rest of it — no extra flag
needed. `compress`, `lha` and `arj` read AND write as of Phase 3c (`lha` reads
seven compression methods and writes `-lh5-`; `arj` reads five and writes only
the uncompressed one, so an ARJ archive stuffr writes is larger than its
input — and nothing outside this project has ever read one, since no
`arj`/`unarj` tool is obtainable); `arc` and `zoo` are read-only
and refuse `pack --format <name>` at exit 3.
`--features legacy` still exists and still works; it only matters paired with
`--no-default-features` (e.g. `--no-default-features --features pure`, the
build the `purity` CI job checks, is the one combination that excludes them).

## Use

```sh
stuffr pack proj -o backup.tar.gz       # walk a directory, container over codec
stuffr list backup.tar.gz               # index, mode, size, name
stuffr unpack backup.tar.gz -C out/     # path containment and bomb limits on by default
stuffr cat logs.tar.zst app.log         # stream one entry to stdout
stuffr info archive.xz                  # resolved chain, ladder rung, fidelity
stuffr test archive.zip                 # integrity check, no extraction
stuffr formats                          # capability matrix for THIS build
stuffr --examples                       # worked examples for every verb
```

`-` means stdin everywhere, so `curl … | stuffr cat - | grep pattern` works.

Twelve codecs — `gzip`, `zlib`, `deflate`, `bzip2`, `brotli`, `lz4`,
`snappy`, `zstd`, `xz`, `lzma`, `lzip` and Unix `compress` (`.Z`), all
round-trip — and eight containers: `tar`, `ar`, `cpio` (`newc` only),
`zip`/`zip64`, `lha` and `arj` are six round-trip containers, and `arc`/PAK
and `zoo` are two read-only containers. That is what a plain
`cargo install stuffr-cli` gives you; `stuffr formats` prints the matrix for
the build you actually have.

Invoked as `bzip2`, `bunzip2`, `bzcat`, `bzip2recover`, `gzip`, `gunzip`,
`zcat`, `gzcat`, `xz`, `unxz`, `xzcat`, `lzma`, `unlzma`, `lzcat`, `zstd`,
`unzstd`, `zstdcat`, `zstdmt`, `lz4`, `unlz4`, `lz4cat`, `lz4c`, `unzip`,
`zipinfo`, `funzip`, `compress` or `uncompress`, the binary behaves as that
tool, byte for byte on stdout, stderr and exit codes (twenty-seven names;
`unzip -Z` is `zipinfo`).
`stuffr install-links --dir DIR` makes the links, and nothing makes them for
you. The gzip names follow the platform (GNU gzip, or
Apple's on macOS and the BSDs); `STUFFR_GZIP_FLAVOR=gnu|bsd` overrides that.
The unzip names are Info-ZIP UnZip 6.00 in Apple's or Ubuntu's build, the same
way; `STUFFR_UNZIP_FLAVOR=apple|ubuntu` overrides that.
The compress names are Apple's `compress` (487.0.1) on macOS and the BSDs and
ncompress 5.0 elsewhere; `STUFFR_COMPRESS_FLAVOR=apple|ncompress` overrides that.

Full documentation, including the safety defaults and the two build tiers, is in
the [project README](https://github.com/codedeviate/stuffr#readme).

## License

[MIT](LICENSE), with ported code under other permissive licences: the crate's
metadata is
`MIT AND bzip2-1.0.6 AND BSD-2-Clause AND BSD-3-Clause AND 0BSD AND Info-ZIP AND Unlicense`.
The notices ship as `LICENSE-bzip2`, `LICENSE-gzip-bsd`, `LICENSE-xz`,
`LICENSE-zstd`, `LICENSE-lz4`, `LICENSE-infozip`, `LICENSE-compress-bsd` and
`LICENSE-ncompress`. The lz4 family ports nothing (lz4's CLI is
GPL-2.0-or-later and was not read; it is a clean-room implementation from lz4's
documentation and behaviour); `LICENSE-lz4` is liblz4's BSD-2-Clause notice,
for the `lz4-c` tier that links it. The unzip family is ported from Info-ZIP
UnZip 6.0 (Apple's `zip-33` tree, with Debian's patches for the Ubuntu
flavour) under the Info-ZIP licence, `LICENSE-infozip`; it is an altered
version, not an Info-ZIP release. The compress family is ported from Apple's
`compress.c` and `zopen.c` (`LICENSE-compress-bsd`, BSD-3-Clause) and from
ncompress 5.0 (`LICENSE-ncompress`, the Unlicense).
