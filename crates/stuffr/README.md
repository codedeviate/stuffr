# stuffr

Universal compression and archive toolkit for Rust — the **library** facade.
It re-exports [`stuffr-core`](https://crates.io/crates/stuffr-core) and
[`stuffr-formats`](https://crates.io/crates/stuffr-formats) and owns the feature
taxonomy, so this is the crate to `cargo add`.

## Looking for the command?

> **This crate has no binary.** `cargo install stuffr` fails with "no binaries".
> The `stuffr` command is built from the **`stuffr-cli`** package:
>
> ```sh
> cargo install stuffr-cli        # installs the `stuffr` binary
> ```
>
> (Same arrangement as ripgrep's `ripgrep` / `rg`.)

## Library use

```sh
cargo add stuffr
```

`stuffr::registry()` is the entry point: it returns the set of formats *this*
build was compiled with, which is how a caller tells a missing feature flag from
a corrupt file. `stuffr::ops` drives whole-stream compress/decompress/probe, and
`stuffr::entries` drives the container verbs (list, extract, pack) with path
containment and bomb limits on by default.

Eleven codecs (`gzip`, `zlib`, `deflate`, `bzip2`, `brotli`, `lz4`, `snappy`,
`zstd`, `xz`, `lzma`, `lzip`) and four containers (`tar`, `ar`, `cpio` — `newc`
only — and `zip`/`zip64`), each behind its own feature. Codec and container are
separate axes; a stream that cannot seek is escalated up a ladder (in-memory,
then spooled to disk) and the cost of that escalation is reported rather than
hidden.

## Features

| Feature | Contents |
|---|---|
| `pure` *(default)* | everything with a pure-Rust implementation — all eleven codecs, including read **and write** xz, LZMA1 and LZIP, plus all four containers. No C toolchain. |
| `c-backed` | `zstd-sys` and `liblzma`, both vendored and built statically; needs a C compiler and nothing else — no libclang, no system liblzma |

The only capability difference between the tiers is zstd's *encoder*: a default
build writes `.zst` only behind `--allow-weak-encoder`. Individual formats can
also be selected one at a time (`features = ["zstd-c"]`).

Full documentation is in the
[project README](https://github.com/codedeviate/stuffr#readme).

## License

[MIT](LICENSE). Note that `lzma-rust2`, which provides the pure-Rust xz, LZMA1
and LZIP backends, is Apache-2.0 — the one non-MIT dependency in a default
build.
