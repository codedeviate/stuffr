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
cargo install stuffr-cli --features c-backed    # needs a C compiler, nothing else
```

The three read-only legacy formats (Unix `compress` `.Z`, LHA/LZH, ARJ) are
opt-in too, and pure Rust like the default tier:

```sh
cargo install stuffr-cli --features legacy      # adds .Z, .lzh and .arj (read-only)
cargo install stuffr-cli --features full        # both of the above at once
```

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

Eleven codecs (`gzip`, `zlib`, `deflate`, `bzip2`, `brotli`, `lz4`, `snappy`,
`zstd`, `xz`, `lzma`, `lzip`) and four containers (`tar`, `ar`, `cpio` — `newc`
only — and `zip`/`zip64`).

Full documentation, including the safety defaults and the two build tiers, is in
the [project README](https://github.com/codedeviate/stuffr#readme).

## License

[MIT](LICENSE).
