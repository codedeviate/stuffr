# stuffr-formats

Codec and container implementations for
[stuffr](https://github.com/codedeviate/stuffr), a universal compression and
archive toolkit. One module per format, each behind its own feature, each
registered into a [`stuffr-core`](https://crates.io/crates/stuffr-core)
`Registry`.

Most users want the [`stuffr`](https://crates.io/crates/stuffr) facade, which
re-exports this crate and owns the feature bundles.

## Coverage

**Codecs:** `gzip`, `zlib`, `deflate`, `bzip2`, `brotli`, `lz4`, `snappy`,
`zstd`, `xz`, `lzma` (LZMA1), `lzip`.

**Containers:** `tar`, `ar`, `cpio` (`newc` only — not odc, not crc),
`zip`/`zip64`.

Every codec is proven against `stuffr-core`'s twelve-property conformance
harness; every container against the analogous container harness.

## Backends and tiers

Three formats have two interchangeable backends, selected by feature and
mutually exclusive at registration (the C one wins when both are on):

| format | pure feature | C feature |
|---|---|---|
| `zstd` | `zstd-pure` (`ruzstd`) — decode; the encoder is weak and gated | `zstd-c` |
| `xz` | `xz-pure` (`lzma-rust2`) — read **and** write, ~1.4x slower encode | `xz-c` (`liblzma`) |
| `lzma` | `lzma-pure` | `lzma-c` |

`lzip` has only a pure implementation, at full ratio. The C features vendor and
statically build their own C source, so they need a C compiler and nothing else
— no libclang, no system liblzma.

## What the implementations guarantee

Malformed input reports as `io::ErrorKind::InvalidData` at the codec boundary,
whatever the backend emitted, so corruption stays distinguishable from a full
disk. Truncated and concatenated streams are detected rather than silently
decoding to a prefix — a defect this project has now found in five separate
upstream bindings. Decoding is incremental, and the pure LZMA-family decoders
bound their dictionary pre-flight against `DecodeOpts.memory_limit` rather than
trusting the size a file declares about itself.

## License

[MIT](LICENSE). `lzma-rust2`, behind the pure xz/LZMA1/LZIP backends, is
Apache-2.0.
