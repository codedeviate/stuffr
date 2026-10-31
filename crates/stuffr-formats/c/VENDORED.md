# Vendored C sources

## libbrotli 1.2.1 (`brotli-1.2.1/`)

- **Upstream:** https://github.com/google/brotli, tag `v1.2.1`, commit
  `db24a98aed38a16de78cc05ca15cdd8dc2a0d92d`
- **Archive:** https://github.com/google/brotli/archive/refs/tags/v1.2.1.tar.gz
- **Archive SHA-256:** `98d35d11a78dc453aebb7d10c3748f3f73ff78c8267c0dc697b8631f67bf7e8f`
  (the same pin as `.github/actions/brotli-reference`)
- **Copied, unmodified:** `c/common`, `c/dec`, `c/enc`, `c/include`, `LICENSE`
- **Built by:** `crates/stuffr-formats/build.rs`, only under the `brotli-c` feature
- **Security:** 1.2.1 is the fix release for CVE-2026-111497 (out-of-bounds
  write in `c/dec/decode.c`, 1.0.3–1.2.0). Check upstream for newer security
  releases at every stuffr release.

`scripts/check-vendored.sh` downloads the archive, verifies the SHA-256 and
compares every copied file with this tree; CI's `supply-chain` job runs it.
To refresh: replace the directory from a new tag's archive, update the three
pins above (and the reference action's), and re-run the script.
