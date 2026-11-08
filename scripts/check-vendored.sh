#!/bin/sh
# Verify the vendored C sources under crates/stuffr-formats/c are
# byte-identical to upstream's archives (pins in
# crates/stuffr-formats/c/VENDORED.md): libbrotli 1.2.1 and liblz4 1.11.0.
# Exit 0 when identical, 1 on any difference or a hash mismatch.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
c="$root/crates/stuffr-formats/c"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

# fetch <url> <sha256> <file>: download and verify.
fetch() {
    curl -fsSL --retry 3 -o "$work/$3" "$1"
    if command -v sha256sum >/dev/null 2>&1; then
        got=$(sha256sum "$work/$3" | cut -d' ' -f1)
    else
        got=$(shasum -a 256 "$work/$3" | cut -d' ' -f1)
    fi
    if [ "$got" != "$2" ]; then
        echo "check-vendored: $3 sha256 $got, expected $2" >&2
        exit 1
    fi
}

status=0

# libbrotli 1.2.1
fetch https://github.com/google/brotli/archive/refs/tags/v1.2.1.tar.gz \
    98d35d11a78dc453aebb7d10c3748f3f73ff78c8267c0dc697b8631f67bf7e8f brotli.tar.gz
tar -xzf "$work/brotli.tar.gz" -C "$work"
up="$work/brotli-1.2.1"
vendored="$c/brotli-1.2.1"
brotli=0
for d in common dec enc include; do
    diff -r -x stuffr-prefix.h "$up/c/$d" "$vendored/$d" || brotli=1
done
cmp "$up/LICENSE" "$vendored/LICENSE" || brotli=1
# stuffr-prefix.h is ours (generated), not upstream's; it is exempt.
# Nothing extra may sit in the vendored tree either.
extra=$(cd "$vendored" && find . -type f | grep -vE '^\./(common|dec|enc|include)/|^\./(LICENSE|stuffr-prefix\.h)$' || true)
if [ -n "$extra" ]; then
    echo "check-vendored: files not from upstream: $extra" >&2
    brotli=1
fi
[ "$brotli" -eq 0 ] && echo "check-vendored: brotli-1.2.1 matches upstream v1.2.1"
[ "$brotli" -eq 0 ] || status=1

# liblz4 1.11.0: only lib/ is extracted (programs/ is GPL and never read).
fetch https://github.com/lz4/lz4/releases/download/v1.11.0/lz4-1.11.0.tar.gz \
    247e5fa64da5f7b75ee3dd3bed484076396c9ebe8254d9ccf693eb62800c5e26 lz4.tar.gz
tar -xzf "$work/lz4.tar.gz" -C "$work" 'lz4-1.11.0/lib/*'
up="$work/lz4-1.11.0/lib"
vendored="$c/lz4-1.11.0"
lz4=0
files="LICENSE lz4.c lz4.h lz4hc.c lz4hc.h lz4frame.c lz4frame.h lz4frame_static.h xxhash.c xxhash.h"
for f in $files; do
    cmp "$up/$f" "$vendored/$f" || lz4=1
done
allowed=$(printf '%s\n' $files stuffr-prefix.h)
extra=$(cd "$vendored" && find . -type f | sed 's|^\./||' | grep -vxF "$allowed" || true)
if [ -n "$extra" ]; then
    echo "check-vendored: files not from upstream: $extra" >&2
    lz4=1
fi
[ "$lz4" -eq 0 ] && echo "check-vendored: lz4-1.11.0 matches upstream v1.11.0 lib/"
[ "$lz4" -eq 0 ] || status=1

exit "$status"
