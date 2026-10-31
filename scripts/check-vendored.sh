#!/bin/sh
# Verify crates/stuffr-formats/c/brotli-1.2.1 is byte-identical to upstream's
# v1.2.1 archive (pins in crates/stuffr-formats/c/VENDORED.md). Exit 0 when
# identical, 1 on any difference or a hash mismatch.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
url=https://github.com/google/brotli/archive/refs/tags/v1.2.1.tar.gz
sha256=98d35d11a78dc453aebb7d10c3748f3f73ff78c8267c0dc697b8631f67bf7e8f
vendored="$root/crates/stuffr-formats/c/brotli-1.2.1"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
curl -fsSL --retry 3 -o "$work/brotli.tar.gz" "$url"
if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$work/brotli.tar.gz" | cut -d' ' -f1)
else
    got=$(shasum -a 256 "$work/brotli.tar.gz" | cut -d' ' -f1)
fi
if [ "$got" != "$sha256" ]; then
    echo "check-vendored: archive sha256 $got, expected $sha256" >&2
    exit 1
fi
tar -xzf "$work/brotli.tar.gz" -C "$work"
up="$work/brotli-1.2.1"
status=0
for d in common dec enc include; do
    diff -r "$up/c/$d" "$vendored/$d" || status=1
done
cmp "$up/LICENSE" "$vendored/LICENSE" || status=1
# Nothing extra may sit in the vendored tree either.
extra=$(cd "$vendored" && find . -type f | grep -vE '^\./(common|dec|enc|include)/|^\./LICENSE$' || true)
if [ -n "$extra" ]; then
    echo "check-vendored: files not from upstream: $extra" >&2
    status=1
fi
[ "$status" -eq 0 ] && echo "check-vendored: brotli-1.2.1 matches upstream v1.2.1"
exit "$status"
