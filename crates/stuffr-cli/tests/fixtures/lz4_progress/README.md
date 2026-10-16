# lz4 progress fixtures

The differential suite cannot make standard error a terminal (ruling R10), so
the refresh gate and the terminal forms of lz4's progress line are pinned by
unit tests in `src/compat/lz4/display.rs` against these recordings. All come
from lz4 v1.10.0 (`/opt/homebrew/opt/lz4/bin/lz4`) under `LC_ALL=C`, with
standard error a pty, recorded by `record.py` (each line is `<ms since
start>`, a tab, and the `repr` of one read from the pty; the pty turns `\n`
into `\r\n`). Timestamps are what pin the refresh interval: the unit tests
check that no two refreshes are closer than 200 ms and that the gate, replayed
over the recorded times, draws exactly where the reference drew.

`bins` is 200000000 bytes of `cat /usr/bin/* /usr/lib/*.dylib
/opt/homebrew/lib/*.dylib | head -c 200000000` (executables: compressible at
every level, but slow enough at the high ones to show the gate). `a` and `b`
are 40 lines of "the quick brown fox jumps over the lazy dog".

| file | command | input |
|---|---|---|
| `compress_t1_12.rec` | `lz4 -f -v -T1 -12 bins bins.lz4` | `bins` |
| `compress_t1_9.rec` | `lz4 -f -v -T1 -9 bins bins.lz4` | `bins` |
| `compress_legacy_9.rec` | `lz4 -f -v -T1 -9 -l bins bins.l.lz4` | `bins` |
| `compress_vv_9.rec` | `lz4 -f -vv -T1 -9 bins bins.lz4` | `bins` (level 4 draws at every chunk: 48 of 48) |
| `decode_slow.rec` | `record.py out --slow 60 -- lz4 -f -v -dc bins.lz4` | `bins.lz4` from the `-12` run; standard output drained at 60 MB/s so that the decode takes seconds |
| `small_v.rec` | `lz4 -f -v -T3 a a.lz4` | `a`: a thread line, one refresh, summary, `Done in` |
| `small_m.rec` | `lz4 -f -v -m -T1 a b` | `a`, `b`: two summaries, the second file draws no refresh (the gate's clock spans the files), one `Done in` |
| `small_decode_m.rec` | `lz4 -f -v -d -m a.lz4 b.lz4` | the two outputs of `small_m`: one refresh, two summaries, `Done in` |

Re-record (macOS or Linux, with `LZ4=/path/to/lz4`):

```sh
python3 record.py compress_t1_12.rec -- $LZ4 -f -v -T1 -12 bins bins.lz4
```
