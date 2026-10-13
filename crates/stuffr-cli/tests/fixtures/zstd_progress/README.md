# zstd progress fixtures

The differential suite cannot make standard error a terminal (ruling R4), so
the forms of zstd's progress line when it is one are pinned by unit tests in
`src/compat/zstd/display.rs` against these files. All come from zstd 1.5.7
(`/opt/homebrew/opt/zstd/bin/zstd`, `*** Zstandard CLI (64-bit) v1.5.7`)
under `LC_ALL=C`.

## `table.txt`: fileio.c's own printf layouts over fixed counters

`rows.txt` is the input (one record per line, fields documented at the top of
`gen.c`); `table.txt` is `gen.c`'s output for it:

```
cc -o gen gen.c && ./gen < rows.txt > table.txt
```

`gen.c` holds `UTIL_makeHumanReadableSize` verbatim from zstd 1.5.7
`programs/util.c` and the layouts of `FIO_compressZstdFrame`'s "display
notification" and `FIO_decompressZstdFrame`'s `DISPLAYUPDATE_PROGRESS`,
statement for statement. Each output line is the record, a tab, and the bytes
zstd writes for that refresh (`\r` and `\n` escaped). The rows cover display
levels 2, 3 and 4, one file and several, known and unknown sizes, names under,
at and over 18 and 20 bytes, and the unit boundaries. The unit test
`every_table_row_is_the_references_bytes` renders every row with the port and
compares bytes.

## `*.raw`: real terminal runs

Recorded with `record.py`, which runs the reference with standard error on a
pseudo-terminal (the tty's `\n` -> `\r\n` translation switched off, so the
bytes are the program's own) and writes what it wrote to standard error.
Inputs: two 24 MiB files of pseudo-random lowercase words (`one.txt`,
`report-2024-final.txt`; seed 7), compressed at `-19` so there are several
refreshes. The counters differ from run to run (the refresh is on a clock),
so these pin the *shape* of every refresh line, not its figures:

| file | command (in the directory of the inputs) |
|---|---|
| `c1_default.raw` | `zstd -19 -f -k one.txt -o one.zst` |
| `c1_v.raw` | `zstd -v -19 -f -k one.txt -o one.zst` |
| `cn_default.raw` | `zstd -19 -f -k one.txt report-2024-final.txt` |
| `d1_default.raw` | `zstd -d -f -k one.txt.zst -o dd.txt` |
| `dn_default.raw` | `zstd -d -f -k one.txt.zst report-2024-final.txt.zst` |

e.g. `python3 -I record.py c1_default.raw DIR /opt/homebrew/opt/zstd/bin/zstd -19 -f -k one.txt -o one.zst`.
The unit test `recorded_terminal_runs_have_the_ports_shapes` reduces each
chunk (digits to `9`, blanks collapsed, units to `U`) and requires it to be
one of the port's renderings of the same form.
