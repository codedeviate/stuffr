# xz progress fixtures

The differential suite cannot make standard error a terminal (Ruling R4),
so the terminal forms of xz's `-v` progress line, and the line a progress
signal asks for, are pinned by unit tests in
`src/compat/xz/message.rs` against these files. All come from XZ Utils
5.8.4 under `LC_ALL=C`.

## `table.txt`: message.c's own functions

`gen.c` holds message.c's `progress_percentage`, `progress_sizes`,
`progress_speed`, `progress_time` and `progress_remaining`, and util.c's
`uint64_to_nicestr`, copied verbatim from the 5.8.4 tree that
`liblzma-sys` 0.4.9 bundles (0BSD), with the line layouts of
`message_progress_update` and `progress_flush`. It prints, for each row of
counters and elapsed milliseconds, the five forms of the line:

| kind | what |
|---|---|
| `update` | message_progress_update's `\r...\r` line |
| `auto-finished` / `auto-unfinished` | progress_flush on a terminal |
| `plain-finished` / `plain-unfinished` | progress_flush elsewhere, for a file named `f` |

Columns: expected input size, input position, compressed, uncompressed,
elapsed (ms), kind, then the line with `\r`, `\n` and `\\` escaped.

Regenerate:

```sh
cc -O0 -o /tmp/xz-progress-gen gen.c && /tmp/xz-progress-gen > table.txt
```

## The recordings: the binary on a terminal

`record.sh` runs `/opt/homebrew/opt/xz/bin/xz` (or the `bin` directory it
is given) under `script(1)`, so that standard error is a terminal, with
`stty -onlcr` so that every byte is as xz wrote it, over inputs it makes
itself:

| file | command | input |
|---|---|---|
| `two_files.txt` | `xz -v -k a b` | `a` and `b`: "the quick brown fox jumps over the lazy dog\n" × 40 (1760 B) |
| `corrupt.txt` | `xz -dv -k cut.xz` | the first 100 bytes of `xz -c a` |
| `stdin.txt` | `xz -v < a > s.xz` | `a` |
| `files.txt` | `printf 'a\nb\n' \| xz -fkv --files` | `a`, `b` |
| `signals.txt` | `xz -9e -T1 -c big`, sent SIGUSR1 at 0.5 s and SIGALRM at 0.8 s | `big`: 20 MB of awk's `srand(1)` hex |

Each run but the last finishes in well under a second, so it prints no
speed or elapsed time and is compared byte for byte. `signals.txt`'s
figures depend on how far the run got, so only its shape (the name line,
then each signal's line on a line of its own) is compared.

Re-record (macOS; `script`'s arguments differ on Linux):

```sh
sh record.sh [/path/to/xz-5.8.4/bin]
```
