# Damaged archives for `zip -F` / `zip -FF`

Inputs for `compat_zip_bytes::fix_modes_match_the_reference` (0.19.0 Task 8).
Every archive here was made on 2026-10-26 by Apple's `/usr/bin/zip` (Zip 3.0,
macOS 27.0.1) over the measurement record's standard tree (`a.txt` =
`hello\n`, `b.txt` = 50 lines `line N of the b file, some text to compress\n`,
`d/c.txt` = `c\n`, every mtime `touch -t 200109090146.40` under `TZ=UTC`),
with `LANG=C TZ=UTC`, then damaged by a few lines of Python as stated. Unless
said otherwise they were made with `-X`, so they hold no extra field and no
user or group id, and are the same bytes whichever machine reads them.

| File | How it was made | SHA-256 |
|---|---|---|
| `intact.zip` | `zip -X t.zip a.txt b.txt d/c.txt` (462 bytes; central directory at 285, end record at 440) | `b418ced9bbcf4f3d0cffbb3286fbe9db7cac767acad5b5ecd9d623e6ce744344` |
| `cut-central.zip` | the first 300 bytes of `intact.zip`: cut 15 bytes into the first central header, no end record | `acebb3c4581bbe14996d8950ba58293ce20f4d812c7385c2727f5e98b643143a` |
| `cut-data.zip` | the first 200 bytes of `intact.zip`: cut inside `b.txt`'s data | `eaca3e828230e5f98a8f95fda40fc993d53dbe07941f6c9d757c695c56c57c62` |
| `bad-central.zip` | `intact.zip` with the second central header's signature (offset 0x150) made `PK\1\3` | `5ad0012da7da861f81be7d71e071d3998558a1a7c01b23f9239c5280f4d80e71` |
| `preamble.zip` | 100 bytes `x`, then `intact.zip` (its offsets not adjusted) | `a99f2503543dfb8d9b042d3984c5aeef4bb64eeeab0fa1f62a086332d1d14aca` |
| `descriptors.zip` | `zip -X -fd t.zip a.txt b.txt d/c.txt`: every entry deflated with a data descriptor (514 bytes) | `aa67d40b3fb08c847a6223f97f7dbccd4a555cadea30d6669e3457c7d996732a` |
| `descriptors-cut.zip` | the first 347 bytes of `descriptors.zip`: cut 10 bytes into the first central header | `ad5d8751b30c9137e16e332a5a20899c4812e5727eb985fd2fa753cbe05720b3` |
| `comment-cut.zip` | `intact.zip` with the end record's comment length made 50 and only `abc` after it | `93f933edb0f13c0085414efc4ccf4691bdea51e73ac267899167f605270b9785` |
| `junk.zip` | `intact.zip` with `JUNKJUNK` inserted after the first entry (offset 41) | `1786525efe947fc9f88cb6d1c30ae177e6c47006b274b9897814dda3cf4a55cd` |
| `bad-version.zip` | `intact.zip` with the first local header's version byte 5 (host system) made 50 | `f433e7416cf4d6fd7d9707fb1214fe9b72372af6d76b56f9da8aa225db6038e0` |
| `extra-cut.zip` | `zip x.zip a.txt b.txt` WITHOUT `-X` (local `UT` and `ux` fields; uid 501, gid 20), cut 20 bytes into the first central header | `9c841f28ff8cf5446a00593c02f77440265715f6e783c220a92f6c77e9cc9d3b` |

`extra-cut.zip` is the input of ruling Z19's pin (`-FF` copies a local extra
field into the central one with `strcpy`: Apple writes zeros after the first
NUL, Ubuntu heap garbage that changes run to run); it is not in the
differential on Ubuntu.

The split sets the tests need (`s.z01`, `s.z02`, `s.zip`, one part missing)
are made at test time by stuffr itself (`zip -X -s 64k` over 140000 bytes of
the harness's `random(_, 7)`), whose splits `splits_are_byte_identical`
compares with the reference's byte for byte.
