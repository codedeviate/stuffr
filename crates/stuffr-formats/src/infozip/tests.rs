//! Tests for the Info-ZIP decoder ports, one module per C file.

/// Reads `tests/data/infozip/<name>` at run time (ruling P8). The directory
/// is excluded from the published crate, so when it is absent entirely this
/// returns `None` with a note and the caller skips; when it exists but
/// `name` does not, that is a broken checkout, and this panics.
fn fixture(name: &str) -> Option<Vec<u8>> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/infozip");
    if !dir.is_dir() {
        eprintln!(
            "note: {} absent (a published crate); skipping {name}",
            dir.display()
        );
        return None;
    }
    let path = dir.join(name);
    Some(std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
}

/// The data of the first entry of `zip`, by its local header's `csize`.
fn first_entry_data(zip: &[u8]) -> &[u8] {
    assert_eq!(&zip[..4], b"PK\x03\x04", "not a local header");
    let csize = u32::from_le_bytes(zip[18..22].try_into().unwrap()) as usize;
    let name_len = usize::from(u16::from_le_bytes([zip[26], zip[27]]));
    let extra_len = usize::from(u16::from_le_bytes([zip[28], zip[29]]));
    let at = 30 + name_len + extra_len;
    &zip[at..at + csize]
}

/// SHA-256 (FIPS 180-4), small and slow, for the fixtures' digests (as
/// `lz4_opts`' tests have it).
fn sha256(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

mod crypt {
    use crate::infozip::crypt::{Keys, RAND_HEAD_LEN, test_key};

    // The expected values below come from crypt.c itself: `update_keys`,
    // `decrypt_byte` and `init_keys` copied from
    // $UZ_KEEP/unzip60/crypt.c (modulo the `__G` plumbing) over crc32.c's
    // `make_crc_table`, into a scratch `keys.c`, and run once:
    //
    //   cc -O0 -Wall -o keys keys.c && ./keys test && ./keys "" \
    //     && ./keys "$(printf 'p\xe4\xff')"
    //
    // (Apple clang 21.0.0.) Per password it prints the keys after
    // `init_keys`, then `zdecode` over the ciphertext 00 01 .. 0f, then the
    // keys after those sixteen bytes.

    /// `keys.c test`: the keys after `init_keys("test")`.
    const KEYS_TEST: [u32; 3] = [0x7712_f9de, 0x485a_fd7b, 0x5ded_1e32];
    /// `keys.c test`: `zdecode` over 00..0f.
    const PLAIN_TEST: [u8; 16] = [
        0xdf, 0xab, 0xa8, 0xa1, 0x13, 0x1d, 0xe5, 0x56, 0x7e, 0x6f, 0xcb, 0x72, 0xee, 0x6d, 0x98,
        0xaa,
    ];
    /// `keys.c test`: the keys after those sixteen bytes.
    const KEYS_TEST_AFTER: [u32; 3] = [0x70aa_f6a7, 0x9024_e6d8, 0x9e8b_0502];

    /// `keys.c ""`: `zdecode` over 00..0f from the bare initial keys.
    const PLAIN_EMPTY: [u8; 16] = [
        0xab, 0xda, 0x45, 0x7d, 0xb6, 0x72, 0xba, 0x2d, 0xad, 0xf6, 0xe4, 0x08, 0x28, 0xc5, 0x68,
        0xe8,
    ];
    /// `keys.c ""`: the keys after those sixteen bytes.
    const KEYS_EMPTY_AFTER: [u32; 3] = [0x455e_4b23, 0xfa42_2603, 0xabfb_9ddd];

    /// `keys.c "p\xe4\xff"`: bytes above 0x7f, which crypt.c passes through
    /// a (signed, on these hosts) `char` before `CRC32`'s `& 0xff`.
    const KEYS_HIGH: [u32; 3] = [0xd456_86a8, 0x9d35_b95c, 0xe307_dce8];
    const PLAIN_HIGH: [u8; 16] = [
        0xe2, 0xf9, 0x13, 0x1f, 0x18, 0xb0, 0x69, 0x17, 0x57, 0xfc, 0x4c, 0xbc, 0xca, 0xf4, 0x28,
        0xa8,
    ];
    const KEYS_HIGH_AFTER: [u32; 3] = [0x781c_f789, 0x1608_060b, 0xdaad_f20d];

    fn ciphertext_00_to_0f() -> [u8; 16] {
        std::array::from_fn(|i| i as u8)
    }

    /// Encrypts `plain` under `keys`, crypt.h's `zencode`, built from the
    /// decryption API: on a clone, `zdecode(0)` yields the stream byte.
    fn encrypt(keys: &mut Keys, plain: &[u8]) -> Vec<u8> {
        plain
            .iter()
            .map(|&p| {
                let stream = keys.clone().decrypt_byte(0);
                let c = stream ^ p;
                assert_eq!(keys.decrypt_byte(c), p);
                c
            })
            .collect()
    }

    #[test]
    fn keys_after_init_match_crypt_c() {
        // PKWARE APPNOTE 6.1's initial keys, which an empty password leaves
        // untouched.
        assert_eq!(
            Keys::new(b"").raw(),
            [0x1234_5678, 0x2345_6789, 0x3456_7890]
        );
        assert_eq!(Keys::new(b"test").raw(), KEYS_TEST);
        assert_eq!(Keys::new(b"p\xe4\xff").raw(), KEYS_HIGH);
        // init_keys() walks a C string: a NUL ends the password.
        assert_eq!(Keys::new(b"test\0junk").raw(), KEYS_TEST);
    }

    #[test]
    fn decrypt_round_trips_with_the_reference() {
        for (password, plain, after) in [
            (&b"test"[..], PLAIN_TEST, KEYS_TEST_AFTER),
            (&b""[..], PLAIN_EMPTY, KEYS_EMPTY_AFTER),
            (&b"p\xe4\xff"[..], PLAIN_HIGH, KEYS_HIGH_AFTER),
        ] {
            // Whole buffer, as crypt.c's NEXTBYTE path sees it.
            let mut keys = Keys::new(password);
            let mut buf = ciphertext_00_to_0f();
            keys.decrypt(&mut buf);
            assert_eq!(buf, plain, "password {password:?}");
            assert_eq!(keys.raw(), after, "password {password:?}");

            // A byte at a time agrees with the buffer.
            let mut keys = Keys::new(password);
            let bytes: Vec<u8> = ciphertext_00_to_0f()
                .iter()
                .map(|&c| keys.decrypt_byte(c))
                .collect();
            assert_eq!(bytes, plain);

            // And encrypting the reference's plain text gives back 00..0f.
            let mut keys = Keys::new(password);
            assert_eq!(encrypt(&mut keys, &plain), ciphertext_00_to_0f());
            assert_eq!(keys.raw(), after);
        }

        // A longer round trip through the header and the data after it.
        let data = b"The quick brown fox jumps over the lazy dog.\n".repeat(50);
        let mut enc = Keys::new(b"secret");
        let mut header = [0u8; RAND_HEAD_LEN];
        header[..RAND_HEAD_LEN - 1].copy_from_slice(b"random head");
        header[RAND_HEAD_LEN - 1] = 0x5a;
        let mut stream = encrypt(&mut enc, &header);
        stream.extend(encrypt(&mut enc, &data));
        let head: [u8; RAND_HEAD_LEN] = stream[..RAND_HEAD_LEN].try_into().unwrap();
        let mut keys = test_key(b"secret", &head, 0x5a).expect("right password");
        let mut body = stream[RAND_HEAD_LEN..].to_vec();
        keys.decrypt(&mut body);
        assert_eq!(body, data);
    }

    /// Twelve arbitrary ciphertext bytes; `secret` decrypts the last to
    /// `0x8f` (crypt.c, below).
    const COLLISION_HEADER: [u8; RAND_HEAD_LEN] = [
        0x3a, 0xc5, 0x17, 0x80, 0x5e, 0xf2, 0x09, 0x6b, 0xd4, 0x21, 0x9c, 0x47,
    ];

    #[test]
    fn test_key_rejects_a_wrong_password_and_reports_the_lucky_collision() {
        // Expected values from crypt.c's init_keys/zdecode run as testkey()
        // runs them over COLLISION_HEADER, for "secret" and for every
        // "pw0".."pw9999", in a scratch `coll.c`:
        //
        //   cc -O0 -Wall -o coll coll.c && ./coll
        //
        // printing `check=8f`, the first five matching passwords and
        // `count=42` (1 in 256 is ~39 expected over 10,000).
        const CHECK: u8 = 0x8f;
        const FIRST_LUCKY: [&str; 5] = ["pw0", "pw140", "pw268", "pw499", "pw994"];
        const LUCKY_COUNT: usize = 42;

        assert!(test_key(b"secret", &COLLISION_HEADER, CHECK).is_some());
        assert!(test_key(b"secret", &COLLISION_HEADER, CHECK ^ 1).is_none());

        let lucky: Vec<String> = (0..10_000)
            .map(|i| format!("pw{i}"))
            .filter(|pw| test_key(pw.as_bytes(), &COLLISION_HEADER, CHECK).is_some())
            .collect();
        assert_eq!(lucky.len(), LUCKY_COUNT, "{lucky:?}");
        assert_eq!(lucky[..FIRST_LUCKY.len()], FIRST_LUCKY);
        // A wrong password is rejected outright.
        assert!(test_key(b"pw1", &COLLISION_HEADER, CHECK).is_none());

        // The lucky one passes the check byte but decrypts to other keys
        // than the right one: only the entry's CRC can tell them apart.
        let right = test_key(b"secret", &COLLISION_HEADER, CHECK).unwrap();
        let wrong = test_key(b"pw0", &COLLISION_HEADER, CHECK).unwrap();
        assert_ne!(right.raw(), wrong.raw());
        let mut a = *b"payload bytes";
        let mut b = a;
        right.clone().decrypt(&mut a);
        wrong.clone().decrypt(&mut b);
        assert_ne!(a, b);
    }

    /// `/usr/bin/zip -P secret` over three stored files: every entry's
    /// header passes `test_key` with the right check byte and its data
    /// decrypts to the file. macOS only, where `/usr/bin/zip` is
    /// Info-ZIP's Zip 3.0.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_key_accepts_zip_made_archives() {
        let dir = macos::TempDir::new("zip-made");
        let files: [(&str, Vec<u8>); 3] = [
            ("a.txt", b"alpha\n".to_vec()),
            ("b.txt", b"bravo bravo bravo\n".repeat(20)),
            (
                "c.bin",
                (0..3000u32).map(|i| (i * 7 + i / 13) as u8).collect(),
            ),
        ];
        for (name, data) in &files {
            std::fs::write(dir.0.join(name), data).unwrap();
        }
        let out = std::process::Command::new("/usr/bin/zip")
            .args([
                "-q", "-0", "-P", "secret", "out.zip", "a.txt", "b.txt", "c.bin",
            ])
            .current_dir(&dir.0)
            .output()
            .expect("run /usr/bin/zip");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );

        let entries = macos::local_entries(&std::fs::read(dir.0.join("out.zip")).unwrap());
        assert_eq!(entries.len(), files.len());
        for (entry, (name, data)) in entries.iter().zip(&files) {
            assert_eq!(entry.name, name.as_bytes());
            assert_eq!(entry.flags & 1, 1, "{name}: not encrypted");
            assert_eq!(entry.method, 0, "{name}: not stored");
            let check = if entry.flags & 8 != 0 {
                (entry.dos_time >> 8) as u8
            } else {
                (entry.crc >> 24) as u8
            };
            let head: [u8; RAND_HEAD_LEN] = entry.data[..RAND_HEAD_LEN].try_into().unwrap();
            let mut keys = test_key(b"secret", &head, check)
                .unwrap_or_else(|| panic!("{name}: the right password was refused"));
            let mut body = entry.data[RAND_HEAD_LEN..].to_vec();
            keys.decrypt(&mut body);
            assert_eq!(&body, data, "{name}");
        }
    }

    #[cfg(target_os = "macos")]
    mod macos {
        pub(super) struct TempDir(pub(super) std::path::PathBuf);

        impl TempDir {
            pub(super) fn new(tag: &str) -> TempDir {
                let dir = std::env::temp_dir().join(format!(
                    "stuffr-infozip-crypt-{tag}-{}-{:?}",
                    std::process::id(),
                    std::thread::current().id()
                ));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                TempDir(dir)
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        pub(super) struct LocalEntry {
            pub(super) flags: u16,
            pub(super) method: u16,
            pub(super) dos_time: u16,
            pub(super) crc: u32,
            pub(super) name: Vec<u8>,
            pub(super) data: Vec<u8>,
        }

        fn u16_at(b: &[u8], at: usize) -> u16 {
            u16::from_le_bytes([b[at], b[at + 1]])
        }

        fn u32_at(b: &[u8], at: usize) -> u32 {
            u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
        }

        /// Walks the local headers from the start: each `PK\3\4` record,
        /// its data, and its data descriptor when bit 3 is set. `csize` is
        /// read from the local header, which Zip 3.0 rewrites with the real
        /// figure when its output is seekable (on a pipe it leaves the
        /// stored size there, 6 for `a.txt`, and the assertion below fires).
        pub(super) fn local_entries(zip: &[u8]) -> Vec<LocalEntry> {
            let mut at = 0;
            let mut entries = Vec::new();
            while zip.len() >= at + 30 && zip[at..at + 4] == *b"PK\x03\x04" {
                let flags = u16_at(zip, at + 6);
                let method = u16_at(zip, at + 8);
                let dos_time = u16_at(zip, at + 10);
                let csize = u32_at(zip, at + 18) as usize;
                let name_len = u16_at(zip, at + 26) as usize;
                let extra_len = u16_at(zip, at + 28) as usize;
                let name_at = at + 30;
                let data_at = name_at + name_len + extra_len;
                assert!(
                    csize >= super::RAND_HEAD_LEN,
                    "entry at {at}: csize {csize}"
                );
                let mut crc = u32_at(zip, at + 14);
                at = data_at + csize;
                if flags & 8 != 0 {
                    if zip[at..at + 4] == *b"PK\x07\x08" {
                        at += 4;
                    }
                    crc = u32_at(zip, at);
                    at += 12;
                }
                entries.push(LocalEntry {
                    flags,
                    method,
                    dos_time,
                    crc,
                    name: zip[name_at..name_at + name_len].to_vec(),
                    data: zip[data_at..data_at + csize].to_vec(),
                });
            }
            entries
        }
    }
}

mod inflate {
    use crate::infozip::inflate::inflate_max_distance;
    use crate::infozip::{INCOMPLETE_D_TREE, INCOMPLETE_L_TREE, Stop, WSIZE, inflate};

    /// What one [`inflate`] call did: its result (the C's return code, 0 for
    /// success), every chunk it flushed, and every message it passed on.
    struct Run {
        code: i32,
        chunks: Vec<usize>,
        out: Vec<u8>,
        messages: Vec<&'static str>,
    }

    /// [`run_in`] over a fresh zeroed window: what the C driver's
    /// `memset(&G, 0, sizeof G)` gives inflate.c.
    fn run(input: &[u8], deflate64: bool) -> Run {
        run_in(input, deflate64, &mut vec![0; WSIZE])
    }

    fn run_in(input: &[u8], deflate64: bool, window: &mut [u8]) -> Run {
        let mut chunks = Vec::new();
        let mut out = Vec::new();
        let mut messages = Vec::new();
        let r = inflate(
            &mut input.iter(),
            deflate64,
            window,
            &mut |c: &[u8]| -> Result<(), ()> {
                chunks.push(c.len());
                out.extend_from_slice(c);
                Ok(())
            },
            &mut |m| messages.push(m),
        );
        let code = match r {
            Ok(()) => 0,
            Err(Stop::Code(c)) => c,
            Err(Stop::Flush(())) => unreachable!("this flush never fails"),
        };
        Run {
            code,
            chunks,
            out,
            messages,
        }
    }

    // ---- deterministic data: the differential harness's generators ----

    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    fn random(n: usize, seed: u64) -> Vec<u8> {
        let mut r = XorShift(seed);
        (0..n).map(|_| (r.next() >> 24) as u8).collect()
    }

    const WORDS: &[&str] = &[
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "stuffr", "gzip", "member",
        "deflate", "header", "and", "of", "a", "to", "in", "file",
    ];

    fn text(n: usize, seed: u64) -> Vec<u8> {
        let mut r = XorShift(seed);
        let mut v = Vec::with_capacity(n + 16);
        while v.len() < n {
            v.extend_from_slice(WORDS[(r.next() % WORDS.len() as u64) as usize].as_bytes());
            v.push(if r.next().is_multiple_of(9) {
                b'\n'
            } else {
                b' '
            });
        }
        v.truncate(n);
        v
    }

    fn mixed(n: usize, seed: u64) -> Vec<u8> {
        let mut r = XorShift(seed);
        let mut v = Vec::with_capacity(n + 4096);
        while v.len() < n {
            match r.next() % 3 {
                0 => v.extend(text(2048, r.next())),
                1 => v.extend(random(512, r.next() | 1)),
                _ => v.extend(std::iter::repeat_n(b'z', (r.next() % 3000) as usize)),
            }
        }
        v.truncate(n);
        v
    }

    // ---- hand-built streams ----

    /// `data` as stored blocks (at most 65535 bytes each), the last one
    /// final; an empty `data` is one empty final stored block.
    fn stored(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut blocks = data.chunks(0xffff).peekable();
        if blocks.peek().is_none() {
            out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
        }
        while let Some(block) = blocks.next() {
            out.push(u8::from(blocks.peek().is_none()));
            let len = block.len() as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(block);
        }
        out
    }

    #[cfg(feature = "deflate")]
    fn flate2(data: &[u8], level: u32) -> Vec<u8> {
        use std::io::Write;
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(level));
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// 64 inputs from the three generators at sizes either side of the
    /// window, each through every flate2 level 0-9: the output is the input.
    #[cfg(feature = "deflate")]
    #[test]
    fn inflates_like_flate2() {
        const SIZES: [usize; 8] = [0, 1, 300, 5000, 65536, 70001, 131072, 200000];
        for i in 0..64u64 {
            let n = SIZES[(i % 8) as usize];
            let data = match i % 3 {
                0 => text(n, i + 1),
                1 => random(n, i + 1),
                _ => mixed(n, i + 1),
            };
            for level in 0..=9 {
                let r = run(&flate2(&data, level), false);
                assert_eq!(r.code, 0, "input {i} (level {level}, {n} bytes)");
                assert!(r.out == data, "input {i} (level {level}, {n} bytes)");
                assert!(r.messages.is_empty());
            }
        }
    }

    /// `FLUSH(w)` hands over every full 64 KiB window, then the final
    /// `G.wp` bytes, which is a zero-length flush when the output is empty
    /// or a multiple of the window: `inflate()` ends with `FLUSH(G.wp)`
    /// whatever `G.wp` is.
    #[test]
    fn flush_chunks_are_window_sized() {
        for (n, want) in [
            (200_000, vec![WSIZE, WSIZE, WSIZE, 200_000 - 3 * WSIZE]),
            (2 * WSIZE, vec![WSIZE, WSIZE, 0]),
            (WSIZE - 1, vec![WSIZE - 1]),
            (0, vec![0]),
        ] {
            let data = mixed(n, 7);
            let r = run(&stored(&data), false);
            assert_eq!(r.code, 0, "{n} bytes");
            assert_eq!(r.chunks, want, "{n} bytes");
            assert!(r.out == data, "{n} bytes");
            // deflate64 has the same window
            assert_eq!(
                run(&stored(&data), true).chunks,
                want,
                "{n} bytes, deflate64"
            );
        }
    }

    /// A stream cut short is the C's EOF: code 1 from `NEEDBITS`, with only
    /// the full windows before the cut flushed. Cut at the very end (the
    /// last bits of the final block's EOB missing aside), the read-beyond-
    /// EOF tolerance lets the stream finish.
    #[test]
    fn eof_mid_stream_is_code_1() {
        let data = mixed(150_000, 3);
        let s = stored(&data);
        // inside the second stored block's data: the first window was flushed
        let r = run(&s[..70_000], false);
        assert_eq!(r.code, 1);
        assert_eq!(r.chunks, vec![WSIZE]);
        // inside a stored block's length
        assert_eq!(run(&s[..2], false).code, 1);
        // nothing at all: the first NEEDBITS(1) of inflate_block
        let r = run(&[], false);
        assert_eq!((r.code, r.chunks.len()), (1, 0));

        // A fixed block holding only an end-of-block code: 1 (final), 01
        // (fixed), then EOB's seven zero bits, ten bits in two bytes. One
        // byte is the tolerance's case: NEEDBITS(7) breaks at EOF with
        // k = 5 >= 0, and the zero bits it lacks decode as EOB.
        let eob = [0b0000_0011, 0];
        assert_eq!(run(&eob, false).chunks, vec![0]);
        let r = run(&eob[..1], false);
        assert_eq!((r.code, r.chunks), (0, vec![0]));
    }

    /// Task 1's `deflate64-lorem.zip` (commons-compress, method 9): the
    /// output is what `unzip -p` gives on both references (the SHA-256
    /// below, from `/usr/bin/unzip -p deflate64-lorem.zip | shasum -a 256`
    /// and the same in ubuntu:24.04).
    #[test]
    fn deflate64_fixture() {
        let Some(zip) = super::fixture("deflate64-lorem.zip") else {
            return;
        };
        let data = super::first_entry_data(&zip);
        let mut out = Vec::new();
        let (r, max_distance) = inflate_max_distance(&mut data.iter(), true, &mut |c| {
            out.extend_from_slice(c);
            Ok::<(), ()>(())
        });
        assert!(r.is_ok(), "{r:?}");
        assert_eq!(out.len(), 144_060);
        assert_eq!(
            super::sha256(&out),
            "a00c4f3f36515c96b2faef71c054e7f3e86a4f0f4ed4824cb7c5293bb455d28a"
        );
        // Ruling P6: the fixture reaches past a 32 KiB window, so it tests
        // deflate64's distance codes 30 and 31 (measured: 65521).
        assert!(max_distance > 32_768, "longest distance {max_distance}");
    }

    // ---- the damage table: tests/data/infozip/inflate_damage.txt ----

    /// The damage table's undamaged streams: four flate2-made deflate
    /// streams committed under `inflate_damage/` (frozen, so a flate2 or
    /// backend change cannot move them), and the deflate64 fixture's entry.
    const BASES: [(&str, bool); 5] = [
        ("text", false),
        ("mixed", false),
        ("stored", false),
        ("fixed", false),
        ("lorem64", true),
    ];

    /// How many damaged inputs the table holds.
    const DAMAGED: u64 = 200;

    /// The undamaged stream `name`, `None` when the fixtures are absent.
    fn base(name: &str) -> Option<Vec<u8>> {
        if name == "lorem64" {
            let zip = super::fixture("deflate64-lorem.zip")?;
            Some(super::first_entry_data(&zip).to_vec())
        } else {
            super::fixture(&format!("inflate_damage/{name}.deflate"))
        }
    }

    /// Damaged input `i` of `base`: bit flips, a truncation, or inserted
    /// bytes, chosen and placed by a XorShift seeded from `i`. Half the
    /// positions fall in the first 96 bytes, where the block headers and
    /// code trees are. Returns the input and a description without spaces.
    fn damage(base: &[u8], i: u64) -> (Vec<u8>, String) {
        let mut r = XorShift((i + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let len = base.len() as u64;
        let pos = |r: &mut XorShift, room: u64| {
            if r.next().is_multiple_of(2) {
                r.next() % room.min(96)
            } else {
                r.next() % room
            }
        };
        let mut b = base.to_vec();
        let mut kind = Vec::new();
        match r.next() % 3 {
            0 => {
                for _ in 0..1 + r.next() % 3 {
                    let at = pos(&mut r, len) as usize;
                    let bit = r.next() % 8;
                    b[at] ^= 1 << bit;
                    kind.push(format!("{at}.{bit}"));
                }
                (b, format!("flip:{}", kind.join("+")))
            }
            1 => {
                let to = (r.next() % len) as usize;
                b.truncate(to);
                (b, format!("truncate:{to}"))
            }
            _ => {
                for _ in 0..1 + r.next() % 2 {
                    let at = pos(&mut r, b.len() as u64 + 1) as usize;
                    let byte = r.next() as u8;
                    b.insert(at, byte);
                    kind.push(format!("{at}.{byte:02x}"));
                }
                (b, format!("insert:{}", kind.join("+")))
            }
        }
    }

    /// One damaged input of the table.
    struct Damaged {
        i: u64,
        base: &'static str,
        deflate64: bool,
        input: Vec<u8>,
        kind: String,
    }

    /// Damaged inputs `0..DAMAGED`, cycling through [`BASES`].
    fn damaged_inputs() -> Option<Vec<Damaged>> {
        let mut bases = Vec::new();
        for (name, d64) in BASES {
            bases.push((name, d64, base(name)?));
        }
        Some(
            (0..DAMAGED)
                .map(|i| {
                    let (base, deflate64, b) = &bases[(i % BASES.len() as u64) as usize];
                    let (input, kind) = damage(b, i);
                    Damaged {
                        i,
                        base,
                        deflate64: *deflate64,
                        input,
                        kind,
                    }
                })
                .collect(),
        )
    }

    /// One row of `inflate_damage.txt`, the C driver's output:
    /// `NNN|base|kind|input-sha256|rc|messages|total|chunks|output-sha256`.
    fn row(r: &Run, i: u64, base: &str, kind: &str, input: &[u8]) -> String {
        let messages: Vec<&str> = r
            .messages
            .iter()
            .map(|&m| match m {
                INCOMPLETE_L_TREE => "l-tree",
                INCOMPLETE_D_TREE => "d-tree",
                _ => "?",
            })
            .collect();
        let chunks: Vec<String> = r.chunks.iter().map(usize::to_string).collect();
        format!(
            "{i:03}|{base}|{kind}|{}|{}|{}|{}|{}|{}",
            super::sha256(input),
            r.code,
            if messages.is_empty() {
                "-".to_owned()
            } else {
                messages.concat()
            },
            r.out.len(),
            if chunks.is_empty() {
                "-".to_owned()
            } else {
                chunks.join(",")
            },
            super::sha256(&r.out),
        )
    }

    /// Every damaged input gives exactly the C's return code, messages and
    /// flushed chunks (lengths and bytes): Info-ZIP's own `inflate.c`,
    /// compiled against a stub `G` (the driver and recipe are in the
    /// fixtures' README), recorded in `inflate_damage.txt`. The driver
    /// zeroes `G` before each input, so the table is the oracle for a zeroed
    /// window, and this test passes one ([`run`]). The undamaged
    /// bases decode cleanly first, so a row of all-zeros is not mistaken
    /// for agreement.
    #[test]
    fn codes_on_damage_match_the_c() {
        let Some(table) = super::fixture("inflate_damage.txt") else {
            return;
        };
        let table = String::from_utf8(table).unwrap();
        let rows: Vec<&str> = table
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();
        assert_eq!(rows.len() as u64, DAMAGED, "rows in inflate_damage.txt");
        for (name, d64) in BASES {
            let r = run(&base(name).unwrap(), d64);
            assert_eq!(r.code, 0, "{name} undamaged");
        }
        let inputs = damaged_inputs().unwrap();
        let mut wrong = Vec::new();
        let mut codes = std::collections::BTreeMap::new();
        for (d, want) in inputs.iter().zip(&rows) {
            let r = run(&d.input, d.deflate64);
            *codes.entry(r.code).or_insert(0) += 1;
            let got = row(&r, d.i, d.base, &d.kind, &d.input);
            if got != **want {
                wrong.push(format!("  want {want}\n  got  {got}"));
            }
        }
        assert!(
            wrong.is_empty(),
            "{} of {DAMAGED} rows differ from inflate.c:\n{}",
            wrong.len(),
            wrong.join("\n")
        );
        // the table exercises every code inflate.c returns on damage
        for code in [0, 1, 2] {
            assert!(
                codes.contains_key(&code),
                "no row with code {code}: {codes:?}"
            );
        }
    }

    /// Recipe step 2 (README): writes each damaged input to
    /// `$STUFFR_INFOZIP_DAMAGE_OUT/NNN.in`, and `manifest.txt` there for the
    /// C driver (`NNN|base|deflate64|kind|input-sha256|path`).
    #[test]
    #[ignore = "generator for inflate_damage.txt; see tests/data/infozip/README"]
    fn write_damage_inputs() {
        let out = std::path::PathBuf::from(
            std::env::var_os("STUFFR_INFOZIP_DAMAGE_OUT").expect("STUFFR_INFOZIP_DAMAGE_OUT"),
        );
        std::fs::create_dir_all(&out).unwrap();
        let mut manifest = String::new();
        for d in damaged_inputs().expect("fixtures") {
            let path = out.join(format!("{:03}.in", d.i));
            std::fs::write(&path, &d.input).unwrap();
            manifest += &format!(
                "{:03}|{}|{}|{}|{}|{}\n",
                d.i,
                d.base,
                u8::from(d.deflate64),
                d.kind,
                super::sha256(&d.input),
                path.display()
            );
        }
        std::fs::write(out.join("manifest.txt"), manifest).unwrap();
    }

    /// Recipe step 1 (README): writes the four flate2-made bases into
    /// `tests/data/infozip/inflate_damage/`. Run once; they are committed.
    #[cfg(feature = "deflate")]
    #[test]
    #[ignore = "generator for the damage table's bases; see tests/data/infozip/README"]
    fn write_damage_bases() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/infozip/inflate_damage");
        std::fs::create_dir_all(&dir).unwrap();
        let fixed = flate2(&text(40, 24), 9);
        // BTYPE 01: a fixed-Huffman block
        assert_eq!((fixed[0] >> 1) & 3, 1, "not a fixed block");
        for (name, stream) in [
            ("text", flate2(&text(100_000, 21), 6)),
            ("mixed", flate2(&mixed(40_000, 22), 1)),
            ("stored", flate2(&random(3000, 23), 0)),
            ("fixed", fixed),
        ] {
            std::fs::write(dir.join(format!("{name}.deflate")), stream).unwrap();
        }
    }

    // ---- hand-built streams for the edge cases the damage table misses ----

    /// An LSB-first bit writer, as deflate packs its bits.
    #[derive(Default)]
    struct Bits {
        out: Vec<u8>,
        acc: u64,
        n: u32,
    }

    impl Bits {
        fn put(&mut self, v: u32, n: u32) {
            self.acc |= u64::from(v) << self.n;
            self.n += n;
            while self.n >= 8 {
                self.out.push(self.acc as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
        }

        /// A Huffman code, most significant bit first.
        fn code(&mut self, code: u32, len: u32) {
            for i in (0..len).rev() {
                self.put((code >> i) & 1, 1);
            }
        }

        /// A literal/length symbol of the fixed code.
        fn fixed(&mut self, v: u32) {
            let (c, l) = match v {
                0..=143 => (0x30 + v, 8),
                144..=255 => (0x190 + v - 144, 9),
                256..=279 => (v - 256, 7),
                _ => (0xc0 + v - 280, 8),
            };
            self.code(c, l);
        }

        fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                self.out.push(self.acc as u8);
            }
            self.out
        }
    }

    /// Canonical codes for `lengths` (RFC 1951 3.2.2).
    fn canonical(lengths: &[u32]) -> Vec<u32> {
        let mut count = [0u32; 16];
        for &l in lengths {
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut next = [0u32; 16];
        let mut code = 0;
        for bits in 1..16 {
            code = (code + count[bits - 1]) << 1;
            next[bits] = code;
        }
        lengths
            .iter()
            .map(|&l| {
                let c = next[l as usize];
                next[l as usize] += 1;
                c
            })
            .collect()
    }

    /// A final dynamic block's header for `lit` and `dist` code lengths,
    /// sent as plain length symbols over a complete bit-length code
    /// (lengths 1, 2, .., k-1, k-1 over the k distinct lengths used). Returns
    /// the literal/length and distance codes.
    fn dynamic(w: &mut Bits, lit: &[u32], dist: &[u32]) -> (Vec<u32>, Vec<u32>) {
        const BORDER: [u32; 19] = [
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
        ];
        let all: Vec<u32> = lit.iter().chain(dist).copied().collect();
        let mut used: Vec<u32> = all.clone();
        used.sort_unstable();
        used.dedup();
        let k = used.len() as u32;
        assert!((2..=8).contains(&k));
        let mut bl = [0u32; 19];
        for (i, &sym) in used.iter().enumerate() {
            bl[sym as usize] = (i as u32 + 1).min(k - 1);
        }
        let nb = BORDER
            .iter()
            .rposition(|&sym| bl[sym as usize] != 0)
            .unwrap()
            .max(3)
            + 1;
        w.put(1, 1);
        w.put(2, 2);
        w.put(lit.len() as u32 - 257, 5);
        w.put(dist.len() as u32 - 1, 5);
        w.put(nb as u32 - 4, 4);
        for &sym in &BORDER[..nb] {
            w.put(bl[sym as usize], 3);
        }
        let bl_codes = canonical(&bl);
        for &l in &all {
            w.code(bl_codes[l as usize], bl[l as usize]);
        }
        (canonical(lit), canonical(dist))
    }

    /// Literal/length lengths: `nl` codes, the listed ones set.
    fn lengths(nl: usize, set: &[(usize, u32)]) -> Vec<u32> {
        let mut l = vec![0; nl];
        for &(sym, len) in set {
            l[sym] = len;
        }
        l
    }

    /// The hand-built streams: (name, deflate64, stream).
    fn hand_streams() -> Vec<(&'static str, bool, Vec<u8>)> {
        let mut v = Vec::new();

        // 'a' and EOB only: lengths 1 and 2, half a code short.
        let mut w = Bits::default();
        dynamic(&mut w, &lengths(257, &[(97, 1), (256, 2)]), &[1]);
        v.push(("l-tree-incomplete", false, w.finish()));

        // A length code but no distance codes at all.
        let mut w = Bits::default();
        dynamic(&mut w, &lengths(258, &[(97, 1), (256, 2), (257, 2)]), &[0]);
        v.push(("d-tree-empty", false, w.finish()));

        // An incomplete distance tree (lengths 1 and 2) is accepted
        // (PKZIP_BUG_WORKAROUND): 'a', then length 3 at distance 1, EOB.
        let lit = lengths(258, &[(97, 1), (256, 2), (257, 2)]);
        let mut w = Bits::default();
        let (lc, dc) = dynamic(&mut w, &lit, &[1, 2]);
        w.code(lc[97], 1);
        w.code(lc[257], 2);
        w.code(dc[0], 1);
        w.code(lc[256], 2);
        v.push(("d-tree-incomplete-used", false, w.finish()));
        // ... and its missing code "11" is an invalid one.
        let mut w = Bits::default();
        let (lc, _) = dynamic(&mut w, &lit, &[1, 2]);
        w.code(lc[97], 1);
        w.code(lc[257], 2);
        w.code(0b11, 2);
        v.push(("d-tree-incomplete-missing", false, w.finish()));

        // Oversubscribed: three codes of one bit.
        let mut w = Bits::default();
        dynamic(&mut w, &lengths(257, &[(97, 1), (98, 1), (256, 1)]), &[1]);
        v.push(("l-tree-oversubscribed", false, w.finish()));

        // A bit-length code of ONE symbol (length 1, so g == 1 and it is
        // accepted though incomplete). Its missing code "1" is an invalid
        // entry whose v.n is the last value huft_build set, 1, which
        // inflate_dynamic reads without checking e. Sent as "0" then "1"s:
        // every length is 1, an oversubscribed tree (2). Were the invalid
        // entry read as 0, the tree would be one code and decode on.
        let mut w = Bits::default();
        w.put(1, 1);
        w.put(2, 2);
        w.put(0, 5); // 257 literal/length codes
        w.put(0, 5); // 1 distance code
        w.put(14, 4); // 18 bit-length code lengths, up to symbol 1
        for i in 0..18 {
            w.put(u32::from(i == 17), 3); // BORDER[17] is symbol 1
        }
        w.put(0, 1);
        for _ in 0..257 {
            w.put(1, 1);
        }
        v.push(("bl-tree-single-code", false, w.finish()));

        // Block type 3.
        v.push(("block-type-3", false, vec![0b111]));

        // Fixed: 'a', length 3 at distance code 30 (32769 + 14 bits), EOB.
        // Deflate has no code 30; deflate64 reaches before the output.
        for (name, d64) in [("dist-code-30", false), ("dist-code-30-64", true)] {
            let mut w = Bits::default();
            w.put(1, 1);
            w.put(1, 2);
            w.fixed(97);
            w.fixed(257);
            w.code(30, 5);
            w.put(5, 14);
            w.fixed(256);
            v.push((name, d64, w.finish()));
        }

        // Fixed: 'a', 'b', length 3 at distance 5 (code 4, extra bit 0),
        // before the start of the output: a fresh window's zeros.
        let mut w = Bits::default();
        w.put(1, 1);
        w.put(1, 2);
        w.fixed(97);
        w.fixed(98);
        w.fixed(257);
        w.code(4, 5);
        w.put(0, 1);
        w.fixed(256);
        v.push(("before-the-start", false, w.finish()));

        // Fixed: 'a', code 285, distance 1 (code 0), EOB. Deflate64's 285
        // is 3 + 16 extra bits (997 here: 1001 a's); deflate's is 258.
        for (name, d64) in [("length-285", false), ("length-285-64", true)] {
            let mut w = Bits::default();
            w.put(1, 1);
            w.put(1, 2);
            w.fixed(97);
            w.fixed(285);
            if d64 {
                w.put(997, 16);
            }
            w.code(0, 5);
            w.fixed(256);
            v.push((name, d64, w.finish()));
        }
        v
    }

    /// The hand-built streams give what `inflate.c` gives. Each expected
    /// row is the C driver's (README, "inflate_damage.txt") over the
    /// streams `write_hand_inputs` writes: return code, messages, and
    /// output.
    #[test]
    fn edge_cases_match_the_c() {
        let a = |n: usize| vec![b'a'; n];
        let want: [(&str, i32, &[&str], Vec<u8>); 12] = [
            ("l-tree-incomplete", 1, &[INCOMPLETE_L_TREE], vec![]),
            ("d-tree-empty", 1, &[INCOMPLETE_D_TREE], vec![]),
            ("d-tree-incomplete-used", 0, &[], a(4)),
            ("d-tree-incomplete-missing", 1, &[], vec![]),
            ("l-tree-oversubscribed", 2, &[], vec![]),
            ("bl-tree-single-code", 2, &[], vec![]),
            ("block-type-3", 2, &[], vec![]),
            ("dist-code-30", 1, &[], vec![]),
            ("dist-code-30-64", 0, &[], vec![b'a', 0, 0, 0]),
            ("before-the-start", 0, &[], vec![b'a', b'b', 0, 0, 0]),
            ("length-285", 0, &[], a(259)),
            ("length-285-64", 0, &[], a(1001)),
        ];
        let streams = hand_streams();
        assert_eq!(streams.len(), want.len());
        for ((name, d64, stream), (wname, code, messages, out)) in streams.iter().zip(&want) {
            assert_eq!(name, wname);
            let r = run(stream, *d64);
            assert_eq!(
                (r.code, &r.messages[..], &r.out),
                (*code, *messages, out),
                "{name}"
            );
        }
    }

    /// Writes the hand-built streams to `$STUFFR_INFOZIP_DAMAGE_OUT/hand-*.in`
    /// and `manifest-hand.txt`, for the C driver.
    #[test]
    #[ignore = "writes the hand-built streams for the C driver; see tests/data/infozip/README"]
    fn write_hand_inputs() {
        let out = std::path::PathBuf::from(
            std::env::var_os("STUFFR_INFOZIP_DAMAGE_OUT").expect("STUFFR_INFOZIP_DAMAGE_OUT"),
        );
        std::fs::create_dir_all(&out).unwrap();
        let mut manifest = String::new();
        for (i, (name, d64, stream)) in hand_streams().into_iter().enumerate() {
            let path = out.join(format!("hand-{name}.in"));
            std::fs::write(&path, &stream).unwrap();
            manifest += &format!(
                "{i:03}|{name}|{}|hand|{}|{}\n",
                u8::from(d64),
                super::sha256(&stream),
                path.display()
            );
        }
        std::fs::write(out.join("manifest-hand.txt"), manifest).unwrap();
    }

    /// The window is the caller's and is not cleared (`inflate.c:1012`
    /// masks a distance into `slide[]` and never rejects it): a distance
    /// reaching before the entry's first byte copies what the window held.
    /// Pre-filled with 0xAA, the before-the-start cases copy 0xAA where a
    /// zeroed window gives zeros, and over the whole damage table the code,
    /// the chunk lengths and the total never move; only some outputs do.
    #[test]
    fn window_contents_are_what_early_distances_read() {
        let streams = hand_streams();
        let stream = |name: &str| {
            let (_, d64, s) = streams.iter().find(|(n, ..)| *n == name).unwrap();
            (s.clone(), *d64)
        };
        let filled = || vec![0xaa; WSIZE];
        for (name, want) in [
            ("before-the-start", vec![b'a', b'b', 0xaa, 0xaa, 0xaa]),
            ("dist-code-30-64", vec![b'a', 0xaa, 0xaa, 0xaa]),
        ] {
            let (s, d64) = stream(name);
            let r = run_in(&s, d64, &mut filled());
            assert_eq!(
                (r.code, &r.chunks, &r.out),
                (0, &vec![want.len()], &want),
                "{name}"
            );
        }
        // A window longer than WSIZE is accepted; only WSIZE bytes are used.
        let (s, d64) = stream("before-the-start");
        let mut long = vec![0xaa; WSIZE + 10];
        assert_eq!(
            run_in(&s, d64, &mut long).out,
            [b'a', b'b', 0xaa, 0xaa, 0xaa]
        );

        let Some(inputs) = damaged_inputs() else {
            return;
        };
        let mut moved = 0;
        for d in &inputs {
            let zeroed = run(&d.input, d.deflate64);
            let r = run_in(&d.input, d.deflate64, &mut filled());
            assert_eq!(
                (r.code, &r.chunks, &r.messages),
                (zeroed.code, &zeroed.chunks, &zeroed.messages),
                "row {:03}",
                d.i
            );
            moved += usize::from(r.out != zeroed.out);
        }
        assert!(moved > 0, "no damaged row reads before its start");
        eprintln!("{moved} of {DAMAGED} damaged rows read before their start");
    }

    /// A window under `WSIZE` is refused.
    #[test]
    #[should_panic(expected = "under WSIZE")]
    fn short_window_panics() {
        run_in(&[0b0000_0011, 0], false, &mut [0; 100]);
    }
}
