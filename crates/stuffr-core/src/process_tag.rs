//! A per-process number for naming temporaries.

/// A number that names this process in temporary file names.
///
/// Off WASI this is `std::process::id()`. WASI has no process ids and
/// `std::process::id()` panics there, so on `target_os = "wasi"` it is a
/// value fixed for the process lifetime, mixing the clock with the hasher
/// seed (`RandomState`, which WASI seeds from `random_get`) so concurrent
/// instances started in the same instant still differ. A collision is harmless
/// either way: every temporary is made with `create_new` and retried.
///
/// Where a pid is used as a pid (signals, re-raising), call
/// `std::process::id()` directly instead; this is plumbing for names.
#[doc(hidden)]
#[must_use]
pub fn process_tag() -> u32 {
    #[cfg(not(target_os = "wasi"))]
    {
        std::process::id()
    }
    #[cfg(target_os = "wasi")]
    {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        use std::sync::OnceLock;
        use std::time::{SystemTime, UNIX_EPOCH};
        static TAG: OnceLock<u32> = OnceLock::new();
        *TAG.get_or_init(|| {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let mut h = RandomState::new().build_hasher();
            h.write_u128(nanos);
            let v = h.finish();
            (v ^ (v >> 32)) as u32
        })
    }
}

#[cfg(test)]
mod tests {
    use super::process_tag;

    #[test]
    fn process_tag_is_stable() {
        assert_eq!(process_tag(), process_tag());
        #[cfg(not(target_os = "wasi"))]
        assert_eq!(process_tag(), std::process::id());
    }
}
