//! A process-local slab for handing heap payloads to window-message
//! handlers by TOKEN instead of by raw pointer.
//!
//! `WM_USER`-range messages carry an unmarshalled `wparam`, so any
//! same-desktop process can `PostMessageW` an attacker-chosen integer to
//! amwall's fixed window class (`w!("AmwallMainWindow")`). Feeding that
//! integer to `Box::from_raw` — as the connect / update handlers used to
//! — turns it into an arbitrary heap free / type-confusion primitive
//! inside the (commonly non-elevated) GUI process.
//!
//! Instead the poster `stash`es the payload and posts a monotonically
//! increasing token; the handler `take`s it. A forged or stale token is
//! a safe lookup miss, and a token whose payload isn't the expected type
//! is rejected by the downcast. Fable sweep finding #19.

use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

static SLAB: LazyLock<Mutex<HashMap<u64, Box<dyn Any + Send>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT: AtomicU64 = AtomicU64::new(1);

/// Stash a payload, returning a non-zero token to post as the `wparam`.
/// Never returns 0, so a null/zero forged `wparam` is always a miss.
pub fn stash<T: Send + 'static>(value: T) -> usize {
    let token = NEXT.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut slab) = SLAB.lock() {
        slab.insert(token, Box::new(value));
    }
    token as usize
}

/// Reclaim the payload posted under `token`. Returns `None` for an
/// unknown token (already taken, or a forged / bogus message) or a token
/// whose stored payload isn't a `T`.
pub fn take<T: 'static>(token: usize) -> Option<T> {
    let boxed = SLAB.lock().ok()?.remove(&(token as u64))?;
    boxed.downcast::<T>().ok().map(|b| *b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stash_then_take_round_trips() {
        let token = stash(String::from("hello"));
        assert_eq!(take::<String>(token), Some(String::from("hello")));
        // A second take of the same token is a miss (already removed).
        assert_eq!(take::<String>(token), None);
    }

    #[test]
    fn forged_or_wrong_type_token_is_a_safe_miss() {
        // A token that was never stashed -> None (no Box::from_raw on it).
        assert_eq!(take::<String>(0xdead_beef), None);
        // Right token, wrong type -> None (downcast fails), payload dropped.
        let token = stash(42u32);
        assert_eq!(take::<String>(token), None);
    }
}
