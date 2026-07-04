//! Small internal utilities shared across modules.

use std::sync::{Mutex, MutexGuard};

/// Acquire a mutex, recovering from a poisoned state instead of panicking.
///
/// A poisoned mutex means another thread panicked while holding the lock, but
/// the data it protects is still structurally valid. Recovering keeps a single
/// panic from cascading: without this, every later `.lock().unwrap()` on the
/// same mutex would panic in turn, leaving the whole client permanently
/// unusable. This mirrors the strategy already used by the connection pool.
pub(crate) fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
