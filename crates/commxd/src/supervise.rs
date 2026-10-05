//! Fault containment.
//!
//! **Invariant: no single peer, room, transfer, or UI operation may be
//! capable of terminating the daemon.** The only ways commxd exits are a
//! shutdown signal or a failure during startup.
//!
//! Fault domains and what a fault costs:
//!
//! | domain                    | boundary                                  | on fault                          |
//! |---------------------------|-------------------------------------------|-----------------------------------|
//! | peer connection           | its own reader/writer tasks, `Result`s    | that connection is dropped        |
//! | room                      | [`contain`] around every room operation   | that room is nuked ("internal fault") |
//! | file transfer             | its own task, blocking I/O off-runtime    | that transfer is marked failed    |
//! | IPC request / client      | each request runs in its own task         | error reply; client keeps working |
//! | core loops (accept, IPC, tick, UDP, tor) | [`supervise`]: restart with backoff | brief gap, then service resumes |
//!
//! Faults are values (`Result`) at every boundary. Panics are a backstop:
//! the release profile unwinds (not aborts) precisely so a panic can be
//! caught here, and the std mutex guarding daemon state recovers from
//! poisoning. A room whose code panicked is nuked rather than trusted, since
//! its state may be half-updated, which also matches commx's "when in doubt,
//! destroy" stance.

use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

/// Panic payloads can contain arbitrary strings; never print them. Location
/// only, so a contained panic is debuggable without leaking content.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let at = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_else(|| "?".into());
        eprintln!("commxd: contained panic at {at}");
    }));
}

/// Run `f`, converting a panic into `Err`. The caller decides what fault
/// domain to sacrifice (usually: nuke the room `f` was working on).
pub fn contain<T>(f: impl FnOnce() -> T) -> Result<T, ()> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|_| ())
}

/// Keep a long-lived service loop running: if it panics or returns, log and
/// restart it with exponential backoff (reset after 30 s of healthy uptime).
pub fn supervise<F, Fut>(name: &'static str, mut make: F)
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut backoff = Duration::from_millis(100);
        loop {
            let started = Instant::now();
            match tokio::spawn(make()).await {
                Ok(()) => eprintln!("commxd: {name} stopped; restarting"),
                Err(e) if e.is_panic() => eprintln!("commxd: {name} crashed; restarting"),
                Err(_) => return, // cancelled: runtime shutting down
            }
            if started.elapsed() > Duration::from_secs(30) {
                backoff = Duration::from_millis(100);
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(10));
        }
    });
}

/// Pause after an I/O error in an accept/recv loop, so a persistent error
/// (e.g. out of file descriptors) can't spin a core at 100%.
pub async fn io_backoff() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn contain_catches_panics() {
        install_panic_hook();
        assert_eq!(contain(|| 7), Ok(7));
        assert!(contain(|| -> u8 { panic!("boom") }).is_err());
    }

    #[tokio::test]
    async fn supervised_loop_is_restarted_after_panic() {
        install_panic_hook();
        let runs = Arc::new(AtomicU32::new(0));
        let r = runs.clone();
        supervise("test-loop", move || {
            let r = r.clone();
            async move {
                if r.fetch_add(1, Ordering::SeqCst) < 2 {
                    panic!("injected");
                }
                std::future::pending::<()>().await;
            }
        });
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 3, "restarted twice, then healthy");
    }
}
