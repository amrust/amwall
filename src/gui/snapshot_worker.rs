//! One background operation at a time, with no queue of obsolete refresh requests.
use std::cell::Cell;
use std::sync::mpsc::{self, Receiver, SyncSender};

pub(super) struct SnapshotWorker<T> {
    requests: SyncSender<()>,
    results: Receiver<T>,
    pending: Cell<bool>,
}

impl<T: Send + 'static> SnapshotWorker<T> {
    pub(super) fn new(
        mut collect: impl FnMut() -> T + Send + 'static,
        wake: impl Fn() + Send + 'static,
    ) -> Self {
        let (requests, rx) = mpsc::sync_channel(1);
        let (tx, results) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            while rx.recv().is_ok() {
                if tx.send(collect()).is_err() {
                    break;
                }
                wake();
            }
        });
        Self {
            requests,
            results,
            pending: Cell::new(false),
        }
    }

    pub(super) fn request(&self) {
        if !self.pending.get() && self.requests.try_send(()).is_ok() {
            self.pending.set(true);
        }
    }

    pub(super) fn take_ready(&self) -> Option<T> {
        let result = self.results.try_recv().ok()?;
        self.pending.set(false);
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn slow_work_never_blocks_or_builds_a_refresh_backlog() {
        let (release, hold) = mpsc::channel();
        let (completed, done) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let work_calls = calls.clone();
        let worker = SnapshotWorker::new(
            move || {
                work_calls.fetch_add(1, Ordering::SeqCst);
                hold.recv().unwrap_or(0)
            },
            move || {
                let _ = completed.send(());
            },
        );
        for _ in 0..1000 {
            worker.request();
        }
        assert!(worker.take_ready().is_none());
        release.send(17).unwrap();
        done.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(worker.take_ready(), Some(17));
        assert!(!worker.pending.get());
        worker.request();
        release.send(29).unwrap();
        done.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(worker.take_ready(), Some(29));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn dropping_a_window_does_not_wait_for_slow_collection_or_post_its_result() {
        let (entered, running) = mpsc::channel();
        let (release, hold) = mpsc::channel();
        let (finished, exited) = mpsc::channel();
        let (wake, woke) = mpsc::channel();
        let worker = SnapshotWorker::new(
            move || {
                entered.send(()).unwrap();
                hold.recv().unwrap();
                let _ = finished.send(());
            },
            move || {
                let _ = wake.send(());
            },
        );
        worker.request();
        running.recv_timeout(Duration::from_secs(2)).unwrap();
        // Drop must return while the worker is still blocked above.
        drop(worker);
        release.send(()).unwrap();
        exited.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(woke.recv_timeout(Duration::from_secs(2)).is_err());
    }
}
