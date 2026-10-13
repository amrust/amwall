//! Batch cache notifications without leaving the final partial batch invisible.
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

pub(super) const IDLE_FLUSH: Duration = Duration::from_millis(50);

pub(super) struct RefreshBatch {
    pending: usize,
    last: Instant,
}

impl RefreshBatch {
    pub(super) fn new() -> Self {
        Self {
            pending: 0,
            last: Instant::now(),
        }
    }
    /// An idle worker sleeps until work arrives. Only unreported results need
    /// a deadline; otherwise periodic wakeups waste CPU while the app is idle.
    pub(super) fn recv<T>(&self, rx: &Receiver<T>) -> Result<T, RecvTimeoutError> {
        if self.pending == 0 {
            rx.recv().map_err(|_| RecvTimeoutError::Disconnected)
        } else {
            rx.recv_timeout(IDLE_FLUSH)
        }
    }
    pub(super) fn changed(&mut self, now: Instant) -> bool {
        self.pending += 1;
        self.flush(now, self.pending >= 10)
    }
    pub(super) fn flush(&mut self, now: Instant, force: bool) -> bool {
        if self.pending > 0 && (force || now.duration_since(self.last) >= IDLE_FLUSH) {
            self.pending = 0;
            self.last = now;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_single_result_is_published_when_the_worker_goes_idle() {
        let mut batch = RefreshBatch::new();
        let now = batch.last;
        assert!(!batch.changed(now));
        assert!(!batch.flush(now + Duration::from_millis(49), false));
        assert!(batch.flush(now + IDLE_FLUSH, false));
        assert!(!batch.flush(now + IDLE_FLUSH, false));
    }

    #[test]
    fn an_idle_worker_blocks_until_real_work_arrives() {
        let (tx, rx) = std::sync::mpsc::channel();
        let (finished, result) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            finished.send(RefreshBatch::new().recv(&rx)).unwrap();
        });
        assert!(matches!(
            result.recv_timeout(IDLE_FLUSH * 2),
            Err(RecvTimeoutError::Timeout)
        ));
        tx.send(42).unwrap();
        assert_eq!(result.recv_timeout(Duration::from_secs(2)).unwrap(), Ok(42));
        thread.join().unwrap();
    }
}
