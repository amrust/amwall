//! IP Helper, adapter and process queries belong off the window message thread.
use std::collections::HashMap;
use std::net::IpAddr;

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_APP};

use super::connections::{self, Connection, TrafficMonitor};
use super::snapshot_worker::SnapshotWorker;

pub(super) const READY: u32 = WM_APP + 31;

#[derive(Default)]
pub(super) struct NetworkSnapshot {
    pub connections: Vec<Connection>,
    pub interfaces: HashMap<IpAddr, String>,
    pub process_paths: HashMap<u32, String>,
    /// ETW rate sample attached on the UI thread exactly once when this
    /// snapshot arrives. Sorting/repainting must not advance baselines.
    pub pid_rates: HashMap<u32, (u64, u64)>,
}

pub(super) fn start(hwnd: HWND) -> SnapshotWorker<NetworkSnapshot> {
    let raw = hwnd.0;
    let mut monitor = TrafficMonitor::new();
    SnapshotWorker::new(
        move || {
            let connections = connections::enumerate_with_traffic(&mut monitor);
            let interfaces = connections::interface_names_by_ip();
            let mut paths = HashMap::new();
            for connection in &connections {
                paths.entry(connection.pid).or_insert_with(|| {
                    connections::process_full_path(connection.pid)
                        .map(|path| path.to_string_lossy().to_ascii_lowercase())
                });
            }
            NetworkSnapshot {
                connections,
                interfaces,
                process_paths: paths
                    .into_iter()
                    .filter_map(|(pid, path)| path.map(|path| (pid, path)))
                    .collect(),
                pid_rates: HashMap::new(),
            }
        },
        move || unsafe {
            let _ = PostMessageW(HWND(raw), READY, WPARAM(0), LPARAM(0));
        },
    )
}
