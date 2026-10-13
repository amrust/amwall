//! Establish tamper baselines only for newly permitted executables.
use std::path::Path;

use crate::profile::{App, AppKind};

/// Existing baselines belong to the drift checker and are never refreshed
/// here. Blocked executables require no file reads during ordinary saves.
/// Returns whether any missing baseline was captured and must be persisted.
pub(super) fn capture_missing(
    apps: &mut [App],
    mut hash: impl FnMut(&Path) -> Option<String>,
) -> bool {
    let mut changed = false;
    for app in apps {
        if !app.is_enabled || app.hash.is_some() || app.kind() != AppKind::File {
            continue;
        }
        if let Some(baseline) = hash(&app.resolved_path()) {
            app.hash = Some(baseline);
            changed = true;
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(path: impl AsRef<Path>, enabled: bool, baseline: Option<&str>) -> App {
        App {
            path: path.as_ref().to_owned(),
            is_enabled: enabled,
            is_silent: false,
            is_undeletable: false,
            timestamp: 1,
            timer: 0,
            hash: baseline.map(str::to_owned),
            comment: None,
        }
    }

    #[test]
    fn existing_permissions_and_blocked_apps_need_no_file_reads() {
        let mut apps = Vec::new();
        for index in 0..100 {
            apps.push(app(
                format!(r"C:\allowed-{index}.exe"),
                true,
                Some("original"),
            ));
            apps.push(app(format!(r"C:\blocked-{index}.exe"), false, None));
        }
        apps.push(app("Dnscache", true, None));
        apps.push(app("S-1-15-2-12345", true, None));
        assert!(!capture_missing(&mut apps, |_| panic!(
            "unexpected file read"
        )));
        assert!(
            apps.iter()
                .take(200)
                .step_by(2)
                .all(|app| app.hash.as_deref() == Some("original"))
        );
    }

    #[test]
    fn one_new_permission_reads_one_file_and_keeps_existing_baselines() {
        let mut apps = vec![
            app(r"C:\existing.exe", true, Some("old trusted baseline")),
            app(r"C:\new.exe", true, None),
            app(r"C:\blocked.exe", false, None),
        ];
        let mut reads = 0;
        assert!(capture_missing(&mut apps, |path| {
            reads += 1;
            assert_eq!(path, Path::new(r"C:\new.exe"));
            Some("new baseline".into())
        }));
        assert_eq!(reads, 1);
        assert_eq!(apps[0].hash.as_deref(), Some("old trusted baseline"));
        assert_eq!(apps[1].hash.as_deref(), Some("new baseline"));
        assert!(apps[2].hash.is_none());
        assert!(!capture_missing(&mut apps, |_| panic!(
            "baseline was already captured"
        )));
    }

    #[test]
    fn unreadable_executable_retains_its_missing_baseline_and_permission() {
        let mut apps = vec![app(r"C:\unreadable.exe", true, None)];
        let mut reads = 0;
        assert!(!capture_missing(&mut apps, |_| {
            reads += 1;
            None
        }));
        assert_eq!(reads, 1);
        assert!(apps[0].hash.is_none());
        assert!(apps[0].is_enabled);
    }
}
