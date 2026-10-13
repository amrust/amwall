//! Snapshot guard for user decisions arriving from asynchronous prompt windows.
use crate::profile::App;

/// Metadata such as a freshly-computed hash baseline or comment does not
/// change the user's permission decision. Existing hash changes invalidate
/// a pending prompt because they can represent executable drift.
pub(super) fn decision_unchanged(current: &App, expected: &App) -> bool {
    current.path == expected.path
        && current.timestamp == expected.timestamp
        && current.is_enabled == expected.is_enabled
        && current.is_silent == expected.is_silent
        && current.timer == expected.timer
        && (expected.hash.is_none() || current.hash == expected.hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App {
            path: r"C:\test.exe".into(),
            is_enabled: false,
            is_silent: false,
            is_undeletable: false,
            timestamp: 1,
            timer: 0,
            hash: None,
            comment: None,
        }
    }

    #[test]
    fn permission_and_identity_edits_invalidate_a_prompt_snapshot() {
        let expected = app();
        assert!(decision_unchanged(&expected, &expected));
        for edit in 0..5 {
            let mut current = expected.clone();
            match edit {
                0 => current.path = r"C:\other.exe".into(),
                1 => current.timestamp += 1,
                2 => current.is_enabled = true,
                3 => current.is_silent = true,
                4 => current.timer = 123,
                _ => unreachable!(),
            }
            assert!(!decision_unchanged(&current, &expected));
        }
    }

    #[test]
    fn hash_baseline_metadata_does_not_cancel_but_known_hash_changes_do() {
        let expected = app();
        let mut current = expected.clone();
        current.hash = Some("initial baseline".into());
        current.comment = Some("description".into());
        assert!(decision_unchanged(&current, &expected));
        let expected = current.clone();
        current.hash = Some("changed executable".into());
        assert!(!decision_unchanged(&current, &expected));
    }
}
