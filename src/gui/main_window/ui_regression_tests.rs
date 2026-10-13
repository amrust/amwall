//! Real common-control regressions. No App, firewall engine or user settings
//! are opened; all controls are owned by a hidden, disposable test window.
use super::super::column_layout::ColumnLayout;
use super::*;
use windows::Win32::UI::Controls::{LVIS_FOCUSED, LVM_GETCOLUMNWIDTH, LVM_SCROLL};
use windows::Win32::UI::WindowsAndMessaging::{GWL_STYLE, GetScrollPos, GetWindowLongW, SB_HORZ};

struct TestWindow(HWND);

fn prompt_test_state() -> (WndState, crate::profile::App) {
    use std::cell::RefCell;
    let item = crate::profile::App {
        path: r"C:\amwall-prompt-test.exe".into(),
        is_enabled: false,
        is_silent: false,
        is_undeletable: false,
        timestamp: 123,
        timer: 0,
        hash: None,
        comment: None,
    };
    let mut profile = super::super::empty_profile();
    profile.apps.push(item.clone());
    let app = Box::new(App {
        profile: RefCell::new(profile),
        profile_path: RefCell::new(Default::default()),
        internal_profile: super::super::empty_profile(),
        settings: RefCell::new(Default::default()),
        settings_path: RefCell::new(Default::default()),
        internal_rules_state: RefCell::new(Default::default()),
        internal_rules_state_path: RefCell::new(Default::default()),
    });
    (WndState::with_net_meter(app, None), item)
}

fn prompt_token(app: &crate::profile::App, id: u64) -> WPARAM {
    WPARAM(super::super::msg_slab::stash(
        super::super::connect_dialog::PromptEvent {
            path: app.path.clone(),
            id,
        },
    ))
}

fn reserve_test_prompt(state: &WndState, app: &crate::profile::App, id: u64) {
    state.pending_prompts.borrow_mut().insert(
        app.path.clone(),
        PendingPrompt {
            id,
            app: app.clone(),
            parent: HWND::default(),
        },
    );
}

#[test]
fn notification_allow_commits_permission_before_changing_profile_or_caches() {
    let (state, app) = prompt_test_state();
    state.app.settings.borrow_mut().use_hashes = false;
    state.filters_active.set(true);
    state.amwall_filter_ids.borrow_mut().insert(10);
    state.categorized_filter_ids.borrow_mut().per_app.push(10);
    let failed = allow_prompt_app(&state, &app.path, |candidate| {
        assert!(candidate.is_enabled);
        assert!(!state.app.profile.borrow().apps[0].is_enabled);
        Err(crate::wfp::WfpError::FilterAdd(5).into())
    });
    assert!(failed.is_err());
    assert!(!state.app.profile.borrow().apps[0].is_enabled);
    assert_eq!(state.amwall_filter_ids.borrow().len(), 1);
    assert_eq!(state.categorized_filter_ids.borrow().per_app, vec![10]);
    assert!(state.filters_active.get());

    assert!(
        allow_prompt_app(&state, &app.path, |_| {
            assert!(!state.app.profile.borrow().apps[0].is_enabled);
            Ok(vec![20, 21, 22, 23])
        })
        .unwrap()
    );
    assert!(state.app.profile.borrow().apps[0].is_enabled);
    assert_eq!(state.amwall_filter_ids.borrow().len(), 5);
    assert_eq!(
        state.categorized_filter_ids.borrow().per_app,
        vec![10, 20, 21, 22, 23]
    );
    assert!(!allow_prompt_app(&state, &app.path, |_| panic!("duplicate permit")).unwrap());
}

#[test]
fn notification_allow_with_filters_off_only_records_the_explicit_choice() {
    let (state, app) = prompt_test_state();
    state.app.settings.borrow_mut().use_hashes = false;
    assert!(allow_prompt_app(&state, &app.path, |_| panic!("filters are off")).unwrap());
    assert!(state.app.profile.borrow().apps[0].is_enabled);
    assert!(state.amwall_filter_ids.borrow().is_empty());
}

#[test]
fn profile_save_skips_hashing_and_periodic_baselines_are_persisted() {
    let (state, _) = prompt_test_state();
    let root = std::env::temp_dir().join(format!(
        "amwall-hash-save-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let executable = root.join("app.exe");
    let profile_path = root.join("profile.xml");
    std::fs::write(&executable, b"baseline test").unwrap();
    state.app.profile.borrow_mut().apps[0].path = executable.clone();
    *state.app.profile_path.borrow_mut() = profile_path.clone();
    assert!(state.app.settings.borrow().use_hashes);

    save_profile_to_disk(&state);
    assert!(
        state.app.profile.borrow().apps[0].hash.is_none(),
        "catalog saves must not read executables"
    );
    check_hash_drift(HWND::default(), &state);
    let baseline = crate::hash::sha256_file(&executable).unwrap();
    assert_eq!(
        state.app.profile.borrow().apps[0].hash.as_ref(),
        Some(&baseline)
    );
    assert!(
        std::fs::read_to_string(&profile_path)
            .unwrap()
            .contains(&baseline)
    );
    assert!(!state.app.profile.borrow().apps[0].is_enabled);
    std::fs::remove_file(executable).unwrap();
    std::fs::remove_file(profile_path).unwrap();
    std::fs::remove_dir(root).unwrap();
}

#[test]
fn prompt_generations_reject_old_clicks_and_old_close_notifications() {
    let window = TestWindow::new();
    let (state, app) = prompt_test_state();
    reserve_test_prompt(&state, &app, 2);
    assert!(take_current_prompt(&state, prompt_token(&app, 1)).is_none());
    assert_eq!(state.pending_prompts.borrow().get(&app.path).unwrap().id, 2);
    unsafe {
        SetWindowLongPtrW(window.0, GWLP_USERDATA, &state as *const _ as isize);
    }
    on_connect_prompt_closed(window.0, prompt_token(&app, 1));
    assert!(state.pending_prompts.borrow().contains_key(&app.path));
    assert_eq!(
        take_current_prompt(&state, prompt_token(&app, 2)),
        Some(app.path.clone())
    );
    assert!(
        take_current_prompt(&state, prompt_token(&app, 2)).is_none(),
        "each prompt choice is consumed once"
    );
    unsafe {
        SetWindowLongPtrW(window.0, GWLP_USERDATA, 0);
    }
}

#[test]
fn prompt_choices_cannot_override_edits_undo_or_profile_replacement() {
    let (state, app) = prompt_test_state();
    for (id, block) in [(10, true), (11, false)] {
        reserve_test_prompt(&state, &app, id);
        {
            let mut profile = state.app.profile.borrow_mut();
            if block {
                profile.apps[0].is_silent = true;
            } else {
                profile.apps[0].is_enabled = true;
            }
        }
        cancel_changed_prompts(&state);
        state.app.profile.borrow_mut().apps[0] = app.clone();
        assert!(
            take_current_prompt(&state, prompt_token(&app, id)).is_none(),
            "undoing a newer decision must not revive the older prompt"
        );
    }
    reserve_test_prompt(&state, &app, 12);
    state.app.profile.borrow_mut().apps[0].hash = Some("initial baseline".into());
    assert!(
        take_current_prompt(&state, prompt_token(&app, 12)).is_some(),
        "computing a first hash baseline does not change the user's decision"
    );
    state.app.profile.borrow_mut().apps[0] = app.clone();
    reserve_test_prompt(&state, &app, 13);
    cancel_all_prompts(&state);
    state.app.profile.borrow_mut().apps[0] = app.clone();
    assert!(take_current_prompt(&state, prompt_token(&app, 13)).is_none());
    assert!(state.pending_prompts.borrow().is_empty());
}

#[test]
fn event_bursts_yield_without_losing_the_remaining_events() {
    let (tx, rx) = std::sync::mpsc::channel();
    for _ in 0..EVENT_DRAIN_BATCH * 2 + 1 {
        tx.send(crate::wfp::events::NetEvent::Other(0)).unwrap();
    }
    assert_eq!(receive_event_batch(&rx).len(), EVENT_DRAIN_BATCH);
    assert_eq!(receive_event_batch(&rx).len(), EVENT_DRAIN_BATCH);
    assert_eq!(receive_event_batch(&rx).len(), 1);
    assert!(receive_event_batch(&rx).is_empty());
}
impl TestWindow {
    fn new() -> Self {
        unsafe {
            InitCommonControlsEx(&INITCOMMONCONTROLSEX {
                dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
                dwICC: ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES,
            })
            .unwrap();
            let parent = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("STATIC"),
                w!("amwall UI regression"),
                WS_OVERLAPPEDWINDOW,
                0,
                0,
                800,
                400,
                HWND::default(),
                HMENU::default(),
                GetModuleHandleW(PCWSTR::null()).unwrap(),
                None,
            );
            assert_ne!(parent.0, 0);
            Self(parent)
        }
    }

    fn listview(&self, id: i32) -> HWND {
        let lv = create_tab_listview(self.0, id).unwrap();
        unsafe {
            MoveWindow(lv, 0, 0, 500, 260, false).unwrap();
        }
        configure_listview(lv, id, 96).unwrap();
        lv
    }
}
impl Drop for TestWindow {
    fn drop(&mut self) {
        unsafe {
            let _ = DestroyWindow(self.0);
        }
    }
}

fn rows(lv: HWND, ids: impl IntoIterator<Item = usize>) {
    for (row, id) in ids.into_iter().enumerate() {
        let mut text = wide(&format!("process-{id}"));
        let item = LVITEMW {
            mask: LVIF_TEXT | LVIF_PARAM,
            iItem: row as i32,
            pszText: PWSTR(text.as_mut_ptr()),
            lParam: LPARAM(id as isize),
            ..Default::default()
        };
        unsafe {
            SendMessageW(
                lv,
                LVM_INSERTITEMW,
                WPARAM(0),
                LPARAM(&item as *const _ as isize),
            );
        }
        set_subitem(lv, row as i32, 1, "127.0.0.1");
        set_subitem(lv, row as i32, 3, &id.to_string());
        set_subitem(lv, row as i32, 7, "TCP");
    }
}

#[test]
fn native_refill_keeps_hidden_tabs_hidden_and_preserves_user_state() {
    let window = TestWindow::new();
    let active = window.listview(IDC_NETWORK);
    let hidden = window.listview(IDC_LOG);
    rows(active, 0..40);
    rows(hidden, 0..5);
    unsafe {
        ShowWindow(active, SW_SHOW);
    }

    for _ in 0..3 {
        let snapshot = begin_listview_refill(hidden);
        rows(hidden, 0..5);
        end_listview_refill(hidden, snapshot, 5);
        assert_eq!(
            unsafe { GetWindowLongW(hidden, GWL_STYLE) } as u32 & WS_VISIBLE.0,
            0,
            "refreshing a background tab must not expose it above the active tab"
        );
    }

    let flags = LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0 | LVIS_FOCUSED.0);
    let selection = LVITEMW {
        stateMask: flags,
        state: flags,
        ..Default::default()
    };
    unsafe {
        SendMessageW(
            active,
            LVM_SETITEMSTATE,
            WPARAM(10),
            LPARAM(&selection as *const _ as isize),
        );
        SendMessageW(active, LVM_ENSUREVISIBLE, WPARAM(25), LPARAM(0));
        SendMessageW(active, LVM_SCROLL, WPARAM(250), LPARAM(0));
    }
    let horizontal = unsafe { GetScrollPos(active, SB_HORZ) };
    assert!(horizontal > 0);
    let snapshot = begin_listview_refill(active);
    let top_key = snapshot.top_key.clone();
    assert!(snapshot.top > 0);
    rows(active, (0..40).rev());
    end_listview_refill(active, snapshot, 40);
    assert_ne!(
        unsafe { GetWindowLongW(active, GWL_STYLE) } as u32 & WS_VISIBLE.0,
        0
    );
    assert_eq!(
        selected_rows(active, -1),
        vec![29],
        "selection follows process-10 through sorting"
    );
    assert_eq!(
        unsafe {
            SendMessageW(
                active,
                LVM_GETITEMSTATE,
                WPARAM(29),
                LPARAM(LVIS_FOCUSED.0 as isize),
            )
        }
        .0 as u32,
        LVIS_FOCUSED.0
    );
    assert_eq!(unsafe { GetScrollPos(active, SB_HORZ) }, horizontal);
    let top = unsafe { SendMessageW(active, LVM_GETTOPINDEX, WPARAM(0), LPARAM(0)) }.0 as usize;
    assert_eq!(
        row_identities(active).get(top),
        top_key.as_ref(),
        "scroll anchor follows its row"
    );

    // If the selected connection disappears, don't transfer selection to the
    // unrelated connection that happens to occupy the same index.
    let snapshot = begin_listview_refill(active);
    rows(active, (0..40).filter(|id| *id != 10));
    end_listview_refill(active, snapshot, 39);
    assert!(selected_rows(active, -1).is_empty());
}

#[test]
fn native_column_layouts_round_trip_all_views_and_dpi() {
    let window = TestWindow::new();
    let mut settings = super::super::settings::Settings::default();
    for (slot, id) in TAB_LISTVIEW_IDS.iter().copied().enumerate() {
        let lv = window.listview(id);
        let count = listview_column_count(lv) as usize;
        let layout = ColumnLayout {
            widths: (0..count)
                .map(|c| 100 + slot as i32 * 20 + c as i32 * 10)
                .collect(),
            order: (0..count as i32).rev().collect(),
        };
        layout.apply(lv, count, 144);
        assert_eq!(ColumnLayout::capture(lv, count, 144), Some(layout.clone()));
        settings.column_layouts[slot] = Some(layout);
        settings.manual_columns[slot] = (0..count).map(|col| col % 2 == 0).collect();
    }
    let path = std::env::temp_dir().join(format!(
        "amwall-layout-regression-{}.txt",
        std::process::id()
    ));
    settings.save(&path).unwrap();
    let loaded = super::super::settings::Settings::load(&path);
    std::fs::remove_file(path).unwrap();
    assert_eq!(loaded, settings);
    for (slot, id) in TAB_LISTVIEW_IDS.iter().copied().enumerate() {
        let lv = window.listview(id);
        let layout = loaded.column_layouts[slot].as_ref().unwrap();
        layout.apply(lv, layout.widths.len(), 192);
        assert_eq!(
            ColumnLayout::capture(lv, layout.widths.len(), 192).as_ref(),
            Some(layout)
        );
        assert_eq!(
            unsafe { SendMessageW(lv, LVM_GETCOLUMNWIDTH, WPARAM(0), LPARAM(0)) }.0 as i32,
            layout.widths[0] * 2
        );
    }
}

#[test]
fn native_toolbar_wrap_uses_its_real_rectangle() {
    let window = TestWindow::new();
    let controls = toolbar::create(window.0, 96).unwrap();
    let wide_height = toolbar::layout(controls.toolbar, 1200);
    let narrow_height = toolbar::layout(controls.toolbar, 300);
    assert!(
        narrow_height > wide_height,
        "buttons must wrap at narrow widths"
    );
    for width in [1000, 450, 300, 700, 1200] {
        let height = toolbar::layout(controls.toolbar, width);
        let mut rect = RECT::default();
        unsafe {
            GetClientRect(controls.toolbar, &mut rect).unwrap();
        }
        assert_eq!(rect.right, width);
        assert_eq!(rect.bottom, height);
        assert_eq!(height, toolbar::toolbar_layout_height(controls.toolbar));
    }
}

/// Route only persistence messages in this fixture. In particular WM_CREATE,
/// WM_DESTROY and firewall/event timer handlers never run.
unsafe extern "system" fn persistence_parent_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    if msg == WM_SAVE_COLUMN_LAYOUT || (msg == WM_TIMER && wparam.0 == TIMER_SAVE_COLUMNS) {
        unsafe { wnd_proc(hwnd, msg, wparam, lparam) }
    } else {
        unsafe { windows::Win32::UI::Shell::DefSubclassProc(hwnd, msg, wparam, lparam) }
    }
}

#[test]
fn native_header_changes_save_after_commit_and_survive_auto_refresh() {
    use std::cell::RefCell;
    use windows::Win32::UI::Controls::{
        HDN_ENDDRAG, LVM_SETCOLUMNORDERARRAY, LVM_SETCOLUMNWIDTH, NMHEADERW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{DispatchMessageW, MSG, PM_REMOVE, PeekMessageW};
    let window = TestWindow::new();
    let path = std::env::temp_dir().join(format!(
        "amwall-header-regression-{}.txt",
        std::process::id()
    ));
    let app = Box::new(App {
        profile: RefCell::new(super::super::empty_profile()),
        profile_path: RefCell::new(Default::default()),
        internal_profile: super::super::empty_profile(),
        settings: RefCell::new(Default::default()),
        settings_path: RefCell::new(path.clone()),
        internal_rules_state: RefCell::new(Default::default()),
        internal_rules_state_path: RefCell::new(Default::default()),
    });
    let state = WndState::with_net_meter(app, None);
    state.initializing.set(false);
    let lv = window.listview(IDC_NETWORK);
    state.listviews[6].set(lv);
    unsafe {
        SetWindowLongPtrW(window.0, GWLP_USERDATA, &state as *const _ as isize);
        let suggested = RECT {
            left: 0,
            top: 0,
            right: 800,
            bottom: 400,
        };
        on_dpi_changed(
            window.0,
            WPARAM(192),
            LPARAM(&suggested as *const _ as isize),
        );
        assert!(
            state.app.settings.borrow().column_layouts[6].is_none(),
            "DPI changes must not mark an unvisited view as initialized"
        );
        assert_eq!(
            SendMessageW(lv, LVM_GETCOLUMNWIDTH, WPARAM(0), LPARAM(0)).0,
            360
        );
        on_dpi_changed(
            window.0,
            WPARAM(96),
            LPARAM(&suggested as *const _ as isize),
        );
        assert!(
            windows::Win32::UI::Shell::SetWindowSubclass(
                window.0,
                Some(persistence_parent_proc),
                1,
                0
            )
            .as_bool()
        );
        assert!(
            windows::Win32::UI::Shell::SetWindowSubclass(lv, Some(listview_header_proc), 1, 0)
                .as_bool()
        );
        // The native header emits ITEMCHANGED, just as it does during a divider drag.
        SendMessageW(lv, LVM_SETCOLUMNWIDTH, WPARAM(0), LPARAM(375));
        let header = HWND(SendMessageW(lv, LVM_GETHEADER, WPARAM(0), LPARAM(0)).0);
        let mut item = windows::Win32::UI::Controls::HDITEMW {
            mask: windows::Win32::UI::Controls::HDI_ORDER,
            iOrder: 11,
            ..Default::default()
        };
        let notice = NMHEADERW {
            hdr: NMHDR {
                hwndFrom: header,
                idFrom: 0,
                code: HDN_ENDDRAG,
            },
            pitem: &mut item,
            ..Default::default()
        };
        // ENDDRAG arrives before the control commits the new order.
        SendMessageW(
            lv,
            WM_NOTIFY,
            WPARAM(0),
            LPARAM(&notice as *const _ as isize),
        );
        let order: Vec<i32> = (0..12).rev().collect();
        SendMessageW(
            lv,
            LVM_SETCOLUMNORDERARRAY,
            WPARAM(12),
            LPARAM(order.as_ptr() as isize),
        );
        let mut msg = MSG::default();
        let mut saves = 0;
        while PeekMessageW(
            &mut msg,
            window.0,
            WM_SAVE_COLUMN_LAYOUT,
            WM_SAVE_COLUMN_LAYOUT,
            PM_REMOVE,
        )
        .as_bool()
        {
            DispatchMessageW(&msg);
            saves += 1;
        }
        assert!(saves > 0, "header notifications must reach persistence");
        SendMessageW(window.0, WM_TIMER, WPARAM(TIMER_SAVE_COLUMNS), LPARAM(0));
        let _ = KillTimer(window.0, TIMER_SAVE_COLUMNS);
    }
    let loaded = super::super::settings::Settings::load(&path);
    let layout = loaded.column_layouts[6]
        .as_ref()
        .expect("saved connections layout");
    assert_eq!(layout.widths[0], 375);
    assert_eq!(layout.order, (0..12).rev().collect::<Vec<_>>());
    autosize_listview_slot(&state, 6);
    let refreshed = ColumnLayout::capture(lv, 12, 96).unwrap();
    assert_eq!(
        refreshed.widths[0], layout.widths[0],
        "refresh must respect manual width"
    );
    assert_eq!(
        refreshed.order, layout.order,
        "refresh must respect column order"
    );
    assert!(
        loaded.manual_columns[6][0],
        "manual divider change must persist"
    );
    assert!(loaded.manual_columns[6][1..].iter().all(|fixed| !fixed));
    unsafe {
        SetWindowLongPtrW(window.0, GWLP_USERDATA, 0);
        windows::Win32::UI::Shell::RemoveWindowSubclass(window.0, Some(persistence_parent_proc), 1);
    }
    std::fs::remove_file(path).unwrap();
}
