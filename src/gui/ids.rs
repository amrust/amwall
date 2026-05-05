// amwall — control & menu IDs.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Mirrors upstream simplewall's `src/resource.h` — same numeric values
// so anyone reading the upstream source side-by-side recognises the
// IDs immediately. Win32 doesn't care what number we pick, only that
// it's stable across the WndProc lifetime, but matching upstream is
// the cheapest way to keep the code reviewable against the original.
//
// Two distinct ID spaces:
//   - `IDC_*`  — child window / control IDs (HMENU on a child = ID).
//   - `IDM_*`  — menu item IDs (LOWORD of WPARAM in WM_COMMAND).
//
// Both fit in u16 (Win32 packs them into LOWORD), but we expose them
// as `i32` because that's the common usage at call sites
// (`HMENU(id as isize)`, `GetDlgItem(parent, id)`).

#![cfg(windows)]
#![allow(dead_code)]

// ---- child controls ----
//
// Upstream allocates IDC_APPS_PROFILE..IDC_LOG contiguously so a single
// range check (`>= IDC_APPS_PROFILE && <= IDC_LOG`) tells you "this
// listview is one of our tab listviews". Preserve the same layout.

pub const IDC_REBAR: i32 = 102;
pub const IDC_TOOLBAR: i32 = 103;
pub const IDC_SEARCH: i32 = 104;
pub const IDC_TAB: i32 = 105;
pub const IDC_APPS_PROFILE: i32 = 106;
pub const IDC_APPS_SERVICE: i32 = 107;
pub const IDC_APPS_UWP: i32 = 108;
pub const IDC_RULES_BLOCKLIST: i32 = 109;
pub const IDC_RULES_SYSTEM: i32 = 110;
pub const IDC_RULES_CUSTOM: i32 = 111;
pub const IDC_NETWORK: i32 = 112;
pub const IDC_LOG: i32 = 113;
pub const IDC_STATUSBAR: i32 = 114;

/// All eight tab listview IDs in display order. The slice is the
/// authoritative source for "which tabs exist" — `main_window` walks
/// it once at WM_CREATE and again at WM_SIZE.
pub const TAB_LISTVIEW_IDS: &[i32] = &[
    IDC_APPS_PROFILE,
    IDC_APPS_SERVICE,
    IDC_APPS_UWP,
    IDC_RULES_BLOCKLIST,
    IDC_RULES_SYSTEM,
    IDC_RULES_CUSTOM,
    IDC_NETWORK,
    IDC_LOG,
];

// ---- top menu (File/Edit/View/Settings/Blocklist/Help) ----
//
// Numeric values match upstream's `IDM_*` constants (resource.h:212+).
// M5.2 wires the menu structure but only IDM_EXIT actually does
// anything; the rest are stubs that flash in the WM_COMMAND handler
// for now. Real handlers land alongside their feature milestones.

// File
pub const IDM_SETTINGS: u16 = 251;
pub const IDM_ADD_FILE: u16 = 252;
pub const IDM_IMPORT: u16 = 253;
pub const IDM_EXPORT: u16 = 254;
pub const IDM_EXIT: u16 = 255;

// Edit
pub const IDM_PURGE_UNUSED: u16 = 256;
pub const IDM_PURGE_TIMERS: u16 = 257;
pub const IDM_LOGCLEAR: u16 = 258;
pub const IDM_FIND: u16 = 259;
pub const IDM_REFRESH: u16 = 260;

// View
pub const IDM_ALWAYSONTOP_CHK: u16 = 261;
pub const IDM_SHOWFILENAMESONLY_CHK: u16 = 262;
pub const IDM_SHOWSEARCHBAR_CHK: u16 = 263;
pub const IDM_AUTOSIZECOLUMNS_CHK: u16 = 264;
pub const IDM_VIEW_DETAILS: u16 = 265;
pub const IDM_VIEW_ICON: u16 = 266;
pub const IDM_VIEW_TILE: u16 = 267;
pub const IDM_SIZE_SMALL: u16 = 268;
pub const IDM_SIZE_LARGE: u16 = 269;
pub const IDM_SIZE_EXTRALARGE: u16 = 270;
pub const IDM_ICONSISHIDDEN: u16 = 271;
pub const IDM_USEDARKTHEME_CHK: u16 = 272;
pub const IDM_FONT: u16 = 273;

// Settings
pub const IDM_LOADONSTARTUP_CHK: u16 = 274;
pub const IDM_STARTMINIMIZED_CHK: u16 = 275;
pub const IDM_SKIPUACWARNING_CHK: u16 = 276;
pub const IDM_CHECKUPDATES_CHK: u16 = 277;
pub const IDM_RULE_BLOCKOUTBOUND: u16 = 278;
pub const IDM_RULE_BLOCKINBOUND: u16 = 279;
pub const IDM_RULE_ALLOWLOOPBACK: u16 = 280;
pub const IDM_RULE_ALLOW6TO4: u16 = 281;
pub const IDM_RULE_ALLOWWINDOWSUPDATE: u16 = 282;
pub const IDM_PROFILETYPE_PLAIN: u16 = 283;
pub const IDM_PROFILETYPE_COMPRESSED: u16 = 284;
pub const IDM_PROFILETYPE_ENCRYPTED: u16 = 285;
pub const IDM_USENETWORKRESOLUTION_CHK: u16 = 286;
pub const IDM_USECERTIFICATES_CHK: u16 = 287;
pub const IDM_KEEPUNUSED_CHK: u16 = 288;
pub const IDM_USEHASHES_CHK: u16 = 289;
pub const IDM_USEAPPMONITOR_CHK: u16 = 290;
/// Auto-allow Microsoft-signed binaries — amwall extension
/// (no upstream simplewall counterpart). 350-355 are the
/// listview right-click menu IDM_*; 360+ is currently
/// unallocated by both upstream and amwall, so amwall-only
/// extensions live there.
pub const IDM_AUTOALLOW_MICROSOFT_CHK: u16 = 360;

// Blocklist
pub const IDM_BLOCKLIST_SPY_DISABLE: u16 = 291;
pub const IDM_BLOCKLIST_SPY_ALLOW: u16 = 292;
pub const IDM_BLOCKLIST_SPY_BLOCK: u16 = 293;
pub const IDM_BLOCKLIST_UPDATE_DISABLE: u16 = 294;
pub const IDM_BLOCKLIST_UPDATE_ALLOW: u16 = 295;
pub const IDM_BLOCKLIST_UPDATE_BLOCK: u16 = 296;
pub const IDM_BLOCKLIST_EXTRA_DISABLE: u16 = 297;
pub const IDM_BLOCKLIST_EXTRA_ALLOW: u16 = 298;
pub const IDM_BLOCKLIST_EXTRA_BLOCK: u16 = 299;

// Help
pub const IDM_WEBSITE: u16 = 300;
pub const IDM_CHECKUPDATES: u16 = 301;
/// Replaces upstream's `IDM_DONATE` (PayPal). amwall's
/// toolbar opens our GitHub releases page instead — same numeric
/// slot, different action. See `main_window::on_command`.
pub const IDM_RELEASES: u16 = 302;
pub const IDM_ABOUT: u16 = 303;

/// Help → Emergency WFP reset. Tears down amwall's filter set,
/// wipes profile.apps + custom_rules, turns off Enable filters
/// — for users who got into a bad state and need to bail back
/// to the OS-default networking posture.
pub const IDM_EMERGENCY_RESET: u16 = 304;

// Tray menu IDs upstream uses for filter / log / notification
// toggles in main.c. Reused by our toolbar buttons since the
// toolbar mirrors the tray menu's "enable filters / packets log /
// notifications" set.
pub const IDM_TRAY_START: u16 = 305;
pub const IDM_TRAY_ENABLENOTIFICATIONS_CHK: u16 = 306;
pub const IDM_TRAY_ENABLELOG_CHK: u16 = 310;
pub const IDM_TRAY_ENABLEUILOG_CHK: u16 = 311;
pub const IDM_TRAY_LOGSHOW: u16 = 312;
pub const IDM_TRAY_LOGCLEAR: u16 = 313;

/// Tray context-menu "Show amwall" command — restores the main
/// window from hidden / minimized state. Handled in
/// `main_window::on_command`.
pub const IDM_TRAY_SHOW: u16 = 314;

// Listview-context-menu IDM upstream uses for "Create rule".
pub const IDM_OPENRULESEDITOR: u16 = 323;

// ---- listview right-click context menu (M5.4c) ----
//
// Posted as WM_COMMAND from the popup menu shown on NM_RCLICK
// over an apps / services / UWP / rules / network / log row. The
// active listview is captured at popup time and routed back through
// state so the handler can act on the right item.

pub const IDM_PROPERTIES: u16 = 350;
pub const IDM_ALLOW: u16 = 351;
pub const IDM_BLOCK: u16 = 352;
pub const IDM_REMOVE_FROM_PROFILE: u16 = 353;
pub const IDM_EXPLORE: u16 = 354;
pub const IDM_COPY: u16 = 355;
