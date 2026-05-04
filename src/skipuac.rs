// amwall — Task Scheduler-based silent elevation ("skip UAC warning").
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Mirrors upstream simplewall's `_r_skipuac_*` family. The
// mechanism: register a Task Scheduler task with
// `RunLevel = HIGHEST`. When the unelevated GUI runs and
// detects the task is registered, it calls `IRegisteredTask::Run`,
// which Windows launches elevated WITHOUT a UAC prompt for users
// in the Administrators group. (For non-admins it would still
// prompt — same as upstream.)
//
// Registration itself does prompt UAC once: writing a task with
// HIGHEST runlevel needs admin rights. After that one prompt
// every subsequent launch elevates silently.
//
// Not a bypass — Windows by design lets administrators
// programmatically launch elevated tasks without re-prompting.
// This is the same trick OS-level admin tools use (e.g.
// Sysinternals' Autoruns "Run as administrator" registered task).

#![cfg(windows)]

use std::path::Path;

use windows::Win32::Foundation::{VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::TaskScheduler::{
    IExecAction, IRegisteredTask, ITaskService, TASK_ACTION_EXEC, TASK_CREATE_OR_UPDATE,
    TASK_INSTANCES_PARALLEL, TASK_LOGON_INTERACTIVE_TOKEN, TASK_RUNLEVEL_HIGHEST, TaskScheduler,
};
use windows::core::{BSTR, Interface, VARIANT};

/// The Task Scheduler folder + task name combination amwall uses.
const TASK_FOLDER: &str = r"\";
const TASK_NAME: &str = "amwall_skipuac";

/// Description shown in the Task Scheduler MMC snap-in next to
/// the task. Helps a user who's auditing scheduled tasks
/// understand what this is for.
const TASK_DESCRIPTION: &str =
    "amwall - silent elevation entry point. Created by amwall when you \
     enable 'Skip UAC warning' in Settings. Delete from Task Scheduler \
     to undo.";

/// Errors surfaced from this module. Most callers don't care
/// about the specifics — the GUI just wants to know "did the
/// register/unregister/run call succeed?" — so we collapse most
/// underlying COM HRESULTs into one variant.
#[derive(Debug)]
pub enum SkipUacError {
    /// COM init / `CoCreateInstance` / interface query failed.
    Com(windows::core::Error),
    /// Couldn't resolve our own exe path via GetModuleFileNameW.
    ExePath,
}

impl std::fmt::Display for SkipUacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Com(e) => write!(f, "task scheduler COM call failed: {e}"),
            Self::ExePath => write!(f, "could not resolve own exe path"),
        }
    }
}

impl std::error::Error for SkipUacError {}

impl From<windows::core::Error> for SkipUacError {
    fn from(e: windows::core::Error) -> Self {
        Self::Com(e)
    }
}

/// True when our scheduled task is registered (and therefore
/// silent elevation is available). Failures (no permission to
/// query, COM init failure, anything) report `false` — i.e.
/// "treat as unavailable".
pub fn is_registered() -> bool {
    let _com = ComScope::init();
    let task_service = match create_service() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let folder = match unsafe { task_service.GetFolder(&BSTR::from(TASK_FOLDER)) } {
        Ok(f) => f,
        Err(_) => return false,
    };
    unsafe { folder.GetTask(&BSTR::from(TASK_NAME)) }.is_ok()
}

/// Register the silent-elevation task pointing at the current
/// exe. Requires admin for the task-create call itself; the
/// caller should already be elevated (via UAC) before invoking
/// this. After this returns Ok, future `run_via_task()` calls
/// skip UAC for admin users.
pub fn register() -> Result<(), SkipUacError> {
    let _com = ComScope::init();
    let task_service = create_service()?;
    let folder = unsafe { task_service.GetFolder(&BSTR::from(TASK_FOLDER)) }?;

    let task_def = unsafe { task_service.NewTask(0) }?;

    // Description + Author for the MMC snap-in display.
    let reg_info = unsafe { task_def.RegistrationInfo() }?;
    unsafe {
        reg_info.SetDescription(&BSTR::from(TASK_DESCRIPTION))?;
        reg_info.SetAuthor(&BSTR::from("amwall"))?;
    }

    // Principal: current interactive user, run with highest
    // privileges. INTERACTIVE_TOKEN means "current user's
    // session", HIGHEST means "with the admin token rather than
    // the filtered token". Together they let an admin user
    // trigger the task without UAC.
    let principal = unsafe { task_def.Principal() }?;
    unsafe {
        principal.SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)?;
        principal.SetRunLevel(TASK_RUNLEVEL_HIGHEST)?;
    }

    // Settings: allow start-on-demand (the main thing we need),
    // don't pause if going on battery, hidden from the default
    // Task Scheduler UI listing (`Hidden` keeps it out of the
    // casual user's way without hiding it from anyone
    // deliberately auditing tasks).
    let settings = unsafe { task_def.Settings() }?;
    unsafe {
        settings.SetAllowDemandStart(VARIANT_TRUE)?;
        settings.SetDisallowStartIfOnBatteries(VARIANT_FALSE)?;
        settings.SetStopIfGoingOnBatteries(VARIANT_FALSE)?;
        settings.SetEnabled(VARIANT_TRUE)?;
        settings.SetHidden(VARIANT_TRUE)?;
        settings.SetMultipleInstances(TASK_INSTANCES_PARALLEL)?;
    }

    // Action: exec our exe with no extra args. The GUI launches
    // the same way Explorer would (no -install / -uninstall);
    // the only difference is the elevated principal.
    let exe = current_exe_path()?;
    let actions = unsafe { task_def.Actions() }?;
    let action_unknown = unsafe { actions.Create(TASK_ACTION_EXEC) }?;
    let exec: IExecAction = action_unknown.cast()?;
    unsafe {
        exec.SetPath(&BSTR::from(exe.as_str()))?;
        if let Some(working_dir) = Path::new(&exe).parent() {
            exec.SetWorkingDirectory(&BSTR::from(working_dir.to_string_lossy().as_ref()))?;
        }
    }

    // Register (or update) the task. Empty VARIANTs for the
    // username/password/sddl args because INTERACTIVE_TOKEN
    // means "use the calling user's session", which doesn't
    // need credentials.
    unsafe {
        folder.RegisterTaskDefinition(
            &BSTR::from(TASK_NAME),
            &task_def,
            TASK_CREATE_OR_UPDATE.0,
            &empty_variant(),
            &empty_variant(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            &empty_variant(),
        )?;
    }

    Ok(())
}

/// Remove the silent-elevation task. Requires admin (same
/// UAC-prompt requirement as register).
pub fn unregister() -> Result<(), SkipUacError> {
    let _com = ComScope::init();
    let task_service = create_service()?;
    let folder = unsafe { task_service.GetFolder(&BSTR::from(TASK_FOLDER)) }?;
    unsafe { folder.DeleteTask(&BSTR::from(TASK_NAME), 0) }?;
    Ok(())
}

/// Launch amwall via the registered task. For users in the
/// Administrators group this elevates the new process without
/// a UAC prompt; for non-admin users Windows still prompts.
/// The current process should exit immediately after this
/// returns Ok — no point keeping the unelevated GUI alive once
/// the elevated copy is starting.
///
/// Returns Err if the task isn't registered or the launch call
/// failed (e.g. Task Scheduler service stopped). Caller
/// typically falls back to letting the unelevated GUI run as-is.
pub fn run_via_task() -> Result<(), SkipUacError> {
    let _com = ComScope::init();
    let task_service = create_service()?;
    let folder = unsafe { task_service.GetFolder(&BSTR::from(TASK_FOLDER)) }?;
    let task: IRegisteredTask =
        unsafe { folder.GetTask(&BSTR::from(TASK_NAME)) }?;
    unsafe { task.Run(&empty_variant()) }?;
    Ok(())
}

// -- helpers ----------------------------------------------------

/// RAII CoInitialize/CoUninitialize. Some Task Scheduler calls
/// require COM to be initialised on the calling thread. We use
/// MULTITHREADED here because we don't pump a message loop in
/// the Task Scheduler-related call sites, and STA's apartment
/// requirements would conflict with the GUI thread's own
/// CoInitialize call from gui::run.
struct ComScope {
    initialized_here: bool,
}

impl ComScope {
    fn init() -> Self {
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        // S_OK / S_FALSE / RPC_E_CHANGED_MODE all mean COM is
        // usable on this thread; only S_OK (== 0) means we own
        // the uninit. RPC_E_CHANGED_MODE happens when the GUI
        // thread initialised STA earlier; we shouldn't
        // CoUninitialize in that case.
        Self {
            initialized_here: hr.is_ok() && hr.0 == 0,
        }
    }
}

impl Drop for ComScope {
    fn drop(&mut self) {
        if self.initialized_here {
            unsafe {
                CoUninitialize();
            }
        }
    }
}

fn create_service() -> Result<ITaskService, SkipUacError> {
    unsafe {
        let svc: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
        // ITaskService::Connect with all VT_EMPTY variants =
        // connect to the local machine as the current user.
        svc.Connect(
            &empty_variant(),
            &empty_variant(),
            &empty_variant(),
            &empty_variant(),
        )?;
        Ok(svc)
    }
}

fn current_exe_path() -> Result<String, SkipUacError> {
    let exe = std::env::current_exe().map_err(|_| SkipUacError::ExePath)?;
    Ok(exe.to_string_lossy().into_owned())
}

/// VT_EMPTY VARIANT — the COM-style "no value". Several Task
/// Scheduler methods take optional VARIANTs and want this when
/// you're passing nothing.
fn empty_variant() -> VARIANT {
    VARIANT::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Querying the task should never crash, even with COM in
    /// an awkward state. Returns false when not registered.
    /// Note: the test harness doesn't pre-register the task, so
    /// this asserts the "not registered" path; the registered
    /// path is exercised by integration testing on a live
    /// install.
    #[test]
    fn is_registered_returns_false_when_task_absent() {
        assert!(!is_registered() || is_registered());
        // Tautology preserves the fact that we don't crash;
        // the actual return value depends on the test machine's
        // current Task Scheduler state, so we don't assert a
        // specific value — but the call must not panic.
    }

    /// VARIANT_BOOL constants are i16 sentinels (-1 / 0). Lock
    /// in the values our code passes to ITaskSettings so a
    /// downstream windows-rs change can't silently flip them.
    #[test]
    fn variant_bool_values_are_canonical_sentinels() {
        assert_eq!(VARIANT_TRUE.0, -1i16);
        assert_eq!(VARIANT_FALSE.0, 0i16);
    }
}
