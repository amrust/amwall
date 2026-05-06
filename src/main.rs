// amwall — CLI entry point.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version. See LICENSE.
//
// Subcommands (matching upstream's flag style):
//   amwall.exe -install [profile.xml] [-temp] [-silent]
//   amwall.exe -uninstall [-silent]
//   amwall.exe -h | --help
//
// Both -install and -uninstall require Administrator privileges
// (filter management is admin-gated by WFP). When run unelevated
// the binary prints an error and exits 1; auto-relaunch via
// ShellExecuteW "runas" is a follow-up.
//
// Subsystem: windows (not console). Without `windows_subsystem =
// "windows"`, launching the GUI from Explorer / Start Menu briefly
// flashes a console window. The trade-off is that CLI subcommands
// (-install / -uninstall / -h) won't show output unless we
// explicitly attach to the parent process's console first — see
// `cli::run` which calls `attach_to_parent_console` before any
// println!/eprintln! fires.

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    cli::run(std::env::args().collect())
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("amwall is Windows-only (Windows Filtering Platform).");
    std::process::ExitCode::from(1)
}

#[cfg(windows)]
mod cli {
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;

    use amwall::install;
    use amwall::profile;
    use amwall::wfp::WfpEngine;
    use windows::Win32::UI::Shell::IsUserAnAdmin;
    use windows::core::PCWSTR;

    /// Parsed command line. The CLI is small enough that a hand-
    /// rolled argparse + this enum is leaner than pulling in `clap`.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Command {
        /// No arguments — launch the GUI.
        Gui,
        /// `-h` / `--help` — print usage and exit 0.
        Help,
        /// `-install [path] [-temp] [-silent]`.
        Install {
            path: Option<PathBuf>,
            /// `-temp`: install volatile filters that the kernel
            /// removes when the engine session ends or on next
            /// reboot. Default (without `-temp`) is persistent.
            temp: bool,
            /// `-silent`: suppress success output (errors still
            /// printed). Exit code remains the source of truth.
            silent: bool,
        },
        /// `-uninstall [-silent]`.
        Uninstall { silent: bool },
        /// `-skipuac-register` — register the Task Scheduler entry
        /// that lets unelevated launches relaunch silently as
        /// admin. Requires admin (auto-elevated via UAC). Used by
        /// the Settings -> Skip UAC warning toggle when the user
        /// turns it on.
        SkipUacRegister,
        /// `-skipuac-unregister` — remove the entry above.
        SkipUacUnregister,
        /// Argparse failed with a message — print to stderr, exit 2.
        Error(String),
    }

    /// Pure parse: `Vec<String>` (`std::env::args` collected) →
    /// `Command`. No I/O, no Win32, no exit codes — purely structural
    /// so it can be unit-tested without admin or WFP.
    pub fn parse_args(args: Vec<String>) -> Command {
        // args[0] is the program name; subcommand is args[1].
        if args.len() < 2 {
            return Command::Gui;
        }
        match args[1].as_str() {
            "-h" | "--help" => Command::Help,
            "-install" => parse_install_flags(&args[2..]),
            "-uninstall" => parse_uninstall_flags(&args[2..]),
            "-skipuac-register" => Command::SkipUacRegister,
            "-skipuac-unregister" => Command::SkipUacUnregister,
            other => Command::Error(format!("unknown command `{other}`")),
        }
    }

    fn parse_install_flags(rest: &[String]) -> Command {
        let mut path: Option<PathBuf> = None;
        let mut temp = false;
        let mut silent = false;
        for tok in rest {
            match tok.as_str() {
                "-temp" => temp = true,
                "-silent" => silent = true,
                s if s.starts_with('-') => {
                    return Command::Error(format!(
                        "unknown flag `{s}` for -install"
                    ));
                }
                s => {
                    if let Some(prev) = &path {
                        return Command::Error(format!(
                            "multiple profile paths given: `{}` and `{s}`",
                            prev.display()
                        ));
                    }
                    path = Some(PathBuf::from(s));
                }
            }
        }
        Command::Install { path, temp, silent }
    }

    fn parse_uninstall_flags(rest: &[String]) -> Command {
        let mut silent = false;
        for tok in rest {
            match tok.as_str() {
                "-silent" => silent = true,
                s if s.starts_with('-') => {
                    return Command::Error(format!(
                        "unknown flag `{s}` for -uninstall"
                    ));
                }
                s => {
                    return Command::Error(format!(
                        "unexpected argument `{s}` for -uninstall"
                    ));
                }
            }
        }
        Command::Uninstall { silent }
    }

    pub fn run(args: Vec<String>) -> ExitCode {
        let parsed = parse_args(args);
        // GUI mode (no CLI subcommand): redirect stdout + stderr
        // to a fresh timestamped session log under
        // `%APPDATA%\amwall\logs\` so eprintln!s aren't lost in
        // installed mode (windows_subsystem = "windows" leaves
        // stderr pointing at INVALID_HANDLE_VALUE by default).
        // The session log includes OS / RAM / CPU info in its
        // header to make bug reports actionable.
        //
        // CLI mode (-install / -uninstall / -h / etc.): keep the
        // parent-console attach so operation output reaches the
        // calling shell. Sending those messages to a log file
        // would surprise scripted callers who pipe stderr.
        if matches!(parsed, Command::Gui) {
            amwall::logging::init_debug_log();
        } else {
            attach_to_parent_console();
        }
        match parsed {
            // No CLI subcommand → launch the GUI. The GUI doesn't
            // require admin to start (admin is only needed for the
            // install/uninstall actions, which the GUI routes
            // through the same code paths the CLI uses).
            Command::Gui => amwall::gui::run(default_profile_path()),
            Command::Help => {
                print_usage();
                ExitCode::from(0)
            }
            Command::Install { path, temp, silent } => {
                if let Err(exit) = ensure_admin(silent) {
                    return exit;
                }
                let resolved = path.unwrap_or_else(default_profile_path);
                handle_install(&resolved, temp, silent)
            }
            Command::Uninstall { silent } => {
                if let Err(exit) = ensure_admin(silent) {
                    return exit;
                }
                handle_uninstall(silent)
            }
            Command::SkipUacRegister => {
                if let Err(exit) = ensure_admin(true) {
                    return exit;
                }
                match amwall::skipuac::register() {
                    Ok(()) => ExitCode::from(0),
                    Err(e) => {
                        eprintln!("amwall: skipuac register failed: {e}");
                        ExitCode::from(1)
                    }
                }
            }
            Command::SkipUacUnregister => {
                if let Err(exit) = ensure_admin(true) {
                    return exit;
                }
                match amwall::skipuac::unregister() {
                    Ok(()) => ExitCode::from(0),
                    Err(e) => {
                        eprintln!("amwall: skipuac unregister failed: {e}");
                        ExitCode::from(1)
                    }
                }
            }
            Command::Error(msg) => {
                eprintln!("amwall: {msg}");
                print_usage();
                ExitCode::from(2)
            }
        }
    }

    /// Attach this (windows-subsystem) process to the parent
    /// process's console, if any, so println!/eprintln! show up
    /// in the launching shell. After AttachConsole succeeds we
    /// re-fetch the standard handles via SetStdHandle so Rust's
    /// stdio picks up the freshly-attached console — without that
    /// step the Win32 docs say handles are usually inherited but
    /// in practice with windows_subsystem = "windows" the std
    /// handles start as INVALID_HANDLE_VALUE and need the explicit
    /// re-bind.
    ///
    /// No-op when launched without a parent console (Explorer /
    /// Start Menu / a service host) — AttachConsole returns Err
    /// and we silently skip the redirect.
    fn attach_to_parent_console() {
        use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
        use windows::Win32::System::Console::{
            ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_ERROR_HANDLE,
            STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
        };

        // Skip the AttachConsole + re-bind dance if our parent
        // already gave us valid stdio handles via a redirect like
        // `cmd /c amwall 2>> log`. In that case STD_ERROR_HANDLE
        // already points at the log file; calling AttachConsole +
        // SetStdHandle would overwrite it with the parent's console
        // buffer, sending eprintln! to the visible console instead
        // of the redirected file.
        unsafe {
            let stderr = GetStdHandle(STD_ERROR_HANDLE).unwrap_or_default();
            let already_redirected =
                stderr.0 != 0 && stderr != INVALID_HANDLE_VALUE && stderr != HANDLE(0);
            if already_redirected {
                return;
            }
            if AttachConsole(ATTACH_PARENT_PROCESS).is_err() {
                return;
            }
            for std_id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
                if let Ok(h) = GetStdHandle(std_id) {
                    let _ = SetStdHandle(std_id, h);
                }
            }
        }
    }

    /// Ensure the current process is elevated. If it is, return
    /// `Ok(())` and the caller proceeds. If not, request UAC
    /// elevation by re-launching this same exe via ShellExecuteExW
    /// with the `runas` verb, wait for the elevated child to
    /// finish, then return `Err(ExitCode::from(child_exit_code))`
    /// so the caller forwards it. On UAC denial or other failure,
    /// print an error and return `Err(ExitCode::from(1))`.
    ///
    /// Output limitation: the elevated child runs in its own
    /// session/console (Windows enforces this for security) — its
    /// stdout/stderr won't appear in this shell. The parent's exit
    /// code is the source of truth. With `windows_subsystem =
    /// "windows"` and AttachConsole(ATTACH_PARENT_PROCESS), the
    /// elevated child has no parent console to attach to, so any
    /// `println!`/`eprintln!` it emits is silently discarded. This
    /// matches upstream simplewall's behavior.
    fn ensure_admin(silent: bool) -> Result<(), ExitCode> {
        if unsafe { IsUserAnAdmin() }.as_bool() {
            return Ok(());
        }
        if !silent {
            eprintln!("amwall: requesting elevation via UAC...");
        }
        match relaunch_elevated() {
            Ok(code) => Err(ExitCode::from(code)),
            Err(e) => {
                eprintln!("amwall: elevation failed: {e}");
                eprintln!("       Re-run from an elevated PowerShell or Command Prompt.");
                Err(ExitCode::from(1))
            }
        }
    }

    /// Re-launch the current exe with the same argv, elevated via
    /// the `runas` verb. Blocks until the child finishes; returns
    /// the child's exit code, clamped to `u8` for `ExitCode`. Errors
    /// surface as `Err(msg)` — typically UAC denial (the user hit
    /// Cancel on the prompt) or, more rarely, a missing exe path.
    fn relaunch_elevated() -> Result<u8, String> {
        use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{
            GetExitCodeProcess, INFINITE, WaitForSingleObject,
        };
        use windows::Win32::UI::Shell::{
            SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
        };
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        let exe = current_exe_path_wide()
            .ok_or_else(|| "GetModuleFileNameW returned 0".to_string())?;
        let params = build_relaunch_params();
        // Null-terminated wide "runas".
        let verb: Vec<u16> = "runas\0".encode_utf16().collect();

        let mut sei = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: PCWSTR(verb.as_ptr()),
            lpFile: PCWSTR(exe.as_ptr()),
            lpParameters: PCWSTR(params.as_ptr()),
            nShow: SW_SHOWNORMAL.0,
            ..Default::default()
        };

        unsafe { ShellExecuteExW(&mut sei) }
            .map_err(|e| format!("ShellExecuteExW(runas) failed: {e}"))?;

        let proc: HANDLE = sei.hProcess;
        if proc.0 == 0 {
            return Err("UAC accepted but child handle is null".to_string());
        }

        let wait = unsafe { WaitForSingleObject(proc, INFINITE) };
        let mut code: u32 = 1;
        if wait == WAIT_OBJECT_0 {
            let _ = unsafe { GetExitCodeProcess(proc, &mut code) };
        }
        let _ = unsafe { CloseHandle(proc) };

        // ExitCode::from takes u8. Cap at 255; values > 255 are
        // unusual but safe to truncate since we only forward the
        // child's "did it work" signal.
        Ok((code & 0xFF) as u8)
    }

    /// Path to the current process's exe, as a null-terminated wide
    /// buffer suitable for `PCWSTR`. Returns `None` if Win32 fails.
    fn current_exe_path_wide() -> Option<Vec<u16>> {
        use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
        let mut buf = vec![0u16; 1024];
        let n = unsafe { GetModuleFileNameW(None, &mut buf) };
        if n == 0 || (n as usize) >= buf.len() {
            return None;
        }
        buf.truncate(n as usize);
        buf.push(0);
        Some(buf)
    }

    /// Build a Windows command line from `args`, with each
    /// space/tab/quote-containing arg wrapped in `"…"` and internal
    /// `"` escaped to `\"`, matching `CommandLineToArgvW` parsing
    /// rules. Args without special chars pass through verbatim.
    /// Empty args render as `""` (preserved as a positional empty).
    pub(super) fn build_command_line(args: &[String]) -> String {
        let mut s = String::new();
        for (i, a) in args.iter().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            if a.is_empty() || a.contains(' ') || a.contains('\t') || a.contains('"') {
                s.push('"');
                for ch in a.chars() {
                    if ch == '"' {
                        s.push('\\');
                    }
                    s.push(ch);
                }
                s.push('"');
            } else {
                s.push_str(a);
            }
        }
        s
    }

    /// Wide null-terminated form of this process's argv (minus
    /// argv[0]), suitable for `SHELLEXECUTEINFOW.lpParameters`.
    fn build_relaunch_params() -> Vec<u16> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let s = build_command_line(&args);
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        wide
    }

    fn handle_install(path: &Path, temp: bool, silent: bool) -> ExitCode {
        let xml = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "amwall: failed to read profile at {}: {e}",
                    path.display()
                );
                return ExitCode::from(1);
            }
        };
        let profile = match profile::parse_str(&xml) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("amwall: profile parse failed: {e}");
                return ExitCode::from(1);
            }
        };
        let engine = match WfpEngine::open() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("amwall: WFP engine open failed: {e}");
                return ExitCode::from(1);
            }
        };
        // `-temp` flips the persistent flag off — filters become
        // volatile and the kernel removes them on next reboot.
        let persistent = !temp;
        match install::install_profile(&engine, &profile, persistent) {
            Ok(report) => {
                if !silent {
                    let mode = if temp { "temporary" } else { "persistent" };
                    println!(
                        "amwall: installed {} filter(s); skipped {} rule(s) ({mode}).",
                        report.filters_added, report.rules_skipped,
                    );
                }
                ExitCode::from(0)
            }
            Err(e) => {
                eprintln!("amwall: install failed: {e}");
                ExitCode::from(1)
            }
        }
    }

    fn handle_uninstall(silent: bool) -> ExitCode {
        let engine = match WfpEngine::open() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("amwall: WFP engine open failed: {e}");
                return ExitCode::from(1);
            }
        };
        match install::uninstall(&engine) {
            Ok(report) => {
                if !silent {
                    println!(
                        "amwall: removed {} filter(s), {} sublayer(s); provider {}.",
                        report.filters_deleted,
                        report.sublayers_deleted,
                        if report.provider_deleted {
                            "removed"
                        } else {
                            "not present"
                        },
                    );
                }
                ExitCode::from(0)
            }
            Err(e) => {
                eprintln!("amwall: uninstall failed: {e}");
                ExitCode::from(1)
            }
        }
    }

    /// Default profile-file location. In installed mode this is
    /// `%APPDATA%\amwall\profile.xml`; in portable mode (M9.1 —
    /// `amwall.ini` next to the exe) it's `<exe_dir>\profile.xml`.
    /// Routed through `crate::paths::profile_path` so the two
    /// layouts stay in lock-step with the rest of the per-user
    /// state (settings, log).
    fn default_profile_path() -> PathBuf {
        amwall::paths::profile_path()
    }

    fn print_usage() {
        println!("amwall — Rust port of simplewall (Windows Filtering Platform)");
        println!();
        println!("usage:");
        println!("    amwall.exe -install [profile.xml] [-temp] [-silent]");
        println!("        Load profile.xml (or %APPDATA%\\amwall\\profile.xml)");
        println!("        and install its rules into the kernel.");
        println!("        -temp    install volatile filters that go away on reboot");
        println!("        -silent  suppress success output (errors still printed)");
        println!("        Requires Administrator.");
        println!();
        println!("    amwall.exe -uninstall [-silent]");
        println!("        Remove every filter / sublayer / provider that");
        println!("        amwall has installed. Requires Administrator.");
        println!();
        println!("    amwall.exe -h | --help");
        println!("        Print this help.");
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn args(extra: &[&str]) -> Vec<String> {
            std::iter::once("amwall.exe")
                .chain(extra.iter().copied())
                .map(String::from)
                .collect()
        }

        #[test]
        fn no_args_launches_gui() {
            assert_eq!(parse_args(args(&[])), Command::Gui);
        }

        #[test]
        fn dash_h_is_help() {
            assert_eq!(parse_args(args(&["-h"])), Command::Help);
            assert_eq!(parse_args(args(&["--help"])), Command::Help);
        }

        #[test]
        fn install_no_flags() {
            let cmd = parse_args(args(&["-install"]));
            assert_eq!(
                cmd,
                Command::Install { path: None, temp: false, silent: false }
            );
        }

        #[test]
        fn install_with_path() {
            let cmd = parse_args(args(&["-install", "C:\\path\\profile.xml"]));
            assert_eq!(
                cmd,
                Command::Install {
                    path: Some(PathBuf::from("C:\\path\\profile.xml")),
                    temp: false,
                    silent: false,
                }
            );
        }

        #[test]
        fn install_with_temp_and_silent() {
            let cmd = parse_args(args(&["-install", "-temp", "-silent"]));
            assert_eq!(
                cmd,
                Command::Install { path: None, temp: true, silent: true }
            );
        }

        #[test]
        fn install_flag_order_is_arbitrary() {
            // Path between flags works.
            let cmd = parse_args(args(&["-install", "-temp", "p.xml", "-silent"]));
            assert_eq!(
                cmd,
                Command::Install {
                    path: Some(PathBuf::from("p.xml")),
                    temp: true,
                    silent: true,
                }
            );
        }

        #[test]
        fn install_unknown_flag_errors() {
            match parse_args(args(&["-install", "-bogus"])) {
                Command::Error(msg) => assert!(msg.contains("-bogus")),
                other => panic!("expected Error, got {other:?}"),
            }
        }

        #[test]
        fn install_two_paths_errors() {
            match parse_args(args(&["-install", "a.xml", "b.xml"])) {
                Command::Error(msg) => {
                    assert!(msg.contains("multiple profile paths"))
                }
                other => panic!("expected Error, got {other:?}"),
            }
        }

        #[test]
        fn uninstall_no_flags() {
            assert_eq!(
                parse_args(args(&["-uninstall"])),
                Command::Uninstall { silent: false }
            );
        }

        #[test]
        fn uninstall_silent() {
            assert_eq!(
                parse_args(args(&["-uninstall", "-silent"])),
                Command::Uninstall { silent: true }
            );
        }

        #[test]
        fn uninstall_with_unexpected_arg_errors() {
            match parse_args(args(&["-uninstall", "stray"])) {
                Command::Error(msg) => assert!(msg.contains("stray")),
                other => panic!("expected Error, got {other:?}"),
            }
        }

        #[test]
        fn unknown_command_errors() {
            match parse_args(args(&["-frob"])) {
                Command::Error(msg) => assert!(msg.contains("-frob")),
                other => panic!("expected Error, got {other:?}"),
            }
        }

        // ---- build_command_line (M4.6 elevated-relaunch helper) ----

        fn s(strs: &[&str]) -> Vec<String> {
            strs.iter().map(|s| s.to_string()).collect()
        }

        #[test]
        fn build_command_line_simple_args() {
            assert_eq!(build_command_line(&s(&["-install"])), "-install");
            assert_eq!(
                build_command_line(&s(&["-install", "-temp"])),
                "-install -temp",
            );
        }

        #[test]
        fn build_command_line_empty_args_yields_empty_string() {
            assert_eq!(build_command_line(&[]), "");
        }

        #[test]
        fn build_command_line_quotes_args_with_spaces() {
            assert_eq!(
                build_command_line(&s(&["-install", "C:\\Program Files\\p.xml"])),
                r#"-install "C:\Program Files\p.xml""#,
            );
        }

        #[test]
        fn build_command_line_escapes_internal_quotes() {
            assert_eq!(
                build_command_line(&s(&[r#"a"b"#])),
                r#""a\"b""#,
            );
        }

        #[test]
        fn build_command_line_preserves_empty_arg_as_empty_quotes() {
            // An empty positional should round-trip through
            // CommandLineToArgvW as one empty arg, not vanish.
            assert_eq!(build_command_line(&s(&["-x", "", "-y"])), r#"-x "" -y"#);
        }
    }
}
