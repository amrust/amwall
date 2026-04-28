// simplewall-rs — CLI entry point.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version. See LICENSE.
//
// Subcommands (matching upstream's flag style):
//   simplewall-rs.exe -install [profile.xml] [-temp] [-silent]
//   simplewall-rs.exe -uninstall [-silent]
//   simplewall-rs.exe -h | --help
//
// Both -install and -uninstall require Administrator privileges
// (filter management is admin-gated by WFP). When run unelevated
// the binary prints an error and exits 1; auto-relaunch via
// ShellExecuteW "runas" is a follow-up.

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    cli::run(std::env::args().collect())
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("simplewall-rs is Windows-only (Windows Filtering Platform).");
    std::process::ExitCode::from(1)
}

#[cfg(windows)]
mod cli {
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;

    use simplewall_rs::install;
    use simplewall_rs::profile;
    use simplewall_rs::wfp::WfpEngine;
    use windows::Win32::UI::Shell::IsUserAnAdmin;

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
        match parse_args(args) {
            // No CLI subcommand → launch the GUI. The GUI doesn't
            // require admin to start (admin is only needed for the
            // install/uninstall actions, which the GUI routes
            // through the same code paths the CLI uses).
            Command::Gui => simplewall_rs::gui::run(default_profile_path()),
            Command::Help => {
                print_usage();
                ExitCode::from(0)
            }
            Command::Install { path, temp, silent } => {
                if !require_admin() {
                    return ExitCode::from(1);
                }
                let resolved = path.unwrap_or_else(default_profile_path);
                handle_install(&resolved, temp, silent)
            }
            Command::Uninstall { silent } => {
                if !require_admin() {
                    return ExitCode::from(1);
                }
                handle_uninstall(silent)
            }
            Command::Error(msg) => {
                eprintln!("simplewall-rs: {msg}");
                print_usage();
                ExitCode::from(2)
            }
        }
    }

    /// Returns true if the current process is elevated. Otherwise
    /// prints an error and returns false.
    fn require_admin() -> bool {
        let is_admin = unsafe { IsUserAnAdmin() }.as_bool();
        if !is_admin {
            eprintln!(
                "simplewall-rs: Administrator privileges required for filter management."
            );
            eprintln!("       Re-run from an elevated PowerShell or Command Prompt.");
        }
        is_admin
    }

    fn handle_install(path: &Path, temp: bool, silent: bool) -> ExitCode {
        let xml = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "simplewall-rs: failed to read profile at {}: {e}",
                    path.display()
                );
                return ExitCode::from(1);
            }
        };
        let profile = match profile::parse_str(&xml) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("simplewall-rs: profile parse failed: {e}");
                return ExitCode::from(1);
            }
        };
        let engine = match WfpEngine::open() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("simplewall-rs: WFP engine open failed: {e}");
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
                        "simplewall-rs: installed {} filter(s); skipped {} rule(s) ({mode}).",
                        report.filters_added, report.rules_skipped,
                    );
                }
                ExitCode::from(0)
            }
            Err(e) => {
                eprintln!("simplewall-rs: install failed: {e}");
                ExitCode::from(1)
            }
        }
    }

    fn handle_uninstall(silent: bool) -> ExitCode {
        let engine = match WfpEngine::open() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("simplewall-rs: WFP engine open failed: {e}");
                return ExitCode::from(1);
            }
        };
        match install::uninstall(&engine) {
            Ok(report) => {
                if !silent {
                    println!(
                        "simplewall-rs: removed {} filter(s), {} sublayer(s); provider {}.",
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
                eprintln!("simplewall-rs: uninstall failed: {e}");
                ExitCode::from(1)
            }
        }
    }

    /// Default profile-file location: `%APPDATA%\simplewall-rs\profile.xml`.
    /// Falls back to `profile.xml` in the current directory if
    /// `%APPDATA%` is unset (e.g. running as SYSTEM).
    fn default_profile_path() -> PathBuf {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            PathBuf::from(appdata)
                .join("simplewall-rs")
                .join("profile.xml")
        } else {
            PathBuf::from("profile.xml")
        }
    }

    fn print_usage() {
        println!("simplewall-rs — Rust port of simplewall (Windows Filtering Platform)");
        println!();
        println!("usage:");
        println!("    simplewall-rs.exe -install [profile.xml] [-temp] [-silent]");
        println!("        Load profile.xml (or %APPDATA%\\simplewall-rs\\profile.xml)");
        println!("        and install its rules into the kernel.");
        println!("        -temp    install volatile filters that go away on reboot");
        println!("        -silent  suppress success output (errors still printed)");
        println!("        Requires Administrator.");
        println!();
        println!("    simplewall-rs.exe -uninstall [-silent]");
        println!("        Remove every filter / sublayer / provider that");
        println!("        simplewall-rs has installed. Requires Administrator.");
        println!();
        println!("    simplewall-rs.exe -h | --help");
        println!("        Print this help.");
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn args(extra: &[&str]) -> Vec<String> {
            std::iter::once("simplewall-rs.exe")
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
    }
}
