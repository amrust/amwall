# simplewall-rs

A Rust port of [simplewall](https://github.com/henrypp/simplewall), a lightweight tool for configuring [Windows Filtering Platform (WFP)](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) — the kernel-level network filtering API that sits underneath Windows Firewall.

> **Status:** Pre-alpha. Nothing works yet. This README describes the goal, not the current state.

## Goal

Reproduce the functionality of upstream `simplewall` (currently v3.8.7) in idiomatic Rust:

- Configure WFP filters to allow/block per-application network traffic
- Same default-deny posture for outbound and inbound
- Same XML profile format on disk so existing simplewall users can migrate
- Same rule syntax (IPs, CIDR, ranges, ports — see upstream README)
- GUI parity (rules editor, app list, log view, notifications)
- Internal blocklist support (Windows telemetry rules)
- IPv6, UWP/Windows Store apps, WSL, and Windows services support
- 64-bit and ARM64 Windows 7 SP1+ targets, matching upstream

## Why Rust

- Memory safety in code that interacts with kernel-level APIs and parses untrusted XML
- Stronger types around WFP's `FWPM_*` structures and GUIDs
- Easier cross-compilation to ARM64
- No new functionality vs. upstream — the port is a re-implementation, not a fork with changes

## License

GPL-3.0-or-later, same as upstream simplewall. As a derivative work, this license is required (see `NOTICE` and `LICENSE`).

Original simplewall © 2016-2026 Henry++.

## Building

```
cargo build --release
```

Requires Rust 1.85+ and the Windows SDK. Currently builds an empty placeholder binary.

## Roadmap

Tracked in GitHub issues. The high-level milestones are:

1. WFP bindings — wrap `fwpuclnt.dll` and provider/sublayer/filter primitives via `windows-rs`
2. Profile I/O — read/write upstream `profile.xml` format
3. Rules engine — parse rule strings, compile to WFP filter conditions
4. CLI surface — `-install`, `-install -temp`, `-install -silent`, `-uninstall`
5. GUI — equivalent of the Win32 main window, rules editor, log viewer
6. Notifications — packet-drop notifications and logging
7. Internal blocklist — load `profile_internal.sp`
8. Localization — load `simplewall.lng`
9. Installer + portable mode parity

## Contributing

Issues and PRs welcome once the foundation lands. For now this is scaffolding.

## Not affiliated

simplewall-rs is an independent re-implementation. It is not affiliated with, endorsed by, or sponsored by Henry++ or the original simplewall project. For the original C version, go to [henrypp/simplewall](https://github.com/henrypp/simplewall).
