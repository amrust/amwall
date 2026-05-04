<p align="center">
  <img src="assets/amwallgithub.png" alt="amwall" width="270" />
</p>

<p align="center">
  <img src="assets/screenshot.png" alt="amwall main window" />
</p>

# amwall

A Rust port of [simplewall](https://github.com/henrypp/simplewall), a lightweight tool for configuring [Windows Filtering Platform (WFP)](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) — the kernel-level network filtering API that sits underneath Windows Firewall.

> **Status:** v1.0.x — feature-complete parity port of upstream simplewall v3.8.7. Live progress is tracked in [issue #1](https://github.com/amrust/amwall/issues/1); installer downloads at [Releases](https://github.com/amrust/amwall/releases).

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

### Quick build (just the binary)

```
cargo build --release
```

Requires Rust 1.85+ and the Windows SDK. Output: `target\release\amwall.exe`.

### VS Code tasks (Ctrl+Shift+B)

The repo ships [`.vscode/tasks.json`](.vscode/tasks.json) with five tasks. Ctrl+Shift+B picks up the default ("Build MSI installer"); the others are reachable via Ctrl+Shift+P → **Tasks: Run Task**.

| Task | What it does |
|---|---|
| **Build MSI installer** *(default — Ctrl+Shift+B)* | Ensures cargo-wix is installed, runs `cargo build --release --target x86_64-pc-windows-msvc`, then runs `cargo wix` to produce `target\wix\amwall-<version>-x86_64.msi`. Errors out with install instructions if the WiX Toolset 3.x isn't on PATH. |
| **Reveal MSI in Explorer** | Opens `target\wix` in Explorer with the freshest MSI selected. |
| **Rebuild amwall (clean + release, stderr → swaplog.txt)** | `cargo clean` then build + run with stderr captured to `swaplog.txt` for live debugging. |
| **Build amwall (release, stderr → swaplog.txt)** | Same as Rebuild but skips `cargo clean`. Faster. |
| **Build + run amwall ELEVATED (UAC, stderr → swaplog.txt)** | Builds release, then UAC-elevates to launch `amwall.exe`. The elevated `cmd.exe` wrapper handles the stderr redirect since `Start-Process -Verb RunAs` can't pipe stdio. Helper script: [`.vscode/run-elevated.ps1`](.vscode/run-elevated.ps1). |

Building the MSI locally requires [WiX Toolset 3.x](https://github.com/wixtoolset/wix3/releases) on PATH (`candle.exe` / `light.exe`):

```
choco install wixtoolset -y    # from an elevated shell
```

### Building the MSI without VS Code

Same chain the workflow runs:

```
cargo install cargo-wix --locked
cargo build --release --target x86_64-pc-windows-msvc
cargo wix --no-build --nocapture --target x86_64-pc-windows-msvc
```

Output: `target\wix\amwall-<version>-x86_64.msi`.

## Releasing

Releases are produced by the [`release` workflow](.github/workflows/release.yml) running on `windows-latest`. It fires **only on tag push**, not on every commit. The workflow runs the full gating triad (`cargo build --release`, `cargo clippy --all-targets -- -D warnings`, `cargo test`), then `cargo wix`, then attaches the MSI to a **draft** GitHub Release.

### Cutting a release

1. **Bump the version** in [`Cargo.toml`](Cargo.toml) under `[package].version`. Update [`Cargo.lock`](Cargo.lock) by running any `cargo` command (e.g. `cargo build --release`).
2. **Commit** the bump:
   ```
   git add Cargo.toml Cargo.lock
   git commit -m "release: bump version to X.Y.Z"
   git push origin main
   ```
3. **Tag** the commit. Use an annotated tag so GitHub's release page picks up the message:
   ```
   git tag -a vX.Y.Z -m "amwall X.Y.Z - <one-line summary>"
   ```
4. **Push the tag** — this triggers the workflow:
   ```
   git push origin vX.Y.Z
   ```
5. **Watch the build** at https://github.com/amrust/amwall/actions. Cold cache: ~5–7 min. Warm: ~1–2 min.
6. **Review and publish the draft Release**. On success, a draft appears at `https://github.com/amrust/amwall/releases/tag/vX.Y.Z` with the MSI attached and auto-generated changelog. To publish:
   ```
   gh release edit vX.Y.Z --draft=false
   ```
   …or use the GitHub Releases page: **Edit** → **Set as the latest release** → **Publish release**.

The published release becomes the `releases/latest` URL. amwall's built-in update check (`Settings → Check for updates`) compares its compiled-in `CARGO_PKG_VERSION` against this and pops a notify-only dialog when a newer release exists.

### If the workflow fails

The first build chain runs on the just-pushed tag. If it fails, the tag points at a broken state with no Release attached. Two recovery paths:

- **Re-point the tag** (cleanest if no one's downloaded the broken commit yet, e.g. failures during the Build MSI step happen before the Release is created):
  ```
  git tag -d vX.Y.Z
  git push --delete origin vX.Y.Z
  # ...fix the bug, commit, push to main...
  git tag -a vX.Y.Z -m "..."
  git push origin vX.Y.Z
  ```
- **Bump to vX.Y.Z+1** if the broken release was already public (don't rewrite published history).

### MSI internals

The installer template is [`wix/main.wxs`](wix/main.wxs). It uses `WixUI_InstallDir` (Welcome → License → InstallDir → Verify → Progress → Finish), with the GPL-3.0 license text in [`wix/License.rtf`](wix/License.rtf) (regenerate from `LICENSE` with the PowerShell snippet at the top of that file's commit, if upstream's text changes). Stable GUIDs in `main.wxs` should not be regenerated — they're how the MSI recognises an upgrade vs. a fresh install.

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

amwall is an independent re-implementation. It is not affiliated with, endorsed by, or sponsored by Henry++ or the original simplewall project. For the original C version, go to [henrypp/simplewall](https://github.com/henrypp/simplewall).
