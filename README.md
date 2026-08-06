<p align="center">
  <img src="assets/amwallgithub.png" alt="amwall" width="270" />
</p>

<p align="center">
  <a href="https://github.com/amrust/amwall/releases/latest"><img src="https://img.shields.io/github/v/release/amrust/amwall?style=flat-square&label=version&color=blue" alt="version" /></a>
  <a href="https://github.com/amrust/amwall/releases"><img src="https://img.shields.io/github/downloads/amrust/amwall/total?style=flat-square&label=downloads&color=brightgreen" alt="downloads" /></a>
  <a href="https://github.com/amrust/amwall/issues"><img src="https://img.shields.io/github/issues/amrust/amwall?style=flat-square&label=issues&color=yellow" alt="issues" /></a>
  <a href="https://github.com/amrust/amwall/graphs/contributors"><img src="https://img.shields.io/github/contributors/amrust/amwall?style=flat-square&label=contributors&color=brightgreen" alt="contributors" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/amrust/amwall?style=flat-square&label=license&color=orange" alt="license" /></a>
</p>

<p align="center">
  <a href="https://github.com/amrust/amwall/releases/latest/download/amwall-x86_64.msi">
    <img src="https://img.shields.io/badge/Download_amwall-Windows_x64_MSI-1976d2?style=for-the-badge&logo=windows&logoColor=white" alt="Download amwall for Windows" />
  </a>
</p>

<p align="center">
  <img src="assets/screenshot.png" alt="amwall main window" />
</p>

# amwall

A Rust port of [simplewall](https://github.com/henrypp/simplewall), a lightweight tool for configuring [Windows Filtering Platform (WFP)](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) — the kernel-level network filtering API that sits underneath Windows Firewall.

> **Status:** Live progress and roadmap tracked in [issue #1](https://github.com/amrust/amwall/issues/1). Installer downloads at [Releases](https://github.com/amrust/amwall/releases).

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

## Linux port (development)

A Linux port lives under `linux/` (BPF LSM daemon + Qt6 GUI). It's pre-release — no .deb on the Releases page yet, only a self-bootstrapping build script at the repo root: [`linux-build.sh`](linux-build.sh).

The script installs every toolchain dep (Rust nightly + clang/llvm + qt6-base-dev + cargo-deb + bpf-linker), edits GRUB to enable the BPF LSM, builds the daemon + CLI + Qt6 GUI, runs 7 smoke tests, and `dpkg -i`s the resulting `.deb`. Re-runnable from any Mint 22 / Ubuntu 24.04 VM snapshot — APT/Rust steps no-op when already satisfied.

### One-liner: fetch + run latest

From the VM, after every push from this repo:

```bash
sudo systemctl stop amwall-daemon 2>/dev/null; SHA=$(curl -fsSL https://api.github.com/repos/amrust/amwall/commits/main | python3 -c 'import json,sys;print(json.load(sys.stdin)["sha"])') && curl -fsSL https://raw.githubusercontent.com/amrust/amwall/$SHA/linux-build.sh -o ~/linux-build.sh && bash ~/linux-build.sh
```

What it does, step by step:

1. **Stop the daemon** so the in-place reinstall can replace `/usr/bin/amwall-daemon`. Also un-blocks the curl that follows (the daemon's default-deny would otherwise drop it). Trailing `;` (not `&&`) so a fresh-snapshot run with no service unit installed yet still proceeds.
2. **Resolve the current `main` HEAD SHA** via the GitHub API. Required because `https://raw.githubusercontent.com/.../main/...` is CDN-cached for ~5 minutes per push and serving stale content during that window will run an outdated script.
3. **Fetch the script by exact SHA** — content-addressable, never cached stale.
4. **Run it.** Output is teed to `~/amwall-run.log` (full build/test transcript). On completion the script ends with a live combined tail of the daemon journal (`journalctl -fu amwall-daemon`) + GUI log (`~/.local/share/amwall/gui.log`) — Ctrl-C to exit.

### Knobs

- `AMWALL_SKIP_INSTALL=1` — skip `dpkg -i` + service restart; useful when iterating on smoke tests without churning systemd.
- `AMWALL_NO_LOG=1` — disable the `~/amwall-run.log` tee.
- `AMWALL_LOG_FILE=/path/to/log` — override the run-log location.
- `XDG_DATA_HOME=...` — moves the GUI runtime log target (default `~/.local/share/amwall/gui.log`).

### Network reset between iterations

Accumulated rules.toml entries (allow/deny clicks from the connect prompt) and `~/.config/amwall/` (Qt settings) can be wiped without a snapshot rollback:

```bash
sudo amwall-cli reset --yes                # both
sudo amwall-cli reset --yes --keep-rules   # GUI config only
sudo amwall-cli reset --yes --keep-config  # rules only
```

The build script's auto-install step calls `reset --yes` automatically before each `dpkg -i`, so back-to-back runs are clean by default.

### Logs

| Source | Path | How to read |
|---|---|---|
| `linux-build.sh` (full run transcript) | `~/amwall-run.log` | `cat ~/amwall-run.log` |
| `amwall-daemon` (allow/deny, D-Bus, BPF) | systemd journal | `journalctl -fu amwall-daemon` |
| `amwall-gui` (Qt qDebug/qWarning, crashes) | `~/.local/share/amwall/gui.log` | `tail -F ~/.local/share/amwall/gui.log` |
| GUI coredumps (if any) | systemd-coredump | `coredumpctl info amwall-gui` |

`~/.local/share/amwall/gui.log` is the XDG equivalent of Windows amwall's `%APPDATA%\amwall\swaplog.txt`.

### Phase progress

Tracked in the trailing banner of [`linux-build.sh`](linux-build.sh). High level: Phases 1–6.4 complete (BPF LSM default-deny enforcement, D-Bus interface with polkit gating, `.deb` packaging via cargo-deb, Qt6 GUI with status dashboard, per-comm connect prompts with whole-app wildcard rules, User Rules tab). Pending: Connections / Packets log / Apps / Settings tabs, i18n, and a BPF tweak to read `task->group_leader->comm` so multi-thread apps (Firefox's `DNS Resolver #N`) collapse to one prompt instead of one per thread.

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

## Diagnostics

```
amwall.exe -diagnostics [profile.xml] [-out <file>]
```

Prints a read-only self-check and saves a copy to `%APPDATA%\amwall\amwall-diagnostics.txt`
(next to the exe in portable mode). It reports how every app path in the profile resolves on
*this* machine, whether each entry would get a WFP permit, whether any localized column header is
wider than the width its column is created at, and — when elevated — what amwall currently has in
the kernel, enumerated by `providerKey`.

Nothing is installed, removed, or written to the profile. It is deliberately not admin-gated:
requiring elevation would change the thing being measured, so the kernel section is simply skipped
(and says so) when run as a normal user. The exit code is 0 whenever a report was produced —
script against the `[verdict]` lines, not the exit status.

This is the fastest way to confirm a build behaves correctly on real hardware, and the right thing
to attach to a bug report.

## Roadmap

Tracked in GitHub issues. The high-level milestones are:

1. WFP bindings — wrap `fwpuclnt.dll` and provider/sublayer/filter primitives via `windows-rs`
2. Profile I/O — read/write upstream `profile.xml` format
3. Rules engine — parse rule strings, compile to WFP filter conditions
4. CLI surface — `-install`, `-install -temp`, `-install -silent`, `-uninstall`, `-diagnostics`
5. GUI — equivalent of the Win32 main window, rules editor, log viewer
6. Notifications — packet-drop notifications and logging
7. Internal blocklist — load `profile_internal.sp`
8. Localization — 42 languages via `rust-i18n` with auto-detect
9. Installer + portable mode parity

## Localization

amwall ships with **42 languages** embedded at compile time via [`rust-i18n`](https://crates.io/crates/rust-i18n). The app auto-detects the Windows user locale on first launch and persists the choice to `settings.txt`.

### Supported languages

Arabic, Armenian, Azerbaijani, Belarusian, Bulgarian *(planned)*, Catalan, Chinese (Simplified), Chinese (Traditional), Czech, Danish, Dutch, English, Estonian, Finnish, French, Georgian, German, Greek, Hungarian, Indonesian, Italian, Japanese, Kazakh, Korean, Kyrgyz, Latvian, Lithuanian, Norwegian *(planned)*, Persian, Polish, Portuguese, Portuguese (Brazil), Romanian, Russian, Serbian (Cyrillic), Serbian (Latin), Slovak, Slovenian, Spanish, Swedish, Thai, Turkish, Ukrainian, Vietnamese.

### Adding a new language

1. **Copy** `locales/en.toml` to `locales/<code>.toml` (use [ISO 639-1](https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes) codes, e.g. `bg.toml`; for regional variants use `<lang>-<REGION>.toml`, e.g. `pt-BR.toml`).
2. **Translate** all values. Rules:
   - Keys stay exactly the same (only translate values)
   - Keep `%{variable}` placeholders verbatim (`%{count}`, `%{name}`, `%{signer}`, etc.)
   - Keep keyboard shortcuts as-is (`\tCtrl+P`, `\tF5`, `\tEnter`, `\tDel`)
   - Keep technical terms in English: TCP, UDP, ICMP, IPv4, IPv6, SHA-256, WFP, UAC, XML, UWP, loopback, amwall, simplewall, GitHub
   - Place `&` accelerator on an appropriate character for menu mnemonics (CJK languages: remove `&`)
   - Use `\"` for embedded quotes — do **not** use typographic quotes (`"` `"` `„`) inside TOML basic strings, as they break the parser
   - Multi-line strings (`"""..."""`) for `wizard.body` must have the closing `"""` on its own line
3. **Add a display name** in `src/gui/settings_dialog.rs` → `locale_display_name()` so the Settings dropdown shows the native name (e.g. `"bg" => "Български"`).
4. **Rebuild** — `cargo build` picks up new `.toml` files automatically (the `build.rs` watches the `locales/` directory).
5. **Verify** — `cargo build` will fail at compile time if the TOML is malformed. If it builds, the strings are embedded.

### How it works

- `rust_i18n::i18n!("locales", fallback = "en")` in `src/lib.rs` embeds all `locales/*.toml` at compile time
- `t!("key")` / `t!("key", var = val)` anywhere in GUI code returns the localized string
- `build.rs` declares `cargo:rerun-if-changed=locales` so adding/editing any `.toml` triggers recompilation
- On first launch, `GetUserDefaultLocaleName()` detects the Windows locale, maps it to the best available locale (exact match > base language > regional variant), and persists the choice
- Language can be changed at runtime via Settings > Language; the app restarts automatically to apply

### Testing locale files

```
# Build catches malformed TOML at compile time:
cargo build

# Run the test suite (localization is compile-time, no runtime test needed):
cargo test

# Validate a single file without a full build (requires Python 3.11+):
python -c "import tomllib; tomllib.load(open('locales/bg.toml', 'rb')); print('OK')"
```

Common TOML pitfalls that cause `"Parse file failed"`:
- Unescaped `"` inside a basic string (use `\"`)
- Typographic quotes (`"` U+201C, `"` U+201D, `„` U+201E) that look like ASCII `"` to the parser
- Backslash not followed by a valid escape (`\n`, `\t`, `\\`, `\"`)
- `"""` inside a multi-line string without escaping

## Contributing

Issues and PRs welcome.

**Scope.** amwall started as a strict parity port of upstream [henrypp/simplewall v3.8.7](https://github.com/henrypp/simplewall) and v1.0 reached that bar. From v1.1 onward the scope expanded to also include **community-wishlist items upstream has accepted but not shipped** — features that have an open issue / "+1" history in the henrypp/simplewall tracker but that henrypp hasn't had time to land. New mechanisms with no upstream basis (proprietary protocols, paid features, alternative profile formats, etc.) remain out of scope. When in doubt, cross-reference the upstream issue tracker before opening a PR.

**Local setup.**

- Rust 1.85 or newer (matches `rust-version` in [Cargo.toml](Cargo.toml))
- Windows SDK (any recent version; the `windows` crate handles version differences)
- WiX Toolset 3.x if you intend to build the MSI installer locally — `choco install wixtoolset -y` from an elevated shell

**Gate triad** — every PR must pass these locally and they're re-run on every release tag:

```
cargo build --release --target x86_64-pc-windows-msvc
cargo clippy --all-targets --target x86_64-pc-windows-msvc -- -D warnings
cargo test --target x86_64-pc-windows-msvc
```

The release workflow won't produce an MSI if any of these fail, so a PR that breaks them blocks releases for everyone.

**Live testing.** Many WFP behaviours can't be exercised from `cargo test` because they require admin and a live Base Filtering Engine. Tests that fall in this bucket are marked `#[ignore]` with a justification — run them with `cargo test -- --ignored` from an elevated shell. The "Build + run amwall ELEVATED" VS Code task captures stderr to `swaplog.txt` for live-session debugging.

**PR conventions.**

- Conventional-style subject line (e.g. `gui: M11.2 explicit is_silent gate`, `wfp: fix CNDL0104`)
- Commit body explains the *why* and references the upstream behaviour being matched (file + line in henrypp/simplewall when relevant)
- Reference [issue #1](https://github.com/amrust/amwall/issues/1) for milestone-shaped work
- Don't squash-merge series of milestone commits — the per-milestone history is load-bearing for the parity-tracking issue

**Reporting bugs.** Filter-management failures usually surface in `swaplog.txt` (alongside the exe in portable mode, or `%APPDATA%\amwall\swaplog.txt` in installed mode). Attach it to issues. For a snapshot of the kernel filter state at the time of the bug, run `netsh wfp show filters` from an elevated shell and attach `filters.xml`.

## Not affiliated

amwall is an independent re-implementation. It is not affiliated with, endorsed by, or sponsored by Henry++ or the original simplewall project. For the original C version, go to [henrypp/simplewall](https://github.com/henrypp/simplewall).
