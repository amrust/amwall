#!/usr/bin/env bash
# amwall — Linux dev bootstrap.
#
# **POST-MIGRATION** (commit "linux: extract source out of the
# monolithic script"). The full Rust + C++/Qt6 source tree now lives
# as real files under `linux/` and `amwall-core/`. This script only
# does bootstrap + build + install + smoke + tail — no more `write_file`
# heredocs.
#
# Workflow:
#   1. git clone https://github.com/amrust/amwall ~/amwall   (first time)
#   2. cd ~/amwall && ./linux-build.sh                       (every iteration)
#   3. git pull                                              (between)
#
# Single self-contained entry point that takes a fresh Mint 22.x VM
# (post-OS-updates) all the way to "current latest phase built and
# smoke-tested." Re-runnable; APT/rustup steps no-op when satisfied.
#
# Phases this script runs end-to-end:
#   - VM setup: APT packages, Rust toolchain (stable + nightly + rust-src),
#               bpf-linker, GRUB lsm=...,bpf edit (interactive)
#   - Phase 0: linux/ workspace scaffold (5-crate Cargo workspace)
#   - Phase 1: BPF LSM observability — connect events to ring buffer
#   - Phase 2: Default-deny enforcement
#               amwall-ebpf  → RULES HashMap, 4-way wildcard lookup,
#                              -EPERM unless rule matches
#               amwall-daemon → loads rules.toml, populates BPF map,
#                              reloads on mtime change
#               amwall-cli   → allow / deny / list / del subcommands
#   - Phase 3: D-Bus interface + GUI client
#               amwall-daemon → exposes org.amwall.Daemon1 on the SYSTEM
#                              bus (root daemon can't auth onto a user
#                              session bus — EXTERNAL auth rejects when
#                              peer UID ≠ bus owner UID). Methods:
#                              Allow/Deny/Del/List + ConnectAttempt
#                              signal. Live-applies D-Bus changes to the
#                              BPF map.
#                              Policy: /etc/dbus-1/system.d/
#                              org.amwall.Daemon1.conf — root owns name,
#                              all users may call methods + receive
#                              signals (development; tighten with polkit
#                              in Phase 4).
#               amwall-cli   → --dbus flag routes through daemon
#               amwall-gui   → Phase 3 stub (subscribes + prints) —
#                              Phase 3.5 turns it into the real popup.
#   - Phase 3.5: Iced popup GUI
#               amwall-gui   → single Iced window driven by a queue of
#                              denied connection events. Allow/Deny/Skip
#                              buttons; Allow & Deny call back into the
#                              daemon via D-Bus to add a permanent rule.
#                              5-sec dedup on (comm, ip, port) so chatty
#                              processes don't flood the queue. Renders
#                              via tiny-skia (CPU) so it works in VMs
#                              without GPU passthrough. Headless mode
#                              for smoke testing: AMWALL_GUI_HEADLESS=1
#                              skips Iced and just prints signals to
#                              stderr (the original Phase 3 behavior).
#   - Phase 4: Packaging + polkit hardening
#               cargo-deb     → builds a single amwall_<ver>_amd64.deb
#                              containing /usr/bin/{amwall-daemon, -cli,
#                              -gui}, /usr/lib/amwall/amwall-ebpf.bpf,
#                              the systemd unit, the polkit action
#                              policy, the dbus system bus policy, the
#                              .desktop file, and a starter
#                              /etc/amwall/rules.toml.
#               polkit policy → /usr/share/polkit-1/actions/org.amwall.
#                              Daemon1.policy declares the action
#                              `org.amwall.Daemon1.modify-rules`:
#                              allow_active=yes (local Cinnamon session
#                              gets through with no prompt),
#                              allow_inactive=auth_admin_keep (SSH sessions
#                              need admin password). The daemon's
#                              Allow/Deny/Del methods now call polkit's
#                              CheckAuthorization before mutating rules;
#                              List() stays open (read-only).
#               systemd unit  → /lib/systemd/system/amwall-daemon.service.
#                              Installed but not enabled/started by the
#                              .deb postinst — opt-in via
#                              `sudo systemctl enable --now amwall-daemon`.
#               .desktop file → /usr/share/applications/amwall.desktop
#                              so the GUI shows up in app menus.
#               Smoke test    → builds the .deb and asserts the 9
#                              expected paths land in it.
#               Auto-install  → after all 6 smoke tests pass, the
#                              script `dpkg -i`s the .deb, enables +
#                              starts amwall-daemon under systemd, and
#                              launches amwall-gui (detached, log in
#                              ~/.local/share/amwall/gui.log — XDG
#                              equivalent of Win32 amwall's %APPDATA%
#                              swaplog). Override with
#                              AMWALL_SKIP_INSTALL=1 to iterate without
#                              churning systemd.
#   - Phase 6.1: Hybrid Qt6 GUI foundation (Iced replaced)
#               amwall-gui   → C++/Qt6 binary built by CMake under
#                              linux/amwall-gui-qt/. Talks to
#                              amwall-daemon over the existing
#                              org.amwall.Daemon1 system-bus interface
#                              (same wire protocol as the Iced version
#                              and amwall-cli --dbus).
#                              Phase 6.1 surfaces:
#                                - QMainWindow with menu bar (6 top-level
#                                  menus matching Windows: File/Edit/View
#                                  /Settings/Blocklist/Help — placeholders
#                                  for 6.2+),
#                                - QSystemTrayIcon (Mint-Cinnamon native
#                                  via the StatusNotifierItem protocol;
#                                  left-click toggles window, right-click
#                                  menu has Show/Quit),
#                                - close-to-tray (closing the window
#                                  hides it instead of quitting).
#                              No tabs, no dialogs, no D-Bus method calls
#                              yet. Phases 6.2 → 6.9 layer those on.
#                              Build: cmake + qt6-base-dev. Output binary
#                              still installs at /usr/bin/amwall-gui via
#                              the same .deb pipeline.
#                              Smoke test 5 switched from the Iced
#                              binary's old AMWALL_GUI_HEADLESS=1 mode
#                              to dbus-monitor watching the system bus
#                              directly — toolkit-independent.
#   - Phase 5: Workspace consolidation (Linux side only)
#               amwall-core   → hoisted from linux/amwall-core/ to the
#                              repo root as amwall-core/. linux/Cargo.toml's
#                              [workspace.dependencies] now points at
#                              "../amwall-core". Each Linux crate's own
#                              Cargo.toml is unchanged (still
#                              `amwall-core.workspace = true`).
#                              The Windows half of plan Phase 5 — root
#                              Cargo.toml gaining `amwall-core = { path =
#                              "amwall-core" }` and src/rules/*.rs being
#                              rewritten to use amwall_core::rules types
#                              — is INTENTIONALLY OUT OF SCOPE for this
#                              script. It touches Windows code this script
#                              can't validate from a Linux VM and needs a
#                              Windows checkout to land safely. Lands as
#                              a separate commit.
#   - Phase 6.10: Offline + frozen builds (userspace) / locked (ebpf)
#               vendoring     → linux/vendor/ holds every userspace
#                              crate source pinned by linux/Cargo.lock.
#                              The source replacement is NOT in a
#                              .cargo/config.toml file — cargo merges
#                              configs up the directory tree, and
#                              linux/.cargo/config.toml would leak
#                              into the ebpf workspace at
#                              linux/amwall-ebpf/, telling cargo to
#                              look for aya-ebpf in the userspace
#                              mirror where it doesn't exist. The
#                              replacement is passed via --config CLI
#                              flags on the userspace `cargo build`
#                              and as CARGO_SOURCE_* env vars on the
#                              `cargo deb` step (cargo-deb doesn't
#                              forward --config to its inner cargo
#                              metadata invocation).
#               userspace     → `cargo build --release --frozen --offline`
#                              and `cargo deb --no-build --offline`.
#                              Crates.io outage / dep yank / transitive
#                              version drift cannot change what we
#                              build.
#               ebpf          → `cargo build --release --locked` (no
#                              vendor, no --offline). build-std=core
#                              pulls nightly sysroot deps cargo vendor
#                              can't see, so --frozen --offline
#                              hard-fails on missing rustc-literal-
#                              escaper et al. --locked still pins
#                              resolution to Cargo.lock; small (~23
#                              crate) network fetch on first build.
#               `cargo install` for dev tools (bpf-linker, cargo-deb,
#                              aya-tool, bindgen-cli) STAYS online —
#                              bootstrap tooling, not part of the
#                              frozen project graph, and vendoring
#                              them would balloon the repo another
#                              ~500 MB.
#               re-vendor     → when a userspace Cargo.toml changes,
#                              run `cargo vendor --versioned-dirs vendor`
#                              from linux/ and commit the diff alongside
#                              the Cargo.toml change. --frozen will
#                              hard-fail at build time if the lockfile
#                              is stale.
#
# Replay-from-snapshot — every step is idempotent. APT install -y on
# already-installed packages is a no-op. Rustup steps are gated. The
# generated source files in linux/ ALWAYS get overwritten; commit any
# local edits first if you want to keep them.
#
# If GRUB needs editing, the script will prompt, edit, then exit asking
# you to reboot. Re-run after reboot to continue past the build step.
#
# Auto-locates the amwall repo (clones to ~/amwall if missing). Override
# with AMWALL_REPO_DIR=/some/path.
#
# Expected runtime:
#   - First run from snapshot 0: ~15-25 min (apt + rustup + bpf-linker
#     + tokio/zbus compile), then reboot
#   - Second run after reboot:    ~5-10 min
#   - Subsequent re-runs:         < 1 min (incremental + smoke)
#
#   ./linux-build.sh
#
# Honest warning: aya / aya-ebpf / zbus / iced API surfaces evolve. If
# a build or load fails, paste the output back and we'll iterate the
# version pin or call sites. Phase 3.5 layers Iced 0.13 on top of the
# Phase 3 zbus stack, doubling the userspace dep tree — first compile
# of the GUI takes ~5-10 minutes on its own.

set -u
set -o pipefail
# Don't set -e — explicit error handling per step.

# ─── Auto-log the entire run to a paste-friendly file ───────────────
#
# Everything from this point on (stdout + stderr) is teed to
# $AMWALL_LOG_FILE (default: ~/amwall-run.log). The user can
# `cat $AMWALL_LOG_FILE` once the script finishes and paste the
# whole thing back to Claude for triage.
#
# Knobs:
#   AMWALL_NO_LOG=1        disable teeing entirely
#   AMWALL_LOG_FILE=path   override destination (default ~/amwall-run.log)
#   AMWALL_LOGGING_ACTIVE  internal — set by us so a re-exec doesn't
#                          stack a second tee on top of the first
#
# fd 3 / fd 4 hold the original stdout / stderr so the trailing
# `exec bash` (interactive shell drop-in) is NOT captured in the log
# — we restore them right before exec bash. tee gets EOF when its
# stdin pipe is closed and exits cleanly.
if [ -z "${AMWALL_LOGGING_ACTIVE:-}" ] && [ "${AMWALL_NO_LOG:-0}" != "1" ]; then
    AMWALL_LOG_FILE="${AMWALL_LOG_FILE:-$HOME/amwall-run.log}"
    : > "$AMWALL_LOG_FILE"  # truncate any prior log
    # Stamp used to scope coredumpctl --since at end-of-run so we
    # only show cores from THIS script invocation, not old ones.
    AMWALL_RUN_START="$(date '+%Y-%m-%d %H:%M:%S')"
    export AMWALL_LOGGING_ACTIVE=1
    export AMWALL_LOG_FILE
    export AMWALL_RUN_START
    exec 3>&1 4>&2
    # stdbuf -oL forces tee's stdout to be line-buffered. Without it
    # tee block-buffers (its stdout is a pipe-fed terminal here, not
    # detected as a TTY) and INFO lines visibly lag behind /dev/tty
    # prompts — which is what made the GRUB prompt appear ABOVE its
    # own "Current active LSM list" / "Will modify" context lines.
    # Fallback to plain tee if stdbuf isn't installed (coreutils
    # ships it everywhere we target, but be defensive).
    if command -v stdbuf >/dev/null 2>&1; then
        exec > >(stdbuf -oL tee "$AMWALL_LOG_FILE") 2>&1
    else
        exec > >(tee "$AMWALL_LOG_FILE") 2>&1
    fi
    printf '\n'
    printf 'amwall: logging this run to %s\n' "$AMWALL_LOG_FILE"
    printf '         when done:  cat %s   # paste back to Claude\n' "$AMWALL_LOG_FILE"
    printf '\n'
fi

# ─── Helpers ────────────────────────────────────────────────────────

BAR='────────────────────────────────────────────────────────────'
H()    { printf '\n%s\n  %s\n%s\n' "$BAR" "$*" "$BAR"; }
INFO() { printf '  • %s\n' "$*"; }
WARN() { printf '  ! %s\n' "$*" >&2; }
OK()   { printf '  ✓ %s\n' "$*"; }
NEW()  { printf '  + wrote %s\n' "$*"; }
# Prompt + read both go via /dev/tty directly so neither is captured
# by the tee log pipeline. Two bugs this avoids:
#   1. `read -p` writes the prompt to stderr, which the script
#      redirects through `tee` (see the AMWALL_LOG_FILE block above).
#      Even with stdbuf forcing tee line-buffered, a prompt with no
#      trailing newline won't flush — the user sees a stuck script
#      with no visible prompt.
#   2. With curl|bash, bash's stdin is the (exhausted) shell-source
#      pipe — a plain `read` returns EOF instantly and the [Yy]
#      regex silently picks "no", which is what auto-skipped GRUB.
# /dev/tty is the controlling terminal and survives both exec and
# any FD redirection — using it for both halves means the prompt
# appears live and the response is read directly from the user.
# We also print a separator marker around the prompt so it's
# visually unambiguous which output the user is being asked to
# answer, regardless of any residual tee-pipe scheduling lag.
# True headless (no /dev/tty at all) still defaults to "no" with a
# visible note.
ASK() {
    local p="$1" reply=""
    if [ -e /dev/tty ]; then
        {
            printf '\n  ────────────────  USER INPUT NEEDED  ────────────────\n'
            printf '  ? %s [y/N] ' "$p"
        } > /dev/tty
        read -r reply < /dev/tty 2>/dev/null || reply=""
        printf '  ──────────────────────────────────────────────────────\n\n' > /dev/tty
    else
        printf '  ? %s [y/N] (no /dev/tty — defaulting to no)\n' "$p"
    fi
    [[ "$reply" =~ ^[Yy]$ ]]
}

# Make cargo/rustc visible to this script even if the user's bashrc
# hasn't sourced ~/.cargo/env yet.
# shellcheck disable=SC1091
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

GRUB_REBOOT_NEEDED=0

# ─── 0. Preflight ───────────────────────────────────────────────────

H "Preflight"

if [ "$(id -u)" -eq 0 ]; then
    WARN "Don't run as root — script invokes sudo as needed."
    exit 1
fi

if ! grep -q '^UBUNTU_CODENAME=noble' /etc/os-release; then
    WARN "Expected Ubuntu noble (24.04) / Mint 22.x base — got:"
    grep -E '^(NAME|VERSION_CODENAME|UBUNTU_CODENAME)=' /etc/os-release >&2
    ASK "Continue anyway?" || exit 1
fi

PRETTY=$(grep '^PRETTY_NAME=' /etc/os-release | cut -d'"' -f2)
OK "running as $(id -un) on ${PRETTY:-?}"

INFO "(sudo password may be requested during apt / grub / smoke-test steps)"

# ─── 1. APT packages ────────────────────────────────────────────────

H "APT packages"

APT_PKGS=(
    clang llvm
    libbpf-dev
    linux-tools-common "linux-tools-$(uname -r)"
    build-essential pkg-config
    git curl ca-certificates
    dbus
    # Phase 6.1: Qt6 + CMake for the hybrid C++ GUI.
    # qt6-base-dev pulls QtCore/Gui/Widgets/DBus dev headers plus runtime.
    cmake qt6-base-dev
)

INFO "Updating package index..."
sudo apt update -qq

INFO "Installing: ${APT_PKGS[*]}"
sudo apt install -y --no-install-recommends "${APT_PKGS[@]}"

for bin in clang llvm-strip git curl dbus-send; do
    if command -v "$bin" >/dev/null; then
        OK "$bin → $(command -v "$bin")"
    else
        WARN "$bin still missing after apt install"
    fi
done

if dpkg -l libbpf-dev 2>/dev/null | grep -q '^ii'; then
    OK "libbpf-dev installed"
else
    WARN "libbpf-dev failed to install"
fi

# ─── 2. Rust toolchain via rustup ───────────────────────────────────

H "Rust toolchain"

if command -v cargo >/dev/null && command -v rustup >/dev/null; then
    OK "Rust already installed: $(rustc --version)"
else
    INFO "Installing rustup (stable, profile=minimal, no PATH modify)..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal --no-modify-path
    # shellcheck disable=SC1091
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
fi

if ! grep -q 'cargo/env\|cargo/bin' "$HOME/.bashrc" 2>/dev/null; then
    INFO "Adding ~/.cargo/env source to ~/.bashrc"
    echo '. "$HOME/.cargo/env"' >> "$HOME/.bashrc"
fi

INFO "Toolchain status:"
rustup show 2>&1 | sed 's/^/    /'

INFO "Ensuring nightly toolchain..."
if rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    OK "nightly already installed"
else
    rustup toolchain install nightly --profile minimal
fi

INFO "Ensuring rust-src on nightly..."
rustup component add --toolchain nightly rust-src

INFO "Ensuring bpf-linker..."
if command -v bpf-linker >/dev/null 2>&1; then
    OK "bpf-linker already installed: $(bpf-linker --version 2>&1 | head -1)"
else
    INFO "Building bpf-linker via cargo install (5-10 min, links system LLVM)..."
    cargo install bpf-linker
fi

INFO "Ensuring cargo-deb..."
if command -v cargo-deb >/dev/null 2>&1; then
    OK "cargo-deb already installed: $(cargo deb --version 2>&1 | head -1)"
else
    INFO "Building cargo-deb via cargo install (3-5 min)..."
    cargo install cargo-deb
fi

# aya-tool: generates Rust bindings for kernel types from /sys/kernel/btf/vmlinux.
# We use it to emit a vmlinux.rs containing task_struct so the BPF program can
# read task->group_leader->comm (Phase 6.3.1 — collapses Firefox's per-thread
# "DNS Resolver #N" comms back to the binary name "firefox").
#
# aya-tool is NOT on crates.io — it lives in the aya GitHub repo and must be
# installed from --git. Failure here is non-fatal: the BPF build falls back
# to bpf_get_current_comm() (per-thread name) — same as pre-6.3.1, just with
# multi-thread apps spamming separate prompts as a degraded-mode UX.
INFO "Ensuring aya-tool (BTF→Rust bindings for task_struct walk)..."
if command -v aya-tool >/dev/null 2>&1; then
    OK "aya-tool already installed at $(command -v aya-tool)"
else
    INFO "Building aya-tool from aya-rs/aya git (3-5 min, pulls clang-sys)..."
    if cargo install --locked --git https://github.com/aya-rs/aya aya-tool 2>&1 | sed 's/^/    /'; then
        OK "aya-tool installed from git"
    else
        WARN "aya-tool install failed — BPF will use per-thread comm fallback"
        WARN "(multi-thread apps like Firefox will spam prompts; not blocking)"
    fi
fi

# aya-tool shells out to BOTH `bpftool` (for `btf dump ... format c`) and
# the `bindgen` CLI (separate from the bindgen library — comes from the
# bindgen-cli crate). Without bindgen-cli on PATH, aya-tool generate
# returns the obscure "bindgen failed: No such file or directory" we saw
# in earlier runs.
INFO "Ensuring bindgen CLI (aya-tool subprocess dependency)..."
if command -v bindgen >/dev/null 2>&1; then
    OK "bindgen already installed: $(bindgen --version 2>&1 | head -1)"
else
    INFO "Building bindgen-cli via cargo install (2-3 min)..."
    if cargo install --locked bindgen-cli 2>&1 | sed 's/^/    /'; then
        OK "bindgen-cli installed"
    else
        WARN "bindgen-cli install failed — BPF will use per-thread comm fallback"
    fi
fi

# Flag set later when we successfully generate amwall-ebpf/src/vmlinux.rs;
# passed to `cargo build` so the BPF program uses the group_leader walk.
EBPF_CARGO_FEATURES=""

# ─── 3. GRUB — enable bpf in the LSM list ───────────────────────────

H "GRUB — enable bpf in the LSM list"

if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
    OK "bpf is ALREADY in the active LSM list — nothing to do."
else
    CURRENT_LSM=$(cat /sys/kernel/security/lsm 2>/dev/null)
    INFO "Current active LSM list: $CURRENT_LSM"
    INFO "Need to add 'bpf' to the kernel's lsm= boot parameter."
    INFO "Will modify: /etc/default/grub  (timestamped backup created first)"

    if ASK "Edit /etc/default/grub now?"; then
        BACKUP="/etc/default/grub.bak.$(date +%Y%m%d-%H%M%S)"
        sudo cp -a /etc/default/grub "$BACKUP"
        OK "Backed up /etc/default/grub to $BACKUP"

        LSM_PARAM="lsm=${CURRENT_LSM},bpf"

        if grep -E '^GRUB_CMDLINE_LINUX_DEFAULT=.*lsm=' /etc/default/grub >/dev/null; then
            WARN "GRUB_CMDLINE_LINUX_DEFAULT already contains lsm=. Edit manually:"
            grep '^GRUB_CMDLINE_LINUX_DEFAULT' /etc/default/grub | sed 's/^/    /' >&2
            INFO "Make sure 'bpf' is appended to that lsm= list, then run: sudo update-grub"
            exit 1
        else
            sudo sed -i -E \
                "s|^(GRUB_CMDLINE_LINUX_DEFAULT=\")([^\"]*)(\")|\1\2 ${LSM_PARAM}\3|" \
                /etc/default/grub
            OK "Added '${LSM_PARAM}' to GRUB_CMDLINE_LINUX_DEFAULT:"
            grep '^GRUB_CMDLINE_LINUX_DEFAULT' /etc/default/grub | sed 's/^/    /'

            INFO "Running sudo update-grub..."
            sudo update-grub 2>&1 | sed 's/^/    /'
            OK "GRUB updated. Reboot required for bpf LSM to load."
            GRUB_REBOOT_NEEDED=1
        fi
    else
        INFO "Skipped grub edit. To do it manually later:"
        cat <<'EOF'
    sudo cp -a /etc/default/grub /etc/default/grub.bak
    sudo nano /etc/default/grub
    # Inside GRUB_CMDLINE_LINUX_DEFAULT="...", append:
    #   lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf
    sudo update-grub
    sudo reboot
EOF
        WARN "Without bpf in the LSM list, BPF program load will fail."
        exit 1
    fi
fi

# ─── 4. VERIFY ──────────────────────────────────────────────────────

H "VERIFY — prerequisites"

PASS=1
CHK() {
    local label="$1" cmd="$2" detail="${3:-}"
    if eval "$cmd" >/dev/null 2>&1; then
        if [ -n "$detail" ]; then
            local d
            d=$(eval "$detail" 2>/dev/null | head -1)
            OK "$label — $d"
        else
            OK "$label"
        fi
    else
        WARN "$label"
        PASS=0
    fi
}

CHK "rustup present"           'command -v rustup'    'rustup --version'
CHK "rustc present"            'command -v rustc'     'rustc --version'
CHK "cargo present"            'command -v cargo'     'cargo --version'
CHK "nightly toolchain"        'rustup toolchain list 2>/dev/null | grep -q "^nightly"'
CHK "rust-src on nightly"      'rustup +nightly component list --installed 2>/dev/null | grep -q "^rust-src"'
CHK "bpf-linker present"       'command -v bpf-linker' 'bpf-linker --version'
CHK "clang present"            'command -v clang'     'clang --version'
CHK "llvm-strip present"       'command -v llvm-strip'
CHK "libbpf-dev installed"     'dpkg -l libbpf-dev 2>/dev/null | grep -q "^ii"'
CHK "linux-headers available"  '[ -e "/lib/modules/$(uname -r)/build" ]'
CHK "git present"              'command -v git'       'git --version'
CHK "BTF available"            '[ -r /sys/kernel/btf/vmlinux ]'
CHK "system dbus socket"       '[ -S /var/run/dbus/system_bus_socket ]'
CHK "cargo-deb present"        'command -v cargo-deb' 'cargo deb --version'
CHK "polkit actions dir"       '[ -d /usr/share/polkit-1/actions ]'
CHK "polkit running"           'pgrep -x polkitd >/dev/null || pgrep -f /usr/lib/polkit-1/polkitd >/dev/null'
CHK "cmake present"            'command -v cmake'      'cmake --version'
CHK "qmake6 present"           'command -v qmake6'     'qmake6 --version'
CHK "dbus-monitor present"     'command -v dbus-monitor'

if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
    OK "bpf in active LSM list"
elif [ "$GRUB_REBOOT_NEEDED" = 1 ]; then
    INFO "bpf NOT in active LSM list yet — REBOOT to activate (grub was just edited)."
else
    WARN "bpf in active LSM list"
    PASS=0
fi

if [ "$GRUB_REBOOT_NEEDED" = 1 ]; then
    H "REBOOT REQUIRED"
    cat <<'EOF'
  GRUB was just edited to add bpf to the LSM list. Reboot now:

      sudo reboot

  After reboot, re-run this script.
EOF
    exit 0
fi

if [ "$PASS" != 1 ]; then
    H "INCOMPLETE — fix the WARN lines above"
    exit 1
fi

OK "All prerequisites satisfied."

# ─── 4b. D-Bus system bus policy for org.amwall.Daemon1 ─────────────
#
# The daemon runs as root (BPF LSM load is privileged) and therefore
# can't authenticate onto a per-user session bus — EXTERNAL auth on
# the session bus refuses connections whose peer UID doesn't match the
# bus owner. So the daemon owns its name on the SYSTEM bus instead.
#
# That requires an explicit dbus-daemon policy: by default, no one can
# own arbitrary names on the system bus. This file grants:
#   - root          → may own org.amwall.Daemon1
#   - any user      → may call methods on it + receive its signals
# Production should narrow the user policy via polkit (Phase 4).
#
# /etc/dbus-1/system.d/ is watched by the system bus daemon; a SIGHUP
# (or systemctl reload dbus) re-reads policy without dropping clients.

H "D-Bus system bus policy (org.amwall.Daemon1)"

POLICY_FILE=/etc/dbus-1/system.d/org.amwall.Daemon1.conf
POLICY_TMP=$(mktemp)
cat > "$POLICY_TMP" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <!-- root may own the bus name and talk to itself -->
  <policy user="root">
    <allow own="org.amwall.Daemon1"/>
    <allow send_destination="org.amwall.Daemon1"/>
    <allow receive_sender="org.amwall.Daemon1"/>
  </policy>

  <!-- any user may call methods on the daemon and receive its signals.
       Phase 4 will tighten this with polkit per-method auth. -->
  <policy context="default">
    <allow send_destination="org.amwall.Daemon1"/>
    <allow receive_sender="org.amwall.Daemon1"/>
  </policy>
</busconfig>
EOF

if sudo test -f "$POLICY_FILE" && sudo cmp -s "$POLICY_TMP" "$POLICY_FILE"; then
    OK "$POLICY_FILE already up-to-date."
    rm -f "$POLICY_TMP"
else
    INFO "Installing $POLICY_FILE (sudo)..."
    sudo install -m 0644 -o root -g root "$POLICY_TMP" "$POLICY_FILE"
    rm -f "$POLICY_TMP"
    NEW "$POLICY_FILE"
    INFO "Reloading system dbus to pick up new policy..."
    if sudo systemctl reload dbus 2>/dev/null; then
        OK "dbus reloaded."
    else
        WARN "systemctl reload dbus failed — policy may not be active until reboot."
    fi
fi

# ─── 4c. Polkit action policy for org.amwall.Daemon1.modify-rules ───
#
# Polkit gates the daemon's modifying methods (Allow / Deny / Del). The
# system bus policy above lets any user *send* a message to the daemon;
# polkit decides whether the daemon should *act* on it. allow_active=yes
# means a locally-active session (Cinnamon login) gets through with no
# prompt — same UX as the dev-only policy above. SSH'd / inactive
# sessions hit auth_admin_keep and have to provide an admin password.
#
# polkitd auto-reloads action files via inotify; no manual reload needed.
#
# (Same content gets dropped into linux/amwall-daemon/debian/ later for
# the .deb to ship — duplicated to keep the dev-install path self-
# contained.)

H "Polkit action policy (org.amwall.Daemon1.modify-rules)"

POLKIT_FILE=/usr/share/polkit-1/actions/org.amwall.Daemon1.policy
POLKIT_TMP=$(mktemp)
cat > "$POLKIT_TMP" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1.0/policyconfig.dtd">
<policyconfig>
  <vendor>amwall</vendor>
  <vendor_url>https://github.com/amrust/amwall</vendor_url>

  <action id="org.amwall.Daemon1.modify-rules">
    <description>Modify amwall firewall rules</description>
    <message>Authentication is required to modify amwall firewall rules</message>
    <defaults>
      <allow_any>auth_admin_keep</allow_any>
      <allow_inactive>auth_admin_keep</allow_inactive>
      <allow_active>yes</allow_active>
    </defaults>
  </action>
</policyconfig>
EOF

if sudo test -f "$POLKIT_FILE" && sudo cmp -s "$POLKIT_TMP" "$POLKIT_FILE"; then
    OK "$POLKIT_FILE already up-to-date."
    rm -f "$POLKIT_TMP"
else
    INFO "Installing $POLKIT_FILE (sudo)..."
    sudo install -m 0644 -o root -g root "$POLKIT_TMP" "$POLKIT_FILE"
    rm -f "$POLKIT_TMP"
    NEW "$POLKIT_FILE"
    INFO "(polkitd auto-reloads action files; no restart needed.)"
fi

# ─── 5. Locate or clone the amwall repo ─────────────────────────────

H "Locating amwall repo"

REPO_URL="https://github.com/amrust/amwall.git"
DEFAULT_DIR="${HOME}/amwall"

is_amwall_repo() {
    [ -f "$1/Cargo.toml" ] && [ -d "$1/src" ] && \
        grep -q '^name *= *"amwall"' "$1/Cargo.toml" 2>/dev/null
}

REPO_DIR="${AMWALL_REPO_DIR:-}"
if [ -n "$REPO_DIR" ]; then
    if ! is_amwall_repo "$REPO_DIR"; then
        WARN "AMWALL_REPO_DIR='$REPO_DIR' isn't a valid amwall checkout."
        exit 1
    fi
    OK "using AMWALL_REPO_DIR override: $REPO_DIR"
elif is_amwall_repo "$(pwd)"; then
    REPO_DIR="$(pwd)"
    OK "running from inside the amwall repo: $REPO_DIR"
elif is_amwall_repo "$DEFAULT_DIR"; then
    REPO_DIR="$DEFAULT_DIR"
    OK "found existing amwall checkout: $REPO_DIR"
else
    if [ -e "$DEFAULT_DIR" ]; then
        WARN "$DEFAULT_DIR exists but isn't an amwall checkout."
        exit 1
    fi
    INFO "Cloning $REPO_URL → $DEFAULT_DIR"
    git clone "$REPO_URL" "$DEFAULT_DIR" 2>&1 | sed 's/^/    /'
    if ! is_amwall_repo "$DEFAULT_DIR"; then
        WARN "Clone finished but the result doesn't look like the amwall repo."
        exit 1
    fi
    REPO_DIR="$DEFAULT_DIR"
    OK "cloned to $REPO_DIR"
fi
cd "$REPO_DIR"
OK "working directory: $(pwd)"

# ─── 6. Workspace skeleton ──────────────────────────────────────────

H "Workspace skeleton"

mkdir -p linux

rm -f linux/amwall-ebpf/src/lib.rs

# Phase 5 hoist: amwall-core moved from linux/amwall-core/ to the repo
# root as amwall-core/. If a previous run (pre-Phase-5) left the old
# location in place, remove it so workspace resolution doesn't see two
# copies of the same package.
if [ -d linux/amwall-core ]; then
    INFO "Removing stale linux/amwall-core/ (Phase 5 hoist moved it to repo root)..."
    rm -rf linux/amwall-core
fi

# Phase 6.1: amwall-gui dropped as a Rust crate (replaced by C++/Qt6
# project under linux/amwall-gui-qt/). Remove the old Rust dir if a
# pre-Phase-6 run left it; otherwise cargo would still see it.
if [ -d linux/amwall-gui ]; then
    INFO "Removing stale linux/amwall-gui/ (Phase 6.1 replaced Iced with Qt6)..."
    rm -rf linux/amwall-gui
fi

# Sanity: after the post-migration layout the source must already be on
# disk (extracted from the old monolithic script in a one-shot commit).
# If any required tree is missing the user probably forgot to `git pull`.
for required in \
    amwall-core/Cargo.toml \
    linux/Cargo.toml \
    linux/amwall-daemon/Cargo.toml \
    linux/amwall-cli/Cargo.toml \
    linux/amwall-ebpf/Cargo.toml \
    linux/amwall-gui-qt/CMakeLists.txt \
    linux/amwall-daemon/debian/postinst \
; do
    if [ ! -e "$required" ]; then
        WARN "Missing $required — did you 'git pull' on this checkout?"
        exit 1
    fi
done
OK "Source tree present (linux/, amwall-core/, debian/)"

# Maintainer scripts need to be executable for cargo-deb to package
# them correctly. Git preserves the +x bit on Unix, but a clone over
# Windows-mounted shares or a fresh extract may drop it; cheap to
# re-assert on every run.
chmod +x linux/amwall-daemon/debian/postinst \
         linux/amwall-daemon/debian/prerm \
         linux/amwall-daemon/debian/postrm

# ─── Build ──────────────────────────────────────────────────────────

# Phase 6.3.1: try to generate src/vmlinux.rs so the BPF program can
# walk task->group_leader->comm. Requires aya-tool (installed earlier,
# may have failed gracefully) and /sys/kernel/btf/vmlinux (present on
# any kernel built with CONFIG_DEBUG_INFO_BTF=y — Ubuntu/Mint 22 have
# it). Any failure here just leaves EBPF_CARGO_FEATURES empty and the
# BPF falls back to per-thread comm.
H "Generating amwall-ebpf vmlinux.rs (task_struct from BTF)"

VMLINUX_OUT="$REPO_DIR/linux/amwall-ebpf/src/vmlinux.rs"
rm -f "$VMLINUX_OUT"  # always start fresh — stale file from prior run + fresh install failure would build with bad bindings
PHASE_631_STATUS="✗ (disabled — falling back to per-thread comm)"

# aya-tool calls bpftool as a subprocess to dump BTF, then bindgens
# the resulting C header. On Mint/Ubuntu, linux-tools-common installs
# bpftool at /usr/sbin/bpftool which isn't on every shell's PATH for
# non-login sessions, so the spawn fails with ENOENT and aya-tool
# returns "bindgen failed: No such file or directory". Find it
# ourselves and ensure it's on PATH for the duration of the call.
BPFTOOL_PATH=""
for candidate in \
    "$(command -v bpftool 2>/dev/null)" \
    /usr/sbin/bpftool \
    /usr/bin/bpftool \
    "/usr/lib/linux-tools/$(uname -r)/bpftool" \
    /usr/lib/linux-tools-common/bpftool; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
        BPFTOOL_PATH="$candidate"
        break
    fi
done

if [ -z "$BPFTOOL_PATH" ]; then
    WARN "bpftool not found anywhere — apt linux-tools-* may not have installed it."
    WARN "6.3.1 disabled. Try: sudo apt install linux-tools-\$(uname -r) linux-tools-common"
elif ! command -v aya-tool >/dev/null 2>&1; then
    WARN "aya-tool not installed — 6.3.1 disabled (per-thread comm)."
elif ! command -v bindgen >/dev/null 2>&1; then
    WARN "bindgen CLI not installed — aya-tool would fail. 6.3.1 disabled."
elif [ ! -r /sys/kernel/btf/vmlinux ]; then
    WARN "/sys/kernel/btf/vmlinux not readable — 6.3.1 disabled."
else
    INFO "Using bpftool: $BPFTOOL_PATH"
    # Confirm bpftool actually works against the BTF blob before
    # invoking aya-tool — a wrapper that exits non-zero (e.g. kernel
    # version mismatch) would otherwise leave aya-tool's error obscure.
    if ! "$BPFTOOL_PATH" btf dump file /sys/kernel/btf/vmlinux format c >/tmp/btf-smoke.h 2>/tmp/btf-smoke.err; then
        WARN "bpftool btf dump failed — 6.3.1 disabled:"
        sed 's/^/    /' /tmp/btf-smoke.err 2>/dev/null || true
    else
        rm -f /tmp/btf-smoke.h
        # Prepend bpftool's dir so aya-tool's subprocess spawn finds it.
        EXPORT_PATH="$(dirname "$BPFTOOL_PATH"):$PATH"
        INFO "Running: aya-tool generate task_struct"
        if PATH="$EXPORT_PATH" aya-tool generate task_struct >"$VMLINUX_OUT" 2>/tmp/aya-tool.err; then
            BYTES=$(wc -c <"$VMLINUX_OUT")
            if [ "$BYTES" -gt 1000 ]; then
                OK "vmlinux.rs generated (${BYTES} bytes) — 6.3.1 enabled"
                EBPF_CARGO_FEATURES="--features task_walk"
                PHASE_631_STATUS="✓ enabled (vmlinux.rs ${BYTES} bytes)"
            else
                WARN "vmlinux.rs only ${BYTES} bytes — looks empty, disabling 6.3.1"
                sed 's/^/    /' /tmp/aya-tool.err 2>/dev/null || true
                rm -f "$VMLINUX_OUT"
            fi
        else
            WARN "aya-tool generate failed — 6.3.1 disabled:"
            sed 's/^/    /' /tmp/aya-tool.err 2>/dev/null || true
            rm -f "$VMLINUX_OUT"
        fi
    fi
fi
export PHASE_631_STATUS

H "Building amwall-ebpf (slow — rebuilds core)"
INFO "Expect 2-5 minutes the first time."
INFO "Cargo features: ${EBPF_CARGO_FEATURES:-<none>}"
# Phase 6.10: --locked pins resolution to the committed Cargo.lock
# but DOES allow network access. The ebpf workspace is not vendored
# because build-std=core pulls nightly sysroot deps (proc_macro →
# rustc-literal-escaper et al.) that `cargo vendor` doesn't see —
# replacing crates-io with a vendor mirror caused --frozen --offline
# to hard-fail looking for crates we never had a chance to vendor.
# The big win for offline mode is the userspace workspace below
# (207 MB / 173 crates of vendor); the ebpf side has only ~23 small
# crates so the network round-trip is cheap and not worth the
# brittleness.
if (cd linux/amwall-ebpf && cargo build --release --locked $EBPF_CARGO_FEATURES 2>&1 | sed 's/^/    /'); then
    EBPF_BIN="$REPO_DIR/linux/amwall-ebpf/target/bpfel-unknown-none/release/amwall-ebpf"
    if [ ! -f "$EBPF_BIN" ]; then
        WARN "BPF ELF not produced at expected path: $EBPF_BIN"
        exit 1
    fi
    OK "amwall-ebpf built: $(stat -c %s "$EBPF_BIN") bytes"
else
    WARN "amwall-ebpf build failed — see output above. Likely an aya-ebpf API drift."
    exit 1
fi

H "Building Rust userspace (amwall-daemon + amwall-cli, release)"
INFO "Phase 6.1 dropped iced/wgpu/winit/cosmic-text — much faster build now."
INFO "First-time release compile of tokio + zbus + clap + aya: ~3-5 min."
# Phase 6.10: --frozen --offline pins resolution to linux/Cargo.lock
# and routes all crates.io reads through linux/vendor/ (207 MB / 173
# crates). The source-replacement config is passed via --config CLI
# flags rather than a checked-in linux/.cargo/config.toml because
# cargo merges configs UP the directory tree — a config file at
# linux/.cargo/config.toml would leak into the ebpf build sitting
# at linux/amwall-ebpf/ and tell cargo to look for aya-ebpf in the
# userspace vendor mirror where it doesn't exist. Inlining the
# source replacement keeps it scoped to this single cargo invocation.
if (cd linux && cargo build --release --frozen --offline \
        --config 'source.crates-io.replace-with="vendored-sources"' \
        --config 'source.vendored-sources.directory="vendor"' \
        2>&1 | sed 's/^/    /'); then
    OK "Rust userspace built (release)."
else
    WARN "userspace build failed — see output above."
    WARN "Common culprits: zbus 4 proxy/interface macro changes;"
    WARN "                 polkit Proxy / zvariant types in check_polkit;"
    WARN "                 aya 0.13 BPF map / program API drift."
    exit 1
fi

H "Building amwall-gui (C++/Qt6 via CMake)"
INFO "First-time Qt6 compile is ~1-2 min; incremental rebuilds are seconds."
mkdir -p linux/amwall-gui-qt/build
if (cd linux/amwall-gui-qt/build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. 2>&1 | sed 's/^/    /' && \
    cmake --build . --parallel 2>&1 | sed 's/^/    /'); then
    QT_GUI_BIN="$REPO_DIR/linux/amwall-gui-qt/build/amwall-gui"
    if [ ! -x "$QT_GUI_BIN" ]; then
        WARN "Qt GUI built but binary not at expected path: $QT_GUI_BIN"
        ls -la "$REPO_DIR/linux/amwall-gui-qt/build/" 2>&1 | sed 's/^/    /'
        exit 1
    fi
    OK "amwall-gui (Qt6) built: $QT_GUI_BIN ($(stat -c %s "$QT_GUI_BIN") bytes)"
else
    WARN "Qt GUI build failed — see above."
    WARN "Common culprits: missing qt6-base-dev (Widgets / DBus components);"
    WARN "                 cmake too old (need >= 3.16);"
    WARN "                 Qt6 API drift in QSystemTrayIcon / QDBusInterface."
    exit 1
fi

DAEMON_BIN="$REPO_DIR/linux/target/release/amwall-daemon"
CLI_BIN="$REPO_DIR/linux/target/release/amwall-cli"
GUI_BIN="$QT_GUI_BIN"

H "Building .deb package (cargo-deb)"
INFO "Packaging release binaries + debian/ scaffold (--no-build --offline)..."
# Phase 6.10: cargo-deb invokes `cargo metadata` internally to
# resolve asset paths. That metadata call needs the same vendored-
# sources view the userspace build uses, otherwise it tries to hit
# the upstream registry while we're in --offline mode and fails.
# We can't use --config CLI flags because cargo-deb 3.x doesn't
# forward unknown flags to its inner cargo invocation, so we
# express the source replacement as CARGO_SOURCE_* env vars (the
# documented equivalent). VENDOR_ABS is an absolute path so it
# resolves correctly regardless of where cargo-deb cd's internally.
VENDOR_ABS="$REPO_DIR/linux/vendor"
if (cd linux/amwall-daemon && \
        CARGO_SOURCE_CRATES_IO_REPLACE_WITH=vendored-sources \
        CARGO_SOURCE_VENDORED_SOURCES_DIRECTORY="$VENDOR_ABS" \
        cargo deb --no-build --offline 2>&1 | sed 's/^/    /'); then
    DEB_FILE=$(ls "$REPO_DIR/linux/target/debian/"amwall_*.deb 2>/dev/null | head -1)
    if [ -z "$DEB_FILE" ]; then
        WARN ".deb produced but couldn't find it under linux/target/debian/"
        ls -la "$REPO_DIR/linux/target/debian/" 2>&1 | sed 's/^/    /'
        exit 1
    fi
    OK ".deb built: $DEB_FILE ($(stat -c %s "$DEB_FILE") bytes)"
else
    WARN "cargo deb failed — see output above."
    WARN "Common culprits: asset path resolution from linux/amwall-daemon/;"
    WARN "                 missing release binary in linux/target/release/;"
    WARN "                 cargo-deb metadata schema drift."
    exit 1
fi

# ─── Smoke test ─────────────────────────────────────────────────────

H "Smoke test — Phase 2 enforcement + Phase 3 D-Bus + Phase 3.5 GUI (headless)"

INFO "sudo password may be needed (BPF program loading is privileged)."
sudo -v || { WARN "sudo failed — can't load BPF program."; exit 1; }

RULES_PATH="$REPO_DIR/test-rules.toml"
DAEMON_LOG=$(mktemp)
GUI_LOG=$(mktemp)
DAEMON_PID=""
GUI_PID=""

cleanup() {
    if [ -n "${GUI_PID:-}" ]; then
        kill "$GUI_PID" 2>/dev/null || true
        wait "$GUI_PID" 2>/dev/null || true
    fi
    if [ -n "$DAEMON_PID" ]; then
        sudo kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    [ -n "${DAEMON_LOG:-}" ] && rm -f "$DAEMON_LOG"
    [ -n "${GUI_LOG:-}" ] && rm -f "$GUI_LOG"
    [ -n "${RULES_PATH:-}" ] && rm -f "$RULES_PATH"
}
trap cleanup EXIT

# Empty rules → default-deny.
echo "" > "$RULES_PATH"

INFO "starting daemon (system bus — sudo env passes AMWALL_* through env_reset)..."
sudo env \
    AMWALL_EBPF_PATH="$EBPF_BIN" \
    AMWALL_RULES_PATH="$RULES_PATH" \
    "$DAEMON_BIN" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
sleep 3  # allow BPF attach + D-Bus name registration

if ! sudo kill -0 "$DAEMON_PID" 2>/dev/null; then
    WARN "Daemon exited before tests could run."
    sed 's/^/    /' "$DAEMON_LOG"
    DAEMON_PID=""
    exit 1
fi

# Test 1 — default-deny BLOCKS curl
INFO "Test 1: curl -4 https://example.com  (expect BLOCK)"
if curl -4 --max-time 4 -s -o /dev/null https://example.com 2>/dev/null; then
    WARN "Test 1 FAIL — curl succeeded but should have been blocked."
    TEST1=FAIL
else
    OK "Test 1 PASS — curl was blocked."
    TEST1=PASS
fi

# Test 2 — TOML edit + mtime reload ALLOWS curl
INFO "Adding allow rules via amwall-cli (TOML mode)..."
"$CLI_BIN" --rules "$RULES_PATH" allow curl any:443
"$CLI_BIN" --rules "$RULES_PATH" allow curl 127.0.0.53:53
"$CLI_BIN" --rules "$RULES_PATH" allow systemd-resolve any:53

INFO "Current rules:"
"$CLI_BIN" --rules "$RULES_PATH" list | sed 's/^/    /'

INFO "Waiting for daemon mtime reload..."
sleep 1

INFO "Test 2: curl -4 https://example.com  (expect ALLOW)"
if curl -4 --max-time 6 -s -o /dev/null https://example.com; then
    OK "Test 2 PASS — curl succeeded after live reload."
    TEST2=PASS
else
    WARN "Test 2 FAIL — curl blocked despite allow rule."
    TEST2=FAIL
fi

# Test 3 — D-Bus list returns rules
INFO "Test 3: amwall-cli --dbus list  (expect 3 rules from daemon)"
DBUS_LIST=$("$CLI_BIN" --dbus list 2>&1 || true)
echo "$DBUS_LIST" | sed 's/^/    /'
if echo "$DBUS_LIST" | grep -qE 'comm=curl[ ]+any:443'; then
    OK "Test 3 PASS — D-Bus List() returned curl→any:443"
    TEST3=PASS
else
    WARN "Test 3 FAIL — D-Bus List() didn't return expected rule"
    TEST3=FAIL
fi

# Test 4 — D-Bus deny method writes through to TOML
INFO "Test 4: amwall-cli --dbus deny google any:80  (then verify in TOML)"
"$CLI_BIN" --dbus deny google any:80 || true
sleep 1
if "$CLI_BIN" --rules "$RULES_PATH" list | grep -qE 'DENY[ ]+comm=google[ ]+any:80'; then
    OK "Test 4 PASS — D-Bus Deny() persisted to rules.toml"
    TEST4=PASS
else
    WARN "Test 4 FAIL — D-Bus Deny() didn't persist"
    TEST4=FAIL
fi

# Test 5 — daemon emits ConnectAttempt on the system bus
#
# Phase 6.1 dropped the Iced GUI's headless mode; the Qt6 GUI is a
# real graphical app, not a signal-printer. Switch to dbus-monitor —
# a toolkit-independent way to verify the daemon's signal emission.
# Match-rule based (no eavesdropping perm needed) since our system.d
# policy grants `<allow receive_sender="org.amwall.Daemon1"/>` to all
# users.
INFO "Test 5: dbus-monitor captures ConnectAttempt signals during curl"
dbus-monitor --system "type='signal',interface='org.amwall.Daemon1'" \
    >"$GUI_LOG" 2>&1 &
GUI_PID=$!
sleep 1.5  # let dbus-monitor install its match rule
curl -4 --max-time 3 -s -o /dev/null https://example.com >/dev/null 2>&1 || true
sleep 1.5  # let signals flow
kill "$GUI_PID" 2>/dev/null || true
wait "$GUI_PID" 2>/dev/null || true
GUI_PID=""

SIG_COUNT=$(grep -c 'member=ConnectAttempt' "$GUI_LOG" 2>/dev/null || echo 0)
if [ "$SIG_COUNT" -gt 0 ]; then
    OK "Test 5 PASS — dbus-monitor saw $SIG_COUNT ConnectAttempt signal(s)"
    TEST5=PASS
    INFO "Sample (first 6 lines around a signal):"
    grep -A 5 'member=ConnectAttempt' "$GUI_LOG" | head -12 | sed 's/^/    /'
else
    WARN "Test 5 FAIL — no ConnectAttempt signals on the system bus"
    TEST5=FAIL
    INFO "dbus-monitor output:"
    sed 's/^/    /' "$GUI_LOG"
fi

# Stop daemon
sudo kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

# Test 6 — .deb contains the 9 expected paths
INFO "Test 6: dpkg-deb --contents matches expected install paths"
EXPECTED=(
    "./usr/bin/amwall-daemon"
    "./usr/bin/amwall-cli"
    "./usr/bin/amwall-gui"
    "./usr/lib/amwall/amwall-ebpf.bpf"
    "./etc/dbus-1/system.d/org.amwall.Daemon1.conf"
    "./usr/share/polkit-1/actions/org.amwall.Daemon1.policy"
    "./lib/systemd/system/amwall-daemon.service"
    "./usr/share/applications/amwall.desktop"
    "./etc/amwall/rules.toml"
)
DEB_LIST=$(dpkg-deb --contents "$DEB_FILE" | awk '{print $NF}')
MISSING=()
for e in "${EXPECTED[@]}"; do
    if ! echo "$DEB_LIST" | grep -qFx "$e"; then
        MISSING+=("$e")
    fi
done
if [ ${#MISSING[@]} -eq 0 ]; then
    OK "Test 6 PASS — .deb contains all ${#EXPECTED[@]} expected paths"
    TEST6=PASS
else
    WARN "Test 6 FAIL — ${#MISSING[@]} path(s) missing from .deb:"
    for m in "${MISSING[@]}"; do
        WARN "  $m"
    done
    INFO "Full .deb contents:"
    dpkg-deb --contents "$DEB_FILE" | sed 's/^/    /'
    TEST6=FAIL
fi

# Test 7 — amwall-gui --version runs without a display
#
# Phase 6.2: confirms the binary is invokable headlessly. argv parsing
# happens before QApplication is constructed, so we don't need DISPLAY
# / Wayland to print version. Catches link-time / startup regressions
# (missing Qt plugin, ABI mismatch with installed libqt6*) on the
# build host without needing a graphical session.
INFO "Test 7: amwall-gui --version (no display required)"
# Capture exit code separately from output — `|| true` would mask it.
GUI_VER_OUT=$("$GUI_BIN" --version 2>&1)
GUI_VER_RC=$?
echo "$GUI_VER_OUT" | sed 's/^/    /'
if [ "$GUI_VER_RC" = "0" ] && echo "$GUI_VER_OUT" | grep -qE '^amwall-gui [0-9]'; then
    OK "Test 7 PASS — $(echo "$GUI_VER_OUT" | head -1)"
    TEST7=PASS
else
    WARN "Test 7 FAIL — amwall-gui --version exit=$GUI_VER_RC, output above"
    TEST7=FAIL
fi

echo
echo "─── daemon output ──────────────────────────────────────────"
sed 's/^/    /' "$DAEMON_LOG"
echo "────────────────────────────────────────────────────────────"

ALL_PASS=1
[ "$TEST1" = PASS ] || ALL_PASS=0
[ "$TEST2" = PASS ] || ALL_PASS=0
[ "$TEST3" = PASS ] || ALL_PASS=0
[ "$TEST4" = PASS ] || ALL_PASS=0
[ "$TEST5" = PASS ] || ALL_PASS=0
[ "$TEST6" = PASS ] || ALL_PASS=0
[ "$TEST7" = PASS ] || ALL_PASS=0

if [ "$ALL_PASS" = 1 ]; then
    H "✓ PHASES 2 + 3 + 4 + 5 + 6.1 + 6.2 + 6.3 + 6.4 + 6.4.1 + 6.5 ALL CONFIRMED"
    OK "Default-deny / live reload / D-Bus methods / D-Bus signals all work."
    OK "Polkit gates Allow/Deny/Del; local-active session passes through."
    OK ".deb builds and contains all 9 expected files."
    OK "amwall-core hoisted to repo root; Linux workspace consumes it."
    OK "IPv6 is now ENFORCED (6.4.1): parallel RULES_V6 map + 4-way wildcard."
    OK "Qt6 GUI tabs: Overview / User Rules / Connections + connect-prompt."
    OK "Manually verify:"
    OK "  • User Rules tab: Add/Edit/Delete work; rules appear within ~5s."
    OK "  • Connections tab: live /proc/net/tcp + tcp6, auto-refreshes."
    OK "  • Edit menu > Add rule (Ctrl+N) opens the editor on User Rules."
    OK "  • Try connecting to an IPv6 destination from an unknown app —"
    OK "    you should now get a prompt (was silently allowed pre-6.4.1)."
else
    H "✗ Some Phase 2/3/4/5/6.1/6.2/6.3/6.4/6.4.1/6.5 tests had failures"
    WARN "T1 default-deny:        $TEST1"
    WARN "T2 mtime live-reload:   $TEST2"
    WARN "T3 D-Bus List:          $TEST3"
    WARN "T4 D-Bus Deny (polkit): $TEST4"
    WARN "T5 D-Bus signals:       $TEST5"
    WARN "T6 .deb contents:       $TEST6"
    WARN "T7 amwall-gui --version:$TEST7"
    WARN "See daemon output above + 'sudo dmesg | tail -50'."
    WARN "If T4 alone failed: polkit denied the call. Verify with"
    WARN "    pkaction --action-id org.amwall.Daemon1.modify-rules --verbose"
    WARN "If T7 alone failed: Qt link/runtime issue —"
    WARN "    ldd $GUI_BIN  # look for missing libs"
fi

# ─── Install .deb + start service + launch GUI (auto post-test) ─────
#
# Only runs if all 7 smoke tests passed — a broken daemon shouldn't
# get pushed onto systemd. Set AMWALL_SKIP_INSTALL=1 to skip even on
# success (useful when iterating without churn).
#
# Re-run safe: kills any prior amwall-gui, stops the systemd unit,
# dpkg -i replaces the binary, daemon-reload + restart picks up the
# new code, GUI launched detached so it survives the script's exit.

INSTALLED=0

if [ "${AMWALL_SKIP_INSTALL:-0}" = "1" ]; then
    H "Skipping install (AMWALL_SKIP_INSTALL=1)"
elif [ "$ALL_PASS" != 1 ]; then
    H "Skipping install — some smoke tests failed (see above)"
else
    H "Installing .deb → starting amwall-daemon → launching amwall-gui"

    INFO "Stopping any prior amwall-gui + systemd unit (so dpkg can replace)..."
    pkill -x amwall-gui 2>/dev/null || true
    sudo systemctl stop amwall-daemon 2>/dev/null || true

    # Network-reset before reinstall so accumulated rules.toml entries
    # (allow/deny clicks from the connect-prompt during prior runs) and
    # GUI QSettings (~/.config/amwall/) don't leak across iterations.
    # We use the freshly-built CLI from linux/target/release/ — that's
    # the one with the new `reset` subcommand even if the installed
    # /usr/bin/amwall-cli is older. SUDO_USER is honored for the
    # ~/.config clear so it targets /home/$user/.config/amwall, not
    # /root/.config/amwall.
    INFO "$CLI_BIN reset --yes  (clears rules.toml + ~/.config/amwall)"
    # Plain `sudo` (no -E): env_reset clears AMWALL_RULES_PATH so the
    # CLI uses the hardcoded /etc/amwall/rules.toml default. SUDO_USER
    # is still set by sudo, so user_config_dir() targets the invoking
    # user's home directory not /root/.config/.
    if sudo "$CLI_BIN" reset --yes 2>&1 | sed 's/^/    /'; then
        OK "Pre-install reset done."
    else
        WARN "Pre-install reset failed (continuing anyway — install will overwrite)"
    fi

    # --force-confnew: silently take the .deb's version of conf-files
    # when there's a conflict. Section 4b/4c installed the same
    # content directly into /etc/dbus-1/system.d/ and
    # /usr/share/polkit-1/actions/ as untracked files; on first
    # `dpkg -i` of the .deb, dpkg sees those as conflicting and would
    # otherwise prompt. After this, dpkg owns the files as conf-files.
    INFO "sudo dpkg -i --force-confnew $DEB_FILE"
    if sudo dpkg -i --force-confnew "$DEB_FILE" 2>&1 | sed 's/^/    /'; then
        OK ".deb installed."
    else
        WARN "dpkg -i failed — see above. Skipping service start + GUI."
        WARN "If the failure was missing dependencies: sudo apt install -f"
        exec bash
    fi

    INFO "sudo systemctl daemon-reload && enable --now amwall-daemon"
    sudo systemctl daemon-reload 2>&1 | sed 's/^/    /' || true
    if sudo systemctl enable --now amwall-daemon 2>&1 | sed 's/^/    /'; then
        OK "Service enabled + started."
    else
        WARN "Failed to enable/start service. journalctl tail:"
        sudo journalctl -u amwall-daemon -n 20 --no-pager | sed 's/^/    /'
        exec bash
    fi

    sleep 2
    if systemctl is-active --quiet amwall-daemon; then
        OK "amwall-daemon is active."
    else
        WARN "amwall-daemon is NOT active. journalctl tail:"
        sudo journalctl -u amwall-daemon -n 20 --no-pager | sed 's/^/    /'
        WARN "Skipping GUI launch."
        exec bash
    fi

    # XDG-correct location for the GUI runtime log — Linux equivalent
    # of Win32 amwall's %APPDATA%\amwall\swaplog. Honors $XDG_DATA_HOME
    # if set; otherwise ~/.local/share/amwall/gui.log. The script's
    # tail -F at end-of-run targets the same path.
    GUI_LOG_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/amwall"
    mkdir -p "$GUI_LOG_DIR"
    GUI_OUT="$GUI_LOG_DIR/gui.log"
    export GUI_RUNTIME_LOG="$GUI_OUT"   # picked up by the tail -F at end
    INFO "nohup /usr/bin/amwall-gui (log → $GUI_OUT)"
    nohup /usr/bin/amwall-gui >"$GUI_OUT" 2>&1 &
    disown 2>/dev/null || true
    sleep 2
    if pgrep -x amwall-gui >/dev/null; then
        OK "amwall-gui is running. The dashboard should show '● Connected — N rules'"
        OK "and the right-side status bar should show a 'Last refresh' timestamp ticking."
        INSTALLED=1
    else
        WARN "amwall-gui exited. Output:"
        sed 's/^/    /' "$GUI_OUT"
        WARN "Common cause: no DISPLAY set (run from a Cinnamon terminal,"
        WARN "              not over plain SSH)."
    fi
fi

# ─── Done + drop into shell at repo dir ─────────────────────────────

if [ "$INSTALLED" = 1 ]; then
    H "DONE — Phase 6.5 — amwall installed, IPv6 enforced, Qt6 GUI with Connections tab"
else
    H "DONE — through Phase 6.5; install step skipped/failed"
fi

cat <<EOF
  Repo: $REPO_DIR
  (about to drop you into a shell here; type 'exit' to return)

  Suggested commit + snapshot:
    git add linux/ amwall-core/
    git commit -m "linux: Phase 6.4.1 + 6.5 — IPv6 enforcement + Connections tab"
    # then snapshot the VM as 'phase-6.5-connections-tab'

  Try the prompt (rules.toml is empty by default → everything denies):
    curl --max-time 5 https://example.com
    # Watch a top-level dialog pop up: "curl wants to connect..."
    # Pick Allow → daemon persists rule → curl will succeed on retry.
    # Dashboard 'Pending prompts' counter ticks up while dialog is open.

  Daemon status:
    systemctl status amwall-daemon --no-pager
    journalctl -u amwall-daemon -f
    journalctl -u amwall-daemon -n 30 --no-pager

  Manage rules via D-Bus (polkit gates modifies):
    amwall-cli --dbus list
    amwall-cli --dbus allow firefox any:443
    amwall-cli --dbus deny  curl    1.1.1.1:53
    amwall-cli --dbus del   firefox any:443

  Network reset (between dev iterations, no snapshot needed):
    sudo amwall-cli reset --yes              # rules.toml + ~/.config/amwall
    sudo amwall-cli reset --yes --keep-rules # only clear GUI config
    sudo amwall-cli reset --yes --keep-config # only truncate rules
    # The script's auto-install step calls 'reset --yes' before dpkg -i.

  GUI (Qt6, tray-resident):
    amwall-gui                      # opens main window + tray icon
    amwall-gui --version            # headless: print version and exit
    amwall-gui --help               # CLI usage
    # left-click tray → toggle window; right-click tray → Show/Quit
    # closing the window hides to tray; quit only via tray menu
    # File → Refresh (or F5) re-polls daemon
    # View → Always on top is persisted in ~/.config/amwall/amwall.conf
    pkill -x amwall-gui             # force-kill if needed
    tail -f ~/.local/share/amwall/gui.log   # Qt qDebug/qWarning + DBus errors
    # (XDG-correct location; honors \$XDG_DATA_HOME if set)

  Inspect the D-Bus interface:
    busctl introspect org.amwall.Daemon1 /org/amwall/Daemon1

  Inspect polkit's view of our action:
    pkaction --action-id org.amwall.Daemon1.modify-rules --verbose

  Stop / uninstall:
    sudo systemctl disable --now amwall-daemon
    sudo dpkg -P amwall             # purge (removes /etc/amwall/* too)

  Re-run script (rebuilds, re-installs, relaunches GUI):
    cd $REPO_DIR && ./linux-build.sh
    # set AMWALL_SKIP_INSTALL=1 to iterate without touching systemd

  Phase 6 progress (Qt6 GUI, Windows-amwall feature parity):
    - 6.1   ✓ foundation: QMainWindow + tray + close-to-tray
    - 6.2   ✓ status dashboard + DbusClient + real File/View/Help menus
    - 6.3   ✓ connect-prompt dialog (per-comm Allow/Block, whole-app wildcards)
    - 6.3.1 ${PHASE_631_STATUS:-?} BPF walks task->group_leader->comm so
            Firefox's per-thread DNS Resolver #N collapses to one "firefox"
            prompt. Requires aya-tool + /sys/kernel/btf/vmlinux to generate
            src/vmlinux.rs at build time. Falls back to per-thread comm if
            either is missing — see "Cargo features:" line in the build phase.
    - 6.4   ✓ User Rules tab + Rule editor (Edit menu restored)
    - 6.4.1 ✓ IPv6 default-deny via parallel RULES_V6 BPF map
    - 6.5   ✓ Connections tab (live /proc/net/tcp + tcp6; refresh every 5s)
    - 6.5.1 ✓ Per-process column on Connections — socket inode → PID
            via /proc/<pid>/fd/* walk, 5 s cadence, "(unknown)" for
            sockets owned by other users (run as root to resolve all).
    - 6.6   ✓ Packets log tab — rolling 2000-event ConnectAttempt
            history with filter + pause + AF_UNIX toggle.
    - 6.7   ✓ Apps tab — scans /usr/share/applications (+ flatpak +
            snap + ~/.local). Right-click → allow/deny wildcard rule
            for the comm; or "Show in User Rules" to jump tabs.
    - 6.8   ✓ Settings dialog (General / Notifications / About pages)
            wired from File → Settings (Ctrl+,). Persisted prefs:
            startMinimized, confirmQuit, autoBlockSec (prompt timeout),
            packetslog/showLocal default. Always-on-top mirrored back
            to the View menu after each dialog accept.
    - 6.9   ✓ Blocklist tab — parallel BLOCKLIST_V4/V6 BPF maps
            checked BEFORE per-comm rules so a blocklist hit overrides
            any per-app allow. Ships 3 starter lists (telemetry, ads,
            malware) under /usr/share/amwall/blocklists/. State in
            /etc/amwall/blocklists.toml. Toggle = polkit-gated D-Bus.
            (i18n plumbing deferred — invisible without translators,
            adds little vs. visible blocklist enforcement.)

  Plan Phase 5b — Windows-side wiring of amwall-core — still needs a
  Windows checkout (root Cargo.toml + src/rules/*.rs adoption + MSI
  validation). Lands as a separate commit from a Windows session.
EOF

# ─── Drop the tee + dump the full log before interactive shell ──────
#
# Restore stdout/stderr to the original terminal fds so the cat below
# (and anything the user types at the bash prompt) is NOT appended
# to the run log. The tee subprocess gets EOF on its stdin pipe and
# exits cleanly.
#
# Then re-print the entire log at the bottom of the terminal scroll-
# back, bracketed by easy-to-spot markers, so the user can mass-
# select everything between them and paste back. Without this, the
# log content gets fragmented across scrollback (interleaved with
# sudo prompts, the GUI launch detach, etc.).
if [ -n "${AMWALL_LOGGING_ACTIVE:-}" ]; then
    # Give tee a moment to flush its last writes before we close its
    # pipe. Without this, the final ~lines of in-flight output can
    # be missing from the file when we cat it below.
    sync
    exec 1>&3 2>&4 3>&- 4>&-
    sleep 0.3

    printf '\n'
    printf '════════════════════════════════════════════════════════════\n'
    printf '  ▼▼▼  BEGIN AMWALL RUN LOG  ▼▼▼   (%s)\n' "$AMWALL_LOG_FILE"
    printf '════════════════════════════════════════════════════════════\n'
    cat "$AMWALL_LOG_FILE"
    printf '\n'
    printf '════════════════════════════════════════════════════════════\n'
    printf '  ▲▲▲  END AMWALL RUN LOG  ▲▲▲\n'
    printf '════════════════════════════════════════════════════════════\n'
    printf '\n'

    # ─── GUI runtime log (Qt qDebug/qWarning + crash messages) ──────
    # Dumped AFTER the build log so an immediate-startup GUI crash is
    # visible without a second command. The GUI is still running in
    # the background — anything it logs after this point won't be in
    # this dump; re-cat manually with:
    #   tail -f ${XDG_DATA_HOME:-$HOME/.local/share}/amwall/gui.log
    GUI_RUNTIME_LOG="${GUI_RUNTIME_LOG:-${XDG_DATA_HOME:-$HOME/.local/share}/amwall/gui.log}"
    if [ -s "$GUI_RUNTIME_LOG" ]; then
        printf '════════════════════════════════════════════════════════════\n'
        printf '  ▼▼▼  BEGIN GUI RUNTIME LOG  ▼▼▼   (%s)\n' "$GUI_RUNTIME_LOG"
        printf '════════════════════════════════════════════════════════════\n'
        cat "$GUI_RUNTIME_LOG"
        printf '\n'
        printf '════════════════════════════════════════════════════════════\n'
        printf '  ▲▲▲  END GUI RUNTIME LOG  ▲▲▲\n'
        printf '════════════════════════════════════════════════════════════\n'
        printf '\n'
    elif [ -e "$GUI_RUNTIME_LOG" ]; then
        printf '  (GUI runtime log %s is empty — no warnings yet)\n' "$GUI_RUNTIME_LOG"
        printf '\n'
    fi

    # ─── Coredump (only if amwall-gui crashed during this run) ──────
    # systemd-coredump is enabled on Mint by default. Show the most
    # recent core for amwall-gui only if it's newer than the start of
    # this script — older cores are from prior runs and not relevant.
    if command -v coredumpctl >/dev/null 2>&1; then
        # --since=$AMWALL_RUN_START scopes to this run only.
        if coredumpctl list amwall-gui --since="$AMWALL_RUN_START" --no-pager 2>/dev/null \
              | grep -q amwall-gui; then
            printf '════════════════════════════════════════════════════════════\n'
            printf '  ▼▼▼  AMWALL-GUI COREDUMP (this run)  ▼▼▼\n'
            printf '════════════════════════════════════════════════════════════\n'
            coredumpctl info amwall-gui --no-pager 2>&1 | head -80
            printf '\n'
            printf '════════════════════════════════════════════════════════════\n'
            printf '  ▲▲▲  END COREDUMP  ▲▲▲   coredumpctl gdb amwall-gui to dig\n'
            printf '════════════════════════════════════════════════════════════\n'
            printf '\n'
        fi
    fi

    printf '  Paste blocks above to Claude. Other handy commands:\n'
    printf '      cat %s\n' "$AMWALL_LOG_FILE"
    printf '      cat %s\n' "$GUI_RUNTIME_LOG"
    printf '      coredumpctl info amwall-gui\n'
    printf '\n'
fi

# ─── Live combined log: daemon journal + GUI runtime log ───────────
#
# The user wants to see EVERYTHING in real time as they interact with
# the GUI: connect/allow/deny events from the daemon (which logs to
# systemd journal — that's the standard place for system-service
# stdout/stderr) AND Qt warnings/crashes from the GUI (which the
# script redirects to ~/.local/share/amwall/gui.log).
#
# We tail both, prefixed so the source is obvious:
#    [daem] ← amwall-daemon (journalctl -fu amwall-daemon, sudo)
#    [gui ] ← amwall-gui (~/.local/share/amwall/gui.log)
#
# Ctrl-C kills both via the EXIT trap and returns to the parent shell.
# To re-enter the repo afterwards: cd ~/amwall.

GUI_RUNTIME_LOG="${GUI_RUNTIME_LOG:-${XDG_DATA_HOME:-$HOME/.local/share}/amwall/gui.log}"
mkdir -p "$(dirname "$GUI_RUNTIME_LOG")"
[ -e "$GUI_RUNTIME_LOG" ] || : > "$GUI_RUNTIME_LOG"

printf '════════════════════════════════════════════════════════════\n'
printf '  ▶ live combined log — Ctrl-C to exit\n'
printf '       [daem]  amwall-daemon (allow/deny, D-Bus, BPF)\n'
printf '       [gui ]  amwall-gui    (Qt qDebug/qWarning, crashes)\n'
printf '       GUI log file: %s\n' "$GUI_RUNTIME_LOG"
printf '════════════════════════════════════════════════════════════\n'

# Background tail of the GUI log. sed -u (line-buffered) is GNU sed —
# fine on Linux. Prefix added so output is differentiable when both
# streams interleave.
tail -F "$GUI_RUNTIME_LOG" 2>/dev/null | sed -u 's/^/[gui ] /' &
GUI_TAIL_PID=$!
trap 'kill $GUI_TAIL_PID 2>/dev/null; wait $GUI_TAIL_PID 2>/dev/null; true' EXIT INT

# Foreground: daemon journal, with 50 lines of recent context backfilled
# so the user immediately sees what the daemon did during script setup.
# sudo because journalctl -u <system service> requires elevated read
# perms unless the user is in systemd-journal/adm. The earlier sudo -v
# in the smoke-test block keeps the sudo timestamp warm; usually no
# password prompt here.
sudo journalctl -u amwall-daemon -n 50 -f --no-pager 2>&1 | sed -u 's/^/[daem] /'
