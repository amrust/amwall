#!/usr/bin/env bash
# amwall — Linux build script (per linuxplan.md). Single self-contained
# entry point that takes a fresh Mint 22.x VM (post-OS-updates) all the
# way to "current latest phase built and smoke-tested."
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
    exec > >(tee "$AMWALL_LOG_FILE") 2>&1
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
ASK()  { local p="$1" reply; read -r -p "  ? $p [y/N] " reply; [[ "$reply" =~ ^[Yy]$ ]]; }

write_file() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    cat > "$path"
    NEW "$path"
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
# amwall-ebpf's build.rs uses it to emit a vmlinux.rs containing task_struct so
# the BPF program can read task->group_leader->comm (Phase 6.3.1 — collapses
# Firefox's per-thread "DNS Resolver #N" comms back to the binary name).
#
# Failure here is non-fatal: amwall-ebpf's build.rs detects the absence and
# falls back to the per-thread bpf_get_current_comm() — same behavior as
# pre-6.3.1, just one prompt per thread name as a degraded-mode UX.
INFO "Ensuring aya-tool (BTF→Rust bindings for task_struct walk)..."
if command -v aya-tool >/dev/null 2>&1; then
    OK "aya-tool already installed"
else
    INFO "Building aya-tool via cargo install (2-3 min)..."
    if cargo install --locked aya-tool 2>&1 | sed 's/^/    /'; then
        OK "aya-tool installed"
    else
        WARN "aya-tool install failed — BPF will use per-thread comm fallback"
        WARN "(multi-thread apps like Firefox will spam prompts; not blocking)"
    fi
fi

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

write_file linux/.gitignore <<'EOF'
/target/
**/*.rs.bk
EOF

write_file linux/Cargo.toml <<'EOF'
# linux/ — amwall Linux workspace.
#
# amwall-ebpf is intentionally NOT a workspace member. BPF crates need
# their own toolchain (nightly + rust-src) and target (bpfel-unknown-none),
# which conflicts with the userspace crates. It's built standalone:
#     cd amwall-ebpf && cargo build
#
# amwall-core is NOT a workspace member either — Phase 5 hoisted it
# to the repo root (../amwall-core) so the Windows crate can later
# adopt it. Linux workspace members reference it via
# [workspace.dependencies] below, so per-crate Cargo.tomls keep using
# `amwall-core.workspace = true` unchanged.
#
# See linuxproposal.md for the full architecture.

[workspace]
resolver = "2"
members = [
    "amwall-daemon",
    "amwall-cli",
]
exclude = ["amwall-ebpf"]
# Phase 6.1: amwall-gui is no longer a Rust crate — it's a C++/Qt6
# project under linux/amwall-gui-qt/, built by CMake. See that
# directory's CMakeLists.txt.

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT"
repository = "https://github.com/amrust/amwall"

[workspace.dependencies]
amwall-core = { path = "../amwall-core" }
EOF

# ─── amwall-core — shared rule types + TOML I/O (Phase 5: at repo root) ───

H "amwall-core (shared rule types — at repo root for cross-platform reuse)"

write_file amwall-core/.gitignore <<'EOF'
/target/
**/*.rs.bk
EOF

write_file amwall-core/Cargo.toml <<'EOF'
[package]
name = "amwall-core"
version = "0.1.0"
edition = "2021"
license = "MIT"
repository = "https://github.com/amrust/amwall"
description = "Shared rule types and TOML I/O for amwall (Linux + Windows)"

[lib]

[dependencies]
anyhow = "1"
serde = { version = "1", features = ["derive"] }
toml = "0.8"
EOF

write_file amwall-core/src/lib.rs <<'EOF'
//! amwall-core — types and TOML I/O shared between amwall-daemon,
//! amwall-cli, and (eventually) the Windows crate at the repo root.
//!
//! This crate intentionally lives at the REPO ROOT (not under linux/)
//! so the Windows crate can adopt it incrementally without a path
//! that crosses platform-specific subdirectories. Linux workspace
//! members consume it via linux/Cargo.toml's [workspace.dependencies]
//! `amwall-core = { path = "../amwall-core" }`.
//!
//! Windows adoption (post-Phase-5b commit) will be:
//!   1. root Cargo.toml: `amwall-core = { path = "amwall-core" }`
//!   2. src/rules/*.rs: re-export or replace internal Rule type
//!      with amwall_core::rules types where the schemas align.
//!
//! The TOML schema here is Linux's wire format. Windows still owns
//! the simplewall XML profile schema and the rule-string AST under
//! src/rules/parse.rs — those are NOT yet shared. Future work.

pub mod rules;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
EOF

write_file amwall-core/src/rules.rs <<'EOF'
//! Rule on-disk schema (TOML) and conversion to BPF-map keys/values.
//!
//! TOML schema:
//!
//!     [[rule]]
//!     comm   = "curl"      # process name (max 15 chars, matches BPF comm)
//!     ip     = "any"       # "any" or an IPv4 dotted-quad
//!     port   = 443         # 0 = any
//!     action = "allow"     # or "deny"

use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub comm: String,
    pub ip: String,
    pub port: u16,
    pub action: Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RulesFile {
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

impl Rule {
    pub fn comm_bytes(&self) -> [u8; 16] {
        let bytes = self.comm.as_bytes();
        let mut out = [0u8; 16];
        let n = bytes.len().min(15);
        out[..n].copy_from_slice(&bytes[..n]);
        out
    }

    pub fn ip4(&self) -> Result<u32> {
        let s = self.ip.trim();
        if s.eq_ignore_ascii_case("any") || s == "0.0.0.0" || s.is_empty() {
            return Ok(0);
        }
        let addr = Ipv4Addr::from_str(s)
            .with_context(|| format!("rule ip '{}' is not 'any' or a v4 address", s))?;
        Ok(u32::from(addr).to_be())
    }

    pub fn action_byte(&self) -> u8 {
        match self.action {
            Action::Allow => 1,
            Action::Deny => 0,
        }
    }
}

impl RulesFile {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        if text.trim().is_empty() {
            return Ok(Self::default());
        }
        toml::from_str(&text)
            .with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("mkdir -p {}", parent.display()))?;
            }
        }
        let text = toml::to_string_pretty(self).context("serializing rules to TOML")?;
        std::fs::write(path, text)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }
}
EOF

# ─── amwall-cli — TOML mode + D-Bus mode ────────────────────────────

H "amwall-cli (TOML edit + --dbus mode via system bus)"

write_file linux/amwall-cli/Cargo.toml <<'EOF'
[package]
name = "amwall-cli"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
amwall-core.workspace = true
anyhow = "1"
clap = { version = "4", features = ["derive", "env"] }
zbus = "4"
EOF

write_file linux/amwall-cli/src/main.rs <<'EOF'
//! amwall-cli — manage rules.toml directly OR via D-Bus to a running
//! amwall-daemon.
//!
//!   amwall-cli list
//!   amwall-cli allow <comm> <ip>:<port>
//!   amwall-cli deny  <comm> <ip>:<port>
//!   amwall-cli del   <comm> <ip>:<port>
//!   amwall-cli reset [--yes] [--keep-rules] [--keep-config]
//!
//! Add `--dbus` to route the call through the daemon's
//! org.amwall.Daemon1 interface on the SYSTEM bus instead of editing
//! rules.toml. Requires amwall-daemon running and the policy file at
//! /etc/dbus-1/system.d/org.amwall.Daemon1.conf to be installed.
//!
//! `reset` truncates rules.toml AND clears ~/.config/amwall/ (the
//! GUI's QSettings dir). Equivalent to the Win32 amwall "Network
//! reset" item. Run as sudo for /etc/amwall/rules.toml; the user-
//! config part honors $SUDO_USER so it still targets the invoking
//! user's home directory rather than /root/.config/.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;

use amwall_core::rules::{Action, Rule, RulesFile};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "amwall-cli", version, about = "Manage amwall rules")]
struct Cli {
    /// Path to rules.toml (TOML mode only — ignored with --dbus).
    #[arg(long, env = "AMWALL_RULES_PATH")]
    rules: Option<PathBuf>,

    /// Talk to amwall-daemon via D-Bus instead of editing rules.toml.
    #[arg(long)]
    dbus: bool,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Clone)]
enum Cmd {
    /// Print current rules.
    List,
    /// Add an allow rule.
    Allow { comm: String, dest: String },
    /// Add a deny rule.
    Deny { comm: String, dest: String },
    /// Remove a rule.
    Del { comm: String, dest: String },
    /// Reset to clean state: truncate rules.toml + clear ~/.config/amwall/.
    /// Equivalent to Win32 amwall "Network reset". TOML mode only;
    /// run as sudo so it can write /etc/amwall/rules.toml.
    Reset {
        /// Skip the y/N confirmation prompt.
        #[arg(short = 'y', long)]
        yes: bool,
        /// Don't truncate rules.toml.
        #[arg(long)]
        keep_rules: bool,
        /// Don't clear ~/.config/amwall/.
        #[arg(long)]
        keep_config: bool,
    },
}

#[zbus::proxy(
    interface = "org.amwall.Daemon1",
    default_service = "org.amwall.Daemon1",
    default_path = "/org/amwall/Daemon1",
    gen_blocking = true,
    gen_async = false,
)]
trait AmwallDaemon {
    fn allow(&self, comm: &str, ip: &str, port: u16) -> zbus::Result<()>;
    fn deny(&self, comm: &str, ip: &str, port: u16) -> zbus::Result<()>;
    fn del(&self, comm: &str, ip: &str, port: u16) -> zbus::Result<()>;
    fn list(&self) -> zbus::Result<Vec<(String, String, u16, String)>>;
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.dbus {
        run_dbus(cli.command)
    } else {
        run_toml(cli.rules, cli.command)
    }
}

fn run_dbus(cmd: Cmd) -> Result<()> {
    if matches!(cmd, Cmd::Reset { .. }) {
        // Daemon doesn't expose a Reset method yet — would need to
        // truncate the file + clear the BPF map atomically under
        // the rules mutex. Until that lands, route through TOML
        // mode (which only needs sudo for /etc/amwall/rules.toml).
        anyhow::bail!(
            "--dbus reset is not implemented yet; use:\n  sudo amwall-cli reset");
    }

    let conn = zbus::blocking::Connection::system()
        .context("connecting to D-Bus system bus")?;
    let proxy = AmwallDaemonProxy::new(&conn)
        .context("creating D-Bus proxy (is amwall-daemon running?)")?;

    match cmd {
        Cmd::List => {
            let rules = proxy.list().context("D-Bus List() failed")?;
            if rules.is_empty() {
                println!("(no rules)");
            } else {
                for (c, ip, p, a) in rules {
                    println!("{:5}  comm={:<16} {}:{}", a.to_uppercase(), c, ip, p);
                }
            }
        }
        Cmd::Allow { comm, dest } => {
            let (ip, port) = parse_dest(&dest)?;
            proxy.allow(&comm, &ip, port).context("D-Bus Allow() failed")?;
            eprintln!("[via D-Bus] allowed: {} {}:{}", comm, ip, port);
        }
        Cmd::Deny { comm, dest } => {
            let (ip, port) = parse_dest(&dest)?;
            proxy.deny(&comm, &ip, port).context("D-Bus Deny() failed")?;
            eprintln!("[via D-Bus] denied: {} {}:{}", comm, ip, port);
        }
        Cmd::Del { comm, dest } => {
            let (ip, port) = parse_dest(&dest)?;
            proxy.del(&comm, &ip, port).context("D-Bus Del() failed")?;
            eprintln!("[via D-Bus] removed: {} {}:{}", comm, ip, port);
        }
        Cmd::Reset { .. } => unreachable!("handled by the matches!() guard above"),
    }
    Ok(())
}

fn run_toml(rules_arg: Option<PathBuf>, cmd: Cmd) -> Result<()> {
    if let Cmd::Reset { yes, keep_rules, keep_config } = cmd {
        return do_reset(rules_arg, yes, keep_rules, keep_config);
    }
    let path = rules_arg.unwrap_or_else(default_rules_path);
    let mut file = RulesFile::load(&path)?;

    match cmd {
        Cmd::List => {
            if file.rules.is_empty() {
                println!("(no rules — default-deny applies to all IPv4 connects)");
            } else {
                for r in &file.rules {
                    println!(
                        "{:5}  comm={:<16} {}:{}",
                        action_str(r.action),
                        r.comm,
                        r.ip,
                        r.port
                    );
                }
            }
            return Ok(());
        }
        Cmd::Allow { comm, dest } => upsert(&mut file, comm, dest, Action::Allow)?,
        Cmd::Deny  { comm, dest } => upsert(&mut file, comm, dest, Action::Deny)?,
        Cmd::Del   { comm, dest } => {
            let (ip, port) = parse_dest(&dest)?;
            file.rules.retain(|r| !(r.comm == comm && r.ip == ip && r.port == port));
        }
        Cmd::Reset { .. } => unreachable!("handled by the early-return at top of run_toml"),
    }

    file.save(&path)?;
    eprintln!("wrote {} ({} rules)", path.display(), file.rules.len());
    Ok(())
}

fn do_reset(rules_arg: Option<PathBuf>, yes: bool, keep_rules: bool, keep_config: bool) -> Result<()> {
    // Reset targets the SYSTEM rules.toml by default, not
    // ~/.config/amwall/rules.toml. Under sudo, default_rules_path()
    // would return /root/.config/... because HOME is reset to /root,
    // which is never what reset wants. --rules overrides if needed.
    let rules_path = rules_arg.unwrap_or_else(|| PathBuf::from("/etc/amwall/rules.toml"));
    let user_cfg = user_config_dir();

    eprintln!("amwall-cli reset:");
    if !keep_rules {
        eprintln!("  • truncate {}", rules_path.display());
    }
    if !keep_config {
        match &user_cfg {
            Some(p) => eprintln!("  • remove   {}", p.display()),
            None    => eprintln!("  • (no user-config dir found — SUDO_USER and HOME both unset)"),
        }
    }
    if keep_rules && keep_config {
        eprintln!("  (nothing to do — both --keep-rules and --keep-config set)");
        return Ok(());
    }

    if !yes {
        use std::io::Write;
        eprint!("Proceed? [y/N] ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)
            .context("reading confirmation from stdin")?;
        let line = line.trim();
        if !(line.eq_ignore_ascii_case("y") || line.eq_ignore_ascii_case("yes")) {
            eprintln!("aborted.");
            return Ok(());
        }
    }

    if !keep_rules {
        // Atomic truncate via empty-file write. Daemon mtime poll
        // catches it within ~100 ms and rebuilds its BPF map empty.
        std::fs::write(&rules_path, b"")
            .with_context(|| format!(
                "truncating {} (need sudo for /etc/amwall/?)",
                rules_path.display()))?;
        eprintln!("  ✓ truncated {}", rules_path.display());
    }
    if !keep_config {
        if let Some(p) = user_cfg {
            if p.exists() {
                std::fs::remove_dir_all(&p)
                    .with_context(|| format!("removing {}", p.display()))?;
                eprintln!("  ✓ removed {}", p.display());
            } else {
                eprintln!("  - {} did not exist", p.display());
            }
        }
    }
    Ok(())
}

fn user_config_dir() -> Option<PathBuf> {
    // Honor SUDO_USER so `sudo amwall-cli reset` clears the invoking
    // user's config dir, not /root/.config/amwall/. Falls back to
    // $HOME for non-sudo invocations.
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() && sudo_user != "root" {
            return Some(PathBuf::from(format!("/home/{}/.config/amwall", sudo_user)));
        }
    }
    if let Ok(h) = std::env::var("HOME") {
        return Some(PathBuf::from(h).join(".config/amwall"));
    }
    None
}

fn upsert(file: &mut RulesFile, comm: String, dest: String, action: Action) -> Result<()> {
    let (ip, port) = parse_dest(&dest)?;
    file.rules.retain(|r| !(r.comm == comm && r.ip == ip && r.port == port));
    file.rules.push(Rule { comm, ip, port, action });
    Ok(())
}

fn parse_dest(s: &str) -> Result<(String, u16)> {
    let (ip_s, port_s) = s.rsplit_once(':')
        .with_context(|| format!("dest must be 'ip:port' (got '{}')", s))?;
    let port: u16 = port_s.parse().context("port must be 0-65535")?;
    let ip_norm = if ip_s.eq_ignore_ascii_case("any") || ip_s == "0.0.0.0" || ip_s.is_empty() {
        "any".to_string()
    } else {
        Ipv4Addr::from_str(ip_s)
            .with_context(|| format!("ip '{}' is not 'any' or a v4 address", ip_s))?
            .to_string()
    };
    Ok((ip_norm, port))
}

fn default_rules_path() -> PathBuf {
    if let Ok(h) = std::env::var("HOME") {
        PathBuf::from(h).join(".config/amwall/rules.toml")
    } else {
        PathBuf::from("/etc/amwall/rules.toml")
    }
}

fn action_str(a: Action) -> &'static str {
    match a { Action::Allow => "ALLOW", Action::Deny => "DENY" }
}
EOF

# ─── amwall-gui — C++/Qt6 hybrid (Phase 6.1 + 6.2 + 6.3) ────────────
#
# 6.1 laid the QMainWindow + tray + close-to-tray foundation.
# 6.2 added DbusClient + status dashboard + permanent status bar +
#     trimmed menu bar to only menus whose items have real handlers.
# 6.3 adds the connect-prompt dialog: subscribe to ConnectAttempt,
#     filter for default-denies, queue + dedup, modeless top-level
#     dialog with Allow / Block / Dismiss persisting decisions over
#     the existing Daemon1.Allow/Deny methods. Restores Win32-amwall
#     "first-run" behavior. Edit / Settings / Blocklist menus still
#     return in 6.4 / 6.8 / 6.x.

H "amwall-gui-qt (C++/Qt6 — connect-prompt dialog + rule cache)"

write_file linux/amwall-gui-qt/CMakeLists.txt <<'EOF'
cmake_minimum_required(VERSION 3.16)
project(amwall-gui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Qt's signal/slot meta-object machinery + .ui form support + .qrc
# resource embedding — generated at build time.
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Qt6 from qt6-base-dev on Mint 22 / Ubuntu 24.04. Components needed
# so far: Widgets (QMainWindow, menus, tray, dashboard) + DBus
# (talking to amwall-daemon over the system bus) + Network
# (QHostAddress for IPv4 validation in the rule editor). Phases 6.5+
# may add Concurrent (background worker for /proc walks) and
# LinguistTools (translations).
find_package(Qt6 REQUIRED COMPONENTS Widgets DBus Network)

# AMWALL_VERSION is baked into the binary so --version and the About
# box show the same string the .deb is built with. Bumped per phase.
add_compile_definitions(AMWALL_VERSION="0.1.0+phase6.4")

add_executable(amwall-gui
    src/main.cpp
    src/mainwindow.cpp
    src/mainwindow.h
    src/dbusclient.cpp
    src/dbusclient.h
    src/dashboard.cpp
    src/dashboard.h
    src/connectprompt.cpp
    src/connectprompt.h
    src/promptcoordinator.cpp
    src/promptcoordinator.h
    src/userrulestab.cpp
    src/userrulestab.h
    src/ruleeditor.cpp
    src/ruleeditor.h
)

target_link_libraries(amwall-gui PRIVATE
    Qt6::Widgets
    Qt6::DBus
    Qt6::Network
)
EOF

write_file linux/amwall-gui-qt/src/main.cpp <<'EOF'
// amwall-gui — entry point (Phase 6.1 foundation + 6.2 dashboard).
//
// Hybrid C++/Qt6 GUI: talks to amwall-daemon over the existing
// org.amwall.Daemon1 system-bus interface (same wire as
// amwall-cli --dbus). Replaces the Phase 3.5 Iced popup.
//
// Tray-resident: closing the window hides instead of quitting; the
// tray icon's right-click → Quit is the real exit path.
//
// CLI flags handled before QApplication is constructed (so --version
// / --help work in headless environments without a Qt display):
//   --version, -V    print version and exit
//   --help,    -h    print usage and exit

#include <QApplication>

#include <cstdio>
#include <cstring>

#include "mainwindow.h"

#ifndef AMWALL_VERSION
#define AMWALL_VERSION "unknown"
#endif

int main(int argc, char *argv[]) {
    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if (std::strcmp(a, "--version") == 0 || std::strcmp(a, "-V") == 0) {
            std::printf("amwall-gui %s\n", AMWALL_VERSION);
            return 0;
        }
        if (std::strcmp(a, "--help") == 0 || std::strcmp(a, "-h") == 0) {
            std::printf(
                "amwall-gui — Qt6 front-end for amwall-daemon\n"
                "\n"
                "Usage: amwall-gui [OPTIONS]\n"
                "\n"
                "Options:\n"
                "  -V, --version   print version and exit\n"
                "  -h, --help      show this message and exit\n"
                "\n"
                "Talks to org.amwall.Daemon1 on the system bus. The\n"
                "daemon must be running (sudo systemctl start amwall-daemon).\n");
            return 0;
        }
    }

    QApplication app(argc, argv);
    app.setApplicationName("amwall");
    app.setApplicationDisplayName("amwall");
    app.setApplicationVersion(AMWALL_VERSION);
    app.setOrganizationName("amwall");
    app.setOrganizationDomain("amwall.local");
    app.setDesktopFileName("amwall");

    // Tray icon keeps the process alive after the last window closes.
    app.setQuitOnLastWindowClosed(false);

    MainWindow w;
    w.show();

    return app.exec();
}
EOF

write_file linux/amwall-gui-qt/src/mainwindow.h <<'EOF'
// amwall-gui — main window (Phase 6.1 foundation + 6.2 dashboard).
//
// Wires together: DbusClient (live D-Bus state polling), Dashboard
// (central widget that renders DbusClient state + offers refresh),
// menu bar (only menus whose items are real handlers — File / View
// / Help), permanent status-bar widgets, and the system tray icon.
//
// Edit / Settings / Blocklist menus are intentionally absent: they
// reappear when 6.4 (Edit needs tabs) / 6.8 (Settings dialog) /
// 6.x (Blocklist) bring the things they would act on. Empty menus
// would be placeholders, which violates the project's "no
// placeholders" rule.

#pragma once

#include <QMainWindow>
#include <QSystemTrayIcon>

class QAction;
class QCloseEvent;
class QLabel;
class QMenu;
class QTabWidget;
class DbusClient;
class Dashboard;
class PromptCoordinator;
class UserRulesTab;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void onTrayActivated(QSystemTrayIcon::ActivationReason reason);
    void onShowHide();
    void onQuit();
    void onAbout();
    void onAlwaysOnTopToggled(bool on);
    void onDbusStateChanged();
    void onAddRuleFromMenu();   // Edit > Add Rule — switches to User Rules tab

private:
    void setupCentralWidget();
    void setupMenuBar();
    void setupStatusBar();
    void setupTrayIcon();
    void loadSettings();

    DbusClient        *m_dbus = nullptr;
    PromptCoordinator *m_prompts = nullptr;
    QTabWidget        *m_tabs = nullptr;
    Dashboard         *m_dashboard = nullptr;
    UserRulesTab      *m_userRules = nullptr;

    QLabel *m_statusDaemon = nullptr;   // permanent left widget
    QLabel *m_statusRefresh = nullptr;  // permanent right widget

    QSystemTrayIcon *m_trayIcon = nullptr;
    QMenu *m_trayMenu = nullptr;
    QAction *m_showHideAction = nullptr;
    QAction *m_quitAction = nullptr;

    QAction *m_alwaysOnTopAction = nullptr;
};
EOF

write_file linux/amwall-gui-qt/src/mainwindow.cpp <<'EOF'
#include "mainwindow.h"

#include "dashboard.h"
#include "dbusclient.h"
#include "promptcoordinator.h"
#include "userrulestab.h"

#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QIcon>
#include <QKeySequence>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QSettings>
#include <QStatusBar>
#include <QStyle>
#include <QTabWidget>
#include <QtGlobal>

#ifndef AMWALL_VERSION
#define AMWALL_VERSION "unknown"
#endif

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle("amwall");
    resize(900, 600);

    m_dbus = new DbusClient(this);
    connect(m_dbus, &DbusClient::stateChanged,
            this, &MainWindow::onDbusStateChanged);

    // PromptCoordinator must exist BEFORE Dashboard so Dashboard can
    // bind to its pendingCountChanged signal in its constructor.
    m_prompts = new PromptCoordinator(m_dbus, /*windowAnchor=*/this, this);

    setupCentralWidget();
    setupStatusBar();
    setupMenuBar();
    setupTrayIcon();
    loadSettings();

    // Initial poll + start the auto-refresh heartbeat. Dashboard +
    // status bar both render off DbusClient::stateChanged.
    m_dbus->startAutoRefresh(5000);
    m_dbus->refresh();
}

void MainWindow::setupCentralWidget() {
    // Tabbed central. Overview = the existing dashboard. User Rules
    // = the rule list + add/edit/delete (Phase 6.4). 6.5 will append
    // a "Connections" tab; 6.6 a "Packets log" tab; etc.
    m_tabs = new QTabWidget(this);
    m_dashboard = new Dashboard(m_dbus, m_prompts, this);
    m_userRules = new UserRulesTab(m_dbus, this);
    m_tabs->addTab(m_dashboard, tr("&Overview"));
    m_tabs->addTab(m_userRules, tr("&User Rules"));
    // Default to User Rules — that's the action surface; the
    // dashboard is informational and a click away.
    m_tabs->setCurrentWidget(m_userRules);
    setCentralWidget(m_tabs);
}

void MainWindow::onAddRuleFromMenu() {
    if (m_tabs && m_userRules) {
        m_tabs->setCurrentWidget(m_userRules);
        m_userRules->onAddRule();
    }
}

void MainWindow::setupMenuBar() {
    // Only menus with real working handlers are added. See header
    // comment for why Edit / Settings / Blocklist are absent.
    auto *file = menuBar()->addMenu(tr("&File"));
    auto *refresh = file->addAction(tr("&Refresh"));
    refresh->setShortcut(QKeySequence(QKeySequence::Refresh));  // F5
    refresh->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
    connect(refresh, &QAction::triggered, m_dbus, &DbusClient::refresh);
    file->addSeparator();
    auto *quit = file->addAction(tr("&Quit"));
    quit->setShortcut(QKeySequence::Quit);  // Ctrl+Q
    quit->setIcon(style()->standardIcon(QStyle::SP_DialogCloseButton));
    connect(quit, &QAction::triggered, this, &MainWindow::onQuit);

    // Edit menu (re-introduced in Phase 6.4 now that User Rules tab
    // gives the menu items something to act on). Edit / Delete live
    // on the tab itself (selection-driven); only Add Rule is global.
    auto *edit = menuBar()->addMenu(tr("&Edit"));
    auto *addRule = edit->addAction(tr("&Add rule..."));
    addRule->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_N));
    addRule->setIcon(style()->standardIcon(QStyle::SP_FileDialogNewFolder));
    connect(addRule, &QAction::triggered,
            this, &MainWindow::onAddRuleFromMenu);

    auto *view = menuBar()->addMenu(tr("&View"));
    auto *show = view->addAction(tr("&Show window"));
    show->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_W));
    connect(show, &QAction::triggered, this, [this]() {
        // Force-show (vs toggle) so menu item has predictable effect.
        this->show();
        this->raise();
        this->activateWindow();
    });
    m_alwaysOnTopAction = view->addAction(tr("&Always on top"));
    m_alwaysOnTopAction->setCheckable(true);
    connect(m_alwaysOnTopAction, &QAction::toggled,
            this, &MainWindow::onAlwaysOnTopToggled);

    auto *help = menuBar()->addMenu(tr("&Help"));
    auto *about = help->addAction(tr("&About amwall..."));
    about->setIcon(style()->standardIcon(QStyle::SP_MessageBoxInformation));
    connect(about, &QAction::triggered, this, &MainWindow::onAbout);
}

void MainWindow::setupStatusBar() {
    // Permanent widgets stay pinned (vs the transient showMessage
    // area which is reserved for hover tooltips and short status
    // pulses). Mirrors simplewall's IDC_STATUSBAR layout: state on
    // the left, supplementary info on the right.
    m_statusDaemon = new QLabel(tr("● Daemon: probing..."), this);
    m_statusDaemon->setMargin(4);
    statusBar()->addPermanentWidget(m_statusDaemon, /*stretch=*/1);

    m_statusRefresh = new QLabel(tr("Last refresh: —"), this);
    m_statusRefresh->setMargin(4);
    statusBar()->addPermanentWidget(m_statusRefresh, /*stretch=*/0);
}

void MainWindow::setupTrayIcon() {
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        qWarning() << "amwall-gui: system tray not available on this desktop";
        return;
    }

    QIcon icon = QIcon::fromTheme(
        "network-firewall",
        style()->standardIcon(QStyle::SP_ComputerIcon));

    m_trayIcon = new QSystemTrayIcon(icon, this);
    m_trayIcon->setToolTip("amwall — application firewall");

    m_trayMenu = new QMenu(this);
    m_showHideAction = m_trayMenu->addAction(tr("&Show / Hide"));
    connect(m_showHideAction, &QAction::triggered, this, &MainWindow::onShowHide);
    m_trayMenu->addSeparator();
    m_quitAction = m_trayMenu->addAction(tr("&Quit"));
    connect(m_quitAction, &QAction::triggered, this, &MainWindow::onQuit);
    m_trayIcon->setContextMenu(m_trayMenu);

    connect(m_trayIcon, &QSystemTrayIcon::activated,
            this, &MainWindow::onTrayActivated);

    m_trayIcon->show();
}

void MainWindow::loadSettings() {
    QSettings s;  // uses Org=amwall, App=amwall (set in main.cpp)
    bool aot = s.value("view/alwaysOnTop", false).toBool();
    if (aot && m_alwaysOnTopAction) {
        m_alwaysOnTopAction->setChecked(true);  // triggers onAlwaysOnTopToggled
    }
}

void MainWindow::onTrayActivated(QSystemTrayIcon::ActivationReason reason) {
    if (reason == QSystemTrayIcon::Trigger) {
        // Single left-click toggles window visibility (matches Win32
        // amwall's tray-click behavior in src/gui/tray.rs).
        onShowHide();
    }
}

void MainWindow::onShowHide() {
    if (isVisible()) {
        hide();
    } else {
        show();
        raise();
        activateWindow();
    }
}

void MainWindow::onQuit() {
    QApplication::quit();
}

void MainWindow::onAbout() {
    QString text = tr(
        "<h3>amwall</h3>"
        "<p>Per-application firewall for Linux.</p>"
        "<p>Version: <b>%1</b><br>"
        "Built with Qt %2</p>"
        "<p>The daemon (amwall-daemon) enforces default-deny on egress "
        "via a BPF LSM hook; this GUI talks to it over the system D-Bus "
        "interface <code>org.amwall.Daemon1</code>.</p>"
        "<p>amwall-cli (<code>amwall-cli --dbus list</code>) is the "
        "matching command-line client.</p>"
        "<p>Source: <a href='https://github.com/amrust/amwall'>"
        "github.com/amrust/amwall</a></p>")
        .arg(QString::fromLatin1(AMWALL_VERSION),
             QString::fromLatin1(qVersion()));
    QMessageBox::about(this, tr("About amwall"), text);
}

void MainWindow::onAlwaysOnTopToggled(bool on) {
    // Toggling WindowStaysOnTopHint requires re-show on X11/Wayland.
    Qt::WindowFlags f = windowFlags();
    if (on) {
        f |= Qt::WindowStaysOnTopHint;
    } else {
        f &= ~Qt::WindowStaysOnTopHint;
    }
    setWindowFlags(f);
    QSettings().setValue("view/alwaysOnTop", on);
    show();  // re-realize the window with the new flags
}

void MainWindow::onDbusStateChanged() {
    // Render DbusClient state into the permanent status-bar widgets.
    // Dashboard listens to the same signal independently.
    if (m_dbus->isReachable()) {
        m_statusDaemon->setText(
            tr("<span style='color:#2e7d32'>●</span> "
               "Daemon: connected — %n rule(s) loaded", "",
               m_dbus->ruleCount()));
        if (m_trayIcon) {
            m_trayIcon->setToolTip(
                tr("amwall — connected (%1 rules)").arg(m_dbus->ruleCount()));
        }
    } else {
        QString reason = m_dbus->lastError();
        m_statusDaemon->setText(
            tr("<span style='color:#c62828'>○</span> "
               "Daemon: not reachable%1")
                .arg(reason.isEmpty() ? QString()
                                      : QStringLiteral(" — %1").arg(reason)));
        if (m_trayIcon) {
            m_trayIcon->setToolTip(tr("amwall — daemon not reachable"));
        }
    }

    QDateTime ts = m_dbus->lastRefresh();
    m_statusRefresh->setText(
        ts.isValid() ? tr("Last refresh: %1").arg(ts.toString("HH:mm:ss"))
                     : tr("Last refresh: —"));
}

void MainWindow::closeEvent(QCloseEvent *event) {
    // Close-to-tray: hide instead of quit. The tray icon's Quit menu
    // item is the real exit path.
    if (m_trayIcon && m_trayIcon->isVisible()) {
        hide();
        event->ignore();
    } else {
        event->accept();
    }
}
EOF

write_file linux/amwall-gui-qt/src/dbusclient.h <<'EOF'
// DbusClient — D-Bus client for org.amwall.Daemon1.
//
// Owns the system-bus connection. Polls Peer.Ping + List() on a
// QTimer (or on-demand via refresh()) to keep the rule cache fresh.
// Subscribes to the ConnectAttempt signal and re-emits it as a Qt
// signal so PromptCoordinator can react. Provides allow()/deny()
// helpers that fire-and-forget the corresponding daemon methods
// (polkit gates them server-side; failures land in qWarning).
//
// Synchronous .call() is used for List/Ping (small payload, local
// daemon) — async would just add complexity for sub-millisecond
// responses. allow()/deny() use asyncCall to avoid blocking the GUI
// while polkit prompts (when applicable).

#pragma once

#include <QDateTime>
#include <QDBusArgument>
#include <QList>
#include <QMetaType>
#include <QObject>
#include <QString>

class QTimer;

struct RuleEntry {
    QString comm;
    QString ip;
    QString action;  // "allow" or "deny"
    ushort  port;
};
Q_DECLARE_METATYPE(RuleEntry)

// Free-function streaming operators — registered with the D-Bus
// metatype system in DbusClient's ctor. Once registered, Qt can
// (un)marshal QList<RuleEntry> directly via operator>> on a
// QDBusArgument with no manual beginArray/beginStructure dance.
// The manual dance triggers "QDBusArgument: write from a read-only
// object" warnings (because the value-copy hits non-const overloads)
// and eventually corrupts libdbus state into a struct/basic mismatch.
QDBusArgument& operator<<(QDBusArgument &arg, const RuleEntry &e);
const QDBusArgument& operator>>(const QDBusArgument &arg, RuleEntry &e);

class DbusClient : public QObject {
    Q_OBJECT

public:
    explicit DbusClient(QObject *parent = nullptr);

    bool isReachable() const         { return m_reachable; }
    int  ruleCount()   const         { return m_rules.size(); }
    const QList<RuleEntry>& rules() const { return m_rules; }
    QDateTime lastRefresh() const    { return m_lastRefresh; }
    QString lastError() const        { return m_lastError; }

    // True if rules.toml already contains ANY rule (allow or deny,
    // any IP, any port) for this comm. Once the user has decided
    // about an app — even just one specific destination — we don't
    // re-prompt. Matches simplewall/Win32 amwall semantics: the
    // prompt is per-process, not per-(process, ip, port).
    bool hasAnyRuleFor(const QString &comm) const;

    void startAutoRefresh(int intervalMs);
    void stopAutoRefresh();

public slots:
    // Re-poll the daemon and emit stateChanged().
    void refresh();

    // Persist a rule via the daemon. Async — if polkit denies, a
    // qWarning lands in ~/.local/share/amwall/gui.log. After the next refresh
    // tick the rule shows up in our cache.
    void allow(const QString &comm, const QString &ip, ushort port);
    void deny(const QString &comm, const QString &ip, ushort port);

    // Delete an existing rule. Same async pattern.
    void del(const QString &comm, const QString &ip, ushort port);

signals:
    void stateChanged();

    // Re-emitted from the D-Bus ConnectAttempt signal. Filtering
    // (action / family / dedup) lives in PromptCoordinator.
    void connectAttempt(uint pid, const QString &comm,
                        const QString &ip, ushort port,
                        const QString &action);

private slots:
    // Private — wired to QDBusConnection::connect() with the OLD-
    // style SLOT() macro because Qt's D-Bus signal demarshaller
    // requires it. Forwards to the public Qt connectAttempt signal.
    void onDbusConnectAttempt(uint pid, const QString &comm,
                              const QString &ip, ushort port,
                              const QString &action);

private:
    bool pingDaemon(QString *errOut);
    bool listRules(QList<RuleEntry> *out, QString *errOut);
    void subscribeSignals();
    void callModify(const char *method, const QString &comm,
                    const QString &ip, ushort port);

    QTimer *m_timer = nullptr;

    bool             m_reachable = false;
    QList<RuleEntry> m_rules;
    QDateTime        m_lastRefresh;
    QString          m_lastError;
};
EOF

write_file linux/amwall-gui-qt/src/dbusclient.cpp <<'EOF'
#include "dbusclient.h"

#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusError>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusPendingCall>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDebug>
#include <QTimer>

QDBusArgument& operator<<(QDBusArgument &arg, const RuleEntry &e) {
    // Wire order MUST match the daemon's interface:
    //   List() returns a(ssqs) — (comm, ip, port, action)
    arg.beginStructure();
    arg << e.comm << e.ip << e.port << e.action;
    arg.endStructure();
    return arg;
}

const QDBusArgument& operator>>(const QDBusArgument &arg, RuleEntry &e) {
    arg.beginStructure();
    arg >> e.comm >> e.ip >> e.port >> e.action;
    arg.endStructure();
    return arg;
}

DbusClient::DbusClient(QObject *parent) : QObject(parent) {
    // Register custom marshallers ONCE per process. qDBusRegisterMetaType
    // is idempotent but cheap-redundant; we still only get one DbusClient
    // per process so this is fine.
    qDBusRegisterMetaType<RuleEntry>();
    qDBusRegisterMetaType<QList<RuleEntry>>();

    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &DbusClient::refresh);
    subscribeSignals();
}

void DbusClient::subscribeSignals() {
    auto bus = QDBusConnection::systemBus();
    if (!bus.isConnected()) {
        qWarning() << "DbusClient: system bus not connected; signal subscription skipped";
        return;
    }
    // Old-style SLOT() macro is required for QDBusConnection::connect():
    // Qt's D-Bus demarshaller introspects the slot signature to map
    // the wire types `usqs` (uint, str, str, ushort, str). The
    // functor (new-style) form does not work for D-Bus signals.
    bool ok = bus.connect(
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("/org/amwall/Daemon1"),
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("ConnectAttempt"),
        this,
        SLOT(onDbusConnectAttempt(uint, QString, QString, ushort, QString)));
    if (!ok) {
        qWarning() << "DbusClient: failed to subscribe to ConnectAttempt:"
                   << bus.lastError().message();
    }
}

void DbusClient::onDbusConnectAttempt(uint pid, const QString &comm,
                                      const QString &ip, ushort port,
                                      const QString &action) {
    emit connectAttempt(pid, comm, ip, port, action);
}

void DbusClient::startAutoRefresh(int intervalMs) {
    m_timer->start(intervalMs);
}

void DbusClient::stopAutoRefresh() {
    m_timer->stop();
}

void DbusClient::refresh() {
    QString err;
    bool ok = pingDaemon(&err);
    if (ok) {
        QList<RuleEntry> rules;
        ok = listRules(&rules, &err);
        if (ok) {
            m_reachable = true;
            m_rules = std::move(rules);
            m_lastError.clear();
        } else {
            m_reachable = false;
            m_rules.clear();
            m_lastError = err;
        }
    } else {
        m_reachable = false;
        m_rules.clear();
        m_lastError = err;
    }

    m_lastRefresh = QDateTime::currentDateTime();

    // Always emit — status-bar refresh timestamp updates each tick
    // even when the daemon state is unchanged.
    emit stateChanged();
}

bool DbusClient::hasAnyRuleFor(const QString &comm) const {
    for (const RuleEntry &r : m_rules) {
        if (r.comm == comm) return true;
    }
    return false;
}

void DbusClient::allow(const QString &comm, const QString &ip, ushort port) {
    callModify("Allow", comm, ip, port);
}

void DbusClient::deny(const QString &comm, const QString &ip, ushort port) {
    callModify("Deny", comm, ip, port);
}

void DbusClient::del(const QString &comm, const QString &ip, ushort port) {
    callModify("Del", comm, ip, port);
}

void DbusClient::callModify(const char *method, const QString &comm,
                            const QString &ip, ushort port) {
    auto bus = QDBusConnection::systemBus();
    auto msg = QDBusMessage::createMethodCall(
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("/org/amwall/Daemon1"),
        QStringLiteral("org.amwall.Daemon1"),
        QString::fromLatin1(method));
    msg << comm << ip << QVariant::fromValue<ushort>(port);

    // asyncCall: polkit may pop a prompt or take a bus round-trip;
    // don't freeze the GUI while waiting. The timeout is generous
    // because polkit interaction can be slow.
    auto pending = bus.asyncCall(msg, /*timeoutMs=*/15000);
    auto *watcher = new QDBusPendingCallWatcher(pending, this);
    connect(watcher, &QDBusPendingCallWatcher::finished,
            this, [this, method, comm, ip, port](QDBusPendingCallWatcher *w) {
        QDBusPendingReply<> reply = *w;
        if (reply.isError()) {
            qWarning() << "DbusClient:" << method
                       << "(" << comm << "," << ip << "," << port << ") failed:"
                       << reply.error().message();
        } else {
            // Speed up the cache update so PromptCoordinator's hasRule
            // check sees the new entry on the next signal. The 5-second
            // poll would otherwise lag behind a fast user.
            this->refresh();
        }
        w->deleteLater();
    });
}

bool DbusClient::pingDaemon(QString *errOut) {
    auto bus = QDBusConnection::systemBus();
    if (!bus.isConnected()) {
        if (errOut) *errOut = bus.lastError().message();
        return false;
    }
    auto msg = QDBusMessage::createMethodCall(
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("/org/amwall/Daemon1"),
        QStringLiteral("org.freedesktop.DBus.Peer"),
        QStringLiteral("Ping"));
    auto reply = bus.call(msg, QDBus::Block, /*timeoutMs=*/2000);
    if (reply.type() == QDBusMessage::ErrorMessage) {
        if (errOut) *errOut = reply.errorMessage();
        return false;
    }
    return true;
}

bool DbusClient::listRules(QList<RuleEntry> *out, QString *errOut) {
    // org.amwall.Daemon1.List() returns a(ssqs) — array of
    // (comm, ip, port, action) tuples. Demarshalled via the
    // RuleEntry operator>> registered with qDBusRegisterMetaType
    // in the ctor. The previous manual beginArray/beginStructure
    // pattern on a value-copy of QDBusArgument warned
    // "QDBusArgument: write from a read-only object" on every
    // refresh tick and corrupted libdbus state badly enough to
    // crash with "type struct 114 not a basic type" after enough
    // accumulated bad reads.
    auto bus = QDBusConnection::systemBus();
    auto msg = QDBusMessage::createMethodCall(
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("/org/amwall/Daemon1"),
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("List"));
    auto reply = bus.call(msg, QDBus::Block, /*timeoutMs=*/2000);
    if (reply.type() != QDBusMessage::ReplyMessage) {
        if (errOut) *errOut = reply.errorMessage();
        return false;
    }
    if (reply.arguments().isEmpty()) {
        return true;  // empty list, leave *out as-is
    }
    const QVariant first = reply.arguments().first();

    // Path 1: the bus marshaller already converted the wire to our
    // registered QList<RuleEntry> type — no QDBusArgument needed.
    if (first.canConvert<QList<RuleEntry>>()) {
        *out = first.value<QList<RuleEntry>>();
        return true;
    }

    // Path 2: the value is still a raw QDBusArgument (typical for
    // complex types). Stream into a QList — operator>> on QList
    // uses our registered RuleEntry operator>>.
    if (!first.canConvert<QDBusArgument>()) {
        if (errOut) *errOut = QStringLiteral("List() returned unexpected type");
        return false;
    }
    const QDBusArgument arg = first.value<QDBusArgument>();
    QList<RuleEntry> list;
    arg >> list;
    *out = list;
    return true;
}
EOF

write_file linux/amwall-gui-qt/src/dashboard.h <<'EOF'
// Dashboard — central widget shown in MainWindow until 6.4 replaces
// it with the tabbed app/rules/connections view. Renders DbusClient
// state + PromptCoordinator state as a polished status panel:
//   • header with theme icon + product name + version
//   • daemon group: state, rule count, endpoint, refresh button
//   • activity group: pending prompts (live count from coordinator)
// Updates itself on DbusClient::stateChanged + pendingCountChanged.

#pragma once

#include <QWidget>

class QLabel;
class DbusClient;
class PromptCoordinator;

class Dashboard : public QWidget {
    Q_OBJECT

public:
    Dashboard(DbusClient *dbus, PromptCoordinator *prompts,
              QWidget *parent = nullptr);

private slots:
    void onDbusStateChanged();
    void onPendingChanged(int n);

private:
    DbusClient        *m_dbus;
    PromptCoordinator *m_prompts;
    QLabel            *m_stateLabel = nullptr;
    QLabel            *m_countLabel = nullptr;
    QLabel            *m_lastLabel  = nullptr;
    QLabel            *m_pendingLabel = nullptr;
};
EOF

write_file linux/amwall-gui-qt/src/dashboard.cpp <<'EOF'
#include "dashboard.h"

#include "dbusclient.h"
#include "promptcoordinator.h"

#include <QApplication>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QPixmap>
#include <QPushButton>
#include <QSizePolicy>
#include <QStyle>
#include <QVBoxLayout>

#ifndef AMWALL_VERSION
#define AMWALL_VERSION "unknown"
#endif

Dashboard::Dashboard(DbusClient *dbus, PromptCoordinator *prompts,
                     QWidget *parent)
    : QWidget(parent), m_dbus(dbus), m_prompts(prompts) {

    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(24, 24, 24, 24);
    outer->setSpacing(16);

    // ─── Header ───────────────────────────────────────────────────
    auto *header = new QHBoxLayout;
    header->setSpacing(16);

    auto *iconLabel = new QLabel(this);
    QIcon ico = QIcon::fromTheme(
        "network-firewall",
        style()->standardIcon(QStyle::SP_DriveNetIcon));
    iconLabel->setPixmap(ico.pixmap(48, 48));
    header->addWidget(iconLabel, 0, Qt::AlignTop);

    auto *titleBox = new QVBoxLayout;
    titleBox->setSpacing(2);
    auto *title = new QLabel(QStringLiteral("amwall"), this);
    QFont tf = title->font();
    tf.setPointSize(tf.pointSize() + 6);
    tf.setBold(true);
    title->setFont(tf);
    titleBox->addWidget(title);

    auto *subtitle = new QLabel(
        tr("Per-application firewall — version %1")
            .arg(QString::fromLatin1(AMWALL_VERSION)),
        this);
    // Plain palette text (WCAG-compliant contrast); italic instead of
    // a faded gray for visual hierarchy. palette(mid) fails the AA
    // contrast ratio against window backgrounds on most themes.
    subtitle->setStyleSheet("font-style: italic;");
    titleBox->addWidget(subtitle);
    header->addLayout(titleBox, 1);

    outer->addLayout(header);

    // ─── Daemon group ─────────────────────────────────────────────
    auto *daemonGroup = new QGroupBox(tr("Daemon"), this);
    auto *dlayout = new QFormLayout(daemonGroup);
    dlayout->setLabelAlignment(Qt::AlignRight);
    dlayout->setHorizontalSpacing(16);
    dlayout->setVerticalSpacing(8);

    m_stateLabel = new QLabel(tr("(probing...)"), daemonGroup);
    m_stateLabel->setTextFormat(Qt::RichText);
    dlayout->addRow(tr("State:"), m_stateLabel);

    m_countLabel = new QLabel(QStringLiteral("—"), daemonGroup);
    dlayout->addRow(tr("Rules loaded:"), m_countLabel);

    auto *endpoint = new QLabel(
        QStringLiteral("<code>org.amwall.Daemon1</code> (system bus)"),
        daemonGroup);
    endpoint->setTextFormat(Qt::RichText);
    dlayout->addRow(tr("Endpoint:"), endpoint);

    m_lastLabel = new QLabel(tr("never"), daemonGroup);
    dlayout->addRow(tr("Last refresh:"), m_lastLabel);

    auto *refreshBtn = new QPushButton(
        style()->standardIcon(QStyle::SP_BrowserReload),
        tr("Refresh now"),
        daemonGroup);
    refreshBtn->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
    connect(refreshBtn, &QPushButton::clicked, m_dbus, &DbusClient::refresh);
    dlayout->addRow(QString(), refreshBtn);

    outer->addWidget(daemonGroup);

    // ─── Activity group ───────────────────────────────────────────
    auto *activityGroup = new QGroupBox(tr("Activity"), this);
    auto *alayout = new QFormLayout(activityGroup);
    alayout->setLabelAlignment(Qt::AlignRight);
    alayout->setHorizontalSpacing(16);
    alayout->setVerticalSpacing(8);

    m_pendingLabel = new QLabel(QStringLiteral("0"), activityGroup);
    m_pendingLabel->setTextFormat(Qt::RichText);
    alayout->addRow(tr("Pending prompts:"), m_pendingLabel);

    outer->addWidget(activityGroup);
    outer->addStretch(1);

    connect(m_dbus, &DbusClient::stateChanged,
            this, &Dashboard::onDbusStateChanged);
    connect(m_prompts, &PromptCoordinator::pendingCountChanged,
            this, &Dashboard::onPendingChanged);
    onDbusStateChanged();
    onPendingChanged(m_prompts->pendingCount());
}

void Dashboard::onPendingChanged(int n) {
    if (n == 0) {
        m_pendingLabel->setText(tr("<i>0 (idle)</i>"));
    } else {
        m_pendingLabel->setText(
            tr("<span style='color:#ef6c00; font-weight:bold;'>"
               "%n waiting</span>", "", n));
    }
}

void Dashboard::onDbusStateChanged() {
    if (m_dbus->isReachable()) {
        m_stateLabel->setText(
            tr("<span style='color:#2e7d32; font-weight:bold;'>● Connected</span>"));
        m_countLabel->setText(QString::number(m_dbus->ruleCount()));
    } else {
        QString msg = tr("<span style='color:#c62828; font-weight:bold;'>○ Not reachable</span>");
        QString err = m_dbus->lastError();
        if (!err.isEmpty()) {
            // Italic + small font for hierarchy without the bad
            // contrast of palette(mid). Full text color = WCAG AA.
            msg += QStringLiteral("<br><i style='font-size: small;'>%1</i>")
                       .arg(err.toHtmlEscaped());
        }
        msg += QStringLiteral("<br><i style='font-size: small;'>%1</i>")
                   .arg(tr("start with: <code>sudo systemctl start amwall-daemon</code>"));
        m_stateLabel->setText(msg);
        m_countLabel->setText(QStringLiteral("—"));
    }

    QDateTime ts = m_dbus->lastRefresh();
    m_lastLabel->setText(
        ts.isValid() ? ts.toString("yyyy-MM-dd HH:mm:ss") : tr("never"));
}
EOF

write_file linux/amwall-gui-qt/src/connectprompt.h <<'EOF'
// ConnectPromptDialog — modeless top-level dialog shown when an
// unknown process tries to connect (default-deny in BPF). User
// picks Allow or Block — both persist a WHOLE-APP wildcard rule
// (comm, "any", 0) so subsequent connects from the same comm are
// silently allowed/denied. Closing the window via the title-bar X
// is treated as Block (matches simplewall/Win32 amwall: anything
// not explicitly allowed is denied).
//
// Top-level (no parent), Qt::Window, WindowStaysOnTopHint so it
// doesn't get buried under MainWindow or other apps. Centred on
// the primary screen by Qt default.
//
// PromptCoordinator owns the dialog lifecycle.

#pragma once

#include <QDialog>
#include <QString>

class QLabel;

class ConnectPromptDialog : public QDialog {
    Q_OBJECT

public:
    enum Decision { Allow, Block };

    ConnectPromptDialog(uint pid,
                        const QString &comm,
                        const QString &ip,
                        ushort port,
                        QWidget *parent = nullptr);

signals:
    void decided(Decision d);

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    bool m_emitted = false;
    void emitOnce(Decision d);
};
EOF

write_file linux/amwall-gui-qt/src/connectprompt.cpp <<'EOF'
#include "connectprompt.h"

#include <QApplication>
#include <QCloseEvent>
#include <QFont>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QPushButton>
#include <QStyle>
#include <QVBoxLayout>

ConnectPromptDialog::ConnectPromptDialog(uint pid,
                                         const QString &comm,
                                         const QString &ip,
                                         ushort port,
                                         QWidget *parent)
    : QDialog(parent,
              Qt::Window
              | Qt::WindowTitleHint
              | Qt::WindowCloseButtonHint
              | Qt::WindowStaysOnTopHint) {
    setWindowTitle(tr("Connection request — amwall"));
    setModal(false);
    setMinimumWidth(420);

    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(20, 20, 20, 20);
    outer->setSpacing(14);

    // ─── Header row: icon + headline ──────────────────────────────
    auto *header = new QHBoxLayout;
    header->setSpacing(14);

    auto *iconLabel = new QLabel(this);
    QIcon ico = style()->standardIcon(QStyle::SP_MessageBoxQuestion);
    iconLabel->setPixmap(ico.pixmap(40, 40));
    header->addWidget(iconLabel, 0, Qt::AlignTop);

    // "Process" prefix disambiguates from same-name protocols/services
    // (e.g. comm="http" reads as the HTTP protocol without the noun).
    // The kernel's TASK_COMM_NAME is the basename of the executable
    // truncated to 15 chars — see /proc/<pid>/comm.
    auto *headline = new QLabel(
        tr("Process <b>%1</b> wants to connect.").arg(comm.toHtmlEscaped()),
        this);
    headline->setTextFormat(Qt::RichText);
    headline->setWordWrap(true);
    QFont hf = headline->font();
    hf.setPointSize(hf.pointSize() + 1);
    headline->setFont(hf);
    header->addWidget(headline, 1);

    outer->addLayout(header);

    // ─── Detail rows ──────────────────────────────────────────────
    auto *details = new QFormLayout;
    details->setLabelAlignment(Qt::AlignRight);
    details->setHorizontalSpacing(12);
    details->setVerticalSpacing(4);

    details->addRow(tr("Process:"),
        new QLabel(QStringLiteral("<code>%1</code> (pid %2)")
                       .arg(comm.toHtmlEscaped())
                       .arg(pid), this));
    details->addRow(tr("First destination:"),
        new QLabel(QStringLiteral("<code>%1:%2</code>")
                       .arg(ip.toHtmlEscaped())
                       .arg(port), this));
    details->addRow(tr("Default action:"),
        new QLabel(tr("<span style='color:#c62828;'>blocked</span> (no rule)"), this));

    outer->addLayout(details);

    // Italic + small for visual hierarchy; full text color for WCAG
    // contrast. Wording reflects whole-app semantics: Allow / Block
    // persist a wildcard rule for the comm, not just this one
    // destination. Closing the window = Block (default-deny stance).
    auto *hint = new QLabel(
        tr("<i style='font-size: small;'>"
           "Allow lets <b>%1</b> connect to anywhere. Block silently "
           "denies all of its connections. Closing this window also "
           "blocks. Use the User Rules tab later to fine-tune by "
           "destination or port.</i>")
            .arg(comm.toHtmlEscaped()),
        this);
    hint->setTextFormat(Qt::RichText);
    hint->setWordWrap(true);
    outer->addWidget(hint);

    // ─── Buttons ──────────────────────────────────────────────────
    auto *buttons = new QHBoxLayout;
    buttons->addStretch(1);

    auto *blockBtn = new QPushButton(
        style()->standardIcon(QStyle::SP_DialogNoButton),
        tr("&Block"), this);
    auto *allowBtn = new QPushButton(
        style()->standardIcon(QStyle::SP_DialogApplyButton),
        tr("&Allow"), this);
    allowBtn->setDefault(true);

    buttons->addWidget(blockBtn);
    buttons->addWidget(allowBtn);
    outer->addLayout(buttons);

    connect(allowBtn, &QPushButton::clicked, this, [this]{ emitOnce(Allow); });
    connect(blockBtn, &QPushButton::clicked, this, [this]{ emitOnce(Block); });
}

void ConnectPromptDialog::emitOnce(Decision d) {
    if (m_emitted) return;
    m_emitted = true;
    emit decided(d);
    close();
}

void ConnectPromptDialog::closeEvent(QCloseEvent *event) {
    // Window close (X button) counts as Block — anything not
    // explicitly allowed is denied (matches simplewall/Win32 amwall:
    // there's no "ignore this and re-prompt" path). Guard with
    // m_emitted so we don't double-fire when emitOnce already
    // called close().
    if (!m_emitted) {
        m_emitted = true;
        emit decided(Block);
    }
    event->accept();
}
EOF

write_file linux/amwall-gui-qt/src/promptcoordinator.h <<'EOF'
// PromptCoordinator — receives ConnectAttempt signals from
// DbusClient, filters them down to "this is a process the user
// hasn't decided about yet", queues, and shows one
// ConnectPromptDialog at a time.
//
// Per-comm dedup (matches simplewall/Win32 amwall): one prompt per
// process, not per (process, ip, port). On Allow/Block we persist
// a WHOLE-APP wildcard rule (comm, "any", 0). Future connects from
// the same comm hit the BPF wildcard lookup and never raise a signal
// here.
//
// Filters applied:
//   • action == "deny" only             (allows are silent)
//   • ip is real IPv4 (not "(family=N)" — AF_UNIX etc. don't go
//     through the user's network policy)
//   • !DbusClient::hasAnyRuleFor(comm)  (already in rules.toml)
//   • comm not already pending          (per-comm dedup)
//   • comm not recently decided         (60-sec cooldown — by then
//                                        the daemon has reloaded and
//                                        hasAnyRuleFor will catch it)
//
// Emits pendingCountChanged so the Dashboard widget can show the
// "Pending prompts: N" row. When the queue drains, count goes to 0.

#pragma once

#include <QDateTime>
#include <QHash>
#include <QObject>
#include <QQueue>
#include <QSet>
#include <QString>

#include "connectprompt.h"

class DbusClient;
class QWidget;

struct PromptRequest {
    uint    pid;
    QString comm;
    QString ip;     // first observed destination (informational)
    ushort  port;   // first observed port (informational)
};

class PromptCoordinator : public QObject {
    Q_OBJECT

public:
    PromptCoordinator(DbusClient *dbus, QWidget *windowAnchor,
                      QObject *parent = nullptr);

    int pendingCount() const { return m_queue.size() + (m_current ? 1 : 0); }

signals:
    void pendingCountChanged(int n);

private slots:
    void onConnectAttempt(uint pid, const QString &comm,
                          const QString &ip, ushort port,
                          const QString &action);
    void onDecision(ConnectPromptDialog::Decision d);

private:
    void enqueue(const PromptRequest &req);
    void processNext();
    void notifyCount();
    void pruneRecent();  // expire entries older than 60 sec

    DbusClient *m_dbus;
    QWidget    *m_anchor;  // for raising MainWindow when prompt fires

    QQueue<PromptRequest>     m_queue;
    QSet<QString>             m_pending;   // comms currently in queue or showing
    QHash<QString, QDateTime> m_decided;   // comm → decision time (60-sec cooldown)
    PromptRequest             m_currentReq{};
    ConnectPromptDialog      *m_current = nullptr;
};
EOF

write_file linux/amwall-gui-qt/src/promptcoordinator.cpp <<'EOF'
#include "promptcoordinator.h"

#include "dbusclient.h"

#include <QDateTime>
#include <QDebug>
#include <QWidget>

static constexpr int kCooldownSeconds = 60;

PromptCoordinator::PromptCoordinator(DbusClient *dbus, QWidget *windowAnchor,
                                     QObject *parent)
    : QObject(parent), m_dbus(dbus), m_anchor(windowAnchor) {
    connect(m_dbus, &DbusClient::connectAttempt,
            this, &PromptCoordinator::onConnectAttempt);
}

void PromptCoordinator::onConnectAttempt(uint pid, const QString &comm,
                                         const QString &ip, ushort port,
                                         const QString &action) {
    // Filter 1: only default-denies need user attention.
    if (action != QStringLiteral("deny")) return;

    // Filter 2: AF_UNIX / AF_NETLINK / etc. don't have routable
    // destinations — the daemon stamps them as "(family=N)". Don't
    // prompt the user for things they can't meaningfully allow.
    if (ip.startsWith(QStringLiteral("(family="))) return;

    // Filter 3: any rule for this comm exists → user already decided
    // about this app (whole-app semantics; matches Win32 amwall).
    if (m_dbus->hasAnyRuleFor(comm)) return;

    // Filter 4: dedup against currently-pending and recently-decided
    // BY COMM ONLY — one prompt per process, regardless of how many
    // different (ip, port) pairs the process tries.
    pruneRecent();
    if (m_pending.contains(comm)) return;
    if (m_decided.contains(comm)) return;

    enqueue({pid, comm, ip, port});
}

void PromptCoordinator::enqueue(const PromptRequest &req) {
    m_pending.insert(req.comm);
    m_queue.enqueue(req);
    notifyCount();
    if (!m_current) processNext();
}

void PromptCoordinator::processNext() {
    if (m_current) return;
    if (m_queue.isEmpty()) {
        notifyCount();
        return;
    }
    m_currentReq = m_queue.dequeue();
    m_current = new ConnectPromptDialog(
        m_currentReq.pid, m_currentReq.comm, m_currentReq.ip, m_currentReq.port,
        nullptr);
    connect(m_current, &ConnectPromptDialog::decided,
            this, &PromptCoordinator::onDecision);

    // Pull the user's attention to amwall: if MainWindow is hidden,
    // we still want them to see the prompt. The dialog itself is
    // top-level + StaysOnTop so it shows above other apps.
    m_current->show();
    m_current->raise();
    m_current->activateWindow();
    notifyCount();
}

void PromptCoordinator::onDecision(ConnectPromptDialog::Decision d) {
    const QString comm = m_currentReq.comm;
    m_pending.remove(comm);

    // Persist a WHOLE-APP wildcard rule, not a per-(comm, ip, port)
    // rule. ip="any" (BPF dest_ip4=0) + port=0 hits step 4 of the
    // BPF wildcard lookup, covering every future IPv4 connect from
    // this comm. Dismiss is no longer a thing — closing the dialog
    // counts as Block (default-deny stance, matches Win32 amwall).
    static const QString kAnyIp = QStringLiteral("any");
    static constexpr ushort kAnyPort = 0;

    switch (d) {
    case ConnectPromptDialog::Allow:
        m_dbus->allow(comm, kAnyIp, kAnyPort);
        break;
    case ConnectPromptDialog::Block:
        m_dbus->deny(comm, kAnyIp, kAnyPort);
        break;
    }
    m_decided.insert(comm, QDateTime::currentDateTime());

    if (m_current) {
        m_current->deleteLater();
        m_current = nullptr;
    }
    processNext();
}

void PromptCoordinator::notifyCount() {
    emit pendingCountChanged(pendingCount());
}

void PromptCoordinator::pruneRecent() {
    QDateTime cutoff = QDateTime::currentDateTime().addSecs(-kCooldownSeconds);
    auto it = m_decided.begin();
    while (it != m_decided.end()) {
        if (it.value() < cutoff) it = m_decided.erase(it);
        else                     ++it;
    }
}
EOF

write_file linux/amwall-gui-qt/src/ruleeditor.h <<'EOF'
// RuleEditorDialog — modal dialog for adding or editing a rule.
//
// Two modes selected by the constructor:
//   • Add mode (existing == nullptr): all fields editable. Use to
//     create a brand-new rule. (comm, ip, port) is the daemon's
//     unique key — submitting an existing key upserts.
//   • Edit mode (existing != nullptr): only the action is editable.
//     Process / IP / Port are shown read-only. To change those, the
//     user deletes the rule and adds a new one — this avoids the
//     orphan-state risk of "delete-then-add" (no daemon Update RPC).

#pragma once

#include <QDialog>

#include "dbusclient.h"   // for RuleEntry

class QComboBox;
class QLineEdit;
class QSpinBox;
class QDialogButtonBox;

class RuleEditorDialog : public QDialog {
    Q_OBJECT

public:
    explicit RuleEditorDialog(const RuleEntry *existing = nullptr,
                              QWidget *parent = nullptr);

    QString comm()   const;
    QString ip()     const;
    ushort  port()   const;
    QString action() const;   // "allow" | "deny"

private slots:
    void validateAndAccept();

private:
    bool m_isEdit;
    QLineEdit        *m_comm = nullptr;
    QComboBox        *m_action = nullptr;
    QLineEdit        *m_ip = nullptr;
    QSpinBox         *m_port = nullptr;
    QDialogButtonBox *m_buttons = nullptr;
};
EOF

write_file linux/amwall-gui-qt/src/ruleeditor.cpp <<'EOF'
#include "ruleeditor.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHostAddress>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QSpinBox>
#include <QVBoxLayout>

RuleEditorDialog::RuleEditorDialog(const RuleEntry *existing, QWidget *parent)
    : QDialog(parent), m_isEdit(existing != nullptr) {
    setWindowTitle(m_isEdit ? tr("Edit rule") : tr("Add rule"));
    setModal(true);
    setMinimumWidth(380);

    auto *outer = new QVBoxLayout(this);
    auto *form  = new QFormLayout;
    form->setLabelAlignment(Qt::AlignRight);

    // Process (comm) — kernel TASK_COMM_NAME, ASCII, max 15 chars.
    m_comm = new QLineEdit(this);
    m_comm->setMaxLength(15);
    m_comm->setPlaceholderText(tr("e.g. firefox  (max 15 chars, kernel comm)"));
    // Allow letters, digits, underscore, hyphen, dot, colon, and
    // space (Firefox's "DNS Resolver #N" has spaces and #).
    m_comm->setValidator(new QRegularExpressionValidator(
        QRegularExpression("[\\w .:#@/+-]+"), this));
    form->addRow(tr("Process (comm):"), m_comm);

    // Action — Allow / Deny.
    m_action = new QComboBox(this);
    m_action->addItem(tr("Allow"), "allow");
    m_action->addItem(tr("Deny"),  "deny");
    form->addRow(tr("Action:"), m_action);

    // IP — "any" or IPv4 dotted-quad.
    m_ip = new QLineEdit(this);
    m_ip->setPlaceholderText(tr("any  or  192.168.1.1"));
    form->addRow(tr("Destination IP:"), m_ip);

    // Port — 0 = any.
    m_port = new QSpinBox(this);
    m_port->setRange(0, 65535);
    m_port->setSpecialValueText(tr("0  (any port)"));
    form->addRow(tr("Destination port:"), m_port);

    outer->addLayout(form);

    // In Edit mode pre-fill all fields and lock everything except
    // the action combobox. Add mode starts blank with sensible
    // defaults.
    if (existing) {
        m_comm->setText(existing->comm);
        m_ip->setText(existing->ip);
        m_port->setValue(existing->port);
        m_action->setCurrentIndex(existing->action == "deny" ? 1 : 0);
        m_comm->setReadOnly(true);
        m_ip->setReadOnly(true);
        m_port->setReadOnly(true);
        m_port->setButtonSymbols(QAbstractSpinBox::NoButtons);

        auto *note = new QLabel(
            tr("<i style='font-size: small;'>Process / IP / Port are read-only "
               "in Edit. To change those, delete this rule and add a new one.</i>"),
            this);
        note->setTextFormat(Qt::RichText);
        note->setWordWrap(true);
        outer->addWidget(note);
    } else {
        m_ip->setText(QStringLiteral("any"));
    }

    m_buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    outer->addWidget(m_buttons);
    connect(m_buttons, &QDialogButtonBox::accepted,
            this, &RuleEditorDialog::validateAndAccept);
    connect(m_buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

QString RuleEditorDialog::comm()   const { return m_comm->text(); }
QString RuleEditorDialog::ip()     const { return m_ip->text().trimmed(); }
ushort  RuleEditorDialog::port()   const { return static_cast<ushort>(m_port->value()); }
QString RuleEditorDialog::action() const { return m_action->currentData().toString(); }

void RuleEditorDialog::validateAndAccept() {
    if (m_isEdit) {
        // Only the action can change; everything else is locked.
        accept();
        return;
    }

    const QString c = comm().trimmed();
    if (c.isEmpty()) {
        QMessageBox::warning(this, tr("Invalid rule"),
            tr("Process name (comm) cannot be empty."));
        m_comm->setFocus();
        return;
    }

    const QString ipv = ip();
    if (ipv.isEmpty()) {
        QMessageBox::warning(this, tr("Invalid rule"),
            tr("Destination IP cannot be empty.\n\nUse 'any' to match all IPs."));
        m_ip->setFocus();
        return;
    }
    if (ipv.compare(QStringLiteral("any"), Qt::CaseInsensitive) != 0) {
        // Not "any" — must be a valid IPv4 dotted-quad string.
        QHostAddress addr(ipv);
        if (addr.isNull() || addr.protocol() != QAbstractSocket::IPv4Protocol) {
            QMessageBox::warning(this, tr("Invalid rule"),
                tr("Destination IP must be 'any' or a valid IPv4 address "
                   "(e.g. 192.168.1.1).\n\nIPv6 isn't enforced by the BPF "
                   "program yet."));
            m_ip->setFocus();
            return;
        }
    }

    accept();
}
EOF

write_file linux/amwall-gui-qt/src/userrulestab.h <<'EOF'
// UserRulesTab — central tab listing all rules from rules.toml.
//
// Source of truth: DbusClient::rules(). Auto-rebuilds the table
// whenever DbusClient emits stateChanged. Buttons:
//   • Add Rule    → opens RuleEditorDialog in Add mode → dbus.allow/deny
//   • Edit Rule   → opens RuleEditorDialog in Edit mode (action only)
//   • Delete Rule → confirms → dbus.del
//
// Double-click a row also opens Edit. Delete key on the table
// triggers Delete. Enter triggers Edit.

#pragma once

#include <QWidget>

#include "dbusclient.h"

class QLabel;
class QPushButton;
class QTableWidget;

class UserRulesTab : public QWidget {
    Q_OBJECT

public:
    explicit UserRulesTab(DbusClient *dbus, QWidget *parent = nullptr);

public slots:
    // Public so the menu's Edit > Add Rule can drive the same path
    // without duplicating dialog wiring in MainWindow.
    void onAddRule();

private slots:
    void onDbusStateChanged();
    void onSelectionChanged();
    void onEditRule();
    void onDeleteRule();
    void onTableActivated();   // double-click / Enter

private:
    void rebuildTable();
    bool   currentRule(RuleEntry *out) const;

    DbusClient   *m_dbus = nullptr;
    QTableWidget *m_table = nullptr;
    QPushButton  *m_addBtn = nullptr;
    QPushButton  *m_editBtn = nullptr;
    QPushButton  *m_deleteBtn = nullptr;
    QLabel       *m_countLabel = nullptr;
};
EOF

write_file linux/amwall-gui-qt/src/userrulestab.cpp <<'EOF'
#include "userrulestab.h"

#include "ruleeditor.h"

#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QStyle>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

UserRulesTab::UserRulesTab(DbusClient *dbus, QWidget *parent)
    : QWidget(parent), m_dbus(dbus) {

    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(8, 8, 8, 8);
    outer->setSpacing(6);

    // ─── Header (count) ──────────────────────────────────────────
    auto *header = new QHBoxLayout;
    auto *title = new QLabel(tr("<b>User rules</b>"), this);
    title->setTextFormat(Qt::RichText);
    header->addWidget(title);
    m_countLabel = new QLabel(QStringLiteral("(0)"), this);
    header->addWidget(m_countLabel);
    header->addStretch(1);
    outer->addLayout(header);

    // ─── Table ───────────────────────────────────────────────────
    m_table = new QTableWidget(0, 4, this);
    m_table->setHorizontalHeaderLabels({
        tr("Process (comm)"), tr("Action"), tr("Destination IP"), tr("Port")
    });
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSortingEnabled(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setStretchLastSection(false);
    m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    outer->addWidget(m_table, /*stretch=*/1);

    connect(m_table, &QTableWidget::itemSelectionChanged,
            this, &UserRulesTab::onSelectionChanged);
    connect(m_table, &QTableWidget::cellDoubleClicked,
            this, &UserRulesTab::onTableActivated);

    // ─── Buttons ─────────────────────────────────────────────────
    auto *buttons = new QHBoxLayout;
    buttons->addStretch(1);

    m_addBtn = new QPushButton(
        style()->standardIcon(QStyle::SP_FileDialogNewFolder),
        tr("&Add..."), this);
    m_editBtn = new QPushButton(
        style()->standardIcon(QStyle::SP_FileDialogDetailedView),
        tr("&Edit..."), this);
    m_deleteBtn = new QPushButton(
        style()->standardIcon(QStyle::SP_TrashIcon),
        tr("&Delete"), this);

    m_editBtn->setEnabled(false);
    m_deleteBtn->setEnabled(false);

    connect(m_addBtn,    &QPushButton::clicked, this, &UserRulesTab::onAddRule);
    connect(m_editBtn,   &QPushButton::clicked, this, &UserRulesTab::onEditRule);
    connect(m_deleteBtn, &QPushButton::clicked, this, &UserRulesTab::onDeleteRule);

    buttons->addWidget(m_addBtn);
    buttons->addWidget(m_editBtn);
    buttons->addWidget(m_deleteBtn);
    outer->addLayout(buttons);

    connect(m_dbus, &DbusClient::stateChanged,
            this, &UserRulesTab::onDbusStateChanged);
    rebuildTable();
}

void UserRulesTab::onDbusStateChanged() {
    rebuildTable();
}

void UserRulesTab::rebuildTable() {
    // QTableWidget loses selection on row-count changes; selection
    // preservation across rebuilds is a 6.5+ polish item if anyone
    // wants it. For now the user re-clicks if the rebuild interrupts.
    const auto &rules = m_dbus->rules();
    m_table->setSortingEnabled(false);
    m_table->setRowCount(rules.size());
    int row = 0;
    for (const RuleEntry &r : rules) {
        auto *commItem = new QTableWidgetItem(r.comm);
        auto *actionItem = new QTableWidgetItem(r.action.toUpper());
        auto *ipItem = new QTableWidgetItem(r.ip);
        auto *portItem = new QTableWidgetItem(
            r.port == 0 ? tr("any") : QString::number(r.port));

        // Color-code action: green for allow, red for deny.
        if (r.action == QStringLiteral("allow")) {
            actionItem->setForeground(QColor("#2e7d32"));
        } else if (r.action == QStringLiteral("deny")) {
            actionItem->setForeground(QColor("#c62828"));
        }

        m_table->setItem(row, 0, commItem);
        m_table->setItem(row, 1, actionItem);
        m_table->setItem(row, 2, ipItem);
        m_table->setItem(row, 3, portItem);
        ++row;
    }
    m_table->setSortingEnabled(true);
    m_countLabel->setText(QStringLiteral("(%1)").arg(rules.size()));

    // After rebuild, no row is selected; refresh button enabled state.
    onSelectionChanged();
}

void UserRulesTab::onSelectionChanged() {
    bool any = !m_table->selectedItems().isEmpty();
    m_editBtn->setEnabled(any);
    m_deleteBtn->setEnabled(any);
}

bool UserRulesTab::currentRule(RuleEntry *out) const {
    auto sel = m_table->selectedItems();
    if (sel.isEmpty()) return false;
    int row = sel.first()->row();
    out->comm   = m_table->item(row, 0)->text();
    out->action = m_table->item(row, 1)->text().toLower();
    out->ip     = m_table->item(row, 2)->text();
    QString portText = m_table->item(row, 3)->text();
    out->port   = (portText == tr("any")) ? 0 : portText.toUShort();
    return true;
}

void UserRulesTab::onAddRule() {
    RuleEditorDialog dlg(/*existing=*/nullptr, this);
    if (dlg.exec() != QDialog::Accepted) return;
    if (dlg.action() == QStringLiteral("allow")) {
        m_dbus->allow(dlg.comm(), dlg.ip(), dlg.port());
    } else {
        m_dbus->deny(dlg.comm(), dlg.ip(), dlg.port());
    }
}

void UserRulesTab::onEditRule() {
    RuleEntry r;
    if (!currentRule(&r)) return;
    RuleEditorDialog dlg(&r, this);
    if (dlg.exec() != QDialog::Accepted) return;
    // Edit-mode dialog only allows action to change. (comm, ip, port)
    // is the BPF map key; the daemon's Allow/Deny upserts on key match.
    if (dlg.action() == QStringLiteral("allow")) {
        m_dbus->allow(r.comm, r.ip, r.port);
    } else {
        m_dbus->deny(r.comm, r.ip, r.port);
    }
}

void UserRulesTab::onDeleteRule() {
    RuleEntry r;
    if (!currentRule(&r)) return;
    QString summary = QStringLiteral("%1  %2  %3:%4")
                          .arg(r.action.toUpper(), r.comm, r.ip,
                               r.port == 0 ? tr("any") : QString::number(r.port));
    int rc = QMessageBox::question(
        this, tr("Delete rule"),
        tr("Delete this rule?\n\n  %1\n\nThis takes effect immediately.").arg(summary),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (rc != QMessageBox::Yes) return;
    m_dbus->del(r.comm, r.ip, r.port);
}

void UserRulesTab::onTableActivated() {
    onEditRule();
}
EOF


# ─── amwall-ebpf — Phase 2 enforcement (unchanged in Phase 3) ───────

H "amwall-ebpf (RULES HashMap + default-deny LSM)"

write_file linux/amwall-ebpf/Cargo.toml <<'EOF'
# Real BPF program. Builds for bpfel-unknown-none on nightly with
# rust-src + build-std=core. bpf-linker handles LLVM-IR → BPF bytecode.
[package]
name = "amwall-ebpf"
version = "0.1.0"
edition = "2021"
license = "MIT"
publish = false

[dependencies]
aya-ebpf = "0.1"

[[bin]]
name = "amwall-ebpf"
path = "src/main.rs"

[profile.dev]
opt-level = 3
debug = false
debug-assertions = false
overflow-checks = false
lto = true
panic = "abort"
incremental = false
codegen-units = 1
rpath = false

[profile.release]
lto = true
panic = "abort"
codegen-units = 1

[workspace]
EOF

write_file linux/amwall-ebpf/rust-toolchain.toml <<'EOF'
[toolchain]
channel = "nightly"
components = ["rust-src"]
EOF

write_file linux/amwall-ebpf/.cargo/config.toml <<'EOF'
[build]
target = "bpfel-unknown-none"

[unstable]
build-std = ["core"]
EOF

write_file linux/amwall-ebpf/src/main.rs <<'EOF'
//! amwall-ebpf — Phase 2 BPF LSM enforcement (unchanged in Phase 3 —
//! the daemon-side D-Bus work doesn't touch the kernel program).

#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_void,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{lsm, map},
    maps::{HashMap, RingBuf},
    programs::LsmContext,
};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

const ACT_DENY: u8 = 0;
const ACT_ALLOW: u8 = 1;

const VERDICT_ALLOW: i32 = 0;
const VERDICT_DENY: i32 = -1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub pid: u32,
    pub comm: [u8; 16],
    pub family: u16,
    pub dest_port: u16,
    pub dest_ip4: u32,
    pub dest_ip6: [u8; 16],
    pub action: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleKey {
    pub comm: [u8; 16],
    pub dest_ip4: u32,
    pub dest_port: u16,
    pub _pad: u16,
}

// Phase 6.4.1: parallel map for IPv6 lookups. dest_ip6 is the raw
// 16-byte address (network byte order, same as in_addr6). Wildcard
// slot is dest_ip6=[0; 16] + dest_port=0 — populated by the daemon
// whenever the user sets a rule with ip="any" so that wildcard
// allows/denies cover both IPv4 and IPv6 destinations.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleKeyV6 {
    pub comm: [u8; 16],
    pub dest_ip6: [u8; 16],
    pub dest_port: u16,
    pub _pad: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleValue {
    pub action: u8,
    pub _pad: [u8; 7],
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static RULES: HashMap<RuleKey, RuleValue> = HashMap::with_max_entries(1024, 0);

#[map]
static RULES_V6: HashMap<RuleKeyV6, RuleValue> = HashMap::with_max_entries(1024, 0);

#[repr(C)]
struct SockAddrFamily { family: u16 }

#[repr(C)]
struct SockAddrIn { family: u16, port: u16, addr: u32 }

#[repr(C)]
struct SockAddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

#[lsm(hook = "socket_connect")]
pub fn amwall_socket_connect(ctx: LsmContext) -> i32 {
    match decide(&ctx) {
        ACT_ALLOW => VERDICT_ALLOW,
        _         => VERDICT_DENY,
    }
}

fn decide(ctx: &LsmContext) -> u8 {
    let addr_ptr: *const c_void = unsafe { ctx.arg(1) };

    let family = match unsafe {
        bpf_probe_read_kernel::<SockAddrFamily>(addr_ptr as *const SockAddrFamily)
    } {
        Ok(f) => f.family,
        Err(_) => return ACT_ALLOW,
    };

    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let mut entry = match EVENTS.reserve::<ConnectEvent>(0) {
        Some(e) => e,
        None => return ACT_ALLOW,
    };

    let event = entry.as_mut_ptr();
    unsafe {
        (*event).pid = pid;
        (*event).comm = comm;
        (*event).family = family;
        (*event).dest_port = 0;
        (*event).dest_ip4 = 0;
        (*event).dest_ip6 = [0; 16];
        (*event).action = ACT_ALLOW;
        (*event)._pad = [0; 3];
    }

    let action = match family {
        AF_INET => {
            match unsafe {
                bpf_probe_read_kernel::<SockAddrIn>(addr_ptr as *const SockAddrIn)
            } {
                Ok(a) => {
                    let port_host = u16::from_be(a.port);
                    unsafe {
                        (*event).dest_port = port_host;
                        (*event).dest_ip4 = a.addr;
                    }
                    lookup(comm, a.addr, port_host)
                }
                Err(_) => ACT_ALLOW,
            }
        }
        AF_INET6 => {
            // Phase 6.4.1: IPv6 is now subject to the same default-deny
            // policy as IPv4. lookup_v6 does the parallel 4-way wildcard
            // search against RULES_V6; the daemon mirrors "any" rules
            // into both maps so a single user click covers v4 + v6.
            match unsafe {
                bpf_probe_read_kernel::<SockAddrIn6>(addr_ptr as *const SockAddrIn6)
            } {
                Ok(a) => {
                    let port_host = u16::from_be(a.port);
                    unsafe {
                        (*event).dest_port = port_host;
                        (*event).dest_ip6 = a.addr;
                    }
                    lookup_v6(comm, a.addr, port_host)
                }
                Err(_) => ACT_ALLOW,
            }
        }
        _ => ACT_ALLOW,
    };

    unsafe { (*event).action = action; }
    entry.submit(0);
    action
}

fn lookup(comm: [u8; 16], ip: u32, port: u16) -> u8 {
    let k1 = RuleKey { comm, dest_ip4: ip, dest_port: port, _pad: 0 };
    if let Some(v) = unsafe { RULES.get(&k1) } { return v.action; }

    let k2 = RuleKey { comm, dest_ip4: ip, dest_port: 0, _pad: 0 };
    if let Some(v) = unsafe { RULES.get(&k2) } { return v.action; }

    let k3 = RuleKey { comm, dest_ip4: 0, dest_port: port, _pad: 0 };
    if let Some(v) = unsafe { RULES.get(&k3) } { return v.action; }

    let k4 = RuleKey { comm, dest_ip4: 0, dest_port: 0, _pad: 0 };
    if let Some(v) = unsafe { RULES.get(&k4) } { return v.action; }

    ACT_DENY
}

fn lookup_v6(comm: [u8; 16], ip6: [u8; 16], port: u16) -> u8 {
    // 4-way wildcard, mirroring `lookup` for IPv4.
    let k1 = RuleKeyV6 { comm, dest_ip6: ip6, dest_port: port, _pad: [0; 6] };
    if let Some(v) = unsafe { RULES_V6.get(&k1) } { return v.action; }

    let k2 = RuleKeyV6 { comm, dest_ip6: ip6, dest_port: 0, _pad: [0; 6] };
    if let Some(v) = unsafe { RULES_V6.get(&k2) } { return v.action; }

    let k3 = RuleKeyV6 { comm, dest_ip6: [0; 16], dest_port: port, _pad: [0; 6] };
    if let Some(v) = unsafe { RULES_V6.get(&k3) } { return v.action; }

    let k4 = RuleKeyV6 { comm, dest_ip6: [0; 16], dest_port: 0, _pad: [0; 6] };
    if let Some(v) = unsafe { RULES_V6.get(&k4) } { return v.action; }

    ACT_DENY
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
EOF

# ─── amwall-daemon — Phase 3: BPF + D-Bus interface + signals ───────

H "amwall-daemon (BPF loader + D-Bus system-bus interface + ConnectAttempt signal)"

write_file linux/amwall-daemon/Cargo.toml <<'EOF'
[package]
name = "amwall-daemon"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "amwall firewall daemon — BPF LSM enforcement + D-Bus interface"

[dependencies]
amwall-core.workspace = true
aya = "0.13"
anyhow = "1"
ctrlc = "3"
# zbus with tokio backend so we can drive its async work inside the
# daemon's tokio runtime (avoids mixing async-io and tokio reactors).
zbus = { version = "4", default-features = false, features = ["tokio"] }
tokio = { version = "1", features = ["rt", "rt-multi-thread", "macros", "sync", "time"] }

# ─── cargo-deb metadata ──────────────────────────────────────────────
# Builds a single .deb that bundles all four binaries (daemon, cli,
# gui, ebpf blob) plus the system bus policy, polkit action policy,
# systemd unit, .desktop file, and a starter rules.toml.
#
# Run from this directory:
#     cargo deb --no-build
# Output: ../target/debian/amwall_<version>_amd64.deb
#
# IMPORTANT: --no-build is REQUIRED. cargo-deb's auto-build only
# recognizes asset paths that literally start with "target/release/".
# Workspace-relative paths like "../target/release/..." trigger
# cosmetic "will not be built" warnings, and in auto-build mode
# would silently produce a hollow .deb. Build the workspace first
# (`cd linux && cargo build --release`), then `cargo deb --no-build`
# from this directory.

[package.metadata.deb]
name = "amwall"
priority = "optional"
section = "net"
maintainer = "amwall contributors <noreply@amwall.local>"
copyright = "2026, amwall contributors"
extended-description = """\
amwall is a per-application Linux firewall built on BPF LSM. The
amwall-daemon loads a BPF program that intercepts every IPv4 socket
connect() in the kernel and enforces allow/deny rules keyed on the
process comm + destination IP + destination port. amwall-gui is an
Iced popup that lets the user approve new connection attempts in real
time. amwall-cli is a headless rule manager. Rules persist to
/etc/amwall/rules.toml. Privileged operations (rule modification) are
gated by polkit (action 'org.amwall.Daemon1.modify-rules')."""
depends = "$auto, dbus, policykit-1, libqt6widgets6, libqt6dbus6"
assets = [
    ["../target/release/amwall-daemon", "usr/bin/amwall-daemon", "755"],
    ["../target/release/amwall-cli",    "usr/bin/amwall-cli",    "755"],
    ["../amwall-gui-qt/build/amwall-gui", "usr/bin/amwall-gui",  "755"],
    ["../amwall-ebpf/target/bpfel-unknown-none/release/amwall-ebpf",
     "usr/lib/amwall/amwall-ebpf.bpf", "644"],
    ["debian/org.amwall.Daemon1.conf",
     "etc/dbus-1/system.d/org.amwall.Daemon1.conf", "644"],
    ["debian/org.amwall.Daemon1.policy",
     "usr/share/polkit-1/actions/org.amwall.Daemon1.policy", "644"],
    ["debian/amwall-daemon.service",
     "lib/systemd/system/amwall-daemon.service", "644"],
    ["debian/amwall.desktop",
     "usr/share/applications/amwall.desktop", "644"],
    ["debian/rules.toml.example",
     "etc/amwall/rules.toml", "644"],
]
conf-files = [
    "/etc/amwall/rules.toml",
    "/etc/dbus-1/system.d/org.amwall.Daemon1.conf",
    "/usr/share/polkit-1/actions/org.amwall.Daemon1.policy",
]
maintainer-scripts = "debian/"
EOF

write_file linux/amwall-daemon/src/main.rs <<'EOF'
//! amwall-daemon — Phase 3 BPF LSM enforcement + D-Bus management.
//!
//! Architecture (Phase 3 / 3.5 / 4):
//!   - Main thread:     BPF setup, ringbuf drain, mtime poll, event print.
//!                      Forwards each ConnectEvent to the D-Bus thread
//!                      via a tokio mpsc unbounded channel.
//!   - D-Bus thread:    own tokio runtime, runs zbus SYSTEM-bus server
//!                      with org.amwall.Daemon1 interface. (System bus,
//!                      not session: the daemon is root, and root can't
//!                      auth onto a per-user session bus.) Emits
//!                      ConnectAttempt signal for each event received.
//!                      D-Bus method calls (Allow/Deny/Del/List) modify
//!                      rules.toml AND the BPF map directly.
//!                      Bus name registration requires the policy file
//!                      /etc/dbus-1/system.d/org.amwall.Daemon1.conf.
//!   - Polkit (Phase 4): Allow/Deny/Del methods call out to
//!                      org.freedesktop.PolicyKit1 to verify the caller
//!                      is authorized for action
//!                      `org.amwall.Daemon1.modify-rules`. Local-active
//!                      sessions pass without prompt (allow_active=yes
//!                      in the policy). List() stays open (read-only).
//!
//! Required env:    AMWALL_EBPF_PATH    path to the BPF ELF
//! Optional env:    AMWALL_RULES_PATH   path to rules.toml
//!                                       (default: ~/.config/amwall/rules.toml)

use std::collections::{HashMap as StdHashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use aya::maps::{HashMap as AyaHashMap, MapData, RingBuf};
use aya::programs::Lsm;
use aya::{Btf, Ebpf, Pod};
use tokio::sync::mpsc;

use amwall_core::rules::{Action, Rule, RulesFile};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const ACT_ALLOW: u8 = 1;

const POLKIT_ACTION_MODIFY: &str = "org.amwall.Daemon1.modify-rules";

#[repr(C)]
#[derive(Clone, Copy)]
struct ConnectEvent {
    pid: u32,
    comm: [u8; 16],
    family: u16,
    dest_port: u16,
    dest_ip4: u32,
    dest_ip6: [u8; 16],
    action: u8,
    _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct RuleKey {
    comm: [u8; 16],
    dest_ip4: u32,
    dest_port: u16,
    _pad: u16,
}

// Phase 6.4.1: parallel IPv6 BPF map. Mirror layout of amwall-ebpf's
// RuleKeyV6. The daemon installs a v6 wildcard entry for every "any"
// rule so a single user click covers v4 + v6 destinations.
#[repr(C)]
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct RuleKeyV6 {
    comm: [u8; 16],
    dest_ip6: [u8; 16],
    dest_port: u16,
    _pad: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RuleValue {
    action: u8,
    _pad: [u8; 7],
}

unsafe impl Pod for RuleKey {}
unsafe impl Pod for RuleKeyV6 {}
unsafe impl Pod for RuleValue {}

type RulesMap   = AyaHashMap<MapData, RuleKey,   RuleValue>;
type RulesV6Map = AyaHashMap<MapData, RuleKeyV6, RuleValue>;
type RulesShared   = Arc<Mutex<RulesMap>>;
type RulesV6Shared = Arc<Mutex<RulesV6Map>>;

// ─── D-Bus interface ────────────────────────────────────────────────

struct AmwallDaemon {
    rules:    RulesShared,
    rules_v6: RulesV6Shared,
    rules_path: PathBuf,
}

#[zbus::interface(name = "org.amwall.Daemon1")]
impl AmwallDaemon {
    async fn allow(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        comm: String,
        ip: String,
        port: u16,
    ) -> zbus::fdo::Result<()> {
        check_polkit(conn, &header, POLKIT_ACTION_MODIFY).await?;
        self.modify(comm, ip, port, Action::Allow)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    async fn deny(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        comm: String,
        ip: String,
        port: u16,
    ) -> zbus::fdo::Result<()> {
        check_polkit(conn, &header, POLKIT_ACTION_MODIFY).await?;
        self.modify(comm, ip, port, Action::Deny)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    async fn del(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        comm: String,
        ip: String,
        port: u16,
    ) -> zbus::fdo::Result<()> {
        check_polkit(conn, &header, POLKIT_ACTION_MODIFY).await?;
        self.delete(comm, ip, port)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    async fn list(&self) -> zbus::fdo::Result<Vec<(String, String, u16, String)>> {
        let cfg = RulesFile::load(&self.rules_path)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(cfg.rules.iter()
            .map(|r| (
                r.comm.clone(),
                r.ip.clone(),
                r.port,
                action_to_str(r.action).to_string(),
            ))
            .collect())
    }

    #[zbus(signal)]
    async fn connect_attempt(
        ctx: &zbus::SignalContext<'_>,
        pid: u32,
        comm: String,
        ip: String,
        port: u16,
        action: String,
    ) -> zbus::Result<()>;
}

impl AmwallDaemon {
    fn modify(&self, comm: String, ip: String, port: u16, action: Action) -> Result<()> {
        // Surface user/CLI rule changes in the daemon log so triage
        // can correlate "user clicked Allow" → subsequent connection
        // events. Polkit gating already happened in the D-Bus method
        // handler; if we're here the change is authorised.
        eprintln!(
            "[USER ] {} comm={} {}:{} (D-Bus rule change)",
            if matches!(action, Action::Allow) { "ALLOW" } else { "DENY " },
            comm, ip,
            if port == 0 { "any".to_string() } else { port.to_string() },
        );

        // Persist to TOML.
        let mut cfg = RulesFile::load(&self.rules_path).unwrap_or_default();
        cfg.rules.retain(|r| !(r.comm == comm && r.ip == ip && r.port == port));
        cfg.rules.push(Rule { comm: comm.clone(), ip: ip.clone(), port, action });
        cfg.save(&self.rules_path)?;

        // Apply to BPF map immediately. (mtime poll will also trigger
        // a reload moments later — harmless thanks to the diff-style
        // reload that doesn't transiently empty the map.)
        let rule = Rule { comm, ip, port, action };
        let val = RuleValue { action: rule.action_byte(), _pad: [0; 7] };

        // IPv4 map (always — "any" is dest_ip4=0 which is the v4 wildcard).
        let key = RuleKey {
            comm: rule.comm_bytes(),
            dest_ip4: rule.ip4()?,
            dest_port: rule.port,
            _pad: 0,
        };
        {
            let mut map = self.rules.lock().map_err(|_| anyhow::anyhow!("rules mutex poisoned"))?;
            map.insert(key, val, 0)
                .with_context(|| format!("inserting v4 via D-Bus: {:?}", rule))?;
        }

        // Phase 6.4.1: also mirror "any" rules into the v6 wildcard
        // slot. Specific IPv6 addresses aren't supported via the
        // current rules.toml schema (no v6 parsing path) — only "any"
        // touches the v6 map for now. Future: add a v6 ip parsing
        // branch alongside ip4().
        if rule.ip == "any" {
            let key6 = RuleKeyV6 {
                comm: rule.comm_bytes(),
                dest_ip6: [0; 16],
                dest_port: rule.port,
                _pad: [0; 6],
            };
            let mut map6 = self.rules_v6.lock().map_err(|_| anyhow::anyhow!("rules_v6 mutex poisoned"))?;
            map6.insert(key6, val, 0)
                .with_context(|| format!("inserting v6 wildcard via D-Bus: {:?}", rule))?;
        }
        Ok(())
    }

    fn delete(&self, comm: String, ip: String, port: u16) -> Result<()> {
        eprintln!(
            "[USER ] DEL   comm={} {}:{} (D-Bus rule change)",
            comm, ip,
            if port == 0 { "any".to_string() } else { port.to_string() },
        );

        let mut cfg = RulesFile::load(&self.rules_path).unwrap_or_default();
        cfg.rules.retain(|r| !(r.comm == comm && r.ip == ip && r.port == port));
        cfg.save(&self.rules_path)?;

        // Best-effort BPF map removal. Need a Rule to compute the key
        // — action doesn't matter for keying.
        let was_any = ip == "any";
        let dummy = Rule { comm, ip, port, action: Action::Allow };
        let key = RuleKey {
            comm: dummy.comm_bytes(),
            dest_ip4: dummy.ip4()?,
            dest_port: dummy.port,
            _pad: 0,
        };
        {
            let mut map = self.rules.lock().map_err(|_| anyhow::anyhow!("rules mutex poisoned"))?;
            let _ = map.remove(&key);
        }
        // Mirror the "any" → v6-wildcard pairing on delete.
        if was_any {
            let key6 = RuleKeyV6 {
                comm: dummy.comm_bytes(),
                dest_ip6: [0; 16],
                dest_port: dummy.port,
                _pad: [0; 6],
            };
            let mut map6 = self.rules_v6.lock().map_err(|_| anyhow::anyhow!("rules_v6 mutex poisoned"))?;
            let _ = map6.remove(&key6);
        }
        Ok(())
    }
}

fn action_to_str(a: Action) -> &'static str {
    match a { Action::Allow => "allow", Action::Deny => "deny" }
}

// ─── Polkit (Phase 4) ───────────────────────────────────────────────
//
// CheckAuthorization on org.freedesktop.PolicyKit1.Authority.
//   subject       (sa{sv})  = ("system-bus-name", { "name": <caller> })
//   action_id     s         = "org.amwall.Daemon1.modify-rules"
//   details       a{ss}     = empty
//   flags         u         = 1 (AllowUserInteraction)
//   cancellation  s         = ""
//   → result      (bba{ss}) = (is_authorized, is_challenge, details)
async fn check_polkit(
    conn: &zbus::Connection,
    header: &zbus::message::Header<'_>,
    action_id: &str,
) -> zbus::fdo::Result<()> {
    use std::collections::HashMap;
    use zbus::zvariant::Value;

    let sender = header
        .sender()
        .ok_or_else(|| zbus::fdo::Error::Failed("D-Bus message has no sender".into()))?;

    let mut subject_details: HashMap<&str, Value<'_>> = HashMap::new();
    subject_details.insert("name", Value::from(sender.as_str()));
    let subject: (&str, HashMap<&str, Value<'_>>) = ("system-bus-name", subject_details);

    let details: HashMap<&str, &str> = HashMap::new();
    let flags: u32 = 1; // AllowUserInteraction

    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
    )
    .await
    .map_err(|e| zbus::fdo::Error::Failed(format!("polkit proxy: {e}")))?;

    let (is_authorized, _is_challenge, _out_details): (bool, bool, HashMap<String, String>) =
        proxy
            .call(
                "CheckAuthorization",
                &(subject, action_id, details, flags, ""),
            )
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("polkit CheckAuthorization: {e}")))?;

    if is_authorized {
        Ok(())
    } else {
        Err(zbus::fdo::Error::AuthFailed(format!(
            "polkit denied '{action_id}' for caller {sender}"
        )))
    }
}

// ─── D-Bus thread (own tokio runtime) ───────────────────────────────

async fn run_dbus_server(
    rules: RulesShared,
    rules_v6: RulesV6Shared,
    rules_path: PathBuf,
    mut event_rx: mpsc::UnboundedReceiver<ConnectEvent>,
) -> Result<()> {
    eprintln!("amwall-daemon: D-Bus thread starting (system bus)");

    let iface = AmwallDaemon { rules, rules_v6, rules_path };
    let conn = zbus::connection::Builder::system()
        .context("system bus connection (is dbus running?)")?
        .name("org.amwall.Daemon1")
        .context("requesting bus name (policy file installed?)")?
        .serve_at("/org/amwall/Daemon1", iface)
        .context("registering interface")?
        .build()
        .await
        .context("building zbus connection")?;

    let object_server = conn.object_server();
    let iface_ref: zbus::InterfaceRef<AmwallDaemon> = object_server
        .interface("/org/amwall/Daemon1")
        .await
        .context("getting interface ref")?;

    eprintln!("amwall-daemon: D-Bus interface registered at org.amwall.Daemon1 (system bus)");

    while let Some(ev) = event_rx.recv().await {
        let comm = comm_str_owned(&ev.comm);
        let ip = match ev.family {
            AF_INET => Ipv4Addr::from(u32::from_be(ev.dest_ip4)).to_string(),
            AF_INET6 => Ipv6Addr::from(ev.dest_ip6).to_string(),
            other => format!("(family={})", other),
        };
        let action = if ev.action == ACT_ALLOW { "allow" } else { "deny" }.to_string();

        // Best-effort emit; signals to no-listener buses are normal.
        let _ = AmwallDaemon::connect_attempt(
            iface_ref.signal_context(),
            ev.pid,
            comm,
            ip,
            ev.dest_port,
            action,
        ).await;
    }

    Ok(())
}

// ─── Main thread (sync BPF + ringbuf + mtime poll) ──────────────────

fn main() -> Result<()> {
    let ebpf_path: PathBuf = std::env::var("AMWALL_EBPF_PATH")
        .context("AMWALL_EBPF_PATH env var not set")?
        .into();
    let rules_path = rules_path_from_env();

    eprintln!("amwall-daemon: BPF ELF = {}", ebpf_path.display());
    eprintln!("amwall-daemon: rules   = {}", rules_path.display());

    let mut ebpf = Ebpf::load_file(&ebpf_path)
        .with_context(|| format!("loading BPF ELF from {}", ebpf_path.display()))?;
    let btf = Btf::from_sys_fs()
        .context("loading vmlinux BTF (CONFIG_DEBUG_INFO_BTF must be enabled)")?;

    let program: &mut Lsm = ebpf
        .program_mut("amwall_socket_connect")
        .context("amwall_socket_connect program not found in BPF ELF")?
        .try_into()
        .context("amwall_socket_connect is not an Lsm program")?;
    program.load("socket_connect", &btf).context("loading LSM program")?;
    program.attach().context("attaching LSM program")?;

    let rules_raw_map = ebpf.take_map("RULES").context("RULES map missing")?;
    let rules_raw: RulesMap = AyaHashMap::try_from(rules_raw_map)
        .context("RULES map is not a HashMap")?;
    let rules: RulesShared = Arc::new(Mutex::new(rules_raw));

    // Phase 6.4.1: parallel IPv6 rule map.
    let rules_v6_raw_map = ebpf.take_map("RULES_V6").context("RULES_V6 map missing")?;
    let rules_v6_raw: RulesV6Map = AyaHashMap::try_from(rules_v6_raw_map)
        .context("RULES_V6 map is not a HashMap")?;
    let rules_v6: RulesV6Shared = Arc::new(Mutex::new(rules_v6_raw));

    let events_map = ebpf.take_map("EVENTS").context("EVENTS map missing")?;
    let mut events = RingBuf::try_from(events_map).context("EVENTS map is not a ring buffer")?;

    // Initial rule load — populates both v4 and v6 maps from rules.toml.
    {
        let mut map = rules.lock().unwrap();
        let mut map_v6 = rules_v6.lock().unwrap();
        match reload_rules(&mut map, &mut map_v6, &rules_path) {
            Ok(n) => eprintln!("amwall-daemon: loaded {} rules from {}", n, rules_path.display()),
            Err(e) => eprintln!("amwall-daemon: rules load failed: {}", e),
        }
    }
    eprintln!("amwall-daemon: enforcement ON. Default-deny on IPv4 + IPv6. Ctrl-C to exit.");

    // Channel from BPF drain → D-Bus signal emit.
    let (event_tx, event_rx) = mpsc::unbounded_channel::<ConnectEvent>();

    let dbus_rules    = rules.clone();
    let dbus_rules_v6 = rules_v6.clone();
    let dbus_path     = rules_path.clone();
    let dbus_thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime build");
        if let Err(e) = rt.block_on(run_dbus_server(dbus_rules, dbus_rules_v6, dbus_path, event_rx)) {
            eprintln!("amwall-daemon: D-Bus server stopped:");
            for cause in e.chain() {
                eprintln!("  caused by: {}", cause);
            }
        }
    });

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || r.store(false, Ordering::SeqCst))
        .context("installing Ctrl-C handler")?;

    let mut last_mtime = mtime_of(&rules_path);

    while running.load(Ordering::SeqCst) {
        while let Some(item) = events.next() {
            let bytes: &[u8] = &item;
            if bytes.len() < std::mem::size_of::<ConnectEvent>() { continue; }
            let ev: ConnectEvent = unsafe {
                std::ptr::read_unaligned(bytes.as_ptr() as *const ConnectEvent)
            };
            print_event(&ev);
            // Best-effort signal forwarding.
            let _ = event_tx.send(ev);
        }

        let now = mtime_of(&rules_path);
        if now != last_mtime {
            let mut map = rules.lock().unwrap();
            let mut map_v6 = rules_v6.lock().unwrap();
            match reload_rules(&mut map, &mut map_v6, &rules_path) {
                Ok(n) => eprintln!("amwall-daemon: rules reloaded ({} entries)", n),
                Err(e) => eprintln!("amwall-daemon: rules reload FAILED: {}", e),
            }
            drop(map);
            drop(map_v6);
            last_mtime = now;
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    eprintln!("amwall-daemon: shutting down (BPF auto-unloads).");
    drop(event_tx); // closes channel → D-Bus thread exits its recv loop
    let _ = dbus_thread.join();
    Ok(())
}

fn rules_path_from_env() -> PathBuf {
    if let Ok(p) = std::env::var("AMWALL_RULES_PATH") { return p.into(); }
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h).join(".config/amwall/rules.toml");
    }
    PathBuf::from("/etc/amwall/rules.toml")
}

fn mtime_of(path: &Path) -> SystemTime {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

// Diff-style reload: compute desired state, then add/remove rather
// than clear-then-insert. Avoids the brief "default-deny everything"
// window during reload (kernel could see an empty RULES map otherwise).
//
// Phase 6.4.1: also maintains RULES_V6. For each rule with ip="any"
// we install a v6 wildcard slot too, so a single user rule covers
// both address families. Specific IPv6 addresses aren't yet
// representable in rules.toml — only the "any" wildcard reaches v6.
fn reload_rules(map: &mut RulesMap, map_v6: &mut RulesV6Map, path: &Path) -> Result<usize> {
    let cfg = RulesFile::load(path)?;

    let mut desired_v4: StdHashMap<RuleKey, RuleValue> = StdHashMap::new();
    let mut desired_v6: StdHashMap<RuleKeyV6, RuleValue> = StdHashMap::new();
    for r in &cfg.rules {
        let val = RuleValue { action: r.action_byte(), _pad: [0; 7] };
        let key = RuleKey {
            comm: r.comm_bytes(),
            dest_ip4: r.ip4()?,
            dest_port: r.port,
            _pad: 0,
        };
        desired_v4.insert(key, val);
        if r.ip == "any" {
            let key6 = RuleKeyV6 {
                comm: r.comm_bytes(),
                dest_ip6: [0; 16],
                dest_port: r.port,
                _pad: [0; 6],
            };
            desired_v6.insert(key6, val);
        }
    }

    let current_v4: HashSet<RuleKey> = map.keys().filter_map(Result::ok).collect();
    for k in &current_v4 {
        if !desired_v4.contains_key(k) {
            let _ = map.remove(k);
        }
    }
    for (k, v) in &desired_v4 {
        map.insert(*k, *v, 0)?;
    }

    let current_v6: HashSet<RuleKeyV6> = map_v6.keys().filter_map(Result::ok).collect();
    for k in &current_v6 {
        if !desired_v6.contains_key(k) {
            let _ = map_v6.remove(k);
        }
    }
    for (k, v) in &desired_v6 {
        map_v6.insert(*k, *v, 0)?;
    }

    Ok(cfg.rules.len())
}

fn print_event(e: &ConnectEvent) {
    // Per-family tag so log readers can distinguish rule-driven
    // decisions from default-allow paths:
    //   [ALLOW] / [DENY ]  — IPv4 OR IPv6, evaluated against rules.
    //                        v6 has its own family-prefixed variant
    //                        below so reads scan as "v4 vs v6 deny".
    //   [LOCAL]            — AF_UNIX / AF_NETLINK / etc. — local IPC,
    //                        not a network policy concern (matches
    //                        simplewall behavior on Windows).
    //   [USER ]            — appears separately from modify()/delete()
    //                        when a user/CLI action persists a rule.
    let comm = comm_str(&e.comm);
    let (tag, dest) = match e.family {
        AF_INET => {
            let host = u32::from_be(e.dest_ip4);
            let t = if e.action == ACT_ALLOW { "ALLOW" } else { "DENY " };
            (t, format!("{}:{}", Ipv4Addr::from(host), e.dest_port))
        }
        AF_INET6 => {
            let t = if e.action == ACT_ALLOW { "V6 OK" } else { "V6 NO" };
            (t, format!("[{}]:{}", Ipv6Addr::from(e.dest_ip6), e.dest_port))
        }
        _ => (
            "LOCAL",
            format!("(family={})", e.family),
        ),
    };
    eprintln!("[{}] pid={} comm={} dest={}", tag, e.pid, comm, dest);
}

fn comm_str(bytes: &[u8; 16]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).unwrap_or("?")
}

fn comm_str_owned(bytes: &[u8; 16]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
EOF

# ─── debian/ scaffold for cargo-deb (Phase 4) ───────────────────────
#
# Files cargo-deb's [package.metadata.deb].assets references. The dbus
# and polkit policies duplicate the inline content in sections 4b/4c
# (which install them directly into /etc/ and /usr/share/ for the dev
# script run); cargo-deb reads from here so the .deb is self-contained.

H "amwall-daemon debian/ scaffold (postinst, prerm, postrm, .service, .desktop, .policy, .conf)"

write_file linux/amwall-daemon/debian/org.amwall.Daemon1.conf <<'EOF'
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

  <!-- any user may send messages to the daemon and receive its
       signals; per-method authorization is handled by polkit on the
       daemon side, not here. -->
  <policy context="default">
    <allow send_destination="org.amwall.Daemon1"/>
    <allow receive_sender="org.amwall.Daemon1"/>
  </policy>
</busconfig>
EOF

write_file linux/amwall-daemon/debian/org.amwall.Daemon1.policy <<'EOF'
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

write_file linux/amwall-daemon/debian/amwall-daemon.service <<'EOF'
[Unit]
Description=amwall firewall daemon (BPF LSM)
Documentation=https://github.com/amrust/amwall
After=dbus.service network.target
Requires=dbus.service

[Service]
Type=simple
ExecStart=/usr/bin/amwall-daemon
Environment="AMWALL_EBPF_PATH=/usr/lib/amwall/amwall-ebpf.bpf"
Environment="AMWALL_RULES_PATH=/etc/amwall/rules.toml"
Restart=on-failure
RestartSec=5
# BPF LSM load needs CAP_BPF + CAP_SYS_ADMIN + CAP_NET_ADMIN + CAP_PERFMON.
# Running as root is the path of least friction; capability narrowing
# is a follow-up.
User=root

[Install]
WantedBy=multi-user.target
EOF

write_file linux/amwall-daemon/debian/amwall.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=amwall
GenericName=Application firewall
Comment=Per-application firewall (Allow/Deny popups)
Exec=/usr/bin/amwall-gui
Icon=network-firewall
Categories=System;Security;Network;
Terminal=false
StartupNotify=true
Keywords=firewall;network;security;
EOF

write_file linux/amwall-daemon/debian/rules.toml.example <<'EOF'
# /etc/amwall/rules.toml — amwall firewall rules.
#
# IPv4 outbound connect() is denied by default. Add allow rules below
# to grant access per process. ip="any" and port=0 are wildcards. comm
# is the kernel's TASK_COMM_NAME of the calling process (max 15 chars).
#
# The daemon mtime-polls this file every 100 ms and reloads on change.
# amwall-cli --dbus and amwall-gui write through to here.
#
# [[rule]]
# comm = "firefox"
# ip = "any"
# port = 443
# action = "allow"
#
# [[rule]]
# comm = "firefox"
# ip = "any"
# port = 80
# action = "allow"
EOF

write_file linux/amwall-daemon/debian/postinst <<'EOF'
#!/bin/sh
set -e

if [ -x /usr/bin/systemctl ]; then
    systemctl daemon-reload || true
    systemctl reload dbus 2>/dev/null || true
fi

install -d -m 0755 /etc/amwall

# Don't auto-start; user opts in:
#   sudo systemctl enable --now amwall-daemon

exit 0
EOF
chmod +x linux/amwall-daemon/debian/postinst

write_file linux/amwall-daemon/debian/prerm <<'EOF'
#!/bin/sh
set -e

if [ -x /usr/bin/systemctl ] \
   && systemctl is-active --quiet amwall-daemon 2>/dev/null; then
    systemctl stop amwall-daemon || true
fi

exit 0
EOF
chmod +x linux/amwall-daemon/debian/prerm

write_file linux/amwall-daemon/debian/postrm <<'EOF'
#!/bin/sh
set -e

if [ -x /usr/bin/systemctl ]; then
    systemctl daemon-reload || true
    systemctl reload dbus 2>/dev/null || true
fi

# /etc/amwall/rules.toml is a conf-file; dpkg preserves user edits on
# upgrade and prompts on purge. Don't delete it here.

exit 0
EOF
chmod +x linux/amwall-daemon/debian/postrm

# ─── Build ──────────────────────────────────────────────────────────

H "Building amwall-ebpf (slow — pulls aya-ebpf, rebuilds core)"
INFO "Expect 2-5 minutes the first time."
if (cd linux/amwall-ebpf && cargo build --release 2>&1 | sed 's/^/    /'); then
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
if (cd linux && cargo build --release 2>&1 | sed 's/^/    /'); then
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
INFO "Packaging release binaries + debian/ scaffold (--no-build)..."
if (cd linux/amwall-daemon && cargo deb --no-build 2>&1 | sed 's/^/    /'); then
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
    H "✓ PHASES 2 + 3 + 4 + 5 + 6.1 + 6.2 + 6.3 + 6.4 (User Rules tab) ALL CONFIRMED"
    OK "Default-deny / live reload / D-Bus methods / D-Bus signals all work."
    OK "Polkit gates Allow/Deny/Del; local-active session passes through."
    OK ".deb builds and contains all 9 expected files."
    OK "amwall-core hoisted to repo root; Linux workspace consumes it."
    OK "amwall-gui (Qt6): tabbed central (Overview / User Rules) + connect-prompt + dashboard."
    OK "Manually verify: User Rules tab lists rules, Add/Edit/Delete buttons work."
    OK "Edit menu > Add rule (Ctrl+N) opens the editor on the User Rules tab."
else
    H "✗ Some Phase 2/3/4/5/6.1/6.2/6.3/6.4 tests had failures"
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
    H "DONE — Phase 6.4 — amwall installed, daemon running, Qt6 GUI with User Rules tab on screen"
else
    H "DONE — through Phase 6.4; install step skipped/failed"
fi

cat <<EOF
  Repo: $REPO_DIR
  (about to drop you into a shell here; type 'exit' to return)

  Suggested commit + snapshot:
    git add linux/ amwall-core/
    git commit -m "linux: Phase 6.4 — User Rules tab + Rule editor dialog"
    # then snapshot the VM as 'phase-6.4-user-rules-tab'

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
    - 6.1 ✓ — foundation: QMainWindow + tray + close-to-tray
    - 6.2 ✓ — status dashboard + DbusClient + real File/View/Help menus
    - 6.3 ✓ — connect-prompt dialog (per-comm Allow/Block, whole-app wildcards)
    - 6.4 ✓ — User Rules tab + Rule editor (Edit menu restored)
    - 6.5 — Connections tab (live /proc/net walk)
    - 6.6 — Packets log tab (ConnectAttempt history view; signal already wired)
    - 6.7 — Apps tab + App Properties dialog
    - 6.8 — Settings dialog (8-page QNotebook); restores Settings menu
    - 6.9 — i18n (rust_i18n locales/*.toml); Blocklist menu lands here

  6.3.1 (queued) — BPF reads task->group_leader->comm so multi-thread
                   apps (Firefox DNS Resolver #N) collapse to one prompt
                   instead of one per thread name.

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
