#!/usr/bin/env bash
# amwall — first-time install on a brand-new Linux Mint VM.
#
# linux-build.sh assumes you've cloned the repo already, which needs
# git, which isn't on a stock Mint 22.x minimal VM. install.sh is the
# preamble that closes that gap: it apt-installs git + ca-certificates,
# clones amwall to ~/amwall, and execs linux-build.sh.
#
# Designed to be fetchable from a fresh VM with nothing but curl:
#
#   curl -fsSL https://raw.githubusercontent.com/amrust/amwall/main/install.sh | bash
#
# Or download first if you want to read it before running (recommended
# for any curl|bash anywhere, ever):
#
#   curl -fsSL https://raw.githubusercontent.com/amrust/amwall/main/install.sh -o install.sh
#   less install.sh
#   bash install.sh
#
# Knobs:
#   AMWALL_REPO_URL   git URL          (default: https://github.com/amrust/amwall)
#   AMWALL_REPO_DIR   clone target     (default: $HOME/amwall)
#   AMWALL_BRANCH     branch to check out after clone  (default: main)
#
# Re-runnable: if $AMWALL_REPO_DIR already exists as a checkout, it
# does `git pull --ff-only` instead of cloning. APT install steps are
# no-ops when satisfied.

set -eu
set -o pipefail

REPO_URL="${AMWALL_REPO_URL:-https://github.com/amrust/amwall}"
REPO_DIR="${AMWALL_REPO_DIR:-$HOME/amwall}"
BRANCH="${AMWALL_BRANCH:-main}"

if [ -t 1 ]; then
    RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYA=$'\e[36m'; RST=$'\e[0m'
else
    RED=''; GRN=''; YEL=''; CYA=''; RST=''
fi
H()    { printf '\n%s── %s ──%s\n' "$CYA" "$*" "$RST"; }
OK()   { printf '%s[ OK  ]%s %s\n' "$GRN" "$RST" "$*"; }
INFO() { printf '%s[INFO ]%s %s\n' "$CYA" "$RST" "$*"; }
WARN() { printf '%s[WARN ]%s %s\n' "$YEL" "$RST" "$*"; }
FAIL() { printf '%s[FAIL ]%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }

# Running as root would put the clone under /root/, and rustup
# inside linux-build.sh installs per-user — so the daemon binary
# would end up owned by root with rustup state under /root/.cargo
# while the GUI tries to run as the desktop user. Refuse early.
if [ "$(id -u)" -eq 0 ]; then
    FAIL "Don't run install.sh as root. Run as your normal desktop user — it sudo's as needed."
fi

if ! command -v sudo >/dev/null 2>&1; then
    FAIL "sudo not found. Install sudo and add your user to the sudo group first."
fi

if ! command -v apt-get >/dev/null 2>&1; then
    FAIL "apt-get not found. This script targets Debian/Ubuntu/Mint."
fi

if ! grep -qE '^(UBUNTU_CODENAME|VERSION_CODENAME)=' /etc/os-release 2>/dev/null; then
    WARN "Couldn't read /etc/os-release. Continuing anyway — apt is present."
fi

H "Bootstrap: ensure git + curl + ca-certificates"
# We need git to clone the repo and ca-certificates so HTTPS verifies
# github.com. curl is mostly already present on Mint but include it
# for headless / minimal images where it isn't. linux-build.sh's
# big APT list installs all of these too, but it can't run until
# we've cloned the repo.
INFO "sudo apt-get update -qq"
sudo apt-get update -qq
INFO "sudo apt-get install -y git curl ca-certificates"
sudo apt-get install -y --no-install-recommends git curl ca-certificates \
    2>&1 | sed 's/^/    /'

for bin in git curl; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        FAIL "$bin missing after apt install — check the apt output above."
    fi
done
OK "git $(git --version | awk '{print $3}') · curl $(curl --version | head -1 | awk '{print $2}')"

H "Fetching amwall source → $REPO_DIR"
if [ -d "$REPO_DIR/.git" ]; then
    INFO "$REPO_DIR is already a checkout — running git pull --ff-only"
    if (cd "$REPO_DIR" && git pull --ff-only 2>&1 | sed 's/^/    /'); then
        OK "Updated to $(cd "$REPO_DIR" && git rev-parse --short HEAD)"
    else
        WARN "git pull failed (non-fast-forward or merge conflict)."
        WARN "Leaving working tree as-is — fix manually and re-run if needed."
    fi
elif [ -e "$REPO_DIR" ]; then
    FAIL "$REPO_DIR exists but isn't a git checkout. Move it aside or set AMWALL_REPO_DIR=/some/other/path."
else
    INFO "git clone --branch $BRANCH $REPO_URL $REPO_DIR"
    git clone --branch "$BRANCH" "$REPO_URL" "$REPO_DIR" 2>&1 | sed 's/^/    /'
    OK "Cloned at $(cd "$REPO_DIR" && git rev-parse --short HEAD)"
fi

if [ ! -x "$REPO_DIR/linux-build.sh" ]; then
    # git on Windows can drop the executable bit; chmod ensures the
    # next line works on any fresh clone.
    chmod +x "$REPO_DIR/linux-build.sh" 2>/dev/null || true
fi
if [ ! -x "$REPO_DIR/linux-build.sh" ]; then
    FAIL "$REPO_DIR/linux-build.sh missing or not executable. Bad clone?"
fi

H "Handing off to linux-build.sh"
INFO "Installs APT deps, Rust toolchain, builds the .deb, dpkg -i's it,"
INFO "starts amwall-daemon under systemd, and launches amwall-gui."
INFO "First run: 15-25 minutes (mostly Rust + Qt6 compile)."
INFO "Re-runs:  < 1 minute."
INFO ""
# exec replaces this shell so linux-build.sh's own log + tee setup
# work cleanly without a wrapping process.
exec "$REPO_DIR/linux-build.sh"
