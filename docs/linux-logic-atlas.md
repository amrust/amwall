# amwall — Linux Logic Atlas

> Companion to `docs/logic-atlas.md` (the Windows atlas). Same intent: map the whole Linux
> program, name the invariants, and mark what's guarded vs blind. **Derived by static reading only
> — the Linux side has NOT been run or tested from this analysis.** Every enforcement claim below is
> read from source (`amwall-ebpf`, `amwall-daemon`, `amwall-cli`, `amwall-core`, `amwall-gui-qt`),
> not observed on a live kernel. Line numbers drift — trust the shapes and invariants, verify
> against code and a real VM before relying on any of it.
>
> Snapshot: amwall Linux @ workspace `0.1.0` (`linux/` + root `amwall-core`), read 2026-07-25.
> The Linux port is a **physical re-implementation** — it shares only `amwall-core` (a small TOML
> rule schema), not the Windows `rules`/`profile`/`wfp` code. Platform split is by
> `#[cfg(windows)]` at module-declaration sites; there is no shared enforcement trait.

---

## L0 — the whole program at a glance

```
                        ┌──────────────────────── kernel ────────────────────────┐
   app calls connect()  │  security_socket_connect  (BPF LSM hook)                │
        ───────────────▶│      amwall-ebpf::decide()                              │
                        │        1. ENABLED toggle? (off → ACT_ALLOW, no event)   │
                        │        2. read sockaddr family/ip/port (probe_read)     │
                        │        3. BLOCKLIST_V4/V6 hit → ACT_DENY (hard)         │
                        │        4. RULES / RULES_V6 4-way wildcard lookup        │
                        │        5. no match → ACT_DENY  (default-deny)           │
                        │        emit ConnectEvent → EVENTS ring buffer           │
                        │      return 0 (allow) / -EPERM (deny)                    │
                        └───────────────────────────┬─────────────────────────────┘
                                                     │ ring buffer
                        ┌──────────── amwall-daemon (root) ───────────────────────┐
                        │  main thread: drain EVENTS, print, forward via mpsc;    │
                        │    poll rules.toml mtime (100 ms) → diff-reload maps     │
                        │  D-Bus thread (zbus, SYSTEM bus, org.amwall.Daemon1):    │
                        │    Allow/Deny/Del/List, Blocklist*, SetEnabled/IsEnabled,│
                        │    Reset, ResolveSockets; ConnectAttempt + EnabledChanged│
                        │    signals; modify ops polkit-gated (modify-rules)       │
                        └───────────────┬───────────────────────┬─────────────────┘
                     D-Bus system bus   │                       │  D-Bus signals
                        ┌───────────────▼──────┐        ┌────────▼──────────────────┐
                        │ amwall-cli (user/root)│        │ amwall-gui-qt (user)      │
                        │ list/allow/deny/del/  │        │ Qt6 Widgets, tray, 6 tabs,│
                        │ reset; --dbus or TOML │        │ connect prompt, polkit    │
                        └───────────────────────┘        └───────────────────────────┘

  Persistence:  rules.toml (per-user or /etc)   ·  /etc/amwall/blocklists.toml  ·
                /etc/amwall/enabled (master toggle)  ·  ~/.config/amwall/amwall.conf (GUI QSettings)
```

**The enforcement spine is:** `connect()` → BPF `decide()` → verdict, with the daemon/GUI as an
out-of-band control + notification plane. Unlike Windows (where WFP filters ARE the enforcement and
the GUI only manages them), here the **BPF map contents** are the enforcement and the daemon owns
them. Everything the GUI/CLI does is "edit rules.toml and/or the BPF map."

---

## Enforcement core — `amwall-ebpf` (322 lines, `bpfel-unknown-none`)

**Job:** the in-kernel policy. One LSM program.

- **Hook:** `#[lsm(hook = "socket_connect")]` → `amwall_socket_connect` → `decide()`. **This is the
  only hook.** `security_socket_bind` (inbound listen) and `security_socket_sendmsg` (unconnected
  UDP / raw) are NOT attached — see gap #1.
- **Maps:** `EVENTS` (RingBuf 256 KiB), `RULES` (HashMap<RuleKey, RuleValue>, 1024),
  `RULES_V6` (HashMap<RuleKeyV6,…>, 1024), `BLOCKLIST_V4` (HashMap<u32,u8>, 65 536),
  `BLOCKLIST_V6` (HashMap<[u8;16],u8>, 65 536), `ENABLED` (Array<u32>, 1).
- **`RuleKey`:** `{ comm:[u8;16], dest_ip4:u32, dest_port:u16 }`. Identity is the 16-byte **`comm`**
  (process name), NOT a path/inode/hash — see gap #2.
- **`decide()` order:** ENABLED off → `ACT_ALLOW` (and skips the event). Else read family; on any
  `bpf_probe_read_kernel` error → `ACT_ALLOW`; reserve a ring-buffer slot (on failure →
  `ACT_ALLOW`); blocklist hit → `ACT_DENY`; else `lookup`/`lookup_v6`.
- **`lookup` / `lookup_v6`:** 4-way wildcard fallthrough — (ip,port), (ip,*), (*,port), (*,*); no
  match → `ACT_DENY`. This is the default-deny.
- **`current_comm()`:** with the `task_walk` cargo feature (enabled by `linux-build.sh` when
  `aya-tool` emits `vmlinux.rs`), walks `task->group_leader->comm` so Firefox's per-thread worker
  names collapse to `firefox` for prompt dedup; else `bpf_get_current_comm()` (per-thread). Failure
  falls back to per-thread — a UX regression (extra prompts), not a security one.

**Fail-open surfaces (invariant risk — see gap #4):** three `decide()` paths return `ACT_ALLOW` on
failure: probe-read error, ring-buffer-full (`reserve` → `None`), and unknown address family. Under
a connect flood that outpaces the userspace drain, the ring buffer fills and connections pass. WFP
on Windows has no equivalent userspace-pressure fail-open.

---

## Control plane — `amwall-daemon` (1081 lines, root)

**Job:** own the BPF maps, persist rules, expose D-Bus, gate with polkit.

- **Two threads:** (1) main — BPF load/attach, drain `EVENTS`, `print_event`, forward each event to
  the D-Bus thread over a tokio mpsc channel, and poll `rules.toml` mtime every 100 ms; (2) D-Bus —
  its own current-thread tokio runtime, zbus **system-bus** server `org.amwall.Daemon1` at
  `/org/amwall/Daemon1` (root can't auth onto a session bus; needs
  `/etc/dbus-1/system.d/org.amwall.Daemon1.conf`).
- **D-Bus interface:**
  - `Allow(comm, ip, port)` / `Deny(...)` / `Del(...)` — polkit-gated (`org.amwall.Daemon1.modify-rules`);
    write `rules.toml` AND the BPF map.
  - `List()` — read-only, open.
  - `BlocklistList()` (open) / `BlocklistSetEnabled(name, bool)` (polkit) — Phase 6.9 telemetry/ads lists.
  - `SetEnabled(bool)` (polkit) / `IsEnabled()` (open) — master enforcement toggle; persists to
    `/etc/amwall/enabled`; emits `EnabledChanged`.
  - `Reset()` (polkit) — truncate `rules.toml`, delete `blocklists.toml`, empty the blocklist maps.
  - `ResolveSockets([inode]) → [(inode, pid, comm, exe)]` — root walks `/proc/*/fd` so the
    unprivileged GUI can attribute `/proc/net/tcp{,6}` rows to processes.
  - Signals: `ConnectAttempt(pid, comm, ip, port, action)`, `EnabledChanged(bool)`.
- **`reload_rules` / `blocklist::sync`:** **diff-style** (compute desired set, add/remove the delta)
  rather than clear-then-insert — deliberately avoids a transient empty-map "allow-everything"
  window during reload. This is the Linux analogue of the Windows "no fail-open during reinstall"
  invariant, and it's done correctly.
- **`rules_path_from_env`:** `AMWALL_RULES_PATH` else `$HOME/.config/amwall/rules.toml` else
  `/etc/amwall/rules.toml`. The systemd unit sets `AMWALL_RULES_PATH` (via `linux-build.sh`), which
  is what keeps the root daemon and the user's GUI/CLI pointed at the same file — see gap #9.
- **polkit:** `CheckAuthorization` on `org.freedesktop.PolicyKit1.Authority` with
  `AllowUserInteraction`; local-active sessions pass without prompt per the installed policy.

---

## `amwall-cli` (307 lines) and `amwall-core` (113 lines)

- **CLI:** `list / allow / deny / del / reset`, either editing `rules.toml` directly or `--dbus`
  through the daemon. `parse_dest` accepts only `"any"` or an **IPv4** literal (no IPv6). `--dbus
  reset` is explicitly unimplemented (routes you to `sudo amwall-cli reset`). `reset` honors
  `SUDO_USER` so it clears the invoking user's `~/.config/amwall/`, not `/root`'s.
- **amwall-core::rules:** the entire shared model. `Rule { comm:String, ip:String, port:u16, action }`,
  `RulesFile { rules: Vec<Rule> }`, TOML load/save. `comm_bytes()` truncates to 15 chars; `ip4()`
  parses `"any"`/`0.0.0.0`/empty → 0 (wildcard) else an `Ipv4Addr` — **no IPv6 path**;
  `action_byte()` Allow=1/Deny=0. That's the whole schema — no protocol, no port range, no
  direction, no path/hash/signer.

---

## `amwall-gui-qt` (~4350 lines, Qt6 Widgets, unprivileged)

**Job:** the interactive firewall UI. Tray-resident (close-to-tray), 6 tabs, talks only D-Bus.

- **Tabs:** Overview (dashboard) · User Rules (CRUD, the main surface) · Apps (`.desktop` scan →
  per-app allow/block) · Blocklists (enable/disable, polkit) · Connections (`/proc/net/tcp{,6}` +
  daemon `ResolveSockets`) · Packets log (live `ConnectAttempt`, 2000-row cap, pause/clear/filter).
- **Enforcement toggle** surfaced in menu/toolbar/tray/status badge; confirm-on-disable; red
  "FILTERS DISABLED" badge. Master `Reset all rules and config` (two-step confirm → daemon `Reset` +
  clear QSettings).
- **Connect prompt** (`connectprompt` + `promptcoordinator`): modeless top-level, one prompt per
  **comm**, queued one-at-a-time, 60 s cooldown + skip-if-`hasAnyRuleFor(comm)`; optional
  auto-**block** timeout (`notifications/autoBlockSec`, default 0=off). **A decision writes a
  whole-app wildcard rule** `allow/deny comm "any" 0` — see gap #16.
- **Rule editor:** comm (≤15 chars) / action / IP (`any` or IPv4 — **IPv6 rejected**) / port
  (0=any). Edit mode: only Action is editable.
- **Settings (QSettings → `~/.config/amwall/amwall.conf`):** `view/alwaysOnTop`,
  `general/startMinimized`, `general/confirmQuit`, `notifications/autoBlockSec`,
  `packetslog/showLocal`. Daemon-side config (`/etc/amwall/*`) is not edited here.
- **Window geometry: NOT persisted** — hardcoded `resize(900,600)`, no `saveGeometry`/
  `restoreGeometry`; and comments falsely imply geometry is a saved preference — see gap #10.
- **i18n:** QTranslator scaffolding, `en_US` only.

---

## Invariants (Linux) — get these wrong and it silently mis-enforces

1. **Default-deny lives in the BPF `lookup` fallthrough** (`None → ACT_DENY`), NOT in a filter table.
   No rule = blocked. Correct — but only for the `connect()` path (see gap #1).
2. **Blocklist is checked before per-comm rules** (`decide()` step 3), so a blocklist hit hard-denies
   even a user allow — matches the simplewall "system blocklist wins" semantic.
3. **`ENABLED` defaults to on / fail-closed** if the daemon hasn't seeded the map yet
   (`is_enforcement_enabled` returns `true` on `None`). Persisted to `/etc/amwall/enabled`; missing
   file → enabled.
4. **Diff-style map reload** (`reload_rules`, `blocklist::sync`) never transiently empties the maps —
   no allow-everything window during a rules edit. This is load-bearing; a clear-then-insert rewrite
   would reintroduce a fail-open window.
5. **BPF struct layouts are duplicated by hand** in three places — `amwall-ebpf` (`RuleKey`,
   `RuleKeyV6`, `RuleValue`, `ConnectEvent`), `amwall-daemon` (same, `#[repr(C)]` + `Pod`), and the
   GUI's D-Bus signatures. They must stay byte-identical; a field/pad drift silently mis-keys the
   map or mis-reads events. (No shared header enforces this — a real fragility.)
6. **Identity is `comm`** — every rule/verdict is keyed on the 15-char process name. This is THE
   enforcement identity and its weakness (gap #2) is structural, not a bug.

---

## Windows ↔ Linux comparison

| Dimension | Windows (amwall 2.0.1) | Linux (0.1.0) | Verdict |
|---|---|---|---|
| Enforcement mechanism | WFP filters (kernel), persistent | BPF LSM map lookup (kernel) | Both in-kernel; different model |
| Outbound `connect` default-deny | Yes | Yes (v4 + v6) | **Parity** |
| Inbound (listen/accept) default-deny | Yes (ALE_AUTH_RECV_ACCEPT) | **No hook** | **Gap #1** |
| Unconnected UDP / sendmsg | Covered by ALE connect+bind | **Not hooked** — bypasses | **Gap #1** |
| App identity | Full binary path (app-id blob) + optional SHA-256 hash + Authenticode signer | 15-char `comm` only | **Gap #2/#3** |
| Fail mode under pressure | Fails closed (filters persist) | **Fails open** (ringbuf full/probe err → allow) | **Gap #4** |
| IPv6 rules | Full (incl. address ranges) | Wildcard-only (`any`); no specific v6 addr | **Gap #5** |
| Protocol / port-range / direction in rules | Yes | No (single ip + single port) | **Gap #6** |
| Blocklist (hard deny, wins over allow) | Yes | Yes | **Parity** |
| Master "disable filters" toggle | Yes | Yes (`SetEnabled`) | **Parity** |
| Boot-time / persistent enforcement | Yes (BOOTTIME filters) | BPF unloads on daemon exit; systemd restarts it | Divergent (no early-boot coverage) |
| Fallback backend for old kernels | n/a | **No NFQUEUE fallback** (proposal unmet) | **Gap #7** |
| simplewall profile.xml migration | Yes | No (TOML only, no XML/rule-string share) | **Gap #8** |
| Rule-string presets (DNS/HTTP/QUIC…) | Yes (User Rules tab) | No | **Gap #8** |
| i18n | 43 languages | en_US only | **Gap #8** |
| Connect prompt, one-per-app dedup | Yes | Yes (per-comm, 60 s cooldown) | Parity (see #16 for precision) |
| Prompt → allow a *specific* endpoint | Yes | No — always whole-app wildcard | **Gap #16** |
| Timed allows (15 m/1 h/…) | Yes | No | Gap (low) |
| Per-app / per-connection traffic meter | Yes (ETW TCP+UDP) | No | Gap (low, net-new on Win) |
| Network-interface column (Apps) | Yes (2.0.1) | No | Gap (low) |
| Close a live connection | Yes (SetTcpEntry) | No (view-only) | Gap (low) |
| Window position/size persistence | Yes (2.0.1) | **No** (and a false "persisted" comment) | **Gap #10** |
| Privilege split | Single elevated process | root daemon + unprivileged GUI + polkit | Linux model is cleaner here |

---

## Gaps, prioritized (all found by reading, none verified on a kernel)

> **Fix-pass status (branch `feat/linux-gap-fixes`).** These are committed but built/tested only as
> far as a Windows host allows — the Linux crates are unverified pending a Mint VM build:
> - **#5 (specific IPv6 addresses) — FIXED.** `amwall-core` gains `DestIp`/`dest_ip()` (unit-tested,
>   and it *does* compile+test on Windows); the daemon routes v4/v6/any to the right map; the CLI
>   accepts `[v6]:port`; the rule editor validates v6.
> - **#9 (daemon rules-path) — FIXED.** Defaults to `/etc/amwall/rules.toml`, no `$HOME`.
> - **#10 (Qt window geometry) — FIXED.** `save/restoreGeometry` via QSettings.
> - **#14 (shared BPF structs) — FIXED.** New `no_std` `amwall-abi` crate; ebpf + daemon share it.
> - **#6 (TCP/UDP protocol matching) — DEFERRED to VM.** Needs a verifier-sensitive BPF change
>   (read the socket protocol in the LSM hook) that can't be validated off a live kernel; doing it
>   blind would risk a placeholder, so it's held for VM-verified work.
> All other gaps below remain open.

**HIGH — enforcement correctness / security:**

1. **Only `socket_connect` is hooked.** No inbound (`security_socket_bind`) and no unconnected-UDP /
   raw (`security_socket_sendmsg`). Outcome: a server app accepting connections is unfiltered, and
   UDP sent without `connect()` (much DNS, QUIC/HTTP3, many P2P protocols) **completely bypasses**
   the firewall. The proposal listed all three hooks; only one shipped. This is the largest behavior
   gap vs the Windows default-deny posture.
2. **Identity is the 15-char `comm`, not path/inode/hash.** Rename any binary to `firefox` and it
   inherits every `firefox` allow; two programs sharing a comm share rules; names >15 chars collide;
   a rule can't be scoped to a path or user. The proposal explicitly called for inode+device (+
   optional hash). This is spoofable by design.
3. **No binary hash / signature / tamper detection.** Windows has SHA-256 drift auto-disable,
   Authenticode signer extraction, auto-allow-Microsoft-signed, and cert-revocation. Linux has none —
   a compromised/replaced binary at the same path (same comm) keeps its allow silently.
4. **Fail-open in `decide()`.** Probe-read error, ring-buffer-full, and unknown family all return
   `ACT_ALLOW`. A connect flood that outruns the daemon's drain fills the 256 KiB ring buffer and
   opens the firewall. For a default-deny tool this is an invariant violation — the fallback on the
   emit path should be `ACT_DENY` (or the verdict should not depend on being able to emit an event).

**MEDIUM — feature/parity depth:**

5. **IPv6 rules are wildcard-only.** `rules.toml`/`ip4()`/the rule editor are IPv4-only; only
   `ip="any"` reaches `RULES_V6`. No per-address IPv6 allow/deny despite the BPF side supporting it.
6. **Rule model lacks protocol, port ranges, and direction.** Can't express "TCP 443 only" vs UDP,
   a port range, or inbound-vs-outbound. amwall-core `Rule` is comm+ip+port+action.
7. **No NFQUEUE fallback backend.** The proposal's portability guarantee (BPF LSM primary, NFQUEUE
   for kernels <5.7 / no `CONFIG_BPF_LSM`) is absent — no backend trait, no selection, no
   `AMWALL_FORCE_BACKEND`. Non-BPF-LSM kernels are unsupported.
8. **`amwall-core` shares none of the Windows rule-string parser, profile.xml, or locales** (the plan
   said to). Consequences: no simplewall profile migration, no rule-string presets, en_US-only i18n.
16. **Connect-prompt granularity: whole-app wildcard only.** Clicking Allow on "firefox → 1.2.3.4:443"
   writes `allow firefox any 0` — firefox is now allowed to *everything*, not just that endpoint.
   Windows lets you allow the specific endpoint. This is a real precision/usability gap that also
   weakens the security value of the prompt.

**LOW — polish / observation / UX:**

9. **Daemon rules-path seam.** Correct only because the systemd unit sets `AMWALL_RULES_PATH`; if it
   were ever unset the root daemon would read `/root/.config/...` while user tooling writes the
   user's home. Consider hard-defaulting the daemon to `/etc/amwall/rules.toml`.
10. **No window position/size persistence in the Qt GUI** (hardcoded `resize(900,600)`), and comments
   falsely claim it's a saved preference — the exact feature just shipped on Windows (2.0.1). Small,
   self-contained `QWidget::saveGeometry`/`restoreGeometry` via QSettings.
11. No per-app/per-connection traffic meter; no interface column (Windows 2.0.0/2.0.1 features —
    net-new on Windows, so low parity priority).
12. Connections tab is view-only (no close-connection action).
13. No timed allows.
14. **Hand-duplicated BPF struct layouts** across three crates with no shared definition — a latent
    footgun (invariant #5); a shared `#[repr(C)]` module would remove the drift risk.

---

## Blind spots for this analysis (be honest about what "no testing" costs)

Everything here is a **static read**. Not verified, and only verifiable on a live BPF-LSM kernel:

- Whether the BPF program actually loads and the verifier accepts `current_comm()`'s task-walk on
  the target kernels (the plan flags verifier rejections as the #1 risk).
- Whether the ring-buffer fail-open (#4) is reachable in practice and how fast a flood fills 256 KiB.
- The `comm` truncation / task-walk behavior on real multi-threaded apps (Firefox, Chrome) —
  the `comm`-vs-`group_leader->comm` delta the Windows CLAUDE.md guardrails already call out.
- polkit policy correctness (does `allow_active` actually pass a local desktop user without a
  password prompt on Mint?).
- Snap/Flatpak-confined browsers whose `comm` / exe path differ from the `.desktop` `Exec`.

The decisive next step for any of these is the `linuxplan.md` VMware Mint loop, not more reading.
```
