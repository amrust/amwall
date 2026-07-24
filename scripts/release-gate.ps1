# amwall -- release gate runner.
# Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
#
# One command to check a build is safe to tag. Two tiers:
#
#   Tier 1 (automatic, no elevation) -- the gate triad plus the
#     pure-logic invariant tests. This is what CI runs and what
#     `cargo test` covers: parsers, config round-trip, and the
#     default-deny install-plan ordering / action / weight invariants
#     (src/install.rs `default_deny_plan` tests). Catches a logic
#     regression like "block catch-all emitted before the callout".
#
#   Tier 2 (live, ELEVATED) -- installs amwall's real default-deny on
#     the live Base Filtering Engine and proves an ordinary outbound
#     connection that worked a moment ago is now BLOCKED and that the
#     drop surfaces to the event pipeline (tests/live_enforcement.rs).
#     This is the check that would have caught the v1.1.17 / v1.1.18
#     "firewall permits everything" ship, which sailed through a green
#     gate triad twice because `cargo test` never opens the BFE.
#
# Usage:
#   pwsh -File scripts/release-gate.ps1              # Tier 1 (+ Tier 2 if already elevated)
#   pwsh -File scripts/release-gate.ps1 -SkipLive    # Tier 1 only
#   pwsh -File scripts/release-gate.ps1 -Full        # Tier 1 + the ENTIRE ignored live suite
#
# NOTE: Tier 2 briefly cuts this machine's network (a few seconds)
# while default-deny is active; it is torn down automatically, even on
# a failed assertion. Run it when a short network blip is acceptable.

[CmdletBinding()]
param(
    [switch]$SkipLive,
    [switch]$Full,
    [string]$Target = 'x86_64-pc-windows-msvc'
)

$ErrorActionPreference = 'Continue'
$results = [System.Collections.Generic.List[object]]::new()

function Invoke-Step {
    param(
        [string]$Name,
        [string[]]$Cmd
    )
    Write-Host ''
    Write-Host "==> $Name" -ForegroundColor Cyan
    Write-Host "    $($Cmd -join ' ')" -ForegroundColor DarkGray
    & $Cmd[0] @($Cmd[1..($Cmd.Count - 1)])
    $ok = ($LASTEXITCODE -eq 0)
    $script:results.Add([pscustomobject]@{ Step = $Name; Result = if ($ok) { 'PASS' } else { 'FAIL' } })
    if (-not $ok) { Write-Host "    FAILED: $Name (exit $LASTEXITCODE)" -ForegroundColor Red }
    return $ok
}

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = [Security.Principal.WindowsPrincipal]$id
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

Write-Host 'amwall release gate' -ForegroundColor White
Write-Host "target: $Target"

# --- Tier 1: automatic, no elevation ---------------------------------
Invoke-Step 'build (release)'  @('cargo', 'build', '--release', '--target', $Target) | Out-Null
Invoke-Step 'clippy (-D warnings)' @('cargo', 'clippy', '--all-targets', '--target', $Target, '--', '-D', 'warnings') | Out-Null
Invoke-Step 'test (pure-logic + invariants)' @('cargo', 'test', '--target', $Target) | Out-Null

# --- Tier 2: live enforcement, ELEVATED ------------------------------
$elevated = Test-Elevated
if ($SkipLive) {
    Write-Host ''
    Write-Host 'Tier 2 (live enforcement) skipped: -SkipLive.' -ForegroundColor Yellow
}
elseif (-not $elevated) {
    Write-Host ''
    Write-Host 'Tier 2 (live enforcement) skipped: not elevated.' -ForegroundColor Yellow
    Write-Host 'Re-run from an elevated shell to prove the firewall actually blocks:' -ForegroundColor Yellow
    Write-Host '  pwsh -File scripts/release-gate.ps1' -ForegroundColor Yellow
    $results.Add([pscustomobject]@{ Step = 'live enforcement'; Result = 'SKIP (not elevated)' })
}
else {
    Write-Host ''
    Write-Host 'Tier 2 will briefly cut this machine''s network while default-deny is active.' -ForegroundColor Yellow
    if ($Full) {
        Invoke-Step 'live suite (ALL ignored)' @('cargo', 'test', '--target', $Target, '--', '--ignored', '--nocapture') | Out-Null
    }
    else {
        Invoke-Step 'live enforcement (default-deny blocks)' @('cargo', 'test', '--target', $Target, '--test', 'live_enforcement', '--', '--ignored', '--nocapture') | Out-Null
    }
}

# --- Summary ---------------------------------------------------------
Write-Host ''
Write-Host '==================== release gate ====================' -ForegroundColor White
$results | Format-Table -AutoSize | Out-String | Write-Host
$failed = @($results | Where-Object { $_.Result -eq 'FAIL' }).Count
if ($failed -gt 0) {
    Write-Host "RESULT: $failed step(s) FAILED -- do NOT tag this build." -ForegroundColor Red
    exit 1
}
$skipped = @($results | Where-Object { $_.Result -like 'SKIP*' }).Count
if ($skipped -gt 0) {
    Write-Host "RESULT: all run steps PASSED, but $skipped skipped (run elevated for full coverage)." -ForegroundColor Yellow
    exit 0
}
Write-Host 'RESULT: all steps PASSED -- safe to tag.' -ForegroundColor Green
exit 0
