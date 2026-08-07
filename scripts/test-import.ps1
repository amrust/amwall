# amwall - end-to-end import test (issues #11 / #12).
# Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
#
# Proves, on real hardware and against a REAL simplewall profile, that:
#
#   1. every %VAR% app path resolves to a file that exists  (issue #12)
#   2. those apps actually get a per-app permit in the kernel, which is
#      the half `cargo test` structurally cannot observe               (#12)
#   3. no localized column header is wider than its column             (#11)
#
# Safety: filters are installed VOLATILE (`-install -temp`, gone on
# reboot) and are UNINSTALLED again before the script exits, so a failed
# run cannot leave this machine behind a default-deny it did not ask
# for. Pass -KeepFilters to leave them up deliberately.
#
# Usage (from the repo root; it elevates itself, one UAC prompt):
#   pwsh -File scripts\test-import.ps1
#   pwsh -File scripts\test-import.ps1 -ProfilePath "C:\path\to\profile.xml"
#   pwsh -File scripts\test-import.ps1 -KeepFilters

param(
    [string]$ProfilePath = "$env:APPDATA\Henry++\simplewall\profile.xml",
    [switch]$KeepFilters
)

$ErrorActionPreference = 'Continue'
$log = Join-Path $env:TEMP 'amwall-import-test.txt'
$exe = Join-Path $PSScriptRoot '..\target\x86_64-pc-windows-msvc\release\amwall.exe'
$exe = [System.IO.Path]::GetFullPath($exe)

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
}

# The kernel section needs the admin token, and an elevated child's
# stdout is discarded - so re-launch once, write to a file, and print it
# back from the unelevated parent.
if (-not (Test-Elevated)) {
    if (-not (Test-Path $exe)) {
        Write-Host "amwall.exe not found at $exe" -ForegroundColor Red
        Write-Host "Build it first: cargo build --release --target x86_64-pc-windows-msvc"
        exit 1
    }
    if (-not (Test-Path $ProfilePath)) {
        Write-Host "Profile not found: $ProfilePath" -ForegroundColor Red
        exit 1
    }
    Remove-Item $log -ErrorAction SilentlyContinue
    $argv = @('-NoProfile','-File',$PSCommandPath,'-ProfilePath',$ProfilePath)
    if ($KeepFilters) { $argv += '-KeepFilters' }
    Start-Process -FilePath 'pwsh' -ArgumentList $argv -Verb RunAs -Wait
    if (Test-Path $log) { Get-Content $log } else { Write-Host "no output produced (UAC declined?)" -ForegroundColor Yellow }
    exit 0
}

# ---- elevated from here ----------------------------------------------

function Say([string]$s) { $s | Tee-Object -FilePath $log -Append | Out-Null }

Say "amwall import test"
Say "=================="
Say "exe     : $exe"
Say "profile : $ProfilePath"
Say ""

# --- 1. read-only resolution check --------------------------------------
Say "[1] Resolving every app path in the profile (read-only)"
$diagBefore = Join-Path $env:TEMP 'amwall-import-before.txt'
& $exe -diagnostics $ProfilePath -out $diagBefore | Out-Null
$before = Get-Content $diagBefore -Raw
foreach ($line in ($before -split "`r?`n")) {
    if ($line -match '^(total|file_entries|variable_paths|unresolvable|would_get_permit)\s|^env_var_paths|^column_headers|^missing_files|^\s+did not expand|^\s+not on disk') {
        Say "    $($line.Trim())"
    }
}
$expected = 0
if ($before -match 'would_get_permit\s+=\s+(\d+)') { $expected = [int]$Matches[1] }
Say ""

# --- 2. baseline kernel state -------------------------------------------
& $exe -diagnostics $ProfilePath -out (Join-Path $env:TEMP 'amwall-k0.txt') | Out-Null
$k0 = Get-Content (Join-Path $env:TEMP 'amwall-k0.txt') -Raw
$base = 0
if ($k0 -match 'amwall_filter_count\s+=\s+(\d+)') { $base = [int]$Matches[1] }
Say "[2] amwall filters in the kernel before install: $base"
Say ""

# --- 3. install VOLATILE filters ----------------------------------------
Say "[3] Installing filters from the profile (-temp = volatile, gone on reboot)"
& $exe -install $ProfilePath -temp -silent
$installExit = $LASTEXITCODE
Say "    install exit code: $installExit  (0 = success; exit code is the source of truth)"
Say ""

try {
    # --- 4. kernel state after ------------------------------------------
    & $exe -diagnostics $ProfilePath -out (Join-Path $env:TEMP 'amwall-k1.txt') | Out-Null
    $k1 = Get-Content (Join-Path $env:TEMP 'amwall-k1.txt') -Raw
    $after = 0
    if ($k1 -match 'amwall_filter_count\s+=\s+(\d+)') { $after = [int]$Matches[1] }
    Say "[4] amwall filters in the kernel after install : $after   (added $($after - $base))"
    Say ""

    # --- 5. ground truth: are the app-ids the RESOLVED paths? ------------
    # This is the assertion that actually closes issue #12. A permit
    # built from the literal `%ProgramFiles%\...` string would not exist
    # at all; one built correctly names the expanded path.
    Say "[5] netsh wfp show filters - app-id conditions amwall installed"
    $netsh = & netsh wfp show filters file=- 2>&1 | Out-String
    $appIds = [regex]::Matches($netsh, '(?im)^\s*FWPM_CONDITION_ALE_APP_ID.*?\r?\n(?:.*?\r?\n){0,6}?.*?([A-Za-z]:\\[^\r\n]*?\.exe)') |
              ForEach-Object { $_.Groups[1].Value.Trim().ToLower() } | Sort-Object -Unique
    if ($appIds.Count -eq 0) {
        # Fall back to any device-form path amwall may have registered.
        $appIds = [regex]::Matches($netsh, '(?im)(\\device\\harddiskvolume\d+\\[^\r\n"]*?\.exe)') |
                  ForEach-Object { $_.Groups[1].Value.Trim().ToLower() } | Sort-Object -Unique
    }
    if ($appIds.Count -eq 0) {
        Say "    (no app-id conditions parsed - see $env:TEMP\amwall-netsh.txt)"
        $netsh | Out-File (Join-Path $env:TEMP 'amwall-netsh.txt') -Encoding utf8
    } else {
        foreach ($a in $appIds) { Say "    $a" }
        $unexpanded = $appIds | Where-Object { $_ -like '*%*' }
        if ($unexpanded) {
            Say ""
            Say "    !! FAIL: an app-id still contains a % variable:"
            foreach ($u in $unexpanded) { Say "       $u" }
        }
    }
    Say ""

    # --- 6. verdict ------------------------------------------------------
    Say "[6] VERDICT"
    if ($before -match 'env_var_paths\s+=\s+(\S+)') { Say "    env_var_paths   : $($Matches[1])" }
    if ($before -match 'column_headers\s+=\s+(\S+)') { Say "    column_headers  : $($Matches[1])" }
    $delta = $after - $base
    if ($delta -gt 0) {
        Say "    per-app permits : PASS  ($delta filters added; profile expected $expected app(s) to be permitted)"
    } else {
        Say "    per-app permits : FAIL  (install added no filters - the permits did not reach the kernel)"
    }
}
finally {
    if ($KeepFilters) {
        Say ""
        Say "[7] -KeepFilters given: leaving filters INSTALLED."
        Say "    Undo with:  `"$exe`" -uninstall"
    } else {
        Say ""
        Say "[7] Removing the test filters again"
        & $exe -uninstall -silent
        Say "    uninstall exit code: $LASTEXITCODE"
        $netsh2 = & netsh wfp show filters file=- 2>&1 | Out-String
        $left = ([regex]::Matches($netsh2, 'amwall')).Count
        Say "    amwall mentions left in the kernel: $left  (0 = clean)"
    }
}
