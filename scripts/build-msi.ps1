# amwall — multilingual MSI installer build.
# Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
#
# Builds one MSI containing every language transform under wix/lang/.
# Used by both .github/workflows/release.yml (CI) and
# .vscode/tasks.json (Ctrl+Shift+B → "Build MSI installer") so the
# local build matches what tag-driven releases produce.
#
# Pipeline:
#   1. Verify WiX 3.x is on PATH (candle.exe / light.exe / torch.exe).
#   2. Compile main.wxs once with -arch x64.
#   3. Link a base MSI in en-US.
#   4. For every other wxl: link a per-culture MSI, torch -t language
#      against the base to produce a .mst, then embed the .mst into
#      the base MSI's _Storages table by LCID via the helper
#      wix/scripts/embed-transform.vbs.
#   5. Rewrite the Template summary (wix/scripts/set-languages.vbs)
#      so Windows Installer auto-applies the matching transform at
#      install time based on the user's UI language.
#
# Assumes the release binary already exists at
# target\x86_64-pc-windows-msvc\release\amwall.exe — call sites are
# expected to run cargo build first.

$ErrorActionPreference = 'Stop'

if (-not (Get-Command candle.exe -ErrorAction SilentlyContinue)) {
    Write-Error @"
WiX Toolset 3.x not found on PATH. Install via:
  choco install wixtoolset -y    (run from an elevated shell)
or download from https://github.com/wixtoolset/wix3/releases
"@
    exit 1
}

$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.+)"' |
            ForEach-Object { $_.Matches[0].Groups[1].Value })
$targetBin = "target\x86_64-pc-windows-msvc\release"
$wixDir = "target\wix"
$langDir = "$wixDir\lang"

if (-not (Test-Path "$targetBin\amwall.exe")) {
    Write-Error "Release exe missing at $targetBin\amwall.exe — run cargo build --release --target x86_64-pc-windows-msvc first."
    exit 1
}

New-Item -ItemType Directory -Path $wixDir -Force | Out-Null
New-Item -ItemType Directory -Path $langDir -Force | Out-Null

# Compile main.wxs once — the same .wixobj is linked per culture.
# -arch x64 sets the platform so the Template summary lists x64
# (required by ICE80 because main.wxs has Win64="yes" components).
candle.exe -nologo `
    -arch x64 `
    "-dVersion=$version" `
    "-dCargoTargetBinDir=$targetBin" `
    -ext WixUIExtension `
    -out "$wixDir\main.wixobj" `
    wix\main.wxs
if ($LASTEXITCODE -ne 0) { throw "candle.exe failed" }

# Build base MSI in en-US.
$baseMsi = "$wixDir\amwall-$version-x86_64.msi"
light.exe -nologo `
    -ext WixUIExtension `
    -cultures:en-us `
    -loc wix\lang\en-us.wxl `
    -out $baseMsi `
    "$wixDir\main.wixobj"
if ($LASTEXITCODE -ne 0) { throw "light.exe failed for base en-US MSI" }

# Track every embedded LCID, starting with the base.
$lcids = @([System.Globalization.CultureInfo]::new("en-US").LCID)

# Build, transform, and embed each non-base culture.
Get-ChildItem wix\lang\*.wxl |
    Where-Object { $_.BaseName -ne "en-us" } |
    ForEach-Object {
        $culture = $_.BaseName
        $lcid = [System.Globalization.CultureInfo]::new($culture).LCID
        $langMsi = "$langDir\$culture.msi"
        $mst = "$langDir\$culture.mst"

        # `-cultures:<culture>;en-us` so cultures missing from
        # WixUIExtension (e.g. vi-VN, az-Latn-AZ) fall back to English
        # for stock dialog strings.
        light.exe -nologo `
            -ext WixUIExtension `
            "-cultures:$culture;en-us" `
            -loc $_.FullName `
            -out $langMsi `
            "$wixDir\main.wixobj"
        if ($LASTEXITCODE -ne 0) { throw "light.exe failed for $culture" }

        torch.exe -p -t language $baseMsi $langMsi -out $mst
        if ($LASTEXITCODE -ne 0) { throw "torch.exe failed for $culture" }

        cscript //nologo wix\scripts\embed-transform.vbs $baseMsi $mst $lcid
        if ($LASTEXITCODE -ne 0) { throw "embed-transform.vbs failed for $culture (LCID $lcid)" }

        $lcids += $lcid
    }

# Rewrite the Template summary so Windows Installer treats the MSI
# as multilingual and auto-picks the right transform.
$lcidCsv = ($lcids | Sort-Object -Unique) -join ","
cscript //nologo wix\scripts\set-languages.vbs $baseMsi $lcidCsv
if ($LASTEXITCODE -ne 0) { throw "set-languages.vbs failed" }

Write-Host ""
Write-Host "MSI built: $baseMsi" -ForegroundColor Green
Write-Host "Embedded $($lcids.Count) languages: $lcidCsv" -ForegroundColor Green
