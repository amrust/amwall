# Build amwall in release, then launch via UAC with stderr
# redirected to swaplog.txt. The elevated cmd.exe wrapper handles
# the redirection because Start-Process -Verb RunAs can't pipe
# stdio (ShellExecute-based launch).

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

cargo build --release
if ($LASTEXITCODE -ne 0) {
    Write-Error "cargo build failed with exit $LASTEXITCODE"
    exit $LASTEXITCODE
}

$exe = Join-Path $root 'target\release\amwall.exe'
$log = Join-Path $root 'swaplog.txt'

if (-not (Test-Path $exe)) {
    Write-Error "Built binary not found at $exe"
    exit 1
}

# Pre-create / truncate the log file with a header marker so we can
# tell at a glance whether the elevated process actually wrote to it.
"=== elevated launch $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" |
    Set-Content -Path $log -Encoding utf8 -NoNewline

# /k keeps the cmd window open after amwall exits so we can read
# any error messages or path-resolution issues. Echo the inputs so
# the elevated console shows which paths it's working with.
$cmdArgs = "/k echo EXE=`"$exe`" && echo LOG=`"$log`" && echo CWD=%CD% && `"$exe`" 2>> `"$log`" && echo amwall exited code %ERRORLEVEL%"

Write-Host "Launching elevated: cmd.exe $cmdArgs"
Start-Process -Verb RunAs -FilePath cmd.exe -ArgumentList $cmdArgs
