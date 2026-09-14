# Build a standalone Windows installer: one .ps1 that carries netwatch inside
# it and installs without downloading anything.
#
#   tools\make-standalone.ps1 -BinDir E:\rust-target\release
#
# The result is install.ps1 with the release archive appended to it as base64.
# Keeping one copy of the install logic rather than two is the whole point: a
# second implementation would drift from the one people actually use, and the
# offline path is exactly the one nobody would notice had rotted.

[CmdletBinding()]
param(
    # Where netwatch.exe and netwatch-tray.exe were built.
    [Parameter(Mandatory = $true)][string]$BinDir,
    [string]$Out
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
if (-not $Out) { $Out = Join-Path $root 'dist\netwatch-standalone-installer.ps1' }

$exe = Join-Path $BinDir 'netwatch.exe'
$tray = Join-Path $BinDir 'netwatch-tray.exe'
if (-not (Test-Path $exe)) { throw "netwatch.exe not found in $BinDir" }
if (-not (Test-Path $tray)) { throw "netwatch-tray.exe not found in $BinDir" }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("netwatch-bundle-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path (Join-Path $tmp 'netwatch') -Force | Out-Null
try {
    # The payload is the same archive shape install.ps1 already knows how to
    # unpack, so the embedded installer needs no special case for having been
    # handed one.
    Copy-Item $exe, $tray (Join-Path $tmp 'netwatch')
    foreach ($f in 'README.md', 'LICENSE', 'install.ps1') {
        $p = Join-Path $root $f
        if (Test-Path $p) { Copy-Item $p (Join-Path $tmp 'netwatch') }
    }

    $zip = Join-Path $tmp 'payload.zip'
    Compress-Archive -Path (Join-Path $tmp 'netwatch\*') -DestinationPath $zip -Force
    $payload = [Convert]::ToBase64String([IO.File]::ReadAllBytes($zip))

    $installer = Get-Content (Join-Path $root 'install.ps1') -Raw

    # The installer text is embedded in a single-quoted here-string, so nothing
    # in it is expanded while this file is being read. A here-string ends at a
    # line that is exactly "'@", so an installer containing such a line would
    # break out of it — worth checking rather than discovering at install time.
    if ($installer -match "(?m)^'@\s*$") {
        throw "install.ps1 contains a line that would close the here-string."
    }

    $header = @'
# netwatch — standalone installer for Windows.
#
# Everything needed is inside this one file: both executables, the installer,
# and nothing to download. From an ELEVATED PowerShell:
#
#   powershell -ExecutionPolicy Bypass -File netwatch-standalone-installer.ps1
#
# It installs to Program Files, adds that to PATH, starts recording at every
# boot and puts the icon by the clock. NETWATCH_DIR, NETWATCH_NO_AUTOSTART and
# the rest of the usual variables still work.

$ErrorActionPreference = 'Stop'

$nwTmp = Join-Path ([IO.Path]::GetTempPath()) ("netwatch-standalone-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $nwTmp -Force | Out-Null
try {
    $nwZip = Join-Path $nwTmp 'netwatch.zip'
    [IO.File]::WriteAllBytes($nwZip, [Convert]::FromBase64String($NetwatchPayload))

    # Hand the embedded installer the archive and let it do the rest, so there
    # is only ever one implementation of "install netwatch".
    $env:NETWATCH_ARCHIVE_FILE = $nwZip
    $nwInstaller = Join-Path $nwTmp 'install.ps1'
    Set-Content -Path $nwInstaller -Value $NetwatchInstaller -Encoding UTF8
    & powershell -NoProfile -ExecutionPolicy Bypass -File $nwInstaller
    if ($LASTEXITCODE -ne 0) { throw "the installer failed (exit $LASTEXITCODE)." }
}
finally {
    $env:NETWATCH_ARCHIVE_FILE = $null
    Remove-Item $nwTmp -Recurse -Force -ErrorAction SilentlyContinue
}
'@

    New-Item -ItemType Directory -Path (Split-Path -Parent $Out) -Force | Out-Null

    # Payload and installer first: the header refers to both, so they have to
    # exist by the time it runs.
    $sb = [Text.StringBuilder]::new()
    [void]$sb.AppendLine('$NetwatchPayload = @''')
    [void]$sb.AppendLine($payload)
    [void]$sb.AppendLine('''@')
    [void]$sb.AppendLine('$NetwatchInstaller = @''')
    [void]$sb.AppendLine($installer.TrimEnd())
    [void]$sb.AppendLine('''@')
    [void]$sb.AppendLine($header)

    Set-Content -Path $Out -Value $sb.ToString() -Encoding UTF8
    Write-Host "wrote $Out ($((Get-Item $Out).Length) bytes)"
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
