# Install netwatch: binary on PATH, and recording from every boot.
#
#   irm https://github.com/FalconTechDev/netwatch/releases/latest/download/install.ps1 | iex
#
# What this does, in as many words:
#   1. downloads the release archive and checks it against its checksum
#   2. puts netwatch.exe somewhere and adds that to PATH
#   3. registers a scheduled task so recording starts at every boot
#   4. starts recording now, so you do not have to reboot to begin
#
# Step 3 is the one worth reading twice: it arranges for a program to run
# forever on this machine, as SYSTEM, starting before anyone logs in. That is
# what a traffic recorder has to do to be able to answer "what happened
# overnight", and it is stated plainly rather than done quietly.
#
#   NETWATCH_NO_AUTOSTART=1   install the binary only, no task
#   NETWATCH_DIR=<path>       install somewhere else
#   NETWATCH_VERSION=v0.3.0   a particular release

$ErrorActionPreference = 'Stop'

$Repo = 'FalconTechDev/netwatch'
$Task = 'netwatch'

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

$elevated  = Test-Elevated
$autostart = -not $env:NETWATCH_NO_AUTOSTART

# A task running as SYSTEM should point at a machine-wide location: a path
# inside one person's profile disappears with that profile and takes the
# recorder with it. Without elevation there is no machine-wide location to
# write to, so the binary goes in the profile and the task is skipped.
$Dir = if ($env:NETWATCH_DIR) { $env:NETWATCH_DIR }
       elseif ($elevated)     { Join-Path $env:ProgramFiles 'netwatch' }
       else                   { Join-Path $env:LOCALAPPDATA 'Programs\netwatch' }

$scope = if ($elevated) { 'Machine' } else { 'User' }

if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'netwatch is built for 64-bit Windows only.'
}
$target = 'x86_64-pc-windows-msvc'

# ── which version ────────────────────────────────────────────────────────────

$tag = $env:NETWATCH_VERSION
if (-not $tag) {
    Write-Host 'Looking up the latest release...'
    $tag = (Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest").tag_name
}
if (-not $tag) { throw 'Could not work out the latest version. Set $env:NETWATCH_VERSION.' }

$archive = "netwatch-$tag-$target.zip"
$base    = "https://github.com/$Repo/releases/download/$tag"

# ── fetch and verify ─────────────────────────────────────────────────────────

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("netwatch-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading netwatch $tag..."
    $zip = Join-Path $tmp $archive
    Invoke-WebRequest -Uri "$base/$archive" -OutFile $zip -UseBasicParsing

    try {
        $sumFile = Join-Path $tmp "$archive.sha256"
        Invoke-WebRequest -Uri "$base/$archive.sha256" -OutFile $sumFile -UseBasicParsing
        $expected = ((Get-Content $sumFile -Raw).Trim() -split '\s+')[0]
        $actual   = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
        if ($expected -and $expected.ToLower() -ne $actual) {
            throw 'Checksum mismatch - the download is not what the release published.'
        }
    } catch [System.Net.WebException] {
        Write-Host 'No checksum published for this release; skipping verification.'
    }

    Expand-Archive -Path $zip -DestinationPath $tmp -Force

    # Two executables: the console one you type `netwatch` to run, and the
    # windowless one that owns the tray icon. The tray one has no console by
    # design, so it can start at logon without a black window ever appearing.
    $wanted = @('netwatch.exe', 'netwatch-tray.exe')
    $found = @{}
    foreach ($name in $wanted) {
        $hit = Get-ChildItem -Path $tmp -Recurse -Filter $name | Select-Object -First 1
        if ($hit) { $found[$name] = $hit.FullName }
    }
    if (-not $found['netwatch.exe']) { throw 'The archive did not contain netwatch.exe.' }

    # A running recorder or tray holds its file open, so stop both before
    # replacing the binaries they run from - and say so, rather than failing
    # with a file-locked error nobody can act on.
    if ($elevated) {
        schtasks /end /tn $Task 2>&1 | Out-Null
        schtasks /end /tn "$Task-tray" 2>&1 | Out-Null
        Start-Sleep -Milliseconds 500
    }
    taskkill /IM netwatch-tray.exe /F 2>&1 | Out-Null

    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    foreach ($name in $found.Keys) {
        try {
            Copy-Item $found[$name] (Join-Path $Dir $name) -Force
        } catch {
            throw "Could not write $name to $Dir. Close any running netwatch and try again."
        }
        Write-Host "Installed $Dir\$name"
    }
    if (-not $found['netwatch-tray.exe']) {
        Write-Host 'This archive had no tray executable; the icon will be skipped.' -ForegroundColor Yellow
    }
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# ── PATH ─────────────────────────────────────────────────────────────────────

# Read from the registry rather than from $env:Path: that is this session's
# merged copy of the machine's and the user's, and writing it back as either
# one would copy every entry from the other into it.
$existing = [Environment]::GetEnvironmentVariable('Path', $scope)
$entries  = @($existing -split ';' | Where-Object { $_ -ne '' })

if ($entries -contains $Dir) {
    Write-Host "$Dir is already on the $($scope.ToLower()) PATH."
} else {
    [Environment]::SetEnvironmentVariable('Path', (($entries + $Dir) -join ';'), $scope)
    Write-Host "Added $Dir to the $($scope.ToLower()) PATH."
}
if (($env:Path -split ';') -notcontains $Dir) { $env:Path = "$env:Path;$Dir" }

# ── recording at boot ────────────────────────────────────────────────────────

Write-Host ''

if (-not $autostart) {
    Write-Host 'Skipped the startup task (NETWATCH_NO_AUTOSTART was set).'
    Write-Host 'To add it later, from an elevated terminal:  netwatch service install'
}
elseif (-not $elevated) {
    # Never pretend to have done this. An installer that silently installs less
    # than it said leaves someone believing they are recording when they are not.
    Write-Host 'Not elevated, so recording at boot was NOT set up.' -ForegroundColor Yellow
    Write-Host 'netwatch also needs an elevated terminal to run at all: reading which'
    Write-Host 'process sent a packet is a kernel-level question.'
    Write-Host ''
    Write-Host 'From a terminal opened as Administrator:'
    Write-Host '    netwatch service install'
}
else {
    # The binary registers its own task. One implementation rather than two:
    # the definition carries settings that matter — no time limit, and it
    # keeps running on battery — and a second copy of them here would drift
    # away from the one the tests cover.
    & (Join-Path $Dir 'netwatch.exe') service install
    if ($LASTEXITCODE -ne 0) {
        throw "Installed the binary, but registering the startup task failed (exit $LASTEXITCODE)."
    }
    Write-Host ""
    Write-Host "Log at $env:ProgramData\netwatch" -ForegroundColor Green
    Write-Host "An icon is now by the clock, and returns at every logon." -ForegroundColor Green
}

Write-Host ''
Write-Host 'Open a new terminal for the PATH change, then:'
Write-Host '    netwatch                    live view (needs an elevated terminal)'
Write-Host '    netwatch report --hours 12  what used the connection while you were away'
