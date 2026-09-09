# Install netwatch and put it on PATH.
#
#   irm https://github.com/FalconTechDev/netwatch/releases/latest/download/install.ps1 | iex
#
# No administrator rights are needed: the binary goes under your own profile and
# the PATH entry is set for your user, not the machine. Set $env:NETWATCH_DIR
# to install somewhere else.

$ErrorActionPreference = 'Stop'

$Repo = 'FalconTechDev/netwatch'
$Dir  = if ($env:NETWATCH_DIR) { $env:NETWATCH_DIR }
        else { Join-Path $env:LOCALAPPDATA 'Programs\netwatch' }

if ([Environment]::Is64BitOperatingSystem -eq $false) {
    throw 'netwatch is built for 64-bit Windows only.'
}
$target = 'x86_64-pc-windows-msvc'

# ── which version ────────────────────────────────────────────────────────────

$tag = $env:NETWATCH_VERSION
if (-not $tag) {
    Write-Host 'Looking up the latest release...'
    $rel = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
    $tag = $rel.tag_name
}
if (-not $tag) { throw 'Could not work out the latest version. Set $env:NETWATCH_VERSION.' }

$archive = "netwatch-$tag-$target.zip"
$base    = "https://github.com/$Repo/releases/download/$tag"

# ── fetch ────────────────────────────────────────────────────────────────────

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("netwatch-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading netwatch $tag for $target..."
    $zip = Join-Path $tmp $archive
    Invoke-WebRequest -Uri "$base/$archive" -OutFile $zip -UseBasicParsing

    # Verify what arrived against the checksum the release published.
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
    $exe = Get-ChildItem -Path $tmp -Recurse -Filter 'netwatch.exe' | Select-Object -First 1
    if (-not $exe) { throw 'The archive did not contain netwatch.exe.' }

    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    # A running copy cannot be overwritten, and that is worth saying plainly
    # rather than failing with a file-locked error nobody can act on.
    try {
        Copy-Item $exe.FullName (Join-Path $Dir 'netwatch.exe') -Force
    } catch {
        throw "Could not write to $Dir. Close any running netwatch and try again."
    }
    Write-Host "Installed $Dir\netwatch.exe"
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# ── PATH ─────────────────────────────────────────────────────────────────────

# The user's own PATH, read from the registry rather than from $env:Path, which
# is this session's merged copy and would write the machine's entries back into
# the user's if used as the base.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$entries  = @($userPath -split ';' | Where-Object { $_ -ne '' })

if ($entries -contains $Dir) {
    Write-Host "$Dir is already on your PATH."
} else {
    [Environment]::SetEnvironmentVariable('Path', (($entries + $Dir) -join ';'), 'User')
    Write-Host "Added $Dir to your PATH."
}

# Make it work in this session too, so there is something to try right away.
if (($env:Path -split ';') -notcontains $Dir) { $env:Path = "$env:Path;$Dir" }

Write-Host ''
Write-Host 'Open a new terminal for the PATH change to apply everywhere.'
Write-Host 'Then, from an elevated terminal:  netwatch'
