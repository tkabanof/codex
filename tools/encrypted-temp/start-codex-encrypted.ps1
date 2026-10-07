#Requires -Version 5.1
<#
Launch native Codex CLI using an already mounted custom encrypted temp drive.
Existing temp directories are never moved/deleted automatically. Junctions remain
after exit, so missing encrypted storage causes an error instead of plaintext IO.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[D-Zd-z]:$')]
    [string]$Drive,
    [string]$CodexHome = $(if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE '.codex' }),
    [string]$CodexExecutable = 'codex.exe',
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CodexArguments = @()
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ('CodexTempVolume' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class CodexTempVolume {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool GetVolumeInformation(string root, StringBuilder label,
        int labelSize, out uint serial, out uint maxName, out uint flags,
        StringBuilder fs, int fsSize);
}
'@
}
$Drive = $Drive.ToUpperInvariant()
$root = "$Drive\"
$label = New-Object System.Text.StringBuilder 261
$filesystem = New-Object System.Text.StringBuilder 261
[uint32]$serial = 0
[uint32]$maxName = 0
[uint32]$flags = 0
if (-not [CodexTempVolume]::GetVolumeInformation($root, $label, 261, [ref]$serial,
        [ref]$maxName, [ref]$flags, $filesystem, 261) -or
        $filesystem.ToString() -ne 'CodexTempCrypt' -or
        $label.ToString() -ne 'Codex encrypted temp') {
    throw 'Custom encrypted filesystem is not mounted. No plaintext fallback is allowed.'
}
$codex = (Get-Command $CodexExecutable -CommandType Application -ErrorAction Stop).Source
$CodexHome = [System.IO.Path]::GetFullPath($CodexHome)
if ([System.IO.Path]::GetPathRoot($CodexHome) -eq $root) {
    throw 'CODEX_HOME must stay outside the ephemeral drive so databases remain persistent.'
}
if (-not (Test-Path -LiteralPath $CodexHome -PathType Container)) {
    throw 'Create CODEX_HOME first. This launcher does not initialize or move it.'
}

# This is an exclusive configuration step. Close other Codex instances first.
$redirects = @{
    'tmp' = Join-Path $root 'codex-tmp'
    '.tmp' = Join-Path $root 'codex-dot-tmp'
}
# Validate all existing entries before creating any junction.
foreach ($name in $redirects.Keys) {
    $source = Join-Path $CodexHome $name
    $item = Get-Item -LiteralPath $source -Force -ErrorAction SilentlyContinue
    if ($null -ne $item) {
        if ($item.LinkType -ne 'Junction' -or @($item.Target).Count -ne 1 -or
            [string]$item.Target[0] -ne $redirects[$name]) {
            throw "Existing '$source' is not the expected junction. Close Codex and relocate that directory before setup; it will not be overwritten."
        }
    }
}
foreach ($name in $redirects.Keys) {
    New-Item -ItemType Directory -Path $redirects[$name] -Force | Out-Null
    $source = Join-Path $CodexHome $name
    if ($null -eq (Get-Item -LiteralPath $source -Force -ErrorAction SilentlyContinue)) {
        New-Item -ItemType Junction -Path $source -Target $redirects[$name] | Out-Null
    }
}
$systemTemp = Join-Path $root 'system-temp'
New-Item -ItemType Directory -Path $systemTemp -Force | Out-Null
$names = @('TEMP', 'TMP', 'TMPDIR', 'CODEX_HOME')
$previous = @{}
foreach ($name in $names) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    $env:TEMP = $systemTemp
    $env:TMP = $systemTemp
    $env:TMPDIR = $systemTemp
    $env:CODEX_HOME = $CodexHome
    # Avoid reusing a daemon that inherited an unencrypted temporary directory.
    & $codex --no-daemon @CodexArguments
    $codexExit = $LASTEXITCODE
}
finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
}
exit $codexExit
