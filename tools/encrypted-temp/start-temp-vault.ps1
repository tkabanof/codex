#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackingDirectory,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[D-Zd-z]:$')]
    [string]$Drive,
    [string]$BinaryPath = (Join-Path $PSScriptRoot 'dist\temp-vault\temp-vault.bin'),
    [ValidateRange(1, 1048576)]
    [int]$MaxFileMiB = 64,
    [ValidateRange(1, 1048576)]
    [int]$CapacityMiB = 512
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Mounting requires Windows.'
}
$binary = (Get-Item -LiteralPath $BinaryPath -ErrorAction Stop).FullName
if ([IO.Path]::GetFileName($binary) -cne 'temp-vault.bin') {
    throw 'The service executable must be named temp-vault.bin.'
}
$backing = [IO.Path]::GetFullPath($BackingDirectory)
# Windows command-line escaping: double backslashes before quotes and at the
# end of a quoted argument. UseShellExecute=false avoids extension associations.
$escaped = [regex]::Replace($backing, '(\\*)"', '$1$1\"')
$escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
$info = New-Object System.Diagnostics.ProcessStartInfo
$info.FileName = $binary
$info.WorkingDirectory = Split-Path -Parent $binary
$info.Arguments = '--backing "' + $escaped + '" --drive ' + $Drive +
    ' --max-file-mib ' + $MaxFileMiB + ' --capacity-mib ' + $CapacityMiB
$info.UseShellExecute = $false
$process = [System.Diagnostics.Process]::Start($info)
try {
    Write-Host "Temporary-storage service: temp-vault.bin (PID $($process.Id))"
    $process.WaitForExit()
    $serviceExit = $process.ExitCode
}
finally {
    try { if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() } }
    finally { $process.Dispose() }
}
exit $serviceExit
