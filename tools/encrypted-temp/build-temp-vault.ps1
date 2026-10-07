#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$PythonExecutable = (Join-Path $PSScriptRoot '.venv\Scripts\python.exe')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Build this Windows service on Windows.'
}
$python = (Get-Command $PythonExecutable -CommandType Application -ErrorAction Stop).Source
$destination = Join-Path $PSScriptRoot 'dist\temp-vault'
if (Test-Path -LiteralPath $destination) {
    throw "Build destination already exists: $destination. Move the previous build before rebuilding."
}
$staging = Join-Path $PSScriptRoot ('build\package-' + [Guid]::NewGuid().ToString('N'))
$work = Join-Path $staging 'work'
$output = Join-Path $staging 'dist'
New-Item -ItemType Directory -Path $staging | Out-Null

# Onedir embeds Python in the service process and avoids onefile's extraction
# into the ordinary TEMP directory. Do not replace it with a python.exe wrapper.
& $python -m PyInstaller --onedir --noupx --name temp-vault `
    --paths (Join-Path $PSScriptRoot 'src') --collect-all winfspy `
    --distpath $output --workpath $work --specpath $staging `
    (Join-Path $PSScriptRoot 'temp-vault.py')
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }
$bundle = Join-Path $output 'temp-vault'
$generated = Join-Path $bundle 'temp-vault.exe'
$binary = Join-Path $bundle 'temp-vault.bin'
if (-not (Test-Path -LiteralPath $generated -PathType Leaf)) {
    throw 'PyInstaller did not produce the expected Windows binary.'
}
Move-Item -LiteralPath $generated -Destination $binary

# Exercise the renamed PE through CreateProcess, not ShellExecute/PATHEXT.
$info = New-Object System.Diagnostics.ProcessStartInfo
$info.FileName = $binary
$info.Arguments = '--help'
$info.UseShellExecute = $false
$process = [System.Diagnostics.Process]::Start($info)
try {
    if (-not $process.WaitForExit(30000)) {
        $process.Kill()
        $process.WaitForExit()
        throw 'Renamed service launch timed out.'
    }
    if ($process.ExitCode -ne 0) { throw 'Renamed service failed its launch check.' }
}
finally { $process.Dispose() }
if (Test-Path -LiteralPath $generated) { throw 'Unexpected .exe service remains in the bundle.' }
New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
Move-Item -LiteralPath $bundle -Destination $destination
Write-Host "Built: $(Join-Path $destination 'temp-vault.bin')"
