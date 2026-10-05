# Installs commx for the current user (no admin needed) and starts commxd
# at logon from the Startup folder.
#   powershell -ExecutionPolicy Bypass -File install-windows.ps1 [-From <dir with the .exe files>]
param([string]$From = $PSScriptRoot)

$ErrorActionPreference = "Stop"
$dest = Join-Path $env:LOCALAPPDATA "commx\bin"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
foreach ($exe in "commxd.exe", "commx.exe") {
    Copy-Item (Join-Path $From $exe) $dest -Force
}

# Start the daemon at logon, hidden.
$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath("Startup")) "commxd.lnk"))
$lnk.TargetPath = Join-Path $dest "commxd.exe"
$lnk.Arguments = "--detach"
$lnk.WindowStyle = 7
$lnk.Save()

# Put commx on the user's PATH.
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not ($userPath -split ";" | Where-Object { $_ -eq $dest })) {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$dest", "User")
}

Start-Process (Join-Path $dest "commxd.exe") -ArgumentList "--detach" -WindowStyle Hidden
Write-Host "commx installed to $dest. Open a new terminal and run: commx"
Write-Host "For Tor mode, install the Tor Expert Bundle and edit the Startup shortcut to add: --tor --tor-bin <path to tor.exe>"
