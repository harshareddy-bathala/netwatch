<# ──────────────────────────────────────────────────────────────
   install-windows-service.ps1 — Install NetWatch as a Windows
   service via NSSM (Non-Sucking Service Manager).

   Prerequisites:
     1. NSSM installed and on PATH  (https://nssm.cc)
     2. Python 3.11 venv at $InstallDir\venv
     3. Npcap installed in WinPcap-compatible mode

   Usage (run as Administrator):
     .\deploy\install-windows-service.ps1 [-InstallDir C:\NetWatch]
   ────────────────────────────────────────────────────────────── #>
param(
    [string]$InstallDir  = "C:\NetWatch",
    [string]$ServiceName = "NetWatch",
    [int]$Port           = 5000
)

$ErrorActionPreference = 'Stop'

# ── Verify NSSM ──────────────────────────────────────────────
if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
    Write-Error "NSSM not found. Install from https://nssm.cc and add to PATH."
    exit 1
}

# ── Paths ────────────────────────────────────────────────────
$Python  = Join-Path $InstallDir "venv\Scripts\python.exe"
$MainPy  = Join-Path $InstallDir "main.py"

if (-not (Test-Path $Python)) {
    Write-Error "Python venv not found at $Python. Create with: py -3.11 -m venv $InstallDir\venv"
    exit 1
}

# ── Generate a random SECRET_KEY if one isn't set ────────────
$SecretKey = [System.Convert]::ToBase64String(
    (1..48 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }) -as [byte[]]
)

# ── Install Service ──────────────────────────────────────────
Write-Host "Installing $ServiceName service..." -ForegroundColor Cyan

nssm install $ServiceName $Python $MainPy --port $Port
nssm set $ServiceName AppDirectory        $InstallDir
nssm set $ServiceName Description         "NetWatch Network Monitoring Daemon"
nssm set $ServiceName Start               SERVICE_AUTO_START
nssm set $ServiceName ObjectName          LocalSystem

# Environment
nssm set $ServiceName AppEnvironmentExtra `
    "NETWATCH_ENV=production" `
    "SECRET_KEY=$SecretKey" `
    "FLASK_PORT=$Port"

# Logging
$LogDir = Join-Path $InstallDir "logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
nssm set $ServiceName AppStdout           (Join-Path $LogDir "service_stdout.log")
nssm set $ServiceName AppStderr           (Join-Path $LogDir "service_stderr.log")
nssm set $ServiceName AppRotateFiles      1
nssm set $ServiceName AppRotateBytes      52428800   # 50 MB

# Restart on failure
nssm set $ServiceName AppExit Default     Restart
nssm set $ServiceName AppRestartDelay     10000      # 10 s

Write-Host ""
Write-Host "$ServiceName service installed." -ForegroundColor Green
Write-Host "Start with:  nssm start $ServiceName"
Write-Host "Status:       nssm status $ServiceName"
Write-Host "Remove:       nssm remove $ServiceName confirm"
Write-Host ""
Write-Host "Dashboard:    http://localhost:$Port" -ForegroundColor Yellow
