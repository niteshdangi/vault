#!/usr/bin/env pwsh
# install.ps1 — Vault CLI installer for Windows
# Usage: irm https://raw.githubusercontent.com/niteshdangi/vault/main/install.ps1 | iex

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Status  { param([string]$Msg) Write-Host "  " -NoNewline; Write-Host "info" -ForegroundColor Cyan -NoNewline; Write-Host ": $Msg" }
function Write-Success { param([string]$Msg) Write-Host "  " -NoNewline; Write-Host "done" -ForegroundColor Green -NoNewline; Write-Host ": $Msg" }
function Write-Err     { param([string]$Msg) Write-Host "  " -NoNewline; Write-Host "error" -ForegroundColor Red -NoNewline; Write-Host ": $Msg" }
function Write-Warn    { param([string]$Msg) Write-Host "  " -NoNewline; Write-Host "warn" -ForegroundColor Yellow -NoNewline; Write-Host ": $Msg" }

function Exit-WithError {
    param([string]$Msg)
    Write-Err $Msg
    Write-Host ""
    exit 1
}

# ── Banner ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  vault" -ForegroundColor Cyan -NoNewline
Write-Host " installer"
Write-Host "  ─────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

# ── Configuration ────────────────────────────────────────────────────────────

$Repo       = "niteshdangi/vault"
$Asset      = "vault-windows-x86_64.exe"
$Checksums  = "checksums-sha256.txt"
$BinaryName = "vault.exe"
$ApiUrl     = "https://api.github.com/repos/$Repo/releases/latest"

$InstallDir = if ($env:VAULT_INSTALL_DIR) { $env:VAULT_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "vault" }

# ── Fetch latest release ────────────────────────────────────────────────────

Write-Status "Fetching latest release from GitHub..."

try {
    $releaseJson = Invoke-RestMethod -Uri $ApiUrl -Headers @{ 'User-Agent' = 'vault-installer/1.0' } -UseBasicParsing
} catch {
    Exit-WithError "Failed to fetch latest release: $_"
}

$Tag = $releaseJson.tag_name
if (-not $Tag) {
    Exit-WithError "Could not determine latest release tag."
}

Write-Status "Latest release: $Tag"

# ── Build download URLs ─────────────────────────────────────────────────────

$BaseUrl     = "https://github.com/$Repo/releases/download/$Tag"
$AssetUrl    = "$BaseUrl/$Asset"
$ChecksumUrl = "$BaseUrl/$Checksums"

# ── Prepare temp directory ───────────────────────────────────────────────────

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "vault-install-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

$TempBinary   = Join-Path $TempDir $Asset
$TempChecksum = Join-Path $TempDir $Checksums

try {
    # ── Download binary ──────────────────────────────────────────────────────

    Write-Status "Downloading $Asset..."

    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $AssetUrl -OutFile $TempBinary -UseBasicParsing
    } catch {
        Exit-WithError "Failed to download binary: $_"
    }

    # ── Download checksums ───────────────────────────────────────────────────

    Write-Status "Downloading checksums..."

    try {
        Invoke-WebRequest -Uri $ChecksumUrl -OutFile $TempChecksum -UseBasicParsing
    } catch {
        Exit-WithError "Failed to download checksums file: $_"
    }

    # ── Verify SHA-256 ───────────────────────────────────────────────────────

    Write-Status "Verifying SHA-256 checksum..."

    $ActualHash = (Get-FileHash -Path $TempBinary -Algorithm SHA256).Hash.ToLower()

    $ChecksumContent = Get-Content -Path $TempChecksum -Raw
    $ExpectedHash = $null

    foreach ($line in $ChecksumContent -split "`n") {
        $line = $line.Trim()
        if ($line -match "^([a-fA-F0-9]{64})\s+(.+)$") {
            if ($Matches[2].Trim() -eq $Asset) {
                $ExpectedHash = $Matches[1].ToLower()
                break
            }
        }
    }

    if (-not $ExpectedHash) {
        Exit-WithError "Checksum entry for '$Asset' not found in $Checksums."
    }

    if ($ActualHash -ne $ExpectedHash) {
        Exit-WithError "Checksum mismatch!`n    Expected: $ExpectedHash`n    Got:      $ActualHash"
    }

    Write-Success "Checksum verified ($($ActualHash.Substring(0,16))...)"

    # ── Install binary ───────────────────────────────────────────────────────

    Write-Status "Installing to $InstallDir..."

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $Destination = Join-Path $InstallDir $BinaryName

    # If the binary is currently running, this will fail gracefully
    try {
        Copy-Item -Path $TempBinary -Destination $Destination -Force
    } catch {
        Exit-WithError "Failed to install binary. Is vault currently running?`n    $_"
    }

    Write-Success "Installed $BinaryName to $InstallDir"

    # ── Update PATH ──────────────────────────────────────────────────────────

    $RegKey  = 'HKCU:\Environment'
    $Current = (Get-ItemProperty -Path $RegKey -Name 'Path' -ErrorAction SilentlyContinue).Path

    if ($Current -and ($Current -split ';' | ForEach-Object { $_.TrimEnd('\') }) -contains $InstallDir.TrimEnd('\')) {
        Write-Status "PATH already contains $InstallDir"
    } else {
        Write-Status "Adding $InstallDir to user PATH..."
        try {
            $NewPath = if ($Current) { "$Current;$InstallDir" } else { $InstallDir }
            Set-ItemProperty -Path $RegKey -Name 'Path' -Value $NewPath

            # Broadcast WM_SETTINGCHANGE so Explorer picks up the change
            if (-not ('Win32.NativeMethods' -as [type])) {
                Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(
    IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
    uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
            }
            $HWND_BROADCAST = [IntPtr]0xFFFF
            $WM_SETTINGCHANGE = 0x1A
            $result = [UIntPtr]::Zero
            [Win32.NativeMethods]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result) | Out-Null

            Write-Success "Updated user PATH (persistent)"
        } catch {
            Write-Warn "Could not update PATH automatically. Add this manually:`n           $InstallDir"
        }
    }

    # Also update current session PATH
    if ($env:Path -notlike "*$InstallDir*") {
        $env:Path = "$InstallDir;$env:Path"
    }

    # ── Verify installation ──────────────────────────────────────────────────

    Write-Host ""
    Write-Status "Verifying installation..."

    try {
        $HelpOutput = & $Destination --help 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "vault is ready!"
        } else {
            Write-Warn "vault exited with code $LASTEXITCODE (binary may still work)"
        }
    } catch {
        Write-Warn "Could not run vault --help: $_"
    }

    # ── Done ─────────────────────────────────────────────────────────────────

    Write-Host ""
    Write-Host "  ─────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  vault $Tag" -ForegroundColor Cyan -NoNewline
    Write-Host " has been installed."
    Write-Host ""
    Write-Host "  To get started, run:" -ForegroundColor DarkGray
    Write-Host "    vault init" -ForegroundColor White
    Write-Host ""

    if ($Current -and -not (($Current -split ';' | ForEach-Object { $_.TrimEnd('\') }) -contains $InstallDir.TrimEnd('\'))) {
        Write-Host "  Note:" -ForegroundColor Yellow -NoNewline
        Write-Host " Restart your terminal for PATH changes to take effect."
        Write-Host ""
    }

} finally {
    # ── Cleanup ──────────────────────────────────────────────────────────────
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
